//! Device abstraction: result outcome types, the SCSI device seam, and
//! the forwarding impls that let transports drive any LUN type.

use crate::common::store::StoreOp;
use crate::scsi::backend::StorageError;
use crate::scsi::scsi::{asc, Sense, SenseKey};

/// Device type reported via INQUIRY (device.h).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DeviceType {
    Block,
    Cdrom,
}

impl DeviceType {
    /// Peripheral device type byte (INQUIRY byte 0, bits 0-4, SPC-4 §6.4.1).
    pub fn pdt(&self) -> u8 {
        match self {
            Self::Block => 0x00,
            Self::Cdrom => 0x05,
        }
    }
}

/// Outcome of processing one SCSI command (C `snowscsi_result_t`, device.h).
///
/// Zero-alloc, no borrow: for `OutInline` the device has already placed
/// `len` bytes at `data[0..len]`; the transport sends `data[0..len]`
/// directly. For `OutXfer`/`InXfer` the device holds a [`PendingXfer`]
/// and the transport drives `xfer_out`/`xfer_in`. Sense is held in the
/// device and retrieved via `peek_sense`/`take_sense`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CommandOutcome {
    /// No data phase, command succeeded (GOOD).
    Status,
    /// GOOD with pending sense (deferred/recovered, to be fetched via
    /// REQUEST SENSE). Transport leaves sense in device.
    StatusWithSense,
    /// Device → host, synthesized response already at `data[0..len]`.
    ///
    /// `len` is a work-buffer-relative byte count (`usize`): the response
    /// lives inside the caller's `data` scratch, so it can never exceed
    /// `data.len()` (unlike [`CommandOutcome::OutXfer`], whose backend
    /// transfer length stays `u64`).
    OutInline { len: usize },
    /// Device → host, backend source; fetch `len` bytes via `xfer_out`.
    OutXfer { len: u64 },
    /// Host → device; receive `len` bytes via `xfer_in`.
    InXfer { len: u64 },
    /// Host → device parameter list; collect `expected_len` bytes then
    /// call [`ScsiDevice::complete_param`].
    InParam { expected_len: usize },
    /// Command failed, sense is held in the device (peek/take).
    CheckCondition,
}

/// Core command-processing error (no_std, `core::error::Error`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Error {
    /// Caller's data buffer is smaller than [`crate::MIN_DATA_LEN`].
    WorkBufTooSmall,
    /// Sector size must be non-zero (`BlockDevice::disk`).
    InvalidSectorSize,
}

impl core::fmt::Display for Error {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::WorkBufTooSmall => write!(f, "data buffer smaller than MIN_DATA_LEN"),
            Self::InvalidSectorSize => write!(f, "sector_size must be non-zero"),
        }
    }
}

impl core::error::Error for Error {}

/// Direction of a data transfer from the device's perspective.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum XferDir {
    /// Data enters the device (WRITE / host → device, `xfer_in`).
    In,
    /// Data leaves the device (READ / device → host, `xfer_out`).
    Out,
}

/// Pending data transfer context (per-device, per-command).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PendingXfer {
    /// Starting byte offset of the transfer (`base_lba * block_size`).
    pub base_byte: u64,
    /// Block size in bytes (from track/sector_size), for sanity checks.
    pub block_size: u32,
    /// Transfer direction.
    pub dir: XferDir,
    /// Total transfer length in bytes.
    pub transfer_len: u64,
}

/// Result of one `xfer_out` / `xfer_in` chunk.
///
/// The device either handled the chunk **in place** (`Inline`) or hands the
/// platform a [`StoreOp`] to execute (`Store`). There is no error form: a
/// data-phase failure is reported by setting sense and returning
/// `Inline { len: 0 }` (see the module docs); genuine misuse is an internal
/// error in the caller.
#[derive(Debug)]
pub enum Xfer<'a> {
    /// The device handled `len` bytes in place (`len <= buf.len()`; pure
    /// synthesis may produce short).
    Inline { len: usize },
    /// Hand the operation to the platform; the op carries its own buffer
    /// (and, for FS, a path).
    Store(StoreOp<'a>),
}

/// Map a storage error to its `(sense key, ASC, ASCQ)` triple (SPC-3).
pub fn sense_for_storage_error(e: StorageError) -> (SenseKey, u8, u8) {
    match e {
        StorageError::OutOfBounds => (SenseKey::IllegalRequest, asc::LBA_OUT_OF_RANGE, 0),
        StorageError::NotWritable => (SenseKey::DataProtect, asc::WRITE_PROTECTED, 0),
        StorageError::Io(_) => (SenseKey::MediumError, asc::UNRECOVERED_READ_ERROR, 0),
        StorageError::Unsupported => (SenseKey::IllegalRequest, asc::INVALID_FIELD, 0),
    }
}

/// Outcome of the data-phase teardown ([`ScsiDevice::store_done`]).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum XferOutcome {
    /// Storage finished; sense (if any) is held in the device.
    Ok,
    /// The device does not take over the mapping; the session maps the
    /// [`StorageError`] to sense itself.
    Error(StorageError),
}

/// Data-area capacity of a transport scratch buffer, rounded down to a
/// 4-byte multiple.
///
/// Each transport derives its usable data region from its own framing:
/// - iSCSI: `data_capacity(work.len() - BHS_SIZE)` — the PDU data segment
///   must keep `48 + dsl` 4-byte aligned so padding stays zero and
///   `send_pdu`'s `total + pad <= work.len()` invariant holds.
/// - USB MSC: the whole buffer is the data area (`data_capacity(work.len())`),
///   the alignment is a harmless chunk-granularity nicety.
pub fn data_capacity(work_len: usize) -> usize {
    work_len & !3
}

/// The SCSI device seam: the minimal command set the iSCSI/USB transports
/// need from any LUN.
///
/// Transports are generic over `D: ScsiDevice`, so the caller picks the
/// element type of `devs: &mut [D]`:
///
/// - homogeneous fast path — `&mut [BlockDevice<B>]` (zero dispatch);
/// - heterogeneous mixing — `&mut [&mut dyn ScsiDevice]` via the `&mut T`
///   forwarding impl below (protocol-mandated LUN spaces).
///
/// # Memory budget (embedded targets)
///
/// The device never allocates; the transport caller owns all buffers:
///
/// - `data` — the command/data scratch handed to [`ScsiDevice::do_cmd`]
///   (and to `poll`/`step`): **≥ [`crate::MIN_DATA_LEN`] bytes**, checked
///   at runtime (`WorkBufTooSmall`). This is the dominant allocation.
/// - iSCSI additionally prefixes a 48-byte BHS in the same work buffer;
///   USB BOT needs a separate receive scratch of at least `data.len()`.
/// - Session state machines (`IscsiSession`, `BotSession`) are a few
///   hundred bytes each; sense and pending-transfer state live inside
///   the device.
///
/// # Writing your own LUN
///
/// Implement this trait directly (pure-compute or exotic devices), or wrap
/// a built-in to add vendor opcodes — check first, delegate everything
/// else:
///
/// ```
/// use snowscsi::common::seekable_storage::{FlatData, RwRef};
/// use snowscsi::scsi::backend::{BlockBackend, RamBackend};
/// use snowscsi::scsi::block::BlockDevice;
/// use snowscsi::scsi::device::{CommandOutcome, DeviceType, Error, ScsiDevice, Xfer};
/// use snowscsi::scsi::scsi::{Sense, SenseKey};
///
/// struct VendorLun<'a> {
///     inner: BlockDevice<RwRef<'a>>,
/// }
///
/// impl ScsiDevice for VendorLun<'_> {
///     fn do_cmd(&mut self, cdb: &[u8], data: &mut [u8]) -> Result<CommandOutcome, Error> {
///         // Claim vendor opcode 0xC0; everything else falls through to
///         // built-in SBC/SPC.
///         if cdb.first() == Some(&0xC0) {
///             let be = self.inner.backend();
///             if be.read_at(0, &mut data[..16]).is_err() {
///                 self.inner.set_sense(SenseKey::MediumError, 0x11, 0);
///                 return Ok(CommandOutcome::CheckCondition);
///             }
///             return Ok(CommandOutcome::OutInline { len: 16 });
///         }
///         self.inner.do_cmd(cdb, data)
///     }
///     fn xfer_out<'a>(&'a mut self, off: u64, buf: &'a mut [u8]) -> Xfer<'a> {
///         self.inner.xfer_out(off, buf)
///     }
///     fn xfer_in<'a>(&'a mut self, off: u64, buf: &'a [u8]) -> Xfer<'a> {
///         self.inner.xfer_in(off, buf)
///     }
///     fn peek_sense(&self) -> Option<&Sense> {
///         self.inner.peek_sense()
///     }
///     fn take_sense(&mut self) -> Option<Sense> {
///         self.inner.take_sense()
///     }
///     fn device_type(&self) -> DeviceType {
///         self.inner.device_type()
///     }
///     fn sync(&mut self) -> Result<(), snowscsi::common::seekable_storage::StorageError> {
///         self.inner.sync()
///     }
/// }
///
/// // Construction: any writable plane, erased or not.
/// let mut img = vec![0u8; 64 * 1024];
/// let mut bb = BlockBackend::Ram(RamBackend::new(&mut img));
/// let mut lun = VendorLun { inner: BlockDevice::disk(RwRef::new(&mut bb), 512).unwrap() };
/// # let _ = lun.do_cmd(&[0x12, 0, 0, 0, 36, 0], &mut vec![0u8; 8192][..]);
/// ```
///
/// Custom commands are not limited to synthesized replies. A host→device
/// parameter-list command returns `InParam { expected_len }` and the
/// wrapper overrides [`ScsiDevice::complete_param`]; a chunked custom
/// transfer returns `OutXfer`/`InXfer` and the wrapper keeps its own
/// pending-transfer state, serving `xfer_out`/`xfer_in` as the transport
/// drives offsets against it (see the loop below).
///
/// # Canonical transport loop
///
/// ```text
/// let outcome = dev.do_cmd(&cdb, &mut work)?;
/// match outcome {
///     CommandOutcome::OutInline { len } => send(&work[..len as usize]),
///     CommandOutcome::OutXfer { len } => {
///         for off in (0..len).step_by(CHUNK) {
///             match dev.xfer_out(off, &mut chunk[..]) {
///                 Xfer::Inline { .. } => send(&chunk),
///                 Xfer::Store(op) => { /* platform executes op, then store_done */ }
///             }
///         }
///     }
///     CommandOutcome::InXfer { len } => { /* recv chunks into dev.xfer_in */ }
///     CommandOutcome::CheckCondition => { /* peek/take_sense */ }
///     ...
/// }
/// ```
pub trait ScsiDevice {
    /// Process one SCSI command. `data` must be at least
    /// [`crate::MIN_DATA_LEN`] bytes. For `OutInline` the device writes the
    /// response into `data[0..len]` and returns `OutInline { len }`.
    fn do_cmd(&mut self, cdb: &[u8], data: &mut [u8]) -> Result<CommandOutcome, Error>;

    /// Read `buf.len()` bytes for the current READ transfer (device → host).
    /// `transfer_offset` is the byte offset within the transfer (0 ≤ off < transfer_len).
    /// Actual backend byte = `base_byte + transfer_offset`.
    ///
    /// Returns [`Xfer::Inline`] when the device handled the chunk in place
    /// (setting sense and producing `len: 0` on failure), or [`Xfer::Store`]
    /// to hand the platform a [`StoreOp`].
    fn xfer_out<'a>(&'a mut self, transfer_offset: u64, buf: &'a mut [u8]) -> Xfer<'a>;

    /// Write `buf` for the current WRITE transfer (host → device).
    /// Actual backend byte = `base_byte + transfer_offset`.
    fn xfer_in<'a>(&'a mut self, transfer_offset: u64, buf: &'a [u8]) -> Xfer<'a>;

    /// The device's next maintenance / background op (default `None`).
    ///
    /// The session drains this before any terminating status (the data phase
    /// is followed by the device agenda). The returned op may borrow device
    /// state.
    fn next_store_op<'a>(&'a mut self) -> Option<StoreOp<'a>> {
        None
    }

    /// Data-phase teardown: the **single** storage → sense entry point.
    ///
    /// Default: map a [`StorageError`] to sense via
    /// [`sense_for_storage_error`] and return [`XferOutcome::Ok`]. A device
    /// may override to recover / defer, or return [`XferOutcome::Error`] to
    /// hand the mapping back to the session.
    fn store_done(&mut self, r: Result<(), StorageError>) -> XferOutcome {
        match r {
            Ok(()) => XferOutcome::Ok,
            Err(e) => {
                let (key, asc, ascq) = sense_for_storage_error(e);
                self.set_sense(Sense::new(key, asc, ascq));
                XferOutcome::Ok
            }
        }
    }

    /// Borrow the pending sense without consuming it (Status phase peek).
    fn peek_sense(&self) -> Option<&Sense>;

    /// Take the pending sense, clearing the device (Status autosense or REQUEST SENSE).
    fn take_sense(&mut self) -> Option<Sense>;

    fn device_type(&self) -> DeviceType;

    /// Complete a parameter-list Data-Out phase (`InParam`).
    ///
    /// `cdb` is the original CDB, `data` the full parameter list
    /// (`expected_len` bytes) already collected in the transport's
    /// work buffer.
    ///
    /// Default: accept as a no-op (`Status`), matching the built-in
    /// devices' MODE SELECT behavior. Override to validate the parameter
    /// list; a rejecting override must set sense first and return
    /// [`CommandOutcome::CheckCondition`] (the "sense is held in the
    /// device" contract).
    fn complete_param(&mut self, _cdb: &[u8], _data: &[u8]) -> CommandOutcome {
        CommandOutcome::Status
    }

    /// Flush pending backend writes (graceful shutdown).
    ///
    /// Default no-op for compute-only LUNs; storage-backed devices forward
    /// to their backend/media. Errors use the device-level storage error
    /// domain ([`StorageError`]).
    fn sync(&mut self) -> Result<(), StorageError> {
        Ok(())
    }

    /// Inject a Unit Attention condition (SAM-4 §5.14 / SPC-4 §5.14).
    ///
    /// The device queues `SenseKey::UnitAttention` with the given `asc`/`ascq`
    /// so the next non-bypass command reports `CHECK CONDITION` once.
    /// Default no-op for compute LUNs; storage/optical devices override.
    fn inject_unit_attention(&mut self, _asc: u8, _ascq: u8) {}

    /// Replace the pending sense (transport-side synthetic CHECK CONDITION,
    /// e.g. a well-known command rejected before device dispatch).
    /// Default no-op for stateless LUNs that synthesize sense themselves.
    fn set_sense(&mut self, _sense: Sense) {}
}

/// Heterogeneous LUN arrays: `[&mut dyn ScsiDevice]` elements satisfy
/// `D: ScsiDevice` through this forwarding impl (callers never deref
/// manually). Same-type arrays keep the monomorphized fast path.
impl<T: ScsiDevice + ?Sized> ScsiDevice for &mut T {
    fn do_cmd(&mut self, cdb: &[u8], data: &mut [u8]) -> Result<CommandOutcome, Error> {
        (**self).do_cmd(cdb, data)
    }

    fn xfer_out<'a>(&'a mut self, transfer_offset: u64, buf: &'a mut [u8]) -> Xfer<'a> {
        (**self).xfer_out(transfer_offset, buf)
    }

    fn xfer_in<'a>(&'a mut self, transfer_offset: u64, buf: &'a [u8]) -> Xfer<'a> {
        (**self).xfer_in(transfer_offset, buf)
    }

    fn next_store_op<'a>(&'a mut self) -> Option<StoreOp<'a>> {
        (**self).next_store_op()
    }

    fn store_done(&mut self, r: Result<(), StorageError>) -> XferOutcome {
        (**self).store_done(r)
    }

    fn peek_sense(&self) -> Option<&Sense> {
        (**self).peek_sense()
    }

    fn take_sense(&mut self) -> Option<Sense> {
        (**self).take_sense()
    }

    fn device_type(&self) -> DeviceType {
        (**self).device_type()
    }

    fn complete_param(&mut self, cdb: &[u8], data: &[u8]) -> CommandOutcome {
        (**self).complete_param(cdb, data)
    }

    fn sync(&mut self) -> Result<(), StorageError> {
        (**self).sync()
    }

    fn inject_unit_attention(&mut self, asc: u8, ascq: u8) {
        (**self).inject_unit_attention(asc, ascq)
    }

    fn set_sense(&mut self, sense: Sense) {
        (**self).set_sense(sense)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::scsi::backend::RamBackend;
    use crate::scsi::block::BlockDevice;
    use crate::scsi::scsi::op;
    fn work() -> [u8; crate::MIN_DATA_LEN] {
        [0u8; crate::MIN_DATA_LEN]
    }

    #[test]
    fn data_capacity_aligns_down_to_4_bytes() {
        assert_eq!(data_capacity(8192), 8192);
        assert_eq!(data_capacity(8190), 8188);
        assert_eq!(data_capacity(8240), 8240);
        assert_eq!(data_capacity(262144 - 48), 262096);
        assert_eq!(data_capacity(0), 0);
    }

    fn inquiry_pdt(dev: &mut dyn ScsiDevice, w: &mut [u8]) -> u8 {
        let mut cdb = [0u8; 6];
        cdb[0] = op::INQUIRY;
        cdb[4] = 96;
        match dev.do_cmd(&cdb, w).unwrap() {
            CommandOutcome::OutInline { len } => {
                assert!(len >= 1);
                w[0]
            }
            _ => panic!("expected OutInline"),
        }
    }

    #[test]
    fn block_disk_roundtrip_via_dyn_forwarding() {
        // Heterogeneous mixed LUN array: elements are `&mut dyn ScsiDevice`,
        // driven generically through the `&mut T` forwarding impl.
        let mut ram = vec![0u8; 64 * 1024];
        let mut img = vec![0xAAu8; 2048 * 16];
        let mut disk = BlockDevice::disk(RamBackend::new(&mut ram), 512).unwrap();
        let mut optical = BlockDevice::cdrom(RamBackend::new(&mut img)).unwrap();
        let luns: [&mut dyn ScsiDevice; 2] = [&mut disk, &mut optical];

        assert_eq!(inquiry_pdt(luns[0], &mut work()), 0x00);
        assert_eq!(inquiry_pdt(luns[1], &mut work()), 0x05);
        assert_eq!(luns[0].device_type(), DeviceType::Block);
        assert_eq!(luns[1].device_type(), DeviceType::Cdrom);

        // WRITE(10) LBA 0 len 1 on LUN 0, then READ it back.
        let mut w = work();
        let mut cdb = [0u8; 10];
        cdb[0] = op::WRITE_10;
        cdb[8] = 1;
        assert!(matches!(
            luns[0].do_cmd(&cdb, &mut w).unwrap(),
            CommandOutcome::InXfer { len: 512 }
        ));
        assert!(matches!(
            luns[0].xfer_in(0, &w[..512]),
            Xfer::Inline { len: 512 }
        ));
        cdb[0] = op::READ_10;
        assert!(matches!(
            luns[0].do_cmd(&cdb, &mut w).unwrap(),
            CommandOutcome::OutXfer { len: 512 }
        ));
        let mut buf = [0u8; 512];
        assert!(matches!(
            luns[0].xfer_out(0, &mut buf),
            Xfer::Inline { len: 512 }
        ));
        assert_eq!(&buf[..4], &w[..4]);

        // Optical profile refuses writes with DATA PROTECT.
        cdb[0] = op::WRITE_10;
        match luns[1].do_cmd(&cdb, &mut w).unwrap() {
            CommandOutcome::CheckCondition => assert!(luns[1].peek_sense().is_some()),
            CommandOutcome::InXfer { .. } => {
                assert!(matches!(
                    luns[1].xfer_in(0, &w[..512]),
                    Xfer::Inline { len: 0 }
                ));
                assert!(luns[1].peek_sense().is_some());
            }
            other => panic!("unexpected outcome {other:?}"),
        }
    }

    #[test]
    fn scsi_device_sync_defaults_and_forwards() {
        let mut ram = vec![0u8; 4096];
        let mut disk = BlockDevice::disk(RamBackend::new(&mut ram), 512).unwrap();
        // RAM backend sync is a no-op Ok; trait default covers compute LUNs.
        assert!(ScsiDevice::sync(&mut disk).is_ok());
    }

    #[test]
    fn sense_for_storage_error_covers_all_variants() {
        assert_eq!(
            sense_for_storage_error(StorageError::OutOfBounds),
            (SenseKey::IllegalRequest, asc::LBA_OUT_OF_RANGE, 0)
        );
        assert_eq!(
            sense_for_storage_error(StorageError::NotWritable),
            (SenseKey::DataProtect, asc::WRITE_PROTECTED, 0)
        );
        assert_eq!(
            sense_for_storage_error(StorageError::Io(embedded_io::ErrorKind::Other)),
            (SenseKey::MediumError, asc::UNRECOVERED_READ_ERROR, 0)
        );
        assert_eq!(
            sense_for_storage_error(StorageError::Unsupported),
            (SenseKey::IllegalRequest, asc::INVALID_FIELD, 0)
        );
    }

    #[test]
    fn store_done_maps_and_next_store_op_defaults_none() {
        let mut ram = vec![0u8; 4096];
        let mut disk = BlockDevice::disk(RamBackend::new(&mut ram), 512).unwrap();

        // Default `next_store_op` is `None`.
        assert!(disk.next_store_op().is_none());

        // Default `store_done` maps a storage error to sense and returns Ok.
        assert_eq!(disk.store_done(Ok(())), XferOutcome::Ok);
        assert_eq!(
            disk.store_done(Err(StorageError::NotWritable)),
            XferOutcome::Ok
        );
        let s = disk.take_sense().unwrap();
        assert_eq!(s.key, SenseKey::DataProtect);
        assert_eq!(s.asc, asc::WRITE_PROTECTED);
    }
}
