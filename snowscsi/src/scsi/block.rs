//! SBC block device command set (block.c).
//!
//! Implements the direct-access block device commands (SPC-4 / SBC-3).
//! SPC commands (INQUIRY, MODE SENSE, ...) are delegated to
//! [`crate::scsi::spc`]; READ commands return an empty `immediate` and
//! the target hands the platform a [`StoreOp`] via `xfer_out`.

use crate::common::seekable_storage::{FlatData, WritableFlatData};
use crate::common::store::StoreOp;
use crate::scsi::backend::StorageError;
use crate::scsi::device::{
    CommandOutcome, DeviceType, Error, PendingXfer, ScsiDevice, Xfer, XferDir,
};
use crate::scsi::sbc::{execute_sbc, parse_sbc};
use crate::scsi::scsi::{asc, Sense, SenseKey};
use crate::scsi::spc::{block_mode_page, DeviceIdentity, SpcDevice, SpcEffect, BLOCK_IDENTITY};

const CLEAR_SENSE: Sense = Sense::clear();

/// Optical profile sector size (CD-ROM Mode 1 data).
pub const CD_SECTOR_SIZE: u32 = 2048;

/// INQUIRY identity for the optical read-only profile (the former
/// `CDBlockDevice`): SCSI family; MMC is not claimed via INQUIRY
/// descriptors (mimics real hardware: SPC-4/SBC-3 only, MMC via
/// GET CONFIGURATION).
pub const CDBLOCK_IDENTITY: DeviceIdentity = DeviceIdentity {
    vendor: *b"SnowSCSI",
    product: *b"HyperMulti DVD  ",
    revision: *b"0100",
    version_descriptors: [0x00A0, 0x0960, 0x0460, 0x04C0], /* SAM-5, iSCSI, SPC-4, SBC-3 (no MMC) */
};

/// Device-instance write-path state — all legal states, exhaustively.
///
/// "Not writable" comes in two kinds that a single device type must
/// express at runtime (the constructor-chosen difference necessarily
/// degrades to runtime state):
///
/// - [`WritePath::Absent`] — capability missing (`cdrom()` profile).
///   Writes are DATA PROTECT, forever.
/// - [`WritePath::Locked`] — the plane *can* write but policy says no
///   (read-only disk image). Re-openable via [`BlockDevice::set_writable`].
/// - [`WritePath::Open`] — normal writable disk.
///
/// This is **policy only**: the device no longer holds the backend, so
/// there are no captured `fn` pointers here. The plane is executed by the
/// shell (see [`crate::common::store::StorePlane`]); `xfer_out`/`xfer_in`
/// hand it a [`StoreOp`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum WritePath {
    /// No write path (`cdrom()` profile). Always DATA PROTECT.
    Absent,
    /// Plane is write-capable, policy closed (read-only *disk* image).
    /// Re-openable via [`BlockDevice::set_writable`].
    Locked,
    /// Normal writable.
    Open,
}

/// SCSI LUN over an offset-addressed byte plane.
///
/// Three profiles share this one type:
///
/// - [`BlockDevice::disk`] — writable direct-access device (PDT 0x00,
///   `BLOCK_IDENTITY`). The plane must be [`WritableFlatData`].
/// - [`BlockDevice::disk_read_only`] — PDT 0x00 with the write policy
///   locked (`WritePath::Locked`); accepts any [`FlatData`] and can be
///   unlocked later via [`BlockDevice::set_writable`].
/// - [`BlockDevice::cdrom`] — read-only optical profile (PDT 0x05,
///   `CDBLOCK_IDENTITY`, 2048-byte sectors, writes rejected with DATA
///   PROTECT). Accepts any [`FlatData`], including generated sources
///   such as live ISO9660. This is the former `CDBlockDevice`, now over
///   any plane.
///
/// The type is **non-generic**: every constructor borrows the plane once
/// to read its capacity (geometry) and immediately releases it. In steady
/// state the device holds no backend reference at all — data-phase I/O is
/// handed to the platform as a [`StoreOp`].
#[derive(Debug)]
pub struct BlockDevice {
    sector_size: u32,
    /// Capacity in bytes, cached from `plane.capacity()` at construction.
    capacity_bytes: u64,
    /// Write-path state (policy only — see [`WritePath`]).
    write_path: WritePath,
    identity: DeviceIdentity,
    pdt: DeviceType,
    sense: Option<Sense>,
    pending: Option<PendingXfer>,
    prevent_removal: bool,
}

impl BlockDevice {
    /// Read-only optical profile (the former `CDBlockDevice`): sector size
    /// fixed at 2048, every write rejected with DATA PROTECT, MODE SELECT
    /// accepted as a no-op, START STOP ignored.
    ///
    /// # `BlockDevice::cdrom` vs `crate::cdrom::CdromDrive`
    ///
    /// Both serve read-only ISO images, but they are different layers:
    ///
    /// - **`BlockDevice::cdrom(plane)`** — a *simple* read-only LUN
    ///   (PDT 0x05) that answers SBC/SPC over any [`FlatData`] plane.
    ///   Use it when you just want to hand the host an image without
    ///   dragging in the full MMC machinery (embedded targets, quick
    ///   `--block img=…,profile=cd` mounts).
    /// - **`crate::cdrom::CdromDrive`** (feature `cdrom`) — a *complete*
    ///   MMC optical drive (READ TOC, GET CONFIGURATION, tray/medium
    ///   events, runtime media exchange via `load`/`eject`). Use it when
    ///   the guest expects a real optical drive or needs disc swapping.
    pub fn cdrom(plane: &mut dyn FlatData) -> Result<Self, Error> {
        Ok(Self {
            sector_size: CD_SECTOR_SIZE,
            capacity_bytes: plane.capacity(),
            write_path: WritePath::Absent,
            identity: CDBLOCK_IDENTITY,
            pdt: DeviceType::Cdrom,
            sense: None,
            pending: None,
            prevent_removal: false,
        })
    }

    /// Writable direct-access disk (PDT 0x00, `BLOCK_IDENTITY`). The plane
    /// is borrowed only to read geometry; the write path is
    /// `WritePath::Open`.
    pub fn disk(plane: &mut dyn WritableFlatData, sector_size: u32) -> Result<Self, Error> {
        if sector_size == 0 {
            return Err(Error::InvalidSectorSize);
        }
        Ok(Self {
            sector_size,
            capacity_bytes: plane.capacity(),
            write_path: WritePath::Open,
            identity: BLOCK_IDENTITY,
            pdt: DeviceType::Block,
            sense: None,
            pending: None,
            prevent_removal: false,
        })
    }

    /// Direct-access disk (PDT 0x00) with the write policy locked
    /// (`WritePath::Locked`). Accepts any [`FlatData`] — including a
    /// genuinely read-only source — because the lock is policy, not
    /// capability; re-open with [`BlockDevice::set_writable`].
    pub fn disk_read_only(plane: &mut dyn FlatData, sector_size: u32) -> Result<Self, Error> {
        if sector_size == 0 {
            return Err(Error::InvalidSectorSize);
        }
        Ok(Self {
            sector_size,
            capacity_bytes: plane.capacity(),
            write_path: WritePath::Locked,
            identity: BLOCK_IDENTITY,
            pdt: DeviceType::Block,
            sense: None,
            pending: None,
            prevent_removal: false,
        })
    }

    pub fn sector_size(&self) -> u32 {
        self.sector_size
    }

    pub fn device_type(&self) -> DeviceType {
        self.pdt
    }

    /// Borrow the pending sense, if any.
    ///
    /// Single source of truth: `Some` ⇔ a sense is pending. A cleared
    /// sense is stored as `None`, never as `Sense { key: None, .. }`.
    pub fn peek_sense(&self) -> Option<&Sense> {
        self.sense.as_ref()
    }

    /// Take the pending sense, clearing the device (Status autosense or
    /// REQUEST SENSE).
    pub fn take_sense(&mut self) -> Option<Sense> {
        self.sense.take()
    }

    pub(crate) fn max_lba(&self) -> u64 {
        let nblocks = self.capacity_bytes / u64::from(self.sector_size);
        nblocks.saturating_sub(1)
    }

    /// Set sense data directly — the single source of truth for wrapper
    /// authors: a vendor-command handler reports errors by writing the
    /// inner device's sense here (never a private shadow field).
    ///
    /// # Contract
    ///
    /// Call only within command processing that produces the returned
    /// outcome — i.e., between [`BlockDevice::do_cmd`] and the outcome
    /// handed back to the transport. Sense written outside that window
    /// races the host's REQUEST SENSE and may be consumed by the wrong
    /// command.
    pub fn set_sense(&mut self, key: SenseKey, asc: u8, ascq: u8) {
        self.store_sense(Sense::new(key, asc, ascq));
    }

    /// Normalized sense storage: `key == None` means "no pending sense"
    /// and is stored as `None` (see [`SpcDevice::set_sense`]).
    fn store_sense(&mut self, s: Sense) {
        self.sense = (s.key != SenseKey::None).then_some(s);
    }

    pub(crate) fn cc(&mut self, key: SenseKey, asc: u8) -> CommandOutcome {
        self.set_sense(key, asc, 0);
        CommandOutcome::CheckCondition
    }

    fn check_bounds(&self, offset: u64, len: usize) -> Result<(), StorageError> {
        let end = offset
            .checked_add(len as u64)
            .ok_or(StorageError::OutOfBounds)?;
        if end > self.capacity_bytes {
            return Err(StorageError::OutOfBounds);
        }
        Ok(())
    }

    /// Read `buf.len()` bytes for the current READ transfer (device → host).
    /// `transfer_offset` is the byte offset within the transfer.
    ///
    /// Returns [`Xfer::Store`] carrying a [`StoreOp::Read`] addressed at
    /// the absolute plane byte (`base_byte + transfer_offset`); the shell
    /// executes it. The pending/direction/range guards stay here so a
    /// misuse (only reachable through a broken wrapper — `do_cmd` already
    /// validated) sets sense and yields a zero-length [`Xfer::Inline`].
    pub fn xfer_out<'a>(&'a mut self, transfer_offset: u64, buf: &'a mut [u8]) -> Xfer<'a> {
        let (dir, transfer_len, base_byte) = match self.pending {
            Some(p) => (p.dir, p.transfer_len, p.base_byte),
            None => {
                self.set_sense(SenseKey::IllegalRequest, 0x24, 0);
                return Xfer::Inline { len: 0 };
            }
        };
        if dir != XferDir::Out {
            self.set_sense(SenseKey::IllegalRequest, 0x24, 0);
            return Xfer::Inline { len: 0 };
        }
        let end = match transfer_offset.checked_add(buf.len() as u64) {
            Some(e) => e,
            None => {
                self.set_sense(SenseKey::IllegalRequest, 0x21, 0);
                return Xfer::Inline { len: 0 };
            }
        };
        if end > transfer_len {
            self.set_sense(SenseKey::IllegalRequest, 0x21, 0);
            return Xfer::Inline { len: 0 };
        }
        let actual = base_byte + transfer_offset;
        if let Err(e) = self.check_bounds(actual, buf.len()) {
            crate::warn!(
                "READ bounds: off={} len={} capacity={} err={:?}",
                actual,
                buf.len(),
                self.capacity_bytes,
                e
            );
            self.set_sense(SenseKey::MediumError, 0x11, 0);
            return Xfer::Inline { len: 0 };
        }
        Xfer::Store(StoreOp::Read { off: actual, buf })
    }

    /// Write `buf` for the current WRITE transfer (host → device).
    ///
    /// Returns [`Xfer::Store`] carrying a [`StoreOp::Write`] addressed at
    /// the absolute plane byte (`base_byte + transfer_offset`). The
    /// write-path gate (`WritePath::Open` only) and bounds are checked
    /// here; the command phase already rejected `Absent | Locked` with
    /// DATA PROTECT, so this is a defensive re-check for broken wrappers.
    pub fn xfer_in<'a>(&'a mut self, transfer_offset: u64, buf: &'a [u8]) -> Xfer<'a> {
        let (dir, transfer_len, base_byte) = match self.pending {
            Some(p) => (p.dir, p.transfer_len, p.base_byte),
            None => {
                self.set_sense(SenseKey::IllegalRequest, 0x24, 0);
                return Xfer::Inline { len: 0 };
            }
        };
        if dir != XferDir::In {
            self.set_sense(SenseKey::IllegalRequest, 0x24, 0);
            return Xfer::Inline { len: 0 };
        }
        let end = match transfer_offset.checked_add(buf.len() as u64) {
            Some(e) => e,
            None => {
                self.set_sense(SenseKey::IllegalRequest, 0x21, 0);
                return Xfer::Inline { len: 0 };
            }
        };
        if end > transfer_len {
            self.set_sense(SenseKey::IllegalRequest, 0x21, 0);
            return Xfer::Inline { len: 0 };
        }
        if !matches!(self.write_path, WritePath::Open) {
            self.set_sense(SenseKey::DataProtect, asc::WRITE_PROTECTED, 0);
            return Xfer::Inline { len: 0 };
        }
        let actual = base_byte + transfer_offset;
        if let Err(e) = self.check_bounds(actual, buf.len()) {
            crate::warn!(
                "WRITE bounds: off={} len={} capacity={} err={:?}",
                actual,
                buf.len(),
                self.capacity_bytes,
                e
            );
            self.set_sense(SenseKey::MediumError, asc::WRITE_FAULT, 0);
            return Xfer::Inline { len: 0 };
        }
        Xfer::Store(StoreOp::Write { off: actual, buf })
    }

    /// Process one SCSI command (`snowscsi_do_cmd`). `data` must be at
    /// least [`crate::MIN_DATA_LEN`] bytes.
    ///
    /// The CDB is parsed by [`parse_sbc`]: SPC commands are dispatched to
    /// `execute_spc` (via the `SbcCommand::Spc` fall-through), SBC commands
    /// to `execute_sbc`; unknown opcodes yield INVALID COMMAND.
    ///
    /// The command phase performs **no storage I/O**: bounds and
    /// write-protect are validated here, and the data phase only ships a
    /// [`StoreOp`] to the shell.
    pub fn do_cmd(&mut self, cdb: &[u8], data: &mut [u8]) -> Result<CommandOutcome, Error> {
        self.pending = None;
        if data.len() < crate::MIN_DATA_LEN {
            return Err(Error::WorkBufTooSmall);
        }
        // Unit Attention preemption (SPC-4 §5.14 / SAM-4): UA is reported once
        // as CHECK CONDITION, except for INQUIRY / REPORT LUNS / REQUEST SENSE.
        if let Some(s) = self.peek_sense() {
            if s.key == SenseKey::UnitAttention {
                let op = cdb.first().copied().unwrap_or(0);
                let bypass = matches!(
                    op,
                    crate::scsi::scsi::op::INQUIRY
                        | crate::scsi::scsi::op::REQUEST_SENSE
                        | crate::scsi::scsi::op::REPORT_LUNS
                );
                if !bypass {
                    let _ = self.take_sense();
                    return Ok(CommandOutcome::CheckCondition);
                }
            }
        }
        // L-f reserved-bit validation for the block profile (protection
        // type 0). SBC-3 §4.21 (3404/3376): with protection information
        // disabled a non-zero RDPROTECT/WRPROTECT field (byte1 bits 6:4 of
        // the 10/12/16-byte access commands) may be rejected 05/24 — we
        // reject. READ(6)/WRITE(6) byte1 bits 7:5 are Reserved (Tables
        // 54/96). DPO/FUA/FUA_NV bits are below the mask and unaffected.
        match cdb.first().copied() {
            Some(crate::scsi::scsi::op::READ_6 | crate::scsi::scsi::op::WRITE_6)
                if cdb.len() >= 6 && cdb[1] & 0xE0 != 0 =>
            {
                return Ok(self.cc(SenseKey::IllegalRequest, asc::INVALID_FIELD));
            }
            Some(
                crate::scsi::scsi::op::READ_10
                | crate::scsi::scsi::op::READ_12
                | crate::scsi::scsi::op::READ_16
                | crate::scsi::scsi::op::WRITE_10
                | crate::scsi::scsi::op::WRITE_12
                | crate::scsi::scsi::op::WRITE_16,
            ) if cdb.get(1).is_some_and(|&b| b & 0x70 != 0) => {
                return Ok(self.cc(SenseKey::IllegalRequest, asc::INVALID_FIELD));
            }
            _ => {}
        }
        let Some(cmd) = parse_sbc(cdb) else {
            return Ok(self.cc(SenseKey::IllegalRequest, asc::INVALID_COMMAND));
        };
        // execute_sbc is total over SbcCommand: SPC variants delegate to
        // execute_spc internally.
        Ok(execute_sbc(self, cmd, data))
    }

    /// Shared READ(6/10/12/16) handler.
    pub(crate) fn read_cmd(
        &mut self,
        max_lba: u64,
        lba: u64,
        count: u32,
        _data: &mut [u8],
    ) -> CommandOutcome {
        if count == 0 {
            return CommandOutcome::Status;
        }
        if !self.check_lba_range(max_lba, lba, count) {
            return self.cc(SenseKey::IllegalRequest, asc::LBA_OUT_OF_RANGE);
        }
        let bytes = self.count_to_bytes(count);
        let Some(bytes) = bytes else {
            return self.cc(SenseKey::IllegalRequest, asc::INVALID_FIELD);
        };
        let transfer_len = u64::from(bytes);
        let base_byte = lba * u64::from(self.sector_size);
        self.pending = Some(PendingXfer {
            base_byte,
            block_size: self.sector_size,
            dir: XferDir::Out,
            transfer_len,
        });
        CommandOutcome::OutXfer { len: transfer_len }
    }

    /// Shared WRITE(6/10/12/16) handler.
    pub(crate) fn write_cmd(
        &mut self,
        max_lba: u64,
        lba: u64,
        count: u32,
        _data: &mut [u8],
    ) -> CommandOutcome {
        if count == 0 {
            return CommandOutcome::Status;
        }
        if !matches!(self.write_path, WritePath::Open) {
            // Read-only profile (Absent) or locked read-only *image*
            // (Locked): immediate DATA PROTECT — the former CDBlockDevice
            // behavior plus the policy bit.
            return self.cc(SenseKey::DataProtect, asc::WRITE_PROTECTED);
        }
        if !self.check_lba_range(max_lba, lba, count) {
            return self.cc(SenseKey::IllegalRequest, asc::LBA_OUT_OF_RANGE);
        }
        let Some(bytes) = self.count_to_bytes(count) else {
            return self.cc(SenseKey::IllegalRequest, asc::INVALID_FIELD);
        };
        let transfer_len = u64::from(bytes);
        let base_byte = lba * u64::from(self.sector_size);
        self.pending = Some(PendingXfer {
            base_byte,
            block_size: self.sector_size,
            dir: XferDir::In,
            transfer_len,
        });
        CommandOutcome::InXfer { len: transfer_len }
    }

    /// LBA range check: `lba + count` must not exceed `max_lba + 1`.
    fn check_lba_range(&self, max_lba: u64, lba: u64, count: u32) -> bool {
        lba <= max_lba
            && lba
                .checked_add(u64::from(count))
                .is_some_and(|end| end <= max_lba + 1)
    }

    /// `count * sector_size`, rejected (None) if it exceeds u32::MAX.
    fn count_to_bytes(&self, count: u32) -> Option<u32> {
        let bytes = u64::from(count).checked_mul(u64::from(self.sector_size))?;
        u32::try_from(bytes).ok()
    }

    pub(crate) fn read_capacity_10_cmd(
        &mut self,
        pmi: bool,
        req_lba: u32,
        data: &mut [u8],
    ) -> CommandOutcome {
        // SBC-3 Table 62 / §5.15.2: PMI=0 requires LBA=0; PMI=1 requires
        // LBA ≤ RETURNED LBA.
        let max_lba = self.max_lba().min(u32::MAX as u64) as u32;
        if !pmi && req_lba != 0 {
            return self.cc(SenseKey::IllegalRequest, asc::INVALID_FIELD);
        }
        if pmi && req_lba > max_lba {
            return self.cc(SenseKey::IllegalRequest, asc::INVALID_FIELD);
        }
        let mut buf = [0u8; 8];
        buf[0..4].copy_from_slice(&max_lba.to_be_bytes());
        buf[4..8].copy_from_slice(&self.sector_size.to_be_bytes());
        data[0..8].copy_from_slice(&buf);
        CommandOutcome::OutInline { len: 8 }
    }

    pub(crate) fn read_capacity_16_cmd(
        &mut self,
        sa: u8,
        alloc: u32,
        lba: u64,
        pmi: bool,
        data: &mut [u8],
    ) -> CommandOutcome {
        if (sa & 0x1F) != 0x10 {
            return self.cc(SenseKey::IllegalRequest, asc::INVALID_FIELD);
        }
        // SBC-3 §5.16: PMI handling mirrors READ CAPACITY(10) §5.15.2
        if !pmi && lba != 0 {
            return self.cc(SenseKey::IllegalRequest, asc::INVALID_FIELD);
        }
        let max_lba = self.max_lba();
        if pmi && lba > max_lba {
            return self.cc(SenseKey::IllegalRequest, asc::INVALID_FIELD);
        }
        let mut buf = [0u8; 32];
        buf[0..8].copy_from_slice(&max_lba.to_be_bytes());
        buf[8..12].copy_from_slice(&self.sector_size.to_be_bytes());
        let n = 32.min(alloc as usize);
        data[0..n].copy_from_slice(&buf[..n]);
        CommandOutcome::OutInline { len: n }
    }

    pub(crate) fn synchronize_cache_cmd(
        &mut self,
        lba: u32,
        num_blocks: u16,
        immed: bool,
        _sync_nv: bool,
    ) -> CommandOutcome {
        // SBC-3 §5.24: IMMED=1 not supported (no async cache flush).
        if immed {
            return self.cc(SenseKey::IllegalRequest, asc::INVALID_FIELD);
        }
        // SYNC_NV is ignored (RAM disk has no non-volatile cache).
        let max_lba = self.max_lba();
        let lba64 = u64::from(lba);
        if num_blocks == 0 {
            if lba64 > max_lba {
                return self.cc(SenseKey::IllegalRequest, asc::LBA_OUT_OF_RANGE);
            }
        } else if lba64 > max_lba || lba64 + u64::from(num_blocks) > max_lba + 1 {
            return self.cc(SenseKey::IllegalRequest, asc::LBA_OUT_OF_RANGE);
        }
        // Flushing is a plane-level concern: the device holds no backend
        // (the shell owns the planes and flushes them at shutdown). The
        // command is a policy no-op here.
        CommandOutcome::Status
    }

    pub(crate) fn synchronize_cache16_cmd(
        &mut self,
        lba: u64,
        num_blocks: u32,
        immed: bool,
        _sync_nv: bool,
    ) -> CommandOutcome {
        // SBC-3 §5.25: same semantics as (10), with a 64-bit LBA and a
        // 32-bit block count (Table 84). IMMED=1 is unsupported; SYNC_NV is
        // ignored (no non-volatile cache on the RAM plane).
        if immed {
            return self.cc(SenseKey::IllegalRequest, asc::INVALID_FIELD);
        }
        let max_lba = self.max_lba();
        if num_blocks == 0 {
            if lba > max_lba {
                return self.cc(SenseKey::IllegalRequest, asc::LBA_OUT_OF_RANGE);
            }
        } else if lba > max_lba || lba + u64::from(num_blocks) > max_lba + 1 {
            return self.cc(SenseKey::IllegalRequest, asc::LBA_OUT_OF_RANGE);
        }
        // See `synchronize_cache_cmd`: the shell flushes planes.
        CommandOutcome::Status
    }

    pub(crate) fn format_unit_cmd(&mut self, cdb1: u8) -> CommandOutcome {
        // SBC-3 §5.3 Table 27: byte1 = FMTPINFO(7:6) | LONGLIST(5) | FMTDATA(4) |
        // CMPLST(3) | DEFECT LIST FORMAT(2:0). Simplest form is FMTDATA=0
        // (no parameter list, vendor-specific formatting, M per Table 25).
        let fmt_data = cdb1 & 0x10 != 0;
        let fmtpinfo = (cdb1 >> 6) & 0x03;
        if !fmt_data {
            // SBC-3 §5.3.1: FMTDATA=0 + FMTPINFO!=0 => INVALID FIELD IN CDB.
            if fmtpinfo != 0 {
                return self.cc(SenseKey::IllegalRequest, asc::INVALID_FIELD);
            }
            // CMPLST/LONGLIST are ignored when FMTDATA=0 (§5.3.1).
            // No-op format is sufficient for the block profile (RAM disk);
            // real hardware would zero or certify, but GOOD is compliant.
            return CommandOutcome::Status;
        }
        // FMTDATA=1 requires a parameter list; this minimal profile does not
        // implement defect lists / protection provisioning — report INVALID FIELD.
        self.cc(SenseKey::IllegalRequest, asc::INVALID_FIELD)
    }

    /// Policy switch for read-only *disk* images (PDT 0x00 but RO): the
    /// plane stays write-capable, the device refuses writes. Set before
    /// `serve`.
    ///
    /// Total function over the write path (`WritePath`): `Absent`
    /// (the `cdrom()` profile) stays absent regardless of `writable` — a
    /// read-only plane can never be talked into writing; `Locked` and
    /// `Open` swap according to `writable`.
    pub fn set_writable(&mut self, writable: bool) {
        self.write_path = match self.write_path {
            WritePath::Absent => WritePath::Absent,
            WritePath::Locked | WritePath::Open => {
                if writable {
                    WritePath::Open
                } else {
                    WritePath::Locked
                }
            }
        };
    }
}

impl SpcDevice for BlockDevice {
    fn device_type(&self) -> DeviceType {
        self.pdt
    }

    fn identity(&self) -> &DeviceIdentity {
        &self.identity
    }

    fn id(&self) -> u64 {
        self.capacity_bytes
    }

    fn mode_page(&self, page: u8) -> Option<&[u8]> {
        block_mode_page(page)
    }

    fn sense(&self) -> &Sense {
        self.sense.as_ref().unwrap_or(&CLEAR_SENSE)
    }

    fn set_sense(&mut self, sense: Sense) {
        self.store_sense(sense);
    }

    fn start_stop(&mut self, loej: bool, load: bool) -> SpcEffect {
        // Optical profile accepts and ignores START STOP (former
        // CDBlockDevice behavior); disk honors prevent/allow removal.
        if self.pdt == DeviceType::Cdrom {
            return SpcEffect::Good;
        }
        if loej && !load && self.prevent_removal {
            SpcEffect::RemovalPrevented
        } else {
            SpcEffect::Good
        }
    }

    fn set_prevent(&mut self, prevent: bool) {
        self.prevent_removal = prevent;
    }

    fn is_write_protected(&self) -> bool {
        !matches!(self.write_path, WritePath::Open)
    }
}

impl ScsiDevice for BlockDevice {
    fn do_cmd(&mut self, cdb: &[u8], data: &mut [u8]) -> Result<CommandOutcome, Error> {
        self.do_cmd(cdb, data)
    }

    fn xfer_out<'a>(&'a mut self, transfer_offset: u64, buf: &'a mut [u8]) -> Xfer<'a> {
        self.xfer_out(transfer_offset, buf)
    }

    fn xfer_in<'a>(&'a mut self, transfer_offset: u64, buf: &'a [u8]) -> Xfer<'a> {
        self.xfer_in(transfer_offset, buf)
    }

    fn read_ahead_offset(&self, transfer_offset: u64) -> Option<u64> {
        let p = self.pending.as_ref()?;
        (p.dir == XferDir::Out).then(|| p.base_byte + transfer_offset)
    }

    fn peek_sense(&self) -> Option<&Sense> {
        self.peek_sense()
    }

    fn take_sense(&mut self) -> Option<Sense> {
        self.take_sense()
    }

    fn device_type(&self) -> DeviceType {
        self.pdt
    }

    fn complete_param(&mut self, cdb: &[u8], data: &[u8]) -> CommandOutcome {
        // Minimal MODE SELECT validation per SPC-3 §6.7: header + block
        // descriptor + page length must be consistent, otherwise 05/26 or
        // 05/24. We support caching 0x08 (18) and vendor 0x00 (2) only.
        let long = cdb[0] == 0x55;
        let header_len = if long { 8 } else { 4 };
        if data.len() < header_len {
            return self.cc(SenseKey::IllegalRequest, asc::INVALID_FIELD);
        }
        let block_len = if long {
            u16::from_be_bytes([data[6], data[7]]) as usize
        } else {
            data[3] as usize
        };
        if header_len + block_len > data.len() {
            return self.cc(SenseKey::IllegalRequest, asc::INVALID_FIELD);
        }
        let page_start = header_len + block_len;
        if page_start == data.len() {
            return CommandOutcome::Status;
        }
        if page_start + 2 > data.len() {
            return self.cc(SenseKey::IllegalRequest, asc::INVALID_FIELD);
        }
        let page_code = data[page_start] & 0x3F;
        let page_len = data[page_start + 1] as usize;
        if page_start + 2 + page_len != data.len() {
            return self.cc(SenseKey::IllegalRequest, asc::INVALID_FIELD);
        }
        if page_code != 0x08 && page_code != 0x00 {
            return self.cc(SenseKey::IllegalRequest, asc::INVALID_FIELD);
        }
        let expected = if page_code == 0x08 { 18 } else { 2 };
        if page_len != expected {
            return self.cc(SenseKey::IllegalRequest, asc::INVALID_FIELD);
        }
        CommandOutcome::Status
    }

    fn sync(&mut self) -> Result<(), StorageError> {
        // Planes are flushed by the shell (CLI `sync_planes`); the device
        // holds no backend, so there is nothing to flush here.
        Ok(())
    }

    fn inject_unit_attention(&mut self, asc: u8, ascq: u8) {
        self.sense = Some(Sense::new(SenseKey::UnitAttention, asc, ascq));
    }

    fn set_sense(&mut self, sense: Sense) {
        self.sense = Some(sense);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::scsi::backend::RamBackend;
    use crate::scsi::device::XferOutcome;
    use crate::scsi::scsi::op;

    /// Build a 6-byte CDB (test_block.c `make_cdb6`).
    fn make_cdb6(opcode: u8, lba: u32, transfer_len: u8) -> [u8; 6] {
        let mut cdb = [0u8; 6];
        cdb[0] = opcode;
        cdb[1] = ((lba >> 16) & 0x1F) as u8;
        cdb[2] = (lba >> 8) as u8;
        cdb[3] = lba as u8;
        cdb[4] = transfer_len;
        cdb
    }

    /// Build a 10-byte CDB (test_block.c `make_cdb10`).
    fn make_cdb10(opcode: u8, lba: u32, transfer_len: u16) -> [u8; 10] {
        let mut cdb = [0u8; 10];
        cdb[0] = opcode;
        cdb[2] = (lba >> 24) as u8;
        cdb[3] = (lba >> 16) as u8;
        cdb[4] = (lba >> 8) as u8;
        cdb[5] = lba as u8;
        cdb[7] = (transfer_len >> 8) as u8;
        cdb[8] = transfer_len as u8;
        cdb
    }

    /// Build a 12-byte CDB (test_block.c `make_cdb12`).
    fn make_cdb12(opcode: u8, lba: u32, transfer_len: u32) -> [u8; 12] {
        let mut cdb = [0u8; 12];
        cdb[0] = opcode;
        cdb[2] = (lba >> 24) as u8;
        cdb[3] = (lba >> 16) as u8;
        cdb[4] = (lba >> 8) as u8;
        cdb[5] = lba as u8;
        cdb[6] = (transfer_len >> 24) as u8;
        cdb[7] = (transfer_len >> 16) as u8;
        cdb[8] = (transfer_len >> 8) as u8;
        cdb[9] = transfer_len as u8;
        cdb
    }

    /// Build a 16-byte CDB (test_block.c `make_cdb16`).
    fn make_cdb16(opcode: u8, lba: u64, transfer_len: u32) -> [u8; 16] {
        let mut cdb = [0u8; 16];
        cdb[0] = opcode;
        cdb[2] = (lba >> 56) as u8;
        cdb[3] = (lba >> 48) as u8;
        cdb[4] = (lba >> 40) as u8;
        cdb[5] = (lba >> 32) as u8;
        cdb[6] = (lba >> 24) as u8;
        cdb[7] = (lba >> 16) as u8;
        cdb[8] = (lba >> 8) as u8;
        cdb[9] = lba as u8;
        cdb[10] = (transfer_len >> 24) as u8;
        cdb[11] = (transfer_len >> 16) as u8;
        cdb[12] = (transfer_len >> 8) as u8;
        cdb[13] = transfer_len as u8;
        cdb
    }

    fn work() -> [u8; crate::MIN_DATA_LEN] {
        [0u8; crate::MIN_DATA_LEN]
    }

    fn ram_dev(ram: &mut [u8]) -> BlockDevice {
        BlockDevice::disk(&mut RamBackend::new(ram), 512).unwrap()
    }

    /// Execute a device-produced block op against the test's byte plane —
    /// a stand-in for the platform's `StorePlane`.
    fn run_op(op: StoreOp<'_>, plane: &mut [u8]) {
        match op {
            StoreOp::Read { off, buf } => {
                let off = off as usize;
                buf.copy_from_slice(&plane[off..off + buf.len()]);
            }
            StoreOp::Write { off, buf } => {
                let off = off as usize;
                plane[off..off + buf.len()].copy_from_slice(buf);
            }
            other => panic!("unexpected store op: {other:?}"),
        }
    }

    /// Drive the Data-In phase of `outcome`: for `OutXfer` the device hands
    /// a `Store(Read)` which we execute against `plane`; for `OutInline` we
    /// copy from `work`. Returns the transferred byte count.
    fn data_in(
        dev: &mut BlockDevice,
        outcome: CommandOutcome,
        work: &[u8],
        plane: &mut [u8],
        buf: &mut [u8],
    ) -> usize {
        match outcome {
            CommandOutcome::OutXfer { len } => {
                let n = len as usize;
                assert!(n <= buf.len());
                match dev.xfer_out(0, &mut buf[..n]) {
                    Xfer::Store(op) => {
                        run_op(op, plane);
                        n
                    }
                    Xfer::Inline { len } => {
                        assert_eq!(len, n);
                        n
                    }
                }
            }
            CommandOutcome::OutInline { len } => {
                let n = len;
                assert!(n <= buf.len());
                buf[..n].copy_from_slice(&work[..n]);
                n
            }
            _ => panic!("expected OutXfer or OutInline"),
        }
    }

    /// Drive the Data-Out phase of `outcome` (payload already in `work`):
    /// execute the device's `Store(Write)` against `plane`. Returns the
    /// transferred byte count.
    fn data_out(
        dev: &mut BlockDevice,
        outcome: CommandOutcome,
        work: &[u8],
        plane: &mut [u8],
    ) -> usize {
        match outcome {
            CommandOutcome::InXfer { len } => {
                let n = len as usize;
                match dev.xfer_in(0, &work[..n]) {
                    Xfer::Store(op) => {
                        run_op(op, plane);
                        n
                    }
                    Xfer::Inline { len } => {
                        assert_eq!(len, n);
                        n
                    }
                }
            }
            _ => panic!("expected InXfer"),
        }
    }

    #[test]
    fn block_create_ram() {
        let mut ram = [0u8; 1024 * 1024];
        let dev = ram_dev(&mut ram);
        assert_eq!(dev.device_type(), DeviceType::Block);
        assert_eq!(dev.sector_size(), 512);
    }

    #[test]
    fn block_create_rejects_zero_sector() {
        let mut ram = [0u8; 512];
        assert!(BlockDevice::disk(&mut RamBackend::new(&mut ram), 0).is_err());
    }

    #[test]
    fn disk_read_only_rejects_writes_at_command_phase() {
        let mut ram = [0u8; 4096];
        let mut dev = BlockDevice::disk_read_only(&mut RamBackend::new(&mut ram), 512).unwrap();
        assert_eq!(dev.device_type(), DeviceType::Block);
        assert_eq!(dev.sector_size(), 512);

        let mut w = work();
        let cdb = make_cdb10(op::WRITE_10, 0, 1);
        assert_eq!(
            dev.do_cmd(&cdb, &mut w).unwrap(),
            CommandOutcome::CheckCondition
        );
        assert_eq!(dev.peek_sense().unwrap().key, SenseKey::DataProtect);
        assert_eq!(dev.peek_sense().unwrap().asc, asc::WRITE_PROTECTED);

        // Policy is re-openable (unlike the `cdrom()` Absent state).
        dev.set_writable(true);
        assert!(matches!(
            dev.do_cmd(&cdb, &mut w).unwrap(),
            CommandOutcome::InXfer { len: 512 }
        ));
    }

    #[test]
    fn block_read_zero() {
        let mut ram = [0u8; 1024 * 1024];
        let mut dev = ram_dev(&mut ram);
        let mut w = work();
        let cdb = make_cdb10(op::READ_10, 0, 1);
        let outcome = dev.do_cmd(&cdb, &mut w).unwrap();
        let mut buf = [0u8; 512];
        data_in(&mut dev, outcome, &w, &mut ram, &mut buf);
        assert_eq!(buf, [0u8; 512]);
    }

    #[test]
    fn block_write_read_roundtrip() {
        let mut ram = [0u8; 1024 * 1024];
        let mut dev = ram_dev(&mut ram);
        let mut w = work();
        let pattern: Vec<u8> = (0..512).map(|i| (i & 0xFF) as u8).collect();
        w[0..512].copy_from_slice(&pattern);

        let cdb = make_cdb10(op::WRITE_10, 10, 1);
        let outcome = dev.do_cmd(&cdb, &mut w).unwrap();
        assert_eq!(data_out(&mut dev, outcome, &w, &mut ram), 512);

        let cdb = make_cdb10(op::READ_10, 10, 1);
        let outcome = dev.do_cmd(&cdb, &mut w).unwrap();
        let mut buf = [0u8; 512];
        data_in(&mut dev, outcome, &w, &mut ram, &mut buf);
        assert_eq!(buf, pattern.as_slice());
    }

    #[test]
    fn block_lba_out_of_range() {
        let mut ram = [0u8; 1024 * 1024];
        let mut dev = ram_dev(&mut ram);
        let mut w = work();
        let cdb = make_cdb10(op::READ_10, 2048, 1);
        let outcome = dev.do_cmd(&cdb, &mut w).unwrap();
        assert_eq!(outcome, CommandOutcome::CheckCondition);
        assert_eq!(dev.peek_sense().unwrap().key, SenseKey::IllegalRequest);
        assert_eq!(dev.peek_sense().unwrap().asc, asc::LBA_OUT_OF_RANGE);
    }

    #[test]
    fn block_unknown_opcode() {
        let mut ram = [0u8; 1024 * 1024];
        let mut dev = ram_dev(&mut ram);
        let mut w = work();
        let mut cdb = [0u8; 10];
        cdb[0] = 0xFF;
        let outcome = dev.do_cmd(&cdb, &mut w).unwrap();
        assert_eq!(outcome, CommandOutcome::CheckCondition);
        assert_eq!(dev.peek_sense().unwrap().key, SenseKey::IllegalRequest);
        assert_eq!(dev.peek_sense().unwrap().asc, asc::INVALID_COMMAND);
    }

    #[test]
    fn block_read_capacity() {
        let mut ram = [0u8; 1024 * 1024];
        let mut dev = ram_dev(&mut ram);
        let mut w = work();
        let mut cdb = [0u8; 10];
        cdb[0] = op::READ_CAPACITY_10;
        let outcome = dev.do_cmd(&cdb, &mut w).unwrap();
        let mut buf = [0u8; 8];
        data_in(&mut dev, outcome, &w, &mut ram, &mut buf);
        let max_lba = u32::from_be_bytes([buf[0], buf[1], buf[2], buf[3]]);
        let block_size = u32::from_be_bytes([buf[4], buf[5], buf[6], buf[7]]);
        assert_eq!(max_lba, 2047);
        assert_eq!(block_size, 512);
    }

    #[test]
    fn block_read_capacity_16() {
        let mut ram = [0u8; 1024 * 1024];
        let mut dev = ram_dev(&mut ram);
        let mut w = work();
        let mut cdb = [0u8; 16];
        cdb[0] = op::SERVICE_ACTION_IN;
        cdb[1] = 0x10;
        cdb[13] = 0x20;
        let outcome = dev.do_cmd(&cdb, &mut w).unwrap();
        let mut buf = [0u8; 32];
        data_in(&mut dev, outcome, &w, &mut ram, &mut buf);
        assert_eq!(&buf[..8], &[0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x07, 0xFF]);
        assert_eq!(&buf[8..12], &[0x00, 0x00, 0x02, 0x00]);
        assert_eq!(&buf[12..], &[0u8; 20]);
    }

    #[test]
    fn block_read_capacity_16_unknown_sa() {
        let mut ram = [0u8; 1024 * 1024];
        let mut dev = ram_dev(&mut ram);
        let mut w = work();
        let mut cdb = [0u8; 16];
        cdb[0] = op::SERVICE_ACTION_IN;
        cdb[1] = 0xFF;
        let outcome = dev.do_cmd(&cdb, &mut w).unwrap();
        assert_eq!(outcome, CommandOutcome::CheckCondition);
        assert_eq!(dev.peek_sense().unwrap().key, SenseKey::IllegalRequest);
        assert_eq!(dev.peek_sense().unwrap().asc, asc::INVALID_FIELD);
    }

    #[test]
    fn block_read_6_zero_blocks() {
        let mut ram = [0u8; 1024 * 1024];
        let mut dev = ram_dev(&mut ram);
        let mut w = work();
        let cdb = make_cdb6(op::READ_6, 0, 0); /* 0 = 256 blocks */
        let outcome = dev.do_cmd(&cdb, &mut w).unwrap();
        let mut buf = vec![0u8; 256 * 512];
        data_in(&mut dev, outcome, &w, &mut ram, &mut buf);
        assert_eq!(buf, vec![0u8; 256 * 512]);
    }

    #[test]
    fn block_write_read_roundtrip_6() {
        let mut ram = [0u8; 1024 * 1024];
        let mut dev = ram_dev(&mut ram);
        let mut w = work();
        let pattern: Vec<u8> = (0..512).map(|i| (i & 0xFF) as u8).collect();
        w[0..512].copy_from_slice(&pattern);

        let cdb = make_cdb6(op::WRITE_6, 5, 1);
        let outcome = dev.do_cmd(&cdb, &mut w).unwrap();
        assert_eq!(data_out(&mut dev, outcome, &w, &mut ram), 512);

        let cdb = make_cdb6(op::READ_6, 5, 1);
        let outcome = dev.do_cmd(&cdb, &mut w).unwrap();
        let mut buf = [0u8; 512];
        data_in(&mut dev, outcome, &w, &mut ram, &mut buf);
        assert_eq!(buf, pattern.as_slice());
    }

    #[test]
    fn block_write_read_roundtrip_12() {
        let mut ram = [0u8; 1024 * 1024];
        let mut dev = ram_dev(&mut ram);
        let mut w = work();
        let pattern: Vec<u8> = (0..1024).map(|i| (i & 0xFF) as u8).collect();
        w[0..1024].copy_from_slice(&pattern);

        let cdb = make_cdb12(op::WRITE_12, 20, 2);
        let outcome = dev.do_cmd(&cdb, &mut w).unwrap();
        assert_eq!(data_out(&mut dev, outcome, &w, &mut ram), 1024);

        let cdb = make_cdb12(op::READ_12, 20, 2);
        let outcome = dev.do_cmd(&cdb, &mut w).unwrap();
        let mut buf = [0u8; 1024];
        data_in(&mut dev, outcome, &w, &mut ram, &mut buf);
        assert_eq!(&buf, &pattern[..]);
    }

    #[test]
    fn block_write_read_roundtrip_16() {
        let mut ram = [0u8; 1024 * 1024];
        let mut dev = ram_dev(&mut ram);
        let mut w = work();
        let pattern: Vec<u8> = (0..1024).map(|i| (i & 0xFF) as u8).collect();
        w[0..1024].copy_from_slice(&pattern);

        let cdb = make_cdb16(op::WRITE_16, 30, 2);
        let outcome = dev.do_cmd(&cdb, &mut w).unwrap();
        assert_eq!(data_out(&mut dev, outcome, &w, &mut ram), 1024);

        let cdb = make_cdb16(op::READ_16, 30, 2);
        let outcome = dev.do_cmd(&cdb, &mut w).unwrap();
        let mut buf = [0u8; 1024];
        data_in(&mut dev, outcome, &w, &mut ram, &mut buf);
        assert_eq!(&buf, &pattern[..]);
    }

    #[test]
    fn block_lba_out_of_range_6() {
        let mut ram = [0u8; 1024 * 1024];
        let mut dev = ram_dev(&mut ram);
        let mut w = work();
        let cdb = make_cdb6(op::READ_6, 2048, 1);
        let outcome = dev.do_cmd(&cdb, &mut w).unwrap();
        assert_eq!(outcome, CommandOutcome::CheckCondition);
        assert_eq!(dev.peek_sense().unwrap().key, SenseKey::IllegalRequest);
        assert_eq!(dev.peek_sense().unwrap().asc, asc::LBA_OUT_OF_RANGE);
    }

    #[test]
    fn block_lba_out_of_range_12() {
        let mut ram = [0u8; 1024 * 1024];
        let mut dev = ram_dev(&mut ram);
        let mut w = work();
        let cdb = make_cdb12(op::READ_12, 2048, 1);
        let outcome = dev.do_cmd(&cdb, &mut w).unwrap();
        assert_eq!(outcome, CommandOutcome::CheckCondition);
        assert_eq!(dev.peek_sense().unwrap().key, SenseKey::IllegalRequest);
        assert_eq!(dev.peek_sense().unwrap().asc, asc::LBA_OUT_OF_RANGE);
    }

    #[test]
    fn block_lba_out_of_range_16() {
        let mut ram = [0u8; 1024 * 1024];
        let mut dev = ram_dev(&mut ram);
        let mut w = work();
        let cdb = make_cdb16(op::READ_16, 2048, 1);
        let outcome = dev.do_cmd(&cdb, &mut w).unwrap();
        assert_eq!(outcome, CommandOutcome::CheckCondition);
        assert_eq!(dev.peek_sense().unwrap().key, SenseKey::IllegalRequest);
        assert_eq!(dev.peek_sense().unwrap().asc, asc::LBA_OUT_OF_RANGE);
    }

    #[test]
    fn block_synchronize_cache() {
        let mut ram = [0u8; 1024 * 1024];
        let mut dev = ram_dev(&mut ram);
        let mut w = work();
        let mut cdb = [0u8; 10];
        cdb[0] = op::SYNCHRONIZE_CACHE_10;
        assert_eq!(dev.do_cmd(&cdb, &mut w).unwrap(), CommandOutcome::Status);
    }

    #[test]
    fn block_synchronize_cache_16() {
        let mut ram = [0u8; 1024 * 1024];
        let mut dev = ram_dev(&mut ram);
        let mut w = work();

        // Full-range sync → GOOD (SBC-3 §5.25).
        let mut cdb = [0u8; 16];
        cdb[0] = op::SYNCHRONIZE_CACHE_16;
        assert_eq!(dev.do_cmd(&cdb, &mut w).unwrap(), CommandOutcome::Status);

        // IMMED=1 → 05/24 (the RAM plane has no async flush).
        let mut cdb = [0u8; 16];
        cdb[0] = op::SYNCHRONIZE_CACHE_16;
        cdb[1] = 0x02;
        let outcome = dev.do_cmd(&cdb, &mut w).unwrap();
        assert_eq!(outcome, CommandOutcome::CheckCondition);
        assert_eq!(dev.peek_sense().unwrap().key, SenseKey::IllegalRequest);
        assert_eq!(dev.peek_sense().unwrap().asc, asc::INVALID_FIELD);

        // Out-of-range 64-bit LBA → 05/21.
        let mut cdb = [0u8; 16];
        cdb[0] = op::SYNCHRONIZE_CACHE_16;
        cdb[5] = 0x01; /* LBA = 1 << 32, far beyond the 2047-block RAM disk */
        let outcome = dev.do_cmd(&cdb, &mut w).unwrap();
        assert_eq!(outcome, CommandOutcome::CheckCondition);
        assert_eq!(dev.peek_sense().unwrap().key, SenseKey::IllegalRequest);
        assert_eq!(dev.peek_sense().unwrap().asc, asc::LBA_OUT_OF_RANGE);
    }

    #[test]
    fn block_rdprotect_wrprotect_and_read6_reserved_rejected() {
        // L-f: type-0-protection block profile rejects non-zero
        // RDPROTECT/WRPROTECT (SBC-3 §4.21) and READ(6) reserved bits 7:5.
        let mut ram = [0u8; 1024 * 1024];
        let mut dev = ram_dev(&mut ram);
        let mut w = work();

        let mut cdb = [0u8; 10];
        cdb[0] = op::READ_10;
        cdb[1] = 0x10; /* RDPROTECT = 001b */
        cdb[8] = 1;
        let outcome = dev.do_cmd(&cdb, &mut w).unwrap();
        assert_eq!(outcome, CommandOutcome::CheckCondition);
        assert_eq!(dev.peek_sense().unwrap().key, SenseKey::IllegalRequest);
        assert_eq!(dev.peek_sense().unwrap().asc, asc::INVALID_FIELD);

        let mut cdb = [0u8; 10];
        cdb[0] = op::WRITE_10;
        cdb[1] = 0x10; /* WRPROTECT = 001b */
        cdb[8] = 1;
        let outcome = dev.do_cmd(&cdb, &mut w).unwrap();
        assert_eq!(outcome, CommandOutcome::CheckCondition);
        assert_eq!(dev.peek_sense().unwrap().asc, asc::INVALID_FIELD);

        let mut cdb = [0u8; 6];
        cdb[0] = op::READ_6;
        cdb[1] = 0x80; /* reserved bit 7 set */
        cdb[4] = 1;
        let outcome = dev.do_cmd(&cdb, &mut w).unwrap();
        assert_eq!(outcome, CommandOutcome::CheckCondition);
        assert_eq!(dev.peek_sense().unwrap().asc, asc::INVALID_FIELD);

        // DPO|FUA (byte1 bits 3..0) stay legal — mask covers 6:4 only.
        let mut cdb = [0u8; 10];
        cdb[0] = op::READ_10;
        cdb[1] = 0x0C; /* DPO | FUA */
        cdb[8] = 1;
        assert_eq!(
            dev.do_cmd(&cdb, &mut w).unwrap(),
            CommandOutcome::OutXfer { len: 512 }
        );
    }

    #[test]
    fn block_prevent_allow_start_stop_eject() {
        let mut ram = [0u8; 1024 * 1024];
        let mut dev = ram_dev(&mut ram);
        let mut w = work();

        let mut cdb = [0u8; 6];
        cdb[0] = op::PREVENT_ALLOW;
        cdb[4] = 0x01;
        assert_eq!(dev.do_cmd(&cdb, &mut w).unwrap(), CommandOutcome::Status);

        let mut cdb = [0u8; 6];
        cdb[0] = op::START_STOP_UNIT;
        cdb[4] = 0x02; /* LoEj=1, Load=0 (eject) */
        let outcome = dev.do_cmd(&cdb, &mut w).unwrap();
        assert_eq!(outcome, CommandOutcome::CheckCondition);
        assert_eq!(dev.peek_sense().unwrap().key, SenseKey::IllegalRequest);
        assert_eq!(dev.peek_sense().unwrap().asc, asc::MEDIUM_REMOVAL_PREVENTED);
        assert_eq!(
            dev.peek_sense().unwrap().ascq,
            asc::MEDIUM_REMOVAL_PREVENTED_ASCQ
        );

        let mut cdb = [0u8; 6];
        cdb[0] = op::START_STOP_UNIT;
        cdb[4] = 0x00; /* stop */
        assert_eq!(dev.do_cmd(&cdb, &mut w).unwrap(), CommandOutcome::Status);
    }

    #[test]
    fn block_read_capacity_pmi_zero_lba_nonzero() {
        let mut ram = [0u8; 1024 * 1024];
        let mut dev = ram_dev(&mut ram);
        let mut w = work();
        let mut cdb = [0u8; 10];
        cdb[0] = op::READ_CAPACITY_10;
        cdb[5] = 0x01; /* PMI=0, LBA=1 */
        let outcome = dev.do_cmd(&cdb, &mut w).unwrap();
        assert_eq!(outcome, CommandOutcome::CheckCondition);
        assert_eq!(dev.peek_sense().unwrap().key, SenseKey::IllegalRequest);
        assert_eq!(dev.peek_sense().unwrap().asc, asc::INVALID_FIELD);
    }

    #[test]
    fn block_work_buf_too_small() {
        let mut ram = [0u8; 1024 * 1024];
        let mut dev = ram_dev(&mut ram);
        let mut small = [0u8; 100];
        let cdb = make_cdb10(op::READ_10, 0, 1);
        assert_eq!(dev.do_cmd(&cdb, &mut small), Err(Error::WorkBufTooSmall));
    }

    #[cfg(feature = "std")]
    #[test]
    fn block_file_write_read_roundtrip() {
        use std::io::Write as _;

        let dir = std::env::temp_dir();
        let path = dir.join(format!("snowscsi_block_{}.img", std::process::id()));
        let mut f = std::fs::File::create(&path).unwrap();
        f.set_len(1024 * 1024).unwrap();
        f.flush().unwrap();

        let mut backend =
            crate::scsi::backend::FileBackend::open(&path.to_string_lossy(), true).unwrap();
        let mut dev = BlockDevice::disk(&mut backend, 512).unwrap();
        let mut w = work();
        let pattern: Vec<u8> = (0..512).map(|i| (i & 0xFF) as u8).collect();
        w[0..512].copy_from_slice(&pattern);

        let cdb = make_cdb10(op::WRITE_10, 0, 1);
        match dev.do_cmd(&cdb, &mut w).unwrap() {
            CommandOutcome::InXfer { len } => {
                assert_eq!(len, 512);
                match dev.xfer_in(0, &w[0..512]) {
                    Xfer::Store(op) => {
                        crate::common::store::StorePlane::BlockRw(&mut backend)
                            .do_op(op)
                            .unwrap();
                    }
                    other => panic!("expected Store(Write), got {other:?}"),
                }
            }
            _ => panic!("expected InXfer"),
        }

        let mut cdb = [0u8; 10];
        cdb[0] = op::SYNCHRONIZE_CACHE_10;
        assert_eq!(dev.do_cmd(&cdb, &mut w).unwrap(), CommandOutcome::Status);

        // The device no longer flushes; the shell flushes planes.
        crate::common::store::StorePlane::BlockRw(&mut backend)
            .sync()
            .unwrap();

        let on_disk = std::fs::read(&path).unwrap();
        assert_eq!(&on_disk[..512], pattern.as_slice());

        std::fs::remove_file(&path).unwrap();
    }

    #[cfg(feature = "std")]
    #[test]
    fn block_file_read_only() {
        let dir = std::env::temp_dir();
        let path = dir.join(format!("snowscsi_block_ro_{}.img", std::process::id()));
        std::fs::write(&path, [0u8; 512]).unwrap();

        // A read-only FileBackend handed *directly* to `disk()` is
        // write-capable at the policy level: the backend's NotWritable
        // must surface through `store_done` as DATA PROTECT, not WRITE
        // FAULT.
        let mut backend =
            crate::scsi::backend::FileBackend::open(&path.to_string_lossy(), false).unwrap();
        let mut dev = BlockDevice::disk(&mut backend, 512).unwrap();
        let mut w = work();

        let cdb = make_cdb10(op::WRITE_10, 0, 1);
        match dev.do_cmd(&cdb, &mut w).unwrap() {
            CommandOutcome::InXfer { len: _ } => {
                match dev.xfer_in(0, &w[0..512]) {
                    Xfer::Store(op) => {
                        let r = crate::common::store::StorePlane::BlockRw(&mut backend).do_op(op);
                        assert_eq!(r, Err(StorageError::NotWritable));
                        assert_eq!(dev.store_done(r), XferOutcome::Ok);
                    }
                    other => panic!("expected Store(Write), got {other:?}"),
                }
                assert_eq!(dev.peek_sense().unwrap().key, SenseKey::DataProtect);
                assert_eq!(dev.peek_sense().unwrap().asc, asc::WRITE_PROTECTED);
            }
            _ => panic!("expected InXfer"),
        }

        let cdb = make_cdb10(op::READ_10, 0, 1);
        let outcome = dev.do_cmd(&cdb, &mut w).unwrap();
        let mut buf = [0u8; 512];
        match outcome {
            CommandOutcome::OutXfer { len } => {
                assert_eq!(len, 512);
                match dev.xfer_out(0, &mut buf) {
                    Xfer::Store(op) => {
                        crate::common::store::StorePlane::BlockRo(&mut backend)
                            .do_op(op)
                            .unwrap();
                    }
                    other => panic!("expected Store(Read), got {other:?}"),
                }
            }
            _ => panic!("expected OutXfer"),
        }
        assert_eq!(buf, [0u8; 512]);

        std::fs::remove_file(&path).unwrap();
    }

    #[test]
    fn xfer_non_aligned_split_read() {
        let expected: Vec<u8> = (0..4096).map(|i| (i % 251) as u8).collect();
        let mut ram = expected.clone();
        let mut dev = ram_dev(&mut ram);
        let mut w = work();
        let cdb = make_cdb10(op::READ_10, 0, 2); // 1024 bytes
        let outcome = dev.do_cmd(&cdb, &mut w).unwrap();
        match outcome {
            CommandOutcome::OutXfer { len } => {
                assert_eq!(len, 1024);
                let mut chunk1 = vec![0u8; 600];
                match dev.xfer_out(0, &mut chunk1) {
                    Xfer::Store(StoreOp::Read { off, buf }) => {
                        assert_eq!(off, 0);
                        buf.copy_from_slice(&ram[0..600]);
                    }
                    other => panic!("expected Store(Read), got {other:?}"),
                }
                assert_eq!(chunk1, expected[0..600]);
                let mut chunk2 = vec![0u8; 424];
                match dev.xfer_out(600, &mut chunk2) {
                    Xfer::Store(StoreOp::Read { off, buf }) => {
                        assert_eq!(off, 600);
                        buf.copy_from_slice(&ram[600..1024]);
                    }
                    other => panic!("expected Store(Read), got {other:?}"),
                }
                assert_eq!(chunk2, expected[600..1024]);
            }
            _ => panic!("expected OutXfer"),
        }
    }

    #[test]
    fn xfer_non_aligned_split_write() {
        let mut ram = vec![0u8; 4096];
        let mut dev = ram_dev(&mut ram);
        let mut w = work();
        let cdb = make_cdb10(op::WRITE_10, 0, 2);
        let outcome = dev.do_cmd(&cdb, &mut w).unwrap();
        match outcome {
            CommandOutcome::InXfer { len } => {
                assert_eq!(len, 1024);
                let payload: Vec<u8> = (0..1024).map(|i| ((i * 7) % 251) as u8).collect();
                match dev.xfer_in(0, &payload[0..600]) {
                    Xfer::Store(StoreOp::Write { off, buf }) => {
                        assert_eq!(off, 0);
                        ram[0..600].copy_from_slice(buf);
                    }
                    other => panic!("expected Store(Write), got {other:?}"),
                }
                match dev.xfer_in(600, &payload[600..]) {
                    Xfer::Store(StoreOp::Write { off, buf }) => {
                        assert_eq!(off, 600);
                        ram[600..1024].copy_from_slice(buf);
                    }
                    other => panic!("expected Store(Write), got {other:?}"),
                }
                // Verify via read.
                let cdb = make_cdb10(op::READ_10, 0, 2);
                let outcome = dev.do_cmd(&cdb, &mut w).unwrap();
                match outcome {
                    CommandOutcome::OutXfer { len } => {
                        assert_eq!(len, 1024);
                        let mut buf = vec![0u8; 1024];
                        match dev.xfer_out(0, &mut buf) {
                            Xfer::Store(StoreOp::Read { off, buf: out }) => {
                                let off = off as usize;
                                out.copy_from_slice(&ram[off..off + out.len()]);
                            }
                            other => panic!("expected Store(Read), got {other:?}"),
                        }
                        assert_eq!(buf, payload);
                    }
                    _ => panic!("expected OutXfer"),
                }
            }
            _ => panic!("expected InXfer"),
        }
    }

    #[test]
    fn cdrom_profile_set_writable_cannot_unlock() {
        // Regression landmine: `set_writable(true)` on a `cdrom()`
        // device used to flip the policy bit while the captured write ops
        // stayed None ⇒ panic at the first WRITE. With `WritePath`, the
        // Absent state is sticky and the rejection happens at the command
        // phase.
        let mut ram = [0u8; 8192];
        let mut dev = BlockDevice::cdrom(&mut RamBackend::new(&mut ram)).unwrap();
        assert_eq!(dev.device_type(), DeviceType::Cdrom);
        dev.set_writable(true); // must be a no-op
        let mut w = work();
        let cdb = make_cdb10(op::WRITE_10, 0, 1);
        assert_eq!(
            dev.do_cmd(&cdb, &mut w).unwrap(),
            CommandOutcome::CheckCondition
        );
        assert_eq!(dev.peek_sense().unwrap().key, SenseKey::DataProtect);
        assert_eq!(dev.peek_sense().unwrap().asc, asc::WRITE_PROTECTED);
    }

    #[test]
    fn disk_policy_lock_unlock_roundtrip() {
        let mut ram = vec![0u8; 4096];
        let mut dev = BlockDevice::disk(&mut RamBackend::new(&mut ram), 512).unwrap();
        let mut w = work();

        // Lock: WRITE rejected at the command phase with DATA PROTECT.
        dev.set_writable(false);
        let cdb = make_cdb10(op::WRITE_10, 1, 1);
        assert_eq!(
            dev.do_cmd(&cdb, &mut w).unwrap(),
            CommandOutcome::CheckCondition
        );
        assert_eq!(dev.peek_sense().unwrap().key, SenseKey::DataProtect);

        // Re-open: writes flow again and read back intact.
        dev.set_writable(true);
        let pattern: Vec<u8> = (0..512).map(|i| ((i * 13) & 0xFF) as u8).collect();
        w[0..512].copy_from_slice(&pattern);
        let cdb = make_cdb10(op::WRITE_10, 1, 1);
        match dev.do_cmd(&cdb, &mut w).unwrap() {
            CommandOutcome::InXfer { len } => {
                assert_eq!(len, 512);
                match dev.xfer_in(0, &w[0..512]) {
                    Xfer::Store(op) => run_op(op, &mut ram),
                    other => panic!("expected Store(Write), got {other:?}"),
                }
            }
            _ => panic!("expected InXfer"),
        }
        let cdb = make_cdb10(op::READ_10, 1, 1);
        let outcome = dev.do_cmd(&cdb, &mut w).unwrap();
        let mut buf = [0u8; 512];
        data_in(&mut dev, outcome, &w, &mut ram, &mut buf);
        assert_eq!(buf, pattern.as_slice());
    }

    #[test]
    fn sync_is_noop() {
        // The device holds no backend: flushing is the shell's job
        // (`sync_planes`), so `ScsiDevice::sync` is a no-op.
        let mut ram = [0u8; 4096];
        let mut dev = ram_dev(&mut ram);
        assert_eq!(dev.sync(), Ok(()));
    }

    /// A read's read-ahead coordinate must be the **backend** address
    /// `xfer_out` hands the plane (`base_byte + transfer_offset`), never the
    /// transfer-relative offset: the transport matches its next `StoreOp`
    /// against the coordinate, so a relative one makes the speculative read miss
    /// and every chunk is read twice.
    #[test]
    fn read_ahead_offset_is_the_backend_address() {
        let mut w = work();

        // Nothing to pre-fetch before a command, and none during a write phase.
        let mut ram_w = vec![0u8; 8 * 512];
        let mut dev = ram_dev(&mut ram_w);
        assert_eq!(dev.read_ahead_offset(0), None, "nothing in flight");
        let _ = dev.do_cmd(&make_cdb10(op::WRITE_10, 2, 2), &mut w).unwrap();
        assert_eq!(dev.read_ahead_offset(0), None, "a write phase");

        // READ(10) at LBA 2, 2 blocks of 512: the transfer base is 2 * 512.
        let mut ram_r = vec![0u8; 8 * 512];
        let mut dev = ram_dev(&mut ram_r);
        assert_eq!(
            dev.do_cmd(&make_cdb10(op::READ_10, 2, 2), &mut w).unwrap(),
            CommandOutcome::OutXfer { len: 1024 }
        );
        let base = 2 * u64::from(dev.sector_size());
        assert_eq!(dev.read_ahead_offset(0), Some(base));
        assert_eq!(dev.read_ahead_offset(512), Some(base + 512));

        // ...and it agrees with the address `xfer_out` actually produces: that
        // equality is exactly what the transport matches on.
        let mut buf = [0u8; 512];
        match dev.xfer_out(512, &mut buf[..]) {
            Xfer::Store(StoreOp::Read { off, .. }) => {
                assert_eq!(Some(off), dev.read_ahead_offset(512))
            }
            other => panic!("expected Xfer::Store(StoreOp::Read), got {other:?}"),
        }
    }
}
