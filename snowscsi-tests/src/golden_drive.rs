//! Golden USB (BOT) replay driver (`__ASYNC_SEP_PLAN.md` §5.1, "回放 M3 起").
//!
//! At M0 the baseline was recorded with a test-local "driver A"
//! (`need()`/`poll()` loop plus the `clear_feature_halt()` unlock dance).
//! At M3 the USB session core converged on `Action`/`Event` and the loop
//! moved into the library as [`snowscsi::usb::serve`], so golden replay now
//! goes through that shipped loop — the baseline locks the real driver.
//!
//! [`RecBotIo`] reports script exhaustion as `WouldBlock` (its probe signal,
//! which ends a Data-Out overrun drain with `Event::HostIdle`), whereas
//! [`snowscsi::usb::serve`] ends on a non-probe `Ok(0)` receive (`Closed`).
//! [`GoldenBotIo`] bridges the two by translating a **blocking** (non-probe)
//! exhaustion into EOF, exactly as [`crate::golden::RecConn`]'s byte stream
//! returns EOF for the iSCSI replay.

use core::sync::atomic::AtomicBool;
use core::time::Duration;

use snowscsi::scsi::Luns;
use snowscsi::usb::{serve, BotIo, BotIoErr, BotSession, ServeError};

use crate::golden::{RecBotIo, RecGadget};

/// EOF adapter over [`RecBotIo`] (see the module docs).
pub struct GoldenBotIo<'a> {
    inner: &'a mut RecBotIo,
}

impl<'a> GoldenBotIo<'a> {
    pub fn new(inner: &'a mut RecBotIo) -> Self {
        Self { inner }
    }
}

impl BotIo for GoldenBotIo<'_> {
    fn try_recv_out(&mut self, buf: &mut [u8]) -> Result<usize, BotIoErr> {
        // The probe path keeps `RecBotIo`'s semantics: an exhausted script is
        // `WouldBlock` → `Event::HostIdle` (ends the overrun drain).
        self.inner.try_recv_out(buf)
    }

    fn recv_out(&mut self, buf: &mut [u8], timeout: Option<Duration>) -> Result<usize, BotIoErr> {
        // A blocking receive that finds the script exhausted is EOF: report
        // `Ok(0)` so `usb::serve` returns `Closed` (the iSCSI `RecConn` EOF).
        if self.inner.is_empty() {
            return Ok(0);
        }
        self.inner.recv_out(buf, timeout)
    }

    fn send_in(&mut self, buf: &[u8]) -> Result<(), BotIoErr> {
        self.inner.send_in(buf)
    }

    fn stall_both(&mut self) -> Result<(), ()> {
        self.inner.stall_both()
    }

    fn stall_in(&mut self) -> Result<(), ()> {
        self.inner.stall_in()
    }

    fn can_stall_in(&self) -> bool {
        self.inner.can_stall_in()
    }
}

/// Replay the scenario's bulk script to exhaustion through the library serve
/// loop (`usb::serve`), which owns the control plane (`RecGadget`) and the
/// `Action`/`Event` loop. The script ends at a command boundary, where the
/// adapter reports EOF.
pub fn serve_usb(
    io: &mut RecBotIo,
    gadget: &mut RecGadget,
    session: &mut BotSession,
    work: &mut [u8],
    luns: &mut Luns<'_>,
) {
    let stop = AtomicBool::new(false);
    let mut io = GoldenBotIo::new(io);
    // The replay script ends at a command boundary: the adapter reports EOF,
    // which `usb::serve` surfaces as `ServeError::Closed` — a clean end for a
    // finite wire script, exactly like `serve_conn`'s iSCSI EOF.
    match serve(&mut io, gadget, session, work, luns, &stop) {
        Ok(()) | Err(ServeError::Closed) => {}
        Err(e) => panic!("usb::serve failed: {e}"),
    }
}

#[cfg(test)]
mod tests {
    use super::serve_usb;
    use crate::golden::{split, InStep, TraceEntry, CBW_MAGIC, CSW_MAGIC};
    use snowscsi::common::store::StorePlane;
    use snowscsi::scsi::backend::RamBackend;
    use snowscsi::scsi::block::BlockDevice;
    use snowscsi::scsi::device::ScsiDevice;
    use snowscsi::scsi::Luns;
    use snowscsi::usb::{Action, BotSession, Event, CBW_LEN, CSW_LEN};

    /// Build a raw 31-byte CBW from its logical fields (little endian).
    ///
    /// A local copy of `usb_bot::raw_cbw` (private to that module): the golden
    /// scenarios build their CBWs inline (§5.1) rather than depending on the
    /// library's parse-only `Cbw`.
    fn raw_cbw(tag: u32, data_len: u32, flags: u8, lun: u8, cdb: &[u8]) -> [u8; CBW_LEN] {
        let mut raw = [0u8; CBW_LEN];
        raw[0..4].copy_from_slice(&CBW_MAGIC);
        raw[4..8].copy_from_slice(&tag.to_le_bytes());
        raw[8..12].copy_from_slice(&data_len.to_le_bytes());
        raw[12] = flags;
        raw[13] = lun;
        raw[14] = cdb.len() as u8;
        raw[15..15 + cdb.len().min(16)].copy_from_slice(&cdb[..cdb.len().min(16)]);
        raw
    }

    fn block_device(backend: &mut RamBackend<'_>) -> BlockDevice {
        BlockDevice::disk(backend, 512).unwrap()
    }

    /// A normal INQUIRY: the CBW in, 36 data bytes and the CSW out.
    #[test]
    fn normal_inquiry_transaction() {
        let mut ram = vec![0u8; 64 * 1024];
        let mut backend = RamBackend::new(&mut ram);
        let mut dev = block_device(&mut backend);
        let mut session = BotSession::new();
        let mut work = [0u8; snowscsi::MIN_DATA_LEN];

        // INQUIRY, allocation length 36, Data-In.
        let cdb = [0x12u8, 0, 0, 0, 36, 0];
        let cbw = raw_cbw(1, 36, 0x80, 0, &cdb);
        let (mut io, mut gadget) = split(vec![InStep::Bytes(cbw.to_vec())]);

        let mut devs: [&mut dyn ScsiDevice; 1] = [&mut dev];
        let mut planes: [Option<StorePlane<'_>>; 1] = [Some(StorePlane::BlockRw(&mut backend))];
        let mut luns = Luns::new(&mut devs, &mut planes);
        serve_usb(&mut io, &mut gadget, &mut session, &mut work, &mut luns);

        // Wire trace: CBW, the 36-byte INQUIRY response, then the CSW.
        assert_eq!(io.trace.len(), 3, "trace: {:?}", io.trace);
        match &io.trace[0] {
            TraceEntry::H2D(b) => assert_eq!(b.as_slice(), &cbw[..]),
            other => panic!("expected CBW, got {other:?}"),
        }
        match &io.trace[1] {
            TraceEntry::D2H(b) => {
                assert_eq!(b.len(), 36);
                assert_eq!(b[0] & 0x1F, 0x00, "PDT = direct-access block");
            }
            other => panic!("expected INQUIRY data, got {other:?}"),
        }
        match &io.trace[2] {
            TraceEntry::D2H(b) => {
                assert_eq!(b.len(), CSW_LEN);
                assert_eq!(&b[..4], &CSW_MAGIC);
                assert_eq!(u32::from_le_bytes([b[4], b[5], b[6], b[7]]), 1);
                assert_eq!(b[12], 0x00, "CSW status = Passed");
            }
            other => panic!("expected CSW, got {other:?}"),
        }
    }

    /// An invalid CBW STALLs both pipes; a following valid CBW is processed
    /// once it arrives (the new-CBW unlock; CLEAR_FEATURE is handled by the
    /// USB core and must not appear on the wire).
    #[test]
    fn invalid_cbw_stalls_then_unlock_allows_next_cbw() {
        let mut ram = vec![0u8; 64 * 1024];
        let mut backend = RamBackend::new(&mut ram);
        let mut dev = block_device(&mut backend);
        let mut session = BotSession::new();
        let mut work = [0u8; snowscsi::MIN_DATA_LEN];

        // Bad signature, then a valid INQUIRY.
        let mut bad = raw_cbw(1, 0, 0, 0, &[0x00, 0, 0, 0, 0, 0]);
        bad[0] = b'X';
        let cdb = [0x12u8, 0, 0, 0, 36, 0];
        let good = raw_cbw(2, 36, 0x80, 0, &cdb);
        let (mut io, mut gadget) = split(vec![
            InStep::Bytes(bad.to_vec()),
            InStep::Bytes(good.to_vec()),
        ]);

        let mut devs: [&mut dyn ScsiDevice; 1] = [&mut dev];
        let mut planes: [Option<StorePlane<'_>>; 1] = [Some(StorePlane::BlockRw(&mut backend))];
        let mut luns = Luns::new(&mut devs, &mut planes);
        serve_usb(&mut io, &mut gadget, &mut session, &mut work, &mut luns);

        // Both pipes STALLed exactly once, and the drive recovered to run the
        // valid CBW.
        assert_eq!(io.stall_count, 1);
        assert!(
            io.trace.contains(&TraceEntry::Mark("stall_both")),
            "expected a stall_both mark, trace: {:?}",
            io.trace
        );

        // Exactly one CSW went out (the valid CBW's; the invalid one emits
        // none) and it echoes tag 2 with Passed status.
        let csws: Vec<&Vec<u8>> = io
            .trace
            .iter()
            .filter_map(|e| match e {
                TraceEntry::D2H(b) if b.len() == CSW_LEN => Some(b),
                _ => None,
            })
            .collect();
        assert_eq!(csws.len(), 1, "no CSW for the invalid CBW");
        let csw = csws[0];
        assert_eq!(&csw[..4], &CSW_MAGIC);
        assert_eq!(u32::from_le_bytes([csw[4], csw[5], csw[6], csw[7]]), 2);
        assert_eq!(csw[12], 0x00);
    }

    /// The control seam is serviced by `usb::serve` per §3: Get Max LUN replies
    /// with `max_lun()`, Bot Reset acks after `Event::Reset`, Link Reset resets.
    #[test]
    fn control_requests_are_serviced() {
        use crate::golden::CtrlStep;
        use std::sync::atomic::Ordering;

        let mut session = BotSession::with_luns(2);
        let mut work = [0u8; snowscsi::MIN_DATA_LEN];
        let (mut io, mut gadget) = split(vec![
            InStep::Ctrl(CtrlStep::GetMaxLun),
            InStep::Ctrl(CtrlStep::BotReset),
            InStep::Ctrl(CtrlStep::LinkReset),
        ]);

        let mut devs: [&mut dyn ScsiDevice; 0] = [];
        let mut planes: [Option<StorePlane<'_>>; 0] = [];
        {
            let mut luns = Luns::new(&mut devs, &mut planes);
            serve_usb(&mut io, &mut gadget, &mut session, &mut work, &mut luns);
        }

        assert!(
            io.is_empty(),
            "control steps must not enter the bulk script"
        );

        // Get Max LUN replied with `num_luns - 1`.
        assert_eq!(gadget.replies.len(), 1);
        assert_eq!(gadget.replies[0].sent.lock().unwrap().as_slice(), &[1u8]);
        // Bot Reset acked (after the reset).
        assert_eq!(gadget.acks.len(), 1);
        assert!(gadget.acks[0].acked.load(Ordering::SeqCst));
        // Link Reset returned to the Command phase without a UA ack handle.
        // (A fresh empty LUN slice avoids the `Luns` element-lifetime coupling.)
        let mut poll_devs: [&mut dyn ScsiDevice; 0] = [];
        match session.poll(Event::Tick, &mut work, &mut poll_devs) {
            Action::HostRecv {
                len: CBW_LEN,
                probe: false,
            } => {}
            _ => panic!("expected the command boundary after LinkReset"),
        }
    }
}
