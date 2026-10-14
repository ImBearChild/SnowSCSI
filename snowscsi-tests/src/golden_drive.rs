//! Driver A: the single-loop BOT driver used to **record** the golden
//! baseline on the pre-refactor code (`__ASYNC_SEP_PLAN.md` §3 / §5.1).
//!
//! It is the `serve_once` loop of [`crate::usb_bot`] rewritten for the
//! recording seams ([`RecBotIo`]/[`RecGadget`]; the only driver that records
//! the baseline), with the `drive_short` `NeedStall` branch merged in, and it
//! adds the *current-core* unlock dance: after a `Stalled` invalid CBW it
//! calls [`BotSession::clear_feature_halt`] before feeding the next CBW (the
//! `poll` core returns `Done(Stalled)` forever until then). M3 makes the new
//! CBW itself clear the halt, and this driver is deleted at M8.

use snowscsi::scsi::device::ScsiDevice;
use snowscsi::usb::{
    BotIo, BotIoErr, BotSession, BotStepResult, CtrlAck, CtrlReply, CtrlReq, Gadget, SessionEvent,
    SessionNeed, SessionStep, CBW_LEN,
};

use crate::golden::{RecBotIo, RecGadget};

/// Outcome of a whole scenario drive.
#[derive(Debug, Default)]
pub struct DriveReport {
    /// Final transaction result (if any transaction ran).
    pub result: Option<BotStepResult>,
    /// Number of transactions that reached a `Done` state.
    pub transactions: usize,
    /// Number of `stall_both` calls applied.
    pub stalls: u32,
    /// Number of `stall_in` calls applied.
    pub stall_ins: u32,
}

/// Drive the scenario's bulk script to exhaustion.
///
/// The loop services out-of-band control first, then performs one bulk step.
/// An exhausted script at a command boundary ends the drive cleanly; a
/// *mid-transaction* non-probe receive that finds the script exhausted is a
/// test bug (panic), while a probe that finds nothing ends the overrun drain
/// (`OutIdle`).
pub fn drive_usb(
    io: &mut RecBotIo,
    gadget: &mut RecGadget,
    session: &mut BotSession,
    work: &mut [u8],
    recv: &mut [u8],
    devs: &mut [&mut dyn ScsiDevice],
) -> DriveReport {
    let mut report = DriveReport::default();
    // Two independent 1-bit latches, mirroring the two reference drivers:
    // `stall_both_done` is `usb_bot::on_stalled`'s `stalled` (invalid CBW, both
    // pipes) and `stall_in_done` is `usb_bot::drive_short`'s local
    // `stalled_once` (Data-In shortfall, Bulk-In only). They must stay
    // separate: an invalid CBW followed by a `Short` shortfall would otherwise
    // trip the "stall only applied once" assertion.
    let mut stall_both_done = false;
    let mut stall_in_done = false;

    loop {
        // 1. Out-of-band control is serviced between bulk operations.
        if let Some(req) = gadget.try_next_ctrl() {
            match req {
                CtrlReq::BotReset { ack } => {
                    session.reset();
                    ack.ack();
                }
                CtrlReq::GetMaxLun { mut reply } => {
                    let v = session.max_lun();
                    reply.send(&[v]).expect("get-max-lun reply");
                }
                CtrlReq::LinkReset => session.reset(),
            }
            continue;
        }

        // 2. Continuation / terminal decisions.
        match session.need() {
            SessionNeed::Done(BotStepResult::Stalled) => {
                if !stall_both_done {
                    stall_both_done = true;
                    if io.stall_both().is_ok() {
                        report.stalls += 1;
                    } else {
                        // No STALL capability (BOT §4.5): drop the CBW and
                        // return to Command. `clear_feature_halt()` leaves the
                        // STALLed state without injecting a UA (unlike reset()).
                        session.clear_feature_halt();
                        stall_both_done = false;
                    }
                } else if io.is_empty() {
                    report.result = Some(BotStepResult::Stalled);
                    break;
                } else {
                    // The host's CLEAR_FEATURE(ENDPOINT_HALT) is not observable
                    // on the seam; the driver A unlock is an implicit call
                    // before the next CBW. M3 makes the new CBW clear the halt
                    // itself and this call (and this latch) is deleted.
                    session.clear_feature_halt();
                    stall_both_done = false;
                }
                continue;
            }
            // A new command boundary. The previous transaction has fully
            // released (or aborted) its shortfall latch; an empty script ends
            // the drive.
            SessionNeed::NeedOut {
                len: CBW_LEN,
                probe: false,
            } => {
                stall_in_done = false;
                if io.is_empty() {
                    break;
                }
            }
            _ => {}
        }

        // 3. One bulk serve step.
        if let Some(r) = serve_step(
            io,
            session,
            work,
            recv,
            devs,
            &mut stall_in_done,
            &mut report,
        ) {
            report.result = Some(r);
            report.transactions += 1;
        }
    }

    report
}

/// One `need()`-driven bulk step, mirroring `usb_bot::serve_once` plus the
/// merged `drive_short` `NeedStall` arm. Returns `Some` when a transaction
/// ends. `stall_in_done` is the shortfall STALL latch owned by the caller.
fn serve_step(
    io: &mut RecBotIo,
    session: &mut BotSession,
    work: &mut [u8],
    recv: &mut [u8],
    devs: &mut [&mut dyn ScsiDevice],
    stall_in_done: &mut bool,
    report: &mut DriveReport,
) -> Option<BotStepResult> {
    match session.need() {
        SessionNeed::NeedOut { len, probe } => match io.try_recv_out(&mut recv[..len]) {
            Ok(n) => {
                let step = session.poll(SessionEvent::OutRecv { data: &recv[..n] }, work, devs);
                match step {
                    SessionStep::Done(r) => Some(r),
                    _ => None,
                }
            }
            Err(BotIoErr::WouldBlock) => {
                if probe {
                    // No more data ends the overrun drain → CSW.
                    let step = session.poll(SessionEvent::OutIdle, work, devs);
                    if let SessionStep::Done(r) = step {
                        return Some(r);
                    }
                    None
                } else {
                    panic!(
                        "RecBotIo: script ran dry on a blocking bulk-OUT receive \
                         (the scenario forgot to feed {} bytes)",
                        len
                    );
                }
            }
            Err(BotIoErr::Disconnected) => {
                // A gadget is a persistent port: a host unplug resets the
                // session and re-arms (mark already recorded).
                session.reset();
                None
            }
            Err(_) => panic!("RecBotIo: unexpected bulk-OUT I/O error"),
        },
        SessionNeed::NeedIn { len } => {
            let bytes = session.out_slice(&work[..]);
            assert_eq!(
                bytes.len(),
                len,
                "RecBotIo: core offered a bad chunk length"
            );
            io.send_in(bytes).expect("bulk send");
            let step = session.poll(SessionEvent::InSent, work, devs);
            if let SessionStep::Done(r) = step {
                return Some(r);
            }
            None
        }
        SessionNeed::NeedStall => {
            assert!(!*stall_in_done, "stall_in was not released");
            *stall_in_done = true;
            if io.stall_in().is_err() {
                // Deterministic abort (BOT §6.7.2); the transaction died, so
                // the latch must not leak into the next one.
                session.reset();
                *stall_in_done = false;
                return None;
            }
            report.stall_ins += 1;
            // Host CLEAR_FEATURE(ENDPOINT_HALT) is handled by the USB core;
            // release the withheld CSW immediately.
            session.stall_applied();
            None
        }
        SessionNeed::Done(r) => Some(r),
    }
}

#[cfg(test)]
mod tests {
    use super::drive_usb;
    use crate::golden::{split, InStep, TraceEntry, CBW_MAGIC, CSW_MAGIC};
    use snowscsi::scsi::backend::RamBackend;
    use snowscsi::scsi::block::BlockDevice;
    use snowscsi::scsi::device::ScsiDevice;
    use snowscsi::usb::{BotSession, BotStepResult, CBW_LEN, CSW_LEN};

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

    fn block_device<'a>(ram: &'a mut [u8]) -> BlockDevice<RamBackend<'a>> {
        BlockDevice::disk(RamBackend::new(ram), 512).unwrap()
    }

    /// A normal INQUIRY: the CBW in, 36 data bytes and the CSW out.
    #[test]
    fn normal_inquiry_transaction() {
        let mut ram = vec![0u8; 64 * 1024];
        let mut dev = block_device(&mut ram);
        let mut session = BotSession::new();
        let mut work = [0u8; snowscsi::MIN_DATA_LEN];
        let mut recv = [0u8; snowscsi::MIN_DATA_LEN];

        // INQUIRY, allocation length 36, Data-In.
        let cdb = [0x12u8, 0, 0, 0, 36, 0];
        let cbw = raw_cbw(1, 36, 0x80, 0, &cdb);
        let (mut io, mut gadget) = split(vec![InStep::Bytes(cbw.to_vec())]);

        let mut devs: [&mut dyn ScsiDevice; 1] = [&mut dev];
        let report = drive_usb(
            &mut io,
            &mut gadget,
            &mut session,
            &mut work,
            &mut recv,
            &mut devs,
        );

        assert_eq!(report.result, Some(BotStepResult::Processed));
        assert_eq!(report.transactions, 1);
        assert_eq!(report.stalls, 0);
        assert_eq!(report.stall_ins, 0);

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

    /// An invalid CBW STALLs both pipes; the following valid CBW only runs
    /// after the driver A STALLed-state unlock (`clear_feature_halt()`), which
    /// must not itself appear on the wire.
    #[test]
    fn invalid_cbw_stalls_then_unlock_allows_next_cbw() {
        let mut ram = vec![0u8; 64 * 1024];
        let mut dev = block_device(&mut ram);
        let mut session = BotSession::new();
        let mut work = [0u8; snowscsi::MIN_DATA_LEN];
        let mut recv = [0u8; snowscsi::MIN_DATA_LEN];

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
        let report = drive_usb(
            &mut io,
            &mut gadget,
            &mut session,
            &mut work,
            &mut recv,
            &mut devs,
        );

        // Both pipes STALLed exactly once, and the drive recovered to run the
        // valid CBW.
        assert_eq!(report.stalls, 1);
        assert!(
            io.trace.contains(&TraceEntry::Mark("stall_both")),
            "expected a stall_both mark, trace: {:?}",
            io.trace
        );
        assert_eq!(report.result, Some(BotStepResult::Processed));
        assert_eq!(report.transactions, 2, "invalid CBW + valid CBW");

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

    /// The out-of-band control seam is translated per §3: Get Max LUN replies
    /// with `max_lun()`, Bot Reset acks after `reset()`, Link Reset resets.
    #[test]
    fn control_requests_are_serviced() {
        use crate::golden::CtrlStep;
        use std::sync::atomic::Ordering;

        let mut session = BotSession::with_luns(2);
        let mut work = [0u8; snowscsi::MIN_DATA_LEN];
        let mut recv = [0u8; snowscsi::MIN_DATA_LEN];
        let (mut io, mut gadget) = split(vec![
            InStep::Ctrl(CtrlStep::GetMaxLun),
            InStep::Ctrl(CtrlStep::BotReset),
            InStep::Ctrl(CtrlStep::LinkReset),
        ]);

        let mut devs: [&mut dyn ScsiDevice; 0] = [];
        let report = drive_usb(
            &mut io,
            &mut gadget,
            &mut session,
            &mut work,
            &mut recv,
            &mut devs,
        );

        // No bulk command ran; the script ended at a command boundary.
        assert_eq!(report.result, None);
        assert!(
            io.is_empty(),
            "control steps must not enter the bulk script"
        );

        // Get Max LUN replied with `num_luns - 1`.
        assert_eq!(gadget.replies.len(), 1);
        assert_eq!(gadget.replies[0].sent.lock().unwrap().as_slice(), &[1u8]);
        // Bot Reset acked (after reset()).
        assert_eq!(gadget.acks.len(), 1);
        assert!(gadget.acks[0].acked.load(Ordering::SeqCst));
        // Link Reset returned to the Command phase without a UA ack handle.
        assert_eq!(
            session.need(),
            snowscsi::usb::SessionNeed::NeedOut {
                len: CBW_LEN,
                probe: false
            }
        );
    }
}
