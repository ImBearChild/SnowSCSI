//! Integration tests for the USB MSC Bulk-Only Transport session core
//! (§7.2): command sequences, CSW validation, phase/invalid-CBW/invalid-LUN
//! error paths, the usb-storage probe script, control-request ordering,
//! reset-during-data-phase, and cross-platform data-phase regressions.
//!
//! All tests are deterministic, single-threaded and need no root: the host
//! side is a scripted `MockBotIo` + `MockGadget` driving the same
//! non-blocking `BotSession` poll core the PC driver uses.

use crate::mock_bot::{MockAck, MockBotIo, MockGadget, MockReply};
use snowscsi::scsi::backend::RamBackend;
use snowscsi::scsi::block::BlockDevice;
use snowscsi::scsi::device::ScsiDevice;
use snowscsi::usb::{
    BotIo, BotIoErr, BotSession, BotStepResult, CtrlAck, CtrlReply, CtrlReq, Gadget, SessionEvent,
    SessionNeed, SessionStep, ShortfallPolicy, CBW_LEN, CBW_SIGNATURE, CSW_LEN,
};
use std::sync::atomic::Ordering;

/// A 64 KiB block device over stack-owned RAM.
pub(crate) fn block_device<'a>(ram: &'a mut [u8]) -> BlockDevice<RamBackend<'a>> {
    BlockDevice::disk(RamBackend::new(ram), 512).unwrap()
}

pub(crate) fn device_read(dev: &mut BlockDevice<RamBackend<'_>>, offset: u64, buf: &mut [u8]) {
    use embedded_io::{Read, Seek};
    dev.backend()
        .seek(embedded_io::SeekFrom::Start(offset))
        .unwrap();
    dev.backend().read_exact(buf).unwrap();
}

/// Build a raw 31-byte CBW from its logical fields (little endian).
pub(crate) fn raw_cbw(tag: u32, data_len: u32, flags: u8, lun: u8, cdb: &[u8]) -> [u8; CBW_LEN] {
    let mut raw = [0u8; CBW_LEN];
    raw[0..4].copy_from_slice(&CBW_SIGNATURE.to_le_bytes());
    raw[4..8].copy_from_slice(&tag.to_le_bytes());
    raw[8..12].copy_from_slice(&data_len.to_le_bytes());
    raw[12] = flags;
    raw[13] = lun;
    raw[14] = cdb.len() as u8;
    raw[15..15 + cdb.len().min(16)].copy_from_slice(&cdb[..cdb.len().min(16)]);
    raw
}

/// Build a 10-byte READ/WRITE CDB (LBA at bytes 2-5, count at bytes 7-8).
pub(crate) fn rw10(opcode: u8, lba: u32, blocks: u16) -> [u8; 10] {
    let mut cdb = [0u8; 10];
    cdb[0] = opcode;
    cdb[2..6].copy_from_slice(&lba.to_be_bytes());
    cdb[7..9].copy_from_slice(&blocks.to_be_bytes());
    cdb
}

/// Extract (tag, residue, status) from the trailing CSW of a sent stream.
pub(crate) fn csw_fields(sent: &[u8]) -> (u32, u32, u8) {
    let csw = &sent[sent.len() - CSW_LEN..];
    assert_eq!(&csw[..4], b"USBS", "trailing bytes are not a CSW");
    (
        u32::from_le_bytes([csw[4], csw[5], csw[6], csw[7]]),
        u32::from_le_bytes([csw[8], csw[9], csw[10], csw[11]]),
        csw[12],
    )
}

/// Handle a Stalled outcome: STALL both pipes once, or fall back to a reset
/// when STALL is unavailable (§4.5). Returns the outcome when it is final.
fn on_stalled(
    session: &mut BotSession,
    io: &mut MockBotIo,
    stalled: &mut bool,
) -> Option<BotStepResult> {
    if !*stalled {
        if io.stall_both().is_ok() {
            // STALL both pipes and wait for a reset (§4.5).
            *stalled = true;
            return Some(BotStepResult::Stalled);
        }
        // No STALL capability (BOT §4.5): drop the CBW and return to
        // Command. clear_feature_halt() transitions out of the STALLed
        // state without injecting a UA (unlike reset()).
        session.clear_feature_halt();
        return None;
    }
    Some(BotStepResult::Stalled)
}

/// One serve_bot loop iteration (bulk + STALL only; the control gadget is
/// handled by [`serve_ctrl_once`]). Returns `Some` when a transaction ends.
fn serve_once(
    session: &mut BotSession,
    io: &mut MockBotIo,
    work: &mut [u8],
    recv: &mut [u8],
    devs: &mut [&mut dyn ScsiDevice],
    stalled: &mut bool,
) -> Option<BotStepResult> {
    match session.need() {
        SessionNeed::NeedOut { len, probe } => match io.try_recv_out(&mut recv[..len]) {
            Ok(n) => {
                let step = session.poll(SessionEvent::OutRecv { data: &recv[..n] }, work, devs);
                match step {
                    SessionStep::Done(BotStepResult::Stalled) => on_stalled(session, io, stalled),
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
                } else {
                    panic!("mock out-queue ran dry on a blocking receive");
                }
                None
            }
            Err(_) => panic!("mock bulk-OUT I/O error"),
        },
        SessionNeed::NeedIn { len } => {
            let bytes = session.out_slice(&work[..]);
            assert_eq!(bytes.len(), len);
            io.send_in(bytes).unwrap();
            let step = session.poll(SessionEvent::InSent, work, devs);
            if let SessionStep::Done(r) = step {
                return Some(r);
            }
            None
        }
        SessionNeed::Done(BotStepResult::Stalled) => on_stalled(session, io, stalled),
        // `Short` needs a control-plane driver; the dedicated shortfall tests
        // drive it explicitly. `serve_once` is only used by non-`Short` tests.
        SessionNeed::NeedStall => panic!("NeedStall: drive ShortfallPolicy::Short explicitly"),
        SessionNeed::Done(r) => Some(r),
    }
}

/// Drive the poll loop until one transaction ends. `stalled` is the driver's
/// local 1-bit state (§6.3): STALL fires only on the first sighting.
fn drive_until_done(
    session: &mut BotSession,
    io: &mut MockBotIo,
    work: &mut [u8],
    recv: &mut [u8],
    devs: &mut [&mut dyn ScsiDevice],
    stalled: &mut bool,
) -> BotStepResult {
    loop {
        if let Some(r) = serve_once(session, io, work, recv, devs, stalled) {
            return r;
        }
    }
}

/// Handle one queued control request the way serve_bot does (§6.3).
fn serve_ctrl_once(session: &mut BotSession, gadget: &mut MockGadget) -> bool {
    if let Some(req) = gadget.try_next_ctrl() {
        match req {
            CtrlReq::BotReset { ack } => {
                session.reset();
                ack.ack();
            }
            CtrlReq::GetMaxLun { mut reply } => {
                reply.send(&[session.max_lun()]).unwrap();
            }
            CtrlReq::LinkReset => session.reset(),
        }
        true
    } else {
        false
    }
}

fn run_command(
    session: &mut BotSession,
    io: &mut MockBotIo,
    work: &mut [u8],
    recv: &mut [u8],
    devs: &mut [&mut dyn ScsiDevice],
    stalled: &mut bool,
    cbw: &[u8; CBW_LEN],
) -> BotStepResult {
    io.feed_out(cbw);
    drive_until_done(session, io, work, recv, devs, stalled)
}

// ── 1. Command sequences ────────────────────────────────────────────

#[test]
fn command_sequence_inquiry_read_capacity_tur() {
    let mut ram = vec![0u8; 64 * 1024];
    let mut dev = block_device(&mut ram);
    let mut s = BotSession::new();
    macro_rules! luns {
        () => {{
            let mut d: [&mut dyn ScsiDevice; 1] = [&mut dev];
            d
        }};
    }
    let mut work = [0u8; snowscsi::MIN_DATA_LEN];
    let mut recv = [0u8; snowscsi::MIN_DATA_LEN];
    let mut io = MockBotIo::new();
    let mut stalled = false;

    // INQUIRY, alloc 36 → 36-byte response, PDT 0 (direct-access block).
    let cdb = [0x12, 0, 0, 0, 36, 0];
    let r = run_command(
        &mut s,
        &mut io,
        &mut work,
        &mut recv,
        &mut luns!(),
        &mut stalled,
        &raw_cbw(1, 36, 0x80, 0, &cdb),
    );
    assert_eq!(r, BotStepResult::Processed);
    let sent = io.take_sent();
    assert_eq!(sent.len(), 36 + CSW_LEN);
    assert_eq!(sent[0] & 0x1F, 0x00);
    assert_eq!(csw_fields(&sent), (1, 0, 0x00));

    // READ CAPACITY(10) → last LBA + block length.
    let cdb = [0x25, 0, 0, 0, 0, 0, 0, 0, 0, 0];
    let r = run_command(
        &mut s,
        &mut io,
        &mut work,
        &mut recv,
        &mut luns!(),
        &mut stalled,
        &raw_cbw(2, 8, 0x80, 0, &cdb),
    );
    assert_eq!(r, BotStepResult::Processed);
    let sent = io.take_sent();
    assert_eq!(sent.len(), 8 + CSW_LEN);
    let last_lba = u32::from_be_bytes([sent[0], sent[1], sent[2], sent[3]]);
    let block_len = u32::from_be_bytes([sent[4], sent[5], sent[6], sent[7]]);
    assert_eq!(last_lba, 127); // 64 KiB / 512 - 1
    assert_eq!(block_len, 512);

    // TEST UNIT READY → no data, Passed CSW.
    let cdb = [0x00, 0, 0, 0, 0, 0];
    let r = run_command(
        &mut s,
        &mut io,
        &mut work,
        &mut recv,
        &mut luns!(),
        &mut stalled,
        &raw_cbw(3, 0, 0, 0, &cdb),
    );
    assert_eq!(r, BotStepResult::Processed);
    let sent = io.take_sent();
    assert_eq!(sent.len(), CSW_LEN);
    assert_eq!(csw_fields(&sent), (3, 0, 0x00));
}

#[test]
fn command_sequence_read_and_write_verify_backend() {
    let mut ram = vec![0u8; 64 * 1024];
    for (i, b) in ram.iter_mut().enumerate() {
        *b = (i % 251) as u8;
    }
    let mut dev = block_device(&mut ram);
    let mut s = BotSession::new();
    macro_rules! luns {
        () => {{
            let mut d: [&mut dyn ScsiDevice; 1] = [&mut dev];
            d
        }};
    }
    let mut work = [0u8; snowscsi::MIN_DATA_LEN];
    let mut recv = [0u8; snowscsi::MIN_DATA_LEN];
    let mut io = MockBotIo::new();
    let mut stalled = false;

    // READ(10) LBA 0, 8 blocks → 4096 bytes (within one 8K chunk).
    let cdb = [0x28, 0, 0, 0, 0, 0, 0, 0, 8, 0];
    let r = run_command(
        &mut s,
        &mut io,
        &mut work,
        &mut recv,
        &mut luns!(),
        &mut stalled,
        &raw_cbw(4, 4096, 0x80, 0, &cdb),
    );
    assert_eq!(r, BotStepResult::Processed);
    let sent = io.take_sent();
    assert_eq!(sent.len(), 4096 + CSW_LEN);
    let mut check = [0u8; 4096];
    device_read(&mut dev, 0, &mut check);
    assert_eq!(&sent[..4096], &check[..]);
    assert_eq!(csw_fields(&sent), (4, 0, 0x00));

    // WRITE(10) LBA 1, 1 block → 512-byte Data-Out phase.
    let payload: Vec<u8> = (0..512u16).map(|i| (i * 7 % 256) as u8).collect();
    let cdb = rw10(0x2A, 1, 1);
    let cbw = raw_cbw(5, 512, 0x00, 0, &cdb);
    io.feed_out(&cbw);
    io.feed_out(&payload);
    let r = drive_until_done(
        &mut s,
        &mut io,
        &mut work,
        &mut recv,
        &mut luns!(),
        &mut stalled,
    );
    assert_eq!(r, BotStepResult::Processed);
    let sent = io.take_sent();
    assert_eq!(sent.len(), CSW_LEN);
    assert_eq!(csw_fields(&sent), (5, 0, 0x00));
    let mut check = [0u8; 512];
    device_read(&mut dev, 512, &mut check);
    assert_eq!(&check[..], payload.as_slice());

    // READ(10) back LBA 1 → the written payload.
    let cdb = rw10(0x28, 1, 1);
    let r = run_command(
        &mut s,
        &mut io,
        &mut work,
        &mut recv,
        &mut luns!(),
        &mut stalled,
        &raw_cbw(6, 512, 0x80, 0, &cdb),
    );
    assert_eq!(r, BotStepResult::Processed);
    let sent = io.take_sent();
    assert_eq!(&sent[..512], payload.as_slice());
}

#[test]
fn command_sequence_mode_sense_and_request_sense_clear() {
    let mut ram = vec![0u8; 64 * 1024];
    let mut dev = block_device(&mut ram);
    let mut s = BotSession::new().with_shortfall(ShortfallPolicy::ShortNoStall);
    macro_rules! luns {
        () => {{
            let mut d: [&mut dyn ScsiDevice; 1] = [&mut dev];
            d
        }};
    }
    let mut work = [0u8; snowscsi::MIN_DATA_LEN];
    let mut recv = [0u8; snowscsi::MIN_DATA_LEN];
    let mut io = MockBotIo::new();
    let mut stalled = false;

    // MODE SENSE(6) 0x3F, alloc 192 → 4-byte header + 24 bytes of pages.
    let cdb = [0x1A, 0, 0x3F, 0, 192, 0];
    let r = run_command(
        &mut s,
        &mut io,
        &mut work,
        &mut recv,
        &mut luns!(),
        &mut stalled,
        &raw_cbw(7, 192, 0x80, 0, &cdb),
    );
    assert_eq!(r, BotStepResult::Processed);
    let sent = io.take_sent();
    assert_eq!(sent.len(), 28 + CSW_LEN);
    assert_eq!(csw_fields(&sent), (7, 192 - 28, 0x00));

    // Out-of-range READ(10) → CHECK CONDITION → ZLP-terminated phase, then
    // Failed CSW with residue = declared (512 - 0 = 512).
    let cdb = [0x28, 0, 0, 0x1F, 0x40, 0, 0, 0, 1, 0]; // LBA beyond 64 KiB
    let r = run_command(
        &mut s,
        &mut io,
        &mut work,
        &mut recv,
        &mut luns!(),
        &mut stalled,
        &raw_cbw(8, 512, 0x80, 0, &cdb),
    );
    assert_eq!(r, BotStepResult::Processed);
    let sent = io.take_sent();
    assert_eq!(csw_fields(&sent), (8, 512, 0x01)); // Failed

    // REQUEST SENSE → LBA OUT OF RANGE; the device clears its sense.
    let cdb = [0x03, 0, 0, 0, 18, 0];
    let r = run_command(
        &mut s,
        &mut io,
        &mut work,
        &mut recv,
        &mut luns!(),
        &mut stalled,
        &raw_cbw(9, 18, 0x80, 0, &cdb),
    );
    assert_eq!(r, BotStepResult::Processed);
    let sent = io.take_sent();
    assert_eq!(sent.len(), 18 + CSW_LEN);
    assert_eq!(sent[0], 0x70);
    assert_eq!(sent[2], 0x05); // ILLEGAL REQUEST
    assert_eq!(sent[12], 0x21); // LBA OUT OF RANGE
    assert_eq!(csw_fields(&sent), (9, 0, 0x00));

    // Second REQUEST SENSE → no sense (cleared).
    let cdb = [0x03, 0, 0, 0, 18, 0];
    let r = run_command(
        &mut s,
        &mut io,
        &mut work,
        &mut recv,
        &mut luns!(),
        &mut stalled,
        &raw_cbw(10, 18, 0x80, 0, &cdb),
    );
    assert_eq!(r, BotStepResult::Processed);
    let sent = io.take_sent();
    assert_eq!(sent[2], 0x00); // NO SENSE
}

// ── 2. CSW validation ───────────────────────────────────────────────

#[test]
fn csw_host_asks_for_more_gets_short_packet_and_residue() {
    let mut ram = vec![0u8; 64 * 1024];
    let mut dev = block_device(&mut ram);
    let mut s = BotSession::new().with_shortfall(ShortfallPolicy::ShortNoStall);
    macro_rules! luns {
        () => {{
            let mut d: [&mut dyn ScsiDevice; 1] = [&mut dev];
            d
        }};
    }
    let mut work = [0u8; snowscsi::MIN_DATA_LEN];
    let mut recv = [0u8; snowscsi::MIN_DATA_LEN];
    let mut io = MockBotIo::new();
    let mut stalled = false;

    // INQUIRY alloc 95 truncates the 96-byte response; host declared 192 → a
    // short packet + residue (no pad, no STALL; see the core's "Data-In
    // shortfall policy").
    let cdb = [0x12, 0, 0, 0, 95, 0];
    let r = run_command(
        &mut s,
        &mut io,
        &mut work,
        &mut recv,
        &mut luns!(),
        &mut stalled,
        &raw_cbw(1, 192, 0x80, 0, &cdb),
    );
    assert_eq!(r, BotStepResult::Processed);
    let sent = io.take_sent();
    assert_eq!(sent.len(), 95 + CSW_LEN);
    assert_eq!(csw_fields(&sent), (1, 192 - 95, 0x00));
    assert_eq!(io.stall_count, 0, "short packet must not STALL");
}

// ── 3. Phase error / invalid LUN ────────────────────────────────────

#[test]
fn phase_error_on_direction_mismatch() {
    let mut ram = vec![0u8; 64 * 1024];
    let mut dev = block_device(&mut ram);
    let mut s = BotSession::new().with_shortfall(ShortfallPolicy::ShortNoStall);
    macro_rules! luns {
        () => {{
            let mut d: [&mut dyn ScsiDevice; 1] = [&mut dev];
            d
        }};
    }
    let mut work = [0u8; snowscsi::MIN_DATA_LEN];
    let mut recv = [0u8; snowscsi::MIN_DATA_LEN];
    let mut io = MockBotIo::new();
    let mut stalled = false;

    // READ(10) declared with Data-Out direction → the host's 512 data-out
    // bytes are drained, then a Phase Error CSW (residue = declared).
    let cdb = [0x28, 0, 0, 0, 0, 0, 0, 0, 1, 0];
    let cbw = raw_cbw(1, 512, 0x00, 0, &cdb);
    io.feed_out(&cbw);
    io.feed_out(&vec![0x00; 512]);
    let r = drive_until_done(
        &mut s,
        &mut io,
        &mut work,
        &mut recv,
        &mut luns!(),
        &mut stalled,
    );
    assert_eq!(r, BotStepResult::Processed);
    let sent = io.take_sent();
    assert_eq!(csw_fields(&sent), (1, 512, 0x02)); // Phase Error
}

#[test]
fn invalid_lun_is_failed_csw_with_sense_not_phase_error() {
    let mut ram = vec![0u8; 64 * 1024];
    let mut dev = block_device(&mut ram);
    let mut s = BotSession::new();
    macro_rules! luns {
        () => {{
            let mut d: [&mut dyn ScsiDevice; 1] = [&mut dev];
            d
        }};
    }
    let mut work = [0u8; snowscsi::MIN_DATA_LEN];
    let mut recv = [0u8; snowscsi::MIN_DATA_LEN];
    let mut io = MockBotIo::new();
    let mut stalled = false;

    // TUR to LUN 3 (only LUN 0 exists) → Failed, NOT Phase Error.
    let cdb = [0x00, 0, 0, 0, 0, 0];
    let r = run_command(
        &mut s,
        &mut io,
        &mut work,
        &mut recv,
        &mut luns!(),
        &mut stalled,
        &raw_cbw(1, 0, 0, 3, &cdb),
    );
    assert_eq!(r, BotStepResult::Processed);
    let sent = io.take_sent();
    assert_eq!(csw_fields(&sent), (1, 0, 0x01)); // Failed

    // REQUEST SENSE to LUN 3 → LOGICAL UNIT NOT SUPPORTED.
    let cdb = [0x03, 0, 0, 0, 18, 0];
    let r = run_command(
        &mut s,
        &mut io,
        &mut work,
        &mut recv,
        &mut luns!(),
        &mut stalled,
        &raw_cbw(2, 18, 0x80, 3, &cdb),
    );
    assert_eq!(r, BotStepResult::Processed);
    let sent = io.take_sent();
    assert_eq!(sent[12], 0x25);
    assert_eq!(csw_fields(&sent), (2, 0, 0x00));
}

// ── 4. Invalid CBW: both STALL paths ────────────────────────────────

#[test]
fn invalid_cbw_with_stall_available_freezes_until_reset() {
    let mut ram = vec![0u8; 64 * 1024];
    let mut dev = block_device(&mut ram);
    let mut s = BotSession::new();
    macro_rules! luns {
        () => {{
            let mut d: [&mut dyn ScsiDevice; 1] = [&mut dev];
            d
        }};
    }
    let mut work = [0u8; snowscsi::MIN_DATA_LEN];
    let mut recv = [0u8; snowscsi::MIN_DATA_LEN];
    let mut io = MockBotIo::new();
    let mut stalled = false;

    // Bad signature.
    let mut bad = raw_cbw(1, 0, 0, 0, &[0x00, 0, 0, 0, 0, 0]);
    bad[0] = b'X';
    io.feed_out(&bad);
    let r = drive_until_done(
        &mut s,
        &mut io,
        &mut work,
        &mut recv,
        &mut luns!(),
        &mut stalled,
    );
    assert_eq!(r, BotStepResult::Stalled);
    assert_eq!(io.stall_count, 1, "both pipes STALLed once");
    assert!(io.in_.is_empty(), "no CSW for an invalid CBW");

    // Frozen: another drive leaves it Stalled without re-STALLing.
    let r = drive_until_done(
        &mut s,
        &mut io,
        &mut work,
        &mut recv,
        &mut luns!(),
        &mut stalled,
    );
    assert_eq!(r, BotStepResult::Stalled);
    assert_eq!(io.stall_count, 1);

    // BOT §3.1: BotReset preserves STALL. The host must send
    // CLEAR FEATURE(ENDPOINT_HALT) to unfreeze.
    s.reset();
    s.clear_feature_halt();
    stalled = false;
    let cdb = [0x12, 0, 0, 0, 36, 0];
    let r = run_command(
        &mut s,
        &mut io,
        &mut work,
        &mut recv,
        &mut luns!(),
        &mut stalled,
        &raw_cbw(2, 36, 0x80, 0, &cdb),
    );
    assert_eq!(r, BotStepResult::Processed);
    let sent = io.take_sent();
    assert_eq!(csw_fields(&sent), (2, 0, 0x00));
}

#[test]
fn invalid_cbw_without_stall_falls_back_to_command() {
    let mut ram = vec![0u8; 64 * 1024];
    let mut dev = block_device(&mut ram);
    let mut s = BotSession::new();
    macro_rules! luns {
        () => {{
            let mut d: [&mut dyn ScsiDevice; 1] = [&mut dev];
            d
        }};
    }
    let mut work = [0u8; snowscsi::MIN_DATA_LEN];
    let mut recv = [0u8; snowscsi::MIN_DATA_LEN];
    let mut io = MockBotIo::new();
    io.stall_available = false;
    let mut stalled = false;

    // Bad signature followed by a valid CBW: no STALL, no CSW for the bad
    // one, then the valid one is processed (§4.5 fallback).
    let mut bad = raw_cbw(1, 0, 0, 0, &[0x00, 0, 0, 0, 0, 0]);
    bad[0] = b'X';
    io.feed_out(&bad);
    let cdb = [0x12, 0, 0, 0, 36, 0];
    io.feed_out(&raw_cbw(2, 36, 0x80, 0, &cdb));
    let r = drive_until_done(
        &mut s,
        &mut io,
        &mut work,
        &mut recv,
        &mut luns!(),
        &mut stalled,
    );
    assert_eq!(r, BotStepResult::Processed);
    assert_eq!(io.stall_count, 0, "STALL unavailable → fallback reset");
    let sent = io.take_sent();
    assert_eq!(csw_fields(&sent), (2, 0, 0x00));
}

// ── 5. usb-storage probe script ─────────────────────────────────────

#[test]
fn host_probe_script_drives_serve_bot() {
    let mut ram = vec![0u8; 64 * 1024];
    for (i, b) in ram.iter_mut().enumerate() {
        *b = (i * 13 % 256) as u8;
    }
    let mut dev = block_device(&mut ram);
    let mut s = BotSession::new();
    macro_rules! luns {
        () => {{
            let mut d: [&mut dyn ScsiDevice; 1] = [&mut dev];
            d
        }};
    }
    let mut work = [0u8; snowscsi::MIN_DATA_LEN];
    let mut recv = [0u8; snowscsi::MIN_DATA_LEN];
    let mut io = MockBotIo::new();
    let mut gadget = MockGadget::new();
    let mut stalled = false;

    // 1) Get Max LUN (control request) → 0.
    let reply = MockReply::new();
    gadget.inject(CtrlReq::GetMaxLun {
        reply: reply.clone(),
    });
    assert!(serve_ctrl_once(&mut s, &mut gadget));
    assert_eq!(reply.sent.lock().unwrap().as_slice(), &[0u8]);

    // 2) TUR.
    let cdb = [0x00, 0, 0, 0, 0, 0];
    let r = run_command(
        &mut s,
        &mut io,
        &mut work,
        &mut recv,
        &mut luns!(),
        &mut stalled,
        &raw_cbw(1, 0, 0, 0, &cdb),
    );
    assert_eq!(r, BotStepResult::Processed);
    io.take_sent();

    // 3) INQUIRY (alloc 36) → PDT 0.
    let cdb = [0x12, 0, 0, 0, 36, 0];
    let r = run_command(
        &mut s,
        &mut io,
        &mut work,
        &mut recv,
        &mut luns!(),
        &mut stalled,
        &raw_cbw(2, 36, 0x80, 0, &cdb),
    );
    assert_eq!(r, BotStepResult::Processed);
    let sent = io.take_sent();
    assert_eq!(sent[0] & 0x1F, 0x00);

    // 4) READ CAPACITY(10) → 8 bytes.
    let cdb = [0x25, 0, 0, 0, 0, 0, 0, 0, 0, 0];
    let r = run_command(
        &mut s,
        &mut io,
        &mut work,
        &mut recv,
        &mut luns!(),
        &mut stalled,
        &raw_cbw(3, 8, 0x80, 0, &cdb),
    );
    assert_eq!(r, BotStepResult::Processed);
    let sent = io.take_sent();
    assert_eq!(sent.len(), 8 + CSW_LEN);

    // 5) READ(10) LBA 5, 1 block → data matches the backend.
    let cdb = rw10(0x28, 5, 1);
    let r = run_command(
        &mut s,
        &mut io,
        &mut work,
        &mut recv,
        &mut luns!(),
        &mut stalled,
        &raw_cbw(4, 512, 0x80, 0, &cdb),
    );
    assert_eq!(r, BotStepResult::Processed);
    let sent = io.take_sent();
    let mut check = [0u8; 512];
    device_read(&mut dev, 5 * 512, &mut check);
    assert_eq!(&sent[..512], &check[..]);
    assert_eq!(csw_fields(&sent), (4, 0, 0x00));
}

// ── 6. Reset + unit attention ───────────────────────────────────────

#[test]
fn reset_injects_unit_attention() {
    let mut ram = vec![0u8; 64 * 1024];
    let mut dev = block_device(&mut ram);
    let mut s = BotSession::new();
    macro_rules! luns {
        () => {{
            let mut d: [&mut dyn ScsiDevice; 1] = [&mut dev];
            d
        }};
    }
    let mut work = [0u8; snowscsi::MIN_DATA_LEN];
    let mut recv = [0u8; snowscsi::MIN_DATA_LEN];
    let mut io = MockBotIo::new();
    let mut stalled = false;

    s.reset();

    // First TUR → CHECK CONDITION (UA), Failed CSW.
    let cdb = [0x00, 0, 0, 0, 0, 0];
    let r = run_command(
        &mut s,
        &mut io,
        &mut work,
        &mut recv,
        &mut luns!(),
        &mut stalled,
        &raw_cbw(1, 0, 0, 0, &cdb),
    );
    assert_eq!(r, BotStepResult::Processed);
    let sent = io.take_sent();
    assert_eq!(csw_fields(&sent), (1, 0, 0x01));

    // REQUEST SENSE → the UA is reported and cleared.
    let cdb = [0x03, 0, 0, 0, 18, 0];
    let r = run_command(
        &mut s,
        &mut io,
        &mut work,
        &mut recv,
        &mut luns!(),
        &mut stalled,
        &raw_cbw(2, 18, 0x80, 0, &cdb),
    );
    assert_eq!(r, BotStepResult::Processed);
    let sent = io.take_sent();
    assert_eq!(sent[2], 0x06); // UNIT ATTENTION
    assert_eq!(sent[12], 0x29);
    assert_eq!(sent[13], 0x00);

    // Subsequent TUR → GOOD.
    let cdb = [0x00, 0, 0, 0, 0, 0];
    let r = run_command(
        &mut s,
        &mut io,
        &mut work,
        &mut recv,
        &mut luns!(),
        &mut stalled,
        &raw_cbw(3, 0, 0, 0, &cdb),
    );
    assert_eq!(r, BotStepResult::Processed);
    let sent = io.take_sent();
    assert_eq!(csw_fields(&sent), (3, 0, 0x00));
}

// ── 7. Control requests (poll-driven) ───────────────────────────────

#[test]
fn control_requests_get_max_lun_and_bot_reset() {
    let mut s = BotSession::new();
    let mut gadget = MockGadget::new();

    // Get Max LUN → [max_lun]; never STALLs, never errors.
    let reply = MockReply::new();
    gadget.inject(CtrlReq::GetMaxLun {
        reply: reply.clone(),
    });
    assert!(serve_ctrl_once(&mut s, &mut gadget));
    assert_eq!(reply.sent.lock().unwrap().as_slice(), &[0u8]);
    assert_eq!(
        s.need(),
        SessionNeed::NeedOut {
            len: 31,
            probe: false
        }
    );

    // Bot Reset → reset() before ack; back to Command.
    let acked = MockAck::new();
    gadget.inject(CtrlReq::BotReset { ack: acked.clone() });
    assert!(serve_ctrl_once(&mut s, &mut gadget));
    assert!(acked.acked.load(Ordering::SeqCst), "ack called after reset");
    assert_eq!(
        s.need(),
        SessionNeed::NeedOut {
            len: 31,
            probe: false
        }
    );

    // LinkReset → same as a reset.
    gadget.inject(CtrlReq::LinkReset);
    assert!(serve_ctrl_once(&mut s, &mut gadget));
    assert_eq!(
        s.need(),
        SessionNeed::NeedOut {
            len: 31,
            probe: false
        }
    );
}

// ── 8. Reset during a data phase ────────────────────────────────────

#[test]
fn bot_reset_interrupts_data_phase() {
    let mut ram = vec![0u8; 64 * 1024];
    let mut dev = block_device(&mut ram);
    let mut s = BotSession::new();
    macro_rules! luns {
        () => {{
            let mut d: [&mut dyn ScsiDevice; 1] = [&mut dev];
            d
        }};
    }
    let mut work = [0u8; snowscsi::MIN_DATA_LEN];
    let mut recv = [0u8; snowscsi::MIN_DATA_LEN];
    let mut io = MockBotIo::new();
    let mut gadget = MockGadget::new();
    let mut stalled = false;

    // WRITE CBW → data phase.
    let cdb = [0x2A, 0, 0, 0, 0, 0, 0, 0, 1, 0];
    io.feed_out(&raw_cbw(1, 512, 0x00, 0, &cdb));
    assert!(serve_once(
        &mut s,
        &mut io,
        &mut work,
        &mut recv,
        &mut luns!(),
        &mut stalled
    )
    .is_none());
    assert_eq!(
        s.need(),
        SessionNeed::NeedOut {
            len: 512,
            probe: false
        }
    );

    // Partial data received.
    io.feed_out(&[0xAA; 128]);
    assert!(serve_once(
        &mut s,
        &mut io,
        &mut work,
        &mut recv,
        &mut luns!(),
        &mut stalled
    )
    .is_none());
    assert_eq!(
        s.need(),
        SessionNeed::NeedOut {
            len: 384,
            probe: false
        }
    );

    // Bot Reset arrives mid-phase: the transaction is aborted and ack
    // follows reset().
    let acked = MockAck::new();
    gadget.inject(CtrlReq::BotReset { ack: acked.clone() });
    assert!(serve_ctrl_once(&mut s, &mut gadget));
    assert!(acked.acked.load(Ordering::SeqCst));
    assert_eq!(
        s.need(),
        SessionNeed::NeedOut {
            len: 31,
            probe: false
        }
    );

    // A new valid CBW is processed.
    let cdb = [0x12, 0, 0, 0, 36, 0];
    let r = run_command(
        &mut s,
        &mut io,
        &mut work,
        &mut recv,
        &mut luns!(),
        &mut stalled,
        &raw_cbw(2, 36, 0x80, 0, &cdb),
    );
    assert_eq!(r, BotStepResult::Processed);
    let sent = io.take_sent();
    assert_eq!(csw_fields(&sent), (2, 0, 0x00));
}

// ── 9. Cross-platform data-phase regressions (§4.7) ─────────────────

#[test]
fn mode_sense_10_and_prevent_allow() {
    let mut ram = vec![0u8; 64 * 1024];
    let mut dev = block_device(&mut ram);
    let mut s = BotSession::new().with_shortfall(ShortfallPolicy::ShortNoStall);
    macro_rules! luns {
        () => {{
            let mut d: [&mut dyn ScsiDevice; 1] = [&mut dev];
            d
        }};
    }
    let mut work = [0u8; snowscsi::MIN_DATA_LEN];
    let mut recv = [0u8; snowscsi::MIN_DATA_LEN];
    let mut io = MockBotIo::new();
    let mut stalled = false;

    // MODE SENSE(10) 0x3F alloc 192 → 8-byte header + 24 pages.
    let cdb = [0x5A, 0, 0x3F, 0, 0, 0, 0, 0, 192, 0];
    let r = run_command(
        &mut s,
        &mut io,
        &mut work,
        &mut recv,
        &mut luns!(),
        &mut stalled,
        &raw_cbw(1, 192, 0x80, 0, &cdb),
    );
    assert_eq!(r, BotStepResult::Processed);
    let sent = io.take_sent();
    assert_eq!(sent.len(), 32 + CSW_LEN);
    assert_eq!(csw_fields(&sent), (1, 192 - 32, 0x00));
    assert_eq!(io.stall_count, 0);

    // PREVENT ALLOW MEDIUM REMOVAL (prevent) → no data, Passed.
    let cdb = [0x1E, 0, 0, 0, 0x01, 0];
    let r = run_command(
        &mut s,
        &mut io,
        &mut work,
        &mut recv,
        &mut luns!(),
        &mut stalled,
        &raw_cbw(2, 0, 0, 0, &cdb),
    );
    assert_eq!(r, BotStepResult::Processed);
    let sent = io.take_sent();
    assert_eq!(sent.len(), CSW_LEN);
    assert_eq!(csw_fields(&sent), (2, 0, 0x00));
}

#[test]
fn request_sense_with_large_allocation_is_short_packet() {
    let mut ram = vec![0u8; 64 * 1024];
    let mut dev = block_device(&mut ram);
    let mut s = BotSession::new().with_shortfall(ShortfallPolicy::ShortNoStall);
    macro_rules! luns {
        () => {{
            let mut d: [&mut dyn ScsiDevice; 1] = [&mut dev];
            d
        }};
    }
    let mut work = [0u8; snowscsi::MIN_DATA_LEN];
    let mut recv = [0u8; snowscsi::MIN_DATA_LEN];
    let mut io = MockBotIo::new();
    let mut stalled = false;

    // Cause a CC first.
    let cdb = [0x28, 0, 0, 0x1F, 0x40, 0, 0, 0, 1, 0];
    let r = run_command(
        &mut s,
        &mut io,
        &mut work,
        &mut recv,
        &mut luns!(),
        &mut stalled,
        &raw_cbw(1, 512, 0x80, 0, &cdb),
    );
    assert_eq!(r, BotStepResult::Processed);
    io.take_sent();

    // REQUEST SENSE alloc 64 → 18-byte sense + residue, no STALL.
    let cdb = [0x03, 0, 0, 0, 64, 0];
    let r = run_command(
        &mut s,
        &mut io,
        &mut work,
        &mut recv,
        &mut luns!(),
        &mut stalled,
        &raw_cbw(2, 64, 0x80, 0, &cdb),
    );
    assert_eq!(r, BotStepResult::Processed);
    let sent = io.take_sent();
    assert_eq!(sent.len(), 18 + CSW_LEN);
    assert_eq!(csw_fields(&sent), (2, 64 - 18, 0x00));
    assert_eq!(io.stall_count, 0);
}

#[test]
fn data_in_exact_mps_boundary_sends_no_zlp() {
    let mut ram = vec![0u8; 64 * 1024];
    for (i, b) in ram.iter_mut().enumerate() {
        *b = (i % 97) as u8;
    }
    let mut dev = block_device(&mut ram);
    let mut s = BotSession::new();
    macro_rules! luns {
        () => {{
            let mut d: [&mut dyn ScsiDevice; 1] = [&mut dev];
            d
        }};
    }
    let mut work = [0u8; snowscsi::MIN_DATA_LEN];
    let mut recv = [0u8; snowscsi::MIN_DATA_LEN];
    let mut io = MockBotIo::new();
    let mut stalled = false;

    // READ(10) 1 block = 512 bytes = one MPS multiple. The data phase must
    // be exactly 512 bytes with the CSW immediately after — no ZLP.
    let cdb = [0x28, 0, 0, 0, 0, 0, 0, 0, 1, 0];
    let r = run_command(
        &mut s,
        &mut io,
        &mut work,
        &mut recv,
        &mut luns!(),
        &mut stalled,
        &raw_cbw(1, 512, 0x80, 0, &cdb),
    );
    assert_eq!(r, BotStepResult::Processed);
    let sent = io.take_sent();
    assert_eq!(sent.len(), 512 + CSW_LEN);
    let mut check = [0u8; 512];
    device_read(&mut dev, 0, &mut check);
    assert_eq!(&sent[..512], &check[..]);
    assert_eq!(csw_fields(&sent), (1, 0, 0x00));
    // Back in Command, ready for the next CBW.
    assert_eq!(
        s.need(),
        SessionNeed::NeedOut {
            len: 31,
            probe: false
        }
    );
}

#[test]
fn data_out_host_overrun_is_drained() {
    let mut ram = vec![0u8; 64 * 1024];
    let mut dev = block_device(&mut ram);
    let mut s = BotSession::new();
    macro_rules! luns {
        () => {{
            let mut d: [&mut dyn ScsiDevice; 1] = [&mut dev];
            d
        }};
    }
    let mut work = [0u8; snowscsi::MIN_DATA_LEN];
    let mut recv = [0u8; snowscsi::MIN_DATA_LEN];
    let mut io = MockBotIo::new();
    let mut stalled = false;

    // WRITE(10) 512 bytes, but the host transmits 512 + 100 extra bytes.
    let cdb = [0x2A, 0, 0, 0, 0, 0, 0, 0, 1, 0];
    io.feed_out(&raw_cbw(1, 512, 0x00, 0, &cdb));
    io.feed_out(&[0x5A; 512]);
    io.feed_out(&[0x6B; 100]);
    let r = drive_until_done(
        &mut s,
        &mut io,
        &mut work,
        &mut recv,
        &mut luns!(),
        &mut stalled,
    );
    assert_eq!(r, BotStepResult::Processed);

    // Only the declared 512 bytes were written; the excess was discarded.
    let mut check = [0u8; 512];
    device_read(&mut dev, 0, &mut check);
    assert!(check.iter().all(|&b| b == 0x5A));
    let mut tail = [0u8; 128];
    device_read(&mut dev, 512, &mut tail);
    assert!(tail.iter().all(|&b| b == 0));
    let sent = io.take_sent();
    assert_eq!(csw_fields(&sent), (1, 0, 0x00));
}

#[test]
fn opcode_report_luns_synthesized() {
    let mut ram = vec![0u8; 64 * 1024];
    let mut dev = block_device(&mut ram);
    let mut s = BotSession::new();
    macro_rules! luns {
        () => {{
            let mut d: [&mut dyn ScsiDevice; 1] = [&mut dev];
            d
        }};
    }
    let mut work = [0u8; snowscsi::MIN_DATA_LEN];
    let mut recv = [0u8; snowscsi::MIN_DATA_LEN];
    let mut io = MockBotIo::new();
    let mut stalled = false;

    let cdb = [0xA0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 16];
    let r = run_command(
        &mut s,
        &mut io,
        &mut work,
        &mut recv,
        &mut luns!(),
        &mut stalled,
        &raw_cbw(1, 16, 0x80, 0, &cdb),
    );
    assert_eq!(r, BotStepResult::Processed);
    let sent = io.take_sent();
    assert_eq!(sent.len(), 16 + CSW_LEN);
    assert_eq!(u32::from_be_bytes([sent[0], sent[1], sent[2], sent[3]]), 8);
    assert_eq!(sent[8], 0x00); // address method 00b
    assert_eq!(sent[9], 0x00); // LUN id 0
}

// ── 10. Data-In shortfall policy: Short / Pad / ShortNoStall ────────

/// Drive a `Short`-policy transaction to completion, servicing one `stall_in`
/// on `NeedStall` and then releasing the stall (no CLEAR_FEATURE event exists
/// to wait for). Returns `None` when `stall_in` failed and the loop aborted
/// via `reset()`.
fn drive_short(
    session: &mut BotSession,
    io: &mut MockBotIo,
    work: &mut [u8],
    recv: &mut [u8],
    devs: &mut [&mut dyn ScsiDevice],
) -> Option<BotStepResult> {
    let mut stalled_once = false;
    loop {
        match session.need() {
            SessionNeed::NeedOut { len, probe } => match io.try_recv_out(&mut recv[..len]) {
                Ok(n) => {
                    let step = session.poll(SessionEvent::OutRecv { data: &recv[..n] }, work, devs);
                    if let SessionStep::Done(r) = step {
                        return Some(r);
                    }
                }
                Err(BotIoErr::WouldBlock) => {
                    assert!(probe, "mock out-queue ran dry on a blocking receive");
                    let step = session.poll(SessionEvent::OutIdle, work, devs);
                    if let SessionStep::Done(r) = step {
                        return Some(r);
                    }
                }
                Err(_) => panic!("mock bulk-OUT I/O error"),
            },
            SessionNeed::NeedIn { len } => {
                let bytes = session.out_slice(&work[..]);
                assert_eq!(bytes.len(), len);
                io.send_in(bytes).unwrap();
                let step = session.poll(SessionEvent::InSent, work, devs);
                if let SessionStep::Done(r) = step {
                    return Some(r);
                }
            }
            SessionNeed::NeedStall => {
                assert!(!stalled_once, "stall was not released");
                stalled_once = true;
                if io.stall_in().is_err() {
                    // Abort deterministically.
                    session.reset();
                    return None;
                }
                // Release the stall; the withheld CSW follows.
                session.stall_applied();
            }
            SessionNeed::Done(r) => return Some(r),
        }
    }
}

#[test]
fn short_policy_stalls_then_applied_releases_csw() {
    let mut ram = vec![0u8; 64 * 1024];
    let mut dev = block_device(&mut ram);
    let mut s = BotSession::new().with_shortfall(ShortfallPolicy::Short);
    let mut work = [0u8; snowscsi::MIN_DATA_LEN];
    let mut recv = [0u8; snowscsi::MIN_DATA_LEN];
    let mut io = MockBotIo::new();
    let mut luns: [&mut dyn ScsiDevice; 1] = [&mut dev];

    // READ(10) 1 block (512, an MPS multiple) vs declared 1024.
    let cdb = rw10(0x28, 0, 1);
    io.feed_out(&raw_cbw(1, 1024, 0x80, 0, &cdb));
    assert_eq!(
        drive_short(&mut s, &mut io, &mut work, &mut recv, &mut luns),
        Some(BotStepResult::Processed)
    );

    // 512 relevant + a ZLP (empty → adds nothing) + CSW; no padding, no stall_both.
    let sent = io.take_sent();
    assert_eq!(sent.len(), 512 + CSW_LEN, "no pad, no stray bytes");
    assert_eq!(csw_fields(&sent), (1, 1024 - 512, 0x00));
    assert_eq!(io.stall_in_count, 1, "Bulk-In STALLed once");
    assert_eq!(io.stall_count, 0, "stall_both unused for a shortfall");
}

#[test]
fn short_policy_non_mps_shortfall_stalls_without_zlp() {
    let mut ram = vec![0u8; 64 * 1024];
    let mut dev = block_device(&mut ram);
    let mut s = BotSession::new().with_shortfall(ShortfallPolicy::Short);
    let mut work = [0u8; snowscsi::MIN_DATA_LEN];
    let mut recv = [0u8; snowscsi::MIN_DATA_LEN];
    let mut io = MockBotIo::new();
    let mut luns: [&mut dyn ScsiDevice; 1] = [&mut dev];

    // INQUIRY alloc 95 vs declared 192: the short packet ends the read.
    let cdb = [0x12, 0, 0, 0, 95, 0];
    io.feed_out(&raw_cbw(2, 192, 0x80, 0, &cdb));
    assert_eq!(
        drive_short(&mut s, &mut io, &mut work, &mut recv, &mut luns),
        Some(BotStepResult::Processed)
    );
    let sent = io.take_sent();
    assert_eq!(sent.len(), 95 + CSW_LEN);
    assert_eq!(csw_fields(&sent), (2, 192 - 95, 0x00));
    assert_eq!(io.stall_in_count, 1);
}

#[test]
fn short_policy_stall_failure_resets_transaction() {
    let mut ram = vec![0u8; 64 * 1024];
    let mut dev = block_device(&mut ram);
    let mut s = BotSession::new().with_shortfall(ShortfallPolicy::Short);
    let mut work = [0u8; snowscsi::MIN_DATA_LEN];
    let mut recv = [0u8; snowscsi::MIN_DATA_LEN];
    let mut io = MockBotIo::new().set_stall_in(false);
    let mut luns: [&mut dyn ScsiDevice; 1] = [&mut dev];

    let cdb = rw10(0x28, 0, 1);
    io.feed_out(&raw_cbw(3, 1024, 0x80, 0, &cdb));
    // `stall_in` unavailable → the driver aborts via reset.
    assert_eq!(
        drive_short(&mut s, &mut io, &mut work, &mut recv, &mut luns),
        None
    );
    assert_eq!(
        s.need(),
        SessionNeed::NeedOut {
            len: CBW_LEN,
            probe: false
        }
    );
    // Only the 512 relevant bytes went out; the withheld CSW was dropped.
    assert_eq!(io.in_.len(), 512, "no CSW emitted on the abort");
}

#[test]
fn default_policy_is_short_no_stall() {
    assert_eq!(ShortfallPolicy::default(), ShortfallPolicy::ShortNoStall);
    assert_eq!(BotSession::new().shortfall(), ShortfallPolicy::ShortNoStall);

    // The default ending is the plain short packet (no STALL, no pad).
    let mut ram = vec![0u8; 64 * 1024];
    let mut dev = block_device(&mut ram);
    let mut s = BotSession::new(); // no selector: exercise the default
    let mut work = [0u8; snowscsi::MIN_DATA_LEN];
    let mut recv = [0u8; snowscsi::MIN_DATA_LEN];
    let mut io = MockBotIo::new();
    let mut stalled = false;
    let mut luns: [&mut dyn ScsiDevice; 1] = [&mut dev];

    // INQUIRY alloc 95 vs declared 192.
    let cdb = [0x12, 0, 0, 0, 95, 0];
    io.feed_out(&raw_cbw(5, 192, 0x80, 0, &cdb));
    let r = drive_until_done(
        &mut s,
        &mut io,
        &mut work,
        &mut recv,
        &mut luns,
        &mut stalled,
    );
    assert_eq!(r, BotStepResult::Processed);
    let sent = io.take_sent();
    assert_eq!(sent.len(), 95 + CSW_LEN);
    assert_eq!(csw_fields(&sent), (5, 192 - 95, 0x00));
    assert_eq!(io.stall_count, 0);
    assert_eq!(io.stall_in_count, 0);
}
