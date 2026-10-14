//! Integration tests for the USB MSC Bulk-Only Transport session core
//! (§7.2): command sequences, CSW validation, phase/invalid-CBW/invalid-LUN
//! error paths, the usb-storage probe script, control-request ordering,
//! reset-during-data-phase, and cross-platform data-phase regressions.
//!
//! All tests are deterministic, single-threaded and need no root: the host
//! side is a scripted `MockBotIo` + `MockGadget` driving the same
//! non-blocking `BotSession` `poll` core the PC driver uses.
//!
//! The core is converged on `Action`/`Event` (`__STEP1_USB.md`): the driver
//! holds the pending [`Action`] and feeds back one [`Event`] per I/O
//! completion. There is no `Done` boundary — a completed transaction simply
//! returns the next command-boundary `Action::HostRecv { len: 31, .. }` — so
//! the local helpers below track "a CSW was sent" to end one transaction.

use crate::mock_bot::{MockAck, MockBotIo, MockGadget, MockReply};
use snowscsi::common::store::{StoreOp, StorePlane};
use snowscsi::scsi::backend::{RamBackend, StorageError};
use snowscsi::scsi::block::BlockDevice;
use snowscsi::scsi::device::ScsiDevice;
use snowscsi::usb::{
    Action, BotIo, BotIoErr, BotSession, CtrlAck, CtrlReply, CtrlReq, Event, Gadget,
    ShortfallPolicy, CBW_LEN, CBW_SIGNATURE, CSW_LEN,
};
use std::sync::atomic::Ordering;

/// A 64 KiB block device over a caller-owned RAM backend.
///
/// The constructor borrows the backend once for geometry and releases it; the
/// data phase hands the driver a `Store` op to execute against a
/// [`StorePlane`].
pub(crate) fn block_device(backend: &mut RamBackend<'_>) -> BlockDevice {
    BlockDevice::disk(backend, 512).unwrap()
}

/// Read `buf.len()` bytes at `off` through LUN 0's storage plane (the test
/// stand-in for the driver reading the backing store).
fn plane_read(planes: &mut [Option<StorePlane<'_>>], off: u64, buf: &mut [u8]) {
    planes[0]
        .as_mut()
        .unwrap()
        .do_op(StoreOp::Read { off, buf })
        .unwrap();
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

// ── Poll-driven helpers (mirroring `usb::serve`'s bulk arm) ──────────

/// What one `drive_*` call observed for a whole transaction.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Drive {
    /// A CSW was sent and the session returned to the command boundary.
    Processed,
    /// An invalid CBW STALLed both bulk endpoints (no CSW was sent).
    Stalled,
}

/// The pending [`Action`], with every borrow dropped so the driver can touch
/// `work` again before the next `poll`.
enum Step {
    Recv {
        len: usize,
        probe: bool,
    },
    Sent {
        is_csw: bool,
    },
    /// A storage op was executed; the driver feeds `Event::StoreDone`.
    Stored(Result<(), StorageError>),
    StallBoth,
    StallIn,
}

/// Poll the core once with `ev` and classify its `Action`. A `HostSend` is
/// executed here (bulk IN); a `HostRecv` is returned for the driver to fill;
/// an `Action::Store` is executed against the LUN's plane.
fn next_step<D: ScsiDevice>(
    session: &mut BotSession,
    ev: Event,
    work: &mut [u8],
    devs: &mut [D],
    planes: &mut [Option<StorePlane<'_>>],
    io: &mut MockBotIo,
) -> Step {
    match session.poll(ev, work, devs) {
        Action::HostRecv { len, probe } => Step::Recv { len, probe },
        Action::HostSend { bytes, .. } => {
            let is_csw = bytes.len() == CSW_LEN;
            io.send_in(bytes).unwrap();
            Step::Sent { is_csw }
        }
        Action::Store { lun, op } => {
            // Execute the device-produced op on the LUN's plane, exactly like
            // `usb::serve`; the completion is fed back on the next poll.
            let result = planes[lun].as_mut().unwrap().do_op(op);
            Step::Stored(result)
        }
        Action::StallBoth => Step::StallBoth,
        Action::StallIn => Step::StallIn,
        Action::Error(_) => panic!("BOT core error"),
    }
}

/// Drive the poll loop until one transaction ends (a CSW was sent and the
/// session is back at the command boundary) or an invalid CBW STALLed both
/// pipes and the script ran dry. Mirrors `usb::serve`'s bulk arm; the control
/// plane is serviced by [`serve_ctrl_once`] between transactions.
fn drive_until_done<D: ScsiDevice>(
    session: &mut BotSession,
    io: &mut MockBotIo,
    work: &mut [u8],
    devs: &mut [D],
    planes: &mut [Option<StorePlane<'_>>],
) -> Drive {
    let mut ev = Event::Tick;
    let mut csw_sent = false;
    let mut stalled = false;
    loop {
        match next_step(session, ev, work, devs, planes, io) {
            Step::Recv { len, probe } => {
                if csw_sent && len == CBW_LEN && !probe {
                    return Drive::Processed;
                }
                if probe {
                    match io.try_recv_out(&mut work[..len]) {
                        Ok(n) => ev = Event::HostRecv { len: n },
                        Err(BotIoErr::WouldBlock) => ev = Event::HostIdle,
                        Err(_) => panic!("mock bulk-OUT I/O error"),
                    }
                } else {
                    match io.try_recv_out(&mut work[..len]) {
                        Ok(n) if n > 0 => ev = Event::HostRecv { len: n },
                        Err(BotIoErr::WouldBlock) if stalled => return Drive::Stalled,
                        _ => panic!("mock out-queue ran dry on a blocking receive"),
                    }
                }
            }
            Step::Sent { is_csw } => {
                if is_csw {
                    csw_sent = true;
                }
                ev = Event::HostSent;
            }
            Step::Stored(result) => {
                ev = Event::StoreDone { result };
            }
            Step::StallBoth => {
                if io.stall_both().is_ok() {
                    stalled = true;
                }
                // A new CBW arrival clears the halt (the host's
                // CLEAR_FEATURE is handled by the USB core, not observable
                // here), so keep receiving.
                ev = Event::Tick;
            }
            Step::StallIn => panic!("StallIn: drive ShortfallPolicy::Short explicitly"),
        }
    }
}

/// Feed one CBW and drive the transaction to completion.
fn run_command<D: ScsiDevice>(
    session: &mut BotSession,
    io: &mut MockBotIo,
    work: &mut [u8],
    devs: &mut [D],
    planes: &mut [Option<StorePlane<'_>>],
    cbw: &[u8; CBW_LEN],
) -> Drive {
    io.feed_out(cbw);
    drive_until_done(session, io, work, devs, planes)
}

/// Handle one queued control request the way `usb::serve` does (§6.3).
fn serve_ctrl_once<D: ScsiDevice>(
    session: &mut BotSession,
    gadget: &mut MockGadget,
    work: &mut [u8],
    devs: &mut [D],
) -> bool {
    if let Some(req) = gadget.try_next_ctrl() {
        match req {
            CtrlReq::BotReset { ack } => {
                let _ = session.poll(Event::Reset, work, devs);
                ack.ack();
            }
            CtrlReq::GetMaxLun { mut reply } => {
                reply.send(&[session.max_lun()]).unwrap();
            }
            CtrlReq::LinkReset => {
                let _ = session.poll(Event::Reset, work, devs);
            }
        }
        true
    } else {
        false
    }
}

/// Assert the session is at the command boundary (`HostRecv { len: 31 }`).
fn assert_command_boundary<D: ScsiDevice>(
    session: &mut BotSession,
    work: &mut [u8],
    devs: &mut [D],
) {
    match session.poll(Event::Tick, work, devs) {
        Action::HostRecv {
            len: CBW_LEN,
            probe: false,
        } => {}
        _ => panic!("expected the command boundary (HostRecv 31, non-probe)"),
    }
}

// ── 1. Command sequences ────────────────────────────────────────────

#[test]
fn command_sequence_inquiry_read_capacity_tur() {
    let mut ram = vec![0u8; 64 * 1024];
    let mut backend = RamBackend::new(&mut ram);
    let mut dev = block_device(&mut backend);
    let mut s = BotSession::new();
    let mut devs: [&mut dyn ScsiDevice; 1] = [&mut dev];
    let mut planes: [Option<StorePlane<'_>>; 1] = [Some(StorePlane::BlockRw(&mut backend))];
    let mut work = [0u8; snowscsi::MIN_DATA_LEN];
    let mut io = MockBotIo::new();

    // INQUIRY, alloc 36 → 36-byte response, PDT 0 (direct-access block).
    let cdb = [0x12, 0, 0, 0, 36, 0];
    let r = run_command(
        &mut s,
        &mut io,
        &mut work,
        &mut devs,
        &mut planes,
        &raw_cbw(1, 36, 0x80, 0, &cdb),
    );
    assert_eq!(r, Drive::Processed);
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
        &mut devs,
        &mut planes,
        &raw_cbw(2, 8, 0x80, 0, &cdb),
    );
    assert_eq!(r, Drive::Processed);
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
        &mut devs,
        &mut planes,
        &raw_cbw(3, 0, 0, 0, &cdb),
    );
    assert_eq!(r, Drive::Processed);
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
    let mut backend = RamBackend::new(&mut ram);
    let mut dev = block_device(&mut backend);
    let mut s = BotSession::new();
    let mut devs: [&mut dyn ScsiDevice; 1] = [&mut dev];
    let mut planes: [Option<StorePlane<'_>>; 1] = [Some(StorePlane::BlockRw(&mut backend))];
    let mut work = [0u8; snowscsi::MIN_DATA_LEN];
    let mut io = MockBotIo::new();

    // READ(10) LBA 0, 8 blocks → 4096 bytes (within one 8K chunk).
    let cdb = [0x28, 0, 0, 0, 0, 0, 0, 0, 8, 0];
    let r = run_command(
        &mut s,
        &mut io,
        &mut work,
        &mut devs,
        &mut planes,
        &raw_cbw(4, 4096, 0x80, 0, &cdb),
    );
    assert_eq!(r, Drive::Processed);
    let sent = io.take_sent();
    assert_eq!(sent.len(), 4096 + CSW_LEN);
    let mut check = [0u8; 4096];
    plane_read(&mut planes, 0, &mut check);
    assert_eq!(&sent[..4096], &check[..]);
    assert_eq!(csw_fields(&sent), (4, 0, 0x00));

    // WRITE(10) LBA 1, 1 block → 512-byte Data-Out phase.
    let payload: Vec<u8> = (0..512u16).map(|i| (i * 7 % 256) as u8).collect();
    let cdb = rw10(0x2A, 1, 1);
    let cbw = raw_cbw(5, 512, 0x00, 0, &cdb);
    io.feed_out(&cbw);
    io.feed_out(&payload);
    let r = drive_until_done(&mut s, &mut io, &mut work, &mut devs, &mut planes);
    assert_eq!(r, Drive::Processed);
    let sent = io.take_sent();
    assert_eq!(sent.len(), CSW_LEN);
    assert_eq!(csw_fields(&sent), (5, 0, 0x00));
    let mut check = [0u8; 512];
    plane_read(&mut planes, 512, &mut check);
    assert_eq!(&check[..], payload.as_slice());

    // READ(10) back LBA 1 → the written payload.
    let cdb = rw10(0x28, 1, 1);
    let r = run_command(
        &mut s,
        &mut io,
        &mut work,
        &mut devs,
        &mut planes,
        &raw_cbw(6, 512, 0x80, 0, &cdb),
    );
    assert_eq!(r, Drive::Processed);
    let sent = io.take_sent();
    assert_eq!(&sent[..512], payload.as_slice());
}

#[test]
fn command_sequence_mode_sense_and_request_sense_clear() {
    let mut ram = vec![0u8; 64 * 1024];
    let mut backend = RamBackend::new(&mut ram);
    let mut dev = block_device(&mut backend);
    let mut s = BotSession::new().with_shortfall(ShortfallPolicy::ShortNoStall);
    let mut devs: [&mut dyn ScsiDevice; 1] = [&mut dev];
    let mut planes: [Option<StorePlane<'_>>; 1] = [Some(StorePlane::BlockRw(&mut backend))];
    let mut work = [0u8; snowscsi::MIN_DATA_LEN];
    let mut io = MockBotIo::new();

    // MODE SENSE(6) 0x3F, alloc 192 → 4-byte header + 24 bytes of pages.
    let cdb = [0x1A, 0, 0x3F, 0, 192, 0];
    let r = run_command(
        &mut s,
        &mut io,
        &mut work,
        &mut devs,
        &mut planes,
        &raw_cbw(7, 192, 0x80, 0, &cdb),
    );
    assert_eq!(r, Drive::Processed);
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
        &mut devs,
        &mut planes,
        &raw_cbw(8, 512, 0x80, 0, &cdb),
    );
    assert_eq!(r, Drive::Processed);
    let sent = io.take_sent();
    assert_eq!(csw_fields(&sent), (8, 512, 0x01)); // Failed

    // REQUEST SENSE → LBA OUT OF RANGE; the device clears its sense.
    let cdb = [0x03, 0, 0, 0, 18, 0];
    let r = run_command(
        &mut s,
        &mut io,
        &mut work,
        &mut devs,
        &mut planes,
        &raw_cbw(9, 18, 0x80, 0, &cdb),
    );
    assert_eq!(r, Drive::Processed);
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
        &mut devs,
        &mut planes,
        &raw_cbw(10, 18, 0x80, 0, &cdb),
    );
    assert_eq!(r, Drive::Processed);
    let sent = io.take_sent();
    assert_eq!(sent[2], 0x00); // NO SENSE
}

// ── 2. CSW validation ───────────────────────────────────────────────

#[test]
fn csw_host_asks_for_more_gets_short_packet_and_residue() {
    let mut ram = vec![0u8; 64 * 1024];
    let mut backend = RamBackend::new(&mut ram);
    let mut dev = block_device(&mut backend);
    let mut s = BotSession::new().with_shortfall(ShortfallPolicy::ShortNoStall);
    let mut devs: [&mut dyn ScsiDevice; 1] = [&mut dev];
    let mut planes: [Option<StorePlane<'_>>; 1] = [Some(StorePlane::BlockRw(&mut backend))];
    let mut work = [0u8; snowscsi::MIN_DATA_LEN];
    let mut io = MockBotIo::new();

    // INQUIRY alloc 95 truncates the 96-byte response; host declared 192 → a
    // short packet + residue (no pad, no STALL; see the core's "Data-In
    // shortfall policy").
    let cdb = [0x12, 0, 0, 0, 95, 0];
    let r = run_command(
        &mut s,
        &mut io,
        &mut work,
        &mut devs,
        &mut planes,
        &raw_cbw(1, 192, 0x80, 0, &cdb),
    );
    assert_eq!(r, Drive::Processed);
    let sent = io.take_sent();
    assert_eq!(sent.len(), 95 + CSW_LEN);
    assert_eq!(csw_fields(&sent), (1, 192 - 95, 0x00));
    assert_eq!(io.stall_count, 0, "short packet must not STALL");
}

// ── 3. Phase error / invalid LUN ────────────────────────────────────

#[test]
fn phase_error_on_direction_mismatch() {
    let mut ram = vec![0u8; 64 * 1024];
    let mut backend = RamBackend::new(&mut ram);
    let mut dev = block_device(&mut backend);
    let mut s = BotSession::new().with_shortfall(ShortfallPolicy::ShortNoStall);
    let mut devs: [&mut dyn ScsiDevice; 1] = [&mut dev];
    let mut planes: [Option<StorePlane<'_>>; 1] = [Some(StorePlane::BlockRw(&mut backend))];
    let mut work = [0u8; snowscsi::MIN_DATA_LEN];
    let mut io = MockBotIo::new();

    // READ(10) declared with Data-Out direction → the host's 512 data-out
    // bytes are drained, then a Phase Error CSW (residue = declared).
    let cdb = [0x28, 0, 0, 0, 0, 0, 0, 0, 1, 0];
    let cbw = raw_cbw(1, 512, 0x00, 0, &cdb);
    io.feed_out(&cbw);
    io.feed_out(&vec![0x00; 512]);
    let r = drive_until_done(&mut s, &mut io, &mut work, &mut devs, &mut planes);
    assert_eq!(r, Drive::Processed);
    let sent = io.take_sent();
    assert_eq!(csw_fields(&sent), (1, 512, 0x02)); // Phase Error
}

#[test]
fn invalid_lun_is_failed_csw_with_sense_not_phase_error() {
    let mut ram = vec![0u8; 64 * 1024];
    let mut backend = RamBackend::new(&mut ram);
    let mut dev = block_device(&mut backend);
    let mut s = BotSession::new();
    let mut devs: [&mut dyn ScsiDevice; 1] = [&mut dev];
    let mut planes: [Option<StorePlane<'_>>; 1] = [Some(StorePlane::BlockRw(&mut backend))];
    let mut work = [0u8; snowscsi::MIN_DATA_LEN];
    let mut io = MockBotIo::new();

    // TUR to LUN 3 (only LUN 0 exists) → Failed, NOT Phase Error.
    let cdb = [0x00, 0, 0, 0, 0, 0];
    let r = run_command(
        &mut s,
        &mut io,
        &mut work,
        &mut devs,
        &mut planes,
        &raw_cbw(1, 0, 0, 3, &cdb),
    );
    assert_eq!(r, Drive::Processed);
    let sent = io.take_sent();
    assert_eq!(csw_fields(&sent), (1, 0, 0x01)); // Failed

    // REQUEST SENSE to LUN 3 → LOGICAL UNIT NOT SUPPORTED.
    let cdb = [0x03, 0, 0, 0, 18, 0];
    let r = run_command(
        &mut s,
        &mut io,
        &mut work,
        &mut devs,
        &mut planes,
        &raw_cbw(2, 18, 0x80, 3, &cdb),
    );
    assert_eq!(r, Drive::Processed);
    let sent = io.take_sent();
    assert_eq!(sent[12], 0x25);
    assert_eq!(csw_fields(&sent), (2, 0, 0x00));
}

// ── 4. Invalid CBW: both STALL paths ────────────────────────────────

#[test]
fn invalid_cbw_stalls_both_then_new_cbw_recovers() {
    let mut ram = vec![0u8; 64 * 1024];
    let mut backend = RamBackend::new(&mut ram);
    let mut dev = block_device(&mut backend);
    let mut s = BotSession::new();
    let mut devs: [&mut dyn ScsiDevice; 1] = [&mut dev];
    let mut planes: [Option<StorePlane<'_>>; 1] = [Some(StorePlane::BlockRw(&mut backend))];
    let mut work = [0u8; snowscsi::MIN_DATA_LEN];
    let mut io = MockBotIo::new();

    // Bad signature → STALL both pipes once, no CSW; the session returns to
    // the command phase and the script runs dry.
    let mut bad = raw_cbw(1, 0, 0, 0, &[0x00, 0, 0, 0, 0, 0]);
    bad[0] = b'X';
    io.feed_out(&bad);
    let r = drive_until_done(&mut s, &mut io, &mut work, &mut devs, &mut planes);
    assert_eq!(r, Drive::Stalled);
    assert_eq!(io.stall_count, 1, "both pipes STALLed once");
    assert!(io.in_.is_empty(), "no CSW for an invalid CBW");

    // A new CBW arrival clears the halt (CLEAR_FEATURE(ENDPOINT_HALT) is
    // handled by the USB core and is not observable here); the valid CBW is
    // then processed.
    let cdb = [0x12, 0, 0, 0, 36, 0];
    let r = run_command(
        &mut s,
        &mut io,
        &mut work,
        &mut devs,
        &mut planes,
        &raw_cbw(2, 36, 0x80, 0, &cdb),
    );
    assert_eq!(r, Drive::Processed);
    let sent = io.take_sent();
    assert_eq!(csw_fields(&sent), (2, 0, 0x00));
    assert_eq!(io.stall_count, 1, "no re-STALL after a valid CBW");
}

#[test]
fn invalid_cbw_without_stall_falls_back_to_command() {
    let mut ram = vec![0u8; 64 * 1024];
    let mut backend = RamBackend::new(&mut ram);
    let mut dev = block_device(&mut backend);
    let mut s = BotSession::new();
    let mut devs: [&mut dyn ScsiDevice; 1] = [&mut dev];
    let mut planes: [Option<StorePlane<'_>>; 1] = [Some(StorePlane::BlockRw(&mut backend))];
    let mut work = [0u8; snowscsi::MIN_DATA_LEN];
    let mut io = MockBotIo::new();
    io.stall_available = false;

    // Bad signature followed by a valid CBW: no STALL, no CSW for the bad
    // one, then the valid one is processed (§4.5 fallback).
    let mut bad = raw_cbw(1, 0, 0, 0, &[0x00, 0, 0, 0, 0, 0]);
    bad[0] = b'X';
    io.feed_out(&bad);
    let cdb = [0x12, 0, 0, 0, 36, 0];
    io.feed_out(&raw_cbw(2, 36, 0x80, 0, &cdb));
    let r = drive_until_done(&mut s, &mut io, &mut work, &mut devs, &mut planes);
    assert_eq!(r, Drive::Processed);
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
    let mut backend = RamBackend::new(&mut ram);
    let mut dev = block_device(&mut backend);
    let mut s = BotSession::new();
    let mut devs: [&mut dyn ScsiDevice; 1] = [&mut dev];
    let mut planes: [Option<StorePlane<'_>>; 1] = [Some(StorePlane::BlockRw(&mut backend))];
    let mut work = [0u8; snowscsi::MIN_DATA_LEN];
    let mut io = MockBotIo::new();
    let mut gadget = MockGadget::new();

    // 1) Get Max LUN (control request) → 0.
    let reply = MockReply::new();
    gadget.inject(CtrlReq::GetMaxLun {
        reply: reply.clone(),
    });
    assert!(serve_ctrl_once(&mut s, &mut gadget, &mut work, &mut devs));
    assert_eq!(reply.sent.lock().unwrap().as_slice(), &[0u8]);

    // 2) TUR.
    let cdb = [0x00, 0, 0, 0, 0, 0];
    let r = run_command(
        &mut s,
        &mut io,
        &mut work,
        &mut devs,
        &mut planes,
        &raw_cbw(1, 0, 0, 0, &cdb),
    );
    assert_eq!(r, Drive::Processed);
    io.take_sent();

    // 3) INQUIRY (alloc 36) → PDT 0.
    let cdb = [0x12, 0, 0, 0, 36, 0];
    let r = run_command(
        &mut s,
        &mut io,
        &mut work,
        &mut devs,
        &mut planes,
        &raw_cbw(2, 36, 0x80, 0, &cdb),
    );
    assert_eq!(r, Drive::Processed);
    let sent = io.take_sent();
    assert_eq!(sent[0] & 0x1F, 0x00);

    // 4) READ CAPACITY(10) → 8 bytes.
    let cdb = [0x25, 0, 0, 0, 0, 0, 0, 0, 0, 0];
    let r = run_command(
        &mut s,
        &mut io,
        &mut work,
        &mut devs,
        &mut planes,
        &raw_cbw(3, 8, 0x80, 0, &cdb),
    );
    assert_eq!(r, Drive::Processed);
    let sent = io.take_sent();
    assert_eq!(sent.len(), 8 + CSW_LEN);

    // 5) READ(10) LBA 5, 1 block → data matches the backend.
    let cdb = rw10(0x28, 5, 1);
    let r = run_command(
        &mut s,
        &mut io,
        &mut work,
        &mut devs,
        &mut planes,
        &raw_cbw(4, 512, 0x80, 0, &cdb),
    );
    assert_eq!(r, Drive::Processed);
    let sent = io.take_sent();
    let mut check = [0u8; 512];
    plane_read(&mut planes, 5 * 512, &mut check);
    assert_eq!(&sent[..512], &check[..]);
    assert_eq!(csw_fields(&sent), (4, 0, 0x00));
}

// ── 6. Reset + unit attention ───────────────────────────────────────

#[test]
fn reset_injects_unit_attention() {
    let mut ram = vec![0u8; 64 * 1024];
    let mut backend = RamBackend::new(&mut ram);
    let mut dev = block_device(&mut backend);
    let mut s = BotSession::new();
    let mut devs: [&mut dyn ScsiDevice; 1] = [&mut dev];
    let mut planes: [Option<StorePlane<'_>>; 1] = [Some(StorePlane::BlockRw(&mut backend))];
    let mut work = [0u8; snowscsi::MIN_DATA_LEN];
    let mut io = MockBotIo::new();

    let _ = s.poll(Event::Reset, &mut work, &mut devs);

    // First TUR → CHECK CONDITION (UA), Failed CSW.
    let cdb = [0x00, 0, 0, 0, 0, 0];
    let r = run_command(
        &mut s,
        &mut io,
        &mut work,
        &mut devs,
        &mut planes,
        &raw_cbw(1, 0, 0, 0, &cdb),
    );
    assert_eq!(r, Drive::Processed);
    let sent = io.take_sent();
    assert_eq!(csw_fields(&sent), (1, 0, 0x01));

    // REQUEST SENSE → the UA is reported and cleared.
    let cdb = [0x03, 0, 0, 0, 18, 0];
    let r = run_command(
        &mut s,
        &mut io,
        &mut work,
        &mut devs,
        &mut planes,
        &raw_cbw(2, 18, 0x80, 0, &cdb),
    );
    assert_eq!(r, Drive::Processed);
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
        &mut devs,
        &mut planes,
        &raw_cbw(3, 0, 0, 0, &cdb),
    );
    assert_eq!(r, Drive::Processed);
    let sent = io.take_sent();
    assert_eq!(csw_fields(&sent), (3, 0, 0x00));
}

// ── 7. Control requests (poll-driven) ───────────────────────────────

#[test]
fn control_requests_get_max_lun_and_bot_reset() {
    let mut s = BotSession::new();
    let mut gadget = MockGadget::new();
    let mut work = [0u8; snowscsi::MIN_DATA_LEN];
    let mut no_devs: [&mut dyn ScsiDevice; 0] = [];

    // Get Max LUN → [max_lun]; never STALLs, never errors.
    let reply = MockReply::new();
    gadget.inject(CtrlReq::GetMaxLun {
        reply: reply.clone(),
    });
    assert!(serve_ctrl_once(
        &mut s,
        &mut gadget,
        &mut work,
        &mut no_devs
    ));
    assert_eq!(reply.sent.lock().unwrap().as_slice(), &[0u8]);
    assert_command_boundary(&mut s, &mut work, &mut no_devs);

    // Bot Reset → reset before ack; back to Command.
    let acked = MockAck::new();
    gadget.inject(CtrlReq::BotReset { ack: acked.clone() });
    assert!(serve_ctrl_once(
        &mut s,
        &mut gadget,
        &mut work,
        &mut no_devs
    ));
    assert!(acked.acked.load(Ordering::SeqCst), "ack called after reset");
    assert_command_boundary(&mut s, &mut work, &mut no_devs);

    // LinkReset → same as a reset.
    gadget.inject(CtrlReq::LinkReset);
    assert!(serve_ctrl_once(
        &mut s,
        &mut gadget,
        &mut work,
        &mut no_devs
    ));
    assert_command_boundary(&mut s, &mut work, &mut no_devs);
}

// ── 8. Reset during a data phase ────────────────────────────────────

#[test]
fn bot_reset_interrupts_data_phase() {
    let mut ram = vec![0u8; 64 * 1024];
    let mut backend = RamBackend::new(&mut ram);
    let mut dev = block_device(&mut backend);
    let mut s = BotSession::new();
    let mut devs: [&mut dyn ScsiDevice; 1] = [&mut dev];
    let mut planes: [Option<StorePlane<'_>>; 1] = [Some(StorePlane::BlockRw(&mut backend))];
    let mut work = [0u8; snowscsi::MIN_DATA_LEN];
    let mut io = MockBotIo::new();
    let mut gadget = MockGadget::new();

    // WRITE CBW → data phase.
    let cdb = [0x2A, 0, 0, 0, 0, 0, 0, 0, 1, 0];
    io.feed_out(&raw_cbw(1, 512, 0x00, 0, &cdb));
    let len = match s.poll(Event::Tick, &mut work, &mut devs) {
        Action::HostRecv { len, probe: false } => len,
        _ => panic!("expected a CBW receive"),
    };
    assert_eq!(len, CBW_LEN);
    let n = io.try_recv_out(&mut work[..len]).unwrap();
    assert_eq!(n, CBW_LEN);
    match s.poll(Event::HostRecv { len: n }, &mut work, &mut devs) {
        Action::HostRecv {
            len: 512,
            probe: false,
        } => {}
        _ => panic!("expected a 512-byte Data-Out need"),
    }

    // Partial data received: the session hands the 128 received bytes to the
    // device as a Store(Write); once executed it asks for the remaining 384.
    io.feed_out(&[0xAA; 128]);
    let n = io.try_recv_out(&mut work[..512]).unwrap();
    assert_eq!(n, 128);
    let result = match s.poll(Event::HostRecv { len: n }, &mut work, &mut devs) {
        Action::Store { lun, op } => planes[lun].as_mut().unwrap().do_op(op),
        _ => panic!("expected a Store for the partial write"),
    };
    match s.poll(Event::StoreDone { result }, &mut work, &mut devs) {
        Action::HostRecv {
            len: 384,
            probe: false,
        } => {}
        _ => panic!("expected 384 more bytes"),
    }

    // Bot Reset arrives mid-phase: the transaction is aborted and ack
    // follows the reset.
    let acked = MockAck::new();
    gadget.inject(CtrlReq::BotReset { ack: acked.clone() });
    assert!(serve_ctrl_once(&mut s, &mut gadget, &mut work, &mut devs));
    assert!(acked.acked.load(Ordering::SeqCst));
    assert_command_boundary(&mut s, &mut work, &mut devs);

    // A new valid CBW is processed.
    let cdb = [0x12, 0, 0, 0, 36, 0];
    let r = run_command(
        &mut s,
        &mut io,
        &mut work,
        &mut devs,
        &mut planes,
        &raw_cbw(2, 36, 0x80, 0, &cdb),
    );
    assert_eq!(r, Drive::Processed);
    let sent = io.take_sent();
    assert_eq!(csw_fields(&sent), (2, 0, 0x00));
}

// ── 9. Cross-platform data-phase regressions (§4.7) ─────────────────

#[test]
fn mode_sense_10_and_prevent_allow() {
    let mut ram = vec![0u8; 64 * 1024];
    let mut backend = RamBackend::new(&mut ram);
    let mut dev = block_device(&mut backend);
    let mut s = BotSession::new().with_shortfall(ShortfallPolicy::ShortNoStall);
    let mut devs: [&mut dyn ScsiDevice; 1] = [&mut dev];
    let mut planes: [Option<StorePlane<'_>>; 1] = [Some(StorePlane::BlockRw(&mut backend))];
    let mut work = [0u8; snowscsi::MIN_DATA_LEN];
    let mut io = MockBotIo::new();

    // MODE SENSE(10) 0x3F alloc 192 → 8-byte header + 24 pages.
    let cdb = [0x5A, 0, 0x3F, 0, 0, 0, 0, 0, 192, 0];
    let r = run_command(
        &mut s,
        &mut io,
        &mut work,
        &mut devs,
        &mut planes,
        &raw_cbw(1, 192, 0x80, 0, &cdb),
    );
    assert_eq!(r, Drive::Processed);
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
        &mut devs,
        &mut planes,
        &raw_cbw(2, 0, 0, 0, &cdb),
    );
    assert_eq!(r, Drive::Processed);
    let sent = io.take_sent();
    assert_eq!(sent.len(), CSW_LEN);
    assert_eq!(csw_fields(&sent), (2, 0, 0x00));
}

#[test]
fn request_sense_with_large_allocation_is_short_packet() {
    let mut ram = vec![0u8; 64 * 1024];
    let mut backend = RamBackend::new(&mut ram);
    let mut dev = block_device(&mut backend);
    let mut s = BotSession::new().with_shortfall(ShortfallPolicy::ShortNoStall);
    let mut devs: [&mut dyn ScsiDevice; 1] = [&mut dev];
    let mut planes: [Option<StorePlane<'_>>; 1] = [Some(StorePlane::BlockRw(&mut backend))];
    let mut work = [0u8; snowscsi::MIN_DATA_LEN];
    let mut io = MockBotIo::new();

    // Cause a CC first.
    let cdb = [0x28, 0, 0, 0x1F, 0x40, 0, 0, 0, 1, 0];
    let r = run_command(
        &mut s,
        &mut io,
        &mut work,
        &mut devs,
        &mut planes,
        &raw_cbw(1, 512, 0x80, 0, &cdb),
    );
    assert_eq!(r, Drive::Processed);
    io.take_sent();

    // REQUEST SENSE alloc 64 → 18-byte sense + residue, no STALL.
    let cdb = [0x03, 0, 0, 0, 64, 0];
    let r = run_command(
        &mut s,
        &mut io,
        &mut work,
        &mut devs,
        &mut planes,
        &raw_cbw(2, 64, 0x80, 0, &cdb),
    );
    assert_eq!(r, Drive::Processed);
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
    let mut backend = RamBackend::new(&mut ram);
    let mut dev = block_device(&mut backend);
    let mut s = BotSession::new();
    let mut devs: [&mut dyn ScsiDevice; 1] = [&mut dev];
    let mut planes: [Option<StorePlane<'_>>; 1] = [Some(StorePlane::BlockRw(&mut backend))];
    let mut work = [0u8; snowscsi::MIN_DATA_LEN];
    let mut io = MockBotIo::new();

    // READ(10) 1 block = 512 bytes = one MPS multiple. The data phase must
    // be exactly 512 bytes with the CSW immediately after — no ZLP.
    let cdb = [0x28, 0, 0, 0, 0, 0, 0, 0, 1, 0];
    let r = run_command(
        &mut s,
        &mut io,
        &mut work,
        &mut devs,
        &mut planes,
        &raw_cbw(1, 512, 0x80, 0, &cdb),
    );
    assert_eq!(r, Drive::Processed);
    let sent = io.take_sent();
    assert_eq!(sent.len(), 512 + CSW_LEN);
    let mut check = [0u8; 512];
    plane_read(&mut planes, 0, &mut check);
    assert_eq!(&sent[..512], &check[..]);
    assert_eq!(csw_fields(&sent), (1, 0, 0x00));
    // Back in Command, ready for the next CBW.
    assert_command_boundary(&mut s, &mut work, &mut devs);
}

#[test]
fn data_out_host_overrun_is_drained() {
    let mut ram = vec![0u8; 64 * 1024];
    let mut backend = RamBackend::new(&mut ram);
    let mut dev = block_device(&mut backend);
    let mut s = BotSession::new();
    let mut devs: [&mut dyn ScsiDevice; 1] = [&mut dev];
    let mut planes: [Option<StorePlane<'_>>; 1] = [Some(StorePlane::BlockRw(&mut backend))];
    let mut work = [0u8; snowscsi::MIN_DATA_LEN];
    let mut io = MockBotIo::new();

    // WRITE(10) 512 bytes, but the host transmits 512 + 100 extra bytes.
    let cdb = [0x2A, 0, 0, 0, 0, 0, 0, 0, 1, 0];
    io.feed_out(&raw_cbw(1, 512, 0x00, 0, &cdb));
    io.feed_out(&[0x5A; 512]);
    io.feed_out(&[0x6B; 100]);
    let r = drive_until_done(&mut s, &mut io, &mut work, &mut devs, &mut planes);
    assert_eq!(r, Drive::Processed);

    // Only the declared 512 bytes were written; the excess was discarded.
    let mut check = [0u8; 512];
    plane_read(&mut planes, 0, &mut check);
    assert!(check.iter().all(|&b| b == 0x5A));
    let mut tail = [0u8; 128];
    plane_read(&mut planes, 512, &mut tail);
    assert!(tail.iter().all(|&b| b == 0));
    let sent = io.take_sent();
    assert_eq!(csw_fields(&sent), (1, 0, 0x00));
}

#[test]
fn opcode_report_luns_synthesized() {
    let mut ram = vec![0u8; 64 * 1024];
    let mut backend = RamBackend::new(&mut ram);
    let mut dev = block_device(&mut backend);
    let mut s = BotSession::new();
    let mut devs: [&mut dyn ScsiDevice; 1] = [&mut dev];
    let mut planes: [Option<StorePlane<'_>>; 1] = [Some(StorePlane::BlockRw(&mut backend))];
    let mut work = [0u8; snowscsi::MIN_DATA_LEN];
    let mut io = MockBotIo::new();

    let cdb = [0xA0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 16];
    let r = run_command(
        &mut s,
        &mut io,
        &mut work,
        &mut devs,
        &mut planes,
        &raw_cbw(1, 16, 0x80, 0, &cdb),
    );
    assert_eq!(r, Drive::Processed);
    let sent = io.take_sent();
    assert_eq!(sent.len(), 16 + CSW_LEN);
    assert_eq!(u32::from_be_bytes([sent[0], sent[1], sent[2], sent[3]]), 8);
    assert_eq!(sent[8], 0x00); // address method 00b
    assert_eq!(sent[9], 0x00); // LUN id 0
}

// ── 10. Data-In shortfall policy: Short / Pad / ShortNoStall ────────

/// Drive a `Short`-policy transaction to completion, servicing one `stall_in`
/// on `Action::StallIn` and then releasing the stall (`Event::StallApplied`;
/// the host's CLEAR_FEATURE is handled by the USB core). Returns `None` when
/// `stall_in` failed and the transaction was aborted via `Event::Reset`.
fn drive_short<D: ScsiDevice>(
    session: &mut BotSession,
    io: &mut MockBotIo,
    work: &mut [u8],
    devs: &mut [D],
    planes: &mut [Option<StorePlane<'_>>],
) -> Option<Drive> {
    let mut ev = Event::Tick;
    let mut csw_sent = false;
    let mut stalled_once = false;
    loop {
        match next_step(session, ev, work, devs, planes, io) {
            Step::Recv { len, probe } => {
                if csw_sent && len == CBW_LEN && !probe {
                    return Some(Drive::Processed);
                }
                if probe {
                    match io.try_recv_out(&mut work[..len]) {
                        Ok(n) => ev = Event::HostRecv { len: n },
                        Err(BotIoErr::WouldBlock) => ev = Event::HostIdle,
                        Err(_) => panic!("mock bulk-OUT I/O error"),
                    }
                } else {
                    match io.try_recv_out(&mut work[..len]) {
                        Ok(n) if n > 0 => ev = Event::HostRecv { len: n },
                        _ => panic!("mock out-queue ran dry on a blocking receive"),
                    }
                }
            }
            Step::Sent { is_csw } => {
                if is_csw {
                    csw_sent = true;
                }
                ev = Event::HostSent;
            }
            Step::Stored(result) => {
                ev = Event::StoreDone { result };
            }
            Step::StallIn => {
                assert!(!stalled_once, "stall was not released");
                stalled_once = true;
                if io.stall_in().is_err() {
                    // Abort deterministically (the withheld CSW is dropped).
                    let _ = session.poll(Event::Reset, work, devs);
                    return None;
                }
                // Release the stall; the withheld CSW follows.
                ev = Event::StallApplied;
            }
            Step::StallBoth => panic!("unexpected StallBoth in a Short-policy drive"),
        }
    }
}

#[test]
fn short_policy_stalls_then_applied_releases_csw() {
    let mut ram = vec![0u8; 64 * 1024];
    let mut backend = RamBackend::new(&mut ram);
    let mut dev = block_device(&mut backend);
    let mut s = BotSession::new().with_shortfall(ShortfallPolicy::Short);
    let mut work = [0u8; snowscsi::MIN_DATA_LEN];
    let mut io = MockBotIo::new();
    let mut devs: [&mut dyn ScsiDevice; 1] = [&mut dev];
    let mut planes: [Option<StorePlane<'_>>; 1] = [Some(StorePlane::BlockRw(&mut backend))];

    // READ(10) 1 block (512, an MPS multiple) vs declared 1024.
    let cdb = rw10(0x28, 0, 1);
    io.feed_out(&raw_cbw(1, 1024, 0x80, 0, &cdb));
    assert_eq!(
        drive_short(&mut s, &mut io, &mut work, &mut devs, &mut planes),
        Some(Drive::Processed)
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
    let mut backend = RamBackend::new(&mut ram);
    let mut dev = block_device(&mut backend);
    let mut s = BotSession::new().with_shortfall(ShortfallPolicy::Short);
    let mut work = [0u8; snowscsi::MIN_DATA_LEN];
    let mut io = MockBotIo::new();
    let mut devs: [&mut dyn ScsiDevice; 1] = [&mut dev];
    let mut planes: [Option<StorePlane<'_>>; 1] = [Some(StorePlane::BlockRw(&mut backend))];

    // INQUIRY alloc 95 vs declared 192: the short packet ends the read.
    let cdb = [0x12, 0, 0, 0, 95, 0];
    io.feed_out(&raw_cbw(2, 192, 0x80, 0, &cdb));
    assert_eq!(
        drive_short(&mut s, &mut io, &mut work, &mut devs, &mut planes),
        Some(Drive::Processed)
    );
    let sent = io.take_sent();
    assert_eq!(sent.len(), 95 + CSW_LEN);
    assert_eq!(csw_fields(&sent), (2, 192 - 95, 0x00));
    assert_eq!(io.stall_in_count, 1);
}

#[test]
fn short_policy_stall_failure_resets_transaction() {
    let mut ram = vec![0u8; 64 * 1024];
    let mut backend = RamBackend::new(&mut ram);
    let mut dev = block_device(&mut backend);
    let mut s = BotSession::new().with_shortfall(ShortfallPolicy::Short);
    let mut work = [0u8; snowscsi::MIN_DATA_LEN];
    let mut io = MockBotIo::new().set_stall_in(false);
    let mut devs: [&mut dyn ScsiDevice; 1] = [&mut dev];
    let mut planes: [Option<StorePlane<'_>>; 1] = [Some(StorePlane::BlockRw(&mut backend))];

    let cdb = rw10(0x28, 0, 1);
    io.feed_out(&raw_cbw(3, 1024, 0x80, 0, &cdb));
    // `stall_in` unavailable → the driver aborts via reset.
    assert_eq!(
        drive_short(&mut s, &mut io, &mut work, &mut devs, &mut planes),
        None
    );
    assert_command_boundary(&mut s, &mut work, &mut devs);
    // Only the 512 relevant bytes went out; the withheld CSW was dropped.
    assert_eq!(io.in_.len(), 512, "no CSW emitted on the abort");
}

#[test]
fn default_policy_is_short_no_stall() {
    assert_eq!(ShortfallPolicy::default(), ShortfallPolicy::ShortNoStall);
    assert_eq!(BotSession::new().shortfall(), ShortfallPolicy::ShortNoStall);

    // The default ending is the plain short packet (no STALL, no pad).
    let mut ram = vec![0u8; 64 * 1024];
    let mut backend = RamBackend::new(&mut ram);
    let mut dev = block_device(&mut backend);
    let mut s = BotSession::new(); // no selector: exercise the default
    let mut work = [0u8; snowscsi::MIN_DATA_LEN];
    let mut io = MockBotIo::new();
    let mut devs: [&mut dyn ScsiDevice; 1] = [&mut dev];
    let mut planes: [Option<StorePlane<'_>>; 1] = [Some(StorePlane::BlockRw(&mut backend))];

    // INQUIRY alloc 95 vs declared 192.
    let cdb = [0x12, 0, 0, 0, 95, 0];
    io.feed_out(&raw_cbw(5, 192, 0x80, 0, &cdb));
    let r = drive_until_done(&mut s, &mut io, &mut work, &mut devs, &mut planes);
    assert_eq!(r, Drive::Processed);
    let sent = io.take_sent();
    assert_eq!(sent.len(), 95 + CSW_LEN);
    assert_eq!(csw_fields(&sent), (5, 192 - 95, 0x00));
    assert_eq!(io.stall_count, 0);
    assert_eq!(io.stall_in_count, 0);
}

/// FORMAT UNIT's whole-disc `Fill` must run through the **session** agenda
/// (never inline in the device). Pre-fill the plane with a pattern so a no-op
/// FORMAT is detectable, drive FORMAT through the session, and assert the
/// plane is zero afterwards. (Golden scenario ⑬ cannot discriminate this: its
/// RAM starts zeroed, so the post-FORMAT read is zero either way.)
#[test]
fn format_unit_zeroes_the_plane_via_the_session_agenda() {
    use snowscsi::cdrom::dvdram::DvdRamMedia;
    use snowscsi::cdrom::{CdMedia, CdromDrive, HYPER_MULTI_CAPS};

    let mut ram = vec![0x5Au8; 1 << 20];
    let mut backend = RamBackend::new(&mut ram);
    let mut drive = CdromDrive::builder().capabilities(HYPER_MULTI_CAPS).build();
    let _ = drive.load_quiet(CdMedia::Rw(DvdRamMedia::open(&mut backend)));

    let mut s = BotSession::new();
    let mut devs: [&mut dyn ScsiDevice; 1] = [&mut drive];
    let mut planes: [Option<StorePlane<'_>>; 1] = [Some(StorePlane::BlockRw(&mut backend))];
    let mut work = [0u8; snowscsi::MIN_DATA_LEN];
    let mut io = MockBotIo::new();

    // FORMAT UNIT (0x04) followed by its 12-byte format parameter list.
    io.feed_out(&raw_cbw(
        1,
        12,
        0x00,
        0,
        &[0x04, 0x11, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0],
    ));
    io.feed_out(&[
        0x00, 0x00, 0x00, 0x08, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x08, 0x00,
    ]);
    let r = drive_until_done(&mut s, &mut io, &mut work, &mut devs, &mut planes);
    assert_eq!(r, Drive::Processed);

    let mut check = vec![0u8; 1 << 20];
    plane_read(&mut planes, 0, &mut check);
    assert!(
        check.iter().all(|&b| b == 0),
        "FORMAT must zero-fill the whole plane through the session agenda"
    );
}
