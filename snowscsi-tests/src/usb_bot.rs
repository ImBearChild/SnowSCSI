//! Integration tests for the USB MSC Bulk-Only Transport session core.
//!
//! Command sequences, CSW validation, phase/invalid-CBW/invalid-LUN error
//! paths, the usb-storage probe script, control-request ordering,
//! reset-during-data-phase, and the Data-In shortfall policy.
//!
//! All tests are deterministic, single-threaded and need no root: the host
//! side is a scripted `MockBotIo` + `MockGadget` driving the same
//! non-blocking `BotSession` `poll` core the PC driver uses, over a real core
//! `Target` and a synchronous storage plane.

use crate::iscsi_harness::{PlaneSet, TestLu, TestPair};
use crate::mock_bot::{MockAck, MockBotIo, MockGadget, MockReply};
use snowscsi::common::store::{StoreOp, StorePlane};
use snowscsi::core::storage::{BankSide, IoBuf, IoReq, IoToken, Storage, StorageReceipt};
use snowscsi::core::{LongPhase, Lu, PendingKind, RuntimeSet, Target};
use snowscsi::scsi::backend::RamBackend;
use snowscsi::usb::{
    serve, Action, BotIo, BotIoErr, BotSession, BotTargetError, CtrlAck, CtrlReply, CtrlReq, Event,
    Gadget, ShortfallPolicy, CBW_LEN, CBW_SIGNATURE, CSW_LEN, MAX_PAD,
};
use std::collections::VecDeque;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::task::Poll;
use std::time::Duration;

/// Read `buf.len()` bytes at `off` through the storage plane (the test
/// stand-in for the driver reading the backing store).
fn plane_read(storage: &mut PlaneSet<'_>, off: u64, buf: &mut [u8]) {
    storage.exec_raw(StoreOp::Read { off, buf }).unwrap();
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
#[derive(Debug)]
enum Step {
    Recv {
        offset: usize,
        len: usize,
        probe: bool,
    },
    Sent {
        is_csw: bool,
    },
    StoragePending,
    StallBoth,
    StallIn,
}

/// Build the slot table: a heterogeneous runtime LUN set.
fn table<L: Lu<Pair = TestPair>>(slots: &mut [L]) -> Vec<&mut dyn Lu<Pair = TestPair>> {
    slots
        .iter_mut()
        .map(|s| s as &mut dyn Lu<Pair = TestPair>)
        .collect()
}

/// Poll the core once with `ev` and classify its `Action`. A `HostSend` is
/// executed here (bulk IN); a `HostRecv` is returned for the driver to fill.
fn next_step<S: RuntimeSet>(
    session: &mut BotSession,
    ev: Event,
    work: &mut [u8],
    scratch: &mut [u8],
    target: &mut Target<S>,
    storage: &mut dyn Storage,
    io: &mut MockBotIo,
) -> Step {
    match session.poll(ev, work, scratch, target, storage) {
        Action::HostRecv { offset, len, probe } => Step::Recv { offset, len, probe },
        Action::HostSend { bytes } => {
            let is_csw = bytes.len() == CSW_LEN;
            io.send_in(bytes).unwrap();
            Step::Sent { is_csw }
        }
        Action::StoragePending => Step::StoragePending,
        Action::StallBoth => Step::StallBoth,
        Action::StallIn => Step::StallIn,
        Action::Error(_) => panic!("BOT core error"),
    }
}

/// Drive the poll loop until one transaction ends (a CSW was sent and the
/// session is back at the command boundary) or an invalid CBW STALLed both
/// pipes and the script ran dry.
fn drive_until_done<S: RuntimeSet>(
    session: &mut BotSession,
    io: &mut MockBotIo,
    work: &mut [u8],
    scratch: &mut [u8],
    target: &mut Target<S>,
    storage: &mut dyn Storage,
) -> Drive {
    let mut ev = Event::Tick;
    let mut csw_sent = false;
    let mut stalled = false;
    loop {
        match next_step(session, ev, work, scratch, target, storage, io) {
            Step::Recv { offset, len, probe } => {
                if csw_sent && len == CBW_LEN && !probe {
                    return Drive::Processed;
                }
                if probe {
                    match io.try_recv_out(&mut work[offset..offset + len]) {
                        Ok(n) => ev = Event::HostRecv { len: n },
                        Err(BotIoErr::WouldBlock) => ev = Event::HostIdle,
                        Err(_) => panic!("mock bulk-OUT I/O error"),
                    }
                } else {
                    match io.try_recv_out(&mut work[offset..offset + len]) {
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
            Step::StallBoth => {
                if io.stall_both().is_ok() {
                    stalled = true;
                }
                // A new CBW arrival clears the halt (the host's
                // CLEAR_FEATURE is handled by the USB core, not observable
                // here), so keep receiving.
                ev = Event::Tick;
            }
            Step::StoragePending => ev = Event::Tick,
            Step::StallIn => panic!("StallIn: drive ShortfallPolicy::Short explicitly"),
        }
    }
}

/// Feed one CBW and drive the transaction to completion.
fn run_command<S: RuntimeSet>(
    session: &mut BotSession,
    io: &mut MockBotIo,
    work: &mut [u8],
    scratch: &mut [u8],
    target: &mut Target<S>,
    storage: &mut PlaneSet<'_>,
    cbw: &[u8; CBW_LEN],
) -> Drive {
    io.feed_out(cbw);
    drive_until_done(session, io, work, scratch, target, storage)
}

/// Handle one queued control request the way `usb::serve` does.
fn serve_ctrl_once<S: RuntimeSet>(
    session: &mut BotSession,
    gadget: &mut MockGadget,
    work: &mut [u8],
    scratch: &mut [u8],
    target: &mut Target<S>,
    storage: &mut PlaneSet<'_>,
) -> bool {
    if let Some(req) = gadget.try_next_ctrl() {
        match req {
            CtrlReq::BotReset { ack } => {
                let _ = session.poll(Event::Reset, work, scratch, target, storage);
                ack.ack();
            }
            CtrlReq::GetMaxLun { mut reply } => {
                reply.send(&[session.max_lun()]).unwrap();
            }
            CtrlReq::LinkReset => {
                let _ = session.poll(Event::Reset, work, scratch, target, storage);
            }
        }
        true
    } else {
        false
    }
}

/// Assert the session is at the command boundary (`HostRecv { len: 31 }`).
fn assert_command_boundary<S: RuntimeSet>(
    session: &mut BotSession,
    work: &mut [u8],
    scratch: &mut [u8],
    target: &mut Target<S>,
    storage: &mut PlaneSet<'_>,
) {
    match session.poll(Event::Tick, work, scratch, target, storage) {
        Action::HostRecv {
            offset: 0,
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
    let mut slots = [TestLu::block(128, 512, 0)];
    let mut storage = PlaneSet::new(vec![Some(StorePlane::BlockRw(&mut backend))]);
    let mut table = table(&mut slots);
    let mut target = Target::new(&mut table[..]);
    let mut s = BotSession::new();
    let mut work = [0u8; snowscsi::MIN_DATA_LEN];
    let mut scratch = [0u8; snowscsi::MIN_DATA_LEN];
    let mut io = MockBotIo::new();

    // INQUIRY, alloc 36 → 36-byte response, PDT 0 (direct-access block).
    let cdb = [0x12, 0, 0, 0, 36, 0];
    let r = run_command(
        &mut s,
        &mut io,
        &mut work,
        &mut scratch,
        &mut target,
        &mut storage,
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
        &mut scratch,
        &mut target,
        &mut storage,
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
        &mut scratch,
        &mut target,
        &mut storage,
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
    let mut slots = [TestLu::block(128, 512, 0)];
    let mut storage = PlaneSet::new(vec![Some(StorePlane::BlockRw(&mut backend))]);
    let mut table = table(&mut slots);
    let mut target = Target::new(&mut table[..]);
    let mut s = BotSession::new();
    let mut work = [0u8; snowscsi::MIN_DATA_LEN];
    let mut scratch = [0u8; snowscsi::MIN_DATA_LEN];
    let mut io = MockBotIo::new();

    // READ(10) LBA 0, 8 blocks → 4096 bytes.
    let cdb = [0x28, 0, 0, 0, 0, 0, 0, 0, 8, 0];
    let r = run_command(
        &mut s,
        &mut io,
        &mut work,
        &mut scratch,
        &mut target,
        &mut storage,
        &raw_cbw(4, 4096, 0x80, 0, &cdb),
    );
    assert_eq!(r, Drive::Processed);
    let sent = io.take_sent();
    assert_eq!(sent.len(), 4096 + CSW_LEN);
    let mut check = [0u8; 4096];
    plane_read(&mut storage, 0, &mut check);
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
        &mut scratch,
        &mut target,
        &mut storage,
    );
    assert_eq!(r, Drive::Processed);
    let sent = io.take_sent();
    assert_eq!(sent.len(), CSW_LEN);
    assert_eq!(csw_fields(&sent), (5, 0, 0x00));
    let mut check = [0u8; 512];
    plane_read(&mut storage, 512, &mut check);
    assert_eq!(&check[..], payload.as_slice());

    // READ(10) back LBA 1 → the written payload.
    let cdb = rw10(0x28, 1, 1);
    let r = run_command(
        &mut s,
        &mut io,
        &mut work,
        &mut scratch,
        &mut target,
        &mut storage,
        &raw_cbw(6, 512, 0x80, 0, &cdb),
    );
    assert_eq!(r, Drive::Processed);
    let sent = io.take_sent();
    assert_eq!(&sent[..512], payload.as_slice());
}

/// A 512-byte work bank (the transport floor) serves a two-block READ and
/// WRITE byte-exactly: the data area is not block-granular.
#[test]
fn floor_work_bank_reads_and_writes_byte_exact() {
    let mut ram = vec![0u8; 64 * 1024];
    for (i, b) in ram.iter_mut().enumerate() {
        *b = (i % 251) as u8;
    }
    let mut backend = RamBackend::new(&mut ram);
    let mut slots = [TestLu::block(128, 512, 0)];
    let mut storage = PlaneSet::new(vec![Some(StorePlane::BlockRw(&mut backend))]);
    let mut table = table(&mut slots);
    let mut target = Target::new(&mut table[..]);
    let mut s = BotSession::new();
    let mut work = [0u8; snowscsi::MIN_DATA_AREA];
    let mut scratch = [0u8; snowscsi::MIN_DATA_LEN];
    let mut io = MockBotIo::new();

    // READ(10) LBA 0, 2 blocks → 1024 bytes through a 512-byte bank.
    let cdb = rw10(0x28, 0, 2);
    let r = run_command(
        &mut s,
        &mut io,
        &mut work,
        &mut scratch,
        &mut target,
        &mut storage,
        &raw_cbw(0x51, 1024, 0x80, 0, &cdb),
    );
    assert_eq!(r, Drive::Processed);
    let sent = io.take_sent();
    assert_eq!(sent.len(), 1024 + CSW_LEN);
    let mut expected = [0u8; 1024];
    plane_read(&mut storage, 0, &mut expected);
    assert_eq!(&sent[..1024], &expected[..], "the floor-bank read is exact");
    assert_eq!(csw_fields(&sent), (0x51, 0, 0x00));

    // WRITE(10) LBA 2, 2 blocks with a 1024-byte Data-Out phase.
    let payload: Vec<u8> = (0..1024u32).map(|i| (i * 11 % 256) as u8).collect();
    let cdb = rw10(0x2A, 2, 2);
    let cbw = raw_cbw(0x52, 1024, 0x00, 0, &cdb);
    io.feed_out(&cbw);
    io.feed_out(&payload);
    assert_eq!(
        drive_until_done(
            &mut s,
            &mut io,
            &mut work,
            &mut scratch,
            &mut target,
            &mut storage,
        ),
        Drive::Processed
    );
    let sent = io.take_sent();
    assert_eq!(csw_fields(&sent), (0x52, 0, 0x00));
    let mut check = [0u8; 1024];
    plane_read(&mut storage, 1024, &mut check);
    assert_eq!(
        &check[..],
        payload.as_slice(),
        "the floor-bank write is exact"
    );
}

/// The work floor is 512 bytes; the long-operation bank keeps its 8192-byte
/// requirement.
#[test]
fn work_bank_below_the_floor_and_short_scratch_are_rejected() {
    let mut ram = vec![0u8; 4096];
    let mut backend = RamBackend::new(&mut ram);
    let mut slots = [TestLu::block(8, 512, 0)];
    let mut storage = PlaneSet::new(vec![Some(StorePlane::BlockRw(&mut backend))]);
    let mut table = table(&mut slots);
    let mut target = Target::new(&mut table[..]);
    let mut s = BotSession::new();

    let mut short_work = [0u8; snowscsi::MIN_DATA_AREA - 1];
    let mut scratch = [0u8; snowscsi::MIN_DATA_LEN];
    assert!(matches!(
        s.poll(
            Event::Tick,
            &mut short_work,
            &mut scratch,
            &mut target,
            &mut storage
        ),
        Action::Error(BotTargetError::WorkBufTooSmall)
    ));

    let mut work = [0u8; snowscsi::MIN_DATA_AREA];
    let mut short_scratch = [0u8; snowscsi::MIN_DATA_LEN - 1];
    assert!(matches!(
        s.poll(
            Event::Tick,
            &mut work,
            &mut short_scratch,
            &mut target,
            &mut storage
        ),
        Action::Error(BotTargetError::WorkBufTooSmall)
    ));
}

// ── Shared bank (one buffer) ───────────────────────────────────────

/// Bulk driver for one shared-bank transaction.
///
/// Records any bulk read issued while the long-operation token is in flight,
/// and stops the shell once the scripted closing CSW was sent (and, for a
/// FORMAT scenario, the fill completed).
struct SharedBankIo {
    out: Arc<Mutex<VecDeque<u8>>>,
    in_: Vec<u8>,
    in_flight: Arc<AtomicBool>,
    fill_done: Arc<AtomicBool>,
    violated: Arc<AtomicBool>,
    stop_tag: u32,
    need_fill_done: bool,
    saw_close_csw: bool,
    stop: Arc<AtomicBool>,
}

impl SharedBankIo {
    fn read(&mut self, buf: &mut [u8]) -> Result<usize, BotIoErr> {
        if self.in_flight.load(Ordering::SeqCst) {
            self.violated.store(true, Ordering::SeqCst);
        }
        let mut q = self.out.lock().unwrap();
        if q.is_empty() {
            let filled = !self.need_fill_done || self.fill_done.load(Ordering::SeqCst);
            if self.saw_close_csw && filled {
                self.stop.store(true, Ordering::SeqCst);
            }
            return Err(BotIoErr::WouldBlock);
        }
        let n = q.len().min(buf.len());
        for (i, b) in q.drain(..n).enumerate() {
            buf[i] = b;
        }
        Ok(n)
    }
}

impl BotIo for SharedBankIo {
    fn try_recv_out(&mut self, buf: &mut [u8]) -> Result<usize, BotIoErr> {
        self.read(buf)
    }

    fn recv_out(&mut self, buf: &mut [u8], _timeout: Option<Duration>) -> Result<usize, BotIoErr> {
        self.read(buf)
    }

    fn send_in(&mut self, buf: &[u8]) -> Result<(), BotIoErr> {
        if buf.len() == CSW_LEN && &buf[..4] == b"USBS" {
            let tag = u32::from_le_bytes([buf[4], buf[5], buf[6], buf[7]]);
            if tag == self.stop_tag {
                self.saw_close_csw = true;
            }
        }
        self.in_.extend_from_slice(buf);
        Ok(())
    }

    fn stall_both(&mut self) -> Result<(), ()> {
        Ok(())
    }

    fn stall_in(&mut self) -> Result<(), ()> {
        Ok(())
    }

    fn can_stall_in(&self) -> bool {
        true
    }
}

/// Storage wrapper: keeps the first long-operation write pending and injects
/// the queued TUR CBW at that moment, so the input arrives exactly while the
/// token is in flight. `fill_done` tracks the format's final durability sync.
struct SharedPlan<'a> {
    inner: PlaneSet<'a>,
    out: Arc<Mutex<VecDeque<u8>>>,
    in_flight: Arc<AtomicBool>,
    fill_done: Arc<AtomicBool>,
    inject: Option<Vec<u8>>,
}

impl Storage for SharedPlan<'_> {
    fn select_lun(&mut self, lun: usize) {
        self.inner.select_lun(lun);
    }

    fn begin_exec(&mut self, req: IoReq) -> IoToken {
        self.inner.begin_exec(req)
    }

    fn poll_exec(&mut self, token: IoToken, buf: IoBuf<'_>) -> Poll<StorageReceipt> {
        if let Some(bytes) = self.inject.take() {
            self.in_flight.store(true, Ordering::SeqCst);
            self.out.lock().unwrap().extend(bytes);
            return Poll::Pending;
        }
        let sync = matches!(buf, IoBuf::None);
        let receipt = self.inner.poll_exec(token, buf);
        if sync {
            self.fill_done.store(true, Ordering::SeqCst);
        }
        self.in_flight.store(false, Ordering::SeqCst);
        receipt
    }

    fn cancel(&mut self, token: IoToken) {
        self.in_flight.store(false, Ordering::SeqCst);
        self.inner.cancel(token);
    }
}

const FORMAT_TAG: u32 = 0x51;
const TUR_TAG: u32 = 0x52;

/// One buffer: a FORMAT UNIT fill starts as the resident long operation, the
/// host's TUR CBW arrives while its token is in flight, and the shell serves
/// the TUR only after the token settles. The fill is byte-exact.
#[test]
fn shared_bank_defers_the_tur_until_the_long_token_settles() {
    let mut ram = vec![0xEEu8; 64 * 1024];
    let out = Arc::new(Mutex::new(VecDeque::new()));
    let in_flight = Arc::new(AtomicBool::new(false));
    let fill_done = Arc::new(AtomicBool::new(false));
    let violated = Arc::new(AtomicBool::new(false));
    let stop = Arc::new(AtomicBool::new(false));

    // FORMAT UNIT (FmtData=1, Format Code 1) with Immed=1 in the Format List
    // Header: the command completes GOOD and leaves a resident fill.
    let mut params = [0u8; 12];
    params[1] = 0x02; // Immed (MMC-6 Table 240)
    params[2..4].copy_from_slice(&8u16.to_be_bytes());
    params[8] = 0x00; // Format Type 0 (full format)
    let tur = raw_cbw(TUR_TAG, 0, 0x80, 0, &[0x00, 0, 0, 0, 0, 0]);
    {
        let mut q = out.lock().unwrap();
        q.extend(raw_cbw(FORMAT_TAG, 12, 0x00, 0, &[0x04, 0x11, 0, 0, 0, 0]));
        q.extend(params);
    }

    let mut io = SharedBankIo {
        out: Arc::clone(&out),
        in_: Vec::new(),
        in_flight: Arc::clone(&in_flight),
        fill_done: Arc::clone(&fill_done),
        violated: Arc::clone(&violated),
        stop_tag: TUR_TAG,
        need_fill_done: true,
        saw_close_csw: false,
        stop: Arc::clone(&stop),
    };
    let mut gadget = MockGadget::new();
    let mut session = BotSession::new();
    // One allocation at the USB floor: the empty scratch selects the shared
    // bank.
    let mut work = vec![0u8; snowscsi::MIN_DATA_AREA];
    let mut scratch = Vec::new();

    let mut slots = [TestLu::dvdram(1, 0)];
    let mut table = table(&mut slots);
    let mut target = Target::new(&mut table[..]);
    {
        let mut backend = RamBackend::new(&mut ram);
        let mut storage = SharedPlan {
            inner: PlaneSet::new(vec![Some(StorePlane::BlockRw(&mut backend))]),
            out: Arc::clone(&out),
            in_flight: Arc::clone(&in_flight),
            fill_done: Arc::clone(&fill_done),
            inject: Some(tur.to_vec()),
        };
        let result = serve(
            &mut io,
            &mut gadget,
            &mut session,
            &mut work,
            &mut scratch,
            &mut target,
            &mut storage,
            &stop,
        );
        assert_eq!(result, Ok(()), "the scripted host ends the session");
    }

    assert!(
        !violated.load(Ordering::SeqCst),
        "the shell read bulk input while the long token was in flight"
    );
    assert!(io.saw_close_csw, "the TUR was serviced");
    assert!(
        ram[..2048].iter().all(|b| *b == 0),
        "the FORMAT fill is byte-exact over the shared bank"
    );
}

/// The 512-byte USB floor with one buffer: a 2 MiB READ streams through the
/// shared bank in 512-byte chunks, byte-exact.
#[test]
fn shared_bank_512_streams_a_two_mib_read() {
    const BLOCKS: u16 = 4096; // 2 MiB at 512-byte blocks
    const TOTAL: usize = BLOCKS as usize * 512;
    const READ_TAG: u32 = 0x61;

    let mut ram = vec![0u8; 4 * 1024 * 1024];
    for (i, b) in ram.iter_mut().enumerate() {
        *b = (i % 251) as u8;
    }
    let expected = ram[..TOTAL].to_vec();

    let out = Arc::new(Mutex::new(VecDeque::new()));
    let stop = Arc::new(AtomicBool::new(false));
    let in_flight = Arc::new(AtomicBool::new(false));
    let fill_done = Arc::new(AtomicBool::new(false));
    let violated = Arc::new(AtomicBool::new(false));
    out.lock().unwrap().extend(raw_cbw(
        READ_TAG,
        TOTAL as u32,
        0x80,
        0,
        &rw10(0x28, 0, BLOCKS),
    ));

    let mut io = SharedBankIo {
        out: Arc::clone(&out),
        in_: Vec::new(),
        in_flight: Arc::clone(&in_flight),
        fill_done: Arc::clone(&fill_done),
        violated: Arc::clone(&violated),
        stop_tag: READ_TAG,
        need_fill_done: false,
        saw_close_csw: false,
        stop: Arc::clone(&stop),
    };
    let mut gadget = MockGadget::new();
    let mut session = BotSession::new();
    let mut work = vec![0u8; snowscsi::MIN_DATA_AREA]; // 512-byte floor
    let mut scratch = Vec::new();

    let mut slots = [TestLu::block(8192, 512, 0)];
    let mut table = table(&mut slots);
    let mut target = Target::new(&mut table[..]);
    {
        let mut backend = RamBackend::new(&mut ram);
        let mut storage = SharedPlan {
            inner: PlaneSet::new(vec![Some(StorePlane::BlockRw(&mut backend))]),
            out: Arc::clone(&out),
            in_flight: Arc::clone(&in_flight),
            fill_done: Arc::clone(&fill_done),
            inject: None,
        };
        let result = serve(
            &mut io,
            &mut gadget,
            &mut session,
            &mut work,
            &mut scratch,
            &mut target,
            &mut storage,
            &stop,
        );
        assert_eq!(result, Ok(()), "the scripted host ends the session");
    }

    assert!(!violated.load(Ordering::SeqCst));
    assert_eq!(io.in_.len(), TOTAL + CSW_LEN, "data plus one CSW");
    assert_eq!(&io.in_[..TOTAL], &expected[..], "the read is byte-exact");
}

#[test]
fn command_sequence_mode_sense_and_request_sense_clear() {
    let mut ram = vec![0u8; 64 * 1024];
    let mut backend = RamBackend::new(&mut ram);
    let mut slots = [TestLu::block(128, 512, 0)];
    let mut storage = PlaneSet::new(vec![Some(StorePlane::BlockRw(&mut backend))]);
    let mut table = table(&mut slots);
    let mut target = Target::new(&mut table[..]);
    let mut s = BotSession::new().with_shortfall(ShortfallPolicy::ShortNoStall);
    let mut work = [0u8; snowscsi::MIN_DATA_LEN];
    let mut scratch = [0u8; snowscsi::MIN_DATA_LEN];
    let mut io = MockBotIo::new();

    // MODE SENSE(6) 0x3F, alloc 192 → 4-byte header + 24 bytes of pages.
    let cdb = [0x1A, 0, 0x3F, 0, 192, 0];
    let r = run_command(
        &mut s,
        &mut io,
        &mut work,
        &mut scratch,
        &mut target,
        &mut storage,
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
        &mut scratch,
        &mut target,
        &mut storage,
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
        &mut scratch,
        &mut target,
        &mut storage,
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
        &mut scratch,
        &mut target,
        &mut storage,
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
    let mut slots = [TestLu::block(128, 512, 0)];
    let mut storage = PlaneSet::new(vec![Some(StorePlane::BlockRw(&mut backend))]);
    let mut table = table(&mut slots);
    let mut target = Target::new(&mut table[..]);
    let mut s = BotSession::new().with_shortfall(ShortfallPolicy::ShortNoStall);
    let mut work = [0u8; snowscsi::MIN_DATA_LEN];
    let mut scratch = [0u8; snowscsi::MIN_DATA_LEN];
    let mut io = MockBotIo::new();

    // INQUIRY alloc 95 is capped by the core's 36-byte page; host declared
    // 192 → a short packet + residue (no pad, no STALL).
    let cdb = [0x12, 0, 0, 0, 95, 0];
    let r = run_command(
        &mut s,
        &mut io,
        &mut work,
        &mut scratch,
        &mut target,
        &mut storage,
        &raw_cbw(1, 192, 0x80, 0, &cdb),
    );
    assert_eq!(r, Drive::Processed);
    let sent = io.take_sent();
    assert_eq!(sent.len(), 36 + CSW_LEN);
    assert_eq!(csw_fields(&sent), (1, 192 - 36, 0x00));
    assert_eq!(io.stall_count, 0, "short packet must not STALL");
}

// ── 3. Phase error / invalid LUN ────────────────────────────────────

#[test]
fn phase_error_on_direction_mismatch() {
    let mut ram = vec![0u8; 64 * 1024];
    let mut backend = RamBackend::new(&mut ram);
    let mut slots = [TestLu::block(128, 512, 0)];
    let mut storage = PlaneSet::new(vec![Some(StorePlane::BlockRw(&mut backend))]);
    let mut table = table(&mut slots);
    let mut target = Target::new(&mut table[..]);
    let mut s = BotSession::new().with_shortfall(ShortfallPolicy::ShortNoStall);
    let mut work = [0u8; snowscsi::MIN_DATA_LEN];
    let mut scratch = [0u8; snowscsi::MIN_DATA_LEN];
    let mut io = MockBotIo::new();

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
        &mut scratch,
        &mut target,
        &mut storage,
    );
    assert_eq!(r, Drive::Processed);
    let sent = io.take_sent();
    assert_eq!(csw_fields(&sent), (1, 512, 0x02)); // Phase Error
}

#[test]
fn invalid_lun_is_failed_csw_with_sense_not_phase_error() {
    let mut ram = vec![0u8; 64 * 1024];
    let mut backend = RamBackend::new(&mut ram);
    let mut slots = [TestLu::block(128, 512, 0)];
    let mut storage = PlaneSet::new(vec![Some(StorePlane::BlockRw(&mut backend))]);
    let mut table = table(&mut slots);
    let mut target = Target::new(&mut table[..]);
    let mut s = BotSession::new();
    let mut work = [0u8; snowscsi::MIN_DATA_LEN];
    let mut scratch = [0u8; snowscsi::MIN_DATA_LEN];
    let mut io = MockBotIo::new();

    // TUR to LUN 3 (only LUN 0 exists) → Failed, NOT Phase Error.
    let cdb = [0x00, 0, 0, 0, 0, 0];
    let r = run_command(
        &mut s,
        &mut io,
        &mut work,
        &mut scratch,
        &mut target,
        &mut storage,
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
        &mut scratch,
        &mut target,
        &mut storage,
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
    let mut slots = [TestLu::block(128, 512, 0)];
    let mut storage = PlaneSet::new(vec![Some(StorePlane::BlockRw(&mut backend))]);
    let mut table = table(&mut slots);
    let mut target = Target::new(&mut table[..]);
    let mut s = BotSession::new();
    let mut work = [0u8; snowscsi::MIN_DATA_LEN];
    let mut scratch = [0u8; snowscsi::MIN_DATA_LEN];
    let mut io = MockBotIo::new();

    // Bad signature → STALL both pipes once, no CSW; the session returns to
    // the command phase and the script runs dry.
    let mut bad = raw_cbw(1, 0, 0, 0, &[0x00, 0, 0, 0, 0, 0]);
    bad[0] = b'X';
    io.feed_out(&bad);
    let r = drive_until_done(
        &mut s,
        &mut io,
        &mut work,
        &mut scratch,
        &mut target,
        &mut storage,
    );
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
        &mut scratch,
        &mut target,
        &mut storage,
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
    let mut slots = [TestLu::block(128, 512, 0)];
    let mut storage = PlaneSet::new(vec![Some(StorePlane::BlockRw(&mut backend))]);
    let mut table = table(&mut slots);
    let mut target = Target::new(&mut table[..]);
    let mut s = BotSession::new();
    let mut work = [0u8; snowscsi::MIN_DATA_LEN];
    let mut scratch = [0u8; snowscsi::MIN_DATA_LEN];
    let mut io = MockBotIo::new();
    io.stall_available = false;

    // Bad signature followed by a valid CBW: no STALL, no CSW for the bad
    // one, then the valid one is processed (fallback).
    let mut bad = raw_cbw(1, 0, 0, 0, &[0x00, 0, 0, 0, 0, 0]);
    bad[0] = b'X';
    io.feed_out(&bad);
    let cdb = [0x12, 0, 0, 0, 36, 0];
    io.feed_out(&raw_cbw(2, 36, 0x80, 0, &cdb));
    let r = drive_until_done(
        &mut s,
        &mut io,
        &mut work,
        &mut scratch,
        &mut target,
        &mut storage,
    );
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
    let mut slots = [TestLu::block(128, 512, 0)];
    let mut storage = PlaneSet::new(vec![Some(StorePlane::BlockRw(&mut backend))]);
    let mut table = table(&mut slots);
    let mut target = Target::new(&mut table[..]);
    let mut s = BotSession::new();
    let mut work = [0u8; snowscsi::MIN_DATA_LEN];
    let mut scratch = [0u8; snowscsi::MIN_DATA_LEN];
    let mut io = MockBotIo::new();
    let mut gadget = MockGadget::new();

    // 1) Get Max LUN (control request) → 0.
    let reply = MockReply::new();
    gadget.inject(CtrlReq::GetMaxLun {
        reply: reply.clone(),
    });
    assert!(serve_ctrl_once(
        &mut s,
        &mut gadget,
        &mut work,
        &mut scratch,
        &mut target,
        &mut storage
    ));
    assert_eq!(reply.sent.lock().unwrap().as_slice(), &[0u8]);

    // 2) TUR.
    let cdb = [0x00, 0, 0, 0, 0, 0];
    let r = run_command(
        &mut s,
        &mut io,
        &mut work,
        &mut scratch,
        &mut target,
        &mut storage,
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
        &mut scratch,
        &mut target,
        &mut storage,
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
        &mut scratch,
        &mut target,
        &mut storage,
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
        &mut scratch,
        &mut target,
        &mut storage,
        &raw_cbw(4, 512, 0x80, 0, &cdb),
    );
    assert_eq!(r, Drive::Processed);
    let sent = io.take_sent();
    let mut check = [0u8; 512];
    plane_read(&mut storage, 5 * 512, &mut check);
    assert_eq!(&sent[..512], &check[..]);
    assert_eq!(csw_fields(&sent), (4, 0, 0x00));
}

// ── 6. Reset + unit attention ───────────────────────────────────────

#[test]
fn reset_injects_unit_attention() {
    let mut ram = vec![0u8; 64 * 1024];
    let mut backend = RamBackend::new(&mut ram);
    let mut slots = [TestLu::block(128, 512, 0)];
    let mut storage = PlaneSet::new(vec![Some(StorePlane::BlockRw(&mut backend))]);
    let mut table = table(&mut slots);
    let mut target = Target::new(&mut table[..]);
    let mut s = BotSession::new();
    let mut work = [0u8; snowscsi::MIN_DATA_LEN];
    let mut scratch = [0u8; snowscsi::MIN_DATA_LEN];
    let mut io = MockBotIo::new();

    let _ = s.poll(
        Event::Reset,
        &mut work,
        &mut scratch,
        &mut target,
        &mut storage,
    );

    // First TUR → CHECK CONDITION (UA), Failed CSW.
    let cdb = [0x00, 0, 0, 0, 0, 0];
    let r = run_command(
        &mut s,
        &mut io,
        &mut work,
        &mut scratch,
        &mut target,
        &mut storage,
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
        &mut scratch,
        &mut target,
        &mut storage,
        &raw_cbw(2, 18, 0x80, 0, &cdb),
    );
    assert_eq!(r, Drive::Processed);
    let sent = io.take_sent();
    assert_eq!(sent[2], 0x06); // UNIT ATTENTION
    assert_eq!(sent[12], 0x29);
    assert_eq!(sent[13], 0x02); // SCSI BUS RESET OCCURRED

    // Subsequent TUR → GOOD.
    let cdb = [0x00, 0, 0, 0, 0, 0];
    let r = run_command(
        &mut s,
        &mut io,
        &mut work,
        &mut scratch,
        &mut target,
        &mut storage,
        &raw_cbw(3, 0, 0, 0, &cdb),
    );
    assert_eq!(r, Drive::Processed);
    let sent = io.take_sent();
    assert_eq!(csw_fields(&sent), (3, 0, 0x00));
}

// ── 7. Control requests (poll-driven) ───────────────────────────────

#[test]
fn control_requests_get_max_lun_and_bot_reset() {
    let mut slots: [TestLu; 0] = [];
    let mut storage = PlaneSet::new(vec![]);
    let mut table = table(&mut slots);
    let mut target = Target::new(&mut table[..]);
    let mut s = BotSession::new();
    let mut gadget = MockGadget::new();
    let mut work = [0u8; snowscsi::MIN_DATA_LEN];
    let mut scratch = [0u8; snowscsi::MIN_DATA_LEN];

    // Get Max LUN → [max_lun]; never STALLs, never errors.
    let reply = MockReply::new();
    gadget.inject(CtrlReq::GetMaxLun {
        reply: reply.clone(),
    });
    assert!(serve_ctrl_once(
        &mut s,
        &mut gadget,
        &mut work,
        &mut scratch,
        &mut target,
        &mut storage
    ));
    assert_eq!(reply.sent.lock().unwrap().as_slice(), &[0u8]);
    assert_command_boundary(&mut s, &mut work, &mut scratch, &mut target, &mut storage);

    // Bot Reset → reset before ack; back to Command.
    let acked = MockAck::new();
    gadget.inject(CtrlReq::BotReset { ack: acked.clone() });
    assert!(serve_ctrl_once(
        &mut s,
        &mut gadget,
        &mut work,
        &mut scratch,
        &mut target,
        &mut storage
    ));
    assert!(acked.acked.load(Ordering::SeqCst), "ack called after reset");
    assert_command_boundary(&mut s, &mut work, &mut scratch, &mut target, &mut storage);

    // LinkReset → same as a reset.
    gadget.inject(CtrlReq::LinkReset);
    assert!(serve_ctrl_once(
        &mut s,
        &mut gadget,
        &mut work,
        &mut scratch,
        &mut target,
        &mut storage
    ));
    assert_command_boundary(&mut s, &mut work, &mut scratch, &mut target, &mut storage);
}

// ── 8. Reset during a data phase ────────────────────────────────────

#[test]
fn bot_reset_interrupts_data_phase() {
    let mut ram = vec![0u8; 64 * 1024];
    let mut backend = RamBackend::new(&mut ram);
    let mut slots = [TestLu::block(128, 512, 0)];
    let mut storage = PlaneSet::new(vec![Some(StorePlane::BlockRw(&mut backend))]);
    let mut table = table(&mut slots);
    let mut target = Target::new(&mut table[..]);
    let mut s = BotSession::new();
    let mut work = [0u8; snowscsi::MIN_DATA_LEN];
    let mut scratch = [0u8; snowscsi::MIN_DATA_LEN];
    let mut io = MockBotIo::new();
    let mut gadget = MockGadget::new();

    // WRITE CBW → data phase.
    let cdb = [0x2A, 0, 0, 0, 0, 0, 0, 0, 1, 0];
    io.feed_out(&raw_cbw(1, 512, 0x00, 0, &cdb));
    let len = match s.poll(
        Event::Tick,
        &mut work,
        &mut scratch,
        &mut target,
        &mut storage,
    ) {
        Action::HostRecv {
            offset,
            len,
            probe: false,
        } => {
            assert_eq!(offset, 0, "a CBW lands at the start of the bank");
            len
        }
        _ => panic!("expected a CBW receive"),
    };
    assert_eq!(len, CBW_LEN);
    let n = io.try_recv_out(&mut work[..len]).unwrap();
    assert_eq!(n, CBW_LEN);
    match s.poll(
        Event::HostRecv { len: n },
        &mut work,
        &mut scratch,
        &mut target,
        &mut storage,
    ) {
        Action::HostRecv {
            offset: 0,
            len: 512,
            probe: false,
        } => {}
        _ => panic!("expected a 512-byte Data-Out need"),
    }

    // Partial data received: the session moves it and asks for the rest.
    io.feed_out(&[0xAA; 128]);
    let n = io.try_recv_out(&mut work[128..512]).unwrap();
    assert_eq!(n, 128);
    match s.poll(
        Event::HostRecv { len: n },
        &mut work,
        &mut scratch,
        &mut target,
        &mut storage,
    ) {
        Action::HostRecv {
            offset: 128,
            len: 384,
            probe: false,
        } => {}
        _ => panic!("expected 384 more bytes"),
    }

    // Bot Reset arrives mid-phase: the transaction is aborted and ack
    // follows the reset.
    let acked = MockAck::new();
    gadget.inject(CtrlReq::BotReset { ack: acked.clone() });
    assert!(serve_ctrl_once(
        &mut s,
        &mut gadget,
        &mut work,
        &mut scratch,
        &mut target,
        &mut storage
    ));
    assert!(acked.acked.load(Ordering::SeqCst));
    assert_command_boundary(&mut s, &mut work, &mut scratch, &mut target, &mut storage);

    // A new valid CBW is processed.
    let cdb = [0x12, 0, 0, 0, 36, 0];
    let r = run_command(
        &mut s,
        &mut io,
        &mut work,
        &mut scratch,
        &mut target,
        &mut storage,
        &raw_cbw(2, 36, 0x80, 0, &cdb),
    );
    assert_eq!(r, Drive::Processed);
    let sent = io.take_sent();
    assert_eq!(csw_fields(&sent), (2, 0, 0x00));
}

// ── 9. Cross-platform data-phase regressions  ─────────────────

#[test]
fn mode_sense_10_and_prevent_allow() {
    let mut ram = vec![0u8; 64 * 1024];
    let mut backend = RamBackend::new(&mut ram);
    let mut slots = [TestLu::block(128, 512, 0)];
    let mut storage = PlaneSet::new(vec![Some(StorePlane::BlockRw(&mut backend))]);
    let mut table = table(&mut slots);
    let mut target = Target::new(&mut table[..]);
    let mut s = BotSession::new().with_shortfall(ShortfallPolicy::ShortNoStall);
    let mut work = [0u8; snowscsi::MIN_DATA_LEN];
    let mut scratch = [0u8; snowscsi::MIN_DATA_LEN];
    let mut io = MockBotIo::new();

    // MODE SENSE(10) 0x3F alloc 192 → 8-byte header + 24 pages.
    let cdb = [0x5A, 0, 0x3F, 0, 0, 0, 0, 0, 192, 0];
    let r = run_command(
        &mut s,
        &mut io,
        &mut work,
        &mut scratch,
        &mut target,
        &mut storage,
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
        &mut scratch,
        &mut target,
        &mut storage,
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
    let mut slots = [TestLu::block(128, 512, 0)];
    let mut storage = PlaneSet::new(vec![Some(StorePlane::BlockRw(&mut backend))]);
    let mut table = table(&mut slots);
    let mut target = Target::new(&mut table[..]);
    let mut s = BotSession::new().with_shortfall(ShortfallPolicy::ShortNoStall);
    let mut work = [0u8; snowscsi::MIN_DATA_LEN];
    let mut scratch = [0u8; snowscsi::MIN_DATA_LEN];
    let mut io = MockBotIo::new();

    // Cause a CC first.
    let cdb = [0x28, 0, 0, 0x1F, 0x40, 0, 0, 0, 1, 0];
    let r = run_command(
        &mut s,
        &mut io,
        &mut work,
        &mut scratch,
        &mut target,
        &mut storage,
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
        &mut scratch,
        &mut target,
        &mut storage,
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
    let mut slots = [TestLu::block(128, 512, 0)];
    let mut storage = PlaneSet::new(vec![Some(StorePlane::BlockRw(&mut backend))]);
    let mut table = table(&mut slots);
    let mut target = Target::new(&mut table[..]);
    let mut s = BotSession::new();
    let mut work = [0u8; snowscsi::MIN_DATA_LEN];
    let mut scratch = [0u8; snowscsi::MIN_DATA_LEN];
    let mut io = MockBotIo::new();

    // READ(10) 1 block = 512 bytes = one MPS multiple. The data phase must
    // be exactly 512 bytes with the CSW immediately after — no ZLP.
    let cdb = [0x28, 0, 0, 0, 0, 0, 0, 0, 1, 0];
    let r = run_command(
        &mut s,
        &mut io,
        &mut work,
        &mut scratch,
        &mut target,
        &mut storage,
        &raw_cbw(1, 512, 0x80, 0, &cdb),
    );
    assert_eq!(r, Drive::Processed);
    let sent = io.take_sent();
    assert_eq!(sent.len(), 512 + CSW_LEN);
    let mut check = [0u8; 512];
    plane_read(&mut storage, 0, &mut check);
    assert_eq!(&sent[..512], &check[..]);
    assert_eq!(csw_fields(&sent), (1, 0, 0x00));
    // Back in Command, ready for the next CBW.
    assert_command_boundary(&mut s, &mut work, &mut scratch, &mut target, &mut storage);
}

#[test]
fn data_out_host_overrun_is_drained() {
    let mut ram = vec![0u8; 64 * 1024];
    let mut backend = RamBackend::new(&mut ram);
    let mut slots = [TestLu::block(128, 512, 0)];
    let mut storage = PlaneSet::new(vec![Some(StorePlane::BlockRw(&mut backend))]);
    let mut table = table(&mut slots);
    let mut target = Target::new(&mut table[..]);
    let mut s = BotSession::new();
    let mut work = [0u8; snowscsi::MIN_DATA_LEN];
    let mut scratch = [0u8; snowscsi::MIN_DATA_LEN];
    let mut io = MockBotIo::new();

    // WRITE(10) 512 bytes, but the host transmits 512 + 100 extra bytes.
    let cdb = [0x2A, 0, 0, 0, 0, 0, 0, 0, 1, 0];
    io.feed_out(&raw_cbw(1, 512, 0x00, 0, &cdb));
    io.feed_out(&[0x5A; 512]);
    io.feed_out(&[0x6B; 100]);
    let r = drive_until_done(
        &mut s,
        &mut io,
        &mut work,
        &mut scratch,
        &mut target,
        &mut storage,
    );
    assert_eq!(r, Drive::Processed);

    // Only the declared 512 bytes were written; the excess was discarded.
    let mut check = [0u8; 512];
    plane_read(&mut storage, 0, &mut check);
    assert!(check.iter().all(|&b| b == 0x5A));
    let mut tail = [0u8; 128];
    plane_read(&mut storage, 512, &mut tail);
    assert!(tail.iter().all(|&b| b == 0));
    let sent = io.take_sent();
    assert_eq!(csw_fields(&sent), (1, 0, 0x00));
}

#[test]
fn opcode_report_luns_synthesized() {
    let mut ram = vec![0u8; 64 * 1024];
    let mut backend = RamBackend::new(&mut ram);
    let mut slots = [TestLu::block(128, 512, 0)];
    let mut storage = PlaneSet::new(vec![Some(StorePlane::BlockRw(&mut backend))]);
    let mut table = table(&mut slots);
    let mut target = Target::new(&mut table[..]);
    let mut s = BotSession::new();
    let mut work = [0u8; snowscsi::MIN_DATA_LEN];
    let mut scratch = [0u8; snowscsi::MIN_DATA_LEN];
    let mut io = MockBotIo::new();

    let cdb = [0xA0, 0, 0, 0, 0, 0, 0, 0, 0, 16];
    let r = run_command(
        &mut s,
        &mut io,
        &mut work,
        &mut scratch,
        &mut target,
        &mut storage,
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
fn drive_short<S: RuntimeSet>(
    session: &mut BotSession,
    io: &mut MockBotIo,
    work: &mut [u8],
    scratch: &mut [u8],
    target: &mut Target<S>,
    storage: &mut PlaneSet<'_>,
) -> Option<Drive> {
    let mut ev = Event::Tick;
    let mut csw_sent = false;
    let mut stalled_once = false;
    loop {
        match next_step(session, ev, work, scratch, target, storage, io) {
            Step::Recv { offset, len, probe } => {
                if csw_sent && len == CBW_LEN && !probe {
                    return Some(Drive::Processed);
                }
                if probe {
                    match io.try_recv_out(&mut work[offset..offset + len]) {
                        Ok(n) => ev = Event::HostRecv { len: n },
                        Err(BotIoErr::WouldBlock) => ev = Event::HostIdle,
                        Err(_) => panic!("mock bulk-OUT I/O error"),
                    }
                } else {
                    match io.try_recv_out(&mut work[offset..offset + len]) {
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
            Step::StallIn => {
                assert!(!stalled_once, "stall was not released");
                stalled_once = true;
                if io.stall_in().is_err() {
                    // Abort deterministically (the withheld CSW is dropped).
                    let _ = session.poll(Event::Reset, work, scratch, target, storage);
                    return None;
                }
                // Release the stall; the withheld CSW follows.
                ev = Event::StallApplied;
            }
            Step::StoragePending => ev = Event::Tick,
            Step::StallBoth => panic!("unexpected StallBoth in a Short-policy drive"),
        }
    }
}

#[test]
fn short_policy_stalls_then_applied_releases_csw() {
    let mut ram = vec![0u8; 64 * 1024];
    let mut backend = RamBackend::new(&mut ram);
    let mut slots = [TestLu::block(128, 512, 0)];
    let mut storage = PlaneSet::new(vec![Some(StorePlane::BlockRw(&mut backend))]);
    let mut table = table(&mut slots);
    let mut target = Target::new(&mut table[..]);
    let mut s = BotSession::new().with_shortfall(ShortfallPolicy::Short);
    let mut work = [0u8; snowscsi::MIN_DATA_LEN];
    let mut scratch = [0u8; snowscsi::MIN_DATA_LEN];
    let mut io = MockBotIo::new();

    // READ(10) 1 block (512, an MPS multiple) vs declared 1024.
    let cdb = rw10(0x28, 0, 1);
    io.feed_out(&raw_cbw(1, 1024, 0x80, 0, &cdb));
    assert_eq!(
        drive_short(
            &mut s,
            &mut io,
            &mut work,
            &mut scratch,
            &mut target,
            &mut storage
        ),
        Some(Drive::Processed)
    );

    // 512 relevant + a ZLP (empty → adds nothing) + CSW.
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
    let mut slots = [TestLu::block(128, 512, 0)];
    let mut storage = PlaneSet::new(vec![Some(StorePlane::BlockRw(&mut backend))]);
    let mut table = table(&mut slots);
    let mut target = Target::new(&mut table[..]);
    let mut s = BotSession::new().with_shortfall(ShortfallPolicy::Short);
    let mut work = [0u8; snowscsi::MIN_DATA_LEN];
    let mut scratch = [0u8; snowscsi::MIN_DATA_LEN];
    let mut io = MockBotIo::new();

    // INQUIRY alloc 95 (36-byte core page) vs declared 192: the short
    // packet ends the read.
    let cdb = [0x12, 0, 0, 0, 95, 0];
    io.feed_out(&raw_cbw(2, 192, 0x80, 0, &cdb));
    assert_eq!(
        drive_short(
            &mut s,
            &mut io,
            &mut work,
            &mut scratch,
            &mut target,
            &mut storage
        ),
        Some(Drive::Processed)
    );
    let sent = io.take_sent();
    assert_eq!(sent.len(), 36 + CSW_LEN);
    assert_eq!(csw_fields(&sent), (2, 192 - 36, 0x00));
    assert_eq!(io.stall_in_count, 1);
}

#[test]
fn short_policy_stall_failure_resets_transaction() {
    let mut ram = vec![0u8; 64 * 1024];
    let mut backend = RamBackend::new(&mut ram);
    let mut slots = [TestLu::block(128, 512, 0)];
    let mut storage = PlaneSet::new(vec![Some(StorePlane::BlockRw(&mut backend))]);
    let mut table = table(&mut slots);
    let mut target = Target::new(&mut table[..]);
    let mut s = BotSession::new().with_shortfall(ShortfallPolicy::Short);
    let mut work = [0u8; snowscsi::MIN_DATA_LEN];
    let mut scratch = [0u8; snowscsi::MIN_DATA_LEN];
    let mut io = MockBotIo::new().set_stall_in(false);

    let cdb = rw10(0x28, 0, 1);
    io.feed_out(&raw_cbw(3, 1024, 0x80, 0, &cdb));
    // `stall_in` unavailable → the driver aborts via reset.
    assert_eq!(
        drive_short(
            &mut s,
            &mut io,
            &mut work,
            &mut scratch,
            &mut target,
            &mut storage
        ),
        None
    );
    assert_command_boundary(&mut s, &mut work, &mut scratch, &mut target, &mut storage);
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
    let mut slots = [TestLu::block(128, 512, 0)];
    let mut storage = PlaneSet::new(vec![Some(StorePlane::BlockRw(&mut backend))]);
    let mut table = table(&mut slots);
    let mut target = Target::new(&mut table[..]);
    let mut s = BotSession::new(); // no selector: exercise the default
    let mut work = [0u8; snowscsi::MIN_DATA_LEN];
    let mut scratch = [0u8; snowscsi::MIN_DATA_LEN];
    let mut io = MockBotIo::new();

    // INQUIRY alloc 95 (36-byte core page) vs declared 192.
    let cdb = [0x12, 0, 0, 0, 95, 0];
    io.feed_out(&raw_cbw(5, 192, 0x80, 0, &cdb));
    let r = drive_until_done(
        &mut s,
        &mut io,
        &mut work,
        &mut scratch,
        &mut target,
        &mut storage,
    );
    assert_eq!(r, Drive::Processed);
    let sent = io.take_sent();
    assert_eq!(sent.len(), 36 + CSW_LEN);
    assert_eq!(csw_fields(&sent), (5, 192 - 36, 0x00));
    assert_eq!(io.stall_count, 0);
    assert_eq!(io.stall_in_count, 0);
}

/// FORMAT UNIT's whole-disc zero-fill must run through the resident long
/// operation. Pre-fill the plane with a pattern so a no-op FORMAT is
/// detectable, drive FORMAT through the session, advance the long operation on
/// idle entries, and assert the plane is zero afterwards.
#[test]
fn format_unit_zeroes_the_plane_via_the_long_operation() {
    let mut ram = vec![0x5Au8; 1 << 20];
    let mut backend = RamBackend::new(&mut ram);
    let mut slots = [TestLu::dvdram(512, 0)];
    let mut storage = PlaneSet::new(vec![Some(StorePlane::BlockRw(&mut backend))]);
    let mut table = table(&mut slots);
    let mut target = Target::new(&mut table[..]);
    let mut s = BotSession::new();
    let mut work = [0u8; snowscsi::MIN_DATA_LEN];
    let mut scratch = vec![0u8; 64 * 1024];
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
    let r = drive_until_done(
        &mut s,
        &mut io,
        &mut work,
        &mut scratch,
        &mut target,
        &mut storage,
    );
    assert_eq!(r, Drive::Processed);

    // Advance the resident zero-fill on idle entries.
    for _ in 0..32 {
        let _ = s.poll(
            Event::Tick,
            &mut work,
            &mut scratch,
            &mut target,
            &mut storage,
        );
    }

    let mut check = vec![0u8; 1 << 20];
    plane_read(&mut storage, 0, &mut check);
    assert!(
        check.iter().all(|&b| b == 0),
        "FORMAT must zero-fill the whole plane through the long operation"
    );
}

// ── 11. Data-Out residue (BOT §6.6.2) ──────────────────────────────

/// A failed storage write must not report that the host's bytes were
/// processed: the conservative residue is the whole declared length.
#[test]
fn failed_data_out_write_reports_full_residue() {
    // The plane holds one 512-byte block while the device geometry and the
    // CDB address LBA 1, so the storage step fails with OutOfBounds.
    let mut ram = vec![0u8; 512];
    let mut backend = RamBackend::new(&mut ram);
    let mut slots = [TestLu::block(128, 512, 0)];
    let mut storage = PlaneSet::new(vec![Some(StorePlane::BlockRw(&mut backend))]);
    let mut table = table(&mut slots);
    let mut target = Target::new(&mut table[..]);
    let mut s = BotSession::new();
    let mut work = [0u8; snowscsi::MIN_DATA_LEN];
    let mut scratch = [0u8; snowscsi::MIN_DATA_LEN];
    let mut io = MockBotIo::new();

    let cdb = rw10(0x2A, 1, 1);
    io.feed_out(&raw_cbw(1, 512, 0x00, 0, &cdb));
    io.feed_out(&[0x5A; 512]);
    let r = drive_until_done(
        &mut s,
        &mut io,
        &mut work,
        &mut scratch,
        &mut target,
        &mut storage,
    );
    assert_eq!(r, Drive::Processed);
    let sent = io.take_sent();
    assert_eq!(
        csw_fields(&sent),
        (1, 512, 0x01),
        "no byte reached the medium, so the whole declared length is residue"
    );
}

/// A successful Data-Out reports zero residue.
#[test]
fn successful_data_out_reports_zero_residue() {
    let mut ram = vec![0u8; 64 * 1024];
    let mut backend = RamBackend::new(&mut ram);
    let mut slots = [TestLu::block(128, 512, 0)];
    let mut storage = PlaneSet::new(vec![Some(StorePlane::BlockRw(&mut backend))]);
    let mut table = table(&mut slots);
    let mut target = Target::new(&mut table[..]);
    let mut s = BotSession::new();
    let mut work = [0u8; snowscsi::MIN_DATA_LEN];
    let mut scratch = [0u8; snowscsi::MIN_DATA_LEN];
    let mut io = MockBotIo::new();

    let cdb = rw10(0x2A, 0, 1);
    io.feed_out(&raw_cbw(1, 512, 0x00, 0, &cdb));
    io.feed_out(&[0x5A; 512]);
    let r = drive_until_done(
        &mut s,
        &mut io,
        &mut work,
        &mut scratch,
        &mut target,
        &mut storage,
    );
    assert_eq!(r, Drive::Processed);
    let sent = io.take_sent();
    assert_eq!(csw_fields(&sent), (1, 0, 0x00));
}

// ── 12. Host/device transfer matrix (BOT §6.7) ─────────────────────

/// Run one CBW against a fresh 64 KiB block LUN, optionally followed by host
/// data, and return `(CSW fields, plane ops, ZLP count)`.
fn run_phase_case(cbw: [u8; CBW_LEN], host_data: Option<&[u8]>) -> ((u32, u32, u8), usize, u32) {
    let mut ram = vec![0u8; 64 * 1024];
    let mut backend = RamBackend::new(&mut ram);
    let mut slots = [TestLu::block(128, 512, 0)];
    let mut storage = PlaneSet::new(vec![Some(StorePlane::BlockRw(&mut backend))]);
    let mut table = table(&mut slots);
    let mut target = Target::new(&mut table[..]);
    let mut s = BotSession::new();
    let mut work = [0u8; snowscsi::MIN_DATA_LEN];
    let mut scratch = [0u8; snowscsi::MIN_DATA_LEN];
    let mut io = MockBotIo::new();

    io.feed_out(&cbw);
    if let Some(data) = host_data {
        io.feed_out(data);
    }
    let r = drive_until_done(
        &mut s,
        &mut io,
        &mut work,
        &mut scratch,
        &mut target,
        &mut storage,
    );
    assert_eq!(r, Drive::Processed);
    let sent = io.take_sent();
    (csw_fields(&sent), storage.execs, io.zero_in_count)
}

/// Case (2) Hn < Di: the host declared no data but the device wants to send.
#[test]
fn case_02_host_none_device_in_is_phase_error_without_medium_io() {
    let cdb = rw10(0x28, 0, 1);
    let (csw, execs, _) = run_phase_case(raw_cbw(1, 0, 0x80, 0, &cdb), None);
    assert_eq!(csw, (1, 0, 0x02));
    assert_eq!(execs, 0, "the device must not be touched");
}

/// Case (3) Hn < Do: the host declared no data but the device wants to
/// receive.
#[test]
fn case_03_host_none_device_out_is_phase_error_without_medium_io() {
    let cdb = rw10(0x2A, 0, 1);
    let (csw, execs, _) = run_phase_case(raw_cbw(1, 0, 0x00, 0, &cdb), None);
    assert_eq!(csw, (1, 0, 0x02));
    assert_eq!(execs, 0, "the device must not be touched");
}

/// Case (7) Hi < Di: the host expects fewer Data-In bytes than the device
/// intends to send. INQUIRY keeps the case off the medium.
#[test]
fn case_07_host_in_shorter_than_device_in_is_phase_error() {
    let cdb = [0x12, 0, 0, 0, 36, 0];
    let (csw, execs, zlp) = run_phase_case(raw_cbw(1, 18, 0x80, 0, &cdb), None);
    // The host's 18 declared bytes are all relevant data, so residue 0.
    assert_eq!(csw, (1, 0, 0x02));
    assert_eq!(execs, 0, "INQUIRY must not read the medium");
    assert_eq!(zlp, 0, "18 bytes is a short packet on its own");
}

/// Case (8) Hi <> Do: the host expects data-in while the device wants the
/// host to send.
#[test]
fn case_08_host_in_device_out_is_phase_error_without_medium_io() {
    let cdb = rw10(0x2A, 0, 1);
    let (csw, execs, zlp) = run_phase_case(raw_cbw(1, 512, 0x80, 0, &cdb), None);
    assert_eq!(csw, (1, 512, 0x02));
    assert_eq!(execs, 0, "the device must not be touched");
    assert_eq!(zlp, 1, "zero relevant bytes need a ZLP to end the IN phase");
}

/// Case (10) Ho <> Di: the host expects to send while the device wants to
/// send data.
#[test]
fn case_10_host_out_device_in_is_phase_error_without_medium_io() {
    let cdb = rw10(0x28, 0, 1);
    let (csw, execs, _) = run_phase_case(raw_cbw(1, 512, 0x00, 0, &cdb), Some(&[0u8; 512]));
    assert_eq!(csw, (1, 512, 0x02));
    assert_eq!(execs, 0, "the device must not be touched");
}

/// Case (13) Ho < Do: the host will send fewer bytes than the device's format
/// parameter list, so the device aborts before touching the medium.
#[test]
fn case_13_host_out_shorter_than_device_out_is_phase_error() {
    let mut ram = vec![0u8; 1 << 20];
    let mut backend = RamBackend::new(&mut ram);
    let mut slots = [TestLu::dvdram(512, 0)];
    let mut storage = PlaneSet::new(vec![Some(StorePlane::BlockRw(&mut backend))]);
    let mut table = table(&mut slots);
    let mut target = Target::new(&mut table[..]);
    let mut s = BotSession::new();
    let mut work = [0u8; snowscsi::MIN_DATA_LEN];
    let mut scratch = [0u8; snowscsi::MIN_DATA_LEN];
    let mut io = MockBotIo::new();

    // FORMAT UNIT with a 12-byte parameter list, but the CBW declares 8.
    let cdb = [0x04, 0x11, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0];
    io.feed_out(&raw_cbw(1, 8, 0x00, 0, &cdb));
    io.feed_out(&[0u8; 8]);
    let r = drive_until_done(
        &mut s,
        &mut io,
        &mut work,
        &mut scratch,
        &mut target,
        &mut storage,
    );
    assert_eq!(r, Drive::Processed);
    let sent = io.take_sent();
    assert_eq!(csw_fields(&sent), (1, 8, 0x02));
    assert_eq!(storage.execs, 0, "no medium IO may run for a phase error");
}

// ── 13. Restored protocol coverage ─────────────────────────────────

/// A zero-byte Data-In failure terminates the phase with a ZLP before the
/// Failed CSW.
#[test]
fn failed_zero_byte_data_in_sends_zlp_before_csw() {
    let mut ram = vec![0u8; 64 * 1024];
    let mut backend = RamBackend::new(&mut ram);
    let mut slots = [TestLu::block(128, 512, 0)];
    let mut storage = PlaneSet::new(vec![Some(StorePlane::BlockRw(&mut backend))]);
    let mut table = table(&mut slots);
    let mut target = Target::new(&mut table[..]);
    let mut s = BotSession::new();
    let mut work = [0u8; snowscsi::MIN_DATA_LEN];
    let mut scratch = [0u8; snowscsi::MIN_DATA_LEN];
    let mut io = MockBotIo::new();

    // READ beyond the 128-block geometry: CHECK CONDITION with no relevant
    // data, while the CBW declares a 512-byte Data-In phase.
    let cdb = [0x28, 0, 0, 0x1F, 0x40, 0, 0, 0, 1, 0];
    io.feed_out(&raw_cbw(1, 512, 0x80, 0, &cdb));
    let r = drive_until_done(
        &mut s,
        &mut io,
        &mut work,
        &mut scratch,
        &mut target,
        &mut storage,
    );
    assert_eq!(r, Drive::Processed);
    assert_eq!(io.zero_in_count, 1, "one ZLP closes the empty data phase");
    let sent = io.take_sent();
    assert_eq!(sent.len(), CSW_LEN, "ZLP adds no bytes");
    assert_eq!(csw_fields(&sent), (1, 512, 0x01));
}

/// `MAX_PAD` bounds the zero fill: exactly the cap goes out, then a ZLP (the
/// wire length is an MPS multiple), then the CSW with the relevant residue.
#[test]
fn pad_cap_exhaustion_fills_to_max_pad_then_zlp() {
    let mut ram = vec![0u8; 64 * 1024];
    let mut backend = RamBackend::new(&mut ram);
    let mut slots = [TestLu::block(128, 512, 0)];
    let mut storage = PlaneSet::new(vec![Some(StorePlane::BlockRw(&mut backend))]);
    let mut table = table(&mut slots);
    let mut target = Target::new(&mut table[..]);
    let mut s = BotSession::new().with_shortfall(ShortfallPolicy::Pad);
    let mut work = [0u8; snowscsi::MIN_DATA_LEN];
    let mut scratch = [0u8; snowscsi::MIN_DATA_LEN];
    let mut io = MockBotIo::new();

    let cdb = rw10(0x28, 0, 1);
    let declared = 512 + MAX_PAD as u32 + 512;
    io.feed_out(&raw_cbw(1, declared, 0x80, 0, &cdb));
    let r = drive_until_done(
        &mut s,
        &mut io,
        &mut work,
        &mut scratch,
        &mut target,
        &mut storage,
    );
    assert_eq!(r, Drive::Processed);
    let sent = io.take_sent();
    assert_eq!(
        sent.len(),
        512 + MAX_PAD as usize + CSW_LEN,
        "exactly one cap of fill, then the CSW"
    );
    assert_eq!(csw_fields(&sent), (1, declared - 512, 0x00));
    assert_eq!(io.zero_in_count, 1, "MPS-aligned cap needs a ZLP");
}

/// The 31-byte CBW accumulates across partial bulk-OUT receives.
#[test]
fn cbw_accumulates_across_partial_receives() {
    let mut ram = vec![0u8; 64 * 1024];
    let mut backend = RamBackend::new(&mut ram);
    let mut slots = [TestLu::block(128, 512, 0)];
    let mut storage = PlaneSet::new(vec![Some(StorePlane::BlockRw(&mut backend))]);
    let mut table = table(&mut slots);
    let mut target = Target::new(&mut table[..]);
    let mut s = BotSession::new();
    let mut work = [0u8; snowscsi::MIN_DATA_LEN];
    let mut scratch = [0u8; snowscsi::MIN_DATA_LEN];
    let mut io = MockBotIo::new();

    let cdb = [0x12, 0, 0, 0, 36, 0];
    let raw = raw_cbw(1, 36, 0x80, 0, &cdb);
    io.feed_out(&raw[..20]);
    let n = io.try_recv_out(&mut work[..20]).unwrap();
    assert_eq!(n, 20);
    match s.poll(
        Event::HostRecv { len: n },
        &mut work,
        &mut scratch,
        &mut target,
        &mut storage,
    ) {
        Action::HostRecv {
            offset: 0,
            len: 11,
            probe: false,
        } => {}
        other => panic!("expected 11 more CBW bytes, got {other:?}"),
    }
    // The pending action is re-emitted without state change.
    match s.poll(
        Event::Tick,
        &mut work,
        &mut scratch,
        &mut target,
        &mut storage,
    ) {
        Action::HostRecv {
            offset: 0,
            len: 11,
            probe: false,
        } => {}
        other => panic!("expected the re-emitted 11-byte need, got {other:?}"),
    }

    io.feed_out(&raw[20..]);
    let n = io.try_recv_out(&mut work[..11]).unwrap();
    assert_eq!(n, 11);
    match s.poll(
        Event::HostRecv { len: n },
        &mut work,
        &mut scratch,
        &mut target,
        &mut storage,
    ) {
        Action::HostSend { bytes } => assert_eq!(bytes.len(), 36),
        other => panic!("expected the INQUIRY data, got {other:?}"),
    }
}

/// REPORT LUNS is target-level: any addressed LUN is served by slot 0, and a
/// reserved select value fails with INVALID FIELD IN CDB after a ZLP.
#[test]
fn report_luns_any_lun_and_reserved_select() {
    let mut ram0 = vec![0u8; 64 * 1024];
    let mut ram1 = vec![0u8; 64 * 1024];
    let mut backend0 = RamBackend::new(&mut ram0);
    let mut backend1 = RamBackend::new(&mut ram1);
    let mut slots = [TestLu::block(128, 512, 0), TestLu::block(128, 512, 1)];
    let mut storage = PlaneSet::new(vec![
        Some(StorePlane::BlockRw(&mut backend0)),
        Some(StorePlane::BlockRw(&mut backend1)),
    ]);
    let mut table = table(&mut slots);
    let mut target = Target::new(&mut table[..]);
    let mut s = BotSession::with_luns(2);
    let mut work = [0u8; snowscsi::MIN_DATA_LEN];
    let mut scratch = [0u8; snowscsi::MIN_DATA_LEN];
    let mut io = MockBotIo::new();

    // REPORT LUNS addressed to LUN 1 still lists the whole inventory.
    let cdb = [0xA0, 0, 0, 0, 0, 0, 0, 0, 0, 24];
    let r = run_command(
        &mut s,
        &mut io,
        &mut work,
        &mut scratch,
        &mut target,
        &mut storage,
        &raw_cbw(1, 24, 0x80, 1, &cdb),
    );
    assert_eq!(r, Drive::Processed);
    let sent = io.take_sent();
    assert_eq!(sent.len(), 24 + CSW_LEN);
    assert_eq!(u32::from_be_bytes([sent[0], sent[1], sent[2], sent[3]]), 16);
    assert_eq!(sent[9], 0, "first LUN id");
    assert_eq!(sent[17], 1, "second LUN id");
    assert_eq!(csw_fields(&sent), (1, 0, 0x00));

    // Reserved select 03h → Failed + ZLP.
    let cdb = [0xA0, 0, 3, 0, 0, 0, 0, 0, 0, 24];
    let r = run_command(
        &mut s,
        &mut io,
        &mut work,
        &mut scratch,
        &mut target,
        &mut storage,
        &raw_cbw(2, 24, 0x80, 1, &cdb),
    );
    assert_eq!(r, Drive::Processed);
    assert_eq!(io.zero_in_count, 1);
    let sent = io.take_sent();
    assert_eq!(sent.len(), CSW_LEN);
    assert_eq!(csw_fields(&sent), (2, 24, 0x01));

    // REQUEST SENSE carries the saved INVALID FIELD IN CDB (05/24/00).
    let cdb = [0x03, 0, 0, 0, 18, 0];
    let r = run_command(
        &mut s,
        &mut io,
        &mut work,
        &mut scratch,
        &mut target,
        &mut storage,
        &raw_cbw(3, 18, 0x80, 0, &cdb),
    );
    assert_eq!(r, Drive::Processed);
    let sent = io.take_sent();
    assert_eq!(sent[2], 0x05);
    assert_eq!(sent[12], 0x24);
    assert_eq!(sent[13], 0x00);
    assert_eq!(storage.execs, 0, "REPORT LUNS never touches a plane");
}

/// Bulk MPS override and LUN-count clamping.
#[test]
fn session_bulk_mps_and_lun_limits() {
    assert_eq!(BotSession::new().bulk_mps(), 512);
    assert_eq!(BotSession::new().with_bulk_mps(64).bulk_mps(), 64);

    let mut s = BotSession::new();
    s.set_bulk_mps(64);
    assert_eq!(s.bulk_mps(), 64);
    s.set_bulk_mps(512);
    assert_eq!(s.bulk_mps(), 512);
    // 0 is rejected: keep the documented default.
    s.set_bulk_mps(0);
    assert_eq!(s.bulk_mps(), 512);
    assert_eq!(BotSession::new().with_bulk_mps(0).bulk_mps(), 512);

    assert_eq!(BotSession::with_luns(1).max_lun(), 0);
    assert_eq!(BotSession::with_luns(3).max_lun(), 2);
    assert_eq!(BotSession::with_luns(17).max_lun(), 15);
    assert_eq!(BotSession::with_luns(0).max_lun(), 0);
}

/// A flat CD-ROM LUN answers the `--usb --cdrom` path over BOT.
#[test]
fn flat_cdrom_lun_serves_over_bot() {
    let mut ram = vec![0u8; 64 * 2048];
    let mut backend = RamBackend::new(&mut ram);
    let mut slots = [TestLu::cdrom(64, 0)];
    let mut storage = PlaneSet::new(vec![Some(StorePlane::BlockRw(&mut backend))]);
    let mut table = table(&mut slots);
    let mut target = Target::new(&mut table[..]);
    let mut s = BotSession::new();
    let mut work = [0u8; snowscsi::MIN_DATA_LEN];
    let mut scratch = [0u8; snowscsi::MIN_DATA_LEN];
    let mut io = MockBotIo::new();

    // INQUIRY: optical memory device (PDT 5).
    let cdb = [0x12, 0, 0, 0, 36, 0];
    let r = run_command(
        &mut s,
        &mut io,
        &mut work,
        &mut scratch,
        &mut target,
        &mut storage,
        &raw_cbw(1, 36, 0x80, 0, &cdb),
    );
    assert_eq!(r, Drive::Processed);
    let sent = io.take_sent();
    assert_eq!(sent[0] & 0x1F, 0x05, "PDT = CD-ROM");

    // READ CAPACITY(10): 64 sectors of 2048 bytes.
    let cdb = [0x25, 0, 0, 0, 0, 0, 0, 0, 0, 0];
    let r = run_command(
        &mut s,
        &mut io,
        &mut work,
        &mut scratch,
        &mut target,
        &mut storage,
        &raw_cbw(2, 8, 0x80, 0, &cdb),
    );
    assert_eq!(r, Drive::Processed);
    let sent = io.take_sent();
    assert_eq!(u32::from_be_bytes([sent[0], sent[1], sent[2], sent[3]]), 63);
    assert_eq!(
        u32::from_be_bytes([sent[4], sent[5], sent[6], sent[7]]),
        2048
    );

    // READ(10) one sector.
    let cdb = rw10(0x28, 0, 1);
    let r = run_command(
        &mut s,
        &mut io,
        &mut work,
        &mut scratch,
        &mut target,
        &mut storage,
        &raw_cbw(3, 2048, 0x80, 0, &cdb),
    );
    assert_eq!(r, Drive::Processed);
    let sent = io.take_sent();
    assert_eq!(sent.len(), 2048 + CSW_LEN);
    assert_eq!(csw_fields(&sent), (3, 0, 0x00));
}

// ── 14. Stray host byte while the core is storage-only ─────────────

/// A byte arriving while the core drives a storage-only step cannot be a CBW
/// continuation: it is an invalid CBW (STALL both) and the session continues.
#[test]
fn stray_out_byte_during_storage_only_step_stalls_and_recovers() {
    let mut ram = vec![0u8; 64 * 1024];
    let mut backend = RamBackend::new(&mut ram);
    let mut slots = [TestLu::block(128, 512, 0)];
    let mut storage = PlaneSet::new(vec![Some(StorePlane::BlockRw(&mut backend))]).with_pending(1);
    let mut table = table(&mut slots);
    let mut target = Target::new(&mut table[..]);
    let mut s = BotSession::new();
    let mut work = [0u8; snowscsi::MIN_DATA_LEN];
    let mut scratch = [0u8; snowscsi::MIN_DATA_LEN];
    let mut io = MockBotIo::new();

    // SYNCHRONIZE CACHE has no host data phase but needs a storage step.
    let cdb = [0x35, 0, 0, 0, 0, 0, 0, 0, 0, 0];
    io.feed_out(&raw_cbw(1, 0, 0x00, 0, &cdb));

    let mut ev = Event::Tick;
    loop {
        match next_step(
            &mut s,
            ev,
            &mut work,
            &mut scratch,
            &mut target,
            &mut storage,
            &mut io,
        ) {
            Step::Recv {
                offset,
                len,
                probe: false,
            } => {
                let n = io.try_recv_out(&mut work[offset..offset + len]).unwrap();
                ev = Event::HostRecv { len: n };
            }
            Step::StoragePending => {
                // The core is in the storage-only step and has asked for no
                // wire transfer. A stray host byte arrives anyway.
                io.feed_out(&[0xEE]);
                let n = io.try_recv_out(&mut work[..1]).unwrap();
                assert_eq!(n, 1);
                match s.poll(
                    Event::HostRecv { len: n },
                    &mut work,
                    &mut scratch,
                    &mut target,
                    &mut storage,
                ) {
                    Action::StallBoth => {}
                    other => panic!("expected StallBoth, got {other:?}"),
                }
                break;
            }
            Step::Sent { .. } => ev = Event::HostSent,
            Step::Recv { probe: true, .. } => panic!("unexpected probe on a no-data command"),
            Step::StallBoth => panic!("unexpected STALL before the stray byte"),
            Step::StallIn => panic!("unexpected Bulk-In STALL"),
        }
    }

    assert!(io.in_.is_empty(), "no CSW for the abandoned command");
    assert_command_boundary(&mut s, &mut work, &mut scratch, &mut target, &mut storage);

    // The loop is still usable: a fresh command completes normally.
    let cdb = [0x12, 0, 0, 0, 36, 0];
    let r = run_command(
        &mut s,
        &mut io,
        &mut work,
        &mut scratch,
        &mut target,
        &mut storage,
        &raw_cbw(2, 36, 0x80, 0, &cdb),
    );
    assert_eq!(r, Drive::Processed);
    let sent = io.take_sent();
    assert_eq!(csw_fields(&sent), (2, 0, 0x00));
}

// ── Storage-only steps report a storage pending signal ─────────────

/// A no-data command whose storage step stays pending returns
/// `StoragePending`, and the next `Tick` completes it without wire I/O.
#[test]
fn storage_pending_signal_then_tick_completes_the_command() {
    let mut ram = vec![0u8; 64 * 1024];
    let mut backend = RamBackend::new(&mut ram);
    let mut slots = [TestLu::block(128, 512, 0)];
    let mut storage = PlaneSet::new(vec![Some(StorePlane::BlockRw(&mut backend))]).with_pending(1);
    let mut table = table(&mut slots);
    let mut target = Target::new(&mut table[..]);
    let mut s = BotSession::new();
    let mut work = [0u8; snowscsi::MIN_DATA_LEN];
    let mut scratch = [0u8; snowscsi::MIN_DATA_LEN];
    let mut io = MockBotIo::new();

    // SYNCHRONIZE CACHE has no host data phase but needs a storage step.
    let cdb = [0x35, 0, 0, 0, 0, 0, 0, 0, 0, 0];
    io.feed_out(&raw_cbw(7, 0, 0x00, 0, &cdb));

    let (offset, len) = match next_step(
        &mut s,
        Event::Tick,
        &mut work,
        &mut scratch,
        &mut target,
        &mut storage,
        &mut io,
    ) {
        Step::Recv {
            offset,
            len,
            probe: false,
        } => (offset, len),
        other => panic!("expected the CBW receive, got {other:?}"),
    };
    let n = io.try_recv_out(&mut work[offset..offset + len]).unwrap();
    match next_step(
        &mut s,
        Event::HostRecv { len: n },
        &mut work,
        &mut scratch,
        &mut target,
        &mut storage,
        &mut io,
    ) {
        Step::StoragePending => {}
        other => panic!("expected StoragePending, got {other:?}"),
    }
    assert_eq!(target.pending_kind(), Some(PendingKind::Storage));

    // One no-op tick advances the command; the CSW is staged.
    match next_step(
        &mut s,
        Event::Tick,
        &mut work,
        &mut scratch,
        &mut target,
        &mut storage,
        &mut io,
    ) {
        Step::Sent { is_csw: true } => {}
        other => panic!("expected the CSW, got {other:?}"),
    }
    assert_eq!(target.pending_kind(), None);
    assert_eq!(csw_fields(&io.take_sent()), (7, 0, 0x00));
}

// ── Multi-chunk host data phases ────────────────────────────────────

/// A READ larger than the bank is delivered in several bulk-IN phases with a
/// zero residue; a larger WRITE commits every chunk byte-exactly.
#[test]
fn transfers_larger_than_the_bank_stream_in_chunks() {
    let mut ram = vec![0u8; 64 * 1024];
    for (i, b) in ram.iter_mut().enumerate() {
        *b = (i % 251) as u8;
    }
    let mut backend = RamBackend::new(&mut ram);
    let mut slots = [TestLu::block(128, 512, 0)];
    let mut storage = PlaneSet::new(vec![Some(StorePlane::BlockRw(&mut backend))]);
    let mut table = table(&mut slots);
    let mut target = Target::new(&mut table[..]);
    let mut s = BotSession::new();
    // The bank is 8192 bytes: a 32-block transfer is two chunks.
    let mut work = [0u8; snowscsi::MIN_DATA_LEN];
    let mut scratch = [0u8; snowscsi::MIN_DATA_LEN];
    let mut io = MockBotIo::new();

    // READ 32 blocks (16384 bytes) → two bulk-IN data phases.
    let cdb = rw10(0x28, 0, 32);
    let r = run_command(
        &mut s,
        &mut io,
        &mut work,
        &mut scratch,
        &mut target,
        &mut storage,
        &raw_cbw(0x21, 16384, 0x80, 0, &cdb),
    );
    assert_eq!(r, Drive::Processed);
    let sent = io.take_sent();
    assert_eq!(sent.len(), 16384 + CSW_LEN);
    assert_eq!(csw_fields(&sent), (0x21, 0, 0x00), "zero residue");
    assert!(
        io.in_sends >= 3,
        "two data phases plus the CSW (got {})",
        io.in_sends
    );
    let mut check = vec![0u8; 16384];
    plane_read(&mut storage, 0, &mut check);
    assert_eq!(&sent[..16384], check.as_slice(), "byte-exact read");

    // WRITE the same 16384 bytes back at LBA 32, feeding two Data-Out chunks.
    let payload: Vec<u8> = (0..16384u32)
        .map(|i| (i.wrapping_mul(7) % 251) as u8)
        .collect();
    let cdb = rw10(0x2A, 32, 32);
    io.feed_out(&raw_cbw(0x22, 16384, 0x00, 0, &cdb));
    io.feed_out(&payload);
    let r = drive_until_done(
        &mut s,
        &mut io,
        &mut work,
        &mut scratch,
        &mut target,
        &mut storage,
    );
    assert_eq!(r, Drive::Processed);
    let sent = io.take_sent();
    assert_eq!(csw_fields(&sent), (0x22, 0, 0x00), "zero residue");
    let mut check = vec![0u8; 16384];
    plane_read(&mut storage, 32 * 512, &mut check);
    assert_eq!(check, payload, "byte-exact commit");
}

/// A WRITE whose data arrives in USB-request-sized reads (not one big
/// buffer) must still commit every byte and terminate. This mirrors what the
/// real FunctionFS bridge returns: one completion per host request.
#[test]
fn a_write_received_in_request_sized_reads_commits_every_byte() {
    let mut ram = vec![0u8; 64 * 1024];
    let mut backend = RamBackend::new(&mut ram);
    let mut slots = [TestLu::block(128, 512, 0)];
    let mut storage = PlaneSet::new(vec![Some(StorePlane::BlockRw(&mut backend))]);
    let mut table = table(&mut slots);
    let mut target = Target::new(&mut table[..]);
    let mut s = BotSession::new();
    let mut work = vec![0u8; 64 * 1024];
    let mut scratch = vec![0u8; snowscsi::MIN_DATA_LEN];
    let mut io = MockBotIo::new();
    io.max_out_per_read = Some(512);

    let payload: Vec<u8> = (0..65536u32)
        .map(|i| (i.wrapping_mul(11) % 251) as u8)
        .collect();
    let cdb = rw10(0x2A, 0, 128);
    io.feed_out(&raw_cbw(0x77, 65536, 0x00, 0, &cdb));
    io.feed_out(&payload);
    let r = drive_until_done(
        &mut s,
        &mut io,
        &mut work,
        &mut scratch,
        &mut target,
        &mut storage,
    );
    assert_eq!(r, Drive::Processed);
    let sent = io.take_sent();
    assert_eq!(csw_fields(&sent), (0x77, 0, 0x00), "zero residue");
    let mut check = vec![0u8; 65536];
    plane_read(&mut storage, 0, &mut check);
    assert_eq!(check, payload, "byte-exact commit");
}

/// A no-data command whose CBW asks for Data-In is a legal underflow, not a
/// phase error: the device answers CHECK CONDITION and the host gets the
/// short data phase plus the real residue. Treating it as a phase error makes
/// the host reset the port, stalling every queued command behind it.
#[test]
fn a_no_data_command_with_a_data_in_declaration_is_an_underflow() {
    let mut ram = vec![0u8; 64 * 1024];
    let mut backend = RamBackend::new(&mut ram);
    let mut slots = [TestLu::block(128, 512, 0)];
    let mut storage = PlaneSet::new(vec![Some(StorePlane::BlockRw(&mut backend))]);
    let mut table = table(&mut slots);
    let mut target = Target::new(&mut table[..]);
    let mut s = BotSession::new();
    let mut work = vec![0u8; snowscsi::MIN_DATA_LEN];
    let mut scratch = vec![0u8; snowscsi::MIN_DATA_LEN];
    let mut io = MockBotIo::new();

    // BLANK (0xA1) has no data phase; the host still declared 512 Data-In.
    let cdb = [0xA1, 0x08, 0x2E, 0, 0x01, 0, 0, 0, 0, 0xEC, 0, 0];
    let r = run_command(
        &mut s,
        &mut io,
        &mut work,
        &mut scratch,
        &mut target,
        &mut storage,
        &raw_cbw(0x51, 512, 0x80, 0, &cdb),
    );
    assert_eq!(r, Drive::Processed);
    let sent = io.take_sent();
    assert_eq!(csw_fields(&sent), (0x51, 512, 0x01), "Failed, full residue");
    assert_eq!(io.zero_in_count, 1, "the host's data phase ends with a ZLP");

    // The session is still usable.
    let r = run_command(
        &mut s,
        &mut io,
        &mut work,
        &mut scratch,
        &mut target,
        &mut storage,
        &raw_cbw(0x52, 0, 0x00, 0, &[0x00, 0, 0, 0, 0, 0]),
    );
    assert_eq!(r, Drive::Processed);
    let sent = io.take_sent();
    assert_eq!(csw_fields(&sent), (0x52, 0, 0x00), "TUR passes");
}

/// Case (13) Ho < Do at an exact chunk boundary: the first device chunk
/// consumes the host's whole declared length. No second waiting phase may be
/// opened; the device aborts and the Phase Error CSW carries the declared
/// residue.
#[test]
fn case_13_at_a_chunk_boundary_terminates_with_a_phase_error() {
    let mut ram = vec![0u8; 64 * 1024];
    let mut backend = RamBackend::new(&mut ram);
    let mut slots = [TestLu::block(128, 512, 0)];
    let mut storage = PlaneSet::new(vec![Some(StorePlane::BlockRw(&mut backend))]);
    let mut table = table(&mut slots);
    let mut target = Target::new(&mut table[..]);
    let mut s = BotSession::new();
    let mut work = [0u8; snowscsi::MIN_DATA_LEN]; // 8192-byte bank
    let mut scratch = [0u8; snowscsi::MIN_DATA_LEN];
    let mut io = MockBotIo::new();

    // WRITE 32 blocks = 16384 device bytes; the host declares 8192, exactly
    // one bank-sized chunk.
    let cdb = rw10(0x2A, 0, 32);
    io.feed_out(&raw_cbw(0x31, 8192, 0x00, 0, &cdb));
    io.feed_out(&[0xA5u8; 8192]);
    let r = drive_until_done(
        &mut s,
        &mut io,
        &mut work,
        &mut scratch,
        &mut target,
        &mut storage,
    );
    assert_eq!(r, Drive::Processed);
    let sent = io.take_sent();
    assert_eq!(
        csw_fields(&sent),
        (0x31, 8192, 0x02),
        "Phase Error, no declared byte confirmed"
    );

    // The session is still usable.
    let r = run_command(
        &mut s,
        &mut io,
        &mut work,
        &mut scratch,
        &mut target,
        &mut storage,
        &raw_cbw(0x32, 0, 0x00, 0, &[0x00; 6]),
    );
    assert_eq!(r, Drive::Processed);
    assert_eq!(csw_fields(&io.take_sent()), (0x32, 0, 0x00));
}

/// Case (7) Hi < Di at an exact chunk boundary: the device's next chunk has
/// no relevant bytes left. It must short-accept, abort, and emit the Phase
/// Error CSW instead of tearing down the serve loop.
#[test]
fn case_07_at_a_chunk_boundary_reports_a_phase_error_and_keeps_the_session() {
    let mut ram = vec![0u8; 64 * 1024];
    let mut backend = RamBackend::new(&mut ram);
    let mut slots = [TestLu::block(128, 512, 0)];
    let mut storage = PlaneSet::new(vec![Some(StorePlane::BlockRw(&mut backend))]);
    let mut table = table(&mut slots);
    let mut target = Target::new(&mut table[..]);
    let mut s = BotSession::new();
    let mut work = [0u8; snowscsi::MIN_DATA_LEN]; // 8192-byte bank
    let mut scratch = [0u8; snowscsi::MIN_DATA_LEN];
    let mut io = MockBotIo::new();

    // READ 32 blocks = 16384 device bytes; the host declares 8192, exactly one
    // bank-sized chunk.
    let cdb = rw10(0x28, 0, 32);
    let r = run_command(
        &mut s,
        &mut io,
        &mut work,
        &mut scratch,
        &mut target,
        &mut storage,
        &raw_cbw(0x41, 8192, 0x80, 0, &cdb),
    );
    assert_eq!(r, Drive::Processed);
    let sent = io.take_sent();
    assert_eq!(sent.len(), 8192 + CSW_LEN, "only the host's H bytes go out");
    assert_eq!(
        csw_fields(&sent),
        (0x41, 0, 0x02),
        "all declared bytes were relevant; Phase Error"
    );

    // The session is still usable.
    let r = run_command(
        &mut s,
        &mut io,
        &mut work,
        &mut scratch,
        &mut target,
        &mut storage,
        &raw_cbw(0x42, 0, 0x00, 0, &[0x00; 6]),
    );
    assert_eq!(r, Drive::Processed);
    assert_eq!(csw_fields(&io.take_sent()), (0x42, 0, 0x00));
}

// ── Two-bank overlap ────────────────────────────────────────────────

/// One observed step with no borrow back into the session or the banks.
enum TwoBankStep {
    Recv {
        offset: usize,
        len: usize,
        probe: bool,
    },
    Sent {
        start: usize,
        end: usize,
        is_csw: bool,
    },
    StoragePending,
    StallBoth,
    StallIn,
}

/// Poll the session once, executing a pending bulk-IN send immediately.
fn two_bank_next<S: RuntimeSet>(
    session: &mut BotSession,
    ev: Event,
    work: &mut [u8],
    scratch: &mut [u8],
    target: &mut Target<S>,
    storage: &mut dyn Storage,
    io: &mut MockBotIo,
) -> TwoBankStep {
    match session.poll(ev, work, scratch, target, storage) {
        Action::HostRecv { offset, len, probe } => TwoBankStep::Recv { offset, len, probe },
        Action::HostSend { bytes } => {
            let start = bytes.as_ptr() as usize;
            let end = start.saturating_add(bytes.len());
            let is_csw = bytes.len() == CSW_LEN && bytes.starts_with(b"USBS");
            io.send_in(bytes).unwrap();
            TwoBankStep::Sent { start, end, is_csw }
        }
        Action::StallBoth => TwoBankStep::StallBoth,
        Action::StallIn => TwoBankStep::StallIn,
        Action::StoragePending => TwoBankStep::StoragePending,
        Action::Error(e) => panic!("BOT core error: {e:?}"),
    }
}

/// Two equal banks: a 2 MiB READ alternates its bulk-IN source between the
/// command bank and the alternate bank, keeps the CBW in the command bank,
/// and delivers the medium byte-exactly with zero residue.
#[test]
fn overlap_read_alternates_banks_and_is_byte_exact() {
    const BLOCKS: u16 = 4096; // 2 MiB at 512-byte blocks
    const TOTAL: usize = BLOCKS as usize * 512;
    const BANK: usize = 8192;
    const TAG: u32 = 0x71;

    let mut ram = vec![0u8; TOTAL];
    for (i, b) in ram.iter_mut().enumerate() {
        *b = (i % 251) as u8;
    }
    let expected = ram.clone();
    let mut backend = RamBackend::new(&mut ram);
    let mut slots = [TestLu::block(BLOCKS as u64, 512, 0)];
    let mut storage = PlaneSet::new(vec![Some(StorePlane::BlockRw(&mut backend))]);
    let mut table = table(&mut slots);
    let mut target = Target::new(&mut table[..]);
    let mut s = BotSession::new().with_overlap();
    let mut work = vec![0u8; BANK * 2];
    let mut scratch = Vec::new();
    let mut io = MockBotIo::new();
    let cbw = raw_cbw(TAG, TOTAL as u32, 0x80, 0, &rw10(0x28, 0, BLOCKS));
    io.feed_out(&cbw);

    assert!(s.overlap());
    let work_start = work.as_ptr() as usize;
    let mut cbw_offset = None;
    let mut data_sends = Vec::new();
    let mut ev = Event::Tick;
    let mut csw_sent = false;
    loop {
        match two_bank_next(
            &mut s,
            ev,
            &mut work,
            &mut scratch,
            &mut target,
            &mut storage,
            &mut io,
        ) {
            TwoBankStep::Recv { offset, len, probe } => {
                if !csw_sent && cbw_offset.is_none() && len == CBW_LEN && !probe {
                    cbw_offset = Some(offset);
                }
                if csw_sent && len == CBW_LEN && !probe {
                    break;
                }
                if probe {
                    match io.try_recv_out(&mut work[offset..offset + len]) {
                        Ok(n) => ev = Event::HostRecv { len: n },
                        Err(BotIoErr::WouldBlock) => ev = Event::HostIdle,
                        Err(_) => panic!("mock bulk-OUT I/O error"),
                    }
                } else {
                    let n = io.try_recv_out(&mut work[offset..offset + len]).unwrap();
                    ev = Event::HostRecv { len: n };
                }
            }
            TwoBankStep::Sent { start, end, is_csw } => {
                if start >= work_start && end <= work_start + work.len() {
                    let bank = if end <= work_start + BANK {
                        assert!(start >= work_start);
                        0
                    } else {
                        assert!(
                            start >= work_start + BANK,
                            "a bulk-IN chunk must not cross the bank split"
                        );
                        1
                    };
                    data_sends.push((bank, end - start));
                } else {
                    assert!(is_csw, "a HostSend outside work must be the CSW");
                }
                if is_csw {
                    csw_sent = true;
                }
                ev = Event::HostSent;
            }
            TwoBankStep::StoragePending => ev = Event::Tick,
            TwoBankStep::StallBoth => panic!("unexpected StallBoth"),
            TwoBankStep::StallIn => panic!("unexpected StallIn"),
        }
    }

    // The first bank is the command bank, so the CBW starts at offset 0.
    assert_eq!(cbw_offset, Some(0));
    assert_eq!(data_sends.len(), TOTAL / BANK);
    for (chunk, (bank, len)) in data_sends.iter().enumerate() {
        assert_eq!(*len, BANK, "chunk {chunk} must be one bank");
        assert_eq!(*bank, chunk % 2, "chunk {chunk} must alternate banks");
    }

    let sent = io.take_sent();
    assert_eq!(sent.len(), TOTAL + CSW_LEN);
    assert_eq!(&sent[..TOTAL], expected.as_slice(), "byte-exact read");
    assert_eq!(csw_fields(&sent), (TAG, 0, 0x00), "zero residue");
}

/// Two banks: a 16 KiB WRITE receives every chunk into the command bank (the
/// first half), never the alternate, and commits the bytes exactly.
#[test]
fn overlap_write_stays_in_the_command_bank() {
    const BANK: usize = 8192;
    const TOTAL: usize = 2 * BANK;
    const TAG: u32 = 0x72;

    let mut ram = vec![0u8; 64 * 1024];
    let mut backend = RamBackend::new(&mut ram);
    let mut slots = [TestLu::block(128, 512, 0)];
    let mut storage = PlaneSet::new(vec![Some(StorePlane::BlockRw(&mut backend))]);
    let mut table = table(&mut slots);
    let mut target = Target::new(&mut table[..]);
    let mut s = BotSession::new().with_overlap();
    let mut work = vec![0u8; BANK * 2];
    let mut scratch = Vec::new();
    let mut io = MockBotIo::new();

    let payload: Vec<u8> = (0..TOTAL as u32)
        .map(|i| (i.wrapping_mul(13) % 251) as u8)
        .collect();
    let cbw = raw_cbw(TAG, TOTAL as u32, 0x00, 0, &rw10(0x2A, 0, 32));
    io.feed_out(&cbw);
    io.feed_out(&payload);

    let mut ev = Event::Tick;
    let mut csw_sent = false;
    let mut data_recvs = 0;
    loop {
        match two_bank_next(
            &mut s,
            ev,
            &mut work,
            &mut scratch,
            &mut target,
            &mut storage,
            &mut io,
        ) {
            TwoBankStep::Recv { offset, len, probe } => {
                if csw_sent && len == CBW_LEN && !probe {
                    break;
                }
                if !probe && len != CBW_LEN {
                    assert!(
                        offset + len <= BANK,
                        "Data-Out must stay in the command bank (offset {offset}, len {len})"
                    );
                    data_recvs += 1;
                }
                if probe {
                    match io.try_recv_out(&mut work[offset..offset + len]) {
                        Ok(n) => ev = Event::HostRecv { len: n },
                        Err(BotIoErr::WouldBlock) => ev = Event::HostIdle,
                        Err(_) => panic!("mock bulk-OUT I/O error"),
                    }
                } else {
                    let n = io.try_recv_out(&mut work[offset..offset + len]).unwrap();
                    ev = Event::HostRecv { len: n };
                }
            }
            TwoBankStep::Sent { is_csw, .. } => {
                if is_csw {
                    csw_sent = true;
                }
                ev = Event::HostSent;
            }
            TwoBankStep::StoragePending => ev = Event::Tick,
            TwoBankStep::StallBoth => panic!("unexpected StallBoth"),
            TwoBankStep::StallIn => panic!("unexpected StallIn"),
        }
    }

    assert_eq!(data_recvs, TOTAL / BANK, "one receive per bank-sized chunk");
    let sent = io.take_sent();
    assert_eq!(csw_fields(&sent), (TAG, 0, 0x00), "zero residue");
    let mut check = vec![0u8; TOTAL];
    plane_read(&mut storage, 0, &mut check);
    assert_eq!(check, payload, "byte-exact commit");
}

/// A session without overlap keeps the historical layout: the CBW starts at
/// offset 0 of `work`.
#[test]
fn single_bank_session_cbw_starts_at_zero() {
    let mut ram = vec![0u8; 4096];
    let mut backend = RamBackend::new(&mut ram);
    let mut slots = [TestLu::block(8, 512, 0)];
    let mut storage = PlaneSet::new(vec![Some(StorePlane::BlockRw(&mut backend))]);
    let mut table = table(&mut slots);
    let mut target = Target::new(&mut table[..]);
    let mut s = BotSession::new();
    let mut work = [0u8; snowscsi::MIN_DATA_AREA];
    let mut scratch = [0u8; snowscsi::MIN_DATA_LEN];

    assert!(!s.overlap());
    match s.poll(
        Event::Tick,
        &mut work,
        &mut scratch,
        &mut target,
        &mut storage,
    ) {
        Action::HostRecv {
            offset: 0,
            len: CBW_LEN,
            probe: false,
        } => {}
        other => panic!("expected the single-bank command boundary, got {other:?}"),
    }
}

/// Overlap mode rejects an odd total and any bank below the USB data-area
/// floor before touching the target.
#[test]
fn overlap_rejects_odd_total_and_short_bank() {
    let mut ram = vec![0u8; 4096];
    let mut backend = RamBackend::new(&mut ram);
    let mut slots = [TestLu::block(8, 512, 0)];
    let mut storage = PlaneSet::new(vec![Some(StorePlane::BlockRw(&mut backend))]);
    let mut table = table(&mut slots);
    let mut target = Target::new(&mut table[..]);
    let mut s = BotSession::new().with_overlap();
    let mut scratch = [0u8; snowscsi::MIN_DATA_LEN];

    let mut odd = vec![0u8; 2 * snowscsi::MIN_DATA_AREA + 1];
    assert!(matches!(
        s.poll(
            Event::Tick,
            &mut odd,
            &mut scratch,
            &mut target,
            &mut storage
        ),
        Action::Error(BotTargetError::WorkBufTooSmall)
    ));

    let mut short = vec![0u8; 2 * (snowscsi::MIN_DATA_AREA - 1)];
    assert!(matches!(
        s.poll(
            Event::Tick,
            &mut short,
            &mut scratch,
            &mut target,
            &mut storage
        ),
        Action::Error(BotTargetError::WorkBufTooSmall)
    ));

    let mut valid = vec![0u8; 2 * snowscsi::MIN_DATA_AREA];
    match s.poll(
        Event::Tick,
        &mut valid,
        &mut scratch,
        &mut target,
        &mut storage,
    ) {
        Action::HostRecv {
            offset: 0,
            len: CBW_LEN,
            probe: false,
        } => {}
        other => panic!("expected the command boundary after valid sizes, got {other:?}"),
    }
}

// ── Long-operation bank lending ─────────────────────────────────────

/// Routes LUN 0 to the resident long operation's storage plane and every other
/// LUN to the command plane, so both may hold a token at the same time.
struct SplitLunPlan<'a> {
    long: PlaneSet<'a>,
    command: PlaneSet<'a>,
    lun: usize,
}

impl Storage for SplitLunPlan<'_> {
    fn select_lun(&mut self, lun: usize) {
        self.lun = lun;
        self.long.select_lun(0);
        self.command.select_lun(0);
    }

    fn begin_exec(&mut self, req: IoReq) -> IoToken {
        if self.lun == 0 {
            self.long.begin_exec(req)
        } else {
            self.command.begin_exec(req)
        }
    }

    fn poll_exec(&mut self, token: IoToken, buf: IoBuf<'_>) -> Poll<StorageReceipt> {
        if self.lun == 0 {
            self.long.poll_exec(token, buf)
        } else {
            self.command.poll_exec(token, buf)
        }
    }

    fn cancel(&mut self, token: IoToken) {
        if self.lun == 0 {
            self.long.cancel(token);
        } else {
            self.command.cancel(token);
        }
    }
}

/// Overlap mode does not defer the TUR: the shell reads its CBW while the
/// FORMAT zero-fill token is still in flight, the TUR completes, and the fill
/// settles byte-exactly.
#[test]
fn overlap_long_token_does_not_defer_the_tur() {
    let mut ram = vec![0xEEu8; 64 * 1024];
    let out = Arc::new(Mutex::new(VecDeque::new()));
    let in_flight = Arc::new(AtomicBool::new(false));
    let fill_done = Arc::new(AtomicBool::new(false));
    let violated = Arc::new(AtomicBool::new(false));
    let stop = Arc::new(AtomicBool::new(false));

    let mut params = [0u8; 12];
    params[1] = 0x02; // Immed
    params[2..4].copy_from_slice(&8u16.to_be_bytes());
    params[8] = 0x00; // Format Type 0 (full format)
    let tur = raw_cbw(TUR_TAG, 0, 0x80, 0, &[0x00, 0, 0, 0, 0, 0]);
    {
        let mut q = out.lock().unwrap();
        q.extend(raw_cbw(FORMAT_TAG, 12, 0x00, 0, &[0x04, 0x11, 0, 0, 0, 0]));
        q.extend(params);
    }

    let mut io = SharedBankIo {
        out: Arc::clone(&out),
        in_: Vec::new(),
        in_flight: Arc::clone(&in_flight),
        fill_done: Arc::clone(&fill_done),
        violated: Arc::clone(&violated),
        stop_tag: TUR_TAG,
        need_fill_done: true,
        saw_close_csw: false,
        stop: Arc::clone(&stop),
    };
    let mut gadget = MockGadget::new();
    let mut session = BotSession::new().with_overlap();
    let mut work = vec![0u8; 2 * snowscsi::MIN_DATA_LEN];
    let mut scratch = Vec::new();

    let mut slots = [TestLu::dvdram(1, 0)];
    let mut table = table(&mut slots);
    let mut target = Target::new(&mut table[..]);
    {
        let mut backend = RamBackend::new(&mut ram);
        let mut storage = SharedPlan {
            inner: PlaneSet::new(vec![Some(StorePlane::BlockRw(&mut backend))]),
            out: Arc::clone(&out),
            in_flight: Arc::clone(&in_flight),
            fill_done: Arc::clone(&fill_done),
            inject: Some(tur.to_vec()),
        };
        let result = serve(
            &mut io,
            &mut gadget,
            &mut session,
            &mut work,
            &mut scratch,
            &mut target,
            &mut storage,
            &stop,
        );
        assert_eq!(result, Ok(()), "the scripted host ends the session");
    }

    assert!(
        violated.load(Ordering::SeqCst),
        "the overlap shell must read the TUR CBW while the long token is in flight"
    );
    assert!(io.saw_close_csw, "the TUR was serviced");
    assert!(
        session.long_bank().is_none(),
        "the settled fill released its bank"
    );
    assert!(
        ram[..2048].iter().all(|b| *b == 0),
        "the FORMAT fill is byte-exact"
    );
}

/// While the long token holds bank B, a READ on another LUN gets bank A only:
/// it completes byte-exactly and never stages a prefetch into B.
#[test]
fn overlap_one_bank_read_never_uses_the_long_bank() {
    const BANK: usize = 8192;
    const BLOCKS: u16 = 32; // 16 KiB = two bank-sized chunks
    const TOTAL: usize = BLOCKS as usize * 512;
    const FORMAT_TAG_LOCAL: u32 = 0x81;
    const READ_TAG: u32 = 0x82;

    let mut long_ram = vec![0xEEu8; 64 * 1024];
    let mut cmd_ram = vec![0u8; TOTAL];
    for (i, b) in cmd_ram.iter_mut().enumerate() {
        *b = (i % 251) as u8;
    }
    let expected = cmd_ram.clone();
    let mut long_backend = RamBackend::new(&mut long_ram);
    let mut cmd_backend = RamBackend::new(&mut cmd_ram);
    let long = PlaneSet::new(vec![Some(StorePlane::BlockRw(&mut long_backend))]).with_pending(1);
    let command = PlaneSet::new(vec![Some(StorePlane::BlockRw(&mut cmd_backend))]);
    let mut storage = SplitLunPlan {
        long,
        command,
        lun: 0,
    };

    let mut slots = [TestLu::dvdram(1, 0), TestLu::block(128, 512, 1)];
    let mut table = table(&mut slots);
    let mut target = Target::new(&mut table[..]);
    let mut s = BotSession::new().with_overlap();
    let mut work = vec![0u8; 2 * BANK];
    let mut scratch = Vec::new();
    let mut io = MockBotIo::new();

    // Arm the resident FORMAT fill (Immed=1).
    let mut params = [0u8; 12];
    params[1] = 0x02;
    params[2..4].copy_from_slice(&8u16.to_be_bytes());
    io.feed_out(&raw_cbw(
        FORMAT_TAG_LOCAL,
        12,
        0x00,
        0,
        &[0x04, 0x11, 0, 0, 0, 0],
    ));
    io.feed_out(&params);
    assert_eq!(
        drive_until_done(
            &mut s,
            &mut io,
            &mut work,
            &mut scratch,
            &mut target,
            &mut storage,
        ),
        Drive::Processed
    );
    io.take_sent();

    // The first Tick starts the fill token on the bank opposite the command.
    let (cbw_offset, cbw_len) = match s.poll(
        Event::Tick,
        &mut work,
        &mut scratch,
        &mut target,
        &mut storage,
    ) {
        Action::HostRecv {
            offset,
            len,
            probe: false,
        } => (offset, len),
        other => panic!("expected the command boundary, got {other:?}"),
    };
    assert_eq!(s.long_bank(), Some(BankSide::Alt));
    assert_eq!(cbw_offset, 0, "the CBW stays in the command bank");

    // READ LUN 1 while the long token still holds the alternate bank.
    let read_cbw = raw_cbw(READ_TAG, TOTAL as u32, 0x80, 1, &rw10(0x28, 0, BLOCKS));
    io.feed_out(&read_cbw);
    let n = io
        .try_recv_out(&mut work[cbw_offset..cbw_offset + cbw_len])
        .unwrap();
    let work_start = work.as_ptr() as usize;
    let mut data_sends = 0;
    let mut csw_sent = false;
    let mut ev = Event::HostRecv { len: n };
    loop {
        match two_bank_next(
            &mut s,
            ev,
            &mut work,
            &mut scratch,
            &mut target,
            &mut storage,
            &mut io,
        ) {
            TwoBankStep::Recv { offset, len, probe } => {
                if csw_sent && len == CBW_LEN && !probe {
                    break;
                }
                if probe {
                    match io.try_recv_out(&mut work[offset..offset + len]) {
                        Ok(n) => ev = Event::HostRecv { len: n },
                        Err(BotIoErr::WouldBlock) => ev = Event::HostIdle,
                        Err(_) => panic!("mock bulk-OUT I/O error"),
                    }
                } else {
                    let n = io.try_recv_out(&mut work[offset..offset + len]).unwrap();
                    ev = Event::HostRecv { len: n };
                }
            }
            TwoBankStep::Sent { start, end, is_csw } => {
                if start >= work_start && end <= work_start + work.len() {
                    assert!(
                        end <= work_start + BANK,
                        "a one-bank READ staged into the long operation's bank"
                    );
                    data_sends += 1;
                } else {
                    assert!(is_csw, "a HostSend outside work must be the CSW");
                }
                if is_csw {
                    csw_sent = true;
                }
                ev = Event::HostSent;
            }
            TwoBankStep::StoragePending => ev = Event::Tick,
            TwoBankStep::StallBoth => panic!("unexpected StallBoth"),
            TwoBankStep::StallIn => panic!("unexpected StallIn"),
        }
    }

    assert_eq!(data_sends, TOTAL / BANK, "one send per bank-sized chunk");
    assert_eq!(
        s.long_bank(),
        Some(BankSide::Alt),
        "the long token must still be in flight"
    );
    let sent = io.take_sent();
    assert_eq!(sent.len(), TOTAL + CSW_LEN);
    assert_eq!(&sent[..TOTAL], expected.as_slice(), "byte-exact READ");
    assert_eq!(csw_fields(&sent), (READ_TAG, 0, 0x00), "zero residue");

    // Tick the resident fill to completion; its bank is then released.
    for _ in 0..64 {
        let _ = s.poll(
            Event::Tick,
            &mut work,
            &mut scratch,
            &mut target,
            &mut storage,
        );
        if matches!(
            target.snapshot_rt(0).map(|info| info.long.phase),
            Ok(LongPhase::Settled)
        ) {
            break;
        }
    }
    assert!(matches!(
        target.snapshot_rt(0).map(|info| info.long.phase),
        Ok(LongPhase::Settled)
    ));
    assert!(
        s.long_bank().is_none(),
        "the long bank clears when the operation settles"
    );
    let mut check = vec![0u8; 64 * 1024];
    plane_read(&mut storage.long, 0, &mut check);
    assert!(
        check[..2048].iter().all(|&b| b == 0),
        "the FORMAT fill is byte-exact"
    );
}
