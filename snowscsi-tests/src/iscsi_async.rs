//! Asynchronous iSCSI shell integration tests.
//!
//! The wire is a scripted in-memory [`MockAsyncConn`]; the shell is driven by a
//! minimal safe `block_on`, except where the test itself controls progress
//! through a deferred [`Storage`] + [`AsyncWake`] adapter. No runtime, no
//! threads and no `unsafe` are involved.

use core::cell::{Cell, RefCell};
use core::future::Future;
use core::pin::pin;
use core::task::{Context, Poll, Waker};
use std::collections::VecDeque;
use std::rc::Rc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::task::Wake;

use snowscsi::core::async_wake::AsyncWake;
use snowscsi::core::storage::{
    BlockingStorage, IoBuf, IoReq, IoToken, Storage, StorageReceipt, SyncStorage,
};
use snowscsi::core::{Direction, Effect, Fault, Lu, ServeExit, Target};
use snowscsi::iscsi::conn::{read_exact_async, AsyncConn};
use snowscsi::iscsi::pdu::{flag, op, stage, status, BHS_SIZE};
use snowscsi::iscsi::target::IscsiSession;
use snowscsi::iscsi::transport::serve_conn_async;
use snowscsi::MIN_DATA_LEN;

use crate::iscsi_harness::{TestLu, TestPair};

const BLOCKS: usize = 128;
const BLOCK: usize = 512;

/// Login parameters as sent by a Linux open-iscsi initiator.
const REQ_TEXT: &str = "InitiatorName=iqn.1994-05.com.redhat:702f27e1da14\0InitiatorAlias=develop\0TargetName=iqn.1970-01.local.snowscsi:target\0SessionType=Normal\0HeaderDigest=None\0DataDigest=None\0DefaultTime2Wait=2\0DefaultTime2Retain=0\0IFMarker=No\0OFMarker=No\0ErrorRecoveryLevel=0\0InitialR2T=No\0ImmediateData=Yes\0MaxBurstLength=16776192\0FirstBurstLength=262144\0MaxOutstandingR2T=1\0MaxConnections=1\0DataPDUInOrder=Yes\0DataSequenceInOrder=Yes\0MaxRecvDataSegmentLength=262144\0";

fn be32(v: u32) -> [u8; 4] {
    v.to_be_bytes()
}

fn login_bhs(dsl: u32) -> [u8; 48] {
    let mut bhs = [0u8; 48];
    bhs[0] = op::LOGIN_REQ | 0x40;
    bhs[1] = flag::T_BIT | ((stage::OP_PARAM & 0x03) << flag::CSG_SHIFT) | stage::FULL_FEATURE;
    bhs[5] = (dsl >> 16) as u8;
    bhs[6] = (dsl >> 8) as u8;
    bhs[7] = dsl as u8;
    bhs[8..14].copy_from_slice(&[0x00, 0x01, 0x23, 0x45, 0x67, 0x89]);
    bhs
}

fn read10_bhs(lba: u32, blocks: u16, itt: u32, cmd_sn: u32) -> [u8; 48] {
    let mut bhs = [0u8; 48];
    bhs[0] = op::SCSI_CMD;
    bhs[1] = 0x40;
    bhs[16..20].copy_from_slice(&be32(itt));
    bhs[24..28].copy_from_slice(&be32(cmd_sn));
    bhs[28..32].copy_from_slice(&be32(cmd_sn)); // ExpStatSN
    bhs[32] = 0x28; // READ(10)
    bhs[34..38].copy_from_slice(&be32(lba));
    bhs[39..41].copy_from_slice(&blocks.to_be_bytes());
    bhs
}

/// Scripted asynchronous connection: a byte queue in and a recorded stream out.
/// `max_read` forces short reads so partial TCP deliveries are exercised. The
/// wire is shared behind an `Rc<RefCell<_>>` so a test can inspect progress
/// while the future mutably borrows the connection.
#[derive(Default)]
struct Wire {
    input: VecDeque<u8>,
    output: Vec<u8>,
}

struct MockAsyncConn {
    wire: Rc<RefCell<Wire>>,
    max_read: usize,
}

impl MockAsyncConn {
    fn new(max_read: usize) -> Self {
        Self {
            wire: Rc::new(RefCell::new(Wire::default())),
            max_read,
        }
    }

    fn handle(&self) -> Rc<RefCell<Wire>> {
        Rc::clone(&self.wire)
    }

    fn feed_bytes(&mut self, bytes: &[u8]) {
        self.wire.borrow_mut().input.extend(bytes);
    }

    fn feed_padded(&mut self, bhs: &[u8; BHS_SIZE], data: &[u8]) {
        let mut wire = self.wire.borrow_mut();
        wire.input.extend(bhs);
        wire.input.extend(data);
        let pad = (4 - ((BHS_SIZE + data.len()) & 3)) & 3;
        wire.input.extend(std::iter::repeat_n(0u8, pad));
    }
}

impl AsyncConn for MockAsyncConn {
    async fn read(&mut self, buf: &mut [u8]) -> Result<usize, ()> {
        let mut wire = self.wire.borrow_mut();
        if wire.input.is_empty() {
            return Ok(0);
        }
        let n = buf.len().min(wire.input.len()).min(self.max_read.max(1));
        for (out, byte) in buf[..n].iter_mut().zip(wire.input.drain(..n)) {
            *out = byte;
        }
        Ok(n)
    }

    async fn write_all(&mut self, buf: &[u8]) -> Result<(), ()> {
        self.wire.borrow_mut().output.extend_from_slice(buf);
        Ok(())
    }
}

/// Minimal safe single-threaded executor. Every wire future is immediately
/// ready, so this only drives the loop over those completion points.
fn block_on<F: Future>(fut: F) -> F::Output {
    struct NoopWake;

    #[allow(clippy::manual_noop_waker)] // the helper is deliberately driven through `Wake`
    impl Wake for NoopWake {
        fn wake(self: Arc<Self>) {}
    }

    let waker = Waker::from(Arc::new(NoopWake));
    let mut cx = Context::from_waker(&waker);
    let mut fut = pin!(fut);
    loop {
        if let Poll::Ready(v) = fut.as_mut().poll(&mut cx) {
            return v;
        }
    }
}

/// Waker that only counts wake-ups, so a test can assert the future never
/// self-woke while parked on storage.
struct CountingWake(Arc<AtomicUsize>);

impl Wake for CountingWake {
    fn wake(self: Arc<Self>) {
        self.0.fetch_add(1, Ordering::SeqCst);
    }
}

/// Shared completion gate for the deferred storage adapter.
struct WakeGate {
    ready: bool,
    polls: usize,
    waker: Option<Waker>,
}

/// Deferred storage adapter: `poll_exec` stays pending until the test releases
/// the gate, then fills the caller's buffer in place. The shell must wait on
/// [`AsyncWake`] instead of spinning.
struct DeferredStorage {
    backing: Vec<u8>,
    req: Option<IoReq>,
    tag: u32,
    live: bool,
    gate: Rc<RefCell<WakeGate>>,
    pending_execs: Rc<Cell<usize>>,
}

impl DeferredStorage {
    fn new(backing: Vec<u8>, gate: Rc<RefCell<WakeGate>>) -> Self {
        Self {
            backing,
            req: None,
            tag: 0,
            live: false,
            gate,
            pending_execs: Rc::new(Cell::new(0)),
        }
    }

    fn token(&self) -> IoToken {
        IoToken::new(0, self.tag)
    }

    fn contract() -> StorageReceipt {
        StorageReceipt::failed(Fault::Contract, 0, Effect::Known)
    }
}

impl Storage for DeferredStorage {
    fn begin_exec(&mut self, req: IoReq) -> IoToken {
        if self.live {
            return IoToken::new(u8::MAX, 0);
        }
        self.tag = self.tag.wrapping_add(1).max(1);
        self.req = Some(req);
        self.live = true;
        {
            let mut gate = self.gate.borrow_mut();
            gate.ready = false;
            gate.waker = None;
        }
        self.token()
    }

    fn poll_exec(&mut self, token: IoToken, buf: IoBuf<'_>) -> Poll<StorageReceipt> {
        match self.req {
            Some(req) if self.live && token == self.token() => req,
            _ => return Poll::Ready(Self::contract()),
        };

        // Deferred model: nothing is read or written until the test releases
        // the operation, then the caller's buffer is filled in place.
        if !self.gate.borrow().ready {
            self.pending_execs.set(self.pending_execs.get() + 1);
            return Poll::Pending;
        }

        let req = self.req.take().expect("live request");
        self.live = false;
        let ok = match (req.dir, &buf) {
            (Direction::None, IoBuf::None) => req.len == 0,
            (Direction::ToHost, IoBuf::Read(b)) => req.len as usize == b.len(),
            (Direction::FromHost, IoBuf::Write(b)) => req.len as usize == b.len(),
            _ => false,
        };
        if !ok {
            return Poll::Ready(Self::contract());
        }

        let offset = req.offset as usize;
        match buf {
            IoBuf::None => {}
            IoBuf::Read(bytes) => {
                let end = offset + bytes.len();
                if end > self.backing.len() {
                    return Poll::Ready(Self::contract());
                }
                bytes.copy_from_slice(&self.backing[offset..end]);
            }
            IoBuf::Write(bytes) => {
                let end = offset + bytes.len();
                if end > self.backing.len() {
                    return Poll::Ready(Self::contract());
                }
                self.backing[offset..end].copy_from_slice(bytes);
            }
        }
        Poll::Ready(StorageReceipt::ok(req.len as usize))
    }

    fn cancel(&mut self, token: IoToken) {
        if self.live && token == self.token() {
            self.live = false;
            self.req = None;
        }
    }
}

impl AsyncWake for DeferredStorage {
    fn poll_wake(&mut self, cx: &mut Context<'_>) -> Poll<()> {
        let mut gate = self.gate.borrow_mut();
        gate.polls += 1;
        // No live operation means there is nothing to wait for.
        if !self.live || gate.ready {
            Poll::Ready(())
        } else {
            gate.waker = Some(cx.waker().clone());
            Poll::Pending
        }
    }
}

/// Release the gate and wake whoever registered.
fn complete(gate: &Rc<RefCell<WakeGate>>) {
    let waker = {
        let mut gate = gate.borrow_mut();
        gate.ready = true;
        gate.waker.take()
    };
    if let Some(waker) = waker {
        waker.wake();
    }
}

/// Immediately-ready in-memory storage for the short-read scenario.
struct RamSync {
    backing: Vec<u8>,
}

impl SyncStorage for RamSync {
    fn exec(&mut self, req: IoReq, buf: IoBuf<'_>) -> StorageReceipt {
        let ok = match (req.dir, &buf) {
            (Direction::None, IoBuf::None) => req.len == 0,
            (Direction::ToHost, IoBuf::Read(b)) => req.len as usize == b.len(),
            (Direction::FromHost, IoBuf::Write(b)) => req.len as usize == b.len(),
            _ => false,
        };
        if !ok {
            return StorageReceipt::failed(Fault::Contract, 0, Effect::Known);
        }
        let offset = req.offset as usize;
        match buf {
            IoBuf::None => {}
            IoBuf::Read(bytes) => {
                let end = offset + bytes.len();
                if end > self.backing.len() {
                    return StorageReceipt::failed(Fault::OutOfBounds, 0, Effect::Known);
                }
                bytes.copy_from_slice(&self.backing[offset..end]);
            }
            IoBuf::Write(bytes) => {
                let end = offset + bytes.len();
                if end > self.backing.len() {
                    return StorageReceipt::failed(Fault::OutOfBounds, 0, Effect::Known);
                }
                self.backing[offset..end].copy_from_slice(bytes);
            }
        }
        StorageReceipt::ok(req.len as usize)
    }
}

/// Split a recorded device→host byte stream into `(BHS, data segment)` PDUs.
fn pdus(tx: &[u8]) -> Vec<(Vec<u8>, Vec<u8>)> {
    let mut out = Vec::new();
    let mut off = 0usize;
    while off + BHS_SIZE <= tx.len() {
        let bhs = &tx[off..off + BHS_SIZE];
        let dsl = ((bhs[5] as usize) << 16) | ((bhs[6] as usize) << 8) | bhs[7] as usize;
        let data_end = off + BHS_SIZE + dsl;
        if data_end > tx.len() {
            break;
        }
        let pad = (4 - (dsl & 3)) & 3;
        out.push((bhs.to_vec(), tx[off + BHS_SIZE..data_end].to_vec()));
        off = data_end + pad;
    }
    out
}

fn fixture_backing() -> Vec<u8> {
    (0..BLOCKS * BLOCK).map(|i| (i % 251) as u8).collect()
}

fn expected_read(backing: &[u8]) -> Vec<u8> {
    backing[3 * BLOCK..5 * BLOCK].to_vec()
}

fn feed_login_and_read(conn: &mut MockAsyncConn) {
    let text = REQ_TEXT.as_bytes();
    conn.feed_padded(&login_bhs(text.len() as u32), text);
    conn.feed_padded(&read10_bhs(3, 2, 0x1111, 0), &[]);
}

/// Assert the recorded response stream: Login Response, byte-exact Data-In,
/// and a GOOD terminal status (the terminating Data-In carries it).
fn assert_login_read_output(output: &[u8], expected: &[u8]) {
    let frames = pdus(output);
    assert_eq!(frames[0].0[0] & 0x3F, op::LOGIN_RESP, "first PDU is login");
    assert_eq!(frames[0].0[36], 0x00, "login status class");

    let mut data = Vec::new();
    let mut status_pdu = None;
    for (bhs, seg) in &frames[1..] {
        match bhs[0] & 0x3F {
            op::SCSI_DATA_IN => {
                data.extend_from_slice(seg);
                // A terminating Data-In PDU carries the fixed SCSI status.
                if bhs[1] & 0x01 != 0 {
                    status_pdu = Some(bhs);
                }
            }
            op::SCSI_RESP => status_pdu = Some(bhs),
            other => panic!("unexpected PDU opcode {other:#04x}"),
        }
    }
    assert_eq!(data, expected, "READ data must match the backing");
    let response = status_pdu.expect("terminal status PDU");
    assert_eq!(&response[16..20], &be32(0x1111), "ITT echoed");
    assert_eq!(response[3], status::GOOD, "command status");
}

/// A READ waits on the deferred adapter; the future stays pending until the
/// test releases it, then the command completes byte-exact.
#[test]
fn serve_conn_async_awaits_deferred_storage() {
    let backing = fixture_backing();
    let expected = expected_read(&backing);

    let gate = Rc::new(RefCell::new(WakeGate {
        ready: false,
        polls: 0,
        waker: None,
    }));
    let mut storage = DeferredStorage::new(backing, Rc::clone(&gate));
    let pending_execs = Rc::clone(&storage.pending_execs);

    let mut slots = [TestLu::block(BLOCKS as u64, BLOCK as u32, 0)];
    let mut table: Vec<&mut dyn Lu<Pair = TestPair>> = slots
        .iter_mut()
        .map(|slot| slot as &mut dyn Lu<Pair = TestPair>)
        .collect();
    let mut target = Target::new(&mut table[..]);
    let mut session = IscsiSession::new();
    let mut work = vec![0u8; MIN_DATA_LEN + BHS_SIZE];
    let mut scratch = vec![0u8; MIN_DATA_LEN];

    let mut conn = MockAsyncConn::new(usize::MAX);
    feed_login_and_read(&mut conn);
    let wire = conn.handle();

    let wakes = Arc::new(AtomicUsize::new(0));
    let waker = Waker::from(Arc::new(CountingWake(Arc::clone(&wakes))));
    let mut cx = Context::from_waker(&waker);
    let mut fut = pin!(serve_conn_async(
        &mut conn,
        &mut work,
        &mut scratch,
        &mut session,
        &mut target,
        &mut storage,
    ));

    // Login completed, the READ reached the deferred adapter and the shell
    // parked on AsyncWake: one registration, no self-wake, no Data-In yet.
    assert!(fut.as_mut().poll(&mut cx).is_pending());
    assert_eq!(gate.borrow().polls, 1, "the shell must not spin");
    assert_eq!(pending_execs.get(), 1);
    assert_eq!(wakes.load(Ordering::SeqCst), 0, "must not self-wake");
    let parked = wire.borrow().output.len();
    {
        let output = wire.borrow();
        let frames = pdus(&output.output);
        assert_eq!(frames[0].0[0] & 0x3F, op::LOGIN_RESP);
        assert!(
            frames.iter().all(|(b, _)| b[0] & 0x3F != op::SCSI_RESP),
            "no READ response before the storage wake"
        );
    }

    // Still pending without the wake: the test, not the shell, drives progress.
    assert!(fut.as_mut().poll(&mut cx).is_pending());
    assert_eq!(
        gate.borrow().polls,
        2,
        "a spurious poll is only a re-registration"
    );
    assert_eq!(pending_execs.get(), 1, "storage was not polled again");
    assert_eq!(wakes.load(Ordering::SeqCst), 0);
    assert_eq!(
        wire.borrow().output.len(),
        parked,
        "no output before the wake"
    );

    // Release the operation: the registered waker fires and the command ends.
    complete(&gate);
    assert_eq!(wakes.load(Ordering::SeqCst), 1);

    assert_eq!(
        fut.as_mut().poll(&mut cx),
        Poll::Ready(Ok(ServeExit::WireGone))
    );
    assert_login_read_output(&wire.borrow().output, &expected);
}

/// Partial TCP reads (a few bytes per `read`) still assemble the exact PDUs.
#[test]
fn serve_conn_async_completes_across_short_reads() {
    let backing = fixture_backing();
    let expected = expected_read(&backing);
    let mut storage = BlockingStorage::new(RamSync { backing });

    let mut slots = [TestLu::block(BLOCKS as u64, BLOCK as u32, 0)];
    let mut table: Vec<&mut dyn Lu<Pair = TestPair>> = slots
        .iter_mut()
        .map(|slot| slot as &mut dyn Lu<Pair = TestPair>)
        .collect();
    let mut target = Target::new(&mut table[..]);
    let mut session = IscsiSession::new();
    let mut work = vec![0u8; MIN_DATA_LEN + BHS_SIZE];
    let mut scratch = vec![0u8; MIN_DATA_LEN];

    // Deliver at most 5 bytes per read, splitting every BHS and data segment.
    let mut conn = MockAsyncConn::new(5);
    feed_login_and_read(&mut conn);
    let wire = conn.handle();

    let result = block_on(serve_conn_async(
        &mut conn,
        &mut work,
        &mut scratch,
        &mut session,
        &mut target,
        &mut storage,
    ));
    assert_eq!(result, Ok(ServeExit::WireGone));
    assert_login_read_output(&wire.borrow().output, &expected);
}

/// `read_exact_async` loops over short reads and reports EOF as an error.
#[test]
fn read_exact_async_handles_short_reads_and_eof() {
    let mut conn = MockAsyncConn::new(3);
    conn.feed_bytes(b"hello world");
    let mut buf = [0u8; 11];
    assert_eq!(block_on(read_exact_async(&mut conn, &mut buf)), Ok(()));
    assert_eq!(&buf, b"hello world");

    let mut short = [0u8; 12];
    assert_eq!(
        block_on(read_exact_async(&mut conn, &mut short)),
        Err(()),
        "EOF before the buffer is full"
    );
}
