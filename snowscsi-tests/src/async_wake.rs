//! Wake-driven storage adapter and the asynchronous USB shell.
//!
//! The test adapter uses a **safe deferred-completion model**: the core's
//! buffer is re-borrowed by `poll_exec` when the test releases the operation,
//! and the read data is filled in place then. It deliberately does not claim
//! zero-copy — a platform adapter submits the caller's buffer directly; this
//! one only proves that the shell waits on `AsyncWake` instead of spinning.
//!
//! The wire side is an in-memory script with immediate (never-yielding)
//! futures, so the only suspension point in these tests is the storage wait.

use core::cell::{Cell, RefCell};
use core::future::Future;
use core::task::{Context, Poll, Waker};
use std::collections::VecDeque;
use std::rc::Rc;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::Arc;
use std::task::Wake;

use snowscsi::core::async_wake::{wait, AsyncWake};
use snowscsi::core::storage::{IoBuf, IoReq, IoToken, Storage, StorageReceipt};
use snowscsi::core::{Direction, Fault, Lu, Target};
use snowscsi::core::{Flow, ServeExit};
use snowscsi::usb::serve::serve_async;
use snowscsi::usb::{
    AsyncBotRecv, AsyncBotSend, BotIoErr, BotSession, CtrlAck, CtrlReply, CtrlReq, Gadget,
    RecvMode, ServeError, CSW_LEN,
};

use crate::iscsi_harness::{TestLu, TestPair};
use crate::usb_bot::{raw_cbw, rw10};

/// Shared completion state: the adapter registers the waker here and the test
/// releases the operation.
struct WakeGate {
    ready: bool,
    polls: usize,
    waker: Option<Waker>,
}

impl WakeGate {
    fn new() -> Rc<RefCell<Self>> {
        Rc::new(RefCell::new(Self {
            ready: false,
            polls: 0,
            waker: None,
        }))
    }
}

/// Handle around [`WakeGate`] so a test can both await it and release it
/// without borrowing the future's storage argument.
struct Gate(Rc<RefCell<WakeGate>>);

impl AsyncWake for Gate {
    fn poll_wake(&mut self, cx: &mut Context<'_>) -> Poll<()> {
        let mut gate = self.0.borrow_mut();
        gate.polls += 1;
        if gate.ready {
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

/// Counts wakes delivered through the test's manual waker.
struct CountingWake(Arc<AtomicUsize>);

impl Wake for CountingWake {
    fn wake(self: Arc<Self>) {
        self.0.fetch_add(1, Ordering::SeqCst);
    }
}

/// Safe deferred storage adapter over an in-memory backing.
struct DeferredStorage {
    backing: Vec<u8>,
    req: Option<IoReq>,
    tag: u32,
    live: bool,
    gate: Rc<RefCell<WakeGate>>,
    /// Number of `poll_exec` calls that observed `Pending` (shared with the
    /// test so it can inspect progress while the future borrows the adapter).
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
        StorageReceipt::failed(Fault::Contract, 0, snowscsi::core::Effect::Known)
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

/// In-memory USB wire: one scripted input queue and one recorded output.
#[derive(Default)]
struct Wire {
    input: VecDeque<u8>,
    output: Vec<u8>,
}

struct AsyncWire {
    wire: Rc<RefCell<Wire>>,
}

impl AsyncBotRecv for AsyncWire {
    async fn recv(&mut self, buf: &mut [u8], mode: RecvMode) -> Result<usize, BotIoErr> {
        let mut wire = self.wire.borrow_mut();
        if wire.input.is_empty() {
            return match mode {
                RecvMode::Probe => Err(BotIoErr::WouldBlock),
                RecvMode::Until(_) | RecvMode::Forever => Ok(0),
            };
        }
        let n = buf.len().min(wire.input.len());
        for slot in &mut buf[..n] {
            *slot = wire.input.pop_front().expect("input length checked");
        }
        Ok(n)
    }
}

impl AsyncBotSend for AsyncWire {
    async fn send(&mut self, buf: &[u8]) -> Result<(), BotIoErr> {
        self.wire.borrow_mut().output.extend_from_slice(buf);
        Ok(())
    }
}

struct NoAck;
impl CtrlAck for NoAck {
    fn ack(self) {}
}

struct NoReply;
impl CtrlReply for NoReply {
    fn send(&mut self, _data: &[u8]) -> Result<(), ()> {
        Ok(())
    }
}

struct NoGadget;
impl<'a> Gadget<'a> for NoGadget {
    type Ack = NoAck;
    type Reply = NoReply;

    fn try_next_ctrl(&'a mut self) -> Option<CtrlReq<NoAck, NoReply>> {
        None
    }
}

/// `wait` stays pending until the test wakes it, then completes.
#[test]
fn wait_yields_until_woken() {
    let gate = WakeGate::new();
    let mut handle = Gate(Rc::clone(&gate));
    let wakes = Arc::new(AtomicUsize::new(0));
    let waker = Waker::from(Arc::new(CountingWake(Arc::clone(&wakes))));
    let mut cx = Context::from_waker(&waker);

    let mut fut = core::pin::pin!(wait(&mut handle));
    assert!(fut.as_mut().poll(&mut cx).is_pending());
    assert_eq!(gate.borrow().polls, 1, "one registration, no retry loop");
    assert_eq!(wakes.load(Ordering::SeqCst), 0, "must not self-wake");

    complete(&gate);
    assert_eq!(
        wakes.load(Ordering::SeqCst),
        1,
        "test wake reached the waker"
    );
    assert!(fut.as_mut().poll(&mut cx).is_ready());
}

/// A READ goes through `StoragePending`, the shell awaits the adapter, and the
/// test releasing the adapter completes the read byte-exact.
#[test]
fn serve_async_awaits_deferred_storage_without_spinning() {
    const BLOCKS: usize = 128;
    const BLOCK: usize = 512;

    let backing: Vec<u8> = (0..BLOCKS * BLOCK).map(|i| (i % 251) as u8).collect();
    let expected = backing[3 * BLOCK..5 * BLOCK].to_vec();

    let gate = WakeGate::new();
    let mut storage = DeferredStorage::new(backing, Rc::clone(&gate));
    let pending_execs = Rc::clone(&storage.pending_execs);

    let mut slots = [TestLu::block(BLOCKS as u64, BLOCK as u32, 0)];
    let mut table: Vec<&mut dyn Lu<Pair = TestPair>> = slots
        .iter_mut()
        .map(|slot| slot as &mut dyn Lu<Pair = TestPair>)
        .collect();
    let mut target = Target::new(&mut table[..]);
    let mut session = BotSession::new();
    let mut work = vec![0u8; snowscsi::MIN_DATA_LEN];
    let mut scratch = vec![0u8; snowscsi::MIN_DATA_LEN];

    // One READ(10) CBW, LBA 3, two 512-byte blocks.
    let wire = Rc::new(RefCell::new(Wire::default()));
    wire.borrow_mut()
        .input
        .extend(raw_cbw(1, 2 * BLOCK as u32, 0x80, 0, &rw10(0x28, 3, 2)));
    let mut recv = AsyncWire {
        wire: Rc::clone(&wire),
    };
    let mut send = AsyncWire {
        wire: Rc::clone(&wire),
    };
    let mut gadget = NoGadget;
    let stop = Flow::new();

    let wakes = Arc::new(AtomicUsize::new(0));
    let waker = Waker::from(Arc::new(CountingWake(Arc::clone(&wakes))));
    let mut cx = Context::from_waker(&waker);

    let mut fut = core::pin::pin!(serve_async(
        &mut recv,
        &mut send,
        &mut gadget,
        &mut session,
        &mut work,
        &mut scratch,
        &mut target,
        &mut storage,
        &stop,
    ));

    // The shell reached the deferred storage step and yielded: exactly one
    // `poll_wake` registration, no output, and no self-generated wake.
    assert!(fut.as_mut().poll(&mut cx).is_pending());
    assert_eq!(gate.borrow().polls, 1, "the shell must not spin");
    assert_eq!(pending_execs.get(), 1);
    assert_eq!(wakes.load(Ordering::SeqCst), 0);
    assert!(wire.borrow().output.is_empty(), "no data before the wake");

    // The test controls progress: release the operation and wake the future.
    complete(&gate);
    assert_eq!(wakes.load(Ordering::SeqCst), 1);

    match fut.as_mut().poll(&mut cx) {
        Poll::Ready(Ok(ServeExit::WireGone)) => {}
        Poll::Ready(Ok(other)) => panic!("unexpected serve exit: {other:?}"),
        Poll::Ready(Err(e)) => panic!("serve_async failed: {e}"),
        Poll::Pending => panic!("storage completion must finish the read"),
    }
    assert_eq!(gate.borrow().polls, 2, "one wake, one resume");

    let output = wire.borrow().output.clone();
    assert_eq!(
        &output[..expected.len()],
        &expected[..],
        "READ data must match the backing"
    );
    assert_eq!(output.len(), expected.len() + CSW_LEN);
    let csw = &output[expected.len()..];
    assert_eq!(&csw[..4], b"USBS");
    assert_eq!(u32::from_le_bytes([csw[4], csw[5], csw[6], csw[7]]), 1);
    assert_eq!(csw[12], 0x00, "CSW status must be success");
}

/// The shell stays parked while the adapter is pending; a second poll without
/// a wake registers again but makes no progress (the future, not a loop,
/// owns the wait).
#[test]
fn pending_storage_progress_is_controlled_by_the_test() {
    let gate = WakeGate::new();
    let mut gate_handle = Gate(Rc::clone(&gate));
    let mut fut = core::pin::pin!(wait(&mut gate_handle));
    let waker = Waker::from(Arc::new(CountingWake(Arc::new(AtomicUsize::new(0)))));
    let mut cx = Context::from_waker(&waker);

    assert!(fut.as_mut().poll(&mut cx).is_pending());
    assert_eq!(gate.borrow().polls, 1);
    // A spurious poll is still just a registration: no completion, no wake.
    assert!(fut.as_mut().poll(&mut cx).is_pending());
    assert_eq!(gate.borrow().polls, 2);

    complete(&gate);
    assert!(fut.as_mut().poll(&mut cx).is_ready());
    assert_eq!(gate.borrow().polls, 3);
}
