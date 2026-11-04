//! Per-LUN background storage adapter.
//!
//! [`CliStorage`](super::CliStorage) executes each operation inline inside
//! `poll_exec`, so a blocking transport cannot overlap a storage read or write
//! with the wire call it is about to make. This adapter moves the plane onto a
//! dedicated worker thread instead: the operation is posted from `begin_exec`
//! (or the first `poll_exec` for a write, whose data only arrives with the
//! buffer) and the caller polls the channel while the transport is busy.
//!
//! One copy per operation is unavoidable with the current seam: `begin_exec`
//! receives metadata only and `poll_exec` re-borrows the caller's buffer, so
//! the worker stages the bytes in a fixed per-bank buffer that travels with
//! the job.
//!
//! A plane has a fixed table of four slots. Only one job per plane is in
//! flight at a time (the buffer is the shared resource); a second read or sync
//! stays `Pending` until the buffer returns and its own token is polled again.
//! Writes wait in the table until the caller supplies their data.

use core::task::{Context, Poll, Waker};

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc::{self, Receiver, Sender};
use std::sync::{Arc, Mutex};
use std::thread::Scope;

use snowscsi::common::seekable_storage::StorageError;
use snowscsi::core::storage::{IoBuf, IoReq, IoToken, Storage, StorageReceipt};
use snowscsi::core::{Direction, Effect, Fault};

use super::OwnedPlane;

/// Fixed slot table size, matching the library's synchronous adapter.
const SLOTS: usize = 4;

/// One unit of work handed to a plane's worker thread.
struct Job {
    tag: u32,
    req: IoReq,
    /// Per-bank staging buffer; travels to the worker and back so exactly one
    /// buffer exists per plane.
    buf: Vec<u8>,
}

/// A finished job, carrying the staging buffer back.
struct Done {
    tag: u32,
    result: Result<(), StorageError>,
    buf: Vec<u8>,
}

/// Slot lifecycle.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum SlotState {
    /// `FromHost` request whose data has not arrived yet.
    Waiting,
    /// Ready to post, waiting for the plane's staging buffer.
    Pending,
    /// Posted to the worker thread.
    Running,
    /// Worker finished; the receipt is reported on the next poll.
    Settled,
    /// Cancelled while running; freed when the result comes back.
    Cancelled,
}

struct Slot {
    req: IoReq,
    tag: u32,
    state: SlotState,
    result: Option<Result<(), StorageError>>,
    /// Staging buffer of a settled job. It stays reserved here until the token
    /// is polled, so a later job can never overwrite bytes a `ToHost` poll has
    /// not copied out yet.
    staged: Option<Vec<u8>>,
}

/// Completion signal shared between a plane's slot table and its worker.
///
/// The worker records progress before waking, so a completion that lands
/// between the registration and the check in [`WorkerPlane::poll_wake`] is
/// still reported as [`Poll::Ready`].
#[cfg_attr(not(feature = "tokio"), allow(dead_code))]
struct WorkerWake {
    progressed: AtomicBool,
    waker: Mutex<Option<Waker>>,
}

#[cfg_attr(not(feature = "tokio"), allow(dead_code))]
impl WorkerWake {
    fn new() -> Self {
        Self {
            progressed: AtomicBool::new(false),
            waker: Mutex::new(None),
        }
    }

    /// Store the task to wake on the next completion.
    ///
    /// One waiter only: the shell awaits a single connection at a time, so a
    /// second concurrent waiter would overwrite this slot and never wake.
    fn register(&self, waker: &Waker) {
        *self.waker.lock().unwrap() = Some(waker.clone());
    }

    /// Record that the worker posted a result and wake the registered task.
    fn notify(&self) {
        self.progressed.store(true, Ordering::SeqCst);
        let waker = self.waker.lock().unwrap().take();
        if let Some(waker) = waker {
            waker.wake();
        }
    }

    fn take_progress(&self) -> bool {
        self.progressed.swap(false, Ordering::SeqCst)
    }
}

/// One LUN's worker channel plus the slot table the caller addresses.
struct WorkerPlane {
    slots: [Option<Slot>; SLOTS],
    tx: Sender<Job>,
    rx: Receiver<Done>,
    next_tag: u32,
    /// `None` while the buffer is on the worker thread.
    buf: Option<Vec<u8>>,
    per_bank: usize,
    /// The backing plane is a persistent CD-R bundle, so a host eject drops
    /// it instead of leaving it addressable.
    bundle: bool,
    #[cfg_attr(not(feature = "tokio"), allow(dead_code))]
    wake: Arc<WorkerWake>,
}

impl WorkerPlane {
    fn new(
        tx: Sender<Job>,
        rx: Receiver<Done>,
        per_bank: usize,
        bundle: bool,
        wake: Arc<WorkerWake>,
    ) -> Self {
        Self {
            slots: std::array::from_fn(|_| None),
            tx,
            rx,
            next_tag: 1,
            buf: Some(vec![0u8; per_bank]),
            per_bank,
            bundle,
            wake,
        }
    }

    fn mint_tag(&mut self) -> u32 {
        let tag = self.next_tag;
        self.next_tag = self.next_tag.wrapping_add(1).max(1);
        tag
    }

    fn begin(&mut self, req: IoReq) -> IoToken {
        if req.len as usize > self.per_bank {
            return IoToken::new(u8::MAX, 0);
        }
        let Some(index) = self.slots.iter().position(Option::is_none) else {
            return IoToken::new(u8::MAX, 0);
        };
        let tag = self.mint_tag();
        let state = if req.dir == Direction::FromHost {
            SlotState::Waiting
        } else {
            SlotState::Pending
        };
        self.slots[index] = Some(Slot {
            req,
            tag,
            state,
            result: None,
            staged: None,
        });
        let token = IoToken::new(index as u8, tag);
        if req.dir != Direction::FromHost {
            self.try_post(index);
        }
        token
    }

    /// Post a `Pending` slot if the plane's buffer is free.
    fn try_post(&mut self, index: usize) {
        let Some(slot) = self.slots[index].as_ref() else {
            return;
        };
        if slot.state != SlotState::Pending {
            return;
        }
        let Some(buf) = self.buf.take() else {
            return;
        };
        let job = Job {
            tag: slot.tag,
            req: slot.req,
            buf,
        };
        match self.tx.send(job) {
            Ok(()) => {
                if let Some(slot) = self.slots[index].as_mut() {
                    slot.state = SlotState::Running;
                }
            }
            // The worker is gone: keep the buffer and fail the token on its
            // next poll instead of panicking.
            Err(err) => {
                self.buf = Some(err.0.buf);
                if let Some(slot) = self.slots[index].as_mut() {
                    slot.state = SlotState::Settled;
                    slot.result = Some(Err(StorageError::Unsupported));
                }
            }
        }
    }

    /// Collect every finished job without blocking.
    fn drain(&mut self) {
        while let Ok(done) = self.rx.try_recv() {
            let Some(index) = self
                .slots
                .iter()
                .position(|slot| slot.as_ref().is_some_and(|s| s.tag == done.tag))
            else {
                self.buf = Some(done.buf);
                continue;
            };
            let slot = self.slots[index].as_mut().unwrap();
            match slot.state {
                SlotState::Running => {
                    slot.state = SlotState::Settled;
                    slot.result = Some(done.result);
                    slot.staged = Some(done.buf);
                }
                SlotState::Cancelled => {
                    // The buffer is never handed to the caller again.
                    self.slots[index] = None;
                    self.buf = Some(done.buf);
                }
                _ => self.buf = Some(done.buf),
            }
        }
    }

    fn find(&self, token: IoToken) -> Option<usize> {
        self.slots.iter().enumerate().find_map(|(index, slot)| {
            slot.as_ref()
                .filter(|s| IoToken::new(index as u8, s.tag) == token)
                .map(|_| index)
        })
    }

    /// Free the slot named by `index` unless the worker still owns its buffer.
    fn release(&mut self, index: usize) {
        if let Some(slot) = self.slots[index].as_mut() {
            match slot.state {
                SlotState::Running => slot.state = SlotState::Cancelled,
                _ => {
                    let slot = self.slots[index].take().unwrap();
                    if let Some(buf) = slot.staged {
                        self.buf = Some(buf);
                    }
                }
            }
        }
    }

    fn poll(&mut self, token: IoToken, buf: IoBuf<'_>) -> Poll<StorageReceipt> {
        self.drain();
        let Some(index) = self.find(token) else {
            return Poll::Ready(contract());
        };
        let req = self.slots[index].as_ref().unwrap().req;
        if !buf_matches(req, &buf) {
            // The token is spent even when the buffer is wrong, like
            // `CliStorage`.
            self.release(index);
            return Poll::Ready(contract());
        }
        match self.slots[index].as_ref().unwrap().state {
            SlotState::Waiting => {
                // `begin` only creates a `Waiting` slot for `FromHost`, and
                // `buf_matches` already rejected a mismatched buffer, so this
                // arm is defensive: spend the token if it is ever reached.
                let IoBuf::Write(data) = buf else {
                    self.release(index);
                    return Poll::Ready(contract());
                };
                if self.buf.is_none() {
                    return Poll::Pending;
                }
                let staged = self.buf.as_mut().unwrap();
                staged[..data.len()].copy_from_slice(data);
                if let Some(slot) = self.slots[index].as_mut() {
                    slot.state = SlotState::Pending;
                }
                self.try_post(index);
                Poll::Pending
            }
            SlotState::Pending => {
                self.try_post(index);
                Poll::Pending
            }
            SlotState::Running => Poll::Pending,
            SlotState::Settled => {
                let slot = self.slots[index].take().unwrap();
                let confirmed = if req.dir == Direction::None {
                    0
                } else {
                    req.len as usize
                };
                let ok = slot.result.as_ref().is_some_and(|r| r.is_ok());
                if let Some(staged) = slot.staged {
                    if ok {
                        if let IoBuf::Read(out) = buf {
                            out.copy_from_slice(&staged[..out.len()]);
                        }
                    }
                    self.buf = Some(staged);
                }
                match slot.result.unwrap() {
                    Ok(()) => Poll::Ready(StorageReceipt::ok(confirmed)),
                    Err(e) => Poll::Ready(StorageReceipt::failed_for(req.dir, e)),
                }
            }
            SlotState::Cancelled => Poll::Ready(contract()),
        }
    }

    /// Register a waker and report whether this plane can make progress.
    ///
    /// The waker is registered *before* the completion check: a `Done` posted
    /// in between is either collected by the drain or wakes the fresh waker.
    /// `Ready` means a job settled (its receipt is waiting in the slot table)
    /// or nothing is running, so the caller must poll its token to advance.
    /// `Done` is never consumed here beyond moving it into the slot table.
    #[cfg_attr(not(feature = "tokio"), allow(dead_code))]
    fn poll_wake(&mut self, cx: &mut Context<'_>) -> Poll<()> {
        self.wake.register(cx.waker());
        self.drain();
        let settled = self
            .slots
            .iter()
            .flatten()
            .any(|slot| slot.state == SlotState::Settled);
        // A write whose data has not been supplied yet cannot make progress on
        // its own; parking here keeps `StoragePending` from spinning.
        let waiting = self
            .slots
            .iter()
            .flatten()
            .any(|slot| slot.state == SlotState::Waiting);
        let running = self
            .slots
            .iter()
            .flatten()
            .any(|slot| slot.state == SlotState::Running);
        if self.wake.take_progress() || settled || (!running && !waiting) {
            Poll::Ready(())
        } else {
            Poll::Pending
        }
    }

    /// Wait for any in-flight job so the staging buffer is back, then run one
    /// `Sync` on the plane.
    fn sync(&mut self) -> Result<(), StorageError> {
        // The transport loop has returned, so every live token is dead.
        // Reclaim the staging buffer from settled slots first; a running job
        // still owns it and is collected below.
        for slot in &mut self.slots {
            if let Some(slot) = slot.take() {
                if let Some(buf) = slot.staged {
                    self.buf = Some(buf);
                }
            }
        }
        while self.buf.is_none() {
            let done = self.rx.recv().map_err(|_| StorageError::Unsupported)?;
            self.buf = Some(done.buf);
        }
        let tag = self.mint_tag();
        let buf = self.buf.take().ok_or(StorageError::Unsupported)?;
        let job = Job {
            tag,
            req: IoReq {
                resource: 0,
                offset: 0,
                len: 0,
                dir: Direction::None,
            },
            buf,
        };
        self.tx.send(job).map_err(|_| StorageError::Unsupported)?;
        let done = self.rx.recv().map_err(|_| StorageError::Unsupported)?;
        self.buf = Some(done.buf);
        done.result
    }
}

fn contract() -> StorageReceipt {
    StorageReceipt::failed(Fault::Contract, 0, Effect::Known)
}

fn buf_matches(req: IoReq, buf: &IoBuf<'_>) -> bool {
    match (req.dir, buf) {
        (Direction::None, IoBuf::None) => req.len == 0,
        (Direction::ToHost, IoBuf::Read(b)) => req.len as usize == b.len(),
        (Direction::FromHost, IoBuf::Write(b)) => req.len as usize == b.len(),
        _ => false,
    }
}

/// Fixed-slot background storage over the per-LUN [`OwnedPlane`]s.
///
/// Each plane runs on its own thread for the lifetime of the
/// [`thread::scope`] that created the store. Dropping the store closes the job
/// channels, so the scope joins every thread.
pub struct WorkerStore {
    planes: Vec<Option<WorkerPlane>>,
    lun: usize,
}

impl WorkerStore {
    /// Start one worker thread per plane and build the slot tables.
    ///
    /// `per_bank` is the data-area size of one bank (`work.len() / 2` in
    /// dual-bank mode), so the staging buffer can hold any single request a
    /// bank emits.
    pub fn new<'scope>(
        scope: &'scope Scope<'scope, '_>,
        planes: Vec<Option<OwnedPlane>>,
        per_bank: usize,
    ) -> Self {
        let mut workers = Vec::with_capacity(planes.len());
        for plane in planes {
            let Some(plane) = plane else {
                workers.push(None);
                continue;
            };
            let bundle = plane.is_cdr_bundle();
            let (job_tx, job_rx) = mpsc::channel();
            let (done_tx, done_rx) = mpsc::channel();
            let wake = Arc::new(WorkerWake::new());
            let worker_wake = Arc::clone(&wake);
            scope.spawn(move || worker_loop(plane, job_rx, done_tx, worker_wake));
            workers.push(Some(WorkerPlane::new(
                job_tx, done_rx, per_bank, bundle, wake,
            )));
        }
        Self {
            planes: workers,
            lun: 0,
        }
    }

    /// Flush every plane after the transport loop returns.
    pub fn sync(&mut self) -> Result<(), (usize, StorageError)> {
        for (i, plane) in self.planes.iter_mut().enumerate() {
            if let Some(plane) = plane {
                plane.sync().map_err(|e| (i, e))?;
            }
        }
        Ok(())
    }
}

/// Worker thread: execute jobs until the store is dropped.
fn worker_loop(
    mut plane: OwnedPlane,
    jobs: Receiver<Job>,
    done: Sender<Done>,
    wake: Arc<WorkerWake>,
) {
    while let Ok(job) = jobs.recv() {
        let mut buf = job.buf;
        let len = job.req.len as usize;
        let result = match job.req.dir {
            Direction::ToHost => plane.exec(job.req, IoBuf::Read(&mut buf[..len])),
            Direction::FromHost => plane.exec(job.req, IoBuf::Write(&mut buf[..len])),
            Direction::None => plane.exec(job.req, IoBuf::None),
        }
        .map(|_| ());
        if done
            .send(Done {
                tag: job.tag,
                result,
                buf,
            })
            .is_err()
        {
            return;
        }
        wake.notify();
    }
}

impl Storage for WorkerStore {
    fn select_lun(&mut self, lun: usize) {
        self.lun = lun;
    }

    fn resources_released(&mut self, lun: usize) {
        // Dropping the WorkerPlane closes its channels; the worker finishes any
        // in-flight job, sees the closed result channel and drops the plane
        // (closing its cached handles). A bundle cannot be re-addressed after
        // a host eject, so the eject path rendered the last TOC best effort
        // before this point.
        let is_bundle = self
            .planes
            .get(lun)
            .and_then(Option::as_ref)
            .is_some_and(|plane| plane.bundle);
        if is_bundle {
            log::info!("LUN {lun}: recordable-CD bundle plane released after the eject");
            self.planes[lun] = None;
        }
    }

    fn begin_exec(&mut self, req: IoReq) -> IoToken {
        match self.planes.get_mut(self.lun).and_then(Option::as_mut) {
            Some(plane) => plane.begin(req),
            None => IoToken::new(u8::MAX, 0),
        }
    }

    fn poll_exec(&mut self, token: IoToken, buf: IoBuf<'_>) -> Poll<StorageReceipt> {
        match self.planes.get_mut(self.lun).and_then(Option::as_mut) {
            Some(plane) => plane.poll(token, buf),
            None => Poll::Ready(contract()),
        }
    }

    fn cancel(&mut self, token: IoToken) {
        if let Some(plane) = self.planes.get_mut(self.lun).and_then(Option::as_mut) {
            if let Some(index) = plane.find(token) {
                plane.release(index);
            }
        }
    }
}

/// The async shell waits on the plane the runner selected last; a LUN without
/// a plane has nothing left to wait for.
#[cfg(feature = "tokio")]
impl snowscsi::core::async_wake::AsyncWake for WorkerStore {
    fn poll_wake(&mut self, cx: &mut Context<'_>) -> Poll<()> {
        match self.planes.get_mut(self.lun).and_then(Option::as_mut) {
            Some(plane) => plane.poll_wake(cx),
            None => Poll::Ready(()),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::{Duration, Instant};

    fn invalid() -> IoToken {
        IoToken::new(u8::MAX, 0)
    }

    fn read_req(offset: u64, len: u32) -> IoReq {
        IoReq {
            resource: 0,
            offset,
            len,
            dir: Direction::ToHost,
        }
    }

    fn write_req(offset: u64, len: u32) -> IoReq {
        IoReq {
            resource: 0,
            offset,
            len,
            dir: Direction::FromHost,
        }
    }

    fn poll_read(store: &mut WorkerStore, token: IoToken, out: &mut [u8]) -> StorageReceipt {
        let deadline = Instant::now() + Duration::from_secs(5);
        loop {
            if let Poll::Ready(r) = store.poll_exec(token, IoBuf::Read(&mut *out)) {
                return r;
            }
            assert!(Instant::now() < deadline, "read did not settle");
            std::thread::sleep(Duration::from_millis(1));
        }
    }

    fn poll_write(store: &mut WorkerStore, token: IoToken, data: &mut [u8]) -> StorageReceipt {
        let deadline = Instant::now() + Duration::from_secs(5);
        loop {
            if let Poll::Ready(r) = store.poll_exec(token, IoBuf::Write(data)) {
                return r;
            }
            assert!(Instant::now() < deadline, "write did not settle");
            std::thread::sleep(Duration::from_millis(1));
        }
    }

    fn expect_contract(store: &mut WorkerStore, token: IoToken) {
        let mut scratch = [0u8; 8];
        match store.poll_exec(token, IoBuf::Read(&mut scratch)) {
            Poll::Ready(r) => assert_eq!(r.error, Some(Fault::Contract)),
            Poll::Pending => panic!("a dead token must settle immediately"),
        }
    }

    #[test]
    fn read_completes_and_write_stages_its_data() {
        let mut ram = vec![0u8; 4096];
        ram[..4].copy_from_slice(b"disk");
        std::thread::scope(|scope| {
            let plane = OwnedPlane::Ram {
                bytes: ram,
                writable: true,
            };
            let mut store = WorkerStore::new(scope, vec![Some(plane)], 1024);

            // `begin_exec` posts the read; a later poll reports completion.
            let token = store.begin_exec(read_req(0, 4));
            assert_ne!(token, invalid());
            let mut out = [0u8; 4];
            assert_eq!(
                poll_read(&mut store, token, &mut out),
                StorageReceipt::ok(4)
            );
            assert_eq!(&out, b"disk");

            // A write has no bytes at `begin_exec`: the first poll stages them
            // and returns Pending, a later poll completes.
            let token = store.begin_exec(write_req(8, 4));
            assert_ne!(token, invalid());
            let mut data = *b"data";
            assert!(matches!(
                store.poll_exec(token, IoBuf::Write(&mut data)),
                Poll::Pending
            ));
            assert_eq!(
                poll_write(&mut store, token, &mut data),
                StorageReceipt::ok(4)
            );

            let token = store.begin_exec(read_req(8, 4));
            let mut back = [0u8; 4];
            assert_eq!(
                poll_read(&mut store, token, &mut back),
                StorageReceipt::ok(4)
            );
            assert_eq!(&back, b"data");

            assert!(store.sync().is_ok());
        });
    }

    #[test]
    fn cancel_is_idempotent_before_and_after_completion() {
        let ram = vec![0x5Au8; 1024];
        std::thread::scope(|scope| {
            let plane = OwnedPlane::Ram {
                bytes: ram,
                writable: true,
            };
            let mut store = WorkerStore::new(scope, vec![Some(plane)], 512);

            // Cancel while the worker is still running: the token is dead, and
            // repeating the cancel does nothing.
            let token = store.begin_exec(read_req(0, 8));
            store.cancel(token);
            store.cancel(token);
            expect_contract(&mut store, token);

            // The plane is still usable afterwards.
            let token = store.begin_exec(read_req(0, 4));
            let mut out = [0u8; 4];
            assert_eq!(
                poll_read(&mut store, token, &mut out),
                StorageReceipt::ok(4)
            );

            // Cancel after completion is a no-op, and the token stays dead.
            store.cancel(token);
            store.cancel(token);
            expect_contract(&mut store, token);

            assert!(store.sync().is_ok());
        });
    }

    #[test]
    fn unknown_token_is_a_contract_violation() {
        let ram = vec![0u8; 1024];
        std::thread::scope(|scope| {
            let plane = OwnedPlane::Ram {
                bytes: ram,
                writable: false,
            };
            let mut store = WorkerStore::new(scope, vec![Some(plane)], 512);
            expect_contract(&mut store, IoToken::new(9, 123));
            expect_contract(&mut store, invalid());
        });
    }

    #[test]
    fn a_settled_read_keeps_its_buffer_until_it_is_polled() {
        let ram = vec![0u8; 1024];
        std::thread::scope(|scope| {
            let plane = OwnedPlane::Ram {
                bytes: ram,
                writable: true,
            };
            let mut store = WorkerStore::new(scope, vec![Some(plane)], 512);

            // A takes the plane's only staging buffer; B cannot start until A
            // has been polled, even if A's job has already finished.
            let a = store.begin_exec(read_req(0, 4));
            let b = store.begin_exec(read_req(4, 4));
            let mut out = [0u8; 4];
            assert!(matches!(
                store.poll_exec(b, IoBuf::Read(&mut out)),
                Poll::Pending
            ));
            assert!(matches!(
                store.poll_exec(b, IoBuf::Read(&mut out)),
                Poll::Pending
            ));

            let mut a_out = [0u8; 4];
            assert_eq!(poll_read(&mut store, a, &mut a_out), StorageReceipt::ok(4));
            let mut b_out = [0u8; 4];
            assert_eq!(poll_read(&mut store, b, &mut b_out), StorageReceipt::ok(4));

            assert!(store.sync().is_ok());
        });
    }

    /// Waker that records that it was woken.
    #[cfg(feature = "tokio")]
    struct FlagWake(Arc<AtomicBool>);

    #[cfg(feature = "tokio")]
    impl std::task::Wake for FlagWake {
        fn wake(self: Arc<Self>) {
            self.0.store(true, Ordering::SeqCst);
        }

        fn wake_by_ref(self: &Arc<Self>) {
            self.0.store(true, Ordering::SeqCst);
        }
    }

    /// Poll `future` with `cx` until it completes. No runtime and no `unsafe`.
    #[cfg(feature = "tokio")]
    fn block_on<F: core::future::Future>(future: F, cx: &mut Context<'_>) -> F::Output {
        let mut future = std::pin::pin!(future);
        loop {
            if let Poll::Ready(out) = future.as_mut().poll(cx) {
                return out;
            }
            std::thread::yield_now();
        }
    }

    #[cfg(feature = "tokio")]
    #[test]
    fn poll_wake_wakes_the_registered_task_and_reports_a_settled_read() {
        use snowscsi::core::async_wake::{wait, AsyncWake};
        use std::task::Waker;

        let mut ram = vec![0u8; 4096];
        ram[..4].copy_from_slice(b"disk");
        std::thread::scope(|scope| {
            let plane = OwnedPlane::Ram {
                bytes: ram,
                writable: true,
            };
            let mut store = WorkerStore::new(scope, vec![Some(plane)], 1024);

            let woken = Arc::new(AtomicBool::new(false));
            let waker = Waker::from(Arc::new(FlagWake(Arc::clone(&woken))));
            let mut cx = Context::from_waker(&waker);

            // Park a waker before the job exists: an immediate RAM read must
            // still be observed through `wake`, not only through the drain.
            assert!(
                store.poll_wake(&mut cx).is_ready(),
                "no job is running, so the plane must report progress"
            );

            let token = store.begin_exec(read_req(0, 4));
            assert_ne!(token, invalid());

            // Await the adapter exactly as the async shell does.
            block_on(wait(&mut store), &mut cx);
            // `wait` may return because the drain already saw `Done`, a moment
            // before the worker reaches `notify`. Give that wake a bounded wait
            // instead of assuming the two are ordered.
            let deadline = Instant::now() + Duration::from_secs(5);
            while !woken.load(Ordering::SeqCst) && Instant::now() < deadline {
                std::thread::yield_now();
            }
            assert!(
                woken.load(Ordering::SeqCst),
                "the worker must wake the registered waker after posting Done"
            );

            let mut out = [0u8; 4];
            assert_eq!(
                poll_read(&mut store, token, &mut out),
                StorageReceipt::ok(4)
            );
            assert_eq!(&out, b"disk");

            assert!(store.sync().is_ok());
        });
    }

    #[test]
    fn a_full_slot_table_mints_an_invalid_token() {
        let ram = vec![0u8; 1024];
        std::thread::scope(|scope| {
            let plane = OwnedPlane::Ram {
                bytes: ram,
                writable: true,
            };
            let mut store = WorkerStore::new(scope, vec![Some(plane)], 512);

            // Writes wait in the table, so all four slots can be occupied
            // without the single staging buffer ever being touched.
            let tokens: Vec<_> = (0..SLOTS)
                .map(|_| {
                    let token = store.begin_exec(write_req(0, 4));
                    assert_ne!(token, invalid());
                    token
                })
                .collect();
            assert_eq!(store.begin_exec(write_req(0, 4)), invalid());

            for token in tokens {
                store.cancel(token);
            }

            // Reads occupy a slot as well, even though only one can hold the
            // staging buffer at a time.
            let tokens: Vec<_> = (0..SLOTS)
                .map(|_| {
                    let token = store.begin_exec(read_req(0, 4));
                    assert_ne!(token, invalid());
                    token
                })
                .collect();
            assert_eq!(store.begin_exec(read_req(0, 4)), invalid());
            for token in tokens {
                store.cancel(token);
            }
        });
    }

    #[cfg(feature = "cdr-bundle")]
    fn bundle_plane(tag: &str) -> (std::path::PathBuf, OwnedPlane) {
        use crate::stack::BundleStore;
        use snowscsi::common::fs_plane::FsPlaneAdapter;
        use snowscsi::scsi::fs_backend::StdFsBackend;

        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or(0);
        let dir = std::env::temp_dir().join(format!(
            "snowscsi_worker_{tag}_{}_{}",
            std::process::id(),
            nanos
        ));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let fs = FsPlaneAdapter::new(StdFsBackend::new(&dir.to_string_lossy()));
        let plane = OwnedPlane::CdrBundle(BundleStore::new(fs, 359_849, None));
        (dir, plane)
    }

    #[cfg(feature = "cdr-bundle")]
    #[test]
    fn bundle_resources_route_through_the_worker() {
        let (dir, plane) = bundle_plane("route");
        std::thread::scope(|scope| {
            let mut store = WorkerStore::new(scope, vec![Some(plane)], 8192);

            let token = store.begin_exec(IoReq {
                resource: 17,
                offset: 0,
                len: 4,
                dir: Direction::FromHost,
            });
            let mut data = *b"data";
            assert_eq!(
                poll_write(&mut store, token, &mut data),
                StorageReceipt::ok(4)
            );

            let token = store.begin_exec(IoReq {
                resource: 17,
                offset: 0,
                len: 4,
                dir: Direction::ToHost,
            });
            let mut out = [0u8; 4];
            assert_eq!(
                poll_read(&mut store, token, &mut out),
                StorageReceipt::ok(4)
            );
            assert_eq!(&out, b"data");

            assert!(store.sync().is_ok());
        });
        assert!(dir.join("track_1.bin").is_file());
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[cfg(feature = "cdr-bundle")]
    #[test]
    fn resources_released_drops_a_bundle_plane() {
        let (dir, plane) = bundle_plane("drop");
        std::thread::scope(|scope| {
            let mut store = WorkerStore::new(scope, vec![Some(plane)], 8192);
            store.resources_released(0);
            assert_eq!(store.begin_exec(read_req(0, 1)), invalid());
            assert!(store.sync().is_ok());
        });
        let _ = std::fs::remove_dir_all(&dir);
    }
}
