//! Runtime-free slot adapter for asynchronous storage backends.
//!
//! [`Storage`] is a poll seam: `begin_exec` sees metadata only and `poll_exec`
//! re-borrows the caller's buffer, which means a `&mut [u8]` can never outlive
//! the call that handed it over. Any adapter whose I/O completes somewhere
//! else (an interrupt, a driver future, a worker) therefore has to own a
//! buffer of its own. [`SlotPool`] is that adapter: a fixed slot table, one
//! staging buffer, and two wakers, with no allocator, no runtime and no
//! `unsafe`.
//!
//! ```no_run
//! # use snowscsi::core::slots::SlotPool;
//! # async fn example(card: &mut MyCard) {
//! let pool = SlotPool::new([0u8; 8192]);
//! let (mut store, task) = pool.split();
//! // Both futures run in the same task (for example `join!`):
//! //   serve_async(.., &mut store, ..)     — the wire side
//! //   the loop below                      — the backend side
//! loop {
//!     let mut job = task.next_job().await;
//!     let result = match job.req().dir {
//!         snowscsi::core::Direction::ToHost => card.read(job.req().offset, job.data()).await,
//!         _ => card.write(job.req().offset, job.data()).await,
//!     };
//!     task.complete(job, result);
//! }
//! # }
//! # struct MyCard;
//! # impl MyCard {
//! #     async fn read(&mut self, _off: u64, _buf: &mut [u8]) -> Result<usize, snowscsi::common::seekable_storage::StorageError> { Ok(0) }
//! #     async fn write(&mut self, _off: u64, _buf: &mut [u8]) -> Result<usize, snowscsi::common::seekable_storage::StorageError> { Ok(0) }
//! # }
//! ```
//!
//! # Why one buffer and four slots
//!
//! Only one operation can own the staging buffer at a time, so the task queue
//! never holds more than one job: a posted job leaves the pool's buffer empty
//! and the next `begin_exec` parks until the buffer comes back. Four slots keep
//! short operations from starving while a long one is committed.
//!
//! # Constraints
//!
//! - **Same-task.** [`SlotPool`] holds a [`RefCell`], so [`SlotStore`] is
//!   neither `Send` nor `Sync`. The store and its [`SlotTask`] must run in the
//!   same future (the usual `join!` on one executor). A `Send` store for
//!   spawning needs a different synchronisation primitive, which is a
//!   runtime-specific choice the library does not make.
//! - **One store and one task per pool.** Each side registers a single waker,
//!   so two shells sharing a pool would overwrite each other's wake-up. A
//!   second connection is a second pool.
//! - **The buffer bounds one request.** A request longer than the staging
//!   buffer is rejected with [`IoToken::invalid`](super::storage::IoToken),
//!   which the runner reports exactly like an exhausted slot pool (a contract
//!   fault, not a partial transfer). Size the buffer for the largest window
//!   the runner may hand out — normally one command/data bank.
//! - **Dropping the job abandons the operation.** [`Job`] returns the buffer
//!   and frees its slot when dropped, so a cancelled shell (a task future
//!   dropped mid-transfer) cannot strand the pool. The late receipt is never
//!   observed, which is exactly what `cancel` means. [`SlotPool::reset`]
//!   clears anything a dropped future left behind before the pool is reused.
//! - **One copy.** `begin_exec` carries no buffer, so a write is staged into
//!   the adapter buffer and a read is copied back out of it. Removing that
//!   copy needs an owned-slot seam, not a different adapter.
//! - **No borrowing across `await`.** Every [`RefCell`] borrow lives inside one
//!   synchronous method; wakers are collected and fired after the borrow is
//!   dropped.

use ::core::cell::{Cell, RefCell};
use ::core::future::poll_fn;
use ::core::task::{Context, Poll, Waker};

use crate::common::seekable_storage::StorageError;

use super::async_wake::AsyncWake;
use super::device::Direction;
use super::storage::{
    buf_matches, contract_receipt, IoBuf, IoReq, IoToken, Storage, StorageReceipt,
};

/// Fixed slot count, matching the library's synchronous adapters.
const SLOTS: usize = 4;

/// Lifecycle of one slot.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum SlotState {
    /// `FromHost` request whose data has not been supplied yet.
    Waiting,
    /// Ready to post, waiting for the staging buffer.
    Pending,
    /// Handed to the task.
    Running,
    /// Finished; the receipt is reported on the next poll.
    Settled,
    /// Cancelled while running; the slot frees when the result comes back.
    Cancelled,
}

struct Slot<B> {
    req: IoReq,
    tag: u32,
    /// LUN selected when the operation began.
    lun: usize,
    state: SlotState,
    result: Option<Result<usize, StorageError>>,
    /// Staging buffer of a settled read. It stays reserved here until the token
    /// is polled, so a later job can never overwrite bytes the caller has not
    /// copied out yet.
    staged: Option<B>,
}

/// Posted job the task has not taken yet.
///
/// Plain data on purpose: [`Inner`] must never own a [`Job`], whose `Drop`
/// borrows the pool back.
struct Pending<B> {
    tag: u32,
    req: IoReq,
    lun: usize,
    buf: B,
}

/// Wakers to fire once the caller released its [`RefCell`] borrow.
#[derive(Default)]
struct Wake {
    task: Option<Waker>,
    shell: Option<Waker>,
}

impl Wake {
    fn fire(self) {
        if let Some(waker) = self.task {
            waker.wake();
        }
        if let Some(waker) = self.shell {
            waker.wake();
        }
    }
}

/// One unit of work handed to a [`SlotTask`].
///
/// The job owns the staging buffer until [`SlotTask::complete`] or a drop
/// returns it, so the backend can await an asynchronous read/write without
/// borrowing anything the core knows about.
pub struct Job<'p, B> {
    pool: &'p SlotPool<B>,
    tag: u32,
    req: IoReq,
    lun: usize,
    /// `None` once the job was completed (or abandoned).
    buf: Option<B>,
}

impl<B: AsMut<[u8]>> Job<'_, B> {
    /// The request this job executes.
    pub fn req(&self) -> IoReq {
        self.req
    }

    /// The LUN that was selected when the operation began.
    ///
    /// An adapter serving several LUNs from one pool routes on this instead of
    /// re-implementing `select_lun` bookkeeping.
    pub fn lun(&self) -> usize {
        self.lun
    }

    /// Requested length in bytes.
    pub fn len(&self) -> usize {
        self.req.len as usize
    }

    /// Whether the request transfers no data (a sync).
    pub fn is_empty(&self) -> bool {
        self.req.len == 0
    }

    /// The staging bytes of this job (`len()` long).
    pub fn data(&mut self) -> &mut [u8] {
        let len = self.req.len as usize;
        let buf = self.buf.as_mut().expect("job already completed");
        &mut buf.as_mut()[..len]
    }
}

impl<B> Drop for Job<'_, B> {
    fn drop(&mut self) {
        if let Some(buf) = self.buf.take() {
            // The task future was dropped mid-operation: abandon the request
            // rather than stranding the only staging buffer.
            self.pool.abandon(self.tag, buf);
        }
    }
}

/// Runtime-free asynchronous storage adapter.
///
/// Build one over a staging buffer, then [`SlotPool::split`] it into the
/// [`Storage`] side and the task side. The pool must live for as long as both
/// sides; on a target without an allocator, place it in a `static` (for
/// example an `embassy_sync::StaticCell`).
///
/// ```no_run
/// # use snowscsi::core::slots::SlotPool;
/// let pool = SlotPool::new([0u8; 8192]);
/// let (store, task) = pool.split();
/// ```
pub struct SlotPool<B> {
    inner: RefCell<Inner<B>>,
}

impl<B: AsMut<[u8]>> SlotPool<B> {
    /// Build a pool over `buf`, the only staging buffer.
    ///
    /// `buf.len()` is the largest request the pool accepts; give it a whole
    /// command/data bank so no runner window is ever rejected.
    pub fn new(buf: B) -> Self {
        Self {
            inner: RefCell::new(Inner::new(buf)),
        }
    }

    /// Split the pool into the [`Storage`] side and the task side.
    ///
    /// Both sides share the pool, so they must run in one future (the usual
    /// `join!` on a single executor). Split once: each side keeps a single
    /// waker, so a second store or task would overwrite it.
    pub fn split(&self) -> (SlotStore<'_, B>, SlotTask<'_, B>) {
        (SlotStore { pool: self }, SlotTask { pool: self })
    }

    /// Drop every operation the pool still tracks and take the staging buffer
    /// back.
    ///
    /// Call this before reusing a pool whose shell (or task) future was
    /// dropped: a settled read may still hold the buffer for a receipt that
    /// will never be polled. Nothing may be parked in either side when this
    /// runs; both wakers are forgotten.
    pub fn reset(&self) {
        let mut inner = self.inner.borrow_mut();
        inner.reset();
    }
}

impl<B> SlotPool<B> {
    /// Reclaim a job the task dropped without completing.
    fn abandon(&self, tag: u32, buf: B) {
        let mut wake = Wake::default();
        {
            let mut inner = self.inner.borrow_mut();
            inner.abandon(tag, buf, &mut wake);
        }
        wake.fire();
    }
}

/// Slot table, staging buffer and wakers (shared by both sides).
struct Inner<B> {
    slots: [Option<Slot<B>>; SLOTS],
    /// The single staging buffer; `None` while a job or a settled read owns it.
    buf: Option<B>,
    pending: Option<Pending<B>>,
    /// Waker of the shell waiting in [`AsyncWake::poll_wake`].
    shell: Cell<Option<Waker>>,
    /// Waker of the task waiting in [`SlotTask::next_job`].
    task: Cell<Option<Waker>>,
    /// Longest request this pool accepts (`buf.len()`).
    capacity: usize,
    /// LUN selected by the last `Storage::select_lun`.
    lun: usize,
    next_tag: u32,
}

impl<B: AsMut<[u8]>> Inner<B> {
    /// Build the shared state over `buf`, the only staging buffer.
    fn new(buf: B) -> Self {
        let mut buf = buf;
        let capacity = buf.as_mut().len();
        Self {
            slots: [const { None }; SLOTS],
            buf: Some(buf),
            pending: None,
            shell: Cell::new(None),
            task: Cell::new(None),
            capacity,
            lun: 0,
            next_tag: 1,
        }
    }

    fn mint_tag(&mut self) -> u32 {
        let tag = self.next_tag;
        self.next_tag = self.next_tag.wrapping_add(1).max(1);
        tag
    }

    fn begin(&mut self, req: IoReq, wake: &mut Wake) -> IoToken {
        let lun = self.lun;
        if req.len as usize > self.capacity {
            return IoToken::invalid();
        }
        let Some(index) = self.slots.iter().position(Option::is_none) else {
            return IoToken::invalid();
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
            lun,
            state,
            result: None,
            staged: None,
        });
        if state == SlotState::Pending {
            self.try_post(index, wake);
        }
        IoToken::new(index as u8, tag)
    }

    fn find(&self, token: IoToken) -> Option<usize> {
        self.slots.iter().enumerate().find_map(|(index, slot)| {
            slot.as_ref()
                .filter(|s| IoToken::new(index as u8, s.tag) == token)
                .map(|_| index)
        })
    }

    /// Free the slot named by `index`, unless the task still owns its buffer.
    fn release(&mut self, index: usize, wake: &mut Wake) {
        let state = match self.slots[index].as_ref() {
            Some(slot) => slot.state,
            None => return,
        };
        if state == SlotState::Running {
            // The buffer is on the task; the result recycles it.
            if let Some(slot) = self.slots[index].as_mut() {
                slot.state = SlotState::Cancelled;
            }
            return;
        }
        if let Some(slot) = self.slots[index].take() {
            if let Some(staged) = slot.staged {
                self.buf = Some(staged);
                self.post_next(wake);
            }
        }
    }

    fn poll(&mut self, token: IoToken, buf: IoBuf<'_>, wake: &mut Wake) -> Poll<StorageReceipt> {
        let Some(index) = self.find(token) else {
            return Poll::Ready(contract_receipt());
        };
        let req = self.slots[index].as_ref().unwrap().req;
        if !buf_matches(req, &buf) {
            // The token is spent even when the buffer is wrong.
            self.release(index, wake);
            return Poll::Ready(contract_receipt());
        }
        let state = self.slots[index].as_ref().unwrap().state;
        match state {
            SlotState::Waiting => {
                // Only a `FromHost` slot starts in `Waiting`, and `buf_matches`
                // already checked the variant.
                let IoBuf::Write(data) = buf else {
                    self.release(index, wake);
                    return Poll::Ready(contract_receipt());
                };
                let Some(stage) = self.buf.as_mut() else {
                    // The staging buffer is still owned by the task (or by a
                    // settled read); the shell polls again once it returns.
                    return Poll::Pending;
                };
                stage.as_mut()[..data.len()].copy_from_slice(data);
                if let Some(slot) = self.slots[index].as_mut() {
                    slot.state = SlotState::Pending;
                }
                self.try_post(index, wake);
                Poll::Pending
            }
            SlotState::Pending => {
                self.try_post(index, wake);
                Poll::Pending
            }
            SlotState::Running => Poll::Pending,
            SlotState::Settled => {
                let slot = self.slots[index].take().unwrap();
                let ok = slot.result.as_ref().is_some_and(|r| r.is_ok());
                if let Some(mut staged) = slot.staged {
                    if ok {
                        if let IoBuf::Read(out) = buf {
                            out.copy_from_slice(&staged.as_mut()[..out.len()]);
                        }
                    }
                    self.buf = Some(staged);
                    self.post_next(wake);
                }
                match slot.result.unwrap_or(Ok(0)) {
                    Ok(n) => Poll::Ready(StorageReceipt::ok(n)),
                    Err(e) => Poll::Ready(StorageReceipt::failed_for(req.dir, e)),
                }
            }
            SlotState::Cancelled => Poll::Ready(contract_receipt()),
        }
    }

    fn poll_wake(&mut self, cx: &mut Context<'_>) -> Poll<()> {
        self.shell.set(Some(cx.waker().clone()));
        let settled = self
            .slots
            .iter()
            .flatten()
            .any(|slot| slot.state == SlotState::Settled);
        // `Ready` means "poll your token now". A settled receipt blocks on the
        // shell; everything else needs the staging buffer, so a pool that does
        // not have it must park and let the task run. Parking is safe: the only
        // way the buffer comes back is a `complete` or an abandoned job, and
        // both wake the shell.
        if settled || (self.buf.is_some() && !self.active()) {
            Poll::Ready(())
        } else {
            Poll::Pending
        }
    }

    /// Whether some slot will make progress without the shell polling it.
    fn active(&self) -> bool {
        self.slots
            .iter()
            .flatten()
            .any(|slot| matches!(slot.state, SlotState::Running | SlotState::Pending))
    }
}

impl<B> Inner<B> {
    /// Post a `Pending` slot when the staging buffer is free.
    fn try_post(&mut self, index: usize, wake: &mut Wake) {
        let Some(slot) = self.slots[index].as_ref() else {
            return;
        };
        if slot.state != SlotState::Pending {
            return;
        }
        let Some(buf) = self.buf.take() else {
            return;
        };
        let pending = Pending {
            tag: slot.tag,
            req: slot.req,
            lun: slot.lun,
            buf,
        };
        if let Some(slot) = self.slots[index].as_mut() {
            slot.state = SlotState::Running;
        }
        self.pending = Some(pending);
        wake.task = self.task.take();
    }

    /// Post the oldest parked slot, if the buffer is free again.
    fn post_next(&mut self, wake: &mut Wake) {
        for index in 0..SLOTS {
            let pending = self.slots[index]
                .as_ref()
                .is_some_and(|slot| slot.state == SlotState::Pending);
            if pending {
                self.try_post(index, wake);
                return;
            }
        }
    }

    /// Report a finished job back into its slot.
    fn complete(
        &mut self,
        tag: u32,
        req: IoReq,
        buf: Option<B>,
        result: Result<usize, StorageError>,
        wake: &mut Wake,
    ) {
        let mut buf = buf;
        match self
            .slots
            .iter()
            .position(|slot| slot.as_ref().is_some_and(|s| s.tag == tag))
        {
            Some(index) if self.slots[index].as_ref().unwrap().state == SlotState::Running => {
                if req.dir == Direction::ToHost {
                    let slot = self.slots[index].as_mut().unwrap();
                    slot.state = SlotState::Settled;
                    slot.result = Some(result);
                    slot.staged = buf.take();
                } else {
                    // A write or sync already reached the medium: release the
                    // buffer now so the next job can start.
                    if let Some(slot) = self.slots[index].as_mut() {
                        slot.state = SlotState::Settled;
                        slot.result = Some(result);
                    }
                    self.buf = buf.take();
                    self.post_next(wake);
                }
            }
            Some(index) => {
                // The operation was cancelled: drop the slot, recycle the
                // buffer, and let a parked slot post.
                self.slots[index] = None;
                self.buf = buf.take();
                self.post_next(wake);
            }
            None => {
                self.buf = buf.take();
                self.post_next(wake);
            }
        }
        // A shell parked while the buffer was gone must be reconsidered in
        // every case above, including the cancelled and unknown-token ones.
        wake.shell = self.shell.take();
    }

    /// Reclaim the buffer of a job the task dropped without completing.
    ///
    /// Needs no buffer access, so it is callable from [`Job`]'s `Drop`, which
    /// cannot require `B: AsMut<[u8]>`.
    fn abandon(&mut self, tag: u32, buf: B, wake: &mut Wake) {
        if let Some(index) = self
            .slots
            .iter()
            .position(|slot| slot.as_ref().is_some_and(|s| s.tag == tag))
        {
            self.slots[index] = None;
        }
        self.buf = Some(buf);
        self.post_next(wake);
        wake.shell = self.shell.take();
    }

    fn reset(&mut self) {
        for index in 0..SLOTS {
            if let Some(slot) = self.slots[index].take() {
                if let Some(staged) = slot.staged {
                    self.buf = Some(staged);
                }
            }
        }
        if let Some(pending) = self.pending.take() {
            self.buf = Some(pending.buf);
        }
        self.shell.set(None);
        self.task.set(None);
    }
}

/// [`Storage`] side of a [`SlotPool`].
///
/// Hands every operation to the matching [`SlotTask`] and reports its receipt
/// back. Not `Send`/`Sync`: the pool is a [`RefCell`].
pub struct SlotStore<'a, B> {
    pool: &'a SlotPool<B>,
}

impl<B: AsMut<[u8]>> Storage for SlotStore<'_, B> {
    fn select_lun(&mut self, lun: usize) {
        self.pool.inner.borrow_mut().lun = lun;
    }

    fn begin_exec(&mut self, req: IoReq) -> IoToken {
        let mut wake = Wake::default();
        let token = {
            let mut inner = self.pool.inner.borrow_mut();
            inner.begin(req, &mut wake)
        };
        wake.fire();
        token
    }

    fn poll_exec(&mut self, token: IoToken, buf: IoBuf<'_>) -> Poll<StorageReceipt> {
        let mut wake = Wake::default();
        let polled = {
            let mut inner = self.pool.inner.borrow_mut();
            inner.poll(token, buf, &mut wake)
        };
        wake.fire();
        polled
    }

    fn cancel(&mut self, token: IoToken) {
        let mut wake = Wake::default();
        {
            let mut inner = self.pool.inner.borrow_mut();
            if let Some(index) = inner.find(token) {
                inner.release(index, &mut wake);
            }
        }
        wake.fire();
    }
}

impl<B: AsMut<[u8]>> AsyncWake for SlotStore<'_, B> {
    fn poll_wake(&mut self, cx: &mut Context<'_>) -> Poll<()> {
        self.pool.inner.borrow_mut().poll_wake(cx)
    }
}

/// Task side of a [`SlotPool`].
///
/// `next_job` waits for the next posted request; `complete` reports the result
/// (and returns the staging buffer). Both take `&self`: all state lives in the
/// shared pool.
pub struct SlotTask<'a, B> {
    pool: &'a SlotPool<B>,
}

impl<B: AsMut<[u8]>> SlotTask<'_, B> {
    /// Wait for the next job.
    ///
    /// Registers the task waker before checking, so a job posted in between is
    /// either taken here or wakes the fresh waker. Dropping the returned
    /// [`Job`] abandons the operation and returns the buffer.
    pub async fn next_job(&self) -> Job<'_, B> {
        let (tag, req, lun, buf) = poll_fn(|cx| {
            let mut inner = self.pool.inner.borrow_mut();
            inner.task.set(Some(cx.waker().clone()));
            match inner.pending.take() {
                Some(pending) => Poll::Ready((pending.tag, pending.req, pending.lun, pending.buf)),
                None => Poll::Pending,
            }
        })
        .await;
        Job {
            pool: self.pool,
            tag,
            req,
            lun,
            buf: Some(buf),
        }
    }

    /// Report a finished job.
    ///
    /// `result` is the confirmed byte count, or the backend error.
    pub fn complete(&self, mut job: Job<'_, B>, result: Result<usize, StorageError>) {
        debug_assert!(
            ::core::ptr::eq(job.pool, self.pool),
            "job completed by the task of a different pool"
        );
        let Some(buf) = job.buf.take() else {
            return;
        };
        let mut wake = Wake::default();
        {
            let mut inner = self.pool.inner.borrow_mut();
            inner.complete(job.tag, job.req, Some(buf), result, &mut wake);
        }
        wake.fire();
    }

    /// Report a failed job.
    pub fn fail(&self, job: Job<'_, B>, error: StorageError) {
        self.complete(job, Err(error));
    }
}

#[cfg(test)]
mod tests {
    use super::{Job, SlotPool};
    use crate::common::seekable_storage::StorageError;
    use crate::core::async_wake::AsyncWake;
    use crate::core::device::Direction;
    use crate::core::errors::{Effect, Fault};
    use crate::core::storage::{IoBuf, IoReq, Storage};
    use ::core::future::Future;
    use ::core::pin::pin;
    use ::core::task::{Context, Poll, Waker};

    const CAP: usize = 64;

    fn req(dir: Direction, offset: u64, len: u32) -> IoReq {
        IoReq {
            resource: 0,
            offset,
            len,
            dir,
        }
    }

    /// Poll `task.next_job()` once; `None` means the task is parked.
    fn poll_job<'a, B: AsMut<[u8]>>(
        task: &'a super::SlotTask<'_, B>,
        cx: &mut Context<'_>,
    ) -> Option<Job<'a, B>> {
        let mut fut = pin!(task.next_job());
        match fut.as_mut().poll(cx) {
            Poll::Ready(job) => Some(job),
            Poll::Pending => None,
        }
    }

    fn expect_job<'a, B: AsMut<[u8]>>(
        task: &'a super::SlotTask<'_, B>,
        cx: &mut Context<'_>,
    ) -> Job<'a, B> {
        poll_job(task, cx).expect("a job must be posted")
    }

    #[test]
    fn read_is_staged_then_copied_out() {
        let pool = SlotPool::new([0u8; CAP]);
        let (mut store, task) = pool.split();
        let mut cx = Context::from_waker(Waker::noop());

        let token = store.begin_exec(req(Direction::ToHost, 0, 8));
        assert!(token.is_valid());

        // A read posts immediately: the task can take it.
        let mut job = expect_job(&task, &mut cx);
        job.data().copy_from_slice(b"ABCDEFGH");
        task.complete(job, Ok(8));

        let mut out = [0u8; 8];
        match store.poll_exec(token, IoBuf::Read(&mut out)) {
            Poll::Ready(receipt) => {
                assert_eq!(receipt.error, None);
                assert_eq!(receipt.confirmed, 8);
            }
            Poll::Pending => panic!("the receipt must be ready"),
        }
        assert_eq!(&out, b"ABCDEFGH");
    }

    #[test]
    fn write_stages_the_caller_buffer() {
        let pool = SlotPool::new([0u8; CAP]);
        let (mut store, task) = pool.split();
        let mut cx = Context::from_waker(Waker::noop());

        // A write starts parked until the caller supplies the data.
        let token = store.begin_exec(req(Direction::FromHost, 0, 4));
        assert!(poll_job(&task, &mut cx).is_none());

        let mut data = [9u8; 4];
        assert!(matches!(
            store.poll_exec(token, IoBuf::Write(&mut data)),
            Poll::Pending
        ));
        let mut job = expect_job(&task, &mut cx);
        assert_eq!(job.req().dir, Direction::FromHost);
        assert_eq!(job.data(), &[9u8; 4]);
        task.complete(job, Ok(4));

        match store.poll_exec(token, IoBuf::Write(&mut data)) {
            Poll::Ready(receipt) => assert_eq!(receipt.error, None),
            Poll::Pending => panic!("the receipt must be ready"),
        }
    }

    #[test]
    fn sync_job_carries_no_data() {
        let pool = SlotPool::new([0u8; CAP]);
        let (mut store, task) = pool.split();
        let mut cx = Context::from_waker(Waker::noop());

        let token = store.begin_exec(req(Direction::None, 0, 0));
        let mut job = expect_job(&task, &mut cx);
        assert!(job.is_empty());
        assert_eq!(job.data().len(), 0);
        task.complete(job, Ok(0));

        match store.poll_exec(token, IoBuf::None) {
            Poll::Ready(receipt) => {
                assert_eq!(receipt.error, None);
                assert_eq!(receipt.confirmed, 0);
            }
            Poll::Pending => panic!("a sync receipt must be ready"),
        }
    }

    #[test]
    fn a_backend_error_maps_to_the_receipt() {
        let pool = SlotPool::new([0u8; CAP]);
        let (mut store, task) = pool.split();
        let mut cx = Context::from_waker(Waker::noop());

        let token = store.begin_exec(req(Direction::FromHost, 0, 4));
        let mut data = [1u8; 4];
        assert!(matches!(
            store.poll_exec(token, IoBuf::Write(&mut data)),
            Poll::Pending
        ));
        let job = expect_job(&task, &mut cx);
        task.fail(job, StorageError::OutOfBounds);

        match store.poll_exec(token, IoBuf::Write(&mut data)) {
            Poll::Ready(receipt) => {
                assert_eq!(receipt.error, Some(Fault::OutOfBounds));
                assert_eq!(receipt.effect, Effect::UnknownRemainder);
            }
            Poll::Pending => unreachable!(),
        }
    }

    #[test]
    fn contract_violations_spend_the_token() {
        let pool = SlotPool::new([0u8; CAP]);
        let (mut store, _task) = pool.split();

        let token = store.begin_exec(req(Direction::ToHost, 0, 8));
        let mut out = [0u8; 4];
        match store.poll_exec(token, IoBuf::Read(&mut out)) {
            Poll::Ready(receipt) => assert_eq!(receipt.error, Some(Fault::Contract)),
            Poll::Pending => panic!("a bad buffer is a contract violation"),
        }
        // The token is spent: polling again is also a contract violation.
        match store.poll_exec(token, IoBuf::Read(&mut out)) {
            Poll::Ready(receipt) => assert_eq!(receipt.error, Some(Fault::Contract)),
            Poll::Pending => unreachable!(),
        }
    }

    #[test]
    fn one_buffer_serialises_two_reads() {
        let pool = SlotPool::new([0u8; CAP]);
        let (mut store, task) = pool.split();
        let mut cx = Context::from_waker(Waker::noop());

        let first = store.begin_exec(req(Direction::ToHost, 0, 4));
        let second = store.begin_exec(req(Direction::ToHost, 4, 4));

        let mut job = expect_job(&task, &mut cx);
        // The second request cannot post while the first owns the buffer.
        assert!(poll_job(&task, &mut cx).is_none());

        job.data().copy_from_slice(b"WXYZ");
        task.complete(job, Ok(4));
        let mut out = [0u8; 4];
        let _ = store.poll_exec(first, IoBuf::Read(&mut out));
        assert_eq!(&out, b"WXYZ");

        // Releasing the buffer lets the parked slot post.
        let mut job = expect_job(&task, &mut cx);
        job.data().copy_from_slice(b"2345");
        task.complete(job, Ok(4));
        let mut out = [0u8; 4];
        let _ = store.poll_exec(second, IoBuf::Read(&mut out));
        assert_eq!(&out, b"2345");
    }

    #[test]
    fn cancel_returns_the_buffer_only_after_the_result() {
        let pool = SlotPool::new([0u8; CAP]);
        let (mut store, task) = pool.split();
        let mut cx = Context::from_waker(Waker::noop());

        let token = store.begin_exec(req(Direction::ToHost, 0, 4));
        let job = expect_job(&task, &mut cx);
        store.cancel(token);
        // Cancelling twice is idempotent.
        store.cancel(token);
        task.complete(job, Ok(4));

        // The buffer is recycled: a fresh request posts immediately.
        let next = store.begin_exec(req(Direction::ToHost, 8, 4));
        let mut job = expect_job(&task, &mut cx);
        job.data().copy_from_slice(b"post");
        task.complete(job, Ok(4));
        let mut out = [0u8; 4];
        let _ = store.poll_exec(next, IoBuf::Read(&mut out));
        assert_eq!(&out, b"post");
    }

    #[test]
    fn dropping_a_job_abandons_the_operation_and_recycles_the_buffer() {
        let pool = SlotPool::new([0u8; CAP]);
        let (mut store, task) = pool.split();
        let mut cx = Context::from_waker(Waker::noop());

        let token = store.begin_exec(req(Direction::ToHost, 0, 4));
        let job = expect_job(&task, &mut cx);
        drop(job);

        // The abandoned token is gone, and the buffer is free again.
        let mut out = [0u8; 4];
        match store.poll_exec(token, IoBuf::Read(&mut out)) {
            Poll::Ready(receipt) => assert_eq!(receipt.error, Some(Fault::Contract)),
            Poll::Pending => unreachable!(),
        }
        let next = store.begin_exec(req(Direction::ToHost, 4, 4));
        let mut job = expect_job(&task, &mut cx);
        job.data().copy_from_slice(b"kept");
        task.complete(job, Ok(4));
        let mut out = [0u8; 4];
        let _ = store.poll_exec(next, IoBuf::Read(&mut out));
        assert_eq!(&out, b"kept");
    }

    #[test]
    fn a_cancelled_job_parks_a_waiting_write_until_the_buffer_comes_back() {
        let pool = SlotPool::new([0u8; CAP]);
        let (mut store, task) = pool.split();
        let mut cx = Context::from_waker(Waker::noop());

        // A read owns the buffer, then the shell cancels it while the task
        // still holds the job.
        let read = store.begin_exec(req(Direction::ToHost, 0, 4));
        let job = expect_job(&task, &mut cx);
        store.cancel(read);
        assert!(store.poll_wake(&mut cx).is_pending());

        // A write now waits for data AND for the buffer.
        let write = store.begin_exec(req(Direction::FromHost, 0, 4));
        let mut data = [5u8; 4];
        assert!(matches!(
            store.poll_exec(write, IoBuf::Write(&mut data)),
            Poll::Pending
        ));
        // The buffer is gone: parking is the only safe answer, otherwise the
        // shell would spin without ever yielding to the task.
        assert!(store.poll_wake(&mut cx).is_pending());

        drop(job);
        assert!(store.poll_wake(&mut cx).is_ready());
        assert!(matches!(
            store.poll_exec(write, IoBuf::Write(&mut data)),
            Poll::Pending
        ));
        let mut job = expect_job(&task, &mut cx);
        assert_eq!(job.data(), &data);
        task.complete(job, Ok(4));
        match store.poll_exec(write, IoBuf::Write(&mut data)) {
            Poll::Ready(receipt) => assert_eq!(receipt.error, None),
            Poll::Pending => unreachable!(),
        }
    }

    #[test]
    fn reset_reclaims_a_settled_receipt() {
        let pool = SlotPool::new([0u8; CAP]);
        let (mut store, task) = pool.split();
        let mut cx = Context::from_waker(Waker::noop());

        // A settled read keeps the buffer until its receipt is polled.
        let _orphan = store.begin_exec(req(Direction::ToHost, 0, 4));
        let mut job = expect_job(&task, &mut cx);
        job.data().copy_from_slice(b"drop");
        task.complete(job, Ok(4));

        pool.reset();
        let next = store.begin_exec(req(Direction::ToHost, 4, 4));
        let mut job = expect_job(&task, &mut cx);
        job.data().copy_from_slice(b"back");
        task.complete(job, Ok(4));
        let mut out = [0u8; 4];
        let _ = store.poll_exec(next, IoBuf::Read(&mut out));
        assert_eq!(&out, b"back");
    }

    #[test]
    fn poll_wake_parks_while_running_and_wakes_on_completion() {
        let pool = SlotPool::new([0u8; CAP]);
        let (mut store, task) = pool.split();
        let mut cx = Context::from_waker(Waker::noop());

        let _token = store.begin_exec(req(Direction::ToHost, 0, 4));
        assert!(store.poll_wake(&mut cx).is_pending());

        let mut job = expect_job(&task, &mut cx);
        job.data().copy_from_slice(b"done");
        task.complete(job, Ok(4));
        assert!(store.poll_wake(&mut cx).is_ready());
    }

    #[test]
    fn the_fifth_request_is_rejected() {
        let pool = SlotPool::new([0u8; CAP]);
        let (mut store, _task) = pool.split();
        for _ in 0..4 {
            assert!(store.begin_exec(req(Direction::ToHost, 0, 4)).is_valid());
        }
        assert!(!store.begin_exec(req(Direction::ToHost, 0, 4)).is_valid());
    }

    #[test]
    fn jobs_report_the_lun_selected_at_begin() {
        let pool = SlotPool::new([0u8; CAP]);
        let (mut store, task) = pool.split();
        let mut cx = Context::from_waker(Waker::noop());

        store.select_lun(2);
        let first = store.begin_exec(req(Direction::ToHost, 0, 4));
        store.select_lun(0);
        let second = store.begin_exec(req(Direction::ToHost, 8, 4));

        // One buffer: only the first operation is posted.
        let mut job = expect_job(&task, &mut cx);
        assert_eq!(job.lun(), 2);
        job.data().copy_from_slice(b"two2");
        task.complete(job, Ok(4));
        let mut out = [0u8; 4];
        let _ = store.poll_exec(first, IoBuf::Read(&mut out));
        assert_eq!(&out, b"two2");

        let mut job = expect_job(&task, &mut cx);
        assert_eq!(job.lun(), 0, "the second job keeps its own LUN");
        job.data().copy_from_slice(b"zero");
        task.complete(job, Ok(4));
        let _ = store.poll_exec(second, IoBuf::Read(&mut out));
        assert_eq!(&out, b"zero");
    }

    #[test]
    fn an_oversized_request_is_rejected() {
        let pool = SlotPool::new([0u8; CAP]);
        let (mut store, _task) = pool.split();
        let token = store.begin_exec(req(Direction::ToHost, 0, CAP as u32 + 4));
        assert!(!token.is_valid());
    }
}
