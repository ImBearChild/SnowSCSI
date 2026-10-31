//! Storage adapter from the SD card to the core `Storage` seam.
//!
//! The transports drive a [`snowscsi::core::Target`] through a
//! [`Storage`](snowscsi::core::storage::Storage) adapter and park on an
//! [`AsyncWake`]. Here the bytes are moved by a **native async** worker: a
//! single [`sd_task`] future is joined with the USB stack and the BOT loop
//! inside `gadget()`, so the card is borrowed for the lifetime of the gadget
//! and no spawner, `'static` task or `block_on` is involved.
//!
//! ```text
//! msc::run (Storage + AsyncWake)          sd_task (async)
//!   begin_exec  ──► slot table
//!   poll_exec   ──► Job  ──jobs──►  await read_at/write_at/sync
//!   poll_wake   ◄── Done ◄─done──   post + wake
//! ```
//!
//! `begin_exec` sees metadata only and `poll_exec` re-borrows the caller's
//! bank, so the adapter cannot hand that bank straight to the SD driver: one
//! staging buffer (one bank, [`STAGE`]) travels store → job → worker → done →
//! store. A read is copied once into the caller's bank when its receipt is
//! polled, a write once out of it when its data arrives.

use core::task::{Context, Poll};

use embassy_sync::blocking_mutex::raw::NoopRawMutex;
use embassy_sync::channel::{Channel, Receiver, Sender};
use embassy_sync::waitqueue::GenericAtomicWaker;

use snowscsi::common::async_seekable_storage::{AsyncFlatData, AsyncWritableFlatData};
use snowscsi::common::seekable_storage::StorageError;
use snowscsi::core::storage::{IoBuf, IoReq, IoToken, Storage, StorageReceipt};
use snowscsi::core::{AsyncWake, Direction, Effect, Fault};

use crate::sd::SdCard;

/// One staging buffer, sized to one SCSI bank ([`crate::drive::WORK_LEN`]).
pub const STAGE: usize = crate::drive::WORK_LEN;

/// Fixed slot table size, matching the library's synchronous adapter.
const SLOTS: usize = 4;

/// One unit of work handed to the SD worker.
///
/// The staging buffer is moved to the worker and returned through [`Done`], so
/// exactly one buffer exists and a settled read keeps it reserved until the
/// caller polls the receipt.
pub struct Job<'b> {
    tag: u32,
    req: IoReq,
    buf: &'b mut [u8; STAGE],
}

/// A finished job, carrying the staging buffer back.
pub struct Done<'b> {
    tag: u32,
    result: Result<usize, StorageError>,
    buf: &'b mut [u8; STAGE],
}

/// Job channel: capacity one, because only one job can be in flight while the
/// single staging buffer is on the worker.
pub type JobChan<'b> = Channel<NoopRawMutex, Job<'b>, 1>;
/// Completion channel: capacity one, matching the single in-flight job.
pub type DoneChan<'b> = Channel<NoopRawMutex, Done<'b>, 1>;

/// Completion waker shared by the BOT side and the SD worker.
///
/// Both sides run in the **same** `join4` future on one single-threaded
/// executor, and this esp-hal build provides no `critical-section` impl, so
/// `NoopRawMutex` (the documented same-executor mutex) is sound here; the
/// channels and waker never cross a task, thread or interrupt boundary.
pub type StorageWaker = GenericAtomicWaker<NoopRawMutex>;

/// Build the completion waker (see [`StorageWaker`]).
pub const fn storage_waker() -> StorageWaker {
    StorageWaker::new(NoopRawMutex::new())
}

/// Slot lifecycle.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum SlotState {
    /// `FromHost` request whose data has not arrived yet.
    Waiting,
    /// Ready to post, waiting for the staging buffer.
    Pending,
    /// Posted to the worker future.
    Running,
    /// Worker finished; the receipt is reported on the next poll.
    Settled,
    /// Cancelled while running; freed when the result comes back.
    Cancelled,
}

struct Slot<'b> {
    req: IoReq,
    tag: u32,
    state: SlotState,
    result: Option<Result<usize, StorageError>>,
    /// Staging buffer of a settled job. It stays reserved here until the token
    /// is polled, so a later job can never overwrite bytes a `ToHost` poll has
    /// not copied out yet.
    staged: Option<&'b mut [u8; STAGE]>,
}

/// Fixed-slot asynchronous storage over the on-board SD card.
///
/// Both the task and this adapter run in the same future (one `join4`), so the
/// same-executor `NoopRawMutex` channels need no spawner, `Send` bound or
/// `critical-section` implementation.
pub struct SdStore<'c, 'b> {
    jobs: Sender<'c, NoopRawMutex, Job<'b>, 1>,
    done: Receiver<'c, NoopRawMutex, Done<'b>, 1>,
    wake: &'c StorageWaker,
    slots: [Option<Slot<'b>>; SLOTS],
    /// The single staging buffer; `None` while the worker owns it.
    buf: Option<&'b mut [u8; STAGE]>,
    next_tag: u32,
    /// A `Done` was collected since the last `poll_wake`.
    progressed: bool,
}

impl<'c, 'b> SdStore<'c, 'b> {
    /// Build the adapter over the job/completion channels and the staging
    /// buffer.
    ///
    /// `'c` is the borrow of the channels/waker (one gadget invocation) and
    /// `'b` the staging-buffer borrow; they are independent so the channels
    /// do not have to outlive their own payload type.
    pub fn new(
        jobs: &'c JobChan<'b>,
        done: &'c DoneChan<'b>,
        wake: &'c StorageWaker,
        buf: &'b mut [u8; STAGE],
    ) -> Self {
        Self {
            jobs: jobs.sender(),
            done: done.receiver(),
            wake,
            slots: core::array::from_fn(|_| None),
            buf: Some(buf),
            next_tag: 1,
            progressed: false,
        }
    }

    fn mint_tag(&mut self) -> u32 {
        let tag = self.next_tag;
        self.next_tag = self.next_tag.wrapping_add(1).max(1);
        tag
    }

    fn begin(&mut self, req: IoReq) -> IoToken {
        if req.len as usize > STAGE {
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

    /// Post a `Pending` slot if the staging buffer is free.
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
        match self.jobs.try_send(job) {
            Ok(()) => {
                if let Some(slot) = self.slots[index].as_mut() {
                    slot.state = SlotState::Running;
                }
            }
            // The channel cannot be full while no job is in flight, but keep
            // the buffer and let the next poll retry instead of panicking.
            Err(embassy_sync::channel::TrySendError::Full(job)) => {
                self.buf = Some(job.buf);
            }
        }
    }

    /// Collect every finished job without blocking.
    fn drain(&mut self) {
        while let Ok(done) = self.done.try_receive() {
            self.progressed = true;
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
                    if let Some(staged) = slot.staged {
                        self.buf = Some(staged);
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
            // The token is spent even when the buffer is wrong.
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
                let Some(stage) = self.buf.as_mut() else {
                    return Poll::Pending;
                };
                stage[..data.len()].copy_from_slice(data);
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
                    Ok(n) => Poll::Ready(StorageReceipt::ok(n)),
                    Err(e) => Poll::Ready(StorageReceipt::failed(
                        map_err(e),
                        0,
                        if req.dir == Direction::FromHost {
                            Effect::UnknownRemainder
                        } else {
                            Effect::Known
                        },
                    )),
                }
            }
            SlotState::Cancelled => Poll::Ready(contract()),
        }
    }
}

impl Storage for SdStore<'_, '_> {
    fn begin_exec(&mut self, req: IoReq) -> IoToken {
        self.begin(req)
    }

    fn poll_exec(&mut self, token: IoToken, buf: IoBuf<'_>) -> Poll<StorageReceipt> {
        self.poll(token, buf)
    }

    fn cancel(&mut self, token: IoToken) {
        if let Some(index) = self.find(token) {
            self.release(index);
        }
    }
}

impl AsyncWake for SdStore<'_, '_> {
    /// Register the caller's waker, collect finished jobs, and report whether
    /// the runner should poll again.
    ///
    /// The waker is registered *before* the completion check: a `Done` posted
    /// in between is either collected by the drain or wakes the fresh waker.
    /// `Ready` means a job settled, a completion was collected, or nothing is
    /// running and no write is still waiting for its data, so the runner can
    /// advance by polling its token.
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
        if core::mem::take(&mut self.progressed) || settled || (!running && !waiting) {
            Poll::Ready(())
        } else {
            Poll::Pending
        }
    }
}

/// SD worker: execute jobs until the gadget future is dropped.
///
/// One future in the gadget's `join4`; it borrows the card for its lifetime.
/// Each completed job posts its buffer back and wakes the `Storage` side.
pub async fn sd_task<'b>(
    card: &mut SdCard<'_>,
    jobs: &JobChan<'b>,
    done: &DoneChan<'b>,
    wake: &StorageWaker,
) -> ! {
    loop {
        let Job { tag, req, buf } = jobs.receive().await;
        let len = req.len as usize;
        let result = match req.dir {
            Direction::ToHost => AsyncFlatData::read_at(card, req.offset, &mut buf[..len])
                .await
                .map(|()| len),
            Direction::FromHost => AsyncWritableFlatData::write_at(card, req.offset, &buf[..len])
                .await
                .map(|()| len),
            Direction::None => AsyncWritableFlatData::sync(card).await.map(|()| 0),
        };
        done.send(Done { tag, result, buf }).await;
        wake.wake();
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

/// Map the byte-plane error vocabulary onto the core fault vocabulary.
fn map_err(e: StorageError) -> Fault {
    match e {
        StorageError::OutOfBounds => Fault::OutOfBounds,
        StorageError::NotWritable => Fault::NotWritable,
        StorageError::Io(_) => Fault::Io,
        StorageError::Unsupported => Fault::Unsupported,
    }
}
