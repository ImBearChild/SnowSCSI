//! Storage plumbing: one byte plane and the asynchronous SD worker.
//!
//! The slot table, the single staging buffer and the completion wakers live in
//! the library's [`SlotPool`](snowscsi::core::slots::SlotPool). This module only
//! owns the card and executes the jobs the pool hands out, so the whole adapter
//! is the loop in [`sd_task`].
//!
//! Both sides run in the same `join4` future on one executor, which is exactly
//! what the pool requires (it is neither `Send` nor `Sync`): no spawner, no
//! `critical-section` implementation and no channel plumbing.

use snowscsi::common::async_seekable_storage::{AsyncFlatData, AsyncWritableFlatData};
use snowscsi::common::seekable_storage::{FlatData, WritableFlatData, ZeroBackend};
use snowscsi::core::slots::{SlotPool, SlotStore, SlotTask};
use snowscsi::core::Direction;

use crate::sd::SdCard;

/// Size of the single staging buffer (one SCSI bank).
pub const STAGE: usize = crate::drive::WORK_LEN;

/// The pool itself, built once and split into both sides per gadget build.
pub type SdPool = SlotPool<&'static mut [u8; STAGE]>;

/// The `Storage` side of the pool, as seen by the BOT loop.
pub type SdStore<'c, 'b> = SlotStore<'c, &'b mut [u8; STAGE]>;

/// The task side of the pool, as seen by [`sd_task`].
pub type SdJobs<'c, 'b> = SlotTask<'c, &'b mut [u8; STAGE]>;

/// One byte plane behind the single LUN.
pub enum Backing<'a> {
    /// The on-board microSD card.
    Sd(SdCard<'a>),
    /// All-zero measurement plane: reads return zeros, writes are discarded.
    Zero(ZeroBackend),
}

impl<'a> Backing<'a> {
    /// Back the LUN with the SD card.
    pub fn sd(card: SdCard<'a>) -> Self {
        Self::Sd(card)
    }

    /// Back the LUN with an all-zero plane of `capacity` bytes (measurement).
    pub fn zero(capacity: u64) -> Self {
        Self::Zero(ZeroBackend::new(capacity))
    }
}

/// Execute jobs until the gadget future is dropped.
///
/// One future in the gadget's `join4`; it borrows the card for its lifetime.
/// Each finished job reports its buffer and result back through the pool,
/// which wakes the `StoragePending` wait on the BOT side.
pub async fn sd_task(backing: &mut Backing<'_>, jobs: &SdJobs<'_, '_>) -> ! {
    loop {
        let mut job = jobs.next_job().await;
        let req = job.req();
        let len = req.len as usize;
        let result = {
            let buf = job.data();
            match backing {
                Backing::Sd(card) => match req.dir {
                    Direction::ToHost => {
                        AsyncFlatData::read_at(card, req.offset, buf)
                            .await
                            .map(|()| len)
                    }
                    Direction::FromHost => {
                        AsyncWritableFlatData::write_at(card, req.offset, buf)
                            .await
                            .map(|()| len)
                    }
                    Direction::None => AsyncWritableFlatData::sync(card).await.map(|()| 0),
                },
                // The measurement plane completes without awaiting: its data is
                // already resident (zeros / discarded).
                Backing::Zero(zero) => match req.dir {
                    Direction::ToHost => {
                        FlatData::read_at(zero, req.offset, buf).map(|()| len)
                    }
                    Direction::FromHost => {
                        WritableFlatData::write_at(zero, req.offset, buf).map(|()| len)
                    }
                    Direction::None => WritableFlatData::sync(zero).map(|()| 0),
                },
            }
        };
        jobs.complete(job, result);
    }
}
