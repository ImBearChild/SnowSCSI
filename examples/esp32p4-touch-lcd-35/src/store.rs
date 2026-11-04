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
//!
//! # Encrypted plane
//!
//! [`Backing::SdCipher`] wraps the card in
//! [`AsyncCipherPlane`](snowscsi::common::cipher::AsyncCipherPlane) with the
//! hardware AES engine from [`crate::aes`], composed by
//! [`AesCtr`](snowscsi::common::cipher::AesCtr) into the same offset-addressed,
//! length-preserving CTR stream the CLI's encrypted bundles use. The plane is a
//! straight decorator: geometry, `sync` and the error mapping are the card's.
//!
//! [`Backing::Zero`] is deliberately **not** encrypted: it is the measurement
//! plane, and keeping AES out of it is what lets the USB/BOT ceiling be measured
//! on its own.

use snowscsi::common::async_seekable_storage::{AsyncFlatData, AsyncWritableFlatData};
use snowscsi::common::cipher::{AesCtr, AsyncCipherPlane};
use snowscsi::common::seekable_storage::{StorageError, ZeroBackend};
use snowscsi::core::slots::{SlotPool, SlotStore, SlotTask};
use snowscsi::core::Direction;

use crate::aes::{P4Aes, AES_BUF};
use crate::sd::SdCard;

/// Size of the single staging buffer (one SCSI bank).
pub const STAGE: usize = crate::drive::WORK_LEN;

/// Staging chunk used by the encrypting plane's write/fill path.
///
/// The plane keeps this buffer **inside the `Backing` value** (on the stack,
/// next to the card), so it is a tradeoff rather than a free knob: a bigger
/// chunk means fewer hardware-AES transfers per host command (each transfer
/// resets the peripheral and busy-waits), but a bigger `main` frame. 2 KiB is
/// the same size as one DMA buffer (`AES_BUF`) and comfortably fits the small
/// main-task stack; the read path is not limited by it (a read hands the whole
/// buffer to the cipher in one call, and the hardware layer chunks at
/// `AES_BUF`).
pub const CIPHER_SCRATCH: usize = AES_BUF;

/// The pool itself, built once and split into both sides per gadget build.
pub type SdPool = SlotPool<&'static mut [u8; STAGE]>;

/// The `Storage` side of the pool, as seen by the BOT loop.
pub type SdStore<'c, 'b> = SlotStore<'c, &'b mut [u8; STAGE]>;

/// The task side of the pool, as seen by [`sd_task`].
pub type SdJobs<'c, 'b> = SlotTask<'c, &'b mut [u8; STAGE]>;

/// The encrypted SD plane: card + hardware AES-CTR.
pub type SdCipherPlane<'a> = AsyncCipherPlane<SdCard<'a>, AesCtr<P4Aes>, CIPHER_SCRATCH>;

/// One byte plane behind the single LUN.
pub enum Backing<'a> {
    /// The on-board microSD card, served plaintext.
    Sd(SdCard<'a>),
    /// The on-board microSD card behind hardware AES-256-CTR.
    SdCipher(SdCipherPlane<'a>),
    /// All-zero measurement plane: reads return zeros, writes are discarded.
    Zero(ZeroBackend),
}

impl<'a> Backing<'a> {
    /// Back the LUN with the SD card, plaintext.
    pub fn sd(card: SdCard<'a>) -> Self {
        Self::Sd(card)
    }

    /// Back the LUN with the SD card, encrypted with `aes` under `nonce`.
    ///
    /// `nonce` is the fixed high half of the 128-bit CTR counter; the low half
    /// is the block index inside the image. It must match the nonce in the
    /// host-side `image.enc.SNOWBUNDLE` sidecar of the raw ciphertext image on
    /// the card — a different nonce decrypts to garbage (there is no in-image
    /// header to detect this).
    pub fn sd_encrypted(card: SdCard<'a>, aes: P4Aes, nonce: [u8; 8]) -> Self {
        Self::SdCipher(AsyncCipherPlane::new(card, AesCtr::new(aes, nonce)))
    }

    /// Back the LUN with an all-zero plane of `capacity` bytes (measurement).
    pub fn zero(capacity: u64) -> Self {
        Self::Zero(ZeroBackend::new(capacity))
    }
}

/// Delegate to the active plane; the encrypted arm runs the hardware CTR.
impl AsyncFlatData for Backing<'_> {
    async fn read_at(&mut self, off: u64, buf: &mut [u8]) -> Result<(), StorageError> {
        match self {
            Self::Sd(card) => AsyncFlatData::read_at(card, off, buf).await,
            Self::SdCipher(plane) => AsyncFlatData::read_at(plane, off, buf).await,
            Self::Zero(zero) => AsyncFlatData::read_at(zero, off, buf).await,
        }
    }

    fn capacity(&self) -> u64 {
        match self {
            Self::Sd(card) => AsyncFlatData::capacity(card),
            Self::SdCipher(plane) => AsyncFlatData::capacity(plane),
            Self::Zero(zero) => AsyncFlatData::capacity(zero),
        }
    }
}

/// Delegate to the active plane; the encrypted arm encrypts before the write.
impl AsyncWritableFlatData for Backing<'_> {
    async fn write_at(&mut self, off: u64, buf: &[u8]) -> Result<(), StorageError> {
        match self {
            Self::Sd(card) => AsyncWritableFlatData::write_at(card, off, buf).await,
            Self::SdCipher(plane) => AsyncWritableFlatData::write_at(plane, off, buf).await,
            Self::Zero(zero) => AsyncWritableFlatData::write_at(zero, off, buf).await,
        }
    }

    async fn sync(&mut self) -> Result<(), StorageError> {
        match self {
            Self::Sd(card) => AsyncWritableFlatData::sync(card).await,
            Self::SdCipher(plane) => AsyncWritableFlatData::sync(plane).await,
            Self::Zero(zero) => AsyncWritableFlatData::sync(zero).await,
        }
    }

    /// Delegated explicitly (rather than left to the 512-byte default) so the
    /// encrypted plane encrypts each fill chunk and the zero plane keeps its
    /// bounds-check-only fill.
    async fn fill_at(&mut self, off: u64, len: u64, byte: u8) -> Result<(), StorageError> {
        match self {
            Self::Sd(card) => AsyncWritableFlatData::fill_at(card, off, len, byte).await,
            Self::SdCipher(plane) => AsyncWritableFlatData::fill_at(plane, off, len, byte).await,
            Self::Zero(zero) => AsyncWritableFlatData::fill_at(zero, off, len, byte).await,
        }
    }
}

/// Execute jobs until the gadget future is dropped.
///
/// One future in the gadget's `join4`; it borrows the plane for its lifetime.
/// Each finished job reports its buffer and result back through the pool,
/// which wakes the `StoragePending` wait on the BOT side.
pub async fn sd_task(backing: &mut Backing<'_>, jobs: &SdJobs<'_, '_>) -> ! {
    loop {
        let mut job = jobs.next_job().await;
        let req = job.req();
        let len = req.len as usize;
        let result = {
            let buf = job.data();
            match req.dir {
                Direction::ToHost => AsyncFlatData::read_at(backing, req.offset, buf)
                    .await
                    .map(|()| len),
                Direction::FromHost => AsyncWritableFlatData::write_at(backing, req.offset, buf)
                    .await
                    .map(|()| len),
                Direction::None => AsyncWritableFlatData::sync(backing).await.map(|()| 0),
            }
        };
        jobs.complete(job, result);
    }
}
