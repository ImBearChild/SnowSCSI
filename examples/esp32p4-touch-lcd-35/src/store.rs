//! Storage adapter from the SD card to the core `Storage` seam.
//!
//! The transports drive a [`snowscsi::core::Target`] through a
//! [`Storage`](snowscsi::core::storage::Storage) adapter. `SdCard` already
//! speaks the synchronous byte-plane seams ([`FlatData`] + [`WritableFlatData`],
//! which delegate to the asynchronous SDMMC path with
//! [`embassy_futures::block_on`]), so this module only lifts it into the core
//! seam with the library's [`BlockingStorage`] (four slots, always
//! [`Poll::Ready`](core::task::Poll::Ready), `AsyncWake` always ready).
//!
//! The [`Backing`] enum keeps the measurement path in `main` (`ZERO_BACKEND`):
//! an all-zero plane that measures USB + BOT with no SD I/O at all.

use snowscsi::common::seekable_storage::{FlatData, StorageError, WritableFlatData, ZeroBackend};
use snowscsi::core::storage::{IoBuf, IoReq, StorageReceipt, SyncStorage};
use snowscsi::core::{Direction, Effect, Fault};

use crate::sd::SdCard;

/// One byte plane behind the single LUN.
pub enum Backing<'a> {
    /// The on-board microSD card.
    Sd(SdCard<'a>),
    /// All-zero measurement plane: reads return zeros, writes are discarded.
    Zero(ZeroBackend),
}

/// Synchronous storage over the LUN's byte plane.
pub struct SdStore<'a>(pub Backing<'a>);

impl<'a> SdStore<'a> {
    /// Back the LUN with the SD card.
    pub fn sd(card: SdCard<'a>) -> Self {
        Self(Backing::Sd(card))
    }

    /// Back the LUN with an all-zero plane of `capacity` bytes (measurement).
    pub fn zero(capacity: u64) -> Self {
        Self(Backing::Zero(ZeroBackend::new(capacity)))
    }
}

impl SyncStorage for SdStore<'_> {
    fn exec(&mut self, req: IoReq, buf: IoBuf<'_>) -> StorageReceipt {
        let len = req.len as usize;
        let res = match buf {
            IoBuf::Read(b) => match &mut self.0 {
                Backing::Sd(card) => card.read_at(req.offset, b),
                Backing::Zero(zero) => zero.read_at(req.offset, b),
            }
            .map(|()| len),
            IoBuf::Write(b) => match &mut self.0 {
                Backing::Sd(card) => card.write_at(req.offset, b),
                Backing::Zero(zero) => zero.write_at(req.offset, b),
            }
            .map(|()| len),
            IoBuf::None => match &mut self.0 {
                Backing::Sd(card) => card.sync(),
                Backing::Zero(zero) => zero.sync(),
            }
            .map(|()| 0),
        };
        match res {
            Ok(n) => StorageReceipt::ok(n),
            Err(e) => StorageReceipt::failed(
                map_err(e),
                0,
                if req.dir == Direction::FromHost {
                    Effect::UnknownRemainder
                } else {
                    Effect::Known
                },
            ),
        }
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
