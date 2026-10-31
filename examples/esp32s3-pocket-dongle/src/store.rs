//! Storage adapter from the SD card to the core `Storage` seam.
//!
//! The transports drive a [`snowscsi::core::Target`] through a
//! [`Storage`](snowscsi::core::storage::Storage) adapter. `SdCard` already
//! speaks the synchronous byte-plane seams ([`FlatData`] + [`WritableFlatData`],
//! which delegate to the asynchronous SDMMC path with
//! [`embassy_futures::block_on`]), so this module only lifts it into the core
//! seam with the library's [`BlockingStorage`] (four slots, always
//! [`Poll::Ready`](core::task::Poll::Ready), `AsyncWake` always ready).

use snowscsi::common::seekable_storage::{FlatData, StorageError, WritableFlatData};
use snowscsi::core::storage::{IoBuf, IoReq, StorageReceipt, SyncStorage};
use snowscsi::core::{Direction, Effect, Fault};

use crate::sd::SdCard;

/// Synchronous storage over the on-board SD card.
pub struct SdStore<'a>(pub SdCard<'a>);

impl<'a> SdStore<'a> {
    /// Back the LUN with `card`.
    pub fn new(card: SdCard<'a>) -> Self {
        Self(card)
    }
}

impl SyncStorage for SdStore<'_> {
    fn exec(&mut self, req: IoReq, buf: IoBuf<'_>) -> StorageReceipt {
        let len = req.len as usize;
        let res = match buf {
            IoBuf::Read(b) => self.0.read_at(req.offset, b).map(|()| len),
            IoBuf::Write(b) => self.0.write_at(req.offset, b).map(|()| len),
            IoBuf::None => self.0.sync().map(|()| 0),
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
