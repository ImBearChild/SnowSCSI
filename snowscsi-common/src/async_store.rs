//! Asynchronous storage-plane seam, mirroring [`crate::store`].
//!
//! A single [`AsyncStorePlane::do_op`] entry takes the same
//! [`crate::store::StoreOp`] vocabulary as the synchronous shell. Two bridges
//! make existing backends usable without touching them:
//!
//! * the blanket `impl<T: AsyncWritableFlatData + ?Sized> AsyncStorePlane for T`
//!   turns any writable asynchronous byte plane into a plane directly;
//! * [`BlockingAsync`] wraps an already-erased *synchronous* [`StorePlane`]
//!   (block read-only / read-write / filesystem) and drives it without
//!   blocking the executor for a whole-disc fill.
//!
//! `async fn` in a trait is not object-safe, so the plane is a generic trait
//! (not an enum of `&mut dyn`); heterogeneous LUNs compose two planes with
//! [`Either`].

use crate::async_seekable_storage::{yield_now, AsyncWritableFlatData};
use crate::seekable_storage::StorageError;
use crate::store::{StoreOp, StorePlane};

/// Chunk size for the [`BlockingAsync`] bridge's outer `Fill` split.
///
/// 64 KiB — it exists only to bound how long a single synchronous inner op
/// runs before the bridge yields; it is not a buffer size and allocates
/// nothing.
const FILL_BRIDGE_CHUNK: usize = 64 * 1024;

/// Asynchronous mirror of [`crate::store::StorePlane`].
///
/// One [`Self::do_op`] entry executes a [`StoreOp`] on the addressed plane,
/// plus a direct plane-level [`Self::sync`]. `async fn` in a trait is not
/// object-safe, so the plane is used through a generic type parameter
/// (typically the `P` of a LUN container) rather than `&mut dyn`.
#[allow(async_fn_in_trait)]
pub trait AsyncStorePlane {
    /// Execute `op` on this plane.
    ///
    /// A model mismatch (a filesystem op on a byte plane, or a byte op on a
    /// filesystem plane) is [`StorageError::Unsupported`]; a write on a
    /// read-only plane is [`StorageError::NotWritable`].
    async fn do_op(&mut self, op: StoreOp<'_>) -> Result<(), StorageError>;

    /// Persist the plane (plane-level [`StoreOp::Sync`]).
    async fn sync(&mut self) -> Result<(), StorageError>;
}

/// Any writable asynchronous byte plane is a store plane.
///
/// `Read`/`Write`/`Fill`/`Sync` dispatch to the byte plane; the path-addressed
/// filesystem ops are not part of a byte plane's model and return
/// [`StorageError::Unsupported`]. A read-only [`AsyncFlatData`] plane gets no
/// blanket — a read-only blanket would overlap this writable one — so a
/// read-only plane is wrapped explicitly, e.g. through [`BlockingAsync`] over
/// a read-only synchronous plane.
///
/// [`AsyncFlatData`]: crate::async_seekable_storage::AsyncFlatData
impl<T: AsyncWritableFlatData + ?Sized> AsyncStorePlane for T {
    async fn do_op(&mut self, op: StoreOp<'_>) -> Result<(), StorageError> {
        match op {
            StoreOp::Read { off, buf } => self.read_at(off, buf).await,
            StoreOp::Write { off, buf } => self.write_at(off, buf).await,
            StoreOp::Fill { off, len, byte } => self.fill_at(off, len, byte).await,
            StoreOp::Sync => AsyncWritableFlatData::sync(self).await,
            StoreOp::FileRead { .. }
            | StoreOp::FileWrite { .. }
            | StoreOp::FileRemove { .. } => Err(StorageError::Unsupported),
        }
    }

    async fn sync(&mut self) -> Result<(), StorageError> {
        AsyncWritableFlatData::sync(self).await
    }
}

/// Synchronous-to-asynchronous pass-through bridge.
///
/// Wraps an already-erased synchronous [`StorePlane`] (read-only block,
/// read-write block, or filesystem). Each `Fill` is split into 64 KiB-sized
/// inner ops with a [`yield_now`] after every chunk, so a whole-disc format
/// cannot pin the executor; every other op is forwarded once and then yields
/// once. The bridge does **not** run the inner
/// op concurrently with anything else — a synchronous inner op occupies the
/// executor for its duration, so filesystem I/O forwarded here still blocks.
pub struct BlockingAsync<P>(pub P);

impl AsyncStorePlane for BlockingAsync<StorePlane<'_>> {
    async fn do_op(&mut self, op: StoreOp<'_>) -> Result<(), StorageError> {
        match op {
            StoreOp::Fill {
                mut off,
                mut len,
                byte,
            } => {
                while len > 0 {
                    let n = core::cmp::min(len, FILL_BRIDGE_CHUNK as u64);
                    self.0.do_op(StoreOp::Fill { off, len: n, byte })?;
                    off += n;
                    len -= n;
                    yield_now().await;
                }
                Ok(())
            }
            other => {
                self.0.do_op(other)?;
                yield_now().await;
                Ok(())
            }
        }
    }

    async fn sync(&mut self) -> Result<(), StorageError> {
        self.0.sync()?;
        yield_now().await;
        Ok(())
    }
}

/// Heterogeneous plane wrapper (generic enum, not `dyn`).
///
/// Composes two plane types — typically a native asynchronous plane and a
/// [`BlockingAsync`] bridge — into a single [`AsyncStorePlane`], so one LUN
/// container can hold either kind. Further combinations compose with nested
/// `Either` or a user-written enum.
pub enum Either<A, B> {
    /// First plane.
    A(A),
    /// Second plane.
    B(B),
}

impl<A: AsyncStorePlane, B: AsyncStorePlane> AsyncStorePlane for Either<A, B> {
    async fn do_op(&mut self, op: StoreOp<'_>) -> Result<(), StorageError> {
        match self {
            Either::A(a) => a.do_op(op).await,
            Either::B(b) => b.do_op(op).await,
        }
    }

    async fn sync(&mut self) -> Result<(), StorageError> {
        match self {
            Either::A(a) => AsyncStorePlane::sync(a).await,
            Either::B(b) => AsyncStorePlane::sync(b).await,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::seekable_storage::RamBackend;

    fn block_on<F: core::future::Future>(fut: F) -> F::Output {
        let mut fut = core::pin::pin!(fut);
        let mut cx = core::task::Context::from_waker(core::task::Waker::noop());
        loop {
            if let core::task::Poll::Ready(v) = fut.as_mut().poll(&mut cx) {
                return v;
            }
        }
    }

    #[test]
    fn blanket_dispatches_block_ops() {
        let mut ram = [0u8; 64];
        let mut backend = RamBackend::new(&mut ram);
        block_on(async {
            AsyncStorePlane::do_op(
                &mut backend,
                StoreOp::Write {
                    off: 4,
                    buf: &[1, 2, 3, 4],
                },
            )
            .await
            .unwrap();
            let mut out = [0u8; 4];
            AsyncStorePlane::do_op(
                &mut backend,
                StoreOp::Read {
                    off: 4,
                    buf: &mut out,
                },
            )
            .await
            .unwrap();
            assert_eq!(out, [1, 2, 3, 4]);

            AsyncStorePlane::do_op(
                &mut backend,
                StoreOp::Fill {
                    off: 0,
                    len: 64,
                    byte: 0x5A,
                },
            )
            .await
            .unwrap();
            AsyncStorePlane::do_op(&mut backend, StoreOp::Sync)
                .await
                .unwrap();

            // A path-addressed op is not part of a byte plane's model.
            assert_eq!(
                AsyncStorePlane::do_op(
                    &mut backend,
                    StoreOp::FileRead {
                        path: "x",
                        off: 0,
                        buf: &mut out,
                    },
                )
                .await,
                Err(StorageError::Unsupported)
            );
        });
        assert!(ram.iter().all(|&b| b == 0x5A));
    }

    #[test]
    fn blocking_bridge_forwards_and_chunks() {
        // More than one 64 KiB bridge chunk so the outer split is exercised.
        let mut ram = [0u8; 70_000];
        let mut backend = RamBackend::new(&mut ram);
        {
            let mut bridge = BlockingAsync(StorePlane::BlockRw(&mut backend));
            block_on(async {
                bridge
                    .do_op(StoreOp::Write {
                        off: 0,
                        buf: &[7u8; 8],
                    })
                    .await
                    .unwrap();
                bridge
                    .do_op(StoreOp::Fill {
                        off: 0,
                        len: 70_000,
                        byte: 0x11,
                    })
                    .await
                    .unwrap();
                bridge.sync().await.unwrap();
            });
        }
        assert!(ram.iter().all(|&b| b == 0x11));
    }

    #[test]
    fn blocking_bridge_read_only_rejects_write() {
        let mut ram = [0u8; 16];
        let mut backend = RamBackend::new(&mut ram);
        let mut bridge = BlockingAsync(StorePlane::BlockRo(&mut backend));
        block_on(async {
            assert_eq!(
                bridge
                    .do_op(StoreOp::Write {
                        off: 0,
                        buf: &[1],
                    })
                    .await,
                Err(StorageError::NotWritable)
            );
        });
    }

    #[test]
    fn either_dispatches_to_both_sides() {
        let mut a = [0u8; 16];
        let mut b = [0u8; 16];
        let mut left: Either<RamBackend<'_>, RamBackend<'_>> =
            Either::A(RamBackend::new(&mut a));
        let mut right: Either<RamBackend<'_>, RamBackend<'_>> =
            Either::B(RamBackend::new(&mut b));
        block_on(async {
            left.do_op(StoreOp::Write {
                off: 0,
                buf: &[1, 2],
            })
            .await
            .unwrap();
            right
                .do_op(StoreOp::Write {
                    off: 0,
                    buf: &[3, 4],
                })
                .await
                .unwrap();
            left.sync().await.unwrap();
        });
        assert_eq!(&a[..2], &[1, 2]);
        assert_eq!(&b[..2], &[3, 4]);
    }
}
