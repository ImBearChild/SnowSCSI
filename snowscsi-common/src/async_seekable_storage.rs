//! Asynchronous byte-plane storage seams, mirroring [`crate::seekable_storage`].
//!
//! [`AsyncFlatData`] is the read-only plane; [`AsyncWritableFlatData`] adds
//! offset-addressed write + persist plus a chunked
//! [`AsyncWritableFlatData::fill_at`]. Addressing, the error type
//! ([`StorageError`]) and the synchronous [`AsyncFlatData::capacity`] query
//! match the synchronous seam exactly; only the call protocol differs
//! (`async fn` instead of a blocking call).
//!
//! These traits bind no runtime: an `async fn` in a trait is the only coupling
//! to the executor, so the seam is `no_std` and works with any executor.
//! `async fn` in a trait is not object-safe, so planes are used through a
//! generic type parameter rather than `&mut dyn` (see
//! [`crate::async_store::AsyncStorePlane`]).

use crate::seekable_storage::{FlatData, RamBackend, StorageError, WritableFlatData, ZeroBackend};

/// Stack chunk size for the default [`AsyncWritableFlatData::fill_at`] loop.
///
/// One sector (512 B) — the same size the synchronous seam uses: safe for
/// every backend's alignment (SD blocks, 512e sectors) and small enough for an
/// MCU stack. Backends with a cheaper primitive override `fill_at`
/// (`RamBackend` uses `memset`).
const FILL_CHUNK: usize = 512;

/// Yield control back to the executor exactly once.
///
/// The returned future resolves to [`core::task::Poll::Pending`] on its first
/// poll (after arranging a self-wake) and [`core::task::Poll::Ready`] on the
/// next. It is used between fill blocks so a backend whose writes complete
/// synchronously (RAM, or a bridge over a blocking backend) cannot pin the
/// executor for the whole duration of a large fill.
pub async fn yield_now() {
    let mut yielded = false;
    core::future::poll_fn(move |cx| {
        if yielded {
            core::task::Poll::Ready(())
        } else {
            yielded = true;
            cx.waker().wake_by_ref();
            core::task::Poll::Pending
        }
    })
    .await
}

/// Read-only disc data plane: asynchronous mirror of
/// [`crate::seekable_storage::FlatData`].
///
/// Offset-addressed byte source. The error type is fixed ([`StorageError`])
/// so implementations agree on failures across the seam, and
/// [`Self::capacity`] stays synchronous because geometry is needed before any
/// I/O begins (READ CAPACITY).
#[allow(async_fn_in_trait)]
pub trait AsyncFlatData {
    /// Read `buf.len()` bytes starting at `off`.
    ///
    /// Implementations must bounds-check: `off + buf.len() > capacity()` is
    /// [`StorageError::OutOfBounds`] (do NOT rely on short reads).
    async fn read_at(&mut self, off: u64, buf: &mut [u8]) -> Result<(), StorageError>;

    /// Backing size in bytes (geometry derivation).
    fn capacity(&self) -> u64;
}

/// Writable disc data plane: asynchronous mirror of
/// [`crate::seekable_storage::WritableFlatData`] — [`AsyncFlatData`] plus
/// offset-addressed write and persist.
#[allow(async_fn_in_trait)]
pub trait AsyncWritableFlatData: AsyncFlatData {
    /// Write `buf.len()` bytes at `off`. Same bounds contract as
    /// [`AsyncFlatData::read_at`].
    ///
    /// Convention: reject *policy* read-only states with
    /// [`StorageError::NotWritable`] — never a bare I/O error — so devices can
    /// surface DATA PROTECT instead of WRITE FAULT.
    async fn write_at(&mut self, off: u64, buf: &[u8]) -> Result<(), StorageError>;

    /// Persist pending writes beyond page cache (`fsync` semantics).
    async fn sync(&mut self) -> Result<(), StorageError>;

    /// Fill `len` bytes at `off` with `byte`.
    ///
    /// Default: bounds-check against [`AsyncFlatData::capacity`] (rejecting an
    /// `off + len` overflow and a past-capacity range with
    /// [`StorageError::OutOfBounds`]) then loop [`Self::write_at`] over a
    /// 512-byte stack chunk — no `alloc`. After each block the default body
    /// yields once via [`yield_now`], so a backend that completes writes
    /// synchronously does not monopolise the executor across a whole-disc
    /// fill. Backends with a cheaper primitive override: `RamBackend` uses
    /// `memset`; syscall-backed stores may use a larger chunk to amortise
    /// syscalls.
    async fn fill_at(&mut self, mut off: u64, mut len: u64, byte: u8) -> Result<(), StorageError> {
        let end = off.checked_add(len).ok_or(StorageError::OutOfBounds)?;
        if end > self.capacity() {
            return Err(StorageError::OutOfBounds);
        }
        let chunk = [byte; FILL_CHUNK];
        while len > 0 {
            let n = core::cmp::min(len, FILL_CHUNK as u64) as usize;
            self.write_at(off, &chunk[..n]).await?;
            off += n as u64;
            len -= n as u64;
            yield_now().await;
        }
        Ok(())
    }
}

// The RAM backend satisfies the asynchronous planes by delegating to the
// synchronous ones: its slice is always resident, so no call ever waits, and a
// single body per operation avoids drift between the two seams.
impl AsyncFlatData for RamBackend<'_> {
    async fn read_at(&mut self, off: u64, buf: &mut [u8]) -> Result<(), StorageError> {
        FlatData::read_at(self, off, buf)
    }

    fn capacity(&self) -> u64 {
        FlatData::capacity(self)
    }
}

impl AsyncWritableFlatData for RamBackend<'_> {
    async fn write_at(&mut self, off: u64, buf: &[u8]) -> Result<(), StorageError> {
        WritableFlatData::write_at(self, off, buf)
    }

    async fn sync(&mut self) -> Result<(), StorageError> {
        WritableFlatData::sync(self)
    }

    /// `memset` — the synchronous bounds-checked fill reaches
    /// [`SeekableStorage::fill_at`](crate::seekable_storage::SeekableStorage::fill_at)
    /// and fills the slice in one go: no chunk loop, no yield.
    async fn fill_at(&mut self, off: u64, len: u64, byte: u8) -> Result<(), StorageError> {
        WritableFlatData::fill_at(self, off, len, byte)
    }
}

// The all-zero backend likewise satisfies the asynchronous planes by
// delegating to the synchronous ones: reads never wait (they synthesise
// zeros) and writes are discarded, so a single body per operation avoids
// drift between the two seams.
impl AsyncFlatData for ZeroBackend {
    async fn read_at(&mut self, off: u64, buf: &mut [u8]) -> Result<(), StorageError> {
        FlatData::read_at(self, off, buf)
    }

    fn capacity(&self) -> u64 {
        FlatData::capacity(self)
    }
}

impl AsyncWritableFlatData for ZeroBackend {
    async fn write_at(&mut self, off: u64, buf: &[u8]) -> Result<(), StorageError> {
        WritableFlatData::write_at(self, off, buf)
    }

    async fn sync(&mut self) -> Result<(), StorageError> {
        WritableFlatData::sync(self)
    }

    /// Writes are discarded, so the synchronous bounds-checked fill is a
    /// bounds check only: no chunk loop, no yield.
    async fn fill_at(&mut self, off: u64, len: u64, byte: u8) -> Result<(), StorageError> {
        WritableFlatData::fill_at(self, off, len, byte)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

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
    fn yield_now_completes() {
        block_on(yield_now());
    }

    #[test]
    fn ram_async_roundtrip_and_capacity() {
        let mut ram = [0u8; 512];
        let mut b = RamBackend::new(&mut ram);
        block_on(async {
            assert_eq!(AsyncFlatData::capacity(&b), 512);
            AsyncWritableFlatData::write_at(&mut b, 100, &[1, 2, 3, 4])
                .await
                .unwrap();
            let mut out = [0u8; 4];
            AsyncFlatData::read_at(&mut b, 100, &mut out).await.unwrap();
            assert_eq!(out, [1, 2, 3, 4]);
            // Past capacity and `off + len` overflow both reject.
            assert_eq!(
                AsyncFlatData::read_at(&mut b, 510, &mut out).await,
                Err(StorageError::OutOfBounds)
            );
            assert_eq!(
                AsyncWritableFlatData::write_at(&mut b, u64::MAX, &[0]).await,
                Err(StorageError::OutOfBounds)
            );
            AsyncWritableFlatData::sync(&mut b).await.unwrap();
        });
    }

    #[test]
    fn ram_async_fill_is_memset_and_bounds_checked() {
        let mut ram = [0xFFu8; 64];
        let mut b = RamBackend::new(&mut ram);
        block_on(async {
            AsyncWritableFlatData::fill_at(&mut b, 8, 16, 0)
                .await
                .unwrap();
            assert_eq!(
                AsyncWritableFlatData::fill_at(&mut b, 60, 8, 0).await,
                Err(StorageError::OutOfBounds)
            );
            assert_eq!(
                AsyncWritableFlatData::fill_at(&mut b, u64::MAX, 2, 0).await,
                Err(StorageError::OutOfBounds)
            );
        });
        assert!(ram[..8].iter().all(|&x| x == 0xFF));
        assert!(ram[8..24].iter().all(|&x| x == 0));
        assert!(ram[24..].iter().all(|&x| x == 0xFF));
    }

    #[test]
    fn default_fill_loops_over_chunks() {
        // A direct impl (not reached through `SeekableStorage`) exercises the
        // default `fill_at` loop, which chunks over `write_at` — here spanning
        // more than one 512-byte `FILL_CHUNK` — and yields after each block.
        struct Mem([u8; 1500]);
        impl AsyncFlatData for Mem {
            async fn read_at(&mut self, off: u64, buf: &mut [u8]) -> Result<(), StorageError> {
                let s = off as usize;
                buf.copy_from_slice(&self.0[s..s + buf.len()]);
                Ok(())
            }
            fn capacity(&self) -> u64 {
                self.0.len() as u64
            }
        }
        impl AsyncWritableFlatData for Mem {
            async fn write_at(&mut self, off: u64, buf: &[u8]) -> Result<(), StorageError> {
                let s = off as usize;
                self.0[s..s + buf.len()].copy_from_slice(buf);
                Ok(())
            }
            async fn sync(&mut self) -> Result<(), StorageError> {
                Ok(())
            }
        }

        let mut m = Mem([0u8; 1500]);
        block_on(async {
            m.fill_at(0, 1500, 0x7E).await.unwrap(); // 512 + 512 + 476
            assert_eq!(m.fill_at(1499, 2, 0).await, Err(StorageError::OutOfBounds));
            assert_eq!(
                m.fill_at(u64::MAX, 2, 0).await,
                Err(StorageError::OutOfBounds)
            );
        });
        assert!(m.0.iter().all(|&x| x == 0x7E));
    }

    #[test]
    fn zero_async_read_write_and_capacity() {
        let mut b = ZeroBackend::new(512);
        block_on(async {
            assert_eq!(AsyncFlatData::capacity(&b), 512);
            // Write is accepted and discarded; a subsequent read is zeros.
            AsyncWritableFlatData::write_at(&mut b, 100, &[1, 2, 3, 4])
                .await
                .unwrap();
            let mut out = [0xAAu8; 4];
            AsyncFlatData::read_at(&mut b, 100, &mut out).await.unwrap();
            assert_eq!(out, [0, 0, 0, 0]);
            // Past capacity and `off + len` overflow both reject.
            assert_eq!(
                AsyncFlatData::read_at(&mut b, 510, &mut out).await,
                Err(StorageError::OutOfBounds)
            );
            assert_eq!(
                AsyncWritableFlatData::write_at(&mut b, u64::MAX, &[0]).await,
                Err(StorageError::OutOfBounds)
            );
            AsyncWritableFlatData::sync(&mut b).await.unwrap();
        });
    }

    #[test]
    fn zero_async_fill_is_discarded_and_bounds_checked() {
        let mut b = ZeroBackend::new(64);
        block_on(async {
            AsyncWritableFlatData::fill_at(&mut b, 8, 16, 0x5A)
                .await
                .unwrap();
            assert_eq!(
                AsyncWritableFlatData::fill_at(&mut b, 60, 8, 0).await,
                Err(StorageError::OutOfBounds)
            );
            assert_eq!(
                AsyncWritableFlatData::fill_at(&mut b, u64::MAX, 2, 0).await,
                Err(StorageError::OutOfBounds)
            );
            let mut out = [0xAAu8; 16];
            AsyncFlatData::read_at(&mut b, 8, &mut out).await.unwrap();
            assert!(out.iter().all(|&x| x == 0));
        });
    }
}
