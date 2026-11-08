//! Asynchronous filesystem seam, mirroring [`crate::fs_storage`].
//!
//! [`AsyncFsStorage`] is the `async fn` mirror of
//! [`FsStorage`](crate::fs_storage::FsStorage): a namespace backend
//! (`open`/`close`/`read_dir`/`sync`/`remove`) plus per-file byte access
//! through an owned [`AsyncFsFile`] handle. It exists so a bundle can be
//! served on an executor without blocking it on filesystem I/O.
//!
//! # Offset-addressed files, no cursor
//!
//! An [`AsyncFsFile`] has no seek: every byte operation names its offset
//! ([`AsyncFsFile::read_at`] / [`AsyncFsFile::write_at`]). This keeps a file
//! usable from one chunk-table slot while the bundle juggles several files,
//! and it matches the offset-addressed [`AsyncFlatData`] seam the bundle
//! implements.
//!
//! # Explicit lifecycle
//!
//! [`AsyncFsStorage::close`] is `async`: a filesystem may need to wait for a
//! pending write before releasing a handle. There is no RAII close, so:
//!
//! - [`crate::async_flat_bundle::AsyncFlatBundle`] does **not** implement
//!   `Drop`; dropping it only drops the handles. Call
//!   [`crate::async_flat_bundle::AsyncFlatBundle::shutdown`] (or at least
//!   `sync`, for writable media) to flush and close deterministically.
//! - A handle stored in a chunk table must be **owned**, not borrow
//!   `&mut self`. The associated type has no lifetime parameter, so an
//!   implementation cannot tie `Self::File` to the backend borrow; use an
//!   owned fd/struct (clone an `Arc`, open a fresh descriptor, etc.).
//!
//! # No sync blanket impl
//!
//! There is deliberately no blanket `impl<T: FsStorage> AsyncFsStorage for T`:
//! it would silently run blocking I/O inside an `async fn`, which is exactly
//! what this seam exists to avoid. An application that wants to bridge a
//! blocking backend should use a runtime-specific adapter that moves the work
//! to a blocking pool.
//!
//! [`AsyncFlatData`]: crate::async_seekable_storage::AsyncFlatData

use crate::fs_storage::{DirEntry, FsError, OpenOptions};

/// One open asynchronous file, addressed by explicit offsets.
///
/// A handle owns its file: it must not borrow the backend (see the module
/// documentation). `read_at`/`write_at` may transfer fewer bytes than
/// requested; the caller loops. A read returning `0` means end-of-file.
// `len` is an offset/geometry query, not a container length: there is no
// meaningful separate `is_empty` operation on a file handle.
#[allow(clippy::len_without_is_empty)]
#[allow(async_fn_in_trait)]
pub trait AsyncFsFile {
    /// Read from `off`, returning the number of bytes read (`0` at EOF).
    ///
    /// Unlike the bundle's logical plane, this is the **physical** file view:
    /// a read past physical EOF is a short read, not an error.
    async fn read_at(&mut self, off: u64, buf: &mut [u8]) -> Result<usize, FsError>;

    /// Write at `off`, returning the number of bytes written.
    ///
    /// An implementation returns [`FsError::NotWritable`] when the handle was
    /// opened without write access. A return of `0` is treated as an I/O
    /// failure by [`crate::async_flat_bundle::AsyncFlatBundle`].
    async fn write_at(&mut self, off: u64, buf: &[u8]) -> Result<usize, FsError>;

    /// Flush this file's data and metadata (`fsync` semantics).
    async fn flush(&mut self) -> Result<(), FsError>;

    /// Current physical file length in bytes.
    async fn len(&mut self) -> Result<u64, FsError>;
}

/// Asynchronous filesystem backend.
///
/// The root supplied by [`Self::root`] **is** the bundle directory: chunk
/// files and `SNOWBUNDLE` are opened by relative path from it.
#[allow(async_fn_in_trait)]
pub trait AsyncFsStorage {
    /// Owned byte-stream handle.
    type File: AsyncFsFile;

    /// Open `path` with `opts`.
    async fn open(&mut self, path: &str, opts: OpenOptions) -> Result<Self::File, FsError>;

    /// Close and release `path`'s handle.
    ///
    /// Explicit and asynchronous: the bundle calls it on LRU eviction and in
    /// `shutdown`, and never from a destructor.
    async fn close(&mut self, file: Self::File) -> Result<(), FsError>;

    /// Scan a directory into `out`, returning the number written.
    ///
    /// Same truncation contract as
    /// [`FsStorage::read_dir`](crate::fs_storage::FsStorage::read_dir): a
    /// full buffer does **not** imply the directory was exhausted.
    async fn read_dir(&mut self, path: &str, out: &mut [DirEntry]) -> Result<usize, FsError>;

    /// Root directory path (the bundle directory).
    fn root(&self) -> &str;

    /// Persist the whole filesystem.
    async fn sync(&mut self) -> Result<(), FsError>;

    /// Persist one file's data and metadata to stable storage.
    ///
    /// The default falls back to the backend-wide [`Self::sync`]. Override it
    /// when the backend can fsync a single path without flushing everything.
    async fn sync_file(&mut self, path: &str) -> Result<(), FsError> {
        let _ = path;
        self.sync().await
    }

    /// Remove a file.
    async fn remove(&mut self, path: &str) -> Result<(), FsError>;
}
