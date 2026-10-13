//! Filesystem storage seam for CD-ROM bundle / live FS devices.
//!
//! [`FsStorage`] models a file/directory abstraction that embedded callers
//! implement (littlefs, FatFs, etc.). The std implementation
//! (`StdFsBackend`, not linked here: it lives in another crate,
//! `snowscsi::scsi::fs_backend`).

use embedded_io::ErrorKind as IoErrorKind;

/// Directory entry returned by [`FsStorage::read_dir`].
#[derive(Debug, Clone)]
pub struct DirEntry {
    /// File or directory name (no path separator).
    pub name: heapless::String<256>,
    /// `true` if this entry is a directory.
    pub is_dir: bool,
    /// Size in bytes (0 for directories).
    pub size: u64,
}

/// Filesystem access error (`no_std`, `core::error::Error`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FsError {
    /// File or directory not found.
    NotFound,
    /// Read/write past end of file.
    OutOfBounds,
    /// Write attempted on a read-only handle.
    NotWritable,
    /// Underlying I/O failure (mapped from `embedded_io::ErrorKind`).
    Io(IoErrorKind),
}

impl core::fmt::Display for FsError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::NotFound => write!(f, "file or directory not found"),
            Self::OutOfBounds => write!(f, "access past end of file"),
            Self::NotWritable => write!(f, "file is read-only"),
            Self::Io(kind) => write!(f, "filesystem I/O error: {kind:?}"),
        }
    }
}

impl core::error::Error for FsError {}

/// Options for [`FsStorage::open`].
///
/// Mirrors the no_std subset of `std::fs::OpenOptions`.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct OpenOptions {
    pub read: bool,
    pub write: bool,
    pub create: bool,
    pub truncate: bool,
}

impl OpenOptions {
    /// Read-only probe — file must exist.
    pub const fn read_only() -> Self {
        Self {
            read: true,
            write: false,
            create: false,
            truncate: false,
        }
    }

    /// Open existing or create; read-write, no truncate.
    pub const fn open_or_create() -> Self {
        Self {
            read: true,
            write: true,
            create: true,
            truncate: false,
        }
    }

    /// Open an **existing** file read-write (no create, no truncate).
    ///
    /// Used by read-write bundles so every cached chunk handle is writable:
    /// a read must never cache a handle that a later write cannot use.
    pub const fn read_write() -> Self {
        Self {
            read: true,
            write: true,
            create: false,
            truncate: false,
        }
    }

    /// Create or truncate; read-write.
    pub const fn create_or_truncate() -> Self {
        Self {
            read: true,
            write: true,
            create: true,
            truncate: true,
        }
    }
}

/// Filesystem storage backend.
///
/// Namespace operations (open / close / read_dir / remove / sync) stay on
/// the backend. **Byte-level** read/write/seek moves to the associated
/// [`File`](FsStorage::File) type — each opened file is an independent
/// `embedded_io::Read + Write + Seek` stream.
pub trait FsStorage {
    /// Each opened file is a seekable byte stream.
    type File: embedded_io::Read + embedded_io::Write + embedded_io::Seek;

    /// Open a file at `path` with the given `opts`.
    fn open(&mut self, path: &str, opts: OpenOptions) -> Result<Self::File, FsError>;

    /// Close a file (embedded-io has no close; lifecycle managed by FsStorage).
    fn close(&mut self, file: Self::File);

    /// Scan a directory, returning all entries (including sub-directories).
    ///
    /// # Truncation semantics
    ///
    /// At most `out.len()` entries are written. The return value is the
    /// number written (`<= out.len()`); **`ret == out.len()` does NOT
    /// imply the directory was exhausted** — there may be more entries.
    /// Callers that must not lose entries MUST treat a full buffer as
    /// "directory too large" and fail loudly (the in-tree live-FS
    /// scanner returns `CdLiveFsError::DirTooLarge` in that case).
    /// Silently continuing with a full buffer drops files.
    ///
    /// # Stack budget (embedded callers)
    ///
    /// Each [`DirEntry`] is ~280 bytes on a 32-bit target
    /// (`String<256>` + `is_dir` + `u64 size`, aligned). Size the batch
    /// to your stack: 16 ≈ 4.5 KB, 32 ≈ 9 KB, 128 ≈ 36 KB. Batch into a
    /// per-directory loop if your FS seam allows re-scanning; do not
    /// default to `[DirEntry; MAX_FILES]`.
    fn read_dir(&mut self, path: &str, out: &mut [DirEntry]) -> Result<usize, FsError>;

    /// Root directory absolute path (for ISO9660 path table).
    fn root(&self) -> &str;

    /// Persist the entire filesystem.
    fn sync(&mut self) -> Result<(), FsError>;

    /// Remove a file (BLANK / orphan track cleanup).
    fn remove(&mut self, path: &str) -> Result<(), FsError>;
}
