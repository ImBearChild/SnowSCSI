//! FlatBundle: directory-chunked block-device plane.
//!
//! A [`FlatBundle<F>`] splits one logical block device into fixed-size chunk
//! files (`{:06}.img`) stored in a plain filesystem directory through the
//! [`FsStorage`] seam — no proprietary binary format, on-demand physical
//! allocation, and the FAT32 4 GiB limit is sidestepped per chunk.
//!
//! Design notes:
//! - **`FsStorage` root = the bundle directory.** Chunks and the manifest are
//!   opened by relative path (`"000000.img"`, `"SNOWBUNDLE"`) from the root,
//!   same as `LiveData`'s scanner. The bundle holds **no `dir` field**.
//! - The bundle implements [`FlatData`] (read) + [`WritableFlatData`]
//!   (write+sync) directly — it deliberately does **not** implement
//!   [`SeekableStorage`](crate::seekable_storage::SeekableStorage) (no embedded-io cursor semantics; addressing is explicit
//!   via the `off` argument).
//! - **Sparse/hole semantics:** a chunk file only extends to the highest byte
//!   ever written. The read path treats physical EOF inside a chunk as a hole
//!   and zero-fills it; it never surfaces `UnexpectedEof` as an error (which
//!   the SCSI layer would map to READ ERROR). Missing chunks are zero-filled
//!   too, and are only probed read-only (a hole read never creates a file).
//! - **Best-effort `sync`:** the chunk slot keeps only an index, and this type
//!   knows the path through `chunk_path(idx)`, but it deliberately relies on the
//!   backend-wide [`FsStorage::sync`]: it flushes every open handle and then
//!   syncs the filesystem. Per-chunk [`FsStorage::sync_file`] is not used here.
//!
//! # Feature gating
//!
//! The core struct + read/write path are compiled unconditionally (and stay
//! `no_std`-clean). The manifest handling ([`FlatBundle::create`],
//! [`FlatBundle::create_with_meta`], [`FlatBundle::open`]) is gated behind the
//! `bundle` feature. The manifest itself is the shared canonical
//! [`crate::bundle`] format (`SNOWBUNDLE`, `kind = flat`); the cipher/keyslot
//! block is preserved but not interpreted here — the cipher decorator owns
//! it.

use embedded_io::Error as _;
use embedded_io::ErrorKind as IoErrorKind;
use heapless::Vec as HeaplessVec;

#[cfg(feature = "bundle")]
use crate::bundle::{BundleKind, MANIFEST_NAME, MAX_MANIFEST};
use crate::bundle::{BundleMeta, ManifestError};
use crate::fs_storage::{FsError, FsStorage, OpenOptions};
use crate::seekable_storage::{FlatData, StorageError, WritableFlatData};

/// Default chunk size when the manifest is absent (100 MiB).
pub const DEFAULT_CHUNK_SIZE: u64 = 100 * 1024 * 1024;

/// Header file name used before the `SNOWBUNDLE` format. Only probed to
/// refuse a silent reinterpretation of an old directory.
///
/// Shared with the asynchronous [`crate::async_flat_bundle`] open/create paths
/// so both reject a legacy directory identically.
#[cfg(feature = "bundle")]
pub(crate) const LEGACY_HEADER_NAME: &str = "BUNDLE";

/// Maximum number of simultaneously-open chunk file handles (LRU bound).
pub const MAX_OPEN_CHUNKS: usize = 8;

/// Maximum number of addressable chunks (`{:06}.img` → 6 digits).
const MAX_CHUNKS: u64 = 999_999;

/// `FlatBundle` construction/geometry/manifest errors.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BundleError {
    /// Underlying filesystem failure.
    Fs(FsError),
    /// The `SNOWBUNDLE` manifest is malformed.
    Manifest(ManifestError),
    /// The manifest parsed but describes a non-flat bundle.
    WrongKind,
    /// `FlatBundle::create` on a directory that already has a manifest.
    AlreadyExists,
    /// The directory carries the legacy `BUNDLE` header from an older format.
    /// It is refused rather than reinterpreted with new geometry.
    LegacyHeader,
    /// No manifest and no caller-supplied `virtual_size`.
    MissingVirtualSize,
    /// Geometry rejected (`chunk_size`/`virtual_size`/`sector_size` alignment,
    /// zero, or chunk-count overflow). See `validate_geometry`.
    InvalidGeometry,
    /// A keyslot-bearing manifest cannot be written through this
    /// non-atomic library path; the application must write it atomically.
    CipherRequiresAtomicManifest,
}

impl core::fmt::Display for BundleError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::Fs(e) => write!(f, "filesystem error: {e}"),
            Self::Manifest(e) => write!(f, "manifest error: {e}"),
            Self::WrongKind => write!(f, "not a flat bundle"),
            Self::AlreadyExists => write!(f, "SNOWBUNDLE manifest already exists"),
            Self::LegacyHeader => write!(
                f,
                "legacy BUNDLE header found; recreate the bundle in the current format"
            ),
            Self::MissingVirtualSize => {
                write!(f, "virtual_size required (no SNOWBUNDLE manifest)")
            }
            Self::InvalidGeometry => write!(f, "invalid bundle geometry"),
            Self::CipherRequiresAtomicManifest => write!(
                f,
                "keyslot-bearing manifests must be written atomically by the application"
            ),
        }
    }
}

impl core::error::Error for BundleError {}

impl From<FsError> for BundleError {
    fn from(e: FsError) -> Self {
        Self::Fs(e)
    }
}

impl From<ManifestError> for BundleError {
    fn from(e: ManifestError) -> Self {
        Self::Manifest(e)
    }
}

/// One open chunk file handle (LRU slot).
struct ChunkSlot<F: FsStorage> {
    idx: u64,
    file: F::File,
    last_used: u64,
}

/// Directory-chunked, random-writable block plane over an [`FsStorage`].
///
/// `F`'s root **is** the bundle directory: chunks are
/// `"{:06}.img"` relative to it, the optional manifest is `"SNOWBUNDLE"`.
pub struct FlatBundle<F: FsStorage> {
    fs: F,
    chunk_size: u64,
    virtual_size: u64,
    sector_size: u32,
    /// Read-only mode: `write_at` returns [`StorageError::NotWritable`]
    /// and chunk files are opened read-only. The data plane and the device
    /// policy must agree (read-only media cannot even be opened `r+b`).
    read_only: bool,
    /// Parsed manifest, or `None` when the plane was built from explicit
    /// geometry only.
    meta: Option<BundleMeta>,
    open_chunks: HeaplessVec<ChunkSlot<F>, MAX_OPEN_CHUNKS>,
    tick: u64,
}

impl<F: FsStorage> FlatBundle<F> {
    /// Construct a read-write bundle with explicit geometry (no manifest I/O).
    ///
    /// `fs` must be rooted at the bundle directory; the directory must already
    /// exist (the `FsStorage` seam has no `mkdir` — host callers create it).
    /// Validates geometry at construction time.
    pub fn new(
        fs: F,
        chunk_size: u64,
        virtual_size: u64,
        sector_size: u32,
    ) -> Result<Self, BundleError> {
        Self::build(fs, chunk_size, virtual_size, sector_size, false)
    }

    /// Construct a **read-only** bundle with explicit geometry.
    ///
    /// Same as [`Self::new`], but the plane rejects every write with
    /// [`StorageError::NotWritable`] and opens chunk files read-only, so
    /// it works on read-only media (read-only filesystem / mount) where even
    /// `r+b` would fail.
    pub fn new_read_only(
        fs: F,
        chunk_size: u64,
        virtual_size: u64,
        sector_size: u32,
    ) -> Result<Self, BundleError> {
        Self::build(fs, chunk_size, virtual_size, sector_size, true)
    }

    fn build(
        fs: F,
        chunk_size: u64,
        virtual_size: u64,
        sector_size: u32,
        read_only: bool,
    ) -> Result<Self, BundleError> {
        validate_geometry(chunk_size, virtual_size, sector_size)?;
        Ok(Self {
            fs,
            chunk_size,
            virtual_size,
            sector_size,
            read_only,
            meta: None,
            open_chunks: HeaplessVec::new(),
            tick: 0,
        })
    }

    /// Manifest this bundle was opened/created from, when one was involved.
    ///
    /// A bundle constructed with [`Self::new`]/[`Self::new_read_only`] has no
    /// manifest and returns `None`.
    pub fn meta(&self) -> Option<&BundleMeta> {
        self.meta.as_ref()
    }

    /// Whether this bundle is read-only (`write_at` → `NotWritable`).
    pub fn is_read_only(&self) -> bool {
        self.read_only
    }

    /// Logical device size in bytes (equals `virtual_size`).
    pub fn capacity(&self) -> u64 {
        self.virtual_size
    }

    /// Chunk size in bytes.
    pub fn chunk_size(&self) -> u64 {
        self.chunk_size
    }

    /// Sector size (geometry, `512` or `2048`).
    pub fn sector_size(&self) -> u32 {
        self.sector_size
    }

    /// Create a new flat bundle with the given geometry.
    ///
    /// Builds a plaintext [`BundleKind::Flat`] manifest and delegates to
    /// [`Self::create_with_meta`]; see there for the manifest/failure rules.
    #[cfg(feature = "bundle")]
    pub fn create(
        fs: F,
        chunk_size: u64,
        virtual_size: u64,
        sector_size: u32,
    ) -> Result<Self, BundleError> {
        let meta = BundleMeta {
            kind: BundleKind::Flat {
                virtual_size,
                chunk_size,
                sector_size,
            },
            cipher: None,
            has_crc: false,
        };
        Self::create_with_meta(fs, &meta)
    }

    /// Create a new bundle from an explicit manifest.
    ///
    /// Only [`BundleKind::Flat`] is accepted ([`BundleError::WrongKind`]).
    /// Fails with [`BundleError::AlreadyExists`] if a `SNOWBUNDLE` manifest is
    /// already present (prevents accidental overwrite). The manifest is
    /// written with `create_or_truncate`, flushed, closed and the filesystem
    /// synced. Chunk 0 is not pre-allocated; the first write creates it.
    ///
    /// The manifest is written directly through [`FsStorage`], which has no
    /// rename/atomic-replace operation. This is suitable for plaintext
    /// manifests and library tests; an application that stores a keyslot
    /// (the CLI, for example) must write the manifest atomically itself and
    /// then open the bundle with [`Self::open`], because a torn keyslot
    /// manifest is the only copy of the volume master key.
    #[cfg(feature = "bundle")]
    pub fn create_with_meta(mut fs: F, meta: &BundleMeta) -> Result<Self, BundleError> {
        let (chunk_size, virtual_size, sector_size, manifest) = prepare_create(meta)?;
        match fs.open(MANIFEST_NAME, OpenOptions::read_only()) {
            Ok(file) => {
                fs.close(file);
                return Err(BundleError::AlreadyExists);
            }
            Err(FsError::NotFound) => {}
            Err(e) => return Err(BundleError::Fs(e)),
        }
        // A legacy directory must not be silently given new geometry: its
        // chunk files were written with the old header's chunk size.
        match fs.open(LEGACY_HEADER_NAME, OpenOptions::read_only()) {
            Ok(file) => {
                fs.close(file);
                return Err(BundleError::LegacyHeader);
            }
            Err(FsError::NotFound) => {}
            Err(e) => return Err(BundleError::Fs(e)),
        }
        let mut file = fs
            .open(MANIFEST_NAME, OpenOptions::create_or_truncate())
            .map_err(BundleError::Fs)?;
        embedded_io::Write::write_all(&mut file, &manifest)
            .map_err(|e| BundleError::Fs(FsError::Io(e.kind())))?;
        embedded_io::Write::flush(&mut file).map_err(|e| BundleError::Fs(FsError::Io(e.kind())))?;
        fs.close(file);
        fs.sync().map_err(BundleError::Fs)?;
        let mut bundle = Self::build(fs, chunk_size, virtual_size, sector_size, false)?;
        // `encode` always emits a CRC line, so the stored metadata reflects
        // what a re-open would parse.
        let mut stored = *meta;
        stored.has_crc = true;
        bundle.meta = Some(stored);
        Ok(bundle)
    }

    /// Open an existing (or manifest-less) bundle, merging the `SNOWBUNDLE`
    /// manifest with caller overrides (caller wins per-field).
    ///
    /// - `chunk_override` / `size_override` / `sector_override`: optional
    ///   caller values that override the manifest (or fill in for a missing
    ///   manifest).
    /// - A present manifest must be a [`BundleKind::Flat`] bundle, otherwise
    ///   [`BundleError::WrongKind`].
    /// - A missing manifest with no `size_override` yields
    ///   [`BundleError::MissingVirtualSize`].
    #[cfg(feature = "bundle")]
    pub fn open(
        fs: F,
        chunk_override: Option<u64>,
        size_override: Option<u64>,
        sector_override: Option<u32>,
    ) -> Result<Self, BundleError> {
        Self::open_impl(fs, chunk_override, size_override, sector_override, false)
    }

    /// Like [`Self::open`], but read-only: no header is created and every
    /// write is rejected with [`StorageError::NotWritable`]. Use for
    /// bundles on read-only media.
    #[cfg(feature = "bundle")]
    pub fn open_read_only(
        fs: F,
        chunk_override: Option<u64>,
        size_override: Option<u64>,
        sector_override: Option<u32>,
    ) -> Result<Self, BundleError> {
        Self::open_impl(fs, chunk_override, size_override, sector_override, true)
    }

    #[cfg(feature = "bundle")]
    fn open_impl(
        mut fs: F,
        chunk_override: Option<u64>,
        size_override: Option<u64>,
        sector_override: Option<u32>,
        read_only: bool,
    ) -> Result<Self, BundleError> {
        let mut meta = None;
        match fs.open(MANIFEST_NAME, OpenOptions::read_only()) {
            Ok(mut f) => {
                let mut data = HeaplessVec::<u8, MAX_MANIFEST>::new();
                let mut tmp = [0u8; 64];
                loop {
                    let n = match embedded_io::Read::read(&mut f, &mut tmp) {
                        Ok(n) => n,
                        Err(e) => {
                            fs.close(f);
                            return Err(BundleError::Fs(FsError::Io(e.kind())));
                        }
                    };
                    if n == 0 {
                        break;
                    }
                    if data.extend_from_slice(&tmp[..n]).is_err() {
                        fs.close(f);
                        return Err(BundleError::Manifest(ManifestError::TooLarge));
                    }
                }
                fs.close(f);
                meta = Some(BundleMeta::parse(&data)?);
            }
            Err(FsError::NotFound) => {
                // Never reinterpret an old bundle with new geometry: its
                // chunk files use the legacy header's chunk size.
                match fs.open(LEGACY_HEADER_NAME, OpenOptions::read_only()) {
                    Ok(file) => {
                        fs.close(file);
                        return Err(BundleError::LegacyHeader);
                    }
                    Err(FsError::NotFound) => {}
                    Err(e) => return Err(BundleError::Fs(e)),
                }
            }
            Err(e) => return Err(BundleError::Fs(e)),
        }
        let (chunk_size, virtual_size, sector_size) = resolve_geometry(
            meta.as_ref(),
            chunk_override,
            size_override,
            sector_override,
        )?;
        let mut bundle = Self::build(fs, chunk_size, virtual_size, sector_size, read_only)?;
        bundle.meta = meta;
        Ok(bundle)
    }

    /// Relative path of chunk `idx` within the bundle directory.
    fn chunk_path(&self, idx: u64) -> heapless::String<16> {
        chunk_path(idx)
    }

    /// Ensure a slot for chunk `idx` is open, returning its index in
    /// `open_chunks`. Opens read-only (`create = false`, returns `None` if the
    /// chunk is absent) or open-or-create (`create = true`). Evicts the
    /// least-recently-used slot when at capacity.
    ///
    /// A **read-write** bundle opens reads `read_write()` as well, so every
    /// cached handle is writable and a read can never poison a later write
    /// (writing a read-only fd is `EBADF`). A **read-only** bundle opens
    /// everything `read_only()` and never reaches the `create` path.
    fn ensure_chunk(&mut self, idx: u64, create: bool) -> Result<Option<usize>, FsError> {
        if let Some(i) = self.open_chunks.iter().position(|s| s.idx == idx) {
            self.open_chunks[i].last_used = self.tick;
            self.tick = self.tick.wrapping_add(1);
            return Ok(Some(i));
        }
        let opts = if create {
            OpenOptions::open_or_create()
        } else if self.read_only {
            OpenOptions::read_only()
        } else {
            OpenOptions::read_write()
        };
        let path = self.chunk_path(idx);
        let file = match self.fs.open(path.as_str(), opts) {
            Ok(f) => f,
            Err(FsError::NotFound) if !create => return Ok(None),
            Err(e) => return Err(e),
        };
        self.evict_one();
        self.open_chunks
            .push(ChunkSlot {
                idx,
                file,
                last_used: self.tick,
            })
            .map_err(|_| FsError::Io(IoErrorKind::Other))?;
        self.tick = self.tick.wrapping_add(1);
        Ok(Some(self.open_chunks.len() - 1))
    }

    /// Evict the least-recently-used chunk slot (when at capacity), closing its
    /// handle via `FsStorage::close`.
    fn evict_one(&mut self) {
        if self.open_chunks.len() < MAX_OPEN_CHUNKS {
            return;
        }
        let mut min_i = 0;
        for i in 1..self.open_chunks.len() {
            if self.open_chunks[i].last_used < self.open_chunks[min_i].last_used {
                min_i = i;
            }
        }
        let slot = self.open_chunks.swap_remove(min_i);
        self.fs.close(slot.file);
    }
}

impl<F: FsStorage> Drop for FlatBundle<F> {
    fn drop(&mut self) {
        // Close every open chunk handle (the `FsStorage` seam owns close).
        while let Some(slot) = self.open_chunks.pop() {
            self.fs.close(slot.file);
        }
    }
}

impl<F: FsStorage> FlatData for FlatBundle<F> {
    fn read_at(&mut self, off: u64, buf: &mut [u8]) -> Result<(), StorageError> {
        let end = off
            .checked_add(buf.len() as u64)
            .ok_or(StorageError::OutOfBounds)?;
        if end > self.virtual_size {
            return Err(StorageError::OutOfBounds);
        }
        let mut pos = off;
        let mut dst = buf;
        while !dst.is_empty() {
            let (idx, chunk_off, take) = chunk_span(pos, dst.len(), self.chunk_size);
            let (chunk_dst, rest) = dst.split_at_mut(take);
            match self.ensure_chunk(idx, false) {
                Ok(Some(i)) => {
                    let file = &mut self.open_chunks[i].file;
                    use embedded_io::{Read, Seek};
                    file.seek(embedded_io::SeekFrom::Start(chunk_off))
                        .map_err(|e| StorageError::Io(e.kind()))?;
                    // Zero-fill holes past physical EOF (never an error).
                    let mut sub = chunk_dst;
                    while !sub.is_empty() {
                        let n = file.read(sub).map_err(|e| StorageError::Io(e.kind()))?;
                        if n == 0 {
                            sub.fill(0);
                            break;
                        }
                        sub = &mut sub[n..];
                    }
                }
                Ok(None) => chunk_dst.fill(0),
                Err(e) => return Err(StorageError::from(e)),
            }
            pos += take as u64;
            dst = rest;
        }
        Ok(())
    }

    fn capacity(&self) -> u64 {
        self.virtual_size
    }
}

impl<F: FsStorage> WritableFlatData for FlatBundle<F> {
    fn write_at(&mut self, off: u64, buf: &[u8]) -> Result<(), StorageError> {
        if self.read_only {
            // Data-plane policy rejection; the device maps this to DATA PROTECT.
            return Err(StorageError::NotWritable);
        }
        let end = off
            .checked_add(buf.len() as u64)
            .ok_or(StorageError::OutOfBounds)?;
        if end > self.virtual_size {
            return Err(StorageError::OutOfBounds);
        }
        let mut pos = off;
        let mut src = buf;
        while !src.is_empty() {
            let (idx, chunk_off, take) = chunk_span(pos, src.len(), self.chunk_size);
            let (chunk_src, rest) = src.split_at(take);
            let i = self
                .ensure_chunk(idx, true)
                .map_err(StorageError::from)?
                .ok_or(StorageError::Io(IoErrorKind::Other))?;
            let file = &mut self.open_chunks[i].file;
            use embedded_io::Seek;
            file.seek(embedded_io::SeekFrom::Start(chunk_off))
                .map_err(|e| StorageError::Io(e.kind()))?;
            embedded_io::Write::write_all(file, chunk_src).map_err(|e| match e.kind() {
                IoErrorKind::PermissionDenied => StorageError::NotWritable,
                kind => StorageError::Io(kind),
            })?;
            pos += take as u64;
            src = rest;
        }
        Ok(())
    }

    fn sync(&mut self) -> Result<(), StorageError> {
        if self.read_only {
            // Nothing was ever written; nothing to flush.
            return Ok(());
        }
        for slot in self.open_chunks.iter_mut() {
            embedded_io::Write::flush(&mut slot.file).map_err(|e| StorageError::Io(e.kind()))?;
        }
        self.fs.sync().map_err(StorageError::from)?;
        Ok(())
    }
}

/// Validate bundle geometry.
///
/// Used by `FlatBundle` construction and by the CLI before it creates a
/// bundle directory, so invalid `--size`/`--chunk`/`--sector` values fail
/// without leaving an empty directory behind.
pub fn validate_geometry(
    chunk_size: u64,
    virtual_size: u64,
    sector_size: u32,
) -> Result<(), BundleError> {
    if chunk_size == 0 || virtual_size == 0 {
        return Err(BundleError::InvalidGeometry);
    }
    if sector_size != 512 && sector_size != 2048 {
        return Err(BundleError::InvalidGeometry);
    }
    if chunk_size < u64::from(sector_size) {
        return Err(BundleError::InvalidGeometry);
    }
    if !virtual_size.is_multiple_of(u64::from(sector_size)) {
        return Err(BundleError::InvalidGeometry);
    }
    let chunks = if virtual_size.is_multiple_of(chunk_size) {
        virtual_size / chunk_size
    } else {
        virtual_size / chunk_size + 1
    };
    if chunks > MAX_CHUNKS {
        return Err(BundleError::InvalidGeometry);
    }
    Ok(())
}

/// Relative path of chunk `idx` within a bundle directory (`{:06}.img`).
///
/// Shared by the synchronous [`FlatBundle`] and the asynchronous
/// [`crate::async_flat_bundle::AsyncFlatBundle`].
pub(crate) fn chunk_path(idx: u64) -> heapless::String<16> {
    let mut s = heapless::String::<16>::new();
    use core::fmt::Write as _;
    let _ = write!(s, "{:06}.img", idx);
    s
}

/// Split a logical position into `(chunk index, offset in chunk, take)`.
///
/// `take` is the number of bytes in the current chunk starting at `pos`, i.e.
/// `min(remaining, chunk_size - pos % chunk_size)`. Both bundles use this so a
/// read/write never spans a chunk file.
pub(crate) fn chunk_span(pos: u64, remaining: usize, chunk_size: u64) -> (u64, u64, usize) {
    let chunk_off = pos % chunk_size;
    let until_end = chunk_size - chunk_off;
    let take = if until_end >= remaining as u64 {
        remaining
    } else {
        until_end as usize
    };
    (pos / chunk_size, chunk_off, take)
}

/// Resolve bundle geometry from an optional manifest plus caller overrides.
///
/// Caller values win per field; a missing manifest falls back to
/// [`DEFAULT_CHUNK_SIZE`], no virtual size and 512-byte sectors. A present
/// non-flat manifest is [`BundleError::WrongKind`], and a zero virtual size
/// after merging is [`BundleError::MissingVirtualSize`].
///
/// Shared by the synchronous and asynchronous `open` paths.
#[cfg(feature = "bundle")]
pub(crate) fn resolve_geometry(
    meta: Option<&BundleMeta>,
    chunk_override: Option<u64>,
    size_override: Option<u64>,
    sector_override: Option<u32>,
) -> Result<(u64, u64, u32), BundleError> {
    let (manifest_chunk, manifest_virtual, manifest_sector) = match meta.map(|m| m.kind) {
        Some(BundleKind::Flat {
            virtual_size,
            chunk_size,
            sector_size,
        }) => (chunk_size, virtual_size, sector_size),
        Some(_) => return Err(BundleError::WrongKind),
        None => (DEFAULT_CHUNK_SIZE, 0, 512),
    };
    let chunk_size = chunk_override.unwrap_or(manifest_chunk);
    let virtual_size = size_override.unwrap_or(manifest_virtual);
    let sector_size = sector_override.unwrap_or(manifest_sector);
    if virtual_size == 0 {
        return Err(BundleError::MissingVirtualSize);
    }
    Ok((chunk_size, virtual_size, sector_size))
}

/// Validate and encode a manifest for bundle creation.
///
/// Returns `(chunk_size, virtual_size, sector_size, encoded_manifest)`. Only
/// [`BundleKind::Flat`] is accepted ([`BundleError::WrongKind`]); geometry is
/// validated with [`validate_geometry`]; a keyslot-bearing manifest is
/// refused with [`BundleError::CipherRequiresAtomicManifest`] because the
/// non-atomic library create path must not write the only copy of a VMK.
///
/// Shared by the synchronous and asynchronous `create_with_meta` paths.
#[cfg(feature = "bundle")]
pub(crate) fn prepare_create(
    meta: &BundleMeta,
) -> Result<(u64, u64, u32, HeaplessVec<u8, MAX_MANIFEST>), BundleError> {
    let (chunk_size, virtual_size, sector_size) = match meta.kind {
        BundleKind::Flat {
            virtual_size,
            chunk_size,
            sector_size,
        } => (chunk_size, virtual_size, sector_size),
        _ => return Err(BundleError::WrongKind),
    };
    validate_geometry(chunk_size, virtual_size, sector_size)?;
    if meta.cipher.is_some() {
        return Err(BundleError::CipherRequiresAtomicManifest);
    }
    let manifest = meta.encode()?;
    Ok((chunk_size, virtual_size, sector_size, manifest))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::fs_storage::DirEntry;
    use std::cell::RefCell;
    use std::collections::HashMap;
    use std::rc::Rc;

    // ── Shared in-memory FsStorage mock ─────────────────────────────────
    // common cannot see scsi's `StdFsBackend` (dependency direction), so unit
    // tests run against an in-memory store. The store is `Rc<RefCell<…>>` so
    // multiple bundles can share it and persistence after drop() is
    // observable directly.

    type Store = Rc<RefCell<HashMap<String, Rc<RefCell<Vec<u8>>>>>>;

    struct MockFs {
        store: Store,
    }

    impl MockFs {
        fn new() -> (Self, Store) {
            let store: Store = Rc::default();
            (
                Self {
                    store: Rc::clone(&store),
                },
                store,
            )
        }
    }

    struct MockFile {
        data: Rc<RefCell<Vec<u8>>>,
        pos: u64,
        writable: bool,
    }

    impl embedded_io::ErrorType for MockFile {
        type Error = IoErrorKind;
    }

    impl embedded_io::Read for MockFile {
        fn read(&mut self, buf: &mut [u8]) -> Result<usize, Self::Error> {
            let data = self.data.borrow();
            let start = self.pos as usize;
            if start >= data.len() {
                return Ok(0);
            }
            let n = buf.len().min(data.len() - start);
            buf[..n].copy_from_slice(&data[start..start + n]);
            self.pos += n as u64;
            Ok(n)
        }
    }

    impl embedded_io::Write for MockFile {
        fn write(&mut self, buf: &[u8]) -> Result<usize, Self::Error> {
            if !self.writable {
                // Models write(2) on a read-only fd (EBADF).
                return Err(IoErrorKind::Other);
            }
            let mut data = self.data.borrow_mut();
            let start = self.pos as usize;
            if start > data.len() {
                data.resize(start, 0);
            }
            let end = start + buf.len();
            if end > data.len() {
                data.resize(end, 0);
            }
            data[start..end].copy_from_slice(buf);
            self.pos = end as u64;
            Ok(buf.len())
        }
        fn flush(&mut self) -> Result<(), Self::Error> {
            Ok(())
        }
    }

    impl embedded_io::Seek for MockFile {
        fn seek(&mut self, pos: embedded_io::SeekFrom) -> Result<u64, Self::Error> {
            let end = self.data.borrow().len() as i64;
            let new = match pos {
                embedded_io::SeekFrom::Start(o) => o,
                embedded_io::SeekFrom::Current(d) => (self.pos as i64 + d).max(0) as u64,
                embedded_io::SeekFrom::End(d) => (end + d).max(0) as u64,
            };
            self.pos = new;
            Ok(new)
        }
    }

    impl FsStorage for MockFs {
        type File = MockFile;

        fn open(&mut self, path: &str, opts: OpenOptions) -> Result<MockFile, FsError> {
            let mut map = self.store.borrow_mut();
            let present = map.contains_key(path);
            if !present && !opts.create {
                return Err(FsError::NotFound);
            }
            let rc = map.entry(path.to_string()).or_default().clone();
            if opts.truncate {
                rc.borrow_mut().clear();
            }
            Ok(MockFile {
                data: rc,
                pos: 0,
                writable: opts.write,
            })
        }

        fn close(&mut self, _file: MockFile) {
            // Data lives in the shared store; nothing to flush back.
        }

        fn read_dir(&mut self, _path: &str, out: &mut [DirEntry]) -> Result<usize, FsError> {
            let map = self.store.borrow();
            let mut n = 0;
            for (name, data) in map.iter() {
                if n >= out.len() {
                    break;
                }
                let mut s = heapless::String::<256>::new();
                let _ = s.push_str(name);
                out[n] = DirEntry {
                    name: s,
                    is_dir: false,
                    size: data.borrow().len() as u64,
                };
                n += 1;
            }
            Ok(n)
        }

        fn root(&self) -> &str {
            ""
        }

        fn sync(&mut self) -> Result<(), FsError> {
            Ok(())
        }

        fn remove(&mut self, path: &str) -> Result<(), FsError> {
            if self.store.borrow_mut().remove(path).is_some() {
                Ok(())
            } else {
                Err(FsError::NotFound)
            }
        }
    }

    fn mk(fs: MockFs, chunk: u64, size: u64) -> FlatBundle<MockFs> {
        FlatBundle::new(fs, chunk, size, 512).unwrap()
    }

    #[test]
    fn roundtrip() {
        let (fs, _store) = MockFs::new();
        let mut b = mk(fs, 1 << 20, 1 << 20);
        let pattern: Vec<u8> = (0..4096).map(|i| (i & 0xFF) as u8).collect();
        b.write_at(0, &pattern).unwrap();
        let mut out = vec![0u8; 4096];
        b.read_at(0, &mut out).unwrap();
        assert_eq!(out, pattern);
    }

    #[test]
    fn missing_chunk_read_zeros_and_no_file_created() {
        let (fs, store) = MockFs::new();
        let mut b = mk(fs, 1 << 20, 4 << 20);
        let mut out = vec![0u8; 512];
        b.read_at(3 << 20, &mut out).unwrap(); // chunk 3 never written
        assert_eq!(out, vec![0u8; 512]);
        // Read-only probing must not create files.
        assert!(store.borrow().is_empty());
    }

    #[test]
    fn partial_chunk_read_hole() {
        let (fs, _store) = MockFs::new();
        let mut b = mk(fs, 1 << 20, 1 << 20);
        // Write only the middle of chunk 0 (offset 512..1536).
        b.write_at(512, &[0xAA; 1024]).unwrap();
        let mut out = vec![0u8; 4096];
        b.read_at(0, &mut out).unwrap();
        assert_eq!(&out[0..512], &[0u8; 512]);
        assert_eq!(&out[512..1536], &[0xAA; 1024]);
        assert_eq!(&out[1536..4096], &[0u8; 4096 - 1536]);
    }

    #[test]
    fn auto_create_chunk() {
        let (fs, store) = MockFs::new();
        let mut b = mk(fs, 1 << 20, 4 << 20);
        b.write_at(1 << 20, &[0x42; 8]).unwrap(); // chunk 1
        assert!(store.borrow().contains_key("000001.img"));
        let mut out = vec![0u8; 8];
        b.read_at(1 << 20, &mut out).unwrap();
        assert_eq!(out, vec![0x42; 8]);
    }

    #[test]
    fn write_past_eof_extends() {
        let (fs, _store) = MockFs::new();
        let mut b = mk(fs, 1 << 20, 1 << 20);
        b.write_at(600, &[1, 2, 3, 4]).unwrap();
        // The gap [0,600) is a hole (zeros), tail is data.
        let mut out = vec![0u8; 1024];
        b.read_at(0, &mut out).unwrap();
        assert_eq!(&out[0..600], &[0u8; 600]);
        assert_eq!(&out[600..604], &[1, 2, 3, 4]);
    }

    #[test]
    fn read_then_write_same_chunk_ok() {
        // A read caches a writable handle for a read-write bundle, so a later
        // write to the same chunk reuses it without EBADF (regression).
        let (fs, store) = MockFs::new();
        {
            let mut b = mk(fs, 1 << 20, 4 << 20);
            b.write_at(0, &[0x11; 4096]).unwrap();
            b.sync().unwrap();
        }
        let mut b = mk(MockFs { store }, 1 << 20, 4 << 20);
        let mut out = vec![0u8; 4096];
        b.read_at(0, &mut out).unwrap();
        assert_eq!(out, vec![0x11; 4096]);
        b.write_at(0, &[0x22; 4096]).unwrap();
        b.read_at(0, &mut out).unwrap();
        assert_eq!(out, vec![0x22; 4096]);
    }

    #[test]
    fn read_only_rejects_writes_and_reads_holes() {
        let (fs, store) = MockFs::new();
        let mut b = FlatBundle::new_read_only(fs, 1 << 20, 4 << 20, 512).unwrap();
        assert!(b.is_read_only());
        // Reads work and missing chunks read as zeros ...
        let mut out = vec![0xAAu8; 512];
        b.read_at(0, &mut out).unwrap();
        assert_eq!(out, vec![0u8; 512]);
        // ... writes are refused with the policy error, not an I/O error ...
        assert_eq!(b.write_at(0, &[0x11; 512]), Err(StorageError::NotWritable));
        // ... and neither created a chunk file.
        assert!(store.borrow().is_empty());
    }

    #[test]
    fn capacity() {
        let (fs, _store) = MockFs::new();
        let b = mk(fs, 1 << 20, 4 << 20);
        assert_eq!(FlatData::capacity(&b), 4 << 20);
        assert_eq!(b.capacity(), 4 << 20);
        assert_eq!(b.chunk_size(), 1 << 20);
        assert_eq!(b.sector_size(), 512);
    }

    #[test]
    fn sync_flush_makes_data_readable() {
        let (fs, _store) = MockFs::new();
        let mut b = mk(fs, 1 << 20, 1 << 20);
        b.write_at(0, &[0x55; 512]).unwrap();
        b.sync().unwrap();
        let mut out = vec![0u8; 512];
        b.read_at(0, &mut out).unwrap();
        assert_eq!(out, vec![0x55; 512]);
    }

    #[test]
    fn cross_chunk_boundary() {
        let chunk = 512u64;
        let (fs, store) = MockFs::new();
        let mut b = mk(fs, chunk, 4096);
        let pattern: Vec<u8> = (100..164).map(|i| (i & 0xFF) as u8).collect(); // 64 bytes
        let off = 500; // straddles chunk 0/1 boundary at 512
        b.write_at(off, &pattern).unwrap();
        let mut out = vec![0u8; 64];
        b.read_at(off, &mut out).unwrap();
        assert_eq!(out, pattern);
        assert!(store.borrow().contains_key("000000.img"));
        assert!(store.borrow().contains_key("000001.img"));
    }

    #[test]
    fn cross_chunk_sparse() {
        const CHUNK: u64 = 512;
        let (fs, _store) = MockFs::new();
        let mut b = mk(fs, CHUNK, 4096);
        b.write_at(0, &[0x11; 16]).unwrap(); // chunk 0
        b.write_at(2 * CHUNK, &[0x22; 16]).unwrap(); // chunk 2
                                                     // chunk 1 missing entirely -> zeros between.
        let mut out = vec![0u8; (2 * CHUNK + 16) as usize];
        b.read_at(0, &mut out).unwrap();
        assert_eq!(&out[0..16], &[0x11; 16]);
        assert_eq!(
            &out[16..2 * CHUNK as usize],
            &[0u8; 2 * CHUNK as usize - 16]
        );
        assert_eq!(
            &out[2 * CHUNK as usize..2 * CHUNK as usize + 16],
            &[0x22; 16]
        );
    }

    #[test]
    fn lru_eviction_bounds_open_handles() {
        let (fs, _store) = MockFs::new();
        let mut b = mk(fs, 1 << 20, 16 << 20);
        // Touch more chunks than MAX_OPEN_CHUNKS.
        for i in 0..16u64 {
            b.write_at(i << 20, &[i as u8; 8]).unwrap();
        }
        assert!(b.open_chunks.len() <= MAX_OPEN_CHUNKS);
        // All data still readable (slots re-open on demand).
        for i in 0..16u64 {
            let mut out = vec![0u8; 8];
            b.read_at(i << 20, &mut out).unwrap();
            assert_eq!(out, vec![i as u8; 8]);
        }
    }

    #[test]
    fn bounds_check() {
        let (fs, _store) = MockFs::new();
        let mut b = mk(fs, 1 << 20, 4096);
        let mut out = vec![0u8; 16];
        assert_eq!(b.read_at(4096, &mut out), Err(StorageError::OutOfBounds));
        assert_eq!(b.read_at(4090, &mut out), Err(StorageError::OutOfBounds));
        assert_eq!(b.write_at(4096, &[0; 1]), Err(StorageError::OutOfBounds));
        assert_eq!(b.write_at(4090, &[0; 16]), Err(StorageError::OutOfBounds));
        // In-bounds reads still work at the very end of the volume.
        let mut tail = vec![0u8; 8];
        assert_eq!(b.read_at(4096 - 8, &mut tail), Ok(()));
    }

    #[test]
    fn geometry_validation() {
        assert!(FlatBundle::new(MockFs::new().0, 0, 4096, 512).is_err()); // chunk 0
        assert!(FlatBundle::new(MockFs::new().0, 512, 0, 512).is_err()); // size 0
        assert!(FlatBundle::new(MockFs::new().0, 512, 4096, 256).is_err()); // bad sector
        assert!(FlatBundle::new(MockFs::new().0, 512, 4096, 2048).is_err()); // chunk < sector
        assert!(FlatBundle::new(MockFs::new().0, 512, 4095, 512).is_err()); // unaligned
        assert!(FlatBundle::new(MockFs::new().0, 1, MAX_CHUNKS * 2, 512).is_err());
        // overflow
    }

    // ── manifest tests (require the `bundle` feature) ───────────────────

    #[cfg(feature = "bundle")]
    #[test]
    fn create_writes_canonical_manifest() {
        let (fs, store) = MockFs::new();
        let b = FlatBundle::create(fs, 1 << 20, 4 << 20, 512).unwrap();
        let raw = store.borrow()[MANIFEST_NAME].borrow().clone();
        let meta = BundleMeta::parse(&raw).unwrap();
        assert_eq!(
            meta.kind,
            BundleKind::Flat {
                virtual_size: 4 << 20,
                chunk_size: 1 << 20,
                sector_size: 512,
            }
        );
        assert!(meta.has_crc);
        assert_eq!(meta.cipher, None);
        // The stored metadata mirrors what a re-open parses (the encoder
        // always writes a CRC line).
        assert_eq!(b.meta().unwrap().kind, meta.kind);
        assert!(b.meta().unwrap().has_crc);
        // The writer never enumerates the directory.
        assert_eq!(store.borrow().len(), 1);
    }

    #[cfg(feature = "bundle")]
    #[test]
    fn legacy_bundle_is_refused_not_reinterpreted() {
        let (fs, store) = MockFs::new();
        store.borrow_mut().insert(
            "BUNDLE".to_string(),
            Rc::new(RefCell::new(b"magic = snow_flat_bnd\n".to_vec())),
        );
        assert_eq!(
            FlatBundle::open(fs, None, Some(8 << 20), None).err(),
            Some(BundleError::LegacyHeader)
        );
        let (fs, _store) = MockFs::new();
        assert!(FlatBundle::create(fs, 1 << 20, 8 << 20, 512).is_ok());
        let (fs, store) = MockFs::new();
        store.borrow_mut().insert(
            "BUNDLE".to_string(),
            Rc::new(RefCell::new(b"magic = snow_flat_bnd\n".to_vec())),
        );
        assert_eq!(
            FlatBundle::create(fs, 1 << 20, 8 << 20, 512).err(),
            Some(BundleError::LegacyHeader)
        );
    }

    #[cfg(feature = "bundle")]
    #[test]
    fn opens_manifest_without_crc() {
        let (fs, store) = MockFs::new();
        let body = "magic = snow_bundle\nversion = 1\nkind = flat\nvirtual_size = 8388608\nchunk_size = 1048576\nsector_size = 512\ncipher = none\n";
        store.borrow_mut().insert(
            MANIFEST_NAME.to_string(),
            Rc::new(RefCell::new(body.as_bytes().to_vec())),
        );
        let b = FlatBundle::open(fs, None, None, None).unwrap();
        assert_eq!(b.capacity(), 8 << 20);
        assert_eq!(b.chunk_size(), 1 << 20);
        assert!(!b.meta().unwrap().has_crc);
    }

    #[cfg(feature = "bundle")]
    #[test]
    fn create_with_meta_rejects_a_keyslot_manifest() {
        let (fs, store) = MockFs::new();
        let cipher = crate::bundle::CipherMeta {
            cipher: crate::bundle::CipherAlg::Xor,
            nonce: [7; 8],
            key_id: [8; 8],
            slot: crate::bundle::KeySlot {
                kdf: crate::bundle::KdfKind::None,
                iterations: None,
                salt: [9; 16],
                wrap_nonce: [10; 8],
                wrapped_key: [11; 32],
                tag: [12; 16],
            },
        };
        let meta = BundleMeta {
            kind: BundleKind::Flat {
                virtual_size: 4 << 20,
                chunk_size: 1 << 20,
                sector_size: 512,
            },
            cipher: Some(cipher),
            has_crc: false,
        };
        assert_eq!(
            FlatBundle::create_with_meta(fs, &meta).err(),
            Some(BundleError::CipherRequiresAtomicManifest)
        );
        // The refused write left no manifest behind.
        assert!(!store.borrow().contains_key(MANIFEST_NAME));
        // The format itself still round-trips the keyslot block.
        let encoded = meta.encode().unwrap();
        assert_eq!(BundleMeta::parse(&encoded).unwrap().cipher, Some(cipher));
    }

    #[cfg(feature = "bundle")]
    #[test]
    fn create_with_meta_rejects_non_flat_kind() {
        let (fs, _store) = MockFs::new();
        let meta = BundleMeta {
            kind: BundleKind::Image { size: 4096 },
            cipher: None,
            has_crc: false,
        };
        assert_eq!(
            FlatBundle::create_with_meta(fs, &meta).err(),
            Some(BundleError::WrongKind)
        );
    }

    #[cfg(feature = "bundle")]
    #[test]
    fn create_rejects_existing_manifest() {
        let (mut fs, _store) = MockFs::new();
        let mut f = fs
            .open(MANIFEST_NAME, OpenOptions::create_or_truncate())
            .unwrap();
        embedded_io::Write::write_all(&mut f, b"magic = snow_bundle\n").unwrap();
        fs.close(f);
        assert!(matches!(
            FlatBundle::create(fs, 1 << 20, 4 << 20, 512),
            Err(BundleError::AlreadyExists)
        ));
    }

    #[cfg(feature = "bundle")]
    #[test]
    fn open_requires_virtual_size_when_no_manifest() {
        let (fs, _store) = MockFs::new();
        assert!(matches!(
            FlatBundle::open(fs, None, None, None),
            Err(BundleError::MissingVirtualSize)
        ));
    }

    #[cfg(feature = "bundle")]
    #[test]
    fn open_rejects_wrong_kind() {
        let (mut fs, _store) = MockFs::new();
        let meta = BundleMeta {
            kind: BundleKind::Cdr,
            cipher: None,
            has_crc: false,
        };
        let bytes = meta.encode().unwrap();
        let mut f = fs
            .open(MANIFEST_NAME, OpenOptions::create_or_truncate())
            .unwrap();
        embedded_io::Write::write_all(&mut f, &bytes).unwrap();
        fs.close(f);
        assert_eq!(
            FlatBundle::open(fs, None, Some(4096), None).err(),
            Some(BundleError::WrongKind)
        );
    }

    #[cfg(feature = "bundle")]
    #[test]
    fn open_rejects_malformed_manifest() {
        let (mut fs, _store) = MockFs::new();
        let mut f = fs
            .open(MANIFEST_NAME, OpenOptions::create_or_truncate())
            .unwrap();
        embedded_io::Write::write_all(&mut f, b"magic = NOPE\n").unwrap();
        fs.close(f);
        assert_eq!(
            FlatBundle::open(fs, None, Some(4096), None).err(),
            Some(BundleError::Manifest(ManifestError::BadMagic))
        );
    }

    #[cfg(feature = "bundle")]
    #[test]
    fn open_rejects_manifest_larger_than_max() {
        let (mut fs, _store) = MockFs::new();
        let mut f = fs
            .open(MANIFEST_NAME, OpenOptions::create_or_truncate())
            .unwrap();
        let mut data = vec![b'a'; MAX_MANIFEST + 1];
        data[MAX_MANIFEST] = b'\n';
        embedded_io::Write::write_all(&mut f, &data).unwrap();
        fs.close(f);
        assert_eq!(
            FlatBundle::open(fs, None, Some(4096), None).err(),
            Some(BundleError::Manifest(ManifestError::TooLarge))
        );
    }

    #[cfg(feature = "bundle")]
    #[test]
    fn create_then_reopen_persists() {
        // Two bundles sharing one store imitate "drop + reopen on same dir".
        let (fs, store) = MockFs::new();
        {
            let mut b = FlatBundle::create(fs, 1 << 20, 4 << 20, 512).unwrap();
            b.write_at(0, &[0x33; 64]).unwrap();
            b.sync().unwrap();
        }
        let mut b2 = FlatBundle::open(MockFs { store }, None, None, None).unwrap();
        let mut out = vec![0u8; 64];
        b2.read_at(0, &mut out).unwrap();
        assert_eq!(out, vec![0x33; 64]);
        assert!(b2.meta().is_some());
    }

    #[cfg(feature = "bundle")]
    #[test]
    fn open_merge_overrides() {
        let (fs1, store) = MockFs::new();
        {
            let mut b = FlatBundle::create(fs1, 1 << 20, 4 << 20, 512).unwrap();
            b.sync().unwrap();
        }
        let b2 = FlatBundle::open(MockFs { store }, Some(1 << 21), None, None).unwrap();
        assert_eq!(b2.chunk_size(), 1 << 21);
        assert_eq!(b2.capacity(), 4 << 20);
        assert_eq!(b2.sector_size(), 512);
    }

    #[cfg(feature = "bundle")]
    #[test]
    fn explicit_new_has_no_meta() {
        let (fs, _store) = MockFs::new();
        let b = mk(fs, 1 << 20, 4 << 20);
        assert_eq!(b.meta(), None);
    }
}
