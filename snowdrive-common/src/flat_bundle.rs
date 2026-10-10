//! FlatBundle: directory-chunked block-device plane.
//!
//! A [`FlatBundle<F>`] splits one logical block device into fixed-size chunk
//! files (`{:06}.img`) stored in a plain filesystem directory through the
//! [`FsStorage`] seam — no proprietary binary format, on-demand physical
//! allocation, and the FAT32 4 GiB limit is sidestepped per chunk.
//!
//! Design notes:
//! - **`FsStorage` root = the bundle directory.** Chunks and `BUNDLE` are
//!   opened by relative path (`"000000.img"`, `"BUNDLE"`) from the root, same
//!   as `LiveData`'s scanner. The bundle holds **no `dir` field**.
//! - The bundle implements [`FlatData`] (read) + [`WritableFlatData`]
//!   (write+sync) directly — it deliberately does **not** implement
//!   [`SeekableStorage`](crate::seekable_storage::SeekableStorage) (no embedded-io cursor semantics; addressing is explicit
//!   via the `off` argument).
//! - **Sparse/hole semantics:** a chunk file only extends to the highest byte
//!   ever written. The read path treats physical EOF inside a chunk as a hole
//!   and zero-fills it; it never surfaces `UnexpectedEof` as an error (which
//!   the SCSI layer would map to READ ERROR). Missing chunks are zero-filled
//!   too, and are only probed read-only (a hole read never creates a file).
//! - **Best-effort `sync`:** the `FsStorage`/`embedded_io` seams cap durability
//!   at OS page cache (`flush`). True fsync requires extending the seam; this
//!   implementation guarantees page-cache visibility only.
//!
//! # Feature gating
//!
//! The core struct + read/write path are compiled unconditionally (and stay
//! `no_std`-clean). The `BUNDLE` INI header handling ([`FlatBundle::create`],
//! [`FlatBundle::open`], `parse_bundle_header`) is gated behind the `bundle`
//! feature (which pulls in `ini_core`).

use embedded_io::Error as _;
use embedded_io::ErrorKind as IoErrorKind;
use heapless::Vec as HeaplessVec;

use crate::fs_storage::{FsError, FsStorage, OpenOptions};
use crate::seekable_storage::{FlatData, StorageError, WritableFlatData};

/// Default chunk size when the `BUNDLE` header is absent (100 MiB).
pub const DEFAULT_CHUNK_SIZE: u64 = 100 * 1024 * 1024;

/// Maximum number of simultaneously-open chunk file handles (LRU bound).
pub const MAX_OPEN_CHUNKS: usize = 8;

/// Maximum number of addressable chunks (`{:06}.img` → 6 digits).
const MAX_CHUNKS: u64 = 999_999;

/// `FlatBundle` construction/geometry/header errors.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BundleError {
    /// Underlying filesystem failure.
    Fs(FsError),
    /// `BUNDLE` header is not valid UTF-8 / INI / numeric field.
    BadHeader,
    /// `BUNDLE` header exists but the `magic` value is not `snow_flat_bnd`.
    BadMagic,
    /// `BUNDLE` header exists but lacks a `magic` key.
    MissingMagic,
    /// `FlatBundle::create` on a directory that already has a `BUNDLE`.
    AlreadyExists,
    /// No header and no caller-supplied `virtual_size`.
    MissingVirtualSize,
    /// Geometry rejected (`chunk_size`/`virtual_size`/`sector_size` alignment,
    /// zero, or chunk-count overflow). See `validate_geometry`.
    InvalidGeometry,
}

impl core::fmt::Display for BundleError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::Fs(e) => write!(f, "filesystem error: {e}"),
            Self::BadHeader => write!(f, "invalid BUNDLE header"),
            Self::BadMagic => write!(f, "invalid BUNDLE magic"),
            Self::MissingMagic => write!(f, "BUNDLE header missing magic key"),
            Self::AlreadyExists => write!(f, "BUNDLE header already exists"),
            Self::MissingVirtualSize => write!(f, "virtual_size required (no BUNDLE header)"),
            Self::InvalidGeometry => write!(f, "invalid bundle geometry"),
        }
    }
}

impl core::error::Error for BundleError {}

impl From<FsError> for BundleError {
    fn from(e: FsError) -> Self {
        Self::Fs(e)
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
/// `"{:06}.img"` relative to it, the optional header is `"BUNDLE"`.
pub struct FlatBundle<F: FsStorage> {
    fs: F,
    chunk_size: u64,
    virtual_size: u64,
    sector_size: u32,
    /// Read-only mode: `write_at` returns [`StorageError::NotWritable`]
    /// and chunk files are opened read-only. The data plane and the device
    /// policy must agree (read-only media cannot even be opened `r+b`).
    read_only: bool,
    open_chunks: HeaplessVec<ChunkSlot<F>, MAX_OPEN_CHUNKS>,
    tick: u64,
}

impl<F: FsStorage> FlatBundle<F> {
    /// Construct a read-write bundle with explicit geometry (no `BUNDLE` header
    /// I/O).
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
            open_chunks: HeaplessVec::new(),
            tick: 0,
        })
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

    /// Create a new bundle: validate geometry, write the `BUNDLE` header, and
    /// return the bundle. Requires the directory to already exist.
    ///
    /// Fails with [`BundleError::AlreadyExists`] if a `BUNDLE` header is
    /// already present (prevents accidental overwrite). Chunk 0 is not
    /// pre-allocated; the first write creates it.
    #[cfg(feature = "bundle")]
    pub fn create(
        mut fs: F,
        chunk_size: u64,
        virtual_size: u64,
        sector_size: u32,
    ) -> Result<Self, BundleError> {
        validate_geometry(chunk_size, virtual_size, sector_size)?;
        match fs.open("BUNDLE", OpenOptions::read_only()) {
            Ok(_) => return Err(BundleError::AlreadyExists),
            Err(FsError::NotFound) => {}
            Err(e) => return Err(BundleError::Fs(e)),
        }
        let mut hdr = heapless::String::<160>::new();
        use core::fmt::Write as _;
        write!(
            hdr,
            "magic = snow_flat_bnd\r\nversion = 1\r\nchunk_size = {}\r\nvirtual_size = {}\r\nsector_size = {}\r\n",
            chunk_size, virtual_size, sector_size
        )
        .map_err(|_| BundleError::BadHeader)?;
        let mut file = fs
            .open("BUNDLE", OpenOptions::create_or_truncate())
            .map_err(BundleError::Fs)?;
        embedded_io::Write::write_all(&mut file, hdr.as_bytes())
            .map_err(|e| BundleError::Fs(FsError::Io(e.kind())))?;
        embedded_io::Write::flush(&mut file).map_err(|e| BundleError::Fs(FsError::Io(e.kind())))?;
        fs.close(file);
        fs.sync().map_err(BundleError::Fs)?;
        Self::new(fs, chunk_size, virtual_size, sector_size)
    }

    /// Open an existing (or header-less) bundle, merging the `BUNDLE` header
    /// with caller overrides (caller wins per-field).
    ///
    /// - `chunk_override` / `size_override` / `sector_override`: optional
    ///   caller values that override the header (or fill in for a missing
    ///   header).
    /// - A missing header with no `size_override` yields
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
        let mut header = BundleHeader::default();
        match fs.open("BUNDLE", OpenOptions::read_only()) {
            Ok(mut f) => {
                let mut data = HeaplessVec::<u8, 2048>::new();
                let mut tmp = [0u8; 256];
                loop {
                    let n = embedded_io::Read::read(&mut f, &mut tmp)
                        .map_err(|e| BundleError::Fs(FsError::Io(e.kind())))?;
                    if n == 0 {
                        break;
                    }
                    data.extend_from_slice(&tmp[..n])
                        .map_err(|_| BundleError::BadHeader)?;
                }
                fs.close(f);
                header = parse_bundle_header(&data)?;
            }
            Err(FsError::NotFound) => {}
            Err(e) => return Err(BundleError::Fs(e)),
        }
        let chunk_size = chunk_override.unwrap_or(header.chunk_size);
        let virtual_size = size_override.unwrap_or(header.virtual_size);
        let sector_size = sector_override.unwrap_or(header.sector_size);
        if virtual_size == 0 {
            return Err(BundleError::MissingVirtualSize);
        }
        Self::build(fs, chunk_size, virtual_size, sector_size, read_only)
    }

    /// Relative path of chunk `idx` within the bundle directory.
    fn chunk_path(&self, idx: u64) -> heapless::String<16> {
        let mut s = heapless::String::<16>::new();
        use core::fmt::Write as _;
        let _ = write!(s, "{:06}.img", idx);
        s
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
            let chunk_off = pos % self.chunk_size;
            let take = {
                let remain = self.chunk_size - chunk_off;
                if remain >= dst.len() as u64 {
                    dst.len()
                } else {
                    remain as usize
                }
            };
            let (chunk_dst, rest) = dst.split_at_mut(take);
            match self.ensure_chunk(pos / self.chunk_size, false) {
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
            let chunk_off = pos % self.chunk_size;
            let take = {
                let remain = self.chunk_size - chunk_off;
                if remain >= src.len() as u64 {
                    src.len()
                } else {
                    remain as usize
                }
            };
            let (chunk_src, rest) = src.split_at(take);
            let i = self
                .ensure_chunk(pos / self.chunk_size, true)
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
fn validate_geometry(
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

/// Parsed `BUNDLE` header (only used behind the `bundle` feature).
#[cfg(feature = "bundle")]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct BundleHeader {
    version: u32,
    chunk_size: u64,
    virtual_size: u64,
    sector_size: u32,
}

#[cfg(feature = "bundle")]
impl Default for BundleHeader {
    fn default() -> Self {
        Self {
            version: 1,
            chunk_size: DEFAULT_CHUNK_SIZE,
            virtual_size: 0,
            sector_size: 512,
        }
    }
}

/// Parse a `BUNDLE` INI header. Comments use `;` (traditional INI, `ini_core`'s
/// default — no `comment_char` needed); `auto_trim` strips surrounding space.
///
/// `magic` is mandatory when the file exists; `virtual_size`/`chunk_size`/
/// `sector_size` are optional (defaults fill in). Unknown keys are ignored
/// (forward compatibility).
#[cfg(feature = "bundle")]
fn parse_bundle_header(input: &[u8]) -> Result<BundleHeader, BundleError> {
    let doc = core::str::from_utf8(input).map_err(|_| BundleError::BadHeader)?;
    let parser = ini_core::Parser::new(doc).auto_trim(true);
    let mut header = BundleHeader::default();
    let mut magic_seen = false;
    for item in parser {
        match item {
            // Item::Comment fires only on ';' lines; Item::Error only for a bad
            // [SECTION line (this format has none).
            ini_core::Item::Comment(_) => {}
            ini_core::Item::Property(key, Some(value)) => match key {
                "magic" => {
                    magic_seen = true;
                    if value != "snow_flat_bnd" {
                        return Err(BundleError::BadMagic);
                    }
                }
                "version" => header.version = value.parse().map_err(|_| BundleError::BadHeader)?,
                "chunk_size" => {
                    header.chunk_size = value.parse().map_err(|_| BundleError::BadHeader)?
                }
                "virtual_size" => {
                    header.virtual_size = value.parse().map_err(|_| BundleError::BadHeader)?
                }
                "sector_size" => {
                    header.sector_size = value.parse().map_err(|_| BundleError::BadHeader)?
                }
                _ => {} // unknown key: ignore (forward compatible)
            },
            ini_core::Item::Property(_, None) => {} // line without '=': ignore
            _ => {}
        }
    }
    if !magic_seen {
        return Err(BundleError::MissingMagic);
    }
    Ok(header)
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

    // ── header tests (require the `bundle` feature) ─────────────────────

    #[cfg(feature = "bundle")]
    #[test]
    fn header_parse_comments_and_order() {
        let input = b"; comment\r\nmagic = snow_flat_bnd\r\nversion = 1\r\nchunk_size = 1048576\r\nvirtual_size = 2097152\r\nsector_size = 512\r\n";
        let h = parse_bundle_header(input).unwrap();
        assert_eq!(h.chunk_size, 1 << 20);
        assert_eq!(h.virtual_size, 2 << 20);
        assert_eq!(h.sector_size, 512);
        assert_eq!(h.version, 1);
    }

    #[cfg(feature = "bundle")]
    #[test]
    fn header_missing_magic_rejected() {
        let input = b"chunk_size = 1048576\r\nvirtual_size = 2097152\r\n";
        assert_eq!(parse_bundle_header(input), Err(BundleError::MissingMagic));
        let input2 = b"magic = NOPE\r\n";
        assert_eq!(parse_bundle_header(input2), Err(BundleError::BadMagic));
    }

    #[cfg(feature = "bundle")]
    #[test]
    fn header_bad_utf8_rejected() {
        assert_eq!(
            parse_bundle_header(&[0xFF, 0xFE]),
            Err(BundleError::BadHeader)
        );
    }

    #[cfg(feature = "bundle")]
    #[test]
    fn create_rejects_existing_header() {
        let (mut fs, _store) = MockFs::new();
        let mut f = fs
            .open("BUNDLE", OpenOptions::create_or_truncate())
            .unwrap();
        embedded_io::Write::write_all(&mut f, b"magic = snow_flat_bnd\r\n").unwrap();
        fs.close(f);
        assert!(matches!(
            FlatBundle::create(fs, 1 << 20, 4 << 20, 512),
            Err(BundleError::AlreadyExists)
        ));
    }

    #[cfg(feature = "bundle")]
    #[test]
    fn open_requires_virtual_size_when_no_header() {
        let (fs, _store) = MockFs::new();
        assert!(matches!(
            FlatBundle::open(fs, None, None, None),
            Err(BundleError::MissingVirtualSize)
        ));
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
    }
}
