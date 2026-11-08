//! `AsyncFlatBundle`: asynchronous directory-chunked block-device plane.
//!
//! The `async fn` mirror of [`crate::flat_bundle::FlatBundle`]: one logical
//! block device split into fixed-size chunk files (`{:06}.img`) in a plain
//! filesystem directory, served through the
//! [`AsyncFsStorage`] seam without blocking an executor.
//!
//! Semantics are deliberately identical to the synchronous bundle:
//!
//! - the backend root **is** the bundle directory;
//! - chunks are opened on demand and cached in an LRU bounded by
//!   [`MAX_OPEN_CHUNKS`], with eviction calling [`AsyncFsStorage::close`];
//! - a chunk only extends to its highest written byte; a read past physical
//!   EOF (or from a missing chunk) zero-fills the hole and never creates a
//!   file;
//! - a write never crosses a chunk-file boundary: it is split at the chunk
//!   edge and each part opens/creates its own chunk;
//! - `sync` flushes every open handle and then syncs the filesystem;
//! - [`AsyncFlatData::capacity`] stays synchronous (geometry before I/O).
//!
//! # Explicit lifecycle
//!
//! Async close cannot run from `Drop`, so this type implements no destructor.
//! Dropping it only drops the [`AsyncFsFile`] handles — data may still be
//! buffered and the backend's `close` never runs. Call `shutdown` for
//! a deterministic flush-and-close: it syncs first on writable media, then
//! closes every open chunk handle and returns the first error.
//!
//! # Feature gating
//!
//! The struct and read/write/sync paths are available whenever `async-io` is
//! enabled. Manifest handling (`create`, `create_with_meta`, `open`,
//! `open_read_only`) additionally requires `bundle`.
//!
//! [`AsyncFsFile`]: crate::async_fs_storage::AsyncFsFile

use embedded_io::ErrorKind as IoErrorKind;
use heapless::Vec as HeaplessVec;

use crate::async_fs_storage::{AsyncFsFile, AsyncFsStorage};
use crate::async_seekable_storage::{AsyncFlatData, AsyncWritableFlatData};
use crate::bundle::BundleMeta;
#[cfg(feature = "bundle")]
use crate::bundle::{BundleKind, ManifestError, MANIFEST_NAME, MAX_MANIFEST};
use crate::flat_bundle::{chunk_path, chunk_span, validate_geometry, BundleError, MAX_OPEN_CHUNKS};
#[cfg(feature = "bundle")]
use crate::flat_bundle::{prepare_create, resolve_geometry, LEGACY_HEADER_NAME};
use crate::fs_storage::{FsError, OpenOptions};
use crate::seekable_storage::StorageError;

/// One open async chunk file handle (LRU slot).
struct ChunkSlot<F: AsyncFsStorage> {
    idx: u64,
    file: F::File,
    last_used: u64,
}

/// Directory-chunked, random-writable block plane over an [`AsyncFsStorage`].
///
/// `F`'s root **is** the bundle directory: chunks are `"{:06}.img"` relative
/// to it, the optional manifest is `"SNOWBUNDLE"`.
pub struct AsyncFlatBundle<F: AsyncFsStorage> {
    fs: F,
    chunk_size: u64,
    virtual_size: u64,
    sector_size: u32,
    /// Read-only mode: `write_at` returns [`StorageError::NotWritable`] and
    /// chunk files are opened read-only (writable media may not even be
    /// openable `r+`).
    read_only: bool,
    /// Parsed manifest, or `None` when built from explicit geometry.
    meta: Option<BundleMeta>,
    open_chunks: HeaplessVec<ChunkSlot<F>, MAX_OPEN_CHUNKS>,
    tick: u64,
}

impl<F: AsyncFsStorage> AsyncFlatBundle<F> {
    /// Construct a read-write bundle with explicit geometry (no manifest I/O).
    ///
    /// `fs` must be rooted at the bundle directory, which must already exist
    /// (the seam has no `mkdir`). Geometry is validated here.
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
    /// Chunks are opened read-only and every write is rejected with
    /// [`StorageError::NotWritable`], so this works on read-only media.
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

    /// Manifest this bundle was opened/created from, if any.
    pub fn meta(&self) -> Option<&BundleMeta> {
        self.meta.as_ref()
    }

    /// Whether this bundle is read-only (`write_at` → `NotWritable`).
    pub fn is_read_only(&self) -> bool {
        self.read_only
    }

    /// Logical device size in bytes.
    pub fn capacity(&self) -> u64 {
        self.virtual_size
    }

    /// Chunk size in bytes.
    pub fn chunk_size(&self) -> u64 {
        self.chunk_size
    }

    /// Sector size (`512` or `2048`).
    pub fn sector_size(&self) -> u32 {
        self.sector_size
    }

    /// Create a new flat bundle with the given geometry.
    ///
    /// Builds a plaintext [`BundleKind::Flat`] manifest and delegates to
    /// [`Self::create_with_meta`].
    #[cfg(feature = "bundle")]
    pub async fn create(
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
        Self::create_with_meta(fs, &meta).await
    }

    /// Create a new bundle from an explicit manifest.
    ///
    /// Same rules as the synchronous
    /// [`FlatBundle::create_with_meta`](crate::flat_bundle::FlatBundle::create_with_meta):
    /// only [`BundleKind::Flat`] is accepted, a keyslot-bearing manifest is
    /// refused with [`BundleError::CipherRequiresAtomicManifest`], an existing
    /// `SNOWBUNDLE` is [`BundleError::AlreadyExists`], and a legacy `BUNDLE`
    /// header is [`BundleError::LegacyHeader`]. The manifest is written with
    /// `create_or_truncate`, flushed, closed and the filesystem synced.
    #[cfg(feature = "bundle")]
    pub async fn create_with_meta(mut fs: F, meta: &BundleMeta) -> Result<Self, BundleError> {
        let (chunk_size, virtual_size, sector_size, manifest) = prepare_create(meta)?;
        match fs.open(MANIFEST_NAME, OpenOptions::read_only()).await {
            Ok(file) => {
                let _ = fs.close(file).await;
                return Err(BundleError::AlreadyExists);
            }
            Err(FsError::NotFound) => {}
            Err(e) => return Err(BundleError::Fs(e)),
        }
        // A legacy directory must not silently receive new geometry: its
        // chunks were written with the old header's chunk size.
        match fs.open(LEGACY_HEADER_NAME, OpenOptions::read_only()).await {
            Ok(file) => {
                let _ = fs.close(file).await;
                return Err(BundleError::LegacyHeader);
            }
            Err(FsError::NotFound) => {}
            Err(e) => return Err(BundleError::Fs(e)),
        }
        let mut file = fs
            .open(MANIFEST_NAME, OpenOptions::create_or_truncate())
            .await
            .map_err(BundleError::Fs)?;
        if let Err(e) = write_all_at(&mut file, 0, &manifest).await {
            let _ = fs.close(file).await;
            return Err(BundleError::Fs(e));
        }
        if let Err(e) = file.flush().await {
            let _ = fs.close(file).await;
            return Err(BundleError::Fs(e));
        }
        fs.close(file).await.map_err(BundleError::Fs)?;
        fs.sync().await.map_err(BundleError::Fs)?;
        let mut bundle = Self::build(fs, chunk_size, virtual_size, sector_size, false)?;
        // `encode` always emits a CRC line, so the stored metadata mirrors
        // what a re-open parses.
        let mut stored = *meta;
        stored.has_crc = true;
        bundle.meta = Some(stored);
        Ok(bundle)
    }

    /// Open an existing (or manifest-less) bundle, merging the `SNOWBUNDLE`
    /// manifest with caller overrides (caller wins per field).
    ///
    /// A present manifest must be [`BundleKind::Flat`]
    /// ([`BundleError::WrongKind`]); a missing manifest needs `size_override`
    /// ([`BundleError::MissingVirtualSize`]); a legacy `BUNDLE` header is
    /// refused with [`BundleError::LegacyHeader`].
    #[cfg(feature = "bundle")]
    pub async fn open(
        fs: F,
        chunk_override: Option<u64>,
        size_override: Option<u64>,
        sector_override: Option<u32>,
    ) -> Result<Self, BundleError> {
        Self::open_impl(fs, chunk_override, size_override, sector_override, false).await
    }

    /// Like [`Self::open`], but read-only.
    #[cfg(feature = "bundle")]
    pub async fn open_read_only(
        fs: F,
        chunk_override: Option<u64>,
        size_override: Option<u64>,
        sector_override: Option<u32>,
    ) -> Result<Self, BundleError> {
        Self::open_impl(fs, chunk_override, size_override, sector_override, true).await
    }

    #[cfg(feature = "bundle")]
    async fn open_impl(
        mut fs: F,
        chunk_override: Option<u64>,
        size_override: Option<u64>,
        sector_override: Option<u32>,
        read_only: bool,
    ) -> Result<Self, BundleError> {
        let meta = match fs.open(MANIFEST_NAME, OpenOptions::read_only()).await {
            Ok(mut file) => {
                let mut data = HeaplessVec::<u8, MAX_MANIFEST>::new();
                let mut tmp = [0u8; 64];
                let mut off = 0u64;
                loop {
                    let n = match file.read_at(off, &mut tmp).await {
                        Ok(n) => n,
                        Err(e) => {
                            let _ = fs.close(file).await;
                            return Err(BundleError::Fs(e));
                        }
                    };
                    if n == 0 {
                        break;
                    }
                    off += n as u64;
                    if data.extend_from_slice(&tmp[..n]).is_err() {
                        let _ = fs.close(file).await;
                        return Err(BundleError::Manifest(ManifestError::TooLarge));
                    }
                }
                fs.close(file).await.map_err(BundleError::Fs)?;
                Some(BundleMeta::parse(&data)?)
            }
            Err(FsError::NotFound) => {
                // Never reinterpret an old bundle with new geometry.
                match fs.open(LEGACY_HEADER_NAME, OpenOptions::read_only()).await {
                    Ok(file) => {
                        let _ = fs.close(file).await;
                        return Err(BundleError::LegacyHeader);
                    }
                    Err(FsError::NotFound) => {}
                    Err(e) => return Err(BundleError::Fs(e)),
                }
                None
            }
            Err(e) => return Err(BundleError::Fs(e)),
        };
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

    /// Ensure a slot for chunk `idx` is open, returning its index in
    /// `open_chunks`.
    ///
    /// `create == false` opens read-only-or-read-write (never creates) and
    /// returns `None` when the chunk is absent; `create == true` opens with
    /// `open_or_create`. Evicts the least-recently-used slot (calling
    /// [`AsyncFsStorage::close`]) when at capacity.
    async fn ensure_chunk(&mut self, idx: u64, create: bool) -> Result<Option<usize>, FsError> {
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
        let path = chunk_path(idx);
        let file = match self.fs.open(path.as_str(), opts).await {
            Ok(f) => f,
            Err(FsError::NotFound) if !create => return Ok(None),
            Err(e) => return Err(e),
        };
        self.evict_one().await?;
        let slot = ChunkSlot {
            idx,
            file,
            last_used: self.tick,
        };
        if let Err(slot) = self.open_chunks.push(slot) {
            // Unreachable after `evict_one`, but close the handle explicitly
            // instead of dropping it.
            let _ = self.fs.close(slot.file).await;
            return Err(FsError::Io(IoErrorKind::Other));
        }
        self.tick = self.tick.wrapping_add(1);
        Ok(Some(self.open_chunks.len() - 1))
    }

    /// Evict the least-recently-used chunk slot, closing its handle.
    async fn evict_one(&mut self) -> Result<(), FsError> {
        if self.open_chunks.len() < MAX_OPEN_CHUNKS {
            return Ok(());
        }
        let mut min_i = 0;
        for i in 1..self.open_chunks.len() {
            if self.open_chunks[i].last_used < self.open_chunks[min_i].last_used {
                min_i = i;
            }
        }
        let slot = self.open_chunks.swap_remove(min_i);
        self.fs.close(slot.file).await
    }

    /// Flush and close every open chunk handle, then drop the bundle.
    ///
    /// On writable media this syncs first (every open handle is flushed, then
    /// [`AsyncFsStorage::sync`] runs), so the data is durable before the
    /// handles go away. Errors do not stop the remaining closes: the first
    /// sync/close error is returned after everything has been attempted.
    pub async fn shutdown(mut self) -> Result<(), BundleError> {
        let mut first: Option<BundleError> = None;
        if !self.read_only {
            for slot in self.open_chunks.iter_mut() {
                if let Err(e) = slot.file.flush().await {
                    first.get_or_insert(BundleError::Fs(e));
                }
            }
            if let Err(e) = self.fs.sync().await {
                first.get_or_insert(BundleError::Fs(e));
            }
        }
        while let Some(slot) = self.open_chunks.pop() {
            if let Err(e) = self.fs.close(slot.file).await {
                first.get_or_insert(BundleError::Fs(e));
            }
        }
        match first {
            Some(e) => Err(e),
            None => Ok(()),
        }
    }
}

/// Write `buf` at `off`, looping over short writes.
///
/// A zero-length write is an I/O error: it would spin forever.
async fn write_all_at<F: AsyncFsFile>(
    file: &mut F,
    mut off: u64,
    mut buf: &[u8],
) -> Result<(), FsError> {
    while !buf.is_empty() {
        let n = file.write_at(off, buf).await?;
        if n == 0 {
            return Err(FsError::Io(IoErrorKind::Other));
        }
        off += n as u64;
        buf = &buf[n..];
    }
    Ok(())
}

impl<F: AsyncFsStorage> AsyncFlatData for AsyncFlatBundle<F> {
    async fn read_at(&mut self, off: u64, buf: &mut [u8]) -> Result<(), StorageError> {
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
            match self.ensure_chunk(idx, false).await {
                Ok(Some(i)) => {
                    let file = &mut self.open_chunks[i].file;
                    // Zero-fill holes past physical EOF (never an error).
                    let mut done = 0usize;
                    while done < chunk_dst.len() {
                        let n = file
                            .read_at(chunk_off + done as u64, &mut chunk_dst[done..])
                            .await
                            .map_err(StorageError::from)?;
                        if n == 0 {
                            chunk_dst[done..].fill(0);
                            break;
                        }
                        done += n;
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

impl<F: AsyncFsStorage> AsyncWritableFlatData for AsyncFlatBundle<F> {
    async fn write_at(&mut self, off: u64, buf: &[u8]) -> Result<(), StorageError> {
        if self.read_only {
            // Data-plane policy rejection (device maps it to DATA PROTECT).
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
                .await
                .map_err(StorageError::from)?
                .ok_or(StorageError::Io(IoErrorKind::Other))?;
            let file = &mut self.open_chunks[i].file;
            write_all_at(file, chunk_off, chunk_src)
                .await
                .map_err(StorageError::from)?;
            pos += take as u64;
            src = rest;
        }
        Ok(())
    }

    async fn sync(&mut self) -> Result<(), StorageError> {
        if self.read_only {
            // Nothing was ever written; nothing to flush.
            return Ok(());
        }
        for slot in self.open_chunks.iter_mut() {
            slot.file.flush().await.map_err(StorageError::from)?;
        }
        self.fs.sync().await.map_err(StorageError::from)?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::fs_storage::{DirEntry, FsStorage};
    use std::cell::{Cell, RefCell};
    use std::collections::HashMap;
    use std::rc::Rc;

    fn block_on<F: core::future::Future>(fut: F) -> F::Output {
        let mut fut = core::pin::pin!(fut);
        let mut cx = core::task::Context::from_waker(core::task::Waker::noop());
        loop {
            if let core::task::Poll::Ready(v) = fut.as_mut().poll(&mut cx) {
                return v;
            }
        }
    }

    // ── Shared in-memory async FsStorage mock ───────────────────────────
    // A `Rc<RefCell<...>>` store lets two bundles (and the synchronous
    // `FlatBundle` in the differential test) share the same files, so
    // persistence after drop/shutdown is observable directly.

    type Store = Rc<RefCell<HashMap<String, Rc<RefCell<Vec<u8>>>>>>;

    struct MockAsyncFs {
        store: Store,
        opens: Rc<Cell<usize>>,
        closes: Rc<Cell<usize>>,
    }

    impl MockAsyncFs {
        fn new() -> (Self, Store, Rc<Cell<usize>>, Rc<Cell<usize>>) {
            let store: Store = Rc::default();
            let opens = Rc::new(Cell::new(0));
            let closes = Rc::new(Cell::new(0));
            (
                Self {
                    store: Rc::clone(&store),
                    opens: Rc::clone(&opens),
                    closes: Rc::clone(&closes),
                },
                store,
                opens,
                closes,
            )
        }

        fn from_store(store: Store) -> (Self, Rc<Cell<usize>>, Rc<Cell<usize>>) {
            let opens = Rc::new(Cell::new(0));
            let closes = Rc::new(Cell::new(0));
            (
                Self {
                    store,
                    opens: Rc::clone(&opens),
                    closes: Rc::clone(&closes),
                },
                opens,
                closes,
            )
        }
    }

    struct MockAsyncFile {
        data: Rc<RefCell<Vec<u8>>>,
        writable: bool,
    }

    impl AsyncFsFile for MockAsyncFile {
        async fn read_at(&mut self, off: u64, buf: &mut [u8]) -> Result<usize, FsError> {
            let start = usize::try_from(off).map_err(|_| FsError::OutOfBounds)?;
            let data = self.data.borrow();
            if start >= data.len() {
                return Ok(0);
            }
            let n = buf.len().min(data.len() - start);
            buf[..n].copy_from_slice(&data[start..start + n]);
            Ok(n)
        }

        async fn write_at(&mut self, off: u64, buf: &[u8]) -> Result<usize, FsError> {
            if !self.writable {
                return Err(FsError::NotWritable);
            }
            let start = usize::try_from(off).map_err(|_| FsError::OutOfBounds)?;
            let mut data = self.data.borrow_mut();
            if start > data.len() {
                data.resize(start, 0);
            }
            let end = start + buf.len();
            if end > data.len() {
                data.resize(end, 0);
            }
            data[start..end].copy_from_slice(buf);
            Ok(buf.len())
        }

        async fn flush(&mut self) -> Result<(), FsError> {
            Ok(())
        }

        async fn len(&mut self) -> Result<u64, FsError> {
            Ok(self.data.borrow().len() as u64)
        }
    }

    impl AsyncFsStorage for MockAsyncFs {
        type File = MockAsyncFile;

        async fn open(&mut self, path: &str, opts: OpenOptions) -> Result<MockAsyncFile, FsError> {
            self.opens.set(self.opens.get() + 1);
            let mut map = self.store.borrow_mut();
            let present = map.contains_key(path);
            if !present && !opts.create {
                return Err(FsError::NotFound);
            }
            let rc = map.entry(path.to_string()).or_default().clone();
            if opts.truncate {
                rc.borrow_mut().clear();
            }
            Ok(MockAsyncFile {
                data: rc,
                writable: opts.write,
            })
        }

        async fn close(&mut self, _file: MockAsyncFile) -> Result<(), FsError> {
            self.closes.set(self.closes.get() + 1);
            Ok(())
        }

        async fn read_dir(&mut self, _path: &str, out: &mut [DirEntry]) -> Result<usize, FsError> {
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

        async fn sync(&mut self) -> Result<(), FsError> {
            Ok(())
        }

        async fn remove(&mut self, path: &str) -> Result<(), FsError> {
            if self.store.borrow_mut().remove(path).is_some() {
                Ok(())
            } else {
                Err(FsError::NotFound)
            }
        }
    }

    fn mk(fs: MockAsyncFs, chunk: u64, size: u64) -> AsyncFlatBundle<MockAsyncFs> {
        AsyncFlatBundle::new(fs, chunk, size, 512).unwrap()
    }

    #[test]
    fn roundtrip() {
        let (fs, _store, _opens, _closes) = MockAsyncFs::new();
        let mut b = mk(fs, 1 << 20, 1 << 20);
        block_on(async {
            let pattern: Vec<u8> = (0..4096).map(|i| (i & 0xFF) as u8).collect();
            b.write_at(0, &pattern).await.unwrap();
            let mut out = vec![0u8; 4096];
            b.read_at(0, &mut out).await.unwrap();
            assert_eq!(out, pattern);
        });
    }

    #[test]
    fn cross_chunk_boundary() {
        let (fs, store, _opens, _closes) = MockAsyncFs::new();
        let mut b = mk(fs, 512, 4096);
        block_on(async {
            let pattern: Vec<u8> = (100..164).map(|i| (i & 0xFF) as u8).collect();
            let off = 500; // straddles the chunk 0/1 boundary at 512
            b.write_at(off, &pattern).await.unwrap();
            let mut out = vec![0u8; 64];
            b.read_at(off, &mut out).await.unwrap();
            assert_eq!(out, pattern);
        });
        assert!(store.borrow().contains_key("000000.img"));
        assert!(store.borrow().contains_key("000001.img"));
    }

    #[test]
    fn missing_chunk_read_zeros_and_no_file_created() {
        let (fs, store, _opens, _closes) = MockAsyncFs::new();
        let mut b = mk(fs, 1 << 20, 4 << 20);
        block_on(async {
            let mut out = vec![0xAAu8; 512];
            b.read_at(3 << 20, &mut out).await.unwrap();
            assert_eq!(out, vec![0u8; 512]);
        });
        // Read-only probing must not create files.
        assert!(store.borrow().is_empty());
    }

    #[test]
    fn partial_chunk_read_hole() {
        let (fs, _store, _opens, _closes) = MockAsyncFs::new();
        let mut b = mk(fs, 1 << 20, 1 << 20);
        block_on(async {
            b.write_at(512, &[0xAA; 1024]).await.unwrap();
            let mut out = vec![0u8; 4096];
            b.read_at(0, &mut out).await.unwrap();
            assert_eq!(&out[0..512], &[0u8; 512]);
            assert_eq!(&out[512..1536], &[0xAA; 1024]);
            assert_eq!(&out[1536..4096], &[0u8; 4096 - 1536]);
        });
    }

    #[test]
    fn auto_create_chunk() {
        let (fs, store, _opens, _closes) = MockAsyncFs::new();
        let mut b = mk(fs, 1 << 20, 4 << 20);
        block_on(async {
            b.write_at(1 << 20, &[0x42; 8]).await.unwrap(); // chunk 1
            let mut out = vec![0u8; 8];
            b.read_at(1 << 20, &mut out).await.unwrap();
            assert_eq!(out, vec![0x42; 8]);
        });
        assert!(store.borrow().contains_key("000001.img"));
    }

    #[test]
    fn read_then_write_same_chunk_ok() {
        let (fs, store, _opens, _closes) = MockAsyncFs::new();
        {
            let mut b = mk(fs, 1 << 20, 4 << 20);
            block_on(async {
                b.write_at(0, &[0x11; 4096]).await.unwrap();
                b.sync().await.unwrap();
            });
        }
        let (fs, _o, _c) = MockAsyncFs::from_store(store);
        let mut b = mk(fs, 1 << 20, 4 << 20);
        block_on(async {
            let mut out = vec![0u8; 4096];
            b.read_at(0, &mut out).await.unwrap();
            assert_eq!(out, vec![0x11; 4096]);
            b.write_at(0, &[0x22; 4096]).await.unwrap();
            b.read_at(0, &mut out).await.unwrap();
            assert_eq!(out, vec![0x22; 4096]);
        });
    }

    #[test]
    fn read_only_rejects_writes_and_reads_holes() {
        let (fs, store, _opens, _closes) = MockAsyncFs::new();
        let mut b = AsyncFlatBundle::new_read_only(fs, 1 << 20, 4 << 20, 512).unwrap();
        block_on(async {
            assert!(b.is_read_only());
            let mut out = vec![0xAAu8; 512];
            b.read_at(0, &mut out).await.unwrap();
            assert_eq!(out, vec![0u8; 512]);
            assert_eq!(
                b.write_at(0, &[0x11; 512]).await,
                Err(StorageError::NotWritable)
            );
            b.sync().await.unwrap();
        });
        assert!(store.borrow().is_empty());
    }

    #[test]
    fn bounds_check() {
        let (fs, _store, _opens, _closes) = MockAsyncFs::new();
        let mut b = mk(fs, 1 << 20, 4096);
        block_on(async {
            let mut out = vec![0u8; 16];
            assert_eq!(
                b.read_at(4096, &mut out).await,
                Err(StorageError::OutOfBounds)
            );
            assert_eq!(
                b.read_at(4090, &mut out).await,
                Err(StorageError::OutOfBounds)
            );
            assert_eq!(
                b.write_at(4096, &[0; 1]).await,
                Err(StorageError::OutOfBounds)
            );
            assert_eq!(
                b.write_at(4090, &[0; 16]).await,
                Err(StorageError::OutOfBounds)
            );
            let mut tail = vec![0u8; 8];
            assert_eq!(b.read_at(4096 - 8, &mut tail).await, Ok(()));
        });
    }

    #[test]
    fn lru_eviction_bounds_open_handles() {
        let (fs, _store, _opens, _closes) = MockAsyncFs::new();
        let mut b = mk(fs, 1 << 20, 16 << 20);
        block_on(async {
            for i in 0..16u64 {
                b.write_at(i << 20, &[i as u8; 8]).await.unwrap();
            }
            assert!(b.open_chunks.len() <= MAX_OPEN_CHUNKS);
            for i in 0..16u64 {
                let mut out = vec![0u8; 8];
                b.read_at(i << 20, &mut out).await.unwrap();
                assert_eq!(out, vec![i as u8; 8]);
            }
        });
    }

    #[test]
    fn capacity() {
        let (fs, _store, _opens, _closes) = MockAsyncFs::new();
        let b = mk(fs, 1 << 20, 4 << 20);
        assert_eq!(AsyncFlatData::capacity(&b), 4 << 20);
        assert_eq!(b.capacity(), 4 << 20);
        assert_eq!(b.chunk_size(), 1 << 20);
        assert_eq!(b.sector_size(), 512);
    }

    #[test]
    fn geometry_validation() {
        assert!(AsyncFlatBundle::new(MockAsyncFs::new().0, 0, 4096, 512).is_err());
        assert!(AsyncFlatBundle::new(MockAsyncFs::new().0, 512, 0, 512).is_err());
        assert!(AsyncFlatBundle::new(MockAsyncFs::new().0, 512, 4096, 256).is_err());
        assert!(AsyncFlatBundle::new(MockAsyncFs::new().0, 512, 4096, 2048).is_err());
        assert!(AsyncFlatBundle::new(MockAsyncFs::new().0, 512, 4095, 512).is_err());
    }

    #[test]
    fn shutdown_closes_every_open_handle() {
        let (fs, _store, _opens, closes) = MockAsyncFs::new();
        let mut b = mk(fs, 1 << 20, 4 << 20);
        let (open_len, before) = block_on(async {
            for i in 0..3u64 {
                b.write_at(i << 20, &[i as u8; 8]).await.unwrap();
            }
            (b.open_chunks.len(), closes.get())
        });
        assert_eq!(open_len, 3);
        block_on(b.shutdown()).unwrap();
        // Exactly the cached handles were closed (no double close).
        assert_eq!(closes.get() - before, open_len);
    }

    #[test]
    fn shutdown_closes_read_only_handles_without_syncing() {
        let (fs, store, _opens, closes) = MockAsyncFs::new();
        store.borrow_mut().insert(
            "000000.img".to_string(),
            Rc::new(RefCell::new(vec![0u8; 8])),
        );
        let mut b = AsyncFlatBundle::new_read_only(fs, 1 << 20, 4 << 20, 512).unwrap();
        let (open_len, before) = block_on(async {
            let mut out = vec![0u8; 8];
            b.read_at(0, &mut out).await.unwrap();
            (b.open_chunks.len(), closes.get())
        });
        assert_eq!(open_len, 1);
        block_on(b.shutdown()).unwrap();
        assert_eq!(closes.get() - before, open_len);
    }

    // ── manifest tests (require the `bundle` feature) ───────────────────

    #[cfg(feature = "bundle")]
    #[test]
    fn create_writes_canonical_manifest() {
        let (fs, store, _opens, _closes) = MockAsyncFs::new();
        let b = block_on(AsyncFlatBundle::create(fs, 1 << 20, 4 << 20, 512)).unwrap();
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
        assert_eq!(b.meta().unwrap().kind, meta.kind);
        assert!(b.meta().unwrap().has_crc);
        // The writer never enumerates or pre-allocates chunks.
        assert_eq!(store.borrow().len(), 1);
    }

    #[cfg(feature = "bundle")]
    #[test]
    fn create_then_reopen_persists() {
        let (fs, store, _opens, _closes) = MockAsyncFs::new();
        block_on(async {
            let mut b = AsyncFlatBundle::create(fs, 1 << 20, 4 << 20, 512)
                .await
                .unwrap();
            b.write_at(0, &[0x33; 64]).await.unwrap();
            b.shutdown().await.unwrap();
        });
        let (fs, _o, _c) = MockAsyncFs::from_store(store);
        block_on(async {
            let mut b = AsyncFlatBundle::open(fs, None, None, None).await.unwrap();
            let mut out = vec![0u8; 64];
            b.read_at(0, &mut out).await.unwrap();
            assert_eq!(out, vec![0x33; 64]);
            assert!(b.meta().is_some());
        });
    }

    #[cfg(feature = "bundle")]
    #[test]
    fn open_merge_overrides() {
        let (fs1, store, _o, _c) = MockAsyncFs::new();
        block_on(async {
            let b = AsyncFlatBundle::create(fs1, 1 << 20, 4 << 20, 512)
                .await
                .unwrap();
            b.shutdown().await.unwrap();
        });
        let (fs2, _o2, _c2) = MockAsyncFs::from_store(store);
        block_on(async {
            let b = AsyncFlatBundle::open(fs2, Some(1 << 21), None, None)
                .await
                .unwrap();
            assert_eq!(b.chunk_size(), 1 << 21);
            assert_eq!(b.capacity(), 4 << 20);
            assert_eq!(b.sector_size(), 512);
        });
    }

    #[cfg(feature = "bundle")]
    #[test]
    fn open_requires_virtual_size_when_no_manifest() {
        let (fs, _store, _o, _c) = MockAsyncFs::new();
        assert_eq!(
            block_on(AsyncFlatBundle::open(fs, None, None, None)).err(),
            Some(BundleError::MissingVirtualSize)
        );
    }

    #[cfg(feature = "bundle")]
    #[test]
    fn open_manifest_less_with_override() {
        let (fs, _store, _o, _c) = MockAsyncFs::new();
        block_on(async {
            let b = AsyncFlatBundle::open(fs, Some(512), Some(4096), None)
                .await
                .unwrap();
            assert_eq!(b.capacity(), 4096);
            assert_eq!(b.chunk_size(), 512);
            assert!(b.meta().is_none());
        });
    }

    #[cfg(feature = "bundle")]
    #[test]
    fn legacy_bundle_is_refused_not_reinterpreted() {
        let (fs, store, _o, _c) = MockAsyncFs::new();
        store.borrow_mut().insert(
            "BUNDLE".to_string(),
            Rc::new(RefCell::new(b"magic = snow_flat_bnd\n".to_vec())),
        );
        assert_eq!(
            block_on(AsyncFlatBundle::open(fs, None, Some(8 << 20), None)).err(),
            Some(BundleError::LegacyHeader)
        );
        let (fs, store2, _o, _c) = MockAsyncFs::new();
        store2.borrow_mut().insert(
            "BUNDLE".to_string(),
            Rc::new(RefCell::new(b"magic = snow_flat_bnd\n".to_vec())),
        );
        assert_eq!(
            block_on(AsyncFlatBundle::create(fs, 1 << 20, 8 << 20, 512)).err(),
            Some(BundleError::LegacyHeader)
        );
    }

    #[cfg(feature = "bundle")]
    #[test]
    fn create_rejects_existing_manifest() {
        let (mut fs, _store, _o, _c) = MockAsyncFs::new();
        block_on(async {
            let mut f = fs
                .open(MANIFEST_NAME, OpenOptions::create_or_truncate())
                .await
                .unwrap();
            write_all_at(&mut f, 0, b"magic = snow_bundle\n")
                .await
                .unwrap();
            fs.close(f).await.unwrap();
            assert_eq!(
                AsyncFlatBundle::create(fs, 1 << 20, 4 << 20, 512)
                    .await
                    .err(),
                Some(BundleError::AlreadyExists)
            );
        });
    }

    #[cfg(feature = "bundle")]
    #[test]
    fn create_with_meta_rejects_a_keyslot_manifest() {
        let (fs, store, _o, _c) = MockAsyncFs::new();
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
            block_on(AsyncFlatBundle::create_with_meta(fs, &meta)).err(),
            Some(BundleError::CipherRequiresAtomicManifest)
        );
        assert!(!store.borrow().contains_key(MANIFEST_NAME));
    }

    #[cfg(feature = "bundle")]
    #[test]
    fn create_with_meta_rejects_non_flat_kind() {
        let (fs, _store, _o, _c) = MockAsyncFs::new();
        let meta = BundleMeta {
            kind: BundleKind::Image { size: 4096 },
            cipher: None,
            has_crc: false,
        };
        assert_eq!(
            block_on(AsyncFlatBundle::create_with_meta(fs, &meta)).err(),
            Some(BundleError::WrongKind)
        );
    }

    #[cfg(feature = "bundle")]
    #[test]
    fn open_rejects_wrong_kind() {
        let (mut fs, _store, _o, _c) = MockAsyncFs::new();
        let meta = BundleMeta {
            kind: BundleKind::Cdr,
            cipher: None,
            has_crc: false,
        };
        block_on(async {
            let bytes = meta.encode().unwrap();
            let mut f = fs
                .open(MANIFEST_NAME, OpenOptions::create_or_truncate())
                .await
                .unwrap();
            write_all_at(&mut f, 0, &bytes).await.unwrap();
            fs.close(f).await.unwrap();
            assert_eq!(
                AsyncFlatBundle::open(fs, None, Some(4096), None)
                    .await
                    .err(),
                Some(BundleError::WrongKind)
            );
        });
    }

    #[cfg(feature = "bundle")]
    #[test]
    fn open_rejects_malformed_manifest() {
        let (mut fs, _store, _o, _c) = MockAsyncFs::new();
        block_on(async {
            let mut f = fs
                .open(MANIFEST_NAME, OpenOptions::create_or_truncate())
                .await
                .unwrap();
            write_all_at(&mut f, 0, b"magic = NOPE\n").await.unwrap();
            fs.close(f).await.unwrap();
            assert_eq!(
                AsyncFlatBundle::open(fs, None, Some(4096), None)
                    .await
                    .err(),
                Some(BundleError::Manifest(ManifestError::BadMagic))
            );
        });
    }

    // ── differential test against the synchronous FlatBundle ────────────
    // Both bundles address the same `Rc<RefCell<Vec<u8>>>` store, so a write
    // through one plane must be exactly what the other plane reads back.

    struct SyncMockFs {
        store: Store,
    }

    struct SyncMockFile {
        data: Rc<RefCell<Vec<u8>>>,
        pos: u64,
        writable: bool,
    }

    impl embedded_io::ErrorType for SyncMockFile {
        type Error = IoErrorKind;
    }

    impl embedded_io::Read for SyncMockFile {
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

    impl embedded_io::Write for SyncMockFile {
        fn write(&mut self, buf: &[u8]) -> Result<usize, Self::Error> {
            if !self.writable {
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

    impl embedded_io::Seek for SyncMockFile {
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

    impl FsStorage for SyncMockFs {
        type File = SyncMockFile;

        fn open(&mut self, path: &str, opts: OpenOptions) -> Result<SyncMockFile, FsError> {
            let mut map = self.store.borrow_mut();
            let present = map.contains_key(path);
            if !present && !opts.create {
                return Err(FsError::NotFound);
            }
            let rc = map.entry(path.to_string()).or_default().clone();
            if opts.truncate {
                rc.borrow_mut().clear();
            }
            Ok(SyncMockFile {
                data: rc,
                pos: 0,
                writable: opts.write,
            })
        }

        fn close(&mut self, _file: SyncMockFile) {}

        fn read_dir(&mut self, _path: &str, _out: &mut [DirEntry]) -> Result<usize, FsError> {
            Ok(0)
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

    #[test]
    fn differential_with_sync_bundle() {
        use crate::flat_bundle::FlatBundle;
        use crate::seekable_storage::{FlatData, WritableFlatData};

        let (af, store, _o, _c) = MockAsyncFs::new();
        let mut ab = mk(af, 512, 4096);
        let pattern: Vec<u8> = (0..700).map(|i| ((i * 7) & 0xFF) as u8).collect();

        // Async write -> sync read (crosses chunks 0, 1 and 2).
        block_on(ab.write_at(300, &pattern)).unwrap();
        let mut sb = FlatBundle::new(
            SyncMockFs {
                store: Rc::clone(&store),
            },
            512,
            4096,
            512,
        )
        .unwrap();
        let mut out = vec![0u8; pattern.len()];
        sb.read_at(300, &mut out).unwrap();
        assert_eq!(out, pattern);

        // Sync write -> async read.
        let sync_pattern: Vec<u8> = (0..900).map(|i| ((i * 3) & 0xFF) as u8).collect();
        sb.write_at(1024, &sync_pattern).unwrap();
        let mut async_out = vec![0u8; sync_pattern.len()];
        block_on(ab.read_at(1024, &mut async_out)).unwrap();
        assert_eq!(async_out, sync_pattern);

        // Holes agree too: a sparse gap reads as zeros through both planes.
        let mut a_hole = vec![0xAAu8; 100];
        let mut s_hole = vec![0xAAu8; 100];
        block_on(ab.read_at(4096 - 100, &mut a_hole)).unwrap();
        sb.read_at(4096 - 100, &mut s_hole).unwrap();
        assert_eq!(a_hole, s_hole);
    }
}
