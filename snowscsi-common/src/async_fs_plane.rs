//! Asynchronous path-addressed filesystem plane + LRU handle cache.
//!
//! [`AsyncFsPlane`] is the `async fn` mirror of
//! [`FsPlane`](crate::fs_plane::FsPlane): random read/write of a file,
//! addressed by `path` + `off`, plus directory scan / remove / sync. It exists
//! so a resource store can serve a recordable-CD bundle on an executor without
//! blocking it on filesystem I/O.
//!
//! [`AsyncFsPlaneAdapter`] implements it over any [`AsyncFsStorage`] by keeping
//! a small LRU cache of open file handles keyed by path, so callers never
//! manage `open`/`close` themselves. Unlike the synchronous adapter it has no
//! destructor: [`AsyncFsStorage::close`] is asynchronous, so dropping the
//! adapter only drops the handles. Call [`AsyncFsPlane::shutdown`] for a
//! deterministic flush-and-close.

use embedded_io::ErrorKind as IoErrorKind;

use crate::async_fs_storage::{AsyncFsFile, AsyncFsStorage};
use crate::fs_storage::{DirEntry, FsError, OpenOptions};

/// Asynchronous filesystem plane.
///
/// `async fn` in a trait is not object-safe, so the plane is used through a
/// generic type parameter rather than `&mut dyn` (same convention as the other
/// asynchronous seams).
///
/// [`read`](Self::read) must fill the whole buffer or report
/// [`FsError::OutOfBounds`] at end-of-file; a backend may return short reads
/// internally, so implementations loop until the buffer is full.
#[allow(async_fn_in_trait)]
pub trait AsyncFsPlane {
    /// Scan the directory at `path`, returning the number of entries written
    /// (`<= out.len()`; a full buffer does not imply exhaustion).
    async fn read_dir(&mut self, path: &str, out: &mut [DirEntry]) -> Result<usize, FsError>;

    /// Read `buf.len()` bytes at byte offset `off` of the file at `path`.
    async fn read(&mut self, path: &str, off: u64, buf: &mut [u8]) -> Result<(), FsError>;

    /// Return the current length in bytes of the file at `path`.
    ///
    /// The default is unsupported: a backend without a size primitive cannot
    /// distinguish a short file from a missing one. Callers that only need a
    /// best-effort prefix (the CD-R track reader) treat `NotFound` as empty.
    async fn len(&mut self, path: &str) -> Result<u64, FsError> {
        let _ = path;
        Err(FsError::Io(IoErrorKind::Unsupported))
    }

    /// Truncate the file at `path` to zero length, creating it when absent.
    ///
    /// The default is unsupported. Callers that reuse a resource id must
    /// truncate before writing a new payload at offset 0.
    async fn truncate(&mut self, path: &str) -> Result<(), FsError> {
        let _ = path;
        Err(FsError::Io(IoErrorKind::Unsupported))
    }

    /// Write `buf` at byte offset `off` of the file at `path` (creating it).
    async fn write(&mut self, path: &str, off: u64, buf: &[u8]) -> Result<(), FsError>;

    /// Remove the file at `path`.
    async fn remove(&mut self, path: &str) -> Result<(), FsError>;

    /// Persist the filesystem.
    async fn sync(&mut self) -> Result<(), FsError>;

    /// Persist the file at `path` to stable storage (per-file fsync).
    ///
    /// Defaults to a plane-wide [`sync`](Self::sync): a backend that cannot
    /// flush one file can still offer the stronger filesystem-wide guarantee.
    async fn sync_file(&mut self, path: &str) -> Result<(), FsError> {
        let _ = path;
        self.sync().await
    }

    /// Flush and close whatever the backend holds, ending its use.
    ///
    /// Defaults to [`sync`](Self::sync): a path-addressed backend with no
    /// handles of its own has nothing to close. An adapter that caches handles
    /// (such as [`AsyncFsPlaneAdapter`]) overrides this to sync and drain the
    /// cache.
    async fn shutdown(&mut self) -> Result<(), FsError> {
        self.sync().await
    }
}

/// One cached open file handle, keyed by `path`.
struct Slot<F: AsyncFsStorage> {
    path: heapless::String<256>,
    file: F::File,
    /// Whether the cached handle was opened read-write (a read may reuse a
    /// writable handle; a write must never reuse a read-only one).
    writable: bool,
    last_used: u64,
}

/// [`AsyncFsPlane`] over any [`AsyncFsStorage`], with a path → handle LRU of
/// `N` slots (default 8). A full cache evicts the least-recently-used handle
/// via [`AsyncFsStorage::close`].
pub struct AsyncFsPlaneAdapter<F: AsyncFsStorage, const N: usize = 8> {
    fs: F,
    slots: heapless::Vec<Slot<F>, N>,
    tick: u64,
}

impl<F: AsyncFsStorage, const N: usize> AsyncFsPlaneAdapter<F, N> {
    /// Wrap `fs` with an empty handle cache.
    pub fn new(fs: F) -> Self {
        Self {
            fs,
            slots: heapless::Vec::new(),
            tick: 0,
        }
    }

    /// Look up the cached slot for `path`, bumping its recency on a hit.
    fn touch(&mut self, path: &str) -> Option<usize> {
        let i = self.slots.iter().position(|s| s.path.as_str() == path)?;
        self.slots[i].last_used = self.tick;
        self.tick = self.tick.wrapping_add(1);
        Some(i)
    }

    /// Evict the least-recently-used slot when the cache is full, closing its
    /// handle via [`AsyncFsStorage::close`].
    async fn evict_one(&mut self) -> Result<(), FsError> {
        if self.slots.is_empty() || self.slots.len() < N {
            return Ok(());
        }
        let mut min_i = 0;
        for i in 1..self.slots.len() {
            if self.slots[i].last_used < self.slots[min_i].last_used {
                min_i = i;
            }
        }
        let slot = self.slots.swap_remove(min_i);
        self.fs.close(slot.file).await
    }

    /// Cache `file` under `path`, evicting first if needed. Returns the slot
    /// index. A path longer than the 256-byte key (or a zero-capacity cache)
    /// closes `file` and reports an I/O error rather than leaking the handle.
    async fn insert(
        &mut self,
        path: &str,
        file: F::File,
        writable: bool,
    ) -> Result<usize, FsError> {
        self.evict_one().await?;
        let mut p = heapless::String::<256>::new();
        if p.push_str(path).is_err() {
            let _ = self.fs.close(file).await;
            return Err(FsError::Io(IoErrorKind::Other));
        }
        if let Err(slot) = self.slots.push(Slot {
            path: p,
            file,
            writable,
            last_used: self.tick,
        }) {
            let _ = self.fs.close(slot.file).await;
            return Err(FsError::Io(IoErrorKind::Other));
        }
        self.tick = self.tick.wrapping_add(1);
        Ok(self.slots.len() - 1)
    }

    /// Open `path` and cache it, returning its slot index.
    async fn open_into(
        &mut self,
        path: &str,
        opts: OpenOptions,
        writable: bool,
    ) -> Result<usize, FsError> {
        let file = self.fs.open(path, opts).await?;
        self.insert(path, file, writable).await
    }
}

/// Read exactly `buf.len()` bytes at `off`, looping over short reads.
///
/// A zero-length read before the buffer is full is end-of-file, reported as
/// [`FsError::OutOfBounds`].
async fn read_exact_at<F: AsyncFsFile>(
    file: &mut F,
    mut off: u64,
    mut buf: &mut [u8],
) -> Result<(), FsError> {
    while !buf.is_empty() {
        let n = file.read_at(off, buf).await?;
        if n == 0 {
            return Err(FsError::OutOfBounds);
        }
        if n > buf.len() {
            return Err(FsError::Io(IoErrorKind::Other));
        }
        off += n as u64;
        buf = &mut buf[n..];
    }
    Ok(())
}

/// Write all of `buf` at `off`, looping over short writes.
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
        if n > buf.len() {
            return Err(FsError::Io(IoErrorKind::Other));
        }
        off += n as u64;
        buf = &buf[n..];
    }
    Ok(())
}

impl<F: AsyncFsStorage, const N: usize> AsyncFsPlane for AsyncFsPlaneAdapter<F, N> {
    async fn read_dir(&mut self, path: &str, out: &mut [DirEntry]) -> Result<usize, FsError> {
        self.fs.read_dir(path, out).await
    }

    async fn read(&mut self, path: &str, off: u64, buf: &mut [u8]) -> Result<(), FsError> {
        // A read may reuse any cached handle (read-only or writable).
        let i = match self.touch(path) {
            Some(i) => i,
            None => {
                self.open_into(path, OpenOptions::read_only(), false)
                    .await?
            }
        };
        read_exact_at(&mut self.slots[i].file, off, buf).await
    }

    async fn len(&mut self, path: &str) -> Result<u64, FsError> {
        // A size query is a read-only operation and reuses any cached handle.
        let i = match self.touch(path) {
            Some(i) => i,
            None => {
                self.open_into(path, OpenOptions::read_only(), false)
                    .await?
            }
        };
        self.slots[i].file.len().await
    }

    async fn truncate(&mut self, path: &str) -> Result<(), FsError> {
        // Drop any cached handle first: the reopened handle must be the one
        // carrying the truncation, not a stale read-only view.
        if let Some(i) = self.slots.iter().position(|s| s.path.as_str() == path) {
            let slot = self.slots.swap_remove(i);
            let _ = self.fs.close(slot.file).await;
        }
        self.open_into(path, OpenOptions::create_or_truncate(), true)
            .await?;
        Ok(())
    }

    async fn write(&mut self, path: &str, off: u64, buf: &[u8]) -> Result<(), FsError> {
        // A write must reuse a cached handle only if it is writable; a cached
        // read-only handle is closed and reopened read-write (a read must never
        // poison a later write).
        let i = match self.touch(path) {
            Some(i) if self.slots[i].writable => i,
            Some(i) => {
                let slot = self.slots.swap_remove(i);
                let _ = self.fs.close(slot.file).await;
                self.open_into(path, OpenOptions::open_or_create(), true)
                    .await?
            }
            None => {
                self.open_into(path, OpenOptions::open_or_create(), true)
                    .await?
            }
        };
        write_all_at(&mut self.slots[i].file, off, buf).await
    }

    async fn remove(&mut self, path: &str) -> Result<(), FsError> {
        if let Some(i) = self.slots.iter().position(|s| s.path.as_str() == path) {
            let slot = self.slots.swap_remove(i);
            let _ = self.fs.close(slot.file).await;
        }
        self.fs.remove(path).await
    }

    async fn sync(&mut self) -> Result<(), FsError> {
        self.fs.sync().await
    }

    async fn sync_file(&mut self, path: &str) -> Result<(), FsError> {
        if let Some(i) = self.touch(path) {
            if self.slots[i].writable {
                // A buffered backend must see the cached handle's bytes before
                // the fsync; a read-only handle has nothing of ours to flush.
                self.slots[i].file.flush().await?;
            }
        }
        self.fs.sync_file(path).await
    }

    async fn shutdown(&mut self) -> Result<(), FsError> {
        // Flush buffered writes held by cached handles before the backend-wide
        // sync, then close every handle. Errors do not stop the remaining
        // work; the first one is returned.
        let mut first = None;
        for slot in self.slots.iter_mut() {
            if slot.writable {
                if let Err(e) = slot.file.flush().await {
                    first.get_or_insert(e);
                }
            }
        }
        if let Err(e) = self.fs.sync().await {
            first.get_or_insert(e);
        }
        while let Some(slot) = self.slots.pop() {
            if let Err(e) = self.fs.close(slot.file).await {
                first.get_or_insert(e);
            }
        }
        match first {
            Some(e) => Err(e),
            None => Ok(()),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
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

    // ── Shared in-memory AsyncFsStorage mock ────────────────────────────
    // The store is `Rc<RefCell<…>>` so a fresh backend can reopen the same
    // files, and close/flush/sync counters record handle lifecycle.

    type Store = Rc<RefCell<HashMap<String, Rc<RefCell<Vec<u8>>>>>>;
    type SyncLog = Rc<RefCell<Vec<String>>>;

    #[derive(Clone)]
    struct Counters {
        opens: Rc<Cell<usize>>,
        closes: Rc<Cell<usize>>,
        flushes: Rc<Cell<usize>>,
        plane_syncs: Rc<Cell<usize>>,
        sync_files: SyncLog,
        fail_close: Rc<Cell<bool>>,
    }

    impl Counters {
        fn new() -> Self {
            Self {
                opens: Rc::new(Cell::new(0)),
                closes: Rc::new(Cell::new(0)),
                flushes: Rc::new(Cell::new(0)),
                plane_syncs: Rc::new(Cell::new(0)),
                sync_files: Rc::new(RefCell::new(Vec::new())),
                fail_close: Rc::new(Cell::new(false)),
            }
        }
    }

    struct MockAsyncFs {
        store: Store,
        counters: Counters,
    }

    impl MockAsyncFs {
        fn new() -> (Self, Store, Counters) {
            let store: Store = Rc::default();
            let counters = Counters::new();
            (
                Self {
                    store: Rc::clone(&store),
                    counters: counters.clone(),
                },
                store,
                counters,
            )
        }

        fn from_store(store: &Store) -> Self {
            Self {
                store: Rc::clone(store),
                counters: Counters::new(),
            }
        }
    }

    struct MockAsyncFile {
        data: Rc<RefCell<Vec<u8>>>,
        writable: bool,
        counters: Counters,
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
            self.counters.flushes.set(self.counters.flushes.get() + 1);
            Ok(())
        }

        async fn len(&mut self) -> Result<u64, FsError> {
            Ok(self.data.borrow().len() as u64)
        }
    }

    impl AsyncFsStorage for MockAsyncFs {
        type File = MockAsyncFile;

        async fn open(&mut self, path: &str, opts: OpenOptions) -> Result<MockAsyncFile, FsError> {
            self.counters.opens.set(self.counters.opens.get() + 1);
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
                counters: self.counters.clone(),
            })
        }

        async fn close(&mut self, _file: MockAsyncFile) -> Result<(), FsError> {
            self.counters.closes.set(self.counters.closes.get() + 1);
            if self.counters.fail_close.get() {
                return Err(FsError::Io(IoErrorKind::Other));
            }
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
            self.counters
                .plane_syncs
                .set(self.counters.plane_syncs.get() + 1);
            Ok(())
        }

        async fn sync_file(&mut self, path: &str) -> Result<(), FsError> {
            self.counters.sync_files.borrow_mut().push(path.to_string());
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

    /// Backend that keeps the default [`AsyncFsStorage::sync_file`].
    struct DefaultSyncFs(MockAsyncFs);

    impl AsyncFsStorage for DefaultSyncFs {
        type File = MockAsyncFile;

        async fn open(&mut self, path: &str, opts: OpenOptions) -> Result<MockAsyncFile, FsError> {
            self.0.open(path, opts).await
        }

        async fn close(&mut self, file: MockAsyncFile) -> Result<(), FsError> {
            self.0.close(file).await
        }

        async fn read_dir(&mut self, path: &str, out: &mut [DirEntry]) -> Result<usize, FsError> {
            self.0.read_dir(path, out).await
        }

        fn root(&self) -> &str {
            self.0.root()
        }

        async fn sync(&mut self) -> Result<(), FsError> {
            self.0.sync().await
        }

        async fn remove(&mut self, path: &str) -> Result<(), FsError> {
            self.0.remove(path).await
        }
    }

    #[test]
    fn write_read_roundtrip() {
        let (fs, _store, _c) = MockAsyncFs::new();
        let mut p = AsyncFsPlaneAdapter::<_, 8>::new(fs);
        block_on(async {
            p.write("a", 0, b"hello").await.unwrap();
            let mut out = [0u8; 5];
            p.read("a", 0, &mut out).await.unwrap();
            assert_eq!(&out, b"hello");
        });
    }

    #[test]
    fn read_past_eof_is_out_of_bounds() {
        let (fs, _store, _c) = MockAsyncFs::new();
        let mut p = AsyncFsPlaneAdapter::<_, 8>::new(fs);
        block_on(async {
            p.write("a", 0, b"abc").await.unwrap();
            assert_eq!(
                p.read("a", 0, &mut [0u8; 4]).await,
                Err(FsError::OutOfBounds)
            );
            // A read starting past EOF is the same error, not a short buffer.
            assert_eq!(
                p.read("a", 9, &mut [0u8; 1]).await,
                Err(FsError::OutOfBounds)
            );
        });
    }

    #[test]
    fn read_then_write_reopens_read_write() {
        // A read caches a read-only handle; a later write to the same path must
        // close it and reopen read-write instead of failing.
        let (fs, store, _c) = MockAsyncFs::new();
        block_on(async {
            AsyncFsPlaneAdapter::<_, 8>::new(fs)
                .write("a", 0, b"hello")
                .await
                .unwrap();
        });
        let mut p = AsyncFsPlaneAdapter::<_, 8>::new(MockAsyncFs::from_store(&store));
        block_on(async {
            let mut out = [0u8; 5];
            p.read("a", 0, &mut out).await.unwrap();
            assert_eq!(&out, b"hello");

            p.write("a", 5, b" world").await.unwrap();
            let mut out2 = [0u8; 11];
            p.read("a", 0, &mut out2).await.unwrap();
            assert_eq!(&out2, b"hello world");
        });
    }

    #[test]
    fn len_and_truncate() {
        let (fs, _store, _c) = MockAsyncFs::new();
        let mut p = AsyncFsPlaneAdapter::<_, 8>::new(fs);
        block_on(async {
            p.write("a", 0, b"abc").await.unwrap();
            assert_eq!(p.len("a").await, Ok(3));
            p.write("a", 5, b"x").await.unwrap();
            assert_eq!(p.len("a").await, Ok(6), "seek-end reports the grown size");
            assert_eq!(p.len("missing").await, Err(FsError::NotFound));

            p.truncate("a").await.unwrap();
            assert_eq!(p.len("a").await, Ok(0));
            assert_eq!(
                p.read("a", 0, &mut [0u8; 1]).await,
                Err(FsError::OutOfBounds)
            );

            p.truncate("new").await.unwrap();
            assert_eq!(p.len("new").await, Ok(0));
            p.write("new", 0, b"z").await.unwrap();
            let mut out = [0u8; 1];
            p.read("new", 0, &mut out).await.unwrap();
            assert_eq!(&out, b"z");
        });
    }

    #[test]
    fn remove_drops_handle_and_file() {
        let (fs, store, c) = MockAsyncFs::new();
        let mut p = AsyncFsPlaneAdapter::<_, 8>::new(fs);
        block_on(async {
            p.write("a", 0, b"x").await.unwrap();
            assert!(store.borrow().contains_key("a"));
            let before = c.closes.get();

            p.remove("a").await.unwrap();
            assert_eq!(c.closes.get(), before + 1);
            assert!(!store.borrow().contains_key("a"));
            assert_eq!(p.read("a", 0, &mut [0u8; 1]).await, Err(FsError::NotFound));
        });
    }

    #[test]
    fn lru_evicts_least_recently_used() {
        let (fs, _store, c) = MockAsyncFs::new();
        let mut p = AsyncFsPlaneAdapter::<_, 2>::new(fs);
        block_on(async {
            p.write("a", 0, b"A").await.unwrap();
            p.write("b", 0, b"B").await.unwrap();
            // Cache full: opening "c" evicts "a" (the LRU slot).
            p.write("c", 0, b"C").await.unwrap();
        });

        assert_eq!(p.slots.len(), 2);
        assert_eq!(c.closes.get(), 1);
        assert!(p.slots.iter().all(|s| s.path.as_str() != "a"));
        assert!(p.slots.iter().any(|s| s.path.as_str() == "b"));
        assert!(p.slots.iter().any(|s| s.path.as_str() == "c"));
    }

    #[test]
    fn sync_file_flushes_writable_handle_and_does_not_sync_plane() {
        let (fs, _store, c) = MockAsyncFs::new();
        let mut p = AsyncFsPlaneAdapter::<_, 8>::new(fs);
        block_on(async {
            p.write("a", 0, b"abc").await.unwrap();
            let flushes = c.flushes.get();
            p.sync_file("a").await.unwrap();
            assert_eq!(c.flushes.get(), flushes + 1);
        });
        assert_eq!(&*c.sync_files.borrow(), &["a".to_string()]);
        assert_eq!(
            c.plane_syncs.get(),
            0,
            "a per-file sync must not fall back to the plane-wide sync"
        );
    }

    #[test]
    fn default_sync_file_falls_back_to_the_backend_sync() {
        let (fs, _store, c) = MockAsyncFs::new();
        let mut p = AsyncFsPlaneAdapter::<_, 8>::new(DefaultSyncFs(fs));
        block_on(async {
            assert_eq!(p.sync_file("a").await, Ok(()));
        });
        assert!(c.sync_files.borrow().is_empty());
        assert_eq!(
            c.plane_syncs.get(),
            1,
            "a backend without a per-file primitive must fall back to its own sync"
        );
    }

    #[test]
    fn read_dir_and_sync_delegate() {
        let (fs, _store, c) = MockAsyncFs::new();
        let mut p = AsyncFsPlaneAdapter::<_, 8>::new(fs);
        block_on(async {
            p.write("a", 0, b"abc").await.unwrap();
            p.write("b", 0, b"de").await.unwrap();

            let mut entries: [DirEntry; 8] = core::array::from_fn(|_| DirEntry {
                name: heapless::String::new(),
                is_dir: false,
                size: 0,
            });
            let n = p.read_dir("", &mut entries).await.unwrap();
            assert_eq!(n, 2);
            assert!(entries
                .iter()
                .any(|e| e.name.as_str() == "a" && e.size == 3));
            assert!(entries
                .iter()
                .any(|e| e.name.as_str() == "b" && e.size == 2));

            p.sync().await.unwrap();
        });
        assert_eq!(c.plane_syncs.get(), 1);
    }

    #[test]
    fn shutdown_syncs_then_closes_every_cached_handle() {
        let (fs, _store, c) = MockAsyncFs::new();
        let mut p = AsyncFsPlaneAdapter::<_, 8>::new(fs);
        let open_len = block_on(async {
            for i in 0..3u8 {
                let name = ["a", "b", "c"][usize::from(i)];
                p.write(name, 0, &[i]).await.unwrap();
            }
            p.slots.len()
        });
        assert_eq!(open_len, 3);
        block_on(p.shutdown()).unwrap();
        assert_eq!(c.plane_syncs.get(), 1);
        // Exactly the cached handles were closed (no double close).
        assert_eq!(c.closes.get(), open_len);
    }

    #[test]
    fn shutdown_reports_the_first_close_error_but_closes_everything() {
        let (fs, _store, c) = MockAsyncFs::new();
        let mut p = AsyncFsPlaneAdapter::<_, 8>::new(fs);
        block_on(async {
            p.write("a", 0, b"A").await.unwrap();
            p.write("b", 0, b"B").await.unwrap();
            c.fail_close.set(true);
            assert_eq!(p.shutdown().await, Err(FsError::Io(IoErrorKind::Other)));
        });
        assert_eq!(c.closes.get(), 2, "every cached handle was still closed");
    }
}
