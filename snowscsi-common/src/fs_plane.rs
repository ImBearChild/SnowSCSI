//! Path-addressed filesystem plane + LRU handle cache.
//!
//! [`FsPlane`] is the object-safe seam a driver holds: "random read/write of a
//! file, addressed by `path` + `off`", plus directory scan / remove / sync.
//! [`FsPlaneAdapter`] implements it over any [`FsStorage`] by keeping a small
//! LRU cache of open file handles keyed by path, so callers never manage
//! `open`/`close` themselves.

use embedded_io::Error as _;
use embedded_io::ErrorKind as IoErrorKind;
use embedded_io::{Read as _, ReadExactError, Seek as _, Write as _};

use crate::fs_storage::{DirEntry, FsError, FsStorage, OpenOptions};

/// Object-safe filesystem plane.
pub trait FsPlane {
    /// Scan the directory at `path`, returning the number of entries written
    /// (`<= out.len()`; a full buffer does not imply exhaustion).
    fn read_dir(&mut self, path: &str, out: &mut [DirEntry]) -> Result<usize, FsError>;

    /// Read `buf.len()` bytes at byte offset `off` of the file at `path`.
    fn read(&mut self, path: &str, off: u64, buf: &mut [u8]) -> Result<(), FsError>;

    /// Return the current length in bytes of the file at `path`.
    ///
    /// The default is unsupported: a backend without a size primitive cannot
    /// distinguish a short file from a missing one. Callers that only need a
    /// best-effort prefix (the CD-R track reader) treat `NotFound` as empty.
    fn len(&mut self, path: &str) -> Result<u64, FsError> {
        let _ = path;
        Err(FsError::Io(IoErrorKind::Unsupported))
    }

    /// Truncate the file at `path` to zero length, creating it when absent.
    ///
    /// The default is unsupported. Callers that reuse a resource id must
    /// truncate before writing a new payload at offset 0.
    fn truncate(&mut self, path: &str) -> Result<(), FsError> {
        let _ = path;
        Err(FsError::Io(IoErrorKind::Unsupported))
    }

    /// Write `buf` at byte offset `off` of the file at `path` (creating it).
    fn write(&mut self, path: &str, off: u64, buf: &[u8]) -> Result<(), FsError>;

    /// Remove the file at `path`.
    fn remove(&mut self, path: &str) -> Result<(), FsError>;

    /// Persist the filesystem.
    fn sync(&mut self) -> Result<(), FsError>;

    /// Persist the file at `path` to stable storage (per-file fsync).
    ///
    /// Defaults to a plane-wide [`sync`](Self::sync): a backend that cannot
    /// flush one file can still offer the stronger filesystem-wide guarantee.
    fn sync_file(&mut self, path: &str) -> Result<(), FsError> {
        let _ = path;
        self.sync()
    }
}

/// One cached open file handle, keyed by `path`.
struct Slot<F: FsStorage> {
    path: heapless::String<256>,
    file: F::File,
    /// Whether the cached handle was opened read-write (a read may reuse a
    /// writable handle; a write must never reuse a read-only one).
    writable: bool,
    last_used: u64,
}

/// `FsPlane` over any [`FsStorage`], with a path → handle LRU of `N` slots
/// (default 8). A full cache evicts the least-recently-used handle via
/// [`FsStorage::close`].
pub struct FsPlaneAdapter<F: FsStorage, const N: usize = 8> {
    fs: F,
    slots: heapless::Vec<Slot<F>, N>,
    tick: u64,
}

impl<F: FsStorage, const N: usize> FsPlaneAdapter<F, N> {
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
    /// handle via [`FsStorage::close`].
    fn evict_one(&mut self) {
        if self.slots.is_empty() || self.slots.len() < N {
            return;
        }
        let mut min_i = 0;
        for i in 1..self.slots.len() {
            if self.slots[i].last_used < self.slots[min_i].last_used {
                min_i = i;
            }
        }
        let slot = self.slots.swap_remove(min_i);
        self.fs.close(slot.file);
    }

    /// Cache `file` under `path`, evicting first if needed. Returns the slot
    /// index. A path longer than the 256-byte key (or a zero-capacity cache)
    /// closes `file` and reports an I/O error rather than leaking the handle.
    fn insert(&mut self, path: &str, file: F::File, writable: bool) -> Result<usize, FsError> {
        self.evict_one();
        let mut p = heapless::String::<256>::new();
        if p.push_str(path).is_err() {
            self.fs.close(file);
            return Err(FsError::Io(IoErrorKind::Other));
        }
        if let Err(slot) = self.slots.push(Slot {
            path: p,
            file,
            writable,
            last_used: self.tick,
        }) {
            self.fs.close(slot.file);
            return Err(FsError::Io(IoErrorKind::Other));
        }
        self.tick = self.tick.wrapping_add(1);
        Ok(self.slots.len() - 1)
    }
}

impl<F: FsStorage, const N: usize> FsPlane for FsPlaneAdapter<F, N> {
    fn read_dir(&mut self, path: &str, out: &mut [DirEntry]) -> Result<usize, FsError> {
        self.fs.read_dir(path, out)
    }

    fn read(&mut self, path: &str, off: u64, buf: &mut [u8]) -> Result<(), FsError> {
        // A read may reuse any cached handle (read-only or writable).
        let i = match self.touch(path) {
            Some(i) => i,
            None => {
                let file = self.fs.open(path, OpenOptions::read_only())?;
                self.insert(path, file, false)?
            }
        };
        let file = &mut self.slots[i].file;
        file.seek(embedded_io::SeekFrom::Start(off))
            .map_err(|e| FsError::Io(e.kind()))?;
        file.read_exact(buf).map_err(|e| match e {
            ReadExactError::UnexpectedEof => FsError::OutOfBounds,
            ReadExactError::Other(e) => FsError::Io(e.kind()),
        })
    }

    fn len(&mut self, path: &str) -> Result<u64, FsError> {
        // Seek-to-end is the only size query the embedded-io file seam has.
        let i = match self.touch(path) {
            Some(i) => i,
            None => {
                let file = self.fs.open(path, OpenOptions::read_only())?;
                self.insert(path, file, false)?
            }
        };
        let file = &mut self.slots[i].file;
        file.seek(embedded_io::SeekFrom::End(0))
            .map_err(|e| FsError::Io(e.kind()))
    }

    fn truncate(&mut self, path: &str) -> Result<(), FsError> {
        // Drop any cached handle first: the reopened handle must be the one
        // carrying the truncation, not a stale read-only view.
        if let Some(i) = self.slots.iter().position(|s| s.path.as_str() == path) {
            let slot = self.slots.swap_remove(i);
            self.fs.close(slot.file);
        }
        let file = self.fs.open(path, OpenOptions::create_or_truncate())?;
        self.insert(path, file, true)?;
        Ok(())
    }

    fn write(&mut self, path: &str, off: u64, buf: &[u8]) -> Result<(), FsError> {
        // A write must reuse a cached handle only if it is writable; a cached
        // read-only handle is closed and reopened read-write (a read must never
        // poison a later write).
        let i = match self.touch(path) {
            Some(i) if self.slots[i].writable => i,
            Some(i) => {
                let slot = self.slots.swap_remove(i);
                self.fs.close(slot.file);
                let file = self.fs.open(path, OpenOptions::open_or_create())?;
                self.insert(path, file, true)?
            }
            None => {
                let file = self.fs.open(path, OpenOptions::open_or_create())?;
                self.insert(path, file, true)?
            }
        };
        let file = &mut self.slots[i].file;
        file.seek(embedded_io::SeekFrom::Start(off))
            .map_err(|e| FsError::Io(e.kind()))?;
        file.write_all(buf).map_err(|e| FsError::Io(e.kind()))
    }

    fn remove(&mut self, path: &str) -> Result<(), FsError> {
        if let Some(i) = self.slots.iter().position(|s| s.path.as_str() == path) {
            let slot = self.slots.swap_remove(i);
            self.fs.close(slot.file);
        }
        self.fs.remove(path)
    }

    fn sync(&mut self) -> Result<(), FsError> {
        self.fs.sync()
    }

    fn sync_file(&mut self, path: &str) -> Result<(), FsError> {
        if let Some(i) = self.touch(path) {
            if self.slots[i].writable {
                // A buffered backend must see the cached handle's bytes before
                // the fsync; a read-only handle has nothing of ours to flush.
                self.slots[i]
                    .file
                    .flush()
                    .map_err(|e| FsError::Io(e.kind()))?;
            }
        }
        self.fs.sync_file(path)
    }
}

impl<F: FsStorage, const N: usize> Drop for FsPlaneAdapter<F, N> {
    fn drop(&mut self) {
        // Close every cached handle (the `FsStorage` seam owns close).
        while let Some(slot) = self.slots.pop() {
            self.fs.close(slot.file);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::cell::{Cell, RefCell};
    use std::collections::HashMap;
    use std::rc::Rc;

    // ── Shared in-memory FsStorage mock ─────────────────────────────────
    // `common` cannot see `scsi`'s `StdFsBackend` (dependency direction), so
    // unit tests run against an in-memory store. The store is
    // `Rc<RefCell<…>>` so multiple adapters can share it (data survives a
    // drop) and a close counter records handle lifecycle.

    type Store = Rc<RefCell<HashMap<String, Rc<RefCell<Vec<u8>>>>>>;
    type SyncLog = Rc<RefCell<Vec<String>>>;
    type SyncCount = Rc<Cell<usize>>;

    struct MockFs {
        store: Store,
        closes: Rc<Cell<usize>>,
        /// Paths passed to `sync_file`, in call order.
        sync_files: SyncLog,
        /// Number of plane-wide `sync` calls.
        plane_syncs: SyncCount,
    }

    impl MockFs {
        fn new() -> (Self, Store, Rc<Cell<usize>>) {
            let (fs, store, closes, _, _) = Self::tracked();
            (fs, store, closes)
        }

        fn tracked() -> (Self, Store, Rc<Cell<usize>>, SyncLog, SyncCount) {
            let store: Store = Rc::default();
            let closes = Rc::new(Cell::new(0));
            let sync_files = Rc::new(RefCell::new(Vec::new()));
            let plane_syncs = Rc::new(Cell::new(0));
            (
                Self {
                    store: Rc::clone(&store),
                    closes: Rc::clone(&closes),
                    sync_files: Rc::clone(&sync_files),
                    plane_syncs: Rc::clone(&plane_syncs),
                },
                store,
                closes,
                sync_files,
                plane_syncs,
            )
        }

        /// A fresh backend over an existing store (fresh close/sync counters).
        fn with_store(store: &Store) -> Self {
            Self {
                store: Rc::clone(store),
                closes: Rc::new(Cell::new(0)),
                sync_files: Rc::new(RefCell::new(Vec::new())),
                plane_syncs: Rc::new(Cell::new(0)),
            }
        }
    }

    /// Backend that keeps the default [`FsStorage::sync_file`] (delegates to
    /// the backend-wide `sync`).
    struct DefaultSyncFs(MockFs);

    impl FsStorage for DefaultSyncFs {
        type File = MockFile;

        fn open(&mut self, path: &str, opts: OpenOptions) -> Result<MockFile, FsError> {
            self.0.open(path, opts)
        }

        fn close(&mut self, file: MockFile) {
            self.0.close(file);
        }

        fn read_dir(&mut self, path: &str, out: &mut [DirEntry]) -> Result<usize, FsError> {
            self.0.read_dir(path, out)
        }

        fn root(&self) -> &str {
            self.0.root()
        }

        fn sync(&mut self) -> Result<(), FsError> {
            self.0.sync()
        }

        fn remove(&mut self, path: &str) -> Result<(), FsError> {
            self.0.remove(path)
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
            self.closes.set(self.closes.get() + 1);
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
            self.plane_syncs.set(self.plane_syncs.get() + 1);
            Ok(())
        }

        fn sync_file(&mut self, path: &str) -> Result<(), FsError> {
            self.sync_files.borrow_mut().push(path.to_string());
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
    fn write_read_roundtrip() {
        let (fs, _store, _closes) = MockFs::new();
        let mut p = FsPlaneAdapter::<_, 8>::new(fs);
        p.write("a", 0, b"hello").unwrap();
        let mut out = [0u8; 5];
        p.read("a", 0, &mut out).unwrap();
        assert_eq!(&out, b"hello");
    }

    #[test]
    fn read_then_write_reopens_read_write() {
        // Regression: a read caches a read-only handle; a later write to the
        // same path must close it and reopen read-write instead of failing.
        let (fs, store, _closes) = MockFs::new();
        {
            let mut p = FsPlaneAdapter::<_, 8>::new(fs);
            p.write("a", 0, b"hello").unwrap();
        }
        let mut p = FsPlaneAdapter::<_, 8>::new(MockFs::with_store(&store));

        let mut out = [0u8; 5];
        p.read("a", 0, &mut out).unwrap();
        assert_eq!(&out, b"hello");

        p.write("a", 5, b" world").unwrap();
        let mut out2 = [0u8; 11];
        p.read("a", 0, &mut out2).unwrap();
        assert_eq!(&out2, b"hello world");
    }

    #[test]
    fn remove_drops_handle_and_file() {
        let (fs, store, closes) = MockFs::new();
        let mut p = FsPlaneAdapter::<_, 8>::new(fs);
        p.write("a", 0, b"x").unwrap();
        assert!(store.borrow().contains_key("a"));
        let before = closes.get();

        p.remove("a").unwrap();
        assert_eq!(closes.get(), before + 1);
        assert!(!store.borrow().contains_key("a"));
        assert_eq!(p.read("a", 0, &mut [0u8; 1]), Err(FsError::NotFound));
    }

    #[test]
    fn lru_evicts_least_recently_used() {
        let (fs, _store, closes) = MockFs::new();
        let mut p = FsPlaneAdapter::<_, 2>::new(fs);
        p.write("a", 0, b"A").unwrap();
        p.write("b", 0, b"B").unwrap();
        // Cache full: opening "c" evicts "a" (the LRU slot).
        p.write("c", 0, b"C").unwrap();

        assert_eq!(p.slots.len(), 2);
        assert_eq!(closes.get(), 1);
        assert!(p.slots.iter().all(|s| s.path.as_str() != "a"));
        assert!(p.slots.iter().any(|s| s.path.as_str() == "b"));
        assert!(p.slots.iter().any(|s| s.path.as_str() == "c"));
    }

    #[test]
    fn read_past_eof_is_out_of_bounds() {
        let (fs, _store, _closes) = MockFs::new();
        let mut p = FsPlaneAdapter::<_, 8>::new(fs);
        p.write("a", 0, b"abc").unwrap();
        assert_eq!(p.read("a", 0, &mut [0u8; 4]), Err(FsError::OutOfBounds));
    }

    #[test]
    fn len_reports_file_size_and_missing_is_not_found() {
        let (fs, _store, _closes) = MockFs::new();
        let mut p = FsPlaneAdapter::<_, 8>::new(fs);
        p.write("a", 0, b"abc").unwrap();
        assert_eq!(p.len("a"), Ok(3));
        p.write("a", 5, b"x").unwrap();
        assert_eq!(p.len("a"), Ok(6), "seek-end reports the grown size");
        assert_eq!(p.len("missing"), Err(FsError::NotFound));
    }

    #[test]
    fn truncate_clears_an_existing_file_and_creates_a_missing_one() {
        let (fs, _store, _closes) = MockFs::new();
        let mut p = FsPlaneAdapter::<_, 8>::new(fs);
        p.write("a", 0, b"abcdef").unwrap();
        p.truncate("a").unwrap();
        assert_eq!(p.len("a"), Ok(0));
        assert_eq!(p.read("a", 0, &mut [0u8; 1]), Err(FsError::OutOfBounds));

        p.truncate("new").unwrap();
        assert_eq!(p.len("new"), Ok(0));
        p.write("new", 0, b"z").unwrap();
        let mut out = [0u8; 1];
        p.read("new", 0, &mut out).unwrap();
        assert_eq!(&out, b"z");
    }

    #[test]
    fn read_missing_file_is_not_found() {
        let (fs, _store, _closes) = MockFs::new();
        let mut p = FsPlaneAdapter::<_, 8>::new(fs);
        assert_eq!(p.read("missing", 0, &mut [0u8; 1]), Err(FsError::NotFound));
    }

    #[test]
    fn read_dir_and_sync_delegate() {
        let (fs, _store, _closes) = MockFs::new();
        let mut p = FsPlaneAdapter::<_, 8>::new(fs);
        p.write("a", 0, b"abc").unwrap();
        p.write("b", 0, b"de").unwrap();

        let mut entries: [DirEntry; 8] = core::array::from_fn(|_| DirEntry {
            name: heapless::String::new(),
            is_dir: false,
            size: 0,
        });
        let n = p.read_dir("", &mut entries).unwrap();
        assert_eq!(n, 2);
        assert!(entries
            .iter()
            .any(|e| e.name.as_str() == "a" && e.size == 3));
        assert!(entries
            .iter()
            .any(|e| e.name.as_str() == "b" && e.size == 2));

        p.sync().unwrap();
    }

    #[test]
    fn sync_file_is_per_path_and_does_not_flush_the_plane() {
        let (fs, _store, _closes, sync_files, plane_syncs) = MockFs::tracked();
        let mut p = FsPlaneAdapter::<_, 8>::new(fs);
        p.sync_file("a").unwrap();
        assert_eq!(&*sync_files.borrow(), &["a".to_string()]);
        assert_eq!(
            plane_syncs.get(),
            0,
            "a per-file sync must not fall back to the plane-wide sync"
        );
    }

    #[test]
    fn default_sync_file_falls_back_to_the_backend_sync() {
        let (fs, _store, _closes, sync_files, plane_syncs) = MockFs::tracked();
        let mut p = FsPlaneAdapter::<_, 8>::new(DefaultSyncFs(fs));
        assert_eq!(p.sync_file("a"), Ok(()));
        assert!(sync_files.borrow().is_empty());
        assert_eq!(
            plane_syncs.get(),
            1,
            "a backend without a per-file primitive must fall back to its own sync"
        );
    }
}
