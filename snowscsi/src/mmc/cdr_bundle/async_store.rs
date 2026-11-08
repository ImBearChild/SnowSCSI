//! Asynchronous resource store for a recordable-CD (CD-R/CD-RW) bundle.
//!
//! This is the `async fn` mirror of the application-side synchronous bundle
//! store: the medium addresses files by resource id (`0` = aggregate sync,
//! `1`/`2` = `toc.0`/`toc.1`, `16 + n` = `track_<n>.bin`), so this type owns
//! the [`AsyncFsPlane`] seam plus the geometry restored from (or requested
//! for) the disc.
//!
//! # Resource contract
//!
//! The wire contract is the one documented by
//! [`cdr_bundle`](super): `0` is the aggregate flush, `1`/`2` are the strict
//! TOC slots, `16 + n` is track `n`, and any other id is a contract fault.
//!
//! - A track read returns the readable prefix followed by zeros: a missing or
//!   short `track_<n>.bin` is an empty/partial track, never an error.
//! - The first write at offset `0` truncates the track first, so a reused
//!   resource id cannot inherit a stale tail.
//! - A TOC slot read is strict: a missing or short slot is an error, never a
//!   zero-filled body. Writes are plain random writes (a header write at
//!   offset `0` must not truncate the body already written at offset 256).
//!
//! Every successful track/TOC write marks the resource dirty.
//! [`AsyncCdrStore::sync`] fsyncs each dirty file once and then settles the
//! plane-wide flush; [`AsyncCdrStore::sync_resource`] does the same for one
//! resource. A file that vanished since its write has nothing left to make
//! durable, so `NotFound` on a per-file sync is success.
//!
//! # No orphan cleanup
//!
//! Unlike the synchronous application store, this type never enumerates the
//! directory and never removes files. A stored TOC may reference a track that
//! was skipped during recovery, so only the application can decide whether a
//! `track_<n>.bin` is garbage. It may reconcile with
//! [`Self::read_dir`](AsyncFsPlane::read_dir) (through the plane) and
//! [`CdrBundleMedium::track_numbers`].
//!
//! # Explicit lifecycle
//!
//! Async close cannot run from `Drop`. Dropping the store only drops the
//! plane's handles; call [`AsyncCdrStore::shutdown`] to sync and close
//! deterministically.

use crate::common::async_fs_plane::AsyncFsPlane;
use crate::common::fs_storage::FsError;
use crate::common::seekable_storage::StorageError;
use crate::core::storage::{IoBuf, IoReq};
use crate::core::Direction;

use super::toc::{
    max_tracks_for_slot, toc_file, track_file, TocError, TocHeader, TOC_HEADER_LEN,
    TOC_SLOT_DEFAULT,
};
use super::{CdrBundleMedium, DiscKind, Recovery};

/// Largest resource id the fixed dirty table can address.
///
/// Valid ids are `1`, `2` and `17..=16 + max_tracks`; the maximum track count
/// is 99, so the highest addressable id is 115.
const DIRTY_SLOTS: usize = 128;

/// A recordable-CD store failure.
///
/// Kept coarse on purpose: the store runs on a `no_std` embedded target, so it
/// never formats a diagnostic string.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CdrStoreError {
    /// Filesystem I/O failed.
    Fs(FsError),
    /// A TOC slot could not be restored or a blank medium could not be built.
    Toc(TocError),
    /// The caller's reusable TOC slot buffer is smaller than the slot.
    ShortSlotBuffer {
        /// Slot size declared by the header.
        needed: u32,
        /// Capacity of the supplied buffer.
        got: usize,
    },
    /// No TOC slot was usable (a corrupt slot must never be overwritten with a
    /// fresh blank disc).
    NoUsableToc,
    /// Read-only recovery requires an existing TOC; a blank disc is not
    /// created.
    ReadOnlyRequiresToc,
}

impl core::fmt::Display for CdrStoreError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::Fs(e) => write!(f, "bundle filesystem error: {e}"),
            Self::Toc(e) => write!(f, "TOC error: {e}"),
            Self::ShortSlotBuffer { needed, got } => {
                write!(
                    f,
                    "TOC slot buffer too small: need {needed} bytes, got {got}"
                )
            }
            Self::NoUsableToc => write!(f, "no usable recordable-CD TOC"),
            Self::ReadOnlyRequiresToc => {
                write!(f, "read-only recovery requires an existing TOC")
            }
        }
    }
}

impl core::error::Error for CdrStoreError {}

impl From<FsError> for CdrStoreError {
    fn from(e: FsError) -> Self {
        Self::Fs(e)
    }
}

impl From<TocError> for CdrStoreError {
    fn from(e: TocError) -> Self {
        Self::Toc(e)
    }
}

/// State of one TOC slot as seen by the restore probe.
#[derive(Clone, Copy)]
enum SlotState {
    /// The file does not exist.
    Missing,
    /// At least the 256-byte header is present and parses.
    Valid(TocHeader),
    /// The file exists but its header cannot be used.
    Corrupt,
}

/// Asynchronous recordable-CD resource store.
///
/// `F` is a path-addressed filesystem plane (typically
/// [`AsyncFsPlaneAdapter`](crate::common::async_fs_plane::AsyncFsPlaneAdapter))
/// rooted at the bundle directory. The type never allocates: the dirty table is
/// fixed and the caller supplies the reusable TOC slot buffer.
pub struct AsyncCdrStore<F: AsyncFsPlane> {
    fs: F,
    /// Capacity hint for a new bundle. A stored TOC overrides it on reopen.
    capacity_sectors: u64,
    /// Requested TOC slot size for a new bundle (`None` = medium default).
    slot: Option<u32>,
    /// Track ids the configured slot can persist (`16 + n`, `n >= 1`).
    max_tracks: u16,
    /// Resources written since their last successful fsync, keyed by resource
    /// id. Only `1`, `2` and `17..=16 + max_tracks` can ever be set.
    dirty: [bool; DIRTY_SLOTS],
}

impl<F: AsyncFsPlane> AsyncCdrStore<F> {
    /// Wrap a filesystem plane and the requested medium geometry.
    pub fn new(fs: F, capacity_sectors: u64, slot: Option<u32>) -> Self {
        Self {
            fs,
            capacity_sectors,
            slot,
            max_tracks: max_tracks_for_slot(slot.unwrap_or(TOC_SLOT_DEFAULT)),
            dirty: [false; DIRTY_SLOTS],
        }
    }

    /// Nominal capacity in bytes (2048-byte logical blocks).
    pub fn capacity_bytes(&self) -> u64 {
        self.capacity_sectors.saturating_mul(2048)
    }

    /// Restore (or create) the medium from the two alternating TOC slots.
    ///
    /// The caller supplies a reusable buffer for the slot body (`slot_buf`); it
    /// must be at least the slot size declared by the header. Nothing is
    /// allocated by this function.
    ///
    /// Only the 256-byte headers are probed first, because the body length
    /// lives in the header. Valid candidates are then opened newest-first
    /// (higher `seq`, then higher slot index). A stored TOC owns the disc
    /// capacity and kind: `capacity_sectors`/`kind` are only hints for a new
    /// blank bundle, and `kind = None` means the default CD-R.
    ///
    /// A missing slot is not an error, but an unreadable or malformed slot is
    /// unless another slot is usable, and a blank disc is never started over a
    /// corrupt slot. Read-only recovery with no TOC is also an error. This type
    /// performs no orphan-file cleanup (see the module documentation).
    pub async fn open_medium(
        &mut self,
        capacity_sectors: u64,
        kind: Option<DiscKind>,
        recovery: Recovery,
        slot_buf: &mut [u8],
    ) -> Result<CdrBundleMedium, CdrStoreError> {
        let mut states = [SlotState::Missing; 2];
        for (slot, state) in states.iter_mut().enumerate() {
            let slot = slot as u8;
            let mut bytes = [0u8; TOC_HEADER_LEN];
            *state = match self.fs.read(toc_file(slot), 0, &mut bytes).await {
                Ok(()) => match TocHeader::parse(&bytes) {
                    Ok(header) => SlotState::Valid(header),
                    Err(_) => SlotState::Corrupt,
                },
                Err(FsError::NotFound) => SlotState::Missing,
                Err(_) => SlotState::Corrupt,
            };
        }

        // Newest-first order over the two physical slots.
        let order: [u8; 2] = match (&states[0], &states[1]) {
            (SlotState::Valid(a), SlotState::Valid(b)) => {
                if a.newer_than(b) {
                    [0, 1]
                } else {
                    [1, 0]
                }
            }
            (SlotState::Valid(_), _) => [0, 1],
            (_, SlotState::Valid(_)) => [1, 0],
            _ => [0, 1],
        };

        let corrupt = states
            .iter()
            .any(|state| matches!(state, SlotState::Corrupt));
        let mut open_error = false;
        for slot in order {
            let SlotState::Valid(header) = states[slot as usize] else {
                continue;
            };
            let size = header.slot_size as usize;
            if slot_buf.len() < size {
                return Err(CdrStoreError::ShortSlotBuffer {
                    needed: header.slot_size,
                    got: slot_buf.len(),
                });
            }
            if self
                .fs
                .read(toc_file(slot), 0, &mut slot_buf[..size])
                .await
                .is_err()
            {
                open_error = true;
                continue;
            }
            match CdrBundleMedium::open_at(slot, &slot_buf[..size], 0, recovery) {
                Ok(medium) => {
                    self.max_tracks = max_tracks_for_slot(medium.slot_size());
                    // The stored disc owns the geometry and media kind from
                    // here on.
                    self.capacity_sectors = medium.capacity_sectors();
                    self.dirty = [false; DIRTY_SLOTS];
                    return Ok(medium);
                }
                Err(_) => open_error = true,
            }
        }

        if open_error || corrupt {
            return Err(CdrStoreError::NoUsableToc);
        }
        if recovery == Recovery::ReadOnly {
            return Err(CdrStoreError::ReadOnlyRequiresToc);
        }
        let slot = self.slot.unwrap_or(TOC_SLOT_DEFAULT);
        let disc_kind = kind.unwrap_or(DiscKind::Cdr);
        let medium = CdrBundleMedium::with_disc(capacity_sectors, disc_kind, slot)?;
        self.capacity_sectors = medium.capacity_sectors();
        self.max_tracks = max_tracks_for_slot(medium.slot_size());
        self.dirty = [false; DIRTY_SLOTS];
        Ok(medium)
    }

    /// Convert a resource id into its file path.
    ///
    /// `scratch` holds a rendered track name for the duration of the call (a
    /// track path is `track_<n>.bin`; TOC slots are static names). Returns
    /// `None` for every id outside the contract.
    fn resource_path(scratch: &mut heapless::String<16>, resource: u16) -> Option<&str> {
        match resource {
            1 | 2 => Some(toc_file((resource - 1) as u8)),
            track if track > 16 => {
                *scratch = track_file(track - 16);
                Some(scratch.as_str())
            }
            _ => None,
        }
    }

    /// Whether `resource` is a valid id for the configured medium.
    fn valid_resource(&self, resource: u16) -> bool {
        match resource {
            1 | 2 => true,
            track if track > 16 => track - 16 <= self.max_tracks,
            _ => false,
        }
    }

    /// Mark `resource` dirty (no-op for an id outside the contract).
    fn mark(&mut self, resource: u16) {
        if self.valid_resource(resource) {
            if let Some(slot) = self.dirty.get_mut(usize::from(resource)) {
                *slot = true;
            }
        }
    }

    /// Read one resource, zero-filling a track's unavailable tail.
    ///
    /// A TOC slot (`1`/`2`) is strict. A track returns the full requested
    /// length: the readable prefix is preserved and the rest is zeros, exactly
    /// like the synchronous store. A missing track file is an empty track.
    pub async fn read_resource(
        &mut self,
        resource: u16,
        off: u64,
        buf: &mut [u8],
    ) -> Result<usize, StorageError> {
        if !self.valid_resource(resource) {
            return Err(StorageError::Unsupported);
        }
        let mut scratch = heapless::String::<16>::new();
        let path = Self::resource_path(&mut scratch, resource).ok_or(StorageError::Unsupported)?;
        if resource <= 16 {
            // Strict TOC slot: a missing or short slot is an error, never a
            // zero-filled body.
            self.fs.read(path, off, buf).await?;
            return Ok(buf.len());
        }
        let len = match self.fs.len(path).await {
            Ok(len) => len,
            Err(FsError::NotFound) => 0,
            Err(e) => return Err(e.into()),
        };
        let available = len.saturating_sub(off).min(buf.len() as u64);
        let prefix = available as usize;
        if prefix > 0 {
            match self.fs.read(path, off, &mut buf[..prefix]).await {
                Ok(()) => {}
                // The file vanished or shrank between the size probe and the
                // read; the safe view is zeros.
                Err(FsError::NotFound | FsError::OutOfBounds) => buf[..prefix].fill(0),
                Err(e) => return Err(e.into()),
            }
        }
        buf[prefix..].fill(0);
        Ok(buf.len())
    }

    /// Write one resource and mark it dirty.
    ///
    /// A track's first write at offset `0` truncates the file first; a TOC
    /// write never truncates (the body at offset 256 is written before the
    /// header at offset 0).
    pub async fn write_resource(
        &mut self,
        resource: u16,
        off: u64,
        buf: &mut [u8],
    ) -> Result<usize, StorageError> {
        if !self.valid_resource(resource) {
            return Err(StorageError::Unsupported);
        }
        let mut scratch = heapless::String::<16>::new();
        let path = Self::resource_path(&mut scratch, resource).ok_or(StorageError::Unsupported)?;
        if resource > 16 && off == 0 {
            // A reused track id must not inherit a stale tail. The truncation
            // itself changes bytes, so it is dirty even if the write fails.
            self.fs.truncate(path).await?;
            self.mark(resource);
        }
        self.fs.write(path, off, buf).await?;
        self.mark(resource);
        Ok(buf.len())
    }

    /// Fsync one resource if a write left it dirty.
    ///
    /// A clean resource performs no call and returns `0`. A file that vanished
    /// since its write has nothing left to make durable, so `NotFound` is not a
    /// sync failure. A successful per-file sync also settles the namespace
    /// through the plane-wide sync, because a slot created by this save has no
    /// durable directory entry before that.
    pub async fn sync_resource(&mut self, resource: u16) -> Result<usize, StorageError> {
        self.sync_path(resource)
            .await
            .map(|_| 0)
            .map_err(StorageError::from)
    }

    /// Fsync one dirty resource; returns whether it was dirty.
    async fn sync_path(&mut self, resource: u16) -> Result<bool, FsError> {
        let index = usize::from(resource);
        if !self.dirty.get(index).copied().unwrap_or(false) {
            return Ok(false);
        }
        let mut scratch = heapless::String::<16>::new();
        let Some(path) = Self::resource_path(&mut scratch, resource) else {
            // Unreachable: `mark` never sets an invalid id.
            if let Some(slot) = self.dirty.get_mut(index) {
                *slot = false;
            }
            return Ok(false);
        };
        match self.fs.sync_file(path).await {
            Ok(()) | Err(FsError::NotFound) => {}
            Err(e) => return Err(e),
        }
        if let Some(slot) = self.dirty.get_mut(index) {
            *slot = false;
        }
        // A newly created slot has no directory entry until the namespace is
        // settled; the plane-wide sync covers that.
        self.fs.sync().await?;
        Ok(true)
    }

    /// Execute one resource-addressed request.
    ///
    /// `0` is the aggregate flush (`Direction::None` only); `1`/`2` are the TOC
    /// slots; `16 + n` (`1 <= n <= max_tracks`) is track `n`. Anything else is a
    /// contract fault ([`StorageError::Unsupported`]). A track read returns the
    /// readable prefix followed by zeros.
    pub async fn exec(&mut self, req: IoReq, buf: IoBuf<'_>) -> Result<usize, StorageError> {
        match req.resource {
            0 => match (req.dir, buf) {
                (Direction::None, IoBuf::None) => self.sync().await,
                _ => Err(StorageError::Unsupported),
            },
            resource if self.valid_resource(resource) => match (req.dir, buf) {
                (Direction::None, IoBuf::None) => self.sync_resource(resource).await,
                (Direction::ToHost, IoBuf::Read(b)) => {
                    self.read_resource(resource, req.offset, b).await
                }
                (Direction::FromHost, IoBuf::Write(b)) => {
                    self.write_resource(resource, req.offset, b).await
                }
                _ => Err(StorageError::Unsupported),
            },
            _ => Err(StorageError::Unsupported),
        }
    }

    /// Aggregate flush (`Sync { resource: 0 }`).
    ///
    /// Fsyncs every dirty TOC/track file in resource-id order and then settles
    /// the plane-wide flush. A path is dropped from the dirty table only after
    /// its per-file sync succeeded, so a failure leaves the remaining work for
    /// the next aggregate sync.
    pub async fn sync(&mut self) -> Result<usize, StorageError> {
        self.sync_all()
            .await
            .map(|()| 0)
            .map_err(StorageError::from)
    }

    /// Fsync every dirty resource, then the plane.
    async fn sync_all(&mut self) -> Result<(), FsError> {
        for index in 0..DIRTY_SLOTS {
            if !self.dirty[index] {
                continue;
            }
            let resource = index as u16;
            let mut scratch = heapless::String::<16>::new();
            let Some(path) = Self::resource_path(&mut scratch, resource) else {
                // Unreachable: `mark` never sets an invalid id.
                self.dirty[index] = false;
                continue;
            };
            match self.fs.sync_file(path).await {
                Ok(()) | Err(FsError::NotFound) => {}
                Err(e) => return Err(e),
            }
            self.dirty[index] = false;
        }
        self.fs.sync().await
    }

    /// Sync, then shut the plane down (flushing and closing its handles).
    ///
    /// Errors do not stop the shutdown: the first sync/shutdown error is
    /// returned after both have been attempted.
    pub async fn shutdown(mut self) -> Result<(), CdrStoreError> {
        let mut first = self.sync_all().await.err().map(CdrStoreError::Fs);
        if let Err(e) = self.fs.shutdown().await {
            first.get_or_insert(CdrStoreError::Fs(e));
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
    use crate::common::fs_storage::DirEntry;
    use std::cell::{Cell, RefCell};
    use std::collections::HashMap;
    use std::rc::Rc;

    use crate::mmc::cdr_bundle::{TOC_SLOT_MAX, TOC_SLOT_MIN};

    fn block_on<F: core::future::Future>(fut: F) -> F::Output {
        let mut fut = core::pin::pin!(fut);
        let mut cx = core::task::Context::from_waker(core::task::Waker::noop());
        loop {
            if let core::task::Poll::Ready(v) = fut.as_mut().poll(&mut cx) {
                return v;
            }
        }
    }

    // ── In-memory AsyncFsPlane mock ─────────────────────────────────────

    type Store = Rc<RefCell<HashMap<String, Rc<RefCell<Vec<u8>>>>>>;

    #[derive(Clone)]
    struct Counters {
        sync_files: Rc<RefCell<Vec<String>>>,
        plane_syncs: Rc<Cell<usize>>,
        shut_downs: Rc<Cell<usize>>,
    }

    impl Counters {
        fn new() -> Self {
            Self {
                sync_files: Rc::new(RefCell::new(Vec::new())),
                plane_syncs: Rc::new(Cell::new(0)),
                shut_downs: Rc::new(Cell::new(0)),
            }
        }
    }

    struct MockPlane {
        store: Store,
        counters: Counters,
    }

    impl MockPlane {
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

    impl AsyncFsPlane for MockPlane {
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

        async fn read(&mut self, path: &str, off: u64, buf: &mut [u8]) -> Result<(), FsError> {
            let map = self.store.borrow();
            let data = map.get(path).ok_or(FsError::NotFound)?.borrow();
            let start = usize::try_from(off).map_err(|_| FsError::OutOfBounds)?;
            let end = start.checked_add(buf.len()).ok_or(FsError::OutOfBounds)?;
            if end > data.len() {
                return Err(FsError::OutOfBounds);
            }
            buf.copy_from_slice(&data[start..end]);
            Ok(())
        }

        async fn len(&mut self, path: &str) -> Result<u64, FsError> {
            let map = self.store.borrow();
            let data = map.get(path).ok_or(FsError::NotFound)?.borrow();
            Ok(data.len() as u64)
        }

        async fn truncate(&mut self, path: &str) -> Result<(), FsError> {
            let rc = self
                .store
                .borrow_mut()
                .entry(path.to_string())
                .or_default()
                .clone();
            rc.borrow_mut().clear();
            Ok(())
        }

        async fn write(&mut self, path: &str, off: u64, buf: &[u8]) -> Result<(), FsError> {
            let start = usize::try_from(off).map_err(|_| FsError::OutOfBounds)?;
            let rc = self
                .store
                .borrow_mut()
                .entry(path.to_string())
                .or_default()
                .clone();
            let mut data = rc.borrow_mut();
            if start > data.len() {
                data.resize(start, 0);
            }
            let end = start + buf.len();
            if end > data.len() {
                data.resize(end, 0);
            }
            data[start..end].copy_from_slice(buf);
            Ok(())
        }

        async fn remove(&mut self, path: &str) -> Result<(), FsError> {
            if self.store.borrow_mut().remove(path).is_some() {
                Ok(())
            } else {
                Err(FsError::NotFound)
            }
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

        async fn shutdown(&mut self) -> Result<(), FsError> {
            self.counters
                .shut_downs
                .set(self.counters.shut_downs.get() + 1);
            self.counters
                .plane_syncs
                .set(self.counters.plane_syncs.get() + 1);
            Ok(())
        }
    }

    // ── Helpers ─────────────────────────────────────────────────────────

    /// Render a blank-medium slot image at physical slot `slot`.
    fn slot_image(capacity: u64, slot_size: u32, want_slot: u8) -> Vec<u8> {
        let mut medium = CdrBundleMedium::with_disc(capacity, DiscKind::Cdr, slot_size).unwrap();
        let mut image = vec![0u8; slot_size as usize];
        if want_slot == 0 {
            assert_eq!(medium.toc_image(&mut image).unwrap(), 0);
        } else {
            // The save bookkeeping alternates slots: render slot 0 first.
            let mut first = vec![0u8; slot_size as usize];
            assert_eq!(medium.toc_image(&mut first).unwrap(), 0);
            assert_eq!(medium.toc_image(&mut image).unwrap(), 1);
        }
        image
    }

    fn store_file(store: &Store, name: &str, bytes: &[u8]) {
        store
            .borrow_mut()
            .insert(name.to_string(), Rc::new(RefCell::new(bytes.to_vec())));
    }

    fn read_req(resource: u16, offset: u64, len: u32) -> IoReq {
        IoReq {
            resource,
            offset,
            len,
            dir: Direction::ToHost,
        }
    }

    fn write_req(resource: u16, offset: u64, len: u32) -> IoReq {
        IoReq {
            resource,
            offset,
            len,
            dir: Direction::FromHost,
        }
    }

    fn sync_req(resource: u16) -> IoReq {
        IoReq {
            resource,
            offset: 0,
            len: 0,
            dir: Direction::None,
        }
    }

    fn blank_store(fs: MockPlane) -> (AsyncCdrStore<MockPlane>, CdrBundleMedium) {
        let mut store = AsyncCdrStore::new(fs, 1000, None);
        let mut buf = vec![0u8; TOC_SLOT_MAX as usize];
        let medium = block_on(store.open_medium(1000, None, Recovery::Delete, &mut buf)).unwrap();
        (store, medium)
    }

    // ── open_medium ─────────────────────────────────────────────────────

    #[test]
    fn blank_open_creates_a_medium() {
        let (fs, store, _c) = MockPlane::new();
        let (cdr, medium) = blank_store(fs);
        assert_eq!(medium.capacity_sectors(), 1000);
        assert_eq!(medium.kind(), DiscKind::Cdr);
        assert_eq!(medium.slot_size(), TOC_SLOT_DEFAULT);
        assert_eq!(cdr.capacity_bytes(), 1000 * 2048);
        assert_eq!(cdr.max_tracks, max_tracks_for_slot(TOC_SLOT_DEFAULT));
        // A blank open writes nothing.
        assert!(store.borrow().is_empty());
    }

    #[test]
    fn read_only_without_toc_is_an_error() {
        let (fs, _store, _c) = MockPlane::new();
        let mut store = AsyncCdrStore::new(fs, 1000, None);
        let mut buf = vec![0u8; TOC_SLOT_MAX as usize];
        assert_eq!(
            block_on(store.open_medium(1000, None, Recovery::ReadOnly, &mut buf)).err(),
            Some(CdrStoreError::ReadOnlyRequiresToc)
        );
    }

    #[test]
    fn write_toc_slot_then_reopen_restores_geometry() {
        let (fs, data, _c) = MockPlane::new();
        let (mut store, _medium) = blank_store(fs);
        let mut image = slot_image(1000, TOC_SLOT_MAX, 0);
        block_on(store.write_resource(1, 0, &mut image)).unwrap();
        block_on(store.sync()).unwrap();

        let mut reopened = AsyncCdrStore::new(MockPlane::from_store(&data), 0, None);
        let mut buf = vec![0u8; TOC_SLOT_MAX as usize];
        let medium = block_on(reopened.open_medium(0, None, Recovery::ReadOnly, &mut buf)).unwrap();
        assert_eq!(medium.capacity_sectors(), 1000);
        assert_eq!(reopened.capacity_bytes(), 1000 * 2048);
        assert_eq!(reopened.max_tracks, max_tracks_for_slot(TOC_SLOT_MAX));
    }

    #[test]
    fn newest_toc_slot_wins() {
        let (fs, data, _c) = MockPlane::new();
        let mut store = AsyncCdrStore::new(fs, 1000, None);
        let mut buf = vec![0u8; TOC_SLOT_MAX as usize];
        block_on(store.open_medium(1000, None, Recovery::Delete, &mut buf)).unwrap();

        let slot0 = slot_image(1000, TOC_SLOT_MAX, 0);
        let slot1 = slot_image(1000, TOC_SLOT_MAX, 1);
        store_file(&data, toc_file(0), &slot0);
        store_file(&data, toc_file(1), &slot1);

        let mut reopened = AsyncCdrStore::new(MockPlane::from_store(&data), 0, None);
        let medium = block_on(reopened.open_medium(0, None, Recovery::ReadOnly, &mut buf)).unwrap();
        // Slot 1 carries the later sequence number.
        assert_eq!(medium.current_slot(), 1);
        assert_eq!(medium.toc_seq(), 2);
    }

    #[test]
    fn corrupt_slot_without_a_usable_one_is_refused() {
        let (fs, data, _c) = MockPlane::new();
        let mut store = AsyncCdrStore::new(fs, 1000, None);
        let mut buf = vec![0u8; TOC_SLOT_MAX as usize];
        store_file(&data, toc_file(0), b"not a toc");
        assert_eq!(
            block_on(store.open_medium(1000, None, Recovery::Delete, &mut buf)).err(),
            Some(CdrStoreError::NoUsableToc)
        );
    }

    #[test]
    fn corrupt_slot_is_ignored_when_another_is_usable() {
        let (fs, data, _c) = MockPlane::new();
        let mut store = AsyncCdrStore::new(fs, 0, None);
        let mut buf = vec![0u8; TOC_SLOT_MAX as usize];
        store_file(&data, toc_file(0), b"not a toc");
        store_file(&data, toc_file(1), &slot_image(1000, TOC_SLOT_MAX, 1));
        let medium = block_on(store.open_medium(0, None, Recovery::ReadOnly, &mut buf)).unwrap();
        assert_eq!(medium.current_slot(), 1);
        assert_eq!(medium.capacity_sectors(), 1000);
    }

    #[test]
    fn short_slot_buffer_is_reported() {
        let (fs, data, _c) = MockPlane::new();
        let mut store = AsyncCdrStore::new(fs, 1000, None);
        store_file(&data, toc_file(0), &slot_image(1000, TOC_SLOT_MIN, 0));
        let mut buf = vec![0u8; 1024];
        assert_eq!(
            block_on(store.open_medium(1000, None, Recovery::Delete, &mut buf)).err(),
            Some(CdrStoreError::ShortSlotBuffer {
                needed: TOC_SLOT_MIN,
                got: 1024,
            })
        );
    }

    // ── resource IO ─────────────────────────────────────────────────────

    #[test]
    fn track_write_read_roundtrip() {
        let (fs, _data, _c) = MockPlane::new();
        let (mut store, _medium) = blank_store(fs);
        let mut payload = *b"hello";
        block_on(store.write_resource(17, 0, &mut payload)).unwrap();
        let mut out = [0xAAu8; 8];
        let n = block_on(store.read_resource(17, 0, &mut out)).unwrap();
        assert_eq!(n, 8, "a track read returns the full requested length");
        assert_eq!(&out[..5], b"hello");
        assert_eq!(&out[5..], &[0, 0, 0], "short tail is zero-filled");
    }

    #[test]
    fn offset_zero_write_truncates() {
        let (fs, _data, _c) = MockPlane::new();
        let (mut store, _medium) = blank_store(fs);
        let mut first = *b"abcdef";
        block_on(store.write_resource(17, 0, &mut first)).unwrap();
        let mut second = *b"xy";
        block_on(store.write_resource(17, 0, &mut second)).unwrap();
        let mut out = [0u8; 8];
        block_on(store.read_resource(17, 0, &mut out)).unwrap();
        assert_eq!(&out[..2], b"xy");
        assert_eq!(&out[2..], &[0; 6], "the stale tail was truncated");

        // A write at a non-zero offset keeps the prefix and extends the file.
        let mut tail_byte = *b"Z";
        block_on(store.write_resource(17, 4, &mut tail_byte)).unwrap();
        let mut out = [0u8; 8];
        block_on(store.read_resource(17, 0, &mut out)).unwrap();
        assert_eq!(&out[..2], b"xy");
        assert_eq!(&out[2..4], &[0, 0]);
        assert_eq!(&out[4..5], b"Z");
    }

    #[test]
    fn short_and_missing_tracks_zero_fill() {
        let (fs, data, _c) = MockPlane::new();
        let (mut store, _medium) = blank_store(fs);
        store_file(&data, track_file(1).as_str(), b"abc");

        let mut out = [0xAAu8; 6];
        block_on(store.read_resource(17, 0, &mut out)).unwrap();
        assert_eq!(&out[..3], b"abc");
        assert_eq!(&out[3..], &[0, 0, 0]);

        // A read starting past the recorded length is all zeros.
        let mut tail = [0xAAu8; 4];
        block_on(store.read_resource(17, 100, &mut tail)).unwrap();
        assert_eq!(tail, [0; 4]);

        // Track 2 has no file at all: also zeros.
        let mut missing = [0xAAu8; 4];
        block_on(store.read_resource(18, 0, &mut missing)).unwrap();
        assert_eq!(missing, [0; 4]);
    }

    #[test]
    fn toc_read_is_strict() {
        let (fs, data, _c) = MockPlane::new();
        let (mut store, _medium) = blank_store(fs);
        let mut out = [0u8; 4];
        assert_eq!(
            block_on(store.read_resource(1, 0, &mut out)),
            Err(StorageError::OutOfBounds),
            "a missing TOC slot is an error, not zeros"
        );

        store_file(&data, toc_file(1), b"short");
        let mut out = [0u8; 16];
        assert_eq!(
            block_on(store.read_resource(2, 0, &mut out)),
            Err(StorageError::OutOfBounds)
        );
    }

    #[test]
    fn unsupported_resources_are_rejected() {
        let (fs, _data, _c) = MockPlane::new();
        let mut store = AsyncCdrStore::new(fs, 1000, Some(TOC_SLOT_MIN));
        let mut buf = vec![0u8; TOC_SLOT_MIN as usize];
        block_on(store.open_medium(1000, None, Recovery::Delete, &mut buf)).unwrap();
        assert_eq!(store.max_tracks, 1, "the minimum slot fits one track");

        let mut out = [0u8; 4];
        for resource in [0u16, 3, 16, 18] {
            assert_eq!(
                block_on(store.read_resource(resource, 0, &mut out)),
                Err(StorageError::Unsupported),
                "resource {resource} must be a contract fault"
            );
        }
        assert_eq!(
            block_on(store.write_resource(18, 0, &mut out)),
            Err(StorageError::Unsupported)
        );
    }

    #[test]
    fn exec_routes_directions() {
        let (fs, _data, _c) = MockPlane::new();
        let (mut store, _medium) = blank_store(fs);

        // Aggregate flush with no buffer.
        assert_eq!(block_on(store.exec(sync_req(0), IoBuf::None)), Ok(0));
        // Aggregate flush refuses a data direction.
        let mut out = [0u8; 4];
        assert_eq!(
            block_on(store.exec(read_req(0, 0, 4), IoBuf::Read(&mut out))),
            Err(StorageError::Unsupported)
        );
        // A sync request with a buffer is a contract fault.
        assert_eq!(
            block_on(store.exec(sync_req(1), IoBuf::Read(&mut out))),
            Err(StorageError::Unsupported)
        );

        // Track write then read through `exec`.
        let mut track = *b"data";
        assert_eq!(
            block_on(store.exec(write_req(17, 0, 4), IoBuf::Write(&mut track))),
            Ok(4)
        );
        let mut out = [0u8; 4];
        assert_eq!(
            block_on(store.exec(read_req(17, 0, 4), IoBuf::Read(&mut out))),
            Ok(4)
        );
        assert_eq!(&out, b"data");

        // Resource-level sync flushes the dirty track.
        assert_eq!(block_on(store.exec(sync_req(17), IoBuf::None)), Ok(0));
    }

    // ── sync bookkeeping ────────────────────────────────────────────────

    #[test]
    fn sync_flushes_only_dirty_resources_once() {
        let (fs, _data, c) = MockPlane::new();
        let (mut store, _medium) = blank_store(fs);
        let mut track = *b"track";
        block_on(store.write_resource(17, 0, &mut track)).unwrap();
        let mut image = slot_image(1000, TOC_SLOT_MAX, 0);
        block_on(store.write_resource(1, 0, &mut image)).unwrap();

        block_on(store.sync()).unwrap();
        let mut synced = c.sync_files.borrow().clone();
        synced.sort();
        assert_eq!(
            synced,
            vec![toc_file(0).to_string(), track_file(1).to_string()]
        );
        assert_eq!(c.plane_syncs.get(), 1);

        // A second sync has no dirty file left, but still settles the plane.
        block_on(store.sync()).unwrap();
        assert_eq!(c.sync_files.borrow().len(), 2);
        assert_eq!(c.plane_syncs.get(), 2);
    }

    #[test]
    fn sync_resource_skips_a_clean_file() {
        let (fs, _data, c) = MockPlane::new();
        let (mut store, _medium) = blank_store(fs);
        block_on(store.sync_resource(17)).unwrap();
        assert!(c.sync_files.borrow().is_empty());
        assert_eq!(c.plane_syncs.get(), 0);

        let mut payload = *b"x";
        block_on(store.write_resource(17, 0, &mut payload)).unwrap();
        block_on(store.sync_resource(17)).unwrap();
        assert_eq!(&*c.sync_files.borrow(), &[track_file(1).to_string()]);
        assert_eq!(c.plane_syncs.get(), 1);

        // Now clean: a repeated sync is a no-op.
        block_on(store.sync_resource(17)).unwrap();
        assert_eq!(c.sync_files.borrow().len(), 1);
    }

    #[test]
    fn shutdown_syncs_and_closes_the_plane() {
        let (fs, _data, c) = MockPlane::new();
        let (mut store, _medium) = blank_store(fs);
        let mut payload = *b"x";
        block_on(store.write_resource(17, 0, &mut payload)).unwrap();
        block_on(store.shutdown()).unwrap();
        assert_eq!(&*c.sync_files.borrow(), &[track_file(1).to_string()]);
        assert_eq!(c.shut_downs.get(), 1);
    }

    #[test]
    fn error_display_is_diagnostic() {
        assert!(format!("{}", CdrStoreError::NoUsableToc).contains("no usable"));
        assert!(format!(
            "{}",
            CdrStoreError::ShortSlotBuffer {
                needed: 4096,
                got: 1024
            }
        )
        .contains("4096"));
        assert!(format!("{}", CdrStoreError::Fs(FsError::NotFound)).contains("not found"));
    }
}
