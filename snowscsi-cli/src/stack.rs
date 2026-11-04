//! Application glue between the CLI's device specifications and the core
//! `Target` seams.
//!
//! The CLI serves a heterogeneous LUN set (block disks and MMC drives) through
//! one core target, so it needs three adapters that the library deliberately
//! leaves to the application:
//!
//! - [`CliMedium`] — one MMC medium enum (flat CD / DVD-RAM) so the drive type
//!   stays a single `MmcDrive<CliMedium>`;
//! - [`CliLu`] — one runtime `Lu` enum over the block and MMC slot types, with
//!   a single [`CliPair`] (the core `Pair` type of this application);
//! - [`CliStorage`] — a [`Storage`] adapter over the per-LUN [`OwnedPlane`]s,
//!   routed by the runner's `select_lun` hook.
//!
//! The glue owns no protocol state: every method forwards to the wrapped core
//! type.

use core::task::Poll;

use snowscsi::block::BlockDevice;
use snowscsi::cdrom::media::LiveData;
#[cfg(feature = "cipher")]
use snowscsi::common::cipher::CipherPlane;
#[cfg(feature = "bundle")]
use snowscsi::common::flat_bundle::FlatBundle;
#[cfg(feature = "cdr-bundle")]
use snowscsi::common::fs_plane::{FsPlane, FsPlaneAdapter};
#[cfg(feature = "cdr-bundle")]
use snowscsi::common::fs_storage::{DirEntry, FsError};
use snowscsi::common::seekable_storage::{FlatData, StorageError, WritableFlatData};
use snowscsi::common::store::{StoreOp, StorePlane};
#[cfg(feature = "cdr-bundle")]
use snowscsi::core::storage::SyncStorage;
use snowscsi::core::storage::{IoBuf, IoReq, IoToken, Storage, StorageReceipt};
use snowscsi::core::{
    Admission, BoundaryPermit, Change, ChangeResult, CommandContext, CommandPermit, Completion,
    Delivery, Effect, Fault, Feedback, InterruptReason, KnownEffects, LongInfo, Lu, LuImpl, LuInfo,
    OwnerBindPermit, Pair, PollStep, Sense, Spc, TargetId, UaClass,
};
#[cfg(feature = "cdr-bundle")]
use snowscsi::mmc::cdr_bundle::{
    max_tracks_for_slot, toc_file, track_file, CdrBundleMedium, DiscKind, Recovery, TocHeader,
    TOC_HEADER_LEN, TOC_SLOT_DEFAULT,
};
#[cfg(feature = "dvdram")]
use snowscsi::mmc::DvdRamMedium;
use snowscsi::mmc::{
    AtipInfo, DiscInfo, FlatCdMedium, MmcAttrs, MmcDrive, MmcMedium, MmcOp, Session, Track,
    TrackInfo, TrackInfoRequest,
};
use snowscsi::scsi::backend::FileBackend;
use snowscsi::scsi::fs_backend::StdFsBackend;

#[cfg(feature = "cipher")]
use crate::cipher::CliCipher;
#[cfg(all(feature = "cdr-bundle", feature = "cipher"))]
use snowscsi::core::cipher_store::CipherStore;
#[cfg(all(feature = "cdr-bundle", feature = "cipher"))]
use snowscsi::core::storage::BlockingStorage;

#[cfg(feature = "tokio")]
pub mod tokio_conn;
pub mod worker;

/// Application backing handle: the CLI only needs an identity per LUN.
pub type CliBacking = u32;

/// One CLI-owned store plane.
///
/// Every variant owns its bytes — there is no borrow — so a plane can be moved
/// into a worker thread or an asynchronous backend task. The synchronous path
/// still builds a temporary [`StorePlane`] borrow per operation.
// The CLI builds one plane per LUN; the size difference is dominated by the
// live scanner's file table, not a hot-path concern (same rationale as
// `CliLu` below).
#[allow(clippy::large_enum_variant)]
pub enum OwnedPlane {
    /// Read-only file or block device.
    BlockRo(FileBackend),
    /// Writable file or block device.
    BlockRw(FileBackend),
    /// In-memory plane (`--block ram=`, `--dvdram=ram`).
    Ram {
        /// Backing bytes.
        bytes: Vec<u8>,
        /// Whether the LUN may write (the media policy is separate).
        writable: bool,
    },
    /// Directory-chunked filesystem plane (read-only or writable, as opened).
    #[cfg(feature = "bundle")]
    Bundle(FlatBundle<StdFsBackend>),
    /// Persistent CD-R bundle directory: resource-addressed TOC slots and
    /// track files (see [`BundleStore`]), optionally encrypted per resource.
    #[cfg(feature = "cdr-bundle")]
    CdrBundle(CdrStore),
    /// Encrypting view over another owned plane.
    #[cfg(feature = "cipher")]
    Cipher(Box<CipherPlane<OwnedPlane, CliCipher>>),
    /// Live ISO9660 directory scan (read-only).
    Live(LiveData<StdFsBackend>),
}

/// Paths whose bytes were written but not yet fsynced.
///
/// The filesystem seam stays separate from this bookkeeping so the ordering
/// rules (mark once, drop after a successful sync) are unit-testable without a
/// mock filesystem.
#[cfg(feature = "cdr-bundle")]
#[derive(Default)]
struct DirtyPaths {
    paths: Vec<String>,
}

#[cfg(feature = "cdr-bundle")]
impl DirtyPaths {
    /// Mark `path` dirty once, preserving first-dirty order.
    fn mark(&mut self, path: &str) {
        if !self.paths.iter().any(|p| p == path) {
            self.paths.push(path.to_string());
        }
    }

    /// Remove `path` after it was synced.
    fn take(&mut self, path: &str) -> bool {
        match self.paths.iter().position(|p| p == path) {
            Some(i) => {
                self.paths.remove(i);
                true
            }
            None => false,
        }
    }

    /// Fsync every dirty path once, in first-dirty order.
    ///
    /// A path is dropped only after its sync succeeded, so a failure leaves the
    /// remaining work for the next aggregate sync.
    fn sync_all<F>(&mut self, mut sync: F) -> Result<(), FsError>
    where
        F: FnMut(&str) -> Result<(), FsError>,
    {
        while let Some(path) = self.paths.first().cloned() {
            sync(&path)?;
            self.take(&path);
        }
        Ok(())
    }

    /// Fsync `path` only when it is dirty, dropping it after a successful sync.
    fn sync_one<F>(&mut self, path: &str, sync: F) -> Result<bool, FsError>
    where
        F: FnOnce() -> Result<(), FsError>,
    {
        if !self.paths.iter().any(|p| p == path) {
            return Ok(false);
        }
        sync()?;
        self.take(path);
        Ok(true)
    }
}

/// Sync `path`, treating a vanished file as "nothing left to make durable".
#[cfg(feature = "cdr-bundle")]
fn sync_file_or_missing(fs: &mut FsPlaneAdapter<StdFsBackend>, path: &str) -> Result<(), FsError> {
    match fs.sync_file(path) {
        Ok(()) | Err(FsError::NotFound) => Ok(()),
        Err(e) => Err(e),
    }
}

/// Write a rendered TOC slot image to `<dir>/toc.<slot>` atomically.
///
/// The complete image is written to `<dir>/toc.<slot>.tmp`, fsynced, and then
/// renamed over the real slot. Within the temp file the header/body order is
/// irrelevant because the file is not visible until the rename, which makes
/// the slot switch atomic. The directory is fsynced best effort so the rename
/// is durable, and a failed write/rename removes the temporary file. Used by
/// the serve paths that own the store (the plane may be dropped right after an
/// eject) and by `bundle-create cdr` for the initial slot.
#[cfg(feature = "cdr-bundle")]
pub(crate) fn write_toc_snapshot(dir: &str, slot: u8, image: &[u8]) -> std::io::Result<()> {
    use std::io::Write;

    let name = toc_file(slot);
    let path = std::path::Path::new(dir).join(name);
    let tmp = std::path::Path::new(dir).join(format!("{name}.tmp"));
    let write = (|| {
        {
            let mut file = std::fs::OpenOptions::new()
                .create(true)
                .truncate(true)
                .write(true)
                .open(&tmp)?;
            file.write_all(image)?;
            file.sync_all()?;
        }
        std::fs::rename(&tmp, &path)?;
        if let Ok(dir) = std::fs::File::open(dir) {
            let _ = dir.sync_all();
        }
        Ok(())
    })();
    if write.is_err() {
        let _ = std::fs::remove_file(&tmp);
    }
    write
}

/// Snapshot a CD-R bundle pair before an eject drops its plane.
///
/// Only a writable, non-finalized medium with pending state (an open track or
/// an unsaved transition) is rendered; a clean or finalized disc writes
/// nothing. The medium's in-memory save bookkeeping advances as if the slot
/// save had completed, so a later save alternates to the other slot.
#[cfg(feature = "cdr-bundle")]
pub(crate) fn snapshot_cdr_eject(pair: &mut CliPair, dir: &str) -> Result<bool, String> {
    let medium = match &mut pair.medium {
        CliPairMedium::Mmc(CliMedium::CdrBundle(medium)) => medium,
        _ => return Ok(false),
    };
    if !medium.eject_needs_save() {
        return Ok(false);
    }
    let mut image = vec![0u8; medium.slot_size() as usize];
    let slot = medium.toc_image(&mut image).map_err(|e| e.to_string())?;
    write_toc_snapshot(dir, slot, &image).map_err(|e| e.to_string())?;
    Ok(true)
}

/// Persistent CD-R directory store.
///
/// The medium addresses files by resource id (`0` = aggregate sync, `1`/`2` =
/// `toc.0`/`toc.1`, `16 + n` = `track_<n>.bin`), so this plane owns the
/// filesystem seam plus the geometry from the requested disc preset.
#[cfg(feature = "cdr-bundle")]
pub struct BundleStore {
    fs: FsPlaneAdapter<StdFsBackend>,
    /// Capacity hint for a new bundle. A stored TOC overrides it on reopen.
    capacity_sectors: u64,
    /// Requested TOC slot size for a new bundle (`None` = medium default).
    slot: Option<u32>,
    /// Track ids the configured slot can persist (`16 + n`, `n >= 1`).
    max_tracks: u16,
    /// Files written since their last successful fsync.
    dirty: DirtyPaths,
}

/// One TOC slot as seen during the restore probe.
#[cfg(feature = "cdr-bundle")]
enum SlotState {
    /// The file does not exist.
    Missing,
    /// At least the 256-byte header is present and parses.
    Valid(TocHeader),
    /// The file exists but its header cannot be used.
    Corrupt(String),
}

/// Parse a `track_<n>.bin` file name back to its track id.
///
/// Only this exact naming pattern is reconcilable; `toc.0`/`toc.1` and
/// unrelated files never match, so they are never removed.
#[cfg(feature = "cdr-bundle")]
fn track_number(name: &str) -> Option<u16> {
    name.strip_prefix("track_")?
        .strip_suffix(".bin")?
        .parse()
        .ok()
}

/// Whether `name` looks like a track file (`track_*.bin`), including a
/// non-canonical spelling that [`track_number`] cannot parse.
#[cfg(feature = "cdr-bundle")]
fn is_track_name(name: &str) -> bool {
    name.strip_prefix("track_")
        .and_then(|rest| rest.strip_suffix(".bin"))
        .is_some_and(|digits| !digits.is_empty())
}

/// Largest `read_dir` batch the orphan reconciliation will allocate.
#[cfg(feature = "cdr-bundle")]
const ORPHAN_SCAN_MAX: usize = 1024;

#[cfg(feature = "cdr-bundle")]
impl BundleStore {
    /// Wrap a directory and the requested medium geometry.
    pub fn new(fs: FsPlaneAdapter<StdFsBackend>, capacity_sectors: u64, slot: Option<u32>) -> Self {
        Self {
            fs,
            capacity_sectors,
            slot,
            max_tracks: max_tracks_for_slot(slot.unwrap_or(TOC_SLOT_DEFAULT)),
            dirty: DirtyPaths::default(),
        }
    }

    /// Nominal capacity in bytes.
    fn capacity_bytes(&self) -> u64 {
        self.capacity_sectors.saturating_mul(2048)
    }

    /// Aggregate flush (`Sync { resource: 0 }`).
    ///
    /// Fsyncs every dirty track and TOC file and then settles the backend-wide
    /// flush. The per-file fsync makes the written bytes durable; crash safety
    /// of the TOC comes from the header CRC plus the alternating slots, so a
    /// torn slot is rejected on restore.
    fn sync(&mut self) -> Result<usize, StorageError> {
        let Self { fs, dirty, .. } = self;
        dirty
            .sync_all(|path| sync_file_or_missing(fs, path))
            .map_err(StorageError::from)?;
        fs.sync().map_err(StorageError::from)?;
        Ok(0)
    }

    /// Fsync one resource file if a write left it dirty.
    ///
    /// A file that vanished since its write has nothing left to make durable,
    /// so `NotFound` is not a sync failure. A successful per-file sync also
    /// settles the namespace through the backend-wide sync, because a slot
    /// created by this save has no durable directory entry before that.
    fn sync_path(&mut self, path: &str) -> Result<usize, StorageError> {
        let Self { fs, dirty, .. } = self;
        let synced = dirty
            .sync_one(path, || sync_file_or_missing(fs, path))
            .map_err(StorageError::from)?;
        if synced {
            // A newly created slot has no directory entry until the namespace
            // is settled; the backend-wide sync covers that.
            fs.sync().map_err(StorageError::from)?;
        }
        Ok(0)
    }

    /// Execute one resource-addressed request.
    ///
    /// `0` is the aggregate flush; `1`/`2` are the TOC slots; `16 + n`
    /// (`1 <= n <= max_tracks`) is track `n`. Anything else is a contract
    /// fault. A track read returns the readable prefix followed by zeros.
    pub fn exec(&mut self, req: IoReq, buf: IoBuf<'_>) -> Result<usize, StorageError> {
        match req.resource {
            0 => match req.dir {
                snowscsi::core::Direction::None => self.sync(),
                _ => Err(StorageError::Unsupported),
            },
            1 | 2 => {
                let slot = req.resource - 1;
                let path = toc_file(slot as u8);
                self.file_op(path, req, buf, false)
            }
            resource if resource > 16 => {
                let track = resource - 16;
                if track > self.max_tracks {
                    return Err(StorageError::Unsupported);
                }
                let path = track_file(track);
                self.file_op(&path, req, buf, true)
            }
            _ => Err(StorageError::Unsupported),
        }
    }

    /// Read/write/sync one filesystem resource.
    fn file_op(
        &mut self,
        path: &str,
        req: IoReq,
        buf: IoBuf<'_>,
        track: bool,
    ) -> Result<usize, StorageError> {
        match (req.dir, buf) {
            // `Sync` on a TOC slot or track fsyncs exactly that resource when a
            // write left it dirty; a clean file is not re-synced.
            (snowscsi::core::Direction::None, IoBuf::None) => self.sync_path(path),
            (snowscsi::core::Direction::ToHost, IoBuf::Read(b)) => {
                if track {
                    self.read_track(path, req.offset, b)
                } else {
                    // A TOC slot is strict: a missing or short slot is an
                    // error, never a zero-filled body.
                    self.fs.read(path, req.offset, b)?;
                    Ok(b.len())
                }
            }
            (snowscsi::core::Direction::FromHost, IoBuf::Write(b)) => {
                if track && req.offset == 0 {
                    // A reused track id must not inherit a stale tail. The
                    // resource contract says its first write truncates.
                    self.fs.truncate(path)?;
                    self.dirty.mark(path);
                }
                self.fs.write(path, req.offset, b)?;
                self.dirty.mark(path);
                Ok(b.len())
            }
            _ => Err(StorageError::Unsupported),
        }
    }

    /// Read a track's readable prefix, zero-filling the remainder.
    ///
    /// A missing track file is an empty track (all zeros), and a short file
    /// keeps its readable prefix instead of losing it to a whole-buffer fill.
    fn read_track(
        &mut self,
        path: &str,
        offset: u64,
        out: &mut [u8],
    ) -> Result<usize, StorageError> {
        let len = match self.fs.len(path) {
            Ok(len) => len,
            Err(FsError::NotFound) => 0,
            Err(e) => return Err(e.into()),
        };
        let available = len.saturating_sub(offset).min(out.len() as u64);
        let prefix = available as usize;
        if prefix > 0 {
            match self.fs.read(path, offset, &mut out[..prefix]) {
                Ok(()) => {}
                // The file vanished or shrank between the size probe and the
                // read; the safe view is zeros.
                Err(FsError::NotFound | FsError::OutOfBounds) => out[..prefix].fill(0),
                Err(e) => return Err(e.into()),
            }
        }
        out[prefix..].fill(0);
        Ok(out.len())
    }

    /// Read the whole bundle directory into one owned entry list.
    ///
    /// The `FsPlane::read_dir` seam has no cursor: every call restarts at the
    /// first entry and truncates at the buffer length, so a full batch only
    /// means "possibly more". The batch doubles up to [`ORPHAN_SCAN_MAX`]; a
    /// directory that still fills that batch is reported as too large for a
    /// complete reconciliation and returns `None` (the caller must remove
    /// nothing from a partial view).
    fn scan_bundle_dir(&mut self) -> Option<Vec<DirEntry>> {
        let mut batch = 16usize;
        loop {
            let mut entries = vec![
                DirEntry {
                    name: heapless::String::new(),
                    is_dir: false,
                    size: 0,
                };
                batch
            ];
            let n = match self.fs.read_dir(".", &mut entries) {
                Ok(n) => n,
                Err(e) => {
                    log::warn!("bundle: directory scan failed: {e}");
                    return None;
                }
            };
            if n < batch {
                entries.truncate(n);
                return Some(entries);
            }
            if batch == ORPHAN_SCAN_MAX {
                log::warn!(
                    "bundle: directory has {ORPHAN_SCAN_MAX}+ entries; too large for a \
                     complete orphan reconciliation"
                );
                return None;
            }
            batch = (batch * 2).min(ORPHAN_SCAN_MAX);
        }
    }

    /// Remove track files the restored TOC does not reference.
    ///
    /// Only the clean restored-TOC path calls this; a skipped slot disables
    /// reconciliation because a track may exist only in that slot. A track
    /// file is kept only when its name is exactly [`track_file`]'s canonical
    /// spelling, the TOC references that id, and the configured slot can still
    /// persist it. Any other `track_<n>.bin` spelling is an orphan.
    /// `toc.0`/`toc.1` never match the track name, so they are never removed.
    /// A failed removal is logged and never fails the open.
    fn remove_orphan_tracks(&mut self, medium: &CdrBundleMedium) {
        let Some(entries) = self.scan_bundle_dir() else {
            return;
        };
        let referenced: Vec<u16> = medium.track_numbers().collect();
        let max_track = max_tracks_for_slot(medium.slot_size());
        let mut removed = 0usize;
        for entry in &entries {
            if entry.is_dir {
                continue;
            }
            let Some(track) = track_number(entry.name.as_str()) else {
                continue;
            };
            let canonical = track_file(track);
            if entry.name.as_str() == canonical.as_str()
                && track <= max_track
                && referenced.contains(&track)
            {
                continue;
            }
            match self.fs.remove(entry.name.as_str()) {
                Ok(()) => removed += 1,
                Err(FsError::NotFound) => {}
                Err(e) => {
                    log::warn!("bundle: failed to remove orphan {}: {e}", entry.name);
                }
            }
        }
        if removed > 0 {
            log::info!("bundle: removed {removed} orphan track file(s)");
        }
    }

    /// Restore (or create) the medium from the two alternating TOC slots.
    ///
    /// The caller reads only the 256-byte headers first, because the body
    /// length lives in the header; the newer valid slot is then read in full
    /// and parsed with its physical index (`open_at`). A stored TOC owns the
    /// disc capacity and kind: `capacity_sectors`/`kind` are only hints for a
    /// new blank bundle, and `kind = None` means the default CD-R and never
    /// warns on reopen. A missing slot is not an error, but an unreadable or
    /// malformed slot is unless the other slot is usable.
    pub fn open_medium(
        &mut self,
        capacity_sectors: u64,
        kind: Option<DiscKind>,
        recovery: Recovery,
    ) -> Result<CdrBundleMedium, String> {
        let states: [SlotState; 2] = std::array::from_fn(|slot: usize| {
            let slot = slot as u8;
            let mut bytes = [0u8; TOC_HEADER_LEN];
            match self.fs.read(toc_file(slot), 0, &mut bytes) {
                Ok(()) => match TocHeader::parse(&bytes) {
                    Ok(header) => SlotState::Valid(header),
                    Err(e) => SlotState::Corrupt(format!("invalid header: {e}")),
                },
                Err(FsError::NotFound) => SlotState::Missing,
                Err(e) => SlotState::Corrupt(format!("header read failed: {e}")),
            }
        });
        let mut candidates = Vec::new();
        match (&states[0], &states[1]) {
            (SlotState::Valid(a), SlotState::Valid(b)) => {
                if a.newer_than(b) {
                    candidates.push((0u8, *a));
                    candidates.push((1u8, *b));
                } else {
                    candidates.push((1u8, *b));
                    candidates.push((0u8, *a));
                }
            }
            (SlotState::Valid(a), _) => candidates.push((0u8, *a)),
            (_, SlotState::Valid(b)) => candidates.push((1u8, *b)),
            _ => {}
        }
        let corrupt: Vec<String> = states
            .iter()
            .enumerate()
            .filter_map(|(slot, state)| match state {
                SlotState::Corrupt(reason) => Some(format!("toc.{slot}: {reason}")),
                _ => None,
            })
            .collect();
        let mut open_error = None;
        for (slot, header) in candidates {
            let mut bytes = vec![0u8; header.slot_size as usize];
            match self.fs.read(toc_file(slot), 0, &mut bytes) {
                Ok(()) => {}
                Err(e) => {
                    open_error = Some(format!("toc.{slot}: body read failed: {e}"));
                    continue;
                }
            }
            match CdrBundleMedium::open_at(slot, &bytes, 0, recovery) {
                Ok(medium) => {
                    if !corrupt.is_empty() || open_error.is_some() {
                        let mut ignored = corrupt.clone();
                        if let Some(e) = &open_error {
                            ignored.push(e.clone());
                        }
                        log::warn!(
                            "bundle: using toc.{slot}; ignored unusable TOC slot(s): {}",
                            ignored.join(", ")
                        );
                    }
                    let stored = medium.capacity_sectors();
                    if capacity_sectors != 0 && stored != capacity_sectors {
                        log::warn!(
                            "bundle: stored capacity {stored} sectors wins over the \
                             medium= hint {capacity_sectors}"
                        );
                    }
                    if let Some(hint) = kind {
                        if hint != medium.kind() {
                            log::warn!(
                                "bundle: stored disc kind {:?} wins over the medium= hint {hint:?}",
                                medium.kind()
                            );
                        }
                    }
                    self.max_tracks = max_tracks_for_slot(medium.slot_size());
                    // The stored disc owns the geometry and media kind from
                    // here on.
                    self.capacity_sectors = stored;
                    // Only a clean restore reconciles: a skipped slot may be
                    // the only place a track is referenced, so a transient
                    // read error must not delete its payload. A read-only
                    // recovery never deletes. Runs before the plane is
                    // installed in the session.
                    if recovery == Recovery::Delete {
                        if corrupt.is_empty() && open_error.is_none() {
                            self.remove_orphan_tracks(&medium);
                        } else {
                            log::warn!(
                                "bundle: skipping orphan track cleanup because a TOC slot \
                                 was unreadable"
                            );
                        }
                    }
                    return Ok(medium);
                }
                Err(e) => open_error = Some(format!("toc.{slot}: {e}")),
            }
        }
        if let Some(e) = open_error {
            return Err(format!("no usable recordable-CD TOC ({e})"));
        }
        if !corrupt.is_empty() {
            return Err(format!(
                "no usable recordable-CD TOC ({}); refusing to start blank over a corrupt slot",
                corrupt.join(", ")
            ));
        }
        if recovery == Recovery::ReadOnly {
            return Err(
                "read-only recovery requires an existing recordable-CD TOC; refusing to create a blank disc"
                    .to_string(),
            );
        }
        let slot = self.slot.unwrap_or(TOC_SLOT_DEFAULT);
        let disc_kind = kind.unwrap_or(DiscKind::Cdr);
        log::warn!("bundle: no TOC slot found; starting a new blank {disc_kind:?} (slot {slot})");
        let medium = CdrBundleMedium::with_disc(capacity_sectors, disc_kind, slot)
            .map_err(|e| format!("invalid CD-R/CD-RW TOC slot size {slot}: {e}"))?;
        self.max_tracks = max_tracks_for_slot(medium.slot_size());
        // There is no TOC to reconcile against, so a leftover track file may
        // hold the only copy of recorded data: report it, never wipe the
        // directory. Runs before the plane is installed in the session.
        if let Some(entries) = self.scan_bundle_dir() {
            let leftovers = entries
                .iter()
                .filter(|entry| !entry.is_dir && is_track_name(entry.name.as_str()))
                .count();
            if leftovers > 0 {
                log::warn!(
                    "bundle: no TOC found; leaving {leftovers} leftover track file(s) untouched"
                );
            }
        }
        Ok(medium)
    }
}

#[cfg(feature = "cdr-bundle")]
impl SyncStorage for BundleStore {
    fn exec(&mut self, req: IoReq, buf: IoBuf<'_>) -> StorageReceipt {
        match BundleStore::exec(self, req, buf) {
            Ok(n) => StorageReceipt::ok(n),
            Err(e) => StorageReceipt::failed_for(req.dir, e),
        }
    }
}

/// CD-R resource store: plaintext, or encrypted per track resource.
///
/// The cipher wraps the same [`BundleStore`] resources. Its `encrypt_from`
/// is [`snowscsi::mmc::cdr_bundle::TRACK_RESOURCE_BASE`] + 1 (`17`), so
/// `toc.0`/`toc.1` (resources 1/2) stay plaintext and resource `16` passes
/// through untouched (it is not a track, so the backend rejects it) while
/// every `track_<n>.bin` resource is encrypted with the manifest nonce XOR its
/// resource id.
///
/// A truncated or missing track file is zero-filled by [`BundleStore`] before
/// the cipher sees it, so its unavailable tail decrypts as keystream. The CD-R
/// medium normally bounds reads by the recorded length, so a healthy disc
/// never reaches that path; treat a short track as damaged data.
// The plain store is large; one CdrStore is built per LUN, not per operation
// (same rationale as `OwnedPlane` above).
#[allow(clippy::large_enum_variant)]
#[cfg(feature = "cdr-bundle")]
pub enum CdrStore {
    /// Plaintext CD-R resources.
    Plain(BundleStore),
    /// Track resources encrypted through the library cipher decorator.
    #[cfg(feature = "cipher")]
    Cipher(Box<CipherStore<BlockingStorage<BundleStore>, CliCipher>>),
}

#[cfg(feature = "cdr-bundle")]
impl CdrStore {
    /// Wrap a plaintext CD-R store.
    pub fn new(store: BundleStore) -> Self {
        Self::Plain(store)
    }

    /// Wrap a CD-R store whose track resources are encrypted.
    ///
    /// `nonce` is the manifest's 8-byte nonce; the decorator derives each
    /// resource's domain from it, so the TOC resources never change.
    #[cfg(feature = "cipher")]
    pub fn new_cipher(store: BundleStore, cipher: CliCipher, nonce: [u8; 8]) -> Self {
        Self::Cipher(Box::new(CipherStore::new(
            BlockingStorage::new(store),
            cipher,
            nonce,
            // `BundleStore` accepts only `resource > 16` (track 1 = 17), so
            // resource 16 is never transformed and stays a contract fault.
            snowscsi::mmc::cdr_bundle::TRACK_RESOURCE_BASE + 1,
        )))
    }

    /// Whether track resources are encrypted by this store.
    ///
    /// An encrypted recordable bundle must stay write-once: a CD-RW BLANK
    /// would let track 1 reuse resource 17 at offset 0 under the same
    /// `(key, nonce)` and therefore repeat a keystream.
    pub fn is_ciphered(&self) -> bool {
        #[cfg(feature = "cipher")]
        {
            matches!(self, Self::Cipher(_))
        }
        #[cfg(not(feature = "cipher"))]
        {
            false
        }
    }

    /// Restore (or create) the medium from the two alternating TOC slots.
    pub fn open_medium(
        &mut self,
        capacity_sectors: u64,
        kind: Option<DiscKind>,
        recovery: Recovery,
    ) -> Result<CdrBundleMedium, String> {
        match self {
            Self::Plain(store) => store.open_medium(capacity_sectors, kind, recovery),
            #[cfg(feature = "cipher")]
            Self::Cipher(store) => {
                store
                    .inner_mut()
                    .inner_mut()
                    .open_medium(capacity_sectors, kind, recovery)
            }
        }
    }

    /// Execute one resource-addressed request.
    pub fn exec(&mut self, req: IoReq, buf: IoBuf<'_>) -> Result<usize, StorageError> {
        match self {
            Self::Plain(store) => store.exec(req, buf),
            #[cfg(feature = "cipher")]
            Self::Cipher(store) => store.exec_now(req, buf),
        }
    }

    /// Nominal capacity in bytes.
    pub fn capacity_bytes(&self) -> u64 {
        match self {
            Self::Plain(store) => store.capacity_bytes(),
            #[cfg(feature = "cipher")]
            Self::Cipher(store) => store.inner().inner().capacity_bytes(),
        }
    }

    /// Aggregate flush (`Sync { resource: 0 }`).
    ///
    /// The cipher never touches TOC or sync bookkeeping, so this always
    /// delegates to the wrapped [`BundleStore`].
    pub fn sync(&mut self) -> Result<usize, StorageError> {
        match self {
            Self::Plain(store) => store.sync(),
            #[cfg(feature = "cipher")]
            Self::Cipher(store) => store.inner_mut().inner_mut().sync(),
        }
    }
}

impl OwnedPlane {
    /// Restore (or create) the CD-R/CD-RW medium behind this plane.
    #[cfg(feature = "cdr-bundle")]
    pub fn open_cdr_medium(
        &mut self,
        capacity_sectors: u64,
        kind: Option<DiscKind>,
        recovery: Recovery,
    ) -> Result<CdrBundleMedium, String> {
        match self {
            Self::CdrBundle(store) => store.open_medium(capacity_sectors, kind, recovery),
            _ => Err("not a CD-R/CD-RW bundle plane".to_string()),
        }
    }

    /// Logical sector size of a flat bundle plane, when this plane is one.
    ///
    /// The manifest owns the geometry, so the CLI block-device builders take
    /// the sector size from here instead of the spec's `sector=` default.
    pub fn sector_size(&self) -> Option<u32> {
        match self {
            #[cfg(feature = "bundle")]
            Self::Bundle(bundle) => Some(bundle.sector_size()),
            #[cfg(feature = "cipher")]
            Self::Cipher(plane) => plane.inner().sector_size(),
            _ => None,
        }
    }

    /// Whether this plane should be addressed as a writable plane.
    pub(crate) fn is_writable(&self) -> bool {
        match self {
            Self::BlockRw(_) => true,
            Self::Ram { writable, .. } => *writable,
            #[cfg(feature = "bundle")]
            Self::Bundle(bundle) => !bundle.is_read_only(),
            #[cfg(feature = "cdr-bundle")]
            Self::CdrBundle(_) => true,
            #[cfg(feature = "cipher")]
            Self::Cipher(plane) => plane.inner().is_writable(),
            Self::BlockRo(_) | Self::Live(_) => false,
        }
    }

    /// Whether this plane is the persistent CD-R directory store.
    #[cfg(feature = "cdr-bundle")]
    pub(crate) fn is_cdr_bundle(&self) -> bool {
        match self {
            Self::CdrBundle(_) => true,
            #[cfg(feature = "cipher")]
            Self::Cipher(plane) => plane.inner().is_cdr_bundle(),
            _ => false,
        }
    }

    /// Whether this plane is the persistent CD-R directory store.
    #[cfg(not(feature = "cdr-bundle"))]
    pub(crate) fn is_cdr_bundle(&self) -> bool {
        false
    }

    /// Build the erased borrow the synchronous store path executes on.
    fn as_store_plane(&mut self) -> StorePlane<'_> {
        if self.is_writable() {
            StorePlane::BlockRw(self)
        } else {
            StorePlane::BlockRo(self)
        }
    }

    /// Execute one storage request against the addressed resource.
    ///
    /// Block planes keep the single-resource (`0`) contract. A CD-R bundle
    /// routes resources onto its filesystem (`toc.0`/`toc.1`,
    /// `track_<n>.bin`) and treats any other id as unsupported. The return
    /// value is the confirmed byte count (`0` for a sync).
    pub fn exec(&mut self, req: IoReq, buf: IoBuf<'_>) -> Result<usize, StorageError> {
        #[cfg(feature = "cdr-bundle")]
        if let Self::CdrBundle(store) = self {
            return store.exec(req, buf);
        }
        if req.resource != 0 {
            return Err(StorageError::Unsupported);
        }
        let (op, confirmed) = match buf {
            IoBuf::None => (StoreOp::Sync, 0),
            IoBuf::Read(b) => {
                let len = b.len();
                (
                    StoreOp::Read {
                        off: req.offset,
                        buf: b,
                    },
                    len,
                )
            }
            IoBuf::Write(b) => {
                let len = b.len();
                (
                    StoreOp::Write {
                        off: req.offset,
                        buf: b,
                    },
                    len,
                )
            }
        };
        let mut plane = self.as_store_plane();
        plane.do_op(op)?;
        Ok(confirmed)
    }
}

/// Bounds-checked in-memory read.
pub(crate) fn ram_read(bytes: &[u8], off: u64, buf: &mut [u8]) -> Result<(), StorageError> {
    let start = usize::try_from(off).map_err(|_| StorageError::OutOfBounds)?;
    let end = start
        .checked_add(buf.len())
        .filter(|end| *end <= bytes.len())
        .ok_or(StorageError::OutOfBounds)?;
    buf.copy_from_slice(&bytes[start..end]);
    Ok(())
}

impl FlatData for OwnedPlane {
    fn read_at(&mut self, off: u64, buf: &mut [u8]) -> Result<(), StorageError> {
        match self {
            Self::BlockRo(backend) | Self::BlockRw(backend) => backend.read_at(off, buf),
            Self::Ram { bytes, .. } => ram_read(bytes, off, buf),
            #[cfg(feature = "bundle")]
            Self::Bundle(bundle) => bundle.read_at(off, buf),
            // The CD-R device addresses files by resource, never by a byte
            // offset on the plane.
            #[cfg(feature = "cdr-bundle")]
            Self::CdrBundle(_) => Err(StorageError::Unsupported),
            #[cfg(feature = "cipher")]
            Self::Cipher(plane) => FlatData::read_at(&mut **plane, off, buf),
            Self::Live(live) => live.read_at(off, buf),
        }
    }

    fn capacity(&self) -> u64 {
        match self {
            Self::BlockRo(backend) | Self::BlockRw(backend) => backend.capacity(),
            Self::Ram { bytes, .. } => bytes.len() as u64,
            #[cfg(feature = "bundle")]
            Self::Bundle(bundle) => bundle.capacity(),
            #[cfg(feature = "cdr-bundle")]
            Self::CdrBundle(store) => store.capacity_bytes(),
            #[cfg(feature = "cipher")]
            Self::Cipher(plane) => FlatData::capacity(&**plane),
            Self::Live(live) => live.capacity(),
        }
    }
}

impl WritableFlatData for OwnedPlane {
    fn write_at(&mut self, off: u64, buf: &[u8]) -> Result<(), StorageError> {
        match self {
            Self::BlockRw(backend) => backend.write_at(off, buf),
            Self::Ram {
                bytes,
                writable: true,
            } => ram_write(bytes, off, buf),
            #[cfg(feature = "bundle")]
            Self::Bundle(bundle) => bundle.write_at(off, buf),
            #[cfg(feature = "cdr-bundle")]
            Self::CdrBundle(_) => Err(StorageError::Unsupported),
            #[cfg(feature = "cipher")]
            Self::Cipher(plane) => WritableFlatData::write_at(&mut **plane, off, buf),
            _ => Err(StorageError::NotWritable),
        }
    }

    fn sync(&mut self) -> Result<(), StorageError> {
        match self {
            Self::BlockRw(backend) => backend.sync(),
            #[cfg(feature = "bundle")]
            Self::Bundle(bundle) => bundle.sync(),
            #[cfg(feature = "cdr-bundle")]
            Self::CdrBundle(store) => store.sync().map(|_| ()),
            #[cfg(feature = "cipher")]
            Self::Cipher(plane) => WritableFlatData::sync(&mut **plane),
            // A read-only plane, or memory that already is the store.
            Self::BlockRo(_) | Self::Live(_) | Self::Ram { .. } => Ok(()),
        }
    }

    fn fill_at(&mut self, off: u64, len: u64, byte: u8) -> Result<(), StorageError> {
        match self {
            Self::BlockRw(backend) => backend.fill_at(off, len, byte),
            Self::Ram {
                bytes,
                writable: true,
            } => {
                let start = usize::try_from(off).map_err(|_| StorageError::OutOfBounds)?;
                let end = usize::try_from(len)
                    .ok()
                    .and_then(|len| start.checked_add(len))
                    .filter(|end| *end <= bytes.len())
                    .ok_or(StorageError::OutOfBounds)?;
                bytes[start..end].fill(byte);
                Ok(())
            }
            #[cfg(feature = "bundle")]
            Self::Bundle(bundle) => bundle.fill_at(off, len, byte),
            #[cfg(feature = "cdr-bundle")]
            Self::CdrBundle(_) => Err(StorageError::Unsupported),
            #[cfg(feature = "cipher")]
            Self::Cipher(plane) => WritableFlatData::fill_at(&mut **plane, off, len, byte),
            _ => Err(StorageError::NotWritable),
        }
    }
}

/// Bounds-checked in-memory write.
pub(crate) fn ram_write(bytes: &mut [u8], off: u64, buf: &[u8]) -> Result<(), StorageError> {
    let start = usize::try_from(off).map_err(|_| StorageError::OutOfBounds)?;
    let end = start
        .checked_add(buf.len())
        .filter(|end| *end <= bytes.len())
        .ok_or(StorageError::OutOfBounds)?;
    bytes[start..end].copy_from_slice(buf);
    Ok(())
}

/// The media member of a CLI pair: a block slot has no medium, an MMC slot
/// carries one of the supported media.
// The recordable-CD medium's fixed track/session tables are large, but the CLI
// builds one pair per LUN (same rationale as `OwnedPlane`).
#[allow(clippy::large_enum_variant)]
pub enum CliPairMedium {
    /// Block slot (`NoMedium`).
    Block(snowscsi::core::NoMedium),
    /// MMC slot.
    Mmc(CliMedium),
}

/// The one pair type of the CLI target.
pub type CliPair = Pair<CliPairMedium, CliBacking>;

/// MMC medium enum: a flat read-only CD, a blank DVD-RAM, or a persistent
/// recordable-CD bundle.
// The recordable-CD medium's fixed track/session tables are large, but the CLI
// builds one per LUN (same rationale as `OwnedPlane`).
#[allow(clippy::large_enum_variant)]
pub enum CliMedium {
    /// Read-only CD data medium.
    Flat(FlatCdMedium),
    /// Rewritable DVD-RAM medium.
    #[cfg(feature = "dvdram")]
    DvdRam(DvdRamMedium),
    /// Sequential recordable CD (CD-R/CD-RW) with a persistent TOC.
    #[cfg(feature = "cdr-bundle")]
    CdrBundle(CdrBundleMedium),
}

impl MmcMedium for CliMedium {
    type State = ();

    fn attrs(&self) -> MmcAttrs {
        match self {
            Self::Flat(m) => m.attrs(),
            #[cfg(feature = "dvdram")]
            Self::DvdRam(m) => m.attrs(),
            #[cfg(feature = "cdr-bundle")]
            Self::CdrBundle(m) => m.attrs(),
        }
    }

    fn state(&self) -> &Self::State {
        &()
    }

    fn begin(&mut self, op: MmcOp) -> Result<(), Completion> {
        match self {
            Self::Flat(m) => m.begin(op),
            #[cfg(feature = "dvdram")]
            Self::DvdRam(m) => m.begin(op),
            #[cfg(feature = "cdr-bundle")]
            Self::CdrBundle(m) => m.begin(op),
        }
    }

    fn poll<'a>(&mut self, fb: Feedback, data: &'a mut [u8]) -> PollStep<'a> {
        match self {
            Self::Flat(m) => m.poll(fb, data),
            #[cfg(feature = "dvdram")]
            Self::DvdRam(m) => m.poll(fb, data),
            #[cfg(feature = "cdr-bundle")]
            Self::CdrBundle(m) => m.poll(fb, data),
        }
    }

    fn poll_with_alt<'a>(
        &mut self,
        fb: Feedback,
        data: &'a mut [u8],
        alt: &'a mut [u8],
    ) -> PollStep<'a> {
        match self {
            Self::Flat(m) => m.poll_with_alt(fb, data, alt),
            #[cfg(feature = "dvdram")]
            Self::DvdRam(m) => m.poll_with_alt(fb, data, alt),
            #[cfg(feature = "cdr-bundle")]
            Self::CdrBundle(m) => m.poll_with_alt(fb, data, alt),
        }
    }

    fn active(&self) -> bool {
        match self {
            Self::Flat(m) => m.active(),
            #[cfg(feature = "dvdram")]
            Self::DvdRam(m) => m.active(),
            #[cfg(feature = "cdr-bundle")]
            Self::CdrBundle(m) => m.active(),
        }
    }

    fn interrupt(&mut self, reason: InterruptReason, known: KnownEffects) {
        match self {
            Self::Flat(m) => m.interrupt(reason, known),
            #[cfg(feature = "dvdram")]
            Self::DvdRam(m) => m.interrupt(reason, known),
            #[cfg(feature = "cdr-bundle")]
            Self::CdrBundle(m) => m.interrupt(reason, known),
        }
    }

    fn commit(&mut self) -> Result<(), Completion> {
        match self {
            Self::Flat(m) => m.commit(),
            #[cfg(feature = "dvdram")]
            Self::DvdRam(m) => m.commit(),
            #[cfg(feature = "cdr-bundle")]
            Self::CdrBundle(m) => m.commit(),
        }
    }

    fn track(&self, number: u16) -> Option<Track> {
        match self {
            Self::Flat(m) => m.track(number),
            #[cfg(feature = "dvdram")]
            Self::DvdRam(m) => m.track(number),
            #[cfg(feature = "cdr-bundle")]
            Self::CdrBundle(m) => m.track(number),
        }
    }

    fn session(&self, number: u16) -> Option<Session> {
        match self {
            Self::Flat(m) => m.session(number),
            #[cfg(feature = "dvdram")]
            Self::DvdRam(m) => m.session(number),
            #[cfg(feature = "cdr-bundle")]
            Self::CdrBundle(m) => m.session(number),
        }
    }

    fn track_info(&self, request: TrackInfoRequest) -> Option<TrackInfo> {
        match self {
            Self::Flat(m) => m.track_info(request),
            #[cfg(feature = "dvdram")]
            Self::DvdRam(m) => m.track_info(request),
            // The default projection would lose invisible/lead-in tracks.
            #[cfg(feature = "cdr-bundle")]
            Self::CdrBundle(m) => m.track_info(request),
        }
    }

    fn disc_info(&self) -> DiscInfo {
        match self {
            Self::Flat(m) => m.disc_info(),
            #[cfg(feature = "dvdram")]
            Self::DvdRam(m) => m.disc_info(),
            #[cfg(feature = "cdr-bundle")]
            Self::CdrBundle(m) => m.disc_info(),
        }
    }

    fn atip(&self) -> Option<AtipInfo> {
        match self {
            Self::Flat(m) => m.atip(),
            #[cfg(feature = "dvdram")]
            Self::DvdRam(m) => m.atip(),
            // Only a recordable CD (CD-R/CD-RW) has a pre-groove; without
            // this forward the CLI would lose the medium's ATIP and answer
            // format 4 with 24/00.
            #[cfg(feature = "cdr-bundle")]
            Self::CdrBundle(m) => m.atip(),
        }
    }

    fn blank_supported(&self) -> bool {
        match self {
            Self::Flat(m) => m.blank_supported(),
            #[cfg(feature = "dvdram")]
            Self::DvdRam(m) => m.blank_supported(),
            // Without this forward the CLI would route BLANK to the generic
            // zero-fill path instead of the CD-RW's TOC reset.
            #[cfg(feature = "cdr-bundle")]
            Self::CdrBundle(m) => m.blank_supported(),
        }
    }

    fn set_test_write(&mut self, on: bool) {
        match self {
            Self::Flat(m) => m.set_test_write(on),
            #[cfg(feature = "dvdram")]
            Self::DvdRam(m) => m.set_test_write(on),
            // Without this forward the CLI accepts MODE SELECT Test Write but
            // the recordable-CD medium keeps recording.
            #[cfg(feature = "cdr-bundle")]
            Self::CdrBundle(m) => m.set_test_write(on),
        }
    }

    fn set_multi_session(&mut self, open: bool) {
        match self {
            Self::Flat(m) => m.set_multi_session(open),
            #[cfg(feature = "dvdram")]
            Self::DvdRam(m) => m.set_multi_session(open),
            // Without this forward the CLI accepts MODE SELECT Multi-session
            // but the recordable-CD medium finalizes on the next CLOSE.
            #[cfg(feature = "cdr-bundle")]
            Self::CdrBundle(m) => m.set_multi_session(open),
        }
    }
}

/// Block slot type: the public six-command SPC wrapper over a block profile.
pub type CliBlockLu = LuImpl<Spc<BlockDevice>, CliBacking>;
/// MMC slot type: the public six-command SPC wrapper over an MMC drive.
pub type CliMmcLu = LuImpl<Spc<MmcDrive<CliMedium>>, CliBacking>;

/// One runtime LUN over the two slot kinds, sharing [`CliPair`].
// The two slot kinds are deliberately unboxed: the CLI builds one per LUN and
// the size difference is a few hundred bytes, not a hot-path concern.
#[allow(clippy::large_enum_variant)]
pub enum CliLu {
    /// Block disk (PDT 0x00) or optical block profile.
    Block(CliBlockLu),
    /// MMC drive (PDT 0x05).
    Mmc(CliMmcLu),
}

fn block_pair(pair: Pair<snowscsi::core::NoMedium, CliBacking>) -> CliPair {
    Pair {
        medium: CliPairMedium::Block(pair.medium),
        backing: pair.backing,
    }
}

#[allow(clippy::result_large_err)]
fn from_block_pair(pair: CliPair) -> Result<Pair<snowscsi::core::NoMedium, CliBacking>, CliPair> {
    match pair.medium {
        CliPairMedium::Block(medium) => Ok(Pair {
            medium,
            backing: pair.backing,
        }),
        CliPairMedium::Mmc(_) => Err(pair),
    }
}

fn mmc_pair(pair: Pair<CliMedium, CliBacking>) -> CliPair {
    Pair {
        medium: CliPairMedium::Mmc(pair.medium),
        backing: pair.backing,
    }
}

#[allow(clippy::result_large_err)]
fn from_mmc_pair(pair: CliPair) -> Result<Pair<CliMedium, CliBacking>, CliPair> {
    match pair.medium {
        CliPairMedium::Mmc(medium) => Ok(Pair {
            medium,
            backing: pair.backing,
        }),
        CliPairMedium::Block(_) => Err(pair),
    }
}

fn convert_change<P, Q>(change: Change<P>, f: impl Fn(P) -> Q) -> Change<Q> {
    match change {
        Change::Install(p) => Change::Install(f(p)),
        Change::Replace(p) => Change::Replace(f(p)),
        Change::Remove => Change::Remove,
    }
}

fn convert_result<P, Q>(result: ChangeResult<P>, f: impl Fn(P) -> Q) -> ChangeResult<Q> {
    ChangeResult {
        pair: result.pair.map(f),
        local: result.local,
        delivery: result.delivery,
        effects: result.effects,
    }
}

impl Lu for CliLu {
    type Pair = CliPair;

    fn admit(&self, cdb: &[u8]) -> Admission {
        match self {
            Self::Block(lu) => lu.admit(cdb),
            Self::Mmc(lu) => lu.admit(cdb),
        }
    }

    fn prepare(
        &mut self,
        permit: &CommandPermit,
        ctx: CommandContext,
        cdb: &[u8],
    ) -> Result<(), Completion> {
        match self {
            Self::Block(lu) => lu.prepare(permit, ctx, cdb),
            Self::Mmc(lu) => lu.prepare(permit, ctx, cdb),
        }
    }

    fn active(&self) -> bool {
        match self {
            Self::Block(lu) => lu.active(),
            Self::Mmc(lu) => lu.active(),
        }
    }

    fn resume(&mut self, permit: &CommandPermit) -> Result<(), Completion> {
        match self {
            Self::Block(lu) => lu.resume(permit),
            Self::Mmc(lu) => lu.resume(permit),
        }
    }

    fn poll<'a>(
        &mut self,
        permit: &CommandPermit,
        feedback: Feedback,
        data: &'a mut [u8],
    ) -> PollStep<'a> {
        match self {
            Self::Block(lu) => lu.poll(permit, feedback, data),
            Self::Mmc(lu) => lu.poll(permit, feedback, data),
        }
    }

    fn poll_with_alt<'a>(
        &mut self,
        permit: &CommandPermit,
        feedback: Feedback,
        data: &'a mut [u8],
        alt: &'a mut [u8],
    ) -> PollStep<'a> {
        match self {
            Self::Block(lu) => lu.poll_with_alt(permit, feedback, data, alt),
            Self::Mmc(lu) => lu.poll_with_alt(permit, feedback, data, alt),
        }
    }

    fn poll_long<'a>(
        &mut self,
        permit: &CommandPermit,
        feedback: Feedback,
        data: &'a mut [u8],
    ) -> PollStep<'a> {
        match self {
            Self::Block(lu) => lu.poll_long(permit, feedback, data),
            Self::Mmc(lu) => lu.poll_long(permit, feedback, data),
        }
    }

    fn long_info(&self) -> LongInfo {
        match self {
            Self::Block(lu) => lu.long_info(),
            Self::Mmc(lu) => lu.long_info(),
        }
    }

    fn snapshot(&self) -> LuInfo {
        match self {
            Self::Block(lu) => lu.snapshot(),
            Self::Mmc(lu) => lu.snapshot(),
        }
    }

    fn interrupt(
        &mut self,
        permit: &CommandPermit,
        reason: InterruptReason,
        known: KnownEffects,
    ) -> Result<(), Fault> {
        match self {
            Self::Block(lu) => lu.interrupt(permit, reason, known),
            Self::Mmc(lu) => lu.interrupt(permit, reason, known),
        }
    }

    fn finish_delivery(&mut self, permit: &CommandPermit, delivery: Delivery) {
        match self {
            Self::Block(lu) => lu.finish_delivery(permit, delivery),
            Self::Mmc(lu) => lu.finish_delivery(permit, delivery),
        }
    }

    fn autosense_delivered(&mut self, permit: &CommandPermit, sense: Sense) {
        match self {
            Self::Block(lu) => lu.autosense_delivered(permit, sense),
            Self::Mmc(lu) => lu.autosense_delivered(permit, sense),
        }
    }

    fn raise_ua(&mut self, permit: &CommandPermit, class: UaClass) {
        match self {
            Self::Block(lu) => lu.raise_ua(permit, class),
            Self::Mmc(lu) => lu.raise_ua(permit, class),
        }
    }

    fn owner(&self) -> TargetId {
        match self {
            Self::Block(lu) => lu.owner(),
            Self::Mmc(lu) => lu.owner(),
        }
    }

    fn bind_owner(&mut self, permit: &OwnerBindPermit, owner: TargetId) {
        match self {
            Self::Block(lu) => lu.bind_owner(permit, owner),
            Self::Mmc(lu) => lu.bind_owner(permit, owner),
        }
    }

    fn take_rt(&mut self, permit: &BoundaryPermit) -> Option<ChangeResult<CliPair>> {
        match self {
            Self::Block(lu) => lu.take_rt(permit).map(|r| convert_result(r, block_pair)),
            Self::Mmc(lu) => lu.take_rt(permit).map(|r| convert_result(r, mmc_pair)),
        }
    }

    fn has_result(&self) -> bool {
        match self {
            Self::Block(lu) => lu.has_result(),
            Self::Mmc(lu) => lu.has_result(),
        }
    }

    fn force_remove_rt(&mut self, permit: &BoundaryPermit) -> Result<(), Fault> {
        match self {
            Self::Block(lu) => lu.force_remove_rt(permit),
            Self::Mmc(lu) => lu.force_remove_rt(permit),
        }
    }

    fn install_rt(
        &mut self,
        permit: &BoundaryPermit,
        pair: CliPair,
    ) -> Result<(), (CliPair, Fault)> {
        match self {
            Self::Block(lu) => match from_block_pair(pair) {
                Ok(pair) => lu
                    .install_rt(permit, pair)
                    .map_err(|(p, f)| (block_pair(p), f)),
                Err(pair) => Err((pair, Fault::Contract)),
            },
            Self::Mmc(lu) => match from_mmc_pair(pair) {
                Ok(pair) => lu
                    .install_rt(permit, pair)
                    .map_err(|(p, f)| (mmc_pair(p), f)),
                Err(pair) => Err((pair, Fault::Contract)),
            },
        }
    }

    fn propose_rt(
        &mut self,
        permit: &BoundaryPermit,
        change: Change<CliPair>,
    ) -> Result<(), (Change<CliPair>, Fault)> {
        match self {
            Self::Block(lu) => {
                let inner = change_cross(change, from_block_pair);
                match inner {
                    Ok(change) => lu
                        .propose_rt(permit, change)
                        .map_err(|(c, f)| (convert_change(c, block_pair), f)),
                    Err(change) => Err((change, Fault::Contract)),
                }
            }
            Self::Mmc(lu) => {
                let inner = change_cross(change, from_mmc_pair);
                match inner {
                    Ok(change) => lu
                        .propose_rt(permit, change)
                        .map_err(|(c, f)| (convert_change(c, mmc_pair), f)),
                    Err(change) => Err((change, Fault::Contract)),
                }
            }
        }
    }

    fn advance_rt(&mut self, permit: &BoundaryPermit) -> Result<(), Fault> {
        match self {
            Self::Block(lu) => lu.advance_rt(permit),
            Self::Mmc(lu) => lu.advance_rt(permit),
        }
    }

    fn eject_rt(&mut self, permit: &BoundaryPermit) -> Result<(), Fault> {
        match self {
            Self::Block(lu) => lu.eject_rt(permit),
            Self::Mmc(lu) => lu.eject_rt(permit),
        }
    }

    fn take_eject_request(&mut self) -> bool {
        // A removable block slot asks for an eject through the same gate as
        // the MMC drive; a fixed block slot never records one.
        match self {
            Self::Block(lu) => lu.take_eject_request(),
            Self::Mmc(lu) => lu.take_eject_request(),
        }
    }
}

/// Convert a `Change<CliPair>` into the slot-specific pair, keeping the
/// original on a type mismatch (the caller returns it unchanged).
#[allow(clippy::result_large_err)]
fn change_cross<P>(
    change: Change<CliPair>,
    f: impl Fn(CliPair) -> Result<P, CliPair>,
) -> Result<Change<P>, Change<CliPair>> {
    match change {
        Change::Install(pair) => match f(pair) {
            Ok(p) => Ok(Change::Install(p)),
            Err(pair) => Err(Change::Install(pair)),
        },
        Change::Replace(pair) => match f(pair) {
            Ok(p) => Ok(Change::Replace(p)),
            Err(pair) => Err(Change::Replace(pair)),
        },
        Change::Remove => Ok(Change::Remove),
    }
}

/// Fixed-slot synchronous storage over the per-LUN [`OwnedPlane`]s.
///
/// A plane executes synchronously, so `begin_exec` only records the request
/// and `poll_exec` builds the temporary [`StorePlane`] borrow, runs it and
/// answers `Ready` immediately. The runner selects the addressed LUN
/// (`Storage::select_lun`) before each entry, which keeps one adapter usable
/// for the whole heterogeneous slot set.
pub struct CliStorage {
    planes: Vec<Option<OwnedPlane>>,
    lun: usize,
    pending: Option<(IoReq, u32)>,
    tag: u32,
}

impl CliStorage {
    /// Build the adapter over one plane slot per LUN.
    pub fn new(planes: Vec<Option<OwnedPlane>>) -> Self {
        Self {
            planes,
            lun: 0,
            pending: None,
            tag: 1,
        }
    }

    /// Replace (or drop) one LUN's plane.
    ///
    /// A removable block LUN drops its plane on eject and installs a freshly
    /// opened one when the application inserts a new card. An out-of-range LUN
    /// is a no-op. USB-only (the iSCSI path has no card-swap loop).
    #[cfg(target_os = "linux")]
    pub fn set_plane(&mut self, lun: usize, plane: Option<OwnedPlane>) {
        if let Some(slot) = self.planes.get_mut(lun) {
            *slot = plane;
        }
    }

    /// Flush every plane; errors are returned for the caller to report.
    pub fn sync(
        &mut self,
    ) -> Result<(), (usize, snowscsi::common::seekable_storage::StorageError)> {
        for (i, plane) in self.planes.iter_mut().enumerate() {
            if let Some(plane) = plane {
                let req = IoReq {
                    resource: 0,
                    offset: 0,
                    len: 0,
                    dir: snowscsi::core::Direction::None,
                };
                plane.exec(req, IoBuf::None).map_err(|e| (i, e))?;
            }
        }
        Ok(())
    }

    fn contract() -> StorageReceipt {
        StorageReceipt::failed(Fault::Contract, 0, Effect::Known)
    }
}

impl Storage for CliStorage {
    fn select_lun(&mut self, lun: usize) {
        self.lun = lun;
    }

    fn resources_released(&mut self, lun: usize) {
        // A CD-R bundle cannot be re-addressed after a host eject: drop its
        // plane so the cached handles close. The eject path rendered the last
        // TOC best effort before this point.
        let is_bundle = self
            .planes
            .get(lun)
            .and_then(Option::as_ref)
            .is_some_and(OwnedPlane::is_cdr_bundle);
        if is_bundle {
            log::info!("LUN {lun}: recordable-CD bundle plane released after the eject");
            self.pending = None;
            self.planes[lun] = None;
        }
    }

    fn begin_exec(&mut self, req: IoReq) -> IoToken {
        if self.pending.is_some() || self.lun >= self.planes.len() {
            return IoToken::new(u8::MAX, 0);
        }
        let tag = self.tag;
        self.tag = self.tag.wrapping_add(1).max(1);
        self.pending = Some((req, tag));
        IoToken::new(0, tag)
    }

    fn poll_exec(&mut self, token: IoToken, buf: IoBuf<'_>) -> Poll<StorageReceipt> {
        let (req, tag) = match self.pending {
            Some((req, tag)) if token == IoToken::new(0, tag) => (req, tag),
            _ => return Poll::Ready(Self::contract()),
        };
        let _ = tag;
        self.pending = None;
        let ok = match (req.dir, &buf) {
            (snowscsi::core::Direction::None, IoBuf::None) => req.len == 0,
            (snowscsi::core::Direction::ToHost, IoBuf::Read(b)) => req.len as usize == b.len(),
            (snowscsi::core::Direction::FromHost, IoBuf::Write(b)) => req.len as usize == b.len(),
            _ => false,
        };
        if !ok {
            return Poll::Ready(Self::contract());
        }
        let Some(plane) = self.planes.get_mut(self.lun).and_then(|p| p.as_mut()) else {
            return Poll::Ready(Self::contract());
        };
        match plane.exec(req, buf) {
            Ok(confirmed) => Poll::Ready(StorageReceipt::ok(confirmed)),
            Err(e) => Poll::Ready(StorageReceipt::failed_for(req.dir, e)),
        }
    }

    fn cancel(&mut self, token: IoToken) {
        if let Some((_, tag)) = self.pending {
            if token == IoToken::new(0, tag) {
                self.pending = None;
            }
        }
    }
}

/// Inline storage never pends, so an async shell waiting on it completes on
/// the first poll (the same contract as the library's synchronous adapter).
#[cfg(feature = "tokio")]
impl snowscsi::core::async_wake::AsyncWake for CliStorage {
    fn poll_wake(&mut self, _cx: &mut core::task::Context<'_>) -> Poll<()> {
        Poll::Ready(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn assert_send<T: Send>() {}

    #[test]
    fn owned_plane_is_send() {
        assert_send::<OwnedPlane>();
    }

    // ── CD-R dirty-path bookkeeping ──────────────────────────────────────

    #[cfg(feature = "cdr-bundle")]
    #[test]
    fn dirty_paths_mark_tracks_and_slots_once() {
        let mut dirty = DirtyPaths::default();
        dirty.mark("track_1.bin");
        dirty.mark("toc.0");
        dirty.mark("track_1.bin");
        assert_eq!(dirty.paths, vec!["track_1.bin", "toc.0"]);
    }

    #[cfg(feature = "cdr-bundle")]
    #[test]
    fn dirty_paths_aggregate_sync_drains_everything_once() {
        let mut dirty = DirtyPaths::default();
        dirty.mark("track_1.bin");
        dirty.mark("toc.0");

        let mut synced = Vec::new();
        dirty
            .sync_all(|path| {
                synced.push(path.to_string());
                Ok(())
            })
            .unwrap();
        assert_eq!(synced, vec!["track_1.bin", "toc.0"]);
        assert!(dirty.paths.is_empty());

        // Nothing is dirty any more, so a second aggregate sync is a no-op.
        dirty
            .sync_all(|path| panic!("clean path re-synced: {path}"))
            .unwrap();
    }

    #[cfg(feature = "cdr-bundle")]
    #[test]
    fn dirty_paths_per_resource_sync_drains_only_that_path() {
        let mut dirty = DirtyPaths::default();
        dirty.mark("track_1.bin");
        dirty.mark("track_2.bin");

        let mut synced = Vec::new();
        assert!(dirty
            .sync_one("track_1.bin", || {
                synced.push("track_1.bin");
                Ok(())
            })
            .unwrap());
        assert_eq!(synced, vec!["track_1.bin"]);
        assert_eq!(dirty.paths, vec!["track_2.bin"]);

        // A clean path is not re-synced.
        assert!(!dirty
            .sync_one("track_1.bin", || panic!("clean path re-synced"))
            .unwrap());
        assert_eq!(dirty.paths, vec!["track_2.bin"]);
    }

    #[cfg(feature = "cdr-bundle")]
    #[test]
    fn dirty_paths_keep_a_failed_sync_for_retry() {
        let mut dirty = DirtyPaths::default();
        dirty.mark("track_1.bin");

        assert!(dirty.sync_all(|_| Err(FsError::OutOfBounds)).is_err());
        assert_eq!(dirty.paths, vec!["track_1.bin"]);

        assert!(dirty
            .sync_one("track_1.bin", || Err(FsError::OutOfBounds))
            .is_err());
        assert_eq!(dirty.paths, vec!["track_1.bin"]);
    }

    #[cfg(feature = "cdr-bundle")]
    #[test]
    fn reads_do_not_mark_a_path_dirty() {
        let dir = temp_dir("cdr_dirty_read");
        let fs = FsPlaneAdapter::new(StdFsBackend::new(&dir.to_string_lossy()));
        let mut store = BundleStore::new(fs, 359_849, None);

        let mut out = [0xAAu8; 8];
        assert_eq!(
            store.exec(
                io_req(17, 0, 8, snowscsi::core::Direction::ToHost),
                IoBuf::Read(&mut out)
            ),
            Ok(8)
        );
        assert!(store.dirty.paths.is_empty());

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[cfg(feature = "cdr-bundle")]
    #[test]
    fn missing_file_sync_is_not_an_error_and_drops_the_path() {
        let dir = temp_dir("cdr_dirty_missing");
        let fs = FsPlaneAdapter::new(StdFsBackend::new(&dir.to_string_lossy()));
        let mut store = BundleStore::new(fs, 359_849, None);

        store.dirty.mark("track_9.bin");
        assert_eq!(store.sync(), Ok(0));
        assert!(store.dirty.paths.is_empty());

        store.dirty.mark("toc.0");
        assert_eq!(store.sync_path("toc.0"), Ok(0));
        assert!(store.dirty.paths.is_empty());

        let _ = std::fs::remove_dir_all(&dir);
    }

    /// Storage that must never be used by the no-data eject command.
    struct NoStorage;

    impl Storage for NoStorage {
        fn begin_exec(&mut self, _req: IoReq) -> IoToken {
            IoToken::new(u8::MAX, 0)
        }

        fn poll_exec(&mut self, _token: IoToken, _buf: IoBuf<'_>) -> Poll<StorageReceipt> {
            Poll::Ready(StorageReceipt::failed(Fault::Contract, 0, Effect::Known))
        }

        fn cancel(&mut self, _token: IoToken) {}
    }

    #[test]
    fn block_lu_forwards_the_eject_request() {
        let ctx = CommandContext {
            lun: 0,
            lun_count: 1,
            host_bytes: 0,
            host_direction: snowscsi::core::Direction::None,
        };
        let cdb = [0x1B, 0, 0, 0, 0x02, 0];
        let mut work = [0u8; 64];
        let mut scratch = [0u8; 64];
        let mut storage = NoStorage;

        let mut removable = CliLu::Block(LuImpl::new(
            Spc::new(BlockDevice::new(
                snowscsi::block::BlockAttrs::new(16, 512).with_removable(),
            )),
            1,
        ));
        let mut target =
            snowscsi::core::Target::new([&mut removable as &mut dyn Lu<Pair = CliPair>]);
        assert_eq!(
            target.drive_rt(0, &mut storage, ctx, &cdb, &mut work, &mut scratch),
            Ok(Completion::Good)
        );
        assert_eq!(
            target.tick(),
            snowscsi::core::RunOutcome::ResourcesReady { lun: 0 },
            "CliLu must forward the block arm's eject request"
        );

        let mut fixed = CliLu::Block(LuImpl::new(
            Spc::new(BlockDevice::new(snowscsi::block::BlockAttrs::new(16, 512))),
            1,
        ));
        let mut target = snowscsi::core::Target::new([&mut fixed as &mut dyn Lu<Pair = CliPair>]);
        assert_eq!(
            target.drive_rt(0, &mut storage, ctx, &cdb, &mut work, &mut scratch),
            Ok(Completion::Good)
        );
        assert_ne!(
            target.tick(),
            snowscsi::core::RunOutcome::ResourcesReady { lun: 0 }
        );
    }

    // ── CD-R bundle plane ────────────────────────────────────────────────

    #[cfg(feature = "cdr-bundle")]
    fn temp_dir(tag: &str) -> std::path::PathBuf {
        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or(0);
        let dir =
            std::env::temp_dir().join(format!("snowscsi_{tag}_{}_{}", std::process::id(), nanos));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).expect("create temp dir");
        dir
    }

    #[cfg(feature = "cdr-bundle")]
    fn bundle_plane(dir: &std::path::Path) -> OwnedPlane {
        bundle_plane_with(dir, 359_849)
    }

    #[cfg(feature = "cdr-bundle")]
    fn bundle_plane_with(dir: &std::path::Path, capacity_sectors: u64) -> OwnedPlane {
        bundle_plane_slot(dir, capacity_sectors, None)
    }

    #[cfg(feature = "cdr-bundle")]
    fn bundle_plane_slot(
        dir: &std::path::Path,
        capacity_sectors: u64,
        slot: Option<u32>,
    ) -> OwnedPlane {
        let fs = FsPlaneAdapter::new(StdFsBackend::new(&dir.to_string_lossy()));
        OwnedPlane::CdrBundle(CdrStore::new(BundleStore::new(fs, capacity_sectors, slot)))
    }

    #[cfg(feature = "cdr-bundle")]
    fn bundle_plane_disc(dir: &std::path::Path, capacity_sectors: u64) -> OwnedPlane {
        bundle_plane_with(dir, capacity_sectors)
    }

    #[cfg(feature = "cdr-bundle")]
    fn io_req(resource: u16, offset: u64, len: u32, dir: snowscsi::core::Direction) -> IoReq {
        IoReq {
            resource,
            offset,
            len,
            dir,
        }
    }

    #[cfg(feature = "cdr-bundle")]
    struct PlaneStorage<'a>(&'a mut OwnedPlane);

    #[cfg(feature = "cdr-bundle")]
    impl snowscsi::core::storage::SyncStorage for PlaneStorage<'_> {
        fn exec(&mut self, req: IoReq, buf: IoBuf<'_>) -> StorageReceipt {
            match self.0.exec(req, buf) {
                Ok(confirmed) => StorageReceipt::ok(confirmed),
                Err(e) => StorageReceipt::failed_for(req.dir, e),
            }
        }
    }

    #[cfg(feature = "cdr-bundle")]
    struct NoHost;

    #[cfg(feature = "cdr-bundle")]
    impl snowscsi::core::storage::SyncHost for NoHost {
        fn publish(&mut self, _plan: snowscsi::core::DataPlan) -> Result<(), Fault> {
            Ok(())
        }
        fn receive(
            &mut self,
            req: snowscsi::core::storage::HostReq,
            _buf: snowscsi::core::storage::HostBuf<'_>,
        ) -> snowscsi::core::storage::HostReceipt {
            snowscsi::core::storage::HostReceipt::from_adapter(req.len as usize, None)
        }
        fn send(
            &mut self,
            req: snowscsi::core::storage::HostReq,
            _buf: snowscsi::core::storage::HostBuf<'_>,
        ) -> snowscsi::core::storage::HostReceipt {
            snowscsi::core::storage::HostReceipt::from_adapter(req.len as usize, None)
        }
        fn delivery(&self) -> Delivery {
            Delivery::Complete
        }
    }

    /// Drive SYNCHRONIZE CACHE through a real `MmcDrive<CdrBundleMedium>`.
    ///
    /// In TAO this closes the open track and saves the TOC, so a later
    /// CLOSE TRACK/SESSION can finalize the disc. The medium is borrowed, so
    /// the caller still owns it for the next command.
    #[cfg(feature = "cdr-bundle")]
    fn drive_sync_cache(plane: &mut OwnedPlane, medium: &mut CdrBundleMedium) {
        use snowscsi::core::storage::{BlockingHost, BlockingStorage};
        use snowscsi::core::{cons, Cons, Here, Nil, StaticTarget, Target};

        type SyncTarget<'a> = Target<Cons<LuImpl<Spc<MmcDrive<BorrowedMedium<'a>>>, u32>, Nil>>;
        let mut storage = BlockingStorage::new(PlaneStorage(plane));
        let mut host = BlockingHost::new(NoHost);
        let mut target = SyncTarget::new(cons(
            LuImpl::new(Spc::new(MmcDrive::new(BorrowedMedium(medium))), 1u32),
            Nil,
        ));
        let mut work = [0u8; 4096];
        let mut scratch = [0u8; 4096];
        let ctx = CommandContext {
            lun: 0,
            lun_count: 1,
            host_bytes: 0,
            host_direction: snowscsi::core::Direction::None,
        };
        // SYNCHRONIZE CACHE (10).
        let cdb = [0x35u8, 0, 0, 0, 0, 0, 0, 0, 0, 0];
        assert_eq!(
            target.drive_static_host::<Here>(
                &mut storage,
                &mut host,
                ctx,
                &cdb,
                &mut work,
                &mut scratch,
            ),
            Ok(Completion::Good)
        );
    }

    /// Drive one no-data MMC command (CLOSE TRACK/SESSION) through a real
    /// `MmcDrive<CdrBundleMedium>` so the medium performs its TOC save.
    #[cfg(feature = "cdr-bundle")]
    fn drive_close_session(plane: &mut OwnedPlane, medium: CdrBundleMedium) {
        use snowscsi::core::storage::{BlockingHost, BlockingStorage};
        use snowscsi::core::{cons, Cons, Here, Nil, StaticTarget, Target};

        type CloseTarget = Target<Cons<LuImpl<Spc<MmcDrive<CdrBundleMedium>>, u32>, Nil>>;
        let mut storage = BlockingStorage::new(PlaneStorage(plane));
        let mut host = BlockingHost::new(NoHost);
        let mut target = CloseTarget::new(cons(
            LuImpl::new(Spc::new(MmcDrive::new(medium)), 1u32),
            Nil,
        ));
        let mut work = [0u8; 4096];
        let mut scratch = [0u8; 4096];
        let ctx = CommandContext {
            lun: 0,
            lun_count: 1,
            host_bytes: 0,
            host_direction: snowscsi::core::Direction::None,
        };
        // CLOSE TRACK/SESSION, close function 010b (session).
        let cdb = [0x5B, 0, 2, 0, 0, 0, 0, 0, 0, 0];
        assert_eq!(
            target.drive_static_host::<Here>(
                &mut storage,
                &mut host,
                ctx,
                &cdb,
                &mut work,
                &mut scratch,
            ),
            Ok(Completion::Good)
        );
    }

    /// Issue BLANK (all) through a real `MmcDrive<CliMedium>` over a bundle
    /// directory, then reopen the directory and return the restored medium.
    #[cfg(feature = "cdr-bundle")]
    fn cli_blank(dir_name: &str, kind: Option<DiscKind>) -> (Completion, CdrBundleMedium) {
        use snowscsi::core::storage::{BlockingHost, BlockingStorage};
        use snowscsi::core::{cons, Cons, Here, Nil, StaticTarget, Target};

        type BlankTarget = Target<Cons<LuImpl<Spc<MmcDrive<CliMedium>>, u32>, Nil>>;

        let dir = temp_dir(dir_name);
        let mut plane = bundle_plane(&dir);
        let medium = plane
            .open_cdr_medium(359_849, kind, Recovery::Delete)
            .expect("bundle");
        let mut target = BlankTarget::new(cons(
            LuImpl::new(Spc::new(MmcDrive::new(CliMedium::CdrBundle(medium))), 1u32),
            Nil,
        ));
        let mut work = [0u8; 4096];
        let mut scratch = [0u8; 4096];
        let completion = {
            let mut storage = BlockingStorage::new(PlaneStorage(&mut plane));
            let mut host = BlockingHost::new(NoHost);
            target
                .drive_static_host::<Here>(
                    &mut storage,
                    &mut host,
                    command_ctx(snowscsi::core::Direction::None, 0),
                    &[0xA1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0],
                    &mut work,
                    &mut scratch,
                )
                .expect("BLANK reaches the target")
        };
        drop(target);
        let reopened = plane
            .open_cdr_medium(0, None, Recovery::Delete)
            .expect("reopen after BLANK");
        let _ = std::fs::remove_dir_all(&dir);
        (completion, reopened)
    }

    #[cfg(feature = "cdr-bundle")]
    #[test]
    fn cli_medium_forwards_blank_supported() {
        use snowscsi::mmc::CdrDiscState;

        let (completion, medium) = cli_blank("cli_cdrw_blank", Some(DiscKind::Cdrw));
        assert_eq!(completion, Completion::Good);
        assert_eq!(medium.kind(), DiscKind::Cdrw);
        assert_eq!(medium.disc_state(), CdrDiscState::Blank);
        assert_eq!(medium.attrs().profile, 0x000A);

        // A write-once CD-R has no blank state; BLANK is 24/00.
        let (completion, medium) = cli_blank("cli_cdr_blank", Some(DiscKind::Cdr));
        assert_eq!(completion, Completion::Check(snowscsi::core::INVALID_FIELD));
        assert_eq!(medium.kind(), DiscKind::Cdr);
        assert_eq!(medium.attrs().profile, 0x0009);
    }

    /// READ TOC format 4 must reach the medium through the CLI enum: without
    /// the `atip()` forward, the CLI would answer `24/00` on a CD-R.
    #[cfg(feature = "cdr-bundle")]
    #[test]
    fn cli_medium_forwards_atip_and_serves_format4() {
        use snowscsi::core::storage::{BlockingHost, BlockingStorage};
        use snowscsi::core::{cons, Cons, Here, Nil, StaticTarget, Target};
        use snowscsi::mmc::CdrCapacity;

        type TocTarget = Target<Cons<LuImpl<Spc<MmcDrive<CliMedium>>, u32>, Nil>>;

        let dir = temp_dir("cli_cdr_atip");
        let mut plane = bundle_plane(&dir);
        let medium = plane
            .open_cdr_medium(
                CdrCapacity::Cdr80.sectors(),
                Some(DiscKind::Cdr),
                Recovery::Delete,
            )
            .expect("fresh bundle");
        let cli = CliMedium::CdrBundle(medium);
        let atip = cli.atip().expect("the enum forwards the CD-R ATIP");
        assert_eq!(atip.lead_in, [97, 34, 23]);
        assert_eq!(atip.lead_out, [79, 59, 74]);

        let mut target = TocTarget::new(cons(LuImpl::new(Spc::new(MmcDrive::new(cli)), 1u32), Nil));
        let mut storage = BlockingStorage::new(PlaneStorage(&mut plane));
        let mut host = BlockingHost::new(NoHost);
        let mut work = [0u8; 4096];
        let mut scratch = [0u8; 4096];
        let ctx = CommandContext {
            lun: 0,
            lun_count: 1,
            host_bytes: 28,
            host_direction: snowscsi::core::Direction::ToHost,
        };
        // READ TOC/PMA/ATIP, format 4 (ATIP), allocation length 28.
        let mut cdb = [0u8; 10];
        cdb[0] = 0x43;
        cdb[2] = 4;
        cdb[8] = 28;
        assert_eq!(
            target.drive_static_host::<Here>(
                &mut storage,
                &mut host,
                ctx,
                &cdb,
                &mut work,
                &mut scratch,
            ),
            Ok(Completion::Good)
        );
        assert_eq!(&work[0..2], &26u16.to_be_bytes(), "ATIP data length");
        assert_eq!(work[6], 0x80, "descriptor byte 2: CD-R, no A-valid");
        assert_eq!(&work[12..15], &[79, 59, 74], "lead-out M/S/F");

        let _ = std::fs::remove_dir_all(&dir);
    }

    /// The CLI enum must forward `set_multi_session` to the CD-R medium:
    /// without it the medium would finalize on the next CLOSE SESSION even
    /// though the host asked for another session.
    #[cfg(feature = "cdr-bundle")]
    #[test]
    fn cli_medium_forwards_multi_session() {
        use snowscsi::mmc::CdrCapacity;

        let dir = temp_dir("cli_cdr_multi");
        let mut plane = bundle_plane(&dir);
        let medium = plane
            .open_cdr_medium(
                CdrCapacity::Cdr80.sectors(),
                Some(DiscKind::Cdr),
                Recovery::Delete,
            )
            .expect("fresh bundle");
        let mut cli = CliMedium::CdrBundle(medium);
        assert!(!cli_multi(&cli));
        cli.set_multi_session(true);
        assert!(cli_multi(&cli));
        cli.set_multi_session(false);
        assert!(!cli_multi(&cli));

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[cfg(feature = "cdr-bundle")]
    fn cli_multi(medium: &CliMedium) -> bool {
        match medium {
            CliMedium::CdrBundle(medium) => medium.multi_session(),
            _ => panic!("expected a CD-R bundle medium"),
        }
    }

    #[cfg(feature = "cdr-bundle")]
    fn command_ctx(direction: snowscsi::core::Direction, bytes: u64) -> CommandContext {
        CommandContext {
            lun: 0,
            lun_count: 1,
            host_bytes: bytes,
            host_direction: direction,
        }
    }

    /// MODE SELECT(10) parameter list with Test Write + TAO / Data Block Type 8.
    #[cfg(feature = "cdr-bundle")]
    fn dummy_mode_page() -> Vec<u8> {
        let mut page = vec![0u8; 60];
        page[0..2].copy_from_slice(&58u16.to_be_bytes());
        page[8] = 0x05;
        page[9] = 0x32;
        page[10] = 0x01 | 0x10; // Test Write | Track-at-Once
        page[11] = 0x04; // Track Mode: data
        page[12] = 0x08; // Data Block Type: Mode 1
        page
    }

    /// The CLI enum must forward `set_test_write` to the CD-R medium: without
    /// it the accepted `-dummy` mode still records, creating `track_*.bin` and
    /// a TOC slot in the bundle directory.
    #[cfg(feature = "cdr-bundle")]
    #[test]
    fn cli_medium_forwards_test_write_and_keeps_the_bundle_blank() {
        use snowscsi::core::storage::{BlockingHost, BlockingStorage};
        use snowscsi::core::{cons, Cons, Here, Nil, StaticTarget, Target};
        use snowscsi::mmc::{CdrCapacity, CdrDiscState};

        type DummyTarget = Target<Cons<LuImpl<Spc<MmcDrive<CliMedium>>, u32>, Nil>>;

        let dir = temp_dir("cli_cdr_dummy");
        let mut plane = bundle_plane(&dir);
        let medium = plane
            .open_cdr_medium(
                CdrCapacity::Cdr80.sectors(),
                Some(DiscKind::Cdr),
                Recovery::Delete,
            )
            .expect("fresh bundle");
        let mut target = DummyTarget::new(cons(
            LuImpl::new(Spc::new(MmcDrive::new(CliMedium::CdrBundle(medium))), 1u32),
            Nil,
        ));
        let mut work = [0u8; 4096];
        let mut scratch = [0u8; 4096];

        {
            let mut storage = BlockingStorage::new(PlaneStorage(&mut plane));

            // MODE SELECT(10) page 0x05: Test Write + TAO / DBT 8.
            let params = dummy_mode_page();
            let mut cdb = [0u8; 10];
            cdb[0] = 0x55;
            cdb[1] = 0x10;
            cdb[7..9].copy_from_slice(&(params.len() as u16).to_be_bytes());
            let mut host = BlockingHost::new(BytesHost(params));
            assert_eq!(
                target.drive_static_host::<Here>(
                    &mut storage,
                    &mut host,
                    command_ctx(snowscsi::core::Direction::FromHost, 60),
                    &cdb,
                    &mut work,
                    &mut scratch,
                ),
                Ok(Completion::Good)
            );

            // WRITE(10) with FUA at the NWA: the simulated data phase spans
            // more than one bank and must not issue the post-write sync.
            let mut cdb = [0u8; 10];
            cdb[0] = 0x2A;
            cdb[1] = 0x08; // FUA
            cdb[7..9].copy_from_slice(&3u16.to_be_bytes());
            let mut host = BlockingHost::new(FillHost(0x5A));
            assert_eq!(
                target.drive_static_host::<Here>(
                    &mut storage,
                    &mut host,
                    command_ctx(snowscsi::core::Direction::FromHost, 3 * 2048),
                    &cdb,
                    &mut work,
                    &mut scratch,
                ),
                Ok(Completion::Good)
            );

            // SYNCHRONIZE CACHE and CLOSE TRACK/SESSION 010b are no-ops.
            let mut host = BlockingHost::new(NoHost);
            let mut sync = [0u8; 10];
            sync[0] = 0x35;
            assert_eq!(
                target.drive_static_host::<Here>(
                    &mut storage,
                    &mut host,
                    command_ctx(snowscsi::core::Direction::None, 0),
                    &sync,
                    &mut work,
                    &mut scratch,
                ),
                Ok(Completion::Good)
            );
            let close = [0x5B, 0, 2, 0, 0, 0, 0, 0, 0, 0];
            assert_eq!(
                target.drive_static_host::<Here>(
                    &mut storage,
                    &mut host,
                    command_ctx(snowscsi::core::Direction::None, 0),
                    &close,
                    &mut work,
                    &mut scratch,
                ),
                Ok(Completion::Good)
            );
        }

        let names: Vec<String> = std::fs::read_dir(&dir)
            .expect("bundle directory")
            .map(|entry| entry.unwrap().file_name().to_string_lossy().into_owned())
            .collect();
        assert!(
            names
                .iter()
                .all(|name| !name.starts_with("toc.") && !name.starts_with("track_")),
            "a simulated burn wrote bundle files: {names:?}"
        );

        let reopened = plane
            .open_cdr_medium(
                CdrCapacity::Cdr80.sectors(),
                Some(DiscKind::Cdr),
                Recovery::Delete,
            )
            .expect("reopen the simulated disc");
        assert_eq!(reopened.disc_state(), CdrDiscState::Blank);
        assert_eq!(reopened.toc_seq(), 0);
        assert_eq!(reopened.attrs().tracks, 0);

        let _ = std::fs::remove_dir_all(&dir);
    }

    /// Host that fills every received data phase with one byte value.
    #[cfg(feature = "cdr-bundle")]
    struct FillHost(u8);

    #[cfg(feature = "cdr-bundle")]
    impl snowscsi::core::storage::SyncHost for FillHost {
        fn publish(&mut self, _plan: snowscsi::core::DataPlan) -> Result<(), Fault> {
            Ok(())
        }
        fn receive(
            &mut self,
            req: snowscsi::core::storage::HostReq,
            buf: snowscsi::core::storage::HostBuf<'_>,
        ) -> snowscsi::core::storage::HostReceipt {
            match buf {
                snowscsi::core::storage::HostBuf::Recv { buf: bytes, .. } => {
                    let accepted = (req.len as usize).min(bytes.len());
                    bytes[..accepted].fill(self.0);
                    snowscsi::core::storage::HostReceipt::from_adapter(accepted, None)
                }
                snowscsi::core::storage::HostBuf::Send { .. } => {
                    snowscsi::core::storage::HostReceipt::from_adapter(0, Some(Fault::Contract))
                }
            }
        }
        fn send(
            &mut self,
            _req: snowscsi::core::storage::HostReq,
            _buf: snowscsi::core::storage::HostBuf<'_>,
        ) -> snowscsi::core::storage::HostReceipt {
            snowscsi::core::storage::HostReceipt::from_adapter(0, Some(Fault::Contract))
        }
        fn delivery(&self) -> Delivery {
            Delivery::Complete
        }
    }

    /// Host that supplies a fixed byte payload to a FromHost data phase.
    #[cfg(feature = "cdr-bundle")]
    struct BytesHost(Vec<u8>);

    #[cfg(feature = "cdr-bundle")]
    impl snowscsi::core::storage::SyncHost for BytesHost {
        fn publish(&mut self, _plan: snowscsi::core::DataPlan) -> Result<(), Fault> {
            Ok(())
        }
        fn receive(
            &mut self,
            req: snowscsi::core::storage::HostReq,
            buf: snowscsi::core::storage::HostBuf<'_>,
        ) -> snowscsi::core::storage::HostReceipt {
            match buf {
                snowscsi::core::storage::HostBuf::Recv { buf: bytes, .. } => {
                    let accepted = (req.len as usize).min(bytes.len()).min(self.0.len());
                    bytes[..accepted].copy_from_slice(&self.0[..accepted]);
                    snowscsi::core::storage::HostReceipt::from_adapter(accepted, None)
                }
                snowscsi::core::storage::HostBuf::Send { .. } => {
                    snowscsi::core::storage::HostReceipt::from_adapter(0, Some(Fault::Contract))
                }
            }
        }
        fn send(
            &mut self,
            req: snowscsi::core::storage::HostReq,
            _buf: snowscsi::core::storage::HostBuf<'_>,
        ) -> snowscsi::core::storage::HostReceipt {
            snowscsi::core::storage::HostReceipt::from_adapter(req.len as usize, None)
        }
        fn delivery(&self) -> Delivery {
            Delivery::Complete
        }
    }
    #[cfg(feature = "cdr-bundle")]
    struct BorrowedMedium<'a>(&'a mut CdrBundleMedium);

    #[cfg(feature = "cdr-bundle")]
    impl MmcMedium for BorrowedMedium<'_> {
        type State = <CdrBundleMedium as MmcMedium>::State;

        fn attrs(&self) -> MmcAttrs {
            self.0.attrs()
        }

        fn state(&self) -> &Self::State {
            self.0.state()
        }

        fn begin(&mut self, op: MmcOp) -> Result<(), Completion> {
            self.0.begin(op)
        }

        fn poll<'a>(&mut self, fb: Feedback, data: &'a mut [u8]) -> PollStep<'a> {
            self.0.poll(fb, data)
        }

        fn poll_with_alt<'a>(
            &mut self,
            fb: Feedback,
            data: &'a mut [u8],
            alt: &'a mut [u8],
        ) -> PollStep<'a> {
            self.0.poll_with_alt(fb, data, alt)
        }

        fn active(&self) -> bool {
            self.0.active()
        }

        fn interrupt(&mut self, reason: InterruptReason, known: KnownEffects) {
            self.0.interrupt(reason, known);
        }

        fn commit(&mut self) -> Result<(), Completion> {
            self.0.commit()
        }

        fn track(&self, number: u16) -> Option<Track> {
            self.0.track(number)
        }

        fn session(&self, number: u16) -> Option<Session> {
            self.0.session(number)
        }

        fn track_info(&self, request: TrackInfoRequest) -> Option<TrackInfo> {
            self.0.track_info(request)
        }

        fn disc_info(&self) -> DiscInfo {
            self.0.disc_info()
        }

        fn atip(&self) -> Option<AtipInfo> {
            self.0.atip()
        }

        fn blank_supported(&self) -> bool {
            self.0.blank_supported()
        }

        fn set_test_write(&mut self, on: bool) {
            self.0.set_test_write(on);
        }

        fn set_multi_session(&mut self, open: bool) {
            self.0.set_multi_session(open);
        }
    }

    /// Drive one WRITE(10) block through a real `MmcDrive<CdrBundleMedium>`,
    /// leaving the medium open (and therefore unsaved) for the test.
    #[cfg(feature = "cdr-bundle")]
    fn drive_write_track(plane: &mut OwnedPlane, medium: &mut CdrBundleMedium, lba: u64) {
        use snowscsi::core::storage::{BlockingHost, BlockingStorage};
        use snowscsi::core::{cons, Cons, Here, Nil, StaticTarget, Target};

        type WriteTarget<'a> = Target<Cons<LuImpl<Spc<MmcDrive<BorrowedMedium<'a>>>, u32>, Nil>>;
        let mut storage = BlockingStorage::new(PlaneStorage(plane));
        let mut host = BlockingHost::new(FillHost(0x5A));
        let mut target = WriteTarget::new(cons(
            LuImpl::new(Spc::new(MmcDrive::new(BorrowedMedium(medium))), 1u32),
            Nil,
        ));
        let mut work = [0u8; 4096];
        let mut scratch = [0u8; 4096];
        let ctx = CommandContext {
            lun: 0,
            lun_count: 1,
            host_bytes: 2048,
            host_direction: snowscsi::core::Direction::FromHost,
        };
        // WRITE(10): one block at `lba`.
        let mut cdb = [0u8; 10];
        cdb[0] = 0x2A;
        cdb[2..6].copy_from_slice(&(lba as u32).to_be_bytes());
        cdb[7..9].copy_from_slice(&1u16.to_be_bytes());
        assert_eq!(
            target.drive_static_host::<Here>(
                &mut storage,
                &mut host,
                ctx,
                &cdb,
                &mut work,
                &mut scratch,
            ),
            Ok(Completion::Good)
        );
    }

    #[cfg(feature = "cdr-bundle")]
    #[test]
    fn cdr_bundle_exec_routes_resources() {
        use snowscsi::core::Direction;

        let dir = temp_dir("cdr_exec");
        let mut plane = bundle_plane(&dir);

        // TOC slot 0 (resource 1).
        let mut hello = *b"hello";
        assert_eq!(
            plane.exec(
                io_req(1, 0, 5, Direction::FromHost),
                IoBuf::Write(&mut hello)
            ),
            Ok(5)
        );
        let mut toc0 = [0u8; 5];
        assert_eq!(
            plane.exec(io_req(1, 0, 5, Direction::ToHost), IoBuf::Read(&mut toc0)),
            Ok(5)
        );
        assert_eq!(&toc0, b"hello");

        // TOC slot 1 (resource 2) is an independent file.
        let mut world = *b"world";
        assert_eq!(
            plane.exec(
                io_req(2, 4, 5, Direction::FromHost),
                IoBuf::Write(&mut world)
            ),
            Ok(5)
        );
        let mut toc1 = [0u8; 9];
        assert_eq!(
            plane.exec(io_req(2, 0, 9, Direction::ToHost), IoBuf::Read(&mut toc1)),
            Ok(9)
        );
        assert_eq!(&toc1[..4], &[0u8; 4]);
        assert_eq!(&toc1[4..], b"world");

        // Track 1 (`16 + 1`).
        let mut data = *b"data";
        assert_eq!(
            plane.exec(
                io_req(17, 0, 4, Direction::FromHost),
                IoBuf::Write(&mut data)
            ),
            Ok(4)
        );
        let mut track = [0u8; 4];
        assert_eq!(
            plane.exec(io_req(17, 0, 4, Direction::ToHost), IoBuf::Read(&mut track)),
            Ok(4)
        );
        assert_eq!(&track, b"data");

        // A short track read keeps the readable prefix and zero-fills only
        // the suffix.
        let mut short = [0xAAu8; 8];
        assert_eq!(
            plane.exec(io_req(17, 2, 8, Direction::ToHost), IoBuf::Read(&mut short)),
            Ok(8)
        );
        assert_eq!(&short[..2], b"ta");
        assert_eq!(&short[2..], &[0u8; 6]);

        // A reused track id truncates on its first write, so no stale tail
        // survives.
        let mut digits = *b"01234567";
        assert_eq!(
            plane.exec(
                io_req(17, 0, 8, Direction::FromHost),
                IoBuf::Write(&mut digits)
            ),
            Ok(8)
        );
        let mut abcd = *b"ABCD";
        assert_eq!(
            plane.exec(
                io_req(17, 0, 4, Direction::FromHost),
                IoBuf::Write(&mut abcd)
            ),
            Ok(4)
        );
        let mut reused = [0xAAu8; 8];
        assert_eq!(
            plane.exec(
                io_req(17, 0, 8, Direction::ToHost),
                IoBuf::Read(&mut reused)
            ),
            Ok(8)
        );
        assert_eq!(&reused[..4], b"ABCD");
        assert_eq!(&reused[4..], &[0u8; 4]);

        // A missing track file is an empty track (all zeros).
        let mut missing = [0xAAu8; 8];
        assert_eq!(
            plane.exec(
                io_req(18, 0, 8, Direction::ToHost),
                IoBuf::Read(&mut missing)
            ),
            Ok(8)
        );
        assert_eq!(missing, [0u8; 8]);

        // A short/missing TOC slot stays strict.
        let mut one = [0u8; 1];
        assert_eq!(
            plane.exec(io_req(1, 10, 1, Direction::ToHost), IoBuf::Read(&mut one)),
            Err(StorageError::OutOfBounds)
        );

        // Unknown resources and plain byte addressing are unsupported, and
        // track ids are bounded by the slot layout.
        for resource in [3u16, 4, 15, 16] {
            assert_eq!(
                plane.exec(
                    io_req(resource, 0, 1, Direction::ToHost),
                    IoBuf::Read(&mut one)
                ),
                Err(StorageError::Unsupported),
                "resource {resource}"
            );
        }
        assert_eq!(
            plane.exec(
                io_req(65535, 0, 1, Direction::ToHost),
                IoBuf::Read(&mut one)
            ),
            Err(StorageError::Unsupported)
        );
        assert_eq!(
            plane.exec(io_req(0, 0, 1, Direction::ToHost), IoBuf::Read(&mut one)),
            Err(StorageError::Unsupported)
        );
        let mut zero = [0u8; 1];
        assert_eq!(
            plane.exec(
                io_req(0, 0, 1, Direction::FromHost),
                IoBuf::Write(&mut zero)
            ),
            Err(StorageError::Unsupported)
        );

        // `resource 0` is the aggregate flush; every file resource also syncs.
        assert_eq!(
            plane.exec(io_req(0, 0, 0, Direction::None), IoBuf::None),
            Ok(0)
        );
        assert_eq!(
            plane.exec(io_req(1, 0, 0, Direction::None), IoBuf::None),
            Ok(0)
        );
        assert_eq!(
            plane.exec(io_req(17, 0, 0, Direction::None), IoBuf::None),
            Ok(0)
        );

        // The plane's nominal geometry is the medium preset; byte addressing
        // is not part of the model.
        assert_eq!(FlatData::capacity(&plane), 359_849 * 2048);
        assert_eq!(plane.read_at(0, &mut one), Err(StorageError::Unsupported));
        assert_eq!(plane.write_at(0, &[0]), Err(StorageError::Unsupported));

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[cfg(feature = "cdr-bundle")]
    #[test]
    fn cdr_bundle_toc_survives_reopen() {
        use snowscsi::mmc::cdr_bundle::TOC_SLOT_DEFAULT;
        use snowscsi::mmc::CdrDiscState;

        let dir = temp_dir("cdr_reopen");
        let mut plane = bundle_plane(&dir);

        let medium = plane
            .open_cdr_medium(359_849, Some(DiscKind::Cdr), Recovery::Delete)
            .expect("fresh bundle");
        assert_eq!(medium.toc_seq(), 0);

        // CLOSE SESSION on a blank disc is a success no-op once its (empty)
        // TOC slot has been saved.
        drive_close_session(&mut plane, medium);

        let reopened = plane
            .open_cdr_medium(359_849, Some(DiscKind::Cdr), Recovery::Delete)
            .expect("reopen bundle");
        assert_eq!(reopened.toc_seq(), 1);
        assert_eq!(reopened.disc_state(), CdrDiscState::Blank);
        assert_eq!(reopened.slot_size(), TOC_SLOT_DEFAULT);
        assert!(dir.join("toc.0").is_file());
        assert_eq!(
            std::fs::metadata(dir.join("toc.0")).unwrap().len(),
            u64::from(TOC_SLOT_DEFAULT)
        );

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[cfg(feature = "cdr-bundle")]
    #[test]
    fn cdr_bundle_kind_hint_and_stored_kind() {
        use snowscsi::mmc::CdrDiscState;

        // A fresh directory uses the hint: a CD-RW preset creates a CD-RW.
        let dir = temp_dir("cdr_kind_cdrw");
        let mut plane = bundle_plane_disc(&dir, 359_849);
        let medium = plane
            .open_cdr_medium(359_849, Some(DiscKind::Cdrw), Recovery::Delete)
            .expect("fresh CD-RW bundle");
        assert_eq!(medium.kind(), DiscKind::Cdrw);
        assert_eq!(medium.attrs().profile, 0x000A);
        drive_close_session(&mut plane, medium);

        // Opening without `medium=` (kind = None) must simply restore the
        // stored kind and never warn.
        let restored = plane
            .open_cdr_medium(359_849, None, Recovery::Delete)
            .expect("reopen CD-RW bundle without a kind hint");
        assert_eq!(restored.kind(), DiscKind::Cdrw);

        // An explicit conflicting CD-R hint also loses to the stored TOC (the
        // mismatch is logged like a capacity mismatch).
        let reopened = plane
            .open_cdr_medium(359_849, Some(DiscKind::Cdr), Recovery::Delete)
            .expect("reopen CD-RW bundle");
        assert_eq!(reopened.kind(), DiscKind::Cdrw);
        assert_eq!(reopened.disc_state(), CdrDiscState::Blank);
        assert_eq!(reopened.attrs().profile, 0x000A);

        // The reverse: a stored CD-R TOC wins over `medium=cdrw80`-style hint.
        let cdr_dir = temp_dir("cdr_kind_stored_cdr");
        let mut cdr_plane = bundle_plane(&cdr_dir);
        let cdr = cdr_plane
            .open_cdr_medium(359_849, Some(DiscKind::Cdr), Recovery::Delete)
            .expect("fresh CD-R bundle");
        drive_close_session(&mut cdr_plane, cdr);
        let reopened = cdr_plane
            .open_cdr_medium(359_849, Some(DiscKind::Cdrw), Recovery::Delete)
            .expect("reopen CD-R bundle");
        assert_eq!(reopened.kind(), DiscKind::Cdr);
        assert_eq!(reopened.attrs().profile, 0x0009);

        let _ = std::fs::remove_dir_all(&dir);
        let _ = std::fs::remove_dir_all(&cdr_dir);
    }

    #[cfg(feature = "cdr-bundle")]
    #[test]
    fn cdr_bundle_open_removes_orphan_tracks_on_delete_only() {
        let dir = temp_dir("cdr_orphans");
        // The default 64 KiB slot persists up to 99 track ids, so track 100 is
        // above the configured bound.
        let mut plane = bundle_plane(&dir);
        let mut medium = plane
            .open_cdr_medium(359_849, Some(DiscKind::Cdr), Recovery::Delete)
            .expect("fresh bundle");
        drive_write_track(&mut plane, &mut medium, 0);
        drive_sync_cache(&mut plane, &mut medium);
        drive_close_session(&mut plane, medium);
        assert!(dir.join("track_1.bin").is_file(), "track 1 was recorded");

        // 20 in-range but unreferenced ids (more than the initial 16-entry
        // batch, so the scan must grow), one id above the slot maximum, one
        // non-canonical spelling of the unreferenced track 2, and one
        // non-canonical spelling of the *referenced* track 1.
        for track in 2..=21u16 {
            std::fs::write(dir.join(format!("track_{track}.bin")), b"orphan").unwrap();
        }
        std::fs::write(dir.join("track_100.bin"), b"stray").unwrap();
        std::fs::write(dir.join("track_02.bin"), b"odd").unwrap();
        std::fs::write(dir.join("track_01.bin"), b"odd-canonical").unwrap();
        let mut orphan_names: Vec<String> = (2..=21u16)
            .map(|track| format!("track_{track}.bin"))
            .collect();
        orphan_names.push("track_100.bin".to_string());
        orphan_names.push("track_02.bin".to_string());
        orphan_names.push("track_01.bin".to_string());
        assert!(orphan_names.len() > 16, "batch growth must be exercised");

        let toc_before: Vec<Option<Vec<u8>>> = ["toc.0", "toc.1"]
            .iter()
            .map(|name| std::fs::read(dir.join(name)).ok())
            .collect();

        // A read-only open is a recovery view: it must not delete anything.
        let mut readonly_plane = bundle_plane(&dir);
        let readonly = readonly_plane
            .open_cdr_medium(0, Some(DiscKind::Cdr), Recovery::ReadOnly)
            .expect("read-only restore");
        assert_eq!(readonly.track_numbers().collect::<Vec<_>>(), vec![1]);
        for name in &orphan_names {
            assert!(dir.join(name).is_file(), "read-only open removed {name}");
        }
        assert!(dir.join("track_1.bin").is_file());
        drop(readonly_plane);

        // A delete open reconciles the directory against the restored TOC.
        let mut plane = bundle_plane(&dir);
        let medium = plane
            .open_cdr_medium(0, Some(DiscKind::Cdr), Recovery::Delete)
            .expect("reopen");
        assert_eq!(medium.track_numbers().collect::<Vec<_>>(), vec![1]);
        assert!(
            dir.join("track_1.bin").is_file(),
            "a referenced canonical track stays"
        );
        for name in &orphan_names {
            assert!(!dir.join(name).exists(), "{name} must be removed");
        }
        for (name, before) in ["toc.0", "toc.1"].iter().zip(toc_before) {
            assert_eq!(
                std::fs::read(dir.join(name)).ok(),
                before,
                "{name} must never be touched"
            );
        }

        // A second delete open is a no-op: every remaining track is in the TOC.
        drop(plane);
        let mut plane = bundle_plane(&dir);
        plane
            .open_cdr_medium(0, Some(DiscKind::Cdr), Recovery::Delete)
            .expect("reopen again");
        assert!(dir.join("track_1.bin").is_file());

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[cfg(feature = "cdr-bundle")]
    #[test]
    fn cdr_bundle_blank_start_reports_and_keeps_leftover_tracks() {
        let dir = temp_dir("cdr_orphan_blank");
        std::fs::write(dir.join("track_1.bin"), b"leftover").unwrap();
        std::fs::write(dir.join("track_02.bin"), b"odd").unwrap();

        // With no TOC there is nothing to reconcile against, so the leftovers
        // may be the only copy of recorded data: warn and keep them.
        let mut plane = bundle_plane(&dir);
        let medium = plane
            .open_cdr_medium(359_849, Some(DiscKind::Cdr), Recovery::Delete)
            .expect("blank start");
        assert_eq!(medium.toc_seq(), 0);
        assert!(
            dir.join("track_1.bin").is_file(),
            "a TOC-less directory is never wiped"
        );
        assert!(dir.join("track_02.bin").is_file());
        assert!(
            !dir.join("toc.0").is_file(),
            "a blank start writes no TOC slot yet"
        );

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[cfg(feature = "cdr-bundle")]
    #[test]
    fn cdr_bundle_cleanup_is_skipped_when_a_slot_is_unreadable() {
        let dir = temp_dir("cdr_orphan_corrupt");
        let mut plane = bundle_plane(&dir);
        let mut medium = plane
            .open_cdr_medium(359_849, Some(DiscKind::Cdr), Recovery::Delete)
            .expect("fresh bundle");
        drive_write_track(&mut plane, &mut medium, 0);
        drive_sync_cache(&mut plane, &mut medium);
        drive_close_session(&mut plane, medium);
        drop(plane);

        // Slot 0 is the clean TOC; slot 1 is unreadable. A track referenced
        // only by a skipped slot must not be deleted on a transient error.
        std::fs::write(dir.join("toc.1"), [0x5Au8; 256]).unwrap();
        std::fs::write(dir.join("track_2.bin"), b"orphan").unwrap();

        let mut plane = bundle_plane(&dir);
        let medium = plane
            .open_cdr_medium(0, Some(DiscKind::Cdr), Recovery::Delete)
            .expect("uses slot 0");
        assert_eq!(medium.track_numbers().collect::<Vec<_>>(), vec![1]);
        assert!(
            dir.join("track_2.bin").is_file(),
            "a skipped slot must disable reconciliation"
        );

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[cfg(feature = "cdr-bundle")]
    #[test]
    fn cdr_bundle_stored_capacity_wins_on_reopen() {
        let dir = temp_dir("cdr_capacity");
        let mut plane = bundle_plane_with(&dir, 332_849); // cdr74

        let medium = plane
            .open_cdr_medium(332_849, Some(DiscKind::Cdr), Recovery::Delete)
            .expect("fresh cdr74");
        drive_close_session(&mut plane, medium);

        // A default cdr80 hint must not reject the stored cdr74 capacity.
        let reopened = plane
            .open_cdr_medium(359_849, Some(DiscKind::Cdr), Recovery::Delete)
            .expect("stored capacity wins");
        assert_eq!(reopened.capacity_sectors(), 332_849);
        assert_eq!(FlatData::capacity(&plane), 332_849 * 2048);

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[cfg(feature = "cdr-bundle")]
    #[test]
    fn cdr_bundle_one_valid_one_corrupt_slot() {
        let dir = temp_dir("cdr_one_valid");
        let mut plane = bundle_plane(&dir);
        let medium = plane
            .open_cdr_medium(359_849, Some(DiscKind::Cdr), Recovery::Delete)
            .unwrap();
        drive_close_session(&mut plane, medium);
        // Slot 0 is valid; make slot 1 look like a corrupt header.
        std::fs::write(dir.join("toc.1"), [0x5Au8; 256]).unwrap();

        let reopened = plane
            .open_cdr_medium(359_849, Some(DiscKind::Cdr), Recovery::Delete)
            .expect("the valid slot is used");
        assert_eq!(reopened.toc_seq(), 1);
        assert_eq!(reopened.current_slot(), 0);

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[cfg(feature = "cdr-bundle")]
    #[test]
    fn cdr_bundle_single_corrupt_slot_is_an_error() {
        let dir = temp_dir("cdr_corrupt");
        std::fs::write(dir.join("toc.0"), [0x5Au8; 256]).unwrap();
        let mut plane = bundle_plane(&dir);

        let err = match plane.open_cdr_medium(359_849, Some(DiscKind::Cdr), Recovery::Delete) {
            Ok(_) => panic!("a corrupt slot must not become blank"),
            Err(e) => e,
        };
        assert!(err.contains("corrupt"), "{err}");
        // Refusing to start did not overwrite the file.
        assert_eq!(std::fs::read(dir.join("toc.0")).unwrap(), vec![0x5Au8; 256]);

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[cfg(feature = "cdr-bundle")]
    #[test]
    fn cdr_bundle_both_slots_missing_start_blank() {
        let dir = temp_dir("cdr_missing");
        let mut plane = bundle_plane(&dir);
        let medium = plane
            .open_cdr_medium(359_849, Some(DiscKind::Cdr), Recovery::Delete)
            .expect("blank start");
        assert_eq!(medium.toc_seq(), 0);
        assert!(!dir.join("toc.0").is_file());

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[cfg(feature = "cdr-bundle")]
    #[test]
    fn cdr_bundle_readonly_recovery_needs_a_toc() {
        let dir = temp_dir("cdr_readonly");
        let mut plane = bundle_plane(&dir);
        assert!(plane
            .open_cdr_medium(359_849, Some(DiscKind::Cdr), Recovery::ReadOnly)
            .is_err());

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[cfg(feature = "cdr-bundle")]
    #[test]
    fn cdr_bundle_corrupt_body_is_an_error() {
        let dir = temp_dir("cdr_bad_body");
        let mut plane = bundle_plane(&dir);
        let medium = plane
            .open_cdr_medium(359_849, Some(DiscKind::Cdr), Recovery::Delete)
            .unwrap();
        drive_close_session(&mut plane, medium);

        // The header still parses; the body checksum no longer matches.
        let path = dir.join("toc.0");
        let mut bytes = std::fs::read(&path).unwrap();
        bytes[260] ^= 0x01;
        std::fs::write(&path, &bytes).unwrap();

        let mut plane = bundle_plane(&dir);
        assert!(plane
            .open_cdr_medium(359_849, Some(DiscKind::Cdr), Recovery::Delete)
            .is_err());
        assert_eq!(
            std::fs::read(&path).unwrap(),
            bytes,
            "a refused body is not overwritten"
        );

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[cfg(feature = "cdr-bundle")]
    #[test]
    fn cdr_bundle_slot_size_only_applies_to_a_new_bundle() {
        let dir = temp_dir("cdr_slot");
        let fs = FsPlaneAdapter::new(StdFsBackend::new(&dir.to_string_lossy()));
        let mut plane =
            OwnedPlane::CdrBundle(CdrStore::new(BundleStore::new(fs, 359_849, Some(8192))));
        let medium = plane
            .open_cdr_medium(359_849, Some(DiscKind::Cdr), Recovery::Delete)
            .unwrap();
        assert_eq!(medium.slot_size(), 8192);
        drive_close_session(&mut plane, medium);

        // A different slot= on the reopen is a hint for a new disc only.
        let fs = FsPlaneAdapter::new(StdFsBackend::new(&dir.to_string_lossy()));
        let mut plane = OwnedPlane::CdrBundle(CdrStore::new(BundleStore::new(
            fs,
            359_849,
            Some(32 * 1024),
        )));
        let reopened = plane
            .open_cdr_medium(359_849, Some(DiscKind::Cdr), Recovery::Delete)
            .expect("stored slot wins");
        assert_eq!(reopened.slot_size(), 8192);

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[cfg(feature = "cdr-bundle")]
    #[test]
    fn cdr_bundle_open_at_rejects_a_copied_slot() {
        use snowscsi::mmc::CdrDiscState;

        let dir = temp_dir("cdr_copied");
        let mut plane = bundle_plane(&dir);
        // Two saves alternate the slots: slot 0 seq 1, slot 1 seq 2.
        let medium = plane
            .open_cdr_medium(359_849, Some(DiscKind::Cdr), Recovery::Delete)
            .unwrap();
        drive_close_session(&mut plane, medium);
        let medium = plane
            .open_cdr_medium(359_849, Some(DiscKind::Cdr), Recovery::Delete)
            .unwrap();
        drive_close_session(&mut plane, medium);
        assert!(dir.join("toc.0").is_file() && dir.join("toc.1").is_file());
        // Copy the older slot over the newer one: its header still claims
        // physical slot 0, so the CLI must not accept it as slot 1.
        std::fs::copy(dir.join("toc.0"), dir.join("toc.1")).unwrap();

        let reopened = plane
            .open_cdr_medium(359_849, Some(DiscKind::Cdr), Recovery::Delete)
            .expect("the physical slot wins");
        assert_eq!(reopened.current_slot(), 0);
        assert_eq!(reopened.disc_state(), CdrDiscState::Blank);

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[cfg(feature = "cdr-bundle")]
    #[test]
    fn cdr_bundle_eject_snapshot_survives_reopen() {
        use snowscsi::core::Direction;
        use snowscsi::mmc::{CdrDiscState, TrackStatus};

        let dir = temp_dir("cdr_snapshot");
        let mut plane = bundle_plane(&dir);
        let mut medium = plane
            .open_cdr_medium(359_849, Some(DiscKind::Cdr), Recovery::Delete)
            .expect("fresh bundle");
        drive_write_track(&mut plane, &mut medium, 0);
        assert!(
            medium.eject_needs_save(),
            "an open track needs an eject snapshot"
        );

        let mut pair = CliPair {
            medium: CliPairMedium::Mmc(CliMedium::CdrBundle(medium)),
            backing: 0,
        };
        let dir_text = dir.to_string_lossy().into_owned();
        assert_eq!(snapshot_cdr_eject(&mut pair, &dir_text), Ok(true));
        assert!(
            !dir.join("toc.0.tmp").exists(),
            "the atomic snapshot must not leave a temp file"
        );
        let slot_image = std::fs::read(dir.join("toc.0")).expect("slot file");
        assert_eq!(slot_image.len(), TOC_SLOT_DEFAULT as usize);
        CdrBundleMedium::open_at(0, &slot_image, 0, Recovery::Delete)
            .expect("the slot file is a complete image");

        let CliPairMedium::Mmc(CliMedium::CdrBundle(medium)) = pair.medium else {
            panic!("snapshot must keep the CD-R medium");
        };
        assert_eq!(medium.current_slot(), 0);
        assert_eq!(medium.toc_seq(), 1);
        assert!(!medium.needs_save());
        assert!(!medium.eject_needs_save());
        drop(plane);

        let mut reopened_plane = bundle_plane(&dir);
        let mut reopened = reopened_plane
            .open_cdr_medium(0, Some(DiscKind::Cdr), Recovery::Delete)
            .expect("reopen the snapshot");
        assert_eq!(reopened.current_slot(), 0);
        assert_eq!(reopened.toc_seq(), 1);
        assert_eq!(reopened.disc_state(), CdrDiscState::Appendable);
        assert_eq!(reopened.capacity_sectors(), 359_849);
        let info = reopened
            .track_info(TrackInfoRequest::Number(1))
            .expect("track 1");
        assert_eq!(info.status, TrackStatus::Complete);
        assert_eq!(
            info.length, 300,
            "the eject close pads like SYNCHRONIZE CACHE"
        );

        let mut data = [0u8; 2048];
        assert_eq!(
            reopened_plane.exec(
                io_req(17, 0, 2048, Direction::ToHost),
                IoBuf::Read(&mut data)
            ),
            Ok(2048)
        );
        assert_eq!(data, [0x5A; 2048], "the written prefix survives the eject");

        // A second snapshot alternates to slot 1; reopening selects the newer
        // slot by sequence number, not by file name.
        let mut image = vec![0u8; reopened.slot_size() as usize];
        let slot = reopened.toc_image(&mut image).expect("second snapshot");
        assert_eq!(slot, 1);
        write_toc_snapshot(&dir_text, slot, &image).expect("write slot 1");
        assert!(
            !dir.join("toc.1.tmp").exists(),
            "the second snapshot must not leave a temp file"
        );
        drop(reopened);
        drop(reopened_plane);

        let mut latest_plane = bundle_plane(&dir);
        let latest = latest_plane
            .open_cdr_medium(0, Some(DiscKind::Cdr), Recovery::Delete)
            .expect("reopen the newer slot");
        assert_eq!(latest.current_slot(), 1);
        assert_eq!(latest.toc_seq(), 2);
        assert_eq!(latest.disc_state(), CdrDiscState::Appendable);

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[cfg(feature = "cdr-bundle")]
    #[test]
    fn cdr_bundle_snapshot_skips_clean_and_non_mmc_pairs() {
        // A saved disc with no open track and no pending transition renders
        // nothing.
        let source = temp_dir("cdr_snapshot_clean_src");
        let mut plane = bundle_plane(&source);
        let medium = plane
            .open_cdr_medium(359_849, Some(DiscKind::Cdr), Recovery::Delete)
            .expect("fresh bundle");
        drive_close_session(&mut plane, medium);
        let clean = plane
            .open_cdr_medium(359_849, Some(DiscKind::Cdr), Recovery::Delete)
            .expect("saved bundle");
        assert!(!clean.eject_needs_save());

        let target = temp_dir("cdr_snapshot_clean_dst");
        let target_text = target.to_string_lossy().into_owned();
        let mut pair = CliPair {
            medium: CliPairMedium::Mmc(CliMedium::CdrBundle(clean)),
            backing: 0,
        };
        assert_eq!(snapshot_cdr_eject(&mut pair, &target_text), Ok(false));
        assert!(
            std::fs::read_dir(&target).unwrap().next().is_none(),
            "a clean disc must not write a TOC slot"
        );

        // A non-MMC pair is not a CD-R bundle either.
        let block_dir = temp_dir("cdr_snapshot_block");
        let block_text = block_dir.to_string_lossy().into_owned();
        let mut block_pair = CliPair {
            medium: CliPairMedium::Block(snowscsi::core::NoMedium),
            backing: 0,
        };
        assert_eq!(snapshot_cdr_eject(&mut block_pair, &block_text), Ok(false));
        assert!(
            std::fs::read_dir(&block_dir).unwrap().next().is_none(),
            "a block pair must not write a TOC slot"
        );

        let _ = std::fs::remove_dir_all(&source);
        let _ = std::fs::remove_dir_all(&target);
        let _ = std::fs::remove_dir_all(&block_dir);
    }

    #[cfg(feature = "cdr-bundle")]
    #[test]
    fn cdr_bundle_resources_released_drops_the_plane() {
        use snowscsi::core::storage::Storage;

        let dir = temp_dir("cdr_eject");
        let mut storage = CliStorage::new(vec![Some(bundle_plane(&dir))]);
        storage.select_lun(0);
        storage.resources_released(0);
        assert!(storage.planes[0].is_none());
        let token = storage.begin_exec(io_req(1, 0, 1, snowscsi::core::Direction::ToHost));
        let mut one = [0u8; 1];
        match storage.poll_exec(token, IoBuf::Read(&mut one)) {
            Poll::Ready(receipt) => assert_eq!(receipt.error, Some(Fault::Contract)),
            Poll::Pending => panic!("a dropped plane must fail immediately"),
        }
        assert!(storage.sync().is_ok());

        let _ = std::fs::remove_dir_all(&dir);
    }

    /// The cipher wrapper must leave capacity and sync bookkeeping to the
    /// wrapped [`BundleStore`] while encrypting only track resources.
    #[cfg(all(feature = "cdr-bundle", feature = "cipher"))]
    #[test]
    fn cdr_store_cipher_wrapper_reports_capacity_and_syncs() {
        use snowscsi::common::bundle::{CipherAlg, CipherMeta, KdfKind};
        use snowscsi::common::cipher::CipherKey;

        let dir = temp_dir("cdr_cipher_wrapper");
        let fs = FsPlaneAdapter::new(StdFsBackend::new(&dir.to_string_lossy()));
        let store = BundleStore::new(fs, 359_849, None);
        let meta = CipherMeta {
            cipher: CipherAlg::Xor,
            kdf: KdfKind::None,
            iterations: None,
            salt: None,
            nonce: [0x5Au8; 8],
        };
        let key = CipherKey::from_bytes(&[0x42u8; 32]).unwrap();
        let cipher = CliCipher::from_meta(&meta, &key).unwrap();
        let mut store = CdrStore::new_cipher(store, cipher, [0x5Au8; 8]);

        assert!(store.is_ciphered());
        assert_eq!(store.capacity_bytes(), 359_849 * 2048);

        // Resource 17 travels through the cipher; the file at rest is not the
        // plaintext and an aggregate sync still succeeds.
        let plain = [0xA5u8; 32];
        let mut input = plain;
        assert_eq!(
            store.exec(
                io_req(17, 0, 32, snowscsi::core::Direction::FromHost),
                IoBuf::Write(&mut input),
            ),
            Ok(32)
        );
        let at_rest = std::fs::read(dir.join("track_1.bin")).expect("track file");
        assert_ne!(&at_rest[..32], &plain);
        assert_eq!(store.sync(), Ok(0));

        let mut out = [0u8; 32];
        assert_eq!(
            store.exec(
                io_req(17, 0, 32, snowscsi::core::Direction::ToHost),
                IoBuf::Read(&mut out),
            ),
            Ok(32)
        );
        assert_eq!(out, plain);

        let _ = std::fs::remove_dir_all(&dir);
    }
}
