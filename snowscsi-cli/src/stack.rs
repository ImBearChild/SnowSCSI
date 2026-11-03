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
#[cfg(feature = "bundle")]
use snowscsi::common::flat_bundle::FlatBundle;
#[cfg(feature = "cdr-bundle")]
use snowscsi::common::fs_plane::{FsPlane, FsPlaneAdapter};
#[cfg(feature = "cdr-bundle")]
use snowscsi::common::fs_storage::FsError;
use snowscsi::common::seekable_storage::{FlatData, StorageError, WritableFlatData};
use snowscsi::common::store::{StoreOp, StorePlane};
use snowscsi::core::storage::{IoBuf, IoReq, IoToken, Storage, StorageReceipt};
use snowscsi::core::{
    Admission, BoundaryPermit, Change, ChangeResult, CommandContext, CommandPermit, Completion,
    Delivery, Effect, Fault, Feedback, InterruptReason, KnownEffects, LongInfo, Lu, LuImpl, LuInfo,
    OwnerBindPermit, Pair, PollStep, Sense, Spc, TargetId, UaClass,
};
#[cfg(feature = "cdr-bundle")]
use snowscsi::mmc::cdr_bundle::{
    max_tracks_for_slot, toc_file, track_file, CdrBundleMedium, Recovery, TocHeader,
    TOC_HEADER_LEN, TOC_SLOT_DEFAULT,
};
#[cfg(feature = "dvdram")]
use snowscsi::mmc::DvdRamMedium;
use snowscsi::mmc::{
    DiscInfo, FlatCdMedium, MmcAttrs, MmcDrive, MmcMedium, MmcOp, Session, Track, TrackInfo,
    TrackInfoRequest,
};
use snowscsi::scsi::backend::FileBackend;
use snowscsi::scsi::fs_backend::StdFsBackend;

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
    /// track files (see [`BundleStore`]).
    #[cfg(feature = "cdr-bundle")]
    CdrBundle(BundleStore),
    /// Live ISO9660 directory scan (read-only).
    Live(LiveData<StdFsBackend>),
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

#[cfg(feature = "cdr-bundle")]
impl BundleStore {
    /// Wrap a directory and the requested medium geometry.
    pub fn new(fs: FsPlaneAdapter<StdFsBackend>, capacity_sectors: u64, slot: Option<u32>) -> Self {
        Self {
            fs,
            capacity_sectors,
            slot,
            max_tracks: max_tracks_for_slot(slot.unwrap_or(TOC_SLOT_DEFAULT)),
        }
    }

    /// Nominal capacity in bytes.
    fn capacity_bytes(&self) -> u64 {
        self.capacity_sectors.saturating_mul(2048)
    }

    /// Aggregate flush (`Sync { resource: 0 }`).
    ///
    /// The `FsStorage` seam has no fsync, so this settles the page cache only.
    fn sync(&mut self) -> Result<usize, StorageError> {
        self.fs.sync().map_err(StorageError::from)?;
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
            // `Sync` on a TOC slot or track flushes the whole plane: the
            // medium has no per-file durability and the `FsPlane` seam only
            // exposes a plane-level sync.
            (snowscsi::core::Direction::None, IoBuf::None) => self.sync(),
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
                }
                self.fs.write(path, req.offset, b)?;
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

    /// Restore (or create) the medium from the two alternating TOC slots.
    ///
    /// The caller reads only the 256-byte headers first, because the body
    /// length lives in the header; the newer valid slot is then read in full
    /// and parsed with its physical index (`open_at`). A stored TOC owns the
    /// disc capacity: `capacity_sectors` is only a hint for a new blank bundle.
    /// A missing slot is not an error, but an unreadable or malformed slot is
    /// unless the other slot is usable.
    pub fn open_medium(
        &mut self,
        capacity_sectors: u64,
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
                    self.max_tracks = max_tracks_for_slot(medium.slot_size());
                    // The stored disc owns the geometry from here on.
                    self.capacity_sectors = stored;
                    return Ok(medium);
                }
                Err(e) => open_error = Some(format!("toc.{slot}: {e}")),
            }
        }
        if let Some(e) = open_error {
            return Err(format!("no usable CD-R TOC ({e})"));
        }
        if !corrupt.is_empty() {
            return Err(format!(
                "no usable CD-R TOC ({}); refusing to start blank over a corrupt slot",
                corrupt.join(", ")
            ));
        }
        if recovery == Recovery::ReadOnly {
            return Err(
                "read-only recovery requires an existing CD-R TOC; refusing to create a blank disc"
                    .to_string(),
            );
        }
        let slot = self.slot.unwrap_or(TOC_SLOT_DEFAULT);
        log::warn!("bundle: no TOC slot found; starting a new blank CD-R (slot {slot})");
        let medium = CdrBundleMedium::with_capacity_and_slot(capacity_sectors, slot)
            .map_err(|e| format!("invalid CD-R TOC slot size {slot}: {e}"))?;
        self.max_tracks = max_tracks_for_slot(medium.slot_size());
        Ok(medium)
    }
}

impl OwnedPlane {
    /// Restore (or create) the CD-R medium behind this plane.
    #[cfg(feature = "cdr-bundle")]
    pub fn open_cdr_medium(
        &mut self,
        capacity_sectors: u64,
        recovery: Recovery,
    ) -> Result<CdrBundleMedium, String> {
        match self {
            Self::CdrBundle(store) => store.open_medium(capacity_sectors, recovery),
            _ => Err("not a CD-R bundle plane".to_string()),
        }
    }

    /// Whether this plane should be addressed as a writable plane.
    fn is_writable(&self) -> bool {
        match self {
            Self::BlockRw(_) => true,
            Self::Ram { writable, .. } => *writable,
            #[cfg(feature = "bundle")]
            Self::Bundle(bundle) => !bundle.is_read_only(),
            #[cfg(feature = "cdr-bundle")]
            Self::CdrBundle(_) => true,
            Self::BlockRo(_) | Self::Live(_) => false,
        }
    }

    /// Whether this plane is the persistent CD-R directory store.
    #[cfg(feature = "cdr-bundle")]
    pub(crate) fn is_cdr_bundle(&self) -> bool {
        matches!(self, Self::CdrBundle(_))
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
// The CD-R medium's fixed track/session tables are large, but the CLI builds
// one pair per LUN (same rationale as `OwnedPlane`).
#[allow(clippy::large_enum_variant)]
pub enum CliPairMedium {
    /// Block slot (`NoMedium`).
    Block(snowscsi::core::NoMedium),
    /// MMC slot.
    Mmc(CliMedium),
}

/// The one pair type of the CLI target.
pub type CliPair = Pair<CliPairMedium, CliBacking>;

/// MMC medium enum: a flat read-only CD or a blank DVD-RAM.
// The CD-R medium's fixed track/session tables are large, but the CLI builds
// one per LUN (same rationale as `OwnedPlane`).
#[allow(clippy::large_enum_variant)]
pub enum CliMedium {
    /// Read-only CD data medium.
    Flat(FlatCdMedium),
    /// Rewritable DVD-RAM medium.
    #[cfg(feature = "dvdram")]
    DvdRam(DvdRamMedium),
    /// Sequential write-once CD-R with a persistent TOC.
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
        // plane so the cached handles close. Anything the host did not flush
        // with CLOSE/SYNCHRONIZE CACHE is lost.
        let is_bundle = self
            .planes
            .get(lun)
            .and_then(Option::as_ref)
            .is_some_and(OwnedPlane::is_cdr_bundle);
        if is_bundle {
            log::warn!(
                "LUN {lun}: CD-R bundle ejected; unsaved writes are lost \
                 (the host must CLOSE/SYNCHRONIZE CACHE before eject)"
            );
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
        bundle_plane_with(dir, 360_000)
    }

    #[cfg(feature = "cdr-bundle")]
    fn bundle_plane_with(dir: &std::path::Path, capacity_sectors: u64) -> OwnedPlane {
        let fs = FsPlaneAdapter::new(StdFsBackend::new(&dir.to_string_lossy()));
        OwnedPlane::CdrBundle(BundleStore::new(fs, capacity_sectors, None))
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

    #[cfg(feature = "cdr-bundle")]
    #[test]
    fn cdr_bundle_exec_routes_resources() {
        use snowscsi::core::Direction;

        let dir = temp_dir("cdr_exec");
        let mut plane = bundle_plane(&dir);

        // TOC slot 0 (resource 1).
        assert_eq!(
            plane.exec(io_req(1, 0, 5, Direction::FromHost), IoBuf::Write(b"hello")),
            Ok(5)
        );
        let mut toc0 = [0u8; 5];
        assert_eq!(
            plane.exec(io_req(1, 0, 5, Direction::ToHost), IoBuf::Read(&mut toc0)),
            Ok(5)
        );
        assert_eq!(&toc0, b"hello");

        // TOC slot 1 (resource 2) is an independent file.
        assert_eq!(
            plane.exec(io_req(2, 4, 5, Direction::FromHost), IoBuf::Write(b"world")),
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
        assert_eq!(
            plane.exec(io_req(17, 0, 4, Direction::FromHost), IoBuf::Write(b"data")),
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
        assert_eq!(
            plane.exec(
                io_req(17, 0, 8, Direction::FromHost),
                IoBuf::Write(b"01234567")
            ),
            Ok(8)
        );
        assert_eq!(
            plane.exec(io_req(17, 0, 4, Direction::FromHost), IoBuf::Write(b"ABCD")),
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
        assert_eq!(
            plane.exec(io_req(0, 0, 1, Direction::FromHost), IoBuf::Write(&[0])),
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
        assert_eq!(FlatData::capacity(&plane), 360_000 * 2048);
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
            .open_cdr_medium(360_000, Recovery::Delete)
            .expect("fresh bundle");
        assert_eq!(medium.toc_seq(), 0);

        // CLOSE SESSION on a blank disc is a success no-op once its (empty)
        // TOC slot has been saved.
        drive_close_session(&mut plane, medium);

        let reopened = plane
            .open_cdr_medium(360_000, Recovery::Delete)
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
    fn cdr_bundle_stored_capacity_wins_on_reopen() {
        let dir = temp_dir("cdr_capacity");
        let mut plane = bundle_plane_with(&dir, 333_000); // cdr74

        let medium = plane
            .open_cdr_medium(333_000, Recovery::Delete)
            .expect("fresh cdr74");
        drive_close_session(&mut plane, medium);

        // A default cdr80 hint must not reject the stored cdr74 capacity.
        let reopened = plane
            .open_cdr_medium(360_000, Recovery::Delete)
            .expect("stored capacity wins");
        assert_eq!(reopened.capacity_sectors(), 333_000);
        assert_eq!(FlatData::capacity(&plane), 333_000 * 2048);

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[cfg(feature = "cdr-bundle")]
    #[test]
    fn cdr_bundle_one_valid_one_corrupt_slot() {
        let dir = temp_dir("cdr_one_valid");
        let mut plane = bundle_plane(&dir);
        let medium = plane.open_cdr_medium(360_000, Recovery::Delete).unwrap();
        drive_close_session(&mut plane, medium);
        // Slot 0 is valid; make slot 1 look like a corrupt header.
        std::fs::write(dir.join("toc.1"), [0x5Au8; 256]).unwrap();

        let reopened = plane
            .open_cdr_medium(360_000, Recovery::Delete)
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

        let err = match plane.open_cdr_medium(360_000, Recovery::Delete) {
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
            .open_cdr_medium(360_000, Recovery::Delete)
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
        assert!(plane.open_cdr_medium(360_000, Recovery::ReadOnly).is_err());

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[cfg(feature = "cdr-bundle")]
    #[test]
    fn cdr_bundle_corrupt_body_is_an_error() {
        let dir = temp_dir("cdr_bad_body");
        let mut plane = bundle_plane(&dir);
        let medium = plane.open_cdr_medium(360_000, Recovery::Delete).unwrap();
        drive_close_session(&mut plane, medium);

        // The header still parses; the body checksum no longer matches.
        let path = dir.join("toc.0");
        let mut bytes = std::fs::read(&path).unwrap();
        bytes[260] ^= 0x01;
        std::fs::write(&path, &bytes).unwrap();

        let mut plane = bundle_plane(&dir);
        assert!(plane.open_cdr_medium(360_000, Recovery::Delete).is_err());
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
        let mut plane = OwnedPlane::CdrBundle(BundleStore::new(fs, 360_000, Some(8192)));
        let medium = plane.open_cdr_medium(360_000, Recovery::Delete).unwrap();
        assert_eq!(medium.slot_size(), 8192);
        drive_close_session(&mut plane, medium);

        // A different slot= on the reopen is a hint for a new disc only.
        let fs = FsPlaneAdapter::new(StdFsBackend::new(&dir.to_string_lossy()));
        let mut plane = OwnedPlane::CdrBundle(BundleStore::new(fs, 360_000, Some(32 * 1024)));
        let reopened = plane
            .open_cdr_medium(360_000, Recovery::Delete)
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
        let medium = plane.open_cdr_medium(360_000, Recovery::Delete).unwrap();
        drive_close_session(&mut plane, medium);
        let medium = plane.open_cdr_medium(360_000, Recovery::Delete).unwrap();
        drive_close_session(&mut plane, medium);
        assert!(dir.join("toc.0").is_file() && dir.join("toc.1").is_file());
        // Copy the older slot over the newer one: its header still claims
        // physical slot 0, so the CLI must not accept it as slot 1.
        std::fs::copy(dir.join("toc.0"), dir.join("toc.1")).unwrap();

        let reopened = plane
            .open_cdr_medium(360_000, Recovery::Delete)
            .expect("the physical slot wins");
        assert_eq!(reopened.current_slot(), 0);
        assert_eq!(reopened.disc_state(), CdrDiscState::Blank);

        let _ = std::fs::remove_dir_all(&dir);
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
}
