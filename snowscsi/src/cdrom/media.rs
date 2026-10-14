//! CD-ROM media types, geometry and media-layer methods.
//!
//! - Type definitions (Track, SessionInfo, DiscState, DiscType, ...).
//! - `CdMedia` gains inherent methods that `CdromDrive` delegates to;
//!   `DvdRam` variant is concrete; `MediaEventStatus` for GESN.
//!
//! Types defined here:
//! - Geometry constants (`MAX_TRACKS`, `SECTOR_SIZE_DATA`, …)
//! - `TrackKind`, `TrackStatus`, `RecordingMode`, `DiscState`, `DiscType`
//! - `TrackFile`, `Track`, `SessionInfo`
//! - `MediaError` (write-path error model, A1)
//! - `MediaEventStatus` (GESN media class response)
//! - `CdMedia` enum with inherent methods for the drive layer

use crate::cdrom::common::{CurrentProfile, MediaState};
#[cfg(feature = "dvdram")]
use crate::cdrom::dvdram::DvdRamMedia;
use crate::common::seekable_storage::FlatData;
use crate::scsi::backend::StorageError;

// ── Geometry constants ─────────────────────────────────

/// Maximum number of tracks on a single disc (MMC limit).
pub const MAX_TRACKS: usize = 99;

/// Maximum number of files that may back a single track (Bundle FAT32 split).
pub const MAX_FILES_PER_TRACK: usize = 16;

/// Maximum number of sessions on a single disc (MMC logical limit).
pub const MAX_SESSIONS: usize = 99;

/// Logical block size for data tracks (Mode 1: 2048 bytes).
pub const SECTOR_SIZE_DATA: u16 = 2048;

/// Logical block size for audio tracks (raw: 2352 bytes).
pub const SECTOR_SIZE_AUDIO: u16 = 2352;

/// Pre-gap sectors before each track's data area (150 = 2 seconds at 75 s/s).
pub const PREGAP_SECTORS: u32 = 150;

/// Default CD capacity for 80 minutes of audio (360 000 sectors).
pub const DEFAULT_CD_CAPACITY: u32 = 360_000;

/// Sector size in bytes (module-level alias for `SECTOR_SIZE_DATA`).
pub const SECTOR_SIZE: u32 = 2048;

// ── Track / Session / Disc enums ──────────────────────

/// Whether a track carries data or audio.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TrackKind {
    Data,
    Audio,
}

/// Track recording status (analogous to MMC-6 Table 367).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TrackStatus {
    /// RESERVE TRACK issued but no data written yet.
    Reserved,
    /// Writing started but CLOSE TRACK not yet issued.
    Incomplete,
    /// Track is closed and readable.
    Complete,
}

/// Recording mode for the disc.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RecordingMode {
    /// CD-R always; CD-RW initial state.
    Sequential,
    /// CD-RW after FORMAT UNIT (restricted overwrite).
    RestrictedOverwrite,
}

/// Overall disc state (MMC-6 Table 367).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DiscState {
    /// No tracks written; disc is empty.
    Blank,
    /// At least one open track; more data may be appended.
    Appendable,
    /// All tracks closed; disc is finalised and read-only.
    Finalized,
}

/// Physical disc type for profile reporting.
///
/// **Not** the same as `DiscInfo.disc_type: u8` (MMC-6 Table 369 byte 8
/// values like 0x00/0x20).  This enum identifies the *media family*;
/// the disc-info byte is a layout concern of the drive layer.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DiscType {
    /// 0x0008 — CD-ROM (read-only pressed/ROM media).
    CdRom,
    /// 0x0009 — CD-R (write-once recordable).
    CdR,
    /// 0x000A — CD-RW (rewritable).
    CdRw,
}

impl DiscType {
    /// Numeric profile code for GET CONFIGURATION (MMC-6 Table 64).
    pub fn profile_code(self) -> u16 {
        match self {
            Self::CdRom => 0x0008,
            Self::CdR => 0x0009,
            Self::CdRw => 0x000A,
        }
    }
}

// ── Track / Session data structures ───────────────────

/// A file backing part of a track's data (Bundle multi-file split,).
#[derive(Debug, Clone)]
pub struct TrackFile {
    /// Ordinal within the track (0-based).
    pub idx: u8,
    /// File size in bytes.
    pub size: u64,
}

/// Track descriptor — one per logical track on the disc.
#[derive(Debug, Clone)]
pub struct Track {
    /// Track number (1-basedMC convention).
    pub num: u8,
    /// Data or audio.
    pub kind: TrackKind,
    /// Sector size in bytes (2048 for data, 2352 for audio).
    pub block_size: u16,
    /// Recording status (Reserved / Incomplete / Complete).
    pub status: TrackStatus,
    /// Session this track belongs to (1-based).
    pub session: u8,
    /// First LBA of the track (including pre-gap).
    pub start_lba: u32,
    /// First LBA of user data (start_lba + pregap).
    pub data_start_lba: u32,
    /// Number of user-data sectors in the track.
    pub length_sectors: u32,
    /// Number of sectors allocated on the medium (>= length_sectors).
    pub allocated_sectors: u32,
    /// Next Writable Address (only meaningful for Incomplete tracks).
    pub nwa: u32,
    /// Free logical blocks available for writing (Complete: 0).
    pub free_lbas: u32,
    /// Files backing this track's data (Bundle multi-file; empty for flat/live).
    pub files: heapless::Vec<TrackFile, MAX_FILES_PER_TRACK>,
}

/// Session descriptor — one per session on the disc.
#[derive(Debug, Clone)]
pub struct SessionInfo {
    /// Session number (1-based).
    pub num: u8,
    /// First track number in this session.
    pub first_track: u8,
    /// First LBA of the session (start of lead-in or pre-gap).
    pub start_lba: u32,
    /// Lead-out start LBA (first sector after the session).
    pub lead_out_lba: u32,
    /// Whether the session is closed (lead-in written).
    pub closed: bool,
}

// ── Write-path error model ────────────────────────────────────

/// Errors from the media write path.
///
/// The drive layer maps these to SCSI sense codes:
/// - `IllegalField` → 24h/00h (INVALID FIELD IN CDB)
/// - `WriteProtected` → 07h/00h (DATA PROTECT) / 27h/00h (WRITE PROTECTED)
/// - `OutOfBounds` → 21h/00h (LOGICAL BLOCK ADDRESS OUT OF RANGE)
/// - `Io(kind)` → sense passthrough (`kind` preserved from the plane's
///   [`StorageError`], never collapsed to `Other`)
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MediaError {
    /// Invalid field in CDB (NWA mismatch, reservation size < 300, etc.).
    IllegalField,
    /// Medium is write-protected or disc is finalized.
    WriteProtected,
    /// Logical block address out of range.
    OutOfBounds,
    /// Underlying storage I/O failure, with the plane's error kind.
    Io(embedded_io::ErrorKind),
}

impl core::fmt::Display for MediaError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::IllegalField => write!(f, "invalid field"),
            Self::WriteProtected => write!(f, "write protected"),
            Self::OutOfBounds => write!(f, "out of bounds"),
            Self::Io(kind) => write!(f, "I/O error: {kind:?}"),
        }
    }
}

impl core::error::Error for MediaError {}

impl From<StorageError> for MediaError {
    fn from(e: StorageError) -> Self {
        match e {
            StorageError::OutOfBounds => Self::OutOfBounds,
            StorageError::NotWritable => Self::WriteProtected,
            StorageError::Io(kind) => Self::Io(kind),
            // Op/plane model mismatch → INVALID FIELD IN CDB (24h/00h), the
            // same sense `sense_for_storage_error` assigns to `Unsupported`.
            StorageError::Unsupported => Self::IllegalField,
        }
    }
}

// ── GESN media event status (GET EVENT STATUS NOTIFICATION) ────

/// Media event status for GET EVENT STATUS NOTIFICATION (MMC-6 Table 265).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MediaEventStatus {
    /// No change since last poll.
    NoChange,
    /// Media was removed.
    MediaRemoved,
    /// New media was inserted.
    MediaInserted,
}

// ── CdMedia enum ──────────────────────────────────────

/// The media slot inside a [`CdromDrive`](super::drive::CdromDrive).
///
/// `None` means the tray is empty.  Each variant wraps a concrete media
/// type that provides **cached geometry**; data-phase I/O is handed to the
/// shell as a [`StoreOp`](crate::common::store::StoreOp).
///
/// - `Ro(…)` — read-only disc over any [`FlatData`] source.
/// - `Rw(…)` (feature `dvdram`) — random-writable DVD-RAM over any writable
///   plane.
#[derive(Debug)]
pub enum CdMedia {
    /// Read-only disc: flat ISO/RAM image or live-generated ISO9660 —
    /// anything that speaks [`FlatData`]. Geometry derives from the
    /// plane capacity at construction time.
    Ro(FlatMedia),

    /// Random-writable DVD-RAM/RW: a UDF 2.01 volume over an erased
    /// writable plane (`dvdram` feature).
    #[cfg(feature = "dvdram")]
    Rw(DvdRamMedia),
}

/// Physical tray state: at most one disc, either loaded or parked by a
/// SCSI-initiated eject (`START STOP loej=1`). A parked disc is logically
/// NOT PRESENT but its slot is held until
/// [`CdromDrive::take_media`](crate::cdrom::drive::CdromDrive::take_media)
/// returns it to the application.
#[derive(Debug)]
pub enum Tray {
    /// No disc.
    Empty,
    /// Disc loaded and addressable.
    Loaded(CdMedia),
    /// Disc ejected by the host; awaiting reclaim via `take_media()`.
    Parked(CdMedia),
}

impl Tray {
    /// Take the disc out of any occupied state.
    pub(crate) fn disc(self) -> Option<CdMedia> {
        match self {
            Tray::Empty => None,
            Tray::Loaded(m) | Tray::Parked(m) => Some(m),
        }
    }
}

impl CdMedia {
    /// Build a read-only disc over any [`FlatData`] source (ISO image,
    /// RAM bytes, live-generated ISO9660, user planes). The plane is
    /// borrowed once to read its capacity and immediately released.
    pub fn ro(plane: &mut dyn FlatData) -> Self {
        Self::Ro(FlatMedia::new(plane))
    }
}

impl CdMedia {
    /// Whether the loaded medium accepts SBC random writes (`Rw` = true).
    pub fn is_writable(&self) -> bool {
        match self {
            Self::Ro(_) => false,
            #[cfg(feature = "dvdram")]
            Self::Rw(_) => true,
        }
    }

    /// Describe the currently inserted medium without exposing drive
    /// capabilities.
    pub fn state(&self) -> MediaState {
        let profile = self.profile();
        let max_lba = self.max_lba().min(u32::MAX as u64) as u32;
        match self {
            #[cfg(feature = "dvdram")]
            Self::Rw(_) => MediaState {
                profile,
                present: true,
                ready: true,
                formatted: true,
                formattable: true,
                erasable: true,
                write_protected: false,
                random_writable: true,
                defect_management: true,
                max_lba,
                block_size: SECTOR_SIZE,
            },
            Self::Ro(_) => MediaState {
                profile,
                present: true,
                ready: true,
                formatted: true,
                formattable: false,
                erasable: false,
                write_protected: true,
                random_writable: false,
                defect_management: false,
                max_lba,
                block_size: SECTOR_SIZE,
            },
        }
    }

    // ── Profile ────────────────────────────────────────

    /// Current Profile for GET CONFIGURATION.
    pub fn profile(&self) -> CurrentProfile {
        match self {
            Self::Ro(m) => m.profile(),
            #[cfg(feature = "dvdram")]
            Self::Rw(_) => CurrentProfile::DvdRam,
        }
    }

    // ── Geometry ───────────────────────────────────────

    /// Largest readable LBA.
    pub fn max_lba(&self) -> u64 {
        match self {
            Self::Ro(m) => m.max_lba(),
            #[cfg(feature = "dvdram")]
            Self::Rw(m) => m.max_lba(),
        }
    }

    /// Lead-out start LBA = number of data sectors.
    pub fn lead_out_lba(&self) -> u32 {
        match self {
            Self::Ro(m) => m.lead_out_lba(),
            #[cfg(feature = "dvdram")]
            Self::Rw(m) => m.lead_out_lba(),
        }
    }

    /// Media capacity in bytes (cached at construction).
    pub fn capacity(&self) -> u64 {
        match self {
            Self::Ro(m) => m.capacity(),
            #[cfg(feature = "dvdram")]
            Self::Rw(m) => m.capacity(),
        }
    }

    // ── GESN ──────────────────────────────────────────────

    /// Media event status for GET EVENT STATUS NOTIFICATION.
    pub fn event_status(&self) -> MediaEventStatus {
        let _ = self;
        MediaEventStatus::NoChange
    }

    // ── READ DVD STRUCTURE ────────────────────────────

    /// Physical format information for READ DVD STRUCTURE format 0.
    pub fn dvd_physical_format(&self) -> Option<DvdPhysicalFormat> {
        match self {
            #[cfg(feature = "dvdram")]
            Self::Rw(m) => Some(DvdPhysicalFormat {
                disk_category_part_version: 0x10, // DVD-RAM, version 0
                layer_type: 0x04,                 // single-layer, rewritable
                data_start: 0x0003_0000,
                data_end: 0x0003_0000 + m.lead_out_lba(),
                next_writable: 0x0003_0000 + m.lead_out_lba(),
            }),
            Self::Ro(_) => None,
        }
    }

    /// Whether this media type supports the given READ DVD STRUCTURE format.
    pub fn supports_dvd_structure_format(&self, format: u8) -> bool {
        #[cfg(feature = "dvdram")]
        {
            matches!(self, Self::Rw(_))
                && matches!(format, 0 | 0x08 | 0x09 | 0x0A | 0x0B | 0x30 | 0xC0)
        }
        #[cfg(not(feature = "dvdram"))]
        {
            let _ = format;
            false
        }
    }
}

// ── FlatMedia ───────────────────────────────────────────────

// `FlatData`/`WritableFlatData` live in `snowscsi-common::seekable_storage`
// (the capability ladder); block backends are lifted by blanket impl and
// generated sources implement `FlatData` directly.

/// Physical format information for READ DVD STRUCTURE format 0
/// (MMC-6, Table 398).
#[derive(Debug, Clone, Copy)]
pub struct DvdPhysicalFormat {
    pub disk_category_part_version: u8,
    pub layer_type: u8,
    pub data_start: u32,
    pub data_end: u32,
    pub next_writable: u32,
}

/// Flat (read-only) media: single track, single session, finalized.
///
/// **Non-generic and backend-free**: the plane is borrowed once at
/// construction to read its capacity, then released. Only the derived
/// geometry (`capacity_sectors`/`tracks`/`sessions`) is retained; the drive
/// addresses the LUN's store plane for data-phase I/O.
#[derive(Debug)]
pub struct FlatMedia {
    capacity_sectors: u32,
    tracks: [Track; 1],
    sessions: [SessionInfo; 1],
}

impl FlatMedia {
    /// Create a flat media over `plane`; geometry derives from its capacity.
    /// The plane is borrowed only for the capacity read and released.
    pub fn new(plane: &mut dyn FlatData) -> Self {
        Self::from_capacity(plane.capacity())
    }

    /// Build the fixed single-track / single-session geometry from a byte
    /// capacity.
    fn from_capacity(cap: u64) -> Self {
        let capacity_sectors = (cap / u64::from(SECTOR_SIZE)).min(u32::MAX as u64) as u32;
        let tracks = [Track {
            num: 1,
            kind: TrackKind::Data,
            block_size: SECTOR_SIZE_DATA,
            status: TrackStatus::Complete,
            session: 1,
            start_lba: 0,
            data_start_lba: 0,
            length_sectors: capacity_sectors,
            allocated_sectors: capacity_sectors,
            nwa: 0,
            free_lbas: 0,
            files: heapless::Vec::new(),
        }];
        let sessions = [SessionInfo {
            num: 1,
            first_track: 1,
            start_lba: 0,
            lead_out_lba: capacity_sectors,
            closed: true,
        }];
        Self {
            capacity_sectors,
            tracks,
            sessions,
        }
    }

    pub fn profile(&self) -> CurrentProfile {
        CurrentProfile::from_capacity(self.capacity())
    }

    /// Capacity in bytes (sector-aligned, from the cached geometry).
    pub fn capacity(&self) -> u64 {
        u64::from(self.capacity_sectors) * u64::from(SECTOR_SIZE)
    }

    pub fn max_lba(&self) -> u64 {
        self.capacity_sectors.saturating_sub(1) as u64
    }

    pub fn lead_out_lba(&self) -> u32 {
        self.capacity_sectors
    }

    pub fn tracks(&self) -> &[Track] {
        &self.tracks
    }

    pub fn sessions(&self) -> &[SessionInfo] {
        &self.sessions
    }
}

// ── LiveData re-export from snowscsi-iso9660 ───────────────────

pub use snowscsi_iso9660::{CdLiveFsError, LiveData, LiveDataBuilder};

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sector_size_constants() {
        assert_eq!(SECTOR_SIZE_DATA, 2048);
        assert_eq!(SECTOR_SIZE_AUDIO, 2352);
        assert_eq!(SECTOR_SIZE, 2048);
    }

    #[test]
    fn disc_type_profile_codes() {
        assert_eq!(DiscType::CdRom.profile_code(), 0x0008);
        assert_eq!(DiscType::CdR.profile_code(), 0x0009);
        assert_eq!(DiscType::CdRw.profile_code(), 0x000A);
    }

    #[test]
    fn track_defaults_construct() {
        let t = Track {
            num: 1,
            kind: TrackKind::Data,
            block_size: SECTOR_SIZE_DATA,
            status: TrackStatus::Complete,
            session: 1,
            start_lba: 0,
            data_start_lba: PREGAP_SECTORS,
            length_sectors: 1000,
            allocated_sectors: 1000,
            nwa: 0,
            free_lbas: 0,
            files: heapless::Vec::new(),
        };
        assert_eq!(t.num, 1);
        assert_eq!(t.data_start_lba, PREGAP_SECTORS);
    }

    #[test]
    fn session_info_construct() {
        let s = SessionInfo {
            num: 1,
            first_track: 1,
            start_lba: 0,
            lead_out_lba: 360_000,
            closed: true,
        };
        assert_eq!(s.num, 1);
        assert!(s.closed);
    }

    #[test]
    fn media_error_variants() {
        let e = MediaError::WriteProtected;
        assert_eq!(e, MediaError::WriteProtected);
        assert_ne!(e, MediaError::OutOfBounds);
    }

    #[test]
    fn default_cd_capacity() {
        assert_eq!(DEFAULT_CD_CAPACITY, 360_000);
    }

    #[test]
    fn pregap_sectors() {
        assert_eq!(PREGAP_SECTORS, 150);
    }
}
