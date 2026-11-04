//! Sequential recordable CD medium (CD-R and CD-RW).
//!
//! The medium models a CD-R or CD-RW whose payload lives in the application's
//! storage. Both kinds use the same Track-at-Once recording path and the same
//! alternating TOC slots; only erasability differs (Orange Book: write-once
//! dye versus a phase-change layer that BLANK can return to the blank state).
//! The storage resource contract is:
//!
//! - `0` is the aggregate flush (`Sync { resource: 0 }` must flush every
//!   track resource);
//! - `1`/`2` are the two TOC slots (`toc.0`/`toc.1`);
//! - `16 + n` is track `n` (`track_<n>.bin`);
//! - any other resource id is a contract fault, never a valid request.
//!
//! A track resource is created/truncated by its first write at offset `0`;
//! short reads zero-fill. A TOC save creates the target slot lazily with the
//! body/padding write at offset 256, rewrites the 256-byte header at offset 0
//! last, and then fsyncs the slot: a plain write at offset 0 must not truncate
//! an existing resource. The track/session layout (the TOC) is
//! persisted in two alternating slots so an interrupted save leaves the
//! previous document intact. The header binds the body by length and CRC-32,
//! so the last valid slot is only replaced after the whole new slot has been
//! written. The slot format and its strict parser live in [`toc`].
//!
//! Writing follows the TAO shape a recorder uses: the first `WRITE(10)` may
//! land on the next writable address without a preceding `RESERVE TRACK`, and
//! `SYNCHRONIZE CACHE` pads and closes the open track. A closed track starts
//! the next one after a 150-block pre-gap; pre-gaps and unwritten regions read
//! as zeros without touching storage.
//!
//! Logical block accounting (capacity, LBA, NWA, track length and the TOC) is
//! always in 2048-byte blocks, but a track resource stores its payload at the
//! track kind's density: 2048 bytes per logical block for a data track and
//! 2352 bytes per logical block for a CD-DA audio track. Track resource
//! offsets are relative to the track's first user block, so a read or write
//! must use the owning track's density; READ CD CD-DA and READ(10) therefore
//! cannot share a span that crosses a differently sized track.
//!
//! Durability: a FUA write syncs its data before GOOD. `CLOSE TRACK SESSION`
//! and `SYNCHRONIZE CACHE` both sync the aggregate data (`Sync { resource: 0 }`)
//! before writing and syncing the TOC slot.
//!
//! [`CdrBundleMedium`] never allocates: the track and session tables are
//! fixed-capacity `heapless::Vec`s, and the save state machine regenerates the
//! TOC in the caller's bank instead of holding a slot-sized buffer.

use heapless::Vec;

pub mod toc;

pub use self::toc::{
    max_tracks_for_slot, toc_file, toc_resource, track_file, track_resource, Recovery, TocError,
    TocHeader, TOC_HEADER_LEN, TOC_RESOURCE_0, TOC_RESOURCE_1, TOC_SLOT_DEFAULT, TOC_SLOT_MAX,
    TOC_SLOT_MIN, TRACK_RESOURCE_BASE,
};

use super::attrs::{
    AtipInfo, DiscInfo, DiscStatus, MmcAttrs, MmcWriteMode, SectorKind, Session, Track, TrackInfo,
    TrackInfoRequest, TrackKind, TrackStatus,
};
use super::medium::MmcMedium;
use super::op::MmcOp;
use crate::core::storage::StorageOp;
use crate::core::{
    storage_fault_sense, Completion, DataPlan, Direction, Effect, Fault, Feedback, FeedbackKind,
    InterruptReason, IoContext, KnownEffects, PollStep, Sense, COMMAND_ABORTED, INTERNAL_FAILURE,
    INVALID_FIELD, LBA_OUT_OF_RANGE, MEDIUM_ERROR, WRITE_PROTECTED,
};

/// CD data block length.
const BLOCK_LEN: u32 = 2048;
/// CD-DA audio sector length stored per logical block of an audio track.
const AUDIO_SECTOR_LEN: u32 = 2352;
/// Pre-gap before every track after the first.
const PREGAP_BLOCKS: u64 = 150;
/// Length of the 1-minute lead-in area at the start of every appended session.
///
/// The next session's lead-in starts at the previous session's lead-out; its
/// first track preamble starts this many blocks later, and user data starts
/// one [`PREGAP_BLOCKS`] pre-gap after that.
pub(crate) const SESSION_LEADIN_BLOCKS: u64 = 4500;
/// Minimum recorded length of a closed track.
const MIN_TRACK_BLOCKS: u64 = 300;
/// Start address of the disc lead-in.
const MEDIUM_LEADIN: i64 = -11077;
/// Fixed track-table capacity.
const MAX_TRACKS: usize = 99;
/// Fixed session-table capacity.
const MAX_SESSIONS: usize = 16;
/// Features that are Current for a recordable CD (CD-R and CD-RW alike): the
/// Track-at-Once set.
const CDR_FEATURES: &[u16] = &[0x0010, 0x001D, 0x001E, 0x0021, 0x002D];

/// ILLEGAL REQUEST / INVALID ADDRESS FOR WRITE.
const INVALID_ADDRESS_FOR_WRITE: Sense = Sense::new(0x05, 0x21, 0x02);
/// ILLEGAL REQUEST / ILLEGAL MODE FOR THIS TRACK.
const ILLEGAL_MODE_FOR_THIS_TRACK: Sense = Sense::new(0x05, 0x64, 0x00);
/// ILLEGAL REQUEST / SESSION FIXATION ERROR - INCOMPLETE TRACK IN SESSION.
const SESSION_FIXATION_INCOMPLETE_TRACK: Sense = Sense::new(0x05, 0x72, 0x03);
/// ILLEGAL REQUEST / EMPTY OR PARTIALLY WRITTEN RESERVED TRACK.
const EMPTY_OR_PARTIALLY_WRITTEN_RESERVED_TRACK: Sense = Sense::new(0x05, 0x72, 0x04);

/// Storage bytes per logical block for a track kind.
const fn sector_len(kind: TrackKind) -> u32 {
    match kind {
        TrackKind::Data => BLOCK_LEN,
        TrackKind::Audio => AUDIO_SECTOR_LEN,
    }
}

/// Standard recordable CD capacities, expressed as the disc's lead-out start LBA.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CdrCapacity {
    /// 74-minute disc.
    Cdr74,
    /// 80-minute disc.
    Cdr80,
    /// 90-minute high-capacity disc.
    Cdr90,
    /// 99-minute high-capacity disc.
    Cdr99,
}

impl CdrCapacity {
    /// Number of writable logical blocks, i.e. the lead-out start LBA.
    ///
    /// Real media end at the `M:59:74` frame of the last full minute
    /// (`minutes * 60 * 75 - 151`), so the lead-out of an 80-minute disc is
    /// LBA 359 849 rather than a flat 360 000. The value is both the addressable
    /// block count and the lead-out ATIP reports; READ CAPACITY reports the
    /// last writable block, one below it, while the disc is blank.
    ///
    /// The 90- and 99-minute presets are high-capacity media: their lead-out is
    /// above MMC's recommended maximum of `79:59:74`, and real media describe
    /// the extra room through the `A1` capacity extension, which this model
    /// does not encode.
    #[must_use]
    pub const fn sectors(self) -> u64 {
        let minutes: u64 = match self {
            Self::Cdr74 => 74,
            Self::Cdr80 => 80,
            Self::Cdr90 => 90,
            Self::Cdr99 => 99,
        };
        minutes * 60 * 75 - 151
    }
}

/// Recordable CD media kind.
///
/// Both kinds share the Track-at-Once path and the persistent TOC layout. The
/// Orange Book difference is erasability: a CD-R records a write-once dye, so
/// written blocks can never be erased, while a CD-RW records a phase-change
/// layer that BLANK returns to the blank state.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DiscKind {
    /// Write-once CD-R (profile `0x09`).
    Cdr,
    /// Erasable CD-RW (profile `0x0A`).
    Cdrw,
}

/// Disc-level state of a sequential medium.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CdrDiscState {
    /// No track has been started.
    Blank,
    /// At least one track exists and the disc is not finalized.
    Appendable,
    /// The session is closed and no further writes are accepted.
    Finalized,
}

/// Public phase of the medium's in-flight operation.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CdrBundleState {
    /// No operation.
    Idle,
    /// Admitted; the data plan has not been published yet.
    Publish,
    /// READ: the backing read is being issued.
    ReadIo,
    /// READ: a segment is being delivered to the host.
    Deliver,
    /// WRITE: waiting for the host data.
    WriteRecv,
    /// WRITE: the backing write is being issued.
    WriteIo,
    /// COMMIT: the sync is being issued.
    SyncIo,
    /// COMMIT: waiting for the sync receipt.
    SyncWait,
    /// TOC: the next slot write or sync is being issued.
    SaveIo,
    /// TOC: waiting for a slot write or sync receipt.
    SaveWait,
    /// Completion fixed; the operation is over.
    Done,
}

/// One recorded, reserved or open track.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct TrackEntry {
    number: u16,
    session: u16,
    /// First block of the track, including the pre-gap.
    start_lba: u64,
    /// First user block of the track.
    data_start_lba: u64,
    /// Blocks reserved for the track (`0` means unallocated).
    allocated: u64,
    /// Recorded (or padded) length in blocks; serialized as the TOC `written`
    /// field (the recorded extent).
    length: u64,
    /// Blocks actually recorded; a close may pad `length` beyond this;
    /// serialized as the TOC `length` field (the user-written prefix).
    written: u64,
    /// Next writable address.
    nwa: u64,
    /// Recording state.
    status: TrackStatus,
    /// Data or audio.
    kind: TrackKind,
    /// The track came from an explicit `RESERVE TRACK`.
    reserved: bool,
}

/// One session slot.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct SessionEntry {
    number: u16,
    first_track: u16,
    last_track: u16,
    start_lba: u64,
    /// First block after the session's recorded data.
    lead_out_lba: u64,
    /// The session has been closed.
    closed: bool,
}

/// Backing action selected by [`MmcMedium::begin`].
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Op {
    /// Read `bytes` starting at `lba`; `kind` fixes the per-block size.
    Read {
        lba: u64,
        bytes: u32,
        kind: TrackKind,
    },
    /// Write `bytes` at `offset` into the track's resource; `sector_len` is the
    /// track's storage bytes per logical block.
    Write {
        track: u16,
        offset: u64,
        bytes: u32,
        sector_len: u32,
    },
    /// Consume `bytes` of host data without recording it (Test Write).
    TestWrite { bytes: u32 },
    /// Flush the backing (uncommitted data only).
    Sync,
    /// Persist the TOC: optional data sync, slot write, slot sync.
    SaveToc,
}

/// One read segment starting at a byte offset inside the admitted read.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Segment {
    /// Recorded bytes: a backing read of `len` bytes at `resource`/`offset`.
    Recorded {
        resource: u16,
        offset: u64,
        len: usize,
    },
    /// Unrecorded bytes: zero-fill `len` bytes, no backing read.
    Gap { len: usize },
}

/// Stage of the TOC save state machine.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum SaveStage {
    /// `Commit`/`Close`: the aggregate data resource is synced first.
    DataSync,
    /// The body and padding are written (they replace the old body first).
    Body,
    /// The header is written last, binding the new body by length/checksum.
    Header,
    /// The written slot is being synced.
    SlotSync,
}

/// Snapshot restored when a `RESERVE TRACK` save fails.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct ReserveRollback {
    tracks: usize,
    sessions: usize,
    last_session: Option<SessionEntry>,
    open_track: Option<u16>,
    disc: CdrDiscState,
    needs_save: bool,
}

/// In-flight TOC save.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct SaveState {
    /// Slot being written (`0` or `1`).
    slot: u8,
    /// Sequence number claimed by the slot.
    seq: u32,
    /// Current stage.
    stage: SaveStage,
    /// Slot bytes already written in the current stage.
    offset: u32,
    /// Body byte count (`body_end = TOC_HEADER_LEN + body_len`).
    body_len: u32,
    /// Body checksum bound into the header.
    checksum: u32,
    /// `max_tracks` advertised by the header.
    max_tracks: u16,
    /// A `RESERVE TRACK` save rolls its new track back on failure.
    rollback: Option<ReserveRollback>,
}

/// Sequential recordable CD medium (CD-R/CD-RW) with a persistent TOC.
pub struct CdrBundleMedium {
    capacity: u64,
    kind: DiscKind,
    disc: CdrDiscState,
    tracks: Vec<TrackEntry, MAX_TRACKS>,
    sessions: Vec<SessionEntry, MAX_SESSIONS>,
    open_track: Option<u16>,
    op: Option<Op>,
    phase: CdrBundleState,
    /// Bytes of the current read/write already transferred.
    progress: u32,
    /// Bytes of the current read/write chunk.
    chunk_len: usize,
    /// The staged read chunk lives in the alternate caller bank (`alt`), so
    /// the next `Send` must take it from there.
    chunk_in_alt: bool,
    /// Bank of the chunk the staged `Send` prefetches for the following step.
    next_in_alt: bool,
    /// Bytes of that prefetched chunk.
    next_len: usize,
    /// The current write command created its track implicitly.
    implicit_created: bool,
    /// Fixed slot size in bytes.
    slot_size: u32,
    /// Sequence number of the newest saved TOC.
    toc_seq: u32,
    /// Slot holding the newest saved TOC.
    current_slot: u8,
    /// At least one slot was loaded or saved.
    saved: bool,
    /// A read-only recovery made the disc reject writes.
    read_only: bool,
    /// A state transition still has to reach a TOC slot.
    needs_save: bool,
    /// The host selected the Write Parameters Test Write (-dummy) mode.
    test_write: bool,
    /// The host selected the Multi-session mode (the next session closure may
    /// keep the disc appendable instead of finalizing it).
    multi_session: bool,
    /// Start address of the disc lead-in.
    medium_leadin: i64,
    /// In-flight TOC save.
    save: Option<SaveState>,
}

impl CdrBundleMedium {
    /// Build a blank CD-R with a standard capacity and the default TOC slot.
    #[must_use]
    pub fn blank(capacity: CdrCapacity) -> Self {
        Self::with_capacity(capacity.sectors())
    }

    /// Build a blank medium of `kind` with a standard capacity and the default
    /// TOC slot.
    #[must_use]
    pub fn blank_disc(kind: DiscKind, capacity: CdrCapacity) -> Self {
        Self::build(capacity.sectors(), kind, TOC_SLOT_DEFAULT)
            .expect("default TOC slot size is valid")
    }

    /// Build a blank CD-R with an explicit sector count and the default TOC
    /// slot size ([`TOC_SLOT_DEFAULT`]).
    #[must_use]
    pub fn with_capacity(sectors: u64) -> Self {
        Self::build(sectors, DiscKind::Cdr, TOC_SLOT_DEFAULT)
            .expect("default TOC slot size is valid")
    }

    /// Build a blank CD-R with an explicit sector count and slot size.
    ///
    /// `slot_size` must be within [`TOC_SLOT_MIN`]..=[`TOC_SLOT_MAX`]; it is
    /// never silently disabled. A medium constructed this way starts with slot
    /// 0 as current and saves its first TOC there with sequence 1.
    pub fn with_capacity_and_slot(sectors: u64, slot_size: u32) -> Result<Self, TocError> {
        Self::build(sectors, DiscKind::Cdr, slot_size)
    }

    /// Build a blank medium of `kind` with an explicit sector count and slot
    /// size.
    ///
    /// `slot_size` must be within [`TOC_SLOT_MIN`]..=[`TOC_SLOT_MAX`]; it is
    /// never silently disabled. A medium constructed this way starts with slot
    /// 0 as current and saves its first TOC there with sequence 1. The kind is
    /// persisted in the TOC body, so a later [`Self::open`] restores it.
    pub fn with_disc(sectors: u64, kind: DiscKind, slot_size: u32) -> Result<Self, TocError> {
        Self::build(sectors, kind, slot_size)
    }

    fn build(sectors: u64, kind: DiscKind, slot_size: u32) -> Result<Self, TocError> {
        if slot_size < TOC_SLOT_MIN {
            return Err(TocError::BadSlotSize);
        }
        if slot_size > TOC_SLOT_MAX {
            return Err(TocError::TooLarge);
        }
        Ok(Self {
            capacity: sectors,
            kind,
            disc: CdrDiscState::Blank,
            tracks: Vec::new(),
            sessions: Vec::new(),
            open_track: None,
            op: None,
            phase: CdrBundleState::Idle,
            progress: 0,
            chunk_len: 0,
            chunk_in_alt: false,
            next_in_alt: false,
            next_len: 0,
            implicit_created: false,
            slot_size,
            toc_seq: 0,
            current_slot: 0,
            saved: false,
            read_only: false,
            needs_save: false,
            test_write: false,
            multi_session: false,
            medium_leadin: MEDIUM_LEADIN,
            save: None,
        })
    }

    /// Restore a medium from a full slot (header + body + padding).
    ///
    /// `capacity` is the caller's sector count; `0` accepts the stored value
    /// and a different non-zero value is rejected. `recovery` decides what
    /// happens to tracks that were not closed when the TOC was written. The
    /// physical slot index comes from the header (`slot`), never from `seq`.
    pub fn open(slot: &[u8], capacity: u64, recovery: Recovery) -> Result<Self, TocError> {
        let parsed = toc::parse(slot, capacity)?;
        Self::from_parsed(parsed, recovery)
    }

    /// Restore a medium from a slot read from known physical position `slot`.
    ///
    /// Unlike [`Self::open`], this rejects a copied/restored document whose
    /// stored `slot` does not match the position it was read from. Applications
    /// that address the two slots explicitly should use this entry point.
    pub fn open_at(
        slot: u8,
        bytes: &[u8],
        capacity: u64,
        recovery: Recovery,
    ) -> Result<Self, TocError> {
        let parsed = toc::parse(bytes, capacity)?;
        if parsed.header.slot != slot {
            return Err(TocError::Invalid);
        }
        Self::from_parsed(parsed, recovery)
    }

    fn from_parsed(parsed: toc::ParsedToc, recovery: Recovery) -> Result<Self, TocError> {
        let mut medium = Self::build(parsed.capacity, parsed.kind, parsed.header.slot_size)?;
        medium.disc = parsed.disc;
        medium.tracks = parsed.tracks;
        medium.sessions = parsed.sessions;
        medium.toc_seq = parsed.header.seq;
        medium.current_slot = parsed.header.slot;
        medium.saved = true;
        medium.medium_leadin = parsed.medium_leadin;
        match recovery {
            Recovery::Delete => {
                if medium.drop_unclosed_tracks() {
                    medium.needs_save = true;
                }
            }
            Recovery::ReadOnly => medium.freeze_written_prefix(),
        }
        Ok(medium)
    }

    /// Addressable logical blocks; the lead-out starts at this LBA.
    #[must_use]
    pub const fn capacity_sectors(&self) -> u64 {
        self.capacity
    }

    /// Recordable media kind (CD-R or CD-RW).
    #[must_use]
    pub const fn kind(&self) -> DiscKind {
        self.kind
    }

    /// Start address of the disc lead-in.
    #[must_use]
    pub const fn medium_leadin(&self) -> i64 {
        self.medium_leadin
    }

    /// Current disc-level state.
    #[must_use]
    pub const fn disc_state(&self) -> CdrDiscState {
        self.disc
    }

    /// Whether the host selected the Write Parameters Multi-session mode.
    #[doc(hidden)]
    #[must_use]
    pub const fn multi_session(&self) -> bool {
        self.multi_session
    }

    /// Fixed TOC slot size in bytes.
    #[must_use]
    pub const fn slot_size(&self) -> u32 {
        self.slot_size
    }

    /// Sequence number of the newest saved TOC (`0` before the first save).
    #[must_use]
    pub const fn toc_seq(&self) -> u32 {
        self.toc_seq
    }

    /// Slot holding the newest saved TOC (slot 0 before the first save).
    #[must_use]
    pub const fn current_slot(&self) -> u8 {
        self.current_slot
    }

    /// Track numbers present in the TOC, for orphan-file reconciliation.
    pub fn track_numbers(&self) -> impl Iterator<Item = u16> + '_ {
        self.tracks.iter().map(|track| track.number)
    }

    /// Whether an in-memory transition still has to reach a TOC slot.
    #[must_use]
    pub const fn needs_save(&self) -> bool {
        self.needs_save
    }

    /// Whether a host eject must persist a TOC snapshot first.
    ///
    /// A finalized disc and a read-only recovery medium already describe a
    /// complete disc, so an eject has nothing left to save for them.
    #[must_use]
    pub const fn eject_needs_save(&self) -> bool {
        !self.write_protected() && (self.needs_save || self.open_track.is_some())
    }

    /// Whether writes are refused by a recovery latch or a finalized disc.
    const fn write_protected(&self) -> bool {
        self.read_only || matches!(self.disc, CdrDiscState::Finalized)
    }

    /// Number of tracks the configured slot can persist.
    fn track_capacity(&self) -> usize {
        usize::from(toc::max_tracks_for_slot(self.slot_size))
    }

    /// Drop the unclosed tail and the sessions it leaves empty.
    ///
    /// Tracks are sequential, so keeping the complete prefix preserves both
    /// contiguous track/session numbering and the `16 + track` payload
    /// resource of every surviving track. Returns whether anything changed.
    fn drop_unclosed_tracks(&mut self) -> bool {
        let keep = self
            .tracks
            .iter()
            .position(|track| track.status != TrackStatus::Complete)
            .unwrap_or(self.tracks.len());
        let changed = keep != self.tracks.len();
        self.tracks.truncate(keep);
        let surviving = self.tracks.len() as u16;

        let mut sessions: Vec<SessionEntry, MAX_SESSIONS> = Vec::new();
        for old in &self.sessions {
            if old.first_track > surviving {
                break;
            }
            let mut session = *old;
            session.last_track = session.last_track.min(surviving);
            if let Some(track) = self
                .tracks
                .iter()
                .find(|track| track.number == session.last_track)
            {
                session.lead_out_lba = track.nwa;
            }
            let _ = sessions.push(session);
        }
        self.sessions = sessions;
        if self.tracks.is_empty() {
            self.disc = CdrDiscState::Blank;
            self.sessions.clear();
        } else if changed || self.disc == CdrDiscState::Blank {
            self.disc = CdrDiscState::Appendable;
        }
        changed
    }

    /// Erase the disc back to the blank state, keeping capacity/kind/slot.
    ///
    /// Only the in-memory TOC state changes; the caller persists it. Track
    /// payload files are left untouched: the resource contract truncates a
    /// reused `track_<n>.bin` on its first write at offset 0, so BLANK never
    /// removes or zero-fills a track file itself.
    fn reset_to_blank(&mut self) {
        self.tracks.clear();
        self.sessions.clear();
        self.open_track = None;
        self.disc = CdrDiscState::Blank;
        self.implicit_created = false;
        self.save = None;
    }

    /// Keep the written prefix of every track and protect the disc.
    fn freeze_written_prefix(&mut self) {
        for track in &mut self.tracks {
            let end = track
                .data_start_lba
                .saturating_add(track.written)
                .min(self.capacity);
            track.nwa = end;
            track.length = end.saturating_sub(track.data_start_lba);
            track.written = track.length;
            track.status = TrackStatus::Complete;
        }
        for session in &mut self.sessions {
            let mut lead_out = session.lead_out_lba;
            for track in self
                .tracks
                .iter()
                .filter(|track| track.session == session.number)
            {
                lead_out = lead_out.max(track.nwa);
            }
            session.lead_out_lba = lead_out;
            session.closed = true;
        }
        if !self.tracks.is_empty() || !self.sessions.is_empty() {
            self.disc = CdrDiscState::Finalized;
        }
        self.read_only = true;
    }

    /// Clear the operation state.
    fn reset(&mut self) {
        self.op = None;
        self.phase = CdrBundleState::Idle;
        self.progress = 0;
        self.chunk_len = 0;
        self.chunk_in_alt = false;
        self.next_in_alt = false;
        self.next_len = 0;
        self.implicit_created = false;
        self.save = None;
    }

    /// Total bytes selected by the admitted operation.
    fn total_bytes(&self) -> usize {
        match self.op {
            Some(Op::Read { bytes, .. } | Op::Write { bytes, .. } | Op::TestWrite { bytes }) => {
                bytes as usize
            }
            _ => 0,
        }
    }

    /// Byte length of the next write chunk, bounded by the caller's bank.
    fn write_chunk(&self, bank_len: usize) -> usize {
        self.total_bytes()
            .saturating_sub(self.progress as usize)
            .min(bank_len)
    }

    /// Validate a read range and return its byte count.
    fn read_range(&self, lba: u64, blocks: u16, kind: TrackKind) -> Result<u32, Completion> {
        if blocks == 0 {
            return Ok(0);
        }
        let end = lba
            .checked_add(u64::from(blocks))
            .ok_or(Completion::Check(LBA_OUT_OF_RANGE))?;
        if end > self.capacity {
            return Err(Completion::Check(LBA_OUT_OF_RANGE));
        }
        let bytes = u64::from(blocks) * u64::from(sector_len(kind));
        if bytes > u64::from(u32::MAX) {
            return Err(Completion::Check(INVALID_FIELD));
        }
        Ok(bytes as u32)
    }

    /// Reject a read whose requested sector kind does not match every track it
    /// touches.
    ///
    /// Logical block addressing stays 2048-byte based for both kinds, but the
    /// storage layout differs (2048 vs 2352 bytes per block). A read that only
    /// crosses gaps is valid for either kind (gaps zero-fill); a read that
    /// touches an audio and a data track has no single consistent sector size.
    fn check_read_kind(&self, lba: u64, blocks: u16, kind: TrackKind) -> Result<(), Completion> {
        if blocks == 0 {
            return Ok(());
        }
        let end = lba.saturating_add(u64::from(blocks));
        for track in &self.tracks {
            let start = track.data_start_lba;
            let len = track.length.max(track.written).max(track.allocated);
            let track_end = start.saturating_add(len);
            if start < end && lba < track_end && track.kind != kind {
                return Err(Completion::Check(ILLEGAL_MODE_FOR_THIS_TRACK));
            }
        }
        Ok(())
    }

    /// Resolve `SectorKind::Auto` for a read at `lba`.
    ///
    /// The track containing the first block selects the sector size; an
    /// untracked block (a gap or pre-gap) uses the logical 2048-byte size.
    fn read_kind_at(&self, lba: u64) -> TrackKind {
        self.tracks
            .iter()
            .find(|track| {
                let start = track.data_start_lba;
                let end =
                    start.saturating_add(track.length.max(track.written).max(track.allocated));
                (start..end).contains(&lba)
            })
            .map_or(TrackKind::Data, |track| track.kind)
    }

    /// Admit a read with an explicit sector kind.
    fn admit_read(&mut self, lba: u64, blocks: u16, kind: TrackKind) -> Result<(), Completion> {
        let bytes = self.read_range(lba, blocks, kind)?;
        if bytes == 0 {
            return Err(Completion::Good);
        }
        self.check_read_kind(lba, blocks, kind)?;
        self.op = Some(Op::Read { lba, bytes, kind });
        Ok(())
    }

    /// Start positions of the next track:
    /// `(session_start_lba, track_start_lba, data_start_lba)`.
    ///
    /// A track appended to an open session follows the previous track after
    /// the usual 150-block pre-gap. A track that starts a new session uses the
    /// documented multi-session geometry: the session lead-in begins at the
    /// previous session's lead-out, the first track preamble starts 4500 blocks
    /// (one minute) later, and its user data starts one pre-gap after that.
    fn next_positions(&self) -> (u64, u64, u64) {
        match self.tracks.last() {
            None => (0, 0, 0),
            Some(last) => match self.sessions.last() {
                Some(session) if session.closed => {
                    let lead_in = session.lead_out_lba;
                    let track_start = lead_in.saturating_add(SESSION_LEADIN_BLOCKS);
                    (
                        lead_in,
                        track_start,
                        track_start.saturating_add(PREGAP_BLOCKS),
                    )
                }
                Some(session) => {
                    let track_start = last.data_start_lba.saturating_add(last.length);
                    (
                        session.start_lba,
                        track_start,
                        track_start.saturating_add(PREGAP_BLOCKS),
                    )
                }
                None => (0, 0, 0),
            },
        }
    }

    /// Next writable address of the disc.
    fn current_nwa(&self) -> u64 {
        if let Some(number) = self.open_track {
            return self
                .tracks
                .iter()
                .find(|track| track.number == number)
                .map_or(0, |track| track.nwa);
        }
        match self.tracks.last() {
            None => 0,
            Some(_) => self.next_positions().2,
        }
    }

    /// Find a track by number.
    fn track_entry(&self, number: u16) -> Option<&TrackEntry> {
        self.tracks.iter().find(|track| track.number == number)
    }

    /// Open a session for `track` if the last session is already closed.
    fn ensure_session(&mut self, track: u16, session_start_lba: u64) -> Result<(), Completion> {
        match self.sessions.last_mut() {
            Some(session) if !session.closed => {
                session.last_track = track;
                return Ok(());
            }
            _ => {}
        }
        if self.sessions.len() >= MAX_SESSIONS {
            return Err(Completion::Check(INVALID_FIELD));
        }
        let number = self.sessions.len() as u16 + 1;
        self.sessions
            .push(SessionEntry {
                number,
                first_track: track,
                last_track: track,
                start_lba: session_start_lba,
                lead_out_lba: session_start_lba,
                closed: false,
            })
            .map_err(|_| Completion::Check(INVALID_FIELD))
    }

    /// Add a track and make it the open one.
    #[allow(clippy::too_many_arguments)]
    fn push_track(
        &mut self,
        number: u16,
        session_start_lba: u64,
        start_lba: u64,
        data_start_lba: u64,
        allocated: u64,
        status: TrackStatus,
        kind: TrackKind,
        reserved: bool,
    ) -> Result<(), Completion> {
        self.ensure_session(number, session_start_lba)?;
        let session_number = self.sessions.last().map_or(1, |session| session.number);
        self.tracks
            .push(TrackEntry {
                number,
                session: session_number,
                start_lba,
                data_start_lba,
                allocated,
                length: 0,
                written: 0,
                nwa: data_start_lba,
                status,
                kind,
                reserved,
            })
            .map_err(|_| Completion::Check(INVALID_FIELD))?;
        if let Some(session) = self
            .sessions
            .iter_mut()
            .find(|session| session.number == session_number)
        {
            session.last_track = number;
            session.lead_out_lba = data_start_lba;
        }
        self.open_track = Some(number);
        self.disc = CdrDiscState::Appendable;
        Ok(())
    }

    /// Admit a write, creating an implicit track when none is open.
    ///
    /// `kind` is the requested recording mode. A new track adopts it; a
    /// reserved track that carries no data yet may still adopt it; an already
    /// recorded track only accepts its own kind (`05/64/00` otherwise).
    fn admit_write(&mut self, lba: u64, blocks: u16, kind: TrackKind) -> Result<(), Completion> {
        let end = lba
            .checked_add(u64::from(blocks))
            .ok_or(Completion::Check(LBA_OUT_OF_RANGE))?;
        if end > self.capacity {
            return Err(Completion::Check(LBA_OUT_OF_RANGE));
        }

        let (number, session_start_lba, start_lba, data_start_lba, nwa, limit, block_bytes) =
            match self.open_track {
                Some(number) => {
                    let track = self
                        .track_entry(number)
                        .ok_or(Completion::Check(INTERNAL_FAILURE))?;
                    if track.written > 0 && track.kind != kind {
                        return Err(Completion::Check(ILLEGAL_MODE_FOR_THIS_TRACK));
                    }
                    let limit = if track.reserved {
                        track.data_start_lba.saturating_add(track.allocated)
                    } else {
                        self.capacity
                    }
                    .min(self.capacity);
                    let session_start_lba = self
                        .sessions
                        .iter()
                        .find(|session| session.number == track.session)
                        .map_or(0, |session| session.start_lba);
                    (
                        number,
                        session_start_lba,
                        track.start_lba,
                        track.data_start_lba,
                        track.nwa,
                        limit,
                        sector_len(kind),
                    )
                }
                None => {
                    let number = self.tracks.len() as u16 + 1;
                    if usize::from(number) > self.track_capacity() {
                        return Err(Completion::Check(INVALID_FIELD));
                    }
                    let (session_start_lba, start_lba, data_start_lba) = self.next_positions();
                    (
                        number,
                        session_start_lba,
                        start_lba,
                        data_start_lba,
                        data_start_lba,
                        self.capacity,
                        sector_len(kind),
                    )
                }
            };

        if end > limit {
            return Err(Completion::Check(LBA_OUT_OF_RANGE));
        }
        if lba != nwa {
            return Err(Completion::Check(INVALID_ADDRESS_FOR_WRITE));
        }

        if self.open_track.is_none() {
            self.push_track(
                number,
                session_start_lba,
                start_lba,
                data_start_lba,
                0,
                TrackStatus::Incomplete,
                kind,
                false,
            )?;
            self.implicit_created = true;
        } else if let Some(track) = self
            .tracks
            .iter_mut()
            .find(|track| track.number == number && track.status != TrackStatus::Complete)
        {
            if track.written == 0 {
                // A reserved track was created without recording-mode
                // information; its first real write decides data vs audio.
                track.kind = kind;
            }
            track.status = TrackStatus::Incomplete;
        }

        let offset = (lba - data_start_lba)
            .checked_mul(u64::from(block_bytes))
            .ok_or(Completion::Check(LBA_OUT_OF_RANGE))?;
        let bytes = u64::from(blocks) * u64::from(block_bytes);
        if bytes > u64::from(u32::MAX) {
            return Err(Completion::Check(INVALID_FIELD));
        }
        self.op = Some(Op::Write {
            track: number,
            offset,
            bytes: bytes as u32,
            sector_len: block_bytes,
        });
        Ok(())
    }

    /// Admit a simulated write: only the address range is checked.
    ///
    /// Test Write consumes the host's data without touching the track/session
    /// tables, so the next writable address, the TOC and the backing all stay
    /// exactly as they were.
    fn admit_test_write(
        &mut self,
        lba: u64,
        blocks: u16,
        kind: TrackKind,
    ) -> Result<(), Completion> {
        let end = lba
            .checked_add(u64::from(blocks))
            .ok_or(Completion::Check(LBA_OUT_OF_RANGE))?;
        if end > self.capacity {
            return Err(Completion::Check(LBA_OUT_OF_RANGE));
        }
        let bytes = u64::from(blocks) * u64::from(sector_len(kind));
        if bytes > u64::from(u32::MAX) {
            return Err(Completion::Check(INVALID_FIELD));
        }
        self.op = Some(Op::TestWrite {
            bytes: bytes as u32,
        });
        Ok(())
    }

    /// Validate a `RESERVE TRACK` size against the disc geometry.
    ///
    /// This is the part of a reservation that does not depend on an open
    /// track, so the Test Write no-op path can still reject an impossible
    /// request.
    fn validate_reserve_track(&self, size: u32) -> Result<(), Completion> {
        let size = u64::from(size);
        if size < MIN_TRACK_BLOCKS {
            return Err(Completion::Check(INVALID_FIELD));
        }
        let number = self.tracks.len() as u16 + 1;
        if usize::from(number) > self.track_capacity() {
            return Err(Completion::Check(INVALID_FIELD));
        }
        let (_, start_lba, _) = self.next_positions();
        // Track 1 starts at the first user block and has no pre-gap; every
        // later track occupies its pre-gap plus the allocated blocks.
        let required = if self.tracks.is_empty() {
            size
        } else {
            size.saturating_add(PREGAP_BLOCKS)
        };
        if required > self.capacity.saturating_sub(start_lba) {
            return Err(Completion::Check(INVALID_FIELD));
        }
        Ok(())
    }

    /// Admit `RESERVE TRACK`; it changes the write state.
    fn reserve_track(&mut self, size: u32) -> Result<(), Completion> {
        if self.write_protected() {
            return Err(Completion::Check(WRITE_PROTECTED));
        }
        if self.open_track.is_some()
            || self.tracks.iter().any(|track| {
                matches!(
                    track.status,
                    TrackStatus::Reserved | TrackStatus::Incomplete
                )
            })
        {
            return Err(Completion::Check(INVALID_FIELD));
        }
        self.validate_reserve_track(size)?;
        let number = self.tracks.len() as u16 + 1;
        let (session_start_lba, start_lba, data_start_lba) = self.next_positions();
        self.push_track(
            number,
            session_start_lba,
            start_lba,
            data_start_lba,
            u64::from(size),
            TrackStatus::Reserved,
            TrackKind::Data,
            true,
        )
    }

    /// Pad and close the open track, if any.
    fn close_open_track(&mut self) {
        let Some(number) = self.open_track.take() else {
            return;
        };
        if let Some(track) = self.tracks.iter_mut().find(|track| track.number == number) {
            let room = self.capacity.saturating_sub(track.data_start_lba);
            let limit = if track.reserved {
                track.allocated.min(room)
            } else {
                room
            };
            let length = if track.reserved {
                // A reserved track is padded to the end of its reservation,
                // whether or not any user blocks were recorded in it.
                track.allocated.min(limit)
            } else {
                track.length.max(MIN_TRACK_BLOCKS).min(limit)
            };
            track.length = length;
            track.nwa = track.data_start_lba.saturating_add(length);
            track.status = TrackStatus::Complete;
            let session = track.session;
            let end = track.nwa;
            if let Some(entry) = self
                .sessions
                .iter_mut()
                .find(|entry| entry.number == session)
            {
                entry.last_track = track.number;
                entry.lead_out_lba = end;
            }
        }
    }

    /// Close the session and finalize the disc.
    fn finalize(&mut self) -> Result<(), Completion> {
        if self.disc == CdrDiscState::Finalized {
            return Ok(());
        }
        // An open or partially recorded track blocks session fixation. A
        // reserved track that never received user blocks has its own sense.
        if let Some(number) = self.open_track {
            return Err(Completion::Check(match self.track_entry(number) {
                Some(track) if track.status == TrackStatus::Reserved && track.written == 0 => {
                    EMPTY_OR_PARTIALLY_WRITTEN_RESERVED_TRACK
                }
                _ => SESSION_FIXATION_INCOMPLETE_TRACK,
            }));
        }
        if let Some(track) = self.tracks.iter().find(|track| {
            matches!(
                track.status,
                TrackStatus::Reserved | TrackStatus::Incomplete
            )
        }) {
            return Err(Completion::Check(
                if track.status == TrackStatus::Reserved && track.written == 0 {
                    EMPTY_OR_PARTIALLY_WRITTEN_RESERVED_TRACK
                } else {
                    SESSION_FIXATION_INCOMPLETE_TRACK
                },
            ));
        }
        // Finalizing an empty disc (no recorded user data anywhere) is a
        // success no-op; it must not latch the disc write-protected. This is
        // a disc-wide check: an empty trailing session must not hide data
        // recorded in an earlier session.
        let has_data = self.tracks.iter().any(|track| track.written > 0);
        if !has_data {
            return Ok(());
        }
        let end = self.tracks.iter().map(|track| track.nwa).max().unwrap_or(0);
        for session in self.sessions.iter_mut() {
            session.closed = true;
            if session.lead_out_lba == 0 {
                session.lead_out_lba = end;
            }
        }
        self.disc = CdrDiscState::Finalized;
        Ok(())
    }

    /// Close the current session.
    ///
    /// With the Write Parameters Multi-session field set to `11b` the session
    /// is only closed: the disc stays [`CdrDiscState::Appendable`] and a later
    /// write may start the next session at the lead-in following this
    /// session's lead-out. Without it the disc is finalized as before.
    fn close_session(&mut self) -> Result<(), Completion> {
        if self.disc == CdrDiscState::Finalized {
            return Ok(());
        }
        if !self.multi_session {
            return self.finalize();
        }
        // A CLOSE SESSION without a preceding SYNCHRONIZE CACHE still seals
        // the open track before the session is closed.
        if self.open_track.is_some() {
            self.close_open_track();
        } else if let Some(track) = self.tracks.iter().find(|track| {
            matches!(
                track.status,
                TrackStatus::Reserved | TrackStatus::Incomplete
            )
        }) {
            return Err(Completion::Check(
                if track.status == TrackStatus::Reserved && track.written == 0 {
                    EMPTY_OR_PARTIALLY_WRITTEN_RESERVED_TRACK
                } else {
                    SESSION_FIXATION_INCOMPLETE_TRACK
                },
            ));
        }
        let Some(number) = self.sessions.last().map(|session| session.number) else {
            return Ok(());
        };
        let has_data = self
            .tracks
            .iter()
            .any(|track| track.session == number && track.written > 0);
        let end = self
            .tracks
            .iter()
            .filter(|track| track.session == number)
            .map(|track| track.nwa)
            .max()
            .unwrap_or(0);
        if let Some(session) = self
            .sessions
            .iter_mut()
            .find(|session| session.number == number)
        {
            if session.closed {
                return Ok(());
            }
            session.lead_out_lba = end;
            session.closed = true;
        }
        // Closing a session with no recorded user data is still a successful
        // close; it does not by itself make a blank disc appendable for a
        // next-session write.
        if has_data {
            self.disc = CdrDiscState::Appendable;
        }
        Ok(())
    }

    /// Apply the blocks confirmed by a write receipt to the open track.
    fn confirm_write(&mut self, blocks: u64) {
        let Some(Op::Write { track, .. }) = self.op else {
            return;
        };
        let capacity = self.capacity;
        let mut session_end = None;
        if let Some(entry) = self.tracks.iter_mut().find(|entry| entry.number == track) {
            let limit = if entry.reserved {
                entry.data_start_lba.saturating_add(entry.allocated)
            } else {
                capacity
            }
            .min(capacity);
            entry.nwa = entry.nwa.saturating_add(blocks).min(limit);
            entry.length = entry.nwa.saturating_sub(entry.data_start_lba);
            entry.written = entry.length;
            if entry.status != TrackStatus::Complete {
                entry.status = TrackStatus::Incomplete;
            }
            session_end = Some((entry.session, entry.nwa));
        }
        if let Some((session, end)) = session_end {
            if let Some(entry) = self
                .sessions
                .iter_mut()
                .find(|entry| entry.number == session)
            {
                entry.lead_out_lba = end;
            }
        }
    }

    /// Arm a TOC save after an in-memory state transition.
    ///
    /// The body is written before the header, so a torn save cannot pair a new
    /// header with an old body. A body that cannot fit leaves the previous
    /// slot untouched and fails the command.
    fn start_save(
        &mut self,
        sync_data: bool,
        rollback: Option<ReserveRollback>,
    ) -> Result<(), Completion> {
        if self.read_only {
            return Err(Completion::Check(WRITE_PROTECTED));
        }
        let max_tracks = toc::max_tracks_for_slot(self.slot_size);
        if max_tracks == 0
            || self.tracks.len() > usize::from(max_tracks)
            || self.tracks.iter().any(|track| track.number > max_tracks)
        {
            return Err(Completion::Check(INTERNAL_FAILURE));
        }
        let body_len = toc::body_len(
            &self.tracks,
            &self.sessions,
            self.capacity,
            self.medium_leadin,
            self.disc,
            self.kind,
        );
        if TOC_HEADER_LEN
            .checked_add(body_len)
            .is_none_or(|end| end > self.slot_size as usize)
        {
            return Err(Completion::Check(INTERNAL_FAILURE));
        }
        let checksum = toc::body_checksum(
            &self.tracks,
            &self.sessions,
            self.capacity,
            self.medium_leadin,
            self.disc,
            self.kind,
        );
        let seq = match self.toc_seq.checked_add(1) {
            Some(seq) => seq,
            None => return Err(Completion::Check(INTERNAL_FAILURE)),
        };
        let slot = if self.saved {
            1 - self.current_slot
        } else {
            self.current_slot
        };
        self.save = Some(SaveState {
            slot,
            seq,
            stage: if sync_data {
                SaveStage::DataSync
            } else {
                SaveStage::Body
            },
            offset: if sync_data { 0 } else { TOC_HEADER_LEN as u32 },
            body_len: body_len as u32,
            checksum,
            max_tracks,
            rollback,
        });
        self.op = Some(Op::SaveToc);
        Ok(())
    }

    /// Render the next alternating TOC slot into `out` and seal the medium.
    ///
    /// This is the pre-eject snapshot path: it performs the same in-memory
    /// sealing as `SYNCHRONIZE CACHE` (padding and closing an open track),
    /// renders the slot image that a save would write, and advances the save
    /// bookkeeping without touching storage. `out` must be at least
    /// [`Self::slot_size`] bytes; the header is written at offset 0 and the
    /// body plus padding fills the rest. The returned slot index is the
    /// physical slot an application must write (via [`toc_resource`] /
    /// [`toc_file`]). A later save therefore alternates to the other slot and
    /// the sequence numbers stay monotonic.
    ///
    /// A render failure after the seal still leaves the medium sealed with
    /// `needs_save` set, so the next `CLOSE`/`SYNCHRONIZE CACHE` persists the
    /// compacted state.
    pub fn toc_image(&mut self, out: &mut [u8]) -> Result<u8, TocError> {
        if self.read_only {
            return Err(TocError::WriteProtected);
        }
        let slot_size = self.slot_size as usize;
        if out.len() < slot_size {
            return Err(TocError::Invalid);
        }

        self.close_open_track();
        self.needs_save = true;

        let max_tracks = toc::max_tracks_for_slot(self.slot_size);
        if max_tracks == 0
            || self.tracks.len() > usize::from(max_tracks)
            || self.tracks.iter().any(|track| track.number > max_tracks)
        {
            return Err(TocError::TooLarge);
        }
        let body_len = toc::body_len(
            &self.tracks,
            &self.sessions,
            self.capacity,
            self.medium_leadin,
            self.disc,
            self.kind,
        );
        if TOC_HEADER_LEN
            .checked_add(body_len)
            .is_none_or(|end| end > slot_size)
        {
            return Err(TocError::TooLarge);
        }
        let checksum = toc::body_checksum(
            &self.tracks,
            &self.sessions,
            self.capacity,
            self.medium_leadin,
            self.disc,
            self.kind,
        );
        let seq = self.toc_seq.checked_add(1).ok_or(TocError::Invalid)?;
        let slot = if self.saved {
            1 - self.current_slot
        } else {
            self.current_slot
        };
        let save = SaveState {
            slot,
            seq,
            stage: SaveStage::Body,
            offset: TOC_HEADER_LEN as u32,
            body_len: body_len as u32,
            checksum,
            max_tracks,
            rollback: None,
        };

        out[..slot_size].fill(0);
        if self.render_header(save, 0, &mut out[..TOC_HEADER_LEN]) != TOC_HEADER_LEN
            || self.render_body_slot(
                save,
                TOC_HEADER_LEN as u32,
                &mut out[TOC_HEADER_LEN..slot_size],
            ) != slot_size - TOC_HEADER_LEN
        {
            return Err(TocError::Invalid);
        }

        self.toc_seq = seq;
        self.current_slot = slot;
        self.saved = true;
        self.needs_save = false;
        Ok(slot)
    }

    /// Undo a `RESERVE TRACK` that could not be persisted.
    fn rollback_reserve(&mut self, rollback: ReserveRollback) {
        self.tracks.truncate(rollback.tracks);
        self.sessions.truncate(rollback.sessions);
        if let (Some(session), Some(slot)) = (rollback.last_session, self.sessions.last_mut()) {
            *slot = session;
        }
        self.open_track = rollback.open_track;
        self.disc = rollback.disc;
        self.needs_save = rollback.needs_save;
    }

    /// Abort a save, applying a pending reservation rollback.
    fn abort_save(&mut self, save: SaveState, completion: Completion) -> PollStep<'static> {
        if let Some(rollback) = save.rollback {
            self.rollback_reserve(rollback);
        }
        self.save = None;
        self.finish(completion)
    }

    fn abort_save_sense(
        &mut self,
        save: SaveState,
        fault: Fault,
        ctx: IoContext,
    ) -> PollStep<'static> {
        if let Some(rollback) = save.rollback {
            self.rollback_reserve(rollback);
        }
        self.save = None;
        self.storage_sense(fault, ctx)
    }

    /// Render body bytes or padding at slot offset `offset` (`>= 256`).
    fn render_body_slot(&self, save: SaveState, offset: u32, out: &mut [u8]) -> usize {
        let slot_size = self.slot_size as usize;
        let start = offset as usize;
        let body_end = TOC_HEADER_LEN + save.body_len as usize;
        let want = out.len().min(slot_size.saturating_sub(start));
        let mut written = 0usize;
        if start < body_end {
            let body_at = start - TOC_HEADER_LEN;
            let take = want.min(body_end - start);
            written += toc::render_body(
                &self.tracks,
                &self.sessions,
                self.capacity,
                self.medium_leadin,
                self.disc,
                self.kind,
                body_at,
                &mut out[..take],
            );
        }
        let cursor = start + written;
        if cursor < slot_size && written < want {
            let padding_at = cursor - body_end;
            written +=
                toc::render_padding(slot_size - body_end, padding_at, &mut out[written..want]);
        }
        written
    }

    /// Copy the header bytes at header offset `offset`.
    fn render_header(&self, save: SaveState, offset: u32, out: &mut [u8]) -> usize {
        let header = toc::header_bytes(
            save.slot,
            self.slot_size,
            save.max_tracks,
            save.body_len,
            save.checksum,
            save.seq,
        );
        let start = offset as usize;
        let take = out.len().min(TOC_HEADER_LEN.saturating_sub(start));
        out[..take].copy_from_slice(&header[start..start + take]);
        take
    }

    /// Issue the next save operation (data sync, body, header or slot sync).
    fn save_next<'a>(&mut self, data: &'a mut [u8]) -> PollStep<'a> {
        let Some(save) = self.save else {
            return self.finish(Completion::Check(INTERNAL_FAILURE));
        };
        match save.stage {
            SaveStage::DataSync => {
                self.phase = CdrBundleState::SaveWait;
                PollStep::Io(StorageOp::Sync { resource: 0 })
            }
            SaveStage::Body => {
                let remaining = (self.slot_size - save.offset) as usize;
                if remaining == 0 {
                    self.save = Some(SaveState {
                        stage: SaveStage::Header,
                        offset: 0,
                        ..save
                    });
                    return self.save_next(data);
                }
                let chunk = remaining.min(data.len());
                if chunk == 0 {
                    return self.abort_save(save, Completion::Check(INTERNAL_FAILURE));
                }
                if self.render_body_slot(save, save.offset, &mut data[..chunk]) != chunk {
                    return self.abort_save(save, Completion::Check(INTERNAL_FAILURE));
                }
                self.chunk_len = chunk;
                self.phase = CdrBundleState::SaveWait;
                PollStep::Io(StorageOp::Write {
                    resource: toc_resource(save.slot),
                    offset: u64::from(save.offset),
                    buf: &mut data[..chunk],
                })
            }
            SaveStage::Header => {
                let remaining = (TOC_HEADER_LEN as u32 - save.offset) as usize;
                if remaining == 0 {
                    self.save = Some(SaveState {
                        stage: SaveStage::SlotSync,
                        offset: 0,
                        ..save
                    });
                    return self.save_next(data);
                }
                let chunk = remaining.min(data.len());
                if chunk == 0 {
                    return self.abort_save(save, Completion::Check(INTERNAL_FAILURE));
                }
                if self.render_header(save, save.offset, &mut data[..chunk]) != chunk {
                    return self.abort_save(save, Completion::Check(INTERNAL_FAILURE));
                }
                self.chunk_len = chunk;
                self.phase = CdrBundleState::SaveWait;
                PollStep::Io(StorageOp::Write {
                    resource: toc_resource(save.slot),
                    offset: u64::from(save.offset),
                    buf: &mut data[..chunk],
                })
            }
            SaveStage::SlotSync => {
                self.phase = CdrBundleState::SaveWait;
                PollStep::Io(StorageOp::Sync {
                    resource: toc_resource(save.slot),
                })
            }
        }
    }

    /// Fold the receipt of the in-flight save operation.
    fn save_done<'a>(&mut self, fb: Feedback, data: &'a mut [u8]) -> PollStep<'a> {
        let Some(mut save) = self.save else {
            return self.finish(Completion::Check(INTERNAL_FAILURE));
        };
        let Some(receipt) = fb.io() else {
            return self.abort_save(save, Completion::Check(INTERNAL_FAILURE));
        };
        match save.stage {
            SaveStage::DataSync => {
                if let Some(fault) = receipt.error() {
                    return self.abort_save_sense(save, fault, IoContext::Sync);
                }
                if receipt.effect() != Effect::Known {
                    return self.abort_save(save, Completion::Check(MEDIUM_ERROR));
                }
                save.stage = SaveStage::Body;
                save.offset = TOC_HEADER_LEN as u32;
                self.save = Some(save);
                self.save_next(data)
            }
            SaveStage::Body => {
                let chunk = self.chunk_len;
                if let Some(fault) = receipt.error() {
                    return self.abort_save_sense(save, fault, IoContext::Write);
                }
                let confirmed = receipt.confirmed().min(chunk);
                if confirmed < chunk || receipt.effect() != Effect::Known {
                    return self.abort_save(save, Completion::Check(MEDIUM_ERROR));
                }
                save.offset = save.offset.saturating_add(confirmed as u32);
                if save.offset >= self.slot_size {
                    save.stage = SaveStage::Header;
                    save.offset = 0;
                }
                self.save = Some(save);
                self.save_next(data)
            }
            SaveStage::Header => {
                let chunk = self.chunk_len;
                if let Some(fault) = receipt.error() {
                    return self.abort_save_sense(save, fault, IoContext::Write);
                }
                let confirmed = receipt.confirmed().min(chunk);
                if confirmed < chunk || receipt.effect() != Effect::Known {
                    return self.abort_save(save, Completion::Check(MEDIUM_ERROR));
                }
                save.offset = save.offset.saturating_add(confirmed as u32);
                if save.offset >= TOC_HEADER_LEN as u32 {
                    save.stage = SaveStage::SlotSync;
                    save.offset = 0;
                }
                self.save = Some(save);
                self.save_next(data)
            }
            SaveStage::SlotSync => {
                if let Some(fault) = receipt.error() {
                    return self.abort_save_sense(save, fault, IoContext::Sync);
                }
                if receipt.effect() != Effect::Known {
                    return self.abort_save(save, Completion::Check(MEDIUM_ERROR));
                }
                self.toc_seq = save.seq;
                self.current_slot = save.slot;
                self.saved = true;
                self.needs_save = false;
                self.save = None;
                self.finish(Completion::Good)
            }
        }
    }

    /// Pure projection of the read segment at `progress`, bounded by `bank_len`.
    ///
    /// `progress` is a byte offset into the admitted read, so the projection is
    /// the same whether it describes the chunk to read now or the one a
    /// prefetch should stage. `None` means the request cannot be staged (no
    /// bytes left, no bank, or a zero-length segment).
    fn segment_at(&self, progress: usize, bank_len: usize) -> Option<Segment> {
        let remaining = self.total_bytes().saturating_sub(progress);
        if remaining == 0 || bank_len == 0 {
            return None;
        }
        let Some(Op::Read { lba, kind, .. }) = self.op else {
            return None;
        };
        let block_bytes = u64::from(sector_len(kind));
        let pos = lba
            .saturating_mul(block_bytes)
            .saturating_add(progress as u64);
        let current_lba = pos / block_bytes;

        if let Some(track) = self
            .tracks
            .iter()
            .find(|track| {
                track.written > 0
                    && (track.data_start_lba..track.data_start_lba.saturating_add(track.written))
                        .contains(&current_lba)
            })
            .copied()
        {
            let segment_end = track
                .data_start_lba
                .saturating_add(track.written)
                .saturating_mul(block_bytes);
            let available = segment_end.saturating_sub(pos);
            let len = (remaining as u64).min(bank_len as u64).min(available) as usize;
            if len == 0 {
                return None;
            }
            let offset = pos.saturating_sub(track.data_start_lba.saturating_mul(block_bytes));
            return Some(Segment::Recorded {
                resource: track_resource(track.number),
                offset,
                len,
            });
        }

        let mut boundary = pos.saturating_add(remaining as u64);
        for track in &self.tracks {
            let at = track.data_start_lba.saturating_mul(block_bytes);
            if at > pos && at < boundary {
                boundary = at;
            }
        }
        let len = (remaining as u64)
            .min(bank_len as u64)
            .min(boundary.saturating_sub(pos)) as usize;
        if len == 0 {
            return None;
        }
        Some(Segment::Gap { len })
    }

    /// Issue the next read segment, or zero-fill an unrecorded one.
    ///
    /// This is the serial path: it is taken after a plain send (no companion),
    /// and it either starts a required read or delivers a zero-filled gap.
    fn next_read_step<'a>(&mut self, data: &'a mut [u8]) -> PollStep<'a> {
        if self.total_bytes().saturating_sub(self.progress as usize) == 0 {
            return self.finish(Completion::Good);
        }
        let Some(segment) = self.segment_at(self.progress as usize, data.len()) else {
            return self.finish(Completion::Check(INTERNAL_FAILURE));
        };
        match segment {
            Segment::Recorded {
                resource,
                offset,
                len,
            } => {
                self.chunk_len = len;
                self.chunk_in_alt = false;
                self.phase = CdrBundleState::ReadIo;
                PollStep::Io(StorageOp::Read {
                    resource,
                    offset,
                    buf: &mut data[..len],
                })
            }
            Segment::Gap { len } => {
                data[..len].fill(0);
                self.chunk_len = len;
                self.chunk_in_alt = false;
                self.phase = CdrBundleState::Deliver;
                PollStep::Send {
                    bytes: &data[..len],
                    prefetch: None,
                }
            }
        }
    }

    /// Describe the recorded segment after the staged chunk.
    ///
    /// Pure projection: no stage, progress or bank state changes. A gap or a
    /// second bank too small for one segment yields no companion (the serial
    /// path handles those).
    fn peek_prefetch(&self, data_len: usize, alt_len: usize) -> Option<(bool, u16, u64, usize)> {
        if alt_len == 0 {
            return None;
        }
        let next_progress = self.progress as usize + self.chunk_len;
        let use_alt = !self.chunk_in_alt;
        let bank_len = if use_alt { alt_len } else { data_len };
        match self.segment_at(next_progress, bank_len) {
            Some(Segment::Recorded {
                resource,
                offset,
                len,
            }) => Some((use_alt, resource, offset, len)),
            Some(Segment::Gap { .. }) | None => None,
        }
    }

    /// Send the staged chunk, with the speculative read of the next segment
    /// when a second caller bank and a recorded segment both exist.
    ///
    /// The only send path of a read, so a command that had to take the serial
    /// step re-enters the pipeline on its next chunk instead of staying serial
    /// for the rest of the transfer.
    fn send_staged_with_prefetch<'a>(
        &mut self,
        data: &'a mut [u8],
        alt: &'a mut [u8],
    ) -> PollStep<'a> {
        let peek = self.peek_prefetch(data.len(), alt.len());
        self.next_in_alt = peek.is_some_and(|(in_alt, ..)| in_alt);
        self.next_len = peek.map_or(0, |(_, _, _, len)| len);
        let len = self.chunk_len;
        if self.chunk_in_alt {
            let bytes = &alt[..len];
            let prefetch = peek.map(|(_, resource, offset, prefetch_len)| {
                crate::core::storage::PrefetchOp::Read {
                    resource,
                    offset,
                    buf: &mut data[..prefetch_len],
                }
            });
            PollStep::Send { bytes, prefetch }
        } else {
            let bytes = &data[..len];
            let prefetch = peek.map(|(_, resource, offset, prefetch_len)| {
                crate::core::storage::PrefetchOp::Read {
                    resource,
                    offset,
                    buf: &mut alt[..prefetch_len],
                }
            });
            PollStep::Send { bytes, prefetch }
        }
    }

    /// Remove a track the current command created implicitly and that never
    /// received a confirmed block.
    fn drop_implicit_track(&mut self, number: u16) {
        if self.open_track == Some(number) {
            self.open_track = None;
        }
        if self
            .tracks
            .last()
            .is_some_and(|track| track.number == number)
        {
            let _ = self.tracks.pop();
        }
        if self
            .sessions
            .last()
            .is_some_and(|session| session.first_track == number)
        {
            let _ = self.sessions.pop();
        }
        match self.tracks.last().copied() {
            Some(last) => {
                if let Some(session) = self.sessions.iter_mut().find(|session| !session.closed) {
                    session.last_track = last.number;
                    session.lead_out_lba = last.nwa;
                }
            }
            None => self.disc = CdrDiscState::Blank,
        }
    }

    /// Fix a terminal completion.
    fn finish(&mut self, completion: Completion) -> PollStep<'static> {
        self.phase = CdrBundleState::Done;
        self.op = None;
        self.implicit_created = false;
        self.save = None;
        PollStep::Complete(completion)
    }

    /// Map an adapter fault with the direction-specific default table.
    fn storage_sense(&mut self, fault: Fault, ctx: IoContext) -> PollStep<'static> {
        match storage_fault_sense(fault, ctx) {
            Some(sense) => self.finish(Completion::Check(sense)),
            None => self.finish(Completion::Check(INTERNAL_FAILURE)),
        }
    }
}

impl MmcMedium for CdrBundleMedium {
    type State = CdrBundleState;

    fn attrs(&self) -> MmcAttrs {
        let (write_mode, profile) = match self.kind {
            DiscKind::Cdr => (MmcWriteMode::WriteOnce, 0x0009),
            DiscKind::Cdrw => (MmcWriteMode::Rewritable, 0x000A),
        };
        MmcAttrs {
            write_mode,
            block_len: BLOCK_LEN,
            sectors: self.capacity,
            tracks: self.tracks.len() as u16,
            sessions: self.sessions.len() as u16,
            write_protected: self.write_protected(),
            needs_recovery: false,
            profile,
            current_features: CDR_FEATURES,
        }
    }

    fn state(&self) -> &Self::State {
        &self.phase
    }

    fn begin(&mut self, op: MmcOp) -> Result<(), Completion> {
        if self.active() {
            return Err(Completion::Busy);
        }
        // A rejected admission must not leave the previous command's terminal
        // phase visible.
        self.phase = CdrBundleState::Idle;
        self.progress = 0;
        self.chunk_len = 0;
        self.chunk_in_alt = false;
        self.next_in_alt = false;
        self.next_len = 0;
        self.implicit_created = false;
        // In Test Write mode the recording commands are simulations: they
        // report GOOD without changing the disc or touching the TOC. A real
        // open track or an unsaved transition still takes the normal path, so
        // the simulation never hides pending state.
        if self.test_write && self.open_track.is_none() && !self.needs_save {
            match op {
                MmcOp::Commit | MmcOp::Close { .. } => return Err(Completion::Good),
                MmcOp::ReserveTrack { size } => {
                    if self.write_protected() {
                        return Err(Completion::Check(WRITE_PROTECTED));
                    }
                    self.validate_reserve_track(size)?;
                    return Err(Completion::Good);
                }
                _ => {}
            }
        }
        match op {
            MmcOp::Read { lba, blocks } => {
                self.admit_read(lba, blocks, TrackKind::Data)?;
            }
            MmcOp::ReadSectors { lba, blocks, kind } => match kind {
                SectorKind::Auto => {
                    let resolved = self.read_kind_at(lba);
                    self.admit_read(lba, blocks, resolved)?;
                }
                SectorKind::Data2048 => self.admit_read(lba, blocks, TrackKind::Data)?,
                SectorKind::Audio2352 => self.admit_read(lba, blocks, TrackKind::Audio)?,
            },
            MmcOp::Write { lba, blocks } => {
                if self.write_protected() {
                    return Err(Completion::Check(WRITE_PROTECTED));
                }
                if blocks == 0 {
                    return Err(Completion::Good);
                }
                if self.test_write {
                    self.admit_test_write(lba, blocks, TrackKind::Data)?;
                } else {
                    self.admit_write(lba, blocks, TrackKind::Data)?;
                }
            }
            MmcOp::WriteSectors { lba, blocks, kind } => match kind {
                SectorKind::Auto | SectorKind::Data2048 => {
                    if self.write_protected() {
                        return Err(Completion::Check(WRITE_PROTECTED));
                    }
                    if blocks == 0 {
                        return Err(Completion::Good);
                    }
                    if self.test_write {
                        self.admit_test_write(lba, blocks, TrackKind::Data)?;
                    } else {
                        self.admit_write(lba, blocks, TrackKind::Data)?;
                    }
                }
                // CD-DA audio keeps 2352 bytes per logical block in its track
                // resource; the LBA/NWA accounting stays 2048-byte based.
                SectorKind::Audio2352 => {
                    if self.write_protected() {
                        return Err(Completion::Check(WRITE_PROTECTED));
                    }
                    if blocks == 0 {
                        return Err(Completion::Good);
                    }
                    if self.test_write {
                        self.admit_test_write(lba, blocks, TrackKind::Audio)?;
                    } else {
                        self.admit_write(lba, blocks, TrackKind::Audio)?;
                    }
                }
            },
            MmcOp::Commit => {
                // A TAO recorder relies on SYNCHRONIZE CACHE to pad and close
                // the track before it finalizes the disc. The aggregate data is
                // synced before the TOC body/header.
                if self.read_only {
                    self.op = Some(Op::Sync);
                } else {
                    self.close_open_track();
                    self.needs_save = true;
                    self.start_save(true, None)?;
                }
            }
            MmcOp::Close { function } => match function {
                1 => {
                    if self.read_only {
                        return Err(Completion::Check(WRITE_PROTECTED));
                    }
                    if self.open_track.is_some() {
                        self.close_open_track();
                        self.needs_save = true;
                    } else if !self.needs_save {
                        return Err(Completion::Good);
                    }
                    self.start_save(true, None)?;
                }
                2 => {
                    if self.read_only {
                        return if self.disc == CdrDiscState::Finalized {
                            Err(Completion::Good)
                        } else {
                            Err(Completion::Check(WRITE_PROTECTED))
                        };
                    }
                    if self.disc == CdrDiscState::Finalized && !self.needs_save {
                        return Err(Completion::Good);
                    }
                    self.close_session()?;
                    self.needs_save = true;
                    self.start_save(true, None)?;
                }
                _ => return Err(Completion::Check(INVALID_FIELD)),
            },
            MmcOp::ReserveTrack { size } => {
                let rollback = ReserveRollback {
                    tracks: self.tracks.len(),
                    sessions: self.sessions.len(),
                    last_session: self.sessions.last().copied(),
                    open_track: self.open_track,
                    disc: self.disc,
                    needs_save: self.needs_save,
                };
                self.reserve_track(size)?;
                self.needs_save = true;
                if let Err(completion) = self.start_save(false, Some(rollback)) {
                    self.rollback_reserve(rollback);
                    return Err(completion);
                }
            }
            MmcOp::Blank { blanking, .. } => {
                // Precedence is fixed: a write-once CD-R has no blank state
                // (24/00), a recovery latch wins over erasability (07/27), and
                // only then does the blanking type matter (24/00 for anything
                // but all/minimal). The drive does not duplicate these checks
                // on the medium-owned path.
                if self.kind == DiscKind::Cdr {
                    return Err(Completion::Check(INVALID_FIELD));
                }
                if self.read_only {
                    return Err(Completion::Check(WRITE_PROTECTED));
                }
                if blanking > 1 {
                    return Err(Completion::Check(INVALID_FIELD));
                }
                self.reset_to_blank();
                self.needs_save = true;
                // No data sync: only the TOC state changed. IMMED is accepted
                // because the medium completes synchronously.
                self.start_save(false, None)?;
            }
            // FORMAT UNIT is not erasable on a sequential CD medium, and the
            // descriptor commands are encoded by the drive.
            MmcOp::Format { .. } | MmcOp::TrackInfo { .. } | MmcOp::DiscInfo => {
                return Err(Completion::Check(INVALID_FIELD))
            }
        }
        self.phase = CdrBundleState::Publish;
        Ok(())
    }

    fn poll<'a>(&mut self, fb: Feedback, data: &'a mut [u8]) -> PollStep<'a> {
        self.poll_with_alt(fb, data, &mut [])
    }

    fn poll_with_alt<'a>(
        &mut self,
        fb: Feedback,
        data: &'a mut [u8],
        alt: &'a mut [u8],
    ) -> PollStep<'a> {
        let total = self.total_bytes();
        match (self.phase, fb.kind()) {
            (CdrBundleState::Publish, FeedbackKind::Begin) => match self.op {
                Some(Op::Read { bytes, .. }) => {
                    self.phase = CdrBundleState::ReadIo;
                    PollStep::Publish(DataPlan {
                        direction: Direction::ToHost,
                        bytes: u64::from(bytes),
                    })
                }
                Some(Op::Write { bytes, .. }) => {
                    self.phase = CdrBundleState::WriteRecv;
                    PollStep::Publish(DataPlan {
                        direction: Direction::FromHost,
                        bytes: u64::from(bytes),
                    })
                }
                Some(Op::TestWrite { bytes }) => {
                    self.phase = CdrBundleState::WriteRecv;
                    PollStep::Publish(DataPlan {
                        direction: Direction::FromHost,
                        bytes: u64::from(bytes),
                    })
                }
                Some(Op::Sync) => {
                    self.phase = CdrBundleState::SyncIo;
                    PollStep::Publish(DataPlan {
                        direction: Direction::None,
                        bytes: 0,
                    })
                }
                Some(Op::SaveToc) => {
                    self.phase = CdrBundleState::SaveIo;
                    PollStep::Publish(DataPlan {
                        direction: Direction::None,
                        bytes: 0,
                    })
                }
                None => PollStep::Idle,
            },
            (CdrBundleState::ReadIo, FeedbackKind::PlanAccepted) => self.next_read_step(data),
            (CdrBundleState::ReadIo, FeedbackKind::IoDone) => {
                let chunk = self.chunk_len;
                let Some(receipt) = fb.io() else {
                    return self.finish(Completion::Check(INTERNAL_FAILURE));
                };
                if let Some(fault) = receipt.error() {
                    return self.storage_sense(fault, IoContext::Read);
                }
                if receipt.confirmed() < chunk {
                    return self.finish(Completion::Check(MEDIUM_ERROR));
                }
                self.phase = CdrBundleState::Deliver;
                self.send_staged_with_prefetch(data, alt)
            }
            (CdrBundleState::Deliver, FeedbackKind::HostSentWithIo) => {
                let chunk = self.chunk_len;
                let (accepted, failed) = match fb.host() {
                    Some(receipt) => (receipt.accepted().min(chunk), receipt.error().is_some()),
                    None => (0, true),
                };
                if failed || accepted < chunk {
                    return self.finish(Completion::Check(COMMAND_ABORTED));
                }
                let Some(io) = fb.io() else {
                    return self.finish(Completion::Check(INTERNAL_FAILURE));
                };
                self.progress = self.progress.saturating_add(chunk as u32);
                if io.error().is_some() || io.confirmed() != self.next_len {
                    // The speculative segment is optional: re-read the range
                    // as a required read; the command outcome is unchanged.
                    return self.next_read_step(data);
                }
                if (self.progress as usize) < total {
                    self.chunk_in_alt = self.next_in_alt;
                    self.chunk_len = self.next_len;
                    self.phase = CdrBundleState::Deliver;
                    return self.send_staged_with_prefetch(data, alt);
                }
                self.finish(Completion::Good)
            }
            (CdrBundleState::Deliver, FeedbackKind::HostSent) => {
                let chunk = self.chunk_len;
                let (accepted, failed) = match fb.host() {
                    Some(receipt) => (receipt.accepted().min(chunk), receipt.error().is_some()),
                    None => (0, true),
                };
                if failed || accepted < chunk {
                    return self.finish(Completion::Check(COMMAND_ABORTED));
                }
                self.progress = self.progress.saturating_add(chunk as u32);
                if (self.progress as usize) < total {
                    self.next_read_step(data)
                } else {
                    self.finish(Completion::Good)
                }
            }
            (CdrBundleState::WriteRecv, FeedbackKind::PlanAccepted) => {
                let chunk = self.write_chunk(data.len());
                if total > 0 && chunk == 0 {
                    // A bank that cannot stage one block is the target's own
                    // inability to stage the transfer, not a bad CDB.
                    return self.finish(Completion::Check(INTERNAL_FAILURE));
                }
                self.chunk_len = chunk;
                PollStep::Receive {
                    buf: &mut data[..chunk],
                    write: None,
                }
            }
            (CdrBundleState::WriteRecv, FeedbackKind::HostReceived) => {
                let chunk = self.chunk_len;
                let (accepted, failed) = match fb.host() {
                    Some(receipt) => (receipt.accepted().min(chunk), receipt.error().is_some()),
                    None => (0, true),
                };
                if failed || accepted < chunk {
                    // A short Data-Out is not a partial write.
                    return self.finish(Completion::Check(COMMAND_ABORTED));
                }
                if matches!(self.op, Some(Op::TestWrite { .. })) {
                    // A simulated write consumes the host's data but never
                    // reaches the backing or the track tables.
                    self.progress = self.progress.saturating_add(chunk as u32);
                    if (self.progress as usize) < total {
                        let next = self.write_chunk(data.len());
                        if next == 0 {
                            return self.finish(Completion::Check(INTERNAL_FAILURE));
                        }
                        self.chunk_len = next;
                        return PollStep::Receive {
                            buf: &mut data[..next],
                            write: None,
                        };
                    }
                    return self.finish(Completion::Good);
                }
                let Some(Op::Write { track, offset, .. }) = self.op else {
                    return self.finish(Completion::Check(INTERNAL_FAILURE));
                };
                let at = offset.saturating_add(u64::from(self.progress));
                self.phase = CdrBundleState::WriteIo;
                PollStep::Io(StorageOp::Write {
                    resource: track_resource(track),
                    offset: at,
                    buf: &mut data[..accepted],
                })
            }
            (CdrBundleState::WriteIo, FeedbackKind::IoDone) => {
                let chunk = self.chunk_len;
                let Some(receipt) = fb.io() else {
                    return self.finish(Completion::Check(INTERNAL_FAILURE));
                };
                let confirmed = receipt.confirmed().min(chunk);
                let Some(Op::Write { sector_len, .. }) = self.op else {
                    return self.finish(Completion::Check(INTERNAL_FAILURE));
                };
                let block_bytes = u64::from(sector_len);
                let before = u64::from(self.progress) / block_bytes;
                self.progress = self.progress.saturating_add(confirmed as u32);
                let after = u64::from(self.progress) / block_bytes;
                self.confirm_write(after.saturating_sub(before));
                if let Some(fault) = receipt.error() {
                    return self.storage_sense(fault, IoContext::Write);
                }
                if confirmed < chunk || receipt.effect() != Effect::Known {
                    return self.finish(Completion::Check(MEDIUM_ERROR));
                }
                if (self.progress as usize) < total {
                    self.phase = CdrBundleState::WriteRecv;
                    let next = self.write_chunk(data.len());
                    if next == 0 {
                        return self.finish(Completion::Check(INTERNAL_FAILURE));
                    }
                    self.chunk_len = next;
                    PollStep::Receive {
                        buf: &mut data[..next],
                        write: None,
                    }
                } else {
                    self.finish(Completion::Good)
                }
            }
            (CdrBundleState::SyncIo, FeedbackKind::PlanAccepted) => {
                self.phase = CdrBundleState::SyncWait;
                PollStep::Io(StorageOp::Sync { resource: 0 })
            }
            (CdrBundleState::SyncWait, FeedbackKind::IoDone) => {
                let Some(receipt) = fb.io() else {
                    return self.finish(Completion::Check(INTERNAL_FAILURE));
                };
                if let Some(fault) = receipt.error() {
                    return self.storage_sense(fault, IoContext::Sync);
                }
                if receipt.effect() != Effect::Known {
                    return self.finish(Completion::Check(MEDIUM_ERROR));
                }
                self.finish(Completion::Good)
            }
            (CdrBundleState::SaveIo, FeedbackKind::PlanAccepted) => self.save_next(data),
            (CdrBundleState::SaveWait, FeedbackKind::IoDone) => self.save_done(fb, data),
            _ => PollStep::Idle,
        }
    }

    fn active(&self) -> bool {
        self.op.is_some()
    }

    fn interrupt(&mut self, _reason: InterruptReason, known: KnownEffects) {
        if let Some(Op::Write {
            track, sector_len, ..
        }) = self.op
        {
            // A write receipt the runner already observed may not have reached
            // the medium. Book its confirmed whole blocks before dropping the
            // operation state.
            let remaining = (self.total_bytes() as u64).saturating_sub(u64::from(self.progress));
            let confirmed = known.confirmed_write.min(remaining) as u32;
            let block_bytes = u64::from(sector_len);
            let before = u64::from(self.progress) / block_bytes;
            let after = u64::from(self.progress.saturating_add(confirmed)) / block_bytes;
            self.confirm_write(after.saturating_sub(before));

            if self.implicit_created
                && self
                    .track_entry(track)
                    .is_some_and(|entry| entry.written == 0)
            {
                self.drop_implicit_track(track);
            }
        }
        if let Some(save) = self.save {
            if let Some(rollback) = save.rollback {
                self.rollback_reserve(rollback);
            }
        }
        self.reset();
    }

    fn commit(&mut self) -> Result<(), Completion> {
        Ok(())
    }

    fn set_test_write(&mut self, on: bool) {
        self.test_write = on;
    }

    fn set_multi_session(&mut self, open: bool) {
        self.multi_session = open;
    }

    fn track(&self, number: u16) -> Option<Track> {
        let track = self.track_entry(number)?;
        Some(Track {
            number: track.number,
            session: track.session,
            // The TOC reports the first block carrying user information, not
            // the physical pre-gap start.
            start_lba: track.data_start_lba,
            blocks: track.length,
            kind: track.kind,
        })
    }

    fn session(&self, number: u16) -> Option<Session> {
        let session = self
            .sessions
            .iter()
            .find(|session| session.number == number)?;
        Some(Session {
            number: session.number,
            first_track: session.first_track,
            last_track: session.last_track,
            start_lba: session.start_lba,
        })
    }

    fn track_info(&self, request: TrackInfoRequest) -> Option<TrackInfo> {
        match request {
            TrackInfoRequest::Number(0) => Some(lead_in_info(self.medium_leadin)),
            TrackInfoRequest::Number(0xFF) => {
                (self.disc != CdrDiscState::Finalized).then(|| self.invisible_info())
            }
            TrackInfoRequest::Number(number) => {
                if usize::from(number) == self.tracks.len() + 1 {
                    (self.disc != CdrDiscState::Finalized).then(|| self.invisible_info())
                } else {
                    self.track_entry(number)
                        .map(|track| recorded_info(track, self.capacity))
                }
            }
            TrackInfoRequest::Lba(lba) => {
                if let Some(track) = self.tracks.iter().find(|track| {
                    let extent = track
                        .data_start_lba
                        .saturating_add(track.length.max(track.allocated));
                    (track.start_lba..extent).contains(&lba)
                }) {
                    Some(recorded_info(track, self.capacity))
                } else if self.disc != CdrDiscState::Finalized && lba < self.capacity {
                    Some(self.invisible_info())
                } else {
                    None
                }
            }
            TrackInfoRequest::Session(number) => {
                let session = self
                    .sessions
                    .iter()
                    .find(|session| session.number == number)?;
                self.track_entry(session.first_track)
                    .map(|track| recorded_info(track, self.capacity))
            }
        }
    }

    fn disc_info(&self) -> DiscInfo {
        let last_session = self.sessions.last();
        let sessions = match self.disc {
            CdrDiscState::Blank => 1,
            CdrDiscState::Appendable => {
                // MMC-6 6.21.3.1.7: complete sessions plus the
                // incomplete/empty session, if one is open.
                let closed = self
                    .sessions
                    .iter()
                    .filter(|session| session.closed)
                    .count() as u16;
                match last_session {
                    Some(session) if !session.closed => closed.saturating_add(1),
                    _ => closed,
                }
            }
            CdrDiscState::Finalized => self.sessions.len().max(1) as u16,
        };
        let last_session_lba = if self.disc == CdrDiscState::Blank {
            0
        } else {
            last_session
                .map(|session| session.lead_out_lba.saturating_sub(1))
                .unwrap_or(0)
        };
        // The last session is complete only when it has been closed. A
        // multi-session disc keeps `Appendable` with a closed last session.
        let last_session_complete = match self.disc {
            CdrDiscState::Blank => false,
            CdrDiscState::Appendable => last_session.is_some_and(|session| session.closed),
            CdrDiscState::Finalized => true,
        };
        DiscInfo {
            status: match self.disc {
                CdrDiscState::Blank => DiscStatus::Empty,
                CdrDiscState::Appendable => DiscStatus::Incomplete,
                CdrDiscState::Finalized => DiscStatus::Finalized,
            },
            sessions,
            last_session_lba,
            writable: false,
            erasable: self.kind == DiscKind::Cdrw,
            first_track: 1,
            first_track_last_session: last_session.map_or(1, |session| session.first_track),
            last_track_last_session: last_session.map_or(1, |session| session.last_track),
            last_session_state: match self.disc {
                CdrDiscState::Blank => 0,
                CdrDiscState::Appendable if last_session_complete => 3,
                CdrDiscState::Appendable => 1,
                CdrDiscState::Finalized => 3,
            },
            last_session_lead_in: match self.disc {
                // A blank disc reports its own lead-in. While appendable the
                // field is where the next lead-in begins: the lead-out of the
                // last *closed* session (never the moving NWA of an open one),
                // or the disc lead-in when no session is complete yet.
                CdrDiscState::Blank => Some(self.medium_leadin),
                CdrDiscState::Appendable => {
                    match self.sessions.iter().rev().find(|session| session.closed) {
                        Some(session) => Some(signed_lba(session.lead_out_lba)),
                        None => Some(self.medium_leadin),
                    }
                }
                CdrDiscState::Finalized => None,
            },
            last_possible_lead_out: match self.disc {
                CdrDiscState::Finalized => None,
                // The ATIP lead-out and the addressable extent agree: the
                // media geometry is authoritative before the final lead-out is
                // recorded, and DISC INFORMATION must not disagree with READ
                // TOC format 4.
                CdrDiscState::Blank | CdrDiscState::Appendable => Some(signed_lba(self.capacity)),
            },
            disc_type: 0xFF,
        }
    }

    fn atip(&self) -> Option<AtipInfo> {
        Some(AtipInfo {
            lead_in: atip_time_code(self.medium_leadin),
            lead_out: atip_address(self.capacity),
            writing_power: 5,
            reference_speed: 0,
            unrestricted: true,
            disc_type: match self.kind {
                DiscKind::Cdr => 0,
                DiscKind::Cdrw => 1,
            },
            disc_sub_type: 0,
            a1: None,
            a2: None,
            a3: None,
        })
    }

    /// A CD-RW has BLANK semantics; a CD-R does not.
    fn blank_supported(&self) -> bool {
        self.kind == DiscKind::Cdrw
    }
}

/// The lead-in pseudo-track (`READ TRACK INFORMATION` number 0).
fn lead_in_info(medium_leadin: i64) -> TrackInfo {
    TrackInfo {
        number: 0,
        session: 0,
        start_lba: medium_leadin,
        length: 0,
        allocated: 0,
        nwa: 0,
        free_blocks: 0,
        status: TrackStatus::Complete,
        kind: TrackKind::Data,
        packet: false,
    }
}

/// Offset of the ATIP time base: a disc address becomes a lead-in time code by
/// adding the usual `+150` frame offset and wrapping inside a 100-minute disc
/// (`100 * 60 * 75`), i.e. `450150 + address`.
const ATIP_PROGRAM_ORIGIN: i64 = 450_150;

/// Split a raw ATIP frame count into binary M/S/F bytes.
///
/// The time base wraps inside a 100-minute disc (`100 * 60 * 75` frames), so
/// the minute byte is always `0..=99` and a geometry past `99:59:74` continues
/// from `00:00:00`, exactly like the ATIP frame numbering.
fn atip_msf(frames: i64) -> [u8; 3] {
    let value = frames.rem_euclid(75 * 60 * 100);
    let m = value / (75 * 60);
    let s = (value % (75 * 60)) / 75;
    let f = value % 75;
    [m as u8, s as u8, f as u8]
}

/// ATIP time code of a disc address (`450150 + address`), e.g. the lead-in.
fn atip_time_code(address: i64) -> [u8; 3] {
    atip_msf(ATIP_PROGRAM_ORIGIN.saturating_add(address))
}

/// Absolute MSF (`address + 150`) of a disc address, e.g. the lead-out.
fn atip_address(address: u64) -> [u8; 3] {
    atip_msf(signed_lba(address).saturating_add(150))
}

/// Free blocks for a CD track (MMC-6 6.26.3.16.1): `last possible lead-out -
/// NWA - 2`. The last possible lead-out is the medium capacity, so the
/// user-visible space is `capacity - nwa - 2`, clamped by the track's remaining
/// allocation.
fn cd_free_blocks(capacity: u64, nwa: u64, allocation: Option<u64>) -> u64 {
    let available = capacity.saturating_sub(nwa).saturating_sub(2);
    match allocation {
        Some(remaining) => available.min(remaining),
        None => available,
    }
}

/// Project a recorded track into the track-information view.
fn recorded_info(track: &TrackEntry, capacity: u64) -> TrackInfo {
    let consumed = track.nwa.saturating_sub(track.data_start_lba);
    let free_blocks = match track.status {
        TrackStatus::Complete => 0,
        TrackStatus::Invisible => cd_free_blocks(
            capacity,
            track.nwa,
            Some(track.allocated.saturating_sub(consumed)),
        ),
        TrackStatus::Reserved => cd_free_blocks(
            capacity,
            track.nwa,
            Some(track.allocated.saturating_sub(consumed)),
        ),
        TrackStatus::Incomplete if track.reserved => cd_free_blocks(
            capacity,
            track.nwa,
            Some(track.allocated.saturating_sub(consumed)),
        ),
        TrackStatus::Incomplete => cd_free_blocks(capacity, track.nwa, None),
    };
    TrackInfo {
        number: track.number,
        session: track.session,
        start_lba: signed_lba(track.data_start_lba),
        length: track.length,
        allocated: track.allocated,
        nwa: track.nwa,
        free_blocks,
        status: track.status,
        kind: track.kind,
        packet: false,
    }
}

/// Clamp a non-negative LBA into the signed track-information field.
const fn signed_lba(lba: u64) -> i64 {
    if lba > i64::MAX as u64 {
        i64::MAX
    } else {
        lba as i64
    }
}

impl CdrBundleMedium {
    /// Project the not-yet-recorded track after the last recorded one.
    fn invisible_info(&self) -> TrackInfo {
        let number = self.tracks.len() as u16 + 1;
        let (_, _, data_start_lba) = self.next_positions();
        let allocated = self.capacity.saturating_sub(data_start_lba);
        let nwa = self.current_nwa();
        TrackInfo {
            number,
            session: self.sessions.len() as u16 + 1,
            start_lba: signed_lba(data_start_lba),
            length: 0,
            allocated,
            nwa,
            free_blocks: cd_free_blocks(self.capacity, nwa, Some(allocated)),
            status: TrackStatus::Invisible,
            kind: TrackKind::Data,
            packet: false,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::core::storage::{HostReceipt, IoReceipt};
    use crate::core::{KnownEffects, WRITE_ERROR};

    /// Minimal recording storage: remembers every operation and fills reads
    /// with a deterministic pattern.
    #[derive(Default)]
    struct Mock {
        reads: std::vec::Vec<(u16, u64, usize)>,
        writes: std::vec::Vec<(u16, u64, usize)>,
        syncs: std::vec::Vec<u16>,
    }

    impl Mock {
        fn read_into(&mut self, resource: u16, offset: u64, buf: &mut [u8]) {
            self.reads.push((resource, offset, buf.len()));
            for (index, byte) in buf.iter_mut().enumerate() {
                *byte = (offset as usize + index) as u8;
            }
        }

        fn write_from(&mut self, resource: u16, offset: u64, buf: &[u8]) {
            self.writes.push((resource, offset, buf.len()));
        }

        fn sync(&mut self, resource: u16) {
            self.syncs.push(resource);
        }
    }

    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    enum StoreEv {
        Write(u16, u64, usize),
        Sync(u16),
    }

    /// Byte-plane backing used by the TOC tests: resources are independent
    /// byte vectors, so a TOC write can never clobber track payload.
    #[derive(Default)]
    struct StoreMock {
        mem: std::collections::HashMap<u16, std::vec::Vec<u8>>,
        writes: std::vec::Vec<(u16, u64, usize)>,
        syncs: std::vec::Vec<u16>,
        events: std::vec::Vec<StoreEv>,
        fail_write: bool,
        fail_toc_header: bool,
        fail_sync: bool,
        fail_sync_resource: Option<u16>,
    }

    impl StoreMock {
        fn slot(&self, slot: u8) -> std::vec::Vec<u8> {
            self.mem
                .get(&toc_resource(slot))
                .cloned()
                .unwrap_or_default()
        }
    }

    impl Backing for StoreMock {
        fn read_into(&mut self, resource: u16, offset: u64, buf: &mut [u8]) {
            let src = self
                .mem
                .get(&resource)
                .map_or(&[][..], |bytes| bytes.as_slice());
            for (index, byte) in buf.iter_mut().enumerate() {
                *byte = src.get(offset as usize + index).copied().unwrap_or(0);
            }
        }

        fn write_from(&mut self, resource: u16, offset: u64, buf: &[u8]) {
            self.writes.push((resource, offset, buf.len()));
            self.events
                .push(StoreEv::Write(resource, offset, buf.len()));
            let bytes = self.mem.entry(resource).or_default();
            let end = offset as usize + buf.len();
            if bytes.len() < end {
                bytes.resize(end, 0);
            }
            bytes[offset as usize..end].copy_from_slice(buf);
        }

        fn sync(&mut self, resource: u16) {
            self.syncs.push(resource);
            self.events.push(StoreEv::Sync(resource));
        }

        fn write_fails(&self, resource: u16, offset: u64) -> bool {
            self.fail_write
                || (self.fail_toc_header
                    && (resource == TOC_RESOURCE_0 || resource == TOC_RESOURCE_1)
                    && offset == 0)
        }

        fn sync_fails(&self, resource: u16) -> bool {
            self.fail_sync || self.fail_sync_resource == Some(resource)
        }
    }

    /// Storage operations used by the medium test helpers.
    trait Backing {
        fn read_into(&mut self, resource: u16, offset: u64, buf: &mut [u8]);
        fn write_from(&mut self, resource: u16, offset: u64, buf: &[u8]);
        fn sync(&mut self, resource: u16);
        fn write_fails(&self, resource: u16, offset: u64) -> bool;
        fn sync_fails(&self, resource: u16) -> bool;
    }

    impl Backing for Mock {
        fn read_into(&mut self, resource: u16, offset: u64, buf: &mut [u8]) {
            Mock::read_into(self, resource, offset, buf);
        }

        fn write_from(&mut self, resource: u16, offset: u64, buf: &[u8]) {
            Mock::write_from(self, resource, offset, buf);
        }

        fn sync(&mut self, resource: u16) {
            Mock::sync(self, resource);
        }

        fn write_fails(&self, _resource: u16, _offset: u64) -> bool {
            false
        }

        fn sync_fails(&self, _resource: u16) -> bool {
            false
        }
    }

    fn run_read<B: Backing>(
        medium: &mut CdrBundleMedium,
        mock: &mut B,
        lba: u64,
        blocks: u16,
        bank: usize,
    ) -> (std::vec::Vec<u8>, Completion) {
        let mut data = std::vec![0u8; bank];
        assert_eq!(medium.begin(MmcOp::Read { lba, blocks }), Ok(()));
        let mut feedback = Feedback::begin();
        let mut collected = std::vec::Vec::new();
        loop {
            match medium.poll(feedback, &mut data) {
                PollStep::Publish(plan) => {
                    assert_eq!(plan.direction, Direction::ToHost);
                    assert_eq!(plan.bytes, u64::from(blocks) * 2048);
                    feedback = Feedback::plan_accepted();
                }
                PollStep::Io(StorageOp::Read {
                    resource,
                    offset,
                    buf,
                }) => {
                    let len = buf.len();
                    mock.read_into(resource, offset, buf);
                    feedback = Feedback::io_done(IoReceipt::test(len, None, Effect::Known));
                }
                PollStep::Send { bytes, prefetch } => {
                    assert!(prefetch.is_none());
                    collected.extend_from_slice(bytes);
                    let len = bytes.len();
                    feedback = Feedback::host_sent(HostReceipt::test(len, None));
                }
                PollStep::Complete(completion) => return (collected, completion),
                other => panic!("unexpected read step: {other:?}"),
            }
        }
    }

    /// Drive a read with a second caller bank, honouring the prefetch the
    /// medium attaches to a send. Returns the delivered bytes, the completion
    /// and the number of companions actually issued.
    #[allow(clippy::too_many_arguments)]
    fn run_read_alt<B: Backing>(
        medium: &mut CdrBundleMedium,
        mock: &mut B,
        op: MmcOp,
        total: usize,
        bank: usize,
    ) -> (std::vec::Vec<u8>, Completion, usize) {
        let mut data = std::vec![0u8; bank];
        let mut alt = std::vec![0u8; bank];
        assert_eq!(medium.begin(op), Ok(()));
        let mut feedback = Feedback::begin();
        let mut collected = std::vec::Vec::new();
        let mut companions = 0;
        loop {
            match medium.poll_with_alt(feedback, &mut data, &mut alt) {
                PollStep::Publish(plan) => {
                    assert_eq!(plan.direction, Direction::ToHost);
                    assert_eq!(plan.bytes, total as u64);
                    feedback = Feedback::plan_accepted();
                }
                PollStep::Io(StorageOp::Read {
                    resource,
                    offset,
                    buf,
                }) => {
                    let len = buf.len();
                    mock.read_into(resource, offset, buf);
                    feedback = Feedback::io_done(IoReceipt::test(len, None, Effect::Known));
                }
                PollStep::Send { bytes, prefetch } => {
                    let len = bytes.len();
                    collected.extend_from_slice(bytes);
                    match prefetch {
                        Some(crate::core::storage::PrefetchOp::Read {
                            resource,
                            offset,
                            buf,
                        }) => {
                            let prefetch_len = buf.len();
                            mock.read_into(resource, offset, buf);
                            companions += 1;
                            feedback = Feedback::host_sent_with_io(
                                HostReceipt::test(len, None),
                                IoReceipt::test(prefetch_len, None, Effect::Known),
                            );
                        }
                        None => feedback = Feedback::host_sent(HostReceipt::test(len, None)),
                    }
                }
                PollStep::Complete(completion) => return (collected, completion, companions),
                other => panic!("unexpected read step: {other:?}"),
            }
        }
    }

    fn run_write<B: Backing>(
        medium: &mut CdrBundleMedium,
        mock: &mut B,
        lba: u64,
        blocks: u16,
        payload: &[u8],
        bank: usize,
    ) -> Completion {
        run_write_kind(
            medium,
            mock,
            lba,
            blocks,
            payload,
            bank,
            SectorKind::Data2048,
        )
    }

    /// Run a `WRITE SECTORS` operation with an explicit sector kind.
    #[allow(clippy::too_many_arguments)]
    fn run_write_kind<B: Backing>(
        medium: &mut CdrBundleMedium,
        mock: &mut B,
        lba: u64,
        blocks: u16,
        payload: &[u8],
        bank: usize,
        kind: SectorKind,
    ) -> Completion {
        let mut data = std::vec![0u8; bank];
        assert_eq!(
            medium.begin(MmcOp::WriteSectors { lba, blocks, kind }),
            Ok(())
        );
        let mut feedback = Feedback::begin();
        let mut received = 0usize;
        loop {
            match medium.poll(feedback, &mut data) {
                PollStep::Publish(plan) => {
                    assert_eq!(plan.direction, Direction::FromHost);
                    assert_eq!(plan.bytes, payload.len() as u64);
                    feedback = Feedback::plan_accepted();
                }
                PollStep::Receive { buf, write } => {
                    assert!(write.is_none());
                    let len = buf.len();
                    buf.copy_from_slice(&payload[received..received + len]);
                    received += len;
                    feedback = Feedback::host_received(HostReceipt::test(len, None));
                }
                PollStep::Io(StorageOp::Write {
                    resource,
                    offset,
                    buf,
                }) => {
                    if mock.write_fails(resource, offset) {
                        feedback = Feedback::io_done(IoReceipt::test(
                            0,
                            Some(Fault::Io),
                            Effect::UnknownRemainder,
                        ));
                    } else {
                        mock.write_from(resource, offset, buf);
                        feedback =
                            Feedback::io_done(IoReceipt::test(buf.len(), None, Effect::Known));
                    }
                }
                PollStep::Complete(completion) => {
                    assert_eq!(received, payload.len(), "every host byte was received");
                    return completion;
                }
                other => panic!("unexpected write step: {other:?}"),
            }
        }
    }

    /// Run a `READ SECTORS` operation with an explicit sector kind.
    fn run_read_kind<B: Backing>(
        medium: &mut CdrBundleMedium,
        mock: &mut B,
        lba: u64,
        blocks: u16,
        kind: SectorKind,
        bank: usize,
    ) -> (std::vec::Vec<u8>, Completion) {
        let mut data = std::vec![0u8; bank];
        assert_eq!(
            medium.begin(MmcOp::ReadSectors { lba, blocks, kind }),
            Ok(())
        );
        let mut feedback = Feedback::begin();
        let mut collected = std::vec::Vec::new();
        loop {
            match medium.poll(feedback, &mut data) {
                PollStep::Publish(plan) => {
                    assert_eq!(plan.direction, Direction::ToHost);
                    feedback = Feedback::plan_accepted();
                }
                PollStep::Io(StorageOp::Read {
                    resource,
                    offset,
                    buf,
                }) => {
                    let len = buf.len();
                    mock.read_into(resource, offset, buf);
                    feedback = Feedback::io_done(IoReceipt::test(len, None, Effect::Known));
                }
                PollStep::Send { bytes, prefetch } => {
                    assert!(prefetch.is_none());
                    collected.extend_from_slice(bytes);
                    let len = bytes.len();
                    feedback = Feedback::host_sent(HostReceipt::test(len, None));
                }
                PollStep::Complete(completion) => return (collected, completion),
                other => panic!("unexpected read step: {other:?}"),
            }
        }
    }

    /// Run a no-data control operation, including its persistent TOC save.
    fn run_control<B: Backing>(
        medium: &mut CdrBundleMedium,
        mock: &mut B,
        op: MmcOp,
        bank: usize,
    ) -> Completion {
        let mut data = std::vec![0u8; bank];
        match medium.begin(op) {
            Ok(()) => {}
            Err(completion) => return completion,
        }
        let mut feedback = Feedback::begin();
        loop {
            match medium.poll(feedback, &mut data) {
                PollStep::Publish(plan) => {
                    assert_eq!(
                        plan,
                        DataPlan {
                            direction: Direction::None,
                            bytes: 0,
                        }
                    );
                    feedback = Feedback::plan_accepted();
                }
                PollStep::Io(StorageOp::Sync { resource }) => {
                    if mock.sync_fails(resource) {
                        feedback =
                            Feedback::io_done(IoReceipt::test(0, Some(Fault::Io), Effect::Known));
                    } else {
                        mock.sync(resource);
                        feedback = Feedback::io_done(IoReceipt::test(0, None, Effect::Known));
                    }
                }
                PollStep::Io(StorageOp::Write {
                    resource,
                    offset,
                    buf,
                }) => {
                    if mock.write_fails(resource, offset) {
                        feedback = Feedback::io_done(IoReceipt::test(
                            0,
                            Some(Fault::Io),
                            Effect::UnknownRemainder,
                        ));
                    } else {
                        mock.write_from(resource, offset, buf);
                        feedback =
                            Feedback::io_done(IoReceipt::test(buf.len(), None, Effect::Known));
                    }
                }
                PollStep::Complete(completion) => return completion,
                other => panic!("unexpected control step: {other:?}"),
            }
        }
    }

    fn run_commit<B: Backing>(medium: &mut CdrBundleMedium, mock: &mut B) -> Completion {
        run_control(medium, mock, MmcOp::Commit, 4096)
    }

    fn close_track<B: Backing>(
        medium: &mut CdrBundleMedium,
        mock: &mut B,
        function: u8,
    ) -> Completion {
        run_control(medium, mock, MmcOp::Close { function }, 4096)
    }

    fn reserve_medium<B: Backing>(
        medium: &mut CdrBundleMedium,
        mock: &mut B,
        size: u32,
    ) -> Completion {
        run_control(medium, mock, MmcOp::ReserveTrack { size }, 4096)
    }

    fn write_one<B: Backing>(medium: &mut CdrBundleMedium, mock: &mut B, lba: u64) {
        let payload = std::vec![0x5Au8; 2048];
        assert_eq!(
            run_write(medium, mock, lba, 1, &payload, 2048),
            Completion::Good
        );
    }

    #[test]
    fn capacities_are_lead_out_addresses() {
        assert_eq!(CdrCapacity::Cdr74.sectors(), 332_849);
        assert_eq!(CdrCapacity::Cdr80.sectors(), 359_849);
        assert_eq!(CdrCapacity::Cdr90.sectors(), 404_849);
        assert_eq!(CdrCapacity::Cdr99.sectors(), 445_349);
        let medium = CdrBundleMedium::blank(CdrCapacity::Cdr80);
        assert_eq!(medium.capacity_sectors(), 359_849);
        assert_eq!(medium.medium_leadin(), -11_077);
        assert_eq!(medium.disc_state(), CdrDiscState::Blank);
    }

    #[test]
    fn atip_describes_the_media_in_every_disc_state() {
        let mut medium = CdrBundleMedium::blank(CdrCapacity::Cdr80);
        let mut mock = Mock::default();
        // The ATIP time base starts 450 150 frames before the program area, so
        // -11 077 is 439 073 = 97:34:23; an 80-minute lead-out is 359 849 +
        // 150 = 359 999 = 79:59:74. Both are plain binary M/S/F bytes.
        let check = |atip: AtipInfo| {
            assert_eq!(atip.lead_in, [97, 34, 23]);
            assert_eq!(atip.lead_out, [79, 59, 74]);
            assert_eq!(atip.writing_power, 5);
            assert_eq!(atip.reference_speed, 0);
            assert!(atip.unrestricted, "general-purpose media");
            assert_eq!(atip.disc_type, 0, "CD-R");
            assert_eq!(atip.disc_sub_type, 0);
            assert_eq!(atip.a1, None);
            assert_eq!(atip.a2, None);
            assert_eq!(atip.a3, None);
        };

        // The pre-groove is written before any data, so all disc states
        // describe the same media.
        check(medium.atip().expect("blank ATIP"));
        write_one(&mut medium, &mut mock, 0);
        assert_eq!(medium.disc_state(), CdrDiscState::Appendable);
        check(medium.atip().expect("appendable ATIP"));
        assert_eq!(close_track(&mut medium, &mut mock, 1), Completion::Good);
        assert_eq!(close_track(&mut medium, &mut mock, 2), Completion::Good);
        assert_eq!(medium.disc_state(), CdrDiscState::Finalized);
        check(medium.atip().expect("finalized ATIP"));
    }

    #[test]
    fn atip_lead_out_follows_the_preset_geometry() {
        // `sectors + 150` split into binary M/S/F: the 90- and 99-minute
        // presets are above MMC's recommended lead-out, like real
        // high-capacity media.
        for (capacity, lead_out) in [
            (CdrCapacity::Cdr74, [73, 59, 74]),
            (CdrCapacity::Cdr80, [79, 59, 74]),
            (CdrCapacity::Cdr90, [89, 59, 74]),
            (CdrCapacity::Cdr99, [98, 59, 74]),
        ] {
            let medium = CdrBundleMedium::blank(capacity);
            let atip = medium.atip().expect("ATIP");
            assert_eq!(atip.lead_out, lead_out, "{capacity:?}");
            assert_eq!(atip.lead_in, [97, 34, 23], "{capacity:?}");
        }
    }

    #[test]
    fn atip_wraps_past_a_100_minute_disc() {
        // The ATIP time base wraps at 100 minutes (450 000 frames), so a
        // capacity past 99:59:74 continues from 00:00:00 instead of saturating.
        let medium = CdrBundleMedium::with_capacity(450_000);
        assert_eq!(medium.atip().expect("ATIP").lead_out, [0, 2, 0]);
        assert_eq!(medium.disc_info().last_possible_lead_out, Some(450_000));
    }

    #[test]
    fn restored_medium_reports_the_same_atip_as_a_fresh_one() {
        // A TOC slot only stores the geometry; ATIP is derived from it, so a
        // reopened disc describes the same media as a blank one.
        let mut medium = CdrBundleMedium::blank(CdrCapacity::Cdr90);
        let mut store = StoreMock::default();
        write_one(&mut medium, &mut store, 0);
        assert_eq!(close_track(&mut medium, &mut store, 1), Completion::Good);
        let slot = store.slot(0);
        let reopened = CdrBundleMedium::open_at(0, &slot, 0, Recovery::Delete)
            .expect("reopen from the saved slot");
        assert_eq!(reopened.capacity_sectors(), CdrCapacity::Cdr90.sectors());
        assert_eq!(
            reopened.atip(),
            CdrBundleMedium::blank(CdrCapacity::Cdr90).atip()
        );
    }

    #[test]
    fn disc_kind_round_trips_and_old_cdr_bodies_still_load() {
        let mut medium = CdrBundleMedium::blank_disc(DiscKind::Cdrw, CdrCapacity::Cdr80);
        assert_eq!(medium.kind(), DiscKind::Cdrw);
        let mut store = StoreMock::default();
        write_one(&mut medium, &mut store, 0);
        assert_eq!(close_track(&mut medium, &mut store, 1), Completion::Good);

        let slot = store.slot(0);
        let header = TocHeader::parse(&slot).expect("header");
        let body_end = TOC_HEADER_LEN + header.body_len as usize;
        let text = std::str::from_utf8(&slot[TOC_HEADER_LEN..body_end]).expect("body");
        assert!(text.contains("disc_type = cdrw\n"), "body:\n{text}");

        let reopened = CdrBundleMedium::open(&slot, 0, Recovery::Delete).expect("reopen");
        assert_eq!(reopened.kind(), DiscKind::Cdrw);

        // A slot written before the kind existed names the CD-R default and
        // must keep loading as a CD-R.
        let old = open_body(VALID_BODY).expect("legacy cdr body");
        assert_eq!(old.kind(), DiscKind::Cdr);

        // An unknown disc type is still rejected.
        let unknown = VALID_BODY.replace("disc_type = cdr", "disc_type = dvd");
        assert!(open_body(&unknown).is_err());
    }

    #[test]
    fn disc_kind_drives_attrs_disc_info_and_atip() {
        let cdr = CdrBundleMedium::blank(CdrCapacity::Cdr80);
        let cdrw = CdrBundleMedium::blank_disc(DiscKind::Cdrw, CdrCapacity::Cdr80);

        assert_eq!(cdr.attrs().write_mode, MmcWriteMode::WriteOnce);
        assert_eq!(cdr.attrs().profile, 0x0009);
        assert!(!cdr.attrs().write_protected);
        assert!(!cdr.disc_info().erasable);
        assert_eq!(cdr.disc_info().disc_type, 0xFF);
        assert!(!cdr.blank_supported());
        let atip = cdr.atip().expect("CD-R ATIP");
        assert_eq!(atip.disc_type, 0);
        assert_eq!(atip.disc_sub_type, 0);

        assert_eq!(cdrw.attrs().write_mode, MmcWriteMode::Rewritable);
        assert_eq!(cdrw.attrs().profile, 0x000A);
        assert!(!cdrw.attrs().write_protected);
        assert!(cdrw.disc_info().erasable);
        assert_eq!(cdrw.disc_info().disc_type, 0xFF);
        assert!(cdrw.blank_supported());
        let atip = cdrw.atip().expect("CD-RW ATIP");
        assert_eq!(atip.disc_type, 1);
        assert_eq!(atip.disc_sub_type, 0);

        // Both kinds keep the Track-at-Once current-feature set.
        for medium in [&cdr, &cdrw] {
            assert_eq!(medium.attrs().current_features, CDR_FEATURES);
            assert_eq!(medium.capacity_sectors(), CdrCapacity::Cdr80.sectors());
        }
    }

    #[test]
    fn blank_all_resets_a_finalized_cdrw_and_allows_a_new_burn() {
        let mut medium = CdrBundleMedium::blank_disc(DiscKind::Cdrw, CdrCapacity::Cdr74);
        let mut store = StoreMock::default();
        write_one(&mut medium, &mut store, 0);
        assert_eq!(close_track(&mut medium, &mut store, 1), Completion::Good);
        assert_eq!(close_track(&mut medium, &mut store, 2), Completion::Good);
        assert_eq!(medium.disc_state(), CdrDiscState::Finalized);
        assert!(medium.attrs().write_protected);
        assert_eq!(
            medium.begin(MmcOp::Write { lba: 0, blocks: 1 }),
            Err(Completion::Check(WRITE_PROTECTED))
        );

        store.writes.clear();
        store.syncs.clear();
        assert_eq!(
            run_control(
                &mut medium,
                &mut store,
                MmcOp::Blank {
                    blanking: 0,
                    immediate: false,
                },
                4096,
            ),
            Completion::Good
        );
        assert_eq!(medium.disc_state(), CdrDiscState::Blank);
        assert_eq!(medium.attrs().tracks, 0);
        assert_eq!(medium.attrs().sessions, 0);
        assert!(!medium.attrs().write_protected);
        assert_eq!(medium.capacity_sectors(), CdrCapacity::Cdr74.sectors());
        assert_eq!(medium.kind(), DiscKind::Cdrw);
        // BLANK only writes/syncs a TOC slot, never a track resource.
        assert!(store
            .writes
            .iter()
            .all(|(resource, _, _)| matches!(*resource, TOC_RESOURCE_0 | TOC_RESOURCE_1)));
        assert!(store
            .syncs
            .iter()
            .all(|resource| matches!(*resource, TOC_RESOURCE_0 | TOC_RESOURCE_1)));

        let saved = store.slot(medium.current_slot());
        let reopened = CdrBundleMedium::open_at(medium.current_slot(), &saved, 0, Recovery::Delete)
            .expect("blanked TOC");
        assert_eq!(reopened.disc_state(), CdrDiscState::Blank);
        assert_eq!(reopened.kind(), DiscKind::Cdrw);
        assert_eq!(reopened.disc_info().status, DiscStatus::Empty);

        // The erased disc is writable again and finalizes like a fresh one.
        let mut next = reopened;
        let mut store = StoreMock::default();
        write_one(&mut next, &mut store, 0);
        assert_eq!(close_track(&mut next, &mut store, 1), Completion::Good);
        assert_eq!(close_track(&mut next, &mut store, 2), Completion::Good);
        assert_eq!(next.disc_state(), CdrDiscState::Finalized);
    }

    #[test]
    fn minimal_blank_is_accepted_and_other_blanks_are_rejected() {
        let mut medium = CdrBundleMedium::blank_disc(DiscKind::Cdrw, CdrCapacity::Cdr80);
        let mut store = StoreMock::default();
        write_one(&mut medium, &mut store, 0);
        assert_eq!(
            run_control(
                &mut medium,
                &mut store,
                MmcOp::Blank {
                    blanking: 1,
                    immediate: true,
                },
                4096,
            ),
            Completion::Good
        );
        assert_eq!(medium.disc_state(), CdrDiscState::Blank);

        // Only all/minimal blank are defined for a CD-RW.
        assert_eq!(
            medium.begin(MmcOp::Blank {
                blanking: 2,
                immediate: false,
            }),
            Err(Completion::Check(INVALID_FIELD))
        );

        // A write-once CD-R has no blank state.
        let mut cdr = CdrBundleMedium::blank(CdrCapacity::Cdr80);
        assert_eq!(
            cdr.begin(MmcOp::Blank {
                blanking: 0,
                immediate: false,
            }),
            Err(Completion::Check(INVALID_FIELD))
        );
    }

    #[test]
    fn blank_on_a_read_only_recovery_is_write_protected() {
        let body = VALID_BODY.replace("disc_type = cdr", "disc_type = cdrw");
        let mut frozen =
            CdrBundleMedium::open(&slot_from_body(&body), 0, Recovery::ReadOnly).expect("frozen");
        assert_eq!(frozen.kind(), DiscKind::Cdrw);
        assert_eq!(
            frozen.begin(MmcOp::Blank {
                blanking: 0,
                immediate: false,
            }),
            Err(Completion::Check(WRITE_PROTECTED))
        );
    }

    #[test]
    fn blank_attrs_disc_info_and_track_info() {
        let medium = CdrBundleMedium::blank(CdrCapacity::Cdr74);
        let attrs = medium.attrs();
        assert_eq!(attrs.write_mode, MmcWriteMode::WriteOnce);
        assert_eq!(attrs.block_len, 2048);
        assert_eq!(attrs.sectors, 332_849);
        assert_eq!(attrs.tracks, 0);
        assert_eq!(attrs.sessions, 0);
        assert!(!attrs.write_protected);
        assert!(!attrs.needs_recovery);
        assert_eq!(attrs.profile, 0x0009);
        assert_eq!(
            attrs.current_features,
            &[0x0010, 0x001D, 0x001E, 0x0021, 0x002D]
        );

        let info = medium.disc_info();
        assert_eq!(info.status, DiscStatus::Empty);
        assert_eq!(info.sessions, 1);
        assert_eq!(info.first_track, 1);
        assert_eq!(info.first_track_last_session, 1);
        assert_eq!(info.last_track_last_session, 1);
        assert_eq!(info.last_session_state, 0);
        assert_eq!(info.last_session_lead_in, Some(-11_077));
        assert_eq!(info.last_possible_lead_out, Some(332_849));
        assert!(!info.erasable);
        assert_eq!(info.disc_type, 0xFF);

        let lead_in = medium
            .track_info(TrackInfoRequest::Number(0))
            .expect("lead-in");
        assert_eq!(lead_in.number, 0);
        assert_eq!(lead_in.session, 0);
        assert_eq!(lead_in.start_lba, -11_077);
        assert_eq!(lead_in.length, 0);
        assert_eq!(lead_in.nwa, 0);
        assert_eq!(lead_in.status, TrackStatus::Complete);

        let invisible = medium
            .track_info(TrackInfoRequest::Number(0xFF))
            .expect("invisible track");
        assert_eq!(invisible.number, 1);
        assert_eq!(invisible.session, 1);
        assert_eq!(invisible.start_lba, 0);
        assert_eq!(invisible.length, 0);
        assert_eq!(invisible.allocated, 332_849);
        assert_eq!(invisible.nwa, 0);
        assert_eq!(invisible.free_blocks, 332_847);
        assert_eq!(invisible.status, TrackStatus::Invisible);
        assert_eq!(
            medium.track_info(TrackInfoRequest::Number(1)),
            Some(invisible)
        );
        assert_eq!(medium.track(1), None);
        assert_eq!(medium.session(1), None);
        assert_eq!(medium.track_info(TrackInfoRequest::Number(2)), None);
    }

    #[test]
    fn first_write_without_reserve_creates_an_implicit_track() {
        let mut medium = CdrBundleMedium::blank(CdrCapacity::Cdr80);
        let mut mock = Mock::default();
        let payload: std::vec::Vec<u8> = (0..4 * 2048).map(|index| index as u8).collect();
        assert_eq!(
            run_write(&mut medium, &mut mock, 0, 2, &payload[..4096], 2048),
            Completion::Good
        );

        let attrs = medium.attrs();
        assert_eq!(attrs.tracks, 1);
        assert_eq!(attrs.sessions, 1);
        assert_eq!(medium.disc_state(), CdrDiscState::Appendable);

        let info = medium
            .track_info(TrackInfoRequest::Number(1))
            .expect("track 1");
        assert_eq!(info.number, 1);
        assert_eq!(info.session, 1);
        assert_eq!(info.start_lba, 0);
        assert_eq!(info.length, 2);
        assert_eq!(info.allocated, 0, "an implicit track has no reservation");
        assert_eq!(info.nwa, 2);
        assert_eq!(info.free_blocks, 359_845);
        assert_eq!(info.status, TrackStatus::Incomplete);

        assert_eq!(
            medium
                .track_info(TrackInfoRequest::Lba(1))
                .map(|info| info.number),
            Some(1)
        );
        assert_eq!(
            medium
                .track_info(TrackInfoRequest::Lba(0))
                .map(|info| info.number),
            Some(1)
        );

        let track = medium.track(1).expect("track 1");
        assert_eq!(track.start_lba, 0);
        assert_eq!(track.blocks, 2);

        assert_eq!(mock.writes, std::vec![(17, 0, 2048), (17, 2048, 2048)]);

        let (data, completion) = run_read(&mut medium, &mut mock, 0, 2, 2048);
        assert_eq!(completion, Completion::Good);
        assert_eq!(data.len(), 4096);
        assert_eq!(mock.reads, std::vec![(17, 0, 2048), (17, 2048, 2048)]);
    }

    #[test]
    fn write_address_errors() {
        let mut medium = CdrBundleMedium::with_capacity(8);
        let mut mock = Mock::default();
        write_one(&mut medium, &mut mock, 0);

        assert_eq!(
            medium.begin(MmcOp::Write { lba: 0, blocks: 1 }),
            Err(Completion::Check(INVALID_ADDRESS_FOR_WRITE))
        );
        assert_eq!(
            medium.begin(MmcOp::Write { lba: 8, blocks: 1 }),
            Err(Completion::Check(LBA_OUT_OF_RANGE))
        );
        assert_eq!(
            medium.begin(MmcOp::Write { lba: 9, blocks: 1 }),
            Err(Completion::Check(LBA_OUT_OF_RANGE))
        );

        assert_eq!(close_track(&mut medium, &mut mock, 1), Completion::Good);
        assert_eq!(close_track(&mut medium, &mut mock, 2), Completion::Good);
        assert!(medium.attrs().write_protected);
        assert_eq!(
            medium.begin(MmcOp::Write { lba: 1, blocks: 1 }),
            Err(Completion::Check(WRITE_PROTECTED))
        );
        assert_eq!(
            medium.begin(MmcOp::Write { lba: 0, blocks: 1 }),
            Err(Completion::Check(WRITE_PROTECTED))
        );
    }

    #[test]
    fn reserve_track_validation_and_padding() {
        let mut medium = CdrBundleMedium::with_capacity(4096);
        assert_eq!(
            medium.begin(MmcOp::ReserveTrack { size: 299 }),
            Err(Completion::Check(INVALID_FIELD))
        );
        // Track 1 has no pre-gap, so the whole capacity is available to it.
        let mut first = CdrBundleMedium::with_capacity(400);
        let mut mock = Mock::default();
        assert_eq!(reserve_medium(&mut first, &mut mock, 300), Completion::Good);
        assert_eq!(
            CdrBundleMedium::with_capacity(400).begin(MmcOp::ReserveTrack { size: 401 }),
            Err(Completion::Check(INVALID_FIELD))
        );

        assert_eq!(
            reserve_medium(&mut medium, &mut mock, 500),
            Completion::Good
        );
        let reserved = medium
            .track_info(TrackInfoRequest::Number(1))
            .expect("reserved track");
        assert_eq!(reserved.status, TrackStatus::Reserved);
        assert_eq!(reserved.start_lba, 0);
        assert_eq!(reserved.length, 0);
        assert_eq!(reserved.allocated, 500);
        assert_eq!(reserved.nwa, 0);
        assert_eq!(reserved.free_blocks, 500);

        assert_eq!(
            medium.begin(MmcOp::ReserveTrack { size: 500 }),
            Err(Completion::Check(INVALID_FIELD))
        );

        let mut mock = Mock::default();
        write_one(&mut medium, &mut mock, 0);
        let after_write = medium
            .track_info(TrackInfoRequest::Number(1))
            .expect("track 1");
        assert_eq!(after_write.status, TrackStatus::Incomplete);
        assert_eq!(after_write.length, 1);
        assert_eq!(after_write.nwa, 1);
        assert_eq!(after_write.free_blocks, 499);

        assert_eq!(close_track(&mut medium, &mut mock, 1), Completion::Good);
        let closed = medium
            .track_info(TrackInfoRequest::Number(1))
            .expect("closed track");
        assert_eq!(closed.status, TrackStatus::Complete);
        assert_eq!(
            closed.length, 500,
            "a reserved track pads to its allocation"
        );
        assert_eq!(closed.nwa, 500);
        assert_eq!(closed.free_blocks, 0);
        assert_eq!(medium.track(1).expect("track 1").blocks, 500);
    }

    #[test]
    fn reserve_after_a_closed_track_counts_the_pregap() {
        let mut medium = CdrBundleMedium::with_capacity(1000);
        let mut mock = Mock::default();
        write_one(&mut medium, &mut mock, 0);
        assert_eq!(close_track(&mut medium, &mut mock, 1), Completion::Good);

        // Track 2 starts at 300 and its user data starts at 450, leaving 700
        // blocks. The pre-gap counts against that space.
        assert_eq!(
            medium.begin(MmcOp::ReserveTrack { size: 551 }),
            Err(Completion::Check(INVALID_FIELD))
        );
        assert_eq!(
            reserve_medium(&mut medium, &mut mock, 550),
            Completion::Good
        );
    }

    #[test]
    fn close_session_with_multi_session_appends_and_then_finalizes() {
        let mut medium = CdrBundleMedium::with_capacity(100_000);
        let mut store = StoreMock::default();
        medium.set_multi_session(true);

        write_one(&mut medium, &mut store, 0);
        assert_eq!(close_track(&mut medium, &mut store, 2), Completion::Good);

        // The session is closed but the disc is still appendable.
        assert_eq!(medium.disc_state(), CdrDiscState::Appendable);
        assert!(!medium.attrs().write_protected);
        let info = medium.disc_info();
        assert_eq!(info.status, DiscStatus::Incomplete);
        assert_eq!(info.sessions, 1);
        assert_eq!(info.first_track_last_session, 1);
        assert_eq!(info.last_track_last_session, 1);
        assert_eq!(info.last_session_state, 3);
        // Session 1 was padded to 300 blocks; the next session's lead-in is
        // recorded there, its first track preamble starts at 300 + 4500 and
        // its user data at 300 + 4500 + 150.
        assert_eq!(info.last_session_lba, 299);
        assert_eq!(info.last_session_lead_in, Some(300));

        // The `11b` close must not drop the recorded session-1 data.
        let (payload, completion) = run_read(&mut medium, &mut store, 0, 1, 2048);
        assert_eq!(completion, Completion::Good);
        assert_eq!(payload, std::vec![0x5A; 2048]);

        let invisible = medium
            .track_info(TrackInfoRequest::Number(0xFF))
            .expect("invisible track of session 2");
        assert_eq!(invisible.session, 2);
        assert_eq!(invisible.start_lba, 4_950);
        assert_eq!(invisible.nwa, 4_950);

        // A write at the reported NWA starts session 2 with that geometry.
        write_one(&mut medium, &mut store, 4_950);
        let session2 = medium.session(2).expect("session 2");
        assert_eq!(session2.start_lba, 300);
        assert_eq!(session2.first_track, 2);
        let track2 = medium.track(2).expect("track 2");
        assert_eq!(track2.session, 2);
        assert_eq!(track2.start_lba, 4_950);
        assert_eq!(medium.disc_info().sessions, 2);
        assert_eq!(medium.disc_info().last_session_state, 1);

        // Closing session 2 with multi-session still set keeps the disc open.
        assert_eq!(close_track(&mut medium, &mut store, 2), Completion::Good);
        assert_eq!(medium.disc_state(), CdrDiscState::Appendable);
        assert_eq!(medium.disc_info().sessions, 2);
        assert_eq!(medium.disc_info().last_session_state, 3);

        // A host that no longer allows a next session finalizes the disc.
        medium.set_multi_session(false);
        assert_eq!(close_track(&mut medium, &mut store, 2), Completion::Good);
        assert_eq!(medium.disc_state(), CdrDiscState::Finalized);
        assert!(medium.attrs().write_protected);
        let info = medium.disc_info();
        assert_eq!(info.sessions, 2);
        assert_eq!(info.first_track_last_session, 2);
        assert_eq!(info.last_track_last_session, 2);
        assert_eq!(info.last_session_state, 3);
        assert_eq!(info.last_session_lead_in, None);
        assert_eq!(info.last_possible_lead_out, None);
    }

    #[test]
    fn restored_multi_session_toc_appends_another_session() {
        let mut medium = CdrBundleMedium::with_capacity(100_000);
        let mut store = StoreMock::default();
        medium.set_multi_session(true);
        write_one(&mut medium, &mut store, 0);
        assert_eq!(close_track(&mut medium, &mut store, 2), Completion::Good);

        let slot = medium.current_slot();
        let restored_slot = store.slot(slot);
        let mut reopened =
            CdrBundleMedium::open_at(slot, &restored_slot, 0, Recovery::Delete).expect("reopen");
        assert_eq!(reopened.disc_state(), CdrDiscState::Appendable);
        assert_eq!(reopened.disc_info().sessions, 1);
        assert_eq!(reopened.disc_info().last_session_state, 3);
        let nwa = reopened
            .track_info(TrackInfoRequest::Number(0xFF))
            .expect("invisible track")
            .nwa;
        assert_eq!(nwa, 4_950);

        // A real host re-applies the Write Parameters page after a restart.
        reopened.set_multi_session(true);
        write_one(&mut reopened, &mut store, nwa);
        assert_eq!(reopened.session(2).expect("session 2").start_lba, 300);
        assert_eq!(close_track(&mut reopened, &mut store, 1), Completion::Good);
        reopened.set_multi_session(false);
        assert_eq!(close_track(&mut reopened, &mut store, 2), Completion::Good);

        assert_eq!(reopened.disc_state(), CdrDiscState::Finalized);
        let info = reopened.disc_info();
        assert_eq!(info.sessions, 2);
        assert_eq!(info.first_track_last_session, 2);
        assert_eq!(info.last_track_last_session, 2);
        assert_eq!(info.last_session_state, 3);
    }

    #[test]
    fn third_session_appends_after_two_multi_session_closes() {
        let mut medium = CdrBundleMedium::with_capacity(200_000);
        let mut store = StoreMock::default();
        medium.set_multi_session(true);

        write_one(&mut medium, &mut store, 0);
        assert_eq!(close_track(&mut medium, &mut store, 2), Completion::Good);
        write_one(&mut medium, &mut store, 4_950);
        assert_eq!(close_track(&mut medium, &mut store, 2), Completion::Good);

        // Session 2 was padded to 5250; session 3 starts at that lead-in.
        let invisible = medium
            .track_info(TrackInfoRequest::Number(0xFF))
            .expect("invisible track of session 3");
        assert_eq!(invisible.session, 3);
        assert_eq!(invisible.nwa, 9_900);

        write_one(&mut medium, &mut store, 9_900);
        let session3 = medium.session(3).expect("session 3");
        assert_eq!(session3.start_lba, 5_250);
        assert_eq!(session3.first_track, 3);
        assert_eq!(medium.disc_info().sessions, 3);

        assert_eq!(close_track(&mut medium, &mut store, 1), Completion::Good);
        medium.set_multi_session(false);
        assert_eq!(close_track(&mut medium, &mut store, 2), Completion::Good);
        assert_eq!(medium.disc_state(), CdrDiscState::Finalized);
        let info = medium.disc_info();
        assert_eq!(info.sessions, 3);
        assert_eq!(info.first_track_last_session, 3);
        assert_eq!(info.last_track_last_session, 3);
        assert_eq!(info.last_session_state, 3);
    }

    #[test]
    fn finalize_latches_with_data_before_an_empty_trailing_session() {
        let mut medium = CdrBundleMedium::with_capacity(200_000);
        let mut store = StoreMock::default();
        medium.set_multi_session(true);

        // Session 1 carries data and is closed for another session.
        write_one(&mut medium, &mut store, 0);
        assert_eq!(close_track(&mut medium, &mut store, 2), Completion::Good);

        // Session 2 only reserves a track and closes it without user data.
        assert_eq!(
            reserve_medium(&mut medium, &mut store, 300),
            Completion::Good
        );
        assert_eq!(close_track(&mut medium, &mut store, 1), Completion::Good);

        // Finalizing must still latch on session 1's data.
        medium.set_multi_session(false);
        assert_eq!(close_track(&mut medium, &mut store, 2), Completion::Good);
        assert_eq!(medium.disc_state(), CdrDiscState::Finalized);
        assert!(medium.attrs().write_protected);
        assert_eq!(medium.disc_info().sessions, 2);
        assert_eq!(medium.disc_info().last_session_state, 3);
    }

    #[test]
    fn finalize_rejects_open_or_incomplete_tracks() {
        let mut medium = CdrBundleMedium::with_capacity(4096);
        let mut mock = Mock::default();
        write_one(&mut medium, &mut mock, 0);

        assert_eq!(
            medium.begin(MmcOp::Close { function: 2 }),
            Err(Completion::Check(SESSION_FIXATION_INCOMPLETE_TRACK))
        );

        assert_eq!(close_track(&mut medium, &mut mock, 1), Completion::Good);
        assert_eq!(close_track(&mut medium, &mut mock, 2), Completion::Good);
        assert_eq!(medium.disc_state(), CdrDiscState::Finalized);
        let info = medium.disc_info();
        assert_eq!(info.status, DiscStatus::Finalized);
        assert_eq!(info.last_session_state, 3);
        assert_eq!(info.last_session_lead_in, None);
        assert_eq!(info.last_possible_lead_out, None);
        assert!(medium.attrs().write_protected);

        // A second finalize is a GOOD no-op.
        assert_eq!(
            medium.begin(MmcOp::Close { function: 2 }),
            Err(Completion::Good)
        );
    }

    #[test]
    fn finalize_blank_is_a_noop() {
        let mut medium = CdrBundleMedium::with_capacity(4096);
        let mut store = StoreMock::default();
        assert_eq!(close_track(&mut medium, &mut store, 2), Completion::Good);
        assert_eq!(medium.disc_state(), CdrDiscState::Blank);
        assert!(!medium.attrs().write_protected);
        assert_eq!(medium.toc_seq(), 1);
        assert_eq!(medium.current_slot(), 0);
        assert!(!medium.needs_save());
        let reopened =
            CdrBundleMedium::open(&store.slot(0), 0, Recovery::Delete).expect("blank TOC");
        assert_eq!(reopened.disc_state(), CdrDiscState::Blank);
        assert_eq!(reopened.toc_seq(), 1);
    }

    #[test]
    fn finalize_rejects_a_reserved_track_without_data() {
        let mut medium = CdrBundleMedium::with_capacity(4096);
        let mut mock = Mock::default();
        assert_eq!(
            reserve_medium(&mut medium, &mut mock, 500),
            Completion::Good
        );
        assert_eq!(
            medium.begin(MmcOp::Close { function: 2 }),
            Err(Completion::Check(EMPTY_OR_PARTIALLY_WRITTEN_RESERVED_TRACK))
        );
        // Closing the empty reserved track leaves it complete but empty, so
        // session fixation is still a no-op rather than a finalize.
        assert_eq!(close_track(&mut medium, &mut mock, 1), Completion::Good);
        let closed = medium
            .track_info(TrackInfoRequest::Number(1))
            .expect("closed track");
        assert_eq!(closed.length, 500);
        assert_eq!(close_track(&mut medium, &mut mock, 2), Completion::Good);
        assert_eq!(medium.disc_state(), CdrDiscState::Appendable);
        assert!(!medium.attrs().write_protected);
    }

    #[test]
    fn finalize_rejects_a_reserved_track_with_data() {
        let mut medium = CdrBundleMedium::with_capacity(4096);
        let mut mock = Mock::default();
        assert_eq!(
            reserve_medium(&mut medium, &mut mock, 500),
            Completion::Good
        );
        write_one(&mut medium, &mut mock, 0);
        assert_eq!(
            medium.begin(MmcOp::Close { function: 2 }),
            Err(Completion::Check(SESSION_FIXATION_INCOMPLETE_TRACK))
        );
    }

    #[test]
    fn commit_pads_and_closes_the_open_track() {
        let mut medium = CdrBundleMedium::with_capacity(4096);
        let mut mock = Mock::default();
        write_one(&mut medium, &mut mock, 0);

        assert_eq!(run_commit(&mut medium, &mut mock), Completion::Good);
        // The aggregate data is synced before the TOC slot is written and
        // synced.
        assert_eq!(mock.syncs, std::vec![0, 1]);
        let info = medium
            .track_info(TrackInfoRequest::Number(1))
            .expect("closed track");
        assert_eq!(info.status, TrackStatus::Complete);
        assert_eq!(info.length, 300);
        assert_eq!(info.nwa, 300);

        // The padding is virtual: reading it needs no storage access.
        mock.reads.clear();
        let (padded, completion) = run_read(&mut medium, &mut mock, 1, 10, 2048);
        assert_eq!(completion, Completion::Good);
        assert!(mock.reads.is_empty(), "padding is not backed by storage");
        assert_eq!(padded, std::vec![0u8; 10 * 2048]);

        // Track 2 starts at the previous end (300) and its first user block is
        // 150 blocks later.
        write_one(&mut medium, &mut mock, 450);
        assert_eq!(medium.track(2).expect("track 2").start_lba, 450);
        for lba in [300, 449, 450] {
            assert_eq!(
                medium
                    .track_info(TrackInfoRequest::Lba(lba))
                    .map(|info| info.number),
                Some(2),
                "LBA {lba} belongs to track 2's pre-gap/data extent"
            );
        }
        assert_eq!(
            medium
                .track_info(TrackInfoRequest::Lba(299))
                .map(|info| info.number),
            Some(1)
        );
        assert_eq!(
            medium.begin(MmcOp::Write { lba: 1, blocks: 1 }),
            Err(Completion::Check(INVALID_ADDRESS_FOR_WRITE))
        );
    }

    #[test]
    fn format_is_not_supported() {
        let mut medium = CdrBundleMedium::with_capacity(4096);
        assert_eq!(
            medium.begin(MmcOp::Format { blocks: 4096 }),
            Err(Completion::Check(INVALID_FIELD))
        );
        assert!(!medium.active());
    }

    #[test]
    fn pre_gap_and_untracked_reads_are_zero_without_storage_io() {
        let mut medium = CdrBundleMedium::with_capacity(1024);
        let mut mock = Mock::default();
        write_one(&mut medium, &mut mock, 0);
        assert_eq!(close_track(&mut medium, &mut mock, 1), Completion::Good);

        // Track 1 is padded to 300 blocks; track 2 starts at 300 and its user
        // data starts after a 150-block pre-gap at 450.
        write_one(&mut medium, &mut mock, 450);
        assert_eq!(close_track(&mut medium, &mut mock, 1), Completion::Good);
        mock.reads.clear();
        mock.writes.clear();

        let (zeros, completion) = run_read(&mut medium, &mut mock, 300, 150, 4096);
        assert_eq!(completion, Completion::Good);
        assert!(mock.reads.is_empty(), "the pre-gap needs no storage read");
        assert_eq!(zeros, std::vec![0u8; 150 * 2048]);

        let (holes, completion) = run_read(&mut medium, &mut mock, 800, 10, 2048);
        assert_eq!(completion, Completion::Good);
        assert!(mock.reads.is_empty(), "unwritten LBAs need no storage read");
        assert_eq!(holes, std::vec![0u8; 10 * 2048]);

        assert_eq!(
            medium.begin(MmcOp::Read {
                lba: 1024,
                blocks: 1
            }),
            Err(Completion::Check(LBA_OUT_OF_RANGE))
        );
    }

    #[test]
    fn a_read_can_span_recorded_and_zero_segments() {
        let mut medium = CdrBundleMedium::with_capacity(1024);
        let mut mock = Mock::default();
        write_one(&mut medium, &mut mock, 0);
        assert_eq!(close_track(&mut medium, &mut mock, 1), Completion::Good);
        write_one(&mut medium, &mut mock, 450);
        assert_eq!(close_track(&mut medium, &mut mock, 1), Completion::Good);
        mock.reads.clear();
        assert_eq!(medium.track(1).expect("track 1").start_lba, 0);
        assert_eq!(
            medium.track(2).expect("track 2").start_lba,
            450,
            "the TOC start is the first user block"
        );
        for lba in [300, 449, 450] {
            assert_eq!(
                medium
                    .track_info(TrackInfoRequest::Lba(lba))
                    .map(|info| info.number),
                Some(2)
            );
        }

        // LBA 0 is track 1's recorded block, 1..449 is virtual padding and the
        // next pre-gap, and 450 is track 2's first block.
        let (data, completion) = run_read(&mut medium, &mut mock, 0, 451, 4096);
        assert_eq!(completion, Completion::Good);
        assert_eq!(data.len(), 451 * 2048);
        assert_eq!(mock.reads, std::vec![(17, 0, 2048), (18, 0, 2048)]);
        assert!(data[2048..450 * 2048].iter().all(|byte| *byte == 0));
    }

    /// A read longer than the bank keeps the next recorded segment in flight
    /// with every send when a second caller bank exists.
    #[test]
    fn a_two_bank_read_prefetches_the_next_segment() {
        let mut medium = CdrBundleMedium::with_capacity(64);
        let mut mock = Mock::default();
        let payload = std::vec![0x5Au8; 8 * 2048];
        assert_eq!(
            run_write(&mut medium, &mut mock, 0, 8, &payload, 2048),
            Completion::Good
        );

        let (single, completion) = run_read(&mut medium, &mut mock, 0, 8, 2048);
        assert_eq!(completion, Completion::Good);
        let (piped, completion, companions) = run_read_alt(
            &mut medium,
            &mut mock,
            MmcOp::Read { lba: 0, blocks: 8 },
            8 * 2048,
            2048,
        );
        assert_eq!(completion, Completion::Good);
        assert_eq!(piped, single, "the pipeline delivers the same bytes");
        assert_eq!(companions, 7, "one companion per later segment");
    }

    /// Partial-sector banks stream and prefetch byte-exactly too.
    #[test]
    fn a_two_bank_read_below_one_sector_prefetches_too() {
        let mut medium = CdrBundleMedium::with_capacity(8);
        let mut mock = Mock::default();
        let payload = [0x3Cu8; 2048];
        assert_eq!(
            run_write(&mut medium, &mut mock, 0, 1, &payload, 512),
            Completion::Good
        );

        let (single, completion) = run_read(&mut medium, &mut mock, 0, 1, 512);
        assert_eq!(completion, Completion::Good);
        let (piped, completion, companions) = run_read_alt(
            &mut medium,
            &mut mock,
            MmcOp::Read { lba: 0, blocks: 1 },
            2048,
            512,
        );
        assert_eq!(completion, Completion::Good);
        assert_eq!(piped, single);
        assert_eq!(companions, 3);
    }

    /// Unrecorded segments have nothing to read ahead: they are delivered from
    /// the serial path and the pipeline resumes after them.
    #[test]
    fn a_two_bank_read_crosses_zero_segments() {
        let mut medium = CdrBundleMedium::with_capacity(1024);
        let mut mock = Mock::default();
        let payload = std::vec![0x11u8; 2 * 2048];
        assert_eq!(
            run_write(&mut medium, &mut mock, 0, 2, &payload, 2048),
            Completion::Good
        );
        assert_eq!(close_track(&mut medium, &mut mock, 1), Completion::Good);
        assert_eq!(
            run_write(&mut medium, &mut mock, 450, 2, &payload, 2048),
            Completion::Good
        );
        assert_eq!(close_track(&mut medium, &mut mock, 1), Completion::Good);

        let (single, completion) = run_read(&mut medium, &mut mock, 0, 452, 2048);
        assert_eq!(completion, Completion::Good);
        let (piped, completion, companions) = run_read_alt(
            &mut medium,
            &mut mock,
            MmcOp::Read {
                lba: 0,
                blocks: 452,
            },
            452 * 2048,
            2048,
        );
        assert_eq!(completion, Completion::Good);
        assert_eq!(piped, single);
        assert_eq!(piped.len(), 452 * 2048);
        assert!(
            piped[2 * 2048..450 * 2048].iter().all(|byte| *byte == 0),
            "the padding and pre-gap stay zero"
        );
        assert_eq!(
            companions, 2,
            "one companion per recorded pair, none across the gap"
        );
    }

    /// Audio segments prefetch by byte with the 2352-byte sector size.
    #[test]
    fn a_two_bank_audio_read_prefetches_at_2352() {
        let mut medium = CdrBundleMedium::with_capacity(16);
        let mut mock = Mock::default();
        let payload = std::vec![0x24u8; 4 * 2352];
        assert_eq!(
            run_write_kind(
                &mut medium,
                &mut mock,
                0,
                4,
                &payload,
                2352,
                SectorKind::Audio2352
            ),
            Completion::Good
        );
        mock.reads.clear();

        let (data, completion, companions) = run_read_alt(
            &mut medium,
            &mut mock,
            MmcOp::ReadSectors {
                lba: 0,
                blocks: 4,
                kind: SectorKind::Audio2352,
            },
            4 * 2352,
            2352,
        );
        assert_eq!(completion, Completion::Good);
        assert_eq!(data.len(), 4 * 2352);
        assert_eq!(companions, 3, "one companion per audio sector");
        assert_eq!(
            mock.reads,
            std::vec![
                (17, 0, 2352),
                (17, 2352, 2352),
                (17, 4704, 2352),
                (17, 7056, 2352),
            ]
        );
    }

    #[test]
    fn banks_smaller_than_a_block_still_stream() {
        let mut medium = CdrBundleMedium::with_capacity(8);
        let mut mock = Mock::default();
        let payload = [0x3Cu8; 2048];
        assert_eq!(
            run_write(&mut medium, &mut mock, 0, 1, &payload, 512),
            Completion::Good
        );
        assert_eq!(
            mock.writes,
            std::vec![
                (17, 0, 512),
                (17, 512, 512),
                (17, 1024, 512),
                (17, 1536, 512),
            ]
        );
        assert_eq!(
            medium
                .track_info(TrackInfoRequest::Number(1))
                .expect("track 1")
                .nwa,
            1
        );

        let (data, completion) = run_read(&mut medium, &mut mock, 0, 1, 512);
        assert_eq!(completion, Completion::Good);
        assert_eq!(data.len(), 2048);
        assert_eq!(
            mock.reads,
            std::vec![
                (17, 0, 512),
                (17, 512, 512),
                (17, 1024, 512),
                (17, 1536, 512),
            ]
        );
    }

    #[test]
    fn track_info_lba_covers_pregaps_and_reserved_allocations() {
        let mut medium = CdrBundleMedium::with_capacity(1024);
        let mut mock = Mock::default();
        assert_eq!(
            reserve_medium(&mut medium, &mut mock, 500),
            Completion::Good
        );
        for lba in [0, 1, 499] {
            assert_eq!(
                medium
                    .track_info(TrackInfoRequest::Lba(lba))
                    .map(|info| info.number),
                Some(1),
                "the reserved allocation owns LBA {lba}"
            );
        }
        assert_eq!(
            medium
                .track_info(TrackInfoRequest::Lba(500))
                .map(|info| info.status),
            Some(TrackStatus::Invisible)
        );

        assert_eq!(close_track(&mut medium, &mut mock, 1), Completion::Good);
        // Track 2 starts at 500 and its first user block is 650.
        assert_eq!(
            reserve_medium(&mut medium, &mut mock, 300),
            Completion::Good
        );
        let track = medium.track(2).expect("track 2");
        assert_eq!(track.start_lba, 650);
        for lba in [500, 649, 650, 949] {
            assert_eq!(
                medium
                    .track_info(TrackInfoRequest::Lba(lba))
                    .map(|info| info.number),
                Some(2),
                "track 2 owns its pre-gap and allocation at LBA {lba}"
            );
        }
        assert_eq!(
            medium
                .track_info(TrackInfoRequest::Lba(950))
                .map(|info| info.status),
            Some(TrackStatus::Invisible)
        );
    }

    #[test]
    fn zero_length_and_capacity_boundary() {
        let mut medium = CdrBundleMedium::with_capacity(8);
        let mut mock = Mock::default();
        let (data, completion) = run_read(&mut medium, &mut mock, 7, 1, 2048);
        assert_eq!(completion, Completion::Good);
        assert_eq!(data, std::vec![0u8; 2048]);
        assert!(mock.reads.is_empty());

        assert_eq!(
            medium.begin(MmcOp::Read { lba: 8, blocks: 0 }),
            Err(Completion::Good)
        );
        assert_eq!(
            medium.begin(MmcOp::Read { lba: 8, blocks: 1 }),
            Err(Completion::Check(LBA_OUT_OF_RANGE))
        );
        assert_eq!(
            medium.begin(MmcOp::Write { lba: 8, blocks: 0 }),
            Err(Completion::Good)
        );
        assert_eq!(
            medium.begin(MmcOp::Write { lba: 8, blocks: 1 }),
            Err(Completion::Check(LBA_OUT_OF_RANGE))
        );
        assert_eq!(
            medium.begin(MmcOp::Write { lba: 7, blocks: 0 }),
            Err(Completion::Good)
        );
        assert_eq!(
            medium.attrs().tracks,
            0,
            "no track from a zero-length write"
        );
    }

    #[test]
    fn interrupt_books_confirmed_blocks() {
        let mut medium = CdrBundleMedium::with_capacity(4096);
        let mut data = [0u8; 4096];
        assert_eq!(medium.begin(MmcOp::Write { lba: 0, blocks: 2 }), Ok(()));
        assert!(matches!(
            medium.poll(Feedback::begin(), &mut data),
            PollStep::Publish(_)
        ));
        assert!(matches!(
            medium.poll(Feedback::plan_accepted(), &mut data),
            PollStep::Receive { buf, .. } if buf.len() == 4096
        ));
        assert!(matches!(
            medium.poll(
                Feedback::host_received(HostReceipt::test(4096, None)),
                &mut data
            ),
            PollStep::Io(StorageOp::Write { offset: 0, .. })
        ));

        medium.interrupt(
            InterruptReason::Disconnect,
            KnownEffects {
                confirmed_write: 2048,
                ..KnownEffects::NONE
            },
        );
        assert!(!medium.active());
        assert_eq!(medium.state(), &CdrBundleState::Idle);
        let info = medium
            .track_info(TrackInfoRequest::Number(1))
            .expect("track 1");
        assert_eq!(info.status, TrackStatus::Incomplete);
        assert_eq!(info.nwa, 1);
        assert_eq!(info.length, 1);
        assert_eq!(medium.begin(MmcOp::Write { lba: 1, blocks: 1 }), Ok(()));
    }

    #[test]
    fn interrupt_drops_an_empty_implicit_track() {
        let mut medium = CdrBundleMedium::with_capacity(4096);
        let mut data = [0u8; 2048];
        assert_eq!(medium.begin(MmcOp::Write { lba: 0, blocks: 1 }), Ok(()));
        assert_eq!(medium.attrs().tracks, 1);
        assert!(matches!(
            medium.poll(Feedback::begin(), &mut data),
            PollStep::Publish(_)
        ));
        assert!(matches!(
            medium.poll(Feedback::plan_accepted(), &mut data),
            PollStep::Receive { .. }
        ));
        assert!(matches!(
            medium.poll(
                Feedback::host_received(HostReceipt::test(2048, None)),
                &mut data
            ),
            PollStep::Io(StorageOp::Write { .. })
        ));

        medium.interrupt(InterruptReason::HostDataLost, KnownEffects::NONE);
        assert!(!medium.active());
        assert_eq!(medium.disc_state(), CdrDiscState::Blank);
        assert_eq!(medium.attrs().tracks, 0);
        assert_eq!(medium.attrs().sessions, 0);
        assert_eq!(
            medium
                .track_info(TrackInfoRequest::Number(1))
                .map(|info| info.status),
            Some(TrackStatus::Invisible)
        );
    }

    #[test]
    fn interrupt_drops_the_open_implicit_track_and_reuses_lba_zero() {
        let mut medium = CdrBundleMedium::with_capacity(4096);
        let mut data = [0u8; 2048];
        assert_eq!(medium.begin(MmcOp::Write { lba: 0, blocks: 1 }), Ok(()));
        assert!(matches!(
            medium.poll(Feedback::begin(), &mut data),
            PollStep::Publish(_)
        ));
        assert!(matches!(
            medium.poll(Feedback::plan_accepted(), &mut data),
            PollStep::Receive { .. }
        ));
        assert!(matches!(
            medium.poll(
                Feedback::host_received(HostReceipt::test(2048, None)),
                &mut data
            ),
            PollStep::Io(StorageOp::Write { .. })
        ));

        // Link loss during the first block: the implicit track never received
        // a confirmed block, so it is dropped together with its open handle.
        medium.interrupt(InterruptReason::Disconnect, KnownEffects::NONE);
        assert!(!medium.active());
        assert_eq!(medium.disc_state(), CdrDiscState::Blank);
        assert_eq!(medium.attrs().tracks, 0);
        assert_eq!(medium.attrs().sessions, 0);

        let mut store = Mock::default();
        let payload = [0x3Cu8; 2048];
        assert_eq!(
            run_write(&mut medium, &mut store, 0, 1, &payload, 2048),
            Completion::Good,
            "the next write must reuse LBA 0 instead of hitting a dangling open track"
        );
        assert_eq!(medium.attrs().tracks, 1);
    }

    #[test]
    fn a_failed_write_leaves_the_track_at_the_last_confirmed_block() {
        let mut medium = CdrBundleMedium::with_capacity(4096);
        let payload = [0xA5u8; 4096];
        let mut data = [0u8; 4096];
        assert_eq!(medium.begin(MmcOp::Write { lba: 0, blocks: 2 }), Ok(()));
        assert!(matches!(
            medium.poll(Feedback::begin(), &mut data),
            PollStep::Publish(_)
        ));
        assert!(matches!(
            medium.poll(Feedback::plan_accepted(), &mut data),
            PollStep::Receive { buf, .. } if buf.len() == 4096
        ));
        data.copy_from_slice(&payload);
        assert!(matches!(
            medium.poll(
                Feedback::host_received(HostReceipt::test(4096, None)),
                &mut data
            ),
            PollStep::Io(StorageOp::Write { offset: 0, .. })
        ));
        // The first block is confirmed, the second is not.
        assert!(matches!(
            medium.poll(
                Feedback::io_done(IoReceipt::test(2048, Some(Fault::Io), Effect::Known)),
                &mut data
            ),
            PollStep::Complete(Completion::Check(WRITE_ERROR))
        ));
        let info = medium
            .track_info(TrackInfoRequest::Number(1))
            .expect("track 1");
        assert_eq!(info.status, TrackStatus::Incomplete);
        assert_eq!(info.nwa, 1);
        assert_eq!(info.length, 1);
        assert!(!medium.active());
        assert_eq!(medium.begin(MmcOp::Write { lba: 1, blocks: 1 }), Ok(()));
    }

    // ── Persistent TOC ──────────────────────────────────────────────────

    const VALID_BODY: &str = "\
disc_type = cdr
disc_state = appendable
capacity_sectors = 1000
medium_leadin = -11077
[track.1]
status = reserved
session = 1
start_lba = 0
data_start_lba = 0
allocated = 500
length = 0
written = 0
nwa = 0
kind = data
reserved = 1
[session.1]
first_track = 1
last_track = 1
start_lba = 0
lead_out_lba = 0
closed = 0
end = 1
";

    /// Build a full slot from a hand-written body (`slot` 0, `seq` 1).
    fn slot_from_body(body: &str) -> std::vec::Vec<u8> {
        slot_from_body_at(0, 1, body)
    }

    fn slot_from_body_at(slot: u8, seq: u32, body: &str) -> std::vec::Vec<u8> {
        let slot_size = TOC_SLOT_DEFAULT as usize;
        let body_len = body.len();
        assert!(TOC_HEADER_LEN + body_len < slot_size, "body fits");
        let mut out = std::vec![0u8; slot_size];
        out[TOC_HEADER_LEN..TOC_HEADER_LEN + body_len].copy_from_slice(body.as_bytes());
        let padding = slot_size - TOC_HEADER_LEN - body_len;
        assert_eq!(
            toc::render_padding(padding, 0, &mut out[TOC_HEADER_LEN + body_len..]),
            padding
        );
        let header = toc::header_bytes(
            slot,
            TOC_SLOT_DEFAULT,
            toc::max_tracks_for_slot(TOC_SLOT_DEFAULT),
            body_len as u32,
            toc::checksum(body.as_bytes()),
            seq,
        );
        out[..TOC_HEADER_LEN].copy_from_slice(&header);
        out
    }

    fn open_body(body: &str) -> Result<CdrBundleMedium, TocError> {
        CdrBundleMedium::open(&slot_from_body(body), 0, Recovery::Delete)
    }

    #[test]
    fn toc_layout_helpers_name_slots_and_tracks() {
        assert_eq!(toc_resource(0), 1);
        assert_eq!(toc_resource(1), 2);
        assert_eq!(toc_file(0), "toc.0");
        assert_eq!(toc_file(1), "toc.1");
        assert_eq!(track_resource(1), 17);
        assert_eq!(track_resource(99), 115);
        assert_eq!(track_file(1).as_str(), "track_1.bin");
        assert_eq!(track_file(65_535).as_str(), "track_65535.bin");
        assert_eq!(TOC_HEADER_LEN, 256);
        assert_eq!(TOC_SLOT_MIN, 4096);
        assert_eq!(TOC_SLOT_DEFAULT, 64 * 1024);
        assert_eq!(TOC_SLOT_MAX, 64 * 1024);
    }

    #[test]
    fn toc_round_trip_blank_write_close_and_continue() {
        let mut medium = CdrBundleMedium::blank(CdrCapacity::Cdr74);
        let mut store = StoreMock::default();
        write_one(&mut medium, &mut store, 0);
        assert_eq!(close_track(&mut medium, &mut store, 1), Completion::Good);

        assert_eq!(medium.slot_size(), TOC_SLOT_DEFAULT);
        assert_eq!(medium.toc_seq(), 1);
        assert_eq!(medium.current_slot(), 0);
        let slot0 = store.slot(0);
        assert_eq!(slot0.len(), TOC_SLOT_DEFAULT as usize);
        let header = TocHeader::parse(&slot0).expect("header");
        assert_eq!(header.slot, 0);
        assert_eq!(header.seq, 1);
        assert_eq!(header.slot_size, TOC_SLOT_DEFAULT);
        assert_eq!(slot0[slot0.len() - 1], b'\n');
        let body_end = TOC_HEADER_LEN + header.body_len as usize;
        let text = std::str::from_utf8(&slot0[TOC_HEADER_LEN..body_end]).expect("body");
        assert!(text.contains("disc_state = appendable\n"));
        assert!(text.contains("[track.1]\nstatus = complete\n"));
        assert!(text.contains("end = 1\n"));
        assert!(slot0[body_end..]
            .iter()
            .all(|byte| *byte == b';' || *byte == b'\n'));

        let reopened = CdrBundleMedium::open(&slot0, 0, Recovery::Delete).expect("reopen");
        assert_eq!(reopened.capacity_sectors(), 332_849);
        assert_eq!(reopened.toc_seq(), 1);
        assert_eq!(reopened.current_slot(), 0);
        assert_eq!(reopened.disc_state(), CdrDiscState::Appendable);
        assert_eq!(
            reopened.track_numbers().collect::<std::vec::Vec<_>>(),
            std::vec![1]
        );
        let info = reopened
            .track_info(TrackInfoRequest::Number(1))
            .expect("track 1");
        assert_eq!(info.status, TrackStatus::Complete);
        assert_eq!(info.length, 300);

        // Continue on the reopened medium; the next save alternates to slot 1.
        let mut next = reopened;
        write_one(&mut next, &mut store, 450);
        assert_eq!(close_track(&mut next, &mut store, 1), Completion::Good);
        assert_eq!(next.toc_seq(), 2);
        assert_eq!(next.current_slot(), 1);
        let slot1 = store.slot(1);
        let reopened = CdrBundleMedium::open(&slot1, 0, Recovery::Delete).expect("second reopen");
        assert_eq!(reopened.toc_seq(), 2);
        assert_eq!(
            reopened.track_numbers().collect::<std::vec::Vec<_>>(),
            std::vec![1, 2]
        );
        assert_eq!(store.slot(0), slot0, "the older slot is untouched");
    }

    #[test]
    fn toc_image_seals_an_open_track() {
        let mut medium = CdrBundleMedium::with_capacity(4096);
        let mut store = StoreMock::default();
        write_one(&mut medium, &mut store, 0);
        assert!(medium.eject_needs_save());

        let mut image = std::vec![0u8; medium.slot_size() as usize];
        let slot = medium.toc_image(&mut image).expect("eject snapshot");
        assert_eq!(slot, 0);
        assert_eq!(medium.toc_seq(), 1);
        assert_eq!(medium.current_slot(), 0);
        assert!(medium.saved);
        assert!(!medium.needs_save());
        assert!(
            !medium.eject_needs_save(),
            "the snapshot cleared the save state"
        );

        let mut reopened = CdrBundleMedium::open_at(slot, &image, 0, Recovery::Delete)
            .expect("the snapshot restores");
        assert_eq!(reopened.capacity_sectors(), 4096);
        assert_eq!(reopened.disc_state(), CdrDiscState::Appendable);
        let info = reopened
            .track_info(TrackInfoRequest::Number(1))
            .expect("track 1");
        assert_eq!(info.status, TrackStatus::Complete);
        assert_eq!(info.length, MIN_TRACK_BLOCKS);
        assert_eq!(info.nwa, MIN_TRACK_BLOCKS);

        // The written prefix, not the close padding, is the readable extent.
        let (data, completion) = run_read(&mut reopened, &mut store, 0, 1, 2048);
        assert_eq!(completion, Completion::Good);
        assert_eq!(data, std::vec![0x5Au8; 2048]);
    }

    #[test]
    fn toc_image_eject_needs_save_rules() {
        // A clean save has no pending state.
        let mut clean = CdrBundleMedium::with_capacity(4096);
        let mut store = StoreMock::default();
        write_one(&mut clean, &mut store, 0);
        assert_eq!(close_track(&mut clean, &mut store, 1), Completion::Good);
        assert!(!clean.eject_needs_save());

        // A finalized disc is complete even with the write-once latch.
        assert_eq!(close_track(&mut clean, &mut store, 2), Completion::Good);
        assert_eq!(clean.disc_state(), CdrDiscState::Finalized);
        assert!(!clean.eject_needs_save());

        // Read-only recovery refuses a snapshot without writing anything.
        let mut frozen = CdrBundleMedium::open(&slot_from_body(VALID_BODY), 0, Recovery::ReadOnly)
            .expect("read-only recovery");
        assert!(!frozen.eject_needs_save());
        let mut image = std::vec![0xAAu8; frozen.slot_size() as usize];
        let before = image.clone();
        assert_eq!(frozen.toc_image(&mut image), Err(TocError::WriteProtected));
        assert_eq!(
            image, before,
            "a refused snapshot leaves the buffer untouched"
        );
    }

    #[test]
    fn toc_image_alternates_slots_and_sequence() {
        let mut medium = CdrBundleMedium::with_capacity(4096);
        let mut store = StoreMock::default();
        write_one(&mut medium, &mut store, 0);

        let mut first = std::vec![0u8; medium.slot_size() as usize];
        assert_eq!(medium.toc_image(&mut first), Ok(0));
        assert_eq!(medium.toc_seq(), 1);
        assert_eq!(medium.current_slot(), 0);
        assert!(!medium.eject_needs_save());

        let mut second = std::vec![0u8; medium.slot_size() as usize];
        assert_eq!(medium.toc_image(&mut second), Ok(1));
        assert_eq!(medium.toc_seq(), 2);
        assert_eq!(medium.current_slot(), 1);
        assert!(!medium.eject_needs_save());

        let older = CdrBundleMedium::open_at(0, &first, 0, Recovery::Delete).expect("slot 0");
        let newer = CdrBundleMedium::open_at(1, &second, 0, Recovery::Delete).expect("slot 1");
        assert_eq!(older.toc_seq(), 1);
        assert_eq!(newer.toc_seq(), 2);
        assert!(newer.toc_seq() > older.toc_seq());
    }

    #[test]
    fn toc_save_alternates_and_a_torn_newest_slot_falls_back() {
        let mut medium = CdrBundleMedium::with_capacity(4096);
        let mut store = StoreMock::default();
        write_one(&mut medium, &mut store, 0);
        assert_eq!(close_track(&mut medium, &mut store, 1), Completion::Good);
        write_one(&mut medium, &mut store, 450);
        assert_eq!(close_track(&mut medium, &mut store, 1), Completion::Good);

        let slot0 = store.slot(0);
        let slot1 = store.slot(1);
        assert_eq!(
            CdrBundleMedium::open(&slot0, 0, Recovery::Delete)
                .unwrap()
                .toc_seq(),
            1
        );
        assert_eq!(
            CdrBundleMedium::open(&slot1, 0, Recovery::Delete)
                .unwrap()
                .toc_seq(),
            2
        );

        // Torn newest slot: the header survives but the body does not.
        let mut torn = slot1.clone();
        let end = torn
            .windows(6)
            .position(|window| window == b"end = ")
            .expect("end line");
        for byte in &mut torn[end..] {
            *byte = b'x';
        }
        assert!(CdrBundleMedium::open(&torn, 0, Recovery::Delete).is_err());
        let older = CdrBundleMedium::open(&slot0, 0, Recovery::Delete).expect("older wins");
        assert_eq!(older.toc_seq(), 1);
        assert_eq!(older.track_numbers().count(), 1);

        // A truncated slot is rejected too.
        assert!(CdrBundleMedium::open(&slot1[..128], 0, Recovery::Delete).is_err());
    }

    #[test]
    fn toc_parser_rejects_malformed_slots() {
        let mut bad_magic = slot_from_body(VALID_BODY);
        bad_magic[8..20].copy_from_slice(b"snow_bad_bnd");
        assert_eq!(
            CdrBundleMedium::open(&bad_magic, 0, Recovery::Delete).err(),
            Some(TocError::BadMagic)
        );

        let mut bad_version = slot_from_body(VALID_BODY);
        let at = bad_version
            .windows(9)
            .position(|window| window == b"version =")
            .expect("version");
        bad_version[at + 10] = b'2';
        assert_eq!(
            CdrBundleMedium::open(&bad_version, 0, Recovery::Delete).err(),
            Some(TocError::BadVersion)
        );

        let mut bad_header = slot_from_body(VALID_BODY);
        let at = bad_header
            .windows(10)
            .position(|window| window == b"max_tracks")
            .expect("max_tracks");
        bad_header[at] = b'x';
        assert_eq!(
            CdrBundleMedium::open(&bad_header, 0, Recovery::Delete).err(),
            Some(TocError::BadHeader)
        );

        let truncated_line = &VALID_BODY[..VALID_BODY.len() - 1];
        assert!(open_body(truncated_line).is_err());

        for body in [
            VALID_BODY.replace("end = 1\n", ""),
            format!("{VALID_BODY}[track.1]\nstatus = complete\n"),
            VALID_BODY.replace("kind = data", "session = 1"),
            VALID_BODY.replace("kind = data", "bogus = data"),
            VALID_BODY.replace("kind = data", "kind"),
            VALID_BODY
                .replace("data_start_lba = 0", "data_start_lba = 10")
                .replace("nwa = 0", "nwa = 5"),
            VALID_BODY
                .replace("allocated = 500", "allocated = 10")
                .replace("nwa = 0", "nwa = 20"),
            VALID_BODY
                .replace("length = 0", "length = 10")
                .replace("written = 0", "written = 5"),
            VALID_BODY.replace("last_track = 1", "last_track = 2"),
            VALID_BODY.replace("disc_type = cdr", "disc_type = dvd"),
            format!("[unknown]\nkey = value\n{VALID_BODY}"),
        ] {
            assert!(
                CdrBundleMedium::open(&slot_from_body(&body), 0, Recovery::Delete).is_err(),
                "body must be rejected: {body}"
            );
        }

        let good = slot_from_body(VALID_BODY);
        assert_eq!(
            CdrBundleMedium::open(&good[..8192], 0, Recovery::Delete).err(),
            Some(TocError::Invalid)
        );

        let mut too_large = good.clone();
        let at = too_large
            .windows(10)
            .position(|window| window == b"slot_size ")
            .expect("slot_size");
        too_large[at + 12..at + 17].copy_from_slice(b"65537");
        assert_eq!(
            CdrBundleMedium::open(&too_large, 0, Recovery::Delete).err(),
            Some(TocError::TooLarge)
        );
    }

    #[test]
    fn toc_recovery_delete_and_read_only() {
        let deleted = open_body(VALID_BODY).expect("delete recovery");
        assert_eq!(deleted.disc_state(), CdrDiscState::Blank);
        assert_eq!(deleted.attrs().tracks, 0);
        assert_eq!(deleted.attrs().sessions, 0);
        assert_eq!(deleted.track_numbers().count(), 0);
        assert!(!deleted.attrs().write_protected);
        assert!(
            deleted.needs_save(),
            "the compacted TOC still has to be saved"
        );

        let mut frozen = CdrBundleMedium::open(&slot_from_body(VALID_BODY), 0, Recovery::ReadOnly)
            .expect("read-only recovery");
        assert_eq!(frozen.disc_state(), CdrDiscState::Finalized);
        assert!(frozen.attrs().write_protected);
        let info = frozen
            .track_info(TrackInfoRequest::Number(1))
            .expect("track 1");
        assert_eq!(info.status, TrackStatus::Complete);
        assert_eq!(info.length, 0);
        assert_eq!(
            frozen.begin(MmcOp::Write { lba: 0, blocks: 1 }),
            Err(Completion::Check(WRITE_PROTECTED))
        );
        assert_eq!(
            frozen.begin(MmcOp::ReserveTrack { size: 300 }),
            Err(Completion::Check(WRITE_PROTECTED))
        );
        assert_eq!(
            frozen.begin(MmcOp::Close { function: 1 }),
            Err(Completion::Check(WRITE_PROTECTED))
        );

        // A padded closed track keeps only its written prefix in read-only
        // recovery.
        let padded = VALID_BODY
            .replace("status = reserved", "status = complete")
            .replace("length = 0", "length = 1")
            .replace("written = 0", "written = 300")
            .replace("nwa = 0", "nwa = 300")
            .replace("lead_out_lba = 0", "lead_out_lba = 300")
            .replace("reserved = 1", "reserved = 0");
        let frozen = CdrBundleMedium::open(&slot_from_body(&padded), 0, Recovery::ReadOnly)
            .expect("padded read-only");
        let info = frozen
            .track_info(TrackInfoRequest::Number(1))
            .expect("track 1");
        assert_eq!(info.length, 1);
        assert_eq!(info.nwa, 1);

        // A complete record survives both recovery modes.
        let complete = VALID_BODY
            .replace("status = reserved", "status = complete")
            .replace("reserved = 1", "reserved = 0");
        assert_eq!(
            open_body(&complete)
                .expect("complete survives delete")
                .attrs()
                .tracks,
            1
        );
        assert_eq!(
            CdrBundleMedium::open(&slot_from_body(&complete), 0, Recovery::ReadOnly)
                .expect("complete survives read-only")
                .attrs()
                .tracks,
            1
        );
    }

    #[test]
    fn toc_save_streams_through_a_small_bank() {
        let mut medium = CdrBundleMedium::with_capacity(4096);
        let mut store = StoreMock::default();
        write_one(&mut medium, &mut store, 0);
        assert_eq!(
            run_control(&mut medium, &mut store, MmcOp::Close { function: 1 }, 512),
            Completion::Good
        );
        let slot_writes = store
            .writes
            .iter()
            .filter(|(resource, _, _)| *resource == toc_resource(0))
            .count();
        assert!(slot_writes > 2, "the slot is written in several chunks");
        let slot = store.slot(0);
        let reopened = CdrBundleMedium::open(&slot, 0, Recovery::Delete).expect("parse");
        assert_eq!(reopened.attrs().tracks, 1);
        assert_eq!(reopened.toc_seq(), 1);
    }

    #[test]
    fn toc_round_trips_32_tracks_and_16_sessions() {
        let mut tracks: heapless::Vec<TrackEntry, MAX_TRACKS> = heapless::Vec::new();
        let mut sessions: heapless::Vec<SessionEntry, MAX_SESSIONS> = heapless::Vec::new();
        let mut next_start = 0u64;
        let mut next_data = 0u64;
        for number in 1..=32u16 {
            let session = (number - 1) / 2 + 1;
            let first = (session - 1) * 2 + 1;
            if number == first && session > 1 {
                // A new session's lead-in follows the previous lead-out; its
                // first track preamble starts one minute later.
                let session_start = next_start;
                next_start = session_start + SESSION_LEADIN_BLOCKS;
                next_data = next_start + 150;
            }
            let start_lba = next_start;
            let data_start_lba = next_data;
            let nwa = data_start_lba + 300;
            let _ = tracks.push(TrackEntry {
                number,
                session,
                start_lba,
                data_start_lba,
                allocated: 0,
                length: 300,
                written: 300,
                nwa,
                status: TrackStatus::Complete,
                kind: TrackKind::Data,
                reserved: false,
            });
            next_start = data_start_lba + 300;
            next_data = next_start + 150;
        }
        for number in 1..=16u16 {
            let first_track = number * 2 - 1;
            let last_track = number * 2;
            let start_lba = tracks
                .iter()
                .find(|track| track.number == first_track)
                .map_or(0, |track| track.start_lba);
            let start_lba = if number == 1 {
                start_lba
            } else {
                start_lba - SESSION_LEADIN_BLOCKS
            };
            let lead_out_lba = tracks
                .iter()
                .find(|track| track.number == last_track)
                .map_or(0, |track| track.nwa);
            let _ = sessions.push(SessionEntry {
                number,
                first_track,
                last_track,
                start_lba,
                lead_out_lba,
                closed: true,
            });
        }
        let len = toc::body_len(
            &tracks,
            &sessions,
            100_000,
            MEDIUM_LEADIN,
            CdrDiscState::Appendable,
            DiscKind::Cdr,
        );
        let mut body = std::vec![0u8; len];
        assert_eq!(
            toc::render_body(
                &tracks,
                &sessions,
                100_000,
                MEDIUM_LEADIN,
                CdrDiscState::Appendable,
                DiscKind::Cdr,
                0,
                &mut body
            ),
            len
        );
        let text = std::str::from_utf8(&body).expect("utf8");
        let slot = slot_from_body(text);
        let reopened = CdrBundleMedium::open(&slot, 0, Recovery::Delete).expect("round trip");
        assert_eq!(reopened.attrs().tracks, 32);
        assert_eq!(reopened.attrs().sessions, 16);
        assert_eq!(reopened.track_numbers().count(), 32);
    }

    #[test]
    fn toc_body_too_large_fails_without_touching_the_previous_slot() {
        let mut medium = CdrBundleMedium::with_capacity(4096);
        let mut store = StoreMock::default();
        assert_eq!(
            reserve_medium(&mut medium, &mut store, 300),
            Completion::Good
        );
        let previous = store.slot(0);
        assert!(!previous.is_empty());
        medium.slot_size = 512;
        assert_eq!(
            close_track(&mut medium, &mut store, 1),
            Completion::Check(INTERNAL_FAILURE)
        );
        assert_eq!(store.slot(0), previous);
        assert_eq!(medium.toc_seq(), 1);
        assert_eq!(medium.current_slot(), 0);
        assert!(!medium.active());
    }

    fn newest_slot(store: &StoreMock) -> std::vec::Vec<u8> {
        let mut best: Option<(TocHeader, std::vec::Vec<u8>)> = None;
        for slot in [0u8, 1] {
            let bytes = store.slot(slot);
            let Ok(header) = TocHeader::parse(&bytes) else {
                continue;
            };
            if bytes.len() != header.slot_size as usize {
                continue;
            }
            if best
                .as_ref()
                .is_none_or(|(current, _)| header.newer_than(current))
            {
                best = Some((header, bytes));
            }
        }
        best.expect("a valid slot").1
    }

    #[test]
    fn toc_header_two_step_read_equal_seq_and_copied_slot() {
        let slot0 = slot_from_body_at(0, 1, VALID_BODY);
        let slot1 = slot_from_body_at(1, 1, VALID_BODY);
        let h0 = TocHeader::parse(&slot0[..TOC_HEADER_LEN]).expect("header 0");
        let h1 = TocHeader::parse(&slot1[..TOC_HEADER_LEN]).expect("header 1");
        assert_eq!(h0.slot, 0);
        assert_eq!(h1.slot, 1);
        assert_eq!(h0.slot_size, slot0.len() as u32);
        assert_eq!(h0.max_tracks, toc::max_tracks_for_slot(h0.slot_size));
        assert!(h1.newer_than(&h0), "equal seq selects the higher slot");
        assert!(!h0.newer_than(&h1));
        assert_eq!(
            CdrBundleMedium::open(&slot0, 0, Recovery::Delete)
                .unwrap()
                .current_slot(),
            0
        );
        assert_eq!(
            CdrBundleMedium::open(&slot1, 0, Recovery::Delete)
                .unwrap()
                .current_slot(),
            1
        );
        assert_eq!(
            TocHeader::parse(&slot0[..128]).err(),
            Some(TocError::BadHeader)
        );

        // A slot copied into the other physical position keeps its stored
        // index; the next save targets the other slot, never the one loaded.
        let copied = slot_from_body_at(1, 5, VALID_BODY);
        assert_eq!(
            CdrBundleMedium::open_at(0, &copied, 0, Recovery::Delete).err(),
            Some(TocError::Invalid),
            "a copied slot fails the physical-position check"
        );
        let mut medium = CdrBundleMedium::open(&copied, 0, Recovery::Delete).expect("copied slot");
        assert_eq!(medium.current_slot(), 1);
        let mut store = StoreMock::default();
        assert_eq!(run_commit(&mut medium, &mut store), Completion::Good);
        assert!(!store.slot(0).is_empty());
        assert!(store.slot(1).is_empty());

        // A capacity hint that disagrees with the stored value is rejected.
        assert_eq!(
            CdrBundleMedium::open(&slot0, 1001, Recovery::Delete).err(),
            Some(TocError::Invalid)
        );
    }

    #[test]
    fn toc_rejects_hybrid_bodies_and_torn_headers() {
        let old = slot_from_body_at(0, 1, VALID_BODY);
        let new_body = VALID_BODY.replace("disc_state = appendable", "disc_state = finalized");
        let new = slot_from_body_at(1, 2, &new_body);
        let mut hybrid = new.clone();
        for (index, byte) in hybrid.iter_mut().enumerate().skip(TOC_HEADER_LEN + 64) {
            *byte = old[index];
        }
        assert!(CdrBundleMedium::open(&hybrid, 0, Recovery::Delete).is_err());
        assert!(CdrBundleMedium::open(&old, 0, Recovery::Delete).is_ok());
        assert_eq!(
            TocHeader::parse(&new[..TOC_HEADER_LEN - 1]).err(),
            Some(TocError::BadHeader)
        );

        let at = |bytes: &[u8], needle: &[u8]| {
            bytes
                .windows(needle.len())
                .position(|window| window == needle)
                .expect("header field")
        };
        let mut bad_checksum = new.clone();
        let p = at(&bad_checksum, b"checksum = ") + 11;
        bad_checksum[p] = if bad_checksum[p] == b'0' { b'1' } else { b'0' };
        assert!(CdrBundleMedium::open(&bad_checksum, 0, Recovery::Delete).is_err());

        let mut bad_slot = new.clone();
        let p = at(&bad_slot, b"slot = ") + 7;
        bad_slot[p] = b'2';
        assert_eq!(
            CdrBundleMedium::open(&bad_slot, 0, Recovery::Delete).err(),
            Some(TocError::Invalid)
        );

        let mut bad_body_len = new.clone();
        let p = at(&bad_body_len, b"body_len = ") + 11;
        bad_body_len[p] = b'0';
        assert!(CdrBundleMedium::open(&bad_body_len, 0, Recovery::Delete).is_err());

        // The old slot still wins after a torn new header.
        let mut torn = new.clone();
        torn[..TOC_HEADER_LEN].fill(b';');
        assert!(CdrBundleMedium::open(&torn, 0, Recovery::Delete).is_err());
        assert_eq!(
            CdrBundleMedium::open(&old, 0, Recovery::Delete)
                .unwrap()
                .toc_seq(),
            1
        );
    }

    #[test]
    fn toc_exact_slot_bytes_and_blank_round_trip() {
        let mut medium = CdrBundleMedium::with_capacity(4096);
        let mut store = StoreMock::default();
        assert_eq!(close_track(&mut medium, &mut store, 2), Completion::Good);
        let slot = store.slot(0);
        let header = TocHeader::parse(&slot[..TOC_HEADER_LEN]).expect("header");
        assert!(slot.starts_with(b"magic = snow_cdr_bnd\n"));
        assert_eq!(header.slot, 0);
        assert_eq!(header.seq, 1);
        assert_eq!(header.slot_size, TOC_SLOT_DEFAULT);
        assert_eq!(slot.len(), TOC_SLOT_DEFAULT as usize);
        assert_eq!(slot[slot.len() - 1], b'\n');
        let body_end = TOC_HEADER_LEN + header.body_len as usize;
        let body = std::str::from_utf8(&slot[TOC_HEADER_LEN..body_end]).expect("body");
        assert!(body.contains("disc_state = blank\n"));
        assert!(body.ends_with("end = 1\n"));
        assert_eq!(
            toc::checksum(&slot[TOC_HEADER_LEN..body_end]),
            header.checksum
        );
        assert!(slot[body_end..]
            .iter()
            .all(|byte| *byte == b';' || *byte == b'\n'));
        let reopened = CdrBundleMedium::open(&slot, 0, Recovery::Delete).expect("blank reopen");
        assert_eq!(reopened.disc_state(), CdrDiscState::Blank);
        assert_eq!(reopened.toc_seq(), 1);
        assert_eq!(reopened.current_slot(), 0);
    }

    #[test]
    fn toc_close_flushes_data_before_the_toc() {
        let mut medium = CdrBundleMedium::with_capacity(4096);
        let mut store = StoreMock::default();
        write_one(&mut medium, &mut store, 0);
        let start = store.events.len();
        assert!(matches!(
            store.events[start - 1],
            StoreEv::Write(resource, _, _) if resource == track_resource(1)
        ));
        assert_eq!(close_track(&mut medium, &mut store, 1), Completion::Good);
        let tail = &store.events[start..];
        assert!(matches!(tail.first(), Some(StoreEv::Sync(0))));
        assert!(matches!(
            tail.last(),
            Some(StoreEv::Sync(resource)) if *resource == TOC_RESOURCE_0
        ));
        let slot_writes: std::vec::Vec<(u64, usize)> = tail
            .iter()
            .filter_map(|event| match event {
                StoreEv::Write(resource, offset, len) if *resource == TOC_RESOURCE_0 => {
                    Some((*offset, *len))
                }
                _ => None,
            })
            .collect();
        assert_eq!(
            slot_writes.first().map(|(offset, _)| *offset),
            Some(TOC_HEADER_LEN as u64),
            "the body is written first"
        );
        assert_eq!(
            slot_writes.last().map(|(offset, _)| *offset),
            Some(0),
            "the header is written last"
        );
    }

    #[test]
    fn toc_save_failures_keep_needs_save_and_retry() {
        // CLOSE 1: a TOC write failure keeps the transition and retries.
        let mut medium = CdrBundleMedium::with_capacity(4096);
        let mut store = StoreMock::default();
        write_one(&mut medium, &mut store, 0);
        store.fail_write = true;
        assert_eq!(
            close_track(&mut medium, &mut store, 1),
            Completion::Check(WRITE_ERROR)
        );
        assert!(medium.needs_save());
        assert_eq!(medium.toc_seq(), 0);
        store.fail_write = false;
        assert_eq!(close_track(&mut medium, &mut store, 1), Completion::Good);
        assert!(!medium.needs_save());
        assert_eq!(medium.toc_seq(), 1);

        // A header-last failure with a 256/512-byte bank leaves the old slot.
        let mut medium = CdrBundleMedium::with_capacity(4096);
        let mut store = StoreMock::default();
        assert_eq!(
            reserve_medium(&mut medium, &mut store, 300),
            Completion::Good
        );
        let old = store.slot(0);
        store.fail_toc_header = true;
        assert_eq!(
            run_control(&mut medium, &mut store, MmcOp::Close { function: 1 }, 256),
            Completion::Check(WRITE_ERROR)
        );
        assert!(medium.needs_save());
        assert_eq!(
            CdrBundleMedium::open(&old, 0, Recovery::Delete)
                .unwrap()
                .toc_seq(),
            1
        );
        store.fail_toc_header = false;
        assert_eq!(
            run_control(&mut medium, &mut store, MmcOp::Close { function: 1 }, 512),
            Completion::Good
        );
        assert!(!medium.needs_save());

        // CLOSE 1: a slot-sync failure is retryable.
        let mut medium = CdrBundleMedium::with_capacity(4096);
        let mut store = StoreMock::default();
        assert_eq!(
            reserve_medium(&mut medium, &mut store, 300),
            Completion::Good
        );
        store.fail_sync_resource = Some(TOC_RESOURCE_1);
        assert_eq!(
            close_track(&mut medium, &mut store, 1),
            Completion::Check(MEDIUM_ERROR)
        );
        assert!(medium.needs_save());
        store.fail_sync_resource = None;
        assert_eq!(close_track(&mut medium, &mut store, 1), Completion::Good);
        assert!(!medium.needs_save());

        // CLOSE 2: a slot-sync failure is retryable.
        let mut medium = CdrBundleMedium::with_capacity(4096);
        let mut store = StoreMock::default();
        write_one(&mut medium, &mut store, 0);
        assert_eq!(close_track(&mut medium, &mut store, 1), Completion::Good);
        store.fail_sync_resource = Some(TOC_RESOURCE_1);
        assert_eq!(
            close_track(&mut medium, &mut store, 2),
            Completion::Check(MEDIUM_ERROR)
        );
        assert!(medium.needs_save());
        store.fail_sync_resource = None;
        assert_eq!(close_track(&mut medium, &mut store, 2), Completion::Good);
        assert!(!medium.needs_save());

        // CLOSE 2: a TOC write failure is retryable.
        let mut medium = CdrBundleMedium::with_capacity(4096);
        let mut store = StoreMock::default();
        write_one(&mut medium, &mut store, 0);
        assert_eq!(close_track(&mut medium, &mut store, 1), Completion::Good);
        store.fail_write = true;
        assert_eq!(
            close_track(&mut medium, &mut store, 2),
            Completion::Check(WRITE_ERROR)
        );
        assert!(medium.needs_save());
        store.fail_write = false;
        assert_eq!(close_track(&mut medium, &mut store, 2), Completion::Good);
        assert!(!medium.needs_save());

        // COMMIT: a data-sync failure is retryable.
        let mut medium = CdrBundleMedium::with_capacity(4096);
        let mut store = StoreMock::default();
        write_one(&mut medium, &mut store, 0);
        store.fail_sync = true;
        assert_eq!(
            run_commit(&mut medium, &mut store),
            Completion::Check(MEDIUM_ERROR)
        );
        assert!(medium.needs_save());
        store.fail_sync = false;
        assert_eq!(run_commit(&mut medium, &mut store), Completion::Good);
        assert!(!medium.needs_save());

        // COMMIT: a TOC write failure is retryable.
        let mut medium = CdrBundleMedium::with_capacity(4096);
        let mut store = StoreMock::default();
        write_one(&mut medium, &mut store, 0);
        store.fail_write = true;
        assert_eq!(
            run_commit(&mut medium, &mut store),
            Completion::Check(WRITE_ERROR)
        );
        assert!(medium.needs_save());
        store.fail_write = false;
        assert_eq!(run_commit(&mut medium, &mut store), Completion::Good);
        assert!(!medium.needs_save());
    }

    #[test]
    fn toc_reserve_rolls_back_when_the_save_fails() {
        let mut medium = CdrBundleMedium::with_capacity(4096);
        let mut store = StoreMock {
            fail_write: true,
            ..Default::default()
        };
        assert_eq!(
            reserve_medium(&mut medium, &mut store, 500),
            Completion::Check(WRITE_ERROR)
        );
        assert_eq!(medium.attrs().tracks, 0);
        assert_eq!(medium.attrs().sessions, 0);
        assert!(!medium.needs_save());
        store.fail_write = false;
        assert_eq!(
            reserve_medium(&mut medium, &mut store, 500),
            Completion::Good
        );
        assert_eq!(medium.attrs().tracks, 1);
        assert!(!medium.needs_save());

        // A slot-sync failure rolls the reservation back too.
        let mut medium = CdrBundleMedium::with_capacity(4096);
        let mut store = StoreMock {
            fail_sync_resource: Some(TOC_RESOURCE_0),
            ..Default::default()
        };
        assert_eq!(
            reserve_medium(&mut medium, &mut store, 500),
            Completion::Check(MEDIUM_ERROR)
        );
        assert_eq!(medium.attrs().tracks, 0);
        assert!(!medium.needs_save());
        store.fail_sync_resource = None;
        assert_eq!(
            reserve_medium(&mut medium, &mut store, 500),
            Completion::Good
        );
    }

    #[test]
    fn toc_99_tracks_at_slot_max_and_41_rejected_at_16k() {
        let mut medium = CdrBundleMedium::with_capacity(100_000);
        let mut store = StoreMock::default();
        for index in 0..99 {
            write_one(&mut medium, &mut store, index * 450);
            assert_eq!(close_track(&mut medium, &mut store, 1), Completion::Good);
        }
        let slot = newest_slot(&store);
        let reopened = CdrBundleMedium::open(&slot, 0, Recovery::Delete).expect("99 tracks");
        assert_eq!(reopened.attrs().tracks, 99);
        assert_eq!(reopened.attrs().sessions, 1);
        assert_eq!(reopened.toc_seq(), 99);

        let mut medium =
            CdrBundleMedium::with_capacity_and_slot(100_000, 16 * 1024).expect("16 KiB slot");
        let mut store = StoreMock::default();
        for index in 0..40 {
            write_one(&mut medium, &mut store, index * 450);
            assert_eq!(close_track(&mut medium, &mut store, 1), Completion::Good);
        }
        assert_eq!(medium.attrs().tracks, 40);
        assert_eq!(
            medium.begin(MmcOp::Write {
                lba: 40 * 450,
                blocks: 1
            }),
            Err(Completion::Check(INVALID_FIELD)),
            "the implicit first write is rejected at the slot cap"
        );
        assert_eq!(
            reserve_medium(&mut medium, &mut store, 300),
            Completion::Check(INVALID_FIELD)
        );
        assert_eq!(medium.attrs().tracks, 40);
        assert!(!medium.needs_save());
    }

    #[test]
    fn toc_round_trips_99_tracks_and_16_sessions() {
        let mut tracks: heapless::Vec<TrackEntry, MAX_TRACKS> = heapless::Vec::new();
        let mut sessions: heapless::Vec<SessionEntry, MAX_SESSIONS> = heapless::Vec::new();
        let mut next_lead_out = 0u64;
        for number in 1..=16u16 {
            let first_track = (number - 1) * 6 + 1;
            let last_track = if number == 16 { 99 } else { number * 6 };
            let session_start = next_lead_out;
            let mut start_lba = if number == 1 {
                0
            } else {
                session_start + SESSION_LEADIN_BLOCKS
            };
            let mut data_start_lba = if number == 1 { 0 } else { start_lba + 150 };
            let mut lead_out_lba = 0;
            for track_number in first_track..=last_track {
                let nwa = data_start_lba + 300;
                let _ = tracks.push(TrackEntry {
                    number: track_number,
                    session: number,
                    start_lba,
                    data_start_lba,
                    allocated: 0,
                    length: 300,
                    written: 300,
                    nwa,
                    status: TrackStatus::Complete,
                    kind: TrackKind::Data,
                    reserved: false,
                });
                lead_out_lba = nwa;
                start_lba = nwa;
                data_start_lba = start_lba + 150;
            }
            let _ = sessions.push(SessionEntry {
                number,
                first_track,
                last_track,
                start_lba: session_start,
                lead_out_lba,
                closed: true,
            });
            next_lead_out = lead_out_lba;
        }
        let len = toc::body_len(
            &tracks,
            &sessions,
            500_000,
            MEDIUM_LEADIN,
            CdrDiscState::Appendable,
            DiscKind::Cdr,
        );
        let mut body = std::vec![0u8; len];
        assert_eq!(
            toc::render_body(
                &tracks,
                &sessions,
                500_000,
                MEDIUM_LEADIN,
                CdrDiscState::Appendable,
                DiscKind::Cdr,
                0,
                &mut body
            ),
            len
        );
        let text = std::str::from_utf8(&body).expect("utf8");
        let slot = slot_from_body_at(0, 1, text);
        let reopened = CdrBundleMedium::open(&slot, 0, Recovery::Delete).expect("99/16");
        assert_eq!(reopened.attrs().tracks, 99);
        assert_eq!(reopened.attrs().sessions, 16);
    }

    #[test]
    fn toc_parser_rejects_non_contiguous_tracks_and_sessions() {
        let gap_body = "\
disc_type = cdr
disc_state = appendable
capacity_sectors = 4000
medium_leadin = -11077
[track.1]
status = complete
session = 1
start_lba = 0
data_start_lba = 0
allocated = 0
length = 300
written = 300
nwa = 300
kind = data
reserved = 0
[track.3]
status = complete
session = 1
start_lba = 600
data_start_lba = 750
allocated = 0
length = 300
written = 300
nwa = 1050
kind = data
reserved = 0
[session.1]
first_track = 1
last_track = 3
start_lba = 0
lead_out_lba = 1050
closed = 0
end = 1
";
        assert!(open_body(gap_body).is_err());

        let session_gap = "\
disc_type = cdr
disc_state = appendable
capacity_sectors = 4000
medium_leadin = -11077
[track.1]
status = complete
session = 1
start_lba = 0
data_start_lba = 0
allocated = 0
length = 300
written = 300
nwa = 300
kind = data
reserved = 0
[track.2]
status = complete
session = 2
start_lba = 300
data_start_lba = 450
allocated = 0
length = 300
written = 300
nwa = 750
kind = data
reserved = 0
[track.3]
status = complete
session = 2
start_lba = 750
data_start_lba = 900
allocated = 0
length = 300
written = 300
nwa = 1200
kind = data
reserved = 0
[session.1]
first_track = 1
last_track = 1
start_lba = 0
lead_out_lba = 300
closed = 1
[session.2]
first_track = 3
last_track = 3
start_lba = 750
lead_out_lba = 1200
closed = 1
end = 1
";
        assert!(open_body(session_gap).is_err());
    }

    #[test]
    fn toc_delete_compacts_the_unclosed_tail() {
        let body = "\
disc_type = cdr
disc_state = appendable
capacity_sectors = 4000
medium_leadin = -11077
[track.1]
status = complete
session = 1
start_lba = 0
data_start_lba = 0
allocated = 0
length = 300
written = 300
nwa = 300
kind = data
reserved = 0
[track.2]
status = incomplete
session = 1
start_lba = 300
data_start_lba = 450
allocated = 0
length = 10
written = 10
nwa = 460
kind = data
reserved = 0
[track.3]
status = complete
session = 1
start_lba = 460
data_start_lba = 610
allocated = 0
length = 300
written = 300
nwa = 910
kind = data
reserved = 0
[session.1]
first_track = 1
last_track = 3
start_lba = 0
lead_out_lba = 910
closed = 0
end = 1
";
        let slot = slot_from_body_at(0, 1, body);
        let mut medium = CdrBundleMedium::open(&slot, 0, Recovery::Delete).expect("compacted");
        assert_eq!(medium.attrs().tracks, 1);
        assert!(medium.needs_save());
        let mut store = StoreMock::default();
        assert_eq!(run_commit(&mut medium, &mut store), Completion::Good);
        let saved = store.slot(1);
        let reopened = CdrBundleMedium::open(&saved, 0, Recovery::Delete).expect("reopened");
        assert_eq!(reopened.attrs().tracks, 1);
        assert_eq!(reopened.attrs().sessions, 1);
        assert_eq!(
            reopened.track_numbers().collect::<std::vec::Vec<_>>(),
            std::vec![1]
        );
    }

    #[test]
    fn toc_slot_size_bounds() {
        assert!(matches!(
            CdrBundleMedium::with_capacity_and_slot(1000, 0),
            Err(TocError::BadSlotSize)
        ));
        assert!(matches!(
            CdrBundleMedium::with_capacity_and_slot(1000, TOC_HEADER_LEN as u32),
            Err(TocError::BadSlotSize)
        ));
        assert!(matches!(
            CdrBundleMedium::with_capacity_and_slot(1000, 1024),
            Err(TocError::BadSlotSize)
        ));
        assert!(CdrBundleMedium::with_capacity_and_slot(1000, TOC_SLOT_MIN).is_ok());
        assert!(CdrBundleMedium::with_capacity_and_slot(1000, TOC_SLOT_MAX).is_ok());
        assert!(matches!(
            CdrBundleMedium::with_capacity_and_slot(1000, TOC_SLOT_MAX + 1),
            Err(TocError::TooLarge)
        ));

        // The minimum slot is enough for one track and rejects a second.
        let mut medium =
            CdrBundleMedium::with_capacity_and_slot(1000, TOC_SLOT_MIN).expect("minimum slot");
        let mut store = StoreMock::default();
        write_one(&mut medium, &mut store, 0);
        assert_eq!(close_track(&mut medium, &mut store, 1), Completion::Good);
        let mut reopened =
            CdrBundleMedium::open(&store.slot(0), 1000, Recovery::Delete).expect("one track");
        assert_eq!(reopened.attrs().tracks, 1);
        assert_eq!(
            reopened.begin(MmcOp::ReserveTrack { size: 300 }),
            Err(Completion::Check(INVALID_FIELD))
        );
    }

    #[test]
    fn test_write_consumes_a_multi_bank_data_phase_without_recording() {
        let mut medium = CdrBundleMedium::with_capacity(4096);
        let mut mock = Mock::default();
        medium.set_test_write(true);
        let payload: std::vec::Vec<u8> = (0..3 * 2048).map(|index| index as u8).collect();
        assert_eq!(
            run_write(&mut medium, &mut mock, 0, 3, &payload, 2048),
            Completion::Good
        );

        assert_eq!(medium.disc_state(), CdrDiscState::Blank);
        let attrs = medium.attrs();
        assert_eq!(attrs.tracks, 0);
        assert_eq!(attrs.sessions, 0);
        assert!(!medium.needs_save());
        assert_eq!(medium.track(1), None);
        assert_eq!(medium.session(1), None);
        assert_eq!(medium.current_nwa(), 0, "the NWA never advances");
        assert!(mock.writes.is_empty(), "a simulated write touches no track");
        assert!(mock.syncs.is_empty());

        // A zero-block write stays a GOOD no-op and the range is still
        // checked.
        assert_eq!(
            medium.begin(MmcOp::Write { lba: 0, blocks: 0 }),
            Err(Completion::Good)
        );
        assert_eq!(
            medium.begin(MmcOp::Write {
                lba: 4096,
                blocks: 1
            }),
            Err(Completion::Check(LBA_OUT_OF_RANGE))
        );

        // WRITE SECTORS (Data2048) is simulated the same way.
        assert_eq!(
            medium.begin(MmcOp::WriteSectors {
                lba: 0,
                blocks: 2,
                kind: SectorKind::Data2048,
            }),
            Ok(())
        );
        let mut data = std::vec![0u8; 2048];
        match medium.poll(Feedback::begin(), &mut data) {
            PollStep::Publish(plan) => assert_eq!(plan.bytes, 2 * 2048),
            other => panic!("expected test-write publish, got {other:?}"),
        }
        match medium.poll(Feedback::plan_accepted(), &mut data) {
            PollStep::Receive { buf, .. } => assert_eq!(buf.len(), 2048),
            other => panic!("expected test-write receive, got {other:?}"),
        }
        match medium.poll(
            Feedback::host_received(HostReceipt::test(2048, None)),
            &mut data,
        ) {
            PollStep::Receive { buf, .. } => assert_eq!(buf.len(), 2048),
            other => panic!("expected the second chunk, got {other:?}"),
        }
        match medium.poll(
            Feedback::host_received(HostReceipt::test(2048, None)),
            &mut data,
        ) {
            PollStep::Complete(Completion::Good) => {}
            other => panic!("expected test-write completion, got {other:?}"),
        }
        assert_eq!(medium.disc_state(), CdrDiscState::Blank);
        assert_eq!(medium.attrs().tracks, 0);
        assert!(mock.writes.is_empty());

        // CD-DA audio writes are simulated the same way: 2352 bytes per
        // logical block are consumed, nothing is recorded.
        assert_eq!(
            medium.begin(MmcOp::WriteSectors {
                lba: 0,
                blocks: 1,
                kind: SectorKind::Audio2352,
            }),
            Ok(())
        );
        let mut audio = std::vec![0u8; 2352];
        match medium.poll(Feedback::begin(), &mut audio) {
            PollStep::Publish(plan) => assert_eq!(plan.bytes, 2352),
            other => panic!("expected audio test-write publish, got {other:?}"),
        }
        match medium.poll(Feedback::plan_accepted(), &mut audio) {
            PollStep::Receive { buf, .. } => assert_eq!(buf.len(), 2352),
            other => panic!("expected audio test-write receive, got {other:?}"),
        }
        match medium.poll(
            Feedback::host_received(HostReceipt::test(2352, None)),
            &mut audio,
        ) {
            PollStep::Complete(Completion::Good) => {}
            other => panic!("expected audio test-write completion, got {other:?}"),
        }
        assert_eq!(medium.disc_state(), CdrDiscState::Blank);
        assert_eq!(medium.attrs().tracks, 0);
        assert!(mock.writes.is_empty());
    }

    #[test]
    fn test_write_recording_control_commands_are_good_noops() {
        let mut medium = CdrBundleMedium::with_capacity(4096);
        let mut store = StoreMock::default();
        medium.set_test_write(true);
        for op in [
            MmcOp::Commit,
            MmcOp::Close { function: 1 },
            MmcOp::Close { function: 2 },
            MmcOp::ReserveTrack { size: 500 },
        ] {
            assert_eq!(
                run_control(&mut medium, &mut store, op, 4096),
                Completion::Good,
                "{op:?}"
            );
        }
        assert_eq!(medium.disc_state(), CdrDiscState::Blank);
        assert_eq!(medium.attrs().tracks, 0);
        assert!(!medium.needs_save());
        assert!(store.writes.is_empty());
        assert!(store.syncs.is_empty());

        // RESERVE TRACK keeps its geometry validation even while simulating.
        for size in [299, 4097] {
            assert_eq!(
                medium.begin(MmcOp::ReserveTrack { size }),
                Err(Completion::Check(INVALID_FIELD)),
                "size {size}"
            );
        }
        assert_eq!(medium.attrs().tracks, 0);
    }

    #[test]
    fn test_write_does_not_swallow_an_open_track() {
        let mut medium = CdrBundleMedium::with_capacity(4096);
        let mut store = StoreMock::default();
        write_one(&mut medium, &mut store, 0);
        assert!(medium.open_track.is_some());

        // CLOSE must fall through to the real path: the open track is closed
        // and the resulting TOC save reaches storage, even in Test Write mode.
        medium.set_test_write(true);
        assert_eq!(
            run_control(&mut medium, &mut store, MmcOp::Close { function: 1 }, 4096),
            Completion::Good
        );
        assert!(medium.open_track.is_none());
        assert_eq!(medium.disc_state(), CdrDiscState::Appendable);
        assert!(
            store
                .writes
                .iter()
                .any(|(resource, _, _)| *resource == TOC_RESOURCE_0 || *resource == TOC_RESOURCE_1),
            "the close saved a TOC slot: {:?}",
            store.writes
        );
        assert_eq!(medium.attrs().tracks, 1);
    }

    /// Burn one block and finalize, optionally after a simulated write.
    fn burn_after_simulation(simulate: bool) -> (CdrBundleMedium, StoreMock) {
        let mut medium = CdrBundleMedium::with_capacity(4096);
        let mut store = StoreMock::default();
        if simulate {
            medium.set_test_write(true);
            let payload = std::vec![0x77u8; 3 * 2048];
            assert_eq!(
                run_write(&mut medium, &mut store, 0, 3, &payload, 2048),
                Completion::Good
            );
            medium.set_test_write(false);
        }
        write_one(&mut medium, &mut store, 0);
        assert_eq!(close_track(&mut medium, &mut store, 1), Completion::Good);
        assert_eq!(close_track(&mut medium, &mut store, 2), Completion::Good);
        (medium, store)
    }

    #[test]
    fn a_real_burn_after_a_simulated_one_is_unchanged() {
        let (simulated, simulated_store) = burn_after_simulation(true);
        let (plain, plain_store) = burn_after_simulation(false);

        assert_eq!(simulated.disc_state(), CdrDiscState::Finalized);
        assert_eq!(simulated.disc_info(), plain.disc_info());
        assert_eq!(simulated.attrs(), plain.attrs());
        assert_eq!(simulated.track(1), plain.track(1));
        assert_eq!(
            simulated.track_numbers().collect::<std::vec::Vec<_>>(),
            std::vec![1]
        );

        // The simulated data phase left no trace: both burns produce the same
        // TOC slots and the same backing operations.
        assert_eq!(simulated_store.slot(0), plain_store.slot(0));
        assert_eq!(simulated_store.slot(1), plain_store.slot(1));
        assert_eq!(simulated_store.writes, plain_store.writes);
        assert_eq!(simulated_store.syncs, plain_store.syncs);
    }

    #[test]
    fn aborted_simulated_write_leaves_the_medium_blank_and_usable() {
        let mut medium = CdrBundleMedium::with_capacity(4096);
        let mut mock = Mock::default();
        medium.set_test_write(true);
        let mut data = std::vec![0u8; 2048];
        assert_eq!(medium.begin(MmcOp::Write { lba: 0, blocks: 4 }), Ok(()));
        match medium.poll(Feedback::begin(), &mut data) {
            PollStep::Publish(plan) => assert_eq!(plan.bytes, 4 * 2048),
            other => panic!("expected test-write publish, got {other:?}"),
        }
        match medium.poll(Feedback::plan_accepted(), &mut data) {
            PollStep::Receive { buf, .. } => buf.fill(0xAA),
            other => panic!("expected test-write receive, got {other:?}"),
        }
        match medium.poll(
            Feedback::host_received(HostReceipt::test(2048, None)),
            &mut data,
        ) {
            PollStep::Receive { buf, .. } => assert_eq!(buf.len(), 2048),
            other => panic!("expected the second chunk, got {other:?}"),
        }

        medium.interrupt(
            InterruptReason::Disconnect,
            KnownEffects {
                confirmed_write: 2048,
                ..KnownEffects::NONE
            },
        );
        assert!(!medium.active());
        assert_eq!(medium.disc_state(), CdrDiscState::Blank);
        assert_eq!(medium.attrs().tracks, 0);
        assert!(!medium.needs_save());
        assert!(mock.writes.is_empty());

        // The medium is still usable for a real burn.
        medium.set_test_write(false);
        write_one(&mut medium, &mut mock, 0);
        assert_eq!(close_track(&mut medium, &mut mock, 1), Completion::Good);
        assert_eq!(close_track(&mut medium, &mut mock, 2), Completion::Good);
        assert_eq!(medium.disc_state(), CdrDiscState::Finalized);
    }

    #[test]
    fn audio_write_stores_2352_byte_sectors_and_reads_back() {
        let blocks: u16 = 4;
        let payload: std::vec::Vec<u8> = (0..usize::from(blocks) * 2352)
            .map(|index| (index as u8).wrapping_mul(7).wrapping_add(3))
            .collect();
        let mut medium = CdrBundleMedium::with_capacity(4096);
        let mut store = StoreMock::default();
        assert_eq!(
            run_write_kind(
                &mut medium,
                &mut store,
                0,
                blocks,
                &payload,
                4096,
                SectorKind::Audio2352,
            ),
            Completion::Good
        );

        // The track resource holds 2352 bytes per logical block, while the
        // LBA/NWA accounting stays in 2048-byte blocks.
        assert_eq!(
            store.mem.get(&track_resource(1)).map(std::vec::Vec::len),
            Some(usize::from(blocks) * 2352)
        );
        let track = medium.track(1).expect("track 1");
        assert_eq!(track.kind, TrackKind::Audio);
        assert_eq!(track.blocks, u64::from(blocks));
        assert_eq!(
            medium.track_info(TrackInfoRequest::Number(1)).unwrap().nwa,
            4
        );

        // READ CD CD-DA reads the exact 2352-byte sectors back.
        let (read, completion) = run_read_kind(
            &mut medium,
            &mut store,
            0,
            blocks,
            SectorKind::Audio2352,
            4096,
        );
        assert_eq!(completion, Completion::Good);
        assert_eq!(read, payload);

        // READ(10) and a data READ CD have a different block size and cannot
        // address an audio track.
        assert_eq!(
            medium.begin(MmcOp::Read { lba: 0, blocks: 1 }),
            Err(Completion::Check(ILLEGAL_MODE_FOR_THIS_TRACK))
        );
        assert_eq!(
            medium.begin(MmcOp::ReadSectors {
                lba: 0,
                blocks: 1,
                kind: SectorKind::Data2048,
            }),
            Err(Completion::Check(ILLEGAL_MODE_FOR_THIS_TRACK))
        );
    }

    #[test]
    fn audio_gap_read_zero_fills_2352_byte_sectors_without_storage_io() {
        let mut medium = CdrBundleMedium::with_capacity(4096);
        let mut mock = Mock::default();
        assert_eq!(
            run_write_kind(
                &mut medium,
                &mut mock,
                0,
                1,
                &std::vec![0x5A; 2352],
                4096,
                SectorKind::Audio2352,
            ),
            Completion::Good
        );
        assert_eq!(close_track(&mut medium, &mut mock, 1), Completion::Good);
        // The closed track covers 0..300, so 300..450 is the pre-gap of the
        // next track (which does not exist yet).
        mock.reads.clear();
        let (read, completion) = run_read_kind(
            &mut medium,
            &mut mock,
            300,
            150,
            SectorKind::Audio2352,
            150 * 2352,
        );
        assert_eq!(completion, Completion::Good);
        assert_eq!(read.len(), 150 * 2352);
        assert!(read.iter().all(|byte| *byte == 0));
        assert!(mock.reads.is_empty(), "a gap read issues no storage IO");
    }

    #[test]
    fn mixed_mode_audio_and_data_tracks_keep_their_sector_sizes() {
        let audio: std::vec::Vec<u8> = (0..2 * 2352)
            .map(|index| (index as u8).wrapping_mul(11))
            .collect();
        let data: std::vec::Vec<u8> = (0..3 * 2048)
            .map(|index| (index as u8).wrapping_mul(5).wrapping_add(1))
            .collect();
        let mut medium = CdrBundleMedium::with_capacity(4096);
        let mut store = StoreMock::default();
        assert_eq!(
            run_write_kind(
                &mut medium,
                &mut store,
                0,
                2,
                &audio,
                4096,
                SectorKind::Audio2352,
            ),
            Completion::Good
        );
        assert_eq!(close_track(&mut medium, &mut store, 1), Completion::Good);
        // Track 1 pads to 300 blocks, so the data track starts after the
        // 150-block pre-gap at LBA 450.
        assert_eq!(medium.current_nwa(), 450);
        assert_eq!(
            run_write_kind(
                &mut medium,
                &mut store,
                450,
                3,
                &data,
                4096,
                SectorKind::Data2048,
            ),
            Completion::Good
        );
        assert_eq!(medium.track(1).expect("audio").kind, TrackKind::Audio);
        assert_eq!(medium.track(2).expect("data").kind, TrackKind::Data);

        let (read_audio, completion) =
            run_read_kind(&mut medium, &mut store, 0, 2, SectorKind::Audio2352, 4096);
        assert_eq!(completion, Completion::Good);
        assert_eq!(read_audio, audio);
        let (read_data, completion) =
            run_read_kind(&mut medium, &mut store, 450, 3, SectorKind::Data2048, 4096);
        assert_eq!(completion, Completion::Good);
        assert_eq!(read_data, data);

        // A read that spans both sector sizes has no valid interpretation.
        assert_eq!(
            medium.begin(MmcOp::ReadSectors {
                lba: 0,
                blocks: 451,
                kind: SectorKind::Audio2352,
            }),
            Err(Completion::Check(ILLEGAL_MODE_FOR_THIS_TRACK))
        );
        assert_eq!(
            medium.begin(MmcOp::Read { lba: 0, blocks: 1 }),
            Err(Completion::Check(ILLEGAL_MODE_FOR_THIS_TRACK))
        );
        // A CD-DA READ CD cannot address the data track either.
        assert_eq!(
            medium.begin(MmcOp::ReadSectors {
                lba: 450,
                blocks: 1,
                kind: SectorKind::Audio2352,
            }),
            Err(Completion::Check(ILLEGAL_MODE_FOR_THIS_TRACK))
        );

        // Finalize, persist and restore: both kinds and both payloads survive.
        assert_eq!(close_track(&mut medium, &mut store, 1), Completion::Good);
        assert_eq!(close_track(&mut medium, &mut store, 2), Completion::Good);
        assert_eq!(medium.disc_state(), CdrDiscState::Finalized);
        let slot = medium.current_slot();
        let mut reopened =
            CdrBundleMedium::open(&store.slot(slot), 4096, Recovery::Delete).expect("reopened");
        assert_eq!(reopened.track(1).expect("audio").kind, TrackKind::Audio);
        assert_eq!(reopened.track(2).expect("data").kind, TrackKind::Data);
        let (read_audio, completion) =
            run_read_kind(&mut reopened, &mut store, 0, 2, SectorKind::Audio2352, 4096);
        assert_eq!(completion, Completion::Good);
        assert_eq!(read_audio, audio);
        let (read_data, completion) = run_read_kind(
            &mut reopened,
            &mut store,
            450,
            3,
            SectorKind::Data2048,
            4096,
        );
        assert_eq!(completion, Completion::Good);
        assert_eq!(read_data, data);
    }

    #[test]
    fn audio_track_after_data_uses_in_track_byte_offsets() {
        let audio_a: std::vec::Vec<u8> = (0..2 * 2352)
            .map(|index| (index as u8).wrapping_mul(3).wrapping_add(7))
            .collect();
        let audio_b: std::vec::Vec<u8> = (0..3 * 2352)
            .map(|index| (index as u8).wrapping_mul(17).wrapping_add(1))
            .collect();
        let mut medium = CdrBundleMedium::with_capacity(4096);
        let mut store = StoreMock::default();
        write_one(&mut medium, &mut store, 0);
        assert_eq!(close_track(&mut medium, &mut store, 1), Completion::Good);
        assert_eq!(medium.current_nwa(), 450);

        // Track 2 is audio and starts at LBA 450; its second write is at the
        // non-zero in-track offset LBA 452 = byte offset 2 * 2352.
        assert_eq!(
            run_write_kind(
                &mut medium,
                &mut store,
                450,
                2,
                &audio_a,
                16384,
                SectorKind::Audio2352,
            ),
            Completion::Good
        );
        assert_eq!(
            run_write_kind(
                &mut medium,
                &mut store,
                452,
                3,
                &audio_b,
                16384,
                SectorKind::Audio2352,
            ),
            Completion::Good
        );
        let resource = track_resource(2);
        let audio_writes: std::vec::Vec<_> = store
            .writes
            .iter()
            .filter(|(found, _, _)| *found == resource)
            .copied()
            .collect();
        assert_eq!(
            audio_writes,
            std::vec![(resource, 0, 2 * 2352), (resource, 2 * 2352, 3 * 2352)]
        );
        let bytes = store.mem.get(&resource).expect("track 2 payload");
        assert_eq!(bytes.len(), 5 * 2352);
        assert_eq!(&bytes[..2 * 2352], audio_a.as_slice());
        assert_eq!(&bytes[2 * 2352..], audio_b.as_slice());

        let expected: std::vec::Vec<u8> = audio_a.iter().chain(&audio_b).copied().collect();
        let (read, completion) =
            run_read_kind(&mut medium, &mut store, 450, 5, SectorKind::Audio2352, 4096);
        assert_eq!(completion, Completion::Good);
        assert_eq!(read, expected);
    }

    #[test]
    fn reserved_track_adopts_the_audio_kind_on_its_first_write() {
        let mut medium = CdrBundleMedium::with_capacity(4096);
        let mut store = StoreMock::default();
        assert_eq!(
            reserve_medium(&mut medium, &mut store, 500),
            Completion::Good
        );
        // RESERVE TRACK carries no recording mode; the placeholder is data.
        assert_eq!(medium.track(1).expect("reserved").kind, TrackKind::Data);
        let payload = std::vec![0x7Bu8; 2352];
        assert_eq!(
            run_write_kind(
                &mut medium,
                &mut store,
                0,
                1,
                &payload,
                4096,
                SectorKind::Audio2352,
            ),
            Completion::Good
        );
        assert_eq!(medium.track(1).expect("audio").kind, TrackKind::Audio);
        assert_eq!(
            store.mem.get(&track_resource(1)).map(std::vec::Vec::len),
            Some(2352),
            "the resource holds one 2352-byte audio sector"
        );
        let (read, completion) =
            run_read_kind(&mut medium, &mut store, 0, 1, SectorKind::Audio2352, 4096);
        assert_eq!(completion, Completion::Good);
        assert_eq!(read, payload);
    }
}
