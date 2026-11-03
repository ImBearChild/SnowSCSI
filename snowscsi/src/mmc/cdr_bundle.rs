//! Sequential write-once CD-R medium.
//!
//! The medium models a CD-R whose payload lives in the application's storage:
//! each track is a separate storage resource (`16 + track_number`) and reads
//! and writes become [`StorageOp`] at the track-relative byte offset. The
//! track/session layout is held in memory only; this module owns no backing
//! driver and performs no persistence.
//!
//! Writing follows the TAO shape a recorder uses: the first `WRITE(10)` may
//! land on the next writable address without a preceding `RESERVE TRACK`, and
//! `SYNCHRONIZE CACHE` pads and closes the open track. A closed track starts
//! the next one after a 150-block pre-gap; pre-gaps and unwritten regions read
//! as zeros without touching storage.
//!
//! [`CdrBundleMedium`] never allocates: the track and session tables are
//! fixed-capacity `heapless::Vec`s.

use heapless::Vec;

use super::attrs::{
    DiscInfo, DiscStatus, MmcAttrs, MmcWriteMode, SectorKind, Session, Track, TrackInfo,
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
/// Pre-gap before every track after the first.
const PREGAP_BLOCKS: u64 = 150;
/// Minimum recorded length of a closed track.
const MIN_TRACK_BLOCKS: u64 = 300;
/// Start address of the disc lead-in.
const MEDIUM_LEADIN: i64 = -11077;
/// Fixed track-table capacity.
const MAX_TRACKS: usize = 99;
/// Fixed session-table capacity.
const MAX_SESSIONS: usize = 16;
/// Features that are Current for a CD-R.
const CDR_FEATURES: &[u16] = &[0x0010, 0x001E, 0x0021, 0x002D];

/// ILLEGAL REQUEST / INVALID ADDRESS FOR WRITE.
const INVALID_ADDRESS_FOR_WRITE: Sense = Sense::new(0x05, 0x21, 0x02);
/// ILLEGAL REQUEST / SESSION FIXATION ERROR - INCOMPLETE TRACK IN SESSION.
const SESSION_FIXATION_INCOMPLETE_TRACK: Sense = Sense::new(0x05, 0x72, 0x03);
/// ILLEGAL REQUEST / EMPTY OR PARTIALLY WRITTEN RESERVED TRACK.
const EMPTY_OR_PARTIALLY_WRITTEN_RESERVED_TRACK: Sense = Sense::new(0x05, 0x72, 0x04);

/// Standard CD-R capacities in logical blocks.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CdrCapacity {
    /// 74-minute disc.
    Cdr74,
    /// 80-minute disc.
    Cdr80,
    /// 90-minute disc.
    Cdr90,
    /// 99-minute disc.
    Cdr99,
}

impl CdrCapacity {
    /// Addressable logical blocks (`minutes * 60 * 75`).
    #[must_use]
    pub const fn sectors(self) -> u64 {
        let minutes: u64 = match self {
            Self::Cdr74 => 74,
            Self::Cdr80 => 80,
            Self::Cdr90 => 90,
            Self::Cdr99 => 99,
        };
        minutes * 60 * 75
    }
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
    /// Completion fixed; the operation is over.
    Done,
}

/// One recorded, reserved or open track.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct TrackEntry {
    number: u16,
    session: u16,
    /// First block of the track, including the pre-gap.
    start_lba: u64,
    /// First user block of the track.
    data_start_lba: u64,
    /// Blocks reserved for the track (`0` means unallocated).
    allocated: u64,
    /// Recorded (or padded) length in blocks.
    length: u64,
    /// Blocks actually recorded; a close may pad `length` beyond this.
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
struct SessionEntry {
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
    /// Read `bytes` starting at `lba`.
    Read { lba: u64, bytes: u32 },
    /// Write `bytes` at `offset` into the track's resource.
    Write { track: u16, offset: u64, bytes: u32 },
    /// Flush the backing.
    Sync,
}

/// In-memory sequential CD-R medium.
pub struct CdrBundleMedium {
    capacity: u64,
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
    /// The current write command created its track implicitly.
    implicit_created: bool,
}

impl CdrBundleMedium {
    /// Build a blank medium with a standard capacity.
    #[must_use]
    pub fn blank(capacity: CdrCapacity) -> Self {
        Self::with_capacity(capacity.sectors())
    }

    /// Build a blank medium with an explicit sector count.
    #[must_use]
    pub fn with_capacity(sectors: u64) -> Self {
        Self {
            capacity: sectors,
            disc: CdrDiscState::Blank,
            tracks: Vec::new(),
            sessions: Vec::new(),
            open_track: None,
            op: None,
            phase: CdrBundleState::Idle,
            progress: 0,
            chunk_len: 0,
            implicit_created: false,
        }
    }

    /// Addressable logical blocks.
    #[must_use]
    pub const fn capacity_sectors(&self) -> u64 {
        self.capacity
    }

    /// Start address of the disc lead-in.
    #[must_use]
    pub const fn medium_leadin(&self) -> i64 {
        MEDIUM_LEADIN
    }

    /// Current disc-level state.
    #[must_use]
    pub const fn disc_state(&self) -> CdrDiscState {
        self.disc
    }

    /// Clear the operation state.
    fn reset(&mut self) {
        self.op = None;
        self.phase = CdrBundleState::Idle;
        self.progress = 0;
        self.chunk_len = 0;
        self.implicit_created = false;
    }

    /// Total bytes selected by the admitted operation.
    fn total_bytes(&self) -> usize {
        match self.op {
            Some(Op::Read { bytes, .. } | Op::Write { bytes, .. }) => bytes as usize,
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
    fn read_range(&self, lba: u64, blocks: u16) -> Result<u32, Completion> {
        if blocks == 0 {
            return Ok(0);
        }
        let end = lba
            .checked_add(u64::from(blocks))
            .ok_or(Completion::Check(LBA_OUT_OF_RANGE))?;
        if end > self.capacity {
            return Err(Completion::Check(LBA_OUT_OF_RANGE));
        }
        let bytes = u64::from(blocks) * u64::from(BLOCK_LEN);
        if bytes > u64::from(u32::MAX) {
            return Err(Completion::Check(INVALID_FIELD));
        }
        Ok(bytes as u32)
    }

    /// Start positions of the next track: `(start_lba, data_start_lba)`.
    fn next_positions(&self) -> (u64, u64) {
        match self.tracks.last() {
            None => (0, 0),
            Some(last) => {
                let start = last.data_start_lba.saturating_add(last.length);
                (start, start.saturating_add(PREGAP_BLOCKS))
            }
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
            Some(_) => self.next_positions().1,
        }
    }

    /// Find a track by number.
    fn track_entry(&self, number: u16) -> Option<&TrackEntry> {
        self.tracks.iter().find(|track| track.number == number)
    }

    /// Open a session for `track` if the last session is already closed.
    fn ensure_session(&mut self, track: u16, start_lba: u64) -> Result<(), Completion> {
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
                start_lba,
                lead_out_lba: start_lba,
                closed: false,
            })
            .map_err(|_| Completion::Check(INVALID_FIELD))
    }

    /// Add a track and make it the open one.
    fn push_track(
        &mut self,
        number: u16,
        start_lba: u64,
        data_start_lba: u64,
        allocated: u64,
        status: TrackStatus,
        reserved: bool,
    ) -> Result<(), Completion> {
        self.ensure_session(number, start_lba)?;
        self.tracks
            .push(TrackEntry {
                number,
                session: self.sessions.last().map_or(1, |session| session.number),
                start_lba,
                data_start_lba,
                allocated,
                length: 0,
                written: 0,
                nwa: data_start_lba,
                status,
                kind: TrackKind::Data,
                reserved,
            })
            .map_err(|_| Completion::Check(INVALID_FIELD))?;
        self.open_track = Some(number);
        self.disc = CdrDiscState::Appendable;
        Ok(())
    }

    /// Admit a write, creating an implicit track when none is open.
    fn admit_write(&mut self, lba: u64, blocks: u16) -> Result<(), Completion> {
        let end = lba
            .checked_add(u64::from(blocks))
            .ok_or(Completion::Check(LBA_OUT_OF_RANGE))?;
        if end > self.capacity {
            return Err(Completion::Check(LBA_OUT_OF_RANGE));
        }

        let (number, start_lba, data_start_lba, nwa, limit) = match self.open_track {
            Some(number) => {
                let track = self
                    .track_entry(number)
                    .ok_or(Completion::Check(INTERNAL_FAILURE))?;
                let limit = if track.reserved {
                    track.data_start_lba.saturating_add(track.allocated)
                } else {
                    self.capacity
                }
                .min(self.capacity);
                (
                    number,
                    track.start_lba,
                    track.data_start_lba,
                    track.nwa,
                    limit,
                )
            }
            None => {
                let number = self.tracks.len() as u16 + 1;
                if usize::from(number) > MAX_TRACKS {
                    return Err(Completion::Check(INVALID_FIELD));
                }
                let (start_lba, data_start_lba) = self.next_positions();
                (
                    number,
                    start_lba,
                    data_start_lba,
                    data_start_lba,
                    self.capacity,
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
                start_lba,
                data_start_lba,
                0,
                TrackStatus::Incomplete,
                false,
            )?;
            self.implicit_created = true;
        } else if let Some(track) = self
            .tracks
            .iter_mut()
            .find(|track| track.number == number && track.status != TrackStatus::Complete)
        {
            track.status = TrackStatus::Incomplete;
        }

        let offset = (lba - data_start_lba)
            .checked_mul(u64::from(BLOCK_LEN))
            .ok_or(Completion::Check(LBA_OUT_OF_RANGE))?;
        let bytes = u64::from(blocks) * u64::from(BLOCK_LEN);
        if bytes > u64::from(u32::MAX) {
            return Err(Completion::Check(INVALID_FIELD));
        }
        self.op = Some(Op::Write {
            track: number,
            offset,
            bytes: bytes as u32,
        });
        Ok(())
    }

    /// Admit `RESERVE TRACK`; it changes the write state without storage IO.
    fn reserve_track(&mut self, size: u32) -> Result<(), Completion> {
        if self.disc == CdrDiscState::Finalized {
            return Err(Completion::Check(WRITE_PROTECTED));
        }
        let size = u64::from(size);
        if size < MIN_TRACK_BLOCKS {
            return Err(Completion::Check(INVALID_FIELD));
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
        let number = self.tracks.len() as u16 + 1;
        if usize::from(number) > MAX_TRACKS {
            return Err(Completion::Check(INVALID_FIELD));
        }
        let (start_lba, data_start_lba) = self.next_positions();
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
        self.push_track(
            number,
            start_lba,
            data_start_lba,
            size,
            TrackStatus::Reserved,
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
        // Closing an empty session (blank disc, or only empty/reserved tracks)
        // is a success no-op; it must not latch the disc write-protected.
        let has_data = self.sessions.last().is_some_and(|session| {
            self.tracks
                .iter()
                .any(|track| track.session == session.number && track.written > 0)
        });
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

    /// Issue the next read segment, or zero-fill an unrecorded one.
    fn next_read_step<'a>(&mut self, data: &'a mut [u8]) -> PollStep<'a> {
        let total = self.total_bytes();
        let remaining = total.saturating_sub(self.progress as usize);
        if remaining == 0 {
            return self.finish(Completion::Good);
        }
        if data.is_empty() {
            return self.finish(Completion::Check(INTERNAL_FAILURE));
        }
        let max_chunk = data.len();
        let Some(Op::Read { lba, .. }) = self.op else {
            return self.finish(Completion::Check(INTERNAL_FAILURE));
        };
        let pos = lba
            .saturating_mul(u64::from(BLOCK_LEN))
            .saturating_add(u64::from(self.progress));
        let current_lba = pos / u64::from(BLOCK_LEN);

        let recorded = self
            .tracks
            .iter()
            .find(|track| {
                track.written > 0
                    && (track.data_start_lba..track.data_start_lba.saturating_add(track.written))
                        .contains(&current_lba)
            })
            .copied();

        if let Some(track) = recorded {
            let segment_end = track
                .data_start_lba
                .saturating_add(track.written)
                .saturating_mul(u64::from(BLOCK_LEN));
            let available = segment_end.saturating_sub(pos);
            let chunk = (remaining as u64).min(max_chunk as u64).min(available) as usize;
            if chunk == 0 {
                return self.finish(Completion::Check(INTERNAL_FAILURE));
            }
            let offset =
                pos.saturating_sub(track.data_start_lba.saturating_mul(u64::from(BLOCK_LEN)));
            self.chunk_len = chunk;
            self.phase = CdrBundleState::ReadIo;
            return PollStep::Io(StorageOp::Read {
                resource: 16 + track.number,
                offset,
                buf: &mut data[..chunk],
            });
        }

        let mut boundary = pos.saturating_add(remaining as u64);
        for track in &self.tracks {
            let at = track.data_start_lba.saturating_mul(u64::from(BLOCK_LEN));
            if at > pos && at < boundary {
                boundary = at;
            }
        }
        let chunk = (remaining as u64)
            .min(max_chunk as u64)
            .min(boundary.saturating_sub(pos)) as usize;
        if chunk == 0 {
            return self.finish(Completion::Check(INTERNAL_FAILURE));
        }
        for byte in &mut data[..chunk] {
            *byte = 0;
        }
        self.chunk_len = chunk;
        self.phase = CdrBundleState::Deliver;
        PollStep::Send {
            bytes: &data[..chunk],
            prefetch: None,
        }
    }

    /// Remove a track the current command created implicitly and that never
    /// received a confirmed block.
    fn drop_implicit_track(&mut self, number: u16) {
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
        MmcAttrs {
            write_mode: MmcWriteMode::WriteOnce,
            block_len: BLOCK_LEN,
            sectors: self.capacity,
            tracks: self.tracks.len() as u16,
            sessions: self.sessions.len() as u16,
            write_protected: self.disc == CdrDiscState::Finalized,
            needs_recovery: false,
            profile: 0x0009,
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
        self.implicit_created = false;
        match op {
            MmcOp::Read { lba, blocks } => {
                let bytes = self.read_range(lba, blocks)?;
                if bytes == 0 {
                    return Err(Completion::Good);
                }
                self.op = Some(Op::Read { lba, bytes });
            }
            MmcOp::ReadSectors { lba, blocks, kind } => match kind {
                SectorKind::Auto | SectorKind::Data2048 => {
                    let bytes = self.read_range(lba, blocks)?;
                    if bytes == 0 {
                        return Err(Completion::Good);
                    }
                    self.op = Some(Op::Read { lba, bytes });
                }
                // No audio plane on this data medium.
                SectorKind::Audio2352 => return Err(Completion::Check(INVALID_FIELD)),
            },
            MmcOp::Write { lba, blocks } => {
                if self.disc == CdrDiscState::Finalized {
                    return Err(Completion::Check(WRITE_PROTECTED));
                }
                if blocks == 0 {
                    return Err(Completion::Good);
                }
                self.admit_write(lba, blocks)?;
            }
            MmcOp::WriteSectors { lba, blocks, kind } => match kind {
                SectorKind::Auto | SectorKind::Data2048 => {
                    if self.disc == CdrDiscState::Finalized {
                        return Err(Completion::Check(WRITE_PROTECTED));
                    }
                    if blocks == 0 {
                        return Err(Completion::Good);
                    }
                    self.admit_write(lba, blocks)?;
                }
                SectorKind::Audio2352 => return Err(Completion::Check(INVALID_FIELD)),
            },
            MmcOp::Commit => {
                // A TAO recorder relies on SYNCHRONIZE CACHE to pad and close
                // the track before it finalizes the disc.
                self.close_open_track();
                self.op = Some(Op::Sync);
            }
            MmcOp::Close { function } => match function {
                1 => {
                    self.close_open_track();
                    return Err(Completion::Good);
                }
                2 => {
                    self.finalize()?;
                    return Err(Completion::Good);
                }
                _ => return Err(Completion::Check(INVALID_FIELD)),
            },
            MmcOp::ReserveTrack { size } => {
                self.reserve_track(size)?;
                return Err(Completion::Good);
            }
            // FORMAT UNIT/BLANK is not erasable on a write-once medium; the
            // descriptor commands are encoded by the drive.
            MmcOp::Format { .. } | MmcOp::TrackInfo { .. } | MmcOp::DiscInfo => {
                return Err(Completion::Check(INVALID_FIELD))
            }
        }
        self.phase = CdrBundleState::Publish;
        Ok(())
    }

    fn poll<'a>(&mut self, fb: Feedback, data: &'a mut [u8]) -> PollStep<'a> {
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
                Some(Op::Sync) => {
                    self.phase = CdrBundleState::SyncIo;
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
                PollStep::Send {
                    bytes: &data[..chunk],
                    prefetch: None,
                }
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
                let Some(Op::Write { track, offset, .. }) = self.op else {
                    return self.finish(Completion::Check(INTERNAL_FAILURE));
                };
                let at = offset.saturating_add(u64::from(self.progress));
                self.phase = CdrBundleState::WriteIo;
                PollStep::Io(StorageOp::Write {
                    resource: 16 + track,
                    offset: at,
                    buf: &data[..accepted],
                })
            }
            (CdrBundleState::WriteIo, FeedbackKind::IoDone) => {
                let chunk = self.chunk_len;
                let Some(receipt) = fb.io() else {
                    return self.finish(Completion::Check(INTERNAL_FAILURE));
                };
                let confirmed = receipt.confirmed().min(chunk);
                let before = u64::from(self.progress) / u64::from(BLOCK_LEN);
                self.progress = self.progress.saturating_add(confirmed as u32);
                let after = u64::from(self.progress) / u64::from(BLOCK_LEN);
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
            _ => PollStep::Idle,
        }
    }

    fn active(&self) -> bool {
        self.op.is_some()
    }

    fn interrupt(&mut self, _reason: InterruptReason, known: KnownEffects) {
        if let Some(Op::Write { track, .. }) = self.op {
            // A write receipt the runner already observed may not have reached
            // the medium. Book its confirmed whole blocks before dropping the
            // operation state.
            let remaining = (self.total_bytes() as u64).saturating_sub(u64::from(self.progress));
            let confirmed = known.confirmed_write.min(remaining) as u32;
            let before = u64::from(self.progress) / u64::from(BLOCK_LEN);
            let after = u64::from(self.progress.saturating_add(confirmed)) / u64::from(BLOCK_LEN);
            self.confirm_write(after.saturating_sub(before));

            if self.implicit_created
                && self
                    .track_entry(track)
                    .is_some_and(|entry| entry.written == 0)
            {
                self.drop_implicit_track(track);
            }
        }
        self.reset();
    }

    fn commit(&mut self) -> Result<(), Completion> {
        Ok(())
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
            TrackInfoRequest::Number(0) => Some(lead_in_info()),
            TrackInfoRequest::Number(0xFF) => Some(self.invisible_info()),
            TrackInfoRequest::Number(number) => {
                if usize::from(number) == self.tracks.len() + 1 {
                    Some(self.invisible_info())
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
        let sessions = match self.disc {
            CdrDiscState::Blank => 1,
            CdrDiscState::Appendable => {
                self.sessions
                    .iter()
                    .filter(|session| session.closed)
                    .count() as u16
                    + 1
            }
            CdrDiscState::Finalized => self.sessions.len().max(1) as u16,
        };
        let last_session = self.sessions.last();
        let last_session_lba = if self.disc == CdrDiscState::Blank {
            0
        } else {
            last_session
                .map(|session| session.lead_out_lba.saturating_sub(1))
                .unwrap_or(0)
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
            erasable: false,
            first_track: 1,
            first_track_last_session: last_session.map_or(1, |session| session.first_track),
            last_track_last_session: last_session.map_or(1, |session| session.last_track),
            last_session_state: match self.disc {
                CdrDiscState::Blank => 0,
                CdrDiscState::Appendable => 1,
                CdrDiscState::Finalized => 3,
            },
            last_session_lead_in: match self.disc {
                CdrDiscState::Appendable => Some(MEDIUM_LEADIN),
                CdrDiscState::Blank | CdrDiscState::Finalized => None,
            },
            last_possible_lead_out: match self.disc {
                CdrDiscState::Finalized => None,
                CdrDiscState::Blank | CdrDiscState::Appendable => {
                    Some(signed_lba(self.capacity.saturating_sub(2)))
                }
            },
            disc_type: 0xFF,
        }
    }
}

/// The lead-in pseudo-track (`READ TRACK INFORMATION` number 0).
fn lead_in_info() -> TrackInfo {
    TrackInfo {
        number: 0,
        session: 0,
        start_lba: MEDIUM_LEADIN,
        length: 0,
        allocated: 0,
        nwa: 0,
        free_blocks: 0,
        status: TrackStatus::Complete,
        kind: TrackKind::Data,
        packet: false,
    }
}

/// Project a recorded track into the track-information view.
fn recorded_info(track: &TrackEntry, capacity: u64) -> TrackInfo {
    let consumed = track.nwa.saturating_sub(track.data_start_lba);
    let free_blocks = match track.status {
        TrackStatus::Complete => 0,
        TrackStatus::Invisible => track.allocated,
        TrackStatus::Reserved | TrackStatus::Incomplete => {
            if track.reserved {
                track.allocated.saturating_sub(consumed)
            } else {
                capacity.saturating_sub(track.data_start_lba.saturating_add(track.length))
            }
        }
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
        let (_, data_start_lba) = self.next_positions();
        let allocated = self.capacity.saturating_sub(data_start_lba);
        TrackInfo {
            number,
            session: self.sessions.len() as u16 + 1,
            start_lba: signed_lba(data_start_lba),
            length: 0,
            allocated,
            nwa: self.current_nwa(),
            free_blocks: allocated,
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
    use crate::core::WRITE_ERROR;

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

    fn run_read(
        medium: &mut CdrBundleMedium,
        mock: &mut Mock,
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

    fn run_write(
        medium: &mut CdrBundleMedium,
        mock: &mut Mock,
        lba: u64,
        blocks: u16,
        payload: &[u8],
        bank: usize,
    ) -> Completion {
        let mut data = std::vec![0u8; bank];
        assert_eq!(medium.begin(MmcOp::Write { lba, blocks }), Ok(()));
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
                    mock.write_from(resource, offset, buf);
                    feedback = Feedback::io_done(IoReceipt::test(buf.len(), None, Effect::Known));
                }
                PollStep::Complete(completion) => {
                    assert_eq!(received, payload.len(), "every host byte was received");
                    return completion;
                }
                other => panic!("unexpected write step: {other:?}"),
            }
        }
    }

    fn run_commit(medium: &mut CdrBundleMedium, mock: &mut Mock) -> Completion {
        let mut data = [0u8; 0];
        assert_eq!(medium.begin(MmcOp::Commit), Ok(()));
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
                    mock.sync(resource);
                    feedback = Feedback::io_done(IoReceipt::test(0, None, Effect::Known));
                }
                PollStep::Complete(completion) => return completion,
                other => panic!("unexpected commit step: {other:?}"),
            }
        }
    }

    fn write_one(medium: &mut CdrBundleMedium, mock: &mut Mock, lba: u64) {
        let payload = std::vec![0x5Au8; 2048];
        assert_eq!(
            run_write(medium, mock, lba, 1, &payload, 2048),
            Completion::Good
        );
    }

    #[test]
    fn capacities_are_minutes_to_sectors() {
        assert_eq!(CdrCapacity::Cdr74.sectors(), 333_000);
        assert_eq!(CdrCapacity::Cdr80.sectors(), 360_000);
        assert_eq!(CdrCapacity::Cdr90.sectors(), 405_000);
        assert_eq!(CdrCapacity::Cdr99.sectors(), 445_500);
        let medium = CdrBundleMedium::blank(CdrCapacity::Cdr80);
        assert_eq!(medium.capacity_sectors(), 360_000);
        assert_eq!(medium.medium_leadin(), -11_077);
        assert_eq!(medium.disc_state(), CdrDiscState::Blank);
    }

    #[test]
    fn blank_attrs_disc_info_and_track_info() {
        let medium = CdrBundleMedium::blank(CdrCapacity::Cdr74);
        let attrs = medium.attrs();
        assert_eq!(attrs.write_mode, MmcWriteMode::WriteOnce);
        assert_eq!(attrs.block_len, 2048);
        assert_eq!(attrs.sectors, 333_000);
        assert_eq!(attrs.tracks, 0);
        assert_eq!(attrs.sessions, 0);
        assert!(!attrs.write_protected);
        assert!(!attrs.needs_recovery);
        assert_eq!(attrs.profile, 0x0009);
        assert_eq!(attrs.current_features, &[0x0010, 0x001E, 0x0021, 0x002D]);

        let info = medium.disc_info();
        assert_eq!(info.status, DiscStatus::Empty);
        assert_eq!(info.sessions, 1);
        assert_eq!(info.first_track, 1);
        assert_eq!(info.first_track_last_session, 1);
        assert_eq!(info.last_track_last_session, 1);
        assert_eq!(info.last_session_state, 0);
        assert_eq!(info.last_session_lead_in, None);
        assert_eq!(info.last_possible_lead_out, Some(332_998));
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
        assert_eq!(invisible.allocated, 333_000);
        assert_eq!(invisible.nwa, 0);
        assert_eq!(invisible.free_blocks, 333_000);
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
        assert_eq!(info.free_blocks, 359_998);
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

        assert_eq!(
            medium.begin(MmcOp::Close { function: 1 }),
            Err(Completion::Good)
        );
        assert_eq!(
            medium.begin(MmcOp::Close { function: 2 }),
            Err(Completion::Good)
        );
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
        assert_eq!(
            CdrBundleMedium::with_capacity(400).begin(MmcOp::ReserveTrack { size: 300 }),
            Err(Completion::Good)
        );
        assert_eq!(
            CdrBundleMedium::with_capacity(400).begin(MmcOp::ReserveTrack { size: 401 }),
            Err(Completion::Check(INVALID_FIELD))
        );

        assert_eq!(
            medium.begin(MmcOp::ReserveTrack { size: 500 }),
            Err(Completion::Good)
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

        assert_eq!(
            medium.begin(MmcOp::Close { function: 1 }),
            Err(Completion::Good)
        );
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
        assert_eq!(
            medium.begin(MmcOp::Close { function: 1 }),
            Err(Completion::Good)
        );

        // Track 2 starts at 300 and its user data starts at 450, leaving 700
        // blocks. The pre-gap counts against that space.
        assert_eq!(
            medium.begin(MmcOp::ReserveTrack { size: 551 }),
            Err(Completion::Check(INVALID_FIELD))
        );
        assert_eq!(
            medium.begin(MmcOp::ReserveTrack { size: 550 }),
            Err(Completion::Good)
        );
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

        assert_eq!(
            medium.begin(MmcOp::Close { function: 1 }),
            Err(Completion::Good)
        );
        assert_eq!(
            medium.begin(MmcOp::Close { function: 2 }),
            Err(Completion::Good)
        );
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
        assert_eq!(
            medium.begin(MmcOp::Close { function: 2 }),
            Err(Completion::Good)
        );
        assert_eq!(medium.disc_state(), CdrDiscState::Blank);
        assert!(!medium.attrs().write_protected);
    }

    #[test]
    fn finalize_rejects_a_reserved_track_without_data() {
        let mut medium = CdrBundleMedium::with_capacity(4096);
        assert_eq!(
            medium.begin(MmcOp::ReserveTrack { size: 500 }),
            Err(Completion::Good)
        );
        assert_eq!(
            medium.begin(MmcOp::Close { function: 2 }),
            Err(Completion::Check(EMPTY_OR_PARTIALLY_WRITTEN_RESERVED_TRACK))
        );
        // Closing the empty reserved track leaves it complete but empty, so
        // session fixation is still a no-op rather than a finalize.
        assert_eq!(
            medium.begin(MmcOp::Close { function: 1 }),
            Err(Completion::Good)
        );
        let closed = medium
            .track_info(TrackInfoRequest::Number(1))
            .expect("closed track");
        assert_eq!(closed.length, 500);
        assert_eq!(
            medium.begin(MmcOp::Close { function: 2 }),
            Err(Completion::Good)
        );
        assert_eq!(medium.disc_state(), CdrDiscState::Appendable);
        assert!(!medium.attrs().write_protected);
    }

    #[test]
    fn finalize_rejects_a_reserved_track_with_data() {
        let mut medium = CdrBundleMedium::with_capacity(4096);
        let mut mock = Mock::default();
        assert_eq!(
            medium.begin(MmcOp::ReserveTrack { size: 500 }),
            Err(Completion::Good)
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
        assert_eq!(mock.syncs, std::vec![0]);
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
        assert_eq!(
            medium.begin(MmcOp::Close { function: 1 }),
            Err(Completion::Good)
        );

        // Track 1 is padded to 300 blocks; track 2 starts at 300 and its user
        // data starts after a 150-block pre-gap at 450.
        write_one(&mut medium, &mut mock, 450);
        assert_eq!(
            medium.begin(MmcOp::Close { function: 1 }),
            Err(Completion::Good)
        );
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
        assert_eq!(
            medium.begin(MmcOp::Close { function: 1 }),
            Err(Completion::Good)
        );
        write_one(&mut medium, &mut mock, 450);
        assert_eq!(
            medium.begin(MmcOp::Close { function: 1 }),
            Err(Completion::Good)
        );
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
        assert_eq!(
            medium.begin(MmcOp::ReserveTrack { size: 500 }),
            Err(Completion::Good)
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

        assert_eq!(
            medium.begin(MmcOp::Close { function: 1 }),
            Err(Completion::Good)
        );
        // Track 2 starts at 500 and its first user block is 650.
        assert_eq!(
            medium.begin(MmcOp::ReserveTrack { size: 300 }),
            Err(Completion::Good)
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
}
