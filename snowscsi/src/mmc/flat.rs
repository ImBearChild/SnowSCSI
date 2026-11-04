//! Flat read-only CD medium.
//!
//! A single-track, single-session, finalized CD data medium with no backing
//! bytes of its own: reads become
//! [`StorageOp::Read`] at
//! `lba * 2048` and the runner's `Storage` adapter supplies the bytes. The
//! medium never allocates and owns only geometry plus the in-flight step state.
//!
//! Audio sectors and writes are rejected in [`MmcMedium::begin`] with no IO;
//! the drive handles the descriptor commands (TOC/DISC/TRACK) itself and
//! routes CLOSE TRACK SESSION here as a no-op success.

use super::attrs::{
    DiscInfo, DiscStatus, MmcAttrs, MmcWriteMode, SectorKind, Session, Track, TrackKind,
};
use super::medium::MmcMedium;
use super::op::MmcOp;
use crate::core::storage::StorageOp;
use crate::core::{
    storage_fault_sense, Completion, DataPlan, Direction, Effect, Feedback, FeedbackKind,
    InterruptReason, IoContext, KnownEffects, PollStep, COMMAND_ABORTED, INTERNAL_FAILURE,
    INVALID_FIELD, LBA_OUT_OF_RANGE, MEDIUM_ERROR, WRITE_PROTECTED,
};

/// CD data block length.
const BLOCK_LEN: u32 = 2048;

/// Public phase of the flat medium's in-flight operation.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum FlatState {
    /// No operation.
    Idle,
    /// Admitted; the data plan has not been published yet.
    Publish,
    /// READ: the backing read is being issued.
    ReadIo,
    /// READ: a speculative read of the next chunk is being issued.
    PrefetchIo,
    /// READ: waiting for the host send to complete.
    Deliver,
    /// COMMIT: the sync is being issued.
    SyncIo,
    /// COMMIT: waiting for the sync receipt.
    SyncWait,
    /// Completion fixed; the operation is over.
    Done,
}

/// Backing action selected by [`MmcMedium::begin`].
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Op {
    /// Read `bytes` from `offset`.
    Read { offset: u64, bytes: u32 },
    /// Flush the backing.
    Sync,
}

/// Flat, read-only CD data medium.
pub struct FlatCdMedium {
    attrs: MmcAttrs,
    op: Option<Op>,
    phase: FlatState,
    /// Bytes of the read already delivered to the host.
    progress: u32,
    /// The staged chunk lives in the alternate caller bank (`alt`), so the
    /// next `Send` must take it from there.
    chunk_in_alt: bool,
    /// Bytes of the chunk handed to the host, in the bank named by
    /// `chunk_in_alt`.
    chunk_len: usize,
    /// Bank of the chunk the staged `Send` prefetches for the following step.
    next_in_alt: bool,
    /// Bytes of that prefetched chunk.
    next_len: usize,
}

impl FlatCdMedium {
    /// Build a read-only medium from a byte capacity; the sector count is
    /// `capacity_bytes / 2048` (floor, design offset 8).
    #[must_use]
    pub fn new(capacity_bytes: u64) -> Self {
        Self::read_only(capacity_bytes / u64::from(BLOCK_LEN))
    }

    /// Build a read-only medium with an explicit sector count.
    #[must_use]
    pub fn read_only(sectors: u64) -> Self {
        Self {
            attrs: MmcAttrs {
                write_mode: MmcWriteMode::ReadOnly,
                block_len: BLOCK_LEN,
                sectors,
                tracks: 1,
                sessions: 1,
                write_protected: false,
                needs_recovery: false,
                profile: 0x0008,
                current_features: &[0x0010, 0x001D, 0x001E],
            },
            op: None,
            phase: FlatState::Idle,
            progress: 0,
            chunk_in_alt: false,
            chunk_len: 0,
            next_in_alt: false,
            next_len: 0,
        }
    }

    /// Validate a data read and build its backing action.
    fn read_op(&self, lba: u64, blocks: u16) -> Result<Op, Completion> {
        let end = lba
            .checked_add(u64::from(blocks))
            .ok_or(Completion::Check(LBA_OUT_OF_RANGE))?;
        if end > self.attrs.sectors {
            return Err(Completion::Check(LBA_OUT_OF_RANGE));
        }
        let bytes = u64::from(blocks) * u64::from(BLOCK_LEN);
        if bytes > u64::from(u32::MAX) {
            return Err(Completion::Check(INVALID_FIELD));
        }
        let offset = lba
            .checked_mul(u64::from(BLOCK_LEN))
            .ok_or(Completion::Check(LBA_OUT_OF_RANGE))?;
        Ok(Op::Read {
            offset,
            bytes: bytes as u32,
        })
    }

    /// Clear the operation state.
    fn reset(&mut self) {
        self.op = None;
        self.phase = FlatState::Idle;
        self.progress = 0;
        self.chunk_in_alt = false;
        self.chunk_len = 0;
        self.next_in_alt = false;
        self.next_len = 0;
    }

    /// Total bytes selected by the admitted operation.
    fn total_bytes(&self) -> usize {
        match self.op {
            Some(Op::Read { bytes, .. }) => bytes as usize,
            _ => 0,
        }
    }

    /// Bytes of the next chunk, bounded by the caller's bank.
    fn next_chunk(&self, bank_len: usize) -> usize {
        self.total_bytes()
            .saturating_sub(self.progress as usize)
            .min(bank_len)
    }

    /// Byte offset of the next chunk inside the backing.
    fn next_offset(&self) -> u64 {
        match self.op {
            Some(Op::Read { offset, .. }) => offset + u64::from(self.progress),
            _ => 0,
        }
    }

    /// Issue the normal read of the current chunk.
    fn read_chunk<'a>(&mut self, data: &'a mut [u8]) -> PollStep<'a> {
        let len = self.next_chunk(data.len());
        if self.total_bytes() > 0 && len == 0 {
            // A bank that cannot stage one chunk is the target's own inability
            // to stage the transfer (HARDWARE ERROR / INTERNAL TARGET FAILURE),
            // not a bad CDB. `Target::drive_step_*` rejects an empty bank before
            // the medium is polled, so this only guards a direct caller.
            return self.finish(Completion::Check(INTERNAL_FAILURE));
        }
        self.phase = FlatState::ReadIo;
        self.chunk_in_alt = false;
        self.chunk_len = len;
        PollStep::Io(StorageOp::Read {
            resource: 0,
            offset: self.next_offset(),
            buf: &mut data[..len],
        })
    }

    /// Issue the speculative read of the next chunk.
    ///
    /// Consecutive chunks alternate between the caller's two banks: the chunk
    /// after the one just sent lands in the *other* bank, and the following
    /// `Send` takes it from there. An empty `alt` keeps the single-bank
    /// behaviour (prefetch into `data`, send from `data`).
    fn prefetch_chunk<'a>(&mut self, data: &'a mut [u8], alt: &'a mut [u8]) -> PollStep<'a> {
        let use_alt = !alt.is_empty() && !self.chunk_in_alt;
        let (bank, in_alt) = if use_alt { (alt, true) } else { (data, false) };
        let len = self.next_chunk(bank.len());
        if len == 0 {
            // A bank that cannot stage one chunk while bytes remain is the
            // target's own inability to stage the transfer (HARDWARE ERROR /
            // INTERNAL TARGET FAILURE), never a silent GOOD with data still
            // undelivered.
            return self.finish(Completion::Check(INTERNAL_FAILURE));
        }
        self.chunk_in_alt = in_alt;
        self.chunk_len = len;
        self.phase = FlatState::PrefetchIo;
        PollStep::Prefetch(crate::core::storage::PrefetchOp::Read {
            resource: 0,
            offset: self.next_offset(),
            buf: &mut bank[..len],
        })
    }

    /// Describe the speculative read of the chunk after the staged one.
    ///
    /// Pure projection: no stage, progress or bank state changes. A
    /// single-bank caller gets no companion and keeps the serial read-ahead.
    fn peek_prefetch(&self, data_len: usize, alt_len: usize) -> Option<(bool, usize, u64)> {
        if alt_len == 0 || !matches!(self.op, Some(Op::Read { .. })) {
            return None;
        }
        let next_progress = self.progress as usize + self.chunk_len;
        let remaining = self.total_bytes().saturating_sub(next_progress);
        if remaining == 0 {
            return None;
        }
        let use_alt = !self.chunk_in_alt;
        let bank_len = if use_alt { alt_len } else { data_len };
        let len = remaining.min(bank_len);
        if len == 0 {
            return None;
        }
        Some((use_alt, len, self.next_offset() + self.chunk_len as u64))
    }

    /// Send the staged chunk, with the speculative read of the next one when a
    /// second caller bank and a following chunk both exist.
    ///
    /// This is the only send path, so a command that fell back to the serial
    /// read-ahead (`alt` empty or too small) re-enters the pipeline on its next
    /// chunk instead of staying serial for the rest of the transfer. With
    /// nothing to read ahead the peek is `None` and the send is plain.
    fn send_chunk_with_prefetch<'a>(
        &mut self,
        data: &'a mut [u8],
        alt: &'a mut [u8],
    ) -> PollStep<'a> {
        let peek = self.peek_prefetch(data.len(), alt.len());
        self.next_in_alt = peek.is_some_and(|(in_alt, _, _)| in_alt);
        self.next_len = peek.map_or(0, |(_, len, _)| len);
        let len = self.chunk_len;
        if self.chunk_in_alt {
            let bytes = &alt[..len];
            let prefetch =
                peek.map(
                    |(_, prefetch_len, offset)| crate::core::storage::PrefetchOp::Read {
                        resource: 0,
                        offset,
                        buf: &mut data[..prefetch_len],
                    },
                );
            PollStep::Send { bytes, prefetch }
        } else {
            let bytes = &data[..len];
            let prefetch =
                peek.map(
                    |(_, prefetch_len, offset)| crate::core::storage::PrefetchOp::Read {
                        resource: 0,
                        offset,
                        buf: &mut alt[..prefetch_len],
                    },
                );
            PollStep::Send { bytes, prefetch }
        }
    }

    /// Fix a terminal completion.
    fn finish(&mut self, completion: Completion) -> PollStep<'static> {
        self.phase = FlatState::Done;
        self.op = None;
        PollStep::Complete(completion)
    }

    /// Map an adapter fault with the direction-specific default table.
    fn storage_sense(&mut self, fault: crate::core::Fault, ctx: IoContext) -> PollStep<'static> {
        match storage_fault_sense(fault, ctx) {
            Some(sense) => self.finish(Completion::Check(sense)),
            None => self.finish(Completion::Check(INTERNAL_FAILURE)),
        }
    }
}

impl MmcMedium for FlatCdMedium {
    type State = FlatState;

    fn attrs(&self) -> MmcAttrs {
        self.attrs
    }

    fn state(&self) -> &Self::State {
        &self.phase
    }

    fn begin(&mut self, op: MmcOp) -> Result<(), Completion> {
        if self.active() {
            return Err(Completion::Busy);
        }
        self.progress = 0;
        let action = match op {
            MmcOp::Read { lba, blocks } => self.read_op(lba, blocks)?,
            MmcOp::ReadSectors { lba, blocks, kind } => match kind {
                // Auto resolves to data on this all-data medium.
                SectorKind::Auto | SectorKind::Data2048 => self.read_op(lba, blocks)?,
                // Audio is not implemented: reject before any IO.
                SectorKind::Audio2352 => return Err(Completion::Check(INVALID_FIELD)),
            },
            // The flat medium has no write plane.
            MmcOp::Write { .. } | MmcOp::WriteSectors { .. } => {
                return Err(Completion::Check(WRITE_PROTECTED));
            }
            MmcOp::Commit => Op::Sync,
            // Read-only media are already closed; CLOSE is a no-op success.
            MmcOp::Close { .. } => return Err(Completion::Good),
            // Drive-owned descriptor/format operations never reach the medium.
            MmcOp::Format { .. }
            | MmcOp::Blank { .. }
            | MmcOp::ReserveTrack { .. }
            | MmcOp::TrackInfo { .. }
            | MmcOp::DiscInfo => return Err(Completion::Check(INVALID_FIELD)),
        };
        self.op = Some(action);
        self.phase = FlatState::Publish;
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
            (FlatState::Publish, FeedbackKind::Begin) => match self.op {
                Some(Op::Read { bytes, .. }) => {
                    self.phase = FlatState::ReadIo;
                    PollStep::Publish(DataPlan {
                        direction: Direction::ToHost,
                        bytes: u64::from(bytes),
                    })
                }
                Some(Op::Sync) => {
                    self.phase = FlatState::SyncIo;
                    PollStep::Publish(DataPlan {
                        direction: Direction::None,
                        bytes: 0,
                    })
                }
                None => PollStep::Idle,
            },
            (FlatState::ReadIo, FeedbackKind::PlanAccepted) => self.read_chunk(data),
            (FlatState::ReadIo, FeedbackKind::IoDone) => {
                let chunk = self.chunk_len;
                let Some(receipt) = fb.io() else {
                    return self.finish(Completion::Check(INTERNAL_FAILURE));
                };
                if let Some(fault) = receipt.error() {
                    return self.storage_sense(fault, IoContext::Read);
                }
                if receipt.confirmed() < chunk {
                    // A short read is not success; a read has no write effect
                    // to preserve.
                    return self.finish(Completion::Check(MEDIUM_ERROR));
                }
                self.phase = FlatState::Deliver;
                self.send_chunk_with_prefetch(data, alt)
            }
            (FlatState::Deliver, FeedbackKind::HostSentWithIo) => {
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
                if io.error().is_some() || io.confirmed() != self.next_len {
                    // Speculative data is optional: re-read the same range as
                    // a required read; the command outcome is unchanged.
                    self.progress = self.progress.saturating_add(chunk as u32);
                    return self.read_chunk(data);
                }
                self.progress = self.progress.saturating_add(chunk as u32);
                if (self.progress as usize) < total {
                    self.chunk_in_alt = self.next_in_alt;
                    self.chunk_len = self.next_len;
                    self.phase = FlatState::Deliver;
                    return self.send_chunk_with_prefetch(data, alt);
                }
                self.finish(Completion::Good)
            }
            (FlatState::PrefetchIo, FeedbackKind::IoDone) => {
                let chunk = self.chunk_len;
                let failed = match fb.io() {
                    Some(receipt) => receipt.error().is_some() || receipt.confirmed() < chunk,
                    None => true,
                };
                if failed {
                    // Speculative data is optional: re-read the same range as a
                    // required read; the command outcome is unchanged.
                    return self.read_chunk(data);
                }
                self.phase = FlatState::Deliver;
                self.send_chunk_with_prefetch(data, alt)
            }
            (FlatState::Deliver, FeedbackKind::HostSent) => {
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
                    // Read the next chunk ahead into the other bank.
                    return self.prefetch_chunk(data, alt);
                }
                self.finish(Completion::Good)
            }
            (FlatState::SyncIo, FeedbackKind::PlanAccepted) => {
                self.phase = FlatState::SyncWait;
                PollStep::Io(StorageOp::Sync { resource: 0 })
            }
            (FlatState::SyncWait, FeedbackKind::IoDone) => {
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

    fn interrupt(&mut self, _reason: InterruptReason, _known: KnownEffects) {
        self.reset();
    }

    fn commit(&mut self) -> Result<(), Completion> {
        Ok(())
    }

    fn track(&self, number: u16) -> Option<Track> {
        if number != 1 {
            return None;
        }
        Some(Track {
            number: 1,
            session: 1,
            start_lba: 0,
            blocks: self.attrs.sectors,
            kind: TrackKind::Data,
        })
    }

    fn session(&self, number: u16) -> Option<Session> {
        if number != 1 {
            return None;
        }
        Some(Session {
            number: 1,
            first_track: 1,
            last_track: 1,
            start_lba: 0,
        })
    }

    fn disc_info(&self) -> DiscInfo {
        DiscInfo {
            status: DiscStatus::Finalized,
            sessions: 1,
            last_session_lba: self.attrs.sectors.saturating_sub(1),
            writable: false,
            erasable: false,
            first_track: 1,
            first_track_last_session: 1,
            last_track_last_session: 1,
            last_session_state: 3,
            last_session_lead_in: None,
            last_possible_lead_out: None,
            disc_type: 0,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use crate::core::storage::{HostReceipt, IoReceipt};
    use crate::core::Fault;
    use crate::mmc::attrs::SectorKind;

    fn medium(sectors: u64) -> FlatCdMedium {
        FlatCdMedium::read_only(sectors)
    }

    fn io_receipt(confirmed: usize, error: Option<Fault>) -> Feedback {
        Feedback::io_done(IoReceipt::test(confirmed, error, Effect::Known))
    }

    #[test]
    fn capacity_is_floor_not_round_up() {
        assert_eq!(FlatCdMedium::new(4096).attrs().sectors, 2);
        assert_eq!(FlatCdMedium::new(4095).attrs().sectors, 1);
        assert_eq!(FlatCdMedium::new(0).attrs().sectors, 0);
    }

    #[test]
    fn attrs_describe_a_single_read_only_track() {
        let a = medium(16).attrs();
        assert_eq!(a.write_mode, MmcWriteMode::ReadOnly);
        assert_eq!(a.block_len, 2048);
        assert_eq!(a.tracks, 1);
        assert_eq!(a.sessions, 1);
        assert!(!a.write_accessible());
    }

    #[test]
    fn begin_validates_before_any_io() {
        let mut m = medium(4);
        assert_eq!(
            m.begin(MmcOp::Read { lba: 4, blocks: 1 }),
            Err(Completion::Check(LBA_OUT_OF_RANGE))
        );
        assert_eq!(
            m.begin(MmcOp::ReadSectors {
                lba: 0,
                blocks: 1,
                kind: SectorKind::Audio2352,
            }),
            Err(Completion::Check(INVALID_FIELD))
        );
        assert_eq!(
            m.begin(MmcOp::Write { lba: 0, blocks: 1 }),
            Err(Completion::Check(WRITE_PROTECTED))
        );
        assert_eq!(
            m.begin(MmcOp::Format { blocks: 4 }),
            Err(Completion::Check(INVALID_FIELD))
        );
        assert_eq!(
            m.begin(MmcOp::DiscInfo),
            Err(Completion::Check(INVALID_FIELD))
        );
        assert!(!m.active());
        assert_eq!(m.state(), &FlatState::Idle);
    }

    #[test]
    fn busy_while_an_operation_is_admitted() {
        let mut m = medium(4);
        assert_eq!(m.begin(MmcOp::Read { lba: 0, blocks: 1 }), Ok(()));
        assert!(m.active());
        assert_eq!(
            m.begin(MmcOp::Read { lba: 0, blocks: 1 }),
            Err(Completion::Busy)
        );
        m.interrupt(InterruptReason::Reset, KnownEffects::NONE);
        assert!(!m.active());
        assert_eq!(m.begin(MmcOp::Read { lba: 0, blocks: 1 }), Ok(()));
    }

    #[test]
    fn read_publishes_reads_sends_then_good() {
        let mut m = medium(4);
        let mut data = [0u8; 4096];
        assert_eq!(m.begin(MmcOp::Read { lba: 1, blocks: 1 }), Ok(()));
        match m.poll(Feedback::begin(), &mut data) {
            PollStep::Publish(plan) => assert_eq!(
                plan,
                DataPlan {
                    direction: Direction::ToHost,
                    bytes: 2048,
                }
            ),
            other => panic!("expected publish, got {other:?}"),
        }
        match m.poll(Feedback::plan_accepted(), &mut data) {
            PollStep::Io(StorageOp::Read {
                resource,
                offset,
                buf,
            }) => {
                assert_eq!(resource, 0);
                assert_eq!(offset, 2048);
                assert_eq!(buf.len(), 2048);
            }
            other => panic!("expected read IO, got {other:?}"),
        }
        match m.poll(io_receipt(2048, None), &mut data) {
            PollStep::Send { bytes, .. } => assert_eq!(bytes.len(), 2048),
            other => panic!("expected send, got {other:?}"),
        }
        assert!(matches!(
            m.poll(
                Feedback::host_sent(HostReceipt::test(2048, None)),
                &mut data
            ),
            PollStep::Complete(Completion::Good)
        ));
        assert!(!m.active());
    }

    #[test]
    fn read_errors_map_to_medium_error() {
        let mut m = medium(4);
        let mut data = [0u8; 2048];
        assert_eq!(m.begin(MmcOp::Read { lba: 0, blocks: 1 }), Ok(()));
        m.poll(Feedback::begin(), &mut data);
        m.poll(Feedback::plan_accepted(), &mut data);
        assert!(matches!(
            m.poll(io_receipt(0, Some(Fault::Io)), &mut data),
            PollStep::Complete(Completion::Check(MEDIUM_ERROR))
        ));

        let mut m = medium(4);
        assert_eq!(m.begin(MmcOp::Read { lba: 0, blocks: 1 }), Ok(()));
        m.poll(Feedback::begin(), &mut data);
        m.poll(Feedback::plan_accepted(), &mut data);
        assert!(matches!(
            m.poll(io_receipt(1024, None), &mut data),
            PollStep::Complete(Completion::Check(MEDIUM_ERROR))
        ));
    }

    #[test]
    fn commit_publishes_no_data_then_syncs() {
        let mut m = medium(4);
        let mut data = [0u8; 0];
        assert_eq!(m.begin(MmcOp::Commit), Ok(()));
        match m.poll(Feedback::begin(), &mut data) {
            PollStep::Publish(plan) => assert_eq!(
                plan,
                DataPlan {
                    direction: Direction::None,
                    bytes: 0,
                }
            ),
            other => panic!("expected publish, got {other:?}"),
        }
        match m.poll(Feedback::plan_accepted(), &mut data) {
            PollStep::Io(StorageOp::Sync { resource }) => assert_eq!(resource, 0),
            other => panic!("expected sync IO, got {other:?}"),
        }
        assert!(matches!(
            m.poll(io_receipt(0, None), &mut data),
            PollStep::Complete(Completion::Good)
        ));
        assert!(!m.active());
    }

    #[test]
    fn descriptor_values_are_single_track_and_finalized() {
        let m = medium(16);
        let track = m.track(1).expect("track 1");
        assert_eq!(track.number, 1);
        assert_eq!(track.session, 1);
        assert_eq!(track.start_lba, 0);
        assert_eq!(track.blocks, 16);
        assert_eq!(track.kind, TrackKind::Data);
        assert_eq!(m.track(2), None);

        let session = m.session(1).expect("session 1");
        assert_eq!(session.first_track, 1);
        assert_eq!(session.last_track, 1);
        assert_eq!(session.start_lba, 0);
        assert_eq!(m.session(2), None);

        let info = m.disc_info();
        assert_eq!(info.status, DiscStatus::Finalized);
        assert_eq!(info.sessions, 1);
        assert_eq!(info.last_session_lba, 15);
        assert!(!info.writable);
    }

    #[test]
    fn read_larger_than_the_bank_streams_in_chunks() {
        let mut m = medium(4);
        let mut data = [0u8; 16];
        assert_eq!(m.begin(MmcOp::Read { lba: 0, blocks: 4 }), Ok(()));
        match m.poll(Feedback::begin(), &mut data) {
            PollStep::Publish(plan) => assert_eq!(plan.bytes, 8192),
            other => panic!("expected publish, got {other:?}"),
        }
        let mut offset = 0u64;
        let mut prefetches = 0;
        match m.poll(Feedback::plan_accepted(), &mut data) {
            PollStep::Io(StorageOp::Read {
                offset: at, buf, ..
            }) => {
                assert_eq!(at, 0);
                assert_eq!(buf.len(), 16);
            }
            other => panic!("expected read IO, got {other:?}"),
        }
        loop {
            // Feed a full read receipt, then react to the returned step.
            match m.poll(
                Feedback::io_done(IoReceipt::test(16, None, Effect::Known)),
                &mut data,
            ) {
                PollStep::Send { bytes, .. } => {
                    assert_eq!(bytes.len(), 16);
                    offset += 16;
                }
                PollStep::Prefetch(crate::core::storage::PrefetchOp::Read {
                    offset: at,
                    buf,
                    ..
                }) => {
                    prefetches += 1;
                    assert_eq!(at, offset);
                    assert_eq!(buf.len(), 16);
                    continue;
                }
                PollStep::Complete(completion) => {
                    assert_eq!(completion, Completion::Good);
                    break;
                }
                other => panic!("expected send/prefetch, got {other:?}"),
            }
            match m.poll(Feedback::host_sent(HostReceipt::test(16, None)), &mut data) {
                PollStep::Prefetch(crate::core::storage::PrefetchOp::Read {
                    offset: at,
                    buf,
                    ..
                }) => {
                    prefetches += 1;
                    assert_eq!(at, offset);
                    assert_eq!(buf.len(), 16);
                }
                PollStep::Complete(completion) => {
                    assert_eq!(completion, Completion::Good);
                    break;
                }
                other => panic!("expected prefetch, got {other:?}"),
            }
        }
        assert_eq!(prefetches, 8192 / 16 - 1);
        assert!(!m.active());
    }
    /// A two-bank READ alternates the prefetch into the bank that was not just
    /// sent, and delivers every byte exactly once. `data` starts the read; the
    /// following chunks alternate with `alt`.
    #[test]
    fn two_bank_read_prefetches_into_the_alternate_bank() {
        const BANK: usize = 8192;
        const BLOCKS: u16 = 16; // 32 KiB: four chunks
        let mut m = medium(u64::from(BLOCKS));
        let mut data = [0u8; BANK];
        let mut alt = [0u8; BANK];
        let data_addr = data.as_ptr() as usize;
        let alt_addr = alt.as_ptr() as usize;
        let in_data = |buf: &[u8]| {
            let p = buf.as_ptr() as usize;
            p >= data_addr && p + buf.len() <= data_addr + BANK
        };
        let in_alt = |buf: &[u8]| {
            let p = buf.as_ptr() as usize;
            p >= alt_addr && p + buf.len() <= alt_addr + BANK
        };
        let fill = |buf: &mut [u8], at: usize| {
            for (i, byte) in buf.iter_mut().enumerate() {
                *byte = ((at + i) & 0xFF) as u8;
            }
        };

        assert_eq!(
            m.begin(MmcOp::Read {
                lba: 0,
                blocks: BLOCKS
            }),
            Ok(())
        );
        match m.poll_with_alt(Feedback::begin(), &mut data, &mut alt) {
            PollStep::Publish(plan) => assert_eq!(plan.bytes, u64::from(BLOCKS) * 2048),
            other => panic!("expected publish, got {other:?}"),
        }
        match m.poll_with_alt(Feedback::plan_accepted(), &mut data, &mut alt) {
            PollStep::Io(StorageOp::Read { offset, buf, .. }) => {
                assert_eq!(offset, 0);
                assert!(in_data(buf), "the required read uses the work bank");
                fill(buf, 0);
            }
            other => panic!("expected required read, got {other:?}"),
        }

        let mut delivered = 0usize;
        let mut alt_prefetches = 0usize;
        let mut sent_from_alt;
        let mut prefetches = 0usize;
        loop {
            let chunk = BANK.min(BLOCKS as usize * 2048 - delivered);
            match m.poll_with_alt(io_receipt(chunk, None), &mut data, &mut alt) {
                PollStep::Send { bytes, .. } => {
                    assert_eq!(bytes.len(), chunk);
                    for (i, byte) in bytes.iter().enumerate() {
                        assert_eq!(*byte, ((delivered + i) & 0xFF) as u8);
                    }
                    sent_from_alt = in_alt(bytes);
                    delivered += bytes.len();
                }
                other => panic!("expected send, got {other:?}"),
            }
            if delivered == BLOCKS as usize * 2048 {
                assert!(matches!(
                    m.poll_with_alt(
                        Feedback::host_sent(HostReceipt::test(chunk, None)),
                        &mut data,
                        &mut alt
                    ),
                    PollStep::Complete(Completion::Good)
                ));
                break;
            }
            match m.poll_with_alt(
                Feedback::host_sent(HostReceipt::test(chunk, None)),
                &mut data,
                &mut alt,
            ) {
                PollStep::Prefetch(crate::core::storage::PrefetchOp::Read {
                    offset, buf, ..
                }) => {
                    assert_eq!(offset as usize, delivered);
                    let from_alt = in_alt(buf);
                    assert_ne!(from_alt, sent_from_alt, "prefetch into the other bank");
                    if from_alt {
                        alt_prefetches += 1;
                    }
                    fill(buf, delivered);
                    prefetches += 1;
                }
                other => panic!("expected prefetch, got {other:?}"),
            }
        }
        assert_eq!(delivered, BLOCKS as usize * 2048);
        assert_eq!(prefetches, 3, "three later chunks");
        assert_eq!(alt_prefetches, 2, "alternate bank carries the odd chunks");
        assert!(!m.active());
    }

    /// A command that fell back to the serial read-ahead re-enters the
    /// two-bank pipeline on its next chunk instead of staying serial.
    #[test]
    fn a_serial_read_ahead_re_enters_the_prefetch_pipeline() {
        let mut m = medium(1);
        assert_eq!(m.begin(MmcOp::Read { lba: 0, blocks: 1 }), Ok(()));
        let mut data = [0u8; 512];
        let mut alt = [0u8; 512];
        let alt_start = alt.as_ptr() as usize;
        let data_start = data.as_ptr() as usize;
        assert!(matches!(
            m.poll_with_alt(Feedback::begin(), &mut data, &mut alt),
            PollStep::Publish(_)
        ));
        assert!(matches!(
            m.poll_with_alt(Feedback::plan_accepted(), &mut data, &mut alt),
            PollStep::Io(StorageOp::Read { .. })
        ));
        // No second bank for this send: the command takes the serial path.
        assert!(matches!(
            m.poll_with_alt(io_receipt(512, None), &mut data, &mut []),
            PollStep::Send { prefetch: None, .. }
        ));
        // The serial read-ahead lands in the second bank once it is offered.
        assert!(matches!(
            m.poll_with_alt(
                Feedback::host_sent(HostReceipt::test(512, None)),
                &mut data,
                &mut alt
            ),
            PollStep::Prefetch(crate::core::storage::PrefetchOp::Read { .. })
        ));
        // The send that follows carries the next read-ahead: the pipeline is
        // re-entered rather than staying serial for the rest of the command.
        match m.poll_with_alt(io_receipt(512, None), &mut data, &mut alt) {
            PollStep::Send {
                bytes,
                prefetch: Some(crate::core::storage::PrefetchOp::Read { buf, .. }),
            } => {
                assert_eq!(
                    bytes.as_ptr() as usize,
                    alt_start,
                    "send from the second bank"
                );
                assert_eq!(
                    buf.as_ptr() as usize,
                    data_start,
                    "companion into the first"
                );
            }
            other => panic!("expected a companion send, got {other:?}"),
        }
    }
}
