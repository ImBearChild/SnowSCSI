//! DVD-RAM medium.
//!
//! A rewritable single-track data medium behind the `dvdram` feature. Like
//! [`FlatCdMedium`](super::flat::FlatCdMedium) it owns only geometry and the
//! in-flight state: reads and writes become
//! [`StorageOp`] at `lba * 2048`, and the
//! runner's `Storage` adapter supplies the bytes.
//!
//! FORMAT zero-fill is drive-owned (`MmcDrive::poll_long`); this medium accepts
//! `MmcOp::Format` for completeness and reports it complete without IO, so no
//! generic medium-level fill can be mistaken for the drive's long operation.

use super::attrs::{
    DiscInfo, DiscStatus, MmcAttrs, MmcWriteMode, SectorKind, Session, Track, TrackKind,
};
use super::medium::MmcMedium;
use super::op::MmcOp;
use crate::core::storage::StorageOp;
use crate::core::{
    storage_fault_sense, Completion, DataPlan, Direction, Effect, Fault, Feedback, FeedbackKind,
    InterruptReason, IoContext, KnownEffects, PollStep, COMMAND_ABORTED, INTERNAL_FAILURE,
    INVALID_FIELD, LBA_OUT_OF_RANGE, MEDIUM_ERROR,
};

/// DVD-RAM data block length.
const BLOCK_LEN: u32 = 2048;

/// Public phase of the medium's in-flight operation.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DvdRamState {
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

/// Backing action selected by [`MmcMedium::begin`].
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Op {
    /// Read `bytes` from `offset`.
    Read { offset: u64, bytes: u32 },
    /// Write `bytes` at `offset`.
    Write { offset: u64, bytes: u32 },
    /// Flush the backing.
    Sync,
    /// Drive-owned format acknowledgement (no IO).
    Format,
}

/// Rewritable DVD-RAM medium.
pub struct DvdRamMedium {
    attrs: MmcAttrs,
    op: Option<Op>,
    phase: DvdRamState,
    /// Bytes of the current read/write already transferred.
    progress: u32,
    /// The staged read chunk lives in the alternate caller bank (`alt`), so
    /// the next `Send` must take it from there.
    chunk_in_alt: bool,
    /// Bytes of the read chunk handed to the host, in the bank named by
    /// `chunk_in_alt`.
    chunk_len: usize,
    /// Bank of the chunk the staged `Send` prefetches for the following step.
    next_in_alt: bool,
    /// Bytes of that prefetched chunk.
    next_len: usize,
}

impl DvdRamMedium {
    /// Build a rewritable medium with an explicit sector count.
    #[must_use]
    pub fn new(sectors: u64) -> Self {
        Self {
            attrs: MmcAttrs {
                write_mode: MmcWriteMode::Rewritable,
                block_len: BLOCK_LEN,
                sectors,
                tracks: 1,
                sessions: 1,
                write_protected: false,
                needs_recovery: false,
            },
            op: None,
            phase: DvdRamState::Idle,
            progress: 0,
            chunk_in_alt: false,
            chunk_len: 0,
            next_in_alt: false,
            next_len: 0,
        }
    }

    /// Build a medium from a byte capacity; the sector count floors at
    /// `bytes / 2048`.
    #[must_use]
    pub fn from_bytes(bytes: u64) -> Self {
        Self::new(bytes / u64::from(BLOCK_LEN))
    }

    /// Validate `lba + blocks` and compute the byte offset/count.
    fn range(&self, lba: u64, blocks: u16) -> Result<(u64, u32), Completion> {
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
        Ok((offset, bytes as u32))
    }

    /// Clear the operation state.
    fn reset(&mut self) {
        self.op = None;
        self.phase = DvdRamState::Idle;
        self.progress = 0;
        self.chunk_in_alt = false;
        self.chunk_len = 0;
        self.next_in_alt = false;
        self.next_len = 0;
    }

    /// Total bytes selected by the admitted operation.
    fn total_bytes(&self) -> usize {
        match self.op {
            Some(Op::Read { bytes, .. } | Op::Write { bytes, .. }) => bytes as usize,
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
            Some(Op::Read { offset, .. } | Op::Write { offset, .. }) => {
                offset + u64::from(self.progress)
            }
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
        self.phase = DvdRamState::ReadIo;
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
    /// Consecutive read chunks alternate between the caller's two banks: the
    /// chunk after the one just sent lands in the *other* bank, and the
    /// following `Send` takes it from there. An empty `alt` keeps the
    /// single-bank behaviour.
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
        self.phase = DvdRamState::PrefetchIo;
        PollStep::Prefetch(crate::core::storage::PrefetchOp::Read {
            resource: 0,
            offset: self.next_offset(),
            buf: &mut bank[..len],
        })
    }

    /// Send the staged read chunk from the bank that holds it.
    fn send_chunk<'a>(&mut self, data: &'a mut [u8], alt: &'a mut [u8]) -> PollStep<'a> {
        // A plain send carries no read-ahead: never let a stale peek leak into
        // a later combined settlement.
        self.next_in_alt = false;
        self.next_len = 0;
        let len = self.chunk_len;
        if self.chunk_in_alt {
            PollStep::Send {
                bytes: &alt[..len],
                prefetch: None,
            }
        } else {
            PollStep::Send {
                bytes: &data[..len],
                prefetch: None,
            }
        }
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

    /// Send the staged chunk together with the speculative read of the next
    /// one, remembering where that chunk will land.
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
        self.phase = DvdRamState::Done;
        self.op = None;
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

impl MmcMedium for DvdRamMedium {
    type State = DvdRamState;

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
            MmcOp::Read { lba, blocks } => {
                let (offset, bytes) = self.range(lba, blocks)?;
                Op::Read { offset, bytes }
            }
            MmcOp::ReadSectors { lba, blocks, kind } => match kind {
                SectorKind::Auto | SectorKind::Data2048 => {
                    let (offset, bytes) = self.range(lba, blocks)?;
                    Op::Read { offset, bytes }
                }
                // No audio plane on a data medium.
                SectorKind::Audio2352 => return Err(Completion::Check(INVALID_FIELD)),
            },
            MmcOp::Write { lba, blocks } => {
                let (offset, bytes) = self.range(lba, blocks)?;
                Op::Write { offset, bytes }
            }
            MmcOp::WriteSectors { lba, blocks, kind } => match kind {
                SectorKind::Auto | SectorKind::Data2048 => {
                    let (offset, bytes) = self.range(lba, blocks)?;
                    Op::Write { offset, bytes }
                }
                SectorKind::Audio2352 => return Err(Completion::Check(INVALID_FIELD)),
            },
            MmcOp::Commit => Op::Sync,
            // The drive owns the zero-fill through `poll_long`; acknowledging
            // `Format` here keeps the medium vocabulary complete without
            // duplicating the fill.
            MmcOp::Format { .. } => Op::Format,
            // CLOSE TRACK SESSION changes the drive-level write state; a
            // DVD-RAM has no track/session to close and is already writable.
            MmcOp::Close => return Err(Completion::Good),
            MmcOp::TrackInfo { .. } | MmcOp::DiscInfo => {
                return Err(Completion::Check(INVALID_FIELD))
            }
        };
        self.op = Some(action);
        self.phase = DvdRamState::Publish;
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
        if self.op == Some(Op::Format) {
            // Drive-owned fill; the medium only acknowledges the semantic op.
            self.reset();
            return PollStep::Complete(Completion::Good);
        }
        let total = self.total_bytes();
        match (self.phase, fb.kind()) {
            (DvdRamState::Publish, FeedbackKind::Begin) => match self.op {
                Some(Op::Read { bytes, .. }) => {
                    self.phase = DvdRamState::ReadIo;
                    PollStep::Publish(DataPlan {
                        direction: Direction::ToHost,
                        bytes: u64::from(bytes),
                    })
                }
                Some(Op::Write { bytes, .. }) => {
                    self.phase = DvdRamState::WriteRecv;
                    PollStep::Publish(DataPlan {
                        direction: Direction::FromHost,
                        bytes: u64::from(bytes),
                    })
                }
                Some(Op::Sync) => {
                    self.phase = DvdRamState::SyncIo;
                    PollStep::Publish(DataPlan {
                        direction: Direction::None,
                        bytes: 0,
                    })
                }
                Some(Op::Format) | None => PollStep::Idle,
            },
            (DvdRamState::ReadIo, FeedbackKind::PlanAccepted) => self.read_chunk(data),
            (DvdRamState::ReadIo, FeedbackKind::IoDone) => {
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
                self.phase = DvdRamState::Deliver;
                self.send_chunk_with_prefetch(data, alt)
            }
            (DvdRamState::Deliver, FeedbackKind::HostSentWithIo) => {
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
                    self.phase = DvdRamState::Deliver;
                    return self.send_chunk_with_prefetch(data, alt);
                }
                self.finish(Completion::Good)
            }
            (DvdRamState::PrefetchIo, FeedbackKind::IoDone) => {
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
                self.phase = DvdRamState::Deliver;
                self.send_chunk(data, alt)
            }
            (DvdRamState::Deliver, FeedbackKind::HostSent) => {
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
                    return self.prefetch_chunk(data, alt);
                }
                self.finish(Completion::Good)
            }
            (DvdRamState::WriteRecv, FeedbackKind::PlanAccepted) => {
                let chunk = self.next_chunk(data.len());
                if total > 0 && chunk == 0 {
                    // Same staging rule as the read path: a bank that cannot
                    // hold one chunk is the target's own inability to stage
                    // (04/44/00), not a bad CDB. The step entries reject an
                    // empty bank first.
                    return self.finish(Completion::Check(INTERNAL_FAILURE));
                }
                PollStep::Receive(&mut data[..chunk])
            }
            (DvdRamState::WriteRecv, FeedbackKind::HostReceived) => {
                let chunk = self.next_chunk(data.len());
                let (accepted, failed) = match fb.host() {
                    Some(receipt) => (receipt.accepted().min(chunk), receipt.error().is_some()),
                    None => (0, true),
                };
                if failed || accepted < chunk {
                    // A short Data-Out is not a partial write: do not write a
                    // prefix, so no host byte is silently promoted to success.
                    return self.finish(Completion::Check(COMMAND_ABORTED));
                }
                self.phase = DvdRamState::WriteIo;
                PollStep::Io(StorageOp::Write {
                    resource: 0,
                    offset: self.next_offset(),
                    buf: &data[..accepted],
                })
            }
            (DvdRamState::WriteIo, FeedbackKind::IoDone) => {
                let chunk = self.next_chunk(data.len());
                let Some(receipt) = fb.io() else {
                    return self.finish(Completion::Check(INTERNAL_FAILURE));
                };
                if let Some(fault) = receipt.error() {
                    return self.storage_sense(fault, IoContext::Write);
                }
                if receipt.confirmed() < chunk || receipt.effect() != Effect::Known {
                    return self.finish(Completion::Check(MEDIUM_ERROR));
                }
                self.progress = self.progress.saturating_add(chunk as u32);
                if (self.progress as usize) < total {
                    // More host data: start the next chunk's receive phase.
                    let next = self.next_chunk(data.len());
                    self.phase = DvdRamState::WriteRecv;
                    return PollStep::Receive(&mut data[..next]);
                }
                self.finish(Completion::Good)
            }
            (DvdRamState::SyncIo, FeedbackKind::PlanAccepted) => {
                self.phase = DvdRamState::SyncWait;
                PollStep::Io(StorageOp::Sync { resource: 0 })
            }
            (DvdRamState::SyncWait, FeedbackKind::IoDone) => {
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
            // Random-access media: the sequential-media "incomplete" code is
            // reserved; report the baseline host-compatible finalized status.
            status: DiscStatus::Finalized,
            sessions: 1,
            last_session_lba: self.attrs.sectors.saturating_sub(1),
            writable: true,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::core::storage::{HostReceipt, IoReceipt};
    use crate::core::WRITE_PROTECTED;

    fn medium(sectors: u64) -> DvdRamMedium {
        DvdRamMedium::new(sectors)
    }

    #[test]
    fn attrs_describe_a_single_rewritable_track() {
        let a = medium(16).attrs();
        assert_eq!(a.write_mode, MmcWriteMode::Rewritable);
        assert_eq!(a.block_len, 2048);
        assert_eq!(a.sectors, 16);
        assert_eq!(a.tracks, 1);
        assert_eq!(a.sessions, 1);
        assert!(!a.write_protected);
        assert!(a.write_accessible());
        assert_eq!(DvdRamMedium::from_bytes(4095).attrs().sectors, 1);
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
        assert_eq!(m.begin(MmcOp::Close), Err(Completion::Good));
        assert_eq!(
            m.begin(MmcOp::DiscInfo),
            Err(Completion::Check(INVALID_FIELD))
        );
        assert!(!m.active());
    }

    #[test]
    fn read_publishes_reads_sends_then_good() {
        let mut m = medium(4);
        let mut data = [0u8; 2048];
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
        assert!(matches!(
            m.poll(
                Feedback::io_done(IoReceipt::test(2048, None, Effect::Known)),
                &mut data
            ),
            PollStep::Send { bytes, .. } if bytes.len() == 2048
        ));
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
    fn write_receives_then_writes_then_good() {
        let mut m = medium(4);
        let mut data = [0xA5u8; 2048];
        assert_eq!(m.begin(MmcOp::Write { lba: 2, blocks: 1 }), Ok(()));
        match m.poll(Feedback::begin(), &mut data) {
            PollStep::Publish(plan) => assert_eq!(
                plan,
                DataPlan {
                    direction: Direction::FromHost,
                    bytes: 2048,
                }
            ),
            other => panic!("expected publish, got {other:?}"),
        }
        assert!(matches!(
            m.poll(Feedback::plan_accepted(), &mut data),
            PollStep::Receive(buf) if buf.len() == 2048
        ));
        match m.poll(
            Feedback::host_received(HostReceipt::test(2048, None)),
            &mut data,
        ) {
            PollStep::Io(StorageOp::Write {
                resource,
                offset,
                buf,
            }) => {
                assert_eq!(resource, 0);
                assert_eq!(offset, 4096);
                assert!(buf.iter().all(|b| *b == 0xA5));
            }
            other => panic!("expected write IO, got {other:?}"),
        }
        assert!(matches!(
            m.poll(
                Feedback::io_done(IoReceipt::test(2048, None, Effect::Known)),
                &mut data
            ),
            PollStep::Complete(Completion::Good)
        ));
    }

    #[test]
    fn write_error_maps_to_write_error_sense() {
        let mut m = medium(4);
        let mut data = [0u8; 2048];
        assert_eq!(m.begin(MmcOp::Write { lba: 0, blocks: 1 }), Ok(()));
        m.poll(Feedback::begin(), &mut data);
        m.poll(Feedback::plan_accepted(), &mut data);
        m.poll(
            Feedback::host_received(HostReceipt::test(2048, None)),
            &mut data,
        );
        assert!(matches!(
            m.poll(
                Feedback::io_done(IoReceipt::test(0, Some(Fault::NotWritable), Effect::Known)),
                &mut data
            ),
            PollStep::Complete(Completion::Check(WRITE_PROTECTED))
        ));
    }

    #[test]
    fn format_is_acknowledged_without_io() {
        let mut m = medium(4);
        let mut data = [0u8; 0];
        assert_eq!(m.begin(MmcOp::Format { blocks: 4 }), Ok(()));
        assert!(matches!(
            m.poll(Feedback::begin(), &mut data),
            PollStep::Complete(Completion::Good)
        ));
        assert!(!m.active());
    }

    #[test]
    fn descriptor_values_are_single_incomplete_track() {
        let m = medium(16);
        let track = m.track(1).expect("track 1");
        assert_eq!(track.blocks, 16);
        assert_eq!(track.kind, TrackKind::Data);
        assert_eq!(m.track(2), None);
        let info = m.disc_info();
        assert_eq!(info.status, DiscStatus::Finalized);
        assert_eq!(info.last_session_lba, 15);
        assert!(info.writable);
    }

    #[test]
    fn read_larger_than_the_bank_streams_byte_exactly() {
        let mut m = medium(4);
        let mut backing = vec![0u8; 4 * BLOCK_LEN as usize];
        for (i, b) in backing.iter_mut().enumerate() {
            *b = (i % 251) as u8;
        }
        let mut data = [0u8; 1024];
        assert_eq!(m.begin(MmcOp::Read { lba: 0, blocks: 4 }), Ok(()));
        match m.poll(Feedback::begin(), &mut data) {
            PollStep::Publish(plan) => {
                assert_eq!(plan.direction, Direction::ToHost);
                assert_eq!(plan.bytes, backing.len() as u64);
            }
            other => panic!("expected publish, got {other:?}"),
        }

        let mut collected = Vec::new();
        let mut step = m.poll(Feedback::plan_accepted(), &mut data);
        loop {
            match step {
                PollStep::Io(StorageOp::Read { offset, buf, .. })
                | PollStep::Prefetch(crate::core::storage::PrefetchOp::Read {
                    offset, buf, ..
                }) => {
                    let offset = offset as usize;
                    buf.copy_from_slice(&backing[offset..offset + buf.len()]);
                    let len = buf.len();
                    step = m.poll(
                        Feedback::io_done(IoReceipt::test(len, None, Effect::Known)),
                        &mut data,
                    );
                }
                PollStep::Send { bytes, .. } => {
                    collected.extend_from_slice(bytes);
                    let len = bytes.len();
                    step = m.poll(Feedback::host_sent(HostReceipt::test(len, None)), &mut data);
                }
                PollStep::Complete(completion) => {
                    assert_eq!(completion, Completion::Good);
                    break;
                }
                other => panic!("unexpected step {other:?}"),
            }
        }
        assert_eq!(collected, backing, "the streamed read is byte-exact");
        assert!(!m.active());
    }

    #[test]
    fn write_larger_than_the_bank_commits_byte_exactly() {
        let mut m = medium(4);
        let payload: Vec<u8> = (0..4 * BLOCK_LEN as usize)
            .map(|i| (i % 251) as u8)
            .collect();
        let mut backing = vec![0u8; payload.len()];
        let mut data = [0u8; 1024];
        assert_eq!(m.begin(MmcOp::Write { lba: 0, blocks: 4 }), Ok(()));
        match m.poll(Feedback::begin(), &mut data) {
            PollStep::Publish(plan) => {
                assert_eq!(plan.direction, Direction::FromHost);
                assert_eq!(plan.bytes, payload.len() as u64);
            }
            other => panic!("expected publish, got {other:?}"),
        }

        let mut received = 0usize;
        let mut written = 0usize;
        let mut step = m.poll(Feedback::plan_accepted(), &mut data);
        loop {
            match step {
                PollStep::Receive(buf) => {
                    let len = buf.len();
                    buf.copy_from_slice(&payload[received..received + len]);
                    received += len;
                    step = m.poll(
                        Feedback::host_received(HostReceipt::test(len, None)),
                        &mut data,
                    );
                }
                PollStep::Io(StorageOp::Write { offset, buf, .. }) => {
                    let offset = offset as usize;
                    assert_eq!(offset, written, "writes are contiguous");
                    backing[offset..offset + buf.len()].copy_from_slice(buf);
                    let len = buf.len();
                    written += len;
                    step = m.poll(
                        Feedback::io_done(IoReceipt::test(len, None, Effect::Known)),
                        &mut data,
                    );
                }
                PollStep::Complete(completion) => {
                    assert_eq!(completion, Completion::Good);
                    break;
                }
                other => panic!("unexpected step {other:?}"),
            }
        }
        assert_eq!(received, payload.len(), "every host byte was received");
        assert_eq!(backing, payload, "the streamed write is byte-exact");
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
            match m.poll_with_alt(
                Feedback::io_done(IoReceipt::test(chunk, None, Effect::Known)),
                &mut data,
                &mut alt,
            ) {
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
}
