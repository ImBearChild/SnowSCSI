//! DVD-RAM medium (`02-api-profiles.md` §6.6/§6.7).
//!
//! A rewritable single-track data medium behind the `dvdram` feature. Like
//! [`FlatCdMedium`](super::flat::FlatCdMedium) it owns only geometry and the
//! in-flight state: reads and writes become
//! [`StorageOp`](crate::core::storage::StorageOp) at `lba * 2048`, and the
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
    /// READ: the data is being sent to the host.
    SendData,
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
        if self.op == Some(Op::Format) {
            // Drive-owned fill; the medium only acknowledges the semantic op.
            self.reset();
            return PollStep::Complete(Completion::Good);
        }
        let needed = match self.op {
            Some(Op::Read { bytes, .. } | Op::Write { bytes, .. }) => bytes as usize,
            _ => 0,
        };
        if data.len() < needed {
            return self.finish(Completion::Check(INVALID_FIELD));
        }
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
            (DvdRamState::ReadIo, FeedbackKind::PlanAccepted) => {
                let Some(Op::Read { offset, bytes }) = self.op else {
                    return self.finish(Completion::Check(INTERNAL_FAILURE));
                };
                self.phase = DvdRamState::SendData;
                PollStep::Io(StorageOp::Read {
                    resource: 0,
                    offset,
                    buf: &mut data[..bytes as usize],
                })
            }
            (DvdRamState::SendData, FeedbackKind::IoDone) => {
                let Some(receipt) = fb.io() else {
                    return self.finish(Completion::Check(INTERNAL_FAILURE));
                };
                if let Some(fault) = receipt.error() {
                    return self.storage_sense(fault, IoContext::Read);
                }
                if receipt.confirmed() < needed {
                    return self.finish(Completion::Check(MEDIUM_ERROR));
                }
                self.phase = DvdRamState::Deliver;
                PollStep::Send(&data[..needed])
            }
            (DvdRamState::Deliver, FeedbackKind::HostSent) => {
                let (accepted, failed) = match fb.host() {
                    Some(receipt) => (receipt.accepted().min(needed), receipt.error().is_some()),
                    None => (0, true),
                };
                if failed || accepted < needed {
                    self.finish(Completion::Check(COMMAND_ABORTED))
                } else {
                    self.finish(Completion::Good)
                }
            }
            (DvdRamState::WriteRecv, FeedbackKind::PlanAccepted) => {
                PollStep::Receive(&mut data[..needed])
            }
            (DvdRamState::WriteRecv, FeedbackKind::HostReceived) => {
                let (accepted, failed) = match fb.host() {
                    Some(receipt) => (receipt.accepted().min(needed), receipt.error().is_some()),
                    None => (0, true),
                };
                if failed || accepted < needed {
                    // A short Data-Out is not a partial write: do not write a
                    // prefix, so no host byte is silently promoted to success.
                    return self.finish(Completion::Check(COMMAND_ABORTED));
                }
                let Some(Op::Write { offset, .. }) = self.op else {
                    return self.finish(Completion::Check(INTERNAL_FAILURE));
                };
                self.phase = DvdRamState::WriteIo;
                PollStep::Io(StorageOp::Write {
                    resource: 0,
                    offset,
                    buf: &data[..needed],
                })
            }
            (DvdRamState::WriteIo, FeedbackKind::IoDone) => {
                let Some(receipt) = fb.io() else {
                    return self.finish(Completion::Check(INTERNAL_FAILURE));
                };
                if let Some(fault) = receipt.error() {
                    return self.storage_sense(fault, IoContext::Write);
                }
                if receipt.confirmed() < needed || receipt.effect() != Effect::Known {
                    return self.finish(Completion::Check(MEDIUM_ERROR));
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
            PollStep::Send(bytes) if bytes.len() == 2048
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
}
