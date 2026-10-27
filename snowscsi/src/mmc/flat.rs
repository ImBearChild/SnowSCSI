//! Flat read-only CD medium (`02-api-profiles.md` §6.7/§7.4).
//!
//! A single-track, single-session, finalized CD data medium with no backing
//! bytes of its own: reads become
//! [`StorageOp::Read`](crate::core::storage::StorageOp::Read) at
//! `lba * 2048` and the runner's `Storage` adapter supplies the bytes. The
//! medium never allocates and owns only geometry plus the in-flight step state.
//!
//! Audio sectors and writes are rejected in [`MmcMedium::begin`] with no IO;
//! the drive handles the descriptor commands (TOC/DISC/TRACK/CLOSE) itself.

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
    /// READ: the data is being sent to the host.
    SendData,
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
            },
            op: None,
            phase: FlatState::Idle,
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
            // Drive-owned descriptor/format operations never reach the medium.
            MmcOp::Format { .. } | MmcOp::Close | MmcOp::TrackInfo { .. } | MmcOp::DiscInfo => {
                return Err(Completion::Check(INVALID_FIELD))
            }
        };
        self.op = Some(action);
        self.phase = FlatState::Publish;
        Ok(())
    }

    fn poll<'a>(&mut self, fb: Feedback, data: &'a mut [u8]) -> PollStep<'a> {
        let needed = match self.op {
            Some(Op::Read { bytes, .. }) => bytes as usize,
            _ => 0,
        };
        if data.len() < needed {
            return self.finish(Completion::Check(INVALID_FIELD));
        }
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
            (FlatState::ReadIo, FeedbackKind::PlanAccepted) => {
                let Some(Op::Read { offset, bytes }) = self.op else {
                    return self.finish(Completion::Check(INTERNAL_FAILURE));
                };
                self.phase = FlatState::SendData;
                PollStep::Io(StorageOp::Read {
                    resource: 0,
                    offset,
                    buf: &mut data[..bytes as usize],
                })
            }
            (FlatState::SendData, FeedbackKind::IoDone) => {
                let Some(receipt) = fb.io() else {
                    return self.finish(Completion::Check(INTERNAL_FAILURE));
                };
                if let Some(fault) = receipt.error() {
                    return self.storage_sense(fault, IoContext::Read);
                }
                if receipt.confirmed() < needed {
                    // A short read is not success; a read has no write effect
                    // to preserve.
                    return self.finish(Completion::Check(MEDIUM_ERROR));
                }
                self.phase = FlatState::Deliver;
                PollStep::Send(&data[..needed])
            }
            (FlatState::Deliver, FeedbackKind::HostSent) => {
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
            PollStep::Send(bytes) => assert_eq!(bytes.len(), 2048),
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
    fn short_bank_is_invalid_field() {
        let mut m = medium(4);
        let mut data = [0u8; 16];
        assert_eq!(m.begin(MmcOp::Read { lba: 0, blocks: 1 }), Ok(()));
        assert!(matches!(
            m.poll(Feedback::begin(), &mut data),
            PollStep::Complete(Completion::Check(INVALID_FIELD))
        ));
        assert!(!m.active());
    }
}
