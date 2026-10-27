//! Minimal vendor medium (`02-api-profiles.md` §6.1/§6.7).
//!
//! A second, independent [`MmcMedium`] implementation used to prove that a new
//! medium is a new implementation rather than a new device branch: `MmcDrive`
//! has no device-kind match, so this read-only single-track medium answers
//! INQUIRY/READ CAPACITY/READ through the same `Spc`/`MmcDrive` path as the flat
//! CD. It is deliberately not feature gated.
//!
//! Writes and audio sectors are rejected in [`MmcMedium::begin`] with no IO.

use super::attrs::{
    DiscInfo, DiscStatus, MmcAttrs, MmcWriteMode, SectorKind, Session, Track, TrackKind,
};
use super::medium::MmcMedium;
use super::op::MmcOp;
use crate::core::storage::StorageOp;
use crate::core::{
    storage_fault_sense, Completion, DataPlan, Direction, Effect, Fault, Feedback, FeedbackKind,
    InterruptReason, IoContext, KnownEffects, PollStep, COMMAND_ABORTED, INTERNAL_FAILURE,
    INVALID_FIELD, LBA_OUT_OF_RANGE, MEDIUM_ERROR, WRITE_PROTECTED,
};

/// Vendor data block length.
const BLOCK_LEN: u32 = 2048;

/// Public phase of the medium's in-flight operation.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum VendorState {
    /// No operation.
    Idle,
    /// Admitted; the data plan has not been published yet.
    Publish,
    /// The backing read is being issued.
    ReadIo,
    /// The data is being sent to the host.
    SendData,
    /// Waiting for the host send to complete.
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

/// Minimal read-only vendor medium.
pub struct VendorMedium {
    attrs: MmcAttrs,
    op: Option<Op>,
    phase: VendorState,
}

impl VendorMedium {
    /// Build a read-only medium with an explicit sector count.
    #[must_use]
    pub fn new(sectors: u64) -> Self {
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
            phase: VendorState::Idle,
        }
    }

    /// Build a medium from a byte capacity (floored to whole sectors).
    #[must_use]
    pub fn from_bytes(bytes: u64) -> Self {
        Self::new(bytes / u64::from(BLOCK_LEN))
    }

    /// Validate a data read and compute its byte offset/count.
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
        self.phase = VendorState::Idle;
    }

    /// Fix a terminal completion.
    fn finish(&mut self, completion: Completion) -> PollStep<'static> {
        self.phase = VendorState::Done;
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

impl MmcMedium for VendorMedium {
    type State = VendorState;

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
                SectorKind::Audio2352 => return Err(Completion::Check(INVALID_FIELD)),
            },
            MmcOp::Write { .. } | MmcOp::WriteSectors { .. } => {
                return Err(Completion::Check(WRITE_PROTECTED))
            }
            MmcOp::Commit => Op::Sync,
            // The drive owns descriptor/format decoding.
            MmcOp::Format { .. } | MmcOp::TrackInfo { .. } | MmcOp::DiscInfo => {
                return Err(Completion::Check(INVALID_FIELD))
            }
            MmcOp::Close => return Err(Completion::Good),
        };
        self.op = Some(action);
        self.phase = VendorState::Publish;
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
            (VendorState::Publish, FeedbackKind::Begin) => match self.op {
                Some(Op::Read { bytes, .. }) => {
                    self.phase = VendorState::ReadIo;
                    PollStep::Publish(DataPlan {
                        direction: Direction::ToHost,
                        bytes: u64::from(bytes),
                    })
                }
                Some(Op::Sync) => {
                    self.phase = VendorState::SyncIo;
                    PollStep::Publish(DataPlan {
                        direction: Direction::None,
                        bytes: 0,
                    })
                }
                None => PollStep::Idle,
            },
            (VendorState::ReadIo, FeedbackKind::PlanAccepted) => {
                let Some(Op::Read { offset, bytes }) = self.op else {
                    return self.finish(Completion::Check(INTERNAL_FAILURE));
                };
                self.phase = VendorState::SendData;
                PollStep::Io(StorageOp::Read {
                    resource: 0,
                    offset,
                    buf: &mut data[..bytes as usize],
                })
            }
            (VendorState::SendData, FeedbackKind::IoDone) => {
                let Some(receipt) = fb.io() else {
                    return self.finish(Completion::Check(INTERNAL_FAILURE));
                };
                if let Some(fault) = receipt.error() {
                    return self.storage_sense(fault, IoContext::Read);
                }
                if receipt.confirmed() < needed {
                    return self.finish(Completion::Check(MEDIUM_ERROR));
                }
                self.phase = VendorState::Deliver;
                PollStep::Send(&data[..needed])
            }
            (VendorState::Deliver, FeedbackKind::HostSent) => {
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
            (VendorState::SyncIo, FeedbackKind::PlanAccepted) => {
                self.phase = VendorState::SyncWait;
                PollStep::Io(StorageOp::Sync { resource: 0 })
            }
            (VendorState::SyncWait, FeedbackKind::IoDone) => {
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
    use crate::core::Effect;

    #[test]
    fn attrs_are_read_only_and_single_track() {
        let a = VendorMedium::new(8).attrs();
        assert_eq!(a.write_mode, MmcWriteMode::ReadOnly);
        assert_eq!(a.sectors, 8);
        assert_eq!(a.tracks, 1);
        assert!(!a.write_accessible());
        assert_eq!(VendorMedium::from_bytes(4095).attrs().sectors, 1);
    }

    #[test]
    fn writes_and_audio_are_rejected_before_io() {
        let mut m = VendorMedium::new(4);
        assert_eq!(
            m.begin(MmcOp::Write { lba: 0, blocks: 1 }),
            Err(Completion::Check(WRITE_PROTECTED))
        );
        assert_eq!(
            m.begin(MmcOp::ReadSectors {
                lba: 0,
                blocks: 1,
                kind: SectorKind::Audio2352,
            }),
            Err(Completion::Check(INVALID_FIELD))
        );
        assert!(!m.active());
    }

    #[test]
    fn read_round_trip_through_poll() {
        let mut m = VendorMedium::new(4);
        let mut data = [0u8; 2048];
        assert_eq!(m.begin(MmcOp::Read { lba: 1, blocks: 1 }), Ok(()));
        match m.poll(Feedback::begin(), &mut data) {
            PollStep::Publish(plan) => assert_eq!(plan.bytes, 2048),
            other => panic!("expected publish, got {other:?}"),
        }
        match m.poll(Feedback::plan_accepted(), &mut data) {
            PollStep::Io(StorageOp::Read { offset, .. }) => assert_eq!(offset, 2048),
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
    }
}
