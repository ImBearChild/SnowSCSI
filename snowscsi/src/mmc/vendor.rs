//! Minimal vendor medium.
//!
//! A second, independent [`MmcMedium`] implementation used to prove that a new
//! medium is a new implementation rather than a new device branch: `MmcDrive`
//! has no device-kind match, so this read-only single-track medium answers
//! INQUIRY/READ CAPACITY/READ through the same `Spc`/`MmcDrive` path as the flat
//! CD. It is deliberately not feature gated.
//!
//! Reads stream in bank-sized chunks exactly like `FlatCdMedium`: the caller's
//! bank is the staging capacity, so a read larger than the bank is sent in
//! several chunks (with a speculative read of the next one) and never answers
//! CHECK CONDITION for the shortfall.
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

/// Minimal read-only vendor medium.
pub struct VendorMedium {
    attrs: MmcAttrs,
    op: Option<Op>,
    phase: VendorState,
    /// Bytes of the read already delivered to the host.
    progress: u32,
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
            progress: 0,
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
        self.progress = 0;
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
        self.phase = VendorState::ReadIo;
        PollStep::Io(StorageOp::Read {
            resource: 0,
            offset: self.next_offset(),
            buf: &mut data[..len],
        })
    }

    /// Issue the speculative read of the next chunk.
    fn prefetch_chunk<'a>(&mut self, data: &'a mut [u8]) -> PollStep<'a> {
        let len = self.next_chunk(data.len());
        self.phase = VendorState::PrefetchIo;
        PollStep::Prefetch(crate::core::storage::PrefetchOp::Read {
            resource: 0,
            offset: self.next_offset(),
            buf: &mut data[..len],
        })
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
        self.progress = 0;
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
        let total = self.total_bytes();
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
            (VendorState::ReadIo, FeedbackKind::PlanAccepted) => self.read_chunk(data),
            (VendorState::ReadIo, FeedbackKind::IoDone) => {
                let chunk = self.next_chunk(data.len());
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
                self.phase = VendorState::Deliver;
                PollStep::Send(&data[..chunk])
            }
            (VendorState::PrefetchIo, FeedbackKind::IoDone) => {
                let chunk = self.next_chunk(data.len());
                let failed = match fb.io() {
                    Some(receipt) => receipt.error().is_some() || receipt.confirmed() < chunk,
                    None => true,
                };
                if failed {
                    // Speculative data is optional: re-read the same range as a
                    // required read; the command outcome is unchanged.
                    return self.read_chunk(data);
                }
                self.phase = VendorState::Deliver;
                PollStep::Send(&data[..chunk])
            }
            (VendorState::Deliver, FeedbackKind::HostSent) => {
                let chunk = self.next_chunk(data.len());
                let (accepted, failed) = match fb.host() {
                    Some(receipt) => (receipt.accepted().min(chunk), receipt.error().is_some()),
                    None => (0, true),
                };
                if failed || accepted < chunk {
                    return self.finish(Completion::Check(COMMAND_ABORTED));
                }
                self.progress = self.progress.saturating_add(chunk as u32);
                if (self.progress as usize) < total {
                    // Read the next chunk now so the following send does not
                    // wait for storage.
                    return self.prefetch_chunk(data);
                }
                self.finish(Completion::Good)
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
    use crate::core::storage::{HostReceipt, IoReceipt, PrefetchOp};
    use crate::core::Effect;

    fn io_receipt(confirmed: usize) -> Feedback {
        Feedback::io_done(IoReceipt::test(confirmed, None, Effect::Known))
    }

    fn fill_pattern(buf: &mut [u8], at: usize) {
        for (i, byte) in buf.iter_mut().enumerate() {
            *byte = ((at + i) & 0xFF) as u8;
        }
    }

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

    /// A 2 MiB read through an 8 KiB bank returns every byte exactly once,
    /// issues more than one required read only for the first chunk, and never
    /// answers CHECK CONDITION for the shortfall.
    #[test]
    fn a_read_larger_than_the_bank_streams_byte_exact() {
        const BANK: usize = 8192;
        const BLOCKS: u16 = 1024;
        const TOTAL: usize = BLOCKS as usize * 2048;

        let mut m = VendorMedium::new(u64::from(BLOCKS));
        let mut bank = [0u8; BANK];
        assert_eq!(
            m.begin(MmcOp::Read {
                lba: 0,
                blocks: BLOCKS
            }),
            Ok(())
        );
        match m.poll(Feedback::begin(), &mut bank) {
            PollStep::Publish(plan) => assert_eq!(plan.bytes, TOTAL as u64),
            other => panic!("expected publish, got {other:?}"),
        }

        let mut reads = 0u32;
        let mut prefetches = 0u32;
        let mut delivered = 0usize;

        match m.poll(Feedback::plan_accepted(), &mut bank) {
            PollStep::Io(StorageOp::Read { offset, buf, .. }) => {
                assert_eq!(offset, 0);
                assert_eq!(buf.len(), BANK);
                fill_pattern(buf, 0);
                reads += 1;
            }
            other => panic!("expected read IO, got {other:?}"),
        }
        loop {
            match m.poll(io_receipt(BANK), &mut bank) {
                PollStep::Send(bytes) => {
                    assert_eq!(bytes.len(), BANK);
                    for (i, byte) in bytes.iter().enumerate() {
                        assert_eq!(*byte, ((delivered + i) & 0xFF) as u8);
                    }
                    delivered += bytes.len();
                }
                other => panic!("expected send, got {other:?}"),
            }
            if delivered == TOTAL {
                break;
            }
            match m.poll(
                Feedback::host_sent(HostReceipt::test(BANK, None)),
                &mut bank,
            ) {
                PollStep::Prefetch(PrefetchOp::Read { offset, buf, .. }) => {
                    assert_eq!(offset as usize, delivered);
                    assert_eq!(buf.len(), BANK);
                    fill_pattern(buf, delivered);
                    prefetches += 1;
                }
                other => panic!("expected prefetch, got {other:?}"),
            }
        }
        assert!(
            matches!(
                m.poll(
                    Feedback::host_sent(HostReceipt::test(BANK, None)),
                    &mut bank
                ),
                PollStep::Complete(Completion::Good)
            ),
            "the streamed read completes GOOD"
        );
        assert_eq!(reads, 1, "only the first chunk is a required read");
        assert_eq!(prefetches, (TOTAL / BANK - 1) as u32);
        assert!(!m.active());
    }

    /// A 2 MiB read whose bank is larger than the transfer issues exactly one
    /// backing read and no speculative one.
    #[test]
    fn a_read_that_fits_one_chunk_issues_one_read_without_prefetch() {
        const BLOCKS: u16 = 1024;
        const TOTAL: usize = BLOCKS as usize * 2048;

        let mut m = VendorMedium::new(u64::from(BLOCKS));
        let mut bank = vec![0u8; 2 * TOTAL];
        assert_eq!(
            m.begin(MmcOp::Read {
                lba: 0,
                blocks: BLOCKS,
            }),
            Ok(())
        );
        match m.poll(Feedback::begin(), &mut bank) {
            PollStep::Publish(plan) => assert_eq!(plan.bytes, TOTAL as u64),
            other => panic!("expected publish, got {other:?}"),
        }
        match m.poll(Feedback::plan_accepted(), &mut bank) {
            PollStep::Io(StorageOp::Read { offset, buf, .. }) => {
                assert_eq!(offset, 0);
                assert_eq!(buf.len(), TOTAL);
                fill_pattern(buf, 0);
            }
            other => panic!("expected read IO, got {other:?}"),
        }
        match m.poll(io_receipt(TOTAL), &mut bank) {
            PollStep::Send(bytes) => {
                assert_eq!(bytes.len(), TOTAL);
                assert_eq!(bytes[TOTAL - 1], ((TOTAL - 1) & 0xFF) as u8);
            }
            other => panic!("expected send, got {other:?}"),
        }
        assert!(
            matches!(
                m.poll(
                    Feedback::host_sent(HostReceipt::test(TOTAL, None)),
                    &mut bank
                ),
                PollStep::Complete(Completion::Good)
            ),
            "a transfer that fits one chunk must not prefetch"
        );
    }

    /// A failed speculative read is re-read as a required read: the bytes stay
    /// exact and the completion is unchanged.
    #[test]
    fn a_failed_prefetch_falls_back_without_changing_the_completion() {
        let mut m = VendorMedium::new(8);
        let mut bank = [0u8; 8192];
        assert_eq!(m.begin(MmcOp::Read { lba: 0, blocks: 8 }), Ok(()));
        match m.poll(Feedback::begin(), &mut bank) {
            PollStep::Publish(plan) => assert_eq!(plan.bytes, 16384),
            other => panic!("expected publish, got {other:?}"),
        }
        match m.poll(Feedback::plan_accepted(), &mut bank) {
            PollStep::Io(StorageOp::Read { offset, buf, .. }) => {
                assert_eq!(offset, 0);
                fill_pattern(buf, 0);
            }
            other => panic!("expected read IO, got {other:?}"),
        }
        match m.poll(io_receipt(8192), &mut bank) {
            PollStep::Send(bytes) => assert_eq!(bytes.len(), 8192),
            other => panic!("expected send, got {other:?}"),
        }
        match m.poll(
            Feedback::host_sent(HostReceipt::test(8192, None)),
            &mut bank,
        ) {
            PollStep::Prefetch(PrefetchOp::Read { offset, .. }) => assert_eq!(offset, 8192),
            other => panic!("expected prefetch, got {other:?}"),
        }
        // The speculative read fails; the same range is read again as required.
        match m.poll(
            Feedback::io_done(IoReceipt::test(0, Some(Fault::Io), Effect::Known)),
            &mut bank,
        ) {
            PollStep::Io(StorageOp::Read { offset, buf, .. }) => {
                assert_eq!(offset, 8192);
                assert_eq!(buf.len(), 8192);
                fill_pattern(buf, 8192);
            }
            other => panic!("expected fallback read IO, got {other:?}"),
        }
        match m.poll(io_receipt(8192), &mut bank) {
            PollStep::Send(bytes) => {
                for (i, byte) in bytes.iter().enumerate() {
                    assert_eq!(*byte, ((8192 + i) & 0xFF) as u8);
                }
            }
            other => panic!("expected send, got {other:?}"),
        }
        assert!(matches!(
            m.poll(
                Feedback::host_sent(HostReceipt::test(8192, None)),
                &mut bank
            ),
            PollStep::Complete(Completion::Good)
        ));
    }
}
