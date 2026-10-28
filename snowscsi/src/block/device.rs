//! Direct-access block profile: READ(10) / WRITE(10) / SYNCHRONIZE CACHE(10)
//! and FORMAT UNIT over the core poll seam.
//!
//! Authority: `__ARCH__/design/02-api-profiles.md` §5.1–§5.5,
//! `02-api-behavior.md` §8.1/§8.3 and `03-lifecycles.md` §3.4.
//!
//! The device is **non-generic**: it owns geometry, command state, sense and
//! the runtime write policy, but never the backing bytes. Data IO is expressed
//! as [`StorageOp`] and executed by the runner through a [`Storage`] adapter;
//! the device never calls the adapter itself and never allocates.
//!
//! Command-specific failures are fixed in `prepare`, i.e. before any backing
//! access. The runner adds the orthogonal facts it alone owns: `host_bytes`
//! contract checks, short transfer accounting and cancellation. The device
//! converts an adapter [`Fault`] into a wire sense through
//! [`storage_fault_sense`] (`02-api-core.md` §4.17), never a raw fault.
//!
//! [`Storage`]: crate::core::storage::Storage

use crate::block::BlockAttrs;
use crate::core::storage::StorageOp;
use crate::core::{
    storage_fault_sense, BoundaryPermit, Capacity, CommandContext, CommandPermit, Completion,
    DataPlan, Delivery, Device, Direction, Effect, Fault, Feedback, FeedbackKind, InquiryData,
    InterruptReason, IoContext, KnownEffects, LongInfo, NoMedium, PollStep, RemovalEncoding,
    SpcProfile, COMMAND_ABORTED, ILLEGAL_REQUEST, INTERNAL_FAILURE, INVALID_FIELD,
    LBA_OUT_OF_RANGE, MEDIUM_ERROR, NEEDS_RECOVERY, WRITE_ERROR, WRITE_PROTECTED,
};

/// Opcode TEST UNIT READY (SPC-3 6.33). Owned by the Block profile so the
/// public `Spc` wrapper can delegate it without fabricating GOOD.
const TEST_UNIT_READY: u8 = 0x00;
/// Opcode READ(10) (SBC-3 §5.16).
const READ_10: u8 = 0x28;
/// Opcode WRITE(10) (SBC-3 §5.23).
const WRITE_10: u8 = 0x2A;
/// Opcode SYNCHRONIZE CACHE(10) (SBC-3 §5.24).
const SYNC_CACHE_10: u8 = 0x35;
/// Opcode FORMAT UNIT (SBC-3 §5.3).
const FORMAT_UNIT: u8 = 0x04;

/// Largest MODE SENSE(10) response this profile encodes: 8-byte header plus
/// every supported mode page (24 bytes).
const MODE_SENSE_MAX: usize = 32;

/// Mode pages for the block device (SPC-4 §7.4): caching page 0x08
/// (PS=0, WCE=0, RCD=0, DRA=1) followed by the vendor-specific page 0x00.
///
/// The bytes are copied verbatim from the legacy baseline encoder
/// (`scsi::spc::ALL_MODE_PAGES`); core must not depend on the `scsi` module.
const BLOCK_MODE_PAGES: [u8; 24] = [
    0x08, 18, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x20, 0, 0, 0, 0, 0, 0, 0, /* caching PS=0 */
    0x00, 2, 0x00, 0x08, /* vendor page 0x00 */
];

/// Mode pages selected by a MODE SENSE page code (`0x3F` = all pages).
fn block_mode_pages(page: u8) -> Option<&'static [u8]> {
    match page {
        0x08 => Some(&BLOCK_MODE_PAGES[..20]),
        0x00 => Some(&BLOCK_MODE_PAGES[20..]),
        0x3F => Some(&BLOCK_MODE_PAGES),
        _ => None,
    }
}

/// CDB byte 1 bits that this profile does not implement: RDPROTECT/WRPROTECT
/// (bits 7–5), DPO, RARC and the reserved low bits. FUA (bit 3) is accepted:
/// the device has no cache of its own, so a write FUA is honoured by issuing an
/// explicit `StorageOp::Sync` after the write (the adapter owns durability).
const UNSUPPORTED_CDB1: u8 = 0xF7;

/// Per-command stage. Every stage except [`Stage::Idle`] means `active()`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Stage {
    /// No command.
    Idle,
    /// Decoded; publish the plan once, then enter the data stage.
    Publish,
    /// READ: issue the backing read.
    ReadIo,
    /// READ: send the data after the read receipt.
    Send,
    /// WRITE: receive host data.
    WriteRecv,
    /// WRITE: issue the backing write.
    WriteIo,
    /// WRITE with FUA: flush after the write before completing.
    PostSync,
    /// SYNCHRONIZE CACHE: issue the flush.
    SyncIo,
    /// Completion fixed.
    Done,
}

/// Non-generic block device. Geometry and policy only; the backing lives in
/// the application's `Storage` adapter (`05 §5.1`).
pub struct BlockDevice {
    attrs: BlockAttrs,
    stage: Stage,
    direction: Direction,
    lba: u64,
    offset: u64,
    blocks: u16,
    /// Requested byte count (`blocks * block_len`, or 0).
    bytes: u32,
    /// Host bytes actually accepted, used for the write receipt comparison.
    accepted: u32,
    /// The current command requested FUA (force unit access).
    fua: bool,
    /// Host failure that takes precedence over a later storage result.
    host_error: Option<Completion>,
    last_completion: Option<Completion>,
    effects: KnownEffects,
    delivery: Delivery,
    io_issues: u32,
}

impl BlockDevice {
    /// Build a block device from static attributes.
    #[must_use]
    pub fn new(attrs: BlockAttrs) -> Self {
        Self {
            attrs,
            stage: Stage::Idle,
            direction: Direction::None,
            lba: 0,
            offset: 0,
            blocks: 0,
            bytes: 0,
            accepted: 0,
            fua: false,
            host_error: None,
            last_completion: None,
            effects: KnownEffects::NONE,
            delivery: Delivery::NotApplicable,
            io_issues: 0,
        }
    }

    /// Static attributes fixed at construction.
    #[must_use]
    pub const fn attrs(&self) -> BlockAttrs {
        self.attrs
    }

    /// Last fixed completion (probe counter, not a business API).
    #[doc(hidden)]
    #[must_use]
    pub const fn last_completion(&self) -> Option<Completion> {
        self.last_completion
    }

    /// Number of `StorageOp`s issued (probe counter, not a business API).
    #[doc(hidden)]
    #[must_use]
    pub const fn io_issues(&self) -> u32 {
        self.io_issues
    }

    /// Confirmed effects observed from receipts (not a success flag).
    ///
    /// Probe view for fixtures; not a business API (`§4.20`).
    #[doc(hidden)]
    #[must_use]
    pub const fn known_effects(&self) -> KnownEffects {
        self.effects
    }

    /// Whether the device still owns an unfinished command.
    const fn busy(&self) -> bool {
        !matches!(self.stage, Stage::Idle | Stage::Done)
    }

    /// Record an immediate completion and return to `Idle`.
    fn reject(&mut self, completion: Completion) -> Completion {
        self.stage = Stage::Idle;
        self.last_completion = Some(completion);
        completion
    }

    /// Fix a terminal completion for this command.
    fn finish(&mut self, completion: Completion) -> PollStep<'static> {
        self.stage = Stage::Done;
        self.last_completion = Some(completion);
        PollStep::Complete(completion)
    }

    /// Map an adapter fault with the direction-specific default table.
    fn storage_sense(&mut self, fault: Fault, ctx: IoContext) -> PollStep<'static> {
        match storage_fault_sense(fault, ctx) {
            Some(sense) => self.finish(Completion::Check(sense)),
            // Management/runner faults are not SCSI sense; the runner settles
            // before polling again. Keep an explicit non-silent fallback.
            None => self.finish(Completion::Check(INTERNAL_FAILURE)),
        }
    }

    /// Validate a 10-byte CDB shared by READ(10)/WRITE(10)/SYNC(10).
    fn check_cdb10(&self, cdb: &[u8]) -> Result<(), Completion> {
        if cdb.len() < 10 {
            return Err(Completion::Check(INVALID_FIELD));
        }
        // Byte 6 is reserved in all three commands.
        if cdb[6] != 0 {
            return Err(Completion::Check(INVALID_FIELD));
        }
        Ok(())
    }

    /// Decode and validate one command. All checks that must precede backing
    /// access happen here; `Ok` leaves `stage = Publish`.
    fn decode(&mut self, ctx: CommandContext, cdb: &[u8]) -> Result<(), Completion> {
        let opcode = cdb
            .first()
            .copied()
            .ok_or(Completion::Check(INVALID_FIELD))?;
        match opcode {
            TEST_UNIT_READY => {
                if cdb.len() < 6 {
                    return Err(Completion::Check(INVALID_FIELD));
                }
                if ctx.host_direction != Direction::None {
                    return Err(Completion::Check(INVALID_FIELD));
                }
                // A block device is always ready unless it needs recovery.
                Err(Completion::Good)
            }
            READ_10 => {
                self.check_cdb10(cdb)?;
                if cdb[1] & UNSUPPORTED_CDB1 != 0 {
                    return Err(Completion::Check(INVALID_FIELD));
                }
                if ctx.host_direction != Direction::ToHost {
                    return Err(Completion::Check(INVALID_FIELD));
                }
                self.lba = be32(&cdb[2..6]) as u64;
                self.blocks = be16(&cdb[7..9]);
                if self.blocks == 0 && ctx.host_bytes != 0 {
                    // A zero-block command declares no data phase; a non-zero
                    // ctx.host_bytes would otherwise bypass the plan contract.
                    return Err(Completion::Check(INVALID_FIELD));
                }
                // No device cache: a read FUA is accepted and needs no extra IO.
                self.fua = cdb[1] & 0x08 != 0;
                self.direction = Direction::ToHost;
                self.prepare_range()?;
                Ok(())
            }
            WRITE_10 => {
                self.check_cdb10(cdb)?;
                if cdb[1] & UNSUPPORTED_CDB1 != 0 {
                    return Err(Completion::Check(INVALID_FIELD));
                }
                if ctx.host_direction != Direction::FromHost {
                    return Err(Completion::Check(INVALID_FIELD));
                }
                if self.attrs.rejects_writes() {
                    return Err(Completion::Check(WRITE_PROTECTED));
                }
                self.lba = be32(&cdb[2..6]) as u64;
                self.blocks = be16(&cdb[7..9]);
                if self.blocks == 0 && ctx.host_bytes != 0 {
                    return Err(Completion::Check(INVALID_FIELD));
                }
                // FUA=1 on a write is honoured by a post-write Sync.
                self.fua = cdb[1] & 0x08 != 0;
                self.direction = Direction::FromHost;
                self.prepare_range()?;
                Ok(())
            }
            SYNC_CACHE_10 => {
                self.check_cdb10(cdb)?;
                // Byte 1: IMMED (bit 1) is unsupported; SYNC_NV (bit 2) is
                // accepted and ignored (no non-volatile cache).
                if cdb[1] & 0xF9 != 0 {
                    return Err(Completion::Check(INVALID_FIELD));
                }
                if cdb[1] & 0x02 != 0 {
                    return Err(Completion::Check(INVALID_FIELD));
                }
                if ctx.host_direction != Direction::None {
                    return Err(Completion::Check(INVALID_FIELD));
                }
                self.lba = be32(&cdb[2..6]) as u64;
                self.blocks = be16(&cdb[7..9]);
                self.direction = Direction::None;
                self.check_sync_range()?;
                Ok(())
            }
            FORMAT_UNIT => {
                if cdb.len() < 6 || cdb[1] & 0xE0 != 0 {
                    return Err(Completion::Check(INVALID_FIELD));
                }
                if ctx.host_direction != Direction::None {
                    return Err(Completion::Check(INVALID_FIELD));
                }
                // FMTDATA=0 is the mandatory simple (no-op) format. FMTDATA=1
                // and any CMPLST/DEFECT LIST FORMAT bits have no implementation
                // in the block profile.
                if cdb[1] & 0x1F != 0 {
                    return Err(Completion::Check(INVALID_FIELD));
                }
                self.direction = Direction::None;
                // No parameter list and no storage IO: fixed GOOD.
                Err(Completion::Good)
            }
            _ => Err(Completion::Check(ILLEGAL_REQUEST)),
        }
    }

    /// Validate the READ/WRITE range and compute `offset`/`bytes`.
    fn prepare_range(&mut self) -> Result<(), Completion> {
        if self.blocks == 0 {
            // A zero transfer length is a valid no-data command (SBC-3 §5.16).
            self.bytes = 0;
            self.offset = 0;
            return Err(Completion::Good);
        }
        if self.attrs.block_len == 0 {
            return Err(Completion::Check(INVALID_FIELD));
        }
        let end = self
            .lba
            .checked_add(u64::from(self.blocks))
            .ok_or(Completion::Check(LBA_OUT_OF_RANGE))?;
        if end > self.attrs.capacity_blocks {
            return Err(Completion::Check(LBA_OUT_OF_RANGE));
        }
        let bytes = u64::from(self.blocks) * u64::from(self.attrs.block_len);
        if bytes > u64::from(u32::MAX) {
            return Err(Completion::Check(INVALID_FIELD));
        }
        self.bytes = bytes as u32;
        self.offset = self
            .lba
            .checked_mul(u64::from(self.attrs.block_len))
            .ok_or(Completion::Check(LBA_OUT_OF_RANGE))?;
        Ok(())
    }

    /// Validate the SYNCHRONIZE CACHE range (blocks == 0 means "all remaining").
    fn check_sync_range(&mut self) -> Result<(), Completion> {
        let end = self.lba.checked_add(u64::from(self.blocks));
        let end = match self.blocks {
            0 => {
                if self.lba >= self.attrs.capacity_blocks {
                    return Err(Completion::Check(LBA_OUT_OF_RANGE));
                }
                return Ok(());
            }
            _ => end.ok_or(Completion::Check(LBA_OUT_OF_RANGE))?,
        };
        if end > self.attrs.capacity_blocks {
            return Err(Completion::Check(LBA_OUT_OF_RANGE));
        }
        Ok(())
    }

    /// Byte count for the current command, bounded by the caller's bank.
    fn slice_len(&self, bank_len: usize) -> Option<usize> {
        let len = self.bytes as usize;
        (len <= bank_len).then_some(len)
    }
}

impl Device for BlockDevice {
    type Medium = NoMedium;

    fn inquiry_data(&self) -> InquiryData {
        InquiryData::block()
    }

    fn removal_encoding(&self) -> RemovalEncoding {
        RemovalEncoding::Scsi
    }

    fn spc_profile(&self) -> Option<&dyn SpcProfile> {
        Some(self)
    }

    fn prepare(
        &mut self,
        _permit: &CommandPermit,
        ctx: CommandContext,
        cdb: &[u8],
    ) -> Result<(), Completion> {
        if self.busy() {
            return Err(Completion::Busy);
        }
        self.stage = Stage::Idle;
        self.direction = Direction::None;
        self.lba = 0;
        self.offset = 0;
        self.blocks = 0;
        self.bytes = 0;
        self.accepted = 0;
        self.fua = false;
        self.host_error = None;
        self.last_completion = None;
        // Effects are per-command facts, never a cumulative counter.
        self.effects = KnownEffects::NONE;
        if self.attrs.needs_recovery {
            return Err(self.reject(Completion::Check(NEEDS_RECOVERY)));
        }
        match self.decode(ctx, cdb) {
            Ok(()) => {
                self.stage = Stage::Publish;
                Ok(())
            }
            Err(completion) => Err(self.reject(completion)),
        }
    }

    fn active(&self) -> bool {
        self.busy()
    }

    fn resume(&mut self, _permit: &CommandPermit) -> Result<(), Completion> {
        if self.busy() {
            Ok(())
        } else {
            Err(Completion::Busy)
        }
    }

    fn poll<'a>(
        &mut self,
        _permit: &CommandPermit,
        fb: Feedback,
        data: &'a mut [u8],
    ) -> PollStep<'a> {
        let Some(len) = self.slice_len(data.len()) else {
            return self.finish(Completion::Check(INVALID_FIELD));
        };
        match (self.stage, fb.kind()) {
            (Stage::Publish, FeedbackKind::Begin) => {
                let plan = DataPlan {
                    direction: self.direction,
                    bytes: u64::from(self.bytes),
                };
                self.stage = match self.direction {
                    Direction::ToHost => Stage::ReadIo,
                    Direction::FromHost => Stage::WriteRecv,
                    Direction::None => Stage::SyncIo,
                };
                PollStep::Publish(plan)
            }
            // READ: issue the backing read once the plan is accepted.
            (Stage::ReadIo, FeedbackKind::PlanAccepted) => {
                self.io_issues = self.io_issues.saturating_add(1);
                PollStep::Io(StorageOp::Read {
                    resource: 0,
                    offset: self.offset,
                    buf: &mut data[..len],
                })
            }
            (Stage::ReadIo, FeedbackKind::IoDone) => {
                let Some(receipt) = fb.io() else {
                    return self.finish(Completion::Check(INTERNAL_FAILURE));
                };
                if let Some(fault) = receipt.error() {
                    return self.storage_sense(fault, IoContext::Read);
                }
                if receipt.confirmed() != len {
                    // Short read: a read has no write effect to keep; report the
                    // failure without inventing a confirmed write prefix.
                    return self.finish(Completion::Check(MEDIUM_ERROR));
                }
                self.stage = Stage::Send;
                PollStep::Send(&data[..len])
            }
            (Stage::Send, FeedbackKind::HostSent) => {
                let (accepted, failed) = host_facts(fb, len);
                self.effects.host_prefix = accepted as u64;
                if failed || accepted < len {
                    self.finish(Completion::Check(COMMAND_ABORTED))
                } else {
                    self.finish(Completion::Good)
                }
            }
            // WRITE: receive host data, then write the accepted prefix.
            (Stage::WriteRecv, FeedbackKind::PlanAccepted) => PollStep::Receive(&mut data[..len]),
            (Stage::WriteRecv, FeedbackKind::HostReceived) => {
                let (accepted, failed) = host_facts(fb, len);
                self.accepted = accepted as u32;
                self.effects.host_prefix = accepted as u64;
                if accepted == 0 {
                    // Zero progress: nothing to write, and the command fails.
                    return self.finish(Completion::Check(COMMAND_ABORTED));
                }
                self.host_error = if failed || accepted < len {
                    Some(Completion::Check(COMMAND_ABORTED))
                } else {
                    None
                };
                self.stage = Stage::WriteIo;
                self.io_issues = self.io_issues.saturating_add(1);
                PollStep::Io(StorageOp::Write {
                    resource: 0,
                    offset: self.offset,
                    buf: &data[..accepted],
                })
            }
            (Stage::WriteIo, FeedbackKind::IoDone) => {
                let Some(receipt) = fb.io() else {
                    return self.finish(Completion::Check(INTERNAL_FAILURE));
                };
                if let Some(fault) = receipt.error() {
                    self.effects.confirmed_write = self
                        .effects
                        .confirmed_write
                        .saturating_add(receipt.confirmed() as u64);
                    if receipt.effect() == Effect::UnknownRemainder {
                        self.effects.unknown_remainder = true;
                    }
                    return self.storage_sense(fault, IoContext::Write);
                }
                self.effects.confirmed_write = self
                    .effects
                    .confirmed_write
                    .saturating_add(receipt.confirmed() as u64);
                if receipt.effect() == Effect::UnknownRemainder {
                    self.effects.unknown_remainder = true;
                }
                let short = receipt.confirmed() < self.accepted as usize;
                if self.fua && self.host_error.is_none() && !short {
                    // FUA write: flush before reporting GOOD. The adapter owns
                    // whether the flush really reaches non-volatile storage.
                    self.stage = Stage::PostSync;
                    self.io_issues = self.io_issues.saturating_add(1);
                    return PollStep::Io(StorageOp::Sync { resource: 0 });
                }
                match self.host_error.take() {
                    Some(completion) => self.finish(completion),
                    None if short => self.finish(Completion::Check(WRITE_ERROR)),
                    None => self.finish(Completion::Good),
                }
            }
            (Stage::PostSync, FeedbackKind::IoDone) => {
                let Some(receipt) = fb.io() else {
                    return self.finish(Completion::Check(INTERNAL_FAILURE));
                };
                if let Some(fault) = receipt.error() {
                    // The data write is confirmed but not durable; report the
                    // write path failure without claiming durability.
                    if receipt.effect() == Effect::UnknownRemainder {
                        self.effects.unknown_remainder = true;
                    }
                    return self.storage_sense(fault, IoContext::Write);
                }
                if receipt.effect() != Effect::Known {
                    // The flush did not confirm its effect: a FUA write must not
                    // report GOOD (`03 §3.4`).
                    self.effects.unknown_remainder = true;
                    return self.finish(Completion::Check(WRITE_ERROR));
                }
                self.effects.sync_durable = true;
                self.finish(Completion::Good)
            }
            // SYNCHRONIZE CACHE: publish a no-data plan, then flush.
            (Stage::SyncIo, FeedbackKind::PlanAccepted) => {
                self.io_issues = self.io_issues.saturating_add(1);
                PollStep::Io(StorageOp::Sync { resource: 0 })
            }
            (Stage::SyncIo, FeedbackKind::IoDone) => {
                let Some(receipt) = fb.io() else {
                    return self.finish(Completion::Check(INTERNAL_FAILURE));
                };
                if let Some(fault) = receipt.error() {
                    if receipt.effect() == Effect::UnknownRemainder {
                        self.effects.unknown_remainder = true;
                    }
                    return self.storage_sense(fault, IoContext::Sync);
                }
                if receipt.effect() != Effect::Known {
                    self.effects.unknown_remainder = true;
                    return self.finish(Completion::Check(MEDIUM_ERROR));
                }
                self.effects.sync_durable = true;
                self.finish(Completion::Good)
            }
            _ => PollStep::Idle,
        }
    }

    fn poll_long<'a>(
        &mut self,
        _permit: &CommandPermit,
        _fb: Feedback,
        _data: &'a mut [u8],
    ) -> PollStep<'a> {
        PollStep::Idle
    }

    fn long_info(&self) -> LongInfo {
        LongInfo::IDLE
    }

    fn interrupt(
        &mut self,
        _permit: &CommandPermit,
        _reason: InterruptReason,
        known: KnownEffects,
    ) -> Result<(), Fault> {
        self.effects.confirmed_write = self
            .effects
            .confirmed_write
            .saturating_add(known.confirmed_write);
        self.effects.sync_durable |= known.sync_durable;
        self.effects.unknown_remainder |= known.unknown_remainder;
        self.effects.host_prefix = self.effects.host_prefix.max(known.host_prefix);
        self.stage = Stage::Idle;
        self.direction = Direction::None;
        self.bytes = 0;
        self.accepted = 0;
        self.fua = false;
        self.host_error = None;
        if self.attrs.needs_recovery {
            return Err(Fault::NeedsRecovery);
        }
        Ok(())
    }

    fn finish_delivery(&mut self, _permit: &CommandPermit, delivery: Delivery) {
        self.delivery = delivery;
    }

    fn commit(&mut self, _permit: &BoundaryPermit) -> Result<(), Completion> {
        // No local commit while a command is live; the block profile has no
        // medium metadata to persist, but the boundary rule still applies.
        if self.busy() {
            Err(Completion::Busy)
        } else {
            Ok(())
        }
    }

    fn take_medium(&mut self, _permit: &BoundaryPermit) -> Option<NoMedium> {
        if self.busy() {
            None
        } else {
            Some(NoMedium)
        }
    }

    fn install_medium(
        &mut self,
        _permit: &BoundaryPermit,
        medium: NoMedium,
    ) -> Result<(), (NoMedium, Fault)> {
        if self.busy() {
            Err((medium, Fault::Contract))
        } else {
            Ok(())
        }
    }
}

/// Public query profile for the block device: MODE SENSE (pages 0x00, 0x08
/// and 0x3F) and READ CAPACITY(10). GET CONFIGURATION and GESN keep the
/// default `None`, so `Spc` delegates those opcodes to the inner device.
impl SpcProfile for BlockDevice {
    fn medium_type(&self) -> u8 {
        0
    }

    fn write_protected(&self) -> bool {
        // A statically read-only backing or the runtime latch both set WP.
        self.attrs.rejects_writes()
    }

    fn mode_sense(
        &self,
        ten: bool,
        page: u8,
        _dbd: bool,
        pc: u8,
        out: Option<&mut [u8]>,
    ) -> Option<usize> {
        let pages = block_mode_pages(page)?;
        if pc == 3 {
            // Saved pages are unsupported; `Spc` rejects PC=11b before this.
            return None;
        }
        let header = if ten { 8 } else { 4 };
        let total = header + pages.len();
        let mut buf = [0u8; MODE_SENSE_MAX];
        if ten {
            let mode_len = (total - 2) as u16;
            buf[..2].copy_from_slice(&mode_len.to_be_bytes());
            buf[2] = self.medium_type();
            buf[3] = if self.write_protected() { 0x80 } else { 0x00 };
            // Bytes 4..6 are reserved and the block descriptor length (6..8)
            // stays zero: no block descriptor is ever returned.
        } else {
            buf[0] = (total - 1) as u8;
            buf[1] = self.medium_type();
            buf[2] = if self.write_protected() { 0x80 } else { 0x00 };
            // Byte 3 (block descriptor length) stays zero.
        }
        if pc == 1 {
            // Changeable mask: the pages have no changeable fields, so keep
            // the page code/length bytes and zero the payload (same choice as
            // the baseline encoder).
            let mut at = 0usize;
            while at + 2 <= pages.len() {
                let payload = pages[at + 1] as usize;
                buf[header + at] = pages[at];
                buf[header + at + 1] = pages[at + 1];
                at += 2 + payload;
            }
        } else {
            // PC=00b (current) and PC=10b (default) share the same bytes.
            buf[header..total].copy_from_slice(pages);
        }
        if let Some(out) = out {
            // The declared header length always describes `total`, even when
            // the host allocation truncates the response.
            let n = total.min(out.len());
            out[..n].copy_from_slice(&buf[..n]);
        }
        Some(total)
    }

    fn read_capacity(&self) -> Option<Capacity> {
        // Zero blocks is not a valid geometry; clamping keeps the wire value
        // representable (`last_lba` is 32 bits).
        let last = self.attrs.capacity_blocks.saturating_sub(1);
        let last_lba = last.min(u64::from(u32::MAX)) as u32;
        Some(Capacity::new(last_lba, self.attrs.block_len))
    }
}

/// Accepted-prefix and failure facts from a host receipt.
fn host_facts(fb: Feedback, len: usize) -> (usize, bool) {
    match fb.host() {
        Some(receipt) => {
            let accepted = receipt.accepted().min(len);
            (accepted, receipt.error().is_some())
        }
        // A missing receipt is a contract breach, never a success.
        None => (0, true),
    }
}

/// Big-endian 16-bit field from a CDB.
fn be16(bytes: &[u8]) -> u16 {
    (u16::from(bytes[0]) << 8) | u16::from(bytes[1])
}

/// Big-endian 32-bit field from a CDB.
fn be32(bytes: &[u8]) -> u32 {
    (u32::from(bytes[0]) << 24)
        | (u32::from(bytes[1]) << 16)
        | (u32::from(bytes[2]) << 8)
        | u32::from(bytes[3])
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::core::storage::{HostReceipt, IoReceipt, StorageReceipt};
    use crate::core::Effect;

    fn cdb10(opcode: u8, lba: u32, blocks: u16) -> [u8; 10] {
        let mut cdb = [0u8; 10];
        cdb[0] = opcode;
        cdb[2] = (lba >> 24) as u8;
        cdb[3] = (lba >> 16) as u8;
        cdb[4] = (lba >> 8) as u8;
        cdb[5] = lba as u8;
        cdb[7] = (blocks >> 8) as u8;
        cdb[8] = blocks as u8;
        cdb
    }

    fn ctx(direction: Direction, bytes: u64) -> CommandContext {
        CommandContext {
            lun: 0,
            lun_count: 1,
            host_bytes: bytes,
            host_direction: direction,
        }
    }

    fn permit() -> CommandPermit {
        CommandPermit::new(crate::core::TargetId::UNBOUND)
    }

    fn device() -> BlockDevice {
        BlockDevice::new(BlockAttrs::new(16, 512))
    }

    fn io_receipt(confirmed: usize, error: Option<Fault>) -> Feedback {
        Feedback::io_done(IoReceipt::test(confirmed, error, Effect::Known))
    }

    #[test]
    fn read_publishes_reads_then_sends() {
        let mut dev = device();
        let permit = permit();
        let mut data = [0u8; 1024];
        assert_eq!(
            dev.prepare(&permit, ctx(Direction::ToHost, 1024), &cdb10(READ_10, 2, 2)),
            Ok(())
        );
        let plan = match dev.poll(&permit, Feedback::begin(), &mut data) {
            PollStep::Publish(plan) => plan,
            other => panic!("expected publish, got {other:?}"),
        };
        assert_eq!(
            plan,
            DataPlan {
                direction: Direction::ToHost,
                bytes: 1024
            }
        );
        match dev.poll(&permit, Feedback::plan_accepted(), &mut data) {
            PollStep::Io(StorageOp::Read {
                resource,
                offset,
                buf,
            }) => {
                assert_eq!(resource, 0);
                assert_eq!(offset, 1024);
                assert_eq!(buf.len(), 1024);
            }
            other => panic!("expected read IO, got {other:?}"),
        }
        assert_eq!(dev.io_issues(), 1);
        match dev.poll(&permit, io_receipt(1024, None), &mut data) {
            PollStep::Send(bytes) => assert_eq!(bytes.len(), 1024),
            other => panic!("expected send, got {other:?}"),
        }
        let receipt = HostReceipt::test(1024, None);
        assert!(matches!(
            dev.poll(&permit, Feedback::host_sent(receipt), &mut data),
            PollStep::Complete(Completion::Good)
        ));
        assert!(!dev.active());
        assert_eq!(dev.last_completion(), Some(Completion::Good));
    }

    #[test]
    fn read_short_receipt_keeps_prefix_and_fails() {
        let mut dev = device();
        let permit = permit();
        let mut data = [0u8; 512];
        dev.prepare(&permit, ctx(Direction::ToHost, 512), &cdb10(READ_10, 0, 1))
            .expect("prepare");
        dev.poll(&permit, Feedback::begin(), &mut data);
        dev.poll(&permit, Feedback::plan_accepted(), &mut data);
        assert!(matches!(
            dev.poll(&permit, io_receipt(128, None), &mut data),
            PollStep::Complete(Completion::Check(MEDIUM_ERROR))
        ));
        assert_eq!(
            dev.known_effects().confirmed_write,
            0,
            "a read prefix is not a write effect"
        );
    }

    #[test]
    fn read_io_error_maps_to_medium_error() {
        let mut dev = device();
        let permit = permit();
        let mut data = [0u8; 512];
        dev.prepare(&permit, ctx(Direction::ToHost, 512), &cdb10(READ_10, 0, 1))
            .expect("prepare");
        dev.poll(&permit, Feedback::begin(), &mut data);
        dev.poll(&permit, Feedback::plan_accepted(), &mut data);
        assert!(matches!(
            dev.poll(&permit, io_receipt(0, Some(Fault::Io)), &mut data),
            PollStep::Complete(Completion::Check(MEDIUM_ERROR))
        ));
    }

    #[test]
    fn write_receives_then_writes_then_good() {
        let mut dev = device();
        let permit = permit();
        let mut data = [0u8; 512];
        dev.prepare(
            &permit,
            ctx(Direction::FromHost, 512),
            &cdb10(WRITE_10, 1, 1),
        )
        .expect("prepare");
        let plan = match dev.poll(&permit, Feedback::begin(), &mut data) {
            PollStep::Publish(plan) => plan,
            other => panic!("expected publish, got {other:?}"),
        };
        assert_eq!(plan.bytes, 512);
        assert!(matches!(
            dev.poll(&permit, Feedback::plan_accepted(), &mut data),
            PollStep::Receive(_)
        ));
        match dev.poll(
            &permit,
            Feedback::host_received(HostReceipt::test(512, None)),
            &mut data,
        ) {
            PollStep::Io(StorageOp::Write {
                resource,
                offset,
                buf,
            }) => {
                assert_eq!(resource, 0);
                assert_eq!(offset, 512);
                assert_eq!(buf.len(), 512);
            }
            other => panic!("expected write IO, got {other:?}"),
        }
        assert!(matches!(
            dev.poll(&permit, io_receipt(512, None), &mut data),
            PollStep::Complete(Completion::Good)
        ));
        assert_eq!(dev.known_effects().confirmed_write, 512);
    }

    #[test]
    fn write_protected_rejected_before_backing() {
        let mut dev = BlockDevice::new(BlockAttrs {
            capacity_blocks: 16,
            block_len: 512,
            write_mode: crate::core::Writability::ReadOnly,
            write_protected: false,
            needs_recovery: false,
        });
        let permit = permit();
        let cdb = cdb10(WRITE_10, 0, 1);
        assert_eq!(
            dev.prepare(&permit, ctx(Direction::FromHost, 512), &cdb),
            Err(Completion::Check(WRITE_PROTECTED))
        );
        assert_eq!(dev.io_issues(), 0);
        assert!(!dev.active());
    }

    #[test]
    fn lba_out_of_range_and_overflow_are_rejected_without_io() {
        let mut dev = device();
        let permit = permit();
        assert_eq!(
            dev.prepare(
                &permit,
                ctx(Direction::ToHost, 1024),
                &cdb10(READ_10, 15, 2)
            ),
            Err(Completion::Check(LBA_OUT_OF_RANGE))
        );
        assert_eq!(dev.io_issues(), 0);
        assert_eq!(
            dev.prepare(
                &permit,
                ctx(Direction::ToHost, 512),
                &cdb10(READ_10, u32::MAX, 1)
            ),
            Err(Completion::Check(LBA_OUT_OF_RANGE))
        );
    }

    #[test]
    fn format_fmtdata_branches() {
        let mut dev = device();
        let permit = permit();
        let mut cdb = [0u8; 6];
        cdb[0] = FORMAT_UNIT;
        assert_eq!(
            dev.prepare(&permit, ctx(Direction::None, 0), &cdb),
            Err(Completion::Good),
            "FMTDATA=0 is a no-op GOOD"
        );
        assert_eq!(dev.io_issues(), 0);

        let mut dev = device();
        cdb[1] = 0x10;
        assert_eq!(
            dev.prepare(&permit, ctx(Direction::None, 0), &cdb),
            Err(Completion::Check(INVALID_FIELD))
        );
        assert_eq!(dev.io_issues(), 0);
    }

    #[test]
    fn sync_publishes_no_data_then_flushes() {
        let mut dev = device();
        let permit = permit();
        let mut data = [0u8; 0];
        dev.prepare(
            &permit,
            ctx(Direction::None, 0),
            &cdb10(SYNC_CACHE_10, 0, 0),
        )
        .expect("prepare");
        match dev.poll(&permit, Feedback::begin(), &mut data) {
            PollStep::Publish(plan) => assert_eq!(
                plan,
                DataPlan {
                    direction: Direction::None,
                    bytes: 0
                }
            ),
            other => panic!("expected publish, got {other:?}"),
        }
        assert!(matches!(
            dev.poll(&permit, Feedback::plan_accepted(), &mut data),
            PollStep::Io(StorageOp::Sync { resource: 0 })
        ));
        assert!(matches!(
            dev.poll(&permit, io_receipt(0, None), &mut data),
            PollStep::Complete(Completion::Good)
        ));
        assert!(dev.known_effects().sync_durable);
    }

    #[test]
    fn sync_immed_is_rejected() {
        let mut dev = device();
        let permit = permit();
        let mut cdb = cdb10(SYNC_CACHE_10, 0, 0);
        cdb[1] = 0x02;
        assert_eq!(
            dev.prepare(&permit, ctx(Direction::None, 0), &cdb),
            Err(Completion::Check(INVALID_FIELD))
        );
    }

    #[test]
    fn unknown_opcode_is_illegal_request() {
        let mut dev = device();
        let permit = permit();
        let mut cdb = cdb10(0xBE, 0, 1); // READ CD - MMC command on Block
        assert_eq!(
            dev.prepare(&permit, ctx(Direction::ToHost, 512), &cdb),
            Err(Completion::Check(ILLEGAL_REQUEST))
        );
        cdb[0] = 0x00; // TEST UNIT READY is now owned by the Block profile
        assert_eq!(
            dev.prepare(&permit, ctx(Direction::None, 0), &cdb[..6]),
            Err(Completion::Good)
        );
        cdb[0] = 0x7F; // still an unknown opcode
        assert_eq!(
            dev.prepare(&permit, ctx(Direction::FromHost, 512), &cdb),
            Err(Completion::Check(ILLEGAL_REQUEST))
        );
        assert_eq!(dev.io_issues(), 0);
    }

    #[test]
    fn wrong_direction_is_invalid_field() {
        let mut dev = device();
        let permit = permit();
        assert_eq!(
            dev.prepare(
                &permit,
                ctx(Direction::FromHost, 512),
                &cdb10(READ_10, 0, 1)
            ),
            Err(Completion::Check(INVALID_FIELD))
        );
        assert_eq!(
            dev.prepare(&permit, ctx(Direction::ToHost, 512), &cdb10(WRITE_10, 0, 1)),
            Err(Completion::Check(INVALID_FIELD))
        );
    }

    #[test]
    fn reserved_bits_and_short_cdb_are_invalid_field() {
        let mut dev = device();
        let permit = permit();
        let mut cdb = cdb10(READ_10, 0, 1);
        cdb[1] = 0x80; // RDPROTECT
        assert_eq!(
            dev.prepare(&permit, ctx(Direction::ToHost, 512), &cdb),
            Err(Completion::Check(INVALID_FIELD))
        );
        assert_eq!(
            dev.prepare(&permit, ctx(Direction::ToHost, 512), &cdb[..8]),
            Err(Completion::Check(INVALID_FIELD))
        );
    }

    #[test]
    fn zero_transfer_read_is_good_without_io() {
        let mut dev = device();
        let permit = permit();
        assert_eq!(
            dev.prepare(&permit, ctx(Direction::ToHost, 0), &cdb10(READ_10, 0, 0)),
            Err(Completion::Good)
        );
        assert_eq!(dev.io_issues(), 0);
    }

    #[test]
    fn busy_device_rejects_second_prepare() {
        let mut dev = device();
        let permit = permit();
        let mut data = [0u8; 512];
        dev.prepare(&permit, ctx(Direction::ToHost, 512), &cdb10(READ_10, 0, 1))
            .expect("prepare");
        dev.poll(&permit, Feedback::begin(), &mut data);
        assert_eq!(
            dev.prepare(&permit, ctx(Direction::ToHost, 512), &cdb10(READ_10, 0, 1)),
            Err(Completion::Busy)
        );
    }

    #[test]
    fn interrupt_preserves_known_effects_and_idles() {
        let mut dev = device();
        let permit = permit();
        let mut data = [0u8; 512];
        dev.prepare(
            &permit,
            ctx(Direction::FromHost, 512),
            &cdb10(WRITE_10, 0, 1),
        )
        .expect("prepare");
        dev.poll(&permit, Feedback::begin(), &mut data);
        let known = KnownEffects {
            confirmed_write: 128,
            sync_durable: false,
            unknown_remainder: true,
            host_prefix: 256,
        };
        assert_eq!(dev.interrupt(&permit, InterruptReason::Stop, known), Ok(()));
        assert!(!dev.active());
        assert_eq!(dev.known_effects().confirmed_write, 128);
        assert!(dev.known_effects().unknown_remainder);
        assert_eq!(dev.known_effects().host_prefix, 256);
    }

    #[test]
    fn needs_recovery_rejects_all_commands() {
        let mut dev = BlockDevice::new(BlockAttrs {
            capacity_blocks: 16,
            block_len: 512,
            write_mode: crate::core::Writability::Writable,
            write_protected: false,
            needs_recovery: true,
        });
        let permit = permit();
        assert_eq!(
            dev.prepare(&permit, ctx(Direction::ToHost, 512), &cdb10(READ_10, 0, 1)),
            Err(Completion::Check(NEEDS_RECOVERY))
        );
        assert_eq!(dev.io_issues(), 0);
    }

    #[test]
    fn storage_receipt_type_is_accepted_by_the_seam() {
        // Compile-time check: the profile only ever builds StorageOp values;
        // the receipt type it sees through Feedback is the core one.
        let receipt = StorageReceipt::ok(1);
        assert_eq!(receipt.confirmed, 1);
    }

    #[test]
    fn write_fua_issues_a_post_sync() {
        let mut dev = device();
        let permit = permit();
        let mut data = [0u8; 512];
        let mut cdb = cdb10(WRITE_10, 0, 1);
        cdb[1] = 0x08; // FUA
        dev.prepare(&permit, ctx(Direction::FromHost, 512), &cdb)
            .expect("prepare");
        dev.poll(&permit, Feedback::begin(), &mut data);
        dev.poll(&permit, Feedback::plan_accepted(), &mut data);
        assert!(matches!(
            dev.poll(
                &permit,
                Feedback::host_received(HostReceipt::test(512, None)),
                &mut data
            ),
            PollStep::Io(StorageOp::Write { .. })
        ));
        assert!(matches!(
            dev.poll(&permit, io_receipt(512, None), &mut data),
            PollStep::Io(StorageOp::Sync { resource: 0 })
        ));
        assert!(matches!(
            dev.poll(&permit, io_receipt(0, None), &mut data),
            PollStep::Complete(Completion::Good)
        ));
        assert!(dev.known_effects().sync_durable);
        assert_eq!(dev.io_issues(), 2, "write + post-write sync");
    }

    #[test]
    fn read_fua_is_accepted_without_extra_io() {
        let mut dev = device();
        let permit = permit();
        let mut data = [0u8; 512];
        let mut cdb = cdb10(READ_10, 0, 1);
        cdb[1] = 0x08; // FUA
        dev.prepare(&permit, ctx(Direction::ToHost, 512), &cdb)
            .expect("prepare");
        dev.poll(&permit, Feedback::begin(), &mut data);
        dev.poll(&permit, Feedback::plan_accepted(), &mut data);
        assert!(matches!(
            dev.poll(&permit, io_receipt(512, None), &mut data),
            PollStep::Send(_)
        ));
        assert!(matches!(
            dev.poll(
                &permit,
                Feedback::host_sent(HostReceipt::test(512, None)),
                &mut data
            ),
            PollStep::Complete(Completion::Good)
        ));
        assert_eq!(dev.io_issues(), 1, "a read FUA needs no flush");
    }

    #[test]
    fn write_fua_sync_failure_does_not_claim_durability() {
        let mut dev = device();
        let permit = permit();
        let mut data = [0u8; 512];
        let mut cdb = cdb10(WRITE_10, 0, 1);
        cdb[1] = 0x08;
        dev.prepare(&permit, ctx(Direction::FromHost, 512), &cdb)
            .expect("prepare");
        dev.poll(&permit, Feedback::begin(), &mut data);
        dev.poll(&permit, Feedback::plan_accepted(), &mut data);
        dev.poll(
            &permit,
            Feedback::host_received(HostReceipt::test(512, None)),
            &mut data,
        );
        dev.poll(&permit, io_receipt(512, None), &mut data);
        assert!(matches!(
            dev.poll(&permit, io_receipt(0, Some(Fault::Io)), &mut data),
            PollStep::Complete(Completion::Check(WRITE_ERROR))
        ));
        assert!(!dev.known_effects().sync_durable);
    }

    #[test]
    fn reserved_cdb1_bits_are_rejected_but_fua_is_accepted() {
        let mut dev = device();
        let permit = permit();
        let mut cdb = cdb10(READ_10, 0, 1);
        for bit in [0x80u8, 0x40, 0x20, 0x10, 0x04, 0x02, 0x01] {
            cdb[1] = bit;
            assert_eq!(
                dev.prepare(&permit, ctx(Direction::ToHost, 512), &cdb),
                Err(Completion::Check(INVALID_FIELD)),
                "byte1 bit {bit:#04x} must be rejected"
            );
        }
        cdb[1] = 0x08; // FUA is accepted
        assert_eq!(
            dev.prepare(&permit, ctx(Direction::ToHost, 512), &cdb),
            Ok(())
        );
    }

    #[test]
    fn write_fua_sync_unknown_effect_does_not_claim_good() {
        let mut dev = device();
        let permit = permit();
        let mut data = [0u8; 512];
        let mut cdb = cdb10(WRITE_10, 0, 1);
        cdb[1] = 0x08;
        dev.prepare(&permit, ctx(Direction::FromHost, 512), &cdb)
            .expect("prepare");
        dev.poll(&permit, Feedback::begin(), &mut data);
        dev.poll(&permit, Feedback::plan_accepted(), &mut data);
        dev.poll(
            &permit,
            Feedback::host_received(HostReceipt::test(512, None)),
            &mut data,
        );
        dev.poll(&permit, io_receipt(512, None), &mut data);
        let unknown = Feedback::io_done(IoReceipt::test(0, None, Effect::UnknownRemainder));
        assert!(matches!(
            dev.poll(&permit, unknown, &mut data),
            PollStep::Complete(Completion::Check(WRITE_ERROR))
        ));
        assert!(!dev.known_effects().sync_durable);
        assert!(dev.known_effects().unknown_remainder);
    }

    #[test]
    fn sync_unknown_effect_does_not_claim_durable() {
        let mut dev = device();
        let permit = permit();
        let mut data = [0u8; 0];
        dev.prepare(
            &permit,
            ctx(Direction::None, 0),
            &cdb10(SYNC_CACHE_10, 0, 0),
        )
        .expect("prepare");
        dev.poll(&permit, Feedback::begin(), &mut data);
        assert!(matches!(
            dev.poll(&permit, Feedback::plan_accepted(), &mut data),
            PollStep::Io(StorageOp::Sync { .. })
        ));
        let unknown = Feedback::io_done(IoReceipt::test(0, None, Effect::UnknownRemainder));
        assert!(matches!(
            dev.poll(&permit, unknown, &mut data),
            PollStep::Complete(Completion::Check(MEDIUM_ERROR))
        ));
        assert!(!dev.known_effects().sync_durable);
        assert!(dev.known_effects().unknown_remainder);
    }
}
