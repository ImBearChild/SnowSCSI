//! Device lifecycle seam and the static profile descriptors it exposes.
//!
//! [`Device`] owns only "can a pair member be handed back / installed" and the
//! command lifecycle; it never sees profile behaviour. `Medium` has no unified
//! trait bound: it may be [`NoMedium`], an MMC medium, or an application type.
//!
//! `Feedback`/`FeedbackKind`/`PollStep` are declared here because the
//! [`Device::poll`] signature needs them. This is the staging shape: the
//! runner owns construction/consumption of `Feedback`, and the storage
//! (`Io`/`Prefetch`) variants of [`PollStep`] arrive with the `StorageOp`
//! vocabulary in the storage/host card.

use super::eject::RemovalLocks;
use super::errors::{Completion, Delivery, Fault, KnownEffects};
use super::long::LongInfo;
use super::permit::{BoundaryPermit, CommandPermit};
use super::profile::SpcProfile;
use super::storage::{HostReceipt, IoReceipt, PrefetchOp, StorageOp};

/// Core's zero-sized placeholder pair member. It implements no trait; a
/// medium-less device uses `type Medium = NoMedium` and treats it purely as an
/// ownership token.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct NoMedium;

/// The two members a slot owns: a medium and its backing handle.
#[derive(Debug, PartialEq, Eq)]
pub struct Pair<M, B> {
    /// The medium member (see [`Device::Medium`]).
    pub medium: M,
    /// The application's backing handle/identity (not the bytes themselves).
    pub backing: B,
}

/// Static INQUIRY facts. Block defaults to PDT 0x00;
/// CD-ROM/MMC overrides to 0x05.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct InquiryData {
    /// Peripheral Device Type: Block 0x00, CD-ROM 0x05.
    pub pdt: u8,
    /// Removable-medium (RMB) bit.
    pub removable: bool,
    /// Vendor identification, space/zero padded.
    pub vendor: [u8; 8],
    /// Product identification, space/zero padded.
    pub product: [u8; 16],
    /// Product revision level.
    pub revision: [u8; 4],
}

impl InquiryData {
    /// Direct-access block device: PDT 0x00, vendor "SNOW", product "SCSI",
    /// revision "P1  ".
    #[must_use]
    pub const fn block() -> Self {
        Self {
            pdt: 0x00,
            removable: false,
            vendor: *b"SNOW\0\0\0\0",
            product: *b"SCSI\0\0\0\0\0\0\0\0\0\0\0\0",
            revision: *b"P1  ",
        }
    }

    /// CD-ROM device: PDT 0x05, vendor "SNOW", product "CD-ROM", revision
    /// "P1  ".
    #[must_use]
    pub const fn cdrom() -> Self {
        Self {
            pdt: 0x05,
            removable: true,
            vendor: *b"SNOW\0\0\0\0",
            product: *b"CD-ROM\0\0\0\0\0\0\0\0\0\0",
            revision: *b"P1  ",
        }
    }
}

/// PREVENT/ALLOW encoding family.
///
/// `Scsi` is the SPC-3 Table 119 two-bit enumeration; `Mmc` is MMC-6 Table 329
/// (bit 1 selects normal/persistent, bit 0 selects clear/set).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RemovalEncoding {
    /// SBC/SPC-3 encoding, used by block devices.
    Scsi,
    /// MMC-6 encoding, used by CD-ROM/MMC devices.
    Mmc,
}

/// Direction of a host data phase.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Direction {
    /// No host data.
    None,
    /// Device → host (READ-style).
    ToHost,
    /// Host → device (WRITE-style).
    FromHost,
}

/// Command context. `lun` is the wire LUN, not a static type-level index.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct CommandContext {
    /// Wire LUN of the addressed slot.
    pub lun: u64,
    /// Fixed slot count of the owning Target. Target/StaticTarget fill
    /// this from `slot_count()`; standalone callers pass at least 1.
    pub lun_count: u32,
    /// Total host byte count declared by the command (0 = no host data).
    pub host_bytes: u64,
    /// Direction of the host data phase.
    pub host_direction: Direction,
}

/// The single data plan a device may publish for a command. It is accepted
/// once; direction and total bytes are frozen afterwards.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct DataPlan {
    /// Direction of the planned data phase.
    pub direction: Direction,
    /// Total planned byte count.
    pub bytes: u64,
}

/// Result of `Lu::admit`; a reject already carries its completion and must not
/// touch the medium/backing.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Admission {
    /// The command may proceed to `prepare`.
    Proceed,
    /// The command is rejected with this completion.
    Reject(Completion),
}

/// Target identity. Fields are private; [`TargetId::UNBOUND`] is the
/// standalone/test identity.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct TargetId(u32);

impl TargetId {
    /// Identity used by standalone LUs/runners that no `Target` owns.
    pub const UNBOUND: TargetId = TargetId(0);

    /// Mint an identity. Crate-private: only `Target`/`Runner` may stamp one
    /// Applications cannot forge ownership.
    #[allow(dead_code)] // minted by `Target` in the target/runner card
    pub(crate) const fn new(raw: u32) -> Self {
        Self(raw)
    }

    /// Raw identity value.
    #[must_use]
    pub const fn get(self) -> u32 {
        self.0
    }
}

/// Why a runner-driven abnormal settlement is being performed.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum InterruptReason {
    /// Transport reset.
    Reset,
    /// Connection/session disconnected.
    Disconnect,
    /// Host data (Data-Out) was lost.
    HostDataLost,
    /// Transport restriction (burst/credit limit) stopped the command.
    TransportRestriction,
    /// `Target::stop` drain/stop path.
    Stop,
}

/// Application control request. It is queued at the authoritative boundary by
/// the Runner; it is not a SCSI command.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Control {
    /// No-op control consumed at a complete boundary.
    Nop,
    /// Abort the active command only; medium/result transactions are untouched.
    Abort,
}

/// Static writability of a backing. It is a fact
/// field, never a behaviour dispatch; `write_protected` remains the runtime
/// policy/latch.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Writability {
    /// The backing can never be written.
    ReadOnly,
    /// The backing is writable unless a runtime latch says otherwise.
    Writable,
}

/// Feedback kind for one poll step.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum FeedbackKind {
    /// First step after `prepare`; no prior plan/receipt.
    Begin,
    /// The runner accepted the published [`DataPlan`].
    PlanAccepted,
    /// A storage operation completed (receipt available).
    IoDone,
    /// A host receive phase completed (receipt available).
    HostReceived,
    /// A host send phase completed (receipt available).
    HostSent,
}

/// Opaque per-poll feedback.
///
/// Only the runner may mint one; a device can read it but
/// cannot forge it. A device reads `kind()` and, for the matching kind, the
/// opaque [`IoReceipt`]/[`HostReceipt`].
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Feedback {
    kind: FeedbackKind,
    io: IoReceipt,
    host: HostReceipt,
}

impl Feedback {
    /// First step after `prepare`; no prior plan or receipt.
    #[allow(dead_code)] // minted by `Runner` in the runner card
    pub(crate) fn begin() -> Self {
        Self {
            kind: FeedbackKind::Begin,
            io: IoReceipt::test(0, None, super::errors::Effect::Known),
            host: HostReceipt::test(0, None),
        }
    }

    /// The runner accepted the published plan.
    #[allow(dead_code)] // minted by `Runner` in the runner card
    pub(crate) fn plan_accepted() -> Self {
        Self {
            kind: FeedbackKind::PlanAccepted,
            io: IoReceipt::test(0, None, super::errors::Effect::Known),
            host: HostReceipt::test(0, None),
        }
    }

    /// A storage operation completed; `io` carries its facts.
    #[allow(dead_code)] // minted by `Runner` in the runner card
    pub(crate) fn io_done(io: IoReceipt) -> Self {
        Self {
            kind: FeedbackKind::IoDone,
            io,
            host: HostReceipt::test(0, None),
        }
    }

    /// A host receive phase completed; `host` carries the accepted prefix.
    #[allow(dead_code)] // minted by `Runner` in the runner card
    pub(crate) fn host_received(host: HostReceipt) -> Self {
        Self {
            kind: FeedbackKind::HostReceived,
            io: IoReceipt::test(0, None, super::errors::Effect::Known),
            host,
        }
    }

    /// A host send phase completed; `host` carries the accepted prefix.
    #[allow(dead_code)] // minted by `Runner` in the runner card
    pub(crate) fn host_sent(host: HostReceipt) -> Self {
        Self {
            kind: FeedbackKind::HostSent,
            io: IoReceipt::test(0, None, super::errors::Effect::Known),
            host,
        }
    }

    /// What this poll step is reporting.
    #[must_use]
    pub const fn kind(&self) -> FeedbackKind {
        self.kind
    }

    /// Storage receipt, present only for [`FeedbackKind::IoDone`].
    #[must_use]
    pub const fn io(&self) -> Option<IoReceipt> {
        match self.kind {
            FeedbackKind::IoDone => Some(self.io),
            _ => None,
        }
    }

    /// Host receipt, present for `HostReceived`/`HostSent`.
    #[must_use]
    pub const fn host(&self) -> Option<HostReceipt> {
        match self.kind {
            FeedbackKind::HostReceived | FeedbackKind::HostSent => Some(self.host),
            _ => None,
        }
    }
}

/// One step of a command or resident long operation.
///
/// Slices are valid only for this poll step; the runner re-borrows a caller
/// bank on every pending poll and core never stores `&mut [u8]`.
///
/// A **long operation** may span several entries with one retained adapter
/// token: `Io`/`Prefetch` is issued once and polls at most once per entry
/// (`Pending` keeps the token, `Ready` delivers one `FeedbackKind::IoDone` on a
/// later entry). The runner's `data` bank (`scratch`) stays owned by the caller
/// until the operation settles, while `work` remains free for query commands.
#[derive(Debug)]
pub enum PollStep<'a> {
    /// Publish the one data plan; accepted once, then frozen.
    Publish(DataPlan),
    /// Required storage IO; the runner splits it into `IoReq` + `IoBuf`.
    Io(StorageOp<'a>),
    /// Speculative read; failure/cancel never changes the completion.
    Prefetch(PrefetchOp<'a>),
    /// Receive host data into the caller's bank (write-style commands).
    Receive(&'a mut [u8]),
    /// Send data to the host (read-style commands).
    Send(&'a [u8]),
    /// The local completion is fixed.
    Complete(Completion),
    /// No work is ready in this step.
    Idle,
}

/// Device lifecycle seam.
///
/// `inquiry_data`/`removal_encoding` are defaulted so existing implementations
/// compile unchanged; `Spc<D>` uses them for profile-aware INQUIRY and
/// PREVENT/ALLOW. `commit` is a **local** medium-metadata hook: it has no
/// `Storage` parameter and must not issue storage IO. Durable host data is
/// committed by the host's SYNCHRONIZE CACHE.
pub trait Device {
    /// The pair's medium member. No unified trait bound.
    type Medium;

    /// INQUIRY's static device data. Default: direct-access block (PDT 0x00).
    fn inquiry_data(&self) -> InquiryData {
        InquiryData::block()
    }

    /// PREVENT/ALLOW encoding family. Default: SBC / SPC-3 Table 119.
    fn removal_encoding(&self) -> RemovalEncoding {
        RemovalEncoding::Scsi
    }

    /// Optional capability set for the public SPC query commands
    /// (MODE SENSE, READ CAPACITY, GET CONFIGURATION, GET EVENT STATUS
    /// NOTIFICATION). Default: `None`, so the wrapper delegates those opcodes
    /// to the device unchanged.
    fn spc_profile(&self) -> Option<&dyn SpcProfile> {
        None
    }

    /// Optional removal-lock projection for the management view. Default:
    /// the slot has no lock state to expose.
    fn removal_locks(&self) -> Option<RemovalLocks> {
        None
    }

    /// Decode and admit a command. Returns `Busy` if a command is active.
    fn prepare(
        &mut self,
        permit: &CommandPermit,
        ctx: CommandContext,
        cdb: &[u8],
    ) -> Result<(), Completion>;

    /// A command is still active and must be resumed, not prepared anew.
    fn active(&self) -> bool;

    /// Resume after a dropped future; the runner keeps the pending feedback.
    fn resume(&mut self, permit: &CommandPermit) -> Result<(), Completion>;

    /// One step of the active command; `data` is the caller's bank.
    fn poll<'a>(
        &mut self,
        permit: &CommandPermit,
        fb: Feedback,
        data: &'a mut [u8],
    ) -> PollStep<'a>;

    /// One step of the resident long operation (if any).
    ///
    /// `data` is the caller's long-operation bank (`scratch`). The runner
    /// issues the returned `Io`/`Prefetch` once and polls it at most once per
    /// entry, retaining the token across `Pending`; the receipt comes back as a
    /// [`FeedbackKind::IoDone`] on a later entry. The bank stays owned by the
    /// caller until the operation settles; a concurrent query command uses
    /// `work`, never this bank.
    fn poll_long<'a>(
        &mut self,
        permit: &CommandPermit,
        fb: Feedback,
        data: &'a mut [u8],
    ) -> PollStep<'a>;

    /// Projection of the resident long operation.
    fn long_info(&self) -> LongInfo;

    /// Settle an abnormal end after in-flight IO has settled and `known` facts
    /// are available. Preserve real effects, never replay unknown writes, and
    /// perform at most bounded cleanup; a failed settle is terminal.
    fn interrupt(
        &mut self,
        permit: &CommandPermit,
        reason: InterruptReason,
        known: KnownEffects,
    ) -> Result<(), Fault>;

    /// Book the delivery outcome of a command whose completion is fixed. Must
    /// not restart the command or overwrite the issued completion.
    fn finish_delivery(&mut self, permit: &CommandPermit, delivery: Delivery);

    /// Local medium-metadata commit before detaching the old pair. It has no
    /// `Storage` parameter, must not issue storage IO, and is not a durability
    /// promise. Default: no-op.
    fn commit(&mut self, permit: &BoundaryPermit) -> Result<(), Completion> {
        let _ = permit;
        Ok(())
    }

    /// Host EJECT succeeded: the SPC wrapper may clear the normal (never the
    /// persistent) PREVENT latch. Default: no-op.
    fn host_eject_succeeded(&mut self, permit: &BoundaryPermit) {
        let _ = permit;
    }

    /// Detach the resident medium at a management boundary.
    fn take_medium(&mut self, permit: &BoundaryPermit) -> Option<Self::Medium>;

    /// Install a medium at a management boundary; returns it back on failure.
    fn install_medium(
        &mut self,
        permit: &BoundaryPermit,
        medium: Self::Medium,
    ) -> Result<(), (Self::Medium, Fault)>;
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::core::errors::Effect;

    struct Dummy;

    impl Device for Dummy {
        type Medium = NoMedium;

        fn prepare(
            &mut self,
            _permit: &CommandPermit,
            _ctx: CommandContext,
            _cdb: &[u8],
        ) -> Result<(), Completion> {
            Ok(())
        }

        fn active(&self) -> bool {
            false
        }

        fn resume(&mut self, _permit: &CommandPermit) -> Result<(), Completion> {
            Ok(())
        }

        fn poll<'a>(
            &mut self,
            _permit: &CommandPermit,
            _fb: Feedback,
            _data: &'a mut [u8],
        ) -> PollStep<'a> {
            PollStep::Idle
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
            _known: KnownEffects,
        ) -> Result<(), Fault> {
            Ok(())
        }

        fn finish_delivery(&mut self, _permit: &CommandPermit, _delivery: Delivery) {}

        fn take_medium(&mut self, _permit: &BoundaryPermit) -> Option<NoMedium> {
            Some(NoMedium)
        }

        fn install_medium(
            &mut self,
            _permit: &BoundaryPermit,
            _medium: NoMedium,
        ) -> Result<(), (NoMedium, Fault)> {
            Ok(())
        }
    }

    #[test]
    fn inquiry_block_fixed_bytes() {
        let data = InquiryData::block();
        assert_eq!(data.pdt, 0x00);
        assert!(!data.removable);
        assert_eq!(&data.vendor, b"SNOW\0\0\0\0");
        assert_eq!(&data.product, b"SCSI\0\0\0\0\0\0\0\0\0\0\0\0");
        assert_eq!(&data.revision, b"P1  ");
    }

    #[test]
    fn inquiry_cdrom_fixed_bytes() {
        let data = InquiryData::cdrom();
        assert_eq!(data.pdt, 0x05);
        assert!(data.removable);
        assert_eq!(&data.vendor, b"SNOW\0\0\0\0");
        assert_eq!(&data.product, b"CD-ROM\0\0\0\0\0\0\0\0\0\0");
        assert_eq!(&data.revision, b"P1  ");
    }

    #[test]
    fn device_defaults_are_block_scsi_and_noop_commit() {
        let mut dev = Dummy;
        assert_eq!(dev.inquiry_data(), InquiryData::block());
        assert_eq!(dev.removal_encoding(), RemovalEncoding::Scsi);
        let permit = BoundaryPermit::new(TargetId::UNBOUND);
        assert_eq!(dev.commit(&permit), Ok(()));
        dev.host_eject_succeeded(&permit);
        assert_eq!(dev.take_medium(&permit), Some(NoMedium));
        assert_eq!(dev.install_medium(&permit, NoMedium), Ok(()));
    }

    #[test]
    fn target_id_unbound_is_zero() {
        assert_eq!(TargetId::UNBOUND.get(), 0);
        assert_eq!(TargetId::new(7).get(), 7);
        assert_ne!(TargetId::new(7), TargetId::UNBOUND);
    }

    #[test]
    fn pair_and_admission_are_values() {
        let pair = Pair {
            medium: NoMedium,
            backing: 3u8,
        };
        assert_eq!(pair.medium, NoMedium);
        assert_eq!(pair.backing, 3);
        assert_eq!(Admission::Proceed, Admission::Proceed);
        assert_ne!(Admission::Proceed, Admission::Reject(Completion::Busy));
    }

    #[test]
    fn feedback_reports_its_kind_and_receipts() {
        let begin = Feedback::begin();
        assert_eq!(begin.kind(), FeedbackKind::Begin);
        assert_eq!(begin.io(), None);
        assert_eq!(begin.host(), None);

        let io = Feedback::io_done(IoReceipt::test(64, None, Effect::Known));
        assert_eq!(io.kind(), FeedbackKind::IoDone);
        assert_eq!(io.io().expect("io receipt").confirmed(), 64);
        assert_eq!(io.host(), None);

        let host = Feedback::host_received(HostReceipt::test(32, None));
        assert_eq!(host.kind(), FeedbackKind::HostReceived);
        assert_eq!(host.host().expect("host receipt").accepted(), 32);
        assert_eq!(host.io(), None);
    }

    #[test]
    fn poll_step_idle_and_complete_are_constructible() {
        let step: PollStep<'_> = PollStep::Idle;
        assert!(matches!(step, PollStep::Idle));
        let step: PollStep<'_> = PollStep::Complete(Completion::Good);
        assert!(matches!(step, PollStep::Complete(Completion::Good)));
    }
}
