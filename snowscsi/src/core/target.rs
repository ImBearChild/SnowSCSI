//! `Target`: the single application entry over a slot set and its runner.
//!
//! Two paths share one runner:
//!
//! - **runtime** ([`Target`] + [`RuntimeSet`]): `&mut [&mut dyn Lu]`-style
//!   tables, selected by a wire LUN at run time;
//! - **static** ([`StaticTarget`] + `Cons`/[`At`]): zero-cost type-level slot
//!   selection, still validated against the wire LUN at run time.
//!
//! Every command entry checks the LUN **before** touching a slot: a runtime LUN
//! outside the fixed set is [`Fault::LunNotFound`] (→ `05/25/00`), and
//! `ctx.lun` must equal the entry LUN (`Fault::Contract` otherwise). Read-only
//! projections (`snapshot_*`) use [`BoundaryReject::WrongSlot`] instead.
//!
//! `ctx.lun_count` is always filled from `slot_count()` here; a standalone
//! caller that bypasses `Target` must provide at least `1`.
//!
//! Production deliberately has no null host: [`Target::drive_rt`] /
//! [`StaticTarget::drive_static`] accept only commands with no host data phase
//! ([`NoHostData`]); a data-bearing command must use the `_host` variants with a
//! real [`HostTransport`]. This is a compile-time-visible contract, not a
//! zero-filled success.

// The public signatures are frozen by: the eight-argument
// step entries and the nested `Change<…>` result types are normative, so the
// generic clippy thresholds are deliberately waived here.
#![allow(clippy::too_many_arguments, clippy::type_complexity)]

use ::core::sync::atomic::{AtomicU32, Ordering};
use ::core::task::Poll;

use super::collections::{At, Index, RuntimeSet, SlotSet};
use super::device::{CommandContext, Control, DataPlan, Direction, TargetId};
use super::errors::{Completion, Delivery, Fault, Sense};
use super::long::LongInfo;
use super::lu::Lu;
use super::management::{BoundaryReject, Change, ChangeResult, LuInfo};
use super::permit::{BoundaryPermit, CommandPermit, OwnerBindPermit};
use super::runner::{DriveStep, RunOutcome, Runner};
use super::storage::{HostBuf, HostReceipt, HostReq, HostToken, HostTransport};
use super::ua::UaClass;

/// Source of fresh target identities (never reused, `Relaxed` is enough).
static NEXT_TARGET: AtomicU32 = AtomicU32::new(1);

/// A fixed slot set plus its runner.
pub struct Target<S: SlotSet> {
    owner: TargetId,
    runner: Runner,
    slots: S,
    /// Wire LUN of the single active command, if any. A step entry for another
    /// LUN is `Fault::Contract` (one command at a time).
    active_lun: Option<usize>,
}

impl<S: SlotSet> Target<S> {
    /// The only public constructor: binds every slot to a fresh identity.
    ///
    /// Adapter rebinding is the application's responsibility; the library
    /// never verifies that an adapter really points at the pair's backing.
    pub fn new(mut slots: S) -> Self {
        // `fetch_add` may wrap; slot ownership must never fall back to
        // `TargetId::UNBOUND` (0), which permits compare against.
        let raw = NEXT_TARGET.fetch_add(1, Ordering::Relaxed);
        let owner = TargetId::new(raw.max(1));
        slots.bind_owner(&OwnerBindPermit::new(), owner);
        Self {
            owner,
            runner: Runner::for_target(owner),
            slots,
            active_lun: None,
        }
    }

    /// Owning target identity.
    pub const fn owner(&self) -> TargetId {
        self.owner
    }

    /// Fixed slot count; also the value written into `CommandContext.lun_count`.
    pub fn slot_count(&self) -> usize {
        self.slots.slot_count()
    }

    /// Read-only slot-set projection (does not grant management rights).
    pub const fn slots(&self) -> &S {
        &self.slots
    }

    /// Read-only runner projection.
    pub const fn runner(&self) -> &Runner {
        &self.runner
    }

    /// Whether the resident long operation holds a retained adapter token.
    ///
    /// This is a projection, **not** a boundary: a query may still start while
    /// a long IO is in flight (split mode). A shell whose `work` bank is shared
    /// with the long operation uses it to defer input until the token settles.
    pub fn long_io_in_flight(&self) -> bool {
        self.runner.long_io_in_flight()
    }

    /// Application control entry.
    ///
    /// `Nop` requires a complete boundary on every resident slot; `Abort` may
    /// be requested while a command is active (and is consumed as a no-op when
    /// idle).
    pub fn request_control(&mut self, control: Control) -> Result<(), BoundaryReject> {
        match control {
            Control::Nop => {
                self.slots.check_boundary(&self.runner)?;
                self.runner.request_control(control)
            }
            Control::Abort => self.runner.request_control(control),
        }
    }

    /// Close new submission; the active command is drained by the next
    /// `drive_step_*` (**not** a cancel).
    pub fn stop(&mut self) {
        self.runner.request_stop();
    }

    /// Transport ended (reset/disconnect); not recoverable.
    pub fn transport_ended(&mut self) {
        self.runner.transport_ended();
    }

    /// Enter the fatal state; the next settled `tick` reports `Ended{Fatal}`.
    pub fn fatal(&mut self, fault: Fault) {
        self.runner.set_fatal(fault);
    }

    /// One service entry.
    pub fn tick(&mut self) -> RunOutcome {
        self.runner.tick()
    }
}

impl<S: RuntimeSet> Target<S> {
    /// Read-only `LuInfo` projection; an out-of-range LUN is `WrongSlot`.
    pub fn snapshot_rt(&self, lun: usize) -> Result<LuInfo, BoundaryReject> {
        self.slots
            .get_ref(lun)
            .map(|slot| slot.snapshot())
            .ok_or(BoundaryReject::WrongSlot)
    }

    /// Settle the command left live by a transport end and report the terminal
    /// outcome.
    ///
    /// [`Self::transport_ended`] only raises the terminal flag: without a later
    /// command step the slot would stay active and every command on the next
    /// connection would answer BUSY. This entry cancels the retained token (the
    /// wire is gone), settles the device with `InterruptReason::Stop`, and books
    /// the failed delivery. It is idempotent and is a no-op when no command was
    /// active.
    ///
    /// The host seam is expected to be dead (typically after
    /// `IscsiSession::connection_lost`): no PDU is staged or sent here.
    pub fn settle_transport_end(
        &mut self,
        storage: &mut dyn super::storage::Storage,
        host: &mut dyn HostTransport,
    ) -> RunOutcome {
        self.runner.transport_ended();
        if let Some(lun) = self.active_lun.take() {
            storage.select_lun(lun);
            if let Some(slot) = self.slots.get(lun) {
                let Self { runner, .. } = self;
                return runner.settle_transport_end(slot, storage, host);
            }
        }
        self.runner
            .terminal_outcome()
            .unwrap_or(RunOutcome::ServiceReady)
    }

    /// Start a command on a runtime LUN.
    ///
    /// The LUN and `ctx.lun` are checked before any slot/backing is touched.
    pub fn drive_start_rt(
        &mut self,
        lun: usize,
        ctx: CommandContext,
        cdb: &[u8],
    ) -> Result<(), Fault> {
        let count = self.slots.slot_count();
        if lun >= count {
            return Err(Fault::LunNotFound);
        }
        if ctx.lun != lun as u64 {
            return Err(Fault::Contract);
        }
        let mut ctx = ctx;
        ctx.lun_count = count as u32;
        let Self { runner, slots, .. } = self;
        let slot = slots.get(lun).ok_or(Fault::LunNotFound)?;
        runner.start_command(slot, ctx, cdb)?;
        self.active_lun = Some(lun);
        Ok(())
    }

    /// One command step. `Pending` is a real adapter state: the caller keeps
    /// `work` unchanged and calls again later.
    pub fn drive_step_rt(
        &mut self,
        lun: usize,
        storage: &mut dyn super::storage::Storage,
        host: &mut dyn HostTransport,
        work: &mut [u8],
        alt: &mut [u8],
        scratch: &mut [u8],
    ) -> Result<DriveStep, Fault> {
        let count = self.slots.slot_count();
        if lun >= count {
            return Err(Fault::LunNotFound);
        }
        if self.active_lun != Some(lun) {
            return Err(Fault::Contract);
        }
        // The adapter must know the LUN before any step work, including the
        // empty-bank rejection below: settling a retained token cancels it
        // through the adapter, and a multi-LUN adapter cancels the operation of
        // the *selected* LUN.
        storage.select_lun(lun);
        if work.is_empty() {
            // The bank is the staging capacity: a bank that cannot make
            // progress at all is a caller contract violation, never a SCSI
            // condition. `scratch` is deliberately not checked (callers may
            // pass an empty one). Settle the active command so the slot is not
            // left wedged behind it.
            let Self { runner, slots, .. } = self;
            let fault = match slots.get(lun) {
                Some(slot) => runner.reject_empty_bank(slot, storage, host),
                None => Fault::LunNotFound,
            };
            self.active_lun = None;
            return Err(fault);
        }
        let Self { runner, slots, .. } = self;
        let slot = slots.get(lun).ok_or(Fault::LunNotFound)?;
        let result = runner.step_command(slot, storage, host, work, alt, scratch)?;
        if matches!(result, DriveStep::Done(_)) {
            runner.claim_long_feedback(lun, slot.long_info());
        }
        if matches!(result, DriveStep::Done(_) | DriveStep::Control(_)) {
            self.active_lun = None;
        }
        Ok(result)
    }

    /// Busy-wait wrapper for commands **without** a host data phase.
    ///
    /// A READ/WRITE-style command needs [`Self::drive_rt_host`] or
    /// [`Self::drive_step_rt`]; this entry rejects a data plan with
    /// `Fault::Contract` rather than fabricating host bytes.
    pub fn drive_rt(
        &mut self,
        lun: usize,
        storage: &mut dyn super::storage::Storage,
        ctx: CommandContext,
        cdb: &[u8],
        work: &mut [u8],
        scratch: &mut [u8],
    ) -> Result<Completion, Fault> {
        self.drive_start_rt(lun, ctx, cdb)?;
        let mut host = NoHostData;
        loop {
            match self.drive_step_rt(lun, storage, &mut host, work, &mut [], scratch)? {
                DriveStep::Pending => {}
                DriveStep::Done(completion) => return Ok(completion),
                DriveStep::Control(_) => return Err(Fault::Cancelled),
            }
        }
    }

    /// Busy-wait wrapper with a real transport data seam.
    pub fn drive_rt_host(
        &mut self,
        lun: usize,
        storage: &mut dyn super::storage::Storage,
        host: &mut dyn HostTransport,
        ctx: CommandContext,
        cdb: &[u8],
        work: &mut [u8],
        scratch: &mut [u8],
    ) -> Result<Completion, Fault> {
        self.drive_start_rt(lun, ctx, cdb)?;
        loop {
            match self.drive_step_rt(lun, storage, host, work, &mut [], scratch)? {
                DriveStep::Pending => {}
                DriveStep::Done(completion) => return Ok(completion),
                DriveStep::Control(_) => return Err(Fault::Cancelled),
            }
        }
    }

    /// Record a successful host EJECT for a runtime LUN.
    ///
    /// # Operator eject is application policy, not a library entry
    ///
    /// The library exposes only the host-side success entry; the
    /// operator/control-plane eject (GUI/hardware button) belongs to the
    /// application. The application reads the latches from
    /// [`Self::snapshot_rt`], calls
    /// [`decide_eject`](super::eject::decide_eject) with
    /// [`EjectOrigin::Operator`](super::eject::EjectOrigin), and performs or
    /// refuses its own removal. The library deliberately offers no
    /// `operator_eject_*` entry and never detaches on that path: a refused
    /// request changes no slot state. Pinning fixture:
    /// `core_p3::operator_eject_policy_reads_live_latches_and_detaches_nothing`.
    pub fn host_eject_succeeded_rt(&mut self, lun: usize) -> Result<(), Fault> {
        if self.runner.terminal_outcome().is_some() || self.runner.has_pending_control() {
            return Err(Fault::Boundary);
        }
        self.runner.result_barrier().map_err(|_| Fault::Contract)?;
        {
            let slot = self.slots.get_ref(lun).ok_or(Fault::LunNotFound)?;
            self.runner
                .boundary::<S::Pair>(slot)
                .map_err(|_| Fault::Boundary)?;
        }
        let Self {
            runner,
            slots,
            owner,
            ..
        } = self;
        let permit = BoundaryPermit::new(*owner);
        let slot = slots.get(lun).ok_or(Fault::LunNotFound)?;
        if !slot.accepts_permit(&permit) {
            return Err(Fault::ForeignBoundary);
        }
        // Mark the transaction in flight: while it runs, `take` has nothing to
        // hand back and new service is refused.
        runner.begin_eject(lun).map_err(|_| Fault::Contract)?;
        match slot.eject_rt(&permit) {
            Ok(()) => runner.finish_eject(lun).map_err(|_| Fault::Contract),
            Err(fault) => {
                runner.eject_failed();
                Err(fault)
            }
        }
    }

    /// Record that the transport delivered a fixed CHECK CONDITION as
    /// autosense in the completion frame.
    ///
    /// The command is already settled (`drive_step_rt` returned
    /// [`DriveStep::Done`]); this only forwards the autosense-consumption event
    /// to the slot so a later REQUEST SENSE starts from a cleared instance.
    /// `sense` is the instance the completion carried, so a runner-fabricated
    /// completion cannot consume an unrelated saved sense. Transports without
    /// autosense never call it.
    #[allow(dead_code)] // called by the iSCSI transport (feature `iscsi`)
    pub(crate) fn autosense_delivered_rt(&mut self, lun: usize, sense: Sense) -> Result<(), Fault> {
        let Self { slots, owner, .. } = self;
        let slot = slots.get(lun).ok_or(Fault::LunNotFound)?;
        let permit = CommandPermit::new(*owner);
        slot.autosense_delivered(&permit, sense);
        Ok(())
    }

    /// Raise a pending unit attention on a runtime LUN.
    ///
    /// This is the transport-driven entry (a LOGICAL UNIT RESET task
    /// management function); an out-of-range LUN is [`Fault::LunNotFound`].
    /// The addressed slot decides how to report it: the public
    /// [`Spc`](super::spc::Spc) wrapper stores the condition and reports it on
    /// the next reporting command, while a bare profile keeps no
    /// unit-attention state.
    #[allow(dead_code)] // called by the iSCSI transport (feature `iscsi`)
    pub fn raise_ua_rt(&mut self, lun: usize, class: UaClass) -> Result<(), Fault> {
        let Self { slots, owner, .. } = self;
        let slot = slots.get(lun).ok_or(Fault::LunNotFound)?;
        let permit = CommandPermit::new(*owner);
        slot.raise_ua(&permit, class);
        Ok(())
    }

    /// Take a detached pair exactly once; an out-of-range LUN is `WrongSlot`.
    ///
    /// A successful take may clear the global host-eject handback barrier
    /// (`await_take`). That releases the forces deferred on other LUNs: the
    /// runner detaches such a LUN and publishes its `ResourcesReady`, so a
    /// later `take` can claim it. "One handback per take" counts *handbacks*,
    /// not forces: a force on an empty (already detached) slot detaches nothing
    /// and publishes no `ResourcesReady`, so several deferred forces may
    /// complete inside the same take while their pairs are claimed by later
    /// takes.
    pub fn take_rt(&mut self, lun: usize) -> Result<ChangeResult<S::Pair>, BoundaryReject> {
        let Self { runner, slots, .. } = self;
        let result = {
            let slot = slots.get(lun).ok_or(BoundaryReject::WrongSlot)?;
            runner.take_rt(lun, slot)?
        };
        let count = slots.slot_count();
        for other in 0..count {
            if runner.result_barrier().is_err() {
                break;
            }
            if !runner.force_pending(other) {
                continue;
            }
            let had_terminal = runner.terminal_outcome().is_some();
            let Some(slot) = slots.get(other) else {
                break;
            };
            runner.resume_pending_force(other, slot);
            // A failed detach ends the service; do not keep detaching other
            // LUNs after that first fault.
            if !had_terminal && runner.terminal_outcome().is_some() {
                break;
            }
        }
        Ok(result)
    }

    /// Save a candidate change on a runtime LUN.
    pub fn propose_rt(
        &mut self,
        lun: usize,
        change: Change<S::Pair>,
    ) -> Result<(), (Change<S::Pair>, Fault)> {
        let Self { runner, slots, .. } = self;
        let slot = match slots.get(lun) {
            Some(slot) => slot,
            None => return Err((change, Fault::LunNotFound)),
        };
        runner.propose_rt(slot, change)
    }

    /// Commit + detach old + install candidate.
    pub fn advance_rt(&mut self, lun: usize) -> Result<(), Fault> {
        let Self { runner, slots, .. } = self;
        let slot = slots.get(lun).ok_or(Fault::LunNotFound)?;
        runner.advance_rt(lun, slot)
    }

    /// Install an application-returned pair into a runtime LUN.
    pub fn install_rt(&mut self, lun: usize, pair: S::Pair) -> Result<(), (S::Pair, Fault)> {
        let Self { runner, slots, .. } = self;
        let slot = match slots.get(lun) {
            Some(slot) => slot,
            None => return Err((pair, Fault::LunNotFound)),
        };
        runner.install_rt(lun, slot, pair)
    }

    /// Emergency removal on a runtime LUN.
    ///
    /// # Settle target
    ///
    /// `drive_state` is target-global, but a command belongs to one slot, so
    /// only the LUN that owns the live command is settled. Forcing an idle LUN
    /// while another one runs detaches the addressed LUN and leaves the running
    /// command active and steppable. A slot that reports `Lu::active()` while
    /// the live command belongs elsewhere is refused with `Fault::Contract`
    /// rather than detaching an unsettled device or settling the wrong slot.
    ///
    /// # Deferred forces and bounds
    ///
    /// A force accepted while a result (on this or another LUN) or the global
    /// host-eject handback is resident detaches nothing yet: it arms a per-LUN
    /// deferral that a later `take` completes. The deferral set is an
    /// allocation-free `u64`
    /// mask (`no_std`), so **`lun >= 64` is rejected with `Fault::Contract`**
    /// before any slot state is touched (a LUN outside this target is
    /// `Fault::LunNotFound` first).
    ///
    /// # Static multi-slot limitation
    ///
    /// [`StaticTarget::take_static_at`] takes one compile-time slot and cannot
    /// enumerate the others, so it releases only the deferred force belonging to
    /// that same slot. A force deferred on a *second* static slot stays armed
    /// after that barrier clears; the application must re-issue
    /// [`StaticTarget::force_remove_static`] for it explicitly. [`Self::take_rt`]
    /// sweeps the whole runtime set instead.
    pub fn force_remove_rt(
        &mut self,
        lun: usize,
        storage: &mut dyn super::storage::Storage,
        host: &mut dyn HostTransport,
    ) -> Result<(), Fault> {
        let Self { runner, slots, .. } = self;
        let slot = slots.get(lun).ok_or(Fault::LunNotFound)?;
        storage.select_lun(lun);
        runner.force_remove_rt(lun, slot, storage, host)
    }

    /// Advance a resident long operation on a runtime LUN.
    ///
    /// `work` serves the current command (it is left untouched here); `scratch`
    /// is the resident long operation's data bank. One entry polls the adapter
    /// **at most once**: a long operation may span several entries with one
    /// retained token, and the bank stays borrowed until it settles
    /// (`Ready`/`cancel`). A query command may use `work` while a long IO is in
    /// flight. A foreign LUN (another LUN's long operation owns the
    /// slot) fails closed with `Fault::Boundary`.
    pub fn poll_long_entry_rt(
        &mut self,
        lun: usize,
        storage: &mut dyn super::storage::Storage,
        work: &mut [u8],
        scratch: &mut [u8],
    ) -> Result<LongInfo, Fault> {
        let Self { runner, slots, .. } = self;
        let slot = slots.get(lun).ok_or(Fault::LunNotFound)?;
        storage.select_lun(lun);
        // `work` is intentionally unused: a long entry must not consume the
        // bank a concurrent query command is using.
        let _ = work;
        runner.poll_long_entry(lun, slot, storage, scratch)
    }
}

/// Zero-side-effect host for the no-data convenience entries.
///
/// It accepts only a `Direction::None` / zero-byte plan. A data-bearing plan is
/// rejected and the runner settles with `Fault::Contract`; it never fabricates
/// bytes or accepts them silently.
struct NoHostData;

impl HostTransport for NoHostData {
    fn publish(&mut self, plan: DataPlan) -> Result<(), Fault> {
        if plan.direction == Direction::None && plan.bytes == 0 {
            Ok(())
        } else {
            Err(Fault::Contract)
        }
    }

    fn begin_recv(&mut self, _req: HostReq) -> HostToken {
        HostToken::invalid()
    }

    fn begin_send(&mut self, _req: HostReq) -> HostToken {
        HostToken::invalid()
    }

    fn poll_host(&mut self, _token: HostToken, _buf: HostBuf<'_>) -> Poll<HostReceipt> {
        Poll::Ready(HostReceipt::new(
            0,
            Some(Fault::Contract),
            TargetId::UNBOUND,
        ))
    }

    fn cancel(&mut self, _token: HostToken) {}

    fn delivery(&self) -> Delivery {
        Delivery::NotApplicable
    }
}

/// Static (type-level) extension over [`Target`].
///
/// A missing index is a compile error; a wrong **wire** LUN is a run-time
/// [`BoundaryReject::WrongSlot`] and must not fall through to slot 0.
pub trait StaticTarget<S: SlotSet> {
    /// Validate that `wire_lun` names the slot selected by `I`.
    fn check_wire_lun<I: Index>(&self, wire_lun: usize) -> Result<(), BoundaryReject>
    where
        S: At<I>;

    /// Read-only projection of the static slot selected by `I`.
    fn snapshot_static<I>(&self) -> LuInfo
    where
        I: Index,
        S: At<I>,
        <S as At<I>>::Slot: Lu;

    /// Start a command on the static slot selected by `I`.
    fn drive_start_static<I>(&mut self, ctx: CommandContext, cdb: &[u8]) -> Result<(), Fault>
    where
        I: Index,
        S: At<I>,
        <S as At<I>>::Slot: Lu;

    /// One step of the static slot's active command.
    fn drive_step_static<I>(
        &mut self,
        storage: &mut dyn super::storage::Storage,
        host: &mut dyn HostTransport,
        work: &mut [u8],
        alt: &mut [u8],
        scratch: &mut [u8],
    ) -> Result<DriveStep, Fault>
    where
        I: Index,
        S: At<I>,
        <S as At<I>>::Slot: Lu;

    /// Busy-wait wrapper for commands **without** a host data phase.
    fn drive_static<I>(
        &mut self,
        storage: &mut dyn super::storage::Storage,
        ctx: CommandContext,
        cdb: &[u8],
        work: &mut [u8],
        scratch: &mut [u8],
    ) -> Result<Completion, Fault>
    where
        I: Index,
        S: At<I>,
        <S as At<I>>::Slot: Lu;

    /// Busy-wait wrapper with a real transport data seam.
    fn drive_static_host<I>(
        &mut self,
        storage: &mut dyn super::storage::Storage,
        host: &mut dyn HostTransport,
        ctx: CommandContext,
        cdb: &[u8],
        work: &mut [u8],
        scratch: &mut [u8],
    ) -> Result<Completion, Fault>
    where
        I: Index,
        S: At<I>,
        <S as At<I>>::Slot: Lu;

    /// Static slot selected by `I`, addressed by a run-time wire LUN.
    fn drive_static_at<I>(
        &mut self,
        wire_lun: usize,
        storage: &mut dyn super::storage::Storage,
        ctx: CommandContext,
        cdb: &[u8],
        work: &mut [u8],
        scratch: &mut [u8],
    ) -> Result<Completion, Fault>
    where
        I: Index,
        S: At<I>,
        <S as At<I>>::Slot: Lu;

    /// Static slot selected by `I` with a real transport data seam.
    fn drive_static_at_host<I>(
        &mut self,
        wire_lun: usize,
        storage: &mut dyn super::storage::Storage,
        host: &mut dyn HostTransport,
        ctx: CommandContext,
        cdb: &[u8],
        work: &mut [u8],
        scratch: &mut [u8],
    ) -> Result<Completion, Fault>
    where
        I: Index,
        S: At<I>,
        <S as At<I>>::Slot: Lu;

    /// Take a detached pair from the static slot selected by `I`.
    fn take_static_at<I>(
        &mut self,
        wire_lun: usize,
    ) -> Result<ChangeResult<<<S as At<I>>::Slot as Lu>::Pair>, BoundaryReject>
    where
        I: Index,
        S: At<I>,
        <S as At<I>>::Slot: Lu;

    /// Record a successful host EJECT on the static slot selected by `I`.
    fn host_eject_succeeded_static<I>(&mut self) -> Result<(), Fault>
    where
        I: Index,
        S: At<I>,
        <S as At<I>>::Slot: Lu;

    /// Save a candidate change on the static slot selected by `I`.
    fn propose_static<I>(
        &mut self,
        change: Change<<<S as At<I>>::Slot as Lu>::Pair>,
    ) -> Result<(), (Change<<<S as At<I>>::Slot as Lu>::Pair>, Fault)>
    where
        I: Index,
        S: At<I>,
        <S as At<I>>::Slot: Lu;

    /// `propose → advance → take` on the static slot.
    fn advance_static<I>(&mut self) -> Result<(), Fault>
    where
        I: Index,
        S: At<I>,
        <S as At<I>>::Slot: Lu;

    /// Install an application-returned pair into the static slot.
    fn install_static<I>(
        &mut self,
        pair: <<S as At<I>>::Slot as Lu>::Pair,
    ) -> Result<(), (<<S as At<I>>::Slot as Lu>::Pair, Fault)>
    where
        I: Index,
        S: At<I>,
        <S as At<I>>::Slot: Lu;

    /// Emergency removal on the static slot.
    ///
    /// The storage adapter is told the slot's wire LUN
    /// ([`Storage::select_lun`](super::storage::Storage::select_lun)) before the
    /// detach, exactly like the runtime path.
    fn force_remove_static<I>(
        &mut self,
        storage: &mut dyn super::storage::Storage,
        host: &mut dyn HostTransport,
    ) -> Result<(), Fault>
    where
        I: Index,
        S: At<I>,
        <S as At<I>>::Slot: Lu;

    /// Advance a resident long operation on the static slot.
    ///
    /// `work` serves the current command; `scratch` is the resident long
    /// operation's data bank. One entry polls the adapter at most once, so a
    /// long operation may span several entries with one retained token; the
    /// bank stays borrowed until it settles. A query command may use `work`
    /// while a long IO is in flight because the returned operation borrows only
    /// `scratch`.
    fn poll_long_entry_static<I>(
        &mut self,
        storage: &mut dyn super::storage::Storage,
        work: &mut [u8],
        scratch: &mut [u8],
    ) -> Result<LongInfo, Fault>
    where
        I: Index,
        S: At<I>,
        <S as At<I>>::Slot: Lu;
}

impl<S: SlotSet> StaticTarget<S> for Target<S> {
    fn check_wire_lun<I: Index>(&self, wire_lun: usize) -> Result<(), BoundaryReject>
    where
        S: At<I>,
    {
        if wire_lun == I::INDEX && I::INDEX < self.slots.slot_count() {
            Ok(())
        } else {
            Err(BoundaryReject::WrongSlot)
        }
    }

    fn snapshot_static<I>(&self) -> LuInfo
    where
        I: Index,
        S: At<I>,
        <S as At<I>>::Slot: Lu,
    {
        self.slots.slot().snapshot()
    }

    fn drive_start_static<I>(&mut self, ctx: CommandContext, cdb: &[u8]) -> Result<(), Fault>
    where
        I: Index,
        S: At<I>,
        <S as At<I>>::Slot: Lu,
    {
        let count = self.slots.slot_count();
        if I::INDEX >= count {
            return Err(Fault::LunNotFound);
        }
        if ctx.lun != I::INDEX as u64 {
            return Err(Fault::Contract);
        }
        let mut ctx = ctx;
        ctx.lun_count = count as u32;
        let Self { runner, slots, .. } = self;
        runner.start_command(slots.slot_mut(), ctx, cdb)?;
        self.active_lun = Some(I::INDEX);
        Ok(())
    }

    fn drive_step_static<I>(
        &mut self,
        storage: &mut dyn super::storage::Storage,
        host: &mut dyn HostTransport,
        work: &mut [u8],
        alt: &mut [u8],
        scratch: &mut [u8],
    ) -> Result<DriveStep, Fault>
    where
        I: Index,
        S: At<I>,
        <S as At<I>>::Slot: Lu,
    {
        if self.active_lun != Some(I::INDEX) {
            return Err(Fault::Contract);
        }
        // The adapter is told the wire LUN before any step work (the empty-bank
        // rejection below settles through the adapter).
        storage.select_lun(I::INDEX);
        if work.is_empty() {
            // Same empty-bank contract as the runtime entry: the bank is the
            // staging capacity, so a bank that cannot make progress is a
            // caller contract violation, and the active command is settled
            // rather than left wedged behind it.
            let Self { runner, slots, .. } = self;
            let fault = runner.reject_empty_bank(slots.slot_mut(), storage, host);
            self.active_lun = None;
            return Err(fault);
        }
        let Self { runner, slots, .. } = self;
        let result = runner.step_command(slots.slot_mut(), storage, host, work, alt, scratch)?;
        if matches!(result, DriveStep::Done(_)) {
            runner.claim_long_feedback(I::INDEX, slots.slot_mut().long_info());
        }
        if matches!(result, DriveStep::Done(_) | DriveStep::Control(_)) {
            self.active_lun = None;
        }
        Ok(result)
    }

    fn drive_static<I>(
        &mut self,
        storage: &mut dyn super::storage::Storage,
        ctx: CommandContext,
        cdb: &[u8],
        work: &mut [u8],
        scratch: &mut [u8],
    ) -> Result<Completion, Fault>
    where
        I: Index,
        S: At<I>,
        <S as At<I>>::Slot: Lu,
    {
        self.drive_start_static::<I>(ctx, cdb)?;
        let mut host = NoHostData;
        loop {
            match self.drive_step_static::<I>(storage, &mut host, work, &mut [], scratch)? {
                DriveStep::Pending => {}
                DriveStep::Done(completion) => return Ok(completion),
                DriveStep::Control(_) => return Err(Fault::Cancelled),
            }
        }
    }

    fn drive_static_host<I>(
        &mut self,
        storage: &mut dyn super::storage::Storage,
        host: &mut dyn HostTransport,
        ctx: CommandContext,
        cdb: &[u8],
        work: &mut [u8],
        scratch: &mut [u8],
    ) -> Result<Completion, Fault>
    where
        I: Index,
        S: At<I>,
        <S as At<I>>::Slot: Lu,
    {
        self.drive_start_static::<I>(ctx, cdb)?;
        loop {
            match self.drive_step_static::<I>(storage, host, work, &mut [], scratch)? {
                DriveStep::Pending => {}
                DriveStep::Done(completion) => return Ok(completion),
                DriveStep::Control(_) => return Err(Fault::Cancelled),
            }
        }
    }

    fn drive_static_at<I>(
        &mut self,
        wire_lun: usize,
        storage: &mut dyn super::storage::Storage,
        ctx: CommandContext,
        cdb: &[u8],
        work: &mut [u8],
        scratch: &mut [u8],
    ) -> Result<Completion, Fault>
    where
        I: Index,
        S: At<I>,
        <S as At<I>>::Slot: Lu,
    {
        self.check_wire_lun::<I>(wire_lun)
            .map_err(|_| Fault::Contract)?;
        if ctx.lun != wire_lun as u64 {
            return Err(Fault::Contract);
        }
        self.drive_static::<I>(storage, ctx, cdb, work, scratch)
    }

    fn drive_static_at_host<I>(
        &mut self,
        wire_lun: usize,
        storage: &mut dyn super::storage::Storage,
        host: &mut dyn HostTransport,
        ctx: CommandContext,
        cdb: &[u8],
        work: &mut [u8],
        scratch: &mut [u8],
    ) -> Result<Completion, Fault>
    where
        I: Index,
        S: At<I>,
        <S as At<I>>::Slot: Lu,
    {
        self.check_wire_lun::<I>(wire_lun)
            .map_err(|_| Fault::Contract)?;
        if ctx.lun != wire_lun as u64 {
            return Err(Fault::Contract);
        }
        self.drive_static_host::<I>(storage, host, ctx, cdb, work, scratch)
    }

    fn take_static_at<I>(
        &mut self,
        wire_lun: usize,
    ) -> Result<ChangeResult<<<S as At<I>>::Slot as Lu>::Pair>, BoundaryReject>
    where
        I: Index,
        S: At<I>,
        <S as At<I>>::Slot: Lu,
    {
        self.check_wire_lun::<I>(wire_lun)?;
        let Self { runner, slots, .. } = self;
        runner.take_rt(I::INDEX, slots.slot_mut())
    }

    fn host_eject_succeeded_static<I>(&mut self) -> Result<(), Fault>
    where
        I: Index,
        S: At<I>,
        <S as At<I>>::Slot: Lu,
    {
        if I::INDEX >= self.slots.slot_count() {
            return Err(Fault::LunNotFound);
        }
        if self.runner.terminal_outcome().is_some() || self.runner.has_pending_control() {
            return Err(Fault::Boundary);
        }
        self.runner.result_barrier().map_err(|_| Fault::Contract)?;
        let Self {
            runner,
            slots,
            owner,
            ..
        } = self;
        let permit = BoundaryPermit::new(*owner);
        {
            let slot = slots.slot();
            runner
                .boundary::<<<S as At<I>>::Slot as Lu>::Pair>(slot)
                .map_err(|_| Fault::Boundary)?;
            if !slot.accepts_permit(&permit) {
                return Err(Fault::ForeignBoundary);
            }
        }
        runner.begin_eject(I::INDEX).map_err(|_| Fault::Contract)?;
        match slots.slot_mut().eject_rt(&permit) {
            Ok(()) => runner.finish_eject(I::INDEX).map_err(|_| Fault::Contract),
            Err(fault) => {
                runner.eject_failed();
                Err(fault)
            }
        }
    }

    fn propose_static<I>(
        &mut self,
        change: Change<<<S as At<I>>::Slot as Lu>::Pair>,
    ) -> Result<(), (Change<<<S as At<I>>::Slot as Lu>::Pair>, Fault)>
    where
        I: Index,
        S: At<I>,
        <S as At<I>>::Slot: Lu,
    {
        let Self { runner, slots, .. } = self;
        runner.propose_rt(slots.slot_mut(), change)
    }

    fn advance_static<I>(&mut self) -> Result<(), Fault>
    where
        I: Index,
        S: At<I>,
        <S as At<I>>::Slot: Lu,
    {
        let Self { runner, slots, .. } = self;
        runner.advance_rt(I::INDEX, slots.slot_mut())
    }

    fn install_static<I>(
        &mut self,
        pair: <<S as At<I>>::Slot as Lu>::Pair,
    ) -> Result<(), (<<S as At<I>>::Slot as Lu>::Pair, Fault)>
    where
        I: Index,
        S: At<I>,
        <S as At<I>>::Slot: Lu,
    {
        let Self { runner, slots, .. } = self;
        runner.install_rt(I::INDEX, slots.slot_mut(), pair)
    }

    fn force_remove_static<I>(
        &mut self,
        storage: &mut dyn super::storage::Storage,
        host: &mut dyn HostTransport,
    ) -> Result<(), Fault>
    where
        I: Index,
        S: At<I>,
        <S as At<I>>::Slot: Lu,
    {
        let Self { runner, slots, .. } = self;
        storage.select_lun(I::INDEX);
        runner.force_remove_rt(I::INDEX, slots.slot_mut(), storage, host)
    }

    fn poll_long_entry_static<I>(
        &mut self,
        storage: &mut dyn super::storage::Storage,
        work: &mut [u8],
        scratch: &mut [u8],
    ) -> Result<LongInfo, Fault>
    where
        I: Index,
        S: At<I>,
        <S as At<I>>::Slot: Lu,
    {
        let Self { runner, slots, .. } = self;
        // `work` belongs to the current command; the resident long operation
        // uses `scratch` only.
        let _ = work;
        storage.select_lun(I::INDEX);
        runner.poll_long_entry(I::INDEX, slots.slot_mut(), storage, scratch)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::block::{BlockAttrs, BlockDevice};
    use crate::core::collections::{cons, Here, Nil, There};
    use crate::core::storage::{
        BlockingHost, BlockingStorage, IoBuf, IoReq, StorageReceipt, SyncHost, SyncStorage,
    };
    use crate::core::{Completion, Direction, LuImpl, NoMedium};

    struct PassthroughStorage;

    impl SyncStorage for PassthroughStorage {
        fn exec(&mut self, _req: IoReq, buf: IoBuf<'_>) -> StorageReceipt {
            let len = match &buf {
                IoBuf::None => 0,
                IoBuf::Read(b) => b.len(),
                IoBuf::Write(b) => b.len(),
            };
            StorageReceipt::ok(len)
        }
    }

    struct RecordingHost;

    impl SyncHost for RecordingHost {
        fn publish(&mut self, _plan: DataPlan) -> Result<(), Fault> {
            Ok(())
        }
        fn receive(&mut self, _req: HostReq, buf: HostBuf<'_>) -> HostReceipt {
            if let HostBuf::Recv { buf: b, .. } = buf {
                for byte in b.iter_mut() {
                    *byte = 0x5a;
                }
            }
            HostReceipt::new(usize::MAX, None, TargetId::UNBOUND)
        }
        fn send(&mut self, _req: HostReq, _buf: HostBuf<'_>) -> HostReceipt {
            HostReceipt::new(usize::MAX, None, TargetId::UNBOUND)
        }
        fn delivery(&self) -> Delivery {
            Delivery::Complete
        }
    }

    type Slot = LuImpl<BlockDevice, u8>;

    fn slot(backing: u8) -> Slot {
        LuImpl::new(BlockDevice::new(BlockAttrs::new(16, 512)), backing)
    }

    fn read_cdb(blocks: u16) -> [u8; 10] {
        let mut cdb = [0u8; 10];
        cdb[0] = 0x28;
        cdb[8] = blocks as u8;
        cdb
    }

    fn sync_cdb() -> [u8; 10] {
        let mut cdb = [0u8; 10];
        cdb[0] = 0x35;
        cdb
    }

    fn ctx(lun: u64, direction: Direction, bytes: u64) -> CommandContext {
        CommandContext {
            lun,
            lun_count: 0,
            host_bytes: bytes,
            host_direction: direction,
        }
    }

    #[test]
    fn runtime_snapshot_and_out_of_range_wrong_slot() {
        let mut slots = [slot(1), slot(2)];
        let (head, tail) = slots.split_at_mut(1);
        let table: [&mut dyn Lu<Pair = crate::core::Pair<NoMedium, u8>>; 2] =
            [&mut head[0], &mut tail[0]];
        let target = Target::new(table);
        assert_eq!(target.slot_count(), 2);
        assert!(target.snapshot_rt(0).is_ok());
        assert!(target.snapshot_rt(1).is_ok());
        assert_eq!(target.snapshot_rt(2), Err(BoundaryReject::WrongSlot));
    }

    #[test]
    fn runtime_start_checks_lun_and_ctx() {
        let mut slots = [slot(1), slot(2)];
        let (head, tail) = slots.split_at_mut(1);
        let table: [&mut dyn Lu<Pair = crate::core::Pair<NoMedium, u8>>; 2] =
            [&mut head[0], &mut tail[0]];
        let mut target = Target::new(table);
        assert_eq!(
            target.drive_start_rt(2, ctx(2, Direction::None, 0), &sync_cdb()),
            Err(Fault::LunNotFound)
        );
        assert_eq!(
            target.drive_start_rt(0, ctx(1, Direction::None, 0), &sync_cdb()),
            Err(Fault::Contract)
        );
        assert_eq!(
            target.drive_start_rt(0, ctx(0, Direction::None, 0), &sync_cdb()),
            Ok(())
        );
    }

    #[test]
    fn runtime_sync_completes_without_host_data() {
        let mut slots = [slot(1)];
        let table: &mut [&mut dyn Lu<Pair = crate::core::Pair<NoMedium, u8>>] =
            &mut [&mut slots[0]];
        let mut target = Target::new(table);
        let mut storage = BlockingStorage::new(PassthroughStorage);
        let mut work = [0u8; 512];
        let mut scratch = [0u8; 512];
        assert_eq!(
            target.drive_rt(
                0,
                &mut storage,
                ctx(0, Direction::None, 0),
                &sync_cdb(),
                &mut work,
                &mut scratch
            ),
            Ok(Completion::Good)
        );
    }

    #[test]
    fn runtime_read_requires_the_host_entry() {
        let mut slots = [slot(1)];
        let table: &mut [&mut dyn Lu<Pair = crate::core::Pair<NoMedium, u8>>] =
            &mut [&mut slots[0]];
        let mut target = Target::new(table);
        let mut storage = BlockingStorage::new(PassthroughStorage);
        let mut work = [0u8; 512];
        let mut scratch = [0u8; 512];
        assert_eq!(
            target.drive_rt(
                0,
                &mut storage,
                ctx(0, Direction::ToHost, 512),
                &read_cdb(1),
                &mut work,
                &mut scratch
            ),
            Err(Fault::Contract),
            "the no-host entry must reject a data phase, never fabricate it"
        );

        let mut slots = [slot(1)];
        let table: &mut [&mut dyn Lu<Pair = crate::core::Pair<NoMedium, u8>>] =
            &mut [&mut slots[0]];
        let mut target = Target::new(table);
        let mut host = BlockingHost::new(RecordingHost);
        assert_eq!(
            target.drive_rt_host(
                0,
                &mut storage,
                &mut host,
                ctx(0, Direction::ToHost, 512),
                &read_cdb(1),
                &mut work,
                &mut scratch
            ),
            Ok(Completion::Good)
        );
    }

    struct LunRecorder {
        selected: Option<usize>,
    }

    impl crate::core::storage::Storage for LunRecorder {
        fn select_lun(&mut self, lun: usize) {
            self.selected = Some(lun);
        }

        fn begin_exec(&mut self, _req: IoReq) -> crate::core::storage::IoToken {
            crate::core::storage::IoToken::new(0, 1)
        }

        fn poll_exec(
            &mut self,
            _token: crate::core::storage::IoToken,
            buf: IoBuf<'_>,
        ) -> core::task::Poll<StorageReceipt> {
            let len = match &buf {
                IoBuf::None => 0,
                IoBuf::Read(b) => b.len(),
                IoBuf::Write(b) => b.len(),
            };
            core::task::Poll::Ready(StorageReceipt::ok(len))
        }

        fn cancel(&mut self, _token: crate::core::storage::IoToken) {}
    }

    #[test]
    fn static_multi_slot_drive_selects_the_wire_lun_on_the_adapter() {
        let slots = cons(slot(1), cons(slot(2), Nil));
        let mut target = Target::new(slots);
        let mut storage = LunRecorder { selected: None };
        let mut work = [0u8; 512];
        let mut scratch = [0u8; 512];
        assert_eq!(
            target.drive_static_at::<There<Here>>(
                1,
                &mut storage,
                ctx(1, Direction::None, 0),
                &sync_cdb(),
                &mut work,
                &mut scratch
            ),
            Ok(Completion::Good)
        );
        assert_eq!(
            storage.selected,
            Some(1),
            "the adapter must be told the wire LUN, not the static slot index"
        );
    }

    #[test]
    fn static_wire_lun_is_validated() {
        let slots = cons(slot(1), cons(slot(2), Nil));
        let mut target = Target::new(slots);
        assert_eq!(target.check_wire_lun::<Here>(0), Ok(()));
        assert_eq!(
            target.check_wire_lun::<Here>(1),
            Err(BoundaryReject::WrongSlot)
        );
        assert_eq!(target.check_wire_lun::<There<Here>>(1), Ok(()));
        assert_eq!(
            target.check_wire_lun::<There<Here>>(0),
            Err(BoundaryReject::WrongSlot)
        );
        let mut storage = BlockingStorage::new(PassthroughStorage);
        let mut work = [0u8; 512];
        let mut scratch = [0u8; 512];
        assert_eq!(
            target.drive_static_at::<There<Here>>(
                0,
                &mut storage,
                ctx(0, Direction::None, 0),
                &sync_cdb(),
                &mut work,
                &mut scratch
            ),
            Err(Fault::Contract)
        );
        assert_eq!(
            target.drive_static_at::<There<Here>>(
                1,
                &mut storage,
                ctx(1, Direction::None, 0),
                &sync_cdb(),
                &mut work,
                &mut scratch
            ),
            Ok(Completion::Good)
        );
    }

    #[test]
    fn static_snapshot_and_take() {
        let slots = cons(slot(1), cons(slot(2), Nil));
        let mut target = Target::new(slots);
        assert!(target.snapshot_static::<Here>().ready);
        assert!(target.snapshot_static::<There<Here>>().ready);
        assert!(target.propose_static::<Here>(Change::Remove).is_ok());
        assert!(target.advance_static::<Here>().is_ok());
        assert_eq!(
            target.take_static_at::<Here>(1),
            Err(BoundaryReject::WrongSlot)
        );
        let result = target.take_static_at::<Here>(0).expect("take");
        assert_eq!(
            result.pair,
            Some(crate::core::Pair {
                medium: NoMedium,
                backing: 1
            })
        );
    }

    #[test]
    fn control_nop_requires_every_slot_boundary() {
        let mut slots = [slot(1), slot(2)];
        let (head, tail) = slots.split_at_mut(1);
        let table: [&mut dyn Lu<Pair = crate::core::Pair<NoMedium, u8>>; 2] =
            [&mut head[0], &mut tail[0]];
        let mut target = Target::new(table);
        assert_eq!(target.request_control(Control::Nop), Ok(()));
        assert_eq!(target.tick(), RunOutcome::ControlApplied(Control::Nop));
    }

    #[test]
    fn stop_is_cooperative_and_tick_waits() {
        let mut slots = [slot(1)];
        let table: &mut [&mut dyn Lu<Pair = crate::core::Pair<NoMedium, u8>>] =
            &mut [&mut slots[0]];
        let mut target = Target::new(table);
        target.stop();
        assert_eq!(
            target.tick(),
            RunOutcome::Ended {
                reason: crate::core::RunEnd::Stopped,
                error: None
            }
        );
    }

    #[test]
    fn tick_reports_fatal_after_settlement() {
        let mut slots = [slot(1)];
        let table: &mut [&mut dyn Lu<Pair = crate::core::Pair<NoMedium, u8>>] =
            &mut [&mut slots[0]];
        let mut target = Target::new(table);
        target.fatal(Fault::NeedsRecovery);
        assert_eq!(
            target.tick(),
            RunOutcome::Ended {
                reason: crate::core::RunEnd::Fatal,
                error: Some(Fault::NeedsRecovery)
            }
        );
    }

    #[test]
    fn proposal_on_out_of_range_lun_is_lun_not_found() {
        let mut slots = [slot(1)];
        let table: &mut [&mut dyn Lu<Pair = crate::core::Pair<NoMedium, u8>>] =
            &mut [&mut slots[0]];
        let mut target = Target::new(table);
        assert_eq!(
            target.propose_rt(1, Change::Remove),
            Err((Change::Remove, Fault::LunNotFound))
        );
        assert_eq!(target.advance_rt(1), Err(Fault::LunNotFound));
        assert_eq!(
            target.install_rt(
                1,
                crate::core::Pair {
                    medium: NoMedium,
                    backing: 9
                }
            ),
            Err((
                crate::core::Pair {
                    medium: NoMedium,
                    backing: 9
                },
                Fault::LunNotFound
            ))
        );
    }

    #[test]
    fn no_host_data_rejects_a_published_plan() {
        let mut host = NoHostData;
        assert_eq!(
            host.publish(DataPlan {
                direction: Direction::None,
                bytes: 0
            }),
            Ok(())
        );
        assert_eq!(
            host.publish(DataPlan {
                direction: Direction::ToHost,
                bytes: 512
            }),
            Err(Fault::Contract)
        );
    }

    #[test]
    fn step_for_another_lun_is_contract() {
        let mut slots = [slot(1), slot(2)];
        let (head, tail) = slots.split_at_mut(1);
        let table: [&mut dyn Lu<Pair = crate::core::Pair<NoMedium, u8>>; 2] =
            [&mut head[0], &mut tail[0]];
        let mut target = Target::new(table);
        let mut storage = BlockingStorage::new(PassthroughStorage);
        let mut host = BlockingHost::new(RecordingHost);
        let mut work = [0u8; 512];
        let mut scratch = [0u8; 512];
        target
            .drive_start_rt(0, ctx(0, Direction::None, 0), &sync_cdb())
            .expect("start LUN 0");
        assert_eq!(
            target.drive_step_rt(1, &mut storage, &mut host, &mut work, &mut [], &mut scratch),
            Err(Fault::Contract)
        );
        assert_eq!(
            target.drive_step_rt(0, &mut storage, &mut host, &mut work, &mut [], &mut scratch),
            Ok(DriveStep::Done(Completion::Good))
        );
    }

    #[test]
    fn empty_work_bank_is_a_contract_fault_and_settles_the_command() {
        let mut slots = [slot(1)];
        let table: &mut [&mut dyn Lu<Pair = crate::core::Pair<NoMedium, u8>>] =
            &mut [&mut slots[0]];
        let mut target = Target::new(table);
        let mut storage = BlockingStorage::new(PassthroughStorage);
        let mut host = BlockingHost::new(RecordingHost);
        let mut scratch = [0u8; 512];
        target
            .drive_start_rt(0, ctx(0, Direction::ToHost, 512), &read_cdb(1))
            .expect("start READ");
        let mut empty: [u8; 0] = [];
        assert_eq!(
            target.drive_step_rt(
                0,
                &mut storage,
                &mut host,
                &mut empty,
                &mut [],
                &mut scratch
            ),
            Err(Fault::Contract),
            "a bank that cannot make progress is a caller contract violation"
        );
        // The command was settled, not left wedged behind an unsteppable bank.
        target
            .drive_start_rt(0, ctx(0, Direction::None, 0), &sync_cdb())
            .expect("the slot accepts a new command");
        let mut work = [0u8; 512];
        assert_eq!(
            target.drive_step_rt(0, &mut storage, &mut host, &mut work, &mut [], &mut scratch),
            Ok(DriveStep::Done(Completion::Good))
        );
    }

    #[test]
    fn empty_work_bank_on_the_static_entry_is_a_contract_fault_and_settles() {
        let mut target = Target::new(cons(slot(1), Nil));
        let mut storage = BlockingStorage::new(PassthroughStorage);
        let mut host = BlockingHost::new(RecordingHost);
        let mut scratch = [0u8; 512];
        target
            .drive_start_static::<Here>(ctx(0, Direction::ToHost, 512), &read_cdb(1))
            .expect("start READ");
        let mut empty: [u8; 0] = [];
        assert_eq!(
            target.drive_step_static::<Here>(
                &mut storage,
                &mut host,
                &mut empty,
                &mut [],
                &mut scratch
            ),
            Err(Fault::Contract),
            "a bank that cannot make progress is a caller contract violation"
        );
        // The command was settled, not left wedged behind an unsteppable bank.
        target
            .drive_start_static::<Here>(ctx(0, Direction::None, 0), &sync_cdb())
            .expect("the slot accepts a new command");
        let mut work = [0u8; 512];
        assert_eq!(
            target.drive_step_static::<Here>(
                &mut storage,
                &mut host,
                &mut work,
                &mut [],
                &mut scratch
            ),
            Ok(DriveStep::Done(Completion::Good))
        );
    }

    /// Adapter probe: records the `select_lun` / `cancel` order and retains the
    /// first issued token (the first poll answers `Pending`).
    struct OrderProbe {
        log: Vec<&'static str>,
        polls: u32,
    }

    impl crate::core::storage::Storage for OrderProbe {
        fn select_lun(&mut self, _lun: usize) {
            self.log.push("select");
        }

        fn begin_exec(&mut self, _req: IoReq) -> crate::core::storage::IoToken {
            crate::core::storage::IoToken::new(0, 1)
        }

        fn poll_exec(
            &mut self,
            _token: crate::core::storage::IoToken,
            buf: IoBuf<'_>,
        ) -> core::task::Poll<StorageReceipt> {
            self.polls += 1;
            if self.polls == 1 {
                return core::task::Poll::Pending;
            }
            let len = match &buf {
                IoBuf::None => 0,
                IoBuf::Read(b) => b.len(),
                IoBuf::Write(b) => b.len(),
            };
            core::task::Poll::Ready(StorageReceipt::ok(len))
        }

        fn cancel(&mut self, _token: crate::core::storage::IoToken) {
            self.log.push("cancel");
        }
    }

    #[test]
    fn empty_work_bank_selects_the_lun_before_cancelling_the_retained_token() {
        let mut slots = [slot(1), slot(2)];
        let (head, tail) = slots.split_at_mut(1);
        let table: [&mut dyn Lu<Pair = crate::core::Pair<NoMedium, u8>>; 2] =
            [&mut head[0], &mut tail[0]];
        let mut target = Target::new(table);
        let mut storage = OrderProbe {
            log: Vec::new(),
            polls: 0,
        };
        let mut host = BlockingHost::new(RecordingHost);
        let mut work = [0u8; 512];
        let mut scratch = [0u8; 512];

        target
            .drive_start_rt(0, ctx(0, Direction::ToHost, 512), &read_cdb(1))
            .expect("start READ");
        assert_eq!(
            target.drive_step_rt(0, &mut storage, &mut host, &mut work, &mut [], &mut scratch),
            Ok(DriveStep::Pending),
            "the in-flight read retains its adapter token"
        );
        assert_eq!(storage.log, vec!["select"], "one selection per step entry");

        let mut empty: [u8; 0] = [];
        assert_eq!(
            target.drive_step_rt(
                0,
                &mut storage,
                &mut host,
                &mut empty,
                &mut [],
                &mut scratch
            ),
            Err(Fault::Contract)
        );
        assert_eq!(
            storage.log,
            vec!["select", "select", "cancel"],
            "the adapter is told the LUN before the retained token is cancelled"
        );
    }

    /// A host send that goes `Pending` must pin the alternate bank too: the
    /// next continuation with the same two banks is not a contract violation.
    struct PendingSendHost {
        pending_once: bool,
    }

    impl HostTransport for PendingSendHost {
        fn publish(&mut self, _plan: DataPlan) -> Result<(), Fault> {
            Ok(())
        }

        fn begin_recv(&mut self, _req: HostReq) -> HostToken {
            HostToken::invalid()
        }

        fn begin_send(&mut self, _req: HostReq) -> HostToken {
            HostToken::new(0, 1)
        }

        fn poll_host(&mut self, _token: HostToken, _buf: HostBuf<'_>) -> Poll<HostReceipt> {
            if self.pending_once {
                self.pending_once = false;
                return Poll::Pending;
            }
            Poll::Ready(HostReceipt::new(usize::MAX, None, TargetId::UNBOUND))
        }

        fn cancel(&mut self, _token: HostToken) {}

        fn delivery(&self) -> Delivery {
            Delivery::Complete
        }
    }

    #[test]
    fn a_pending_host_send_keeps_the_alternate_bank_pinned() {
        let mut slots = [slot(1)];
        let table: &mut [&mut dyn Lu<Pair = crate::core::Pair<NoMedium, u8>>] =
            &mut [&mut slots[0]];
        let mut target = Target::new(table);
        let mut storage = BlockingStorage::new(PassthroughStorage);
        let mut host = PendingSendHost { pending_once: true };
        let mut work = [0u8; 512];
        let mut alt = [0u8; 512];
        let mut scratch = [0u8; 512];

        target
            .drive_start_rt(0, ctx(0, Direction::ToHost, 512), &read_cdb(1))
            .expect("start READ");
        assert_eq!(
            target.drive_step_rt(
                0,
                &mut storage,
                &mut host,
                &mut work,
                &mut alt,
                &mut scratch
            ),
            Ok(DriveStep::Pending),
            "the host send is retained"
        );
        assert_eq!(
            target.drive_step_rt(
                0,
                &mut storage,
                &mut host,
                &mut work,
                &mut alt,
                &mut scratch
            ),
            Ok(DriveStep::Done(Completion::Good)),
            "the same banks continue without a spurious contract fault"
        );
    }

    #[test]
    fn a_changed_alternate_bank_mid_command_is_contract() {
        let mut slots = [slot(1)];
        let table: &mut [&mut dyn Lu<Pair = crate::core::Pair<NoMedium, u8>>] =
            &mut [&mut slots[0]];
        let mut target = Target::new(table);
        let mut storage = OrderProbe {
            log: Vec::new(),
            polls: 0,
        };
        let mut host = BlockingHost::new(RecordingHost);
        let mut work = [0u8; 512];
        let mut alt = [0u8; 512];
        let mut scratch = [0u8; 512];

        target
            .drive_start_rt(0, ctx(0, Direction::ToHost, 512), &read_cdb(1))
            .expect("start READ");
        assert_eq!(
            target.drive_step_rt(
                0,
                &mut storage,
                &mut host,
                &mut work,
                &mut alt,
                &mut scratch
            ),
            Ok(DriveStep::Pending),
            "the read retains its adapter token"
        );

        // Same work bank, different alternate bank address.
        let mut other = [0u8; 512];
        assert_eq!(
            target.drive_step_rt(
                0,
                &mut storage,
                &mut host,
                &mut work,
                &mut other,
                &mut scratch
            ),
            Err(Fault::Contract),
            "the alternate bank is pinned for the command's duration"
        );

        // Same address, different length.
        let table: &mut [&mut dyn Lu<Pair = crate::core::Pair<NoMedium, u8>>] =
            &mut [&mut slots[0]];
        let mut target = Target::new(table);
        let mut storage = OrderProbe {
            log: Vec::new(),
            polls: 0,
        };
        target
            .drive_start_rt(0, ctx(0, Direction::ToHost, 512), &read_cdb(1))
            .expect("start READ");
        assert_eq!(
            target.drive_step_rt(
                0,
                &mut storage,
                &mut host,
                &mut work,
                &mut alt,
                &mut scratch
            ),
            Ok(DriveStep::Pending)
        );
        let (short, _) = alt.split_at_mut(256);
        assert_eq!(
            target.drive_step_rt(0, &mut storage, &mut host, &mut work, short, &mut scratch),
            Err(Fault::Contract),
            "the pinned alternate length must not change"
        );
    }

    #[test]
    fn raise_ua_rt_addresses_the_runtime_slot() {
        use crate::core::{Sense, Spc, UaClass};

        let mut slots = [LuImpl::new(
            Spc::new(BlockDevice::new(BlockAttrs::new(16, 512))),
            1u8,
        )];
        let table: &mut [&mut dyn Lu<Pair = crate::core::Pair<NoMedium, u8>>] =
            &mut [&mut slots[0]];
        let mut target = Target::new(table);
        let mut storage = BlockingStorage::new(PassthroughStorage);
        let mut work = [0u8; 512];
        let mut scratch = [0u8; 512];

        assert_eq!(
            target.raise_ua_rt(1, UaClass::LuReset),
            Err(Fault::LunNotFound)
        );
        target.raise_ua_rt(0, UaClass::LuReset).expect("raise");
        assert_eq!(
            target.drive_rt(
                0,
                &mut storage,
                ctx(0, Direction::None, 0),
                &[0x00, 0, 0, 0, 0, 0],
                &mut work,
                &mut scratch
            ),
            Ok(Completion::Check(Sense::new(0x06, 0x29, 0x03)))
        );
    }

    #[test]
    fn unit_attention_outranks_the_empty_slot_gate() {
        use crate::core::{Sense, Spc, UaClass};

        let mut slots = [LuImpl::new(
            Spc::new(BlockDevice::new(BlockAttrs::new(16, 512))),
            1u8,
        )];
        let table: &mut [&mut dyn Lu<Pair = crate::core::Pair<NoMedium, u8>>] =
            &mut [&mut slots[0]];
        let mut target = Target::new(table);
        let mut storage = BlockingStorage::new(PassthroughStorage);
        let mut host = BlockingHost::new(RecordingHost);
        let mut work = [0u8; 512];
        let mut scratch = [0u8; 512];

        target.raise_ua_rt(0, UaClass::LuReset).expect("raise");
        target
            .force_remove_rt(0, &mut storage, &mut host)
            .expect("force remove");
        assert!(target.take_rt(0).expect("take").pair.is_some());
        assert!(!target.snapshot_rt(0).expect("slot").ready);

        let tur = [0x00u8, 0, 0, 0, 0, 0];
        assert_eq!(
            target.drive_rt(
                0,
                &mut storage,
                ctx(0, Direction::None, 0),
                &tur,
                &mut work,
                &mut scratch
            ),
            Ok(Completion::Check(Sense::new(0x06, 0x29, 0x03))),
            "the pending unit attention is delivered on the empty slot"
        );
        assert_eq!(
            target.drive_rt(
                0,
                &mut storage,
                ctx(0, Direction::None, 0),
                &tur,
                &mut work,
                &mut scratch
            ),
            Ok(Completion::Check(crate::core::MEDIUM_NOT_PRESENT)),
            "the empty-slot gate applies once the attention was delivered"
        );
    }

    #[test]
    fn failed_eject_is_not_fatal() {
        let mut target = Target::new(cons(slot(1), Nil));
        // Empty the slot first: eject then fails before any detach.
        target
            .propose_static::<Here>(Change::Remove)
            .expect("propose");
        target.advance_static::<Here>().expect("advance");
        let _ = target.take_static_at::<Here>(0).expect("old pair");
        assert_eq!(
            target.host_eject_succeeded_static::<Here>(),
            Err(Fault::Contract)
        );
        assert_eq!(
            target.tick(),
            RunOutcome::ServiceReady,
            "a pre-detach eject failure must not end the service"
        );
        // The eject_pending window must be gone: control is accepted again.
        assert_eq!(target.request_control(Control::Nop), Ok(()));
    }
    // ── Host phases carry the bank side ────────────────────────────

    /// Scripted device that emits one host step from the caller's banks.
    enum BankScript {
        SendAlt,
        RecvAlt,
        SendOutside,
    }

    struct BankDevice {
        script: Option<BankScript>,
        active: bool,
    }

    static OUTSIDE: [u8; 16] = [0xAA; 16];

    impl crate::core::Device for BankDevice {
        type Medium = NoMedium;

        fn prepare(
            &mut self,
            _permit: &crate::core::CommandPermit,
            _ctx: CommandContext,
            _cdb: &[u8],
        ) -> Result<(), Completion> {
            self.active = true;
            Ok(())
        }

        fn active(&self) -> bool {
            self.active
        }

        fn resume(&mut self, _permit: &crate::core::CommandPermit) -> Result<(), Completion> {
            Ok(())
        }

        fn poll_with_alt<'a>(
            &mut self,
            _permit: &crate::core::CommandPermit,
            fb: crate::core::Feedback,
            data: &'a mut [u8],
            alt: &'a mut [u8],
        ) -> crate::core::PollStep<'a> {
            match fb.kind() {
                crate::core::FeedbackKind::Begin => {
                    let direction = match self.script {
                        Some(BankScript::RecvAlt) => Direction::FromHost,
                        _ => Direction::ToHost,
                    };
                    crate::core::PollStep::Publish(DataPlan {
                        direction,
                        bytes: data.len() as u64,
                    })
                }
                crate::core::FeedbackKind::PlanAccepted => match self.script.take() {
                    Some(BankScript::SendAlt) => crate::core::PollStep::Send(&alt[..data.len()]),
                    Some(BankScript::RecvAlt) => {
                        self.script = None;
                        crate::core::PollStep::Receive(&mut alt[..data.len()])
                    }
                    Some(BankScript::SendOutside) => {
                        crate::core::PollStep::Send(&OUTSIDE[..data.len()])
                    }
                    None => crate::core::PollStep::Complete(Completion::Good),
                },
                _ => {
                    self.active = false;
                    crate::core::PollStep::Complete(Completion::Good)
                }
            }
        }

        fn poll<'a>(
            &mut self,
            _permit: &crate::core::CommandPermit,
            _fb: crate::core::Feedback,
            _data: &'a mut [u8],
        ) -> crate::core::PollStep<'a> {
            // These fixtures drive `poll_with_alt` only.
            crate::core::PollStep::Idle
        }

        fn poll_long<'a>(
            &mut self,
            _permit: &crate::core::CommandPermit,
            _fb: crate::core::Feedback,
            _data: &'a mut [u8],
        ) -> crate::core::PollStep<'a> {
            crate::core::PollStep::Idle
        }

        fn long_info(&self) -> crate::core::LongInfo {
            crate::core::LongInfo::IDLE
        }

        fn interrupt(
            &mut self,
            _permit: &crate::core::CommandPermit,
            _reason: crate::core::InterruptReason,
            _known: crate::core::KnownEffects,
        ) -> Result<(), Fault> {
            Ok(())
        }

        fn finish_delivery(
            &mut self,
            _permit: &crate::core::CommandPermit,
            _delivery: crate::core::Delivery,
        ) {
        }

        fn take_medium(&mut self, _permit: &crate::core::BoundaryPermit) -> Option<NoMedium> {
            Some(NoMedium)
        }

        fn install_medium(
            &mut self,
            _permit: &crate::core::BoundaryPermit,
            _medium: NoMedium,
        ) -> Result<(), (NoMedium, Fault)> {
            Ok(())
        }
    }

    #[derive(Default)]
    struct BankHost {
        sent: Vec<(crate::core::storage::BankSide, usize, usize)>,
        recv: Vec<(crate::core::storage::BankSide, usize, usize)>,
        polls: usize,
    }

    impl HostTransport for BankHost {
        fn publish(&mut self, _plan: DataPlan) -> Result<(), Fault> {
            Ok(())
        }

        fn begin_recv(&mut self, _req: HostReq) -> HostToken {
            HostToken::new(0, 3)
        }

        fn begin_send(&mut self, _req: HostReq) -> HostToken {
            HostToken::new(0, 4)
        }

        fn poll_host(&mut self, _token: HostToken, buf: HostBuf<'_>) -> Poll<HostReceipt> {
            self.polls += 1;
            match buf {
                HostBuf::Send { bytes, bank } => {
                    self.sent.push((bank, bytes.len(), bytes.as_ptr() as usize));
                }
                HostBuf::Recv { buf, bank } => {
                    let at = buf.as_ptr() as usize;
                    self.recv.push((bank, buf.len(), at));
                    buf.fill(0x5A);
                }
            }
            Poll::Ready(HostReceipt::new(usize::MAX, None, TargetId::UNBOUND))
        }

        fn cancel(&mut self, _token: HostToken) {}

        fn delivery(&self) -> crate::core::Delivery {
            crate::core::Delivery::Complete
        }
    }

    /// A device that sends from the alternate bank hands the host adapter the
    /// alternate slice and `BankSide::Alt`.
    #[test]
    fn a_send_from_the_alternate_bank_reaches_the_host_as_alt() {
        use crate::core::storage::BankSide;
        let mut slots = [LuImpl::new(
            BankDevice {
                script: Some(BankScript::SendAlt),
                active: false,
            },
            1u8,
        )];
        let table: &mut [&mut dyn Lu<Pair = crate::core::Pair<NoMedium, u8>>] =
            &mut [&mut slots[0]];
        let mut target = Target::new(table);
        let mut storage = BlockingStorage::new(PassthroughStorage);
        let mut host = BankHost::default();
        let mut work = [0u8; 16];
        let mut alt = [0x11u8; 16];
        let mut scratch = [0u8; 16];
        let alt_start = alt.as_ptr() as usize;

        target
            .drive_start_rt(0, ctx(0, Direction::ToHost, 16), &read_cdb(1))
            .expect("start");
        assert_eq!(
            target.drive_step_rt(
                0,
                &mut storage,
                &mut host,
                &mut work,
                &mut alt,
                &mut scratch
            ),
            Ok(DriveStep::Done(Completion::Good))
        );
        assert_eq!(host.polls, 1);
        assert_eq!(host.sent.len(), 1);
        assert_eq!(host.sent[0].0, BankSide::Alt);
        assert_eq!(host.sent[0].1, 16);
        assert_eq!(
            host.sent[0].2, alt_start,
            "the host saw the alternate bank's slice"
        );
    }

    /// The same for a receive into the alternate bank.
    #[test]
    fn a_receive_into_the_alternate_bank_reaches_the_host_as_alt() {
        use crate::core::storage::BankSide;
        let mut slots = [LuImpl::new(
            BankDevice {
                script: Some(BankScript::RecvAlt),
                active: false,
            },
            1u8,
        )];
        let table: &mut [&mut dyn Lu<Pair = crate::core::Pair<NoMedium, u8>>] =
            &mut [&mut slots[0]];
        let mut target = Target::new(table);
        let mut storage = BlockingStorage::new(PassthroughStorage);
        let mut host = BankHost::default();
        let mut work = [0u8; 16];
        let mut alt = [0u8; 16];
        let mut scratch = [0u8; 16];
        let alt_start = alt.as_ptr() as usize;

        target
            .drive_start_rt(0, ctx(0, Direction::FromHost, 16), &read_cdb(1))
            .expect("start");
        assert_eq!(
            target.drive_step_rt(
                0,
                &mut storage,
                &mut host,
                &mut work,
                &mut alt,
                &mut scratch
            ),
            Ok(DriveStep::Done(Completion::Good))
        );
        assert_eq!(host.recv.len(), 1);
        assert_eq!(host.recv[0].0, BankSide::Alt);
        assert_eq!(host.recv[0].1, 16);
        assert_eq!(host.recv[0].2, alt_start);
        assert_eq!(alt, [0x5A; 16], "the host wrote into the alternate bank");
    }

    /// A slice outside both banks is a contract violation and never reaches the
    /// host adapter.
    #[test]
    fn a_host_slice_outside_both_banks_is_contract() {
        let mut slots = [LuImpl::new(
            BankDevice {
                script: Some(BankScript::SendOutside),
                active: false,
            },
            1u8,
        )];
        let table: &mut [&mut dyn Lu<Pair = crate::core::Pair<NoMedium, u8>>] =
            &mut [&mut slots[0]];
        let mut target = Target::new(table);
        let mut storage = BlockingStorage::new(PassthroughStorage);
        let mut host = BankHost::default();
        let mut work = [0u8; 16];
        let mut alt = [0u8; 16];
        let mut scratch = [0u8; 16];

        target
            .drive_start_rt(0, ctx(0, Direction::ToHost, 16), &read_cdb(1))
            .expect("start");
        assert_eq!(
            target.drive_step_rt(
                0,
                &mut storage,
                &mut host,
                &mut work,
                &mut alt,
                &mut scratch
            ),
            Err(Fault::Contract)
        );
        assert_eq!(host.polls, 0, "the host adapter is never called");
    }
}
