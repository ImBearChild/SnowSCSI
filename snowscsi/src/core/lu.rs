//! The `Lu` slot seam and the single `LuImpl` device wrapper.
//!
//! [`Lu`] is object-safe on purpose: the runtime path keeps
//! `&mut dyn Lu<Pair = P>` slots, so every method takes concrete arguments,
//! there are no GATs and no `async fn`s. The runner drives it; an application
//! never calls these entries directly because every permission entry needs a
//! crate-private permit. `Target` (the next card) mints those permits.
//!
//! [`LuImpl`] owns one device plus the pair/transaction state that must survive
//! a dropped future: the prepared candidate, the resident result, the
//! `needs_recovery` flag and the preserved old pair. It never stores a buffer,
//! never allocates and never issues storage IO — `Device::commit` is a local
//! metadata hook.

use super::device::{
    Admission, CommandContext, Device, Feedback, InterruptReason, Pair, PollStep, TargetId,
};
use super::eject::RemovalLocks;
use super::errors::{
    commit_fault, Completion, Delivery, Fault, KnownEffects, Sense, FORMAT_IN_PROGRESS,
    INTERNAL_FAILURE, MEDIUM_NOT_PRESENT, NEEDS_RECOVERY,
};
use super::long::{LongInfo, LongPhase};
use super::management::{Change, ChangeResult, LuInfo};
use super::permit::{BoundaryPermit, CommandPermit, OwnerBindPermit};
use super::ua::UaClass;

/// One addressable slot: a device plus the pair it currently owns.
///
/// # Contract
///
/// - `admit` runs **before** any medium/backing access; a reject
///   already carries its completion.
/// - `prepare` starts a command; `resume` continues one whose future was
///   dropped. Re-preparing an active command must fail with `Busy`,
///   never replay it.
/// - `interrupt` is called only after the in-flight IO has settled and only
///   with the facts the runner actually observed; it performs at most one
///   bounded cleanup and never issues storage IO.
/// - `finish_delivery` books a delivery outcome for a completion that is
///   already fixed; it never restarts the command and never rolls back a status
///   that was already sent.
/// - `take_rt` is the only object-safe way to claim a resident result. A normal
///   medium exchange uses `propose → advance → take`; a bare "take current" is
///   not part of the public API.
pub trait Lu {
    /// The pair this slot owns: a device medium plus the application backing.
    type Pair;

    /// Cheap admission check before `prepare`; a reject must not touch the
    /// medium or the backing.
    fn admit(&self, cdb: &[u8]) -> Admission;

    /// Decode and start a command. `Busy` means one is already active.
    fn prepare(
        &mut self,
        permit: &CommandPermit,
        ctx: CommandContext,
        cdb: &[u8],
    ) -> Result<(), Completion>;

    /// Whether a command is still active (it must be `resume`d, not prepared
    /// again).
    fn active(&self) -> bool;

    /// Resume an active command after a dropped future with the pending
    /// feedback kept by the runner; never replays the command.
    fn resume(&mut self, permit: &CommandPermit) -> Result<(), Completion>;

    /// One step of the active command; `data` is the caller's bank for this
    /// step only (core never stores it).
    fn poll<'a>(
        &mut self,
        permit: &CommandPermit,
        feedback: Feedback,
        data: &'a mut [u8],
    ) -> PollStep<'a>;

    /// One step of the active command with an optional second caller bank.
    ///
    /// Default: ignore `alt` and behave exactly like [`Self::poll`].
    fn poll_with_alt<'a>(
        &mut self,
        permit: &CommandPermit,
        feedback: Feedback,
        data: &'a mut [u8],
        alt: &'a mut [u8],
    ) -> PollStep<'a> {
        let _ = alt;
        self.poll(permit, feedback, data)
    }

    /// One step of the resident long operation (a second, independent context).
    fn poll_long<'a>(
        &mut self,
        permit: &CommandPermit,
        feedback: Feedback,
        data: &'a mut [u8],
    ) -> PollStep<'a>;

    /// Projection of the resident long operation.
    fn long_info(&self) -> LongInfo;

    /// Read-only projection. It is **not** the authoritative boundary: the
    /// runner also owns required/speculative IO, retained input, an unconsumed
    /// completion and the live execution borrow.
    fn snapshot(&self) -> LuInfo;

    /// Settle an abnormal end after the in-flight IO has settled and the
    /// `known` facts are available. Preserve real effects; never replay unknown
    /// writes.
    fn interrupt(
        &mut self,
        permit: &CommandPermit,
        reason: InterruptReason,
        known: KnownEffects,
    ) -> Result<(), Fault>;

    /// Book the delivery outcome of a completion that is already fixed.
    fn finish_delivery(&mut self, permit: &CommandPermit, delivery: Delivery);

    /// The transport delivered the fixed CHECK CONDITION as autosense.
    ///
    /// Only transports that can carry the sense data inside the completion
    /// frame call this; it clears the saved sense instance that was just
    /// reported. `sense` is the instance the completion carried, so a
    /// runner-fabricated completion cannot consume an unrelated saved sense.
    /// Default: no-op.
    fn autosense_delivered(&mut self, permit: &CommandPermit, sense: Sense) {
        let _ = (permit, sense);
    }

    /// Raise a pending unit attention (SPC-3 5.6) on this slot.
    ///
    /// The permit is the owning target's command permit; a foreign permit is
    /// ignored. The condition is reported by the device on the next command
    /// that reports it (never by INQUIRY) and consumed exactly once. A bare
    /// profile keeps no unit-attention state and ignores the raise; the public
    /// [`Spc`](super::spc::Spc) wrapper owns the pending set.
    fn raise_ua(&mut self, permit: &CommandPermit, class: UaClass);

    /// Target identity this slot is bound to.
    fn owner(&self) -> TargetId;

    /// Compare by owner only. Replace/remove/eject/take never change the target
    /// identity, so this only ever compares owners.
    fn accepts_permit(&self, permit: &BoundaryPermit) -> bool {
        permit.owner() == self.owner()
    }

    /// Bind the slot to its target. The [`OwnerBindPermit`] has no public
    /// constructor, so an application cannot rebind a slot after `Target::new`.
    fn bind_owner(&mut self, permit: &OwnerBindPermit, owner: TargetId);

    /// Take the resident management result exactly once; `None` when empty.
    fn take_rt(&mut self, permit: &BoundaryPermit) -> Option<ChangeResult<Self::Pair>>;

    /// Whether a detached result is resident (query only; never consumes it).
    fn has_result(&self) -> bool;

    /// Emergency eject: no commit, no PREVENT/candidate check. The runner has
    /// already cancelled any pending token and settled the command.
    fn force_remove_rt(&mut self, permit: &BoundaryPermit) -> Result<(), Fault>;

    /// Install a pair handed back by the application; returns it on failure.
    ///
    /// This is the second documented recovery path out of `needs_recovery`
    /// The AwaitTake barrier
    /// is enforced one level up: `Runner::service_gate` refuses this entry (and
    /// `propose`/`advance`) while a management result is still resident, so a
    /// reinstall requires the application to `take` the candidate first. This
    /// seam only checks its own device/boundary state, and a refused install
    /// returns `pair` unchanged. Pinning fixture:
    /// `core_p3::replace_install_and_restore_failure_needs_recovery_and_blocks_reinstall_before_take`.
    fn install_rt(
        &mut self,
        permit: &BoundaryPermit,
        pair: Self::Pair,
    ) -> Result<(), (Self::Pair, Fault)>;

    /// Save a candidate change without touching the current pair. On failure
    /// the original input is returned.
    fn propose_rt(
        &mut self,
        permit: &BoundaryPermit,
        change: Change<Self::Pair>,
    ) -> Result<(), (Change<Self::Pair>, Fault)>;

    /// `propose → advance → take`: commit old, detach old, install candidate.
    fn advance_rt(&mut self, permit: &BoundaryPermit) -> Result<(), Fault>;

    /// Host EJECT transaction: local commit, detach the whole pair into the
    /// result, leave the slot empty. The runner then publishes `ResourcesReady`;
    /// the application takes the pair exactly once.
    fn eject_rt(&mut self, permit: &BoundaryPermit) -> Result<(), Fault>;

    /// Consume the eject request of the last completed command.
    ///
    /// The runner calls this at the completion point of a GOOD command and
    /// performs the detach itself. Default: no request (a device that cannot
    /// eject, or an inner device that does not implement it).
    fn take_eject_request(&mut self) -> bool {
        false
    }
}

/// MMC-6 §6.4.4.3 foreground-FORMAT allow list, plus REPORT LUNS, which SPC-3
/// 6.21 requires to be answerable even when the LU is not ready.
fn admitted_during_foreground(opcode: u8) -> bool {
    matches!(
        opcode,
        0x03 // REQUEST SENSE
            | 0x12 // INQUIRY
            | 0x46 // GET CONFIGURATION (MMC)
            | 0x4A // GET EVENT STATUS NOTIFICATION (MMC)
            | 0xA0 // REPORT LUNS (SPC-3, target level)
    )
}

/// Device-level commands that stay answerable on an **empty** slot.
///
/// START STOP UNIT is how the host closes a tray it already opened (and how
/// Windows retries an eject); it touches no medium, so an empty slot answers it
/// instead of `MEDIUM NOT PRESENT`. PREVENT/ALLOW is deliberately **not** in
/// this set: clearing the normal latch issues a storage `Sync`, which must not
/// reach a stale adapter binding after the medium was removed.
fn admitted_without_medium(opcode: u8) -> bool {
    opcode == 0x1B // START STOP UNIT
}

/// Canonical slot: a [`Device`] plus the application's backing handle.
///
/// The backing is only an identity/handle; the bytes live in the application's
/// storage adapter. The slot never stores the adapter.
pub struct LuImpl<D: Device, B> {
    device: D,
    backing: Option<B>,
    candidate: Option<Change<Pair<D::Medium, B>>>,
    result: Option<ChangeResult<Pair<D::Medium, B>>>,
    owner: TargetId,
    /// An `install_medium(old)` restore failed during `advance_rt`; the slot
    /// must not serve commands until an explicit force/reinstall.
    needs_recovery: bool,
    /// Old pair preserved after a failed restore (never silently reinstated).
    recovery: Option<Pair<D::Medium, B>>,
    /// Effects captured by the last `interrupt`, reported by a later force.
    last_known: KnownEffects,
}

impl<D: Device, B> LuImpl<D, B> {
    /// Build an unbound slot (owner [`TargetId::UNBOUND`]) with **no pair**.
    ///
    /// The slot is an empty logical unit: the mandatory query set answers, media
    /// commands are `MEDIUM NOT PRESENT`, and `install_rt` supplies the first
    /// pair. This is the starting state a drive needs to enumerate before any
    /// medium exists.
    pub fn empty(device: D) -> Self {
        Self {
            device,
            backing: None,
            candidate: None,
            result: None,
            owner: TargetId::UNBOUND,
            needs_recovery: false,
            recovery: None,
            last_known: KnownEffects::NONE,
        }
    }

    /// Build an unbound slot (owner [`TargetId::UNBOUND`]) holding `backing`.
    pub fn new(device: D, backing: B) -> Self {
        Self {
            backing: Some(backing),
            ..Self::empty(device)
        }
    }

    /// Build a slot already bound to `owner`.
    ///
    /// Crate-internal: production binding goes through `Target::new`, which
    /// mints the [`OwnerBindPermit`]; an application must not forge an owner.
    #[allow(dead_code)] // `Target` builds bound slots; tests use it here
    pub(crate) fn with_owner(owner: TargetId, device: D, backing: B) -> Self {
        let mut slot = Self::new(device, backing);
        slot.owner = owner;
        slot
    }

    /// Borrow the wrapped device.
    pub fn device_ref(&self) -> &D {
        &self.device
    }

    /// Borrow the resident backing handle, if any.
    pub fn backing_ref(&self) -> Option<&B> {
        self.backing.as_ref()
    }

    /// Whether a candidate change is resident.
    pub fn has_candidate(&self) -> bool {
        self.candidate.is_some()
    }

    /// Whether the slot needs an explicit recovery before it can serve again.
    pub fn needs_recovery(&self) -> bool {
        self.needs_recovery
    }

    /// `long_settled`: only `Idle`/`Settled` allow management or a
    /// resource take.
    fn long_settled(&self) -> bool {
        matches!(
            self.device.long_info().phase,
            LongPhase::Idle | LongPhase::Settled
        )
    }

    /// Owner check for a management permit.
    fn permit_ok(&self, permit: &BoundaryPermit) -> bool {
        permit.owner() == self.owner
    }

    /// Owner check for a command permit.
    fn command_ok(&self, permit: &CommandPermit) -> bool {
        permit.owner() == self.owner
    }

    /// Store `pair` in `result` and report the local failure, so the
    /// application's input is never lost: a known failure terminates the
    /// transaction and the candidate goes to `result`.
    fn fail_advance(
        &mut self,
        pair: Option<Pair<D::Medium, B>>,
        fault: Fault,
        effects: KnownEffects,
    ) -> Result<(), Fault> {
        self.candidate = None;
        self.result = pair.map(|pair| ChangeResult {
            pair: Some(pair),
            local: Err(fault),
            delivery: Delivery::NotApplicable,
            effects,
        });
        Err(fault)
    }

    /// Effects for a result that never ran a commit: report the facts captured
    /// by `interrupt`, but never claim durability.
    fn force_effects(&mut self) -> KnownEffects {
        let effects = KnownEffects {
            sync_durable: false,
            ..self.last_known
        };
        self.last_known = KnownEffects::NONE;
        effects
    }
}

impl<D: Device, B> Lu for LuImpl<D, B> {
    type Pair = Pair<D::Medium, B>;

    fn admit(&self, cdb: &[u8]) -> Admission {
        let opcode = cdb.first().copied().unwrap_or(0xFF);
        // No pair means no medium: media commands must not reach a stale
        // adapter binding after Remove/host-eject. The
        // mandatory query set (INQUIRY/REQUEST SENSE/REPORT LUNS/…) stays
        // answerable on an empty slot (`§4.19`, SPC-3 6.21). A pending unit
        // attention outranks the empty-slot gate: the next reporting command
        // must deliver it before the device can report MEDIUM NOT PRESENT.
        if self.backing.is_none()
            && !admitted_during_foreground(opcode)
            && !admitted_without_medium(opcode)
            && !self.device.admits_without_medium(cdb)
            && self.device.pending_ua().is_none()
        {
            return Admission::Reject(Completion::Check(MEDIUM_NOT_PRESENT));
        }
        // A slot that failed to restore its old medium must not serve: its
        // backing/adapter binding is stale.
        if self.needs_recovery {
            return Admission::Reject(Completion::Check(NEEDS_RECOVERY));
        }
        let long = self.device.long_info();
        if long.phase == LongPhase::Foreground && !admitted_during_foreground(opcode) {
            return Admission::Reject(Completion::Check(FORMAT_IN_PROGRESS));
        }
        Admission::Proceed
    }

    fn prepare(
        &mut self,
        permit: &CommandPermit,
        ctx: CommandContext,
        cdb: &[u8],
    ) -> Result<(), Completion> {
        if !self.command_ok(permit) {
            return Err(Completion::Check(INTERNAL_FAILURE));
        }
        // Defensive repeat of the admission check: an empty slot forwards only
        // the mandatory query set; a media command never issues storage IO.
        // A pending unit attention still has to be delivered first.
        if self.backing.is_none() {
            let opcode = cdb.first().copied().unwrap_or(0xFF);
            if !admitted_during_foreground(opcode)
                && !admitted_without_medium(opcode)
                && !self.device.admits_without_medium(cdb)
                && self.device.pending_ua().is_none()
            {
                return Err(Completion::Check(MEDIUM_NOT_PRESENT));
            }
        }
        // A new command starts with no observed effect; the previous command's
        // `last_known` must not leak into it.
        self.last_known = KnownEffects::NONE;
        self.device.prepare(permit, ctx, cdb)
    }

    fn active(&self) -> bool {
        self.device.active()
    }

    fn resume(&mut self, permit: &CommandPermit) -> Result<(), Completion> {
        if !self.command_ok(permit) {
            return Err(Completion::Check(INTERNAL_FAILURE));
        }
        self.device.resume(permit)
    }

    fn poll<'a>(
        &mut self,
        permit: &CommandPermit,
        feedback: Feedback,
        data: &'a mut [u8],
    ) -> PollStep<'a> {
        if !self.command_ok(permit) {
            return PollStep::Complete(Completion::Check(INTERNAL_FAILURE));
        }
        self.device.poll(permit, feedback, data)
    }

    fn poll_with_alt<'a>(
        &mut self,
        permit: &CommandPermit,
        feedback: Feedback,
        data: &'a mut [u8],
        alt: &'a mut [u8],
    ) -> PollStep<'a> {
        if !self.command_ok(permit) {
            return PollStep::Complete(Completion::Check(INTERNAL_FAILURE));
        }
        self.device.poll_with_alt(permit, feedback, data, alt)
    }

    fn poll_long<'a>(
        &mut self,
        permit: &CommandPermit,
        feedback: Feedback,
        data: &'a mut [u8],
    ) -> PollStep<'a> {
        if !self.command_ok(permit) {
            return PollStep::Complete(Completion::Check(INTERNAL_FAILURE));
        }
        self.device.poll_long(permit, feedback, data)
    }

    fn long_info(&self) -> LongInfo {
        self.device.long_info()
    }

    fn snapshot(&self) -> LuInfo {
        let locks = self.device.removal_locks().unwrap_or(RemovalLocks {
            prevent: false,
            persistent_prevent: false,
        });
        LuInfo {
            long: self.device.long_info(),
            ready: self.backing.is_some() && !self.needs_recovery,
            // The PREVENT latches live in the device profile; this projection
            // is the management view only.
            prevent: locks.prevent,
            persistent_prevent: locks.persistent_prevent,
            // Command + long-operation projection only; the runner owns the
            // authoritative conjunction.
            boundary: !self.device.active() && self.long_settled(),
        }
    }

    fn interrupt(
        &mut self,
        permit: &CommandPermit,
        reason: InterruptReason,
        known: KnownEffects,
    ) -> Result<(), Fault> {
        if !self.command_ok(permit) {
            return Err(Fault::ForeignBoundary);
        }
        // Remember the facts so an emergency force can still report them after
        // the device has settled (force row).
        self.last_known = known;
        self.device.interrupt(permit, reason, known)
    }

    fn finish_delivery(&mut self, permit: &CommandPermit, delivery: Delivery) {
        // Delivery facts belong to the owning runner; a foreign permit is
        // silently ignored rather than handed to the device.
        if !self.command_ok(permit) {
            return;
        }
        self.device.finish_delivery(permit, delivery);
    }

    fn autosense_delivered(&mut self, permit: &CommandPermit, sense: Sense) {
        if !self.command_ok(permit) {
            return;
        }
        self.device.autosense_delivered(permit, sense);
    }

    fn raise_ua(&mut self, permit: &CommandPermit, class: UaClass) {
        if !self.command_ok(permit) {
            return;
        }
        self.device.raise_ua(permit, class);
    }

    fn owner(&self) -> TargetId {
        self.owner
    }

    fn bind_owner(&mut self, _permit: &OwnerBindPermit, owner: TargetId) {
        self.owner = owner;
    }

    fn take_rt(&mut self, permit: &BoundaryPermit) -> Option<ChangeResult<Self::Pair>> {
        if !self.permit_ok(permit) {
            return None;
        }
        // Only a result produced by `advance`, the host-eject transaction or
        // `force_remove_rt` can be claimed here.
        self.result.take()
    }

    fn has_result(&self) -> bool {
        self.result.is_some()
    }

    fn force_remove_rt(&mut self, permit: &BoundaryPermit) -> Result<(), Fault> {
        if !self.permit_ok(permit) {
            return Err(Fault::ForeignBoundary);
        }
        // The result slot is single-entry: an older result must be taken before
        // force can hand back another pair (the runner defers instead).
        if self.result.is_some() {
            return Err(Fault::Contract);
        }
        // Force is an emergency eject, not a transaction: a prepared candidate
        // is dropped rather than installed, and no commit runs.
        self.candidate = None;
        if self.needs_recovery {
            // The old pair could not be reinstalled. Hand the preserved pair
            // back through force instead of pretending the slot is healthy.
            let pair = match self.recovery.take() {
                Some(pair) => pair,
                None => return Ok(()),
            };
            self.needs_recovery = false;
            let effects = self.force_effects();
            self.result = Some(ChangeResult {
                pair: Some(pair),
                local: Ok(()),
                delivery: Delivery::NotApplicable,
                effects,
            });
            return Ok(());
        }
        if self.backing.is_none() {
            return Ok(());
        }
        let medium = match self.device.take_medium(permit) {
            Some(medium) => medium,
            None => return Err(Fault::Contract),
        };
        let backing = match self.backing.take() {
            Some(backing) => backing,
            None => {
                let _ = self.device.install_medium(permit, medium);
                return Err(Fault::Contract);
            }
        };
        let effects = self.force_effects();
        self.result = Some(ChangeResult {
            pair: Some(Pair { medium, backing }),
            // Force deliberately did not commit: local success, with
            // `sync_durable = false` and any unknown write remainder reported
            // as an effect — never as `Err(Fault::Commit)`.
            local: Ok(()),
            delivery: Delivery::NotApplicable,
            effects,
        });
        Ok(())
    }

    fn install_rt(
        &mut self,
        permit: &BoundaryPermit,
        pair: Self::Pair,
    ) -> Result<(), (Self::Pair, Fault)> {
        if !self.permit_ok(permit) {
            return Err((pair, Fault::ForeignBoundary));
        }
        // A successful install is one of the two documented recovery paths
        // (force **or** reinstall); the preserved old pair is
        // dropped only after the new medium is accepted.
        if self.device.active() || !self.long_settled() {
            return Err((pair, Fault::Contract));
        }
        if self.backing.is_some() {
            return Err((pair, Fault::Contract));
        }
        let Pair { medium, backing } = pair;
        match self.device.install_medium(permit, medium) {
            Ok(()) => {
                self.backing = Some(backing);
                self.needs_recovery = false;
                self.recovery = None;
                Ok(())
            }
            Err((medium, fault)) => Err((Pair { medium, backing }, fault)),
        }
    }

    fn propose_rt(
        &mut self,
        permit: &BoundaryPermit,
        change: Change<Self::Pair>,
    ) -> Result<(), (Change<Self::Pair>, Fault)> {
        if !self.permit_ok(permit) {
            return Err((change, Fault::ForeignBoundary));
        }
        // A competing proposal is refused and returns its own input; the
        // resident candidate is never overwritten.
        if self.candidate.is_some() {
            return Err((change, Fault::Contract));
        }
        if self.device.active() || !self.long_settled() {
            return Err((change, Fault::Contract));
        }
        self.candidate = Some(change);
        Ok(())
    }

    fn advance_rt(&mut self, permit: &BoundaryPermit) -> Result<(), Fault> {
        if !self.permit_ok(permit) {
            return Err(Fault::ForeignBoundary);
        }
        if self.device.active() || !self.long_settled() || self.needs_recovery {
            return Err(Fault::Contract);
        }
        if self.result.is_some() {
            // The previous result must be taken before a new advance.
            return Err(Fault::Contract);
        }
        let change = match self.candidate.take() {
            Some(change) => change,
            None => return Err(Fault::Contract),
        };
        match change {
            Change::Install(pair) => {
                if self.backing.is_some() {
                    return self.fail_advance(Some(pair), Fault::Contract, KnownEffects::NONE);
                }
                let Pair { medium, backing } = pair;
                match self.device.install_medium(permit, medium) {
                    Ok(()) => {
                        self.backing = Some(backing);
                        // Install has no old pair to hand back ("no old"),
                        // so no result is produced and `take` returns
                        // `NothingToTake`.
                        self.result = None;
                        Ok(())
                    }
                    Err((medium, fault)) => {
                        self.fail_advance(Some(Pair { medium, backing }), fault, KnownEffects::NONE)
                    }
                }
            }
            Change::Replace(pair) => {
                if self.backing.is_none() {
                    return self.fail_advance(Some(pair), Fault::Contract, KnownEffects::NONE);
                }
                // 1. explicit local commit of the old medium (never a hidden
                //    runner `Sync`).
                if let Err(completion) = self.device.commit(permit) {
                    let fault = commit_fault(completion).unwrap_or(Fault::Contract);
                    // A real commit failure: candidate to result, old kept.
                    return self.fail_advance(Some(pair), fault, KnownEffects::NONE);
                }
                // 2. detach the old pair as a whole.
                let old_medium = match self.device.take_medium(permit) {
                    Some(medium) => medium,
                    None => {
                        return self.fail_advance(Some(pair), Fault::Contract, KnownEffects::NONE)
                    }
                };
                let old_backing = match self.backing.take() {
                    Some(backing) => backing,
                    None => {
                        let _ = self.device.install_medium(permit, old_medium);
                        return self.fail_advance(Some(pair), Fault::Contract, KnownEffects::NONE);
                    }
                };
                // 3. install the candidate. A failed install restores the old
                //    pair; if the restore itself fails the slot enters
                //    `needs_recovery` and the old pair is preserved for force.
                let Pair { medium, backing } = pair;
                match self.device.install_medium(permit, medium) {
                    Ok(()) => {
                        self.backing = Some(backing);
                        self.result = Some(ChangeResult {
                            pair: Some(Pair {
                                medium: old_medium,
                                backing: old_backing,
                            }),
                            local: Ok(()),
                            delivery: Delivery::NotApplicable,
                            // The local commit is metadata-only, not host
                            // durable.
                            effects: KnownEffects::NONE,
                        });
                        Ok(())
                    }
                    Err((medium, fault)) => match self.device.install_medium(permit, old_medium) {
                        Ok(()) => {
                            self.backing = Some(old_backing);
                            self.fail_advance(
                                Some(Pair { medium, backing }),
                                fault,
                                KnownEffects::NONE,
                            )
                        }
                        Err((old_medium, _old_fault)) => {
                            // Never silently pretend the old pair is installed.
                            self.backing = None;
                            self.needs_recovery = true;
                            self.recovery = Some(Pair {
                                medium: old_medium,
                                backing: old_backing,
                            });
                            self.result = Some(ChangeResult {
                                pair: Some(Pair { medium, backing }),
                                local: Err(Fault::NeedsRecovery),
                                delivery: Delivery::NotApplicable,
                                effects: KnownEffects::NONE,
                            });
                            Err(Fault::NeedsRecovery)
                        }
                    },
                }
            }
            Change::Remove => {
                if self.backing.is_none() {
                    return self.fail_advance(None, Fault::Contract, KnownEffects::NONE);
                }
                if let Err(completion) = self.device.commit(permit) {
                    let fault = commit_fault(completion).unwrap_or(Fault::Contract);
                    // A failed remove changes nothing: no result, old stays.
                    return self.fail_advance(None, fault, KnownEffects::NONE);
                }
                let medium = match self.device.take_medium(permit) {
                    Some(medium) => medium,
                    None => return self.fail_advance(None, Fault::Contract, KnownEffects::NONE),
                };
                let backing = match self.backing.take() {
                    Some(backing) => backing,
                    None => {
                        return match self.device.install_medium(permit, medium) {
                            Ok(()) => Err(Fault::Contract),
                            Err(_) => {
                                self.needs_recovery = true;
                                Err(Fault::NeedsRecovery)
                            }
                        };
                    }
                };
                self.result = Some(ChangeResult {
                    pair: Some(Pair { medium, backing }),
                    local: Ok(()),
                    delivery: Delivery::NotApplicable,
                    effects: KnownEffects::NONE,
                });
                Ok(())
            }
        }
    }

    fn eject_rt(&mut self, permit: &BoundaryPermit) -> Result<(), Fault> {
        if !self.permit_ok(permit) {
            return Err(Fault::ForeignBoundary);
        }
        // An empty slot, an unresolved candidate/result, an active
        // command or a non-settled long operation is rejected before any
        // detach.
        if self.device.active() || !self.long_settled() {
            return Err(Fault::Contract);
        }
        if self.backing.is_none() || self.candidate.is_some() || self.result.is_some() {
            return Err(Fault::Contract);
        }
        // 1. local commit; a commit failure detaches nothing.
        if let Err(completion) = self.device.commit(permit) {
            return Err(commit_fault(completion).unwrap_or(Fault::Contract));
        }
        // 2. detach the whole pair into `result`.
        let medium = match self.device.take_medium(permit) {
            Some(medium) => medium,
            None => return Err(Fault::Contract),
        };
        let backing = match self.backing.take() {
            Some(backing) => backing,
            None => {
                let _ = self.device.install_medium(permit, medium);
                return Err(Fault::Contract);
            }
        };
        // 3. the host's own EJECT succeeded: the profile may clear the normal
        //    (never the persistent) PREVENT latch.
        self.device.host_eject_succeeded(permit);
        // `ChangeResult.delivery` is the delivery state **at the moment the
        // result is produced**. A host eject is ordered as
        // commit → detach/result → send the full status → `ResourcesReady`, so
        // when this result appears the status has not been sent yet:
        // `Delivery::Pending` is the truthful snapshot. The snapshot is not
        // rewritten later (the command's `finish_delivery` runs before the
        // detach); a failed status never rolls back this commit/detach, and
        // `take_rt` still hands the pair back once.
        self.result = Some(ChangeResult {
            pair: Some(Pair { medium, backing }),
            local: Ok(()),
            delivery: Delivery::Pending,
            // Report the effects captured by an earlier abnormal settlement
            // (never silently drop an unknown write remainder).
            effects: self.force_effects(),
        });
        Ok(())
    }

    fn take_eject_request(&mut self) -> bool {
        self.device.take_eject_request()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::block::{BlockAttrs, BlockDevice};
    use crate::core::device::{Direction, NoMedium};

    /// Device double: records the management hooks and exposes a settable long
    /// operation phase and commit result. Command steps are irrelevant here.
    struct HookDevice {
        long: LongInfo,
        active: bool,
        commits: u32,
        ejects: u32,
        uas: u32,
        medium: Option<NoMedium>,
        commit_result: Result<(), Completion>,
    }

    impl HookDevice {
        fn new() -> Self {
            Self {
                long: LongInfo::IDLE,
                active: false,
                commits: 0,
                ejects: 0,
                uas: 0,
                medium: Some(NoMedium),
                commit_result: Ok(()),
            }
        }
    }

    impl Device for HookDevice {
        type Medium = NoMedium;

        fn prepare(
            &mut self,
            _permit: &CommandPermit,
            _ctx: CommandContext,
            _cdb: &[u8],
        ) -> Result<(), Completion> {
            self.active = true;
            Ok(())
        }

        fn active(&self) -> bool {
            self.active
        }

        fn resume(&mut self, _permit: &CommandPermit) -> Result<(), Completion> {
            Ok(())
        }

        fn poll<'a>(
            &mut self,
            _permit: &CommandPermit,
            _feedback: Feedback,
            _data: &'a mut [u8],
        ) -> PollStep<'a> {
            PollStep::Idle
        }

        fn poll_long<'a>(
            &mut self,
            _permit: &CommandPermit,
            _feedback: Feedback,
            _data: &'a mut [u8],
        ) -> PollStep<'a> {
            PollStep::Idle
        }

        fn long_info(&self) -> LongInfo {
            self.long
        }

        fn interrupt(
            &mut self,
            _permit: &CommandPermit,
            _reason: InterruptReason,
            _known: KnownEffects,
        ) -> Result<(), Fault> {
            self.active = false;
            Ok(())
        }

        fn finish_delivery(&mut self, _permit: &CommandPermit, _delivery: Delivery) {}

        fn raise_ua(&mut self, _permit: &CommandPermit, _class: UaClass) {
            self.uas = self.uas.saturating_add(1);
        }

        fn commit(&mut self, _permit: &BoundaryPermit) -> Result<(), Completion> {
            self.commits = self.commits.saturating_add(1);
            self.commit_result
        }

        fn host_eject_succeeded(&mut self, _permit: &BoundaryPermit) {
            self.ejects = self.ejects.saturating_add(1);
        }

        fn take_medium(&mut self, _permit: &BoundaryPermit) -> Option<NoMedium> {
            self.medium.take()
        }

        fn install_medium(
            &mut self,
            _permit: &BoundaryPermit,
            medium: NoMedium,
        ) -> Result<(), (NoMedium, Fault)> {
            self.medium = Some(medium);
            Ok(())
        }
    }

    fn ctx() -> CommandContext {
        CommandContext {
            lun: 0,
            lun_count: 1,
            host_bytes: 0,
            host_direction: Direction::None,
        }
    }

    fn pair(backing: u8) -> Pair<NoMedium, u8> {
        Pair {
            medium: NoMedium,
            backing,
        }
    }

    #[test]
    fn foreground_format_only_admits_the_query_allow_list() {
        let mut device = HookDevice::new();
        device.long = LongInfo {
            phase: LongPhase::Foreground,
            write_accessible: false,
            progress: Some(32),
            error: None,
        };
        let slot = LuImpl::new(device, 0u8);
        // WRITE(10) is not on the allow list while the format is foreground.
        assert_eq!(
            slot.admit(&[0x2A, 0, 0, 0, 0, 0, 0, 0, 1, 0]),
            Admission::Reject(Completion::Check(FORMAT_IN_PROGRESS))
        );
        for opcode in [0x03u8, 0x12, 0x46, 0x4A, 0xA0] {
            assert_eq!(
                slot.admit(&[opcode]),
                Admission::Proceed,
                "opcode {opcode:#04x} stays admitted during a foreground FORMAT"
            );
        }
    }

    #[test]
    fn needs_recovery_rejects_admission_and_force_returns_the_pair() {
        let owner = TargetId::new(3);
        let mut slot = LuImpl::with_owner(owner, HookDevice::new(), 5u8);
        slot.needs_recovery = true;
        slot.recovery = Some(pair(4));
        assert_eq!(
            slot.admit(&[0x12]),
            Admission::Reject(Completion::Check(NEEDS_RECOVERY))
        );
        assert!(!slot.snapshot().ready);
        assert!(slot.needs_recovery());

        let permit = BoundaryPermit::new(owner);
        // Reinstall is the other documented recovery path. The
        // preserved old pair is dropped only after the new medium is accepted.
        slot.backing = None;
        assert_eq!(slot.install_rt(&permit, pair(8)), Ok(()));
        assert!(!slot.needs_recovery());
        assert_eq!(slot.backing_ref(), Some(&8));
        assert_eq!(slot.force_remove_rt(&permit), Ok(()));
        let result = slot.take_rt(&permit).expect("recovered pair");
        assert_eq!(result.pair, Some(pair(8)));
        assert_eq!(result.local, Ok(()));
        assert!(!result.effects.sync_durable);
        assert_eq!(slot.take_rt(&permit), None);
    }

    #[test]
    fn foreign_permits_are_rejected_without_touching_the_device() {
        let mut slot = LuImpl::with_owner(TargetId::new(7), HookDevice::new(), 5u8);
        let command = CommandPermit::new(TargetId::new(8));
        let boundary = BoundaryPermit::new(TargetId::new(8));
        let mut bank = [0u8; 64];

        assert_eq!(
            slot.prepare(&command, ctx(), &[0x00]),
            Err(Completion::Check(INTERNAL_FAILURE))
        );
        assert_eq!(
            slot.resume(&command),
            Err(Completion::Check(INTERNAL_FAILURE))
        );
        match slot.poll(&command, Feedback::begin(), &mut bank) {
            PollStep::Complete(completion) => {
                assert_eq!(completion, Completion::Check(INTERNAL_FAILURE));
            }
            other => panic!("unexpected poll step: {other:?}"),
        }
        assert_eq!(
            slot.interrupt(&command, InterruptReason::Stop, KnownEffects::NONE),
            Err(Fault::ForeignBoundary)
        );
        // A foreign delivery report is silently ignored.
        slot.finish_delivery(&command, Delivery::Failed);
        // A foreign unit-attention raise is ignored too.
        let foreign_owner = TargetId::new(8);
        slot.raise_ua(&CommandPermit::new(foreign_owner), UaClass::LuReset);
        assert_eq!(slot.device_ref().uas, 0);
        assert_eq!(slot.take_rt(&boundary), None);
        assert_eq!(slot.force_remove_rt(&boundary), Err(Fault::ForeignBoundary));
        assert!(!slot.has_result());
        // Nothing was started, detached or committed.
        assert!(!slot.device_ref().active);
        assert_eq!(slot.device_ref().commits, 0);
        assert_eq!(slot.backing_ref(), Some(&5));
    }

    #[test]
    fn propose_advance_take_hands_the_old_pair_back_once() {
        let owner = TargetId::new(9);
        let mut slot = LuImpl::with_owner(owner, HookDevice::new(), 7u8);
        let permit = BoundaryPermit::new(owner);

        assert_eq!(
            slot.advance_rt(&permit),
            Err(Fault::Contract),
            "advance without a candidate is a contract violation"
        );
        assert_eq!(slot.propose_rt(&permit, Change::Replace(pair(9))), Ok(()));
        assert!(slot.has_candidate());
        // A competing proposal is refused and returns its own input.
        assert_eq!(
            slot.propose_rt(&permit, Change::Remove),
            Err((Change::Remove, Fault::Contract))
        );
        assert_eq!(slot.advance_rt(&permit), Ok(()));
        assert!(!slot.has_candidate());
        assert_eq!(slot.device_ref().commits, 1);

        let result = slot.take_rt(&permit).expect("old pair");
        assert_eq!(result.pair, Some(pair(7)));
        assert_eq!(result.local, Ok(()));
        assert_eq!(result.delivery, Delivery::NotApplicable);
        // The one-shot result is gone; the new pair is current.
        assert_eq!(slot.take_rt(&permit), None);
        assert!(!slot.has_result());
        assert_eq!(slot.backing_ref(), Some(&9));
        assert!(slot.snapshot().ready);
    }

    #[test]
    fn failed_commit_returns_the_candidate_and_keeps_the_old_pair() {
        let owner = TargetId::new(10);
        let mut device = HookDevice::new();
        device.commit_result = Err(Completion::Check(INTERNAL_FAILURE));
        let mut slot = LuImpl::with_owner(owner, device, 7u8);
        let permit = BoundaryPermit::new(owner);

        slot.propose_rt(&permit, Change::Replace(pair(9)))
            .expect("propose");
        assert_eq!(slot.advance_rt(&permit), Err(Fault::Commit));
        assert_eq!(slot.device_ref().commits, 1);
        assert_eq!(slot.backing_ref(), Some(&7), "the old pair stays current");
        let result = slot.take_rt(&permit).expect("candidate returned");
        assert_eq!(result.pair, Some(pair(9)));
        assert_eq!(result.local, Err(Fault::Commit));
        assert!(!result.effects.sync_durable);
    }

    #[test]
    fn force_detaches_without_committing_and_is_not_durable() {
        let owner = TargetId::new(11);
        let mut slot = LuImpl::with_owner(owner, HookDevice::new(), 2u8);
        let permit = BoundaryPermit::new(owner);

        assert_eq!(slot.force_remove_rt(&permit), Ok(()));
        assert_eq!(
            slot.device_ref().commits,
            0,
            "force must not run the local commit hook"
        );
        let result = slot.take_rt(&permit).expect("forced pair");
        assert_eq!(result.pair, Some(pair(2)));
        assert_eq!(result.local, Ok(()));
        assert!(
            !result.effects.sync_durable,
            "force never claims durability"
        );
        assert_eq!(slot.backing_ref(), None);
        assert!(!slot.snapshot().ready);
        // A second force on an empty slot is a no-op, not a contract failure.
        assert_eq!(slot.force_remove_rt(&permit), Ok(()));
    }

    #[test]
    fn raise_ua_forwards_only_with_the_owning_permit() {
        let owner = TargetId::new(21);
        let mut slot = LuImpl::with_owner(owner, HookDevice::new(), 1u8);
        slot.raise_ua(&CommandPermit::new(owner), UaClass::LuReset);
        assert_eq!(slot.device_ref().uas, 1);
        slot.raise_ua(&CommandPermit::new(TargetId::new(22)), UaClass::LuReset);
        assert_eq!(slot.device_ref().uas, 1);
    }

    #[test]
    fn eject_commits_detaches_and_marks_the_delivery_pending() {
        let owner = TargetId::new(13);
        let mut slot = LuImpl::with_owner(owner, HookDevice::new(), 1u8);
        let permit = BoundaryPermit::new(owner);

        assert_eq!(slot.eject_rt(&permit), Ok(()));
        assert_eq!(slot.device_ref().commits, 1);
        assert_eq!(slot.device_ref().ejects, 1);
        assert_eq!(slot.backing_ref(), None);
        assert!(!slot.snapshot().ready);
        let result = slot.take_rt(&permit).expect("ejected pair");
        assert_eq!(result.delivery, Delivery::Pending);
        assert_eq!(result.local, Ok(()));
        assert_eq!(result.pair, Some(pair(1)));
        // An empty slot cannot be ejected twice.
        assert_eq!(slot.eject_rt(&permit), Err(Fault::Contract));
    }

    #[test]
    fn remove_advance_empties_the_slot() {
        let owner = TargetId::new(15);
        let mut slot = LuImpl::with_owner(owner, HookDevice::new(), 7u8);
        let permit = BoundaryPermit::new(owner);

        slot.propose_rt(&permit, Change::Remove).expect("propose");
        assert_eq!(slot.advance_rt(&permit), Ok(()));
        assert_eq!(slot.backing_ref(), None);
        assert!(!slot.snapshot().ready);
        let result = slot.take_rt(&permit).expect("removed pair");
        assert_eq!(result.pair, Some(pair(7)));
        // Installing the returned pair into the now-empty slot succeeds.
        assert_eq!(slot.install_rt(&permit, pair(7)), Ok(()));
        assert_eq!(slot.backing_ref(), Some(&7));
        assert!(slot.snapshot().ready);
    }

    #[test]
    fn empty_slot_rejects_commands_without_touching_the_device() {
        let mut slot = LuImpl::new(BlockDevice::new(BlockAttrs::new(16, 512)), 1u8);
        let boundary = BoundaryPermit::new(TargetId::UNBOUND);
        slot.force_remove_rt(&boundary)
            .expect("force removes the pair");
        assert!(!slot.snapshot().ready);
        // Media commands are refused, but the mandatory query set stays
        // answerable on an empty slot (SPC-3 6.21, §4.19).
        assert_eq!(
            slot.admit(&[0x28, 0, 0, 0, 0, 0, 0, 0, 1, 0]),
            Admission::Reject(Completion::Check(MEDIUM_NOT_PRESENT))
        );
        assert_eq!(slot.admit(&[0x12]), Admission::Proceed);
        assert_eq!(slot.admit(&[0x03]), Admission::Proceed);
        assert_eq!(slot.admit(&[0xA0]), Admission::Proceed);
        // MODE SENSE is only admitted by a device that opts in (MmcDrive does;
        // a block LUN keeps the empty-slot reject).
        assert_eq!(
            slot.admit(&[0x1A, 0, 0x2A, 0, 64, 0]),
            Admission::Reject(Completion::Check(MEDIUM_NOT_PRESENT))
        );
        assert_eq!(
            slot.admit(&[0x5A, 0, 0x2A, 0, 0, 0, 0, 0, 0, 64]),
            Admission::Reject(Completion::Check(MEDIUM_NOT_PRESENT))
        );
        let permit = CommandPermit::new(TargetId::UNBOUND);
        let ctx = CommandContext {
            lun: 0,
            lun_count: 1,
            host_bytes: 0,
            host_direction: Direction::None,
        };
        assert_eq!(
            slot.prepare(&permit, ctx, &[0x28, 0, 0, 0, 0, 0, 0, 0, 1, 0]),
            Err(Completion::Check(MEDIUM_NOT_PRESENT))
        );
    }

    #[test]
    fn empty_slot_admits_a_device_level_mode_sense() {
        use crate::core::Spc;
        use crate::mmc::{FlatCdMedium, MmcCaps, MmcDrive};

        let slot: LuImpl<_, u8> =
            LuImpl::empty(Spc::new(MmcDrive::<FlatCdMedium>::empty(MmcCaps::cdrom())));
        // MODE SENSE is a drive query: the empty gate must let it through so
        // `Spc`/`MmcDrive` can answer the drive pages.
        assert_eq!(
            slot.admit(&[0x5A, 0, 0x2A, 0, 0, 0, 0, 0, 0, 1]),
            Admission::Proceed
        );
        assert_eq!(slot.admit(&[0x1A, 0, 0x00, 0, 64, 0]), Admission::Proceed);
        // A media command is still refused.
        assert_eq!(
            slot.admit(&[0x28, 0, 0, 0, 0, 0, 0, 0, 1, 0]),
            Admission::Reject(Completion::Check(MEDIUM_NOT_PRESENT))
        );
    }

    #[test]
    fn install_advance_produces_no_result() {
        let mut slot = LuImpl::new(BlockDevice::new(BlockAttrs::new(16, 512)), 1u8);
        let p = BoundaryPermit::new(TargetId::UNBOUND);
        slot.propose_rt(&p, Change::Remove).expect("propose remove");
        slot.advance_rt(&p).expect("remove");
        let _ = slot.take_rt(&p).expect("old pair");
        slot.propose_rt(&p, Change::Install(pair(9)))
            .expect("propose install");
        slot.advance_rt(&p).expect("install");
        assert_eq!(slot.backing_ref(), Some(&9));
        assert!(!slot.has_result(), "install has no old pair to hand back");
        assert_eq!(slot.take_rt(&p), None);
    }
}
