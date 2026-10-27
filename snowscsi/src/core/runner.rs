//! Command runner: authoritative boundary, command step machine and
//! stop/abort settlement.
//!
//! Authority: `__ARCH__/design/02-api.md` §4.3/§4.4,
//! `__ARCH__/design/02-api-core.md` §4.7/§4.11 and
//! `__ARCH__/design/03-lifecycles.md` §3.2–§3.4/§3.6.
//!
//! The runner owns what a slot cannot know:
//!
//! - the authoritative boundary (`command_active`, required/speculative IO,
//!   retained input, unconsumed completion, live execution borrow) plus the
//!   long-operation settled check (`§4.11`);
//! - the current [`Feedback`] and one pending adapter token with metadata only —
//!   core never stores a `&mut [u8]`, the shell re-supplies `work` on every
//!   step;
//! - lifecycle settlement: **Stop is a drain, everything else cancels**
//!   (`03 §3.3`).
//!
//! `stop`, `transport_ended` and `fatal` may be requested while a command is
//! live. `tick` reports `Ended` only after a `step_command` call settled the
//! command; until then it keeps returning `ServiceReady`.
//!
//! `Target` (the next card) is the only public owner of a `Runner`: every entry
//! here is crate-private except [`Runner::enter_execution_borrow`].

use ::core::cell::Cell;
use ::core::task::Poll;

use super::device::{
    Admission, CommandContext, Control, DataPlan, Direction, Feedback, InterruptReason, PollStep,
    TargetId,
};
use super::errors::{Completion, Delivery, Effect, Fault, KnownEffects, ABORTED_COMMAND};
use super::long::{LongInfo, LongPhase};
use super::lu::Lu;
use super::management::{BoundaryReject, Change, ChangeResult};
use super::permit::{BoundaryPermit, CommandPermit, ExecutionGuard};
use super::storage::{
    HostBuf, HostReceipt, HostReq, HostToken, HostTransport, IoBuf, IoReceipt, IoReq, IoToken,
    PrefetchOp, Storage, StorageOp, StorageReceipt,
};

/// Why the service loop ended.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RunEnd {
    /// `Target::stop`: new submission closed, pending work drained.
    Stopped,
    /// The transport ended (reset/disconnect); not recoverable.
    TransportEnded,
    /// A fatal service error.
    Fatal,
}

/// One outcome per service entry. There is no unbounded event queue: a
/// termination reason or a resource handback is returned exactly when the
/// application must act on it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RunOutcome {
    /// No control was applied and no resource was handed back; keep serving.
    ServiceReady,
    /// This `tick` consumed a `Control` (only `Nop`; `Abort` is applied by
    /// `step_command`).
    ControlApplied(Control),
    /// A host eject succeeded; `lun`'s old pair is resident and the application
    /// must `take` it before service continues.
    ResourcesReady {
        /// Wire LUN whose pair awaits a take.
        lun: usize,
    },
    /// The service loop ended for an explicit reason.
    Ended {
        /// Why service ended.
        reason: RunEnd,
        /// Fatal error, if any.
        error: Option<Fault>,
    },
}

/// One command-level step. `Pending` is a real adapter state, not a busy-loop
/// fiction: the shell may do other work and call the next step later.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DriveStep {
    /// Not settled yet; the runner kept the feedback and the pending token.
    Pending,
    /// The local completion is fixed; the shell still delivers it.
    Done(Completion),
    /// The runner settled the command at the control plane.
    Control(RunOutcome),
}

/// One pending adapter operation. Tokens are metadata-only and `Copy`; the
/// buffer is re-borrowed from the caller's `work` on every step, so
/// `buf_offset` is relative to `work`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum PendingOp {
    Storage {
        token: IoToken,
        req: IoReq,
        buf_offset: usize,
        prefetch: bool,
    },
    HostRecv {
        token: HostToken,
        req: HostReq,
        buf_offset: usize,
    },
    HostSend {
        token: HostToken,
        req: HostReq,
        buf_offset: usize,
    },
}

/// Per-command step state. Every field is `Copy`: no buffer lifetime is stored.
#[derive(Clone, Copy, Debug)]
struct DriveState {
    feedback: Feedback,
    host_failed: bool,
    pending: Option<PendingOp>,
    /// Fixed completion produced by an admission/prepare reject.
    done: Option<Completion>,
    /// Declared command context; the `Publish` contract compares against it.
    ctx: CommandContext,
    /// Work-bank identity captured on the first `Pending`: the shell must pass
    /// the same bank (address and length) on every continuation.
    work_addr: usize,
    work_len: usize,
    /// Whether the single data plan has already been published.
    published: bool,
}

/// Result of one runner-issued storage operation.
enum IoSettlement {
    /// The token is live; the caller stores it and reports `Pending`.
    Pending(PendingOp),
    /// The adapter answered inside this step.
    Ready(StorageReceipt),
    /// The adapter pool is exhausted; nothing was issued.
    Unissued,
}

/// What the runner must do with one storage settlement.
enum IoAbsorb {
    /// Token retained; store the state and report `Pending`.
    Pending,
    /// Receipt folded into `state.feedback`; poll the device again.
    Retained,
    /// Contract violation with no external effect (nothing was issued).
    Unissued,
    /// Contract violation reported for an operation that did reach the adapter.
    Contract,
}

/// Authoritative runner state.
///
/// The `Cell` counters let a step mutate bookkeeping while the runner is
/// borrowed immutably (`boundary` is a read-only projection over them). An
/// application can hold [`Runner::enter_execution_borrow`] while reading the
/// boundary, but it cannot reach a management entry at the same time.
pub struct Runner {
    owner: TargetId,
    command_active: Cell<bool>,
    required_io: Cell<bool>,
    speculative_io: Cell<bool>,
    retained_input: Cell<usize>,
    unconsumed_completion: Cell<bool>,
    execution_borrow: Cell<u32>,
    pending_control: Option<Control>,
    stop: bool,
    transport_end: bool,
    fatal: Option<Fault>,
    await_take: Option<usize>,
    /// Host-eject transaction in flight (AwaitDelivery): commit/detach may be
    /// under way but no result is resident yet (`§4.11`).
    eject_pending: Option<usize>,
    long_feedback: Option<Feedback>,
    drive_state: Cell<Option<DriveState>>,
    /// Deferred emergency removals, one bit per LUN.
    ///
    /// A force accepted while a result/handback barrier is resident must not
    /// overwrite that result (`02-api-core.md` §4.10); it is recorded here and
    /// completed by the `take` that clears the barrier. The slot used to be a
    /// single `Option<usize>`, which silently lost a force aimed at another
    /// LUN: the take that released the barrier only ever continued its own
    /// LUN. The mask stays allocation-free (`no_std`); LUNs >= 64 are rejected
    /// with `Fault::Contract` (documented bound).
    force_pending: u64,
    /// Consumed control events (probe counter, not a business API).
    #[doc(hidden)]
    pub control_events: u32,
    /// Resource takes observed (probe counter, not a business API).
    #[doc(hidden)]
    pub take_events: u32,
    /// Host-eject handbacks published (probe counter, not a business API).
    #[doc(hidden)]
    pub eject_events: u32,
    /// Explicit speculative prefetches executed (probe counter).
    #[allow(dead_code)] // read by the later probe harness
    prefetch_events: Cell<u32>,
}

impl Runner {
    /// Standalone runner (owner [`TargetId::UNBOUND`]).
    #[allow(dead_code)] // wired by `Target::new` (C2) and driven by tests here
    pub(crate) fn new() -> Self {
        Self::for_target(TargetId::UNBOUND)
    }

    /// Runner owned by `owner`; permits minted here only match that owner.
    #[allow(dead_code)] // `Target` (C2) constructs its runner with its identity
    pub(crate) fn for_target(owner: TargetId) -> Self {
        Self {
            owner,
            command_active: Cell::new(false),
            required_io: Cell::new(false),
            speculative_io: Cell::new(false),
            retained_input: Cell::new(0),
            unconsumed_completion: Cell::new(false),
            execution_borrow: Cell::new(0),
            pending_control: None,
            stop: false,
            transport_end: false,
            fatal: None,
            await_take: None,
            eject_pending: None,
            long_feedback: None,
            drive_state: Cell::new(None),
            force_pending: 0,
            control_events: 0,
            take_events: 0,
            eject_events: 0,
            prefetch_events: Cell::new(0),
        }
    }

    /// Owning target identity.
    #[allow(dead_code)] // read by `Target::owner` (C2)
    pub(crate) const fn owner(&self) -> TargetId {
        self.owner
    }

    /// Whether a control request is queued (used by `Target`'s control gate).
    pub(crate) const fn has_pending_control(&self) -> bool {
        self.pending_control.is_some()
    }

    fn permit(&self) -> BoundaryPermit {
        BoundaryPermit::new(self.owner)
    }

    fn command_permit(&self) -> CommandPermit {
        CommandPermit::new(self.owner)
    }

    /// Enter an execution window.
    ///
    /// The guard is a RAII **counter**, not a flag: nested windows do not clear
    /// each other on drop. The runner remains readable (`boundary` reports
    /// [`BoundaryReject::ExecutionBorrowAlive`]) but no management entry can
    /// pass its gate while a guard is alive.
    pub fn enter_execution_borrow(&self) -> ExecutionGuard<'_> {
        ExecutionGuard::new(&self.execution_borrow)
    }

    /// The authoritative boundary, in the fixed order of `§4.11`.
    ///
    /// `LuInfo::boundary` is only the command/long-operation projection; this
    /// conjunction is the authority.
    pub(crate) fn boundary<P>(&self, slot: &dyn Lu<Pair = P>) -> Result<(), BoundaryReject> {
        self.boundary_of(slot)
    }

    /// Boundary over any slot reference (also used by the generic entries).
    fn boundary_of<L: Lu + ?Sized>(&self, slot: &L) -> Result<(), BoundaryReject> {
        self.boundary_checks(slot, true)
    }

    /// Boundary for starting a command.
    ///
    /// A resident foreground long operation (MMC FORMAT/BLANK) must **not**
    /// reject the command at the runner: the medium gate belongs to the device
    /// (`Lu::admit` returns `2/04/04` and the profile refuses before any IO).
    /// Management entries keep the stricter [`Self::boundary_of`].
    fn command_boundary_of<L: Lu + ?Sized>(&self, slot: &L) -> Result<(), BoundaryReject> {
        self.boundary_checks(slot, false)
    }

    fn boundary_checks<L: Lu + ?Sized>(
        &self,
        slot: &L,
        require_long_settled: bool,
    ) -> Result<(), BoundaryReject> {
        if self.command_active.get() || slot.active() {
            return Err(BoundaryReject::CommandActive);
        }
        if self.required_io.get() {
            return Err(BoundaryReject::RequiredIoInFlight);
        }
        if self.speculative_io.get() {
            return Err(BoundaryReject::SpeculativeIoInFlight);
        }
        if self.retained_input.get() > 0 {
            return Err(BoundaryReject::RetainedInput);
        }
        if self.unconsumed_completion.get() {
            return Err(BoundaryReject::UnconsumedCompletion);
        }
        if self.execution_borrow.get() > 0 {
            return Err(BoundaryReject::ExecutionBorrowAlive);
        }
        if require_long_settled
            && !matches!(slot.long_info().phase, LongPhase::Idle | LongPhase::Settled)
        {
            return Err(BoundaryReject::LongOperationActive);
        }
        Ok(())
    }

    /// Global result barrier: an unclaimed `ResourcesReady` handback blocks new
    /// service. `take` deliberately does not use this gate — taking clears it.
    pub(crate) fn result_barrier(&self) -> Result<(), BoundaryReject> {
        if self.await_take.is_some() {
            Err(BoundaryReject::AwaitingResourceTake)
        } else {
            Ok(())
        }
    }

    /// Gate for a resident long-operation entry.
    ///
    /// It applies the lifecycle/control checks of `service_gate` but does not
    /// reject the long operation's own non-settled phase (that is what this
    /// entry is there to advance). Everything else — ended, control, result
    /// barrier, command, in-flight IO, retained input, unconsumed completion,
    /// live borrow — still blocks.
    fn poll_long_gate<L: Lu + ?Sized>(&self, slot: &L) -> Result<(), BoundaryReject> {
        if self.terminal_outcome().is_some() {
            return Err(BoundaryReject::Ended);
        }
        if self.pending_control.is_some() {
            return Err(BoundaryReject::ControlPending);
        }
        if self.eject_pending.is_some() {
            return Err(BoundaryReject::EjectPending);
        }
        self.result_barrier()?;
        if self.command_active.get() || slot.active() {
            return Err(BoundaryReject::CommandActive);
        }
        if self.required_io.get() {
            return Err(BoundaryReject::RequiredIoInFlight);
        }
        if self.speculative_io.get() {
            return Err(BoundaryReject::SpeculativeIoInFlight);
        }
        if self.retained_input.get() > 0 {
            return Err(BoundaryReject::RetainedInput);
        }
        if self.unconsumed_completion.get() {
            return Err(BoundaryReject::UnconsumedCompletion);
        }
        if self.execution_borrow.get() > 0 {
            return Err(BoundaryReject::ExecutionBorrowAlive);
        }
        Ok(())
    }

    /// Service gate for management (`§4.11`): ended, control-pending, result
    /// barrier, boundary.
    ///
    /// `awaiting_resource_take` has two sources: the runner's global
    /// `await_take` (host-eject `ResourcesReady` not claimed yet) and a result
    /// the slot itself still holds from `advance`/`force`. Both are the same
    /// design term — "a result has been produced and awaits `take`" — so a new
    /// transaction cannot start before the one-shot result is claimed
    /// (`03 §3.6` AwaitTake row). `take` deliberately does not use this gate; it
    /// is what clears the barrier.
    ///
    /// **Barrier scope (deliberate, documented drift).** `03 §3.6` and
    /// `02-api-core §4.11` name `service_gate` the gate for commands, long
    /// operations *and* management. The production scope is narrower: this
    /// gate (with `slot.has_result()`) blocks only `propose`/`advance`/`install`.
    /// `command_gate` and `poll_long_gate` consult the global `result_barrier`
    /// but **not** a slot-resident result, because the slot would otherwise
    /// deadlock: a command is how the application inspects the medium it has to
    /// hand back, and nothing else can clear the barrier but `take`. Pinning
    /// fixture: `core_p3::a_resident_result_blocks_management_but_not_commands`.
    fn service_gate<L: Lu + ?Sized>(&self, slot: &L) -> Result<(), BoundaryReject> {
        if self.terminal_outcome().is_some() {
            return Err(BoundaryReject::Ended);
        }
        if self.pending_control.is_some() {
            return Err(BoundaryReject::ControlPending);
        }
        if self.eject_pending.is_some() {
            return Err(BoundaryReject::EjectPending);
        }
        self.result_barrier()?;
        if slot.has_result() {
            return Err(BoundaryReject::AwaitingResourceTake);
        }
        self.boundary_of(slot)
    }

    /// Service gate for starting a command. Unlike [`Self::service_gate`] it
    /// lets the device answer the foreground-format rejection itself.
    fn command_gate<L: Lu + ?Sized>(&self, slot: &L) -> Result<(), BoundaryReject> {
        if self.terminal_outcome().is_some() {
            return Err(BoundaryReject::Ended);
        }
        if self.pending_control.is_some() {
            return Err(BoundaryReject::ControlPending);
        }
        if self.eject_pending.is_some() {
            return Err(BoundaryReject::EjectPending);
        }
        self.result_barrier()?;
        self.command_boundary_of(slot)
    }

    /// Terminal outcome regardless of in-flight work, in the fixed order
    /// fatal → transport end → stopped.
    pub(crate) fn terminal_outcome(&self) -> Option<RunOutcome> {
        if let Some(fault) = self.fatal {
            Some(RunOutcome::Ended {
                reason: RunEnd::Fatal,
                error: Some(fault),
            })
        } else if self.transport_end {
            Some(RunOutcome::Ended {
                reason: RunEnd::TransportEnded,
                error: None,
            })
        } else if self.stop {
            Some(RunOutcome::Ended {
                reason: RunEnd::Stopped,
                error: None,
            })
        } else {
            None
        }
    }

    /// Terminal outcome only once nothing still has to settle: `tick` must not
    /// report `Ended` while a command or its in-flight IO is live.
    fn settled_terminal_outcome(&self) -> Option<RunOutcome> {
        if self.command_active.get() || self.drive_state.get().is_some() {
            None
        } else {
            self.terminal_outcome()
        }
    }

    // ── bookkeeping ────────────────────────────────────────────────────

    fn note_command_started(&self) {
        self.command_active.set(true);
    }

    fn note_command_finished(&self) {
        self.command_active.set(false);
    }

    fn note_required_io(&self, in_flight: bool) {
        self.required_io.set(in_flight);
    }

    fn note_speculative_io(&self, in_flight: bool) {
        self.speculative_io.set(in_flight);
    }

    fn cancel_speculative_io(&self) {
        self.speculative_io.set(false);
    }

    /// Retained inbound bytes keep the boundary incomplete; wired by the
    /// transport/`Spc` card.
    #[allow(dead_code)]
    fn hold_retained_input(&self, bytes: usize) {
        self.retained_input
            .set(self.retained_input.get().saturating_add(bytes));
    }

    /// Drop the retained-input obligation once the bytes were consumed/parsed.
    #[allow(dead_code)]
    fn clear_retained_input(&self) {
        self.retained_input.set(0);
    }

    fn note_completion(&self) {
        self.unconsumed_completion.set(true);
    }

    fn consume_completion(&self) {
        self.unconsumed_completion.set(false);
    }

    // ── command start / step ───────────────────────────────────────────

    /// Start one command: admission and `prepare` only. All data/IO work happens
    /// in [`Runner::step_command`], which may return `Pending` across calls.
    #[allow(dead_code)] // `Target::drive_start_*` (C2); driven by tests here
    pub(crate) fn start_command<L: Lu + ?Sized>(
        &self,
        lu: &mut L,
        ctx: CommandContext,
        cdb: &[u8],
    ) -> Result<(), Fault> {
        if self.drive_state.get().is_some() || self.command_gate(lu).is_err() {
            return Err(Fault::Boundary);
        }
        let permit = self.command_permit();
        self.note_command_started();
        match lu.admit(cdb) {
            Admission::Proceed => {}
            Admission::Reject(completion) => {
                // A rejection is already a fixed completion; the medium and the
                // backing were never touched.
                self.note_command_finished();
                self.note_completion();
                self.drive_state.set(Some(DriveState {
                    feedback: Feedback::begin(),
                    host_failed: false,
                    pending: None,
                    done: Some(completion),
                    ctx,
                    work_addr: 0,
                    work_len: 0,
                    published: false,
                }));
                return Ok(());
            }
        }
        if let Err(completion) = lu.prepare(&permit, ctx, cdb) {
            // The completion is fixed but the shell still owes the status, so
            // the truthful delivery state is `Pending`, not `Complete`.
            lu.finish_delivery(&permit, Delivery::Pending);
            self.note_command_finished();
            self.note_completion();
            self.drive_state.set(Some(DriveState {
                feedback: Feedback::begin(),
                host_failed: false,
                pending: None,
                done: Some(completion),
                ctx,
                work_addr: 0,
                work_len: 0,
                published: false,
            }));
            return Ok(());
        }
        self.drive_state.set(Some(DriveState {
            feedback: Feedback::begin(),
            host_failed: false,
            pending: None,
            done: None,
            ctx,
            work_addr: 0,
            work_len: 0,
            published: false,
        }));
        Ok(())
    }

    /// Cancel one pending token. `cancel`/`poll_exec` return before the buffer
    /// may be reused, so this must complete before settling (`03 §3.3`).
    fn cancel_pending(
        &self,
        pending: PendingOp,
        storage: &mut dyn Storage,
        host: &mut dyn HostTransport,
    ) {
        match pending {
            PendingOp::Storage {
                token, prefetch, ..
            } => {
                storage.cancel(token);
                if prefetch {
                    self.cancel_speculative_io();
                } else {
                    self.note_required_io(false);
                }
            }
            PendingOp::HostRecv { token, .. } | PendingOp::HostSend { token, .. } => {
                host.cancel(token);
            }
        }
    }

    /// Facts already known for an operation whose end the runner cannot
    /// observe: an unobserved write/sync or host receive keeps
    /// `unknown_remainder`; a read or a send has no unrecoverable effect.
    fn known_unobserved(dir: Direction) -> KnownEffects {
        KnownEffects {
            unknown_remainder: matches!(dir, Direction::FromHost | Direction::None),
            ..KnownEffects::NONE
        }
    }

    /// Facts already known for a dropped pending operation.
    fn known_for_pending(pending: Option<PendingOp>) -> KnownEffects {
        match pending {
            Some(PendingOp::Storage { req, .. }) => Self::known_unobserved(req.dir),
            Some(PendingOp::HostRecv { .. }) => Self::known_unobserved(Direction::FromHost),
            Some(PendingOp::HostSend { .. }) => Self::known_unobserved(Direction::ToHost),
            None => KnownEffects::NONE,
        }
    }

    /// Facts confirmed by a storage receipt that arrived while a Stop drained.
    fn known_from_storage_receipt(req: IoReq, receipt: StorageReceipt) -> KnownEffects {
        let mut known = KnownEffects::NONE;
        if req.dir == Direction::FromHost {
            known.confirmed_write = receipt.confirmed as u64;
        }
        if req.dir == Direction::None && receipt.error.is_none() && receipt.effect == Effect::Known
        {
            known.sync_durable = true;
        }
        known.unknown_remainder = receipt.effect == Effect::UnknownRemainder;
        known
    }

    /// Facts confirmed by a host receipt that arrived while a Stop drained.
    fn known_from_host_receipt(receipt: HostReceipt) -> KnownEffects {
        KnownEffects {
            host_prefix: receipt.accepted() as u64,
            ..KnownEffects::NONE
        }
    }

    /// Stop is a cooperative **drain**, not a cancel (`03 §3.3`).
    ///
    /// New submission is already closed by `Target::stop`. The pending token is
    /// polled once more: `Pending` keeps the state, `Ready` merges its confirmed
    /// prefix/durable/unknown facts into `known` and settles. Only an adapter
    /// error (or a token that can no longer be addressed) falls back to
    /// `cancel`. Returns `Some(Pending)` while the drain still has work.
    fn drain_stop_active<L: Lu + ?Sized>(
        &mut self,
        lu: &mut L,
        storage: &mut dyn Storage,
        host: &mut dyn HostTransport,
        work: &mut [u8],
        mut state: DriveState,
    ) -> Result<Option<DriveStep>, Fault> {
        let known = match state.pending {
            Some(PendingOp::Storage {
                token,
                req,
                buf_offset,
                prefetch,
            }) => {
                let polled =
                    pending_io_buf(work, req, buf_offset).map(|buf| storage.poll_exec(token, buf));
                match polled {
                    Some(Poll::Pending) => {
                        state.work_addr = work.as_ptr() as usize;
                        state.work_len = work.len();
                        self.drive_state.set(Some(state));
                        return Ok(Some(DriveStep::Pending));
                    }
                    Some(Poll::Ready(raw)) => {
                        if prefetch {
                            self.cancel_speculative_io();
                        } else {
                            self.note_required_io(false);
                        }
                        let receipt = sanitize_storage_receipt(req, raw);
                        let mut known = Self::known_from_storage_receipt(req, receipt);
                        if raw.error.is_some()
                            && matches!(req.dir, Direction::FromHost | Direction::None)
                        {
                            // The adapter reported a failure: cancel the token
                            // and keep the remainder unknown.
                            storage.cancel(token);
                            known.unknown_remainder = true;
                        }
                        known
                    }
                    None => {
                        // The caller's `work` no longer addresses this window:
                        // the drain cannot advance, so it cancels.
                        storage.cancel(token);
                        if prefetch {
                            self.cancel_speculative_io();
                        } else {
                            self.note_required_io(false);
                        }
                        Self::known_unobserved(req.dir)
                    }
                }
            }
            Some(PendingOp::HostRecv {
                token,
                req,
                buf_offset,
            })
            | Some(PendingOp::HostSend {
                token,
                req,
                buf_offset,
            }) => {
                let is_recv = req.dir == Direction::FromHost;
                let polled = pending_host_buf(work, req, buf_offset, is_recv)
                    .map(|buf| host.poll_host(token, buf));
                match polled {
                    Some(Poll::Pending) => {
                        state.work_addr = work.as_ptr() as usize;
                        state.work_len = work.len();
                        self.drive_state.set(Some(state));
                        return Ok(Some(DriveStep::Pending));
                    }
                    Some(Poll::Ready(raw)) => {
                        let mut known = Self::known_from_host_receipt(raw);
                        if raw.error().is_some() {
                            host.cancel(token);
                            if is_recv {
                                known.unknown_remainder = true;
                            }
                        }
                        known
                    }
                    None => {
                        host.cancel(token);
                        Self::known_unobserved(req.dir)
                    }
                }
            }
            None => KnownEffects::NONE,
        };
        let permit = self.command_permit();
        let interrupted = lu.interrupt(&permit, InterruptReason::Stop, known);
        lu.finish_delivery(&permit, Delivery::Failed);
        self.note_command_finished();
        self.drive_state.set(None);
        if let Err(fault) = interrupted {
            // A failed settle is terminal: the slot can no longer prove a safe
            // state (`03 §3.3`).
            self.fatal = Some(fault);
            return Err(fault);
        }
        Ok(None)
    }

    /// Immediate cancel path: `cancel` the pending token, settle with `known`,
    /// then clear the command.
    fn settle_abnormally<L: Lu + ?Sized>(
        &mut self,
        lu: &mut L,
        storage: &mut dyn Storage,
        host: &mut dyn HostTransport,
        reason: InterruptReason,
    ) -> Result<(), Fault> {
        let state = match self.drive_state.get() {
            Some(state) => state,
            None => return Ok(()),
        };
        if state.done.is_some() {
            // A completion fixed by admission/prepare never started execution:
            // `03 §3.3` forbids `interrupt` here (no command, no IO).
            self.note_command_finished();
            self.consume_completion();
            self.drive_state.set(None);
            return Ok(());
        }
        let known = Self::known_for_pending(state.pending);
        if let Some(pending) = state.pending {
            self.cancel_pending(pending, storage, host);
        }
        let permit = self.command_permit();
        let interrupted = lu.interrupt(&permit, reason, known);
        lu.finish_delivery(&permit, Delivery::Failed);
        self.note_command_finished();
        self.drive_state.set(None);
        if let Err(fault) = interrupted {
            self.fatal = Some(fault);
            return Err(fault);
        }
        Ok(())
    }

    /// Transport end/fatal path.
    fn abort_active<L: Lu + ?Sized>(
        &mut self,
        lu: &mut L,
        storage: &mut dyn Storage,
        host: &mut dyn HostTransport,
        outcome: RunOutcome,
    ) -> Result<(), Fault> {
        let reason = match outcome {
            RunOutcome::Ended {
                reason: RunEnd::TransportEnded,
                ..
            } => InterruptReason::Stop,
            _ => InterruptReason::Stop,
        };
        self.settle_abnormally(lu, storage, host, reason)
    }

    /// Apply a pending `Control::Abort`: cancel the pending token, settle with
    /// ABORTED COMMAND, never detach or eject the medium.
    fn abort_control<L: Lu + ?Sized>(
        &mut self,
        lu: &mut L,
        storage: &mut dyn Storage,
        host: &mut dyn HostTransport,
    ) -> Result<DriveStep, Fault> {
        self.pending_control = None;
        self.control_events = self.control_events.saturating_add(1);
        if self.drive_state.get().is_none() {
            // `Abort` is queued only while a command is active; an idle Abort is
            // an accepted no-op (`§4.10`).
            return Ok(DriveStep::Control(RunOutcome::ServiceReady));
        }
        self.settle_abnormally(lu, storage, host, InterruptReason::Stop)?;
        Ok(DriveStep::Done(Completion::Check(ABORTED_COMMAND)))
    }

    /// Advance one command step. `Pending` across calls keeps the feedback, the
    /// command phase and the pending token; `scratch` is the shell-owned second
    /// bank (unused in P2a, which runs one command at a time).
    #[allow(dead_code)] // `Target::drive_step_*` (C2); driven by tests here
    pub(crate) fn step_command<L: Lu + ?Sized>(
        &mut self,
        lu: &mut L,
        storage: &mut dyn Storage,
        host: &mut dyn HostTransport,
        work: &mut [u8],
        _scratch: &mut [u8],
    ) -> Result<DriveStep, Fault> {
        let mut state = self.drive_state.get().ok_or(Fault::Contract)?;

        // A `Pending` command must be continued with the *same* work bank
        // (`§4.3`): a different address/length would reinterpret the retained
        // token against the wrong bytes.
        let work_addr = work.as_ptr() as usize;
        let work_len = work.len();
        if state.pending.is_some()
            && state.work_len != 0
            && (state.work_addr != work_addr || state.work_len != work_len)
        {
            if let Some(pending) = state.pending {
                self.cancel_pending(pending, storage, host);
            }
            let known = Self::known_for_pending(state.pending);
            self.settle_contract(lu, known);
            return Err(Fault::Contract);
        }

        // 1. A completion fixed by admission/prepare is reported exactly once.
        if let Some(completion) = state.done {
            self.drive_state.set(None);
            self.consume_completion();
            return Ok(DriveStep::Done(completion));
        }

        // 2. Lifecycle settlement settles before any new IO (`03 §3.3`).
        if let Some(outcome) = self.terminal_outcome() {
            match outcome {
                RunOutcome::Ended {
                    reason: RunEnd::Stopped,
                    ..
                } => {
                    if self
                        .drain_stop_active(lu, storage, host, work, state)?
                        .is_some()
                    {
                        return Ok(DriveStep::Pending);
                    }
                    return Ok(DriveStep::Control(outcome));
                }
                _ => {
                    self.abort_active(lu, storage, host, outcome)?;
                    return Ok(DriveStep::Control(outcome));
                }
            }
        }

        // 3. `Abort` is consumed by a step entry, never by `tick`.
        if matches!(self.pending_control, Some(Control::Abort)) {
            return self.abort_control(lu, storage, host);
        }

        // 4. Continue the retained adapter operation, then poll the device once
        //    more with the receipt as feedback.
        if let Some(pending) = state.pending {
            match pending {
                PendingOp::Storage {
                    token,
                    req,
                    buf_offset,
                    prefetch,
                } => {
                    let polled = pending_io_buf(work, req, buf_offset)
                        .map(|buf| storage.poll_exec(token, buf));
                    match polled {
                        Some(Poll::Pending) => return Ok(DriveStep::Pending),
                        Some(Poll::Ready(receipt)) => {
                            if prefetch {
                                self.cancel_speculative_io();
                            } else {
                                self.note_required_io(false);
                            }
                            state.pending = None;
                            if !matches!(
                                self.absorb_io(&mut state, req, IoSettlement::Ready(receipt)),
                                IoAbsorb::Retained
                            ) {
                                self.settle_contract(lu, Self::known_unobserved(req.dir));
                                return Err(Fault::Contract);
                            }
                        }
                        None => {
                            // The retained window is no longer addressable in
                            // `work`: cancel before settling, never drop a live
                            // token (`03 §3.4`).
                            storage.cancel(token);
                            if prefetch {
                                self.cancel_speculative_io();
                            } else {
                                self.note_required_io(false);
                            }
                            self.settle_contract(lu, Self::known_unobserved(req.dir));
                            return Err(Fault::Contract);
                        }
                    }
                }
                PendingOp::HostRecv {
                    token,
                    req,
                    buf_offset,
                } => match self.resume_host(host, work, token, req, buf_offset, true) {
                    HostResume::Pending => return Ok(DriveStep::Pending),
                    HostResume::Retained(raw) => {
                        state.pending = None;
                        if raw.error() == Some(Fault::Contract) {
                            self.settle_contract(lu, Self::known_unobserved(Direction::FromHost));
                            return Err(Fault::Contract);
                        }
                        if raw.error().is_some() {
                            state.host_failed = true;
                        }
                        state.feedback = Feedback::host_received(raw);
                    }
                    HostResume::Unaddressable => {
                        host.cancel(token);
                        self.settle_contract(lu, Self::known_unobserved(Direction::FromHost));
                        return Err(Fault::Contract);
                    }
                },
                PendingOp::HostSend {
                    token,
                    req,
                    buf_offset,
                } => match self.resume_host(host, work, token, req, buf_offset, false) {
                    HostResume::Pending => return Ok(DriveStep::Pending),
                    HostResume::Retained(raw) => {
                        state.pending = None;
                        if raw.error() == Some(Fault::Contract) {
                            self.settle_contract(lu, Self::known_unobserved(Direction::ToHost));
                            return Err(Fault::Contract);
                        }
                        if raw.error().is_some() {
                            state.host_failed = true;
                        }
                        state.feedback = Feedback::host_sent(raw);
                    }
                    HostResume::Unaddressable => {
                        host.cancel(token);
                        self.settle_contract(lu, Self::known_unobserved(Direction::ToHost));
                        return Err(Fault::Contract);
                    }
                },
            }
        }

        let permit = self.command_permit();
        let work_start = work.as_ptr() as usize;
        let work_len = work.len();
        loop {
            let step = lu.poll(&permit, state.feedback, work);
            match step {
                PollStep::Publish(plan) => {
                    if state.published {
                        // A command publishes exactly one data plan (`§4.4`).
                        self.settle_contract(lu, KnownEffects::NONE);
                        return Err(Fault::Contract);
                    }
                    state.published = true;
                    // `host_bytes` contract: the direction must match; a
                    // Data-In response may be shorter than the declared host
                    // capacity (legal SCSI underflow), while Data-Out and
                    // no-data phases must match exactly. A violation settles
                    // as `Fault::Contract` without calling `host.publish` and
                    // without touching the backing.
                    if plan_contract(state.ctx, plan) {
                        self.settle_contract(lu, KnownEffects::NONE);
                        return Err(Fault::Contract);
                    }
                    if let Err(fault) = host.publish(plan) {
                        // The transport rejected the plan; no data moves and no
                        // storage IO may run for this command.
                        self.settle_contract(lu, KnownEffects::NONE);
                        return Err(fault);
                    }
                    state.feedback = Feedback::plan_accepted();
                }
                PollStep::Io(StorageOp::Read {
                    resource,
                    offset,
                    buf,
                }) => {
                    let req = IoReq {
                        resource,
                        offset,
                        len: buf.len() as u32,
                        dir: Direction::ToHost,
                    };
                    let buf_offset = slice_offset(work_start, work_len, buf);
                    let settlement =
                        self.exec_io(storage, req, IoBuf::Read(buf), buf_offset, false);
                    if self.advance_io(lu, &mut state, req, settlement)? {
                        state.work_addr = work.as_ptr() as usize;
                        state.work_len = work.len();
                        self.drive_state.set(Some(state));
                        return Ok(DriveStep::Pending);
                    }
                }
                PollStep::Io(StorageOp::Write {
                    resource,
                    offset,
                    buf,
                }) => {
                    let req = IoReq {
                        resource,
                        offset,
                        len: buf.len() as u32,
                        dir: Direction::FromHost,
                    };
                    let buf_offset = slice_offset(work_start, work_len, buf);
                    let settlement =
                        self.exec_io(storage, req, IoBuf::Write(buf), buf_offset, false);
                    if self.advance_io(lu, &mut state, req, settlement)? {
                        state.work_addr = work.as_ptr() as usize;
                        state.work_len = work.len();
                        self.drive_state.set(Some(state));
                        return Ok(DriveStep::Pending);
                    }
                }
                PollStep::Io(StorageOp::Sync { resource }) => {
                    let req = IoReq {
                        resource,
                        offset: 0,
                        len: 0,
                        dir: Direction::None,
                    };
                    let settlement = self.exec_io(storage, req, IoBuf::None, Some(0), false);
                    if self.advance_io(lu, &mut state, req, settlement)? {
                        state.work_addr = work.as_ptr() as usize;
                        state.work_len = work.len();
                        self.drive_state.set(Some(state));
                        return Ok(DriveStep::Pending);
                    }
                }
                PollStep::Prefetch(PrefetchOp::Read {
                    resource,
                    offset,
                    buf,
                }) => {
                    self.prefetch_events
                        .set(self.prefetch_events.get().saturating_add(1));
                    let req = IoReq {
                        resource,
                        offset,
                        len: buf.len() as u32,
                        dir: Direction::ToHost,
                    };
                    let buf_offset = slice_offset(work_start, work_len, buf);
                    let settlement = self.exec_io(storage, req, IoBuf::Read(buf), buf_offset, true);
                    if self.advance_io(lu, &mut state, req, settlement)? {
                        state.work_addr = work.as_ptr() as usize;
                        state.work_len = work.len();
                        self.drive_state.set(Some(state));
                        return Ok(DriveStep::Pending);
                    }
                }
                PollStep::Receive(buf) => {
                    // A host data phase must match the declared direction;
                    // otherwise the plan/context contract was already broken.
                    if state.ctx.host_direction != Direction::FromHost {
                        self.settle_contract(lu, KnownEffects::NONE);
                        return Err(Fault::Contract);
                    }
                    let req = HostReq {
                        len: buf.len() as u32,
                        dir: Direction::FromHost,
                    };
                    let buf_offset = slice_offset(work_start, work_len, buf);
                    let token = host.begin_recv(req);
                    if !token.is_valid() {
                        self.settle_contract(lu, KnownEffects::NONE);
                        return Err(Fault::Contract);
                    }
                    match host.poll_host(token, HostBuf::Recv(buf)) {
                        Poll::Pending => match buf_offset {
                            Some(offset) => {
                                state.pending = Some(PendingOp::HostRecv {
                                    token,
                                    req,
                                    buf_offset: offset,
                                });
                                state.work_addr = work.as_ptr() as usize;
                                state.work_len = work.len();
                                self.drive_state.set(Some(state));
                                return Ok(DriveStep::Pending);
                            }
                            None => {
                                host.cancel(token);
                                self.settle_contract(
                                    lu,
                                    Self::known_unobserved(Direction::FromHost),
                                );
                                return Err(Fault::Contract);
                            }
                        },
                        Poll::Ready(raw) if raw.error() == Some(Fault::Contract) => {
                            self.settle_contract(lu, Self::known_unobserved(Direction::FromHost));
                            return Err(Fault::Contract);
                        }
                        Poll::Ready(raw) => {
                            let accepted = raw.accepted().min(req.len as usize);
                            let error = raw.error();
                            if error.is_some() {
                                state.host_failed = true;
                            }
                            state.feedback = Feedback::host_received(HostReceipt::new(
                                accepted, error, self.owner,
                            ));
                        }
                    }
                }
                PollStep::Send(buf) => {
                    if state.ctx.host_direction != Direction::ToHost {
                        self.settle_contract(lu, KnownEffects::NONE);
                        return Err(Fault::Contract);
                    }
                    let req = HostReq {
                        len: buf.len() as u32,
                        dir: Direction::ToHost,
                    };
                    let buf_offset = slice_offset(work_start, work_len, buf);
                    let token = host.begin_send(req);
                    if !token.is_valid() {
                        self.settle_contract(lu, KnownEffects::NONE);
                        return Err(Fault::Contract);
                    }
                    match host.poll_host(token, HostBuf::Send(buf)) {
                        Poll::Pending => match buf_offset {
                            Some(offset) => {
                                state.pending = Some(PendingOp::HostSend {
                                    token,
                                    req,
                                    buf_offset: offset,
                                });
                                state.work_addr = work.as_ptr() as usize;
                                state.work_len = work.len();
                                self.drive_state.set(Some(state));
                                return Ok(DriveStep::Pending);
                            }
                            None => {
                                host.cancel(token);
                                self.settle_contract(lu, Self::known_unobserved(Direction::ToHost));
                                return Err(Fault::Contract);
                            }
                        },
                        Poll::Ready(raw) if raw.error() == Some(Fault::Contract) => {
                            self.settle_contract(lu, Self::known_unobserved(Direction::ToHost));
                            return Err(Fault::Contract);
                        }
                        Poll::Ready(raw) => {
                            let accepted = raw.accepted().min(req.len as usize);
                            let error = raw.error();
                            if error.is_some() {
                                state.host_failed = true;
                            }
                            state.feedback =
                                Feedback::host_sent(HostReceipt::new(accepted, error, self.owner));
                        }
                    }
                }
                PollStep::Complete(completion) => {
                    // A failed host data phase means the frame was not fully
                    // delivered; an already sent status is never rolled back.
                    let delivery = if state.host_failed {
                        Delivery::Failed
                    } else {
                        host.delivery()
                    };
                    lu.finish_delivery(&permit, delivery);
                    self.note_command_finished();
                    self.drive_state.set(None);
                    return Ok(DriveStep::Done(completion));
                }
                PollStep::Idle => {
                    // The device produced neither work nor a completion. P2a
                    // keeps the model's no-progress fallback: the command is
                    // fixed as `Busy` instead of spinning.
                    lu.finish_delivery(&permit, Delivery::Pending);
                    self.note_command_finished();
                    self.drive_state.set(None);
                    return Ok(DriveStep::Done(Completion::Busy));
                }
            }
        }
    }

    /// Issue one storage operation and poll it once.
    fn exec_io(
        &self,
        storage: &mut dyn Storage,
        req: IoReq,
        buf: IoBuf<'_>,
        buf_offset: Option<usize>,
        prefetch: bool,
    ) -> IoSettlement {
        let token = storage.begin_exec(req);
        if !token.is_valid() {
            // Pool exhausted: no operation exists, so no effect and no token.
            return IoSettlement::Unissued;
        }
        if prefetch {
            self.note_speculative_io(true);
        } else {
            self.note_required_io(true);
        }
        match storage.poll_exec(token, buf) {
            Poll::Pending => match buf_offset {
                Some(offset) => IoSettlement::Pending(PendingOp::Storage {
                    token,
                    req,
                    buf_offset: offset,
                    prefetch,
                }),
                None => {
                    // The window is not addressable inside `work`, so the next
                    // step could not re-borrow it: cancel instead of retaining
                    // an unpollable token.
                    storage.cancel(token);
                    if prefetch {
                        self.cancel_speculative_io();
                    } else {
                        self.note_required_io(false);
                    }
                    IoSettlement::Ready(StorageReceipt::failed(
                        Fault::Contract,
                        0,
                        Effect::UnknownRemainder,
                    ))
                }
            },
            Poll::Ready(receipt) => {
                if prefetch {
                    self.cancel_speculative_io();
                } else {
                    self.note_required_io(false);
                }
                IoSettlement::Ready(receipt)
            }
        }
    }

    /// Fold one settlement into the step state.
    fn absorb_io(
        &mut self,
        state: &mut DriveState,
        req: IoReq,
        settlement: IoSettlement,
    ) -> IoAbsorb {
        match settlement {
            IoSettlement::Pending(pending) => {
                state.pending = Some(pending);
                IoAbsorb::Pending
            }
            IoSettlement::Unissued => IoAbsorb::Unissued,
            IoSettlement::Ready(raw) if raw.error == Some(Fault::Contract) => IoAbsorb::Contract,
            IoSettlement::Ready(raw) => {
                // A receipt-level contract violation is never mapped to SCSI
                // sense; only real facts reach the device.
                let receipt = sanitize_storage_receipt(req, raw);
                state.feedback = Feedback::io_done(IoReceipt::from_storage(receipt, self.owner));
                IoAbsorb::Retained
            }
        }
    }

    /// Apply one storage settlement; `Ok(true)` means "store the state and
    /// report `Pending`".
    fn advance_io<L: Lu + ?Sized>(
        &mut self,
        lu: &mut L,
        state: &mut DriveState,
        req: IoReq,
        settlement: IoSettlement,
    ) -> Result<bool, Fault> {
        match self.absorb_io(state, req, settlement) {
            IoAbsorb::Pending => Ok(true),
            IoAbsorb::Retained => Ok(false),
            IoAbsorb::Unissued => {
                self.settle_contract(lu, KnownEffects::NONE);
                Err(Fault::Contract)
            }
            IoAbsorb::Contract => {
                self.settle_contract(lu, Self::known_unobserved(req.dir));
                Err(Fault::Contract)
            }
        }
    }

    /// Settle the active command as a runner-side contract violation.
    ///
    /// The `InterruptReason` vocabulary has no contract variant; `Stop` is the
    /// neutral "the runner is ending this command" value, and every caller
    /// passes the facts it actually knows (never a fabricated success).
    fn settle_contract<L: Lu + ?Sized>(&mut self, lu: &mut L, known: KnownEffects) {
        let permit = self.command_permit();
        let interrupted = lu.interrupt(&permit, InterruptReason::Stop, known);
        lu.finish_delivery(&permit, Delivery::Failed);
        self.note_command_finished();
        self.drive_state.set(None);
        if let Err(fault) = interrupted {
            // A settle that cannot be proven safe ends the service (`03 §3.3`).
            self.set_fatal(fault);
        }
    }

    /// Resume a retained host phase for this step. The buffer is re-borrowed
    /// from `work`; a window that is no longer addressable is reported so the
    /// caller can cancel the token before settling.
    fn resume_host(
        &self,
        host: &mut dyn HostTransport,
        work: &mut [u8],
        token: HostToken,
        req: HostReq,
        buf_offset: usize,
        recv: bool,
    ) -> HostResume {
        let polled = match pending_host_buf(work, req, buf_offset, recv) {
            Some(buf) => host.poll_host(token, buf),
            None => return HostResume::Unaddressable,
        };
        match polled {
            Poll::Pending => HostResume::Pending,
            Poll::Ready(raw) => {
                // A short or failed phase keeps exactly the prefix the adapter
                // reported; it is never rounded up to the request.
                let accepted = raw.accepted().min(req.len as usize);
                HostResume::Retained(HostReceipt::new(accepted, raw.error(), self.owner))
            }
        }
    }

    // ── management ─────────────────────────────────────────────────────

    /// Take a detached pair exactly once. `take_gate` is the boundary (which
    /// already contains `long_settled`); it deliberately excludes ended,
    /// control-pending and await-take so a fixed result stays claimable.
    ///
    /// A successful take that clears the global handback barrier also releases
    /// the deferred force for **this** LUN (see [`Self::resume_pending_force`]);
    /// forces deferred on other LUNs are released by `Target::take_rt`, which
    /// can reach their slots.
    #[allow(dead_code)] // `Target::take_rt` (C2); driven by tests here
    pub(crate) fn take_rt<L: Lu + ?Sized>(
        &mut self,
        lun: usize,
        lu: &mut L,
    ) -> Result<ChangeResult<L::Pair>, BoundaryReject> {
        self.boundary_of(lu)?;
        let permit = self.permit();
        if !lu.accepts_permit(&permit) {
            return Err(BoundaryReject::ForeignBoundary);
        }
        let result = lu.take_rt(&permit).ok_or(BoundaryReject::NothingToTake)?;
        if self.await_take == Some(lun) {
            self.await_take = None;
            self.take_events = self.take_events.saturating_add(1);
        }
        self.resume_pending_force(lun, lu);
        Ok(result)
    }

    /// Bit for `lun` in the deferred-force mask, or `Fault::Contract` for a
    /// LUN outside the allocation-free bound.
    fn force_bit(lun: usize) -> Result<u64, Fault> {
        if lun < u64::BITS as usize {
            Ok(1u64 << lun)
        } else {
            Err(Fault::Contract)
        }
    }

    /// Whether a force is deferred for `lun`.
    pub(crate) const fn force_pending(&self, lun: usize) -> bool {
        lun < u64::BITS as usize && self.force_pending & (1u64 << lun) != 0
    }

    /// Finish a force that was deferred behind a resident result or the global
    /// handback barrier, after a `take` cleared that barrier.
    ///
    /// `take_rt` has no storage/host adapter, so this only runs a slot that is
    /// idle: no result, no command (`Lu::active()` cover the device side). An
    /// idle `force_remove_rt` is a no-op settlement, and the detach itself
    /// needs no adapter. A slot that started a new command while its force was
    /// deferred stays pending; the application must call `force_remove_*` again
    /// with the adapters so the command is settled before the detach.
    ///
    /// A failed detach (or a failure to publish the handback) ends the service
    /// with `Fatal`/`NeedsRecovery`; it is never a silent success
    /// (`03 §3.6`, delayed-force failure row). One call completes at most one
    /// LUN. The caller loops while [`Self::result_barrier`] is clear: a force
    /// that actually detached a pair publishes `await_take` and stops the
    /// sweep, while a force on an empty slot detaches nothing, so more than one
    /// such force can complete without an `await_take` in between.
    pub(crate) fn resume_pending_force<L: Lu + ?Sized>(&mut self, lun: usize, lu: &mut L) {
        let bit = match Self::force_bit(lun) {
            Ok(bit) if self.force_pending & bit != 0 => bit,
            _ => return,
        };
        // Still blocked: the result/handback must be taken first. A busy
        // device is never detached here (`Lu::active()`); its command needs the
        // adapters to settle, so the force stays armed.
        if lu.has_result()
            || lu.active()
            || self.await_take.is_some()
            || self.eject_pending.is_some()
        {
            return;
        }
        // A live command needs the adapters to cancel/settle before detaching.
        if self.drive_state.get().is_some() {
            return;
        }
        self.force_pending &= !bit;
        let permit = self.permit();
        if !lu.accepts_permit(&permit) {
            self.set_fatal(Fault::ForeignBoundary);
            return;
        }
        match lu.force_remove_rt(&permit) {
            Ok(()) if lu.has_result() => {
                if let Err(reject) = self.host_eject_succeeded(lun) {
                    let fault = match reject {
                        BoundaryReject::EjectPending => Fault::Contract,
                        _ => Fault::NeedsRecovery,
                    };
                    self.set_fatal(fault);
                }
            }
            Ok(()) => {}
            Err(fault) => self.set_fatal(fault),
        }
    }

    /// Propose a candidate change. The transaction cannot cross an ended,
    /// control-pending or result-barrier state.
    #[allow(dead_code)] // `Target::propose_rt` (C2); driven by tests here
    pub(crate) fn propose_rt<L: Lu + ?Sized>(
        &mut self,
        lu: &mut L,
        change: Change<L::Pair>,
    ) -> Result<(), (Change<L::Pair>, Fault)> {
        if self.service_gate(lu).is_err() {
            return Err((change, Fault::Boundary));
        }
        let permit = self.permit();
        if !lu.accepts_permit(&permit) {
            return Err((change, Fault::ForeignBoundary));
        }
        lu.propose_rt(&permit, change)
    }

    /// `propose → advance → take`. The commit is the device's local hook, never
    /// an injected runner `Sync`.
    #[allow(dead_code)] // `Target::advance_rt` (C2); driven by tests here
    pub(crate) fn advance_rt<L: Lu + ?Sized>(&mut self, lu: &mut L) -> Result<(), Fault> {
        self.service_gate(lu).map_err(|_| Fault::Boundary)?;
        let permit = self.permit();
        if !lu.accepts_permit(&permit) {
            return Err(Fault::ForeignBoundary);
        }
        lu.advance_rt(&permit)
    }

    /// Install an application-returned pair.
    #[allow(dead_code)] // `Target::install_rt` (C2); driven by tests here
    pub(crate) fn install_rt<L: Lu + ?Sized>(
        &mut self,
        lu: &mut L,
        pair: L::Pair,
    ) -> Result<(), (L::Pair, Fault)> {
        if self.service_gate(lu).is_err() {
            return Err((pair, Fault::Boundary));
        }
        let permit = self.permit();
        if !lu.accepts_permit(&permit) {
            return Err((pair, Fault::ForeignBoundary));
        }
        lu.install_rt(&permit, pair)
    }

    /// Emergency removal. Any pending token is cancelled first; an already
    /// resident result (or the global handback barrier) defers the force until
    /// the application takes, per LUN.
    ///
    /// **Settle target.** `drive_state` is target-global but a command belongs
    /// to exactly one slot, so only the LUN in `drive_state.ctx.lun` is
    /// settled. A force aimed at another, idle LUN detaches that LUN and leaves
    /// the running command untouched; settling the addressed slot instead would
    /// interrupt a device that owns nothing and clear a state the running LUN
    /// can no longer step (`03 §3.3` immediate-cancel, `03 §3.6` force row). A
    /// slot that still reports `Lu::active()` while `drive_state` is empty or
    /// belongs elsewhere is refused with `Fault::Contract`: detaching it would
    /// leave its command unsettled, and settling it would corrupt the owner.
    ///
    /// The deferral mask covers LUNs `0..64`; a larger LUN is rejected with
    /// `Fault::Contract` before anything is touched (allocation-free bound,
    /// see [`Self::force_bit`]). Repeating the force for an already-deferred
    /// LUN is still allowed and re-settles any command that started after the
    /// first request — but only if that LUN owns the command.
    #[allow(dead_code)] // `Target::force_remove_rt` (C2); driven by tests here
    pub(crate) fn force_remove_rt<L: Lu + ?Sized>(
        &mut self,
        lun: usize,
        lu: &mut L,
        storage: &mut dyn Storage,
        host: &mut dyn HostTransport,
    ) -> Result<(), Fault> {
        let bit = Self::force_bit(lun)?;
        // Force is one of the immediate-cancel paths (`03 §3.3`). Settle first,
        // even when an earlier force is still deferred: a command may have
        // started on this LUN while its result was resident.
        match self.drive_state.get() {
            Some(state) if state.ctx.lun == lun as u64 => {
                self.settle_abnormally(lu, storage, host, InterruptReason::Stop)?;
            }
            // Another LUN owns the live command (or there is none). A slot that
            // still has a command of its own has no state to settle from here.
            _ if lu.active() => return Err(Fault::Contract),
            _ => {}
        }
        let permit = self.permit();
        if !lu.accepts_permit(&permit) {
            return Err(Fault::ForeignBoundary);
        }
        if lu.has_result() || self.await_take.is_some() {
            // Never overwrite a resident result; finish after the take.
            self.force_pending |= bit;
            return Ok(());
        }
        // No barrier remains: this call completes any earlier deferral.
        self.force_pending &= !bit;
        lu.force_remove_rt(&permit).inspect_err(|fault| {
            self.set_fatal(*fault);
        })?;
        if lu.has_result() {
            if let Err(reject) = self.host_eject_succeeded(lun) {
                let fault = match reject {
                    BoundaryReject::EjectPending => Fault::Contract,
                    _ => Fault::NeedsRecovery,
                };
                self.set_fatal(fault);
                return Err(fault);
            }
        }
        Ok(())
    }

    /// Start a host-eject transaction (AwaitDelivery). While it is in flight
    /// `take` has nothing to hand back and new service is refused.
    pub(crate) fn begin_eject(&mut self, lun: usize) -> Result<(), BoundaryReject> {
        if self.await_take.is_some() || self.eject_pending.is_some() {
            return Err(BoundaryReject::EjectPending);
        }
        self.eject_pending = Some(lun);
        Ok(())
    }

    /// The transaction produced its result: publish the take barrier.
    pub(crate) fn finish_eject(&mut self, lun: usize) -> Result<(), BoundaryReject> {
        self.eject_pending = None;
        if self.await_take.is_some() {
            return Err(BoundaryReject::EjectPending);
        }
        self.await_take = Some(lun);
        self.eject_events = self.eject_events.saturating_add(1);
        Ok(())
    }

    /// A host-eject attempt failed before detaching the old pair (empty slot,
    /// unresolved candidate/result, or local commit). The pair is still
    /// installed, so this is a normal error — not a fatal service condition
    /// (`02-api-core §4.11`, `03 §3.6`); it must not leave a take barrier.
    pub(crate) fn eject_failed(&mut self) {
        self.eject_pending = None;
    }

    /// A host EJECT committed and detached its pair; the next `tick` reports
    /// `ResourcesReady`. Exactly one handback may be pending.
    #[allow(dead_code)] // `Target::host_eject_succeeded_*` (C2)
    pub(crate) fn host_eject_succeeded(&mut self, lun: usize) -> Result<(), BoundaryReject> {
        self.begin_eject(lun)?;
        self.finish_eject(lun)
    }

    /// Queue a control request. `Nop` still requires the caller (`Target`) to
    /// check every resident slot's boundary via `SlotSet::check_boundary`;
    /// `Abort` is accepted while a command is active and consumed as a no-op
    /// when idle.
    #[allow(dead_code)] // `Target::request_control` (C2); driven by tests here
    pub(crate) fn request_control(&mut self, control: Control) -> Result<(), BoundaryReject> {
        if self.pending_control.is_some() {
            return Err(BoundaryReject::ControlPending);
        }
        if self.terminal_outcome().is_some() {
            return Err(BoundaryReject::Ended);
        }
        match control {
            Control::Nop => {
                self.result_barrier()?;
                self.pending_control = Some(Control::Nop);
            }
            Control::Abort => {
                if self.drive_state.get().is_some() {
                    self.pending_control = Some(Control::Abort);
                } else {
                    // An idle Abort has no task; consume it immediately.
                    self.control_events = self.control_events.saturating_add(1);
                }
            }
        }
        Ok(())
    }

    /// Application control plane: close new submission and drain the active
    /// command (`Target::stop`).
    #[allow(dead_code)] // `Target::stop` (C2); driven by tests here
    pub(crate) fn request_stop(&mut self) {
        self.stop = true;
    }

    /// Transport ended (link reset/disconnect); not recoverable.
    #[allow(dead_code)] // `Target::transport_ended` (C2); driven by tests here
    pub(crate) fn transport_ended(&mut self) {
        self.transport_end = true;
    }

    /// Enter the fatal state; the next settled `tick` reports `Ended{Fatal}`.
    #[allow(dead_code)] // `Target::fatal` (C2); driven by tests here
    pub(crate) fn set_fatal(&mut self, fault: Fault) {
        // The first fault is the authoritative one; later failures must not
        // mask the root cause of an already-ended service.
        if self.fatal.is_none() {
            self.fatal = Some(fault);
        }
    }

    /// One service entry: at most one reason, never a queued event.
    ///
    /// Order (`§4.11`): fatal → transport ended → stopped → await take →
    /// pending `Nop` → `ServiceReady`. A live command is never reported as
    /// `Ended`.
    #[allow(dead_code)] // `Target::tick` (C2); driven by tests here
    pub(crate) fn tick(&mut self) -> RunOutcome {
        if let Some(outcome) = self.settled_terminal_outcome() {
            return outcome;
        }
        if let Some(lun) = self.await_take {
            return RunOutcome::ResourcesReady { lun };
        }
        match self.pending_control {
            Some(Control::Nop) => {
                self.pending_control = None;
                self.control_events = self.control_events.saturating_add(1);
                RunOutcome::ControlApplied(Control::Nop)
            }
            // `Abort` is applied by `step_command`, not by `tick`.
            Some(Control::Abort) => RunOutcome::ServiceReady,
            None => RunOutcome::ServiceReady,
        }
    }

    /// Advance a resident long operation by exactly one entry.
    #[allow(dead_code)] // `Target::poll_long_entry_*` (C2)
    pub(crate) fn poll_long_entry<L: Lu + ?Sized>(
        &mut self,
        lu: &mut L,
        storage: &mut dyn Storage,
        data: &mut [u8],
    ) -> Result<LongInfo, Fault> {
        self.poll_long_gate(lu).map_err(|_| Fault::Boundary)?;
        let feedback = self.long_feedback.take().unwrap_or_else(Feedback::begin);
        let permit = self.command_permit();
        let step = lu.poll_long(&permit, feedback, data);
        match step {
            PollStep::Io(op) => {
                let receipt = exec_storage(storage, op);
                if receipt.error == Some(Fault::Contract) {
                    return Err(Fault::Contract);
                }
                self.long_feedback = Some(Feedback::io_done(IoReceipt::from_storage(
                    receipt, self.owner,
                )));
            }
            PollStep::Prefetch(PrefetchOp::Read {
                resource,
                offset,
                buf,
            }) => {
                // Speculative reads never change the long-operation outcome; a
                // failure is reported to the device, which falls back to `Io`.
                let receipt = exec_storage(
                    storage,
                    StorageOp::Read {
                        resource,
                        offset,
                        buf,
                    },
                );
                if receipt.error == Some(Fault::Contract) {
                    return Err(Fault::Contract);
                }
                self.long_feedback = Some(Feedback::io_done(IoReceipt::from_storage(
                    receipt, self.owner,
                )));
            }
            PollStep::Complete(_) => {
                self.long_feedback = None;
            }
            PollStep::Idle => {}
            PollStep::Publish(_) | PollStep::Receive(_) | PollStep::Send(_) => {
                return Err(Fault::Contract)
            }
        }
        Ok(lu.long_info())
    }
}

/// Outcome of resuming a retained host phase.
enum HostResume {
    /// Still pending; keep the token.
    Pending,
    /// Ready receipt, clamped to the request.
    Retained(HostReceipt),
    /// The retained window is no longer addressable inside `work`.
    Unaddressable,
}

/// The host-data contract: the direction must match; a Data-In response may be
/// shorter than the declared host capacity, while Data-Out and no-data must
/// match exactly (`02-api.md §4.3`, A1).
fn plan_contract(ctx: CommandContext, plan: DataPlan) -> bool {
    if plan.direction != ctx.host_direction {
        return true;
    }
    match plan.direction {
        // Data-In: `ctx.host_bytes` is the host's declared receive capacity,
        // so a shorter natural response is legal SCSI (`05 §5.1`). Underflow is
        // accounted by the host receipt, never by fabricating bytes.
        Direction::ToHost => plan.bytes > ctx.host_bytes,
        // Data-Out and no-data phases must match exactly: the device may not
        // write less/more than the host declared.
        Direction::FromHost | Direction::None => plan.bytes != ctx.host_bytes,
    }
}

/// Offset of `buf` inside the caller's `work` bank, when it is contained.
fn slice_offset(work_start: usize, work_len: usize, buf: &[u8]) -> Option<usize> {
    let start = buf.as_ptr() as usize;
    let end = start.checked_add(buf.len())?;
    let work_end = work_start.checked_add(work_len)?;
    if start >= work_start && end <= work_end {
        Some(start - work_start)
    } else {
        None
    }
}

/// Rebuild the storage buffer from metadata; `None` means the retained window
/// is no longer addressable in `work`.
fn pending_io_buf<'a>(work: &'a mut [u8], req: IoReq, offset: usize) -> Option<IoBuf<'a>> {
    let len = req.len as usize;
    let end = offset.checked_add(len)?;
    match req.dir {
        Direction::None => {
            if len == 0 {
                Some(IoBuf::None)
            } else {
                None
            }
        }
        Direction::ToHost => work.get_mut(offset..end).map(IoBuf::Read),
        Direction::FromHost => work.get(offset..end).map(IoBuf::Write),
    }
}

/// Rebuild the host buffer from metadata.
fn pending_host_buf<'a>(
    work: &'a mut [u8],
    req: HostReq,
    offset: usize,
    recv: bool,
) -> Option<HostBuf<'a>> {
    let end = offset.checked_add(req.len as usize)?;
    if recv {
        work.get_mut(offset..end).map(HostBuf::Recv)
    } else {
        work.get(offset..end).map(HostBuf::Send)
    }
}

/// Sanitize an adapter receipt against the request it answers (`03 §3.4`).
///
/// `Ready(n > requested)` cannot be trusted: the previously confirmed prefix is
/// kept (nothing new is accepted) and the remainder is recorded as unknown. A
/// short/failed operation keeps its trustworthy prefix.
fn sanitize_storage_receipt(req: IoReq, receipt: StorageReceipt) -> StorageReceipt {
    if receipt.confirmed > req.len as usize {
        return StorageReceipt {
            confirmed: 0,
            error: receipt.error,
            effect: Effect::UnknownRemainder,
        };
    }
    receipt
}

/// Busy-execute one storage operation for the long-operation entry.
///
/// Core has no executor or waker, so a long-operation entry completes its
/// single operation synchronously; an invalid token or a contract receipt is
/// returned instead of spinning.
fn exec_storage(storage: &mut dyn Storage, op: StorageOp<'_>) -> StorageReceipt {
    match op {
        StorageOp::Read {
            resource,
            offset,
            buf,
        } => {
            let req = IoReq {
                resource,
                offset,
                len: buf.len() as u32,
                dir: Direction::ToHost,
            };
            let token = storage.begin_exec(req);
            if !token.is_valid() {
                return StorageReceipt::failed(Fault::Contract, 0, Effect::Known);
            }
            loop {
                match storage.poll_exec(token, IoBuf::Read(&mut *buf)) {
                    Poll::Pending => {}
                    Poll::Ready(receipt) => return sanitize_storage_receipt(req, receipt),
                }
            }
        }
        StorageOp::Write {
            resource,
            offset,
            buf,
        } => {
            let req = IoReq {
                resource,
                offset,
                len: buf.len() as u32,
                dir: Direction::FromHost,
            };
            let token = storage.begin_exec(req);
            if !token.is_valid() {
                return StorageReceipt::failed(Fault::Contract, 0, Effect::Known);
            }
            loop {
                match storage.poll_exec(token, IoBuf::Write(buf)) {
                    Poll::Pending => {}
                    Poll::Ready(receipt) => return sanitize_storage_receipt(req, receipt),
                }
            }
        }
        StorageOp::Sync { resource } => {
            let req = IoReq {
                resource,
                offset: 0,
                len: 0,
                dir: Direction::None,
            };
            let token = storage.begin_exec(req);
            if !token.is_valid() {
                return StorageReceipt::failed(Fault::Contract, 0, Effect::Known);
            }
            loop {
                match storage.poll_exec(token, IoBuf::None) {
                    Poll::Pending => {}
                    Poll::Ready(receipt) => return sanitize_storage_receipt(req, receipt),
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::core::device::{Device, NoMedium, Pair};
    use crate::core::lu::LuImpl;
    use crate::core::storage::{BlockingHost, BlockingStorage, SyncHost, SyncStorage};

    const SCRIPT_LEN: usize = 8;
    const BANK: usize = 1024;

    /// One scripted device step.
    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    #[allow(dead_code)] // Send/Receive stay in the double's vocabulary
    enum Script {
        Publish(DataPlan),
        Read { len: usize },
        Write { len: usize },
        Sync,
        Send { len: usize },
        Receive { len: usize },
        Complete(Completion),
    }

    /// Device double: replays a fixed script and records the runner's calls.
    struct ScriptDevice {
        script: [Option<Script>; SCRIPT_LEN],
        cursor: usize,
        active: bool,
        long: LongInfo,
        interrupts: u32,
        last_reason: Option<InterruptReason>,
        last_known: KnownEffects,
        last_io: Option<IoReceipt>,
        deliveries: u32,
        last_delivery: Option<Delivery>,
        commits: u32,
        medium: Option<NoMedium>,
    }

    impl ScriptDevice {
        fn new(script: [Option<Script>; SCRIPT_LEN]) -> Self {
            Self {
                script,
                cursor: 0,
                active: false,
                long: LongInfo::IDLE,
                interrupts: 0,
                last_reason: None,
                last_known: KnownEffects::NONE,
                last_io: None,
                deliveries: 0,
                last_delivery: None,
                commits: 0,
                medium: Some(NoMedium),
            }
        }
    }

    impl Device for ScriptDevice {
        type Medium = NoMedium;

        fn prepare(
            &mut self,
            _permit: &CommandPermit,
            _ctx: CommandContext,
            _cdb: &[u8],
        ) -> Result<(), Completion> {
            self.active = true;
            self.cursor = 0;
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
            feedback: Feedback,
            data: &'a mut [u8],
        ) -> PollStep<'a> {
            if let Some(io) = feedback.io() {
                self.last_io = Some(io);
            }
            let step = match self.script.get(self.cursor).copied().flatten() {
                Some(step) => step,
                None => return PollStep::Idle,
            };
            self.cursor += 1;
            match step {
                Script::Publish(plan) => PollStep::Publish(plan),
                Script::Read { len } => PollStep::Io(StorageOp::Read {
                    resource: 1,
                    offset: 0,
                    buf: &mut data[..len],
                }),
                Script::Write { len } => PollStep::Io(StorageOp::Write {
                    resource: 1,
                    offset: 0,
                    buf: &data[..len],
                }),
                Script::Sync => PollStep::Io(StorageOp::Sync { resource: 1 }),
                Script::Send { len } => PollStep::Send(&data[..len]),
                Script::Receive { len } => PollStep::Receive(&mut data[..len]),
                Script::Complete(completion) => {
                    self.active = false;
                    PollStep::Complete(completion)
                }
            }
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
            reason: InterruptReason,
            known: KnownEffects,
        ) -> Result<(), Fault> {
            self.interrupts = self.interrupts.saturating_add(1);
            self.last_reason = Some(reason);
            self.last_known = known;
            self.active = false;
            Ok(())
        }

        fn finish_delivery(&mut self, _permit: &CommandPermit, delivery: Delivery) {
            self.deliveries = self.deliveries.saturating_add(1);
            self.last_delivery = Some(delivery);
        }

        fn commit(&mut self, _permit: &BoundaryPermit) -> Result<(), Completion> {
            self.commits = self.commits.saturating_add(1);
            Ok(())
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

    /// Synchronous execution recorder behind [`BlockingStorage`].
    #[derive(Default)]
    struct Recorder {
        execs: usize,
        reads: usize,
        writes: usize,
        syncs: usize,
    }

    impl SyncStorage for Recorder {
        fn exec(&mut self, req: IoReq, buf: IoBuf<'_>) -> StorageReceipt {
            self.execs += 1;
            match buf {
                IoBuf::None => self.syncs += 1,
                IoBuf::Read(_) => self.reads += 1,
                IoBuf::Write(_) => self.writes += 1,
            }
            // Full success for whatever was requested.
            StorageReceipt::ok(req.len as usize)
        }
    }

    /// Storage double: mints real tokens through the blocking adapter, but can
    /// answer `Pending` first and records the buffer variant it was handed.
    struct HoldStorage {
        inner: BlockingStorage<Recorder>,
        pending_polls: usize,
        begins: usize,
        cancels: usize,
        buf_tags: [u8; 8],
        buf_count: usize,
    }

    impl HoldStorage {
        fn new(pending_polls: usize) -> Self {
            Self {
                inner: BlockingStorage::new(Recorder::default()),
                pending_polls,
                begins: 0,
                cancels: 0,
                buf_tags: [0u8; 8],
                buf_count: 0,
            }
        }

        fn recorder(&self) -> &Recorder {
            self.inner.inner()
        }

        fn tags(&self) -> &[u8] {
            &self.buf_tags[..self.buf_count]
        }
    }

    impl Storage for HoldStorage {
        fn begin_exec(&mut self, req: IoReq) -> IoToken {
            self.begins += 1;
            self.inner.begin_exec(req)
        }

        fn poll_exec(&mut self, token: IoToken, buf: IoBuf<'_>) -> Poll<StorageReceipt> {
            if self.buf_count < self.buf_tags.len() {
                self.buf_tags[self.buf_count] = match &buf {
                    IoBuf::None => 0,
                    IoBuf::Read(_) => 1,
                    IoBuf::Write(_) => 2,
                };
                self.buf_count += 1;
            }
            if self.pending_polls > 0 {
                self.pending_polls -= 1;
                return Poll::Pending;
            }
            self.inner.poll_exec(token, buf)
        }

        fn cancel(&mut self, token: IoToken) {
            self.cancels += 1;
            self.inner.cancel(token);
        }
    }

    /// Host recorder behind [`BlockingHost`].
    struct HostRec {
        publishes: usize,
        plans: [Option<DataPlan>; 4],
        recvs: usize,
        sends: usize,
    }

    impl HostRec {
        fn new() -> Self {
            Self {
                publishes: 0,
                plans: [None; 4],
                recvs: 0,
                sends: 0,
            }
        }
    }

    impl SyncHost for HostRec {
        fn publish(&mut self, plan: DataPlan) -> Result<(), Fault> {
            if self.publishes < self.plans.len() {
                self.plans[self.publishes] = Some(plan);
            }
            self.publishes += 1;
            Ok(())
        }

        fn receive(&mut self, req: HostReq, _buf: HostBuf<'_>) -> HostReceipt {
            self.recvs += 1;
            HostReceipt::new(req.len as usize, None, TargetId::UNBOUND)
        }

        fn send(&mut self, req: HostReq, _buf: HostBuf<'_>) -> HostReceipt {
            self.sends += 1;
            HostReceipt::new(req.len as usize, None, TargetId::UNBOUND)
        }

        fn delivery(&self) -> Delivery {
            Delivery::Complete
        }
    }

    struct HoldHost {
        inner: BlockingHost<HostRec>,
        pending_polls: usize,
        cancels: usize,
    }

    impl HoldHost {
        fn new() -> Self {
            Self {
                inner: BlockingHost::new(HostRec::new()),
                pending_polls: 0,
                cancels: 0,
            }
        }

        fn recorder(&self) -> &HostRec {
            self.inner.inner()
        }
    }

    impl HostTransport for HoldHost {
        fn publish(&mut self, plan: DataPlan) -> Result<(), Fault> {
            self.inner.publish(plan)
        }

        fn begin_recv(&mut self, req: HostReq) -> HostToken {
            self.inner.begin_recv(req)
        }

        fn begin_send(&mut self, req: HostReq) -> HostToken {
            self.inner.begin_send(req)
        }

        fn poll_host(&mut self, token: HostToken, buf: HostBuf<'_>) -> Poll<HostReceipt> {
            if self.pending_polls > 0 {
                self.pending_polls -= 1;
                return Poll::Pending;
            }
            self.inner.poll_host(token, buf)
        }

        fn cancel(&mut self, token: HostToken) {
            self.cancels += 1;
            self.inner.cancel(token);
        }

        fn delivery(&self) -> Delivery {
            self.inner.delivery()
        }
    }

    /// One slot + runner + adapters + the two service banks.
    struct Bench {
        slot: LuImpl<ScriptDevice, u8>,
        runner: Runner,
        storage: HoldStorage,
        host: HoldHost,
        work: [u8; BANK],
        scratch: [u8; BANK],
    }

    impl Bench {
        fn new(script: [Option<Script>; SCRIPT_LEN], pending_polls: usize) -> Self {
            Self {
                slot: LuImpl::new(ScriptDevice::new(script), 7u8),
                runner: Runner::new(),
                storage: HoldStorage::new(pending_polls),
                host: HoldHost::new(),
                work: [0u8; BANK],
                scratch: [0u8; BANK],
            }
        }

        fn start(&mut self, ctx: CommandContext) -> Result<(), Fault> {
            self.runner.start_command(&mut self.slot, ctx, &[0x2A])
        }

        fn step(&mut self) -> Result<DriveStep, Fault> {
            self.runner.step_command(
                &mut self.slot,
                &mut self.storage,
                &mut self.host,
                &mut self.work,
                &mut self.scratch,
            )
        }
    }

    fn ctx(direction: Direction, bytes: u64) -> CommandContext {
        CommandContext {
            lun: 0,
            lun_count: 1,
            host_bytes: bytes,
            host_direction: direction,
        }
    }

    fn write_script(bytes: usize) -> [Option<Script>; SCRIPT_LEN] {
        [
            Some(Script::Publish(DataPlan {
                direction: Direction::FromHost,
                bytes: bytes as u64,
            })),
            Some(Script::Write { len: bytes }),
            Some(Script::Complete(Completion::Good)),
            None,
            None,
            None,
            None,
            None,
        ]
    }

    #[test]
    fn publish_must_match_the_declared_host_bytes_exactly() {
        // ctx bytes / plan bytes: legacy "0 vs non-0" plans must now be rejected.
        for (ctx_bytes, plan_bytes) in [(512u64, 1024u64), (0u64, 512u64)] {
            let script = [
                Some(Script::Publish(DataPlan {
                    direction: Direction::FromHost,
                    bytes: plan_bytes,
                })),
                Some(Script::Write { len: 512 }),
                Some(Script::Complete(Completion::Good)),
                None,
                None,
                None,
                None,
                None,
            ];
            let mut bench = Bench::new(script, 0);
            bench
                .start(ctx(Direction::FromHost, ctx_bytes))
                .expect("start");
            assert_eq!(
                bench.step(),
                Err(Fault::Contract),
                "ctx={ctx_bytes} plan={plan_bytes} must violate the exact contract"
            );
            assert_eq!(
                bench.host.recorder().publishes,
                0,
                "host.publish must not run for a rejected plan"
            );
            assert_eq!(bench.storage.begins, 0, "no storage token may be issued");
            assert_eq!(bench.storage.recorder().execs, 0, "backing untouched");
            assert_eq!(bench.slot.device_ref().commits, 0);
            assert_eq!(
                bench.slot.device_ref().interrupts,
                1,
                "the command is settled once"
            );
            assert_eq!(
                bench.slot.device_ref().last_delivery,
                Some(Delivery::Failed),
                "a contract settle never claims delivery"
            );
        }
    }

    #[test]
    fn published_data_in_underflow_is_legal() {
        // A Data-In response shorter than the host's declared capacity is a
        // legal short read (SCSI); the plan contract must not reject it.
        let script = [
            Some(Script::Publish(DataPlan {
                direction: Direction::ToHost,
                bytes: 36,
            })),
            Some(Script::Read { len: 36 }),
            Some(Script::Send { len: 36 }),
            Some(Script::Complete(Completion::Good)),
            None,
            None,
            None,
            None,
        ];
        let mut bench = Bench::new(script, 0);
        bench.start(ctx(Direction::ToHost, 96)).expect("start");
        assert_eq!(bench.step(), Ok(DriveStep::Done(Completion::Good)));
        assert_eq!(bench.host.recorder().publishes, 1);
        assert_eq!(
            bench.host.recorder().plans[0],
            Some(DataPlan {
                direction: Direction::ToHost,
                bytes: 36
            })
        );
        assert_eq!(
            bench.host.recorder().sends,
            1,
            "the natural 36 bytes are sent"
        );
    }

    #[test]
    fn published_data_in_overrun_is_contract() {
        // The host declared 96 bytes but the device plans 128: an over-run is
        // not a short read and must be rejected before host.publish.
        let script = [
            Some(Script::Publish(DataPlan {
                direction: Direction::ToHost,
                bytes: 128,
            })),
            Some(Script::Read { len: 128 }),
            Some(Script::Complete(Completion::Good)),
            None,
            None,
            None,
            None,
            None,
        ];
        let mut bench = Bench::new(script, 0);
        bench.start(ctx(Direction::ToHost, 96)).expect("start");
        assert_eq!(bench.step(), Err(Fault::Contract));
        assert_eq!(bench.host.recorder().publishes, 0);
        assert_eq!(bench.storage.begins, 0);
        assert_eq!(bench.storage.recorder().execs, 0);
        assert_eq!(bench.slot.device_ref().interrupts, 1);
    }

    #[test]
    fn pending_storage_operation_is_retained_across_calls() {
        let mut bench = Bench::new(write_script(512), 1);
        bench.start(ctx(Direction::FromHost, 512)).expect("start");

        assert_eq!(bench.step(), Ok(DriveStep::Pending));
        assert_eq!(bench.storage.begins, 1);
        assert_eq!(
            bench.storage.recorder().execs,
            0,
            "the adapter has not executed yet"
        );

        assert_eq!(bench.step(), Ok(DriveStep::Done(Completion::Good)));
        assert_eq!(bench.storage.begins, 1, "the same token is resumed");
        assert_eq!(bench.storage.recorder().execs, 1);
        assert_eq!(bench.storage.recorder().writes, 1);
        assert_eq!(bench.storage.cancels, 0);
        let io = bench
            .slot
            .device_ref()
            .last_io
            .expect("device saw the receipt");
        assert_eq!(io.confirmed(), 512);
        assert_eq!(bench.slot.device_ref().deliveries, 1);
        assert_eq!(
            bench.host.recorder().plans[0],
            Some(DataPlan {
                direction: Direction::FromHost,
                bytes: 512,
            }),
            "the published plan keeps the declared numbers"
        );
        assert_eq!(
            bench.slot.device_ref().last_delivery,
            Some(Delivery::Complete)
        );
        assert!(bench.runner.terminal_outcome().is_none());
    }

    #[test]
    fn stop_drains_the_pending_write_instead_of_cancelling() {
        let mut bench = Bench::new(write_script(512), 1);
        bench.start(ctx(Direction::FromHost, 512)).expect("start");
        assert_eq!(bench.step(), Ok(DriveStep::Pending));

        bench.runner.request_stop();
        // A live command must not be reported as ended while it still drains.
        assert_eq!(bench.runner.tick(), RunOutcome::ServiceReady);

        assert_eq!(
            bench.step(),
            Ok(DriveStep::Control(RunOutcome::Ended {
                reason: RunEnd::Stopped,
                error: None,
            }))
        );
        assert_eq!(bench.storage.cancels, 0, "Stop drains, it never cancels");
        let device = bench.slot.device_ref();
        assert_eq!(device.last_reason, Some(InterruptReason::Stop));
        assert_eq!(device.last_known.confirmed_write, 512);
        assert!(!device.last_known.unknown_remainder);
        assert_eq!(device.last_delivery, Some(Delivery::Failed));
        assert_eq!(
            bench.runner.tick(),
            RunOutcome::Ended {
                reason: RunEnd::Stopped,
                error: None,
            }
        );
    }

    #[test]
    fn transport_end_and_abort_cancel_immediately() {
        let mut bench = Bench::new(write_script(512), 1);
        bench.start(ctx(Direction::FromHost, 512)).expect("start");
        assert_eq!(bench.step(), Ok(DriveStep::Pending));
        bench.runner.transport_ended();
        assert_eq!(bench.runner.tick(), RunOutcome::ServiceReady);
        assert_eq!(
            bench.step(),
            Ok(DriveStep::Control(RunOutcome::Ended {
                reason: RunEnd::TransportEnded,
                error: None,
            }))
        );
        assert_eq!(bench.storage.cancels, 1, "transport end cancels");
        let device = bench.slot.device_ref();
        assert!(device.last_known.unknown_remainder);
        assert_eq!(device.last_delivery, Some(Delivery::Failed));
        assert_eq!(
            bench.runner.tick(),
            RunOutcome::Ended {
                reason: RunEnd::TransportEnded,
                error: None,
            }
        );

        let mut bench = Bench::new(write_script(512), 1);
        bench.start(ctx(Direction::FromHost, 512)).expect("start");
        assert_eq!(bench.step(), Ok(DriveStep::Pending));
        bench
            .runner
            .request_control(Control::Abort)
            .expect("abort is accepted while a command is active");
        assert_eq!(
            bench.step(),
            Ok(DriveStep::Done(Completion::Check(ABORTED_COMMAND)))
        );
        assert_eq!(
            Completion::Check(ABORTED_COMMAND),
            Completion::Check(crate::core::errors::Sense::new(0x0B, 0x45, 0x00))
        );
        assert_eq!(bench.storage.cancels, 1, "abort cancels the pending token");
        let device = bench.slot.device_ref();
        assert!(device.last_known.unknown_remainder);
        assert_eq!(device.last_delivery, Some(Delivery::Failed));
        // Abort ends the command only; the target keeps serving.
        assert_eq!(bench.runner.tick(), RunOutcome::ServiceReady);
    }

    #[test]
    fn io_directions_map_to_the_matching_storage_buffers() {
        let script = [
            Some(Script::Publish(DataPlan {
                direction: Direction::ToHost,
                bytes: 512,
            })),
            Some(Script::Read { len: 512 }),
            Some(Script::Sync),
            Some(Script::Complete(Completion::Good)),
            None,
            None,
            None,
            None,
        ];
        let mut bench = Bench::new(script, 0);
        bench.start(ctx(Direction::ToHost, 512)).expect("start");
        assert_eq!(bench.step(), Ok(DriveStep::Done(Completion::Good)));
        assert_eq!(
            bench.storage.tags(),
            &[1u8, 0u8][..],
            "ToHost => IoBuf::Read, Sync => IoBuf::None"
        );
        assert_eq!(bench.storage.recorder().reads, 1);
        assert_eq!(bench.storage.recorder().syncs, 1);
    }

    #[test]
    fn host_write_direction_maps_to_a_write_buffer() {
        let mut bench = Bench::new(write_script(512), 0);
        bench.start(ctx(Direction::FromHost, 512)).expect("start");
        assert_eq!(bench.step(), Ok(DriveStep::Done(Completion::Good)));
        assert_eq!(bench.storage.tags(), &[2u8][..], "FromHost => IoBuf::Write");
        assert_eq!(bench.storage.recorder().writes, 1);
        assert_eq!(bench.host.recorder().recvs, 0);
        assert_eq!(bench.host.recorder().sends, 0);
        assert_eq!(bench.host.cancels, 0);
    }

    #[test]
    fn boundary_counts_the_execution_borrow_and_retained_input() {
        let bench = Bench::new([None; SCRIPT_LEN], 0);
        assert_eq!(bench.runner.boundary(&bench.slot), Ok(()));
        let guard = bench.runner.enter_execution_borrow();
        assert_eq!(
            bench.runner.boundary(&bench.slot),
            Err(BoundaryReject::ExecutionBorrowAlive)
        );
        drop(guard);
        bench.runner.hold_retained_input(4);
        assert_eq!(
            bench.runner.boundary(&bench.slot),
            Err(BoundaryReject::RetainedInput)
        );
        bench.runner.clear_retained_input();
        assert_eq!(bench.runner.boundary(&bench.slot), Ok(()));
    }

    #[test]
    fn management_entries_respect_the_service_gate() {
        let mut bench = Bench::new(write_script(512), 1);
        bench.start(ctx(Direction::FromHost, 512)).expect("start");
        assert_eq!(bench.step(), Ok(DriveStep::Pending));

        assert_eq!(
            bench.runner.propose_rt(&mut bench.slot, Change::Remove),
            Err((Change::Remove, Fault::Boundary)),
            "a live command blocks a proposal"
        );
        assert_eq!(
            bench.runner.take_rt(0, &mut bench.slot),
            Err(BoundaryReject::CommandActive)
        );

        assert_eq!(bench.step(), Ok(DriveStep::Done(Completion::Good)));
        assert_eq!(
            bench.runner.propose_rt(&mut bench.slot, Change::Remove),
            Ok(())
        );
        assert!(bench.slot.has_candidate());
    }

    #[test]
    fn a_resident_result_blocks_new_management_until_taken() {
        let mut bench = Bench::new([None; SCRIPT_LEN], 0);
        let permit = BoundaryPermit::new(TargetId::UNBOUND);
        bench.slot.force_remove_rt(&permit).expect("force detaches");
        assert!(bench.slot.has_result());

        // A produced result is `awaiting_resource_take`: no new transaction may
        // start before it is claimed (`§4.11` service_gate, `§3.6` AwaitTake).
        assert_eq!(
            bench.runner.service_gate(&bench.slot),
            Err(BoundaryReject::AwaitingResourceTake)
        );
        assert_eq!(
            bench.runner.propose_rt(&mut bench.slot, Change::Remove),
            Err((Change::Remove, Fault::Boundary))
        );
        let pair = Pair {
            medium: NoMedium,
            backing: 4,
        };
        assert_eq!(
            bench.runner.install_rt(&mut bench.slot, pair),
            Err((
                Pair {
                    medium: NoMedium,
                    backing: 4,
                },
                Fault::Boundary
            ))
        );
        assert_eq!(
            bench.runner.advance_rt(&mut bench.slot),
            Err(Fault::Boundary)
        );

        // `take` is the one entry allowed through, and it clears the barrier.
        assert!(bench.runner.take_rt(0, &mut bench.slot).is_ok());
        assert!(!bench.slot.has_result());
        assert_eq!(bench.runner.service_gate(&bench.slot), Ok(()));
    }

    #[test]
    fn host_eject_handback_blocks_service_until_taken() {
        let mut bench = Bench::new([None; SCRIPT_LEN], 0);
        bench.runner.host_eject_succeeded(2).expect("handback");
        assert_eq!(bench.runner.tick(), RunOutcome::ResourcesReady { lun: 2 });
        assert_eq!(
            bench.runner.result_barrier(),
            Err(BoundaryReject::AwaitingResourceTake)
        );
        assert_eq!(
            bench.runner.host_eject_succeeded(3),
            Err(BoundaryReject::EjectPending),
            "a second handback is explicit backpressure"
        );

        // The force path detaches the pair; the take clears the barrier.
        let permit = BoundaryPermit::new(TargetId::UNBOUND);
        bench.slot.force_remove_rt(&permit).expect("force detaches");
        let result = bench.runner.take_rt(2, &mut bench.slot).expect("take");
        assert!(result.pair.is_some());
        assert_eq!(bench.runner.tick(), RunOutcome::ServiceReady);
        assert_eq!(bench.runner.result_barrier(), Ok(()));
    }

    #[test]
    fn long_entry_projects_the_device_state() {
        let mut bench = Bench::new([None; SCRIPT_LEN], 0);
        let mut bank = [0u8; 64];
        let info = bench
            .runner
            .poll_long_entry(&mut bench.slot, &mut bench.storage, &mut bank)
            .expect("long entry");
        assert_eq!(info, LongInfo::IDLE);

        bench.runner.request_stop();
        assert_eq!(
            bench
                .runner
                .poll_long_entry(&mut bench.slot, &mut bench.storage, &mut bank),
            Err(Fault::Boundary)
        );
    }

    #[test]
    fn fatal_tick_reports_the_fault_once_settled() {
        let mut bench = Bench::new([None; SCRIPT_LEN], 0);
        bench.runner.set_fatal(Fault::NeedsRecovery);
        assert_eq!(
            bench.runner.tick(),
            RunOutcome::Ended {
                reason: RunEnd::Fatal,
                error: Some(Fault::NeedsRecovery),
            }
        );
    }

    #[test]
    fn pending_command_requires_the_same_work_bank() {
        let mut bench = Bench::new(write_script(512), 1);
        bench.start(ctx(Direction::FromHost, 512)).expect("start");
        assert_eq!(bench.step(), Ok(DriveStep::Pending));
        let mut other = [0u8; BANK];
        let err = bench.runner.step_command(
            &mut bench.slot,
            &mut bench.storage,
            &mut bench.host,
            &mut other,
            &mut bench.scratch,
        );
        assert_eq!(err, Err(Fault::Contract));
        assert_eq!(bench.storage.cancels, 1);
    }

    #[test]
    fn eject_pending_is_separate_from_awaiting_take() {
        let mut bench = Bench::new([None; SCRIPT_LEN], 0);
        bench.runner.begin_eject(0).expect("begin eject");
        // AwaitDelivery: no result yet, so take has nothing and service is
        // refused, but there is no take barrier.
        assert_eq!(bench.runner.result_barrier(), Ok(()));
        assert_eq!(
            bench.runner.take_rt(0, &mut bench.slot),
            Err(BoundaryReject::NothingToTake)
        );
        assert!(bench.runner.service_gate(&bench.slot).is_err());
        bench.runner.finish_eject(0).expect("finish eject");
        // AwaitTake: the result barrier is now explicit.
        assert_eq!(
            bench.runner.result_barrier(),
            Err(BoundaryReject::AwaitingResourceTake)
        );
        assert_eq!(bench.runner.tick(), RunOutcome::ResourcesReady { lun: 0 });
    }
}
