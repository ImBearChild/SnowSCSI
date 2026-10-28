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
//!   step. A resident long operation may additionally retain **one** adapter
//!   token across entries, re-borrowed from the caller's `data` bank;
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

/// One retained adapter operation of the resident long operation.
///
/// Same metadata-only shape as [`PendingOp::Storage`] and the same buffer rule:
/// the window is re-borrowed from the caller's `data` bank on every entry, so
/// `buf_offset` is relative to that bank. At most one exists per Target
/// (one resident long operation), keyed to its LUN.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct LongPending {
    token: IoToken,
    req: IoReq,
    buf_offset: usize,
    prefetch: bool,
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
    ///
    /// The receipt was **returned**, so its own facts (confirmed prefix,
    /// [`Effect`]) are carried instead of an unreported-cancel guess
    /// (`03 §3.3` "receipt 已返回").
    Contract(KnownEffects),
}

/// Outcome of issuing one long-operation storage request (`Io`/`Prefetch`).
enum LongIo {
    /// The adapter answered `Pending`; the token is retained keyed to the LUN.
    Pending,
    /// The adapter answered `Ready`; the receipt is already sanitized.
    Ready(StorageReceipt),
    /// The adapter pool is exhausted; no operation was issued.
    Unissued,
    /// The adapter answered `Pending` for a window that cannot be re-borrowed
    /// from the caller's bank; the token was cancelled and the operation's end
    /// was never observed (write/sync remainder unknown).
    Unaddressable(Direction),
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
    /// Pending long-operation receipt, keyed to the LUN that owns it.
    ///
    /// A Target runs at most one resident long operation at a time
    /// (`02-api-core.md:350`, `03 §3.7`): a fixed per-LUN array is not
    /// possible without allocation, so the runner serializes long entries on
    /// the owning LUN. A different LUN's entry fails closed with
    /// `Fault::Boundary` without consuming this receipt.
    long_feedback: Option<(usize, Feedback)>,
    /// Retained adapter token of the resident long operation, keyed to its LUN.
    ///
    /// One adapter poll per entry: the token is polled at most once, `Pending`
    /// returns the unchanged projection, `Ready` turns into `long_feedback`
    /// (the device consumes it on the next entry). Never re-borrowed from a
    /// different bank than the one it was issued against.
    long_pending: Option<(usize, LongPending)>,
    /// Data-bank identity captured when `long_pending` was stored: the caller
    /// must pass the same bank (address and length) while the token is live.
    /// Same rule as [`DriveState::work_addr`]/[`DriveState::work_len`].
    long_data_addr: usize,
    long_data_len: usize,
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
    /// LUNs whose resident long operation was cancelled by a force while its
    /// phase stayed `Foreground`/`Background`.
    ///
    /// The device is not restarted by a force (only a detach discards it), so
    /// `long_settled` would otherwise reject the `take` that must deliver the
    /// R-C effects and the deferred force that must detach the pair. This
    /// runner-side latch is the only bypass: it lets a take cross **only** the
    /// long-phase check for that LUN, never a live token, a command, retained
    /// input, an unconsumed completion or a result barrier. Same allocation-free
    /// 64-LUN bound as [`Self::force_pending`] (`force_bit` → `Fault::Contract`
    /// above it).
    force_long_cancelled: u64,
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
    #[allow(dead_code)] // wired by `Target::new` and driven by tests here
    pub(crate) fn new() -> Self {
        Self::for_target(TargetId::UNBOUND)
    }

    /// Runner owned by `owner`; permits minted here only match that owner.
    #[allow(dead_code)] // `Target` constructs its runner with its identity
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
            long_pending: None,
            long_data_addr: 0,
            long_data_len: 0,
            drive_state: Cell::new(None),
            force_pending: 0,
            force_long_cancelled: 0,
            control_events: 0,
            take_events: 0,
            eject_events: 0,
            prefetch_events: Cell::new(0),
        }
    }

    /// Owning target identity.
    #[allow(dead_code)] // read by `Target::owner`
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
    ///
    /// Rejects while the resident long operation holds a retained IO token
    /// (`RequiredIoInFlight`) in addition to the long-phase check.
    fn boundary_of<L: Lu + ?Sized>(&self, slot: &L) -> Result<(), BoundaryReject> {
        self.boundary_checks(slot, true, true)
    }

    /// Boundary for starting a command.
    ///
    /// A resident foreground long operation (MMC FORMAT/BLANK) must **not**
    /// reject the command at the runner: the medium gate belongs to the device
    /// (`Lu::admit` returns `2/04/04` and the profile refuses before any IO).
    /// The same holds for the long operation's retained IO token: queries stay
    /// serviceable while a long IO is pending (`03 §3.7`), so this path
    /// ignores both the long phase and the long IO obligation. Management
    /// entries keep the stricter [`Self::boundary_of`].
    fn command_boundary_of<L: Lu + ?Sized>(&self, slot: &L) -> Result<(), BoundaryReject> {
        self.boundary_checks(slot, false, false)
    }

    fn boundary_checks<L: Lu + ?Sized>(
        &self,
        slot: &L,
        require_long_settled: bool,
        reject_long_io: bool,
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
        // The resident long operation's retained token is an IO obligation too,
        // but it is **not** the command-owned `required_io` flag: queries must
        // still start while it is live (`03 §3.7`), while management/take must
        // not cross it. `RequiredIoInFlight` is the boundary-row reason for a
        // live IO obligation (`02-api-core §4.11`).
        if reject_long_io && self.long_io_in_flight() {
            return Err(BoundaryReject::RequiredIoInFlight);
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
    /// reject the long operation's own non-settled phase or its retained token
    /// (that is what this entry is there to advance). Everything else — ended,
    /// control, result barrier, command, retained input, unconsumed completion,
    /// live borrow — still blocks. `required_io`/`speculative_io` are not
    /// checked here: those flags belong to a command-owned IO, and a command
    /// cannot be live (`command_active`/`slot.active()` already reject it).
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
    /// report `Ended` while a command or its in-flight IO is live, nor while
    /// the resident long operation holds a retained token (a terminal flag
    /// with in-flight IO keeps `ServiceReady` so the token can drain/cancel).
    fn settled_terminal_outcome(&self) -> Option<RunOutcome> {
        if self.command_active.get()
            || self.drive_state.get().is_some()
            || self.long_pending.is_some()
        {
            None
        } else {
            self.terminal_outcome()
        }
    }

    /// Whether the resident long operation holds a retained adapter token.
    ///
    /// This is the long-entry analogue of `required_io`: an in-flight IO
    /// obligation that management/take must not cross. It is deliberately **not**
    /// the command-owned [`Runner`] flag, because queries must stay serviceable
    /// while a long IO is pending (`03 §3.7`); see
    /// [`Self::command_boundary_of`].
    const fn long_io_in_flight(&self) -> bool {
        self.long_pending.is_some()
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
    #[allow(dead_code)] // `Target::drive_start_*`; driven by tests here
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

    /// Adapter receipt for an operation the runner had to cancel **without**
    /// observing its end (long-entry bank mismatch / unaddressable window).
    ///
    /// The shape mirrors [`Self::known_unobserved`]: a write/sync reports
    /// [`Effect::UnknownRemainder`], a read never invents one (`03 §3.4`).
    fn cancelled_receipt(dir: Direction) -> StorageReceipt {
        let effect = if matches!(dir, Direction::FromHost | Direction::None) {
            Effect::UnknownRemainder
        } else {
            Effect::Known
        };
        StorageReceipt::failed(Fault::Contract, 0, effect)
    }

    /// Drop the workflow flags of one long-operation adapter request.
    fn clear_long_token(&mut self) {
        self.long_pending = None;
        self.long_data_addr = 0;
        self.long_data_len = 0;
    }

    /// Cancel the resident long operation's retained adapter token for `lun`.
    ///
    /// Only `force_remove_*` can reach this: it is the one immediate-cancel path
    /// that carries a `Storage` adapter. Returns the cancelled request so the
    /// caller can book its unobserved effects (`03 §3.3` force row); the device
    /// keeps its `Foreground`/`Background` projection because the operation's
    /// end was never observed, so [`Self::resume_pending_force`] still refuses
    /// to treat it as settled.
    fn cancel_long_pending(
        &mut self,
        lun: usize,
        storage: &mut dyn Storage,
    ) -> Option<LongPending> {
        let (owner, pending) = self.long_pending?;
        if owner != lun {
            return None;
        }
        storage.cancel(pending.token);
        self.clear_long_token();
        Some(pending)
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

    /// Facts confirmed by a storage receipt that was **returned** by the
    /// adapter.
    ///
    /// A returned receipt is authoritative for its own facts (`03 §3.3`
    /// "receipt 已返回" = consume the receipt first, a later cancel must not
    /// overwrite it): the confirmed write prefix is kept exactly as reported and
    /// `unknown_remainder` follows the receipt's [`Effect`]. An error on the
    /// receipt — including [`Fault::Contract`] — does not by itself fabricate an
    /// unknown remainder; only a write/sync whose end was never observed does
    /// (see [`Self::known_unobserved`]). A read never produces a write/sync
    /// remainder (`03 §3.4`: cancelling a read must not invent a write
    /// `Unknown`), so an impossible read-side `UnknownRemainder` is masked.
    fn known_from_storage_receipt(req: IoReq, receipt: StorageReceipt) -> KnownEffects {
        let write_or_sync = matches!(req.dir, Direction::FromHost | Direction::None);
        let mut known = KnownEffects::NONE;
        if req.dir == Direction::FromHost {
            known.confirmed_write = receipt.confirmed as u64;
        }
        if req.dir == Direction::None && receipt.error.is_none() && receipt.effect == Effect::Known
        {
            known.sync_durable = true;
        }
        known.unknown_remainder = write_or_sync && receipt.effect == Effect::UnknownRemainder;
        known
    }

    /// Facts confirmed by a host receipt that was **returned** by the
    /// adapter: the accepted/sent prefix is a returned fact and is never
    /// replaced by a fabricated unknown remainder (`03 §3.3`).
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
                        let known = Self::known_from_storage_receipt(req, receipt);
                        if raw.error.is_some() {
                            // An errored token is cancelled for slot
                            // hygiene. `cancel` returning does not rewrite the
                            // facts the returned receipt already established
                            // (`03 §3.3` "receipt 已返回").
                            storage.cancel(token);
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
                        // A returned host receipt is authoritative: keep its
                        // (clamped) accepted prefix and do not fabricate an
                        // unknown write remainder. The token is still cancelled
                        // for slot hygiene when the adapter reported an error.
                        if raw.error().is_some() {
                            host.cancel(token);
                        }
                        Self::known_from_host_receipt(sanitize_host_receipt(req, raw, self.owner))
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
            // state (`03 §3.3`). The first fault wins; a settle failure must not
            // mask an already-recorded root cause.
            self.set_fatal(fault);
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
            // The first fault is authoritative; a settle failure must not mask
            // the root cause of an already-ending service.
            self.set_fatal(fault);
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
    /// bank (one command runs at a time).
    #[allow(dead_code)] // `Target::drive_step_*`; driven by tests here
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
                            match self.absorb_io(&mut state, req, IoSettlement::Ready(receipt)) {
                                IoAbsorb::Retained => {}
                                IoAbsorb::Contract(known) => {
                                    self.settle_contract(lu, known);
                                    return Err(Fault::Contract);
                                }
                                // A returned `Ready` receipt is never `Pending`
                                // or `Unissued`; keep the match future-proof
                                // without inventing an unknown remainder.
                                IoAbsorb::Pending | IoAbsorb::Unissued => {
                                    self.settle_contract(lu, KnownEffects::NONE);
                                    return Err(Fault::Contract);
                                }
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
                            // The receipt was returned: keep its accepted prefix
                            // and never invent an unknown remainder.
                            self.settle_contract(lu, Self::known_from_host_receipt(raw));
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
                            // The receipt was returned: keep its accepted prefix
                            // and never invent an unknown remainder.
                            self.settle_contract(lu, Self::known_from_host_receipt(raw));
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
                            // A returned receipt keeps its (clamped) accepted
                            // prefix; a contract error alone is not an unknown
                            // write.
                            let known = Self::known_from_host_receipt(sanitize_host_receipt(
                                req, raw, self.owner,
                            ));
                            self.settle_contract(lu, known);
                            return Err(Fault::Contract);
                        }
                        Poll::Ready(raw) => {
                            let receipt = sanitize_host_receipt(req, raw, self.owner);
                            if receipt.error().is_some() {
                                state.host_failed = true;
                            }
                            state.feedback = Feedback::host_received(receipt);
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
                            // A returned receipt keeps its (clamped) accepted
                            // prefix; a contract error alone is not an unknown
                            // write.
                            let known = Self::known_from_host_receipt(sanitize_host_receipt(
                                req, raw, self.owner,
                            ));
                            self.settle_contract(lu, known);
                            return Err(Fault::Contract);
                        }
                        Poll::Ready(raw) => {
                            let receipt = sanitize_host_receipt(req, raw, self.owner);
                            if receipt.error().is_some() {
                                state.host_failed = true;
                            }
                            state.feedback = Feedback::host_sent(receipt);
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
                    // The device produced neither work nor a completion; the
                    // no-progress fallback fixes the command as `Busy` instead
                    // of spinning.
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
            IoSettlement::Ready(raw) if raw.error == Some(Fault::Contract) => {
                // The adapter answered (the receipt is a returned fact): keep
                // its confirmed prefix and effect instead of treating the
                // operation as an unreported cancel (`03 §3.3`).
                let receipt = sanitize_storage_receipt(req, raw);
                IoAbsorb::Contract(Self::known_from_storage_receipt(req, receipt))
            }
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
            IoAbsorb::Contract(known) => {
                self.settle_contract(lu, known);
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
                HostResume::Retained(sanitize_host_receipt(req, raw, self.owner))
            }
        }
    }

    // ── management ─────────────────────────────────────────────────────

    /// Take a detached pair exactly once. `take_gate` is the boundary (which
    /// already contains `long_settled`); it deliberately excludes ended,
    /// control-pending and await-take so a fixed result stays claimable.
    ///
    /// A retained long-entry adapter token is the runner's `long_io`
    /// obligation, so the gate rejects the take with
    /// [`BoundaryReject::RequiredIoInFlight`] before the long-phase check (a
    /// device could report `Idle` while the token is live). This entry never
    /// cancels or re-borrows that token; only `force_remove_*` (which has a
    /// `Storage` adapter) cancels one.
    ///
    /// [`Self::take_boundary_of`] relaxes **only** the long-phase rejection,
    /// and only for a LUN whose long operation a force already cancelled
    /// ([`Self::force_long_cancelled`]); the handback booked by that force must
    /// stay deliverable even though the device keeps `Foreground` until the
    /// detach.
    ///
    /// A successful take that clears the global handback barrier also releases
    /// the deferred force for **this** LUN (see [`Self::resume_pending_force`]);
    /// forces deferred on other LUNs are released by `Target::take_rt`, which
    /// can reach their slots.
    #[allow(dead_code)] // `Target::take_rt`; driven by tests here
    pub(crate) fn take_rt<L: Lu + ?Sized>(
        &mut self,
        lun: usize,
        lu: &mut L,
    ) -> Result<ChangeResult<L::Pair>, BoundaryReject> {
        self.take_boundary_of(lun, lu)?;
        let permit = self.permit();
        if !lu.accepts_permit(&permit) {
            return Err(BoundaryReject::ForeignBoundary);
        }
        let result = lu.take_rt(&permit).ok_or(BoundaryReject::NothingToTake)?;
        self.clear_long_feedback(lun);
        if self.await_take == Some(lun) {
            self.await_take = None;
            self.take_events = self.take_events.saturating_add(1);
        }
        // The deferred force (if any) may detach the current pair, which clears
        // the latch itself. If no force remains armed, the take completes the
        // bypass: a fresh medium must not inherit it.
        self.resume_pending_force(lun, lu);
        if !self.force_pending(lun) {
            self.clear_force_long_cancelled(lun);
        }
        Ok(result)
    }

    /// Gate for [`Self::take_rt`].
    ///
    /// The authoritative boundary, with **only** the long-phase rejection
    /// relaxed for a LUN whose long operation a force already cancelled
    /// ([`Self::force_long_cancelled`]): the device keeps its `Foreground`
    /// projection until the pair is detached, so the handback booked by the
    /// force (including `unknown_remainder`) must stay deliverable. A live
    /// token, command, retained input, unconsumed completion, result barrier or
    /// live borrow still blocks.
    fn take_boundary_of<L: Lu + ?Sized>(&self, lun: usize, slot: &L) -> Result<(), BoundaryReject> {
        self.boundary_checks(slot, !self.force_long_cancelled(lun), true)
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

    /// Whether a force cancelled `lun`'s resident long operation while its
    /// phase stayed `Foreground`/`Background` (the take bypass latch).
    pub(crate) const fn force_long_cancelled(&self, lun: usize) -> bool {
        lun < u64::BITS as usize && self.force_long_cancelled & (1u64 << lun) != 0
    }

    /// Arm the take bypass for `lun` (see [`Self::force_long_cancelled`]).
    fn set_force_long_cancelled(&mut self, lun: usize) -> Result<(), Fault> {
        let bit = Self::force_bit(lun)?;
        self.force_long_cancelled |= bit;
        Ok(())
    }

    /// Drop the take bypass for `lun`; out-of-range LUNs never had it set.
    fn clear_force_long_cancelled(&mut self, lun: usize) {
        if lun < u64::BITS as usize {
            self.force_long_cancelled &= !(1u64 << lun);
        }
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
        // adapters to settle, so the force stays armed. A non-settled resident
        // long operation has the same problem: this entry has **no** storage
        // adapter, so it cannot cancel the retained long-entry token. It stays
        // armed until the application calls `force_remove_*` with the adapters.
        // The token itself is checked as well: a device may report `Idle`
        // while a long IO is still retained by the runner. A force-cancelled
        // long op (`force_long_cancelled`) does not block the detach: its token
        // is already gone and the pair is committed for removal.
        let forced_long = self.force_long_cancelled(lun);
        if lu.has_result()
            || lu.active()
            || self.await_take.is_some()
            || self.eject_pending.is_some()
            || self.long_pending.is_some_and(|(owner, _)| owner == lun)
            || (!forced_long
                && !matches!(lu.long_info().phase, LongPhase::Idle | LongPhase::Settled))
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
                self.clear_long_feedback(lun);
                self.clear_force_long_cancelled(lun);
                if let Err(reject) = self.host_eject_succeeded(lun) {
                    let fault = match reject {
                        BoundaryReject::EjectPending => Fault::Contract,
                        _ => Fault::NeedsRecovery,
                    };
                    self.set_fatal(fault);
                }
            }
            Ok(()) => {
                self.clear_long_feedback(lun);
                self.clear_force_long_cancelled(lun);
            }
            Err(fault) => self.set_fatal(fault),
        }
    }

    /// Propose a candidate change. The transaction cannot cross an ended,
    /// control-pending or result-barrier state.
    #[allow(dead_code)] // `Target::propose_rt`; driven by tests here
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
    #[allow(dead_code)] // `Target::advance_rt`; driven by tests here
    pub(crate) fn advance_rt<L: Lu + ?Sized>(
        &mut self,
        lun: usize,
        lu: &mut L,
    ) -> Result<(), Fault> {
        self.service_gate(lu).map_err(|_| Fault::Boundary)?;
        let permit = self.permit();
        if !lu.accepts_permit(&permit) {
            return Err(Fault::ForeignBoundary);
        }
        lu.advance_rt(&permit)?;
        // `advance` detaches the old pair; its resident long result cannot
        // follow the new medium, and a fresh medium never inherits the
        // force-cancelled long-phase bypass.
        self.clear_long_feedback(lun);
        self.clear_force_long_cancelled(lun);
        Ok(())
    }

    /// Install an application-returned pair.
    #[allow(dead_code)] // `Target::install_rt`; driven by tests here
    pub(crate) fn install_rt<L: Lu + ?Sized>(
        &mut self,
        lun: usize,
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
        lu.install_rt(&permit, pair)?;
        self.clear_long_feedback(lun);
        self.clear_force_long_cancelled(lun);
        Ok(())
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
    ///
    /// **Forced-long latch.** If the LUN still reports a resident
    /// `Foreground`/`Background` operation after the cancel, the force arms
    /// [`Self::force_long_cancelled`]. The device is only discarded by the
    /// detach, so without the latch `long_settled` would reject both the take
    /// that delivers the force effects and the deferred detach — a permanent
    /// dead end. The latch relaxes only the long-phase check in `take`, never a
    /// live token/command/barrier, and is cleared by any pair change
    /// (`take` completion without an armed force, `advance`, `install`, host
    /// eject, force detach).
    #[allow(dead_code)] // `Target::force_remove_rt`; driven by tests here
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
        // A resident long operation may hold one retained adapter token for
        // this LUN. Force is an immediate-cancel path (`03 §3.3`): cancel the
        // token before any detach, including before a deferral, so the adapter
        // slot is freed even if the detach happens later. A write/sync whose
        // end was never observed must leave `unknown_remainder` in the force
        // handback (`ChangeResult.effects`); a read has no write effect. The
        // device's own long-op state is discarded by the detach, so no
        // synthetic receipt is fed to it.
        if let Some(pending) = self.cancel_long_pending(lun, storage) {
            let known = Self::known_unobserved(pending.req.dir);
            if known != KnownEffects::NONE {
                // `Lu::interrupt` records the facts in the slot before the
                // device hook, so a failing hook cannot lose the remainder. A
                // read settles with `NONE`, which would only overwrite facts.
                let permit = self.command_permit();
                let _ = lu.interrupt(&permit, InterruptReason::Stop, known);
            }
        }
        // The force cancelled the resident long operation (token and/or its
        // phase). The device keeps `Foreground`/`Background` until the detach,
        // so arm the take-only latch that lets the handback (with the R-C
        // effects) and the deferred force complete. A force on a LUN with no
        // resident long op must not arm it.
        let permit = self.permit();
        if !lu.accepts_permit(&permit) {
            return Err(Fault::ForeignBoundary);
        }
        match lu.long_info().phase {
            LongPhase::Foreground | LongPhase::Background => {
                self.set_force_long_cancelled(lun)?;
            }
            LongPhase::Idle | LongPhase::Settled => {}
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
        // A force that detached immediately completes the pair change: a fresh
        // medium must not inherit the long-phase bypass.
        self.clear_long_feedback(lun);
        self.clear_force_long_cancelled(lun);
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
        // The host eject detached this LUN's pair; its resident long result
        // must not leak into a later fill and the force-cancelled bypass must
        // not follow a fresh medium.
        self.clear_long_feedback(lun);
        self.clear_force_long_cancelled(lun);
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
    #[allow(dead_code)] // `Target::host_eject_succeeded_*`
    pub(crate) fn host_eject_succeeded(&mut self, lun: usize) -> Result<(), BoundaryReject> {
        self.begin_eject(lun)?;
        self.finish_eject(lun)
    }

    /// Queue a control request. `Nop` still requires the caller (`Target`) to
    /// check every resident slot's boundary via `SlotSet::check_boundary`;
    /// `Abort` is accepted while a command is active and consumed as a no-op
    /// when idle.
    #[allow(dead_code)] // `Target::request_control`; driven by tests here
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
                // Only a command that is actually active owns an Abort. A
                // fixed-completion command (admission reject / prepare error)
                // has `command_active == false` while `drive_state.done` is
                // still owed; queueing there would never be consumed and would
                // wedge every later entry in `ControlPending`.
                if self.command_active.get() {
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
    #[allow(dead_code)] // `Target::stop`; driven by tests here
    pub(crate) fn request_stop(&mut self) {
        self.stop = true;
    }

    /// Transport ended (link reset/disconnect); not recoverable.
    #[allow(dead_code)] // `Target::transport_ended`; driven by tests here
    pub(crate) fn transport_ended(&mut self) {
        self.transport_end = true;
    }

    /// Enter the fatal state; the next settled `tick` reports `Ended{Fatal}`.
    #[allow(dead_code)] // `Target::fatal`; driven by tests here
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
    #[allow(dead_code)] // `Target::tick`; driven by tests here
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

    /// Claim the single long-operation slot when a command leaves a resident
    /// foreground/background operation on `lun`.
    ///
    /// Once claimed, an entry for any other LUN fails closed with
    /// `Fault::Boundary` until this owner settles or its pair is detached.
    pub(crate) fn claim_long_feedback(&mut self, lun: usize, info: LongInfo) {
        if self.long_feedback.is_none()
            && matches!(info.phase, LongPhase::Foreground | LongPhase::Background)
        {
            self.long_feedback = Some((lun, Feedback::begin()));
        }
    }

    /// Drop a pending long-operation receipt only when `lun` owns it.
    fn clear_long_feedback(&mut self, lun: usize) {
        if matches!(self.long_feedback, Some((owner, _)) if owner == lun) {
            self.long_feedback = None;
        }
    }

    /// Advance a resident long operation by exactly one entry.
    ///
    /// A Target has at most one active resident long operation. Both the
    /// pending adapter token and the pending receipt are keyed to its LUN: an
    /// entry for a different LUN fails closed with `Fault::Boundary` before the
    /// device or the adapter is touched, while an `Idle` answer from the owning
    /// device drops the receipt (the operation is gone). Arming a second long
    /// operation is an application error; it can only advance after the owner
    /// settles (or its pair is detached/taken).
    ///
    /// **One adapter poll per entry.** A long operation may span several
    /// entries with one retained [`IoToken`]:
    ///
    /// - a retained token for this LUN is re-borrowed from `data` and polled
    ///   **once**; `Pending` returns the unchanged [`LongInfo`] without polling
    ///   the device, `Ready` clears the token and stores the receipt as the
    ///   keyed feedback (the device consumes it on the next entry — the same
    ///   one-step lag as before);
    /// - with no retained token the device is polled once and a request is
    ///   issued and polled once; `Pending` retains the token, `Ready` stores
    ///   the feedback. There is **no** loop over `Poll::Pending` and therefore
    ///   no runner-side pending budget: a stalled adapter costs one poll per
    ///   entry and cannot grow work or memory.
    /// - a `data` bank that no longer matches the token's bank (address and
    ///   length, including an empty bank) is never re-borrowed: the token is
    ///   cancelled, the operation is settled through the bounded contract path
    ///   and `Fault::Contract` is returned.
    /// - a LUN whose long operation a force already cancelled
    ///   ([`Self::force_long_cancelled`]) is committed for removal: every entry
    ///   returns `Fault::Boundary` without issuing IO or reading the device.
    ///
    /// **Terminal flags and a live token.** `tick` stays `ServiceReady` while
    /// the token is pending. This entry then runs *before* the normal
    /// gate, keyed to the owning LUN: `stop` **drains** the token (one poll per
    /// entry, then one bounded device poll with the receipt);
    /// `transport_ended`/`fatal` **cancel** it (one `storage.cancel`, then a
    /// synthesized cancelled receipt fed to the device so it settles/records
    /// the fault). With no token, the normal gate rejects new entries — a
    /// terminal target never issues new IO. `Stop` neither detaches nor ejects;
    /// the fill may stay `Foreground` afterwards because only `force_remove_*`
    /// can escape it.
    ///
    /// A `Fault::Contract` receipt is delivered back to the device in the same
    /// entry (one bounded settle step, never a loop) so an `MmcDrive` is
    /// already `Settled` before `Err(Fault::Contract)` is surfaced.
    #[allow(dead_code)] // `Target::poll_long_entry_*`
    pub(crate) fn poll_long_entry<L: Lu + ?Sized>(
        &mut self,
        lun: usize,
        lu: &mut L,
        storage: &mut dyn Storage,
        data: &mut [u8],
    ) -> Result<LongInfo, Fault> {
        if matches!(self.long_pending, Some((owner, _)) if owner != lun) {
            return Err(Fault::Boundary);
        }
        if matches!(self.long_feedback, Some((owner, _)) if owner != lun) {
            return Err(Fault::Boundary);
        }
        // A force already cancelled this LUN's long operation and committed the
        // pair for removal. No new IO, and the device projection is not even
        // read: the handback happens through `take`/the deferred force.
        if self.force_long_cancelled(lun) {
            return Err(Fault::Boundary);
        }
        let permit = self.command_permit();

        // 0. A terminal flag with a retained token: drain (Stop) or cancel
        //    (transport end / fatal) before the normal gate. With no token the
        //    gate below rejects the entry.
        if self.long_pending.is_some() {
            if let Some(outcome) = self.terminal_outcome() {
                let stopped = matches!(
                    outcome,
                    RunOutcome::Ended {
                        reason: RunEnd::Stopped,
                        ..
                    }
                );
                return self.settle_long_terminal(lun, lu, storage, &permit, data, stopped);
            }
        }
        self.poll_long_gate(lu).map_err(|_| Fault::Boundary)?;

        // 1. Resume the retained adapter token for this LUN. One poll, never
        //    the device: the receipt is consumed by the device on the next
        //    entry.
        if let Some((_, pending)) = self.long_pending {
            let data_addr = data.as_ptr() as usize;
            let data_len = data.len();
            // An empty bank is a mismatch too: the retained window can never
            // be re-borrowed from it.
            let same_bank = self.long_data_addr == data_addr && self.long_data_len == data_len;
            let buf = same_bank
                .then(|| pending_io_buf(data, pending.req, pending.buf_offset))
                .flatten();
            if let Some(buf) = buf {
                match storage.poll_exec(pending.token, buf) {
                    Poll::Pending => return Ok(lu.long_info()),
                    Poll::Ready(raw) => {
                        self.clear_long_token();
                        let receipt = sanitize_storage_receipt(pending.req, raw);
                        return self.absorb_long_receipt(lun, lu, &permit, receipt, data);
                    }
                }
            }
            // The caller's bank is no longer the one the token was issued
            // against (or the window is no longer addressable inside it):
            // never re-borrow a different bank. Cancel, then settle the
            // abandoned operation through the bounded contract path.
            storage.cancel(pending.token);
            self.clear_long_token();
            let feedback = Feedback::io_done(IoReceipt::from_storage(
                Self::cancelled_receipt(pending.req.dir),
                self.owner,
            ));
            self.long_feedback = Some((lun, feedback));
            return self.settle_contract_long(lun, lu, &permit, feedback, data);
        }

        // 2. No retained token: poll the device once, issue at most one
        //    storage operation and poll it once.
        let feedback = match self.long_feedback.take() {
            Some((owner, feedback)) if owner == lun => feedback,
            _ => Feedback::begin(),
        };
        let data_addr = data.as_ptr() as usize;
        let data_len = data.len();
        let step = lu.poll_long(&permit, feedback, data);
        let outcome = match step {
            PollStep::Io(op) => {
                let (req, buf, buf_offset) = split_long_op(op, data_addr, data_len);
                self.long_io(
                    lun, storage, req, buf, buf_offset, false, data_addr, data_len,
                )
            }
            PollStep::Prefetch(PrefetchOp::Read {
                resource,
                offset,
                buf,
            }) => {
                // Speculative reads never change the long-operation outcome; a
                // failure is reported to the device, which falls back to `Io`.
                let req = IoReq {
                    resource,
                    offset,
                    len: buf.len() as u32,
                    dir: Direction::ToHost,
                };
                let buf_offset = slice_offset(data_addr, data_len, buf);
                self.long_io(
                    lun,
                    storage,
                    req,
                    IoBuf::Read(buf),
                    buf_offset,
                    true,
                    data_addr,
                    data_len,
                )
            }
            PollStep::Complete(_) => {
                self.clear_long_feedback(lun);
                return Ok(lu.long_info());
            }
            PollStep::Idle => {
                // `Idle` only means "no work ready in this step". Keep the
                // receipt only while the device still owns a live long
                // operation (a foreground `Begin` guard also answers `Idle`);
                // a settled/idle projection means the operation is gone.
                if matches!(
                    lu.long_info().phase,
                    LongPhase::Foreground | LongPhase::Background
                ) {
                    self.long_feedback = Some((lun, feedback));
                } else {
                    self.clear_long_feedback(lun);
                }
                return Ok(lu.long_info());
            }
            PollStep::Publish(_) | PollStep::Receive(_) | PollStep::Send(_) => {
                // The device broke the long-operation contract but did not
                // consume the receipt: restore it instead of dropping facts.
                self.long_feedback = Some((lun, feedback));
                return Err(Fault::Contract);
            }
        };
        let receipt = match outcome {
            // Token retained; the device is not polled again in this entry.
            LongIo::Pending => return Ok(lu.long_info()),
            LongIo::Ready(receipt) => receipt,
            // Pool exhausted: nothing was issued, so no effect and no token.
            LongIo::Unissued => StorageReceipt::failed(Fault::Contract, 0, Effect::Known),
            // The adapter answered `Pending` for a window outside `data`; the
            // token was already cancelled and its end was never observed.
            LongIo::Unaddressable(dir) => Self::cancelled_receipt(dir),
        };
        self.absorb_long_receipt(lun, lu, &permit, receipt, data)
    }

    /// Terminal-flag settlement for a retained long-operation token.
    ///
    /// `Stop` drains (`03 §3.3`): one adapter poll per entry until `Ready`,
    /// then one bounded device poll with the returned receipt. A bank mismatch
    /// cannot advance the drain, so it cancels and books the unobserved effect
    /// instead. `transport_ended`/`fatal` cancel immediately: one
    /// `storage.cancel`, then a synthesized cancelled receipt
    /// ([`Self::cancelled_receipt`]) fed to the device so it settles/records the
    /// fault. Neither path issues new IO.
    fn settle_long_terminal<L: Lu + ?Sized>(
        &mut self,
        lun: usize,
        lu: &mut L,
        storage: &mut dyn Storage,
        permit: &CommandPermit,
        data: &mut [u8],
        stopped: bool,
    ) -> Result<LongInfo, Fault> {
        let Some((_, pending)) = self.long_pending else {
            return Err(Fault::Boundary);
        };
        let receipt = if stopped {
            let data_addr = data.as_ptr() as usize;
            let data_len = data.len();
            let same_bank = self.long_data_addr == data_addr && self.long_data_len == data_len;
            let buf = same_bank
                .then(|| pending_io_buf(data, pending.req, pending.buf_offset))
                .flatten();
            let Some(buf) = buf else {
                // The drain cannot re-borrow its window: cancel and report the
                // unobserved effect (same rule as the normal mismatch path).
                storage.cancel(pending.token);
                self.clear_long_token();
                let receipt = Self::cancelled_receipt(pending.req.dir);
                let feedback = Feedback::io_done(IoReceipt::from_storage(receipt, self.owner));
                return self.feed_long_terminal(lun, lu, permit, feedback, data, false);
            };
            match storage.poll_exec(pending.token, buf) {
                Poll::Pending => return Ok(lu.long_info()),
                Poll::Ready(raw) => {
                    self.clear_long_token();
                    sanitize_storage_receipt(pending.req, raw)
                }
            }
        } else {
            storage.cancel(pending.token);
            self.clear_long_token();
            Self::cancelled_receipt(pending.req.dir)
        };
        let feedback = Feedback::io_done(IoReceipt::from_storage(receipt, self.owner));
        self.feed_long_terminal(lun, lu, permit, feedback, data, stopped)
    }

    /// Feed one terminal receipt to the device with a single bounded
    /// `poll_long`, never issuing new IO.
    ///
    /// On `Stop` the resident fill may stay `Foreground` (a terminal target
    /// issues no more IO; `force_remove_*` remains the escape). On transport
    /// end/fatal a device that still asks for IO is stopped with one bounded
    /// `interrupt(Stop, NONE)` so it cannot keep a phantom in-flight operation.
    fn feed_long_terminal<L: Lu + ?Sized>(
        &mut self,
        lun: usize,
        lu: &mut L,
        permit: &CommandPermit,
        feedback: Feedback,
        data: &mut [u8],
        stopped: bool,
    ) -> Result<LongInfo, Fault> {
        self.long_feedback = Some((lun, feedback));
        match lu.poll_long(permit, feedback, data) {
            PollStep::Io(_) | PollStep::Prefetch(_) => {
                if !stopped {
                    let _ = lu.interrupt(permit, InterruptReason::Stop, KnownEffects::NONE);
                }
            }
            PollStep::Complete(_)
            | PollStep::Idle
            | PollStep::Publish(_)
            | PollStep::Receive(_)
            | PollStep::Send(_) => {}
        }
        self.clear_long_feedback(lun);
        Ok(lu.long_info())
    }

    /// Issue one long-operation storage request and poll it exactly once.
    ///
    /// `Pending` retains the token together with the caller's bank identity;
    /// `Ready` returns the sanitized receipt. Nothing loops, and **no**
    /// `required_io`/`speculative_io` flag is set: those are command-owned
    /// obligations, while a long IO must leave queries serviceable
    /// (`03 §3.7`). The obligation is [`Self::long_io_in_flight`] instead.
    #[allow(clippy::too_many_arguments)]
    fn long_io(
        &mut self,
        lun: usize,
        storage: &mut dyn Storage,
        req: IoReq,
        buf: IoBuf<'_>,
        buf_offset: Option<usize>,
        prefetch: bool,
        data_addr: usize,
        data_len: usize,
    ) -> LongIo {
        let token = storage.begin_exec(req);
        if !token.is_valid() {
            return LongIo::Unissued;
        }
        match storage.poll_exec(token, buf) {
            Poll::Ready(raw) => LongIo::Ready(sanitize_storage_receipt(req, raw)),
            Poll::Pending => match buf_offset {
                Some(offset) => {
                    self.long_pending = Some((
                        lun,
                        LongPending {
                            token,
                            req,
                            buf_offset: offset,
                            prefetch,
                        },
                    ));
                    self.long_data_addr = data_addr;
                    self.long_data_len = data_len;
                    LongIo::Pending
                }
                None => {
                    // The window is not addressable inside `data`; the next
                    // entry could not re-borrow it, so cancel now.
                    storage.cancel(token);
                    LongIo::Unaddressable(req.dir)
                }
            },
        }
    }

    /// Store one returned long-operation receipt as the keyed feedback and
    /// settle a `Fault::Contract` one bounded step before surfacing it.
    fn absorb_long_receipt<L: Lu + ?Sized>(
        &mut self,
        lun: usize,
        lu: &mut L,
        permit: &CommandPermit,
        receipt: StorageReceipt,
        data: &mut [u8],
    ) -> Result<LongInfo, Fault> {
        // A returned receipt is authoritative even for `Contract`
        // (`03 §3.3`): feed it back before surfacing the fault, so the device
        // settles from the confirmed prefix/effect and a later entry cannot
        // re-issue the cancelled operation.
        let feedback = Feedback::io_done(IoReceipt::from_storage(receipt, self.owner));
        self.long_feedback = Some((lun, feedback));
        if receipt.error == Some(Fault::Contract) {
            return self.settle_contract_long(lun, lu, permit, feedback, data);
        }
        Ok(lu.long_info())
    }

    /// One bounded settle step after a `Fault::Contract` long receipt.
    ///
    /// The receipt is already stored keyed to `lun`. Polling the device once
    /// more is exactly what the next entry would do; it lets an `MmcDrive`
    /// reach `Settled` before the error surfaces. A second `Io`/`Prefetch` is
    /// **not** executed and the already-consumed receipt is never re-fed: the
    /// device is told to stop with a bounded `interrupt(Stop, NONE)` (no IO is
    /// in flight), the slot is cleared, and the entry returns the contract
    /// fault. This is a one-step cleanup, not an IO loop.
    fn settle_contract_long<L: Lu + ?Sized>(
        &mut self,
        lun: usize,
        lu: &mut L,
        permit: &CommandPermit,
        feedback: Feedback,
        data: &mut [u8],
    ) -> Result<LongInfo, Fault> {
        match lu.poll_long(permit, feedback, data) {
            PollStep::Io(_) | PollStep::Prefetch(_) => {
                // The device consumed the receipt and asked for another IO.
                // Never re-feed it (the receipt is spent) and never execute the
                // requested IO; one bounded cleanup settles the device.
                let _ = lu.interrupt(permit, InterruptReason::Stop, KnownEffects::NONE);
                self.clear_long_feedback(lun);
            }
            PollStep::Complete(_)
            | PollStep::Idle
            | PollStep::Publish(_)
            | PollStep::Receive(_)
            | PollStep::Send(_) => self.clear_long_feedback(lun),
        }
        Err(Fault::Contract)
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

/// Split one long-operation [`StorageOp`] into its metadata request, buffer and
/// offset inside the caller's `data` bank.
fn split_long_op<'a>(
    op: StorageOp<'a>,
    data_addr: usize,
    data_len: usize,
) -> (IoReq, IoBuf<'a>, Option<usize>) {
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
            let buf_offset = slice_offset(data_addr, data_len, buf);
            (req, IoBuf::Read(buf), buf_offset)
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
            let buf_offset = slice_offset(data_addr, data_len, buf);
            (req, IoBuf::Write(buf), buf_offset)
        }
        StorageOp::Sync { resource } => (
            IoReq {
                resource,
                offset: 0,
                len: 0,
                dir: Direction::None,
            },
            IoBuf::None,
            Some(0),
        ),
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

/// Clamp a returned host receipt to the request it answers (`03 §3.4`).
///
/// The accepted/sent prefix can never exceed the request (a larger number is a
/// contract violation and must not be over-reported). The runner stamps its own
/// identity so an adapter cannot forge ownership.
fn sanitize_host_receipt(req: HostReq, receipt: HostReceipt, owner: TargetId) -> HostReceipt {
    HostReceipt::new(
        receipt.accepted().min(req.len as usize),
        receipt.error(),
        owner,
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::core::device::{Device, NoMedium, Pair};
    use crate::core::lu::LuImpl;
    use crate::core::storage::{BlockingHost, BlockingStorage, SyncHost, SyncStorage};
    use crate::core::FeedbackKind;

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

    /// Purpose-built long-operation device for the receipt hand-off tests.
    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    enum ProbeMode {
        /// Consume the receipt, then ask for another IO (R1).
        SettleIo,
        /// First entry issues IO; the next returns `Idle` while still
        /// `Foreground`, then the third consumes the same receipt (R2).
        IdleOnce,
    }

    struct ProbeLong {
        mode: ProbeMode,
        long: LongInfo,
        step: u32,
        ios: u32,
        interrupts: u32,
        last_reason: Option<InterruptReason>,
        last_known: KnownEffects,
        last_effect: Option<Effect>,
    }

    impl ProbeLong {
        fn new(mode: ProbeMode) -> Self {
            Self {
                mode,
                long: LongInfo::IDLE,
                step: 0,
                ios: 0,
                interrupts: 0,
                last_reason: None,
                last_known: KnownEffects::NONE,
                last_effect: None,
            }
        }

        fn io<'a>(data: &'a mut [u8]) -> PollStep<'a> {
            PollStep::Io(StorageOp::Write {
                resource: 1,
                offset: 0,
                buf: &data[..8],
            })
        }
    }

    impl Device for ProbeLong {
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
            _feedback: Feedback,
            _data: &'a mut [u8],
        ) -> PollStep<'a> {
            PollStep::Idle
        }

        fn poll_long<'a>(
            &mut self,
            _permit: &CommandPermit,
            feedback: Feedback,
            data: &'a mut [u8],
        ) -> PollStep<'a> {
            if let Some(io) = feedback.io() {
                self.ios = self.ios.saturating_add(1);
                self.last_effect = Some(io.effect());
            }
            match self.mode {
                ProbeMode::SettleIo => {
                    self.long = LongInfo {
                        phase: LongPhase::Foreground,
                        write_accessible: false,
                        progress: Some(0),
                        error: None,
                    };
                    match feedback.kind() {
                        FeedbackKind::Begin | FeedbackKind::IoDone => ProbeLong::io(data),
                        _ => PollStep::Idle,
                    }
                }
                ProbeMode::IdleOnce => {
                    self.step = self.step.saturating_add(1);
                    match self.step {
                        1 => {
                            self.long = LongInfo {
                                phase: LongPhase::Foreground,
                                write_accessible: false,
                                progress: Some(0),
                                error: None,
                            };
                            ProbeLong::io(data)
                        }
                        2 => PollStep::Idle,
                        _ => {
                            self.long = LongInfo {
                                phase: LongPhase::Settled,
                                write_accessible: true,
                                progress: Some(100),
                                error: None,
                            };
                            PollStep::Complete(Completion::Good)
                        }
                    }
                }
            }
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
            Ok(())
        }

        fn finish_delivery(&mut self, _permit: &CommandPermit, _delivery: Delivery) {}

        fn take_medium(&mut self, _permit: &BoundaryPermit) -> Option<NoMedium> {
            None
        }

        fn install_medium(
            &mut self,
            _permit: &BoundaryPermit,
            medium: NoMedium,
        ) -> Result<(), (NoMedium, Fault)> {
            Err((medium, Fault::Contract))
        }
    }

    /// Storage double for the receipt hand-off tests (contract or success).
    struct ProbePlane {
        fault: Option<Fault>,
    }

    impl SyncStorage for ProbePlane {
        fn exec(&mut self, _req: IoReq, _buf: IoBuf<'_>) -> StorageReceipt {
            match self.fault {
                Some(fault) => StorageReceipt::failed(fault, 0, Effect::Known),
                None => StorageReceipt::ok(0),
            }
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
    fn resume_pending_force_refuses_a_live_long_token_even_when_the_device_is_idle() {
        // Unit test of the guard, not a public-path scenario: it sets
        // `long_pending` directly because a realistic `Lu` cannot issue long IO
        // from a slot that already holds a resident result (the medium is gone).
        let mut bench = Bench::new([None; SCRIPT_LEN], 0);
        // A force is armed for LUN 0 while the runner still retains a long
        // token, even though the device projects `Idle` (the token is the only
        // record of the live IO).
        bench.runner.force_pending = 1;
        bench.runner.long_pending = Some((
            0,
            LongPending {
                token: IoToken::invalid(),
                req: IoReq {
                    resource: 0,
                    offset: 0,
                    len: 8,
                    dir: Direction::FromHost,
                },
                buf_offset: 0,
                prefetch: false,
            },
        ));
        bench.runner.resume_pending_force(0, &mut bench.slot);
        assert_eq!(bench.slot.long_info().phase, LongPhase::Idle);
        assert!(
            !bench.slot.has_result(),
            "a bare take must not detach a slot with a live runner token"
        );
        assert!(bench.slot.snapshot().ready, "the pair stays installed");
        assert!(bench.runner.force_pending(0), "the force stays armed");
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
            bench.runner.install_rt(0, &mut bench.slot, pair),
            Err((
                Pair {
                    medium: NoMedium,
                    backing: 4,
                },
                Fault::Boundary
            ))
        );
        assert_eq!(
            bench.runner.advance_rt(0, &mut bench.slot),
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
    fn settle_contract_long_never_refeeds_a_consumed_receipt() {
        let mut slot = LuImpl::new(ProbeLong::new(ProbeMode::SettleIo), 1u8);
        let mut runner = Runner::new();
        let mut storage = BlockingStorage::new(ProbePlane {
            fault: Some(Fault::Contract),
        });
        let mut data = [0u8; 64];

        assert_eq!(
            runner.poll_long_entry(0, &mut slot, &mut storage, &mut data),
            Err(Fault::Contract)
        );
        let probe = slot.device_ref();
        assert_eq!(probe.ios, 1, "the receipt was delivered exactly once");
        assert_eq!(probe.interrupts, 1, "one bounded cleanup");
        assert_eq!(probe.last_reason, Some(InterruptReason::Stop));
        assert_eq!(probe.last_known, KnownEffects::NONE);
        assert!(
            runner.long_feedback.is_none(),
            "a spent receipt must not be restored"
        );
    }

    #[test]
    fn an_idle_answer_while_foreground_keeps_the_receipt() {
        let mut slot = LuImpl::new(ProbeLong::new(ProbeMode::IdleOnce), 1u8);
        let mut runner = Runner::new();
        let mut storage = BlockingStorage::new(ProbePlane { fault: None });
        let mut data = [0u8; 64];

        // Entry 1 issues the IO and stores the receipt.
        let info = runner
            .poll_long_entry(0, &mut slot, &mut storage, &mut data)
            .expect("first entry");
        assert_eq!(info.phase, LongPhase::Foreground);
        assert_eq!(slot.device_ref().ios, 0);

        // Entry 2 consumes the receipt but answers `Idle` while Foreground:
        // the receipt must be restored, not dropped.
        let info = runner
            .poll_long_entry(0, &mut slot, &mut storage, &mut data)
            .expect("idle entry");
        assert_eq!(info.phase, LongPhase::Foreground, "not reported as gone");
        assert_eq!(slot.device_ref().ios, 1);
        assert!(
            runner.long_feedback.is_some(),
            "the receipt survived an Idle-with-work-pending answer"
        );

        // Entry 3 consumes it again and settles.
        let info = runner
            .poll_long_entry(0, &mut slot, &mut storage, &mut data)
            .expect("settle entry");
        assert_eq!(info.phase, LongPhase::Settled);
        assert_eq!(slot.device_ref().ios, 2);
        assert!(runner.long_feedback.is_none());
    }

    #[test]
    fn long_entry_projects_the_device_state() {
        let mut bench = Bench::new([None; SCRIPT_LEN], 0);
        let mut bank = [0u8; 64];
        let info = bench
            .runner
            .poll_long_entry(0, &mut bench.slot, &mut bench.storage, &mut bank)
            .expect("long entry");
        assert_eq!(info, LongInfo::IDLE);

        bench.runner.request_stop();
        assert_eq!(
            bench
                .runner
                .poll_long_entry(0, &mut bench.slot, &mut bench.storage, &mut bank),
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
    fn a_long_entry_that_loses_its_bank_cancels_once_and_keeps_the_write_remainder_unknown() {
        // The former `drive_exec` budget test pinned the receipt shape of a
        // write whose end was never observed. That fact is still observable on
        // the real long-entry path: a retained token is cancelled when the
        // caller's bank changes, and the device is told
        // `Fault::Contract`/`UnknownRemainder` for the abandoned write.
        let mut slot = LuImpl::new(ProbeLong::new(ProbeMode::SettleIo), 1u8);
        let mut runner = Runner::new();
        let mut storage = HoldStorage::new(usize::MAX);
        let mut bank = [0u8; 64];
        let mut other = [0u8; 64];

        // Entry 1 issues the write and retains the stalled token.
        let info = runner
            .poll_long_entry(0, &mut slot, &mut storage, &mut bank)
            .expect("first entry");
        assert_eq!(info.phase, LongPhase::Foreground);
        assert_eq!(storage.begins, 1);
        assert_eq!(storage.cancels, 0);
        assert!(runner.long_pending.is_some());

        // Entry 2 must not re-borrow a different bank: cancel once, then settle
        // the abandoned write through the bounded contract path.
        assert_eq!(
            runner.poll_long_entry(0, &mut slot, &mut storage, &mut other),
            Err(Fault::Contract)
        );
        assert_eq!(storage.begins, 1, "the operation is never re-issued");
        assert_eq!(storage.cancels, 1, "the retained token is cancelled once");
        assert!(runner.long_pending.is_none(), "no adapter slot is retained");
        let probe = slot.device_ref();
        assert_eq!(probe.ios, 1, "one write receipt reached the device");
        assert_eq!(
            probe.last_effect,
            Some(Effect::UnknownRemainder),
            "a cancelled write keeps an unknown remainder"
        );
        assert_eq!(probe.interrupts, 1, "exactly one bounded cleanup");
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
