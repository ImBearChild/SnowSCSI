//! Management values: pending changes, transaction results, slot projections
//! and boundary rejects.
//!
//! These are pure values. They do not implement the management transaction;
//! `Target`/`Runner` own that state machine.

use super::errors::{Delivery, Fault, KnownEffects};
use super::long::LongInfo;

/// A requested management change of a slot's pair.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Change<P> {
    /// Install a pair into an empty slot.
    Install(P),
    /// Replace the current pair with the candidate.
    Replace(P),
    /// Remove the current pair.
    Remove,
}

/// The single result of a management transaction, taken exactly once.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ChangeResult<P> {
    /// Detached/returned pair, if the transaction produced one.
    pub pair: Option<P>,
    /// Local transaction failure (commit/detach/install/restore) only.
    pub local: Result<(), Fault>,
    /// Delivery state when the result was produced (host-eject transactions).
    pub delivery: Delivery,
    /// Confirmed write/durable facts; not a success flag.
    pub effects: KnownEffects,
}

/// Read-only projection of a slot. It is **not** the authoritative boundary:
/// the runner also checks required/speculative IO, retained input, unconsumed
/// completion and the live execution borrow.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct LuInfo {
    /// Long-operation projection.
    pub long: LongInfo,
    /// Whether the slot can accept commands.
    pub ready: bool,
    /// Normal PREVENT latch (cleared by a successful host eject).
    pub prevent: bool,
    /// Persistent PREVENT latch (never implicitly cleared).
    pub persistent_prevent: bool,
    /// Command + long-operation projection only; not an authority.
    pub boundary: bool,
}

impl LuInfo {
    /// Whether either removal lock is set. This is the derived view; the two
    /// latches stay separately observable so a host eject (normal cleared,
    /// persistent kept) is distinguishable from an unlocked slot.
    #[must_use]
    pub const fn is_locked(&self) -> bool {
        self.prevent || self.persistent_prevent
    }
}

/// Why a management/boundary-dependent operation was refused.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum BoundaryReject {
    /// A command is still active on the slot.
    CommandActive,
    /// Required storage IO is still in flight.
    RequiredIoInFlight,
    /// Speculative prefetch IO is still in flight.
    SpeculativeIoInFlight,
    /// Retained inbound bytes have not been consumed.
    RetainedInput,
    /// A fixed completion has not been consumed.
    UnconsumedCompletion,
    /// An execution borrow guard is alive.
    ExecutionBorrowAlive,
    /// A long operation has not settled.
    LongOperationActive,
    /// A control request is queued.
    ControlPending,
    /// A host-eject transaction is in flight and produced no result yet
    /// (AwaitDelivery); `take` has nothing to hand back.
    EjectPending,
    /// A detached result is resident and must be taken; this is distinct from
    /// [`Self::EjectPending`].
    AwaitingResourceTake,
    /// The target has ended its lifecycle.
    Ended,
    /// No result is resident to take.
    NothingToTake,
    /// The LUN is outside this target's fixed slot set.
    WrongSlot,
    /// The permit belongs to another target.
    ForeignBoundary,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn change_and_result_are_plain_values() {
        let change = Change::Replace(7u8);
        assert_eq!(change, Change::Replace(7));
        assert_ne!(change, Change::Remove);

        let result: ChangeResult<u8> = ChangeResult {
            pair: Some(3),
            local: Ok(()),
            delivery: Delivery::Complete,
            effects: KnownEffects::NONE,
        };
        assert_eq!(result.pair, Some(3));
        assert_eq!(result.local, Ok(()));
        assert_eq!(result.effects, KnownEffects::NONE);
    }

    #[test]
    fn lu_info_is_a_projection() {
        let info = LuInfo {
            long: LongInfo::IDLE,
            ready: true,
            prevent: false,
            persistent_prevent: false,
            boundary: true,
        };
        assert!(info.ready);
        assert!(info.boundary);
        assert!(!info.is_locked());
        assert_eq!(info.long, LongInfo::IDLE);
    }

    #[test]
    fn boundary_rejects_are_distinct() {
        assert_ne!(BoundaryReject::WrongSlot, BoundaryReject::NothingToTake);
        assert_ne!(BoundaryReject::Ended, BoundaryReject::EjectPending);
        assert_ne!(
            BoundaryReject::EjectPending,
            BoundaryReject::AwaitingResourceTake
        );
    }
}
