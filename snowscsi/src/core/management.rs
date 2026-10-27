//! Management values: pending changes, transaction results, slot projections
//! and boundary rejects.
//!
//! Authority: `__ARCH__/design/02-api-core.md` §4.7/§4.10/§4.11 and
//! `__ARCH__/design/02-api.md` §4.3.
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
    /// Whether a removal lock (normal or persistent) is set.
    pub locked: bool,
    /// Command + long-operation projection only; not an authority.
    pub boundary: bool,
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
    /// [`Self::EjectPending`] (`§4.11`).
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
            locked: false,
            boundary: true,
        };
        assert!(info.ready);
        assert!(info.boundary);
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
