//! Eject policy: host-command versus operator/control-plane origin.
//!
//! The host's own EJECT is its explicit choice and is not blocked by its own
//! PREVENT latch; performing it clears the **normal** (never the persistent)
//! latch. An operator/control-plane eject is exactly what PREVENT protects
//! against, so any lock set rejects it with `05/53/02`.

use super::errors::{Completion, MEDIUM_REMOVAL_PREVENTED};

/// Who requested the eject.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum EjectOrigin {
    /// The host's own EJECT command.
    HostCommand,
    /// Operator/control-plane eject (GUI, hardware button, CLI).
    Operator,
}

/// The two independent removal latches.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct RemovalLocks {
    /// Normal PREVENT latch (cleared by a successful host eject).
    pub prevent: bool,
    /// Persistent PREVENT latch (never implicitly cleared).
    pub persistent_prevent: bool,
}

/// Result of the eject policy decision.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct EjectDecision {
    /// Whether the eject may proceed.
    pub allowed: bool,
    /// Whether the successful eject clears the normal PREVENT latch.
    pub clear_normal_prevent: bool,
    /// Completion to return for the eject request.
    pub completion: Completion,
}

/// Decide an eject request from the current locks and the requesting origin.
///
/// - Host command: always allowed; clears the normal latch if it was set.
///   The persistent latch is untouched.
/// - Operator: any lock rejects with `05/53/02`; otherwise allowed.
#[must_use]
pub const fn decide_eject(locks: RemovalLocks, origin: EjectOrigin) -> EjectDecision {
    match origin {
        EjectOrigin::HostCommand => EjectDecision {
            allowed: true,
            clear_normal_prevent: locks.prevent,
            completion: Completion::Good,
        },
        EjectOrigin::Operator => {
            if locks.prevent || locks.persistent_prevent {
                EjectDecision {
                    allowed: false,
                    clear_normal_prevent: false,
                    completion: Completion::Check(MEDIUM_REMOVAL_PREVENTED),
                }
            } else {
                EjectDecision {
                    allowed: true,
                    clear_normal_prevent: false,
                    completion: Completion::Good,
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::core::errors::Sense;

    const NONE: RemovalLocks = RemovalLocks {
        prevent: false,
        persistent_prevent: false,
    };
    const NORMAL: RemovalLocks = RemovalLocks {
        prevent: true,
        persistent_prevent: false,
    };
    const PERSISTENT: RemovalLocks = RemovalLocks {
        prevent: false,
        persistent_prevent: true,
    };
    const BOTH: RemovalLocks = RemovalLocks {
        prevent: true,
        persistent_prevent: true,
    };

    #[test]
    fn host_command_ignores_locks_and_clears_normal() {
        for locks in [NONE, NORMAL, PERSISTENT, BOTH] {
            let decision = decide_eject(locks, EjectOrigin::HostCommand);
            assert!(decision.allowed);
            assert_eq!(decision.completion, Completion::Good);
            assert_eq!(decision.clear_normal_prevent, locks.prevent);
        }
    }

    #[test]
    fn operator_without_locks_is_allowed() {
        let decision = decide_eject(NONE, EjectOrigin::Operator);
        assert!(decision.allowed);
        assert!(!decision.clear_normal_prevent);
        assert_eq!(decision.completion, Completion::Good);
    }

    #[test]
    fn operator_is_rejected_by_either_lock() {
        for locks in [NORMAL, PERSISTENT, BOTH] {
            let decision = decide_eject(locks, EjectOrigin::Operator);
            assert!(!decision.allowed);
            assert!(!decision.clear_normal_prevent);
            assert_eq!(
                decision.completion,
                Completion::Check(MEDIUM_REMOVAL_PREVENTED)
            );
            assert_eq!(MEDIUM_REMOVAL_PREVENTED, Sense::new(0x05, 0x53, 0x02));
        }
    }

    #[test]
    fn removal_locks_default_is_unlocked() {
        assert_eq!(RemovalLocks::default(), NONE);
    }
}
