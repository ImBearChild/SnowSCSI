//! Resident long-operation projection.
//!
//! The long-operation state lives in the Device; `poll_long` rebuilds the
//! execution context on every call and persists only this state. The runner
//! keeps the *one* retained adapter token (and the caller's `data` bank
//! identity) beside this projection, keyed to the LUN: `Pending` yields across
//! entries without polling the device, `Ready` is consumed on the next entry.
//! A Target has at most one active long operation, and management is rejected
//! while `phase != Settled`.

use super::errors::Fault;

/// Phase of the resident long operation.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum LongPhase {
    /// No long operation requested.
    Idle,
    /// Running and the medium is not writable yet (only the query commands and
    /// REPORT LUNS are admitted).
    Foreground,
    /// Running but the medium is write accessible; media commands may run.
    ///
    /// Reserved: the current implementation has **only** the foreground
    /// format/blank path. DVD+RW background format is deliberately not
    /// implemented; no production path produces this
    /// variant.
    Background,
    /// Finished; the result is resident until management takes it.
    Settled,
}

/// Read-only projection of a device's long operation.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct LongInfo {
    /// Current phase.
    pub phase: LongPhase,
    /// Whether the foreground gate has been lifted.
    pub write_accessible: bool,
    /// Meaningful progress only; `None` when not applicable.
    ///
    /// `Some(100)` is observable only when `phase == Settled && error.is_none()`.
    /// A foreground fill whose final durability sync is still pending reports
    /// `Some(99)`; a failed settle carries the real progress reached at the
    /// failure (`< 100`, or `None` when no progress is meaningful).
    pub progress: Option<u32>,
    /// Terminal error, if the operation settled abnormally.
    pub error: Option<Fault>,
}

impl LongInfo {
    /// Idle, write accessible, no progress and no error.
    pub const IDLE: LongInfo = LongInfo {
        phase: LongPhase::Idle,
        write_accessible: true,
        progress: None,
        error: None,
    };
}

impl Default for LongInfo {
    fn default() -> Self {
        Self::IDLE
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn idle_projection_matches_default() {
        let idle = LongInfo::IDLE;
        assert_eq!(idle, LongInfo::default());
        assert_eq!(idle.phase, LongPhase::Idle);
        assert!(idle.write_accessible);
        assert_eq!(idle.progress, None);
        assert_eq!(idle.error, None);
    }

    #[test]
    fn foreground_progress_is_reported() {
        let info = LongInfo {
            phase: LongPhase::Foreground,
            write_accessible: false,
            progress: Some(64),
            error: None,
        };
        assert_eq!(info.progress, Some(64));
        assert!(!info.write_accessible);
        assert_ne!(info.phase, LongPhase::Settled);
    }
}
