//! Service-loop vocabulary shared by the transports.
//!
//! A transport loop owns **no** device lifetime. It returns to the application
//! at every point the application may have to act on the [`Target`](super::Target)
//! and leaves the target reusable; only the application decides when a target
//! is finished ([`Target::stop`](super::Target::stop)) or when a transport
//! session is really gone.
//!
//! [`Flow`] is the application → loop direction: a runtime-free, single-word
//! request checked at every loop turn. It is deliberately not a callback and
//! not a new protocol state: the loop only reads it between turns.
//!
//! [`ServeExit`] is the loop → application direction. `Err` from a transport
//! loop always means a caller bug (work buffer too small, impossible state),
//! never an ordinary link loss: that is [`ServeExit::WireGone`].

use ::core::sync::atomic::{AtomicU8, Ordering};

use super::runner::RunOutcome;

/// What the application wants a transport loop to do next.
///
/// `Run` is the default; `Pause` is a request to stop at the next management
/// boundary and hand the target back (the loop never returns mid-command);
/// `Stop` ends the loop after settling any live command.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum FlowState {
    /// Keep serving.
    Run,
    /// Return [`ServeExit::Paused`] at the next management boundary.
    Pause,
    /// Return [`ServeExit::Stopped`] and end the loop.
    Stop,
}

/// A single-word, `no_std`-friendly flow request.
///
/// The loop reads it with `Relaxed` ordering: it is a request, not a
/// synchronisation primitive, and one extra loop turn is harmless.
#[derive(Debug)]
pub struct Flow(AtomicU8);

impl Flow {
    /// A flow that keeps serving.
    #[must_use]
    pub const fn new() -> Self {
        Self(AtomicU8::new(0))
    }

    /// Keep serving.
    pub fn run(&self) {
        self.0.store(0, Ordering::Relaxed);
    }

    /// Return at the next management boundary.
    pub fn pause(&self) {
        self.0.store(1, Ordering::Relaxed);
    }

    /// End the loop after settling any live command.
    pub fn stop(&self) {
        self.0.store(2, Ordering::Relaxed);
    }

    /// Current request.
    #[must_use]
    pub fn state(&self) -> FlowState {
        match self.0.load(Ordering::Relaxed) {
            1 => FlowState::Pause,
            2 => FlowState::Stop,
            _ => FlowState::Run,
        }
    }
}

impl Default for Flow {
    fn default() -> Self {
        Self::new()
    }
}

/// Why a transport loop returned.
///
/// On **every** variant the loop leaves no live command behind: `Paused` and
/// `Outcome` are only returned at a point where no I/O is in flight (the
/// pending action is re-emitted on re-entry), while `Stopped` and `WireGone`
/// settle one first. The target is therefore always safe to manage or to serve
/// again.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ServeExit {
    /// The application asked to pause and the target reached a management
    /// boundary. Act on the target, then call the loop again.
    Paused,
    /// The application asked to stop. The live command (if any) was settled;
    /// the target itself was not stopped and may be served again.
    Stopped,
    /// The core needs the application: a pair awaits a take
    /// ([`RunOutcome::ResourcesReady`]), a control was applied, or the target
    /// ended (fatal or `Target::stop`).
    Outcome(RunOutcome),
    /// The transport link is gone. The live command was settled; the same
    /// target is reusable when the link comes back.
    WireGone,
}
