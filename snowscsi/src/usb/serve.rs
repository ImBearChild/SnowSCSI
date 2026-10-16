//! Synchronous shell loop for the USB BOT core.
//!
//! [`serve`] owns the platform loop that used to live in the CLI: it polls the
//! control plane, executes the [`BotSession`]'s next [`Action`] exactly once
//! over the [`BotIo`] seam (or over a [`Luns`] storage plane for
//! [`Action::Store`]), and feeds the completion back as an [`Event`]. The
//! platform only implements the two seams ([`BotIo`] / [`Gadget`]); it carries
//! no protocol knowledge.
//!
//! Platform quirks (e.g. the Linux FunctionFS aio receive needing an
//! MPS-multiple buffer) live in the platform's `BotIo` implementation, not
//! here — `serve` is platform-agnostic.

use core::sync::atomic::{AtomicBool, Ordering};
use core::time::Duration;

use crate::scsi::Luns;
use crate::usb::gadget::{CtrlAck, CtrlReply, CtrlReq, Gadget};
use crate::usb::io::{BotIo, BotIoErr};
use crate::usb::target::{Action, BotSession, BotTargetError, Event, ShortfallPolicy};

/// Serve-loop receive granularity: bounds the control-pipe / stop-flag check
/// latency between bulk receives (mirrors the PC driver's 50ms ctrl poll).
const BOT_POLL_GRANULARITY: Duration = Duration::from_millis(50);

/// Error returned by [`serve`] (no_std).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ServeError {
    /// The bulk link closed (zero-length receive or unrecoverable I/O).
    Closed,
    /// The BOT core reported an error.
    Core(BotTargetError),
    /// The control-plane reply (Get Max LUN) failed.
    Control,
    /// A `Store` addressed a LUN with no storage plane (`planes[lun] == None`
    /// or an out-of-range LUN).
    Internal,
    /// The session's `Short` Data-In shortfall policy needs a Bulk-In STALL
    /// but the transport cannot STALL.
    PolicyNeedsStall,
}

impl core::fmt::Display for ServeError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::Closed => write!(f, "bulk link closed"),
            Self::Core(e) => write!(f, "BOT core error: {e}"),
            Self::Control => write!(f, "control-plane reply failed"),
            Self::Internal => write!(f, "internal BOT serve error"),
            Self::PolicyNeedsStall => {
                write!(
                    f,
                    "shortfall policy needs a Bulk-In STALL the transport cannot do"
                )
            }
        }
    }
}

impl core::error::Error for ServeError {}

/// Serve a USB BOT session until `stop` is set.
///
/// Each turn polls the control plane first ([`CtrlReq::BotReset`] /
/// [`CtrlReq::LinkReset`] ⇒ [`Event::Reset`] + ack; [`CtrlReq::GetMaxLun`] ⇒
/// reply `session.max_lun()`), then executes the pending [`Action`] once.
/// `work` is the single time-multiplexed buffer (see [`BotSession::poll`]);
/// `luns` is the aligned device/plane pair (destructured for disjoint borrows,
/// so a `Store` op that borrows the device can be executed against the plane).
///
/// `Action::StallBoth` (invalid CBW) STALLs both endpoints and keeps receiving:
/// the core has already returned to the Command phase and a new CBW clears the
/// halt, so there is **no** `stalled` gate (the fix for the invalid-CBW wedge).
pub fn serve<B: BotIo, G: for<'a> Gadget<'a>>(
    io: &mut B,
    gadget: &mut G,
    session: &mut BotSession,
    work: &mut [u8],
    luns: &mut Luns<'_>,
    stop: &AtomicBool,
) -> Result<(), ServeError> {
    // Disjoint borrows: `devs` is handed to `poll`/`store_done`, `planes` is
    // used to execute `Action::Store` ops (whose buffer/path may borrow the
    // device) without aliasing the device slice.
    let Luns { devs, planes } = luns;

    // A `Short` session needs a Bulk-In STALL; a transport that cannot do it
    // would only degrade into a reset storm, so reject the mismatch up front.
    if session.shortfall() == ShortfallPolicy::Short && !io.can_stall_in() {
        return Err(ServeError::PolicyNeedsStall);
    }

    // Carry the completion to feed the core. `Event::Tick` re-emits the
    // current pending `Action` without changing state, so a turn whose outcome
    // is "nothing new" (a stall, a receive timeout) carries `Tick` and the
    // next `poll` re-emits the pending action.
    let mut ev = Event::Tick;
    loop {
        if stop.load(Ordering::Relaxed) {
            return Ok(());
        }

        // 1) Control plane first (arrives at any time, even mid data phase).
        if let Some(req) = gadget.try_next_ctrl() {
            match req {
                CtrlReq::BotReset { ack } => {
                    let _ = session.poll(Event::Reset, work, devs);
                    ack.ack();
                    // Reset cancels any pending completion.
                    ev = Event::Tick;
                }
                CtrlReq::GetMaxLun { mut reply } => {
                    reply
                        .send(&[session.max_lun()])
                        .map_err(|_| ServeError::Control)?;
                }
                CtrlReq::LinkReset => {
                    let _ = session.poll(Event::Reset, work, devs);
                    ev = Event::Tick;
                }
            }
            continue;
        }

        // 2) Feed the carried event and execute the returned `Action` exactly
        // once. The action is the *result* of the event, so a transient
        // `StallBoth` / `Error` is executed here (re-fetching via `Tick` would
        // lose it); the next completion is carried in `ev`.
        match session.poll(ev, work, devs) {
            Action::HostRecv { len, probe } => {
                if probe {
                    // Non-blocking overrun drain: one try, then HostIdle ends it.
                    ev = match io.try_recv_out(&mut work[..len]) {
                        Ok(0) => return Err(ServeError::Closed),
                        Ok(n) => Event::HostRecv { len: n },
                        Err(BotIoErr::WouldBlock) => Event::HostIdle,
                        Err(BotIoErr::Disconnected) => Event::Reset,
                        Err(BotIoErr::Io) => return Err(ServeError::Closed),
                    };
                } else {
                    ev = match io.recv_out(&mut work[..len], Some(BOT_POLL_GRANULARITY)) {
                        Ok(0) => return Err(ServeError::Closed),
                        Ok(n) => Event::HostRecv { len: n },
                        // Timeout: re-check the control plane and stop flag.
                        Err(BotIoErr::WouldBlock) => Event::Tick,
                        Err(BotIoErr::Disconnected) => Event::Reset,
                        Err(BotIoErr::Io) => return Err(ServeError::Closed),
                    };
                }
            }
            Action::HostSend { bytes, .. } => {
                ev = match io.send_in(bytes) {
                    Ok(()) => Event::HostSent,
                    Err(BotIoErr::Disconnected) => Event::Reset,
                    Err(_) => return Err(ServeError::Closed),
                };
            }
            Action::Store { lun, op } => {
                // Execute the storage op on the LUN's plane and hand the result
                // back to the core (which maps it via `store_done`). A `Store`
                // on a self-backed / out-of-range LUN is an internal error.
                let result = planes
                    .get_mut(lun)
                    .and_then(|plane| plane.as_mut())
                    .ok_or(ServeError::Internal)?
                    .do_op(op);
                ev = Event::StoreDone { result };
            }
            Action::StallBoth => {
                // Invalid CBW: STALL both pipes (ignore a missing capability).
                // The core is back in the Command phase; keep receiving — a
                // new CBW arriving means the halt has been cleared (no
                // `stalled` gate).
                let _ = io.stall_both();
                ev = Event::Tick;
            }
            Action::StallIn => {
                ev = match io.stall_in() {
                    Ok(()) => {
                        // The host's CLEAR_FEATURE is handled by the USB core;
                        // the withheld CSW is released immediately.
                        Event::StallApplied
                    }
                    // A `Short`-without-`stall_in` mismatch aborts
                    // deterministically (reset drops the withheld CSW).
                    Err(()) => Event::Reset,
                };
            }
            Action::Error(e) => return Err(ServeError::Core(e)),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::usb::gadget::{CtrlAck, CtrlReply};

    /// Minimal bulk driver with a configurable STALL capability.
    struct StubIo {
        can_stall: bool,
    }

    impl BotIo for StubIo {
        fn try_recv_out(&mut self, _buf: &mut [u8]) -> Result<usize, BotIoErr> {
            Err(BotIoErr::WouldBlock)
        }

        fn recv_out(
            &mut self,
            _buf: &mut [u8],
            _timeout: Option<Duration>,
        ) -> Result<usize, BotIoErr> {
            Err(BotIoErr::WouldBlock)
        }

        fn send_in(&mut self, _buf: &[u8]) -> Result<(), BotIoErr> {
            Ok(())
        }

        fn can_stall_in(&self) -> bool {
            self.can_stall
        }
    }

    /// Ack handle that does nothing.
    struct NoAck;
    impl CtrlAck for NoAck {
        fn ack(self) {}
    }

    /// Reply handle that accepts anything.
    struct NoReply;
    impl CtrlReply for NoReply {
        fn send(&mut self, _data: &[u8]) -> Result<(), ()> {
            Ok(())
        }
    }

    /// Gadget that never surfaces a control request.
    struct NoGadget;
    impl<'a> Gadget<'a> for NoGadget {
        type Ack = NoAck;
        type Reply = NoReply;

        fn try_next_ctrl(&'a mut self) -> Option<CtrlReq<NoAck, NoReply>> {
            None
        }
    }

    /// Drive `serve` with `stop` already set: the policy check runs before the
    /// loop, so a compatible combination returns `Ok(())` immediately and an
    /// incompatible one is rejected up front.
    fn run(policy: ShortfallPolicy, can_stall: bool, stop_set: bool) -> Result<(), ServeError> {
        let mut io = StubIo { can_stall };
        let mut gadget = NoGadget;
        let mut session = BotSession::new().with_shortfall(policy);
        let mut work = [0u8; crate::MIN_DATA_LEN];
        let mut luns = Luns::new(&mut [], &mut []);
        let stop = AtomicBool::new(stop_set);
        serve(
            &mut io,
            &mut gadget,
            &mut session,
            &mut work,
            &mut luns,
            &stop,
        )
    }

    #[test]
    fn short_policy_without_stall_capability_is_rejected() {
        assert_eq!(
            run(ShortfallPolicy::Short, false, false),
            Err(ServeError::PolicyNeedsStall)
        );
    }

    #[test]
    fn short_policy_with_stall_capability_is_accepted() {
        assert_eq!(run(ShortfallPolicy::Short, true, true), Ok(()));
    }

    #[test]
    fn non_short_policy_without_stall_capability_is_accepted() {
        assert_eq!(run(ShortfallPolicy::ShortNoStall, false, true), Ok(()));
    }
}
