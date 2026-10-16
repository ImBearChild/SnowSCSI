//! Shell loops for the USB BOT core.
//!
//! [`serve`] owns the synchronous platform loop that used to live in the CLI:
//! it polls the control plane, executes the [`BotSession`]'s next [`Action`]
//! exactly once over the [`BotIo`] seam (or over a [`Luns`] storage plane for
//! [`Action::Store`]), and feeds the completion back as an [`Event`]. The
//! platform only implements the two seams ([`BotIo`] / [`Gadget`]); it carries
//! no protocol knowledge.
//!
//! `serve_async` (feature `async-io`) is the asynchronous mirror: the same
//! control plane and the same event/action contract, but the bulk seam is
//! awaited (`AsyncBotRecv` / `AsyncBotSend`) and an [`Action::Store`] runs on
//! an `AsyncStorePlane`. It is serial — one operation is awaited at a time —
//! and drains the control plane after every await so a reset supersedes the
//! in-flight completion. Both loops share [`handle_ctrl`], so reset and
//! Get Max LUN behave identically.
//!
//! Platform quirks (e.g. the Linux FunctionFS aio receive needing an
//! MPS-multiple buffer) live in the platform's `BotIo` implementation, not
//! here — the loops are platform-agnostic.

use core::sync::atomic::{AtomicBool, Ordering};
use core::time::Duration;

use crate::scsi::device::ScsiDevice;
use crate::scsi::Luns;
use crate::usb::gadget::{CtrlAck, CtrlReply, CtrlReq, Gadget};
use crate::usb::io::{BotIo, BotIoErr};
use crate::usb::target::{Action, BotSession, BotTargetError, Event, ShortfallPolicy};

#[cfg(feature = "async-io")]
use crate::common::async_store::AsyncStorePlane;
#[cfg(feature = "async-io")]
use crate::scsi::AsyncLuns;
#[cfg(feature = "async-io")]
use crate::usb::async_io::{AsyncBotRecv, AsyncBotSend, RecvMode};

/// Serve-loop receive granularity: bounds the control-pipe / stop-flag check
/// latency between bulk receives (mirrors the PC driver's 50ms ctrl poll).
const BOT_POLL_GRANULARITY: Duration = Duration::from_millis(50);

/// Asynchronous serve-loop receive granularity: the bounded wait used for a
/// non-probe bulk-OUT receive, so a silent host cannot pin the loop away from
/// the control plane and the stop flag. Mirrors [`BOT_POLL_GRANULARITY`].
#[cfg(feature = "async-io")]
const CTRL_POLL_GRANULARITY: Duration = BOT_POLL_GRANULARITY;

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

/// Handle **one** pending control request, if any.
///
/// `ev` is the completion carried to the core: [`CtrlReq::BotReset`] /
/// [`CtrlReq::LinkReset`] replace it with [`Event::Tick`] (the reset cancels
/// any pending completion), while [`CtrlReq::GetMaxLun`] leaves it untouched.
/// Returns `true` when a request was handled (the caller should check again),
/// `false` when none is pending.
///
/// Shared by the synchronous and asynchronous shell loops so their control
/// plane behavior is identical.
fn handle_ctrl<G: for<'a> Gadget<'a>>(
    gadget: &mut G,
    session: &mut BotSession,
    work: &mut [u8],
    devs: &mut [&mut dyn ScsiDevice],
    ev: &mut Event,
) -> Result<bool, ServeError> {
    let Some(req) = gadget.try_next_ctrl() else {
        return Ok(false);
    };
    match req {
        CtrlReq::BotReset { ack } => {
            let _ = session.poll(Event::Reset, work, devs);
            ack.ack();
            // Reset cancels any pending completion.
            *ev = Event::Tick;
        }
        CtrlReq::GetMaxLun { mut reply } => {
            reply
                .send(&[session.max_lun()])
                .map_err(|_| ServeError::Control)?;
        }
        CtrlReq::LinkReset => {
            let _ = session.poll(Event::Reset, work, devs);
            *ev = Event::Tick;
        }
    }
    Ok(true)
}

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
        if handle_ctrl(gadget, session, work, devs, &mut ev)? {
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

/// Asynchronous serial shell: the awaited mirror of [`serve`].
///
/// Same control plane, same event/action contract, same reset semantics — but
/// the bulk seam is awaited ([`AsyncBotRecv`] / [`AsyncBotSend`]) and an
/// [`Action::Store`] runs on an [`AsyncStorePlane`]. One operation is in
/// flight at a time (no overlap), and the control plane is drained after every
/// await so a reset that arrives while an I/O is in flight supersedes the
/// in-flight completion (the completion is discarded and `Event::Tick`
/// carried instead).
///
/// `work` is the time-multiplexed data buffer (as in [`serve`]); `scratch` is
/// reserved for read-ahead overlap and unused here. `luns` is the aligned
/// device/plane bundle, destructured for disjoint borrows. A `Short` session
/// whose transport cannot STALL Bulk-In is rejected up front
/// ([`ServeError::PolicyNeedsStall`]), exactly like the synchronous loop.
#[cfg(feature = "async-io")]
#[allow(clippy::too_many_arguments)]
pub async fn serve_async<R, S, G, P>(
    recv: &mut R,
    send: &mut S,
    gadget: &mut G,
    session: &mut BotSession,
    work: &mut [u8],
    scratch: &mut [u8],
    luns: &mut AsyncLuns<'_, P>,
    stop: &AtomicBool,
) -> Result<(), ServeError>
where
    R: AsyncBotRecv,
    S: AsyncBotSend,
    G: for<'a> Gadget<'a>,
    P: AsyncStorePlane,
{
    // Read-ahead scratch is not used by the serial loop.
    let _ = scratch;

    // Disjoint borrows: `devs` is handed to `poll`, `planes` executes
    // `Action::Store` ops without aliasing the device slice.
    let AsyncLuns { devs, planes } = luns;

    // A `Short` session needs a Bulk-In STALL; reject a transport that cannot
    // do it before entering the loop (same up-front check as `serve`).
    if session.shortfall() == ShortfallPolicy::Short && !send.can_stall_in() {
        return Err(ServeError::PolicyNeedsStall);
    }

    let mut ev = Event::Tick;
    loop {
        if stop.load(Ordering::Relaxed) {
            return Ok(());
        }

        // 1) Control plane first (arrives at any time, even mid data phase).
        if handle_ctrl(gadget, session, work, devs, &mut ev)? {
            continue;
        }

        // 2) Feed the carried event, execute the returned action, and carry
        // the completion in `ev`.
        match session.poll(ev, work, devs) {
            Action::HostRecv { len, probe } => {
                if probe {
                    // Non-blocking overrun drain: one try, then HostIdle ends it.
                    ev = match recv.recv_probe(&mut work[..len]).await {
                        Ok(0) => return Err(ServeError::Closed),
                        Ok(n) => Event::HostRecv { len: n },
                        Err(BotIoErr::WouldBlock) => Event::HostIdle,
                        Err(BotIoErr::Disconnected) => Event::Reset,
                        Err(BotIoErr::Io) => return Err(ServeError::Closed),
                    };
                } else {
                    ev = match recv
                        .recv(&mut work[..len], RecvMode::Until(CTRL_POLL_GRANULARITY))
                        .await
                    {
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
                ev = match send.send(bytes).await {
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
                    .and_then(Option::as_mut)
                    .ok_or(ServeError::Internal)?
                    .do_op(op)
                    .await;
                ev = Event::StoreDone { result };
            }
            Action::StallBoth => {
                // Invalid CBW: STALL both pipes (ignore a missing capability).
                let _ = recv.stall_both().await;
                ev = Event::Tick;
            }
            Action::StallIn => {
                ev = match send.stall_in().await {
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

        // A control request can arrive while an I/O await is in flight. Drain
        // it now, before the completion is fed back, so a reset supersedes the
        // just-completed I/O (its event is replaced by `Event::Tick`).
        while !stop.load(Ordering::Relaxed) {
            if !handle_ctrl(gadget, session, work, devs, &mut ev)? {
                break;
            }
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

    // ── Asynchronous shell ──────────────────────────────────────────────

    /// Minimal single-threaded executor: poll to completion with a no-op
    /// waker. The stubs below never actually yield, so a single poll suffices;
    /// the loop is kept general.
    #[cfg(feature = "async-io")]
    fn block_on<F: core::future::Future>(fut: F) -> F::Output {
        let mut fut = core::pin::pin!(fut);
        let mut cx = core::task::Context::from_waker(core::task::Waker::noop());
        loop {
            if let core::task::Poll::Ready(v) = fut.as_mut().poll(&mut cx) {
                return v;
            }
        }
    }

    /// Asynchronous bulk-OUT stub: never has data.
    #[cfg(feature = "async-io")]
    struct StubAsyncRecv;

    #[cfg(feature = "async-io")]
    impl AsyncBotRecv for StubAsyncRecv {
        async fn recv(&mut self, _buf: &mut [u8], _mode: RecvMode) -> Result<usize, BotIoErr> {
            Err(BotIoErr::WouldBlock)
        }
    }

    /// Asynchronous bulk-IN stub with a configurable STALL capability.
    #[cfg(feature = "async-io")]
    struct StubAsyncSend {
        can_stall: bool,
    }

    #[cfg(feature = "async-io")]
    impl AsyncBotSend for StubAsyncSend {
        async fn send(&mut self, _buf: &[u8]) -> Result<(), BotIoErr> {
            Ok(())
        }

        fn can_stall_in(&self) -> bool {
            self.can_stall
        }
    }

    /// Plane stub: accepts every op.
    #[cfg(feature = "async-io")]
    struct StubPlane;

    #[cfg(feature = "async-io")]
    impl AsyncStorePlane for StubPlane {
        async fn do_op(
            &mut self,
            _op: crate::common::store::StoreOp<'_>,
        ) -> Result<(), crate::common::seekable_storage::StorageError> {
            Ok(())
        }

        async fn sync(&mut self) -> Result<(), crate::common::seekable_storage::StorageError> {
            Ok(())
        }
    }

    /// Drive `serve_async` with `stop` already set: the policy check runs
    /// before the loop, so a compatible combination returns `Ok(())`
    /// immediately and an incompatible one is rejected up front.
    #[cfg(feature = "async-io")]
    fn run_async(
        policy: ShortfallPolicy,
        can_stall: bool,
        stop_set: bool,
    ) -> Result<(), ServeError> {
        let mut recv = StubAsyncRecv;
        let mut send = StubAsyncSend { can_stall };
        let mut gadget = NoGadget;
        let mut session = BotSession::new().with_shortfall(policy);
        let mut work = [0u8; crate::MIN_DATA_LEN];
        let mut scratch = [0u8; crate::MIN_DATA_LEN];
        let mut luns: AsyncLuns<'_, StubPlane> = AsyncLuns::new(&mut [], &mut []);
        let stop = AtomicBool::new(stop_set);
        block_on(serve_async(
            &mut recv,
            &mut send,
            &mut gadget,
            &mut session,
            &mut work,
            &mut scratch,
            &mut luns,
            &stop,
        ))
    }

    #[cfg(feature = "async-io")]
    #[test]
    fn async_short_policy_without_stall_capability_is_rejected() {
        assert_eq!(
            run_async(ShortfallPolicy::Short, false, false),
            Err(ServeError::PolicyNeedsStall)
        );
    }

    #[cfg(feature = "async-io")]
    #[test]
    fn async_short_policy_with_stall_capability_is_accepted() {
        assert_eq!(run_async(ShortfallPolicy::Short, true, true), Ok(()));
    }
}
