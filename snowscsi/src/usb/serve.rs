//! Shell loops for the USB BOT core.
//!
//! [`serve`] owns the synchronous platform loop: it polls the control plane,
//! executes the [`BotSession`]'s next [`Action`] exactly once over the
//! [`BotIo`] seam, and feeds the completion back as an [`Event`]. The platform
//! only implements the two seams ([`BotIo`] / [`Gadget`]); it carries no
//! protocol knowledge. Storage I/O happens inside the core [`Target`] through
//! the [`Storage`] adapter, so the shell never sees a device operation.
//!
//! `serve_async` (feature `async-io`) is the asynchronous mirror: the same
//! control plane and the same event/action contract, but the bulk seam is
//! awaited (`AsyncBotRecv` / `AsyncBotSend`). It still performs one command
//! step per entry; storage I/O is the core's and cannot be overlapped by the
//! shell. Both loops share `handle_ctrl`, so reset and Get Max LUN behave
//! identically.
//!
//! Platform quirks (e.g. the Linux FunctionFS aio receive needing an
//! MPS-multiple buffer) live in the platform's `BotIo` implementation, not
//! here — the loops are platform-agnostic.

use core::sync::atomic::{AtomicBool, Ordering};
use core::time::Duration;

use crate::core::storage::Storage;
use crate::core::{RuntimeSet, Target};
use crate::usb::gadget::{CtrlAck, CtrlReply, CtrlReq, Gadget};
use crate::usb::io::{BotIo, BotIoErr};
use crate::usb::target::{Action, BotSession, BotTargetError, Event, ShortfallPolicy};

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
    /// The core target is in an unusable terminal state.
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
#[allow(clippy::too_many_arguments)]
fn handle_ctrl<G, S>(
    gadget: &mut G,
    session: &mut BotSession,
    work: &mut [u8],
    scratch: &mut [u8],
    target: &mut Target<S>,
    storage: &mut dyn Storage,
    ev: &mut Event,
) -> Result<bool, ServeError>
where
    G: for<'a> Gadget<'a>,
    S: RuntimeSet,
{
    let Some(req) = gadget.try_next_ctrl() else {
        return Ok(false);
    };
    match req {
        CtrlReq::BotReset { ack } => {
            let _ = session.poll(Event::Reset, work, scratch, target, storage);
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
            let _ = session.poll(Event::Reset, work, scratch, target, storage);
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
/// `work` is the transport data bank (see [`BotSession::poll`]); `scratch` is
/// the long-operation bank, and an **empty** `scratch` selects the shared
/// bank: the loop drives the long operation one `Tick` step per turn and
/// defers bulk and control input while its token is in flight (at most one
/// long-operation chunk). An overlap session keeps both banks inside `work`,
/// so the long operation takes the bank the command is not using and input is
/// **not** deferred. `target` owns the LUN slots and `storage` executes the
/// device's storage operations.
///
/// `Action::StallBoth` (invalid CBW) STALLs both endpoints and keeps receiving:
/// the core has already returned to the Command phase and a new CBW clears the
/// halt, so there is **no** `stalled` gate (the fix for the invalid-CBW wedge).
#[allow(clippy::too_many_arguments)]
pub fn serve<B, G, S>(
    io: &mut B,
    gadget: &mut G,
    session: &mut BotSession,
    work: &mut [u8],
    scratch: &mut [u8],
    target: &mut Target<S>,
    storage: &mut dyn Storage,
    stop: &AtomicBool,
) -> Result<(), ServeError>
where
    B: BotIo,
    G: for<'a> Gadget<'a>,
    S: RuntimeSet,
{
    let result = serve_loop(io, gadget, session, work, scratch, target, storage, stop);
    // Whatever ended the loop, the wire is gone: settle a live command before
    // the slots are served again.
    let _ = target.settle_transport_end(storage, session);
    result
}

#[allow(clippy::too_many_arguments)]
fn serve_loop<B, G, S>(
    io: &mut B,
    gadget: &mut G,
    session: &mut BotSession,
    work: &mut [u8],
    scratch: &mut [u8],
    target: &mut Target<S>,
    storage: &mut dyn Storage,
    stop: &AtomicBool,
) -> Result<(), ServeError>
where
    B: BotIo,
    G: for<'a> Gadget<'a>,
    S: RuntimeSet,
{
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
    // Overlap sessions keep both banks inside `work`; the session allocates the
    // free one to a resident long operation, so input is never deferred for a
    // long token. Shared mode still owns `work` while the token is in flight.
    let shared = scratch.is_empty() && !session.overlap();
    loop {
        if stop.load(Ordering::Relaxed) {
            return Ok(());
        }

        // Shared bank: while the resident long operation holds an adapter
        // token, `work` is its data bank. Drive it one step per turn and defer
        // every input (control requests included) until it settles; the
        // deferral is bounded by one long-operation chunk.
        if shared && target.long_io_in_flight() {
            match session.poll(Event::Tick, work, scratch, target, storage) {
                // Nothing is staged in `work`; the framing action is re-emitted
                // once the token settles.
                Action::HostRecv { .. } => continue,
                // No wire transfer is pending while the command waits on
                // storage; keep the loop turning so the token can settle.
                Action::StoragePending => continue,
                // Data or a stall response is staged in `work`, which the long
                // token owns: dropping it would lose or corrupt output.
                Action::HostSend { .. } | Action::StallBoth | Action::StallIn => {
                    return Err(ServeError::Core(BotTargetError::Internal))
                }
                Action::Error(e) => return Err(ServeError::Core(e)),
            }
        }

        // 1) Control plane first (arrives at any time, even mid data phase).
        if handle_ctrl(gadget, session, work, scratch, target, storage, &mut ev)? {
            continue;
        }

        // 2) Feed the carried event and execute the returned `Action` exactly
        // once. The action is the *result* of the event, so a transient
        // `StallBoth` / `Error` is executed here (re-fetching via `Tick` would
        // lose it); the next completion is carried in `ev`.
        match session.poll(ev, work, scratch, target, storage) {
            Action::HostRecv { .. } if shared && target.long_io_in_flight() => {
                // The step above started the resident long operation; its token
                // now owns `work`. The receive is re-emitted on the next entry,
                // so drop it and drive the long operation first.
                ev = Event::Tick;
                continue;
            }
            Action::HostSend { .. } | Action::StallBoth | Action::StallIn
                if shared && target.long_io_in_flight() =>
            {
                // The output bytes live in `work`, which the long token is
                // using; this state must not be reached.
                return Err(ServeError::Core(BotTargetError::Internal));
            }
            Action::HostRecv { offset, len, probe } => {
                let end = offset + len;
                if end > work.len() {
                    return Err(ServeError::Internal);
                }
                if probe {
                    // Non-blocking overrun drain: one try, then HostIdle ends it.
                    ev = match io.try_recv_out(&mut work[offset..end]) {
                        Ok(0) => return Err(ServeError::Closed),
                        Ok(n) => Event::HostRecv { len: n },
                        Err(BotIoErr::WouldBlock) => Event::HostIdle,
                        Err(BotIoErr::Disconnected) => Event::Reset,
                        Err(BotIoErr::Io) => return Err(ServeError::Closed),
                    };
                } else {
                    ev = match io.recv_out(&mut work[offset..end], Some(BOT_POLL_GRANULARITY)) {
                        Ok(0) => return Err(ServeError::Closed),
                        Ok(n) => Event::HostRecv { len: n },
                        // Timeout: re-check the control plane and stop flag.
                        Err(BotIoErr::WouldBlock) => Event::Tick,
                        Err(BotIoErr::Disconnected) => Event::Reset,
                        Err(BotIoErr::Io) => return Err(ServeError::Closed),
                    };
                }
            }
            Action::HostSend { bytes } => {
                ev = match io.send_in(bytes) {
                    Ok(()) => Event::HostSent,
                    Err(BotIoErr::Disconnected) => Event::Reset,
                    Err(_) => return Err(ServeError::Closed),
                };
            }
            Action::StoragePending => {
                // No wire I/O: retry the command once on the next turn with a
                // no-op tick. The blocking adapter is ready on that poll.
                ev = Event::Tick;
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

/// Asynchronous serve shell: the awaited mirror of [`serve`].
///
/// Same control plane, same event/action contract, same reset semantics — but
/// the bulk seam is awaited ([`AsyncBotRecv`] / [`AsyncBotSend`]). The control
/// plane is drained after every await so a reset that arrives while an I/O is
/// in flight supersedes the in-flight completion (the completion is discarded
/// and `Event::Tick` carried instead).
///
/// Each entry performs one [`BotSession::poll`] step; storage I/O runs inside
/// the core target and is never handed to the shell, so there is no overlap
/// state to carry across awaits.
#[cfg(feature = "async-io")]
#[allow(clippy::too_many_arguments)]
pub async fn serve_async<R, S, G, T>(
    recv: &mut R,
    send: &mut S,
    gadget: &mut G,
    session: &mut BotSession,
    work: &mut [u8],
    scratch: &mut [u8],
    target: &mut Target<T>,
    storage: &mut dyn Storage,
    stop: &AtomicBool,
) -> Result<(), ServeError>
where
    R: AsyncBotRecv,
    S: AsyncBotSend,
    G: for<'a> Gadget<'a>,
    T: RuntimeSet,
{
    // A `Short` session needs a Bulk-In STALL; reject a transport that cannot
    // do it before entering the loop (same up-front check as `serve`).
    if session.shortfall() == ShortfallPolicy::Short && !send.can_stall_in() {
        return Err(ServeError::PolicyNeedsStall);
    }

    let result = async {
        let mut ev = Event::Tick;
        let shared = scratch.is_empty();
        loop {
            if stop.load(Ordering::Relaxed) {
                return Ok(());
            }

            // Shared bank: drive the resident long operation one step per turn
            // and defer every input (control requests included) until its token
            // settles. The deferral is bounded by one long-operation chunk.
            if shared && target.long_io_in_flight() {
                match session.poll(Event::Tick, work, scratch, target, storage) {
                    // Nothing is staged in `work`; the framing action is
                    // re-emitted once the token settles.
                    Action::HostRecv { .. } => continue,
                    // No wire transfer is pending while the command waits on
                    // storage; keep the loop turning so the token can settle.
                    Action::StoragePending => continue,
                    // Data or a stall response is staged in `work`, which the
                    // long token owns: dropping it would lose or corrupt output.
                    Action::HostSend { .. } | Action::StallBoth | Action::StallIn => {
                        return Err(ServeError::Core(BotTargetError::Internal))
                    }
                    Action::Error(e) => return Err(ServeError::Core(e)),
                }
            }

            // 1) Control plane first (arrives at any time, even mid data phase).
            // A reset replaces `ev` with `Tick` and aborts the in-flight
            // transfer.
            if handle_ctrl(gadget, session, work, scratch, target, storage, &mut ev)? {
                continue;
            }

            // A receive that actually delivered fresh bytes (not a probe) must
            // survive a control reset drained *after* the await: the bytes
            // already arrived, and the session is reset before this event is
            // fed, so dispatching them is correct.
            let mut fresh_recv: Option<usize> = None;

            // 2) Feed the carried event, execute the returned action, and
            // carry the completion in `ev`.
            match session.poll(ev, work, scratch, target, storage) {
                Action::HostRecv { .. } if shared && target.long_io_in_flight() => {
                    // The step above started the resident long operation; its
                    // token now owns `work`. The receive is re-emitted on the
                    // next entry, so drop it and drive the long operation first.
                    ev = Event::Tick;
                    continue;
                }
                Action::HostSend { .. } | Action::StallBoth | Action::StallIn
                    if shared && target.long_io_in_flight() =>
                {
                    // The output bytes live in `work`, which the long token is
                    // using; this state must not be reached.
                    return Err(ServeError::Core(BotTargetError::Internal));
                }
                Action::HostRecv { offset, len, probe } => {
                    let end = offset + len;
                    if end > work.len() {
                        return Err(ServeError::Internal);
                    }
                    if probe {
                        ev = match recv.recv_probe(&mut work[offset..end]).await {
                            Ok(0) => return Err(ServeError::Closed),
                            Ok(n) => Event::HostRecv { len: n },
                            Err(BotIoErr::WouldBlock) => Event::HostIdle,
                            Err(BotIoErr::Disconnected) => Event::Reset,
                            Err(BotIoErr::Io) => return Err(ServeError::Closed),
                        };
                    } else {
                        ev = match recv
                            .recv(
                                &mut work[offset..end],
                                RecvMode::Until(CTRL_POLL_GRANULARITY),
                            )
                            .await
                        {
                            Ok(0) => return Err(ServeError::Closed),
                            Ok(n) => {
                                fresh_recv = Some(n);
                                Event::HostRecv { len: n }
                            }
                            Err(BotIoErr::WouldBlock) => Event::Tick,
                            Err(BotIoErr::Disconnected) => Event::Reset,
                            Err(BotIoErr::Io) => return Err(ServeError::Closed),
                        };
                    }
                }
                Action::HostSend { bytes } => {
                    ev = match send.send(bytes).await {
                        Ok(()) => Event::HostSent,
                        Err(BotIoErr::Disconnected) => Event::Reset,
                        Err(_) => return Err(ServeError::Closed),
                    };
                }
                Action::StoragePending => {
                    // No wire I/O: retry the command once on the next turn with
                    // a no-op tick. A storage adapter that stays pending is the
                    // async shell's concern.
                    ev = Event::Tick;
                }
                Action::StallBoth => {
                    let _ = recv.stall_both().await;
                    ev = Event::Tick;
                }
                Action::StallIn => {
                    ev = match send.stall_in().await {
                        Ok(()) => Event::StallApplied,
                        Err(()) => Event::Reset,
                    };
                }
                Action::Error(e) => return Err(ServeError::Core(e)),
            }

            // A control request can arrive while an I/O await is in flight.
            // Drain it now, before the completion is fed back, so a reset
            // supersedes the just-completed I/O (its event is replaced by
            // `Event::Tick`).
            while !stop.load(Ordering::Relaxed) {
                if !handle_ctrl(gadget, session, work, scratch, target, storage, &mut ev)? {
                    break;
                }
            }

            // A reset drained above replaces the completion with `Event::Tick`.
            // A freshly received chunk is still in `work` and the session was
            // just reset, so dispatch it instead of dropping it.
            if let Some(len) = fresh_recv {
                if ev == Event::Tick {
                    ev = Event::HostRecv { len };
                }
            }
        }
    }
    .await;
    let _ = target.settle_transport_end(storage, session);
    result
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::core::Lu;
    use crate::core::NoMedium;
    use crate::core::Pair;
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

    type Slot = crate::core::LuImpl<crate::block::BlockDevice, u8>;

    /// Drive `serve` with `stop` already set: the policy check runs before the
    /// loop, so a compatible combination returns `Ok(())` immediately and an
    /// incompatible one is rejected up front.
    fn run(policy: ShortfallPolicy, can_stall: bool, stop_set: bool) -> Result<(), ServeError> {
        let mut io = StubIo { can_stall };
        let mut gadget = NoGadget;
        let mut session = BotSession::new().with_shortfall(policy);
        let mut work = [0u8; crate::MIN_DATA_LEN];
        let mut scratch = [0u8; crate::MIN_DATA_LEN];
        let mut slot = Slot::new(
            crate::block::BlockDevice::new(crate::block::BlockAttrs::new(16, 512)),
            1u8,
        );
        let table: &mut [&mut dyn Lu<Pair = Pair<NoMedium, u8>>] = &mut [&mut slot];
        let mut target = Target::new(table);
        let mut storage = crate::core::storage::BlockingStorage::new(Passthrough);
        let stop = AtomicBool::new(stop_set);
        serve(
            &mut io,
            &mut gadget,
            &mut session,
            &mut work,
            &mut scratch,
            &mut target,
            &mut storage,
            &stop,
        )
    }

    struct Passthrough;

    impl crate::core::storage::SyncStorage for Passthrough {
        fn exec(
            &mut self,
            _req: crate::core::storage::IoReq,
            buf: crate::core::storage::IoBuf<'_>,
        ) -> crate::core::storage::StorageReceipt {
            let len = match &buf {
                crate::core::storage::IoBuf::None => 0,
                crate::core::storage::IoBuf::Read(b) => b.len(),
                crate::core::storage::IoBuf::Write(b) => b.len(),
            };
            crate::core::storage::StorageReceipt::ok(len)
        }
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
        let mut slot = Slot::new(
            crate::block::BlockDevice::new(crate::block::BlockAttrs::new(16, 512)),
            1u8,
        );
        let table: &mut [&mut dyn Lu<Pair = Pair<NoMedium, u8>>] = &mut [&mut slot];
        let mut target = Target::new(table);
        let mut storage = crate::core::storage::BlockingStorage::new(Passthrough);
        let stop = AtomicBool::new(stop_set);
        block_on(serve_async(
            &mut recv,
            &mut send,
            &mut gadget,
            &mut session,
            &mut work,
            &mut scratch,
            &mut target,
            &mut storage,
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

    /// Asynchronous bulk-OUT source that delivers one CBW and then EOF.
    #[cfg(feature = "async-io")]
    struct OneCbwRecv {
        cbw: Option<[u8; crate::usb::CBW_LEN]>,
    }

    #[cfg(feature = "async-io")]
    impl AsyncBotRecv for OneCbwRecv {
        async fn recv(&mut self, buf: &mut [u8], _mode: RecvMode) -> Result<usize, BotIoErr> {
            match self.cbw.take() {
                Some(bytes) => {
                    let n = bytes.len().min(buf.len());
                    buf[..n].copy_from_slice(&bytes[..n]);
                    Ok(n)
                }
                None => Ok(0),
            }
        }
    }

    /// Asynchronous bulk-IN sink recording the first 128 sent bytes.
    #[cfg(feature = "async-io")]
    struct RecordingSend {
        bytes: [u8; 128],
        len: usize,
    }

    #[cfg(feature = "async-io")]
    impl AsyncBotSend for RecordingSend {
        async fn send(&mut self, buf: &[u8]) -> Result<(), BotIoErr> {
            let n = buf.len().min(self.bytes.len() - self.len);
            self.bytes[self.len..self.len + n].copy_from_slice(&buf[..n]);
            self.len += n;
            Ok(())
        }
    }

    /// Gadget that surfaces one Bulk-Only Reset on its second poll (after the
    /// first bulk receive has completed).
    #[cfg(feature = "async-io")]
    struct ResetAfterRecv {
        calls: usize,
    }

    #[cfg(feature = "async-io")]
    impl<'a> Gadget<'a> for ResetAfterRecv {
        type Ack = NoAck;
        type Reply = NoReply;

        fn try_next_ctrl(&'a mut self) -> Option<CtrlReq<NoAck, NoReply>> {
            self.calls += 1;
            if self.calls == 2 {
                Some(CtrlReq::BotReset { ack: NoAck })
            } else {
                None
            }
        }
    }

    /// A CBW received before a control reset was drained must still be fed to
    /// the session (the fresh receive is not dropped by the reset).
    #[cfg(feature = "async-io")]
    #[test]
    fn async_reset_after_recv_keeps_the_received_cbw() {
        use crate::usb::{CBW_LEN, CBW_SIGNATURE, CSW_LEN};

        let mut cbw = [0u8; CBW_LEN];
        cbw[0..4].copy_from_slice(&CBW_SIGNATURE.to_le_bytes());
        cbw[4..8].copy_from_slice(&1u32.to_le_bytes());
        cbw[8..12].copy_from_slice(&36u32.to_le_bytes());
        cbw[12] = 0x80;
        cbw[14] = 6;
        cbw[15..21].copy_from_slice(&[0x12, 0, 0, 0, 36, 0]);

        let mut recv = OneCbwRecv { cbw: Some(cbw) };
        let mut send = RecordingSend {
            bytes: [0u8; 128],
            len: 0,
        };
        let mut gadget = ResetAfterRecv { calls: 0 };
        let mut session = BotSession::new();
        let mut work = [0u8; crate::MIN_DATA_LEN];
        let mut scratch = [0u8; crate::MIN_DATA_LEN];
        let mut slot = crate::core::LuImpl::new(
            crate::core::Spc::new(crate::block::BlockDevice::new(
                crate::block::BlockAttrs::new(16, 512),
            )),
            1u8,
        );
        let table: &mut [&mut dyn Lu<Pair = Pair<NoMedium, u8>>] = &mut [&mut slot];
        let mut target = Target::new(table);
        let mut storage = crate::core::storage::BlockingStorage::new(Passthrough);
        let stop = AtomicBool::new(false);

        let result = block_on(serve_async(
            &mut recv,
            &mut send,
            &mut gadget,
            &mut session,
            &mut work,
            &mut scratch,
            &mut target,
            &mut storage,
            &stop,
        ));
        assert!(matches!(result, Ok(()) | Err(ServeError::Closed)));

        // The INQUIRY response and its CSW were sent: the CBW survived the
        // reset drained after the await.
        assert!(
            send.len >= 36 + CSW_LEN,
            "sent {} bytes ({:?}); result {:?}",
            send.len,
            &send.bytes[..send.len],
            result
        );
        assert_eq!(send.bytes[0] & 0x1F, 0x00, "INQUIRY response, PDT 0");
        let csw = &send.bytes[send.len - CSW_LEN..];
        assert_eq!(&csw[..4], b"USBS");
        assert_eq!(u32::from_le_bytes([csw[4], csw[5], csw[6], csw[7]]), 1);
    }
}
