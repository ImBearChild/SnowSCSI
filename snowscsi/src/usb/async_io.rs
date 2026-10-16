//! Asynchronous bulk-OUT / bulk-IN driver seam for the BOT core, mirroring
//! [`crate::usb::io`] without binding any runtime. Receive and send are split
//! so the two directions can be driven concurrently; the control plane is
//! shared with the synchronous shell, so no asynchronous gadget seam exists.
//!
//! An `async fn` in a trait is the only coupling to the executor, so this
//! seam works on `no_std` and with any runtime. The protocol core
//! ([`crate::usb::target::BotSession`]) is runtime-agnostic and unchanged: an
//! asynchronous shell awaits these methods and feeds the resulting
//! [`Event`](crate::usb::target::Event)s back into the session.
//!
//! Error kinds mirror the synchronous seam: [`BotIoErr`] is deliberately
//! coarse, and a zero-length receive signals a disconnect rather than an
//! error (see [`AsyncBotRecv::recv`]).

use core::time::Duration;

use crate::usb::io::BotIoErr;

/// How long [`AsyncBotRecv::recv`] may wait for a bulk-OUT packet.
///
/// The three modes let one receive entry point serve the distinct call
/// sites: a non-blocking drain, a bounded wait, and a true block. They exist
/// separately because the caller — not the transport — knows whether data is
/// known to be pending.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RecvMode {
    /// Non-blocking: return [`BotIoErr::WouldBlock`] immediately when no
    /// packet is available. Used for a speculative drain where the absence
    /// of data is itself meaningful (end of a data phase).
    Probe,
    /// Bounded wait: block for at most the given duration, then return
    /// [`BotIoErr::WouldBlock`] when nothing arrived. A zero duration is
    /// equivalent to [`Self::Probe`].
    Until(Duration),
    /// Unbounded wait: only use when a packet is known to be pending, so the
    /// future cannot hang on a silent link. Used for the command and data
    /// phases, where the host is contractually expected to send.
    Forever,
}

/// Asynchronous bulk-OUT receive seam (CBW arrival and the Data-Out phase).
///
/// # Contract
///
/// - `Ok(n)` reports `n` bytes just received, `n <= buf.len()`. A
///   packet-oriented transport (one packet per call, `n` bounded by the
///   endpoint max packet size) makes a short `n` a short packet; a buffered
///   transport may return several packets in one call. Either way `n` is a
///   byte count — the caller re-receives until the phase ends, so a short
///   `n` is progress, not a partial read to retry.
/// - `buf` is the caller's receive scratch. Paths that pre-receive ahead of
///   the core must size it to at least one bulk max packet size; a path that
///   receives only the core-requested length may pass a shorter buffer (a
///   31-byte CBW, or a sub-MPS final data chunk). A host packet larger than
///   `buf` is a host overrun — the transport reports it as an error
///   ([`BotIoErr::Io`]), not a caller sizing bug.
/// - `Ok(0)` means the link is down — treat it exactly like
///   [`BotIoErr::Disconnected`] (a host unplug / device detach is expected
///   and recoverable: reset the session and re-arm the endpoints).
/// - `Err(BotIoErr::WouldBlock)` follows [`RecvMode`]: `Probe` and an
///   expired `Until` report it; `Forever` never does.
#[allow(async_fn_in_trait)]
#[allow(clippy::result_unit_err)]
pub trait AsyncBotRecv {
    /// Await one bulk-OUT packet into `buf` according to `mode`.
    async fn recv(&mut self, buf: &mut [u8], mode: RecvMode) -> Result<usize, BotIoErr>;

    /// Await one packet, blocking until the host sends (the command and data
    /// phases, where a packet is known to be pending).
    async fn recv_wait(&mut self, buf: &mut [u8]) -> Result<usize, BotIoErr> {
        self.recv(buf, RecvMode::Forever).await
    }

    /// Non-blocking receive attempt; [`BotIoErr::WouldBlock`] when nothing is
    /// available.
    async fn recv_probe(&mut self, buf: &mut [u8]) -> Result<usize, BotIoErr> {
        self.recv(buf, RecvMode::Probe).await
    }

    /// Optional capability: STALL both bulk endpoints for an invalid CBW.
    /// Unavailable by default; a transport without endpoint STALL falls back
    /// to dropping the invalid CBW.
    async fn stall_both(&mut self) -> Result<(), ()> {
        Err(())
    }
}

/// Asynchronous bulk-IN send seam (the Data-In phase and the CSW).
///
/// # Contract
///
/// - `send` delivers one bulk packet: the transport must send exactly
///   `buf.len()` bytes. The caller sizes a packet to at most the endpoint
///   max packet size; an empty `buf` is a valid zero-length packet (ZLP) that
///   terminates a data phase.
/// - [`can_stall_in`](Self::can_stall_in) is the capability declaration: a
///   caller that selects a Data-In shortfall policy needing a Bulk-In halt
///   must check it before relying on [`stall_in`](Self::stall_in).
#[allow(async_fn_in_trait)]
#[allow(clippy::result_unit_err)]
pub trait AsyncBotSend {
    /// Send one bulk-IN packet (`buf` bytes; empty = a zero-length packet).
    async fn send(&mut self, buf: &[u8]) -> Result<(), BotIoErr>;

    /// Optional capability: STALL the Bulk-In endpoint for a Data-In
    /// shortfall. Unavailable by default (`Err(())`); a transport that cannot
    /// halt the endpoint returns `Err(())`, and the caller must abort the
    /// transaction deterministically (reset) instead of assuming the halt
    /// took effect.
    async fn stall_in(&mut self) -> Result<(), ()> {
        Err(())
    }

    /// Capability declaration: whether this transport can actually STALL
    /// Bulk-In. Defaults to `false`; a transport that implements
    /// [`stall_in`](Self::stall_in) overrides this to `true`.
    fn can_stall_in(&self) -> bool {
        false
    }
}
