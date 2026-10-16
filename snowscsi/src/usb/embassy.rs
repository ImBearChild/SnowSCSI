//! `embassy-usb` adapters for the asynchronous BOT shell.
//!
//! The asynchronous seam ([`crate::usb::async_io`]) is runtime-agnostic; this
//! module binds it to the bulk endpoint pair of an [`embassy_usb`] device and
//! to a class [`Handler`](embassy_usb::Handler) that answers the two BOT class
//! requests on the control pipe. The three halves are independent so the shell
//! ([`serve_async`](crate::usb::serve::serve_async)) can borrow them separately:
//!
//! - [`RecvHalf`] wraps a bulk-OUT endpoint as [`AsyncBotRecv`];
//! - [`SendHalf`] wraps a bulk-IN endpoint as [`AsyncBotSend`];
//! - [`GadgetHalf`] lifts a Bulk-Only Reset out of a shared flag as the
//!   synchronous [`Gadget`] seam.
//!
//! [`EmbassyBot`] bundles the three as public fields for convenience.
//!
//! # Control plane
//!
//! embassy-usb delivers control requests synchronously to the class `Handler`,
//! so there is no awaitable control source and the synchronous [`Gadget`] seam
//! is reused. The handler sets a `&'static AtomicBool` when it accepts a
//! Bulk-Only Reset and answers Get Max LUN directly from `control_in`;
//! [`GadgetHalf`] drains that flag as [`CtrlReq::BotReset`] (its ack and reply
//! handles are no-ops, since the handler has already completed the control
//! transfer). The flag is consumed only at a loop boundary, so the shell must
//! drain the control plane after every await to apply a reset before the CBW
//! that may immediately follow it.
//!
//! # STALL
//!
//! embassy-usb keeps its `Bus` private to `UsbDevice`, so endpoint STALL is
//! unreachable from a class driver. The `stall_both` / `stall_in` seam defaults
//! are therefore kept (`Err(())`) and `can_stall_in` stays `false`: a session
//! whose shortfall policy needs a Bulk-In halt is rejected by the shell up
//! front rather than relying on a STALL that cannot be applied.
//!
//! # Reset status stage
//!
//! Deviation: embassy-usb completes a class control request's status stage as
//! soon as the handler returns
//! [`OutResponse::Accepted`](embassy_usb::control::OutResponse::Accepted), so a
//! Bulk-Only Reset is acknowledged immediately. The Bulk-Only Transport
//! specification (BOT §6.4) instead requires the status stage to be NAKed until
//! the reset is complete. [`GadgetHalf`] only surfaces the reset to the shell at
//! the next loop boundary, so the acknowledgment precedes the reset by a short
//! window. This is accepted and documented, like the unreachable-STALL
//! limitation above.

use core::sync::atomic::{AtomicBool, Ordering};
use core::time::Duration as CoreDuration;

use embassy_time::{with_timeout, Duration, TimeoutError};
use embassy_usb::driver::{EndpointError, EndpointIn, EndpointOut};

use crate::usb::async_io::{AsyncBotRecv, AsyncBotSend, RecvMode};
use crate::usb::gadget::{CtrlAck, CtrlReply, CtrlReq, Gadget};
use crate::usb::io::BotIoErr;

/// Zero-timeout duration: `with_timeout` with this value polls the wrapped
/// future once before its timer, so a pending packet wins over the timeout.
const ZERO: Duration = Duration::from_ticks(0);

/// Map an endpoint error to the coarse bulk seam error.
///
/// A disabled endpoint is a host detach (recoverable: the shell resets the
/// session); a buffer overflow is a host overrun the transport cannot absorb,
/// which is fatal at the seam (`BotIoErr::Io`) rather than a silent drain.
fn recv_err(err: EndpointError) -> BotIoErr {
    match err {
        EndpointError::Disabled => BotIoErr::Disconnected,
        EndpointError::BufferOverflow => BotIoErr::Io,
    }
}

/// Map an endpoint error to the coarse bulk seam error (see [`recv_err`]).
fn send_err(err: EndpointError) -> BotIoErr {
    match err {
        EndpointError::Disabled => BotIoErr::Disconnected,
        EndpointError::BufferOverflow => BotIoErr::Io,
    }
}

/// Convert a seam timeout to an embassy duration.
///
/// The seam uses `core::time::Duration`; embassy measures in ticks. The value
/// is clamped to a bounded microsecond count before conversion: `from_micros`
/// scales by the platform tick rate, and `with_timeout` adds the result to the
/// current instant, so a near-`u64::MAX` count — or `core::time::Duration::MAX`
/// — would overflow and panic. The cap sits far above any real poll
/// granularity (the caller uses 50 ms), so the conversion stays exact where it
/// matters and bounded everywhere.
fn to_embassy(d: CoreDuration) -> Duration {
    /// Upper bound on the converted microsecond count (1000 s).
    const MAX_MICROS: u64 = 1_000_000_000;
    let micros = u64::try_from(d.as_micros().min(u128::from(MAX_MICROS))).unwrap_or(MAX_MICROS);
    Duration::from_micros(micros)
}

/// Bulk-OUT receive half: wraps one embassy [`EndpointOut`].
pub struct RecvHalf<O> {
    /// The wrapped bulk-OUT endpoint.
    pub ep: O,
}

impl<O: EndpointOut> RecvHalf<O> {
    /// Read one bulk transfer into `buf`, starting at `*n`, until the buffer is
    /// full or a short packet (`< max_packet_size`) ends the transfer. The
    /// running byte count is accumulated into `*n`, so a caller can keep the
    /// bytes already consumed from the endpoint if a surrounding timeout fires.
    async fn read_into(&mut self, buf: &mut [u8], n: &mut usize) -> Result<(), BotIoErr> {
        let max_packet_size = self.ep.info().max_packet_size as usize;
        while *n < buf.len() {
            let i = self.ep.read(&mut buf[*n..]).await.map_err(recv_err)?;
            *n += i;
            if i < max_packet_size {
                break;
            }
        }
        Ok(())
    }
}

impl<O: EndpointOut> AsyncBotRecv for RecvHalf<O> {
    async fn recv(&mut self, buf: &mut [u8], mode: RecvMode) -> Result<usize, BotIoErr> {
        match mode {
            // A transfer is known to be pending: consolidate a whole chunk into
            // `buf` so a block-backed caller does not do a read-modify-write
            // per packet. Parking on `wait_enabled` first matters on hardware:
            // a not-yet-configured endpoint returns `Disabled` immediately, so
            // without a yield point a blocking read would spin and starve the
            // device poll task. Once enabled it returns at once.
            RecvMode::Forever => {
                self.ep.wait_enabled().await;
                let mut n = 0;
                self.read_into(buf, &mut n).await?;
                Ok(n)
            }
            // Speculative drain: a single non-blocking attempt and no wait — it
            // must return promptly. `with_timeout` polls the read first, so an
            // already arrived packet returns before the timeout.
            RecvMode::Probe => match with_timeout(ZERO, self.ep.read(buf)).await {
                Ok(r) => r.map_err(recv_err),
                Err(TimeoutError) => Err(BotIoErr::WouldBlock),
            },
            // Bounded wait under one overall deadline. Expiry keeps the bytes
            // already consumed (they are gone from the endpoint and must not be
            // dropped); with none consumed it is a would-block, not an error.
            // Parking on `wait_enabled` first keeps a disabled endpoint from
            // spinning (see `Forever`) before the bounded read starts.
            RecvMode::Until(d) => {
                self.ep.wait_enabled().await;
                let mut n = 0;
                let outcome = with_timeout(to_embassy(d), self.read_into(buf, &mut n)).await;
                match outcome {
                    Ok(Ok(())) => Ok(n),
                    Ok(Err(e)) => Err(e),
                    Err(TimeoutError) => {
                        if n > 0 {
                            Ok(n)
                        } else {
                            Err(BotIoErr::WouldBlock)
                        }
                    }
                }
            }
        }
    }

    // `stall_both` keeps the seam default (`Err(())`): endpoint STALL is not
    // reachable from an embassy-usb class driver.
}

/// Bulk-IN send half: wraps one embassy [`EndpointIn`].
pub struct SendHalf<I> {
    /// The wrapped bulk-IN endpoint.
    pub ep: I,
}

impl<I: EndpointIn> AsyncBotSend for SendHalf<I> {
    async fn send(&mut self, buf: &[u8]) -> Result<(), BotIoErr> {
        // `write` sends exactly one packet and rejects a buffer larger than the
        // endpoint max packet size; the shell hands over a whole Data-In chunk
        // (up to the work-buffer size), so a non-empty chunk must be split with
        // the trait chunker. `needs_zlp` stays false: the core drives any
        // zero-length packet explicitly, and an empty buffer already is one.
        if buf.is_empty() {
            self.ep.write(buf).await.map_err(send_err)
        } else {
            self.ep.write_transfer(buf, false).await.map_err(send_err)
        }
    }

    // `stall_in` / `can_stall_in` keep the seam defaults (`Err(())` / `false`):
    // endpoint STALL is not reachable from an embassy-usb class driver.
}

/// Control-plane half: lifts a Bulk-Only Reset from a shared flag.
///
/// The class `Handler` owns the control pipe (inside `UsbDevice`), so it cannot
/// hand a request to the shell directly. Instead it sets this `&'static`
/// flag when it accepts a Bulk-Only Reset; [`GadgetHalf`] drains the flag as a
/// [`CtrlReq::BotReset`]. Get Max LUN never reaches this half — the handler
/// answers it inline — so the reply shell is never produced.
pub struct GadgetHalf {
    /// Set by the class `Handler` on a Bulk-Only Reset, cleared on drain.
    reset: &'static AtomicBool,
}

impl GadgetHalf {
    /// Wrap the shared reset flag the class `Handler` sets.
    pub fn new(reset: &'static AtomicBool) -> Self {
        Self { reset }
    }
}

impl<'a> Gadget<'a> for GadgetHalf {
    type Ack = NoopAck;
    type Reply = NoopReply;

    fn try_next_ctrl(&'a mut self) -> Option<CtrlReq<Self::Ack, Self::Reply>> {
        // Take-and-clear: `try_next_ctrl` must make progress when drained in a
        // loop, so a reset is surfaced exactly once.
        if self.reset.swap(false, Ordering::Relaxed) {
            Some(CtrlReq::BotReset { ack: NoopAck })
        } else {
            None
        }
    }
}

/// Acknowledgment shell for a Bulk-Only Reset.
///
/// The class `Handler` has already accepted the control request's status stage
/// (embassy-usb completes it when `control_out` returns `OutResponse::Accepted`),
/// so there is nothing left to do here.
pub struct NoopAck;

impl CtrlAck for NoopAck {
    fn ack(self) {}
}

/// Reply shell for Get Max LUN.
///
/// [`GadgetHalf`] never surfaces a Get Max LUN (the handler answers it inline),
/// so this handle is never constructed; sending through it is a no-op error.
pub struct NoopReply;

impl CtrlReply for NoopReply {
    fn send(&mut self, _data: &[u8]) -> Result<(), ()> {
        Err(())
    }
}

/// Convenience bundle of the three adapters as public fields.
///
/// The asynchronous shell takes three independent `&mut`s, so the caller drives
/// it as `serve_async(&mut bot.out, &mut bot.in_, &mut bot.gadget, …)`.
pub struct EmbassyBot<O, I> {
    /// Bulk-OUT receive half.
    pub out: RecvHalf<O>,
    /// Bulk-IN send half.
    pub in_: SendHalf<I>,
    /// Control-plane half.
    pub gadget: GadgetHalf,
}

impl<O, I> EmbassyBot<O, I> {
    /// Bundle a bulk-OUT endpoint, a bulk-IN endpoint and the shared reset flag.
    pub fn new(out: O, in_: I, reset: &'static AtomicBool) -> Self {
        Self {
            out: RecvHalf { ep: out },
            in_: SendHalf { ep: in_ },
            gadget: GadgetHalf::new(reset),
        }
    }
}

#[cfg(all(test, feature = "embassy"))]
mod tests {
    use super::*;

    use core::cell::RefCell;
    use core::future::poll_fn;
    use core::task::Poll;
    use std::collections::VecDeque;

    use embassy_usb::driver::{Direction, Endpoint, EndpointAddress, EndpointInfo, EndpointType};

    // `with_timeout` builds a `Timer`, which reads `Instant::now()` and
    // schedules a wake through the global `embassy-time-driver` symbols. The
    // `mock-driver` dev-dependency provides those symbols (via
    // `embassy_time::MockDriver`), so no hand-written time shim is needed here.
    // Its monotonic clock, together with the manual executor below, keeps these
    // tests deterministic and fast (no real sleeps).

    /// Minimal single-threaded executor: poll with a no-op waker until ready.
    fn block_on<F: core::future::Future>(fut: F) -> F::Output {
        let mut fut = core::pin::pin!(fut);
        let mut cx = core::task::Context::from_waker(core::task::Waker::noop());
        loop {
            if let Poll::Ready(v) = fut.as_mut().poll(&mut cx) {
                return v;
            }
        }
    }

    /// Canned bulk-OUT outcome for the mock endpoint.
    enum ReadOutcome {
        /// Deliver these bytes.
        Data(Vec<u8>),
        /// The endpoint is disabled.
        Disabled,
        /// The host packet does not fit the buffer.
        Overflow,
        /// No packet is available; the read future stays pending.
        Pending,
    }

    /// Mock endpoint: serves canned OUT outcomes and records IN writes as
    /// packet lengths. `write` mirrors the hardware rule that a single packet
    /// larger than the max packet size overflows.
    struct MockEp {
        info: EndpointInfo,
        reads: RefCell<VecDeque<ReadOutcome>>,
        writes: RefCell<Vec<usize>>,
    }

    impl MockEp {
        fn new(dir: Direction, max_packet_size: u16, reads: Vec<ReadOutcome>) -> Self {
            Self {
                info: EndpointInfo {
                    addr: EndpointAddress::from_parts(0, dir),
                    ep_type: EndpointType::Bulk,
                    max_packet_size,
                    interval_ms: 0,
                },
                reads: RefCell::new(reads.into()),
                writes: RefCell::new(Vec::new()),
            }
        }
    }

    impl Endpoint for MockEp {
        fn info(&self) -> &EndpointInfo {
            &self.info
        }

        async fn wait_enabled(&mut self) {}
    }

    impl EndpointOut for MockEp {
        async fn read(&mut self, buf: &mut [u8]) -> Result<usize, EndpointError> {
            // Take the outcome out before awaiting so no `RefCell` borrow is
            // held across the pending await below.
            let outcome = self.reads.borrow_mut().pop_front();
            match outcome {
                Some(ReadOutcome::Data(data)) => {
                    let n = data.len().min(buf.len());
                    buf[..n].copy_from_slice(&data[..n]);
                    Ok(n)
                }
                Some(ReadOutcome::Disabled) => Err(EndpointError::Disabled),
                Some(ReadOutcome::Overflow) => Err(EndpointError::BufferOverflow),
                Some(ReadOutcome::Pending) | None => poll_fn(|_| Poll::Pending).await,
            }
        }
    }

    impl EndpointIn for MockEp {
        async fn write(&mut self, buf: &[u8]) -> Result<(), EndpointError> {
            if buf.len() > self.info.max_packet_size as usize {
                return Err(EndpointError::BufferOverflow);
            }
            self.writes.borrow_mut().push(buf.len());
            Ok(())
        }
    }

    #[test]
    fn send_chunks_a_multi_packet_chunk_and_keeps_zlp_single() {
        let mut half = SendHalf {
            ep: MockEp::new(Direction::In, 8, Vec::new()),
        };

        // A single `write` of a >MPS buffer overflows on hardware ...
        assert_eq!(
            block_on(half.ep.write(&[0u8; 20])),
            Err(EndpointError::BufferOverflow)
        );

        // ... so `send` chunks it: 20 bytes at MPS 8 → 8 + 8 + 4.
        block_on(half.send(&[0u8; 20])).unwrap();
        assert_eq!(half.ep.writes.borrow().as_slice(), &[8, 8, 4]);

        // An empty buffer is a single zero-length packet.
        block_on(half.send(&[])).unwrap();
        assert_eq!(half.ep.writes.borrow().as_slice(), &[8, 8, 4, 0]);
    }

    #[test]
    fn recv_maps_disabled_to_disconnected_and_overflow_to_io() {
        let mut buf = [0u8; 8];

        let mut half = RecvHalf {
            ep: MockEp::new(Direction::Out, 64, vec![ReadOutcome::Disabled]),
        };
        assert_eq!(
            block_on(half.recv(&mut buf, RecvMode::Forever)),
            Err(BotIoErr::Disconnected)
        );

        let mut half = RecvHalf {
            ep: MockEp::new(Direction::Out, 64, vec![ReadOutcome::Overflow]),
        };
        assert_eq!(
            block_on(half.recv(&mut buf, RecvMode::Forever)),
            Err(BotIoErr::Io)
        );
    }

    #[test]
    fn recv_until_reports_timeout_as_would_block() {
        // The mock driver's monotonic clock makes a zero-length timeout ready
        // on the second poll; no advance is needed (and no real sleep).
        embassy_time::MockDriver::get().reset();

        let mut half = RecvHalf {
            ep: MockEp::new(Direction::Out, 64, vec![ReadOutcome::Pending]),
        };
        let mut buf = [0u8; 8];
        assert_eq!(
            block_on(half.recv(&mut buf, RecvMode::Until(core::time::Duration::ZERO))),
            Err(BotIoErr::WouldBlock)
        );
    }

    #[test]
    fn recv_probe_reads_at_most_one_packet() {
        let mut half = RecvHalf {
            ep: MockEp::new(
                Direction::Out,
                64,
                vec![
                    ReadOutcome::Data(vec![1, 2, 3]),
                    ReadOutcome::Data(vec![4, 5, 6]),
                ],
            ),
        };
        let mut buf = [0u8; 8];
        assert_eq!(block_on(half.recv(&mut buf, RecvMode::Probe)), Ok(3));
        assert_eq!(&buf[..3], &[1, 2, 3]);
        // Probe is a single non-blocking attempt: the second packet is untouched.
        assert_eq!(half.ep.reads.borrow().len(), 1);
    }

    #[test]
    fn recv_forever_consolidates_a_multi_packet_transfer() {
        // MPS 8: two full packets then a short one end the transfer, so a
        // single `recv` returns the whole 20-byte chunk and leaves the trailing
        // packet for the next call.
        let mut half = RecvHalf {
            ep: MockEp::new(
                Direction::Out,
                8,
                vec![
                    ReadOutcome::Data(vec![1; 8]),
                    ReadOutcome::Data(vec![2; 8]),
                    ReadOutcome::Data(vec![3; 4]),
                    ReadOutcome::Data(vec![4; 8]),
                ],
            ),
        };
        let mut buf = [0u8; 32];
        assert_eq!(block_on(half.recv(&mut buf, RecvMode::Forever)), Ok(20));
        assert_eq!(&buf[..8], &[1; 8]);
        assert_eq!(&buf[8..16], &[2; 8]);
        assert_eq!(&buf[16..20], &[3; 4]);
        assert_eq!(half.ep.reads.borrow().len(), 1);
    }

    #[test]
    fn recv_until_keeps_bytes_received_before_the_deadline() {
        // One full packet arrives, then the host stalls; the overall deadline
        // expires but the already-consumed bytes must be returned, not dropped.
        embassy_time::MockDriver::get().reset();

        let mut half = RecvHalf {
            ep: MockEp::new(
                Direction::Out,
                8,
                vec![ReadOutcome::Data(vec![7; 8]), ReadOutcome::Pending],
            ),
        };
        let mut buf = [0u8; 32];
        assert_eq!(
            block_on(half.recv(&mut buf, RecvMode::Until(core::time::Duration::ZERO))),
            Ok(8)
        );
        assert_eq!(&buf[..8], &[7; 8]);
    }
}
