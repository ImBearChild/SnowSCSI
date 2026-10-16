//! USB Mass Storage — Bulk-Only Transport (BOT) class.
//!
//! The library owns the BOT loop: this module supplies only the platform seams
//! around `embassy-usb`'s bulk endpoints and lets [`serve_async`] drive the
//! [`BotSession`] state machine. The seams are:
//!
//! * [`ConsolidatingRecv`] wraps the bulk-OUT endpoint, accumulating a whole
//!   Data-Out chunk before feeding the core (and tallying the RX meter);
//!   [`CountingIn`] wraps the bulk-IN endpoint for the TX meter;
//! * [`GadgetHalf`](snowscsi::usb::GadgetHalf) lifts a Bulk-Only Reset out of
//!   the shared [`PENDING_RESET`] flag.
//!
//! Control requests (Get Max LUN / Bulk-Only Reset) are delivered to
//! [`MscHandler`] by [`embassy_usb::UsbDevice::run`]. The handler cannot borrow
//! the session, so it answers Get Max LUN inline and signals a reset through the
//! [`PENDING_RESET`] static; the serve loop drains that flag at each loop
//! boundary. The status LCD reads [`usb_connected`], [`rx_bytes`] and
//! [`tx_bytes`].

use core::sync::atomic::{AtomicBool, AtomicU32, Ordering};
use core::time::Duration as CoreDuration;

use defmt::warn;
use embassy_time::{with_timeout, Duration, Instant, TimeoutError};
use embassy_usb::control::{InResponse, OutResponse, Recipient, Request, RequestType};
use embassy_usb::driver::{Endpoint, EndpointError, EndpointIn, EndpointInfo, EndpointOut};
use embassy_usb::Handler;

use snowscsi::common::async_store::AsyncStorePlane;
use snowscsi::scsi::AsyncLuns;
use snowscsi::usb::serve::serve_async;
use snowscsi::usb::{
    AsyncBotRecv, BotIoErr, BotSession, Event, GadgetHalf, RecvMode, SendHalf, ServeError,
    BOT_RESET, GET_MAX_LUN,
};

/// Number of LUNs presented to the host, zero-based (SPC Get Max LUN answer).
///
/// One LUN: the whole SD card exposed as a DVD-RAM UDF-RW volume.
pub const MAX_LUN: u8 = 0;

/// Set by [`MscHandler`] on a Bulk-Only Reset (control request or bus reset)
/// and drained by the serve loop's gadget half, which feeds it to the session.
///
/// The handler runs inside `UsbDevice::run` and cannot borrow the session, so
/// the reset request is carried out-of-band through this flag.
static PENDING_RESET: AtomicBool = AtomicBool::new(false);

/// Whether the USB device is currently enabled *and* configured.
///
/// Maintained from the [`Handler`] callbacks (there is no public
/// `UsbDeviceState` getter); the status LCD reads it via [`usb_connected`].
static USB_CONNECTED: AtomicBool = AtomicBool::new(false);

/// Bulk bytes received from the host (CBW fragments, Data-Out payload
/// chunks), measured as each bulk-OUT packet completes. The status LCD divides
/// the refresh-to-refresh delta by the interval to show an **RX**
/// (host → device) rate.
static RX_BYTES: AtomicU32 = AtomicU32::new(0);

/// Bulk bytes sent to the host (Data-In chunks, synthesized responses, CSWs),
/// measured as each bulk-IN packet completes. The status LCD divides the
/// refresh-to-refresh delta by the interval to show a **TX** (device → host)
/// rate.
static TX_BYTES: AtomicU32 = AtomicU32::new(0);

/// Whether the host currently has the gadget enabled and configured.
pub fn usb_connected() -> bool {
    USB_CONNECTED.load(Ordering::Relaxed)
}

/// Total bulk bytes received from the host (→ LCD RX/TX rate via
/// [`SpeedMark`]). Wraps at 2^32; [`SpeedMark::take`] deltas are immune to
/// that as long as one refresh window moves less than 4 GiB (a Full-Speed
/// bulk pipe cannot come close in half a second).
pub fn rx_bytes() -> u32 {
    RX_BYTES.load(Ordering::Relaxed)
}

/// Total bulk bytes sent to the host (→ LCD RX/TX rate via [`SpeedMark`]).
pub fn tx_bytes() -> u32 {
    TX_BYTES.load(Ordering::Relaxed)
}

/// The shared Bulk-Only Reset flag the class [`Handler`] sets and the serve
/// loop's gadget half drains.
pub fn reset_flag() -> &'static AtomicBool {
    &PENDING_RESET
}

/// Delta-sampler for the LCD speed line: converts the cumulative [`rx_bytes`]
/// / [`tx_bytes`] counters into a per-window KB/s pair.
///
/// The gadget's refresh task owns one instance; [`SpeedMark::take`] is called
/// once per 500 ms refresh with the current counter values and returns the
/// throughput over the *elapsed* window (interval measured locally, so the
/// readout stays correct even if the tick drifts).
pub struct SpeedMark {
    /// Counters at the previous `take` (cumulative bytes, may have wrapped).
    prev: (u32, u32),
    /// Wall time at the previous `take`.
    at: embassy_time::Instant,
}

impl SpeedMark {
    /// Start sampling: `prev` is aligned to the *current* cumulative counter
    /// values (`rx0`/`tx0`), so the first `take` only reports bytes moved
    /// after the sampler was created (never the history since boot).
    pub fn new(rx0: u32, tx0: u32) -> Self {
        Self {
            prev: (rx0, tx0),
            at: embassy_time::Instant::now(),
        }
    }

    /// Sample the current cumulative byte counts and return the `(RX, TX)`
    /// average KB/s since the previous call (decimal kilobytes, 1 KB = 1000 B).
    pub fn take(&mut self, rx: u32, tx: u32) -> (u32, u32) {
        let now = embassy_time::Instant::now();
        let us = now
            .checked_duration_since(self.at)
            .map(|d| d.as_micros())
            .filter(|&us| us > 0)
            .unwrap_or(1);
        self.at = now;

        // wrapping_sub keeps the delta correct across a counter wrap.
        let d_rx = rx.wrapping_sub(self.prev.0);
        let d_tx = tx.wrapping_sub(self.prev.1);
        self.prev = (rx, tx);

        // bytes * 1e6 / µs = bytes/s; ÷1000 → decimal KB/s. Per-window deltas
        // are modest (the 64-bit product per direction stays inside u64).
        let to_kbps =
            |delta: u32| -> u32 { ((delta as u64 * 1_000_000 / us as u64) / 1000) as u32 };
        (to_kbps(d_rx), to_kbps(d_tx))
    }
}

/// Zero-sized USB class handler for the Mass Storage interface.
///
/// Handles the two BOT class requests on the control pipe:
/// * Get Max LUN (`0xFE`) — reply with [`MAX_LUN`];
/// * Bulk-Only Reset (`0xFF`) — set [`PENDING_RESET`] and accept.
///
/// Bus callbacks keep [`USB_CONNECTED`] and [`PENDING_RESET`] in step. Note
/// that embassy-usb consumes CLEAR FEATURE(ENDPOINT_HALT) itself and never
/// forwards it to a handler, so a preserved STALL cannot be observed from here.
pub struct MscHandler;

impl Handler for MscHandler {
    fn enabled(&mut self, enabled: bool) {
        if !enabled {
            USB_CONNECTED.store(false, Ordering::Relaxed);
        }
    }

    fn reset(&mut self) {
        PENDING_RESET.store(true, Ordering::Relaxed);
        USB_CONNECTED.store(false, Ordering::Relaxed);
    }

    fn configured(&mut self, configured: bool) {
        USB_CONNECTED.store(configured, Ordering::Relaxed);
        if !configured {
            PENDING_RESET.store(true, Ordering::Relaxed);
        }
    }

    fn suspended(&mut self, suspended: bool) {
        if suspended {
            USB_CONNECTED.store(false, Ordering::Relaxed);
        }
    }

    fn control_out(&mut self, req: Request, _data: &[u8]) -> Option<OutResponse> {
        if req.request_type == RequestType::Class
            && req.recipient == Recipient::Interface
            && req.request == BOT_RESET
        {
            PENDING_RESET.store(true, Ordering::Relaxed);
            Some(OutResponse::Accepted)
        } else {
            None
        }
    }

    fn control_in<'a>(&'a mut self, req: Request, buf: &'a mut [u8]) -> Option<InResponse<'a>> {
        if req.request_type == RequestType::Class
            && req.recipient == Recipient::Interface
            && req.request == GET_MAX_LUN
            && !buf.is_empty()
        {
            buf[0] = MAX_LUN;
            Some(InResponse::Accepted(&buf[..1]))
        } else {
            None
        }
    }
}

/// Zero-timeout duration for the non-blocking probe: `with_timeout` polls the
/// wrapped read once before its timer, so an already-arrived packet wins.
const ZERO: Duration = Duration::from_ticks(0);

/// Upper bound on a converted timeout (1000 s); mirrors the library adapter so
/// a maximal `core::time::Duration` cannot overflow `Instant + Duration`.
const MAX_MICROS: u64 = 1_000_000_000;

/// Convert a seam timeout (`core::time::Duration`) to an embassy duration.
fn to_embassy(d: CoreDuration) -> Duration {
    let micros = u64::try_from(d.as_micros().min(u128::from(MAX_MICROS))).unwrap_or(MAX_MICROS);
    Duration::from_micros(micros)
}

/// Map an endpoint error to the coarse bulk seam error.
fn recv_err(err: EndpointError) -> BotIoErr {
    match err {
        EndpointError::Disabled => BotIoErr::Disconnected,
        EndpointError::BufferOverflow => BotIoErr::Io,
    }
}

/// Bulk-OUT half: a **consolidating** [`AsyncBotRecv`] over one endpoint.
///
/// A Full-Speed link delivers at most one 64-byte packet per `ep.read`, but the
/// shell hands this half the whole core-requested chunk (or the overlap
/// scratch) as `buf`. It therefore keeps reading packets into `buf` until it is
/// full or a short packet ends the bulk transfer. Handing the core one packet
/// at a time would make it emit a `StoreOp::Write` per 64 bytes, turning each
/// 512-byte SD sector write into a read-modify-write cycle; consolidating
/// yields one write per core chunk. The RX meter is tallied per packet, once.
pub struct ConsolidatingRecv<O> {
    /// The wrapped bulk-OUT endpoint.
    pub ep: O,
}

impl<O: EndpointOut> ConsolidatingRecv<O> {
    /// Tally one received packet for the LCD RX meter.
    fn tally(&self, n: usize) {
        RX_BYTES.fetch_add(n as u32, Ordering::Relaxed);
    }

    /// Accumulate packets until `buf` is full or a short packet arrives.
    async fn fill(&mut self, buf: &mut [u8]) -> Result<usize, BotIoErr> {
        let mps = self.ep.info().max_packet_size as usize;
        let mut n = 0usize;
        while n < buf.len() {
            let i = self.ep.read(&mut buf[n..]).await.map_err(recv_err)?;
            self.tally(i);
            n += i;
            // A short packet terminates the host's bulk transfer early.
            if i < mps {
                break;
            }
        }
        Ok(n)
    }

    /// As [`Self::fill`], but bounded by an overall deadline. On expiry the
    /// bytes already received are returned as progress — they were consumed
    /// from the endpoint and must not be dropped — while nothing received is
    /// [`BotIoErr::WouldBlock`]. A zero-length read is a link-down `Ok(0)`, not
    /// a timeout.
    async fn fill_until(&mut self, buf: &mut [u8], deadline: Instant) -> Result<usize, BotIoErr> {
        let mps = self.ep.info().max_packet_size as usize;
        let mut n = 0usize;
        while n < buf.len() {
            let remaining = deadline.saturating_duration_since(Instant::now());
            match with_timeout(remaining, self.ep.read(&mut buf[n..])).await {
                Ok(Ok(i)) => {
                    self.tally(i);
                    n += i;
                    if i < mps {
                        break;
                    }
                }
                Ok(Err(e)) => return Err(recv_err(e)),
                // Expiry with nothing received is a would-block; with bytes
                // already in `buf` it is progress.
                Err(TimeoutError) => {
                    return if n > 0 {
                        Ok(n)
                    } else {
                        Err(BotIoErr::WouldBlock)
                    };
                }
            }
        }
        Ok(n)
    }
}

impl<O: EndpointOut> AsyncBotRecv for ConsolidatingRecv<O> {
    async fn recv(&mut self, buf: &mut [u8], mode: RecvMode) -> Result<usize, BotIoErr> {
        match mode {
            // Non-blocking drain: a single attempt, no consolidation loop.
            RecvMode::Probe => match with_timeout(ZERO, self.ep.read(buf)).await {
                Ok(Ok(i)) => {
                    self.tally(i);
                    Ok(i)
                }
                Ok(Err(e)) => Err(recv_err(e)),
                Err(TimeoutError) => Err(BotIoErr::WouldBlock),
            },
            // A packet is known to be pending: park until the endpoint is live
            // (a not-yet-configured endpoint returns `Disabled` immediately and
            // would otherwise spin), then accumulate without a deadline.
            RecvMode::Forever => {
                self.ep.wait_enabled().await;
                self.fill(buf).await
            }
            // Bounded total wait: park, then accumulate under a deadline.
            RecvMode::Until(d) => {
                self.ep.wait_enabled().await;
                let deadline = Instant::now().saturating_add(to_embassy(d));
                self.fill_until(buf, deadline).await
            }
        }
    }
}

/// Bulk-IN endpoint wrapper that tallies sent bytes for the status LCD.
pub struct CountingIn<I>(pub I);

impl<I: EndpointIn> Endpoint for CountingIn<I> {
    fn info(&self) -> &EndpointInfo {
        self.0.info()
    }

    async fn wait_enabled(&mut self) {
        self.0.wait_enabled().await
    }
}

impl<I: EndpointIn> EndpointIn for CountingIn<I> {
    async fn write(&mut self, buf: &[u8]) -> Result<(), EndpointError> {
        let r = self.0.write(buf).await;
        if r.is_ok() {
            TX_BYTES.fetch_add(buf.len() as u32, Ordering::Relaxed);
        }
        r
    }
}

/// The three independent seams [`serve_async`] borrows.
///
/// The OUT half consolidates (see [`ConsolidatingRecv`]); the IN half uses the
/// library's chunking [`SendHalf`] (a Data-In chunk is split into MPS packets
/// correctly there); the control half drains the shared reset flag.
pub struct Bot<O, I> {
    /// Bulk-OUT receive half (consolidating).
    pub out: ConsolidatingRecv<O>,
    /// Bulk-IN send half (chunked, byte-counting).
    pub in_: SendHalf<CountingIn<I>>,
    /// Control-plane half.
    pub gadget: GadgetHalf,
}

/// Bundle the two bulk endpoints and the shared reset flag for the serve loop.
pub fn bot<O, I>(out: O, in_: I) -> Bot<O, I> {
    Bot {
        out: ConsolidatingRecv { ep: out },
        in_: SendHalf {
            ep: CountingIn(in_),
        },
        gadget: GadgetHalf::new(reset_flag()),
    }
}

/// Run the BOT protocol loop forever over a bulk endpoint pair.
///
/// `work` is the SCSI data region (must be ≥ [`snowscsi::MIN_DATA_LEN`]);
/// `scratch` is the equal-length overlap buffer the shell pre-receives into;
/// `luns` is the device/plane bundle; `stop` is the shared shutdown flag.
///
/// The library shell owns the protocol loop. This wrapper re-arms the session
/// and restarts it after a host disconnect, so the gadget future never returns:
/// a disconnect parks the next receive until the host re-enumerates.
pub async fn run<O, I, P>(
    bot: &mut Bot<O, I>,
    session: &mut BotSession,
    work: &mut [u8],
    scratch: &mut [u8],
    luns: &mut AsyncLuns<'_, P>,
    stop: &AtomicBool,
) -> !
where
    O: EndpointOut,
    I: EndpointIn,
    P: AsyncStorePlane,
{
    assert!(
        work.len() >= snowscsi::MIN_DATA_LEN,
        "work buffer smaller than MIN_DATA_LEN"
    );

    loop {
        // Drop any transaction left over from a previous host session and
        // inject the post-reset UNIT ATTENTION, exactly like the shell's own
        // reset path.
        {
            let AsyncLuns { devs, .. } = &mut *luns;
            let _ = session.poll(Event::Reset, work, devs);
        }

        match serve_async(
            &mut bot.out,
            &mut bot.in_,
            &mut bot.gadget,
            session,
            work,
            scratch,
            luns,
            stop,
        )
        .await
        {
            // `Ok` only on a set stop flag; a closed link restarts the loop.
            Ok(()) | Err(ServeError::Closed) => {}
            Err(_) => warn!("bot: serve loop stopped; restarting"),
        }

        if stop.load(Ordering::Relaxed) {
            // This firmware has no shutdown path; park so a set flag cannot
            // spin the restart loop.
            core::future::pending::<()>().await;
        }
    }
}
