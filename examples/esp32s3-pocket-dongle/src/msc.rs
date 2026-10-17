//! USB Mass Storage — Bulk-Only Transport (BOT) class.
//!
//! The library owns the BOT loop: this module supplies only the platform seams
//! around `embassy-usb`'s bulk endpoints and lets [`serve_async`] drive the
//! [`BotSession`] state machine. The seams are:
//!
//! * [`CountingOut`]/[`CountingIn`] wrap the bulk endpoints and tally the bytes
//!   the status LCD shows as RX/TX;
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

use defmt::warn;
use embassy_usb::control::{InResponse, OutResponse, Recipient, Request, RequestType};
use embassy_usb::driver::{Endpoint, EndpointError, EndpointIn, EndpointInfo, EndpointOut};
use embassy_usb::Handler;

use snowscsi::common::async_store::AsyncStorePlane;
use snowscsi::scsi::AsyncLuns;
use snowscsi::usb::serve::serve_async;
use snowscsi::usb::{BotSession, EmbassyBot, Event, ServeError, BOT_RESET, GET_MAX_LUN};

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

/// Number of times the serve loop returned and was re-armed (any
/// [`ServeError`] other than a clean stop). A rising count while a host is
/// attached means the BOT loop is erroring out (link closed, core error,
/// control failure) instead of serving — the LCD shows it as `F<n>` next to
/// the USB state.
static RESTARTS: AtomicU32 = AtomicU32::new(0);

/// Bulk-IN packets the shell tried to send (`CountingIn::write` calls). Stays
/// at zero when the device never generates a response; a non-zero count with
/// `TX_BYTES == 0` means every send failed.
static TX_CALLS: AtomicU32 = AtomicU32::new(0);

/// `CountingIn::write` calls that returned `EndpointError::Disabled` (the
/// Synopsys IN endpoint's `usbaep` bit was clear — endpoint not enabled).
static TX_DISABLED: AtomicU32 = AtomicU32::new(0);

/// `CountingIn::write` calls that returned `EndpointError::BufferOverflow`.
static TX_OVERFLOW: AtomicU32 = AtomicU32::new(0);

/// Bulk-OUT reads whose first four bytes were the CBW signature `USBC` (a
/// real command block was received).
static RX_CBW: AtomicU32 = AtomicU32::new(0);

/// Bulk-OUT reads whose first four bytes were **not** `USBC` (stale/garbage
/// endpoint data — the BOT core would reject these as invalid CBWs).
static RX_OTHER: AtomicU32 = AtomicU32::new(0);

/// USB bus resets seen by the class [`Handler`] (`reset()` callback). A bus
/// reset disables every endpoint (the Synopsys driver's `configure_endpoints`
/// clears `usbaep`) until the host sends SET_CONFIGURATION again; a reset the
/// host does not follow with a reconfiguration leaves the bulk-IN endpoint
/// permanently disabled.
static BUS_RESETS: AtomicU32 = AtomicU32::new(0);

/// Whether the host currently has the gadget enabled and configured.
pub fn usb_connected() -> bool {
    USB_CONNECTED.load(Ordering::Relaxed)
}

/// Total bulk bytes received from the host (→ LCD RX meter). Wraps at 2^32;
/// the LCD only reads it for display, so the wrap is harmless.
pub fn rx_bytes() -> u32 {
    RX_BYTES.load(Ordering::Relaxed)
}

/// Total bulk bytes sent to the host (→ LCD TX meter).
pub fn tx_bytes() -> u32 {
    TX_BYTES.load(Ordering::Relaxed)
}

/// Number of serve-loop restarts (see `RESTARTS`).
pub fn restarts() -> u32 {
    RESTARTS.load(Ordering::Relaxed)
}

/// Bulk-IN send diagnostics: `(calls, disabled, overflow)` (see `TX_CALLS`).
pub fn tx_diag() -> (u32, u32, u32) {
    (
        TX_CALLS.load(Ordering::Relaxed),
        TX_DISABLED.load(Ordering::Relaxed),
        TX_OVERFLOW.load(Ordering::Relaxed),
    )
}

/// USB bus resets seen by the class handler (see `BUS_RESETS`).
pub fn bus_resets() -> u32 {
    BUS_RESETS.load(Ordering::Relaxed)
}

/// Command-phase read classification: `(cbw_signature, other)` (see `RX_CBW`).
pub fn rx_diag() -> (u32, u32) {
    (
        RX_CBW.load(Ordering::Relaxed),
        RX_OTHER.load(Ordering::Relaxed),
    )
}

/// Delta-sampler for the LCD throughput line: converts the cumulative
/// [`rx_bytes`] / [`tx_bytes`] counters into a per-window KB/s pair.
///
/// The gadget's refresh task owns one instance; [`SpeedMark::take`] is called
/// once per refresh with the current counter values and returns the throughput
/// over the *elapsed* window (interval measured locally, so the readout stays
/// correct even if the tick drifts).
pub struct SpeedMark {
    /// Counters at the previous `take` (cumulative bytes, may have wrapped).
    prev: (u32, u32),
    /// Wall time at the previous `take`.
    at: embassy_time::Instant,
}

impl SpeedMark {
    /// Start sampling: `prev` is aligned to the *current* cumulative counter
    /// values (`rx0`/`tx0`), so the first `take` only reports bytes moved after
    /// the sampler was created (never the history since boot).
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

/// The shared Bulk-Only Reset flag the class [`Handler`] sets and the serve
/// loop's gadget half drains.
pub fn reset_flag() -> &'static AtomicBool {
    &PENDING_RESET
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
        BUS_RESETS.fetch_add(1, Ordering::Relaxed);
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

/// Bulk-OUT endpoint wrapper that tallies received bytes for the status LCD.
///
/// The serve loop receives through the library's consolidating receive half,
/// which reads one packet at a time into the caller's buffer (until it is full
/// or a short packet ends the transfer). Counting here therefore stays exact —
/// one tally per received packet — and a whole Data-Out chunk still reaches the
/// core as one `StoreOp::Write` rather than a read-modify-write per 64-byte
/// packet.
pub struct CountingOut<O>(pub O);

impl<O: EndpointOut> Endpoint for CountingOut<O> {
    fn info(&self) -> &EndpointInfo {
        self.0.info()
    }

    async fn wait_enabled(&mut self) {
        self.0.wait_enabled().await
    }
}

impl<O: EndpointOut> EndpointOut for CountingOut<O> {
    async fn read(&mut self, buf: &mut [u8]) -> Result<usize, EndpointError> {
        let r = self.0.read(buf).await;
        if let Ok(n) = r {
            RX_BYTES.fetch_add(n as u32, Ordering::Relaxed);
            // Only the 31-byte command phase is classified, so Data-Out
            // payload reads are not mistaken for (non-)CBWs.
            if n == snowscsi::usb::CBW_LEN {
                if buf[..4] == *b"USBC" {
                    RX_CBW.fetch_add(1, Ordering::Relaxed);
                } else {
                    RX_OTHER.fetch_add(1, Ordering::Relaxed);
                }
            }
        }
        r
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
        TX_CALLS.fetch_add(1, Ordering::Relaxed);
        let r = self.0.write(buf).await;
        match &r {
            Ok(()) => {
                TX_BYTES.fetch_add(buf.len() as u32, Ordering::Relaxed);
            }
            Err(EndpointError::Disabled) => {
                TX_DISABLED.fetch_add(1, Ordering::Relaxed);
            }
            Err(EndpointError::BufferOverflow) => {
                TX_OVERFLOW.fetch_add(1, Ordering::Relaxed);
            }
        }
        r
    }
}

/// Bundle the two bulk endpoints (behind the byte-counting adapters) and the
/// shared reset flag into the [`EmbassyBot`] the serve loop drives.
pub fn bot<O, I>(out: O, in_: I) -> EmbassyBot<CountingOut<O>, CountingIn<I>> {
    EmbassyBot::new(CountingOut(out), CountingIn(in_), reset_flag())
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
    bot: &mut EmbassyBot<O, I>,
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
            Ok(()) => {}
            Err(ServeError::Closed) => {
                RESTARTS.fetch_add(1, Ordering::Relaxed);
            }
            Err(_) => {
                RESTARTS.fetch_add(1, Ordering::Relaxed);
                warn!("bot: serve loop stopped; restarting");
            }
        }

        if stop.load(Ordering::Relaxed) {
            // This firmware has no shutdown path; park so a set flag cannot
            // spin the restart loop.
            core::future::pending::<()>().await;
        }
    }
}
