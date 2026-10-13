//! USB Mass Storage — Bulk-Only Transport (BOT) class.
//!
//! Drives `snowscsi::usb`'s non-blocking [`BotSession`] with the
//! `embassy-usb` bulk endpoints of the ESP32-S3 USB-OTG device controller.
//! Unlike the Linux FunctionFS driver, the OTG transport is
//! fully async: the session state machine is fed one [`SessionEvent`] per
//! endpoint completion and the next need is read straight from
//! [`BotSession::need`] / [`BotSession::out_slice`].
//!
//! Control requests (Get Max LUN / Bulk-Only Reset) are delivered to
//! [`MscHandler`] by [`embassy_usb::UsbDevice::run`]. The handler cannot borrow
//! the session, so it signals through the [`PENDING_RESET`] / [`USB_CONNECTED`]
//! statics; the BOT loop drains the reset flag at the top of each iteration,
//! and the status LCD (M4) reads [`usb_connected`], [`rx_bytes`] and
//! [`tx_bytes`].

use core::sync::atomic::{AtomicBool, AtomicU32, Ordering};

use defmt::warn;
use embassy_futures::select::{select, Either};
use embassy_time::{Duration, Timer};
use embassy_usb::control::{InResponse, OutResponse, Recipient, Request, RequestType};
use embassy_usb::driver::{EndpointError, EndpointIn, EndpointOut};
use embassy_usb::Handler;

use snowscsi::scsi::device::ScsiDevice;
use snowscsi::usb::{
    BotSession, BotStepResult, BotTargetError, SessionEvent, SessionNeed, SessionStep, BOT_RESET,
    GET_MAX_LUN,
};

/// Number of LUNs presented to the host, zero-based (SPC Get Max LUN answer).
///
/// One LUN: the whole SD card exposed as a DVD-RAM UDF-RW volume.
pub const MAX_LUN: u8 = 0;

/// Upper bound for the non-blocking overrun-drain probe: the BOT loop races a
/// bulk-OUT read against this timeout so a host that stops mid-phase cannot
/// wedge the session. Any real overrun bytes belong to the same bulk stream as
/// the declared data and are queued in the endpoint FIFO by the time the write
/// completes, so the read returns immediately; the timeout only bounds the
/// (normal, conforming-host) no-overrun case and therefore sits on the critical
/// path of *every* write. 200 µs (systimer resolution, not the 100 Hz scheduler
/// tick) is ample for the queued case and removes ~0.8 ms/write.
const PROBE_TIMEOUT: Duration = Duration::from_micros(200);

/// Set by [`MscHandler`] on a Bulk-Only Reset (control request or bus reset)
/// and consumed at the top of the BOT loop, which calls [`BotSession::reset`].
///
/// The handler runs inside `UsbDevice::run` and cannot borrow the session, so
/// the reset request is carried out-of-band through this flag.
static PENDING_RESET: AtomicBool = AtomicBool::new(false);

/// Whether the USB device is currently enabled *and* configured.
///
/// Maintained from the [`Handler`] callbacks (there is no public
/// `UsbDeviceState` getter); the M4 status LCD reads it via [`usb_connected`].
static USB_CONNECTED: AtomicBool = AtomicBool::new(false);

/// Bulk bytes received from the host (CBW fragments, Data-Out payload
/// chunks), measured at the endpoint-completion points of the BOT loop. The
/// status LCD divides the refresh-to-refresh delta by the interval to show an
/// **RX** (host → device) rate.
static RX_BYTES: AtomicU32 = AtomicU32::new(0);

/// Bulk bytes sent to the host (Data-In chunks, synthesized responses, CSWs),
/// measured at the endpoint-completion points of the BOT loop. The status LCD
/// divides the refresh-to-refresh delta by the interval to show a **TX**
/// (device → host) rate.
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
/// forwards it to a handler, so a preserved STALL cannot be observed from
/// here (see the `Stalled` handling in [`handle_done`]).
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

/// Run the BOT protocol loop forever over a bulk endpoint pair.
///
/// `work` is the SCSI data region (must be ≥ [`snowscsi::MIN_DATA_LEN`]);
/// `recv` is the bulk-OUT scratch (≥ `work.len()` and a multiple of the
/// endpoint MPS is recommended); `devs` is the LUN slice.
///
/// Mirrors the CLI's `serve_bot` poll loop: a pending reset is applied first,
/// then exactly one endpoint operation is driven to completion and its result
/// fed back to the session. `ep_out`/`ep_in` are `embassy-usb` endpoints, so
/// the loop is cancellation-free (each operation is awaited rather than
/// polled with a deadline — except the overrun probe, which must not block).
pub async fn run<O, I, D>(
    ep_out: &mut O,
    ep_in: &mut I,
    session: &mut BotSession,
    work: &mut [u8],
    recv: &mut [u8],
    devs: &mut [D],
) -> !
where
    O: EndpointOut,
    I: EndpointIn,
    D: ScsiDevice,
{
    assert!(
        work.len() >= snowscsi::MIN_DATA_LEN,
        "work buffer smaller than MIN_DATA_LEN"
    );

    loop {
        // Wait until the host has configured the device and enabled the bulk
        // endpoints, yielding to `UsbDevice::run()` which performs enumeration.
        //
        // CRITICAL: before configuration, the Synopsys driver's `read` returns
        // `Err(Disabled)` *immediately*; awaiting an already-ready future does
        // not yield, so a naive read loop would spin synchronously and starve
        // `UsbDevice::run()` (USB never comes up). `wait_enabled` parks the
        // task until the endpoints are live.
        ep_out.wait_enabled().await;
        ep_in.wait_enabled().await;

        // Out-of-band Bulk-Only Reset requested on the control pipe / bus.
        if PENDING_RESET.swap(false, Ordering::Relaxed) {
            session.reset();
        }

        match session.need() {
            SessionNeed::NeedOut { len, probe } => {
                // Never read more than the receive scratch; the core keeps
                // asking for the remainder on the next iteration.
                let n = len.min(recv.len());
                if probe {
                    // Data-Out overrun drain: try once with a short deadline so
                    // a host that stops sending cannot wedge the session. If
                    // nothing arrives, feed OutIdle so the core closes the
                    // phase with the CSW.
                    match select(ep_out.read(&mut recv[..n]), Timer::after(PROBE_TIMEOUT)).await {
                        Either::First(Ok(got)) => {
                            // Count before the session feed: this is a real
                            // bulk-OUT reception regardless of the outcome.
                            RX_BYTES.fetch_add(got as u32, Ordering::Relaxed);
                            feed(
                                session,
                                SessionEvent::OutRecv { data: &recv[..got] },
                                work,
                                devs,
                            );
                        }
                        Either::First(Err(EndpointError::Disabled)) => session.reset(),
                        Either::First(Err(EndpointError::BufferOverflow)) => {
                            warn!("bot: bulk OUT probe buffer overflow");
                        }
                        Either::Second(()) => {
                            feed(session, SessionEvent::OutIdle, work, devs);
                        }
                    }
                } else {
                    // Consolidate the whole pending chunk into one OutRecv. Feeding
                    // one 64-byte packet at a time makes the BOT core call xfer_in
                    // for every 64 bytes, turning each sector write into many tiny
                    // read-modify-write SD cycles. `n` is exactly what the core
                    // wants for this phase.
                    let mps = ep_out.info().max_packet_size as usize;
                    let mut got = 0usize;
                    let mut reset = false;
                    while got < n {
                        match ep_out.read(&mut recv[got..n]).await {
                            Ok(0) => break,
                            Ok(i) => {
                                got += i;
                                // A short packet terminates the host's bulk transfer early.
                                if i < mps {
                                    break;
                                }
                            }
                            Err(EndpointError::Disabled) => {
                                // Link gone: drop the transaction; anything
                                // already accumulated must NOT be fed, as
                                // `reset` has returned to the Command phase.
                                session.reset();
                                reset = true;
                                break;
                            }
                            Err(EndpointError::BufferOverflow) => {
                                // A packet larger than the remaining space in
                                // `recv[got..n]` (non-conforming/overrunning
                                // host). Keep the bytes already accumulated —
                                // feeding them keeps the core byte-synchronised
                                // — and let the outer loop retry the rest.
                                warn!("bot: bulk OUT packet larger than remaining recv space");
                                break;
                            }
                        }
                    }
                    if !reset && got > 0 {
                        // Count the Data-Out payload once per consolidated
                        // chunk, before feeding the session.
                        RX_BYTES.fetch_add(got as u32, Ordering::Relaxed);
                        feed(
                            session,
                            SessionEvent::OutRecv { data: &recv[..got] },
                            work,
                            devs,
                        );
                    }
                }
            }
            SessionNeed::NeedIn { .. } => {
                // Borrow the outgoing bytes only for the transfer; the borrow
                // must end before `feed` re-borrows the session. An empty
                // slice is a real ZLP (`write_transfer` would send nothing).
                // Capture the payload length inside the block: it is needed
                // for the TX byte meter after the borrow ends.
                let (sent_len, send) = {
                    let data = session.out_slice(work);
                    let sent_len = data.len();
                    let send = if data.is_empty() {
                        ep_in.write(&[]).await
                    } else {
                        ep_in.write_transfer(data, false).await
                    };
                    (sent_len, send)
                };
                match send {
                    Ok(()) => {
                        TX_BYTES.fetch_add(sent_len as u32, Ordering::Relaxed);
                        feed(session, SessionEvent::InSent, work, devs);
                    }
                    Err(EndpointError::Disabled) => session.reset(),
                    Err(EndpointError::BufferOverflow) => {
                        warn!("bot: bulk IN packet larger than endpoint");
                    }
                }
            }
            SessionNeed::NeedStall => {
                // Unreachable with the pinned `ShortNoStall` policy: only
                // `ShortfallPolicy::Short` stalls, and embassy-usb cannot expose
                // endpoint STALL to a class. Defensive reset if it ever happens.
                warn!("bot: unexpected NeedStall; resetting session");
                session.reset();
            }
            SessionNeed::Done(r) => handle_done(session, r),
        }
    }
}

/// Feed one bulk event to the session and react to a transaction end.
///
/// Keeps the `SessionStep` borrow scoped to this call so `handle_done` can
/// borrow the session mutably again.
fn feed<D: ScsiDevice>(
    session: &mut BotSession,
    ev: SessionEvent<'_>,
    work: &mut [u8],
    devs: &mut [D],
) {
    let done = match session.poll(ev, work, devs) {
        SessionStep::Done(r) => Some(r),
        _ => None,
    };
    if let Some(r) = done {
        handle_done(session, r);
    }
}

/// React to a transaction-end result from the core.
fn handle_done(session: &mut BotSession, result: BotStepResult) {
    match result {
        BotStepResult::Stalled => {
            // Deviation: the BOT spec wants both bulk endpoints STALLed on an
            // invalid CBW, but embassy-usb's `Bus` (which owns
            // `endpoint_set_stalled`) is private to `UsbDevice`. We cannot set
            // the STALL condition from the class driver. Instead drop the bad
            // transaction and reset the session; a conforming host never sends
            // an invalid CBW, and a reset is what the host would do next
            // anyway.
            warn!("bot: invalid CBW; endpoint STALL unsupported, resetting session");
            session.reset();
        }
        BotStepResult::Error(BotTargetError::Internal) => {
            warn!("bot: internal state error; resetting session");
            session.reset();
        }
        BotStepResult::Error(_) => {
            warn!("bot: transaction error; continuing");
        }
        BotStepResult::Unsupported => {
            // Emitted only by the blocking `step()` wrapper; this async loop
            // never calls it. Defensive no-op.
            warn!("bot: Unsupported step() result; ignoring");
        }
        BotStepResult::Processed | BotStepResult::Closed => {}
    }
}
