//! USB MSC Bulk-Only Transport session state machine (target.rs).
//!
//! [`BotSession`] is a pure, non-blocking protocol state machine: it never
//! blocks and never touches platform I/O. A driver feeds one [`SessionEvent`]
//! (an I/O completion) per [`BotSession::poll`] call and learns the next
//! need from the returned [`SessionStep`] (or the copyable [`BotSession::need`]).
//! The same core is driven by the PC FunctionFS poll loop, the blocking
//! [`BotSession::step`] convenience wrapper, and embedded `select!` drivers.
//!
//! Out-of-band control never enters the core: Bulk-Only Reset and Get Max
//! LUN arrive on the control pipe at any time (even mid data phase), so the
//! driver calls [`BotSession::reset`] / [`BotSession::max_lun`] directly
//! between bulk events.
//!
//! Design invariants (§4 / §3.7 / §3.8):
//! - CBW (31B) accumulates into an internal buffer; CSW (13B) is assembled
//!   in an internal buffer; the caller's `data` area holds only SCSI data.
//! - STALL is used for invalid CBWs (both pipes) and, under
//!   [`ShortfallPolicy::Short`], for a Data-In shortfall (Bulk-In only).
//! - Data-Out host overrun is drained to a short packet so leftover bytes
//!   never corrupt the next CBW.
//! - After a reset the session injects a UNIT ATTENTION: delivered on the
//!   next TEST UNIT READY (Failed CSW), cleared by REQUEST SENSE.
//!
//! ## Data-In shortfall policy ([`ShortfallPolicy`])
//!
//! BOT §6.7.2 (cases (4)/(5): the host's `dCBWDataTransferLength` exceeding
//! the data the device intends to send) lets the device either pad fill data up
//! to `dCBWDataTransferLength`, or end with a short packet **and STALL** the
//! Bulk-In pipe. A plain short packet without the STALL skips that *shall* and
//! is therefore outside the specification (the BOT spec calls un-outlined
//! behaviour indeterminate). The session selects one of three behaviours, whose
//! rationale is on [`ShortfallPolicy`]:
//!
//! - [`ShortfallPolicy::ShortNoStall`] (default, max-compat): the phase ends
//!   with a short packet (plus a ZLP when the produced length is a multiple of
//!   the bulk MPS, including zero) and reports the shortfall in
//!   `dCSWDataResidue`. This is the deliberate, documented deviation — verified
//!   benign on Linux usb-storage, UEFI/EDK2, FreeBSD and U-Boot. Mainline
//!   Linux's own gadget does the same and admits it:
//!   "This violates the Bulk-Only Transport specification, which requires us
//!   to pad the data if we don't halt the endpoint. Presumably nobody will
//!   mind." — `drivers/usb/gadget/function/f_mass_storage.c`, `finish_reply()`.
//! - [`ShortfallPolicy::Short`] (conformant): the short packet is followed by a
//!   Bulk-In STALL; the CSW is queued straight away and reaches the host once
//!   it clears the halt (handled by the USB core). It needs a driver that
//!   implements `BotIo::stall_in` — retrying transient `-EAGAIN` (the endpoint
//!   cannot be halted while a request is queued or the FIFO still holds
//!   uncollected bytes) — and then calls [`BotSession::stall_applied`]. A real
//!   `stall_in` failure aborts the transaction via [`BotSession::reset`].
//! - [`ShortfallPolicy::Pad`] (conformant up to the cap): fill zeros up to
//!   `dCBWDataTransferLength`, capped at [`MAX_PAD`]. The fill is not "relevant"
//!   data, so the residue stays `declared − produced`. A cap-exhausted pad ends
//!   like `ShortNoStall`. `Pad` never touches the control plane.
//!
//! The ZLP is mandatory whenever the data phase ends on a shortfall whose wire
//! length is an exact multiple of the MPS: a bulk-IN transfer only ends on the
//! requested byte count, a short packet, or an error, so an MPS-multiple
//! shortfall (including zero bytes) must be terminated with a ZLP (or, for
//! `Short`, the STALL) or the host never sees the end of the data phase.
//!
//! Residue is always `declared − produced` (the *relevant* data actually sent);
//! `Pad` fill bytes are not relevant, so a fully padded phase still reports a
//! non-zero residue.
//!
//! ## `step()` constraint
//!
//! [`BotSession::step`] does not service the control plane, so it pre-rejects
//! [`ShortfallPolicy::Short`] with [`BotStepResult::Unsupported`] at entry,
//! before any wire effect. Drive `Short` with a `need()`/`poll()` loop that
//! handles [`SessionNeed::NeedStall`]. `ShortNoStall` and `Pad` are fully
//! drivable by `step()`.

use core::time::Duration;

use crate::scsi::device::{CommandOutcome, ScsiDevice, Xfer};
use crate::scsi::scsi::{asc, op as scsi_op, Sense, SenseKey};
use crate::usb::bot::{BotDir, Cbw, Csw, CswStatus};
use crate::usb::io::BotIo;
use crate::usb::{CBW_LEN, CSW_LEN};

/// Blocking `step` receive granularity: drives the poll loop and bounds the
/// Data-Out overrun drain wait (mirrors the PC driver's 50ms ctrl poll).
const STEP_RECV_TIMEOUT: Duration = Duration::from_millis(50);

/// Default USB bulk endpoint max packet size (high-speed, 512 B; full-speed is
/// 64 B). FunctionFS high-speed enumeration is the only tested path, so this
/// remains the default; Full-Speed devices (e.g. the ESP32-S3 internal PHY)
/// override it per session with [`BotSession::with_bulk_mps`] /
/// [`BotSession::set_bulk_mps`].
/// A Data-In phase that ends on a full-MPS packet is not a short packet, so a
/// shortfall whose length is a multiple of the MPS — including zero bytes —
/// must be closed with a ZLP before the CSW (BOT §6.7 Case (4)/(5)).
const BOT_BULK_MPS: u64 = 512;

/// Maximum number of fill bytes a single `ShortfallPolicy::Pad` data phase
/// will send. A `dCBWDataTransferLength` far beyond the produced data
/// (host bug or hostile host) degrades to the `ShortNoStall` ending once this
/// many fill bytes have gone out, so a garbage CBW cannot trigger an unbounded
/// zero pour. Units: bytes.
pub const MAX_PAD: u64 = 64 * 1024;

/// Zero source for `ShortfallPolicy::Pad` fill, emitted through
/// [`BotSession::out_slice`]. `4096` is a multiple of every realistic bulk MPS
/// (64 Full-Speed, 512 High-Speed), so intermediate fill chunks are full-MPS
/// packets; only a chunk reaching the (possibly non-aligned) pad target is a
/// short packet, which is correct because it is the final transfer.
const ZERO_CHUNK: [u8; 4096] = [0u8; 4096];

/// Policy for ending a Data-In command's data stage when a shortfall of
/// relevant data occurs (BOT §6.7.2). The default (`ShortNoStall`) is the
/// max-compat deviation; `Short` and `Pad` are the conformant modes. The
/// caller knows its transport, so the selected variant is the capability
/// declaration; a `Short`-without-`stall_in` mismatch exits through the
/// reset route (the driver calls [`BotSession::reset`]), never silently.
///
/// ## Choice logic (why exactly three values)
///
/// Conformance alone never demands `Pad` — a conformant ending (short packet
/// plus STALL) is available at any shortfall size; the split exists where
/// callers *cannot* stall. Per value:
///
/// - `ShortNoStall` — default. Runs unaided on any transport (no halt
///   capability, no clear observability required); the deliberate deviation
///   for all shortfall sizes, S3-validated. For devices whose shortfalls are
///   almost all large Data-phase errors, this is the semantically honest
///   choice.
/// - `Short` — opt-in for stall-capable transports *with* clear observability
///   (both legs). Any shortfall size; enters the host's halt/clear recovery
///   flow (per-host software path, verified benign on Linux/EDK2/FreeBSD/
///   U-Boot).
/// - `Pad` — opt-in for stall-less transports. Near-free for the structural
///   small shortfalls that occur routinely (INQUIRY/REQUEST SENSE/MODE SENSE:
///   tens to ~200 bytes ≈ one FS packet), and avoids the halt/clear/recovery
///   path entirely (`-EBADMSG`-flavoured quirk risk included). Large
///   shortfalls are capped by [`MAX_PAD`] and degrade to the `ShortNoStall`
///   ending, so a garbage `dCBWDataTransferLength` cannot turn into an
///   unbounded zero pour. The policy is "pad small, never flood" — conformant
///   precisely where it matters most.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum ShortfallPolicy {
    /// Conformant below the fill cap: pad fill zeros up to
    /// `dCBWDataTransferLength`, sending at most [`MAX_PAD`] fill bytes (the
    /// fill is not "relevant" data — residue stays `declared − produced`).
    /// Pure bulk state machine (no control plane) — unconditionally: a
    /// shortfall that exhausts the cap ends like `ShortNoStall` (short packet
    /// plus CSW), so `Pad` is explicitly non-conformant above the cap and never
    /// touches the stall path.
    ///
    /// The fill is delivered without a premature short packet: the final
    /// relevant chunk is zero-extended in-buffer to the next bulk-MPS boundary
    /// before it is sent, so a shortfall whose relevant length is not a
    /// multiple of the MPS (e.g. a 95-byte INQUIRY against a declared 192) is
    /// still filled to `dCBWDataTransferLength` conformantly, rather than
    /// leaking a short packet that would terminate the host's bulk-IN before
    /// the fill.
    Pad,
    /// Conformant: short packet then STALL Bulk-In; the withheld CSW is queued
    /// immediately and delivered once the host clears the halt. Requires a
    /// driver that implements `stall_in` (retrying transient `-EAGAIN`) and
    /// then calls [`BotSession::stall_applied`]; a real `stall_in` failure
    /// aborts via [`BotSession::reset`].
    Short,
    /// Non-conformant, default: plain short packet, no STALL. Runs unaided on
    /// any transport (no stall capability, no clear observability required);
    /// the S3-validated behaviour.
    #[default]
    ShortNoStall,
}

/// One bulk I/O completion fed from the driver to the core.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SessionEvent<'a> {
    /// bulk OUT (host → device): `data` is a CBW fragment or a Data-Out
    /// chunk (borrowed from the driver's receive buffer).
    OutRecv { data: &'a [u8] },
    /// bulk IN (device → host): the pending packet has been sent.
    InSent,
    /// The driver's bulk-OUT receive found no data (timed out). Ignored by
    /// every state except the Data-Out overrun drain, where it ends the
    /// drain and moves on to the CSW.
    OutIdle,
}

/// The core's next need, returned by [`BotSession::poll`].
///
/// `NeedIn` borrows the caller's `data` region (Data-In chunks / synthesized
/// responses) or the internal CSW buffer; `NeedOut` needs `len` more bytes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SessionStep<'a> {
    /// Receive `len` more bytes. `probe` marks a non-blocking drain receive
    /// (Data-Out overrun): the driver should try once; a WouldBlock result
    /// ends the data phase and should be fed back as [`SessionEvent::OutIdle`].
    NeedOut { len: usize, probe: bool },
    /// Send these bytes (chunk from `data`, or the internal CSW).
    NeedIn(&'a [u8]),
    /// STALL the Bulk-In endpoint (`ShortfallPolicy::Short`; see the
    /// module-level "Data-In shortfall policy"). The driver calls
    /// `BotIo::stall_in` (retrying transient `-EAGAIN`), then
    /// [`BotSession::stall_applied`] to release the withheld CSW.
    NeedStall,
    /// The transaction ended; the driver stops feeding bulk events.
    Done(BotStepResult),
}

/// Copyable variant of [`SessionStep`] (no borrows), for [`BotSession::need`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SessionNeed {
    /// See [`SessionStep::NeedOut`].
    NeedOut { len: usize, probe: bool },
    /// Send `len` bytes (fetch via [`BotSession::out_slice`]).
    NeedIn { len: usize },
    /// STALL the Bulk-In endpoint (see [`SessionStep::NeedStall`]).
    NeedStall,
    /// Transaction ended; the driver stops feeding bulk events.
    Done(BotStepResult),
}

/// How a transaction ended.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BotStepResult {
    /// CSW sent; back in Command phase.
    Processed,
    /// Invalid CBW — STALL both bulk endpoints and wait for a reset.
    Stalled,
    /// I/O link failed (used by the blocking `step` wrapper).
    Closed,
    /// Caller bug (buffer too small / impossible event).
    Error(BotTargetError),
    /// The selected [`ShortfallPolicy`] cannot be driven by the blocking
    /// [`BotSession::step`] wrapper. Emitted only by `step()` and only for
    /// `Short` (which needs a `need()`/`poll()` loop that services the
    /// control plane); returned at entry, before any wire effect.
    Unsupported,
}

/// Core-level error (no_std).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BotTargetError {
    /// The caller's `data` buffer is smaller than [`crate::MIN_DATA_LEN`].
    WorkBufTooSmall,
    /// I/O failure (reported through the blocking `step` wrapper).
    Io,
    /// An impossible state transition (driver fed a wrong event).
    Internal,
}

impl core::fmt::Display for BotTargetError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::WorkBufTooSmall => write!(f, "data buffer smaller than MIN_DATA_LEN"),
            Self::Io => write!(f, "bulk I/O failure"),
            Self::Internal => write!(f, "internal BOT state error"),
        }
    }
}

impl core::error::Error for BotTargetError {}

/// BOT phase machine state (all Copy).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum BotState {
    /// Command phase: accumulate the 31-byte CBW.
    Command { got: usize },
    /// Data-In phase: send chunks from the device until `sent == transfer_len`.
    DataIn {
        expected: u64,
        transfer_len: u64,
        sent: u64,
        tag: u32,
        lun: usize,
        chunk: usize,
    },
    /// Data-Out phase: receive chunks and write to the backend.
    DataOut {
        declared: u64,
        to_write: u64,
        received: u64,
        written: u64,
        tag: u32,
        lun: usize,
        status: CswStatus,
        chunk: usize,
    },
    /// Parameter-list Data-Out: receive `expected` bytes contiguously
    /// into `data[0..expected]` then call `complete_param`.
    ParamOut {
        expected: u64,
        received: u64,
        tag: u32,
        lun: usize,
        cdb: [u8; 16],
        cdb_len: usize,
        chunk: usize,
    },
    /// Data-Out host overrun: read-and-discard until a short packet.
    DataOutOverrun {
        tag: u32,
        residue: u64,
        status: CswStatus,
        chunk: usize,
    },
    /// CSW pending in the internal buffer.
    Csw,
    /// Data-In pad: send fill zeros to reach `declared` (BOT §6.7.2
    /// alternative to STALL), capped at [`MAX_PAD`] fill bytes. `produced` is
    /// the relevant data already sent (the residue basis, `declared −
    /// produced`); `wire` is the total bytes actually sent so far (relevant +
    /// fill, excluding the pending `chunk`); `chunk` is the next fill chunk
    /// length, served from an internal zero source. A cap-exhausted pad ends
    /// `ShortNoStall`-style (short packet + CSW, no STALL).
    DataInPad {
        tag: u32,
        declared: u64,
        produced: u64,
        wire: u64,
        status: CswStatus,
        chunk: usize,
    },
    /// CSW pending, but a zero-length packet must terminate the data phase
    /// first (a shortfall whose length is a multiple of the bulk MPS,
    /// including zero bytes — see [`finish_data_in`]). Carries the shortfall
    /// payload so the terminating `InSent` can enter [`BotState::DataInStall`]
    /// under `ShortfallPolicy::Short`.
    CswZlp {
        tag: u32,
        declared: u64,
        actual: u64,
        status: CswStatus,
    },
    /// The CSW is pending, but the driver must first STALL Bulk-In
    /// (`ShortfallPolicy::Short`): `need()` returns `NeedStall`. Holds the CSW
    /// payload that [`BotSession::stall_applied`] turns into the CSW once the
    /// driver has set the halt. The host's CLEAR_FEATURE is handled by the USB
    /// core and is not observable here, so this state is released by the driver
    /// (see [`stall_applied`](BotSession::stall_applied)), not by an event.
    /// Distinct from the invalid-CBW terminal [`BotState::Stalled`].
    DataInStall {
        tag: u32,
        declared: u64,
        actual: u64,
        status: CswStatus,
    },
    /// Frozen after an invalid CBW; only `reset()` unfreezes.
    Stalled,
}

/// BOT session: a non-blocking protocol state machine over one bulk pipe
/// pair (plus the driver-mediated control pipe).
#[derive(Debug)]
pub struct BotSession {
    state: BotState,
    cbw: [u8; CBW_LEN],
    csw: [u8; CSW_LEN],
    num_luns: u8,
    invalid_lun_sense: Option<Sense>,
    pending_ua: Option<Sense>,
    /// Bulk endpoint max packet size in bytes used for the Data-In ZLP
    /// decision (`BOT_BULK_MPS` by default; 64 for Full-Speed, 512 for
    /// High-Speed). Stored as `u64` to match the transfer counter domain.
    bulk_mps: u64,
    /// How a Data-In shortfall ends (default `ShortNoStall`; see
    /// [`ShortfallPolicy`]).
    shortfall: ShortfallPolicy,
}

impl Default for BotSession {
    fn default() -> Self {
        Self::new()
    }
}

impl BotSession {
    /// A session serving a single LUN.
    pub fn new() -> Self {
        Self::with_luns(1)
    }

    /// A session serving `num_luns` logical units (1..=16), used by drivers
    /// that must answer Get Max LUN before the first [`poll`] call.
    ///
    /// [`poll`]: Self::poll
    pub fn with_luns(num_luns: usize) -> Self {
        Self {
            state: BotState::Command { got: 0 },
            cbw: [0u8; CBW_LEN],
            csw: [0u8; CSW_LEN],
            num_luns: num_luns.clamp(1, 16) as u8,
            invalid_lun_sense: None,
            pending_ua: None,
            bulk_mps: BOT_BULK_MPS,
            shortfall: ShortfallPolicy::default(),
        }
    }

    /// Override the bulk endpoint max packet size used for the Data-In ZLP
    /// decision (builder style). The value is the USB bulk endpoint's
    /// `wMaxPacketSize`: **64** for Full-Speed, **512** for High-Speed.
    ///
    /// `0` is rejected and the default (`BOT_BULK_MPS`) is kept instead.
    pub fn with_bulk_mps(mut self, mps: u16) -> Self {
        self.set_bulk_mps(mps);
        self
    }

    /// Set the bulk endpoint max packet size used for the Data-In ZLP decision
    /// (see [`with_bulk_mps`](Self::with_bulk_mps)). `0` is rejected and the
    /// default (`BOT_BULK_MPS`) is kept instead.
    pub fn set_bulk_mps(&mut self, mps: u16) {
        self.bulk_mps = if mps == 0 {
            BOT_BULK_MPS
        } else {
            u64::from(mps)
        };
    }

    /// The bulk endpoint max packet size currently used for the Data-In ZLP
    /// decision (64 for Full-Speed, 512 for High-Speed by default).
    pub fn bulk_mps(&self) -> u16 {
        self.bulk_mps as u16
    }

    /// Select the Data-In shortfall policy (builder style; see
    /// [`ShortfallPolicy`]). Defaults to `ShortNoStall`.
    pub fn with_shortfall(mut self, policy: ShortfallPolicy) -> Self {
        self.set_shortfall(policy);
        self
    }

    /// Set the Data-In shortfall policy (see [`with_shortfall`](Self::with_shortfall)).
    pub fn set_shortfall(&mut self, policy: ShortfallPolicy) {
        self.shortfall = policy;
    }

    /// The session's current Data-In shortfall policy.
    pub fn shortfall(&self) -> ShortfallPolicy {
        self.shortfall
    }

    /// The session's current need (Copy; the driver polls the matching
    /// endpoint / checks ep0 in between).
    pub fn need(&self) -> SessionNeed {
        match self.state {
            BotState::Command { got } => SessionNeed::NeedOut {
                len: CBW_LEN - got,
                probe: false,
            },
            BotState::DataIn { chunk, .. } => SessionNeed::NeedIn { len: chunk },
            BotState::DataOut { chunk, .. } => SessionNeed::NeedOut {
                len: chunk,
                probe: false,
            },
            BotState::ParamOut { chunk, .. } => SessionNeed::NeedOut {
                len: chunk,
                probe: false,
            },
            BotState::DataOutOverrun { chunk, .. } => SessionNeed::NeedOut {
                len: chunk,
                probe: true,
            },
            BotState::Csw => SessionNeed::NeedIn { len: CSW_LEN },
            BotState::CswZlp { .. } => SessionNeed::NeedIn { len: 0 },
            BotState::DataInPad { chunk, .. } => SessionNeed::NeedIn { len: chunk },
            BotState::DataInStall { .. } => SessionNeed::NeedStall,
            BotState::Stalled => SessionNeed::Done(BotStepResult::Stalled),
        }
    }

    /// The bytes to send when `need() == NeedIn`: a Data-In chunk from the
    /// caller's `data` region, or the internal CSW buffer.
    pub fn out_slice<'a>(&'a mut self, data: &'a [u8]) -> &'a [u8] {
        match self.state {
            BotState::Csw => &self.csw[..],
            BotState::DataIn { chunk, .. } => &data[..chunk],
            BotState::DataInPad { chunk, .. } => &ZERO_CHUNK[..chunk],
            _ => &[],
        }
    }

    /// Get Max LUN answer value (`num_luns - 1`, ≤ 15). The LUN count is
    /// refreshed from the device slice on every command.
    pub fn max_lun(&self) -> u8 {
        self.num_luns.saturating_sub(1)
    }

    /// Bulk-Only Reset / LinkReset: abort any in-flight transaction, return
    /// to the Command phase, and inject a UNIT ATTENTION for the next
    /// TEST UNIT READY (BOT §4.2, §5.2).
    ///
    /// Per BOT §3.1, a Bulk-Only Reset **preserves** the endpoint STALL
    /// condition. If the session is currently STALLed (invalid CBW), the
    /// reset keeps it STALLed until the host sends CLEAR FEATURE(ENDPOINT_HALT);
    /// see [`clear_feature_halt`](Self::clear_feature_halt).
    pub fn reset(&mut self) {
        self.cbw = [0u8; CBW_LEN];
        self.invalid_lun_sense = None;
        self.pending_ua = Some(Sense::new(SenseKey::UnitAttention, asc::POWER_ON_RESET, 0));
        // BOT §3.1: preserve STALL across BotReset. Only leave the STALLed
        // state via CLEAR FEATURE(ENDPOINT_HALT).
        if !matches!(self.state, BotState::Stalled) {
            self.state = BotState::Command { got: 0 };
        }
    }

    /// CLEAR FEATURE(ENDPOINT_HALT): clear a bulk-endpoint STALL condition
    /// (USB 2.0 §9.4.1) and return to the Command phase.
    ///
    /// Per BOT §3.1, the host must send this request after a BotReset that
    /// preserved a STALL condition to resume normal operation. This is only
    /// meaningful for transports that can observe the host's CLEAR_FEATURE (a
    /// platform-level capability); a data-phase STALL left by a
    /// `ShortfallPolicy::Short` shortfall is released with
    /// [`stall_applied`](Self::stall_applied) instead.
    pub fn clear_feature_halt(&mut self) {
        if matches!(self.state, BotState::Stalled) {
            self.state = BotState::Command { got: 0 };
        }
    }

    /// Release the data-phase STALL entered by a `ShortfallPolicy::Short`
    /// shortfall. The driver calls this immediately after [`BotIo::stall_in`]
    /// succeeds: the host's CLEAR_FEATURE(ENDPOINT_HALT) is handled by the USB
    /// core and is **not** observable by the function, so the core does not
    /// wait for an event — the withheld CSW is queued straight away and reaches
    /// the host once it clears the halt. No-op outside the `DataInStall` state.
    pub fn stall_applied(&mut self) {
        if matches!(self.state, BotState::DataInStall { .. }) {
            self.state = BotState::Csw;
        }
    }

    /// Non-blocking state-machine step: consume one event and return the
    /// next need. `data` is the pure SCSI data area (≥
    /// [`crate::MIN_DATA_LEN`] for commands routed to the device); `devs`
    /// is the LUN slice.
    pub fn poll<'a, 'e, D: ScsiDevice>(
        &'a mut self,
        ev: SessionEvent<'e>,
        data: &'a mut [u8],
        devs: &mut [D],
    ) -> SessionStep<'a> {
        match self.state {
            BotState::Stalled => SessionStep::Done(BotStepResult::Stalled),
            BotState::Command { got } => self.poll_command(ev, data, devs, got),
            BotState::DataIn { .. } => self.poll_data_in(ev, data, devs),
            BotState::DataOut { .. } => self.poll_data_out(ev, data, devs),
            BotState::ParamOut { .. } => self.poll_param_out(ev, data, devs),
            BotState::DataOutOverrun { .. } => self.poll_overrun(ev),
            BotState::Csw => self.poll_csw(ev),
            BotState::CswZlp { .. } => self.poll_csw_zlp(ev),
            BotState::DataInPad { .. } => self.poll_data_in_pad(ev),
            BotState::DataInStall { .. } => self.poll_data_in_stall(ev),
        }
    }

    /// Blocking convenience wrapper over `need()` + `poll()`: drives one
    /// transaction to completion using `io`. `recv` is the driver's receive
    /// scratch (≥ `data.len()`). Out-of-band control is NOT handled here.
    pub fn step<B: BotIo, D: ScsiDevice>(
        &mut self,
        io: &mut B,
        data: &mut [u8],
        recv: &mut [u8],
        devs: &mut [D],
    ) -> BotStepResult {
        // `Short` needs the `stall_in` capability that `step()` does not
        // service. Pre-reject at entry, before any wire effect, so a mid-phase
        // exit can never leave the wire in a half-phase.
        if self.shortfall == ShortfallPolicy::Short {
            return BotStepResult::Unsupported;
        }
        if data.len() < crate::MIN_DATA_LEN {
            return BotStepResult::Error(BotTargetError::WorkBufTooSmall);
        }
        loop {
            match self.need() {
                SessionNeed::NeedOut { len, .. } => {
                    if len > recv.len() {
                        return BotStepResult::Error(BotTargetError::WorkBufTooSmall);
                    }
                    match io.recv_out(&mut recv[..len], Some(STEP_RECV_TIMEOUT)) {
                        Ok(n) => {
                            if n == 0 {
                                return BotStepResult::Closed;
                            }
                            let step =
                                self.poll(SessionEvent::OutRecv { data: &recv[..n] }, data, devs);
                            if let SessionStep::Done(r) = step {
                                return r;
                            }
                        }
                        Err(crate::usb::BotIoErr::WouldBlock) => {
                            let step = self.poll(SessionEvent::OutIdle, data, devs);
                            if let SessionStep::Done(r) = step {
                                return r;
                            }
                        }
                        Err(_) => return BotStepResult::Closed,
                    }
                }
                SessionNeed::NeedIn { len } => {
                    let bytes = self.out_slice(&data[..]);
                    if bytes.len() != len {
                        return BotStepResult::Error(BotTargetError::Internal);
                    }
                    if io.send_in(bytes).is_err() {
                        return BotStepResult::Closed;
                    }
                    let step = self.poll(SessionEvent::InSent, data, devs);
                    if let SessionStep::Done(r) = step {
                        return r;
                    }
                }
                SessionNeed::NeedStall => {
                    // Unreachable: `Short` (the only policy that stalls) was
                    // pre-rejected above; `Pad`/`ShortNoStall` never stall.
                    return BotStepResult::Unsupported;
                }
                SessionNeed::Done(r) => return r,
            }
        }
    }

    // ── Command phase ──────────────────────────────────────────────

    fn poll_command<'a, 'e, D: ScsiDevice>(
        &'a mut self,
        ev: SessionEvent<'e>,
        data: &'a mut [u8],
        devs: &mut [D],
        got: usize,
    ) -> SessionStep<'a> {
        match ev {
            SessionEvent::InSent => {
                SessionStep::Done(BotStepResult::Error(BotTargetError::Internal))
            }
            SessionEvent::OutIdle => SessionStep::NeedOut {
                len: CBW_LEN - got,
                probe: false,
            },
            SessionEvent::OutRecv { data: chunk } => {
                if chunk.len() > CBW_LEN - got {
                    crate::warn!(
                        "bot: CBW packet tail {} bytes discarded (single-packet CBW is 31B)",
                        chunk.len() - (CBW_LEN - got)
                    );
                }
                let add = chunk.len().min(CBW_LEN - got);
                self.cbw[got..got + add].copy_from_slice(&chunk[..add]);
                let got = got + add;
                if got < CBW_LEN {
                    self.state = BotState::Command { got };
                    return SessionStep::NeedOut {
                        len: CBW_LEN - got,
                        probe: false,
                    };
                }
                match Cbw::parse(&self.cbw) {
                    None => {
                        self.state = BotState::Stalled;
                        SessionStep::Done(BotStepResult::Stalled)
                    }
                    Some(cbw) => self.dispatch_cbw(&cbw, data, devs),
                }
            }
        }
    }

    // ── Command dispatch ───────────────────────────────────────────

    fn dispatch_cbw<'a, D: ScsiDevice>(
        &'a mut self,
        cbw: &Cbw,
        data: &'a mut [u8],
        devs: &mut [D],
    ) -> SessionStep<'a> {
        self.num_luns = devs.len().clamp(1, 16) as u8;
        let cdb = cbw.cdb_slice();
        let declared = u64::from(cbw.data_len);
        let mut hx = [0u8; 49];
        crate::debug!(
            "bot cbw lun={} dir={:?} len={} tag={} cdb={}",
            cbw.lun,
            cbw.dir,
            declared,
            cbw.tag,
            core::str::from_utf8(crate::cdrom::drive::hex_of(&mut hx, cdb)).unwrap_or("?")
        );

        // REPORT LUNS is served for any addressed LUN (§5.3).
        if cdb.first() == Some(&scsi_op::REPORT_LUNS) {
            // SPC-3 Table 148: SELECT REPORT 00h/02h report the full
            // inventory here (all LUNs are peripheral/flat); 01h reports
            // well-known logical units only (none implemented → empty list);
            // 03h-FFh are reserved → CHECK CONDITION / INVALID FIELD IN CDB.
            let select = cdb.get(2).copied().unwrap_or(0);
            if select > 0x02 {
                if let Some(dev) = devs.get_mut(cbw.lun as usize) {
                    dev.set_sense(Sense::new(SenseKey::IllegalRequest, asc::INVALID_FIELD, 0));
                }
                return self.finish_cmd(cbw, 0, CswStatus::Failed, data.len());
            }
            let n = write_report_luns(data, if select == 0x01 { 0 } else { devs.len() });
            return self.synthesize_data_in(cbw, data, n as u64);
        }

        if cbw.lun as usize >= devs.len() {
            // Invalid LUN (§4.6): Failed CSW + REQUEST SENSE (ASC 0x25).
            // SPC-3 §6.27: REQUEST SENSE to an unsupported LUN shall return
            // GOOD with sense ILLEGAL REQUEST / LOGICAL UNIT NOT SUPPORTED,
            // and shall do so on *every* REQUEST SENSE (not consume once).
            if cdb.first() == Some(&scsi_op::REQUEST_SENSE) {
                let sense = self.invalid_lun_sense.unwrap_or(Sense::new(
                    SenseKey::IllegalRequest,
                    asc::LOGICAL_UNIT_NOT_SUPPORTED,
                    0,
                ));
                self.invalid_lun_sense = Some(sense);
                let n = sense.write_fixed(data);
                return self.synthesize_data_in(cbw, data, n as u64);
            }
            self.invalid_lun_sense = Some(Sense::new(
                SenseKey::IllegalRequest,
                asc::LOGICAL_UNIT_NOT_SUPPORTED,
                0,
            ));
            return self.finish_cmd(cbw, 0, CswStatus::Failed, data.len());
        }

        // Valid LUN: unit-attention injection (§5.2). The UA is delivered
        // on the next TEST UNIT READY and cleared by REQUEST SENSE.
        if self.pending_ua.is_some() {
            match cdb.first() {
                Some(&scsi_op::TEST_UNIT_READY) => {
                    return self.finish_cmd(cbw, 0, CswStatus::Failed, data.len());
                }
                Some(&scsi_op::REQUEST_SENSE) => {
                    // Defensive: no UA (driver raced a reset) — report an
                    // empty fixed-sense (NO SENSE) instead of panicking.
                    let sense = self.pending_ua.take().unwrap_or_else(Sense::clear);
                    let n = sense.write_fixed(data);
                    return self.synthesize_data_in(cbw, data, n as u64);
                }
                _ => {}
            }
        }

        let lun = cbw.lun as usize;
        let outcome = match devs[lun].do_cmd(cdb, data) {
            Ok(o) => o,
            Err(crate::scsi::device::Error::WorkBufTooSmall) => {
                return SessionStep::Done(BotStepResult::Error(BotTargetError::WorkBufTooSmall));
            }
            Err(_) => {
                return SessionStep::Done(BotStepResult::Error(BotTargetError::Internal));
            }
        };
        match outcome {
            CommandOutcome::Status => self.finish_cmd(cbw, 0, CswStatus::Passed, data.len()),
            CommandOutcome::StatusWithSense => {
                self.finish_cmd(cbw, 0, CswStatus::Passed, data.len())
            }
            CommandOutcome::CheckCondition => {
                self.finish_cmd(cbw, 0, CswStatus::Failed, data.len())
            }
            CommandOutcome::OutInline { len } => {
                if declared == 0 {
                    // BOT §6.7.1 Case (2) Hn<Di: Di with Hn => PhaseError.
                    if len > 0 {
                        return self.finish_cmd(cbw, 0, CswStatus::PhaseError, data.len());
                    }
                    return self.finish_cmd(cbw, 0, CswStatus::Passed, data.len());
                }
                if cbw.dir != BotDir::DataIn {
                    return self.finish_cmd(cbw, 0, CswStatus::PhaseError, data.len());
                }
                // `len` is work-buffer-relative (`usize`); widen once at the
                // BOT boundary (declared ≤ u32::MAX per the CBW spec, so the
                // min below is exact on every target).
                let actual = (len as u64).min(declared);
                if actual == 0 {
                    return self.finish_cmd(cbw, 0, CswStatus::Passed, data.len());
                }
                let mut chunk = (actual as usize).min(data.len());
                if chunk as u64 == actual {
                    chunk += self.merge_pad_boundary(data, chunk, declared, actual);
                }
                self.state = BotState::DataIn {
                    expected: declared,
                    transfer_len: actual,
                    sent: chunk as u64,
                    tag: cbw.tag,
                    lun,
                    chunk,
                };
                SessionStep::NeedIn(&data[..chunk])
            }
            CommandOutcome::OutXfer { len: transfer_len } => {
                if declared == 0 {
                    // BOT §6.7.1 Case (2) Hn<Di.
                    if transfer_len > 0 {
                        return self.finish_cmd(cbw, 0, CswStatus::PhaseError, data.len());
                    }
                    return self.finish_cmd(cbw, 0, CswStatus::Passed, data.len());
                }
                if cbw.dir != BotDir::DataIn {
                    return self.finish_cmd(cbw, 0, CswStatus::PhaseError, data.len());
                }
                let actual = transfer_len.min(declared);
                if actual == 0 {
                    return self.finish_cmd(cbw, 0, CswStatus::Passed, data.len());
                }
                let mut chunk = (actual as usize).min(data.len());
                let produced = match devs[lun].xfer_out(0, &mut data[..chunk]) {
                    Xfer::Inline { len } => len,
                    Xfer::Store(_) => {
                        return SessionStep::Done(BotStepResult::Error(BotTargetError::Internal));
                    }
                };
                if produced != chunk {
                    return self.finish_cmd(cbw, 0, CswStatus::Failed, data.len());
                }
                if chunk as u64 == actual {
                    chunk += self.merge_pad_boundary(data, chunk, declared, actual);
                }
                self.state = BotState::DataIn {
                    expected: declared,
                    transfer_len: actual,
                    sent: chunk as u64,
                    tag: cbw.tag,
                    lun,
                    chunk,
                };
                SessionStep::NeedIn(&data[..chunk])
            }
            CommandOutcome::InXfer { len: transfer_len } => {
                if declared == 0 {
                    // BOT §6.7.1 Case (3) Hn<Do.
                    if transfer_len > 0 {
                        return self.finish_cmd(cbw, 0, CswStatus::PhaseError, data.len());
                    }
                    return self.finish_cmd(cbw, 0, CswStatus::Passed, data.len());
                }
                if cbw.dir != BotDir::DataOut {
                    return self.finish_cmd(cbw, 0, CswStatus::PhaseError, data.len());
                }
                let to_write = transfer_len.min(declared);
                let status = CswStatus::Passed;
                let chunk = (declared as usize).min(data.len());
                self.state = BotState::DataOut {
                    declared,
                    to_write,
                    received: 0,
                    written: 0,
                    tag: cbw.tag,
                    lun,
                    status,
                    chunk,
                };
                SessionStep::NeedOut {
                    len: chunk,
                    probe: false,
                }
            }
            CommandOutcome::InParam { expected_len } => {
                let expected = expected_len as u64;
                if expected == 0 {
                    return self.finish_cmd(cbw, 0, CswStatus::Passed, data.len());
                }
                if cbw.dir != BotDir::DataOut {
                    return self.finish_cmd(cbw, 0, CswStatus::PhaseError, data.len());
                }
                // BOT §6.7.3 Case (13) Ho<Do: Ho < Do => PhaseError.
                if declared < expected {
                    return self.finish_cmd(cbw, 0, CswStatus::PhaseError, data.len());
                }
                if declared != expected {
                    return self.finish_cmd(cbw, 0, CswStatus::Failed, data.len());
                }
                let first_chunk = (expected as usize).min(data.len());
                self.state = BotState::ParamOut {
                    expected,
                    received: 0,
                    tag: cbw.tag,
                    lun,
                    cdb: {
                        let mut cdb_buf = [0u8; 16];
                        let cdb_len = cdb.len().min(16);
                        cdb_buf[..cdb_len].copy_from_slice(&cdb[..cdb_len]);
                        cdb_buf
                    },
                    cdb_len: cdb.len().min(16),
                    chunk: first_chunk,
                };
                SessionStep::NeedOut {
                    len: first_chunk,
                    probe: false,
                }
            }
        }
    }

    /// Enter a Data-In phase for a response already synthesized into
    /// `data[0..available]` (REPORT LUNS, core-injected sense).
    fn synthesize_data_in<'a>(
        &'a mut self,
        cbw: &Cbw,
        data: &'a mut [u8],
        available: u64,
    ) -> SessionStep<'a> {
        let declared = u64::from(cbw.data_len);
        if declared == 0 && available > 0 {
            // BOT §6.7.1 Case (2) Hn<Di (synthesized REPORT LUNS/sense).
            return self.finish_cmd(cbw, 0, CswStatus::PhaseError, data.len());
        }
        let actual = available.min(declared);
        if actual == 0 {
            return self.finish_cmd(cbw, 0, CswStatus::Passed, data.len());
        }
        let mut chunk = (actual as usize).min(data.len());
        if chunk as u64 == actual {
            chunk += self.merge_pad_boundary(data, chunk, declared, actual);
        }
        self.state = BotState::DataIn {
            expected: declared,
            transfer_len: actual,
            sent: chunk as u64,
            tag: cbw.tag,
            lun: usize::from(cbw.lun),
            chunk,
        };
        SessionStep::NeedIn(&data[..chunk])
    }

    /// Write the CSW for `(tag, residue, status)` into the internal buffer.
    /// Does not change the state. Residue is clamped to `u32` (BOT §5.2).
    fn store_csw(&mut self, tag: u32, residue: u64, status: CswStatus) {
        // BOT §5.2: dCSWDataResidue is 32-bit; CBW dCBWDataTransferLength is 32-bit,
        // so residue <= declared <= u32::MAX in practice. Clamp with warn if larger.
        let residue_u32 = u32::try_from(residue).unwrap_or_else(|_| {
            crate::warn!("bot: residue {} truncated to u32::MAX", residue);
            u32::MAX
        });
        let csw = Csw {
            tag,
            residue: residue_u32,
            status,
        };
        csw.write(&mut self.csw);
    }

    /// Assemble the CSW into the internal buffer and move to the CSW state.
    fn finish_csw_bot<'a>(
        &'a mut self,
        tag: u32,
        residue: u64,
        status: CswStatus,
    ) -> SessionStep<'a> {
        self.store_csw(tag, residue, status);
        self.state = BotState::Csw;
        SessionStep::NeedIn(&self.csw[..])
    }

    /// Plain shortfall ending: the short packet is already on the wire; report
    /// the shortfall via `dCSWDataResidue` and send the CSW (with a ZLP first
    /// when the produced length is an MPS multiple, so a full-MPS last packet
    /// is terminated). No padding, no STALL.
    fn finish_short_fall<'a>(
        &'a mut self,
        tag: u32,
        declared: u64,
        actual: u64,
        status: CswStatus,
    ) -> SessionStep<'a> {
        crate::debug!(
            "bot csw tag={} residue={} status={:?}",
            tag,
            declared - actual,
            status
        );
        self.store_csw(tag, declared - actual, status);
        if actual < declared && actual.is_multiple_of(self.bulk_mps) {
            self.state = BotState::CswZlp {
                tag,
                declared,
                actual,
                status,
            };
            SessionStep::NeedIn(&[])
        } else {
            self.state = BotState::Csw;
            SessionStep::NeedIn(&self.csw[..])
        }
    }

    /// `ShortfallPolicy::Short` ending: the short packet is on the wire; when it
    /// was a full-MPS last packet, terminate it with a ZLP first. Then the phase
    /// STALLs Bulk-In (`DataInStall`); the driver sets the halt and calls
    /// [`BotSession::stall_applied`], which releases the withheld CSW.
    fn finish_short_stall<'a>(
        &'a mut self,
        tag: u32,
        declared: u64,
        actual: u64,
        status: CswStatus,
    ) -> SessionStep<'a> {
        crate::debug!(
            "bot csw (stall) tag={} residue={} status={:?}",
            tag,
            declared - actual,
            status
        );
        self.store_csw(tag, declared - actual, status);
        if actual.is_multiple_of(self.bulk_mps) {
            self.state = BotState::CswZlp {
                tag,
                declared,
                actual,
                status,
            };
            SessionStep::NeedIn(&[])
        } else {
            self.state = BotState::DataInStall {
                tag,
                declared,
                actual,
                status,
            };
            SessionStep::NeedStall
        }
    }

    /// Zero-extend the final relevant Data-In chunk in `data` to the next
    /// bulk-MPS boundary under `ShortfallPolicy::Pad`, so the host never sees a
    /// premature short packet before the fill. Bounded by the fill budget
    /// (`declared − produced`, capped at [`MAX_PAD`]) and the remaining buffer;
    /// returns the number of fill bytes merged. A no-op for other policies or
    /// when there is no shortfall. Requires an MPS-aligned work buffer for the
    /// boundary to fit; callers degrade gracefully otherwise (see
    /// [`end_shortfall_data_in`]).
    fn merge_pad_boundary(
        &self,
        data: &mut [u8],
        chunk: usize,
        declared: u64,
        produced: u64,
    ) -> usize {
        if self.shortfall != ShortfallPolicy::Pad || produced >= declared {
            return 0;
        }
        let budget = (declared - produced).min(MAX_PAD);
        let mps = self.bulk_mps.max(1);
        let rem = chunk as u64 % mps;
        let boundary = if rem == 0 { 0 } else { mps - rem };
        let room = data.len().saturating_sub(chunk) as u64;
        let merge = boundary.min(budget).min(room) as usize;
        if merge > 0 {
            data[chunk..chunk + merge].fill(0);
        }
        merge
    }

    /// Pad a Data-In shortfall to `declared` (capped at [`MAX_PAD`]) or, once
    /// the cap/alignment forbids it, end `ShortNoStall`-style. `produced` is
    /// the relevant data sent; `wire` is the total already on the wire
    /// (relevant + any boundary-merged fill). Residue is `declared − produced`
    /// (the fill is *not* relevant data).
    fn end_shortfall_data_in<'a>(
        &'a mut self,
        tag: u32,
        declared: u64,
        produced: u64,
        wire: u64,
        status: CswStatus,
    ) -> SessionStep<'a> {
        let mps = self.bulk_mps.max(1);
        // A non-MPS-multiple wire length below `declared` means a short packet
        // already terminated the host's bulk-IN (e.g. a non-MPS-aligned work
        // buffer blocked the boundary merge); appending fill now would corrupt
        // the CSW. End ShortNoStall-style.
        if wire < declared && !wire.is_multiple_of(mps) {
            return self.finish_short_fall(tag, declared, produced, status);
        }
        let target = declared.min(produced + MAX_PAD);
        if wire >= target {
            return self.write_pad_csw(tag, declared, produced, wire, status);
        }
        let chunk = ((target - wire) as usize).min(ZERO_CHUNK.len());
        self.state = BotState::DataInPad {
            tag,
            declared,
            produced,
            wire,
            status,
            chunk,
        };
        SessionStep::NeedIn(&ZERO_CHUNK[..chunk])
    }

    /// Send the CSW after a completed `Pad` fill. A fully-filled phase
    /// (`wire == declared`) sends the CSW directly; a cap-exhausted phase
    /// (`wire < declared`) ends like `ShortNoStall` — with a ZLP first when the
    /// wire length is an MPS multiple, no STALL.
    fn write_pad_csw<'a>(
        &'a mut self,
        tag: u32,
        declared: u64,
        produced: u64,
        wire: u64,
        status: CswStatus,
    ) -> SessionStep<'a> {
        crate::debug!(
            "bot csw (pad) tag={} residue={} wire={} status={:?}",
            tag,
            declared - produced,
            wire,
            status
        );
        self.store_csw(tag, declared - produced, status);
        if wire < declared && wire.is_multiple_of(self.bulk_mps) {
            self.state = BotState::CswZlp {
                tag,
                declared,
                actual: produced,
                status,
            };
            SessionStep::NeedIn(&[])
        } else {
            self.state = BotState::Csw;
            SessionStep::NeedIn(&self.csw[..])
        }
    }

    /// End a Data-In (or no-data) phase with the CSW.
    ///
    /// If fewer than `declared` bytes were produced, the shortfall is resolved
    /// per the session's [`ShortfallPolicy`]: `Pad` fills to `declared` (capped
    /// at [`MAX_PAD`]), `Short` ENDs the phase with a short packet then STALLs
    /// Bulk-In, and `ShortNoStall` (the default) reports the shortfall via
    /// `dCSWDataResidue` and sends a short packet. A produced length that is a
    /// multiple of the bulk MPS is terminated with a ZLP first. Residue is
    /// 32-bit (BOT §5.2); truncation is guarded (declared is 32-bit).
    fn finish_data_in<'a>(
        &'a mut self,
        tag: u32,
        declared: u64,
        actual: u64,
        status: CswStatus,
    ) -> SessionStep<'a> {
        let actual = actual.min(declared);
        if actual < declared {
            return match self.shortfall {
                ShortfallPolicy::Pad => {
                    self.end_shortfall_data_in(tag, declared, actual, actual, status)
                }
                ShortfallPolicy::Short => self.finish_short_stall(tag, declared, actual, status),
                ShortfallPolicy::ShortNoStall => {
                    self.finish_short_fall(tag, declared, actual, status)
                }
            };
        }
        self.finish_short_fall(tag, declared, actual, status)
    }

    /// End a transaction, first resolving the data phase the CBW declared
    /// (§6.7). `actual` is the number of Data-In bytes produced. A declared
    /// Data-Out phase is drained instead of left in the bulk-OUT fifo (the
    /// host will send `declared` bytes regardless of the outcome).
    fn finish_cmd<'a>(
        &'a mut self,
        cbw: &Cbw,
        actual: u64,
        status: CswStatus,
        data_len: usize,
    ) -> SessionStep<'a> {
        let declared = u64::from(cbw.data_len);
        if declared > 0 && cbw.dir == BotDir::DataOut {
            return self.start_data_out_drain(cbw, status, data_len);
        }
        self.finish_data_in(cbw.tag, declared, actual, status)
    }

    /// Enter a Data-Out phase that writes nothing: receive and discard the
    /// host's `declared` bytes so the next CBW is not corrupted (§3.8),
    /// then send the CSW with `status`.
    fn start_data_out_drain<'a>(
        &'a mut self,
        cbw: &Cbw,
        status: CswStatus,
        data_len: usize,
    ) -> SessionStep<'a> {
        let declared = u64::from(cbw.data_len);
        let chunk = (declared as usize).min(data_len);
        self.state = BotState::DataOut {
            declared,
            to_write: 0,
            received: 0,
            written: 0,
            tag: cbw.tag,
            lun: cbw.lun as usize,
            status,
            chunk,
        };
        SessionStep::NeedOut {
            len: chunk,
            probe: false,
        }
    }

    // ── Data-In phase ───────────────────────────────────────────────

    fn poll_data_in<'a, 'e, D: ScsiDevice>(
        &'a mut self,
        ev: SessionEvent<'e>,
        data: &'a mut [u8],
        devs: &mut [D],
    ) -> SessionStep<'a> {
        let st = self.state;
        let BotState::DataIn {
            expected,
            transfer_len,
            sent,
            tag,
            lun,
            chunk,
        } = st
        else {
            return SessionStep::Done(BotStepResult::Error(BotTargetError::Internal));
        };
        match ev {
            SessionEvent::InSent => {
                if sent >= transfer_len {
                    // Relevant data complete. `sent` may exceed `transfer_len`
                    // when `Pad` boundary-merged fill zeros into the final chunk.
                    if transfer_len < expected && self.shortfall == ShortfallPolicy::Pad {
                        return self.end_shortfall_data_in(
                            tag,
                            expected,
                            transfer_len,
                            sent,
                            CswStatus::Passed,
                        );
                    }
                    return self.finish_data_in(tag, expected, transfer_len, CswStatus::Passed);
                }
                let remaining = transfer_len - sent;
                let mut next = (remaining as usize).min(data.len());
                let produced = match devs[lun].xfer_out(sent, &mut data[..next]) {
                    Xfer::Inline { len } => len,
                    Xfer::Store(_) => {
                        return SessionStep::Done(BotStepResult::Error(BotTargetError::Internal));
                    }
                };
                if produced != next {
                    // Transfer failed midway.
                    if sent < expected && self.shortfall == ShortfallPolicy::Pad {
                        return self.end_shortfall_data_in(
                            tag,
                            expected,
                            sent,
                            sent,
                            CswStatus::Failed,
                        );
                    }
                    return self.finish_data_in(tag, expected, sent, CswStatus::Failed);
                }
                if next as u64 == remaining {
                    // Final relevant chunk: boundary-merge Pad fill in-buffer so
                    // the host never sees a premature short packet.
                    next += self.merge_pad_boundary(data, next, expected, transfer_len);
                }
                self.state = BotState::DataIn {
                    expected,
                    transfer_len,
                    sent: sent + next as u64,
                    tag,
                    lun,
                    chunk: next,
                };
                SessionStep::NeedIn(&data[..next])
            }
            SessionEvent::OutRecv { .. } | SessionEvent::OutIdle => {
                // No-op: still need to send the pending chunk.
                SessionStep::NeedIn(&data[..chunk])
            }
        }
    }

    // ── Data-In pad (ShortfallPolicy::Pad) ──────────────────────────

    fn poll_data_in_pad<'a>(&'a mut self, ev: SessionEvent<'_>) -> SessionStep<'a> {
        let st = self.state;
        let BotState::DataInPad {
            tag,
            declared,
            produced,
            wire,
            status,
            chunk,
        } = st
        else {
            return SessionStep::Done(BotStepResult::Error(BotTargetError::Internal));
        };
        match ev {
            SessionEvent::InSent => {
                let wire = wire + chunk as u64;
                let target = declared.min(produced + MAX_PAD);
                if wire >= target {
                    return self.write_pad_csw(tag, declared, produced, wire, status);
                }
                let next = ((target - wire) as usize).min(ZERO_CHUNK.len());
                self.state = BotState::DataInPad {
                    tag,
                    declared,
                    produced,
                    wire,
                    status,
                    chunk: next,
                };
                SessionStep::NeedIn(&ZERO_CHUNK[..next])
            }
            SessionEvent::OutRecv { .. } | SessionEvent::OutIdle => {
                // No-op: still need to send the pending fill chunk.
                SessionStep::NeedIn(&ZERO_CHUNK[..chunk])
            }
        }
    }

    // ── Data-In stall (ShortfallPolicy::Short) ──────────────────────

    /// Transient stall state: the shortfall's short packet (and any ZLP) is on
    /// the wire and the driver is about to STALL Bulk-In. Bulk events are
    /// ignored (the endpoint is halted, so none should arrive); `need()` keeps
    /// asking for the STALL until the driver calls
    /// [`BotSession::stall_applied`], which releases the CSW. A driver whose
    /// `BotIo::stall_in` fails calls [`BotSession::reset`].
    fn poll_data_in_stall<'a>(&'a mut self, _ev: SessionEvent<'_>) -> SessionStep<'a> {
        SessionStep::NeedStall
    }

    // ── Data-Out phase ──────────────────────────────────────────────

    fn poll_data_out<'a, 'e, D: ScsiDevice>(
        &'a mut self,
        ev: SessionEvent<'e>,
        data: &'a mut [u8],
        devs: &mut [D],
    ) -> SessionStep<'a> {
        let st = self.state;
        let BotState::DataOut {
            declared,
            to_write,
            received,
            written,
            tag,
            lun,
            status,
            chunk,
        } = st
        else {
            return SessionStep::Done(BotStepResult::Error(BotTargetError::Internal));
        };
        match ev {
            SessionEvent::OutRecv { data: recv } => {
                let mut written = written;
                let mut status = status;
                if status == CswStatus::Passed && written < to_write {
                    let w = (recv.len() as u64).min(to_write - written) as usize;
                    if w > 0 {
                        let produced = match devs[lun].xfer_in(written, &recv[..w]) {
                            Xfer::Inline { len } => len,
                            Xfer::Store(_) => {
                                return SessionStep::Done(BotStepResult::Error(
                                    BotTargetError::Internal,
                                ));
                            }
                        };
                        if produced == w {
                            written += produced as u64;
                        } else {
                            status = CswStatus::Failed;
                        }
                    }
                }
                let received = received + recv.len() as u64;
                if received >= declared {
                    let residue = declared - written;
                    if received > declared {
                        // Overshoot already consumed the excess: straight to CSW.
                        return self.finish_csw_bot(tag, residue, status);
                    }
                    // Exact end of the declared phase: probe for a host
                    // overrun (leftover bytes would corrupt the next CBW).
                    self.state = BotState::DataOutOverrun {
                        tag,
                        residue,
                        status,
                        chunk: data.len(),
                    };
                    return SessionStep::NeedOut {
                        len: data.len(),
                        probe: true,
                    };
                }
                let next = ((declared - received) as usize).min(data.len());
                self.state = BotState::DataOut {
                    declared,
                    to_write,
                    received,
                    written,
                    tag,
                    lun,
                    status,
                    chunk: next,
                };
                SessionStep::NeedOut {
                    len: next,
                    probe: false,
                }
            }
            SessionEvent::OutIdle => {
                // Host paused mid phase: keep waiting for the chunk.
                SessionStep::NeedOut {
                    len: chunk,
                    probe: false,
                }
            }
            SessionEvent::InSent => {
                SessionStep::Done(BotStepResult::Error(BotTargetError::Internal))
            }
        }
    }

    // ── Parameter-list Data-Out ─────────────────────────────────────

    fn poll_param_out<'a, 'e, D: ScsiDevice>(
        &'a mut self,
        ev: SessionEvent<'e>,
        data: &'a mut [u8],
        devs: &mut [D],
    ) -> SessionStep<'a> {
        let st = self.state;
        let BotState::ParamOut {
            expected,
            received,
            tag,
            lun,
            cdb,
            cdb_len,
            chunk,
        } = st
        else {
            return SessionStep::Done(BotStepResult::Error(BotTargetError::Internal));
        };
        match ev {
            SessionEvent::OutRecv { data: recv } => {
                let remaining = expected - received;
                if recv.len() as u64 > remaining {
                    // Host overran declared length: copy what fits, drain rest.
                    let fit = remaining as usize;
                    if fit > 0 {
                        data[received as usize..received as usize + fit]
                            .copy_from_slice(&recv[..fit]);
                    }
                    let status = match devs[lun]
                        .complete_param(&cdb[..cdb_len], &data[..expected as usize])
                    {
                        CommandOutcome::Status => CswStatus::Passed,
                        CommandOutcome::StatusWithSense => CswStatus::Passed,
                        CommandOutcome::CheckCondition => CswStatus::Failed,
                        _ => CswStatus::Failed,
                    };
                    // Extra bytes beyond declared are already in recv[fit..]; treat as overrun.
                    // If extra exactly fills a packet, we still need to probe.
                    self.state = BotState::DataOutOverrun {
                        tag,
                        residue: 0,
                        status,
                        chunk: data.len(),
                    };
                    // If recv had extra and was short packet (< chunk), we can go straight to CSW.
                    // For now, enter overrun probe to drain any further excess.
                    return SessionStep::NeedOut {
                        len: data.len(),
                        probe: true,
                    };
                }
                // Normal case: copy recv into param buffer.
                data[received as usize..received as usize + recv.len()].copy_from_slice(recv);
                let received = received + recv.len() as u64;
                if received >= expected {
                    let cdb_slice = &cdb[..cdb_len];
                    let outcome = devs[lun].complete_param(cdb_slice, &data[..expected as usize]);
                    let status = match outcome {
                        CommandOutcome::Status => CswStatus::Passed,
                        CommandOutcome::StatusWithSense => CswStatus::Passed,
                        CommandOutcome::CheckCondition => CswStatus::Failed,
                        _ => CswStatus::Failed,
                    };
                    if received > expected {
                        return self.finish_csw_bot(tag, 0, status);
                    }
                    // Exact: probe for host overrun before CSW (like DataOut).
                    self.state = BotState::DataOutOverrun {
                        tag,
                        residue: 0,
                        status,
                        chunk: data.len(),
                    };
                    return SessionStep::NeedOut {
                        len: data.len(),
                        probe: true,
                    };
                }
                let next = ((expected - received) as usize).min(data.len() - received as usize);
                self.state = BotState::ParamOut {
                    expected,
                    received,
                    tag,
                    lun,
                    cdb,
                    cdb_len,
                    chunk: next,
                };
                SessionStep::NeedOut {
                    len: next,
                    probe: false,
                }
            }
            SessionEvent::OutIdle => SessionStep::NeedOut {
                len: chunk,
                probe: false,
            },
            SessionEvent::InSent => {
                SessionStep::Done(BotStepResult::Error(BotTargetError::Internal))
            }
        }
    }

    // ── Data-Out overrun drain ──────────────────────────────────────

    fn poll_overrun<'a>(&'a mut self, ev: SessionEvent<'_>) -> SessionStep<'a> {
        let st = self.state;
        let BotState::DataOutOverrun {
            tag,
            residue,
            status,
            chunk,
        } = st
        else {
            return SessionStep::Done(BotStepResult::Error(BotTargetError::Internal));
        };
        match ev {
            SessionEvent::OutRecv { data } => {
                if data.len() < chunk {
                    // Short packet: leftover drained → CSW.
                    return self.finish_csw_bot(tag, residue, status);
                }
                // Full chunk: more leftover pending.
                self.state = BotState::DataOutOverrun {
                    tag,
                    residue,
                    status,
                    chunk,
                };
                SessionStep::NeedOut {
                    len: chunk,
                    probe: true,
                }
            }
            SessionEvent::OutIdle => self.finish_csw_bot(tag, residue, status),
            SessionEvent::InSent => {
                SessionStep::Done(BotStepResult::Error(BotTargetError::Internal))
            }
        }
    }

    // ── CSW phase ───────────────────────────────────────────────────

    fn poll_csw<'a>(&'a mut self, ev: SessionEvent<'_>) -> SessionStep<'a> {
        match ev {
            SessionEvent::InSent => {
                self.state = BotState::Command { got: 0 };
                SessionStep::Done(BotStepResult::Processed)
            }
            SessionEvent::OutRecv { .. } | SessionEvent::OutIdle => {
                SessionStep::NeedIn(&self.csw[..])
            }
        }
    }

    /// The zero-length packet that terminates a short Data-In phase has been
    /// sent; under `ShortfallPolicy::Short` the phase then STALLs (`DataInStall`)
    /// instead of sending the CSW immediately.
    fn poll_csw_zlp<'a>(&'a mut self, ev: SessionEvent<'_>) -> SessionStep<'a> {
        let st = self.state;
        let BotState::CswZlp {
            tag,
            declared,
            actual,
            status,
        } = st
        else {
            return SessionStep::Done(BotStepResult::Error(BotTargetError::Internal));
        };
        match ev {
            SessionEvent::InSent => {
                if self.shortfall == ShortfallPolicy::Short && actual < declared {
                    self.state = BotState::DataInStall {
                        tag,
                        declared,
                        actual,
                        status,
                    };
                    SessionStep::NeedStall
                } else {
                    self.state = BotState::Csw;
                    SessionStep::NeedIn(&self.csw[..])
                }
            }
            SessionEvent::OutRecv { .. } | SessionEvent::OutIdle => SessionStep::NeedIn(&[]),
        }
    }
}

/// Build the REPORT LUNS response (SPC-4 §6.21) into `data`: 4-byte BE LUN
/// list length + 4 reserved bytes + 8-byte single-level LUN entries. Returns
/// the number of bytes written (clamped to `data.len()`).
///
/// The 4 reserved bytes keep the 8-byte entries 8-aligned, as required by
/// Linux's `scsi_report_lun_scan` (see the iSCSI target's comment).
fn write_report_luns(data: &mut [u8], num_luns: usize) -> usize {
    let list_len = u32::try_from(num_luns)
        .ok()
        .and_then(|n| n.checked_mul(8))
        .unwrap_or(u32::MAX);
    let total = 8usize + (list_len as usize);
    let n = total.min(data.len());
    let entries = num_luns.min(n.saturating_sub(8) / 8);
    data[0..4].copy_from_slice(&list_len.to_be_bytes());
    data[4..n.min(8)].fill(0);
    for i in 0..entries {
        let off = 8 + i * 8;
        data[off] = 0x00; // address method 00b, bus id 0
        data[off + 1] = i as u8; // single-level LUN id
        data[off + 2..off + 8].fill(0);
    }
    n
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::scsi::backend::{BlockBackend, RamBackend};
    use crate::scsi::block::BlockDevice;
    use crate::usb::{BotIoErr, CBW_SIGNATURE};
    use core::cell::RefCell;
    use std::collections::VecDeque;

    /// A 64 KiB block device over stack-owned RAM.
    fn test_dev(ram: &mut [u8]) -> BlockDevice<BlockBackend<'_>> {
        BlockDevice::disk(BlockBackend::Ram(RamBackend::new(ram)), 512).unwrap()
    }

    fn work() -> [u8; crate::MIN_DATA_LEN] {
        [0u8; crate::MIN_DATA_LEN]
    }

    /// Build a raw 31-byte CBW from its logical fields (little endian).
    fn raw_cbw(tag: u32, data_len: u32, flags: u8, lun: u8, cdb: &[u8]) -> [u8; CBW_LEN] {
        let mut raw = [0u8; CBW_LEN];
        raw[0..4].copy_from_slice(&CBW_SIGNATURE.to_le_bytes());
        raw[4..8].copy_from_slice(&tag.to_le_bytes());
        raw[8..12].copy_from_slice(&data_len.to_le_bytes());
        raw[12] = flags;
        raw[13] = lun;
        raw[14] = cdb.len() as u8;
        raw[15..15 + cdb.len().min(16)].copy_from_slice(&cdb[..cdb.len().min(16)]);
        raw
    }

    /// Read the pending CSW from the session's internal buffer.
    fn read_csw(s: &mut BotSession, data: &mut [u8]) -> (u32, u32, u8) {
        let csw = s.out_slice(&data[..]);
        assert_eq!(csw.len(), CSW_LEN);
        assert_eq!(&csw[0..4], b"USBS");
        (
            u32::from_le_bytes([csw[4], csw[5], csw[6], csw[7]]),
            u32::from_le_bytes([csw[8], csw[9], csw[10], csw[11]]),
            csw[12],
        )
    }

    fn inquiry_cdb(alloc: u8) -> [u8; 6] {
        let mut cdb = [0u8; 6];
        cdb[0] = scsi_op::INQUIRY;
        cdb[4] = alloc;
        cdb
    }

    fn read_via_xfer(dev: &mut BlockDevice<BlockBackend<'_>>, lba: u64, buf: &mut [u8]) {
        let mut work = [0u8; crate::MIN_DATA_LEN];
        let blocks = (buf.len() as u64).div_ceil(512) as u32;
        let nblocks = blocks.max(1) as u16; // at least 1 for small reads like 64B tail
        let mut cdb = [0u8; 10];
        cdb[0] = scsi_op::READ_10;
        cdb[2] = ((lba >> 24) & 0xFF) as u8;
        cdb[3] = ((lba >> 16) & 0xFF) as u8;
        cdb[4] = ((lba >> 8) & 0xFF) as u8;
        cdb[5] = (lba & 0xFF) as u8;
        cdb[7] = ((nblocks >> 8) & 0xFF) as u8;
        cdb[8] = (nblocks & 0xFF) as u8;
        let outcome = dev.do_cmd(&cdb, &mut work).expect("READ setup");
        match outcome {
            CommandOutcome::OutXfer { len } => {
                assert!(len >= buf.len() as u64);
                let n = buf.len();
                assert!(matches!(dev.xfer_out(0, buf), Xfer::Inline { len } if len == n));
            }
            other => panic!("expected OutXfer, got {other:?}"),
        }
    }

    #[test]
    fn need_starts_in_command_phase() {
        let s = BotSession::new();
        assert_eq!(
            s.need(),
            SessionNeed::NeedOut {
                len: 31,
                probe: false
            }
        );
        assert_eq!(s.max_lun(), 0);
    }

    #[test]
    fn with_luns_sets_max_lun() {
        assert_eq!(BotSession::with_luns(1).max_lun(), 0);
        assert_eq!(BotSession::with_luns(3).max_lun(), 2);
        assert_eq!(BotSession::with_luns(17).max_lun(), 15);
    }

    #[test]
    fn bulk_mps_default_and_override() {
        // Default is the documented high-speed 512.
        assert_eq!(BotSession::new().bulk_mps(), 512);
        assert_eq!(BotSession::with_luns(2).bulk_mps(), 512);

        // Builder override (Full-Speed 64).
        assert_eq!(BotSession::new().with_bulk_mps(64).bulk_mps(), 64);

        // Mutating setter.
        let mut s = BotSession::new();
        s.set_bulk_mps(64);
        assert_eq!(s.bulk_mps(), 64);
        s.set_bulk_mps(512);
        assert_eq!(s.bulk_mps(), 512);

        // 0 is rejected and falls back to the default.
        assert_eq!(BotSession::new().with_bulk_mps(0).bulk_mps(), 512);
        s.set_bulk_mps(0);
        assert_eq!(s.bulk_mps(), 512);
    }

    #[test]
    fn cbw_accumulates_across_partial_receives() {
        let mut ram = vec![0u8; 64 * 1024];
        let mut devs = [test_dev(&mut ram)];
        let mut s = BotSession::new();
        let mut data = work();

        let raw = raw_cbw(1, 96, 0x80, 0, &inquiry_cdb(96));
        let step = s.poll(
            SessionEvent::OutRecv { data: &raw[..20] },
            &mut data,
            &mut devs,
        );
        assert_eq!(
            step,
            SessionStep::NeedOut {
                len: 11,
                probe: false
            }
        );
        assert_eq!(
            s.need(),
            SessionNeed::NeedOut {
                len: 11,
                probe: false
            }
        );

        let step = s.poll(
            SessionEvent::OutRecv { data: &raw[20..] },
            &mut data,
            &mut devs,
        );
        match step {
            SessionStep::NeedIn(_) => {}
            other => panic!("expected NeedIn, got {other:?}"),
        }
    }

    #[test]
    fn inquiry_roundtrip_with_csw() {
        let mut ram = vec![0u8; 64 * 1024];
        let mut devs = [test_dev(&mut ram)];
        let mut s = BotSession::new();
        let mut data = work();

        let raw = raw_cbw(0xAAAA_AAAA, 96, 0x80, 0, &inquiry_cdb(96));
        let step = s.poll(SessionEvent::OutRecv { data: &raw }, &mut data, &mut devs);
        match step {
            SessionStep::NeedIn(bytes) => {
                assert_eq!(bytes.len(), 96);
                assert_eq!(bytes[0] & 0x1F, 0x00); // PDT = direct-access block
            }
            other => panic!("expected NeedIn with INQUIRY data, got {other:?}"),
        }
        assert_eq!(s.need(), SessionNeed::NeedIn { len: 96 });

        // Data sent → CSW pending (tag echo, Passed; residue 0: host
        // declared 96 and the INQUIRY response is 96 bytes).
        let step = s.poll(SessionEvent::InSent, &mut data, &mut devs);
        match step {
            SessionStep::NeedIn(_) => {}
            other => panic!("expected CSW, got {other:?}"),
        }
        let (tag, residue, status) = read_csw(&mut s, &mut data);
        assert_eq!(tag, 0xAAAA_AAAA);
        assert_eq!(residue, 0);
        assert_eq!(status, 0x00);

        // CSW sent → back to Command.
        let step = s.poll(SessionEvent::InSent, &mut data, &mut devs);
        assert_eq!(step, SessionStep::Done(BotStepResult::Processed));
        assert_eq!(
            s.need(),
            SessionNeed::NeedOut {
                len: 31,
                probe: false
            }
        );
    }

    #[test]
    fn read_10_chunks_across_work_buffer() {
        let mut ram = vec![0u8; 64 * 1024];
        for (i, b) in ram.iter_mut().enumerate() {
            *b = (i % 251) as u8;
        }
        let mut devs = [test_dev(&mut ram)];
        let mut s = BotSession::new();
        let mut data = work();

        // READ(10) LBA 0, 20 blocks → 10240 bytes (> one 8K chunk).
        let cdb = [0x28, 0, 0, 0, 0, 0, 0, 0, 20, 0];
        let raw = raw_cbw(0x1111, 10240, 0x80, 0, &cdb);
        let step = s.poll(SessionEvent::OutRecv { data: &raw }, &mut data, &mut devs);
        match step {
            SessionStep::NeedIn(bytes) => {
                assert_eq!(bytes.len(), 8192);
                assert_eq!(bytes[0], 0);
                assert_eq!(bytes[8191], (8191 % 251) as u8);
            }
            other => panic!("expected first chunk, got {other:?}"),
        }

        let step = s.poll(SessionEvent::InSent, &mut data, &mut devs);
        match step {
            SessionStep::NeedIn(bytes) => {
                assert_eq!(bytes.len(), 2048);
                assert_eq!(bytes[0], (8192 % 251) as u8);
            }
            other => panic!("expected second chunk, got {other:?}"),
        }

        let step = s.poll(SessionEvent::InSent, &mut data, &mut devs);
        match step {
            SessionStep::NeedIn(_) => {}
            other => panic!("expected CSW, got {other:?}"),
        }
        let (_, residue, status) = read_csw(&mut s, &mut data);
        assert_eq!(residue, 0);
        assert_eq!(status, 0x00);
        assert_eq!(
            s.poll(SessionEvent::InSent, &mut data, &mut devs),
            SessionStep::Done(BotStepResult::Processed)
        );
    }

    #[test]
    fn write_10_writes_received_data_and_probes_overrun() {
        let mut ram = vec![0u8; 64 * 1024];
        let mut devs = [test_dev(&mut ram)];
        let mut s = BotSession::new();
        let mut data = work();

        // WRITE(10) LBA 0, 1 block → 512 bytes.
        let cdb = [0x2A, 0, 0, 0, 0, 0, 0, 0, 1, 0];
        let raw = raw_cbw(0x2222, 512, 0x00, 0, &cdb);
        let step = s.poll(SessionEvent::OutRecv { data: &raw }, &mut data, &mut devs);
        assert_eq!(
            step,
            SessionStep::NeedOut {
                len: 512,
                probe: false
            }
        );
        assert_eq!(
            s.need(),
            SessionNeed::NeedOut {
                len: 512,
                probe: false
            }
        );

        // Feed the data chunk → declared phase complete → overrun probe.
        let payload: Vec<u8> = (0..512u16).map(|i| (i % 7) as u8).collect();
        let wlen = data.len();
        let step = s.poll(
            SessionEvent::OutRecv { data: &payload },
            &mut data,
            &mut devs,
        );
        assert_eq!(
            step,
            SessionStep::NeedOut {
                len: wlen,
                probe: true
            }
        );
        let mut check = [0u8; 512];
        read_via_xfer(&mut devs[0], 0, &mut check);
        assert_eq!(&check[..], payload.as_slice());

        // No more data → OutIdle ends the drain → CSW.
        let step = s.poll(SessionEvent::OutIdle, &mut data, &mut devs);
        match step {
            SessionStep::NeedIn(_) => {}
            other => panic!("expected CSW, got {other:?}"),
        }
        let (tag, residue, status) = read_csw(&mut s, &mut data);
        assert_eq!(tag, 0x2222);
        assert_eq!(residue, 0);
        assert_eq!(status, 0x00);
        assert_eq!(
            s.poll(SessionEvent::InSent, &mut data, &mut devs),
            SessionStep::Done(BotStepResult::Processed)
        );
    }

    #[test]
    fn data_out_overrun_is_drained_to_short_packet() {
        let mut ram = vec![0u8; 64 * 1024];
        let mut devs = [test_dev(&mut ram)];
        let mut s = BotSession::new();
        let mut data = work();

        let cdb = [0x2A, 0, 0, 0, 0, 0, 0, 0, 1, 0];
        let raw = raw_cbw(0x3333, 512, 0x00, 0, &cdb);
        let step = s.poll(SessionEvent::OutRecv { data: &raw }, &mut data, &mut devs);
        assert_eq!(
            step,
            SessionStep::NeedOut {
                len: 512,
                probe: false
            }
        );

        let payload: Vec<u8> = vec![0x5A; 512];
        let wlen = data.len();
        let step = s.poll(
            SessionEvent::OutRecv { data: &payload },
            &mut data,
            &mut devs,
        );
        assert_eq!(
            step,
            SessionStep::NeedOut {
                len: wlen,
                probe: true
            }
        );

        // Host over-sent 100 extra bytes: drain (short packet) → CSW.
        let extra = vec![0x6B; 100];
        let step = s.poll(SessionEvent::OutRecv { data: &extra }, &mut data, &mut devs);
        match step {
            SessionStep::NeedIn(_) => {}
            other => panic!("expected CSW after drain, got {other:?}"),
        }
        // The excess was discarded, not written to the backend.
        let mut check = [0u8; 512];
        read_via_xfer(&mut devs[0], 0, &mut check);
        assert_eq!(&check[..], payload.as_slice());
        let mut tail = [0u8; 64];
        read_via_xfer(&mut devs[0], 1, &mut tail);
        assert!(tail.iter().all(|&b| b == 0));

        let (_, residue, status) = read_csw(&mut s, &mut data);
        assert_eq!(residue, 0);
        assert_eq!(status, 0x00);
    }

    #[test]
    fn phase_error_on_direction_mismatch() {
        let mut ram = vec![0u8; 64 * 1024];
        let mut devs = [test_dev(&mut ram)];
        let mut s = BotSession::new();
        let mut data = work();

        // READ(10) declared with Data-Out direction → the host will send
        // the declared bytes, so they are drained, then a Phase Error CSW.
        let cdb = [0x28, 0, 0, 0, 0, 0, 0, 0, 1, 0];
        let raw = raw_cbw(0x4444, 512, 0x00, 0, &cdb);
        let step = s.poll(SessionEvent::OutRecv { data: &raw }, &mut data, &mut devs);
        assert_eq!(
            step,
            SessionStep::NeedOut {
                len: 512,
                probe: false
            }
        );
        let payload = vec![0u8; 512];
        let step = s.poll(
            SessionEvent::OutRecv { data: &payload },
            &mut data,
            &mut devs,
        );
        match step {
            SessionStep::NeedOut { probe: true, .. } => {}
            other => panic!("expected overrun probe, got {other:?}"),
        }
        let step = s.poll(SessionEvent::OutIdle, &mut data, &mut devs);
        match step {
            SessionStep::NeedIn(_) => {}
            other => panic!("expected CSW, got {other:?}"),
        }
        let (_, residue, status) = read_csw(&mut s, &mut data);
        assert_eq!(residue, 512);
        assert_eq!(status, 0x02); // Phase Error
    }

    #[test]
    fn zero_data_data_in_sends_zlp_then_csw() {
        let mut ram = vec![0u8; 64 * 1024];
        let mut devs = [test_dev(&mut ram)];
        let mut s = BotSession::new().with_shortfall(ShortfallPolicy::ShortNoStall);
        let mut data = work();

        // READ(10) at an out-of-range LBA → CHECK CONDITION, but the CBW
        // declared a 512-byte Data-In phase. The zero-byte phase must be
        // closed with a ZLP before the CSW (BOT §6.7 Case (4)/(5)).
        let cdb = [0x28, 0, 0, 0xFF, 0xFF, 0, 0, 0, 1, 0];
        let raw = raw_cbw(0x20, 512, 0x80, 0, &cdb);
        let step = s.poll(SessionEvent::OutRecv { data: &raw }, &mut data, &mut devs);
        match step {
            SessionStep::NeedIn(bytes) => {
                assert!(bytes.is_empty());
                assert_eq!(s.need(), SessionNeed::NeedIn { len: 0 });
            }
            other => panic!("expected empty ZLP need, got {other:?}"),
        }
        // ZLP sent → CSW pending (Failed, residue = declared = 512).
        let step = s.poll(SessionEvent::InSent, &mut data, &mut devs);
        match step {
            SessionStep::NeedIn(_) => {}
            other => panic!("expected CSW, got {other:?}"),
        }
        let (tag, residue, status) = read_csw(&mut s, &mut data);
        assert_eq!(tag, 0x20);
        assert_eq!(residue, 512);
        assert_eq!(status, 0x01); // Failed
        assert_eq!(
            s.poll(SessionEvent::InSent, &mut data, &mut devs),
            SessionStep::Done(BotStepResult::Processed)
        );
    }

    #[test]
    fn mps_multiple_shortfall_sends_zlp_then_csw() {
        let mut ram = vec![0u8; 64 * 1024];
        let mut devs = [test_dev(&mut ram)];
        let mut s = BotSession::new().with_shortfall(ShortfallPolicy::ShortNoStall);
        let mut data = work();

        // READ(10) count 1 → 512 data bytes, while CBW declared 1024. The
        // shortfall is not padded: the phase ends with a short packet. 512 is
        // a multiple of the bulk MPS, so a ZLP must terminate the data phase
        // before the CSW (BOT §6.7 Case (4)/(5)).
        let cdb = [0x28, 0, 0, 0, 0, 0, 0, 0, 1, 0];
        let raw = raw_cbw(0x21, 1024, 0x80, 0, &cdb);
        let step = s.poll(SessionEvent::OutRecv { data: &raw }, &mut data, &mut devs);
        match step {
            SessionStep::NeedIn(bytes) => assert_eq!(bytes.len(), 512),
            other => panic!("expected 512-byte chunk, got {other:?}"),
        }
        // 512 bytes sent: 512 % MPS == 0 → an empty ZLP first.
        let step = s.poll(SessionEvent::InSent, &mut data, &mut devs);
        match step {
            SessionStep::NeedIn(bytes) => assert!(bytes.is_empty(), "expected ZLP"),
            other => panic!("expected ZLP, got {other:?}"),
        }
        // Then the CSW.
        let step = s.poll(SessionEvent::InSent, &mut data, &mut devs);
        match step {
            SessionStep::NeedIn(_) => {}
            other => panic!("expected CSW, got {other:?}"),
        }
        let (tag, residue, status) = read_csw(&mut s, &mut data);
        assert_eq!(tag, 0x21);
        assert_eq!(residue, 1024 - 512);
        assert_eq!(status, 0x00); // Passed
        assert_eq!(
            s.poll(SessionEvent::InSent, &mut data, &mut devs),
            SessionStep::Done(BotStepResult::Processed)
        );
    }

    #[test]
    fn failed_data_out_drains_declared_then_csw() {
        let mut ram = vec![0u8; 64 * 1024];
        let mut devs = [test_dev(&mut ram)];
        let mut s = BotSession::new();
        let mut data = work();

        // WRITE(10) at an out-of-range LBA → CHECK CONDITION, but the CBW
        // declared a 512-byte Data-Out phase the host will still send. The
        // bytes must be drained so they cannot corrupt the next CBW.
        let cdb = [0x2A, 0, 0, 0xFF, 0xFF, 0, 0, 0, 1, 0];
        let raw = raw_cbw(0x22, 512, 0x00, 0, &cdb);
        let step = s.poll(SessionEvent::OutRecv { data: &raw }, &mut data, &mut devs);
        assert_eq!(
            step,
            SessionStep::NeedOut {
                len: 512,
                probe: false
            }
        );

        // The host's data-out arrives and is discarded (nothing written).
        let payload = vec![0xAA; 512];
        let step = s.poll(
            SessionEvent::OutRecv { data: &payload },
            &mut data,
            &mut devs,
        );
        match step {
            SessionStep::NeedOut { probe: true, .. } => {}
            other => panic!("expected overrun probe, got {other:?}"),
        }
        let step = s.poll(SessionEvent::OutIdle, &mut data, &mut devs);
        match step {
            SessionStep::NeedIn(_) => {}
            other => panic!("expected CSW, got {other:?}"),
        }
        let (tag, residue, status) = read_csw(&mut s, &mut data);
        assert_eq!(tag, 0x22);
        assert_eq!(residue, 512); // nothing written
        assert_eq!(status, 0x01); // Failed
                                  // The backend was not written.
        let mut check = [0u8; 512];
        read_via_xfer(&mut devs[0], 0, &mut check);
        assert!(check.iter().all(|&b| b == 0));
    }

    #[test]
    fn invalid_cbw_frozen_until_reset() {
        let mut ram = vec![0u8; 64 * 1024];
        let mut devs = [test_dev(&mut ram)];
        let mut s = BotSession::new();
        let mut data = work();

        let mut bad = raw_cbw(1, 0, 0, 0, &[0x00, 0, 0, 0, 0, 0]);
        bad[0] = b'X'; // bad signature
        let step = s.poll(SessionEvent::OutRecv { data: &bad }, &mut data, &mut devs);
        assert_eq!(step, SessionStep::Done(BotStepResult::Stalled));
        assert_eq!(s.need(), SessionNeed::Done(BotStepResult::Stalled));

        // Frozen: any further bulk event is ignored.
        let step = s.poll(SessionEvent::OutRecv { data: &bad }, &mut data, &mut devs);
        assert_eq!(step, SessionStep::Done(BotStepResult::Stalled));
        let step = s.poll(SessionEvent::InSent, &mut data, &mut devs);
        assert_eq!(step, SessionStep::Done(BotStepResult::Stalled));

        // BOT §3.1: BotReset preserves the STALL condition. The session stays
        // STALLed until CLEAR FEATURE(ENDPOINT_HALT) is received.
        s.reset();
        assert_eq!(s.need(), SessionNeed::Done(BotStepResult::Stalled));

        // CLEAR FEATURE(ENDPOINT_HALT) unfreezes; a valid CBW is then processed.
        s.clear_feature_halt();
        assert_eq!(
            s.need(),
            SessionNeed::NeedOut {
                len: 31,
                probe: false
            }
        );
        let raw = raw_cbw(2, 96, 0x80, 0, &inquiry_cdb(96));
        let step = s.poll(SessionEvent::OutRecv { data: &raw }, &mut data, &mut devs);
        match step {
            SessionStep::NeedIn(bytes) => assert_eq!(bytes.len(), 96),
            other => panic!("expected INQUIRY data, got {other:?}"),
        }
    }

    #[test]
    fn reset_interrupts_data_phase() {
        let mut ram = vec![0u8; 64 * 1024];
        let mut devs = [test_dev(&mut ram)];
        let mut s = BotSession::new();
        let mut data = work();

        let cdb = [0x2A, 0, 0, 0, 0, 0, 0, 0, 1, 0];
        let raw = raw_cbw(5, 512, 0x00, 0, &cdb);
        let step = s.poll(SessionEvent::OutRecv { data: &raw }, &mut data, &mut devs);
        assert_eq!(
            step,
            SessionStep::NeedOut {
                len: 512,
                probe: false
            }
        );

        // Partial data received.
        let part = vec![0xAA; 128];
        let step = s.poll(SessionEvent::OutRecv { data: &part }, &mut data, &mut devs);
        assert_eq!(
            step,
            SessionStep::NeedOut {
                len: 384,
                probe: false
            }
        );

        // Reset aborts the transaction and returns to Command.
        s.reset();
        assert_eq!(
            s.need(),
            SessionNeed::NeedOut {
                len: 31,
                probe: false
            }
        );

        // A new valid CBW is processed.
        let raw = raw_cbw(6, 96, 0x80, 0, &inquiry_cdb(96));
        let step = s.poll(SessionEvent::OutRecv { data: &raw }, &mut data, &mut devs);
        match step {
            SessionStep::NeedIn(_) => {}
            other => panic!("expected INQUIRY data, got {other:?}"),
        }
    }

    #[test]
    fn invalid_lun_failed_csw_then_request_sense() {
        let mut ram = vec![0u8; 64 * 1024];
        let mut devs = [test_dev(&mut ram)];
        let mut s = BotSession::new();
        let mut data = work();

        // TEST UNIT READY to LUN 3 (only LUN 0 exists) → Failed CSW.
        let raw = raw_cbw(7, 0, 0, 3, &[0x00, 0, 0, 0, 0, 0]);
        let step = s.poll(SessionEvent::OutRecv { data: &raw }, &mut data, &mut devs);
        match step {
            SessionStep::NeedIn(_) => {}
            other => panic!("expected CSW, got {other:?}"),
        }
        let (tag, residue, status) = read_csw(&mut s, &mut data);
        assert_eq!(tag, 7);
        assert_eq!(residue, 0);
        assert_eq!(status, 0x01); // Failed
        assert_eq!(
            s.poll(SessionEvent::InSent, &mut data, &mut devs),
            SessionStep::Done(BotStepResult::Processed)
        );

        // REQUEST SENSE to the invalid LUN → LOGICAL UNIT NOT SUPPORTED.
        let mut rs = [0u8; 6];
        rs[0] = scsi_op::REQUEST_SENSE;
        rs[4] = 18;
        let raw = raw_cbw(8, 18, 0x80, 3, &rs);
        let step = s.poll(SessionEvent::OutRecv { data: &raw }, &mut data, &mut devs);
        match step {
            SessionStep::NeedIn(bytes) => {
                assert_eq!(bytes.len(), 18);
                assert_eq!(bytes[0], 0x70); // fixed format
                assert_eq!(bytes[2], 0x05); // ILLEGAL REQUEST
                assert_eq!(bytes[12], 0x25); // LOGICAL UNIT NOT SUPPORTED
            }
            other => panic!("expected sense data, got {other:?}"),
        }
        let step = s.poll(SessionEvent::InSent, &mut data, &mut devs);
        match step {
            SessionStep::NeedIn(_) => {}
            other => panic!("expected CSW, got {other:?}"),
        }
        let (_, _, status) = read_csw(&mut s, &mut data);
        assert_eq!(status, 0x00); // Passed
    }

    #[test]
    fn unit_attention_after_reset() {
        let mut ram = vec![0u8; 64 * 1024];
        let mut devs = [test_dev(&mut ram)];
        let mut s = BotSession::new();
        let mut data = work();

        s.reset();

        // First TEST UNIT READY → CHECK CONDITION (UA), Failed CSW.
        let raw = raw_cbw(1, 0, 0, 0, &[0x00, 0, 0, 0, 0, 0]);
        let step = s.poll(SessionEvent::OutRecv { data: &raw }, &mut data, &mut devs);
        match step {
            SessionStep::NeedIn(_) => {}
            other => panic!("expected CSW, got {other:?}"),
        }
        let (_, _, status) = read_csw(&mut s, &mut data);
        assert_eq!(status, 0x01); // Failed
        assert_eq!(
            s.poll(SessionEvent::InSent, &mut data, &mut devs),
            SessionStep::Done(BotStepResult::Processed)
        );

        // REQUEST SENSE → the UA (0x29/00) is reported and cleared.
        let mut rs = [0u8; 6];
        rs[0] = scsi_op::REQUEST_SENSE;
        rs[4] = 18;
        let raw = raw_cbw(2, 18, 0x80, 0, &rs);
        let step = s.poll(SessionEvent::OutRecv { data: &raw }, &mut data, &mut devs);
        match step {
            SessionStep::NeedIn(bytes) => {
                assert_eq!(bytes[2], 0x06); // UNIT ATTENTION
                assert_eq!(bytes[12], 0x29);
                assert_eq!(bytes[13], 0x00);
            }
            other => panic!("expected UA sense, got {other:?}"),
        }
        let step = s.poll(SessionEvent::InSent, &mut data, &mut devs);
        match step {
            SessionStep::NeedIn(_) => {} // CSW pending
            other => panic!("expected CSW, got {other:?}"),
        }
        assert_eq!(
            s.poll(SessionEvent::InSent, &mut data, &mut devs),
            SessionStep::Done(BotStepResult::Processed)
        );

        // Subsequent TEST UNIT READY → GOOD (Passed CSW).
        let raw = raw_cbw(3, 0, 0, 0, &[0x00, 0, 0, 0, 0, 0]);
        let step = s.poll(SessionEvent::OutRecv { data: &raw }, &mut data, &mut devs);
        match step {
            SessionStep::NeedIn(_) => {}
            other => panic!("expected CSW, got {other:?}"),
        }
        let (_, _, status) = read_csw(&mut s, &mut data);
        assert_eq!(status, 0x00); // Passed
    }

    #[test]
    fn report_luns_select_report_semantics() {
        let mut ram = vec![0u8; 64 * 1024];
        let mut devs = [test_dev(&mut ram)];
        let mut s = BotSession::new();
        let mut data = work();

        // 01h → empty inventory (no well-known logical units implemented).
        let raw = raw_cbw(21, 16, 0x80, 0, &[0xA0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 16]);
        let step = s.poll(SessionEvent::OutRecv { data: &raw }, &mut data, &mut devs);
        let p1 = match step {
            SessionStep::NeedIn(bytes) => bytes.to_vec(),
            other => panic!("expected REPORT LUNS data, got {other:?}"),
        };
        assert_eq!(u32::from_be_bytes([p1[0], p1[1], p1[2], p1[3]]), 0);
        match s.poll(SessionEvent::InSent, &mut data, &mut devs) {
            SessionStep::NeedIn(_) => {}
            other => panic!("expected CSW, got {other:?}"),
        }
        let (_, _, st1) = read_csw(&mut s, &mut data);
        assert_eq!(st1, 0x00);
        assert_eq!(
            s.poll(SessionEvent::InSent, &mut data, &mut devs),
            SessionStep::Done(BotStepResult::Processed)
        );

        // 02h → full inventory (same as 00h for peripheral-only arrays).
        let raw = raw_cbw(22, 16, 0x80, 0, &[0xA0, 0, 2, 0, 0, 0, 0, 0, 0, 0, 0, 16]);
        let step = s.poll(SessionEvent::OutRecv { data: &raw }, &mut data, &mut devs);
        let p2 = match step {
            SessionStep::NeedIn(bytes) => bytes.to_vec(),
            other => panic!("expected REPORT LUNS data, got {other:?}"),
        };
        assert_eq!(u32::from_be_bytes([p2[0], p2[1], p2[2], p2[3]]), 8);
        assert_eq!(p2[8], 0x00); // address method 00b
        assert_eq!(p2[9], 0x00); // LUN 0
        match s.poll(SessionEvent::InSent, &mut data, &mut devs) {
            SessionStep::NeedIn(_) => {}
            other => panic!("expected CSW, got {other:?}"),
        }
        let (_, _, st2) = read_csw(&mut s, &mut data);
        assert_eq!(st2, 0x00);
        assert_eq!(
            s.poll(SessionEvent::InSent, &mut data, &mut devs),
            SessionStep::Done(BotStepResult::Processed)
        );

        // 03h (reserved) → Failed CSW; 05/24 sense stored on the device.
        // actual=0 < declared=16 → ZLP, then CSW (BOT §6.7.2 short packet).
        let raw = raw_cbw(23, 16, 0x80, 0, &[0xA0, 0, 3, 0, 0, 0, 0, 0, 0, 0, 0, 16]);
        let step = s.poll(SessionEvent::OutRecv { data: &raw }, &mut data, &mut devs);
        match step {
            SessionStep::NeedIn(bytes) => assert_eq!(bytes.len(), 0), // ZLP
            other => panic!("expected ZLP, got {other:?}"),
        }
        match s.poll(SessionEvent::InSent, &mut data, &mut devs) {
            SessionStep::NeedIn(_) => {}
            other => panic!("expected CSW, got {other:?}"),
        }
        let (_, _, st3) = read_csw(&mut s, &mut data);
        assert_eq!(st3, 0x01); // Failed
        assert_eq!(
            s.poll(SessionEvent::InSent, &mut data, &mut devs),
            SessionStep::Done(BotStepResult::Processed)
        );

        // REQUEST SENSE → INVALID FIELD IN CDB (0x24).
        let mut rs = [0u8; 6];
        rs[0] = scsi_op::REQUEST_SENSE;
        rs[4] = 18;
        let raw = raw_cbw(24, 18, 0x80, 0, &rs);
        let step = s.poll(SessionEvent::OutRecv { data: &raw }, &mut data, &mut devs);
        match step {
            SessionStep::NeedIn(bytes) => {
                assert_eq!(bytes[12], 0x24);
            }
            other => panic!("expected sense data, got {other:?}"),
        }
    }

    #[test]
    fn report_luns_is_synthesized_for_any_lun() {
        let mut ram = vec![0u8; 64 * 1024];
        let mut devs = [test_dev(&mut ram)];
        let mut s = BotSession::new();
        let mut data = work();

        // REPORT LUNS, allocation 16, addressed to LUN 0.
        let cdb = [0xA0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 16];
        let raw = raw_cbw(9, 16, 0x80, 0, &cdb);
        let step = s.poll(SessionEvent::OutRecv { data: &raw }, &mut data, &mut devs);
        match step {
            SessionStep::NeedIn(bytes) => {
                assert_eq!(bytes.len(), 16);
                assert_eq!(
                    u32::from_be_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]),
                    8
                ); // one LUN × 8
                assert_eq!(bytes[8], 0x00); // address method 00b
                assert_eq!(bytes[9], 0x00); // LUN id 0
            }
            other => panic!("expected REPORT LUNS data, got {other:?}"),
        }
    }

    #[test]
    fn host_asks_for_more_data_gets_short_packet_and_residue() {
        let mut ram = vec![0u8; 64 * 1024];
        let mut devs = [test_dev(&mut ram)];
        let mut s = BotSession::new().with_shortfall(ShortfallPolicy::ShortNoStall);
        let mut data = work();

        // INQUIRY data is 96 bytes, but the host declared 192.
        let raw = raw_cbw(10, 192, 0x80, 0, &inquiry_cdb(96));
        let step = s.poll(SessionEvent::OutRecv { data: &raw }, &mut data, &mut devs);
        match step {
            SessionStep::NeedIn(bytes) => assert_eq!(bytes.len(), 96),
            other => panic!("expected short INQUIRY packet, got {other:?}"),
        }
        let step = s.poll(SessionEvent::InSent, &mut data, &mut devs);
        match step {
            SessionStep::NeedIn(_) => {}
            other => panic!("expected CSW, got {other:?}"),
        }
        let (_, residue, status) = read_csw(&mut s, &mut data);
        assert_eq!(residue, 192 - 96); // short packet + residue, no STALL
        assert_eq!(status, 0x00);
    }

    /// Scripted bulk driver for the blocking `step` wrapper.
    struct ScriptIo {
        out: VecDeque<u8>,
        sent: RefCell<Vec<u8>>,
        stall: u32,
    }

    impl ScriptIo {
        fn new(out: &[u8]) -> Self {
            Self {
                out: out.iter().copied().collect(),
                sent: RefCell::new(Vec::new()),
                stall: 0,
            }
        }
    }

    impl BotIo for ScriptIo {
        fn try_recv_out(&mut self, buf: &mut [u8]) -> Result<usize, BotIoErr> {
            if self.out.is_empty() {
                return Err(BotIoErr::WouldBlock);
            }
            let n = self.out.len().min(buf.len());
            for (i, b) in self.out.drain(..n).enumerate() {
                buf[i] = b;
            }
            Ok(n)
        }

        fn recv_out(
            &mut self,
            buf: &mut [u8],
            _timeout: Option<Duration>,
        ) -> Result<usize, BotIoErr> {
            self.try_recv_out(buf)
        }

        fn send_in(&mut self, buf: &[u8]) -> Result<(), BotIoErr> {
            self.sent.borrow_mut().extend_from_slice(buf);
            Ok(())
        }

        fn stall_both(&mut self) -> Result<(), ()> {
            self.stall += 1;
            Ok(())
        }
    }

    #[test]
    fn step_drives_inquiry_to_completion() {
        let mut ram = vec![0u8; 64 * 1024];
        let mut devs = [test_dev(&mut ram)];
        let mut s = BotSession::new();
        let mut data = work();
        let mut recv = work();

        let raw = raw_cbw(0xCAFE, 96, 0x80, 0, &inquiry_cdb(96));
        let mut io = ScriptIo::new(&raw);
        let r = s.step(&mut io, &mut data, &mut recv, &mut devs);
        assert_eq!(r, BotStepResult::Processed);

        // Sent: 96-byte INQUIRY response then the 13-byte CSW.
        let sent = io.sent.borrow();
        assert_eq!(sent.len(), 96 + CSW_LEN);
        assert_eq!(sent[0] & 0x1F, 0x00);
        assert_eq!(
            &sent[sent.len() - CSW_LEN..sent.len() - CSW_LEN + 4],
            b"USBS"
        );
        assert_eq!(
            u32::from_le_bytes([
                sent[sent.len() - 9],
                sent[sent.len() - 8],
                sent[sent.len() - 7],
                sent[sent.len() - 6],
            ]),
            0xCAFE
        );
        assert_eq!(sent[sent.len() - 1], 0x00); // Passed
    }

    #[test]
    fn step_drives_write_with_data_phase() {
        let mut ram = vec![0u8; 64 * 1024];
        let mut devs = [test_dev(&mut ram)];
        let mut s = BotSession::new();
        let mut data = work();
        let mut recv = work();

        let cdb = [0x2A, 0, 0, 0, 0, 0, 0, 0, 1, 0];
        let raw = raw_cbw(0xBEEF, 512, 0x00, 0, &cdb);
        let payload: Vec<u8> = (0..512u16).map(|i| (i % 3) as u8).collect();
        // Queue: CBW + data payload.
        let mut stream = Vec::with_capacity(31 + 512);
        stream.extend_from_slice(&raw);
        stream.extend_from_slice(&payload);

        let mut io = ScriptIo::new(&stream);
        let r = s.step(&mut io, &mut data, &mut recv, &mut devs);
        assert_eq!(r, BotStepResult::Processed);
        let mut check = [0u8; 512];
        read_via_xfer(&mut devs[0], 0, &mut check);
        assert_eq!(&check[..], payload.as_slice());
    }

    // ── Data-In shortfall policy ────────────────────────────────────

    /// A 10-byte READ(10) CDB for `blocks` blocks at LBA 0.
    fn read10(blocks: u16) -> [u8; 10] {
        let mut cdb = [0u8; 10];
        cdb[0] = scsi_op::READ_10;
        cdb[7] = (blocks >> 8) as u8;
        cdb[8] = (blocks & 0xFF) as u8;
        cdb
    }

    #[test]
    fn default_shortfall_is_short_no_stall() {
        assert_eq!(ShortfallPolicy::default(), ShortfallPolicy::ShortNoStall);
        // The default session uses the max-compat policy.
        assert_eq!(BotSession::new().shortfall(), ShortfallPolicy::ShortNoStall);
        let mut s = BotSession::new();
        s.set_shortfall(ShortfallPolicy::Pad);
        assert_eq!(s.shortfall(), ShortfallPolicy::Pad);
        assert_eq!(
            BotSession::new()
                .with_shortfall(ShortfallPolicy::Short)
                .shortfall(),
            ShortfallPolicy::Short
        );
    }

    #[test]
    fn pad_fills_shortfall_to_declared_with_relevant_residue() {
        let mut ram = vec![0u8; 64 * 1024];
        let mut devs = [test_dev(&mut ram)];
        let mut s = BotSession::new().with_shortfall(ShortfallPolicy::Pad);
        let mut data = work();

        // READ(10) 1 block = 512 bytes; host declared 1024.
        let raw = raw_cbw(1, 1024, 0x80, 0, &read10(1));
        match s.poll(SessionEvent::OutRecv { data: &raw }, &mut data, &mut devs) {
            SessionStep::NeedIn(bytes) => assert_eq!(bytes.len(), 512),
            other => panic!("expected 512 relevant bytes, got {other:?}"),
        }
        // Fill zeros up to `declared`.
        match s.poll(SessionEvent::InSent, &mut data, &mut devs) {
            SessionStep::NeedIn(bytes) => {
                assert_eq!(bytes.len(), 512);
                assert!(bytes.iter().all(|&b| b == 0), "fill must be zeros");
            }
            other => panic!("expected 512 fill bytes, got {other:?}"),
        }
        // Then the CSW; residue is the *relevant* shortfall, not 0.
        match s.poll(SessionEvent::InSent, &mut data, &mut devs) {
            SessionStep::NeedIn(_) => {}
            other => panic!("expected CSW, got {other:?}"),
        }
        let (tag, residue, status) = read_csw(&mut s, &mut data);
        assert_eq!(tag, 1);
        assert_eq!(residue, 1024 - 512);
        assert_eq!(status, 0x00);
        assert_eq!(
            s.poll(SessionEvent::InSent, &mut data, &mut devs),
            SessionStep::Done(BotStepResult::Processed)
        );
    }

    #[test]
    fn pad_mps_multiple_shortfall_has_no_stray_trailer() {
        let mut ram = vec![0u8; 64 * 1024];
        let mut devs = [test_dev(&mut ram)];
        let mut s = BotSession::new().with_shortfall(ShortfallPolicy::Pad);
        let mut data = work();

        // READ(10) 2 blocks = 1024 bytes (2 MPS); host declared 2048.
        let raw = raw_cbw(2, 2048, 0x80, 0, &read10(2));
        match s.poll(SessionEvent::OutRecv { data: &raw }, &mut data, &mut devs) {
            SessionStep::NeedIn(bytes) => assert_eq!(bytes.len(), 1024),
            other => panic!("expected 1024 relevant bytes, got {other:?}"),
        }
        match s.poll(SessionEvent::InSent, &mut data, &mut devs) {
            SessionStep::NeedIn(bytes) => assert_eq!(bytes.len(), 1024),
            other => panic!("expected 1024 fill bytes, got {other:?}"),
        }
        // Fully filled to declared → CSW directly (no ZLP/stray trailer).
        match s.poll(SessionEvent::InSent, &mut data, &mut devs) {
            SessionStep::NeedIn(_) => {}
            other => panic!("expected CSW, got {other:?}"),
        }
        let (_, residue, status) = read_csw(&mut s, &mut data); // asserts CSW length
        assert_eq!(residue, 2048 - 1024);
        assert_eq!(status, 0x00);
    }

    #[test]
    fn pad_non_mps_aligned_shortfall_still_fills() {
        // A 95-byte INQUIRY against a declared 192: the final relevant chunk is
        // zero-extended in-buffer to declared, so the host never sees a
        // premature short packet.
        let mut ram = vec![0u8; 64 * 1024];
        let mut devs = [test_dev(&mut ram)];
        let mut s = BotSession::new().with_shortfall(ShortfallPolicy::Pad);
        let mut data = work();

        let raw = raw_cbw(3, 192, 0x80, 0, &inquiry_cdb(95));
        match s.poll(SessionEvent::OutRecv { data: &raw }, &mut data, &mut devs) {
            SessionStep::NeedIn(bytes) => {
                assert_eq!(bytes.len(), 192, "one transfer reaching declared");
                assert_eq!(bytes[0] & 0x1F, 0x00); // INQUIRY payload
                assert!(bytes[95..].iter().all(|&b| b == 0), "tail is fill");
            }
            other => panic!("expected a single 192-byte transfer, got {other:?}"),
        }
        match s.poll(SessionEvent::InSent, &mut data, &mut devs) {
            SessionStep::NeedIn(_) => {}
            other => panic!("expected CSW, got {other:?}"),
        }
        let (_, residue, status) = read_csw(&mut s, &mut data);
        assert_eq!(residue, 192 - 95);
        assert_eq!(status, 0x00);
    }

    #[test]
    fn pad_cap_hit_ends_short_no_stall() {
        let mut ram = vec![0u8; 64 * 1024];
        let mut devs = [test_dev(&mut ram)];
        let mut s = BotSession::new().with_shortfall(ShortfallPolicy::Pad);
        let mut data = vec![0u8; 64 * 1024];
        let mut recv = work();

        // READ(10) 1 block (512 produced); declared far past produced + MAX_PAD.
        let declared = 512 + MAX_PAD as u32 + 512;
        let raw = raw_cbw(4, declared, 0x80, 0, &read10(1));
        let mut io = ScriptIo::new(&raw);
        let r = s.step(&mut io, &mut data, &mut recv, &mut devs);
        assert_eq!(r, BotStepResult::Processed);

        // 512 relevant + exactly MAX_PAD fill + ZLP (wire is MPS-multiple) + CSW.
        let wire = 512 + MAX_PAD as usize;
        let sent = io.sent.borrow();
        assert_eq!(sent.len(), wire + CSW_LEN, "no STALL, no oversized pour");
        let csw = &sent[sent.len() - CSW_LEN..];
        assert_eq!(&csw[..4], b"USBS");
        assert_eq!(
            u32::from_le_bytes([csw[8], csw[9], csw[10], csw[11]]),
            declared - 512
        );
        assert_eq!(csw[12], 0x00);
    }

    #[test]
    fn step_drives_pad_to_declared() {
        let mut ram = vec![0u8; 64 * 1024];
        let mut devs = [test_dev(&mut ram)];
        let mut s = BotSession::new().with_shortfall(ShortfallPolicy::Pad);
        let mut data = work();
        let mut recv = work();

        let raw = raw_cbw(5, 1024, 0x80, 0, &read10(1));
        let mut io = ScriptIo::new(&raw);
        let r = s.step(&mut io, &mut data, &mut recv, &mut devs);
        assert_eq!(r, BotStepResult::Processed);
        // 512 relevant + 512 fill + CSW.
        assert_eq!(io.sent.borrow().len(), 512 + 512 + CSW_LEN);
    }

    #[test]
    fn short_shortfall_zlp_stall_applied_then_csw() {
        let mut ram = vec![0u8; 64 * 1024];
        let mut devs = [test_dev(&mut ram)];
        let mut s = BotSession::new().with_shortfall(ShortfallPolicy::Short);
        let mut data = work();

        // READ 1 block (512, an MPS multiple) vs declared 1024.
        let raw = raw_cbw(6, 1024, 0x80, 0, &read10(1));
        match s.poll(SessionEvent::OutRecv { data: &raw }, &mut data, &mut devs) {
            SessionStep::NeedIn(bytes) => assert_eq!(bytes.len(), 512),
            other => panic!("expected 512 relevant bytes, got {other:?}"),
        }
        // 512 % MPS == 0 → a ZLP first.
        assert_eq!(
            s.poll(SessionEvent::InSent, &mut data, &mut devs),
            SessionStep::NeedIn(&[])
        );
        assert_eq!(s.need(), SessionNeed::NeedIn { len: 0 });
        // Then the STALL.
        assert_eq!(
            s.poll(SessionEvent::InSent, &mut data, &mut devs),
            SessionStep::NeedStall
        );
        assert_eq!(s.need(), SessionNeed::NeedStall);
        // Bulk events are ignored while stalled.
        assert_eq!(
            s.poll(SessionEvent::InSent, &mut data, &mut devs),
            SessionStep::NeedStall
        );
        assert_eq!(
            s.poll(SessionEvent::OutRecv { data: &[] }, &mut data, &mut devs),
            SessionStep::NeedStall
        );
        // The driver releases the stall (no CLEAR_FEATURE event to wait for).
        s.stall_applied();
        assert_eq!(s.need(), SessionNeed::NeedIn { len: CSW_LEN });
        let (tag, residue, status) = read_csw(&mut s, &mut data);
        assert_eq!(tag, 6);
        assert_eq!(residue, 1024 - 512);
        assert_eq!(status, 0x00);
    }

    #[test]
    fn short_non_mps_shortfall_stalls_without_zlp() {
        let mut ram = vec![0u8; 64 * 1024];
        let mut devs = [test_dev(&mut ram)];
        let mut s = BotSession::new().with_shortfall(ShortfallPolicy::Short);
        let mut data = work();

        let raw = raw_cbw(7, 192, 0x80, 0, &inquiry_cdb(95));
        match s.poll(SessionEvent::OutRecv { data: &raw }, &mut data, &mut devs) {
            SessionStep::NeedIn(bytes) => assert_eq!(bytes.len(), 95),
            other => panic!("expected 95 relevant bytes, got {other:?}"),
        }
        // 95 % MPS != 0: the short packet already terminated the read → STALL
        // directly, no ZLP.
        assert_eq!(
            s.poll(SessionEvent::InSent, &mut data, &mut devs),
            SessionStep::NeedStall
        );
        s.stall_applied();
        let (_, residue, status) = read_csw(&mut s, &mut data);
        assert_eq!(residue, 192 - 95);
        assert_eq!(status, 0x00);
    }

    #[test]
    fn short_bot_reset_in_data_in_stall_aborts() {
        let mut ram = vec![0u8; 64 * 1024];
        let mut devs = [test_dev(&mut ram)];
        let mut s = BotSession::new().with_shortfall(ShortfallPolicy::Short);
        let mut data = work();

        let raw = raw_cbw(8, 192, 0x80, 0, &inquiry_cdb(95));
        s.poll(SessionEvent::OutRecv { data: &raw }, &mut data, &mut devs);
        assert_eq!(
            s.poll(SessionEvent::InSent, &mut data, &mut devs),
            SessionStep::NeedStall
        );

        // Bot Reset aborts the transaction; the CSW is dropped.
        s.reset();
        assert_eq!(
            s.need(),
            SessionNeed::NeedOut {
                len: CBW_LEN,
                probe: false
            }
        );
        // A later (stale) release is a no-op: no CSW is emitted.
        s.stall_applied();
        assert_eq!(
            s.need(),
            SessionNeed::NeedOut {
                len: CBW_LEN,
                probe: false
            }
        );
    }

    #[test]
    fn step_rejects_short_before_any_wire_effect() {
        let mut ram = vec![0u8; 64 * 1024];
        let mut devs = [test_dev(&mut ram)];
        let mut s = BotSession::new().with_shortfall(ShortfallPolicy::Short);
        let mut data = work();
        let mut recv = work();

        // Even an exact-length command (no shortfall) is rejected at entry.
        let raw = raw_cbw(9, 96, 0x80, 0, &inquiry_cdb(96));
        let mut io = ScriptIo::new(&raw);
        assert_eq!(
            s.step(&mut io, &mut data, &mut recv, &mut devs),
            BotStepResult::Unsupported
        );
        assert!(io.sent.borrow().is_empty(), "no wire effect");
        assert_eq!(
            s.need(),
            SessionNeed::NeedOut {
                len: CBW_LEN,
                probe: false
            }
        );
    }

    #[test]
    fn exact_length_transfer_unaffected_by_policy() {
        for policy in [
            ShortfallPolicy::Pad,
            ShortfallPolicy::Short,
            ShortfallPolicy::ShortNoStall,
        ] {
            let mut ram = vec![0u8; 64 * 1024];
            let mut devs = [test_dev(&mut ram)];
            let mut s = BotSession::new().with_shortfall(policy);
            let mut data = work();

            // INQUIRY alloc 96, declared 96: no shortfall.
            let raw = raw_cbw(10, 96, 0x80, 0, &inquiry_cdb(96));
            match s.poll(SessionEvent::OutRecv { data: &raw }, &mut data, &mut devs) {
                SessionStep::NeedIn(bytes) => assert_eq!(bytes.len(), 96),
                other => panic!("[{policy:?}] expected 96 bytes, got {other:?}"),
            }
            match s.poll(SessionEvent::InSent, &mut data, &mut devs) {
                SessionStep::NeedIn(_) => {}
                other => panic!("[{policy:?}] expected CSW, got {other:?}"),
            }
            let (_, residue, status) = read_csw(&mut s, &mut data);
            assert_eq!(residue, 0, "[{policy:?}] exact transfer has no residue");
            assert_eq!(status, 0x00);
            assert_eq!(
                s.poll(SessionEvent::InSent, &mut data, &mut devs),
                SessionStep::Done(BotStepResult::Processed)
            );
        }
    }
}
