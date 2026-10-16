//! USB MSC Bulk-Only Transport session state machine (target.rs).
//!
//! [`BotSession`] is a pure, non-blocking protocol state machine: it never
//! blocks and never touches platform I/O. A shell feeds one [`Event`] (an I/O
//! completion or a control-plane notification) per [`BotSession::poll`] call
//! and learns the next [`Action`] (receive, send, stall, or — from Step 2 on —
//! a storage op). The library shell [`crate::usb::serve()`] owns the platform
//! loop; the PC FunctionFS driver and embedded `select!` drivers implement the
//! same `Event`/`Action` contract.
//!
//! Out-of-band control enters the core as events: Bulk-Only Reset and
//! LinkReset arrive as [`Event::Reset`], Get Max LUN is a pure getter
//! ([`BotSession::max_lun`]). There is no out-of-band state mutation.
//!
//! Design invariants (§4 / §3.7 / §3.8):
//! - CBW (31B) accumulates into an internal buffer; CSW (13B) is assembled
//!   in an internal buffer; the caller's `work` area holds only SCSI data.
//! - STALL is used for invalid CBWs (both pipes, [`Action::StallBoth`]) and,
//!   under [`ShortfallPolicy::Short`], for a Data-In shortfall (Bulk-In only,
//!   [`Action::StallIn`]).
//! - Data-Out host overrun is drained to a short packet so leftover bytes
//!   never corrupt the next CBW.
//! - After a reset the session injects a UNIT ATTENTION: delivered on the
//!   next TEST UNIT READY (Failed CSW), cleared by REQUEST SENSE.
//!
//! ## Single-buffer model
//!
//! `poll` takes one time-multiplexed `work` buffer. A receive always lands at
//! `work[0..len]`; Data-In and synthesized responses are written into `work`.
//! A parameter-list Data-Out accumulates at the **tail** of `work` (the
//! `received` bytes sit at `work[work.len() - received..]`) so a front-landing
//! receive never clobbers earlier chunks.
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
//!   Bulk-In STALL ([`Action::StallIn`]); the CSW is queued straight away and
//!   reaches the host once it clears the halt (handled by the USB core). It
//!   needs a driver that implements `BotIo::stall_in` — retrying transient
//!   `-EAGAIN` (the endpoint cannot be halted while a request is queued or the
//!   FIFO still holds uncollected bytes) — and then feeds
//!   [`Event::StallApplied`]. A real `stall_in` failure aborts the transaction
//!   via [`Event::Reset`].
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

use crate::common::seekable_storage::StorageError;
use crate::common::store::StoreOp;
use crate::scsi::device::{sense_for_storage_error, CommandOutcome, ScsiDevice, Xfer, XferOutcome};
use crate::scsi::scsi::{asc, op as scsi_op, Sense, SenseKey};
use crate::usb::bot::{BotDir, Cbw, Csw, CswStatus};
use crate::usb::{CBW_LEN, CSW_LEN};

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
/// [`Action::HostSend`]. `4096` is a multiple of every realistic bulk MPS
/// (64 Full-Speed, 512 High-Speed), so intermediate fill chunks are full-MPS
/// packets; only a chunk reaching the (possibly non-aligned) pad target is a
/// short packet, which is correct because it is the final transfer.
const ZERO_CHUNK: [u8; 4096] = [0u8; 4096];

/// Policy for ending a Data-In command's data stage when a shortfall of
/// relevant data occurs (BOT §6.7.2). The default (`ShortNoStall`) is the
/// max-compat deviation; `Short` and `Pad` are the conformant modes. The
/// caller knows its transport, so the selected variant is the capability
/// declaration; a `Short`-without-`stall_in` mismatch exits through the
/// reset route (the shell feeds [`Event::Reset`]), never silently.
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
    /// Conformant: short packet then STALL Bulk-In ([`Action::StallIn`]); the
    /// withheld CSW is queued immediately and delivered once the host clears
    /// the halt. Requires a driver that implements `BotIo::stall_in` (retrying
    /// transient `-EAGAIN`) and then feeds [`Event::StallApplied`]; a real
    /// `stall_in` failure aborts via [`Event::Reset`].
    Short,
    /// Non-conformant, default: plain short packet, no STALL. Runs unaided on
    /// any transport (no stall capability, no clear observability required);
    /// the S3-validated behaviour.
    #[default]
    ShortNoStall,
}

/// The core's next action, returned by [`BotSession::poll`].
///
/// Normal flow never emits a "done" action: after a CSW is sent,
/// `poll(Event::HostSent)` returns the next command-phase
/// [`Action::HostRecv`] directly. Only the abnormal outcomes are distinct
/// (`StallBoth`/`StallIn`/`Error`).
#[derive(Debug)]
pub enum Action<'a> {
    /// Receive `len` bytes into `work[0..len]`. `probe` marks a non-blocking
    /// drain receive (Data-Out overrun): the shell should try once; a
    /// WouldBlock result ends the data phase and should be fed back as
    /// [`Event::HostIdle`].
    HostRecv { len: usize, probe: bool },
    /// Send `bytes` on the bulk-IN pipe. `prefetch` is the next read-ahead
    /// coordinate `(off, len)` for read-phase overlap (`None` in Step 1).
    HostSend {
        bytes: &'a [u8],
        prefetch: Option<(u64, usize)>,
    },
    /// Hand a storage op to the platform: the device's `xfer_out`/`xfer_in`
    /// returned [`Xfer::Store`] for the current data-phase chunk. The shell
    /// executes the op and feeds the result back as [`Event::StoreDone`];
    /// the Store is invisible on the wire.
    Store { lun: usize, op: StoreOp<'a> },
    /// Invalid CBW (BOT §6.6.1): STALL both bulk endpoints. The core has
    /// already returned to the Command phase; a new CBW arriving clears the
    /// halt (the host's CLEAR_FEATURE is handled by the USB core).
    StallBoth,
    /// `ShortfallPolicy::Short` Data-In shortfall: STALL Bulk-In, then feed
    /// [`Event::StallApplied`] to release the withheld CSW.
    StallIn,
    /// Core-level error (work buffer too small / impossible transition).
    Error(BotTargetError),
}

/// One completion fed from the shell to the core.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Event {
    /// No-I/O driver tick (startup + timer): change no state and re-emit the
    /// current pending [`Action`].
    Tick,
    /// The shell received `len` bytes into `work[0..len]`.
    HostRecv { len: usize },
    /// The shell's receive found no data (timed out). Has end-of-phase
    /// meaning for the Data-Out overrun drain.
    HostIdle,
    /// The pending bulk-IN packet has been sent.
    HostSent,
    /// A storage op finished: `result` is the plane's outcome. Fed by the
    /// shell after it executed an [`Action::Store`]; the session maps it
    /// through [`ScsiDevice::store_done`] and continues the data phase.
    StoreDone { result: Result<(), StorageError> },
    /// The `Short` shortfall's Bulk-In STALL has been applied; release the
    /// withheld CSW.
    StallApplied,
    /// Bulk-Only Reset / LinkReset: abort any in-flight transaction, return to
    /// the Command phase, and inject a UNIT ATTENTION (BOT §4.2, §5.2).
    Reset,
}

/// Core-level error (no_std).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BotTargetError {
    /// The caller's `work` buffer is smaller than [`crate::MIN_DATA_LEN`].
    WorkBufTooSmall,
    /// I/O failure (reported through the shell).
    Io,
    /// An impossible state transition (shell fed a wrong event).
    Internal,
}

impl core::fmt::Display for BotTargetError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::WorkBufTooSmall => write!(f, "work buffer smaller than MIN_DATA_LEN"),
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
    /// Data-In phase awaiting a storage op (`Xfer::Store`): the chunk is in
    /// flight in the platform. `sent` is the relevant data already sent
    /// (excluding this chunk); on [`Event::StoreDone`] the chunk is finalized
    /// — including the `ShortfallPolicy::Pad` boundary merge — and the phase
    /// continues exactly like the `Inline` path.
    DataInStore {
        expected: u64,
        transfer_len: u64,
        sent: u64,
        tag: u32,
        lun: usize,
        chunk: usize,
    },
    /// Data-Out phase awaiting a storage op (`Xfer::Store`): the received
    /// chunk `got` (of which `w` bytes were handed to `xfer_in`) is in flight.
    /// On [`Event::StoreDone`] `written` advances by `w` (or `status` becomes
    /// `Failed`) and the phase continues exactly like the `Inline` path.
    DataOutStore {
        declared: u64,
        to_write: u64,
        received: u64,
        written: u64,
        tag: u32,
        lun: usize,
        status: CswStatus,
        got: usize,
        w: usize,
    },
    /// Parameter-list Data-Out: receive `expected` bytes into the **tail** of
    /// `work` then call `complete_param`.
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
        lun: usize,
        chunk: usize,
    },
    /// Terminal-status pending: the data phase (including any ZLP / STALL) is
    /// done, but the device agenda (`ScsiDevice::next_store_op`) must be drained
    /// before the CSW. Carries the CSW
    /// payload; each `Some(op)` is yielded as [`Action::Store`] and awaited via
    /// [`Event::StoreDone`], then `devs[lun].store_done(result)` maps a failure
    /// to sense (the terminal status becomes `Failed`). `None` emits the CSW
    /// exactly as before.
    Agenda {
        tag: u32,
        residue: u64,
        status: CswStatus,
        lun: usize,
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
        lun: usize,
        chunk: usize,
    },
    /// CSW pending, but a zero-length packet must terminate the data phase
    /// first (a shortfall whose length is a multiple of the bulk MPS,
    /// including zero bytes — see [`finish_data_in`]). Carries the shortfall
    /// payload so the terminating `HostSent` can enter [`BotState::DataInStall`]
    /// under `ShortfallPolicy::Short`.
    CswZlp {
        tag: u32,
        declared: u64,
        actual: u64,
        status: CswStatus,
        lun: usize,
    },
    /// The CSW is pending, but the shell must first STALL Bulk-In
    /// (`ShortfallPolicy::Short`): `pending()` returns [`Action::StallIn`].
    /// Holds the CSW payload that [`Event::StallApplied`] turns into the CSW
    /// once the shell has set the halt. The host's CLEAR_FEATURE is handled by
    /// the USB core and is not observable here, so this state is released by
    /// [`Event::StallApplied`], not by a bulk event.
    DataInStall {
        tag: u32,
        declared: u64,
        actual: u64,
        status: CswStatus,
        lun: usize,
    },
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

    /// Get Max LUN answer value (`num_luns - 1`, ≤ 15). The LUN count is
    /// refreshed from the device slice on every command. Pure getter (no state
    /// change).
    pub fn max_lun(&self) -> u8 {
        self.num_luns.saturating_sub(1)
    }

    /// The action for the current state (the old `need()` + `out_slice()`
    /// merged). Used to re-emit the pending [`Action`] on [`Event::Tick`] and
    /// after an out-of-band control event.
    fn pending<'a>(&'a mut self, work: &'a mut [u8]) -> Action<'a> {
        match self.state {
            BotState::Command { got } => Action::HostRecv {
                len: CBW_LEN - got,
                probe: false,
            },
            BotState::DataIn { chunk, .. } => Action::HostSend {
                bytes: &work[..chunk],
                prefetch: None,
            },
            BotState::DataOut { chunk, .. } => Action::HostRecv {
                len: chunk,
                probe: false,
            },
            // A storage op is in flight. The op itself borrows the platform
            // buffer / device and cannot be rebuilt here; the shell executes
            // the pending `Action::Store` immediately and feeds
            // `Event::StoreDone`, so this is only reachable on a mis-fed
            // `Tick` / out-of-band event.
            BotState::DataInStore { .. } | BotState::DataOutStore { .. } => {
                Action::Error(BotTargetError::Internal)
            }
            // An agenda op is in flight: same reasoning as the data-phase
            // store states (the op cannot be rebuilt from state).
            BotState::Agenda { .. } => Action::Error(BotTargetError::Internal),
            BotState::ParamOut { chunk, .. } => Action::HostRecv {
                len: chunk,
                probe: false,
            },
            BotState::DataOutOverrun { chunk, .. } => Action::HostRecv {
                len: chunk,
                probe: true,
            },
            BotState::Csw => Action::HostSend {
                bytes: &self.csw[..],
                prefetch: None,
            },
            BotState::CswZlp { .. } => Action::HostSend {
                bytes: &[],
                prefetch: None,
            },
            BotState::DataInPad { chunk, .. } => Action::HostSend {
                bytes: &ZERO_CHUNK[..chunk],
                prefetch: None,
            },
            BotState::DataInStall { .. } => Action::StallIn,
        }
    }

    /// Bulk-Only Reset / LinkReset body: abort any in-flight transaction,
    /// return to the Command phase, and inject a UNIT ATTENTION for the next
    /// TEST UNIT READY (BOT §4.2, §5.2).
    ///
    /// Unlike the pre-Step-1 core there is no persistent `Stalled` state: an
    /// invalid CBW returns to the Command phase immediately (the host's
    /// CLEAR_FEATURE is handled by the USB core), so a reset always lands in
    /// `Command { got: 0 }`.
    fn reset_state(&mut self) {
        self.cbw = [0u8; CBW_LEN];
        self.invalid_lun_sense = None;
        self.pending_ua = Some(Sense::new(SenseKey::UnitAttention, asc::POWER_ON_RESET, 0));
        self.state = BotState::Command { got: 0 };
    }

    /// Enter the terminal-status agenda: remember the pending CSW payload and
    /// start draining the device agenda. Every terminal-status transition (CSW,
    /// GOOD or CHECK CONDITION) funnels through here so the device's
    /// maintenance/background ops (`next_store_op`) run **after** the data phase
    /// (including any ZLP / STALL) and **before** the CSW.
    ///
    /// `lun` may be out of range (invalid-LUN / REPORT LUNS terminal statuses);
    /// the drain then skips the device entirely and emits the CSW unchanged.
    fn enter_agenda<'a, D: ScsiDevice>(
        &'a mut self,
        tag: u32,
        residue: u64,
        status: CswStatus,
        lun: usize,
        devs: &'a mut [D],
    ) -> Action<'a> {
        self.state = BotState::Agenda {
            tag,
            residue,
            status,
            lun,
        };
        self.drain_agenda(devs)
    }

    /// Yield the next agenda op, or emit the terminal status once the agenda is
    /// drained. The CSW is written into the internal buffer on emission (the
    /// same bytes the pre-agenda code produced).
    fn drain_agenda<'a, D: ScsiDevice>(&'a mut self, devs: &'a mut [D]) -> Action<'a> {
        let BotState::Agenda {
            tag,
            residue,
            status,
            lun,
        } = self.state
        else {
            return Action::Error(BotTargetError::Internal);
        };
        if lun < devs.len() {
            if let Some(op) = devs[lun].next_store_op() {
                // Re-state the pending payload (the op is in flight).
                self.state = BotState::Agenda {
                    tag,
                    residue,
                    status,
                    lun,
                };
                return Action::Store { lun, op };
            }
        }
        self.store_csw(tag, residue, status);
        self.state = BotState::Csw;
        Action::HostSend {
            bytes: &self.csw[..],
            prefetch: None,
        }
    }

    /// Agenda op completion: map the result through `devs[lun].store_done` (a
    /// failure sets sense and turns the terminal status `Failed`) and continue
    /// the drain. `residue`/`tag` semantics are unchanged.
    fn poll_agenda<'a, D: ScsiDevice>(&'a mut self, ev: Event, devs: &'a mut [D]) -> Action<'a> {
        let BotState::Agenda {
            tag,
            residue,
            status,
            lun,
        } = self.state
        else {
            return Action::Error(BotTargetError::Internal);
        };
        match ev {
            Event::StoreDone { result } => {
                let status = if lun < devs.len() && store_done_failed(devs, lun, result) {
                    CswStatus::Failed
                } else {
                    status
                };
                self.state = BotState::Agenda {
                    tag,
                    residue,
                    status,
                    lun,
                };
                self.drain_agenda(devs)
            }
            _ => Action::Error(BotTargetError::Internal),
        }
    }

    /// Non-blocking state-machine step: consume one event and return the next
    /// action. `work` is the single time-multiplexed buffer; `devs` is the LUN
    /// slice.
    pub fn poll<'a, D: ScsiDevice>(
        &'a mut self,
        ev: Event,
        work: &'a mut [u8],
        devs: &'a mut [D],
    ) -> Action<'a> {
        // Out-of-band / no-I/O events first (they do not depend on the phase).
        match ev {
            Event::Reset => {
                self.reset_state();
                return self.pending(work);
            }
            Event::StallApplied => {
                // The `Short` shortfall's STALL is on the wire; the data phase
                // is now complete, so drain the device agenda before the CSW.
                if let BotState::DataInStall {
                    tag,
                    declared,
                    actual,
                    status,
                    lun,
                } = self.state
                {
                    return self.enter_agenda(tag, declared - actual, status, lun, devs);
                }
                return self.pending(work);
            }
            Event::Tick => return self.pending(work),
            // `StoreDone` is consumed by the Data-In/Data-Out store states
            // below; any other state treats it as a mis-fed event.
            Event::StoreDone { .. }
            | Event::HostRecv { .. }
            | Event::HostIdle
            | Event::HostSent => {}
        }
        match self.state {
            BotState::Command { got } => self.poll_command(ev, work, devs, got),
            BotState::DataIn { .. } => self.poll_data_in(ev, work, devs),
            BotState::DataInStore { .. } => self.poll_data_in_store(ev, work, devs),
            BotState::DataOut { .. } => self.poll_data_out(ev, work, devs),
            BotState::DataOutStore { .. } => self.poll_data_out_store(ev, work, devs),
            BotState::ParamOut { .. } => self.poll_param_out(ev, work, devs),
            BotState::DataOutOverrun { .. } => self.poll_overrun(ev, devs),
            BotState::Agenda { .. } => self.poll_agenda(ev, devs),
            BotState::Csw => self.poll_csw(ev),
            BotState::CswZlp { .. } => self.poll_csw_zlp(ev, devs),
            BotState::DataInPad { .. } => self.poll_data_in_pad(ev, devs),
            BotState::DataInStall { .. } => self.poll_data_in_stall(ev),
        }
    }

    // ── Command phase ──────────────────────────────────────────────

    fn poll_command<'a, D: ScsiDevice>(
        &'a mut self,
        ev: Event,
        work: &'a mut [u8],
        devs: &'a mut [D],
        got: usize,
    ) -> Action<'a> {
        match ev {
            Event::HostSent => Action::Error(BotTargetError::Internal),
            Event::HostIdle => Action::HostRecv {
                len: CBW_LEN - got,
                probe: false,
            },
            Event::HostRecv { len } => {
                // The shell guarantees `len <= work.len()`; clamp defensively.
                let recv = &work[..len.min(work.len())];
                if recv.len() > CBW_LEN - got {
                    crate::warn!(
                        "bot: CBW packet tail {} bytes discarded (single-packet CBW is 31B)",
                        recv.len() - (CBW_LEN - got)
                    );
                }
                let add = recv.len().min(CBW_LEN - got);
                self.cbw[got..got + add].copy_from_slice(&recv[..add]);
                let got = got + add;
                if got < CBW_LEN {
                    self.state = BotState::Command { got };
                    return Action::HostRecv {
                        len: CBW_LEN - got,
                        probe: false,
                    };
                }
                match Cbw::parse(&self.cbw) {
                    None => {
                        // Invalid CBW (BOT §6.6.1): STALL both endpoints and
                        // return to the Command phase. The host's
                        // CLEAR_FEATURE(ENDPOINT_HALT) is handled by the USB
                        // core; the next CBW arriving means the halt is clear.
                        self.state = BotState::Command { got: 0 };
                        Action::StallBoth
                    }
                    Some(cbw) => self.dispatch_cbw(&cbw, work, devs),
                }
            }
            _ => Action::Error(BotTargetError::Internal),
        }
    }

    // ── Command dispatch ───────────────────────────────────────────

    fn dispatch_cbw<'a, D: ScsiDevice>(
        &'a mut self,
        cbw: &Cbw,
        work: &'a mut [u8],
        devs: &'a mut [D],
    ) -> Action<'a> {
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
            core::str::from_utf8(crate::scsi::util::hex_of(&mut hx, cdb)).unwrap_or("?")
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
                return self.finish_cmd(
                    cbw,
                    0,
                    CswStatus::Failed,
                    work.len(),
                    cbw.lun as usize,
                    devs,
                );
            }
            let n = write_report_luns(work, if select == 0x01 { 0 } else { devs.len() });
            return self.synthesize_data_in(cbw, work, n as u64, devs);
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
                let n = sense.write_fixed(work);
                return self.synthesize_data_in(cbw, work, n as u64, devs);
            }
            self.invalid_lun_sense = Some(Sense::new(
                SenseKey::IllegalRequest,
                asc::LOGICAL_UNIT_NOT_SUPPORTED,
                0,
            ));
            return self.finish_cmd(
                cbw,
                0,
                CswStatus::Failed,
                work.len(),
                cbw.lun as usize,
                devs,
            );
        }

        // Valid LUN: unit-attention injection (§5.2). The UA is delivered
        // on the next TEST UNIT READY and cleared by REQUEST SENSE.
        if self.pending_ua.is_some() {
            match cdb.first() {
                Some(&scsi_op::TEST_UNIT_READY) => {
                    return self.finish_cmd(
                        cbw,
                        0,
                        CswStatus::Failed,
                        work.len(),
                        cbw.lun as usize,
                        devs,
                    );
                }
                Some(&scsi_op::REQUEST_SENSE) => {
                    // Defensive: no UA (driver raced a reset) — report an
                    // empty fixed-sense (NO SENSE) instead of panicking.
                    let sense = self.pending_ua.take().unwrap_or_else(Sense::clear);
                    let n = sense.write_fixed(work);
                    return self.synthesize_data_in(cbw, work, n as u64, devs);
                }
                _ => {}
            }
        }

        let lun = cbw.lun as usize;
        let outcome = match devs[lun].do_cmd(cdb, work) {
            Ok(o) => o,
            Err(crate::scsi::device::Error::WorkBufTooSmall) => {
                return Action::Error(BotTargetError::WorkBufTooSmall);
            }
            Err(_) => {
                return Action::Error(BotTargetError::Internal);
            }
        };
        match outcome {
            CommandOutcome::Status => {
                self.finish_cmd(cbw, 0, CswStatus::Passed, work.len(), lun, devs)
            }
            CommandOutcome::StatusWithSense => {
                self.finish_cmd(cbw, 0, CswStatus::Passed, work.len(), lun, devs)
            }
            CommandOutcome::CheckCondition => {
                self.finish_cmd(cbw, 0, CswStatus::Failed, work.len(), lun, devs)
            }
            CommandOutcome::OutInline { len } => {
                if declared == 0 {
                    // BOT §6.7.1 Case (2) Hn<Di: Di with Hn => PhaseError.
                    if len > 0 {
                        return self.finish_cmd(
                            cbw,
                            0,
                            CswStatus::PhaseError,
                            work.len(),
                            lun,
                            devs,
                        );
                    }
                    return self.finish_cmd(cbw, 0, CswStatus::Passed, work.len(), lun, devs);
                }
                if cbw.dir != BotDir::DataIn {
                    return self.finish_cmd(cbw, 0, CswStatus::PhaseError, work.len(), lun, devs);
                }
                // `len` is work-buffer-relative (`usize`); widen once at the
                // BOT boundary (declared ≤ u32::MAX per the CBW spec, so the
                // min below is exact on every target).
                let actual = (len as u64).min(declared);
                if actual == 0 {
                    return self.finish_cmd(cbw, 0, CswStatus::Passed, work.len(), lun, devs);
                }
                let mut chunk = (actual as usize).min(work.len());
                if chunk as u64 == actual {
                    chunk += self.merge_pad_boundary(work, chunk, declared, actual);
                }
                self.state = BotState::DataIn {
                    expected: declared,
                    transfer_len: actual,
                    sent: chunk as u64,
                    tag: cbw.tag,
                    lun,
                    chunk,
                };
                Action::HostSend {
                    bytes: &work[..chunk],
                    prefetch: None,
                }
            }
            CommandOutcome::OutXfer { len: transfer_len } => {
                if declared == 0 {
                    // BOT §6.7.1 Case (2) Hn<Di.
                    if transfer_len > 0 {
                        return self.finish_cmd(
                            cbw,
                            0,
                            CswStatus::PhaseError,
                            work.len(),
                            lun,
                            devs,
                        );
                    }
                    return self.finish_cmd(cbw, 0, CswStatus::Passed, work.len(), lun, devs);
                }
                if cbw.dir != BotDir::DataIn {
                    return self.finish_cmd(cbw, 0, CswStatus::PhaseError, work.len(), lun, devs);
                }
                let actual = transfer_len.min(declared);
                if actual == 0 {
                    return self.finish_cmd(cbw, 0, CswStatus::Passed, work.len(), lun, devs);
                }
                let mut chunk = (actual as usize).min(work.len());
                // The device may hand back a `Store` op whose buffer borrows
                // `work`; because the `Inline` branch below still needs `work`,
                // split the op into its Copy fields first (see [`StoreDesc`])
                // and re-attach a fresh borrow only once the call's borrow of
                // `work` has ended.
                let probe = match devs[lun].xfer_out(0, &mut work[..chunk]) {
                    Xfer::Inline { len } => Ok(len),
                    Xfer::Store(op) => match StoreDesc::of(op) {
                        Some(desc) => Err(desc),
                        None => return Action::Error(BotTargetError::Internal),
                    },
                };
                let produced = match probe {
                    Ok(len) => len,
                    Err(desc) => {
                        self.state = BotState::DataInStore {
                            expected: declared,
                            transfer_len: actual,
                            sent: 0,
                            tag: cbw.tag,
                            lun,
                            chunk,
                        };
                        return Action::Store {
                            lun,
                            op: desc.attach(&mut work[..chunk]),
                        };
                    }
                };
                if produced != chunk {
                    return self.finish_cmd(cbw, 0, CswStatus::Failed, work.len(), lun, devs);
                }
                if chunk as u64 == actual {
                    chunk += self.merge_pad_boundary(work, chunk, declared, actual);
                }
                self.state = BotState::DataIn {
                    expected: declared,
                    transfer_len: actual,
                    sent: chunk as u64,
                    tag: cbw.tag,
                    lun,
                    chunk,
                };
                Action::HostSend {
                    bytes: &work[..chunk],
                    prefetch: None,
                }
            }
            CommandOutcome::InXfer { len: transfer_len } => {
                if declared == 0 {
                    // BOT §6.7.1 Case (3) Hn<Do.
                    if transfer_len > 0 {
                        return self.finish_cmd(
                            cbw,
                            0,
                            CswStatus::PhaseError,
                            work.len(),
                            lun,
                            devs,
                        );
                    }
                    return self.finish_cmd(cbw, 0, CswStatus::Passed, work.len(), lun, devs);
                }
                if cbw.dir != BotDir::DataOut {
                    return self.finish_cmd(cbw, 0, CswStatus::PhaseError, work.len(), lun, devs);
                }
                let to_write = transfer_len.min(declared);
                let status = CswStatus::Passed;
                let chunk = (declared as usize).min(work.len());
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
                Action::HostRecv {
                    len: chunk,
                    probe: false,
                }
            }
            CommandOutcome::InParam { expected_len } => {
                let expected = expected_len as u64;
                if expected == 0 {
                    return self.finish_cmd(cbw, 0, CswStatus::Passed, work.len(), lun, devs);
                }
                if cbw.dir != BotDir::DataOut {
                    return self.finish_cmd(cbw, 0, CswStatus::PhaseError, work.len(), lun, devs);
                }
                // BOT §6.7.3 Case (13) Ho<Do: Ho < Do => PhaseError.
                if declared < expected {
                    return self.finish_cmd(cbw, 0, CswStatus::PhaseError, work.len(), lun, devs);
                }
                if declared != expected {
                    return self.finish_cmd(cbw, 0, CswStatus::Failed, work.len(), lun, devs);
                }
                let first_chunk = (expected as usize).min(work.len());
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
                Action::HostRecv {
                    len: first_chunk,
                    probe: false,
                }
            }
        }
    }

    /// Enter a Data-In phase for a response already synthesized into
    /// `work[0..available]` (REPORT LUNS, core-injected sense).
    fn synthesize_data_in<'a, D: ScsiDevice>(
        &'a mut self,
        cbw: &Cbw,
        work: &'a mut [u8],
        available: u64,
        devs: &'a mut [D],
    ) -> Action<'a> {
        let declared = u64::from(cbw.data_len);
        let lun = cbw.lun as usize;
        if declared == 0 && available > 0 {
            // BOT §6.7.1 Case (2) Hn<Di (synthesized REPORT LUNS/sense).
            return self.finish_cmd(cbw, 0, CswStatus::PhaseError, work.len(), lun, devs);
        }
        let actual = available.min(declared);
        if actual == 0 {
            return self.finish_cmd(cbw, 0, CswStatus::Passed, work.len(), lun, devs);
        }
        let mut chunk = (actual as usize).min(work.len());
        if chunk as u64 == actual {
            chunk += self.merge_pad_boundary(work, chunk, declared, actual);
        }
        self.state = BotState::DataIn {
            expected: declared,
            transfer_len: actual,
            sent: chunk as u64,
            tag: cbw.tag,
            lun: usize::from(cbw.lun),
            chunk,
        };
        Action::HostSend {
            bytes: &work[..chunk],
            prefetch: None,
        }
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

    /// Assemble the CSW into the internal buffer and enter the terminal-status
    /// agenda (which drains `next_store_op` before emitting the CSW).
    fn finish_csw_bot<'a, D: ScsiDevice>(
        &'a mut self,
        tag: u32,
        residue: u64,
        status: CswStatus,
        lun: usize,
        devs: &'a mut [D],
    ) -> Action<'a> {
        self.enter_agenda(tag, residue, status, lun, devs)
    }

    /// Plain shortfall ending: the short packet is already on the wire; report
    /// the shortfall via `dCSWDataResidue` and send the CSW (with a ZLP first
    /// when the produced length is an MPS multiple, so a full-MPS last packet
    /// is terminated). No padding, no STALL.
    fn finish_short_fall<'a, D: ScsiDevice>(
        &'a mut self,
        tag: u32,
        declared: u64,
        actual: u64,
        status: CswStatus,
        lun: usize,
        devs: &'a mut [D],
    ) -> Action<'a> {
        crate::debug!(
            "bot csw tag={} residue={} status={:?}",
            tag,
            declared - actual,
            status
        );
        if actual < declared && actual.is_multiple_of(self.bulk_mps) {
            self.store_csw(tag, declared - actual, status);
            self.state = BotState::CswZlp {
                tag,
                declared,
                actual,
                status,
                lun,
            };
            Action::HostSend {
                bytes: &[],
                prefetch: None,
            }
        } else {
            self.enter_agenda(tag, declared - actual, status, lun, devs)
        }
    }

    /// `ShortfallPolicy::Short` ending: the short packet is on the wire; when it
    /// was a full-MPS last packet, terminate it with a ZLP first. Then the phase
    /// STALLs Bulk-In (`DataInStall`); the shell sets the halt and feeds
    /// [`Event::StallApplied`], which drains the agenda and releases the
    /// withheld CSW.
    fn finish_short_stall<'a>(
        &'a mut self,
        tag: u32,
        declared: u64,
        actual: u64,
        status: CswStatus,
        lun: usize,
    ) -> Action<'a> {
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
                lun,
            };
            Action::HostSend {
                bytes: &[],
                prefetch: None,
            }
        } else {
            self.state = BotState::DataInStall {
                tag,
                declared,
                actual,
                status,
                lun,
            };
            Action::StallIn
        }
    }

    /// Zero-extend the final relevant Data-In chunk in `work` to the next
    /// bulk-MPS boundary under `ShortfallPolicy::Pad`, so the host never sees a
    /// premature short packet before the fill. Bounded by the fill budget
    /// (`declared − produced`, capped at [`MAX_PAD`]) and the remaining buffer;
    /// returns the number of fill bytes merged. A no-op for other policies or
    /// when there is no shortfall. Requires an MPS-aligned work buffer for the
    /// boundary to fit; callers degrade gracefully otherwise (see
    /// [`end_shortfall_data_in`]).
    fn merge_pad_boundary(
        &self,
        work: &mut [u8],
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
        let room = work.len().saturating_sub(chunk) as u64;
        let merge = boundary.min(budget).min(room) as usize;
        if merge > 0 {
            work[chunk..chunk + merge].fill(0);
        }
        merge
    }

    /// Pad a Data-In shortfall to `declared` (capped at [`MAX_PAD`]) or, once
    /// the cap/alignment forbids it, end `ShortNoStall`-style. `produced` is
    /// the relevant data sent; `wire` is the total already on the wire
    /// (relevant + any boundary-merged fill). Residue is `declared − produced`
    /// (the fill is *not* relevant data).
    #[allow(clippy::too_many_arguments)]
    fn end_shortfall_data_in<'a, D: ScsiDevice>(
        &'a mut self,
        tag: u32,
        declared: u64,
        produced: u64,
        wire: u64,
        status: CswStatus,
        lun: usize,
        devs: &'a mut [D],
    ) -> Action<'a> {
        let mps = self.bulk_mps.max(1);
        // A non-MPS-multiple wire length below `declared` means a short packet
        // already terminated the host's bulk-IN (e.g. a non-MPS-aligned work
        // buffer blocked the boundary merge); appending fill now would corrupt
        // the CSW. End ShortNoStall-style.
        if wire < declared && !wire.is_multiple_of(mps) {
            return self.finish_short_fall(tag, declared, produced, status, lun, devs);
        }
        let target = declared.min(produced + MAX_PAD);
        if wire >= target {
            return self.write_pad_csw(tag, declared, produced, wire, status, lun, devs);
        }
        let chunk = ((target - wire) as usize).min(ZERO_CHUNK.len());
        self.state = BotState::DataInPad {
            tag,
            declared,
            produced,
            wire,
            status,
            lun,
            chunk,
        };
        Action::HostSend {
            bytes: &ZERO_CHUNK[..chunk],
            prefetch: None,
        }
    }

    /// Send the CSW after a completed `Pad` fill. A fully-filled phase
    /// (`wire == declared`) sends the CSW directly; a cap-exhausted phase
    /// (`wire < declared`) ends like `ShortNoStall` — with a ZLP first when the
    /// wire length is an MPS multiple, no STALL.
    #[allow(clippy::too_many_arguments)]
    fn write_pad_csw<'a, D: ScsiDevice>(
        &'a mut self,
        tag: u32,
        declared: u64,
        produced: u64,
        wire: u64,
        status: CswStatus,
        lun: usize,
        devs: &'a mut [D],
    ) -> Action<'a> {
        crate::debug!(
            "bot csw (pad) tag={} residue={} wire={} status={:?}",
            tag,
            declared - produced,
            wire,
            status
        );
        if wire < declared && wire.is_multiple_of(self.bulk_mps) {
            self.store_csw(tag, declared - produced, status);
            self.state = BotState::CswZlp {
                tag,
                declared,
                actual: produced,
                status,
                lun,
            };
            Action::HostSend {
                bytes: &[],
                prefetch: None,
            }
        } else {
            self.enter_agenda(tag, declared - produced, status, lun, devs)
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
    fn finish_data_in<'a, D: ScsiDevice>(
        &'a mut self,
        tag: u32,
        declared: u64,
        actual: u64,
        status: CswStatus,
        lun: usize,
        devs: &'a mut [D],
    ) -> Action<'a> {
        let actual = actual.min(declared);
        if actual < declared {
            return match self.shortfall {
                ShortfallPolicy::Pad => {
                    self.end_shortfall_data_in(tag, declared, actual, actual, status, lun, devs)
                }
                ShortfallPolicy::Short => {
                    self.finish_short_stall(tag, declared, actual, status, lun)
                }
                ShortfallPolicy::ShortNoStall => {
                    self.finish_short_fall(tag, declared, actual, status, lun, devs)
                }
            };
        }
        self.finish_short_fall(tag, declared, actual, status, lun, devs)
    }

    /// End a transaction, first resolving the data phase the CBW declared
    /// (§6.7). `actual` is the number of Data-In bytes produced. A declared
    /// Data-Out phase is drained instead of left in the bulk-OUT fifo (the
    /// host will send `declared` bytes regardless of the outcome).
    fn finish_cmd<'a, D: ScsiDevice>(
        &'a mut self,
        cbw: &Cbw,
        actual: u64,
        status: CswStatus,
        work_len: usize,
        lun: usize,
        devs: &'a mut [D],
    ) -> Action<'a> {
        let declared = u64::from(cbw.data_len);
        if declared > 0 && cbw.dir == BotDir::DataOut {
            return self.start_data_out_drain(cbw, status, work_len, lun);
        }
        self.finish_data_in(cbw.tag, declared, actual, status, lun, devs)
    }

    /// Enter a Data-Out phase that writes nothing: receive and discard the
    /// host's `declared` bytes so the next CBW is not corrupted (§3.8),
    /// then send the CSW with `status`.
    fn start_data_out_drain<'a>(
        &'a mut self,
        cbw: &Cbw,
        status: CswStatus,
        work_len: usize,
        lun: usize,
    ) -> Action<'a> {
        let declared = u64::from(cbw.data_len);
        let chunk = (declared as usize).min(work_len);
        self.state = BotState::DataOut {
            declared,
            to_write: 0,
            received: 0,
            written: 0,
            tag: cbw.tag,
            lun,
            status,
            chunk,
        };
        Action::HostRecv {
            len: chunk,
            probe: false,
        }
    }

    // ── Data-In phase ───────────────────────────────────────────────

    fn poll_data_in<'a, D: ScsiDevice>(
        &'a mut self,
        ev: Event,
        work: &'a mut [u8],
        devs: &'a mut [D],
    ) -> Action<'a> {
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
            return Action::Error(BotTargetError::Internal);
        };
        match ev {
            Event::HostSent => {
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
                            lun,
                            devs,
                        );
                    }
                    return self.finish_data_in(
                        tag,
                        expected,
                        transfer_len,
                        CswStatus::Passed,
                        lun,
                        devs,
                    );
                }
                let remaining = transfer_len - sent;
                let mut next = (remaining as usize).min(work.len());
                // See the `OutXfer` arm of `dispatch_cbw`: extract the op's
                // Copy fields before re-borrowing `work` for the `Inline` send.
                let probe = match devs[lun].xfer_out(sent, &mut work[..next]) {
                    Xfer::Inline { len } => Ok(len),
                    Xfer::Store(op) => match StoreDesc::of(op) {
                        Some(desc) => Err(desc),
                        None => return Action::Error(BotTargetError::Internal),
                    },
                };
                let produced = match probe {
                    Ok(len) => len,
                    Err(desc) => {
                        self.state = BotState::DataInStore {
                            expected,
                            transfer_len,
                            sent,
                            tag,
                            lun,
                            chunk: next,
                        };
                        return Action::Store {
                            lun,
                            op: desc.attach(&mut work[..next]),
                        };
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
                            lun,
                            devs,
                        );
                    }
                    return self.finish_data_in(tag, expected, sent, CswStatus::Failed, lun, devs);
                }
                if next as u64 == remaining {
                    // Final relevant chunk: boundary-merge Pad fill in-buffer so
                    // the host never sees a premature short packet.
                    next += self.merge_pad_boundary(work, next, expected, transfer_len);
                }
                self.state = BotState::DataIn {
                    expected,
                    transfer_len,
                    sent: sent + next as u64,
                    tag,
                    lun,
                    chunk: next,
                };
                Action::HostSend {
                    bytes: &work[..next],
                    prefetch: None,
                }
            }
            Event::HostRecv { .. } | Event::HostIdle => {
                // No-op: still need to send the pending chunk.
                Action::HostSend {
                    bytes: &work[..chunk],
                    prefetch: None,
                }
            }
            _ => Action::Error(BotTargetError::Internal),
        }
    }

    /// Finalize a Data-In chunk whose storage op finished (`Xfer::Store`).
    ///
    /// On success the chunk is sent exactly like the `Inline` path (including
    /// the `Pad` boundary merge on the final relevant chunk); on failure the
    /// data phase is terminated with the same residue/CSW path as the old
    /// `produced != chunk` shortfall.
    fn poll_data_in_store<'a, D: ScsiDevice>(
        &'a mut self,
        ev: Event,
        work: &'a mut [u8],
        devs: &'a mut [D],
    ) -> Action<'a> {
        let st = self.state;
        let BotState::DataInStore {
            expected,
            transfer_len,
            sent,
            tag,
            lun,
            chunk,
        } = st
        else {
            return Action::Error(BotTargetError::Internal);
        };
        match ev {
            Event::StoreDone { result } => {
                if store_done_failed(devs, lun, result) {
                    return self.finish_data_in(tag, expected, sent, CswStatus::Failed, lun, devs);
                }
                let remaining = transfer_len - sent;
                let mut next = chunk;
                if next as u64 == remaining {
                    // Final relevant chunk: boundary-merge Pad fill in-buffer
                    // so the host never sees a premature short packet.
                    next += self.merge_pad_boundary(work, next, expected, transfer_len);
                }
                self.state = BotState::DataIn {
                    expected,
                    transfer_len,
                    sent: sent + next as u64,
                    tag,
                    lun,
                    chunk: next,
                };
                Action::HostSend {
                    bytes: &work[..next],
                    prefetch: None,
                }
            }
            _ => Action::Error(BotTargetError::Internal),
        }
    }

    // ── Data-In pad (ShortfallPolicy::Pad) ──────────────────────────

    fn poll_data_in_pad<'a, D: ScsiDevice>(
        &'a mut self,
        ev: Event,
        devs: &'a mut [D],
    ) -> Action<'a> {
        let st = self.state;
        let BotState::DataInPad {
            tag,
            declared,
            produced,
            wire,
            status,
            lun,
            chunk,
        } = st
        else {
            return Action::Error(BotTargetError::Internal);
        };
        match ev {
            Event::HostSent => {
                let wire = wire + chunk as u64;
                let target = declared.min(produced + MAX_PAD);
                if wire >= target {
                    return self.write_pad_csw(tag, declared, produced, wire, status, lun, devs);
                }
                let next = ((target - wire) as usize).min(ZERO_CHUNK.len());
                self.state = BotState::DataInPad {
                    tag,
                    declared,
                    produced,
                    wire,
                    status,
                    lun,
                    chunk: next,
                };
                Action::HostSend {
                    bytes: &ZERO_CHUNK[..next],
                    prefetch: None,
                }
            }
            Event::HostRecv { .. } | Event::HostIdle => {
                // No-op: still need to send the pending fill chunk.
                Action::HostSend {
                    bytes: &ZERO_CHUNK[..chunk],
                    prefetch: None,
                }
            }
            _ => Action::Error(BotTargetError::Internal),
        }
    }

    // ── Data-In stall (ShortfallPolicy::Short) ──────────────────────

    /// Transient stall state: the shortfall's short packet (and any ZLP) is on
    /// the wire and the shell is about to STALL Bulk-In. Bulk events are
    /// ignored (the endpoint is halted, so none should arrive); `pending()`
    /// keeps returning [`Action::StallIn`] until the shell feeds
    /// [`Event::StallApplied`], which releases the CSW. A shell whose
    /// `BotIo::stall_in` fails feeds [`Event::Reset`].
    fn poll_data_in_stall<'a>(&'a mut self, _ev: Event) -> Action<'a> {
        Action::StallIn
    }

    // ── Data-Out phase ──────────────────────────────────────────────

    fn poll_data_out<'a, D: ScsiDevice>(
        &'a mut self,
        ev: Event,
        work: &'a mut [u8],
        devs: &'a mut [D],
    ) -> Action<'a> {
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
            return Action::Error(BotTargetError::Internal);
        };
        match ev {
            Event::HostRecv { len } => {
                let mut written = written;
                let mut status = status;
                if status == CswStatus::Passed && written < to_write {
                    let w = (len as u64).min(to_write - written) as usize;
                    if w > 0 {
                        // Detach the op's Copy fields before re-borrowing `devs`
                        // for the terminal-status agenda (see [`StoreDesc`]).
                        let probe = match devs[lun].xfer_in(written, &work[..w]) {
                            Xfer::Inline { len } => Ok(len),
                            Xfer::Store(op) => match StoreDesc::of(op) {
                                Some(desc) => Err(desc),
                                None => return Action::Error(BotTargetError::Internal),
                            },
                        };
                        let produced = match probe {
                            Ok(len) => len,
                            Err(desc) => {
                                self.state = BotState::DataOutStore {
                                    declared,
                                    to_write,
                                    received,
                                    written,
                                    tag,
                                    lun,
                                    status,
                                    got: len,
                                    w,
                                };
                                return Action::Store {
                                    lun,
                                    op: desc.attach(&mut work[..w]),
                                };
                            }
                        };
                        if produced == w {
                            written += produced as u64;
                        } else {
                            status = CswStatus::Failed;
                        }
                    }
                }
                let received = received + len as u64;
                if received >= declared {
                    let residue = declared - written;
                    if received > declared {
                        // Overshoot already consumed the excess: straight to CSW.
                        return self.finish_csw_bot(tag, residue, status, lun, devs);
                    }
                    // Exact end of the declared phase: probe for a host
                    // overrun (leftover bytes would corrupt the next CBW).
                    self.state = BotState::DataOutOverrun {
                        tag,
                        residue,
                        status,
                        lun,
                        chunk: work.len(),
                    };
                    return Action::HostRecv {
                        len: work.len(),
                        probe: true,
                    };
                }
                let next = ((declared - received) as usize).min(work.len());
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
                Action::HostRecv {
                    len: next,
                    probe: false,
                }
            }
            Event::HostIdle => {
                // Host paused mid phase: keep waiting for the chunk.
                Action::HostRecv {
                    len: chunk,
                    probe: false,
                }
            }
            _ => Action::Error(BotTargetError::Internal),
        }
    }

    /// Continue a Data-Out phase after its storage op finished
    /// (`Xfer::Store`). On success `written` advances by the handed-to-
    /// `xfer_in` count `w`; on failure `status` becomes `Failed`. The received
    /// bookkeeping then proceeds exactly like the `Inline` path (overrun probe
    /// or the next receive).
    fn poll_data_out_store<'a, D: ScsiDevice>(
        &'a mut self,
        ev: Event,
        work: &'a mut [u8],
        devs: &'a mut [D],
    ) -> Action<'a> {
        let st = self.state;
        let BotState::DataOutStore {
            declared,
            to_write,
            received,
            written,
            tag,
            lun,
            status,
            got,
            w,
        } = st
        else {
            return Action::Error(BotTargetError::Internal);
        };
        match ev {
            Event::StoreDone { result } => {
                let mut written = written;
                let mut status = status;
                if store_done_failed(devs, lun, result) {
                    status = CswStatus::Failed;
                } else {
                    written += w as u64;
                }
                let received = received + got as u64;
                if received >= declared {
                    let residue = declared - written;
                    if received > declared {
                        // Overshoot already consumed the excess: straight to CSW.
                        return self.finish_csw_bot(tag, residue, status, lun, devs);
                    }
                    // Exact end of the declared phase: probe for a host
                    // overrun (leftover bytes would corrupt the next CBW).
                    self.state = BotState::DataOutOverrun {
                        tag,
                        residue,
                        status,
                        lun,
                        chunk: work.len(),
                    };
                    return Action::HostRecv {
                        len: work.len(),
                        probe: true,
                    };
                }
                let next = ((declared - received) as usize).min(work.len());
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
                Action::HostRecv {
                    len: next,
                    probe: false,
                }
            }
            _ => Action::Error(BotTargetError::Internal),
        }
    }

    // ── Parameter-list Data-Out ─────────────────────────────────────

    fn poll_param_out<'a, D: ScsiDevice>(
        &'a mut self,
        ev: Event,
        work: &'a mut [u8],
        devs: &'a mut [D],
    ) -> Action<'a> {
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
            return Action::Error(BotTargetError::Internal);
        };
        match ev {
            Event::HostRecv { len: n } => {
                let remaining = expected - received;
                let base = work.len() - expected as usize;
                if n as u64 > remaining {
                    // Host overran declared length: keep the first `remaining`
                    // bytes, complete the parameter list, then drain the rest.
                    let fit = remaining as usize;
                    if fit > 0 {
                        let dst = work.len() - received as usize - fit;
                        work.copy_within(0..fit, dst);
                    }
                    let status = match devs[lun]
                        .complete_param(&cdb[..cdb_len], &work[base..base + expected as usize])
                    {
                        CommandOutcome::Status | CommandOutcome::StatusWithSense => {
                            CswStatus::Passed
                        }
                        _ => CswStatus::Failed,
                    };
                    self.state = BotState::DataOutOverrun {
                        tag,
                        residue: 0,
                        status,
                        lun,
                        chunk: work.len(),
                    };
                    return Action::HostRecv {
                        len: work.len(),
                        probe: true,
                    };
                }
                // Normal case: move the received bytes to the tail so they sit
                // contiguously after the already-accumulated bytes.
                let dst = work.len() - received as usize - n;
                work.copy_within(0..n, dst);
                let received = received + n as u64;
                if received >= expected {
                    let status = match devs[lun]
                        .complete_param(&cdb[..cdb_len], &work[base..base + expected as usize])
                    {
                        CommandOutcome::Status | CommandOutcome::StatusWithSense => {
                            CswStatus::Passed
                        }
                        _ => CswStatus::Failed,
                    };
                    // Exact end: probe for host overrun before CSW.
                    self.state = BotState::DataOutOverrun {
                        tag,
                        residue: 0,
                        status,
                        lun,
                        chunk: work.len(),
                    };
                    return Action::HostRecv {
                        len: work.len(),
                        probe: true,
                    };
                }
                let next = ((expected - received) as usize).min(work.len() - received as usize);
                self.state = BotState::ParamOut {
                    expected,
                    received,
                    tag,
                    lun,
                    cdb,
                    cdb_len,
                    chunk: next,
                };
                Action::HostRecv {
                    len: next,
                    probe: false,
                }
            }
            Event::HostIdle => Action::HostRecv {
                len: chunk,
                probe: false,
            },
            _ => Action::Error(BotTargetError::Internal),
        }
    }

    // ── Data-Out overrun drain ──────────────────────────────────────

    fn poll_overrun<'a, D: ScsiDevice>(&'a mut self, ev: Event, devs: &'a mut [D]) -> Action<'a> {
        let st = self.state;
        let BotState::DataOutOverrun {
            tag,
            residue,
            status,
            lun,
            chunk,
        } = st
        else {
            return Action::Error(BotTargetError::Internal);
        };
        match ev {
            Event::HostRecv { len } => {
                if len < chunk {
                    // Short packet: leftover drained → CSW.
                    return self.finish_csw_bot(tag, residue, status, lun, devs);
                }
                // Full chunk: more leftover pending.
                self.state = BotState::DataOutOverrun {
                    tag,
                    residue,
                    status,
                    lun,
                    chunk,
                };
                Action::HostRecv {
                    len: chunk,
                    probe: true,
                }
            }
            Event::HostIdle => self.finish_csw_bot(tag, residue, status, lun, devs),
            _ => Action::Error(BotTargetError::Internal),
        }
    }

    // ── CSW phase ───────────────────────────────────────────────────

    fn poll_csw<'a>(&'a mut self, ev: Event) -> Action<'a> {
        match ev {
            Event::HostSent => {
                // Normal ending: no "done" boundary — hand back the next
                // command-phase receive directly.
                self.state = BotState::Command { got: 0 };
                Action::HostRecv {
                    len: CBW_LEN,
                    probe: false,
                }
            }
            Event::HostRecv { .. } | Event::HostIdle => Action::HostSend {
                bytes: &self.csw[..],
                prefetch: None,
            },
            _ => Action::Error(BotTargetError::Internal),
        }
    }

    /// The zero-length packet that terminates a short Data-In phase has been
    /// sent; under `ShortfallPolicy::Short` the phase then STALLs (`DataInStall`)
    /// instead of sending the CSW immediately. Otherwise the data phase is
    /// complete and the device agenda is drained before the CSW.
    fn poll_csw_zlp<'a, D: ScsiDevice>(&'a mut self, ev: Event, devs: &'a mut [D]) -> Action<'a> {
        let st = self.state;
        let BotState::CswZlp {
            tag,
            declared,
            actual,
            status,
            lun,
        } = st
        else {
            return Action::Error(BotTargetError::Internal);
        };
        match ev {
            Event::HostSent => {
                if self.shortfall == ShortfallPolicy::Short && actual < declared {
                    self.state = BotState::DataInStall {
                        tag,
                        declared,
                        actual,
                        status,
                        lun,
                    };
                    Action::StallIn
                } else {
                    self.enter_agenda(tag, declared - actual, status, lun, devs)
                }
            }
            Event::HostRecv { .. } | Event::HostIdle => Action::HostSend {
                bytes: &[],
                prefetch: None,
            },
            _ => Action::Error(BotTargetError::Internal),
        }
    }
}

/// A byte-addressed [`StoreOp`] with its buffer detached, used to survive the
/// borrow of `work` that `xfer_out` takes while the session still needs `work`
/// on the `Inline` branch.
///
/// By contract the op returned by the device carries exactly the slice the
/// session passed (`&mut work[..chunk]`), so it can be split into its Copy
/// fields and the buffer and then rebuilt identically once the call's borrow
/// has ended. This is the classic NLL "conditional borrow" workaround:
/// returning the op directly would force the call's mutable borrow of `work`
/// to live for the whole function, so the `Inline` branch could not re-borrow
/// `work`. The reconstructed op is byte-identical, so the Store stays
/// invisible on the wire.
///
/// Only the byte-addressed variants appear here: the data phase is
/// byte-addressed (`BlockDevice::xfer_out`/`xfer_in`), while path-addressed FS
/// ops are produced by the device agenda (`next_store_op`), never by the data
/// phase. A path-addressed op in the data phase is a contract violation and is
/// reported as [`BotTargetError::Internal`] (it also cannot be detached here —
/// its `path` borrows the device for the same lifetime as the buffer).
#[derive(Clone, Copy)]
enum StoreDesc {
    Read { off: u64 },
    Write { off: u64 },
    Fill { off: u64, len: u64, byte: u8 },
    Sync,
}

impl StoreDesc {
    /// Split a byte-addressed `op` into its Copy fields, dropping the buffer
    /// borrow. `None` for a path-addressed (FS) op (see the type docs).
    fn of(op: StoreOp<'_>) -> Option<Self> {
        match op {
            StoreOp::Read { off, .. } => Some(Self::Read { off }),
            StoreOp::Write { off, .. } => Some(Self::Write { off }),
            StoreOp::Fill { off, len, byte } => Some(Self::Fill { off, len, byte }),
            StoreOp::Sync => Some(Self::Sync),
            StoreOp::FileRead { .. } | StoreOp::FileWrite { .. } | StoreOp::FileRemove { .. } => {
                None
            }
        }
    }

    /// Re-attach `buf` — the same slice the device received — to rebuild the op.
    fn attach<'b>(self, buf: &'b mut [u8]) -> StoreOp<'b> {
        match self {
            Self::Read { off } => StoreOp::Read { off, buf },
            Self::Write { off } => StoreOp::Write { off, buf },
            Self::Fill { off, len, byte } => StoreOp::Fill { off, len, byte },
            Self::Sync => StoreOp::Sync,
        }
    }
}

/// Feed a finished storage op to `devs[lun].store_done` and report whether the
/// data phase must fail.
///
/// [`ScsiDevice::store_done`]'s default maps a [`StorageError`] to sense (so a
/// left sense means failure); a recovering override leaves no sense and the
/// phase continues. [`XferOutcome::Error`] means the device declined to take
/// over the mapping, so the session applies it via
/// [`sense_for_storage_error`].
fn store_done_failed<D: ScsiDevice>(
    devs: &mut [D],
    lun: usize,
    result: Result<(), StorageError>,
) -> bool {
    match devs[lun].store_done(result) {
        XferOutcome::Ok => result.is_err() && devs[lun].peek_sense().is_some(),
        XferOutcome::Error(e) => {
            let (key, asc, ascq) = sense_for_storage_error(e);
            devs[lun].set_sense(Sense::new(key, asc, ascq));
            true
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
    use crate::scsi::backend::RamBackend;
    use crate::scsi::block::BlockDevice;
    use crate::scsi::device::{DeviceType, Error};
    use crate::usb::{BotIo, BotIoErr, CBW_SIGNATURE};
    use core::cell::RefCell;
    use core::time::Duration;
    use std::collections::VecDeque;

    /// A 64 KiB block device over test-owned RAM.
    ///
    /// The built-in [`BlockDevice`] hands the platform a [`StoreOp`] and holds
    /// no plane, so a plane-less device cannot read/write its own RAM. These
    /// session tests exercise the **wire** (chunk lengths, CSW residue, ZLP,
    /// shortfall policy), which is independent of whether the device yields
    /// `Inline` or `Store`; the `Store` path itself is covered end-to-end by
    /// the `snowscsi-tests` golden fixtures through `usb::serve`. So the test
    /// LUN executes the built-in block op **inline** against its RAM and
    /// reports `Inline`, keeping every session-level assertion unchanged.
    struct TestLun<'r> {
        inner: BlockDevice,
        ram: &'r mut [u8],
    }

    impl ScsiDevice for TestLun<'_> {
        fn do_cmd(&mut self, cdb: &[u8], data: &mut [u8]) -> Result<CommandOutcome, Error> {
            self.inner.do_cmd(cdb, data)
        }

        fn xfer_out<'a>(&'a mut self, transfer_offset: u64, buf: &'a mut [u8]) -> Xfer<'a> {
            match self.inner.xfer_out(transfer_offset, buf) {
                Xfer::Store(StoreOp::Read { off, buf: b }) => {
                    let off = off as usize;
                    b.copy_from_slice(&self.ram[off..off + b.len()]);
                    Xfer::Inline { len: b.len() }
                }
                other => other,
            }
        }

        fn xfer_in<'a>(&'a mut self, transfer_offset: u64, buf: &'a [u8]) -> Xfer<'a> {
            match self.inner.xfer_in(transfer_offset, buf) {
                Xfer::Store(StoreOp::Write { off, buf: b }) => {
                    let off = off as usize;
                    self.ram[off..off + b.len()].copy_from_slice(b);
                    Xfer::Inline { len: b.len() }
                }
                other => other,
            }
        }

        fn peek_sense(&self) -> Option<&Sense> {
            self.inner.peek_sense()
        }

        fn take_sense(&mut self) -> Option<Sense> {
            self.inner.take_sense()
        }

        fn device_type(&self) -> DeviceType {
            self.inner.device_type()
        }

        fn complete_param(&mut self, cdb: &[u8], data: &[u8]) -> CommandOutcome {
            self.inner.complete_param(cdb, data)
        }

        fn sync(&mut self) -> Result<(), StorageError> {
            self.inner.sync()
        }

        fn inject_unit_attention(&mut self, asc: u8, ascq: u8) {
            self.inner.inject_unit_attention(asc, ascq);
        }

        fn set_sense(&mut self, sense: Sense) {
            ScsiDevice::set_sense(&mut self.inner, sense);
        }
    }

    /// A 64 KiB block device over stack-owned RAM.
    fn test_dev(ram: &mut [u8]) -> TestLun<'_> {
        let inner = BlockDevice::disk(&mut RamBackend::new(ram), 512).unwrap();
        TestLun { inner, ram }
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

    /// Feed host bytes into `work` and poll a `HostRecv` of that length.
    fn recv<'a, D: ScsiDevice>(
        s: &'a mut BotSession,
        work: &'a mut [u8],
        devs: &'a mut [D],
        bytes: &[u8],
    ) -> Action<'a> {
        work[..bytes.len()].copy_from_slice(bytes);
        s.poll(Event::HostRecv { len: bytes.len() }, work, devs)
    }

    /// Poll a `HostSent` (the pending bulk-IN packet has been sent).
    fn sent<'a, D: ScsiDevice>(
        s: &'a mut BotSession,
        work: &'a mut [u8],
        devs: &'a mut [D],
    ) -> Action<'a> {
        s.poll(Event::HostSent, work, devs)
    }

    /// Poll a `HostIdle` (the shell's receive found nothing).
    fn idle<'a, D: ScsiDevice>(
        s: &'a mut BotSession,
        work: &'a mut [u8],
        devs: &'a mut [D],
    ) -> Action<'a> {
        s.poll(Event::HostIdle, work, devs)
    }

    /// Poll an `Event::Reset` (BotReset / LinkReset).
    fn reset<'a, D: ScsiDevice>(
        s: &'a mut BotSession,
        work: &'a mut [u8],
        devs: &'a mut [D],
    ) -> Action<'a> {
        s.poll(Event::Reset, work, devs)
    }

    /// Assert the action is a receive of `len` bytes with the given `probe`.
    fn expect_recv(action: Action<'_>, len: usize, probe: bool) {
        match action {
            Action::HostRecv { len: l, probe: p } => {
                assert_eq!(l, len, "HostRecv len");
                assert_eq!(p, probe, "HostRecv probe");
            }
            other => panic!("expected HostRecv {{ len: {len}, probe: {probe} }}, got {other:?}"),
        }
    }

    /// Read the pending CSW from the session's internal buffer (via the
    /// private `pending()` re-emit).
    fn read_csw(s: &mut BotSession, work: &mut [u8]) -> (u32, u32, u8) {
        let csw = match s.pending(work) {
            Action::HostSend { bytes, .. } => bytes,
            other => panic!("expected a pending HostSend, got {other:?}"),
        };
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

    fn read_via_xfer(dev: &mut TestLun<'_>, lba: u64, buf: &mut [u8]) {
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
        let mut s = BotSession::new();
        let mut work = work();
        match s.pending(&mut work) {
            Action::HostRecv { len, probe } => {
                assert_eq!(len, 31);
                assert!(!probe);
            }
            other => panic!("expected HostRecv, got {other:?}"),
        }
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
        let mut work = work();

        let raw = raw_cbw(1, 96, 0x80, 0, &inquiry_cdb(96));
        let step = recv(&mut s, &mut work, &mut devs, &raw[..20]);
        expect_recv(step, 11, false);
        // The pending action re-emitted on Tick matches.
        expect_recv(s.poll(Event::Tick, &mut work, &mut devs), 11, false);

        let step = recv(&mut s, &mut work, &mut devs, &raw[20..]);
        match step {
            Action::HostSend { .. } => {}
            other => panic!("expected HostSend, got {other:?}"),
        }
    }

    #[test]
    fn inquiry_roundtrip_with_csw() {
        let mut ram = vec![0u8; 64 * 1024];
        let mut devs = [test_dev(&mut ram)];
        let mut s = BotSession::new();
        let mut work = work();

        let raw = raw_cbw(0xAAAA_AAAA, 96, 0x80, 0, &inquiry_cdb(96));
        let step = recv(&mut s, &mut work, &mut devs, &raw);
        match step {
            Action::HostSend { bytes, .. } => {
                assert_eq!(bytes.len(), 96);
                assert_eq!(bytes[0] & 0x1F, 0x00); // PDT = direct-access block
            }
            other => panic!("expected HostSend with INQUIRY data, got {other:?}"),
        }
        match s.poll(Event::Tick, &mut work, &mut devs) {
            Action::HostSend { bytes, .. } => assert_eq!(bytes.len(), 96),
            other => panic!("expected re-emitted INQUIRY data, got {other:?}"),
        }

        // Data sent → CSW pending (tag echo, Passed; residue 0: host
        // declared 96 and the INQUIRY response is 96 bytes).
        match sent(&mut s, &mut work, &mut devs) {
            Action::HostSend { bytes, .. } => assert_eq!(bytes.len(), CSW_LEN),
            other => panic!("expected CSW, got {other:?}"),
        }
        let (tag, residue, status) = read_csw(&mut s, &mut work);
        assert_eq!(tag, 0xAAAA_AAAA);
        assert_eq!(residue, 0);
        assert_eq!(status, 0x00);

        // CSW sent → back to Command (next CBW receive).
        expect_recv(sent(&mut s, &mut work, &mut devs), CBW_LEN, false);
    }

    #[test]
    fn read_10_chunks_across_work_buffer() {
        let mut ram = vec![0u8; 64 * 1024];
        for (i, b) in ram.iter_mut().enumerate() {
            *b = (i % 251) as u8;
        }
        let mut devs = [test_dev(&mut ram)];
        let mut s = BotSession::new();
        let mut work = work();

        // READ(10) LBA 0, 20 blocks → 10240 bytes (> one 8K chunk).
        let cdb = [0x28, 0, 0, 0, 0, 0, 0, 0, 20, 0];
        let raw = raw_cbw(0x1111, 10240, 0x80, 0, &cdb);
        match recv(&mut s, &mut work, &mut devs, &raw) {
            Action::HostSend { bytes, .. } => {
                assert_eq!(bytes.len(), 8192);
                assert_eq!(bytes[0], 0);
                assert_eq!(bytes[8191], (8191 % 251) as u8);
            }
            other => panic!("expected first chunk, got {other:?}"),
        }

        match sent(&mut s, &mut work, &mut devs) {
            Action::HostSend { bytes, .. } => {
                assert_eq!(bytes.len(), 2048);
                assert_eq!(bytes[0], (8192 % 251) as u8);
            }
            other => panic!("expected second chunk, got {other:?}"),
        }

        match sent(&mut s, &mut work, &mut devs) {
            Action::HostSend { bytes, .. } => assert_eq!(bytes.len(), CSW_LEN),
            other => panic!("expected CSW, got {other:?}"),
        }
        let (_, residue, status) = read_csw(&mut s, &mut work);
        assert_eq!(residue, 0);
        assert_eq!(status, 0x00);
        expect_recv(sent(&mut s, &mut work, &mut devs), CBW_LEN, false);
    }

    #[test]
    fn write_10_writes_received_data_and_probes_overrun() {
        let mut ram = vec![0u8; 64 * 1024];
        let mut devs = [test_dev(&mut ram)];
        let mut s = BotSession::new();
        let mut work = work();

        // WRITE(10) LBA 0, 1 block → 512 bytes.
        let cdb = [0x2A, 0, 0, 0, 0, 0, 0, 0, 1, 0];
        let raw = raw_cbw(0x2222, 512, 0x00, 0, &cdb);
        let step = recv(&mut s, &mut work, &mut devs, &raw);
        expect_recv(step, 512, false);
        expect_recv(s.poll(Event::Tick, &mut work, &mut devs), 512, false);

        // Feed the data chunk → declared phase complete → overrun probe.
        let payload: Vec<u8> = (0..512u16).map(|i| (i % 7) as u8).collect();
        let wlen = work.len();
        let step = recv(&mut s, &mut work, &mut devs, &payload);
        expect_recv(step, wlen, true);
        let mut check = [0u8; 512];
        read_via_xfer(&mut devs[0], 0, &mut check);
        assert_eq!(&check[..], payload.as_slice());

        // No more data → OutIdle ends the drain → CSW.
        match idle(&mut s, &mut work, &mut devs) {
            Action::HostSend { bytes, .. } => assert_eq!(bytes.len(), CSW_LEN),
            other => panic!("expected CSW, got {other:?}"),
        }
        let (tag, residue, status) = read_csw(&mut s, &mut work);
        assert_eq!(tag, 0x2222);
        assert_eq!(residue, 0);
        assert_eq!(status, 0x00);
        expect_recv(sent(&mut s, &mut work, &mut devs), CBW_LEN, false);
    }

    #[test]
    fn data_out_overrun_is_drained_to_short_packet() {
        let mut ram = vec![0u8; 64 * 1024];
        let mut devs = [test_dev(&mut ram)];
        let mut s = BotSession::new();
        let mut work = work();

        let cdb = [0x2A, 0, 0, 0, 0, 0, 0, 0, 1, 0];
        let raw = raw_cbw(0x3333, 512, 0x00, 0, &cdb);
        let step = recv(&mut s, &mut work, &mut devs, &raw);
        expect_recv(step, 512, false);

        let payload: Vec<u8> = vec![0x5A; 512];
        let wlen = work.len();
        let step = recv(&mut s, &mut work, &mut devs, &payload);
        expect_recv(step, wlen, true);

        // Host over-sent 100 extra bytes: drain (short packet) → CSW.
        let extra = vec![0x6B; 100];
        match recv(&mut s, &mut work, &mut devs, &extra) {
            Action::HostSend { bytes, .. } => assert_eq!(bytes.len(), CSW_LEN),
            other => panic!("expected CSW after drain, got {other:?}"),
        }
        // The excess was discarded, not written to the backend.
        let mut check = [0u8; 512];
        read_via_xfer(&mut devs[0], 0, &mut check);
        assert_eq!(&check[..], payload.as_slice());
        let mut tail = [0u8; 64];
        read_via_xfer(&mut devs[0], 1, &mut tail);
        assert!(tail.iter().all(|&b| b == 0));

        let (_, residue, status) = read_csw(&mut s, &mut work);
        assert_eq!(residue, 0);
        assert_eq!(status, 0x00);
    }

    #[test]
    fn phase_error_on_direction_mismatch() {
        let mut ram = vec![0u8; 64 * 1024];
        let mut devs = [test_dev(&mut ram)];
        let mut s = BotSession::new();
        let mut work = work();

        // READ(10) declared with Data-Out direction → the host will send
        // the declared bytes, so they are drained, then a Phase Error CSW.
        let cdb = [0x28, 0, 0, 0, 0, 0, 0, 0, 1, 0];
        let raw = raw_cbw(0x4444, 512, 0x00, 0, &cdb);
        let step = recv(&mut s, &mut work, &mut devs, &raw);
        expect_recv(step, 512, false);
        let payload = vec![0u8; 512];
        match recv(&mut s, &mut work, &mut devs, &payload) {
            Action::HostRecv { probe: true, .. } => {}
            other => panic!("expected overrun probe, got {other:?}"),
        }
        match idle(&mut s, &mut work, &mut devs) {
            Action::HostSend { bytes, .. } => assert_eq!(bytes.len(), CSW_LEN),
            other => panic!("expected CSW, got {other:?}"),
        }
        let (_, residue, status) = read_csw(&mut s, &mut work);
        assert_eq!(residue, 512);
        assert_eq!(status, 0x02); // Phase Error
    }

    #[test]
    fn zero_data_data_in_sends_zlp_then_csw() {
        let mut ram = vec![0u8; 64 * 1024];
        let mut devs = [test_dev(&mut ram)];
        let mut s = BotSession::new().with_shortfall(ShortfallPolicy::ShortNoStall);
        let mut work = work();

        // READ(10) at an out-of-range LBA → CHECK CONDITION, but the CBW
        // declared a 512-byte Data-In phase. The zero-byte phase must be
        // closed with a ZLP before the CSW (BOT §6.7 Case (4)/(5)).
        let cdb = [0x28, 0, 0, 0xFF, 0xFF, 0, 0, 0, 1, 0];
        let raw = raw_cbw(0x20, 512, 0x80, 0, &cdb);
        match recv(&mut s, &mut work, &mut devs, &raw) {
            Action::HostSend { bytes, .. } => assert!(bytes.is_empty()),
            other => panic!("expected empty ZLP, got {other:?}"),
        }
        match s.poll(Event::Tick, &mut work, &mut devs) {
            Action::HostSend { bytes, .. } => assert!(bytes.is_empty()),
            other => panic!("expected pending ZLP, got {other:?}"),
        }
        // ZLP sent → CSW pending (Failed, residue = declared = 512).
        match sent(&mut s, &mut work, &mut devs) {
            Action::HostSend { bytes, .. } => assert_eq!(bytes.len(), CSW_LEN),
            other => panic!("expected CSW, got {other:?}"),
        }
        let (tag, residue, status) = read_csw(&mut s, &mut work);
        assert_eq!(tag, 0x20);
        assert_eq!(residue, 512);
        assert_eq!(status, 0x01); // Failed
        expect_recv(sent(&mut s, &mut work, &mut devs), CBW_LEN, false);
    }

    #[test]
    fn mps_multiple_shortfall_sends_zlp_then_csw() {
        let mut ram = vec![0u8; 64 * 1024];
        let mut devs = [test_dev(&mut ram)];
        let mut s = BotSession::new().with_shortfall(ShortfallPolicy::ShortNoStall);
        let mut work = work();

        // READ(10) count 1 → 512 data bytes, while CBW declared 1024. The
        // shortfall is not padded: the phase ends with a short packet. 512 is
        // a multiple of the bulk MPS, so a ZLP must terminate the data phase
        // before the CSW (BOT §6.7 Case (4)/(5)).
        let cdb = [0x28, 0, 0, 0, 0, 0, 0, 0, 1, 0];
        let raw = raw_cbw(0x21, 1024, 0x80, 0, &cdb);
        match recv(&mut s, &mut work, &mut devs, &raw) {
            Action::HostSend { bytes, .. } => assert_eq!(bytes.len(), 512),
            other => panic!("expected 512-byte chunk, got {other:?}"),
        }
        // 512 bytes sent: 512 % MPS == 0 → an empty ZLP first.
        match sent(&mut s, &mut work, &mut devs) {
            Action::HostSend { bytes, .. } => assert!(bytes.is_empty(), "expected ZLP"),
            other => panic!("expected ZLP, got {other:?}"),
        }
        // Then the CSW.
        match sent(&mut s, &mut work, &mut devs) {
            Action::HostSend { bytes, .. } => assert_eq!(bytes.len(), CSW_LEN),
            other => panic!("expected CSW, got {other:?}"),
        }
        let (tag, residue, status) = read_csw(&mut s, &mut work);
        assert_eq!(tag, 0x21);
        assert_eq!(residue, 1024 - 512);
        assert_eq!(status, 0x00); // Passed
        expect_recv(sent(&mut s, &mut work, &mut devs), CBW_LEN, false);
    }

    #[test]
    fn failed_data_out_drains_declared_then_csw() {
        let mut ram = vec![0u8; 64 * 1024];
        let mut devs = [test_dev(&mut ram)];
        let mut s = BotSession::new();
        let mut work = work();

        // WRITE(10) at an out-of-range LBA → CHECK CONDITION, but the CBW
        // declared a 512-byte Data-Out phase the host will still send. The
        // bytes must be drained so they cannot corrupt the next CBW.
        let cdb = [0x2A, 0, 0, 0xFF, 0xFF, 0, 0, 0, 1, 0];
        let raw = raw_cbw(0x22, 512, 0x00, 0, &cdb);
        let step = recv(&mut s, &mut work, &mut devs, &raw);
        expect_recv(step, 512, false);

        // The host's data-out arrives and is discarded (nothing written).
        let payload = vec![0xAA; 512];
        match recv(&mut s, &mut work, &mut devs, &payload) {
            Action::HostRecv { probe: true, .. } => {}
            other => panic!("expected overrun probe, got {other:?}"),
        }
        match idle(&mut s, &mut work, &mut devs) {
            Action::HostSend { bytes, .. } => assert_eq!(bytes.len(), CSW_LEN),
            other => panic!("expected CSW, got {other:?}"),
        }
        let (tag, residue, status) = read_csw(&mut s, &mut work);
        assert_eq!(tag, 0x22);
        assert_eq!(residue, 512); // nothing written
        assert_eq!(status, 0x01); // Failed
                                  // The backend was not written.
        let mut check = [0u8; 512];
        read_via_xfer(&mut devs[0], 0, &mut check);
        assert!(check.iter().all(|&b| b == 0));
    }

    #[test]
    fn invalid_cbw_stalls_and_recovers() {
        let mut ram = vec![0u8; 64 * 1024];
        let mut devs = [test_dev(&mut ram)];
        let mut s = BotSession::new();
        let mut work = work();

        // An invalid CBW STALLs both endpoints and returns to the Command
        // phase (no persistent Stalled state; a new CBW clears the halt).
        let mut bad = raw_cbw(1, 0, 0, 0, &[0x00, 0, 0, 0, 0, 0]);
        bad[0] = b'X'; // bad signature
        match recv(&mut s, &mut work, &mut devs, &bad) {
            Action::StallBoth => {}
            other => panic!("expected StallBoth, got {other:?}"),
        }
        // Back in Command: the next valid CBW is processed.
        let raw = raw_cbw(2, 96, 0x80, 0, &inquiry_cdb(96));
        match recv(&mut s, &mut work, &mut devs, &raw) {
            Action::HostSend { bytes, .. } => assert_eq!(bytes.len(), 96),
            other => panic!("expected INQUIRY data, got {other:?}"),
        }

        // A reset also returns to the Command phase.
        expect_recv(reset(&mut s, &mut work, &mut devs), CBW_LEN, false);
    }

    #[test]
    fn reset_interrupts_data_phase() {
        let mut ram = vec![0u8; 64 * 1024];
        let mut devs = [test_dev(&mut ram)];
        let mut s = BotSession::new();
        let mut work = work();

        let cdb = [0x2A, 0, 0, 0, 0, 0, 0, 0, 1, 0];
        let raw = raw_cbw(5, 512, 0x00, 0, &cdb);
        let step = recv(&mut s, &mut work, &mut devs, &raw);
        expect_recv(step, 512, false);

        // Partial data received.
        let part = vec![0xAA; 128];
        let step = recv(&mut s, &mut work, &mut devs, &part);
        expect_recv(step, 384, false);

        // Reset aborts the transaction and returns to Command.
        expect_recv(reset(&mut s, &mut work, &mut devs), CBW_LEN, false);

        // A new valid CBW is processed.
        let raw = raw_cbw(6, 96, 0x80, 0, &inquiry_cdb(96));
        match recv(&mut s, &mut work, &mut devs, &raw) {
            Action::HostSend { bytes, .. } => assert_eq!(bytes.len(), 96),
            other => panic!("expected INQUIRY data, got {other:?}"),
        }
    }

    #[test]
    fn invalid_lun_failed_csw_then_request_sense() {
        let mut ram = vec![0u8; 64 * 1024];
        let mut devs = [test_dev(&mut ram)];
        let mut s = BotSession::new();
        let mut work = work();

        // TEST UNIT READY to LUN 3 (only LUN 0 exists) → Failed CSW.
        let raw = raw_cbw(7, 0, 0, 3, &[0x00, 0, 0, 0, 0, 0]);
        match recv(&mut s, &mut work, &mut devs, &raw) {
            Action::HostSend { bytes, .. } => assert_eq!(bytes.len(), CSW_LEN),
            other => panic!("expected CSW, got {other:?}"),
        }
        let (tag, residue, status) = read_csw(&mut s, &mut work);
        assert_eq!(tag, 7);
        assert_eq!(residue, 0);
        assert_eq!(status, 0x01); // Failed
        expect_recv(sent(&mut s, &mut work, &mut devs), CBW_LEN, false);

        // REQUEST SENSE to the invalid LUN → LOGICAL UNIT NOT SUPPORTED.
        let mut rs = [0u8; 6];
        rs[0] = scsi_op::REQUEST_SENSE;
        rs[4] = 18;
        let raw = raw_cbw(8, 18, 0x80, 3, &rs);
        match recv(&mut s, &mut work, &mut devs, &raw) {
            Action::HostSend { bytes, .. } => {
                assert_eq!(bytes.len(), 18);
                assert_eq!(bytes[0], 0x70); // fixed format
                assert_eq!(bytes[2], 0x05); // ILLEGAL REQUEST
                assert_eq!(bytes[12], 0x25); // LOGICAL UNIT NOT SUPPORTED
            }
            other => panic!("expected sense data, got {other:?}"),
        }
        match sent(&mut s, &mut work, &mut devs) {
            Action::HostSend { bytes, .. } => assert_eq!(bytes.len(), CSW_LEN),
            other => panic!("expected CSW, got {other:?}"),
        }
        let (_, _, status) = read_csw(&mut s, &mut work);
        assert_eq!(status, 0x00); // Passed
    }

    #[test]
    fn unit_attention_after_reset() {
        let mut ram = vec![0u8; 64 * 1024];
        let mut devs = [test_dev(&mut ram)];
        let mut s = BotSession::new();
        let mut work = work();

        expect_recv(reset(&mut s, &mut work, &mut devs), CBW_LEN, false);

        // First TEST UNIT READY → CHECK CONDITION (UA), Failed CSW.
        let raw = raw_cbw(1, 0, 0, 0, &[0x00, 0, 0, 0, 0, 0]);
        match recv(&mut s, &mut work, &mut devs, &raw) {
            Action::HostSend { bytes, .. } => assert_eq!(bytes.len(), CSW_LEN),
            other => panic!("expected CSW, got {other:?}"),
        }
        let (_, _, status) = read_csw(&mut s, &mut work);
        assert_eq!(status, 0x01); // Failed
        expect_recv(sent(&mut s, &mut work, &mut devs), CBW_LEN, false);

        // REQUEST SENSE → the UA (0x29/00) is reported and cleared.
        let mut rs = [0u8; 6];
        rs[0] = scsi_op::REQUEST_SENSE;
        rs[4] = 18;
        let raw = raw_cbw(2, 18, 0x80, 0, &rs);
        match recv(&mut s, &mut work, &mut devs, &raw) {
            Action::HostSend { bytes, .. } => {
                assert_eq!(bytes[2], 0x06); // UNIT ATTENTION
                assert_eq!(bytes[12], 0x29);
                assert_eq!(bytes[13], 0x00);
            }
            other => panic!("expected UA sense, got {other:?}"),
        }
        match sent(&mut s, &mut work, &mut devs) {
            Action::HostSend { bytes, .. } => assert_eq!(bytes.len(), CSW_LEN),
            other => panic!("expected CSW, got {other:?}"),
        }
        expect_recv(sent(&mut s, &mut work, &mut devs), CBW_LEN, false);

        // Subsequent TEST UNIT READY → GOOD (Passed CSW).
        let raw = raw_cbw(3, 0, 0, 0, &[0x00, 0, 0, 0, 0, 0]);
        match recv(&mut s, &mut work, &mut devs, &raw) {
            Action::HostSend { bytes, .. } => assert_eq!(bytes.len(), CSW_LEN),
            other => panic!("expected CSW, got {other:?}"),
        }
        let (_, _, status) = read_csw(&mut s, &mut work);
        assert_eq!(status, 0x00); // Passed
    }

    #[test]
    fn report_luns_select_report_semantics() {
        let mut ram = vec![0u8; 64 * 1024];
        let mut devs = [test_dev(&mut ram)];
        let mut s = BotSession::new();
        let mut work = work();

        // 01h → empty inventory (no well-known logical units implemented).
        let raw = raw_cbw(21, 16, 0x80, 0, &[0xA0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 16]);
        let p1 = match recv(&mut s, &mut work, &mut devs, &raw) {
            Action::HostSend { bytes, .. } => bytes.to_vec(),
            other => panic!("expected REPORT LUNS data, got {other:?}"),
        };
        assert_eq!(u32::from_be_bytes([p1[0], p1[1], p1[2], p1[3]]), 0);
        match sent(&mut s, &mut work, &mut devs) {
            Action::HostSend { bytes, .. } => assert_eq!(bytes.len(), CSW_LEN),
            other => panic!("expected CSW, got {other:?}"),
        }
        let (_, _, st1) = read_csw(&mut s, &mut work);
        assert_eq!(st1, 0x00);
        expect_recv(sent(&mut s, &mut work, &mut devs), CBW_LEN, false);

        // 02h → full inventory (same as 00h for peripheral-only arrays).
        let raw = raw_cbw(22, 16, 0x80, 0, &[0xA0, 0, 2, 0, 0, 0, 0, 0, 0, 0, 0, 16]);
        let p2 = match recv(&mut s, &mut work, &mut devs, &raw) {
            Action::HostSend { bytes, .. } => bytes.to_vec(),
            other => panic!("expected REPORT LUNS data, got {other:?}"),
        };
        assert_eq!(u32::from_be_bytes([p2[0], p2[1], p2[2], p2[3]]), 8);
        assert_eq!(p2[8], 0x00); // address method 00b
        assert_eq!(p2[9], 0x00); // LUN 0
        match sent(&mut s, &mut work, &mut devs) {
            Action::HostSend { bytes, .. } => assert_eq!(bytes.len(), CSW_LEN),
            other => panic!("expected CSW, got {other:?}"),
        }
        let (_, _, st2) = read_csw(&mut s, &mut work);
        assert_eq!(st2, 0x00);
        expect_recv(sent(&mut s, &mut work, &mut devs), CBW_LEN, false);

        // 03h (reserved) → Failed CSW; 05/24 sense stored on the device.
        // actual=0 < declared=16 → ZLP, then CSW (BOT §6.7.2 short packet).
        let raw = raw_cbw(23, 16, 0x80, 0, &[0xA0, 0, 3, 0, 0, 0, 0, 0, 0, 0, 0, 16]);
        match recv(&mut s, &mut work, &mut devs, &raw) {
            Action::HostSend { bytes, .. } => assert_eq!(bytes.len(), 0), // ZLP
            other => panic!("expected ZLP, got {other:?}"),
        }
        match sent(&mut s, &mut work, &mut devs) {
            Action::HostSend { bytes, .. } => assert_eq!(bytes.len(), CSW_LEN),
            other => panic!("expected CSW, got {other:?}"),
        }
        let (_, _, st3) = read_csw(&mut s, &mut work);
        assert_eq!(st3, 0x01); // Failed
        expect_recv(sent(&mut s, &mut work, &mut devs), CBW_LEN, false);

        // REQUEST SENSE → INVALID FIELD IN CDB (0x24).
        let mut rs = [0u8; 6];
        rs[0] = scsi_op::REQUEST_SENSE;
        rs[4] = 18;
        let raw = raw_cbw(24, 18, 0x80, 0, &rs);
        match recv(&mut s, &mut work, &mut devs, &raw) {
            Action::HostSend { bytes, .. } => assert_eq!(bytes[12], 0x24),
            other => panic!("expected sense data, got {other:?}"),
        }
    }

    #[test]
    fn report_luns_is_synthesized_for_any_lun() {
        let mut ram = vec![0u8; 64 * 1024];
        let mut devs = [test_dev(&mut ram)];
        let mut s = BotSession::new();
        let mut work = work();

        // REPORT LUNS, allocation 16, addressed to LUN 0.
        let cdb = [0xA0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 16];
        let raw = raw_cbw(9, 16, 0x80, 0, &cdb);
        match recv(&mut s, &mut work, &mut devs, &raw) {
            Action::HostSend { bytes, .. } => {
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
        let mut work = work();

        // INQUIRY data is 96 bytes, but the host declared 192.
        let raw = raw_cbw(10, 192, 0x80, 0, &inquiry_cdb(96));
        match recv(&mut s, &mut work, &mut devs, &raw) {
            Action::HostSend { bytes, .. } => assert_eq!(bytes.len(), 96),
            other => panic!("expected short INQUIRY packet, got {other:?}"),
        }
        match sent(&mut s, &mut work, &mut devs) {
            Action::HostSend { bytes, .. } => assert_eq!(bytes.len(), CSW_LEN),
            other => panic!("expected CSW, got {other:?}"),
        }
        let (_, residue, status) = read_csw(&mut s, &mut work);
        assert_eq!(residue, 192 - 96); // short packet + residue, no STALL
        assert_eq!(status, 0x00);
    }

    /// Scripted bulk driver for the local `drive_once` helper.
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

    /// Drive one transaction to completion over a scripted `BotIo` (the
    /// removed blocking `step` wrapper's replacement). Returns once the CSW
    /// has been sent and the core is back in the Command phase.
    fn drive_once<D: ScsiDevice>(
        s: &mut BotSession,
        io: &mut ScriptIo,
        work: &mut [u8],
        devs: &mut [D],
    ) {
        let mut csw_sent = false;
        let mut guard = 0usize;
        loop {
            guard += 1;
            assert!(guard < 4096, "drive_once stuck");
            match s.poll(Event::Tick, work, devs) {
                Action::HostRecv { len, probe } => {
                    if csw_sent && len == CBW_LEN {
                        return;
                    }
                    match io.try_recv_out(&mut work[..len]) {
                        Ok(n) => {
                            if n == 0 {
                                return;
                            }
                            let _ = s.poll(Event::HostRecv { len: n }, work, devs);
                        }
                        Err(BotIoErr::WouldBlock) => {
                            if probe {
                                let _ = s.poll(Event::HostIdle, work, devs);
                            } else {
                                return;
                            }
                        }
                        Err(_) => return,
                    }
                }
                Action::HostSend { bytes, .. } => {
                    let is_csw = bytes.len() == CSW_LEN && bytes.starts_with(b"USBS");
                    io.send_in(bytes).expect("bulk send");
                    let _ = s.poll(Event::HostSent, work, devs);
                    if is_csw {
                        csw_sent = true;
                    }
                }
                Action::StallBoth => {
                    let _ = io.stall_both();
                }
                Action::StallIn => {
                    io.stall_in().expect("stall_in");
                    let _ = s.poll(Event::StallApplied, work, devs);
                }
                Action::Error(e) => panic!("drive_once core error: {e:?}"),
                // `TestLun` executes the built-in block op inline, so the
                // session never yields a `Store` here (the `Store` path is
                // covered end-to-end by the `snowscsi-tests` golden fixtures).
                Action::Store { .. } => panic!("Store unreachable with the inline test LUN"),
            }
        }
    }

    #[test]
    fn drive_inquiry_to_completion() {
        let mut ram = vec![0u8; 64 * 1024];
        let mut devs = [test_dev(&mut ram)];
        let mut s = BotSession::new();
        let mut work = work();

        let raw = raw_cbw(0xCAFE, 96, 0x80, 0, &inquiry_cdb(96));
        let mut io = ScriptIo::new(&raw);
        drive_once(&mut s, &mut io, &mut work, &mut devs);

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
    fn drive_write_with_data_phase() {
        let mut ram = vec![0u8; 64 * 1024];
        let mut devs = [test_dev(&mut ram)];
        let mut s = BotSession::new();
        let mut work = work();

        let cdb = [0x2A, 0, 0, 0, 0, 0, 0, 0, 1, 0];
        let raw = raw_cbw(0xBEEF, 512, 0x00, 0, &cdb);
        let payload: Vec<u8> = (0..512u16).map(|i| (i % 3) as u8).collect();
        // Queue: CBW + data payload.
        let mut stream = Vec::with_capacity(31 + 512);
        stream.extend_from_slice(&raw);
        stream.extend_from_slice(&payload);

        let mut io = ScriptIo::new(&stream);
        drive_once(&mut s, &mut io, &mut work, &mut devs);
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
        let mut work = work();

        // READ(10) 1 block = 512 bytes; host declared 1024.
        let raw = raw_cbw(1, 1024, 0x80, 0, &read10(1));
        match recv(&mut s, &mut work, &mut devs, &raw) {
            Action::HostSend { bytes, .. } => assert_eq!(bytes.len(), 512),
            other => panic!("expected 512 relevant bytes, got {other:?}"),
        }
        // Fill zeros up to `declared`.
        match sent(&mut s, &mut work, &mut devs) {
            Action::HostSend { bytes, .. } => {
                assert_eq!(bytes.len(), 512);
                assert!(bytes.iter().all(|&b| b == 0), "fill must be zeros");
            }
            other => panic!("expected 512 fill bytes, got {other:?}"),
        }
        // Then the CSW; residue is the *relevant* shortfall, not 0.
        match sent(&mut s, &mut work, &mut devs) {
            Action::HostSend { bytes, .. } => assert_eq!(bytes.len(), CSW_LEN),
            other => panic!("expected CSW, got {other:?}"),
        }
        let (tag, residue, status) = read_csw(&mut s, &mut work);
        assert_eq!(tag, 1);
        assert_eq!(residue, 1024 - 512);
        assert_eq!(status, 0x00);
        expect_recv(sent(&mut s, &mut work, &mut devs), CBW_LEN, false);
    }

    #[test]
    fn pad_mps_multiple_shortfall_has_no_stray_trailer() {
        let mut ram = vec![0u8; 64 * 1024];
        let mut devs = [test_dev(&mut ram)];
        let mut s = BotSession::new().with_shortfall(ShortfallPolicy::Pad);
        let mut work = work();

        // READ(10) 2 blocks = 1024 bytes (2 MPS); host declared 2048.
        let raw = raw_cbw(2, 2048, 0x80, 0, &read10(2));
        match recv(&mut s, &mut work, &mut devs, &raw) {
            Action::HostSend { bytes, .. } => assert_eq!(bytes.len(), 1024),
            other => panic!("expected 1024 relevant bytes, got {other:?}"),
        }
        match sent(&mut s, &mut work, &mut devs) {
            Action::HostSend { bytes, .. } => assert_eq!(bytes.len(), 1024),
            other => panic!("expected 1024 fill bytes, got {other:?}"),
        }
        // Fully filled to declared → CSW directly (no ZLP/stray trailer).
        match sent(&mut s, &mut work, &mut devs) {
            Action::HostSend { bytes, .. } => assert_eq!(bytes.len(), CSW_LEN),
            other => panic!("expected CSW, got {other:?}"),
        }
        let (_, residue, status) = read_csw(&mut s, &mut work); // asserts CSW length
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
        let mut work = work();

        let raw = raw_cbw(3, 192, 0x80, 0, &inquiry_cdb(95));
        match recv(&mut s, &mut work, &mut devs, &raw) {
            Action::HostSend { bytes, .. } => {
                assert_eq!(bytes.len(), 192, "one transfer reaching declared");
                assert_eq!(bytes[0] & 0x1F, 0x00); // INQUIRY payload
                assert!(bytes[95..].iter().all(|&b| b == 0), "tail is fill");
            }
            other => panic!("expected a single 192-byte transfer, got {other:?}"),
        }
        match sent(&mut s, &mut work, &mut devs) {
            Action::HostSend { bytes, .. } => assert_eq!(bytes.len(), CSW_LEN),
            other => panic!("expected CSW, got {other:?}"),
        }
        let (_, residue, status) = read_csw(&mut s, &mut work);
        assert_eq!(residue, 192 - 95);
        assert_eq!(status, 0x00);
    }

    #[test]
    fn pad_cap_hit_ends_short_no_stall() {
        let mut ram = vec![0u8; 64 * 1024];
        let mut devs = [test_dev(&mut ram)];
        let mut s = BotSession::new().with_shortfall(ShortfallPolicy::Pad);
        let mut work = vec![0u8; 64 * 1024];

        // READ(10) 1 block (512 produced); declared far past produced + MAX_PAD.
        let declared = 512 + MAX_PAD as u32 + 512;
        let raw = raw_cbw(4, declared, 0x80, 0, &read10(1));
        let mut io = ScriptIo::new(&raw);
        drive_once(&mut s, &mut io, &mut work, &mut devs);

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
    fn drive_pad_to_declared() {
        let mut ram = vec![0u8; 64 * 1024];
        let mut devs = [test_dev(&mut ram)];
        let mut s = BotSession::new().with_shortfall(ShortfallPolicy::Pad);
        let mut work = work();

        let raw = raw_cbw(5, 1024, 0x80, 0, &read10(1));
        let mut io = ScriptIo::new(&raw);
        drive_once(&mut s, &mut io, &mut work, &mut devs);
        // 512 relevant + 512 fill + CSW.
        assert_eq!(io.sent.borrow().len(), 512 + 512 + CSW_LEN);
    }

    #[test]
    fn short_shortfall_zlp_stall_applied_then_csw() {
        let mut ram = vec![0u8; 64 * 1024];
        let mut devs = [test_dev(&mut ram)];
        let mut s = BotSession::new().with_shortfall(ShortfallPolicy::Short);
        let mut work = work();

        // READ 1 block (512, an MPS multiple) vs declared 1024.
        let raw = raw_cbw(6, 1024, 0x80, 0, &read10(1));
        match recv(&mut s, &mut work, &mut devs, &raw) {
            Action::HostSend { bytes, .. } => assert_eq!(bytes.len(), 512),
            other => panic!("expected 512 relevant bytes, got {other:?}"),
        }
        // 512 % MPS == 0 → a ZLP first.
        match sent(&mut s, &mut work, &mut devs) {
            Action::HostSend { bytes, .. } => assert!(bytes.is_empty()),
            other => panic!("expected ZLP, got {other:?}"),
        }
        match s.poll(Event::Tick, &mut work, &mut devs) {
            Action::HostSend { bytes, .. } => assert!(bytes.is_empty()),
            other => panic!("expected pending ZLP, got {other:?}"),
        }
        // Then the STALL.
        match sent(&mut s, &mut work, &mut devs) {
            Action::StallIn => {}
            other => panic!("expected StallIn, got {other:?}"),
        }
        match s.poll(Event::Tick, &mut work, &mut devs) {
            Action::StallIn => {}
            other => panic!("expected pending StallIn, got {other:?}"),
        }
        // Bulk events are ignored while stalled.
        match sent(&mut s, &mut work, &mut devs) {
            Action::StallIn => {}
            other => panic!("expected StallIn, got {other:?}"),
        }
        match recv(&mut s, &mut work, &mut devs, &[]) {
            Action::StallIn => {}
            other => panic!("expected StallIn, got {other:?}"),
        }
        // The shell releases the stall (no CLEAR_FEATURE event to wait for).
        match s.poll(Event::StallApplied, &mut work, &mut devs) {
            Action::HostSend { bytes, .. } => assert_eq!(bytes.len(), CSW_LEN),
            other => panic!("expected CSW, got {other:?}"),
        }
        let (tag, residue, status) = read_csw(&mut s, &mut work);
        assert_eq!(tag, 6);
        assert_eq!(residue, 1024 - 512);
        assert_eq!(status, 0x00);
    }

    #[test]
    fn short_non_mps_shortfall_stalls_without_zlp() {
        let mut ram = vec![0u8; 64 * 1024];
        let mut devs = [test_dev(&mut ram)];
        let mut s = BotSession::new().with_shortfall(ShortfallPolicy::Short);
        let mut work = work();

        let raw = raw_cbw(7, 192, 0x80, 0, &inquiry_cdb(95));
        match recv(&mut s, &mut work, &mut devs, &raw) {
            Action::HostSend { bytes, .. } => assert_eq!(bytes.len(), 95),
            other => panic!("expected 95 relevant bytes, got {other:?}"),
        }
        // 95 % MPS != 0: the short packet already terminated the read → STALL
        // directly, no ZLP.
        match sent(&mut s, &mut work, &mut devs) {
            Action::StallIn => {}
            other => panic!("expected StallIn, got {other:?}"),
        }
        let _ = s.poll(Event::StallApplied, &mut work, &mut devs);
        let (_, residue, status) = read_csw(&mut s, &mut work);
        assert_eq!(residue, 192 - 95);
        assert_eq!(status, 0x00);
    }

    #[test]
    fn short_bot_reset_in_data_in_stall_aborts() {
        let mut ram = vec![0u8; 64 * 1024];
        let mut devs = [test_dev(&mut ram)];
        let mut s = BotSession::new().with_shortfall(ShortfallPolicy::Short);
        let mut work = work();

        let raw = raw_cbw(8, 192, 0x80, 0, &inquiry_cdb(95));
        let _ = recv(&mut s, &mut work, &mut devs, &raw);
        match sent(&mut s, &mut work, &mut devs) {
            Action::StallIn => {}
            other => panic!("expected StallIn, got {other:?}"),
        }

        // Bot Reset aborts the transaction; the CSW is dropped.
        expect_recv(reset(&mut s, &mut work, &mut devs), CBW_LEN, false);
        // A later (stale) release is a no-op: no CSW is emitted.
        expect_recv(
            s.poll(Event::StallApplied, &mut work, &mut devs),
            CBW_LEN,
            false,
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
            let mut work = work();

            // INQUIRY alloc 96, declared 96: no shortfall.
            let raw = raw_cbw(10, 96, 0x80, 0, &inquiry_cdb(96));
            match recv(&mut s, &mut work, &mut devs, &raw) {
                Action::HostSend { bytes, .. } => assert_eq!(bytes.len(), 96),
                other => panic!("[{policy:?}] expected 96 bytes, got {other:?}"),
            }
            match sent(&mut s, &mut work, &mut devs) {
                Action::HostSend { bytes, .. } => assert_eq!(bytes.len(), CSW_LEN),
                other => panic!("[{policy:?}] expected CSW, got {other:?}"),
            }
            let (_, residue, status) = read_csw(&mut s, &mut work);
            assert_eq!(residue, 0, "[{policy:?}] exact transfer has no residue");
            assert_eq!(status, 0x00);
            expect_recv(sent(&mut s, &mut work, &mut devs), CBW_LEN, false);
        }
    }
}
