//! USB MSC Bulk-Only Transport session state machine.
//!
//! [`BotSession`] is a pure, non-blocking protocol state machine: it never
//! blocks and never touches platform I/O. A shell feeds one [`Event`] (an I/O
//! completion or a control-plane notification) per [`BotSession::poll`] call
//! and learns the next [`Action`]. The library shell [`crate::usb::serve()`]
//! owns the platform loop; the PC FunctionFS driver and embedded `select!`
//! drivers implement the same `Event`/`Action` contract.
//!
//! SCSI command execution is delegated to the core [`Target`]: the session
//! builds the [`CommandContext`] from the CBW, starts the command and drives it
//! one step per entry. Host data phases are implemented by this type as
//! [`HostTransport`]: the data-in stream is chunked onto the bulk-IN endpoint,
//! the data-out stream is received into the caller's bank, and the BOT
//! H-versus-D contract is enforced in [`HostTransport::publish`].
//!
//! Out-of-band control enters the core as events: Bulk-Only Reset and
//! LinkReset arrive as [`Event::Reset`], Get Max LUN is a pure getter
//! ([`BotSession::max_lun`]). There is no out-of-band state mutation.
//!
//! Response framing:
//! - CBW (31B) accumulates into an internal buffer; CSW (13B) is assembled in
//!   an internal buffer; the caller's `work` area holds only SCSI data.
//! - STALL is used for invalid CBWs (both pipes, [`Action::StallBoth`]) and,
//!   under [`ShortfallPolicy::Short`], for a Data-In shortfall (Bulk-In only,
//!   [`Action::StallIn`]).
//! - Data-Out host overrun is drained to a short packet so leftover bytes
//!   never corrupt the next CBW.
//! - A reset raises a BUS RESET unit attention on every LUN of the target.
//!
//! # Work-buffer contract
//!
//! `work` is the transport's data bank: it bounds one device data chunk (the
//! core streams a larger transfer in bank-sized chunks). The data-in wire
//! stream is additionally chunked at [`WIRE_CHUNK`] bytes independently of the
//! bank size. `scratch` is the resident long-operation bank and must hold at
//! least [`crate::MIN_DATA_LEN`] bytes.
//!
//! # Data-In shortfall policy ([`ShortfallPolicy`])
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

use core::task::Poll;

use crate::core::storage::{HostBuf, HostReceipt, HostReq, HostToken, HostTransport, Storage};
use crate::core::{
    CommandContext, Completion, Control, DataPlan, Delivery, Direction, Fault, LongPhase,
    RunOutcome, RuntimeSet, Target, UaClass,
};
use crate::scsi::scsi::{op as scsi_op, opcode_from_cdb};
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

/// Wire chunk size for a Data-In phase. Independent of the caller's bank so a
/// large transfer is still split into bounded bulk packets.
const WIRE_CHUNK: usize = 8192;

/// Upper bound on a Data-Out drain chunk.
const DRAIN_CHUNK: usize = 8192;

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
///   for all shortfall sizes. For devices whose shortfalls are almost all
///   large Data-phase errors, this is the semantically honest choice.
/// - `Short` — opt-in for stall-capable transports *with* clear observability
///   (both legs). Any shortfall size; enters the host's halt/clear recovery
///   flow.
/// - `Pad` — opt-in for stall-less transports. Near-free for the structural
///   small shortfalls that occur routinely (INQUIRY/REQUEST SENSE/MODE SENSE:
///   tens to ~200 bytes ≈ one FS packet), and avoids the halt/clear/recovery
///   path entirely. Large shortfalls are capped by [`MAX_PAD`] and degrade to
///   the `ShortNoStall` ending, so a garbage `dCBWDataTransferLength` cannot
///   turn into an unbounded zero pour.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum ShortfallPolicy {
    /// Conformant below the fill cap: pad fill zeros up to
    /// `dCBWDataTransferLength`, sending at most [`MAX_PAD`] fill bytes (the
    /// fill is not "relevant" data — residue stays `declared − produced`).
    /// A shortfall that exhausts the cap ends like `ShortNoStall`.
    Pad,
    /// Conformant: short packet then STALL Bulk-In ([`Action::StallIn`]); the
    /// withheld CSW is queued immediately and delivered once the host clears
    /// the halt. Requires a driver that implements `BotIo::stall_in` and then
    /// feeds [`Event::StallApplied`].
    Short,
    /// Non-conformant, default: plain short packet, no STALL. Runs unaided on
    /// any transport.
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
    /// Receive up to `len` bytes into `work[offset..offset + len]`. The offset
    /// is the position this segment occupies in the caller's bank, so a data
    /// phase that arrives in several USB requests never overwrites what it has
    /// already accumulated. `probe` marks a non-blocking drain receive
    /// (Data-Out overrun): the shell should try once; a WouldBlock result ends
    /// the data phase and should be fed back as [`Event::HostIdle`].
    HostRecv {
        offset: usize,
        len: usize,
        probe: bool,
    },
    /// Send `bytes` on the bulk-IN pipe.
    HostSend { bytes: &'a [u8] },
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
    /// The `Short` shortfall's Bulk-In STALL has been applied; release the
    /// withheld CSW.
    StallApplied,
    /// Bulk-Only Reset / LinkReset: abort any in-flight transaction, return to
    /// the Command phase, and raise a BUS RESET unit attention (BOT §4.2,
    /// §5.2).
    Reset,
}

/// Core-level error (no_std).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BotTargetError {
    /// The caller's `work` buffer is smaller than [`crate::MIN_DATA_LEN`], or
    /// the scratch bank is smaller than [`crate::MIN_DATA_LEN`].
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
enum Stage {
    /// Command phase: accumulate the 31-byte CBW.
    Command { got: usize },
    /// A core command is active; `phase` carries its host data phase.
    Exec,
    /// Synthesized Data-In (REPORT LUNS / invalid-LUN sense): send
    /// `total` bytes already staged in `work`.
    Synth {
        total: u64,
        wire: u64,
        staged: Option<u32>,
        tag: u32,
        declared: u64,
        lun: usize,
    },
    /// Data-In fill after a `Pad` shortfall.
    Pad {
        target: u64,
        wire: u64,
        declared: u64,
        chunk: u32,
        csw: CswPending,
    },
    /// A zero-length packet terminates the data phase before the CSW.
    Zlp { csw: CswPending, stall: bool },
    /// The CSW is withheld until the shell STALLs Bulk-In.
    Stall { csw: CswPending },
    /// Data-Out drain: known remainder, then a non-blocking overrun probe.
    Drain {
        remaining: u64,
        probe: bool,
        csw: CswPending,
    },
    /// CSW pending in the internal buffer.
    Csw,
}

/// CSW payload of a terminal status.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct CswPending {
    tag: u32,
    residue: u64,
    status: CswStatus,
    lun: usize,
}

/// Device host data phase of the active command.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Phase {
    Idle,
    Send(SendPhase),
    Recv(RecvPhase),
}

/// Data-In progress (the device's send stream).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct SendPhase {
    token: HostToken,
    /// Device plan D (relevant bytes, total across chunks).
    plan: u32,
    /// Relevant bytes already staged on the wire.
    produced: u32,
    /// Total wire bytes staged (relevant + any fill) across chunks.
    wire: u32,
    /// Total wire target including fill (`min(H, D + MAX_PAD)` for `Pad`).
    pad_target: u32,
    /// Relevant bytes of the current device chunk.
    chunk_len: u32,
    /// Relevant bytes accepted by the device for the current chunk.
    chunk_accept: u32,
    /// Wire target of the current chunk (end of the relevant data, or the pad
    /// target when the chunk completes the plan).
    chunk_wire_end: u32,
    /// Wire total when the current chunk started.
    phase_wire_base: u32,
    /// Chunk staged and awaiting `Event::HostSent`: bank offset and length.
    staged: Option<(u32, u32)>,
}

/// Data-Out progress (the device's receive stream).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct RecvPhase {
    token: HostToken,
    /// Device plan D (total across chunks).
    plan: u32,
    /// Bytes the device accepts: `min(D, H)`.
    limit: u32,
    /// Wire bytes received into the bank (total across chunks).
    received: u32,
    /// Prefix the device confirmed to the host seam (total across chunks).
    accepted: u32,
    /// Wire offset where the current device chunk starts.
    chunk_base: u32,
    /// Bytes requested by the current device chunk.
    chunk_len: u32,
    /// Wire target for the current chunk (`min(H, chunk_base + chunk_len)`).
    wire_target: u32,
    /// The BOT layer finished the wire receive; `poll_host` may answer Ready.
    wire_done: bool,
}

/// H-versus-D gate computed by [`HostTransport::publish`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct Gate {
    /// A plan was published.
    seen: bool,
    /// Published device plan length (relevant bytes).
    plan_bytes: u32,
    /// The plan is a phase error (case 7 / case 13).
    phase_error: bool,
    /// The transport rejected the plan; the runner settles the command.
    rejected: bool,
}

impl Gate {
    const EMPTY: Gate = Gate {
        seen: false,
        plan_bytes: 0,
        phase_error: false,
        rejected: false,
    };
}

/// BOT session: a non-blocking protocol state machine over one bulk pipe
/// pair (plus the driver-mediated control pipe).
#[derive(Debug)]
pub struct BotSession {
    stage: Stage,
    phase: Phase,
    cbw: [u8; CBW_LEN],
    csw: [u8; CSW_LEN],
    num_luns: u8,
    /// Bulk endpoint max packet size in bytes used for the Data-In ZLP
    /// decision (`BOT_BULK_MPS` by default; 64 for Full-Speed, 512 for
    /// High-Speed).
    bulk_mps: u64,
    /// How a Data-In shortfall ends (default `ShortNoStall`).
    shortfall: ShortfallPolicy,
    /// CBW tag / declared host length / direction of the active transaction.
    tag: u32,
    declared: u64,
    host_dir: BotDir,
    /// Wire LUN of the active transaction.
    lun: usize,
    /// The core command is active (started, not yet settled).
    cmd_active: bool,
    /// Host-phase token generation; a token is dead after `Ready`/`cancel`.
    host_gen: u32,
    /// Delivery state of the current completion.
    delivery: Delivery,
    /// The plan gate of the active command.
    gate: Gate,
    /// LUN whose resident long operation the idle entries advance.
    long_lun: Option<usize>,
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
    /// that must answer Get Max LUN before the first [`poll`] call. The count
    /// is refreshed from the target on every entry.
    ///
    /// [`poll`]: Self::poll
    pub fn with_luns(num_luns: usize) -> Self {
        Self {
            stage: Stage::Command { got: 0 },
            phase: Phase::Idle,
            cbw: [0u8; CBW_LEN],
            csw: [0u8; CSW_LEN],
            num_luns: num_luns.clamp(1, 16) as u8,
            bulk_mps: BOT_BULK_MPS,
            shortfall: ShortfallPolicy::default(),
            tag: 0,
            declared: 0,
            host_dir: BotDir::DataOut,
            lun: 0,
            cmd_active: false,
            host_gen: 1,
            delivery: Delivery::NotApplicable,
            gate: Gate::EMPTY,
            long_lun: None,
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
    /// refreshed from the target on every [`poll`](Self::poll) entry. Pure
    /// getter (no state change).
    pub fn max_lun(&self) -> u8 {
        self.num_luns.saturating_sub(1)
    }

    // ── Poll interface (non-blocking state machine) ───────────────

    /// Non-blocking state-machine step: consume one [`Event`] and return the
    /// next [`Action`].
    ///
    /// `work` is the transport's data bank (the CBW/CSW live in internal
    /// buffers). `scratch` is the resident long-operation bank. `target` owns
    /// the LUN slots and `storage` executes the device's storage operations;
    /// the session itself implements the [`HostTransport`] data seam and
    /// performs at most one command step per entry.
    pub fn poll<'a, S: RuntimeSet>(
        &'a mut self,
        ev: Event,
        work: &'a mut [u8],
        scratch: &'a mut [u8],
        target: &'a mut Target<S>,
        storage: &'a mut dyn Storage,
    ) -> Action<'a> {
        if work.len() < crate::MIN_DATA_LEN || scratch.len() < crate::MIN_DATA_LEN {
            return Action::Error(BotTargetError::WorkBufTooSmall);
        }
        self.num_luns = target.slot_count().clamp(1, 16) as u8;

        // Every entry that starts at a command boundary advances the resident
        // long operation once: one poll per entry.
        if !self.cmd_active
            && matches!(self.stage, Stage::Command { .. })
            && self.idle_entry(work, scratch, target, storage)
        {
            return Action::Error(BotTargetError::Io);
        }

        match ev {
            Event::Reset => {
                self.reset(work, scratch, target, storage);
                self.pending(work)
            }
            Event::StallApplied => {
                if let Stage::Stall { csw } = self.stage {
                    self.write_csw(csw);
                }
                self.pending(work)
            }
            Event::Tick => self.pending(work),
            Event::HostSent => self.on_sent(work, scratch, target, storage),
            Event::HostRecv { len } => self.on_recv(len, work, scratch, target, storage),
            Event::HostIdle => self.on_idle(work, scratch, target, storage),
        }
    }

    /// Advance a resident long operation and the target lifecycle once per
    /// idle entry. Returns `true` when the target reported its terminal
    /// outcome.
    fn idle_entry<S: RuntimeSet>(
        &mut self,
        work: &mut [u8],
        scratch: &mut [u8],
        target: &mut Target<S>,
        storage: &mut dyn Storage,
    ) -> bool {
        if let Some(lun) = self.long_lun {
            match target.poll_long_entry_rt(lun, storage, work, scratch) {
                Ok(info) => {
                    if !matches!(info.phase, LongPhase::Foreground | LongPhase::Background) {
                        self.long_lun = None;
                        if info.phase == LongPhase::Settled && info.error.is_none() {
                            // The medium changed under the host: report it on
                            // the next reporting command, like the device's
                            // own post-format unit attention.
                            let _ = target.raise_ua_rt(lun, UaClass::MediumChanged);
                        }
                    }
                }
                Err(fault) => {
                    self.long_lun = None;
                    target.fatal(fault);
                }
            }
        }
        matches!(target.tick(), RunOutcome::Ended { .. })
    }

    fn on_sent<'a, S: RuntimeSet>(
        &'a mut self,
        work: &'a mut [u8],
        scratch: &mut [u8],
        target: &mut Target<S>,
        storage: &mut dyn Storage,
    ) -> Action<'a> {
        match self.stage {
            Stage::Exec if matches!(self.phase, Phase::Send(_)) => {
                self.step(work, scratch, target, storage);
                self.pending(work)
            }
            Stage::Synth {
                mut wire,
                staged,
                total,
                tag,
                declared,
                lun,
            } => {
                let Some(chunk) = staged else {
                    return Action::Error(BotTargetError::Internal);
                };
                wire = wire.saturating_add(u64::from(chunk));
                if wire < total {
                    self.stage = Stage::Synth {
                        total,
                        wire,
                        staged: Some((total - wire).min(WIRE_CHUNK as u64).max(1) as u32),
                        tag,
                        declared,
                        lun,
                    };
                } else {
                    self.finish_data_in(tag, declared, total, total, CswStatus::Passed, false, lun);
                }
                self.pending(work)
            }
            Stage::Pad {
                target: pad_target,
                wire,
                declared,
                chunk,
                csw,
            } => {
                let wire = wire.saturating_add(u64::from(chunk));
                if wire < pad_target {
                    self.stage = Stage::Pad {
                        target: pad_target,
                        wire,
                        declared,
                        chunk: (pad_target - wire).min(ZERO_CHUNK.len() as u64) as u32,
                        csw,
                    };
                } else if wire < declared && wire.is_multiple_of(self.bulk_mps) {
                    // Cap exhausted on an MPS boundary: a short packet must
                    // terminate the bulk-IN phase.
                    self.stage = Stage::Zlp { csw, stall: false };
                } else {
                    self.write_csw(csw);
                }
                self.pending(work)
            }
            Stage::Zlp { csw, stall } => {
                if stall {
                    self.stage = Stage::Stall { csw };
                } else {
                    self.write_csw(csw);
                }
                self.pending(work)
            }
            Stage::Csw => {
                self.stage = Stage::Command { got: 0 };
                self.cmd_active = false;
                self.delivery = Delivery::Complete;
                self.phase = Phase::Idle;
                self.pending(work)
            }
            _ => Action::Error(BotTargetError::Internal),
        }
    }

    fn on_recv<'a, S: RuntimeSet>(
        &'a mut self,
        len: usize,
        work: &'a mut [u8],
        scratch: &mut [u8],
        target: &mut Target<S>,
        storage: &mut dyn Storage,
    ) -> Action<'a> {
        match self.stage {
            Stage::Command { got } => self.on_cbw(len, got, work, scratch, target, storage),
            Stage::Exec if matches!(self.phase, Phase::Recv(_)) => {
                let mut stray = false;
                let done = {
                    let Phase::Recv(p) = &mut self.phase else {
                        return Action::Error(BotTargetError::Internal);
                    };
                    let cap = work.len() as u32;
                    let local_received = p.received.saturating_sub(p.chunk_base);
                    let local_target = p.wire_target.saturating_sub(p.chunk_base).min(cap);
                    let remaining = local_target.saturating_sub(local_received);
                    if len as u32 > remaining {
                        stray = true;
                        false
                    } else {
                        // The shell wrote this segment straight at its final
                        // bank offset, so no move is needed here.
                        p.received = p.received.saturating_add(len as u32);
                        let done = p.received >= p.wire_target;
                        if done {
                            p.wire_done = true;
                        }
                        done
                    }
                };
                if stray {
                    // No receive is outstanding (the wire phase already ended
                    // and the device is in a storage-only step): the byte is
                    // framing noise, so treat it as an invalid CBW.
                    self.abort_active(work, scratch, target, storage);
                    return Action::StallBoth;
                }
                if done {
                    self.step(work, scratch, target, storage);
                }
                self.pending(work)
            }
            Stage::Drain {
                remaining,
                probe,
                csw,
            } => {
                if probe {
                    if len < DRAIN_CHUNK {
                        self.write_csw(csw);
                    } else {
                        self.stage = Stage::Drain {
                            remaining,
                            probe,
                            csw,
                        };
                    }
                } else {
                    let done = (len as u64).min(remaining);
                    let remaining = remaining - done;
                    if remaining == 0 {
                        self.stage = Stage::Drain {
                            remaining: 0,
                            probe: true,
                            csw,
                        };
                    } else {
                        self.stage = Stage::Drain {
                            remaining,
                            probe: false,
                            csw,
                        };
                    }
                }
                self.pending(work)
            }
            _ => {
                // A receive outside a command/data phase is framing noise, not
                // an impossible transition: drop the transaction as an invalid
                // CBW instead of ending the serve loop.
                self.abort_active(work, scratch, target, storage);
                Action::StallBoth
            }
        }
    }

    fn on_idle<'a, S: RuntimeSet>(
        &'a mut self,
        work: &'a mut [u8],
        scratch: &mut [u8],
        target: &mut Target<S>,
        storage: &mut dyn Storage,
    ) -> Action<'a> {
        match self.stage {
            // A storage-only step is in flight: drive it again.
            Stage::Exec if matches!(self.phase, Phase::Idle) => {
                self.step(work, scratch, target, storage);
                self.pending(work)
            }
            // A host data phase paused: keep waiting for the same chunk.
            Stage::Command { .. }
            | Stage::Exec
            | Stage::Synth { .. }
            | Stage::Pad { .. }
            | Stage::Csw
            | Stage::Zlp { .. }
            | Stage::Stall { .. } => self.pending(work),
            // A non-blocking drain probe found nothing: the overrun is over.
            Stage::Drain {
                probe: true, csw, ..
            } => {
                self.write_csw(csw);
                self.pending(work)
            }
            Stage::Drain { remaining, csw, .. } => {
                self.stage = Stage::Drain {
                    remaining,
                    probe: false,
                    csw,
                };
                self.pending(work)
            }
        }
    }

    // ── Command phase ──────────────────────────────────────────────

    fn on_cbw<'a, S: RuntimeSet>(
        &'a mut self,
        len: usize,
        got: usize,
        work: &'a mut [u8],
        scratch: &mut [u8],
        target: &mut Target<S>,
        storage: &mut dyn Storage,
    ) -> Action<'a> {
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
            self.stage = Stage::Command { got };
            return self.pending(work);
        }
        match Cbw::parse(&self.cbw) {
            None => {
                // Invalid CBW (BOT §6.6.1): STALL both endpoints and return
                // to the Command phase. The host's
                // CLEAR_FEATURE(ENDPOINT_HALT) is handled by the USB core;
                // the next CBW arriving means the halt is clear.
                self.stage = Stage::Command { got: 0 };
                Action::StallBoth
            }
            Some(cbw) => {
                self.dispatch_cbw(&cbw, work, scratch, target, storage);
                self.pending(work)
            }
        }
    }

    // ── Command dispatch ───────────────────────────────────────────

    fn dispatch_cbw<S: RuntimeSet>(
        &mut self,
        cbw: &Cbw,
        work: &mut [u8],
        scratch: &mut [u8],
        target: &mut Target<S>,
        storage: &mut dyn Storage,
    ) {
        let cdb = cbw.cdb_slice();
        let declared = u64::from(cbw.data_len);
        self.tag = cbw.tag;
        self.declared = declared;
        self.host_dir = cbw.dir;
        self.lun = cbw.lun as usize;
        self.gate = Gate::EMPTY;
        let mut hx = [0u8; 49];
        crate::debug!(
            "bot cbw lun={} dir={:?} len={} tag={} cdb={}",
            cbw.lun,
            cbw.dir,
            declared,
            cbw.tag,
            core::str::from_utf8(crate::scsi::util::hex_of(&mut hx, cdb)).unwrap_or("?")
        );

        let opcode = opcode_from_cdb(cdb);

        // A declared host direction that contradicts the command family is a
        // BOT phase error before the device is touched: never feed the medium
        // a fabricated Data-Out, never send device data the host asked to
        // write.
        if declared > 0 {
            let natural = if data_in_opcode(opcode) {
                Some(BotDir::DataIn)
            } else if data_out_opcode(opcode) {
                Some(BotDir::DataOut)
            } else {
                None
            };
            if matches!(natural, Some(dir) if dir != cbw.dir) {
                self.enter_phase_error(cbw.dir, declared);
                return;
            }
        }

        let slot_count = target.slot_count();
        // REPORT LUNS is a target-level command: any addressed LUN is served by
        // slot 0, whose response lists the whole inventory.
        let lun = if opcode == scsi_op::REPORT_LUNS {
            0
        } else {
            self.lun
        };
        if self.lun >= slot_count && opcode != scsi_op::REPORT_LUNS {
            // Invalid LUN: Failed CSW + REQUEST SENSE (ASC 0x25). SPC-3 §6.27:
            // REQUEST SENSE to an unsupported LUN returns GOOD with sense
            // ILLEGAL REQUEST / LOGICAL UNIT NOT SUPPORTED on *every* call.
            if opcode == scsi_op::REQUEST_SENSE {
                let sense = crate::core::LUN_NOT_SUPPORTED;
                let n = sense_write_fixed(sense, work);
                self.synthesize_data_in(n, declared);
            } else {
                self.fail_command(CswStatus::Failed);
            }
            return;
        }
        self.lun = lun;

        let direction = match cbw.dir {
            BotDir::DataIn => Direction::ToHost,
            BotDir::DataOut if declared > 0 => Direction::FromHost,
            // Hn < Do: the host declared no data but the command family is
            // Data-Out, so the device still sees the write intent and its
            // publish gate rejects the plan as a phase error.
            BotDir::DataOut if data_out_opcode(opcode) => Direction::FromHost,
            BotDir::DataOut => {
                if data_in_opcode(opcode) {
                    Direction::ToHost
                } else {
                    Direction::None
                }
            }
        };
        let ctx = CommandContext {
            lun: lun as u64,
            lun_count: 0,
            host_bytes: CommandContext::UNBOUNDED_HOST_BYTES,
            host_direction: direction,
        };
        match target.drive_start_rt(lun, ctx, cdb) {
            Ok(()) => {
                self.cmd_active = true;
                self.delivery = Delivery::Pending;
                self.stage = Stage::Exec;
                self.phase = Phase::Idle;
                self.step(work, scratch, target, storage);
            }
            Err(Fault::LunNotFound) => {
                if opcode == scsi_op::REQUEST_SENSE {
                    let sense = crate::core::LUN_NOT_SUPPORTED;
                    let n = sense_write_fixed(sense, work);
                    self.synthesize_data_in(n, declared);
                } else {
                    self.fail_command(CswStatus::Failed);
                }
            }
            Err(_) => {
                // A busy/lifecycle refusal is a SCSI CHECK CONDITION, never a
                // phase error.
                crate::debug!("lun {} refused the command", lun);
                self.fail_command(CswStatus::Failed);
            }
        }
    }

    /// One step of the active command, then map its outcome to an ending.
    fn step<S: RuntimeSet>(
        &mut self,
        work: &mut [u8],
        scratch: &mut [u8],
        target: &mut Target<S>,
        storage: &mut dyn Storage,
    ) {
        let lun = self.lun;
        let result = target.drive_step_rt(lun, storage, self, work, scratch);
        match result {
            Ok(crate::core::DriveStep::Pending) => {}
            Ok(crate::core::DriveStep::Done(completion)) => self.finish(completion),
            Ok(crate::core::DriveStep::Control(_)) => {
                // A queued control settled the command without a SCSI status.
                self.delivery = Delivery::Failed;
                self.fail_command(CswStatus::Failed);
            }
            Err(fault) => {
                crate::debug!("command step failed: fault={}", fault_state(fault));
                self.delivery = Delivery::Failed;
                if self.gate.rejected
                    || (fault == Fault::Contract && !self.gate.seen && self.declared > 0)
                {
                    // The plan contradicted the wire's H/D declaration.
                    self.enter_phase_error(self.host_dir, self.declared);
                } else {
                    self.fail_command(CswStatus::Failed);
                }
            }
        }
        // A command that left the medium busy keeps the long operation
        // resident; the idle entries advance it.
        if let Ok(info) = target.snapshot_rt(lun) {
            if matches!(
                info.long.phase,
                LongPhase::Foreground | LongPhase::Background
            ) {
                self.long_lun = Some(lun);
            }
        }
    }

    /// Finish the active command from its fixed completion.
    fn finish(&mut self, completion: Completion) {
        let tag = self.tag;
        let declared = self.declared;
        let gate = self.gate;
        let lun = self.lun;
        let status = if gate.phase_error {
            CswStatus::PhaseError
        } else {
            match completion {
                Completion::Good => CswStatus::Passed,
                _ => CswStatus::Failed,
            }
        };

        let (relevant, wire, received, accepted, plan) = match self.phase {
            Phase::Send(p) => (
                u64::from(p.wire.min(p.plan)),
                u64::from(p.wire),
                0,
                0,
                u64::from(p.plan),
            ),
            Phase::Recv(p) => (
                0,
                0,
                u64::from(p.received),
                u64::from(p.accepted),
                u64::from(p.plan),
            ),
            Phase::Idle => (0, 0, 0, 0, 0),
        };
        self.cmd_active = false;
        self.phase = Phase::Idle;
        self.delivery = Delivery::Pending;

        if self.host_dir == BotDir::DataOut {
            self.finish_data_out(tag, declared, received, accepted, plan, status, lun);
        } else {
            self.finish_data_in(tag, declared, relevant, wire, status, gate.phase_error, lun);
        }
    }

    // ── Endings ────────────────────────────────────────────────────

    /// A terminal status with no device data phase.
    fn fail_command(&mut self, status: CswStatus) {
        let tag = self.tag;
        let declared = self.declared;
        let lun = self.lun;
        self.cmd_active = false;
        self.phase = Phase::Idle;
        if self.host_dir == BotDir::DataOut {
            self.finish_data_out(tag, declared, 0, 0, 0, status, lun);
        } else {
            self.finish_data_in(tag, declared, 0, 0, status, false, lun);
        }
    }

    /// Phase-error ending before any device data moved.
    fn enter_phase_error(&mut self, dir: BotDir, declared: u64) {
        self.cmd_active = false;
        self.phase = Phase::Idle;
        let csw = CswPending {
            tag: self.tag,
            residue: declared,
            status: CswStatus::PhaseError,
            lun: self.lun,
        };
        if dir == BotDir::DataOut && declared > 0 {
            self.stage = Stage::Drain {
                remaining: declared,
                probe: false,
                csw,
            };
        } else if declared > 0 {
            // No device data went out; terminate the host's data-in phase.
            self.stage = Stage::Zlp { csw, stall: false };
        } else {
            self.write_csw(csw);
        }
    }

    /// Data-In ending: `relevant` device bytes were put on the wire out of
    /// `declared` host bytes; `wire` includes any merged fill.
    #[allow(clippy::too_many_arguments)]
    fn finish_data_in(
        &mut self,
        tag: u32,
        declared: u64,
        relevant: u64,
        wire: u64,
        status: CswStatus,
        phase_error: bool,
        lun: usize,
    ) {
        let relevant = relevant.min(declared);
        let csw = CswPending {
            tag,
            residue: declared - relevant,
            status,
            lun,
        };
        if relevant >= declared {
            self.write_csw(csw);
            return;
        }
        if phase_error {
            // Never fabricate data for a phase error: only the short-packet
            // terminator (and the selected STALL) applies.
            if wire.is_multiple_of(self.bulk_mps) {
                self.stage = Stage::Zlp {
                    csw,
                    stall: self.shortfall == ShortfallPolicy::Short,
                };
            } else if self.shortfall == ShortfallPolicy::Short {
                self.stage = Stage::Stall { csw };
            } else {
                self.write_csw(csw);
            }
            return;
        }
        match self.shortfall {
            ShortfallPolicy::Pad => {
                let target = declared.min(relevant.saturating_add(MAX_PAD));
                if wire >= target {
                    // Fully filled, or the cap ran out.
                    if wire < declared && wire.is_multiple_of(self.bulk_mps) {
                        self.stage = Stage::Zlp { csw, stall: false };
                    } else {
                        self.write_csw(csw);
                    }
                } else if wire < declared && !wire.is_multiple_of(self.bulk_mps) {
                    // A non-MPS-aligned wire length already ended the host's
                    // bulk-IN; appending fill would corrupt the CSW.
                    self.write_csw(csw);
                } else {
                    self.stage = Stage::Pad {
                        target,
                        wire,
                        declared,
                        chunk: (target - wire).min(ZERO_CHUNK.len() as u64) as u32,
                        csw,
                    };
                }
            }
            ShortfallPolicy::Short => {
                if relevant.is_multiple_of(self.bulk_mps) {
                    self.stage = Stage::Zlp { csw, stall: true };
                } else {
                    self.stage = Stage::Stall { csw };
                }
            }
            ShortfallPolicy::ShortNoStall => {
                if relevant.is_multiple_of(self.bulk_mps) {
                    self.stage = Stage::Zlp { csw, stall: false };
                } else {
                    self.write_csw(csw);
                }
            }
        }
    }

    /// Data-Out ending: `received` host bytes reached the transport and
    /// `accepted` is the device-confirmed prefix out of `declared`. Drains the
    /// remainder (and probes for overrun) first.
    ///
    /// BOT §6.6.2 defines the residue as `dCBWDataTransferLength` minus the
    /// data the device actually processed. Only a `Passed` completion proves
    /// the accepted prefix reached the medium; any other ending (storage
    /// error, CHECK CONDITION, phase error) must report the full declared
    /// length so the host never believes an unconfirmed write landed.
    #[allow(clippy::too_many_arguments)]
    fn finish_data_out(
        &mut self,
        tag: u32,
        declared: u64,
        received: u64,
        accepted: u64,
        plan: u64,
        status: CswStatus,
        lun: usize,
    ) {
        let processed = if status == CswStatus::Passed {
            accepted.min(declared).min(plan)
        } else {
            0
        };
        let csw = CswPending {
            tag,
            residue: declared - processed,
            status,
            lun,
        };
        if declared == 0 {
            self.write_csw(csw);
            return;
        }
        self.stage = Stage::Drain {
            remaining: declared.saturating_sub(received),
            probe: received >= declared,
            csw,
        };
    }

    /// Enter a synthesized Data-In phase for `available` bytes staged in
    /// `work[0..available]`.
    fn synthesize_data_in(&mut self, available: usize, declared: u64) {
        self.cmd_active = false;
        self.phase = Phase::Idle;
        let available = available as u64;
        if declared == 0 {
            // BOT §6.7.1 Case (2) Hn<Di.
            let csw = CswPending {
                tag: self.tag,
                residue: 0,
                status: CswStatus::PhaseError,
                lun: self.lun,
            };
            self.write_csw(csw);
            return;
        }
        let total = available.min(declared);
        if total == 0 {
            let csw = CswPending {
                tag: self.tag,
                residue: declared,
                status: CswStatus::Passed,
                lun: self.lun,
            };
            self.write_csw(csw);
            return;
        }
        self.stage = Stage::Synth {
            total,
            wire: 0,
            staged: Some(total.min(WIRE_CHUNK as u64) as u32),
            tag: self.tag,
            declared,
            lun: self.lun,
        };
    }

    /// Serialize `csw` into the internal buffer and enter the CSW phase.
    fn write_csw(&mut self, csw: CswPending) {
        let residue = u32::try_from(csw.residue).unwrap_or_else(|_| {
            crate::warn!("bot: residue {} truncated to u32::MAX", csw.residue);
            u32::MAX
        });
        crate::debug!(
            "bot csw tag={} residue={} status={:?}",
            csw.tag,
            residue,
            csw.status
        );
        Csw {
            tag: csw.tag,
            residue,
            status: csw.status,
        }
        .write(&mut self.csw);
        self.stage = Stage::Csw;
        self.phase = Phase::Idle;
    }

    // ── Reset ──────────────────────────────────────────────────────

    /// Abandon the active transaction without a CSW and without a unit
    /// attention: cancel the core command (and any retained host token), then
    /// return to the Command phase.
    ///
    /// A resident long operation is deliberately left running: the reset
    /// abandons the command/framing boundary, not the medium operation.
    fn abort_active<S: RuntimeSet>(
        &mut self,
        work: &mut [u8],
        scratch: &mut [u8],
        target: &mut Target<S>,
        storage: &mut dyn Storage,
    ) {
        if self.cmd_active {
            let lun = self.lun;
            // Reset recovery keeps the command-abort path; no `Control::Nop`
            // is queued because the boundary is not clean by definition here.
            let _ = target.request_control(Control::Abort);
            let _ = target.drive_step_rt(lun, storage, self, work, scratch);
        }
        self.stage = Stage::Command { got: 0 };
        self.phase = Phase::Idle;
        self.cmd_active = false;
        self.gate = Gate::EMPTY;
        self.delivery = Delivery::NotApplicable;
    }

    /// Bulk-Only Reset / LinkReset body: abort any in-flight transaction,
    /// return to the Command phase, and raise a BUS RESET unit attention on
    /// every LUN (BOT §4.2, §5.2).
    ///
    /// This aborts the active command but leaves a resident long operation
    /// running (`long_lun` is unchanged); no `Control::Nop` is issued because
    /// reset recovery needs the command-abort path, not a clean boundary.
    fn reset<S: RuntimeSet>(
        &mut self,
        work: &mut [u8],
        scratch: &mut [u8],
        target: &mut Target<S>,
        storage: &mut dyn Storage,
    ) {
        self.abort_active(work, scratch, target, storage);
        let count = target.slot_count();
        for lun in 0..count {
            let _ = target.raise_ua_rt(lun, UaClass::BusReset);
        }
    }

    // ── Action projection ─────────────────────────────────────────

    /// The action for the current state (re-emitted on `Event::Tick` and after
    /// an out-of-band control event).
    fn pending<'a>(&'a mut self, work: &'a mut [u8]) -> Action<'a> {
        self.stage_send(work.len());
        let stage = self.stage;
        match stage {
            Stage::Command { got } => Action::HostRecv {
                offset: 0,
                len: CBW_LEN - got,
                probe: false,
            },
            Stage::Exec => match self.phase {
                Phase::Send(p) => {
                    let (bank_offset, len) = p.staged.unwrap_or((0, 0));
                    let start = bank_offset as usize;
                    let end = start + len as usize;
                    if end > work.len() || start >= end {
                        return Action::Error(BotTargetError::Internal);
                    }
                    // Fill bytes beyond the device's relevant bytes are zeros,
                    // never stale bank contents.
                    let plan = p.chunk_len as usize;
                    if end > plan {
                        work[plan.max(start)..end].fill(0);
                    }
                    Action::HostSend {
                        bytes: &work[start..end],
                    }
                }
                Phase::Recv(p) => {
                    let cap = work.len() as u32;
                    let local_received = p.received.saturating_sub(p.chunk_base);
                    let local_target = p.wire_target.saturating_sub(p.chunk_base).min(cap);
                    if local_received < local_target {
                        Action::HostRecv {
                            offset: local_received as usize,
                            len: (local_target - local_received) as usize,
                            probe: false,
                        }
                    } else {
                        // The core is still on a storage operation with no
                        // wire phase; probe so the shell loops back with a
                        // `HostIdle` and the next entry drives it again.
                        Action::HostRecv {
                            offset: 0,
                            len: 1,
                            probe: true,
                        }
                    }
                }
                Phase::Idle => Action::HostRecv {
                    offset: 0,
                    len: 1,
                    probe: true,
                },
            },
            Stage::Synth {
                total,
                wire,
                staged,
                ..
            } => {
                let Some(chunk) = staged else {
                    return Action::Error(BotTargetError::Internal);
                };
                let start = wire as usize;
                let end = start + chunk as usize;
                if end > work.len() || end as u64 > total {
                    return Action::Error(BotTargetError::Internal);
                }
                Action::HostSend {
                    bytes: &work[start..end],
                }
            }
            Stage::Pad { chunk, .. } => Action::HostSend {
                bytes: &ZERO_CHUNK[..chunk as usize],
            },
            Stage::Zlp { .. } => Action::HostSend { bytes: &[] },
            Stage::Stall { .. } => Action::StallIn,
            Stage::Drain {
                remaining, probe, ..
            } => Action::HostRecv {
                offset: 0,
                len: if probe {
                    DRAIN_CHUNK
                } else {
                    remaining.min(DRAIN_CHUNK as u64) as usize
                },
                probe,
            },
            Stage::Csw => Action::HostSend {
                bytes: &self.csw[..],
            },
        }
    }
}

/// Fixed-format sense (SPC-3): response code, sense key, additional length,
/// ASC/ASCQ. Writes at most 18 bytes into `dst` and returns the count.
fn sense_write_fixed(sense: crate::core::Sense, dst: &mut [u8]) -> usize {
    let n = dst.len().min(18);
    dst[..n].fill(0);
    if n > 0 {
        dst[0] = 0x70;
    }
    if n > 2 {
        dst[2] = sense.key;
    }
    if n > 7 {
        dst[7] = 0x0A;
    }
    if n > 12 {
        dst[12] = sense.asc;
    }
    if n > 13 {
        dst[13] = sense.ascq;
    }
    n
}

/// Small copyable projection of a runner fault for logging (defmt-safe).
fn fault_state(fault: Fault) -> u8 {
    match fault {
        Fault::Io => 1,
        Fault::OutOfBounds => 2,
        Fault::NotWritable => 3,
        Fault::Unsupported => 4,
        Fault::Cancelled => 5,
        Fault::NeedsRecovery => 6,
        Fault::Commit => 7,
        Fault::Contract => 8,
        Fault::CounterExhausted => 9,
        Fault::Boundary => 10,
        Fault::ForeignBoundary => 11,
        Fault::LunNotFound => 12,
    }
}

/// Opcodes whose command CDB expects a Data-In phase even when the CBW does
/// not set the direction bit. An unlisted opcode is treated as no-data.
fn data_in_opcode(opcode: u8) -> bool {
    matches!(
        opcode,
        scsi_op::READ_6
            | scsi_op::READ_10
            | scsi_op::READ_16
            | scsi_op::READ_12
            | scsi_op::INQUIRY
            | scsi_op::REQUEST_SENSE
            | scsi_op::REPORT_LUNS
            | scsi_op::MODE_SENSE_6
            | scsi_op::MODE_SENSE_10
            | scsi_op::READ_CAPACITY_10
            | scsi_op::SERVICE_ACTION_IN
            | scsi_op::READ_FORMAT_CAPACITIES
            | scsi_op::GET_CONFIGURATION
            | scsi_op::GET_EVENT_STATUS_NOTIFICATION
            | scsi_op::READ_TOC
            | scsi_op::READ_DISC_INFORMATION
            | scsi_op::READ_TRACK_INFORMATION
            | scsi_op::READ_BUFFER_CAPACITY
            | scsi_op::READ_CD
            | scsi_op::READ_CD_MSF
            | scsi_op::GET_PERFORMANCE
            | scsi_op::READ_DVD_STRUCTURE
            | 0x1C // RECEIVE DIAGNOSTIC RESULTS
    )
}

/// Opcodes whose command CDB expects a Data-Out phase. Used only to detect a
/// wire direction that contradicts the command family before the device is
/// touched; an unknown vendor opcode is left to the device's own gate.
fn data_out_opcode(opcode: u8) -> bool {
    matches!(
        opcode,
        scsi_op::WRITE_6
            | scsi_op::WRITE_10
            | scsi_op::WRITE_12
            | scsi_op::WRITE_16
            | scsi_op::MODE_SELECT_6
            | scsi_op::MODE_SELECT_10
            | scsi_op::FORMAT_UNIT
            | scsi_op::SEND_DIAGNOSTIC
            | 0x2E // WRITE AND VERIFY(10)
            | 0x8E // WRITE AND VERIFY(16)
            | 0x41 // WRITE SAME(10)
            | 0x93 // WRITE SAME(16)
            | 0x4C // LOG SELECT
            | 0xBF // SEND DVD STRUCTURE
            | 0xA1 // BLANK
    )
}

// ── HostTransport ─────────────────────────────────────────────────

impl HostTransport for BotSession {
    fn publish(&mut self, plan: DataPlan) -> Result<(), Fault> {
        self.gate.seen = true;
        self.gate.plan_bytes = u32::try_from(plan.bytes).unwrap_or(u32::MAX);
        let declared = self.declared;
        let reject = |gate: &mut Gate| {
            gate.phase_error = true;
            gate.rejected = true;
            Err(Fault::Contract)
        };
        match (self.host_dir, plan.direction) {
            (BotDir::DataIn, Direction::ToHost) => {
                if declared == 0 {
                    // Hn < Di.
                    return reject(&mut self.gate);
                }
                if plan.bytes > declared {
                    // Hi < Di: send at most H, report the real count, phase
                    // error.
                    self.gate.phase_error = true;
                }
                Ok(())
            }
            (BotDir::DataIn, Direction::FromHost) => {
                // Hi <> Do: never feed a fabricated Data-Out.
                reject(&mut self.gate)
            }
            (BotDir::DataIn, Direction::None) => Ok(()),
            (BotDir::DataOut, Direction::FromHost) => {
                if declared == 0 {
                    // Hn < Do.
                    return reject(&mut self.gate);
                }
                if plan.bytes > declared {
                    // Ho < Do: at most H, report the facts, phase error.
                    self.gate.phase_error = true;
                }
                Ok(())
            }
            (BotDir::DataOut, Direction::ToHost) => {
                // Ho <> Di.
                reject(&mut self.gate)
            }
            (BotDir::DataOut, Direction::None) => Ok(()),
        }
    }

    fn begin_recv(&mut self, req: HostReq) -> HostToken {
        let token = self.next_token();
        if req.dir != Direction::FromHost || req.len == 0 {
            return HostToken::invalid();
        }
        let total = self.gate.plan_bytes;
        let declared = self.declared.min(u64::from(u32::MAX)) as u32;
        // The wire phase already consumed everything the host declared while
        // the device still has plan bytes to go (Host out < Device out at an
        // exact phase boundary). The host cannot send more, so keep the counts
        // and answer the next device chunk with a zero receipt: the device
        // short-accepts, aborts, and finish() reports the phase error instead
        // of waiting for a chunk that will never arrive.
        if let Phase::Recv(p) = self.phase {
            if p.received >= declared && p.accepted < p.plan {
                let mut p = p;
                p.token = token;
                p.chunk_base = p.received;
                p.chunk_len = req.len;
                p.wire_target = p.received;
                p.wire_done = true;
                self.phase = Phase::Recv(p);
                return token;
            }
        }
        // A later device chunk continues the same wire data phase.
        let continuing =
            matches!(self.phase, Phase::Recv(p) if p.received > 0 && p.received < declared);
        let mut p = match self.phase {
            Phase::Recv(p) if continuing => p,
            _ => RecvPhase {
                token,
                plan: total,
                limit: total.min(declared),
                received: 0,
                accepted: 0,
                chunk_base: 0,
                chunk_len: 0,
                wire_target: 0,
                wire_done: false,
            },
        };
        if req.len > total.saturating_sub(p.accepted) {
            return HostToken::invalid();
        }
        p.token = token;
        p.chunk_base = p.received;
        p.chunk_len = req.len;
        // A chunk that completes the plan on the first receive keeps the
        // original whole-declared phase (the remaining H bytes are drained
        // after the device consumes D). A chunked transfer reads one chunk per
        // data phase so the bank never has to hold the whole transfer.
        let completes_plan = p.received.saturating_add(req.len) >= total;
        p.wire_target = if completes_plan && p.received == 0 {
            declared
        } else {
            declared.min(p.received.saturating_add(req.len))
        };
        p.wire_done = false;
        self.phase = Phase::Recv(p);
        token
    }

    fn begin_send(&mut self, req: HostReq) -> HostToken {
        let token = self.next_token();
        if req.dir != Direction::ToHost || req.len == 0 {
            return HostToken::invalid();
        }
        let total = self.gate.plan_bytes;
        let declared = self.declared.min(u64::from(u32::MAX)) as u32;
        let limit = total.min(declared);
        let pad_target = if self.shortfall == ShortfallPolicy::Pad && total < declared {
            declared.min(total.saturating_add(MAX_PAD as u32))
        } else {
            limit
        };
        // A later device chunk continues the same Data-In stream.
        let continuing = matches!(self.phase, Phase::Send(p) if p.produced < p.plan);
        let mut p = match self.phase {
            Phase::Send(p) if continuing => p,
            _ => SendPhase {
                token,
                plan: total,
                produced: 0,
                wire: 0,
                pad_target,
                chunk_len: 0,
                chunk_accept: 0,
                chunk_wire_end: 0,
                phase_wire_base: 0,
                staged: None,
            },
        };
        if req.len > total.saturating_sub(p.produced) {
            return HostToken::invalid();
        }
        let relevant_end = p.produced.saturating_add(req.len).min(limit);
        // The send phase is bounded by `limit`, not by the device plan total:
        // bytes beyond the host's declared length are never put on the wire.
        // The final relevant chunk also carries any `Pad` fill.
        let chunk_wire_end = if relevant_end >= p.plan {
            p.pad_target
        } else {
            relevant_end
        };
        p.token = token;
        p.chunk_len = req.len;
        p.chunk_accept = relevant_end.saturating_sub(p.produced);
        p.chunk_wire_end = chunk_wire_end;
        p.phase_wire_base = p.wire;
        p.staged = None;
        self.phase = Phase::Send(p);
        token
    }

    fn poll_host(&mut self, token: HostToken, buf: HostBuf<'_>) -> Poll<HostReceipt> {
        match self.phase {
            Phase::Send(mut p) if p.token == token => {
                let HostBuf::Send(b) = buf else {
                    return Poll::Ready(HostReceipt::from_adapter(0, Some(Fault::Contract)));
                };
                if b.len() != p.chunk_len as usize {
                    return Poll::Ready(HostReceipt::from_adapter(0, Some(Fault::Contract)));
                }
                if p.chunk_accept == 0 {
                    // The host's declared length is exhausted while the device
                    // still has plan bytes to send (case 7 at an exact phase
                    // boundary). There is no relevant byte in this chunk, so
                    // accept zero: the device short-accepts, aborts, and
                    // finish() reports the phase error instead of asking for a
                    // staged chunk that can never exist.
                    self.phase = Phase::Send(p);
                    return Poll::Ready(HostReceipt::from_adapter(0, None));
                }
                let Some((_, len)) = p.staged.take() else {
                    // First poll: the BOT layer has not staged a chunk yet;
                    // the device must keep waiting.
                    self.phase = Phase::Send(p);
                    return Poll::Pending;
                };
                p.wire = p.wire.saturating_add(len);
                if p.wire < p.chunk_wire_end {
                    self.phase = Phase::Send(p);
                    Poll::Pending
                } else {
                    p.produced = p.produced.saturating_add(p.chunk_accept);
                    self.phase = Phase::Send(p);
                    Poll::Ready(HostReceipt::from_adapter(p.chunk_accept as usize, None))
                }
            }
            Phase::Recv(p) if p.token == token => {
                let HostBuf::Recv(b) = buf else {
                    return Poll::Ready(HostReceipt::from_adapter(0, Some(Fault::Contract)));
                };
                if b.len() != p.chunk_len as usize {
                    return Poll::Ready(HostReceipt::from_adapter(0, Some(Fault::Contract)));
                }
                if !p.wire_done {
                    self.phase = Phase::Recv(p);
                    return Poll::Pending;
                }
                // The receipt covers this chunk only; the transport keeps the
                // running total so residue is computed from the whole plan.
                let end = p.received.min(p.plan).min(p.limit);
                let accepted = end.saturating_sub(p.accepted);
                let mut p = p;
                p.accepted = end;
                self.phase = Phase::Recv(p);
                Poll::Ready(HostReceipt::from_adapter(accepted as usize, None))
            }
            _ => Poll::Ready(HostReceipt::from_adapter(0, Some(Fault::Contract))),
        }
    }

    fn cancel(&mut self, token: HostToken) {
        let live = match self.phase {
            Phase::Send(p) => p.token == token,
            Phase::Recv(p) => p.token == token,
            Phase::Idle => false,
        };
        if live {
            self.phase = Phase::Idle;
            self.host_gen = self.host_gen.wrapping_add(1).max(1);
        }
    }

    fn delivery(&self) -> Delivery {
        self.delivery
    }
}

impl BotSession {
    fn next_token(&mut self) -> HostToken {
        self.host_gen = self.host_gen.wrapping_add(1).max(1);
        HostToken::new(0, self.host_gen)
    }

    /// Stage the next Data-In chunk inside `work` (the caller's bank).
    fn stage_send(&mut self, work_len: usize) {
        if let Phase::Send(p) = &mut self.phase {
            if p.staged.is_some() || p.wire >= p.chunk_wire_end {
                return;
            }
            // The bank holds one phase at a time; any fill beyond it is the
            // `Pad` stage's zero source.
            let bank_end = p
                .phase_wire_base
                .saturating_add(work_len.min(u32::MAX as usize) as u32);
            if p.chunk_wire_end > bank_end {
                p.chunk_wire_end = bank_end;
            }
            let start = p.wire.saturating_sub(p.phase_wire_base);
            let cap = (work_len.min(u32::MAX as usize) as u32).saturating_sub(start);
            let remaining = p.chunk_wire_end.saturating_sub(p.wire);
            let n = remaining.min(WIRE_CHUNK as u32).min(cap);
            if n > 0 {
                p.staged = Some((start, n));
            }
        }
    }
}
