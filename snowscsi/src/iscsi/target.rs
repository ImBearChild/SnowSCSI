//! iSCSI target protocol state machine (RFC 3720 §5 / §10).
//!
//! [`IscsiSession`] is a pure, non-blocking protocol state machine: it never
//! blocks and never touches platform I/O. A shell feeds one [`Event`] (an I/O
//! completion) per [`IscsiSession::poll`] call and learns the next [`Action`]
//! (receive, send or close). The library shell
//! `crate::iscsi::transport::serve` (behind `std`) owns the platform loop; the
//! shell carries no protocol knowledge.
//!
//! The session owns all framing: incoming PDUs are read in stages (the 48-byte
//! BHS, then the remainder — AHS + data segment + padding), driven by the
//! [`Action::HostRecv`] offset/length pairs, so a shell carries no protocol
//! knowledge. The AHS/data bytes are placed where the SCSI layer needs them:
//! the BHS at `work[0..48]`, a Data-Out segment at its final offset inside the
//! command's data area.
//!
//! SCSI command execution is delegated to the core [`Target`]: the session
//! builds the [`CommandContext`] from the wire, starts the command and drives
//! it one step per entry. Host data phases are implemented by this type as
//! [`HostTransport`]: Data-In is chunked into `MaxRecvDataSegmentLength`
//! PDUs, Data-Out is solicited with R2T and consumed one PDU at a time.
//!
//! Key protocol behaviour kept from the legacy implementation: CID read at
//! byte 20-21 (from iscsi_pdu), Data-Out ITT/TTT/BufferOffset/DataSN validation
//! with Reject 0x09, TMF CmdSN check by I bit, out-of-window/duplicate CmdSN
//! silently ignored, Reject carries the rejected PDU header with ITT=0xffffffff,
//! and read-timeout coverage is delegated to the `Conn` implementation.
//!
//! # Work-buffer contract
//!
//! `work` is the wire/PDU bank: `work.len() >= crate::MIN_DATA_LEN +
//! pdu::BHS_SIZE`. The leading [`pdu::BHS_SIZE`] bytes carry the wire header;
//! the remainder is the SCSI data area and the transport's [`HostTransport`]
//! bank. `scratch` is the resident long-operation bank and must hold at least
//! [`crate::MIN_DATA_LEN`] bytes.

use core::cell::Cell;

use crate::core::storage::{HostBuf, HostReceipt, HostReq, HostToken, HostTransport, Storage};
use crate::core::{
    CommandContext, Completion, Control, DataPlan, Delivery, Direction, Fault, LongPhase,
    RuntimeSet, Sense, Target, UaClass, LUN_NOT_SUPPORTED,
};
use crate::iscsi::pdu::{
    flag, iscsi_opcode_name, op, pdu_pad_len, reject, stage, status, tmf, tmf_response, Bhs,
    BHS_SIZE, MAX_DATA_SEGMENT,
};
use crate::scsi::scsi::{op as scsi_op, opcode_from_cdb, opcode_name};

// ── Public types ─────────────────────────────────────────────────────

/// The core's next action, returned by [`IscsiSession::poll`].
///
/// Normal flow never emits a "done" boundary: after a response is sent,
/// `poll(Event::HostSent)` returns the next command-phase
/// [`Action::HostRecv`] directly. Only [`Action::Closed`] / [`Action::Error`]
/// are distinct endings.
#[derive(Debug)]
pub enum Action<'a> {
    /// Receive `len` bytes into `work[offset..offset + len]`.
    ///
    /// The BHS of a PDU is read at offset 0; a data segment is read directly
    /// at its final place in the SCSI data area, so the transport never has to
    /// stage or copy it.
    HostRecv {
        /// Byte offset inside `work`.
        offset: usize,
        /// Number of bytes to receive.
        len: usize,
    },
    /// Send `bytes` to the wire (a complete PDU: BHS + data + padding).
    /// `prefetch` is the next read-ahead coordinate for read-phase overlap
    /// (always `None` in v1).
    HostSend {
        /// Complete PDU to put on the wire.
        bytes: &'a [u8],
        /// Read-ahead coordinate (unused).
        prefetch: Option<(u64, usize)>,
    },
    /// The connection is done (Logout response sent, peer closed, or a fatal
    /// protocol error): the shell closes it.
    Closed,
    /// Internal error (caller bug): work buffer too small, etc.
    Error(TargetError),
}

/// One completion fed from the shell to [`IscsiSession::poll`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Event {
    /// No-I/O driver tick (startup + timer): make progress on a resident long
    /// operation and re-emit the current pending [`Action`].
    Tick,
    /// The shell received `len` bytes (at the offset of the previous
    /// [`Action::HostRecv`]).
    HostRecv {
        /// Number of bytes the shell stored.
        len: usize,
    },
    /// The pending [`Action::HostSend`] packet has been sent.
    HostSent,
}

/// Target-level error (no_std).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TargetError {
    /// Caller's work buffer is smaller than [`crate::MIN_DATA_LEN`] +
    /// `BHS_SIZE` (data area too small for the SCSI layer), or the scratch
    /// bank is smaller than [`crate::MIN_DATA_LEN`].
    WorkBufTooSmall,
    /// Connection I/O failure (details logged by the transport).
    Io,
    /// Unexpected internal state.
    Internal,
}

impl core::fmt::Display for TargetError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::WorkBufTooSmall => write!(f, "work buffer smaller than MIN_DATA_LEN + BHS_SIZE"),
            Self::Io => write!(f, "connection I/O failure"),
            Self::Internal => write!(f, "internal target error"),
        }
    }
}

impl core::error::Error for TargetError {}

/// Login phase stage (RFC 3720 §5.1).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub enum LoginStage {
    /// Security negotiation stage.
    Security,
    /// Operational parameter negotiation stage.
    OpParam,
    /// Full feature phase.
    FullFeature,
}

impl LoginStage {
    fn from_csg(csg: u8) -> Option<LoginStage> {
        match csg {
            stage::SECURITY => Some(LoginStage::Security),
            stage::OP_PARAM => Some(LoginStage::OpParam),
            stage::FULL_FEATURE => Some(LoginStage::FullFeature),
            _ => None,
        }
    }
}

/// Negotiated login parameters (RFC 3720 §10.12-.14).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct NegotiatedParams {
    /// Immediate (unsolicited) write data accepted with the command.
    pub immediate_data: bool,
    /// An R2T is required before any solicited Data-Out.
    pub initial_r2t: bool,
    /// First unsolicited burst limit.
    pub first_burst_len: u32,
    /// Per-R2T burst limit.
    pub max_burst_len: u32,
    /// Outstanding R2T limit (single-transfer model: always 1).
    pub max_outstanding_r2t: u32,
}

impl Default for NegotiatedParams {
    fn default() -> Self {
        Self {
            immediate_data: true,
            initial_r2t: true,
            first_burst_len: DEFAULT_FIRST_BURST,
            max_burst_len: DEFAULT_MAX_BURST,
            max_outstanding_r2t: 1,
        }
    }
}

// ── Private constants ───────────────────────────────────────────────

/// iSCSI Qualified Name for this target (RFC 3720 §3.2.6).
/// Static single-target model; matches `snowscsi-cli::ISCSI_TARGET_NAME`.
const TARGET_NAME: &str = "iqn.1970-01.local.snowscsi:target";

/// Target Transfer Tag for R2T — single outstanding transfer.
const TTT: u32 = 1;
/// RFC 3720 §12.14 suggested defaults (clamped when the initiator sends more).
const DEFAULT_FIRST_BURST: u32 = 65536;
const DEFAULT_MAX_BURST: u32 = 262144;
/// Upper bound for the negotiated MaxRecvDataSegmentLength: the BHS
/// DataSegmentLength field is 24 bits (RFC 3720 §3.1).
const HARD_CAP: usize = 0xFF_FFFF;
/// Largest login data segment accepted for negotiation.
const LOGIN_MAX: usize = 4096;
/// SCSI status BUSY (SPC-3); no constant exists in the PDU module.
const STATUS_BUSY: u8 = 0x08;

// ── Login parameter table ──────────────────────────────────────────

struct LoginParam {
    key: &'static str,
    value: Option<&'static str>,
    always: bool,
}

const LOGIN_TABLE: &[LoginParam] = &[
    LoginParam {
        key: "TargetAlias",
        value: Some("SnowSCSI"),
        always: true,
    },
    LoginParam {
        // AuthMethod=None only; CHAP/KRB5 omitted due to no-alloc
        // constraint (RFC 3720 §8.2.1 CHAP MUST is a known gap, documented).
        key: "AuthMethod",
        value: Some("None"),
        always: false,
    },
    LoginParam {
        key: "HeaderDigest",
        value: Some("None"),
        always: false,
    },
    LoginParam {
        key: "DataDigest",
        value: Some("None"),
        always: false,
    },
    LoginParam {
        key: "InitialR2T",
        value: Some("Yes"),
        always: false,
    },
    LoginParam {
        key: "ImmediateData",
        value: Some("Yes"),
        always: false,
    },
    LoginParam {
        key: "MaxBurstLength",
        value: None,
        always: false,
    },
    LoginParam {
        key: "FirstBurstLength",
        value: None,
        always: false,
    },
    LoginParam {
        key: "MaxRecvDataSegmentLength",
        value: None, // advertised dynamically (buffer-derived, §6.4.1)
        always: false,
    },
    LoginParam {
        key: "MaxOutstandingR2T",
        value: Some("1"),
        always: false,
    },
    LoginParam {
        key: "ErrorRecoveryLevel",
        value: Some("0"),
        always: false,
    },
    LoginParam {
        key: "MaxConnections",
        value: Some("1"),
        always: false,
    },
    LoginParam {
        key: "TargetPortalGroupTag",
        value: Some("1"),
        always: true,
    },
    LoginParam {
        key: "DataPDUInOrder",
        value: None,
        always: false,
    },
    LoginParam {
        key: "DataSequenceInOrder",
        value: None,
        always: false,
    },
    LoginParam {
        key: "DefaultTime2Wait",
        value: None,
        always: false,
    },
    LoginParam {
        key: "DefaultTime2Retain",
        value: None,
        always: false,
    },
    LoginParam {
        key: "IFMarker",
        value: None,
        always: false,
    },
    LoginParam {
        key: "OFMarker",
        value: None,
        always: false,
    },
];

/// Initiator-only keys never echoed in a Login Response (RFC 3720 §12.4).
const SKIP_KEYS: &[&str] = &[
    "InitiatorName",
    "InitiatorAlias",
    "SessionType",
    "TargetName",
];

// ── Session state machine ──────────────────────────────────────────

/// One shell-visible position of the session.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Session {
    /// Waiting for the BHS of the next PDU.
    RecvPdu,
    /// Waiting for the remainder of the current PDU (stored at
    /// `work[BHS_SIZE..]`).
    RecvData { total: usize },
    /// Waiting for a Data-Out BHS solicited by an R2T.
    OutBhs,
    /// Waiting for a Data-Out data segment; the shell stores it at the final
    /// offset inside the SCSI data area.
    OutData { dsl: usize },
    /// Waiting for the Data-Out padding (discarded into `work[0..pad]`).
    OutPad { pad: usize },
    /// A complete PDU is staged in `work[..len]` and must be sent.
    Send { len: usize, kind: SendKind },
    /// Terminal (Logout / fatal protocol error / peer close).
    Closed,
}

/// Why a staged PDU is being sent; decides the transition on `HostSent`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum SendKind {
    /// Any PDU after which the session keeps serving (login, NOP, text,
    /// terminal status).
    Continue,
    /// Close the connection after this PDU (logout, reject).
    Close,
    /// A task-management response; an abort may still have to settle the
    /// command afterwards.
    Tmf,
    /// A terminal SCSI status PDU (`itt` identifies the command). Sending it
    /// completes the delivery booked for that command; `autosense` names the
    /// LUN whose saved sense instance the PDU carries (consumed only once the
    /// send is observed and only when it matches that instance).
    Status {
        /// Initiator Task Tag of the command whose status this PDU carries.
        itt: u32,
        /// LUN and sense carried as autosense by this status, if any.
        autosense: Option<(usize, Sense)>,
    },
    /// An R2T; the next wire action is the Data-Out BHS.
    R2t,
    /// An intermediate Data-In chunk; the command send phase resumes.
    DataIn,
}

/// Transport-side host data phase of the one active command.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum HostPhase {
    /// No host data phase (yet).
    Idle,
    /// Data-In phase.
    Send(SendPhase),
    /// Data-Out phase.
    Recv(RecvPhase),
}

/// Data-In progress.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct SendPhase {
    token: HostToken,
    /// Total bytes of the published plan (the device's send length).
    total: u32,
    /// Bytes already handed to the wire.
    sent: u32,
    /// DataSN of the next Data-In PDU.
    data_sn: u32,
    /// Intermediate chunk staged by `poll_host`, not yet turned into a PDU.
    staged: Option<(u32, u32)>,
    /// Final chunk held back for the terminating Data-In (offset, length).
    held: Option<(u32, u32)>,
}

/// Data-Out progress.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct RecvPhase {
    token: HostToken,
    /// Total bytes of the published plan (the device's receive length).
    total: u32,
    /// Bytes accepted so far (immediate data included).
    accepted: u32,
    /// Next R2TSN.
    r2t_sn: u32,
    /// DataSN expected in the next Data-Out PDU of the current burst.
    data_sn: u32,
    /// Bytes still expected in the current burst.
    burst_remaining: u32,
    /// The outer step must send an R2T for the current burst.
    r2t_pending: bool,
    /// A Data-Out PDU was accounted but the runner has not consumed the fact.
    consumed: bool,
    /// Every byte of the plan was received.
    done: bool,
}

/// Per-connection iSCSI session state.
///
/// `cmd_sn` is the last consumed CmdSN; non-immediate commands are accepted
/// only when `CmdSN == cmd_sn + 1` (queue depth 1, MaxCmdSN = ExpCmdSN).
#[derive(Debug)]
pub struct IscsiSession {
    cmd_sn: u32,
    stat_sn: Cell<u32>,
    stage: LoginStage,
    max_recv_data_segment: u32,
    neg: NegotiatedParams,
    is_discovery: bool,
    session: Session,
    /// BHS of the PDU currently being framed: saved on the BHS read.
    bhs: [u8; BHS_SIZE],
    /// Identity of the core command in flight, if any.
    cmd_active: bool,
    cmd_lun: usize,
    cmd_itt: u32,
    cmd_direction: Direction,
    cmd_w: bool,
    /// Immediate write bytes already in the SCSI data area.
    immediate: u32,
    /// The single plan published by the device for the active command.
    plan: DataPlan,
    /// Host data phase of the active command.
    host: HostPhase,
    /// Token generation; a token is dead after `Ready`/`cancel`.
    host_gen: u32,
    /// Delivery state of the current completion.
    delivery: Delivery,
    /// ITT of the terminal status PDU currently staged on the wire, if any.
    ///
    /// It is cleared when that PDU is observed sent; a peer/transport failure
    /// while it is set means the status never reached the host.
    status_itt: Option<u32>,
    /// LUN and sense carried by the status PDU currently staged.
    ///
    /// Staging the PDU does not consume the saved instance: only an observed
    /// send (`SendKind::Status`) does, and only when the carried sense is the
    /// device's saved instance, so a failed send leaves the sense for a later
    /// REQUEST SENSE.
    status_autosense: Option<(usize, Sense)>,
    /// A TMF ABORT TASK was queued and the command still has to settle.
    abort_pending: bool,
    /// LUN whose resident long operation the idle entries advance.
    long_lun: Option<usize>,
    /// Length of the SCSI data area handed to the core for the current step.
    bank_len: usize,
}

impl Default for IscsiSession {
    fn default() -> Self {
        Self::new()
    }
}

/// What one entry wants the shell to do next (no borrows).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Emit {
    Recv { offset: usize, len: usize },
    Send(usize),
    Closed,
    Error(TargetError),
}

impl IscsiSession {
    /// Create a session in the default (pre-login) state.
    pub fn new() -> Self {
        crate::info!("new iSCSI session");
        Self {
            cmd_sn: 0,
            stat_sn: Cell::new(0),
            stage: LoginStage::Security,
            max_recv_data_segment: MAX_DATA_SEGMENT,
            neg: NegotiatedParams::default(),
            is_discovery: false,
            session: Session::RecvPdu,
            bhs: [0u8; BHS_SIZE],
            cmd_active: false,
            cmd_lun: 0,
            cmd_itt: 0,
            cmd_direction: Direction::None,
            cmd_w: false,
            immediate: 0,
            plan: DataPlan {
                direction: Direction::None,
                bytes: 0,
            },
            host: HostPhase::Idle,
            host_gen: 1,
            delivery: Delivery::NotApplicable,
            status_itt: None,
            status_autosense: None,
            abort_pending: false,
            long_lun: None,
            bank_len: 0,
        }
    }

    /// Current login stage.
    pub fn stage(&self) -> LoginStage {
        self.stage
    }

    /// The shell can no longer reach the peer (read/write failure or EOF
    /// mid-PDU).
    ///
    /// Books `Failed` for a completion whose status PDU never reached the
    /// wire; a command whose status was already observed sent keeps
    /// `Complete`. The shell ends the connection right after this.
    pub fn connection_lost(&mut self) {
        if self.cmd_active || self.status_itt.is_some() {
            self.delivery = Delivery::Failed;
        }
        self.cmd_active = false;
        self.status_itt = None;
        self.status_autosense = None;
        self.host = HostPhase::Idle;
    }

    // ── Poll interface (non-blocking state machine) ───────────────

    /// Non-blocking state-machine step: consume one [`Event`] and return the
    /// next [`Action`].
    ///
    /// `work` is the single time-multiplexed PDU bank
    /// (`>= crate::MIN_DATA_LEN + BHS_SIZE`): incoming bytes land at the
    /// offset the previous action requested, the 48-byte BHS at
    /// `work[..BHS_SIZE]`, and the SCSI data area at `work[BHS_SIZE..]`.
    /// The whole host transfer of a command must fit in that data area
    /// (`work.len() - BHS_SIZE`); a larger transfer is answered with a
    /// target-side resource sense instead of being streamed.
    /// `scratch` is the resident long-operation bank (`>= MIN_DATA_LEN`).
    ///
    /// `target` owns the LUN slots, `storage` executes the device's storage
    /// operations; the session itself implements the [`HostTransport`] data
    /// seam and performs at most one command step per entry.
    pub fn poll<'a, S: RuntimeSet>(
        &'a mut self,
        ev: Event,
        work: &'a mut [u8],
        scratch: &'a mut [u8],
        target: &'a mut Target<S>,
        storage: &'a mut dyn Storage,
    ) -> Action<'a> {
        if work.len() < crate::MIN_DATA_LEN + BHS_SIZE {
            return Action::Error(TargetError::WorkBufTooSmall);
        }
        if scratch.len() < crate::MIN_DATA_LEN {
            return Action::Error(TargetError::WorkBufTooSmall);
        }
        let emit = self.entry(ev, work, scratch, target, storage);
        match emit {
            Emit::Recv { offset, len } => Action::HostRecv { offset, len },
            Emit::Send(len) => Action::HostSend {
                bytes: &work[..len],
                prefetch: None,
            },
            Emit::Closed => Action::Closed,
            Emit::Error(e) => Action::Error(e),
        }
    }

    fn entry<S: RuntimeSet>(
        &mut self,
        ev: Event,
        work: &mut [u8],
        scratch: &mut [u8],
        target: &mut Target<S>,
        storage: &mut dyn Storage,
    ) -> Emit {
        // Every entry that starts at a PDU boundary and owns no command also
        // advances the resident long operation once: one poll per entry.
        if self.session == Session::RecvPdu && !self.cmd_active {
            if let Some(out) = self.idle_entry(work, scratch, target, storage) {
                return out;
            }
        }
        match ev {
            Event::Tick => self.expectation(),
            Event::HostRecv { len } => self.on_recv(len, work, scratch, target, storage),
            Event::HostSent => self.on_sent(work, scratch, target, storage),
        }
    }

    /// The action that re-emits the current position.
    fn expectation(&self) -> Emit {
        match self.session {
            Session::RecvPdu | Session::OutBhs => Emit::Recv {
                offset: 0,
                len: BHS_SIZE,
            },
            Session::RecvData { total } => Emit::Recv {
                offset: BHS_SIZE,
                len: total,
            },
            Session::OutData { dsl } => {
                let accepted = match self.host {
                    HostPhase::Recv(p) => p.accepted as usize,
                    _ => 0,
                };
                Emit::Recv {
                    offset: BHS_SIZE + accepted,
                    len: dsl,
                }
            }
            Session::OutPad { pad } => Emit::Recv {
                offset: 0,
                len: pad,
            },
            Session::Send { len, .. } => Emit::Send(len),
            Session::Closed => Emit::Closed,
        }
    }

    /// Advance a resident long operation and the target lifecycle once per
    /// idle entry.
    fn idle_entry<S: RuntimeSet>(
        &mut self,
        work: &mut [u8],
        scratch: &mut [u8],
        target: &mut Target<S>,
        storage: &mut dyn Storage,
    ) -> Option<Emit> {
        if let Some(lun) = self.long_lun {
            match target.poll_long_entry_rt(lun, storage, work, scratch) {
                Ok(info) => {
                    if !matches!(info.phase, LongPhase::Foreground | LongPhase::Background) {
                        self.long_lun = None;
                    }
                }
                Err(fault) => {
                    self.long_lun = None;
                    target.fatal(fault);
                }
            }
        }
        match target.tick() {
            crate::core::RunOutcome::Ended { .. } => {
                self.session = Session::Closed;
                Some(Emit::Closed)
            }
            _ => None,
        }
    }

    fn on_recv<S: RuntimeSet>(
        &mut self,
        len: usize,
        work: &mut [u8],
        scratch: &mut [u8],
        target: &mut Target<S>,
        storage: &mut dyn Storage,
    ) -> Emit {
        match self.session {
            Session::RecvPdu => {
                if len != BHS_SIZE || work.len() < BHS_SIZE {
                    return Emit::Error(TargetError::Internal);
                }
                self.bhs.copy_from_slice(&work[..BHS_SIZE]);
                match self.pdu_remainder(work.len()) {
                    Ok(0) => self.dispatch(work, scratch, target, storage),
                    Ok(total) => {
                        self.session = Session::RecvData { total };
                        Emit::Recv {
                            offset: BHS_SIZE,
                            len: total,
                        }
                    }
                    Err(e) => Emit::Error(e),
                }
            }
            Session::RecvData { total } => {
                if len != total {
                    return Emit::Error(TargetError::Internal);
                }
                self.session = Session::RecvPdu;
                self.dispatch(work, scratch, target, storage)
            }
            Session::OutBhs => {
                if len != BHS_SIZE {
                    return Emit::Error(TargetError::Internal);
                }
                self.bhs.copy_from_slice(&work[..BHS_SIZE]);
                let bhs = Bhs::from_bytes(self.bhs);
                if bhs.total_ahs_length() != 0 {
                    return self.reject(work, reject::PROTOCOL_ERROR);
                }
                let dsl = bhs.data_segment_len() as usize;
                if bhs.opcode() != op::SCSI_DATA_OUT {
                    // A zero-length TMF/NOP may interleave with a data-out
                    // burst (RFC 3720 §10.5); everything else is a protocol
                    // error in this state.
                    if dsl == 0 && matches!(bhs.opcode(), op::SCSI_TASK_REQ | op::NOP_OUT) {
                        self.session = Session::RecvPdu;
                        return self.dispatch(work, scratch, target, storage);
                    }
                    return self.reject(work, reject::PROTOCOL_ERROR);
                }
                let accepted = match self.host {
                    HostPhase::Recv(p) => p.accepted,
                    _ => return Emit::Error(TargetError::Internal),
                };
                if let Some(reason) = self.check_data_out(&bhs, dsl) {
                    return self.reject(work, reason);
                }
                if dsl == 0 {
                    return self.finish_data_out(0, work, scratch, target, storage);
                }
                let end = BHS_SIZE + accepted as usize + dsl;
                if end > work.len() {
                    return Emit::Error(TargetError::WorkBufTooSmall);
                }
                self.session = Session::OutData { dsl };
                Emit::Recv {
                    offset: BHS_SIZE + accepted as usize,
                    len: dsl,
                }
            }
            Session::OutData { dsl } => {
                if len != dsl {
                    return Emit::Error(TargetError::Internal);
                }
                let pad = pdu_pad_len(dsl as u32) as usize;
                if pad > 0 {
                    self.session = Session::OutPad { pad };
                    Emit::Recv {
                        offset: 0,
                        len: pad,
                    }
                } else {
                    self.finish_data_out(dsl as u32, work, scratch, target, storage)
                }
            }
            Session::OutPad { pad } => {
                if len != pad {
                    return Emit::Error(TargetError::Internal);
                }
                // The Data-Out length is not recoverable from the pad frame;
                // the accepted offsets were validated on the BHS and the data
                // segment was placed by the shell already.
                let dsl = match self.bhs_data_out_len() {
                    Some(dsl) => dsl,
                    None => return Emit::Error(TargetError::Internal),
                };
                self.finish_data_out(dsl, work, scratch, target, storage)
            }
            Session::Send { .. } => Emit::Error(TargetError::Internal),
            Session::Closed => Emit::Closed,
        }
    }

    fn on_sent<S: RuntimeSet>(
        &mut self,
        work: &mut [u8],
        scratch: &mut [u8],
        target: &mut Target<S>,
        storage: &mut dyn Storage,
    ) -> Emit {
        let kind = match self.session {
            Session::Send { kind, .. } => kind,
            Session::Closed => return Emit::Closed,
            _ => return Emit::Error(TargetError::Internal),
        };
        match kind {
            SendKind::Close => {
                self.session = Session::Closed;
                Emit::Closed
            }
            SendKind::Continue => {
                self.session = Session::RecvPdu;
                self.resume_idle(work, scratch, target, storage)
            }
            SendKind::Tmf => {
                if self.abort_pending {
                    self.abort_pending = false;
                    return self.step(work, scratch, target, storage);
                }
                self.session = Session::RecvPdu;
                self.resume_idle(work, scratch, target, storage)
            }
            SendKind::R2t => {
                self.session = Session::OutBhs;
                self.expectation()
            }
            SendKind::Status { itt, autosense } => {
                if self.status_itt == Some(itt) {
                    self.delivery = Delivery::Complete;
                    self.status_itt = None;
                    if let Some((lun, sense)) = autosense {
                        // The completion frame carried the saved sense to the
                        // host, exactly like a completed REQUEST SENSE. A
                        // failed send never reaches this point, and a
                        // fabricated completion does not match the saved
                        // instance so it consumes nothing.
                        let _ = target.autosense_delivered_rt(lun, sense);
                    }
                }
                self.status_autosense = None;
                self.session = Session::RecvPdu;
                self.resume_idle(work, scratch, target, storage)
            }
            SendKind::DataIn => {
                if let HostPhase::Send(p) = &mut self.host {
                    if let Some((_, len)) = p.staged.take() {
                        p.sent = p.sent.saturating_add(len);
                        p.data_sn = p.data_sn.wrapping_add(1);
                    }
                }
                self.step(work, scratch, target, storage)
            }
        }
    }

    /// Return to the position the session was at before an interleaved PDU.
    fn resume_idle<S: RuntimeSet>(
        &mut self,
        work: &mut [u8],
        scratch: &mut [u8],
        target: &mut Target<S>,
        storage: &mut dyn Storage,
    ) -> Emit {
        if self.cmd_active {
            match self.host {
                HostPhase::Recv(p) if p.r2t_pending => {
                    self.build_r2t(work);
                    self.session = Session::Send {
                        len: BHS_SIZE,
                        kind: SendKind::R2t,
                    };
                    Emit::Send(BHS_SIZE)
                }
                HostPhase::Recv(_) => {
                    self.session = Session::OutBhs;
                    Emit::Recv {
                        offset: 0,
                        len: BHS_SIZE,
                    }
                }
                _ => {
                    self.session = Session::RecvPdu;
                    Emit::Recv {
                        offset: 0,
                        len: BHS_SIZE,
                    }
                }
            }
        } else if let Some(out) = self.idle_entry(work, scratch, target, storage) {
            out
        } else {
            self.expectation()
        }
    }

    // ── PDU framing helpers ───────────────────────────────────────

    /// The length of the current PDU's remainder (AHS + data + padding),
    /// computed from the saved BHS.
    fn pdu_remainder(&self, work_len: usize) -> Result<usize, TargetError> {
        let bhs = Bhs::from_bytes(self.bhs);
        let dsl = bhs.data_segment_len() as usize;
        let total =
            usize::from(bhs.total_ahs_length()) * 4 + dsl + pdu_pad_len(dsl as u32) as usize;
        if BHS_SIZE + total > work_len {
            return Err(TargetError::WorkBufTooSmall);
        }
        Ok(total)
    }

    /// Data-Out length of the saved BHS (used after the padding read).
    fn bhs_data_out_len(&self) -> Option<u32> {
        let bhs = Bhs::from_bytes(self.bhs);
        if bhs.opcode() == op::SCSI_DATA_OUT {
            Some(bhs.data_segment_len())
        } else {
            None
        }
    }

    fn check_data_out(&self, bhs: &Bhs, dsl: usize) -> Option<u8> {
        let p = match self.host {
            HostPhase::Recv(p) => p,
            _ => return Some(reject::PROTOCOL_ERROR),
        };
        if bhs.itt() != self.cmd_itt || bhs.ttt() != TTT {
            return Some(reject::INVALID_PDU_FIELD);
        }
        if bhs.buffer_offset() != p.accepted {
            return Some(reject::INVALID_PDU_FIELD);
        }
        if bhs.data_sn() != p.data_sn {
            return Some(reject::INVALID_PDU_FIELD);
        }
        if dsl > self.max_recv_data_segment as usize {
            return Some(reject::PROTOCOL_ERROR);
        }
        if dsl as u64 > p.burst_remaining as u64 {
            return Some(reject::INVALID_PDU_FIELD);
        }
        None
    }

    fn finish_data_out<S: RuntimeSet>(
        &mut self,
        dsl: u32,
        work: &mut [u8],
        scratch: &mut [u8],
        target: &mut Target<S>,
        storage: &mut dyn Storage,
    ) -> Emit {
        if let HostPhase::Recv(p) = &mut self.host {
            p.accepted = p.accepted.saturating_add(dsl);
            p.data_sn = p.data_sn.wrapping_add(1);
            p.burst_remaining = p.burst_remaining.saturating_sub(dsl);
            p.consumed = true;
        } else {
            return Emit::Error(TargetError::Internal);
        }
        crate::trace!(
            "  Data-Out: len={} accepted={}",
            dsl,
            match self.host {
                HostPhase::Recv(p) => p.accepted,
                _ => 0,
            }
        );
        self.step(work, scratch, target, storage)
    }

    // ── Command driving ───────────────────────────────────────────

    fn drive<S: RuntimeSet>(
        &mut self,
        target: &mut Target<S>,
        storage: &mut dyn Storage,
        work: &mut [u8],
    ) -> Stepped {
        let lun = self.cmd_lun;
        let bank = &mut work[BHS_SIZE..];
        self.bank_len = bank.len();
        match target.drive_step_rt(lun, storage, self, bank, &mut []) {
            Ok(crate::core::DriveStep::Pending) => Stepped::Pending,
            Ok(crate::core::DriveStep::Done(completion)) => Stepped::Done(completion),
            Ok(crate::core::DriveStep::Control(outcome)) => Stepped::Control(outcome),
            Err(fault) => Stepped::Err(fault),
        }
    }

    /// One step of the active command, then map its outcome to a wire action.
    fn step<S: RuntimeSet>(
        &mut self,
        work: &mut [u8],
        _scratch: &mut [u8],
        target: &mut Target<S>,
        storage: &mut dyn Storage,
    ) -> Emit {
        match self.drive(target, storage, work) {
            Stepped::Pending => match self.host {
                HostPhase::Send(p) => match p.staged {
                    Some((offset, len)) => self.emit_data_in(work, offset, len),
                    None => Emit::Error(TargetError::Internal),
                },
                HostPhase::Recv(p) => {
                    if p.r2t_pending {
                        self.build_r2t(work);
                        self.session = Session::Send {
                            len: BHS_SIZE,
                            kind: SendKind::R2t,
                        };
                        Emit::Send(BHS_SIZE)
                    } else {
                        self.session = Session::OutBhs;
                        Emit::Recv {
                            offset: 0,
                            len: BHS_SIZE,
                        }
                    }
                }
                HostPhase::Idle => {
                    // The command is pending on storage. There is no timer in
                    // this state machine, so the next PDU (e.g. a TMF) drives
                    // the next step.
                    self.session = Session::RecvPdu;
                    Emit::Recv {
                        offset: 0,
                        len: BHS_SIZE,
                    }
                }
            },
            Stepped::Done(completion) => self.finish_command(completion, work, target),
            Stepped::Control(_outcome) => {
                crate::debug!("target control outcome");
                if self.cmd_active || self.status_itt.is_some() {
                    // The connection is closing before the status PDU reached
                    // the host.
                    self.delivery = Delivery::Failed;
                    self.status_itt = None;
                }
                self.status_autosense = None;
                self.cmd_active = false;
                self.host = HostPhase::Idle;
                self.session = Session::Closed;
                Emit::Closed
            }
            Stepped::Err(fault) => {
                crate::debug!("command step failed: {:?}", fault_state(fault));
                self.host = HostPhase::Idle;
                self.status_autosense = None;
                // A runner-level contract/boundary fault means the command
                // cannot continue; reject the offending PDU and close. The
                // reject path books the failed delivery of any outstanding
                // status before clearing the command.
                self.reject(work, reject::PROTOCOL_ERROR)
            }
        }
    }

    fn finish_command<S: RuntimeSet>(
        &mut self,
        completion: Completion,
        work: &mut [u8],
        target: &mut Target<S>,
    ) -> Emit {
        let itt = self.cmd_itt;
        let lun = self.cmd_lun;
        let was_to_host = self.cmd_direction == Direction::ToHost;
        let phase = self.host;
        self.cmd_active = false;
        self.host = HostPhase::Idle;
        let (sent, data_sn, held) = match phase {
            HostPhase::Send(p) => (p.sent, p.data_sn, p.held),
            _ => (0, 0, None),
        };
        let emit = match completion {
            Completion::Good => match held {
                Some((offset, len)) => {
                    self.emit_data_in_final(work, offset, len, data_sn, status::GOOD)
                }
                None if was_to_host => self.emit_data_in_final(work, 0, 0, data_sn, status::GOOD),
                None => self.emit_response(work, itt, status::GOOD, None),
            },
            Completion::Check(sense) => {
                if let Some((offset, len)) = held {
                    // Data already streamed: the last chunk terminates the
                    // transfer; no autosense field exists in a Data-In PDU.
                    self.emit_data_in_final(work, offset, len, data_sn, status::CHECK_CONDITION)
                } else if sent > 0 {
                    self.emit_data_in_final(work, 0, 0, data_sn, status::CHECK_CONDITION)
                } else {
                    // The completion frame carries the sense as autosense. The
                    // saved instance is consumed only when the status send is
                    // observed, not while staging the PDU.
                    self.status_autosense = Some((lun, sense));
                    self.emit_response(work, itt, status::CHECK_CONDITION, Some(sense))
                }
            }
            Completion::Busy => self.emit_response(work, itt, STATUS_BUSY, None),
            Completion::ReservationConflict | Completion::TaskSetFull => self.emit_response(
                work,
                itt,
                status::CHECK_CONDITION,
                Some(crate::core::COMMAND_ABORTED),
            ),
        };
        // Arm the long-operation fan-out for this LUN if the command left the
        // medium busy.
        if let Ok(info) = target.snapshot_rt(lun) {
            if matches!(
                info.long.phase,
                LongPhase::Foreground | LongPhase::Background
            ) {
                self.long_lun = Some(lun);
            }
        }
        self.immediate = 0;
        emit
    }

    // ── Response PDU builders ─────────────────────────────────────

    fn emit_response(
        &mut self,
        work: &mut [u8],
        itt: u32,
        scsi_status: u8,
        sense: Option<Sense>,
    ) -> Emit {
        self.note_status(itt);
        let autosense = self.status_autosense.take();
        let len = self.build_response(work, itt, scsi_status, sense);
        self.session = Session::Send {
            len,
            kind: SendKind::Status { itt, autosense },
        };
        Emit::Send(len)
    }

    /// Remember that `itt`'s terminal status PDU is now staged.
    ///
    /// Only the active command's status counts: a BUSY response emitted for an
    /// interleaved PDU must not overwrite the delivery state of the command
    /// that is still running.
    fn note_status(&mut self, itt: u32) {
        if itt == self.cmd_itt {
            self.status_itt = Some(itt);
        }
    }

    fn build_response(
        &mut self,
        work: &mut [u8],
        itt: u32,
        scsi_status: u8,
        sense: Option<Sense>,
    ) -> usize {
        let mut bhs = Bhs::new();
        bhs.set_opcode(op::SCSI_RESP);
        bhs.set_flags(flag::F_BIT);
        bhs.set_itt(itt);
        bhs.set_status(scsi_status);
        bhs.set_stat_sn(self.stat_sn.get());
        bhs.set_exp_cmd_sn(self.cmd_sn.wrapping_add(1));
        bhs.set_max_cmd_sn(self.cmd_sn.wrapping_add(1));
        let mut dlen = 0usize;
        if scsi_status == status::CHECK_CONDITION {
            if let Some(sense) = sense {
                work[BHS_SIZE] = 0;
                work[BHS_SIZE + 1] = 18;
                sense_write_fixed(sense, &mut work[BHS_SIZE + 2..BHS_SIZE + 20]);
                dlen = 20;
            }
        }
        bhs.set_data_segment_len(dlen as u32);
        work[..BHS_SIZE].copy_from_slice(bhs.as_bytes());
        let total = BHS_SIZE + dlen;
        let pad = pdu_pad_len(dlen as u32) as usize;
        work[total..total + pad].fill(0);
        self.stat_sn.set(self.stat_sn.get().wrapping_add(1));
        total + pad
    }

    /// Intermediate Data-In chunk: F=0, S=0, no status.
    fn emit_data_in(&mut self, work: &mut [u8], offset: u32, len: u32) -> Emit {
        let data_sn = match self.host {
            HostPhase::Send(p) => p.data_sn,
            _ => return Emit::Error(TargetError::Internal),
        };
        let total = self.build_data_in(work, self.cmd_itt, offset, len, data_sn, false, 0);
        self.session = Session::Send {
            len: total,
            kind: SendKind::DataIn,
        };
        Emit::Send(total)
    }

    /// Terminating Data-In PDU (F=1, S=1) carrying the fixed status.
    fn emit_data_in_final(
        &mut self,
        work: &mut [u8],
        offset: u32,
        len: u32,
        data_sn: u32,
        status: u8,
    ) -> Emit {
        self.note_status(self.cmd_itt);
        let total = self.build_data_in(work, self.cmd_itt, offset, len, data_sn, true, status);
        self.session = Session::Send {
            len: total,
            kind: SendKind::Status {
                itt: self.cmd_itt,
                autosense: None,
            },
        };
        Emit::Send(total)
    }

    #[allow(clippy::too_many_arguments)]
    fn build_data_in(
        &mut self,
        work: &mut [u8],
        itt: u32,
        offset: u32,
        len: u32,
        data_sn: u32,
        final_pdu: bool,
        scsi_status: u8,
    ) -> usize {
        let len = len as usize;
        if offset > 0 && len > 0 {
            let start = BHS_SIZE + offset as usize;
            let end = start + len;
            work.copy_within(start..end, BHS_SIZE);
        }
        let mut bhs = Bhs::new();
        bhs.set_opcode(op::SCSI_DATA_IN);
        if final_pdu {
            bhs.set_flags(flag::F_BIT | flag::S_BIT);
            bhs.set_status(scsi_status);
        }
        bhs.set_itt(itt);
        bhs.set_data_sn(data_sn);
        bhs.set_buffer_offset(offset);
        bhs.set_data_segment_len(len as u32);
        bhs.set_stat_sn(self.stat_sn.get());
        bhs.set_exp_cmd_sn(self.cmd_sn.wrapping_add(1));
        bhs.set_max_cmd_sn(self.cmd_sn.wrapping_add(1));
        work[..BHS_SIZE].copy_from_slice(bhs.as_bytes());
        let total = BHS_SIZE + len;
        // Intermediate chunks are 4-aligned, so only a terminating PDU can
        // need padding; its bytes follow the last data byte.
        let pad = if final_pdu {
            pdu_pad_len(len as u32) as usize
        } else {
            0
        };
        if pad > 0 {
            work[total..total + pad].fill(0);
        }
        if final_pdu {
            self.stat_sn.set(self.stat_sn.get().wrapping_add(1));
        }
        total + pad
    }

    fn build_r2t(&mut self, work: &mut [u8]) {
        let p = match &mut self.host {
            HostPhase::Recv(p) => p,
            _ => return,
        };
        let desired = (u64::from(self.neg.max_burst_len))
            .min(u64::from(p.total.saturating_sub(p.accepted)))
            .min(u64::from(u32::MAX)) as u32;
        let mut bhs = Bhs::new();
        bhs.set_opcode(op::R2T);
        bhs.set_flags(flag::F_BIT);
        bhs.set_itt(self.cmd_itt);
        bhs.set_ttt(TTT);
        bhs.set_lun(self.cmd_lun as u8);
        bhs.set_stat_sn(self.stat_sn.get());
        bhs.set_exp_cmd_sn(self.cmd_sn.wrapping_add(1));
        bhs.set_max_cmd_sn(self.cmd_sn.wrapping_add(1));
        bhs.set_r2t_sn(p.r2t_sn);
        bhs.set_buffer_offset(p.accepted);
        bhs.set_desired_data_len(desired);
        crate::trace!(
            "R2T: R2TSN={} BO={} DesiredLen={} LUN={}",
            p.r2t_sn,
            p.accepted,
            desired,
            self.cmd_lun
        );
        p.r2t_sn = p.r2t_sn.wrapping_add(1);
        p.data_sn = 0;
        p.burst_remaining = desired;
        p.r2t_pending = false;
        work[..BHS_SIZE].copy_from_slice(bhs.as_bytes());
    }

    fn reject(&mut self, work: &mut [u8], reason: u8) -> Emit {
        let rejected = Bhs::from_bytes(self.bhs);
        crate::warn!(
            "rejecting {} (0x{:02X}) reason={} (0x{:02X})",
            iscsi_opcode_name(rejected.opcode()),
            rejected.opcode(),
            reason,
            reason
        );
        let mut bhs = Bhs::new();
        bhs.set_opcode(op::REJECT);
        bhs.set_flags(flag::F_BIT);
        bhs.set_reject_reason(reason);
        bhs.set_itt(0xFFFF_FFFF);
        bhs.set_stat_sn(self.stat_sn.get());
        bhs.set_exp_cmd_sn(self.cmd_sn.wrapping_add(1));
        bhs.set_max_cmd_sn(self.cmd_sn.wrapping_add(1));
        bhs.set_data_segment_len(BHS_SIZE as u32);
        work[..BHS_SIZE].copy_from_slice(bhs.as_bytes());
        work[BHS_SIZE..2 * BHS_SIZE].copy_from_slice(rejected.as_bytes());
        let total = 2 * BHS_SIZE;
        let pad = pdu_pad_len(BHS_SIZE as u32) as usize;
        work[total..total + pad].fill(0);
        self.stat_sn.set(self.stat_sn.get().wrapping_add(1));
        self.session = Session::Send {
            len: total + pad,
            kind: SendKind::Close,
        };
        if self.cmd_active || self.status_itt.is_some() {
            // The connection ends without the terminal status: the completion
            // was never delivered.
            self.delivery = Delivery::Failed;
            self.status_itt = None;
        }
        // The staged status is discarded, so its autosense instance stays
        // available for a later REQUEST SENSE.
        self.status_autosense = None;
        if self.cmd_active {
            // The connection ends with the command still owned by the target.
            self.cmd_active = false;
        }
        Emit::Send(total + pad)
    }

    // ── PDU dispatch ──────────────────────────────────────────────

    fn dispatch<S: RuntimeSet>(
        &mut self,
        work: &mut [u8],
        scratch: &mut [u8],
        target: &mut Target<S>,
        storage: &mut dyn Storage,
    ) -> Emit {
        let bhs = Bhs::from_bytes(self.bhs);
        // AHS defense: assumes TotalAHSLength = 0.
        if bhs.total_ahs_length() != 0 {
            return self.reject(work, reject::PROTOCOL_ERROR);
        }
        let iscsi_op = bhs.opcode();
        crate::debug!(
            "recv {} (0x{:02X}) stage={:?} cmd_sn={} stat_sn={}",
            iscsi_opcode_name(iscsi_op),
            iscsi_op,
            self.stage,
            self.cmd_sn,
            self.stat_sn.get()
        );
        if self.stage != LoginStage::FullFeature {
            if iscsi_op != op::LOGIN_REQ {
                return self.reject(work, reject::PROTOCOL_ERROR);
            }
            return self.handle_login(work);
        }
        let dsl = bhs.data_segment_len() as usize;
        let pdu = Pdu { bhs, dsl };
        match iscsi_op {
            op::SCSI_CMD => self.handle_scsi_cmd(work, scratch, target, storage, &pdu),
            op::SCSI_TASK_REQ => self.handle_tmf(work, scratch, target, storage, &pdu),
            op::NOP_OUT => self.handle_nop(work, &pdu),
            op::LOGOUT_REQ => self.handle_logout(work, &pdu),
            op::TEXT_REQ => self.handle_text(work, &pdu),
            // A Data-Out PDU with no receive phase waiting for it belongs to a
            // task the target no longer owns — typically a burst still in
            // flight when ABORT TASK settled the command. Its status is already
            // on the wire, so the segment is dropped instead of tearing down a
            // session the initiator is still using.
            op::SCSI_DATA_OUT => {
                crate::debug!(
                    "discarding unsolicited Data-Out: itt=0x{:08X} len={}",
                    pdu.bhs.itt(),
                    dsl
                );
                self.expectation()
            }
            _ => self.reject(work, reject::PROTOCOL_ERROR),
        }
    }

    // ── Full Feature: SCSI Command ────────────────────────────────

    fn handle_scsi_cmd<S: RuntimeSet>(
        &mut self,
        work: &mut [u8],
        scratch: &mut [u8],
        target: &mut Target<S>,
        storage: &mut dyn Storage,
        pdu: &Pdu,
    ) -> Emit {
        let bhs = &pdu.bhs;
        let recv_cmd_sn = bhs.cmd_sn();
        let immediate_flag = bhs.as_bytes()[0] & 0x40 != 0;
        // Only a non-immediate command consumes a CmdSN (RFC 3720 §10.4.10):
        // an immediate one may carry a CmdSN outside the window and must not
        // move ExpCmdSN, or the initiator's next command falls out of range.
        if !immediate_flag {
            if recv_cmd_sn != self.cmd_sn.wrapping_add(1) {
                return Emit::Recv {
                    offset: 0,
                    len: BHS_SIZE,
                };
            }
            self.cmd_sn = recv_cmd_sn;
        }

        let itt = bhs.itt();
        if !bhs.lun_is_single_level() {
            return self.reject(work, reject::INVALID_PDU_FIELD);
        }
        let cdb = bhs.cdb();
        let scsi_opcode = opcode_from_cdb(cdb);
        let wire_lun = bhs.lun() as usize;
        let w_bit = bhs.as_bytes()[1] & 0x20 != 0;

        if self.cmd_active {
            // One command at a time; the window stays closed until its
            // response is sent.
            return self.emit_response(work, itt, STATUS_BUSY, None);
        }
        if pdu.dsl > self.max_recv_data_segment as usize {
            return self.reject(work, reject::PROTOCOL_ERROR);
        }
        if pdu.dsl > 0 && !w_bit {
            return self.reject(work, reject::PROTOCOL_ERROR);
        }

        // REPORT LUNS is a well-known command (SPC-3) and must be served from
        // any LUN, even an unsupported one. Any resident slot can answer it:
        // the response lists every LUN of the Target.
        let slot_count = target.slot_count();
        let lun = if wire_lun < slot_count {
            wire_lun
        } else if scsi_opcode == scsi_op::REPORT_LUNS && slot_count > 0 {
            0
        } else {
            wire_lun
        };

        crate::debug!(
            "scsi cmd: {} (0x{:02X}) itt=0x{:08X} lun={} cmd_sn={} dsl={}",
            opcode_name(scsi_opcode),
            scsi_opcode,
            itt,
            wire_lun,
            recv_cmd_sn,
            pdu.dsl
        );

        let direction = if w_bit {
            Direction::FromHost
        } else if data_in_opcode(scsi_opcode) {
            Direction::ToHost
        } else {
            Direction::None
        };

        self.cmd_itt = itt;
        self.cmd_lun = lun;
        self.cmd_direction = direction;
        self.cmd_w = w_bit;
        // Immediate write data of the command PDU already sits at
        // `work[BHS_SIZE..BHS_SIZE + dsl]`, which is the SCSI data area the
        // device receives into.
        self.immediate = if w_bit { pdu.dsl as u32 } else { 0 };
        self.plan = DataPlan {
            direction: Direction::None,
            bytes: 0,
        };
        self.host = HostPhase::Idle;
        self.delivery = Delivery::NotApplicable;
        self.status_itt = None;
        self.status_autosense = None;
        self.abort_pending = false;

        let ctx = CommandContext {
            lun: lun as u64,
            lun_count: 0,
            host_bytes: CommandContext::UNBOUNDED_HOST_BYTES,
            host_direction: direction,
        };
        match target.drive_start_rt(lun, ctx, cdb) {
            Ok(()) => {
                self.cmd_active = true;
                // A completion is owed from the first step until its status
                // PDU is on the wire.
                self.delivery = Delivery::Pending;
                self.step(work, scratch, target, storage)
            }
            Err(Fault::LunNotFound) => {
                self.delivery = Delivery::Pending;
                self.no_lun(work, cdb)
            }
            Err(Fault::Boundary) | Err(Fault::Contract) => {
                crate::debug!("lun {} refused the command", lun);
                self.emit_response(work, itt, STATUS_BUSY, None)
            }
            Err(_) => self.emit_response(
                work,
                itt,
                status::CHECK_CONDITION,
                Some(crate::core::INTERNAL_FAILURE),
            ),
        }
    }

    /// A well-formed command addressed to a LUN this target does not have:
    /// `05/25/00` as CHECK CONDITION (or GOOD sense data for REQUEST SENSE).
    fn no_lun(&mut self, work: &mut [u8], cdb: &[u8]) -> Emit {
        let itt = self.cmd_itt;
        let opcode = opcode_from_cdb(cdb);
        if opcode == scsi_op::REQUEST_SENSE {
            let alloc = cdb.get(4).copied().unwrap_or(0) as usize;
            let n = alloc.min(18);
            if n > 0 {
                sense_write_fixed(LUN_NOT_SUPPORTED, &mut work[BHS_SIZE..BHS_SIZE + n]);
            }
            // A Data-In carrying the fixed-format sense; the command is not
            // driven by any slot.
            self.note_status(itt);
            let total = self.build_data_in(work, itt, 0, n as u32, 0, true, status::GOOD);
            self.session = Session::Send {
                len: total,
                kind: SendKind::Status {
                    itt,
                    autosense: None,
                },
            };
            return Emit::Send(total);
        }
        self.emit_response(work, itt, status::CHECK_CONDITION, Some(LUN_NOT_SUPPORTED))
    }

    // ── Full Feature: Task Management / NOP / Logout ─────────────

    fn handle_tmf<S: RuntimeSet>(
        &mut self,
        work: &mut [u8],
        _scratch: &mut [u8],
        target: &mut Target<S>,
        _storage: &mut dyn Storage,
        pdu: &Pdu,
    ) -> Emit {
        let bhs = &pdu.bhs;
        let recv_cmd_sn = bhs.cmd_sn();
        let immediate_flag = bhs.as_bytes()[0] & 0x40 != 0;

        // RFC 3720 §10.4.10: ExpCmdSN is the next expected **non-immediate**
        // command. An immediate TMF carries a CmdSN only to scope group
        // functions, so it must not consume one — advancing here would make
        // the initiator's next command fall outside `ExpCmdSN..MaxCmdSN` (and
        // a conforming target silently drops it, wedging the session).
        if !immediate_flag {
            if recv_cmd_sn != self.cmd_sn.wrapping_add(1) {
                return Emit::Recv {
                    offset: 0,
                    len: BHS_SIZE,
                };
            }
            self.cmd_sn = recv_cmd_sn;
        }

        if !bhs.lun_is_single_level() {
            return self.reject(work, reject::INVALID_PDU_FIELD);
        }
        let lun = bhs.lun() as usize;
        let function = bhs.tmf_function();
        let response = match function {
            tmf::LOGICAL_UNIT_RESET => {
                if lun < target.slot_count() {
                    // The reset invalidates the initiator's cached
                    // logical-unit state: raise the reset unit attention and
                    // let the next reporting command deliver it.
                    match target.raise_ua_rt(lun, UaClass::LuReset) {
                        Ok(()) => tmf_response::COMPLETE,
                        Err(_) => tmf_response::LUN_DOES_NOT_EXIST,
                    }
                } else {
                    tmf_response::LUN_DOES_NOT_EXIST
                }
            }
            tmf::ABORT_TASK => {
                if lun < target.slot_count() {
                    // Only the active command can be aborted; the runner
                    // settles it at the next step with 0B/45/00.
                    let _ = target.request_control(Control::Abort);
                    self.abort_pending = self.cmd_active;
                    tmf_response::COMPLETE
                } else {
                    tmf_response::LUN_DOES_NOT_EXIST
                }
            }
            _ => tmf_response::NOT_SUPPORTED,
        };

        let mut resp = Bhs::new();
        resp.set_opcode(op::SCSI_TASK_RESP);
        resp.set_flags(flag::F_BIT);
        resp.set_itt(bhs.itt());
        resp.set_tmf_response(response);
        resp.set_stat_sn(self.stat_sn.get());
        resp.set_exp_cmd_sn(self.cmd_sn.wrapping_add(1));
        resp.set_max_cmd_sn(self.cmd_sn.wrapping_add(1));
        work[..BHS_SIZE].copy_from_slice(resp.as_bytes());
        let pad = pdu_pad_len(0) as usize;
        work[BHS_SIZE..BHS_SIZE + pad].fill(0);
        self.stat_sn.set(self.stat_sn.get().wrapping_add(1));
        self.session = Session::Send {
            len: BHS_SIZE + pad,
            kind: SendKind::Tmf,
        };
        Emit::Send(BHS_SIZE + pad)
    }

    fn handle_nop(&mut self, work: &mut [u8], pdu: &Pdu) -> Emit {
        let bhs = &pdu.bhs;
        let itt = bhs.itt();
        let immediate_flag = bhs.as_bytes()[0] & 0x40 != 0;

        if itt == 0xFFFF_FFFF {
            // RFC 3720 §10.18.1: ITT=0xFFFFFFFF requires I bit set, no response,
            // CmdSN not advanced.
            if !immediate_flag {
                return self.reject(work, reject::PROTOCOL_ERROR);
            }
            return Emit::Recv {
                offset: 0,
                len: BHS_SIZE,
            };
        }

        // RFC 3720 §3.2.2.1: non-immediate commands advance CmdSN.
        if !immediate_flag {
            let recv_cmd_sn = bhs.cmd_sn();
            if recv_cmd_sn != self.cmd_sn.wrapping_add(1) {
                return Emit::Recv {
                    offset: 0,
                    len: BHS_SIZE,
                };
            }
            self.cmd_sn = recv_cmd_sn;
        }

        let mut resp = Bhs::new();
        resp.set_opcode(op::NOP_IN);
        resp.set_flags(flag::F_BIT);
        resp.set_itt(itt);
        // RFC 3720 §10.18.1: Target Transfer Tag is copied from the NOP-Out
        // ("shall be copied"), so it is echoed — for the open-iscsi keepalive
        // NOP-Out it is 0xFFFFFFFF, but a data-transfer-terminating NOP-Out
        // legitimately carries a real TTT.
        resp.set_ttt(bhs.ttt());
        resp.set_stat_sn(self.stat_sn.get());
        resp.set_exp_cmd_sn(self.cmd_sn.wrapping_add(1));
        resp.set_max_cmd_sn(self.cmd_sn.wrapping_add(1));
        let dlen = if pdu.dsl <= MAX_DATA_SEGMENT as usize {
            resp.set_data_segment_len(pdu.dsl as u32);
            pdu.dsl
        } else {
            0
        };
        work[..BHS_SIZE].copy_from_slice(resp.as_bytes());
        let total = BHS_SIZE + dlen;
        let pad = pdu_pad_len(dlen as u32) as usize;
        work[total..total + pad].fill(0);
        self.stat_sn.set(self.stat_sn.get().wrapping_add(1));
        self.session = Session::Send {
            len: total + pad,
            kind: SendKind::Continue,
        };
        Emit::Send(total + pad)
    }

    fn handle_logout(&mut self, work: &mut [u8], pdu: &Pdu) -> Emit {
        let bhs = &pdu.bhs;
        let mut resp = Bhs::new();
        resp.set_opcode(op::LOGOUT_RESP);
        resp.set_flags(flag::F_BIT);
        resp.set_itt(bhs.itt());
        resp.set_stat_sn(self.stat_sn.get());
        resp.set_exp_cmd_sn(self.cmd_sn.wrapping_add(1));
        resp.set_max_cmd_sn(self.cmd_sn.wrapping_add(1));
        work[..BHS_SIZE].copy_from_slice(resp.as_bytes());
        let pad = pdu_pad_len(0) as usize;
        work[BHS_SIZE..BHS_SIZE + pad].fill(0);
        self.stat_sn.set(self.stat_sn.get().wrapping_add(1));
        self.session = Session::Send {
            len: BHS_SIZE + pad,
            kind: SendKind::Close,
        };
        Emit::Send(BHS_SIZE + pad)
    }

    fn handle_text(&mut self, work: &mut [u8], pdu: &Pdu) -> Emit {
        let bhs = &pdu.bhs;
        // F=0 (continuation) and non-0xFFFFFFFF TTT are not supported (no
        // fragmentation); the handler stays lenient for a minimal text BHS.
        if pdu.dsl > work.len() - BHS_SIZE {
            return Emit::Error(TargetError::WorkBufTooSmall);
        }
        let data = &work[BHS_SIZE..BHS_SIZE + pdu.dsl];
        let mut pos = 0usize;
        let mut found = false;
        let mut value: &[u8] = &[];
        while pos < data.len() {
            let end = data[pos..]
                .iter()
                .position(|&b| b == 0)
                .map_or(data.len(), |i| pos + i);
            let entry = &data[pos..end];
            if let Some(eq) = entry.iter().position(|&b| b == b'=') {
                let k = &entry[..eq];
                let v = &entry[eq + 1..];
                if k == b"SendTargets" {
                    found = true;
                    value = v;
                    break;
                }
            }
            if end >= data.len() {
                break;
            }
            pos = end + 1;
        }
        if !found {
            // Unknown Text key — reject.
            return self.reject(work, reject::COMMAND_NOT_SUPPORTED);
        }
        // Minimal SendTargets: static target only, no TargetAddress, no
        // continuation. RFC 3720 Appendix D: All / <iqn> / <empty> for
        // discovery vs operational.
        let should_return = value == b"All" || value.is_empty() || value == TARGET_NAME.as_bytes();
        let mut resp = Bhs::new();
        resp.set_opcode(op::TEXT_RESP);
        resp.set_flags(flag::F_BIT);
        resp.set_itt(bhs.itt());
        resp.set_ttt(0xFFFF_FFFF);
        resp.set_stat_sn(self.stat_sn.get());
        resp.set_exp_cmd_sn(self.cmd_sn.wrapping_add(1));
        resp.set_max_cmd_sn(self.cmd_sn.wrapping_add(1));
        let dlen: u32 = if should_return {
            let txt = TARGET_NAME.as_bytes();
            let prefix = b"TargetName=";
            let needed = prefix.len() + txt.len() + 1;
            if needed > work.len() - BHS_SIZE {
                return Emit::Error(TargetError::WorkBufTooSmall);
            }
            work[BHS_SIZE..BHS_SIZE + prefix.len()].copy_from_slice(prefix);
            work[BHS_SIZE + prefix.len()..BHS_SIZE + prefix.len() + txt.len()].copy_from_slice(txt);
            work[BHS_SIZE + prefix.len() + txt.len()] = 0;
            needed as u32
        } else {
            0
        };
        resp.set_data_segment_len(dlen);
        work[..BHS_SIZE].copy_from_slice(resp.as_bytes());
        let total = BHS_SIZE + dlen as usize;
        let pad = pdu_pad_len(dlen) as usize;
        work[total..total + pad].fill(0);
        self.stat_sn.set(self.stat_sn.get().wrapping_add(1));
        self.session = Session::Send {
            len: total + pad,
            kind: SendKind::Continue,
        };
        Emit::Send(total + pad)
    }

    // ── Login Phase ───────────────────────────────────────────────

    fn handle_login(&mut self, work: &mut [u8]) -> Emit {
        let pdu = Pdu {
            bhs: Bhs::from_bytes(self.bhs),
            dsl: Bhs::from_bytes(self.bhs).data_segment_len() as usize,
        };
        let req = &pdu.bhs;
        // Login C bit (byte1 bit6, RFC 3720 §10.12.1) — continuation not
        // supported; reject if set.
        if req.as_bytes()[1] & 0x40 != 0 {
            return self.reject(work, reject::PROTOCOL_ERROR);
        }
        // Version range check (RFC 3720 §10.13.5): we support 0x00 only.
        let req_min = req.version_min();
        if req_min > 0x00 {
            let mut resp = Bhs::new();
            resp.set_opcode(op::LOGIN_RESP);
            resp.set_itt(req.itt());
            resp.set_flags(req.csg() << flag::CSG_SHIFT);
            resp.as_mut_bytes()[2] = 0x00; // Version-max
            resp.as_mut_bytes()[3] = 0x00; // Version-active
            resp.as_mut_bytes()[8..14].copy_from_slice(&req.as_bytes()[8..14]);
            if req.tsih() == 0 {
                resp.as_mut_bytes()[15] = 1;
            } else {
                resp.as_mut_bytes()[14..16].copy_from_slice(&req.as_bytes()[14..16]);
            }
            resp.set_data_segment_len(0);
            resp.set_stat_sn(self.stat_sn.get());
            resp.set_exp_cmd_sn(req.cmd_sn());
            resp.set_max_cmd_sn(req.cmd_sn());
            resp.as_mut_bytes()[36] = 0x02; // Initiator Error
            resp.as_mut_bytes()[37] = 0x05; // Version not supported
            work[..BHS_SIZE].copy_from_slice(resp.as_bytes());
            let pad = pdu_pad_len(0) as usize;
            work[BHS_SIZE..BHS_SIZE + pad].fill(0);
            self.stat_sn.set(self.stat_sn.get().wrapping_add(1));
            self.session = Session::Send {
                len: BHS_SIZE + pad,
                kind: SendKind::Close,
            };
            return Emit::Send(BHS_SIZE + pad);
        }
        let req_csg = req.csg() & 0x03;
        let t = req.t_bit();

        // The receive data-segment capability scales with the caller's work
        // bank (data area = work minus BHS, 4-aligned, bounded by the 24-bit
        // DataSegmentLength field). Negotiation then clamps the initiator's
        // declared value to this cap.
        self.max_recv_data_segment =
            crate::scsi::device::data_capacity(work.len() - BHS_SIZE).min(HARD_CAP) as u32;

        // Negotiate: build the response text (updating `self.neg` alongside).
        let resp_len = if pdu.dsl <= LOGIN_MAX {
            let (head, tail) = work.split_at_mut(BHS_SIZE + pdu.dsl);
            let Some(n) = self.negotiate(&head[BHS_SIZE..], tail) else {
                return Emit::Error(TargetError::WorkBufTooSmall);
            };
            work.copy_within(BHS_SIZE + pdu.dsl..BHS_SIZE + pdu.dsl + n, BHS_SIZE);
            n
        } else {
            let Some(n) = self.negotiate(&[], &mut work[BHS_SIZE..]) else {
                return Emit::Error(TargetError::WorkBufTooSmall);
            };
            n
        };

        let nsg = if t {
            match req_csg {
                stage::SECURITY => stage::OP_PARAM,
                _ => stage::FULL_FEATURE,
            }
        } else {
            0
        };
        crate::debug!(
            "login: CSG={} NSG={} T={} TSIH={} itt=0x{:08X}",
            req_csg,
            nsg,
            t,
            req.tsih(),
            req.itt()
        );

        let mut resp = Bhs::new();
        resp.set_opcode(op::LOGIN_RESP);
        resp.set_itt(req.itt());
        resp.set_flags((if t { flag::T_BIT } else { 0 }) | (req_csg << flag::CSG_SHIFT) | nsg);
        resp.as_mut_bytes()[2] = 0x00; // Version-max (RFC 3720 §10.13.2)
        resp.as_mut_bytes()[3] = 0x00; // Version-active
                                       // ISID echo (bytes 8-13, RFC 3720 §10.12).
        resp.as_mut_bytes()[8..14].copy_from_slice(&req.as_bytes()[8..14]);
        // TSIH: non-zero for a new session's final response.
        if req.tsih() == 0 {
            resp.as_mut_bytes()[15] = 1;
        } else {
            resp.as_mut_bytes()[14..16].copy_from_slice(&req.as_bytes()[14..16]);
        }
        resp.set_data_segment_len(resp_len as u32);
        resp.set_stat_sn(self.stat_sn.get());
        resp.set_exp_cmd_sn(req.cmd_sn());
        resp.set_max_cmd_sn(req.cmd_sn());

        // Assemble: BHS at work[0..48], data at work[48..48+resp_len].
        work[..BHS_SIZE].copy_from_slice(resp.as_bytes());
        let total = BHS_SIZE + resp_len;
        let pad = pdu_pad_len(resp_len as u32) as usize;
        work[total..total + pad].fill(0);
        self.stat_sn.set(self.stat_sn.get().wrapping_add(1));

        if t {
            self.stage = LoginStage::from_csg(nsg).unwrap_or(LoginStage::FullFeature);
            if self.stage == LoginStage::FullFeature {
                crate::debug!("login complete: FullFeature, cmd_sn={}", req.cmd_sn());
                self.cmd_sn = req.cmd_sn().wrapping_sub(1);
            }
        } else {
            self.stage = LoginStage::from_csg(req_csg).unwrap_or(LoginStage::Security);
        }
        self.session = Session::Send {
            len: total + pad,
            kind: SendKind::Continue,
        };
        Emit::Send(total + pad)
    }

    /// Parse initiator key=value text into a response, updating negotiated
    /// parameters. Writes into `dst`, returns the response length or `None`
    /// if `dst` is too small.
    fn negotiate(&mut self, src: &[u8], dst: &mut [u8]) -> Option<usize> {
        let mut w = 0usize;
        let mut sent = [false; LOGIN_TABLE.len()];
        let mut p = 0usize;
        while p < src.len() {
            let Some(eq) = src[p..].iter().position(|&b| b == b'=') else {
                break;
            };
            let eq = p + eq;
            let val_end = src[eq + 1..]
                .iter()
                .position(|&b| b == 0)
                .map_or(src.len(), |i| eq + 1 + i);
            let key = &src[p..eq];
            let val = &src[eq + 1..val_end];

            if key == b"SessionType" {
                self.is_discovery = val == b"Discovery";
            } else if let Some(idx) = find_key(key) {
                sent[idx] = true;
                if key == b"ImmediateData" {
                    // RFC 3720 §12.11 Result function is AND, Default Yes.
                    let initiator_yes = val == b"Yes";
                    let result_yes = initiator_yes; // target offers Yes
                    self.neg.immediate_data = result_yes;
                    let out: &[u8] = if result_yes { b"Yes" } else { b"No" };
                    if !append_kv(dst, &mut w, key, out) {
                        return None;
                    }
                } else if key == b"InitialR2T" {
                    // RFC 3720 §12.10 Result function is OR, Default Yes.
                    let initiator_yes = val == b"Yes";
                    let result_yes = initiator_yes || true; // target offers Yes
                    self.neg.initial_r2t = result_yes;
                    let out: &[u8] = if result_yes { b"Yes" } else { b"No" };
                    if !append_kv(dst, &mut w, key, out) {
                        return None;
                    }
                } else if key == b"MaxBurstLength" {
                    // RFC 3720 §12.14 Result function is Minimum.
                    if let Some(v) = parse_u32(val) {
                        let negotiated = v.min(DEFAULT_MAX_BURST);
                        self.neg.max_burst_len = negotiated;
                        if !append_kv_u32(dst, &mut w, key, negotiated) {
                            return None;
                        }
                    } else if !append_kv(dst, &mut w, key, val) {
                        return None;
                    }
                } else if key == b"FirstBurstLength" {
                    // RFC 3720 §12.13 Result function is Minimum.
                    if let Some(v) = parse_u32(val) {
                        let negotiated = v.min(DEFAULT_FIRST_BURST);
                        self.neg.first_burst_len = negotiated;
                        if !append_kv_u32(dst, &mut w, key, negotiated) {
                            return None;
                        }
                    } else if !append_kv(dst, &mut w, key, val) {
                        return None;
                    }
                } else if key == b"MaxRecvDataSegmentLength" {
                    // Advertise the negotiated (buffer-derived) value,
                    // not the raw initiator figure.
                    self.apply_neg(LOGIN_TABLE[idx].key, val);
                    if !append_kv_u32(dst, &mut w, key, self.max_recv_data_segment) {
                        return None;
                    }
                } else {
                    self.apply_neg(LOGIN_TABLE[idx].key, val);
                    let out_val: &[u8] = match LOGIN_TABLE[idx].value {
                        Some(v) => v.as_bytes(),
                        None => val,
                    };
                    if !append_kv(dst, &mut w, key, out_val) {
                        return None;
                    }
                }
            } else if !is_skip_key(key) && !append_kv(dst, &mut w, key, b"Reject") {
                return None;
            }
            p = if val_end < src.len() {
                val_end + 1
            } else {
                src.len()
            };
        }
        for (i, param) in LOGIN_TABLE.iter().enumerate() {
            if param.always && !sent[i] {
                if let Some(v) = param.value {
                    if !append_kv(dst, &mut w, param.key.as_bytes(), v.as_bytes()) {
                        return None;
                    }
                }
            }
        }
        Some(w)
    }

    fn apply_neg(&mut self, key: &str, val: &[u8]) {
        match key {
            "MaxRecvDataSegmentLength" => {
                if let Some(v) = parse_u32(val) {
                    self.max_recv_data_segment = v.min(self.max_recv_data_segment);
                }
            }
            "MaxBurstLength" => {
                if let Some(v) = parse_u32(val) {
                    self.neg.max_burst_len = v.min(DEFAULT_MAX_BURST);
                }
            }
            "FirstBurstLength" => {
                if let Some(v) = parse_u32(val) {
                    self.neg.first_burst_len = v.min(DEFAULT_FIRST_BURST);
                }
            }
            "ImmediateData" => self.neg.immediate_data = val == b"Yes",
            "InitialR2T" => self.neg.initial_r2t = val == b"Yes",
            "MaxOutstandingR2T" => {
                if let Some(v) = parse_u32(val) {
                    self.neg.max_outstanding_r2t = v.min(1);
                }
            }
            _ => {}
        }
    }
}

/// Outcome of one core command step.
enum Stepped {
    /// Still running.
    Pending,
    /// The local completion is fixed.
    Done(Completion),
    /// The runner settled at the control plane.
    Control(crate::core::RunOutcome),
    /// Runner-level fault (contract / boundary); the connection cannot continue
    /// this command.
    Err(Fault),
}

// ── Host data seam ─────────────────────────────────────────────────

impl HostTransport for IscsiSession {
    fn publish(&mut self, plan: DataPlan) -> Result<(), Fault> {
        // iSCSI's own gate: the W bit declares whether the command expects a
        // Data-Out phase. A device plan that contradicts it is a contract
        // violation (the command is settled by the runner).
        match plan.direction {
            Direction::ToHost | Direction::None if self.cmd_w => {
                self.delivery = Delivery::Failed;
                Err(Fault::Contract)
            }
            Direction::FromHost if !self.cmd_w => {
                self.delivery = Delivery::Failed;
                Err(Fault::Contract)
            }
            _ => {
                self.plan = plan;
                Ok(())
            }
        }
    }

    fn begin_recv(&mut self, req: HostReq) -> HostToken {
        let token = self.next_token();
        // The core always receives the whole published plan; a chunked device
        // request would need a per-chunk offset that the wire does not carry.
        if req.dir != Direction::FromHost || u64::from(req.len) != self.plan.bytes {
            return HostToken::new(u8::MAX, 0);
        }
        let total = req.len;
        let accepted = self.immediate.min(total);
        let done = accepted >= total;
        self.host = HostPhase::Recv(RecvPhase {
            token,
            total,
            accepted,
            r2t_sn: 0,
            data_sn: 0,
            burst_remaining: 0,
            r2t_pending: !done,
            consumed: false,
            done,
        });
        token
    }

    fn begin_send(&mut self, req: HostReq) -> HostToken {
        let token = self.next_token();
        if req.dir != Direction::ToHost || u64::from(req.len) != self.plan.bytes {
            return HostToken::new(u8::MAX, 0);
        }
        self.host = HostPhase::Send(SendPhase {
            token,
            total: req.len,
            sent: 0,
            data_sn: 0,
            staged: None,
            held: None,
        });
        token
    }

    fn poll_host(&mut self, token: HostToken, buf: HostBuf<'_>) -> core::task::Poll<HostReceipt> {
        use core::task::Poll;
        let phase = match self.host {
            HostPhase::Send(p) if p.token == token => Phase::Send(p),
            HostPhase::Recv(p) if p.token == token => Phase::Recv(p),
            _ => return Poll::Ready(HostReceipt::from_adapter(0, Some(Fault::Contract))),
        };
        match phase {
            Phase::Send(mut p) => {
                let buf = match buf {
                    HostBuf::Send(buf) if buf.len() == p.total as usize => buf,
                    _ => return Poll::Ready(HostReceipt::from_adapter(0, Some(Fault::Contract))),
                };
                let remaining = p.total.saturating_sub(p.sent);
                if remaining == 0 {
                    self.host = HostPhase::Send(p);
                    return Poll::Ready(HostReceipt::from_adapter(p.sent as usize, None));
                }
                let bank = buf.len() as u32;
                let cap = remaining.min(self.max_recv_data_segment).min(bank);
                if cap == 0 {
                    return Poll::Ready(HostReceipt::from_adapter(
                        p.sent as usize,
                        Some(Fault::Contract),
                    ));
                }
                if cap < remaining {
                    // Intermediate chunk: keep it 4-aligned so the padding of
                    // this PDU never overwrites unsent data.
                    let chunk = (cap & !3).max(4);
                    p.staged = Some((p.sent, chunk));
                    self.host = HostPhase::Send(p);
                    return Poll::Pending;
                }
                // Last chunk: hold it back for the terminating Data-In, which
                // also carries the fixed status. The wire cost is zero: the
                // caller's bank still holds the bytes.
                let pad = pdu_pad_len(remaining) as usize;
                if remaining as usize + pad > self.bank_len {
                    // Keep a 4-aligned prefix and leave the (<=4-byte) tail
                    // for a second PDU whose padding fits.
                    let tail = remaining & 3;
                    let split = remaining.saturating_sub(tail);
                    if split > 0 && split < remaining {
                        p.staged = Some((p.sent, split));
                        self.host = HostPhase::Send(p);
                        return Poll::Pending;
                    }
                }
                p.held = Some((p.sent, remaining));
                let accepted = p.sent.saturating_add(remaining);
                self.host = HostPhase::Send(p);
                Poll::Ready(HostReceipt::from_adapter(accepted as usize, None))
            }
            Phase::Recv(mut p) => {
                match buf {
                    HostBuf::Recv(buf) if buf.len() == p.total as usize => {}
                    _ => return Poll::Ready(HostReceipt::from_adapter(0, Some(Fault::Contract))),
                }
                if p.done {
                    self.host = HostPhase::Recv(p);
                    return Poll::Ready(HostReceipt::from_adapter(p.accepted as usize, None));
                }
                if p.consumed {
                    p.consumed = false;
                    if p.accepted >= p.total {
                        p.done = true;
                        self.host = HostPhase::Recv(p);
                        return Poll::Ready(HostReceipt::from_adapter(p.accepted as usize, None));
                    }
                    if p.burst_remaining == 0 {
                        p.r2t_pending = true;
                    }
                }
                self.host = HostPhase::Recv(p);
                Poll::Pending
            }
        }
    }

    fn cancel(&mut self, token: HostToken) {
        let live = match self.host {
            HostPhase::Send(p) => p.token == token,
            HostPhase::Recv(p) => p.token == token,
            HostPhase::Idle => false,
        };
        if live {
            self.host = HostPhase::Idle;
            self.host_gen = self.host_gen.wrapping_add(1).max(1);
        }
    }

    fn delivery(&self) -> Delivery {
        self.delivery
    }
}

impl IscsiSession {
    fn next_token(&mut self) -> HostToken {
        self.host_gen = self.host_gen.wrapping_add(1).max(1);
        HostToken::new(0, self.host_gen)
    }
}

enum Phase {
    Send(SendPhase),
    Recv(RecvPhase),
}

// ── Private helpers ─────────────────────────────────────────────────

struct Pdu {
    bhs: Bhs,
    dsl: usize,
}

/// Opcodes whose command CDB expects a Data-In phase even when the transport
/// does not set the W bit. An unlisted vendor opcode is treated as no-data.
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

/// Fixed-format sense (SPC-3): response code, sense key, additional length,
/// ASC/ASCQ. Writes at most 18 bytes into `dst`.
fn sense_write_fixed(sense: Sense, dst: &mut [u8]) -> usize {
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

// ── Login key helpers ──────────────────────────────────────────────

fn find_key(key: &[u8]) -> Option<usize> {
    LOGIN_TABLE.iter().position(|p| p.key.as_bytes() == key)
}

fn is_skip_key(key: &[u8]) -> bool {
    SKIP_KEYS.iter().any(|k| k.as_bytes() == key)
}

fn append_kv(dst: &mut [u8], w: &mut usize, k: &[u8], v: &[u8]) -> bool {
    let need = k.len() + 1 + v.len() + 1;
    if *w + need > dst.len() {
        return false;
    }
    dst[*w..*w + k.len()].copy_from_slice(k);
    *w += k.len();
    dst[*w] = b'=';
    *w += 1;
    dst[*w..*w + v.len()].copy_from_slice(v);
    *w += v.len();
    dst[*w] = 0;
    *w += 1;
    true
}

fn append_kv_u32(dst: &mut [u8], w: &mut usize, key: &[u8], v: u32) -> bool {
    let mut buf = [0u8; 10];
    let digits = fmt_u32(v, &mut buf);
    append_kv(dst, w, key, digits)
}

fn fmt_u32(v: u32, buf: &mut [u8; 10]) -> &[u8] {
    let mut n = v;
    let mut i = buf.len();
    loop {
        i -= 1;
        buf[i] = b'0' + (n % 10) as u8;
        n /= 10;
        if n == 0 {
            break;
        }
    }
    &buf[i..]
}

fn parse_u32(v: &[u8]) -> Option<u32> {
    if v.is_empty() {
        return None;
    }
    let mut n: u32 = 0;
    for &b in v {
        if !b.is_ascii_digit() {
            return None;
        }
        n = n.checked_mul(10)?.checked_add((b - b'0') as u32)?;
    }
    Some(n)
}

// ── Tests ───────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn negotiate_rejects_a_tiny_response_bank() {
        let mut session = IscsiSession::new();
        let src = b"InitiatorName=iqn.test\0TargetName=iqn.target\0";
        let mut tiny = [0u8; 10];
        assert!(session.negotiate(src, &mut tiny).is_none());
    }

    #[test]
    fn sense_write_fixed_is_spc3_fixed_format() {
        let mut buf = [0u8; 18];
        assert_eq!(
            sense_write_fixed(Sense::new(0x05, 0x25, 0x00), &mut buf),
            18
        );
        assert_eq!(buf[0], 0x70);
        assert_eq!(buf[2], 0x05);
        assert_eq!(buf[7], 0x0A);
        assert_eq!(buf[12], 0x25);
        assert_eq!(buf[13], 0x00);

        // Truncation writes the prefix only.
        let mut small = [0xAAu8; 4];
        assert_eq!(
            sense_write_fixed(Sense::new(0x0B, 0x45, 0x00), &mut small),
            4
        );
        assert_eq!(small, [0x70, 0, 0x0B, 0]);
    }

    #[test]
    fn a_rejected_plan_books_a_failed_delivery() {
        let mut session = IscsiSession::new();
        // No command declared a Data-Out phase (W=0), so a FromHost plan is
        // rejected by the transport's own gate.
        assert_eq!(
            session.publish(DataPlan {
                direction: Direction::FromHost,
                bytes: 4,
            }),
            Err(Fault::Contract)
        );
        assert_eq!(session.delivery(), Delivery::Failed);
    }

    #[test]
    fn data_in_table_covers_the_standard_read_family() {
        for opcode in [
            scsi_op::READ_6,
            scsi_op::READ_10,
            scsi_op::READ_16,
            scsi_op::INQUIRY,
            scsi_op::REQUEST_SENSE,
            scsi_op::REPORT_LUNS,
            scsi_op::GET_CONFIGURATION,
            scsi_op::READ_TOC,
        ] {
            assert!(data_in_opcode(opcode), "0x{opcode:02X} must be Data-In");
        }
        for opcode in [
            scsi_op::TEST_UNIT_READY,
            scsi_op::WRITE_10,
            scsi_op::SYNCHRONIZE_CACHE_10,
            scsi_op::FORMAT_UNIT,
            0xA1, // BLANK
        ] {
            assert!(
                !data_in_opcode(opcode),
                "0x{opcode:02X} must not be Data-In"
            );
        }
    }
}
