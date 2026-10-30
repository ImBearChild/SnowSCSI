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
//! the BHS at `work[base..base + 48]`, a Data-Out segment at its final offset
//! inside the command's data area, where `base` is the PDU bank offset of the
//! session.
//!
//! SCSI command execution is delegated to the core [`Target`]: the session
//! builds the [`CommandContext`] from the wire, starts the command and drives
//! it one step per entry. Host data phases are implemented by this type as
//! [`HostTransport`]: Data-In is split into sequences bounded by
//! `MaxBurstLength`, each PDU bounded by the initiator's declared
//! `MaxRecvDataSegmentLength`; Data-Out is solicited with R2T and consumed one
//! PDU at a time.
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
//! pdu::BHS_SIZE`. At the PDU base the leading [`pdu::BHS_SIZE`] bytes carry
//! the wire header; the remainder of the bank is the SCSI data area and the
//! transport's [`HostTransport`] bank, which bounds one device data chunk (a
//! larger transfer is streamed in chunks). Its size also fixes this target's
//! declared `MaxRecvDataSegmentLength` for the connection (RFC 3720 §12.12).
//! `scratch` is the resident long-operation bank and must hold at least
//! [`crate::MIN_DATA_LEN`] bytes.
//!
//! With [`IscsiSession::with_overlap`] `work` is instead the **total** of two
//! equal banks, each `BHS_SIZE + data area`. Command framing, Data-Out and
//! responses stay in one bank; a Data-In chunk may be staged in either bank, so
//! each deferred send carries the base of the bank that holds it. A resident
//! long token owns one bank and commands run on the other.

use core::cell::Cell;

use crate::core::storage::{
    BankSide, HostBuf, HostReceipt, HostReq, HostToken, HostTransport, Storage,
};
use crate::core::{
    CommandContext, Completion, Control, DataPlan, Delivery, Direction, Fault, LongPhase,
    PendingKind, RuntimeSet, Sense, Target, UaClass, LUN_NOT_SUPPORTED,
};
use crate::iscsi::pdu::{
    flag, iscsi_opcode_name, op, pdu_pad_len, reject, stage, status, tmf, tmf_response, Bhs,
    BHS_SIZE,
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
    /// `offset` is absolute in `work`; the session has already added the
    /// current PDU bank base. The BHS of a PDU is read at the bank base, a
    /// data segment is read directly at its final place in the SCSI data
    /// area, so the transport never has to stage or copy it.
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
    /// The active command is waiting on a storage operation and no wire
    /// transfer is staged. Feed [`Event::Tick`] to advance it once; no bytes
    /// are read or written.
    StoragePending,
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
    /// `BHS_SIZE` behind the PDU base (data area too small for the SCSI layer
    /// and the Login text), that data area (`work.len() - pdu_base -
    /// BHS_SIZE`) is not a multiple of 4, an overlap total does not split into
    /// two aligned banks of at least that size, or the scratch bank is smaller
    /// than [`crate::MIN_DATA_LEN`].
    WorkBufTooSmall,
    /// Connection I/O failure (details logged by the transport).
    Io,
    /// Unexpected internal state.
    Internal,
}

impl core::fmt::Display for TargetError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::WorkBufTooSmall => {
                write!(
                    f,
                    "work buffer below MIN_DATA_LEN + BHS_SIZE, scratch below MIN_DATA_LEN, or misaligned"
                )
            }
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
/// Base offset of a PDU that no command owns (Login, Text, NOP, Logout, task
/// management, Reject): those responses must never borrow the bank a running
/// command is using.
const CONTROL_PDU_BASE: usize = 0;
/// RFC 3720 §12.13/§12.14 suggested defaults (clamped when the initiator sends
/// more).
const DEFAULT_FIRST_BURST: u32 = 65536;
const DEFAULT_MAX_BURST: u32 = 262144;
/// Upper bound for a peer-declared `MaxRecvDataSegmentLength`: the BHS
/// DataSegmentLength field is 24 bits (RFC 3720 §3.1).
const HARD_CAP: u32 = 0xFF_FFFF;
/// RFC 3720 §12.12 floor for `MaxRecvDataSegmentLength`.
const MIN_RECV_DATA_SEGMENT: u32 = 512;
/// Upper cap for the `MaxRecvDataSegmentLength` this target accepts.
///
/// This is our own receive capability (RFC 3720 §12.12 is declarative and per
/// direction): it bounds incoming Data-Out segments and is what the Login
/// Response declares, independently of what the initiator offered. The value is
/// derived from the work bank at the first entry
/// (`clamp(data_area, 512, 8192)`) and stays fixed for the connection.
///
/// The bank floor is [`crate::MIN_DATA_LEN`] + `BHS_SIZE`, so the derivation
/// settles at 8192 rather than at the protocol minimum of 512: RFC 3720 §6.1
/// applies the default `MaxRecvDataSegmentLength` (8192) during Login, before
/// any negotiation, so a conformant first Login Request may carry up to 8192
/// bytes of text. The bank must be able to stage it; a smaller declared value
/// only becomes safe once the Login text is streamed. It never bounds Data-In
/// (that direction is bounded by the initiator's declaration).
const OUR_RECV_MDSL: u32 = 8192;
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
    /// `work[base + BHS_SIZE..]`).
    RecvData { total: usize },
    /// Waiting for a Data-Out BHS solicited by an R2T.
    OutBhs,
    /// Waiting for a Data-Out data segment; the shell stores it at the final
    /// offset inside the SCSI data area.
    OutData { dsl: usize },
    /// Waiting for the Data-Out padding (discarded at the PDU bank base).
    OutPad { pad: usize },
    /// A complete PDU is staged in `work[base..base + len]` and must be sent.
    Send {
        len: usize,
        /// Bank offset the staged PDU starts at, fixed when it was built.
        base: usize,
        kind: SendKind,
    },
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
    /// DataSN of the next Data-In PDU (continues across device chunks).
    data_sn: u32,
    /// Bytes already sent in the current sequence (reset when a PDU with F=1
    /// is observed sent). Bounds every sequence by `MaxBurstLength`.
    seq_bytes: u32,
    /// First byte offset of the current device send chunk.
    phase_base: u32,
    /// Bytes requested by the current device send chunk.
    phase_len: u32,
    /// Chunk staged by `poll_host`, not yet turned into a PDU: PDU
    /// BufferOffset, bank offset inside the current phase, length, F bit.
    staged: Option<(u32, u32, u32, bool)>,
    /// Final chunk held back for the terminating Data-In (PDU BufferOffset,
    /// bank offset, length).
    held: Option<(u32, u32, u32)>,
    /// Physical bank holding the current device chunk (overlap only; always
    /// `Work` for a single-bank session).
    chunk_bank: BankSide,
}

/// Data-Out progress.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct RecvPhase {
    token: HostToken,
    /// Total bytes of the published plan (the device's receive length).
    total: u32,
    /// Bytes accepted so far (immediate data included).
    accepted: u32,
    /// Bytes accounted to the device across completed chunks.
    produced: u32,
    /// First byte offset of the current device receive chunk.
    chunk_base: u32,
    /// Bytes requested by the current device receive chunk.
    phase_len: u32,
    /// End (exclusive) of the current device receive chunk.
    phase_end: u32,
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
    /// Largest data segment this target accepts (our own capability); bounds
    /// incoming Data-Out and is declared in the Login Response.
    our_recv_mdsl: u32,
    /// `our_recv_mdsl` was derived from the work bank; the value is fixed for
    /// the connection once the first entry has seen the bank.
    recv_mdsl_fixed: bool,
    /// Largest data segment the initiator declared it can receive; bounds
    /// every Data-In PDU we send.
    peer_recv_mdsl: u32,
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
    /// Two-bank overlap mode (default off).
    overlap: bool,
    /// Physical bank holding command framing, Data-Out and the responses.
    cmd_bank: BankSide,
    /// Second bank the current command may prefetch into (overlap only).
    cmd_alt: Option<BankSide>,
    /// Physical bank lent to the resident long operation while its adapter
    /// token is in flight.
    long_bank: Option<BankSide>,
    /// The command bank for the PDU at the current boundary was fixed.
    bank_fixed: bool,
    /// Length of one bank inside `work` (`work.len()` outside overlap).
    bank_size: usize,
    /// Length of the SCSI data area handed to the core for the current step.
    bank_len: usize,
    /// Bank offset of the PDU currently being framed inside `work`.
    ///
    /// The BHS sits at `work[pdu_base..pdu_base + BHS_SIZE]` and the SCSI data
    /// area at `work[pdu_base + BHS_SIZE..]`. It is `0` for the single-bank
    /// session and only changes at a PDU boundary.
    pdu_base: usize,
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
    Send { len: usize, base: usize },
    StoragePending,
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
            our_recv_mdsl: OUR_RECV_MDSL,
            recv_mdsl_fixed: false,
            // RFC 3720 §12.12 default until the initiator declares its own.
            peer_recv_mdsl: OUR_RECV_MDSL,
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
            overlap: false,
            cmd_bank: BankSide::Work,
            cmd_alt: None,
            long_bank: None,
            bank_fixed: false,
            bank_size: 0,
            bank_len: 0,
            pdu_base: 0,
        }
    }

    /// Select the two-bank overlap mode (builder style; default off).
    ///
    /// In overlap mode [`poll`](Self::poll)'s `work` is the **total** of two
    /// equal banks: its length must be even, each half at least
    /// [`crate::MIN_DATA_LEN`] + [`BHS_SIZE`], and each half's data area a
    /// multiple of four. Command framing, Data-Out and responses use one bank;
    /// a Data-In chunk may be staged from either bank, so the core can read the
    /// next device chunk into the other bank while the current PDU is on the
    /// wire. Single-bank sessions keep the historical layout (`work` is one
    /// bank).
    pub fn with_overlap(mut self) -> Self {
        self.overlap = true;
        self
    }

    /// Whether the session uses two equal banks inside `work`.
    pub fn overlap(&self) -> bool {
        self.overlap
    }

    /// The bank currently lent to the resident long operation, if its storage
    /// token is in flight. `None` when no long token is pending or the session
    /// is not in overlap mode.
    pub fn long_bank(&self) -> Option<BankSide> {
        self.long_bank
    }

    /// Absolute offset of physical bank `side` inside `work`.
    fn bank_base(&self, side: BankSide) -> usize {
        if self.overlap && side == BankSide::Alt {
            self.bank_size
        } else {
            0
        }
    }

    /// The other one of the two banks.
    const fn other_bank(bank: BankSide) -> BankSide {
        match bank {
            BankSide::Work => BankSide::Alt,
            BankSide::Alt => BankSide::Work,
        }
    }

    /// The bank that is not the command bank.
    fn alternate_bank(&self) -> BankSide {
        Self::other_bank(self.cmd_bank)
    }

    /// Map a runner-side bank (relative to the `work`/`alt` arguments) to the
    /// physical half of the caller's `work`.
    fn physical_bank(&self, side: BankSide) -> BankSide {
        if !self.overlap {
            BankSide::Work
        } else {
            match side {
                BankSide::Work => self.cmd_bank,
                BankSide::Alt => self.alternate_bank(),
            }
        }
    }

    /// Absolute base of the bank a staged PDU lives in.
    fn send_base(&self, bank: BankSide) -> usize {
        if self.overlap {
            self.bank_base(bank)
        } else {
            self.pdu_base
        }
    }

    /// Base offset of a PDU that no command owns (Login, Text, NOP, Logout,
    /// task management, Reject).
    ///
    /// A single-bank session keeps the control bank at offset 0; an overlap
    /// session frames the response in the command bank, which is never the bank
    /// a resident long token holds.
    fn control_base(&self) -> usize {
        if self.overlap {
            self.pdu_base
        } else {
            CONTROL_PDU_BASE
        }
    }

    /// End of the bank that starts at `base` (the whole `work` in single-bank
    /// mode). A PDU may never be assembled past this point.
    fn bank_end(&self, work_len: usize, base: usize) -> usize {
        if self.overlap {
            let half = if self.bank_size != 0 {
                self.bank_size
            } else {
                work_len / 2
            };
            base + half
        } else {
            work_len
        }
    }

    /// Fix the command bank for the PDU beginning at this boundary.
    ///
    /// A resident long operation with an in-flight token holds one bank; the
    /// command then gets the other bank and no alternate. With no token pending
    /// the command gets bank A and bank B as its alternate.
    fn fix_boundary(&mut self) {
        if !self.overlap {
            // Single-bank sessions have nothing to choose: the base stays where
            // the session already framed it.
            self.cmd_bank = BankSide::Work;
            self.cmd_alt = None;
            self.bank_fixed = true;
            return;
        }
        match self.long_bank {
            Some(long) => {
                self.cmd_bank = Self::other_bank(long);
                self.cmd_alt = None;
            }
            None => {
                self.cmd_bank = BankSide::Work;
                self.cmd_alt = Some(BankSide::Alt);
            }
        }
        self.pdu_base = self.bank_base(self.cmd_bank);
        self.bank_fixed = true;
    }

    /// Keep the command's alternate consistent with the long operation's bank:
    /// it loses the alternate when the long token takes that bank and regains
    /// it once the token has settled. A running command keeps the allocation
    /// fixed for its duration.
    fn refresh_command_alt(&mut self) {
        if !self.overlap || !self.bank_fixed || self.cmd_active {
            return;
        }
        self.cmd_alt = match self.long_bank {
            Some(_) => None,
            None => Some(self.alternate_bank()),
        };
    }

    /// Forget the long bank once its adapter token has settled.
    fn settle_long<S: RuntimeSet>(&mut self, target: &Target<S>) {
        if !target.long_io_in_flight() {
            self.long_bank = None;
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
    /// `work[pdu_base..pdu_base + BHS_SIZE]`, and the SCSI data area at
    /// `work[pdu_base + BHS_SIZE..]`.
    /// The data area bounds one device data chunk (`work.len() - pdu_base -
    /// BHS_SIZE`); a larger transfer is streamed in bank-sized chunks, and
    /// each Data-In PDU still carries at most `MaxRecvDataSegmentLength`
    /// bytes. The data area also fixes the `MaxRecvDataSegmentLength` this
    /// target declares for the connection (RFC 3720 §12.12).
    /// `scratch` is the resident long-operation bank: an **empty** `scratch`
    /// selects the shared bank (`work` serves both paths, and the long
    /// operation only advances on [`Event::Tick`]); a non-empty one must be at
    /// least [`crate::MIN_DATA_LEN`] and keeps the split mode, where queries
    /// stay serviceable while a long IO is in flight.
    ///
    /// An overlap session ([`Self::with_overlap`]) treats `work` as the total
    /// of two equal banks instead: the command bank is fixed at each PDU
    /// boundary, the alternate bank may hold a Data-In chunk, and the resident
    /// long operation borrows one bank while its token is in flight. Overlap
    /// is explicit and never inferred from `work.len()`.
    ///
    /// `target` owns the LUN slots, `storage` executes the device's storage
    /// operations; the session itself implements the [`HostTransport`] data
    /// seam and performs at most one command step per entry.
    pub fn poll<'a, 'b, S: RuntimeSet>(
        &'a mut self,
        ev: Event,
        work: &'a mut [u8],
        scratch: &'a mut [u8],
        target: &'b mut Target<S>,
        storage: &'b mut dyn Storage,
    ) -> Action<'a> {
        let (data_area, bank_size) = if self.overlap {
            let total = work.len();
            if !total.is_multiple_of(2) {
                return Action::Error(TargetError::WorkBufTooSmall);
            }
            let half = total / 2;
            if half < crate::MIN_DATA_LEN + BHS_SIZE
                || (self.pdu_base != 0 && self.pdu_base != half)
            {
                return Action::Error(TargetError::WorkBufTooSmall);
            }
            (half - BHS_SIZE, half)
        } else {
            let base = self.pdu_base;
            if base > work.len() || work.len() - base < crate::MIN_DATA_LEN + BHS_SIZE {
                return Action::Error(TargetError::WorkBufTooSmall);
            }
            (work.len() - base - BHS_SIZE, work.len())
        };
        // Every Data-In PDU is padded to a 4-byte boundary, and the padding
        // may land on bytes that are still unsent when a chunk is staged.
        // Require an aligned data area up front instead of trusting that
        // callers always size the bank that way.
        if !data_area.is_multiple_of(4) {
            return Action::Error(TargetError::WorkBufTooSmall);
        }
        self.bank_size = bank_size;
        if scratch.len() < crate::MIN_DATA_LEN && !scratch.is_empty() {
            return Action::Error(TargetError::WorkBufTooSmall);
        }
        // Our own receive capability is the bank's data area, clamped to the
        // protocol range (RFC 3720 §12.12). The bank floor is
        // `MIN_DATA_LEN + BHS_SIZE`, so this settles at the 8192 cap: the
        // default MDSL applies during Login (RFC 3720 §6.1) and a conformant
        // first Login Request may carry up to 8192 bytes of text, which the
        // bank must be able to stage. Derive it before any PDU is framed, so
        // the Login Response declares it, and never change it while the
        // connection lives.
        if !self.recv_mdsl_fixed {
            self.our_recv_mdsl =
                data_area.clamp(MIN_RECV_DATA_SEGMENT as usize, OUR_RECV_MDSL as usize) as u32;
            self.recv_mdsl_fixed = true;
        }
        let emit = self.entry(ev, work, scratch, target, storage);
        match emit {
            Emit::Recv { offset, len } => Action::HostRecv { offset, len },
            Emit::Send { len, base } => Action::HostSend {
                bytes: &work[base..base + len],
                prefetch: None,
            },
            Emit::StoragePending => Action::StoragePending,
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
        // advances the resident long operation once: one poll per entry. With
        // an empty `scratch` the long operation shares `work` with the wire, so
        // it may only advance on a `Tick` entry: a `HostRecv`/`HostSent` entry
        // can hold a staged PDU in that buffer. Overlap mode gives the long
        // operation one of the two banks and lends it only on a `Tick` entry,
        // so a command that is starting or finishing in the same entry never
        // sees its alternate disappear underneath it.
        let shared = scratch.is_empty() && !self.overlap;
        if self.overlap {
            if self.session == Session::RecvPdu && !self.cmd_active {
                self.settle_long(target);
                if matches!(ev, Event::Tick) {
                    if !self.bank_fixed {
                        self.fix_boundary();
                    }
                    if let Some(out) = self.overlap_idle_entry(work, target, storage) {
                        return out;
                    }
                    self.refresh_command_alt();
                }
            }
        } else if self.session == Session::RecvPdu
            && !self.cmd_active
            && (!shared || matches!(ev, Event::Tick))
        {
            if let Some(out) = self.idle_entry(work, scratch, target, storage) {
                return out;
            }
        }
        match ev {
            Event::Tick => {
                // A command waiting on storage advances exactly one step; there
                // is no wire transfer to re-emit.
                if self.cmd_active
                    && self.session == Session::RecvPdu
                    && target.pending_kind() == Some(PendingKind::Storage)
                {
                    self.step(work, scratch, target, storage)
                } else {
                    self.expectation()
                }
            }
            Event::HostRecv { len } => self.on_recv(len, work, scratch, target, storage),
            Event::HostSent => {
                let emit = self.on_sent(work, scratch, target, storage);
                if !shared {
                    // Split and overlap modes keep their own path.
                    return emit;
                }
                // Shared bank: the response bytes have already been written to
                // the wire, so a `HostSent` handler that returns to the PDU
                // boundary with no active command may advance the resident
                // long operation once. This is where a fill armed by an Immed
                // FORMAT/BLANK gets its first storage IO (such a command
                // completes without any). The pre-event rule is unchanged: in
                // shared mode `idle_entry` is never run at the top of a
                // `HostRecv`/`HostSent` entry.
                if self.session == Session::RecvPdu && !self.cmd_active {
                    if let Some(out) = self.idle_entry(work, scratch, target, storage) {
                        if matches!(out, Emit::Closed | Emit::Error(_)) {
                            return out;
                        }
                    }
                }
                emit
            }
        }
    }

    /// Re-emit the BHS receive for the next PDU at the bank this boundary
    /// already selected.
    ///
    /// Used when a PDU was consumed without starting a command (out-of-window
    /// CmdSN, no-response NOP). The bank choice is kept so the shell's read
    /// offset stays valid; a later boundary re-applies the selection.
    fn boundary_recv(&mut self) -> Emit {
        self.bank_fixed = true;
        Emit::Recv {
            offset: self.pdu_base,
            len: BHS_SIZE,
        }
    }

    /// The action that re-emits the current position.
    fn expectation(&mut self) -> Emit {
        if self.session == Session::RecvPdu && !self.cmd_active && !self.bank_fixed {
            self.fix_boundary();
        }
        let base = self.pdu_base;
        match self.session {
            Session::RecvPdu | Session::OutBhs => Emit::Recv {
                offset: base,
                len: BHS_SIZE,
            },
            Session::RecvData { total } => Emit::Recv {
                offset: base + BHS_SIZE,
                len: total,
            },
            Session::OutData { dsl } => {
                let local = match self.host {
                    HostPhase::Recv(p) => p.accepted.saturating_sub(p.chunk_base) as usize,
                    _ => 0,
                };
                Emit::Recv {
                    offset: base + BHS_SIZE + local,
                    len: dsl,
                }
            }
            Session::OutPad { pad } => Emit::Recv {
                offset: base,
                len: pad,
            },
            Session::Send { len, base, .. } => Emit::Send { len, base },
            Session::Closed => Emit::Closed,
        }
    }

    /// Advance a resident long operation and the target lifecycle once per
    /// idle entry.
    ///
    /// With an empty `scratch` the long operation shares `work` as its data
    /// bank: `poll_long_entry_rt` ignores its `work` argument, so the empty
    /// slice goes there and `work` is the bank.
    fn idle_entry<S: RuntimeSet>(
        &mut self,
        work: &mut [u8],
        scratch: &mut [u8],
        target: &mut Target<S>,
        storage: &mut dyn Storage,
    ) -> Option<Emit> {
        if let Some(lun) = self.long_lun {
            let mut empty = [0u8; 0];
            let polled = if scratch.is_empty() {
                target.poll_long_entry_rt(lun, storage, &mut empty, work)
            } else {
                target.poll_long_entry_rt(lun, storage, work, scratch)
            };
            match polled {
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

    /// Overlap-mode long entry: lend the resident long operation one bank of
    /// `work` (the bank the command does not hold) and keep using that same
    /// bank while its storage token is in flight.
    fn overlap_idle_entry<S: RuntimeSet>(
        &mut self,
        work: &mut [u8],
        target: &mut Target<S>,
        storage: &mut dyn Storage,
    ) -> Option<Emit> {
        if let Some(lun) = self.long_lun {
            let bank = match self.long_bank {
                Some(bank) => bank,
                // A live token must never be re-borrowed from a guessed bank.
                None if target.long_io_in_flight() => {
                    return match target.tick() {
                        crate::core::RunOutcome::Ended { .. } => {
                            self.session = Session::Closed;
                            Some(Emit::Closed)
                        }
                        _ => None,
                    };
                }
                None => self.alternate_bank(),
            };
            if bank == self.cmd_bank {
                // The command bank must never be handed to the long operation.
                return Some(Emit::Error(TargetError::Internal));
            }
            let (first, second) = work.split_at_mut(self.bank_size);
            let long = match bank {
                BankSide::Work => first,
                BankSide::Alt => second,
            };
            let mut empty = [0u8; 0];
            match target.poll_long_entry_rt(lun, storage, &mut empty, long) {
                Ok(info) => {
                    if matches!(info.phase, LongPhase::Foreground | LongPhase::Background) {
                        self.long_bank = target.long_io_in_flight().then_some(bank);
                    } else {
                        self.long_lun = None;
                        self.long_bank = None;
                    }
                }
                Err(fault) => {
                    self.long_lun = None;
                    self.long_bank = None;
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
                let base = self.pdu_base;
                if len != BHS_SIZE || work.len() < base.saturating_add(BHS_SIZE) {
                    return Emit::Error(TargetError::Internal);
                }
                self.bhs.copy_from_slice(&work[base..base + BHS_SIZE]);
                // This PDU has consumed the boundary it was framed for; the
                // next PDU that asks for a BHS re-fixes the command bank.
                self.bank_fixed = false;
                // Bound the declared segment before framing the remainder: a
                // PDU above this target's receive capability is answered (and
                // the connection closed) without consuming its payload.
                let declared = Bhs::from_bytes(self.bhs).data_segment_len() as usize;
                if declared > self.our_recv_mdsl as usize {
                    return self.oversized_segment(work);
                }
                match self.pdu_remainder(work.len()) {
                    Ok(0) => self.dispatch(work, scratch, target, storage),
                    Ok(total) => {
                        self.session = Session::RecvData { total };
                        Emit::Recv {
                            offset: base + BHS_SIZE,
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
                let base = self.pdu_base;
                if len != BHS_SIZE {
                    return Emit::Error(TargetError::Internal);
                }
                self.bhs.copy_from_slice(&work[base..base + BHS_SIZE]);
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
                let local = match self.host {
                    HostPhase::Recv(p) => accepted.saturating_sub(p.chunk_base),
                    _ => 0,
                };
                let end = base + BHS_SIZE + local as usize + dsl;
                if end > self.bank_end(work.len(), base) {
                    return Emit::Error(TargetError::WorkBufTooSmall);
                }
                self.session = Session::OutData { dsl };
                Emit::Recv {
                    offset: base + BHS_SIZE + local as usize,
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
                        offset: self.pdu_base,
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
                    if let Some((_, _, len, f_bit)) = p.staged.take() {
                        p.sent = p.sent.saturating_add(len);
                        p.data_sn = p.data_sn.wrapping_add(1);
                        // DataSN keeps counting across sequences; only the
                        // per-sequence byte budget restarts at an F=1 PDU.
                        p.seq_bytes = if f_bit {
                            0
                        } else {
                            p.seq_bytes.saturating_add(len)
                        };
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
                    let base = self.pdu_base;
                    self.session = Session::Send {
                        len: BHS_SIZE,
                        base,
                        kind: SendKind::R2t,
                    };
                    Emit::Send {
                        len: BHS_SIZE,
                        base,
                    }
                }
                HostPhase::Recv(_) => {
                    self.session = Session::OutBhs;
                    Emit::Recv {
                        offset: self.pdu_base,
                        len: BHS_SIZE,
                    }
                }
                _ => {
                    self.session = Session::RecvPdu;
                    Emit::Recv {
                        offset: self.pdu_base,
                        len: BHS_SIZE,
                    }
                }
            }
        } else if self.overlap {
            // The command bank for the next PDU is fixed by `expectation`,
            // based on the long operation's bank. The long operation itself
            // advances only on a `Tick` at a boundary.
            self.settle_long(target);
            self.expectation()
        } else if !scratch.is_empty() {
            if let Some(out) = self.idle_entry(work, scratch, target, storage) {
                out
            } else {
                self.expectation()
            }
        } else {
            // Shared bank (empty `scratch`): reached from `on_sent` after the
            // response was written to the wire. Progress is deferred to the
            // post-`HostSent` step in `entry`, which advances the resident long
            // operation once with `work` as its bank.
            self.expectation()
        }
    }

    // ── PDU framing helpers ───────────────────────────────────────

    /// The length of the current PDU's remainder (AHS + data + padding),
    /// computed from the saved BHS.
    ///
    /// `work_len` is the whole caller allocation. In overlap mode the room is
    /// one bank (`bank_size`), never the whole allocation; in single-bank mode
    /// it is the whole `work`.
    fn pdu_remainder(&self, work_len: usize) -> Result<usize, TargetError> {
        let bhs = Bhs::from_bytes(self.bhs);
        let dsl = bhs.data_segment_len() as usize;
        let total =
            usize::from(bhs.total_ahs_length()) * 4 + dsl + pdu_pad_len(dsl as u32) as usize;
        // The PDU must fit inside its own bank, never the bank behind it.
        let available = if self.overlap {
            self.bank_size
        } else {
            work_len.saturating_sub(self.pdu_base)
        };
        if BHS_SIZE + total > available {
            return Err(TargetError::WorkBufTooSmall);
        }
        Ok(total)
    }

    /// Answer a PDU whose data segment exceeds [`OUR_RECV_MDSL`].
    ///
    /// During Login the response is a Login Response with a non-zero status
    /// class (RFC 3720 §10.13.5); everywhere else it is a Reject carrying the
    /// protocol-error reason. Both end the connection, so the oversized
    /// payload is never read.
    fn oversized_segment(&mut self, work: &mut [u8]) -> Emit {
        let bhs = Bhs::from_bytes(self.bhs);
        if self.stage != LoginStage::FullFeature && bhs.opcode() == op::LOGIN_REQ {
            // Status-Class 2 (Initiator Error), Detail 0x0B (invalid request
            // during login).
            return self.login_error(work, 0x02, 0x0B);
        }
        self.reject(work, reject::PROTOCOL_ERROR)
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
        if dsl > self.our_recv_mdsl as usize {
            return Some(reject::PROTOCOL_ERROR);
        }
        if dsl as u64 > p.burst_remaining as u64 {
            return Some(reject::INVALID_PDU_FIELD);
        }
        if bhs.buffer_offset().saturating_add(dsl as u32) > p.phase_end {
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
        let stepped = if self.overlap {
            let (first, second) = work.split_at_mut(self.bank_size);
            let (cmd_half, alt_half) = match self.cmd_bank {
                BankSide::Work => (first, second),
                BankSide::Alt => (second, first),
            };
            let cmd = &mut cmd_half[BHS_SIZE..];
            self.bank_len = cmd.len();
            let alt: &mut [u8] = match self.cmd_alt {
                Some(_) => &mut alt_half[BHS_SIZE..],
                None => &mut [],
            };
            target.drive_step_rt(lun, storage, self, cmd, alt, &mut [])
        } else {
            let bank = &mut work[self.pdu_base + BHS_SIZE..];
            self.bank_len = bank.len();
            target.drive_step_rt(lun, storage, self, bank, &mut [], &mut [])
        };
        match stepped {
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
                    Some((offset, bank, len, f_bit)) => {
                        self.emit_data_in(work, offset, bank, len, f_bit)
                    }
                    None => Emit::Error(TargetError::Internal),
                },
                HostPhase::Recv(p) => {
                    if p.r2t_pending {
                        self.build_r2t(work);
                        let base = self.pdu_base;
                        self.session = Session::Send {
                            len: BHS_SIZE,
                            base,
                            kind: SendKind::R2t,
                        };
                        Emit::Send {
                            len: BHS_SIZE,
                            base,
                        }
                    } else {
                        self.session = Session::OutBhs;
                        Emit::Recv {
                            offset: self.pdu_base,
                            len: BHS_SIZE,
                        }
                    }
                }
                HostPhase::Idle => {
                    // The command is pending on storage. There is no wire
                    // transfer to stage; the shell feeds `Event::Tick` to
                    // advance it once.
                    self.session = Session::RecvPdu;
                    Emit::StoragePending
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
        let (sent, data_sn, held, chunk_bank) = match phase {
            HostPhase::Send(p) => (p.sent, p.data_sn, p.held, p.chunk_bank),
            _ => (0, 0, None, BankSide::Work),
        };
        // A held chunk is framed in the bank that holds it; a zero-length
        // terminating Data-In has no chunk and stays in the command bank.
        let held_base = match held {
            Some(_) => self.send_base(chunk_bank),
            None => self.pdu_base,
        };
        let emit = match completion {
            Completion::Good => match held {
                Some((offset, bank, len)) => self.emit_data_in_final(
                    work,
                    held_base,
                    offset,
                    bank,
                    len,
                    data_sn,
                    status::GOOD,
                ),
                None if was_to_host => {
                    self.emit_data_in_final(work, held_base, 0, 0, 0, data_sn, status::GOOD)
                }
                None => self.emit_response(work, itt, status::GOOD, None),
            },
            Completion::Check(sense) => {
                if let Some((offset, bank, len)) = held {
                    // Data already streamed: the last chunk terminates the
                    // transfer; no autosense field exists in a Data-In PDU.
                    self.emit_data_in_final(
                        work,
                        held_base,
                        offset,
                        bank,
                        len,
                        data_sn,
                        status::CHECK_CONDITION,
                    )
                } else if sent > 0 {
                    self.emit_data_in_final(
                        work,
                        held_base,
                        0,
                        0,
                        0,
                        data_sn,
                        status::CHECK_CONDITION,
                    )
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
        let base = self.pdu_base;
        self.session = Session::Send {
            len,
            base,
            kind: SendKind::Status { itt, autosense },
        };
        Emit::Send { len, base }
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
        let base = self.pdu_base;
        if scsi_status == status::CHECK_CONDITION {
            if let Some(sense) = sense {
                work[base + BHS_SIZE] = 0;
                work[base + BHS_SIZE + 1] = 18;
                sense_write_fixed(sense, &mut work[base + BHS_SIZE + 2..base + BHS_SIZE + 20]);
                dlen = 20;
            }
        }
        bhs.set_data_segment_len(dlen as u32);
        work[base..base + BHS_SIZE].copy_from_slice(bhs.as_bytes());
        let total = BHS_SIZE + dlen;
        let pad = pdu_pad_len(dlen as u32) as usize;
        work[base + total..base + total + pad].fill(0);
        self.stat_sn.set(self.stat_sn.get().wrapping_add(1));
        total + pad
    }

    /// Intermediate Data-In chunk: S=0, no status; F=1 only when the PDU ends
    /// a sequence (RFC 3720 §10.7.1).
    fn emit_data_in(
        &mut self,
        work: &mut [u8],
        offset: u32,
        bank: u32,
        len: u32,
        f_bit: bool,
    ) -> Emit {
        let data_sn = match self.host {
            HostPhase::Send(p) => p.data_sn,
            _ => return Emit::Error(TargetError::Internal),
        };
        let chunk_bank = match self.host {
            HostPhase::Send(p) => p.chunk_bank,
            _ => BankSide::Work,
        };
        let base = self.send_base(chunk_bank);
        let total = self.build_data_in(
            work,
            base,
            self.cmd_itt,
            offset,
            bank,
            len,
            data_sn,
            f_bit,
            None,
        );
        self.session = Session::Send {
            len: total,
            base,
            kind: SendKind::DataIn,
        };
        Emit::Send { len: total, base }
    }

    /// Terminating Data-In PDU (F=1, S=1) carrying the fixed status.
    #[allow(clippy::too_many_arguments)]
    fn emit_data_in_final(
        &mut self,
        work: &mut [u8],
        base: usize,
        offset: u32,
        bank: u32,
        len: u32,
        data_sn: u32,
        status: u8,
    ) -> Emit {
        self.note_status(self.cmd_itt);
        let total = self.build_data_in(
            work,
            base,
            self.cmd_itt,
            offset,
            bank,
            len,
            data_sn,
            true,
            Some(status),
        );
        self.session = Session::Send {
            len: total,
            base,
            kind: SendKind::Status {
                itt: self.cmd_itt,
                autosense: None,
            },
        };
        Emit::Send { len: total, base }
    }

    #[allow(clippy::too_many_arguments)]
    fn build_data_in(
        &mut self,
        work: &mut [u8],
        base: usize,
        itt: u32,
        offset: u32,
        bank: u32,
        len: u32,
        data_sn: u32,
        f_bit: bool,
        scsi_status: Option<u8>,
    ) -> usize {
        let len = len as usize;
        if bank > 0 && len > 0 {
            // The device's send buffer for this chunk sits at the start of the
            // SCSI data area; move it in front of the BHS.
            let start = base + BHS_SIZE + bank as usize;
            let end = start + len;
            work.copy_within(start..end, base + BHS_SIZE);
        }
        let mut bhs = Bhs::new();
        bhs.set_opcode(op::SCSI_DATA_IN);
        let mut flags = if f_bit { flag::F_BIT } else { 0 };
        if let Some(scsi_status) = scsi_status {
            // The S bit implies the final PDU of the whole transfer, so F is
            // always set alongside it.
            flags |= flag::F_BIT | flag::S_BIT;
            bhs.set_status(scsi_status);
        }
        bhs.set_flags(flags);
        bhs.set_itt(itt);
        bhs.set_data_sn(data_sn);
        bhs.set_buffer_offset(offset);
        bhs.set_data_segment_len(len as u32);
        bhs.set_stat_sn(self.stat_sn.get());
        bhs.set_exp_cmd_sn(self.cmd_sn.wrapping_add(1));
        bhs.set_max_cmd_sn(self.cmd_sn.wrapping_add(1));
        work[base..base + BHS_SIZE].copy_from_slice(bhs.as_bytes());
        let total = BHS_SIZE + len;
        // Every Data-In PDU is padded to a 4-byte boundary, including
        // intermediate chunks: an intermediate tail may be 1-3 bytes long.
        let pad = pdu_pad_len(len as u32) as usize;
        if pad > 0 {
            work[base + total..base + total + pad].fill(0);
        }
        if scsi_status.is_some() {
            self.stat_sn.set(self.stat_sn.get().wrapping_add(1));
        }
        total + pad
    }

    fn build_r2t(&mut self, work: &mut [u8]) {
        let base = self.pdu_base;
        let p = match &mut self.host {
            HostPhase::Recv(p) => p,
            _ => return,
        };
        let desired = (u64::from(self.neg.max_burst_len))
            .min(u64::from(p.phase_end.saturating_sub(p.accepted)))
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
        work[base..base + BHS_SIZE].copy_from_slice(bhs.as_bytes());
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
        // A Reject is a control PDU: it is framed in the command bank (or the
        // control bank when there is only one), never over the bank a resident
        // long token holds.
        let base = self.control_base();
        let mut bhs = Bhs::new();
        bhs.set_opcode(op::REJECT);
        bhs.set_flags(flag::F_BIT);
        bhs.set_reject_reason(reason);
        bhs.set_itt(0xFFFF_FFFF);
        bhs.set_stat_sn(self.stat_sn.get());
        bhs.set_exp_cmd_sn(self.cmd_sn.wrapping_add(1));
        bhs.set_max_cmd_sn(self.cmd_sn.wrapping_add(1));
        bhs.set_data_segment_len(BHS_SIZE as u32);
        work[base..base + BHS_SIZE].copy_from_slice(bhs.as_bytes());
        work[base + BHS_SIZE..base + 2 * BHS_SIZE].copy_from_slice(rejected.as_bytes());
        let total = 2 * BHS_SIZE;
        let pad = pdu_pad_len(BHS_SIZE as u32) as usize;
        work[base + total..base + total + pad].fill(0);
        self.stat_sn.set(self.stat_sn.get().wrapping_add(1));
        self.session = Session::Send {
            len: total + pad,
            base,
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
        Emit::Send {
            len: total + pad,
            base,
        }
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
                return self.boundary_recv();
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
        if pdu.dsl > self.our_recv_mdsl as usize {
            return self.reject(work, reject::PROTOCOL_ERROR);
        }
        if pdu.dsl > 0 && (!w_bit || !self.neg.immediate_data) {
            return self.reject(work, reject::PROTOCOL_ERROR);
        }
        // Unsolicited data is immediate data plus any unsolicited Data-Out
        // (RFC 3720 §12.14). The target always requires an R2T, so the only
        // unsolicited bytes are the command PDU's own data segment; it must
        // not exceed FirstBurstLength.
        if pdu.dsl as u32 > self.neg.first_burst_len {
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
        // `work[base + BHS_SIZE..base + BHS_SIZE + dsl]`, which is the SCSI
        // data area the device receives into.
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
            let base = self.pdu_base;
            if n > 0 {
                sense_write_fixed(
                    LUN_NOT_SUPPORTED,
                    &mut work[base + BHS_SIZE..base + BHS_SIZE + n],
                );
            }
            // A Data-In carrying the fixed-format sense; the command is not
            // driven by any slot.
            self.note_status(itt);
            let total =
                self.build_data_in(work, base, itt, 0, 0, n as u32, 0, true, Some(status::GOOD));
            self.session = Session::Send {
                len: total,
                base,
                kind: SendKind::Status {
                    itt,
                    autosense: None,
                },
            };
            return Emit::Send { len: total, base };
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
                return self.boundary_recv();
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
        let base = self.control_base();
        work[base..base + BHS_SIZE].copy_from_slice(resp.as_bytes());
        let pad = pdu_pad_len(0) as usize;
        work[base + BHS_SIZE..base + BHS_SIZE + pad].fill(0);
        self.stat_sn.set(self.stat_sn.get().wrapping_add(1));
        self.session = Session::Send {
            len: BHS_SIZE + pad,
            base,
            kind: SendKind::Tmf,
        };
        Emit::Send {
            len: BHS_SIZE + pad,
            base,
        }
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
            return self.boundary_recv();
        }

        // RFC 3720 §3.2.2.1: non-immediate commands advance CmdSN.
        if !immediate_flag {
            let recv_cmd_sn = bhs.cmd_sn();
            if recv_cmd_sn != self.cmd_sn.wrapping_add(1) {
                return self.boundary_recv();
            }
            self.cmd_sn = recv_cmd_sn;
        }

        let mut resp = Bhs::new();
        resp.set_opcode(op::NOP_IN);
        resp.set_flags(flag::F_BIT);
        resp.set_itt(itt);
        // RFC 3720 §10.19.1: a NOP-In answering a NOP-Out carries the reserved
        // 0xffffffff tag, and one answering an earlier NOP-In (whose reply
        // carries a valid tag) copies it back. Echoing the request tag covers
        // both: a ping carries 0xffffffff.
        resp.set_ttt(bhs.ttt());
        resp.set_stat_sn(self.stat_sn.get());
        resp.set_exp_cmd_sn(self.cmd_sn.wrapping_add(1));
        resp.set_max_cmd_sn(self.cmd_sn.wrapping_add(1));
        // RFC 3720 §10.19/§12.12: duplicate up to the first
        // MaxRecvDataSegmentLength bytes of the ping data — bounded by what the
        // peer declared it can receive, not by a fixed constant.
        let dlen = pdu.dsl.min(self.peer_recv_mdsl as usize);
        resp.set_data_segment_len(dlen as u32);
        let source = self.pdu_base;
        let base = self.control_base();
        work[base..base + BHS_SIZE].copy_from_slice(resp.as_bytes());
        if source != base && dlen > 0 {
            // The echoed ping data was received in the request's bank; move it
            // behind the control BHS so the response stays at the control base.
            work.copy_within(source + BHS_SIZE..source + BHS_SIZE + dlen, base + BHS_SIZE);
        }
        let total = BHS_SIZE + dlen;
        let pad = pdu_pad_len(dlen as u32) as usize;
        work[base + total..base + total + pad].fill(0);
        self.stat_sn.set(self.stat_sn.get().wrapping_add(1));
        self.session = Session::Send {
            len: total + pad,
            base,
            kind: SendKind::Continue,
        };
        Emit::Send {
            len: total + pad,
            base,
        }
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
        let base = self.control_base();
        work[base..base + BHS_SIZE].copy_from_slice(resp.as_bytes());
        let pad = pdu_pad_len(0) as usize;
        work[base + BHS_SIZE..base + BHS_SIZE + pad].fill(0);
        self.stat_sn.set(self.stat_sn.get().wrapping_add(1));
        self.session = Session::Send {
            len: BHS_SIZE + pad,
            base,
            kind: SendKind::Close,
        };
        Emit::Send {
            len: BHS_SIZE + pad,
            base,
        }
    }

    fn handle_text(&mut self, work: &mut [u8], pdu: &Pdu) -> Emit {
        let bhs = &pdu.bhs;
        // F=0 (continuation) and non-0xFFFFFFFF TTT are not supported (no
        // fragmentation); the handler stays lenient for a minimal text BHS.
        let source = self.pdu_base;
        if pdu.dsl
            > self
                .bank_end(work.len(), source)
                .saturating_sub(source + BHS_SIZE)
        {
            return Emit::Error(TargetError::WorkBufTooSmall);
        }
        let data = &work[source + BHS_SIZE..source + BHS_SIZE + pdu.dsl];
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
        let base = self.control_base();
        let mut resp = Bhs::new();
        resp.set_opcode(op::TEXT_RESP);
        resp.set_flags(flag::F_BIT);
        resp.set_itt(bhs.itt());
        resp.set_ttt(0xFFFF_FFFF);
        resp.set_stat_sn(self.stat_sn.get());
        resp.set_exp_cmd_sn(self.cmd_sn.wrapping_add(1));
        resp.set_max_cmd_sn(self.cmd_sn.wrapping_add(1));
        let dlen: u32 = if should_return {
            // RFC 3720 §10.11.6: a Text Response must not exceed the
            // initiator's declared receive segment; also stay inside this
            // target's own segment bound and the work bank.
            let cap = work
                .len()
                .saturating_sub(base)
                .saturating_sub(BHS_SIZE)
                .min(self.our_recv_mdsl as usize)
                .min(self.peer_recv_mdsl as usize);
            let txt = TARGET_NAME.as_bytes();
            let prefix = b"TargetName=";
            let needed = prefix.len() + txt.len() + 1;
            if needed <= cap {
                work[base + BHS_SIZE..base + BHS_SIZE + prefix.len()].copy_from_slice(prefix);
                work[base + BHS_SIZE + prefix.len()..base + BHS_SIZE + prefix.len() + txt.len()]
                    .copy_from_slice(txt);
                work[base + BHS_SIZE + prefix.len() + txt.len()] = 0;
                needed as u32
            } else {
                // The key cannot be delivered as requested; answer it as not
                // understood (RFC 3720 §5.2) if even that does not fit, send
                // an empty data segment.
                let alt = b"TargetName=NotUnderstood\0";
                if alt.len() <= cap {
                    work[base + BHS_SIZE..base + BHS_SIZE + alt.len()].copy_from_slice(alt);
                    alt.len() as u32
                } else {
                    0
                }
            }
        } else {
            0
        };
        resp.set_data_segment_len(dlen);
        work[base..base + BHS_SIZE].copy_from_slice(resp.as_bytes());
        let total = BHS_SIZE + dlen as usize;
        let pad = pdu_pad_len(dlen) as usize;
        work[base + total..base + total + pad].fill(0);
        self.stat_sn.set(self.stat_sn.get().wrapping_add(1));
        self.session = Session::Send {
            len: total + pad,
            base,
            kind: SendKind::Continue,
        };
        Emit::Send {
            len: total + pad,
            base,
        }
    }

    // ── Login Phase ───────────────────────────────────────────────

    fn handle_login(&mut self, work: &mut [u8]) -> Emit {
        let pdu = Pdu {
            bhs: Bhs::from_bytes(self.bhs),
            dsl: Bhs::from_bytes(self.bhs).data_segment_len() as usize,
        };
        let req = &pdu.bhs;
        // Login is framed before any command owns a bank.
        let base = CONTROL_PDU_BASE;
        // Login C bit (byte1 bit6, RFC 3720 §10.12.1) — continuation not
        // supported; reject if set.
        if req.as_bytes()[1] & 0x40 != 0 {
            return self.reject(work, reject::PROTOCOL_ERROR);
        }
        // Version range check (RFC 3720 §10.13.5): we support 0x00 only.
        let req_min = req.version_min();
        if req_min > 0x00 {
            // Initiator Error / Version not supported.
            return self.login_error(work, 0x02, 0x05);
        }
        if pdu.dsl > self.our_recv_mdsl as usize || base + BHS_SIZE + pdu.dsl > work.len() {
            // Initiator Error / Invalid during login.
            return self.login_error(work, 0x02, 0x0B);
        }
        let req_csg = req.csg() & 0x03;
        let t = req.t_bit();

        // `our_recv_mdsl` is this target's own receive capability: it bounds
        // incoming Data-Out segments and is what the Login Response declares.
        // It does not depend on the initiator's declaration, and it never
        // bounds Data-In (the initiator's value does).

        // Negotiate: build the response text (updating `self.neg` alongside)
        // in the free tail, then move it in front of the BHS. `negotiate`
        // never writes past the bounded response area, so a pathological
        // request truncates cleanly instead of failing the session.
        let (head, tail) = work.split_at_mut(base + BHS_SIZE + pdu.dsl);
        let resp_len = self.negotiate(&head[base + BHS_SIZE..], tail);
        work.copy_within(
            base + BHS_SIZE + pdu.dsl..base + BHS_SIZE + pdu.dsl + resp_len,
            base + BHS_SIZE,
        );

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

        // Assemble: BHS at work[base..base+48], data behind it.
        work[base..base + BHS_SIZE].copy_from_slice(resp.as_bytes());
        let total = BHS_SIZE + resp_len;
        let pad = pdu_pad_len(resp_len as u32) as usize;
        work[base + total..base + total + pad].fill(0);
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
            base,
            kind: SendKind::Continue,
        };
        Emit::Send {
            len: total + pad,
            base,
        }
    }

    /// Login Response rejecting the request with the given Status-Class and
    /// Status-Detail (RFC 3720 §10.13.5). A non-zero class ends the
    /// connection.
    fn login_error(&mut self, work: &mut [u8], status_class: u8, status_detail: u8) -> Emit {
        let req = Bhs::from_bytes(self.bhs);
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
        resp.as_mut_bytes()[36] = status_class;
        resp.as_mut_bytes()[37] = status_detail;
        let base = CONTROL_PDU_BASE;
        work[base..base + BHS_SIZE].copy_from_slice(resp.as_bytes());
        let pad = pdu_pad_len(0) as usize;
        work[base + BHS_SIZE..base + BHS_SIZE + pad].fill(0);
        self.stat_sn.set(self.stat_sn.get().wrapping_add(1));
        self.session = Session::Send {
            len: BHS_SIZE + pad,
            base,
            kind: SendKind::Close,
        };
        Emit::Send {
            len: BHS_SIZE + pad,
            base,
        }
    }

    /// Parse initiator key=value text into a response, updating negotiated
    /// parameters. Writes at most `min(dst, our_recv_mdsl, peer_recv_mdsl)`
    /// bytes and returns the response length.
    fn negotiate(&mut self, src: &[u8], dst: &mut [u8]) -> usize {
        // A declaration in this request takes effect for its own response.
        if let Some(v) = src_u32(src, b"MaxRecvDataSegmentLength") {
            self.peer_recv_mdsl = v.clamp(MIN_RECV_DATA_SEGMENT, HARD_CAP);
        }
        // FirstBurstLength may only be answered once MaxBurstLength is known,
        // regardless of the order the keys appear in the request (RFC 3720
        // §12.14 integrity rule).
        let burst_ceiling = src_u32(src, b"MaxBurstLength")
            .map(clamp_max_burst)
            .unwrap_or(self.neg.max_burst_len);
        // Never emit more than the receiver declared or this target accepts,
        // and never past the caller's bank (RFC 3720 §10.11.6/§12.12).
        let cap = dst
            .len()
            .min(self.our_recv_mdsl as usize)
            .min(self.peer_recv_mdsl as usize);
        let dst = &mut dst[..cap];

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
                    append_key(dst, &mut w, key, out);
                } else if key == b"InitialR2T" {
                    // RFC 3720 §12.10 Result function is OR, Default Yes.
                    let initiator_yes = val == b"Yes";
                    let result_yes = initiator_yes || true; // target offers Yes
                    self.neg.initial_r2t = result_yes;
                    let out: &[u8] = if result_yes { b"Yes" } else { b"No" };
                    append_key(dst, &mut w, key, out);
                } else if key == b"MaxBurstLength" {
                    // RFC 3720 §12.13 Result function is Minimum. A value
                    // outside the valid range (or not numeric) keeps the
                    // current/default figure.
                    let negotiated = parse_u32(val)
                        .map(clamp_max_burst)
                        .unwrap_or(self.neg.max_burst_len);
                    self.neg.max_burst_len = negotiated;
                    append_key_u32(dst, &mut w, key, negotiated);
                } else if key == b"FirstBurstLength" {
                    // RFC 3720 §12.14 Result function is Minimum; the result
                    // must stay within 512..=MaxBurstLength.
                    let negotiated = parse_u32(val)
                        .map(|v| clamp_first_burst(v, burst_ceiling))
                        .unwrap_or_else(|| {
                            clamp_first_burst(self.neg.first_burst_len, burst_ceiling)
                        });
                    self.neg.first_burst_len = negotiated;
                    append_key_u32(dst, &mut w, key, negotiated);
                } else if key == b"MaxRecvDataSegmentLength" {
                    // Declarative and per direction (RFC 3720 §12.12): the
                    // initiator's figure bounds the Data-In PDUs we send; the
                    // response carries our own receive capability, unchanged
                    // by the offer.
                    append_key_u32(dst, &mut w, key, self.our_recv_mdsl);
                } else {
                    self.apply_neg(LOGIN_TABLE[idx].key, val);
                    let out_val: &[u8] = match LOGIN_TABLE[idx].value {
                        Some(v) => v.as_bytes(),
                        None => val,
                    };
                    append_key(dst, &mut w, key, out_val);
                }
            } else if !is_skip_key(key) {
                // RFC 3720 §5.2: a key not understood is answered with
                // NotUnderstood, never with Reject.
                append_key(dst, &mut w, key, b"NotUnderstood");
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
                    append_key(dst, &mut w, param.key.as_bytes(), v.as_bytes());
                }
            }
        }
        // Integrity rule after every parameter is known (RFC 3720 §5.2/§12.14).
        self.neg.first_burst_len =
            clamp_first_burst(self.neg.first_burst_len, self.neg.max_burst_len);
        w
    }

    fn apply_neg(&mut self, key: &str, val: &[u8]) {
        match key {
            "MaxBurstLength" => {
                if let Some(v) = parse_u32(val) {
                    self.neg.max_burst_len = clamp_max_burst(v);
                }
            }
            "FirstBurstLength" => {
                if let Some(v) = parse_u32(val) {
                    self.neg.first_burst_len = clamp_first_burst(v, self.neg.max_burst_len);
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
        if req.dir != Direction::FromHost {
            return HostToken::new(u8::MAX, 0);
        }
        let total = u32::try_from(self.plan.bytes).unwrap_or(u32::MAX);
        // A second (or later) device chunk continues the same plan; only the
        // first one starts from zero and consumes the immediate data.
        let mut p = match self.host {
            HostPhase::Recv(p) if p.produced < p.total => p,
            _ => RecvPhase {
                token,
                total,
                accepted: self.immediate.min(total),
                produced: 0,
                chunk_base: 0,
                phase_len: 0,
                phase_end: 0,
                r2t_sn: 0,
                data_sn: 0,
                burst_remaining: 0,
                r2t_pending: false,
                consumed: false,
                done: false,
            },
        };
        if p.produced >= p.total {
            p.token = token;
            p.chunk_base = 0;
            p.phase_len = req.len;
            p.done = true;
            self.host = HostPhase::Recv(p);
            return token;
        }
        if req.len == 0 || u64::from(req.len) > u64::from(p.total - p.produced) {
            return HostToken::new(u8::MAX, 0);
        }
        let base = p.produced;
        p.token = token;
        p.chunk_base = base;
        p.phase_len = req.len;
        p.phase_end = base + req.len;
        p.data_sn = 0;
        p.burst_remaining = 0;
        p.r2t_pending = p.accepted < p.phase_end;
        p.consumed = false;
        p.done = false;
        self.host = HostPhase::Recv(p);
        token
    }

    fn begin_send(&mut self, req: HostReq) -> HostToken {
        let token = self.next_token();
        if req.dir != Direction::ToHost {
            return HostToken::new(u8::MAX, 0);
        }
        let total = u32::try_from(self.plan.bytes).unwrap_or(u32::MAX);
        // A second (or later) device chunk continues the same Data-In stream:
        // DataSN and BufferOffset keep counting across chunks.
        let mut p = match self.host {
            HostPhase::Send(p) if p.sent < p.total => p,
            _ => SendPhase {
                token,
                total,
                sent: 0,
                data_sn: 0,
                seq_bytes: 0,
                phase_base: 0,
                phase_len: 0,
                staged: None,
                held: None,
                chunk_bank: BankSide::Work,
            },
        };
        if req.len == 0 || u64::from(req.len) > u64::from(p.total - p.sent) {
            return HostToken::new(u8::MAX, 0);
        }
        p.token = token;
        p.phase_base = p.sent;
        p.phase_len = req.len;
        p.staged = None;
        p.held = None;
        self.host = HostPhase::Send(p);
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
                let (buf, side) = match buf {
                    HostBuf::Send { bytes: buf, bank } if buf.len() == p.phase_len as usize => {
                        (buf, bank)
                    }
                    _ => return Poll::Ready(HostReceipt::from_adapter(0, Some(Fault::Contract))),
                };
                if self.overlap && side != BankSide::Work && self.cmd_alt.is_none() {
                    // The runner can only name the alternate bank when the
                    // command was given one.
                    return Poll::Ready(HostReceipt::from_adapter(0, Some(Fault::Contract)));
                }
                p.chunk_bank = self.physical_bank(side);
                let remaining = (p.phase_base + p.phase_len).saturating_sub(p.sent);
                if remaining == 0 {
                    self.host = HostPhase::Send(p);
                    return Poll::Ready(HostReceipt::from_adapter(p.phase_len as usize, None));
                }
                let bank = buf.len() as u32;
                // Per-PDU bound: our device chunk remainder, the initiator's
                // declared receive segment, the bank, and the room left in the
                // current sequence (RFC 3720 §10.7.1).
                let burst_left = self.neg.max_burst_len.saturating_sub(p.seq_bytes);
                let cap = remaining.min(self.peer_recv_mdsl).min(bank).min(burst_left);
                if cap == 0 {
                    return Poll::Ready(HostReceipt::from_adapter(
                        p.sent.saturating_sub(p.phase_base) as usize,
                        Some(Fault::Contract),
                    ));
                }
                let last_of_plan = p.sent + cap >= p.total;
                let local = p.sent.saturating_sub(p.phase_base);
                if cap < remaining {
                    // Intermediate PDU: stage a 4-aligned prefix so its
                    // padding never lands on bytes that are still unsent.
                    let chunk = cap & !3;
                    if chunk == 0 {
                        // Not reachable with an aligned bank and the
                        // MaxRecvDataSegmentLength floor; fail closed.
                        return Poll::Ready(HostReceipt::from_adapter(
                            local as usize,
                            Some(Fault::Contract),
                        ));
                    }
                    let f_bit = send_ends_sequence(p.seq_bytes, chunk, self.neg.max_burst_len);
                    p.staged = Some((p.sent, local, chunk, f_bit));
                    self.host = HostPhase::Send(p);
                    return Poll::Pending;
                }
                if last_of_plan {
                    // Last PDU of the last chunk: hold it back for the
                    // terminating Data-In, which also carries the fixed status.
                    let pad = pdu_pad_len(remaining) as usize;
                    if remaining as usize + pad > self.bank_len {
                        // Keep a 4-aligned prefix and leave the tail for a
                        // second PDU whose padding fits.
                        let tail = remaining & 3;
                        let split = remaining.saturating_sub(tail);
                        if split > 0 && split < remaining {
                            let f_bit =
                                send_ends_sequence(p.seq_bytes, split, self.neg.max_burst_len);
                            p.staged = Some((p.sent, local, split, f_bit));
                            self.host = HostPhase::Send(p);
                            return Poll::Pending;
                        }
                    }
                    p.held = Some((p.sent, local, remaining));
                    let accepted = p.phase_len;
                    self.host = HostPhase::Send(p);
                    return Poll::Ready(HostReceipt::from_adapter(accepted as usize, None));
                }
                // Last PDU of an intermediate chunk: stage exactly the bytes
                // that remain (a 1-3 byte tail is padded, never rounded up
                // into the next chunk). F is set only when this PDU closes a
                // sequence.
                let f_bit = send_ends_sequence(p.seq_bytes, remaining, self.neg.max_burst_len);
                p.staged = Some((p.sent, local, remaining, f_bit));
                self.host = HostPhase::Send(p);
                Poll::Pending
            }
            Phase::Recv(mut p) => {
                match buf {
                    HostBuf::Recv { buf, bank }
                        if buf.len() == p.phase_len as usize
                            && (!self.overlap || bank == BankSide::Work) => {}
                    _ => return Poll::Ready(HostReceipt::from_adapter(0, Some(Fault::Contract))),
                }
                if p.done {
                    self.host = HostPhase::Recv(p);
                    return Poll::Ready(HostReceipt::from_adapter(p.phase_len as usize, None));
                }
                if p.accepted >= p.phase_end {
                    // The chunk was already covered by immediate data.
                    p.produced = p.phase_end;
                    let accepted = p.phase_len;
                    self.host = HostPhase::Recv(p);
                    return Poll::Ready(HostReceipt::from_adapter(accepted as usize, None));
                }
                if p.consumed {
                    p.consumed = false;
                    if p.accepted >= p.phase_end {
                        p.produced = p.phase_end;
                        let accepted = p.phase_len;
                        self.host = HostPhase::Recv(p);
                        return Poll::Ready(HostReceipt::from_adapter(accepted as usize, None));
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

/// Negotiated `MaxBurstLength` (RFC 3720 §12.13): the minimum of the
/// initiator's offer and our default, kept inside the protocol's valid range so
/// a sequence can always make progress.
fn clamp_max_burst(v: u32) -> u32 {
    v.clamp(MIN_RECV_DATA_SEGMENT, DEFAULT_MAX_BURST)
}

/// Negotiated `FirstBurstLength` (RFC 3720 §12.14): at most our default and
/// never above `MaxBurstLength`, with the protocol's 512-byte floor.
fn clamp_first_burst(v: u32, max_burst_len: u32) -> u32 {
    v.clamp(MIN_RECV_DATA_SEGMENT, DEFAULT_FIRST_BURST)
        .min(max_burst_len.max(MIN_RECV_DATA_SEGMENT))
}

/// First numeric value offered for `key` in a login request, if any.
fn src_u32(src: &[u8], key: &[u8]) -> Option<u32> {
    let mut p = 0usize;
    while p < src.len() {
        let eq = p + src[p..].iter().position(|&b| b == b'=')?;
        let val_end = src[eq + 1..]
            .iter()
            .position(|&b| b == 0)
            .map_or(src.len(), |i| eq + 1 + i);
        if &src[p..eq] == key {
            return parse_u32(&src[eq + 1..val_end]);
        }
        p = if val_end < src.len() {
            val_end + 1
        } else {
            src.len()
        };
    }
    None
}

/// Whether a Data-In PDU of `len` bytes at `seq_bytes` into its sequence closes
/// it.
///
/// A sequence ends when this PDU exhausts `MaxBurstLength`, or when the room
/// left (1-3 bytes) could no longer hold another 4-aligned segment. Ending a
/// little early is always allowed; exceeding the limit is not (RFC 3720
/// §10.7.1).
fn send_ends_sequence(seq_bytes: u32, len: u32, max_burst_len: u32) -> bool {
    seq_bytes.saturating_add(len).saturating_add(3) >= max_burst_len
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

fn append_key(dst: &mut [u8], w: &mut usize, k: &[u8], v: &[u8]) {
    // A key whose normal answer does not fit is still answered, as
    // NotUnderstood, when that shorter value fits (RFC 3720 §5.2).
    if !append_kv(dst, w, k, v) {
        let _ = append_kv(dst, w, k, b"NotUnderstood");
    }
}

fn append_key_u32(dst: &mut [u8], w: &mut usize, key: &[u8], v: u32) {
    let mut buf = [0u8; 10];
    let digits = fmt_u32(v, &mut buf);
    append_key(dst, w, key, digits);
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
    fn negotiate_never_writes_past_a_tiny_response_bank() {
        let mut session = IscsiSession::new();
        let src = b"InitiatorName=iqn.test\0TargetName=iqn.target\0";
        let mut tiny = [0u8; 10];
        let n = session.negotiate(src, &mut tiny);
        assert!(n <= tiny.len(), "the response length stays inside the bank");
        assert_eq!(n, 0, "no key fits, so the response is empty");
    }

    #[test]
    fn negotiate_caps_the_response_at_our_receive_segment() {
        // Many short unknown keys would expand far past one receive segment if
        // each were answered in full.
        let mut src = Vec::new();
        for _ in 0..2000 {
            src.extend_from_slice(b"a=\0");
        }
        let mut session = IscsiSession::new();
        let mut dst = vec![0u8; 16 * 1024];
        let n = session.negotiate(&src, &mut dst);
        assert!(n <= OUR_RECV_MDSL as usize);
        assert!(n > 0);
        assert_eq!(dst[n - 1], 0, "the last entry is NUL-terminated");
        let entries = dst[..n]
            .split(|&b| b == 0)
            .filter(|entry| !entry.is_empty());
        assert!(entries.into_iter().all(|entry| entry == b"a=NotUnderstood"));
    }

    #[test]
    fn peer_receive_segment_offer_above_the_wire_field_is_clamped() {
        let mut session = IscsiSession::new();
        let src = b"MaxRecvDataSegmentLength=16777216\0";
        let mut dst = [0u8; 512];
        let _ = session.negotiate(src, &mut dst);
        assert_eq!(session.peer_recv_mdsl, HARD_CAP);
    }

    #[test]
    fn non_numeric_offers_keep_their_defaults() {
        let mut session = IscsiSession::new();
        let src = b"MaxBurstLength=not-a-number\0FirstBurstLength=also-not\0MaxRecvDataSegmentLength=NaN\0";
        let mut dst = [0u8; 512];
        let n = session.negotiate(src, &mut dst);
        assert_eq!(session.neg.max_burst_len, DEFAULT_MAX_BURST);
        assert_eq!(session.neg.first_burst_len, DEFAULT_FIRST_BURST);
        assert_eq!(session.peer_recv_mdsl, OUR_RECV_MDSL);
        let data = &dst[..n];
        assert!(contains_entry(data, b"MaxBurstLength=262144"));
        assert!(contains_entry(data, b"FirstBurstLength=65536"));
        assert!(contains_entry(data, b"MaxRecvDataSegmentLength=8192"));
    }

    #[test]
    fn first_burst_offer_is_clamped_to_the_burst_range() {
        let mut session = IscsiSession::new();
        let src = b"MaxBurstLength=512\0FirstBurstLength=65536\0";
        let mut dst = [0u8; 512];
        let n = session.negotiate(src, &mut dst);
        assert_eq!(session.neg.max_burst_len, 512);
        assert_eq!(session.neg.first_burst_len, 512);
        assert!(contains_entry(&dst[..n], b"FirstBurstLength=512"));

        // A sub-floor offer is raised to 512.
        let mut session = IscsiSession::new();
        let src = b"FirstBurstLength=1\0";
        let mut dst = [0u8; 512];
        let n = session.negotiate(src, &mut dst);
        assert_eq!(session.neg.first_burst_len, MIN_RECV_DATA_SEGMENT);
        assert!(contains_entry(&dst[..n], b"FirstBurstLength=512"));
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

    /// The 1-3 byte tail at the end of a device chunk is staged exactly, never
    /// rounded up to a 4-byte word that would read past the bank.
    #[test]
    fn send_staging_never_passes_the_chunk_remainder() {
        use core::task::Poll;

        let mut session = IscsiSession::new();
        session.cmd_itt = 1;
        session.peer_recv_mdsl = 8192;
        session.bank_len = 8193;
        session.plan = DataPlan {
            direction: Direction::ToHost,
            bytes: 16385,
        };
        let bank = vec![0u8; 8193];
        let token = session.begin_send(HostReq {
            len: 8193,
            dir: Direction::ToHost,
        });
        assert!(token.is_valid());

        // First PDU: a full segment.
        assert!(matches!(
            session.poll_host(
                token,
                HostBuf::Send {
                    bytes: &bank,
                    bank: crate::core::storage::BankSide::Work
                }
            ),
            Poll::Pending
        ));
        let staged = match &mut session.host {
            HostPhase::Send(p) => {
                let staged = p.staged.take().expect("first segment staged");
                p.sent = p.sent.saturating_add(staged.2);
                p.data_sn = p.data_sn.wrapping_add(1);
                staged
            }
            other => panic!("expected a send phase, got {other:?}"),
        };
        assert_eq!(staged.2, 8192);
        assert!(!staged.3, "the whole transfer fits one sequence");

        // Second PDU: the chunk's last byte, exactly one byte long.
        assert!(matches!(
            session.poll_host(
                token,
                HostBuf::Send {
                    bytes: &bank,
                    bank: crate::core::storage::BankSide::Work
                }
            ),
            Poll::Pending
        ));
        let staged = match &mut session.host {
            HostPhase::Send(p) => p.staged.expect("tail staged"),
            other => panic!("expected a send phase, got {other:?}"),
        };
        assert_eq!(staged.2, 1, "the tail is not rounded up");
        assert!(!staged.3, "the chunk end alone does not close a sequence");
        assert!(
            staged.1 as usize + staged.2 as usize <= bank.len(),
            "staging must stay inside the bank"
        );
    }

    #[test]
    fn every_data_in_pdu_is_padded_even_when_intermediate() {
        let mut session = IscsiSession::new();
        session.cmd_itt = 1;
        let mut work = vec![0xAAu8; BHS_SIZE + 8];
        let total = session.build_data_in(&mut work, 0, 1, 0, 0, 1, 0, false, None);
        assert_eq!(total, BHS_SIZE + 1 + 3);
        assert_eq!(&work[BHS_SIZE + 1..BHS_SIZE + 4], &[0, 0, 0]);
    }

    /// A nonzero PDU base frames the Data-In BHS and payload at the bank start
    /// and emits the staged send from that base.
    #[test]
    fn data_in_framing_and_send_use_a_nonzero_pdu_base() {
        use crate::block::{BlockAttrs, BlockDevice};
        use crate::core::storage::{BlockingStorage, IoBuf, IoReq, StorageReceipt, SyncStorage};
        use crate::core::{Lu, LuImpl, NoMedium, Pair, Spc, Target};

        struct Sink;
        impl SyncStorage for Sink {
            fn exec(&mut self, _req: IoReq, buf: IoBuf<'_>) -> StorageReceipt {
                let len = match &buf {
                    IoBuf::None => 0,
                    IoBuf::Read(b) => b.len(),
                    IoBuf::Write(b) => b.len(),
                };
                StorageReceipt::ok(len)
            }
        }

        const BANK: usize = 8240;
        let mut session = IscsiSession::new();
        session.pdu_base = BANK;
        session.cmd_itt = 7;
        session.recv_mdsl_fixed = true;
        let mut work = vec![0xAAu8; 2 * BANK];

        let payload = [1u8, 2, 3, 4, 5];
        let src = BANK + BHS_SIZE + 16;
        work[src..src + payload.len()].copy_from_slice(&payload);
        let len = session.build_data_in(
            &mut work,
            BANK,
            session.cmd_itt,
            0,
            16,
            payload.len() as u32,
            0,
            false,
            None,
        );
        assert_eq!(len, BHS_SIZE + payload.len() + 3, "the PDU is padded");

        let bhs = Bhs::from_bytes(work[BANK..BANK + BHS_SIZE].try_into().unwrap());
        assert_eq!(bhs.opcode(), op::SCSI_DATA_IN);
        assert_eq!(bhs.data_segment_len() as usize, payload.len());
        assert_eq!(
            &work[BANK + BHS_SIZE..BANK + BHS_SIZE + payload.len()],
            &payload,
            "the payload is moved directly behind the bank's BHS"
        );
        assert!(
            work[..BANK].iter().all(|&b| b == 0xAA),
            "the slot in front of the base is untouched"
        );
        assert!(
            work[BANK + len..src].iter().all(|&b| b == 0xAA),
            "nothing between the PDU end and the source is touched"
        );

        // The deferred send slices from the bank base, not from work[0].
        let mut slot = LuImpl::new(Spc::new(BlockDevice::new(BlockAttrs::new(16, 512))), 0u8);
        let mut table = [&mut slot as &mut dyn Lu<Pair = Pair<NoMedium, u8>>];
        let mut target = Target::new(&mut table[..]);
        let mut storage = BlockingStorage::new(Sink);
        let mut scratch = [0u8; 0];
        session.session = Session::Send {
            len,
            base: BANK,
            kind: SendKind::Continue,
        };
        match session.poll(
            Event::Tick,
            &mut work,
            &mut scratch,
            &mut target,
            &mut storage,
        ) {
            Action::HostSend { bytes, .. } => {
                assert_eq!(bytes.len(), len);
                assert_eq!(
                    bytes[0] & 0x3F,
                    op::SCSI_DATA_IN,
                    "the send starts at the PDU base"
                );
                assert_eq!(&bytes[BHS_SIZE..BHS_SIZE + payload.len()], &payload);
                assert_eq!(
                    &bytes[BHS_SIZE + payload.len()..],
                    &[0, 0, 0],
                    "the emitted PDU keeps its padding"
                );
            }
            other => panic!("expected HostSend, got {other:?}"),
        }

        // The receive path asks for the next BHS at the same base.
        session.session = Session::RecvPdu;
        match session.poll(
            Event::Tick,
            &mut work,
            &mut scratch,
            &mut target,
            &mut storage,
        ) {
            Action::HostRecv { offset, len } => {
                assert_eq!(offset, BANK);
                assert_eq!(len, BHS_SIZE);
            }
            other => panic!("expected HostRecv, got {other:?}"),
        }
    }

    /// A declared segment plus padding that fits the whole work slice but not
    /// the current bank's data area is refused, so framing never runs past
    /// `base + BHS_SIZE + bank data area`.
    #[test]
    fn pdu_remainder_is_bounded_by_the_bank_data_area() {
        const BANK: usize = 8240;
        const AREA: usize = BANK - BHS_SIZE;
        const WORK: usize = 2 * BANK;

        let mut session = IscsiSession::new();
        let mut bhs = Bhs::new();
        bhs.set_data_segment_len(AREA as u32);
        session.bhs = *bhs.as_bytes();

        // Exactly one bank's data area fits at either base.
        assert_eq!(session.pdu_remainder(WORK), Ok(AREA));
        session.pdu_base = BANK;
        assert_eq!(session.pdu_remainder(WORK), Ok(AREA));

        // One byte more overruns the second bank's data area, even though it
        // still fits the whole slice at base 0.
        bhs.set_data_segment_len(AREA as u32 + 1);
        session.bhs = *bhs.as_bytes();
        assert_eq!(
            session.pdu_remainder(WORK),
            Err(TargetError::WorkBufTooSmall)
        );
        session.pdu_base = 0;
        assert_eq!(session.pdu_remainder(WORK), Ok(AREA + 1 + 3));
    }

    #[test]
    fn sequence_boundary_is_the_burst_limit_not_the_chunk_end() {
        // A 100-byte PDU at the end of a device chunk does not close the
        // sequence while MaxBurstLength still has room.
        assert!(!send_ends_sequence(0, 100, 262_144));
        // The PDU that reaches the limit does.
        assert!(send_ends_sequence(262_144 - 512, 512, 262_144));
        // A non-4-multiple limit closes the sequence once fewer than 4 bytes
        // remain, so the next aligned segment can never overflow it.
        assert!(!send_ends_sequence(505, 4, 513));
        assert!(send_ends_sequence(506, 4, 513));
        assert!(send_ends_sequence(509, 4, 513));
    }

    fn contains_entry(data: &[u8], needle: &[u8]) -> bool {
        data.split(|&b| b == 0).any(|entry| entry == needle)
    }
}
