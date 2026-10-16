//! iSCSI target protocol state machine (RFC 3720 §5 / §10).
//!
//! [`IscsiSession`] is a pure, non-blocking protocol state machine: it never
//! blocks and never touches platform I/O.  A shell feeds one [`Event`] (an I/O
//! completion) per [`IscsiSession::poll`] call and learns the next [`Action`]
//! (receive, send, a storage op, or close).  The library shell
//! `crate::iscsi::transport::serve` (behind `std`) owns the platform loop; the
//! shell carries no protocol knowledge.
//!
//! Incoming PDUs are framed in two stages: the core first asks for the
//! 48-byte BHS (`RecvPdu`); on the BHS event it saves the header, parses
//! `DataSegmentLength` / `TotalAHSLength` and asks for the remainder
//! (`RecvData`); on the data event it reassembles the PDU in `work` (data at
//! `work[BHS_SIZE..]`) and dispatches it to the handlers.
//!
//! A device data phase that yields [`Xfer::Store`] is handed to the shell as
//! [`Action::Store`]; the shell executes it against the LUN's storage plane and
//! feeds the result back as [`Event::StoreDone`], which the session maps
//! through [`ScsiDevice::store_done`].  The wire bytes are unchanged.
//!
//! Key fixes over the legacy C implementation: CID read at
//! byte 20-21 (from iscsi_pdu), Data-Out ITT/TTT/BufferOffset/DataSN
//! validation with Reject 0x09 (#11), TMF CmdSN check by I bit (#21),
//! out-of-window/duplicate CmdSN silently ignored (#17), Reject carries
//! the rejected PDU header + ITT=0xffffffff (#18), and read-timeout
//! coverage is delegated to the `Conn` implementation (#10/#20).

use core::cell::Cell;

use crate::common::store::StoreOp;
use crate::iscsi::pdu::{
    flag, iscsi_opcode_name, op, pdu_pad_len, reject, stage, status, tmf, tmf_response, Bhs,
    BHS_SIZE, MAX_DATA_SEGMENT,
};
use crate::scsi::backend::StorageError;
use crate::scsi::device::{sense_for_storage_error, CommandOutcome, ScsiDevice, Xfer, XferOutcome};
use crate::scsi::scsi::op as scsi_op;
use crate::scsi::scsi::{asc, opcode_from_cdb, opcode_name, Sense, SenseKey};

// ── Public types ─────────────────────────────────────────────────────

/// The core's next action, returned by [`IscsiSession::poll`].
///
/// Normal flow never emits a "done" boundary: after a response is sent,
/// `poll(Event::HostSent)` returns the next command-phase
/// [`Action::HostRecv`] directly.  Only [`Action::Closed`] / [`Action::Error`]
/// are distinct endings.
#[derive(Debug)]
pub enum Action<'a> {
    /// Receive `len` bytes into `work[0..len]`.  PDUs are framed in two
    /// stages: first [`BHS_SIZE`], then the remainder
    /// (`TotalAHSLength*4 + DataSegmentLength + padding`).
    HostRecv { len: usize },
    /// Send `bytes` to the wire (a complete PDU: BHS + data + padding).
    /// `prefetch` is the next read-ahead coordinate for read-phase overlap
    /// (always `None` in v1).
    HostSend {
        bytes: &'a [u8],
        prefetch: Option<(u64, usize)>,
    },
    /// Hand a storage op to the shell: the device's `xfer_in`/`xfer_out`
    /// returned [`Xfer::Store`].  The shell executes it against the LUN's
    /// storage plane and feeds the result back as [`Event::StoreDone`].
    Store { lun: usize, op: StoreOp<'a> },
    /// The connection is done (Logout response sent, peer closed, or a fatal
    /// protocol error): the shell closes it.
    Closed,
    /// Internal error (caller bug): work buffer too small, etc.
    Error(TargetError),
}

/// One completion fed from the shell to [`IscsiSession::poll`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Event {
    /// No-I/O driver tick (startup + timer): change no state and re-emit the
    /// current pending [`Action`].
    Tick,
    /// The shell received `len` bytes into `work[0..len]` (a BHS or a data
    /// segment, per the previous [`Action::HostRecv`]).
    HostRecv { len: usize },
    /// The pending [`Action::HostSend`] packet has been sent.
    HostSent,
    /// A storage op finished: the shell executed an [`Action::Store`] and
    /// reports the plane's outcome.  The session maps it through
    /// [`ScsiDevice::store_done`] and continues the data phase.
    StoreDone { result: Result<(), StorageError> },
}

/// Target-level error (no_std).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TargetError {
    /// Caller's work buffer is smaller than [`crate::MIN_DATA_LEN`] +
    /// `BHS_SIZE` (data area too small for the SCSI layer).
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
    Security,
    OpParam,
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
    pub immediate_data: bool,
    pub initial_r2t: bool,
    pub first_burst_len: u32,
    pub max_burst_len: u32,
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
/// Largest login data segment accepted for negotiation (C `LOGIN_RESP_MAX`).
const LOGIN_MAX: usize = 4096;

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
    state: IscsiState,
    /// BHS of the PDU currently being framed: saved on the BHS event and
    /// restored into `work[..BHS_SIZE]` before the PDU is dispatched.
    bhs: [u8; BHS_SIZE],
}

/// Two-stage receive framing (`__M6_ISCSI.md` §2): the BHS is read first, then
/// the AHS + data segment + padding remainder.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Frame {
    /// The R2T for the current burst is pending in `work[..BHS_SIZE]`.
    Send,
    /// Waiting for the 48-byte BHS.
    Bhs,
    /// Waiting for the remainder (`total` bytes).
    Data { total: usize },
}

/// Internal state machine (private).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum IscsiState {
    /// Waiting for the BHS of the next PDU.
    RecvPdu,
    /// Waiting for the remainder of the current PDU (`total` bytes:
    /// `TotalAHSLength*4 + DataSegmentLength + padding`).
    RecvData { total: usize },
    /// Data-In phase: `sent` bytes already staged (not counting the pending
    /// chunk), `pending` the length of the chunk staged in `work` (`data_sn`
    /// its DataSN), `chunk` the maximum chunk size.
    DataIn {
        transfer_len: u64,
        sent: u64,
        itt: u32,
        chunk: usize,
        pending: usize,
        data_sn: u32,
        lun: usize,
    },
    /// Data-In phase awaiting a storage op (`Xfer::Store`): the chunk at
    /// offset `sent` (length `chunk`, DataSN `data_sn`) is in flight.
    DataInStore {
        transfer_len: u64,
        sent: u64,
        itt: u32,
        chunk: usize,
        data_sn: u32,
        lun: usize,
    },
    /// Data-Out immediate-data phase awaiting a storage op (`Xfer::Store`).
    InXferStore {
        itt: u32,
        transfer_len: u64,
        received: u64,
        lun: usize,
    },
    /// Data-Out phase: collecting the Data-Out PDUs solicited by an R2T.
    /// `frame` tracks the two-stage receive (and the pending R2T send).
    R2tCollect {
        itt: u32,
        transfer_len: u64,
        received: u64,
        r2t_sn: u32,
        data_sn: u32,
        expected_bo: u32,
        burst_remaining: u64,
        lun: usize,
        frame: Frame,
    },
    /// Data-Out phase awaiting a storage op (`Xfer::Store`): the chunk at
    /// offset `expected_bo` (length `dsl`) is in flight.
    R2tStore {
        itt: u32,
        transfer_len: u64,
        received: u64,
        r2t_sn: u32,
        data_sn: u32,
        expected_bo: u32,
        burst_remaining: u64,
        lun: usize,
        dsl: usize,
    },
    /// Collecting ParamOut data via R2T. `frame` tracks the two-stage receive.
    ParamCollect {
        itt: u32,
        expected: u64,
        received: u64,
        r2t_sn: u32,
        data_sn: u32,
        expected_bo: u32,
        burst_remaining: u64,
        cdb: [u8; 16],
        cdb_len: usize,
        /// Accumulation offset into work[BHS_SIZE..].
        acc_offset: usize,
        lun: usize,
        frame: Frame,
    },
    /// Terminal-status agenda: the data phase is complete and the device
    /// agenda (`ScsiDevice::next_store_op`) must be drained before the
    /// terminating SCSI Response / final Data-In.  Carries the response
    /// parameters; each `Some(op)` is yielded as [`Action::Store`] and awaited
    /// via [`Event::StoreDone`].
    Agenda(Agenda),
    /// Terminal (Logout / fatal protocol error / peer close).
    Closed,
}

/// Pending terminal status for [`IscsiState::Agenda`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct Agenda {
    itt: u32,
    lun: usize,
    kind: AgendaKind,
    /// A drained agenda op failed: its sense, which turns the terminal status
    /// into CHECK CONDITION.
    failed_sense: Option<Sense>,
}

/// Which terminal PDU the agenda drain emits.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum AgendaKind {
    /// A SCSI Response with `status` (and optional autosense).
    Response { status: u8, sense: Option<Sense> },
    /// A final Data-In (F=1, S=1) already staged in `work`.
    DataInFinal {
        data_len: usize,
        buffer_offset: u32,
        data_sn: u32,
        status: u8,
    },
}

impl Default for IscsiSession {
    fn default() -> Self {
        Self::new()
    }
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
            state: IscsiState::RecvPdu,
            bhs: [0u8; BHS_SIZE],
        }
    }

    pub fn stage(&self) -> LoginStage {
        self.stage
    }

    // ── Poll interface (non-blocking state machine) ───────────────

    /// Non-blocking state-machine step: consume one [`Event`] and return the
    /// next [`Action`].
    ///
    /// `work` is the single time-multiplexed PDU scratch buffer
    /// (`>= crate::MIN_DATA_LEN + BHS_SIZE`): incoming bytes land at
    /// `work[0..len]`, the 48-byte BHS at `work[..BHS_SIZE]`, and the SCSI
    /// data area at `work[BHS_SIZE..]`.  `devs` is the LUN slice; a device
    /// data phase that yields [`Xfer::Store`] is returned as [`Action::Store`]
    /// for the shell to execute.
    pub fn poll<'a, D: ScsiDevice>(
        &'a mut self,
        ev: Event,
        work: &'a mut [u8],
        devs: &'a mut [D],
    ) -> Action<'a> {
        // Single entry guard: every handler below may slice
        // `work[..BHS_SIZE]` and use `work[BHS_SIZE..]` as the data area.
        if work.len() < crate::MIN_DATA_LEN + BHS_SIZE {
            return Action::Error(TargetError::WorkBufTooSmall);
        }
        match ev {
            Event::Tick => self.pending(work),
            Event::HostRecv { len } => self.poll_host_recv(len, work, devs),
            Event::HostSent => self.poll_host_sent(work, devs),
            Event::StoreDone { result } => self.poll_store_done(result, work, devs),
        }
    }

    /// The action for the current state (re-emitted on [`Event::Tick`]).
    ///
    /// A storage op in flight cannot be rebuilt from state (it borrows the
    /// platform buffer / device), so those states report
    /// [`TargetError::Internal`]: the shell executes the pending
    /// [`Action::Store`] immediately and feeds [`Event::StoreDone`].
    fn pending<'a>(&'a mut self, work: &'a mut [u8]) -> Action<'a> {
        match self.state {
            IscsiState::RecvPdu => Action::HostRecv { len: BHS_SIZE },
            IscsiState::RecvData { total } => Action::HostRecv { len: total },
            IscsiState::DataIn { pending, .. } => Action::HostSend {
                bytes: &work[..BHS_SIZE + pending + pdu_pad_len(pending as u32) as usize],
                prefetch: None,
            },
            IscsiState::R2tCollect { frame, .. } | IscsiState::ParamCollect { frame, .. } => {
                match frame {
                    Frame::Send => Action::HostSend {
                        bytes: &work[..BHS_SIZE],
                        prefetch: None,
                    },
                    Frame::Bhs => Action::HostRecv { len: BHS_SIZE },
                    Frame::Data { total } => Action::HostRecv { len: total },
                }
            }
            IscsiState::DataInStore { .. }
            | IscsiState::InXferStore { .. }
            | IscsiState::R2tStore { .. }
            | IscsiState::Agenda(_) => Action::Error(TargetError::Internal),
            IscsiState::Closed => Action::Closed,
        }
    }

    /// Incoming receive event: drive the two-stage framing, then dispatch the
    /// assembled PDU to the handler for the current logical state.
    fn poll_host_recv<'a, D: ScsiDevice>(
        &'a mut self,
        len: usize,
        work: &'a mut [u8],
        devs: &'a mut [D],
    ) -> Action<'a> {
        match self.state {
            IscsiState::RecvPdu => {
                self.save_bhs(work);
                match self.frame_remainder(work) {
                    Ok(total) => {
                        self.state = IscsiState::RecvData { total };
                        Action::HostRecv { len: total }
                    }
                    Err(e) => Action::Error(e),
                }
            }
            IscsiState::RecvData { .. } => {
                self.assemble(work, len);
                self.state = IscsiState::RecvPdu;
                let pdu = self.current_pdu();
                self.dispatch_new_pdu(&pdu, work, devs)
            }
            IscsiState::R2tCollect { frame, .. } => match frame {
                Frame::Bhs => {
                    self.save_bhs(work);
                    match self.frame_remainder(work) {
                        Ok(total) => {
                            self.set_frame(Frame::Data { total });
                            Action::HostRecv { len: total }
                        }
                        Err(e) => Action::Error(e),
                    }
                }
                Frame::Data { .. } => {
                    self.assemble(work, len);
                    self.set_frame(Frame::Bhs);
                    let pdu = self.current_pdu();
                    self.poll_r2t_collect(&pdu, work, devs)
                }
                Frame::Send => self.pending(work),
            },
            IscsiState::ParamCollect { frame, .. } => match frame {
                Frame::Bhs => {
                    self.save_bhs(work);
                    match self.frame_remainder(work) {
                        Ok(total) => {
                            self.set_frame(Frame::Data { total });
                            Action::HostRecv { len: total }
                        }
                        Err(e) => Action::Error(e),
                    }
                }
                Frame::Data { .. } => {
                    self.assemble(work, len);
                    self.set_frame(Frame::Bhs);
                    let pdu = self.current_pdu();
                    self.poll_param_collect(&pdu, work, devs)
                }
                Frame::Send => self.pending(work),
            },
            _ => self.pending(work),
        }
    }

    /// Pending [`Action::HostSend`] completed: advance the state machine.
    fn poll_host_sent<'a, D: ScsiDevice>(
        &'a mut self,
        work: &'a mut [u8],
        devs: &'a mut [D],
    ) -> Action<'a> {
        match self.state {
            // A terminal response / R2T / Data-In has been sent.
            IscsiState::RecvPdu => Action::HostRecv { len: BHS_SIZE },
            IscsiState::DataIn { .. } => self.poll_data_in(work, devs),
            IscsiState::R2tCollect {
                frame: Frame::Send, ..
            } => {
                self.set_frame(Frame::Bhs);
                Action::HostRecv { len: BHS_SIZE }
            }
            IscsiState::ParamCollect {
                frame: Frame::Send, ..
            } => {
                self.set_frame(Frame::Bhs);
                Action::HostRecv { len: BHS_SIZE }
            }
            IscsiState::Closed => Action::Closed,
            _ => Action::Error(TargetError::Internal),
        }
    }

    /// A storage op finished: map it through the device and continue.
    fn poll_store_done<'a, D: ScsiDevice>(
        &'a mut self,
        result: Result<(), StorageError>,
        work: &'a mut [u8],
        devs: &'a mut [D],
    ) -> Action<'a> {
        match self.state {
            IscsiState::DataInStore { .. } => self.poll_data_in_store(result, work, devs),
            IscsiState::InXferStore { .. } => self.poll_in_xfer_store(result, work, devs),
            IscsiState::R2tStore { .. } => self.poll_r2t_store(result, work, devs),
            IscsiState::Agenda(_) => self.poll_agenda(result, work, devs),
            _ => Action::Error(TargetError::Internal),
        }
    }

    /// Save the BHS from `work[..BHS_SIZE]`.
    fn save_bhs(&mut self, work: &[u8]) {
        self.bhs.copy_from_slice(&work[..BHS_SIZE]);
    }

    /// The length of the current PDU's remainder (AHS + data + padding),
    /// computed from the saved BHS.
    fn pdu_remainder(&self) -> usize {
        let bhs = Bhs::from_bytes(self.bhs);
        let dsl = bhs.data_segment_len() as usize;
        usize::from(bhs.total_ahs_length()) * 4 + dsl + pdu_pad_len(dsl as u32) as usize
    }

    /// Validate that the current PDU's remainder fits in the data area.
    fn frame_remainder(&self, work: &[u8]) -> Result<usize, TargetError> {
        let total = self.pdu_remainder();
        if total > work.len() - BHS_SIZE {
            return Err(TargetError::WorkBufTooSmall);
        }
        Ok(total)
    }

    /// Reassemble a received PDU: move the freshly received bytes from
    /// `work[0..len]` up to `work[BHS_SIZE..]`, then restore the saved BHS
    /// into `work[..BHS_SIZE]`.
    fn assemble(&self, work: &mut [u8], len: usize) {
        let len = len.min(work.len() - BHS_SIZE);
        work.copy_within(0..len, BHS_SIZE);
        work[..BHS_SIZE].copy_from_slice(&self.bhs);
    }

    /// The [`Pdu`] described by the saved BHS.
    fn current_pdu(&self) -> Pdu {
        let bhs = Bhs::from_bytes(self.bhs);
        Pdu {
            dsl: bhs.data_segment_len() as usize,
            bhs,
        }
    }

    /// Update the framing stage of the active R2T / ParamOut collection.
    fn set_frame(&mut self, f: Frame) {
        match &mut self.state {
            IscsiState::R2tCollect { frame, .. } => *frame = f,
            IscsiState::ParamCollect { frame, .. } => *frame = f,
            _ => {}
        }
    }

    /// Dispatch an assembled PDU that is not part of an in-progress data
    /// phase (login / SCSI command / TMF / NOP / Logout / Text).
    fn dispatch_new_pdu<'a, D: ScsiDevice>(
        &'a mut self,
        pdu: &Pdu,
        work: &'a mut [u8],
        devs: &'a mut [D],
    ) -> Action<'a> {
        let bhs = &pdu.bhs;

        // AHS defense: Assumes TotalAHSLength = 0.
        if bhs.total_ahs_length() != 0 {
            return self.reject(work, reject::PROTOCOL_ERROR, bhs);
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
                return self.reject(work, reject::PROTOCOL_ERROR, bhs);
            }
            return self.handle_login(work, pdu);
        }

        match iscsi_op {
            op::SCSI_CMD => self.handle_scsi_cmd(work, devs, pdu),
            op::SCSI_TASK_REQ => self.handle_tmf(work, pdu, devs),
            op::NOP_OUT => self.handle_nop(work, pdu),
            op::LOGOUT_REQ => self.handle_logout(work, pdu),
            op::TEXT_REQ => self.handle_text(work, pdu),
            op::LOGIN_REQ => self.reject(work, reject::PROTOCOL_ERROR, bhs),
            _ => self.reject(work, reject::PROTOCOL_ERROR, bhs),
        }
    }

    // ── Data-In phase ─────────────────────────────────────────────

    /// Advance a multi-chunk Data-In phase after the pending chunk was sent.
    fn poll_data_in<'a, D: ScsiDevice>(
        &'a mut self,
        work: &'a mut [u8],
        devs: &'a mut [D],
    ) -> Action<'a> {
        let st = self.state;
        let IscsiState::DataIn {
            transfer_len,
            sent,
            itt,
            chunk,
            pending,
            data_sn,
            lun,
        } = st
        else {
            return Action::Error(TargetError::Internal);
        };
        // The next chunk starts just after the pending one.
        let offset = sent + pending as u64;
        let remaining = transfer_len - offset;
        let next = (remaining as usize).min(chunk);

        let probe = match devs[lun].xfer_out(offset, &mut work[BHS_SIZE..BHS_SIZE + next]) {
            Xfer::Inline { len } => Ok(len),
            Xfer::Store(op) => match StoreDesc::of(op) {
                Some(desc) => Err(desc),
                None => return Action::Error(TargetError::Internal),
            },
        };
        let produced = match probe {
            Ok(produced) => produced,
            Err(desc) => {
                self.state = IscsiState::DataInStore {
                    transfer_len,
                    sent: offset,
                    itt,
                    chunk: next,
                    data_sn: data_sn.wrapping_add(1),
                    lun,
                };
                return Action::Store {
                    lun,
                    op: desc.attach_mut(&mut work[BHS_SIZE..BHS_SIZE + next]),
                };
            }
        };
        if produced != next {
            let sense = devs[lun].take_sense();
            return self.finish_response(work, devs, lun, itt, status::CHECK_CONDITION, sense);
        }
        if offset + next as u64 == transfer_len {
            // Final Data-In (F+S): drain the agenda first.
            return self.finish_data_in_final(
                work,
                devs,
                lun,
                itt,
                next,
                offset as u32,
                data_sn.wrapping_add(1),
                status::GOOD,
            );
        }
        let mut bhs = Bhs::new();
        bhs.set_opcode(op::SCSI_DATA_IN);
        bhs.set_itt(itt);
        bhs.set_data_sn(data_sn.wrapping_add(1));
        bhs.set_buffer_offset(offset as u32);
        bhs.set_data_segment_len(next as u32);
        work[..BHS_SIZE].copy_from_slice(bhs.as_bytes());
        let total = BHS_SIZE + next;
        let pad = pdu_pad_len(next as u32) as usize;
        work[total..total + pad].fill(0);
        self.state = IscsiState::DataIn {
            transfer_len,
            sent: offset,
            itt,
            chunk,
            pending: next,
            data_sn: data_sn.wrapping_add(1),
            lun,
        };
        Action::HostSend {
            bytes: &work[..total + pad],
            prefetch: None,
        }
    }

    /// Finalize a Data-In chunk whose storage op finished (`Xfer::Store`).
    fn poll_data_in_store<'a, D: ScsiDevice>(
        &'a mut self,
        result: Result<(), StorageError>,
        work: &'a mut [u8],
        devs: &'a mut [D],
    ) -> Action<'a> {
        let st = self.state;
        let IscsiState::DataInStore {
            transfer_len,
            sent,
            itt,
            chunk,
            data_sn,
            lun,
        } = st
        else {
            return Action::Error(TargetError::Internal);
        };
        if store_done_failed(&mut devs[lun], result) {
            let sense = devs[lun].take_sense();
            return self.finish_response(work, devs, lun, itt, status::CHECK_CONDITION, sense);
        }
        if sent + chunk as u64 == transfer_len {
            return self.finish_data_in_final(
                work,
                devs,
                lun,
                itt,
                chunk,
                sent as u32,
                data_sn,
                status::GOOD,
            );
        }
        let mut bhs = Bhs::new();
        bhs.set_opcode(op::SCSI_DATA_IN);
        bhs.set_itt(itt);
        bhs.set_data_sn(data_sn);
        bhs.set_buffer_offset(sent as u32);
        bhs.set_data_segment_len(chunk as u32);
        work[..BHS_SIZE].copy_from_slice(bhs.as_bytes());
        let total = BHS_SIZE + chunk;
        let pad = pdu_pad_len(chunk as u32) as usize;
        work[total..total + pad].fill(0);
        self.state = IscsiState::DataIn {
            transfer_len,
            sent,
            itt,
            chunk,
            pending: chunk,
            data_sn,
            lun,
        };
        Action::HostSend {
            bytes: &work[..total + pad],
            prefetch: None,
        }
    }

    /// Data-Out immediate-data storage op finished (`Xfer::Store`).
    fn poll_in_xfer_store<'a, D: ScsiDevice>(
        &'a mut self,
        result: Result<(), StorageError>,
        work: &'a mut [u8],
        devs: &'a mut [D],
    ) -> Action<'a> {
        let st = self.state;
        let IscsiState::InXferStore {
            itt,
            transfer_len,
            received,
            lun,
        } = st
        else {
            return Action::Error(TargetError::Internal);
        };
        if store_done_failed(&mut devs[lun], result) {
            let sense = devs[lun].take_sense();
            return self.finish_response(work, devs, lun, itt, status::CHECK_CONDITION, sense);
        }
        if received == transfer_len {
            // The immediate data completed the whole write.
            return self.finish_response(work, devs, lun, itt, status::GOOD, None);
        }
        // Enter R2T state: send the first R2T.
        self.send_r2t(work, itt, transfer_len, received, 0, 0, lun)
    }

    // ── R2T / Data-Out phase ──────────────────────────────────────

    /// Build and send an R2T PDU, entering [`IscsiState::R2tCollect`] with the
    /// R2T pending in `work[..BHS_SIZE]` (`Frame::Send`).
    #[allow(clippy::too_many_arguments)]
    fn send_r2t<'a>(
        &'a mut self,
        work: &'a mut [u8],
        itt: u32,
        transfer_len: u64,
        received: u64,
        r2t_sn: u32,
        data_sn: u32,
        lun: usize,
    ) -> Action<'a> {
        let burst = (u64::from(self.neg.max_burst_len)).min(transfer_len - received);
        let mut bhs = Bhs::new();
        bhs.set_opcode(op::R2T);
        bhs.set_flags(flag::F_BIT);
        bhs.set_itt(itt);
        bhs.set_ttt(TTT);
        bhs.set_lun(lun as u8);
        bhs.set_stat_sn(self.stat_sn.get());
        bhs.set_exp_cmd_sn(self.cmd_sn.wrapping_add(1));
        bhs.set_max_cmd_sn(self.cmd_sn.wrapping_add(1));
        bhs.set_r2t_sn(r2t_sn);
        bhs.set_buffer_offset(received as u32);
        bhs.set_desired_data_len(burst as u32);
        crate::trace!(
            "R2T: R2TSN={} BO={} DesiredLen={} LUN={}",
            r2t_sn,
            received,
            burst,
            lun
        );
        work[..BHS_SIZE].copy_from_slice(bhs.as_bytes());
        let pad = pdu_pad_len(0) as usize;
        work[BHS_SIZE..BHS_SIZE + pad].fill(0);
        self.state = IscsiState::R2tCollect {
            itt,
            transfer_len,
            received,
            r2t_sn,
            data_sn,
            expected_bo: received as u32,
            burst_remaining: burst,
            lun,
            frame: Frame::Send,
        };
        Action::HostSend {
            bytes: &work[..BHS_SIZE],
            prefetch: None,
        }
    }

    /// Process one assembled Data-Out PDU for the active R2T.
    fn poll_r2t_collect<'a, D: ScsiDevice>(
        &'a mut self,
        pdu: &Pdu,
        work: &'a mut [u8],
        devs: &'a mut [D],
    ) -> Action<'a> {
        let st = self.state;
        let IscsiState::R2tCollect {
            itt,
            transfer_len,
            mut received,
            r2t_sn,
            mut data_sn,
            mut expected_bo,
            mut burst_remaining,
            lun,
            ..
        } = st
        else {
            return Action::Error(TargetError::Internal);
        };

        let pdu_bhs = &pdu.bhs;
        let pdu_dsl = pdu.dsl;

        if pdu_bhs.opcode() != op::SCSI_DATA_OUT {
            return self.reject(work, reject::PROTOCOL_ERROR, pdu_bhs);
        }
        if pdu_bhs.itt() != itt || pdu_bhs.ttt() != TTT {
            return self.reject(work, reject::INVALID_PDU_FIELD, pdu_bhs);
        }
        if pdu_bhs.buffer_offset() != expected_bo {
            return self.reject(work, reject::INVALID_PDU_FIELD, pdu_bhs);
        }
        if pdu_bhs.data_sn() != data_sn {
            return self.reject(work, reject::INVALID_PDU_FIELD, pdu_bhs);
        }
        if pdu_dsl > self.max_recv_data_segment as usize {
            return self.reject(work, reject::PROTOCOL_ERROR, pdu_bhs);
        }
        if pdu_dsl as u64 > burst_remaining {
            return self.reject(work, reject::INVALID_PDU_FIELD, pdu_bhs);
        }

        if pdu_dsl > 0 {
            let probe =
                match devs[lun].xfer_in(expected_bo as u64, &work[BHS_SIZE..BHS_SIZE + pdu_dsl]) {
                    Xfer::Inline { len } => Ok(len),
                    Xfer::Store(op) => match StoreDesc::of(op) {
                        Some(desc) => Err(desc),
                        None => return Action::Error(TargetError::Internal),
                    },
                };
            let produced = match probe {
                Ok(produced) => produced,
                Err(desc) => {
                    self.state = IscsiState::R2tStore {
                        itt,
                        transfer_len,
                        received,
                        r2t_sn,
                        data_sn,
                        expected_bo,
                        burst_remaining,
                        lun,
                        dsl: pdu_dsl,
                    };
                    let Some(op) = desc.attach_ro(&work[BHS_SIZE..BHS_SIZE + pdu_dsl]) else {
                        return Action::Error(TargetError::Internal);
                    };
                    return Action::Store { lun, op };
                }
            };
            if produced != pdu_dsl {
                let sense = devs[lun].take_sense();
                return self.finish_response(work, devs, lun, itt, status::CHECK_CONDITION, sense);
            }
        }

        crate::trace!(
            "  Data-Out: BO={} DataSN={} len={}",
            expected_bo,
            data_sn,
            pdu_dsl
        );
        expected_bo += pdu_dsl as u32;
        received += pdu_dsl as u64;
        burst_remaining -= pdu_dsl as u64;
        data_sn = data_sn.wrapping_add(1);

        if burst_remaining == 0 {
            if received == transfer_len {
                // Transfer complete — drain the agenda then send the SCSI Response.
                return self.finish_response(work, devs, lun, itt, status::GOOD, None);
            }
            // Next R2T — DataSN resets per R2T (RFC 3720 §10.7, DataSN is
            // relative to the R2T's buffer offset, not the whole command).
            return self.send_r2t(work, itt, transfer_len, received, r2t_sn + 1, 0, lun);
        }

        // More Data-Out PDUs expected in this burst.
        self.state = IscsiState::R2tCollect {
            itt,
            transfer_len,
            received,
            r2t_sn,
            data_sn,
            expected_bo,
            burst_remaining,
            lun,
            frame: Frame::Bhs,
        };
        Action::HostRecv { len: BHS_SIZE }
    }

    /// Data-Out storage op finished (`Xfer::Store`).
    fn poll_r2t_store<'a, D: ScsiDevice>(
        &'a mut self,
        result: Result<(), StorageError>,
        work: &'a mut [u8],
        devs: &'a mut [D],
    ) -> Action<'a> {
        let st = self.state;
        let IscsiState::R2tStore {
            itt,
            transfer_len,
            received,
            r2t_sn,
            data_sn,
            expected_bo,
            burst_remaining,
            lun,
            dsl,
        } = st
        else {
            return Action::Error(TargetError::Internal);
        };
        if store_done_failed(&mut devs[lun], result) {
            let sense = devs[lun].take_sense();
            return self.finish_response(work, devs, lun, itt, status::CHECK_CONDITION, sense);
        }
        let expected_bo = expected_bo + dsl as u32;
        let received = received + dsl as u64;
        let burst_remaining = burst_remaining - dsl as u64;
        let data_sn = data_sn.wrapping_add(1);
        if burst_remaining == 0 {
            if received == transfer_len {
                return self.finish_response(work, devs, lun, itt, status::GOOD, None);
            }
            return self.send_r2t(work, itt, transfer_len, received, r2t_sn + 1, 0, lun);
        }
        self.state = IscsiState::R2tCollect {
            itt,
            transfer_len,
            received,
            r2t_sn,
            data_sn,
            expected_bo,
            burst_remaining,
            lun,
            frame: Frame::Bhs,
        };
        Action::HostRecv { len: BHS_SIZE }
    }

    // ── ParamOut collection ───────────────────────────────────────

    /// Process one assembled Data-Out PDU accumulating ParamOut data.
    fn poll_param_collect<'a, D: ScsiDevice>(
        &'a mut self,
        pdu: &Pdu,
        work: &'a mut [u8],
        devs: &'a mut [D],
    ) -> Action<'a> {
        let st = self.state;
        let IscsiState::ParamCollect {
            itt,
            expected,
            mut received,
            r2t_sn,
            mut data_sn,
            mut expected_bo,
            mut burst_remaining,
            cdb,
            cdb_len,
            mut acc_offset,
            lun,
            ..
        } = st
        else {
            return Action::Error(TargetError::Internal);
        };

        let pdu_bhs = &pdu.bhs;
        let pdu_dsl = pdu.dsl;

        if pdu_bhs.opcode() != op::SCSI_DATA_OUT {
            return self.reject(work, reject::PROTOCOL_ERROR, pdu_bhs);
        }
        if pdu_bhs.itt() != itt || pdu_bhs.ttt() != TTT {
            return self.reject(work, reject::INVALID_PDU_FIELD, pdu_bhs);
        }
        if pdu_bhs.buffer_offset() != expected_bo {
            return self.reject(work, reject::INVALID_PDU_FIELD, pdu_bhs);
        }
        if pdu_bhs.data_sn() != data_sn {
            return self.reject(work, reject::INVALID_PDU_FIELD, pdu_bhs);
        }
        if pdu_dsl > self.max_recv_data_segment as usize {
            return self.reject(work, reject::PROTOCOL_ERROR, pdu_bhs);
        }
        if pdu_dsl as u64 > burst_remaining {
            return self.reject(work, reject::INVALID_PDU_FIELD, pdu_bhs);
        }

        // Accumulate into work[BHS_SIZE + acc_offset ..].
        // `copy_within` is safe because acc_offset > 0, so the
        // destination is always at a higher address than the source.
        if pdu_dsl > 0 {
            work.copy_within(BHS_SIZE..BHS_SIZE + pdu_dsl, BHS_SIZE + acc_offset);
        }
        acc_offset += pdu_dsl;
        expected_bo += pdu_dsl as u32;
        received += pdu_dsl as u64;
        burst_remaining -= pdu_dsl as u64;
        data_sn = data_sn.wrapping_add(1);

        if received >= expected {
            // All data collected — complete the parameter.
            let cdb_slice = &cdb[..cdb_len];
            let param_data = &work[BHS_SIZE..BHS_SIZE + expected as usize];
            let outcome = if lun < devs.len() {
                devs[lun].complete_param(cdb_slice, param_data)
            } else {
                CommandOutcome::CheckCondition
            };
            return match outcome {
                CommandOutcome::Status | CommandOutcome::StatusWithSense => {
                    self.finish_response(work, devs, lun, itt, status::GOOD, None)
                }
                CommandOutcome::CheckCondition => {
                    let sense = if lun < devs.len() {
                        devs[lun].take_sense()
                    } else {
                        None
                    };
                    self.finish_response(work, devs, lun, itt, status::CHECK_CONDITION, sense)
                }
                _ => {
                    let sense = Sense::new(SenseKey::IllegalRequest, asc::INVALID_FIELD, 0);
                    self.finish_response(work, devs, lun, itt, status::CHECK_CONDITION, Some(sense))
                }
            };
        }

        if burst_remaining == 0 {
            // Next R2T.
            self.state = IscsiState::ParamCollect {
                itt,
                expected,
                received,
                r2t_sn,
                data_sn,
                expected_bo,
                burst_remaining: (u64::from(self.neg.max_burst_len)).min(expected - received),
                cdb,
                cdb_len,
                acc_offset,
                lun,
                frame: Frame::Bhs,
            };
            return self.send_param_r2t(work, itt, received, r2t_sn + 1);
        }

        self.state = IscsiState::ParamCollect {
            itt,
            expected,
            received,
            r2t_sn,
            data_sn,
            expected_bo,
            burst_remaining,
            cdb,
            cdb_len,
            acc_offset,
            lun,
            frame: Frame::Bhs,
        };
        Action::HostRecv { len: BHS_SIZE }
    }

    /// Build and send a ParamOut R2T PDU.
    fn send_param_r2t<'a>(
        &'a mut self,
        work: &'a mut [u8],
        itt: u32,
        buffer_offset: u64,
        r2t_sn: u32,
    ) -> Action<'a> {
        let st = self.state;
        let IscsiState::ParamCollect {
            expected,
            received,
            lun,
            ..
        } = st
        else {
            return Action::Error(TargetError::Internal);
        };
        let burst = (u64::from(self.neg.max_burst_len)).min(expected - received);
        let mut bhs = Bhs::new();
        bhs.set_opcode(op::R2T);
        bhs.set_flags(flag::F_BIT);
        bhs.set_itt(itt);
        bhs.set_ttt(TTT);
        bhs.set_lun(lun as u8);
        bhs.set_stat_sn(self.stat_sn.get());
        bhs.set_exp_cmd_sn(self.cmd_sn.wrapping_add(1));
        bhs.set_max_cmd_sn(self.cmd_sn.wrapping_add(1));
        bhs.set_r2t_sn(r2t_sn);
        bhs.set_buffer_offset(buffer_offset as u32);
        bhs.set_desired_data_len(burst as u32);
        work[..BHS_SIZE].copy_from_slice(bhs.as_bytes());
        // Update burst_remaining in state.
        if let IscsiState::ParamCollect {
            ref mut burst_remaining,
            ref mut frame,
            ..
        } = self.state
        {
            *burst_remaining = burst;
            *frame = Frame::Send;
        }
        Action::HostSend {
            bytes: &work[..BHS_SIZE],
            prefetch: None,
        }
    }

    // ── Login Phase ───────────────────────────────────────────────

    fn handle_login<'a>(&'a mut self, work: &'a mut [u8], pdu: &Pdu) -> Action<'a> {
        let req = &pdu.bhs;
        // Login C bit (byte1 bit6, RFC 3720 §10.12.1) — continuation not
        // supported; reject if set.
        if req.as_bytes()[1] & 0x40 != 0 {
            return self.reject(work, reject::PROTOCOL_ERROR, req);
        }
        // Version range check (RFC 3720 §10.13.5): we support 0x00 only.
        // If initiator's [min,max] does not include 0, return 02/05.
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
            self.state = IscsiState::Closed;
            return Action::HostSend {
                bytes: &work[..BHS_SIZE + pad],
                prefetch: None,
            };
        }
        let req_csg = req.csg() & 0x03;
        let t = req.t_bit();

        // §6.4.1: the receive data-segment capability scales with the
        // caller's scratch buffer (data area = work minus BHS, 4-aligned,
        // bounded by the 24-bit DataSegmentLength field). Negotiation then
        // clamps the initiator's declared value to this cap.
        self.max_recv_data_segment =
            crate::scsi::device::data_capacity(work.len() - BHS_SIZE).min(HARD_CAP) as u32;

        // Negotiate: build the response text (updated `self.neg` alongside).
        let resp_len = if pdu.dsl <= LOGIN_MAX {
            let (head, tail) = work.split_at_mut(BHS_SIZE + pdu.dsl);
            let Some(n) = self.negotiate(&head[BHS_SIZE..], tail) else {
                return Action::Error(TargetError::WorkBufTooSmall);
            };
            work.copy_within(BHS_SIZE + pdu.dsl..BHS_SIZE + pdu.dsl + n, BHS_SIZE);
            n
        } else {
            let Some(n) = self.negotiate(&[], &mut work[BHS_SIZE..]) else {
                return Action::Error(TargetError::WorkBufTooSmall);
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
        // TSIH: non-zero for a new session's final response (§10.13.3).
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
        Action::HostSend {
            bytes: &work[..total + pad],
            prefetch: None,
        }
    }

    /// Parse initiator key=value text into a response, updating negotiated
    /// parameters.  Writes into `dst`, returns the response length or `None`
    /// if `dst` is too small (caller should report `WorkBufTooSmall`).
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
                    let result_yes = initiator_yes && true; // target offers Yes
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
                    // Advertise the negotiated (buffer-derived) value
                    // (§6.4.1), not the raw initiator figure.
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

    // ── Full Feature: SCSI Command ────────────────────────────────

    fn handle_scsi_cmd<'a, D: ScsiDevice>(
        &'a mut self,
        work: &'a mut [u8],
        devs: &'a mut [D],
        pdu: &Pdu,
    ) -> Action<'a> {
        let bhs = &pdu.bhs;
        let recv_cmd_sn = bhs.cmd_sn();
        let immediate_flag = bhs.as_bytes()[0] & 0x40 != 0;
        if !immediate_flag && recv_cmd_sn != self.cmd_sn.wrapping_add(1) {
            return Action::HostRecv { len: BHS_SIZE };
        }
        self.cmd_sn = recv_cmd_sn;

        let itt = bhs.itt();
        if !bhs.lun_is_single_level() {
            return self.reject(work, reject::INVALID_PDU_FIELD, bhs);
        }
        let cdb = bhs.cdb();
        let scsi_opcode = opcode_from_cdb(cdb);

        // REPORT LUNS is a well-known command (SPC-3) and must be served
        // from any LUN, even an unsupported one.
        if scsi_opcode == scsi_op::REPORT_LUNS {
            let select = cdb.get(2).copied().unwrap_or(0);
            return self.handle_report_luns(
                work,
                devs,
                bhs.lun() as usize,
                itt,
                devs.len(),
                select,
            );
        }

        let lun = bhs.lun() as usize;
        if lun >= devs.len() {
            if scsi_opcode == scsi_op::REQUEST_SENSE {
                // SPC-3 §6.27: REQUEST SENSE to an unsupported LUN shall
                // return GOOD with sense ILLEGAL REQUEST / LOGICAL UNIT NOT SUPPORTED.
                let alloc = cdb.get(4).copied().unwrap_or(0) as usize;
                let sense =
                    Sense::new(SenseKey::IllegalRequest, asc::LOGICAL_UNIT_NOT_SUPPORTED, 0);
                let mut buf = [0u8; 18];
                let n = sense.write_fixed(&mut buf);
                let n = n.min(alloc).min(work.len() - BHS_SIZE);
                if n > 0 {
                    work[BHS_SIZE..BHS_SIZE + n].copy_from_slice(&buf[..n]);
                }
                return self.finish_data_in_final(work, devs, lun, itt, n, 0, 0, status::GOOD);
            }
            let sense = Sense::new(SenseKey::IllegalRequest, asc::LOGICAL_UNIT_NOT_SUPPORTED, 0);
            return self.finish_response(
                work,
                devs,
                lun,
                itt,
                status::CHECK_CONDITION,
                Some(sense),
            );
        }
        if pdu.dsl > self.max_recv_data_segment as usize {
            return self.reject(work, reject::PROTOCOL_ERROR, bhs);
        }
        let w_bit = bhs.as_bytes()[1] & 0x20 != 0;
        if pdu.dsl > 0 && !w_bit {
            return self.reject(work, reject::PROTOCOL_ERROR, bhs);
        }

        crate::debug!(
            "scsi cmd: {} (0x{:02X}) itt=0x{:08X} lun={} cmd_sn={} dsl={}",
            opcode_name(scsi_opcode),
            scsi_opcode,
            itt,
            lun,
            recv_cmd_sn,
            pdu.dsl
        );

        let outcome = match devs[lun].do_cmd(cdb, &mut work[BHS_SIZE..]) {
            Ok(o) => o,
            Err(crate::scsi::device::Error::WorkBufTooSmall) => {
                return Action::Error(TargetError::WorkBufTooSmall)
            }
            Err(_) => return Action::Error(TargetError::Internal),
        };

        match outcome {
            CommandOutcome::Status => {
                crate::debug!("  -> Status (GOOD)");
                self.finish_response(work, devs, lun, itt, status::GOOD, None)
            }
            CommandOutcome::StatusWithSense => {
                crate::debug!("  -> StatusWithSense (GOOD, sense pending)");
                self.finish_response(work, devs, lun, itt, status::GOOD, None)
            }
            CommandOutcome::CheckCondition => {
                let sense = devs[lun].take_sense();
                if let Some(ref s) = sense {
                    crate::debug!(
                        "  -> CheckCondition key={:?} asc=0x{:02X} ascq=0x{:02X}",
                        s.key,
                        s.asc,
                        s.ascq
                    );
                } else {
                    crate::debug!("  -> CheckCondition (no sense)");
                }
                self.finish_response(work, devs, lun, itt, status::CHECK_CONDITION, sense)
            }
            CommandOutcome::OutInline { len } => {
                crate::debug!("  -> OutInline (synthesized, {} bytes)", len);
                let n = len;
                self.finish_data_in_final(work, devs, lun, itt, n, 0, 0, status::GOOD)
            }
            CommandOutcome::OutXfer { len: transfer_len } => {
                crate::debug!("  -> OutXfer (backend, transfer_len={})", transfer_len);
                let chunk = (transfer_len as usize)
                    .min(work.len() - BHS_SIZE)
                    .min(self.max_recv_data_segment as usize);
                // First chunk (intermediate when the transfer spans chunks).
                let probe = match devs[lun].xfer_out(0, &mut work[BHS_SIZE..BHS_SIZE + chunk]) {
                    Xfer::Inline { len } => Ok(len),
                    Xfer::Store(op) => match StoreDesc::of(op) {
                        Some(desc) => Err(desc),
                        None => return Action::Error(TargetError::Internal),
                    },
                };
                let produced = match probe {
                    Ok(produced) => produced,
                    Err(desc) => {
                        self.state = IscsiState::DataInStore {
                            transfer_len,
                            sent: 0,
                            itt,
                            chunk,
                            data_sn: 0,
                            lun,
                        };
                        return Action::Store {
                            lun,
                            op: desc.attach_mut(&mut work[BHS_SIZE..BHS_SIZE + chunk]),
                        };
                    }
                };
                if produced != chunk {
                    let sense = devs[lun].take_sense();
                    return self.finish_response(
                        work,
                        devs,
                        lun,
                        itt,
                        status::CHECK_CONDITION,
                        sense,
                    );
                }
                if chunk as u64 == transfer_len {
                    // All data fits in one chunk — send as final Data-In (F+S),
                    // draining the agenda first.
                    self.finish_data_in_final(work, devs, lun, itt, chunk, 0, 0, status::GOOD)
                } else {
                    // Multi-chunk: first chunk is intermediate (F=0, S=0).
                    let mut dib = Bhs::new();
                    dib.set_opcode(op::SCSI_DATA_IN);
                    dib.set_itt(itt);
                    dib.set_data_segment_len(chunk as u32);
                    work[..BHS_SIZE].copy_from_slice(dib.as_bytes());
                    self.state = IscsiState::DataIn {
                        transfer_len,
                        sent: 0,
                        itt,
                        chunk,
                        pending: chunk,
                        data_sn: 0,
                        lun,
                    };
                    Action::HostSend {
                        bytes: &work[..BHS_SIZE + chunk],
                        prefetch: None,
                    }
                }
            }
            CommandOutcome::InXfer { len: transfer_len } => {
                // Host→device write: consume immediate data already in work.
                let received = (pdu.dsl as u64).min(transfer_len);
                crate::debug!(
                    "  -> InXfer transfer_len={} immediate={}",
                    transfer_len,
                    received
                );
                if received > 0 {
                    let imm = &work[BHS_SIZE..BHS_SIZE + received as usize];
                    let probe = match devs[lun].xfer_in(0, imm) {
                        Xfer::Inline { len } => Ok(len),
                        Xfer::Store(op) => match StoreDesc::of(op) {
                            Some(desc) => Err(desc),
                            None => return Action::Error(TargetError::Internal),
                        },
                    };
                    let produced = match probe {
                        Ok(produced) => produced,
                        Err(desc) => {
                            self.state = IscsiState::InXferStore {
                                itt,
                                transfer_len,
                                received,
                                lun,
                            };
                            let Some(op) =
                                desc.attach_ro(&work[BHS_SIZE..BHS_SIZE + received as usize])
                            else {
                                return Action::Error(TargetError::Internal);
                            };
                            return Action::Store { lun, op };
                        }
                    };
                    if produced != received as usize {
                        let sense = devs[lun].take_sense();
                        return self.finish_response(
                            work,
                            devs,
                            lun,
                            itt,
                            status::CHECK_CONDITION,
                            sense,
                        );
                    }
                }
                if received == transfer_len {
                    return self.finish_response(work, devs, lun, itt, status::GOOD, None);
                }

                // Enter R2T state: send the first R2T.
                self.send_r2t(work, itt, transfer_len, received, 0, 0, lun)
            }
            CommandOutcome::InParam { expected_len } => {
                let expected = expected_len as u64;
                let received = (pdu.dsl as u64).min(expected);
                crate::debug!("  -> InParam expected={} immediate={}", expected, received);
                if expected > 0 && !w_bit {
                    return self.reject(work, reject::PROTOCOL_ERROR, bhs);
                }
                if (pdu.dsl as u64) > expected {
                    return self.reject(work, reject::PROTOCOL_ERROR, bhs);
                }
                if expected as usize > work.len() - BHS_SIZE {
                    return Action::Error(TargetError::WorkBufTooSmall);
                }

                let mut cdb_buf = [0u8; 16];
                let cdb_len = cdb.len().min(16);
                cdb_buf[..cdb_len].copy_from_slice(&cdb[..cdb_len]);

                if received == expected {
                    // All present — complete immediately.
                    let outcome2 = if lun < devs.len() {
                        devs[lun].complete_param(
                            &cdb_buf[..cdb_len],
                            &work[BHS_SIZE..BHS_SIZE + expected as usize],
                        )
                    } else {
                        CommandOutcome::CheckCondition
                    };
                    return match outcome2 {
                        CommandOutcome::Status | CommandOutcome::StatusWithSense => {
                            self.finish_response(work, devs, lun, itt, status::GOOD, None)
                        }
                        CommandOutcome::CheckCondition => {
                            let sense = if lun < devs.len() {
                                devs[lun].take_sense()
                            } else {
                                None
                            };
                            self.finish_response(
                                work,
                                devs,
                                lun,
                                itt,
                                status::CHECK_CONDITION,
                                sense,
                            )
                        }
                        _ => {
                            let sense = Sense::new(SenseKey::IllegalRequest, asc::INVALID_FIELD, 0);
                            self.finish_response(
                                work,
                                devs,
                                lun,
                                itt,
                                status::CHECK_CONDITION,
                                Some(sense),
                            )
                        }
                    };
                }

                // Need to receive the remainder via R2T.
                let acc_offset = received as usize;
                let burst = (u64::from(self.neg.max_burst_len)).min(expected - received);
                self.state = IscsiState::ParamCollect {
                    itt,
                    expected,
                    received,
                    r2t_sn: 0,
                    data_sn: 0,
                    expected_bo: received as u32,
                    burst_remaining: burst,
                    cdb: cdb_buf,
                    cdb_len,
                    acc_offset,
                    lun,
                    frame: Frame::Bhs,
                };
                self.send_param_r2t(work, itt, received, 0)
            }
        }
    }

    /// Build and send the REPORT LUNS response (SPC-4 §6.21).
    #[allow(clippy::too_many_arguments)]
    fn handle_report_luns<'a, D: ScsiDevice>(
        &'a mut self,
        work: &'a mut [u8],
        devs: &'a mut [D],
        lun: usize,
        itt: u32,
        num_luns: usize,
        select_report: u8,
    ) -> Action<'a> {
        // SPC-3 §6.21/Table 148: ONLY 00h (all non well-known), 01h
        // (well-known only) and 02h (all) are defined; the rest are reserved
        // → CHECK CONDITION / INVALID FIELD IN CDB (autosense-in-response).
        if select_report > 0x02 {
            let sense = Sense::new(SenseKey::IllegalRequest, asc::INVALID_FIELD, 0);
            return self.finish_response(
                work,
                devs,
                lun,
                itt,
                status::CHECK_CONDITION,
                Some(sense),
            );
        }
        // 01h = well-known logical units only; this device has none.
        let entries = if select_report == 0x01 { 0 } else { num_luns };
        let list_len = u32::try_from(entries)
            .ok()
            .and_then(|n| n.checked_mul(8))
            .unwrap_or(u32::MAX);
        let total = 8usize + (list_len as usize);
        if total > work.len() - BHS_SIZE {
            return Action::Error(TargetError::WorkBufTooSmall);
        }
        work[BHS_SIZE..BHS_SIZE + 4].copy_from_slice(&list_len.to_be_bytes());
        for b in &mut work[BHS_SIZE + 4..BHS_SIZE + 8] {
            *b = 0;
        }
        for i in 0..entries {
            let off = BHS_SIZE + 8 + i * 8;
            work[off] = 0x00;
            work[off + 1] = i as u8;
            for b in &mut work[off + 2..off + 8] {
                *b = 0;
            }
        }
        crate::debug!(
            "  -> REPORT LUNS: {} LUN(s) (select={})",
            entries,
            select_report
        );
        self.finish_data_in_final(work, devs, lun, itt, total, 0, 0, status::GOOD)
    }

    // ── Full Feature: Task Management / NOP / Logout ─────────────

    fn handle_tmf<'a, D: ScsiDevice>(
        &'a mut self,
        work: &'a mut [u8],
        pdu: &Pdu,
        devs: &'a mut [D],
    ) -> Action<'a> {
        let bhs = &pdu.bhs;
        let recv_cmd_sn = bhs.cmd_sn();
        let immediate_flag = bhs.as_bytes()[0] & 0x40 != 0;

        if !immediate_flag && recv_cmd_sn != self.cmd_sn.wrapping_add(1) {
            return Action::HostRecv { len: BHS_SIZE };
        }
        self.cmd_sn = recv_cmd_sn;

        if !bhs.lun_is_single_level() {
            return self.reject(work, reject::INVALID_PDU_FIELD, bhs);
        }
        let lun = bhs.lun() as usize;
        let function = bhs.tmf_function();
        let response = match function {
            tmf::LOGICAL_UNIT_RESET => {
                if lun < devs.len() {
                    devs[lun].inject_unit_attention(asc::POWER_ON_RESET, 0);
                    tmf_response::COMPLETE
                } else {
                    tmf_response::NOT_SUPPORTED
                }
            }
            tmf::ABORT_TASK => tmf_response::COMPLETE,
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
        Action::HostSend {
            bytes: &work[..BHS_SIZE + pad],
            prefetch: None,
        }
    }

    fn handle_nop<'a>(&'a mut self, work: &'a mut [u8], pdu: &Pdu) -> Action<'a> {
        let bhs = &pdu.bhs;
        let itt = bhs.itt();
        let immediate_flag = bhs.as_bytes()[0] & 0x40 != 0;

        if itt == 0xFFFF_FFFF {
            // RFC 3720 §10.18.1: ITT=0xFFFFFFFF requires I bit set, no response,
            // CmdSN not advanced.
            if !immediate_flag {
                return self.reject(work, reject::PROTOCOL_ERROR, bhs);
            }
            return Action::HostRecv { len: BHS_SIZE };
        }

        // RFC 3720 §3.2.2.1: non-immediate commands advance CmdSN.
        if !immediate_flag {
            let recv_cmd_sn = bhs.cmd_sn();
            if recv_cmd_sn != self.cmd_sn.wrapping_add(1) {
                return Action::HostRecv { len: BHS_SIZE };
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
        // legitimately carries a real TTT. Eagerly overwriting to 0xFFFFFFFF
        // (as suggested by an earlier review) would be a spec violation.
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
        Action::HostSend {
            bytes: &work[..total + pad],
            prefetch: None,
        }
    }

    fn handle_logout<'a>(&'a mut self, work: &'a mut [u8], pdu: &Pdu) -> Action<'a> {
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
        self.state = IscsiState::Closed;
        self.stat_sn.set(self.stat_sn.get().wrapping_add(1));
        Action::HostSend {
            bytes: &work[..BHS_SIZE + pad],
            prefetch: None,
        }
    }

    fn handle_text<'a>(&'a mut self, work: &'a mut [u8], pdu: &Pdu) -> Action<'a> {
        let bhs = &pdu.bhs;
        // F=0 (continuation) and non-0xFFFFFFFF TTT are not supported (no fragmentation);
        // be lenient for the legacy text_request_rejected test that sends a minimal BHS.
        if pdu.dsl > work.len() - BHS_SIZE {
            return Action::Error(TargetError::WorkBufTooSmall);
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
            // Unknown Text key — reject as before (preserves text_request_rejected test).
            return self.reject(work, reject::COMMAND_NOT_SUPPORTED, bhs);
        }
        // Minimal SendTargets: static target only, no TargetAddress, no continuation.
        // RFC 3720 Appendix D: All / <iqn> / <empty> for discovery vs operational.
        // Lenient: serve on both session types (discovery MUST).
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
            // "TargetName=" prefix + IQN + NUL
            let prefix = b"TargetName=";
            let needed = prefix.len() + txt.len() + 1;
            if needed > work.len() - BHS_SIZE {
                return Action::Error(TargetError::WorkBufTooSmall);
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
        self.state = IscsiState::RecvPdu;
        self.stat_sn.set(self.stat_sn.get().wrapping_add(1));
        Action::HostSend {
            bytes: &work[..total + pad],
            prefetch: None,
        }
    }

    // ── Response PDU builders ─────────────────────────────────────

    /// Terminal-status funnel: enter the agenda (drain `next_store_op` on `lun`
    /// before the SCSI Response) and emit the response. Every SCSI terminal
    /// status (GOOD **and** CHECK CONDITION) goes through here.
    #[allow(clippy::too_many_arguments)]
    fn finish_response<'a, D: ScsiDevice>(
        &'a mut self,
        work: &'a mut [u8],
        devs: &'a mut [D],
        lun: usize,
        itt: u32,
        status: u8,
        sense: Option<Sense>,
    ) -> Action<'a> {
        self.state = IscsiState::Agenda(Agenda {
            itt,
            lun,
            kind: AgendaKind::Response { status, sense },
            failed_sense: None,
        });
        self.drain_agenda(work, devs)
    }

    /// Terminal-status funnel for a final Data-In (F=1, S=1): drain the agenda
    /// on `lun` first, then emit the Data-In exactly as before.
    #[allow(clippy::too_many_arguments)]
    fn finish_data_in_final<'a, D: ScsiDevice>(
        &'a mut self,
        work: &'a mut [u8],
        devs: &'a mut [D],
        lun: usize,
        itt: u32,
        data_len: usize,
        buffer_offset: u32,
        data_sn: u32,
        status: u8,
    ) -> Action<'a> {
        self.state = IscsiState::Agenda(Agenda {
            itt,
            lun,
            kind: AgendaKind::DataInFinal {
                data_len,
                buffer_offset,
                data_sn,
                status,
            },
            failed_sense: None,
        });
        self.drain_agenda(work, devs)
    }

    /// Yield the next device-agenda op, or emit the pending terminal status
    /// once the agenda is drained. A `store_done` failure turns the status into
    /// CHECK CONDITION (sense taken from the device).
    fn drain_agenda<'a, D: ScsiDevice>(
        &'a mut self,
        work: &'a mut [u8],
        devs: &'a mut [D],
    ) -> Action<'a> {
        let IscsiState::Agenda(agenda) = self.state else {
            return Action::Error(TargetError::Internal);
        };
        if agenda.lun < devs.len() {
            if let Some(op) = devs[agenda.lun].next_store_op() {
                // The op is in flight; the state stays `Agenda` so
                // `Event::StoreDone` resumes the drain.
                return Action::Store {
                    lun: agenda.lun,
                    op,
                };
            }
        }
        if let Some(sense) = agenda.failed_sense {
            return self.send_scsi_response(
                work,
                agenda.itt,
                status::CHECK_CONDITION,
                Some(&sense),
            );
        }
        match agenda.kind {
            AgendaKind::Response { status, sense } => {
                self.send_scsi_response(work, agenda.itt, status, sense.as_ref())
            }
            AgendaKind::DataInFinal {
                data_len,
                buffer_offset,
                data_sn,
                status,
            } => {
                self.send_data_in_final(work, agenda.itt, data_len, buffer_offset, data_sn, status)
            }
        }
    }

    /// Agenda op completion: map the result through `devs[lun].store_done` (a
    /// failure captures the sense, which turns the terminal status into CHECK
    /// CONDITION) and continue.
    fn poll_agenda<'a, D: ScsiDevice>(
        &'a mut self,
        result: Result<(), StorageError>,
        work: &'a mut [u8],
        devs: &'a mut [D],
    ) -> Action<'a> {
        let IscsiState::Agenda(agenda) = self.state else {
            return Action::Error(TargetError::Internal);
        };
        let mut failed_sense = agenda.failed_sense;
        if agenda.lun < devs.len() && store_done_failed(&mut devs[agenda.lun], result) {
            if let Some(sense) = devs[agenda.lun].take_sense() {
                failed_sense = Some(sense);
            }
        }
        self.state = IscsiState::Agenda(Agenda {
            failed_sense,
            ..agenda
        });
        self.drain_agenda(work, devs)
    }

    fn send_scsi_response<'a>(
        &'a mut self,
        work: &'a mut [u8],
        itt: u32,
        scsi_status: u8,
        sense: Option<&Sense>,
    ) -> Action<'a> {
        self.state = IscsiState::RecvPdu;
        let mut bhs = Bhs::new();
        bhs.set_opcode(op::SCSI_RESP);
        bhs.set_flags(flag::F_BIT);
        bhs.set_itt(itt);
        bhs.set_status(scsi_status);
        bhs.set_stat_sn(self.stat_sn.get());
        bhs.set_exp_cmd_sn(self.cmd_sn.wrapping_add(1));
        bhs.set_max_cmd_sn(self.cmd_sn.wrapping_add(1));
        let mut dlen = 0;
        if scsi_status == status::CHECK_CONDITION {
            if let Some(s) = sense {
                work[BHS_SIZE] = 0;
                work[BHS_SIZE + 1] = 18;
                s.write_fixed(&mut work[BHS_SIZE + 2..BHS_SIZE + 20]);
                dlen = 20;
            }
        }
        bhs.set_data_segment_len(dlen as u32);
        work[..BHS_SIZE].copy_from_slice(bhs.as_bytes());
        let total = BHS_SIZE + dlen;
        let pad = pdu_pad_len(dlen as u32) as usize;
        work[total..total + pad].fill(0);
        self.stat_sn.set(self.stat_sn.get().wrapping_add(1));
        Action::HostSend {
            bytes: &work[..total + pad],
            prefetch: None,
        }
    }

    /// Single final Data-In (F=1, S=1) with status — used for synthesized
    /// responses and the zero-length edge case.
    fn send_data_in_final<'a>(
        &'a mut self,
        work: &'a mut [u8],
        itt: u32,
        data_len: usize,
        buffer_offset: u32,
        data_sn: u32,
        scsi_status: u8,
    ) -> Action<'a> {
        self.state = IscsiState::RecvPdu;
        let mut bhs = Bhs::new();
        bhs.set_opcode(op::SCSI_DATA_IN);
        bhs.set_flags(flag::F_BIT | flag::S_BIT);
        bhs.set_itt(itt);
        bhs.set_status(scsi_status);
        bhs.set_data_sn(data_sn);
        bhs.set_buffer_offset(buffer_offset);
        bhs.set_data_segment_len(data_len as u32);
        bhs.set_stat_sn(self.stat_sn.get());
        bhs.set_exp_cmd_sn(self.cmd_sn.wrapping_add(1));
        bhs.set_max_cmd_sn(self.cmd_sn.wrapping_add(1));
        work[..BHS_SIZE].copy_from_slice(bhs.as_bytes());
        let total = BHS_SIZE + data_len;
        let pad = pdu_pad_len(data_len as u32) as usize;
        work[total..total + pad].fill(0);
        self.stat_sn.set(self.stat_sn.get().wrapping_add(1));
        Action::HostSend {
            bytes: &work[..total + pad],
            prefetch: None,
        }
    }

    /// Send a Reject and close the connection.  The data segment carries
    /// the full header of the rejected PDU; ITT = 0xffffffff (fix #18).
    fn reject<'a>(&'a mut self, work: &'a mut [u8], reason: u8, rejected: &Bhs) -> Action<'a> {
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
        self.state = IscsiState::Closed;
        self.stat_sn.set(self.stat_sn.get().wrapping_add(1));
        Action::HostSend {
            bytes: &work[..total + pad],
            prefetch: None,
        }
    }
}

/// A byte-addressed [`StoreOp`] with its buffer detached, used to survive the
/// borrow of `work` / `devs` that `xfer_out` / `xfer_in` take while the session
/// still needs them on the `Inline` branch (the classic NLL conditional-borrow
/// workaround). By contract the op returned by the device carries exactly the
/// slice the session passed, so it can be split into its Copy fields and
/// rebuilt identically once the call's borrow has ended. The reconstructed op
/// is byte-identical, so the Store stays invisible on the wire.
///
/// Only the byte-addressed variants appear here: the data phase is
/// byte-addressed, while path-addressed FS ops come from the device agenda
/// (`next_store_op`) and never from the data phase.
#[derive(Clone, Copy)]
enum StoreDesc {
    Read { off: u64 },
    Write { off: u64 },
    Fill { off: u64, len: u64, byte: u8 },
    Sync,
}

impl StoreDesc {
    /// Split a byte-addressed `op` into its Copy fields. `None` for a
    /// path-addressed (FS) op, which cannot be detached here.
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

    /// Re-attach a mutable `buf` (the Data-In read buffer).
    fn attach_mut<'b>(self, buf: &'b mut [u8]) -> StoreOp<'b> {
        match self {
            Self::Read { off } => StoreOp::Read { off, buf },
            Self::Write { off } => StoreOp::Write { off, buf },
            Self::Fill { off, len, byte } => StoreOp::Fill { off, len, byte },
            Self::Sync => StoreOp::Sync,
        }
    }

    /// Re-attach an immutable `buf` (the Data-Out write buffer). `None` for a
    /// read op (which needs a mutable buffer and never arrives here).
    fn attach_ro<'b>(self, buf: &'b [u8]) -> Option<StoreOp<'b>> {
        match self {
            Self::Write { off } => Some(StoreOp::Write { off, buf }),
            Self::Fill { off, len, byte } => Some(StoreOp::Fill { off, len, byte }),
            Self::Sync => Some(StoreOp::Sync),
            Self::Read { .. } => None,
        }
    }
}

/// Feed a finished storage op to `dev.store_done` and report whether the
/// data phase must fail.
///
/// [`ScsiDevice::store_done`]'s default maps a [`StorageError`] to sense (so
/// a left sense means failure); a recovering override leaves no sense and the
/// phase continues. [`XferOutcome::Error`] means the device declined to take
/// over the mapping, so the session applies it via
/// [`sense_for_storage_error`].
fn store_done_failed<D: ScsiDevice>(dev: &mut D, r: Result<(), StorageError>) -> bool {
    match dev.store_done(r) {
        XferOutcome::Ok => r.is_err() && dev.peek_sense().is_some(),
        XferOutcome::Error(e) => {
            let (key, asc, ascq) = sense_for_storage_error(e);
            dev.set_sense(Sense::new(key, asc, ascq));
            true
        }
    }
}

// ── Private helpers ─────────────────────────────────────────────────

struct Pdu {
    bhs: Bhs,
    dsl: usize,
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
    use crate::common::store::StorePlane;
    use crate::iscsi::pdu::BHS_SIZE;

    /// Summary of a poll round (no borrows), for the test drivers.
    #[derive(Debug)]
    enum Reply {
        Recv(usize),
        Sent(Vec<u8>),
        Closed,
        Error,
    }

    /// Drive `poll` until it asks for I/O (a receive or a send), executing any
    /// `Action::Store` on `planes` and feeding `Event::StoreDone` back.
    fn step<D: ScsiDevice>(
        session: &mut IscsiSession,
        work: &mut [u8],
        devs: &mut [D],
        planes: &mut [Option<StorePlane<'_>>],
        mut ev: Event,
    ) -> Reply {
        loop {
            match session.poll(ev, work, devs) {
                Action::HostRecv { len } => return Reply::Recv(len),
                Action::HostSend { bytes, .. } => return Reply::Sent(bytes.to_vec()),
                Action::Store { lun, op } => {
                    let result = match planes.get_mut(lun).and_then(|p| p.as_mut()) {
                        Some(plane) => plane.do_op(op),
                        None => return Reply::Error,
                    };
                    ev = Event::StoreDone { result };
                }
                Action::Closed => return Reply::Closed,
                Action::Error(_) => return Reply::Error,
            }
        }
    }

    /// Build a one-PDU Login Request BHS (I=1, T=1, CSG=1, NSG=3).
    fn login_bhs(dsl: usize) -> [u8; 48] {
        let mut bhs = [0u8; 48];
        bhs[0] = op::LOGIN_REQ | 0x40;
        bhs[1] = flag::T_BIT | ((stage::OP_PARAM & 0x03) << flag::CSG_SHIFT) | stage::FULL_FEATURE;
        bhs[5] = (dsl >> 16) as u8;
        bhs[6] = (dsl >> 8) as u8;
        bhs[7] = dsl as u8;
        bhs
    }

    /// The framed remainder length the core requests for a data segment of
    /// `dsl` bytes (AHS = 0): `dsl` rounded up to a 4-byte boundary.
    fn remainder(dsl: usize) -> usize {
        dsl + ((4 - (dsl & 3)) & 3)
    }

    /// Verify the two-stage poll model: Login → Full Feature → SCSI INQUIRY.
    #[test]
    fn poll_login_and_inquiry() {
        use crate::scsi::backend::RamBackend;
        use crate::scsi::block::BlockDevice;

        let mut ram = vec![0u8; 64 * 1024];
        let mut devs = [BlockDevice::disk(&mut RamBackend::new(&mut ram), 512).unwrap()];
        let mut planes: [Option<StorePlane>; 0] = [];
        let mut session = IscsiSession::new();
        let mut work = vec![0u8; crate::MIN_DATA_LEN + BHS_SIZE];

        let login_text = b"InitiatorName=iqn.test\0SessionType=Normal\0";

        // BHS stage → request the data segment.
        work[..48].copy_from_slice(&login_bhs(login_text.len()));
        match step(
            &mut session,
            &mut work,
            &mut devs,
            &mut planes,
            Event::HostRecv { len: BHS_SIZE },
        ) {
            Reply::Recv(len) => assert_eq!(len, remainder(login_text.len())),
            other => panic!("expected data recv, got {other:?}"),
        }
        // Data stage → Login Response.
        work[..remainder(login_text.len())].fill(0);
        work[..login_text.len()].copy_from_slice(login_text);
        match step(
            &mut session,
            &mut work,
            &mut devs,
            &mut planes,
            Event::HostRecv {
                len: remainder(login_text.len()),
            },
        ) {
            Reply::Sent(bytes) => {
                assert!(bytes.len() >= BHS_SIZE);
                assert_eq!(bytes[0] & 0x3F, op::LOGIN_RESP);
            }
            other => panic!("expected login response, got {other:?}"),
        }
        assert_eq!(session.stage(), LoginStage::FullFeature);
        // Response sent → the next command's BHS.
        match step(
            &mut session,
            &mut work,
            &mut devs,
            &mut planes,
            Event::HostSent,
        ) {
            Reply::Recv(len) => assert_eq!(len, BHS_SIZE),
            other => panic!("expected next BHS recv, got {other:?}"),
        }

        // INQUIRY (dsl=0): BHS stage → zero-length data stage.
        let inquiry_cdb = [0x12, 0, 0, 0, 96, 0];
        let mut scsi_bhs = [0u8; 48];
        scsi_bhs[0] = op::SCSI_CMD | 0x40; // I=1 (Immediate) + SCSI_CMD
        scsi_bhs[1] = 0x80; // R=1 (Data-In expected)
        scsi_bhs[24..28].copy_from_slice(&0u32.to_be_bytes()); // CmdSN=0 (next after login)
        scsi_bhs[32..32 + inquiry_cdb.len()].copy_from_slice(&inquiry_cdb);
        work[..48].copy_from_slice(&scsi_bhs);
        work[48..].fill(0);
        match step(
            &mut session,
            &mut work,
            &mut devs,
            &mut planes,
            Event::HostRecv { len: BHS_SIZE },
        ) {
            Reply::Recv(len) => assert_eq!(len, 0),
            other => panic!("expected zero-length data recv, got {other:?}"),
        }
        match step(
            &mut session,
            &mut work,
            &mut devs,
            &mut planes,
            Event::HostRecv { len: 0 },
        ) {
            Reply::Sent(bytes) => {
                assert!(bytes.len() > BHS_SIZE);
                // First byte of INQUIRY response: PDT = 0x00 (direct access).
                assert_eq!(bytes[BHS_SIZE] & 0x1F, 0x00);
            }
            other => panic!("expected INQUIRY response, got {other:?}"),
        }
    }

    #[test]
    fn poll_reject_on_ahs() {
        use crate::scsi::backend::RamBackend;
        use crate::scsi::block::BlockDevice;

        let mut ram = vec![0u8; 64 * 1024];
        let mut devs = [BlockDevice::disk(&mut RamBackend::new(&mut ram), 512).unwrap()];
        let mut planes: [Option<StorePlane>; 0] = [];
        let mut session = IscsiSession::new();
        let mut work = vec![0u8; crate::MIN_DATA_LEN + BHS_SIZE];

        // Login first.
        let login_text = b"InitiatorName=iqn.test\0SessionType=Normal\0";
        work[..48].copy_from_slice(&login_bhs(login_text.len()));
        let _ = step(
            &mut session,
            &mut work,
            &mut devs,
            &mut planes,
            Event::HostRecv { len: BHS_SIZE },
        );
        work[..login_text.len()].copy_from_slice(login_text);
        let _ = step(
            &mut session,
            &mut work,
            &mut devs,
            &mut planes,
            Event::HostRecv {
                len: login_text.len(),
            },
        );
        let _ = step(
            &mut session,
            &mut work,
            &mut devs,
            &mut planes,
            Event::HostSent,
        );
        assert_eq!(session.stage(), LoginStage::FullFeature);

        // SCSI Command with non-zero AHS → Reject.
        let mut scsi_bhs = [0u8; 48];
        scsi_bhs[0] = op::SCSI_CMD;
        scsi_bhs[4] = 1; // TotalAHSLength = 1 → invalid
        work[..48].copy_from_slice(&scsi_bhs);
        match step(
            &mut session,
            &mut work,
            &mut devs,
            &mut planes,
            Event::HostRecv { len: BHS_SIZE },
        ) {
            Reply::Recv(len) => assert_eq!(len, 4), // AHS length
            other => panic!("expected AHS recv, got {other:?}"),
        }
        work[..4].fill(0);
        match step(
            &mut session,
            &mut work,
            &mut devs,
            &mut planes,
            Event::HostRecv { len: 4 },
        ) {
            Reply::Sent(bytes) => {
                assert_eq!(bytes[0] & 0x3F, op::REJECT);
                assert_eq!(session.stage(), LoginStage::FullFeature);
            }
            other => panic!("expected Reject, got {other:?}"),
        }
    }

    #[test]
    fn data_in_respects_max_recv_data_segment() {
        use crate::scsi::backend::RamBackend;
        use crate::scsi::block::BlockDevice;
        use crate::scsi::scsi::op as scsi_op;

        let mut ram = vec![0u8; 64 * 1024];
        let mut devs = [BlockDevice::disk(&mut RamBackend::new(&mut ram), 512).unwrap()];
        let mut plane_backend = RamBackend::new(&mut ram);
        let mut planes = [Some(StorePlane::BlockRw(&mut plane_backend))];
        let mut session = IscsiSession::new();
        let mut work = vec![0u8; 8192 + BHS_SIZE];

        // Login negotiating MaxRecvDataSegmentLength=1024 (small).
        let login_text = b"InitiatorName=iqn.test\0MaxRecvDataSegmentLength=1024\0";
        work[..48].copy_from_slice(&login_bhs(login_text.len()));
        match step(
            &mut session,
            &mut work,
            &mut devs,
            &mut planes,
            Event::HostRecv { len: BHS_SIZE },
        ) {
            Reply::Recv(len) => assert_eq!(len, remainder(login_text.len())),
            other => panic!("expected login data recv, got {other:?}"),
        }
        work[..remainder(login_text.len())].fill(0);
        work[..login_text.len()].copy_from_slice(login_text);
        match step(
            &mut session,
            &mut work,
            &mut devs,
            &mut planes,
            Event::HostRecv {
                len: remainder(login_text.len()),
            },
        ) {
            Reply::Sent(_) => {}
            other => panic!("expected login response, got {other:?}"),
        }
        assert_eq!(session.stage(), LoginStage::FullFeature);
        // Negotiated max should be clipped to 1024 (work 8192 → cap 8192, initiator 1024).
        assert_eq!(session.max_recv_data_segment, 1024);
        let _ = step(
            &mut session,
            &mut work,
            &mut devs,
            &mut planes,
            Event::HostSent,
        );

        // READ_10 for 8 blocks = 4096 bytes, which exceeds negotiated max.
        let mut cdb = [0u8; 10];
        cdb[0] = scsi_op::READ_10;
        cdb[8] = 8;
        let mut scsi_bhs = [0u8; 48];
        scsi_bhs[0] = op::SCSI_CMD | 0x40;
        scsi_bhs[1] = 0x80;
        scsi_bhs[16..20].copy_from_slice(&1u32.to_be_bytes());
        scsi_bhs[24..28].copy_from_slice(&1u32.to_be_bytes());
        scsi_bhs[32..42].copy_from_slice(&cdb);
        work[..48].copy_from_slice(&scsi_bhs);
        work[48..].fill(0);

        // BHS stage → zero-length data stage → first Data-In clipped to 1024.
        match step(
            &mut session,
            &mut work,
            &mut devs,
            &mut planes,
            Event::HostRecv { len: BHS_SIZE },
        ) {
            Reply::Recv(len) => assert_eq!(len, 0),
            other => panic!("expected zero-length data recv, got {other:?}"),
        }
        match step(
            &mut session,
            &mut work,
            &mut devs,
            &mut planes,
            Event::HostRecv { len: 0 },
        ) {
            Reply::Sent(bytes) => {
                let bhs = crate::iscsi::pdu::Bhs::from_bytes(bytes[..48].try_into().unwrap());
                assert_eq!(bhs.opcode(), op::SCSI_DATA_IN);
                assert_eq!(bhs.data_segment_len(), 1024);
                assert_eq!(bytes.len(), BHS_SIZE + 1024);
                match session.state {
                    IscsiState::DataIn { pending, .. } => assert_eq!(pending, 1024),
                    other => panic!("expected DataIn state, got {other:?}"),
                }
            }
            other => panic!("expected first Data-In, got {other:?}"),
        }

        // Second chunk should also be 1024.
        match step(
            &mut session,
            &mut work,
            &mut devs,
            &mut planes,
            Event::HostSent,
        ) {
            Reply::Sent(bytes) => {
                let bhs = crate::iscsi::pdu::Bhs::from_bytes(bytes[..48].try_into().unwrap());
                assert_eq!(bhs.data_segment_len(), 1024);
            }
            other => panic!("expected second Data-In, got {other:?}"),
        }
    }

    #[test]
    fn login_negotiate_overflow_returns_error() {
        use crate::scsi::backend::RamBackend;
        use crate::scsi::block::BlockDevice;

        let mut ram = vec![0u8; 64 * 1024];
        let mut devs = [BlockDevice::disk(&mut RamBackend::new(&mut ram), 512).unwrap()];
        let planes: [Option<StorePlane>; 0] = [];
        let mut session = IscsiSession::new();

        // Direct negotiate with tiny dst should return None (overflow).
        let mut tiny = vec![0u8; 10];
        let src = b"InitiatorName=iqn.test\0TargetName=iqn.target\0";
        assert!(session.negotiate(src, &mut tiny).is_none());

        // Undersized work buffer is rejected up front.
        let mut work3 = vec![0u8; BHS_SIZE + 32];
        work3[..48].copy_from_slice(&login_bhs(0));
        match session.poll(Event::HostRecv { len: BHS_SIZE }, &mut work3, &mut devs) {
            Action::Error(TargetError::WorkBufTooSmall) => {}
            other => panic!("expected WorkBufTooSmall, got {other:?}"),
        }

        // Verify normal login still works with sufficient buffer.
        let mut work_ok = vec![0u8; crate::MIN_DATA_LEN + BHS_SIZE];
        let login_text = b"InitiatorName=iqn.test\0";
        work_ok[..48].copy_from_slice(&login_bhs(login_text.len()));
        match session.poll(Event::HostRecv { len: BHS_SIZE }, &mut work_ok, &mut devs) {
            Action::HostRecv { len } => assert_eq!(len, remainder(login_text.len())),
            other => panic!("expected login data recv, got {other:?}"),
        }
        work_ok[..remainder(login_text.len())].fill(0);
        work_ok[..login_text.len()].copy_from_slice(login_text);
        match session.poll(
            Event::HostRecv {
                len: remainder(login_text.len()),
            },
            &mut work_ok,
            &mut devs,
        ) {
            Action::HostSend { .. } => {}
            other => panic!("expected login response, got {other:?}"),
        }
        let _ = planes;
    }
}
