//! Errors, completions and sense vocabulary.
//!
//! `Storage` adapters only produce [`Fault`]; the Device/profile converts a
//! `Fault` into wire [`Sense`] through [`storage_fault_sense`]. `None` means
//! "management/runner error, never a SCSI sense". [`commit_fault`] is the only
//! producer of [`Fault::Commit`].

/// SCSI sense triple. The response code / additional length framing is added
/// by the transport or the `Spc` wrapper, not stored here.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Sense {
    /// Sense key (response-code low nibble).
    pub key: u8,
    /// Additional sense code.
    pub asc: u8,
    /// Additional sense code qualifier.
    pub ascq: u8,
}

impl Sense {
    /// Build a sense triple from its three wire bytes.
    #[must_use]
    pub const fn new(key: u8, asc: u8, ascq: u8) -> Self {
        Self { key, asc, ascq }
    }
}

/// MMC-6 §6.4.4.3: a foreground FORMAT rejects everything except REQUEST SENSE,
/// INQUIRY, GET CONFIGURATION, GESN and (SPC-3 6.21) REPORT LUNS.
pub const FORMAT_IN_PROGRESS: Sense = Sense::new(0x02, 0x04, 0x04);
/// ILLEGAL REQUEST / INVALID COMMAND OPERATION CODE.
pub const ILLEGAL_REQUEST: Sense = Sense::new(0x05, 0x20, 0x00);
/// ILLEGAL REQUEST / INVALID FIELD IN CDB.
pub const INVALID_FIELD: Sense = Sense::new(0x05, 0x24, 0x00);
/// DATA PROTECT / WRITE PROTECTED.
pub const WRITE_PROTECTED: Sense = Sense::new(0x07, 0x27, 0x00);
/// MEDIUM ERROR / UNRECOVERED READ ERROR (default read-direction mapping).
pub const MEDIUM_ERROR: Sense = Sense::new(0x03, 0x11, 0x00);
/// MEDIUM ERROR / WRITE ERROR (default write-direction mapping).
pub const WRITE_ERROR: Sense = Sense::new(0x03, 0x0C, 0x00);
/// NOT READY / MEDIUM NOT PRESENT.
pub const MEDIUM_NOT_PRESENT: Sense = Sense::new(0x02, 0x3A, 0x00);
/// HARDWARE ERROR / INTERNAL TARGET FAILURE.
pub const INTERNAL_FAILURE: Sense = Sense::new(0x04, 0x44, 0x00);
/// ABORTED COMMAND / OVERLAPPED COMMANDS ATTEMPTED (zero-progress writes).
pub const COMMAND_ABORTED: Sense = Sense::new(0x0B, 0x45, 0x00);
/// Fixed completion used when `Control::Abort` settles the active command
/// Same bytes as [`COMMAND_ABORTED`], separate name
/// for the control path.
pub const ABORTED_COMMAND: Sense = Sense::new(0x0B, 0x45, 0x00);
/// HARDWARE ERROR / LOGICAL UNIT FAILED SELF-TEST (explicit needs-recovery end).
pub const NEEDS_RECOVERY: Sense = Sense::new(0x04, 0x40, 0x00);
/// ILLEGAL REQUEST / MEDIUM REMOVAL PREVENTED (operator eject blocked by a lock).
pub const MEDIUM_REMOVAL_PREVENTED: Sense = Sense::new(0x05, 0x53, 0x02);
/// ILLEGAL REQUEST / LOGICAL BLOCK ADDRESS OUT OF RANGE (`OutOfBounds`).
pub const LBA_OUT_OF_RANGE: Sense = Sense::new(0x05, 0x21, 0x00);
/// ILLEGAL REQUEST / LOGICAL UNIT NOT SUPPORTED (`LunNotFound`).
pub const LUN_NOT_SUPPORTED: Sense = Sense::new(0x05, 0x25, 0x00);

/// Command completion as fixed by the device; `Check` carries the exact sense
/// instance for this command (saved sense is a separate fact).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Completion {
    /// Command completed successfully.
    Good,
    /// CHECK CONDITION with the given sense.
    Check(Sense),
    /// The device is busy and the command was not started.
    Busy,
    /// Reservation conflict (no reservations are created).
    ReservationConflict,
    /// The task set is full.
    TaskSetFull,
}

/// Minimal storage/device error vocabulary.
///
/// `Contract`, `CounterExhausted`, `Boundary` and `ForeignBoundary` are
/// management/runner facts and never map to SCSI sense
/// `LunNotFound` is a wire-LUN fact and does map to
/// `05/25/00`; `Commit` is produced only by [`commit_fault`].
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Fault {
    /// A storage operation failed; direction decides read/write sense.
    Io,
    /// The requested range is outside the backing's bounds.
    OutOfBounds,
    /// The medium (or its runtime latch) is write protected.
    NotWritable,
    /// The command shape is unsupported by this device.
    Unsupported,
    /// The operation was cancelled; its final effect is not observable.
    Cancelled,
    /// Settlement failed and the LU must be treated as needing recovery.
    NeedsRecovery,
    /// The old medium's local commit hook failed; the candidate was kept.
    Commit,
    /// A protocol/adapter contract violation (runner-side, never SCSI sense).
    Contract,
    /// A fixed-size slot/token pool is exhausted.
    CounterExhausted,
    /// The authoritative boundary was not complete.
    Boundary,
    /// A permit/receipt belongs to another target.
    ForeignBoundary,
    /// Runtime wire LUN is outside this Target's fixed slot set.
    LunNotFound,
}

/// Operation context for the default storage-fault → sense mapping.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum IoContext {
    /// Host read path.
    Read,
    /// Host write path.
    Write,
    /// Flush/synchronize path.
    Sync,
    /// Foreground/background media format path.
    Format,
    /// Speculative prefetch (read-only, failure must not change completion).
    Prefetch,
}

/// Default storage-fault → sense mapping.
///
/// The table in is the only normative table and profiles may override
/// any entry explicitly; this helper is a default, not automatic behaviour.
///
/// `IoContext::Sync`, `Format` and `Prefetch` carry no read/write direction, so
/// they use the **read-direction default** `03/11/00`. A profile that knows the
/// real direction must pass `Read`/`Write` or override the mapping; this
/// choice is documented so it is never silently inconsistent.
///
/// `None` means the fault is a management/runner error and must not become a
/// SCSI sense.
#[must_use]
pub const fn storage_fault_sense(fault: Fault, ctx: IoContext) -> Option<Sense> {
    match fault {
        Fault::Io => Some(match ctx {
            IoContext::Write => WRITE_ERROR,
            IoContext::Read | IoContext::Sync | IoContext::Format | IoContext::Prefetch => {
                MEDIUM_ERROR
            }
        }),
        Fault::OutOfBounds => Some(LBA_OUT_OF_RANGE),
        Fault::NotWritable => Some(WRITE_PROTECTED),
        Fault::Unsupported => Some(INVALID_FIELD),
        Fault::LunNotFound => Some(LUN_NOT_SUPPORTED),
        Fault::Cancelled => Some(ABORTED_COMMAND),
        Fault::NeedsRecovery => Some(NEEDS_RECOVERY),
        Fault::Commit
        | Fault::Contract
        | Fault::CounterExhausted
        | Fault::Boundary
        | Fault::ForeignBoundary => None,
    }
}

/// Convert a local-commit completion into a management fault.
///
/// `Good → None`; every other completion → `Some(Fault::Commit)`. This is the
/// only place that produces [`Fault::Commit`]; the
/// commit's `Check(Sense)` itself never enters the SCSI sense table.
#[must_use]
pub const fn commit_fault(completion: Completion) -> Option<Fault> {
    match completion {
        Completion::Good => None,
        _ => Some(Fault::Commit),
    }
}

/// Confirmed write/delivery facts produced by a receipt or a cancel
/// settlement. It is **not** a success flag.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct KnownEffects {
    /// Confirmed prefix not yet fed into the success path (not a cumulative
    /// counter).
    pub confirmed_write: u64,
    /// A SYNCHRONIZE CACHE completed; local commits do not set this.
    pub sync_durable: bool,
    /// A write/sync was dropped or cancelled, so its final effect is unknown.
    pub unknown_remainder: bool,
    /// Prefix already delivered to the host.
    pub host_prefix: u64,
}

impl KnownEffects {
    /// No effect and no uncertainty.
    pub const NONE: KnownEffects = KnownEffects {
        confirmed_write: 0,
        sync_durable: false,
        unknown_remainder: false,
        host_prefix: 0,
    };
}

/// How far a fixed command completion was delivered to the host.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Delivery {
    /// No delivery obligation (no data/status to send).
    NotApplicable,
    /// Completion fixed, status/data not fully delivered yet.
    Pending,
    /// The full frame/status was accepted by the transport adapter.
    Complete,
    /// Delivery failed; an already-sent status is not rolled back.
    Failed,
}

/// The effect of IO that was issued but not fully observed.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Effect {
    /// The receipt's confirmed prefix is the complete known effect.
    Known,
    /// A pending write/sync was cancelled; the remainder is unknown.
    UnknownRemainder,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn storage_fault_sense_read_and_write_differ() {
        let read = storage_fault_sense(Fault::Io, IoContext::Read);
        let write = storage_fault_sense(Fault::Io, IoContext::Write);
        assert_eq!(read, Some(MEDIUM_ERROR));
        assert_eq!(write, Some(WRITE_ERROR));
        assert_ne!(read, write);
        assert_eq!(read, Some(Sense::new(0x03, 0x11, 0x00)));
        assert_eq!(write, Some(Sense::new(0x03, 0x0C, 0x00)));
    }

    #[test]
    fn storage_fault_sense_sync_and_format_use_documented_read_default() {
        assert_eq!(
            storage_fault_sense(Fault::Io, IoContext::Sync),
            Some(MEDIUM_ERROR)
        );
        assert_eq!(
            storage_fault_sense(Fault::Io, IoContext::Format),
            Some(MEDIUM_ERROR)
        );
        assert_eq!(
            storage_fault_sense(Fault::Io, IoContext::Prefetch),
            Some(MEDIUM_ERROR)
        );
    }

    #[test]
    fn storage_fault_sense_lun_not_found_is_05_25_00() {
        assert_eq!(
            storage_fault_sense(Fault::LunNotFound, IoContext::Read),
            Some(LUN_NOT_SUPPORTED)
        );
        assert_eq!(
            storage_fault_sense(Fault::LunNotFound, IoContext::Read),
            Some(Sense::new(0x05, 0x25, 0x00))
        );
    }

    #[test]
    fn storage_fault_sense_maps_the_normative_table() {
        assert_eq!(
            storage_fault_sense(Fault::OutOfBounds, IoContext::Write),
            Some(Sense::new(0x05, 0x21, 0x00))
        );
        assert_eq!(
            storage_fault_sense(Fault::NotWritable, IoContext::Write),
            Some(WRITE_PROTECTED)
        );
        assert_eq!(
            storage_fault_sense(Fault::Unsupported, IoContext::Read),
            Some(INVALID_FIELD)
        );
        assert_eq!(
            storage_fault_sense(Fault::Cancelled, IoContext::Read),
            Some(ABORTED_COMMAND)
        );
        assert_eq!(
            storage_fault_sense(Fault::NeedsRecovery, IoContext::Sync),
            Some(NEEDS_RECOVERY)
        );
    }

    #[test]
    fn storage_fault_sense_management_faults_do_not_map() {
        for fault in [
            Fault::Commit,
            Fault::Contract,
            Fault::CounterExhausted,
            Fault::Boundary,
            Fault::ForeignBoundary,
        ] {
            assert_eq!(storage_fault_sense(fault, IoContext::Read), None);
            assert_eq!(storage_fault_sense(fault, IoContext::Write), None);
        }
    }

    #[test]
    fn commit_fault_only_good_is_none() {
        assert_eq!(commit_fault(Completion::Good), None);
        assert_eq!(
            commit_fault(Completion::Check(INVALID_FIELD)),
            Some(Fault::Commit)
        );
        assert_eq!(commit_fault(Completion::Busy), Some(Fault::Commit));
        assert_eq!(
            commit_fault(Completion::ReservationConflict),
            Some(Fault::Commit)
        );
        assert_eq!(commit_fault(Completion::TaskSetFull), Some(Fault::Commit));
    }

    #[test]
    fn aborted_command_shares_the_abort_bytes() {
        assert_eq!(ABORTED_COMMAND, COMMAND_ABORTED);
        assert_eq!(ABORTED_COMMAND, Sense::new(0x0B, 0x45, 0x00));
    }

    #[test]
    fn known_effects_none_is_empty() {
        let none = KnownEffects::NONE;
        assert_eq!(none, KnownEffects::default());
        assert_eq!(none.confirmed_write, 0);
        assert!(!none.sync_durable);
        assert!(!none.unknown_remainder);
        assert_eq!(none.host_prefix, 0);
    }
}
