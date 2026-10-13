//! USB Mass Storage Class, Bulk-Only Transport (BOT) protocol core
//! (feature `usb`).
//!
//! A no_std BOT protocol core, transport-layout independent like the iSCSI
//! module: the CBW/CSW framing ([`bot`]), the platform I/O seams ([`io`],
//! [`gadget`]) and the non-blocking [`target`] session state machine.
//! Platform transports live outside the lib (FunctionFS on Linux, embedded
//! USB device stacks on MCUs) and implement [`BotIo`] / [`Gadget`].
//!
//! The data area handed to the SCSI device layer is a pure data region
//! ([`crate::MIN_DATA_LEN`]); CBWs and CSWs live in `BotSession`'s internal
//! buffers, so protocol frames never share memory with SCSI data.
//!
//! # Example: driving one BOT transaction
//!
//! The driver feeds bulk events in; the session hands back the next need.
//! A complete no-data transaction (TEST UNIT READY) is two steps:
//!
//! ```
//! use snowscsi::common::seekable_storage::RamBackend;
//! use snowscsi::scsi::block::BlockDevice;
//! use snowscsi::usb::{
//!     BotSession, BotStepResult, SessionEvent, SessionStep, CBW_LEN,
//!     CBW_SIGNATURE, CSW_LEN,
//! };
//! use snowscsi::MIN_DATA_LEN;
//!
//! let mut ram = vec![0u8; 64 * 1024];
//! let mut lun = BlockDevice::disk(RamBackend::new(&mut ram), 512).unwrap();
//! let mut devs = [lun];
//! let mut session = BotSession::new();
//! let mut data = vec![0u8; MIN_DATA_LEN];
//!
//! // A valid TEST UNIT READY CBW: signature + tag + declared length 0 +
//! // flags 0 (no data phase) + LUN 0 + 6-byte CDB (opcode 0x00).
//! let mut cbw = [0u8; CBW_LEN];
//! cbw[0..4].copy_from_slice(&CBW_SIGNATURE.to_le_bytes());
//! cbw[14] = 6;
//! cbw[15] = 0x00; // TEST UNIT READY
//!
//! // One bulk-OUT completion → the CSW is pending on the bulk-IN pipe.
//! match session.poll(SessionEvent::OutRecv { data: &cbw }, &mut data, &mut devs) {
//!     SessionStep::NeedIn(csw) => assert_eq!(csw.len(), CSW_LEN),
//!     other => panic!("expected CSW, got {other:?}"),
//! }
//!
//! // Bulk-IN sent → transaction complete; the session is back in the
//! // Command phase and can accept the next CBW.
//! assert_eq!(
//!     session.poll(SessionEvent::InSent, &mut data, &mut devs),
//!     SessionStep::Done(BotStepResult::Processed)
//! );
//! ```

pub mod bot;
pub mod gadget;
pub mod io;
pub mod target;

pub use bot::{BotDir, Cbw, Csw, CswStatus};
pub use gadget::{CtrlAck, CtrlReply, CtrlReq, Gadget};
pub use io::{BotIo, BotIoErr};
pub use target::{
    BotSession, BotStepResult, BotTargetError, SessionEvent, SessionNeed, SessionStep,
    ShortfallPolicy, MAX_PAD,
};

/// Command Block Wrapper signature (`"USBC"`, BOT §5.1) — stored little
/// endian in the raw 31-byte CBW.
pub const CBW_SIGNATURE: u32 = 0x4342_5355;
/// Command Status Wrapper signature (`"USBS"`, BOT §5.2) — stored little
/// endian in the raw 13-byte CSW.
pub const CSW_SIGNATURE: u32 = 0x5342_5355;
/// Command Block Wrapper size in bytes (BOT §5.1).
pub const CBW_LEN: usize = 31;
/// Command Status Wrapper size in bytes (BOT §5.2).
pub const CSW_LEN: usize = 13;

/// Mass Storage Class interface class code (USB MSC Overview v1.4 §4.1).
pub const MSC_CLASS: u8 = 0x08;
/// Subclass 0x06 = SCSI transparent command set (USB MSC Overview v1.4
/// Table 1; SFF-8070i is 0x05 and obsolete).
pub const MSC_SUBCLASS: u8 = 0x06;
/// Protocol 0x50 = Bulk-Only Transport (USB MSC Overview v1.4 §4.2).
pub const MSC_PROTOCOL: u8 = 0x50;

/// Bulk-Only Mass Storage Reset class request (`bmRequestType` 0x21, BOT
/// §6.4).
pub const BOT_RESET: u8 = 0xFF;
/// Get Max LUN class request (`bmRequestType` 0xA1, BOT §6.5).
pub const GET_MAX_LUN: u8 = 0xFE;
