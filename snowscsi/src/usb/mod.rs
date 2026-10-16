//! USB Mass Storage Class, Bulk-Only Transport (BOT) protocol core
//! (feature `usb`).
//!
//! A no_std BOT protocol core, transport-layout independent like the iSCSI
//! module: the CBW/CSW framing ([`bot`]), the platform I/O seams ([`io`],
//! [`gadget`]), the non-blocking [`target`] session state machine, and the
//! library-owned synchronous shell loop [`serve()`]. Platform transports live
//! outside the lib (FunctionFS on Linux, embedded USB device stacks on MCUs)
//! and implement [`BotIo`] / [`Gadget`].
//!
//! The data area handed to the SCSI device layer is a pure data region
//! ([`crate::MIN_DATA_LEN`]); CBWs and CSWs live in `BotSession`'s internal
//! buffers, so protocol frames never share memory with SCSI data.
//!
//! # Example: driving one BOT transaction
//!
//! The shell feeds bulk events in; the session hands back the next action.
//! A complete no-data transaction (TEST UNIT READY) is two steps:
//!
//! ```
//! use snowscsi::common::seekable_storage::RamBackend;
//! use snowscsi::scsi::block::BlockDevice;
//! use snowscsi::usb::{Action, BotSession, Event, CBW_LEN, CBW_SIGNATURE, CSW_LEN};
//! use snowscsi::MIN_DATA_LEN;
//!
//! let mut ram = vec![0u8; 64 * 1024];
//! let mut lun = BlockDevice::disk(&mut RamBackend::new(&mut ram), 512).unwrap();
//! let mut devs = [lun];
//! let mut session = BotSession::new();
//! let mut work = vec![0u8; MIN_DATA_LEN];
//!
//! // A valid TEST UNIT READY CBW: signature + tag + declared length 0 +
//! // flags 0 (no data phase) + LUN 0 + 6-byte CDB (opcode 0x00).
//! let mut cbw = [0u8; CBW_LEN];
//! cbw[0..4].copy_from_slice(&CBW_SIGNATURE.to_le_bytes());
//! cbw[14] = 6;
//! cbw[15] = 0x00; // TEST UNIT READY
//!
//! // Host bytes land in `work`; one bulk-OUT completion → the CSW is pending.
//! work[..CBW_LEN].copy_from_slice(&cbw);
//! match session.poll(Event::HostRecv { len: CBW_LEN }, &mut work, &mut devs) {
//!     Action::HostSend { bytes, .. } => assert_eq!(bytes.len(), CSW_LEN),
//!     other => panic!("expected CSW, got {other:?}"),
//! }
//!
//! // Bulk-IN sent → back in the Command phase, ready for the next CBW.
//! match session.poll(Event::HostSent, &mut work, &mut devs) {
//!     Action::HostRecv { len, probe: false } => assert_eq!(len, CBW_LEN),
//!     other => panic!("expected next CBW receive, got {other:?}"),
//! }
//! ```

#[cfg(feature = "async-io")]
pub mod async_io;
pub mod bot;
#[cfg(feature = "embassy")]
pub mod embassy;
pub mod gadget;
pub mod io;
pub mod serve;
pub mod target;

#[cfg(feature = "async-io")]
pub use async_io::{AsyncBotRecv, AsyncBotSend, RecvMode};
pub use bot::{BotDir, Cbw, Csw, CswStatus};
#[cfg(feature = "embassy")]
pub use embassy::{EmbassyBot, GadgetHalf, RecvHalf, SendHalf};
pub use gadget::{CtrlAck, CtrlReply, CtrlReq, Gadget};
pub use io::{BotIo, BotIoErr};
pub use serve::{serve, ServeError};
pub use target::{Action, BotSession, BotTargetError, Event, ShortfallPolicy, MAX_PAD};

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
