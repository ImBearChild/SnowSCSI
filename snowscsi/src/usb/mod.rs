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
//! SCSI command execution is delegated to the core [`Target`](crate::core::Target);
//! the session is the transport's [`HostTransport`](crate::core::storage::HostTransport)
//! and the shell's storage adapter executes the device's I/O.
//!
//! The data area handed to the SCSI device layer is a pure data region
//! ([`crate::MIN_DATA_AREA`] minimum); CBWs and CSWs live in `BotSession`'s
//! internal buffers, so protocol frames never share memory with SCSI data.
//!
//! # Example: driving one BOT transaction
//!
//! The shell feeds bulk events in; the session hands back the next action.
//! A complete no-data transaction (TEST UNIT READY) is two steps:
//!
//! ```no_run
//! use snowscsi::block::{BlockAttrs, BlockDevice};
//! use snowscsi::core::storage::{BlockingStorage, IoBuf, IoReq, StorageReceipt, SyncStorage};
//! use snowscsi::core::{Lu, LuImpl, NoMedium, Pair, Target};
//! use snowscsi::usb::{Action, BotSession, Event, CBW_LEN, CBW_SIGNATURE, CSW_LEN};
//! use snowscsi::MIN_DATA_LEN;
//!
//! struct Zeroes;
//! impl SyncStorage for Zeroes {
//!     fn exec(&mut self, _req: IoReq, buf: IoBuf<'_>) -> StorageReceipt {
//!         let len = match &buf {
//!             IoBuf::None => 0,
//!             IoBuf::Read(b) => b.len(),
//!             IoBuf::Write(b) => b.len(),
//!         };
//!         StorageReceipt::ok(len)
//!     }
//! }
//!
//! let mut slot = LuImpl::new(BlockDevice::new(BlockAttrs::new(16, 512)), 0u8);
//! let table: &mut [&mut dyn Lu<Pair = Pair<NoMedium, u8>>] = &mut [&mut slot];
//! let mut target = Target::new(table);
//! let mut storage = BlockingStorage::new(Zeroes);
//! let mut session = BotSession::new();
//! let mut work = vec![0u8; MIN_DATA_LEN];
//! let mut scratch = vec![0u8; MIN_DATA_LEN];
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
//! match session.poll(
//!     Event::HostRecv { len: CBW_LEN },
//!     &mut work,
//!     &mut scratch,
//!     &mut target,
//!     &mut storage,
//! ) {
//!     Action::HostSend { bytes } => assert_eq!(bytes.len(), CSW_LEN),
//!     other => panic!("expected CSW, got {other:?}"),
//! }
//!
//! // Bulk-IN sent → back in the Command phase, ready for the next CBW.
//! match session.poll(
//!     Event::HostSent,
//!     &mut work,
//!     &mut scratch,
//!     &mut target,
//!     &mut storage,
//! ) {
//!     Action::HostRecv {
//!         offset: 0,
//!         len,
//!         probe: false,
//!     } => assert_eq!(len, CBW_LEN),
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

/// Mass Storage Class interface class code (USB MSC Overview v1.4).
pub const MSC_CLASS: u8 = 0x08;
/// Subclass 0x06 = SCSI transparent command set (USB MSC Overview v1.4
/// Table 1; SFF-8070i is 0x05 and obsolete).
pub const MSC_SUBCLASS: u8 = 0x06;
/// Protocol 0x50 = Bulk-Only Transport (USB MSC Overview v1.4).
pub const MSC_PROTOCOL: u8 = 0x50;

/// Bulk-Only Mass Storage Reset class request (`bmRequestType` 0x21, BOT
/// §6.4).
pub const BOT_RESET: u8 = 0xFF;
/// Get Max LUN class request (`bmRequestType` 0xA1, BOT §6.5).
pub const GET_MAX_LUN: u8 = 0xFE;
