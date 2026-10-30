//! iSCSI target protocol core (feature `iscsi`, RFC 3720).
//!
//! A pure session state machine: [`target::IscsiSession`] consumes one
//! [`target::Event`] per [`target::IscsiSession::poll`] call and returns the
//! next [`target::Action`] (receive, send or close). It never touches platform
//! I/O, so the same core serves a blocking TCP server, an async executor task,
//! or a bare-metal driver. SCSI commands are executed by the seam-first core:
//! the session builds the command context from the wire and drives a
//! [`Target`](crate::core::Target) one step per entry, implementing the host
//! data seam ([`HostTransport`](crate::core::storage::HostTransport)) itself.
//!
//! The session owns all framing: incoming PDUs are read in stages (the 48-byte
//! BHS, then the AHS + data segment + padding), driven by the
//! [`Action::HostRecv`](target::Action::HostRecv) offset/length pairs, so a
//! shell carries no protocol knowledge. A device data phase that yields a
//! host `Send` is chunked into Data-In PDUs; a host `Receive` is solicited with
//! R2T and consumed one Data-Out PDU at a time.
//!
//! [`pdu`] holds the 48-byte BHS field codec. The blocking shell
//! `transport::serve` (behind `std`) wraps a `std::net::TcpListener` in a
//! serial accept loop around the `Action`/`Event` protocol. With `async-io`,
//! `transport::serve_conn_async` is the awaited single-connection mirror over
//! `conn::AsyncConn`; the caller owns the listener and runtime.
//!
//! # Work-buffer contract
//!
//! All calls share two caller-provided banks: `work` (PDU + command data,
//! `len >= crate::MIN_DATA_LEN + pdu::BHS_SIZE`) and `scratch` (the resident
//! long-operation bank). The `work` floor keeps room for a Login Request
//! carrying the RFC 3720 §6.1 default `MaxRecvDataSegmentLength` (8192) bytes
//! of text, which a conformant initiator may send before any negotiation.
//! An **empty** `scratch` selects the shared bank: `work` also serves the long
//! operation, the session advances it only on `Event::Tick`, and the shell
//! defers input while a long token is in flight (a query waits at most one
//! long-operation chunk). A **non-empty** `scratch` must be at least
//! [`crate::MIN_DATA_LEN`] and selects the split mode, where queries stay
//! serviceable while a long IO runs. Undersized banks are rejected with
//! [`target::TargetError::WorkBufTooSmall`].
//!
//! `work` is **one** data bank: the leading [`pdu::BHS_SIZE`] bytes carry the
//! wire header, so the usable SCSI data area is exactly `work.len() -
//! pdu::BHS_SIZE`. That area must be a multiple of 4 (every Data-In PDU is
//! padded to a 4-byte boundary) and bounds one device data chunk: a command
//! whose transfer is larger is streamed in bank-sized chunks (Data-In PDUs or
//! per-chunk R2Ts), so the bank no longer has to hold the whole transfer.
//!
//! # Example
//!
//! A fresh session, driven by a no-I/O tick, asks for the next PDU's BHS:
//!
//! ```
//! use snowscsi::block::{BlockAttrs, BlockDevice};
//! use snowscsi::core::storage::{BlockingStorage, IoBuf, IoReq, StorageReceipt, SyncStorage};
//! use snowscsi::core::{Lu, LuImpl, Pair, Spc, Target};
//! use snowscsi::iscsi::pdu::BHS_SIZE;
//! use snowscsi::iscsi::target::{Action, Event, IscsiSession};
//! use snowscsi::MIN_DATA_LEN;
//!
//! struct Sink;
//! impl SyncStorage for Sink {
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
//! let mut slot = LuImpl::new(Spc::new(BlockDevice::new(BlockAttrs::new(16, 512))), 0u8);
//! let mut table = [&mut slot as &mut dyn Lu<Pair = Pair<_, u8>>];
//! let mut target = Target::new(&mut table[..]);
//! let mut storage = BlockingStorage::new(Sink);
//! let mut session = IscsiSession::new();
//! let mut work = vec![0u8; MIN_DATA_LEN + BHS_SIZE];
//! let mut scratch = vec![0u8; MIN_DATA_LEN];
//!
//! match session.poll(
//!     Event::Tick,
//!     &mut work,
//!     &mut scratch,
//!     &mut target,
//!     &mut storage,
//! ) {
//!     Action::HostRecv { offset: 0, len } => assert_eq!(len, BHS_SIZE),
//!     other => panic!("expected HostRecv, got {other:?}"),
//! }
//! ```

pub mod conn;
pub mod pdu;
pub mod target;
#[cfg(feature = "std")]
pub mod transport;
