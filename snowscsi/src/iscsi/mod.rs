//! iSCSI target protocol core (feature `iscsi`, RFC 3720).
//!
//! A pure session state machine: [`target::IscsiSession`] consumes one
//! [`target::Event`] per [`target::IscsiSession::poll`] call and returns the
//! next [`target::Action`] (receive, send, a storage op, or close). It never
//! touches platform I/O, so the same core serves a blocking TCP server, an
//! async executor task, or a bare-metal driver.
//!
//! The session owns all framing: incoming PDUs are read in two stages (the
//! 48-byte BHS, then the AHS + data segment + padding), driven by the
//! [`Action::HostRecv`](target::Action::HostRecv) lengths, so a shell carries
//! no protocol knowledge. A device whose data phase yields a
//! [`Xfer::Store`](crate::scsi::device::Xfer::Store) op is handed to the shell
//! as [`Action::Store`](target::Action::Store); the shell executes it against
//! the LUN's storage plane and feeds the result back as
//! [`Event::StoreDone`](target::Event::StoreDone), which the session maps
//! through
//! [`ScsiDevice::store_done`](crate::scsi::device::ScsiDevice::store_done);
//! the wire bytes are unchanged.
//!
//! [`pdu`] holds the 48-byte BHS field codec. The blocking shell
//! `transport::serve` (behind `std`) wraps a `std::net::TcpListener` in a
//! serial accept loop around the `Action`/`Event` protocol.
//!
//! # Work-buffer contract
//!
//! All calls share one caller-provided scratch buffer:
//! `work.len() >= crate::MIN_DATA_LEN + pdu::BHS_SIZE`. The leading
//! [`pdu::BHS_SIZE`] bytes carry the wire header; the remainder is the
//! SCSI data area handed to the devices. Undersized buffers are rejected
//! with [`target::TargetError::WorkBufTooSmall`].
//!
//! # Example
//!
//! A fresh session, driven by a no-I/O tick, asks for the next PDU's BHS:
//!
//! ```
//! use snowscsi::common::seekable_storage::RamBackend;
//! use snowscsi::iscsi::pdu::BHS_SIZE;
//! use snowscsi::iscsi::target::{Action, Event, IscsiSession};
//! use snowscsi::scsi::block::BlockDevice;
//! use snowscsi::MIN_DATA_LEN;
//!
//! let mut ram = vec![0u8; 64 * 1024];
//! let mut devs = [BlockDevice::disk(&mut RamBackend::new(&mut ram), 512).unwrap()];
//! let mut session = IscsiSession::new();
//! let mut work = vec![0u8; MIN_DATA_LEN + BHS_SIZE];
//!
//! match session.poll(Event::Tick, &mut work, &mut devs) {
//!     Action::HostRecv { len } => assert_eq!(len, BHS_SIZE),
//!     other => panic!("expected HostRecv, got {other:?}"),
//! }
//! ```

pub mod conn;
pub mod pdu;
pub mod target;
#[cfg(feature = "std")]
pub mod transport;
