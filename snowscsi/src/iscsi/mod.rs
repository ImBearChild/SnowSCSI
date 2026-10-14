//! iSCSI target protocol core (feature `iscsi`, RFC 3720).
//!
//! A pure session state machine: [`target::IscsiSession`] consumes one
//! received PDU per call and reports its next need
//! ([`target::SessionStep`] — receive, send, or close). It never touches
//! platform I/O, so the same core serves a blocking TCP server, an async
//! executor task, or a bare-metal driver.
//!
//! Two ways to drive it:
//!
//! - **blocking** — [`target::IscsiSession::step`] loops the state machine
//!   to the end of one transaction over any byte stream. [`conn::Conn`] is
//!   blanket-implemented for every `embedded_io::Read + Write` type.
//! - **non-blocking** — [`target::IscsiSession::poll`], fed one
//!   [`target::SessionEvent::PduReceived`] at a time by a driver that owns
//!   the socket/event loop.
//!
//! Both entry points take the LUN devices and their 1:1 storage planes
//! (aligned slices). A device whose data phase yields a
//! [`Xfer::Store`](crate::scsi::device::Xfer::Store) op has it executed
//! **inline** on `planes[lun]` and fed back through
//! [`ScsiDevice::store_done`](crate::scsi::device::ScsiDevice::store_done);
//! the wire bytes are unchanged. [`target::serve_conn`] (and the
//! [`transport`] accept loop) take the bundled [`crate::scsi::Luns`].
//!
//! [`pdu`] holds the 48-byte BHS field codec; [`transport`] (behind
//! `std`) wraps a `std::net::TcpListener` in a serial accept loop around
//! `step`.
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
//! One blocking transaction against a connection whose peer vanished
//! before login: the state machine answers [`target::StepResult::Closed`]
//! and the driver drops both connection and session.
//!
//! ```
//! use snowscsi::common::seekable_storage::RamBackend;
//! use snowscsi::common::store::StorePlane;
//! use snowscsi::iscsi::pdu::BHS_SIZE;
//! use snowscsi::iscsi::target::{IscsiSession, StepResult};
//! use snowscsi::scsi::block::BlockDevice;
//! use snowscsi::MIN_DATA_LEN;
//!
//! let mut ram = vec![0u8; 64 * 1024];
//! let mut lun = BlockDevice::disk(&mut RamBackend::new(&mut ram), 512).unwrap();
//! let mut devs = [lun];
//! // Storage planes, 1:1 with `devs` (empty here: the peer closes before any
//! // data phase, so no `Store` op is ever produced).
//! let mut planes: [Option<StorePlane>; 0] = [];
//! let mut session = IscsiSession::new();
//! let mut work = vec![0u8; MIN_DATA_LEN + BHS_SIZE];
//!
//! // Any embedded_io Read+Write type is a Conn via the blanket impl;
//! // here: a peer that closed before sending anything (EOF on read).
//! struct PeerClosed;
//! impl embedded_io::ErrorType for PeerClosed {
//!     type Error = core::convert::Infallible;
//! }
//! impl embedded_io::Read for PeerClosed {
//!     fn read(&mut self, _: &mut [u8]) -> Result<usize, Self::Error> {
//!         Ok(0)
//!     }
//! }
//! impl embedded_io::Write for PeerClosed {
//!     fn write(&mut self, buf: &[u8]) -> Result<usize, Self::Error> {
//!         Ok(buf.len())
//!     }
//!     fn flush(&mut self) -> Result<(), Self::Error> {
//!         Ok(())
//!     }
//! }
//!
//! assert_eq!(
//!     session.step(&mut PeerClosed, &mut work, &mut devs, &mut planes),
//!     StepResult::Closed
//! );
//! ```

pub mod conn;
pub mod pdu;
pub mod target;
#[cfg(feature = "std")]
pub mod transport;
