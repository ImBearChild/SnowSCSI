//! SCSI core + devices.
//!
//! ## Modules (filled in as the leaf `snowscsi` crate is folded in)
//! - [`scsi`]: opcodes, sense data, CDB field parsing (SPC-4 / SBC-3 /
//!   MMC-6).  No dependencies on the rest of the crate.
//! - [`device`]: command outcome + device types (device.h).
//! - `backend`: `FileBackend` + the aggregating `BlockBackend` enum
//!   (gated by `std`).
//! - `fs_backend`: `StdFsBackend` + `FsBackend` enum (gated by `std`).
//! - `spc`: SPC command parsing + shared execution (INQUIRY, MODE SENSE, ...).
//! - `sbc`: SBC command parsing + execution (block device set, SBC-3 §5).
//! - `block`: SCSI LUNs over a byte plane — one type, two profiles
//!   (`disk()` writable PDT 0x00 / `cdrom()` read-only PDT 0x05, the
//!   former `CDBlockDevice`). Generic over any `FlatData` backend.
//! - `iscsi_pdu`: iSCSI PDU (BHS) field codec (RFC 3720 §10.x).
//! - `conn`: connection abstraction (`embedded_io::Read + Write`).
//! - `iscsi_target`: iSCSI target session state machine (RFC 3720 §5/§10).
//! - `transport`: BSD TCP transport (gated by `std`).

pub mod backend;
pub mod block;
pub mod device;
#[cfg(feature = "std")]
pub mod fs_backend;
pub mod sbc;
#[allow(clippy::module_inception)]
pub mod scsi;
pub mod spc;
