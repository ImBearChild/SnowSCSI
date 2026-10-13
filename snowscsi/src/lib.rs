//! SnowSCSI SCSI: core + iSCSI + USB MSC + CD-ROM device emulation.
//!
//! This is the main API surface of the SnowSCSI workspace — a SCSI
//! device-emulation toolkit (iSCSI target, USB MSC gadget, virtual
//! disks/optical drives) built on zero-alloc, `no_std`-clean seams.
//!
//! # Workspace map
//!
//! - **this crate** — SPC/SBC/MMC command layers, `BlockDevice` /
//!   [`CdromDrive`](cdrom::CdromDrive), iSCSI target (`iscsi`),
//!   USB BOT core (`usb`).
//! - [`snowscsi_common`] — the storage seams everything is written
//!   against: the capability ladder
//!   [`common::seekable_storage::FlatData`] →
//!   [`common::seekable_storage::WritableFlatData`] →
//!   [`common::seekable_storage::SeekableStorage`], the FS seam
//!   [`common::fs_storage::FsStorage`], and the unified logging macros.
//! - [`snowscsi_iso9660`] — ISO9660 + Joliet live generation
//!   ([`LiveData`](snowscsi_iso9660::live::LiveData),
//!   [`compute_layout`](snowscsi_iso9660::live::compute_layout)).
//! - `snowscsi-cli` (no docs; a thin binary shell) — the `snowscsi`
//!   executable: `serve` and `mkisofs`.
//!
//! Start at [`scsi::device::ScsiDevice`] (the LUN seam every transport
//! drives), [`scsi::block::BlockDevice`] (disk/CD-ROM profiles over any
//! byte plane) or [`iscsi::target::IscsiSession`] /
//! [`usb::BotSession`] (the two transports). Each subsystem's module docs
//! carry runnable examples: [`iscsi`], [`usb`], and — behind the `cdrom`
//! feature — [`cdrom`].

#![cfg_attr(all(not(feature = "std"), not(test)), no_std)]
#![deny(unsafe_code)]

pub use snowscsi_common as common;
pub use snowscsi_common::{debug, error, info, trace, warn};

pub mod scsi;

#[cfg(feature = "cdrom")]
pub mod cdrom;

#[cfg(feature = "iscsi")]
pub mod iscsi;

#[cfg(feature = "usb")]
pub mod usb;

/// Minimum data-area size for `ScsiDevice::do_cmd`: 8192 bytes.
///
/// Every command-processing entry point (`do_cmd`, `poll`, `step`) takes a
/// caller-provided scratch buffer and rejects smaller ones at runtime with
/// `WorkBufTooSmall`. Total RAM budget for one transport + LUN set:
///
/// | Component | Size |
/// |-----------|------|
/// | SCSI data area (`data` / work buffer data region) | ≥ [`MIN_DATA_LEN`] |
/// | iSCSI: PDU header prefix in front of the data area | `BHS_SIZE` (48 B) |
/// | USB BOT: separate driver receive scratch | ≥ `data.len()` |
/// | Session state (`IscsiSession` / `BotSession`) | few hundred bytes each |
///
/// See `ScsiDevice` for the full contract.
pub const MIN_DATA_LEN: usize = 8192;
