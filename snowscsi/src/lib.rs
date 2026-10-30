//! SnowSCSI SCSI: core + iSCSI + USB MSC + CD-ROM device emulation.
//!
//! This is the main API surface of the SnowSCSI workspace — a SCSI
//! device-emulation toolkit (iSCSI target, USB MSC gadget, virtual
//! disks/optical drives) built on zero-alloc, `no_std`-clean seams.
//!
//! # Workspace map
//!
//! - **this crate** — SPC/SBC/MMC command layers, `BlockDevice` /
//!   [`CdromDrive`](cdrom::CdromDrive), the MMC profile ([`mmc::MmcDrive`])
//!   with its flat CD medium, iSCSI target (`iscsi`), USB BOT core (`usb`).
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
//!
//! # One buffer or two (resident long operations)
//!
//! Both transports take a `work` bank and a `scratch` bank. An **empty**
//! `scratch` selects the shared mode: `work` serves the command path and the
//! resident long operation (a FORMAT/BLANK fill) in turn, so the application
//! allocates one buffer. The transport shells never read input while a long
//! token is in flight; the long operation advances one storage step per
//! [`usb::Event::Tick`]/[`iscsi::target::Event::Tick`] entry, so a query that
//! arrives meanwhile waits at most one long-operation chunk.
//!
//! A **non-empty** `scratch` (at least [`MIN_DATA_LEN`]) selects the split
//! mode: the long operation owns its own bank and queries stay serviceable
//! while it runs. The two paths never need a buffer at the same time inside one
//! poll; this slice is strictly sequential and does not overlap storage with
//! the wire.
//!
//! Both transports also offer an explicit **overlap** mode
//! ([`usb::BotSession::with_overlap`], [`iscsi::target::IscsiSession::with_overlap`]):
//! `work` is split into two equal banks and the resident long operation borrows
//! one while the command uses the other. Overlap is never inferred from the
//! buffer length.

#![cfg_attr(all(not(feature = "std"), not(test)), no_std)]
#![deny(unsafe_code)]

pub use snowscsi_common as common;
pub use snowscsi_common::{debug, error, info, trace, warn};

/// Direct-access block device profile.
pub mod block;
/// Core contract layer (`no_std`, no-alloc, no `unsafe`): errors, device
/// lifecycle, permits and management values.
pub mod core;
/// MMC profile (`MmcDrive` + `MmcMedium`) and the flat CD medium.
pub mod mmc;

pub mod scsi;

#[cfg(feature = "cdrom")]
pub mod cdrom;

#[cfg(feature = "iscsi")]
pub mod iscsi;

#[cfg(feature = "usb")]
pub mod usb;

/// Minimum SCSI data area accepted by the USB BOT transport: 512 bytes.
///
/// Matches the minimum SCSI logical block length; BOT itself has no larger
/// minimum (its CBW is 31 bytes). A transfer larger than the area is streamed
/// in bank-sized chunks, so this is the protocol floor, not a performance
/// target. iSCSI keeps [`MIN_DATA_LEN`] plus its 48-byte BHS header as the bank
/// floor: RFC 3720 §6.1 applies the default `MaxRecvDataSegmentLength` (8192)
/// during Login, so a conformant first Login Request may carry up to 8192 bytes
/// of text and the bank must be able to stage it.
pub const MIN_DATA_AREA: usize = 512;

/// Legacy `ScsiDevice` data-area requirement and iSCSI/`scratch` basis:
/// 8192 bytes.
///
/// The legacy `ScsiDevice` command-processing entry points (`do_cmd`, `poll`)
/// **require** this size and reject smaller buffers with `WorkBufTooSmall`.
/// The core iSCSI transport sizes its `work` bank as this plus the 48-byte BHS
/// (the Login text above must fit) and both core transports require this size
/// for the resident long-operation `scratch` bank. USB BOT accepts any `work`
/// data area down to [`MIN_DATA_AREA`]. Total RAM budget for one transport +
/// LUN set:
///
/// | Component | Size |
/// |-----------|------|
/// | SCSI data area (`data` / work buffer data region) | ≥ [`MIN_DATA_AREA`] (USB BOT), ≥ [`MIN_DATA_LEN`] (iSCSI, legacy `ScsiDevice`) |
/// | iSCSI: PDU header prefix in front of the data area | `BHS_SIZE` (48 B) |
/// | USB BOT: single time-multiplexed `work` buffer | ≥ [`MIN_DATA_AREA`] |
/// | Resident long-operation `scratch` (iSCSI, USB BOT) | ≥ [`MIN_DATA_LEN`] |
/// | Session state (`IscsiSession` / `BotSession`) | few hundred bytes each |
///
/// See `ScsiDevice` for the full contract.
pub const MIN_DATA_LEN: usize = 8192;
