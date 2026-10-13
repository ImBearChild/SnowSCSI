//! CD-ROM device emulation.
//!
//! The optical-media device layer, independent of the SCSI block stack.
//! All MMC commands are dispatched through [`CdromDrive`]; media types
//! only provide geometry and a data plane.
//!
//! # Media types
//!
//! - [`CdMedia::Ro`]([`media::CdMedia::Ro`]) — read-only disc over any
//!   [`FlatData`] source (image, RAM, or live-generated ISO9660 via
//!   [`LiveData`]);
//! - [`CdMedia::Rw`]([`media::CdMedia::Rw`]) (feature `dvdram`) — a
//!   random-writable DVD-RAM: [`DvdRamMedia`] over any writable plane.
//!
//! Discs are loaded/ejected at runtime through the drive's media slot;
//! ownership round-trips so an application can keep a pool of discs.
//!
//! # Example
//!
//! Mount a flat ISO payload and answer INQUIRY as a CD-ROM (PDT 0x05):
//!
//! ```
//! use snowscsi::cdrom::{CdMedia, CdromDrive};
//! use snowscsi::common::seekable_storage::RamBackend;
//! use snowscsi::scsi::device::{CommandOutcome, ScsiDevice};
//! use snowscsi::MIN_DATA_LEN;
//!
//! let mut image = vec![0u8; 2048 * 300]; // a small ISO payload
//! let mut backend = RamBackend::new(&mut image);
//! let mut drive = CdromDrive::new();
//! // Initial load without unit attention (a later load()/eject() sets one).
//! drive.load_quiet(CdMedia::ro(&mut backend));
//!
//! let mut data = vec![0u8; MIN_DATA_LEN];
//! let mut cdb = [0u8; 6];
//! cdb[0] = 0x12; // INQUIRY
//! cdb[4] = 96;   // allocation length
//!
//! match drive.do_cmd(&cdb, &mut data).unwrap() {
//!     CommandOutcome::OutInline { len } => {
//!         assert!(len >= 36);
//!         assert_eq!(data[0] & 0x1F, 0x05); // peripheral device type: CD-ROM
//!     }
//!     other => panic!("INQUIRY returns inline data, got {other:?}"),
//! }
//! ```

pub mod common;
pub mod drive;
#[cfg(feature = "dvdram")]
pub mod dvdram;
pub mod media;

// Windows-compatibility regression tests require UDF-RW media (dvdram)
// to exercise the DVD-RAM profile that the captured traffic targets.
#[cfg(all(test, feature = "usb", feature = "dvdram"))]
mod win_compat_tests;

pub use common::{
    build_get_config_response, build_read_buffer_capacity, build_read_disc_info, CdromCapabilities,
    CurrentProfile, DiscInfo, MediaState, CDROM_IDENTITY, DVDRAM_CAPS, HYPER_MULTI_CAPS,
    SECTOR_SIZE,
};
pub use drive::CdromDrive;
#[cfg(feature = "dvdram")]
pub use dvdram::DvdRamMedia;
pub use media::{CdLiveFsError, CdMedia, FlatMedia, LiveData, LiveDataBuilder, MediaError, Tray};
pub use snowscsi_common::seekable_storage::FlatData;
