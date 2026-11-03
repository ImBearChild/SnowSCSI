//! MMC profile: `MmcDrive` over an `MmcMedium`, plus the flat CD medium.
//!
//! [`drive::MmcDrive`](crate::mmc::drive::MmcDrive) only decodes media
//! commands, validates CDB fields and
//! encodes the media-description responses. Public query commands (MODE SENSE,
//! READ CAPACITY, GET CONFIGURATION, GET EVENT STATUS NOTIFICATION) are served
//! by `Spc` through `SpcProfile`; the media command table stays in the drive.
//! [`MmcCaps`](crate::mmc::MmcCaps) is the LU's capability (profiles, 0x2A,
//! random writable) and survives an eject; `MmcAttrs` describes the disc.
//! [`TrackInfo`](crate::mmc::TrackInfo) and
//! [`TrackInfoRequest`](crate::mmc::TrackInfoRequest) describe one track and
//! the READ TRACK INFORMATION address modes; recordable media use them to
//! expose reserved and partially recorded tracks.
//!
//! Byte layouts follow the production baseline in `crate::cdrom::{common,drive}`
//! and are re-implemented here, so this module has no runtime dependency on the
//! old `cdrom` module.
//! [`flat::FlatCdMedium`](crate::mmc::flat::FlatCdMedium) is the single-track,
//! single-session, read-only CD medium used by the fixtures;
//! [`vendor::VendorMedium`](crate::mmc::vendor::VendorMedium) is a second
//! independent read-only medium (a new
//! medium is a new `MmcMedium` impl, never a `MmcDrive` match); and
//! `DvdRamMedium` is the feature-gated rewritable DVD-RAM medium;
//! `cdr_bundle::CdrBundleMedium` is the feature-gated sequential write-once
//! CD-R medium.

pub mod attrs;
#[cfg(feature = "cdr-bundle")]
pub mod cdr_bundle;
pub mod drive;
#[cfg(feature = "dvdram")]
pub mod dvdram;
pub mod flat;
pub mod medium;
pub mod op;
pub mod vendor;

pub use self::attrs::{
    AtipInfo, DiscInfo, DiscStatus, MmcAttrs, MmcWriteMode, SectorKind, Session, Track, TrackInfo,
    TrackInfoRequest, TrackKind, TrackStatus,
};
#[cfg(feature = "cdr-bundle")]
pub use self::cdr_bundle::{
    CdrBundleMedium, CdrBundleState, CdrCapacity, CdrDiscState, Recovery, TocError, TocHeader,
};
pub use self::drive::{MmcCaps, MmcDrive};
#[cfg(feature = "dvdram")]
pub use self::dvdram::{DvdRamMedium, DvdRamState};
pub use self::flat::{FlatCdMedium, FlatState};
pub use self::medium::MmcMedium;
pub use self::op::MmcOp;
pub use self::vendor::{VendorMedium, VendorState};
