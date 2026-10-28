//! MMC profile: `MmcDrive` over an `MmcMedium`, plus the flat CD medium.
//!
//! [`drive::MmcDrive`] only decodes media commands, validates CDB fields and
//! encodes the media-description responses. Public query commands (MODE SENSE,
//! READ CAPACITY, GET CONFIGURATION, GET EVENT STATUS NOTIFICATION) are served
//! by `Spc` through `SpcProfile`; the media command table stays in the drive.
//!
//! Byte layouts follow the production baseline in `crate::cdrom::{common,drive}`
//! and are re-implemented here, so this module has no runtime dependency on the
//! old `cdrom` module. [`flat::FlatCdMedium`] is the single-track, single-
//! session, read-only CD medium used by the fixtures;
//! [`vendor::VendorMedium`] is a second independent read-only medium (a new
//! medium is a new `MmcMedium` impl, never a `MmcDrive` match); and
//! `DvdRamMedium` is the feature-gated rewritable DVD-RAM medium.

pub mod attrs;
pub mod drive;
#[cfg(feature = "dvdram")]
pub mod dvdram;
pub mod flat;
pub mod medium;
pub mod op;
pub mod vendor;

pub use self::attrs::{
    DiscInfo, DiscStatus, MmcAttrs, MmcWriteMode, SectorKind, Session, Track, TrackKind,
};
pub use self::drive::MmcDrive;
#[cfg(feature = "dvdram")]
pub use self::dvdram::{DvdRamMedium, DvdRamState};
pub use self::flat::{FlatCdMedium, FlatState};
pub use self::medium::MmcMedium;
pub use self::op::MmcOp;
pub use self::vendor::{VendorMedium, VendorState};
