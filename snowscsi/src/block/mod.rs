//! Block profile: direct-access geometry, static writability and the
//! READ(10)/WRITE(10)/SYNCHRONIZE CACHE(10)/FORMAT UNIT command family.
//!
//! Authority: `__ARCH__/design/02-api-profiles.md` §5 and
//! `__ARCH__/design/05-acceptance.md` T01/T06/T21.
//!
//! The profile is **non-generic**: [`BlockDevice`] owns geometry, policy and
//! command state, while the backing bytes stay in the application's `Storage`
//! adapter (G6). It never sees paths, media kinds or MMC vocabulary, and it
//! does not depend on the feature-gated `scsi`/`cdrom` modules.

mod attrs;
mod device;

pub use attrs::BlockAttrs;
pub use device::BlockDevice;
