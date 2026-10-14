//! LUN bundle: SCSI device handles and their store planes, kept 1:1.
//!
//! Transports drive a whole LUN set at once. Two parallel slices — devices
//! and planes — would let a caller silently misalign them (write LUN *i*
//! through plane *j*). [`Luns`] packages both behind a single constructor
//! that enforces equal length, and destructuring it
//! (`let Luns { devs, planes } = luns;`) yields disjoint borrows of the two
//! fields so a transport can hand `devs[lun]` to the device seam and
//! `planes[lun]` to the storage seam independently.
//!
//! Every LUN the CLI builds now supplies a real plane; a `None` remains valid
//! for a genuinely self-backed LUN, and a `Store` op routed to it is an
//! internal error.

use crate::common::store::StorePlane;
use crate::scsi::device::ScsiDevice;

/// A 1:1 bundle of LUN devices and their store planes.
///
/// Index `i` of `devs` and index `i` of `planes` describe the same LUN.
pub struct Luns<'a> {
    /// Device handles, one per LUN (LUN `i`).
    pub devs: &'a mut [&'a mut dyn ScsiDevice],
    /// Storage plane for LUN `i`; `None` for self-backed LUNs.
    pub planes: &'a mut [Option<StorePlane<'a>>],
}

impl<'a> Luns<'a> {
    /// Bundle `devs` and `planes`. They must be the same length; a
    /// mismatch is a caller bug and is rejected in debug builds.
    pub fn new(
        devs: &'a mut [&'a mut dyn ScsiDevice],
        planes: &'a mut [Option<StorePlane<'a>>],
    ) -> Self {
        debug_assert_eq!(
            devs.len(),
            planes.len(),
            "Luns: devs/planes length mismatch"
        );
        Self { devs, planes }
    }

    /// Number of LUNs in the bundle (== `planes.len()` by construction).
    pub fn len(&self) -> usize {
        self.devs.len()
    }

    /// Always `false` (a bundle is only ever built with at least one LUN in
    /// practice); provided for lint symmetry with [`Self::len`].
    pub fn is_empty(&self) -> bool {
        self.devs.is_empty()
    }
}
