//! Asynchronous device/plane bundle, mirroring the synchronous LUN bundle in
//! [`crate::scsi::luns`]. Because an `async fn` in trait is not
//! dyn-compatible, the plane side is a generic parameter rather than a `dyn`
//! handle.
//!
//! Transports drive a whole LUN set at once. Two parallel slices — devices
//! and planes — would let a caller silently misalign them (write LUN *i*
//! through plane *j*). [`AsyncLuns`] packages both behind a single
//! constructor that enforces equal length, and destructuring it
//! (`let AsyncLuns { devs, planes } = luns;`) yields disjoint borrows of the
//! two fields so a transport can hand `devs[lun]` to the device seam and
//! `planes[lun]` to the storage seam independently.
//!
//! `P` is the concrete asynchronous plane type; the [`AsyncStorePlane`] bound
//! sits on the impls that actually use the plane, so the bundle can be built
//! and destructured without naming it.

use crate::common::async_store::AsyncStorePlane;
use crate::common::seekable_storage::StorageError;
use crate::common::store::StoreOp;
use crate::scsi::device::ScsiDevice;

/// A 1:1 bundle of LUN devices and their asynchronous store planes.
///
/// Index `i` of `devs` and index `i` of `planes` describe the same LUN.
pub struct AsyncLuns<'a, P> {
    /// Device handles, one per LUN (LUN `i`).
    pub devs: &'a mut [&'a mut dyn ScsiDevice],
    /// Storage plane for LUN `i`; `None` for self-backed LUNs.
    pub planes: &'a mut [Option<P>],
}

impl<'a, P> AsyncLuns<'a, P> {
    /// Bundle `devs` and `planes`. They must be the same length; a mismatch
    /// is a caller bug and is rejected in debug builds.
    pub fn new(devs: &'a mut [&'a mut dyn ScsiDevice], planes: &'a mut [Option<P>]) -> Self {
        debug_assert_eq!(
            devs.len(),
            planes.len(),
            "AsyncLuns: devs/planes length mismatch"
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

impl<P: AsyncStorePlane> AsyncLuns<'_, P> {
    /// Execute `op` against LUN `lun`'s plane. A LUN without a plane
    /// (self-backed) is a caller bug: this helper reports
    /// [`StorageError::Unsupported`], but a shell driving the bundle should
    /// reject a `Store` on a plane-less LUN as its own internal error (as the
    /// synchronous shell does) instead of surfacing a host-visible sense.
    pub async fn do_op(&mut self, lun: usize, op: StoreOp<'_>) -> Result<(), StorageError> {
        match self.planes.get_mut(lun).and_then(Option::as_mut) {
            Some(plane) => plane.do_op(op).await,
            None => Err(StorageError::Unsupported),
        }
    }

    /// Persist every LUN's plane (shutdown flush); a self-backed LUN has
    /// nothing to persist.
    pub async fn sync(&mut self) -> Result<(), StorageError> {
        for plane in self.planes.iter_mut().flatten() {
            plane.sync().await?;
        }
        Ok(())
    }
}
