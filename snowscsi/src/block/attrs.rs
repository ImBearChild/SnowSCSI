//! Static block-device attributes.
//!
//! These are facts fixed at construction time. They contain no MMC media
//! vocabulary and no behaviour dispatch: [`BlockDevice`](super::BlockDevice)
//! reads them, the application decides what to build.

use crate::core::Writability;

/// Geometry, block size, static writability and health of a block device.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct BlockAttrs {
    /// Number of addressable logical blocks.
    pub capacity_blocks: u64,
    /// Logical block length in bytes (must be non-zero for usable geometry).
    pub block_len: u32,
    /// Static writability of the backing.
    pub write_mode: Writability,
    /// Runtime write-protect policy/latch, separate from [`Self::write_mode`].
    pub write_protected: bool,
    /// The device reports a health failure until it is explicitly reinstalled.
    pub needs_recovery: bool,
    /// The LUN's medium is removable (INQUIRY RMB). A slot property, not a
    /// property of the bytes currently installed.
    ///
    /// When set, INQUIRY reports RMB=1 and the SPC wrapper accepts a host
    /// START STOP UNIT (`LoEj=1, Start=0`) eject request. The slot then
    /// detaches its pair and the application can install a new one at the same
    /// LUN; the application is responsible for raising
    /// [`UaClass::MediumChanged`](crate::core::UaClass::MediumChanged) on the
    /// new pair so the host re-reads the medium.
    pub removable: bool,
}

impl BlockAttrs {
    /// Build a writable block device with `capacity_blocks * block_len` bytes.
    #[must_use]
    pub const fn new(capacity_blocks: u64, block_len: u32) -> Self {
        Self {
            capacity_blocks,
            block_len,
            write_mode: Writability::Writable,
            write_protected: false,
            needs_recovery: false,
            removable: false,
        }
    }

    /// Mark the LUN's medium as removable (INQUIRY RMB).
    ///
    /// This is a slot property, so it stays set across a medium swap. The
    /// application installs the replacement pair and raises
    /// [`UaClass::MediumChanged`](crate::core::UaClass::MediumChanged); the
    /// core does not raise it on install.
    #[must_use]
    pub const fn with_removable(mut self) -> Self {
        self.removable = true;
        self
    }

    /// Whether the static/latched write policy rejects a write before the
    /// backing is touched (`needs_recovery` is checked in `prepare`).
    #[doc(hidden)]
    #[must_use]
    pub const fn rejects_writes(&self) -> bool {
        matches!(self.write_mode, Writability::ReadOnly) || self.write_protected
    }

    /// Byte capacity, saturating on absurd geometry.
    #[must_use]
    pub const fn capacity_bytes(&self) -> u64 {
        self.capacity_blocks.saturating_mul(self.block_len as u64)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn writable_by_default() {
        let attrs = BlockAttrs::new(16, 512);
        assert_eq!(attrs.capacity_blocks, 16);
        assert_eq!(attrs.block_len, 512);
        assert_eq!(attrs.write_mode, Writability::Writable);
        assert!(!attrs.write_protected);
        assert!(!attrs.needs_recovery);
        assert!(!attrs.removable, "a block LUN is fixed by default");
        assert!(!attrs.rejects_writes());
        assert_eq!(attrs.capacity_bytes(), 8192);
    }

    #[test]
    fn with_removable_marks_the_slot() {
        let attrs = BlockAttrs::new(16, 512).with_removable();
        assert!(attrs.removable);
        assert_eq!(attrs.capacity_blocks, 16);
        assert_eq!(attrs.block_len, 512);
        assert!(!attrs.rejects_writes());
    }

    #[test]
    fn read_only_or_latched_rejects_writes() {
        let mut attrs = BlockAttrs::new(1, 512);
        attrs.write_mode = Writability::ReadOnly;
        assert!(attrs.rejects_writes());
        attrs.write_mode = Writability::Writable;
        assert!(!attrs.rejects_writes());
        attrs.write_protected = true;
        assert!(attrs.rejects_writes());
    }
}
