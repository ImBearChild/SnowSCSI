//! Medium operation vocabulary.
//!
//! `MmcDrive` decodes a CDB into one `MmcOp`; the medium owns the semantics.
//! `Commit` (SYNCHRONIZE CACHE) and `Close` (CLOSE TRACK SESSION) are
//! deliberately separate: commit persists, close changes the write state.

use super::attrs::SectorKind;

/// One semantic medium operation.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum MmcOp {
    /// Logical block read (READ(10)); block length from `MmcAttrs`.
    Read {
        /// First logical block.
        lba: u64,
        /// Number of blocks.
        blocks: u16,
    },
    /// Logical block write (WRITE(10)).
    Write {
        /// First logical block.
        lba: u64,
        /// Number of blocks.
        blocks: u16,
    },
    /// Non-planar read (READ CD) with an explicit sector interpretation.
    ReadSectors {
        /// First logical block.
        lba: u64,
        /// Number of blocks.
        blocks: u16,
        /// Sector interpretation.
        kind: SectorKind,
    },
    /// Non-planar write; only for media/modes that support it.
    WriteSectors {
        /// First logical block.
        lba: u64,
        /// Number of blocks.
        blocks: u16,
        /// Sector interpretation.
        kind: SectorKind,
    },
    /// READ TOC / READ TRACK INFORMATION semantic entry.
    TrackInfo {
        /// Track number.
        track: u16,
    },
    /// READ DISC INFORMATION semantic entry.
    DiscInfo,
    /// FORMAT UNIT / BLANK zero-fill semantics; a long operation.
    Format {
        /// Number of blocks to format.
        blocks: u64,
    },
    /// CLOSE TRACK SESSION: changes the write state and commits as needed.
    Close,
    /// SYNCHRONIZE CACHE class: persist only; never changes the write state.
    Commit,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn commit_and_close_are_distinct() {
        assert_ne!(MmcOp::Commit, MmcOp::Close);
        assert_eq!(
            MmcOp::ReadSectors {
                lba: 1,
                blocks: 2,
                kind: SectorKind::Auto,
            },
            MmcOp::ReadSectors {
                lba: 1,
                blocks: 2,
                kind: SectorKind::Auto,
            }
        );
        assert_ne!(SectorKind::Data2048, SectorKind::Audio2352);
    }
}
