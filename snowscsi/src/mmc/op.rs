//! Medium operation vocabulary.
//!
//! `MmcDrive` decodes a CDB into one `MmcOp`; the medium owns the semantics.
//! `Commit` (SYNCHRONIZE CACHE) and `Close` (CLOSE TRACK SESSION) are
//! deliberately separate: commit persists, close changes the write state.
//! `ReserveTrack` (RESERVE TRACK) reserves space for a future track and, like
//! `Close`, is the drive's write-state vocabulary rather than a data transfer.

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
    /// CLOSE TRACK SESSION: close function `001b` (track) or `010b` (session)
    /// on CD; changes the write state and commits as needed.
    Close {
        /// Close Function bits from CDB byte 2.
        function: u8,
    },
    /// RESERVE TRACK: reserve `size` logical blocks for the next track.
    ReserveTrack {
        /// Number of logical blocks to reserve.
        size: u32,
    },
    /// SYNCHRONIZE CACHE class: persist only; never changes the write state.
    Commit,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn commit_and_close_are_distinct() {
        assert_ne!(MmcOp::Commit, MmcOp::Close { function: 0 });
        assert_ne!(MmcOp::Close { function: 0 }, MmcOp::Close { function: 1 });
        assert_eq!(
            MmcOp::ReserveTrack { size: 16 },
            MmcOp::ReserveTrack { size: 16 }
        );
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
