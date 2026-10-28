//! MMC medium attributes and descriptive values.
//!
//! `MmcAttrs` carries facts only. The drive reads `block_len`, `sectors`,
//! `write_mode` and `write_protected`; it never dispatches on a media class.

/// Static facts about an MMC medium.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct MmcAttrs {
    /// Static write mode of the medium.
    pub write_mode: MmcWriteMode,
    /// Logical block length in bytes (`2048` for CD data).
    pub block_len: u32,
    /// Addressable logical blocks; `0` means "no medium" (design offset 9).
    pub sectors: u64,
    /// Number of tracks (single-track media report `1`).
    pub tracks: u16,
    /// Number of sessions (single-session media report `1`).
    pub sessions: u16,
    /// Runtime write-protect policy/latch, separate from [`Self::write_mode`].
    pub write_protected: bool,
    /// The medium reports a health failure until it is explicitly reinstalled.
    pub needs_recovery: bool,
}

impl MmcAttrs {
    /// Whether a host write can be accepted at all.
    ///
    /// A read-only, latched or needs-recovery medium is never write accessible;
    /// this is the only place `MmcWriteMode` participates in a decision.
    #[must_use]
    pub const fn write_accessible(&self) -> bool {
        !matches!(self.write_mode, MmcWriteMode::ReadOnly)
            && !self.write_protected
            && !self.needs_recovery
    }
}

/// MMC write mode (design). Core's `Writability` is Block-only.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum MmcWriteMode {
    /// Read-only medium (CD-ROM, DVD-ROM).
    ReadOnly,
    /// Write-once medium (CD-R, DVD-R).
    WriteOnce,
    /// Rewritable medium (CD-RW, DVD-RAM).
    Rewritable,
    /// Blank/unformatted medium.
    Blank,
}

/// Sector interpretation requested by READ CD.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SectorKind {
    /// Let the medium choose data/audio by LBA.
    Auto,
    /// Mode-1 user data (2048 bytes per sector).
    Data2048,
    /// CD-DA audio (2352 bytes per sector).
    Audio2352,
}

/// One track.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Track {
    /// Track number (1-based).
    pub number: u16,
    /// Session the track belongs to.
    pub session: u16,
    /// First LBA of the track.
    pub start_lba: u64,
    /// Number of blocks in the track.
    pub blocks: u64,
    /// Data or audio.
    pub kind: TrackKind,
}

/// Track payload kind.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TrackKind {
    /// Mode-1 data track.
    Data,
    /// CD-DA audio track.
    Audio,
}

/// One session.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Session {
    /// Session number (1-based).
    pub number: u16,
    /// First track in the session.
    pub first_track: u16,
    /// Last track in the session.
    pub last_track: u16,
    /// First LBA of the session.
    pub start_lba: u64,
}

/// Disc-information summary used by READ DISC INFORMATION.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct DiscInfo {
    /// Disc state (MMC-6 Table 367).
    pub status: DiscStatus,
    /// Number of sessions.
    pub sessions: u16,
    /// Last LBA of the last session.
    pub last_session_lba: u64,
    /// Whether the medium accepts random writes.
    pub writable: bool,
}

/// Disc state (MMC-6 Table 367).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DiscStatus {
    /// Empty disc.
    Empty,
    /// Session/track layout incomplete.
    Incomplete,
    /// Finalized disc.
    Finalized,
    /// Any other raw value (truncated to two bits on the wire).
    Other(u8),
}

#[cfg(test)]
mod tests {
    use super::*;

    const fn attrs(mode: MmcWriteMode) -> MmcAttrs {
        MmcAttrs {
            write_mode: mode,
            block_len: 2048,
            sectors: 16,
            tracks: 1,
            sessions: 1,
            write_protected: false,
            needs_recovery: false,
        }
    }

    #[test]
    fn write_accessible_matrix() {
        assert!(!attrs(MmcWriteMode::ReadOnly).write_accessible());
        assert!(attrs(MmcWriteMode::WriteOnce).write_accessible());
        assert!(attrs(MmcWriteMode::Rewritable).write_accessible());
        assert!(attrs(MmcWriteMode::Blank).write_accessible());

        let mut latched = attrs(MmcWriteMode::Rewritable);
        latched.write_protected = true;
        assert!(!latched.write_accessible());

        let mut broken = attrs(MmcWriteMode::Rewritable);
        broken.needs_recovery = true;
        assert!(!broken.write_accessible());
    }

    #[test]
    fn write_mode_is_not_writability() {
        // Blank is not a core `Writability`; only the MMC profile knows it.
        assert_ne!(MmcWriteMode::Blank, MmcWriteMode::ReadOnly);
        assert_eq!(attrs(MmcWriteMode::Blank).sectors, 16);
    }

    #[test]
    fn descriptive_values_are_copyable() {
        let track = Track {
            number: 1,
            session: 1,
            start_lba: 0,
            blocks: 16,
            kind: TrackKind::Data,
        };
        let copy = track;
        assert_eq!(copy, track);
        assert_eq!(track.kind, TrackKind::Data);

        let info = DiscInfo {
            status: DiscStatus::Finalized,
            sessions: 1,
            last_session_lba: 15,
            writable: false,
        };
        assert_eq!(info.status, DiscStatus::Finalized);
        assert_ne!(DiscStatus::Other(2), DiscStatus::Finalized);
    }
}
