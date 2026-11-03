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
    /// Current MMC profile of the mounted medium (`0x08` CD-ROM, `0x09` CD-R,
    /// `0x12` DVD-RAM).
    pub profile: u16,
    /// Features that are Current for the mounted medium (feature codes).
    pub current_features: &'static [u16],
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

/// State of one track on a recordable medium.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TrackStatus {
    /// The track is not on the medium yet; its start and next writable
    /// address are still valid for the first write.
    Invisible,
    /// The track is reserved but carries no recorded data yet.
    Reserved,
    /// The track is partially recorded.
    Incomplete,
    /// The track is closed.
    Complete,
}

/// Semantic track description used by READ TRACK INFORMATION.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct TrackInfo {
    /// Track number (1-based).
    pub number: u16,
    /// Session the track belongs to.
    pub session: u16,
    /// First user block of the track (after the pre-gap).
    ///
    /// Signed because the lead-in address and pre-gap addresses are negative.
    pub start_lba: i64,
    /// Recorded length in blocks (padded after a close).
    pub length: u64,
    /// Reserved length in blocks (`0` when not reserved).
    pub allocated: u64,
    /// Next writable address in blocks.
    pub nwa: u64,
    /// Remaining writable blocks in the track.
    pub free_blocks: u64,
    /// Track state.
    pub status: TrackStatus,
    /// Data or audio.
    pub kind: TrackKind,
    /// The track uses fixed-size packets.
    pub packet: bool,
}

/// What a READ TRACK INFORMATION request addresses.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TrackInfoRequest {
    /// The track containing the given logical block.
    Lba(u64),
    /// The track with the given number.
    Number(u16),
    /// The first track of the given session.
    Session(u16),
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
    /// Whether the medium is rewritable (the Erasable bit of READ DISC
    /// INFORMATION); a write-once medium reports `false`.
    pub erasable: bool,
    /// Number of the first track on the disc.
    pub first_track: u16,
    /// First track of the last session.
    pub first_track_last_session: u16,
    /// Last track of the last session.
    pub last_track_last_session: u16,
    /// State of the last session: `0` empty, `1` incomplete, `3` complete.
    pub last_session_state: u8,
    /// Start address of the last session lead-in, or `None` for "not
    /// applicable" (`FF FF FF FF`).
    ///
    /// Signed because a CD lead-in address is negative.
    pub last_session_lead_in: Option<i64>,
    /// Last possible lead-out address, or `None` for "not applicable".
    pub last_possible_lead_out: Option<i64>,
    /// Disc type: `0` for CD-DA/CD-ROM, `0xFF` for unknown.
    pub disc_type: u8,
}

/// ATIP descriptor data served by READ TOC format 4 (MMC-6 Table 488).
///
/// The drive encodes one instance into the 24-byte ATIP descriptor of the
/// 28-byte response; the 4-byte header declares an ATIP Data Length of `26`.
/// Times are **binary** M/S/F bytes (`0..=99`, not BCD), as an ATIP time code
/// is reported.
///
/// Descriptor byte layout (0-based, after the 4-byte header):
///
/// ```text
///  0   bit7 = 1, bits6-4 = indicative target writing power,
///      bit3 = reserved, bits2-0 = reference speed
///  1   bit7 = 0, bit6 = unrestricted use (URU), bits5-0 = reserved
///  2   bit7 = 1, bit6 = disc type (0 = CD-R, 1 = CD-RW),
///      bits5-3 = disc sub-type, bit2 = A1 valid, bit1 = A2 valid,
///      bit0 = A3 valid
///  3   reserved
///  4-6 ATIP start time of the lead-in (M, S, F)
///  7   reserved
///  8-10 ATIP last possible start time of the lead-out (M, S, F)
///  11  reserved
///  12-14 A1 values, 15 reserved
///  16-18 A2 values, 19 reserved
///  20-22 A3 values, 23 reserved
/// ```
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct AtipInfo {
    /// ATIP start time of the lead-in, binary M/S/F.
    pub lead_in: [u8; 3],
    /// ATIP last possible start time of the lead-out, binary M/S/F.
    pub lead_out: [u8; 3],
    /// Indicative target writing power (3 bits).
    pub writing_power: u8,
    /// Reference speed (3 bits).
    pub reference_speed: u8,
    /// The disc is for unrestricted use (the URU bit).
    pub unrestricted: bool,
    /// Disc type: `0` = CD-R, `1` = CD-RW.
    pub disc_type: u8,
    /// Disc sub-type (3 bits); CD-R has no sub-types and reports `0`.
    pub disc_sub_type: u8,
    /// Additional Information 1, valid when the A1 Valid bit is set.
    pub a1: Option<[u8; 3]>,
    /// Additional Information 2, valid when the A2 Valid bit is set.
    pub a2: Option<[u8; 3]>,
    /// Additional Information 3, valid when the A3 Valid bit is set.
    pub a3: Option<[u8; 3]>,
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
            profile: 0x0008,
            current_features: &[0x0010, 0x001D, 0x001E],
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
            erasable: false,
            first_track: 1,
            first_track_last_session: 1,
            last_track_last_session: 1,
            last_session_state: 3,
            last_session_lead_in: None,
            last_possible_lead_out: None,
            disc_type: 0,
        };
        assert_eq!(info.status, DiscStatus::Finalized);
        assert_ne!(DiscStatus::Other(2), DiscStatus::Finalized);
        assert_eq!(info.first_track, 1);
        assert_eq!(info.last_session_state, 3);
        assert_eq!(info.last_session_lead_in, None);
        assert_eq!(info.disc_type, 0);
    }

    #[test]
    fn track_info_values_are_copyable() {
        let info = TrackInfo {
            number: 2,
            session: 1,
            start_lba: 100,
            length: 20,
            allocated: 32,
            nwa: 120,
            free_blocks: 12,
            status: TrackStatus::Incomplete,
            kind: TrackKind::Data,
            packet: false,
        };
        let copy = info;
        assert_eq!(copy, info);
        assert_eq!(info.status, TrackStatus::Incomplete);
        assert_ne!(TrackStatus::Incomplete, TrackStatus::Complete);
        assert_ne!(TrackStatus::Reserved, TrackStatus::Invisible);
    }

    #[test]
    fn atip_info_values_are_copyable() {
        let atip = AtipInfo {
            lead_in: [97, 34, 23],
            lead_out: [79, 59, 74],
            writing_power: 5,
            reference_speed: 0,
            unrestricted: true,
            disc_type: 0,
            disc_sub_type: 0,
            a1: None,
            a2: Some([1, 2, 3]),
            a3: None,
        };
        let copy = atip;
        assert_eq!(copy, atip);
        assert_eq!(atip.lead_out, [79, 59, 74]);
        assert!(atip.unrestricted);
        assert_ne!(atip.a1, atip.a2);
    }

    #[test]
    fn attrs_carry_the_medium_profile_and_current_features() {
        let attrs = attrs(MmcWriteMode::ReadOnly);
        assert_eq!(attrs.profile, 0x0008);
        assert_eq!(attrs.current_features, &[0x0010, 0x001D, 0x001E]);
    }

    #[test]
    fn track_info_request_addresses_a_track() {
        assert_ne!(TrackInfoRequest::Lba(0), TrackInfoRequest::Number(1));
        assert_eq!(TrackInfoRequest::Session(1), TrackInfoRequest::Session(1));
    }
}
