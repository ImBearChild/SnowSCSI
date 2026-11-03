//! MMC drive: media-command decoding over an [`MmcMedium`].
//!
//! The drive decodes the media command table, validates CDB fields/reserved
//! bits/allocation length and encodes the media-description responses
//! (READ TOC, READ DISC INFORMATION, READ TRACK INFORMATION).
//!
//! `MmcCaps` is the **LU's** capability (supported profiles, mode page 0x2A,
//! random-writable features) and is independent of the installed medium;
//! `MmcAttrs` is the **disc**. [`MmcDrive::new`] derives caps from the medium
//! class as a compatibility shortcut, while [`MmcDrive::empty`] and
//! [`MmcDrive::new_with_caps`] state them explicitly. Public query commands are
//! served by `Spc` through [`SpcProfile`].
//!
//! Byte layouts are re-implemented from the production baseline:
//! `crate::cdrom::drive::read_toc_cmd` (lines 998–1047),
//! `read_disc_info_cmd`/`build_read_disc_info` (drive.rs 1066–1085,
//! common.rs 1213–1237), `read_track_information_cmd` (drive.rs 1257–1307),
//! `gesn_cmd` (drive.rs 1111–1141) and the mode pages of `common.rs` 106–146,
//! 446, 501. This module has no runtime dependency on `cdrom`.

use super::attrs::{
    DiscInfo, DiscStatus, MmcAttrs, MmcWriteMode, SectorKind, TrackInfo, TrackInfoRequest,
    TrackKind, TrackStatus,
};
use super::medium::MmcMedium;
use super::op::MmcOp;
use crate::core::storage::StorageOp;
use crate::core::{
    storage_fault_sense, BoundaryPermit, Capacity, CommandContext, CommandPermit, Completion,
    DataPlan, Delivery, Device, Direction, Effect, Fault, Feedback, FeedbackKind, InquiryData,
    InterruptReason, IoContext, KnownEffects, LongInfo, LongPhase, PollStep, RemovalEncoding,
    Sense, SpcProfile, COMMAND_ABORTED, FORMAT_IN_PROGRESS, INTERNAL_FAILURE, INVALID_FIELD,
    LBA_OUT_OF_RANGE, MEDIUM_ERROR, MEDIUM_NOT_PRESENT, NEEDS_RECOVERY, WRITE_ERROR,
    WRITE_PROTECTED,
};

/// TEST UNIT READY.
const TEST_UNIT_READY: u8 = 0x00;
/// READ(10).
const READ_10: u8 = 0x28;
/// WRITE(10).
const WRITE_10: u8 = 0x2A;
/// SYNCHRONIZE CACHE(10).
const SYNC_CACHE_10: u8 = 0x35;
/// FORMAT UNIT.
const FORMAT_UNIT: u8 = 0x04;
/// READ TOC/PMA/ATIP.
const READ_TOC: u8 = 0x43;
/// READ DISC INFORMATION.
const READ_DISC_INFORMATION: u8 = 0x51;
/// READ TRACK INFORMATION.
const READ_TRACK_INFORMATION: u8 = 0x52;
/// RESERVE TRACK.
const RESERVE_TRACK: u8 = 0x53;
/// CLOSE TRACK SESSION.
const CLOSE_TRACK_SESSION: u8 = 0x5B;
/// BLANK.
const BLANK: u8 = 0xA1;
/// READ CD.
const READ_CD: u8 = 0xBE;
/// MODE SELECT(6).
const MODE_SELECT_6: u8 = 0x15;
/// SEND OPC INFORMATION.
const SEND_OPC: u8 = 0x54;
/// MODE SELECT(10).
const MODE_SELECT_10: u8 = 0x55;
/// SET CD SPEED.
const SET_CD_SPEED: u8 = 0xBB;

/// READ TOC format 0 for the lead-out track (0xAA).
const TOC_LEADOUT_LEN: usize = 12;
/// READ TOC format 1 (session list): 4-byte header + 8-byte descriptor.
const TOC_SESSION_LEN: usize = 12;
/// One TOC track descriptor.
const TOC_DESCRIPTOR_LEN: usize = 8;
/// One compact raw-TOC (format 2) descriptor:
/// session, ADR/control, TNO, POINT, MIN, SEC, FRAME, zero.
const TOC_RAW_DESCRIPTOR_LEN: usize = 8;
/// Staging bound for a multi-track READ TOC response: 4-byte header, the four
/// format-2 lead-in descriptors, one descriptor per track (the CD track-number
/// space is 1..=99) and the lead-out.
const TOC_MAX_LEN: usize = 4 + TOC_DESCRIPTOR_LEN * (99 + 5);
/// READ DISC INFORMATION standard payload.
const DISC_INFO_LEN: usize = 34;
/// READ TRACK INFORMATION payload.
const TRACK_INFO_LEN: usize = 48;
/// GET CONFIGURATION response: header plus the current feature set. Sized for
/// the worst case (12 profiles + every optional descriptor).
const GET_CONFIG_LEN: usize = 256;

/// CD data block length for the default sector size.
const DATA_SECTOR_LEN: u64 = 2048;
/// CD-DA audio sector length.
const AUDIO_SECTOR_LEN: u64 = 2352;

/// FORMAT UNIT parameter list length for a Multi-Media drive (MMC-6 §6.4.3.1:
/// a 4-byte Format List Header plus the single 8-byte Format Descriptor).
const FORMAT_PARAMS_LEN: usize = 12;
/// Largest zero-fill IO issued by one long-operation step.
const FORMAT_CHUNK_MAX: usize = 1024 * 1024;
/// ILLEGAL REQUEST / INVALID FIELD IN PARAMETER LIST. `core::errors` has no
/// constant for it because only the MMC FORMAT UNIT decoder needs it.
const INVALID_FIELD_IN_PARAMETER_LIST: Sense = Sense::new(0x05, 0x26, 0x00);

/// Facts projected when no medium is installed (`take_medium`).
///
/// GET CONFIGURATION and GESN must answer explicitly instead of delegating:
/// their response for an absent medium is identical to a zero-sector medium.
const NO_MEDIUM_ATTRS: MmcAttrs = MmcAttrs {
    write_mode: MmcWriteMode::ReadOnly,
    block_len: 2048,
    sectors: 0,
    tracks: 0,
    sessions: 0,
    write_protected: false,
    needs_recovery: false,
    profile: 0x0000,
    current_features: &[],
};

/// Drive (LU) capabilities: what this drive supports with **no** medium.
///
/// These are not medium attributes. An empty DVD-RAM drive still lists profile
/// `0x12`, reports the recorder capability page (0x2A) and advertises the
/// random-writable feature. The installed medium only supplies the facts that
/// describe the disc (capacity, write protection, current write mode).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct MmcCaps {
    profiles: &'static [u16],
    capabilities_page: &'static [u8],
    random_writable: bool,
}

impl MmcCaps {
    /// Build a capability set.
    ///
    /// `profiles` is the Profile List (at most 12 entries; the GET
    /// CONFIGURATION response is fixed-size). `capabilities_page` is a complete
    /// mode page 0x2A (`[0x2A, len - 2, payload…]`, at most 64 bytes).
    ///
    /// Malformed values are a programmer error: they panic at construction
    /// rather than corrupting the wire later.
    #[must_use]
    pub const fn new(
        profiles: &'static [u16],
        capabilities_page: &'static [u8],
        random_writable: bool,
    ) -> Self {
        assert!(!profiles.is_empty(), "MmcCaps needs at least one profile");
        assert!(
            profiles.len() <= 12,
            "MmcCaps profile list exceeds the GET CONFIGURATION budget"
        );
        assert!(
            capabilities_page.len() >= 2 && capabilities_page.len() <= 64,
            "MmcCaps 0x2A page must be 2..=64 bytes"
        );
        assert!(
            capabilities_page[0] == 0x2A,
            "MmcCaps page must be mode page 0x2A"
        );
        assert!(
            capabilities_page[1] as usize == capabilities_page.len() - 2,
            "MmcCaps 0x2A page length byte must describe its payload"
        );
        Self {
            profiles,
            capabilities_page,
            random_writable,
        }
    }

    /// Profiles the drive supports, in Profile List order.
    #[must_use]
    pub const fn profiles(&self) -> &'static [u16] {
        self.profiles
    }

    /// The complete mode page 0x2A.
    #[must_use]
    pub const fn capabilities_page(&self) -> &'static [u8] {
        self.capabilities_page
    }

    /// Whether random writing (profile 0x12 and features 0x20/0x24) is part of
    /// the drive's command set.
    #[must_use]
    pub const fn random_writable(&self) -> bool {
        self.random_writable
    }

    /// The **default** LU: a Hyper-Multi optical drive.
    ///
    /// Reads CD/CD-R/CD-RW and DVD-ROM/R/RAM/RW/+R/+RW, writes CD-R/CD-RW and
    /// DVD-R/RAM/RW/+R; this is the drive's capability, independent of the
    /// mounted disc. The medium only drives the Current bits (current profile,
    /// current features, capacity).
    #[must_use]
    pub const fn hyper_multi() -> Self {
        Self::new(&HYPER_MULTI_PROFILES, &CDROM_CAPABILITIES_PAGE, true)
    }

    /// The 36-byte DVD-RAM legacy view (fewer write-speed descriptors) with the
    /// same recorder capability bits. Kept for applications that want the
    /// medium-specific 2Ah variant; the default is [`Self::hyper_multi`].
    #[must_use]
    pub const fn dvdram() -> Self {
        Self::new(&DVDRAM_PROFILES, &DVDRAM_CAPABILITIES_PAGE, true)
    }
}

/// Resident zero-fill state (MMC-internal; only projected through `LongInfo`).
///
/// Only the **foreground** FORMAT/BLANK fill exists. `LongPhase::Background`
/// (DVD+RW background format) is reserved and never produced here.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum LongOp {
    /// No resident operation.
    Idle,
    /// A foreground format/blank is running; the media gate is up.
    Foreground {
        /// Total bytes to zero.
        total: u64,
        /// Bytes confirmed zeroed so far.
        done: u64,
        /// Bytes of the single in-flight write (`0` when none).
        in_flight: u64,
        /// The final durability `Sync` was issued for the completed write set.
        ///
        /// The drive owns these writes and reports completion before the host
        /// can issue SYNCHRONIZE CACHE, so it establishes durability itself
        /// with exactly one `Sync` after the last confirmed chunk
        /// A repeated `Begin` while this is set
        /// must not reissue that sync.
        sync: bool,
    },
    /// Finished; the result is resident until management takes it.
    Settled {
        /// Terminal error, if the operation settled abnormally.
        error: Option<Fault>,
        /// Real progress at settle time: `Some(100)` only on success.
        progress: Option<u32>,
    },
}

/// FORMAT UNIT / BLANK command state machine fields.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct FormatCmd {
    /// A 12-byte host parameter list still has to be received.
    params: bool,
    /// The command completed GOOD once validated; the resident long operation
    /// (or the already-settled zero-block case) owns the fill.
    immediate: bool,
}

/// Validated FORMAT UNIT Format List Header facts.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct FormatList {
    /// Try-out: validate feasibility only, never touch the medium.
    try_out: bool,
    /// Immed bit of the Format List Header (MMC-6 Table 240 bit 1).
    immediate: bool,
}

/// `Query` selects the drive-owned part of the command state machine.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Query {
    /// No command.
    None,
    /// An `MmcOp`-backed command in progress.
    Media {
        /// Planned host byte count.
        bytes: u32,
        /// WRITE FUA: issue a post-write SYNC before completing GOOD.
        fua: bool,
        /// A successful completion changed the readable medium (finalize).
        media_change: bool,
        /// The post-write SYNC is in flight.
        syncing: bool,
    },
    /// READ TOC encoded by the drive.
    Toc {
        /// MSF addressing requested.
        msf: bool,
        /// Format field (0 or 1).
        format: u8,
        /// Starting track (0, 1 or 0xAA for format 0).
        track: u8,
    },
    /// READ DISC INFORMATION encoded by the drive.
    DiscInfo,
    /// READ TRACK INFORMATION encoded by the drive.
    TrackInfo {
        /// Decoded address mode and track/session/LBA selector.
        request: TrackInfoRequest,
    },
    /// FORMAT UNIT / BLANK zero-fill state machine.
    Format(FormatCmd),
    /// MODE SELECT receiving its parameter list.
    ModeSelect {
        /// The command was MODE SELECT(10) (8-byte mode header).
        ten: bool,
        /// Planned parameter-list length.
        len: usize,
    },
    /// SEND OPC INFORMATION receiving and discarding its parameter list.
    SendOpc {
        /// Planned parameter-list length.
        len: usize,
    },
}

/// MMC drive over a replaceable medium.
pub struct MmcDrive<M: MmcMedium> {
    medium: Option<M>,
    /// Drive (LU) capabilities. Independent of the installed medium: they
    /// survive an eject and are what an empty drive still reports.
    caps: MmcCaps,
    /// A completed finalize changed the readable extent; report a media
    /// change so the host revalidates the capacity.
    media_changed: bool,
    query: Query,
    /// Bytes selected for a drive-encoded response.
    len: usize,
    /// The data plan for the current encoded response was published.
    published: bool,
    /// Resident zero-fill operation shared by FORMAT UNIT and BLANK.
    long: LongOp,
    /// Required storage operations issued by the medium (probe counter).
    io_issues: u32,
    /// Speculative prefetch operations issued by the medium (probe counter).
    prefetch_issues: u32,
    /// Last SET CD SPEED read speed in kilobytes per second (`0xFFFF` = max).
    read_speed: u16,
    /// Last SET CD SPEED write speed in kilobytes per second (`0xFFFF` = max).
    write_speed: u16,
}

impl<M: MmcMedium> MmcDrive<M> {
    fn with_medium(medium: Option<M>, caps: MmcCaps) -> Self {
        Self {
            medium,
            caps,
            media_changed: false,
            query: Query::None,
            len: 0,
            published: false,
            long: LongOp::Idle,
            io_issues: 0,
            prefetch_issues: 0,
            read_speed: 0,
            write_speed: 0,
        }
    }

    /// Build a **Hyper-Multi** drive with an installed medium.
    ///
    /// The drive is a full multi-format recorder by default; the medium only
    /// supplies the disc facts (capacity, write protection, current profile).
    /// Use [`Self::new_with_caps`] for a deliberately narrower drive.
    #[must_use]
    pub fn new(medium: M) -> Self {
        Self::with_medium(Some(medium), MmcCaps::hyper_multi())
    }

    /// Build a drive with an installed medium and explicit drive capabilities.
    #[must_use]
    pub fn new_with_caps(medium: M, caps: MmcCaps) -> Self {
        Self::with_medium(Some(medium), caps)
    }

    /// Build a drive with an **empty tray** and explicit drive capabilities.
    ///
    /// The capabilities are the LU's, not the medium's: an empty DVD-RAM drive
    /// still lists profile `0x12` and reports the recorder capability page.
    /// Device-level commands stay answerable (INQUIRY through `Spc`, START STOP
    /// UNIT, MODE SENSE, GET CONFIGURATION), while every media command answers
    /// `MEDIUM NOT PRESENT`. The first medium is installed by the slot
    /// (`Target::install_rt`).
    #[must_use]
    pub fn empty(caps: MmcCaps) -> Self {
        Self::with_medium(None, caps)
    }

    /// The drive's capabilities.
    #[must_use]
    pub const fn caps(&self) -> MmcCaps {
        self.caps
    }

    /// Number of required storage operations issued (probe counter, not a
    /// business API).
    #[doc(hidden)]
    #[must_use]
    pub const fn io_issues(&self) -> u32 {
        self.io_issues
    }

    /// Number of speculative prefetch operations issued (probe counter, not a
    /// business API).
    #[doc(hidden)]
    #[must_use]
    pub const fn prefetch_issues(&self) -> u32 {
        self.prefetch_issues
    }

    /// Last requested SET CD SPEED `(read, write)` values in kilobytes per
    /// second (`0xFFFF` selects the drive maximum).
    #[doc(hidden)]
    #[must_use]
    pub const fn cd_speed(&self) -> (u16, u16) {
        (self.read_speed, self.write_speed)
    }

    /// Borrow the installed medium.
    #[must_use]
    pub fn medium(&self) -> Option<&M> {
        self.medium.as_ref()
    }

    /// Mutably borrow the installed medium.
    #[must_use]
    pub fn medium_mut(&mut self) -> Option<&mut M> {
        self.medium.as_mut()
    }

    /// Copy the medium attributes, if a medium is installed.
    fn attrs(&self) -> Option<MmcAttrs> {
        self.medium.as_ref().map(|m| m.attrs())
    }

    /// Decode and validate one CDB (`Ok` leaves a live query).
    fn decode(&mut self, ctx: CommandContext, cdb: &[u8]) -> Result<(), Completion> {
        let opcode = cdb
            .first()
            .copied()
            .ok_or(Completion::Check(INVALID_FIELD))?;
        match opcode {
            TEST_UNIT_READY => self.prepare_tur(ctx, cdb),
            FORMAT_UNIT => self.prepare_format(ctx, cdb),
            BLANK => self.prepare_blank(ctx, cdb),
            READ_10 => self.prepare_transfer(ctx, cdb, false),
            WRITE_10 => self.prepare_transfer(ctx, cdb, true),
            SYNC_CACHE_10 => self.prepare_sync(ctx, cdb),
            READ_TOC => self.prepare_toc(ctx, cdb),
            READ_DISC_INFORMATION => self.prepare_disc_info(ctx, cdb),
            READ_TRACK_INFORMATION => self.prepare_track_info(ctx, cdb),
            RESERVE_TRACK => self.prepare_reserve_track(ctx, cdb),
            READ_CD => self.prepare_read_cd(ctx, cdb),
            CLOSE_TRACK_SESSION => self.prepare_close(ctx, cdb),
            MODE_SELECT_6 => self.prepare_mode_select(ctx, cdb, false),
            MODE_SELECT_10 => self.prepare_mode_select(ctx, cdb, true),
            SEND_OPC => self.prepare_send_opc(ctx, cdb),
            SET_CD_SPEED => self.prepare_set_cd_speed(ctx, cdb),
            _ => Err(Completion::Check(INVALID_FIELD)),
        }
    }

    /// READ(10)/WRITE(10) shared decode.
    fn prepare_transfer(
        &mut self,
        ctx: CommandContext,
        cdb: &[u8],
        write: bool,
    ) -> Result<(), Completion> {
        if cdb.len() < 10 {
            return Err(Completion::Check(INVALID_FIELD));
        }
        // READ(10)/WRITE(10) SBC-3 Table 56/97: RDPROTECT/WRPROTECT (bits
        // 7-5), DPO (bit 4) and the reserved low bits are rejected; FUA (bit
        // 3) is accepted. A READ FUA adds no IO (no device cache); a WRITE FUA
        // is honoured by a post-write Sync before GOOD.
        if cdb[1] & 0xF7 != 0 {
            return Err(Completion::Check(INVALID_FIELD));
        }
        let fua = cdb[1] & 0x08 != 0;
        // Byte 6 is reserved in both CDBs.
        if cdb[6] != 0 {
            return Err(Completion::Check(INVALID_FIELD));
        }
        check_direction(
            ctx,
            if write {
                Direction::FromHost
            } else {
                Direction::ToHost
            },
        )?;
        let lba = u64::from(be32(&cdb[2..6]));
        let blocks = be16(&cdb[7..9]);
        let attrs = self.attrs().ok_or(Completion::Check(MEDIUM_NOT_PRESENT))?;
        if attrs.sectors == 0 {
            return Err(Completion::Check(MEDIUM_NOT_PRESENT));
        }
        // Write protection precedes the transfer length (baseline ordering):
        // even a zero-block WRITE is rejected on read-only media.
        if write && !attrs.write_accessible() {
            return Err(Completion::Check(WRITE_PROTECTED));
        }
        if blocks == 0 {
            // A zero-block command declares no data phase.
            if matches!(ctx.declared_host_bytes(), Some(declared) if declared != 0) {
                return Err(Completion::Check(INVALID_FIELD));
            }
            return Err(Completion::Good);
        }
        if attrs.block_len == 0 {
            return Err(Completion::Check(INVALID_FIELD));
        }
        check_range(lba, u64::from(blocks), attrs.sectors)?;
        let bytes = u64::from(blocks) * u64::from(attrs.block_len);
        if bytes > u64::from(u32::MAX) {
            return Err(Completion::Check(INVALID_FIELD));
        }
        let op = if write {
            MmcOp::Write { lba, blocks }
        } else {
            MmcOp::Read { lba, blocks }
        };
        self.begin_media_fua(op, bytes as u32, write && fua)
    }

    /// SYNCHRONIZE CACHE(10): IMMED is rejected; SYNC_NV is accepted.
    fn prepare_sync(&mut self, ctx: CommandContext, cdb: &[u8]) -> Result<(), Completion> {
        if cdb.len() < 10 {
            return Err(Completion::Check(INVALID_FIELD));
        }
        // SBC-3 Table 105: bit 2 = SYNC_NV (accepted/ignored), bit 1 = IMMED
        // (unsupported), the rest reserved.
        if cdb[1] & 0xFB != 0 {
            return Err(Completion::Check(INVALID_FIELD));
        }
        if cdb[6] != 0 {
            return Err(Completion::Check(INVALID_FIELD));
        }
        check_direction(ctx, Direction::None)?;
        let attrs = self.attrs().ok_or(Completion::Check(MEDIUM_NOT_PRESENT))?;
        if attrs.sectors == 0 {
            return Err(Completion::Check(MEDIUM_NOT_PRESENT));
        }
        let lba = u64::from(be32(&cdb[2..6]));
        let blocks = be16(&cdb[7..9]);
        if lba > attrs.sectors {
            return Err(Completion::Check(LBA_OUT_OF_RANGE));
        }
        if blocks != 0 {
            check_range(lba, u64::from(blocks), attrs.sectors)?;
        }
        self.begin_media(MmcOp::Commit, 0)
    }

    /// READ TOC/PMA/ATIP: formats 0, 1 and 2, LBA or MSF (design offset 2).
    fn prepare_toc(&mut self, ctx: CommandContext, cdb: &[u8]) -> Result<(), Completion> {
        if cdb.len() < 10 {
            return Err(Completion::Check(INVALID_FIELD));
        }
        check_direction(ctx, Direction::ToHost)?;
        // MMC-6 Table 478: byte 1 bit 1 = MSF, the other bits are reserved;
        // byte 2 bits 7-4 are reserved; bytes 3-5 are reserved.
        if cdb[1] & 0xFD != 0 || cdb[2] & 0xF0 != 0 || cdb[3..6] != [0, 0, 0] {
            return Err(Completion::Check(INVALID_FIELD));
        }
        let msf = cdb[1] & 0x02 != 0;
        let format = cdb[2] & 0x0F;
        // Format 4 (ATIP) is not served yet: an unsupported format is
        // ILLEGAL REQUEST / INVALID FIELD IN CDB (`24/00`).
        if format > 2 {
            return Err(Completion::Check(INVALID_FIELD));
        }
        let track = cdb[6];
        let attrs = self.attrs().ok_or(Completion::Check(MEDIUM_NOT_PRESENT))?;
        if attrs.sectors == 0 {
            return Err(Completion::Check(MEDIUM_NOT_PRESENT));
        }
        let total = if format == 0 {
            // A track selector above the last recorded track addresses no
            // existing descriptor; 0xAA selects only the lead-out.
            if track != 0 && track != 0xAA && u16::from(track) > attrs.tracks.min(99) {
                return Err(Completion::Check(INVALID_FIELD));
            }
            // Track AAh describes the lead-out of the last complete session;
            // a blank disc or an open last session has none (Table 474).
            if self
                .medium
                .as_ref()
                .is_some_and(|m| m.disc_info().last_session_state != 3)
            {
                return Err(Completion::Check(INVALID_FIELD));
            }
            if track == 0xAA {
                TOC_LEADOUT_LEN
            } else {
                let first = if track == 0 { 1 } else { u16::from(track) };
                let last = attrs.tracks.min(99);
                let descriptors = last.saturating_sub(first).saturating_add(1);
                4 + TOC_DESCRIPTOR_LEN * (descriptors as usize + 1)
            }
        } else if format == 2 {
            // Raw TOC: byte 6 is a session number in MMC-6. The design only
            // serves the complete disc, so no session selector is accepted.
            if track != 0 {
                return Err(Completion::Check(INVALID_FIELD));
            }
            // A blank disc or an open last session has no recorded TOC.
            let Some(info) = self.medium.as_ref().map(|m| m.disc_info()) else {
                return Err(Completion::Check(MEDIUM_NOT_PRESENT));
            };
            if info.last_session_state != 3 {
                return Err(Completion::Check(INVALID_FIELD));
            }
            let first = info.first_track.max(1);
            let last = attrs.tracks.min(99);
            let descriptors = 4 + usize::from(last.saturating_sub(first).saturating_add(1)) + 1;
            4 + TOC_RAW_DESCRIPTOR_LEN * descriptors
        } else {
            // Format 1 returns the last complete session only.
            if track != 0 {
                return Err(Completion::Check(INVALID_FIELD));
            }
            TOC_SESSION_LEN
        };
        let alloc = usize::from(be16(&cdb[7..9]));
        self.len = total.min(alloc);
        self.query = Query::Toc { msf, format, track };
        Ok(())
    }

    /// READ DISC INFORMATION: data type 0 only.
    fn prepare_disc_info(&mut self, ctx: CommandContext, cdb: &[u8]) -> Result<(), Completion> {
        if cdb.len() < 10 {
            return Err(Completion::Check(INVALID_FIELD));
        }
        // MMC-6 Table 366: byte 1 bits 7-3 reserved, bits 2-0 data type 0;
        // bytes 2-6 are reserved.
        if cdb[1] & 0xF8 != 0 || cdb[2..7] != [0; 5] {
            return Err(Completion::Check(INVALID_FIELD));
        }
        check_direction(ctx, Direction::ToHost)?;
        let attrs = self.attrs().ok_or(Completion::Check(MEDIUM_NOT_PRESENT))?;
        if attrs.sectors == 0 {
            return Err(Completion::Check(MEDIUM_NOT_PRESENT));
        }
        let alloc = usize::from(be16(&cdb[7..9]));
        self.len = DISC_INFO_LEN.min(alloc);
        self.query = Query::DiscInfo;
        Ok(())
    }

    /// READ TRACK INFORMATION: MMC-6 Table 493 (Open bit 3, type bits 2-0,
    /// number in bytes 2-5, byte 6 reserved).
    fn prepare_track_info(&mut self, ctx: CommandContext, cdb: &[u8]) -> Result<(), Completion> {
        if cdb.len() < 10 {
            return Err(Completion::Check(INVALID_FIELD));
        }
        let ty = cdb[1] & 0x07;
        if ty > 2 || cdb[1] & 0xF8 != 0 || cdb[6] != 0 {
            return Err(Completion::Check(INVALID_FIELD));
        }
        check_direction(ctx, Direction::ToHost)?;
        let attrs = self.attrs().ok_or(Completion::Check(MEDIUM_NOT_PRESENT))?;
        if attrs.sectors == 0 {
            return Err(Completion::Check(MEDIUM_NOT_PRESENT));
        }
        let number = be32(&cdb[2..6]);
        let request = match ty {
            0 => TrackInfoRequest::Lba(u64::from(number)),
            1 => TrackInfoRequest::Number(
                u16::try_from(number).map_err(|_| Completion::Check(INVALID_FIELD))?,
            ),
            _ => TrackInfoRequest::Session(
                u16::try_from(number).map_err(|_| Completion::Check(INVALID_FIELD))?,
            ),
        };
        let alloc = usize::from(be16(&cdb[7..9]));
        self.len = TRACK_INFO_LEN.min(alloc);
        self.query = Query::TrackInfo { request };
        Ok(())
    }

    /// RESERVE TRACK: byte 1 bit 0 = ARSV, bytes 2-4 and 9 reserved, bytes
    /// 5-8 = reservation size when ARSV is zero.
    ///
    /// The medium owns the capacity and open-track checks. ARSV=1 is not
    /// served; only an unconditional reservation is accepted.
    fn prepare_reserve_track(&mut self, ctx: CommandContext, cdb: &[u8]) -> Result<(), Completion> {
        if cdb.len() < 10 {
            return Err(Completion::Check(INVALID_FIELD));
        }
        if cdb[1] & 0xFE != 0 || cdb[2..5] != [0, 0, 0] || cdb[9] != 0 {
            return Err(Completion::Check(INVALID_FIELD));
        }
        check_direction(ctx, Direction::None)?;
        if matches!(ctx.declared_host_bytes(), Some(declared) if declared != 0) {
            return Err(Completion::Check(INVALID_FIELD));
        }
        if cdb[1] & 0x01 != 0 {
            // Only an unconditional reservation is served.
            return Err(Completion::Check(INVALID_FIELD));
        }
        let attrs = self.attrs().ok_or(Completion::Check(MEDIUM_NOT_PRESENT))?;
        if attrs.sectors == 0 {
            return Err(Completion::Check(MEDIUM_NOT_PRESENT));
        }
        let size = be32(&cdb[5..9]);
        self.begin_media(MmcOp::ReserveTrack { size }, 0)
    }

    /// READ CD: MMC-6 Table 351/354. Expected Sector Type is CDB byte 1
    /// bits 4-2; byte 9 is the Main Channel Selection and byte 10 the
    /// sub-channel selection.
    fn prepare_read_cd(&mut self, ctx: CommandContext, cdb: &[u8]) -> Result<(), Completion> {
        if cdb.len() < 12 {
            return Err(Completion::Check(INVALID_FIELD));
        }
        check_direction(ctx, Direction::ToHost)?;
        // DAP and the obsolete bit are unsupported; the rest of byte 1 is the
        // expected sector type.
        if cdb[1] & 0x03 != 0 {
            return Err(Completion::Check(INVALID_FIELD));
        }
        let expected = (cdb[1] >> 2) & 0x07;
        let main = cdb[9];
        // Only user data (bit 4) is served; sync/header/subheader/EDC/ECC
        // would change the payload layout. Audio uses the same user-data
        // selection; sub-channel data is never requested.
        if main != 0x10 || cdb[10] != 0 {
            return Err(Completion::Check(INVALID_FIELD));
        }
        let kind = match expected {
            0 | 2 => SectorKind::Data2048, // All types / Mode 1
            1 => SectorKind::Audio2352,    // CD-DA
            _ => return Err(Completion::Check(INVALID_FIELD)),
        };
        let lba = u64::from(be32(&cdb[2..6]));
        let blocks = be24(&cdb[6..9]);
        let blocks = u16::try_from(blocks).map_err(|_| Completion::Check(INVALID_FIELD))?;
        let attrs = self.attrs().ok_or(Completion::Check(MEDIUM_NOT_PRESENT))?;
        if attrs.sectors == 0 {
            return Err(Completion::Check(MEDIUM_NOT_PRESENT));
        }
        if blocks == 0 {
            if matches!(ctx.declared_host_bytes(), Some(declared) if declared != 0) {
                return Err(Completion::Check(INVALID_FIELD));
            }
            return Err(Completion::Good);
        }
        check_range(lba, u64::from(blocks), attrs.sectors)?;
        let sector_len = match kind {
            SectorKind::Audio2352 => AUDIO_SECTOR_LEN,
            SectorKind::Auto | SectorKind::Data2048 => DATA_SECTOR_LEN,
        };
        let bytes = u64::from(blocks) * sector_len;
        if bytes > u64::from(u32::MAX) {
            return Err(Completion::Check(INVALID_FIELD));
        }
        self.begin_media(MmcOp::ReadSectors { lba, blocks, kind }, bytes as u32)
    }

    /// CLOSE TRACK SESSION: MMC-6 Table 234 (byte 1 bit 0 = Immed, byte 2
    /// bits 2-0 = close function, bytes 4-5 = logical track number).
    ///
    /// CD-R/-RW accepts close function 001b (track) and 010b (session);
    /// 000b and 011b..111b are reserved. The transition belongs to the medium,
    /// which reports a no-op success with `Err(Completion::Good)`.
    fn prepare_close(&mut self, ctx: CommandContext, cdb: &[u8]) -> Result<(), Completion> {
        if cdb.len() < 10 {
            return Err(Completion::Check(INVALID_FIELD));
        }
        if cdb[1] & 0xFE != 0 || cdb[2] & 0xF8 != 0 || cdb[3] != 0 || cdb[6..10] != [0; 4] {
            return Err(Completion::Check(INVALID_FIELD));
        }
        check_direction(ctx, Direction::None)?;
        let attrs = self.attrs().ok_or(Completion::Check(MEDIUM_NOT_PRESENT))?;
        if attrs.sectors == 0 {
            return Err(Completion::Check(MEDIUM_NOT_PRESENT));
        }
        let function = cdb[2] & 0x07;
        let track = be16(&cdb[4..6]);
        match function {
            // The invisible track (last + 1) and the open track are both
            // addressable; 0 selects the default track.
            1 => {
                if track != 0 && track != 0xFF && track > attrs.tracks.saturating_add(1) {
                    return Err(Completion::Check(INVALID_FIELD));
                }
            }
            // Closing the session/finalizing addresses no track.
            2 => {
                if track != 0 {
                    return Err(Completion::Check(INVALID_FIELD));
                }
            }
            _ => return Err(Completion::Check(INVALID_FIELD)),
        }
        self.begin_media(MmcOp::Close { function }, 0)?;
        // A finalized disc has a new readable extent; ask the host to
        // revalidate the capacity on the next command.
        if function == 2 {
            if let Query::Media { media_change, .. } = &mut self.query {
                *media_change = true;
            }
        }
        Ok(())
    }

    /// MODE SELECT(6)/MODE SELECT(10): page-list validation only.
    ///
    /// A recorder host learns the write parameters through MODE SENSE page
    /// 0x05, changes Write Type/Track Mode/Data Block Type and sends the whole
    /// list back. Only a page list (PF=1) without save (SP=0) is accepted; the
    /// parameter list is staged in the caller's bank and validated when the
    /// data phase completes.
    fn prepare_mode_select(
        &mut self,
        ctx: CommandContext,
        cdb: &[u8],
        ten: bool,
    ) -> Result<(), Completion> {
        let need = if ten { 10 } else { 6 };
        if cdb.len() < need {
            return Err(Completion::Check(INVALID_FIELD));
        }
        // SPC-3 Tables 94/96: PF is byte 1 bit 4, SP is bit 0, the rest of
        // byte 1 is reserved. Page lists only: PF=1 and SP=0.
        if cdb[1] != 0x10 {
            return Err(Completion::Check(INVALID_FIELD));
        }
        let len = if ten {
            usize::from(be16(&cdb[7..9]))
        } else {
            usize::from(cdb[4])
        };
        if ctx.host_direction != Direction::FromHost {
            return Err(Completion::Check(INVALID_FIELD));
        }
        if matches!(ctx.declared_host_bytes(), Some(declared) if declared != len as u64) {
            return Err(Completion::Check(INVALID_FIELD));
        }
        if len == 0 {
            // SPC-3 6.7: an empty parameter list is a no-op, not an error.
            return Err(Completion::Good);
        }
        self.len = len;
        self.query = Query::ModeSelect { ten, len };
        Ok(())
    }

    /// SEND OPC INFORMATION: a DoOpc request or an 8-byte-granular OPC table.
    ///
    /// The table is consumed and discarded (the recorder does not calibrate
    /// here); its length must be a multiple of eight and a zero length is a
    /// valid no-op.
    fn prepare_send_opc(&mut self, ctx: CommandContext, cdb: &[u8]) -> Result<(), Completion> {
        if cdb.len() < 10 {
            return Err(Completion::Check(INVALID_FIELD));
        }
        // Table 612: only DoOpc (byte 1 bit 0) and Exclude0/1 (byte 2 bits
        // 1-0) are defined; bytes 3-6 are reserved.
        if cdb[1] & 0xFE != 0 || cdb[2] & 0xFC != 0 || cdb[3..7] != [0; 4] {
            return Err(Completion::Check(INVALID_FIELD));
        }
        check_direction(ctx, Direction::FromHost)?;
        let len = usize::from(be16(&cdb[7..9]));
        // Table 614: every table entry is eight bytes.
        if len % 8 != 0 {
            return Err(Completion::Check(INVALID_FIELD));
        }
        if matches!(ctx.declared_host_bytes(), Some(declared) if declared != len as u64) {
            return Err(Completion::Check(INVALID_FIELD));
        }
        if len == 0 {
            return Err(Completion::Good);
        }
        self.len = len;
        self.query = Query::SendOpc { len };
        Ok(())
    }

    /// SET CD SPEED: record the requested read/write speeds.
    ///
    /// The drive has no physical spindle to retune, so it accepts the request
    /// and remembers the values (0xFFFF means "drive maximum").
    fn prepare_set_cd_speed(&mut self, ctx: CommandContext, cdb: &[u8]) -> Result<(), Completion> {
        if cdb.len() < 12 {
            return Err(Completion::Check(INVALID_FIELD));
        }
        check_direction(ctx, Direction::None)?;
        if matches!(ctx.declared_host_bytes(), Some(declared) if declared != 0) {
            return Err(Completion::Check(INVALID_FIELD));
        }
        self.read_speed = be16(&cdb[2..4]);
        self.write_speed = be16(&cdb[4..6]);
        Err(Completion::Good)
    }

    /// TEST UNIT READY: presence first, then the medium health latch.
    fn prepare_tur(&mut self, ctx: CommandContext, cdb: &[u8]) -> Result<(), Completion> {
        if cdb.len() < 6 {
            return Err(Completion::Check(INVALID_FIELD));
        }
        check_direction(ctx, Direction::None)?;
        let attrs = self.attrs().ok_or(Completion::Check(MEDIUM_NOT_PRESENT))?;
        if attrs.sectors == 0 {
            // Log offset 9: a zero-sector medium is "no media".
            return Err(Completion::Check(MEDIUM_NOT_PRESENT));
        }
        if attrs.needs_recovery {
            return Err(Completion::Check(NEEDS_RECOVERY));
        }
        // TUR has no data phase; the fixed GOOD is delivered by the runner.
        Err(Completion::Good)
    }

    /// FORMAT UNIT: default (`byte 1 = 0`) or FmtData/format-code-1 list.
    ///
    /// MMC-6 Table 237 has no Immed bit in the CDB (bit 0 is part of the Format
    /// Code); both Try-out and Immed live in the Format List Header (Table 240).
    /// The default encoding is an IMMED=0 extension for the design subset.
    fn prepare_format(&mut self, ctx: CommandContext, cdb: &[u8]) -> Result<(), Completion> {
        if cdb.len() < 6 {
            return Err(Completion::Check(INVALID_FIELD));
        }
        let byte1 = cdb[1];
        let fmt_data = byte1 & 0x10 != 0 && byte1 & 0x07 == 0x01;
        if byte1 != 0 && !fmt_data {
            return Err(Completion::Check(INVALID_FIELD));
        }
        if fmt_data {
            // The transport declares the 12-byte parameter list as its Data-Out
            // phase; a declared bound must match it exactly, while a transport
            // that declares no bound leaves the length to its own publish gate.
            if ctx.host_direction != Direction::FromHost
                || matches!(ctx.declared_host_bytes(),
                    Some(declared) if declared != FORMAT_PARAMS_LEN as u64)
            {
                return Err(Completion::Check(INVALID_FIELD));
            }
        } else if ctx.host_direction != Direction::None
            || matches!(ctx.declared_host_bytes(), Some(declared) if declared != 0)
        {
            return Err(Completion::Check(INVALID_FIELD));
        }
        let attrs = self.attrs().ok_or(Completion::Check(MEDIUM_NOT_PRESENT))?;
        if !attrs.write_accessible() {
            return Err(Completion::Check(WRITE_PROTECTED));
        }
        // FORMAT UNIT is only meaningful on writable media; a write-once
        // medium (CD-R) must never be zero-filled by a stray FORMAT/BLANK.
        // Unformatted (`Blank`) media stay eligible.
        if matches!(
            attrs.write_mode,
            MmcWriteMode::ReadOnly | MmcWriteMode::WriteOnce
        ) {
            return Err(Completion::Check(INVALID_FIELD));
        }
        self.arm_zero_fill(attrs.sectors, attrs.block_len)?;
        self.query = Query::Format(FormatCmd {
            params: fmt_data,
            immediate: false,
        });
        Ok(())
    }

    /// BLANK: only blanking type 0 (zero-fill), IMMED from CDB byte 1 bit 5.
    fn prepare_blank(&mut self, ctx: CommandContext, cdb: &[u8]) -> Result<(), Completion> {
        if cdb.len() < 6 {
            return Err(Completion::Check(INVALID_FIELD));
        }
        // MMC-6 Table 229: byte 1 bit 5 = Immed, bits 2-0 = Blanking Type.
        if cdb[1] & 0x07 != 0 {
            return Err(Completion::Check(INVALID_FIELD));
        }
        check_direction(ctx, Direction::None)?;
        if matches!(ctx.declared_host_bytes(), Some(declared) if declared != 0) {
            return Err(Completion::Check(INVALID_FIELD));
        }
        let attrs = self.attrs().ok_or(Completion::Check(MEDIUM_NOT_PRESENT))?;
        if !attrs.write_accessible() {
            return Err(Completion::Check(WRITE_PROTECTED));
        }
        // Only a writable medium can be blanked; a write-once CD-R has no
        // blanking semantics and must not be zero-filled.
        if matches!(
            attrs.write_mode,
            MmcWriteMode::ReadOnly | MmcWriteMode::WriteOnce
        ) {
            return Err(Completion::Check(INVALID_FIELD));
        }
        self.arm_zero_fill(attrs.sectors, attrs.block_len)?;
        self.query = Query::Format(FormatCmd {
            params: false,
            immediate: cdb[1] & 0x20 != 0,
        });
        Ok(())
    }

    /// Arm the resident whole-medium zero-fill from the medium geometry.
    fn arm_zero_fill(&mut self, blocks: u64, block_len: u32) -> Result<(), Completion> {
        let bytes = blocks
            .checked_mul(u64::from(block_len))
            .ok_or(Completion::Check(INVALID_FIELD))?;
        self.long = if bytes == 0 {
            LongOp::Settled {
                error: None,
                progress: Some(100),
            }
        } else {
            LongOp::Foreground {
                total: bytes,
                done: 0,
                in_flight: 0,
                sync: false,
            }
        };
        Ok(())
    }

    /// One step of the drive-owned zero-fill. The medium supplies geometry, but
    /// the fill is issued directly as `StorageOp::Write` on resource 0 at byte
    /// offset `done`, so no `MmcOp::Format` reaches the medium. Only one IO is
    /// in flight at a time; a repeated `Begin` while an operation is in flight
    /// does not reissue it (only the matching `IoDone` advances).
    ///
    /// After the last confirmed chunk the drive issues exactly one
    /// `StorageOp::Sync { resource: 0 }` before settling GOOD: it owns those
    /// writes and reports completion before the host's SYNCHRONIZE CACHE can
    /// run, so durability is established here.
    fn fill_step<'a>(&mut self, fb: Feedback, data: &'a mut [u8]) -> PollStep<'a> {
        let LongOp::Foreground {
            total,
            done,
            in_flight,
            sync,
        } = self.long
        else {
            return PollStep::Idle;
        };
        let mut done = done;
        let mut in_flight = in_flight;
        match fb.kind() {
            FeedbackKind::IoDone => {
                let Some(receipt) = fb.io() else {
                    self.long = LongOp::Settled {
                        error: Some(Fault::Contract),
                        progress: failure_progress(done, total),
                    };
                    return PollStep::Complete(Completion::Check(INTERNAL_FAILURE));
                };
                if sync && in_flight == 0 {
                    // Final durability sync receipt. Success needs a known,
                    // error-free, zero-confirmed sync; anything else settles
                    // abnormally but never revokes an already-sent GOOD.
                    let fault = receipt.error().or_else(|| {
                        (receipt.effect() != Effect::Known || receipt.confirmed() != 0)
                            .then_some(Fault::Io)
                    });
                    return match fault {
                        None => {
                            self.long = LongOp::Settled {
                                error: None,
                                progress: Some(100),
                            };
                            PollStep::Complete(Completion::Good)
                        }
                        Some(fault) => {
                            self.long = LongOp::Settled {
                                error: Some(fault),
                                progress: failure_progress(done, total),
                            };
                            PollStep::Complete(Completion::Check(
                                storage_fault_sense(fault, IoContext::Format)
                                    .unwrap_or(MEDIUM_ERROR),
                            ))
                        }
                    };
                }
                if let Some(fault) = receipt.error() {
                    self.long = LongOp::Settled {
                        error: Some(fault),
                        progress: failure_progress(done, total),
                    };
                    return PollStep::Complete(Completion::Check(
                        storage_fault_sense(fault, IoContext::Format).unwrap_or(MEDIUM_ERROR),
                    ));
                }
                if in_flight == 0 || receipt.confirmed() as u64 != in_flight {
                    // A short write leaves an unknown tail; do not replay it.
                    self.long = LongOp::Settled {
                        error: Some(Fault::Io),
                        progress: failure_progress(done, total),
                    };
                    return PollStep::Complete(Completion::Check(MEDIUM_ERROR));
                }
                done += in_flight;
                in_flight = 0;
                if done == total {
                    // The whole medium is zeroed; establish durability before
                    // the long operation settles.
                    self.long = LongOp::Foreground {
                        total,
                        done,
                        in_flight: 0,
                        sync: true,
                    };
                    return PollStep::Io(StorageOp::Sync { resource: 0 });
                }
                self.long = LongOp::Foreground {
                    total,
                    done,
                    in_flight,
                    sync,
                };
            }
            FeedbackKind::Begin => {
                if in_flight != 0 || sync {
                    // A retried `Begin` must not reissue the in-flight write or
                    // the final sync.
                    return PollStep::Idle;
                }
            }
            // The long operation publishes no plan; ignore other feedback.
            FeedbackKind::PlanAccepted
            | FeedbackKind::HostReceived
            | FeedbackKind::HostSent
            | FeedbackKind::HostSentWithIo
            | FeedbackKind::HostReceivedWithIo => return PollStep::Idle,
        }
        let remaining = total.saturating_sub(done);
        if remaining == 0 {
            // Only reachable when the final sync is no longer in flight, which
            // the `Begin` arm above already handles; keep a defensive settle.
            self.long = LongOp::Settled {
                error: None,
                progress: Some(100),
            };
            return PollStep::Complete(Completion::Good);
        }
        let chunk = remaining
            .min(data.len() as u64)
            .min(FORMAT_CHUNK_MAX as u64) as usize;
        if chunk == 0 {
            self.long = LongOp::Settled {
                error: Some(Fault::Contract),
                progress: failure_progress(done, total),
            };
            return PollStep::Complete(Completion::Check(INTERNAL_FAILURE));
        }
        data[..chunk].fill(0);
        self.long = LongOp::Foreground {
            total,
            done,
            in_flight: chunk as u64,
            sync,
        };
        PollStep::Io(StorageOp::Write {
            resource: 0,
            offset: done,
            buf: &data[..chunk],
        })
    }

    /// Pass a validated operation to the medium and remember its byte count.
    fn begin_media(&mut self, op: MmcOp, bytes: u32) -> Result<(), Completion> {
        self.begin_media_fua(op, bytes, false)
    }

    /// Pass a validated operation to the medium; `fua` adds a post-write Sync.
    fn begin_media_fua(&mut self, op: MmcOp, bytes: u32, fua: bool) -> Result<(), Completion> {
        let Some(medium) = self.medium.as_mut() else {
            return Err(Completion::Check(MEDIUM_NOT_PRESENT));
        };
        medium.begin(op)?;
        self.query = Query::Media {
            bytes,
            fua,
            media_change: false,
            syncing: false,
        };
        Ok(())
    }

    /// Drive-encoded response: publish once, fill on the next step, send.
    fn poll_encoded<'a>(
        &mut self,
        fb: Feedback,
        data: &'a mut [u8],
        fill: impl FnOnce(&mut [u8]) -> bool,
    ) -> PollStep<'a> {
        let len = self.len;
        if len == 0 {
            self.query = Query::None;
            return PollStep::Complete(Completion::Good);
        }
        // The caller's bank is the staging capacity: a response that does not
        // fit is sent short (a legal Data-In underflow the transport reports as
        // residue), never as a CHECK CONDITION.
        let send = len.min(data.len());
        if !self.published {
            self.published = true;
            return PollStep::Publish(DataPlan {
                direction: Direction::ToHost,
                bytes: send as u64,
            });
        }
        if matches!(
            fb.kind(),
            FeedbackKind::HostSent | FeedbackKind::HostSentWithIo
        ) {
            self.query = Query::None;
            return PollStep::Complete(Completion::Good);
        }
        if !fill(&mut data[..send]) {
            self.query = Query::None;
            return PollStep::Complete(Completion::Check(INVALID_FIELD));
        }
        PollStep::Send {
            bytes: &data[..send],
            prefetch: None,
        }
    }

    /// Shared command step; `alt` is the optional second caller bank that a
    /// medium may pre-read the next chunk into.
    fn poll_step<'a>(
        &mut self,
        fb: Feedback,
        data: &'a mut [u8],
        alt: &'a mut [u8],
    ) -> PollStep<'a> {
        match self.query {
            Query::None => PollStep::Idle,
            Query::Media {
                bytes: _,
                fua,
                media_change,
                syncing,
            } => {
                if syncing {
                    if fb.kind() != FeedbackKind::IoDone {
                        return PollStep::Idle;
                    }
                    // Only a known durability result may turn a FUA write into
                    // GOOD; an unknown/failed sync keeps the host's doubt.
                    let known = fb
                        .io()
                        .map(|r| r.error().is_none() && r.effect() == Effect::Known)
                        .unwrap_or(false);
                    self.query = Query::None;
                    return PollStep::Complete(if known {
                        Completion::Good
                    } else {
                        Completion::Check(WRITE_ERROR)
                    });
                }
                let Some(medium) = self.medium.as_mut() else {
                    self.query = Query::None;
                    return PollStep::Complete(Completion::Check(MEDIUM_NOT_PRESENT));
                };
                let step = medium.poll_with_alt(fb, data, alt);
                match &step {
                    PollStep::Io(_) => {
                        self.io_issues = self.io_issues.saturating_add(1);
                    }
                    PollStep::Prefetch(_) => {
                        self.prefetch_issues = self.prefetch_issues.saturating_add(1);
                    }
                    PollStep::Send {
                        prefetch: Some(_), ..
                    } => {
                        self.prefetch_issues = self.prefetch_issues.saturating_add(1);
                    }
                    _ => {}
                }
                match step {
                    PollStep::Complete(Completion::Good) if fua => {
                        self.query = Query::Media {
                            bytes: 0,
                            fua,
                            media_change,
                            syncing: true,
                        };
                        PollStep::Io(StorageOp::Sync { resource: 0 })
                    }
                    PollStep::Complete(completion) => {
                        self.query = Query::None;
                        if completion == Completion::Good && media_change {
                            self.media_changed = true;
                        }
                        PollStep::Complete(completion)
                    }
                    other => other,
                }
            }
            Query::Toc { msf, format, track } => {
                let Some(medium) = self.medium.as_ref() else {
                    self.query = Query::None;
                    return PollStep::Complete(Completion::Check(MEDIUM_NOT_PRESENT));
                };
                let info = medium.disc_info();
                let attrs = medium.attrs();
                let mut buf = [0u8; TOC_MAX_LEN];
                let Some(encoded) =
                    encode_toc(medium, info, attrs.tracks, msf, format, track, &mut buf)
                else {
                    self.query = Query::None;
                    return PollStep::Complete(Completion::Check(INVALID_FIELD));
                };
                self.poll_encoded(fb, data, |out| {
                    let n = encoded.min(out.len());
                    out[..n].copy_from_slice(&buf[..n]);
                    true
                })
            }
            Query::DiscInfo => {
                let Some((info, attrs)) = self.medium.as_ref().map(|m| (m.disc_info(), m.attrs()))
                else {
                    self.query = Query::None;
                    return PollStep::Complete(Completion::Check(MEDIUM_NOT_PRESENT));
                };
                self.poll_encoded(fb, data, |out| {
                    encode_disc_info(info, attrs, out);
                    true
                })
            }
            Query::TrackInfo { request } => {
                let Some(medium) = self.medium.as_ref() else {
                    self.query = Query::None;
                    return PollStep::Complete(Completion::Check(MEDIUM_NOT_PRESENT));
                };
                let found = medium.track_info(request);
                let attrs = medium.attrs();
                let Some(info) = found else {
                    self.query = Query::None;
                    // Table 493: an LBA beyond the last possible lead-out is
                    // LBA OUT OF RANGE; only an invalid track/session number
                    // is an invalid field.
                    let sense = match request {
                        TrackInfoRequest::Lba(_) => LBA_OUT_OF_RANGE,
                        TrackInfoRequest::Number(_) | TrackInfoRequest::Session(_) => INVALID_FIELD,
                    };
                    return PollStep::Complete(Completion::Check(sense));
                };
                let recordable_cdr = attrs.write_mode == MmcWriteMode::WriteOnce;
                self.poll_encoded(fb, data, |out| {
                    encode_track_info(info, recordable_cdr, out);
                    true
                })
            }
            Query::Format(cmd) => {
                if cmd.params {
                    // The 12-byte Format List is staged in the caller's bank.
                    // The documented bank floor makes this guard unreachable
                    // through a transport: it is the target's own inability to
                    // stage its parameter list (HARDWARE ERROR / INTERNAL
                    // TARGET FAILURE), not a bad CDB.
                    if !self.published {
                        if data.len() < FORMAT_PARAMS_LEN {
                            self.query = Query::None;
                            self.long = LongOp::Idle;
                            return PollStep::Complete(Completion::Check(INTERNAL_FAILURE));
                        }
                        self.published = true;
                        return PollStep::Publish(DataPlan {
                            direction: Direction::FromHost,
                            bytes: FORMAT_PARAMS_LEN as u64,
                        });
                    }
                    match fb.kind() {
                        FeedbackKind::PlanAccepted => {
                            if data.len() < FORMAT_PARAMS_LEN {
                                self.query = Query::None;
                                self.long = LongOp::Idle;
                                return PollStep::Complete(Completion::Check(INTERNAL_FAILURE));
                            }
                            PollStep::Receive {
                                buf: &mut data[..FORMAT_PARAMS_LEN],
                                write: None,
                            }
                        }
                        FeedbackKind::HostReceived => {
                            if data.len() < FORMAT_PARAMS_LEN {
                                self.query = Query::None;
                                self.long = LongOp::Idle;
                                return PollStep::Complete(Completion::Check(INTERNAL_FAILURE));
                            }
                            let (accepted, failed) = match fb.host() {
                                Some(receipt) => (receipt.accepted(), receipt.error().is_some()),
                                None => (0, true),
                            };
                            if failed || accepted < FORMAT_PARAMS_LEN {
                                self.query = Query::None;
                                self.long = LongOp::Idle;
                                return PollStep::Complete(Completion::Check(COMMAND_ABORTED));
                            }
                            match validate_format_list(&data[..FORMAT_PARAMS_LEN]) {
                                Err(sense) => {
                                    self.query = Query::None;
                                    // Nothing started: the arm from `prepare`
                                    // is rolled back (Try-out/malformed list
                                    // never change observable state).
                                    self.long = LongOp::Idle;
                                    PollStep::Complete(Completion::Check(sense))
                                }
                                Ok(list) if list.try_out => {
                                    self.query = Query::None;
                                    self.long = LongOp::Idle;
                                    PollStep::Complete(Completion::Good)
                                }
                                Ok(list) if list.immediate => {
                                    self.query = Query::None;
                                    PollStep::Complete(Completion::Good)
                                }
                                Ok(_) => {
                                    self.query = Query::Format(FormatCmd {
                                        params: false,
                                        immediate: false,
                                    });
                                    match self.long {
                                        LongOp::Foreground { .. } => {
                                            let step = self.fill_step(Feedback::begin(), data);
                                            if matches!(step, PollStep::Complete(_)) {
                                                self.query = Query::None;
                                            }
                                            step
                                        }
                                        // A zero-byte fill (zero-sector or
                                        // zero-block-length medium) armed
                                        // `Settled` in `prepare`; complete it
                                        // instead of stalling mid-command.
                                        LongOp::Settled { .. } => {
                                            self.query = Query::None;
                                            PollStep::Complete(Completion::Good)
                                        }
                                        LongOp::Idle => {
                                            self.query = Query::None;
                                            PollStep::Complete(Completion::Check(INTERNAL_FAILURE))
                                        }
                                    }
                                }
                            }
                        }
                        _ => PollStep::Idle,
                    }
                } else if cmd.immediate {
                    self.query = Query::None;
                    PollStep::Complete(Completion::Good)
                } else {
                    match self.long {
                        LongOp::Foreground { .. } => {
                            let step = self.fill_step(fb, data);
                            if matches!(step, PollStep::Complete(_)) {
                                self.query = Query::None;
                            }
                            step
                        }
                        // A zero-block medium is already settled.
                        LongOp::Settled { .. } => {
                            self.query = Query::None;
                            PollStep::Complete(Completion::Good)
                        }
                        LongOp::Idle => {
                            self.query = Query::None;
                            PollStep::Complete(Completion::Check(INTERNAL_FAILURE))
                        }
                    }
                }
            }
            Query::ModeSelect { ten, len } => {
                if !self.published {
                    // The documented bank floor makes this guard unreachable
                    // through a transport: it is the target's own inability to
                    // stage the parameter list.
                    if data.len() < len {
                        self.query = Query::None;
                        return PollStep::Complete(Completion::Check(INTERNAL_FAILURE));
                    }
                    self.published = true;
                    return PollStep::Publish(DataPlan {
                        direction: Direction::FromHost,
                        bytes: len as u64,
                    });
                }
                match fb.kind() {
                    FeedbackKind::PlanAccepted => {
                        if data.len() < len {
                            self.query = Query::None;
                            return PollStep::Complete(Completion::Check(INTERNAL_FAILURE));
                        }
                        PollStep::Receive {
                            buf: &mut data[..len],
                            write: None,
                        }
                    }
                    FeedbackKind::HostReceived => {
                        if data.len() < len {
                            self.query = Query::None;
                            return PollStep::Complete(Completion::Check(INTERNAL_FAILURE));
                        }
                        let (accepted, failed) = match fb.host() {
                            Some(receipt) => (receipt.accepted(), receipt.error().is_some()),
                            None => (0, true),
                        };
                        if failed || accepted < len {
                            // A short Data-Out is not a partial mode select.
                            self.query = Query::None;
                            return PollStep::Complete(Completion::Check(COMMAND_ABORTED));
                        }
                        let validated = validate_mode_select(ten, &data[..len], self.attrs());
                        self.query = Query::None;
                        match validated {
                            Ok(()) => PollStep::Complete(Completion::Good),
                            Err(sense) => PollStep::Complete(Completion::Check(sense)),
                        }
                    }
                    _ => PollStep::Idle,
                }
            }
            Query::SendOpc { len } => {
                if !self.published {
                    if data.len() < len {
                        self.query = Query::None;
                        return PollStep::Complete(Completion::Check(INTERNAL_FAILURE));
                    }
                    self.published = true;
                    return PollStep::Publish(DataPlan {
                        direction: Direction::FromHost,
                        bytes: len as u64,
                    });
                }
                match fb.kind() {
                    FeedbackKind::PlanAccepted => {
                        if data.len() < len {
                            self.query = Query::None;
                            return PollStep::Complete(Completion::Check(INTERNAL_FAILURE));
                        }
                        PollStep::Receive {
                            buf: &mut data[..len],
                            write: None,
                        }
                    }
                    FeedbackKind::HostReceived => {
                        let (accepted, failed) = match fb.host() {
                            Some(receipt) => (receipt.accepted(), receipt.error().is_some()),
                            None => (0, true),
                        };
                        self.query = Query::None;
                        if failed || accepted < len {
                            return PollStep::Complete(Completion::Check(COMMAND_ABORTED));
                        }
                        // The OPC table is accepted and discarded: the medium
                        // owns no calibration state here.
                        PollStep::Complete(Completion::Good)
                    }
                    _ => PollStep::Idle,
                }
            }
        }
    }
}

impl<M: MmcMedium> Device for MmcDrive<M> {
    type Medium = M;

    fn inquiry_data(&self) -> InquiryData {
        InquiryData::cdrom()
    }

    fn removal_encoding(&self) -> RemovalEncoding {
        RemovalEncoding::Mmc
    }

    fn admits_without_medium(&self, cdb: &[u8]) -> bool {
        // MODE SENSE(6/10) describes the drive (pages 0x01/0x0E/0x2A/…); the
        // media-description commands stay NOT READY. 0x1B is admitted globally
        // by the slot gate.
        matches!(cdb.first().copied(), Some(0x1A) | Some(0x5A))
    }

    fn take_media_changed(&mut self) -> bool {
        let changed = self.media_changed;
        self.media_changed = false;
        changed
    }

    fn spc_profile(&self) -> Option<&dyn SpcProfile> {
        Some(self)
    }

    fn prepare(
        &mut self,
        _permit: &CommandPermit,
        ctx: CommandContext,
        cdb: &[u8],
    ) -> Result<(), Completion> {
        // MMC-6 §6.4.4.3 foreground gate: while the zero-fill is Foreground,
        // every opcode that reaches the drive is rejected before the CDB is
        // decoded and before the medium/backing is touched. REQUEST SENSE,
        // INQUIRY, GET CONFIGURATION, GESN and REPORT LUNS are served by `Spc`
        // and never reach this method.
        if matches!(self.long, LongOp::Foreground { .. }) {
            return Err(Completion::Check(FORMAT_IN_PROGRESS));
        }
        if self.query != Query::None {
            return Err(Completion::Busy);
        }
        self.published = false;
        self.len = 0;
        self.decode(ctx, cdb)
    }

    fn active(&self) -> bool {
        self.query != Query::None
    }

    fn resume(&mut self, _permit: &CommandPermit) -> Result<(), Completion> {
        Ok(())
    }

    fn poll<'a>(
        &mut self,
        _permit: &CommandPermit,
        fb: Feedback,
        data: &'a mut [u8],
    ) -> PollStep<'a> {
        self.poll_step(fb, data, &mut [])
    }

    fn poll_with_alt<'a>(
        &mut self,
        _permit: &CommandPermit,
        fb: Feedback,
        data: &'a mut [u8],
        alt: &'a mut [u8],
    ) -> PollStep<'a> {
        self.poll_step(fb, data, alt)
    }

    /// Advance the resident long operation.
    ///
    /// Only the foreground FORMAT/BLANK zero-fill exists; DVD+RW background
    /// format is not implemented (`LongPhase::Background` is reserved).
    fn poll_long<'a>(
        &mut self,
        _permit: &CommandPermit,
        fb: Feedback,
        data: &'a mut [u8],
    ) -> PollStep<'a> {
        // Only a resident (IMMED=1) fill is advanced here; a Settled result is
        // resident until management takes it.
        if matches!(self.long, LongOp::Foreground { .. }) {
            self.fill_step(fb, data)
        } else {
            PollStep::Idle
        }
    }

    fn long_info(&self) -> LongInfo {
        match self.long {
            LongOp::Idle => LongInfo::IDLE,
            LongOp::Foreground {
                total, done, sync, ..
            } => LongInfo {
                phase: LongPhase::Foreground,
                write_accessible: false,
                // 100 is reserved for a successful settle; while the final
                // durability Sync is pending the fill is at 99.
                progress: Some(if sync {
                    99
                } else {
                    format_progress(done, total)
                }),
                error: None,
            },
            LongOp::Settled { error, progress } => LongInfo {
                phase: LongPhase::Settled,
                // The foreground gate is down once the fill settled; a failed
                // settle is carried in `error`, not in this projection.
                write_accessible: true,
                progress,
                error,
            },
        }
    }

    fn interrupt(
        &mut self,
        _permit: &CommandPermit,
        reason: InterruptReason,
        known: KnownEffects,
    ) -> Result<(), Fault> {
        let had_command = self.query != Query::None;
        self.query = Query::None;
        self.published = false;
        self.len = 0;
        if had_command && matches!(self.long, LongOp::Foreground { .. }) {
            // An IMMED=0 fill belongs to the interrupted command. A resident
            // IMMED=1 fill survives because no command is active.
            self.long = LongOp::Idle;
        }
        if let Some(medium) = self.medium.as_mut() {
            medium.interrupt(reason, known);
        }
        Ok(())
    }

    fn finish_delivery(&mut self, _permit: &CommandPermit, _delivery: Delivery) {}

    fn commit(&mut self, _permit: &BoundaryPermit) -> Result<(), Completion> {
        match self.medium.as_mut() {
            Some(medium) => medium.commit(),
            None => Ok(()),
        }
    }

    fn take_medium(&mut self, _permit: &BoundaryPermit) -> Option<M> {
        let medium = self.medium.take();
        if medium.is_some() {
            self.query = Query::None;
            self.long = LongOp::Idle;
        }
        medium
    }

    fn install_medium(&mut self, _permit: &BoundaryPermit, medium: M) -> Result<(), (M, Fault)> {
        if self.medium.is_some() {
            return Err((medium, Fault::Contract));
        }
        // A new medium never inherits the previous medium's long result.
        self.long = LongOp::Idle;
        self.query = Query::None;
        self.medium = Some(medium);
        Ok(())
    }
}

/// Public query profile for the MMC drive.
impl<M: MmcMedium> SpcProfile for MmcDrive<M> {
    fn medium_type(&self) -> u8 {
        0x41
    }

    fn write_protected(&self) -> bool {
        self.medium
            .as_ref()
            .is_some_and(|m| m.attrs().write_protected)
    }

    fn mode_sense(
        &self,
        ten: bool,
        page: u8,
        _dbd: bool,
        pc: u8,
        out: Option<&mut [u8]>,
    ) -> Option<usize> {
        if pc == 3 {
            // Saved pages are unsupported; `Spc` rejects PC=11b before this.
            return None;
        }
        // Every page is drive-level, including 0x2A (the recorder capability
        // page) and 0x05 (defaults when no medium is loaded). Only commands
        // that describe *the mounted disc* are NOT READY.
        let caps = self.caps;
        let attrs = self.attrs();
        let mut pages = [0u8; ALL_PAGES_LEN];
        let plen = if page == 0x3F {
            let mut at = 0usize;
            for code in ALL_PAGE_ORDER {
                let bytes = write_page(code, caps, attrs, &mut pages[at..])?;
                at += bytes;
            }
            at
        } else {
            write_page(page, caps, attrs, &mut pages)?
        };
        if pc == 1 {
            // Changeable mask: keep page code/length, zero the payload.
            let mut at = 0usize;
            while at + 2 <= plen {
                let payload = usize::from(pages[at + 1]);
                let end = (at + 2 + payload).min(plen);
                pages[at + 2..end].fill(0);
                at += 2 + payload;
            }
        }
        let header = if ten { 8 } else { 4 };
        let total = header + plen;
        let mut buf = [0u8; MODE_SENSE_MAX];
        let wp = if self.write_protected() { 0x80 } else { 0x00 };
        if ten {
            buf[..2].copy_from_slice(&((total - 2) as u16).to_be_bytes());
            buf[2] = 0x41;
            buf[3] = wp;
        } else {
            buf[0] = (total - 1) as u8;
            buf[1] = 0x41;
            buf[2] = wp;
        }
        buf[header..total].copy_from_slice(&pages[..plen]);
        if let Some(out) = out {
            // The declared header length always describes `total`, even when
            // the host allocation truncates the response.
            let n = total.min(out.len());
            out[..n].copy_from_slice(&buf[..n]);
        }
        Some(total)
    }

    fn read_capacity(&self) -> Option<Capacity> {
        let attrs = self.attrs()?;
        if attrs.sectors == 0 {
            // Zero sectors is "no medium" (log offset 9), not a one-block
            // geometry; READ CAPACITY must not fabricate LBA 0.
            return None;
        }
        // A blank write-once disc has no recorded session, but its ATIP
        // geometry already fixes the future lead-out; report that extent so
        // the host can size the device before the first session. A blank
        // read-only disc keeps the standard zero-sector view.
        let last = self.medium.as_ref().map_or_else(
            || attrs.sectors.saturating_sub(1),
            |medium| {
                let info = medium.disc_info();
                if info.status == DiscStatus::Empty {
                    if attrs.write_mode == MmcWriteMode::WriteOnce {
                        info.last_possible_lead_out
                            .unwrap_or(0)
                            .max(0)
                            .saturating_sub(1) as u64
                    } else {
                        0
                    }
                } else {
                    info.last_session_lba
                }
            },
        );
        let last = last.min(u64::from(u32::MAX)) as u32;
        Some(Capacity::new(last, attrs.block_len))
    }

    fn get_configuration(
        &self,
        rt: u8,
        start_feature: u16,
        out: Option<&mut [u8]>,
    ) -> Option<usize> {
        if rt == 3 {
            return None;
        }
        // An absent medium answers explicitly with the zero-sector view rather
        // than delegating (`Spc` would turn `None` into an unrelated reject).
        let attrs = self.attrs().unwrap_or(NO_MEDIUM_ATTRS);
        let present = attrs.sectors != 0;
        // MMC-6 Table 87: no current profile while no medium is active. The
        // *supported* profile list is a drive property and always present.
        let current_profile = if present { attrs.profile } else { 0x0000 };
        // A recorder also reads stamped CDs, so 0x08 is Current alongside the
        // mounted recordable profile.
        let read_compatible = present
            && matches!(
                attrs.write_mode,
                MmcWriteMode::WriteOnce | MmcWriteMode::Rewritable
            );
        let feature = |code: u16| present && attrs.current_features.contains(&code);
        // The writable-CD feature descriptors only exist for a drive whose
        // profile list includes a recordable CD profile.
        let recordable_cd_caps = self
            .caps
            .profiles()
            .iter()
            .any(|code| matches!(code, 0x0009 | 0x000A));
        // MMC-6 Table 257: RT=01b returns only descriptors with Current=1;
        // RT=10b returns only the matching descriptor; RT=00b everything at
        // or above the starting feature.
        let include = |code: u16, current: bool| match rt {
            2 => code == start_feature,
            1 => current && code >= start_feature,
            _ => code >= start_feature,
        };
        let mut buf = [0u8; GET_CONFIG_LEN];
        if !fits(0, 8, buf.len()) {
            return None;
        }
        let mut off = 8usize;
        if include(0x0000, true) {
            // Profile List: the drive's supported profiles; the mounted
            // profile and the read-compatible CD-ROM profile are Current.
            let entries = self.caps.profiles();
            let count = entries.len();
            let len = 4 + 4 * count;
            if !fits(off, len, buf.len()) {
                return None;
            }
            buf[off..off + 2].copy_from_slice(&0x0000u16.to_be_bytes());
            buf[off + 2] = 0x03; // version 0, persistent, current
            buf[off + 3] = (4 * count) as u8;
            for (i, code) in entries.iter().enumerate() {
                let at = off + 4 + 4 * i;
                let current = *code == current_profile || (read_compatible && *code == 0x0008);
                buf[at..at + 2].copy_from_slice(&code.to_be_bytes());
                buf[at + 3] = u8::from(current);
            }
            off += len;
        }
        if include(0x0001, true) {
            // Core: version 2, persistent/current, SCSI family.
            if !fits(off, 12, buf.len()) {
                return None;
            }
            buf[off..off + 2].copy_from_slice(&0x0001u16.to_be_bytes());
            buf[off + 2] = 0x0B;
            buf[off + 3] = 0x08;
            buf[off + 4..off + 8].copy_from_slice(&[0, 0, 0, 1]);
            buf[off + 8] = 0x06; // INQ2 | DBE
            off += 12;
        }
        if include(0x0003, true) {
            // Removable Medium.
            if !fits(off, 8, buf.len()) {
                return None;
            }
            buf[off..off + 2].copy_from_slice(&0x0003u16.to_be_bytes());
            buf[off + 2] = 0x0B;
            buf[off + 3] = 0x04;
            buf[off + 4] = 0x39;
            off += 8;
        }
        if include(0x0010, feature(0x0010)) {
            // Random Readable: media-dependent current bit and data. MMC-6
            // §5.2.2.4: with Current=0 the dependent data is reserved (zero).
            if !fits(off, 12, buf.len()) {
                return None;
            }
            let current = feature(0x0010);
            buf[off..off + 2].copy_from_slice(&0x0010u16.to_be_bytes());
            buf[off + 2] = u8::from(current);
            buf[off + 3] = 0x08;
            if current {
                buf[off + 4..off + 8].copy_from_slice(&attrs.block_len.to_be_bytes());
                buf[off + 9] = 0x01; // blocking = 1 (16-bit field)
            }
            off += 12;
        }
        if include(0x001D, feature(0x001D)) {
            // MultiRead (mandatory companion of READ CD).
            if !fits(off, 4, buf.len()) {
                return None;
            }
            let current = feature(0x001D);
            buf[off..off + 2].copy_from_slice(&0x001Du16.to_be_bytes());
            buf[off + 2] = u8::from(current);
            buf[off + 3] = 0x00;
            off += 4;
        }
        if include(0x001E, feature(0x001E)) {
            // CD Read.
            if !fits(off, 8, buf.len()) {
                return None;
            }
            let current = feature(0x001E);
            buf[off..off + 2].copy_from_slice(&0x001Eu16.to_be_bytes());
            buf[off + 2] = if current { 0x09 } else { 0x08 };
            buf[off + 3] = 0x04;
            off += 8;
        }
        if self.caps.random_writable() && include(0x0020, feature(0x0020)) {
            // Random Writable (MMC-6 Table 113): version 1, last LBA,
            // block size, blocking, PP + reserved. Current=0 carries no data.
            if !fits(off, 16, buf.len()) {
                return None;
            }
            let current = feature(0x0020);
            buf[off..off + 2].copy_from_slice(&0x0020u16.to_be_bytes());
            buf[off + 2] = if current { 0x05 } else { 0x04 };
            buf[off + 3] = 0x0C;
            if current {
                let last = attrs.sectors.saturating_sub(1).min(u64::from(u32::MAX)) as u32;
                buf[off + 4..off + 8].copy_from_slice(&last.to_be_bytes());
                buf[off + 8..off + 12].copy_from_slice(&attrs.block_len.to_be_bytes());
                buf[off + 12..off + 14].copy_from_slice(&16u16.to_be_bytes()); // blocking
                buf[off + 14] = 0x00; // PP
            }
            off += 16;
        }
        if recordable_cd_caps && include(0x0021, feature(0x0021)) {
            // Incremental Streaming Writable (MMC-6 Table 116): version 3,
            // Data Type 0 (Mode 1) supported, no link sizes.
            if !fits(off, 8, buf.len()) {
                return None;
            }
            let current = feature(0x0021);
            buf[off..off + 2].copy_from_slice(&0x0021u16.to_be_bytes());
            buf[off + 2] = if current { 0x0D } else { 0x0C };
            buf[off + 3] = 0x04;
            if current {
                buf[off + 4..off + 6].copy_from_slice(&1u16.to_be_bytes());
            }
            off += 8;
        }
        if self.caps.random_writable() && include(0x0024, feature(0x0024)) {
            // Defect Management (MMC-6 Table 123): version 1.
            if !fits(off, 8, buf.len()) {
                return None;
            }
            let current = feature(0x0024);
            buf[off..off + 2].copy_from_slice(&0x0024u16.to_be_bytes());
            buf[off + 2] = if current { 0x05 } else { 0x04 };
            buf[off + 3] = 0x04;
            off += 8;
        }
        if recordable_cd_caps && include(0x002D, feature(0x002D)) {
            // CD Track at Once (MMC-6 Table 147): version 2, Data Type 0.
            if !fits(off, 8, buf.len()) {
                return None;
            }
            let current = feature(0x002D);
            buf[off..off + 2].copy_from_slice(&0x002Du16.to_be_bytes());
            buf[off + 2] = if current { 0x09 } else { 0x08 };
            buf[off + 3] = 0x04;
            if current {
                buf[off + 6..off + 8].copy_from_slice(&1u16.to_be_bytes());
            }
            off += 8;
        }
        // Data Length counts every byte after the 4-byte length field and is
        // declared in full even when the caller's allocation truncates.
        if !fits(0, 8, buf.len()) {
            return None;
        }
        buf[0..4].copy_from_slice(&((off - 4) as u32).to_be_bytes());
        buf[6..8].copy_from_slice(&current_profile.to_be_bytes());
        if let Some(out) = out {
            let n = off.min(out.len());
            out[..n].copy_from_slice(&buf[..n]);
        }
        Some(off)
    }

    fn event_status(&self, class: u8, out: Option<&mut [u8]>) -> Option<usize> {
        // As with GET CONFIGURATION, an absent medium gets the explicit
        // zero-sector view instead of `None` (which would delegate/reject).
        let attrs = self.attrs().unwrap_or(NO_MEDIUM_ATTRS);
        let mut buf = [0u8; 8];
        let len = if class & 0x10 != 0 {
            // Media class: Event Header + 4-byte Media Event Descriptor.
            buf[0..2].copy_from_slice(&6u16.to_be_bytes());
            buf[2] = 0x04; // NEA=0, Notification Class = Media
            buf[3] = 0x10; // Supported Event Class = Media
            buf[4] = 0x00; // Event Code 0 = NoChg
            buf[5] = if attrs.sectors != 0 { 0x02 } else { 0x00 };
            8
        } else {
            // No requested class: NEA=1 header only; still advertise Media.
            buf[0..2].copy_from_slice(&2u16.to_be_bytes());
            buf[2] = 0x80;
            buf[3] = 0x10;
            4
        };
        if let Some(out) = out {
            let n = len.min(out.len());
            out[..n].copy_from_slice(&buf[..n]);
        }
        Some(len)
    }
}

// ===========================================================================
// Byte encoders (baseline layouts)
// ===========================================================================

/// Caching page 0x08 (cdrom/common.rs:106).
const CACHING_PAGE: [u8; 20] = [
    0x08, 18, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x20, 0, 0, 0, 0, 0, 0, 0,
];
/// Vendor page 0x00 (cdrom/common.rs:110).
const VENDOR_PAGE: [u8; 4] = [0x00, 2, 0x00, 0x08];
/// CD-ROM Parameters page 0x0D (cdrom/common.rs:113).
const CDROM_PARAMS: [u8; 4] = [0x0D, 0x02, 0x08, 0x00];
/// CD-ROM Audio Control page 0x0E (cdrom/common.rs:116).
const CDROM_AUDIO: [u8; 16] = [
    0x0E, 0x0E, 0x04, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x02, 0x00, 0x00, 0x00,
];
/// Write Parameters page 0x05 payload length (page length byte `0x32`).
const WRITE_PARAMS_LEN: usize = 52;
/// Read/Write Error Recovery page 0x01 (cdrom/common.rs:137).
const READ_WRITE_ERROR_RECOVERY_PAGE: [u8; 12] = [
    0x01, 0x0A, 0xC0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
];
/// Power Condition page 0x1A (cdrom/common.rs:141).
const POWER_CONDITION_PAGE: [u8; 12] = [
    0x1A, 0x0A, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
];
/// Timeout and Protect page 0x1D (cdrom/common.rs:145).
const TIMEOUT_PROTECT_PAGE: [u8; 10] = [0x1D, 0x08, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00];
/// A read-only CD-ROM profile list, used by tests that build a deliberately
/// narrow capability set.
#[cfg(all(test, feature = "dvdram"))]
const CDROM_PROFILES: [u16; 1] = [0x08];
/// Profiles the default Hyper-Multi drive supports, in descending order; the
/// non-current ones are still listed.
const HYPER_MULTI_PROFILES: [u16; 3] = [0x12, 0x09, 0x08];
/// Profiles the narrower DVD-RAM recorder view supports; the non-current one
/// is still listed.
const DVDRAM_PROFILES: [u16; 2] = [0x12, 0x08];
/// CD/DVD Capabilities page 0x2A, fixed 64-byte CD-ROM view
/// (`CDROM_CAPABILITIES`, cdrom/common.rs:446).
const CDROM_CAPABILITIES_PAGE: [u8; 64] = [
    0x2A, 0x3E, 0x3B, 0x37, 0xF0, 0x03, 0x29, 0x00, 0x56, 0x90, 0x00, 0xFF, 0x20, 0x00, 0x56, 0x90,
    0x00, 0x00, 0x56, 0x90, 0x56, 0x90, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x56, 0x90, 0x00, 0x08,
    0x00, 0x00, 0x02, 0xC2, 0x00, 0x00, 0x05, 0x83, 0x00, 0x00, 0x0B, 0x06, 0x00, 0x00, 0x16, 0x0D,
    0x00, 0x00, 0x23, 0xD5, 0x00, 0x00, 0x15, 0xA4, 0x00, 0x00, 0x2B, 0x48, 0x00, 0x00, 0x56, 0x90,
];

/// CD/DVD Capabilities page 0x2A for a rewritable (DVD-RAM) medium.
///
/// Built from the baseline `DVDRAM_CAPS`/`DVDRAM_DESCS`
/// (`cdrom/common.rs:307`, `build_capabilities_page` 375–443): the
/// HyperMulti recorder capability set with one 11080 KB/s write-speed
/// descriptor. It is 36 bytes (the read-only CD view is 64); the page length
/// byte describes each variant completely, so `0x3F` needs no padding.
const DVDRAM_CAPABILITIES_PAGE: [u8; 36] = [
    0x2A, 0x22, 0x3B, 0x37, 0xF0, 0x03, 0x29, 0x00, 0x56, 0x90, 0x00, 0xFF, 0x20, 0x00, 0x56, 0x90,
    0x00, 0x00, 0x56, 0x90, 0x56, 0x90, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x56, 0x90, 0x00, 0x01,
    0x00, 0x00, 0x2B, 0x48,
];

/// Total byte count of all supported mode pages.
const ALL_PAGES_LEN: usize = 12 + 52 + 20 + 4 + 16 + 12 + 10 + 64 + 4;
/// Largest MODE SENSE response: 8-byte header plus every page.
const MODE_SENSE_MAX: usize = 8 + ALL_PAGES_LEN;

/// Page order for `0x3F`: baseline order, vendor page 0x00 last
/// (cdrom/common.rs:501).
const ALL_PAGE_ORDER: [u8; 9] = [0x01, 0x05, 0x08, 0x0D, 0x0E, 0x1A, 0x1D, 0x2A, 0x00];

/// Write Parameters page 0x05 for the mounted medium.
///
/// A CD-R recorder advertises the mode it actually records with: Track-at-Once
/// (Write Type 1), data track mode 4 and 2048-byte Mode 1 data blocks (Data
/// Block Type 8). Read-only and rewritable media keep the default zero page
/// and therefore never claim TAO.
fn write_params_page(attrs: Option<MmcAttrs>) -> [u8; WRITE_PARAMS_LEN] {
    let mut page = [0u8; WRITE_PARAMS_LEN];
    page[0] = 0x05;
    page[1] = 0x32;
    if let Some(attrs) = attrs {
        if attrs.write_mode == MmcWriteMode::WriteOnce {
            page[2] = 0x01; // Write Type: Track-at-Once
            page[3] = 0x04; // Track Mode: data
            page[4] = 0x08; // Data Block Type: Mode 1, 2048 bytes
        }
    }
    page
}

/// Copy one supported mode page into `out` and return its byte count.
///
/// Page 0x05 is medium-dependent; every other page is a fixed drive page.
/// Page 0x2A comes from [`MmcCaps::capabilities_page`]: the 64-byte read-only
/// CD-ROM view or the 36-byte DVD-RAM recorder view. The page length byte
/// describes each one completely, so `0x3F` concatenation never carries padding
/// that a host could parse as another page.
fn write_page(page: u8, caps: MmcCaps, attrs: Option<MmcAttrs>, out: &mut [u8]) -> Option<usize> {
    if page == 0x05 {
        if out.len() < WRITE_PARAMS_LEN {
            return None;
        }
        out[..WRITE_PARAMS_LEN].copy_from_slice(&write_params_page(attrs));
        return Some(WRITE_PARAMS_LEN);
    }
    let bytes: &[u8] = match page {
        0x00 => &VENDOR_PAGE,
        0x01 => &READ_WRITE_ERROR_RECOVERY_PAGE,
        0x08 => &CACHING_PAGE,
        0x0D => &CDROM_PARAMS,
        0x0E => &CDROM_AUDIO,
        0x1A => &POWER_CONDITION_PAGE,
        0x1D => &TIMEOUT_PROTECT_PAGE,
        0x2A => caps.capabilities_page(),
        _ => return None,
    };
    let n = bytes.len().min(out.len());
    out[..n].copy_from_slice(&bytes[..n]);
    Some(bytes.len())
}

/// READ TOC address helper: LBA or absolute MSF (`lba + 150`).
fn toc_address(lba: u32, msf: bool) -> [u8; 4] {
    if !msf {
        return lba.to_be_bytes();
    }
    let value = lba.saturating_add(150);
    let m = value / (75 * 60);
    let s = (value % (75 * 60)) / 75;
    let f = value % 75;
    [0x00, m as u8, s as u8, f as u8]
}

/// ADR/CTL nibble for one track descriptor.
fn toc_control(kind: TrackKind) -> u8 {
    match kind {
        TrackKind::Data => 0x14,  // ADR=1, CTL=4 (data)
        TrackKind::Audio => 0x10, // ADR=1, CTL=0 (audio)
    }
}

/// Three-byte absolute MSF (`lba + 150`) for the compact raw TOC.
fn toc_msf3(lba: u32) -> [u8; 3] {
    let [_, m, s, f] = toc_address(lba, true);
    [m, s, f]
}

/// Write one compact format-2 descriptor:
/// `[session, ADR/control, TNO, POINT, MIN, SEC, FRAME, 0]`.
fn write_raw_descriptor(
    out: &mut [u8],
    session: u16,
    adr_ctl: u8,
    tno: u8,
    point: u8,
    value: [u8; 3],
) {
    out[0] = session.min(255) as u8;
    out[1] = adr_ctl;
    out[2] = tno;
    out[3] = point;
    out[4..7].copy_from_slice(&value);
    out[7] = 0;
}

/// Encode READ TOC format 0 (track list + lead-out), format 1 (last complete
/// session) or format 2 (raw TOC) into `out`, returning the full response
/// length.
///
/// Format 0 emits one descriptor per requested track and always appends the
/// lead-out (`0xAA`, `last_session_lba + 1`). Format 1 emits the first track of
/// the last complete session; a disc without a complete session is rejected.
/// Format 2 emits the Q-subchannel lead-in points A0/A1/A2/B0 followed by one
/// descriptor per track and the lead-out, all in MSF form.
fn encode_toc<M: MmcMedium>(
    medium: &M,
    info: DiscInfo,
    tracks: u16,
    msf: bool,
    format: u8,
    track_req: u8,
    out: &mut [u8],
) -> Option<usize> {
    let last_track = tracks.min(99);
    let mut buf = [0u8; TOC_MAX_LEN];
    let total = if format == 0 {
        let first = info.first_track.max(1);
        let start = if track_req == 0 {
            first
        } else {
            u16::from(track_req).max(first)
        };
        let descriptors = if track_req == 0xAA {
            0
        } else {
            last_track.saturating_sub(start).saturating_add(1)
        };
        let total = 4 + TOC_DESCRIPTOR_LEN * (descriptors as usize + 1);
        if total > buf.len() {
            return None;
        }
        buf[0..2].copy_from_slice(&((total - 2) as u16).to_be_bytes());
        buf[2] = first.min(255) as u8;
        buf[3] = last_track.min(255) as u8;
        let mut at = 4usize;
        if track_req != 0xAA {
            for number in start..=last_track {
                let track = medium.track(number)?;
                let ctl = toc_control(track.kind);
                buf[at + 1] = ctl;
                buf[at + 2] = track.number.min(255) as u8;
                buf[at + 4..at + 8].copy_from_slice(&toc_address(
                    track.start_lba.min(u64::from(u32::MAX)) as u32,
                    msf,
                ));
                at += TOC_DESCRIPTOR_LEN;
            }
        }
        // The lead-out follows the last program-area track.
        let lead_out = info
            .last_session_lba
            .saturating_add(1)
            .min(u64::from(u32::MAX)) as u32;
        let ctl = match medium.track(last_track) {
            Some(track) => toc_control(track.kind),
            None if track_req == 0xAA => 0x14,
            None => return None,
        };
        buf[at + 1] = ctl;
        buf[at + 2] = 0xAA;
        buf[at + 4..at + 8].copy_from_slice(&toc_address(lead_out, msf));
        total
    } else if format == 2 {
        // Raw TOC. A disc without a complete session has no lead-in TOC to
        // report; a complete last session is required.
        let last_complete = match info.status {
            DiscStatus::Finalized => info.sessions,
            DiscStatus::Incomplete if info.sessions > 1 => info.sessions - 1,
            _ => return None,
        };
        let first = info.first_track.max(1);
        let descriptors = 4 + last_track.saturating_sub(first).saturating_add(1) as usize + 1;
        let total = 4 + TOC_RAW_DESCRIPTOR_LEN * descriptors;
        if total > buf.len() {
            return None;
        }
        buf[0..2].copy_from_slice(&((total - 2) as u16).to_be_bytes());
        buf[2] = 0x01;
        buf[3] = last_complete.min(255) as u8;
        let lead_out = info
            .last_session_lba
            .saturating_add(1)
            .min(u64::from(u32::MAX)) as u32;
        let lead_msf = toc_msf3(lead_out);
        let first_track = medium.track(first)?;
        let last_ctl = match medium.track(last_track) {
            Some(track) => toc_control(track.kind),
            None => toc_control(first_track.kind),
        };
        let mut at = 4usize;
        // A0: first track number, disc type (CD-DA/CD-ROM = 00h), PFRAME 0.
        write_raw_descriptor(
            &mut buf[at..at + TOC_RAW_DESCRIPTOR_LEN],
            1,
            toc_control(first_track.kind),
            0,
            0xA0,
            [first.min(255) as u8, 0x00, 0x00],
        );
        at += TOC_RAW_DESCRIPTOR_LEN;
        // A1: last track number.
        write_raw_descriptor(
            &mut buf[at..at + TOC_RAW_DESCRIPTOR_LEN],
            1,
            last_ctl,
            0,
            0xA1,
            [last_track.min(255) as u8, 0x00, 0x00],
        );
        at += TOC_RAW_DESCRIPTOR_LEN;
        // A2: start of the lead-out.
        write_raw_descriptor(
            &mut buf[at..at + TOC_RAW_DESCRIPTOR_LEN],
            1,
            last_ctl,
            0,
            0xA2,
            lead_msf,
        );
        at += TOC_RAW_DESCRIPTOR_LEN;
        // B0: full-TOC marker (ADR=5); a closed disc points at the lead-out.
        write_raw_descriptor(
            &mut buf[at..at + TOC_RAW_DESCRIPTOR_LEN],
            1,
            0x50,
            0,
            0xB0,
            lead_msf,
        );
        at += TOC_RAW_DESCRIPTOR_LEN;
        for number in first..=last_track {
            let track = medium.track(number)?;
            let start = track.start_lba.min(u64::from(u32::MAX)) as u32;
            write_raw_descriptor(
                &mut buf[at..at + TOC_RAW_DESCRIPTOR_LEN],
                track.session,
                toc_control(track.kind),
                0,
                track.number.min(255) as u8,
                toc_msf3(start),
            );
            at += TOC_RAW_DESCRIPTOR_LEN;
        }
        write_raw_descriptor(
            &mut buf[at..at + TOC_RAW_DESCRIPTOR_LEN],
            last_complete,
            last_ctl,
            0,
            0xAA,
            lead_msf,
        );
        total
    } else {
        // Format 1: the last complete session. An incomplete last session
        // leaves the previous (closed) one as the last complete session.
        let last_complete = match info.status {
            DiscStatus::Finalized => info.sessions,
            DiscStatus::Incomplete if info.sessions > 1 => info.sessions - 1,
            _ => return None,
        };
        let session = medium.session(last_complete)?;
        let track = medium.track(session.first_track)?;
        buf[0..2].copy_from_slice(&((TOC_SESSION_LEN - 2) as u16).to_be_bytes());
        buf[2] = 0x01;
        buf[3] = last_complete.min(255) as u8;
        buf[5] = toc_control(track.kind);
        buf[6] = track.number.min(255) as u8;
        buf[8..12].copy_from_slice(&toc_address(
            track.start_lba.min(u64::from(u32::MAX)) as u32,
            msf,
        ));
        TOC_SESSION_LEN
    };
    let n = total.min(out.len());
    out[..n].copy_from_slice(&buf[..n]);
    Some(total)
}

/// MSF field for READ DISC INFORMATION: binary M/S/F with the usual `+150`
/// offset. A negative lead-in address wraps inside a 100-minute disc; `None`
/// (but applicable) is `FF FF FF FF`.
fn disc_msf(lba: Option<i64>) -> [u8; 4] {
    let Some(lba) = lba else {
        return [0xFF; 4];
    };
    let mut value = lba.saturating_add(150);
    if value < 0 {
        value = value.saturating_add(100 * 60 * 75);
    }
    let m = value / (75 * 60);
    let s = (value / 75) % 60;
    let f = value % 75;
    [0x00, m as u8, s as u8, f as u8]
}

/// Encode READ DISC INFORMATION (MMC-6 Table 365).
///
/// Byte 2 carries erasable (bit 4), state of last session (bits 3-2) and disc
/// status (bits 1-0). The Erasable bit is only set for rewritable media; a
/// write-once CD-R reports `0`. CD media encode the lead-in and lead-out
/// addresses as MSF; other media keep the LBA form.
fn encode_disc_info(info: DiscInfo, attrs: MmcAttrs, out: &mut [u8]) {
    let mut buf = [0u8; DISC_INFO_LEN];
    buf[0..2].copy_from_slice(&((DISC_INFO_LEN - 2) as u16).to_be_bytes());
    let status = match info.status {
        DiscStatus::Empty => 0u8,
        DiscStatus::Incomplete => 1,
        DiscStatus::Finalized => 2,
        DiscStatus::Other(raw) => raw & 0x03,
    };
    let erasable = info.erasable && matches!(attrs.write_mode, MmcWriteMode::Rewritable);
    buf[2] = (u8::from(erasable) << 4) | ((info.last_session_state & 0x03) << 2) | status;
    buf[3] = info.first_track.min(255) as u8;
    buf[4] = info.sessions.min(255) as u8;
    buf[5] = info.first_track_last_session.min(255) as u8;
    buf[6] = info.last_track_last_session.min(255) as u8;
    buf[7] = 0x20; // URU=1, MRW status 0
    buf[8] = info.disc_type;
    buf[9] = (info.sessions >> 8).min(255) as u8;
    buf[10] = (info.first_track_last_session >> 8).min(255) as u8;
    buf[11] = (info.last_track_last_session >> 8).min(255) as u8;
    let cdrw = matches!(attrs.profile, 0x0009 | 0x000A);
    if cdrw {
        // CD-R/RW: the lead-in address is negative and wraps within 100
        // minutes; a complete disc reports FF for both fields.
        buf[16..20].copy_from_slice(&disc_msf(info.last_session_lead_in));
        buf[20..24].copy_from_slice(&disc_msf(info.last_possible_lead_out));
    } else if matches!(attrs.profile, 0x0008) {
        // A stamped/read-only CD is complete.
        buf[16..20].copy_from_slice(&[0xFF; 4]);
        buf[20..24].copy_from_slice(&[0xFF; 4]);
    } else {
        // Non-CD media: no Disc Type and zeroed lead-in/lead-out fields
        // (MMC-6 6.21.3.1.15/17/18).
        buf[8] = 0x00;
    }
    let n = DISC_INFO_LEN.min(out.len());
    out[..n].copy_from_slice(&buf[..n]);
}

/// Encode READ TRACK INFORMATION (MMC-6 Table 494).
///
/// RT/Blank follow the track state and the medium class (Tables 497/502):
/// non-recordable media always report RT=0; a recordable CD-R marks invisible
/// and reserved tracks appropriately, distinguishes an empty reserved track
/// from a partially recorded one, and only marks a closed track RT=1. The
/// lead-in pseudo-track (number 0) reports no NWA and a negative start address.
fn encode_track_info(info: TrackInfo, recordable_cdr: bool, out: &mut [u8]) {
    let mut buf = [0u8; TRACK_INFO_LEN];
    buf[0..2].copy_from_slice(&((TRACK_INFO_LEN - 2) as u16).to_be_bytes());
    let lead_in = info.number == 0;
    buf[2] = info.number.min(255) as u8;
    buf[3] = info.session.min(255) as u8;
    // Track Mode is the Q control nibble: 0x04 data, 0x00 audio/lead-in.
    buf[5] = if info.kind == TrackKind::Data && !lead_in {
        0x04
    } else {
        0x00
    };
    let (rt, blank) = if lead_in {
        (0u8, 0u8)
    } else if !recordable_cdr {
        // Table 497: non-recordable media report RT=0, and the Blank bit has
        // no meaning outside CD-R/-RW.
        (0, 0)
    } else {
        match info.status {
            TrackStatus::Invisible => (0, 1),
            TrackStatus::Reserved if info.length == 0 => (1, 1),
            TrackStatus::Reserved => (1, 0),
            TrackStatus::Incomplete => (0, 0),
            TrackStatus::Complete => (1, 0),
        }
    };
    let nwa_valid = !lead_in && !matches!(info.status, TrackStatus::Complete);
    let packet = u8::from(info.packet);
    let data_mode = if lead_in { 0u8 } else { 0x01 };
    buf[6] = (rt << 7) | (blank << 6) | (packet << 5) | data_mode;
    buf[7] = if nwa_valid { 0x01 } else { 0x00 }; // NWA_V bit 0, LRA_V = 0
    buf[8..12].copy_from_slice(&(info.start_lba as u32).to_be_bytes());
    buf[12..16].copy_from_slice(&(info.nwa.min(u64::from(u32::MAX)) as u32).to_be_bytes());
    if nwa_valid {
        buf[16..20]
            .copy_from_slice(&(info.free_blocks.min(u64::from(u32::MAX)) as u32).to_be_bytes());
    }
    // Bytes 20-23 stay zero: this is a TAO/variable-packet medium, not a
    // fixed-packet one.
    let size = info.length.max(info.allocated).min(u64::from(u32::MAX)) as u32;
    buf[24..28].copy_from_slice(&size.to_be_bytes());
    if nwa_valid {
        let lra = info.nwa.saturating_sub(1).min(u64::from(u32::MAX)) as u32;
        buf[28..32].copy_from_slice(&lra.to_be_bytes());
    }
    buf[32] = (info.number >> 8) as u8;
    buf[33] = (info.session >> 8) as u8;
    let n = TRACK_INFO_LEN.min(out.len());
    out[..n].copy_from_slice(&buf[..n]);
}

/// Ensure the host phase direction matches the command family.
fn check_direction(ctx: CommandContext, expected: Direction) -> Result<(), Completion> {
    if ctx.host_direction == expected {
        Ok(())
    } else {
        Err(Completion::Check(INVALID_FIELD))
    }
}

/// Validate the 12-byte FORMAT UNIT parameter list (`cdrom/drive.rs:854–900`).
///
/// MMC-6 Table 240: DPRY, STPF and IP must be zero; when FOV is zero the host
/// must also clear DCRT and Try-out; the list length field is 8. Table 241: the
/// only supported descriptor is Format Type 0 with a 2048-byte (or "use the
/// medium default", 0) block length.
fn validate_format_list(data: &[u8]) -> Result<FormatList, Sense> {
    if data.len() != FORMAT_PARAMS_LEN {
        return Err(INVALID_FIELD_IN_PARAMETER_LIST);
    }
    let header = data[1];
    if header & (0x40 | 0x10 | 0x08) != 0
        || (header & 0x80 == 0 && header & (0x20 | 0x04) != 0)
        || be16(&data[2..4]) != 8
    {
        return Err(INVALID_FIELD_IN_PARAMETER_LIST);
    }
    let block_len = be24(&data[9..12]);
    if data[8] != 0x00 || (block_len != 2048 && block_len != 0) {
        return Err(INVALID_FIELD_IN_PARAMETER_LIST);
    }
    Ok(FormatList {
        try_out: header & 0x04 != 0,
        // Table 240 bit 1; the CDB has no Immed bit (bit 0 is Format Code).
        immediate: header & 0x02 != 0,
    })
}

/// Validate a MODE SELECT parameter list.
///
/// The list must carry a mode header whose block-descriptor length is zero
/// (MM drives have no block descriptors), followed by complete mode pages. On
/// a CD-R the Write Parameters page must describe the supported recording
/// mode: Track-at-Once with 2048-byte Mode 1 blocks. Every other medium
/// accepts and ignores page 0x05. A list without page 0x05 is a no-op.
fn validate_mode_select(ten: bool, data: &[u8], attrs: Option<MmcAttrs>) -> Result<(), Sense> {
    let header = if ten { 8 } else { 4 };
    if data.len() < header {
        return Err(INVALID_FIELD);
    }
    let block_descriptors = if ten {
        usize::from(be16(&data[6..8]))
    } else {
        usize::from(data[3])
    };
    if block_descriptors != 0 {
        return Err(INVALID_FIELD);
    }
    let cdr_recorder = attrs.is_some_and(|attrs| attrs.write_mode == MmcWriteMode::WriteOnce);
    let mut at = header;
    while at < data.len() {
        if at + 2 > data.len() {
            return Err(INVALID_FIELD);
        }
        let code = data[at] & 0x3F;
        let payload = usize::from(data[at + 1]);
        let end = at.checked_add(2 + payload).ok_or(INVALID_FIELD)?;
        if end > data.len() {
            return Err(INVALID_FIELD);
        }
        if code == 0x05 && cdr_recorder {
            // MMC-6 7.4.4: the page is 32h (or 36h with vendor specific
            // bytes). Byte 2 bit 4 is Test Write, bits 3-0 Write Type; byte 4
            // bits 3-0 Data Block Type.
            if payload != 0x32 && payload != 0x36 {
                return Err(INVALID_FIELD);
            }
            let byte2 = data[at + 2];
            if byte2 & 0x10 != 0 {
                // Test Write would pretend to burn; refuse it instead of
                // silently discarding the host's data.
                return Err(INVALID_FIELD);
            }
            if byte2 & 0x0F != 0x01 {
                // Only Track-at-Once is supported: SAO, raw and packet are
                // rejected rather than silently treated as TAO.
                return Err(INVALID_FIELD);
            }
            if data[at + 4] & 0x0F != 0x08 {
                // Only Mode 1 (2048-byte) blocks are accepted.
                return Err(INVALID_FIELD);
            }
        }
        at = end;
    }
    Ok(())
}

/// Zero-fill progress in whole percent, clamped to 0..=100.
fn format_progress(done: u64, total: u64) -> u32 {
    if total == 0 {
        return 100;
    }
    (done.saturating_mul(100) / total).min(100) as u32
}

/// Progress carried by a failed settle: never 100.
fn failure_progress(done: u64, total: u64) -> Option<u32> {
    Some(format_progress(done, total).min(99))
}

/// Validate `lba + blocks` against the medium's sector count.
fn check_range(lba: u64, blocks: u64, sectors: u64) -> Result<(), Completion> {
    let end = lba
        .checked_add(blocks)
        .ok_or(Completion::Check(LBA_OUT_OF_RANGE))?;
    if end > sectors {
        return Err(Completion::Check(LBA_OUT_OF_RANGE));
    }
    Ok(())
}

/// Whether `at..at + len` is inside a staging buffer of `cap` bytes.
fn fits(at: usize, len: usize, cap: usize) -> bool {
    at.checked_add(len).is_some_and(|end| end <= cap)
}

/// Big-endian 16-bit field.
fn be16(bytes: &[u8]) -> u16 {
    (u16::from(bytes[0]) << 8) | u16::from(bytes[1])
}

/// Big-endian 24-bit field.
fn be24(bytes: &[u8]) -> u32 {
    (u32::from(bytes[0]) << 16) | (u32::from(bytes[1]) << 8) | u32::from(bytes[2])
}

/// Big-endian 32-bit field.
fn be32(bytes: &[u8]) -> u32 {
    (u32::from(bytes[0]) << 24)
        | (u32::from(bytes[1]) << 16)
        | (u32::from(bytes[2]) << 8)
        | u32::from(bytes[3])
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::core::storage::{HostReceipt, IoReceipt, StorageOp};
    use crate::core::{Effect, InterruptReason as Irq, TargetId};
    use crate::mmc::attrs::{Session, Track};
    #[cfg(feature = "cdr-bundle")]
    use crate::mmc::cdr_bundle::{CdrBundleMedium, CdrCapacity};
    use crate::mmc::flat::FlatCdMedium;
    use std::cell::Cell;

    fn permit() -> CommandPermit {
        CommandPermit::new(TargetId::UNBOUND)
    }

    fn boundary() -> BoundaryPermit {
        BoundaryPermit::new(TargetId::UNBOUND)
    }

    fn ctx(direction: Direction, bytes: u64) -> CommandContext {
        CommandContext {
            lun: 0,
            lun_count: 1,
            host_bytes: bytes,
            host_direction: direction,
        }
    }

    fn drive(sectors: u64) -> MmcDrive<FlatCdMedium> {
        MmcDrive::new(FlatCdMedium::read_only(sectors))
    }

    fn read_cdb(lba: u32, blocks: u16) -> [u8; 10] {
        let mut cdb = [0u8; 10];
        cdb[0] = READ_10;
        cdb[2..6].copy_from_slice(&lba.to_be_bytes());
        cdb[7..9].copy_from_slice(&blocks.to_be_bytes());
        cdb
    }

    /// Run a ToHost descriptor command to completion and return its length.
    fn run_query<M: MmcMedium>(
        dev: &mut MmcDrive<M>,
        cdb: &[u8],
        alloc: u64,
        data: &mut [u8],
    ) -> Completion {
        let permit = permit();
        dev.prepare(&permit, ctx(Direction::ToHost, alloc), cdb)
            .expect("prepare");
        let len = match dev.poll(&permit, Feedback::begin(), data) {
            PollStep::Publish(plan) => {
                assert_eq!(plan.direction, Direction::ToHost);
                plan.bytes as usize
            }
            PollStep::Complete(completion) => return completion,
            other => panic!("expected publish, got {other:?}"),
        };
        match dev.poll(&permit, Feedback::plan_accepted(), data) {
            PollStep::Send { bytes, .. } => assert_eq!(bytes.len(), len),
            PollStep::Complete(completion) => return completion,
            other => panic!("expected send, got {other:?}"),
        }
        match dev.poll(
            &permit,
            Feedback::host_sent(HostReceipt::test(len, None)),
            data,
        ) {
            PollStep::Complete(completion) => completion,
            other => panic!("expected completion, got {other:?}"),
        }
    }

    #[test]
    fn read_toc_format0_lba_and_msf() {
        let mut dev = drive(100);
        let mut cdb = [0u8; 10];
        cdb[0] = READ_TOC;
        cdb[8] = 20;
        let mut data = [0u8; 32];
        assert_eq!(run_query(&mut dev, &cdb, 20, &mut data), Completion::Good);
        assert_eq!(&data[0..2], &[0x00, 0x12]);
        assert_eq!(data[2], 0x01);
        assert_eq!(data[3], 0x01);
        assert_eq!(data[5], 0x14);
        assert_eq!(data[6], 0x01);
        assert_eq!(&data[8..12], &[0u8; 4]);
        assert_eq!(data[13], 0x14);
        assert_eq!(data[14], 0xAA);
        assert_eq!(&data[16..20], &100u32.to_be_bytes());

        // MSF: lead-out 100 + 150 = 250 = 0:03:25.
        cdb[1] = 0x02;
        let mut msf = [0u8; 32];
        assert_eq!(run_query(&mut dev, &cdb, 20, &mut msf), Completion::Good);
        assert_eq!(&msf[16..20], &[0x00, 0x00, 0x03, 0x19]);
    }

    #[test]
    fn read_toc_format1_session_descriptor() {
        let mut dev = drive(100);
        let mut cdb = [0u8; 10];
        cdb[0] = READ_TOC;
        cdb[2] = 0x01;
        cdb[8] = 12;
        let mut data = [0u8; 32];
        assert_eq!(run_query(&mut dev, &cdb, 12, &mut data), Completion::Good);
        assert_eq!(&data[0..2], &[0x00, 0x0A]);
        assert_eq!(data[2], 0x01);
        assert_eq!(data[3], 0x01);
        assert_eq!(data[4], 0x00); // reserved
        assert_eq!(data[5], 0x14); // ADR/CTL (data)
        assert_eq!(data[6], 0x01); // first track in the last complete session
        assert_eq!(data[7], 0x00); // reserved
        assert_eq!(&data[8..12], &[0u8; 4]); // start address
    }

    #[test]
    fn read_toc_truncation_keeps_declared_length() {
        let mut dev = drive(100);
        let mut cdb = [0u8; 10];
        cdb[0] = READ_TOC;
        cdb[8] = 10;
        let mut data = [0u8; 32];
        assert_eq!(run_query(&mut dev, &cdb, 10, &mut data), Completion::Good);
        // Only 10 bytes are sent, but the header still declares the full 18.
        assert_eq!(&data[0..2], &[0x00, 0x12]);
        assert_eq!(data[5], 0x14);

        // Allocation length 0 is a zero-data GOOD.
        let permit = permit();
        cdb[8] = 0;
        let mut dev = drive(100);
        dev.prepare(&permit, ctx(Direction::ToHost, 0), &cdb)
            .expect("prepare");
        assert!(matches!(
            dev.poll(&permit, Feedback::begin(), &mut data),
            PollStep::Complete(Completion::Good)
        ));
        assert!(!dev.active());
    }

    #[test]
    fn read_toc_rejects_unsupported_format_and_track() {
        let mut dev = drive(100);
        let permit = permit();
        let mut cdb = [0u8; 10];
        cdb[0] = READ_TOC;
        cdb[2] = 0x03; // format 3 (PMA) is not served
        assert_eq!(
            dev.prepare(&permit, ctx(Direction::ToHost, 20), &cdb),
            Err(Completion::Check(INVALID_FIELD))
        );
        cdb[2] = 0x04; // format 4 (ATIP) is not served
        assert_eq!(
            dev.prepare(&permit, ctx(Direction::ToHost, 20), &cdb),
            Err(Completion::Check(INVALID_FIELD))
        );
        cdb[2] = 0;
        cdb[6] = 2;
        assert_eq!(
            dev.prepare(&permit, ctx(Direction::ToHost, 20), &cdb),
            Err(Completion::Check(INVALID_FIELD))
        );
    }

    #[test]
    fn read_disc_information_offsets() {
        let mut dev = drive(100);
        let mut cdb = [0u8; 10];
        cdb[0] = READ_DISC_INFORMATION;
        cdb[8] = 34;
        let mut data = [0u8; 48];
        assert_eq!(run_query(&mut dev, &cdb, 34, &mut data), Completion::Good);
        assert_eq!(&data[0..2], &[0x00, 0x20]);
        assert_eq!(data[2] & 0x03, 0x02); // Disc Status = finalized
        assert_eq!((data[2] >> 2) & 0x03, 0x03); // last session complete
        assert_eq!(data[2] & 0x10, 0x00); // not erasable
        assert_eq!(data[3], 1);
        assert_eq!(data[4], 1);
        assert_eq!(data[5], 1);
        assert_eq!(data[6], 1);
        assert_eq!(data[7], 0x20);
        // A finalized CD has no applicable lead-in/lead-out addresses.
        assert_eq!(&data[16..20], &[0xFF; 4]);
        assert_eq!(&data[20..24], &[0xFF; 4]);
    }

    #[test]
    fn read_track_information_layout() {
        let mut dev = drive(100);
        let mut cdb = [0u8; 10];
        cdb[0] = READ_TRACK_INFORMATION;
        cdb[2..6].copy_from_slice(&1u32.to_be_bytes());
        cdb[8] = 48;
        let mut data = [0u8; 64];
        assert_eq!(run_query(&mut dev, &cdb, 48, &mut data), Completion::Good);
        assert_eq!(&data[0..2], &[0x00, 0x2E]);
        assert_eq!(data[2], 1);
        assert_eq!(data[3], 1);
        assert_eq!(data[5], 0x04); // Track Mode: data
        assert_eq!(data[6], 0x01); // non-recordable: RT=0, Data Mode 1
        assert_eq!(data[7], 0x00); // NWA_V=0 on a closed track
        assert_eq!(&data[20..24], &0u32.to_be_bytes()); // no fixed packets
        assert_eq!(&data[24..28], &100u32.to_be_bytes());
    }

    #[test]
    fn read_capacity_and_mode_sense_lengths() {
        let dev = drive(100);
        let profile = dev.spc_profile().expect("profile");
        assert_eq!(profile.medium_type(), 0x41);
        assert!(!profile.write_protected());
        assert_eq!(profile.read_capacity(), Some(Capacity::new(99, 2048)));

        let mut short = [0u8; 64];
        assert_eq!(
            profile.mode_sense(false, 0x08, false, 0, Some(&mut short)),
            Some(24)
        );
        assert_eq!(short[0], 23);
        assert_eq!(short[1], 0x41);
        assert_eq!(short[2], 0x00);
        assert_eq!(short[3], 0x00);
        assert_eq!(short[4], 0x08);
        assert_eq!(short[5], 18);

        let mut long = [0u8; 64];
        assert_eq!(
            profile.mode_sense(true, 0x08, false, 0, Some(&mut long)),
            Some(28)
        );
        assert_eq!(&long[0..2], &26u16.to_be_bytes());
        assert_eq!(long[2], 0x41);
        assert_eq!(long[6..8], [0x00, 0x00]);
        assert_eq!(long[8], 0x08);

        let mut all = [0u8; 216];
        assert_eq!(
            profile.mode_sense(false, 0x3F, false, 0, Some(&mut all)),
            Some(198)
        );
        assert_eq!(all[0], 197);
        let mut at = 4usize;
        let mut codes = [0u8; 9];
        for code in &mut codes {
            *code = all[at] & 0x3F;
            at += 2 + usize::from(all[at + 1]);
        }
        assert_eq!(codes, ALL_PAGE_ORDER);
        assert_eq!(profile.mode_sense(true, 0x3F, false, 0, None), Some(202));
        assert_eq!(profile.mode_sense(false, 0x0A, false, 0, None), None);
    }

    #[test]
    fn get_configuration_header_and_features() {
        let dev = drive(100);
        let profile = dev.spc_profile().expect("profile");
        let mut buf = [0u8; 128];
        let n = profile.get_configuration(0, 0, Some(&mut buf)).expect("GC");
        assert_eq!(n, 108);
        assert_eq!(&buf[0..4], &104u32.to_be_bytes());
        assert_eq!(&buf[6..8], &0x0008u16.to_be_bytes());
        // Profile List: the Hyper-Multi drive supports [0x12, 0x09, 0x08];
        // only the mounted CD-ROM profile is Current.
        assert_eq!(&buf[8..10], &[0x00, 0x00]);
        assert_eq!(buf[10], 0x03);
        assert_eq!(buf[11], 12);
        assert_eq!(&buf[12..14], &0x0012u16.to_be_bytes());
        assert_eq!(buf[15], 0);
        assert_eq!(&buf[16..18], &0x0009u16.to_be_bytes());
        assert_eq!(buf[19], 0);
        assert_eq!(&buf[20..22], &0x0008u16.to_be_bytes());
        assert_eq!(buf[23], 0x01);
        // Core, Removable Medium, Random Readable, MultiRead, CD Read,
        // Random Writable + Defect Management (Current=0 on a read-only disc).
        assert_eq!(&buf[24..26], &[0x00, 0x01]);
        assert_eq!(&buf[36..38], &[0x00, 0x03]);
        assert_eq!(&buf[44..46], &[0x00, 0x10]);
        assert_eq!(&buf[48..52], &2048u32.to_be_bytes());
        assert_eq!(buf[53], 0x01);
        assert_eq!(&buf[56..58], &[0x00, 0x1D]);
        assert_eq!(&buf[60..62], &[0x00, 0x1E]);
        let at20 = feature_at(&buf, n, 0x0020).expect("Random Writable listed");
        assert_eq!(buf[at20 + 2] & 1, 0);

        // RT=10b returns only the identified feature.
        let mut only = [0u8; 64];
        assert_eq!(
            profile.get_configuration(2, 0x0010, Some(&mut only)),
            Some(20)
        );
        assert_eq!(&only[0..4], &16u32.to_be_bytes());
        assert_eq!(&only[8..10], &[0x00, 0x10]);

        // An unidentified feature yields the bare 8-byte header.
        assert_eq!(profile.get_configuration(2, 0x0050, None), Some(8));

        // RT=01b returns only current features at or above the start.
        assert_eq!(profile.get_configuration(1, 0x0010, None), Some(32));
    }

    #[test]
    fn get_configuration_stays_within_its_staging_buffer_with_twelve_profiles() {
        // The capability list allows 12 entries; the profile list plus every
        // optional descriptor must stay inside the fixed response buffer.
        const PROFILES: [u16; 12] = [
            0x12, 0x09, 0x08, 0x03, 0x04, 0x05, 0x06, 0x07, 0x0A, 0x0B, 0x0C, 0x0D,
        ];
        let caps = MmcCaps::new(&PROFILES, &CDROM_CAPABILITIES_PAGE, true);
        let dev = MmcDrive::new_with_caps(FlatCdMedium::read_only(1), caps);
        let profile = dev.spc_profile().expect("profile");
        let mut buf = [0u8; 256];
        let n = profile
            .get_configuration(0, 0, Some(&mut buf))
            .expect("GC with 12 profiles");
        assert_eq!(n, 144, "8 header + 52 profiles + 84 descriptors");
        assert!(n <= GET_CONFIG_LEN);
        assert_eq!(buf[11], 48, "12 profile entries");
        assert_eq!(&buf[0..4], &140u32.to_be_bytes());
        // A smaller caller allocation truncates legitimately; the declared
        // response length still describes the full data.
        let mut small = [0u8; 32];
        assert_eq!(profile.get_configuration(0, 0, Some(&mut small)), Some(144));
    }

    #[test]
    fn event_status_media_and_unsupported_class() {
        let dev = drive(100);
        let profile = dev.spc_profile().expect("profile");
        let mut buf = [0u8; 8];
        assert_eq!(profile.event_status(0x10, Some(&mut buf)), Some(8));
        assert_eq!(&buf[0..2], &6u16.to_be_bytes());
        assert_eq!(buf[2], 0x04);
        assert_eq!(buf[3], 0x10);
        assert_eq!(buf[4], 0x00);
        assert_eq!(buf[5], 0x02); // media present, tray closed

        assert_eq!(profile.event_status(0x00, Some(&mut buf)), Some(4));
        assert_eq!(&buf[0..2], &2u16.to_be_bytes());
        assert_eq!(buf[2], 0x80);
        assert_eq!(buf[3], 0x10);
    }

    #[test]
    fn write_is_rejected_before_the_medium() {
        let mut dev = drive(100);
        let permit = permit();
        let mut cdb = [0u8; 10];
        cdb[0] = WRITE_10;
        cdb[8] = 1;
        assert_eq!(
            dev.prepare(&permit, ctx(Direction::FromHost, 2048), &cdb),
            Err(Completion::Check(WRITE_PROTECTED))
        );
        assert!(!dev.active());
        assert!(!dev.medium().expect("medium").active());

        // Write protection also wins over the zero-block no-data path.
        cdb[8] = 0;
        assert_eq!(
            dev.prepare(&permit, ctx(Direction::FromHost, 0), &cdb),
            Err(Completion::Check(WRITE_PROTECTED))
        );
    }

    #[test]
    fn read_cd_data_auto_and_audio() {
        let mut dev = drive(100);
        let permit = permit();
        let mut cdb = [0u8; 12];
        cdb[0] = READ_CD;
        cdb[1] = 0x00; // Expected Sector Type = All
        cdb[8] = 1; // 24-bit transfer length
        cdb[9] = 0x10; // Main Channel Selection: user data
        let mut data = [0u8; 2048];
        assert_eq!(
            dev.prepare(&permit, ctx(Direction::ToHost, 2048), &cdb),
            Ok(())
        );
        match dev.poll(&permit, Feedback::begin(), &mut data) {
            PollStep::Publish(plan) => assert_eq!(plan.bytes, 2048),
            other => panic!("expected publish, got {other:?}"),
        }
        match dev.poll(&permit, Feedback::plan_accepted(), &mut data) {
            PollStep::Io(crate::core::storage::StorageOp::Read { offset, buf, .. }) => {
                assert_eq!(offset, 0);
                assert_eq!(buf.len(), 2048);
            }
            other => panic!("expected read IO, got {other:?}"),
        }
        let io = Feedback::io_done(IoReceipt::test(2048, None, Effect::Known));
        assert!(matches!(
            dev.poll(&permit, io, &mut data),
            PollStep::Send { bytes, .. } if bytes.len() == 2048
        ));
        assert!(matches!(
            dev.poll(
                &permit,
                Feedback::host_sent(HostReceipt::test(2048, None)),
                &mut data
            ),
            PollStep::Complete(Completion::Good)
        ));

        let mut auto = [0u8; 12];
        auto[0] = READ_CD;
        auto[1] = 0x00;
        auto[8] = 1;
        auto[9] = 0x10;
        assert_eq!(
            dev.prepare(&permit, ctx(Direction::ToHost, 2048), &auto),
            Ok(())
        );
        dev.interrupt(&permit, Irq::Reset, KnownEffects::NONE)
            .expect("interrupt");

        let mut audio = [0u8; 12];
        audio[0] = READ_CD;
        audio[1] = 0x04; // Expected Sector Type = CD-DA
        audio[8] = 1;
        audio[9] = 0x10;
        assert_eq!(
            dev.prepare(&permit, ctx(Direction::ToHost, 2352), &audio),
            Err(Completion::Check(INVALID_FIELD))
        );
        audio[1] = 0x0C; // Mode 2 Form 1 is not supported
        assert_eq!(
            dev.prepare(&permit, ctx(Direction::ToHost, 2048), &audio),
            Err(Completion::Check(INVALID_FIELD))
        );
    }

    #[test]
    fn close_track_session_selects_the_medium_transition() {
        let mut dev = drive(100);
        let permit = permit();
        let mut cdb = [0u8; 10];
        cdb[0] = CLOSE_TRACK_SESSION;
        // Close function 000b is reserved.
        assert_eq!(
            dev.prepare(&permit, ctx(Direction::None, 0), &cdb),
            Err(Completion::Check(INVALID_FIELD))
        );

        // Function 001b (track) is routed to the medium, which reports a
        // no-op success for already-closed media.
        cdb[2] = 0x01;
        assert_eq!(
            dev.prepare(&permit, ctx(Direction::None, 0), &cdb),
            Err(Completion::Good)
        );
        assert!(!dev.active());

        // Function 010b (session) is also a no-op success on a read-only CD.
        cdb[2] = 0x02;
        assert_eq!(
            dev.prepare(&permit, ctx(Direction::None, 0), &cdb),
            Err(Completion::Good)
        );

        // Functions 011b..111b are reserved for CD-R/-RW.
        for function in 3..=7 {
            cdb[2] = function;
            assert_eq!(
                dev.prepare(&permit, ctx(Direction::None, 0), &cdb),
                Err(Completion::Check(INVALID_FIELD)),
                "close function {function} must be rejected"
            );
        }

        cdb[2] = 0x01;
        cdb[1] = 0x02; // reserved byte 1 bit
        assert_eq!(
            dev.prepare(&permit, ctx(Direction::None, 0), &cdb),
            Err(Completion::Check(INVALID_FIELD))
        );
    }

    #[test]
    fn format_and_blank_are_wired_to_the_zero_fill_slice() {
        // The old stub rejected both opcodes; this test now pins the new
        // contract: FORMAT on read-only media is a write-protect CHECK, BLANK
        // with a non-zero blanking type is an INVALID FIELD CHECK.
        let mut dev = drive(100);
        let permit = permit();
        let cdb = [FORMAT_UNIT, 0, 0, 0, 0, 0];
        assert_eq!(
            dev.prepare(&permit, ctx(Direction::None, 0), &cdb),
            Err(Completion::Check(WRITE_PROTECTED))
        );
        let blank = [BLANK, 0x01, 0, 0, 0, 0];
        assert_eq!(
            dev.prepare(&permit, ctx(Direction::None, 0), &blank),
            Err(Completion::Check(INVALID_FIELD))
        );
    }

    // ── FORMAT/BLANK long-operation fixtures ──────────────────────────

    #[test]
    fn format_and_blank_admit_an_unformatted_blank_medium() {
        let permit = permit();
        let mut dev = MmcDrive::new(SpyMedium::new(MmcWriteMode::Blank, 1));
        let cdb = [FORMAT_UNIT, 0, 0, 0, 0, 0];
        assert_eq!(dev.prepare(&permit, ctx(Direction::None, 0), &cdb), Ok(()));
        assert!(matches!(
            dev.long,
            LongOp::Foreground { .. } | LongOp::Settled { .. }
        ));
        dev.interrupt(&permit, Irq::Reset, KnownEffects::NONE)
            .expect("interrupt");

        let blank = [BLANK, 0, 0, 0, 0, 0];
        assert_eq!(
            dev.prepare(&permit, ctx(Direction::None, 0), &blank),
            Ok(())
        );
    }

    /// Medium double that records how often the drive touched it.
    struct SpyMedium {
        attrs: MmcAttrs,
        attrs_calls: Cell<u32>,
        begin_calls: Cell<u32>,
        poll_calls: Cell<u32>,
        commit_calls: Cell<u32>,
    }

    impl SpyMedium {
        fn new(write_mode: MmcWriteMode, sectors: u64) -> Self {
            Self {
                attrs: MmcAttrs {
                    write_mode,
                    block_len: 2048,
                    sectors,
                    tracks: 1,
                    sessions: 1,
                    write_protected: false,
                    needs_recovery: false,
                    profile: if matches!(write_mode, MmcWriteMode::Rewritable) {
                        0x0012
                    } else {
                        0x0008
                    },
                    current_features: if matches!(write_mode, MmcWriteMode::Rewritable) {
                        &[0x0010, 0x001D, 0x001E, 0x0020, 0x0024]
                    } else {
                        &[0x0010, 0x001D, 0x001E]
                    },
                },
                attrs_calls: Cell::new(0),
                begin_calls: Cell::new(0),
                poll_calls: Cell::new(0),
                commit_calls: Cell::new(0),
            }
        }

        fn rewritable(sectors: u64) -> Self {
            Self::new(MmcWriteMode::Rewritable, sectors)
        }

        fn read_only(sectors: u64) -> Self {
            Self::new(MmcWriteMode::ReadOnly, sectors)
        }

        fn snap(&self) -> (u32, u32, u32) {
            (
                self.attrs_calls.get(),
                self.begin_calls.get(),
                self.poll_calls.get(),
            )
        }
    }

    impl MmcMedium for SpyMedium {
        type State = ();

        fn attrs(&self) -> MmcAttrs {
            self.attrs_calls.set(self.attrs_calls.get() + 1);
            self.attrs
        }

        fn state(&self) -> &Self::State {
            &()
        }

        fn begin(&mut self, _op: MmcOp) -> Result<(), Completion> {
            self.begin_calls.set(self.begin_calls.get() + 1);
            Err(Completion::Good)
        }

        fn poll<'a>(&mut self, _fb: Feedback, _data: &'a mut [u8]) -> PollStep<'a> {
            self.poll_calls.set(self.poll_calls.get() + 1);
            PollStep::Idle
        }

        fn active(&self) -> bool {
            false
        }

        fn interrupt(&mut self, _reason: InterruptReason, _known: KnownEffects) {}

        fn commit(&mut self) -> Result<(), Completion> {
            self.commit_calls.set(self.commit_calls.get() + 1);
            Ok(())
        }

        fn track(&self, number: u16) -> Option<Track> {
            (number == 1).then_some(Track {
                number: 1,
                session: 1,
                start_lba: 0,
                blocks: self.attrs.sectors,
                kind: TrackKind::Data,
            })
        }

        fn session(&self, number: u16) -> Option<Session> {
            (number == 1).then_some(Session {
                number: 1,
                first_track: 1,
                last_track: 1,
                start_lba: 0,
            })
        }

        fn disc_info(&self) -> DiscInfo {
            DiscInfo {
                status: DiscStatus::Finalized,
                sessions: 1,
                last_session_lba: self.attrs.sectors.saturating_sub(1),
                writable: false,
                erasable: false,
                first_track: 1,
                first_track_last_session: 1,
                last_track_last_session: 1,
                last_session_state: 3,
                last_session_lead_in: None,
                last_possible_lead_out: None,
                disc_type: 0,
            }
        }
    }

    /// Format List Header + the single 8-byte Format Descriptor.
    fn format_params(header: u8, block_len: u32) -> [u8; FORMAT_PARAMS_LEN] {
        let mut p = [0u8; FORMAT_PARAMS_LEN];
        p[1] = header;
        p[2..4].copy_from_slice(&8u16.to_be_bytes());
        p[8] = 0x00; // Format Type 0 (full format)
        p[9] = (block_len >> 16) as u8;
        p[10] = (block_len >> 8) as u8;
        p[11] = block_len as u8;
        p
    }

    /// Outcome of the FmtData receive phase.
    enum ParamsOutcome {
        Complete(Completion),
        /// IMMED=0: the drive started the command-owned fill with an IO step.
        FillStarted,
    }

    /// Drive the Publish → Receive → HostReceived phase with `params`.
    fn receive_params(
        dev: &mut MmcDrive<SpyMedium>,
        permit: &CommandPermit,
        params: &[u8; FORMAT_PARAMS_LEN],
    ) -> ParamsOutcome {
        let mut data = [0u8; 4096];
        match dev.poll(permit, Feedback::begin(), &mut data) {
            PollStep::Publish(plan) => {
                assert_eq!(plan.direction, Direction::FromHost);
                assert_eq!(plan.bytes, FORMAT_PARAMS_LEN as u64);
            }
            other => panic!("expected parameter-list publish, got {other:?}"),
        }
        match dev.poll(permit, Feedback::plan_accepted(), &mut data) {
            PollStep::Receive { buf: bytes, .. } => assert_eq!(bytes.len(), FORMAT_PARAMS_LEN),
            other => panic!("expected parameter-list receive, got {other:?}"),
        }
        data[..FORMAT_PARAMS_LEN].copy_from_slice(params);
        match dev.poll(
            permit,
            Feedback::host_received(HostReceipt::test(FORMAT_PARAMS_LEN, None)),
            &mut data,
        ) {
            PollStep::Complete(completion) => ParamsOutcome::Complete(completion),
            PollStep::Io(_) => ParamsOutcome::FillStarted,
            other => panic!("unexpected step after parameter list: {other:?}"),
        }
    }

    /// Drive a resident long operation to completion and record its write
    /// offsets/lengths. Every passed buffer must be zeroed by the drive and the
    /// operation must end with exactly one durability `Sync`.
    fn drive_long(
        dev: &mut MmcDrive<SpyMedium>,
        permit: &CommandPermit,
        data: &mut [u8],
    ) -> Vec<(u64, usize)> {
        let mut ios = Vec::new();
        let mut syncs = 0usize;
        let mut fb = Feedback::begin();
        for _ in 0..64 {
            match dev.poll_long(permit, fb, data) {
                PollStep::Io(StorageOp::Write { offset, buf, .. }) => {
                    assert!(buf.iter().all(|b| *b == 0), "fill buffer must be zeroed");
                    ios.push((offset, buf.len()));
                    fb = Feedback::io_done(IoReceipt::test(buf.len(), None, Effect::Known));
                }
                PollStep::Io(StorageOp::Sync { resource: 0 }) => {
                    syncs += 1;
                    fb = Feedback::io_done(IoReceipt::test(0, None, Effect::Known));
                }
                PollStep::Complete(Completion::Good) => {
                    assert_eq!(syncs, 1, "the fill must end with exactly one Sync");
                    return ios;
                }
                other => panic!("unexpected long step: {other:?}"),
            }
        }
        panic!("resident long operation did not settle");
    }

    #[test]
    fn tur_reports_presence_health_and_empty_medium() {
        let permit = permit();
        let cctx = ctx(Direction::None, 0);
        let tur = [TEST_UNIT_READY, 0, 0, 0, 0, 0];

        let mut dev = MmcDrive::new(SpyMedium::rewritable(16));
        assert_eq!(dev.prepare(&permit, cctx, &tur), Err(Completion::Good));

        let mut broken = SpyMedium::rewritable(16);
        broken.attrs.needs_recovery = true;
        let mut dev = MmcDrive::new(broken);
        assert_eq!(
            dev.prepare(&permit, cctx, &tur),
            Err(Completion::Check(NEEDS_RECOVERY))
        );

        let mut empty = MmcDrive::new(SpyMedium::rewritable(16));
        assert!(empty.take_medium(&boundary()).is_some());
        assert_eq!(
            empty.prepare(&permit, cctx, &tur),
            Err(Completion::Check(MEDIUM_NOT_PRESENT))
        );
    }

    #[test]
    fn format_default_immed_zero_fills_in_poll() {
        let mut dev = MmcDrive::new(SpyMedium::rewritable(4));
        let permit = permit();
        let cdb = [FORMAT_UNIT, 0, 0, 0, 0, 0];
        assert_eq!(dev.prepare(&permit, ctx(Direction::None, 0), &cdb), Ok(()));
        let info = dev.long_info();
        assert_eq!(info.phase, LongPhase::Foreground);
        assert!(!info.write_accessible);
        assert_eq!(info.progress, Some(0));
        // The zero-fill is drive-owned: the medium is never asked to begin.
        assert_eq!(dev.medium().expect("medium").begin_calls.get(), 0);

        let mut data = [0u8; 4096];
        match dev.poll(&permit, Feedback::begin(), &mut data) {
            PollStep::Io(StorageOp::Write {
                resource,
                offset,
                buf,
            }) => {
                assert_eq!(resource, 0);
                assert_eq!(offset, 0);
                assert_eq!(buf.len(), 4096);
                assert!(buf.iter().all(|b| *b == 0));
            }
            other => panic!("expected first fill IO, got {other:?}"),
        }
        match dev.poll(
            &permit,
            Feedback::io_done(IoReceipt::test(4096, None, Effect::Known)),
            &mut data,
        ) {
            PollStep::Io(StorageOp::Write { offset, buf, .. }) => {
                assert_eq!(offset, 4096);
                assert_eq!(buf.len(), 4096);
                assert!(buf.iter().all(|b| *b == 0));
            }
            other => panic!("expected second fill IO, got {other:?}"),
        }
        assert_eq!(dev.long_info().progress, Some(50));
        match dev.poll(
            &permit,
            Feedback::io_done(IoReceipt::test(4096, None, Effect::Known)),
            &mut data,
        ) {
            PollStep::Io(StorageOp::Sync { resource: 0 }) => {}
            other => panic!("expected the final durability sync, got {other:?}"),
        }
        // The final durability sync is pending: progress is 99, never 100.
        assert_eq!(dev.long_info().progress, Some(99));
        // A repeated Begin while the sync is in flight must not reissue it.
        assert!(matches!(
            dev.poll_long(&permit, Feedback::begin(), &mut data),
            PollStep::Idle
        ));
        match dev.poll(
            &permit,
            Feedback::io_done(IoReceipt::test(0, None, Effect::Known)),
            &mut data,
        ) {
            PollStep::Complete(Completion::Good) => {}
            other => panic!("expected GOOD after the sync, got {other:?}"),
        }
        assert!(!dev.active());
        let info = dev.long_info();
        assert_eq!(info.phase, LongPhase::Settled);
        assert!(info.write_accessible);
        assert_eq!(info.progress, Some(100));
        assert!(matches!(
            dev.poll_long(&permit, Feedback::begin(), &mut data),
            PollStep::Idle
        ));
    }

    #[test]
    fn format_parameter_list_immed_one_completes_then_poll_long_fills() {
        let mut dev = MmcDrive::new(SpyMedium::rewritable(4));
        let permit = permit();
        let cdb = [FORMAT_UNIT, 0x11, 0, 0, 0, 0];
        assert_eq!(
            dev.prepare(
                &permit,
                ctx(Direction::FromHost, FORMAT_PARAMS_LEN as u64),
                &cdb
            ),
            Ok(())
        );
        // FOV | DCRT | Immed, the Windows/dvd+rw-format fixture.
        let params = format_params(0xA2, 0);
        match receive_params(&mut dev, &permit, &params) {
            ParamsOutcome::Complete(Completion::Good) => {}
            ParamsOutcome::Complete(other) => panic!("expected GOOD, got {other:?}"),
            ParamsOutcome::FillStarted => panic!("IMMED=1 must not start the fill in poll"),
        }
        assert!(!dev.active());
        let info = dev.long_info();
        assert_eq!(info.phase, LongPhase::Foreground);
        assert_eq!(info.progress, Some(0));
        assert_eq!(dev.medium().expect("medium").begin_calls.get(), 0);

        let mut data = [0u8; 4096];
        assert_eq!(
            drive_long(&mut dev, &permit, &mut data),
            vec![(0, 4096), (4096, 4096)]
        );
        let info = dev.long_info();
        assert_eq!(info.phase, LongPhase::Settled);
        assert!(info.write_accessible);
        assert_eq!(info.progress, Some(100));
        assert!(matches!(
            dev.poll_long(&permit, Feedback::begin(), &mut data),
            PollStep::Idle
        ));
    }

    #[test]
    fn poll_long_io_borrows_the_caller_bank_not_the_device() {
        // Borrow-domain proof: the returned `PollStep::Io` may be held while
        // the device is read (`long_info`/`medium`), so a concurrent query is
        // possible. The IO buffer points into the caller's bank.
        let permit = permit();
        let mut dev = MmcDrive::new(SpyMedium::rewritable(4));
        assert_eq!(
            dev.prepare(
                &permit,
                ctx(Direction::None, 0),
                &[FORMAT_UNIT, 0, 0, 0, 0, 0]
            ),
            Ok(())
        );
        let mut bank = [0xA5u8; 8192];
        let base = bank.as_ptr();
        let op = dev.poll_long(&permit, Feedback::begin(), &mut bank);
        let info = dev.long_info();
        let medium = dev.medium().expect("medium");
        assert_eq!(info.phase, LongPhase::Foreground);
        assert_eq!(medium.attrs().sectors, 4);
        match op {
            PollStep::Io(StorageOp::Write { offset, buf, .. }) => {
                assert_eq!(offset, 0);
                assert_eq!(buf.as_ptr(), base, "IO must point into the caller bank");
                assert!(buf.iter().all(|b| *b == 0), "the bank is zeroed in place");
            }
            other => panic!("expected a write into the caller bank, got {other:?}"),
        }
    }

    #[test]
    fn final_fill_sync_failure_settles_without_good_or_replay() {
        let permit = permit();
        let mut dev = MmcDrive::new(SpyMedium::rewritable(2));
        assert_eq!(
            dev.prepare(
                &permit,
                ctx(Direction::None, 0),
                &[FORMAT_UNIT, 0, 0, 0, 0, 0]
            ),
            Ok(())
        );
        let mut data = [0u8; 4096];
        assert!(matches!(
            dev.poll(&permit, Feedback::begin(), &mut data),
            PollStep::Io(StorageOp::Write { .. })
        ));
        assert!(matches!(
            dev.poll(
                &permit,
                Feedback::io_done(IoReceipt::test(4096, None, Effect::Known)),
                &mut data
            ),
            PollStep::Io(StorageOp::Sync { resource: 0 })
        ));
        // Pressing Begin again while the sync is in flight must not reissue it.
        assert!(matches!(
            dev.poll_long(&permit, Feedback::begin(), &mut data),
            PollStep::Idle
        ));
        assert!(matches!(
            dev.poll(
                &permit,
                Feedback::io_done(IoReceipt::test(0, Some(Fault::Io), Effect::Known)),
                &mut data
            ),
            PollStep::Complete(Completion::Check(MEDIUM_ERROR))
        ));
        let info = dev.long_info();
        assert_eq!(info.phase, LongPhase::Settled);
        assert_eq!(info.error, Some(Fault::Io));
        assert_eq!(info.progress, Some(99), "a failed settle never reports 100");
        // The settled operation never replays the sync or a write.
        assert!(matches!(
            dev.poll_long(&permit, Feedback::begin(), &mut data),
            PollStep::Idle
        ));
    }

    #[test]
    fn final_fill_sync_with_unknown_effect_is_an_io_fault() {
        let permit = permit();
        for receipt in [
            IoReceipt::test(0, None, Effect::UnknownRemainder),
            IoReceipt::test(1, None, Effect::Known),
        ] {
            let mut dev = MmcDrive::new(SpyMedium::rewritable(2));
            assert_eq!(
                dev.prepare(
                    &permit,
                    ctx(Direction::None, 0),
                    &[FORMAT_UNIT, 0, 0, 0, 0, 0]
                ),
                Ok(())
            );
            let mut data = [0u8; 4096];
            assert!(matches!(
                dev.poll(&permit, Feedback::begin(), &mut data),
                PollStep::Io(StorageOp::Write { .. })
            ));
            assert!(matches!(
                dev.poll(
                    &permit,
                    Feedback::io_done(IoReceipt::test(4096, None, Effect::Known)),
                    &mut data
                ),
                PollStep::Io(StorageOp::Sync { resource: 0 })
            ));
            assert!(matches!(
                dev.poll(&permit, Feedback::io_done(receipt), &mut data),
                PollStep::Complete(Completion::Check(MEDIUM_ERROR))
            ));
            assert_eq!(dev.long_info().error, Some(Fault::Io));
            assert_eq!(dev.long_info().progress, Some(99));
        }
    }

    #[test]
    fn zero_byte_fills_settle_without_io() {
        // A writable medium with no sectors (e.g. `from_bytes(0)`) arms an
        // already-settled fill. Both encodings must complete GOOD and clear the
        // command query, otherwise the LU wedges on `Busy`.
        let permit = permit();

        let mut dev = MmcDrive::new(SpyMedium::rewritable(0));
        let cdb = [FORMAT_UNIT, 0x11, 0, 0, 0, 0];
        assert_eq!(
            dev.prepare(
                &permit,
                ctx(Direction::FromHost, FORMAT_PARAMS_LEN as u64),
                &cdb
            ),
            Ok(())
        );
        match receive_params(&mut dev, &permit, &format_params(0x80, 0)) {
            ParamsOutcome::Complete(Completion::Good) => {}
            ParamsOutcome::Complete(other) => panic!("expected GOOD, got {other:?}"),
            ParamsOutcome::FillStarted => panic!("a zero-byte fill must not issue IO"),
        }
        assert!(!dev.active(), "the format query must be cleared");
        let info = dev.long_info();
        assert_eq!(info.phase, LongPhase::Settled);
        assert!(info.write_accessible);
        assert_eq!(info.progress, Some(100));
        assert_eq!(dev.medium().expect("medium").begin_calls.get(), 0);

        // The byte-1 default encoding takes the same settled path.
        let mut dev = MmcDrive::new(SpyMedium::rewritable(0));
        let mut data = [0u8; 8];
        assert_eq!(
            dev.prepare(
                &permit,
                ctx(Direction::None, 0),
                &[FORMAT_UNIT, 0, 0, 0, 0, 0]
            ),
            Ok(())
        );
        assert!(matches!(
            dev.poll(&permit, Feedback::begin(), &mut data),
            PollStep::Complete(Completion::Good)
        ));
        assert!(!dev.active());
        assert_eq!(dev.long_info().phase, LongPhase::Settled);

        // BLANK on the same zero-sector medium.
        let mut dev = MmcDrive::new(SpyMedium::rewritable(0));
        assert_eq!(
            dev.prepare(&permit, ctx(Direction::None, 0), &[BLANK, 0, 0, 0, 0, 0]),
            Ok(())
        );
        assert!(matches!(
            dev.poll(&permit, Feedback::begin(), &mut data),
            PollStep::Complete(Completion::Good)
        ));
        assert!(!dev.active());
        assert_eq!(dev.long_info().phase, LongPhase::Settled);
    }

    #[test]
    fn format_parameter_list_tryout_makes_no_io_and_keeps_idle() {
        let mut dev = MmcDrive::new(SpyMedium::rewritable(4));
        let permit = permit();
        let cdb = [FORMAT_UNIT, 0x11, 0, 0, 0, 0];
        assert_eq!(
            dev.prepare(
                &permit,
                ctx(Direction::FromHost, FORMAT_PARAMS_LEN as u64),
                &cdb
            ),
            Ok(())
        );
        // FOV | Try-out.
        let params = format_params(0x84, 2048);
        match receive_params(&mut dev, &permit, &params) {
            ParamsOutcome::Complete(Completion::Good) => {}
            ParamsOutcome::Complete(other) => panic!("expected GOOD, got {other:?}"),
            ParamsOutcome::FillStarted => panic!("Try-out must not start a fill"),
        }
        assert!(!dev.active());
        assert_eq!(dev.long_info().phase, LongPhase::Idle);
        let mut data = [0u8; 4096];
        assert!(matches!(
            dev.poll_long(&permit, Feedback::begin(), &mut data),
            PollStep::Idle
        ));
        assert_eq!(dev.medium().expect("medium").begin_calls.get(), 0);
    }

    #[test]
    fn format_parameter_list_validation() {
        let permit = permit();
        let cdb = [FORMAT_UNIT, 0x11, 0, 0, 0, 0];
        let cctx = ctx(Direction::FromHost, FORMAT_PARAMS_LEN as u64);
        let invalid_list = Sense::new(0x05, 0x26, 0x00);

        // Format Type != 0.
        let mut dev = MmcDrive::new(SpyMedium::rewritable(4));
        assert_eq!(dev.prepare(&permit, cctx, &cdb), Ok(()));
        let mut params = format_params(0x82, 2048);
        params[8] = 0x01;
        assert!(matches!(
            receive_params(&mut dev, &permit, &params),
            ParamsOutcome::Complete(Completion::Check(sense)) if sense == invalid_list
        ));
        assert_eq!(dev.long_info().phase, LongPhase::Idle);

        // Format List Length != 8.
        let mut dev = MmcDrive::new(SpyMedium::rewritable(4));
        assert_eq!(dev.prepare(&permit, cctx, &cdb), Ok(()));
        let mut params = format_params(0x82, 2048);
        params[2..4].copy_from_slice(&0u16.to_be_bytes());
        assert!(matches!(
            receive_params(&mut dev, &permit, &params),
            ParamsOutcome::Complete(Completion::Check(sense)) if sense == invalid_list
        ));

        // Block length other than 2048/0.
        let mut dev = MmcDrive::new(SpyMedium::rewritable(4));
        assert_eq!(dev.prepare(&permit, cctx, &cdb), Ok(()));
        let params = format_params(0x82, 512);
        assert!(matches!(
            receive_params(&mut dev, &permit, &params),
            ParamsOutcome::Complete(Completion::Check(sense)) if sense == invalid_list
        ));

        // Format Code 010b is not supported.
        let mut dev = MmcDrive::new(SpyMedium::rewritable(4));
        assert_eq!(
            dev.prepare(&permit, cctx, &[FORMAT_UNIT, 0x12, 0, 0, 0, 0]),
            Err(Completion::Check(INVALID_FIELD))
        );
        // FmtData with Format Code 000b is not supported.
        assert_eq!(
            dev.prepare(&permit, cctx, &[FORMAT_UNIT, 0x10, 0, 0, 0, 0]),
            Err(Completion::Check(INVALID_FIELD))
        );
        // A parameter-list encoding needs its 12 declared Data-Out bytes.
        assert_eq!(
            dev.prepare(&permit, ctx(Direction::FromHost, 0), &cdb),
            Err(Completion::Check(INVALID_FIELD))
        );
    }

    #[test]
    fn format_unit_parameters_reject_a_sub_list_bank_as_internal_failure() {
        // A parameter list that cannot be staged is the target's own inability
        // (HARDWARE ERROR / INTERNAL TARGET FAILURE), not a CDB problem, and
        // never a caller-bank sense. The documented bank floor makes it
        // unreachable through a transport.
        let permit = permit();
        let cdb = [FORMAT_UNIT, 0x11, 0, 0, 0, 0];
        let mut small = [0u8; FORMAT_PARAMS_LEN - 4];

        // Publish step.
        let mut dev = MmcDrive::new(SpyMedium::rewritable(2));
        assert_eq!(
            dev.prepare(&permit, ctx(Direction::FromHost, 12), &cdb),
            Ok(())
        );
        assert!(matches!(
            dev.poll(&permit, Feedback::begin(), &mut small),
            PollStep::Complete(Completion::Check(INTERNAL_FAILURE))
        ));
        assert!(!dev.active());
        assert_eq!(dev.long_info().phase, LongPhase::Idle);

        // PlanAccepted step.
        let mut dev = MmcDrive::new(SpyMedium::rewritable(2));
        dev.prepare(&permit, ctx(Direction::FromHost, 12), &cdb)
            .expect("prepare");
        let mut big = [0u8; 4096];
        assert!(matches!(
            dev.poll(&permit, Feedback::begin(), &mut big),
            PollStep::Publish(_)
        ));
        assert!(matches!(
            dev.poll(&permit, Feedback::plan_accepted(), &mut small),
            PollStep::Complete(Completion::Check(INTERNAL_FAILURE))
        ));
        assert!(!dev.active());

        // HostReceived step.
        let mut dev = MmcDrive::new(SpyMedium::rewritable(2));
        dev.prepare(&permit, ctx(Direction::FromHost, 12), &cdb)
            .expect("prepare");
        assert!(matches!(
            dev.poll(&permit, Feedback::begin(), &mut big),
            PollStep::Publish(_)
        ));
        assert!(matches!(
            dev.poll(&permit, Feedback::plan_accepted(), &mut big),
            PollStep::Receive { buf: bytes, .. } if bytes.len() == FORMAT_PARAMS_LEN
        ));
        assert!(matches!(
            dev.poll(
                &permit,
                Feedback::host_received(HostReceipt::test(FORMAT_PARAMS_LEN, None)),
                &mut small
            ),
            PollStep::Complete(Completion::Check(INTERNAL_FAILURE))
        ));
        assert!(!dev.active());
        assert_eq!(dev.long_info().phase, LongPhase::Idle);
    }

    #[test]
    fn format_write_protection_precedes_the_medium() {
        let permit = permit();
        let cdb = [FORMAT_UNIT, 0, 0, 0, 0, 0];
        let mut dev = MmcDrive::new(SpyMedium::read_only(4));
        assert_eq!(
            dev.prepare(&permit, ctx(Direction::None, 0), &cdb),
            Err(Completion::Check(WRITE_PROTECTED))
        );
        assert_eq!(dev.long_info().phase, LongPhase::Idle);
        assert_eq!(dev.medium().expect("medium").begin_calls.get(), 0);

        let mut empty = MmcDrive::new(SpyMedium::rewritable(4));
        assert!(empty.take_medium(&boundary()).is_some());
        assert_eq!(
            empty.prepare(&permit, ctx(Direction::None, 0), &cdb),
            Err(Completion::Check(MEDIUM_NOT_PRESENT))
        );
    }

    #[test]
    fn blank_arms_the_zero_fill_and_validates_the_type() {
        let permit = permit();
        let mut dev = MmcDrive::new(SpyMedium::rewritable(2));
        let mut data = [0u8; 4096];
        // Blanking type 0, IMMED=0.
        assert_eq!(
            dev.prepare(&permit, ctx(Direction::None, 0), &[BLANK, 0, 0, 0, 0, 0]),
            Ok(())
        );
        match dev.poll(&permit, Feedback::begin(), &mut data) {
            PollStep::Io(StorageOp::Write { offset, buf, .. }) => {
                assert_eq!(offset, 0);
                assert_eq!(buf.len(), 4096);
                assert!(buf.iter().all(|b| *b == 0));
            }
            other => panic!("expected fill IO, got {other:?}"),
        }
        assert!(matches!(
            dev.poll(
                &permit,
                Feedback::io_done(IoReceipt::test(4096, None, Effect::Known)),
                &mut data
            ),
            PollStep::Io(StorageOp::Sync { resource: 0 })
        ));
        assert!(matches!(
            dev.poll(
                &permit,
                Feedback::io_done(IoReceipt::test(0, None, Effect::Known)),
                &mut data
            ),
            PollStep::Complete(Completion::Good)
        ));
        assert_eq!(dev.long_info().phase, LongPhase::Settled);

        // Any other blanking type is rejected before the medium.
        let mut dev = MmcDrive::new(SpyMedium::rewritable(2));
        assert_eq!(
            dev.prepare(&permit, ctx(Direction::None, 0), &[BLANK, 0x01, 0, 0, 0, 0]),
            Err(Completion::Check(INVALID_FIELD))
        );

        // Read-only media cannot be blanked.
        let mut dev = MmcDrive::new(SpyMedium::read_only(2));
        assert_eq!(
            dev.prepare(&permit, ctx(Direction::None, 0), &[BLANK, 0, 0, 0, 0, 0]),
            Err(Completion::Check(WRITE_PROTECTED))
        );
    }

    #[test]
    fn blank_immed_one_completes_and_the_resident_fill_runs_later() {
        let mut dev = MmcDrive::new(SpyMedium::rewritable(2));
        let permit = permit();
        // IMMED is CDB byte 1 bit 5 (MMC-6 Table 229).
        assert_eq!(
            dev.prepare(&permit, ctx(Direction::None, 0), &[BLANK, 0x20, 0, 0, 0, 0]),
            Ok(())
        );
        let mut data = [0u8; 4096];
        assert!(matches!(
            dev.poll(&permit, Feedback::begin(), &mut data),
            PollStep::Complete(Completion::Good)
        ));
        assert_eq!(dev.long_info().phase, LongPhase::Foreground);
        assert_eq!(drive_long(&mut dev, &permit, &mut data), vec![(0, 4096)]);
        assert_eq!(dev.long_info().phase, LongPhase::Settled);
    }

    #[test]
    fn foreground_gate_rejects_every_opcode_before_medium_access() {
        let mut dev = MmcDrive::new(SpyMedium::rewritable(4));
        let permit = permit();
        // FmtData arms the resident operation in `prepare`; it need not be
        // completed for the gate to be up.
        let cdb = [FORMAT_UNIT, 0x11, 0, 0, 0, 0];
        assert_eq!(
            dev.prepare(
                &permit,
                ctx(Direction::FromHost, FORMAT_PARAMS_LEN as u64),
                &cdb
            ),
            Ok(())
        );
        assert_eq!(dev.long_info().phase, LongPhase::Foreground);
        let before = dev.medium().expect("medium").snap();

        let opcodes: [([u8; 12], Direction, u64); 7] = [
            (
                [TEST_UNIT_READY, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0],
                Direction::None,
                0,
            ),
            (
                [READ_10, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0],
                Direction::ToHost,
                2048,
            ),
            (
                [WRITE_10, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0],
                Direction::FromHost,
                2048,
            ),
            (
                [READ_TOC, 0, 0, 0, 0, 0, 0, 0, 20, 0, 0, 0],
                Direction::ToHost,
                20,
            ),
            (
                [READ_CD, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0],
                Direction::ToHost,
                2048,
            ),
            (
                [CLOSE_TRACK_SESSION, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0],
                Direction::None,
                0,
            ),
            ([BLANK, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0], Direction::None, 0),
        ];
        for (cdb, direction, bytes) in opcodes {
            assert_eq!(
                dev.prepare(&permit, ctx(direction, bytes), &cdb),
                Err(Completion::Check(FORMAT_IN_PROGRESS)),
                "opcode {:#04x} must be gated",
                cdb[0]
            );
        }
        assert_eq!(
            dev.medium().expect("medium").snap(),
            before,
            "the gate must not touch the medium"
        );
    }

    #[test]
    fn close_routes_to_the_medium_without_a_local_commit() {
        let permit = permit();
        let mut cdb = [0u8; 10];
        cdb[0] = CLOSE_TRACK_SESSION;
        cdb[2] = 0x01; // close function 001b

        let mut dev = MmcDrive::new(SpyMedium::rewritable(2));
        assert_eq!(
            dev.prepare(&permit, ctx(Direction::None, 0), &cdb),
            Err(Completion::Good)
        );
        let medium = dev.medium().expect("medium");
        assert_eq!(
            medium.begin_calls.get(),
            1,
            "the medium owns the transition"
        );
        assert_eq!(
            medium.commit_calls.get(),
            0,
            "CLOSE is not a metadata commit"
        );
    }

    #[test]
    fn format_fill_chunk_is_capped_at_one_mib() {
        // 2 MiB medium, 2 MiB caller bank: one step still issues at most 1 MiB.
        let mut dev = MmcDrive::new(SpyMedium::rewritable(1024));
        let permit = permit();
        assert_eq!(
            dev.prepare(
                &permit,
                ctx(Direction::None, 0),
                &[FORMAT_UNIT, 0, 0, 0, 0, 0]
            ),
            Ok(())
        );
        let mut data = vec![0u8; 2 * 1024 * 1024];
        match dev.poll(&permit, Feedback::begin(), &mut data) {
            PollStep::Io(StorageOp::Write { offset, buf, .. }) => {
                assert_eq!(offset, 0);
                assert_eq!(buf.len(), FORMAT_CHUNK_MAX);
            }
            other => panic!("expected capped fill IO, got {other:?}"),
        }
    }

    #[test]
    fn default_drive_is_hyper_multi_and_dvdram_is_an_explicit_view() {
        // The medium class is not the drive class: `new` is Hyper-Multi for a
        // read-only CD and for a rewritable DVD-RAM alike.
        let read_only = MmcDrive::new(SpyMedium::read_only(4));
        let rewritable = MmcDrive::new(SpyMedium::rewritable(4));
        for dev in [&read_only, &rewritable] {
            let profile = dev.spc_profile().expect("profile");
            assert_eq!(profile.mode_sense(false, 0x2A, false, 0, None), Some(68));
            assert_eq!(profile.mode_sense(false, 0x3F, false, 0, None), Some(198));
        }
        // The 36-byte DVD-RAM view is an explicit capability preset.
        let explicit = MmcDrive::new_with_caps(SpyMedium::rewritable(4), MmcCaps::dvdram());
        let profile = explicit.spc_profile().expect("profile");
        assert_eq!(profile.mode_sense(false, 0x2A, false, 0, None), Some(40));
        assert_eq!(profile.mode_sense(false, 0x3F, false, 0, None), Some(170));
    }

    #[test]
    fn zero_block_read_completes_good_with_no_io() {
        let mut dev = drive(100);
        let permit = permit();
        let cdb = read_cdb(0, 0);
        assert_eq!(
            dev.prepare(&permit, ctx(Direction::ToHost, 0), &cdb),
            Err(Completion::Good)
        );
        assert!(!dev.active());
    }

    #[test]
    fn read_validation_rejects_bad_fields_and_ranges() {
        let mut dev = drive(100);
        let permit = permit();
        assert_eq!(
            dev.prepare(&permit, ctx(Direction::ToHost, 2048), &read_cdb(100, 1)),
            Err(Completion::Check(LBA_OUT_OF_RANGE))
        );
        let mut bad = read_cdb(0, 1);
        bad[1] = 0x01;
        assert_eq!(
            dev.prepare(&permit, ctx(Direction::ToHost, 2048), &bad),
            Err(Completion::Check(INVALID_FIELD))
        );
        let mut reserved = read_cdb(0, 1);
        reserved[6] = 0x01;
        assert_eq!(
            dev.prepare(&permit, ctx(Direction::ToHost, 2048), &reserved),
            Err(Completion::Check(INVALID_FIELD))
        );
        assert_eq!(
            dev.prepare(&permit, ctx(Direction::FromHost, 2048), &read_cdb(0, 1)),
            Err(Completion::Check(INVALID_FIELD))
        );
    }

    #[test]
    fn sync_cache_publishes_no_data_and_completes() {
        let mut dev = drive(100);
        let permit = permit();
        let mut cdb = [0u8; 10];
        cdb[0] = SYNC_CACHE_10;
        assert_eq!(dev.prepare(&permit, ctx(Direction::None, 0), &cdb), Ok(()));
        let mut data = [0u8; 0];
        match dev.poll(&permit, Feedback::begin(), &mut data) {
            PollStep::Publish(plan) => assert_eq!(
                plan,
                DataPlan {
                    direction: Direction::None,
                    bytes: 0,
                }
            ),
            other => panic!("expected publish, got {other:?}"),
        }
        assert!(matches!(
            dev.poll(&permit, Feedback::plan_accepted(), &mut data),
            PollStep::Io(crate::core::storage::StorageOp::Sync { resource: 0 })
        ));
        assert!(matches!(
            dev.poll(
                &permit,
                Feedback::io_done(IoReceipt::test(0, None, Effect::Known)),
                &mut data
            ),
            PollStep::Complete(Completion::Good)
        ));
        assert!(!dev.active());

        cdb[1] = 0x02; // IMMED
        assert_eq!(
            dev.prepare(&permit, ctx(Direction::None, 0), &cdb),
            Err(Completion::Check(INVALID_FIELD))
        );
    }

    #[test]
    fn read_larger_than_the_bank_streams_from_the_medium() {
        let mut dev = drive(100);
        let permit = permit();
        assert_eq!(
            dev.prepare(&permit, ctx(Direction::ToHost, 2048), &read_cdb(0, 1)),
            Ok(())
        );
        let mut data = [0u8; 16];
        match dev.poll(&permit, Feedback::begin(), &mut data) {
            PollStep::Publish(plan) => assert_eq!(plan.bytes, 2048),
            other => panic!("expected publish, got {other:?}"),
        }
        let mut fb = Feedback::plan_accepted();
        let mut prefetches = 0;
        let mut ios = 0;
        loop {
            match dev.poll(&permit, fb, &mut data) {
                PollStep::Io(StorageOp::Read { buf, .. }) => {
                    assert_eq!(buf.len(), 16);
                    ios += 1;
                    fb = Feedback::io_done(IoReceipt::test(16, None, Effect::Known));
                }
                PollStep::Prefetch(crate::core::storage::PrefetchOp::Read { buf, .. }) => {
                    assert_eq!(buf.len(), 16);
                    prefetches += 1;
                    fb = Feedback::io_done(IoReceipt::test(16, None, Effect::Known));
                }
                PollStep::Send { bytes, .. } => {
                    assert_eq!(bytes.len(), 16);
                    fb = Feedback::host_sent(HostReceipt::test(16, None));
                }
                PollStep::Complete(completion) => {
                    assert_eq!(completion, Completion::Good);
                    break;
                }
                other => panic!("unexpected step {other:?}"),
            }
        }
        assert_eq!(ios, 1, "only the first chunk is a normal read");
        assert_eq!(prefetches, 2048 / 16 - 1);
        assert_eq!(dev.io_issues(), 1);
        assert_eq!(dev.prefetch_issues(), 2048 / 16 - 1);
        assert!(!dev.active());
    }

    #[test]
    fn no_medium_get_configuration_matches_a_zero_sector_medium() {
        // No medium: after `take_medium` the profile answers instead of delegating.
        let mut dev = drive(100);
        let removed = dev.take_medium(&boundary()).expect("medium");
        assert_eq!(removed.attrs().sectors, 100);
        let profile = dev.spc_profile().expect("profile");

        let mut absent = [0u8; 128];
        let len = profile
            .get_configuration(0, 0, Some(&mut absent))
            .expect("GC must answer without a medium");
        let mut zero = [0u8; 128];
        let zero_len = MmcDrive::new(FlatCdMedium::read_only(0))
            .spc_profile()
            .expect("profile")
            .get_configuration(0, 0, Some(&mut zero))
            .expect("GC must answer for a zero-sector medium");
        assert_eq!((len, &absent), (zero_len, &zero));
        assert_eq!(
            &absent[6..8],
            &0x0000u16.to_be_bytes(),
            "no current profile"
        );
        assert_eq!(absent[11], 12, "recorder, CD-R and CD-ROM stay listed");
        assert_eq!(&absent[12..14], &0x0012u16.to_be_bytes());
        assert_eq!(absent[15], 0);
        assert_eq!(&absent[16..18], &0x0009u16.to_be_bytes());
        assert_eq!(absent[19], 0);
        assert_eq!(&absent[20..22], &0x0008u16.to_be_bytes());
        assert_eq!(absent[23], 0);
        // RT=10b and RT=01b also answer from the absent default.
        assert!(profile.get_configuration(2, 0x0050, None).is_some());
        assert!(profile.get_configuration(1, 0x0010, None).is_some());
        assert_eq!(profile.get_configuration(3, 0, None), None);
    }

    #[test]
    fn no_medium_event_status_matches_a_zero_sector_medium() {
        let mut dev = drive(100);
        assert!(dev.take_medium(&boundary()).is_some());
        let profile = dev.spc_profile().expect("profile");

        let mut absent = [0u8; 8];
        let len = profile
            .event_status(0x10, Some(&mut absent))
            .expect("GESN must answer without a medium");
        let mut zero = [0u8; 8];
        let zero_len = MmcDrive::new(FlatCdMedium::read_only(0))
            .spc_profile()
            .expect("profile")
            .event_status(0x10, Some(&mut zero))
            .expect("GESN must answer for a zero-sector medium");
        assert_eq!((len, &absent), (zero_len, &zero));
        assert_eq!(&absent[0..2], &6u16.to_be_bytes());
        assert_eq!(absent[3], 0x10, "Media class advertised");
        assert_eq!(absent[4], 0x00, "NoChg");
        assert_eq!(absent[5], 0x00, "no media present");
        // No class requested: header-only, same advertised class.
        assert_eq!(profile.event_status(0x00, None), Some(4));
    }

    /// Find a GET CONFIGURATION feature descriptor in a response.
    fn feature_at(buf: &[u8], n: usize, code: u16) -> Option<usize> {
        let mut at = 8;
        while at + 4 <= n {
            let found = u16::from_be_bytes([buf[at], buf[at + 1]]);
            let len = buf[at + 3] as usize;
            if found == code {
                return Some(at);
            }
            at += 4 + len;
        }
        None
    }

    #[test]
    fn no_medium_answers_drive_queries_and_rejects_media_commands() {
        let mut dev = drive(100);
        let boundary = boundary();
        let removed = dev.take_medium(&boundary).expect("medium");
        assert!(dev.medium().is_none());
        assert_eq!(removed.attrs().sectors, 100);

        let permit = permit();
        assert_eq!(
            dev.prepare(&permit, ctx(Direction::ToHost, 2048), &read_cdb(0, 1)),
            Err(Completion::Check(MEDIUM_NOT_PRESENT))
        );
        let profile = dev.spc_profile().expect("profile");
        assert_eq!(profile.read_capacity(), None);
        // MODE SENSE describes the drive: it answers with no medium. Only the
        // page that describes the mounted disc's write parameters would be
        // medium-specific; it answers defaults (MMC-6 §7.4.1) too.
        assert_eq!(profile.mode_sense(false, 0x08, false, 0, None), Some(24));
        assert_eq!(profile.mode_sense(false, 0x2A, false, 0, None), Some(68));
        assert_eq!(profile.mode_sense(false, 0x05, false, 0, None), Some(56));
        assert_eq!(profile.mode_sense(false, 0x3F, false, 0, None), Some(198));
        // GC/GESN answer explicitly with the zero-sector view instead of
        // delegating to `Spc` (which would reject for an unrelated reason).
        assert_eq!(profile.get_configuration(0, 0, None), Some(108));
        assert_eq!(profile.event_status(0x10, None), Some(8));

        let mut cdb = [0u8; 10];
        cdb[0] = READ_TOC;
        assert_eq!(
            dev.prepare(&permit, ctx(Direction::ToHost, 20), &cdb),
            Err(Completion::Check(MEDIUM_NOT_PRESENT))
        );

        assert!(dev.install_medium(&boundary, removed).is_ok());
        assert!(matches!(
            dev.install_medium(&boundary, FlatCdMedium::read_only(1)),
            Err((_, Fault::Contract))
        ));
    }

    #[test]
    fn empty_default_drive_reports_hyper_multi_caps() {
        // The default drive is a Hyper-Multi recorder; an empty tray keeps
        // every drive capability (only Current bits are cleared).
        let cd = MmcDrive::<FlatCdMedium>::empty(MmcCaps::hyper_multi());
        let profile = cd.spc_profile().expect("profile");
        assert_eq!(profile.mode_sense(false, 0x2A, false, 0, None), Some(68));
        let mut buf = [0u8; 128];
        let n = profile
            .get_configuration(0, 0, Some(&mut buf))
            .expect("GC on an empty drive");
        assert_eq!(n, 108);
        assert_eq!(&buf[6..8], &0u16.to_be_bytes(), "no current profile");
        assert_eq!(&buf[12..14], &0x12u16.to_be_bytes());
        assert_eq!(buf[15], 0);
        assert_eq!(&buf[16..18], &0x09u16.to_be_bytes());
        assert_eq!(buf[19], 0);
        assert_eq!(&buf[20..22], &0x08u16.to_be_bytes());
        assert_eq!(buf[23], 0);
        let at20 = feature_at(&buf, n, 0x0020).expect("Random Writable listed");
        assert_eq!(buf[at20 + 2] & 1, 0);
        assert!(buf[at20 + 4..at20 + 16].iter().all(|b| *b == 0));
        let at24 = feature_at(&buf, n, 0x0024).expect("Defect Management listed");
        assert_eq!(buf[at24 + 2] & 1, 0);
    }

    #[cfg(feature = "dvdram")]
    #[test]
    fn empty_recorder_reports_recorder_caps() {
        use crate::mmc::DvdRamMedium;

        // The capabilities are the LU's: an empty recorder still lists 0x12,
        // reports the 36-byte recorder page and advertises 0x20/0x24 with
        // Current=0 (Linux's cdrom_probe_write_features consumes 0x20).
        let ram = MmcDrive::<DvdRamMedium>::empty(MmcCaps::dvdram());
        let profile = ram.spc_profile().expect("profile");
        assert_eq!(profile.mode_sense(false, 0x2A, false, 0, None), Some(40));
        assert_eq!(profile.mode_sense(true, 0x2A, false, 0, None), Some(44));
        assert_eq!(profile.mode_sense(true, 0x3F, false, 0, None), Some(174));
        let mut buf = [0u8; 128];
        let n = profile
            .get_configuration(0, 0, Some(&mut buf))
            .expect("GC on an empty recorder");
        assert!(n > 32);
        assert_eq!(&buf[6..8], &0u16.to_be_bytes(), "no current profile");
        // Profile List: [0x12, 0x08], both Current=0.
        assert_eq!(&buf[12..14], &0x12u16.to_be_bytes());
        assert_eq!(buf[15], 0);
        assert_eq!(&buf[16..18], &0x08u16.to_be_bytes());
        assert_eq!(buf[19], 0);
        // The recorder features stay listed (Linux's write-feature probe reads
        // 0x20), with Current=0 and no dependent data while the tray is empty.
        let at20 = feature_at(&buf, n, 0x0020).expect("Random Writable listed");
        assert_eq!(buf[at20 + 2] & 0x01, 0, "Current=0 with no disc");
        assert!(
            buf[at20 + 4..at20 + 16].iter().all(|b| *b == 0),
            "Current=0 carries no dependent data"
        );
        let at24 = feature_at(&buf, n, 0x0024).expect("Defect Management listed");
        assert_eq!(buf[at24 + 2] & 0x01, 0, "Current=0 with no disc");
    }

    #[test]
    fn explicit_caps_do_not_contradict_the_medium() {
        // A recorder capability set over a read-only disc: the profile list
        // keeps 0x12, but only the mounted profile is current and the
        // random-writable feature is not.
        let mixed = MmcDrive::new_with_caps(FlatCdMedium::read_only(16), MmcCaps::dvdram());
        let profile = mixed.spc_profile().expect("profile");
        let mut buf = [0u8; 128];
        let n = profile.get_configuration(0, 0, Some(&mut buf)).expect("GC");
        assert_eq!(&buf[6..8], &0x0008u16.to_be_bytes());
        let at20 = feature_at(&buf, n, 0x0020).expect("Random Writable listed");
        assert_eq!(buf[at20 + 2] & 0x01, 0);
        assert!(buf[at20 + 4..at20 + 16].iter().all(|b| *b == 0));

        #[cfg(feature = "dvdram")]
        {
            use crate::mmc::DvdRamMedium;
            let mixed = MmcDrive::new_with_caps(
                DvdRamMedium::new(16),
                MmcCaps::new(&CDROM_PROFILES, &CDROM_CAPABILITIES_PAGE, false),
            );
            let profile = mixed.spc_profile().expect("profile");
            let n = profile.get_configuration(0, 0, Some(&mut buf)).expect("GC");
            // The mounted medium still owns the Current profile, even when
            // the capability set does not advertise random writing.
            assert_eq!(&buf[6..8], &0x0012u16.to_be_bytes());
            assert!(feature_at(&buf, n, 0x0020).is_none());
            assert!(feature_at(&buf, n, 0x0021).is_none());
            assert!(feature_at(&buf, n, 0x002D).is_none());
        }
    }

    #[test]
    fn admits_drive_commands_without_medium() {
        let dev = MmcDrive::<FlatCdMedium>::empty(MmcCaps::hyper_multi());
        assert!(dev.admits_without_medium(&[0x1A]));
        assert!(dev.admits_without_medium(&[0x5A, 0, 0x2A]));
        assert!(!dev.admits_without_medium(&[0x12]));
        assert!(!dev.admits_without_medium(&[]));
    }

    #[test]
    fn spc_wrapper_serves_queries_and_delegates_media_commands() {
        use crate::core::Spc;

        let mut dev = Spc::new(drive(100));
        let permit = permit();
        let mut data = [0u8; 64];

        // READ CAPACITY(10) is intercepted through the profile.
        let mut capacity = [0u8; 10];
        capacity[0] = 0x25;
        dev.prepare(&permit, ctx(Direction::ToHost, 8), &capacity)
            .expect("prepare");
        match dev.poll(&permit, Feedback::begin(), &mut data) {
            PollStep::Publish(plan) => assert_eq!(plan.bytes, 8),
            other => panic!("expected publish, got {other:?}"),
        }
        match dev.poll(&permit, Feedback::plan_accepted(), &mut data) {
            PollStep::Send { bytes, .. } => assert_eq!(bytes.len(), 8),
            other => panic!("expected send, got {other:?}"),
        }
        assert_eq!(&data[0..4], &99u32.to_be_bytes());
        assert_eq!(&data[4..8], &2048u32.to_be_bytes());
        assert!(matches!(
            dev.poll(
                &permit,
                Feedback::host_sent(HostReceipt::test(8, None)),
                &mut data
            ),
            PollStep::Complete(Completion::Good)
        ));

        // GESN media class is intercepted through the profile.
        let mut gesn = [0u8; 10];
        gesn[0] = 0x4A;
        gesn[1] = 0x01;
        gesn[4] = 0x10;
        gesn[8] = 8;
        dev.prepare(&permit, ctx(Direction::ToHost, 8), &gesn)
            .expect("prepare");
        dev.poll(&permit, Feedback::begin(), &mut data);
        dev.poll(&permit, Feedback::plan_accepted(), &mut data);
        assert_eq!(data[2], 0x04);
        assert_eq!(data[5], 0x02);
        assert!(matches!(
            dev.poll(
                &permit,
                Feedback::host_sent(HostReceipt::test(8, None)),
                &mut data
            ),
            PollStep::Complete(Completion::Good)
        ));

        // READ TOC is a media command, so `Spc` delegates it to the drive.
        let mut toc = [0u8; 10];
        toc[0] = READ_TOC;
        toc[8] = 20;
        dev.prepare(&permit, ctx(Direction::ToHost, 20), &toc)
            .expect("prepare");
        match dev.poll(&permit, Feedback::begin(), &mut data) {
            PollStep::Publish(plan) => assert_eq!(plan.bytes, 20),
            other => panic!("expected publish, got {other:?}"),
        }
        dev.poll(&permit, Feedback::plan_accepted(), &mut data);
        assert_eq!(&data[0..2], &[0x00, 0x12]);
        assert!(matches!(
            dev.poll(
                &permit,
                Feedback::host_sent(HostReceipt::test(20, None)),
                &mut data
            ),
            PollStep::Complete(Completion::Good)
        ));
        assert!(!dev.active());
    }

    #[test]
    fn interrupt_clears_the_drive_and_medium() {
        let mut dev = drive(100);
        let permit = permit();
        assert_eq!(
            dev.prepare(&permit, ctx(Direction::ToHost, 2048), &read_cdb(0, 1)),
            Ok(())
        );
        assert!(dev.active());
        assert!(dev.medium().expect("medium").active());
        dev.interrupt(&permit, Irq::Disconnect, KnownEffects::NONE)
            .expect("interrupt");
        assert!(!dev.active());
        assert!(!dev.medium().expect("medium").active());
    }

    #[test]
    fn read_fua_is_accepted_and_protection_bits_rejected() {
        let mut dev = drive(100);
        let permit = permit();
        let mut cdb = read_cdb(0, 1);
        cdb[1] = 0x08; // FUA
        assert_eq!(
            dev.prepare(&permit, ctx(Direction::ToHost, 2048), &cdb),
            Ok(())
        );
        dev.interrupt(&permit, Irq::Reset, KnownEffects::NONE)
            .expect("interrupt");
        for bits in [0x80, 0x10, 0x01] {
            cdb[1] = bits;
            assert_eq!(
                dev.prepare(&permit, ctx(Direction::ToHost, 2048), &cdb),
                Err(Completion::Check(INVALID_FIELD)),
                "byte 1 {bits:#04x} must be rejected"
            );
        }
    }

    struct CompleteMedium;

    impl MmcMedium for CompleteMedium {
        type State = ();

        fn attrs(&self) -> MmcAttrs {
            MmcAttrs {
                write_mode: MmcWriteMode::Rewritable,
                block_len: 2048,
                sectors: 4,
                tracks: 1,
                sessions: 1,
                write_protected: false,
                needs_recovery: false,
                profile: 0x0012,
                current_features: &[0x0010, 0x001D, 0x001E, 0x0020, 0x0024],
            }
        }

        fn state(&self) -> &Self::State {
            &()
        }

        fn begin(&mut self, _op: MmcOp) -> Result<(), Completion> {
            Ok(())
        }

        fn poll<'a>(&mut self, _fb: Feedback, _data: &'a mut [u8]) -> PollStep<'a> {
            PollStep::Complete(Completion::Good)
        }

        fn active(&self) -> bool {
            false
        }

        fn interrupt(&mut self, _reason: InterruptReason, _known: KnownEffects) {}

        fn track(&self, number: u16) -> Option<Track> {
            (number == 1).then_some(Track {
                number: 1,
                session: 1,
                start_lba: 0,
                blocks: 4,
                kind: TrackKind::Data,
            })
        }

        fn session(&self, number: u16) -> Option<Session> {
            (number == 1).then_some(Session {
                number: 1,
                first_track: 1,
                last_track: 1,
                start_lba: 0,
            })
        }

        fn disc_info(&self) -> DiscInfo {
            DiscInfo {
                status: DiscStatus::Finalized,
                sessions: 1,
                last_session_lba: 3,
                writable: true,
                erasable: true,
                first_track: 1,
                first_track_last_session: 1,
                last_track_last_session: 1,
                last_session_state: 3,
                last_session_lead_in: None,
                last_possible_lead_out: None,
                disc_type: 0xFF,
            }
        }
    }

    #[test]
    fn write_fua_posts_sync_before_good() {
        let mut dev = MmcDrive::new(CompleteMedium);
        let permit = permit();
        dev.query = Query::Media {
            bytes: 0,
            fua: true,
            media_change: false,
            syncing: false,
        };
        let mut data = [0u8; 16];
        assert!(matches!(
            dev.poll(&permit, Feedback::begin(), &mut data),
            PollStep::Io(StorageOp::Sync { resource: 0 })
        ));
        assert!(dev.active());
        assert!(matches!(
            dev.poll(
                &permit,
                Feedback::io_done(IoReceipt::test(0, None, Effect::Known)),
                &mut data
            ),
            PollStep::Complete(Completion::Good)
        ));
        assert!(!dev.active());
    }

    #[test]
    fn explicit_recorder_caps_select_the_recorder_page() {
        let dev =
            MmcDrive::new_with_caps(SpyMedium::new(MmcWriteMode::Blank, 4), MmcCaps::dvdram());
        let profile = dev.spc_profile().expect("profile");
        assert_eq!(profile.mode_sense(false, 0x2A, false, 0, None), Some(40));
    }

    #[test]
    fn read_track_information_rejects_bad_type_and_number() {
        let mut dev = drive(100);
        let permit = permit();
        let mut cdb = [0u8; 10];
        cdb[0] = READ_TRACK_INFORMATION;
        cdb[8] = 48;
        let mut data = [0u8; 64];

        // A track number beyond the medium has no descriptor.
        cdb[1] = 1; // track number type
        cdb[2..6].copy_from_slice(&5u32.to_be_bytes());
        assert_eq!(
            run_query(&mut dev, &cdb, 48, &mut data),
            Completion::Check(INVALID_FIELD)
        );

        cdb[1] = 3; // reserved type
        assert_eq!(
            dev.prepare(&permit, ctx(Direction::ToHost, 48), &cdb),
            Err(Completion::Check(INVALID_FIELD))
        );

        // An LBA outside every track has no descriptor either.
        cdb[1] = 0; // LBA type
        cdb[2..6].copy_from_slice(&101u32.to_be_bytes());
        assert_eq!(
            run_query(&mut dev, &cdb, 48, &mut data),
            Completion::Check(LBA_OUT_OF_RANGE)
        );
    }

    #[test]
    fn sync_accepts_sync_nv_and_rejects_immed() {
        let mut dev = drive(100);
        let permit = permit();
        let mut cdb = [0u8; 10];
        cdb[0] = SYNC_CACHE_10;
        cdb[1] = 0x04; // SYNC_NV
        assert_eq!(dev.prepare(&permit, ctx(Direction::None, 0), &cdb), Ok(()));
        dev.interrupt(&permit, Irq::Reset, KnownEffects::NONE)
            .expect("interrupt");
        cdb[1] = 0x02; // IMMED
        assert_eq!(
            dev.prepare(&permit, ctx(Direction::None, 0), &cdb),
            Err(Completion::Check(INVALID_FIELD))
        );
    }

    #[test]
    fn dvdram_get_configuration_advertises_random_writable() {
        let dev = MmcDrive::new(SpyMedium::rewritable(4));
        let profile = dev.spc_profile().expect("profile");
        let mut buf = [0u8; 128];
        let total = profile
            .get_configuration(0, 0, Some(&mut buf))
            .expect("configuration");
        assert_eq!(&buf[0..4], &((total - 4) as u32).to_be_bytes());
        assert_eq!(&buf[6..8], &0x0012u16.to_be_bytes());
        // Three profile-list entries: DVD-RAM (current), CD-R, CD-ROM.
        assert_eq!(buf[11], 12);
        assert_eq!(&buf[12..14], &0x0012u16.to_be_bytes());
        assert_eq!(buf[15], 0x01);
        assert_eq!(&buf[16..18], &0x0009u16.to_be_bytes());
        assert_eq!(buf[19], 0x00);
        assert_eq!(&buf[20..22], &0x0008u16.to_be_bytes());
        assert_eq!(buf[23], 0x01, "CD-ROM is read-compatible with DVD-RAM");

        let mut at = 8usize;
        let mut codes = [0u16; 10];
        let mut n = 0usize;
        while at + 4 <= total && n < codes.len() {
            let code = u16::from_be_bytes([buf[at], buf[at + 1]]);
            codes[n] = code;
            n += 1;
            at += 4 + usize::from(buf[at + 3]);
        }
        assert!(codes[..n].contains(&0x0020), "Random Writable");
        assert!(codes[..n].contains(&0x0024), "Defect Management");
        assert!(codes[..n].contains(&0x0021), "Incremental Streaming");
        assert!(codes[..n].contains(&0x002D), "CD Track at Once");
        // Descriptor arithmetic: profile list (2), core, removable, readable,
        // multiread, CD read -> Random Writable at 68, Incremental Streaming
        // at 84, Defect Management at 92, CD Track at Once at 100.
        assert_eq!(&buf[68..70], &[0x00, 0x20]);
        assert_eq!(buf[70], 0x05); // version 1, current
        assert_eq!(buf[71], 0x0C);
        assert_eq!(&buf[72..76], &3u32.to_be_bytes());
        assert_eq!(&buf[76..80], &2048u32.to_be_bytes());
        assert_eq!(&buf[80..82], &16u16.to_be_bytes());
        assert_eq!(buf[82], 0x00); // PP
        assert_eq!(&buf[84..86], &[0x00, 0x21]);
        assert_eq!(buf[86], 0x0C, "Incremental Streaming not current");
        assert_eq!(&buf[92..94], &[0x00, 0x24]);
        assert_eq!(buf[94], 0x05);
        assert_eq!(buf[95], 0x04);
        assert_eq!(&buf[100..102], &[0x00, 0x2D]);
        assert_eq!(buf[102], 0x08, "CD Track at Once not current");
    }

    #[test]
    fn zero_sector_media_rejects_every_media_command() {
        let mut dev = drive(0);
        let permit = permit();
        let mut cdb = [0u8; 12];
        let commands: [(u8, Direction); 6] = [
            (READ_TOC, Direction::ToHost),
            (READ_DISC_INFORMATION, Direction::ToHost),
            (READ_TRACK_INFORMATION, Direction::ToHost),
            (READ_10, Direction::ToHost),
            (WRITE_10, Direction::FromHost),
            (READ_CD, Direction::ToHost),
        ];
        for (opcode, direction) in commands {
            cdb.fill(0);
            cdb[0] = opcode;
            if opcode == READ_CD {
                cdb[9] = 0x10;
            }
            assert_eq!(
                dev.prepare(
                    &permit,
                    ctx(direction, 0),
                    &cdb[..if opcode == READ_CD { 12 } else { 10 }]
                ),
                Err(Completion::Check(MEDIUM_NOT_PRESENT)),
                "opcode {opcode:#04x}"
            );
        }
    }

    #[test]
    fn read_track_information_rejects_open_and_reserved_types() {
        let mut dev = drive(100);
        let permit = permit();
        let mut cdb = [0u8; 10];
        cdb[0] = READ_TRACK_INFORMATION;
        cdb[8] = 48;
        for ty in 3..=7 {
            cdb[1] = ty;
            assert_eq!(
                dev.prepare(&permit, ctx(Direction::ToHost, 48), &cdb),
                Err(Completion::Check(INVALID_FIELD)),
                "type {ty}"
            );
        }
        cdb[1] = 0x08; // Open = 1
        assert_eq!(
            dev.prepare(&permit, ctx(Direction::ToHost, 48), &cdb),
            Err(Completion::Check(INVALID_FIELD))
        );
    }

    fn cdr_attrs() -> MmcAttrs {
        MmcAttrs {
            write_mode: MmcWriteMode::WriteOnce,
            block_len: 2048,
            sectors: 333_000,
            tracks: 0,
            sessions: 0,
            write_protected: false,
            needs_recovery: false,
            profile: 0x0009,
            current_features: &[0x0010, 0x001D, 0x001E, 0x0021, 0x002D],
        }
    }

    fn blank_disc_info() -> DiscInfo {
        DiscInfo {
            status: DiscStatus::Empty,
            sessions: 1,
            last_session_lba: 0,
            writable: false,
            erasable: false,
            first_track: 1,
            first_track_last_session: 1,
            last_track_last_session: 1,
            last_session_state: 0,
            last_session_lead_in: Some(-11_077),
            last_possible_lead_out: Some(332_998),
            disc_type: 0xFF,
        }
    }

    #[test]
    fn disc_information_encoder_offsets() {
        let mut buf = [0u8; DISC_INFO_LEN];
        encode_disc_info(blank_disc_info(), cdr_attrs(), &mut buf);
        assert_eq!(&buf[0..2], &((DISC_INFO_LEN - 2) as u16).to_be_bytes());
        // Data Type 0, not erasable, empty session, empty disc.
        assert_eq!(buf[2], 0x00);
        assert_eq!(buf[3], 1, "first track on disc");
        assert_eq!(buf[4], 1, "number of sessions");
        assert_eq!(buf[5], 1, "first track in last session");
        assert_eq!(buf[6], 1, "last track in last session");
        assert_eq!(buf[7], 0x20, "URU");
        assert_eq!(buf[8], 0xFF, "unknown disc type");
        assert_eq!(&buf[9..12], &[0, 0, 0], "MSB halves");
        assert_eq!(&buf[12..16], &[0; 4], "disc identification");
        // Blank/appendable CD-R report the next lead-in; -11_077 wraps to
        // 97:34:23 within a 100-minute disc.
        assert_eq!(&buf[16..20], &[0x00, 0x61, 0x22, 0x17]);
        // 332_998 + 150 = 74:01:73 in binary M/S/F.
        assert_eq!(&buf[20..24], &[0x00, 0x4A, 0x01, 0x49]);

        // An appendable CD-R reports the incomplete disc/session state.
        let mut info = blank_disc_info();
        info.status = DiscStatus::Incomplete;
        info.last_session_state = 1;
        let mut buf = [0u8; DISC_INFO_LEN];
        encode_disc_info(info, cdr_attrs(), &mut buf);
        assert_eq!(buf[2], 0x05, "incomplete disc / session");

        // A complete CD-R reports FF for both addresses.
        let mut info = blank_disc_info();
        info.status = DiscStatus::Finalized;
        info.last_session_state = 3;
        info.last_session_lead_in = None;
        info.last_possible_lead_out = None;
        let mut buf = [0u8; DISC_INFO_LEN];
        encode_disc_info(info, cdr_attrs(), &mut buf);
        assert_eq!(&buf[16..20], &[0xFF; 4]);
        assert_eq!(&buf[20..24], &[0xFF; 4]);

        // A rewritable medium sets Erasable (bit 4). Non-CD media report no
        // disc type and zeroed lead-in/lead-out fields.
        let mut attrs = cdr_attrs();
        attrs.write_mode = MmcWriteMode::Rewritable;
        attrs.profile = 0x0012;
        let mut info = blank_disc_info();
        info.erasable = true;
        let mut buf = [0u8; DISC_INFO_LEN];
        encode_disc_info(info, attrs, &mut buf);
        assert_eq!(buf[2], 0x10, "Erasable<<4 only");
        assert_eq!(buf[8], 0x00, "no CD disc type");
        assert_eq!(&buf[16..24], &[0u8; 8], "non-CD lead-in/lead-out");
    }

    #[test]
    fn track_information_encoder_offsets() {
        // Invisible track: blank, NWA valid at LBA 0, full free space.
        let invisible = TrackInfo {
            number: 1,
            session: 1,
            start_lba: 0,
            length: 0,
            allocated: 333_000,
            nwa: 0,
            free_blocks: 332_996,
            status: TrackStatus::Invisible,
            kind: TrackKind::Data,
            packet: false,
        };
        let mut buf = [0u8; TRACK_INFO_LEN];
        encode_track_info(invisible, true, &mut buf);
        assert_eq!(&buf[0..2], &((TRACK_INFO_LEN - 2) as u16).to_be_bytes());
        assert_eq!(buf[2], 1, "track LSB");
        assert_eq!(buf[3], 1, "session LSB");
        assert_eq!(buf[5], 0x04, "data track mode");
        assert_eq!(buf[6], 0x41, "Blank=1, Data Mode 1");
        assert_eq!(buf[7], 0x01, "NWA_V (bit 0)");
        assert_eq!(&buf[8..12], &0u32.to_be_bytes(), "track start");
        assert_eq!(&buf[12..16], &0u32.to_be_bytes(), "NWA");
        assert_eq!(&buf[16..20], &332_996u32.to_be_bytes(), "free blocks");
        assert_eq!(&buf[20..24], &0u32.to_be_bytes(), "no fixed packets");
        assert_eq!(&buf[24..28], &333_000u32.to_be_bytes(), "track size");
        assert_eq!(&buf[28..32], &0u32.to_be_bytes(), "NWA-1");
        assert_eq!((buf[32], buf[33], buf[34]), (0, 0, 0), "track/session MSB");

        // An empty reserved track is RT=1/Blank=1; a partially recorded one
        // is RT=1/Blank=0.
        let reserved = TrackInfo {
            number: 2,
            session: 1,
            start_lba: 400,
            length: 0,
            allocated: 500,
            nwa: 400,
            free_blocks: 500,
            status: TrackStatus::Reserved,
            kind: TrackKind::Data,
            packet: false,
        };
        let mut buf = [0u8; TRACK_INFO_LEN];
        encode_track_info(reserved, true, &mut buf);
        assert_eq!(buf[6], 0xC1, "reserved empty: RT=1, Blank=1");
        assert_eq!(buf[7], 0x01, "NWA_V");

        let mut reserved_with_data = reserved;
        reserved_with_data.length = 40;
        let mut buf = [0u8; TRACK_INFO_LEN];
        encode_track_info(reserved_with_data, true, &mut buf);
        assert_eq!(buf[6], 0x81, "reserved with data: RT=1, Blank=0");

        // An incomplete track is RT=0/Blank=0.
        let mut incomplete = reserved;
        incomplete.status = TrackStatus::Incomplete;
        incomplete.length = 40;
        incomplete.allocated = 0;
        let mut buf = [0u8; TRACK_INFO_LEN];
        encode_track_info(incomplete, true, &mut buf);
        assert_eq!(buf[6], 0x01, "incomplete: RT=0, Blank=0");

        // A closed track has RT=1 and no valid NWA/free blocks.
        let complete = TrackInfo {
            number: 2,
            session: 1,
            start_lba: 100,
            length: 10,
            allocated: 10,
            nwa: 110,
            free_blocks: 0,
            status: TrackStatus::Complete,
            kind: TrackKind::Data,
            packet: false,
        };
        let mut buf = [0u8; TRACK_INFO_LEN];
        encode_track_info(complete, true, &mut buf);
        assert_eq!(buf[2], 2);
        assert_eq!(buf[6], 0x81, "RT=1, Data Mode 1");
        assert_eq!(buf[7], 0x00, "no NWA_V");
        assert_eq!(&buf[8..12], &100u32.to_be_bytes());
        assert_eq!(&buf[16..20], &0u32.to_be_bytes());
        assert_eq!(&buf[24..28], &10u32.to_be_bytes());
        assert_eq!(&buf[28..32], &0u32.to_be_bytes());

        // Non-recordable media always report RT=0 (Table 497).
        let mut buf = [0u8; TRACK_INFO_LEN];
        encode_track_info(complete, false, &mut buf);
        assert_eq!(buf[6], 0x01, "non-recordable: RT=0, Blank=0");

        // The lead-in pseudo-track reports no NWA and a negative start.
        let lead_in = TrackInfo {
            number: 0,
            session: 0,
            start_lba: -11_077,
            length: 0,
            allocated: 0,
            nwa: 0,
            free_blocks: 0,
            status: TrackStatus::Complete,
            kind: TrackKind::Data,
            packet: false,
        };
        let mut buf = [0u8; TRACK_INFO_LEN];
        encode_track_info(lead_in, true, &mut buf);
        assert_eq!(buf[2], 0);
        assert_eq!(buf[5], 0x00, "lead-in track mode");
        assert_eq!(buf[6], 0x00, "RT=Blank=0");
        assert_eq!(buf[7], 0x00, "no NWA");
        assert_eq!(&buf[8..12], &(-11_077i32 as u32).to_be_bytes());
    }

    // =======================================================================
    // Recorder control: MODE SENSE/SELECT 0x05, SET CD SPEED, SEND OPC
    // =======================================================================

    /// Run a FromHost parameter-list command to completion.
    fn run_receive<M: MmcMedium>(
        dev: &mut MmcDrive<M>,
        cdb: &[u8],
        payload: &[u8],
        data: &mut [u8],
    ) -> Completion {
        let permit = permit();
        match dev.prepare(&permit, ctx(Direction::FromHost, payload.len() as u64), cdb) {
            Ok(()) => {}
            Err(completion) => return completion,
        }
        let len = match dev.poll(&permit, Feedback::begin(), data) {
            PollStep::Publish(plan) => {
                assert_eq!(plan.direction, Direction::FromHost);
                plan.bytes as usize
            }
            PollStep::Complete(completion) => return completion,
            other => panic!("expected publish, got {other:?}"),
        };
        assert_eq!(len, payload.len());
        match dev.poll(&permit, Feedback::plan_accepted(), data) {
            PollStep::Receive { buf, write } => {
                assert!(write.is_none());
                assert_eq!(buf.len(), len);
                buf.copy_from_slice(payload);
            }
            PollStep::Complete(completion) => return completion,
            other => panic!("expected receive, got {other:?}"),
        }
        match dev.poll(
            &permit,
            Feedback::host_received(HostReceipt::test(len, None)),
            data,
        ) {
            PollStep::Complete(completion) => completion,
            other => panic!("expected completion, got {other:?}"),
        }
    }

    fn mode_select_cdb(ten: bool, len: usize) -> std::vec::Vec<u8> {
        let mut cdb = if ten {
            std::vec![0u8; 10]
        } else {
            std::vec![0u8; 6]
        };
        cdb[0] = if ten { MODE_SELECT_10 } else { MODE_SELECT_6 };
        cdb[1] = 0x10; // PF=1, SP=0
        if ten {
            cdb[7..9].copy_from_slice(&(len as u16).to_be_bytes());
        } else {
            cdb[4] = len as u8;
        }
        cdb
    }

    fn test_write_params_page(
        write_type: u8,
        track_mode: u8,
        dbt: u8,
        test_write: bool,
    ) -> Vec<u8> {
        let mut page = vec![0u8; 2 + WRITE_PARAMS_LEN];
        page[0] = 0x05;
        page[1] = 0x32;
        page[2] = (u8::from(test_write) << 4) | (write_type & 0x0F);
        page[3] = track_mode & 0x0F;
        page[4] = dbt & 0x0F;
        page
    }

    fn mode_select_params(ten: bool, pages: &[u8]) -> Vec<u8> {
        let mut params = vec![0u8; if ten { 8 } else { 4 }];
        params.extend_from_slice(pages);
        params
    }

    #[cfg(feature = "cdr-bundle")]
    fn cdr_drive() -> MmcDrive<CdrBundleMedium> {
        MmcDrive::new(CdrBundleMedium::blank(CdrCapacity::Cdr74))
    }

    #[cfg(feature = "cdr-bundle")]
    fn write_medium_block(medium: &mut CdrBundleMedium, lba: u64) {
        let mut data = [0u8; 2048];
        assert_eq!(medium.begin(MmcOp::Write { lba, blocks: 1 }), Ok(()));
        match medium.poll(Feedback::begin(), &mut data) {
            PollStep::Publish(plan) => assert_eq!(plan.bytes, 2048),
            other => panic!("expected write publish, got {other:?}"),
        }
        match medium.poll(Feedback::plan_accepted(), &mut data) {
            PollStep::Receive { buf, .. } => buf.fill(0x5A),
            other => panic!("expected write receive, got {other:?}"),
        }
        match medium.poll(
            Feedback::host_received(HostReceipt::test(2048, None)),
            &mut data,
        ) {
            PollStep::Io(StorageOp::Write { buf, .. }) => assert_eq!(buf.len(), 2048),
            other => panic!("expected write IO, got {other:?}"),
        }
        assert!(matches!(
            medium.poll(
                Feedback::io_done(IoReceipt::test(2048, None, Effect::Known)),
                &mut data
            ),
            PollStep::Complete(Completion::Good)
        ));
    }

    #[cfg(feature = "cdr-bundle")]
    fn run_control_medium(medium: &mut CdrBundleMedium, op: MmcOp) {
        let mut data = [0u8; 4096];
        assert_eq!(medium.begin(op), Ok(()));
        let mut feedback = Feedback::begin();
        loop {
            match medium.poll(feedback, &mut data) {
                PollStep::Publish(plan) => {
                    assert_eq!(plan.direction, Direction::None);
                    feedback = Feedback::plan_accepted();
                }
                PollStep::Io(StorageOp::Sync { .. }) => {
                    feedback = Feedback::io_done(IoReceipt::test(0, None, Effect::Known));
                }
                PollStep::Io(StorageOp::Write { buf, .. }) => {
                    feedback = Feedback::io_done(IoReceipt::test(buf.len(), None, Effect::Known));
                }
                PollStep::Complete(Completion::Good) => return,
                other => panic!("expected control completion, got {other:?}"),
            }
        }
    }

    #[cfg(feature = "cdr-bundle")]
    fn commit_medium(medium: &mut CdrBundleMedium) {
        run_control_medium(medium, MmcOp::Commit);
    }

    #[cfg(feature = "cdr-bundle")]
    fn finalized_cdr_drive() -> MmcDrive<CdrBundleMedium> {
        let mut medium = CdrBundleMedium::blank(CdrCapacity::Cdr74);
        write_medium_block(&mut medium, 0);
        commit_medium(&mut medium);
        run_control_medium(&mut medium, MmcOp::Close { function: 2 });
        MmcDrive::new(medium)
    }

    #[cfg(feature = "cdr-bundle")]
    #[test]
    fn mode_sense_page_05_cdr_claims_tao() {
        let dev = cdr_drive();
        let profile = dev.spc_profile().expect("profile");
        let mut long = [0u8; 64];
        assert_eq!(
            profile.mode_sense(true, 0x05, false, 0, Some(&mut long)),
            Some(60)
        );
        assert_eq!(&long[0..2], &58u16.to_be_bytes());
        assert_eq!(long[8], 0x05);
        assert_eq!(long[9], 0x32);
        assert_eq!(long[10], 0x01, "Write Type = Track-at-Once");
        assert_eq!(long[11], 0x04, "Track Mode = data");
        assert_eq!(long[12], 0x08, "Data Block Type = Mode 1");

        let mut short = [0u8; 64];
        assert_eq!(
            profile.mode_sense(false, 0x05, false, 0, Some(&mut short)),
            Some(56)
        );
        assert_eq!(&short[4..9], &[0x05, 0x32, 0x01, 0x04, 0x08]);
    }

    #[test]
    fn mode_sense_page_05_read_only_does_not_claim_tao() {
        let dev = drive(100);
        let profile = dev.spc_profile().expect("profile");
        let mut buf = [0u8; 64];
        assert_eq!(
            profile.mode_sense(true, 0x05, false, 0, Some(&mut buf)),
            Some(60)
        );
        assert_eq!(&buf[8..13], &[0x05, 0x32, 0x00, 0x00, 0x00]);
    }

    #[cfg(feature = "dvdram")]
    #[test]
    fn mode_sense_page_05_dvdram_does_not_claim_tao() {
        let dev = MmcDrive::new(crate::mmc::dvdram::DvdRamMedium::new(16));
        let profile = dev.spc_profile().expect("profile");
        let mut buf = [0u8; 64];
        assert_eq!(
            profile.mode_sense(true, 0x05, false, 0, Some(&mut buf)),
            Some(60)
        );
        assert_eq!(&buf[8..13], &[0x05, 0x32, 0x00, 0x00, 0x00]);
    }

    #[cfg(feature = "cdr-bundle")]
    #[test]
    fn mode_select_accepts_tao_on_a_cdr() {
        let mut dev = cdr_drive();
        let page = test_write_params_page(1, 4, 8, false);
        let mut data = [0u8; 128];
        for ten in [false, true] {
            let params = mode_select_params(ten, &page);
            let cdb = mode_select_cdb(ten, params.len());
            assert_eq!(
                run_receive(&mut dev, &cdb, &params, &mut data),
                Completion::Good,
                "MODE SELECT ten={ten}"
            );
            assert!(!dev.active());
        }
    }

    #[cfg(feature = "cdr-bundle")]
    #[test]
    fn mode_select_rejects_unsupported_write_parameters() {
        let mut dev = cdr_drive();
        let mut data = [0u8; 128];
        for (write_type, track_mode, dbt, test_write) in [
            (2, 4, 8, false),  // Session-at-Once
            (3, 4, 8, false),  // RAW
            (0, 4, 8, false),  // Packet/Incremental
            (1, 4, 8, true),   // Test Write (-dummy)
            (1, 4, 0, false),  // raw 2352-byte blocks
            (1, 4, 10, false), // Mode 2 Form 1
        ] {
            let page = test_write_params_page(write_type, track_mode, dbt, test_write);
            let params = mode_select_params(true, &page);
            let cdb = mode_select_cdb(true, params.len());
            assert_eq!(
                run_receive(&mut dev, &cdb, &params, &mut data),
                Completion::Check(INVALID_FIELD),
                "write type {write_type}, dbt {dbt}, test {test_write}"
            );
            assert!(!dev.active());
        }
    }

    #[cfg(feature = "cdr-bundle")]
    #[test]
    fn mode_select_rejects_bad_cdb_and_parameter_structure() {
        let mut dev = cdr_drive();
        let permit = permit();
        let page = test_write_params_page(1, 4, 8, false);
        let params = mode_select_params(true, &page);
        let mut cdb = mode_select_cdb(true, params.len());

        // PF=0 or SP=1 are not page lists.
        cdb[1] = 0x00;
        assert_eq!(
            dev.prepare(&permit, ctx(Direction::FromHost, params.len() as u64), &cdb),
            Err(Completion::Check(INVALID_FIELD))
        );
        cdb[1] = 0x11;
        assert_eq!(
            dev.prepare(&permit, ctx(Direction::FromHost, params.len() as u64), &cdb),
            Err(Completion::Check(INVALID_FIELD))
        );
        // The transport's declared byte count must match the CDB length.
        cdb[1] = 0x10;
        assert_eq!(
            dev.prepare(
                &permit,
                ctx(Direction::FromHost, params.len() as u64 + 1),
                &cdb
            ),
            Err(Completion::Check(INVALID_FIELD))
        );
        // A zero-length list is a no-op.
        let empty = mode_select_cdb(false, 0);
        assert_eq!(
            dev.prepare(&permit, ctx(Direction::FromHost, 0), &empty),
            Err(Completion::Good)
        );

        let mut data = [0u8; 128];
        // Non-zero block descriptor length.
        let mut bad = params.clone();
        bad[6..8].copy_from_slice(&8u16.to_be_bytes());
        assert_eq!(
            run_receive(&mut dev, &cdb, &bad, &mut data),
            Completion::Check(INVALID_FIELD)
        );
        // Page length that does not fit the list.
        let mut truncated = params.clone();
        truncated[9] = 0x40;
        assert_eq!(
            run_receive(&mut dev, &cdb, &truncated, &mut data),
            Completion::Check(INVALID_FIELD)
        );
        // Write Parameters page length must be 32h or 36h.
        let mut wrong_page_len = params.clone();
        wrong_page_len[9] = 0x10;
        assert_eq!(
            run_receive(&mut dev, &cdb, &wrong_page_len, &mut data),
            Completion::Check(INVALID_FIELD)
        );
        assert!(!dev.active());
    }

    #[cfg(feature = "cdr-bundle")]
    #[test]
    fn mode_select_without_page_05_is_a_noop() {
        let mut dev = cdr_drive();
        let mut data = [0u8; 128];
        let page = [0x08u8, 0x02, 0x00, 0x00]; // caching page
        let params = mode_select_params(true, &page);
        let cdb = mode_select_cdb(true, params.len());
        assert_eq!(
            run_receive(&mut dev, &cdb, &params, &mut data),
            Completion::Good
        );
    }

    #[test]
    fn mode_select_on_a_read_only_medium_ignores_the_page() {
        let mut dev = drive(100);
        let mut data = [0u8; 128];
        // Even a SAO + Test Write page is accepted and ignored on a ROM.
        let page = test_write_params_page(2, 4, 8, true);
        let params = mode_select_params(true, &page);
        let cdb = mode_select_cdb(true, params.len());
        assert_eq!(
            run_receive(&mut dev, &cdb, &params, &mut data),
            Completion::Good
        );
    }

    #[test]
    fn set_cd_speed_records_the_requested_speeds() {
        let mut dev = drive(100);
        let permit = permit();
        let mut cdb = [0u8; 12];
        cdb[0] = SET_CD_SPEED;
        cdb[2..4].copy_from_slice(&7060u16.to_be_bytes());
        cdb[4..6].copy_from_slice(&4236u16.to_be_bytes());
        assert_eq!(
            dev.prepare(&permit, ctx(Direction::None, 0), &cdb),
            Err(Completion::Good)
        );
        assert_eq!(dev.cd_speed(), (7060, 4236));
        assert!(!dev.active());

        // A host data phase is invalid for a no-data command.
        assert_eq!(
            dev.prepare(&permit, ctx(Direction::None, 4), &cdb),
            Err(Completion::Check(INVALID_FIELD))
        );
    }

    #[test]
    fn send_opc_accepts_eight_byte_entries_and_rejects_a_partial_one() {
        let mut dev = drive(100);
        let permit = permit();
        let mut data = [0u8; 32];
        for len in [0usize, 8, 16] {
            let mut cdb = [0u8; 10];
            cdb[0] = SEND_OPC;
            cdb[7..9].copy_from_slice(&(len as u16).to_be_bytes());
            let payload = vec![0u8; len];
            assert_eq!(
                run_receive(&mut dev, &cdb, &payload, &mut data),
                Completion::Good,
                "SEND OPC length {len}"
            );
            assert!(!dev.active());
        }
        let mut cdb = [0u8; 10];
        cdb[0] = SEND_OPC;
        cdb[7..9].copy_from_slice(&7u16.to_be_bytes());
        assert_eq!(
            dev.prepare(&permit, ctx(Direction::FromHost, 7), &cdb),
            Err(Completion::Check(INVALID_FIELD))
        );
    }

    #[cfg(feature = "cdr-bundle")]
    #[test]
    fn read_toc_format2_raw_descriptors_on_a_finalized_cdr() {
        let mut dev = finalized_cdr_drive();
        let mut cdb = [0u8; 10];
        cdb[0] = READ_TOC;
        cdb[2] = 0x02;
        cdb[8] = 64;
        let mut data = [0u8; 64];
        assert_eq!(run_query(&mut dev, &cdb, 64, &mut data), Completion::Good);
        assert_eq!(&data[0..2], &50u16.to_be_bytes(), "52-byte response");
        assert_eq!(data[2], 1, "first complete session");
        assert_eq!(data[3], 1, "last complete session");

        let desc = |at: usize| &data[at..at + TOC_RAW_DESCRIPTOR_LEN];
        // A0: first track 1, CD-DA/CD-ROM disc type 00h, PFRAME 0.
        assert_eq!(desc(4), &[1, 0x14, 0, 0xA0, 1, 0x00, 0x00, 0]);
        // A1: last track 1.
        assert_eq!(desc(12), &[1, 0x14, 0, 0xA1, 1, 0, 0, 0]);
        // A2: lead-out at LBA 300 => 00:06:00.
        assert_eq!(desc(20), &[1, 0x14, 0, 0xA2, 0, 6, 0, 0]);
        // B0: closed full-TOC marker (ADR=5) at the lead-out.
        assert_eq!(desc(28), &[1, 0x50, 0, 0xB0, 0, 6, 0, 0]);
        // Track 1 starts at LBA 0 => 00:02:00.
        assert_eq!(desc(36), &[1, 0x14, 0, 1, 0, 2, 0, 0]);
        // Lead-out descriptor.
        assert_eq!(desc(44), &[1, 0x14, 0, 0xAA, 0, 6, 0, 0]);
    }

    #[cfg(feature = "cdr-bundle")]
    #[test]
    fn read_toc_format2_rejects_a_blank_disc_and_bad_selector() {
        let mut dev = cdr_drive();
        let permit = permit();
        let mut cdb = [0u8; 10];
        cdb[0] = READ_TOC;
        cdb[2] = 0x02;
        cdb[8] = 64;
        assert_eq!(
            dev.prepare(&permit, ctx(Direction::ToHost, 64), &cdb),
            Err(Completion::Check(INVALID_FIELD))
        );
        // Format 2 takes no session selector in the design.
        cdb[6] = 1;
        let mut dev = finalized_cdr_drive();
        assert_eq!(
            dev.prepare(&permit, ctx(Direction::ToHost, 64), &cdb),
            Err(Completion::Check(INVALID_FIELD))
        );
    }

    #[cfg(feature = "cdr-bundle")]
    fn reserve_track_cdb(arsv: bool, size: u32) -> [u8; 10] {
        let mut cdb = [0u8; 10];
        cdb[0] = RESERVE_TRACK;
        cdb[1] = u8::from(arsv);
        cdb[5..9].copy_from_slice(&size.to_be_bytes());
        cdb
    }

    #[cfg(feature = "cdr-bundle")]
    fn run_control_drive(
        dev: &mut MmcDrive<CdrBundleMedium>,
        cdb: &[u8],
        data: &mut [u8],
    ) -> Completion {
        let permit = permit();
        match dev.prepare(&permit, ctx(Direction::None, 0), cdb) {
            Ok(()) => {}
            Err(completion) => return completion,
        }
        let mut feedback = Feedback::begin();
        loop {
            match dev.poll(&permit, feedback, data) {
                PollStep::Publish(plan) => {
                    assert_eq!(plan.direction, Direction::None);
                    feedback = Feedback::plan_accepted();
                }
                PollStep::Io(StorageOp::Sync { .. }) => {
                    feedback = Feedback::io_done(IoReceipt::test(0, None, Effect::Known));
                }
                PollStep::Io(StorageOp::Write { buf, .. }) => {
                    feedback = Feedback::io_done(IoReceipt::test(buf.len(), None, Effect::Known));
                }
                PollStep::Complete(completion) => return completion,
                other => panic!("expected control completion, got {other:?}"),
            }
        }
    }

    #[cfg(feature = "cdr-bundle")]
    #[test]
    fn reserve_track_decodes_and_persists_the_toc() {
        let mut dev = cdr_drive();
        let mut data = [0u8; 4096];
        assert_eq!(
            run_control_drive(&mut dev, &reserve_track_cdb(false, 500), &mut data),
            Completion::Good
        );
        let medium = dev.medium().expect("medium");
        assert_eq!(medium.toc_seq(), 1);
        assert_eq!(medium.current_slot(), 0);

        let mut cdb = [0u8; 10];
        cdb[0] = READ_TRACK_INFORMATION;
        cdb[1] = 1;
        cdb[2..6].copy_from_slice(&1u32.to_be_bytes());
        cdb[8] = 48;
        assert_eq!(run_query(&mut dev, &cdb, 48, &mut data), Completion::Good);
        assert_eq!(data[2], 1, "track number");
        assert_eq!(data[6], 0xC1, "reserved empty track");
        assert_eq!(&data[24..28], &500u32.to_be_bytes(), "allocation");
    }

    #[cfg(feature = "cdr-bundle")]
    #[test]
    fn reserve_track_rejects_arsv_reserved_bits_and_bad_context() {
        let mut dev = cdr_drive();
        let permit = permit();

        assert_eq!(
            dev.prepare(
                &permit,
                ctx(Direction::None, 0),
                &reserve_track_cdb(true, 500)
            ),
            Err(Completion::Check(INVALID_FIELD)),
            "ARSV=1 is not served"
        );
        let mut cdb = reserve_track_cdb(false, 500);
        cdb[2] = 1;
        assert_eq!(
            dev.prepare(&permit, ctx(Direction::None, 0), &cdb),
            Err(Completion::Check(INVALID_FIELD))
        );
        let mut cdb = reserve_track_cdb(false, 500);
        cdb[9] = 1;
        assert_eq!(
            dev.prepare(&permit, ctx(Direction::None, 0), &cdb),
            Err(Completion::Check(INVALID_FIELD))
        );
        let cdb = reserve_track_cdb(false, 500);
        assert_eq!(
            dev.prepare(&permit, ctx(Direction::FromHost, 0), &cdb),
            Err(Completion::Check(INVALID_FIELD))
        );
        assert_eq!(
            dev.prepare(&permit, ctx(Direction::ToHost, 0), &cdb),
            Err(Completion::Check(INVALID_FIELD))
        );
        assert_eq!(
            dev.prepare(&permit, ctx(Direction::None, 4), &cdb),
            Err(Completion::Check(INVALID_FIELD))
        );
        assert_eq!(
            dev.prepare(
                &permit,
                ctx(Direction::None, 0),
                &reserve_track_cdb(false, 299)
            ),
            Err(Completion::Check(INVALID_FIELD)),
            "the medium owns the minimum size"
        );
        assert!(!dev.active());
    }

    #[cfg(feature = "cdr-bundle")]
    #[test]
    fn read_toc_format2_truncates_but_keeps_the_declared_length() {
        let mut dev = finalized_cdr_drive();
        let mut cdb = [0u8; 10];
        cdb[0] = READ_TOC;
        cdb[2] = 0x02;
        cdb[8] = 20;
        let mut data = [0u8; 64];
        assert_eq!(run_query(&mut dev, &cdb, 20, &mut data), Completion::Good);
        // Only the first 20 bytes are sent; the header still declares 50.
        assert_eq!(&data[0..2], &50u16.to_be_bytes());
        assert_eq!(data[2], 1);
        assert_eq!(data[3], 1);
        assert_eq!(&data[4..12], &[1, 0x14, 0, 0xA0, 1, 0x00, 0x00, 0]);
        assert_eq!(&data[12..20], &[1, 0x14, 0, 0xA1, 1, 0, 0, 0]);
    }
}
