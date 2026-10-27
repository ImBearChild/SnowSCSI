//! MMC drive: media-command decoding over an [`MmcMedium`].
//!
//! Authority: `__ARCH__/design/02-api-profiles.md` §6.1/§6.5 and the P2b
//! implementation log (`__ARCH__/handoff/P2B-IMPLEMENT-LOG.md` §3).
//!
//! The drive decodes the media command table, validates CDB fields/reserved
//! bits/allocation length and encodes the media-description responses
//! (READ TOC, READ DISC INFORMATION, READ TRACK INFORMATION). It never matches
//! a media class or write mode: `MmcAttrs` facts and `MmcMedium` semantics are
//! the only inputs. Public query commands are served by `Spc` through
//! [`SpcProfile`].
//!
//! Byte layouts are re-implemented from the production baseline:
//! `crate::cdrom::drive::read_toc_cmd` (lines 998–1047),
//! `read_disc_info_cmd`/`build_read_disc_info` (drive.rs 1066–1085,
//! common.rs 1213–1237), `read_track_information_cmd` (drive.rs 1257–1307),
//! `gesn_cmd` (drive.rs 1111–1141) and the mode pages of `common.rs` 106–146,
//! 446, 501. This module has no runtime dependency on `cdrom`.

use super::attrs::{
    DiscInfo, DiscStatus, MmcAttrs, MmcWriteMode, SectorKind, Session, Track, TrackKind,
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
/// CLOSE TRACK SESSION.
const CLOSE_TRACK_SESSION: u8 = 0x5B;
/// BLANK.
const BLANK: u8 = 0xA1;
/// READ CD.
const READ_CD: u8 = 0xBE;

/// READ TOC format 0 with both descriptors (track 0/1).
const TOC_FULL_LEN: usize = 20;
/// READ TOC format 0 for the lead-out track (0xAA).
const TOC_LEADOUT_LEN: usize = 12;
/// READ TOC format 1 (session list): 4-byte header + 8-byte descriptor.
const TOC_SESSION_LEN: usize = 12;
/// READ DISC INFORMATION standard payload.
const DISC_INFO_LEN: usize = 34;
/// READ TRACK INFORMATION payload.
const TRACK_INFO_LEN: usize = 48;
/// GET CONFIGURATION response: header plus the current feature set.
const GET_CONFIG_LEN: usize = 128;

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

/// Resident zero-fill state (MMC-internal; only projected through `LongInfo`).
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
    },
    /// Finished; the result is resident until P3 management takes it.
    Settled { error: Option<Fault> },
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
        /// Requested track number.
        track: u16,
    },
    /// CLOSE TRACK SESSION: validated, no medium operation.
    Close,
    /// FORMAT UNIT / BLANK zero-fill state machine.
    Format(FormatCmd),
}

/// MMC drive over a replaceable medium.
pub struct MmcDrive<M: MmcMedium> {
    medium: Option<M>,
    query: Query,
    /// Bytes selected for a drive-encoded response.
    len: usize,
    /// The data plan for the current encoded response was published.
    published: bool,
    /// Resident zero-fill operation shared by FORMAT UNIT and BLANK.
    long: LongOp,
}

impl<M: MmcMedium> MmcDrive<M> {
    /// Build a drive with an installed medium.
    #[must_use]
    pub fn new(medium: M) -> Self {
        Self {
            medium: Some(medium),
            query: Query::None,
            len: 0,
            published: false,
            long: LongOp::Idle,
        }
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
            READ_CD => self.prepare_read_cd(ctx, cdb),
            CLOSE_TRACK_SESSION => self.prepare_close(ctx, cdb),
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
            if ctx.host_bytes != 0 {
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

    /// READ TOC/PMA/ATIP: formats 0 and 1, LBA or MSF (design offset 2).
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
        if format > 1 {
            return Err(Completion::Check(INVALID_FIELD));
        }
        let track = cdb[6];
        if format == 0 && !matches!(track, 0 | 1 | 0xAA) {
            return Err(Completion::Check(INVALID_FIELD));
        }
        if format == 1 && track != 0 {
            return Err(Completion::Check(INVALID_FIELD));
        }
        let attrs = self.attrs().ok_or(Completion::Check(MEDIUM_NOT_PRESENT))?;
        if attrs.sectors == 0 {
            return Err(Completion::Check(MEDIUM_NOT_PRESENT));
        }
        let total = match (format, track) {
            (0, 0xAA) => TOC_LEADOUT_LEN,
            (0, _) => TOC_FULL_LEN,
            _ => TOC_SESSION_LEN,
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
        let track = match ty {
            0 => {
                // LBA: must be within the medium; the single track is 1.
                if u64::from(number) >= attrs.sectors {
                    return Err(Completion::Check(LBA_OUT_OF_RANGE));
                }
                1u16
            }
            1 => {
                // Track number: this medium has exactly one track.
                if number != 1 {
                    return Err(Completion::Check(INVALID_FIELD));
                }
                1u16
            }
            _ => {
                // Session number (type 2): exactly one session.
                if number != 1 {
                    return Err(Completion::Check(INVALID_FIELD));
                }
                1u16
            }
        };
        let alloc = usize::from(be16(&cdb[7..9]));
        self.len = TRACK_INFO_LEN.min(alloc);
        self.query = Query::TrackInfo { track };
        Ok(())
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
            if ctx.host_bytes != 0 {
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

    /// CLOSE TRACK SESSION: close function 0 only; read-only media is already
    /// closed. MMC-6 Table 234: byte 1 = Immed, byte 2 bits 3-0 = function.
    fn prepare_close(&mut self, ctx: CommandContext, cdb: &[u8]) -> Result<(), Completion> {
        if cdb.len() < 10 {
            return Err(Completion::Check(INVALID_FIELD));
        }
        if cdb[1] & 0xFE != 0 || cdb[2] != 0 || cdb[3..10] != [0; 7] {
            return Err(Completion::Check(INVALID_FIELD));
        }
        check_direction(ctx, Direction::None)?;
        if self.medium.is_none() {
            return Err(Completion::Check(MEDIUM_NOT_PRESENT));
        }
        self.query = Query::Close;
        Ok(())
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
    /// The default encoding is an IMMED=0 P2b extension for the design subset.
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
            // phase; the plan published in `poll` must match it exactly.
            if ctx.host_direction != Direction::FromHost
                || ctx.host_bytes != FORMAT_PARAMS_LEN as u64
            {
                return Err(Completion::Check(INVALID_FIELD));
            }
        } else if ctx.host_direction != Direction::None || ctx.host_bytes != 0 {
            return Err(Completion::Check(INVALID_FIELD));
        }
        let attrs = self.attrs().ok_or(Completion::Check(MEDIUM_NOT_PRESENT))?;
        if !attrs.write_accessible() {
            return Err(Completion::Check(WRITE_PROTECTED));
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
        if ctx.host_bytes != 0 {
            return Err(Completion::Check(INVALID_FIELD));
        }
        let attrs = self.attrs().ok_or(Completion::Check(MEDIUM_NOT_PRESENT))?;
        if !attrs.write_accessible() {
            return Err(Completion::Check(WRITE_PROTECTED));
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
            LongOp::Settled { error: None }
        } else {
            LongOp::Foreground {
                total: bytes,
                done: 0,
                in_flight: 0,
            }
        };
        Ok(())
    }

    /// One step of the drive-owned zero-fill. The medium supplies geometry, but
    /// the fill is issued directly as `StorageOp::Write` on resource 0 at byte
    /// offset `done`, so no `MmcOp::Format` reaches the medium. Only one IO is
    /// in flight at a time; a repeated `Begin` while `in_flight != 0` does not
    /// reissue the same write (only the matching `IoDone` advances).
    fn fill_step<'a>(&mut self, fb: Feedback, data: &'a mut [u8]) -> PollStep<'a> {
        let LongOp::Foreground {
            total,
            done,
            in_flight,
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
                    };
                    return PollStep::Complete(Completion::Check(INTERNAL_FAILURE));
                };
                if let Some(fault) = receipt.error() {
                    self.long = LongOp::Settled { error: Some(fault) };
                    return PollStep::Complete(Completion::Check(
                        storage_fault_sense(fault, IoContext::Format).unwrap_or(INTERNAL_FAILURE),
                    ));
                }
                if in_flight == 0 || receipt.confirmed() as u64 != in_flight {
                    // A short write leaves an unknown tail; do not replay it.
                    self.long = LongOp::Settled {
                        error: Some(Fault::Io),
                    };
                    return PollStep::Complete(Completion::Check(MEDIUM_ERROR));
                }
                done += in_flight;
                in_flight = 0;
                self.long = LongOp::Foreground {
                    total,
                    done,
                    in_flight,
                };
            }
            FeedbackKind::Begin => {
                if in_flight != 0 {
                    // A retried `Begin` must not reissue the in-flight write.
                    return PollStep::Idle;
                }
            }
            // The long operation publishes no plan; ignore other feedback.
            FeedbackKind::PlanAccepted | FeedbackKind::HostReceived | FeedbackKind::HostSent => {
                return PollStep::Idle
            }
        }
        let remaining = total.saturating_sub(done);
        if remaining == 0 {
            self.long = LongOp::Settled { error: None };
            return PollStep::Complete(Completion::Good);
        }
        let chunk = remaining
            .min(data.len() as u64)
            .min(FORMAT_CHUNK_MAX as u64) as usize;
        if chunk == 0 {
            self.long = LongOp::Settled {
                error: Some(Fault::Contract),
            };
            return PollStep::Complete(Completion::Check(INTERNAL_FAILURE));
        }
        data[..chunk].fill(0);
        self.long = LongOp::Foreground {
            total,
            done,
            in_flight: chunk as u64,
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
        if !self.published {
            self.published = true;
            return PollStep::Publish(DataPlan {
                direction: Direction::ToHost,
                bytes: len as u64,
            });
        }
        if fb.kind() == FeedbackKind::HostSent {
            self.query = Query::None;
            return PollStep::Complete(Completion::Good);
        }
        if data.len() < len {
            self.query = Query::None;
            return PollStep::Complete(Completion::Check(INVALID_FIELD));
        }
        if !fill(&mut data[..len]) {
            self.query = Query::None;
            return PollStep::Complete(Completion::Check(INVALID_FIELD));
        }
        PollStep::Send(&data[..len])
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
        match self.query {
            Query::None => PollStep::Idle,
            Query::Media {
                bytes,
                fua,
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
                if data.len() < bytes as usize {
                    // A short caller bank is a runner contract breach; drop the
                    // admitted medium operation so the medium is not left
                    // half-active.
                    if let Some(medium) = self.medium.as_mut() {
                        medium.interrupt(InterruptReason::TransportRestriction, KnownEffects::NONE);
                    }
                    self.query = Query::None;
                    return PollStep::Complete(Completion::Check(INVALID_FIELD));
                }
                let Some(medium) = self.medium.as_mut() else {
                    self.query = Query::None;
                    return PollStep::Complete(Completion::Check(MEDIUM_NOT_PRESENT));
                };
                match medium.poll(fb, data) {
                    PollStep::Complete(Completion::Good) if fua => {
                        self.query = Query::Media {
                            bytes,
                            fua,
                            syncing: true,
                        };
                        PollStep::Io(StorageOp::Sync { resource: 0 })
                    }
                    PollStep::Complete(completion) => {
                        self.query = Query::None;
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
                let Some(track_info) = medium.track(1) else {
                    self.query = Query::None;
                    return PollStep::Complete(Completion::Check(MEDIUM_NOT_PRESENT));
                };
                let Some(session) = medium.session(1) else {
                    self.query = Query::None;
                    return PollStep::Complete(Completion::Check(MEDIUM_NOT_PRESENT));
                };
                let lead_out = track_info
                    .start_lba
                    .saturating_add(track_info.blocks)
                    .min(u64::from(u32::MAX)) as u32;
                self.poll_encoded(fb, data, |out| {
                    encode_toc(track_info, session, lead_out, msf, format, track, out);
                    true
                })
            }
            Query::DiscInfo => {
                let Some((info, attrs)) = self.medium.as_ref().map(|m| (m.disc_info(), m.attrs()))
                else {
                    self.query = Query::None;
                    return PollStep::Complete(Completion::Check(MEDIUM_NOT_PRESENT));
                };
                let erasable = matches!(
                    attrs.write_mode,
                    MmcWriteMode::Rewritable | MmcWriteMode::WriteOnce
                );
                self.poll_encoded(fb, data, |out| {
                    encode_disc_info(info, attrs.sectors, erasable, out);
                    true
                })
            }
            Query::TrackInfo { track } => {
                let number = if track == 0 || track == 0xFF {
                    1
                } else {
                    track
                };
                let found = self.medium.as_ref().and_then(|m| m.track(number));
                self.poll_encoded(fb, data, |out| match found {
                    Some(track) => {
                        encode_track_info(track, out);
                        true
                    }
                    None => false,
                })
            }
            Query::Close => {
                self.query = Query::None;
                // CLOSE is the write-state transition; a writable medium gets
                // its local metadata commit hook (no storage IO). A failure is
                // reported as the command's CHECK.
                if self.attrs().is_some_and(|a| a.write_accessible()) {
                    if let Some(medium) = self.medium.as_mut() {
                        if let Err(completion) = medium.commit() {
                            return PollStep::Complete(if completion == Completion::Good {
                                Completion::Good
                            } else {
                                completion
                            });
                        }
                    }
                }
                PollStep::Complete(Completion::Good)
            }
            Query::Format(cmd) => {
                if cmd.params {
                    if !self.published {
                        if data.len() < FORMAT_PARAMS_LEN {
                            self.query = Query::None;
                            self.long = LongOp::Idle;
                            return PollStep::Complete(Completion::Check(INVALID_FIELD));
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
                                return PollStep::Complete(Completion::Check(INVALID_FIELD));
                            }
                            PollStep::Receive(&mut data[..FORMAT_PARAMS_LEN])
                        }
                        FeedbackKind::HostReceived => {
                            if data.len() < FORMAT_PARAMS_LEN {
                                self.query = Query::None;
                                self.long = LongOp::Idle;
                                return PollStep::Complete(Completion::Check(INVALID_FIELD));
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
        }
    }

    fn poll_long<'a>(
        &mut self,
        _permit: &CommandPermit,
        fb: Feedback,
        data: &'a mut [u8],
    ) -> PollStep<'a> {
        // Only a resident (IMMED=1) fill is advanced here; a Settled result is
        // resident until P3 management takes it.
        if matches!(self.long, LongOp::Foreground { .. }) {
            self.fill_step(fb, data)
        } else {
            PollStep::Idle
        }
    }

    fn long_info(&self) -> LongInfo {
        match self.long {
            LongOp::Idle => LongInfo::IDLE,
            LongOp::Foreground { total, done, .. } => LongInfo {
                phase: LongPhase::Foreground,
                write_accessible: false,
                progress: Some(format_progress(done, total)),
                error: None,
            },
            LongOp::Settled { error } => LongInfo {
                phase: LongPhase::Settled,
                // The foreground gate is down once the fill settled; a failed
                // settle is carried in `error`, not in this projection.
                write_accessible: true,
                progress: Some(100),
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
        let attrs = self.attrs()?;
        if pc == 3 {
            // Saved pages are unsupported; `Spc` rejects PC=11b before this.
            return None;
        }
        // The 0x2A view follows the medium facts, never a device class: a
        // rewritable or blank DVD-RAM advertises the recorder page.
        let rewritable = matches!(
            attrs.write_mode,
            MmcWriteMode::Rewritable | MmcWriteMode::Blank
        );
        let mut pages = [0u8; ALL_PAGES_LEN];
        let plen = if page == 0x3F {
            let mut at = 0usize;
            for code in ALL_PAGE_ORDER {
                let bytes = page_bytes(code, rewritable)?;
                pages[at..at + bytes.len()].copy_from_slice(bytes);
                at += bytes.len();
            }
            at
        } else {
            let bytes = page_bytes(page, rewritable)?;
            pages[..bytes.len()].copy_from_slice(bytes);
            bytes.len()
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
        let last = attrs.sectors.saturating_sub(1).min(u64::from(u32::MAX)) as u32;
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
        let attrs = self.attrs()?;
        let present = attrs.sectors != 0;
        let rewritable = matches!(
            attrs.write_mode,
            MmcWriteMode::Rewritable | MmcWriteMode::WriteOnce
        );
        // MMC-6 Table 87: no current profile while no medium is active.
        let current_profile = if !present {
            0x0000u16
        } else if rewritable {
            0x0012u16
        } else {
            0x0008u16
        };
        // MMC-6 Table 257: RT=01b returns only descriptors with Current=1;
        // RT=10b returns only the matching descriptor; RT=00b everything at
        // or above the starting feature.
        let include = |code: u16, current: bool| match rt {
            2 => code == start_feature,
            1 => current && code >= start_feature,
            _ => code >= start_feature,
        };
        let mut buf = [0u8; GET_CONFIG_LEN];
        let mut off = 8usize;
        if include(0x0000, true) {
            // Profile List: the active profile first, then the always-present
            // CD-ROM profile for a rewritable drive.
            let mut entries = [0u8; 2];
            let mut count = 0usize;
            if rewritable {
                entries[count] = 0x12;
                count += 1;
            }
            entries[count] = 0x08;
            count += 1;
            buf[off..off + 2].copy_from_slice(&0x0000u16.to_be_bytes());
            buf[off + 2] = 0x03; // version 0, persistent, current
            buf[off + 3] = (4 * count) as u8;
            for (i, code) in entries[..count].iter().enumerate() {
                let at = off + 4 + 4 * i;
                buf[at..at + 2].copy_from_slice(&u16::from(*code).to_be_bytes());
                buf[at + 3] = if u16::from(*code) == current_profile {
                    0x01
                } else {
                    0x00
                };
            }
            off += 4 + 4 * count;
        }
        if include(0x0001, true) {
            // Core: version 2, persistent/current, SCSI family.
            buf[off..off + 2].copy_from_slice(&0x0001u16.to_be_bytes());
            buf[off + 2] = 0x0B;
            buf[off + 3] = 0x08;
            buf[off + 4..off + 8].copy_from_slice(&[0, 0, 0, 1]);
            buf[off + 8] = 0x06; // INQ2 | DBE
            off += 12;
        }
        if include(0x0003, true) {
            // Removable Medium.
            buf[off..off + 2].copy_from_slice(&0x0003u16.to_be_bytes());
            buf[off + 2] = 0x0B;
            buf[off + 3] = 0x04;
            buf[off + 4] = 0x39;
            off += 8;
        }
        if include(0x0010, present) {
            // Random Readable: media-dependent current bit.
            buf[off..off + 2].copy_from_slice(&0x0010u16.to_be_bytes());
            buf[off + 2] = if present { 0x01 } else { 0x00 };
            buf[off + 3] = 0x08;
            buf[off + 4..off + 8].copy_from_slice(&attrs.block_len.to_be_bytes());
            buf[off + 9] = 0x01; // blocking = 1 (16-bit field)
            off += 12;
        }
        if include(0x001D, present) {
            // MultiRead (mandatory companion of READ CD).
            buf[off..off + 2].copy_from_slice(&0x001Du16.to_be_bytes());
            buf[off + 2] = if present { 0x01 } else { 0x00 };
            buf[off + 3] = 0x00;
            off += 4;
        }
        if include(0x001E, present) {
            // CD Read.
            buf[off..off + 2].copy_from_slice(&0x001Eu16.to_be_bytes());
            buf[off + 2] = if present { 0x09 } else { 0x08 };
            buf[off + 3] = 0x04;
            off += 8;
        }
        if rewritable && include(0x0020, present) {
            // Random Writable (MMC-6 Table 113): version 1, last LBA,
            // block size, blocking, PP + reserved.
            buf[off..off + 2].copy_from_slice(&0x0020u16.to_be_bytes());
            buf[off + 2] = if present { 0x05 } else { 0x04 };
            buf[off + 3] = 0x0C;
            let last = attrs.sectors.saturating_sub(1).min(u64::from(u32::MAX)) as u32;
            buf[off + 4..off + 8].copy_from_slice(&last.to_be_bytes());
            buf[off + 8..off + 12].copy_from_slice(&attrs.block_len.to_be_bytes());
            buf[off + 12..off + 14].copy_from_slice(&16u16.to_be_bytes()); // blocking
            buf[off + 14] = 0x00; // PP
            off += 16;
        }
        if rewritable && include(0x0024, present) {
            // Defect Management (MMC-6 Table 123): version 1.
            buf[off..off + 2].copy_from_slice(&0x0024u16.to_be_bytes());
            buf[off + 2] = if present { 0x05 } else { 0x04 };
            buf[off + 3] = 0x04;
            off += 8;
        }
        // Data Length counts every byte after the 4-byte length field and is
        // declared in full even when the caller's allocation truncates.
        buf[0..4].copy_from_slice(&((off - 4) as u32).to_be_bytes());
        buf[6..8].copy_from_slice(&current_profile.to_be_bytes());
        if let Some(out) = out {
            let n = off.min(out.len());
            out[..n].copy_from_slice(&buf[..n]);
        }
        Some(off)
    }

    fn event_status(&self, class: u8, out: Option<&mut [u8]>) -> Option<usize> {
        let attrs = self.attrs()?;
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
/// Write Parameters page 0x05 (cdrom/common.rs:129).
const WRITE_PARAMS_PAGE: [u8; 52] = [
    0x05, 0x32, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00,
];
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
/// descriptor. Keep the fixed 64-byte size so `0x3F` stays consistent with the
/// read-only CD page.
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

/// Bytes of one supported mode page (`0x3F` excluded).
///
/// Page 0x2A has two fixed variants: the 64-byte read-only CD-ROM view and
/// the 36-byte DVD-RAM recorder view selected by `MmcAttrs::write_mode` (not
/// by any device/media class match). The page length byte describes each one
/// completely, so `0x3F` concatenation never carries padding that a host
/// could parse as another page.
fn page_bytes(page: u8, rewritable: bool) -> Option<&'static [u8]> {
    match page {
        0x00 => Some(&VENDOR_PAGE),
        0x01 => Some(&READ_WRITE_ERROR_RECOVERY_PAGE),
        0x05 => Some(&WRITE_PARAMS_PAGE),
        0x08 => Some(&CACHING_PAGE),
        0x0D => Some(&CDROM_PARAMS),
        0x0E => Some(&CDROM_AUDIO),
        0x1A => Some(&POWER_CONDITION_PAGE),
        0x1D => Some(&TIMEOUT_PROTECT_PAGE),
        0x2A if rewritable => Some(&DVDRAM_CAPABILITIES_PAGE),
        0x2A => Some(&CDROM_CAPABILITIES_PAGE),
        _ => None,
    }
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

/// Encode READ TOC (`cdrom/drive.rs:998–1047`) using the medium's track and
/// session values. Format 1 is the MMC-6 4-byte header + 8-byte descriptor
/// (12 bytes total).
fn encode_toc(
    track: Track,
    session: Session,
    lead_out_lba: u32,
    msf: bool,
    format: u8,
    track_req: u8,
    out: &mut [u8],
) {
    let mut buf = [0u8; TOC_FULL_LEN];
    let ctl = match track.kind {
        TrackKind::Data => 0x14,  // ADR=1, CTL=4 (data)
        TrackKind::Audio => 0x10, // ADR=1, CTL=0 (audio)
    };
    let total = if format == 0 {
        if track_req == 0xAA {
            buf[0..2].copy_from_slice(&((TOC_LEADOUT_LEN - 2) as u16).to_be_bytes());
            buf[2] = session.first_track.min(255) as u8;
            buf[3] = session.last_track.min(255) as u8;
            buf[5] = ctl;
            buf[6] = 0xAA;
            buf[8..12].copy_from_slice(&toc_address(lead_out_lba, msf));
            TOC_LEADOUT_LEN
        } else {
            buf[0..2].copy_from_slice(&((TOC_FULL_LEN - 2) as u16).to_be_bytes());
            buf[2] = session.first_track.min(255) as u8;
            buf[3] = session.last_track.min(255) as u8;
            buf[5] = ctl;
            buf[6] = track.number.min(255) as u8;
            buf[8..12].copy_from_slice(&toc_address(
                track.start_lba.min(u64::from(u32::MAX)) as u32,
                msf,
            ));
            buf[13] = ctl;
            buf[14] = 0xAA;
            buf[16..20].copy_from_slice(&toc_address(lead_out_lba, msf));
            TOC_FULL_LEN
        }
    } else {
        // Format 1: first/last complete session + one 8-byte descriptor.
        buf[0..2].copy_from_slice(&((TOC_SESSION_LEN - 2) as u16).to_be_bytes());
        buf[2] = session.number.min(255) as u8;
        buf[3] = session.number.min(255) as u8;
        buf[5] = ctl;
        buf[6] = session.first_track.min(255) as u8;
        buf[8..12].copy_from_slice(&toc_address(
            track.start_lba.min(u64::from(u32::MAX)) as u32,
            msf,
        ));
        TOC_SESSION_LEN
    };
    let n = total.min(out.len());
    out[..n].copy_from_slice(&buf[..n]);
}

/// Encode READ DISC INFORMATION (`cdrom/common.rs:1213–1237`).
///
/// Byte 2 carries erasable (bit 6), state of last session (bits 3-2) and disc
/// status (bits 1-0); `writable` is a separate policy fact and must not be
/// substituted for erasable.
fn encode_disc_info(info: DiscInfo, sectors: u64, erasable: bool, out: &mut [u8]) {
    let mut buf = [0u8; DISC_INFO_LEN];
    buf[0..2].copy_from_slice(&((DISC_INFO_LEN - 2) as u16).to_be_bytes());
    let status = match info.status {
        DiscStatus::Empty => 0u8,
        DiscStatus::Incomplete => 1,
        DiscStatus::Finalized => 2,
        DiscStatus::Other(raw) => raw & 0x03,
    };
    // State of Last Session (MMC-6 Table 366): complete only when finalized.
    let last_session = match info.status {
        DiscStatus::Finalized => 3u8,
        DiscStatus::Incomplete => 1,
        DiscStatus::Empty | DiscStatus::Other(_) => 0,
    };
    buf[2] = (u8::from(erasable) << 6) | (last_session << 2) | status;
    buf[3] = 0x01; // first track number
    buf[4] = info.sessions.min(255) as u8;
    buf[5] = 0x01; // first track in the last session
    buf[6] = 0x01; // last track in the last session
    buf[7] = 0x20; // URU=1, MRW status 0
                   // Bytes 9–19 stay zero (MSB halves, identification, last session lead-in).
    let lead_out = sectors.min(u64::from(u32::MAX)) as u32;
    buf[20..24].copy_from_slice(&lead_out.to_be_bytes());
    let n = DISC_INFO_LEN.min(out.len());
    out[..n].copy_from_slice(&buf[..n]);
}

/// Encode READ TRACK INFORMATION (`cdrom/drive.rs:1257–1307`).
fn encode_track_info(track: Track, out: &mut [u8]) {
    let mut buf = [0u8; TRACK_INFO_LEN];
    buf[0..2].copy_from_slice(&((TRACK_INFO_LEN - 2) as u16).to_be_bytes());
    buf[2] = track.number.min(255) as u8;
    buf[3] = track.session.min(255) as u8;
    if track.kind == TrackKind::Data {
        buf[5] = 0x04; // Track Mode: data (Q control)
        buf[6] = 0x01; // Data Mode: Mode 1
    }
    buf[7] = 0x00; // reserved; NWA_V = 0 (no writable track here)
                   // Bytes 8–19: free blocks, next writable address and NWA validity stay 0.
    buf[20..24].copy_from_slice(&16u32.to_be_bytes()); // packet size
    let capacity = track.blocks.min(u64::from(u32::MAX)) as u32;
    buf[24..28].copy_from_slice(&capacity.to_be_bytes());
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

/// Zero-fill progress in whole percent, clamped to 0..=100.
fn format_progress(done: u64, total: u64) -> u32 {
    if total == 0 {
        return 100;
    }
    (done.saturating_mul(100) / total).min(100) as u32
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
    use crate::mmc::attrs::Session;
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
    fn run_query(
        dev: &mut MmcDrive<FlatCdMedium>,
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
            PollStep::Send(bytes) => assert_eq!(bytes.len(), len),
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
        cdb[2] = 0x02;
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
        assert_eq!(data[3], 1);
        assert_eq!(data[4], 1);
        assert_eq!(data[5], 1);
        assert_eq!(data[6], 1);
        assert_eq!(data[7], 0x20);
        assert_eq!(&data[20..24], &100u32.to_be_bytes());
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
        assert_eq!(data[6], 0x01); // Data Mode: Mode 1
        assert_eq!(data[7], 0x00); // reserved, NWA_V=0
        assert_eq!(&data[20..24], &16u32.to_be_bytes());
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
        assert_eq!(profile.get_configuration(0, 0, Some(&mut buf)), Some(60));
        assert_eq!(&buf[0..4], &56u32.to_be_bytes());
        assert_eq!(&buf[6..8], &0x0008u16.to_be_bytes());
        // Profile List: one current CD-ROM profile.
        assert_eq!(&buf[8..10], &[0x00, 0x00]);
        assert_eq!(buf[10], 0x03);
        assert_eq!(buf[11], 4);
        assert_eq!(&buf[12..14], &0x0008u16.to_be_bytes());
        assert_eq!(buf[15], 0x01);
        // Core, Removable Medium, Random Readable, MultiRead, CD Read.
        assert_eq!(&buf[16..18], &[0x00, 0x01]);
        assert_eq!(&buf[28..30], &[0x00, 0x03]);
        assert_eq!(&buf[36..38], &[0x00, 0x10]);
        assert_eq!(&buf[40..44], &2048u32.to_be_bytes());
        assert_eq!(buf[45], 0x01);
        assert_eq!(&buf[48..50], &[0x00, 0x1D]);
        assert_eq!(&buf[52..54], &[0x00, 0x1E]);

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
            PollStep::Send(bytes) if bytes.len() == 2048
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
    fn close_track_session_is_validated_and_good() {
        let mut dev = drive(100);
        let permit = permit();
        let mut cdb = [0u8; 10];
        cdb[0] = CLOSE_TRACK_SESSION;
        assert_eq!(dev.prepare(&permit, ctx(Direction::None, 0), &cdb), Ok(()));
        let mut data = [0u8; 0];
        assert!(matches!(
            dev.poll(&permit, Feedback::begin(), &mut data),
            PollStep::Complete(Completion::Good)
        ));
        assert!(!dev.active());

        cdb[1] = 0x00;
        cdb[2] = 0x01; // close function 1 is unsupported
        assert_eq!(
            dev.prepare(&permit, ctx(Direction::None, 0), &cdb),
            Err(Completion::Check(INVALID_FIELD))
        );
        cdb[2] = 0x00;
        cdb[1] = 0x02; // reserved byte 1 bit
        assert_eq!(
            dev.prepare(&permit, ctx(Direction::None, 0), &cdb),
            Err(Completion::Check(INVALID_FIELD))
        );
    }

    #[test]
    fn format_and_blank_are_wired_to_the_zero_fill_slice() {
        // The old P2b stub rejected both opcodes; this test now pins the new
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
            PollStep::Receive(bytes) => assert_eq!(bytes.len(), FORMAT_PARAMS_LEN),
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
    /// offsets/lengths. Every passed buffer must be zeroed by the drive.
    fn drive_long(
        dev: &mut MmcDrive<SpyMedium>,
        permit: &CommandPermit,
        data: &mut [u8],
    ) -> Vec<(u64, usize)> {
        let mut ios = Vec::new();
        let mut fb = Feedback::begin();
        for _ in 0..64 {
            match dev.poll_long(permit, fb, data) {
                PollStep::Io(StorageOp::Write { offset, buf, .. }) => {
                    assert!(buf.iter().all(|b| *b == 0), "fill buffer must be zeroed");
                    ios.push((offset, buf.len()));
                    fb = Feedback::io_done(IoReceipt::test(buf.len(), None, Effect::Known));
                }
                PollStep::Complete(Completion::Good) => return ios,
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
            PollStep::Complete(Completion::Good) => {}
            other => panic!("expected GOOD, got {other:?}"),
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
    fn close_commits_only_writable_media() {
        let permit = permit();
        let mut cdb = [0u8; 10];
        cdb[0] = CLOSE_TRACK_SESSION;
        let mut data = [0u8; 0];

        let mut dev = MmcDrive::new(SpyMedium::rewritable(2));
        assert_eq!(dev.prepare(&permit, ctx(Direction::None, 0), &cdb), Ok(()));
        assert!(matches!(
            dev.poll(&permit, Feedback::begin(), &mut data),
            PollStep::Complete(Completion::Good)
        ));
        assert_eq!(dev.medium().expect("medium").commit_calls.get(), 1);

        let mut dev = MmcDrive::new(SpyMedium::read_only(2));
        assert_eq!(dev.prepare(&permit, ctx(Direction::None, 0), &cdb), Ok(()));
        assert!(matches!(
            dev.poll(&permit, Feedback::begin(), &mut data),
            PollStep::Complete(Completion::Good)
        ));
        assert_eq!(dev.medium().expect("medium").commit_calls.get(), 0);
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
    fn mode_sense_2a_follows_the_write_mode() {
        let read_only = MmcDrive::new(SpyMedium::read_only(4));
        let rewritable = MmcDrive::new(SpyMedium::rewritable(4));
        let mut cd = [0u8; 68];
        let mut ram = [0u8; 68];
        assert_eq!(
            read_only.spc_profile().expect("profile").mode_sense(
                false,
                0x2A,
                false,
                0,
                Some(&mut cd)
            ),
            Some(68)
        );
        assert_eq!(
            rewritable.spc_profile().expect("profile").mode_sense(
                false,
                0x2A,
                false,
                0,
                Some(&mut ram)
            ),
            Some(40)
        );
        assert_eq!(&cd[4..6], &[0x2A, 0x3E]);
        assert_eq!(&ram[4..6], &[0x2A, 0x22]);
        assert_ne!(&cd[4..68], &ram[4..40]);
        // The 0x3F total follows the selected 0x2A variant; no padding bytes
        // are inserted that a host could parse as a following page.
        assert_eq!(
            read_only
                .spc_profile()
                .expect("profile")
                .mode_sense(false, 0x3F, false, 0, None),
            Some(198)
        );
        assert_eq!(
            rewritable
                .spc_profile()
                .expect("profile")
                .mode_sense(false, 0x3F, false, 0, None),
            Some(170)
        );
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
    fn short_bank_is_rejected() {
        let mut dev = drive(100);
        let permit = permit();
        assert_eq!(
            dev.prepare(&permit, ctx(Direction::ToHost, 2048), &read_cdb(0, 1)),
            Ok(())
        );
        let mut data = [0u8; 16];
        assert!(matches!(
            dev.poll(&permit, Feedback::begin(), &mut data),
            PollStep::Complete(Completion::Check(INVALID_FIELD))
        ));
        assert!(!dev.active());
        assert!(!dev.medium().expect("medium").active());
    }

    #[test]
    fn no_medium_rejects_media_queries_and_install_is_exclusive() {
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
        assert_eq!(profile.mode_sense(false, 0x08, false, 0, None), None);
        assert_eq!(profile.get_configuration(0, 0, None), None);
        assert_eq!(profile.event_status(0x10, None), None);

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
            PollStep::Send(bytes) => assert_eq!(bytes.len(), 8),
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
    fn blank_write_mode_selects_the_recorder_page() {
        let dev = MmcDrive::new(SpyMedium::new(MmcWriteMode::Blank, 4));
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

        cdb[1] = 1; // track number type
        cdb[2..6].copy_from_slice(&5u32.to_be_bytes());
        assert_eq!(
            dev.prepare(&permit, ctx(Direction::ToHost, 48), &cdb),
            Err(Completion::Check(INVALID_FIELD))
        );

        cdb[1] = 3; // reserved type
        assert_eq!(
            dev.prepare(&permit, ctx(Direction::ToHost, 48), &cdb),
            Err(Completion::Check(INVALID_FIELD))
        );

        cdb[1] = 0; // LBA type
        cdb[2..6].copy_from_slice(&101u32.to_be_bytes());
        assert_eq!(
            dev.prepare(&permit, ctx(Direction::ToHost, 48), &cdb),
            Err(Completion::Check(LBA_OUT_OF_RANGE))
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
        // Two profile-list entries: DVD-RAM first (current), CD-ROM second.
        assert_eq!(buf[11], 8);
        assert_eq!(&buf[12..14], &0x0012u16.to_be_bytes());
        assert_eq!(buf[15], 0x01);
        assert_eq!(&buf[16..18], &0x0008u16.to_be_bytes());
        assert_eq!(buf[19], 0x00);

        let mut at = 8usize;
        let mut codes = [0u16; 8];
        let mut n = 0usize;
        while at + 4 <= total && n < codes.len() {
            let code = u16::from_be_bytes([buf[at], buf[at + 1]]);
            codes[n] = code;
            n += 1;
            at += 4 + usize::from(buf[at + 3]);
        }
        assert!(codes[..n].contains(&0x0020), "Random Writable");
        assert!(codes[..n].contains(&0x0024), "Defect Management");
        // Descriptor arithmetic: profile list (2), core, removable, readable,
        // multiread, CD read -> Random Writable at 64, Defect Management at 80.
        assert_eq!(&buf[64..66], &[0x00, 0x20]);
        assert_eq!(buf[66], 0x05); // version 1, current
        assert_eq!(buf[67], 0x0C);
        assert_eq!(&buf[68..72], &3u32.to_be_bytes());
        assert_eq!(&buf[72..76], &2048u32.to_be_bytes());
        assert_eq!(&buf[76..78], &16u16.to_be_bytes());
        assert_eq!(buf[78], 0x00); // PP
        assert_eq!(&buf[80..82], &[0x00, 0x24]);
        assert_eq!(buf[82], 0x05);
        assert_eq!(buf[83], 0x04);
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
}
