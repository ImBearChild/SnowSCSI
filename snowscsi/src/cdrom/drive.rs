//! CdromDrive: unified CD-ROM device with swappable media.
//!
//! One constant device identity + one mutable media slot.  **All** MMC
//! command dispatch lives here; media types only provide geometry and a
//! data plane.  `SpcDevice` is implemented directly — `CdromDeviceCommon`
//! is retired.
//!
//! `CdromDrive::builder()` constructs the drive identity (INQUIRY, caps,
//! drive_id).  Media is injected at runtime via `load()`/`eject()`.

use crate::cdrom::common::{
    build_get_config_response_for_media, build_read_buffer_capacity, build_read_disc_info,
    cdrom_mode_page_for_caps, default_write_params_page, CdromCapabilities, DiscInfo, MediaState,
    CDROM_IDENTITY, SECTOR_SIZE,
};
use crate::cdrom::media::{CdMedia, Tray};
use crate::common::store::StoreOp;
use crate::scsi::device::{CommandOutcome, DeviceType, PendingXfer, Xfer, XferDir};
use crate::scsi::scsi::{
    asc, cdb_lba10, cdb_len_from_opcode, cdb_opcode, cdb_read_args, cdb_write_args, op, Sense,
    SenseKey,
};
use crate::scsi::spc::{execute_spc, parse_spc, DeviceIdentity, SpcCommand, SpcDevice, SpcEffect};
use crate::scsi::util::hex_of;

const CLEAR_SENSE: Sense = Sense::clear();

// ── CdromDrive ────────────────────────────────────────

/// Unified CD-ROM drive with a swappable media slot.
///
/// The drive identity (INQUIRY, caps, drive_id) is constant; the media
/// slot is mutable.  `SpcDevice` is implemented directly here.
///
/// The drive is **non-generic and backend-free**: media geometry is cached
/// at load time, data-phase I/O is handed to the shell as a
/// [`StoreOp`], and FORMAT/BLANK/SYNCHRONIZE
/// CACHE maintenance is produced by
/// [`ScsiDevice::next_store_op`](crate::scsi::device::ScsiDevice::next_store_op).
#[derive(Debug)]
pub struct CdromDrive {
    pub(crate) sense: Option<Sense>,
    pub(crate) pending: Option<PendingXfer>,
    pub(crate) prevent_removal: bool,
    /// Device capability model — single source for GET CONFIG features
    /// and MODE SENSE 0x2A page.
    pub(crate) caps: CdromCapabilities,
    /// VPD 0x80/0x83恒定标识（换盘不漂移,）.
    pub(crate) drive_id: u64,
    /// INQUIRY identity.
    pub(crate) identity: DeviceIdentity,
    /// Tray: at most one disc, loaded or parked after a SCSI eject.
    pub(crate) tray: Tray,
    /// Tray state: `true` = open.
    pub(crate) tray_open: bool,
    /// Page 0x05 write parameter cache.
    #[allow(dead_code)] // reserved for the future write-path (page 0x05)
    pub(crate) mode_page_05: [u8; 52],
    #[allow(dead_code)]
    pub(crate) mode_page_05_valid: bool,
    /// `true` when `load()` was requested by START STOP Load=1 on an
    /// empty tray.
    pub(crate) media_requested: bool,
    // ── Maintenance agenda (drained by the session before any terminal
    // status; see `ScsiDevice::next_store_op`) ────────────────────────
    /// Next byte offset of a pending FORMAT/BLANK zero-fill.
    format_off: u64,
    /// Remaining bytes to zero-fill (`0` ⇒ no fill agenda armed).
    format_remaining: u64,
    /// Byte written by each pending `Fill` chunk (always zero here).
    format_byte: u8,
    /// One-shot `StoreOp::Sync` armed by SYNCHRONIZE CACHE.
    sync_pending: bool,
}

impl Default for CdromDrive {
    fn default() -> Self {
        Self::new()
    }
}

impl CdromDrive {
    /// Create a drive with default identity and capabilities.
    pub fn new() -> Self {
        Self::builder().build()
    }

    /// Start building a new drive.
    pub fn builder() -> CdromDriveBuilder {
        CdromDriveBuilder {
            identity: CDROM_IDENTITY,
            caps: CdromCapabilities::hyper_multi(),
            drive_id: 0,
        }
    }

    // ── Media slot ─────────────────────────────────────

    /// Disc-pool usage (runtime media swap across ANY backend kinds):
    ///
    /// ```text
    /// use snowscsi::cdrom::media::{CdMedia, FlatMedia, LiveData};
    /// use snowscsi::cdrom::drive::CdromDrive;
    /// # fn demo(
    /// #     img_file: &mut impl snowscsi_common::seekable_storage::FlatData,
    /// #     my_fs: impl snowscsi_common::fs_storage::FsStorage,
    /// #     sd_card: impl snowscsi_common::seekable_storage::WritableFlatData,
    /// # ) -> Result<(), Box<dyn core::error::Error>> {
    /// let mut drive = CdromDrive::new();
    ///
    /// let mut live_data = LiveData::new(my_fs, "LABEL")?;      // bind first:
    /// let mut disc_a = CdMedia::ro(&mut live_data);            // geometry only
    /// let mut disc_b = CdMedia::Ro(FlatMedia::new(img_file));  // plane read once
    /// // DVD-RAM over a writable plane (feature `dvdram`):
    /// // let mut disc_c = CdMedia::Rw(DvdRamMedia::open(&mut sd_card));
    /// # Ok(())
    /// # }
    /// ```
    ///
    /// The media holds only cached geometry; the backing plane is owned by the
    /// shell (the LUN's `StorePlane`). `load`/`eject` round-trip the media
    /// value so a small "disc pool" can be swapped at runtime.
    ///
    /// Load media into the drive, returning whatever occupied the tray
    /// (a loaded disc or one parked by a SCSI eject). Sets UNIT ATTENTION.
    pub fn load(&mut self, media: CdMedia) -> Option<CdMedia> {
        let old = core::mem::replace(&mut self.tray, Tray::Loaded(media)).disc();
        if old.is_some() {
            self.tray_open = false;
        }
        self.sense = Some(Sense::new(
            SenseKey::UnitAttention,
            asc::MEDIUM_MAY_HAVE_CHANGED,
            0,
        ));
        old
    }

    /// Load media without setting UNIT ATTENTION (for test setup / initial load).
    pub fn load_quiet(&mut self, media: CdMedia) -> Option<CdMedia> {
        let old = core::mem::replace(&mut self.tray, Tray::Loaded(media)).disc();
        if old.is_some() {
            self.tray_open = false;
        }
        old
    }

    /// Eject the media, handing it back to the caller. Idempotent on an
    /// empty tray *and* on a parked disc (a disc parked by a SCSI eject
    /// belongs to the drive until [`Self::take_media`] reclaims it);
    /// queues UNIT ATTENTION whenever a disc comes out.
    pub fn eject(&mut self) -> Option<CdMedia> {
        if matches!(self.tray, Tray::Parked(_)) {
            return None;
        }
        let taken = core::mem::replace(&mut self.tray, Tray::Empty).disc();
        self.tray_open = true;
        if taken.is_some() {
            self.sense = Some(Sense::new(
                SenseKey::UnitAttention,
                asc::MEDIUM_MAY_HAVE_CHANGED,
                0,
            ));
        }
        taken
    }

    /// SCSI-initiated eject (`START STOP loej=1`): Loaded → Parked plus
    /// UNIT ATTENTION. The disc stays owned by the drive — physically it
    /// sticks out of the slot until [`Self::take_media`] reclaims it or
    /// a new [`Self::load`] swaps it. On an
    /// empty or already-parked tray it merely presents the tray; an
    /// empty tray presenting itself is not a medium-change event
    /// (§14.3 次-1), so no UNIT ATTENTION is queued.
    pub(crate) fn park(&mut self) {
        if let Some(m) = core::mem::replace(&mut self.tray, Tray::Empty).disc() {
            self.tray = Tray::Parked(m);
            self.sense = Some(Sense::new(
                SenseKey::UnitAttention,
                asc::MEDIUM_MAY_HAVE_CHANGED,
                0,
            ));
        }
        self.tray_open = true;
    }

    /// Reclaim a disc parked by a SCSI-initiated eject (`START STOP loej=1`).
    pub fn take_media(&mut self) -> Option<CdMedia> {
        if matches!(self.tray, Tray::Parked(_)) {
            core::mem::replace(&mut self.tray, Tray::Empty).disc()
        } else {
            None
        }
    }

    /// The loaded medium, if any. A parked disc is SCSI-ejected: logically
    /// NOT PRESENT until reclaimed or reloaded.
    ///
    /// Retained for callers that inspect/adjust the loaded media value; the
    /// device itself no longer reads or writes through it (data I/O goes
    /// through the LUN's store plane).
    #[allow(dead_code)]
    pub(crate) fn loaded_mut(&mut self) -> Option<&mut CdMedia> {
        match &mut self.tray {
            Tray::Loaded(m) => Some(m),
            _ => None,
        }
    }

    fn loaded_ref(&self) -> Option<&CdMedia> {
        match &self.tray {
            Tray::Loaded(m) => Some(m),
            _ => None,
        }
    }

    fn loaded(&self) -> bool {
        matches!(self.tray, Tray::Loaded(_))
    }

    /// Whether media is present.
    pub fn is_media_present(&self) -> bool {
        self.loaded()
    }

    /// Whether `load()` was requested by START STOP Load=1 on empty tray.
    pub fn media_requested(&self) -> bool {
        self.media_requested
    }

    /// Borrow the pending sense, if any (single source of truth: `Some`
    /// ⇔ a sense is pending).
    pub fn peek_sense(&self) -> Option<&Sense> {
        self.sense.as_ref()
    }

    /// Take the pending sense, clearing the device.
    pub fn take_sense(&mut self) -> Option<Sense> {
        self.sense.take()
    }

    // ── Helper ─────────────────────────────────────────────────────

    fn set_sense(&mut self, key: SenseKey, asc: u8, ascq: u8) {
        self.sense = Some(Sense::new(key, asc, ascq));
    }

    fn cc(&mut self, key: SenseKey, asc: u8) -> CommandOutcome {
        self.set_sense(key, asc, 0);
        CommandOutcome::CheckCondition
    }

    fn not_ready(&mut self) -> CommandOutcome {
        let ascq = if self.tray_open {
            asc::MEDIUM_NOT_PRESENT_TRAY_OPEN
        } else {
            asc::MEDIUM_NOT_PRESENT_TRAY_CLOSED
        };
        let s = Sense::new(SenseKey::NotReady, asc::MEDIUM_NOT_PRESENT, ascq);
        self.sense = Some(s);
        CommandOutcome::CheckCondition
    }

    fn lead_out_lba(&self) -> u32 {
        if let Some(m) = self.loaded_ref() {
            return m.lead_out_lba();
        }
        0
    }

    fn max_lba(&self) -> u64 {
        if let Some(m) = self.loaded_ref() {
            return m.max_lba();
        }
        0
    }

    /// Whether the loaded medium accepts SBC random writes.
    fn is_random_writable(&self) -> bool {
        self.media_state().random_writable
    }

    fn media_state(&self) -> MediaState {
        self.loaded_ref()
            .map(CdMedia::state)
            .unwrap_or_else(MediaState::empty)
    }

    /// TOC address helper (LBA or MSF).
    fn toc_address(&self, lba: u32, msf: bool) -> [u8; 4] {
        if !msf {
            return lba.to_be_bytes();
        }
        let v = lba + 150;
        let m = v / (75 * 60);
        let s = (v % (75 * 60)) / 75;
        let f = v % 75;
        [0x00, m as u8, s as u8, f as u8]
    }

    // ── xfer helpers ──────────────────────────────────────────────

    /// Capacity in bytes of the loaded medium (cached geometry), or `None`
    /// when the tray is empty / parked.
    fn media_capacity(&self) -> Option<u64> {
        self.loaded_ref().map(CdMedia::capacity)
    }

    /// Arm the FORMAT UNIT / BLANK whole-disc zero-fill agenda: every
    /// logical block of the loaded medium is cleared.
    /// [`ScsiDevice::next_store_op`](crate::scsi::device::ScsiDevice::next_store_op)
    /// yields the fill as `StoreOp::Fill` in 64 KiB chunks until exhausted;
    /// the command phase performs no storage I/O.
    #[cfg(feature = "dvdram")]
    fn arm_format(&mut self) {
        let cap = self.media_capacity().unwrap_or(0);
        self.format_off = 0;
        self.format_remaining = cap;
        self.format_byte = 0;
    }

    /// Read `buf.len()` bytes for the current READ transfer (device → host).
    ///
    /// Returns [`Xfer::Store`] carrying a [`StoreOp::Read`] addressed at the
    /// absolute plane byte (`base_byte + transfer_offset`); the shell executes
    /// it against the LUN's store plane. The pending/direction/range guards
    /// stay here so a misuse (only reachable through a broken wrapper —
    /// `do_cmd` already validated) sets sense and yields a zero-length
    /// [`Xfer::Inline`].
    pub fn xfer_out<'a>(&'a mut self, transfer_offset: u64, buf: &'a mut [u8]) -> Xfer<'a> {
        let (dir, transfer_len, base_byte) = match self.pending {
            Some(p) => (p.dir, p.transfer_len, p.base_byte),
            None => {
                self.set_sense(SenseKey::IllegalRequest, 0x24, 0);
                return Xfer::Inline { len: 0 };
            }
        };
        if dir != XferDir::Out {
            self.set_sense(SenseKey::IllegalRequest, 0x24, 0);
            return Xfer::Inline { len: 0 };
        }
        let end = match transfer_offset.checked_add(buf.len() as u64) {
            Some(e) => e,
            None => {
                self.set_sense(SenseKey::IllegalRequest, 0x21, 0);
                return Xfer::Inline { len: 0 };
            }
        };
        if end > transfer_len {
            self.set_sense(SenseKey::IllegalRequest, 0x21, 0);
            return Xfer::Inline { len: 0 };
        }
        let actual = base_byte + transfer_offset;
        // Defensive geometry guard (the plane would also bound-check). An
        // out-of-range read or an empty tray reports MEDIUM ERROR 11h/00h,
        // matching the old direct `read_data` mapping.
        match self.media_capacity() {
            Some(cap)
                if actual
                    .checked_add(buf.len() as u64)
                    .is_some_and(|e| e <= cap) => {}
            _ => {
                self.set_sense(SenseKey::MediumError, 0x11, 0);
                return Xfer::Inline { len: 0 };
            }
        }
        Xfer::Store(StoreOp::Read { off: actual, buf })
    }

    /// Write `buf` for the current WRITE transfer (host → device).
    ///
    /// Returns [`Xfer::Store`] carrying a [`StoreOp::Write`] addressed at the
    /// absolute plane byte (`base_byte + transfer_offset`). The write-path
    /// gate (random-writable media only) and geometry are checked here; the
    /// command phase already rejected read-only media with DATA PROTECT, so
    /// this is a defensive re-check for broken wrappers.
    pub fn xfer_in<'a>(&'a mut self, transfer_offset: u64, buf: &'a [u8]) -> Xfer<'a> {
        let (dir, transfer_len, base_byte) = match self.pending {
            Some(p) => (p.dir, p.transfer_len, p.base_byte),
            None => {
                self.set_sense(SenseKey::IllegalRequest, 0x24, 0);
                return Xfer::Inline { len: 0 };
            }
        };
        if dir != XferDir::In {
            self.set_sense(SenseKey::IllegalRequest, 0x24, 0);
            return Xfer::Inline { len: 0 };
        }
        let end = match transfer_offset.checked_add(buf.len() as u64) {
            Some(e) => e,
            None => {
                self.set_sense(SenseKey::IllegalRequest, 0x21, 0);
                return Xfer::Inline { len: 0 };
            }
        };
        if end > transfer_len {
            self.set_sense(SenseKey::IllegalRequest, 0x21, 0);
            return Xfer::Inline { len: 0 };
        }
        if !self.is_random_writable() {
            self.set_sense(SenseKey::DataProtect, asc::WRITE_PROTECTED, 0);
            return Xfer::Inline { len: 0 };
        }
        let actual = base_byte + transfer_offset;
        match self.media_capacity() {
            Some(cap)
                if actual
                    .checked_add(buf.len() as u64)
                    .is_some_and(|e| e <= cap) => {}
            None => {
                self.set_sense(SenseKey::DataProtect, asc::WRITE_PROTECTED, 0);
                return Xfer::Inline { len: 0 };
            }
            Some(_) => {
                self.set_sense(SenseKey::IllegalRequest, asc::LBA_OUT_OF_RANGE, 0);
                return Xfer::Inline { len: 0 };
            }
        }
        Xfer::Store(StoreOp::Write { off: actual, buf })
    }

    // ── Unified command dispatch ───────────────────────

    /// Process one SCSI command.  **All** MMC commands are dispatched
    /// here — media only provides structured values.
    pub fn do_cmd(
        &mut self,
        cdb: &[u8],
        data: &mut [u8],
    ) -> Result<CommandOutcome, crate::scsi::device::Error> {
        if data.len() < crate::MIN_DATA_LEN {
            return Err(crate::scsi::device::Error::WorkBufTooSmall);
        }
        // PendingXfer is per-command: clear at entry.
        self.pending = None;
        // The maintenance agenda is per-command too: a stale fill/sync from a
        // command the session never drained must not leak into the next one.
        self.format_remaining = 0;
        self.sync_pending = false;

        let spc = parse_spc(cdb);

        // DELIBERATE SPEC DEVIATION, documented here so nobody "fixes" it
        // back by accident. With a PREVENT latch set, the letter of the
        // standards requires rejecting a LoEj ejection: SPC-3 §6.13 says the
        // LU "shall not allow medium removal" and shall inhibit even
        // operator mechanisms while prevention is in effect, and MMC-6 §6.13
        // states plainly that such a START STOP UNIT "is rejected by the
        // Drive". The compliant answer is CHECK CONDITION 05/53/02.
        //
        // We honour the request anyway and clear the latch: Windows' eject
        // path never sends PREVENT=0 first (usbms-28/snow4), so strict
        // compliance makes ejection permanently impossible against this
        // guest. If strict semantics are ever wanted, gate this block
        // behind a CLI flag.
        let is_user_eject = matches!(
            spc,
            Some(SpcCommand::StartStop {
                loej: true,
                load: false,
            })
        );
        if is_user_eject && self.prevent_removal {
            self.prevent_removal = false;
        }

        // Sense delivery rules (SPC-4 §5.14 / §7.9):
        // - REQUEST SENSE must ALWAYS reach the executor untouched: it has
        //   to serve whatever the last CHECK CONDITION carried. Neither the
        //   UA preemption below nor stale-sense cleanup may consume or drop
        //   a pending sense on its behalf. (Regression: discarding stale
        //   sense at entry made every REQUEST SENSE answer NO SENSE, which
        //   blinded Windows' eject retries.)
        // - A UNIT ATTENTION preempts exactly one other command — reported
        //   once as CHECK CONDITION carrying it, consumed on delivery —
        //   except for INQUIRY / REPORT LUNS / REQUEST SENSE (SPC-4: these
        //   never clear a unit attention) and the user eject above (a tray
        //   button press neither reports nor clears it).
        // - Any other pending sense is inert for command dispatch: it must
        //   not preempt, but it is left in place so a following REQUEST
        //   SENSE can still report it; the next error simply overwrites it.
        if let Some(s) = self.peek_sense() {
            // MMC-6 §4.1.6.1: GET CONFIGURATION / GESN must not be terminated
            // by Unit Attention (same exemption as INQUIRY / REQUEST SENSE).
            let ua_bypass = is_user_eject
                || matches!(spc, Some(SpcCommand::RequestSense { .. }))
                || cdb_opcode(cdb) == Some(op::REQUEST_SENSE)
                || matches!(spc, Some(SpcCommand::Inquiry { .. }))
                || matches!(
                    cdb_opcode(cdb),
                    Some(op::INQUIRY)
                        | Some(op::REPORT_LUNS)
                        | Some(op::GET_CONFIGURATION)
                        | Some(op::GET_EVENT_STATUS_NOTIFICATION)
                );
            if s.key == SenseKey::UnitAttention && !ua_bypass {
                let _ = self.take_sense(); // reported once — drop it
                return Ok(CommandOutcome::CheckCondition);
            }
        }

        let spc = parse_spc(cdb);

        // ── Intercept TUR before execute_spc ──────────
        if let Some(SpcCommand::TestUnitReady) = spc {
            if matches!(self.tray, Tray::Loaded(_)) {
                // GOOD; sense already None or will be cleared by not having UA.
                // Ensure sense is cleared for GOOD? With owning Option, GOOD leaves sense None.
                // If there was a UA that was bypass? TUR is not bypass, so we wouldn't be here with UA.
                return Ok(CommandOutcome::Status);
            }
            return Ok(self.not_ready());
        }

        if let Some(SpcCommand::ModeSense {
            long,
            page: 0x05,
            pc: _,
            alloc,
        }) = spc
        {
            return Ok(self.mode_sense_write_params(long, alloc, data));
        }
        if let Some(SpcCommand::ModeSelect { alloc, .. }) = spc {
            return Ok(self.mode_select_cmd(alloc));
        }

        let outcome = if let Some(cmd) = spc {
            execute_spc(self, cmd, data)
        } else {
            let Some(op) = cdb_opcode(cdb) else {
                return Ok(self.cc(SenseKey::IllegalRequest, asc::INVALID_COMMAND));
            };
            if cdb.len() < usize::from(cdb_len_from_opcode(op)) {
                return Ok(self.cc(SenseKey::IllegalRequest, asc::INVALID_COMMAND));
            }
            match op {
                op::FORMAT_UNIT => self.format_unit_cmd(cdb),
                // ── READ(6/10/12/16) ────────────────────────────
                op::READ_6 | op::READ_10 | op::READ_12 | op::READ_16 => {
                    let Some((lba, count)) = cdb_read_args(op, cdb) else {
                        return Ok(self.cc(SenseKey::IllegalRequest, asc::INVALID_COMMAND));
                    };
                    self.read_cmd(lba, count, data)
                }

                // ── WRITE(6/10/12/16) ───────────────────────────
                op::WRITE_6 | op::WRITE_10 | op::WRITE_12 | op::WRITE_16 => {
                    let Some((lba, count)) = cdb_write_args(op, cdb) else {
                        return Ok(self.cc(SenseKey::IllegalRequest, asc::INVALID_COMMAND));
                    };
                    if !self.is_random_writable() {
                        self.cc(SenseKey::DataProtect, asc::WRITE_PROTECTED)
                    } else if count == 0 {
                        CommandOutcome::Status
                    } else if lba > self.max_lba()
                        || lba
                            .checked_add(u64::from(count))
                            .is_none_or(|end| end > self.max_lba() + 1)
                    {
                        self.cc(SenseKey::IllegalRequest, asc::LBA_OUT_OF_RANGE)
                    } else {
                        let Some(bytes) = u64::from(count).checked_mul(u64::from(SECTOR_SIZE))
                        else {
                            return Ok(self.cc(SenseKey::IllegalRequest, asc::INVALID_FIELD));
                        };
                        let transfer_len = bytes;
                        self.pending = Some(PendingXfer {
                            base_byte: lba * u64::from(SECTOR_SIZE),

                            block_size: SECTOR_SIZE,
                            dir: XferDir::In,
                            transfer_len,
                        });
                        CommandOutcome::InXfer { len: transfer_len }
                    }
                }

                // ── READ CAPACITY(10) ───────────────────────────
                op::READ_CAPACITY_10 => {
                    let Some(lba) = cdb_lba10(cdb) else {
                        return Ok(self.cc(SenseKey::IllegalRequest, asc::INVALID_COMMAND));
                    };
                    // SBC-3 Table 62: PMI is byte 8 bit 0; byte 1 bit 0 is Obsolete.
                    self.read_capacity_10_cmd(cdb[8] & 0x01 != 0, lba, data)
                }

                // ── READ CAPACITY(16) ───────────────────────────
                op::SERVICE_ACTION_IN => {
                    let sa = cdb[1] & 0x1F;
                    let alloc = (u32::from(cdb[10]) << 24)
                        | (u32::from(cdb[11]) << 16)
                        | (u32::from(cdb[12]) << 8)
                        | u32::from(cdb[13]);
                    let lba = u64::from_be_bytes([
                        cdb[2], cdb[3], cdb[4], cdb[5], cdb[6], cdb[7], cdb[8], cdb[9],
                    ]);
                    let pmi = cdb[14] & 0x01 != 0;
                    self.read_capacity_16_cmd(sa, alloc, lba, pmi, data)
                }

                // ── READ TOC (0x43) ─────────────────────────────
                op::READ_TOC => {
                    if !self.loaded() {
                        return Ok(self.not_ready());
                    }
                    self.read_toc_cmd(cdb, data)
                }

                // ── GET CONFIGURATION (0x46) ─────────────────────
                op::GET_CONFIGURATION => self.get_configuration_cmd(cdb, data),

                // ── READ DISC INFORMATION (0x51) ─────────────────
                op::READ_DISC_INFORMATION => {
                    if !self.loaded() {
                        return Ok(self.not_ready());
                    }
                    self.read_disc_info_cmd(cdb, data)
                }

                // ── READ BUFFER CAPACITY (0x5C) ──────────────────
                op::READ_BUFFER_CAPACITY => self.read_buffer_capacity_cmd(cdb, data),

                // ── GET EVENT STATUS NOTIFICATION (0x4A) ──────────
                op::GET_EVENT_STATUS_NOTIFICATION => self.gesn_cmd(cdb, data),

                // ── READ DVD STRUCTURE (0xAD) ────────────────────
                op::READ_DVD_STRUCTURE => {
                    if !self.loaded() {
                        return Ok(self.not_ready());
                    }
                    self.read_dvd_structure_cmd(cdb, data)
                }

                // ── READ TRACK INFORMATION (0x52) ────────────────
                op::READ_TRACK_INFORMATION => {
                    if !self.loaded() {
                        return Ok(self.not_ready());
                    }
                    self.read_track_information_cmd(cdb, data)
                }

                // ── READ CD (0xBE) / READ CD MSF (0xB9) ───────────
                // Minimal Mode-1 alias for CD Read feature (Current=1).
                op::READ_CD | op::READ_CD_MSF => {
                    if !self.loaded() {
                        return Ok(self.not_ready());
                    }
                    self.read_cd_cmd(cdb, data)
                }

                // ── GET PERFORMANCE (0xAC) ─────────────────────────
                // Minimal empty performance table for RTS feature.
                op::GET_PERFORMANCE => {
                    if !self.loaded() {
                        return Ok(self.not_ready());
                    }
                    self.get_performance_cmd(cdb, data)
                }

                // ── READ FORMAT CAPACITIES (0x23) ────────────────
                op::READ_FORMAT_CAPACITIES => self.read_format_capacities_cmd(cdb, data),

                // ── SYNCHRONIZE CACHE(10) ────────────────────────
                op::SYNCHRONIZE_CACHE_10 => {
                    let immed = cdb[1] & 0x02 != 0;
                    if immed {
                        return Ok(self.cc(SenseKey::IllegalRequest, asc::INVALID_FIELD));
                    }
                    let lba = u32::from_be_bytes([cdb[2], cdb[3], cdb[4], cdb[5]]);
                    let num_blocks = u16::from_be_bytes([cdb[7], cdb[8]]);
                    let max_lba = self.max_lba();
                    if num_blocks == 0 {
                        if u64::from(lba) > max_lba {
                            return Ok(self.cc(SenseKey::IllegalRequest, asc::LBA_OUT_OF_RANGE));
                        }
                    } else if u64::from(lba) > max_lba
                        || u64::from(lba) + u64::from(num_blocks) > max_lba + 1
                    {
                        return Ok(self.cc(SenseKey::IllegalRequest, asc::LBA_OUT_OF_RANGE));
                    }
                    // SYNC_NV (cdb[1] & 0x04) is ignored (no non-volatile cache).
                    self.sync_cache_cmd()
                }

                // ── SET CD SPEED (0xBB) ──────────────────────────
                op::SET_CD_SPEED => CommandOutcome::Status,

                // ── SEND OPC (0x54) ──────────────────────────────
                // MMC-6 §6.38: DoOpc=1 → GOOD (OPC values computed, the
                // Parameter List is ignored). DoOpc=0 → receive the declared
                // Parameter List (Table 614); PLL must be an integral
                // multiple of 8 (§6.38.2.4) or 05/24.
                op::SEND_OPC_INFORMATION => {
                    let pll = u16::from_be_bytes([cdb[7], cdb[8]]);
                    if cdb[1] & 0x01 != 0 || pll == 0 {
                        CommandOutcome::Status
                    } else if !pll.is_multiple_of(8) {
                        self.cc(SenseKey::IllegalRequest, asc::INVALID_FIELD)
                    } else {
                        CommandOutcome::InParam {
                            expected_len: pll as usize,
                        }
                    }
                }

                // ── SET STREAMING (0xB6) ─────────────────────────
                // MMC-6 §6.41: only Type=0 (performance descriptor) is
                // supported — no Enhanced Defect Reporting / DBI cache model,
                // so other Types are 05/24 (§6.41.2.2). Receive the declared
                // Parameter List (Table 625) and discard it.
                op::SET_STREAMING => {
                    if cdb[8] != 0 {
                        self.cc(SenseKey::IllegalRequest, asc::INVALID_FIELD)
                    } else {
                        let pll = u16::from_be_bytes([cdb[9], cdb[10]]);
                        if pll == 0 {
                            CommandOutcome::Status
                        } else {
                            CommandOutcome::InParam {
                                expected_len: pll as usize,
                            }
                        }
                    }
                }

                // ── CLOSE TRACK (0x5B) ───────────────────────────
                // MMC-6 Table 234: CDB-only (Immed / Close Function /
                // Logical Track Number) — no parameter list. Our
                // finalized single-track model has nothing to close: GOOD.
                op::CLOSE_TRACK => CommandOutcome::Status,

                // ── BLANK (0xA1) — for DVD-RAM alias to FORMAT (BurnAware clear)
                0xA1 => {
                    if self.is_random_writable() {
                        #[cfg(feature = "dvdram")]
                        {
                            if matches!(self.loaded_ref(), Some(CdMedia::Rw(_))) {
                                // Arm the whole-disc zero-fill on the agenda;
                                // the session drains it before the terminal
                                // status. Report GOOD + UNIT ATTENTION (media
                                // may have changed), matching the old inline
                                // format.
                                self.arm_format();
                                self.sense = Some(Sense::new(
                                    SenseKey::UnitAttention,
                                    asc::MEDIUM_MAY_HAVE_CHANGED,
                                    0,
                                ));
                                CommandOutcome::Status
                            } else {
                                self.cc(SenseKey::DataProtect, asc::WRITE_PROTECTED)
                            }
                        }
                        #[cfg(not(feature = "dvdram"))]
                        {
                            self.cc(SenseKey::DataProtect, asc::WRITE_PROTECTED)
                        }
                    } else {
                        self.cc(SenseKey::IllegalRequest, asc::INVALID_FIELD)
                    }
                }

                // ── Unknown → INVALID COMMAND ─────────────────────
                _ => self.cc(SenseKey::IllegalRequest, asc::INVALID_COMMAND),
            }
        };

        Ok(outcome)
    }

    fn mode_sense_write_params(&self, long: bool, alloc: u16, data: &mut [u8]) -> CommandOutcome {
        let page = if self.mode_page_05_valid {
            &self.mode_page_05[..]
        } else {
            default_write_params_page()
        };
        let header_len = if long { 8 } else { 4 };
        let total = header_len + page.len();
        let mode_len = if long { total - 2 } else { total - 1 };
        let mut buf = [0u8; 64];
        if long {
            buf[0..2].copy_from_slice(&(mode_len as u16).to_be_bytes());
            buf[2] = self.medium_type();
        } else {
            buf[0] = mode_len as u8;
            buf[1] = self.medium_type();
        }
        buf[header_len..total].copy_from_slice(page);
        let n = total.min(alloc as usize).min(data.len());
        data[..n].copy_from_slice(&buf[..n]);
        CommandOutcome::OutInline { len: n }
    }

    fn mode_select_cmd(&mut self, alloc: u16) -> CommandOutcome {
        let expected = alloc as usize;
        if expected == 0 {
            return CommandOutcome::Status;
        }
        // The parameter list is validated in `complete_mode_select` (via
        // `complete_param`) once the transport has collected it. Whether the
        // list arrived as iSCSI immediate data or is gathered via R2T /
        // bulk-Data-Out is the transport's concern, not the device's.
        CommandOutcome::InParam {
            expected_len: expected,
        }
    }

    fn complete_mode_select(&mut self, long: bool, _alloc: u16, data: &[u8]) -> CommandOutcome {
        let header_len = if long { 8 } else { 4 };
        if data.len() < header_len {
            return self.cc(SenseKey::IllegalRequest, asc::INVALID_FIELD);
        }
        let block_len = if long {
            usize::from(u16::from_be_bytes([data[6], data[7]]))
        } else {
            usize::from(data[3])
        };
        let page_start = header_len + block_len;
        if page_start + 2 > data.len() {
            return self.cc(SenseKey::IllegalRequest, asc::INVALID_FIELD);
        }
        let page_code = data[page_start] & 0x3F;
        let page_len = usize::from(data[page_start + 1]);
        let end = page_start + 2 + page_len;
        if page_code != 0x05
            || page_len < 2
            || end > data.len()
            || page_len + 2 > self.mode_page_05.len()
        {
            return self.cc(SenseKey::IllegalRequest, asc::INVALID_FIELD);
        }
        self.mode_page_05.fill(0);
        self.mode_page_05[..2 + page_len].copy_from_slice(&data[page_start..end]);
        self.mode_page_05_valid = true;
        CommandOutcome::Status
    }

    fn format_unit_cmd(&mut self, cdb: &[u8]) -> CommandOutcome {
        if !self.loaded() {
            return self.not_ready();
        }
        // MMC-6 Table 237: byte 1 carries FmtData (bit 4), CmpList (bit 3)
        // and the Format Code (bits 2-0). Multi-Media drives require
        // FmtData=1 and Format Code=001b; CmpList is accepted (DVD-RAM).
        if cdb[1] & 0x10 == 0 || cdb[1] & 0x07 != 0x01 {
            return self.cc(SenseKey::IllegalRequest, asc::INVALID_FIELD);
        }
        // 12-byte parameter list; completion happens in `complete_format_unit`
        // (via `complete_param`) after the transport collects it.
        CommandOutcome::InParam { expected_len: 12 }
    }

    fn complete_format_unit(&mut self, cdb: &[u8], data: &[u8]) -> CommandOutcome {
        if !self.loaded() {
            return self.not_ready();
        }
        if data.len() != 12 {
            return self.cc(
                SenseKey::IllegalRequest,
                asc::INVALID_FIELD_IN_PARAMETER_LIST,
            );
        }
        if cdb[1] & 0x10 == 0 || cdb[1] & 0x07 != 0x01 {
            return self.cc(SenseKey::IllegalRequest, asc::INVALID_FIELD);
        }
        // Format List Header validation (MMC-6 §6.4.3.2, Table 240):
        // DPRY shall be zero, STPF is reserved, IP shall be zero for
        // Multi-Media drives, and when FOV=0 the host must also clear
        // DCRT and Try-out (defaults apply). Immed/VS/DCRT are accepted.
        if data[1] & (0x40 | 0x10 | 0x08) != 0
            || (data[1] & 0x80 == 0 && data[1] & (0x20 | 0x04) != 0)
            || u16::from_be_bytes([data[2], data[3]]) != 8
        {
            return self.cc(
                SenseKey::IllegalRequest,
                asc::INVALID_FIELD_IN_PARAMETER_LIST,
            );
        }
        // Format Descriptor (MMC-6 Table 241). The Number of Blocks field is
        // advisory ("typically ... the number of addressable blocks for the
        // entire disc") — initiators such as dvd+rw-format echo the medium
        // capacity back — so it is not validated. Only the DVD-RAM Full
        // Format (type 00h) with 2048-byte blocks is implemented; a zero
        // block length is tolerated for leniency towards other initiators.
        let block_len = u32::from_be_bytes([0, data[9], data[10], data[11]]);
        if data[8] != 0x00 || (block_len != 2048 && block_len != 0) {
            return self.cc(
                SenseKey::IllegalRequest,
                asc::INVALID_FIELD_IN_PARAMETER_LIST,
            );
        }
        // Try-out determines formatting feasibility without touching the
        // medium (MMC-6 §6.4.3.2 e): validation above is the whole job.
        if data[1] & 0x04 != 0 {
            return CommandOutcome::Status;
        }
        // The format runs synchronously in this emulation, so Immed and
        // non-Immed are observably identical: arm the whole-disc zero-fill
        // agenda, report GOOD, and queue UNIT ATTENTION so the host re-reads
        // DiscInfo/TOC/Capacity. The session drains the agenda (invisible on
        // the wire) before the terminal status; the command phase performs
        // no storage I/O.
        #[cfg(feature = "dvdram")]
        if matches!(self.loaded_ref(), Some(CdMedia::Rw(_))) {
            self.arm_format();
            // Signal media change so host re-reads DiscInfo/TOC/Capacity.
            self.sense = Some(Sense::new(
                SenseKey::UnitAttention,
                asc::MEDIUM_MAY_HAVE_CHANGED,
                0,
            ));
            return CommandOutcome::Status;
        }
        self.cc(SenseKey::DataProtect, asc::WRITE_PROTECTED)
    }

    // ── READ handler ────────────────────────────────────────────────

    fn read_cmd(&mut self, lba: u64, count: u32, _data: &mut [u8]) -> CommandOutcome {
        if count == 0 {
            return CommandOutcome::Status;
        }
        let max = self.max_lba();
        if lba > max
            || lba
                .checked_add(u64::from(count))
                .is_none_or(|end| end > max + 1)
        {
            return self.cc(SenseKey::IllegalRequest, asc::LBA_OUT_OF_RANGE);
        }
        let Some(bytes) = u64::from(count)
            .checked_mul(u64::from(SECTOR_SIZE))
            .and_then(|b| u32::try_from(b).ok())
        else {
            return self.cc(SenseKey::IllegalRequest, asc::INVALID_FIELD);
        };
        let transfer_len = bytes as u64;
        self.pending = Some(PendingXfer {
            base_byte: lba * u64::from(SECTOR_SIZE),
            block_size: SECTOR_SIZE,
            dir: XferDir::Out,
            transfer_len,
        });
        CommandOutcome::OutXfer { len: transfer_len }
    }

    // ── READ CAPACITY ───────────────────────────────────────────────

    fn read_capacity_10_cmd(&mut self, pmi: bool, req_lba: u32, data: &mut [u8]) -> CommandOutcome {
        if !self.loaded() {
            return self.not_ready();
        }
        // SBC-3 §5.15.2: PMI=0 requires LBA=0; PMI=1 requires LBA ≤ RETURNED LBA.
        let max_lba = self.max_lba().min(u32::MAX as u64) as u32;
        if !pmi && req_lba != 0 {
            return self.cc(SenseKey::IllegalRequest, asc::INVALID_FIELD);
        }
        if pmi && req_lba > max_lba {
            return self.cc(SenseKey::IllegalRequest, asc::INVALID_FIELD);
        }
        data[0..4].copy_from_slice(&max_lba.to_be_bytes());
        data[4..8].copy_from_slice(&SECTOR_SIZE.to_be_bytes());
        CommandOutcome::OutInline { len: 8 }
    }

    fn read_capacity_16_cmd(
        &mut self,
        sa: u8,
        alloc: u32,
        lba: u64,
        pmi: bool,
        data: &mut [u8],
    ) -> CommandOutcome {
        if !self.loaded() {
            return self.not_ready();
        }
        if sa != 0x10 {
            return self.cc(SenseKey::IllegalRequest, asc::INVALID_FIELD);
        }
        if !pmi && lba != 0 {
            return self.cc(SenseKey::IllegalRequest, asc::INVALID_FIELD);
        }
        let max_lba = self.max_lba();
        if pmi && lba > max_lba {
            return self.cc(SenseKey::IllegalRequest, asc::INVALID_FIELD);
        }
        let mut buf = [0u8; 32];
        buf[0..8].copy_from_slice(&max_lba.to_be_bytes());
        buf[8..12].copy_from_slice(&SECTOR_SIZE.to_be_bytes());
        let n = 32.min(alloc as usize);
        data[0..n].copy_from_slice(&buf[..n]);
        CommandOutcome::OutInline { len: n }
    }

    // ── READ TOC ────────────────────────────────────────────────────

    fn read_toc_cmd(&mut self, cdb: &[u8], data: &mut [u8]) -> CommandOutcome {
        let msf = cdb[1] & 0x02 != 0;
        let format = cdb[2] & 0x0F;
        let track = cdb[6];
        let alloc = (u16::from(cdb[7]) << 8) | u16::from(cdb[8]);

        let (buf, n): ([u8; 22], usize) = match format {
            0x0 => {
                let lead_out = self.lead_out_lba();
                let track1_addr = self.toc_address(0, msf);
                let lead_addr = self.toc_address(lead_out, msf);
                let mut b = [0u8; 22];
                b[1] = 0x12;
                b[2] = 0x01;
                b[3] = 0x01;
                match track {
                    0 | 1 => {
                        b[5] = 0x14;
                        b[6] = 0x01;
                        b[8..12].copy_from_slice(&track1_addr);
                        b[13] = 0x14;
                        b[14] = 0xAA;
                        b[16..20].copy_from_slice(&lead_addr);
                        (b, 20)
                    }
                    0xAA => {
                        b[1] = 0x0A;
                        b[5] = 0x14;
                        b[6] = 0xAA;
                        b[8..12].copy_from_slice(&lead_addr);
                        (b, 12)
                    }
                    _ => return self.cc(SenseKey::IllegalRequest, asc::INVALID_FIELD),
                }
            }
            0x1 => {
                let mut b = [0u8; 22];
                b[1] = 0x0A;
                b[2] = 0x01;
                b[3] = 0x01;
                b[5] = 0x14;
                b[6] = 0x01;
                b[8..12].copy_from_slice(&self.toc_address(0, msf));
                (b, 12)
            }
            _ => return self.cc(SenseKey::IllegalRequest, asc::INVALID_FIELD),
        };
        let n = n.min(alloc as usize);
        data[0..n].copy_from_slice(&buf[..n]);
        CommandOutcome::OutInline { len: n }
    }

    // ── GET CONFIGURATION ───────────────────────────────────────────

    fn get_configuration_cmd(&mut self, cdb: &[u8], data: &mut [u8]) -> CommandOutcome {
        let rt = cdb[1] & 0x03;
        let start = (u16::from(cdb[2]) << 8) | u16::from(cdb[3]);
        let alloc = (u16::from(cdb[7]) << 8) | u16::from(cdb[8]);
        if rt == 0x03 {
            return self.cc(SenseKey::IllegalRequest, asc::INVALID_FIELD);
        }
        let media = self.media_state();

        build_get_config_response_for_media(data, &self.caps, &media, rt, start, alloc)
    }

    // ── READ DISC INFORMATION ───────────────────────────────────────

    fn read_disc_info_cmd(&mut self, cdb: &[u8], data: &mut [u8]) -> CommandOutcome {
        if cdb[1] & 0x07 != 0 {
            return self.cc(SenseKey::IllegalRequest, asc::INVALID_FIELD);
        }
        let alloc = (u16::from(cdb[7]) << 8) | u16::from(cdb[8]);
        // The emulated medium always has addressable logical blocks — it is
        // always *formatted* — so it is never blank (MMC-6 Table 498: "Blank
        // has no meaning" for DVD-RAM). A formatted *rewritable* reports Disc
        // Status 10b "Finalized" with a Complete last session (Table 372, the
        // BD-RE analogue; a DVD-RAM is the rewritable class). Disc status is
        // about the *medium* format, not the file system the host may or may
        // not have written (FORMAT UNIT != creating a file system).
        //
        // NB: 11b "Others" is the value for *write-once* random media (BD-R
        // RRM, Table 375); real hosts (Linux udisks) refuse to auto-mount a
        // data disc that reports it.
        let disc_status = 2; // 10b Finalized
        let state_of_last_session = 3; // 11b Complete
        let erasable = self.is_random_writable();
        let info = DiscInfo {
            disc_status,
            state_of_last_session,
            erasable,
            sessions: 1,
            first_track: 1,
            last_track: 1,
            disc_type: 0x00,
            mrw_status: 0,
            lead_out_lba: self.lead_out_lba(),
        };
        build_read_disc_info(data, alloc, &info)
    }

    // ── READ BUFFER CAPACITY ────────────────────────────────────────

    fn read_buffer_capacity_cmd(&mut self, cdb: &[u8], data: &mut [u8]) -> CommandOutcome {
        if cdb[1] & 0x01 != 0 {
            return self.cc(SenseKey::IllegalRequest, asc::INVALID_FIELD);
        }
        let alloc = (u16::from(cdb[8]) << 8) | u16::from(cdb[9]);
        build_read_buffer_capacity(data, alloc, 0, 0)
    }

    // ── GET EVENT STATUS NOTIFICATION ────────────────────────────────

    fn gesn_cmd(&mut self, cdb: &[u8], data: &mut [u8]) -> CommandOutcome {
        // Polled bit (byte 1 bit 0): Poll=0 requests async operation.
        // This drive does not support async (no command queuing), so
        // reject per MMC-6 §6.6.1.2.
        if cdb[1] & 0x01 == 0 {
            return self.cc(SenseKey::IllegalRequest, asc::INVALID_FIELD);
        }
        let class = cdb[4];
        let alloc = (u16::from(cdb[7]) << 8) | u16::from(cdb[8]);
        let mut buf = [0u8; 8];
        let resp_len = if class & 0x10 != 0 {
            // Media class requested: NEA=0, Notification Class = Media (100b),
            // followed by the 4-byte Media Event Descriptor (Table 278).
            // Event Descriptor Length = 2 (NEA/class + supported) + 4 = 6.
            buf[0..2].copy_from_slice(&6u16.to_be_bytes());
            buf[2] = 0x04; // NEA=0, Notification Class = Media
            buf[3] = 0x10; // Supported Event Class = Media (Table 265)
            buf[4] = 0x00; // Event Code 0 = NoChg (Table 279)
            buf[5] = (u8::from(self.loaded()) << 1) | u8::from(self.tray_open); // Table 280
            8
        } else {
            // No requested class supported: NEA=1, Notification Class 000b and
            // only the Event Header is returned (Table 265). Supported Event
            // Class still advertises Media (the drive does support it).
            buf[0..2].copy_from_slice(&2u16.to_be_bytes());
            buf[2] = 0x80; // NEA=1
            buf[3] = 0x10; // Supported Event Class = Media
            4
        };
        let n = resp_len.min(alloc as usize).min(data.len());
        data[..n].copy_from_slice(&buf[..n]);
        CommandOutcome::OutInline { len: n }
    }

    // ── READ DVD STRUCTURE ──────────────────────────────────────────

    fn read_dvd_structure_cmd(&mut self, cdb: &[u8], data: &mut [u8]) -> CommandOutcome {
        let media_type = cdb[1] & 0x3F;
        let layer = cdb[6] & 0x0F;
        let format = cdb[7];
        let alloc = (u16::from(cdb[8]) << 8) | u16::from(cdb[9]);
        if media_type != 0 || layer != 0 {
            return self.cc(SenseKey::IllegalRequest, asc::INVALID_FIELD);
        }
        match format {
            0 => {
                #[cfg(feature = "dvdram")]
                if let Some(m) = self.loaded_ref() {
                    if let Some(pf) = m.dvd_physical_format() {
                        let mut buf = [0u8; 28];
                        buf[0..2].copy_from_slice(&0x0018u16.to_be_bytes());
                        buf[4] = pf.disk_category_part_version;
                        buf[6] = pf.layer_type;
                        buf[9..13].copy_from_slice(&pf.data_start.to_be_bytes());
                        buf[13..17].copy_from_slice(&pf.data_end.to_be_bytes());
                        buf[17..21].copy_from_slice(&pf.next_writable.to_be_bytes());
                        let n = buf.len().min(alloc as usize).min(data.len());
                        data[..n].copy_from_slice(&buf[..n]);
                        return CommandOutcome::OutInline { len: n };
                    }
                }
                self.cc(SenseKey::IllegalRequest, asc::INVALID_FIELD)
            }
            0x08 => {
                // DVD-RAM DDS — synthetic 2048-byte DDS info (MMC-6 Table 414)
                #[cfg(feature = "dvdram")]
                if let Some(m) = self.loaded_ref() {
                    if m.profile() == crate::cdrom::common::CurrentProfile::DvdRam {
                        let mut buf = [0u8; 2052];
                        buf[0..2].copy_from_slice(&0x0802u16.to_be_bytes());
                        let n = buf.len().min(alloc as usize).min(data.len());
                        data[..n].copy_from_slice(&buf[..n]);
                        return CommandOutcome::OutInline { len: n };
                    }
                }
                self.cc(SenseKey::IllegalRequest, asc::INVALID_FIELD)
            }
            0x09 => {
                // DVD-RAM Medium Status — 4-byte payload (Table 415)
                #[cfg(feature = "dvdram")]
                if let Some(m) = self.loaded_ref() {
                    if m.profile() == crate::cdrom::common::CurrentProfile::DvdRam {
                        let mut buf = [0u8; 8];
                        buf[0..2].copy_from_slice(&0x0006u16.to_be_bytes());
                        // bytes 4..8: Cartridge=0, MSWI=0, no write protect
                        let n = buf.len().min(alloc as usize).min(data.len());
                        data[..n].copy_from_slice(&buf[..n]);
                        return CommandOutcome::OutInline { len: n };
                    }
                }
                self.cc(SenseKey::IllegalRequest, asc::INVALID_FIELD)
            }
            0x0A => {
                // DVD-RAM Spare Area Information — 12-byte payload (Table 417)
                // SSA=0 logical model: zero spare counts, no allocation.
                #[cfg(feature = "dvdram")]
                if let Some(m) = self.loaded_ref() {
                    if m.profile() == crate::cdrom::common::CurrentProfile::DvdRam {
                        let mut buf = [0u8; 16];
                        buf[0..2].copy_from_slice(&0x000Eu16.to_be_bytes());
                        // bytes 4..7 primary unused, 8..11 supplementary unused, 12..15 allocated
                        let n = buf.len().min(alloc as usize).min(data.len());
                        data[..n].copy_from_slice(&buf[..n]);
                        return CommandOutcome::OutInline { len: n };
                    }
                }
                self.cc(SenseKey::IllegalRequest, asc::INVALID_FIELD)
            }
            0x0B => {
                // DVD-RAM Recording Type — 4-byte payload, Recording Type 0 = general data
                #[cfg(feature = "dvdram")]
                if let Some(m) = self.loaded_ref() {
                    if m.profile() == crate::cdrom::common::CurrentProfile::DvdRam {
                        let mut buf = [0u8; 8];
                        buf[0..2].copy_from_slice(&0x0006u16.to_be_bytes());
                        // payload Recording Type bit 0
                        let n = buf.len().min(alloc as usize).min(data.len());
                        data[..n].copy_from_slice(&buf[..n]);
                        return CommandOutcome::OutInline { len: n };
                    }
                }
                self.cc(SenseKey::IllegalRequest, asc::INVALID_FIELD)
            }
            0x30 => {
                // WDCB (write inhibit DCB) — accept and return empty DCB
                let mut buf = [0u8; 4 + 32768];
                buf[0..2].copy_from_slice(&32768u16.to_be_bytes());
                buf[4..8].copy_from_slice(&0x5744_4300u32.to_be_bytes());
                let n = buf.len().min(alloc as usize).min(data.len());
                data[..n].copy_from_slice(&buf[..n]);
                CommandOutcome::OutInline { len: n }
            }
            0xC0 => {
                // Write protect status — all clear
                let mut buf = [0u8; 8];
                buf[0..2].copy_from_slice(&4u16.to_be_bytes());
                let n = buf.len().min(alloc as usize).min(data.len());
                data[..n].copy_from_slice(&buf[..n]);
                CommandOutcome::OutInline { len: n }
            }
            _ => self.cc(SenseKey::IllegalRequest, asc::INVALID_FIELD),
        }
    }

    // ── READ TRACK INFORMATION ───────────────────────────────────────

    fn read_track_information_cmd(&mut self, cdb: &[u8], data: &mut [u8]) -> CommandOutcome {
        let type_code = cdb[1] & 0x0F;
        let alloc = (u16::from(cdb[7]) << 8) | u16::from(cdb[8]);
        if type_code > 3 {
            return self.cc(SenseKey::IllegalRequest, asc::INVALID_FIELD);
        }
        // Address type validation (MMC-6 Table 493): 0=LBA, 1=track, 2=session.
        let addr = u32::from_be_bytes([cdb[2], cdb[3], cdb[4], cdb[5]]);
        match type_code {
            0 => {
                // LBA addressing: must be within the single data track.
                if addr > self.lead_out_lba() {
                    return self.cc(SenseKey::IllegalRequest, asc::INVALID_FIELD);
                }
            }
            1 => {
                // Track number: single track 1 only. Allow 0 (wildcard) and
                // 0xFF (lead-out) for compatibility, reject 2..0xFE.
                let track = (addr & 0xFF) as u8;
                if track != 0 && track != 1 && track != 0xFF {
                    return self.cc(SenseKey::IllegalRequest, asc::INVALID_FIELD);
                }
            }
            2 => {
                // Session number: single session 1 only.
                let sess = (addr & 0xFF) as u8;
                if sess != 0 && sess != 1 {
                    return self.cc(SenseKey::IllegalRequest, asc::INVALID_FIELD);
                }
            }
            _ => {}
        }
        // Open bit (cdb[1] bit4, TRIO) is ignored for this single-track
        // finalized media — the track is always closed.
        let capacity = self.lead_out_lba();
        let mut buf = [0u8; 48];
        buf[0..2].copy_from_slice(&0x002Eu16.to_be_bytes());
        buf[2] = 1;
        buf[3] = 1;
        buf[6] = 0x04; // uninterrupted Mode-1 data track
        buf[7] = 0x21; // Packet/Inc + Mode 1
        buf[8..12].copy_from_slice(&0u32.to_be_bytes());
        buf[12..16].copy_from_slice(&0u32.to_be_bytes());
        buf[16..20].copy_from_slice(&0u32.to_be_bytes());
        buf[20..24].copy_from_slice(&16u32.to_be_bytes());
        buf[24..28].copy_from_slice(&capacity.to_be_bytes());
        buf[28..32].copy_from_slice(&0u32.to_be_bytes());
        let n = buf.len().min(alloc as usize).min(data.len());
        data[..n].copy_from_slice(&buf[..n]);
        CommandOutcome::OutInline { len: n }
    }

    fn read_cd_cmd(&mut self, cdb: &[u8], _data: &mut [u8]) -> CommandOutcome {
        // MMC-6 READ CD (BEh/B9h) minimal Mode-1 alias: LBA at 2-5, 24-bit
        // transfer length at 6-8 (BE) or MSF at 3-5 (B9). For B9, convert MSF.
        let lba = if cdb[0] == op::READ_CD_MSF {
            let m = u32::from(cdb[3]);
            let s = u32::from(cdb[4]);
            let f = u32::from(cdb[5]);
            // MSF to LBA: LBA = ((M*60)+S)*75 + F -150
            (m * 60 * 75 + s * 75 + f).saturating_sub(150)
        } else {
            u32::from_be_bytes([cdb[2], cdb[3], cdb[4], cdb[5]])
        };
        let sectors = (u32::from(cdb[6]) << 16) | (u32::from(cdb[7]) << 8) | u32::from(cdb[8]);
        let count = sectors;
        if count == 0 {
            return CommandOutcome::Status;
        }
        self.read_cmd(u64::from(lba), count, _data)
    }

    fn get_performance_cmd(&mut self, cdb: &[u8], data: &mut [u8]) -> CommandOutcome {
        // MMC-6 §6.7 GET PERFORMANCE. Only Type 00h (performance data,
        // required by the Real-time Streaming feature we advertise) is
        // supported for this medium; other Type values (unusable area,
        // defect status, write speed, DBI) return 05/24 per §6.7.2.5.
        if cdb.len() < 12 || cdb[11] != 0 {
            return self.cc(SenseKey::IllegalRequest, asc::INVALID_FIELD);
        }
        // Data Type (byte 1 bits 4:0): Tolerance(4:3) | Write(2) | Except(1:0).
        // Only nominal tables (Except=0) are provided.
        let data_type = cdb[1] & 0x1F;
        if data_type & 0x03 != 0 {
            return self.cc(SenseKey::IllegalRequest, asc::INVALID_FIELD);
        }
        let write = (data_type >> 2) & 1 != 0;
        // Maximum Number of Descriptors (bytes 8-9): zero → header only
        // (§6.7.2.4). We surface one nominal descriptor.
        let max_desc = u16::from_be_bytes([cdb[8], cdb[9]]) as usize;
        // Nominal read/write performance (Table 295): a single extent from
        // block 0 to the last addressable block at the drive's rated speed,
        // reported in 1000 bytes/s for 2048-byte sectors (non-CD media).
        let speed = (if write {
            self.caps.max_write_speed
        } else {
            self.caps.max_read_speed
        }) as u32;
        let last = self.max_lba().min(u32::MAX as u64) as u32;
        let mut buf = [0u8; 24]; // header (8) + one descriptor (16)
                                 // Performance Data Length = bytes following the length field
                                 // (header tail 4 + 16 per descriptor); not reduced when max_desc
                                 // truncates the transfer (§6.7.3.1).
        buf[0..4].copy_from_slice(&20u32.to_be_bytes());
        buf[4] = if write { 0x04 } else { 0x00 }; // Write / Except=0
        buf[8..12].copy_from_slice(&0u32.to_be_bytes()); // Start LBA
        buf[12..16].copy_from_slice(&speed.to_be_bytes()); // Start Performance
        buf[16..20].copy_from_slice(&last.to_be_bytes()); // End LBA
        buf[20..24].copy_from_slice(&speed.to_be_bytes()); // End Performance
        let resp = 8 + if max_desc > 0 { 16 } else { 0 };
        let n = resp.min(buf.len()).min(data.len());
        data[..n].copy_from_slice(&buf[..n]);
        CommandOutcome::OutInline { len: n }
    }

    // ── READ FORMAT CAPACITIES ───────────────────────────────────────

    fn read_format_capacities_cmd(&mut self, cdb: &[u8], data: &mut [u8]) -> CommandOutcome {
        if cdb[1] != 0 {
            return self.cc(SenseKey::IllegalRequest, asc::INVALID_FIELD);
        }
        let alloc = (u16::from(cdb[7]) << 8) | u16::from(cdb[8]);
        let partition_len = self.max_lba().min(u32::MAX as u64) as u32 + 1;
        let mut buf = [0u8; 20];
        buf[3] = 16;
        buf[4..8].copy_from_slice(&partition_len.to_be_bytes());
        buf[8] = 0x02; // formatted media
        buf[10] = 0x08; // Block Length 2048 (24-bit)
        buf[12..16].copy_from_slice(&partition_len.to_be_bytes());
        // DVD-RAM uses the standard formatted-medium descriptor.  The
        // descriptor's format type is not the DVD+RW 26h type.
        buf[16] = if self.is_random_writable() {
            0x00
        } else {
            0x26 << 2
        };
        // Type Dependent Parameter of the Formattable Capacity Descriptor
        // (MMC-6 Tables 468/469): Full Format (00h) reports the block length
        // in bytes. Hosts echo this descriptor back inside the FORMAT UNIT
        // parameter list, so it must be accurate — dvd+rw-format copies it
        // verbatim. DVD+RW Basic Format (26h) is "set to zeros".
        if self.is_random_writable() {
            buf[18] = 0x08; // Block Length 2048 (24-bit)
        }
        let n = buf.len().min(alloc as usize).min(data.len());
        data[..n].copy_from_slice(&buf[..n]);
        CommandOutcome::OutInline { len: n }
    }

    // ── SYNCHRONIZE CACHE ────────────────────────────────────────────

    /// Flush the media (SYNCHRONIZE CACHE equivalent).
    ///
    /// Parked media is flushed too: the disc physically sits on the tray
    /// until `take_media()` reclaims it, and host-written data must not
    /// be lost in that window. Empty ⇒ nothing to flush.
    pub fn sync_cache_cmd(&mut self) -> CommandOutcome {
        // A Parked disc is still addressable storage; data safety wins over
        // protocol purity (NOT READY after eject). Empty ⇒ no op is armed.
        // The session drains the one-shot `StoreOp::Sync` before the terminal
        // status; the command phase performs no storage I/O.
        if matches!(self.tray, Tray::Loaded(_) | Tray::Parked(_)) {
            self.sync_pending = true;
        }
        CommandOutcome::Status
    }
}

// ── SpcDevice impl ─────────────────────────────────────────────────

impl SpcDevice for CdromDrive {
    fn device_type(&self) -> DeviceType {
        DeviceType::Cdrom
    }

    fn identity(&self) -> &DeviceIdentity {
        &self.identity
    }

    fn medium_type(&self) -> u8 {
        0x41 // removable media
    }

    fn id(&self) -> u64 {
        self.drive_id
    }

    fn mode_page(&self, page: u8) -> Option<&[u8]> {
        cdrom_mode_page_for_caps(page, &self.caps)
    }

    fn sense(&self) -> &Sense {
        self.sense.as_ref().unwrap_or(&CLEAR_SENSE)
    }

    fn set_sense(&mut self, sense: Sense) {
        // Normalized storage: a cleared sense (key == None) is "no pending
        // sense" — never stored as `Some`.
        self.sense = (sense.key != SenseKey::None).then_some(sense);
    }

    fn start_stop(&mut self, loej: bool, load: bool) -> SpcEffect {
        if loej && !load {
            // Eject: the disc parks on the tray (take_media() reclaims
            // it); only a prevent-locked drive refuses.
            if self.prevent_removal {
                return SpcEffect::RemovalPrevented;
            }
            self.park();
            SpcEffect::Good
        } else if loej && load {
            // Load on empty tray → media_requested.
            if !self.loaded() {
                self.tray_open = false;
                self.media_requested = true;
            }
            SpcEffect::Good
        } else {
            SpcEffect::Good
        }
    }

    fn set_prevent(&mut self, prevent: bool) {
        self.prevent_removal = prevent;
    }

    // MMC-6 §6.13: [SPC-3]'s PREVENT description does not apply to MM
    // devices — the Persistent/Prevent bits (Table 329) are both valid, so
    // the SPC-3 Table 119 note (a) 05/24 rejection must not trigger here.
    fn persistent_prevent_supported(&self) -> bool {
        true
    }

    fn is_write_protected(&self) -> bool {
        !self.is_random_writable()
    }
}

// ── ScsiDevice impl ─────────────────────────────────────────────────

impl crate::scsi::device::ScsiDevice for CdromDrive {
    fn do_cmd(
        &mut self,
        cdb: &[u8],
        data: &mut [u8],
    ) -> Result<CommandOutcome, crate::scsi::device::Error> {
        let mut hx = [0u8; 48];
        crate::debug!(
            "cdrom cmd {}",
            core::str::from_utf8(hex_of(&mut hx, cdb)).unwrap_or("?")
        );
        let outcome = self.do_cmd(cdb, data);
        if matches!(outcome, Ok(CommandOutcome::CheckCondition)) {
            let s = self.sense();
            crate::debug!(
                "cdrom cc key={:#04x} asc={:#04x} ascq={:#04x}",
                s.key as u8,
                s.asc,
                s.ascq
            );
        }
        outcome
    }

    fn xfer_out<'a>(&'a mut self, transfer_offset: u64, buf: &'a mut [u8]) -> Xfer<'a> {
        self.xfer_out(transfer_offset, buf)
    }

    fn xfer_in<'a>(&'a mut self, transfer_offset: u64, buf: &'a [u8]) -> Xfer<'a> {
        self.xfer_in(transfer_offset, buf)
    }

    fn read_ahead_offset(&self, transfer_offset: u64) -> Option<u64> {
        let p = self.pending.as_ref()?;
        (p.dir == XferDir::Out).then(|| p.base_byte + transfer_offset)
    }

    /// Device maintenance agenda.
    ///
    /// FORMAT UNIT / BLANK arm a whole-disc zero-fill; this yields it as
    /// [`StoreOp::Fill`] in **64 KiB chunks** (a single whole-disc op would
    /// pin the shell for seconds) until exhausted. SYNCHRONIZE CACHE arms a
    /// one-shot [`StoreOp::Sync`]. The session drains this before any
    /// terminating status; the op is invisible on the wire, so the
    /// command-phase outcome/status is byte-identical to the old inline
    /// format/flush.
    fn next_store_op<'a>(&'a mut self) -> Option<StoreOp<'a>> {
        /// Fill chunk size: small enough that a whole-disc format stays
        /// responsive to resets/probes, large enough to amortize per-op cost.
        const FILL_CHUNK: u64 = 64 * 1024;
        if self.format_remaining > 0 {
            let len = self.format_remaining.min(FILL_CHUNK);
            let off = self.format_off;
            self.format_off = off + len;
            self.format_remaining -= len;
            return Some(StoreOp::Fill {
                off,
                len,
                byte: self.format_byte,
            });
        }
        if self.sync_pending {
            self.sync_pending = false;
            return Some(StoreOp::Sync);
        }
        None
    }

    fn peek_sense(&self) -> Option<&Sense> {
        self.peek_sense()
    }

    fn take_sense(&mut self) -> Option<Sense> {
        self.take_sense()
    }

    fn device_type(&self) -> DeviceType {
        DeviceType::Cdrom
    }

    fn complete_param(&mut self, cdb: &[u8], data: &[u8]) -> crate::scsi::device::CommandOutcome {
        let mut hx = [0u8; 64];
        crate::debug!(
            "cdrom param op={:#04x} len={} {}",
            cdb.first().copied().unwrap_or(0),
            data.len(),
            core::str::from_utf8(hex_of(&mut hx, data)).unwrap_or("?")
        );
        match cdb.first().copied() {
            Some(op::MODE_SELECT_6) => {
                let alloc = u16::from(cdb[4]);
                self.complete_mode_select(false, alloc, data)
            }
            Some(op::MODE_SELECT_10) => {
                let alloc = (u16::from(cdb[7]) << 8) | u16::from(cdb[8]);
                self.complete_mode_select(true, alloc, data)
            }
            Some(op::FORMAT_UNIT) => self.complete_format_unit(cdb, data),
            // L-e: SEND OPC / SET STREAMING parameter lists are received
            // and discarded (OPC values are not cached and READ DISC
            // INFORMATION reports no OPC tables; streaming performance
            // is not enforced on the virtual medium).
            Some(op::SEND_OPC_INFORMATION | op::SET_STREAMING) => CommandOutcome::Status,
            _ => self.cc(SenseKey::IllegalRequest, asc::INVALID_FIELD),
        }
    }

    fn inject_unit_attention(&mut self, asc: u8, ascq: u8) {
        self.sense = Some(Sense::new(SenseKey::UnitAttention, asc, ascq));
    }

    fn set_sense(&mut self, sense: Sense) {
        self.sense = Some(sense);
    }
}

// ── Builder ───────────────────────────────────────────

/// Builder for `CdromDrive`.
///
/// Constructs the drive identity; media is injected at runtime via
/// `load()`.
#[derive(Debug)]
pub struct CdromDriveBuilder {
    identity: DeviceIdentity,
    caps: CdromCapabilities,
    drive_id: u64,
}

impl CdromDriveBuilder {
    /// Set INQUIRY identity (vendor, product, revision).
    pub fn identity(mut self, vendor: &[u8; 8], product: &[u8; 16], rev: &[u8; 4]) -> Self {
        self.identity = DeviceIdentity {
            vendor: *vendor,
            product: *product,
            revision: *rev,
            version_descriptors: self.identity.version_descriptors,
        };
        self
    }

    /// Set VPD 0x80/0x83 drive serial number (constant, survives media swaps).
    pub fn drive_id(mut self, id: u64) -> Self {
        self.drive_id = id;
        self
    }

    /// Set device capabilities directly.
    pub fn capabilities(mut self, caps: CdromCapabilities) -> Self {
        self.caps = caps;
        self
    }

    /// Enable/disable eject and lock.
    pub fn eject_capable(mut self, eject: bool) -> Self {
        self.caps.eject = eject;
        self.caps.lock = eject;
        self.caps.load = eject;
        self
    }

    /// Build the drive (empty tray). Media is injected at runtime; the
    /// media holds only cached geometry, so the drive is backend-free.
    pub fn build(self) -> CdromDrive {
        CdromDrive {
            sense: None,
            pending: None,
            prevent_removal: false,
            caps: self.caps,
            drive_id: self.drive_id,
            identity: self.identity,
            tray: Tray::Empty,
            tray_open: false,
            mode_page_05: [0u8; 52],
            mode_page_05_valid: false,
            media_requested: false,
            format_off: 0,
            format_remaining: 0,
            format_byte: 0,
            sync_pending: false,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[cfg(feature = "dvdram")]
    use crate::common::seekable_storage::{FlatData, StorageError, WritableFlatData};
    #[cfg(feature = "dvdram")]
    use crate::common::store::{StoreOp, StorePlane};
    use crate::scsi::backend::{BlockBackend, RamBackend};
    #[cfg(feature = "dvdram")]
    use crate::scsi::device::{ScsiDevice, Xfer};

    fn work() -> [u8; crate::MIN_DATA_LEN] {
        [0u8; crate::MIN_DATA_LEN]
    }

    fn data_in(outcome: CommandOutcome, work: &[u8], buf: &mut [u8]) -> usize {
        match outcome {
            CommandOutcome::OutInline { len } => {
                let n = len;
                buf[..n].copy_from_slice(&work[..n]);
                n
            }
            _ => panic!("expected OutInline"),
        }
    }

    /// Execute a READ data phase. The media no longer holds the backend, so
    /// `xfer_out` yields `Xfer::Store(StoreOp::Read)`; run it against `plane`.
    /// `Inline` (synthesized) responses are copied from `work` as before.
    #[cfg(feature = "dvdram")]
    fn data_in_xfer(
        dev: &mut CdromDrive,
        plane: &mut dyn FlatData,
        outcome: CommandOutcome,
        work: &[u8],
        buf: &mut [u8],
    ) -> usize {
        match outcome {
            CommandOutcome::OutXfer { len } => {
                let n = len as usize;
                assert!(n <= buf.len());
                match dev.xfer_out(0, &mut buf[..n]) {
                    Xfer::Store(StoreOp::Read { off, buf }) => {
                        plane.read_at(off, buf).expect("read from plane");
                    }
                    other => panic!("expected Store(Read), got {other:?}"),
                }
                n
            }
            CommandOutcome::OutInline { len } => {
                let n = len;
                assert!(n <= buf.len());
                buf[..n].copy_from_slice(&work[..n]);
                n
            }
            _ => panic!("expected OutXfer or OutInline"),
        }
    }

    /// Execute a WRITE data phase: run the `Xfer::Store(StoreOp::Write)`
    /// against `plane`; return the number of bytes written.
    #[cfg(feature = "dvdram")]
    fn data_out_xfer(dev: &mut CdromDrive, plane: &mut dyn WritableFlatData, buf: &[u8]) -> usize {
        match dev.xfer_in(0, buf) {
            Xfer::Store(StoreOp::Write { off, buf }) => {
                plane.write_at(off, buf).expect("write to plane");
                buf.len()
            }
            Xfer::Inline { len } => len,
            other => panic!("expected Store(Write), got {other:?}"),
        }
    }

    /// Drain the device maintenance agenda (FORMAT `Fill`, SYNCHRONIZE CACHE
    /// `Sync`) by executing every op against `plane` — the shell's job in
    /// production (`usb::serve` / `iscsi`). The session does this before any
    /// terminal status; these unit tests drive the device directly.
    #[cfg(feature = "dvdram")]
    fn drain_agenda(dev: &mut CdromDrive, plane: &mut dyn WritableFlatData) {
        while let Some(op) = dev.next_store_op() {
            StorePlane::BlockRw(plane)
                .do_op(op)
                .expect("agenda op must succeed");
        }
    }

    #[test]
    fn drive_new_defaults() {
        let dev = CdromDrive::new();
        assert!(dev.peek_sense().is_none());
        assert!(!dev.prevent_removal);
        assert!(!dev.tray_open);
        assert!(!dev.media_requested);
        assert_eq!(dev.drive_id, 0);
    }

    #[test]
    fn drive_builder_identity() {
        let dev = CdromDrive::builder()
            .identity(b"TESTDRVR", b"Virtual CD-ROM  ", b"0200")
            .drive_id(0xDEAD_BEEF)
            .eject_capable(true)
            .build();
        assert_eq!(dev.identity.vendor, *b"TESTDRVR");
        assert_eq!(dev.drive_id, 0xDEAD_BEEF);
        assert!(dev.caps.eject);
        assert!(dev.caps.lock);
        assert!(dev.caps.load);
    }

    #[test]
    fn drive_inquiry() {
        let mut dev = CdromDrive::new();
        let mut w = work();
        let mut cdb = [0u8; 6];
        cdb[0] = op::INQUIRY;
        cdb[4] = 96;
        let mut buf = [0u8; 96];
        let n = data_in(dev.do_cmd(&cdb, &mut w).unwrap(), &w, &mut buf);
        assert_eq!(n, 96);
        assert_eq!(buf[0] & 0x1F, 0x05); // PDT = CD-ROM
        assert_eq!(&buf[8..16], b"SnowSCSI");
    }

    #[test]
    fn drive_empty_tray_tur() {
        let mut dev = CdromDrive::new();
        let mut w = work();
        let mut cdb = [0u8; 6];
        cdb[0] = op::TEST_UNIT_READY;
        let outcome = dev.do_cmd(&cdb, &mut w).unwrap();
        assert_eq!(outcome, CommandOutcome::CheckCondition);
        let s = dev.peek_sense().unwrap();
        assert_eq!(s.asc, asc::MEDIUM_NOT_PRESENT);
        assert_eq!(s.ascq, asc::MEDIUM_NOT_PRESENT_TRAY_CLOSED);
    }

    #[test]
    fn drive_send_opc_and_set_streaming_parameter_lists() {
        // L-e: SEND OPC / SET STREAMING must honor the declared parameter
        // list phase (MMC-6 §6.38 / §6.41) instead of swallowing it with a
        // zero-length Data-Out.
        let mut dev = CdromDrive::new();
        let mut w = work();

        // SEND OPC: DoOpc=1 → GOOD, list ignored (§6.38.2.2).
        let mut cdb = [0u8; 10];
        cdb[0] = op::SEND_OPC_INFORMATION;
        cdb[1] = 0x01; /* DoOpc */
        assert_eq!(dev.do_cmd(&cdb, &mut w).unwrap(), CommandOutcome::Status);

        // SEND OPC: DoOpc=0, PLL=0 → GOOD, no operation (§6.38.2.4).
        let mut cdb = [0u8; 10];
        cdb[0] = op::SEND_OPC_INFORMATION;
        assert_eq!(dev.do_cmd(&cdb, &mut w).unwrap(), CommandOutcome::Status);

        // SEND OPC: DoOpc=0, PLL=16 → InParam, list discarded on complete.
        let mut cdb = [0u8; 10];
        cdb[0] = op::SEND_OPC_INFORMATION;
        cdb[8] = 16;
        assert_eq!(
            dev.do_cmd(&cdb, &mut w).unwrap(),
            CommandOutcome::InParam { expected_len: 16 }
        );
        assert_eq!(dev.complete_param(&cdb, &w[..16]), CommandOutcome::Status);

        // SEND OPC: PLL not an integral multiple of 8 → 05/24 (§6.38.2.4).
        let mut cdb = [0u8; 10];
        cdb[0] = op::SEND_OPC_INFORMATION;
        cdb[8] = 12;
        let outcome = dev.do_cmd(&cdb, &mut w).unwrap();
        assert_eq!(outcome, CommandOutcome::CheckCondition);
        assert_eq!(dev.peek_sense().unwrap().key, SenseKey::IllegalRequest);
        assert_eq!(dev.peek_sense().unwrap().asc, asc::INVALID_FIELD);

        // SET STREAMING: Type=0, PLL=0 → GOOD (§6.41.2.3).
        let mut cdb = [0u8; 12];
        cdb[0] = op::SET_STREAMING;
        assert_eq!(dev.do_cmd(&cdb, &mut w).unwrap(), CommandOutcome::Status);

        // SET STREAMING: Type=0, PLL=28 → InParam, descriptor discarded.
        let mut cdb = [0u8; 12];
        cdb[0] = op::SET_STREAMING;
        cdb[10] = 28;
        assert_eq!(
            dev.do_cmd(&cdb, &mut w).unwrap(),
            CommandOutcome::InParam { expected_len: 28 }
        );
        assert_eq!(dev.complete_param(&cdb, &w[..28]), CommandOutcome::Status);

        // SET STREAMING: Type=1 (reserved) → 05/24 (§6.41.2.2).
        let mut cdb = [0u8; 12];
        cdb[0] = op::SET_STREAMING;
        cdb[8] = 0x01;
        let outcome = dev.do_cmd(&cdb, &mut w).unwrap();
        assert_eq!(outcome, CommandOutcome::CheckCondition);
        assert_eq!(dev.peek_sense().unwrap().key, SenseKey::IllegalRequest);
        assert_eq!(dev.peek_sense().unwrap().asc, asc::INVALID_FIELD);
    }

    #[test]
    fn drive_get_configuration_empty_profile() {
        let mut dev = CdromDrive::new();
        let mut w = work();
        let mut cdb = [0u8; 10];
        cdb[0] = op::GET_CONFIGURATION;
        cdb[8] = 64;
        let mut buf = [0u8; 64];
        let n = data_in(dev.do_cmd(&cdb, &mut w).unwrap(), &w, &mut buf);
        assert!(n >= 8);
        // Empty tray → profile 0000h.
        assert_eq!(buf[6], 0x00);
        assert_eq!(buf[7], 0x00);
    }

    #[test]
    fn drive_gesn_media_event_format() {
        let mut dev = CdromDrive::new();
        let mut w = work();
        let mut buf = [0u8; 8];
        // Polled, Media class request: Event Header + Media Event Descriptor.
        let mut cdb = [0u8; 10];
        cdb[0] = op::GET_EVENT_STATUS_NOTIFICATION;
        cdb[1] = 0x01; // Polled
        cdb[4] = 0x10; // Notification Class Request = Media
        cdb[8] = 0x08; // alloc
        let n = data_in(dev.do_cmd(&cdb, &mut w).unwrap(), &w, &mut buf);
        assert_eq!(n, 8);
        // Event Descriptor Length = 2 (header rest) + 4 (media descriptor).
        assert_eq!(&buf[0..2], &[0x00, 0x06]);
        assert_eq!(buf[2], 0x04); // NEA=0, Notification Class = Media (100b)
        assert_eq!(buf[3], 0x10); // Supported Event Class = Media
        assert_eq!(buf[4], 0x00); // Event Code 0 = NoChg (Table 279)
        assert_eq!(buf[5], 0x00); // Media Status: no media, tray closed
        assert_eq!(&buf[6..8], &[0x00, 0x00]); // Start/End slot

        // Media class NOT requested: NEA=1, header only (Table 265).
        let mut cdb2 = [0u8; 10];
        cdb2[0] = op::GET_EVENT_STATUS_NOTIFICATION;
        cdb2[1] = 0x01;
        cdb2[4] = 0x00;
        cdb2[8] = 0x08;
        let n = data_in(dev.do_cmd(&cdb2, &mut w).unwrap(), &w, &mut buf);
        assert_eq!(n, 4);
        assert_eq!(&buf[0..2], &[0x00, 0x02]);
        assert_eq!(buf[2], 0x80); // NEA=1
        assert_eq!(buf[3], 0x10); // Supported Event Class still advertises Media
    }

    #[test]
    fn drive_get_performance_nominal_descriptor() {
        let mut img = vec![0u8; 2048 * 204800];
        let mut dev = CdromDrive::new();
        let mut bb = BlockBackend::Ram(RamBackend::new(&mut img));
        #[cfg(feature = "dvdram")]
        {
            let media = crate::cdrom::dvdram::DvdRamMedia::open(&mut bb);
            dev.load_quiet(crate::cdrom::media::CdMedia::Rw(media));
        }
        #[cfg(not(feature = "dvdram"))]
        dev.load_quiet(crate::cdrom::media::CdMedia::ro(&mut bb));
        let last = dev.max_lba().min(u32::MAX as u64) as u32;

        let mut w = work();
        let mut buf = [0u8; 32];
        // Type 00h, Data Type 0 (read, nominal), max 1 descriptor.
        let mut cdb = [0u8; 12];
        cdb[0] = op::GET_PERFORMANCE;
        cdb[8] = 0x00;
        cdb[9] = 0x01;
        let n = data_in(dev.do_cmd(&cdb, &mut w).unwrap(), &w, &mut buf);
        assert_eq!(n, 24); // header (8) + one nominal descriptor (16)
                           // Performance Data Length = 4 (header tail) + 16 = 20.
        assert_eq!(u32::from_be_bytes(buf[0..4].try_into().unwrap()), 20);
        assert_eq!(buf[4], 0x00); // Write=0, Except=0 (read nominal)
        assert_eq!(&buf[8..12], &0u32.to_be_bytes()); // Start LBA
        assert_eq!(&buf[12..16], &22160u32.to_be_bytes()); // Start Perf (KB/s)
        assert_eq!(&buf[16..20], &last.to_be_bytes()); // End LBA
        assert_eq!(&buf[20..24], &22160u32.to_be_bytes()); // End Perf

        // max descriptors = 0 → header only (§6.7.2.4).
        let mut cdb0 = [0u8; 12];
        cdb0[0] = op::GET_PERFORMANCE;
        let n = data_in(dev.do_cmd(&cdb0, &mut w).unwrap(), &w, &mut buf);
        assert_eq!(n, 8);
        assert_eq!(u32::from_be_bytes(buf[0..4].try_into().unwrap()), 20);

        // Write bit → write nominal table.
        let mut cdw = [0u8; 12];
        cdw[0] = op::GET_PERFORMANCE;
        cdw[1] = 0x04; // Write=1
        cdw[9] = 0x01;
        let _ = data_in(dev.do_cmd(&cdw, &mut w).unwrap(), &w, &mut buf);
        assert_eq!(buf[4], 0x04);

        // Unsupported Type (write speed) → 05/24.
        let mut cdt = [0u8; 12];
        cdt[0] = op::GET_PERFORMANCE;
        cdt[11] = 0x03;
        let out = dev.do_cmd(&cdt, &mut w).unwrap();
        assert_eq!(out, CommandOutcome::CheckCondition);
        assert_eq!(dev.peek_sense().map(|s| s.asc), Some(asc::INVALID_FIELD));
    }

    #[test]
    fn drive_read_capacity_empty_tray() {
        let mut dev = CdromDrive::new();
        let mut w = work();
        let mut cdb = [0u8; 10];
        cdb[0] = op::READ_CAPACITY_10;
        let outcome = dev.do_cmd(&cdb, &mut w).unwrap();
        assert_eq!(outcome, CommandOutcome::CheckCondition);
        assert_eq!(dev.peek_sense().unwrap().asc, asc::MEDIUM_NOT_PRESENT);
    }

    #[test]
    fn drive_mode_sense_2a() {
        let mut dev = CdromDrive::new();
        let mut w = work();
        let mut cdb = [0u8; 6];
        cdb[0] = op::MODE_SENSE_6;
        cdb[2] = 0x2A;
        cdb[4] = 100;
        let mut buf = [0u8; 128];
        let n = data_in(dev.do_cmd(&cdb, &mut w).unwrap(), &w, &mut buf);
        // 4-byte MODE SENSE(6) header + 64-byte 0x2A page.
        assert_eq!(n, 4 + 64);
        assert_eq!(buf[4], 0x2A);
    }

    #[test]
    fn drive_mode_select_write_parameters_roundtrip() {
        let mut dev = CdromDrive::new();
        let mut w = work();
        let mut select = [0u8; 6];
        select[0] = op::MODE_SELECT_6;
        select[1] = 0x10; // PF=1
        select[4] = 56;
        w[4] = 0x05;
        w[5] = 0x32;
        w[6] = 0x41;
        w[7] = 0xC4;
        assert_eq!(
            dev.do_cmd(&select, &mut w).unwrap(),
            CommandOutcome::InParam { expected_len: 56 }
        );
        assert_eq!(
            dev.complete_param(&select, &w[..56]),
            CommandOutcome::Status
        );
        assert!(dev.mode_page_05_valid);

        let mut sense = [0u8; 6];
        sense[0] = op::MODE_SENSE_6;
        sense[2] = 0x05;
        sense[4] = 60;
        let outcome = dev.do_cmd(&sense, &mut w).unwrap();
        match outcome {
            CommandOutcome::OutInline { len } => {
                assert_eq!(len, 4 + 52);
                assert_eq!(&w[4..8], &[0x05, 0x32, 0x41, 0xC4]);
            }
            _ => panic!("expected MODE SENSE data"),
        }
    }

    #[test]
    #[allow(unused_mut, unused_variables)]
    fn drive_format_unit_rejects_read_only_media() {
        let mut dev = CdromDrive::new();
        let mut img = vec![0u8; 2048];
        let mut bb = BlockBackend::Ram(RamBackend::new(&mut img));
        dev.load_quiet(CdMedia::ro(&mut bb));
        let mut cdb = [0u8; 6];
        cdb[0] = op::FORMAT_UNIT;
        cdb[1] = 0x11; // FmtData + format code 1
        let mut w = work();
        w[2..4].copy_from_slice(&8u16.to_be_bytes());
        w[8] = 0x00; // full format
        w[10..12].copy_from_slice(&2048u16.to_be_bytes());
        let outcome = dev.do_cmd(&cdb, &mut w).unwrap();
        assert_eq!(outcome, CommandOutcome::InParam { expected_len: 12 });
        assert_eq!(
            dev.complete_param(&cdb, &w[..12]),
            CommandOutcome::CheckCondition
        );
        let s = dev.peek_sense().unwrap();
        assert_eq!(s.key, SenseKey::DataProtect);
        assert_eq!(s.asc, asc::WRITE_PROTECTED);
    }

    #[test]
    fn drive_pending_overrides_tur() {
        let mut dev = CdromDrive::new();
        // Manually inject a pending UA.
        dev.sense = Some(Sense::new(
            SenseKey::UnitAttention,
            asc::MEDIUM_MAY_HAVE_CHANGED,
            0,
        ));
        let mut w = work();
        let mut cdb = [0u8; 6];
        cdb[0] = op::TEST_UNIT_READY;
        let outcome = dev.do_cmd(&cdb, &mut w).unwrap();
        assert_eq!(outcome, CommandOutcome::CheckCondition);
        // UA is consumed when it is reported (delivered exactly once); the
        // host fetches the details via autosense/REQUEST SENSE.
        assert!(
            dev.peek_sense().is_none(),
            "UA must not linger after being reported"
        );
        // Next TUR should not be UA again (may be NOT READY if no media).
        let outcome2 = dev.do_cmd(&cdb, &mut w).unwrap();
        match outcome2 {
            CommandOutcome::CheckCondition => {
                let s = dev.peek_sense().unwrap();
                assert_ne!(s.key, SenseKey::UnitAttention, "UA should not repeat");
            }
            CommandOutcome::Status => {}
            _ => panic!("unexpected outcome"),
        }
    }

    #[test]
    fn drive_request_sense_clears_pending() {
        let mut dev = CdromDrive::new();
        dev.sense = Some(Sense::new(
            SenseKey::UnitAttention,
            asc::MEDIUM_MAY_HAVE_CHANGED,
            0,
        ));
        let mut w = work();
        let mut cdb = [0u8; 6];
        cdb[0] = op::REQUEST_SENSE;
        cdb[4] = 18;
        let _ = dev.do_cmd(&cdb, &mut w).unwrap();
        // UA should now be cleared via REQUEST SENSE.
        assert!(dev.peek_sense().is_none());
    }

    #[test]
    fn drive_inquiry_bypasses_ua() {
        let mut dev = CdromDrive::new();
        dev.sense = Some(Sense::new(
            SenseKey::UnitAttention,
            asc::MEDIUM_MAY_HAVE_CHANGED,
            0,
        ));
        let mut w = work();
        let mut cdb = [0u8; 6];
        cdb[0] = op::INQUIRY;
        cdb[4] = 96;
        let outcome = dev.do_cmd(&cdb, &mut w).unwrap();
        assert!(matches!(outcome, CommandOutcome::OutInline { .. }));
        // UA is NOT cleared by INQUIRY.
        assert!(dev.peek_sense().is_some());
    }

    #[test]
    fn drive_empty_tray_tur_open_ascq() {
        let mut dev = CdromDrive::new();
        dev.tray_open = true;
        let mut w = work();
        let mut cdb = [0u8; 6];
        cdb[0] = op::TEST_UNIT_READY;
        let outcome = dev.do_cmd(&cdb, &mut w).unwrap();
        assert_eq!(outcome, CommandOutcome::CheckCondition);
        let s = dev.peek_sense().unwrap();
        assert_eq!(s.asc, asc::MEDIUM_NOT_PRESENT);
        assert_eq!(s.ascq, asc::MEDIUM_NOT_PRESENT_TRAY_OPEN);
    }

    #[test]
    fn drive_load_eject_ua_cycle() {
        let mut dev = CdromDrive::new();
        let mut w = work();
        let mut cdb = [0u8; 6];

        // Initially empty tray → NOT READY.
        cdb[0] = op::TEST_UNIT_READY;
        let outcome = dev.do_cmd(&cdb, &mut w).unwrap();
        assert_eq!(outcome, CommandOutcome::CheckCondition);
        assert_eq!(dev.peek_sense().unwrap().asc, asc::MEDIUM_NOT_PRESENT);
        // Clear NOT READY sense before proceeding (simulate REQUEST SENSE or autosense)
        dev.take_sense();

        // START STOP LoEj=1, Load=1 → load media on empty tray.
        use crate::scsi::spc::SpcDevice;
        let effect = dev.start_stop(true, true); // loej=true, load=true
        assert_eq!(effect, SpcEffect::Good);
        assert!(dev.media_requested);
        assert!(!dev.tray_open);

        // Simulate integrator loading media.
        let mut img = vec![0u8; 2048];
        let mut bb = BlockBackend::Ram(RamBackend::new(&mut img));
        dev.load(CdMedia::ro(&mut bb));
        assert!(dev.is_media_present());

        // TUR → CC(UA 28h/00h) — reported once, consumed on delivery.
        cdb[0] = op::TEST_UNIT_READY;
        let outcome = dev.do_cmd(&cdb, &mut w).unwrap();
        assert_eq!(outcome, CommandOutcome::CheckCondition);
        assert!(dev.peek_sense().is_none(), "UA must not linger");
        // REQUEST SENSE still completes fine (empty sense now).
        cdb[0] = op::REQUEST_SENSE;
        cdb[4] = 18;
        let outcome_rs = dev.do_cmd(&cdb, &mut w).unwrap();
        assert!(matches!(outcome_rs, CommandOutcome::OutInline { .. }));
        assert!(dev.peek_sense().is_none());

        // TUR → GOOD.
        cdb[0] = op::TEST_UNIT_READY;
        let outcome = dev.do_cmd(&cdb, &mut w).unwrap();
        assert_eq!(outcome, CommandOutcome::Status);

        // START STOP LoEj=1, Load=0 → eject.
        let effect = dev.start_stop(true, false); // loej=true, load=false
        assert_eq!(effect, SpcEffect::Good);
        assert!(dev.tray_open);
        assert!(!dev.is_media_present());

        // TUR → CC(UA 28h/00h) — consumed on delivery.
        cdb[0] = op::TEST_UNIT_READY;
        let outcome = dev.do_cmd(&cdb, &mut w).unwrap();
        assert_eq!(outcome, CommandOutcome::CheckCondition);
        assert!(dev.peek_sense().is_none());
        // REQUEST SENSE → clears UA.
        cdb[0] = op::REQUEST_SENSE;
        cdb[4] = 18;
        let _ = dev.do_cmd(&cdb, &mut w).unwrap();
        // TUR → NOT READY 3Ah/02h (tray open).
        cdb[0] = op::TEST_UNIT_READY;
        let outcome = dev.do_cmd(&cdb, &mut w).unwrap();
        assert_eq!(outcome, CommandOutcome::CheckCondition);
        let s = dev.peek_sense().unwrap();
        assert_eq!(s.asc, asc::MEDIUM_NOT_PRESENT);
        assert_eq!(s.ascq, asc::MEDIUM_NOT_PRESENT_TRAY_OPEN);
    }

    #[test]
    fn drive_ua_overrides_read_capacity() {
        let mut dev = CdromDrive::new();
        dev.sense = Some(Sense::new(
            SenseKey::UnitAttention,
            asc::MEDIUM_MAY_HAVE_CHANGED,
            0,
        ));
        let mut w = work();
        let mut cdb = [0u8; 10];
        cdb[0] = op::READ_CAPACITY_10;
        let outcome = dev.do_cmd(&cdb, &mut w).unwrap();
        assert_eq!(outcome, CommandOutcome::CheckCondition);
        // UA is consumed when reported; nothing lingers.
        assert!(dev.peek_sense().is_none());
    }

    #[test]
    fn drive_prevent_removal_blocks_eject() {
        let mut dev = CdromDrive::new();
        use crate::scsi::spc::SpcDevice;
        dev.set_prevent(true);
        let effect = dev.start_stop(true, false); // loej=true, load=false
        assert_eq!(effect, SpcEffect::RemovalPrevented);
    }

    /// Backend whose `sync` counts invocations through an outer handle,
    /// so the counter stays reachable while the backend itself is owned
    /// by the media stack.
    #[cfg(feature = "dvdram")]
    struct CountingSyncBackend {
        data: Vec<u8>,
        syncs: std::rc::Rc<core::cell::Cell<u32>>,
    }

    #[cfg(feature = "dvdram")]
    impl FlatData for CountingSyncBackend {
        fn read_at(&mut self, off: u64, buf: &mut [u8]) -> Result<(), StorageError> {
            let off = off as usize;
            buf.copy_from_slice(&self.data[off..off + buf.len()]);
            Ok(())
        }

        fn capacity(&self) -> u64 {
            self.data.len() as u64
        }
    }

    #[cfg(feature = "dvdram")]
    impl WritableFlatData for CountingSyncBackend {
        fn write_at(&mut self, off: u64, buf: &[u8]) -> Result<(), StorageError> {
            let off = off as usize;
            self.data[off..off + buf.len()].copy_from_slice(buf);
            Ok(())
        }

        fn sync(&mut self) -> Result<(), StorageError> {
            self.syncs.set(self.syncs.get() + 1);
            Ok(())
        }
    }

    #[cfg(feature = "dvdram")]
    #[test]
    fn sync_reaches_parked_media() {
        // After a SCSI eject the disc sits Parked on the tray until
        // take_media(); SYNCHRONIZE CACHE must still reach it (a Parked disc
        // is addressable storage — data safety over protocol purity). The
        // command now arms a one-shot `StoreOp::Sync`; draining the agenda
        // (the shell's job, like the shutdown `sync_planes`) flushes it. The
        // former inline flush could be skipped ⇒ data-loss window.
        use crate::cdrom::dvdram::DvdRamMedia;

        let syncs = std::rc::Rc::new(core::cell::Cell::new(0));
        let mut be = CountingSyncBackend {
            data: vec![0u8; 4096 * 2048],
            syncs: std::rc::Rc::clone(&syncs),
        };
        let media = DvdRamMedia::open(&mut be);

        let mut dev = CdromDrive::new();
        let swapped_out = dev.load(CdMedia::Rw(media));
        assert!(swapped_out.is_none());

        // Host-initiated eject: Loaded → Parked.
        use crate::scsi::spc::SpcDevice;
        assert_eq!(dev.start_stop(true, false), SpcEffect::Good);

        // Consume the eject's UNIT ATTENTION first (correct SCSI behavior:
        // the first command after a medium change reports CC/UA).
        assert_eq!(
            dev.take_sense().map(|s| s.key),
            Some(SenseKey::UnitAttention)
        );
        let mut w = work();
        let mut cdb = [0u8; 10];
        cdb[0] = op::SYNCHRONIZE_CACHE_10;
        assert_eq!(dev.do_cmd(&cdb, &mut w).unwrap(), CommandOutcome::Status);
        drain_agenda(&mut dev, &mut be);
        assert_eq!(syncs.get(), 1);

        // Reclaim: the disc leaves with its data flushed.
        assert!(dev.take_media().is_some());
    }

    #[test]
    fn tray_parked_rows_of_truth_table() {
        // App-side eject() on a parked tray is a
        // no-op (Parked → Parked); load() over a parked disc hands the
        // parked media back to the caller.
        use crate::scsi::spc::SpcDevice;

        let mut dev = CdromDrive::new();
        let mut img1 = vec![0u8; 2048];
        let mut bb1 = BlockBackend::Ram(RamBackend::new(&mut img1));
        dev.load_quiet(CdMedia::ro(&mut bb1));

        // SCSI eject parks; the parked disc is logically NOT PRESENT and
        // app-side eject cannot steal it from the tray.
        assert_eq!(dev.start_stop(true, false), SpcEffect::Good);
        assert!(!dev.is_media_present());
        assert!(dev.eject().is_none());

        // A fresh load swaps the parked disc out to the caller.
        let mut img2 = vec![0u8; 2048];
        let mut bb2 = BlockBackend::Ram(RamBackend::new(&mut img2));
        let swapped = dev.load(CdMedia::ro(&mut bb2));
        assert!(swapped.is_some());
        assert!(dev.is_media_present());
    }

    #[test]
    #[allow(unused_mut, unused_variables)]
    fn drive_format_unit_rejects_type_01() {
        let mut dev = CdromDrive::new();
        let mut img = vec![0u8; 4096 * 2048];
        // DvdRam requires dvdram feature
        #[cfg(feature = "dvdram")]
        {
            use crate::cdrom::dvdram::DvdRamMedia;
            let mut bb = BlockBackend::Ram(RamBackend::new(&mut img));
            let media = DvdRamMedia::open(&mut bb);
            dev.load_quiet(CdMedia::Rw(media));
            let mut cdb = [0u8; 6];
            cdb[0] = op::FORMAT_UNIT;
            cdb[1] = 0x11;
            let mut w = work();
            w[1] = 0x00; // options zero
            w[2..4].copy_from_slice(&8u16.to_be_bytes());
            w[8] = 0x01; // Spare Area Expansion — must be rejected
            w[10..12].copy_from_slice(&2048u16.to_be_bytes());
            let outcome = dev.do_cmd(&cdb, &mut w).unwrap();
            assert_eq!(outcome, CommandOutcome::InParam { expected_len: 12 });
            assert_eq!(
                dev.complete_param(&cdb, &w[..12]),
                CommandOutcome::CheckCondition
            );
            assert_eq!(dev.peek_sense().unwrap().key, SenseKey::IllegalRequest);
            assert_eq!(
                dev.peek_sense().unwrap().asc,
                asc::INVALID_FIELD_IN_PARAMETER_LIST
            );
        }
        #[cfg(not(feature = "dvdram"))]
        {
            let _ = (dev, img);
        }
    }

    #[test]
    #[allow(unused_mut, unused_variables)]
    fn drive_format_unit_rejects_init_pattern() {
        let mut dev = CdromDrive::new();
        let mut img = vec![0u8; 4096 * 2048];
        #[cfg(feature = "dvdram")]
        {
            use crate::cdrom::dvdram::DvdRamMedia;
            let mut bb = BlockBackend::Ram(RamBackend::new(&mut img));
            let media = DvdRamMedia::open(&mut bb);
            dev.load_quiet(CdMedia::Rw(media));
            let mut cdb = [0u8; 6];
            cdb[0] = op::FORMAT_UNIT;
            cdb[1] = 0x11;
            let mut w = work();
            w[1] = 0x08; // IP=1 — initialization pattern descriptor present,
                         // which Multi-Media drives reject (MMC-6 §6.4.3.2 d)
            w[2..4].copy_from_slice(&8u16.to_be_bytes());
            w[4..8].copy_from_slice(&[0xAA, 0xBB, 0xCC, 0xDD]);
            w[8] = 0x00;
            w[10..12].copy_from_slice(&2048u16.to_be_bytes());
            let outcome = dev.do_cmd(&cdb, &mut w).unwrap();
            assert_eq!(outcome, CommandOutcome::InParam { expected_len: 12 });
            assert_eq!(
                dev.complete_param(&cdb, &w[..12]),
                CommandOutcome::CheckCondition
            );
            assert_eq!(dev.peek_sense().unwrap().key, SenseKey::IllegalRequest);
            assert_eq!(
                dev.peek_sense().unwrap().asc,
                asc::INVALID_FIELD_IN_PARAMETER_LIST
            );
        }
        #[cfg(not(feature = "dvdram"))]
        {
            let _ = (dev, img);
        }
    }

    #[test]
    #[allow(unused_mut, unused_variables)]
    fn drive_format_unit_tryout_does_not_clear() {
        let mut img = vec![0u8; 4096 * 2048];
        #[cfg(feature = "dvdram")]
        {
            use crate::cdrom::dvdram::DvdRamMedia;
            let mut dev = CdromDrive::new();
            let mut bb = BlockBackend::Ram(RamBackend::new(&mut img));
            let media = DvdRamMedia::open(&mut bb);
            dev.load_quiet(CdMedia::Rw(media));
            // Write pattern via xfer_in path
            let mut w = work();
            let mut cdb = [0u8; 10];
            cdb[0] = op::WRITE_10;
            cdb[5] = 0;
            cdb[8] = 1;
            let outcome = dev.do_cmd(&cdb, &mut w).unwrap();
            match outcome {
                CommandOutcome::InXfer { len } => {
                    let pat = [0xA5u8; 2048];
                    // The media holds no backend: run the WRITE data phase on
                    // the test's own plane (`data_out_xfer`).
                    let _ = len;
                    assert_eq!(data_out_xfer(&mut dev, &mut bb, &pat), pat.len());
                }
                _ => panic!("expected InXfer"),
            }
            // Try-out format (header bit 2 = 0x04, with FOV) should validate
            // and return GOOD without clearing the medium (MMC-6 §6.4.3.2 e).
            let mut cdb = [0u8; 6];
            cdb[0] = op::FORMAT_UNIT;
            cdb[1] = 0x11;
            let mut w = work();
            w[1] = 0x84; // FOV | Try-out
            w[2..4].copy_from_slice(&8u16.to_be_bytes());
            w[4..8].copy_from_slice(&2048u32.to_be_bytes()); // Number of Blocks
            w[8] = 0x00;
            w[10..12].copy_from_slice(&2048u16.to_be_bytes());
            let outcome = dev.do_cmd(&cdb, &mut w).unwrap();
            let outcome = match outcome {
                CommandOutcome::InParam { expected_len } => {
                    assert_eq!(expected_len, 12);
                    dev.complete_param(&cdb, &w[..expected_len])
                }
                _ => outcome,
            };
            assert_eq!(outcome, CommandOutcome::Status);
            // Verify data still present (not cleared) via READ + xfer_out
            let mut cdb = [0u8; 10];
            cdb[0] = op::READ_10;
            cdb[5] = 0;
            cdb[8] = 1;
            let outcome = dev.do_cmd(&cdb, &mut w).unwrap();
            let mut out = [0u8; 2048];
            let n = data_in_xfer(&mut dev, &mut bb, outcome, &w, &mut out);
            assert_eq!(n, 2048);
            assert_eq!(out, [0xA5; 2048]);
        }
    }

    #[test]
    #[allow(unused_mut, unused_variables)]
    fn drive_format_unit_clears_logical_blocks() {
        let mut img = vec![0u8; 4096 * 2048];
        #[cfg(feature = "dvdram")]
        {
            use crate::cdrom::dvdram::DvdRamMedia;
            let mut dev = CdromDrive::new();
            let mut bb = BlockBackend::Ram(RamBackend::new(&mut img));
            let media = DvdRamMedia::open(&mut bb);
            dev.load_quiet(CdMedia::Rw(media));
            // Write some data via xfer_in
            {
                let mut w = work();
                let mut cdb = [0u8; 10];
                cdb[0] = op::WRITE_10;
                cdb[5] = 1; // lba 1
                cdb[8] = 1;
                let outcome = dev.do_cmd(&cdb, &mut w).unwrap();
                match outcome {
                    CommandOutcome::InXfer { .. } => {
                        let pat = [0x5A; 2048];
                        assert_eq!(data_out_xfer(&mut dev, &mut bb, &pat), pat.len());
                    }
                    _ => panic!("expected InXfer"),
                }
            }
            // Normal format (not try-out) should clear
            let mut cdb = [0u8; 6];
            cdb[0] = op::FORMAT_UNIT;
            cdb[1] = 0x11;
            let mut w = work();
            w[1] = 0x00;
            w[2..4].copy_from_slice(&8u16.to_be_bytes());
            w[8] = 0x00;
            w[10..12].copy_from_slice(&2048u16.to_be_bytes());
            let outcome = dev.do_cmd(&cdb, &mut w).unwrap();
            assert_eq!(outcome, CommandOutcome::InParam { expected_len: 12 });
            assert_eq!(dev.complete_param(&cdb, &w[..12]), CommandOutcome::Status);
            // FORMAT arms the zero-fill agenda; drain it (the session does this
            // before the terminal status) so the medium is actually cleared.
            drain_agenda(&mut dev, &mut bb);
            // Consume UA from format (autosense)
            let _ = dev.take_sense();
            // Verify cleared via READ + xfer_out
            let mut w = work();
            let mut cdb = [0u8; 10];
            cdb[0] = op::READ_10;
            cdb[5] = 1;
            cdb[8] = 1;
            let outcome = dev.do_cmd(&cdb, &mut w).unwrap();
            let mut out = [0u8; 2048];
            let n = data_in_xfer(&mut dev, &mut bb, outcome, &w, &mut out);
            assert_eq!(n, 2048);
            assert_eq!(out, [0u8; 2048]);
            // UDF structures should be zeroed — check BEA sector via READ
            let mut cdb = [0u8; 10];
            cdb[0] = op::READ_10;
            cdb[5] = 16;
            cdb[8] = 1;
            let outcome = dev.do_cmd(&cdb, &mut w).unwrap();
            let mut sec = [0u8; 2048];
            let n = data_in_xfer(&mut dev, &mut bb, outcome, &w, &mut sec);
            assert_eq!(n, 2048);
            assert_eq!(sec, [0u8; 2048]);
        }
    }

    /// Regression: replay the exact FORMAT UNIT wire bytes emitted by
    /// `dvd+rw-format` for DVD-RAM (CDB `04 19 …`, parameter list with
    /// FOV|DCRT|Immed and the Formattable Capacity Descriptor echoed back
    /// verbatim). The Number of Blocks field carries the medium capacity —
    /// it must be accepted — and Immed=1 must still clear the medium (the
    /// format itself runs synchronously in this emulation).
    #[test]
    #[allow(unused_mut, unused_variables)]
    fn drive_format_unit_dvd_rw_format_compat() {
        let mut img = vec![0u8; 4096 * 2048];
        #[cfg(feature = "dvdram")]
        {
            use crate::cdrom::dvdram::DvdRamMedia;
            let mut dev = CdromDrive::new();
            let mut bb = BlockBackend::Ram(RamBackend::new(&mut img));
            let media = DvdRamMedia::open(&mut bb);
            dev.load_quiet(CdMedia::Rw(media));
            // Leave a pattern at LBA 1 so we can observe the clear.
            {
                let mut w = work();
                let mut cdb = [0u8; 10];
                cdb[0] = op::WRITE_10;
                cdb[5] = 1;
                cdb[8] = 1;
                match dev.do_cmd(&cdb, &mut w).unwrap() {
                    CommandOutcome::InXfer { .. } => {
                        assert_eq!(data_out_xfer(&mut dev, &mut bb, &[0x5A; 2048]), 2048);
                    }
                    _ => panic!("expected InXfer"),
                }
            }
            // Exactly what dvd+rw-format puts on the wire: CDB byte1
            // 0x19 = FmtData | CmpList | Format Code 001b; parameter list
            // header FOV|DCRT|Immed, descriptor length 8, Number of Blocks =
            // medium capacity (0x00032000), Format Type 00h, block length 0.
            let cdb = [0x04u8, 0x19, 0, 0, 0, 0];
            let mut w = work();
            w[1] = 0xA2;
            w[2..4].copy_from_slice(&8u16.to_be_bytes());
            w[4..8].copy_from_slice(&0x0003_2000u32.to_be_bytes());
            w[8] = 0x00;
            assert_eq!(
                dev.do_cmd(&cdb, &mut w).unwrap(),
                CommandOutcome::InParam { expected_len: 12 }
            );
            assert_eq!(dev.complete_param(&cdb, &w[..12]), CommandOutcome::Status);
            // The format ran even though Immed was set: drain the zero-fill
            // agenda (the session does this before the terminal status).
            drain_agenda(&mut dev, &mut bb);
            let s = dev.take_sense().expect("UNIT ATTENTION after format");
            assert_eq!(s.key, SenseKey::UnitAttention);
            assert_eq!(s.asc, asc::MEDIUM_MAY_HAVE_CHANGED);
            // Medium is cleared.
            let mut w = work();
            let mut cdb = [0u8; 10];
            cdb[0] = op::READ_10;
            cdb[5] = 1;
            cdb[8] = 1;
            let outcome = dev.do_cmd(&cdb, &mut w).unwrap();
            let mut out = [0u8; 2048];
            let n = data_in_xfer(&mut dev, &mut bb, outcome, &w, &mut out);
            assert_eq!(n, 2048);
            assert_eq!(out, [0u8; 2048]);
        }
    }

    #[test]
    #[allow(unused_mut, unused_variables)]
    fn drive_read_dvd_structure_08_09_0a_0b_for_dvdram() {
        let mut img = vec![0u8; 4096 * 2048];
        #[cfg(feature = "dvdram")]
        {
            use crate::cdrom::dvdram::DvdRamMedia;
            let mut dev = CdromDrive::new();
            let mut bb = BlockBackend::Ram(RamBackend::new(&mut img));
            let media = DvdRamMedia::open(&mut bb);
            dev.load_quiet(CdMedia::Rw(media));
            let mut w = work();
            for &fmt in &[0x08u8, 0x09, 0x0A, 0x0B] {
                let mut cdb = [0u8; 12];
                cdb[0] = op::READ_DVD_STRUCTURE;
                cdb[7] = fmt;
                cdb[8] = 0x08; // alloc 2048
                cdb[9] = 0x00;
                let mut out = [0u8; 4096];
                let n = data_in(dev.do_cmd(&cdb, &mut w).unwrap(), &w, &mut out);
                assert!(n >= 4, "format {:02X} should succeed", fmt);
                let len = u16::from_be_bytes([out[0], out[1]]) as usize;
                if fmt == 0x08 {
                    assert_eq!(len, 0x0802);
                } else if fmt == 0x0A {
                    assert_eq!(len, 0x000E);
                } else {
                    assert_eq!(len, 0x0006);
                }
            }
            // Same formats must fail for CD-ROM flat media
            let mut img2 = vec![0u8; 2048];
            let mut bb2 = BlockBackend::Ram(RamBackend::new(&mut img2));
            let mut dev2 = CdromDrive::new();
            dev2.load_quiet(CdMedia::ro(&mut bb2));
            for &fmt in &[0x08u8, 0x09, 0x0A, 0x0B] {
                let mut cdb = [0u8; 12];
                cdb[0] = op::READ_DVD_STRUCTURE;
                cdb[7] = fmt;
                cdb[8] = 0x08;
                let outcome = dev2.do_cmd(&cdb, &mut w).unwrap();
                assert_eq!(outcome, CommandOutcome::CheckCondition);
                assert_eq!(dev2.peek_sense().unwrap().key, SenseKey::IllegalRequest);
            }
        }
    }

    #[test]
    #[allow(unused_mut, unused_variables)]
    fn dvd_ram_always_formatted_no_medium_not_formatted() {
        // Logical DVD-RAM never returns NOT READY/MEDIUM NOT FORMATTED per §2.1
        let mut img = vec![0u8; 4096 * 2048];
        #[cfg(feature = "dvdram")]
        {
            use crate::cdrom::dvdram::DvdRamMedia;
            let mut dev = CdromDrive::new();
            let mut bb = BlockBackend::Ram(RamBackend::new(&mut img));
            let media = DvdRamMedia::open(&mut bb);
            dev.load_quiet(CdMedia::Rw(media));
            // Immediately after load, TUR is GOOD (no format needed)
            let mut w = work();
            let mut cdb = [0u8; 6];
            cdb[0] = op::TEST_UNIT_READY;
            assert_eq!(dev.do_cmd(&cdb, &mut w).unwrap(), CommandOutcome::Status);
            // READ/WRITE should not return MEDIUM NOT FORMATTED
            let mut cdb10 = [0u8; 10];
            cdb10[0] = op::READ_10;
            cdb10[8] = 0x01;
            let out = dev.do_cmd(&cdb10, &mut w).unwrap();
            assert!(matches!(out, CommandOutcome::OutXfer { .. }));
            // consume READ via xfer to clear pending for next WRITE
            if let CommandOutcome::OutXfer { len } = out {
                let mut dummy = vec![0u8; len as usize];
                let _ = dev.xfer_out(0, &mut dummy);
            }
            cdb10[0] = op::WRITE_10;
            let out2 = dev.do_cmd(&cdb10, &mut w).unwrap();
            assert!(matches!(out2, CommandOutcome::InXfer { .. }));
            // Clear pending for next test by doing xfer_in with dummy
            if let CommandOutcome::InXfer { len } = out2 {
                let dummy = vec![0u8; len as usize];
                let _ = dev.xfer_in(0, &dummy);
            }
            // Format then TUR should be UA 28h (media changed), then GOOD after REQUEST SENSE
            let mut cdbf = [0u8; 6];
            cdbf[0] = op::FORMAT_UNIT;
            cdbf[1] = 0x11;
            let mut w2 = work();
            w2[2..4].copy_from_slice(&8u16.to_be_bytes());
            w2[8] = 0x00;
            w2[10..12].copy_from_slice(&2048u16.to_be_bytes());
            assert_eq!(
                dev.do_cmd(&cdbf, &mut w2).unwrap(),
                CommandOutcome::InParam { expected_len: 12 }
            );
            assert_eq!(dev.complete_param(&cdbf, &w2[..12]), CommandOutcome::Status);
            let outcome = dev.do_cmd(&cdb, &mut w).unwrap();
            assert_eq!(outcome, CommandOutcome::CheckCondition);
            // UA is consumed when reported (autosense carries it).
            assert!(dev.peek_sense().is_none());
            let mut cdb_rs = [0u8; 6];
            cdb_rs[0] = op::REQUEST_SENSE;
            cdb_rs[4] = 18;
            let _ = dev.do_cmd(&cdb_rs, &mut w).unwrap();
            assert_eq!(dev.do_cmd(&cdb, &mut w).unwrap(), CommandOutcome::Status);
        }
    }

    /// READ DISC INFORMATION (51h) reports the emulated medium as always
    /// formatted: Disc Status 11b ("Others") with a Complete last session —
    /// MMC-6 says "Blank has no meaning" for DVD-RAM (Table 498), and FORMAT
    /// UNIT (a device operation) is independent of the host creating a file
    /// system.
    #[test]
    #[allow(unused_mut, unused_variables)]
    fn disc_info_reports_always_formatted() {
        let mut img = vec![0u8; 4096 * 2048];
        #[cfg(feature = "dvdram")]
        {
            use crate::cdrom::dvdram::DvdRamMedia;

            fn disc_status(dev: &mut CdromDrive) -> u8 {
                let mut w = [0u8; crate::MIN_DATA_LEN];
                let mut cdb = [0u8; 10];
                cdb[0] = op::READ_DISC_INFORMATION;
                cdb[8] = 0xFF;
                let mut buf = [0u8; 256];
                let n = data_in(dev.do_cmd(&cdb, &mut w).unwrap(), &w, &mut buf);
                assert!(n >= 3, "READ DISC INFORMATION returned {n} bytes");
                // byte 2: erasable(4) | state_of_last_session(3:2) | disc_status(1:0)
                buf[2] & 0x03
            }

            let mut dev = CdromDrive::new();
            let mut bb = BlockBackend::Ram(RamBackend::new(&mut img));
            let media = DvdRamMedia::open(&mut bb);
            dev.load_quiet(CdMedia::Rw(media));

            // Always formatted — 10b "Finalized" (MMC-6 Table 372).
            assert_eq!(disc_status(&mut dev), 2, "always formatted");

            // FORMAT UNIT clears logical blocks but does not change the disc
            // status: it is a device operation, not a file-system creation.
            let mut cdbf = [0u8; 6];
            cdbf[0] = op::FORMAT_UNIT;
            cdbf[1] = 0x11;
            let mut w = work();
            w[2..4].copy_from_slice(&8u16.to_be_bytes());
            w[8] = 0x00;
            w[10..12].copy_from_slice(&2048u16.to_be_bytes());
            assert_eq!(
                dev.do_cmd(&cdbf, &mut w).unwrap(),
                CommandOutcome::InParam { expected_len: 12 }
            );
            assert_eq!(dev.complete_param(&cdbf, &w[..12]), CommandOutcome::Status);
            // Drain the zero-fill agenda (the session does this before the
            // terminal status), then consume the format's UA.
            drain_agenda(&mut dev, &mut bb);
            let mut cdb_rs = [0u8; 6];
            cdb_rs[0] = op::REQUEST_SENSE;
            cdb_rs[4] = 18;
            let _ = dev.do_cmd(&cdb_rs, &mut w).unwrap();
            assert_eq!(
                disc_status(&mut dev),
                2,
                "still formatted after FORMAT UNIT"
            );
        }
    }

    /// The `CdromDrive` read-ahead coordinate is the backend address a media
    /// read will use (`base_byte + transfer_offset`); a drive with no transfer
    /// in flight offers none.
    #[test]
    fn drive_read_ahead_offset_is_the_backend_address() {
        use crate::common::store::StoreOp;
        use crate::scsi::device::{CommandOutcome, ScsiDevice, Xfer};

        let mut dev = CdromDrive::new();
        assert_eq!(dev.read_ahead_offset(0), None, "no transfer in flight");

        let mut img = vec![0u8; 16 * 2048];
        let mut bb = BlockBackend::Ram(RamBackend::new(&mut img));
        dev.load_quiet(CdMedia::ro(&mut bb));

        // READ(10) at LBA 3, 2 CD sectors of 2048.
        let mut cdb = [0u8; 10];
        cdb[0] = op::READ_10;
        cdb[5] = 3;
        cdb[8] = 2;
        let mut w = work();
        assert_eq!(
            dev.do_cmd(&cdb, &mut w).unwrap(),
            CommandOutcome::OutXfer { len: 2 * 2048 }
        );

        let base = 3 * 2048;
        assert_eq!(dev.read_ahead_offset(0), Some(base));
        assert_eq!(dev.read_ahead_offset(2048), Some(base + 2048));

        // ...and it agrees with the address `xfer_out` actually produces.
        let mut buf = vec![0u8; 2048];
        match dev.xfer_out(2048, &mut buf) {
            Xfer::Store(StoreOp::Read { off, .. }) => {
                assert_eq!(Some(off), dev.read_ahead_offset(2048))
            }
            other => panic!("expected Xfer::Store(StoreOp::Read), got {other:?}"),
        }
    }
}
