//! Public SPC wrapper: the six-command host subset over any [`Device`].
//!
//! Authority: `__ARCH__/design/02-api-core.md` §4.19,
//! `02-api-behavior.md` §10.2 and `02-api.md` §4.1.
//!
//! [`Spc`] owns only query state and the prevent/start latches; media commands
//! (READ/WRITE/FORMAT/…) are delegated to the inner device. The wrapper
//! **does not allocate an internal response buffer**: every response is written
//! directly into the caller's `data` on the poll that sends it. Responses are
//! truncated to `min(allocation length, data.len())` and an allocation length
//! of 0 transfers no data at all.
//!
//! The six commands are TEST UNIT READY (0x00, delegated to the inner device),
//! INQUIRY (0x12), REQUEST SENSE (0x03), REPORT LUNS (0xA0), PREVENT/ALLOW
//! (0x1E) and START STOP UNIT (0x1B). `0x1B` stores only the start bit; it
//! never ejects or handles `LoEj`.
//!
//! The public query commands MODE SENSE(6/10) (0x1A/0x5A), READ
//! CAPACITY(10) (0x25), GET CONFIGURATION (0x46) and GET EVENT STATUS
//! NOTIFICATION (0x4A). They are intercepted **only** when the inner device
//! opts in through [`Device::spc_profile`]; otherwise the CDB is delegated to
//! the inner device. The profile encodes the response, so
//! the wrapper still owns no response buffer.
//!
//! REPORT LUNS uses this layout: 8-byte header (`LUN LIST LENGTH` =
//! `8 * lun_count`, then reserved) followed by SAM-3 single-level LUN
//! descriptors `[0x00, lun, 0, 0, 0, 0, 0, 0]` — the LUN number is in byte 1,
//! never byte 0.

use super::device::{
    CommandContext, DataPlan, Device, Direction, Feedback, FeedbackKind, InquiryData,
    InterruptReason, PollStep, RemovalEncoding,
};
use super::eject::RemovalLocks;
use super::errors::{
    Completion, Delivery, Effect, Fault, KnownEffects, Sense, FORMAT_IN_PROGRESS, INVALID_FIELD,
    MEDIUM_NOT_PRESENT, WRITE_ERROR,
};
use super::long::{LongInfo, LongPhase};
use super::permit::{BoundaryPermit, CommandPermit};
use super::storage::StorageOp;

/// TEST UNIT READY.
const TEST_UNIT_READY: u8 = 0x00;
/// REQUEST SENSE.
const REQUEST_SENSE: u8 = 0x03;
/// INQUIRY.
const INQUIRY: u8 = 0x12;
/// MODE SENSE(6).
const MODE_SENSE_6: u8 = 0x1A;
/// START STOP UNIT.
const START_STOP_UNIT: u8 = 0x1B;
/// PREVENT/ALLOW MEDIUM REMOVAL.
const PREVENT_ALLOW: u8 = 0x1E;
/// READ CAPACITY(10) (SBC-3 5.16).
const READ_CAPACITY_10: u8 = 0x25;
/// GET CONFIGURATION (MMC-6 6.5).
const GET_CONFIGURATION: u8 = 0x46;
/// GET EVENT STATUS NOTIFICATION (MMC-6 6.7).
const EVENT_STATUS_NOTIFICATION: u8 = 0x4A;
/// MODE SENSE(10).
const MODE_SENSE_10: u8 = 0x5A;
/// REPORT LUNS.
const REPORT_LUNS: u8 = 0xA0;

/// Standard INQUIRY response length (SPC-3 6.4.2).
const INQUIRY_LEN: usize = 36;
/// Fixed-format sense response length (SPC-3 4.5.1).
const SENSE_LEN: usize = 18;
/// READ CAPACITY(10) response length: last LBA + block length (SBC-3 5.16).
const READ_CAPACITY_LEN: usize = 8;
/// ILLEGAL REQUEST / SAVING PARAMETERS NOT SUPPORTED (SPC-3 6.9, PC=11b).
const SAVING_PARAMETERS_NOT_SUPPORTED: Sense = Sense::new(0x05, 0x39, 0x00);

/// Which Spc-owned query is in progress.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Query {
    /// Nothing active.
    None,
    /// TUR delegated to the inner device.
    Tur,
    /// Immediate completion, no data phase.
    NoData,
    /// Clear the normal PREVENT latch after a successful Sync
    /// (unlock-flush); the latch stays set on failure.
    UnlockFlush,
    /// INQUIRY.
    Inquiry,
    /// REQUEST SENSE.
    RequestSense,
    /// REPORT LUNS.
    ReportLuns,
    /// MODE SENSE(6/10) answered by the profile.
    ModeSense {
        /// 10-byte CDB layout (`0x5A`) instead of the 6-byte one (`0x1A`).
        ten: bool,
        /// Page code (`cdb[2] & 0x3F`).
        page: u8,
        /// Disable block descriptors (`cdb[1] & 0x10`).
        dbd: bool,
        /// Page control (`cdb[2] >> 6`).
        pc: u8,
    },
    /// READ CAPACITY(10) answered by the profile.
    ReadCapacity,
    /// GET CONFIGURATION answered by the profile.
    GetConfiguration {
        /// RT field (`cdb[1] & 0x03`).
        rt: u8,
        /// Starting feature number (`cdb[2..4]`).
        start_feature: u16,
    },
    /// GET EVENT STATUS NOTIFICATION answered by the profile.
    EventStatus {
        /// Notification class (`cdb[4]`).
        class: u8,
    },
}

/// Public SPC wrapper over a profile device.
pub struct Spc<D: Device> {
    inner: D,
    query: Query,
    /// Bytes of the response selected for this command.
    len: usize,
    published: bool,
    prevent: bool,
    persistent_prevent: bool,
    started: bool,
    /// LUN count reported by REPORT LUNS (0 is treated as 1).
    lun_count: u32,
    saved_sense: Option<Sense>,
}

impl<D: Device> Spc<D> {
    /// Wrap a profile device.
    pub fn new(inner: D) -> Self {
        Self {
            inner,
            query: Query::None,
            len: 0,
            published: false,
            prevent: false,
            persistent_prevent: false,
            started: true,
            lun_count: 1,
            saved_sense: None,
        }
    }

    /// Borrow the wrapped device.
    pub fn inner(&self) -> &D {
        &self.inner
    }

    /// Mutably borrow the wrapped device.
    pub fn inner_mut(&mut self) -> &mut D {
        &mut self.inner
    }

    /// Normal PREVENT latch.
    pub const fn is_prevented(&self) -> bool {
        self.prevent
    }

    /// Persistent PREVENT latch.
    pub const fn is_persistent_prevented(&self) -> bool {
        self.persistent_prevent
    }

    /// Last START STOP UNIT state.
    pub const fn is_started(&self) -> bool {
        self.started
    }

    /// Last sense captured from the inner device, if not yet consumed.
    pub const fn saved_sense(&self) -> Option<Sense> {
        self.saved_sense
    }

    /// Body of `Device::prepare`; the trait wrapper records a prepare-level
    /// CHECK as the saved sense so a following REQUEST SENSE can return it.
    fn prepare_inner(
        &mut self,
        permit: &CommandPermit,
        ctx: CommandContext,
        cdb: &[u8],
    ) -> Result<(), Completion> {
        if self.query != Query::None {
            return Err(Completion::Busy);
        }
        let Some(opcode) = cdb.first().copied() else {
            return Err(Completion::Check(INVALID_FIELD));
        };
        match opcode {
            TEST_UNIT_READY => {
                if cdb.len() < 6 {
                    return Err(Completion::Check(INVALID_FIELD));
                }
                // Delegating preserves empty-medium NOT READY and the
                // foreground-FORMAT gate. Every profile that answers TUR owns
                // the GOOD; the wrapper never fabricates one.
                match self.inner.prepare(permit, ctx, cdb) {
                    Ok(()) => {
                        self.query = Query::Tur;
                        Ok(())
                    }
                    Err(other) => Err(other),
                }
            }
            INQUIRY => {
                check_direction(ctx, Direction::ToHost)?;
                if cdb.len() < 5 {
                    return Err(Completion::Check(INVALID_FIELD));
                }
                // Standard INQUIRY only: EVPD/CMDDT and a non-zero page code
                // are unsupported and must CHECK, not return the
                // standard page (SPC-3 6.4.2).
                if cdb[1] & 0x03 != 0 || cdb[2] != 0 {
                    return Err(Completion::Check(INVALID_FIELD));
                }
                let alloc = be16(&cdb[3..5]) as usize;
                self.len = alloc.min(INQUIRY_LEN);
                self.published = false;
                self.query = Query::Inquiry;
                Ok(())
            }
            REQUEST_SENSE => {
                check_direction(ctx, Direction::ToHost)?;
                if cdb.len() < 5 {
                    return Err(Completion::Check(INVALID_FIELD));
                }
                let alloc = cdb[4] as usize;
                self.len = alloc.min(SENSE_LEN);
                self.published = false;
                self.query = Query::RequestSense;
                Ok(())
            }
            REPORT_LUNS => {
                check_direction(ctx, Direction::ToHost)?;
                if cdb.len() < 10 {
                    return Err(Completion::Check(INVALID_FIELD));
                }
                let alloc = be32(&cdb[6..10]) as usize;
                self.lun_count = if ctx.lun_count == 0 { 1 } else { ctx.lun_count };
                let list = 8usize.saturating_mul(self.lun_count as usize);
                let total = 8usize.saturating_add(list);
                self.len = alloc.min(total);
                self.published = false;
                self.query = Query::ReportLuns;
                Ok(())
            }
            MODE_SENSE_6 | MODE_SENSE_10 => {
                // Interception is profile-gated: without a profile the CDB
                // belongs to the inner device unchanged.
                if self.inner.spc_profile().is_none() {
                    return self.inner.prepare(permit, ctx, cdb);
                }
                check_direction(ctx, Direction::ToHost)?;
                let ten = opcode == MODE_SENSE_10;
                let need = if ten { 10 } else { 6 };
                if cdb.len() < need {
                    return Err(Completion::Check(INVALID_FIELD));
                }
                // Foreground FORMAT blocks the medium query commands before
                // any profile access (`02-api-core.md` §4.12, MMC-6 6.5).
                if foreground_format(self.inner.long_info()) {
                    return Err(Completion::Check(FORMAT_IN_PROGRESS));
                }
                // MODE SENSE(6): DBD is byte 1 bit 4. MODE SENSE(10): DBD is
                // byte 1 bit 3 and bit 4 is LLBAA (unsupported here).
                if ten && cdb[1] & 0x10 != 0 {
                    return Err(Completion::Check(INVALID_FIELD));
                }
                let dbd = if ten {
                    cdb[1] & 0x08 != 0
                } else {
                    cdb[1] & 0x10 != 0
                };
                let pc = cdb[2] >> 6;
                let page = cdb[2] & 0x3F;
                if pc == 3 {
                    // Saved pages are not supported (SP=0 in every page).
                    return Err(Completion::Check(SAVING_PARAMETERS_NOT_SUPPORTED));
                }
                let alloc = if ten {
                    be16(&cdb[7..9]) as usize
                } else {
                    cdb[4] as usize
                };
                // `None` asks the profile for the complete response length.
                let total = self
                    .inner
                    .spc_profile()
                    .and_then(|p| p.mode_sense(ten, page, dbd, pc, None));
                let Some(total) = total else {
                    return Err(Completion::Check(INVALID_FIELD));
                };
                self.len = total.min(alloc);
                self.published = false;
                self.query = Query::ModeSense { ten, page, dbd, pc };
                Ok(())
            }
            READ_CAPACITY_10 => {
                if self.inner.spc_profile().is_none() {
                    return self.inner.prepare(permit, ctx, cdb);
                }
                check_direction(ctx, Direction::ToHost)?;
                if cdb.len() < 10 {
                    return Err(Completion::Check(INVALID_FIELD));
                }
                if foreground_format(self.inner.long_info()) {
                    return Err(Completion::Check(FORMAT_IN_PROGRESS));
                }
                // READ CAPACITY has no allocation length: the host must be
                // able to receive the fixed 8-byte response.
                if ctx.host_bytes < READ_CAPACITY_LEN as u64 {
                    return Err(Completion::Check(INVALID_FIELD));
                }
                let capacity = self.inner.spc_profile().and_then(|p| p.read_capacity());
                let Some(capacity) = capacity else {
                    return Err(Completion::Check(MEDIUM_NOT_PRESENT));
                };
                // SBC-3 5.16: PMI=0 requires LBA 0; PMI=1 requires the LBA to
                // be addressable.
                let pmi = cdb[8] & 0x01 != 0;
                let lba = be32(&cdb[2..6]);
                let valid = if pmi {
                    lba <= capacity.last_lba
                } else {
                    lba == 0
                };
                if !valid {
                    return Err(Completion::Check(INVALID_FIELD));
                }
                self.len = READ_CAPACITY_LEN;
                self.published = false;
                self.query = Query::ReadCapacity;
                Ok(())
            }
            GET_CONFIGURATION => {
                if self.inner.spc_profile().is_none() {
                    return self.inner.prepare(permit, ctx, cdb);
                }
                check_direction(ctx, Direction::ToHost)?;
                if cdb.len() < 10 {
                    return Err(Completion::Check(INVALID_FIELD));
                }
                let rt = cdb[1] & 0x03;
                if rt == 3 {
                    return Err(Completion::Check(INVALID_FIELD));
                }
                let start = be16(&cdb[2..4]);
                let alloc = be16(&cdb[7..9]) as usize;
                let total = self
                    .inner
                    .spc_profile()
                    .and_then(|p| p.get_configuration(rt, start, None));
                let Some(total) = total else {
                    // Unsupported by the profile: the opcode stays with the
                    // inner device (delegation, e.g. Block).
                    return self.inner.prepare(permit, ctx, cdb);
                };
                self.len = total.min(alloc);
                self.published = false;
                self.query = Query::GetConfiguration {
                    rt,
                    start_feature: start,
                };
                Ok(())
            }
            EVENT_STATUS_NOTIFICATION => {
                if self.inner.spc_profile().is_none() {
                    return self.inner.prepare(permit, ctx, cdb);
                }
                check_direction(ctx, Direction::ToHost)?;
                if cdb.len() < 10 {
                    return Err(Completion::Check(INVALID_FIELD));
                }
                // Keep the baseline rejection of non-polled GESN.
                if cdb[1] & 0x01 == 0 {
                    return Err(Completion::Check(INVALID_FIELD));
                }
                let class = cdb[4];
                let alloc = be16(&cdb[7..9]) as usize;
                let total = self
                    .inner
                    .spc_profile()
                    .and_then(|p| p.event_status(class, None));
                let Some(total) = total else {
                    return self.inner.prepare(permit, ctx, cdb);
                };
                self.len = total.min(alloc);
                self.published = false;
                self.query = Query::EventStatus { class };
                Ok(())
            }
            PREVENT_ALLOW => {
                check_direction(ctx, Direction::None)?;
                if cdb.len() < 6 {
                    return Err(Completion::Check(INVALID_FIELD));
                }
                // Unlock-flush: clearing the normal latch requires a
                // successful Sync. The latch is only cleared after the Sync
                // completes with a known effect; a failure keeps the lock.
                self.published = false;
                match self.inner.removal_encoding() {
                    // MMC-6 Table 329: bit1 selects normal/persistent, bit0
                    // selects clear/set. The two bits are not independent flags.
                    RemovalEncoding::Mmc => {
                        let persistent = cdb[4] & 0x02 != 0;
                        let set = cdb[4] & 0x01 != 0;
                        if persistent {
                            self.persistent_prevent = set;
                            self.query = Query::NoData;
                        } else if set {
                            self.prevent = true;
                            self.query = Query::NoData;
                        } else if self.prevent {
                            self.query = Query::UnlockFlush;
                        } else {
                            self.query = Query::NoData;
                        }
                    }
                    // SPC-3 Table 119 two-bit enum. Without a changer, 10b/11b
                    // are treated as prevent (documented deviation from the
                    // changer meaning, not a persistent lock).
                    RemovalEncoding::Scsi => match cdb[4] & 0x03 {
                        0 if self.prevent => self.query = Query::UnlockFlush,
                        0 => self.query = Query::NoData,
                        _ => {
                            self.prevent = true;
                            self.query = Query::NoData;
                        }
                    },
                }
                Ok(())
            }
            START_STOP_UNIT => {
                check_direction(ctx, Direction::None)?;
                if cdb.len() < 6 {
                    return Err(Completion::Check(INVALID_FIELD));
                }
                self.started = cdb[4] & 0x01 != 0;
                self.query = Query::NoData;
                Ok(())
            }
            _ => self.inner.prepare(permit, ctx, cdb),
        }
    }
}

/// Ensure the host phase direction matches the command family.
fn check_direction(ctx: CommandContext, expected: Direction) -> Result<(), Completion> {
    if ctx.host_direction == expected {
        Ok(())
    } else {
        Err(Completion::Check(INVALID_FIELD))
    }
}

/// Whether a foreground FORMAT is running and holds the medium gate up.
///
/// MODE SENSE and READ CAPACITY are medium queries and must not report
/// geometry/parameters while the medium is being formatted; GET
/// CONFIGURATION and GESN stay admitted (`02-api-core.md` §4.12).
fn foreground_format(info: LongInfo) -> bool {
    info.phase == LongPhase::Foreground && info.progress.is_some()
}

/// Big-endian 16-bit CDB field.
fn be16(bytes: &[u8]) -> u16 {
    (u16::from(bytes[0]) << 8) | u16::from(bytes[1])
}

/// Big-endian 32-bit CDB field.
fn be32(bytes: &[u8]) -> u32 {
    (u32::from(bytes[0]) << 24)
        | (u32::from(bytes[1]) << 16)
        | (u32::from(bytes[2]) << 8)
        | u32::from(bytes[3])
}

/// Write the INQUIRY standard response into `data`.
fn fill_inquiry(info: InquiryData, data: &mut [u8], n: usize) {
    for byte in &mut data[..n] {
        *byte = 0;
    }
    if n >= 1 {
        data[0] = info.pdt;
    }
    if n >= 2 && info.removable {
        data[1] |= 0x80;
    }
    if n >= 3 {
        data[2] = 5; // SPC-3
    }
    if n >= 4 {
        data[3] = 2; // response data format
    }
    if n >= 5 {
        data[4] = (INQUIRY_LEN - 5) as u8; // additional length = 31
    }
    if n > 8 {
        let take = (n - 8).min(8);
        data[8..8 + take].copy_from_slice(&info.vendor[..take]);
    }
    if n > 16 {
        let take = (n - 16).min(16);
        data[16..16 + take].copy_from_slice(&info.product[..take]);
    }
    if n > 32 {
        let take = (n - 32).min(4);
        data[32..32 + take].copy_from_slice(&info.revision[..take]);
    }
}

/// Write a fixed-format sense response into `data`.
///
/// For a foreground FORMAT (`2/04/04`) with a known progress value, byte 15
/// carries SKSV=1 and bytes 16–17 the Progress Indication
/// (`value / 65536 × 100%`, SPC-3 4.5.2.4 / MMC-6 Table 252).
fn fill_sense(sense: Sense, progress: Option<u32>, data: &mut [u8], n: usize) {
    for byte in &mut data[..n] {
        *byte = 0;
    }
    if n >= 1 {
        data[0] = 0x70;
    }
    if n >= 3 {
        data[2] = sense.key & 0x0f;
    }
    if n >= 8 {
        data[7] = (SENSE_LEN - 8) as u8; // additional sense length = 10
    }
    if n >= 13 {
        data[12] = sense.asc;
    }
    if n >= 14 {
        data[13] = sense.ascq;
    }
    if n >= 18 && sense.key == 0x02 && sense.asc == 0x04 && sense.ascq == 0x04 {
        if let Some(progress) = progress {
            data[15] = 0x80; // SKSV
            let scaled = (progress.min(100) * 65_536 / 100).min(u32::from(u16::MAX));
            data[16..18].copy_from_slice(&(scaled as u16).to_be_bytes());
        }
    }
}

/// Write the REPORT LUNS response into `data`.
fn fill_report_luns(lun_count: u32, data: &mut [u8], n: usize) {
    for byte in &mut data[..n] {
        *byte = 0;
    }
    let list_len = lun_count.saturating_mul(8);
    let len_bytes = list_len.to_be_bytes();
    let head = n.min(4);
    data[..head].copy_from_slice(&len_bytes[..head]);
    let mut i = 0u32;
    while i < lun_count {
        let at = 8 + (i as usize) * 8;
        if at >= n {
            break;
        }
        // SAM-3 single-level: byte0 stays 0 (method + bus), byte1 = LUN.
        if at + 1 < n {
            data[at + 1] = (i & 0xFF) as u8;
        }
        i += 1;
    }
}

impl<D: Device> Device for Spc<D> {
    type Medium = D::Medium;

    fn inquiry_data(&self) -> InquiryData {
        self.inner.inquiry_data()
    }

    fn removal_encoding(&self) -> RemovalEncoding {
        self.inner.removal_encoding()
    }

    fn removal_locks(&self) -> Option<RemovalLocks> {
        Some(RemovalLocks {
            prevent: self.prevent,
            persistent_prevent: self.persistent_prevent,
        })
    }

    fn prepare(
        &mut self,
        permit: &CommandPermit,
        ctx: CommandContext,
        cdb: &[u8],
    ) -> Result<(), Completion> {
        let result = self.prepare_inner(permit, ctx, cdb);
        if let Err(Completion::Check(sense)) = result {
            // A prepare-level CHECK (range, write protect, invalid CDB) is a
            // real command sense; REQUEST SENSE must return it exactly like a
            // poll-level CHECK.
            self.saved_sense = Some(sense);
        }
        result
    }

    fn active(&self) -> bool {
        self.query != Query::None || self.inner.active()
    }

    fn resume(&mut self, permit: &CommandPermit) -> Result<(), Completion> {
        if self.query != Query::None {
            Ok(())
        } else {
            self.inner.resume(permit)
        }
    }

    fn poll<'a>(
        &mut self,
        permit: &CommandPermit,
        fb: Feedback,
        data: &'a mut [u8],
    ) -> PollStep<'a> {
        match self.query {
            Query::None => {
                let step = self.inner.poll(permit, fb, data);
                if let PollStep::Complete(Completion::Check(sense)) = &step {
                    self.saved_sense = Some(*sense);
                }
                step
            }
            Query::Tur => {
                let step = self.inner.poll(permit, fb, data);
                if let PollStep::Complete(completion) = &step {
                    self.query = Query::None;
                    if let Completion::Check(sense) = completion {
                        self.saved_sense = Some(*sense);
                    }
                }
                step
            }
            Query::NoData => {
                self.query = Query::None;
                PollStep::Complete(Completion::Good)
            }
            Query::UnlockFlush => {
                if !self.published {
                    self.published = true;
                    return PollStep::Io(StorageOp::Sync { resource: 0 });
                }
                if fb.kind() != FeedbackKind::IoDone {
                    return PollStep::Idle;
                }
                let known = fb
                    .io()
                    .map(|r| r.error().is_none() && r.effect() == Effect::Known)
                    .unwrap_or(false);
                self.query = Query::None;
                self.published = false;
                if known {
                    self.prevent = false;
                    PollStep::Complete(Completion::Good)
                } else {
                    PollStep::Complete(Completion::Check(WRITE_ERROR))
                }
            }
            Query::ReportLuns => {
                if self.len == 0 {
                    self.query = Query::None;
                    return PollStep::Complete(Completion::Good);
                }
                if !self.published {
                    self.published = true;
                    return PollStep::Publish(DataPlan {
                        direction: Direction::ToHost,
                        bytes: self.len as u64,
                    });
                }
                if fb.kind() == FeedbackKind::HostSent {
                    self.query = Query::None;
                    return PollStep::Complete(Completion::Good);
                }
                if data.len() < self.len {
                    self.query = Query::None;
                    return PollStep::Complete(Completion::Check(INVALID_FIELD));
                }
                fill_report_luns(self.lun_count, data, self.len);
                PollStep::Send(&data[..self.len])
            }
            Query::ModeSense { ten, page, dbd, pc } => {
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
                // The profile writes directly into the caller's bank; header
                // lengths describe the complete, untruncated response.
                let filled = self
                    .inner
                    .spc_profile()
                    .and_then(|p| p.mode_sense(ten, page, dbd, pc, Some(&mut data[..len])));
                if filled.is_none() {
                    self.query = Query::None;
                    return PollStep::Complete(Completion::Check(INVALID_FIELD));
                }
                PollStep::Send(&data[..len])
            }
            Query::ReadCapacity => {
                let len = self.len;
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
                let capacity = self.inner.spc_profile().and_then(|p| p.read_capacity());
                let Some(capacity) = capacity else {
                    self.query = Query::None;
                    return PollStep::Complete(Completion::Check(MEDIUM_NOT_PRESENT));
                };
                data[..4].copy_from_slice(&capacity.last_lba.to_be_bytes());
                data[4..8].copy_from_slice(&capacity.block_len.to_be_bytes());
                PollStep::Send(&data[..len])
            }
            Query::GetConfiguration { rt, start_feature } => {
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
                let filled = self
                    .inner
                    .spc_profile()
                    .and_then(|p| p.get_configuration(rt, start_feature, Some(&mut data[..len])));
                if filled.is_none() {
                    self.query = Query::None;
                    return PollStep::Complete(Completion::Check(INVALID_FIELD));
                }
                PollStep::Send(&data[..len])
            }
            Query::EventStatus { class } => {
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
                let filled = self
                    .inner
                    .spc_profile()
                    .and_then(|p| p.event_status(class, Some(&mut data[..len])));
                if filled.is_none() {
                    self.query = Query::None;
                    return PollStep::Complete(Completion::Check(INVALID_FIELD));
                }
                PollStep::Send(&data[..len])
            }
            Query::Inquiry => {
                if self.len == 0 {
                    self.query = Query::None;
                    return PollStep::Complete(Completion::Good);
                }
                if !self.published {
                    self.published = true;
                    return PollStep::Publish(DataPlan {
                        direction: Direction::ToHost,
                        bytes: self.len as u64,
                    });
                }
                if fb.kind() == FeedbackKind::HostSent {
                    self.query = Query::None;
                    return PollStep::Complete(Completion::Good);
                }
                if data.len() < self.len {
                    self.query = Query::None;
                    return PollStep::Complete(Completion::Check(INVALID_FIELD));
                }
                fill_inquiry(self.inner.inquiry_data(), data, self.len);
                PollStep::Send(&data[..self.len])
            }
            Query::RequestSense => {
                if self.len == 0 {
                    // A completed REQUEST SENSE consumes the saved sense even
                    // when no data is transferred.
                    self.saved_sense = None;
                    self.query = Query::None;
                    return PollStep::Complete(Completion::Good);
                }
                if !self.published {
                    self.published = true;
                    return PollStep::Publish(DataPlan {
                        direction: Direction::ToHost,
                        bytes: self.len as u64,
                    });
                }
                if fb.kind() == FeedbackKind::HostSent {
                    let fully_sent = fb
                        .host()
                        .map(|h| h.error().is_none() && h.accepted() == self.len)
                        .unwrap_or(false);
                    self.query = Query::None;
                    // A short/failed send does not consume the saved sense.
                    if fully_sent {
                        self.saved_sense = None;
                    }
                    return PollStep::Complete(Completion::Good);
                }
                if data.len() < self.len {
                    self.query = Query::None;
                    return PollStep::Complete(Completion::Check(INVALID_FIELD));
                }
                let info = self.inner.long_info();
                let sense = if info.phase == LongPhase::Foreground && info.progress.is_some() {
                    FORMAT_IN_PROGRESS
                } else {
                    self.saved_sense.unwrap_or(Sense::new(0x00, 0x00, 0x00))
                };
                let progress = if info.phase == LongPhase::Foreground {
                    info.progress
                } else {
                    None
                };
                fill_sense(sense, progress, data, self.len);
                PollStep::Send(&data[..self.len])
            }
        }
    }

    fn poll_long<'a>(
        &mut self,
        permit: &CommandPermit,
        fb: Feedback,
        data: &'a mut [u8],
    ) -> PollStep<'a> {
        self.inner.poll_long(permit, fb, data)
    }

    fn long_info(&self) -> LongInfo {
        self.inner.long_info()
    }

    fn interrupt(
        &mut self,
        permit: &CommandPermit,
        reason: InterruptReason,
        known: KnownEffects,
    ) -> Result<(), Fault> {
        self.query = Query::None;
        self.published = false;
        self.len = 0;
        self.inner.interrupt(permit, reason, known)
    }

    fn finish_delivery(&mut self, permit: &CommandPermit, delivery: Delivery) {
        self.inner.finish_delivery(permit, delivery);
    }

    fn commit(&mut self, permit: &BoundaryPermit) -> Result<(), Completion> {
        self.inner.commit(permit)
    }

    fn host_eject_succeeded(&mut self, permit: &BoundaryPermit) {
        // The host's own EJECT clears the normal PREVENT latch; the persistent
        // latch is never implicitly cleared (`02-api-core.md` §4.19, `03 §3.6`).
        self.prevent = false;
        self.inner.host_eject_succeeded(permit);
    }

    fn take_medium(&mut self, permit: &BoundaryPermit) -> Option<Self::Medium> {
        self.inner.take_medium(permit)
    }

    fn install_medium(
        &mut self,
        permit: &BoundaryPermit,
        medium: Self::Medium,
    ) -> Result<(), (Self::Medium, Fault)> {
        self.inner.install_medium(permit, medium)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::block::{BlockAttrs, BlockDevice};
    use crate::core::storage::{HostReceipt, IoReceipt};
    use crate::core::{Capacity, NoMedium, SpcProfile, TargetId};

    fn permit() -> CommandPermit {
        CommandPermit::new(TargetId::UNBOUND)
    }

    fn ctx(direction: Direction, bytes: u64) -> CommandContext {
        CommandContext {
            lun: 0,
            lun_count: 1,
            host_bytes: bytes,
            host_direction: direction,
        }
    }

    fn inquiry_cdb(alloc: u16) -> [u8; 6] {
        let mut cdb = [0u8; 6];
        cdb[0] = 0x12;
        cdb[3] = (alloc >> 8) as u8;
        cdb[4] = alloc as u8;
        cdb
    }

    fn report_luns_cdb(alloc: u32) -> [u8; 10] {
        let mut cdb = [0u8; 10];
        cdb[0] = 0xA0;
        cdb[6] = (alloc >> 24) as u8;
        cdb[7] = (alloc >> 16) as u8;
        cdb[8] = (alloc >> 8) as u8;
        cdb[9] = alloc as u8;
        cdb
    }

    fn device() -> Spc<BlockDevice> {
        Spc::new(BlockDevice::new(BlockAttrs::new(16, 512)))
    }

    #[test]
    fn inquiry_standard_response_and_vendor_fields() {
        let mut spc = device();
        let permit = permit();
        let mut data = [0u8; 36];
        assert_eq!(
            spc.prepare(&permit, ctx(Direction::ToHost, 36), &inquiry_cdb(36)),
            Ok(())
        );
        match spc.poll(&permit, Feedback::begin(), &mut data) {
            PollStep::Publish(plan) => {
                assert_eq!(plan.direction, Direction::ToHost);
                assert_eq!(plan.bytes, 36);
            }
            other => panic!("expected publish, got {other:?}"),
        }
        match spc.poll(&permit, Feedback::plan_accepted(), &mut data) {
            PollStep::Send(bytes) => assert_eq!(bytes.len(), 36),
            other => panic!("expected send, got {other:?}"),
        }
        assert_eq!(data[0], 0x00, "Block PDT");
        assert_eq!(data[2], 5);
        assert_eq!(data[4], 31);
        assert_eq!(&data[8..12], b"SNOW");
        assert!(matches!(
            spc.poll(
                &permit,
                Feedback::host_sent(HostReceipt::test(36, None)),
                &mut data
            ),
            PollStep::Complete(Completion::Good)
        ));
    }

    #[test]
    fn inquiry_truncates_to_allocation_length() {
        let mut spc = device();
        let permit = permit();
        let mut data = [0u8; 16];
        assert_eq!(
            spc.prepare(&permit, ctx(Direction::ToHost, 8), &inquiry_cdb(8)),
            Ok(())
        );
        match spc.poll(&permit, Feedback::begin(), &mut data) {
            PollStep::Publish(plan) => assert_eq!(plan.bytes, 8),
            other => panic!("expected publish, got {other:?}"),
        }
        match spc.poll(&permit, Feedback::plan_accepted(), &mut data) {
            PollStep::Send(bytes) => assert_eq!(bytes.len(), 8),
            other => panic!("expected send, got {other:?}"),
        }
    }

    #[test]
    fn allocation_zero_transfers_nothing() {
        let mut spc = device();
        let permit = permit();
        let mut data = [0u8; 36];
        assert_eq!(
            spc.prepare(&permit, ctx(Direction::ToHost, 0), &inquiry_cdb(0)),
            Ok(())
        );
        assert!(matches!(
            spc.poll(&permit, Feedback::begin(), &mut data),
            PollStep::Complete(Completion::Good)
        ));
    }

    #[test]
    fn report_luns_layout_has_lun_in_byte_one() {
        let mut spc = device();
        let permit = permit();
        let mut data = [0u8; 32];
        let mut ctx3 = ctx(Direction::ToHost, 32);
        ctx3.lun_count = 3;
        assert_eq!(spc.prepare(&permit, ctx3, &report_luns_cdb(32)), Ok(()));
        match spc.poll(&permit, Feedback::begin(), &mut data) {
            PollStep::Publish(plan) => assert_eq!(plan.bytes, 32),
            other => panic!("expected publish, got {other:?}"),
        }
        match spc.poll(&permit, Feedback::plan_accepted(), &mut data) {
            PollStep::Send(bytes) => assert_eq!(bytes.len(), 32),
            other => panic!("expected send, got {other:?}"),
        }
        assert_eq!(&data[0..4], &24u32.to_be_bytes(), "LUN LIST LENGTH");
        assert_eq!(&data[4..8], &[0u8; 4], "reserved");
        // LUN 0..2 at byte 8, 16, 24; the LUN number is in byte 1.
        assert_eq!(&data[8..16], &[0x00, 0, 0, 0, 0, 0, 0, 0]);
        assert_eq!(&data[16..24], &[0x00, 1, 0, 0, 0, 0, 0, 0]);
        assert_eq!(&data[24..32], &[0x00, 2, 0, 0, 0, 0, 0, 0]);
    }

    #[test]
    fn report_luns_truncation_keeps_the_prefix() {
        let mut spc = device();
        let permit = permit();
        let mut data = [0u8; 20];
        let mut ctx3 = ctx(Direction::ToHost, 20);
        ctx3.lun_count = 3;
        assert_eq!(spc.prepare(&permit, ctx3, &report_luns_cdb(20)), Ok(()));
        spc.poll(&permit, Feedback::begin(), &mut data);
        spc.poll(&permit, Feedback::plan_accepted(), &mut data);
        assert_eq!(&data[0..4], &24u32.to_be_bytes());
        assert_eq!(&data[16..20], &[0x00, 1, 0, 0]);
    }

    #[test]
    fn prevent_allow_scsi_encoding_sets_normal_lock() {
        let mut spc = device();
        let permit = permit();
        let mut cdb = [0u8; 6];
        cdb[0] = 0x1E;
        cdb[4] = 1;
        assert_eq!(spc.prepare(&permit, ctx(Direction::None, 0), &cdb), Ok(()));
        assert!(matches!(
            spc.poll(&permit, Feedback::begin(), &mut [0u8; 0]),
            PollStep::Complete(Completion::Good)
        ));
        assert!(spc.is_prevented());
        cdb[4] = 0;
        spc.prepare(&permit, ctx(Direction::None, 0), &cdb)
            .expect("clear");
        assert!(matches!(
            spc.poll(&permit, Feedback::begin(), &mut [0u8; 0]),
            PollStep::Io(StorageOp::Sync { resource: 0 })
        ));
        assert!(spc.is_prevented(), "lock stays until the Sync completes");
        assert!(matches!(
            spc.poll(
                &permit,
                Feedback::io_done(IoReceipt::test(0, None, Effect::Known)),
                &mut [0u8; 0]
            ),
            PollStep::Complete(Completion::Good)
        ));
        assert!(!spc.is_prevented());
        // 10b/11b are treated as prevent on a non-changer (documented
        // deviation from SPC-3 Table 119).
        cdb[4] = 2;
        spc.prepare(&permit, ctx(Direction::None, 0), &cdb)
            .expect("2 = prevent");
        assert!(spc.is_prevented());
    }

    struct MmcDevice(BlockDevice);

    impl Device for MmcDevice {
        type Medium = NoMedium;
        fn removal_encoding(&self) -> RemovalEncoding {
            RemovalEncoding::Mmc
        }
        fn prepare(
            &mut self,
            p: &CommandPermit,
            c: CommandContext,
            cdb: &[u8],
        ) -> Result<(), Completion> {
            self.0.prepare(p, c, cdb)
        }
        fn active(&self) -> bool {
            self.0.active()
        }
        fn resume(&mut self, p: &CommandPermit) -> Result<(), Completion> {
            self.0.resume(p)
        }
        fn poll<'a>(
            &mut self,
            p: &CommandPermit,
            fb: Feedback,
            data: &'a mut [u8],
        ) -> PollStep<'a> {
            self.0.poll(p, fb, data)
        }
        fn poll_long<'a>(
            &mut self,
            p: &CommandPermit,
            fb: Feedback,
            data: &'a mut [u8],
        ) -> PollStep<'a> {
            self.0.poll_long(p, fb, data)
        }
        fn long_info(&self) -> LongInfo {
            self.0.long_info()
        }
        fn interrupt(
            &mut self,
            p: &CommandPermit,
            r: InterruptReason,
            k: KnownEffects,
        ) -> Result<(), Fault> {
            self.0.interrupt(p, r, k)
        }
        fn finish_delivery(&mut self, p: &CommandPermit, d: Delivery) {
            self.0.finish_delivery(p, d)
        }
        fn take_medium(&mut self, p: &BoundaryPermit) -> Option<NoMedium> {
            self.0.take_medium(p)
        }
        fn install_medium(
            &mut self,
            p: &BoundaryPermit,
            m: NoMedium,
        ) -> Result<(), (NoMedium, Fault)> {
            self.0.install_medium(p, m)
        }
    }

    #[test]
    fn prevent_allow_mmc_four_encodings() {
        let mut spc = Spc::new(MmcDevice(BlockDevice::new(BlockAttrs::new(16, 512))));
        let permit = permit();
        let mut cdb = [0u8; 6];
        cdb[0] = 0x1E;
        let step = |spc: &mut Spc<MmcDevice>, cdb: &[u8]| {
            spc.prepare(&permit, ctx(Direction::None, 0), cdb)
                .expect("prepare");
            match spc.poll(&permit, Feedback::begin(), &mut [0u8; 0]) {
                PollStep::Io(StorageOp::Sync { resource: 0 }) => {
                    assert!(matches!(
                        spc.poll(
                            &permit,
                            Feedback::io_done(IoReceipt::test(0, None, Effect::Known)),
                            &mut [0u8; 0]
                        ),
                        PollStep::Complete(Completion::Good)
                    ));
                }
                PollStep::Complete(Completion::Good) => {}
                other => panic!("unexpected step {other:?}"),
            }
        };
        cdb[4] = 0b01; // set normal
        step(&mut spc, &cdb);
        assert!(spc.is_prevented());
        assert!(!spc.is_persistent_prevented());
        cdb[4] = 0b10; // clear persistent (normal unchanged)
        step(&mut spc, &cdb);
        assert!(spc.is_prevented());
        assert!(!spc.is_persistent_prevented());
        cdb[4] = 0b11; // set persistent
        step(&mut spc, &cdb);
        assert!(spc.is_persistent_prevented());
        cdb[4] = 0b00; // clear normal (persistent unchanged)
        step(&mut spc, &cdb);
        assert!(!spc.is_prevented());
        assert!(spc.is_persistent_prevented());
    }

    struct CheckDevice;

    impl Device for CheckDevice {
        type Medium = NoMedium;
        fn prepare(
            &mut self,
            _p: &CommandPermit,
            _c: CommandContext,
            _cdb: &[u8],
        ) -> Result<(), Completion> {
            Ok(())
        }
        fn active(&self) -> bool {
            true
        }
        fn resume(&mut self, _p: &CommandPermit) -> Result<(), Completion> {
            Ok(())
        }
        fn poll<'a>(
            &mut self,
            _p: &CommandPermit,
            _fb: Feedback,
            _data: &'a mut [u8],
        ) -> PollStep<'a> {
            PollStep::Complete(Completion::Check(Sense::new(0x05, 0x24, 0x00)))
        }
        fn poll_long<'a>(
            &mut self,
            _p: &CommandPermit,
            _fb: Feedback,
            _data: &'a mut [u8],
        ) -> PollStep<'a> {
            PollStep::Idle
        }
        fn long_info(&self) -> LongInfo {
            LongInfo::IDLE
        }
        fn interrupt(
            &mut self,
            _p: &CommandPermit,
            _r: InterruptReason,
            _k: KnownEffects,
        ) -> Result<(), Fault> {
            Ok(())
        }
        fn finish_delivery(&mut self, _p: &CommandPermit, _d: Delivery) {}
        fn take_medium(&mut self, _p: &BoundaryPermit) -> Option<NoMedium> {
            Some(NoMedium)
        }
        fn install_medium(
            &mut self,
            _p: &BoundaryPermit,
            _m: NoMedium,
        ) -> Result<(), (NoMedium, Fault)> {
            Ok(())
        }
    }

    fn rs_cdb(alloc: u8) -> [u8; 6] {
        let mut cdb = [0u8; 6];
        cdb[0] = 0x03;
        cdb[4] = alloc;
        cdb
    }

    fn capture_check(spc: &mut Spc<CheckDevice>) {
        let permit = permit();
        let mut data = [0u8; 0];
        spc.prepare(&permit, ctx(Direction::None, 0), &[0x28])
            .expect("unknown opcode delegates");
        assert!(matches!(
            spc.poll(&permit, Feedback::begin(), &mut data),
            PollStep::Complete(Completion::Check(_))
        ));
        assert!(spc.saved_sense().is_some());
    }

    #[test]
    fn request_sense_returns_and_clears_the_saved_sense() {
        let mut spc = Spc::new(CheckDevice);
        capture_check(&mut spc);
        let permit = permit();
        let mut data = [0u8; 18];
        assert_eq!(
            spc.prepare(&permit, ctx(Direction::ToHost, 18), &rs_cdb(18)),
            Ok(())
        );
        spc.poll(&permit, Feedback::begin(), &mut data);
        spc.poll(&permit, Feedback::plan_accepted(), &mut data);
        assert_eq!(&data[0..3], &[0x70, 0x00, 0x05]);
        assert_eq!(data[12], 0x24);
        assert!(spc.saved_sense().is_some());
        assert!(matches!(
            spc.poll(
                &permit,
                Feedback::host_sent(HostReceipt::test(18, None)),
                &mut data
            ),
            PollStep::Complete(Completion::Good)
        ));
        assert!(
            spc.saved_sense().is_none(),
            "complete RS consumes the sense"
        );
    }

    #[test]
    fn request_sense_alloc_zero_still_consumes_saved_sense() {
        let mut spc = Spc::new(CheckDevice);
        capture_check(&mut spc);
        let permit = permit();
        let mut data = [0u8; 0];
        assert_eq!(
            spc.prepare(&permit, ctx(Direction::ToHost, 0), &rs_cdb(0)),
            Ok(())
        );
        assert!(matches!(
            spc.poll(&permit, Feedback::begin(), &mut data),
            PollStep::Complete(Completion::Good)
        ));
        assert!(spc.saved_sense().is_none());
    }

    #[test]
    fn request_sense_short_send_keeps_the_saved_sense() {
        let mut spc = Spc::new(CheckDevice);
        capture_check(&mut spc);
        let permit = permit();
        let mut data = [0u8; 18];
        assert_eq!(
            spc.prepare(&permit, ctx(Direction::ToHost, 18), &rs_cdb(18)),
            Ok(())
        );
        spc.poll(&permit, Feedback::begin(), &mut data);
        spc.poll(&permit, Feedback::plan_accepted(), &mut data);
        let _ = spc.poll(
            &permit,
            Feedback::host_sent(HostReceipt::test(10, None)),
            &mut data,
        );
        assert!(
            spc.saved_sense().is_some(),
            "a short send must not consume the sense"
        );
    }

    #[test]
    fn tur_is_delegated_to_the_profile() {
        let mut spc = device();
        let permit = permit();
        assert_eq!(
            spc.prepare(&permit, ctx(Direction::None, 0), &[0x00, 0, 0, 0, 0, 0]),
            Err(Completion::Good)
        );
    }

    #[test]
    fn start_stop_only_stores_the_start_bit() {
        let mut spc = device();
        let permit = permit();
        assert!(spc.is_started());
        let mut cdb = [0u8; 6];
        cdb[0] = 0x1B;
        cdb[4] = 0x00;
        spc.prepare(&permit, ctx(Direction::None, 0), &cdb)
            .expect("stop");
        assert!(matches!(
            spc.poll(&permit, Feedback::begin(), &mut [0u8; 0]),
            PollStep::Complete(Completion::Good)
        ));
        assert!(!spc.is_started());
        cdb[4] = 0x01;
        spc.prepare(&permit, ctx(Direction::None, 0), &cdb)
            .expect("start");
        spc.poll(&permit, Feedback::begin(), &mut [0u8; 0]);
        assert!(spc.is_started());
    }

    #[test]
    fn wrong_direction_is_rejected_before_publish() {
        let mut spc = device();
        let permit = permit();
        assert_eq!(
            spc.prepare(&permit, ctx(Direction::None, 0), &inquiry_cdb(36)),
            Err(Completion::Check(INVALID_FIELD))
        );
    }

    #[test]
    fn host_eject_clears_normal_but_keeps_persistent_prevent() {
        let mut spc = Spc::new(MmcDevice(BlockDevice::new(BlockAttrs::new(16, 512))));
        let permit = permit();
        let mut cdb = [0u8; 6];
        cdb[0] = 0x1E;
        cdb[4] = 0b01; // set normal
        spc.prepare(&permit, ctx(Direction::None, 0), &cdb)
            .expect("set normal");
        spc.poll(&permit, Feedback::begin(), &mut [0u8; 0]);
        cdb[4] = 0b11; // set persistent
        spc.prepare(&permit, ctx(Direction::None, 0), &cdb)
            .expect("set persistent");
        spc.poll(&permit, Feedback::begin(), &mut [0u8; 0]);
        assert!(spc.is_prevented());
        assert!(spc.is_persistent_prevented());
        let boundary = BoundaryPermit::new(TargetId::UNBOUND);
        spc.host_eject_succeeded(&boundary);
        assert!(!spc.is_prevented(), "host eject clears the normal latch");
        assert!(
            spc.is_persistent_prevented(),
            "host eject never clears the persistent latch"
        );
    }

    #[test]
    fn progress_indication_scaling_is_non_zero_and_clamped() {
        // MMC-6 Table 252: value / 65536 x 100%. Any non-zero progress must
        // produce a non-zero 16-bit field; 99 and 100 stay in range and the
        // existing 65535 clamp is respected.
        let mut data = [0u8; 18];
        let mut field = |progress| {
            fill_sense(FORMAT_IN_PROGRESS, Some(progress), &mut data, 18);
            assert_eq!(data[15], 0x80, "SKSV");
            u16::from_be_bytes([data[16], data[17]])
        };
        assert_eq!(field(0), 0);
        assert!(field(1) > 0, "non-zero progress must not encode as zero");
        let at_99 = field(99);
        let at_100 = field(100);
        assert!(at_99 > 0 && at_99 < at_100);
        assert_eq!(at_100, u16::MAX, "100% is the clamped maximum");
        assert_eq!(field(101), u16::MAX, "the clamp still holds");
        assert_eq!(field(200), u16::MAX, "the clamp still holds");

        fill_sense(FORMAT_IN_PROGRESS, None, &mut data, 18);
        assert_eq!(data[15], 0, "no progress => no SKSV");
        assert_eq!(u16::from_be_bytes([data[16], data[17]]), 0);
    }

    #[test]
    fn request_sense_returns_a_prepare_level_check() {
        use crate::core::LBA_OUT_OF_RANGE;
        let mut spc = device();
        let permit = permit();
        let mut cdb = [0u8; 10];
        cdb[0] = 0x28; // READ(10)
        cdb[5] = 16; // LBA 16 == capacity
        cdb[8] = 1;
        assert_eq!(
            spc.prepare(&permit, ctx(Direction::ToHost, 512), &cdb),
            Err(Completion::Check(LBA_OUT_OF_RANGE))
        );
        assert_eq!(spc.saved_sense(), Some(LBA_OUT_OF_RANGE));
        let mut rs = [0u8; 6];
        rs[0] = 0x03;
        rs[4] = 18;
        assert_eq!(
            spc.prepare(&permit, ctx(Direction::ToHost, 18), &rs),
            Ok(())
        );
        let mut data = [0u8; 18];
        spc.poll(&permit, Feedback::begin(), &mut data);
        spc.poll(&permit, Feedback::plan_accepted(), &mut data);
        assert_eq!(data[2], 0x05, "sense key");
        assert_eq!(data[12], 0x21, "ASC LBA out of range");
    }

    #[test]
    fn report_luns_zero_lun_count_is_reported_as_one() {
        let mut spc = device();
        let permit = permit();
        let mut data = [0u8; 16];
        let mut c = ctx(Direction::ToHost, 16);
        c.lun_count = 0;
        assert_eq!(spc.prepare(&permit, c, &report_luns_cdb(16)), Ok(()));
        spc.poll(&permit, Feedback::begin(), &mut data);
        spc.poll(&permit, Feedback::plan_accepted(), &mut data);
        assert_eq!(&data[0..4], &8u32.to_be_bytes());
        assert_eq!(&data[8..16], &[0u8; 8]);
    }

    #[test]
    fn inquiry_rejects_evpd_cmddt_and_page_code() {
        let mut spc = device();
        let permit = permit();
        let mut cdb = inquiry_cdb(36);
        cdb[1] = 0x01; // EVPD
        assert_eq!(
            spc.prepare(&permit, ctx(Direction::ToHost, 36), &cdb),
            Err(Completion::Check(INVALID_FIELD))
        );
        assert_eq!(spc.saved_sense(), Some(INVALID_FIELD));
        let mut cdb = inquiry_cdb(36);
        cdb[1] = 0x02; // CMDDT
        assert_eq!(
            spc.prepare(&permit, ctx(Direction::ToHost, 36), &cdb),
            Err(Completion::Check(INVALID_FIELD))
        );
        let mut cdb = inquiry_cdb(36);
        cdb[2] = 0x80; // page code
        assert_eq!(
            spc.prepare(&permit, ctx(Direction::ToHost, 36), &cdb),
            Err(Completion::Check(INVALID_FIELD))
        );
    }

    struct Foreground(BlockDevice);

    impl SpcProfile for Foreground {
        fn mode_sense(
            &self,
            ten: bool,
            page: u8,
            dbd: bool,
            pc: u8,
            out: Option<&mut [u8]>,
        ) -> Option<usize> {
            self.0.mode_sense(ten, page, dbd, pc, out)
        }

        fn read_capacity(&self) -> Option<Capacity> {
            self.0.read_capacity()
        }

        fn event_status(&self, _class: u8, out: Option<&mut [u8]>) -> Option<usize> {
            if let Some(out) = out {
                let n = 8.min(out.len());
                out[..n].fill(0x5A);
            }
            Some(8)
        }
    }

    impl Device for Foreground {
        type Medium = NoMedium;

        fn spc_profile(&self) -> Option<&dyn SpcProfile> {
            Some(self)
        }

        fn prepare(
            &mut self,
            p: &CommandPermit,
            c: CommandContext,
            cdb: &[u8],
        ) -> Result<(), Completion> {
            self.0.prepare(p, c, cdb)
        }

        fn active(&self) -> bool {
            self.0.active()
        }

        fn resume(&mut self, p: &CommandPermit) -> Result<(), Completion> {
            self.0.resume(p)
        }

        fn poll<'a>(
            &mut self,
            p: &CommandPermit,
            fb: Feedback,
            data: &'a mut [u8],
        ) -> PollStep<'a> {
            self.0.poll(p, fb, data)
        }

        fn poll_long<'a>(
            &mut self,
            p: &CommandPermit,
            fb: Feedback,
            data: &'a mut [u8],
        ) -> PollStep<'a> {
            self.0.poll_long(p, fb, data)
        }

        fn long_info(&self) -> LongInfo {
            LongInfo {
                phase: LongPhase::Foreground,
                write_accessible: false,
                progress: Some(64),
                error: None,
            }
        }

        fn interrupt(
            &mut self,
            p: &CommandPermit,
            r: InterruptReason,
            k: KnownEffects,
        ) -> Result<(), Fault> {
            self.0.interrupt(p, r, k)
        }

        fn finish_delivery(&mut self, p: &CommandPermit, d: Delivery) {
            self.0.finish_delivery(p, d)
        }

        fn take_medium(&mut self, p: &BoundaryPermit) -> Option<NoMedium> {
            self.0.take_medium(p)
        }

        fn install_medium(
            &mut self,
            p: &BoundaryPermit,
            m: NoMedium,
        ) -> Result<(), (NoMedium, Fault)> {
            self.0.install_medium(p, m)
        }
    }

    #[test]
    fn foreground_format_gates_the_medium_queries_only() {
        let mut spc = Spc::new(Foreground(BlockDevice::new(BlockAttrs::new(16, 512))));
        let permit = permit();
        let mut cdb = [0u8; 6];
        cdb[0] = 0x1A;
        cdb[2] = 0x08;
        cdb[4] = 24;
        assert_eq!(
            spc.prepare(&permit, ctx(Direction::ToHost, 24), &cdb),
            Err(Completion::Check(FORMAT_IN_PROGRESS))
        );
        assert_eq!(spc.saved_sense(), Some(FORMAT_IN_PROGRESS));

        let mut cdb = [0u8; 10];
        cdb[0] = 0x25;
        assert_eq!(
            spc.prepare(&permit, ctx(Direction::ToHost, 8), &cdb),
            Err(Completion::Check(FORMAT_IN_PROGRESS))
        );

        // GESN stays admitted while the foreground FORMAT holds the gate.
        let mut cdb = [0u8; 10];
        cdb[0] = 0x4A;
        cdb[1] = 0x01;
        cdb[8] = 8;
        assert_eq!(
            spc.prepare(&permit, ctx(Direction::ToHost, 8), &cdb),
            Ok(())
        );
        let mut data = [0u8; 8];
        match spc.poll(&permit, Feedback::begin(), &mut data) {
            PollStep::Publish(plan) => {
                assert_eq!(plan.direction, Direction::ToHost);
                assert_eq!(plan.bytes, 8);
            }
            other => panic!("expected publish, got {other:?}"),
        }
        match spc.poll(&permit, Feedback::plan_accepted(), &mut data) {
            PollStep::Send(bytes) => assert_eq!(bytes, &[0x5A; 8]),
            other => panic!("expected send, got {other:?}"),
        }
        assert!(matches!(
            spc.poll(
                &permit,
                Feedback::host_sent(HostReceipt::test(8, None)),
                &mut data
            ),
            PollStep::Complete(Completion::Good)
        ));
    }
}
