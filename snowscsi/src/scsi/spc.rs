//! SPC shared command layer: parsing + generic execution (SPC-4 §6).
//!
//! Commands common to every SCSI device type (TEST UNIT READY, INQUIRY,
//! MODE SENSE, REQUEST SENSE, ...) are parsed here and executed against the
//! [`SpcDevice`] capability seam, so block and (later) CD-ROM devices share
//! the same synthesis logic. Device-specific command sets (SBC/MMC) are
//! handled in their own modules and fall through to this one.

use crate::scsi::device::{CommandOutcome, DeviceType};
use crate::scsi::scsi::{asc, cdb_len_from_opcode, cdb_opcode, op, Sense, SenseKey};

/// INQUIRY standard data length (96 bytes total per SPC-3 Table 81, byte0-95).
const INQUIRY_STD_LEN: usize = 96;
/// VPD 0x00 page list length (7 = 4 header + 3 supported pages).
const VPD_PAGE_LIST_LEN: usize = 7;
/// VPD 0x80 unit serial length (4 header + 16 serial).
const VPD_SERIAL_LEN: usize = 20;
/// VPD 0x83 device identification length (4 header + 4 descriptor + 8 NAA-5).
const VPD_ID_LEN: usize = 16;
/// REQUEST SENSE response length (fixed format).
const SENSE_LEN: usize = 18;

/// Static INQUIRY identity: vendor / product / revision identifiers and the
/// four version descriptors (SPC-4 §6.4.1, table 97).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DeviceIdentity {
    pub vendor: [u8; 8],
    pub product: [u8; 16],
    pub revision: [u8; 4],
    pub version_descriptors: [u16; 4],
}

/// Default identity for block devices (device_internal.h `snowscsi_device`).
pub const BLOCK_IDENTITY: DeviceIdentity = DeviceIdentity {
    vendor: *b"SnowSCSI",
    product: *b"Virtual Disk    ",
    revision: *b"0100",
    version_descriptors: [0x00A0, 0x0960, 0x0460, 0x04C0],
};

/// Mode pages for the block device (SPC-4 §7.4): the caching page
/// (PS=0, page 0x08, WCE=0, RCD=0, DRA=1) followed by the vendor-specific
/// page 0x00. PS=0 because the page is never savable (no SP=1 support).
pub const ALL_MODE_PAGES: [u8; 24] = [
    0x08, 18, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x20, 0, 0, 0, 0, 0, 0, 0, /* caching PS=0 */
    0x00, 2, 0x00, 0x08, /* vendor page 0x00 */
];

/// The block device's [`SpcDevice::mode_page`] implementation (also used by
/// the spc.rs unit-test device, and re-used by every other block-shaped
/// device in the snowscsi family). `0x3F` returns every supported page.
pub fn block_mode_page(page: u8) -> Option<&'static [u8]> {
    match page {
        0x08 => Some(&ALL_MODE_PAGES[..20]),
        0x00 => Some(&ALL_MODE_PAGES[20..24]),
        0x3F => Some(&ALL_MODE_PAGES),
        _ => None,
    }
}

/// Device-side effect of a START STOP UNIT hook ([`SpcDevice::start_stop`]).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SpcEffect {
    /// Command completed, GOOD status.
    Good,
    /// Medium removal was prevented → CHECK CONDITION (ILLEGAL REQUEST /
    /// MEDIUM REMOVAL PREVENTED).
    RemovalPrevented,
}

/// Parsed SPC command (SPC-4 §6). Shared by every device type.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SpcCommand {
    TestUnitReady,
    RequestSense {
        alloc: u8,
    },
    Inquiry {
        evpd: bool,
        page: u8,
        alloc: u16,
    },
    ModeSense {
        long: bool,
        page: u8,
        pc: u8,
        alloc: u16,
    },
    ModeSelect {
        long: bool,
        alloc: u16,
    },
    PreventAllow {
        /// Raw 2-bit PREVENT field (SPC-3 Table 119, MMC-6 Table 329).
        prevent: u8,
    },
    StartStop {
        loej: bool,
        load: bool,
    },
    SendDiagnostic {
        self_test_code: u8,
        pf: bool,
        self_test: bool,
        param_list_len: u16,
    },
    ReceiveDiagnosticResults {
        pcv: bool,
        page: u8,
        alloc: u16,
    },
}

/// Parse `cdb` as an SPC command. Returns `None` for opcodes that belong to a
/// device-specific command set (SBC/MMC), are unknown, or are truncated
/// (shorter than the opcode's fixed group length, SPC-4 §7.3) — this
/// function never panics.
pub fn parse_spc(cdb: &[u8]) -> Option<SpcCommand> {
    // Total: gate on the opcode group length before any field access.
    // All SPC opcodes handled here are group 0 (6 bytes) or group 2
    // (10 bytes).
    if cdb.len() < usize::from(cdb_len_from_opcode(cdb_opcode(cdb)?)) {
        return None;
    }
    match cdb_opcode(cdb)? {
        op::TEST_UNIT_READY => Some(SpcCommand::TestUnitReady),
        op::REQUEST_SENSE => Some(SpcCommand::RequestSense { alloc: cdb[4] }),
        op::INQUIRY => Some(SpcCommand::Inquiry {
            evpd: cdb[1] & 0x01 != 0,
            page: cdb[2],
            alloc: (u16::from(cdb[3]) << 8) | u16::from(cdb[4]),
        }),
        op::MODE_SENSE_6 => Some(SpcCommand::ModeSense {
            long: false,
            page: cdb[2] & 0x3F,
            pc: (cdb[2] >> 6) & 0x03,
            alloc: u16::from(cdb[4]),
        }),
        op::MODE_SENSE_10 => Some(SpcCommand::ModeSense {
            long: true,
            page: cdb[2] & 0x3F,
            pc: (cdb[2] >> 6) & 0x03,
            alloc: (u16::from(cdb[7]) << 8) | u16::from(cdb[8]),
        }),
        op::MODE_SELECT_6 => Some(SpcCommand::ModeSelect {
            long: false,
            alloc: u16::from(cdb[4]),
        }),
        op::MODE_SELECT_10 => Some(SpcCommand::ModeSelect {
            long: true,
            alloc: (u16::from(cdb[7]) << 8) | u16::from(cdb[8]),
        }),
        op::PREVENT_ALLOW => Some(SpcCommand::PreventAllow {
            prevent: cdb[4] & 0x03,
        }),
        op::START_STOP_UNIT => Some(SpcCommand::StartStop {
            loej: cdb[4] & 0x02 != 0,
            load: cdb[4] & 0x01 != 0,
        }),
        op::SEND_DIAGNOSTIC => Some(SpcCommand::SendDiagnostic {
            // SPC-3 Table 171: byte1 = Self-Test Code(7:5) | PF(4=0x10) |
            // Reserved(3) | Self-Test(2=0x04) | DevOffL(1) | UnitOffL(0).
            self_test_code: (cdb[1] >> 5) & 0x07,
            pf: cdb[1] & 0x10 != 0,
            self_test: cdb[1] & 0x04 != 0,
            param_list_len: (u16::from(cdb[3]) << 8) | u16::from(cdb[4]),
        }),
        op::RECEIVE_DIAGNOSTIC => Some(SpcCommand::ReceiveDiagnosticResults {
            pcv: cdb[1] & 0x01 != 0,
            page: cdb[2],
            alloc: (u16::from(cdb[3]) << 8) | u16::from(cdb[4]),
        }),
        _ => None,
    }
}

/// Shared SPC capability seam implemented by every SCSI device.
pub trait SpcDevice {
    fn device_type(&self) -> DeviceType;
    fn identity(&self) -> &DeviceIdentity;
    /// Medium type byte returned in MODE SENSE parameter headers.
    /// Multimedia devices may use this to identify the mounted medium.
    fn medium_type(&self) -> u8 {
        0
    }
    /// Capacity-derived identifier used for VPD 0x80 (unit serial) and VPD
    /// 0x83 (NAA-5) synthesis.
    fn id(&self) -> u64;
    /// Bytes of the mode page(s) for `page` (`0x3F` = every supported page).
    /// `None` for unsupported pages.
    fn mode_page(&self, page: u8) -> Option<&[u8]>;
    fn sense(&self) -> &Sense;
    /// Replace the pending sense.
    ///
    /// Single source of truth for "is a sense pending": implementations
    /// storing `Option<Sense>` must map a `key == SenseKey::None` value to
    /// "no pending sense" (`None`) — a cleared sense is never observable
    /// through [`Self::sense`] or the transport's `peek_sense`/`take_sense`.
    fn set_sense(&mut self, sense: Sense);
    fn start_stop(&mut self, loej: bool, load: bool) -> SpcEffect;
    fn set_prevent(&mut self, prevent: bool);
    /// Whether the logical unit accepts PREVENT values 10b/11b (persistent
    /// prevention). SPC-3 Table 119 note (a): those values are valid only
    /// when both RMB=1 and MCHNGR=1 in the standard INQUIRY data; all other
    /// devices shall terminate with CHECK CONDITION / INVALID FIELD IN CDB.
    /// MMC drives override this to `true`: MMC-6 §6.13 defines its own
    /// Persistent/Prevent bits ([SPC-3] "does not apply to MM devices").
    fn persistent_prevent_supported(&self) -> bool {
        false
    }
    /// Whether the medium is write-protected for MODE SENSE WP bit (SPC-3 §7.4.3).
    fn is_write_protected(&self) -> bool {
        false
    }
}

/// Execute one parsed SPC command against `dev`. Synthesized responses are
/// written into `data[0..]` and returned as [`CommandOutcome::OutInline`].
pub fn execute_spc<D: SpcDevice>(dev: &mut D, cmd: SpcCommand, data: &mut [u8]) -> CommandOutcome {
    match cmd {
        SpcCommand::TestUnitReady => CommandOutcome::Status,

        SpcCommand::RequestSense { alloc } => {
            let s = *dev.sense();
            let mut buf = [0u8; SENSE_LEN];
            let n = s.write_fixed(&mut buf);
            let n = n.min(alloc as usize);
            data[0..n].copy_from_slice(&buf[..n]);
            dev.set_sense(Sense::clear());
            CommandOutcome::OutInline { len: n }
        }

        SpcCommand::Inquiry { evpd, page, alloc } => inquiry(dev, evpd, page, alloc, data),

        SpcCommand::ModeSense {
            long,
            page,
            pc,
            alloc,
            ..
        } => {
            // SPC-3 §6.9 PC field (byte2 bits7:6): 00b current, 01b changeable,
            // 10b default, 11b saved. Saved not supported (SP=0 only).
            if pc == 0b11 {
                return cc(
                    dev,
                    SenseKey::IllegalRequest,
                    asc::SAVING_PARAMETERS_NOT_SUPPORTED,
                );
            }
            let Some(page_bytes) = dev.mode_page(page) else {
                return cc(dev, SenseKey::IllegalRequest, asc::INVALID_FIELD);
            };
            let header_len = if long { 8 } else { 4 };
            let total = header_len + page_bytes.len();
            let mode_len = if long { total - 2 } else { total - 1 };
            let mut buf = [0u8; 256];
            if long {
                buf[0] = (mode_len >> 8) as u8;
                buf[1] = mode_len as u8;
            } else {
                buf[0] = mode_len as u8;
            }
            if long {
                buf[2] = dev.medium_type();
                buf[3] = if dev.is_write_protected() { 0x80 } else { 0x00 };
            } else {
                buf[1] = dev.medium_type();
                buf[2] = if dev.is_write_protected() { 0x80 } else { 0x00 };
            }
            if pc == 0b01 {
                // Changeable mask: our pages have no changeable fields (all 0).
                // Preserve page code/length, zero the rest.
                let mut tmp = [0u8; 256];
                tmp[..page_bytes.len()].copy_from_slice(page_bytes);
                let mut p = 0usize;
                while p + 2 <= page_bytes.len() {
                    let len = tmp[p + 1] as usize;
                    for b in &mut tmp[p + 2..p + 2 + len] {
                        *b = 0;
                    }
                    p += 2 + len;
                }
                buf[header_len..total].copy_from_slice(&tmp[..page_bytes.len()]);
            } else {
                buf[header_len..total].copy_from_slice(page_bytes);
            }
            let n = total.min(alloc as usize);
            data[0..n].copy_from_slice(&buf[..n]);
            CommandOutcome::OutInline { len: n }
        }

        SpcCommand::ModeSelect { long: _, alloc } => {
            if alloc == 0 {
                return CommandOutcome::Status;
            }
            let expected = alloc as usize;
            CommandOutcome::InParam {
                expected_len: expected,
            }
        }

        SpcCommand::PreventAllow { prevent } => {
            // SPC-3 Table 119 note (a): PREVENT 10b/11b are valid only for
            // RMB=1 AND MCHNGR=1 devices. Our disks are neither removable
            // nor changers → reject; MMC drives opt in with their own bits.
            if prevent & 0x02 != 0 && !dev.persistent_prevent_supported() {
                return cc(dev, SenseKey::IllegalRequest, asc::INVALID_FIELD);
            }
            // Removal is prevented for PREVENT fields 01b and 11b only
            // (SPC-3 §6.13; MMC-6 Table 329: Prevent bit set → Locked).
            dev.set_prevent(prevent & 0x01 != 0);
            CommandOutcome::Status
        }

        SpcCommand::StartStop { loej, load } => match dev.start_stop(loej, load) {
            SpcEffect::Good => CommandOutcome::Status,
            SpcEffect::RemovalPrevented => {
                // MEDIUM REMOVAL PREVENTED is ASC 53h / ASCQ 02h; ASCQ 00h
                // would decode as MEDIA LOAD OR EJECT FAILED (SPC-4 §4.5.6).
                cc_q(
                    dev,
                    SenseKey::IllegalRequest,
                    asc::MEDIUM_REMOVAL_PREVENTED,
                    asc::MEDIUM_REMOVAL_PREVENTED_ASCQ,
                )
            }
        },

        // SPC-3 Table 171: byte1 = Self-Test Code(7:5) | PF(4=0x10) |
        // Reserved(3) | Self-Test(2=0x04) | DevOffL(1) | UnitOffL(0).
        // §6.28: support default self-test (SELFTEST=1, param len 0) at minimum.
        SpcCommand::SendDiagnostic {
            self_test_code,
            pf,
            self_test,
            param_list_len,
        } => {
            if self_test_code != 0 {
                // Unsupported self-test code (only 000b default is supported).
                cc(dev, SenseKey::IllegalRequest, asc::INVALID_FIELD)
            } else if self_test && param_list_len == 0 {
                // Default self-test (§6.28 minimum requirement).
                CommandOutcome::Status
            } else if pf && !self_test {
                // PF bit set, no self-test (vendor-specific diagnostic).
                CommandOutcome::Status
            } else {
                cc(dev, SenseKey::IllegalRequest, asc::INVALID_FIELD)
            }
        }

        SpcCommand::ReceiveDiagnosticResults { pcv, page, alloc } => {
            if !pcv {
                // Vendor-specific: no diagnostic parameter data buffered from
                // SEND DIAGNOSTIC (SPC-3 §6.18). Return a zero header.
                let n = 4.min(alloc as usize);
                data[0..n].fill(0);
                return CommandOutcome::OutInline { len: n };
            }
            if page != 0 {
                // Only page 00h (Supported Diagnostic Pages) is implemented
                // (SPC-3 §7.1, Table 196).
                return cc(dev, SenseKey::IllegalRequest, asc::INVALID_FIELD);
            }
            // Supported pages list: page 00h first, ascending (Table 196).
            // Page length = 1 (only page 00h). Total 5 bytes.
            const SUPPORTED: [u8; 5] = [0x00, 0x00, 0x00, 0x01, 0x00];
            let n = SUPPORTED.len().min(alloc as usize);
            data[0..n].copy_from_slice(&SUPPORTED[..n]);
            CommandOutcome::OutInline { len: n }
        }
    }
}

/// INQUIRY handler: standard data and VPD pages 0x00/0x80/0x83 (SPC-4 §6.4).
fn inquiry<D: SpcDevice>(
    dev: &mut D,
    evpd: bool,
    page: u8,
    alloc: u16,
    data: &mut [u8],
) -> CommandOutcome {
    if evpd {
        let dt = dev.device_type();
        let data_out: &[u8] = match page {
            0x00 => {
                let mut buf = [0u8; VPD_PAGE_LIST_LEN];
                buf[0] = dt.pdt();
                buf[3] = 3;
                buf[4] = 0x00;
                buf[5] = 0x80;
                buf[6] = 0x83;
                data[0..VPD_PAGE_LIST_LEN].copy_from_slice(&buf);
                &data[0..VPD_PAGE_LIST_LEN]
            }
            0x80 => {
                let mut buf = [0u8; VPD_SERIAL_LEN];
                buf[0] = dt.pdt();
                buf[1] = 0x80;
                buf[3] = 16;
                let id = dev.id();
                buf[4..8].copy_from_slice(b"SNOW");
                let hex = format_hex16(id);
                buf[8..20].copy_from_slice(&hex[4..16]);
                data[0..VPD_SERIAL_LEN].copy_from_slice(&buf);
                &data[0..VPD_SERIAL_LEN]
            }
            0x83 => {
                let mut buf = [0u8; VPD_ID_LEN];
                buf[0] = dt.pdt();
                buf[1] = 0x83;
                buf[3] = 12;
                buf[4] = 0x01; /* CODE SET = binary */
                buf[5] = 0x03; /* designator type = NAA */
                buf[7] = 8;
                let id = 0x5000_0000_0000_0000u64 | (dev.id() & 0x0FFF_FFFF_FFFF_FFFF);
                buf[8..16].copy_from_slice(&id.to_be_bytes());
                data[0..VPD_ID_LEN].copy_from_slice(&buf);
                &data[0..VPD_ID_LEN]
            }
            _ => return cc(dev, SenseKey::IllegalRequest, asc::INVALID_FIELD),
        };
        let n = data_out.len().min(alloc as usize);
        CommandOutcome::OutInline { len: n }
    } else {
        if page != 0 {
            return cc(dev, SenseKey::IllegalRequest, asc::INVALID_FIELD);
        }
        let dt = dev.device_type();
        let idn = dev.identity();
        let mut buf = [0u8; INQUIRY_STD_LEN];
        buf[0] = dt.pdt();
        if dt == DeviceType::Cdrom {
            buf[1] = 0x80; /* removable */
        }
        buf[2] = 0x06; /* SPC-4 (分歧2, was 0x05) */
        buf[3] = 0x02; /* response data format */
        buf[4] = (INQUIRY_STD_LEN as u8) - 5; /* additional length: bytes after byte 4 */
        buf[6] = 0x80; /* BQue=1 (Basic task mgmt, CmdQue=0) */
        buf[7] = 0x00; /* CmdQue=0 */
        buf[8..16].copy_from_slice(&idn.vendor);
        buf[16..32].copy_from_slice(&idn.product);
        buf[32..36].copy_from_slice(&idn.revision);
        for (i, d) in idn.version_descriptors.iter().enumerate() {
            buf[58 + 2 * i] = (d >> 8) as u8;
            buf[59 + 2 * i] = (d & 0xFF) as u8;
        }
        let n = INQUIRY_STD_LEN.min(alloc as usize);
        data[0..n].copy_from_slice(&buf[..n]);
        CommandOutcome::OutInline { len: n }
    }
}

/// Set sense and return CHECK CONDITION (ASCQ 0).
fn cc<D: SpcDevice>(dev: &mut D, key: SenseKey, asc: u8) -> CommandOutcome {
    cc_q(dev, key, asc, 0)
}

/// Set sense with an explicit ASCQ and return CHECK CONDITION.
fn cc_q<D: SpcDevice>(dev: &mut D, key: SenseKey, asc: u8, ascq: u8) -> CommandOutcome {
    dev.set_sense(Sense::new(key, asc, ascq));
    CommandOutcome::CheckCondition
}

/// Format a u64 as 16 uppercase hex digits (VPD 0x80 serial).
fn format_hex16(v: u64) -> [u8; 16] {
    const HEX: &[u8; 16] = b"0123456789ABCDEF";
    let mut out = [0u8; 16];
    let mut x = v;
    for i in (0..16).rev() {
        out[i] = HEX[(x & 0xF) as usize];
        x >>= 4;
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::scsi::device::{CommandOutcome, DeviceType};
    use crate::scsi::scsi::op;

    /// Minimal test device implementing the SPC capability seam.
    struct TestDev {
        sense: Sense,
        prevent: bool,
        id: u64,
        start_stop_effect: SpcEffect,
    }

    impl TestDev {
        fn new() -> Self {
            Self {
                sense: Sense::clear(),
                prevent: false,
                id: 0x0010_0000,
                start_stop_effect: SpcEffect::Good,
            }
        }
    }

    impl SpcDevice for TestDev {
        fn device_type(&self) -> DeviceType {
            DeviceType::Block
        }
        fn identity(&self) -> &DeviceIdentity {
            &BLOCK_IDENTITY
        }
        fn id(&self) -> u64 {
            self.id
        }
        fn mode_page(&self, page: u8) -> Option<&[u8]> {
            block_mode_page(page)
        }
        fn sense(&self) -> &Sense {
            &self.sense
        }
        fn set_sense(&mut self, sense: Sense) {
            self.sense = sense;
        }
        fn start_stop(&mut self, _loej: bool, _load: bool) -> SpcEffect {
            self.start_stop_effect
        }
        fn set_prevent(&mut self, prevent: bool) {
            self.prevent = prevent;
        }
    }

    fn work() -> [u8; crate::MIN_DATA_LEN] {
        [0u8; crate::MIN_DATA_LEN]
    }

    /// Extract the DataIn payload, returning the number of bytes transferred.
    fn data_in(outcome: CommandOutcome, work: &[u8], buf: &mut [u8]) -> usize {
        match outcome {
            CommandOutcome::OutInline { len } => {
                assert!(len <= buf.len());
                let n = len;
                buf[..n].copy_from_slice(&work[..n]);
                n
            }
            _ => panic!("expected OutInline"),
        }
    }

    fn run(dev: &mut TestDev, cdb: &[u8], work: &mut [u8]) -> CommandOutcome {
        execute_spc(dev, parse_spc(cdb).unwrap(), work)
    }

    /// Run a command that yields Status or CheckCondition (no borrowed
    /// payload) and return a copy of the outcome.
    fn run_static(dev: &mut TestDev, cdb: &[u8]) -> CommandOutcome {
        let mut w = work();
        match run(dev, cdb, &mut w) {
            CommandOutcome::Status => CommandOutcome::Status,
            CommandOutcome::CheckCondition => CommandOutcome::CheckCondition,
            other => panic!("expected Status or CheckCondition, got {other:?}"),
        }
    }

    /// Run a DataIn command and copy the payload into `buf`.
    fn run_data(dev: &mut TestDev, cdb: &[u8], buf: &mut [u8]) -> usize {
        let mut w = work();
        let outcome = run(dev, cdb, &mut w);
        data_in(outcome, &w, buf)
    }

    #[test]
    fn parse_identifies_each_spc_command() {
        let mut cdb = [0u8; 6];
        cdb[0] = op::TEST_UNIT_READY;
        assert_eq!(parse_spc(&cdb), Some(SpcCommand::TestUnitReady));

        let mut cdb = [0u8; 6];
        cdb[0] = op::REQUEST_SENSE;
        cdb[4] = 18;
        assert_eq!(
            parse_spc(&cdb),
            Some(SpcCommand::RequestSense { alloc: 18 })
        );

        let mut cdb = [0u8; 6];
        cdb[0] = op::INQUIRY;
        cdb[1] = 0x01; /* EVPD */
        cdb[2] = 0x83;
        cdb[4] = 16;
        assert_eq!(
            parse_spc(&cdb),
            Some(SpcCommand::Inquiry {
                evpd: true,
                page: 0x83,
                alloc: 16
            })
        );

        let mut cdb = [0u8; 10];
        cdb[0] = op::MODE_SENSE_10;
        cdb[2] = 0x3F;
        cdb[8] = 32;
        assert_eq!(
            parse_spc(&cdb),
            Some(SpcCommand::ModeSense {
                long: true,
                page: 0x3F,
                pc: 0,
                alloc: 32,
            })
        );

        let mut cdb = [0u8; 6];
        cdb[0] = op::MODE_SELECT_6;
        cdb[4] = 8;
        assert_eq!(
            parse_spc(&cdb),
            Some(SpcCommand::ModeSelect {
                long: false,
                alloc: 8
            })
        );

        let mut cdb = [0u8; 6];
        cdb[0] = op::PREVENT_ALLOW;
        cdb[4] = 0x02;
        assert_eq!(
            parse_spc(&cdb),
            Some(SpcCommand::PreventAllow { prevent: 0x02 })
        );

        let mut cdb = [0u8; 6];
        cdb[0] = op::START_STOP_UNIT;
        cdb[4] = 0x02; /* LoEj=1, Load=0 */
        assert_eq!(
            parse_spc(&cdb),
            Some(SpcCommand::StartStop {
                loej: true,
                load: false
            })
        );

        let mut cdb = [0u8; 6];
        cdb[0] = op::SEND_DIAGNOSTIC;
        // SPC-3 Table 171: PF=0x10 (bit 4), SELFTEST=0x04 (bit 2).
        cdb[1] = 0x14; /* PF=1, SELFTEST=1 */
        cdb[4] = 4;
        assert_eq!(
            parse_spc(&cdb),
            Some(SpcCommand::SendDiagnostic {
                self_test_code: 0,
                pf: true,
                self_test: true,
                param_list_len: 4
            })
        );

        let mut cdb = [0u8; 6];
        cdb[0] = op::RECEIVE_DIAGNOSTIC;
        cdb[1] = 0x01; /* PCV=1 */
        cdb[2] = 0x00; /* page 00h */
        cdb[4] = 16;
        assert_eq!(
            parse_spc(&cdb),
            Some(SpcCommand::ReceiveDiagnosticResults {
                pcv: true,
                page: 0x00,
                alloc: 16
            })
        );
    }

    #[test]
    fn parse_returns_none_for_sbc_and_unknown_opcodes() {
        assert_eq!(parse_spc(&[op::READ_10; 10]), None);
        assert_eq!(parse_spc(&[op::READ_CAPACITY_10; 10]), None);
        assert_eq!(parse_spc(&[op::SYNCHRONIZE_CACHE_10; 10]), None);
        assert_eq!(parse_spc(&[0xFF; 6]), None);
    }

    #[test]
    fn execute_test_unit_ready() {
        let mut dev = TestDev::new();
        let cdb = [op::TEST_UNIT_READY; 6];
        assert_eq!(run_static(&mut dev, &cdb), CommandOutcome::Status);
    }

    #[test]
    fn execute_request_sense_reports_and_is_cleared_by_caller() {
        let mut dev = TestDev::new();
        dev.sense = Sense::new(SenseKey::IllegalRequest, asc::INVALID_COMMAND, 0);
        let mut cdb = [0u8; 6];
        cdb[0] = op::REQUEST_SENSE;
        cdb[4] = 18;
        let mut buf = [0u8; 18];
        let n = run_data(&mut dev, &cdb, &mut buf);
        assert_eq!(n, 18);
        assert_eq!(buf[0], 0x70);
        assert_eq!(buf[2], 0x05);
        assert_eq!(buf[12], asc::INVALID_COMMAND);
    }

    #[test]
    fn execute_inquiry_standard() {
        let mut dev = TestDev::new();
        let mut cdb = [0u8; 6];
        cdb[0] = op::INQUIRY;
        cdb[4] = 96;
        let mut buf = [0u8; 96];
        let n = run_data(&mut dev, &cdb, &mut buf);
        assert_eq!(n, 96);
        assert_eq!(buf[0], 0x00); /* PDT = disk */
        assert_eq!(buf[1], 0x00); /* not removable */
        assert_eq!(buf[2], 0x06); /* SPC-4 */
        assert_eq!(buf[4], 91); /* additional length: 96-5 = 91 */
        assert_eq!(buf[6], 0x80); /* BQue=1 (Basic) */
        assert_eq!(buf[7], 0x00); /* CmdQue=0 */
        assert_eq!(&buf[8..16], b"SnowSCSI");
        assert_eq!(&buf[16..32], b"Virtual Disk    ");
        assert_eq!(&buf[32..36], b"0100");
        assert_eq!(
            &buf[58..66],
            &[0x00, 0xA0, 0x09, 0x60, 0x04, 0x60, 0x04, 0xC0]
        );
    }

    #[test]
    fn execute_inquiry_standard_page_nonzero_rejected() {
        let mut dev = TestDev::new();
        let mut cdb = [0u8; 6];
        cdb[0] = op::INQUIRY;
        cdb[2] = 0x01;
        cdb[4] = 96;
        let outcome = run_static(&mut dev, &cdb);
        assert_eq!(outcome, CommandOutcome::CheckCondition);
        assert_eq!(dev.sense.key, SenseKey::IllegalRequest);
        assert_eq!(dev.sense.asc, asc::INVALID_FIELD);
    }

    #[test]
    fn execute_inquiry_vpd_pages() {
        let mut dev = TestDev::new();

        let mut cdb = [0u8; 6];
        cdb[0] = op::INQUIRY;
        cdb[1] = 0x01;
        cdb[2] = 0x00;
        cdb[4] = 7;
        let mut buf = [0u8; 7];
        run_data(&mut dev, &cdb, &mut buf);
        assert_eq!(&buf[3..7], &[0x03, 0x00, 0x80, 0x83]);

        let mut cdb = [0u8; 6];
        cdb[0] = op::INQUIRY;
        cdb[1] = 0x01;
        cdb[2] = 0x80;
        cdb[4] = 20;
        let mut buf = [0u8; 20];
        run_data(&mut dev, &cdb, &mut buf);
        assert_eq!(buf[1], 0x80);
        assert_eq!(buf[3], 16);
        assert_eq!(&buf[4..8], b"SNOW");
        assert_eq!(&buf[8..12], b"0000"); /* hex(0x00100000)[4..8] = "0000" */

        let mut cdb = [0u8; 6];
        cdb[0] = op::INQUIRY;
        cdb[1] = 0x01;
        cdb[2] = 0x83;
        cdb[4] = 16;
        let mut buf = [0u8; 16];
        run_data(&mut dev, &cdb, &mut buf);
        assert_eq!(buf[1], 0x83);
        assert_eq!(buf[4], 0x01); /* CODE SET binary */
        assert_eq!(buf[5], 0x03); /* NAA */
        assert_eq!(buf[8], 0x50); /* NAA-5 prefix (IEEE Registered) */
    }

    #[test]
    fn execute_inquiry_vpd_unsupported_page_rejected() {
        let mut dev = TestDev::new();
        let mut cdb = [0u8; 6];
        cdb[0] = op::INQUIRY;
        cdb[1] = 0x01;
        cdb[2] = 0xFF;
        cdb[4] = 96;
        let outcome = run_static(&mut dev, &cdb);
        assert_eq!(outcome, CommandOutcome::CheckCondition);
        assert_eq!(dev.sense.key, SenseKey::IllegalRequest);
        assert_eq!(dev.sense.asc, asc::INVALID_FIELD);
    }

    #[test]
    fn execute_mode_sense_6_caching_page() {
        let mut dev = TestDev::new();
        let mut cdb = [0u8; 6];
        cdb[0] = op::MODE_SENSE_6;
        cdb[2] = 0x08;
        cdb[4] = 32;
        let mut buf = [0u8; 32];
        let n = run_data(&mut dev, &cdb, &mut buf);
        assert_eq!(n, 24);
        assert_eq!(buf[0], 23); /* mode data length */
        assert_eq!(buf[4], 0x08); /* PS=0 */
        assert_eq!(buf[5], 18);
        assert_eq!(buf[16], 0x20); /* DRA=1 */
    }

    #[test]
    fn execute_mode_sense_6_page_3f_concatenates_pages() {
        let mut dev = TestDev::new();
        let mut cdb = [0u8; 6];
        cdb[0] = op::MODE_SENSE_6;
        cdb[2] = 0x3F;
        cdb[4] = 32;
        let mut buf = [0u8; 32];
        let n = run_data(&mut dev, &cdb, &mut buf);
        assert_eq!(n, 28);
        assert_eq!(buf[24], 0x00);
        assert_eq!(buf[27], 0x08);
    }

    #[test]
    fn execute_mode_sense_10() {
        let mut dev = TestDev::new();
        let mut cdb = [0u8; 10];
        cdb[0] = op::MODE_SENSE_10;
        cdb[2] = 0x08;
        cdb[8] = 32;
        let mut buf = [0u8; 32];
        run_data(&mut dev, &cdb, &mut buf);
        let mode_len = (u16::from(buf[0]) << 8) | u16::from(buf[1]);
        assert_eq!(mode_len, 26);
        assert_eq!(buf[8], 0x08); /* PS=0 */
        assert_eq!(buf[9], 18);
    }

    #[test]
    fn execute_mode_sense_unsupported_page_rejected() {
        let mut dev = TestDev::new();
        let mut cdb = [0u8; 6];
        cdb[0] = op::MODE_SENSE_6;
        cdb[2] = 0x01;
        cdb[4] = 32;
        let outcome = run_static(&mut dev, &cdb);
        assert_eq!(outcome, CommandOutcome::CheckCondition);
        assert_eq!(dev.sense.key, SenseKey::IllegalRequest);
        assert_eq!(dev.sense.asc, asc::INVALID_FIELD);
    }

    #[test]
    fn execute_mode_select_is_noop_good() {
        let mut dev = TestDev::new();
        let mut cdb = [0u8; 10];
        cdb[0] = op::MODE_SELECT_10;
        cdb[1] = 0x10; /* PF=1 */
        assert_eq!(run_static(&mut dev, &cdb), CommandOutcome::Status);
    }

    #[test]
    fn execute_prevent_allow_sets_prevent() {
        let mut dev = TestDev::new();
        let mut cdb = [0u8; 6];
        cdb[0] = op::PREVENT_ALLOW;
        cdb[4] = 0x01;
        assert_eq!(run_static(&mut dev, &cdb), CommandOutcome::Status);
        assert!(dev.prevent);
        // Clear with 00b.
        cdb[4] = 0x00;
        assert_eq!(run_static(&mut dev, &cdb), CommandOutcome::Status);
        assert!(!dev.prevent);
    }

    #[test]
    fn execute_prevent_persistent_values_rejected_on_plain_devices() {
        // SPC-3 Table 119 note (a): PREVENT 10b/11b are valid only when
        // RMB=1 AND MCHNGR=1 — plain disks (RMB=0) must reject them.
        let mut dev = TestDev::new();
        let mut cdb = [0u8; 6];
        cdb[0] = op::PREVENT_ALLOW;
        for prevent in [0x02u8, 0x03] {
            cdb[4] = prevent;
            let outcome = run_static(&mut dev, &cdb);
            assert_eq!(outcome, CommandOutcome::CheckCondition);
            assert_eq!(dev.sense.key, SenseKey::IllegalRequest);
            assert_eq!(dev.sense.asc, asc::INVALID_FIELD);
        }
        // Latch must be untouched.
        assert!(!dev.prevent);
    }

    #[test]
    fn execute_start_stop_good_and_removal_prevented() {
        let mut dev = TestDev::new();
        let mut cdb = [0u8; 6];
        cdb[0] = op::START_STOP_UNIT;
        cdb[4] = 0x02; /* eject */
        assert_eq!(run_static(&mut dev, &cdb), CommandOutcome::Status);

        dev.start_stop_effect = SpcEffect::RemovalPrevented;
        let outcome = run_static(&mut dev, &cdb);
        assert_eq!(outcome, CommandOutcome::CheckCondition);
        assert_eq!(dev.sense.key, SenseKey::IllegalRequest);
        assert_eq!(dev.sense.asc, asc::MEDIUM_REMOVAL_PREVENTED);
        assert_eq!(dev.sense.ascq, asc::MEDIUM_REMOVAL_PREVENTED_ASCQ);
    }

    #[test]
    fn execute_send_diagnostic_pf_only_is_good() {
        let mut dev = TestDev::new();
        let mut cdb = [0u8; 6];
        cdb[0] = op::SEND_DIAGNOSTIC;
        // SPC-3 Table 171: PF = bit 4 = 0x10, SELFTEST = bit 2 = 0x04.
        cdb[1] = 0x10; /* PF=1, SELFTEST=0 */
        assert_eq!(run_static(&mut dev, &cdb), CommandOutcome::Status);
    }

    #[test]
    fn execute_send_diagnostic_default_selftest_is_good() {
        // SPC-3 §6.28: default self-test (SELFTEST=1, param len 0) must succeed.
        let mut dev = TestDev::new();
        let mut cdb = [0u8; 6];
        cdb[0] = op::SEND_DIAGNOSTIC;
        cdb[1] = 0x04; /* SELFTEST=1, param len 0 */
        assert_eq!(run_static(&mut dev, &cdb), CommandOutcome::Status);
    }

    #[test]
    fn execute_send_diagnostic_selftest_with_params_rejected() {
        // SELFTEST=1 with non-zero param list len is invalid.
        let mut dev = TestDev::new();
        let mut cdb = [0u8; 6];
        cdb[0] = op::SEND_DIAGNOSTIC;
        cdb[1] = 0x04; /* SELFTEST=1 */
        cdb[3] = 0x02; /* param list len = 512 */
        let outcome = run_static(&mut dev, &cdb);
        assert_eq!(outcome, CommandOutcome::CheckCondition);
        assert_eq!(dev.sense.key, SenseKey::IllegalRequest);
        assert_eq!(dev.sense.asc, asc::INVALID_FIELD);
    }

    #[test]
    fn execute_send_diagnostic_unsupported_code_rejected() {
        // Non-zero self-test code (bits 7:5) is unsupported.
        let mut dev = TestDev::new();
        let mut cdb = [0u8; 6];
        cdb[0] = op::SEND_DIAGNOSTIC;
        cdb[1] = 0x20; /* Self-Test Code = 001b */
        let outcome = run_static(&mut dev, &cdb);
        assert_eq!(outcome, CommandOutcome::CheckCondition);
        assert_eq!(dev.sense.key, SenseKey::IllegalRequest);
        assert_eq!(dev.sense.asc, asc::INVALID_FIELD);
    }

    #[test]
    fn execute_receive_diagnostic_pcv0_returns_empty() {
        let mut dev = TestDev::new();
        let mut cdb = [0u8; 6];
        cdb[0] = op::RECEIVE_DIAGNOSTIC;
        cdb[4] = 16;
        let mut buf = [0u8; 4];
        let n = run_data(&mut dev, &cdb, &mut buf);
        assert_eq!(n, 4);
        assert_eq!(buf, [0u8; 4]);
    }

    #[test]
    fn execute_receive_diagnostic_supported_pages() {
        // PCV=1, page 00h → Supported Diagnostic Pages (SPC-3 Table 196).
        let mut dev = TestDev::new();
        let mut cdb = [0u8; 6];
        cdb[0] = op::RECEIVE_DIAGNOSTIC;
        cdb[1] = 0x01; /* PCV=1 */
        cdb[4] = 16;
        let mut buf = [0u8; 5];
        let n = run_data(&mut dev, &cdb, &mut buf);
        assert_eq!(n, 5);
        assert_eq!(buf, [0x00, 0x00, 0x00, 0x01, 0x00]);
    }

    #[test]
    fn execute_receive_diagnostic_unknown_page_rejected() {
        let mut dev = TestDev::new();
        let mut cdb = [0u8; 6];
        cdb[0] = op::RECEIVE_DIAGNOSTIC;
        cdb[1] = 0x01; /* PCV=1 */
        cdb[2] = 0xFF;
        cdb[4] = 16;
        let outcome = run_static(&mut dev, &cdb);
        assert_eq!(outcome, CommandOutcome::CheckCondition);
        assert_eq!(dev.sense.key, SenseKey::IllegalRequest);
        assert_eq!(dev.sense.asc, asc::INVALID_FIELD);
    }
}
