//! SCSI core: opcodes, sense keys, sense data and CDB field parsing.
//!
//! Field layouts and sense format follow SBC-3 / SPC-4 (see `__REF_SBC3.pdf.md`,
//! `__REF_SPC3.pdf.md`). Sense data uses the fixed format (response code 70h).

/// SCSI operation codes (SPC-4 §7.3, SBC-3 §5).
pub mod op {
    pub const TEST_UNIT_READY: u8 = 0x00;
    pub const FORMAT_UNIT: u8 = 0x04;
    pub const REQUEST_SENSE: u8 = 0x03;
    pub const READ_6: u8 = 0x08;
    pub const WRITE_6: u8 = 0x0A;
    pub const INQUIRY: u8 = 0x12;
    pub const MODE_SELECT_6: u8 = 0x15;
    pub const MODE_SENSE_6: u8 = 0x1A;
    pub const START_STOP_UNIT: u8 = 0x1B;
    pub const RECEIVE_DIAGNOSTIC: u8 = 0x1C;
    pub const SEND_DIAGNOSTIC: u8 = 0x1D;
    pub const PREVENT_ALLOW: u8 = 0x1E;
    pub const READ_CAPACITY_10: u8 = 0x25;
    pub const READ_10: u8 = 0x28;
    pub const SEND_OPC_INFORMATION: u8 = 0x54;
    pub const WRITE_10: u8 = 0x2A;
    pub const SYNCHRONIZE_CACHE_10: u8 = 0x35;
    pub const SYNCHRONIZE_CACHE_16: u8 = 0x91;
    pub const MODE_SELECT_10: u8 = 0x55;
    pub const MODE_SENSE_10: u8 = 0x5A;
    pub const CLOSE_TRACK: u8 = 0x5B;
    pub const READ_16: u8 = 0x88;
    pub const WRITE_16: u8 = 0x8A;
    pub const SERVICE_ACTION_IN: u8 = 0x9E;
    pub const REPORT_LUNS: u8 = 0xA0;
    pub const READ_12: u8 = 0xA8;
    pub const WRITE_12: u8 = 0xAA;

    // MMC-6 (CD/DVD) opcodes.
    pub const READ_FORMAT_CAPACITIES: u8 = 0x23;
    pub const READ_TOC: u8 = 0x43;
    pub const GET_CONFIGURATION: u8 = 0x46;
    pub const READ_DISC_INFORMATION: u8 = 0x51;
    pub const READ_BUFFER_CAPACITY: u8 = 0x5C;
    pub const READ_TRACK_INFORMATION: u8 = 0x52;
    pub const GET_EVENT_STATUS_NOTIFICATION: u8 = 0x4A;
    pub const READ_CD: u8 = 0xBE;
    pub const READ_CD_MSF: u8 = 0xB9;
    pub const GET_PERFORMANCE: u8 = 0xAC;
    pub const READ_DVD_STRUCTURE: u8 = 0xAD;
    pub const SET_CD_SPEED: u8 = 0xBB;
    pub const SET_STREAMING: u8 = 0xB6;
}

/// Additional sense codes (SPC-4 §4.5.6).
pub mod asc {
    pub const WRITE_FAULT: u8 = 0x03;
    pub const NOT_READY: u8 = 0x04;
    pub const UNRECOVERED_READ_ERROR: u8 = 0x11;
    pub const INVALID_COMMAND: u8 = 0x20;
    pub const LBA_OUT_OF_RANGE: u8 = 0x21;
    pub const INVALID_FIELD: u8 = 0x24;
    /// ASC 26h — INVALID FIELD IN PARAMETER LIST (SPC-4 §4.5.6).
    pub const INVALID_FIELD_IN_PARAMETER_LIST: u8 = 0x26;
    pub const LOGICAL_UNIT_NOT_SUPPORTED: u8 = 0x25;
    pub const WRITE_PROTECTED: u8 = 0x27;
    /// ASC 39h — SAVING PARAMETERS NOT SUPPORTED (SPC-3 §6.9 PC=11b).
    pub const SAVING_PARAMETERS_NOT_SUPPORTED: u8 = 0x39;
    /// ASC 29h — POWER ON, RESET, OR BUS DEVICE RESET OCCURRED (SPC-4
    /// §4.5.6), injected as a unit attention after a device reset.
    pub const POWER_ON_RESET: u8 = 0x29;
    /// ASC 28h — NOT READY TO READY CHANGE, MEDIUM MAY HAVE CHANGED
    /// (SPC-4 §4.5.6).  Injected as unit attention after media load/eject.
    pub const MEDIUM_MAY_HAVE_CHANGED: u8 = 0x28;
    pub const MEDIUM_NOT_PRESENT: u8 = 0x3A;
    /// ASCQ 01h for [`MEDIUM_NOT_PRESENT`]: tray is closed but no media
    /// is present.
    pub const MEDIUM_NOT_PRESENT_TRAY_CLOSED: u8 = 0x01;
    /// ASCQ 02h for [`MEDIUM_NOT_PRESENT`]: tray is open.
    pub const MEDIUM_NOT_PRESENT_TRAY_OPEN: u8 = 0x02;
    pub const MEDIUM_REMOVAL_PREVENTED: u8 = 0x53;
    /// ASCQ for [`MEDIUM_REMOVAL_PREVENTED`]. ASC 53h/02h is MEDIUM
    /// REMOVAL PREVENTED; 53h/00h decodes as MEDIA LOAD OR EJECT FAILED.
    pub const MEDIUM_REMOVAL_PREVENTED_ASCQ: u8 = 0x02;
}

/// Sense key (SPC-4 §4.5.6).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
#[repr(u8)]
pub enum SenseKey {
    None = 0x00,
    NotReady = 0x02,
    MediumError = 0x03,
    IllegalRequest = 0x05,
    UnitAttention = 0x06,
    DataProtect = 0x07,
}

/// Fixed format sense data (SPC-4 §4.5.3).
///
/// Maps C `snowscsi_sense_t` (scsi.h): key in byte2, ASC/ASCQ in
/// bytes 12/13 of the fixed format response (response code 70h).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Sense {
    pub key: SenseKey,
    pub asc: u8,
    pub ascq: u8,
}

impl Sense {
    pub const fn new(key: SenseKey, asc: u8, ascq: u8) -> Self {
        Self { key, asc, ascq }
    }

    /// Clear sense (no error).
    pub const fn clear() -> Self {
        Self::new(SenseKey::None, 0, 0)
    }

    /// Serialize fixed format sense data (response code 70h) into `buf`.
    ///
    /// Layout (SPC-4 §4.5.3, table 26): byte0=70h, byte2=sense key,
    /// byte7=additional sense length (0x0A for 18-byte fixed format),
    /// byte12=ASC, byte13=ASCQ, all other bytes zero. Returns the number of
    /// bytes written (min(18, buf.len())), clamped to the caller's buffer.
    /// ASL is always 0x0A per SPC-3 §6.27 ("shall not adjust ... to reflect
    /// truncation").
    pub fn write_fixed(&self, buf: &mut [u8]) -> usize {
        let n = buf.len().min(18);
        buf[..n].fill(0);
        if n > 0 {
            buf[0] = 0x70;
        }
        if n > 2 {
            buf[2] = self.key as u8;
        }
        if n > 7 {
            buf[7] = 0x0A; // ADDITIONAL SENSE LENGTH = 10 (SPC-3 Table 26)
        }
        if n > 12 {
            buf[12] = self.asc;
        }
        if n > 13 {
            buf[13] = self.ascq;
        }
        n
    }
}

/// Fixed CDB length for an opcode group code (SPC-4 §7.3).
///
/// Groups: 0→6, 1/2→10, 4→16, 5→12 bytes; reserved/vendor groups default
/// to 6. This is the canonical mapping — the iSCSI layer uses it to extract
/// the CDB from the BHS (RFC 3720 §10.3.5) and the parser layers use it as
/// a total-ness gate before field access.
pub const fn cdb_len_from_opcode(opcode: u8) -> u8 {
    match (opcode >> 5) & 0x07 {
        0 => 6,
        1 | 2 => 10,
        4 => 16,
        5 => 12,
        _ => 6,
    }
}

/// CDB operation code: byte 0 (SPC-4 §7.3). Returns `None` for an empty
/// CDB.
///
/// Every accessor in this module returns `Option` so the public parsing
/// surface is total — a caller holding a group-length CDB (the iSCSI
/// target always is) can unwrap safely, and short/empty slices yield
/// `None` instead of panicking.
pub fn cdb_opcode(cdb: &[u8]) -> Option<u8> {
    cdb.first().copied()
}

/// READ(6)/WRITE(6) logical block address: byte1 bits 4:0, byte2, byte3.
///
/// LBA is 21 bits: `(cdb[1] & 0x1F) << 16 | cdb[2] << 8 | cdb[3]`
/// (SBC-3 §5.10). Requires at least 4 bytes.
pub fn cdb_lba6(cdb: &[u8]) -> Option<u32> {
    if cdb.len() < 4 {
        return None;
    }
    Some((u32::from(cdb[1] & 0x1F) << 16) | (u32::from(cdb[2]) << 8) | u32::from(cdb[3]))
}

/// READ(6)/WRITE(6) transfer length (byte4). A value of 0 means 256
/// logical blocks (SBC-3 §5.10). Requires at least 5 bytes.
pub fn cdb_transfer_len6(cdb: &[u8]) -> Option<u32> {
    if cdb.len() < 5 {
        return None;
    }
    let raw = cdb[4];
    Some(if raw == 0 { 256 } else { u32::from(raw) })
}

/// READ(10)/WRITE(10) logical block address: bytes 2..=5 (SBC-3 §5.11).
/// Requires at least 6 bytes.
pub fn cdb_lba10(cdb: &[u8]) -> Option<u32> {
    if cdb.len() < 6 {
        return None;
    }
    Some(
        (u32::from(cdb[2]) << 24)
            | (u32::from(cdb[3]) << 16)
            | (u32::from(cdb[4]) << 8)
            | u32::from(cdb[5]),
    )
}

/// READ(10)/WRITE(10) transfer length: bytes 7..=8 (SBC-3 §5.11).
/// Requires at least 9 bytes.
pub fn cdb_transfer_len10(cdb: &[u8]) -> Option<u16> {
    if cdb.len() < 9 {
        return None;
    }
    Some((u16::from(cdb[7]) << 8) | u16::from(cdb[8]))
}

/// READ(12)/WRITE(12) logical block address: bytes 2..=5 (SBC-3 §5.12).
/// Requires at least 6 bytes (the LBA field occupies bytes 2-5).
pub fn cdb_lba12(cdb: &[u8]) -> Option<u32> {
    cdb_lba10(cdb)
}

/// READ(12)/WRITE(12) transfer length: bytes 6..=9 (SBC-3 §5.12).
/// Requires at least 10 bytes.
pub fn cdb_transfer_len12(cdb: &[u8]) -> Option<u32> {
    if cdb.len() < 10 {
        return None;
    }
    Some(
        (u32::from(cdb[6]) << 24)
            | (u32::from(cdb[7]) << 16)
            | (u32::from(cdb[8]) << 8)
            | u32::from(cdb[9]),
    )
}

/// READ(16)/WRITE(16) logical block address: bytes 2..=9 (SBC-3 §5.13).
/// Requires at least 10 bytes.
pub fn cdb_lba16(cdb: &[u8]) -> Option<u64> {
    if cdb.len() < 10 {
        return None;
    }
    Some(
        (u64::from(cdb[2]) << 56)
            | (u64::from(cdb[3]) << 48)
            | (u64::from(cdb[4]) << 40)
            | (u64::from(cdb[5]) << 32)
            | (u64::from(cdb[6]) << 24)
            | (u64::from(cdb[7]) << 16)
            | (u64::from(cdb[8]) << 8)
            | u64::from(cdb[9]),
    )
}

/// READ(16)/WRITE(16) transfer length: bytes 10..=13 (SBC-3 §5.13).
/// Requires at least 14 bytes.
pub fn cdb_transfer_len16(cdb: &[u8]) -> Option<u32> {
    if cdb.len() < 14 {
        return None;
    }
    Some(
        (u32::from(cdb[10]) << 24)
            | (u32::from(cdb[11]) << 16)
            | (u32::from(cdb[12]) << 8)
            | u32::from(cdb[13]),
    )
}

/// `(lba, count)` for a READ(6/10/12/16) opcode, or `None` if `op` is not a
/// READ variant or the CDB is too short to hold the fields. Convenience
/// wrapper for device dispatch (the CD devices).
pub fn cdb_read_args(op: u8, cdb: &[u8]) -> Option<(u64, u32)> {
    match op {
        op::READ_6 => Some((u64::from(cdb_lba6(cdb)?), cdb_transfer_len6(cdb)?)),
        op::READ_10 => Some((
            u64::from(cdb_lba10(cdb)?),
            u32::from(cdb_transfer_len10(cdb)?),
        )),
        op::READ_12 => Some((u64::from(cdb_lba12(cdb)?), cdb_transfer_len12(cdb)?)),
        op::READ_16 => Some((cdb_lba16(cdb)?, cdb_transfer_len16(cdb)?)),
        _ => None,
    }
}

/// `(lba, count)` for a WRITE(6/10/12/16) CDB.
pub fn cdb_write_args(op: u8, cdb: &[u8]) -> Option<(u64, u32)> {
    match op {
        op::WRITE_6 => Some((u64::from(cdb_lba6(cdb)?), cdb_transfer_len6(cdb)?)),
        op::WRITE_10 => Some((
            u64::from(cdb_lba10(cdb)?),
            u32::from(cdb_transfer_len10(cdb)?),
        )),
        op::WRITE_12 => Some((u64::from(cdb_lba12(cdb)?), cdb_transfer_len12(cdb)?)),
        op::WRITE_16 => Some((cdb_lba16(cdb)?, cdb_transfer_len16(cdb)?)),
        _ => None,
    }
}

/// Extract the SCSI command opcode (first byte) from a raw CDB.
///
/// Convenience for protocol layers that need to inspect the opcode *before*
/// passing the CDB to
/// [`ScsiDevice::do_cmd`](crate::scsi::device::ScsiDevice::do_cmd)
/// (e.g. iSCSI REPORT LUNS
/// special-casing, USB BOT invalid-LUN interception).
pub fn opcode_from_cdb(cdb: &[u8]) -> u8 {
    cdb.first().copied().unwrap_or(0)
}

/// Human-readable opcode name.
pub fn opcode_name(opcode: u8) -> &'static str {
    match opcode {
        op::TEST_UNIT_READY => "TEST_UNIT_READY",
        op::REQUEST_SENSE => "REQUEST_SENSE",
        op::READ_6 => "READ_6",
        op::WRITE_6 => "WRITE_6",
        op::INQUIRY => "INQUIRY",
        op::READ_CAPACITY_10 => "READ_CAPACITY_10",
        op::READ_10 => "READ_10",
        op::SEND_OPC_INFORMATION => "SEND_OPC_INFORMATION",
        op::WRITE_10 => "WRITE_10",
        op::READ_16 => "READ_16",
        op::WRITE_16 => "WRITE_16",
        op::SERVICE_ACTION_IN => "SERVICE_ACTION_IN",
        op::READ_12 => "READ_12",
        op::WRITE_12 => "WRITE_12",
        op::MODE_SENSE_6 => "MODE_SENSE_6",
        op::MODE_SENSE_10 => "MODE_SENSE_10",
        op::MODE_SELECT_6 => "MODE_SELECT_6",
        op::MODE_SELECT_10 => "MODE_SELECT_10",
        op::SYNCHRONIZE_CACHE_10 => "SYNCHRONIZE_CACHE_10",
        op::SYNCHRONIZE_CACHE_16 => "SYNCHRONIZE_CACHE_16",
        op::CLOSE_TRACK => "CLOSE_TRACK",
        op::SEND_DIAGNOSTIC => "SEND_DIAGNOSTIC",
        op::RECEIVE_DIAGNOSTIC => "RECEIVE_DIAGNOSTIC",
        op::REPORT_LUNS => "REPORT_LUNS",
        op::PREVENT_ALLOW => "PREVENT_ALLOW",
        op::START_STOP_UNIT => "START_STOP_UNIT",
        op::READ_TOC => "READ_TOC",
        op::READ_FORMAT_CAPACITIES => "READ_FORMAT_CAPACITIES",
        op::GET_CONFIGURATION => "GET_CONFIGURATION",
        op::READ_DISC_INFORMATION => "READ_DISC_INFORMATION",
        op::READ_BUFFER_CAPACITY => "READ_BUFFER_CAPACITY",
        op::GET_PERFORMANCE => "GET_PERFORMANCE",
        op::SET_STREAMING => "SET_STREAMING",
        op::SET_CD_SPEED => "SET_CD_SPEED",
        _ => "UNKNOWN",
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Build a 6-byte CDB (test_block.c `make_cdb6`).
    fn make_cdb6(opcode: u8, lba: u32, transfer_len: u8) -> [u8; 6] {
        let mut cdb = [0u8; 6];
        cdb[0] = opcode;
        cdb[1] = ((lba >> 16) & 0x1F) as u8;
        cdb[2] = (lba >> 8) as u8;
        cdb[3] = lba as u8;
        cdb[4] = transfer_len;
        cdb
    }

    /// Build a 10-byte CDB (test_block.c `make_cdb10`).
    fn make_cdb10(opcode: u8, lba: u32, transfer_len: u16) -> [u8; 10] {
        let mut cdb = [0u8; 10];
        cdb[0] = opcode;
        cdb[2] = (lba >> 24) as u8;
        cdb[3] = (lba >> 16) as u8;
        cdb[4] = (lba >> 8) as u8;
        cdb[5] = lba as u8;
        cdb[7] = (transfer_len >> 8) as u8;
        cdb[8] = transfer_len as u8;
        cdb
    }

    /// Build a 12-byte CDB (test_block.c `make_cdb12`).
    fn make_cdb12(opcode: u8, lba: u32, transfer_len: u32) -> [u8; 12] {
        let mut cdb = [0u8; 12];
        cdb[0] = opcode;
        cdb[2] = (lba >> 24) as u8;
        cdb[3] = (lba >> 16) as u8;
        cdb[4] = (lba >> 8) as u8;
        cdb[5] = lba as u8;
        cdb[6] = (transfer_len >> 24) as u8;
        cdb[7] = (transfer_len >> 16) as u8;
        cdb[8] = (transfer_len >> 8) as u8;
        cdb[9] = transfer_len as u8;
        cdb
    }

    /// Build a 16-byte CDB (test_block.c `make_cdb16`).
    fn make_cdb16(opcode: u8, lba: u64, transfer_len: u32) -> [u8; 16] {
        let mut cdb = [0u8; 16];
        cdb[0] = opcode;
        cdb[2] = (lba >> 56) as u8;
        cdb[3] = (lba >> 48) as u8;
        cdb[4] = (lba >> 40) as u8;
        cdb[5] = (lba >> 32) as u8;
        cdb[6] = (lba >> 24) as u8;
        cdb[7] = (lba >> 16) as u8;
        cdb[8] = (lba >> 8) as u8;
        cdb[9] = lba as u8;
        cdb[10] = (transfer_len >> 24) as u8;
        cdb[11] = (transfer_len >> 16) as u8;
        cdb[12] = (transfer_len >> 8) as u8;
        cdb[13] = transfer_len as u8;
        cdb
    }

    #[test]
    fn cdb6_opcode_lba_transfer_roundtrip() {
        let cdb = make_cdb6(op::READ_6, 0x0012345, 1);
        assert_eq!(cdb_opcode(&cdb), Some(op::READ_6));
        assert_eq!(cdb_lba6(&cdb), Some(0x0012345));
        assert_eq!(cdb_transfer_len6(&cdb), Some(1));
    }

    #[test]
    fn cdb6_lba_masks_upper_bits_of_byte1() {
        let mut cdb = make_cdb6(op::READ_6, 0x1F0000, 0);
        cdb[1] |= 0xE0; /* upper 3 bits are not part of the LBA */
        assert_eq!(cdb_lba6(&cdb), Some(0x1F0000));
    }

    #[test]
    fn cdb6_transfer_len_zero_means_256() {
        let cdb = make_cdb6(op::READ_6, 0, 0);
        assert_eq!(cdb_transfer_len6(&cdb), Some(256));
        let cdb = make_cdb6(op::READ_6, 0, 0xFF);
        assert_eq!(cdb_transfer_len6(&cdb), Some(255));
    }

    #[test]
    fn cdb10_opcode_lba_transfer_roundtrip() {
        let cdb = make_cdb10(op::READ_10, 0x89ABCDEF, 0x1234);
        assert_eq!(cdb_opcode(&cdb), Some(op::READ_10));
        assert_eq!(cdb_lba10(&cdb), Some(0x89ABCDEF));
        assert_eq!(cdb_transfer_len10(&cdb), Some(0x1234));
    }

    #[test]
    fn cdb12_opcode_lba_transfer_roundtrip() {
        let cdb = make_cdb12(op::WRITE_12, 0x89ABCDEF, 0x01020304);
        assert_eq!(cdb_opcode(&cdb), Some(op::WRITE_12));
        assert_eq!(cdb_lba12(&cdb), Some(0x89ABCDEF));
        assert_eq!(cdb_transfer_len12(&cdb), Some(0x01020304));
    }

    #[test]
    fn cdb16_opcode_lba_transfer_roundtrip() {
        let lba: u64 = 0x0123456789ABCDEF;
        let cdb = make_cdb16(op::WRITE_16, lba, 0xDEADBEEF);
        assert_eq!(cdb_opcode(&cdb), Some(op::WRITE_16));
        assert_eq!(cdb_lba16(&cdb), Some(lba));
        assert_eq!(cdb_transfer_len16(&cdb), Some(0xDEADBEEF));
    }

    #[test]
    fn cdb16_lba_full_range() {
        let cdb = make_cdb16(op::READ_16, u64::MAX, 1);
        assert_eq!(cdb_lba16(&cdb), Some(u64::MAX));
    }

    #[test]
    fn field_accessors_are_total_on_empty_and_short_slices() {
        /* Empty CDB: opcode is None, so no other accessor is reachable. */
        assert_eq!(cdb_opcode(&[]), None);
        assert_eq!(cdb_opcode(&[0x28]), Some(0x28));

        /* Short slices: field accessors return None instead of panicking. */
        assert_eq!(cdb_lba6(&[0; 3]), None);
        assert_eq!(cdb_transfer_len6(&[0; 4]), None);
        assert_eq!(cdb_lba10(&[0; 5]), None);
        assert_eq!(cdb_transfer_len10(&[0; 8]), None);
        assert_eq!(cdb_lba12(&[0; 5]), None);
        assert_eq!(cdb_transfer_len12(&[0; 9]), None);
        assert_eq!(cdb_lba16(&[0; 9]), None);
        assert_eq!(cdb_transfer_len16(&[0; 13]), None);

        /* Group-length slices still parse. */
        assert_eq!(cdb_lba6(&[0, 0, 0, 0, 0, 0]), Some(0));
        assert_eq!(cdb_transfer_len10(&[0; 9]), Some(0));
        assert_eq!(cdb_transfer_len12(&[0; 10]), Some(0));
        assert_eq!(cdb_transfer_len16(&[0; 14]), Some(0));
    }

    #[test]
    fn cdb_len_from_opcode_groups() {
        /* Group 0 (000b) → 6 bytes */
        assert_eq!(cdb_len_from_opcode(0x00), 6);
        assert_eq!(cdb_len_from_opcode(0x12), 6);
        /* Group 1 (001b) → 10 bytes */
        assert_eq!(cdb_len_from_opcode(0x28), 10);
        /* Group 2 (010b) → 10 bytes */
        assert_eq!(cdb_len_from_opcode(0x4C), 10);
        /* Group 4 (100b) → 16 bytes */
        assert_eq!(cdb_len_from_opcode(0x8F), 16);
        /* Group 5 (101b) → 12 bytes */
        assert_eq!(cdb_len_from_opcode(0xA0), 12);
        /* Reserved/vendor groups (3, 6, 7) default to 6 */
        assert_eq!(cdb_len_from_opcode(0xE0), 6);
    }

    #[test]
    fn sense_new_clear_and_fixed_format() {
        let s = Sense::new(SenseKey::IllegalRequest, asc::INVALID_COMMAND, 0);
        assert_eq!(s.key, SenseKey::IllegalRequest);
        assert_eq!(s.asc, asc::INVALID_COMMAND);
        assert_eq!(s.ascq, 0);

        let mut buf = [0u8; 18];
        let n = s.write_fixed(&mut buf);
        assert_eq!(n, 18);
        assert_eq!(buf[0], 0x70); /* response code */
        assert_eq!(buf[2], 0x05); /* ILLEGAL REQUEST */
        assert_eq!(buf[7], 10); /* additional sense length = 0x0A (SPC-3 Table 26) */
        assert_eq!(buf[12], asc::INVALID_COMMAND);
        assert_eq!(buf[13], 0);

        assert_eq!(Sense::clear().key, SenseKey::None);
    }

    #[test]
    fn sense_fixed_format_clamps_to_buffer() {
        let s = Sense::new(SenseKey::IllegalRequest, asc::INVALID_FIELD, 0);
        let mut buf = [0u8; 4];
        let n = s.write_fixed(&mut buf);
        assert_eq!(n, 4);
        assert_eq!(buf[0], 0x70);
        assert_eq!(buf[2], 0x05);
    }

    #[test]
    fn opcode_names() {
        assert_eq!(opcode_name(op::TEST_UNIT_READY), "TEST_UNIT_READY");
        assert_eq!(opcode_name(op::SERVICE_ACTION_IN), "SERVICE_ACTION_IN");
        assert_eq!(opcode_name(0xFF), "UNKNOWN");
    }
}
