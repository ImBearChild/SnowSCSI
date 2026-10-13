//! iSCSI PDU encoding/decoding (RFC 3720 §10.x).
//!
//! The 48-byte Basic Header Segment ([`Bhs`]) is shared by every PDU; this
//! module provides field accessors at their RFC 3720 byte offsets, grouped by
//! PDU type. All numbers are big-endian on the wire.
//!
//! Layout references (RFC 3720):
//! - BHS layout: §10.2.1
//! - SCSI Command (CDB from byte 32, CmdSN 24-27, ExpStatSN 28-31): §10.3
//! - SCSI Response (StatSN 24-27, ExpCmdSN 28-31, MaxCmdSN 32-35): §10.4
//! - Task Management Request (Function byte 2): §10.5
//! - Task Management Response (Response byte 2): §10.6
//! - Data-In / Data-Out (TTT 20-23, DataSN 36-39, BufferOffset 40-43): §10.7
//! - R2T (TTT 20-23, R2TSN 36-39, BufferOffset 40-43, DesiredLen 44-47): §10.8
//! - Login Request (ISID 8-11, TSIH 12-13, CID 20-21, CSG/NSG/T bit byte 1): §10.12
//! - Login Response (Status-Class 36, Status-Detail 37; bytes 20-23 Reserved): §10.13
//! - Reject (Reason byte 2): §10.17
//!
//! negotiates HeaderDigest/DataDigest=None; no CRC32C is implemented.

use core::ops::Index;

/// Basic Header Segment length in bytes (RFC 3720 §10.2.1).
pub const BHS_SIZE: usize = 48;

/// Largest data segment length negotiated (RFC 3720 §10.2.1.6).
pub const MAX_DATA_SEGMENT: u32 = 8192;

/// iSCSI PDU opcodes (RFC 3720 §10.2.1.2).
pub mod op {
    pub const NOP_OUT: u8 = 0x00;
    pub const SCSI_CMD: u8 = 0x01;
    pub const SCSI_TASK_REQ: u8 = 0x02;
    pub const LOGIN_REQ: u8 = 0x03;
    pub const TEXT_REQ: u8 = 0x04;
    pub const SCSI_DATA_OUT: u8 = 0x05;
    pub const LOGOUT_REQ: u8 = 0x06;
    pub const NOP_IN: u8 = 0x20;
    pub const SCSI_RESP: u8 = 0x21;
    pub const SCSI_TASK_RESP: u8 = 0x22;
    pub const LOGIN_RESP: u8 = 0x23;
    pub const TEXT_RESP: u8 = 0x24;
    pub const SCSI_DATA_IN: u8 = 0x25;
    pub const LOGOUT_RESP: u8 = 0x26;
    pub const R2T: u8 = 0x31;
    pub const REJECT: u8 = 0x3F;
}

/// Opcode-specific flag bits and shift counts (byte 1).
pub mod flag {
    /// T (Transit) bit, byte 1 bit 7 — Login PDUs (RFC 3720 §10.12).
    pub const T_BIT: u8 = 0x80;
    /// F (Final) bit, byte 1 bit 7 — Data PDUs (RFC 3720 §10.7).
    pub const F_BIT: u8 = 0x80;
    /// S (Status) bit, byte 1 bit 0 — Data-In carries status (RFC 3720 §10.7).
    pub const S_BIT: u8 = 0x01;
    /// CSG field position, byte 1 bits 3-2 (RFC 3720 §10.12).
    pub const CSG_SHIFT: u8 = 2;
    /// NSG field position, byte 1 bits 1-0 (RFC 3720 §10.12).
    pub const NSG_SHIFT: u8 = 0;
}

/// SCSI status codes carried in the SCSI Response PDU (RFC 3720 §10.4.2).
pub mod status {
    pub const GOOD: u8 = 0x00;
    pub const CHECK_CONDITION: u8 = 0x02;
}

/// Reject reasons (RFC 3720 §10.17.1).
///
/// Protocol/format errors use `PROTOCOL_ERROR` and field-validation failures
/// use `INVALID_PDU_FIELD`. The legacy C values
/// `0x02` (Data Digest Error) and `0x0A` (Long Operation Reject) are NOT used.
pub mod reject {
    pub const PROTOCOL_ERROR: u8 = 0x04;
    pub const COMMAND_NOT_SUPPORTED: u8 = 0x05;
    pub const INVALID_PDU_FIELD: u8 = 0x09;
}

/// SCSI Task Management function codes (RFC 3720 §10.5.1).
pub mod tmf {
    pub const ABORT_TASK: u8 = 1;
    pub const ABORT_TASK_SET: u8 = 2;
    pub const CLEAR_ACA: u8 = 3;
    pub const CLEAR_TASK_SET: u8 = 4;
    pub const LOGICAL_UNIT_RESET: u8 = 5;
    pub const TARGET_WARM_RESET: u8 = 6;
    pub const TARGET_COLD_RESET: u8 = 7;
    pub const TASK_REASSIGN: u8 = 8;
}

/// SCSI Task Management response codes (RFC 3720 §10.6.1).
pub mod tmf_response {
    pub const COMPLETE: u8 = 0x00;
    pub const NOT_SUPPORTED: u8 = 0x04;
}

/// Login phase stages (RFC 3720 §5.1, §10.12).
pub mod stage {
    pub const SECURITY: u8 = 0;
    pub const OP_PARAM: u8 = 1;
    pub const FULL_FEATURE: u8 = 3;
}

/// 48-byte Basic Header Segment (RFC 3720 §10.2.1).
///
/// Field accessors are grouped by PDU type; all big-endian multi-byte fields
/// use their RFC 3720 byte offsets. The struct is a plain byte array — no
/// allocation, callers own the buffer.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Bhs([u8; BHS_SIZE]);

impl Default for Bhs {
    fn default() -> Self {
        Self::new()
    }
}

impl Bhs {
    /// Zero-initialized BHS.
    pub const fn new() -> Self {
        Self([0; BHS_SIZE])
    }

    pub const fn from_bytes(bytes: [u8; BHS_SIZE]) -> Self {
        Self(bytes)
    }

    pub const fn as_bytes(&self) -> &[u8; BHS_SIZE] {
        &self.0
    }

    pub fn as_mut_bytes(&mut self) -> &mut [u8; BHS_SIZE] {
        &mut self.0
    }

    pub fn to_bytes(self) -> [u8; BHS_SIZE] {
        self.0
    }

    // ── Generic fields (all PDUs) ────────────────────────────────

    /// Opcode: byte 0 bits 5-0 (RFC 3720 §10.2.1.2).
    pub fn opcode(&self) -> u8 {
        self.0[0] & 0x3F
    }

    /// Set opcode, preserving the upper two bits (I bit + reserved).
    pub fn set_opcode(&mut self, opcode: u8) {
        self.0[0] = (self.0[0] & 0xC0) | (opcode & 0x3F);
    }

    /// Byte 1 — opcode-specific flags.
    pub fn flags(&self) -> u8 {
        self.0[1]
    }

    pub fn set_flags(&mut self, flags: u8) {
        self.0[1] = flags;
    }

    /// TotalAHSLength, byte 4 (RFC 3720 §10.2.1.5). requires 0.
    pub fn total_ahs_length(&self) -> u8 {
        self.0[4]
    }

    /// DataSegmentLength, bytes 5-7 (24-bit, big-endian) (RFC 3720 §3.1).
    pub fn data_segment_len(&self) -> u32 {
        (u32::from(self.0[5]) << 16) | (u32::from(self.0[6]) << 8) | u32::from(self.0[7])
    }

    /// Set DataSegmentLength without touching byte 4 (TotalAHSLength).
    pub fn set_data_segment_len(&mut self, len: u32) {
        debug_assert!(len <= 0xFF_FFFF, "DataSegmentLength is a 24-bit field");
        self.0[5] = (len >> 16) as u8;
        self.0[6] = (len >> 8) as u8;
        self.0[7] = len as u8;
    }

    /// Initiator Task Tag, bytes 16-19 (RFC 3720 §10.2.1.8).
    pub fn itt(&self) -> u32 {
        get_be32(&self.0[16..20])
    }

    pub fn set_itt(&mut self, itt: u32) {
        put_be32(&mut self.0[16..20], itt);
    }

    /// Single-level LUN: byte 8 = 0, byte 9 = LUN id (RFC 3720 §10.2.1.7).
    pub fn lun(&self) -> u8 {
        self.0[9]
    }

    /// True when the 64-bit LUN field uses single-level peripheral device
    /// addressing (SAM-2 address method 0000b): byte 8 = 0, bytes 10-15 =
    /// 0, LUN id in byte 9. Other encodings (multi-level logical unit,
    /// flat space, extended) are unsupported and rejected as a PDU field
    /// error (RFC 3720 §10.2.1.7).
    pub fn lun_is_single_level(&self) -> bool {
        self.0[8] == 0 && self.0[10..16].iter().all(|&b| b == 0)
    }

    /// Clear the 8-byte LUN field and set the single-level LUN id in byte 9.
    pub fn set_lun(&mut self, lun: u8) {
        self.0[8..16].fill(0);
        self.0[9] = lun;
    }

    // ── Request PDUs: CmdSN / ExpStatSN ──────────────────────────

    /// CmdSN, bytes 24-27 (SCSI Command / TMF / Login / Logout, RFC 3720 §10.3.2).
    pub fn cmd_sn(&self) -> u32 {
        get_be32(&self.0[24..28])
    }

    /// ExpStatSN, bytes 28-31 (SCSI Command / TMF / Login / Logout, §10.3.3).
    pub fn exp_stat_sn(&self) -> u32 {
        get_be32(&self.0[28..32])
    }

    // ── Response PDUs: StatSN / ExpCmdSN / MaxCmdSN ──────────────
    // Same offsets for SCSI Response (§10.4.9-.11), Login Response (§10.13),
    // NOP-In (§10.18), R2T (§10.8), Reject (§10.17), TMF Response (§10.6)
    // and the final (S=1) Data-In (§10.7).

    /// StatSN, bytes 24-27.
    pub fn stat_sn(&self) -> u32 {
        get_be32(&self.0[24..28])
    }

    pub fn set_stat_sn(&mut self, sn: u32) {
        put_be32(&mut self.0[24..28], sn);
    }

    /// ExpCmdSN, bytes 28-31.
    pub fn exp_cmd_sn(&self) -> u32 {
        get_be32(&self.0[28..32])
    }

    pub fn set_exp_cmd_sn(&mut self, sn: u32) {
        put_be32(&mut self.0[28..32], sn);
    }

    /// MaxCmdSN, bytes 32-35.
    pub fn max_cmd_sn(&self) -> u32 {
        get_be32(&self.0[32..36])
    }

    pub fn set_max_cmd_sn(&mut self, sn: u32) {
        put_be32(&mut self.0[32..36], sn);
    }

    // ── Login Request: byte 1 CSG/NSG, T bit; versions; ISID/TSIH/CID ──

    /// CSG, byte 1 bits 3-2 (RFC 3720 §10.12).
    pub fn csg(&self) -> u8 {
        (self.0[1] >> flag::CSG_SHIFT) & 0x03
    }

    /// NSG, byte 1 bits 1-0 (RFC 3720 §10.12).
    pub fn nsg(&self) -> u8 {
        (self.0[1] >> flag::NSG_SHIFT) & 0x03
    }

    pub fn set_nsg(&mut self, nsg: u8) {
        self.0[1] = (self.0[1] & !0x03) | (nsg & 0x03);
    }

    /// T (Transit) bit, byte 1 bit 7 (RFC 3720 §10.12).
    pub fn t_bit(&self) -> bool {
        self.0[1] & flag::T_BIT != 0
    }

    pub fn set_t_bit(&mut self, t: bool) {
        if t {
            self.0[1] |= flag::T_BIT;
        } else {
            self.0[1] &= !flag::T_BIT;
        }
    }

    /// Version-max, byte 2 (RFC 3720 §10.12).
    pub fn version_max(&self) -> u8 {
        self.0[2]
    }

    /// Version-min, byte 3 (RFC 3720 §10.12).
    pub fn version_min(&self) -> u8 {
        self.0[3]
    }

    /// ISID (first 4 bytes), bytes 8-11. The full ISID field spans
    /// bytes 8-13 (6 bytes, RFC 3720 §10.12.5).
    pub fn isid(&self) -> u32 {
        get_be32(&self.0[8..12])
    }

    /// TSIH, bytes 14-15 (RFC 3720 §10.12.3/.13.3).
    ///
    /// The Login Request layout puts ISID at bytes 8-13 and TSIH at
    /// bytes 14-15 — NOT bytes 12-13 (C `do_login` reads `bhs[14..16]`).
    pub fn tsih(&self) -> u16 {
        (u16::from(self.0[14]) << 8) | u16::from(self.0[15])
    }

    /// CID, bytes 20-21 (RFC 3720 §10.12.7).
    ///
    /// Bytes 20-21 per §10.12 — NOT 22-23. There is no
    /// setter: the Login Response keeps bytes 20-23 Reserved (§10.13).
    pub fn cid(&self) -> u16 {
        (u16::from(self.0[20]) << 8) | u16::from(self.0[21])
    }

    // ── Login Response: version-active / status ──────────────────

    /// Version-active, byte 3 (RFC 3720 §10.13.2).
    pub fn version_active(&self) -> u8 {
        self.0[3]
    }

    /// Status-Class, byte 36 (RFC 3720 §10.13.5).
    pub fn status_class(&self) -> u8 {
        self.0[36]
    }

    /// Status-Detail, byte 37 (RFC 3720 §10.13.5).
    pub fn status_detail(&self) -> u8 {
        self.0[37]
    }

    // ── SCSI Command: CDB ────────────────────────────────────────

    /// CDB slice, bytes 32..32+len; len from the CDB opcode group code
    /// (6/10/12/16, RFC 3720 §10.3.5).
    pub fn cdb(&self) -> &[u8] {
        let len = usize::from(cdb_len_from_opcode(self.0[32]));
        &self.0[32..32 + len]
    }

    // ── SCSI Response: status / response ─────────────────────

    /// SCSI status, byte 3 (RFC 3720 §10.4.2).
    pub fn status(&self) -> u8 {
        self.0[3]
    }

    pub fn set_status(&mut self, status: u8) {
        self.0[3] = status;
    }

    /// Response, byte 2 (RFC 3720 §10.4.7). The high-level iSCSI response
    /// for a SCSI Response PDU — 0 = "Command completed at target" (the
    /// only value we emit; Sense data travels in the Data Segment, not
    /// here). Previously mislabeled `set_sense_len`.
    pub fn response(&self) -> u8 {
        self.0[2]
    }

    pub fn set_response(&mut self, response: u8) {
        self.0[2] = response;
    }

    // ── Data-In / Data-Out / R2T: DataSN, Buffer Offset ──────────

    /// DataSN, bytes 36-39 (RFC 3720 §10.7.5).
    pub fn data_sn(&self) -> u32 {
        get_be32(&self.0[36..40])
    }

    pub fn set_data_sn(&mut self, sn: u32) {
        put_be32(&mut self.0[36..40], sn);
    }

    /// Buffer Offset, bytes 40-43 (RFC 3720 §10.7.6).
    pub fn buffer_offset(&self) -> u32 {
        get_be32(&self.0[40..44])
    }

    pub fn set_buffer_offset(&mut self, offset: u32) {
        put_be32(&mut self.0[40..44], offset);
    }

    /// Target Transfer Tag, bytes 20-23 (R2T / Data-Out / Data-In).
    pub fn ttt(&self) -> u32 {
        get_be32(&self.0[20..24])
    }

    pub fn set_ttt(&mut self, ttt: u32) {
        put_be32(&mut self.0[20..24], ttt);
    }

    // ── R2T (RFC 3720 §10.8) ─────────────────────────────────────

    /// R2TSN, bytes 36-39.
    pub fn r2t_sn(&self) -> u32 {
        get_be32(&self.0[36..40])
    }

    pub fn set_r2t_sn(&mut self, sn: u32) {
        put_be32(&mut self.0[36..40], sn);
    }

    /// Desired Data Transfer Length, bytes 44-47 (RFC 3720 §10.8.4).
    pub fn desired_data_len(&self) -> u32 {
        get_be32(&self.0[44..48])
    }

    pub fn set_desired_data_len(&mut self, len: u32) {
        put_be32(&mut self.0[44..48], len);
    }

    // ── Reject (RFC 3720 §10.17) ─────────────────────────────────

    /// Reject Reason, byte 2 (RFC 3720 §10.17.1).
    pub fn reject_reason(&self) -> u8 {
        self.0[2]
    }

    pub fn set_reject_reason(&mut self, reason: u8) {
        self.0[2] = reason;
    }

    // ── Task Management (RFC 3720 §10.5 / §10.6) ─────────────────

    /// TMF Function, byte 2 (RFC 3720 §10.5.1).
    pub fn tmf_function(&self) -> u8 {
        self.0[2] & 0x7F
    }

    /// TMF Response, byte 2 (RFC 3720 §10.6.1).
    pub fn set_tmf_response(&mut self, response: u8) {
        self.0[2] = response;
    }
}

impl Index<usize> for Bhs {
    type Output = u8;

    fn index(&self, index: usize) -> &Self::Output {
        &self.0[index]
    }
}

/// Data Segment Length-derived padding for 4-byte alignment (RFC 3720 §3.1).
///
/// `pad = (4 - ((48 + dsl) & 3)) & 3`; the total PDU length
/// (`48 + dsl + pad`) is always a multiple of 4.
pub const fn pdu_pad_len(data_segment_len: u32) -> u32 {
    (4 - ((48 + data_segment_len) & 3)) & 3
}

/// CDB length derived from the CDB opcode group code (SPC-4 §7.3).
///
/// Canonical definition lives in the SCSI core
/// ([`crate::scsi::scsi::cdb_len_from_opcode`]) so the parser layers share
/// it; this re-export keeps the historical `snowscsi::iscsi::pdu` path.
pub use crate::scsi::scsi::cdb_len_from_opcode;

/// Human-readable name for an iSCSI PDU opcode (RFC 3720 §10.2.1.2).
pub fn iscsi_opcode_name(opcode: u8) -> &'static str {
    match opcode {
        op::NOP_OUT => "NOP_OUT",
        op::SCSI_CMD => "SCSI_CMD",
        op::SCSI_TASK_REQ => "SCSI_TASK_REQ",
        op::LOGIN_REQ => "LOGIN_REQ",
        op::TEXT_REQ => "TEXT_REQ",
        op::SCSI_DATA_OUT => "SCSI_DATA_OUT",
        op::LOGOUT_REQ => "LOGOUT_REQ",
        op::NOP_IN => "NOP_IN",
        op::SCSI_RESP => "SCSI_RESP",
        op::SCSI_TASK_RESP => "SCSI_TASK_RESP",
        op::LOGIN_RESP => "LOGIN_RESP",
        op::TEXT_RESP => "TEXT_RESP",
        op::SCSI_DATA_IN => "SCSI_DATA_IN",
        op::LOGOUT_RESP => "LOGOUT_RESP",
        op::R2T => "R2T",
        op::REJECT => "REJECT",
        _ => "UNKNOWN",
    }
}

fn get_be32(p: &[u8]) -> u32 {
    (u32::from(p[0]) << 24) | (u32::from(p[1]) << 16) | (u32::from(p[2]) << 8) | u32::from(p[3])
}

fn put_be32(p: &mut [u8], v: u32) {
    p[0] = (v >> 24) as u8;
    p[1] = (v >> 16) as u8;
    p[2] = (v >> 8) as u8;
    p[3] = v as u8;
}

#[cfg(test)]
mod tests {
    use super::*;

    fn bhs() -> Bhs {
        Bhs::new()
    }

    #[test]
    fn opcode_roundtrip_and_preserves_upper_bits() {
        let mut b = bhs();
        b.set_opcode(op::SCSI_CMD);
        assert_eq!(b.opcode(), op::SCSI_CMD);

        b.0[0] = 0xC0;
        b.set_opcode(op::LOGIN_REQ);
        assert_eq!(b.opcode(), op::LOGIN_REQ);
        assert_eq!(b.0[0], 0xC3);
    }

    #[test]
    fn flags_roundtrip() {
        let mut b = bhs();
        b.set_flags(0xAB);
        assert_eq!(b.flags(), 0xAB);
        assert_eq!(b.0[1], 0xAB);
    }

    #[test]
    fn data_seg_len_roundtrip() {
        let mut b = bhs();
        b.set_data_segment_len(0x123456);
        assert_eq!(b.data_segment_len(), 0x123456);
        /* RFC 3720 §3.1: DataSegmentLength at bytes 5-7; byte 4 is TotalAHSLength */
        assert_eq!(b.0[4], 0x00);
        assert_eq!(b.0[5], 0x12);
        assert_eq!(b.0[6], 0x34);
        assert_eq!(b.0[7], 0x56);

        b.set_data_segment_len(0);
        assert_eq!(b.data_segment_len(), 0);
    }

    #[test]
    fn itt_roundtrip() {
        let mut b = bhs();
        b.set_itt(0xDEADBEEF);
        assert_eq!(b.itt(), 0xDEADBEEF);
    }

    #[test]
    fn cmd_sn_at_bytes_24_27() {
        let mut b = bhs();
        b.0[24] = 0x00;
        b.0[25] = 0x00;
        b.0[26] = 0x00;
        b.0[27] = 0x05;
        assert_eq!(b.cmd_sn(), 5);
    }

    #[test]
    fn exp_stat_sn_at_bytes_28_31() {
        let mut b = bhs();
        b.0[28] = 0x00;
        b.0[29] = 0x00;
        b.0[30] = 0x00;
        b.0[31] = 0x03;
        assert_eq!(b.exp_stat_sn(), 3);
    }

    #[test]
    fn stat_sn_at_bytes_24_27() {
        let mut b = bhs();
        b.set_stat_sn(42);
        assert_eq!(b.stat_sn(), 42);
        assert_eq!(b.0[24], 0x00);
        assert_eq!(b.0[25], 0x00);
        assert_eq!(b.0[26], 0x00);
        assert_eq!(b.0[27], 0x2A);
    }

    #[test]
    fn exp_cmd_sn_at_bytes_28_31() {
        let mut b = bhs();
        b.set_exp_cmd_sn(99);
        assert_eq!(b.exp_cmd_sn(), 99);
        assert_eq!(b.0[28], 0x00);
        assert_eq!(b.0[29], 0x00);
        assert_eq!(b.0[30], 0x00);
        assert_eq!(b.0[31], 0x63);
    }

    #[test]
    fn max_cmd_sn_at_bytes_32_35() {
        let mut b = bhs();
        b.set_max_cmd_sn(100);
        assert_eq!(b.max_cmd_sn(), 100);
        assert_eq!(b.0[32], 0x00);
        assert_eq!(b.0[33], 0x00);
        assert_eq!(b.0[34], 0x00);
        assert_eq!(b.0[35], 0x64);
    }

    #[test]
    fn login_csg_nsg() {
        let mut b = bhs();
        /* CSG=1 (bits 3-2), NSG=3 (bits 1-0) — RFC 3720 §10.12 */
        b.0[1] = (1 << 2) | 3;
        assert_eq!(b.csg(), 1);
        assert_eq!(b.nsg(), 3);

        b.set_nsg(1);
        assert_eq!(b.nsg(), 1);
        assert_eq!(b.csg(), 1);
    }

    #[test]
    fn t_bit_roundtrip() {
        let mut b = bhs();
        assert!(!b.t_bit());

        b.set_t_bit(true);
        assert!(b.t_bit());
        /* RFC 3720 §10.12: T bit is byte 1, bit 7 */
        assert_eq!(b.0[1] & 0x80, 0x80);
        assert_eq!(b.0[0], 0x00);

        b.set_t_bit(false);
        assert!(!b.t_bit());
        assert_eq!(b.0[1], 0x00);
    }

    #[test]
    fn lun_set_zeroes_byte8_and_upper_lun_bytes() {
        let mut b = bhs();
        b.set_lun(3);
        assert_eq!(b.lun(), 3);
        /* byte 8 = 0 (first-level LUN addressing) */
        assert_eq!(b.0[8], 0x00);
        assert_eq!(b.0[9], 0x03);
        assert_eq!(b.0[10], 0x00);
        assert_eq!(b.0[15], 0x00);
    }

    #[test]
    fn lun_is_single_level_detects_other_address_methods() {
        let mut b = bhs();
        assert!(b.lun_is_single_level());
        b.set_lun(3);
        assert!(b.lun_is_single_level());
        /* SAM-2 logical unit (multi-level) addressing: byte 8 bits 6-3 = 0100b */
        b.0[8] = 0x40;
        assert!(!b.lun_is_single_level());
        b.0[8] = 0x00;
        /* Flat space addressing: byte 8 bits 6-3 = 0010b */
        b.0[8] = 0x20;
        assert!(!b.lun_is_single_level());
        b.0[8] = 0x00;
        /* Reserved high LUN bytes must be zero */
        b.0[10] = 0x01;
        assert!(!b.lun_is_single_level());
        b.0[10] = 0x00;
        b.0[15] = 0xFF;
        assert!(!b.lun_is_single_level());
        b.0[15] = 0x00;
        assert!(b.lun_is_single_level());
    }

    #[test]
    fn cdb_extraction() {
        let mut b = bhs();
        b.set_opcode(op::SCSI_CMD);
        /* cdb[0]=0x28 opcode, cdb[1]=0 reserved,
         * cdb[2-5]=LBA (big-endian, LBA=1), cdb[6]=0 reserved,
         * cdb[7-8]=transfer_len (big-endian, len=1), cdb[9]=0 */
        b.0[32] = 0x28;
        b.0[37] = 0x01;
        b.0[40] = 0x01;

        let cdb = b.cdb();
        assert_eq!(cdb.len(), 10);
        assert_eq!(cdb[0], 0x28);
        assert_eq!(cdb[8], 0x01);
    }

    #[test]
    fn cdb_service_action_in_16() {
        let mut b = bhs();
        b.set_opcode(op::SCSI_CMD);
        /* SERVICE ACTION IN (0x9e) with READ CAPACITY 16 (0x10) */
        b.0[32] = 0x9E;
        b.0[33] = 0x10;
        b.0[45] = 0x20;

        let cdb = b.cdb();
        assert_eq!(cdb.len(), 16);
        assert_eq!(cdb[0], 0x9E);
        assert_eq!(cdb[1], 0x10);
        assert_eq!(cdb[13], 0x20);
    }

    #[test]
    fn scsi_status_at_byte_3() {
        let mut b = bhs();
        b.set_status(status::CHECK_CONDITION);
        assert_eq!(b.status(), status::CHECK_CONDITION);
        assert_eq!(b.0[3], status::CHECK_CONDITION);
    }

    #[test]
    fn response_field_at_byte_2() {
        let mut b = bhs();
        // Byte 2 is the iSCSI Response field, not a sense length — sense
        // data lives in the Data Segment. Regression for the old
        // misleading `set_sense_len` API.
        assert_eq!(b.response(), 0); // Command completed at target
        b.set_response(0);
        assert_eq!(b.0[2], 0);
    }

    #[test]
    fn data_sn_at_bytes_36_39() {
        let mut b = bhs();
        b.set_data_sn(0x12345678);
        assert_eq!(b.data_sn(), 0x12345678);
        assert_eq!(b.0[36], 0x12);
        assert_eq!(b.0[37], 0x34);
        assert_eq!(b.0[38], 0x56);
        assert_eq!(b.0[39], 0x78);
    }

    #[test]
    fn buffer_offset_at_bytes_40_43() {
        let mut b = bhs();
        b.0[40] = 0x00;
        b.0[41] = 0x00;
        b.0[42] = 0x04;
        b.0[43] = 0x00;
        assert_eq!(b.buffer_offset(), 1024);
    }

    #[test]
    fn r2t_fields() {
        let mut b = bhs();
        b.set_r2t_sn(0x0A0B0C0D);
        assert_eq!(b.r2t_sn(), 0x0A0B0C0D);

        b.set_buffer_offset(0x00002000);
        assert_eq!(b.0[40], 0x00);
        assert_eq!(b.0[41], 0x00);
        assert_eq!(b.0[42], 0x20);
        assert_eq!(b.0[43], 0x00);

        b.set_desired_data_len(65536);
        /* Desired Data Transfer Length at bytes 44-47 (RFC 3720 §10.8.4) */
        assert_eq!(b.0[44], 0x00);
        assert_eq!(b.0[45], 0x01);
        assert_eq!(b.0[46], 0x00);
        assert_eq!(b.0[47], 0x00);
    }

    #[test]
    fn ttt_roundtrip() {
        let mut b = bhs();
        b.set_ttt(0xFFFFFFFF);
        assert_eq!(b.ttt(), 0xFFFFFFFF);
        b.set_ttt(0x12345678);
        assert_eq!(b.ttt(), 0x12345678);
    }

    #[test]
    fn reject_reason_at_byte_2() {
        let mut b = bhs();
        b.set_reject_reason(reject::PROTOCOL_ERROR);
        assert_eq!(b.reject_reason(), reject::PROTOCOL_ERROR);
        assert_eq!(b.0[2], reject::PROTOCOL_ERROR);
    }

    #[test]
    fn tmf_function_reads_byte2() {
        let mut b = bhs();
        b.0[2] = tmf::ABORT_TASK;
        assert_eq!(b.tmf_function(), tmf::ABORT_TASK);

        /* byte 2 fully set: bit 7 is outside the 7-bit function field */
        b.0[2] = tmf::LOGICAL_UNIT_RESET | 0x80;
        assert_eq!(b.tmf_function(), tmf::LOGICAL_UNIT_RESET);
    }

    #[test]
    fn tmf_response_set() {
        let mut b = bhs();
        b.set_tmf_response(tmf_response::NOT_SUPPORTED);
        assert_eq!(b.0[2], tmf_response::NOT_SUPPORTED);
    }

    #[test]
    fn data_seg_len_rfc_read() {
        /* Place known bytes at RFC 3720 §3.1 offsets (5-7) — no setter. */
        let mut b = bhs();
        b.0[5] = 0xAB;
        b.0[6] = 0xCD;
        b.0[7] = 0xEF;
        assert_eq!(b.data_segment_len(), 0xABCDEF);
    }

    #[test]
    fn data_seg_len_rfc_write() {
        let mut b = bhs();
        b.set_data_segment_len(0xABCDEF);
        assert_eq!(b.0[4], 0x00);
        assert_eq!(b.0[5], 0xAB);
        assert_eq!(b.0[6], 0xCD);
        assert_eq!(b.0[7], 0xEF);
    }

    #[test]
    fn t_bit_rfc_read() {
        let mut b = bhs();
        b.0[1] = 0x80;
        assert!(b.t_bit());

        b.0[0] = 0x80;
        b.0[1] = 0x00;
        assert!(!b.t_bit());
    }

    #[test]
    fn t_bit_rfc_write() {
        let mut b = bhs();
        b.set_t_bit(true);
        assert_eq!(b.0[1], 0x80);
        assert_eq!(b.0[0], 0x00);

        b.set_t_bit(false);
        assert_eq!(b.0[1], 0x00);
    }

    #[test]
    fn cid_at_bytes_20_21() {
        /* RFC 3720 §10.12: CID at bytes 20-21 — NOT 22-23. */
        let mut b = bhs();
        b.0[20] = 0x12;
        b.0[21] = 0x34;
        assert_eq!(b.cid(), 0x1234);

        /* bytes 22-23 are Reserved and must not be read as part of CID */
        b.0[22] = 0xFF;
        b.0[23] = 0xFF;
        assert_eq!(b.cid(), 0x1234);
    }

    #[test]
    fn login_request_fields() {
        let mut b = bhs();
        b.0[2] = 0x10; /* Version-max */
        b.0[3] = 0x00; /* Version-min */
        b.0[8] = 0x40;
        b.0[9] = 0x00;
        b.0[10] = 0x01;
        b.0[11] = 0x02;
        b.0[14] = 0x00;
        b.0[15] = 0x07;
        assert_eq!(b.version_max(), 0x10);
        assert_eq!(b.version_min(), 0x00);
        assert_eq!(b.isid(), 0x40000102);
        assert_eq!(b.tsih(), 0x0007);

        /* TSIH at bytes 14-15; bytes 12-13 are the tail of the 6-byte ISID */
        b.0[12] = 0xAB;
        b.0[13] = 0xCD;
        assert_eq!(b.tsih(), 0x0007);
    }

    #[test]
    fn login_response_status_class_detail() {
        let mut b = bhs();
        b.set_stat_sn(0);
        b.set_exp_cmd_sn(1);
        b.set_max_cmd_sn(1);
        b.0[36] = 0x00;
        b.0[37] = 0x00;
        assert_eq!(b.stat_sn(), 0);
        assert_eq!(b.exp_cmd_sn(), 1);
        assert_eq!(b.max_cmd_sn(), 1);
        assert_eq!(b.status_class(), 0);
        assert_eq!(b.status_detail(), 0);
    }

    #[test]
    fn data_in_status_fields() {
        /* Final Data-In (S=1): StatSN/ExpCmdSN/MaxCmdSN + DataSN + BO */
        let mut b = bhs();
        b.set_stat_sn(7);
        b.set_exp_cmd_sn(9);
        b.set_max_cmd_sn(9);
        b.set_data_sn(3);
        b.set_buffer_offset(8192);
        assert_eq!(b.stat_sn(), 7);
        assert_eq!(b.exp_cmd_sn(), 9);
        assert_eq!(b.max_cmd_sn(), 9);
        assert_eq!(b.data_sn(), 3);
        assert_eq!(b.buffer_offset(), 8192);
    }

    #[test]
    fn total_ahs_length_read() {
        let mut b = bhs();
        b.0[4] = 0x04;
        assert_eq!(b.total_ahs_length(), 0x04);
    }

    #[test]
    fn pdu_pad_len_multiples_of_four() {
        for dsl in 0..=MAX_DATA_SEGMENT {
            let pad = pdu_pad_len(dsl);
            assert!(pad <= 3);
            assert_eq!((48 + dsl + pad) % 4, 0);
        }
        assert_eq!(pdu_pad_len(8189), 3);
        assert_eq!(pdu_pad_len(8190), 2);
        assert_eq!(pdu_pad_len(8191), 1);
        assert_eq!(pdu_pad_len(8192), 0);
    }

    #[test]
    fn iscsi_opcode_names() {
        assert_eq!(iscsi_opcode_name(op::NOP_OUT), "NOP_OUT");
        assert_eq!(iscsi_opcode_name(op::LOGIN_REQ), "LOGIN_REQ");
        assert_eq!(iscsi_opcode_name(op::R2T), "R2T");
        assert_eq!(iscsi_opcode_name(op::REJECT), "REJECT");
        assert_eq!(iscsi_opcode_name(0x7F), "UNKNOWN");
    }

    #[test]
    fn bhs_index_and_conversion() {
        let mut b = Bhs::from_bytes([0xAA; BHS_SIZE]);
        assert_eq!(b[0], 0xAA);
        assert_eq!(b.as_bytes()[47], 0xAA);
        b.as_mut_bytes()[0] = 0x01;
        assert_eq!(b[0], 0x01);
        assert_eq!(b.to_bytes()[0], 0x01);
        assert_eq!(Bhs::default(), Bhs::new());
    }
}
