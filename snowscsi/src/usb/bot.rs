//! Command Block Wrapper (CBW) / Command Status Wrapper (CSW) encoding and
//! decoding (USB MSC Bulk-Only Transport §5.1 / §5.2).
//!
//! All multi-byte CBW/CSW fields are little endian on the wire; the
//! signatures `"USBC"` / `"USBS"` are read back little endian too.

use crate::usb::{CBW_LEN, CBW_SIGNATURE, CSW_LEN, CSW_SIGNATURE};

/// Data-phase direction carried by a [`Cbw`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub enum BotDir {
    /// Host → device (bulk OUT data phase, direction bit 0).
    DataOut,
    /// Device → host (bulk IN data phase, direction bit 1).
    DataIn,
}

/// Command Block Wrapper (BOT §5.1, 31 bytes, little endian).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Cbw {
    /// `dCBWTag` — echoed verbatim in the associated CSW.
    pub tag: u32,
    /// `dCBWDataTransferLength` — expected data-phase byte count.
    pub data_len: u32,
    /// `bmCBWFlags` bit 7 (ignored by the device when `data_len == 0`).
    pub dir: BotDir,
    /// `bCBWLUN` — addressed logical unit (0-15).
    pub lun: u8,
    /// `CBWCB[16]` — the SCSI command block (only the first `cdb_len`
    /// bytes are significant).
    pub cdb: [u8; 16],
    /// `bCBWCBLength` — valid CDB length (1..=16).
    pub cdb_len: u8,
}

impl Cbw {
    /// Parse a 31-byte raw CBW.
    ///
    /// Returns `None` for an invalid CBW (BOT §6.6.1): a wrong
    /// `dCBWSignature`, `bCBWCBLength` outside 1..=16, or any non-zero
    /// reserved `bmCBWFlags` bit (obsolete bit 6 / reserved bits 5..0,
    /// BOT §5.1).
    pub fn parse(raw: &[u8; CBW_LEN]) -> Option<Cbw> {
        if le32(raw, 0) != CBW_SIGNATURE {
            return None;
        }
        let flags = raw[12];
        if flags & !0x80 != 0 {
            return None;
        }
        let cdb_len = raw[14];
        if cdb_len == 0 || cdb_len > 16 {
            return None;
        }
        let lun_raw = raw[13];
        // BOT §5.1: bCBWLUN is 4 bits (0..15), high nibble reserved (must be 0).
        if lun_raw & 0xF0 != 0 {
            return None;
        }
        let mut cdb = [0u8; 16];
        cdb.copy_from_slice(&raw[15..15 + 16]);
        Some(Cbw {
            tag: le32(raw, 4),
            data_len: le32(raw, 8),
            dir: if flags & 0x80 != 0 {
                BotDir::DataIn
            } else {
                BotDir::DataOut
            },
            lun: lun_raw & 0x0F,
            cdb,
            cdb_len,
        })
    }

    /// The valid CDB bytes (`cdb[..cdb_len]`); the rest of `CBWCB` is
    /// ignored per BOT §5.1.
    pub fn cdb_slice(&self) -> &[u8] {
        &self.cdb[..usize::from(self.cdb_len)]
    }
}

/// CSW status code (BOT §5.2 Table 5.3).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
#[repr(u8)]
pub enum CswStatus {
    /// Command Passed ("good status").
    Passed = 0x00,
    /// Command Failed.
    Failed = 0x01,
    /// Phase Error.
    PhaseError = 0x02,
}

/// Command Status Wrapper (BOT §5.2, 13 bytes, little endian).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Csw {
    /// `dCSWTag` — echoes the associated CBW's tag.
    pub tag: u32,
    /// `dCSWDataResidue` — `dCBWDataTransferLength − actual bytes processed`.
    pub residue: u32,
    /// `bCSWStatus`.
    pub status: CswStatus,
}

impl Csw {
    /// Serialize into a 13-byte CSW buffer.
    pub fn write(&self, out: &mut [u8; CSW_LEN]) {
        out[0..4].copy_from_slice(&CSW_SIGNATURE.to_le_bytes());
        out[4..8].copy_from_slice(&self.tag.to_le_bytes());
        out[8..12].copy_from_slice(&self.residue.to_le_bytes());
        out[12] = self.status as u8;
    }
}

/// Read a little-endian u32 at `off` from a fixed-size raw CBW.
fn le32(raw: &[u8; CBW_LEN], off: usize) -> u32 {
    u32::from_le_bytes([raw[off], raw[off + 1], raw[off + 2], raw[off + 3]])
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Build a raw 31-byte CBW from its logical fields (little endian).
    fn raw_cbw(tag: u32, data_len: u32, flags: u8, lun: u8, cdb: &[u8]) -> [u8; CBW_LEN] {
        let mut raw = [0u8; CBW_LEN];
        raw[0..4].copy_from_slice(&CBW_SIGNATURE.to_le_bytes());
        raw[4..8].copy_from_slice(&tag.to_le_bytes());
        raw[8..12].copy_from_slice(&data_len.to_le_bytes());
        raw[12] = flags;
        raw[13] = lun;
        raw[14] = cdb.len() as u8;
        raw[15..15 + cdb.len().min(16)].copy_from_slice(&cdb[..cdb.len().min(16)]);
        raw
    }

    fn le32_at(b: &[u8], off: usize) -> u32 {
        u32::from_le_bytes([b[off], b[off + 1], b[off + 2], b[off + 3]])
    }

    #[test]
    fn cbw_signature_is_usbc_little_endian() {
        let raw = raw_cbw(0, 0, 0, 0, &[0u8; 6]);
        assert_eq!(&raw[0..4], b"USBC");
        assert!(Cbw::parse(&raw).is_some());
    }

    #[test]
    fn cbw_rejects_bad_signature() {
        let mut raw = raw_cbw(0, 0, 0, 0, &[0u8; 6]);
        raw[0] = b'T';
        assert!(Cbw::parse(&raw).is_none());
    }

    #[test]
    fn cbw_parse_roundtrip_fields() {
        let cdb = [0x28, 0, 0, 0, 8, 0, 0, 0, 1, 0]; // READ(10) LBA 8, 1 block
        let raw = raw_cbw(0xDEAD_BEEF, 512, 0x80, 3, &cdb);
        let cbw = Cbw::parse(&raw).expect("valid CBW");
        assert_eq!(cbw.tag, 0xDEAD_BEEF);
        assert_eq!(cbw.data_len, 512);
        assert_eq!(cbw.dir, BotDir::DataIn);
        assert_eq!(cbw.lun, 3);
        assert_eq!(cbw.cdb_len, 10);
        assert_eq!(cbw.cdb_slice(), &cdb[..]);
        // Unused CBWCB bytes beyond cdb_len are preserved but excluded.
        assert_eq!(cbw.cdb[10], 0);
    }

    #[test]
    fn cbw_fields_are_little_endian() {
        let raw = raw_cbw(0x1122_3344, 0x5566_7788, 0, 0, &[0u8; 6]);
        assert_eq!(le32_at(&raw, 4), 0x1122_3344);
        assert_eq!(le32_at(&raw, 8), 0x5566_7788);
    }

    #[test]
    fn cbw_direction_bit_maps_dir() {
        let out = raw_cbw(1, 0, 0x00, 0, &[0u8; 6]);
        assert_eq!(Cbw::parse(&out).unwrap().dir, BotDir::DataOut);
        let in_ = raw_cbw(1, 0, 0x80, 0, &[0u8; 6]);
        assert_eq!(Cbw::parse(&in_).unwrap().dir, BotDir::DataIn);
    }

    #[test]
    fn cbw_rejects_reserved_flag_bits() {
        // Bit 6 is obsolete, bits 5..0 reserved — any non-zero bit other
        // than the direction bit 7 makes the CBW invalid (BOT §5.1).
        for flags in [0x40, 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x7F] {
            let raw = raw_cbw(1, 0, flags, 0, &[0u8; 6]);
            assert!(
                Cbw::parse(&raw).is_none(),
                "flags 0x{flags:02X} must be rejected"
            );
        }
    }

    #[test]
    fn cbw_cdb_len_boundaries() {
        assert!(Cbw::parse(&raw_cbw(1, 0, 0, 0, &[])).is_none()); // 0 invalid
        assert!(Cbw::parse(&raw_cbw(1, 0, 0, 0, &[0])).is_some()); // 1 valid
        assert!(Cbw::parse(&raw_cbw(1, 0, 0, 0, &[0u8; 16])).is_some()); // 16 valid
        assert!(Cbw::parse(&raw_cbw(1, 0, 0, 0, &[0u8; 17])).is_none()); // >16 invalid
    }

    #[test]
    fn cbw_lun_is_byte_preserved() {
        let raw = raw_cbw(7, 0, 0, 15, &[0u8; 6]);
        assert_eq!(Cbw::parse(&raw).unwrap().lun, 15);
    }

    #[test]
    fn csw_signature_is_usbs_little_endian() {
        let csw = Csw {
            tag: 1,
            residue: 0,
            status: CswStatus::Passed,
        };
        let mut out = [0u8; CSW_LEN];
        csw.write(&mut out);
        assert_eq!(&out[0..4], b"USBS");
        assert_eq!(le32_at(&out, 0), CSW_SIGNATURE);
    }

    #[test]
    fn csw_echoes_tag_and_carries_residue_and_status() {
        let csw = Csw {
            tag: 0xCAFE_BAEB,
            residue: 512,
            status: CswStatus::Failed,
        };
        let mut out = [0u8; CSW_LEN];
        csw.write(&mut out);
        assert_eq!(le32_at(&out, 4), 0xCAFE_BAEB);
        assert_eq!(le32_at(&out, 8), 512);
        assert_eq!(out[12], 0x01);
    }

    #[test]
    fn csw_status_codes() {
        for (status, code) in [
            (CswStatus::Passed, 0x00),
            (CswStatus::Failed, 0x01),
            (CswStatus::PhaseError, 0x02),
        ] {
            let csw = Csw {
                tag: 0,
                residue: 0,
                status,
            };
            let mut out = [0u8; CSW_LEN];
            csw.write(&mut out);
            assert_eq!(out[12], code);
            assert_eq!(status as u8, code);
        }
    }
}
