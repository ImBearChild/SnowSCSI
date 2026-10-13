//! `DvdRamMedia` — a random-writable DVD-RAM over any [`WritableFlatData`] byte
//! plane.
//!
//! The device exposes a **blank** rewritable DVD-RAM: FORMAT UNIT clears all
//! logical blocks (zero-fill), and the **host OS** creates the file system
//! (UDF) on top. This layer therefore never writes or parses file-system
//! structures — it only moves bytes and reports geometry.
//!
//! - **Data plane**: random byte-plane reads/writes through the backend.
//! - **Geometry**: capacity / last LBA / lead-out for the device layer.
//!
//! Free space is left as zeros; the host filesystem allocates and writes it.

use crate::cdrom::common::SECTOR_SIZE;
use crate::common::seekable_storage::{StorageError, WritableFlatData};

/// A random-writable DVD-RAM over a byte plane.
#[derive(Debug)]
pub struct DvdRamMedia<D: WritableFlatData> {
    backend: D,
}

impl<D: WritableFlatData> DvdRamMedia<D> {
    /// Open `backend` as an erased, random-writable DVD-RAM.
    ///
    /// Existing content is used as-is (non-destructive); no file system is
    /// written here — the host creates one (FORMAT UNIT, then its own format).
    pub fn open(backend: D) -> Self {
        Self { backend }
    }

    /// Capacity in bytes (the backend length).
    pub fn capacity(&self) -> u64 {
        self.backend.capacity()
    }

    /// Largest readable LBA (`capacity / 2048 − 1`, saturating).
    pub fn max_lba(&self) -> u64 {
        (self.capacity() / u64::from(SECTOR_SIZE)).saturating_sub(1)
    }

    /// Lead-out start LBA (number of data sectors).
    pub fn lead_out_lba(&self) -> u32 {
        (self.capacity() / u64::from(SECTOR_SIZE)).min(u32::MAX as u64) as u32
    }

    /// Raw plane access.
    pub fn backend(&mut self) -> &mut D {
        &mut self.backend
    }

    /// Read from the byte plane (target data path).
    pub fn read_data(&mut self, offset: u64, buf: &mut [u8]) -> Result<(), StorageError> {
        self.backend.read_at(offset, buf)
    }

    /// Write to the byte plane (target data path).
    pub fn write_data(&mut self, offset: u64, buf: &[u8]) -> Result<(), StorageError> {
        self.backend.write_at(offset, buf)
    }

    /// Flush the byte plane.
    pub fn sync(&mut self) -> Result<(), StorageError> {
        self.backend.sync()
    }

    /// FORMAT UNIT for the emulated DVD-RAM medium: clear all logical blocks
    /// (zero-fill). Does **not** create or rebuild any file system — the host
    /// OS writes the UDF structures afterwards.
    pub fn format_unit(&mut self) -> Result<(), StorageError> {
        self.clear()
    }

    /// Zero-fill every logical block (the destructive part of FORMAT UNIT).
    fn clear(&mut self) -> Result<(), StorageError> {
        let zeroes = [0u8; 8192];
        let mut offset = 0u64;
        while offset < self.capacity() {
            let len = (self.capacity() - offset).min(zeroes.len() as u64) as usize;
            self.backend.write_at(offset, &zeroes[..len])?;
            offset += len as u64;
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::scsi::backend::RamBackend;

    fn ram(capacity: u64) -> Vec<u8> {
        vec![0u8; capacity as usize]
    }

    #[test]
    fn open_geometry_from_capacity() {
        let mut img = ram(2048 * 4096);
        let m = DvdRamMedia::open(RamBackend::new(&mut img));
        assert_eq!(m.capacity(), 2048 * 4096);
        assert_eq!(m.max_lba(), 4095);
        assert_eq!(m.lead_out_lba(), 4096);
    }

    #[test]
    fn write_data_read_data_roundtrip() {
        let mut img = ram(2048 * 4096);
        let mut m = DvdRamMedia::open(RamBackend::new(&mut img));
        let data = [0xAB; 2048];
        m.write_data(300 * 2048, &data).unwrap();
        let mut out = [0u8; 2048];
        m.read_data(300 * 2048, &mut out).unwrap();
        assert_eq!(out, data);
    }

    #[test]
    fn format_unit_clears_medium() {
        let mut img = ram(2048 * 4096);
        let mut m = DvdRamMedia::open(RamBackend::new(&mut img));
        m.write_data(300 * 2048, &[0xA5; 2048]).unwrap();
        m.format_unit().unwrap();
        // FORMAT UNIT clears all logical blocks.
        let mut sector = [0u8; 2048];
        m.read_data(300 * 2048, &mut sector).unwrap();
        assert_eq!(sector, [0u8; 2048]);
    }
}
