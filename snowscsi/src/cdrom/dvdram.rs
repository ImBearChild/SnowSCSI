//! `DvdRamMedia` — a random-writable DVD-RAM over any [`WritableFlatData`] byte
//! plane.
//!
//! The device exposes a **blank** rewritable DVD-RAM: FORMAT UNIT clears all
//! logical blocks (zero-fill), and the **host OS** creates the file system
//! (UDF) on top. This layer therefore never writes or parses file-system
//! structures — it only reports cached geometry.
//!
//! - **Geometry**: capacity / last LBA / lead-out, read from the plane once
//!   at [`DvdRamMedia::open`] and cached (the media holds no backend).
//! - **Data / format**: executed by the shell's store plane and the drive
//!   agenda (`StoreOp::Read`/`Write`/`Fill`/`Sync`), never here.
//!
//! Free space is left as zeros; the host filesystem allocates and writes it.

use crate::cdrom::common::SECTOR_SIZE;
use crate::common::seekable_storage::WritableFlatData;

/// A random-writable DVD-RAM over a byte plane.
///
/// **Non-generic and backend-free**: [`Self::open`] borrows the plane once to
/// read its capacity and releases it. Only the derived geometry is retained;
/// the drive addresses the LUN's store plane for data-phase I/O. FORMAT
/// UNIT / BLANK zero-fill is produced by the drive agenda as a
/// [`StoreOp::Fill`](crate::common::store::StoreOp::Fill).
#[derive(Debug)]
pub struct DvdRamMedia {
    /// Cached capacity in bytes.
    capacity: u64,
    /// Largest readable LBA (`capacity / 2048 − 1`, saturating).
    max_lba: u64,
    /// Lead-out start LBA (number of data sectors, clamped to `u32`).
    lead_out_lba: u32,
}

impl DvdRamMedia {
    /// Open `plane` as an erased, random-writable DVD-RAM.
    ///
    /// The plane is borrowed only for the capacity read and immediately
    /// released — the media holds no backend. Existing content is used as-is
    /// (non-destructive); no file system is written here — the host creates
    /// one (FORMAT UNIT, then its own format).
    pub fn open(plane: &mut dyn WritableFlatData) -> Self {
        let capacity = plane.capacity();
        let sectors = capacity / u64::from(SECTOR_SIZE);
        Self {
            capacity,
            max_lba: sectors.saturating_sub(1),
            lead_out_lba: sectors.min(u32::MAX as u64) as u32,
        }
    }

    /// Capacity in bytes (cached at construction).
    pub fn capacity(&self) -> u64 {
        self.capacity
    }

    /// Largest readable LBA (`capacity / 2048 − 1`, saturating).
    pub fn max_lba(&self) -> u64 {
        self.max_lba
    }

    /// Lead-out start LBA (number of data sectors).
    pub fn lead_out_lba(&self) -> u32 {
        self.lead_out_lba
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::common::seekable_storage::FlatData;
    use crate::scsi::backend::RamBackend;

    #[test]
    fn open_geometry_from_capacity() {
        let mut img = vec![0u8; 2048 * 4096];
        let m = DvdRamMedia::open(&mut RamBackend::new(&mut img));
        assert_eq!(m.capacity(), 2048 * 4096);
        assert_eq!(m.max_lba(), 4095);
        assert_eq!(m.lead_out_lba(), 4096);
    }

    #[test]
    fn open_releases_the_plane() {
        // `open` borrows the plane only for the capacity read; once it
        // returns, the plane is usable again (the media holds no backend).
        let mut img = vec![0u8; 2048 * 8];
        let m = {
            let mut be = RamBackend::new(&mut img);
            DvdRamMedia::open(&mut be)
        };
        assert_eq!(m.lead_out_lba(), 8);
        let mut be = RamBackend::new(&mut img);
        let mut out = [0u8; 16];
        assert!(be.read_at(0, &mut out).is_ok());
    }
}
