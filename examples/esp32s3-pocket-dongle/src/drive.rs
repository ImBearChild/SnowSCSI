//! DVD-RAM optical drive over the on-board SD card.
//!
//! Mirrors the CLI's `--cdrom dvdram=<dev>` construction path
//! (`snowdrive-cli/src/main.rs`): open the SD card as a random-writable byte
//! plane and wrap it in a [`DvdRamMedia`] (a DVD-RAM, PDT `0x05`, profile
//! DVD-RAM). The device exposes a **blank** random-writable DVD-RAM; the host
//! formats it (FORMAT UNIT + its own UDF `mkfs`). This crate never writes
//! file-system structures.

use snowdrive_scsi::cdrom::drive::CdromDrive;
use snowdrive_scsi::cdrom::dvdram::DvdRamMedia;
use snowdrive_scsi::cdrom::media::CdMedia;
use snowdrive_scsi::common::seekable_storage::RwRef;
use snowdrive_scsi::MIN_DATA_LEN;

use crate::sd::SdCard;

/// Command/data scratch length required by `ScsiDevice::do_cmd`.
///
/// `snowdrive-scsi::MIN_DATA_LEN` (8192) is the hard floor checked by every
/// device; a READ(10) of one 2048-byte block fits comfortably inside it.
pub const WORK_LEN: usize = MIN_DATA_LEN;

/// Build a DVD-RAM drive backed by the SD card.
///
/// The returned drive borrows `sd` for `'a`, so the card must outlive it and
/// no other borrow of the card may be live at the same time.
pub fn build<'a>(sd: &'a mut SdCard<'_>) -> CdromDrive<'a> {
    let mut drive = CdromDrive::new();
    // `load` (not `load_quiet`) queues a Unit Attention, which the first
    // TEST UNIT READY reports and consumes — exactly what a real host sees
    // after media insertion.
    drive.load(CdMedia::Rw(DvdRamMedia::open(RwRef::new(sd))));
    drive
}
