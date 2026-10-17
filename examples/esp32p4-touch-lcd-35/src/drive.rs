//! DVD-RAM optical drive over the on-board SD card.
//!
//! Mirrors the CLI's `--cdrom dvdram=<dev>` construction path
//! (`snowscsi-cli/src/main.rs`): open the SD card as a random-writable byte
//! plane and wrap it in a [`DvdRamMedia`] (a DVD-RAM, PDT `0x05`, profile
//! DVD-RAM). The device exposes a **blank** random-writable DVD-RAM; the host
//! formats it (FORMAT UNIT + its own UDF `mkfs`). This crate never writes
//! file-system structures.

use snowscsi::cdrom::drive::CdromDrive;
use snowscsi::cdrom::dvdram::DvdRamMedia;
use snowscsi::cdrom::media::CdMedia;
use snowscsi::common::seekable_storage::{RwRef, WritableFlatData};
use snowscsi::MIN_DATA_LEN;

/// Command/data scratch length for [`ScsiDevice::do_cmd`].
///
/// `snowscsi::MIN_DATA_LEN` (8192) is the hard floor every device checks, and
/// on this USB link it is also the *optimum*: the BOT shell overlaps storage
/// I/O with the bulk transfer only when a host command spans **multiple**
/// chunks, so a smaller (floor-sized) work buffer overlaps more. Measured `dd`
/// on the P4: writes **1.7 MB/s at 64 KiB vs 4.6 MB/s at 8 KiB**; reads are
/// unchanged (~4.2). (4 KiB is rejected by the `MIN_DATA_LEN` assert.)
pub const WORK_LEN: usize = MIN_DATA_LEN;

/// Build a DVD-RAM drive backed by any random-writable byte plane.
///
/// The drive is backend-free: it caches geometry from `plane` (via the
/// synchronous `RwRef` view, whose `capacity()` is all [`DvdRamMedia::open`]
/// reads) and addresses the plane only through the LUN's store plane, so the
/// borrow of `plane` ends when this function returns.
pub fn build<P: WritableFlatData>(plane: &mut P) -> CdromDrive {
    let mut drive = CdromDrive::new();
    // `load` (not `load_quiet`) queues a Unit Attention, which the first
    // TEST UNIT READY reports and consumes — exactly what a real host sees
    // after media insertion.
    drive.load(CdMedia::Rw(DvdRamMedia::open(&mut RwRef::new(plane))));
    drive
}
