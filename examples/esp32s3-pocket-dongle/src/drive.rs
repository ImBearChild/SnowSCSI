//! UDF-RW optical drive over the on-board SD card (M2).
//!
//! Mirrors the CLI's `--cdrom udfrw=<dev>` construction path
//! (`snowdrive-cli/src/main.rs`): open the SD card as a random-writable byte
//! plane, wrap it in a UDF 2.01 [`UdfRwMedia`], and load the media into a
//! [`CdromDrive`].  The result is a DVD-RAM (PDT `0x05`, profile DVD-RAM) that
//! the M3 USB MSC transport can present to a host.
//!
//! The open mode is deliberately [`OpenMode::AsIs`]: the existing card content
//! is used as-is and only the geometry is derived.  `Materialize` (mkfs) is a
//! destructive operation and is *never* used here.

use snowdrive_scsi::cdrom::drive::CdromDrive;
use snowdrive_scsi::cdrom::media::CdMedia;
use snowdrive_scsi::cdrom::udfrw::{OpenMode, UdfRwMedia, UdfRwOptions};
use snowdrive_scsi::common::seekable_storage::RwRef;
use snowdrive_scsi::MIN_DATA_LEN;

use crate::sd::SdCard;

/// Command/data scratch length required by `ScsiDevice::do_cmd`.
///
/// `snowdrive-scsi::MIN_DATA_LEN` (8192) is the hard floor checked by every
/// device; a READ(10) of one 2048-byte block fits comfortably inside it.
pub const WORK_LEN: usize = MIN_DATA_LEN;

/// Failure of the drive build.
#[derive(Debug, Clone, Copy, PartialEq, Eq, defmt::Format)]
pub enum DriveError {
    /// `UdfRwMedia::open_or_materialize` rejected the backend / label /
    /// capacity (layout or storage failure).
    Media,
}

/// Build a DVD-RAM drive backed by the SD card.
///
/// `scratch` (≥ 1 byte; the CLI uses 256) backs the UDF space-bitmap CRC in
/// the `Materialize` path.  Because this function opens with
/// [`OpenMode::AsIs`] the scratch buffer is not written, but the options
/// struct still requires it.
///
/// The returned drive borrows `sd` for `'a`, so the card must outlive it and
/// no other borrow of the card may be live at the same time.
pub fn build<'a>(
    sd: &'a mut SdCard<'_>,
    label: &str,
    scratch: &mut [u8],
) -> Result<CdromDrive<'a>, DriveError> {
    let media = UdfRwMedia::open_or_materialize(
        RwRef::new(sd),
        label,
        UdfRwOptions {
            mode: OpenMode::AsIs,
            scratch,
        },
    )
    .map_err(|_| DriveError::Media)?;

    let mut drive = CdromDrive::new();
    // `load` (not `load_quiet`) queues a Unit Attention, which the first
    // TEST UNIT READY reports and consumes — exactly what a real host sees
    // after media insertion.
    drive.load(CdMedia::Rw(media));
    Ok(drive)
}
