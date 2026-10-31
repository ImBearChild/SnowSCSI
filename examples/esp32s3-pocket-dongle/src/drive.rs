//! DVD-RAM optical drive over the on-board SD card.
//!
//! Mirrors the CLI's `--cdrom dvdram=<dev>` construction path
//! (`snowscsi-cli/src/main.rs`): the SD card becomes the LUN's storage adapter
//! ([`crate::store::SdStore`]) while the device is a [`MmcDrive`] over a
//! [`DvdRamMedium`] (a DVD-RAM, PDT `0x05`, profile DVD-RAM), wrapped in
//! [`Spc`] and [`LuImpl`]. The device exposes a **blank** random-writable
//! DVD-RAM; the host formats it (FORMAT UNIT + its own UDF `mkfs`). This crate
//! never writes file-system structures.

use snowscsi::core::{LuImpl, Pair, Spc};
use snowscsi::mmc::{DvdRamMedium, MmcDrive};
use snowscsi::MIN_DATA_LEN;

/// DVD-RAM logical block length (bytes).
const BLOCK_LEN: u64 = 2048;

/// Command/data scratch length for the BOT session.
///
/// `snowscsi::MIN_DATA_LEN` (8192) is the hard floor checked by the core; a
/// READ(10) of one 2048-byte block fits comfortably inside it.
pub const WORK_LEN: usize = MIN_DATA_LEN;

/// Application backing handle: this firmware has exactly one LUN, so the
/// backing id is an identity.
pub type Backing = u32;

/// The single LUN: the six-command SPC wrapper over the DVD-RAM drive.
pub type DvdRamLu = LuImpl<Spc<MmcDrive<DvdRamMedium>>, Backing>;

/// The core `Pair` type of this target (DVD-RAM medium + backing id).
pub type DvdRamPair = Pair<DvdRamMedium, Backing>;

/// Build a blank DVD-RAM drive sized from the SD card's byte capacity.
///
/// The medium owns only geometry; the bytes come from the LUN's
/// [`Storage`](snowscsi::core::storage::Storage) adapter at operation time, so
/// no borrow of the card is retained here.
pub fn build(capacity_bytes: u64) -> DvdRamLu {
    let sectors = capacity_bytes / BLOCK_LEN;
    let medium = DvdRamMedium::new(sectors);
    let drive = MmcDrive::new(medium);
    LuImpl::new(Spc::new(drive), 0)
}
