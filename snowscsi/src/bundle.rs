//! Bundle identification: directory and sidecar manifests.
//!
//! A bundle is identified by its **manifest**, never by a directory listing:
//! `SNOWBUNDLE` inside a bundle directory (or `<file>.SNOWBUNDLE` next to a
//! single-file image). The manifest is the single entry point for the kind,
//! geometry and optional cipher description. A directory without one is
//! reported as [`Identified::NotBundle`](crate::bundle::Identified::NotBundle),
//! listing the bundle-like names that were found instead.
//!
//! The CD-R TOC (`toc.0`/`toc.1`) is deliberately **plaintext**: capacity and
//! session/track information must be available without a key. Only the track
//! payload resources are encrypted by the resource-addressed cipher decorator.
//!
//! The manifest is **not authenticated**. Its CRC detects accidental damage
//! only; an attacker who can rewrite the manifest can also rewrite the CRC.
//! Stream ciphers are malleable and carry no integrity either, so a modified
//! image/medium decrypts to wrong bytes rather than reporting tampering.
//!
//! # Feature gating
//!
//! The identification functions need the manifest I/O path (`bundle`) and,
//! for a CD-R TOC probe, the recordable-CD medium (`cdr-bundle`). Without
//! `cdr-bundle`, a `kind = cdr` manifest is still identified but the
//! `Identified::Cdr` `toc` field is always [`None`];
//! [`TocSummary`](crate::bundle::TocSummary) remains part of the public shape
//! so callers do not need a feature-specific match.

#[cfg(feature = "bundle")]
use crate::common::bundle::{BundleKind, MANIFEST_NAME, MAX_MANIFEST};
use crate::common::bundle::{BundleMeta, ManifestError};
use crate::common::fs_storage::FsError;
#[cfg(feature = "bundle")]
use crate::common::fs_storage::{FsStorage, OpenOptions};

/// Summary of one validated CD-R TOC slot.
///
/// The type exists in every build so [`Identified::Cdr`] keeps one shape, but
/// it is only ever constructed when `cdr-bundle` is compiled in: without that
/// feature no TOC is probed and `toc` is always [`None`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub struct TocSummary {
    /// Sequence number of the save that produced the slot.
    pub seq: u32,
    /// Total slot size in bytes.
    pub slot_size: u32,
    /// Largest number of tracks the slot can hold.
    pub max_tracks: u16,
    /// Addressable logical blocks stored in the TOC body.
    pub capacity_sectors: u64,
    /// Number of sessions stored in the TOC body.
    pub sessions: u16,
    /// Number of tracks stored in the TOC body.
    pub tracks: u16,
    /// Current MMC profile of the installed medium (`0x09` CD-R, `0x0A` CD-RW).
    pub profile: u16,
}

#[cfg(feature = "cdr-bundle")]
impl TocSummary {
    /// Validate one full TOC slot read from physical position `slot` and
    /// summarize it.
    ///
    /// The 256-byte header is parsed first; its declared `slot_size` bounds the
    /// document that
    /// [`CdrBundleMedium::open_at`](crate::mmc::cdr_bundle::CdrBundleMedium::open_at)
    /// then validates. A slot that was copied from the other position, a short
    /// document, or a body that fails its length/checksum check is rejected;
    /// trailing bytes past the declared slot size are ignored.
    pub fn parse_slot(
        slot: u8,
        bytes: &[u8],
    ) -> Result<TocSummary, crate::mmc::cdr_bundle::TocError> {
        use crate::mmc::cdr_bundle::{
            CdrBundleMedium, Recovery, TocError, TocHeader, TOC_SLOT_MAX,
        };
        use crate::mmc::MmcMedium as _;

        let header = TocHeader::parse(bytes)?;
        if header.slot != slot {
            return Err(TocError::Invalid);
        }
        let total = header.slot_size as usize;
        if header.slot_size > TOC_SLOT_MAX || bytes.len() < total {
            return Err(TocError::Invalid);
        }
        let medium = CdrBundleMedium::open_at(slot, &bytes[..total], 0, Recovery::ReadOnly)?;
        let attrs = medium.attrs();
        Ok(TocSummary {
            seq: header.seq,
            slot_size: header.slot_size,
            max_tracks: header.max_tracks,
            capacity_sectors: attrs.sectors,
            sessions: attrs.sessions,
            tracks: attrs.tracks,
            profile: attrs.profile,
        })
    }

    /// Summarize the newest valid slot among the two raw slot images.
    ///
    /// Each slot is parsed independently; a missing or damaged slot is
    /// ignored. Selection follows the TOC policy: the higher `seq` wins, and
    /// an equal `seq` selects the higher slot index. `None` is returned only
    /// when neither slot is usable.
    pub fn newest(toc0: Option<&[u8]>, toc1: Option<&[u8]>) -> Option<TocSummary> {
        let first = toc0.and_then(|bytes| Self::parse_slot(0, bytes).ok());
        let second = toc1.and_then(|bytes| Self::parse_slot(1, bytes).ok());
        select_newest(first, second)
    }
}

/// Result of classifying a bundle directory or sidecar manifest.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Identified {
    /// A single-file plain image.
    Image {
        /// Parsed manifest.
        meta: BundleMeta,
    },
    /// A directory of fixed-size chunk files.
    Flat {
        /// Parsed manifest.
        meta: BundleMeta,
    },
    /// A recordable CD bundle.
    Cdr {
        /// Parsed manifest.
        meta: BundleMeta,
        /// Newest valid plaintext TOC summary, when one is present.
        toc: Option<TocSummary>,
    },
    /// No manifest, but other bundle-like names were found.
    NotBundle {
        /// Names actually present, in probe order.
        found: heapless::Vec<&'static str, 8>,
    },
}

/// Manifest/TOC identification failure.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IdentifyError {
    /// Underlying filesystem failure.
    Fs(FsError),
    /// The manifest is malformed or too large.
    Manifest(ManifestError),
}

impl ::core::fmt::Display for IdentifyError {
    fn fmt(&self, f: &mut ::core::fmt::Formatter<'_>) -> ::core::fmt::Result {
        match self {
            Self::Fs(e) => write!(f, "filesystem error: {e}"),
            Self::Manifest(e) => write!(f, "manifest error: {e}"),
        }
    }
}

impl ::core::error::Error for IdentifyError {}

impl From<FsError> for IdentifyError {
    fn from(e: FsError) -> Self {
        Self::Fs(e)
    }
}

impl From<ManifestError> for IdentifyError {
    fn from(e: ManifestError) -> Self {
        Self::Manifest(e)
    }
}

/// Names probed when a manifest is absent, in deterministic order.
#[cfg(feature = "bundle")]
const PROBE_NAMES: [&str; 5] = [MANIFEST_NAME, "BUNDLE", "toc.0", "toc.1", "000000.img"];

/// Identify a bundle directory by its manifest.
///
/// Reads `SNOWBUNDLE` (rejecting anything larger than [`MAX_MANIFEST`]); on a
/// `kind = cdr` manifest, additionally probes `toc.0`/`toc.1` and reports the
/// newest valid plaintext header. Without `cdr-bundle`, the TOC probe is
/// skipped and [`Identified::Cdr`] carries `toc: None`.
///
/// A missing manifest is not an error: the names that were found are returned
/// in [`Identified::NotBundle`] so the caller can explain what it saw.
#[cfg(feature = "bundle")]
pub fn identify_dir<F: FsStorage>(fs: &mut F) -> Result<Identified, IdentifyError> {
    let Some(meta) = read_manifest(fs)? else {
        return Ok(Identified::NotBundle {
            found: probe_names(fs),
        });
    };
    if meta.kind == BundleKind::Cdr {
        #[cfg(feature = "cdr-bundle")]
        let toc = probe_toc(fs)?;
        #[cfg(not(feature = "cdr-bundle"))]
        let toc = None;
        Ok(Identified::Cdr { meta, toc })
    } else {
        Ok(classify(meta, None))
    }
}

/// Classify already-read sidecar manifest bytes (a single-file image).
#[cfg(feature = "bundle")]
pub fn identify_manifest(bytes: &[u8]) -> Result<Identified, IdentifyError> {
    let meta = BundleMeta::parse(bytes)?;
    Ok(classify(meta, None))
}

/// Classify already-read manifest bytes together with the two raw TOC slot
/// images (`toc.0`/`toc.1`).
///
/// A `kind = cdr` manifest reports the newest valid slot; a non-CDR kind
/// ignores the TOC bytes. Without `cdr-bundle`, no slot is parsed and
/// [`Identified::Cdr`] carries `toc: None`.
#[cfg(feature = "bundle")]
pub fn identify_manifest_with_toc(
    manifest: &[u8],
    toc0: Option<&[u8]>,
    toc1: Option<&[u8]>,
) -> Result<Identified, IdentifyError> {
    let meta = BundleMeta::parse(manifest)?;
    if meta.kind == BundleKind::Cdr {
        #[cfg(feature = "cdr-bundle")]
        let toc = TocSummary::newest(toc0, toc1);
        #[cfg(not(feature = "cdr-bundle"))]
        let toc = {
            let _ = (toc0, toc1);
            None
        };
        Ok(Identified::Cdr { meta, toc })
    } else {
        Ok(classify(meta, None))
    }
}

/// Map a parsed manifest to its [`Identified`] variant.
#[cfg(feature = "bundle")]
fn classify(meta: BundleMeta, toc: Option<TocSummary>) -> Identified {
    match meta.kind {
        BundleKind::Image { .. } => Identified::Image { meta },
        BundleKind::Flat { .. } => Identified::Flat { meta },
        BundleKind::Cdr => Identified::Cdr { meta, toc },
    }
}

/// Read and parse `SNOWBUNDLE`; `None` means the file does not exist.
#[cfg(feature = "bundle")]
fn read_manifest<F: FsStorage>(fs: &mut F) -> Result<Option<BundleMeta>, IdentifyError> {
    use embedded_io::Error as _;

    let mut file = match fs.open(MANIFEST_NAME, OpenOptions::read_only()) {
        Ok(file) => file,
        Err(FsError::NotFound) => return Ok(None),
        Err(e) => return Err(IdentifyError::Fs(e)),
    };
    let mut data = heapless::Vec::<u8, MAX_MANIFEST>::new();
    let mut tmp = [0u8; 64];
    loop {
        let n = match embedded_io::Read::read(&mut file, &mut tmp) {
            Ok(0) => break,
            Ok(n) => n,
            Err(e) => {
                fs.close(file);
                return Err(IdentifyError::Fs(FsError::Io(e.kind())));
            }
        };
        if data.extend_from_slice(&tmp[..n]).is_err() {
            fs.close(file);
            return Err(IdentifyError::Manifest(ManifestError::TooLarge));
        }
    }
    fs.close(file);
    BundleMeta::parse(&data)
        .map(Some)
        .map_err(IdentifyError::Manifest)
}

/// Collect the bundle-like names that are actually present.
#[cfg(feature = "bundle")]
fn probe_names<F: FsStorage>(fs: &mut F) -> heapless::Vec<&'static str, 8> {
    let mut found = heapless::Vec::new();
    for name in PROBE_NAMES {
        if let Ok(file) = fs.open(name, OpenOptions::read_only()) {
            fs.close(file);
            // Five probes cannot overflow an eight-entry vector.
            let _ = found.push(name);
        }
    }
    found
}

/// Bounded buffer size for one raw TOC slot.
#[cfg(all(feature = "bundle", feature = "cdr-bundle"))]
const TOC_SLOT_BYTES: usize = crate::mmc::cdr_bundle::TOC_SLOT_MAX as usize;

/// Read both TOC slots and keep the newest valid summary.
#[cfg(all(feature = "bundle", feature = "cdr-bundle"))]
fn probe_toc<F: FsStorage>(fs: &mut F) -> Result<Option<TocSummary>, IdentifyError> {
    let first = read_toc_slot(fs, 0);
    let second = read_toc_slot(fs, 1);
    match (first, second) {
        (Ok(first), Ok(second)) => Ok(select_newest(first, second)),
        // A read error on one slot must not hide a usable other slot.
        (Ok(first), Err(_)) => Ok(select_newest(first, None)),
        (Err(_), Ok(second)) => Ok(select_newest(None, second)),
        (Err(error), Err(_)) => Err(error),
    }
}

/// Select the newer summary from two already-validated slots.
#[cfg(feature = "cdr-bundle")]
fn select_newest(first: Option<TocSummary>, second: Option<TocSummary>) -> Option<TocSummary> {
    match (first, second) {
        (Some(a), Some(b)) => Some(if newer(&b, 1, &a, 0) { b } else { a }),
        (Some(summary), None) | (None, Some(summary)) => Some(summary),
        (None, None) => None,
    }
}

/// `true` when `(a, a_slot)` is newer than `(b, b_slot)`.
#[cfg(feature = "cdr-bundle")]
fn newer(a: &TocSummary, a_slot: u8, b: &TocSummary, b_slot: u8) -> bool {
    a.seq > b.seq || (a.seq == b.seq && a_slot > b_slot)
}

/// Read and summarize one full TOC slot.
///
/// The 256-byte header is parsed first to learn `slot_size`; the rest of the
/// slot is then read (capped at [`crate::mmc::cdr_bundle::TOC_SLOT_MAX`]) and
/// parsed by [`TocSummary::parse_slot`] before the temporary buffer is dropped.
/// A missing, short, oversized or malformed slot is `None`, never a fatal
/// error: one damaged slot must not hide the other one. Only a non-`NotFound`
/// open failure is an error.
#[cfg(all(feature = "bundle", feature = "cdr-bundle"))]
fn read_toc_slot<F: FsStorage>(fs: &mut F, slot: u8) -> Result<Option<TocSummary>, IdentifyError> {
    use crate::mmc::cdr_bundle::{toc_file, TocHeader, TOC_HEADER_LEN};

    const SLOT_MAX: usize = TOC_SLOT_BYTES;

    let path = toc_file(slot);
    let mut file = match fs.open(path, OpenOptions::read_only()) {
        Ok(file) => file,
        Err(FsError::NotFound) => return Ok(None),
        Err(e) => return Err(IdentifyError::Fs(e)),
    };
    let mut header = [0u8; TOC_HEADER_LEN];
    let mut got = 0usize;
    let mut failed = false;
    while got < header.len() {
        match embedded_io::Read::read(&mut file, &mut header[got..]) {
            Ok(0) => break,
            Ok(n) => got += n,
            Err(_) => {
                failed = true;
                break;
            }
        }
    }
    if failed || got < header.len() {
        fs.close(file);
        return Ok(None);
    }
    // A file whose header names the other slot is not a usable summary. The
    // header parser already rejects `slot_size > TOC_SLOT_MAX`.
    let parsed = match TocHeader::parse(&header) {
        Ok(parsed) if parsed.slot == slot => parsed,
        _ => {
            fs.close(file);
            return Ok(None);
        }
    };
    let total = parsed.slot_size as usize;
    if total > SLOT_MAX {
        fs.close(file);
        return Ok(None);
    }
    let mut bytes: heapless::Vec<u8, SLOT_MAX> = heapless::Vec::new();
    // The header fits, and `total <= SLOT_MAX` was just checked.
    let _ = bytes.extend_from_slice(&header);
    let _ = bytes.resize(total, 0);
    let mut got = TOC_HEADER_LEN;
    let mut failed = false;
    while got < total {
        match embedded_io::Read::read(&mut file, &mut bytes[got..]) {
            Ok(0) => break,
            Ok(n) => got += n,
            Err(_) => {
                failed = true;
                break;
            }
        }
    }
    fs.close(file);
    if failed || got < total {
        return Ok(None);
    }
    match TocSummary::parse_slot(slot, &bytes) {
        Ok(summary) => Ok(Some(summary)),
        // A valid header with a corrupt body is a damaged slot, not an
        // identification failure.
        Err(_) => Ok(None),
    }
}

#[cfg(all(test, feature = "bundle", feature = "std"))]
mod tests {
    use super::*;
    #[cfg(feature = "cdr-bundle")]
    use crate::mmc::cdr_bundle::{max_tracks_for_slot, TocError, TOC_HEADER_LEN, TOC_SLOT_DEFAULT};
    use crate::scsi::fs_backend::StdFsBackend;

    /// Unique temporary directory, removed on drop.
    struct TempDir(std::path::PathBuf);

    impl TempDir {
        fn new(name: &str) -> Self {
            let dir = std::env::temp_dir().join(format!(
                "snowscsi_bundle_{}_{}",
                name,
                std::process::id()
            ));
            let _ = std::fs::remove_dir_all(&dir);
            std::fs::create_dir_all(&dir).unwrap();
            Self(dir)
        }

        fn write(&self, name: &str, bytes: &[u8]) {
            std::fs::write(self.0.join(name), bytes).unwrap();
        }
    }

    impl Drop for TempDir {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }

    fn backend(dir: &TempDir) -> StdFsBackend {
        StdFsBackend::new(dir.0.to_str().unwrap())
    }

    fn meta(kind: BundleKind) -> BundleMeta {
        BundleMeta {
            kind,
            cipher: None,
            has_crc: false,
        }
    }

    /// Build a full, valid TOC slot with one reserved track and one session.
    #[cfg(feature = "cdr-bundle")]
    fn toc_slot(slot: u8, seq: u32, capacity: u64) -> std::vec::Vec<u8> {
        use crate::mmc::cdr_bundle::toc::{
            checksum, header_bytes, max_tracks_for_slot, render_padding,
        };
        use crate::mmc::cdr_bundle::{TOC_HEADER_LEN, TOC_SLOT_DEFAULT};

        let body = format!(
            "disc_type = cdr\n\
             disc_state = appendable\n\
             capacity_sectors = {capacity}\n\
             medium_leadin = -11077\n\
             [track.1]\n\
             status = reserved\n\
             session = 1\n\
             start_lba = 0\n\
             data_start_lba = 0\n\
             allocated = 500\n\
             length = 0\n\
             written = 0\n\
             nwa = 0\n\
             kind = data\n\
             reserved = 1\n\
             [session.1]\n\
             first_track = 1\n\
             last_track = 1\n\
             start_lba = 0\n\
             lead_out_lba = 0\n\
             closed = 0\n\
             end = 1\n"
        );
        let mut out = vec![0u8; TOC_SLOT_DEFAULT as usize];
        out[TOC_HEADER_LEN..TOC_HEADER_LEN + body.len()].copy_from_slice(body.as_bytes());
        let padding = out.len() - TOC_HEADER_LEN - body.len();
        assert_eq!(
            render_padding(padding, 0, &mut out[TOC_HEADER_LEN + body.len()..]),
            padding
        );
        let header = header_bytes(
            slot,
            TOC_SLOT_DEFAULT,
            max_tracks_for_slot(TOC_SLOT_DEFAULT),
            body.len() as u32,
            checksum(body.as_bytes()),
            seq,
        );
        out[..TOC_HEADER_LEN].copy_from_slice(&header);
        out
    }

    #[test]
    fn identifies_flat_manifest() {
        let dir = TempDir::new("flat");
        let flat = meta(BundleKind::Flat {
            virtual_size: 8 << 20,
            chunk_size: 1 << 20,
            sector_size: 512,
        });
        dir.write(MANIFEST_NAME, &flat.encode().unwrap());
        match identify_dir(&mut backend(&dir)).unwrap() {
            Identified::Flat { meta } => assert_eq!(meta.kind, flat.kind),
            other => panic!("expected a flat bundle, got {other:?}"),
        }
    }

    #[test]
    fn identifies_image_dir_manifest() {
        let dir = TempDir::new("image_dir");
        let image = meta(BundleKind::Image { size: 4096 });
        dir.write(MANIFEST_NAME, &image.encode().unwrap());
        match identify_dir(&mut backend(&dir)).unwrap() {
            Identified::Image { meta } => assert_eq!(meta.kind, image.kind),
            other => panic!("expected an image bundle, got {other:?}"),
        }
    }

    #[test]
    fn identifies_image_sidecar_bytes() {
        let image = meta(BundleKind::Image { size: 1 << 20 });
        let bytes = image.encode().unwrap();
        match identify_manifest(&bytes).unwrap() {
            Identified::Image { meta } => assert_eq!(meta.kind, image.kind),
            other => panic!("expected an image sidecar, got {other:?}"),
        }
    }

    #[test]
    fn rejects_wrong_magic() {
        let err =
            identify_manifest(b"magic = nope\nversion = 1\nkind = image\nsize = 1\n").unwrap_err();
        assert_eq!(err, IdentifyError::Manifest(ManifestError::BadMagic));
    }

    #[test]
    fn identifies_cdr_manifest_and_newest_toc() {
        let dir = TempDir::new("cdr");
        let cdr = meta(BundleKind::Cdr);
        dir.write(MANIFEST_NAME, &cdr.encode().unwrap());

        #[cfg(feature = "cdr-bundle")]
        {
            use crate::mmc::cdr_bundle::{max_tracks_for_slot, TOC_SLOT_DEFAULT};

            dir.write("toc.0", &toc_slot(0, 5, 1_000));
            dir.write("toc.1", &toc_slot(1, 7, 2_000));
            let identified = identify_dir(&mut backend(&dir)).unwrap();
            match identified {
                Identified::Cdr { meta, toc } => {
                    assert_eq!(meta.kind, cdr.kind);
                    let toc = toc.expect("newest slot");
                    assert_eq!(toc.seq, 7);
                    assert_eq!(toc.slot_size, TOC_SLOT_DEFAULT);
                    assert_eq!(toc.max_tracks, max_tracks_for_slot(TOC_SLOT_DEFAULT));
                    assert_eq!(toc.capacity_sectors, 2_000);
                    assert_eq!(toc.sessions, 1);
                    assert_eq!(toc.tracks, 1);
                    assert_eq!(toc.profile, 0x0009);
                }
                other => panic!("expected a CD-R bundle, got {other:?}"),
            }
        }

        #[cfg(not(feature = "cdr-bundle"))]
        {
            match identify_dir(&mut backend(&dir)).unwrap() {
                Identified::Cdr { meta, toc } => {
                    assert_eq!(meta.kind, cdr.kind);
                    assert!(toc.is_none());
                }
                other => panic!("expected a CD-R bundle, got {other:?}"),
            }
        }
    }

    #[cfg(feature = "cdr-bundle")]
    #[test]
    fn cdr_toc_prefers_the_only_valid_slot() {
        let dir = TempDir::new("cdr_one_slot");
        let cdr = meta(BundleKind::Cdr);
        dir.write(MANIFEST_NAME, &cdr.encode().unwrap());

        dir.write("toc.0", b"not a toc");
        dir.write("toc.1", &toc_slot(1, 9, 3_000));
        let identified = identify_dir(&mut backend(&dir)).unwrap();
        match identified {
            Identified::Cdr { toc, .. } => {
                let toc = toc.expect("valid slot 1");
                assert_eq!(toc.seq, 9);
                assert_eq!(toc.capacity_sectors, 3_000);
            }
            other => panic!("expected a CD-R bundle, got {other:?}"),
        }
    }

    #[cfg(feature = "cdr-bundle")]
    #[test]
    fn cdr_toc_ignores_a_corrupt_body() {
        let dir = TempDir::new("cdr_corrupt_body");
        let cdr = meta(BundleKind::Cdr);
        dir.write(MANIFEST_NAME, &cdr.encode().unwrap());

        // A valid header over a body whose checksum no longer matches: the
        // slot must be reported missing, not as an identification failure.
        let mut slot = toc_slot(0, 3, 1_000);
        slot[TOC_HEADER_LEN] ^= 0xFF;
        dir.write("toc.0", &slot);
        match identify_dir(&mut backend(&dir)).unwrap() {
            Identified::Cdr { toc, .. } => assert!(toc.is_none()),
            other => panic!("expected a CD-R bundle, got {other:?}"),
        }
    }

    #[cfg(feature = "cdr-bundle")]
    #[test]
    fn toc_summary_parses_a_valid_slot() {
        let slot = toc_slot(0, 5, 1_000);
        let summary = TocSummary::parse_slot(0, &slot).unwrap();
        assert_eq!(summary.seq, 5);
        assert_eq!(summary.slot_size, TOC_SLOT_DEFAULT);
        assert_eq!(summary.max_tracks, max_tracks_for_slot(TOC_SLOT_DEFAULT));
        assert_eq!(summary.capacity_sectors, 1_000);
        assert_eq!(summary.sessions, 1);
        assert_eq!(summary.tracks, 1);
        assert_eq!(summary.profile, 0x0009);
    }

    #[cfg(feature = "cdr-bundle")]
    #[test]
    fn toc_summary_rejects_a_copied_slot() {
        // Slot 1 content read from physical position 0 is not usable.
        let slot = toc_slot(1, 5, 1_000);
        assert_eq!(
            TocSummary::parse_slot(0, &slot).unwrap_err(),
            TocError::Invalid
        );
    }

    #[cfg(feature = "cdr-bundle")]
    #[test]
    fn toc_summary_rejects_a_corrupt_body() {
        let mut slot = toc_slot(0, 5, 1_000);
        slot[TOC_HEADER_LEN] ^= 0xFF;
        assert_eq!(
            TocSummary::parse_slot(0, &slot).unwrap_err(),
            TocError::Invalid
        );
    }

    #[cfg(feature = "cdr-bundle")]
    #[test]
    fn toc_summary_rejects_short_input() {
        let slot = toc_slot(0, 5, 1_000);
        assert_eq!(
            TocSummary::parse_slot(0, &slot[..TOC_HEADER_LEN]).unwrap_err(),
            TocError::Invalid
        );
    }

    #[cfg(feature = "cdr-bundle")]
    #[test]
    fn toc_newest_prefers_higher_seq_then_higher_slot() {
        let a = toc_slot(0, 5, 1_000);
        let b = toc_slot(1, 7, 2_000);
        let newest = TocSummary::newest(Some(&a), Some(&b)).unwrap();
        assert_eq!(newest.seq, 7);
        assert_eq!(newest.capacity_sectors, 2_000);

        // Equal seq selects the higher slot index.
        let a = toc_slot(0, 7, 1_000);
        let b = toc_slot(1, 7, 2_000);
        assert_eq!(
            TocSummary::newest(Some(&a), Some(&b))
                .unwrap()
                .capacity_sectors,
            2_000
        );

        // A higher seq wins even when it lives in the lower slot.
        let a = toc_slot(0, 9, 1_000);
        let b = toc_slot(1, 7, 2_000);
        assert_eq!(TocSummary::newest(Some(&a), Some(&b)).unwrap().seq, 9);

        // A damaged slot is ignored rather than failing the pair.
        let mut bad = toc_slot(0, 5, 1_000);
        bad[TOC_HEADER_LEN] ^= 0xFF;
        assert_eq!(TocSummary::newest(Some(&bad), Some(&b)).unwrap().seq, 7);
        assert!(TocSummary::newest(Some(&bad), None).is_none());
        assert!(TocSummary::newest(None, None).is_none());

        // A slot image copied into the other argument is ignored: its header
        // names physical slot 1 even though it was supplied as slot 0.
        let copied = toc_slot(1, 9, 1_000);
        assert_eq!(TocSummary::newest(Some(&copied), None).map(|s| s.seq), None);
        assert_eq!(
            TocSummary::newest(None, Some(&copied)).map(|s| s.seq),
            Some(9)
        );
    }

    #[test]
    fn manifest_with_toc_reports_cdr_and_ignores_non_cdr() {
        let cdr = meta(BundleKind::Cdr);
        let cdr_bytes = cdr.encode().unwrap();
        #[cfg(feature = "cdr-bundle")]
        let (toc0, toc1) = (toc_slot(0, 4, 1_000), toc_slot(1, 8, 2_000));
        #[cfg(not(feature = "cdr-bundle"))]
        let (toc0, toc1) = (vec![0u8; 256], vec![0u8; 256]);

        match identify_manifest_with_toc(&cdr_bytes, Some(&toc0), Some(&toc1)).unwrap() {
            Identified::Cdr { meta, toc } => {
                assert_eq!(meta.kind, cdr.kind);
                #[cfg(feature = "cdr-bundle")]
                {
                    let toc = toc.expect("newest slot");
                    assert_eq!(toc.seq, 8);
                    assert_eq!(toc.capacity_sectors, 2_000);
                }
                #[cfg(not(feature = "cdr-bundle"))]
                assert!(toc.is_none());
            }
            other => panic!("expected a CD-R bundle, got {other:?}"),
        }

        let flat = meta(BundleKind::Flat {
            virtual_size: 8 << 20,
            chunk_size: 1 << 20,
            sector_size: 512,
        });
        let flat_bytes = flat.encode().unwrap();
        match identify_manifest_with_toc(&flat_bytes, Some(&toc0), Some(&toc1)).unwrap() {
            Identified::Flat { meta } => assert_eq!(meta.kind, flat.kind),
            other => panic!("expected a flat bundle, got {other:?}"),
        }
    }

    #[test]
    fn missing_manifest_reports_present_names_in_order() {
        let dir = TempDir::new("not_bundle");
        dir.write("BUNDLE", b"legacy");
        dir.write("toc.0", b"legacy toc");
        dir.write("000000.img", b"chunk");
        let identified = identify_dir(&mut backend(&dir)).unwrap();
        match identified {
            Identified::NotBundle { found } => {
                assert_eq!(found.as_slice(), &["BUNDLE", "toc.0", "000000.img"]);
            }
            other => panic!("expected NotBundle, got {other:?}"),
        }
    }

    #[test]
    fn rejects_oversized_manifest() {
        let dir = TempDir::new("oversized");
        let mut bytes = vec![b' '; MAX_MANIFEST];
        bytes.push(b'\n');
        dir.write(MANIFEST_NAME, &bytes);
        let err = identify_dir(&mut backend(&dir)).unwrap_err();
        assert_eq!(err, IdentifyError::Manifest(ManifestError::TooLarge));
    }
}
