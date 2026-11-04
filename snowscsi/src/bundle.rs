//! Bundle identification: directory and sidecar manifests.
//!
//! A bundle is identified by its **manifest**, never by a directory listing:
//! `SNOWBUNDLE` inside a bundle directory (or `<file>.SNOWBUNDLE` next to a
//! single-file image). The manifest is the single entry point for the kind,
//! geometry and optional cipher description. A directory without one is
//! reported as [`Identified::NotBundle`], listing the bundle-like names that
//! were found instead.
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
//! `Identified::Cdr` `toc` field is always [`None`]; the header type remains
//! part of the public shape so callers do not need a feature-specific match.

#[cfg(feature = "bundle")]
use crate::common::bundle::{BundleKind, MANIFEST_NAME, MAX_MANIFEST};
use crate::common::bundle::{BundleMeta, ManifestError};
use crate::common::fs_storage::FsError;
#[cfg(feature = "bundle")]
use crate::common::fs_storage::{FsStorage, OpenOptions};

#[cfg(feature = "cdr-bundle")]
pub use crate::mmc::cdr_bundle::TocHeader;

/// Header summary type when the recordable-CD medium is not compiled in.
///
/// The TOC is never probed without `cdr-bundle`, so this type cannot be
/// constructed; it only keeps [`Identified::Cdr`] one shape across features.
#[cfg(not(feature = "cdr-bundle"))]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub struct TocHeader {
    /// Sequence number of the save that produced the slot.
    pub seq: u32,
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
        /// Newest valid plaintext TOC header, when one is present.
        toc: Option<TocHeader>,
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

/// Map a parsed manifest to its [`Identified`] variant.
#[cfg(feature = "bundle")]
fn classify(meta: BundleMeta, toc: Option<TocHeader>) -> Identified {
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

/// Read the first 256 bytes of both TOC slots and keep the newest valid header.
#[cfg(all(feature = "bundle", feature = "cdr-bundle"))]
fn probe_toc<F: FsStorage>(fs: &mut F) -> Result<Option<TocHeader>, IdentifyError> {
    let first = read_toc_header(fs, 0);
    let second = read_toc_header(fs, 1);
    Ok(match (first, second) {
        (Ok(Some(a)), Ok(Some(b))) => Some(if b.newer_than(&a) { b } else { a }),
        (Ok(Some(header)), Ok(None)) | (Ok(None), Ok(Some(header))) => Some(header),
        (Ok(None), Ok(None)) => None,
        // A read error on one slot must not hide a usable other slot.
        (Ok(header), Err(_)) => header,
        (Err(_), Ok(header)) => header,
        (Err(error), Err(_)) => return Err(error),
    })
}

/// Read one TOC header; a missing, short or malformed slot is `None`.
#[cfg(all(feature = "bundle", feature = "cdr-bundle"))]
fn read_toc_header<F: FsStorage>(fs: &mut F, slot: u8) -> Result<Option<TocHeader>, IdentifyError> {
    let path = crate::mmc::cdr_bundle::toc_file(slot);
    let mut file = match fs.open(path, OpenOptions::read_only()) {
        Ok(file) => file,
        Err(FsError::NotFound) => return Ok(None),
        Err(e) => return Err(IdentifyError::Fs(e)),
    };
    let mut header = [0u8; crate::mmc::cdr_bundle::TOC_HEADER_LEN];
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
    fs.close(file);
    if failed || got < header.len() {
        return Ok(None);
    }
    match TocHeader::parse(&header) {
        // A file whose header names the other slot is not a usable summary.
        Ok(header) if header.slot == slot => Ok(Some(header)),
        _ => Ok(None),
    }
}

#[cfg(all(test, feature = "bundle", feature = "std"))]
mod tests {
    use super::*;
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
            use crate::mmc::cdr_bundle::toc::header_bytes;
            use crate::mmc::cdr_bundle::{max_tracks_for_slot, TOC_SLOT_DEFAULT};

            let max_tracks = max_tracks_for_slot(TOC_SLOT_DEFAULT);
            dir.write(
                "toc.0",
                &header_bytes(0, TOC_SLOT_DEFAULT, max_tracks, 1, 0, 5),
            );
            dir.write(
                "toc.1",
                &header_bytes(1, TOC_SLOT_DEFAULT, max_tracks, 1, 0, 7),
            );
            let identified = identify_dir(&mut backend(&dir)).unwrap();
            match identified {
                Identified::Cdr { meta, toc } => {
                    assert_eq!(meta.kind, cdr.kind);
                    assert_eq!(toc.map(|header| header.seq), Some(7));
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
        use crate::mmc::cdr_bundle::toc::header_bytes;
        use crate::mmc::cdr_bundle::{max_tracks_for_slot, TOC_SLOT_DEFAULT};

        let dir = TempDir::new("cdr_one_slot");
        let cdr = meta(BundleKind::Cdr);
        dir.write(MANIFEST_NAME, &cdr.encode().unwrap());

        dir.write("toc.0", b"not a toc");
        let max_tracks = max_tracks_for_slot(TOC_SLOT_DEFAULT);
        dir.write(
            "toc.1",
            &header_bytes(1, TOC_SLOT_DEFAULT, max_tracks, 1, 0, 9),
        );
        let identified = identify_dir(&mut backend(&dir)).unwrap();
        match identified {
            Identified::Cdr { toc, .. } => {
                assert_eq!(toc.map(|header| header.seq), Some(9));
            }
            other => panic!("expected a CD-R bundle, got {other:?}"),
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
