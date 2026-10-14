//! Cross-validation of the live ISO9660 generator against an independent
//! parser (`iso9660-no-std`, a permissive MIT/Apache-2.0 pure-Rust ISO
//! 9660 reader). This is a pure test dependency: it verifies that the
//! image our generator produces is readable by a spec-strict third-party
//! implementation, and that the tree structure, names, sizes and file
//! contents all match the host directory.

use std::io::Cursor;
use std::path::Path;
use std::path::PathBuf;

use iso9660_no_std::{DirectoryEntry, ISO9660Reader, ISODirectory, ISO9660};

use snowscsi::cdrom::media::LiveData;
use snowscsi::common::seekable_storage::FlatData;
use snowscsi::scsi::fs_backend::StdFsBackend;
use snowscsi_iso9660::live::{MAX_JOLIET_NAME_CHARS, SECTOR_SIZE};

/// Wrap a `std::io::Cursor` so it implements `embedded_io::{Read, Seek}`
/// (the trait `iso9660-no-std` reads through). `read_at` seeks per LBA.
struct CursorReader<'a> {
    cursor: Cursor<&'a [u8]>,
}

impl embedded_io::ErrorType for CursorReader<'_> {
    type Error = embedded_io::ErrorKind;
}

impl embedded_io::Read for CursorReader<'_> {
    fn read(&mut self, buf: &mut [u8]) -> Result<usize, Self::Error> {
        use std::io::Read as _;
        self.cursor
            .read(buf)
            .map_err(|_| embedded_io::ErrorKind::Other)
    }
}

impl embedded_io::Seek for CursorReader<'_> {
    fn seek(&mut self, pos: embedded_io::SeekFrom) -> Result<u64, Self::Error> {
        use std::io::Seek as _;
        let from = match pos {
            embedded_io::SeekFrom::Start(s) => std::io::SeekFrom::Start(s),
            embedded_io::SeekFrom::End(s) => std::io::SeekFrom::End(s),
            embedded_io::SeekFrom::Current(s) => std::io::SeekFrom::Current(s),
        };
        self.cursor
            .seek(from)
            .map_err(|_| embedded_io::ErrorKind::Other)
    }
}

/// Build a host tree under a fresh temp dir and return `(dir, files)`
/// where `files` is `(relative_path, content)`.
fn build_tree() -> (PathBuf, Vec<(String, Vec<u8>)>) {
    let dir = std::env::temp_dir().join(format!("snowscsi_iso_cross_{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(dir.join("docs/deep")).unwrap();
    std::fs::create_dir_all(dir.join("images")).unwrap();

    let mut files: Vec<(String, Vec<u8>)> = Vec::new();
    let mut add = |path: &str, content: Vec<u8>| {
        std::fs::write(dir.join(path), &content).unwrap();
        files.push((path.to_string(), content));
    };
    add("README.TXT", b"hello root".to_vec());
    add("docs/manual.pdf", vec![0x41u8; 2049]); // crosses one sector boundary
    add("docs/deep/notes.txt", vec![0x42u8; 100]);
    add("images/photo.png", vec![0x43u8; 4096]);
    // Exactly MAX_JOLIET_NAME_CHARS characters (including extension):
    // must be preserved whole.
    let exact = format!("{}.TXT", "A".repeat(MAX_JOLIET_NAME_CHARS - 4));
    assert_eq!(exact.chars().count(), MAX_JOLIET_NAME_CHARS);
    add(&exact, b"exact fit".to_vec());
    // One character over: must be truncated to MAX_JOLIET_NAME_CHARS.
    let over = format!("{}.DAT", "B".repeat(MAX_JOLIET_NAME_CHARS + 1));
    add(&over, b"over limit".to_vec());
    (dir, files)
}

/// Dump the whole live image (all sectors) to a `Vec<u8>`.
fn build_image(dir: &Path) -> Vec<u8> {
    let fs = StdFsBackend::new(&dir.to_string_lossy());
    // `LiveData` is itself the read-only `FlatData` plane (media no longer
    // wraps a backend), so read the generated ISO directly through it.
    let mut live = LiveData::new(fs, "CROSS").expect("scan tree");
    let total = live.layout().total as usize;
    let mut img = vec![0u8; total * SECTOR_SIZE as usize];
    for lba in 0..total as u32 {
        let start = lba as usize * SECTOR_SIZE as usize;
        FlatData::read_at(
            &mut live,
            lba as u64 * SECTOR_SIZE as u64,
            &mut img[start..start + SECTOR_SIZE as usize],
        )
        .expect("read sector");
    }
    img
}

/// Recursively collect (relative path, size, content) from a cdfs dir.
fn walk<T: ISO9660Reader>(
    dir: &ISODirectory<T>,
    prefix: &str,
    out: &mut Vec<(String, u64, Vec<u8>)>,
) {
    use embedded_io::Read as _;
    for entry in dir.contents() {
        let entry = entry.expect("cdfs entry");
        let id = entry.identifier().to_string();
        if id.is_empty() || id == "." || id == ".." {
            continue;
        }
        let path = if prefix.is_empty() {
            id
        } else {
            format!("{prefix}/{id}")
        };
        match entry {
            DirectoryEntry::Directory(d) => walk(&d, &path, out),
            DirectoryEntry::File(f) => {
                let mut content = Vec::new();
                // ISOFileReader implements embedded_io::Read (no
                // read_to_end), so loop manually.
                let mut reader = f.read();
                let mut buf = [0u8; 2048];
                loop {
                    let n = reader.read(&mut buf).expect("read file");
                    if n == 0 {
                        break;
                    }
                    content.extend_from_slice(&buf[..n]);
                }
                out.push((path, content.len() as u64, content));
            }
        }
    }
}

#[test]
fn live_image_reads_back_through_iso9660_reader() {
    let (dir, host_files) = build_tree();
    let img = build_image(&dir);
    // iso9660-no-std picks the most featureful root: Joliet (SVD) over the
    // PVD, and decodes UCS-2BE names.
    let iso = ISO9660::new(CursorReader {
        cursor: Cursor::new(&img),
    })
    .expect("reader open image");

    let mut iso_files: Vec<(String, u64, Vec<u8>)> = Vec::new();
    walk(&iso.root, "", &mut iso_files);

    // Every host file is present with matching size and content (the
    // over-limit file is truncated, so it is checked separately below).
    let over = format!("{}.DAT", "B".repeat(MAX_JOLIET_NAME_CHARS + 1));
    for (path, content) in host_files.iter().filter(|(p, _)| *p != over) {
        let expected = content.len() as u64;
        let found = iso_files
            .iter()
            .find(|(p, _, _)| p == path)
            .unwrap_or_else(|| panic!("file {path} missing from the image; found: {iso_files:#?}"));
        assert_eq!(found.1, expected, "size mismatch for {path}");
        assert_eq!(&found.2, content, "content mismatch for {path}");
    }
    assert_eq!(
        iso_files.len(),
        host_files.len(),
        "the image must not contain extra files"
    );

    // The over-limit name is truncated to MAX_JOLIET_NAME_CHARS in the ISO
    // (the ".DAT" extension is cut off too).
    let truncated = "B".repeat(MAX_JOLIET_NAME_CHARS);
    let over_iso = iso_files
        .iter()
        .find(|(p, _, _)| *p == truncated)
        .expect("over-limit file present (truncated)");
    assert_eq!(over_iso.0, truncated);
    assert_ne!(over_iso.0, over);

    let _ = std::fs::remove_dir_all(&dir);
}
