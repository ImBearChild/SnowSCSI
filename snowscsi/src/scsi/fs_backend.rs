//! Filesystem backends + re-exports from [`crate::common`].
//!
//! [`FsStorage`], [`FsError`], [`DirEntry`], and [`OpenOptions`] live
//! in `crate::common::fs_storage`. This module adds the std filesystem
//! backend ([`StdFsBackend`]) and the [`StdFile`] adapter.

pub use crate::common::fs_storage::{DirEntry, FsError, FsStorage, OpenOptions};

/// Map `std::io::ErrorKind` → `embedded_io::ErrorKind`.
#[cfg(feature = "std")]
fn map_io_err(kind: std::io::ErrorKind) -> embedded_io::ErrorKind {
    match kind {
        std::io::ErrorKind::NotFound => embedded_io::ErrorKind::NotFound,
        std::io::ErrorKind::PermissionDenied => embedded_io::ErrorKind::PermissionDenied,
        std::io::ErrorKind::AlreadyExists => embedded_io::ErrorKind::AlreadyExists,
        std::io::ErrorKind::InvalidInput => embedded_io::ErrorKind::InvalidInput,
        std::io::ErrorKind::InvalidData => embedded_io::ErrorKind::InvalidData,
        std::io::ErrorKind::TimedOut => embedded_io::ErrorKind::TimedOut,
        std::io::ErrorKind::Interrupted => embedded_io::ErrorKind::Interrupted,
        std::io::ErrorKind::Unsupported => embedded_io::ErrorKind::Unsupported,
        std::io::ErrorKind::BrokenPipe => embedded_io::ErrorKind::BrokenPipe,
        std::io::ErrorKind::ConnectionRefused => embedded_io::ErrorKind::ConnectionRefused,
        std::io::ErrorKind::ConnectionReset => embedded_io::ErrorKind::ConnectionReset,
        std::io::ErrorKind::ConnectionAborted => embedded_io::ErrorKind::ConnectionAborted,
        std::io::ErrorKind::NotConnected => embedded_io::ErrorKind::NotConnected,
        std::io::ErrorKind::AddrInUse => embedded_io::ErrorKind::AddrInUse,
        std::io::ErrorKind::AddrNotAvailable => embedded_io::ErrorKind::AddrNotAvailable,
        _ => embedded_io::ErrorKind::Other,
    }
}

/// Standard library filesystem backend (std feature, `std::fs`).
///
/// Wraps a directory root; all paths are relative to that root.
#[cfg(feature = "std")]
#[derive(Debug)]
pub struct StdFsBackend {
    root: std::path::PathBuf,
}

#[cfg(feature = "std")]
impl StdFsBackend {
    /// Create a new backend rooted at `root`.
    ///
    /// The directory must exist; it is **not** created automatically.
    pub fn new(root: &str) -> Self {
        Self {
            root: std::path::PathBuf::from(root),
        }
    }

    fn full_path(&self, relative: &str) -> std::path::PathBuf {
        self.root.join(relative)
    }
}

#[cfg(feature = "std")]
impl FsStorage for StdFsBackend {
    type File = StdFile;

    fn open(&mut self, path: &str, opts: OpenOptions) -> Result<StdFile, FsError> {
        let full = self.full_path(path);
        let mut oopts = std::fs::OpenOptions::new();
        oopts
            .read(opts.read)
            .write(opts.write)
            .create(opts.create)
            .truncate(opts.truncate);
        let file = oopts.open(&full).map_err(|e| {
            crate::warn!("std fs open {:?} failed: {}", full, e);
            match e.kind() {
                std::io::ErrorKind::NotFound => FsError::NotFound,
                other => FsError::Io(map_io_err(other)),
            }
        })?;
        Ok(StdFile::new(file))
    }

    fn close(&mut self, _file: StdFile) {
        // File is dropped here — embedded-io has no explicit close.
    }

    fn read_dir(&mut self, path: &str, out: &mut [DirEntry]) -> Result<usize, FsError> {
        let full = self.full_path(path);
        let entries = std::fs::read_dir(&full).map_err(|e| match e.kind() {
            std::io::ErrorKind::NotFound => FsError::NotFound,
            other => FsError::Io(map_io_err(other)),
        })?;
        let mut count = 0;
        for entry in entries {
            if count >= out.len() {
                break;
            }
            let entry = entry.map_err(|e| FsError::Io(map_io_err(e.kind())))?;
            let metadata = entry
                .metadata()
                .map_err(|e| FsError::Io(map_io_err(e.kind())))?;
            let file_name = entry.file_name();
            let name_str = file_name.to_string_lossy();
            let mut name = heapless::String::<256>::new();
            for ch in name_str.chars().take(256) {
                let _ = name.push(ch);
            }
            out[count] = DirEntry {
                name,
                is_dir: metadata.is_dir(),
                size: metadata.len(),
            };
            count += 1;
        }
        Ok(count)
    }

    fn root(&self) -> &str {
        self.root.to_str().unwrap_or("")
    }

    fn sync(&mut self) -> Result<(), FsError> {
        // No open file table to flush in the new FsStorage model.
        Ok(())
    }

    fn remove(&mut self, path: &str) -> Result<(), FsError> {
        let full = self.full_path(path);
        std::fs::remove_file(&full).map_err(|e| match e.kind() {
            std::io::ErrorKind::NotFound => FsError::NotFound,
            other => FsError::Io(map_io_err(other)),
        })
    }
}

/// StdFile adapter — wraps `std::fs::File` as an `embedded_io::Read +
/// Write + Seek` stream for use as `FsStorage::File`.
#[cfg(feature = "std")]
#[derive(Debug)]
pub struct StdFile {
    file: std::fs::File,
}

#[cfg(feature = "std")]
impl StdFile {
    pub fn new(file: std::fs::File) -> Self {
        Self { file }
    }
}

#[cfg(feature = "std")]
impl embedded_io::ErrorType for StdFile {
    type Error = embedded_io::ErrorKind;
}

#[cfg(feature = "std")]
impl embedded_io::Read for StdFile {
    fn read(&mut self, buf: &mut [u8]) -> Result<usize, Self::Error> {
        use std::io::Read;
        Read::read(&mut self.file, buf).map_err(|e| {
            crate::warn!("std file read({} bytes) failed: {}", buf.len(), e);
            map_io_err(e.kind())
        })
    }
}

#[cfg(feature = "std")]
impl embedded_io::Write for StdFile {
    fn write(&mut self, buf: &[u8]) -> Result<usize, Self::Error> {
        use std::io::Write;
        Write::write(&mut self.file, buf).map_err(|e| {
            crate::warn!("std file write({} bytes) failed: {}", buf.len(), e);
            map_io_err(e.kind())
        })
    }

    fn flush(&mut self) -> Result<(), Self::Error> {
        use std::io::Write;
        Write::flush(&mut self.file).map_err(|e| {
            crate::warn!("std file flush failed: {}", e);
            map_io_err(e.kind())
        })
    }
}

#[cfg(feature = "std")]
impl embedded_io::Seek for StdFile {
    fn seek(&mut self, pos: embedded_io::SeekFrom) -> Result<u64, Self::Error> {
        use std::io::Seek;
        let std_pos = match pos {
            embedded_io::SeekFrom::Start(off) => std::io::SeekFrom::Start(off),
            embedded_io::SeekFrom::Current(off) => std::io::SeekFrom::Current(off),
            embedded_io::SeekFrom::End(off) => std::io::SeekFrom::End(off),
        };
        Seek::seek(&mut self.file, std_pos).map_err(|e| {
            crate::warn!("std file seek({:?}) failed: {}", std_pos, e);
            map_io_err(e.kind())
        })
    }
}

#[cfg(feature = "std")]
#[cfg(test)]
mod tests {
    use super::*;

    fn temp_dir(name: &str) -> std::path::PathBuf {
        let dir = std::env::temp_dir().join(format!("snowscsi_fs_{}_{}", name, std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    #[test]
    fn open_read_only_existing_file() {
        let dir = temp_dir("ro_open");
        std::fs::write(dir.join("test.txt"), b"hello").unwrap();
        let mut fs = StdFsBackend::new(&dir.to_string_lossy());
        let mut f = fs.open("test.txt", OpenOptions::read_only()).unwrap();
        let mut buf = [0u8; 16];
        use embedded_io::Read;
        let n = f.read(&mut buf).unwrap();
        assert_eq!(&buf[..n], b"hello");
        fs.close(f);
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn open_read_only_missing_file() {
        let dir = temp_dir("ro_missing");
        let mut fs = StdFsBackend::new(&dir.to_string_lossy());
        let r = fs.open("nope.txt", OpenOptions::read_only());
        assert!(matches!(r, Err(FsError::NotFound)));
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn open_or_create_creates_new() {
        let dir = temp_dir("oc_create");
        let mut fs = StdFsBackend::new(&dir.to_string_lossy());
        let mut f = fs.open("new.txt", OpenOptions::open_or_create()).unwrap();
        use embedded_io::Write;
        f.write_all(b"created").unwrap();
        fs.close(f);
        fs.sync().unwrap();
        assert_eq!(std::fs::read(dir.join("new.txt")).unwrap(), b"created");
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn read_dir_lists_entries() {
        let dir = temp_dir("readdir");
        std::fs::write(dir.join("a.txt"), b"a").unwrap();
        std::fs::write(dir.join("b.txt"), b"bb").unwrap();
        std::fs::create_dir(dir.join("sub")).unwrap();
        let mut fs = StdFsBackend::new(&dir.to_string_lossy());
        let mut entries: [DirEntry; 8] = core::array::from_fn(|_| DirEntry {
            name: heapless::String::new(),
            is_dir: false,
            size: 0,
        });
        let n = fs.read_dir(".", &mut entries).unwrap();
        assert!(n >= 3);
        let names: Vec<&str> = entries[..n].iter().map(|e| e.name.as_str()).collect();
        assert!(names.contains(&"a.txt"));
        assert!(names.contains(&"b.txt"));
        assert!(names.contains(&"sub"));
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn remove_file() {
        let dir = temp_dir("remove");
        std::fs::write(dir.join("gone.txt"), b"bye").unwrap();
        let mut fs = StdFsBackend::new(&dir.to_string_lossy());
        fs.remove("gone.txt").unwrap();
        assert!(!dir.join("gone.txt").exists());
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn root_path() {
        let dir = temp_dir("root");
        let fs = StdFsBackend::new(&dir.to_string_lossy());
        assert_eq!(fs.root(), dir.to_str().unwrap());
        std::fs::remove_dir_all(&dir).unwrap();
    }
}
