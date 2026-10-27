//! Real-file storage adapter smoke test (`SyncStorage` + `BlockingStorage`).
//!
//! This is the only fixture that talks to a real file descriptor instead of an
//! in-memory storage double: `read`, `write`, `seek`, `flush` and `seal` are
//! mapped onto `StorageReceipt`/`Fault` and the adapter is lifted through the
//! production [`BlockingStorage`] seam.
//!
//! **Scope caveat.** The file lives under `/tmp/opencode` (falling back to
//! `std::env::temp_dir()`), i.e. almost certainly tmpfs. That proves the
//! adapter wiring and the directory/file path only: tmpfs has no stable store
//! below it, so this test says **nothing** about power-loss durability and
//! must not be cited as block-device durability evidence. `File::sync_all` is
//! called because that is what the adapter must do, not because tmpfs can
//! honour it.
//!
//! The fixture skips gracefully (prints and returns) when no writable temp
//! directory exists, and removes the file on every path via a `Drop` guard.

#![cfg(unix)]

use std::fs::{File, OpenOptions};
use std::io::{Read, Seek, SeekFrom, Write};
use std::path::PathBuf;
use std::task::Poll;
use std::time::{SystemTime, UNIX_EPOCH};

use snowscsi::core::storage::{
    BlockingStorage, IoBuf, IoReq, Storage, StorageReceipt, SyncStorage,
};
use snowscsi::core::{Direction, Effect, Fault};

/// `SyncStorage` over one real file.
///
/// Mapping:
///
/// - `Direction::ToHost` + `IoBuf::Read` → seek + `read_exact` (confirmed =
///   bytes read);
/// - `Direction::FromHost` + `IoBuf::Write` → seek + `write_all` (confirmed =
///   bytes written);
/// - `Direction::None` + `IoBuf::None` → flush + `sync_all` ("seal" the file);
/// - anything else → `Fault::Contract`, never a fabricated success.
struct FileStorage {
    file: File,
}

impl FileStorage {
    /// Position the descriptor for the next data transfer.
    fn seek_to(&mut self, offset: u64) -> Result<(), Fault> {
        self.file
            .seek(SeekFrom::Start(offset))
            .map(|_| ())
            .map_err(|_| Fault::Io)
    }

    /// Push user-space bytes to the OS.
    fn flush(&mut self) -> Result<(), Fault> {
        self.file.flush().map_err(|_| Fault::Io)
    }

    /// Flush and ask the OS to persist the file (a no-op guarantee on tmpfs).
    fn seal(&mut self) -> StorageReceipt {
        if let Err(fault) = self.flush() {
            return StorageReceipt::failed(fault, 0, Effect::UnknownRemainder);
        }
        match self.file.sync_all() {
            Ok(()) => StorageReceipt::ok(0),
            // The sync's end was not observed: the remainder is unknown.
            Err(_) => StorageReceipt::failed(Fault::Io, 0, Effect::UnknownRemainder),
        }
    }
}

impl SyncStorage for FileStorage {
    fn exec(&mut self, req: IoReq, buf: IoBuf<'_>) -> StorageReceipt {
        match (req.dir, buf) {
            (Direction::None, IoBuf::None) => self.seal(),
            (Direction::ToHost, IoBuf::Read(bytes)) => {
                if self.seek_to(req.offset).is_err() {
                    return StorageReceipt::failed(Fault::Io, 0, Effect::Known);
                }
                match self.file.read_exact(bytes) {
                    Ok(()) => StorageReceipt::ok(bytes.len()),
                    // A read has no write effect; a short/failed read stays a
                    // known failure with the prefix it really returned.
                    Err(_) => StorageReceipt::failed(Fault::Io, 0, Effect::Known),
                }
            }
            (Direction::FromHost, IoBuf::Write(bytes)) => {
                if self.seek_to(req.offset).is_err() {
                    return StorageReceipt::failed(Fault::Io, 0, Effect::Known);
                }
                match self.file.write_all(bytes) {
                    Ok(()) => StorageReceipt::ok(bytes.len()),
                    // The write may have landed partially: never claim "known".
                    Err(_) => StorageReceipt::failed(Fault::Io, 0, Effect::UnknownRemainder),
                }
            }
            _ => StorageReceipt::failed(Fault::Contract, 0, Effect::Known),
        }
    }
}

/// Remove the temp file on every exit path (including a panic).
struct TempFile(PathBuf);

impl Drop for TempFile {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.0);
    }
}

/// One operation through the production token seam.
fn exec<S: Storage>(storage: &mut S, req: IoReq, buf: IoBuf<'_>) -> StorageReceipt {
    let token = storage.begin_exec(req);
    match storage.poll_exec(token, buf) {
        Poll::Ready(receipt) => receipt,
        Poll::Pending => panic!("BlockingStorage must answer Ready immediately"),
    }
}

fn read<S: Storage>(storage: &mut S, offset: u64, buf: &mut [u8]) -> StorageReceipt {
    exec(
        storage,
        IoReq {
            resource: 0,
            offset,
            len: buf.len() as u32,
            dir: Direction::ToHost,
        },
        IoBuf::Read(buf),
    )
}

fn write<S: Storage>(storage: &mut S, offset: u64, buf: &[u8]) -> StorageReceipt {
    exec(
        storage,
        IoReq {
            resource: 0,
            offset,
            len: buf.len() as u32,
            dir: Direction::FromHost,
        },
        IoBuf::Write(buf),
    )
}

fn sync<S: Storage>(storage: &mut S) -> StorageReceipt {
    exec(
        storage,
        IoReq {
            resource: 0,
            offset: 0,
            len: 0,
            dir: Direction::None,
        },
        IoBuf::None,
    )
}

/// A unique file path in a writable temp directory, or `None` to skip.
fn unique_path() -> Option<PathBuf> {
    let stamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .ok()?
        .as_nanos();
    let name = format!("snowscsi-file-storage-{}-{stamp}.bin", std::process::id());
    // Prefer the workspace-approved temp dir; fall back to the platform one.
    for dir in [PathBuf::from("/tmp/opencode"), std::env::temp_dir()] {
        if !dir.is_dir() {
            continue;
        }
        let probe = dir.join(format!(".{name}.probe"));
        match File::create(&probe) {
            Ok(file) => {
                drop(file);
                let _ = std::fs::remove_file(&probe);
                return Some(dir.join(name));
            }
            Err(_) => continue,
        }
    }
    None
}

/// READ → WRITE → SYNC → read back, with the untouched region verified.
///
/// tmpfs proves the adapter/path, not power-loss durability.
#[test]
fn file_storage_round_trips_through_the_blocking_adapter() {
    let Some(path) = unique_path() else {
        println!("skipping: no writable temp directory");
        return;
    };
    let guard = TempFile(path.clone());

    // Original contents: every byte distinct from the write pattern below.
    let original: Vec<u8> = (0..4096u32).map(|i| (i % 251) as u8).collect();
    {
        let mut file = File::create(&path).expect("create the temp file");
        file.write_all(&original).expect("write the original bytes");
    }

    let file = OpenOptions::new()
        .read(true)
        .write(true)
        .open(&path)
        .expect("reopen the temp file");
    let mut storage = BlockingStorage::new(FileStorage { file });

    // 1. READ the original bytes back through the adapter.
    let mut read_back = vec![0u8; original.len()];
    assert_eq!(
        read(&mut storage, 0, &mut read_back),
        StorageReceipt::ok(original.len())
    );
    assert_eq!(read_back, original, "the READ path is byte-exact");

    // 2. WRITE a new pattern in the middle.
    let pattern = vec![0x5Au8; 1024];
    assert_eq!(
        write(&mut storage, 1024, &pattern),
        StorageReceipt::ok(pattern.len())
    );

    // 3. SYNC (flush + sync_all; durability is the OS's business).
    assert_eq!(sync(&mut storage), StorageReceipt::ok(0));

    // 4. READ the written region back.
    let mut written = vec![0u8; pattern.len()];
    assert_eq!(
        read(&mut storage, 1024, &mut written),
        StorageReceipt::ok(pattern.len())
    );
    assert_eq!(written, pattern, "the written bytes survived the SYNC");

    // 5. The untouched regions keep the original bytes.
    let mut head = vec![0u8; 1024];
    assert_eq!(
        read(&mut storage, 0, &mut head),
        StorageReceipt::ok(head.len())
    );
    assert_eq!(head, original[..1024], "bytes before the write are intact");

    let mut tail = vec![0u8; 2048];
    assert_eq!(
        read(&mut storage, 2048, &mut tail),
        StorageReceipt::ok(tail.len())
    );
    assert_eq!(tail, original[2048..], "bytes after the write are intact");

    // 6. A direction/length mismatch is a contract error, not a silent success.
    let mut tiny = [0u8; 4];
    assert_eq!(
        exec(
            &mut storage,
            IoReq {
                resource: 0,
                offset: 0,
                len: 8,
                dir: Direction::ToHost,
            },
            IoBuf::Read(&mut tiny),
        )
        .error,
        Some(Fault::Contract)
    );

    drop(storage);
    drop(guard);
    assert!(!path.exists(), "the temp file is removed");
}
