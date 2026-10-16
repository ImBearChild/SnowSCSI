//! Cross-crate integration tests for the two-store plane vocabulary:
//! [`StorePlane`] dispatch over a real
//! [`RamBackend`] block plane and an [`FsPlaneAdapter`] over the real
//! [`StdFsBackend`] filesystem.
//!
//! These are the end-to-end tests the `snowscsi-common` unit tests cannot be:
//! they drive the erased plane seam from *outside* the crate, exactly the way
//! a transport's `serve` loop does (`luns.planes[lun].do_op(op)`), and back the
//! FS plane with a real on-disk directory so `std::fs` page-cache semantics and
//! the path → handle LRU are exercised for real.
//!
//! Deterministic: no clock, no RNG — fixed patterns and offsets only.

use std::path::PathBuf;

use snowscsi::common::fs_plane::{FsPlane, FsPlaneAdapter};
use snowscsi::common::seekable_storage::{RamBackend, StorageError};
use snowscsi::common::store::{StoreOp, StorePlane};
use snowscsi::scsi::fs_backend::{DirEntry, StdFsBackend};

/// Fresh per-process, per-test temp directory (mirrors `bundle.rs`).
fn temp_dir(name: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!(
        "snowscsi_store_plane_{}_{name}",
        std::process::id()
    ));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    dir
}

/// A zeroed [`DirEntry`] batch for `read_dir`.
///
/// `DirEntry::name` is a `heapless::String<256>`, which this crate does not
/// depend on directly — but `Default::default()` infers the field's type from
/// the struct literal, so no `heapless` path is ever named here.
fn empty_entries<const N: usize>() -> [DirEntry; N] {
    core::array::from_fn(|_| DirEntry {
        name: Default::default(),
        is_dir: false,
        size: 0,
    })
}

/// Scan `path` through the `FsPlane` seam, returning `(count, entries)`.
fn read_dir_entries<const N: usize>(plane: &mut dyn FsPlane, path: &str) -> (usize, [DirEntry; N]) {
    let mut entries: [DirEntry; N] = empty_entries();
    let n = plane.read_dir(path, &mut entries).unwrap();
    (n, entries)
}

/// 1. `BlockRw` over a `RamBackend`: `Write`→`Read` roundtrip, `Fill`→`Read`,
///    and plane-level `Sync`.
#[test]
fn store_plane_block_rw_write_read_fill_sync() {
    let mut ram = [0u8; 1024];
    let pattern: &[u8] = b"hello snowscsi store plane";

    {
        let mut backend = RamBackend::new(&mut ram);
        let mut plane = StorePlane::BlockRw(&mut backend);

        // Write then read back through the erased plane.
        plane
            .do_op(StoreOp::Write {
                off: 100,
                buf: pattern,
            })
            .unwrap();
        let mut out = [0u8; 26];
        plane
            .do_op(StoreOp::Read {
                off: 100,
                buf: &mut out,
            })
            .unwrap();
        assert_eq!(&out, pattern);

        // Fill a region, read it back.
        plane
            .do_op(StoreOp::Fill {
                off: 200,
                len: 64,
                byte: 0xA5,
            })
            .unwrap();
        let mut filled = [0u8; 64];
        plane
            .do_op(StoreOp::Read {
                off: 200,
                buf: &mut filled,
            })
            .unwrap();
        assert_eq!(filled, [0xA5; 64]);

        // Plane-level Sync: both the op form and the method form.
        plane.do_op(StoreOp::Sync).unwrap();
        assert_eq!(plane.sync(), Ok(()));
    }

    // The writes really landed in the backing RAM.
    assert_eq!(&ram[100..100 + pattern.len()], pattern);
    assert_eq!(&ram[200..264], &[0xA5; 64]);
}

/// 2. `BlockRo` over a `RamBackend`: `Read` works, `Write`/`Fill` are rejected
///    as a *policy* error (`NotWritable`), not a generic I/O failure.
#[test]
fn store_plane_block_ro_reads_but_rejects_writes() {
    let mut ram = [0u8; 512];
    ram[..4].copy_from_slice(b"data");

    let mut backend = RamBackend::new(&mut ram);
    let mut plane = StorePlane::BlockRo(&mut backend);

    let mut out = [0u8; 4];
    plane
        .do_op(StoreOp::Read {
            off: 0,
            buf: &mut out,
        })
        .unwrap();
    assert_eq!(&out, b"data");

    assert_eq!(
        plane.do_op(StoreOp::Write {
            off: 0,
            buf: b"xxxx",
        }),
        Err(StorageError::NotWritable)
    );
    assert_eq!(
        plane.do_op(StoreOp::Fill {
            off: 0,
            len: 8,
            byte: 0,
        }),
        Err(StorageError::NotWritable)
    );

    // The rejected writes did not corrupt the data.
    let mut check = [0u8; 4];
    plane
        .do_op(StoreOp::Read {
            off: 0,
            buf: &mut check,
        })
        .unwrap();
    assert_eq!(&check, b"data");
}

/// 3. op × plane model mismatch → `Unsupported` (not `NotWritable`):
///    an FS op on a block plane, and a block op on an FS plane.
#[test]
fn store_plane_op_plane_mismatch_is_unsupported() {
    // FS op on a BlockRw plane.
    let mut ram = [0u8; 256];
    let mut backend = RamBackend::new(&mut ram);
    let mut block = StorePlane::BlockRw(&mut backend);
    let mut fbuf = [0u8; 4];
    assert_eq!(
        block.do_op(StoreOp::FileRead {
            path: "toc.bin",
            off: 0,
            buf: &mut fbuf,
        }),
        Err(StorageError::Unsupported)
    );
    assert_eq!(
        block.do_op(StoreOp::FileRemove { path: "toc.bin" }),
        Err(StorageError::Unsupported)
    );

    // Block op on an Fs plane.
    let dir = temp_dir("mismatch");
    let dir_str = dir.to_string_lossy().into_owned();
    let mut adapter: FsPlaneAdapter<StdFsBackend> =
        FsPlaneAdapter::new(StdFsBackend::new(&dir_str));
    {
        let mut fs = StorePlane::Fs(&mut adapter);
        let mut bbuf = [0u8; 4];
        assert_eq!(
            fs.do_op(StoreOp::Read {
                off: 0,
                buf: &mut bbuf,
            }),
            Err(StorageError::Unsupported)
        );
        assert_eq!(
            fs.do_op(StoreOp::Write {
                off: 0,
                buf: b"xxxx",
            }),
            Err(StorageError::Unsupported)
        );
        assert_eq!(
            fs.do_op(StoreOp::Fill {
                off: 0,
                len: 4,
                byte: 0,
            }),
            Err(StorageError::Unsupported)
        );
    }
    std::fs::remove_dir_all(&dir).unwrap();
}

/// 4. `FsPlaneAdapter` over a real `StdFsBackend` directory: `FileWrite` /
///    `FileRead` roundtrip, `FileRemove`, `read_dir`, `Sync` — with `std::fs`
///    assertions on what actually hit the disk.
#[test]
fn store_plane_fs_file_roundtrip_remove_readdir_sync() {
    let dir = temp_dir("fs");
    let dir_str = dir.to_string_lossy().into_owned();

    // Seed two files with plain std so `read_dir` has something to find.
    std::fs::write(dir.join("a.bin"), b"aaa").unwrap();
    std::fs::write(dir.join("b.bin"), b"bb").unwrap();

    let mut adapter: FsPlaneAdapter<StdFsBackend> =
        FsPlaneAdapter::new(StdFsBackend::new(&dir_str));

    {
        let mut plane = StorePlane::Fs(&mut adapter);

        // Two disjoint writes to the same path (random-access, offset-addressed).
        plane
            .do_op(StoreOp::FileWrite {
                path: "toc.bin",
                off: 0,
                buf: b"0123456789",
            })
            .unwrap();
        plane
            .do_op(StoreOp::FileWrite {
                path: "toc.bin",
                off: 10,
                buf: b"abcdef",
            })
            .unwrap();
        plane.do_op(StoreOp::Sync).unwrap();

        let mut out = [0u8; 16];
        plane
            .do_op(StoreOp::FileRead {
                path: "toc.bin",
                off: 0,
                buf: &mut out,
            })
            .unwrap();
        assert_eq!(&out, b"0123456789abcdef");

        // Read a sub-range at an offset.
        let mut mid = [0u8; 4];
        plane
            .do_op(StoreOp::FileRead {
                path: "toc.bin",
                off: 8,
                buf: &mut mid,
            })
            .unwrap();
        assert_eq!(&mid, b"89ab");
    }

    // The bytes are visible to the OS.
    assert_eq!(
        std::fs::read(dir.join("toc.bin")).unwrap().as_slice(),
        b"0123456789abcdef".as_slice()
    );

    // `read_dir` through the FsPlane seam lists the three files.
    let (n, entries) = read_dir_entries::<16>(&mut adapter, ".");
    let mut names: Vec<String> = entries[..n]
        .iter()
        .map(|e| e.name.as_str().to_owned())
        .collect();
    names.sort();
    assert!(names.contains(&"a.bin".to_string()), "names = {names:?}");
    assert!(names.contains(&"b.bin".to_string()), "names = {names:?}");
    assert!(names.contains(&"toc.bin".to_string()), "names = {names:?}");
    // Sizes come through the entry.
    let a = entries[..n]
        .iter()
        .find(|e| e.name.as_str() == "a.bin")
        .unwrap();
    assert_eq!(a.size, 3);
    assert!(!a.is_dir);

    // `FileRemove` through the plane deletes it on disk.
    {
        let mut plane = StorePlane::Fs(&mut adapter);
        plane
            .do_op(StoreOp::FileRemove { path: "toc.bin" })
            .unwrap();
    }
    assert!(!dir.join("toc.bin").exists());

    // A full/empty buffer does not imply exhaustion — zero-length scan is Ok(0).
    let (n0, _) = read_dir_entries::<0>(&mut adapter, ".");
    assert_eq!(n0, 0);

    drop(adapter);
    std::fs::remove_dir_all(&dir).unwrap();
}

/// 5. LRU eviction: an `FsPlaneAdapter` with only 2 handle slots must survive
///    touching 3 distinct files (evicting via `close`), and every read still
///    returns the right bytes.
#[test]
fn store_plane_fs_lru_evicts_and_reads_stay_correct() {
    let dir = temp_dir("lru");
    let dir_str = dir.to_string_lossy().into_owned();
    let mut adapter: FsPlaneAdapter<StdFsBackend, 2> =
        FsPlaneAdapter::new(StdFsBackend::new(&dir_str));

    let names = ["f0.bin", "f1.bin", "f2.bin"];
    let patterns: [u8; 3] = [0x10, 0x20, 0x30];

    {
        let mut plane = StorePlane::Fs(&mut adapter);

        // Write three distinct files through a 2-slot cache → at least one
        // eviction must happen without panicking.
        for (name, pat) in names.iter().zip(patterns.iter()) {
            let data = [*pat; 32];
            plane
                .do_op(StoreOp::FileWrite {
                    path: name,
                    off: 0,
                    buf: &data,
                })
                .unwrap();
        }
        plane.do_op(StoreOp::Sync).unwrap();

        // Interleaved re-reads, twice around, keep forcing evictions.
        for _ in 0..2 {
            for (name, pat) in names.iter().zip(patterns.iter()) {
                let mut out = [0u8; 32];
                plane
                    .do_op(StoreOp::FileRead {
                        path: name,
                        off: 0,
                        buf: &mut out,
                    })
                    .unwrap();
                assert_eq!(out, [*pat; 32], "read of {name} corrupted");
            }
        }
    }

    // All three landed on disk with their own pattern.
    for (name, pat) in names.iter().zip(patterns.iter()) {
        assert_eq!(std::fs::read(dir.join(name)).unwrap(), vec![*pat; 32]);
    }

    drop(adapter);
    std::fs::remove_dir_all(&dir).unwrap();
}
