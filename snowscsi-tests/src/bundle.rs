//! FlatBundle integration tests.
//!
//! Unlike the `snowscsi-common` unit tests (in-memory mock FS), these drive
//! a **real** `StdFsBackend` over an on-disk directory — exercising the
//! seek-past-EOF extension and OS page-cache semantics of `std::fs` — and run
//! the whole thing through `BlockDevice` (SBC READ/WRITE/READ CAPACITY),
//! which is exactly the plane the CLI serves over iSCSI/USB.

use std::path::PathBuf;

use snowscsi::common::flat_bundle::FlatBundle;
use snowscsi::common::seekable_storage::{FlatData, RwRef, StorageError, WritableFlatData};
use snowscsi::common::store::StorePlane;
use snowscsi::scsi::block::BlockDevice;
use snowscsi::scsi::device::{CommandOutcome, Xfer};
use snowscsi::scsi::fs_backend::StdFsBackend;
use snowscsi::MIN_DATA_LEN;

const SECTOR: u32 = 512;
const READ_10: u8 = 0x28;
const WRITE_10: u8 = 0x2A;
const READ_CAPACITY_10: u8 = 0x25;

fn temp_dir(name: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!("snowscsi_bundle_{}_{name}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    dir
}

fn make_cdb10(opcode: u8, lba: u32, count: u16) -> [u8; 10] {
    let mut cdb = [0u8; 10];
    cdb[0] = opcode;
    cdb[2] = (lba >> 24) as u8;
    cdb[3] = (lba >> 16) as u8;
    cdb[4] = (lba >> 8) as u8;
    cdb[5] = lba as u8;
    cdb[7] = (count >> 8) as u8;
    cdb[8] = count as u8;
    cdb
}

/// SBC block device over a real-directory FlatBundle (512-byte sectors).
///
/// The constructor borrows the bundle once for geometry and releases it; the
/// data phase hands the caller a `Store` op, which the helpers below execute
/// through a [`StorePlane`] over the same bundle.
fn dev(bundle: &mut FlatBundle<StdFsBackend>) -> BlockDevice {
    BlockDevice::disk(&mut RwRef::new(bundle), SECTOR).unwrap()
}

fn work() -> Vec<u8> {
    vec![0u8; MIN_DATA_LEN]
}

/// READ(10) `count` sectors starting at `lba` into `out`.
fn read_sectors(
    dev: &mut BlockDevice,
    bundle: &mut FlatBundle<StdFsBackend>,
    lba: u32,
    count: u16,
    work: &mut [u8],
    out: &mut [u8],
) {
    let cdb = make_cdb10(READ_10, lba, count);
    match dev.do_cmd(&cdb, work).unwrap() {
        CommandOutcome::OutXfer { len } => {
            let n = len as usize;
            assert!(n <= out.len());
            match dev.xfer_out(0, &mut out[..n]) {
                Xfer::Store(op) => {
                    StorePlane::BlockRw(bundle).do_op(op).unwrap();
                }
                other => panic!("READ(10) expected Store, got {other:?}"),
            }
        }
        other => panic!("READ(10) expected OutXfer, got {other:?}"),
    }
}

/// WRITE(10) `count` sectors starting at `lba` from `src`.
fn write_sectors(
    dev: &mut BlockDevice,
    bundle: &mut FlatBundle<StdFsBackend>,
    lba: u32,
    count: u16,
    work: &mut [u8],
    src: &[u8],
) {
    let cdb = make_cdb10(WRITE_10, lba, count);
    let bytes = count as usize * SECTOR as usize;
    match dev.do_cmd(&cdb, work).unwrap() {
        CommandOutcome::InXfer { len } => {
            assert_eq!(len as usize, bytes);
            match dev.xfer_in(0, &src[..bytes]) {
                Xfer::Store(op) => {
                    StorePlane::BlockRw(bundle).do_op(op).unwrap();
                }
                other => panic!("WRITE(10) expected Store, got {other:?}"),
            }
        }
        other => panic!("WRITE(10) expected InXfer, got {other:?}"),
    }
}

#[test]
fn bundle_block_device_roundtrip() {
    let dir = temp_dir("scsi");
    let bundle = FlatBundle::new(
        StdFsBackend::new(&dir.to_string_lossy()),
        1 << 20,
        8 << 20,
        SECTOR,
    )
    .unwrap();
    let mut bundle = bundle;
    let mut dev = dev(&mut bundle);
    let mut w = work();

    let pattern: Vec<u8> = (0..4096).map(|i| (i & 0xFF) as u8).collect();
    write_sectors(&mut dev, &mut bundle, 16, 8, &mut w, &pattern);

    // Read back through SCSI.
    let mut out = vec![0u8; 4096];
    read_sectors(&mut dev, &mut bundle, 16, 8, &mut w, &mut out);
    assert_eq!(out, pattern);

    // Unwritten sectors read as zeros (missing-chunk + intra-chunk holes).
    let mut hole = vec![0u8; 4096];
    read_sectors(&mut dev, &mut bundle, 0, 8, &mut w, &mut hole);
    assert_eq!(hole, vec![0u8; 4096]);

    // READ CAPACITY reports virtual_size / sector_size.
    let mut cap_cdb = [0u8; 10];
    cap_cdb[0] = READ_CAPACITY_10;
    let outcome = dev.do_cmd(&cap_cdb, &mut w).unwrap();
    let mut buf = [0u8; 8];
    match outcome {
        CommandOutcome::OutInline { len } => {
            assert_eq!(len, 8);
            buf[..8].copy_from_slice(&w[..8]);
        }
        other => panic!("READ CAPACITY expected OutInline, got {other:?}"),
    }
    let max_lba = u32::from_be_bytes([buf[0], buf[1], buf[2], buf[3]]);
    let block_size = u32::from_be_bytes([buf[4], buf[5], buf[6], buf[7]]);
    assert_eq!(max_lba, (8 << 20) / 512 - 1);
    assert_eq!(block_size, SECTOR);

    // Chunks are created on demand on the real filesystem.
    let paths = std::fs::read_dir(&dir)
        .unwrap()
        .map(|e| e.unwrap().file_name());
    let names: Vec<String> = paths.map(|n| n.to_string_lossy().into_owned()).collect();
    assert!(names.iter().any(|n| n == "000000.img"));

    std::fs::remove_dir_all(&dir).unwrap();
}

/// Shadow-buffer stress: the same kind of random, multi-size, chunk-straddling
/// block I/O that `mkfs.ext4` performs, over a 32 MiB / 1 MiB-chunk bundle.
#[test]
fn bundle_stress_random_writes_match_shadow() {
    let size: u64 = 32 << 20;
    let chunk: u64 = 1 << 20;
    let dir = temp_dir("stress");
    let dir_str = dir.to_string_lossy().into_owned();
    let mut bundle = FlatBundle::new(StdFsBackend::new(&dir_str), chunk, size, SECTOR).unwrap();

    let mut shadow = vec![0u8; size as usize];
    let mut s: u64 = 0x1234_5678_9abc_def0;
    let mut next = move || {
        s ^= s << 13;
        s ^= s >> 7;
        s ^= s << 17;
        s
    };
    let lens: [usize; 5] = [512, 4096, 65536, 131072, 262144];

    for i in 0..3000u64 {
        let len = lens[(next() % lens.len() as u64) as usize];
        let max_off = size as usize - len;
        let off = ((next() as usize) % (max_off / SECTOR as usize + 1)) * SECTOR as usize;
        let buf: Vec<u8> = (0..len)
            .map(|j| (((off + j) as u64).wrapping_mul(31).wrapping_add(i)) as u8)
            .collect();
        bundle.write_at(off as u64, &buf).unwrap();
        shadow[off..off + len].copy_from_slice(&buf);
    }

    bundle.sync().unwrap();

    // Read the whole device back and compare against the shadow.
    let mut out = vec![0u8; size as usize];
    bundle.read_at(0, &mut out).unwrap();
    let first_bad = out.iter().zip(shadow.iter()).position(|(a, b)| a != b);
    assert_eq!(first_bad, None, "first mismatch at byte {:?}", first_bad);

    std::fs::remove_dir_all(&dir).unwrap();
}

/// A read of an existing chunk (caching a read-only handle) followed by a
/// write to the same chunk must not reuse the read-only handle — `write(2)`
/// on a read-only fd is EBADF. This is the regression for the black-box
/// mkfs failure (chunk boundaries that were read before being written).
#[test]
fn bundle_read_then_write_same_chunk() {
    let dir = temp_dir("read_then_write");
    let dir_str = dir.to_string_lossy().into_owned();

    {
        let mut b =
            FlatBundle::create(StdFsBackend::new(&dir_str), 1 << 20, 4 << 20, SECTOR).unwrap();
        b.write_at(0, &[0x11; 4096]).unwrap();
        b.sync().unwrap();
    }

    // Chunk 0 now exists on disk but is not cached by this instance.
    let mut b = FlatBundle::open(StdFsBackend::new(&dir_str), None, None, None).unwrap();
    let mut out = vec![0u8; 4096];
    b.read_at(0, &mut out).unwrap(); // caches a read-only handle
    assert_eq!(out, vec![0x11; 4096]);
    b.write_at(0, &[0x22; 4096]).unwrap(); // must reopen read-write
    b.read_at(0, &mut out).unwrap();
    assert_eq!(out, vec![0x22; 4096]);

    std::fs::remove_dir_all(&dir).unwrap();
}

/// Randomized mixed READ/WRITE with periodic drop+reopen, validated against a
/// shadow buffer. Deliberately does not assume a bug shape: a random mix over
/// more chunks than `MAX_OPEN_CHUNKS`, plus persistence boundaries, exercises
/// read-before-write, LRU eviction, cross-chunk and hole paths together.
#[test]
fn bundle_mixed_random_io_with_reopen_matches_shadow() {
    let size: u64 = 32 << 20;
    let chunk: u64 = 1 << 20;
    let dir = temp_dir("mixed_io");
    let dir_str = dir.to_string_lossy().into_owned();

    {
        let mut b = FlatBundle::create(StdFsBackend::new(&dir_str), chunk, size, SECTOR).unwrap();
        b.sync().unwrap();
    }

    let mut shadow = vec![0u8; size as usize];
    let mut s: u64 = 0xDEAD_BEEF_1234_5678;
    let mut next = move || {
        s ^= s << 13;
        s ^= s >> 7;
        s ^= s << 17;
        s
    };
    let lens: [usize; 6] = [512, 4096, 16384, 65536, 131072, 262144];

    let mut bundle = FlatBundle::open(StdFsBackend::new(&dir_str), None, None, None).unwrap();

    for step in 0..4000u64 {
        // Cross a persistence boundary every so often.
        if step != 0 && step % 500 == 0 {
            bundle.sync().unwrap();
            drop(bundle);
            bundle = FlatBundle::open(StdFsBackend::new(&dir_str), None, None, None).unwrap();
        }

        let len = lens[(next() % lens.len() as u64) as usize];
        let max_off = size as usize - len;
        let off = ((next() as usize) % (max_off / SECTOR as usize + 1)) * SECTOR as usize;

        if next() & 1 == 0 {
            let mut buf = vec![0u8; len];
            bundle.read_at(off as u64, &mut buf).unwrap();
            let expected = &shadow[off..off + len];
            if buf != expected {
                let bad = buf.iter().zip(expected).position(|(a, b)| a != b).unwrap();
                panic!("read mismatch at byte {} (step {step})", off + bad);
            }
        } else {
            let buf: Vec<u8> = (0..len)
                .map(|j| (((off + j) as u64).wrapping_mul(131).wrapping_add(step)) as u8)
                .collect();
            bundle.write_at(off as u64, &buf).unwrap();
            shadow[off..off + len].copy_from_slice(&buf);
        }
    }

    // Final full-device check.
    bundle.sync().unwrap();
    let mut out = vec![0u8; size as usize];
    bundle.read_at(0, &mut out).unwrap();
    assert_eq!(out, shadow, "final shadow mismatch");

    std::fs::remove_dir_all(&dir).unwrap();
}

/// A read-only bundle: reads work, writes are rejected at the *data plane*
/// with `NotWritable`, and it needs no write access to the directory.
#[test]
fn bundle_read_only_plane() {
    let dir = temp_dir("read_only");
    let dir_str = dir.to_string_lossy().into_owned();

    {
        let mut b =
            FlatBundle::create(StdFsBackend::new(&dir_str), 1 << 20, 8 << 20, SECTOR).unwrap();
        b.write_at(0, &[0x5A; 4096]).unwrap();
        b.sync().unwrap();
    }

    let mut b = FlatBundle::open_read_only(StdFsBackend::new(&dir_str), None, None, None).unwrap();
    assert!(b.is_read_only());
    let mut out = vec![0u8; 4096];
    b.read_at(0, &mut out).unwrap();
    assert_eq!(out, vec![0x5A; 4096]);
    assert_eq!(b.write_at(0, &[0x11; 4096]), Err(StorageError::NotWritable));

    std::fs::remove_dir_all(&dir).unwrap();
}

#[test]
fn bundle_reopen_persists() {
    let dir = temp_dir("reopen");
    let dir_str = dir.to_string_lossy().into_owned();

    {
        let bundle =
            FlatBundle::create(StdFsBackend::new(&dir_str), 1 << 20, 8 << 20, SECTOR).unwrap();
        let mut bundle = bundle;
        let mut dev = dev(&mut bundle);
        let mut w = work();
        let pattern: Vec<u8> = (0..2048).map(|i| ((i * 3) & 0xFF) as u8).collect();
        write_sectors(&mut dev, &mut bundle, 64, 4, &mut w, &pattern);
        dev.do_cmd(&make_cdb10(0x35, 0, 0), &mut w).unwrap(); // SYNCHRONIZE CACHE(10)
                                                              // The device holds no backend: the shell flushes the plane.
        StorePlane::BlockRw(&mut bundle).sync().unwrap();
    } // drop closes chunk handles

    // The BUNDLE header was written to the real dir.
    assert!(dir.join("BUNDLE").is_file());

    // Reopen through the header: geometry and data are restored.
    let bundle = FlatBundle::open(StdFsBackend::new(&dir_str), None, None, None).unwrap();
    let mut bundle = bundle;
    let mut dev = dev(&mut bundle);
    let mut w = work();
    let mut out = vec![0u8; 2048];
    read_sectors(&mut dev, &mut bundle, 64, 4, &mut w, &mut out);
    assert_eq!(
        out,
        (0..2048)
            .map(|i| ((i * 3) & 0xFF) as u8)
            .collect::<Vec<u8>>()
    );

    // Overrides apply on open.
    let b2 = FlatBundle::open(StdFsBackend::new(&dir_str), Some(1 << 21), None, None).unwrap();
    assert_eq!(b2.chunk_size(), 1 << 21);
    assert_eq!(b2.capacity(), 8 << 20);

    std::fs::remove_dir_all(&dir).unwrap();
}
