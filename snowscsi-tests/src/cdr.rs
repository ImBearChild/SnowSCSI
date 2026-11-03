//! CD-R medium command coverage.
//!
//! These drive a real `MmcDrive<CdrBundleMedium>` through `Target`, a
//! `BlockingStorage` over an in-memory byte plane and a `BlockingHost` that
//! supplies WRITE payload. They pin the MMC-6 response encodings and the
//! write-once transitions (write → close track → finalize).

use snowscsi::core::storage::{
    BlockingHost, BlockingStorage, HostBuf, HostReceipt, HostReq, IoBuf, IoReq, StorageReceipt,
    SyncHost, SyncStorage,
};
use snowscsi::core::{
    cons, CommandContext, Completion, Cons, DataPlan, Delivery, Direction, Fault, Here, LuImpl,
    Nil, Spc, StaticTarget, Target, INVALID_FIELD, LBA_OUT_OF_RANGE, WRITE_PROTECTED,
};
use snowscsi::mmc::{CdrBundleMedium, CdrCapacity, MmcDrive};

const WRITE_10: u8 = 0x2A;
const SYNC_CACHE_10: u8 = 0x35;
const READ_CAPACITY_10: u8 = 0x25;
const READ_TOC: u8 = 0x43;
const GET_CONFIGURATION: u8 = 0x46;
const READ_DISC_INFORMATION: u8 = 0x51;
const READ_TRACK_INFORMATION: u8 = 0x52;
const CLOSE_TRACK_SESSION: u8 = 0x5B;
const FORMAT_UNIT: u8 = 0x04;
const BLANK: u8 = 0xA1;

const BLOCK: usize = 2048;
const SECTORS: u64 = 333_000;

// ═══════════════════════════════════════════════════════════════════════════
// Byte-plane storage double
// ═══════════════════════════════════════════════════════════════════════════

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Ev {
    Read(u16, u64, usize),
    Write(u16, u64, usize),
    Sync,
}

struct Plane {
    mem: Vec<u8>,
    log: Vec<Ev>,
}

impl Plane {
    fn new(len: usize) -> Self {
        Self {
            mem: vec![0xEE; len],
            log: Vec::new(),
        }
    }
}

impl SyncStorage for Plane {
    fn exec(&mut self, req: IoReq, buf: IoBuf<'_>) -> StorageReceipt {
        match (req.dir, buf) {
            (Direction::None, IoBuf::None) => {
                self.log.push(Ev::Sync);
                StorageReceipt::ok(0)
            }
            (Direction::ToHost, IoBuf::Read(b)) => {
                self.log.push(Ev::Read(req.resource, req.offset, b.len()));
                let start = req.offset as usize;
                let end = start.saturating_add(b.len());
                if end > self.mem.len() {
                    return StorageReceipt::failed(
                        Fault::OutOfBounds,
                        0,
                        snowscsi::core::Effect::Known,
                    );
                }
                b.copy_from_slice(&self.mem[start..end]);
                StorageReceipt::ok(b.len())
            }
            (Direction::FromHost, IoBuf::Write(b)) => {
                self.log.push(Ev::Write(req.resource, req.offset, b.len()));
                let start = req.offset as usize;
                let end = start.saturating_add(b.len());
                if end > self.mem.len() {
                    return StorageReceipt::failed(
                        Fault::OutOfBounds,
                        0,
                        snowscsi::core::Effect::Known,
                    );
                }
                self.mem[start..end].copy_from_slice(b);
                StorageReceipt::ok(b.len())
            }
            _ => StorageReceipt::failed(Fault::Contract, 0, snowscsi::core::Effect::Known),
        }
    }
}

// ═══════════════════════════════════════════════════════════════════════════
// Host double
// ═══════════════════════════════════════════════════════════════════════════

struct TestHost {
    payload: Vec<u8>,
}

impl TestHost {
    fn new(payload: Vec<u8>) -> Self {
        Self { payload }
    }
}

impl SyncHost for TestHost {
    fn publish(&mut self, _plan: DataPlan) -> Result<(), Fault> {
        Ok(())
    }

    fn receive(&mut self, req: HostReq, buf: HostBuf<'_>) -> HostReceipt {
        match buf {
            HostBuf::Recv { buf: bytes, .. } => {
                let n = (req.len as usize).min(bytes.len()).min(self.payload.len());
                bytes[..n].copy_from_slice(&self.payload[..n]);
                HostReceipt::from_adapter(n, None)
            }
            HostBuf::Send { .. } => HostReceipt::from_adapter(0, Some(Fault::Contract)),
        }
    }

    fn send(&mut self, req: HostReq, _buf: HostBuf<'_>) -> HostReceipt {
        HostReceipt::from_adapter(req.len as usize, None)
    }

    fn delivery(&self) -> Delivery {
        Delivery::Complete
    }
}

// ═══════════════════════════════════════════════════════════════════════════
// Target helpers
// ═══════════════════════════════════════════════════════════════════════════

type CdrTarget = Target<Cons<LuImpl<Spc<MmcDrive<CdrBundleMedium>>, u8>, Nil>>;

fn cdr_target() -> CdrTarget {
    Target::new(cons(
        LuImpl::new(
            Spc::new(MmcDrive::new(CdrBundleMedium::blank(CdrCapacity::Cdr74))),
            1u8,
        ),
        Nil,
    ))
}

fn ctx(direction: Direction, bytes: u64) -> CommandContext {
    CommandContext {
        lun: 0,
        lun_count: 1,
        host_bytes: bytes,
        host_direction: direction,
    }
}

#[allow(clippy::too_many_arguments)]
fn run(
    target: &mut CdrTarget,
    storage: &mut BlockingStorage<Plane>,
    host: &mut BlockingHost<TestHost>,
    cdb: &[u8],
    direction: Direction,
    bytes: u64,
    work: &mut [u8],
    scratch: &mut [u8],
) -> Completion {
    target
        .drive_static_host::<Here>(storage, host, ctx(direction, bytes), cdb, work, scratch)
        .expect("command must not raise a boundary fault")
}

fn get_configuration(alloc: u16) -> [u8; 10] {
    let mut cdb = [0u8; 10];
    cdb[0] = GET_CONFIGURATION;
    cdb[7] = (alloc >> 8) as u8;
    cdb[8] = alloc as u8;
    cdb
}

fn read_disc_information(alloc: u16) -> [u8; 10] {
    let mut cdb = [0u8; 10];
    cdb[0] = READ_DISC_INFORMATION;
    cdb[7] = (alloc >> 8) as u8;
    cdb[8] = alloc as u8;
    cdb
}

fn read_track_information(ty: u8, number: u32, alloc: u16) -> [u8; 10] {
    let mut cdb = [0u8; 10];
    cdb[0] = READ_TRACK_INFORMATION;
    cdb[1] = ty & 0x07;
    cdb[2..6].copy_from_slice(&number.to_be_bytes());
    cdb[7] = (alloc >> 8) as u8;
    cdb[8] = alloc as u8;
    cdb
}

fn read_toc(msf: bool, format: u8, track: u8, alloc: u16) -> [u8; 10] {
    let mut cdb = [0u8; 10];
    cdb[0] = READ_TOC;
    cdb[1] = u8::from(msf) << 1;
    cdb[2] = format & 0x0F;
    cdb[6] = track;
    cdb[7] = (alloc >> 8) as u8;
    cdb[8] = alloc as u8;
    cdb
}

fn read_capacity() -> [u8; 10] {
    let mut cdb = [0u8; 10];
    cdb[0] = READ_CAPACITY_10;
    cdb
}

fn write10(lba: u32, blocks: u16) -> [u8; 10] {
    let mut cdb = [0u8; 10];
    cdb[0] = WRITE_10;
    cdb[2..6].copy_from_slice(&lba.to_be_bytes());
    cdb[7..9].copy_from_slice(&blocks.to_be_bytes());
    cdb
}

fn sync_cache() -> [u8; 10] {
    let mut cdb = [0u8; 10];
    cdb[0] = SYNC_CACHE_10;
    cdb
}

fn close_track_session(function: u8, track: u16) -> [u8; 10] {
    let mut cdb = [0u8; 10];
    cdb[0] = CLOSE_TRACK_SESSION;
    cdb[2] = function;
    cdb[4..6].copy_from_slice(&track.to_be_bytes());
    cdb
}

/// Find a GET CONFIGURATION feature descriptor in a response.
fn feature_at(buf: &[u8], n: usize, code: u16) -> Option<usize> {
    let mut at = 8;
    while at + 4 <= n {
        let found = u16::from_be_bytes([buf[at], buf[at + 1]]);
        let len = buf[at + 3] as usize;
        if found == code {
            return Some(at);
        }
        at += 4 + len;
    }
    None
}

fn msf(m: u8, s: u8, f: u8) -> [u8; 4] {
    [0x00, m, s, f]
}

fn write_one_block(
    target: &mut CdrTarget,
    storage: &mut BlockingStorage<Plane>,
    host: &mut BlockingHost<TestHost>,
    work: &mut [u8],
    scratch: &mut [u8],
) {
    let cdb = write10(0, 1);
    assert_eq!(
        run(
            target,
            storage,
            host,
            &cdb,
            Direction::FromHost,
            BLOCK as u64,
            work,
            scratch,
        ),
        Completion::Good
    );
}

// ═══════════════════════════════════════════════════════════════════════════
// GET CONFIGURATION
// ═══════════════════════════════════════════════════════════════════════════

#[test]
fn cdr_get_configuration_reports_profile_and_writable_features() {
    let mut target = cdr_target();
    let mut storage = BlockingStorage::new(Plane::new(16 * BLOCK));
    let mut host = BlockingHost::new(TestHost::new(Vec::new()));
    let mut work = vec![0u8; 128];
    let mut scratch = vec![0u8; 128];

    assert_eq!(
        run(
            &mut target,
            &mut storage,
            &mut host,
            &get_configuration(128),
            Direction::ToHost,
            128,
            &mut work,
            &mut scratch,
        ),
        Completion::Good
    );

    assert_eq!(&work[0..4], &104u32.to_be_bytes());
    assert_eq!(&work[6..8], &0x0009u16.to_be_bytes(), "current CD-R");
    // Profile List: [0x12, 0x09, 0x08]; the mounted CD-R and the
    // read-compatible CD-ROM profile are Current.
    assert_eq!(&work[12..14], &0x0012u16.to_be_bytes());
    assert_eq!(work[15], 0);
    assert_eq!(&work[16..18], &0x0009u16.to_be_bytes());
    assert_eq!(work[19], 1);
    assert_eq!(&work[20..22], &0x0008u16.to_be_bytes());
    assert_eq!(work[23], 1);

    let n = 108usize;
    let at21 = feature_at(&work, n, 0x0021).expect("Incremental Streaming listed");
    assert_eq!(work[at21 + 2], 0x0D, "0x21 version 3, current");
    let at2d = feature_at(&work, n, 0x002D).expect("CD Track at Once listed");
    assert_eq!(work[at2d + 2], 0x09, "0x2D version 2, current");
    let at20 = feature_at(&work, n, 0x0020).expect("Random Writable listed");
    assert_eq!(work[at20 + 2] & 1, 0, "0x20 not Current for a CD-R");
    let at24 = feature_at(&work, n, 0x0024).expect("Defect Management listed");
    assert_eq!(work[at24 + 2] & 1, 0, "0x24 not Current for a CD-R");
}

// ═══════════════════════════════════════════════════════════════════════════
// READ DISC INFORMATION
// ═══════════════════════════════════════════════════════════════════════════

#[test]
fn cdr_read_disc_information_blank_appendable_and_finalized() {
    let mut target = cdr_target();
    let mut storage = BlockingStorage::new(Plane::new(16 * BLOCK));
    let mut host = BlockingHost::new(TestHost::new(vec![0x5A; BLOCK]));
    let mut work = vec![0u8; 64];
    let mut scratch = vec![0u8; 64];

    // Blank disc.
    assert_eq!(
        run(
            &mut target,
            &mut storage,
            &mut host,
            &read_disc_information(34),
            Direction::ToHost,
            34,
            &mut work,
            &mut scratch,
        ),
        Completion::Good
    );
    assert_eq!(work[0..2], [0x00, 0x20]);
    assert_eq!(work[2], 0x00, "empty, not erasable");
    assert_eq!(work[3], 1, "first track on disc");
    assert_eq!(work[4], 1, "number of sessions");
    assert_eq!(work[5], 1, "first track in last session");
    assert_eq!(work[6], 1, "last track in last session");
    assert_eq!(work[7], 0x20, "URU");
    assert_eq!(work[8], 0xFF, "unknown disc type");
    assert_eq!(&work[9..12], &[0, 0, 0]);
    assert_eq!(&work[16..20], &msf(97, 34, 23), "wrapped blank lead-in");
    assert_eq!(&work[20..24], &msf(74, 1, 73), "last possible lead-out");

    // One block makes the disc appendable.
    write_one_block(
        &mut target,
        &mut storage,
        &mut host,
        &mut work,
        &mut scratch,
    );
    assert_eq!(
        run(
            &mut target,
            &mut storage,
            &mut host,
            &read_disc_information(34),
            Direction::ToHost,
            34,
            &mut work,
            &mut scratch,
        ),
        Completion::Good
    );
    assert_eq!(work[2], 0x05, "incomplete disc / incomplete session");
    assert_eq!(&work[16..20], &msf(97, 34, 23), "wrapped negative lead-in");
    assert_eq!(&work[20..24], &msf(74, 1, 73));

    // SYNCHRONIZE CACHE closes the open track; CLOSE 010b finalizes.
    assert_eq!(
        run(
            &mut target,
            &mut storage,
            &mut host,
            &sync_cache(),
            Direction::None,
            0,
            &mut work,
            &mut scratch,
        ),
        Completion::Good
    );
    assert_eq!(
        run(
            &mut target,
            &mut storage,
            &mut host,
            &close_track_session(2, 0),
            Direction::None,
            0,
            &mut work,
            &mut scratch,
        ),
        Completion::Good
    );
    assert_eq!(
        run(
            &mut target,
            &mut storage,
            &mut host,
            &read_disc_information(34),
            Direction::ToHost,
            34,
            &mut work,
            &mut scratch,
        ),
        Completion::Good
    );
    assert_eq!(work[2], 0x0E, "finalized, complete session, not erasable");
    assert_eq!(work[4], 1);
    assert_eq!(&work[16..20], &[0xFF; 4]);
    assert_eq!(&work[20..24], &[0xFF; 4], "lead-out no longer applicable");
}

// ═══════════════════════════════════════════════════════════════════════════
// READ TRACK INFORMATION
// ═══════════════════════════════════════════════════════════════════════════

#[test]
fn cdr_read_track_information_blank_lead_in_and_after_write() {
    let mut target = cdr_target();
    let mut storage = BlockingStorage::new(Plane::new(16 * BLOCK));
    let mut host = BlockingHost::new(TestHost::new(vec![0x5A; BLOCK]));
    let mut work = vec![0u8; 64];
    let mut scratch = vec![0u8; 64];

    // The invisible (next) track: blank, NWA valid at LBA 0.
    assert_eq!(
        run(
            &mut target,
            &mut storage,
            &mut host,
            &read_track_information(1, 0xFF, 48),
            Direction::ToHost,
            48,
            &mut work,
            &mut scratch,
        ),
        Completion::Good
    );
    assert_eq!(work[0..2], [0x00, 0x2E]);
    assert_eq!(work[2], 1);
    assert_eq!(work[3], 1);
    assert_eq!(work[5], 0x04, "data track mode");
    assert_eq!(work[6], 0x41, "Blank=1, Data Mode 1");
    assert_eq!(work[7], 0x01, "NWA_V");
    assert_eq!(&work[8..12], &0u32.to_be_bytes(), "track start");
    assert_eq!(&work[12..16], &0u32.to_be_bytes(), "NWA 0");
    assert_eq!(&work[16..20], &((SECTORS - 4) as u32).to_be_bytes());
    assert_eq!(&work[20..24], &0u32.to_be_bytes(), "no fixed packets");
    assert_eq!(&work[24..28], &(SECTORS as u32).to_be_bytes());

    // Track 0 is the lead-in pseudo-track.
    assert_eq!(
        run(
            &mut target,
            &mut storage,
            &mut host,
            &read_track_information(1, 0, 48),
            Direction::ToHost,
            48,
            &mut work,
            &mut scratch,
        ),
        Completion::Good
    );
    assert_eq!(work[2], 0);
    assert_eq!(work[3], 0);
    assert_eq!(work[5], 0x00);
    assert_eq!(work[6], 0x00, "RT=Blank=0");
    assert_eq!(work[7], 0x00, "no NWA");
    assert_eq!(&work[8..12], &(-11_077i32 as u32).to_be_bytes());

    // A track past the invisible one does not exist yet.
    assert_eq!(
        run(
            &mut target,
            &mut storage,
            &mut host,
            &read_track_information(1, 2, 48),
            Direction::ToHost,
            48,
            &mut work,
            &mut scratch,
        ),
        Completion::Check(INVALID_FIELD)
    );

    // An LBA beyond the last possible lead-out is LBA OUT OF RANGE, not an
    // invalid field.
    assert_eq!(
        run(
            &mut target,
            &mut storage,
            &mut host,
            &read_track_information(0, SECTORS as u32, 48),
            Direction::ToHost,
            48,
            &mut work,
            &mut scratch,
        ),
        Completion::Check(LBA_OUT_OF_RANGE)
    );

    write_one_block(
        &mut target,
        &mut storage,
        &mut host,
        &mut work,
        &mut scratch,
    );

    // After the first WRITE: incomplete, NWA advanced to 1.
    for cdb in [
        read_track_information(1, 1, 48),
        read_track_information(0, 0, 48),
        read_track_information(2, 1, 48),
    ] {
        assert_eq!(
            run(
                &mut target,
                &mut storage,
                &mut host,
                &cdb,
                Direction::ToHost,
                48,
                &mut work,
                &mut scratch,
            ),
            Completion::Good
        );
        assert_eq!(work[2], 1, "track number");
        assert_eq!(work[3], 1, "session number");
        assert_eq!(work[5], 0x04, "data track mode");
        assert_eq!(work[6], 0x01, "RT=0, Blank=0, Data Mode 1");
        assert_eq!(work[7], 0x01, "NWA_V");
        assert_eq!(&work[8..12], &0u32.to_be_bytes());
        assert_eq!(&work[12..16], &1u32.to_be_bytes(), "NWA advanced");
        assert_eq!(&work[16..20], &((SECTORS - 5) as u32).to_be_bytes());
        assert_eq!(&work[24..28], &1u32.to_be_bytes(), "track size");
        assert_eq!(&work[28..32], &0u32.to_be_bytes(), "last recorded LBA");
    }
}

// ═══════════════════════════════════════════════════════════════════════════
// READ TOC guards
// ═══════════════════════════════════════════════════════════════════════════

#[test]
fn cdr_blank_toc_and_incomplete_session_toc_are_rejected() {
    let mut target = cdr_target();
    let mut storage = BlockingStorage::new(Plane::new(16 * BLOCK));
    let mut host = BlockingHost::new(TestHost::new(vec![0x5A; BLOCK]));
    let mut work = vec![0u8; 64];
    let mut scratch = vec![0u8; 64];

    // A blank disc has no program area.
    assert_eq!(
        run(
            &mut target,
            &mut storage,
            &mut host,
            &read_toc(false, 0, 0, 20),
            Direction::ToHost,
            20,
            &mut work,
            &mut scratch,
        ),
        Completion::Check(INVALID_FIELD)
    );

    write_one_block(
        &mut target,
        &mut storage,
        &mut host,
        &mut work,
        &mut scratch,
    );
    // An appendable disc has no complete session yet: neither the format 0
    // lead-out nor the format 1 session descriptor exists.
    assert_eq!(
        run(
            &mut target,
            &mut storage,
            &mut host,
            &read_toc(false, 0, 0, 20),
            Direction::ToHost,
            20,
            &mut work,
            &mut scratch,
        ),
        Completion::Check(INVALID_FIELD)
    );
    assert_eq!(
        run(
            &mut target,
            &mut storage,
            &mut host,
            &read_toc(false, 1, 0, 12),
            Direction::ToHost,
            12,
            &mut work,
            &mut scratch,
        ),
        Completion::Check(INVALID_FIELD)
    );
}

// ═══════════════════════════════════════════════════════════════════════════
// FORMAT / BLANK guard
// ═══════════════════════════════════════════════════════════════════════════

#[test]
fn cdr_format_and_blank_are_rejected_without_touching_the_backing() {
    let mut target = cdr_target();
    let mut storage = BlockingStorage::new(Plane::new(16 * BLOCK));
    let mut host = BlockingHost::new(TestHost::new(Vec::new()));
    let mut work = vec![0u8; 64];
    let mut scratch = vec![0u8; 64];

    let format = [FORMAT_UNIT, 0, 0, 0, 0, 0];
    assert_eq!(
        run(
            &mut target,
            &mut storage,
            &mut host,
            &format,
            Direction::None,
            0,
            &mut work,
            &mut scratch,
        ),
        Completion::Check(INVALID_FIELD)
    );

    // FmtData + format code 1 would normally carry a 12-byte list.
    let format_list = [FORMAT_UNIT, 0x11, 0, 0, 0, 0];
    assert_eq!(
        run(
            &mut target,
            &mut storage,
            &mut host,
            &format_list,
            Direction::FromHost,
            12,
            &mut work,
            &mut scratch,
        ),
        Completion::Check(INVALID_FIELD)
    );

    for cdb in [
        [BLANK, 0, 0, 0, 0, 0],
        [BLANK, 0x20, 0, 0, 0, 0], // IMMED
    ] {
        assert_eq!(
            run(
                &mut target,
                &mut storage,
                &mut host,
                &cdb,
                Direction::None,
                0,
                &mut work,
                &mut scratch,
            ),
            Completion::Check(INVALID_FIELD)
        );
    }

    assert!(
        storage.inner().log.is_empty(),
        "no zero-fill reached the backing"
    );

    // The medium is still blank after the rejected commands.
    assert_eq!(
        run(
            &mut target,
            &mut storage,
            &mut host,
            &read_capacity(),
            Direction::ToHost,
            8,
            &mut work,
            &mut scratch,
        ),
        Completion::Good
    );
    assert_eq!(&work[0..4], &0u32.to_be_bytes(), "blank disc last LBA");
    assert_eq!(&work[4..8], &(BLOCK as u32).to_be_bytes());
}

// ═══════════════════════════════════════════════════════════════════════════
// Write → close track → finalize, TOC and capacity
// ═══════════════════════════════════════════════════════════════════════════

#[test]
fn cdr_write_sync_close_then_toc_and_capacity() {
    let mut target = cdr_target();
    let mut storage = BlockingStorage::new(Plane::new(16 * BLOCK));
    let mut host = BlockingHost::new(TestHost::new(vec![0x5A; BLOCK]));
    let mut work = vec![0u8; 64];
    let mut scratch = vec![0u8; 64];

    write_one_block(
        &mut target,
        &mut storage,
        &mut host,
        &mut work,
        &mut scratch,
    );
    assert_eq!(
        run(
            &mut target,
            &mut storage,
            &mut host,
            &sync_cache(),
            Direction::None,
            0,
            &mut work,
            &mut scratch,
        ),
        Completion::Good
    );

    // The closed track is padded to the 4-second minimum (300 blocks).
    assert_eq!(
        run(
            &mut target,
            &mut storage,
            &mut host,
            &read_track_information(1, 1, 48),
            Direction::ToHost,
            48,
            &mut work,
            &mut scratch,
        ),
        Completion::Good
    );
    assert_eq!(work[6], 0x81, "RT=1, Data Mode 1");
    assert_eq!(work[7], 0x00, "closed track has no NWA");
    assert_eq!(&work[24..28], &300u32.to_be_bytes());

    assert_eq!(
        run(
            &mut target,
            &mut storage,
            &mut host,
            &close_track_session(2, 0),
            Direction::None,
            0,
            &mut work,
            &mut scratch,
        ),
        Completion::Good
    );

    // READ TOC format 0: track 1 at LBA 0 and the lead-out at LBA 300.
    assert_eq!(
        run(
            &mut target,
            &mut storage,
            &mut host,
            &read_toc(false, 0, 0, 20),
            Direction::ToHost,
            20,
            &mut work,
            &mut scratch,
        ),
        Completion::Good
    );
    assert_eq!(work[0..2], [0x00, 0x12], "18 bytes of TOC data");
    assert_eq!(work[2], 1, "first track");
    assert_eq!(work[3], 1, "last track");
    assert_eq!(work[5], 0x14, "data control");
    assert_eq!(work[6], 1, "track number");
    assert_eq!(&work[8..12], &0u32.to_be_bytes(), "track start");
    assert_eq!(work[13], 0x14);
    assert_eq!(work[14], 0xAA, "lead-out");
    assert_eq!(&work[16..20], &300u32.to_be_bytes(), "lead-out start");

    // READ TOC format 1: the last complete session's first track.
    assert_eq!(
        run(
            &mut target,
            &mut storage,
            &mut host,
            &read_toc(false, 1, 0, 12),
            Direction::ToHost,
            12,
            &mut work,
            &mut scratch,
        ),
        Completion::Good
    );
    assert_eq!(work[0..2], [0x00, 0x0A]);
    assert_eq!(work[2], 1);
    assert_eq!(work[3], 1);
    assert_eq!(work[6], 1, "first track in last complete session");

    // READ CAPACITY reports the last recorded LBA (299 after the 300-block
    // track was padded).
    assert_eq!(
        run(
            &mut target,
            &mut storage,
            &mut host,
            &read_capacity(),
            Direction::ToHost,
            8,
            &mut work,
            &mut scratch,
        ),
        Completion::Good
    );
    assert_eq!(&work[0..4], &299u32.to_be_bytes());
    assert_eq!(&work[4..8], &(BLOCK as u32).to_be_bytes());

    // A finalized CD-R has no invisible track.
    for number in [0xFF, 2] {
        assert_eq!(
            run(
                &mut target,
                &mut storage,
                &mut host,
                &read_track_information(1, number, 48),
                Direction::ToHost,
                48,
                &mut work,
                &mut scratch,
            ),
            Completion::Check(INVALID_FIELD)
        );
    }

    // A finalized disc rejects further writes.
    let cdb = write10(300, 1);
    assert_eq!(
        run(
            &mut target,
            &mut storage,
            &mut host,
            &cdb,
            Direction::FromHost,
            BLOCK as u64,
            &mut work,
            &mut scratch,
        ),
        Completion::Check(WRITE_PROTECTED)
    );
}
