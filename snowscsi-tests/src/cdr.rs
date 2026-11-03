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
    Nil, Sense, Spc, StaticTarget, Target, INVALID_FIELD, LBA_OUT_OF_RANGE, WRITE_PROTECTED,
};
use snowscsi::mmc::{
    CdrBundleMedium, CdrCapacity, CdrDiscState, FlatCdMedium, MmcDrive, MmcMedium, Recovery,
};

const READ_10: u8 = 0x28;
const WRITE_10: u8 = 0x2A;
const SYNC_CACHE_10: u8 = 0x35;
const READ_CAPACITY_10: u8 = 0x25;
const READ_TOC: u8 = 0x43;
const GET_CONFIGURATION: u8 = 0x46;
const READ_DISC_INFORMATION: u8 = 0x51;
const READ_TRACK_INFORMATION: u8 = 0x52;
const RESERVE_TRACK: u8 = 0x53;
const SEND_OPC: u8 = 0x54;
const CLOSE_TRACK_SESSION: u8 = 0x5B;
const FORMAT_UNIT: u8 = 0x04;
const BLANK: u8 = 0xA1;
const MODE_SENSE_10: u8 = 0x5A;
const MODE_SELECT_10: u8 = 0x55;
const SET_CD_SPEED: u8 = 0xBB;

/// ILLEGAL REQUEST / INVALID ADDRESS FOR WRITE: a TAO write must start at the
/// next writable address.
const INVALID_ADDRESS_FOR_WRITE: Sense = Sense::new(0x05, 0x21, 0x02);

const BLOCK: usize = 2048;
const SECTORS: u64 = 332_849;

// ═══════════════════════════════════════════════════════════════════════════
// Byte-plane storage double
// ═══════════════════════════════════════════════════════════════════════════

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Ev {
    Read(u16, u64, usize),
    Write(u16, u64, usize),
    Sync(u16),
}

struct Plane {
    /// One independent byte plane per storage resource, so a TOC slot write
    /// can never clobber track payload.
    mem: std::collections::HashMap<u16, Vec<u8>>,
    len: usize,
    log: Vec<Ev>,
}

impl Plane {
    fn new(len: usize) -> Self {
        Self {
            mem: std::collections::HashMap::new(),
            len,
            log: Vec::new(),
        }
    }

    fn plane(&mut self, resource: u16) -> &mut Vec<u8> {
        let len = self
            .len
            .max(snowscsi::mmc::cdr_bundle::TOC_SLOT_MAX as usize);
        self.mem.entry(resource).or_insert_with(|| vec![0xEE; len])
    }

    fn slot(&self, slot: u8) -> Vec<u8> {
        let mut bytes = self
            .mem
            .get(&snowscsi::mmc::cdr_bundle::toc_resource(slot))
            .cloned()
            .unwrap_or_default();
        bytes.truncate(snowscsi::mmc::cdr_bundle::TOC_SLOT_DEFAULT as usize);
        bytes
    }
}

impl SyncStorage for Plane {
    fn exec(&mut self, req: IoReq, buf: IoBuf<'_>) -> StorageReceipt {
        let start = req.offset as usize;
        let end = start.saturating_add(match &buf {
            IoBuf::None => 0,
            IoBuf::Read(b) => b.len(),
            IoBuf::Write(b) => b.len(),
        });
        match (req.dir, buf) {
            (Direction::None, IoBuf::None) => {
                self.log.push(Ev::Sync(req.resource));
                StorageReceipt::ok(0)
            }
            (Direction::ToHost, IoBuf::Read(b)) => {
                self.log.push(Ev::Read(req.resource, req.offset, b.len()));
                let plane = self.plane(req.resource);
                if end > plane.len() {
                    return StorageReceipt::failed(
                        Fault::OutOfBounds,
                        0,
                        snowscsi::core::Effect::Known,
                    );
                }
                b.copy_from_slice(&plane[start..end]);
                StorageReceipt::ok(b.len())
            }
            (Direction::FromHost, IoBuf::Write(b)) => {
                self.log.push(Ev::Write(req.resource, req.offset, b.len()));
                let plane = self.plane(req.resource);
                if end > plane.len() {
                    return StorageReceipt::failed(
                        Fault::OutOfBounds,
                        0,
                        snowscsi::core::Effect::Known,
                    );
                }
                plane[start..end].copy_from_slice(b);
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
    cdr_target_with(CdrCapacity::Cdr74)
}

fn cdr_target_with(capacity: CdrCapacity) -> CdrTarget {
    Target::new(cons(
        LuImpl::new(
            Spc::new(MmcDrive::new(CdrBundleMedium::blank(capacity))),
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

/// Consume an optional medium-change unit attention before reading the disc.
///
/// A finalize reports `06/28/00`; a blank or merely appendable disc does not.
/// `cdr_finalize_reports_a_medium_change_unit_attention` asserts the strict
/// case.
fn consume_medium_change(
    target: &mut CdrTarget,
    storage: &mut BlockingStorage<Plane>,
    host: &mut BlockingHost<TestHost>,
    work: &mut [u8],
    scratch: &mut [u8],
) {
    match run(
        target,
        storage,
        host,
        &[0u8; 6],
        Direction::None,
        0,
        work,
        scratch,
    ) {
        Completion::Good => {}
        Completion::Check(sense) => assert_eq!(
            sense,
            Sense::new(0x06, 0x28, 0x00),
            "only a medium change may precede the read"
        ),
        other => panic!("unexpected TUR completion {other:?}"),
    }
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

fn read10(lba: u32, blocks: u16) -> [u8; 10] {
    let mut cdb = [0u8; 10];
    cdb[0] = READ_10;
    cdb[2..6].copy_from_slice(&lba.to_be_bytes());
    cdb[7..9].copy_from_slice(&blocks.to_be_bytes());
    cdb
}

/// SEND OPC INFORMATION with a parameter table of `len` bytes.
fn send_opc(len: u16) -> [u8; 10] {
    let mut cdb = [0u8; 10];
    cdb[0] = SEND_OPC;
    cdb[7] = (len >> 8) as u8;
    cdb[8] = len as u8;
    cdb
}

fn sync_cache() -> [u8; 10] {
    let mut cdb = [0u8; 10];
    cdb[0] = SYNC_CACHE_10;
    cdb
}

fn reserve_track_cdb(arsv: bool, size: u32) -> [u8; 10] {
    let mut cdb = [0u8; 10];
    cdb[0] = RESERVE_TRACK;
    cdb[1] = u8::from(arsv);
    cdb[5..9].copy_from_slice(&size.to_be_bytes());
    cdb
}

fn close_track_session(function: u8, track: u16) -> [u8; 10] {
    let mut cdb = [0u8; 10];
    cdb[0] = CLOSE_TRACK_SESSION;
    cdb[2] = function;
    cdb[4..6].copy_from_slice(&track.to_be_bytes());
    cdb
}

fn mode_sense10(page: u8, alloc: u16) -> [u8; 10] {
    let mut cdb = [0u8; 10];
    cdb[0] = MODE_SENSE_10;
    cdb[2] = page;
    cdb[7] = (alloc >> 8) as u8;
    cdb[8] = alloc as u8;
    cdb
}

fn mode_select10(length: u16) -> [u8; 10] {
    let mut cdb = [0u8; 10];
    cdb[0] = MODE_SELECT_10;
    cdb[1] = 0x10; // PF=1, SP=0: a page list, not saved
    cdb[7] = (length >> 8) as u8;
    cdb[8] = length as u8;
    cdb
}

/// The MODE SELECT(10) parameter list a TAO recorder sends: a mode header with
/// no block descriptors, then Write Parameters page 0x05 asking for
/// Track-at-Once, data track mode 4 and Data Block Type 8 (Mode 1, 2048-byte
/// blocks).
fn tao_mode_page() -> Vec<u8> {
    let mut page = vec![0u8; 60];
    page[0..2].copy_from_slice(&58u16.to_be_bytes());
    page[8] = 0x05;
    page[9] = 0x32;
    page[10] = 0x01; // Write Type = Track-at-Once
    page[11] = 0x04; // Track Mode = data
    page[12] = 0x08; // Data Block Type = Mode 1
    page
}

/// The same page with Test Write (byte 2 bit 4) set, as `wodim -dummy` sends.
fn dummy_mode_page() -> Vec<u8> {
    let mut page = tao_mode_page();
    page[10] |= 0x10;
    page
}

fn set_cd_speed(read: u16, write: u16) -> [u8; 12] {
    let mut cdb = [0u8; 12];
    cdb[0] = SET_CD_SPEED;
    cdb[2..4].copy_from_slice(&read.to_be_bytes());
    cdb[4..6].copy_from_slice(&write.to_be_bytes());
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
    consume_medium_change(
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
    assert_eq!(&work[20..24], &msf(73, 59, 74), "last possible lead-out");

    // One block makes the disc appendable.
    write_one_block(
        &mut target,
        &mut storage,
        &mut host,
        &mut work,
        &mut scratch,
    );
    consume_medium_change(
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
    assert_eq!(&work[20..24], &msf(73, 59, 74));

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
    consume_medium_change(
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
    assert_eq!(&work[16..20], &((SECTORS - 2) as u32).to_be_bytes());
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
        assert_eq!(&work[16..20], &((SECTORS - 3) as u32).to_be_bytes());
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
// READ TOC format 4 (ATIP)
// ═══════════════════════════════════════════════════════════════════════════

#[test]
fn cdr_read_toc_format4_reports_atip() {
    let mut target = cdr_target_with(CdrCapacity::Cdr80);
    let mut storage = BlockingStorage::new(Plane::new(16 * BLOCK));
    let mut host = BlockingHost::new(TestHost::new(vec![0x5A; BLOCK]));
    let mut work = vec![0u8; 64];
    let mut scratch = vec![0u8; 64];

    assert_eq!(
        run(
            &mut target,
            &mut storage,
            &mut host,
            &read_toc(false, 4, 0, 28),
            Direction::ToHost,
            28,
            &mut work,
            &mut scratch,
        ),
        Completion::Good
    );
    // 4-byte header + the 24-byte descriptor, no optional S4 block: the ATIP
    // Data Length is 26.
    assert_eq!(&work[0..2], &26u16.to_be_bytes());
    assert_eq!(&work[2..4], &[0, 0]);
    let atip = work[..28].to_vec();
    let d = &atip[4..28];
    assert_eq!(d[0], 0xD0, "bit7, writing power 5, reference speed 0");
    assert_eq!(d[1], 0x40, "bit7 clear, URU set");
    assert_eq!(d[2], 0x80, "CD-R, not erasable, no A-valid bit");
    assert_eq!(d[3], 0x00);
    // 450150 - 11077 = 439073 = 97:34:23 in binary M/S/F.
    assert_eq!(&d[4..7], &[97, 34, 23], "ATIP start time of lead-in");
    assert_eq!(d[7], 0x00);
    // 359849 + 150 = 359999 = 79:59:74.
    assert_eq!(&d[8..11], &[79, 59, 74], "last possible lead-out");
    assert_eq!(d[11], 0x00);
    assert_eq!(&d[12..24], &[0u8; 12], "no A1/A2/A3 values");

    // MMC-6 6.25.3.6.1: the MSF bit affects no field of format 4.
    let mut msf = vec![0u8; 64];
    assert_eq!(
        run(
            &mut target,
            &mut storage,
            &mut host,
            &read_toc(true, 4, 0, 28),
            Direction::ToHost,
            28,
            &mut msf,
            &mut scratch,
        ),
        Completion::Good
    );
    assert_eq!(&msf[..28], &atip[..], "the MSF bit is ignored");

    // A short allocation truncates the transfer but keeps the declared length.
    let mut short = vec![0u8; 64];
    assert_eq!(
        run(
            &mut target,
            &mut storage,
            &mut host,
            &read_toc(false, 4, 0, 10),
            Direction::ToHost,
            10,
            &mut short,
            &mut scratch,
        ),
        Completion::Good
    );
    assert_eq!(&short[0..2], &26u16.to_be_bytes());
    assert_eq!(&short[2..10], &atip[2..10]);

    // cdrkit first reads only the 4-byte header to learn the declared data
    // length (26) and then sizes its buffer from it; the allocation length does
    // not change the declared length.
    let mut probe = vec![0u8; 64];
    assert_eq!(
        run(
            &mut target,
            &mut storage,
            &mut host,
            &read_toc(false, 4, 0, 4),
            Direction::ToHost,
            4,
            &mut probe,
            &mut scratch,
        ),
        Completion::Good
    );
    assert_eq!(&probe[0..2], &26u16.to_be_bytes());
    assert_eq!(&probe[2..4], &[0, 0]);
    assert_eq!(&probe[4..8], &[0u8; 4], "nothing past the allocation");

    // Byte 6 is reserved for format 4.
    assert_eq!(
        run(
            &mut target,
            &mut storage,
            &mut host,
            &read_toc(false, 4, 1, 28),
            Direction::ToHost,
            28,
            &mut work,
            &mut scratch,
        ),
        Completion::Check(INVALID_FIELD)
    );

    // The blank ATIP extent agrees with READ CAPACITY: the host may size the
    // device from either before the first session.
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
    assert_eq!(
        &work[0..4],
        &((CdrCapacity::Cdr80.sectors() - 1) as u32).to_be_bytes()
    );

    // The pre-groove is written before any data, so a recorded and a finalized
    // disc report the same descriptor.
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
            &read_toc(false, 4, 0, 28),
            Direction::ToHost,
            28,
            &mut work,
            &mut scratch,
        ),
        Completion::Good
    );
    assert_eq!(&work[..28], &atip[..], "appendable disc");

    // SYNCHRONIZE CACHE pads and closes the open track; CLOSE 010b then
    // finalizes the disc.
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
    consume_medium_change(
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
            &read_toc(false, 4, 0, 28),
            Direction::ToHost,
            28,
            &mut work,
            &mut scratch,
        ),
        Completion::Good
    );
    assert_eq!(&work[..28], &atip[..], "finalized disc");
}

#[test]
fn cdr_read_toc_format4_is_rejected_for_a_stamped_cd() {
    // MMC-6 6.25.3.6.3: a non-CD-recordable medium has no ATIP, so format 4
    // is ILLEGAL REQUEST / INVALID FIELD IN CDB.
    type FlatTarget = Target<Cons<LuImpl<Spc<MmcDrive<FlatCdMedium>>, u8>, Nil>>;
    let mut target = FlatTarget::new(cons(
        LuImpl::new(Spc::new(MmcDrive::new(FlatCdMedium::read_only(16))), 1u8),
        Nil,
    ));
    let mut storage = BlockingStorage::new(Plane::new(16 * BLOCK));
    let mut host = BlockingHost::new(TestHost::new(Vec::new()));
    let mut work = vec![0u8; 64];
    let mut scratch = vec![0u8; 64];

    assert_eq!(
        target
            .drive_static_host::<Here>(
                &mut storage,
                &mut host,
                ctx(Direction::ToHost, 28),
                &read_toc(false, 4, 0, 28),
                &mut work,
                &mut scratch,
            )
            .expect("command must not raise a boundary fault"),
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
    assert_eq!(
        &work[0..4],
        &((CdrCapacity::Cdr74.sectors() - 1) as u32).to_be_bytes(),
        "blank disc ATIP last writable LBA"
    );
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

    consume_medium_change(
        &mut target,
        &mut storage,
        &mut host,
        &mut work,
        &mut scratch,
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

// ═══════════════════════════════════════════════════════════════════════════
// cdrkit recorder-control sequence: MODE SENSE/SELECT 0x05 + SET CD SPEED
// ═══════════════════════════════════════════════════════════════════════════

#[test]
fn cdr_recorder_control_sequence_returns_good_before_a_write() {
    let mut target = cdr_target();
    let mut storage = BlockingStorage::new(Plane::new(16 * BLOCK));
    let mut host = BlockingHost::new(TestHost::new(Vec::new()));
    let mut work = vec![0u8; 256];
    let mut scratch = vec![0u8; 256];

    // MODE SENSE(10) page 0x05: the CD-R recorder parameters.
    assert_eq!(
        run(
            &mut target,
            &mut storage,
            &mut host,
            &mode_sense10(0x05, 64),
            Direction::ToHost,
            64,
            &mut work,
            &mut scratch,
        ),
        Completion::Good
    );
    assert_eq!(&work[0..2], &58u16.to_be_bytes(), "8 + 52 bytes");
    assert_eq!(work[8], 0x05, "Write Parameters page");
    assert_eq!(work[9], 0x32, "page length");
    assert_eq!(work[10], 0x01, "Write Type = Track-at-Once");
    assert_eq!(work[11], 0x04, "Track Mode = data");
    assert_eq!(work[12], 0x08, "Data Block Type = Mode 1");

    // Send the same page back as a MODE SELECT(10) page list.
    let params = work[..60].to_vec();
    let mut select_host = BlockingHost::new(TestHost::new(params));
    assert_eq!(
        run(
            &mut target,
            &mut storage,
            &mut select_host,
            &mode_select10(60),
            Direction::FromHost,
            60,
            &mut work,
            &mut scratch,
        ),
        Completion::Good
    );

    // SET CD SPEED is accepted and remembered.
    assert_eq!(
        run(
            &mut target,
            &mut storage,
            &mut select_host,
            &set_cd_speed(7060, 4236),
            Direction::None,
            0,
            &mut work,
            &mut scratch,
        ),
        Completion::Good
    );

    // The recorder still accepts the first TAO write.
    let mut write_host = BlockingHost::new(TestHost::new(vec![0x5A; BLOCK]));
    write_one_block(
        &mut target,
        &mut storage,
        &mut write_host,
        &mut work,
        &mut scratch,
    );
}

// ═══════════════════════════════════════════════════════════════════════════
// cdrkit `wodim -tao` trace: no RESERVE TRACK, write at the NWA
// ═══════════════════════════════════════════════════════════════════════════

/// The command order `wodim -tao` uses on a blank CD-R (cdrkit does not
/// reserve a track when the host driver already reports the next writable
/// address): query the recorder, accept its TAO page, set the speed, send an
/// OPC table, write at the NWA, flush, and close the session.
///
/// This pins the whole path a real burner walks, including the two TOC saves
/// (`SYNCHRONIZE CACHE` closes the track, `CLOSE TRACK/SESSION` finalizes it)
/// and the persistent medium restored from a slot.
#[test]
fn cdr_cdrkit_tao_trace() {
    let mut target = cdr_target();
    let mut storage = BlockingStorage::new(Plane::new(16 * BLOCK));
    let mut host = BlockingHost::new(TestHost::new(Vec::new()));
    let mut work = vec![0u8; 4096];
    let mut scratch = vec![0u8; 4096];

    // 1. GET CONFIGURATION: the drive reports CD-R as its current profile and
    //    lists the read/write feature set a TAO recorder needs.
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
    assert_eq!(
        &work[6..8],
        &0x0009u16.to_be_bytes(),
        "current CD-R profile"
    );
    // Profile list: CD-ROM (0x08) and CD-R (0x09) are Current; the
    // read-compatible CD-RW profile (0x12) is listed but not Current.
    assert_eq!(&work[12..14], &0x0012u16.to_be_bytes());
    assert_eq!(work[15], 0, "0x12 not Current on a CD-R");
    assert_eq!(&work[16..18], &0x0009u16.to_be_bytes());
    assert_eq!(work[19], 1, "0x09 Current");
    assert_eq!(&work[20..22], &0x0008u16.to_be_bytes());
    assert_eq!(work[23], 1, "0x08 Current");
    let listed = 108usize;
    let at21 = feature_at(&work, listed, 0x0021).expect("Incremental Streaming");
    assert_eq!(work[at21 + 2] & 1, 1, "0x21 Current");
    let at2d = feature_at(&work, listed, 0x002D).expect("CD Track at Once");
    assert_eq!(work[at2d + 2] & 1, 1, "0x2D Current");
    let at20 = feature_at(&work, listed, 0x0020).expect("Random Writable");
    assert_eq!(work[at20 + 2] & 1, 0, "0x20 not Current for a CD-R");
    let at24 = feature_at(&work, listed, 0x0024).expect("Defect Management");
    assert_eq!(work[at24 + 2] & 1, 0, "0x24 not Current for a CD-R");

    // 2. READ DISC INFORMATION: empty, one session, not erasable, with the
    //    lead-in and last-possible-lead-out addresses in MSF.
    consume_medium_change(
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
    assert_eq!(work[2] & 0x03, 0x00, "Empty disc");
    assert_eq!(work[2] & 0x10, 0, "not erasable");
    assert_eq!(work[4], 1, "one session");
    assert_eq!(&work[16..20], &msf(97, 34, 23), "lead-in MSF");
    assert_eq!(
        &work[20..24],
        &msf(73, 59, 74),
        "last possible lead-out MSF"
    );

    // 3. READ TRACK INFORMATION type 1, track 0xFF: the invisible next track
    //    has a valid NWA at LBA 0.
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
    assert_eq!(work[2], 1);
    assert_eq!(work[3], 1);
    assert_eq!(work[6] & 0x40, 0x40, "invisible (blank) track");
    assert_eq!(work[7] & 0x01, 0x01, "NWA valid");
    assert_eq!(&work[12..16], &0u32.to_be_bytes(), "NWA 0");

    // 4. MODE SENSE(10) page 0x05: TAO with data track mode 4 and Mode 1
    //    (2048-byte) blocks.
    assert_eq!(
        run(
            &mut target,
            &mut storage,
            &mut host,
            &mode_sense10(0x05, 64),
            Direction::ToHost,
            64,
            &mut work,
            &mut scratch,
        ),
        Completion::Good
    );
    assert_eq!(&work[0..2], &58u16.to_be_bytes(), "8 + 52 bytes");
    assert_eq!(work[8], 0x05, "Write Parameters page");
    assert_eq!(work[9], 0x32, "page length");
    assert_eq!(work[10], 0x01, "Write Type = Track-at-Once");
    assert_eq!(work[11], 0x04, "Track Mode = data");
    assert_eq!(work[12], 0x08, "Data Block Type = Mode 1");

    // 5. MODE SELECT(10): the recorder accepts the TAO page it just reported.
    let mut select_host = BlockingHost::new(TestHost::new(tao_mode_page()));
    assert_eq!(
        run(
            &mut target,
            &mut storage,
            &mut select_host,
            &mode_select10(60),
            Direction::FromHost,
            60,
            &mut work,
            &mut scratch,
        ),
        Completion::Good
    );

    // 6. SET CD SPEED: accepted (the emulated spindle has no speed to set).
    assert_eq!(
        run(
            &mut target,
            &mut storage,
            &mut select_host,
            &set_cd_speed(0xFFFF, 0xFFFF),
            Direction::None,
            0,
            &mut work,
            &mut scratch,
        ),
        Completion::Good
    );

    // 7. SEND OPC INFORMATION: one eight-byte table entry is accepted and
    //    discarded.
    let mut opc_host = BlockingHost::new(TestHost::new(vec![0u8; 8]));
    assert_eq!(
        run(
            &mut target,
            &mut storage,
            &mut opc_host,
            &send_opc(8),
            Direction::FromHost,
            8,
            &mut work,
            &mut scratch,
        ),
        Completion::Good
    );

    // 8. WRITE(10) at the NWA (LBA 0) without RESERVE TRACK: the medium opens
    //    track 1 implicitly and records one block.
    let payload: Vec<u8> = (0..BLOCK).map(|i| (i % 251) as u8).collect();
    let mut write_host = BlockingHost::new(TestHost::new(payload.clone()));
    assert_eq!(
        run(
            &mut target,
            &mut storage,
            &mut write_host,
            &write10(0, 1),
            Direction::FromHost,
            BLOCK as u64,
            &mut work,
            &mut scratch,
        ),
        Completion::Good
    );
    assert_eq!(
        run(
            &mut target,
            &mut storage,
            &mut write_host,
            &read_track_information(1, 1, 48),
            Direction::ToHost,
            48,
            &mut work,
            &mut scratch,
        ),
        Completion::Good
    );
    assert_eq!(&work[12..16], &1u32.to_be_bytes(), "NWA advanced to 1");
    assert_eq!(&work[28..32], &0u32.to_be_bytes(), "last recorded LBA 0");
    // The payload is the first block of track 1's resource, at offset 0.
    let writes: Vec<_> = storage
        .inner()
        .log
        .iter()
        .filter_map(|event| match event {
            Ev::Write(resource, offset, len) => Some((*resource, *offset, *len)),
            _ => None,
        })
        .collect();
    assert_eq!(
        writes,
        vec![(snowscsi::mmc::cdr_bundle::track_resource(1), 0, BLOCK)],
        "exactly one payload write, into track 1 at offset 0"
    );

    // 9. SYNCHRONIZE CACHE pads and closes the track. A later TAO write may
    //    not restart at block 0: the next writable address moved past the
    //    padded track.
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
            &mut write_host,
            &read_track_information(1, 1, 48),
            Direction::ToHost,
            48,
            &mut work,
            &mut scratch,
        ),
        Completion::Good
    );
    assert_eq!(work[6], 0x81, "RT=1, Data Mode 1");
    assert_eq!(work[7], 0x00, "a closed track has no NWA");
    assert_eq!(&work[24..28], &300u32.to_be_bytes(), "padded to 300 blocks");
    assert_eq!(
        run(
            &mut target,
            &mut storage,
            &mut write_host,
            &write10(0, 1),
            Direction::FromHost,
            BLOCK as u64,
            &mut work,
            &mut scratch,
        ),
        Completion::Check(INVALID_ADDRESS_FOR_WRITE),
        "the write must resume at the new NWA, never overwrite track 1"
    );

    // 10. CLOSE TRACK/SESSION function 2 finalizes the disc.
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
    consume_medium_change(
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
    assert_eq!(work[2], 0x0E, "finalized, last session complete");
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
    assert_eq!(work[6], 1, "track number");
    assert_eq!(&work[8..12], &0u32.to_be_bytes(), "track 1 start");
    assert_eq!(work[14], 0xAA, "lead-out descriptor");
    assert_eq!(&work[16..20], &300u32.to_be_bytes(), "lead-out start");
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
    assert_eq!(&work[0..4], &299u32.to_be_bytes(), "last recorded block");

    // 11. Both saves restore through their physical slot. Slot 0 is the
    //     SYNCHRONIZE CACHE snapshot (track closed, session still open); slot
    //     1 is the finalized disc CLOSE wrote. Both keep track 1 at its
    //     padded length and point its data at resource `16 + 1`.
    let slot0 = storage.inner().slot(0);
    let slot1 = storage.inner().slot(1);
    let synced = CdrBundleMedium::open_at(0, &slot0, SECTORS, Recovery::Delete)
        .expect("toc.0 restores the SYNCHRONIZE CACHE snapshot");
    assert_eq!(
        synced.disc_state(),
        CdrDiscState::Appendable,
        "the sync closed the track but did not finalize the disc"
    );
    assert_eq!(synced.track_numbers().collect::<Vec<_>>(), vec![1]);
    let info = synced
        .track_info(snowscsi::mmc::TrackInfoRequest::Number(1))
        .expect("track 1");
    assert_eq!(info.length, 300);
    assert_eq!(info.nwa, 300);

    let finalized = CdrBundleMedium::open_at(1, &slot1, SECTORS, Recovery::Delete)
        .expect("toc.1 restores the finalized disc");
    assert_eq!(finalized.disc_state(), CdrDiscState::Finalized);
    assert_eq!(finalized.track_numbers().collect::<Vec<_>>(), vec![1]);
    let info = finalized
        .track_info(snowscsi::mmc::TrackInfoRequest::Number(1))
        .expect("track 1");
    assert_eq!(info.length, 300);
    assert_eq!(info.nwa, 300);

    // The restored medium reads the recorded block through track 1's payload
    // resource, and the bytes are the ones the host wrote.
    storage.inner_mut().log.clear();
    let mut reopened_target: CdrTarget = Target::new(cons(
        LuImpl::new(Spc::new(MmcDrive::new(finalized)), 1u8),
        Nil,
    ));
    assert_eq!(
        run(
            &mut reopened_target,
            &mut storage,
            &mut host,
            &read10(0, 1),
            Direction::ToHost,
            BLOCK as u64,
            &mut work,
            &mut scratch,
        ),
        Completion::Good
    );
    assert_eq!(&work[..BLOCK], &payload[..]);
    assert_eq!(
        storage.inner().log,
        vec![Ev::Read(
            snowscsi::mmc::cdr_bundle::track_resource(1),
            0,
            BLOCK
        )],
        "the read is served from track 1 at offset 0"
    );
}

// ═══════════════════════════════════════════════════════════════════════════
// cdrkit `wodim -dummy` trace: Test Write consumes the data phase
// ═══════════════════════════════════════════════════════════════════════════

/// `wodim -dummy -tao` selects Test Write in MODE SELECT page 0x05, sends the
/// payload, flushes and closes the session. Every command must report GOOD
/// while the disc stays blank: the data phase is consumed, no track is
/// created, and no TOC slot is written.
#[test]
fn cdr_dummy_tao_trace_leaves_the_disc_blank() {
    let mut target = cdr_target();
    let mut storage = BlockingStorage::new(Plane::new(16 * BLOCK));
    let mut host = BlockingHost::new(TestHost::new(Vec::new()));
    let mut work = vec![0u8; 4096];
    let mut scratch = vec![0u8; 4096];

    // Drain the install medium-change unit attention.
    consume_medium_change(
        &mut target,
        &mut storage,
        &mut host,
        &mut work,
        &mut scratch,
    );

    // 1. MODE SELECT(10) page 0x05 with Test Write + TAO/DBT 8.
    let mut select_host = BlockingHost::new(TestHost::new(dummy_mode_page()));
    assert_eq!(
        run(
            &mut target,
            &mut storage,
            &mut select_host,
            &mode_select10(60),
            Direction::FromHost,
            60,
            &mut work,
            &mut scratch,
        ),
        Completion::Good
    );

    // 2. MODE SENSE reports the simulated mode back.
    assert_eq!(
        run(
            &mut target,
            &mut storage,
            &mut host,
            &mode_sense10(0x05, 64),
            Direction::ToHost,
            64,
            &mut work,
            &mut scratch,
        ),
        Completion::Good
    );
    assert_eq!(work[10] & 0x10, 0x10, "Test Write is Current");
    assert_eq!(work[10] & 0x0F, 0x01, "Write Type stays TAO");
    assert_eq!(work[12], 0x08, "Data Block Type stays Mode 1");

    // 3. WRITE(10) with FUA at the NWA for a few blocks: the data phase is
    //    larger than the work bank and is consumed without recording. FUA must
    //    not issue the aggregate sync in the simulated mode.
    let payload = vec![0x5A; 3 * BLOCK];
    let mut write_host = BlockingHost::new(TestHost::new(payload));
    let mut write = write10(0, 3);
    write[1] = 0x08; // FUA
    assert_eq!(
        run(
            &mut target,
            &mut storage,
            &mut write_host,
            &write,
            Direction::FromHost,
            3 * BLOCK as u64,
            &mut work,
            &mut scratch,
        ),
        Completion::Good
    );

    // 4. SYNCHRONIZE CACHE and CLOSE TRACK/SESSION 010b are GOOD no-ops.
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

    // 5. No finalize happened, so there is no medium-change unit attention.
    assert_eq!(
        run(
            &mut target,
            &mut storage,
            &mut host,
            &[0u8; 6],
            Direction::None,
            0,
            &mut work,
            &mut scratch,
        ),
        Completion::Good
    );

    // 6. The disc is still blank with the NWA at LBA 0.
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
    assert_eq!(work[2] & 0x03, 0x00, "Empty disc");
    assert_eq!(work[2] & 0x10, 0, "not erasable");
    assert_eq!(work[4], 1, "still one session");
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
    assert_eq!(work[2], 1, "invisible track 1");
    assert_eq!(work[6] & 0x40, 0x40, "invisible (blank) track");
    assert_eq!(&work[12..16], &0u32.to_be_bytes(), "NWA still 0");

    // 7. The backing saw no track write and no TOC save.
    let log = &storage.inner().log;
    assert!(
        !log.iter().any(|event| matches!(event, Ev::Write(..))),
        "a simulated write never reaches storage: {log:?}"
    );
    assert!(
        !log.iter().any(|event| matches!(event, Ev::Sync(_))),
        "neither SYNCHRONIZE CACHE nor CLOSE syncs: {log:?}"
    );

    // 8. Clearing Test Write leaves the disc burnable: the real TAO sequence
    //    starts at LBA 0 as if nothing had happened.
    let mut select_host = BlockingHost::new(TestHost::new(tao_mode_page()));
    assert_eq!(
        run(
            &mut target,
            &mut storage,
            &mut select_host,
            &mode_select10(60),
            Direction::FromHost,
            60,
            &mut work,
            &mut scratch,
        ),
        Completion::Good
    );
    let mut write_host = BlockingHost::new(TestHost::new(vec![0x5A; BLOCK]));
    write_one_block(
        &mut target,
        &mut storage,
        &mut write_host,
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
    consume_medium_change(
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
    assert_eq!(work[2], 0x0E, "the real burn finalized the disc");
}

// ═══════════════════════════════════════════════════════════════════════════
// RESERVE TRACK and the persisted-TOC reopen path
// ═══════════════════════════════════════════════════════════════════════════

#[test]
fn cdr_reserve_write_sync_close_and_reopen_from_a_slot() {
    let mut target = cdr_target();
    let mut storage = BlockingStorage::new(Plane::new(16 * BLOCK));
    let mut host = BlockingHost::new(TestHost::new(vec![0x5A; BLOCK]));
    let mut work = vec![0u8; 4096];
    let mut scratch = vec![0u8; 4096];

    // RESERVE TRACK allocates 500 blocks and persists the reserved TOC.
    assert_eq!(
        run(
            &mut target,
            &mut storage,
            &mut host,
            &reserve_track_cdb(false, 500),
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
            &read_track_information(1, 1, 48),
            Direction::ToHost,
            48,
            &mut work,
            &mut scratch,
        ),
        Completion::Good
    );
    assert_eq!(work[6], 0xC1, "reserved empty track");
    assert_eq!(&work[24..28], &500u32.to_be_bytes(), "allocation");

    // ARSV is not served.
    assert_eq!(
        run(
            &mut target,
            &mut storage,
            &mut host,
            &reserve_track_cdb(true, 500),
            Direction::None,
            0,
            &mut work,
            &mut scratch,
        ),
        Completion::Check(INVALID_FIELD)
    );

    // WRITE one block, close the track with SYNCHRONIZE CACHE, then finalize.
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

    // SYNCHRONIZE CACHE orders the aggregate data sync before the TOC write
    // and the slot sync.
    let log = &storage.inner().log;
    let data_sync = log
        .iter()
        .rposition(|event| *event == Ev::Sync(0))
        .expect("aggregate data sync");
    let toc_write = log
        .iter()
        .rposition(|event| matches!(event, Ev::Write(resource, _, _) if *resource != 0))
        .expect("TOC write");
    let toc_sync = log
        .iter()
        .rposition(|event| matches!(event, Ev::Sync(resource) if *resource != 0))
        .expect("TOC sync");
    assert!(data_sync < toc_write && toc_write < toc_sync);

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

    // Both TOC slots are written; the newest one reopens the finalized disc.
    let slots = [storage.inner().slot(0), storage.inner().slot(1)];
    let mut newest = None;
    let mut newest_seq = 0;
    for slot in &slots {
        if let Ok(medium) = CdrBundleMedium::open(slot, SECTORS, Recovery::Delete) {
            if medium.toc_seq() > newest_seq {
                newest_seq = medium.toc_seq();
                newest = Some(medium);
            }
        }
    }
    let reopened = newest.expect("a valid TOC slot");
    assert_eq!(newest_seq, 3, "reserve, sync and close each saved");
    assert_eq!(reopened.disc_state(), CdrDiscState::Finalized);
    assert_eq!(
        reopened.track_numbers().collect::<Vec<_>>(),
        vec![1],
        "one track survives"
    );
    let info = reopened
        .track_info(snowscsi::mmc::TrackInfoRequest::Number(1))
        .expect("track 1");
    assert_eq!(info.length, 500, "the reservation is padded on close");

    // A fresh target over the reopened medium serves the persisted layout.
    let mut reopened_target: CdrTarget = Target::new(cons(
        LuImpl::new(Spc::new(MmcDrive::new(reopened)), 1u8),
        Nil,
    ));
    assert_eq!(
        run(
            &mut reopened_target,
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
    assert_eq!(&work[8..12], &0u32.to_be_bytes(), "track 1 start");
    assert_eq!(&work[16..20], &500u32.to_be_bytes(), "lead-out");
    assert_eq!(
        run(
            &mut reopened_target,
            &mut storage,
            &mut host,
            &write10(500, 1),
            Direction::FromHost,
            BLOCK as u64,
            &mut work,
            &mut scratch,
        ),
        Completion::Check(WRITE_PROTECTED)
    );
}

#[test]
fn cdr_finalize_reports_a_medium_change_unit_attention() {
    let mut target = cdr_target();
    let mut storage = BlockingStorage::new(Plane::new(16 * BLOCK));
    let mut host = BlockingHost::new(TestHost::new(vec![0x5A; BLOCK]));
    let mut work = vec![0u8; 4096];
    let mut scratch = vec![0u8; 4096];

    assert_eq!(
        run(
            &mut target,
            &mut storage,
            &mut host,
            &write10(0, 1),
            Direction::FromHost,
            BLOCK as u64,
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

    let tur = [0u8; 6];
    assert_eq!(
        run(
            &mut target,
            &mut storage,
            &mut host,
            &tur,
            Direction::None,
            0,
            &mut work,
            &mut scratch,
        ),
        Completion::Check(Sense::new(0x06, 0x28, 0x00)),
        "finalize must report a medium change so the host revalidates"
    );
    assert_eq!(
        run(
            &mut target,
            &mut storage,
            &mut host,
            &tur,
            Direction::None,
            0,
            &mut work,
            &mut scratch,
        ),
        Completion::Good
    );
}

/// Issue READ CAPACITY and return the reported last LBA.
fn capacity_lba(
    target: &mut CdrTarget,
    storage: &mut BlockingStorage<Plane>,
    host: &mut BlockingHost<TestHost>,
    work: &mut [u8],
    scratch: &mut [u8],
) -> u32 {
    assert_eq!(
        run(
            target,
            storage,
            host,
            &read_capacity(),
            Direction::ToHost,
            8,
            work,
            scratch,
        ),
        Completion::Good
    );
    u32::from_be_bytes([work[0], work[1], work[2], work[3]])
}

#[test]
fn cdr_blank_capacity_reports_the_recordable_extent() {
    let mut target = cdr_target();
    let mut storage = BlockingStorage::new(Plane::new(16 * BLOCK));
    let mut host = BlockingHost::new(TestHost::new(Vec::new()));
    let mut work = vec![0u8; 64];
    let mut scratch = vec![0u8; 64];

    // A blank CD-R has no recorded session, but the ATIP extent is already
    // known; the host sizes the block device from it before the first write.
    let capacity = CdrCapacity::Cdr74.sectors();
    assert_eq!(
        capacity_lba(
            &mut target,
            &mut storage,
            &mut host,
            &mut work,
            &mut scratch
        ),
        (capacity - 1) as u32,
        "last writable LBA of the ATIP extent"
    );
    assert_eq!(
        u32::from_be_bytes([work[4], work[5], work[6], work[7]]),
        BLOCK as u32
    );
}

#[test]
fn cdr_unfinalized_capacity_keeps_the_atip_extent() {
    let mut target = cdr_target();
    let mut storage = BlockingStorage::new(Plane::new(16 * BLOCK));
    let mut host = BlockingHost::new(TestHost::new(vec![0x5A; BLOCK]));
    let mut work = vec![0u8; 64];
    let mut scratch = vec![0u8; 64];
    let extent = (CdrCapacity::Cdr74.sectors() - 1) as u32;

    // A reserved-only track has no recorded block, but the disc is appendable
    // and its ATIP geometry already fixes the future lead-out.
    assert_eq!(
        run(
            &mut target,
            &mut storage,
            &mut host,
            &reserve_track_cdb(false, 500),
            Direction::None,
            0,
            &mut work,
            &mut scratch,
        ),
        Completion::Good
    );
    assert_eq!(
        capacity_lba(
            &mut target,
            &mut storage,
            &mut host,
            &mut work,
            &mut scratch
        ),
        extent,
        "a reserved-only appendable disc keeps the ATIP extent"
    );

    // A partially burned track must not shrink the block device mid-burn when
    // the host re-probes READ CAPACITY.
    write_one_block(
        &mut target,
        &mut storage,
        &mut host,
        &mut work,
        &mut scratch,
    );
    assert_eq!(
        capacity_lba(
            &mut target,
            &mut storage,
            &mut host,
            &mut work,
            &mut scratch
        ),
        extent,
        "a partially burned appendable disc keeps the ATIP extent"
    );
}

#[test]
fn cdr_finalized_capacity_reports_the_recorded_extent() {
    let mut target = cdr_target();
    let mut storage = BlockingStorage::new(Plane::new(16 * BLOCK));
    let mut host = BlockingHost::new(TestHost::new(vec![0x5A; BLOCK]));
    let mut work = vec![0u8; 64];
    let mut scratch = vec![0u8; 64];

    // Record three blocks in an implicit track.
    for lba in 0..3u32 {
        assert_eq!(
            run(
                &mut target,
                &mut storage,
                &mut host,
                &write10(lba, 1),
                Direction::FromHost,
                BLOCK as u64,
                &mut work,
                &mut scratch,
            ),
            Completion::Good
        );
    }
    // SYNCHRONIZE CACHE closes the open track; CLOSE TRACK/SESSION finalizes.
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

    // A finalized disc reports the last recorded LBA, not the ATIP extent.
    // Closing pads a track to the minimum length, so the three written blocks
    // finalize as a 300-block track (last LBA 299).
    consume_medium_change(
        &mut target,
        &mut storage,
        &mut host,
        &mut work,
        &mut scratch,
    );
    assert_eq!(
        capacity_lba(
            &mut target,
            &mut storage,
            &mut host,
            &mut work,
            &mut scratch
        ),
        299,
        "last recorded LBA of a finalized disc"
    );
}

#[test]
fn cdr_appendable_reopened_capacity_keeps_the_atip_extent() {
    let mut target = cdr_target();
    let mut storage = BlockingStorage::new(Plane::new(16 * BLOCK));
    let mut host = BlockingHost::new(TestHost::new(vec![0x5A; BLOCK]));
    let mut work = vec![0u8; 64];
    let mut scratch = vec![0u8; 64];

    // One recorded block, closed by SYNCHRONIZE CACHE: the TOC is saved while
    // the disc is still Appendable (not finalized).
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
    let slot = storage.inner().slot(0);
    let medium = CdrBundleMedium::open(&slot, SECTORS, Recovery::Delete).expect("appendable slot");
    assert_eq!(medium.disc_state(), CdrDiscState::Appendable);

    // A medium restored from that slot still reports the ATIP extent, so the
    // block device does not shrink when the host re-probes after a restart.
    let mut reopened: CdrTarget =
        Target::new(cons(LuImpl::new(Spc::new(MmcDrive::new(medium)), 1u8), Nil));
    assert_eq!(
        capacity_lba(
            &mut reopened,
            &mut storage,
            &mut host,
            &mut work,
            &mut scratch
        ),
        (SECTORS - 1) as u32,
        "an appendable restored from its TOC keeps the ATIP extent"
    );
}
