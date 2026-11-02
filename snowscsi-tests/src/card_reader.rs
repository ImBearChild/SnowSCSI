//! Removable block LUN (card reader) integration fixtures.
//!
//! A `BlockDevice` whose `BlockAttrs::removable` is set reports INQUIRY RMB=1
//! and accepts the host START STOP UNIT (`LoEj=1, Start=0`) eject. The slot
//! then detaches its pair and publishes `ResourcesReady`; the LUN stays
//! enumerated as an empty slot (`3A/00` for media commands) until the
//! application installs a replacement pair at the same LUN and raises
//! `UaClass::MediumChanged`.
//!
//! Geometry lives on `BlockDevice`, so a capacity change is modelled the same
//! way the CLI does it: the slot device is rebuilt (with the new geometry)
//! before the new pair is installed. The runner keeps no state across a clean
//! `take`, so this is the documented "same LUN, new medium" flow.

use snowscsi::block::{BlockAttrs, BlockDevice};
use snowscsi::core::storage::{
    BlockingHost, BlockingStorage, HostBuf, HostReceipt, HostReq, IoBuf, IoReq, StorageReceipt,
    SyncHost, SyncStorage,
};
use snowscsi::core::{
    CommandContext, Completion, DataPlan, Delivery, Direction, Effect, Fault, Lu, LuImpl, NoMedium,
    Pair, RunOutcome, Sense, Spc, Target, UaClass, MEDIUM_NOT_PRESENT,
};

type CardSlot = LuImpl<Spc<BlockDevice>, u32>;
type CardTarget<'a> = Target<[&'a mut dyn Lu<Pair = CardPair>; 1]>;
type CardPair = Pair<NoMedium, u32>;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Ev {
    Read(u64, usize),
    Sync,
}

/// Byte plane with an operation trace, so "no storage IO" is observable.
struct Plane {
    mem: Vec<u8>,
    log: Vec<Ev>,
}

impl Plane {
    fn new(len: usize, fill: u8) -> Self {
        Self {
            mem: vec![fill; len],
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
                self.log.push(Ev::Read(req.offset, b.len()));
                let start = req.offset as usize;
                let end = start.saturating_add(b.len());
                if end > self.mem.len() {
                    return StorageReceipt::failed(Fault::OutOfBounds, 0, Effect::Known);
                }
                b.copy_from_slice(&self.mem[start..end]);
                StorageReceipt::ok(b.len())
            }
            _ => StorageReceipt::failed(Fault::Contract, 0, Effect::Known),
        }
    }
}

#[derive(Default)]
struct TestHost {
    /// Device → host bytes, in send order.
    sent: Vec<u8>,
}

impl SyncHost for TestHost {
    fn publish(&mut self, _plan: DataPlan) -> Result<(), Fault> {
        Ok(())
    }

    fn receive(&mut self, _req: HostReq, _buf: HostBuf<'_>) -> HostReceipt {
        HostReceipt::from_adapter(0, Some(Fault::Contract))
    }

    fn send(&mut self, _req: HostReq, buf: HostBuf<'_>) -> HostReceipt {
        match buf {
            HostBuf::Send { bytes, .. } => {
                self.sent.extend_from_slice(bytes);
                HostReceipt::from_adapter(bytes.len(), None)
            }
            HostBuf::Recv { .. } => HostReceipt::from_adapter(0, Some(Fault::Contract)),
        }
    }

    fn delivery(&self) -> Delivery {
        Delivery::Complete
    }
}

fn ctx(direction: Direction, bytes: u64) -> CommandContext {
    CommandContext {
        lun: 0,
        lun_count: 1,
        host_bytes: bytes,
        host_direction: direction,
    }
}

fn make_slot(attrs: BlockAttrs, backing: u32) -> CardSlot {
    LuImpl::new(Spc::new(BlockDevice::new(attrs)), backing)
}

fn make_target(slot: &mut CardSlot) -> CardTarget<'_> {
    Target::new([slot as &mut dyn Lu<Pair = CardPair>])
}

fn drive(
    target: &mut CardTarget<'_>,
    storage: &mut BlockingStorage<Plane>,
    host: &mut BlockingHost<TestHost>,
    direction: Direction,
    bytes: u64,
    cdb: &[u8],
    work: &mut [u8],
    scratch: &mut [u8],
) -> Completion {
    target
        .drive_rt_host(0, storage, host, ctx(direction, bytes), cdb, work, scratch)
        .expect("no runner fault")
}

fn inquiry() -> [u8; 6] {
    [0x12, 0, 0, 0, 36, 0]
}

fn tur() -> [u8; 6] {
    [0x00, 0, 0, 0, 0, 0]
}

fn start_stop_eject() -> [u8; 6] {
    [0x1B, 0, 0, 0, 0x02, 0]
}

fn read_capacity() -> [u8; 10] {
    [0x25, 0, 0, 0, 0, 0, 0, 0, 0, 0]
}

fn read10(lba: u32, blocks: u16) -> [u8; 10] {
    let mut cdb = [0u8; 10];
    cdb[0] = 0x28;
    cdb[2..6].copy_from_slice(&lba.to_be_bytes());
    cdb[7..9].copy_from_slice(&blocks.to_be_bytes());
    cdb
}

fn prevent_allow() -> [u8; 6] {
    [0x1E, 0, 0, 0, 0, 0]
}

fn report_luns() -> [u8; 10] {
    [0xA0, 0, 0, 0, 0, 0, 0, 0, 0, 8]
}

#[test]
fn removable_block_reports_rmb_and_its_geometry() {
    let attrs = BlockAttrs::new(16, 512).with_removable();
    let mut slot = make_slot(attrs, 1);
    let mut target = make_target(&mut slot);
    let mut storage = BlockingStorage::new(Plane::new(16 * 512, 0xAB));
    let mut host = BlockingHost::new(TestHost::default());
    let mut work = vec![0u8; 4096];
    let mut scratch = vec![0u8; 64];

    assert_eq!(
        drive(
            &mut target,
            &mut storage,
            &mut host,
            Direction::ToHost,
            36,
            &inquiry(),
            &mut work,
            &mut scratch,
        ),
        Completion::Good
    );
    assert_eq!(work[0], 0x00, "block PDT");
    assert_eq!(work[1] & 0x80, 0x80, "INQUIRY RMB follows BlockAttrs");

    assert_eq!(
        drive(
            &mut target,
            &mut storage,
            &mut host,
            Direction::ToHost,
            8,
            &read_capacity(),
            &mut work,
            &mut scratch,
        ),
        Completion::Good
    );
    assert_eq!(
        u32::from_be_bytes([work[0], work[1], work[2], work[3]]),
        15,
        "last LBA of the installed geometry"
    );
    assert_eq!(
        u32::from_be_bytes([work[4], work[5], work[6], work[7]]),
        512,
        "block length of the installed geometry"
    );
}

#[test]
fn host_eject_detaches_the_pair_and_publishes_resources_ready() {
    let attrs = BlockAttrs::new(16, 512).with_removable();
    let mut slot = make_slot(attrs, 1);
    let mut target = make_target(&mut slot);
    let mut storage = BlockingStorage::new(Plane::new(16 * 512, 0xAB));
    let mut host = BlockingHost::new(TestHost::default());
    let mut work = vec![0u8; 4096];
    let mut scratch = vec![0u8; 64];

    assert_eq!(
        drive(
            &mut target,
            &mut storage,
            &mut host,
            Direction::None,
            0,
            &start_stop_eject(),
            &mut work,
            &mut scratch,
        ),
        Completion::Good,
        "the ejecting START STOP UNIT completes GOOD"
    );
    assert_eq!(target.tick(), RunOutcome::ResourcesReady { lun: 0 });
    assert!(!target.snapshot_rt(0).expect("slot").ready);

    let pair: CardPair = target
        .take_rt(0)
        .expect("detached pair")
        .pair
        .expect("pair");
    assert_eq!(
        pair.backing, 1,
        "the application gets its backing handle back"
    );
    assert_eq!(
        target.take_rt(0),
        Err(snowscsi::core::BoundaryReject::NothingToTake)
    );
}

#[test]
fn empty_removable_lun_answers_queries_and_rejects_media_commands() {
    let attrs = BlockAttrs::new(16, 512).with_removable();
    let mut slot = make_slot(attrs, 1);
    let mut target = make_target(&mut slot);
    let mut storage = BlockingStorage::new(Plane::new(16 * 512, 0xAB));
    let mut host = BlockingHost::new(TestHost::default());
    let mut work = vec![0u8; 4096];
    let mut scratch = vec![0u8; 64];

    assert_eq!(
        drive(
            &mut target,
            &mut storage,
            &mut host,
            Direction::None,
            0,
            &start_stop_eject(),
            &mut work,
            &mut scratch,
        ),
        Completion::Good
    );
    assert_eq!(target.tick(), RunOutcome::ResourcesReady { lun: 0 });
    let _ = target.take_rt(0).expect("detached pair");

    let io_before = storage.inner().log.len();

    // Empty-slot queries stay answerable. TUR is a media command and reports
    // no medium; INQUIRY and REPORT LUNS answer normally.
    assert_eq!(
        drive(
            &mut target,
            &mut storage,
            &mut host,
            Direction::None,
            0,
            &tur(),
            &mut work,
            &mut scratch,
        ),
        Completion::Check(MEDIUM_NOT_PRESENT)
    );
    host.inner_mut().sent.clear();
    assert_eq!(
        drive(
            &mut target,
            &mut storage,
            &mut host,
            Direction::ToHost,
            36,
            &inquiry(),
            &mut work,
            &mut scratch,
        ),
        Completion::Good
    );
    assert_eq!(work[1] & 0x80, 0x80, "RMB survives the eject");
    assert_eq!(
        drive(
            &mut target,
            &mut storage,
            &mut host,
            Direction::ToHost,
            8,
            &report_luns(),
            &mut work,
            &mut scratch,
        ),
        Completion::Good
    );

    // Media commands are MEDIUM NOT PRESENT, not a storage fault, and issue
    // no backing IO.
    assert_eq!(
        drive(
            &mut target,
            &mut storage,
            &mut host,
            Direction::ToHost,
            512,
            &read10(0, 1),
            &mut work,
            &mut scratch,
        ),
        Completion::Check(MEDIUM_NOT_PRESENT)
    );
    assert_eq!(
        drive(
            &mut target,
            &mut storage,
            &mut host,
            Direction::ToHost,
            8,
            &read_capacity(),
            &mut work,
            &mut scratch,
        ),
        Completion::Check(MEDIUM_NOT_PRESENT),
        "an empty slot must not report capacity 0"
    );
    assert_eq!(
        drive(
            &mut target,
            &mut storage,
            &mut host,
            Direction::None,
            0,
            &prevent_allow(),
            &mut work,
            &mut scratch,
        ),
        Completion::Check(MEDIUM_NOT_PRESENT),
        "PREVENT/ALLOW stays rejected on an empty slot"
    );
    assert_eq!(
        storage.inner().log.len(),
        io_before,
        "an empty slot must not issue storage IO"
    );
}

#[test]
fn a_new_card_at_the_same_lun_reports_its_geometry_after_one_medium_changed_ua() {
    // Eject the first card and drop the pair.
    let mut old_slot = make_slot(BlockAttrs::new(16, 512).with_removable(), 1);
    let mut target = make_target(&mut old_slot);
    let mut storage = BlockingStorage::new(Plane::new(16 * 512, 0xAB));
    let mut host = BlockingHost::new(TestHost::default());
    let mut work = vec![0u8; 4096];
    let mut scratch = vec![0u8; 64];

    assert_eq!(
        drive(
            &mut target,
            &mut storage,
            &mut host,
            Direction::None,
            0,
            &start_stop_eject(),
            &mut work,
            &mut scratch,
        ),
        Completion::Good
    );
    assert_eq!(target.tick(), RunOutcome::ResourcesReady { lun: 0 });
    let old = target.take_rt(0).expect("old pair");
    assert_eq!(old.pair.map(|p| p.backing), Some(1));
    drop(target);

    // Application rebuilds the LUN device with the new card geometry (same
    // LUN), then installs the new pair and raises MediumChanged before
    // service resumes.
    let new_attrs = BlockAttrs::new(24, 512).with_removable();
    let mut new_slot = LuImpl::empty(Spc::new(BlockDevice::new(new_attrs)));
    let mut target = make_target(&mut new_slot);
    assert_eq!(
        target.install_rt(
            0,
            CardPair {
                medium: NoMedium,
                backing: 2,
            }
        ),
        Ok(())
    );
    assert_eq!(target.raise_ua_rt(0, UaClass::MediumChanged), Ok(()));

    let mut storage = BlockingStorage::new(Plane::new(24 * 512, 0xCD));
    let mut host = BlockingHost::new(TestHost::default());

    // The first reporting command consumes the unit attention exactly once.
    assert_eq!(
        drive(
            &mut target,
            &mut storage,
            &mut host,
            Direction::None,
            0,
            &tur(),
            &mut work,
            &mut scratch,
        ),
        Completion::Check(Sense::new(0x06, 0x28, 0x00)),
        "MEDIUM CHANGED UA"
    );
    assert_eq!(
        drive(
            &mut target,
            &mut storage,
            &mut host,
            Direction::None,
            0,
            &tur(),
            &mut work,
            &mut scratch,
        ),
        Completion::Good,
        "the UA is reported exactly once"
    );

    assert_eq!(
        drive(
            &mut target,
            &mut storage,
            &mut host,
            Direction::ToHost,
            8,
            &read_capacity(),
            &mut work,
            &mut scratch,
        ),
        Completion::Good
    );
    assert_eq!(
        u32::from_be_bytes([work[0], work[1], work[2], work[3]]),
        23,
        "the new card's capacity is reported"
    );
    assert_eq!(
        u32::from_be_bytes([work[4], work[5], work[6], work[7]]),
        512
    );

    host.inner_mut().sent.clear();
    assert_eq!(
        drive(
            &mut target,
            &mut storage,
            &mut host,
            Direction::ToHost,
            1024,
            &read10(0, 2),
            &mut work,
            &mut scratch,
        ),
        Completion::Good
    );
    assert_eq!(
        host.inner().sent,
        vec![0xCD; 1024],
        "READ(10) reads the new plane's bytes"
    );
}

#[test]
fn a_fixed_block_lun_ignores_loej() {
    let mut slot = make_slot(BlockAttrs::new(16, 512), 1);
    let mut target = make_target(&mut slot);
    let mut storage = BlockingStorage::new(Plane::new(16 * 512, 0xAB));
    let mut host = BlockingHost::new(TestHost::default());
    let mut work = vec![0u8; 4096];
    let mut scratch = vec![0u8; 64];

    assert_eq!(
        drive(
            &mut target,
            &mut storage,
            &mut host,
            Direction::None,
            0,
            &start_stop_eject(),
            &mut work,
            &mut scratch,
        ),
        Completion::Good
    );
    assert_ne!(
        target.tick(),
        RunOutcome::ResourcesReady { lun: 0 },
        "a fixed LUN never hands its pair back on LoEj"
    );
    assert!(target.snapshot_rt(0).expect("slot").ready);
    assert_eq!(
        target.take_rt(0),
        Err(snowscsi::core::BoundaryReject::NothingToTake)
    );
    assert_eq!(
        drive(
            &mut target,
            &mut storage,
            &mut host,
            Direction::None,
            0,
            &tur(),
            &mut work,
            &mut scratch,
        ),
        Completion::Good,
        "the fixed medium is still installed"
    );
}
