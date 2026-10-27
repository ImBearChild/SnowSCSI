//! Long-operation and resident-query fixtures.
//!
//! Covered here (`__ARCH__/design/03-lifecycles.md` §3.7,
//! `02-api-core.md` §4.12):
//!
//! 1. a long entry uses the `scratch` bank only; a sentinel in `work` survives
//!    the whole operation (D1);
//! 2. a `Fault::Contract` long-operation receipt is fed back before the error,
//!    so the next entry settles and never re-issues the cancelled write (D2);
//! 3. the drive-owned zero-fill ends with exactly one `Sync` (D3 success);
//! 4. a failing final `Sync` settles the device with an error, no GOOD and no
//!    replay (D3 failure);
//! 5. GC/GESN answer explicitly after `take_medium` (D4);
//! 6. INQUIRY/RS/GC/GESN are admitted with `work` while TUR/READ/WRITE get
//!    `2/04/04`, with zero medium/backing access, and the long op still
//!    advances from `scratch`.
//!
//! The compile-time borrow-domain proof (D6) lives next to the concrete
//! `MmcDrive` in `snowscsi/src/mmc/drive.rs` so it can name the profile type.

use snowscsi::core::storage::{
    BlockingHost, BlockingStorage, HostBuf, HostReceipt, HostReq, IoBuf, IoReq, StorageReceipt,
    SyncHost, SyncStorage,
};
use snowscsi::core::{
    cons, At, BoundaryReject, Change, CommandContext, Completion, Cons, Control, DataPlan,
    Delivery, Device, Direction, DriveStep, Effect, Fault, Here, InquiryData, LongInfo, LongPhase,
    Lu, LuImpl, Nil, Pair, RemovalEncoding, RemovalLocks, RunOutcome, Sense, SlotSet, Spc,
    SpcProfile, StaticTarget, Target, FORMAT_IN_PROGRESS, MEDIUM_NOT_PRESENT,
};
use snowscsi::mmc::{
    DiscInfo, DiscStatus, MmcAttrs, MmcDrive, MmcMedium, MmcOp, MmcWriteMode, Session, Track,
    TrackKind,
};
use std::cell::Cell;
use std::rc::Rc;

// ═══════════════════════════════════════════════════════════════════════════
// Byte-plane storage double
// ═══════════════════════════════════════════════════════════════════════════

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Ev {
    Read(u64, usize),
    Write(u64, usize),
    Sync,
}

struct Plane {
    mem: Vec<u8>,
    log: Vec<Ev>,
    write_zero: Vec<bool>,
    write_error: Option<Fault>,
    sync_error: Option<Fault>,
}

impl Plane {
    fn new(len: usize) -> Self {
        Self {
            mem: vec![0xEE; len],
            log: Vec::new(),
            write_zero: Vec::new(),
            write_error: None,
            sync_error: None,
        }
    }

    fn writes(&self) -> Vec<(u64, usize)> {
        self.log
            .iter()
            .filter_map(|ev| match ev {
                Ev::Write(offset, len) => Some((*offset, *len)),
                _ => None,
            })
            .collect()
    }

    fn syncs(&self) -> usize {
        self.log.iter().filter(|ev| matches!(ev, Ev::Sync)).count()
    }

    fn zeroed(&self, len: usize) -> bool {
        self.mem.len() >= len && self.mem[..len].iter().all(|b| *b == 0)
    }
}

impl SyncStorage for Plane {
    fn exec(&mut self, req: IoReq, buf: IoBuf<'_>) -> StorageReceipt {
        match (req.dir, buf) {
            (Direction::None, IoBuf::None) => {
                self.log.push(Ev::Sync);
                match self.sync_error {
                    Some(error) => StorageReceipt::failed(error, 0, Effect::Known),
                    None => StorageReceipt::ok(0),
                }
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
            (Direction::FromHost, IoBuf::Write(b)) => {
                self.log.push(Ev::Write(req.offset, b.len()));
                self.write_zero.push(b.iter().all(|byte| *byte == 0));
                if let Some(error) = self.write_error {
                    return StorageReceipt::failed(error, 0, Effect::Known);
                }
                let start = req.offset as usize;
                let end = start.saturating_add(b.len());
                if end > self.mem.len() {
                    return StorageReceipt::failed(Fault::OutOfBounds, 0, Effect::Known);
                }
                self.mem[start..end].copy_from_slice(b);
                StorageReceipt::ok(b.len())
            }
            _ => StorageReceipt::failed(Fault::Contract, 0, Effect::Known),
        }
    }
}

// ═══════════════════════════════════════════════════════════════════════════
// Medium + host doubles
// ═══════════════════════════════════════════════════════════════════════════

#[derive(Clone, Debug, Default)]
struct Counters {
    begins: Rc<Cell<u32>>,
    polls: Rc<Cell<u32>>,
}

impl Counters {
    fn snap(&self) -> (u32, u32) {
        (self.begins.get(), self.polls.get())
    }
}

#[derive(Debug)]
struct SpyMedium {
    attrs: MmcAttrs,
    counters: Counters,
}

impl SpyMedium {
    fn with_counters(sectors: u64, counters: Counters) -> Self {
        Self {
            attrs: MmcAttrs {
                write_mode: MmcWriteMode::Rewritable,
                block_len: 2048,
                sectors,
                tracks: 1,
                sessions: 1,
                write_protected: false,
                needs_recovery: false,
            },
            counters,
        }
    }
}

impl MmcMedium for SpyMedium {
    type State = ();

    fn attrs(&self) -> MmcAttrs {
        self.attrs
    }

    fn state(&self) -> &Self::State {
        &()
    }

    fn begin(&mut self, _op: MmcOp) -> Result<(), Completion> {
        self.counters.begins.set(self.counters.begins.get() + 1);
        Err(Completion::Good)
    }

    fn poll<'a>(
        &mut self,
        _fb: snowscsi::core::Feedback,
        _data: &'a mut [u8],
    ) -> snowscsi::core::PollStep<'a> {
        self.counters.polls.set(self.counters.polls.get() + 1);
        snowscsi::core::PollStep::Idle
    }

    fn active(&self) -> bool {
        false
    }

    fn interrupt(
        &mut self,
        _reason: snowscsi::core::InterruptReason,
        _known: snowscsi::core::KnownEffects,
    ) {
    }

    fn track(&self, number: u16) -> Option<Track> {
        (number == 1).then_some(Track {
            number: 1,
            session: 1,
            start_lba: 0,
            blocks: self.attrs.sectors,
            kind: TrackKind::Data,
        })
    }

    fn session(&self, number: u16) -> Option<Session> {
        (number == 1).then_some(Session {
            number: 1,
            first_track: 1,
            last_track: 1,
            start_lba: 0,
        })
    }

    fn disc_info(&self) -> DiscInfo {
        DiscInfo {
            status: DiscStatus::Finalized,
            sessions: 1,
            last_session_lba: self.attrs.sectors.saturating_sub(1),
            writable: true,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum HostEvent {
    Publish(DataPlan),
    Sent(usize),
}

struct TestHost {
    params: [u8; 12],
    events: Vec<HostEvent>,
}

impl TestHost {
    fn params(params: [u8; 12]) -> Self {
        Self {
            params,
            events: Vec::new(),
        }
    }

    fn data() -> Self {
        Self::params([0u8; 12])
    }
}

impl SyncHost for TestHost {
    fn publish(&mut self, plan: DataPlan) -> Result<(), Fault> {
        self.events.push(HostEvent::Publish(plan));
        Ok(())
    }

    fn receive(&mut self, req: HostReq, buf: HostBuf<'_>) -> HostReceipt {
        match buf {
            HostBuf::Recv(bytes) => {
                let n = (req.len as usize).min(bytes.len()).min(self.params.len());
                bytes[..n].copy_from_slice(&self.params[..n]);
                HostReceipt::from_adapter(n, None)
            }
            HostBuf::Send(_) => HostReceipt::from_adapter(0, Some(Fault::Contract)),
        }
    }

    fn send(&mut self, req: HostReq, _buf: HostBuf<'_>) -> HostReceipt {
        let accepted = req.len as usize;
        self.events.push(HostEvent::Sent(accepted));
        HostReceipt::from_adapter(accepted, None)
    }

    fn delivery(&self) -> Delivery {
        Delivery::Complete
    }
}

// ═══════════════════════════════════════════════════════════════════════════
// Target helpers
// ═══════════════════════════════════════════════════════════════════════════

type MmcTarget = Target<Cons<LuImpl<Spc<MmcDrive<SpyMedium>>, u8>, Nil>>;

fn target(sectors: u64) -> MmcTarget {
    target_counted(sectors).0
}

fn target_counted(sectors: u64) -> (MmcTarget, Counters) {
    let counters = Counters::default();
    let target = Target::new(cons(
        LuImpl::new(
            Spc::new(MmcDrive::new(SpyMedium::with_counters(
                sectors,
                counters.clone(),
            ))),
            1u8,
        ),
        Nil,
    ));
    (target, counters)
}

fn ctx(direction: Direction, bytes: u64) -> CommandContext {
    CommandContext {
        lun: 0,
        lun_count: 1,
        host_bytes: bytes,
        host_direction: direction,
    }
}

fn ctx_lun(lun: u64, direction: Direction, bytes: u64) -> CommandContext {
    CommandContext {
        lun,
        lun_count: 2,
        host_bytes: bytes,
        host_direction: direction,
    }
}

fn slot0<S>(target: &Target<S>) -> &<S as At<Here>>::Slot
where
    S: SlotSet + At<Here>,
{
    <S as At<Here>>::slot(target.slots())
}

fn format_params(header: u8, block_len: u32) -> [u8; 12] {
    let mut p = [0u8; 12];
    p[1] = header;
    p[2..4].copy_from_slice(&8u16.to_be_bytes());
    p[8] = 0x00; // Format Type 0 (full format)
    p[9] = (block_len >> 16) as u8;
    p[10] = (block_len >> 8) as u8;
    p[11] = block_len as u8;
    p
}

/// Start FORMAT UNIT with IMMED=1 (FOV | DCRT | Immed) and its 12-byte list.
fn start_immed_format(
    target: &mut MmcTarget,
    storage: &mut BlockingStorage<Plane>,
    host: &mut BlockingHost<TestHost>,
    work: &mut [u8],
    scratch: &mut [u8],
) -> Completion {
    start_immed_format_dev(target, 0, storage, host, work, scratch)
}

fn start_immed_format_dev<D: Device>(
    target: &mut Target<Cons<LuImpl<D, u8>, Nil>>,
    lun: u64,
    storage: &mut BlockingStorage<Plane>,
    host: &mut BlockingHost<TestHost>,
    work: &mut [u8],
    scratch: &mut [u8],
) -> Completion {
    let params = format_params(0xA2, 0);
    *host = BlockingHost::new(TestHost::params(params));
    target
        .drive_static_host::<Here>(
            storage,
            host,
            ctx_lun(lun, Direction::FromHost, 12),
            &[0x04, 0x11, 0, 0, 0, 0],
            work,
            scratch,
        )
        .expect("FORMAT start")
}

// ═══════════════════════════════════════════════════════════════════════════
// Two-LUN runtime target
// ═══════════════════════════════════════════════════════════════════════════

type TwoPair = Pair<SpyMedium, u8>;
type TwoTarget<'a> = Target<[&'a mut dyn Lu<Pair = TwoPair>; 2]>;

/// Build a two-LUN runtime target; the slot devices stay in the test scope.
macro_rules! two_lun_target {
    ($name:ident, $sectors:expr, $c0:ident, $c1:ident) => {
        let $c0 = Counters::default();
        let $c1 = Counters::default();
        let mut d0 = LuImpl::new(
            Spc::new(MmcDrive::new(SpyMedium::with_counters(
                $sectors,
                $c0.clone(),
            ))),
            1u8,
        );
        let mut d1 = LuImpl::new(
            Spc::new(MmcDrive::new(SpyMedium::with_counters(
                $sectors,
                $c1.clone(),
            ))),
            2u8,
        );
        let mut $name: TwoTarget<'_> = Target::new([
            &mut d0 as &mut dyn Lu<Pair = TwoPair>,
            &mut d1 as &mut dyn Lu<Pair = TwoPair>,
        ]);
    };
}

fn start_immed_format_rt(
    target: &mut TwoTarget<'_>,
    lun: usize,
    storage: &mut BlockingStorage<Plane>,
    host: &mut BlockingHost<TestHost>,
    work: &mut [u8],
    scratch: &mut [u8],
) -> Completion {
    let params = format_params(0xA2, 0);
    *host = BlockingHost::new(TestHost::params(params));
    target
        .drive_rt_host(
            lun,
            storage,
            host,
            ctx_lun(lun as u64, Direction::FromHost, 12),
            &[0x04, 0x11, 0, 0, 0, 0],
            work,
            scratch,
        )
        .expect("FORMAT start")
}

fn poll_long_rt(
    target: &mut TwoTarget<'_>,
    lun: usize,
    storage: &mut BlockingStorage<Plane>,
    work: &mut [u8],
    scratch: &mut [u8],
) -> Result<LongInfo, Fault> {
    target.poll_long_entry_rt(lun, storage, work, scratch)
}

// ═══════════════════════════════════════════════════════════════════════════
// Delivery/interrupt counting device wrapper
// ═══════════════════════════════════════════════════════════════════════════

#[derive(Clone)]
struct Life {
    deliveries: Rc<Cell<u32>>,
    interrupts: Rc<Cell<u32>>,
}

impl Life {
    fn new() -> Self {
        Self {
            deliveries: Rc::new(Cell::new(0)),
            interrupts: Rc::new(Cell::new(0)),
        }
    }

    fn snap(&self) -> (u32, u32) {
        (self.deliveries.get(), self.interrupts.get())
    }
}

struct Counting<D> {
    inner: D,
    life: Life,
}

impl<D: Device> Device for Counting<D> {
    type Medium = D::Medium;

    fn inquiry_data(&self) -> InquiryData {
        self.inner.inquiry_data()
    }

    fn removal_encoding(&self) -> RemovalEncoding {
        self.inner.removal_encoding()
    }

    fn spc_profile(&self) -> Option<&dyn SpcProfile> {
        self.inner.spc_profile()
    }

    fn removal_locks(&self) -> Option<RemovalLocks> {
        self.inner.removal_locks()
    }

    fn prepare(
        &mut self,
        permit: &snowscsi::core::CommandPermit,
        ctx: CommandContext,
        cdb: &[u8],
    ) -> Result<(), Completion> {
        self.inner.prepare(permit, ctx, cdb)
    }

    fn active(&self) -> bool {
        self.inner.active()
    }

    fn resume(&mut self, permit: &snowscsi::core::CommandPermit) -> Result<(), Completion> {
        self.inner.resume(permit)
    }

    fn poll<'a>(
        &mut self,
        permit: &snowscsi::core::CommandPermit,
        fb: snowscsi::core::Feedback,
        data: &'a mut [u8],
    ) -> snowscsi::core::PollStep<'a> {
        self.inner.poll(permit, fb, data)
    }

    fn poll_long<'a>(
        &mut self,
        permit: &snowscsi::core::CommandPermit,
        fb: snowscsi::core::Feedback,
        data: &'a mut [u8],
    ) -> snowscsi::core::PollStep<'a> {
        self.inner.poll_long(permit, fb, data)
    }

    fn long_info(&self) -> LongInfo {
        self.inner.long_info()
    }

    fn interrupt(
        &mut self,
        permit: &snowscsi::core::CommandPermit,
        reason: snowscsi::core::InterruptReason,
        known: snowscsi::core::KnownEffects,
    ) -> Result<(), Fault> {
        self.life.interrupts.set(self.life.interrupts.get() + 1);
        self.inner.interrupt(permit, reason, known)
    }

    fn finish_delivery(&mut self, permit: &snowscsi::core::CommandPermit, delivery: Delivery) {
        self.life.deliveries.set(self.life.deliveries.get() + 1);
        self.inner.finish_delivery(permit, delivery);
    }

    fn commit(&mut self, permit: &snowscsi::core::BoundaryPermit) -> Result<(), Completion> {
        self.inner.commit(permit)
    }

    fn host_eject_succeeded(&mut self, permit: &snowscsi::core::BoundaryPermit) {
        self.inner.host_eject_succeeded(permit);
    }

    fn take_medium(&mut self, permit: &snowscsi::core::BoundaryPermit) -> Option<Self::Medium> {
        self.inner.take_medium(permit)
    }

    fn install_medium(
        &mut self,
        permit: &snowscsi::core::BoundaryPermit,
        medium: Self::Medium,
    ) -> Result<(), (Self::Medium, Fault)> {
        self.inner.install_medium(permit, medium)
    }
}

type CountingTarget = Target<Cons<LuImpl<Counting<MmcDrive<SpyMedium>>, u8>, Nil>>;

fn counting_target(sectors: u64) -> (CountingTarget, Life) {
    let life = Life::new();
    let target = Target::new(cons(
        LuImpl::new(
            Counting {
                inner: MmcDrive::new(SpyMedium::with_counters(sectors, Counters::default())),
                life: life.clone(),
            },
            1u8,
        ),
        Nil,
    ));
    (target, life)
}

fn tur_cdb() -> [u8; 6] {
    [0x00, 0, 0, 0, 0, 0]
}

fn read10(lba: u32, blocks: u16) -> [u8; 10] {
    let mut cdb = [0u8; 10];
    cdb[0] = 0x28;
    cdb[2..6].copy_from_slice(&lba.to_be_bytes());
    cdb[7..9].copy_from_slice(&blocks.to_be_bytes());
    cdb
}

fn write10(lba: u32, blocks: u16) -> [u8; 10] {
    let mut cdb = read10(lba, blocks);
    cdb[0] = 0x2A;
    cdb
}

fn get_configuration(rt: u8, alloc: u16) -> [u8; 10] {
    let mut cdb = [0u8; 10];
    cdb[0] = 0x46;
    cdb[1] = rt & 0x03;
    cdb[7] = (alloc >> 8) as u8;
    cdb[8] = alloc as u8;
    cdb
}

fn gesn(class: u8, poll: bool, alloc: u16) -> [u8; 10] {
    let mut cdb = [0u8; 10];
    cdb[0] = 0x4A;
    cdb[1] = u8::from(poll);
    cdb[4] = class;
    cdb[7] = (alloc >> 8) as u8;
    cdb[8] = alloc as u8;
    cdb
}

fn inquiry() -> [u8; 6] {
    let mut cdb = [0u8; 6];
    cdb[0] = 0x12;
    cdb[4] = 0xFF;
    cdb
}

fn request_sense() -> [u8; 6] {
    [0x03, 0, 0, 0, 18, 0]
}

// ═══════════════════════════════════════════════════════════════════════════
// D1 — the long entry uses `scratch`; `work` keeps its sentinel
// ═══════════════════════════════════════════════════════════════════════════

#[test]
fn long_entry_uses_scratch_and_leaves_work_untouched() {
    let mut target = target(4);
    let mut storage = BlockingStorage::new(Plane::new(16 * 1024));
    let mut host = BlockingHost::new(TestHost::data());
    let mut work = vec![0u8; 4096];
    let mut scratch = vec![0u8; 4096];

    assert_eq!(
        start_immed_format(
            &mut target,
            &mut storage,
            &mut host,
            &mut work,
            &mut scratch
        ),
        Completion::Good
    );
    // From here on `work` belongs to command traffic; the resident fill must
    // never read or write it.
    work.fill(0xA5);
    scratch.fill(0xFF);

    let mut entries = 0;
    loop {
        let info = target
            .poll_long_entry_static::<Here>(&mut storage, &mut work, &mut scratch)
            .expect("poll_long");
        entries += 1;
        assert!(entries < 16, "the long operation did not settle");
        assert!(
            work.iter().all(|b| *b == 0xA5),
            "a long entry must not touch the command bank"
        );
        if info.phase == LongPhase::Settled {
            assert_eq!(info.error, None);
            break;
        }
        assert_eq!(info.phase, LongPhase::Foreground);
    }

    assert_eq!(
        storage.inner().writes(),
        vec![(0, 4096), (4096, 4096)],
        "the zero-fill must be chunked from scratch, not work"
    );
    assert!(storage.inner().write_zero.iter().all(|z| *z));
    assert!(storage.inner().zeroed(8192));
    assert_eq!(storage.inner().syncs(), 1);
    assert!(work.iter().all(|b| *b == 0xA5));
}

// ═══════════════════════════════════════════════════════════════════════════
// D2 — a Contract receipt is fed back before the error
// ═══════════════════════════════════════════════════════════════════════════

#[test]
fn a_contract_long_receipt_settles_before_the_error_and_is_never_reissued() {
    let mut target = target(1);
    let mut plane = Plane::new(2048);
    plane.write_error = Some(Fault::Contract);
    let mut storage = BlockingStorage::new(plane);
    let mut host = BlockingHost::new(TestHost::data());
    let mut work = vec![0u8; 4096];
    let mut scratch = vec![0u8; 4096];

    assert_eq!(
        start_immed_format(
            &mut target,
            &mut storage,
            &mut host,
            &mut work,
            &mut scratch
        ),
        Completion::Good
    );
    assert_eq!(
        target.poll_long_entry_static::<Here>(&mut storage, &mut work, &mut scratch),
        Err(Fault::Contract),
        "the entry surfaces the contract fault"
    );
    assert_eq!(
        storage.inner().writes(),
        vec![(0, 2048)],
        "the first write was issued and then cancelled"
    );
    // The receipt is delivered in the same entry, so the device is
    // already Settled when the error surfaces and `take` is not blocked by
    // `LongOperationActive`.
    let info = target.snapshot_static::<Here>().long;
    assert_eq!(info.phase, LongPhase::Settled);
    assert_eq!(info.error, Some(Fault::Contract));
    assert_eq!(info.progress, Some(0));
    assert!(
        matches!(
            target.take_static_at::<Here>(0),
            Err(BoundaryReject::NothingToTake)
        ),
        "the long operation no longer blocks take"
    );

    // The next entry stays settled and does not re-issue the write.
    assert_eq!(
        target.poll_long_entry_static::<Here>(&mut storage, &mut work, &mut scratch),
        Ok(LongInfo {
            phase: LongPhase::Settled,
            write_accessible: true,
            progress: Some(0),
            error: Some(Fault::Contract),
        })
    );
    assert_eq!(
        storage.inner().writes(),
        vec![(0, 2048)],
        "the cancelled write must not be replayed"
    );
    // A settled operation is inert; no further storage IO.
    assert_eq!(
        target.poll_long_entry_static::<Here>(&mut storage, &mut work, &mut scratch),
        Ok(LongInfo {
            phase: LongPhase::Settled,
            write_accessible: true,
            progress: Some(0),
            error: Some(Fault::Contract),
        })
    );
    assert_eq!(storage.inner().writes(), vec![(0, 2048)]);
    assert_eq!(storage.inner().syncs(), 0);
}

// ═══════════════════════════════════════════════════════════════════════════
// D3 — final Sync success and failure
// ═══════════════════════════════════════════════════════════════════════════

#[test]
fn zero_fill_ends_with_exactly_one_sync_after_the_writes() {
    let mut target = target(2);
    let mut storage = BlockingStorage::new(Plane::new(8 * 1024));
    let mut host = BlockingHost::new(TestHost::data());
    let mut work = vec![0u8; 4096];
    let mut scratch = vec![0u8; 4096];

    assert_eq!(
        start_immed_format(
            &mut target,
            &mut storage,
            &mut host,
            &mut work,
            &mut scratch
        ),
        Completion::Good
    );
    let mut entries = 0;
    loop {
        let info = target
            .poll_long_entry_static::<Here>(&mut storage, &mut work, &mut scratch)
            .expect("poll_long");
        entries += 1;
        assert!(entries < 16, "the long operation did not settle");
        if info.phase == LongPhase::Settled {
            assert_eq!(info.error, None);
            break;
        }
    }
    assert_eq!(
        storage.inner().log,
        vec![Ev::Write(0, 4096), Ev::Sync],
        "writes first, then exactly one durability Sync"
    );
    assert_eq!(storage.inner().syncs(), 1);
}

#[test]
fn a_failing_final_sync_settles_with_an_error_without_replay() {
    let mut target = target(1);
    let mut plane = Plane::new(2048);
    plane.sync_error = Some(Fault::Io);
    let mut storage = BlockingStorage::new(plane);
    let mut host = BlockingHost::new(TestHost::data());
    let mut work = vec![0u8; 4096];
    let mut scratch = vec![0u8; 4096];

    assert_eq!(
        start_immed_format(
            &mut target,
            &mut storage,
            &mut host,
            &mut work,
            &mut scratch
        ),
        Completion::Good
    );
    let mut entries = 0;
    loop {
        let info = target
            .poll_long_entry_static::<Here>(&mut storage, &mut work, &mut scratch)
            .expect("poll_long");
        entries += 1;
        assert!(entries < 16, "the long operation did not settle");
        if info.phase == LongPhase::Settled {
            assert_eq!(info.error, Some(Fault::Io), "the sync fault is reported");
            break;
        }
    }
    assert_eq!(
        storage.inner().log,
        vec![Ev::Write(0, 2048), Ev::Sync],
        "the write ran once; the failed sync is not retried"
    );
    // A settled operation never replays a write or the sync.
    assert_eq!(
        target.poll_long_entry_static::<Here>(&mut storage, &mut work, &mut scratch),
        Ok(LongInfo {
            phase: LongPhase::Settled,
            write_accessible: true,
            progress: Some(99),
            error: Some(Fault::Io),
        })
    );
    assert_eq!(
        storage.inner().log,
        vec![Ev::Write(0, 2048), Ev::Sync],
        "no replay after the error"
    );
}

// ═══════════════════════════════════════════════════════════════════════════
// D4 — explicit no-medium GC/GESN through Spc
// ═══════════════════════════════════════════════════════════════════════════

#[test]
fn no_medium_gc_and_gesn_answer_explicitly_through_spc() {
    let mut target = target(8);
    let mut storage = BlockingStorage::new(Plane::new(0));
    let mut work = vec![0u8; 64];
    let mut scratch = vec![0u8; 64];

    assert!(target.propose_static::<Here>(Change::Remove).is_ok());
    target.advance_static::<Here>().expect("advance remove");
    let taken = target.take_static_at::<Here>(0).expect("take pair");
    assert!(taken.pair.is_some(), "the medium was handed back");

    let mut host = BlockingHost::new(TestHost::data());
    assert_eq!(
        target.drive_static_host::<Here>(
            &mut storage,
            &mut host,
            ctx(Direction::ToHost, 64),
            &get_configuration(0, 64),
            &mut work,
            &mut scratch,
        ),
        Ok(Completion::Good),
        "GC must answer explicitly, not delegate"
    );
    assert_eq!(&work[6..8], &0x0000u16.to_be_bytes(), "no current profile");
    assert_eq!(work[11], 4, "one CD-ROM profile entry");

    assert_eq!(
        target.drive_static_host::<Here>(
            &mut storage,
            &mut host,
            ctx(Direction::ToHost, 8),
            &gesn(0x10, true, 8),
            &mut work,
            &mut scratch,
        ),
        Ok(Completion::Good),
        "GESN must answer explicitly, not delegate"
    );
    assert_eq!(&work[0..2], &6u16.to_be_bytes());
    assert_eq!(work[3], 0x10, "Media class advertised");
    assert_eq!(work[4], 0x00, "NoChg");
    assert_eq!(work[5], 0x00, "no media present");

    // TUR still reports no media through the ordinary gate.
    assert_eq!(
        target.drive_static::<Here>(
            &mut storage,
            ctx(Direction::None, 0),
            &tur_cdb(),
            &mut work,
            &mut scratch,
        ),
        Ok(Completion::Check(MEDIUM_NOT_PRESENT))
    );
}

// ═══════════════════════════════════════════════════════════════════════════
// Queries during the foreground format
// ═══════════════════════════════════════════════════════════════════════════

#[test]
fn queries_use_work_while_the_foreground_fill_advances_from_scratch() {
    let (mut target, counters) = target_counted(4);
    let mut storage = BlockingStorage::new(Plane::new(16 * 1024));
    let mut host = BlockingHost::new(TestHost::data());
    let mut work = vec![0u8; 4096];
    let mut scratch = vec![0u8; 4096];

    assert_eq!(
        start_immed_format(
            &mut target,
            &mut storage,
            &mut host,
            &mut work,
            &mut scratch
        ),
        Completion::Good
    );
    assert_eq!(slot0(&target).long_info().phase, LongPhase::Foreground);
    // Non-zero sentinel so the zeroing assertion below is meaningful.
    scratch.fill(0xFF);

    // First fill chunk comes from `scratch`; `work` is free for queries.
    assert_eq!(
        target
            .poll_long_entry_static::<Here>(&mut storage, &mut work, &mut scratch)
            .expect("poll_long")
            .phase,
        LongPhase::Foreground
    );
    assert_eq!(storage.inner().writes(), vec![(0, 4096)]);
    assert!(
        scratch[..4096].iter().all(|b| *b == 0),
        "the fill must overwrite the pre-filled 0xFF scratch region with zeros"
    );

    let medium_before = counters.snap();
    let ops_before = storage.inner().log.len();
    let mut queries = BlockingHost::new(TestHost::data());

    // INQUIRY.
    assert_eq!(
        target.drive_static_host::<Here>(
            &mut storage,
            &mut queries,
            ctx(Direction::ToHost, 96),
            &inquiry(),
            &mut work,
            &mut scratch,
        ),
        Ok(Completion::Good)
    );
    assert_eq!(work[0], 0x05, "MMC inquiry PDT is CD-ROM");

    // REQUEST SENSE carries FORMAT IN PROGRESS + SKSV + progress.
    assert_eq!(
        target.drive_static_host::<Here>(
            &mut storage,
            &mut queries,
            ctx(Direction::ToHost, 18),
            &request_sense(),
            &mut work,
            &mut scratch,
        ),
        Ok(Completion::Good)
    );
    assert_eq!(work[2] & 0x0F, 0x02, "NOT READY");
    assert_eq!(work[12], 0x04, "ASC = LOGICAL UNIT NOT READY");
    assert_eq!(work[13], 0x04, "ASCQ = FORMAT IN PROGRESS");
    assert_eq!(work[15] & 0x80, 0x80, "SKSV set");
    assert_eq!(u16::from_be_bytes([work[16], work[17]]), 0);

    // GET CONFIGURATION / GESN stay admitted and use `work`.
    assert_eq!(
        target.drive_static_host::<Here>(
            &mut storage,
            &mut queries,
            ctx(Direction::ToHost, 64),
            &get_configuration(0, 64),
            &mut work,
            &mut scratch,
        ),
        Ok(Completion::Good)
    );
    assert_eq!(
        &work[6..8],
        &0x0012u16.to_be_bytes(),
        "current DVD-RAM profile"
    );
    assert_eq!(
        target.drive_static_host::<Here>(
            &mut storage,
            &mut queries,
            ctx(Direction::ToHost, 8),
            &gesn(0x10, true, 8),
            &mut work,
            &mut scratch,
        ),
        Ok(Completion::Good)
    );
    assert_eq!(work[5], 0x02, "media present");

    // REPORT LUNS is a live admitted command during the foreground fill.
    let mut report_luns = [0u8; 10];
    report_luns[0] = 0xA0;
    report_luns[9] = 8;
    assert_eq!(
        target.drive_static_host::<Here>(
            &mut storage,
            &mut queries,
            ctx(Direction::ToHost, 8),
            &report_luns,
            &mut work,
            &mut scratch,
        ),
        Ok(Completion::Good)
    );
    assert_eq!(
        u32::from_be_bytes([work[0], work[1], work[2], work[3]]),
        8,
        "one LUN in the REPORT LUNS list"
    );

    // TUR/READ/WRITE are rejected by the foreground gate; the medium and the
    // backing stay untouched by those failed commands.
    for cdb in [&tur_cdb()[..], &read10(0, 1)[..], &write10(0, 1)[..]] {
        let direction = match cdb[0] {
            0x28 => Direction::ToHost,
            0x2A => Direction::FromHost,
            _ => Direction::None,
        };
        assert_eq!(
            target.drive_static::<Here>(
                &mut storage,
                ctx(direction, 0),
                cdb,
                &mut work,
                &mut scratch,
            ),
            Ok(Completion::Check(FORMAT_IN_PROGRESS)),
            "opcode {:#04x} must be gated",
            cdb[0]
        );
    }
    let medium_after = counters.snap();
    assert_eq!(
        medium_after, medium_before,
        "media commands touched the medium"
    );
    assert_eq!(
        storage.inner().log.len(),
        ops_before,
        "query/gated commands issued storage IO"
    );

    // The long operation still advances from `scratch` after the queries.
    work.fill(0xA5);
    assert_eq!(
        target
            .poll_long_entry_static::<Here>(&mut storage, &mut work, &mut scratch)
            .expect("poll_long")
            .phase,
        LongPhase::Foreground
    );
    assert_eq!(
        storage.inner().writes(),
        vec![(0, 4096), (4096, 4096)],
        "the second chunk came from scratch"
    );
    loop {
        let info = target
            .poll_long_entry_static::<Here>(&mut storage, &mut work, &mut scratch)
            .expect("poll_long");
        assert!(
            work.iter().all(|b| *b == 0xA5),
            "post-query long entries must still leave work untouched"
        );
        if info.phase == LongPhase::Settled {
            assert_eq!(info.error, None);
            break;
        }
    }
    assert_eq!(storage.inner().syncs(), 1);
    assert!(storage.inner().zeroed(8192));
}

// ═══════════════════════════════════════════════════════════════════════════
// R3 — non-zero Progress Indication end to end
// ═══════════════════════════════════════════════════════════════════════════

#[test]
fn request_sense_reports_non_zero_progress_mid_fill() {
    let mut target = target(4);
    let mut storage = BlockingStorage::new(Plane::new(16 * 1024));
    let mut host = BlockingHost::new(TestHost::data());
    let mut work = vec![0u8; 4096];
    let mut scratch = vec![0u8; 4096];

    assert_eq!(
        start_immed_format(
            &mut target,
            &mut storage,
            &mut host,
            &mut work,
            &mut scratch
        ),
        Completion::Good
    );
    // First entry issues chunk 0; the second confirms it and issues chunk 1.
    assert_eq!(
        target
            .poll_long_entry_static::<Here>(&mut storage, &mut work, &mut scratch)
            .unwrap()
            .phase,
        LongPhase::Foreground
    );
    let info = target
        .poll_long_entry_static::<Here>(&mut storage, &mut work, &mut scratch)
        .unwrap();
    assert_eq!(info.phase, LongPhase::Foreground);
    assert_eq!(info.progress, Some(50), "one of two chunks confirmed");

    let mut sense_host = BlockingHost::new(TestHost::data());
    assert_eq!(
        target.drive_static_host::<Here>(
            &mut storage,
            &mut sense_host,
            ctx(Direction::ToHost, 18),
            &request_sense(),
            &mut work,
            &mut scratch,
        ),
        Ok(Completion::Good)
    );
    assert_eq!(work[2] & 0x0F, 0x02, "NOT READY");
    assert_eq!(work[12], 0x04, "ASC = LOGICAL UNIT NOT READY");
    assert_eq!(work[13], 0x04, "ASCQ = FORMAT IN PROGRESS");
    assert_eq!(work[15] & 0x80, 0x80, "SKSV set");
    // fill_sense: progress.min(100) * 65536 / 100, round-down.
    assert_eq!(
        u16::from_be_bytes([work[16], work[17]]),
        0x8000,
        "50% scales to 0x8000"
    );
}

// ═══════════════════════════════════════════════════════════════════════════
// R5 — Abort during an owed fixed completion is a no-op
// ═══════════════════════════════════════════════════════════════════════════

#[test]
fn an_abort_while_a_fixed_completion_is_owed_is_a_no_op() {
    let mut target = target(2);
    let mut storage = BlockingStorage::new(Plane::new(8 * 1024));
    let mut host = BlockingHost::new(TestHost::data());
    let mut work = vec![0u8; 4096];
    let mut scratch = vec![0u8; 4096];

    // A resident fill makes TUR an admission reject with a completion fixed
    // at start (`command_active == false`, `drive_state.done` still owed).
    assert_eq!(
        start_immed_format(
            &mut target,
            &mut storage,
            &mut host,
            &mut work,
            &mut scratch
        ),
        Completion::Good
    );
    target
        .drive_start_static::<Here>(ctx(Direction::None, 0), &tur_cdb())
        .expect("admission-rejected command starts");

    // Abort must be consumed as a no-op, not queued behind the owed Done.
    assert_eq!(target.request_control(Control::Abort), Ok(()));
    assert_eq!(
        target.drive_step_static::<Here>(&mut storage, &mut host, &mut work, &mut scratch),
        Ok(DriveStep::Done(Completion::Check(FORMAT_IN_PROGRESS)))
    );
    assert_eq!(target.tick(), RunOutcome::ServiceReady);

    // No ControlPending: an admitted query works immediately.
    let mut queries = BlockingHost::new(TestHost::data());
    assert_eq!(
        target.drive_static_host::<Here>(
            &mut storage,
            &mut queries,
            ctx(Direction::ToHost, 96),
            &inquiry(),
            &mut work,
            &mut scratch,
        ),
        Ok(Completion::Good)
    );

    // The resident fill also still advances and settles.
    loop {
        let info = target
            .poll_long_entry_static::<Here>(&mut storage, &mut work, &mut scratch)
            .unwrap();
        if info.phase == LongPhase::Settled {
            assert_eq!(info.error, None);
            break;
        }
    }
    // A medium operation works after the fill.
    assert_eq!(
        target.drive_static::<Here>(
            &mut storage,
            ctx(Direction::None, 0),
            &tur_cdb(),
            &mut work,
            &mut scratch,
        ),
        Ok(Completion::Good)
    );
}

// ═══════════════════════════════════════════════════════════════════════════
// One resident long operation per Target
// ═══════════════════════════════════════════════════════════════════════════

#[test]
fn an_idle_lun_does_not_steal_the_owner_receipt() {
    two_lun_target!(target, 4, _c0, _c1);
    let mut s0 = BlockingStorage::new(Plane::new(8 * 1024));
    let mut s1 = BlockingStorage::new(Plane::new(8 * 1024));
    let mut host = BlockingHost::new(TestHost::data());
    let mut work = vec![0u8; 4096];
    let mut scratch = vec![0u8; 4096];

    assert_eq!(
        start_immed_format_rt(&mut target, 0, &mut s0, &mut host, &mut work, &mut scratch),
        Completion::Good
    );
    assert_eq!(
        poll_long_rt(&mut target, 0, &mut s0, &mut work, &mut scratch)
            .unwrap()
            .phase,
        LongPhase::Foreground
    );
    let owner_log = s0.inner().log.clone();
    assert_eq!(owner_log, vec![Ev::Write(0, 4096)]);

    // LUN 1 is idle and has no long operation: its entry must fail closed and
    // must not consume LUN 0's pending receipt.
    assert_eq!(
        poll_long_rt(&mut target, 1, &mut s1, &mut work, &mut scratch),
        Err(Fault::Boundary)
    );
    assert_eq!(
        s0.inner().log,
        owner_log,
        "owner state must not be consumed"
    );
    assert!(s1.inner().log.is_empty(), "the idle LUN issued no IO");
    assert_eq!(target.snapshot_rt(1).unwrap().long.phase, LongPhase::Idle);

    // The owner still advances to a clean settle.
    loop {
        let info = poll_long_rt(&mut target, 0, &mut s0, &mut work, &mut scratch).unwrap();
        if info.phase != LongPhase::Settled {
            assert!(
                info.progress <= Some(99),
                "only a successful settle reports 100"
            );
        }
        if info.phase == LongPhase::Settled {
            assert_eq!(info.error, None);
            assert_eq!(info.progress, Some(100));
            break;
        }
    }
    assert_eq!(s0.inner().writes(), vec![(0, 4096), (4096, 4096)]);
    assert_eq!(s0.inner().syncs(), 1);
}

#[test]
fn a_second_armed_lun_gets_boundary_until_the_owner_settles() {
    two_lun_target!(target, 4, _c0, _c1);
    let mut s0 = BlockingStorage::new(Plane::new(8 * 1024));
    let mut s1 = BlockingStorage::new(Plane::new(8 * 1024));
    let mut host = BlockingHost::new(TestHost::data());
    let mut work = vec![0u8; 4096];
    let mut scratch = vec![0u8; 4096];

    assert_eq!(
        start_immed_format_rt(&mut target, 0, &mut s0, &mut host, &mut work, &mut scratch),
        Completion::Good
    );
    assert_eq!(
        start_immed_format_rt(&mut target, 1, &mut s1, &mut host, &mut work, &mut scratch),
        Completion::Good
    );
    assert_eq!(
        target.snapshot_rt(1).unwrap().long.phase,
        LongPhase::Foreground
    );

    // LUN 0 claims the single long-operation slot on its first entry.
    poll_long_rt(&mut target, 0, &mut s0, &mut work, &mut scratch).unwrap();
    assert_eq!(
        poll_long_rt(&mut target, 1, &mut s1, &mut work, &mut scratch),
        Err(Fault::Boundary),
        "the second armed operation cannot advance while the owner runs"
    );

    // Owner settles ...
    loop {
        let info = poll_long_rt(&mut target, 0, &mut s0, &mut work, &mut scratch).unwrap();
        if info.phase == LongPhase::Settled {
            assert_eq!(info.error, None);
            break;
        }
    }
    // A confirm poll of the settled owner must not keep a stale claim.
    assert_eq!(
        poll_long_rt(&mut target, 0, &mut s0, &mut work, &mut scratch)
            .unwrap()
            .phase,
        LongPhase::Settled
    );

    // ... then the second, previously armed operation advances from offset 0.
    let info = poll_long_rt(&mut target, 1, &mut s1, &mut work, &mut scratch).unwrap();
    assert_eq!(info.phase, LongPhase::Foreground);
    assert_eq!(s1.inner().writes(), vec![(0, 4096)]);
    loop {
        let info = poll_long_rt(&mut target, 1, &mut s1, &mut work, &mut scratch).unwrap();
        if info.phase == LongPhase::Settled {
            assert_eq!(info.error, None);
            assert_eq!(info.progress, Some(100));
            break;
        }
    }
    assert_eq!(s1.inner().writes(), vec![(0, 4096), (4096, 4096)]);
    assert_eq!(s1.inner().syncs(), 1);
}

#[test]
fn a_second_lun_entry_is_boundary_without_touching_either_side() {
    two_lun_target!(target, 2, _c0, c1);
    let mut s0 = BlockingStorage::new(Plane::new(8 * 1024));
    let mut s1 = BlockingStorage::new(Plane::new(8 * 1024));
    let mut host = BlockingHost::new(TestHost::data());
    let mut work = vec![0u8; 4096];
    let mut scratch = vec![0u8; 4096];

    assert_eq!(
        start_immed_format_rt(&mut target, 0, &mut s0, &mut host, &mut work, &mut scratch),
        Completion::Good
    );
    assert_eq!(
        start_immed_format_rt(&mut target, 1, &mut s1, &mut host, &mut work, &mut scratch),
        Completion::Good
    );
    poll_long_rt(&mut target, 0, &mut s0, &mut work, &mut scratch).unwrap();

    let logs = (s0.inner().log.clone(), s1.inner().log.clone());
    let medium = c1.snap();
    let lun0 = target.snapshot_rt(0).unwrap().long;
    let lun1 = target.snapshot_rt(1).unwrap().long;

    assert_eq!(
        poll_long_rt(&mut target, 1, &mut s1, &mut work, &mut scratch),
        Err(Fault::Boundary)
    );
    assert_eq!((s0.inner().log.clone(), s1.inner().log.clone()), logs);
    assert_eq!(c1.snap(), medium, "the losing LUN's medium was not polled");
    assert_eq!(target.snapshot_rt(0).unwrap().long, lun0);
    assert_eq!(target.snapshot_rt(1).unwrap().long, lun1);
}

#[test]
fn force_take_install_mid_fill_leaves_no_stale_receipt() {
    let mut target = target(4);
    let mut storage = BlockingStorage::new(Plane::new(16 * 1024));
    let mut host = BlockingHost::new(TestHost::data());
    let mut work = vec![0u8; 4096];
    let mut scratch = vec![0u8; 4096];

    assert_eq!(
        start_immed_format(
            &mut target,
            &mut storage,
            &mut host,
            &mut work,
            &mut scratch
        ),
        Completion::Good
    );
    assert_eq!(
        target
            .poll_long_entry_static::<Here>(&mut storage, &mut work, &mut scratch)
            .unwrap()
            .phase,
        LongPhase::Foreground
    );
    assert_eq!(storage.inner().writes(), vec![(0, 4096)]);

    // Force detaches mid-fill (the receipt is still resident), take claims the
    // pair, install puts it back.
    target
        .force_remove_static::<Here>(&mut storage, &mut host)
        .expect("force detach");
    assert_eq!(target.snapshot_static::<Here>().long.phase, LongPhase::Idle);
    let taken = target.take_static_at::<Here>(0).expect("take");
    let pair = taken.pair.expect("pair");
    target.install_static::<Here>(pair).expect("install");

    // A fresh fill starts at offset 0 and must not consume a stale receipt.
    assert_eq!(
        start_immed_format(
            &mut target,
            &mut storage,
            &mut host,
            &mut work,
            &mut scratch
        ),
        Completion::Good
    );
    let info = target
        .poll_long_entry_static::<Here>(&mut storage, &mut work, &mut scratch)
        .expect("fresh fill entry");
    assert_eq!(info.phase, LongPhase::Foreground);
    assert_eq!(
        storage.inner().writes(),
        vec![(0, 4096), (0, 4096)],
        "the fresh fill restarted at offset 0"
    );
    loop {
        let info = target
            .poll_long_entry_static::<Here>(&mut storage, &mut work, &mut scratch)
            .unwrap();
        if info.phase == LongPhase::Settled {
            assert_eq!(info.error, None, "no stale Contract/Io fault");
            assert_eq!(info.progress, Some(100));
            break;
        }
    }
    assert_eq!(
        storage.inner().writes(),
        vec![(0, 4096), (0, 4096), (4096, 4096)]
    );
    assert_eq!(storage.inner().syncs(), 1);
}

// ═══════════════════════════════════════════════════════════════════════════
// The FORMAT GOOD is delivered once and never re-delivered
// ═══════════════════════════════════════════════════════════════════════════

#[test]
fn a_later_fill_failure_never_revokes_or_redelivers_the_format_good() {
    let (mut target, life) = counting_target(2);
    let mut plane = Plane::new(8 * 1024);
    plane.sync_error = Some(Fault::Io);
    let mut storage = BlockingStorage::new(plane);
    let mut host = BlockingHost::new(TestHost::data());
    let mut work = vec![0u8; 4096];
    let mut scratch = vec![0u8; 4096];

    assert_eq!(
        start_immed_format_dev(
            &mut target,
            0,
            &mut storage,
            &mut host,
            &mut work,
            &mut scratch
        ),
        Completion::Good
    );
    assert_eq!(life.snap(), (1, 0), "FORMAT GOOD delivered exactly once");

    loop {
        let info = target
            .poll_long_entry_static::<Here>(&mut storage, &mut work, &mut scratch)
            .unwrap();
        if info.phase == LongPhase::Settled {
            assert_eq!(info.error, Some(Fault::Io));
            assert_eq!(
                life.snap(),
                (1, 0),
                "a failed fill never re-delivers status or interrupts"
            );
            break;
        }
    }

    // The boundary is serviceable: a later TUR is a fresh, independent status.
    assert_eq!(
        target.drive_static::<Here>(
            &mut storage,
            ctx(Direction::None, 0),
            &tur_cdb(),
            &mut work,
            &mut scratch,
        ),
        Ok(Completion::Good)
    );
    assert_eq!(life.snap(), (2, 0), "only the new command was delivered");
}

// Silence an unused import warning while keeping the byte-layout list
// explicit for future fixtures.
#[allow(dead_code)]
fn _sense_layout() -> Sense {
    Sense::new(0x02, 0x04, 0x04)
}
