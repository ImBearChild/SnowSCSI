//! Long-operation and resident-query fixtures.
//!
//! Covered here:
//!
//! 1. a long entry uses the `scratch` bank only; a sentinel in `work` survives
//!    the whole operation;
//! 2. a `Fault::Contract` long-operation receipt is fed back before the error,
//!    so the next entry settles and never re-issues the cancelled write;
//! 3. the drive-owned zero-fill ends with exactly one `Sync`;
//! 4. a failing final `Sync` settles the device with an error, no GOOD and no
//!    replay;
//! 5. GC/GESN answer explicitly after `take_medium`;
//! 6. INQUIRY/RS/GC/GESN are admitted with `work` while TUR/READ/WRITE get
//!    `2/04/04`, with zero medium/backing access, and the long op still
//!    advances from `scratch`.
//!
//! The compile-time borrow-domain proof lives next to the concrete
//! `MmcDrive` in `snowscsi/src/mmc/drive.rs` so it can name the profile type.

use snowscsi::core::storage::{
    BlockingHost, BlockingStorage, HostBuf, HostReceipt, HostReq, IoBuf, IoReq, IoToken, Storage,
    StorageReceipt, SyncHost, SyncStorage,
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
            HostBuf::Recv { buf: bytes, .. } => {
                let n = (req.len as usize).min(bytes.len()).min(self.params.len());
                bytes[..n].copy_from_slice(&self.params[..n]);
                HostReceipt::from_adapter(n, None)
            }
            HostBuf::Send { .. } => HostReceipt::from_adapter(0, Some(Fault::Contract)),
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
    storage: &mut dyn Storage,
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

/// Start IMMED FORMAT through any [`Storage`] adapter (the parity fixture needs
/// both a `BlockingStorage` and a `Pending`-first double).
fn start_format_any(
    target: &mut MmcTarget,
    storage: &mut dyn Storage,
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
            ctx(Direction::FromHost, 12),
            &[0x04, 0x11, 0, 0, 0, 0],
            work,
            scratch,
        )
        .expect("FORMAT start")
}

/// Start IMMED FORMAT and advance the resident fill until it settles.
///
/// Returns the number of long entries used and the final projection; the
/// entry count is the only thing the sync/async parity fixture allows to
/// differ.
fn run_format_fill(
    target: &mut MmcTarget,
    storage: &mut dyn Storage,
    host: &mut BlockingHost<TestHost>,
    work: &mut [u8],
    scratch: &mut [u8],
) -> (u32, LongInfo) {
    assert_eq!(
        start_format_any(target, storage, host, work, scratch),
        Completion::Good
    );
    let mut entries = 0u32;
    loop {
        entries += 1;
        assert!(entries < 64, "the long operation did not settle");
        let info = target
            .poll_long_entry_static::<Here>(storage, work, scratch)
            .expect("poll_long");
        if info.phase == LongPhase::Settled {
            return (entries, info);
        }
        assert_eq!(info.phase, LongPhase::Foreground);
    }
}

fn poll_long_rt(
    target: &mut TwoTarget<'_>,
    lun: usize,
    storage: &mut dyn Storage,
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
// The long entry uses `scratch`; `work` keeps its sentinel
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
// A Contract receipt is fed back before the error
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
// Final Sync success and failure
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
// Sync/async adapter parity
// ═══════════════════════════════════════════════════════════════════════════

/// Storage double that answers `Pending` a fixed number of times per operation
/// before delegating to a real [`BlockingStorage`] over the same [`Plane`].
///
/// It records every `begin_exec` request (the storage-op trace) and the
/// poll/cancel counts, so a `Pending` run can be compared with a fully
/// synchronous run byte for byte.
struct PendingStorage {
    inner: BlockingStorage<Plane>,
    pendings_per_op: usize,
    remaining: usize,
    begins: Vec<IoReq>,
    polls: u32,
    cancels: u32,
}

impl PendingStorage {
    fn new(plane: Plane, pendings_per_op: usize) -> Self {
        Self {
            inner: BlockingStorage::new(plane),
            pendings_per_op,
            remaining: 0,
            begins: Vec::new(),
            polls: 0,
            cancels: 0,
        }
    }
}

impl Storage for PendingStorage {
    fn begin_exec(&mut self, req: IoReq) -> IoToken {
        self.begins.push(req);
        self.remaining = self.pendings_per_op;
        self.inner.begin_exec(req)
    }

    fn poll_exec(&mut self, token: IoToken, buf: IoBuf<'_>) -> std::task::Poll<StorageReceipt> {
        self.polls = self.polls.saturating_add(1);
        if self.remaining > 0 {
            self.remaining -= 1;
            return std::task::Poll::Pending;
        }
        self.inner.poll_exec(token, buf)
    }

    fn cancel(&mut self, token: IoToken) {
        self.cancels = self.cancels.saturating_add(1);
        self.inner.cancel(token);
    }
}

/// The same MMC FORMAT script driven through a synchronous adapter
/// and through one that yields `Pending` K times per operation must produce the
/// same device trace (`Publish`/`Io` sequence with offsets and lengths), the
/// same storage op trace (direction/offset/len order), the same final contents,
/// completion and [`LongInfo`], and one `begin_exec` per operation.
///
/// Only the **entry count** may differ: the async run spends extra entries on
/// `Pending`, and a long-operation receipt is always consumed by the device on
/// the entry *after* it was stored (the documented one-step lag).
#[test]
fn sync_and_async_adapters_produce_the_same_long_operation_trace() {
    const K: usize = 2;
    let mut work = vec![0u8; 4096];
    let mut scratch = vec![0u8; 4096];

    // 1. BlockingStorage over a SyncStorage: every poll is Ready.
    let mut sync_target = target(4);
    let mut sync_storage = BlockingStorage::new(Plane::new(16 * 1024));
    let mut sync_host = BlockingHost::new(TestHost::data());
    let (sync_entries, sync_info) = run_format_fill(
        &mut sync_target,
        &mut sync_storage,
        &mut sync_host,
        &mut work,
        &mut scratch,
    );
    let sync_log = sync_storage.inner().log.clone();
    let sync_events = sync_host.inner().events.clone();

    // 2. The same script behind a Storage double that yields Pending K times.
    let mut async_target = target(4);
    let mut async_storage = PendingStorage::new(Plane::new(16 * 1024), K);
    let mut async_host = BlockingHost::new(TestHost::data());
    let (async_entries, async_info) = run_format_fill(
        &mut async_target,
        &mut async_storage,
        &mut async_host,
        &mut work,
        &mut scratch,
    );
    let async_log = async_storage.inner.inner().log.clone();
    let async_events = async_host.inner().events.clone();

    // Identical device trace: publish/receive order plus storage op family,
    // offset and length, in order.
    assert_eq!(
        async_events, sync_events,
        "the host trace must be identical"
    );
    assert_eq!(
        async_log, sync_log,
        "the device/storage op trace (direction/offset/len order) must be identical"
    );
    assert_eq!(
        async_storage.inner.inner().mem,
        sync_storage.inner().mem,
        "the final backing contents must be identical"
    );

    // Identical completion and projection.
    assert_eq!(async_info, sync_info);
    assert_eq!(sync_info.phase, LongPhase::Settled);
    assert_eq!(sync_info.progress, Some(100));
    assert_eq!(sync_info.error, None);

    // One `begin_exec` per operation in both runs: 2 zero-fill writes + 1 Sync
    // for the 4-sector medium.
    assert_eq!(async_log.len(), 3, "writes then one durability Sync");
    assert_eq!(
        async_storage.begins.len(),
        async_log.len(),
        "the async run begins every operation exactly once"
    );
    for (req, ev) in async_storage.begins.iter().zip(&async_log) {
        let expected = match ev {
            Ev::Read(offset, len) => (Direction::ToHost, *offset, *len as u32),
            Ev::Write(offset, len) => (Direction::FromHost, *offset, *len as u32),
            Ev::Sync => (Direction::None, 0, 0),
        };
        assert_eq!(
            (req.dir, req.offset, req.len),
            expected,
            "the async storage op trace matches the synchronous one"
        );
    }
    assert_eq!(async_storage.cancels, 0, "no token is cancelled");
    assert_eq!(
        async_storage.polls,
        (async_storage.begins.len() as u32) * (K as u32 + 1),
        "each operation is polled K times as Pending, then Ready"
    );
    assert!(
        async_entries > sync_entries,
        "Pending spans entries ({async_entries} vs {sync_entries}); the trace does not change"
    );
}

// ═══════════════════════════════════════════════════════════════════════════
// Explicit no-medium GC/GESN through Spc
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
// Queries while a long IO token is actually Pending
// ═══════════════════════════════════════════════════════════════════════════

/// A long-entry token is **not** a command-owned
/// `required_io` obligation. With the token still `Pending`, INQUIRY /
/// REQUEST SENSE / REPORT LUNS start and complete from `work`, READ/WRITE/TUR
/// stay device-gated with zero medium/backing calls, and the long entry then
/// resumes the *same* token (one poll per entry, no second `begin_exec`).
/// Management still refuses to cross the live long IO.
#[test]
fn queries_are_served_while_a_long_token_is_pending() {
    let (mut target, counters) = target_counted(4);
    // Two Pending answers: the first write token survives several entries.
    let mut storage = PendingStorage::new(Plane::new(16 * 1024), 2);
    let mut host = BlockingHost::new(TestHost::data());
    let mut work = vec![0u8; 4096];
    let mut scratch = vec![0u8; 4096];

    assert_eq!(
        start_format_any(
            &mut target,
            &mut storage,
            &mut host,
            &mut work,
            &mut scratch
        ),
        Completion::Good
    );
    // Entry 1 issues the first zero-fill write and yields Pending.
    assert_eq!(
        target
            .poll_long_entry_static::<Here>(&mut storage, &mut work, &mut scratch)
            .expect("long entry")
            .phase,
        LongPhase::Foreground
    );
    assert_eq!(storage.begins.len(), 1);
    assert_eq!(storage.polls, 1);
    assert_eq!(target.tick(), RunOutcome::ServiceReady);

    // Management must not cross the live long IO.
    assert!(matches!(
        target.propose_static::<Here>(Change::Remove),
        Err((Change::Remove, Fault::Boundary))
    ));

    let medium_before = counters.snap();
    let mut queries = BlockingHost::new(TestHost::data());

    // INQUIRY is served from `work` while the token is pending.
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

    // REQUEST SENSE reports FORMAT IN PROGRESS with SKSV and progress.
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

    // READ/WRITE/TUR still get the device foreground gate, zero medium IO.
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
    assert_eq!(
        counters.snap(),
        medium_before,
        "gated commands touched the medium"
    );

    // The queries never issued or polled the long token.
    assert_eq!(storage.begins.len(), 1, "no second operation was begun");
    assert_eq!(storage.polls, 1, "the pending token was not polled");

    // The long entry resumes the same token: one poll per entry, then Ready.
    assert_eq!(
        target
            .poll_long_entry_static::<Here>(&mut storage, &mut work, &mut scratch)
            .expect("long entry")
            .phase,
        LongPhase::Foreground
    );
    assert_eq!((storage.begins.len(), storage.polls), (1, 2));
    assert_eq!(
        target
            .poll_long_entry_static::<Here>(&mut storage, &mut work, &mut scratch)
            .expect("long entry")
            .phase,
        LongPhase::Foreground
    );
    assert_eq!((storage.begins.len(), storage.polls), (1, 3));

    // ... and the fill finishes normally from `scratch`.
    loop {
        let info = target
            .poll_long_entry_static::<Here>(&mut storage, &mut work, &mut scratch)
            .expect("poll_long");
        if info.phase == LongPhase::Settled {
            assert_eq!(info.error, None);
            break;
        }
    }
    assert_eq!(storage.cancels, 0);
    assert_eq!(storage.inner.inner().syncs(), 1);
    assert_eq!(target.tick(), RunOutcome::ServiceReady);
}

// ═══════════════════════════════════════════════════════════════════════════
// Terminal flags with a live long token
// ═══════════════════════════════════════════════════════════════════════════

/// Stop = drain: a retained long token keeps `tick` at `ServiceReady`, the
/// next entry polls the **same** token once to `Ready`, and only then does the
/// service report `Ended`. Nothing is cancelled and the resident fill may stay
/// `Foreground` (a terminal target never issues new IO).
#[test]
fn stop_drains_a_pending_long_token_before_reporting_ended() {
    let mut target = target(2);
    let mut storage = PendingStorage::new(Plane::new(8 * 1024), 1);
    let mut host = BlockingHost::new(TestHost::data());
    let mut work = vec![0u8; 4096];
    let mut scratch = vec![0u8; 4096];

    assert_eq!(
        start_format_any(
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
            .expect("long entry")
            .phase,
        LongPhase::Foreground
    );
    assert_eq!(storage.polls, 1);

    target.stop();
    assert_eq!(
        target.tick(),
        RunOutcome::ServiceReady,
        "a live token keeps the service up"
    );

    // Drain entry: the same token answers Ready; the receipt is fed once.
    let info = target
        .poll_long_entry_static::<Here>(&mut storage, &mut work, &mut scratch)
        .expect("drain entry");
    assert_eq!(info.phase, LongPhase::Foreground);
    assert_eq!(storage.polls, 2, "one more poll of the same token");
    assert_eq!(storage.cancels, 0, "Stop drains, it never cancels");
    assert_eq!(storage.begins.len(), 1, "the operation is never re-issued");

    // Token is gone: the service can now end, and no further IO is issued.
    assert_eq!(
        target.tick(),
        RunOutcome::Ended {
            reason: snowscsi::core::RunEnd::Stopped,
            error: None,
        }
    );
    let polls = storage.polls;
    assert_eq!(
        target.poll_long_entry_static::<Here>(&mut storage, &mut work, &mut scratch),
        Err(Fault::Boundary),
        "no new long entry after a terminal flag"
    );
    assert_eq!(storage.polls, polls, "the token is never polled again");
}

/// Link loss = cancel: the retained long token is cancelled through the
/// adapter and the slot stays serviceable (no terminal state).
#[test]
fn link_loss_cancels_a_pending_long_write_and_settles_the_device() {
    let mut target = target(2);
    // Never leaves Pending: only a terminal cancel can end this token.
    let mut storage = PendingStorage::new(Plane::new(8 * 1024), usize::MAX);
    let mut host = BlockingHost::new(TestHost::data());
    let mut work = vec![0u8; 4096];
    let mut scratch = vec![0u8; 4096];

    assert_eq!(
        start_format_any(
            &mut target,
            &mut storage,
            &mut host,
            &mut work,
            &mut scratch
        ),
        Completion::Good
    );
    target
        .poll_long_entry_static::<Here>(&mut storage, &mut work, &mut scratch)
        .expect("long entry");
    assert_eq!(storage.polls, 1);

    target.link_lost_static::<Here>(&mut storage, &mut host, &mut work, &mut scratch);
    assert_eq!(storage.cancels, 1, "cancelled exactly once");
    assert_eq!(storage.polls, 1, "the cancelled token is never polled");
    // The synthesized cancelled receipt must settle the device: leaving it
    // `Foreground` would make every media command FORMAT IN PROGRESS forever on
    // a target that is supposed to outlive the link.
    let info = target.snapshot_static::<Here>();
    assert_eq!(info.long.phase, LongPhase::Settled);
    assert_eq!(info.long.error, Some(Fault::Contract));
    assert_eq!(
        target.tick(),
        RunOutcome::ServiceReady,
        "a lost link does not end the target"
    );
}

/// Fatal = cancel: same shape as a link loss, but the fatal fault is
/// what `Ended` reports; the long op records its own cancelled receipt.
#[test]
fn fatal_cancels_a_pending_long_write_and_records_the_fault() {
    let mut target = target(2);
    let mut storage = PendingStorage::new(Plane::new(8 * 1024), usize::MAX);
    let mut host = BlockingHost::new(TestHost::data());
    let mut work = vec![0u8; 4096];
    let mut scratch = vec![0u8; 4096];

    assert_eq!(
        start_format_any(
            &mut target,
            &mut storage,
            &mut host,
            &mut work,
            &mut scratch
        ),
        Completion::Good
    );
    target
        .poll_long_entry_static::<Here>(&mut storage, &mut work, &mut scratch)
        .expect("long entry");

    target.fatal(Fault::NeedsRecovery);
    assert_eq!(target.tick(), RunOutcome::ServiceReady);

    let info = target
        .poll_long_entry_static::<Here>(&mut storage, &mut work, &mut scratch)
        .expect("cancel entry");
    assert_eq!(storage.cancels, 1);
    assert_eq!(storage.polls, 1);
    assert_eq!(info.error, Some(Fault::Contract));
    assert_eq!(
        target.tick(),
        RunOutcome::Ended {
            reason: snowscsi::core::RunEnd::Fatal,
            error: Some(Fault::NeedsRecovery),
        }
    );
    let polls = storage.polls;
    let cancels = storage.cancels;
    assert_eq!(
        target.poll_long_entry_static::<Here>(&mut storage, &mut work, &mut scratch),
        Err(Fault::Boundary)
    );
    assert_eq!((storage.polls, storage.cancels), (polls, cancels));
}

// ═══════════════════════════════════════════════════════════════════════════
// Forced-long latch: a force-cancelled long op must still be takeable
// ═══════════════════════════════════════════════════════════════════════════

/// The exact dead-end repro: `Replace → advance` leaves a resident result, a
/// fill holds a `Pending` write token, `force_remove_rt` cancels the token but
/// defers on the resident result. The forced-long latch must let the take
/// deliver the old pair and the deferred force detach the current one (with the
/// force's unknown write remainder), ending in an installable empty slot.
#[test]
fn a_force_cancelled_long_operation_still_hands_back_and_detaches() {
    let mut target = target(4);
    let mut storage = PendingStorage::new(Plane::new(16 * 1024), usize::MAX);
    let mut host = BlockingHost::new(TestHost::data());
    let mut work = vec![0u8; 4096];
    let mut scratch = vec![0u8; 4096];

    // Replace: the old pair becomes a resident result while a fresh medium runs.
    let replacement = Pair {
        medium: SpyMedium::with_counters(4, Counters::default()),
        backing: 2u8,
    };
    assert!(target
        .propose_static::<Here>(Change::Replace(replacement))
        .is_ok());
    target.advance_static::<Here>().expect("advance replace");
    assert!(target.snapshot_static::<Here>().ready);

    // The fresh medium starts a fill whose first write token stalls.
    assert_eq!(
        start_format_any(
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
            .expect("long entry")
            .phase,
        LongPhase::Foreground
    );
    assert_eq!((storage.begins.len(), storage.polls), (1, 1));

    // The force cancels the token, books the unknown write remainder and defers
    // on the resident result.
    target
        .force_remove_static::<Here>(&mut storage, &mut host)
        .expect("force accepts");
    assert_eq!(storage.cancels, 1);
    assert_eq!(storage.polls, 1);
    assert!(target.snapshot_static::<Here>().ready, "force deferred");

    // NEW-2: a latched LUN refuses long entries without touching the adapter
    // or the projection.
    let before = (
        storage.begins.len(),
        storage.polls,
        storage.cancels,
        target.snapshot_static::<Here>().long,
    );
    assert_eq!(
        target.poll_long_entry_static::<Here>(&mut storage, &mut work, &mut scratch),
        Err(Fault::Boundary),
        "a pair committed for removal issues no new IO"
    );
    assert_eq!(
        (
            storage.begins.len(),
            storage.polls,
            storage.cancels,
            target.snapshot_static::<Here>().long,
        ),
        before,
        "neither the adapter nor the projection was touched"
    );

    // The latch lets the take cross only the long-phase check: the old pair is
    // handed back, and the deferred force detaches the current (unsettled) pair.
    let old = target.take_static_at::<Here>(0).expect("old pair takeable");
    assert_eq!(
        old.pair.map(|p| p.backing),
        Some(1u8),
        "the replaced old pair is handed back"
    );
    assert_eq!(
        target.tick(),
        RunOutcome::ResourcesReady { lun: 0 },
        "the deferred force detached the current pair"
    );
    assert!(!target.snapshot_static::<Here>().ready);

    let forced = target
        .take_static_at::<Here>(0)
        .expect("forced pair takeable");
    assert_eq!(forced.pair.map(|p| p.backing), Some(2u8));
    assert!(
        forced.effects.unknown_remainder,
        "the force handback carries the cancelled write remainder"
    );
    assert_eq!(forced.effects.confirmed_write, 0);
    assert_eq!(target.tick(), RunOutcome::ServiceReady);

    // Nothing wedges: the now-empty slot accepts a fresh pair.
    let pair = Pair {
        medium: SpyMedium::with_counters(4, Counters::default()),
        backing: 3u8,
    };
    assert!(target.install_static::<Here>(pair).is_ok());
    assert!(target.snapshot_static::<Here>().ready);
    assert_eq!(target.tick(), RunOutcome::ServiceReady);
}

/// A force on a `Foreground` long op with **no** token (IMMED start, no entry
/// yet) also arms the latch and detaches immediately; the take is not blocked
/// by `LongOperationActive`.
#[test]
fn a_force_on_a_tokenless_foreground_long_operation_still_detaches() {
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
    assert_eq!(
        target.snapshot_static::<Here>().long.phase,
        LongPhase::Foreground
    );
    // No long entry has run: no adapter token is retained.

    target
        .force_remove_static::<Here>(&mut storage, &mut host)
        .expect("force detaches");
    assert!(!target.snapshot_static::<Here>().ready);
    assert_eq!(target.tick(), RunOutcome::ResourcesReady { lun: 0 });

    let taken = target
        .take_static_at::<Here>(0)
        .expect("the forced pair is takeable");
    assert_eq!(taken.pair.map(|p| p.backing), Some(1u8));
    assert!(
        !taken.effects.unknown_remainder,
        "nothing was issued, so there is no unknown remainder"
    );
    assert_eq!(target.tick(), RunOutcome::ServiceReady);
    assert_eq!(
        target.snapshot_static::<Here>().long.phase,
        LongPhase::Idle,
        "the detach discarded the resident long operation"
    );
}

/// A normal (non-force) take during a `Foreground` fill still gets the
/// long-operation rejection: the latch is only armed by a force.
#[test]
fn a_normal_take_during_foreground_still_rejects() {
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
    // One entry completes the first chunk synchronously: no token is retained,
    // so only the long phase can reject the take.
    assert_eq!(
        target
            .poll_long_entry_static::<Here>(&mut storage, &mut work, &mut scratch)
            .expect("long entry")
            .phase,
        LongPhase::Foreground
    );
    assert!(matches!(
        target.take_static_at::<Here>(0),
        Err(BoundaryReject::LongOperationActive)
    ));
}

// ═══════════════════════════════════════════════════════════════════════════
// Deferred force with a live long token
// ═══════════════════════════════════════════════════════════════════════════

/// Force row: a force deferred behind a **slot-resident result** still
/// cancels the live long token exactly once (no leaked adapter slot) and the
/// target keeps serving (`ServiceReady`, never `Ended`). The deferred detach is
/// left armed because the resident long operation is not settled.
#[test]
fn a_deferred_force_cancels_a_live_long_token_once() {
    two_lun_target!(target, 4, _c0, _c1);
    // LUN 1's fill token never leaves Pending.
    let mut s1 = PendingStorage::new(Plane::new(16 * 1024), usize::MAX);
    let mut host = BlockingHost::new(TestHost::data());
    let mut work = vec![0u8; 4096];
    let mut scratch = vec![0u8; 4096];

    // Replace on LUN 1: the old pair is resident (force must defer on it) while
    // a fresh medium is installed and can run a long op.
    let replacement = Pair {
        medium: SpyMedium::with_counters(4, Counters::default()),
        backing: 2u8,
    };
    assert!(target.propose_rt(1, Change::Replace(replacement)).is_ok());
    target.advance_rt(1).expect("advance replace");
    assert!(target.snapshot_rt(1).expect("slot 1").ready);

    assert_eq!(
        start_immed_format_rt(&mut target, 1, &mut s1, &mut host, &mut work, &mut scratch),
        Completion::Good
    );
    assert_eq!(
        poll_long_rt(&mut target, 1, &mut s1, &mut work, &mut scratch)
            .expect("long entry")
            .phase,
        LongPhase::Foreground
    );
    assert_eq!((s1.begins.len(), s1.polls), (1, 1));
    assert_eq!(target.tick(), RunOutcome::ServiceReady);

    // The force is deferred on LUN 1's resident result, but the live token is
    // still cancelled exactly once.
    assert_eq!(target.force_remove_rt(1, &mut s1, &mut host), Ok(()));
    assert_eq!(s1.cancels, 1, "the deferred force still cancels the token");
    assert_eq!(s1.polls, 1, "the cancelled token is never polled again");
    assert_eq!(s1.begins.len(), 1, "the write is never re-issued");
    assert!(
        target.snapshot_rt(1).expect("slot 1").ready,
        "deferred: LUN 1 stays installed"
    );
    assert_eq!(
        target.snapshot_rt(1).expect("slot 1").long.phase,
        LongPhase::Foreground,
        "the resident operation is not settled by the cancel"
    );
    assert_eq!(
        target.tick(),
        RunOutcome::ServiceReady,
        "a deferred force with a cancelled token keeps serving"
    );
}

// ═══════════════════════════════════════════════════════════════════════════
// Foreign LUN fail-closed with a live token
// ═══════════════════════════════════════════════════════════════════════════

/// The owner of a `Pending` long token is serialized: a foreign LUN entry is
/// `Boundary` without touching either adapter or either projection, and the
/// owner then resumes the same token.
#[test]
fn a_foreign_long_entry_is_boundary_without_touching_a_pending_token() {
    two_lun_target!(target, 4, _c0, _c1);
    let mut s0 = PendingStorage::new(Plane::new(16 * 1024), 2);
    let mut s1 = PendingStorage::new(Plane::new(16 * 1024), 2);
    let mut host = BlockingHost::new(TestHost::data());
    let mut work = vec![0u8; 4096];
    let mut scratch = vec![0u8; 4096];

    assert_eq!(
        start_immed_format_rt(&mut target, 1, &mut s1, &mut host, &mut work, &mut scratch),
        Completion::Good
    );
    assert_eq!(
        poll_long_rt(&mut target, 1, &mut s1, &mut work, &mut scratch)
            .expect("LUN 1 entry")
            .phase,
        LongPhase::Foreground
    );
    assert_eq!((s1.begins.len(), s1.polls), (1, 1));

    let luns = (
        target.snapshot_rt(0).unwrap().long,
        target.snapshot_rt(1).unwrap().long,
    );
    assert_eq!(
        poll_long_rt(&mut target, 0, &mut s0, &mut work, &mut scratch),
        Err(Fault::Boundary),
        "the non-owner LUN fails closed"
    );
    assert_eq!(
        (s0.begins.len(), s0.polls),
        (0, 0),
        "LUN 0 adapter untouched"
    );
    assert_eq!(
        (s1.begins.len(), s1.polls),
        (1, 1),
        "the owner's token was not consumed"
    );
    assert_eq!(
        (
            target.snapshot_rt(0).unwrap().long,
            target.snapshot_rt(1).unwrap().long
        ),
        luns,
        "neither projection changed"
    );

    // The owner still advances the same token.
    assert_eq!(
        poll_long_rt(&mut target, 1, &mut s1, &mut work, &mut scratch)
            .expect("owner advances")
            .phase,
        LongPhase::Foreground
    );
    assert_eq!((s1.begins.len(), s1.polls), (1, 2));
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
        target.drive_step_static::<Here>(&mut storage, &mut host, &mut work, &mut [], &mut scratch),
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
