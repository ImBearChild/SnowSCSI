//! Shared iSCSI test harness for the seam-first core.
//!
//! The transport tests drive a real [`Target`] over a heterogeneous slot set,
//! so they need the same application glue a real shell needs: one physical
//! medium enum, one runtime `Lu` enum with a single pair type, and a
//! synchronous [`SyncStorage`] over a [`StorePlane`].

use core::task::Poll;

use snowscsi::block::{BlockAttrs, BlockDevice};
use snowscsi::common::store::{StoreOp, StorePlane};
use snowscsi::core::async_wake::AsyncWake;
use snowscsi::core::storage::{IoBuf, IoReq, IoToken, Storage, StorageReceipt};
use snowscsi::core::{
    Admission, BoundaryPermit, Change, ChangeResult, CommandContext, CommandPermit, Completion,
    Delivery, Effect, Fault, Feedback, InterruptReason, KnownEffects, LongInfo, Lu, LuImpl, LuInfo,
    NoMedium, OwnerBindPermit, Pair, PollStep, Sense, Spc, TargetId, UaClass,
};
use snowscsi::mmc::{
    DiscInfo, DvdRamMedium, FlatCdMedium, MmcAttrs, MmcDrive, MmcMedium, MmcOp, Session, Track,
};

/// Application backing handle used by every test slot.
pub type TestBacking = u32;

/// Test pair type shared by every slot.
pub type TestPair = Pair<TestMedium2, TestBacking>;

/// Medium member of a test pair.
pub enum TestMedium2 {
    /// Block slot.
    None(NoMedium),
    /// MMC slot.
    Mmc(TestMedium),
}

/// Supported test media.
pub enum TestMedium {
    /// Read-only flat CD.
    Flat(FlatCdMedium),
    /// Blank rewritable DVD-RAM.
    DvdRam(DvdRamMedium),
}

impl MmcMedium for TestMedium {
    type State = ();

    fn attrs(&self) -> MmcAttrs {
        match self {
            Self::Flat(m) => m.attrs(),
            Self::DvdRam(m) => m.attrs(),
        }
    }

    fn state(&self) -> &Self::State {
        &()
    }

    fn begin(&mut self, op: MmcOp) -> Result<(), Completion> {
        match self {
            Self::Flat(m) => m.begin(op),
            Self::DvdRam(m) => m.begin(op),
        }
    }

    fn poll<'a>(&mut self, fb: Feedback, data: &'a mut [u8]) -> PollStep<'a> {
        match self {
            Self::Flat(m) => m.poll(fb, data),
            Self::DvdRam(m) => m.poll(fb, data),
        }
    }

    fn poll_with_alt<'a>(
        &mut self,
        fb: Feedback,
        data: &'a mut [u8],
        alt: &'a mut [u8],
    ) -> PollStep<'a> {
        match self {
            Self::Flat(m) => m.poll_with_alt(fb, data, alt),
            Self::DvdRam(m) => m.poll_with_alt(fb, data, alt),
        }
    }

    fn active(&self) -> bool {
        match self {
            Self::Flat(m) => m.active(),
            Self::DvdRam(m) => m.active(),
        }
    }

    fn interrupt(&mut self, reason: InterruptReason, known: KnownEffects) {
        match self {
            Self::Flat(m) => m.interrupt(reason, known),
            Self::DvdRam(m) => m.interrupt(reason, known),
        }
    }

    fn track(&self, number: u16) -> Option<Track> {
        match self {
            Self::Flat(m) => m.track(number),
            Self::DvdRam(m) => m.track(number),
        }
    }

    fn session(&self, number: u16) -> Option<Session> {
        match self {
            Self::Flat(m) => m.session(number),
            Self::DvdRam(m) => m.session(number),
        }
    }

    fn disc_info(&self) -> DiscInfo {
        match self {
            Self::Flat(m) => m.disc_info(),
            Self::DvdRam(m) => m.disc_info(),
        }
    }
}

/// One runtime test LUN over the block and MMC slot kinds.
#[allow(clippy::large_enum_variant)]
pub enum TestLu {
    /// Block profile.
    Block(LuImpl<Spc<BlockDevice>, TestBacking>),
    /// MMC profile.
    Mmc(LuImpl<Spc<MmcDrive<TestMedium>>, TestBacking>),
}

impl TestLu {
    /// Block slot with the given geometry.
    pub fn block(blocks: u64, block_len: u32, backing: TestBacking) -> Self {
        Self::Block(LuImpl::new(
            Spc::new(BlockDevice::new(BlockAttrs::new(blocks, block_len))),
            backing,
        ))
    }

    /// Write-protected block slot with the given geometry.
    pub fn block_read_only(blocks: u64, block_len: u32, backing: TestBacking) -> Self {
        let mut attrs = BlockAttrs::new(blocks, block_len);
        attrs.write_mode = snowscsi::core::Writability::ReadOnly;
        Self::Block(LuImpl::new(Spc::new(BlockDevice::new(attrs)), backing))
    }

    /// Read-only flat CD slot with `sectors` 2048-byte blocks.
    pub fn cdrom(sectors: u64, backing: TestBacking) -> Self {
        Self::Mmc(LuImpl::new(
            Spc::new(MmcDrive::new(TestMedium::Flat(FlatCdMedium::read_only(
                sectors,
            )))),
            backing,
        ))
    }

    /// Blank rewritable DVD-RAM slot with `sectors` 2048-byte blocks.
    pub fn dvdram(sectors: u64, backing: TestBacking) -> Self {
        Self::Mmc(LuImpl::new(
            Spc::new(MmcDrive::new(TestMedium::DvdRam(DvdRamMedium::new(
                sectors,
            )))),
            backing,
        ))
    }
}

fn block_pair(pair: Pair<NoMedium, TestBacking>) -> TestPair {
    Pair {
        medium: TestMedium2::None(pair.medium),
        backing: pair.backing,
    }
}

fn from_block(pair: TestPair) -> Result<Pair<NoMedium, TestBacking>, TestPair> {
    match pair.medium {
        TestMedium2::None(medium) => Ok(Pair {
            medium,
            backing: pair.backing,
        }),
        TestMedium2::Mmc(_) => Err(pair),
    }
}

fn mmc_pair(pair: Pair<TestMedium, TestBacking>) -> TestPair {
    Pair {
        medium: TestMedium2::Mmc(pair.medium),
        backing: pair.backing,
    }
}

fn from_mmc(pair: TestPair) -> Result<Pair<TestMedium, TestBacking>, TestPair> {
    match pair.medium {
        TestMedium2::Mmc(medium) => Ok(Pair {
            medium,
            backing: pair.backing,
        }),
        TestMedium2::None(_) => Err(pair),
    }
}

fn map_result<P, Q>(r: ChangeResult<P>, f: impl Fn(P) -> Q) -> ChangeResult<Q> {
    ChangeResult {
        pair: r.pair.map(f),
        local: r.local,
        delivery: r.delivery,
        effects: r.effects,
    }
}

fn map_change<P, Q>(c: Change<P>, f: impl Fn(P) -> Q) -> Change<Q> {
    match c {
        Change::Install(p) => Change::Install(f(p)),
        Change::Replace(p) => Change::Replace(f(p)),
        Change::Remove => Change::Remove,
    }
}

fn cross<Q>(
    change: Change<TestPair>,
    f: impl Fn(TestPair) -> Result<Q, TestPair>,
) -> Result<Change<Q>, Change<TestPair>> {
    match change {
        Change::Install(p) => f(p).map(Change::Install).map_err(Change::Install),
        Change::Replace(p) => f(p).map(Change::Replace).map_err(Change::Replace),
        Change::Remove => Ok(Change::Remove),
    }
}

impl Lu for TestLu {
    type Pair = TestPair;

    fn admit(&self, cdb: &[u8]) -> Admission {
        match self {
            Self::Block(l) => l.admit(cdb),
            Self::Mmc(l) => l.admit(cdb),
        }
    }

    fn prepare(
        &mut self,
        permit: &CommandPermit,
        ctx: CommandContext,
        cdb: &[u8],
    ) -> Result<(), Completion> {
        match self {
            Self::Block(l) => l.prepare(permit, ctx, cdb),
            Self::Mmc(l) => l.prepare(permit, ctx, cdb),
        }
    }

    fn active(&self) -> bool {
        match self {
            Self::Block(l) => l.active(),
            Self::Mmc(l) => l.active(),
        }
    }

    fn resume(&mut self, permit: &CommandPermit) -> Result<(), Completion> {
        match self {
            Self::Block(l) => l.resume(permit),
            Self::Mmc(l) => l.resume(permit),
        }
    }

    fn poll<'a>(
        &mut self,
        permit: &CommandPermit,
        feedback: Feedback,
        data: &'a mut [u8],
    ) -> PollStep<'a> {
        match self {
            Self::Block(l) => l.poll(permit, feedback, data),
            Self::Mmc(l) => l.poll(permit, feedback, data),
        }
    }

    fn poll_with_alt<'a>(
        &mut self,
        permit: &CommandPermit,
        feedback: Feedback,
        data: &'a mut [u8],
        alt: &'a mut [u8],
    ) -> PollStep<'a> {
        match self {
            Self::Block(l) => l.poll_with_alt(permit, feedback, data, alt),
            Self::Mmc(l) => l.poll_with_alt(permit, feedback, data, alt),
        }
    }

    fn poll_long<'a>(
        &mut self,
        permit: &CommandPermit,
        feedback: Feedback,
        data: &'a mut [u8],
    ) -> PollStep<'a> {
        match self {
            Self::Block(l) => l.poll_long(permit, feedback, data),
            Self::Mmc(l) => l.poll_long(permit, feedback, data),
        }
    }

    fn long_info(&self) -> LongInfo {
        match self {
            Self::Block(l) => l.long_info(),
            Self::Mmc(l) => l.long_info(),
        }
    }

    fn snapshot(&self) -> LuInfo {
        match self {
            Self::Block(l) => l.snapshot(),
            Self::Mmc(l) => l.snapshot(),
        }
    }

    fn interrupt(
        &mut self,
        permit: &CommandPermit,
        reason: InterruptReason,
        known: KnownEffects,
    ) -> Result<(), Fault> {
        match self {
            Self::Block(l) => l.interrupt(permit, reason, known),
            Self::Mmc(l) => l.interrupt(permit, reason, known),
        }
    }

    fn finish_delivery(&mut self, permit: &CommandPermit, delivery: Delivery) {
        match self {
            Self::Block(l) => l.finish_delivery(permit, delivery),
            Self::Mmc(l) => l.finish_delivery(permit, delivery),
        }
    }

    fn autosense_delivered(&mut self, permit: &CommandPermit, sense: Sense) {
        match self {
            Self::Block(l) => l.autosense_delivered(permit, sense),
            Self::Mmc(l) => l.autosense_delivered(permit, sense),
        }
    }

    fn raise_ua(&mut self, permit: &CommandPermit, class: UaClass) {
        match self {
            Self::Block(l) => l.raise_ua(permit, class),
            Self::Mmc(l) => l.raise_ua(permit, class),
        }
    }

    fn owner(&self) -> TargetId {
        match self {
            Self::Block(l) => l.owner(),
            Self::Mmc(l) => l.owner(),
        }
    }

    fn bind_owner(&mut self, permit: &OwnerBindPermit, owner: TargetId) {
        match self {
            Self::Block(l) => l.bind_owner(permit, owner),
            Self::Mmc(l) => l.bind_owner(permit, owner),
        }
    }

    fn take_rt(&mut self, permit: &BoundaryPermit) -> Option<ChangeResult<TestPair>> {
        match self {
            Self::Block(l) => l.take_rt(permit).map(|r| map_result(r, block_pair)),
            Self::Mmc(l) => l.take_rt(permit).map(|r| map_result(r, mmc_pair)),
        }
    }

    fn has_result(&self) -> bool {
        match self {
            Self::Block(l) => l.has_result(),
            Self::Mmc(l) => l.has_result(),
        }
    }

    fn force_remove_rt(&mut self, permit: &BoundaryPermit) -> Result<(), Fault> {
        match self {
            Self::Block(l) => l.force_remove_rt(permit),
            Self::Mmc(l) => l.force_remove_rt(permit),
        }
    }

    fn install_rt(
        &mut self,
        permit: &BoundaryPermit,
        pair: TestPair,
    ) -> Result<(), (TestPair, Fault)> {
        match self {
            Self::Block(l) => match from_block(pair) {
                Ok(p) => l.install_rt(permit, p).map_err(|(p, f)| (block_pair(p), f)),
                Err(p) => Err((p, Fault::Contract)),
            },
            Self::Mmc(l) => match from_mmc(pair) {
                Ok(p) => l.install_rt(permit, p).map_err(|(p, f)| (mmc_pair(p), f)),
                Err(p) => Err((p, Fault::Contract)),
            },
        }
    }

    fn propose_rt(
        &mut self,
        permit: &BoundaryPermit,
        change: Change<TestPair>,
    ) -> Result<(), (Change<TestPair>, Fault)> {
        match self {
            Self::Block(l) => match cross(change, from_block) {
                Ok(c) => l
                    .propose_rt(permit, c)
                    .map_err(|(c, f)| (map_change(c, block_pair), f)),
                Err(c) => Err((c, Fault::Contract)),
            },
            Self::Mmc(l) => match cross(change, from_mmc) {
                Ok(c) => l
                    .propose_rt(permit, c)
                    .map_err(|(c, f)| (map_change(c, mmc_pair), f)),
                Err(c) => Err((c, Fault::Contract)),
            },
        }
    }

    fn advance_rt(&mut self, permit: &BoundaryPermit) -> Result<(), Fault> {
        match self {
            Self::Block(l) => l.advance_rt(permit),
            Self::Mmc(l) => l.advance_rt(permit),
        }
    }

    fn eject_rt(&mut self, permit: &BoundaryPermit) -> Result<(), Fault> {
        match self {
            Self::Block(l) => l.eject_rt(permit),
            Self::Mmc(l) => l.eject_rt(permit),
        }
    }
}

/// Core fault for a byte-plane error.
pub fn map_storage_error(e: snowscsi::common::seekable_storage::StorageError) -> Fault {
    use snowscsi::common::seekable_storage::StorageError;
    match e {
        StorageError::OutOfBounds => Fault::OutOfBounds,
        StorageError::NotWritable => Fault::NotWritable,
        StorageError::Io(_) => Fault::Io,
        StorageError::Unsupported => Fault::Unsupported,
    }
}

/// Multi-LUN synchronous storage adapter routing by the runner's LUN hook.
pub struct PlaneSet<'a> {
    planes: Vec<Option<StorePlane<'a>>>,
    lun: usize,
    token: Option<(IoReq, u32)>,
    tag: u32,
    /// Number of plane operations actually executed (test observability).
    pub execs: usize,
    /// When non-zero, the next poll(s) answer `Pending` before touching the
    /// plane (used to observe the core's storage-only steps).
    pub pending_polls: usize,
}

impl<'a> PlaneSet<'a> {
    /// Wrap one plane slot per LUN.
    pub fn new(planes: Vec<Option<StorePlane<'a>>>) -> Self {
        Self {
            planes,
            lun: 0,
            token: None,
            tag: 1,
            execs: 0,
            pending_polls: 0,
        }
    }

    /// Answer the next `polls` storage executions as `Pending` (a
    /// storage-only step the shell must drive again).
    pub fn with_pending(mut self, polls: usize) -> Self {
        self.pending_polls = polls;
        self
    }

    /// Execute one raw store operation on the selected LUN.
    pub fn exec_raw(
        &mut self,
        op: StoreOp<'_>,
    ) -> Result<(), snowscsi::common::seekable_storage::StorageError> {
        match self.planes.get_mut(self.lun).and_then(|p| p.as_mut()) {
            Some(plane) => plane.do_op(op),
            None => Err(snowscsi::common::seekable_storage::StorageError::Unsupported),
        }
    }
}

impl Storage for PlaneSet<'_> {
    fn select_lun(&mut self, lun: usize) {
        self.lun = lun;
    }

    fn begin_exec(&mut self, req: IoReq) -> IoToken {
        if self.token.is_some() || self.lun >= self.planes.len() {
            return IoToken::new(u8::MAX, 0);
        }
        let tag = self.tag;
        self.tag = self.tag.wrapping_add(1).max(1);
        self.token = Some((req, tag));
        IoToken::new(0, tag)
    }

    fn poll_exec(&mut self, token: IoToken, buf: IoBuf<'_>) -> Poll<StorageReceipt> {
        let (req, tag) = match self.token {
            Some((req, tag)) if token == IoToken::new(0, tag) => (req, tag),
            _ => return Poll::Ready(StorageReceipt::failed(Fault::Contract, 0, Effect::Known)),
        };
        if self.pending_polls > 0 {
            self.pending_polls -= 1;
            return Poll::Pending;
        }
        let _ = tag;
        self.token = None;
        let ok = match (req.dir, &buf) {
            (snowscsi::core::Direction::None, IoBuf::None) => req.len == 0,
            (snowscsi::core::Direction::ToHost, IoBuf::Read(b)) => req.len as usize == b.len(),
            (snowscsi::core::Direction::FromHost, IoBuf::Write(b)) => req.len as usize == b.len(),
            _ => false,
        };
        if !ok {
            return Poll::Ready(StorageReceipt::failed(Fault::Contract, 0, Effect::Known));
        }
        let Some(plane) = self.planes.get_mut(self.lun).and_then(|p| p.as_mut()) else {
            return Poll::Ready(StorageReceipt::failed(Fault::Contract, 0, Effect::Known));
        };
        let confirmed = match &buf {
            IoBuf::None => 0,
            IoBuf::Read(b) => b.len(),
            IoBuf::Write(b) => b.len(),
        };
        let op = match buf {
            IoBuf::None => StoreOp::Sync,
            IoBuf::Read(b) => StoreOp::Read {
                off: req.offset,
                buf: b,
            },
            IoBuf::Write(b) => StoreOp::Write {
                off: req.offset,
                buf: b,
            },
        };
        self.execs += 1;
        match plane.do_op(op) {
            Ok(()) => Poll::Ready(StorageReceipt::ok(confirmed)),
            Err(e) => Poll::Ready(StorageReceipt::failed(
                map_storage_error(e),
                0,
                if req.dir == snowscsi::core::Direction::FromHost {
                    Effect::UnknownRemainder
                } else {
                    Effect::Known
                },
            )),
        }
    }

    fn cancel(&mut self, token: IoToken) {
        if let Some((_, tag)) = self.token {
            if token == IoToken::new(0, tag) {
                self.token = None;
            }
        }
    }
}

/// A synchronous plane set is always ready: `poll_exec` only reports the
/// scripted `pending_polls` count, which a wake-based shell never leaves
/// armed in the golden replay.
impl AsyncWake for PlaneSet<'_> {
    fn poll_wake(&mut self, _cx: &mut core::task::Context<'_>) -> Poll<()> {
        Poll::Ready(())
    }
}
