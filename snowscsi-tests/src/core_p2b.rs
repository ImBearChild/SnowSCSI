//! Query-command fixtures: the public commands served by the `Spc`
//! wrapper through the guest profile seam.
//!
//! Covered here: MODE SENSE(6/10) on `BlockDevice`, READ CAPACITY(10),
//! allocation-length truncation, the delegation path (a device without an
//! `SpcProfile`), GET CONFIGURATION / GESN fall-through on Block, and the
//! foreground FORMAT admission gate.
//!
//! The fixtures use the same public `Target` + real `SyncStorage`/`SyncHost`
//! adapters as `core_p2a`: query commands issue no storage IO, so the plane
//! fails the command if one is ever requested.

use snowscsi::block::{BlockAttrs, BlockDevice};
use snowscsi::core::storage::{
    BlockingHost, BlockingStorage, HostBuf, HostReceipt, HostReq, IoBuf, IoReq, StorageReceipt,
    SyncHost, SyncStorage,
};
use snowscsi::core::{
    cons, Admission, At, BoundaryPermit, Capacity, Change, CommandContext, CommandPermit,
    Completion, Cons, DataPlan, Delivery, Device, Direction, Effect, Fault, Feedback, Here,
    InterruptReason, KnownEffects, LongInfo, LongPhase, Lu, LuImpl, Nil, NoMedium, PollStep, Sense,
    SlotSet, Spc, SpcProfile, StaticTarget, Target, FORMAT_IN_PROGRESS, ILLEGAL_REQUEST,
    INVALID_FIELD, MEDIUM_NOT_PRESENT, WRITE_PROTECTED,
};
use snowscsi::mmc::{DvdRamMedium, FlatCdMedium, MmcDrive, MmcMedium, VendorMedium};

/// Mode pages the block profile must reproduce byte for byte (baseline
/// `scsi::spc::ALL_MODE_PAGES`: caching page 0x08 then vendor page 0x00).
const BLOCK_MODE_PAGES: [u8; 24] = [
    0x08, 18, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x20, 0, 0, 0, 0, 0, 0, 0, /* caching PS=0 */
    0x00, 2, 0x00, 0x08, /* vendor page 0x00 */
];

/// Query commands issue no storage IO; any call is a contract breach.
struct NoIo;

impl SyncStorage for NoIo {
    fn exec(&mut self, _req: IoReq, _buf: IoBuf<'_>) -> StorageReceipt {
        StorageReceipt::failed(Fault::Contract, 0, Effect::Known)
    }
}

/// What the host seam saw: the plan and the natural send length.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum HostEvent {
    Publish(DataPlan),
    Sent(usize),
}

struct TestHost {
    events: Vec<HostEvent>,
}

impl TestHost {
    fn new() -> Self {
        Self { events: Vec::new() }
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
                let accepted = (req.len as usize).min(bytes.len());
                bytes[..accepted].fill(0xa5);
                HostReceipt::from_adapter(accepted, None)
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

fn ctx(direction: Direction, bytes: u64) -> CommandContext {
    CommandContext {
        lun: 0,
        lun_count: 1,
        host_bytes: bytes,
        host_direction: direction,
    }
}

fn mode_sense_6(page: u8, pc: u8, alloc: u8) -> [u8; 6] {
    [0x1A, 0x00, (pc << 6) | (page & 0x3F), 0x00, alloc, 0x00]
}

fn mode_sense_10(page: u8, dbd: bool, alloc: u16) -> [u8; 10] {
    let mut cdb = [0u8; 10];
    cdb[0] = 0x5A;
    cdb[1] = if dbd { 0x08 } else { 0x00 };
    cdb[2] = page & 0x3F;
    cdb[7] = (alloc >> 8) as u8;
    cdb[8] = alloc as u8;
    cdb
}

fn read_capacity_10(lba: u32, pmi: bool) -> [u8; 10] {
    let mut cdb = [0u8; 10];
    cdb[0] = 0x25;
    cdb[2] = (lba >> 24) as u8;
    cdb[3] = (lba >> 16) as u8;
    cdb[4] = (lba >> 8) as u8;
    cdb[5] = lba as u8;
    cdb[8] = u8::from(pmi);
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

type BlockTarget = Target<Cons<LuImpl<Spc<BlockDevice>, u8>, Nil>>;

fn block_target() -> BlockTarget {
    Target::new(cons(
        LuImpl::new(Spc::new(BlockDevice::new(BlockAttrs::new(16, 512))), 1u8),
        Nil,
    ))
}

/// Probe access to the first static slot (same helper shape as `core_p2a`).
fn slot0<S>(target: &Target<S>) -> &<S as At<Here>>::Slot
where
    S: SlotSet + At<Here>,
{
    <S as At<Here>>::slot(target.slots())
}

/// MODE SENSE(6) page 0x08: 4-byte header + the baseline caching page.
#[test]
fn mode_sense_6_caching_page_layout() {
    let mut target = block_target();
    let mut storage = BlockingStorage::new(NoIo);
    let mut host = BlockingHost::new(TestHost::new());
    let mut work = [0u8; 64];
    let mut scratch = [0u8; 64];

    assert_eq!(
        target.drive_static_host::<Here>(
            &mut storage,
            &mut host,
            ctx(Direction::ToHost, 24),
            &mode_sense_6(0x08, 0, 24),
            &mut work,
            &mut scratch,
        ),
        Ok(Completion::Good)
    );
    assert_eq!(work[0], 23, "mode data length = total - 1");
    assert_eq!(work[1], 0, "medium type");
    assert_eq!(work[2], 0, "WP bit clear");
    assert_eq!(work[3], 0, "block descriptor length");
    assert_eq!(&work[4..24], &BLOCK_MODE_PAGES[..20]);
    assert_eq!(
        host.inner().events,
        vec![
            HostEvent::Publish(DataPlan {
                direction: Direction::ToHost,
                bytes: 24,
            }),
            HostEvent::Sent(24),
        ]
    );
}

/// MODE SENSE(10) page 0x3F: 8-byte header + both pages, DBD accepted.
#[test]
fn mode_sense_10_all_pages_with_dbd() {
    let mut target = block_target();
    let mut storage = BlockingStorage::new(NoIo);
    let mut host = BlockingHost::new(TestHost::new());
    let mut work = [0u8; 64];
    let mut scratch = [0u8; 64];

    assert_eq!(
        target.drive_static_host::<Here>(
            &mut storage,
            &mut host,
            ctx(Direction::ToHost, 32),
            &mode_sense_10(0x3F, true, 32),
            &mut work,
            &mut scratch,
        ),
        Ok(Completion::Good)
    );
    assert_eq!(
        &work[0..2],
        &30u16.to_be_bytes(),
        "mode data length = total - 2"
    );
    assert_eq!(work[2], 0, "medium type");
    assert_eq!(work[3], 0, "WP bit clear");
    assert_eq!(&work[4..6], &[0, 0], "reserved");
    assert_eq!(&work[6..8], &[0, 0], "block descriptor length (DBD)");
    assert_eq!(&work[8..32], &BLOCK_MODE_PAGES, "0x08 then 0x00");
    assert_eq!(
        host.inner().events,
        vec![
            HostEvent::Publish(DataPlan {
                direction: Direction::ToHost,
                bytes: 32,
            }),
            HostEvent::Sent(32),
        ]
    );
}

/// Truncation to the allocation length keeps the complete-response header
/// length: the profile returns the full length, `Spc` sends `min(alloc, total)`.
#[test]
fn mode_sense_truncation_keeps_the_declared_length() {
    let mut target = block_target();
    let mut storage = BlockingStorage::new(NoIo);
    let mut host = BlockingHost::new(TestHost::new());
    let mut work = [0u8; 8];
    let mut scratch = [0u8; 8];

    assert_eq!(
        target.drive_static_host::<Here>(
            &mut storage,
            &mut host,
            ctx(Direction::ToHost, 8),
            &mode_sense_6(0x08, 0, 8),
            &mut work,
            &mut scratch,
        ),
        Ok(Completion::Good)
    );
    assert_eq!(work[0], 23, "header still declares the 24-byte response");
    assert_eq!(&work[4..8], &BLOCK_MODE_PAGES[..4]);
    assert_eq!(
        host.inner().events,
        vec![
            HostEvent::Publish(DataPlan {
                direction: Direction::ToHost,
                bytes: 8,
            }),
            HostEvent::Sent(8),
        ]
    );
}

/// PC=01b (changeable): page code/length kept, payload zeroed (baseline
/// behavior chosen for this implementation).
#[test]
fn mode_sense_changeable_page_keeps_code_and_length() {
    let mut target = block_target();
    let mut storage = BlockingStorage::new(NoIo);
    let mut host = BlockingHost::new(TestHost::new());
    let mut work = [0u8; 64];
    let mut scratch = [0u8; 64];

    assert_eq!(
        target.drive_static_host::<Here>(
            &mut storage,
            &mut host,
            ctx(Direction::ToHost, 24),
            &mode_sense_6(0x08, 1, 24),
            &mut work,
            &mut scratch,
        ),
        Ok(Completion::Good)
    );
    assert_eq!(work[0], 23);
    assert_eq!(&work[4..6], &[0x08, 18], "page code and length preserved");
    assert!(
        work[6..24].iter().all(|b| *b == 0),
        "changeable payload is all zero (no changeable fields)"
    );
}

/// PC=11b (saved) is not supported: ILLEGAL REQUEST / SAVING PARAMETERS NOT
/// SUPPORTED (05/39/00).
#[test]
fn mode_sense_saved_page_control_is_rejected() {
    let mut target = block_target();
    let mut storage = BlockingStorage::new(NoIo);
    let mut work = [0u8; 64];
    let mut scratch = [0u8; 64];

    assert_eq!(
        target.drive_static::<Here>(
            &mut storage,
            ctx(Direction::ToHost, 24),
            &mode_sense_6(0x08, 3, 24),
            &mut work,
            &mut scratch,
        ),
        Ok(Completion::Check(Sense::new(0x05, 0x39, 0x00)))
    );
}

/// READ CAPACITY(10): exactly 8 bytes, last LBA and block length big-endian.
#[test]
fn read_capacity_is_exactly_eight_bytes() {
    let mut target = block_target();
    let mut storage = BlockingStorage::new(NoIo);
    let mut host = BlockingHost::new(TestHost::new());
    let mut work = [0u8; 8];
    let mut scratch = [0u8; 8];

    assert_eq!(
        target.drive_static_host::<Here>(
            &mut storage,
            &mut host,
            ctx(Direction::ToHost, 8),
            &read_capacity_10(0, false),
            &mut work,
            &mut scratch,
        ),
        Ok(Completion::Good)
    );
    assert_eq!(
        &work[0..4],
        &15u32.to_be_bytes(),
        "16 blocks -> last LBA 15"
    );
    assert_eq!(&work[4..8], &512u32.to_be_bytes(), "block length");
    assert_eq!(
        host.inner().events,
        vec![
            HostEvent::Publish(DataPlan {
                direction: Direction::ToHost,
                bytes: 8,
            }),
            HostEvent::Sent(8),
        ]
    );
}

/// PMI=0 requires LBA 0; PMI=1 requires an addressable LBA.
#[test]
fn read_capacity_validates_pmi_and_lba() {
    let mut target = block_target();
    let mut storage = BlockingStorage::new(NoIo);
    let mut host = BlockingHost::new(TestHost::new());
    let mut work = [0u8; 8];
    let mut scratch = [0u8; 8];

    assert_eq!(
        target.drive_static_host::<Here>(
            &mut storage,
            &mut host,
            ctx(Direction::ToHost, 8),
            &read_capacity_10(1, false),
            &mut work,
            &mut scratch,
        ),
        Ok(Completion::Check(INVALID_FIELD)),
        "PMI=0 with a non-zero LBA"
    );
    assert_eq!(
        target.drive_static_host::<Here>(
            &mut storage,
            &mut host,
            ctx(Direction::ToHost, 8),
            &read_capacity_10(16, true),
            &mut work,
            &mut scratch,
        ),
        Ok(Completion::Check(INVALID_FIELD)),
        "PMI=1 with an LBA past the last block"
    );
    assert_eq!(
        target.drive_static_host::<Here>(
            &mut storage,
            &mut host,
            ctx(Direction::ToHost, 8),
            &read_capacity_10(15, true),
            &mut work,
            &mut scratch,
        ),
        Ok(Completion::Good),
        "PMI=1 with the last addressable LBA"
    );
}

/// Allocation length 0 transfers no data: no plan, no send, GOOD.
#[test]
fn allocation_zero_sends_nothing() {
    let mut target = block_target();
    let mut storage = BlockingStorage::new(NoIo);
    let mut host = BlockingHost::new(TestHost::new());
    let mut work = [0u8; 8];
    let mut scratch = [0u8; 8];

    assert_eq!(
        target.drive_static_host::<Here>(
            &mut storage,
            &mut host,
            ctx(Direction::ToHost, 0),
            &mode_sense_6(0x08, 0, 0),
            &mut work,
            &mut scratch,
        ),
        Ok(Completion::Good)
    );
    assert!(host.inner().events.is_empty(), "MODE SENSE alloc 0");
}

// ── Mock devices ────────────────────────────────────────────────────────

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum MockKind {
    /// No `SpcProfile`: every opcode must reach `Device::prepare`.
    NoProfile,
    /// Profile answers GET CONFIGURATION and GESN.
    Queries,
    /// Foreground FORMAT resident long operation.
    Foreground,
}

/// Minimal device used to prove the profile gate and the delegation path.
struct Mock {
    kind: MockKind,
    prepares: u32,
}

impl Mock {
    fn new(kind: MockKind) -> Self {
        Self { kind, prepares: 0 }
    }
}

impl SpcProfile for Mock {
    fn mode_sense(
        &self,
        _ten: bool,
        page: u8,
        _dbd: bool,
        _pc: u8,
        out: Option<&mut [u8]>,
    ) -> Option<usize> {
        if page != 0x08 {
            return None;
        }
        let total = 6;
        if let Some(out) = out {
            let n = total.min(out.len());
            out[..n].fill(0x08);
        }
        Some(total)
    }

    fn read_capacity(&self) -> Option<Capacity> {
        Some(Capacity::new(3, 512))
    }

    fn get_configuration(&self, _rt: u8, _start: u16, out: Option<&mut [u8]>) -> Option<usize> {
        let total = 16;
        if let Some(out) = out {
            let n = total.min(out.len());
            out[..n].fill(0xC0);
        }
        Some(total)
    }

    fn event_status(&self, class: u8, out: Option<&mut [u8]>) -> Option<usize> {
        if class != 0x00 {
            return None;
        }
        let total = 8;
        if let Some(out) = out {
            let n = total.min(out.len());
            out[..n].fill(0xE0);
        }
        Some(total)
    }
}

impl Device for Mock {
    type Medium = NoMedium;

    fn spc_profile(&self) -> Option<&dyn SpcProfile> {
        match self.kind {
            MockKind::NoProfile => None,
            MockKind::Queries | MockKind::Foreground => Some(self),
        }
    }

    fn prepare(
        &mut self,
        _permit: &CommandPermit,
        _ctx: CommandContext,
        _cdb: &[u8],
    ) -> Result<(), Completion> {
        self.prepares += 1;
        Err(Completion::Check(ILLEGAL_REQUEST))
    }

    fn active(&self) -> bool {
        false
    }

    fn resume(&mut self, _permit: &CommandPermit) -> Result<(), Completion> {
        Ok(())
    }

    fn poll<'a>(
        &mut self,
        _permit: &CommandPermit,
        _fb: Feedback,
        _data: &'a mut [u8],
    ) -> PollStep<'a> {
        PollStep::Complete(Completion::Check(ILLEGAL_REQUEST))
    }

    fn poll_long<'a>(
        &mut self,
        _permit: &CommandPermit,
        _fb: Feedback,
        _data: &'a mut [u8],
    ) -> PollStep<'a> {
        PollStep::Idle
    }

    fn long_info(&self) -> LongInfo {
        match self.kind {
            MockKind::Foreground => LongInfo {
                phase: LongPhase::Foreground,
                write_accessible: false,
                progress: Some(64),
                error: None,
            },
            MockKind::NoProfile | MockKind::Queries => LongInfo::IDLE,
        }
    }

    fn interrupt(
        &mut self,
        _permit: &CommandPermit,
        _reason: InterruptReason,
        _known: KnownEffects,
    ) -> Result<(), Fault> {
        Ok(())
    }

    fn finish_delivery(&mut self, _permit: &CommandPermit, _delivery: Delivery) {}

    fn take_medium(&mut self, _permit: &BoundaryPermit) -> Option<NoMedium> {
        Some(NoMedium)
    }

    fn install_medium(
        &mut self,
        _permit: &BoundaryPermit,
        medium: NoMedium,
    ) -> Result<(), (NoMedium, Fault)> {
        let _ = medium;
        Ok(())
    }
}

type MockTarget = Target<Cons<LuImpl<Spc<Mock>, u8>, Nil>>;

fn mock_target(kind: MockKind) -> MockTarget {
    Target::new(cons(LuImpl::new(Spc::new(Mock::new(kind)), 1u8), Nil))
}

/// Without an `SpcProfile` the four new opcodes are delegated to the inner
/// device: the wrapper itself would answer INVALID_FIELD,
/// the inner device answers ILLEGAL REQUEST.
#[test]
fn no_profile_delegates_the_new_opcodes() {
    let mut target = mock_target(MockKind::NoProfile);
    let mut storage = BlockingStorage::new(NoIo);
    let mut work = [0u8; 32];
    let mut scratch = [0u8; 32];

    let cdbs: [&[u8]; 5] = [
        &mode_sense_6(0x08, 0, 24),
        &mode_sense_10(0x3F, false, 32),
        &read_capacity_10(0, false),
        &get_configuration(0, 8),
        &gesn(0x00, true, 8),
    ];
    for cdb in cdbs {
        assert_eq!(
            target.drive_static::<Here>(
                &mut storage,
                ctx(Direction::ToHost, 0),
                cdb,
                &mut work,
                &mut scratch,
            ),
            Ok(Completion::Check(ILLEGAL_REQUEST)),
            "opcode {:#04x} must reach the inner device",
            cdb[0]
        );
    }
    assert_eq!(
        slot0(&target).device_ref().inner().prepares,
        cdbs.len() as u32,
        "every CDB reached Device::prepare"
    );
}

/// Block implements MODE SENSE/READ CAPACITY only; GET CONFIGURATION and GESN
/// keep the default profile answer and fall through to the inner Block, which
/// rejects the opcode (delegated behavior).
#[test]
fn block_get_configuration_and_gesn_fall_through() {
    let mut target = block_target();
    let mut storage = BlockingStorage::new(NoIo);
    let mut work = [0u8; 16];
    let mut scratch = [0u8; 16];

    assert_eq!(
        target.drive_static::<Here>(
            &mut storage,
            ctx(Direction::ToHost, 8),
            &get_configuration(0, 8),
            &mut work,
            &mut scratch,
        ),
        Ok(Completion::Check(ILLEGAL_REQUEST)),
        "GET CONFIGURATION is not implemented by Block"
    );
    assert_eq!(
        target.drive_static::<Here>(
            &mut storage,
            ctx(Direction::ToHost, 8),
            &gesn(0x00, true, 8),
            &mut work,
            &mut scratch,
        ),
        Ok(Completion::Check(ILLEGAL_REQUEST)),
        "GESN is not implemented by Block"
    );
    // Non-polled GESN is rejected by the wrapper itself (baseline rule).
    assert_eq!(
        target.drive_static::<Here>(
            &mut storage,
            ctx(Direction::ToHost, 8),
            &gesn(0x00, false, 8),
            &mut work,
            &mut scratch,
        ),
        Ok(Completion::Check(INVALID_FIELD)),
        "Poll bit 0 is invalid"
    );
}

/// A profile that implements GET CONFIGURATION/GESN drives the full data
/// phase through the wrapper.
#[test]
fn profile_gets_and_gc_response_flow() {
    let mut target = mock_target(MockKind::Queries);
    let mut storage = BlockingStorage::new(NoIo);
    let mut host = BlockingHost::new(TestHost::new());
    let mut work = [0u8; 16];
    let mut scratch = [0u8; 16];

    assert_eq!(
        target.drive_static_host::<Here>(
            &mut storage,
            &mut host,
            ctx(Direction::ToHost, 8),
            &gesn(0x00, true, 8),
            &mut work,
            &mut scratch,
        ),
        Ok(Completion::Good)
    );
    assert_eq!(&work[..8], &[0xE0; 8]);
    assert_eq!(
        host.inner().events,
        vec![
            HostEvent::Publish(DataPlan {
                direction: Direction::ToHost,
                bytes: 8,
            }),
            HostEvent::Sent(8),
        ]
    );

    let mut host = BlockingHost::new(TestHost::new());
    assert_eq!(
        target.drive_static_host::<Here>(
            &mut storage,
            &mut host,
            ctx(Direction::ToHost, 16),
            &get_configuration(0, 16),
            &mut work,
            &mut scratch,
        ),
        Ok(Completion::Good)
    );
    assert_eq!(&work[..16], &[0xC0; 16]);
    assert_eq!(
        host.inner().events,
        vec![
            HostEvent::Publish(DataPlan {
                direction: Direction::ToHost,
                bytes: 16,
            }),
            HostEvent::Sent(16),
        ]
    );

    // Allocation length 0 for GET CONFIGURATION: no plan, no send, GOOD.
    let mut host = BlockingHost::new(TestHost::new());
    assert_eq!(
        target.drive_static_host::<Here>(
            &mut storage,
            &mut host,
            ctx(Direction::ToHost, 0),
            &get_configuration(0, 0),
            &mut work,
            &mut scratch,
        ),
        Ok(Completion::Good)
    );
    assert!(host.inner().events.is_empty(), "GET CONFIGURATION alloc 0");
}

/// Foreground FORMAT admits only the query allow-list: MODE SENSE and READ
/// CAPACITY are rejected at the `Lu` boundary with 02/04/04, GET
/// CONFIGURATION and GESN still proceed.
///
/// The `Spc`-level gate itself (and GESN success while the gate is up) is
/// covered by `core::spc::tests::foreground_format_gates_the_medium_queries_only`:
/// the `Runner` boundary refuses to start any command while a resident long
/// operation is not settled, so the wrapper gate is only reachable by direct
/// `Spc` users.
#[test]
fn foreground_format_is_gated_at_admission() {
    let slot = LuImpl::new(Mock::new(MockKind::Foreground), 1u8);
    assert_eq!(
        slot.admit(&mode_sense_6(0x08, 0, 24)),
        Admission::Reject(Completion::Check(FORMAT_IN_PROGRESS))
    );
    assert_eq!(
        slot.admit(&read_capacity_10(0, false)),
        Admission::Reject(Completion::Check(FORMAT_IN_PROGRESS))
    );
    assert_eq!(
        slot.admit(&get_configuration(0, 8)),
        Admission::Proceed,
        "GET CONFIGURATION is admitted during a foreground FORMAT"
    );
    assert_eq!(
        slot.admit(&gesn(0x00, true, 8)),
        Admission::Proceed,
        "GESN is admitted during a foreground FORMAT"
    );
}

// ═══════════════════════════════════════════════════════════════════════════
// Format / BLANK / long-operation / DVD-RAM / vendor fixtures
// ═══════════════════════════════════════════════════════════════════════════

/// Byte-plane storage mock: real bytes for round trips, recorded IO, and
/// injectable write/read faults.
#[derive(Default)]
struct Plane {
    mem: Vec<u8>,
    writes: Vec<(u64, usize)>,
    /// Whether each recorded write buffer was entirely zero (FORMAT/BLANK).
    write_zero: Vec<bool>,
    reads: Vec<(u64, usize)>,
    syncs: usize,
    fail_writes: bool,
    fail_reads: bool,
}

impl Plane {
    fn new(len: usize) -> Self {
        Self {
            mem: vec![0xEE; len],
            ..Self::default()
        }
    }

    fn zeroed(&self, len: usize) -> bool {
        self.mem.len() >= len && self.mem[..len].iter().all(|b| *b == 0)
    }
}

impl SyncStorage for Plane {
    fn exec(&mut self, req: IoReq, buf: IoBuf<'_>) -> StorageReceipt {
        match (req.dir, buf) {
            (Direction::None, IoBuf::None) => {
                self.syncs += 1;
                StorageReceipt::ok(0)
            }
            (Direction::ToHost, IoBuf::Read(b)) => {
                self.reads.push((req.offset, b.len()));
                if self.fail_reads {
                    return StorageReceipt::failed(Fault::Io, 0, Effect::Known);
                }
                let start = req.offset as usize;
                let end = start.saturating_add(b.len());
                if end > self.mem.len() {
                    return StorageReceipt::failed(Fault::OutOfBounds, 0, Effect::Known);
                }
                b.copy_from_slice(&self.mem[start..end]);
                StorageReceipt::ok(b.len())
            }
            (Direction::FromHost, IoBuf::Write(b)) => {
                self.writes.push((req.offset, b.len()));
                self.write_zero.push(b.iter().all(|byte| *byte == 0));
                if self.fail_writes {
                    return StorageReceipt::failed(Fault::Io, 0, Effect::UnknownRemainder);
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

/// Host seam that supplies a FORMAT UNIT parameter list on Data-Out.
struct ParamHost {
    params: [u8; 12],
    events: Vec<HostEvent>,
}

impl ParamHost {
    fn new(params: [u8; 12]) -> Self {
        Self {
            params,
            events: Vec::new(),
        }
    }
}

impl SyncHost for ParamHost {
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
        self.events.push(HostEvent::Sent(req.len as usize));
        HostReceipt::from_adapter(req.len as usize, None)
    }

    fn delivery(&self) -> Delivery {
        Delivery::Complete
    }
}

/// Format List Header + the single 8-byte Format Descriptor.
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

type DvdTarget = Target<Cons<LuImpl<Spc<MmcDrive<DvdRamMedium>>, u8>, Nil>>;
type VendorTarget = Target<Cons<LuImpl<Spc<MmcDrive<VendorMedium>>, u8>, Nil>>;
type MmcFlatTarget = Target<Cons<LuImpl<Spc<MmcDrive<FlatCdMedium>>, u8>, Nil>>;

fn dvd_target(sectors: u64) -> DvdTarget {
    Target::new(cons(
        LuImpl::new(Spc::new(MmcDrive::new(DvdRamMedium::new(sectors))), 1u8),
        Nil,
    ))
}

fn vendor_target(sectors: u64) -> VendorTarget {
    Target::new(cons(
        LuImpl::new(Spc::new(MmcDrive::new(VendorMedium::new(sectors))), 1u8),
        Nil,
    ))
}

fn mmc_flat_target(sectors: u64) -> MmcFlatTarget {
    Target::new(cons(
        LuImpl::new(
            Spc::new(MmcDrive::new(FlatCdMedium::read_only(sectors))),
            1u8,
        ),
        Nil,
    ))
}

fn tur_cdb() -> [u8; 6] {
    [0x00, 0, 0, 0, 0, 0]
}

/// TUR is served by the profile: present => GOOD; a taken pair is NOT READY.
#[test]
fn mmc_tur_present_and_no_medium() {
    let mut target = dvd_target(8);
    let mut storage = BlockingStorage::new(Plane::new(0));
    let mut work = [0u8; 8];
    let mut scratch = [0u8; 8];
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

    let taken = {
        assert!(target.propose_static::<Here>(Change::Remove).is_ok());
        target.advance_static::<Here>().expect("advance remove");
        let Ok(taken) = target.take_static_at::<Here>(0) else {
            panic!("take pair failed");
        };
        taken
    };
    assert!(taken.pair.is_some());
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

/// FORMAT IMMED=1: GOOD after validation, the foreground gate rejects the
/// media command set with 02/04/04 and zero storage IO, the resident operation
/// settles through `poll_long`, and READ/WRITE work afterwards.
#[test]
fn mmc_format_immed_one_gates_media_commands_and_settles() {
    let mut target = dvd_target(4);
    let mut storage = BlockingStorage::new(Plane::new(16 * 1024));
    let mut host = BlockingHost::new(ParamHost::new(format_params(0xA2, 0)));
    let mut work = vec![0u8; 4096];
    // The resident long operation uses `scratch`, so it must be large enough
    // for the fixture's expected 4096-byte chunks.
    let mut scratch = vec![0u8; 4096];
    let cdb = [0x04u8, 0x11, 0, 0, 0, 0];

    assert_eq!(
        target.drive_static_host::<Here>(
            &mut storage,
            &mut host,
            ctx(Direction::FromHost, 12),
            &cdb,
            &mut work,
            &mut scratch,
        ),
        Ok(Completion::Good)
    );
    assert!(
        storage.inner().writes.is_empty(),
        "IMMED=1 must not zero-fill inside the command"
    );
    let long = slot0(&target).long_info();
    assert_eq!(long.phase, LongPhase::Foreground);
    assert!(!long.write_accessible);
    assert_eq!(long.progress, Some(0));

    // Admission matrix while Foreground: only RS/INQUIRY/GC/GESN/REPORT LUNS.
    {
        let slot = slot0(&target);
        let rejected: [&[u8]; 7] = [
            &tur_cdb(),
            &read10(0, 1),
            &write10(0, 1),
            &[0x43, 0, 0, 0, 0, 0, 0, 0, 20, 0],
            &[0xBE, 0, 0, 0, 0, 0, 0, 0, 1, 0x08, 0, 0],
            &[0x5B, 0, 0, 0, 0, 0, 0, 0, 0, 0],
            &[0xA1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0],
        ];
        for cdb in rejected {
            assert_eq!(
                slot.admit(cdb),
                Admission::Reject(Completion::Check(FORMAT_IN_PROGRESS)),
                "opcode {:#04x} must be gated",
                cdb[0]
            );
        }
        let mut inquiry = [0u8; 6];
        inquiry[0] = 0x12;
        inquiry[4] = 0xFF;
        let mut report_luns = [0u8; 10];
        report_luns[0] = 0xA0;
        report_luns[6..10].copy_from_slice(&8u32.to_be_bytes());
        let admitted: [&[u8]; 4] = [
            &inquiry,
            &report_luns,
            &get_configuration(0, 64),
            &gesn(0x10, true, 8),
        ];
        for cdb in admitted {
            assert_eq!(
                slot.admit(cdb),
                Admission::Proceed,
                "opcode {:#04x} must stay admitted",
                cdb[0]
            );
        }
    }
    assert!(storage.inner().writes.is_empty());
    assert!(storage.inner().reads.is_empty());

    // The runner does not reject a command merely because a resident long
    // operation is unsettled: the command reaches the device gate and the host
    // sees CHECK 2/04/04 (not a boundary fault) with zero medium/backing
    // access. `core_p4` covers the same live path with the `work`/`scratch`
    // split and the query set.
    let rejected: [&[u8]; 3] = [&tur_cdb(), &read10(0, 1), &write10(0, 1)];
    for cdb in rejected {
        assert_eq!(
            target.drive_static::<Here>(
                &mut storage,
                ctx(Direction::None, 0),
                cdb,
                &mut work,
                &mut scratch,
            ),
            Ok(Completion::Check(FORMAT_IN_PROGRESS)),
            "opcode {:#04x} must be rejected by the device gate",
            cdb[0]
        );
    }
    // REQUEST SENSE during the foreground phase carries the FORMAT IN
    // PROGRESS sense with SKSV and a progress value.
    let mut sense_host = BlockingHost::new(TestHost::new());
    let request_sense = [0x03u8, 0, 0, 0, 18, 0];
    assert_eq!(
        target.drive_static_host::<Here>(
            &mut storage,
            &mut sense_host,
            ctx(Direction::ToHost, 18),
            &request_sense,
            &mut work,
            &mut scratch,
        ),
        Ok(Completion::Good)
    );
    assert_eq!(work[2] & 0x0F, 0x02, "NOT READY");
    assert_eq!(work[12], 0x04, "ASC = LOGICAL UNIT NOT READY");
    assert_eq!(work[13], 0x04, "ASCQ = FORMAT IN PROGRESS");
    assert_eq!(work[15] & 0x80, 0x80, "SKSV set");
    assert_eq!(
        u16::from_be_bytes([work[16], work[17]]),
        0,
        "progress starts at 0%"
    );

    assert!(storage.inner().writes.is_empty());
    assert!(storage.inner().reads.is_empty());

    // Advance the resident operation; the drive issues one bounded IO per step.
    let mut entries = 0;
    loop {
        let info = target
            .poll_long_entry_static::<Here>(&mut storage, &mut work, &mut scratch)
            .expect("poll_long");
        entries += 1;
        assert!(entries < 16, "long operation did not settle");
        if info.phase == LongPhase::Settled {
            assert!(info.write_accessible);
            assert_eq!(info.progress, Some(100));
            break;
        }
        assert_eq!(info.phase, LongPhase::Foreground);
    }
    assert_eq!(
        storage.inner().writes,
        vec![(0, 4096), (4096, 4096)],
        "the whole 4-sector medium is zero-filled once, in order"
    );
    assert_eq!(
        storage.inner().syncs,
        1,
        "the drive establishes durability with exactly one final Sync"
    );
    assert!(storage.inner().zeroed(8192));

    // After Settled the medium is writable and READ/WRITE are allowed.
    let mut host = BlockingHost::new(TestHost::new());
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
    assert_eq!(
        target.drive_static_host::<Here>(
            &mut storage,
            &mut host,
            ctx(Direction::ToHost, 2048),
            &read10(0, 1),
            &mut work,
            &mut scratch,
        ),
        Ok(Completion::Good)
    );
    assert_eq!(
        target.drive_static_host::<Here>(
            &mut storage,
            &mut host,
            ctx(Direction::FromHost, 2048),
            &write10(0, 1),
            &mut work,
            &mut scratch,
        ),
        Ok(Completion::Good)
    );
    assert_eq!(storage.inner().reads, vec![(0, 2048)]);
    assert_eq!(
        storage.inner().writes,
        vec![(0, 4096), (4096, 4096), (0, 2048)]
    );
    assert!(storage.inner().mem[..2048].iter().all(|b| *b == 0xA5));

    // The query set keeps working after the format settled.
    let mut inquiry = [0u8; 6];
    inquiry[0] = 0x12;
    inquiry[4] = 0xFF;
    let mut report_luns = [0u8; 10];
    report_luns[0] = 0xA0;
    report_luns[6..10].copy_from_slice(&8u32.to_be_bytes());
    assert_eq!(
        target.drive_static_host::<Here>(
            &mut storage,
            &mut host,
            ctx(Direction::ToHost, 96),
            &inquiry,
            &mut work,
            &mut scratch,
        ),
        Ok(Completion::Good)
    );
    assert_eq!(work[0], 0x05, "MMC inquiry PDT is CD-ROM");
    assert_eq!(
        target.drive_static_host::<Here>(
            &mut storage,
            &mut host,
            ctx(Direction::ToHost, 8),
            &report_luns,
            &mut work,
            &mut scratch,
        ),
        Ok(Completion::Good)
    );
    assert_eq!(
        target.drive_static_host::<Here>(
            &mut storage,
            &mut host,
            ctx(Direction::ToHost, 64),
            &get_configuration(0, 64),
            &mut work,
            &mut scratch,
        ),
        Ok(Completion::Good)
    );
    assert_eq!(
        target.drive_static_host::<Here>(
            &mut storage,
            &mut host,
            ctx(Direction::ToHost, 8),
            &gesn(0x10, true, 8),
            &mut work,
            &mut scratch,
        ),
        Ok(Completion::Good)
    );
}

/// FORMAT IMMED=0 (parameter list and the byte-1 default encoding) drives the
/// zero-fill inside `poll` and completes only after the whole medium is zeroed.
#[test]
fn mmc_format_immed_zero_zero_fills_in_poll() {
    let mut target = dvd_target(4);
    let mut storage = BlockingStorage::new(Plane::new(16 * 1024));
    let mut host = BlockingHost::new(ParamHost::new(format_params(0x80, 0)));
    let mut work = vec![0u8; 4096];
    let mut scratch = vec![0u8; 64];
    assert_eq!(
        target.drive_static_host::<Here>(
            &mut storage,
            &mut host,
            ctx(Direction::FromHost, 12),
            &[0x04, 0x11, 0, 0, 0, 0],
            &mut work,
            &mut scratch,
        ),
        Ok(Completion::Good)
    );
    assert_eq!(storage.inner().writes, vec![(0, 4096), (4096, 4096)]);
    assert_eq!(storage.inner().write_zero, vec![true, true]);
    assert_eq!(storage.inner().syncs, 1, "one final durability sync");
    assert!(storage.inner().zeroed(8192));
    assert_eq!(slot0(&target).long_info().phase, LongPhase::Settled);

    // The byte-1 default encoding has no parameter list and also completes in
    // the command.
    let mut target = dvd_target(2);
    let mut storage = BlockingStorage::new(Plane::new(8 * 1024));
    assert_eq!(
        target.drive_static::<Here>(
            &mut storage,
            ctx(Direction::None, 0),
            &[0x04, 0, 0, 0, 0, 0],
            &mut work,
            &mut scratch,
        ),
        Ok(Completion::Good)
    );
    assert_eq!(storage.inner().writes, vec![(0, 4096)]);
    assert_eq!(storage.inner().write_zero, vec![true]);
    assert_eq!(storage.inner().syncs, 1, "one final durability sync");
    assert!(storage.inner().zeroed(4096));
    assert_eq!(slot0(&target).long_info().phase, LongPhase::Settled);
}

/// A zero-sector writable medium arms an already-settled fill. Both FORMAT
/// encodings must still complete GOOD and clear the command query; a
/// mid-command `Idle` here used to be mapped to Busy by the runner and wedged
/// the LU. Regression for the reported defect.
#[test]
fn mmc_format_zero_sector_medium_does_not_wedge() {
    let mut work = vec![0u8; 64];
    let mut scratch = vec![0u8; 64];

    let mut target = dvd_target(0);
    let mut storage = BlockingStorage::new(Plane::new(0));
    let mut host = BlockingHost::new(ParamHost::new(format_params(0x80, 0)));
    assert_eq!(
        target.drive_static_host::<Here>(
            &mut storage,
            &mut host,
            ctx(Direction::FromHost, 12),
            &[0x04, 0x11, 0, 0, 0, 0],
            &mut work,
            &mut scratch,
        ),
        Ok(Completion::Good)
    );
    assert!(storage.inner().writes.is_empty());
    assert_eq!(slot0(&target).long_info().phase, LongPhase::Settled);
    // The slot is still serviceable: TUR reaches the drive and returns the
    // fixed no-medium sense (log offset 9: zero sectors means no media), not a
    // wedged command.
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

    let mut target = dvd_target(0);
    assert_eq!(
        target.drive_static::<Here>(
            &mut storage,
            ctx(Direction::None, 0),
            &[0x04, 0, 0, 0, 0, 0],
            &mut work,
            &mut scratch,
        ),
        Ok(Completion::Good)
    );
    assert_eq!(slot0(&target).long_info().phase, LongPhase::Settled);
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

/// Malformed lists, Try-out and read-only media never touch the backing.
#[test]
fn mmc_format_rejects_malformed_lists_tryout_and_read_only() {
    let mut work = vec![0u8; 4096];
    let mut scratch = vec![0u8; 64];
    let cdb = [0x04u8, 0x11, 0, 0, 0, 0];

    // Format Type != 0 => 05/26/00.
    let mut target = dvd_target(4);
    let mut storage = BlockingStorage::new(Plane::new(16 * 1024));
    let mut params = format_params(0x82, 2048);
    params[8] = 0x01;
    let mut host = BlockingHost::new(ParamHost::new(params));
    assert_eq!(
        target.drive_static_host::<Here>(
            &mut storage,
            &mut host,
            ctx(Direction::FromHost, 12),
            &cdb,
            &mut work,
            &mut scratch,
        ),
        Ok(Completion::Check(Sense::new(0x05, 0x26, 0x00)))
    );
    assert!(storage.inner().writes.is_empty());
    assert_eq!(slot0(&target).long_info().phase, LongPhase::Idle);

    // Try-out (FOV | Try-out) validates and returns GOOD with no IO and no
    // observable long-operation state.
    let mut target = dvd_target(4);
    let mut storage = BlockingStorage::new(Plane::new(16 * 1024));
    let mut host = BlockingHost::new(ParamHost::new(format_params(0x84, 2048)));
    assert_eq!(
        target.drive_static_host::<Here>(
            &mut storage,
            &mut host,
            ctx(Direction::FromHost, 12),
            &cdb,
            &mut work,
            &mut scratch,
        ),
        Ok(Completion::Good)
    );
    assert!(storage.inner().writes.is_empty());
    assert_eq!(slot0(&target).long_info().phase, LongPhase::Idle);

    // Read-only media reject FORMAT before any IO.
    let mut target = mmc_flat_target(8);
    let mut storage = BlockingStorage::new(Plane::new(32 * 1024));
    assert_eq!(
        target.drive_static::<Here>(
            &mut storage,
            ctx(Direction::None, 0),
            &[0x04, 0, 0, 0, 0, 0],
            &mut work,
            &mut scratch,
        ),
        Ok(Completion::Check(WRITE_PROTECTED))
    );
    assert!(storage.inner().writes.is_empty());
}

/// BLANK type 0 zero-fills writable media; read-only media and other blanking
/// types are rejected before any IO.
#[test]
fn mmc_blank_zero_fills_only_writable_media() {
    let mut work = vec![0u8; 4096];
    let mut scratch = vec![0u8; 64];
    let blank = [0xA1u8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0];

    let mut target = dvd_target(2);
    let mut storage = BlockingStorage::new(Plane::new(8 * 1024));
    assert_eq!(
        target.drive_static::<Here>(
            &mut storage,
            ctx(Direction::None, 0),
            &blank,
            &mut work,
            &mut scratch,
        ),
        Ok(Completion::Good)
    );
    assert_eq!(storage.inner().writes, vec![(0, 4096)]);
    assert_eq!(storage.inner().write_zero, vec![true]);
    assert_eq!(storage.inner().syncs, 1, "one final durability sync");
    assert!(storage.inner().zeroed(4096));
    assert_eq!(slot0(&target).long_info().phase, LongPhase::Settled);

    let mut target = mmc_flat_target(2);
    let mut storage = BlockingStorage::new(Plane::new(8 * 1024));
    assert_eq!(
        target.drive_static::<Here>(
            &mut storage,
            ctx(Direction::None, 0),
            &blank,
            &mut work,
            &mut scratch,
        ),
        Ok(Completion::Check(WRITE_PROTECTED))
    );
    assert!(storage.inner().writes.is_empty());

    let mut blank_type_1 = blank;
    blank_type_1[1] = 0x01;
    let mut target = dvd_target(2);
    let mut storage = BlockingStorage::new(Plane::new(8 * 1024));
    assert_eq!(
        target.drive_static::<Here>(
            &mut storage,
            ctx(Direction::None, 0),
            &blank_type_1,
            &mut work,
            &mut scratch,
        ),
        Ok(Completion::Check(INVALID_FIELD))
    );
    assert!(storage.inner().writes.is_empty());
}

/// DVD-RAM write-then-read goes through the same `StorageOp` plane at
/// `lba * 2048` in both directions.
#[test]
fn mmc_dvdram_read_write_round_trip() {
    let mut target = dvd_target(8);
    let mut storage = BlockingStorage::new(Plane::new(32 * 1024));
    let mut host = BlockingHost::new(TestHost::new());
    let mut work = vec![0u8; 4096];
    let mut scratch = vec![0u8; 64];

    assert_eq!(
        target.drive_static_host::<Here>(
            &mut storage,
            &mut host,
            ctx(Direction::FromHost, 2048),
            &write10(2, 1),
            &mut work,
            &mut scratch,
        ),
        Ok(Completion::Good)
    );
    assert_eq!(storage.inner().writes, vec![(4096, 2048)]);
    assert!(storage.inner().mem[4096..6144].iter().all(|b| *b == 0xA5));

    assert_eq!(
        target.drive_static_host::<Here>(
            &mut storage,
            &mut host,
            ctx(Direction::ToHost, 2048),
            &read10(2, 1),
            &mut work,
            &mut scratch,
        ),
        Ok(Completion::Good)
    );
    assert_eq!(storage.inner().reads, vec![(4096, 2048)]);
    assert_eq!(
        host.inner().events,
        vec![
            HostEvent::Publish(DataPlan {
                direction: Direction::FromHost,
                bytes: 2048,
            }),
            HostEvent::Publish(DataPlan {
                direction: Direction::ToHost,
                bytes: 2048,
            }),
            HostEvent::Sent(2048),
        ]
    );
}

/// A new medium is a new `MmcMedium` impl: INQUIRY/READ CAPACITY/READ work
/// through the shared `Spc` path without any device-kind branch.
#[test]
fn mmc_vendor_medium_uses_the_shared_spc_path() {
    let mut target = vendor_target(4);
    let mut storage = BlockingStorage::new(Plane::new(16 * 1024));
    let mut host = BlockingHost::new(TestHost::new());
    let mut work = vec![0u8; 4096];
    let mut scratch = vec![0u8; 64];

    let mut inquiry = [0u8; 6];
    inquiry[0] = 0x12;
    inquiry[4] = 0xFF;
    assert_eq!(
        target.drive_static_host::<Here>(
            &mut storage,
            &mut host,
            ctx(Direction::ToHost, 96),
            &inquiry,
            &mut work,
            &mut scratch,
        ),
        Ok(Completion::Good)
    );
    assert_eq!(work[0], 0x05);

    assert_eq!(
        target.drive_static_host::<Here>(
            &mut storage,
            &mut host,
            ctx(Direction::ToHost, 8),
            &read_capacity_10(0, false),
            &mut work,
            &mut scratch,
        ),
        Ok(Completion::Good)
    );
    assert_eq!(&work[0..4], &3u32.to_be_bytes());
    assert_eq!(&work[4..8], &2048u32.to_be_bytes());

    assert_eq!(
        target.drive_static_host::<Here>(
            &mut storage,
            &mut host,
            ctx(Direction::ToHost, 2048),
            &read10(0, 1),
            &mut work,
            &mut scratch,
        ),
        Ok(Completion::Good)
    );
    assert_eq!(storage.inner().reads, vec![(0, 2048)]);

    assert_eq!(
        target.drive_static_host::<Here>(
            &mut storage,
            &mut host,
            ctx(Direction::FromHost, 2048),
            &write10(0, 1),
            &mut work,
            &mut scratch,
        ),
        Ok(Completion::Check(WRITE_PROTECTED))
    );
}

/// MODE SENSE page 0x2A follows the medium facts: the read-only CD page or the
/// DVD-RAM recorder page, both fixed at 64 bytes so 0x3F is unchanged.
#[test]
fn mmc_mode_sense_2a_variants() {
    let mut flat = mmc_flat_target(8);
    let mut dvd = dvd_target(8);
    let mut storage = BlockingStorage::new(NoIo);
    let mut host = BlockingHost::new(TestHost::new());
    let mut work = [0u8; 80];
    let mut scratch = [0u8; 80];

    assert_eq!(
        flat.drive_static_host::<Here>(
            &mut storage,
            &mut host,
            ctx(Direction::ToHost, 68),
            &mode_sense_6(0x2A, 0, 68),
            &mut work,
            &mut scratch,
        ),
        Ok(Completion::Good)
    );
    let cd_page = work[4..68].to_vec();
    assert_eq!(&cd_page[..2], &[0x2A, 0x3E]);

    assert_eq!(
        dvd.drive_static_host::<Here>(
            &mut storage,
            &mut host,
            ctx(Direction::ToHost, 68),
            &mode_sense_6(0x2A, 0, 68),
            &mut work,
            &mut scratch,
        ),
        Ok(Completion::Good)
    );
    let ram_page = work[4..40].to_vec();
    assert_eq!(&ram_page[..2], &[0x2A, 0x22]);
    assert_ne!(cd_page, ram_page);
    assert_eq!(cd_page.len(), 64);
    assert_eq!(ram_page.len(), 36);

    // 0x3F stays the same total for both variants.
    let profile = slot0(&flat)
        .device_ref()
        .inner()
        .spc_profile()
        .expect("profile");
    assert_eq!(profile.mode_sense(false, 0x3F, false, 0, None), Some(198));
    let profile = slot0(&dvd)
        .device_ref()
        .inner()
        .spc_profile()
        .expect("profile");
    assert_eq!(profile.mode_sense(false, 0x3F, false, 0, None), Some(170));
}

/// Live ISO data is just a byte capacity: `FlatCdMedium::new` floors it to
/// sectors, READ CD Data2048 works and Audio2352 is rejected as 05/24/00.
#[test]
fn mmc_live_capacity_flat_medium_read_cd() {
    use snowscsi::cdrom::media::LiveData;
    use snowscsi::common::seekable_storage::FlatData;
    use snowscsi::scsi::fs_backend::StdFsBackend;

    let dir = std::env::temp_dir().join(format!("snowscsi_core_p2b_live_{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).expect("temp dir");
    std::fs::write(dir.join("HELLO.TXT"), b"core p2b live fixture").expect("write file");
    let live = LiveData::new(StdFsBackend::new(&dir.to_string_lossy()), "LIVE").expect("live");
    let capacity = live.capacity();
    assert!(capacity >= 2048);
    assert_eq!(FlatCdMedium::new(capacity).attrs().sectors, capacity / 2048);
    // Floor, never round up, for a trailing partial sector.
    assert_eq!(
        FlatCdMedium::new(capacity + 100).attrs().sectors,
        (capacity + 100) / 2048
    );

    let mut target = Target::new(cons(
        LuImpl::new(Spc::new(MmcDrive::new(FlatCdMedium::new(capacity))), 1u8),
        Nil,
    ));
    let mut storage = BlockingStorage::new(Plane::new(capacity as usize));
    let mut host = BlockingHost::new(TestHost::new());
    let mut work = vec![0u8; 4096];
    let mut scratch = vec![0u8; 64];

    let mut read_cd = [0u8; 12];
    read_cd[0] = 0xBE;
    read_cd[1] = 0x00; // Expected Sector Type = All
    read_cd[8] = 1; // one block
    read_cd[9] = 0x10; // Main Channel Selection: user data
    assert_eq!(
        target.drive_static_host::<Here>(
            &mut storage,
            &mut host,
            ctx(Direction::ToHost, 2048),
            &read_cd,
            &mut work,
            &mut scratch,
        ),
        Ok(Completion::Good)
    );
    assert_eq!(storage.inner().reads, vec![(0, 2048)]);

    read_cd[1] = 0x04; // Expected Sector Type = CD-DA
    read_cd[9] = 0x10; // user data selection
    let before = storage.inner().reads.len();
    assert_eq!(
        target.drive_static_host::<Here>(
            &mut storage,
            &mut host,
            ctx(Direction::ToHost, 2352),
            &read_cd,
            &mut work,
            &mut scratch,
        ),
        Ok(Completion::Check(INVALID_FIELD))
    );
    assert_eq!(
        storage.inner().reads.len(),
        before,
        "audio must issue no IO"
    );

    let _ = std::fs::remove_dir_all(&dir);
}

/// MODE SENSE(10) LLBAA is not supported and must CHECK, not be read as DBD.
#[test]
fn mode_sense_10_llbaa_is_rejected() {
    let mut target = block_target();
    let mut storage = BlockingStorage::new(NoIo);
    let mut host = BlockingHost::new(TestHost::new());
    let mut work = [0u8; 64];
    let mut scratch = [0u8; 64];
    let mut cdb = mode_sense_10(0x3F, false, 64);
    cdb[1] = 0x10; // LLBAA
    assert_eq!(
        target.drive_static_host::<Here>(
            &mut storage,
            &mut host,
            ctx(Direction::ToHost, 64),
            &cdb,
            &mut work,
            &mut scratch,
        ),
        Ok(Completion::Check(INVALID_FIELD))
    );
}

/// DVD-RAM READ DISC INFORMATION reports the random-media finalized status
/// and the erasable bit, not the sequential-media "incomplete" code.
#[test]
fn mmc_dvdram_read_disc_information_is_finalized() {
    let mut target = dvd_target(4);
    let mut storage = BlockingStorage::new(Plane::new(16 * 1024));
    let mut host = BlockingHost::new(TestHost::new());
    let mut work = vec![0u8; 64];
    let mut scratch = vec![0u8; 64];
    let cdb = [0x51u8, 0, 0, 0, 0, 0, 0, 0, 34, 0];
    assert_eq!(
        target.drive_static_host::<Here>(
            &mut storage,
            &mut host,
            ctx(Direction::ToHost, 34),
            &cdb,
            &mut work,
            &mut scratch,
        ),
        Ok(Completion::Good)
    );
    assert_eq!(&work[0..2], &32u16.to_be_bytes());
    // erasable = 1, state of last session = 3 (complete), status = 2 (finalized)
    assert_eq!(work[2], 0x4E);
    assert_eq!(work[3], 1);
    assert_eq!(work[4], 1);
    assert_eq!(&work[20..24], &4u32.to_be_bytes());
}
