//! Acceptance fixtures: removal locks, host/operator eject, the
//! unlock-flush contract and the management transaction
//! (`propose`/`advance`/`take`/`install`/`force`).
//!
//! These are isolated fixtures (mock storage, no real platform): the
//! normal/persistent latches live in `Spc`, the `LuInfo` projection is read
//! through `Target::snapshot_rt`, and clearing the normal latch must issue a
//! `StorageOp::Sync` whose known success is the only thing that clears it.
//! The management fixtures drive the public `Target`/`StaticTarget` entries
//! over real `BlockingStorage`/`BlockingHost` adapters and assert the
//! ownership rules of `__ARCH__/design/02-api-core.md` §4.10/§4.11 and
//! `03-lifecycles.md` §3.6.

use snowscsi::block::{BlockAttrs, BlockDevice};
use snowscsi::core::storage::{
    BlockingHost, BlockingStorage, HostBuf, HostReceipt, HostReq, IoBuf, IoReq, StorageReceipt,
    SyncHost, SyncStorage,
};
use snowscsi::core::{
    cons, decide_eject, At, BoundaryPermit, BoundaryReject, Change, CommandContext, CommandPermit,
    Completion, Cons, DataPlan, Delivery, Device, Direction, Effect, EjectOrigin, Fault, Feedback,
    Here, InterruptReason, KnownEffects, LongInfo, LongPhase, Lu, LuImpl, Nil, NoMedium, Pair,
    PollStep, RemovalLocks, RunEnd, RunOutcome, SlotSet, Spc, StaticTarget, Target,
    INTERNAL_FAILURE, MEDIUM_NOT_PRESENT, MEDIUM_REMOVAL_PREVENTED, WRITE_ERROR,
};
use snowscsi::mmc::{DvdRamMedium, FlatCdMedium, MmcDrive};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Op {
    Sync,
}

/// Recording sync plane: PREVENT/ALLOW only issues Sync in this slice.
struct Plane {
    ops: Vec<Op>,
}

impl Plane {
    fn new() -> Self {
        Self { ops: Vec::new() }
    }
}

impl SyncStorage for Plane {
    fn exec(&mut self, req: IoReq, buf: IoBuf<'_>) -> StorageReceipt {
        match (req.dir, buf) {
            (Direction::None, IoBuf::None) => {
                self.ops.push(Op::Sync);
                StorageReceipt::ok(0)
            }
            _ => StorageReceipt::failed(Fault::Contract, 0, Effect::Known),
        }
    }
}

/// A storage adapter whose Sync always fails; the lock must survive.
struct FailSync;

impl SyncStorage for FailSync {
    fn exec(&mut self, _req: IoReq, _buf: IoBuf<'_>) -> StorageReceipt {
        StorageReceipt::failed(Fault::Io, 0, Effect::Known)
    }
}

type BlockTarget = Target<Cons<LuImpl<Spc<BlockDevice>, u8>, Nil>>;
type MmcTarget = Target<Cons<LuImpl<Spc<MmcDrive<FlatCdMedium>>, u8>, Nil>>;
type DvdTarget = Target<Cons<LuImpl<Spc<MmcDrive<DvdRamMedium>>, u8>, Nil>>;

fn block_target() -> BlockTarget {
    block_target_with(1)
}

fn block_target_with(backing: u8) -> BlockTarget {
    Target::new(cons(
        LuImpl::new(
            Spc::new(BlockDevice::new(BlockAttrs::new(16, 512))),
            backing,
        ),
        Nil,
    ))
}

fn dvd_target() -> DvdTarget {
    Target::new(cons(
        LuImpl::new(Spc::new(MmcDrive::new(DvdRamMedium::new(16))), 1u8),
        Nil,
    ))
}

/// Pair identity for the block profile (`Medium = NoMedium`).
fn pair_none(backing: u8) -> Pair<NoMedium, u8> {
    Pair {
        medium: NoMedium,
        backing,
    }
}

/// First static slot (type-level `Here`), for identity probes only.
fn slot0<S>(target: &Target<S>) -> &<S as At<Here>>::Slot
where
    S: SlotSet + At<Here>,
{
    <S as At<Here>>::slot(target.slots())
}

/// TEST UNIT READY through the public static entry (no host data phase).
fn tur<S>(target: &mut Target<S>, work: &mut [u8], scratch: &mut [u8]) -> Completion
where
    S: SlotSet + At<Here>,
    <S as At<Here>>::Slot: Lu,
{
    let mut storage = BlockingStorage::new(Plane::new());
    target
        .drive_static::<Here>(&mut storage, ctx(), &[0x00, 0, 0, 0, 0, 0], work, scratch)
        .expect("no fault")
}

/// Host seam for the entries that only need a transport value (force).
struct QuietHost;

impl SyncHost for QuietHost {
    fn publish(&mut self, plan: DataPlan) -> Result<(), Fault> {
        if plan.direction == Direction::None && plan.bytes == 0 {
            Ok(())
        } else {
            Err(Fault::Contract)
        }
    }

    fn receive(&mut self, _req: HostReq, _buf: HostBuf<'_>) -> HostReceipt {
        HostReceipt::from_adapter(0, Some(Fault::Contract))
    }

    fn send(&mut self, _req: HostReq, _buf: HostBuf<'_>) -> HostReceipt {
        HostReceipt::from_adapter(0, Some(Fault::Contract))
    }

    fn delivery(&self) -> Delivery {
        Delivery::NotApplicable
    }
}

fn mmc_target() -> MmcTarget {
    Target::new(cons(
        LuImpl::new(Spc::new(MmcDrive::new(FlatCdMedium::read_only(16))), 1u8),
        Nil,
    ))
}

fn prevent_cdb(value: u8) -> [u8; 6] {
    [0x1E, 0, 0, 0, value, 0]
}

fn ctx() -> CommandContext {
    CommandContext {
        lun: 0,
        lun_count: 1,
        host_bytes: 0,
        host_direction: Direction::None,
    }
}

fn prevent<S, B>(
    target: &mut Target<S>,
    storage: &mut BlockingStorage<B>,
    work: &mut [u8],
    scratch: &mut [u8],
    value: u8,
) -> Completion
where
    S: snowscsi::core::SlotSet + At<Here>,
    <S as At<Here>>::Slot: Lu,
    B: SyncStorage,
{
    target
        .drive_static::<Here>(storage, ctx(), &prevent_cdb(value), work, scratch)
        .expect("no fault")
}

#[test]
fn mmc_lock_projection_and_host_eject_keeps_persistent() {
    let mut target = mmc_target();
    let mut storage = BlockingStorage::new(Plane::new());
    let mut work = [0u8; 128];
    let mut scratch = [0u8; 64];

    assert_eq!(
        prevent(&mut target, &mut storage, &mut work, &mut scratch, 0b01),
        Completion::Good
    );
    let info = target.snapshot_static::<Here>();
    assert!(info.prevent);
    assert!(!info.persistent_prevent);
    assert!(info.is_locked());

    // MMC bit1 selects persistent, bit0 selects set.
    assert_eq!(
        prevent(&mut target, &mut storage, &mut work, &mut scratch, 0b11),
        Completion::Good
    );
    let info = target.snapshot_static::<Here>();
    assert!(info.prevent);
    assert!(info.persistent_prevent);

    // Host eject clears the normal latch and detaches the pair; the persistent
    // latch survives and the slot is no longer ready.
    target
        .host_eject_succeeded_static::<Here>()
        .expect("host eject");
    let info = target.snapshot_static::<Here>();
    assert!(!info.prevent);
    assert!(info.persistent_prevent);
    assert!(info.is_locked());
    assert!(!info.ready);
}

#[test]
fn operator_eject_refuses_either_lock() {
    let none = RemovalLocks {
        prevent: false,
        persistent_prevent: false,
    };
    let normal = RemovalLocks {
        prevent: true,
        persistent_prevent: false,
    };
    let persistent = RemovalLocks {
        prevent: false,
        persistent_prevent: true,
    };
    let both = RemovalLocks {
        prevent: true,
        persistent_prevent: true,
    };

    assert!(decide_eject(none, EjectOrigin::Operator).allowed);
    for locks in [normal, persistent, both] {
        let decision = decide_eject(locks, EjectOrigin::Operator);
        assert!(!decision.allowed);
        assert_eq!(
            decision.completion,
            Completion::Check(MEDIUM_REMOVAL_PREVENTED)
        );
        assert!(!decision.clear_normal_prevent);
    }

    // The host's own eject is never blocked; it clears normal, not persistent.
    let decision = decide_eject(both, EjectOrigin::HostCommand);
    assert!(decision.allowed);
    assert!(decision.clear_normal_prevent);
}

#[test]
fn unlock_flush_clears_the_normal_latch_after_known_sync() {
    let mut target = block_target();
    let mut storage = BlockingStorage::new(Plane::new());
    let mut work = [0u8; 128];
    let mut scratch = [0u8; 64];

    assert_eq!(
        prevent(&mut target, &mut storage, &mut work, &mut scratch, 0b01),
        Completion::Good
    );
    assert!(target.snapshot_static::<Here>().prevent);

    assert_eq!(
        prevent(&mut target, &mut storage, &mut work, &mut scratch, 0b00),
        Completion::Good
    );
    assert!(storage.inner().ops.contains(&Op::Sync));
    assert!(!target.snapshot_static::<Here>().prevent);
}

#[test]
fn unlock_flush_failure_keeps_the_normal_latch() {
    let mut target = block_target();
    let mut storage = BlockingStorage::new(Plane::new());
    let mut work = [0u8; 128];
    let mut scratch = [0u8; 64];

    assert_eq!(
        prevent(&mut target, &mut storage, &mut work, &mut scratch, 0b01),
        Completion::Good
    );

    let mut failing = BlockingStorage::new(FailSync);
    assert_eq!(
        prevent(&mut target, &mut failing, &mut work, &mut scratch, 0b00),
        Completion::Check(WRITE_ERROR)
    );
    assert!(target.snapshot_static::<Here>().prevent);
}

// ── Management transactions ────────────────────────────────────────────────
// `03 §3.6` state machine, `02-api-core §4.10` sequencing and the `§4.11`
// gates. Every entry below is the public `Target`/`StaticTarget` one; the
// pair's `u8` is its backing identity (G6 keeps the adapter application-side).

/// Install into an empty slot. The candidate becomes current and the
/// transaction produces **no** result, so `take` is `NothingToTake`.
#[test]
fn install_into_an_empty_slot_becomes_current_without_a_result() {
    let mut target = block_target_with(1);
    let mut work = [0u8; 128];
    let mut scratch = [0u8; 64];

    // Reach the empty state through the real host-eject transaction, then
    // claim the detached pair exactly once.
    target
        .host_eject_succeeded_static::<Here>()
        .expect("host eject");
    assert!(!target.snapshot_static::<Here>().ready);
    let ejected = target.take_static_at::<Here>(0).expect("ejected pair");
    assert_eq!(ejected.pair, Some(pair_none(1)));
    assert_eq!(ejected.delivery, Delivery::Pending);
    assert_eq!(
        target.take_static_at::<Here>(0),
        Err(BoundaryReject::NothingToTake)
    );
    // An empty slot refuses media commands; only the query set stays answerable.
    assert_eq!(
        tur(&mut target, &mut work, &mut scratch),
        Completion::Check(MEDIUM_NOT_PRESENT)
    );

    assert_eq!(
        target.propose_static::<Here>(Change::Install(pair_none(4))),
        Ok(())
    );
    assert_eq!(target.advance_static::<Here>(), Ok(()));
    assert_eq!(
        slot0(&target).backing_ref(),
        Some(&4),
        "candidate is current"
    );
    let info = target.snapshot_static::<Here>();
    assert!(info.ready);
    assert!(info.boundary);
    // Install has no old pair, so there is no result to hand back: both the
    // first and any later take are `NothingToTake` (§4.10 "Install: no old").
    assert_eq!(
        target.take_static_at::<Here>(0),
        Err(BoundaryReject::NothingToTake)
    );
    assert_eq!(
        target.take_static_at::<Here>(0),
        Err(BoundaryReject::NothingToTake)
    );
    assert_eq!(tur(&mut target, &mut work, &mut scratch), Completion::Good);
}

/// Replace commits, installs the candidate and returns the old pair once
/// with the documented (`NONE`) effects.
#[test]
fn replace_commits_installs_and_hands_the_old_pair_back_once() {
    let mut target = block_target_with(7);

    assert_eq!(
        target.propose_static::<Here>(Change::Replace(pair_none(9))),
        Ok(())
    );
    // `propose` saves the candidate and does not touch the current pair.
    assert!(slot0(&target).has_candidate());
    assert_eq!(slot0(&target).backing_ref(), Some(&7));

    assert_eq!(target.advance_static::<Here>(), Ok(()));
    assert!(!slot0(&target).has_candidate());
    assert_eq!(
        slot0(&target).backing_ref(),
        Some(&9),
        "new pair is current"
    );
    // `advance_static` takes no storage adapter at all, so it cannot inject a
    // runner `Sync` (§4.10). The observable fact is the reported effect set
    // (asserted below); the local-commit hook count is pinned directly by the
    // scripted-device fixtures further down.

    let result = target.take_static_at::<Here>(0).expect("old pair");
    assert_eq!(result.pair, Some(pair_none(7)), "exactly the old pair");
    assert_eq!(result.local, Ok(()));
    assert_eq!(result.delivery, Delivery::NotApplicable);
    // The local commit is metadata-only, so no effect and no durability is
    // claimed (`local = Ok(())` does not mean `sync_durable`).
    assert_eq!(result.effects, KnownEffects::NONE);
    assert!(!result.effects.sync_durable);
    assert_eq!(
        target.take_static_at::<Here>(0),
        Err(BoundaryReject::NothingToTake),
        "a second take is not the next candidate"
    );
    assert!(target.snapshot_static::<Here>().ready);
}

/// Remove empties the slot; installing the returned pair restores service
/// (`empty reentry`).
#[test]
fn remove_empties_the_slot_and_the_returned_pair_restores_service() {
    let mut target = block_target_with(3);
    let mut work = [0u8; 128];
    let mut scratch = [0u8; 64];

    assert_eq!(target.propose_static::<Here>(Change::Remove), Ok(()));
    assert_eq!(target.advance_static::<Here>(), Ok(()));
    let info = target.snapshot_static::<Here>();
    assert!(!info.ready, "a removed pair leaves an empty slot");
    assert_eq!(slot0(&target).backing_ref(), None);
    assert_eq!(
        tur(&mut target, &mut work, &mut scratch),
        Completion::Check(MEDIUM_NOT_PRESENT)
    );

    let result = target.take_static_at::<Here>(0).expect("removed pair");
    assert_eq!(result.pair, Some(pair_none(3)));
    assert_eq!(result.local, Ok(()));
    assert_eq!(result.effects, KnownEffects::NONE);
    let old = result.pair.expect("removed pair");
    assert_eq!(
        target.take_static_at::<Here>(0),
        Err(BoundaryReject::NothingToTake)
    );

    // Empty reentry: the returned pair installs back and the slot serves again.
    assert_eq!(target.install_static::<Here>(old), Ok(()));
    assert!(target.snapshot_static::<Here>().ready);
    assert_eq!(slot0(&target).backing_ref(), Some(&3));
    assert_eq!(tur(&mut target, &mut work, &mut scratch), Completion::Good);
}

/// A competing proposal returns its own input; a proposal with a resident
/// result is refused until the application takes it.
#[test]
fn competing_and_late_proposals_are_refused_with_the_original_input() {
    let mut target = block_target_with(7);

    assert_eq!(
        target.propose_static::<Here>(Change::Replace(pair_none(9))),
        Ok(())
    );
    // A competing proposal is refused and returns its own input unchanged; the
    // resident candidate is never overwritten (§4.10).
    match target.propose_static::<Here>(Change::Replace(pair_none(11))) {
        Err((returned, fault)) => {
            assert_eq!(fault, Fault::Contract);
            assert_eq!(returned, Change::Replace(pair_none(11)));
        }
        Ok(()) => panic!("a competing proposal must be refused"),
    }
    assert_eq!(target.advance_static::<Here>(), Ok(()));
    assert_eq!(
        slot0(&target).backing_ref(),
        Some(&9),
        "the first candidate wins"
    );

    // A result is resident: the take barrier must be cleared by `take` before
    // any new normal proposal (§3.6 AwaitTake row, §4.11 `service_gate`).
    match target.propose_static::<Here>(Change::Replace(pair_none(13))) {
        Err((returned, fault)) => {
            assert_eq!(fault, Fault::Boundary);
            assert_eq!(returned, Change::Replace(pair_none(13)));
        }
        Ok(()) => panic!("a proposal before take must be refused"),
    }
    let result = target.take_static_at::<Here>(0).expect("old pair");
    assert_eq!(result.pair, Some(pair_none(7)));

    // The take cleared the barrier, so the same proposal is accepted now.
    assert_eq!(
        target.propose_static::<Here>(Change::Replace(pair_none(13))),
        Ok(())
    );
}

/// §4.11: `take` before `advance` has no result; a prepared candidate is not a
/// result.
#[test]
fn take_before_advance_is_nothing_to_take() {
    let mut target = block_target_with(2);
    assert_eq!(
        target.take_static_at::<Here>(0),
        Err(BoundaryReject::NothingToTake)
    );
    assert_eq!(
        target.propose_static::<Here>(Change::Replace(pair_none(4))),
        Ok(())
    );
    assert_eq!(
        target.take_static_at::<Here>(0),
        Err(BoundaryReject::NothingToTake)
    );
}

/// §4.11 permission table: a foreground long operation refuses `take`
/// (`take_gate`) and `propose`/`advance`/`install` (`service_gate`).
#[test]
fn foreground_long_operation_blocks_take_and_management() {
    let mut target = dvd_target();
    let mut storage = BlockingStorage::new(Plane::new());
    let mut work = [0u8; 128];
    let mut scratch = [0u8; 64];

    // BLANK with IMMED (MMC-6 Table 229): the command completes GOOD while the
    // drive-owned zero-fill stays resident in the foreground phase (§3.7).
    assert_eq!(
        target.drive_static::<Here>(
            &mut storage,
            ctx(),
            &[0xA1, 0x20, 0, 0, 0, 0],
            &mut work,
            &mut scratch,
        ),
        Ok(Completion::Good)
    );
    let info = target.snapshot_static::<Here>();
    assert_eq!(info.long.phase, LongPhase::Foreground);
    assert!(
        info.ready,
        "the pair is installed; only the long op is live"
    );
    assert!(!info.boundary);

    // `take_gate = boundary && long_settled`.
    assert!(matches!(
        target.take_static_at::<Here>(0),
        Err(BoundaryReject::LongOperationActive)
    ));
    // `service_gate` refuses the transaction entries while the long op runs.
    assert!(matches!(
        target.propose_static::<Here>(Change::Remove),
        Err((Change::Remove, Fault::Boundary))
    ));
    assert!(matches!(
        target.install_static::<Here>(Pair {
            medium: DvdRamMedium::new(16),
            backing: 9,
        }),
        Err((_, Fault::Boundary))
    ));
    assert_eq!(target.advance_static::<Here>(), Err(Fault::Boundary));
}

/// §4.10 force row: no commit, no durability claim, the old pair leaves through
/// the one-shot result, and a force that arrives while a result is resident is
/// accepted and deferred.
///
/// This fixture takes the **empty-slot** continuation arm: the deferred force
/// finds nothing installed and produces no second handback. The arm that hands
/// a second (forced) pair back is
/// `force_defers_while_a_result_is_resident_and_hands_the_forced_pair_back_once`.
#[test]
fn force_removes_without_commit_and_defers_a_second_detach() {
    let mut target = block_target_with(5);
    let mut storage = BlockingStorage::new(Plane::new());
    let mut host = BlockingHost::new(QuietHost);

    assert_eq!(
        target.force_remove_static::<Here>(&mut storage, &mut host),
        Ok(())
    );
    // Force is an emergency eject, not a transaction: it injects no storage IO.
    // The stronger fact — the device's local `commit` hook is never called — is
    // pinned by the scripted-device fixture below (`commits` count).
    assert!(
        storage.inner().ops.is_empty(),
        "force must not inject storage IO"
    );
    assert!(!target.snapshot_static::<Here>().ready);
    assert_eq!(target.tick(), RunOutcome::ResourcesReady { lun: 0 });

    // A resident result is never silently overwritten: the second force is
    // accepted and deferred until the application takes (§4.10).
    assert_eq!(
        target.force_remove_static::<Here>(&mut storage, &mut host),
        Ok(())
    );
    assert!(storage.inner().ops.is_empty());

    let result = target.take_static_at::<Here>(0).expect("forced pair");
    assert_eq!(result.pair, Some(pair_none(5)));
    assert_eq!(result.local, Ok(()));
    assert_eq!(result.delivery, Delivery::NotApplicable);
    // Force did not commit, so it never claims durability.
    assert!(!result.effects.sync_durable);
    assert_eq!(
        target.take_static_at::<Here>(0),
        Err(BoundaryReject::NothingToTake)
    );

    // The slot was already empty when the deferred force ran, so it detached
    // nothing: no second result, no second `ResourcesReady`.
    assert_eq!(target.tick(), RunOutcome::ServiceReady);
    assert_eq!(
        target.force_remove_static::<Here>(&mut storage, &mut host),
        Ok(())
    );
    assert_eq!(
        target.take_static_at::<Here>(0),
        Err(BoundaryReject::NothingToTake)
    );
}

/// `LuInfo.ready` follows the pair, and `is_locked` keeps reflecting
/// the two independent latches across eject, take and install.
#[test]
fn lu_info_ready_and_the_latches_survive_eject_take_and_install() {
    let mut target = mmc_target();
    let mut storage = BlockingStorage::new(Plane::new());
    let mut work = [0u8; 128];
    let mut scratch = [0u8; 64];

    // Both latches (MMC-6 Table 329: bit1 selects persistent vs normal, bit0
    // selects clear vs set — so they are set by two separate commands).
    assert_eq!(
        prevent(&mut target, &mut storage, &mut work, &mut scratch, 0b01),
        Completion::Good
    );
    assert_eq!(
        prevent(&mut target, &mut storage, &mut work, &mut scratch, 0b11),
        Completion::Good
    );
    let info = target.snapshot_static::<Here>();
    assert!(info.ready);
    assert!(info.boundary);
    assert!(info.prevent && info.persistent_prevent);
    assert!(info.is_locked());

    // Host eject: empty slot, normal latch cleared, persistent kept.
    target
        .host_eject_succeeded_static::<Here>()
        .expect("host eject");
    let info = target.snapshot_static::<Here>();
    assert!(!info.ready);
    assert!(!info.prevent);
    assert!(info.persistent_prevent);
    assert!(info.is_locked(), "a persistent latch outlives the pair");

    let ejected = target.take_static_at::<Here>(0).expect("ejected pair");
    assert_eq!(ejected.pair.as_ref().map(|pair| pair.backing), Some(1));

    // A fresh pair installs into the empty slot: ready again, latches intact.
    assert!(matches!(
        target.install_static::<Here>(Pair {
            medium: FlatCdMedium::read_only(16),
            backing: 2,
        }),
        Ok(())
    ));
    let info = target.snapshot_static::<Here>();
    assert!(info.ready);
    assert!(!info.prevent);
    assert!(
        info.persistent_prevent,
        "a pair change never resets the persistent latch"
    );
    assert!(info.is_locked());
    assert_eq!(tur(&mut target, &mut work, &mut scratch), Completion::Good);

    // Clearing the persistent latch (bit1 clear) leaves the slot unlocked.
    assert_eq!(
        prevent(&mut target, &mut storage, &mut work, &mut scratch, 0b10),
        Completion::Good
    );
    let info = target.snapshot_static::<Here>();
    assert!(!info.prevent && !info.persistent_prevent);
    assert!(!info.is_locked());
}

/// §4.10/§4.11 through the *runtime* entries: `force_remove_rt` detaches into a
/// one-shot result and the result barrier blocks a new normal proposal until
/// the application takes it.
#[test]
fn runtime_force_remove_sets_the_result_barrier_until_take() {
    let mut slots = [LuImpl::new(
        Spc::new(BlockDevice::new(BlockAttrs::new(16, 512))),
        6u8,
    )];
    let table: [&mut dyn Lu<Pair = Pair<NoMedium, u8>>; 1] = [&mut slots[0]];
    let mut target = Target::new(table);
    let mut storage = BlockingStorage::new(Plane::new());
    let mut host = BlockingHost::new(QuietHost);

    assert_eq!(target.force_remove_rt(0, &mut storage, &mut host), Ok(()));
    assert!(
        storage.inner().ops.is_empty(),
        "force must not inject storage IO"
    );
    assert_eq!(target.tick(), RunOutcome::ResourcesReady { lun: 0 });
    assert!(!target.snapshot_rt(0).expect("slot").ready);
    assert!(matches!(
        target.propose_rt(0, Change::Remove),
        Err((Change::Remove, Fault::Boundary))
    ));

    let result = target.take_rt(0).expect("forced pair");
    assert_eq!(result.pair, Some(pair_none(6)));
    assert_eq!(result.local, Ok(()));
    assert!(!result.effects.sync_durable);
    assert_eq!(target.take_rt(0), Err(BoundaryReject::NothingToTake));
}

// ── Scripted device: the known-failure rows ────────────────────────────────
// The block/MMC profiles cannot fail `commit`/`install_medium` on demand, so
// the failure rows are driven through a test-local `Device` double. It is
// used only through `Target`/`LuImpl`; nothing here is public API. Every hook
// is counted so a fixture can observe the real transaction steps (commit called
// once, one detach, two installs, …) instead of inferring them.

/// Scripted `Device` double with a settable commit result, an install-failure
/// budget and a settable detach/settlement failure.
struct ScriptedDevice {
    medium: Option<NoMedium>,
    active: bool,
    commit_result: Result<(), Completion>,
    /// Number of upcoming `install_medium` calls that fail (medium returned).
    install_faults: u32,
    /// 1-based index of the first `take_medium` call that fails (detach); the
    /// counter is per device, `u32::MAX` never fails.
    take_medium_fails_at: u32,
    /// Settlement failure reported by `interrupt`.
    interrupt_fault: Option<Fault>,
    commits: u32,
    installs: u32,
    takes: u32,
}

impl ScriptedDevice {
    fn ready() -> Self {
        Self {
            medium: Some(NoMedium),
            active: false,
            commit_result: Ok(()),
            install_faults: 0,
            take_medium_fails_at: u32::MAX,
            interrupt_fault: None,
            commits: 0,
            installs: 0,
            takes: 0,
        }
    }

    fn with_commit_fault() -> Self {
        Self {
            commit_result: Err(Completion::Check(INTERNAL_FAILURE)),
            ..Self::ready()
        }
    }

    fn failing_installs(count: u32) -> Self {
        Self {
            install_faults: count,
            ..Self::ready()
        }
    }

    fn failing_take_medium_at(call: u32) -> Self {
        Self {
            take_medium_fails_at: call,
            ..Self::ready()
        }
    }

    fn with_interrupt_fault(fault: Fault) -> Self {
        Self {
            interrupt_fault: Some(fault),
            ..Self::ready()
        }
    }
}

impl Device for ScriptedDevice {
    type Medium = NoMedium;

    fn prepare(
        &mut self,
        _permit: &CommandPermit,
        _ctx: CommandContext,
        _cdb: &[u8],
    ) -> Result<(), Completion> {
        self.active = true;
        Ok(())
    }

    fn active(&self) -> bool {
        self.active
    }

    fn resume(&mut self, _permit: &CommandPermit) -> Result<(), Completion> {
        Ok(())
    }

    fn poll<'a>(
        &mut self,
        _permit: &CommandPermit,
        _feedback: Feedback,
        _data: &'a mut [u8],
    ) -> PollStep<'a> {
        PollStep::Idle
    }

    fn poll_long<'a>(
        &mut self,
        _permit: &CommandPermit,
        _feedback: Feedback,
        _data: &'a mut [u8],
    ) -> PollStep<'a> {
        PollStep::Idle
    }

    fn long_info(&self) -> LongInfo {
        LongInfo::IDLE
    }

    fn interrupt(
        &mut self,
        _permit: &CommandPermit,
        _reason: InterruptReason,
        _known: KnownEffects,
    ) -> Result<(), Fault> {
        self.active = false;
        match self.interrupt_fault {
            Some(fault) => Err(fault),
            None => Ok(()),
        }
    }

    fn finish_delivery(&mut self, _permit: &CommandPermit, _delivery: Delivery) {}

    fn commit(&mut self, _permit: &BoundaryPermit) -> Result<(), Completion> {
        self.commits = self.commits.saturating_add(1);
        self.commit_result
    }

    fn take_medium(&mut self, _permit: &BoundaryPermit) -> Option<NoMedium> {
        self.takes = self.takes.saturating_add(1);
        if self.takes >= self.take_medium_fails_at {
            return None;
        }
        self.medium.take()
    }

    fn install_medium(
        &mut self,
        _permit: &BoundaryPermit,
        medium: NoMedium,
    ) -> Result<(), (NoMedium, Fault)> {
        self.installs = self.installs.saturating_add(1);
        if self.install_faults > 0 {
            self.install_faults -= 1;
            // An install failure is a known failure but **not** a commit
            // failure, so the reported `local` fault must be this one.
            return Err((medium, Fault::Io));
        }
        self.medium = Some(medium);
        Ok(())
    }
}

type ScriptTarget = Target<Cons<LuImpl<ScriptedDevice, u8>, Nil>>;

fn script_target(device: ScriptedDevice, backing: u8) -> ScriptTarget {
    Target::new(cons(LuImpl::new(device, backing), Nil))
}

/// Known commit failure: the transaction stops before detach; the old
/// pair stays current, the candidate is handed back once with `local` naming
/// the real commit failure, and no result is invented for the slot.
#[test]
fn replace_commit_failure_keeps_the_old_pair_and_returns_the_candidate() {
    let mut target = script_target(ScriptedDevice::with_commit_fault(), 7);

    assert_eq!(
        target.propose_static::<Here>(Change::Replace(pair_none(9))),
        Ok(())
    );
    assert_eq!(target.advance_static::<Here>(), Err(Fault::Commit));

    let slot = slot0(&target);
    assert_eq!(slot.backing_ref(), Some(&7), "the old pair stays current");
    assert_eq!(slot.device_ref().commits, 1, "commit was attempted once");
    assert_eq!(
        slot.device_ref().takes,
        0,
        "a commit failure detaches nothing"
    );
    assert_eq!(slot.device_ref().installs, 0, "and installs nothing");
    assert!(slot.device_ref().medium.is_some());
    assert!(!slot.needs_recovery());
    assert!(target.snapshot_static::<Here>().ready);

    let candidate = target.take_static_at::<Here>(0).expect("candidate");
    assert_eq!(
        candidate.pair,
        Some(pair_none(9)),
        "the candidate, not the old"
    );
    assert_eq!(candidate.local, Err(Fault::Commit));
    assert_eq!(candidate.delivery, Delivery::NotApplicable);
    assert!(!candidate.effects.sync_durable);
    assert_eq!(
        target.take_static_at::<Here>(0),
        Err(BoundaryReject::NothingToTake)
    );

    // Known failure terminates the transaction: after the take the slot is
    // Ready again and a new proposal is accepted (§4.10).
    assert_eq!(
        target.propose_static::<Here>(Change::Replace(pair_none(11))),
        Ok(())
    );
}

/// Known install failure: the candidate fails to install, the old pair is
/// restored exactly and the candidate leaves through the one-shot result.
#[test]
fn replace_install_failure_restores_the_old_pair_and_returns_the_candidate() {
    let mut target = script_target(ScriptedDevice::failing_installs(1), 7);

    assert_eq!(
        target.propose_static::<Here>(Change::Replace(pair_none(9))),
        Ok(())
    );
    assert_eq!(target.advance_static::<Here>(), Err(Fault::Io));

    let slot = slot0(&target);
    assert_eq!(slot.backing_ref(), Some(&7), "the old backing is restored");
    assert!(slot.device_ref().medium.is_some(), "the old medium is back");
    assert!(!slot.needs_recovery());
    assert!(target.snapshot_static::<Here>().ready);
    assert_eq!(slot.device_ref().commits, 1);
    assert_eq!(slot.device_ref().takes, 1, "the old pair was detached once");
    assert_eq!(
        slot.device_ref().installs,
        2,
        "candidate install failed, old restore succeeded"
    );

    let candidate = target.take_static_at::<Here>(0).expect("candidate");
    assert_eq!(candidate.pair, Some(pair_none(9)));
    // The reported fault is the real install failure, never rewritten as a
    // commit failure (§4.10/§4.17).
    assert_eq!(candidate.local, Err(Fault::Io));
    assert_eq!(
        target.take_static_at::<Here>(0),
        Err(BoundaryReject::NothingToTake)
    );

    // The slot was never emptied, so a second install over the restored pair is
    // a contract violation and the input is returned unchanged.
    match target.install_static::<Here>(pair_none(9)) {
        Err((returned, fault)) => {
            assert_eq!(fault, Fault::Contract);
            assert_eq!(returned, pair_none(9));
        }
        Ok(()) => panic!("install over a resident pair must be refused"),
    }
}

/// §4.10 restore failure: the slot must not pretend the old pair is
/// healthy. It reports `NeedsRecovery`, is not ready, keeps the candidate in
/// the result and preserves the old pair for force — and `install` is refused
/// until the result has been taken (AwaitTake barrier).
#[test]
fn replace_install_and_restore_failure_needs_recovery_and_blocks_reinstall_before_take() {
    let mut target = script_target(ScriptedDevice::failing_installs(2), 7);

    assert_eq!(
        target.propose_static::<Here>(Change::Replace(pair_none(9))),
        Ok(())
    );
    assert_eq!(
        target.advance_static::<Here>(),
        Err(Fault::NeedsRecovery),
        "a failed restore is a needs-recovery condition, not a commit failure"
    );

    {
        let slot = slot0(&target);
        assert!(slot.needs_recovery());
        assert_eq!(slot.backing_ref(), None, "old is not silently reinstated");
        assert!(
            slot.device_ref().medium.is_none(),
            "the preserved old medium is not in the device"
        );
        assert!(slot.has_result());
    }
    let info = target.snapshot_static::<Here>();
    assert!(!info.ready, "LuInfo.ready must be false in needs_recovery");

    // The management gate is the AwaitTake barrier: recovery-by-reinstall needs
    // the result taken first (§3.6 permission table, §4.11 service_gate).
    match target.install_static::<Here>(pair_none(7)) {
        Err((returned, fault)) => {
            assert_eq!(fault, Fault::Boundary);
            assert_eq!(returned, pair_none(7));
        }
        Ok(()) => panic!("install with a resident result must be refused"),
    }
    assert!(
        slot0(&target).needs_recovery(),
        "the refused install changed nothing"
    );

    let candidate = target.take_static_at::<Here>(0).expect("candidate");
    assert_eq!(candidate.pair, Some(pair_none(9)));
    assert_eq!(candidate.local, Err(Fault::NeedsRecovery));
    assert_eq!(
        target.take_static_at::<Here>(0),
        Err(BoundaryReject::NothingToTake)
    );

    // With the result taken the barrier is clear, so the documented reinstall
    // recovery path works and clears `needs_recovery`.
    assert_eq!(target.install_static::<Here>(pair_none(7)), Ok(()));
    let slot = slot0(&target);
    assert!(!slot.needs_recovery());
    assert_eq!(slot.backing_ref(), Some(&7));
    assert!(target.snapshot_static::<Here>().ready);
}

/// §4.10 force recovery: after a failed restore the old pair is preserved and
/// handed back by `force_remove_*`, never by a silent reinstall.
#[test]
fn force_returns_the_pair_preserved_by_a_failed_restore() {
    let mut target = script_target(ScriptedDevice::failing_installs(2), 7);
    let mut storage = BlockingStorage::new(Plane::new());
    let mut host = BlockingHost::new(QuietHost);

    assert_eq!(
        target.propose_static::<Here>(Change::Replace(pair_none(9))),
        Ok(())
    );
    assert_eq!(target.advance_static::<Here>(), Err(Fault::NeedsRecovery));
    let candidate = target.take_static_at::<Here>(0).expect("candidate");
    assert_eq!(candidate.pair, Some(pair_none(9)));
    assert!(slot0(&target).needs_recovery());
    let commits = slot0(&target).device_ref().commits;

    assert_eq!(
        target.force_remove_static::<Here>(&mut storage, &mut host),
        Ok(())
    );
    assert_eq!(target.tick(), RunOutcome::ResourcesReady { lun: 0 });
    assert!(!slot0(&target).needs_recovery());
    assert_eq!(
        slot0(&target).device_ref().commits,
        commits,
        "force never runs the commit hook"
    );

    let recovered = target.take_static_at::<Here>(0).expect("preserved pair");
    assert_eq!(recovered.pair, Some(pair_none(7)), "the preserved old pair");
    assert_eq!(recovered.local, Ok(()));
    assert!(
        !recovered.effects.sync_durable,
        "force claims no durability"
    );
    assert_eq!(
        target.take_static_at::<Here>(0),
        Err(BoundaryReject::NothingToTake)
    );
    assert_eq!(slot0(&target).backing_ref(), None);
    assert!(!target.snapshot_static::<Here>().ready);
}

/// Known remove failure: a commit failure changes nothing — old stays
/// current and no result is produced, so `take` is `NothingToTake`.
#[test]
fn remove_commit_failure_keeps_the_old_pair_and_produces_no_result() {
    let mut target = script_target(ScriptedDevice::with_commit_fault(), 3);

    assert_eq!(target.propose_static::<Here>(Change::Remove), Ok(()));
    assert_eq!(target.advance_static::<Here>(), Err(Fault::Commit));

    let slot = slot0(&target);
    assert_eq!(slot.backing_ref(), Some(&3), "old is untouched");
    assert!(slot.device_ref().medium.is_some());
    assert_eq!(slot.device_ref().commits, 1);
    assert_eq!(slot.device_ref().takes, 0, "no detach on a failed commit");
    assert!(!slot.has_result(), "Remove failure produces no result");
    assert!(target.snapshot_static::<Here>().ready);

    assert_eq!(
        target.take_static_at::<Here>(0),
        Err(BoundaryReject::NothingToTake)
    );
    assert_eq!(
        target.tick(),
        RunOutcome::ServiceReady,
        "no result means no ResourcesReady"
    );
}

/// Known failure installing into an empty slot: the candidate goes to the
/// result and the slot stays empty.
#[test]
fn install_failure_into_an_empty_slot_leaves_it_empty_and_returns_the_candidate() {
    let mut target = script_target(ScriptedDevice::failing_installs(1), 3);

    // Empty the slot through the real Remove transaction; it never installs, so
    // the failure budget is still intact.
    assert_eq!(target.propose_static::<Here>(Change::Remove), Ok(()));
    assert_eq!(target.advance_static::<Here>(), Ok(()));
    let gone = target.take_static_at::<Here>(0).expect("removed pair");
    assert_eq!(gone.pair, Some(pair_none(3)));
    assert_eq!(slot0(&target).backing_ref(), None);
    assert_eq!(slot0(&target).device_ref().installs, 0);

    assert_eq!(
        target.propose_static::<Here>(Change::Install(pair_none(4))),
        Ok(())
    );
    assert_eq!(target.advance_static::<Here>(), Err(Fault::Io));

    let slot = slot0(&target);
    assert_eq!(slot.backing_ref(), None, "the slot stays empty");
    assert!(!slot.needs_recovery());
    assert!(!target.snapshot_static::<Here>().ready);
    assert_eq!(slot.device_ref().installs, 1, "one install attempt");

    let candidate = target.take_static_at::<Here>(0).expect("candidate");
    assert_eq!(candidate.pair, Some(pair_none(4)));
    assert_eq!(candidate.local, Err(Fault::Io));
    assert_eq!(
        target.take_static_at::<Here>(0),
        Err(BoundaryReject::NothingToTake)
    );

    // The returned pair still installs back into the empty slot.
    assert_eq!(target.install_static::<Here>(pair_none(3)), Ok(()));
    assert!(target.snapshot_static::<Here>().ready);
}

/// §3.6 drop windows: a saved proposal and a produced result both survive an
/// event-loop turn that neither advances nor takes.
#[test]
fn a_prepared_candidate_and_a_produced_result_survive_an_event_loop_turn() {
    let mut target = script_target(ScriptedDevice::ready(), 7);

    // Window 1: proposal prepared but not advanced.
    assert_eq!(
        target.propose_static::<Here>(Change::Replace(pair_none(9))),
        Ok(())
    );
    assert_eq!(target.tick(), RunOutcome::ServiceReady);
    assert!(slot0(&target).has_candidate(), "the candidate survived");
    assert_eq!(
        slot0(&target).backing_ref(),
        Some(&7),
        "the candidate is not current before advance"
    );
    assert_eq!(target.advance_static::<Here>(), Ok(()));

    // Window 2: completion produced but not taken.
    assert!(slot0(&target).has_result());
    assert_eq!(target.tick(), RunOutcome::ServiceReady);
    assert!(slot0(&target).has_result(), "the result survived the turn");
    let old = target.take_static_at::<Here>(0).expect("old pair");
    assert_eq!(old.pair, Some(pair_none(7)));
}

/// §4.11 barrier scope (documented drift): a resident result blocks new
/// management only. Commands keep being serviced while it awaits `take`,
/// otherwise the application could never inspect the slot it must drain.
#[test]
fn a_resident_result_blocks_management_but_not_commands() {
    let mut target = block_target_with(7);
    let mut work = [0u8; 128];
    let mut scratch = [0u8; 64];

    assert_eq!(
        target.propose_static::<Here>(Change::Replace(pair_none(9))),
        Ok(())
    );
    assert_eq!(target.advance_static::<Here>(), Ok(()));
    assert!(slot0(&target).has_result());

    // TEST UNIT READY is still serviced and answers for the *new* current pair.
    assert_eq!(tur(&mut target, &mut work, &mut scratch), Completion::Good);
    assert!(
        slot0(&target).has_result(),
        "serving a command does not consume the result"
    );

    // Management is refused until the result is claimed (§3.6 AwaitTake row).
    assert!(matches!(
        target.propose_static::<Here>(Change::Remove),
        Err((Change::Remove, Fault::Boundary))
    ));
    let old = target.take_static_at::<Here>(0).expect("old pair");
    assert_eq!(old.pair, Some(pair_none(7)));
    assert_eq!(target.propose_static::<Here>(Change::Remove), Ok(()));
}

/// §4.10 force row (deferred detach): a force that arrives while a result is
/// resident is accepted, detaches nothing yet, and its detach runs when the
/// older result is taken — the forced pair is handed back exactly once.
#[test]
fn force_defers_while_a_result_is_resident_and_hands_the_forced_pair_back_once() {
    let mut target = script_target(ScriptedDevice::ready(), 7);
    let mut storage = BlockingStorage::new(Plane::new());
    let mut host = BlockingHost::new(QuietHost);

    // Replace installs candidate 9 and leaves the old pair (7) resident.
    assert_eq!(
        target.propose_static::<Here>(Change::Replace(pair_none(9))),
        Ok(())
    );
    assert_eq!(target.advance_static::<Here>(), Ok(()));
    assert!(slot0(&target).has_result());
    assert_eq!(slot0(&target).backing_ref(), Some(&9));
    let commits = slot0(&target).device_ref().commits;
    assert_eq!(commits, 1, "only the Replace committed");

    // Accepted, but deferred: handing back a second pair now would silently
    // overwrite the resident result (§4.10).
    assert_eq!(
        target.force_remove_static::<Here>(&mut storage, &mut host),
        Ok(())
    );
    assert_eq!(
        slot0(&target).backing_ref(),
        Some(&9),
        "deferred: the current pair is still installed"
    );
    assert!(slot0(&target).device_ref().medium.is_some());
    assert_eq!(slot0(&target).device_ref().takes, 1, "no second detach yet");
    assert_eq!(
        slot0(&target).device_ref().commits,
        commits,
        "force has no commit"
    );
    assert_eq!(
        target.tick(),
        RunOutcome::ServiceReady,
        "a deferred force publishes no ResourcesReady yet"
    );

    // `take` returns the *old* result (7), not the current pair, and releases
    // the deferred force in the same call.
    let old = target.take_static_at::<Here>(0).expect("old pair");
    assert_eq!(old.pair, Some(pair_none(7)));
    assert_eq!(old.local, Ok(()));
    assert_eq!(
        slot0(&target).backing_ref(),
        None,
        "the deferred force detached the current pair"
    );
    assert_eq!(
        slot0(&target).device_ref().takes,
        2,
        "one detach for the Replace, one for the deferred force"
    );
    assert!(slot0(&target).has_result(), "the forced pair is resident");
    assert_eq!(target.tick(), RunOutcome::ResourcesReady { lun: 0 });

    let forced = target.take_static_at::<Here>(0).expect("forced pair");
    assert_eq!(forced.pair, Some(pair_none(9)), "the forced pair, once");
    assert_eq!(forced.local, Ok(()));
    assert_eq!(forced.delivery, Delivery::NotApplicable);
    assert!(!forced.effects.sync_durable, "force claims no durability");
    assert_eq!(
        target.take_static_at::<Here>(0),
        Err(BoundaryReject::NothingToTake)
    );
    assert_eq!(target.tick(), RunOutcome::ServiceReady);
    assert_eq!(slot0(&target).device_ref().commits, commits);
}

/// The same deferred sequence through the **runtime** entries
/// (`force_remove_rt`/`take_rt`, §4.10): the forced pair is handed back only
/// after the older result, and only once.
#[test]
fn runtime_deferred_force_hands_the_forced_pair_back_after_the_old_result() {
    let mut slots = [LuImpl::new(ScriptedDevice::ready(), 7u8)];
    let table: [&mut dyn Lu<Pair = Pair<NoMedium, u8>>; 1] = [&mut slots[0]];
    let mut target = Target::new(table);
    let mut storage = BlockingStorage::new(Plane::new());
    let mut host = BlockingHost::new(QuietHost);

    assert_eq!(target.propose_rt(0, Change::Replace(pair_none(9))), Ok(()));
    assert_eq!(target.advance_rt(0), Ok(()));

    // Deferred: the resident result must be taken before any handback.
    assert_eq!(target.force_remove_rt(0, &mut storage, &mut host), Ok(()));
    assert_eq!(target.tick(), RunOutcome::ServiceReady);

    let old = target.take_rt(0).expect("old pair");
    assert_eq!(old.pair, Some(pair_none(7)));
    assert_eq!(target.tick(), RunOutcome::ResourcesReady { lun: 0 });

    let forced = target.take_rt(0).expect("forced pair");
    assert_eq!(forced.pair, Some(pair_none(9)), "the forced pair, once");
    assert_eq!(forced.local, Ok(()));
    assert_eq!(target.take_rt(0), Err(BoundaryReject::NothingToTake));
    assert_eq!(target.tick(), RunOutcome::ServiceReady);
}

/// §4.10 delayed-force failure (Contract): if the deferred detach cannot run,
/// the application still gets the older result back, and the next `tick` ends
/// the service instead of pretending it is healthy.
#[test]
fn a_deferred_force_that_cannot_detach_ends_the_service() {
    // Detach #1 belongs to the Replace; detach #2 (the deferred force) fails.
    let mut target = script_target(ScriptedDevice::failing_take_medium_at(2), 7);
    let mut storage = BlockingStorage::new(Plane::new());
    let mut host = BlockingHost::new(QuietHost);

    assert_eq!(
        target.propose_static::<Here>(Change::Replace(pair_none(9))),
        Ok(())
    );
    assert_eq!(target.advance_static::<Here>(), Ok(()));
    assert_eq!(
        target.force_remove_static::<Here>(&mut storage, &mut host),
        Ok(())
    );
    assert_eq!(slot0(&target).backing_ref(), Some(&9));

    let old = target.take_static_at::<Here>(0).expect("old pair");
    assert_eq!(old.pair, Some(pair_none(7)), "the older result is returned");
    assert_eq!(
        slot0(&target).backing_ref(),
        Some(&9),
        "a failed detach keeps the pair installed"
    );
    assert!(!slot0(&target).has_result());
    assert_eq!(
        target.tick(),
        RunOutcome::Ended {
            reason: RunEnd::Fatal,
            error: Some(Fault::Contract),
        }
    );
    assert_eq!(
        target.take_static_at::<Here>(0),
        Err(BoundaryReject::NothingToTake)
    );
}

/// §4.10 delayed-force failure (NeedsRecovery): when the cooperative
/// settlement of a live command cannot finish, force keeps the fixed facts and
/// ends the service with `Fault::NeedsRecovery`.
#[test]
fn a_force_that_cannot_settle_ends_the_service_with_needs_recovery() {
    let mut target = script_target(
        ScriptedDevice::with_interrupt_fault(Fault::NeedsRecovery),
        6,
    );
    let mut storage = BlockingStorage::new(Plane::new());
    let mut host = BlockingHost::new(QuietHost);

    // A live command is what force has to settle; the scripted `interrupt`
    // refuses to settle it.
    assert_eq!(
        target.drive_start_static::<Here>(ctx(), &[0x12, 0, 0, 0, 0, 0]),
        Ok(())
    );
    assert!(
        !target.snapshot_static::<Here>().boundary,
        "the command is live"
    );

    assert_eq!(
        target.force_remove_static::<Here>(&mut storage, &mut host),
        Err(Fault::NeedsRecovery)
    );
    // Fixed facts are kept: nothing was detached or invented.
    assert_eq!(slot0(&target).backing_ref(), Some(&6));
    assert!(!slot0(&target).has_result());
    assert_eq!(slot0(&target).device_ref().takes, 0);
    assert_eq!(
        target.tick(),
        RunOutcome::Ended {
            reason: RunEnd::Fatal,
            error: Some(Fault::NeedsRecovery),
        }
    );
    assert_eq!(
        target.take_static_at::<Here>(0),
        Err(BoundaryReject::NothingToTake)
    );
}
