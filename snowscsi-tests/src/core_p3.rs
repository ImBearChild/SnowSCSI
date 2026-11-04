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
//! ownership and sequencing rules.

use snowscsi::block::{BlockAttrs, BlockDevice};
use snowscsi::core::storage::{
    BlockingHost, BlockingStorage, HostBuf, HostReceipt, HostReq, HostToken, HostTransport, IoBuf,
    IoReq, IoToken, PrefetchOp, Storage, StorageOp, StorageReceipt, SyncHost, SyncStorage, WriteOp,
};
use snowscsi::core::{
    cons, decide_eject, At, BoundaryPermit, BoundaryReject, Change, CommandContext, CommandPermit,
    Completion, Cons, Control, DataPlan, Delivery, Device, Direction, DriveStep, Effect,
    EjectOrigin, Fault, Feedback, FeedbackKind, Here, InterruptReason, KnownEffects, LongInfo,
    LongPhase, Lu, LuImpl, Nil, NoMedium, Pair, PendingKind, PollStep, RemovalLocks, RunEnd,
    RunOutcome, Sense, SlotSet, Spc, StaticTarget, Target, ABORTED_COMMAND, INTERNAL_FAILURE,
    MEDIUM_NOT_PRESENT, MEDIUM_REMOVAL_PREVENTED, WRITE_ERROR,
};
use snowscsi::mmc::{DvdRamMedium, FlatCdMedium, MmcDrive};
use std::cell::{Cell, RefCell};
use std::rc::Rc;
use std::task::Poll;

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

/// Command context for a multi-slot runtime LUN (`Target::drive_start_rt`
/// refills `lun_count` from `slot_count()`).
fn ctx_at(lun: u64) -> CommandContext {
    CommandContext {
        lun,
        lun_count: 2,
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
// State machine, sequencing and gates. Every entry below is the public
// `Target`/`StaticTarget` one; the
// pair's `u8` is its backing identity (the adapter stays application-side).

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
    // first and any later take are `NothingToTake` ("Install: no old").
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
    // runner `Sync`. The observable fact is the reported effect set
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
    // resident candidate is never overwritten.
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
    // any new normal proposal (AwaitTake row, `service_gate`).
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

/// `take` before `advance` has no result; a prepared candidate is not a
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

/// Permission table: a foreground long operation refuses `take`
/// (`take_gate`) and `propose`/`advance`/`install` (`service_gate`).
#[test]
fn foreground_long_operation_blocks_take_and_management() {
    let mut target = dvd_target();
    let mut storage = BlockingStorage::new(Plane::new());
    let mut work = [0u8; 128];
    let mut scratch = [0u8; 64];

    // BLANK with IMMED (MMC-6 Table 229): the command completes GOOD while the
    // drive-owned zero-fill stays resident in the foreground phase.
    assert_eq!(
        target.drive_static::<Here>(
            &mut storage,
            ctx(),
            &[0xA1, 0x20, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0],
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

/// Force row: no commit, no durability claim, the old pair leaves through
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
    // accepted and deferred until the application takes.
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

/// Through the *runtime* entries: `force_remove_rt` detaches into a
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
// is counted and recorded in call order so a fixture can observe the real
// transaction steps (commit called once, one detach, two installs, …) and their
// order instead of inferring them.

/// One management hook observed by [`ScriptedDevice`], in call order. Order
/// The observable order: a host eject is commit → detach, a force
/// is interrupt → detach, and Abort never detaches.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Hook {
    Interrupt,
    Commit,
    Take,
    Install,
}

/// Shared hook log for devices that a fixture cannot reach after construction.
///
/// A runtime array target (`[&mut dyn Lu; N]`) does not implement [`At`], so
/// the two-slot fixtures cannot read `device_ref()` once the target owns the
/// slots. A `Spy` handle is cloned before construction and records the same
/// hooks (`interrupt`, `take_medium`) the static fixtures read from the device.
#[derive(Default)]
struct Spy {
    interrupts: Cell<u32>,
    events: RefCell<Vec<Hook>>,
}

impl Spy {
    fn events(&self) -> std::cell::Ref<'_, Vec<Hook>> {
        self.events.borrow()
    }
}

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
    /// `interrupt` calls observed (the force/abort settlement path).
    interrupts: u32,
    /// Call order of the management hooks, for the order-sensitive fixtures.
    events: Vec<Hook>,
    /// `poll` completes on its first step instead of using the `Idle` model
    /// fallback (a command that must be stepped to `Good` and clears `active`).
    completes: bool,
    /// Optional shared log for fixtures that cannot reach the device afterwards.
    spy: Option<Rc<Spy>>,
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
            interrupts: 0,
            events: Vec::new(),
            completes: false,
            spy: None,
        }
    }

    /// A ready device whose hooks are also recorded in `spy`.
    fn spied(spy: Rc<Spy>) -> Self {
        Self {
            spy: Some(spy),
            ..Self::ready()
        }
    }

    /// A spied device whose command completes on its first step.
    fn completing(spy: Rc<Spy>) -> Self {
        Self {
            completes: true,
            ..Self::spied(spy)
        }
    }

    /// Record `hook` in the shared spy, if this device has one.
    fn spy_hook(&self, hook: Hook) {
        if let Some(spy) = &self.spy {
            if hook == Hook::Interrupt {
                spy.interrupts.set(spy.interrupts.get().saturating_add(1));
            }
            spy.events.borrow_mut().push(hook);
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
        if self.completes {
            // No data phase: the first step completes and the device stops
            // being active (a real profile clears its query/operation).
            self.active = false;
            return PollStep::Complete(Completion::Good);
        }
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
        self.interrupts = self.interrupts.saturating_add(1);
        self.events.push(Hook::Interrupt);
        self.spy_hook(Hook::Interrupt);
        self.active = false;
        match self.interrupt_fault {
            Some(fault) => Err(fault),
            None => Ok(()),
        }
    }

    fn finish_delivery(&mut self, _permit: &CommandPermit, _delivery: Delivery) {}

    fn commit(&mut self, _permit: &BoundaryPermit) -> Result<(), Completion> {
        self.commits = self.commits.saturating_add(1);
        self.events.push(Hook::Commit);
        self.commit_result
    }

    fn take_medium(&mut self, _permit: &BoundaryPermit) -> Option<NoMedium> {
        self.takes = self.takes.saturating_add(1);
        self.events.push(Hook::Take);
        self.spy_hook(Hook::Take);
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
        self.events.push(Hook::Install);
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
    // Ready again and a new proposal is accepted.
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
    // commit failure.
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

/// Restore failure: the slot must not pretend the old pair is
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
    // the result taken first (permission table, service_gate).
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

/// Force recovery: after a failed restore the old pair is preserved and
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

/// Drop windows: a saved proposal and a produced result both survive an
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

/// Barrier scope (documented drift): a resident result blocks new
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

    // Management is refused until the result is claimed (AwaitTake row).
    assert!(matches!(
        target.propose_static::<Here>(Change::Remove),
        Err((Change::Remove, Fault::Boundary))
    ));
    let old = target.take_static_at::<Here>(0).expect("old pair");
    assert_eq!(old.pair, Some(pair_none(7)));
    assert_eq!(target.propose_static::<Here>(Change::Remove), Ok(()));
}

/// Force row (deferred detach): a force that arrives while a result is
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
    // overwrite the resident result.
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
/// (`force_remove_rt`/`take_rt`): the forced pair is handed back only
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

/// Delayed-force failure (Contract): if the deferred detach cannot run,
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

/// Delayed-force failure (NeedsRecovery): when the cooperative
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

// ── Multi-LUN deferred force ───────────────────────────────────────────────
// `Runner::force_pending` used to be a single LUN. A force that arrived while
// another LUN held the global host-eject handback barrier was therefore lost:
// the `take` that cleared the barrier only continued the *same* LUN, leaving
// the deferred slot installed with no result. The deferred mask is per LUN
// (bounded to 64, `Fault::Contract` above), and a take releases one deferred
// force at a time because `await_take` is a single global handback.

/// Force row: a force deferred behind a barrier on **another** LUN is
/// released by the take that clears that barrier, and its pair is handed back
/// exactly once.
#[test]
fn a_take_releases_a_force_deferred_on_another_lun() {
    let mut slots = [
        LuImpl::new(ScriptedDevice::ready(), 7u8),
        LuImpl::new(ScriptedDevice::ready(), 8u8),
    ];
    let [slot0, slot1] = &mut slots;
    let table: [&mut dyn Lu<Pair = Pair<NoMedium, u8>>; 2] = [slot0, slot1];
    let mut target = Target::new(table);
    let mut storage = BlockingStorage::new(Plane::new());
    let mut host = BlockingHost::new(QuietHost);

    // LUN 0 publishes the global `await_take` handback barrier.
    target.host_eject_succeeded_rt(0).expect("host eject");
    assert_eq!(target.tick(), RunOutcome::ResourcesReady { lun: 0 });
    assert!(!target.snapshot_rt(0).expect("slot").ready);

    // The force on LUN 1 is accepted but deferred: the barrier belongs to LUN 0.
    assert_eq!(target.force_remove_rt(1, &mut storage, &mut host), Ok(()));
    assert!(
        target.snapshot_rt(1).expect("slot").ready,
        "deferred: LUN 1 is still installed"
    );
    assert_eq!(target.take_rt(1), Err(BoundaryReject::NothingToTake));

    // The take that clears the barrier must also complete the LUN 1 force.
    let ejected = target.take_rt(0).expect("ejected pair");
    assert_eq!(ejected.pair, Some(pair_none(7)));
    assert!(
        !target.snapshot_rt(1).expect("slot").ready,
        "the deferred force detached LUN 1"
    );
    assert_eq!(target.tick(), RunOutcome::ResourcesReady { lun: 1 });

    let forced = target.take_rt(1).expect("forced pair");
    assert_eq!(
        forced.pair,
        Some(pair_none(8)),
        "the forced pair, exactly once"
    );
    assert_eq!(forced.local, Ok(()));
    assert_eq!(forced.delivery, Delivery::NotApplicable);
    assert!(!forced.effects.sync_durable, "force claims no durability");
    assert_eq!(target.take_rt(1), Err(BoundaryReject::NothingToTake));
    assert_eq!(target.tick(), RunOutcome::ServiceReady);
}

/// Force row: two forces deferred on different LUNs are both accepted
/// (not `Fault::Contract`) and are released one handback at a time, because the
/// runner publishes at most one `ResourcesReady` before the next `take`.
#[test]
fn two_deferred_forces_are_released_one_handback_at_a_time() {
    let mut slots = [
        LuImpl::new(ScriptedDevice::ready(), 7u8),
        LuImpl::new(ScriptedDevice::ready(), 8u8),
        LuImpl::new(ScriptedDevice::ready(), 9u8),
    ];
    let [slot0, slot1, slot2] = &mut slots;
    let table: [&mut dyn Lu<Pair = Pair<NoMedium, u8>>; 3] = [slot0, slot1, slot2];
    let mut target = Target::new(table);
    let mut storage = BlockingStorage::new(Plane::new());
    let mut host = BlockingHost::new(QuietHost);

    target.host_eject_succeeded_rt(0).expect("host eject");
    assert_eq!(target.tick(), RunOutcome::ResourcesReady { lun: 0 });

    // Both forces are accepted and deferred behind the LUN 0 barrier; the
    // second one must not be a `Contract` reject.
    assert_eq!(target.force_remove_rt(1, &mut storage, &mut host), Ok(()));
    assert_eq!(target.force_remove_rt(2, &mut storage, &mut host), Ok(()));
    assert!(target.snapshot_rt(1).expect("slot").ready);
    assert!(target.snapshot_rt(2).expect("slot").ready);

    // First take: releases exactly one deferred handback (lowest LUN).
    let first = target.take_rt(0).expect("ejected pair");
    assert_eq!(first.pair, Some(pair_none(7)));
    assert!(!target.snapshot_rt(1).expect("slot").ready);
    assert!(
        target.snapshot_rt(2).expect("slot").ready,
        "only one handback may be pending"
    );
    assert_eq!(target.tick(), RunOutcome::ResourcesReady { lun: 1 });

    // Taking the LUN 1 result releases the LUN 2 force.
    let second = target.take_rt(1).expect("forced pair");
    assert_eq!(second.pair, Some(pair_none(8)));
    assert!(!target.snapshot_rt(2).expect("slot").ready);
    assert_eq!(target.tick(), RunOutcome::ResourcesReady { lun: 2 });

    let third = target.take_rt(2).expect("forced pair");
    assert_eq!(third.pair, Some(pair_none(9)));
    assert_eq!(target.take_rt(2), Err(BoundaryReject::NothingToTake));
    assert_eq!(target.tick(), RunOutcome::ServiceReady);
}

// ── Multi-LUN force settlement ─────────────────────────────────────────────
// `drive_state` is target-global, but a command belongs to exactly one slot.
// A force aimed at LUN 1 while LUN 0 runs must neither interrupt LUN 1 (which
// owns nothing) nor clear the LUN 0 command it does not own: LUN 0 would stay
// `active()` with no state left to step (`step_command` → `Fault::Contract`),
// and a later force would detach a device that was never settled.

/// Immediate-cancel / force row: forcing an idle LUN while another
/// LUN runs detaches only the addressed slot and leaves the running command
/// untouched and steppable.
#[test]
fn a_force_on_one_lun_leaves_the_active_command_on_another_lun_alone() {
    let spy0 = Rc::new(Spy::default());
    let spy1 = Rc::new(Spy::default());
    let mut slots = [
        LuImpl::new(ScriptedDevice::completing(Rc::clone(&spy0)), 7u8),
        LuImpl::new(ScriptedDevice::spied(Rc::clone(&spy1)), 8u8),
    ];
    let [slot0, slot1] = &mut slots;
    let table: [&mut dyn Lu<Pair = Pair<NoMedium, u8>>; 2] = [slot0, slot1];
    let mut target = Target::new(table);
    let mut storage = BlockingStorage::new(Plane::new());
    let mut host = BlockingHost::new(QuietHost);
    let mut work = [0u8; 128];
    let mut scratch = [0u8; 64];

    // LUN 0 owns the one live command (`drive_state.ctx.lun == 0`); no slot has
    // a resident result.
    assert_eq!(
        target.drive_start_rt(0, ctx_at(0), &[0x12, 0, 0, 0, 0, 0]),
        Ok(())
    );
    assert!(!target.snapshot_rt(0).expect("slot 0").boundary);
    assert!(target.snapshot_rt(1).expect("slot 1").boundary);

    // Forcing the idle LUN 1 detaches it; it must not interrupt its idle device
    // and must not settle the LUN 0 command it does not own.
    assert_eq!(target.force_remove_rt(1, &mut storage, &mut host), Ok(()));
    assert!(!target.snapshot_rt(1).expect("slot 1").ready);
    assert_eq!(spy1.events().as_slice(), [Hook::Take].as_slice());
    assert_eq!(spy1.interrupts.get(), 0, "LUN 1 owned no command");
    assert_eq!(spy0.interrupts.get(), 0, "LUN 0's command was not settled");
    assert!(spy0.events().is_empty(), "force never touched LUN 0");
    assert!(
        !target.snapshot_rt(0).expect("slot 0").boundary,
        "the LUN 0 command is still live"
    );

    // …and it still completes normally instead of a `Contract` fault.
    assert_eq!(
        target.drive_step_rt(0, &mut storage, &mut host, &mut work, &mut [], &mut scratch),
        Ok(DriveStep::Done(Completion::Good))
    );
    assert!(target.snapshot_rt(0).expect("slot 0").boundary);
    assert!(spy0.events().is_empty());

    // The forced LUN 1 pair is handed back exactly once.
    assert_eq!(target.tick(), RunOutcome::ResourcesReady { lun: 1 });
    let forced = target.take_rt(1).expect("forced pair");
    assert_eq!(forced.pair, Some(pair_none(8)));
    assert_eq!(target.take_rt(1), Err(BoundaryReject::NothingToTake));

    // LUN 0 is idle again and can be forced itself.
    assert_eq!(target.force_remove_rt(0, &mut storage, &mut host), Ok(()));
    assert_eq!(target.tick(), RunOutcome::ResourcesReady { lun: 0 });
    let old = target.take_rt(0).expect("forced pair");
    assert_eq!(old.pair, Some(pair_none(7)));
    assert_eq!(target.take_rt(0), Err(BoundaryReject::NothingToTake));
    assert_eq!(target.tick(), RunOutcome::ServiceReady);
}

/// Deferred force row, second trigger: repeating a force for a LUN whose
/// result is resident used to re-settle the *global* `drive_state`, i.e. the
/// command another LUN owns. The repeat may only re-arm the deferral.
#[test]
fn a_repeated_deferred_force_does_not_settle_a_command_on_another_lun() {
    let spy0 = Rc::new(Spy::default());
    let spy1 = Rc::new(Spy::default());
    let mut slots = [
        LuImpl::new(ScriptedDevice::completing(Rc::clone(&spy0)), 7u8),
        LuImpl::new(ScriptedDevice::spied(Rc::clone(&spy1)), 8u8),
    ];
    let [slot0, slot1] = &mut slots;
    let table: [&mut dyn Lu<Pair = Pair<NoMedium, u8>>; 2] = [slot0, slot1];
    let mut target = Target::new(table);
    let mut storage = BlockingStorage::new(Plane::new());
    let mut host = BlockingHost::new(QuietHost);
    let mut work = [0u8; 128];
    let mut scratch = [0u8; 64];

    // LUN 1 holds its old pair (8) as a resident result after a Replace; 9 is
    // the current pair.
    assert_eq!(target.propose_rt(1, Change::Replace(pair_none(9))), Ok(()));
    assert_eq!(target.advance_rt(1), Ok(()));
    assert!(target.snapshot_rt(1).expect("slot 1").ready);

    // A command now runs on LUN 0 and owns the global `drive_state`.
    assert_eq!(
        target.drive_start_rt(0, ctx_at(0), &[0x12, 0, 0, 0, 0, 0]),
        Ok(())
    );

    // The force on LUN 1 is deferred behind its resident result; the repeat
    // must not settle the LUN 0 command that the global state belongs to.
    assert_eq!(target.force_remove_rt(1, &mut storage, &mut host), Ok(()));
    assert_eq!(target.force_remove_rt(1, &mut storage, &mut host), Ok(()));
    assert!(
        target.snapshot_rt(1).expect("slot 1").ready,
        "still deferred: the result must be taken first"
    );
    assert_eq!(spy1.interrupts.get(), 0, "LUN 1 owns no command");
    assert_eq!(spy0.interrupts.get(), 0, "LUN 0's command was not settled");
    assert!(spy0.events().is_empty(), "force never touched LUN 0");
    assert!(
        !target.snapshot_rt(0).expect("slot 0").boundary,
        "the LUN 0 command is still live"
    );

    // LUN 0 still completes normally.
    assert_eq!(
        target.drive_step_rt(0, &mut storage, &mut host, &mut work, &mut [], &mut scratch),
        Ok(DriveStep::Done(Completion::Good))
    );

    // The take that clears the barrier releases the deferred LUN 1 force once.
    let old = target.take_rt(1).expect("old pair");
    assert_eq!(old.pair, Some(pair_none(8)));
    assert!(!target.snapshot_rt(1).expect("slot 1").ready);
    assert_eq!(target.tick(), RunOutcome::ResourcesReady { lun: 1 });
    let forced = target.take_rt(1).expect("forced pair");
    assert_eq!(forced.pair, Some(pair_none(9)));
    assert_eq!(target.take_rt(1), Err(BoundaryReject::NothingToTake));
    assert_eq!(target.tick(), RunOutcome::ServiceReady);
    assert_eq!(spy1.interrupts.get(), 0);
    assert_eq!(spy0.interrupts.get(), 0);
}

// ── Host eject full chain ──────────────────────────────────────────────────

/// Host eject with no locks — local commit, detach/result, status and
/// `ResourcesReady`; the old pair is taken once, the slot is empty, and
/// installing the returned pair restores service (empty reentry).
#[test]
fn host_eject_commits_detaches_and_the_returned_pair_restores_service() {
    let mut target = script_target(ScriptedDevice::ready(), 7);

    assert_eq!(target.host_eject_succeeded_static::<Here>(), Ok(()));
    let device = slot0(&target).device_ref();
    assert_eq!(device.commits, 1, "local commit ran");
    assert_eq!(device.takes, 1, "the pair was detached");
    assert_eq!(device.installs, 0);
    // The fixed host-eject order: local commit, then detach.
    assert_eq!(device.events, [Hook::Commit, Hook::Take]);
    assert!(slot0(&target).has_result());
    assert_eq!(target.tick(), RunOutcome::ResourcesReady { lun: 0 });

    let info = target.snapshot_static::<Here>();
    assert!(!info.ready, "the slot is empty after the eject");
    assert!(!info.is_locked(), "no locks were set");
    assert_eq!(slot0(&target).backing_ref(), None);

    let result = target.take_static_at::<Here>(0).expect("ejected pair");
    assert_eq!(result.pair, Some(pair_none(7)), "the old pair, once");
    assert_eq!(result.local, Ok(()));
    // The result was produced before the status was sent (order).
    assert_eq!(result.delivery, Delivery::Pending);
    assert_eq!(result.effects, KnownEffects::NONE);
    assert_eq!(
        target.take_static_at::<Here>(0),
        Err(BoundaryReject::NothingToTake)
    );
    assert_eq!(target.tick(), RunOutcome::ServiceReady);
    assert_eq!(slot0(&target).device_ref().commits, 1);

    // Empty reentry: the returned pair installs back and commands are admitted
    // again (the scripted device answers the model fallback, not
    // `MEDIUM NOT PRESENT`).
    assert_eq!(target.install_static::<Here>(pair_none(7)), Ok(()));
    assert!(target.snapshot_static::<Here>().ready);
    assert!(slot0(&target).device_ref().medium.is_some());
    assert_eq!(
        slot0(&target).device_ref().events,
        [Hook::Commit, Hook::Take, Hook::Install],
        "empty reentry installs the returned pair after the commit/detach"
    );
    let mut work = [0u8; 128];
    let mut scratch = [0u8; 64];
    assert_eq!(tur(&mut target, &mut work, &mut scratch), Completion::Busy);
}

/// Host eject with normal + persistent PREVENT set still succeeds, clears
/// normal, keeps persistent and hands the pair back once.
#[test]
fn host_eject_with_both_locks_clears_normal_keeps_persistent_and_returns_the_pair() {
    let mut target = mmc_target();
    let mut storage = BlockingStorage::new(Plane::new());
    let mut work = [0u8; 128];
    let mut scratch = [0u8; 64];

    // MMC bit1 selects persistent, bit0 selects set.
    assert_eq!(
        prevent(&mut target, &mut storage, &mut work, &mut scratch, 0b01),
        Completion::Good
    );
    assert_eq!(
        prevent(&mut target, &mut storage, &mut work, &mut scratch, 0b11),
        Completion::Good
    );
    let info = target.snapshot_static::<Here>();
    assert!(info.prevent && info.persistent_prevent);

    assert_eq!(target.host_eject_succeeded_static::<Here>(), Ok(()));
    let info = target.snapshot_static::<Here>();
    assert!(!info.prevent, "host eject clears the normal latch");
    assert!(info.persistent_prevent, "the persistent latch survives");
    assert!(info.is_locked());
    assert!(!info.ready);

    assert_eq!(target.tick(), RunOutcome::ResourcesReady { lun: 0 });
    let result = target.take_static_at::<Here>(0).expect("ejected pair");
    assert_eq!(result.pair.as_ref().map(|pair| pair.backing), Some(1));
    assert_eq!(result.local, Ok(()));
    assert_eq!(result.delivery, Delivery::Pending);
    assert_eq!(
        target.take_static_at::<Here>(0).err(),
        Some(BoundaryReject::NothingToTake)
    );
    assert_eq!(target.tick(), RunOutcome::ServiceReady);
}

/// A local-commit failure during host eject detaches nothing, produces no
/// result, leaves the slot ready and does not end the service.
#[test]
fn host_eject_commit_failure_keeps_the_slot_ready() {
    let mut target = script_target(ScriptedDevice::with_commit_fault(), 5);

    assert_eq!(
        target.host_eject_succeeded_static::<Here>(),
        Err(Fault::Commit)
    );
    let device = slot0(&target).device_ref();
    assert_eq!(device.commits, 1, "the commit was attempted");
    assert_eq!(device.takes, 0, "nothing is detached before a commit");
    assert_eq!(device.events, [Hook::Commit]);
    assert!(!slot0(&target).has_result());
    assert_eq!(slot0(&target).backing_ref(), Some(&5));

    let info = target.snapshot_static::<Here>();
    assert!(info.ready);
    assert_eq!(
        target.take_static_at::<Here>(0),
        Err(BoundaryReject::NothingToTake)
    );
    assert_eq!(target.tick(), RunOutcome::ServiceReady);
    // No `eject_pending` leaked: normal management is accepted again.
    assert_eq!(target.propose_static::<Here>(Change::Remove), Ok(()));
}

/// A failed status send after the detach does not roll back the
/// commit/detach; the result stays resident and is takeable once even after a
/// lost link.
#[test]
fn a_failed_host_status_keeps_the_result_takeable() {
    let mut target = script_target(ScriptedDevice::ready(), 3);

    assert_eq!(target.host_eject_succeeded_static::<Here>(), Ok(()));
    let commits = slot0(&target).device_ref().commits;
    let takes = slot0(&target).device_ref().takes;
    assert_eq!(target.tick(), RunOutcome::ResourcesReady { lun: 0 });

    // A lost link must not re-commit, re-detach or discard the fixed result.
    let result = target
        .take_static_at::<Here>(0)
        .expect("the result survives the failed status");
    assert_eq!(result.pair, Some(pair_none(3)));
    assert_eq!(result.local, Ok(()));
    assert_eq!(
        result.delivery,
        Delivery::Pending,
        "the snapshot is not rewritten to Complete"
    );
    assert_eq!(slot0(&target).device_ref().commits, commits);
    assert_eq!(slot0(&target).device_ref().takes, takes);
    assert_eq!(
        target.take_static_at::<Here>(0),
        Err(BoundaryReject::NothingToTake)
    );
}

// ── Force from abnormal states / Abort ─────────────────────────────────────

/// Force from an active command settles it with `interrupt` before
/// detaching; the old pair is handed back once and no commit runs.
#[test]
fn force_settles_an_active_command_before_detaching() {
    let mut target = script_target(ScriptedDevice::ready(), 4);
    let mut storage = BlockingStorage::new(Plane::new());
    let mut host = BlockingHost::new(QuietHost);

    assert_eq!(
        target.drive_start_static::<Here>(ctx(), &[0x12, 0, 0, 0, 0, 0]),
        Ok(())
    );
    assert!(
        !target.snapshot_static::<Here>().boundary,
        "command is live"
    );

    assert_eq!(
        target.force_remove_static::<Here>(&mut storage, &mut host),
        Ok(())
    );
    let device = slot0(&target).device_ref();
    assert_eq!(device.interrupts, 1, "the command was settled first");
    assert!(!device.active);
    assert_eq!(device.takes, 1, "then the pair was detached");
    assert_eq!(device.commits, 0, "force never commits");
    // The settle must precede the detach; a detach-first order would leave a
    // live command on a pair the application is about to receive.
    assert_eq!(device.events, [Hook::Interrupt, Hook::Take]);
    assert!(slot0(&target).has_result());

    assert_eq!(target.tick(), RunOutcome::ResourcesReady { lun: 0 });
    let result = target.take_static_at::<Here>(0).expect("forced pair");
    assert_eq!(result.pair, Some(pair_none(4)));
    assert_eq!(
        target.take_static_at::<Here>(0),
        Err(BoundaryReject::NothingToTake)
    );
}

/// Delayed-force failure: a detach that cannot run is reported, not
/// hidden — the pair stays installed, no result is invented and the next
/// settled `tick` ends the service with the fault.
#[test]
fn a_force_that_cannot_detach_ends_the_service_without_a_result() {
    let mut target = script_target(ScriptedDevice::failing_take_medium_at(1), 5);
    let mut storage = BlockingStorage::new(Plane::new());
    let mut host = BlockingHost::new(QuietHost);

    assert_eq!(
        target.force_remove_static::<Here>(&mut storage, &mut host),
        Err(Fault::Contract)
    );
    let device = slot0(&target).device_ref();
    assert_eq!(device.takes, 1);
    assert_eq!(device.commits, 0);
    assert_eq!(device.events, [Hook::Take]);
    assert_eq!(
        slot0(&target).backing_ref(),
        Some(&5),
        "a failed detach keeps the pair installed"
    );
    assert!(!slot0(&target).has_result());
    assert_eq!(
        target.take_static_at::<Here>(0),
        Err(BoundaryReject::NothingToTake)
    );
    assert_eq!(
        target.tick(),
        RunOutcome::Ended {
            reason: RunEnd::Fatal,
            error: Some(Fault::Contract),
        }
    );
}

/// `Control::Abort` ends the command (`0B/45/00`) but never detaches the
/// medium, produces no management result and leaves the target serving.
#[test]
fn abort_ends_the_command_without_detaching_the_medium() {
    let mut target = script_target(ScriptedDevice::ready(), 6);
    let mut storage = BlockingStorage::new(Plane::new());
    let mut host = BlockingHost::new(QuietHost);
    let mut work = [0u8; 64];
    let mut scratch = [0u8; 32];

    assert_eq!(
        target.drive_start_static::<Here>(ctx(), &[0x12, 0, 0, 0, 0, 0]),
        Ok(())
    );
    assert_eq!(target.request_control(Control::Abort), Ok(()));
    assert_eq!(
        target.drive_step_static::<Here>(&mut storage, &mut host, &mut work, &mut [], &mut scratch),
        Ok(DriveStep::Done(Completion::Check(ABORTED_COMMAND)))
    );

    let device = slot0(&target).device_ref();
    assert_eq!(device.interrupts, 1, "Abort settles the command");
    assert_eq!(device.takes, 0, "Abort never detaches the medium");
    assert_eq!(device.commits, 0);
    assert_eq!(device.events, [Hook::Interrupt]);
    assert!(device.medium.is_some());
    assert_eq!(slot0(&target).backing_ref(), Some(&6));
    assert!(!slot0(&target).has_result());
    assert_eq!(target.tick(), RunOutcome::ServiceReady);
    assert_eq!(
        target.take_static_at::<Here>(0),
        Err(BoundaryReject::NothingToTake)
    );
}

/// Operator eject is a policy decision, not a library detach entry — the
/// application reads the live latches, calls `decide_eject`, and a refused
/// request changes no slot state.
#[test]
fn operator_eject_policy_reads_live_latches_and_detaches_nothing() {
    let mut target = mmc_target();
    let mut storage = BlockingStorage::new(Plane::new());
    let mut work = [0u8; 128];
    let mut scratch = [0u8; 64];

    assert_eq!(
        prevent(&mut target, &mut storage, &mut work, &mut scratch, 0b01),
        Completion::Good
    );
    let info = target.snapshot_static::<Here>();
    let locks = RemovalLocks {
        prevent: info.prevent,
        persistent_prevent: info.persistent_prevent,
    };
    let decision = decide_eject(locks, EjectOrigin::Operator);
    assert!(!decision.allowed);
    assert_eq!(
        decision.completion,
        Completion::Check(MEDIUM_REMOVAL_PREVENTED)
    );

    // The policy is the only library seam: nothing was detached or produced.
    assert!(target.snapshot_static::<Here>().ready);
    assert_eq!(slot0(&target).backing_ref(), Some(&1));
    assert_eq!(
        target.take_static_at::<Here>(0).err(),
        Some(BoundaryReject::NothingToTake)
    );
    assert_eq!(target.tick(), RunOutcome::ServiceReady);
}

// ═══════════════════════════════════════════════════════════════════════════
// Abnormal settlement: Stop drains, every other end cancels
// ═══════════════════════════════════════════════════════════════════════════
//
// Every fixture drives the public `Target` entries over a scripted device and
// scripted adapter pair that append to **one** shared call log, so the design's
// order is asserted on the real sequence: `cancel`/the drained receipt returns
// before `interrupt`, `interrupt` before `finish_delivery(Failed)`, a token is
// re-polled and never re-issued (no replay), and no settlement path detaches or
// installs a medium.
//
// Rows that cannot be modelled in core (written reason):
//
// - "partial header" / "complete header not admitted": core receives an
//   already-complete CDB slice (`Target::drive_start_*`); BHS/CBW framing and
//   the input barrier are transport facts, covered by the transport layer. This
//   slice must not fake a header the runner never sees.
// - "sending frame" segment prefixes: the exact wire framing belongs to
//   `HostTransport`; core only observes the returned receipt, which the
//   fixtures do cover (full-status-sent hook, in-flight send, short send).
// - "retained input 未清": the runner's `retained_input` hold is crate-private
//   and not wired to any `Target` entry, so the window is pinned by the runner
//   unit test (`boundary_counts_the_execution_borrow_and_retained_input`) and by
//   the unconsumed-completion window below, not by a transport fixture.

/// One observed call, in real call order across the device and both adapters.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Ev {
    /// `Storage::begin_exec` saw this metadata (never a buffer).
    Begin { dir: Direction, len: u32 },
    /// `Storage::poll_exec` re-borrowed a buffer of this shape.
    Poll {
        dir: Direction,
        len: u32,
        none_buf: bool,
    },
    /// `Storage::cancel` returned.
    Cancel,
    /// `Device::interrupt` was entered with these facts.
    Interrupt {
        reason: InterruptReason,
        known: KnownEffects,
    },
    /// `Device::finish_delivery` was entered.
    Delivery(Delivery),
    /// `Device::take_medium` ran (a detach).
    Take,
    /// `Device::install_medium` ran (a new medium).
    Install,
    /// The device observed a storage receipt.
    IoSeen {
        confirmed: usize,
        error: Option<Fault>,
    },
    /// `HostTransport::poll_host` was entered.
    HostPoll { dir: Direction, len: u32 },
    /// `HostTransport::cancel` returned.
    HostCancel,
}

type Log = Rc<RefCell<Vec<Ev>>>;

/// Copy of the shared call log.
fn events(log: &Log) -> Vec<Ev> {
    log.borrow().clone()
}

/// Position of the first event matching `pred`.
fn at(log: &Log, pred: impl Fn(&Ev) -> bool) -> usize {
    log.borrow()
        .iter()
        .position(pred)
        .expect("the expected call was observed")
}

/// One scripted device step (`PollStep` without the borrow).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Step {
    Publish(DataPlan),
    Write(usize),
    Read(usize),
    Prefetch(usize),
    Sync,
    Receive(usize),
    ReceiveCombined { len: usize, write: usize },
    Send(usize),
    SendCombined { len: usize, prefetch: usize },
    Complete(Completion),
}

const SETTLE_SCRIPT: usize = 8;

/// Scripted device that replays [`Step`]s and records every settlement hook in
/// the shared log. It never issues storage IO itself (`commit` is the default
/// no-op).
struct SettleDevice {
    steps: [Option<Step>; SETTLE_SCRIPT],
    cursor: usize,
    active: bool,
    medium: Option<NoMedium>,
    interrupt_fault: Option<Fault>,
    log: Log,
    interrupts: u32,
    /// How many times the device was polled (proof that a settle did not poll
    /// again after a returned receipt).
    polls: u32,
    deliveries: Vec<Delivery>,
    last_known: Option<KnownEffects>,
    takes: u32,
    installs: u32,
    /// Receipts handed to `poll`, in order: `(confirmed, error)`.
    seen: Vec<(usize, Option<Fault>)>,
    /// Feedback kinds observed, in order.
    feedbacks: Vec<FeedbackKind>,
}

impl SettleDevice {
    fn new(log: Log, steps: [Option<Step>; SETTLE_SCRIPT]) -> Self {
        Self {
            steps,
            cursor: 0,
            active: false,
            medium: Some(NoMedium),
            interrupt_fault: None,
            log,
            interrupts: 0,
            polls: 0,
            deliveries: Vec::new(),
            last_known: None,
            takes: 0,
            installs: 0,
            seen: Vec::new(),
            feedbacks: Vec::new(),
        }
    }

    /// A device whose `interrupt` settlement fails with `fault`.
    fn failing_settle(log: Log, steps: [Option<Step>; SETTLE_SCRIPT], fault: Fault) -> Self {
        Self {
            interrupt_fault: Some(fault),
            ..Self::new(log, steps)
        }
    }
}

impl Device for SettleDevice {
    type Medium = NoMedium;

    fn prepare(
        &mut self,
        _permit: &CommandPermit,
        _ctx: CommandContext,
        _cdb: &[u8],
    ) -> Result<(), Completion> {
        self.active = true;
        self.cursor = 0;
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
        permit: &CommandPermit,
        feedback: Feedback,
        data: &'a mut [u8],
    ) -> PollStep<'a> {
        self.poll_with_alt(permit, feedback, data, &mut [])
    }

    fn poll_with_alt<'a>(
        &mut self,
        _permit: &CommandPermit,
        feedback: Feedback,
        data: &'a mut [u8],
        alt: &'a mut [u8],
    ) -> PollStep<'a> {
        self.polls = self.polls.saturating_add(1);
        self.feedbacks.push(feedback.kind());
        if let Some(io) = feedback.io() {
            self.seen.push((io.confirmed(), io.error()));
            self.log.borrow_mut().push(Ev::IoSeen {
                confirmed: io.confirmed(),
                error: io.error(),
            });
        }
        let step = match self.steps.get(self.cursor).copied().flatten() {
            Some(step) => step,
            None => return PollStep::Idle,
        };
        self.cursor += 1;
        match step {
            Step::Publish(plan) => PollStep::Publish(plan),
            Step::Write(len) => PollStep::Io(StorageOp::Write {
                resource: 1,
                offset: 0,
                buf: &mut data[..len],
            }),
            Step::Read(len) => PollStep::Io(StorageOp::Read {
                resource: 1,
                offset: 0,
                buf: &mut data[..len],
            }),
            Step::Prefetch(len) => PollStep::Prefetch(PrefetchOp::Read {
                resource: 1,
                offset: 0,
                buf: &mut data[..len],
            }),
            Step::Sync => PollStep::Io(StorageOp::Sync { resource: 1 }),
            Step::Receive(len) => PollStep::Receive {
                buf: &mut data[..len],
                write: None,
            },
            Step::ReceiveCombined { len, write } => PollStep::Receive {
                buf: &mut alt[..len],
                write: Some(WriteOp::Write {
                    resource: 1,
                    offset: 1,
                    buf: &mut data[..write],
                }),
            },
            Step::Send(len) => PollStep::Send {
                bytes: &data[..len],
                prefetch: None,
            },
            Step::SendCombined { len, prefetch } => PollStep::Send {
                bytes: &data[..len],
                prefetch: Some(PrefetchOp::Read {
                    resource: 1,
                    offset: 1,
                    buf: &mut alt[..prefetch],
                }),
            },
            Step::Complete(completion) => {
                self.active = false;
                PollStep::Complete(completion)
            }
        }
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
        reason: InterruptReason,
        known: KnownEffects,
    ) -> Result<(), Fault> {
        self.interrupts = self.interrupts.saturating_add(1);
        self.last_known = Some(known);
        self.active = false;
        self.log.borrow_mut().push(Ev::Interrupt { reason, known });
        match self.interrupt_fault {
            Some(fault) => Err(fault),
            None => Ok(()),
        }
    }

    fn finish_delivery(&mut self, _permit: &CommandPermit, delivery: Delivery) {
        self.deliveries.push(delivery);
        self.log.borrow_mut().push(Ev::Delivery(delivery));
    }

    fn take_medium(&mut self, _permit: &BoundaryPermit) -> Option<NoMedium> {
        self.takes = self.takes.saturating_add(1);
        self.log.borrow_mut().push(Ev::Take);
        self.medium.take()
    }

    fn install_medium(
        &mut self,
        _permit: &BoundaryPermit,
        medium: NoMedium,
    ) -> Result<(), (NoMedium, Fault)> {
        self.installs = self.installs.saturating_add(1);
        self.log.borrow_mut().push(Ev::Install);
        self.medium = Some(medium);
        Ok(())
    }
}

/// Scripted storage adapter: `pending` consecutive `Pending` answers, then the
/// programmed receipt. `exhausted` mints the pool-exhausted token instead.
struct SettleStorage {
    log: Log,
    pending: u32,
    receipt: StorageReceipt,
    exhausted: bool,
    begins: u32,
    polls: u32,
    cancels: u32,
    /// Buffer shape per `poll_exec`: `(direction, len, was IoBuf::None)`.
    bufs: Vec<(Direction, u32, bool)>,
}

impl SettleStorage {
    fn ready(log: Log, receipt: StorageReceipt) -> Self {
        Self {
            log,
            pending: 0,
            receipt,
            exhausted: false,
            begins: 0,
            polls: 0,
            cancels: 0,
            bufs: Vec::new(),
        }
    }

    fn pending_then(log: Log, pending: u32, receipt: StorageReceipt) -> Self {
        Self {
            pending,
            ..Self::ready(log, receipt)
        }
    }

    fn stalled(log: Log) -> Self {
        Self::pending_then(log, u32::MAX, StorageReceipt::ok(0))
    }

    fn exhausted(log: Log) -> Self {
        Self {
            exhausted: true,
            ..Self::ready(log, StorageReceipt::ok(0))
        }
    }
}

impl Storage for SettleStorage {
    fn begin_exec(&mut self, req: IoReq) -> IoToken {
        self.begins = self.begins.saturating_add(1);
        self.log.borrow_mut().push(Ev::Begin {
            dir: req.dir,
            len: req.len,
        });
        if self.exhausted {
            // The pool-exhausted token shape (`IoToken::invalid` is crate-only).
            return IoToken::new(u8::MAX, 0);
        }
        IoToken::new(0, self.begins)
    }

    fn poll_exec(&mut self, _token: IoToken, buf: IoBuf<'_>) -> Poll<StorageReceipt> {
        let (dir, len, none_buf) = match &buf {
            IoBuf::None => (Direction::None, 0, true),
            IoBuf::Read(b) => (Direction::ToHost, b.len(), false),
            IoBuf::Write(b) => (Direction::FromHost, b.len(), false),
        };
        self.polls = self.polls.saturating_add(1);
        self.bufs.push((dir, len as u32, none_buf));
        self.log.borrow_mut().push(Ev::Poll {
            dir,
            len: len as u32,
            none_buf,
        });
        if self.pending > 0 {
            self.pending -= 1;
            return Poll::Pending;
        }
        Poll::Ready(self.receipt)
    }

    fn cancel(&mut self, _token: IoToken) {
        self.cancels = self.cancels.saturating_add(1);
        self.log.borrow_mut().push(Ev::Cancel);
    }
}

/// Storage plane where the first operation (the required read) settles at once
/// and every later operation (the companion prefetch) answers `Pending` a
/// programmed number of times before it is ready.
struct CompanionStorage {
    log: Log,
    begins: u32,
    polls: u32,
    cancels: u32,
    prefetch_pending: u32,
}

impl CompanionStorage {
    fn new(log: Log, prefetch_pending: u32) -> Self {
        Self {
            log,
            begins: 0,
            polls: 0,
            cancels: 0,
            prefetch_pending,
        }
    }
}

impl Storage for CompanionStorage {
    fn begin_exec(&mut self, req: IoReq) -> IoToken {
        self.begins = self.begins.saturating_add(1);
        self.log.borrow_mut().push(Ev::Begin {
            dir: req.dir,
            len: req.len,
        });
        IoToken::new(0, self.begins)
    }

    fn poll_exec(&mut self, _token: IoToken, buf: IoBuf<'_>) -> Poll<StorageReceipt> {
        let len = match &buf {
            IoBuf::None => 0,
            IoBuf::Read(b) => b.len(),
            IoBuf::Write(b) => b.len(),
        };
        self.polls = self.polls.saturating_add(1);
        if self.begins >= 2 && self.prefetch_pending > 0 {
            self.prefetch_pending -= 1;
            return Poll::Pending;
        }
        Poll::Ready(StorageReceipt::ok(len))
    }

    fn cancel(&mut self, _token: IoToken) {
        self.cancels = self.cancels.saturating_add(1);
        self.log.borrow_mut().push(Ev::Cancel);
    }
}

/// Scripted transport: `pending` consecutive `Pending` answers, then a receipt
/// with the programmed accepted prefix/error.
struct SettleHost {
    log: Log,
    pending: u32,
    /// Polls answered `Ready` before `pending` starts applying.
    ready_before_pending: u32,
    accepted: Option<usize>,
    error: Option<Fault>,
    delivery: Delivery,
    publish_fault: Option<Fault>,
    publishes: u32,
    plans: Vec<DataPlan>,
    begins: u32,
    polls: u32,
    cancels: u32,
    /// Bytes accepted by a completed send, in order.
    sent: Vec<u8>,
}

impl SettleHost {
    fn ready(log: Log) -> Self {
        Self {
            log,
            pending: 0,
            ready_before_pending: 0,
            accepted: None,
            error: None,
            delivery: Delivery::Complete,
            publish_fault: None,
            publishes: 0,
            plans: Vec::new(),
            begins: 0,
            polls: 0,
            cancels: 0,
            sent: Vec::new(),
        }
    }

    fn pending_then(log: Log, pending: u32) -> Self {
        Self {
            pending,
            ..Self::ready(log)
        }
    }

    /// Answer `ready` polls at once, then keep answering `Pending`.
    fn ready_then_pending(log: Log, ready: u32, pending: u32) -> Self {
        Self {
            pending,
            ready_before_pending: ready,
            ..Self::ready(log)
        }
    }
}

impl HostTransport for SettleHost {
    fn publish(&mut self, plan: DataPlan) -> Result<(), Fault> {
        self.publishes = self.publishes.saturating_add(1);
        self.plans.push(plan);
        match self.publish_fault {
            Some(fault) => Err(fault),
            None => Ok(()),
        }
    }

    fn begin_recv(&mut self, _req: HostReq) -> HostToken {
        self.begins = self.begins.saturating_add(1);
        HostToken::new(0, self.begins)
    }

    fn begin_send(&mut self, _req: HostReq) -> HostToken {
        self.begins = self.begins.saturating_add(1);
        HostToken::new(0, self.begins)
    }

    fn poll_host(&mut self, _token: HostToken, buf: HostBuf<'_>) -> Poll<HostReceipt> {
        let (dir, len) = match &buf {
            HostBuf::Recv { buf: b, .. } => (Direction::FromHost, b.len()),
            HostBuf::Send { bytes: b, .. } => (Direction::ToHost, b.len()),
        };
        self.polls = self.polls.saturating_add(1);
        self.log.borrow_mut().push(Ev::HostPoll {
            dir,
            len: len as u32,
        });
        if self.ready_before_pending > 0 {
            self.ready_before_pending -= 1;
        } else if self.pending > 0 {
            self.pending -= 1;
            return Poll::Pending;
        }
        let accepted = self.accepted.unwrap_or(len);
        if let HostBuf::Send { bytes, .. } = buf {
            self.sent
                .extend_from_slice(&bytes[..accepted.min(bytes.len())]);
        }
        Poll::Ready(HostReceipt::from_adapter(accepted, self.error))
    }

    fn cancel(&mut self, _token: HostToken) {
        self.cancels = self.cancels.saturating_add(1);
        self.log.borrow_mut().push(Ev::HostCancel);
    }

    fn delivery(&self) -> Delivery {
        self.delivery
    }
}

/// Resident long-operation device: one scripted `PollStep` per `poll_long` entry.
struct LongDevice {
    steps: [Option<Step>; 4],
    cursor: usize,
    /// Projection reported by `long_info`; `Complete` settles it.
    long: LongInfo,
    medium: Option<NoMedium>,
    interrupts: u32,
    last_known: KnownEffects,
}

impl LongDevice {
    fn foreground() -> LongInfo {
        LongInfo {
            phase: LongPhase::Foreground,
            write_accessible: false,
            progress: Some(0),
            error: None,
        }
    }

    fn staged(steps: [Option<Step>; 4]) -> Self {
        Self {
            steps,
            cursor: 0,
            long: Self::foreground(),
            medium: Some(NoMedium),
            interrupts: 0,
            last_known: KnownEffects::NONE,
        }
    }
}

impl Device for LongDevice {
    type Medium = NoMedium;

    fn prepare(
        &mut self,
        _permit: &CommandPermit,
        _ctx: CommandContext,
        _cdb: &[u8],
    ) -> Result<(), Completion> {
        Ok(())
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
        _feedback: Feedback,
        _data: &'a mut [u8],
    ) -> PollStep<'a> {
        PollStep::Idle
    }

    fn poll_long<'a>(
        &mut self,
        _permit: &CommandPermit,
        _feedback: Feedback,
        data: &'a mut [u8],
    ) -> PollStep<'a> {
        let step = match self.steps.get(self.cursor).copied().flatten() {
            Some(step) => step,
            None => return PollStep::Idle,
        };
        self.cursor += 1;
        match step {
            Step::Read(len) => PollStep::Io(StorageOp::Read {
                resource: 1,
                offset: 0,
                buf: &mut data[..len],
            }),
            Step::Write(len) => PollStep::Io(StorageOp::Write {
                resource: 1,
                offset: 0,
                buf: &mut data[..len],
            }),
            Step::Sync => PollStep::Io(StorageOp::Sync { resource: 1 }),
            Step::Complete(completion) => {
                self.long = LongInfo {
                    phase: LongPhase::Settled,
                    write_accessible: true,
                    progress: Some(100),
                    error: None,
                };
                PollStep::Complete(completion)
            }
            // A long operation has no host phase and no second publish.
            Step::Publish(_)
            | Step::Prefetch(_)
            | Step::Receive(_)
            | Step::ReceiveCombined { .. }
            | Step::Send(_)
            | Step::SendCombined { .. } => PollStep::Idle,
        }
    }

    fn long_info(&self) -> LongInfo {
        self.long
    }

    fn interrupt(
        &mut self,
        _permit: &CommandPermit,
        _reason: InterruptReason,
        known: KnownEffects,
    ) -> Result<(), Fault> {
        self.interrupts = self.interrupts.saturating_add(1);
        self.last_known = known;
        Ok(())
    }

    fn finish_delivery(&mut self, _permit: &CommandPermit, _delivery: Delivery) {}

    fn take_medium(&mut self, _permit: &BoundaryPermit) -> Option<NoMedium> {
        let medium = self.medium.take();
        if medium.is_some() {
            // Detaching the medium discards the resident operation, like a real
            // drive (`MmcDrive::take_medium`).
            self.long = LongInfo::IDLE;
            self.cursor = self.steps.len();
        }
        medium
    }

    fn install_medium(
        &mut self,
        _permit: &BoundaryPermit,
        medium: NoMedium,
    ) -> Result<(), (NoMedium, Fault)> {
        self.medium = Some(medium);
        Ok(())
    }
}

type SettleTarget = Target<Cons<LuImpl<SettleDevice, u8>, Nil>>;
type LongTarget = Target<Cons<LuImpl<LongDevice, u8>, Nil>>;

fn settle_target(device: SettleDevice, backing: u8) -> SettleTarget {
    Target::new(cons(LuImpl::new(device, backing), Nil))
}

/// `CommandContext` with a declared host data phase.
fn ctx_data(direction: Direction, bytes: u64) -> CommandContext {
    CommandContext {
        lun: 0,
        lun_count: 1,
        host_bytes: bytes,
        host_direction: direction,
    }
}

/// A 512-byte Data-Out command (`WRITE(6)`), the standard pending-write script.
fn write_steps() -> [Option<Step>; SETTLE_SCRIPT] {
    [
        Some(Step::Publish(DataPlan {
            direction: Direction::FromHost,
            bytes: 512,
        })),
        Some(Step::Write(512)),
        Some(Step::Complete(Completion::Good)),
        None,
        None,
        None,
        None,
        None,
    ]
}

fn plan_512(direction: Direction) -> DataPlan {
    DataPlan {
        direction,
        bytes: 512,
    }
}

// ── Row 1: Stop is a drain ─────────────────────────────────────

/// `stop` closes submission and **drains** a pending write. The drain
/// polls the same token, merges the confirmed prefix into `known`, and only then
/// settles (`interrupt` → `finish_delivery(Failed)`). Nothing is cancelled, the
/// command is not replayed, and the pair is neither detached nor replaced.
#[test]
fn stop_drains_a_pending_write_and_merges_the_confirmed_prefix() {
    let log: Log = Rc::new(RefCell::new(Vec::new()));
    let mut target = settle_target(SettleDevice::new(log.clone(), write_steps()), 9);
    let mut storage = SettleStorage::pending_then(log.clone(), 1, StorageReceipt::ok(512));
    let mut host = SettleHost::ready(log.clone());
    let mut work = [0u8; 1024];
    let mut scratch = [0u8; 1024];

    assert_eq!(
        target.drive_start_static::<Here>(ctx_data(Direction::FromHost, 512), &[0x2A]),
        Ok(())
    );
    assert_eq!(
        target.drive_step_static::<Here>(&mut storage, &mut host, &mut work, &mut [], &mut scratch),
        Ok(DriveStep::Pending)
    );
    assert_eq!((storage.begins, storage.polls, storage.cancels), (1, 1, 0));

    target.stop();
    assert_eq!(
        target.tick(),
        RunOutcome::ServiceReady,
        "a drain still in flight must not be reported as `Ended`"
    );
    assert_eq!(
        target.drive_step_static::<Here>(&mut storage, &mut host, &mut work, &mut [], &mut scratch),
        Ok(DriveStep::Control(RunOutcome::Ended {
            reason: RunEnd::Stopped,
            error: None,
        }))
    );

    assert_eq!(
        storage.cancels, 0,
        "Stop drains a healthy token, never cancels"
    );
    assert_eq!(
        storage.begins, 1,
        "the same token is polled again, not re-issued"
    );
    assert_eq!(storage.polls, 2);

    let device = slot0(&target).device_ref();
    assert_eq!(device.interrupts, 1);
    assert_eq!(
        device.polls, 2,
        "the device produced `Publish` and `Write`; the drain does not poll it again"
    );
    assert!(
        device.seen.is_empty(),
        "the drained receipt is merged into `known`, never fed back (no replay)"
    );
    assert_eq!(
        device.last_known,
        Some(KnownEffects {
            confirmed_write: 512,
            ..KnownEffects::NONE
        }),
        "the drained receipt's confirmed prefix reaches the device"
    );
    assert_eq!(device.deliveries, vec![Delivery::Failed]);
    assert_eq!(
        (device.takes, device.installs),
        (0, 0),
        "Stop never detaches"
    );
    assert!(!device.active);
    assert!(
        at(&log, |e| matches!(e, Ev::Poll { .. }))
            < at(&log, |e| matches!(e, Ev::Interrupt { .. })),
        "the drained receipt is merged before `interrupt`"
    );
    assert!(
        at(&log, |e| matches!(e, Ev::Interrupt { .. }))
            < at(&log, |e| matches!(e, Ev::Delivery(_))),
        "`finish_delivery` books an already fixed completion"
    );

    assert_eq!(
        target.tick(),
        RunOutcome::Ended {
            reason: RunEnd::Stopped,
            error: None,
        }
    );
    assert_eq!(
        slot0(&target).backing_ref(),
        Some(&9),
        "no detach and no new medium after a Stop"
    );
    assert!(target.snapshot_static::<Here>().ready);
    assert_eq!(
        target.take_static_at::<Here>(0),
        Err(BoundaryReject::NothingToTake),
        "Stop produces no management result"
    );
    assert_eq!(
        target.drive_start_static::<Here>(ctx_data(Direction::FromHost, 512), &[0x2A]),
        Err(Fault::Boundary),
        "new submission stays closed"
    );
}

/// `03:60/83/118`: an errored receipt is still a **returned** fact. The drain
/// keeps its confirmed prefix, cancels the token for slot hygiene, and the
/// receipt's own `Effect` decides the remainder — no fabricated unknown.
#[test]
fn stop_drains_a_failing_write_and_keeps_the_confirmed_prefix() {
    let log: Log = Rc::new(RefCell::new(Vec::new()));
    let mut target = settle_target(SettleDevice::new(log.clone(), write_steps()), 9);
    let mut storage = SettleStorage::pending_then(
        log.clone(),
        1,
        StorageReceipt::failed(Fault::Io, 128, Effect::Known),
    );
    let mut host = SettleHost::ready(log.clone());
    let mut work = [0u8; 1024];
    let mut scratch = [0u8; 1024];

    target
        .drive_start_static::<Here>(ctx_data(Direction::FromHost, 512), &[0x2A])
        .expect("start");
    assert_eq!(
        target.drive_step_static::<Here>(&mut storage, &mut host, &mut work, &mut [], &mut scratch),
        Ok(DriveStep::Pending)
    );

    target.stop();
    assert_eq!(
        target.drive_step_static::<Here>(&mut storage, &mut host, &mut work, &mut [], &mut scratch),
        Ok(DriveStep::Control(RunOutcome::Ended {
            reason: RunEnd::Stopped,
            error: None,
        }))
    );

    assert_eq!(
        storage.cancels, 1,
        "the errored token is cancelled for slot hygiene"
    );
    let device = slot0(&target).device_ref();
    assert_eq!(
        device.last_known,
        Some(KnownEffects {
            confirmed_write: 128,
            ..KnownEffects::NONE
        }),
        "the returned prefix survives and `Effect::Known` keeps the remainder known"
    );
    assert_eq!(device.deliveries, vec![Delivery::Failed]);
    assert!(
        at(&log, |e| matches!(e, Ev::Cancel)) < at(&log, |e| matches!(e, Ev::Interrupt { .. })),
        "`cancel` returns before the settle"
    );
}

/// `03:60/83/118`: a Stop drain whose write receipt is `Fault::Contract` with
/// `Effect::Known` keeps the prefix, marks no unknown remainder, cancels once
/// for slot hygiene, and still returns `Control(Ended { Stopped })`.
#[test]
fn stop_drains_a_contract_write_receipt_without_fabricating_an_unknown_remainder() {
    let log: Log = Rc::new(RefCell::new(Vec::new()));
    let mut target = settle_target(SettleDevice::new(log.clone(), write_steps()), 9);
    let mut storage = SettleStorage::pending_then(
        log.clone(),
        1,
        StorageReceipt::failed(Fault::Contract, 128, Effect::Known),
    );
    let mut host = SettleHost::ready(log.clone());
    let mut work = [0u8; 1024];
    let mut scratch = [0u8; 1024];

    target
        .drive_start_static::<Here>(ctx_data(Direction::FromHost, 512), &[0x2A])
        .expect("start");
    assert_eq!(
        target.drive_step_static::<Here>(&mut storage, &mut host, &mut work, &mut [], &mut scratch),
        Ok(DriveStep::Pending)
    );

    target.stop();
    assert_eq!(
        target.drive_step_static::<Here>(&mut storage, &mut host, &mut work, &mut [], &mut scratch),
        Ok(DriveStep::Control(RunOutcome::Ended {
            reason: RunEnd::Stopped,
            error: None,
        })),
        "the Ended shape holds even for a `Contract` receipt"
    );

    assert_eq!(storage.cancels, 1);
    let device = slot0(&target).device_ref();
    assert_eq!(
        device.last_known,
        Some(KnownEffects {
            confirmed_write: 128,
            ..KnownEffects::NONE
        }),
        "the contract receipt's prefix is returned fact, not an unknown remainder"
    );
    assert_eq!(device.deliveries, vec![Delivery::Failed]);
    assert!(
        at(&log, |e| matches!(e, Ev::Cancel)) < at(&log, |e| matches!(e, Ev::Interrupt { .. }))
    );
}

/// `03:60/83/118/138-139`: a drained Sync whose receipt is `Fault::Contract`
/// with `Effect::Known` claims neither durability nor an unknown write
/// remainder; the token is still cancelled once.
#[test]
fn stop_drains_a_contract_sync_receipt_without_durability_or_an_unknown_remainder() {
    let log: Log = Rc::new(RefCell::new(Vec::new()));
    let mut target = settle_target(
        SettleDevice::new(
            log.clone(),
            [
                Some(Step::Publish(DataPlan {
                    direction: Direction::None,
                    bytes: 0,
                })),
                Some(Step::Sync),
                Some(Step::Complete(Completion::Good)),
                None,
                None,
                None,
                None,
                None,
            ],
        ),
        4,
    );
    let mut storage = SettleStorage::pending_then(
        log.clone(),
        1,
        StorageReceipt::failed(Fault::Contract, 0, Effect::Known),
    );
    let mut host = SettleHost::ready(log.clone());
    let mut work = [0u8; 64];
    let mut scratch = [0u8; 64];

    target
        .drive_start_static::<Here>(ctx_data(Direction::None, 0), &[0x35])
        .expect("start");
    assert_eq!(
        target.drive_step_static::<Here>(&mut storage, &mut host, &mut work, &mut [], &mut scratch),
        Ok(DriveStep::Pending)
    );
    target.stop();
    assert_eq!(
        target.drive_step_static::<Here>(&mut storage, &mut host, &mut work, &mut [], &mut scratch),
        Ok(DriveStep::Control(RunOutcome::Ended {
            reason: RunEnd::Stopped,
            error: None,
        }))
    );

    assert_eq!(storage.cancels, 1);
    assert_eq!(
        slot0(&target).device_ref().last_known,
        Some(KnownEffects::NONE),
        "an errored Sync is not durable and is not an unknown write remainder"
    );
}

/// `03:60/83/118`: a drained write receipt that reports
/// `Effect::UnknownRemainder` keeps both its confirmed prefix and the unknown
/// flag; the effect field, not the byte count, decides (`03:138-139`).
#[test]
fn stop_drains_a_write_receipt_that_reports_an_unknown_remainder() {
    let log: Log = Rc::new(RefCell::new(Vec::new()));
    let mut target = settle_target(SettleDevice::new(log.clone(), write_steps()), 9);
    let mut storage = SettleStorage::pending_then(
        log.clone(),
        1,
        StorageReceipt::failed(Fault::Io, 64, Effect::UnknownRemainder),
    );
    let mut host = SettleHost::ready(log.clone());
    let mut work = [0u8; 1024];
    let mut scratch = [0u8; 1024];

    target
        .drive_start_static::<Here>(ctx_data(Direction::FromHost, 512), &[0x2A])
        .expect("start");
    assert_eq!(
        target.drive_step_static::<Here>(&mut storage, &mut host, &mut work, &mut [], &mut scratch),
        Ok(DriveStep::Pending)
    );
    target.stop();
    assert_eq!(
        target.drive_step_static::<Here>(&mut storage, &mut host, &mut work, &mut [], &mut scratch),
        Ok(DriveStep::Control(RunOutcome::Ended {
            reason: RunEnd::Stopped,
            error: None,
        }))
    );

    assert_eq!(storage.cancels, 1);
    assert_eq!(
        slot0(&target).device_ref().last_known,
        Some(KnownEffects {
            confirmed_write: 64,
            unknown_remainder: true,
            ..KnownEffects::NONE
        })
    );
}

/// `03:60/83`: a Stop drain of an errored host receive keeps the accepted
/// prefix it already returned, does not fabricate a write remainder, and
/// cancels the token for slot hygiene.
#[test]
fn stop_drains_an_errored_host_receive_keeping_the_host_prefix() {
    let log: Log = Rc::new(RefCell::new(Vec::new()));
    let mut target = settle_target(
        SettleDevice::new(
            log.clone(),
            [
                Some(Step::Publish(plan_512(Direction::FromHost))),
                Some(Step::Receive(512)),
                Some(Step::Complete(Completion::Good)),
                None,
                None,
                None,
                None,
                None,
            ],
        ),
        5,
    );
    let mut storage = SettleStorage::ready(log.clone(), StorageReceipt::ok(0));
    let mut host = SettleHost {
        pending: 1,
        accepted: Some(256),
        error: Some(Fault::Io),
        ..SettleHost::ready(log.clone())
    };
    let mut work = [0u8; 1024];
    let mut scratch = [0u8; 1024];

    target
        .drive_start_static::<Here>(ctx_data(Direction::FromHost, 512), &[0x2A])
        .expect("start");
    assert_eq!(
        target.drive_step_static::<Here>(&mut storage, &mut host, &mut work, &mut [], &mut scratch),
        Ok(DriveStep::Pending)
    );
    target.stop();
    assert_eq!(
        target.drive_step_static::<Here>(&mut storage, &mut host, &mut work, &mut [], &mut scratch),
        Ok(DriveStep::Control(RunOutcome::Ended {
            reason: RunEnd::Stopped,
            error: None,
        }))
    );

    assert_eq!(host.cancels, 1, "the errored host token is cancelled");
    let device = slot0(&target).device_ref();
    assert_eq!(
        device.last_known,
        Some(KnownEffects {
            host_prefix: 256,
            ..KnownEffects::NONE
        }),
        "the returned accepted prefix survives; the remainder is not unknown"
    );
    assert_eq!(device.deliveries, vec![Delivery::Failed]);
    assert!(
        at(&log, |e| matches!(e, Ev::HostCancel)) < at(&log, |e| matches!(e, Ev::Interrupt { .. }))
    );
}

/// `03:60/83/118` +: a Stop drain of a pending **read** whose receipt is
/// `failed(Io, 0, Known)` keeps `NONE` (a read never fabricates a write/sync
/// remainder). The errored token is still cancelled for slot hygiene, which is
/// the widened drain handling this fixture pins.
#[test]
fn stop_drains_an_errored_read_without_fabricating_a_write_remainder() {
    let log: Log = Rc::new(RefCell::new(Vec::new()));
    let mut target = settle_target(
        SettleDevice::new(
            log.clone(),
            [
                Some(Step::Publish(plan_512(Direction::ToHost))),
                Some(Step::Read(512)),
                Some(Step::Complete(Completion::Good)),
                None,
                None,
                None,
                None,
                None,
            ],
        ),
        5,
    );
    let mut storage = SettleStorage::pending_then(
        log.clone(),
        1,
        StorageReceipt::failed(Fault::Io, 0, Effect::Known),
    );
    let mut host = SettleHost::ready(log.clone());
    let mut work = [0u8; 1024];
    let mut scratch = [0u8; 1024];

    target
        .drive_start_static::<Here>(ctx_data(Direction::ToHost, 512), &[0x28])
        .expect("start");
    assert_eq!(
        target.drive_step_static::<Here>(&mut storage, &mut host, &mut work, &mut [], &mut scratch),
        Ok(DriveStep::Pending)
    );
    target.stop();
    assert_eq!(
        target.drive_step_static::<Here>(&mut storage, &mut host, &mut work, &mut [], &mut scratch),
        Ok(DriveStep::Control(RunOutcome::Ended {
            reason: RunEnd::Stopped,
            error: None,
        }))
    );

    assert_eq!(
        storage.cancels, 1,
        "the errored token is cancelled for slot hygiene (any direction)"
    );
    assert_eq!(storage.begins, 1, "no replay");
    assert_eq!(
        slot0(&target).device_ref().last_known,
        Some(KnownEffects::NONE),
        "an errored read has no write effect and no unknown remainder"
    );
    assert_eq!(
        slot0(&target).device_ref().deliveries,
        vec![Delivery::Failed]
    );
    assert!(
        at(&log, |e| matches!(e, Ev::Cancel)) < at(&log, |e| matches!(e, Ev::Interrupt { .. }))
    );
}

/// A Sync is issued with `IoBuf::None` (`dir == None`, `len == 0`)
/// and a successful drain of it becomes `known.sync_durable`.
#[test]
fn stop_drains_a_pending_sync_into_a_durable_effect() {
    let log: Log = Rc::new(RefCell::new(Vec::new()));
    let mut target = settle_target(
        SettleDevice::new(
            log.clone(),
            [
                Some(Step::Publish(DataPlan {
                    direction: Direction::None,
                    bytes: 0,
                })),
                Some(Step::Sync),
                Some(Step::Complete(Completion::Good)),
                None,
                None,
                None,
                None,
                None,
            ],
        ),
        4,
    );
    let mut storage = SettleStorage::pending_then(log.clone(), 1, StorageReceipt::ok(0));
    let mut host = SettleHost::ready(log.clone());
    let mut work = [0u8; 64];
    let mut scratch = [0u8; 64];

    target
        .drive_start_static::<Here>(ctx_data(Direction::None, 0), &[0x35])
        .expect("start");
    assert_eq!(
        target.drive_step_static::<Here>(&mut storage, &mut host, &mut work, &mut [], &mut scratch),
        Ok(DriveStep::Pending)
    );
    target.stop();
    assert_eq!(
        target.drive_step_static::<Here>(&mut storage, &mut host, &mut work, &mut [], &mut scratch),
        Ok(DriveStep::Control(RunOutcome::Ended {
            reason: RunEnd::Stopped,
            error: None,
        }))
    );

    assert_eq!(
        storage.bufs,
        vec![(Direction::None, 0, true), (Direction::None, 0, true)],
        "a Sync is polled with `IoBuf::None`, never a zero-length read/write"
    );
    assert_eq!(storage.cancels, 0);
    let device = slot0(&target).device_ref();
    assert_eq!(
        device.last_known,
        Some(KnownEffects {
            sync_durable: true,
            ..KnownEffects::NONE
        }),
        "the drained Sync proves durability and nothing else"
    );
    assert_eq!(device.deliveries, vec![Delivery::Failed]);
}

/// A pending host **receive** drains across two steps; `tick` stays
/// `ServiceReady` until the drain settles, and the accepted prefix becomes
/// `known.host_prefix` without a cancel.
#[test]
fn stop_drains_a_pending_host_receive_across_two_steps() {
    let log: Log = Rc::new(RefCell::new(Vec::new()));
    let mut target = settle_target(
        SettleDevice::new(
            log.clone(),
            [
                Some(Step::Publish(plan_512(Direction::FromHost))),
                Some(Step::Receive(512)),
                Some(Step::Complete(Completion::Good)),
                None,
                None,
                None,
                None,
                None,
            ],
        ),
        5,
    );
    let mut storage = SettleStorage::ready(log.clone(), StorageReceipt::ok(0));
    let mut host = SettleHost::pending_then(log.clone(), 2);
    let mut work = [0u8; 1024];
    let mut scratch = [0u8; 1024];

    target
        .drive_start_static::<Here>(ctx_data(Direction::FromHost, 512), &[0x2A])
        .expect("start");
    assert_eq!(
        target.drive_step_static::<Here>(&mut storage, &mut host, &mut work, &mut [], &mut scratch),
        Ok(DriveStep::Pending)
    );
    assert_eq!((host.begins, host.polls, host.cancels), (1, 1, 0));

    target.stop();
    assert_eq!(
        target.drive_step_static::<Here>(&mut storage, &mut host, &mut work, &mut [], &mut scratch),
        Ok(DriveStep::Pending),
        "the drain keeps the same host token"
    );
    assert_eq!(target.tick(), RunOutcome::ServiceReady);
    assert_eq!(
        target.drive_step_static::<Here>(&mut storage, &mut host, &mut work, &mut [], &mut scratch),
        Ok(DriveStep::Control(RunOutcome::Ended {
            reason: RunEnd::Stopped,
            error: None,
        }))
    );

    assert_eq!(host.polls, 3, "one host token, polled three times");
    assert_eq!(host.begins, 1, "never re-issued");
    assert_eq!(
        host.cancels, 0,
        "a healthy host phase is drained, not cancelled"
    );
    assert_eq!(
        storage.begins, 0,
        "no storage operation for a host-only phase"
    );
    assert_eq!(
        slot0(&target).device_ref().last_known,
        Some(KnownEffects {
            host_prefix: 512,
            ..KnownEffects::NONE
        })
    );
}

/// Same drain for a pending host **send** (Data-In). A send leaves no
/// unknown write remainder.
#[test]
fn stop_drains_a_pending_host_send() {
    let log: Log = Rc::new(RefCell::new(Vec::new()));
    let mut target = settle_target(
        SettleDevice::new(
            log.clone(),
            [
                Some(Step::Publish(plan_512(Direction::ToHost))),
                Some(Step::Send(512)),
                Some(Step::Complete(Completion::Good)),
                None,
                None,
                None,
                None,
                None,
            ],
        ),
        6,
    );
    let mut storage = SettleStorage::ready(log.clone(), StorageReceipt::ok(0));
    let mut host = SettleHost::pending_then(log.clone(), 1);
    let mut work = [0u8; 1024];
    let mut scratch = [0u8; 1024];

    target
        .drive_start_static::<Here>(ctx_data(Direction::ToHost, 512), &[0x28])
        .expect("start");
    assert_eq!(
        target.drive_step_static::<Here>(&mut storage, &mut host, &mut work, &mut [], &mut scratch),
        Ok(DriveStep::Pending)
    );
    target.stop();
    assert_eq!(
        target.drive_step_static::<Here>(&mut storage, &mut host, &mut work, &mut [], &mut scratch),
        Ok(DriveStep::Control(RunOutcome::Ended {
            reason: RunEnd::Stopped,
            error: None,
        }))
    );

    assert_eq!(host.cancels, 0);
    let device = slot0(&target).device_ref();
    assert_eq!(
        device.last_known,
        Some(KnownEffects {
            host_prefix: 512,
            ..KnownEffects::NONE
        }),
        "a Data-In send has no write effect to call unknown"
    );
    assert_eq!(device.deliveries, vec![Delivery::Failed]);
}

/// (preparing, IO not yet issued): Stop settles with the honest empty
/// `KnownEffects` — nothing was issued, so nothing is claimed or marked
/// unknown — and does not invent IO.
#[test]
fn stop_with_no_io_in_flight_settles_with_no_effects() {
    let log: Log = Rc::new(RefCell::new(Vec::new()));
    let mut target = settle_target(SettleDevice::new(log.clone(), [None; SETTLE_SCRIPT]), 3);
    let mut storage = SettleStorage::ready(log.clone(), StorageReceipt::ok(0));
    let mut host = SettleHost::ready(log.clone());
    let mut work = [0u8; 64];
    let mut scratch = [0u8; 64];

    target
        .drive_start_static::<Here>(ctx_data(Direction::FromHost, 512), &[0x2A])
        .expect("start");
    target.stop();
    assert_eq!(
        target.drive_step_static::<Here>(&mut storage, &mut host, &mut work, &mut [], &mut scratch),
        Ok(DriveStep::Control(RunOutcome::Ended {
            reason: RunEnd::Stopped,
            error: None,
        }))
    );

    assert_eq!((storage.begins, host.begins), (0, 0), "nothing is issued");
    let device = slot0(&target).device_ref();
    assert_eq!(device.interrupts, 1);
    assert_eq!(
        events(&log)
            .into_iter()
            .find(|e| matches!(e, Ev::Interrupt { .. })),
        Some(Ev::Interrupt {
            reason: InterruptReason::Stop,
            known: KnownEffects::NONE,
        })
    );
    assert_eq!(device.last_known, Some(KnownEffects::NONE));
    assert_eq!(device.deliveries, vec![Delivery::Failed]);
}

/// A drained speculative prefetch never manufactures a write `Unknown`.
/// Stop ends the command, so no completion is expected or asserted here — only
/// the absence of a write remainder (and the lack of a cancel) is pinned.
#[test]
fn stop_drains_a_speculative_prefetch_without_an_unknown_remainder() {
    let log: Log = Rc::new(RefCell::new(Vec::new()));
    let mut target = settle_target(
        SettleDevice::new(
            log.clone(),
            [
                Some(Step::Publish(plan_512(Direction::ToHost))),
                Some(Step::Prefetch(64)),
                Some(Step::Complete(Completion::Good)),
                None,
                None,
                None,
                None,
                None,
            ],
        ),
        7,
    );
    let mut storage = SettleStorage::pending_then(log.clone(), 1, StorageReceipt::ok(64));
    let mut host = SettleHost::ready(log.clone());
    let mut work = [0u8; 1024];
    let mut scratch = [0u8; 1024];

    target
        .drive_start_static::<Here>(ctx_data(Direction::ToHost, 512), &[0x28])
        .expect("start");
    assert_eq!(
        target.drive_step_static::<Here>(&mut storage, &mut host, &mut work, &mut [], &mut scratch),
        Ok(DriveStep::Pending)
    );
    target.stop();
    assert_eq!(
        target.drive_step_static::<Here>(&mut storage, &mut host, &mut work, &mut [], &mut scratch),
        Ok(DriveStep::Control(RunOutcome::Ended {
            reason: RunEnd::Stopped,
            error: None,
        }))
    );

    assert_eq!(storage.cancels, 0);
    assert_eq!(
        slot0(&target).device_ref().last_known,
        Some(KnownEffects::NONE),
        "a read leaves no write effect and no unknown remainder"
    );
}

/// (work-bank identity): a step that passes a different work bank cannot
/// re-borrow the retained window. The step entry cancels the token once and
/// settles; it must not spin, re-issue, or reinterpret the token against the
/// wrong bytes.
#[test]
fn a_step_with_a_changed_work_bank_cancels_the_retained_token_once() {
    let log: Log = Rc::new(RefCell::new(Vec::new()));
    let mut target = settle_target(SettleDevice::new(log.clone(), write_steps()), 2);
    let mut storage = SettleStorage::pending_then(log.clone(), 1, StorageReceipt::ok(512));
    let mut host = SettleHost::ready(log.clone());
    let mut work = [0u8; 1024];
    let mut scratch = [0u8; 1024];
    let mut other = [0u8; 1024];

    target
        .drive_start_static::<Here>(ctx_data(Direction::FromHost, 512), &[0x2A])
        .expect("start");
    assert_eq!(
        target.drive_step_static::<Here>(&mut storage, &mut host, &mut work, &mut [], &mut scratch),
        Ok(DriveStep::Pending)
    );
    target.stop();
    // A different work bank cannot re-borrow the retained window.
    assert_eq!(
        target.drive_step_static::<Here>(
            &mut storage,
            &mut host,
            &mut other,
            &mut [],
            &mut scratch
        ),
        Err(Fault::Contract)
    );
    assert_eq!(storage.cancels, 1, "the token is cancelled before settling");
    assert_eq!(storage.begins, 1, "no re-issue");
    let device = slot0(&target).device_ref();
    assert_eq!(device.interrupts, 1, "exactly one bounded settle");
    assert_eq!(device.deliveries, vec![Delivery::Failed]);
    assert!(
        at(&log, |e| matches!(e, Ev::Cancel)) < at(&log, |e| matches!(e, Ev::Interrupt { .. }))
    );
}

// ── Row 2: link loss / `fatal` / `Abort` cancel ─────────────────────────────

/// (link loss): the pending token is cancelled **before**
/// `interrupt`; a write remainder becomes unknown; the service ends only after
/// the settlement.
#[test]
fn link_loss_cancels_the_pending_write_before_the_interrupt() {
    let log: Log = Rc::new(RefCell::new(Vec::new()));
    let mut target = settle_target(SettleDevice::new(log.clone(), write_steps()), 9);
    let mut storage = SettleStorage::pending_then(log.clone(), 1, StorageReceipt::ok(512));
    let mut host = SettleHost::ready(log.clone());
    let mut work = [0u8; 1024];
    let mut scratch = [0u8; 1024];

    target
        .drive_start_static::<Here>(ctx_data(Direction::FromHost, 512), &[0x2A])
        .expect("start");
    assert_eq!(
        target.drive_step_static::<Here>(&mut storage, &mut host, &mut work, &mut [], &mut scratch),
        Ok(DriveStep::Pending)
    );

    target.link_lost_static::<Here>(&mut storage, &mut host, &mut work, &mut scratch);

    assert_eq!(storage.cancels, 1, "link loss cancels exactly once");
    assert_eq!(
        storage.polls, 1,
        "the token is cancelled, not polled to Ready"
    );
    assert_eq!(storage.begins, 1, "no replay");
    let device = slot0(&target).device_ref();
    assert_eq!(
        device.last_known,
        Some(KnownEffects {
            unknown_remainder: true,
            ..KnownEffects::NONE
        }),
        "an unobserved pending write keeps an unknown remainder"
    );
    assert_eq!(device.deliveries, vec![Delivery::Failed]);
    assert_eq!((device.takes, device.installs), (0, 0));
    assert!(
        at(&log, |e| matches!(e, Ev::Cancel)) < at(&log, |e| matches!(e, Ev::Interrupt { .. })),
        "`cancel` returns before `interrupt`"
    );
    assert!(
        at(&log, |e| matches!(e, Ev::Interrupt { .. }))
            < at(&log, |e| matches!(e, Ev::Delivery(_)))
    );

    assert_eq!(
        target.tick(),
        RunOutcome::ServiceReady,
        "a lost link does not end the target"
    );
    // A late event cannot act on a settled command or a new medium.
    assert_eq!(
        target.drive_step_static::<Here>(&mut storage, &mut host, &mut work, &mut [], &mut scratch),
        Err(Fault::Contract)
    );
    assert_eq!(storage.begins, 1);
    assert_eq!(slot0(&target).device_ref().interrupts, 1);
}

/// ("读取取消不凭空制造写入 Unknown"): an immediate cancel of a pending
/// *read* settles with no write/sync remainder and no confirmed write prefix,
/// even though the cancelled token is reported exactly once.
#[test]
fn link_loss_cancels_a_pending_read_without_an_unknown_remainder() {
    let log: Log = Rc::new(RefCell::new(Vec::new()));
    let mut target = settle_target(
        SettleDevice::new(
            log.clone(),
            [
                Some(Step::Publish(plan_512(Direction::ToHost))),
                Some(Step::Read(512)),
                Some(Step::Complete(Completion::Good)),
                None,
                None,
                None,
                None,
                None,
            ],
        ),
        5,
    );
    let mut storage = SettleStorage::pending_then(log.clone(), 1, StorageReceipt::ok(512));
    let mut host = SettleHost::ready(log.clone());
    let mut work = [0u8; 1024];
    let mut scratch = [0u8; 1024];

    target
        .drive_start_static::<Here>(ctx_data(Direction::ToHost, 512), &[0x28])
        .expect("start");
    assert_eq!(
        target.drive_step_static::<Here>(&mut storage, &mut host, &mut work, &mut [], &mut scratch),
        Ok(DriveStep::Pending)
    );

    target.link_lost_static::<Here>(&mut storage, &mut host, &mut work, &mut scratch);

    assert_eq!(
        (storage.begins, storage.polls),
        (1, 1),
        "cancelled, not polled"
    );
    assert_eq!(storage.cancels, 1);
    let device = slot0(&target).device_ref();
    assert_eq!(
        device.last_known,
        Some(KnownEffects::NONE),
        "a cancelled read has no write effect and no unknown remainder"
    );
    assert_eq!(device.deliveries, vec![Delivery::Failed]);
}

/// (fatal): a pending host token is cancelled first, the settle carries the
/// host prefix/unknown facts, and `tick` reports the first fault once settled.
#[test]
fn fatal_cancels_a_pending_host_token_before_the_interrupt() {
    let log: Log = Rc::new(RefCell::new(Vec::new()));
    let mut target = settle_target(
        SettleDevice::new(
            log.clone(),
            [
                Some(Step::Publish(plan_512(Direction::FromHost))),
                Some(Step::Receive(512)),
                Some(Step::Complete(Completion::Good)),
                None,
                None,
                None,
                None,
                None,
            ],
        ),
        5,
    );
    let mut storage = SettleStorage::ready(log.clone(), StorageReceipt::ok(0));
    let mut host = SettleHost::pending_then(log.clone(), 2);
    let mut work = [0u8; 1024];
    let mut scratch = [0u8; 1024];

    target
        .drive_start_static::<Here>(ctx_data(Direction::FromHost, 512), &[0x2A])
        .expect("start");
    assert_eq!(
        target.drive_step_static::<Here>(&mut storage, &mut host, &mut work, &mut [], &mut scratch),
        Ok(DriveStep::Pending)
    );

    target.fatal(Fault::NeedsRecovery);
    assert_eq!(target.tick(), RunOutcome::ServiceReady);
    assert_eq!(
        target.drive_step_static::<Here>(&mut storage, &mut host, &mut work, &mut [], &mut scratch),
        Ok(DriveStep::Control(RunOutcome::Ended {
            reason: RunEnd::Fatal,
            error: Some(Fault::NeedsRecovery),
        }))
    );

    assert_eq!(host.cancels, 1, "the pending host token is cancelled");
    assert_eq!(host.polls, 1, "no further poll of a cancelled token");
    let device = slot0(&target).device_ref();
    assert_eq!(
        device.last_known,
        Some(KnownEffects {
            host_prefix: 0,
            unknown_remainder: true,
            ..KnownEffects::NONE
        }),
        "a dropped receive is an unknown write remainder"
    );
    assert_eq!(device.deliveries, vec![Delivery::Failed]);
    assert!(
        at(&log, |e| matches!(e, Ev::HostCancel)) < at(&log, |e| matches!(e, Ev::Interrupt { .. }))
    );
    assert_eq!(
        target.tick(),
        RunOutcome::Ended {
            reason: RunEnd::Fatal,
            error: Some(Fault::NeedsRecovery),
        }
    );
}

/// `03:120-125`: `fatal` cancels a pending storage **write** before `interrupt`,
/// marks the unobserved remainder unknown, and the service ends only after the
/// settlement.
#[test]
fn fatal_cancels_a_pending_storage_write_before_the_interrupt() {
    let log: Log = Rc::new(RefCell::new(Vec::new()));
    let mut target = settle_target(SettleDevice::new(log.clone(), write_steps()), 9);
    let mut storage = SettleStorage::pending_then(log.clone(), 1, StorageReceipt::ok(512));
    let mut host = SettleHost::ready(log.clone());
    let mut work = [0u8; 1024];
    let mut scratch = [0u8; 1024];

    target
        .drive_start_static::<Here>(ctx_data(Direction::FromHost, 512), &[0x2A])
        .expect("start");
    assert_eq!(
        target.drive_step_static::<Here>(&mut storage, &mut host, &mut work, &mut [], &mut scratch),
        Ok(DriveStep::Pending)
    );

    target.fatal(Fault::Io);
    assert_eq!(
        target.tick(),
        RunOutcome::ServiceReady,
        "the settle is still owed, so the end is not reported yet"
    );
    assert_eq!(
        target.drive_step_static::<Here>(&mut storage, &mut host, &mut work, &mut [], &mut scratch),
        Ok(DriveStep::Control(RunOutcome::Ended {
            reason: RunEnd::Fatal,
            error: Some(Fault::Io),
        }))
    );

    assert_eq!(storage.cancels, 1, "fatal cancels exactly once");
    assert_eq!(storage.polls, 1, "the token is cancelled, not drained");
    assert_eq!(storage.begins, 1, "no replay");
    let device = slot0(&target).device_ref();
    assert_eq!(
        device.last_known,
        Some(KnownEffects {
            unknown_remainder: true,
            ..KnownEffects::NONE
        }),
        "a cancelled pending write keeps an unknown remainder"
    );
    assert_eq!(device.deliveries, vec![Delivery::Failed]);
    assert!(
        at(&log, |e| matches!(e, Ev::Cancel)) < at(&log, |e| matches!(e, Ev::Interrupt { .. }))
    );
    assert_eq!(
        target.tick(),
        RunOutcome::Ended {
            reason: RunEnd::Fatal,
            error: Some(Fault::Io),
        }
    );
}

/// `Control::Abort` cancels the pending send, settles once, and returns
/// `0B/45/00` without detaching the medium or ending the target.
#[test]
fn abort_of_a_pending_send_returns_aborted_command_without_detaching() {
    let log: Log = Rc::new(RefCell::new(Vec::new()));
    let mut target = settle_target(
        SettleDevice::new(
            log.clone(),
            [
                Some(Step::Publish(plan_512(Direction::ToHost))),
                Some(Step::Send(512)),
                Some(Step::Complete(Completion::Good)),
                None,
                None,
                None,
                None,
                None,
            ],
        ),
        6,
    );
    let mut storage = SettleStorage::ready(log.clone(), StorageReceipt::ok(0));
    let mut host = SettleHost::pending_then(log.clone(), 2);
    let mut work = [0u8; 1024];
    let mut scratch = [0u8; 1024];

    target
        .drive_start_static::<Here>(ctx_data(Direction::ToHost, 512), &[0x28])
        .expect("start");
    assert_eq!(
        target.drive_step_static::<Here>(&mut storage, &mut host, &mut work, &mut [], &mut scratch),
        Ok(DriveStep::Pending)
    );

    assert_eq!(target.request_control(Control::Abort), Ok(()));
    assert_eq!(
        target.drive_step_static::<Here>(&mut storage, &mut host, &mut work, &mut [], &mut scratch),
        Ok(DriveStep::Done(Completion::Check(Sense::new(
            0x0B, 0x45, 0x00
        ))))
    );

    assert_eq!(host.cancels, 1);
    assert_eq!(host.polls, 1, "the cancelled token is not polled again");
    let device = slot0(&target).device_ref();
    assert_eq!(device.interrupts, 1);
    assert_eq!(
        device.last_known,
        Some(KnownEffects::NONE),
        "a cancelled send has no write effect"
    );
    assert_eq!(device.deliveries, vec![Delivery::Failed]);
    assert_eq!(
        (device.takes, device.installs),
        (0, 0),
        "Abort never detaches"
    );
    assert!(device.medium.is_some());
    assert_eq!(slot0(&target).backing_ref(), Some(&6));
    assert!(!slot0(&target).has_result());
    assert!(
        at(&log, |e| matches!(e, Ev::HostCancel)) < at(&log, |e| matches!(e, Ev::Interrupt { .. }))
    );
    // Abort ends the command only: the target keeps serving.
    assert_eq!(target.tick(), RunOutcome::ServiceReady);
    assert_eq!(
        target.take_static_at::<Here>(0),
        Err(BoundaryReject::NothingToTake)
    );
    // The abort was consumed; a late step has nothing to settle.
    assert_eq!(
        target.drive_step_static::<Here>(&mut storage, &mut host, &mut work, &mut [], &mut scratch),
        Err(Fault::Contract)
    );
    assert_eq!(slot0(&target).device_ref().interrupts, 1);
}

/// An Abort of a pending write reports the unknown remainder instead of a
/// fabricated clean state.
#[test]
fn abort_of_a_pending_write_reports_the_unknown_remainder() {
    let log: Log = Rc::new(RefCell::new(Vec::new()));
    let mut target = settle_target(SettleDevice::new(log.clone(), write_steps()), 9);
    let mut storage = SettleStorage::pending_then(log.clone(), 1, StorageReceipt::ok(512));
    let mut host = SettleHost::ready(log.clone());
    let mut work = [0u8; 1024];
    let mut scratch = [0u8; 1024];

    target
        .drive_start_static::<Here>(ctx_data(Direction::FromHost, 512), &[0x2A])
        .expect("start");
    assert_eq!(
        target.drive_step_static::<Here>(&mut storage, &mut host, &mut work, &mut [], &mut scratch),
        Ok(DriveStep::Pending)
    );
    assert_eq!(target.request_control(Control::Abort), Ok(()));
    assert_eq!(
        target.drive_step_static::<Here>(&mut storage, &mut host, &mut work, &mut [], &mut scratch),
        Ok(DriveStep::Done(Completion::Check(Sense::new(
            0x0B, 0x45, 0x00
        ))))
    );

    assert_eq!(storage.cancels, 1);
    assert_eq!(
        slot0(&target).device_ref().last_known,
        Some(KnownEffects {
            unknown_remainder: true,
            ..KnownEffects::NONE
        })
    );
}

// ── Row 3: injection points ────────────────────────────────────────────────

/// (`begin_exec` before issue): a pool-exhausted (invalid) token means no
/// operation exists, so the settle carries no fabricated effect and nothing is
/// polled.
#[test]
fn a_pool_exhausted_token_settles_without_an_adapter_operation() {
    let log: Log = Rc::new(RefCell::new(Vec::new()));
    let mut target = settle_target(SettleDevice::new(log.clone(), write_steps()), 9);
    let mut storage = SettleStorage::exhausted(log.clone());
    let mut host = SettleHost::ready(log.clone());
    let mut work = [0u8; 1024];
    let mut scratch = [0u8; 1024];

    target
        .drive_start_static::<Here>(ctx_data(Direction::FromHost, 512), &[0x2A])
        .expect("start");
    assert_eq!(
        target.drive_step_static::<Here>(&mut storage, &mut host, &mut work, &mut [], &mut scratch),
        Err(Fault::Contract)
    );
    assert_eq!((storage.begins, storage.polls, storage.cancels), (1, 0, 0));
    let device = slot0(&target).device_ref();
    assert_eq!(
        device.last_known,
        Some(KnownEffects::NONE),
        "nothing was issued, so nothing can be unknown"
    );
    assert_eq!(device.deliveries, vec![Delivery::Failed]);
    assert!(!device.active);
    assert_eq!(
        target.tick(),
        RunOutcome::ServiceReady,
        "a runner-side contract fault settles the command, not the service"
    );
}

/// (`Ready(Err(n))`): the receipt error reaches the device exactly once;
/// the operation is never replayed, and a command that completed normally is
/// never interrupted afterwards — a late link loss does not roll back an
/// already booked status.
#[test]
fn a_receipt_error_is_fed_back_once_and_never_replayed() {
    let log: Log = Rc::new(RefCell::new(Vec::new()));
    let mut target = settle_target(
        SettleDevice::new(
            log.clone(),
            [
                Some(Step::Publish(plan_512(Direction::FromHost))),
                Some(Step::Write(512)),
                Some(Step::Complete(Completion::Check(WRITE_ERROR))),
                None,
                None,
                None,
                None,
                None,
            ],
        ),
        9,
    );
    let mut storage = SettleStorage::pending_then(
        log.clone(),
        1,
        StorageReceipt::failed(Fault::Io, 128, Effect::Known),
    );
    let mut host = SettleHost::ready(log.clone());
    let mut work = [0u8; 1024];
    let mut scratch = [0u8; 1024];

    target
        .drive_start_static::<Here>(ctx_data(Direction::FromHost, 512), &[0x2A])
        .expect("start");
    assert_eq!(
        target.drive_step_static::<Here>(&mut storage, &mut host, &mut work, &mut [], &mut scratch),
        Ok(DriveStep::Pending)
    );
    assert_eq!(
        target.drive_step_static::<Here>(&mut storage, &mut host, &mut work, &mut [], &mut scratch),
        Ok(DriveStep::Done(Completion::Check(WRITE_ERROR)))
    );

    assert_eq!(storage.begins, 1, "one operation, never replayed");
    assert_eq!(storage.polls, 2, "the same token: Pending, then Ready");
    assert_eq!(storage.cancels, 0);
    let device = slot0(&target).device_ref();
    assert_eq!(
        device.seen,
        vec![(128, Some(Fault::Io))],
        "the trustworthy prefix and the error reach the device once"
    );
    assert_eq!(
        device.interrupts, 0,
        "a completed command is not interrupted"
    );
    assert_eq!(device.deliveries, vec![Delivery::Complete]);

    // The full-status-sent hook already ran; a later transport failure must not
    // re-book delivery or interrupt the device again.
    target.link_lost_static::<Here>(&mut storage, &mut host, &mut work, &mut scratch);
    assert_eq!(target.tick(), RunOutcome::ServiceReady);
    let device = slot0(&target).device_ref();
    assert_eq!(device.deliveries, vec![Delivery::Complete]);
    assert_eq!(device.interrupts, 0);
    assert_eq!(storage.begins, 1);
}

/// ("receipt 已返回") +: a returned receipt is authoritative for its
/// own facts. An adapter receipt that breaks the contract settles the command
/// before the device is polled again, the confirmed write prefix it reports is
/// preserved, and `unknown_remainder` follows the receipt's `Effect` — a
/// `Fault::Contract` alone never fabricates uncertainty.
#[test]
fn a_contract_receipt_settles_before_the_next_poll() {
    let log: Log = Rc::new(RefCell::new(Vec::new()));
    let mut target = settle_target(SettleDevice::new(log.clone(), write_steps()), 9);
    let mut storage = SettleStorage::ready(
        log.clone(),
        StorageReceipt::failed(Fault::Contract, 128, Effect::Known),
    );
    let mut host = SettleHost::ready(log.clone());
    let mut work = [0u8; 1024];
    let mut scratch = [0u8; 1024];

    target
        .drive_start_static::<Here>(ctx_data(Direction::FromHost, 512), &[0x2A])
        .expect("start");
    assert_eq!(
        target.drive_step_static::<Here>(&mut storage, &mut host, &mut work, &mut [], &mut scratch),
        Err(Fault::Contract)
    );

    assert_eq!(
        (storage.begins, storage.polls),
        (1, 1),
        "one operation, one poll"
    );
    let device = slot0(&target).device_ref();
    assert_eq!(
        device.polls, 2,
        "the device produced `Publish` and `Write`; the contract receipt is not polled back"
    );
    assert_eq!(
        device.seen,
        Vec::new(),
        "a contract receipt is never mapped into device facts"
    );
    assert_eq!(
        device.last_known,
        Some(KnownEffects {
            confirmed_write: 128,
            ..KnownEffects::NONE
        }),
        "the returned confirmed prefix survives the contract settle"
    );
    assert_eq!(device.deliveries, vec![Delivery::Failed]);
    assert_eq!(device.interrupts, 1, "exactly one bounded settle");
    // The command is gone: another step cannot replay the write.
    assert_eq!(
        target.drive_step_static::<Here>(&mut storage, &mut host, &mut work, &mut [], &mut scratch),
        Err(Fault::Contract)
    );
    assert_eq!((storage.begins, storage.polls), (1, 1), "no replay");
}

/// (`Ready(n > requested)` / `Effect::UnknownRemainder`): the effect on the
/// returned receipt stays authoritative. A write receipt that reports both a
/// confirmed prefix and an unknown remainder reaches the device with both,
/// instead of being flattened to a clean or a fabricated state.
#[test]
fn a_contract_receipt_with_an_unknown_effect_keeps_the_remainder_unknown() {
    let log: Log = Rc::new(RefCell::new(Vec::new()));
    let mut target = settle_target(SettleDevice::new(log.clone(), write_steps()), 9);
    let mut storage = SettleStorage::ready(
        log.clone(),
        StorageReceipt::failed(Fault::Contract, 32, Effect::UnknownRemainder),
    );
    let mut host = SettleHost::ready(log.clone());
    let mut work = [0u8; 1024];
    let mut scratch = [0u8; 1024];

    target
        .drive_start_static::<Here>(ctx_data(Direction::FromHost, 512), &[0x2A])
        .expect("start");
    assert_eq!(
        target.drive_step_static::<Here>(&mut storage, &mut host, &mut work, &mut [], &mut scratch),
        Err(Fault::Contract)
    );

    let device = slot0(&target).device_ref();
    assert_eq!(
        device.last_known,
        Some(KnownEffects {
            confirmed_write: 32,
            unknown_remainder: true,
            ..KnownEffects::NONE
        }),
        "the receipt's `Effect::UnknownRemainder` is honoured, not guessed"
    );
    assert_eq!(device.seen, Vec::new());
    assert_eq!(device.deliveries, vec![Delivery::Failed]);
}

/// ("读取取消不凭空制造写入 Unknown"): a read never carries a write/sync
/// remainder. Even a contract-violating read receipt that claims
/// `Effect::UnknownRemainder` cannot make the runner report one.
#[test]
fn a_contract_receipt_from_a_read_never_fabricates_an_unknown_remainder() {
    let log: Log = Rc::new(RefCell::new(Vec::new()));
    let mut target = settle_target(
        SettleDevice::new(
            log.clone(),
            [
                Some(Step::Publish(plan_512(Direction::ToHost))),
                Some(Step::Read(512)),
                Some(Step::Complete(Completion::Good)),
                None,
                None,
                None,
                None,
                None,
            ],
        ),
        5,
    );
    let mut storage = SettleStorage::ready(
        log.clone(),
        StorageReceipt::failed(Fault::Contract, 0, Effect::UnknownRemainder),
    );
    let mut host = SettleHost::ready(log.clone());
    let mut work = [0u8; 1024];
    let mut scratch = [0u8; 1024];

    target
        .drive_start_static::<Here>(ctx_data(Direction::ToHost, 512), &[0x28])
        .expect("start");
    assert_eq!(
        target.drive_step_static::<Here>(&mut storage, &mut host, &mut work, &mut [], &mut scratch),
        Err(Fault::Contract)
    );

    assert_eq!((storage.begins, storage.polls), (1, 1));
    let device = slot0(&target).device_ref();
    assert_eq!(device.polls, 2, "no device poll after the returned receipt");
    assert_eq!(device.seen, Vec::new());
    assert_eq!(
        device.last_known,
        Some(KnownEffects::NONE),
        "a read leaves no write/sync remainder, whatever the receipt claims"
    );
    assert_eq!(device.deliveries, vec![Delivery::Failed]);
}

/// `03:60`: a returned host receipt is authoritative even when it carries
/// `Fault::Contract`. A pending send whose receipt reports 256 accepted bytes
/// settles with that `host_prefix` and never fabricates a write remainder.
#[test]
fn a_contract_host_send_receipt_keeps_the_accepted_prefix() {
    let log: Log = Rc::new(RefCell::new(Vec::new()));
    let mut target = settle_target(
        SettleDevice::new(
            log.clone(),
            [
                Some(Step::Publish(plan_512(Direction::ToHost))),
                Some(Step::Send(512)),
                Some(Step::Complete(Completion::Good)),
                None,
                None,
                None,
                None,
                None,
            ],
        ),
        6,
    );
    let mut storage = SettleStorage::ready(log.clone(), StorageReceipt::ok(0));
    let mut host = SettleHost {
        pending: 1,
        accepted: Some(256),
        error: Some(Fault::Contract),
        ..SettleHost::ready(log.clone())
    };
    let mut work = [0u8; 1024];
    let mut scratch = [0u8; 1024];

    target
        .drive_start_static::<Here>(ctx_data(Direction::ToHost, 512), &[0x28])
        .expect("start");
    assert_eq!(
        target.drive_step_static::<Here>(&mut storage, &mut host, &mut work, &mut [], &mut scratch),
        Ok(DriveStep::Pending)
    );
    assert_eq!(
        target.drive_step_static::<Here>(&mut storage, &mut host, &mut work, &mut [], &mut scratch),
        Err(Fault::Contract)
    );

    assert_eq!(host.begins, 1, "one host token, never replayed");
    assert_eq!(host.polls, 2, "Pending, then the returned contract receipt");
    assert_eq!(host.cancels, 0, "a returned receipt is not a dropped token");
    let device = slot0(&target).device_ref();
    assert_eq!(
        device.last_known,
        Some(KnownEffects {
            host_prefix: 256,
            ..KnownEffects::NONE
        }),
        "the accepted prefix is a returned fact; a send has no write remainder"
    );
    assert_eq!(device.deliveries, vec![Delivery::Failed]);
}

/// (`Ready(n > requested)` on the **inline** host path): a receive whose
/// first poll returns `accepted > req.len` with `Fault::Contract` settles with
/// the prefix clamped to the request and no fabricated unknown remainder. The
/// inline contract branch does not cancel (the receipt already returned).
#[test]
fn an_inline_contract_host_receive_clamps_the_accepted_prefix() {
    let log: Log = Rc::new(RefCell::new(Vec::new()));
    let mut target = settle_target(
        SettleDevice::new(
            log.clone(),
            [
                Some(Step::Publish(plan_512(Direction::FromHost))),
                Some(Step::Receive(512)),
                Some(Step::Complete(Completion::Good)),
                None,
                None,
                None,
                None,
                None,
            ],
        ),
        5,
    );
    let mut storage = SettleStorage::ready(log.clone(), StorageReceipt::ok(0));
    // `pending == 0`: the first `poll_host` returns `Ready`, i.e. the inline
    // `PollStep::Receive` branch (not the retained `resume_host` path).
    let mut host = SettleHost {
        accepted: Some(1024),
        error: Some(Fault::Contract),
        ..SettleHost::ready(log.clone())
    };
    let mut work = [0u8; 1024];
    let mut scratch = [0u8; 1024];

    target
        .drive_start_static::<Here>(ctx_data(Direction::FromHost, 512), &[0x2A])
        .expect("start");
    assert_eq!(
        target.drive_step_static::<Here>(&mut storage, &mut host, &mut work, &mut [], &mut scratch),
        Err(Fault::Contract)
    );

    assert_eq!(host.begins, 1, "one inline host token");
    assert_eq!(
        host.polls, 1,
        "the inline receipt arrives on the first poll"
    );
    assert_eq!(
        host.cancels, 0,
        "the inline contract branch settles a returned receipt without cancelling"
    );
    let device = slot0(&target).device_ref();
    assert_eq!(
        device.last_known,
        Some(KnownEffects {
            host_prefix: 512,
            ..KnownEffects::NONE
        }),
        "1024 > 512 is clamped to the request, and a receive is never an unknown remainder"
    );
    assert_eq!(device.interrupts, 1, "exactly one bounded settle");
    assert_eq!(device.deliveries, vec![Delivery::Failed]);
    // The command is settled: another step cannot replay the receive.
    assert_eq!(
        target.drive_step_static::<Here>(&mut storage, &mut host, &mut work, &mut [], &mut scratch),
        Err(Fault::Contract)
    );
    assert_eq!(host.begins, 1, "no replay");
    assert_eq!(target.tick(), RunOutcome::ServiceReady);
}

/// (`IoBuf::None`): a *Sync* is polled with `IoBuf::None`, and a storage
/// that returns a contract violation for it is settled without claiming
/// durability, without inventing an unknown write remainder, and without polling
/// the device again after the returned receipt.
#[test]
fn a_sync_contract_violation_reports_no_durability() {
    let log: Log = Rc::new(RefCell::new(Vec::new()));
    let mut target = settle_target(
        SettleDevice::new(
            log.clone(),
            [
                Some(Step::Publish(DataPlan {
                    direction: Direction::None,
                    bytes: 0,
                })),
                Some(Step::Sync),
                Some(Step::Complete(Completion::Good)),
                None,
                None,
                None,
                None,
                None,
            ],
        ),
        4,
    );
    let mut storage = SettleStorage::ready(
        log.clone(),
        StorageReceipt::failed(Fault::Contract, 0, Effect::Known),
    );
    let mut host = SettleHost::ready(log.clone());
    let mut work = [0u8; 64];
    let mut scratch = [0u8; 64];

    target
        .drive_start_static::<Here>(ctx_data(Direction::None, 0), &[0x35])
        .expect("start");
    assert_eq!(
        target.drive_step_static::<Here>(&mut storage, &mut host, &mut work, &mut [], &mut scratch),
        Err(Fault::Contract)
    );
    assert_eq!(
        storage.bufs,
        vec![(Direction::None, 0, true)],
        "the Sync was handed `IoBuf::None`, never a zero-length read/write"
    );
    let device = slot0(&target).device_ref();
    assert_eq!(device.polls, 2, "no device poll after the returned receipt");
    assert_eq!(
        device.last_known,
        Some(KnownEffects::NONE),
        "a failed Sync is `sync_durable = false`, not an unknown write remainder"
    );
    assert_eq!(device.deliveries, vec![Delivery::Failed]);
}

/// (cleanup failure): a settle that cannot be proven safe is terminal, is
/// attempted exactly once (no recursion), and the next `tick` reports the fault.
#[test]
fn a_failed_interrupt_settles_once_and_ends_the_service() {
    let log: Log = Rc::new(RefCell::new(Vec::new()));
    let mut target = settle_target(
        SettleDevice::failing_settle(log.clone(), write_steps(), Fault::NeedsRecovery),
        9,
    );
    let mut storage = SettleStorage::pending_then(log.clone(), 1, StorageReceipt::ok(512));
    let mut host = SettleHost::ready(log.clone());
    let mut work = [0u8; 1024];
    let mut scratch = [0u8; 1024];

    target
        .drive_start_static::<Here>(ctx_data(Direction::FromHost, 512), &[0x2A])
        .expect("start");
    assert_eq!(
        target.drive_step_static::<Here>(&mut storage, &mut host, &mut work, &mut [], &mut scratch),
        Ok(DriveStep::Pending)
    );
    target.stop();
    assert_eq!(
        target.drive_step_static::<Here>(&mut storage, &mut host, &mut work, &mut [], &mut scratch),
        Err(Fault::NeedsRecovery)
    );

    let device = slot0(&target).device_ref();
    assert_eq!(
        device.interrupts, 1,
        "one bounded settle, never a retry loop"
    );
    assert_eq!(device.deliveries, vec![Delivery::Failed]);
    assert_eq!(
        target.tick(),
        RunOutcome::Ended {
            reason: RunEnd::Fatal,
            error: Some(Fault::NeedsRecovery),
        }
    );
    assert_eq!(slot0(&target).device_ref().interrupts, 1);
}

/// (cleanup failure) + first-fault precedence: a settle failure must not
/// overwrite an already-recorded fatal root cause (`set_fatal` keeps the first
/// fault). The step still reports the settle fault; `tick` keeps the root one.
#[test]
fn a_failed_settle_does_not_overwrite_the_first_fatal_fault() {
    let log: Log = Rc::new(RefCell::new(Vec::new()));
    let mut target = settle_target(
        SettleDevice::failing_settle(log.clone(), write_steps(), Fault::NeedsRecovery),
        9,
    );
    let mut storage = SettleStorage::pending_then(log.clone(), 1, StorageReceipt::ok(512));
    let mut host = SettleHost::ready(log.clone());
    let mut work = [0u8; 1024];
    let mut scratch = [0u8; 1024];

    target
        .drive_start_static::<Here>(ctx_data(Direction::FromHost, 512), &[0x2A])
        .expect("start");
    assert_eq!(
        target.drive_step_static::<Here>(&mut storage, &mut host, &mut work, &mut [], &mut scratch),
        Ok(DriveStep::Pending)
    );

    // The root fault is recorded first, then the settle also fails.
    target.fatal(Fault::Io);
    assert_eq!(
        target.drive_step_static::<Here>(&mut storage, &mut host, &mut work, &mut [], &mut scratch),
        Err(Fault::NeedsRecovery),
        "the step reports the settle fault it just observed"
    );
    assert_eq!(
        target.tick(),
        RunOutcome::Ended {
            reason: RunEnd::Fatal,
            error: Some(Fault::Io),
        },
        "the first fault stays authoritative"
    );
}

/// A rejected data plan moves no data and starts no storage IO.
#[test]
fn a_rejected_data_plan_starts_no_io() {
    let log: Log = Rc::new(RefCell::new(Vec::new()));
    let mut target = settle_target(SettleDevice::new(log.clone(), write_steps()), 9);
    let mut storage = SettleStorage::ready(log.clone(), StorageReceipt::ok(512));
    let mut host = SettleHost {
        publish_fault: Some(Fault::Io),
        ..SettleHost::ready(log.clone())
    };
    let mut work = [0u8; 1024];
    let mut scratch = [0u8; 1024];

    target
        .drive_start_static::<Here>(ctx_data(Direction::FromHost, 512), &[0x2A])
        .expect("start");
    assert_eq!(
        target.drive_step_static::<Here>(&mut storage, &mut host, &mut work, &mut [], &mut scratch),
        Err(Fault::Io)
    );
    assert_eq!(host.publishes, 1);
    assert_eq!(storage.begins, 0, "no storage IO for a refused plan");
    let device = slot0(&target).device_ref();
    assert_eq!(device.last_known, Some(KnownEffects::NONE));
    assert_eq!(device.deliveries, vec![Delivery::Failed]);
    assert!(!device.active);
}

/// (local settled before send): a completion fixed while the host data
/// phase has not started is reported without inventing a send.
#[test]
fn a_completion_fixed_before_the_send_starts_no_host_phase() {
    let log: Log = Rc::new(RefCell::new(Vec::new()));
    let mut target = settle_target(
        SettleDevice::new(
            log.clone(),
            [
                Some(Step::Publish(plan_512(Direction::ToHost))),
                Some(Step::Complete(Completion::Good)),
                None,
                None,
                None,
                None,
                None,
                None,
            ],
        ),
        6,
    );
    let mut storage = SettleStorage::ready(log.clone(), StorageReceipt::ok(0));
    let mut host = SettleHost::ready(log.clone());
    let mut work = [0u8; 1024];
    let mut scratch = [0u8; 1024];

    target
        .drive_start_static::<Here>(ctx_data(Direction::ToHost, 512), &[0x28])
        .expect("start");
    assert_eq!(
        target.drive_step_static::<Here>(&mut storage, &mut host, &mut work, &mut [], &mut scratch),
        Ok(DriveStep::Done(Completion::Good))
    );
    assert_eq!(host.publishes, 1);
    assert_eq!(
        host.begins, 0,
        "no send token is minted for a settled command"
    );
    assert_eq!(storage.begins, 0);
    assert_eq!(
        slot0(&target).device_ref().deliveries,
        vec![Delivery::Complete]
    );
    assert_eq!(target.tick(), RunOutcome::ServiceReady);
}

// ── Row 4: idle / empty / drop windows ─────────────────────────────────────

/// `stop` with no command settles nothing — no `interrupt`, no delivery,
/// no IO — and the next `tick` reports the end.
#[test]
fn stop_with_no_command_reports_ended_without_an_interrupt() {
    let log: Log = Rc::new(RefCell::new(Vec::new()));
    let mut target = settle_target(SettleDevice::new(log.clone(), write_steps()), 9);
    let mut storage = SettleStorage::ready(log.clone(), StorageReceipt::ok(512));
    let mut host = SettleHost::ready(log.clone());
    let mut work = [0u8; 1024];
    let mut scratch = [0u8; 1024];

    target.stop();
    assert_eq!(
        target.tick(),
        RunOutcome::Ended {
            reason: RunEnd::Stopped,
            error: None,
        }
    );
    let device = slot0(&target).device_ref();
    assert_eq!(
        device.interrupts, 0,
        "no command, so nothing is interrupted"
    );
    assert!(device.deliveries.is_empty());
    assert_eq!((storage.begins, host.begins), (0, 0));
    assert_eq!(
        target.drive_step_static::<Here>(&mut storage, &mut host, &mut work, &mut [], &mut scratch),
        Err(Fault::Contract),
        "there is no active command to step"
    );
    assert_eq!(events(&log), Vec::new(), "no adapter or device call at all");
}

/// An idle `Abort` is accepted as a no-op; nothing is settled and service
/// continues.
#[test]
fn abort_with_no_active_command_is_a_no_op() {
    let log: Log = Rc::new(RefCell::new(Vec::new()));
    let mut target = settle_target(SettleDevice::new(log.clone(), write_steps()), 9);
    let mut storage = SettleStorage::ready(log.clone(), StorageReceipt::ok(512));
    let mut host = SettleHost::ready(log.clone());
    let mut work = [0u8; 1024];
    let mut scratch = [0u8; 1024];

    assert_eq!(target.request_control(Control::Abort), Ok(()));
    assert_eq!(target.tick(), RunOutcome::ServiceReady);
    let device = slot0(&target).device_ref();
    assert_eq!(device.interrupts, 0);
    assert!(device.deliveries.is_empty());
    // Service continues: a command still starts and runs.
    assert_eq!(
        target.drive_start_static::<Here>(ctx_data(Direction::FromHost, 512), &[0x2A]),
        Ok(())
    );
    assert_eq!(
        target.drive_step_static::<Here>(&mut storage, &mut host, &mut work, &mut [], &mut scratch),
        Ok(DriveStep::Done(Completion::Good))
    );
}

/// (retained input / unconsumed completion): an admission rejection is a
/// completion the shell still owes; until it is reported the boundary stays
/// incomplete, so neither a new command nor a management transaction may start.
#[test]
fn an_unconsumed_completion_blocks_the_next_command_until_it_is_reported() {
    let mut target = block_target();
    let mut storage = BlockingStorage::new(Plane::new());
    let mut host = BlockingHost::new(QuietHost);
    let mut work = [0u8; 64];
    let mut scratch = [0u8; 64];

    assert_eq!(target.propose_static::<Here>(Change::Remove), Ok(()));
    assert_eq!(target.advance_static::<Here>(), Ok(()));
    assert!(target
        .take_static_at::<Here>(0)
        .expect("removed pair")
        .pair
        .is_some());

    // A media command on the empty slot is rejected at admission: the rejection
    // is already a fixed completion, but the shell has not been given it.
    assert_eq!(
        target.drive_start_static::<Here>(ctx(), &[0x00, 0, 0, 0, 0, 0]),
        Ok(())
    );
    assert_eq!(
        target.drive_start_static::<Here>(ctx(), &[0x12, 0, 0, 0, 0, 0]),
        Err(Fault::Boundary),
        "an unconsumed completion keeps the boundary incomplete"
    );
    assert!(matches!(
        target.propose_static::<Here>(Change::Install(pair_none(2))),
        Err((Change::Install(_), Fault::Boundary))
    ));

    assert_eq!(
        target.drive_step_static::<Here>(&mut storage, &mut host, &mut work, &mut [], &mut scratch),
        Ok(DriveStep::Done(Completion::Check(MEDIUM_NOT_PRESENT)))
    );
    // The completion was reported exactly once: management is admissible again.
    assert_eq!(
        target.propose_static::<Here>(Change::Install(pair_none(2))),
        Ok(())
    );
}

// ── Row 5: the long-operation entry polls the adapter once per entry ───────

/// A long operation may span entries with **one retained token**.
/// Each entry polls the adapter at most once: `Pending` returns the unchanged
/// projection (the device is not polled again), `Ready` is stored for the next
/// entry. The operation is begun once, never re-issued and never cancelled.
#[test]
fn a_long_entry_polls_a_bounded_pending_then_completes() {
    let log: Log = Rc::new(RefCell::new(Vec::new()));
    let mut target: LongTarget = Target::new(cons(
        LuImpl::new(
            LongDevice::staged([
                Some(Step::Sync),
                Some(Step::Complete(Completion::Good)),
                None,
                None,
            ]),
            3u8,
        ),
        Nil,
    ));
    let mut storage = SettleStorage::pending_then(log.clone(), 2, StorageReceipt::ok(0));
    let mut work = [0u8; 64];
    let mut scratch = [0u8; 64];

    // Entry 1: the device asks for the Sync; the adapter answers Pending.
    let info = target
        .poll_long_entry_static::<Here>(&mut storage, &mut work, &mut scratch)
        .expect("first entry");
    assert_eq!(info.phase, LongPhase::Foreground);
    assert_eq!(storage.begins, 1, "one operation for the whole entry run");
    assert_eq!(storage.polls, 1);
    assert_eq!(storage.cancels, 0);

    // Entry 2: the same token answers Pending again; the device is not polled.
    let info = target
        .poll_long_entry_static::<Here>(&mut storage, &mut work, &mut scratch)
        .expect("second entry");
    assert_eq!(info.phase, LongPhase::Foreground);
    assert_eq!((storage.begins, storage.polls, storage.cancels), (1, 2, 0));

    // Entry 3: Ready is stored keyed to the LUN; the device consumes it next.
    let info = target
        .poll_long_entry_static::<Here>(&mut storage, &mut work, &mut scratch)
        .expect("third entry");
    assert_eq!(info.phase, LongPhase::Foreground);
    assert_eq!((storage.begins, storage.polls, storage.cancels), (1, 3, 0));
    assert_eq!(
        storage.bufs,
        vec![(Direction::None, 0, true); 3],
        "every poll re-borrows the same Sync window"
    );

    // Entry 4: the device consumes the receipt and settles.
    let info = target
        .poll_long_entry_static::<Here>(&mut storage, &mut work, &mut scratch)
        .expect("settle entry");
    assert_eq!(info.phase, LongPhase::Settled);
    assert_eq!(info.progress, Some(100));
    assert_eq!(
        (storage.begins, storage.polls, storage.cancels),
        (1, 3, 0),
        "settling neither re-issues nor polls the adapter again"
    );
}

/// `poll_long_gate` does not need the command `required_io`/`speculative_io`
/// flags: they are only set while a command is active, and `command_active`
/// alone rejects the long entry before the long adapter is touched.
#[test]
fn a_live_command_blocks_the_long_entry_without_polling_its_adapter() {
    let log: Log = Rc::new(RefCell::new(Vec::new()));
    let mut target = settle_target(SettleDevice::new(log.clone(), write_steps()), 9);
    let mut storage = SettleStorage::pending_then(log.clone(), 1, StorageReceipt::ok(512));
    let mut host = SettleHost::ready(log.clone());
    let mut long_storage = SettleStorage::ready(log.clone(), StorageReceipt::ok(0));
    let mut work = [0u8; 1024];
    let mut scratch = [0u8; 1024];

    target
        .drive_start_static::<Here>(ctx_data(Direction::FromHost, 512), &[0x2A])
        .expect("start the write");
    assert_eq!(
        target.drive_step_static::<Here>(&mut storage, &mut host, &mut work, &mut [], &mut scratch),
        Ok(DriveStep::Pending),
        "the command owns a Pending storage token"
    );

    assert_eq!(
        target.poll_long_entry_static::<Here>(&mut long_storage, &mut work, &mut scratch),
        Err(Fault::Boundary),
        "a live command rejects the long entry"
    );
    assert_eq!(long_storage.begins, 0, "the long adapter was never begun");
    assert_eq!(long_storage.polls, 0, "the long adapter was never polled");
    assert_eq!(long_storage.cancels, 0);
}

/// An adapter that never leaves `Pending` cannot grow work or
/// memory — the entry polls it exactly once and yields `Ok(Foreground)`; there
/// is **no** runner-side budget, busy loop or contract fault. The escape is
/// `force_remove_*`, which cancels the retained token exactly once before it
/// detaches the pair.
#[test]
fn a_stalled_long_entry_yields_and_force_cancels_the_token_once() {
    let log: Log = Rc::new(RefCell::new(Vec::new()));
    let mut target: LongTarget = Target::new(cons(
        LuImpl::new(
            LongDevice::staged([Some(Step::Sync), None, None, None]),
            3u8,
        ),
        Nil,
    ));
    let mut storage = SettleStorage::stalled(log.clone());
    let mut host = SettleHost::ready(log.clone());
    let mut work = [0u8; 64];
    let mut scratch = [0u8; 64];

    // Eight entries, one adapter poll each: no growth, no cancel, no fault.
    for entry in 1..=8 {
        let info = target
            .poll_long_entry_static::<Here>(&mut storage, &mut work, &mut scratch)
            .expect("a stalled adapter yields, it is not a fault");
        assert_eq!(info.phase, LongPhase::Foreground);
        assert_eq!(storage.begins, 1, "the operation is begun exactly once");
        assert_eq!(storage.polls, entry, "exactly one poll per entry");
        assert_eq!(
            storage.cancels, 0,
            "a live token is never cancelled by a yield"
        );
    }

    // A live long IO is a boundary obligation and is checked before the long
    // phase. This device also reports `Foreground`, but the IO reason fires
    // first; the Idle-projection variant is pinned by the runner unit test
    // `resume_pending_force_refuses_a_live_long_token_even_when_the_device_is_idle`.
    assert!(matches!(
        target.take_static_at::<Here>(0),
        Err(BoundaryReject::RequiredIoInFlight)
    ));
    assert_eq!(storage.polls, 8, "a rejected take never polls the token");

    // Force is the escape: cancel the retained token once, then detach.
    target
        .force_remove_static::<Here>(&mut storage, &mut host)
        .expect("force detach");
    assert_eq!(storage.cancels, 1, "the retained token is cancelled once");
    assert_eq!(storage.begins, 1, "the operation is never re-issued");
    assert!(
        !target.snapshot_static::<Here>().ready,
        "force detached the pair"
    );
    assert_eq!(
        target.snapshot_static::<Here>().long.phase,
        LongPhase::Idle,
        "a detached medium discards the resident projection"
    );
    let pair = target.take_static_at::<Here>(0).expect("forced pair").pair;
    assert_eq!(pair, Some(pair_none(3)));

    // No adapter slot is retained: an entry now only polls the device again.
    let polls = storage.polls;
    target
        .poll_long_entry_static::<Here>(&mut storage, &mut work, &mut scratch)
        .expect("a detached slot still answers the entry");
    assert_eq!(storage.polls, polls, "no token to poll after the cancel");
}

/// Force row: force cancels a stalled long **write** token. Its
/// end was never observed, so the handback must carry
/// `unknown_remainder = true` (confirmed prefix 0) instead of `NONE`.
#[test]
fn force_cancels_a_stalled_long_write_and_reports_the_unknown_remainder() {
    let log: Log = Rc::new(RefCell::new(Vec::new()));
    let mut target: LongTarget = Target::new(cons(
        LuImpl::new(
            LongDevice::staged([Some(Step::Write(8)), None, None, None]),
            3u8,
        ),
        Nil,
    ));
    let mut storage = SettleStorage::stalled(log.clone());
    let mut host = SettleHost::ready(log.clone());
    let mut work = [0u8; 64];
    let mut scratch = [0u8; 64];

    assert_eq!(
        target
            .poll_long_entry_static::<Here>(&mut storage, &mut work, &mut scratch)
            .expect("long entry")
            .phase,
        LongPhase::Foreground
    );
    assert_eq!(storage.begins, 1);
    assert_eq!(storage.polls, 1);

    target
        .force_remove_static::<Here>(&mut storage, &mut host)
        .expect("force detach");
    assert_eq!(storage.cancels, 1, "the retained token is cancelled once");
    assert_eq!(
        storage.polls, 1,
        "the cancelled write is never polled again"
    );
    assert_eq!(storage.begins, 1, "the write is never re-issued");
    let device = target.slots().slot().device_ref();
    assert_eq!(
        device.interrupts, 1,
        "force books the long-cancel facts once"
    );
    assert!(
        device.last_known.unknown_remainder,
        "a cancelled long write keeps an unknown remainder"
    );
    assert_eq!(device.last_known.confirmed_write, 0);

    let taken = target.take_static_at::<Here>(0).expect("take the pair");
    assert_eq!(taken.pair, Some(pair_none(3)));
    assert!(
        taken.effects.unknown_remainder,
        "the force handback reports the unknown write remainder"
    );
    assert_eq!(taken.effects.confirmed_write, 0);
    assert!(!taken.effects.sync_durable, "force claims no durability");
}

// ── Data-In companion (send + speculative read) ─────────────────────────────

/// A non-blocking companion stays in flight after the wire send settled: the
/// next `Tick` reaps it and the device receives one combined feedback with both
/// receipts, then sends the following chunk.
#[test]
fn combined_send_reaps_the_prefetch_on_a_tick() {
    let log: Log = Rc::new(RefCell::new(Vec::new()));
    let mut target = settle_target(
        SettleDevice::new(
            log.clone(),
            [
                Some(Step::Publish(DataPlan {
                    direction: Direction::ToHost,
                    bytes: 1024,
                })),
                Some(Step::Read(512)),
                Some(Step::SendCombined {
                    len: 512,
                    prefetch: 512,
                }),
                Some(Step::Send(512)),
                Some(Step::Complete(Completion::Good)),
                None,
                None,
                None,
            ],
        ),
        4,
    );
    let mut storage = CompanionStorage::new(log.clone(), 2);
    let mut host = SettleHost::pending_then(log.clone(), 1);
    let mut work = [0u8; 512];
    let mut alt = [0u8; 512];
    let mut scratch = [0u8; 512];

    target
        .drive_start_static::<Here>(ctx_data(Direction::ToHost, 1024), &[0x28])
        .expect("start");
    assert_eq!(
        target.drive_step_static::<Here>(
            &mut storage,
            &mut host,
            &mut work,
            &mut alt,
            &mut scratch
        ),
        Ok(DriveStep::Pending)
    );
    assert_eq!(storage.begins, 2, "required read + one companion");
    assert_eq!(host.begins, 1, "one host send token");
    assert_eq!(
        target.pending_kind(),
        Some(PendingKind::Host),
        "the shell still owes the wire send"
    );

    // The shell reports the send; the companion is still in flight, so the
    // command stays pending on storage only.
    assert_eq!(
        target.drive_step_static::<Here>(
            &mut storage,
            &mut host,
            &mut work,
            &mut alt,
            &mut scratch
        ),
        Ok(DriveStep::Pending)
    );
    assert_eq!(target.pending_kind(), Some(PendingKind::Storage));

    // The next tick settles the companion; the device sees one combined
    // feedback and sends the last chunk immediately.
    assert_eq!(
        target.drive_step_static::<Here>(
            &mut storage,
            &mut host,
            &mut work,
            &mut alt,
            &mut scratch
        ),
        Ok(DriveStep::Done(Completion::Good))
    );
    assert_eq!(storage.begins, 2, "the prefetch is never re-submitted");
    let device = slot0(&target).device_ref();
    assert_eq!(
        device
            .feedbacks
            .iter()
            .filter(|kind| **kind == FeedbackKind::HostSentWithIo)
            .count(),
        1,
        "exactly one combined feedback"
    );
    assert_eq!(host.sent.len(), 1024, "both chunks reached the host");
}

/// `Abort` with both tokens live cancels the companion before the host and
/// leaves the banks usable for the next command.
#[test]
fn abort_with_both_tokens_cancels_the_companion_first() {
    let log: Log = Rc::new(RefCell::new(Vec::new()));
    let mut target = settle_target(
        SettleDevice::new(
            log.clone(),
            [
                Some(Step::Publish(DataPlan {
                    direction: Direction::ToHost,
                    bytes: 1024,
                })),
                Some(Step::Read(512)),
                Some(Step::SendCombined {
                    len: 512,
                    prefetch: 512,
                }),
                Some(Step::Send(512)),
                Some(Step::Complete(Completion::Good)),
                None,
                None,
                None,
            ],
        ),
        4,
    );
    let mut storage = CompanionStorage::new(log.clone(), u32::MAX);
    let mut host = SettleHost::pending_then(log.clone(), u32::MAX);
    let mut work = [0u8; 512];
    let mut alt = [0u8; 512];
    let mut scratch = [0u8; 512];

    target
        .drive_start_static::<Here>(ctx_data(Direction::ToHost, 1024), &[0x28])
        .expect("start");
    assert_eq!(
        target.drive_step_static::<Here>(
            &mut storage,
            &mut host,
            &mut work,
            &mut alt,
            &mut scratch
        ),
        Ok(DriveStep::Pending)
    );
    assert_eq!(storage.cancels, 0);
    assert_eq!(host.cancels, 0);

    assert_eq!(target.request_control(Control::Abort), Ok(()));
    assert_eq!(
        target.drive_step_static::<Here>(
            &mut storage,
            &mut host,
            &mut work,
            &mut alt,
            &mut scratch
        ),
        Ok(DriveStep::Done(Completion::Check(Sense::new(
            0x0B, 0x45, 0x00
        ))))
    );
    assert_eq!(storage.cancels, 1, "the companion is cancelled");
    assert_eq!(host.cancels, 1, "the host token is cancelled");
    let storage_cancel = at(&log, |event| matches!(event, Ev::Cancel));
    let host_cancel = at(&log, |event| matches!(event, Ev::HostCancel));
    assert!(
        storage_cancel < host_cancel,
        "the companion is cancelled before the host token"
    );
    assert!(host_cancel < at(&log, |event| matches!(event, Ev::Interrupt { .. })));
    assert!(slot0(&target).device_ref().medium.is_some());

    // The same banks start the next command without a stale-window contract.
    assert_eq!(
        target.drive_start_static::<Here>(ctx_data(Direction::ToHost, 1024), &[0x28]),
        Ok(())
    );
    assert_eq!(
        target.drive_step_static::<Here>(
            &mut storage,
            &mut host,
            &mut work,
            &mut alt,
            &mut scratch
        ),
        Ok(DriveStep::Pending)
    );
}

/// `stop` with a sent chunk (retained host receipt) and a live storage
/// companion drains both tokens: the host first, then the companion, without
/// cancelling anything, and merges the completed send into `known`.
#[test]
fn stop_with_both_tokens_drains_then_settles() {
    let log: Log = Rc::new(RefCell::new(Vec::new()));
    let mut target = settle_target(
        SettleDevice::new(
            log.clone(),
            [
                Some(Step::Publish(DataPlan {
                    direction: Direction::ToHost,
                    bytes: 1024,
                })),
                Some(Step::Read(512)),
                Some(Step::SendCombined {
                    len: 512,
                    prefetch: 512,
                }),
                Some(Step::Send(512)),
                Some(Step::Complete(Completion::Good)),
                None,
                None,
                None,
            ],
        ),
        4,
    );
    // Both domains stay live across the `HostSent` entry: the host token needs
    // two polls and the companion two more.
    let mut storage = CompanionStorage::new(log.clone(), 4);
    let mut host = SettleHost::pending_then(log.clone(), 2);
    let mut work = [0u8; 512];
    let mut alt = [0u8; 512];
    let mut scratch = [0u8; 512];

    assert_eq!(
        target.drive_start_static::<Here>(ctx_data(Direction::ToHost, 1024), &[0x28]),
        Ok(())
    );
    assert_eq!(
        target.drive_step_static::<Here>(
            &mut storage,
            &mut host,
            &mut work,
            &mut alt,
            &mut scratch
        ),
        Ok(DriveStep::Pending)
    );
    assert_eq!(target.pending_kind(), Some(PendingKind::Host));
    assert_eq!((storage.cancels, host.cancels), (0, 0));

    // The shell reports the send; both tokens are still live afterwards.
    assert_eq!(
        target.drive_step_static::<Here>(
            &mut storage,
            &mut host,
            &mut work,
            &mut alt,
            &mut scratch
        ),
        Ok(DriveStep::Pending)
    );
    assert_eq!(target.pending_kind(), Some(PendingKind::Host));
    assert_eq!((storage.cancels, host.cancels), (0, 0));

    target.stop();
    assert_eq!(
        target.tick(),
        RunOutcome::ServiceReady,
        "a drain still in flight must not be reported as `Ended`"
    );

    // The first drain entry settles the host token (its receipt is retained)
    // and keeps polling the companion.
    assert_eq!(
        target.drive_step_static::<Here>(
            &mut storage,
            &mut host,
            &mut work,
            &mut alt,
            &mut scratch
        ),
        Ok(DriveStep::Pending)
    );
    assert_eq!(target.pending_kind(), Some(PendingKind::Storage));
    assert_eq!((storage.cancels, host.cancels), (0, 0));

    // The companion is still pending: the drain keeps its state.
    assert_eq!(
        target.drive_step_static::<Here>(
            &mut storage,
            &mut host,
            &mut work,
            &mut alt,
            &mut scratch
        ),
        Ok(DriveStep::Pending)
    );
    assert_eq!(target.pending_kind(), Some(PendingKind::Storage));
    assert_eq!((storage.cancels, host.cancels), (0, 0));

    // Both facts have settled: Stop settles without cancelling either token.
    assert_eq!(
        target.drive_step_static::<Here>(
            &mut storage,
            &mut host,
            &mut work,
            &mut alt,
            &mut scratch
        ),
        Ok(DriveStep::Control(RunOutcome::Ended {
            reason: RunEnd::Stopped,
            error: None,
        }))
    );
    assert_eq!(
        (storage.cancels, host.cancels),
        (0, 0),
        "Stop drains healthy tokens, never cancels"
    );
    assert_eq!(target.pending_kind(), None);

    let device = slot0(&target).device_ref();
    assert_eq!(device.interrupts, 1);
    assert_eq!(
        device.last_known,
        Some(KnownEffects {
            host_prefix: 512,
            ..KnownEffects::NONE
        }),
        "the completed send contributes its prefix; a read-ahead has no unknown remainder"
    );
    assert_eq!(device.deliveries, vec![Delivery::Failed]);
    assert!(device.medium.is_some(), "Stop never detaches the medium");

    // The old bank/token state is gone: the next command reaches the same
    // terminal gate, not a stale-window contract.
    assert_eq!(
        target.drive_start_static::<Here>(ctx_data(Direction::ToHost, 1024), &[0x28]),
        Err(Fault::Boundary),
        "a stopped target is terminal; the bank is not left wedged behind a token"
    );
}

// ── Data-Out companion (receive + required write) ───────────────────────────

fn write_pipeline_steps() -> [Option<Step>; 8] {
    [
        Some(Step::Publish(DataPlan {
            direction: Direction::FromHost,
            bytes: 1024,
        })),
        Some(Step::Receive(512)),
        Some(Step::ReceiveCombined {
            len: 512,
            write: 512,
        }),
        Some(Step::Write(512)),
        Some(Step::Complete(Completion::Good)),
        None,
        None,
        None,
    ]
}

/// The write companion settles before the receive token: the combined feedback
/// is delivered once and the last chunk is written as a plain `Io`.
#[test]
fn write_pipeline_settles_the_companion_first() {
    let log: Log = Rc::new(RefCell::new(Vec::new()));
    let mut target = settle_target(SettleDevice::new(log.clone(), write_pipeline_steps()), 4);
    let mut storage = SettleStorage::ready(log.clone(), StorageReceipt::ok(512));
    let mut host = SettleHost::pending_then(log.clone(), 1);
    let mut work = [0u8; 512];
    let mut alt = [0u8; 512];
    let mut scratch = [0u8; 512];

    target
        .drive_start_static::<Here>(ctx_data(Direction::FromHost, 1024), &[0x2A])
        .expect("start");
    let mut result = Ok(DriveStep::Pending);
    for _ in 0..4 {
        result = target.drive_step_static::<Here>(
            &mut storage,
            &mut host,
            &mut work,
            &mut alt,
            &mut scratch,
        );
        if result != Ok(DriveStep::Pending) {
            break;
        }
    }
    assert_eq!(result, Ok(DriveStep::Done(Completion::Good)));
    assert_eq!(storage.begins, 2, "one pipeline write plus the final write");
    let device = slot0(&target).device_ref();
    assert_eq!(
        device
            .feedbacks
            .iter()
            .filter(|kind| **kind == FeedbackKind::HostReceivedWithIo)
            .count(),
        1,
        "exactly one combined feedback"
    );
    assert_eq!(device.last_known, None);
}

/// The receive token settles first: the runner retains it, then the companion
/// settles on the next entry and the combined feedback is delivered once.
#[test]
fn write_pipeline_settles_the_receive_first() {
    let log: Log = Rc::new(RefCell::new(Vec::new()));
    let mut target = settle_target(SettleDevice::new(log.clone(), write_pipeline_steps()), 4);
    let mut storage = SettleStorage::pending_then(log.clone(), 1, StorageReceipt::ok(512));
    let mut host = SettleHost::ready(log.clone());
    let mut work = [0u8; 512];
    let mut alt = [0u8; 512];
    let mut scratch = [0u8; 512];

    target
        .drive_start_static::<Here>(ctx_data(Direction::FromHost, 1024), &[0x2A])
        .expect("start");
    assert_eq!(
        target.drive_step_static::<Here>(
            &mut storage,
            &mut host,
            &mut work,
            &mut alt,
            &mut scratch
        ),
        Ok(DriveStep::Pending)
    );
    assert_eq!(target.pending_kind(), Some(PendingKind::Storage));
    assert_eq!(
        target.drive_step_static::<Here>(
            &mut storage,
            &mut host,
            &mut work,
            &mut alt,
            &mut scratch
        ),
        Ok(DriveStep::Done(Completion::Good))
    );
    assert_eq!(storage.begins, 2);
    let device = slot0(&target).device_ref();
    assert_eq!(
        device
            .feedbacks
            .iter()
            .filter(|kind| **kind == FeedbackKind::HostReceivedWithIo)
            .count(),
        1,
        "exactly one combined feedback"
    );
}

/// `Stop` with a retained receive and a live write companion drains both
/// without cancelling and merges the host prefix with the confirmed write.
#[test]
fn stop_with_both_data_out_tokens_drains_then_settles() {
    let log: Log = Rc::new(RefCell::new(Vec::new()));
    let mut target = settle_target(SettleDevice::new(log.clone(), write_pipeline_steps()), 4);
    let mut storage = SettleStorage::pending_then(log.clone(), 3, StorageReceipt::ok(512));
    let mut host = SettleHost::ready_then_pending(log.clone(), 1, 1);
    let mut work = [0u8; 512];
    let mut alt = [0u8; 512];
    let mut scratch = [0u8; 512];

    target
        .drive_start_static::<Here>(ctx_data(Direction::FromHost, 1024), &[0x2A])
        .expect("start");
    assert_eq!(
        target.drive_step_static::<Here>(
            &mut storage,
            &mut host,
            &mut work,
            &mut alt,
            &mut scratch
        ),
        Ok(DriveStep::Pending)
    );
    assert_eq!(target.pending_kind(), Some(PendingKind::Host));

    target.stop();
    assert_eq!(target.tick(), RunOutcome::ServiceReady);
    assert_eq!(
        target.drive_step_static::<Here>(
            &mut storage,
            &mut host,
            &mut work,
            &mut alt,
            &mut scratch
        ),
        Ok(DriveStep::Pending)
    );
    assert_eq!(target.pending_kind(), Some(PendingKind::Storage));
    assert_eq!((storage.cancels, host.cancels), (0, 0));
    assert_eq!(
        target.drive_step_static::<Here>(
            &mut storage,
            &mut host,
            &mut work,
            &mut alt,
            &mut scratch
        ),
        Ok(DriveStep::Pending)
    );
    assert_eq!(target.pending_kind(), Some(PendingKind::Storage));
    assert_eq!(
        target.drive_step_static::<Here>(
            &mut storage,
            &mut host,
            &mut work,
            &mut alt,
            &mut scratch
        ),
        Ok(DriveStep::Control(RunOutcome::Ended {
            reason: RunEnd::Stopped,
            error: None,
        }))
    );
    assert_eq!(
        (storage.cancels, host.cancels),
        (0, 0),
        "Stop drains both healthy tokens"
    );
    let device = slot0(&target).device_ref();
    assert_eq!(device.interrupts, 1);
    assert_eq!(
        device.last_known,
        Some(KnownEffects {
            confirmed_write: 512,
            host_prefix: 512,
            ..KnownEffects::NONE
        }),
        "host facts merge first, then the confirmed write"
    );
}

/// `Abort` with both Data-Out tokens cancels the companion before the host
/// token and leaves the banks reusable.
#[test]
fn abort_with_both_data_out_tokens_cancels_the_companion_first() {
    let log: Log = Rc::new(RefCell::new(Vec::new()));
    let mut target = settle_target(SettleDevice::new(log.clone(), write_pipeline_steps()), 4);
    let mut storage = SettleStorage::pending_then(log.clone(), u32::MAX, StorageReceipt::ok(512));
    let mut host = SettleHost::ready_then_pending(log.clone(), 1, u32::MAX);
    let mut work = [0u8; 512];
    let mut alt = [0u8; 512];
    let mut scratch = [0u8; 512];

    target
        .drive_start_static::<Here>(ctx_data(Direction::FromHost, 1024), &[0x2A])
        .expect("start");
    assert_eq!(
        target.drive_step_static::<Here>(
            &mut storage,
            &mut host,
            &mut work,
            &mut alt,
            &mut scratch
        ),
        Ok(DriveStep::Pending)
    );
    assert_eq!(target.pending_kind(), Some(PendingKind::Host));

    assert_eq!(target.request_control(Control::Abort), Ok(()));
    assert_eq!(
        target.drive_step_static::<Here>(
            &mut storage,
            &mut host,
            &mut work,
            &mut alt,
            &mut scratch
        ),
        Ok(DriveStep::Done(Completion::Check(Sense::new(
            0x0B, 0x45, 0x00
        ))))
    );
    assert_eq!(storage.cancels, 1);
    assert_eq!(host.cancels, 1);
    assert!(
        at(&log, |event| matches!(event, Ev::Cancel))
            < at(&log, |event| matches!(event, Ev::HostCancel)),
        "the write companion is cancelled before the receive token"
    );

    // The same banks start the next command without a stale-window contract.
    assert_eq!(
        target.drive_start_static::<Here>(ctx_data(Direction::FromHost, 1024), &[0x2A]),
        Ok(())
    );
    assert_eq!(
        target.drive_step_static::<Here>(
            &mut storage,
            &mut host,
            &mut work,
            &mut alt,
            &mut scratch
        ),
        Ok(DriveStep::Pending)
    );
}

/// START STOP UNIT `LoEj=1, Start=0` is the host's own eject: the runner
/// detaches the pair after the completion is fixed, publishes
/// `ResourcesReady`, and the empty slot answers `MEDIUM_NOT_PRESENT` until the
/// application installs a new medium.
#[test]
fn host_loej_detaches_the_medium_and_the_slot_stays_servable() {
    let mut target = Target::new(cons(
        LuImpl::new(Spc::new(MmcDrive::new(FlatCdMedium::read_only(16))), 7u8),
        Nil,
    ));
    let mut storage = BlockingStorage::new(Plane::new());
    let mut work = [0u8; 512];
    let mut scratch = [0u8; 512];

    // LoEj=1, Start=0 (eject), no data phase.
    assert_eq!(
        target.drive_static::<Here>(
            &mut storage,
            ctx(),
            &[0x1B, 0, 0, 0, 0x02, 0],
            &mut work,
            &mut scratch
        ),
        Ok(Completion::Good)
    );
    assert_eq!(
        target.tick(),
        RunOutcome::ResourcesReady { lun: 0 },
        "the detach is published once the completion is fixed"
    );
    let taken = target
        .take_static_at::<Here>(0)
        .expect("the ejected pair is resident");
    assert_eq!(taken.local, Ok(()));
    assert!(taken.pair.is_some());

    // Empty slot: TUR is NOT READY / MEDIUM NOT PRESENT, not a dead device.
    assert_eq!(
        target.drive_static::<Here>(
            &mut storage,
            ctx(),
            &[0x00, 0, 0, 0, 0, 0],
            &mut work,
            &mut scratch
        ),
        Ok(Completion::Check(MEDIUM_NOT_PRESENT))
    );
    assert_eq!(target.tick(), RunOutcome::ServiceReady);

    // A second eject on the empty tray is a no-op GOOD (Windows retries it).
    assert_eq!(
        target.drive_static::<Here>(
            &mut storage,
            ctx(),
            &[0x1B, 0, 0, 0, 0x02, 0],
            &mut work,
            &mut scratch
        ),
        Ok(Completion::Good)
    );
    assert_eq!(
        target.tick(),
        RunOutcome::ServiceReady,
        "no handback, no death"
    );

    // Insert a fresh, larger disc: geometry comes from the medium.
    assert!(target
        .install_static::<Here>(Pair {
            medium: FlatCdMedium::read_only(64),
            backing: 8u8,
        })
        .is_ok());
    assert_eq!(
        target.drive_static::<Here>(
            &mut storage,
            ctx(),
            &[0x00, 0, 0, 0, 0, 0],
            &mut work,
            &mut scratch
        ),
        Ok(Completion::Good)
    );
}

/// A LUN can be built empty (an enumerated drive with an open tray) and filled
/// later without an eject/rebuild cycle.
#[test]
fn a_lun_can_start_empty_and_be_filled_without_an_eject() {
    let mut target = Target::new(cons(
        LuImpl::empty(Spc::new(MmcDrive::<FlatCdMedium>::empty(
            snowscsi::mmc::MmcCaps::hyper_multi(),
        ))),
        Nil,
    ));
    let mut storage = BlockingStorage::new(Plane::new());
    let mut work = [0u8; 512];
    let mut scratch = [0u8; 512];

    // The LU enumerates and reports no medium, but IT is not dead.
    assert!(!target.snapshot_static::<Here>().ready);
    assert_eq!(
        target.drive_static::<Here>(
            &mut storage,
            ctx(),
            &[0x00, 0, 0, 0, 0, 0],
            &mut work,
            &mut scratch
        ),
        Ok(Completion::Check(MEDIUM_NOT_PRESENT))
    );

    // The first medium is installed at a management boundary: no eject, no
    // rebuild. (The app raises `MediumChanged` through `raise_ua_rt` on the
    // runtime target; the static fixture has no UA entry.)
    assert!(target
        .install_static::<Here>(Pair {
            medium: FlatCdMedium::read_only(16),
            backing: 8u8,
        })
        .is_ok());
    assert!(target.snapshot_static::<Here>().ready);
    assert_eq!(
        target.drive_static::<Here>(
            &mut storage,
            ctx(),
            &[0x00, 0, 0, 0, 0, 0],
            &mut work,
            &mut scratch
        ),
        Ok(Completion::Good)
    );
}
