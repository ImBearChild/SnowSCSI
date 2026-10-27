//! P3 acceptance fixtures: removal locks, host/operator eject and the
//! unlock-flush contract.
//!
//! These are isolated fixtures (mock storage, no real platform): the
//! normal/persistent latches live in `Spc`, the `LuInfo` projection is read
//! through `Target::snapshot_rt`, and clearing the normal latch must issue a
//! `StorageOp::Sync` whose known success is the only thing that clears it.

use snowscsi::block::{BlockAttrs, BlockDevice};
use snowscsi::core::storage::{BlockingStorage, IoBuf, IoReq, StorageReceipt, SyncStorage};
use snowscsi::core::{
    cons, decide_eject, At, CommandContext, Completion, Cons, Direction, Effect, EjectOrigin,
    Fault, Here, Lu, LuImpl, Nil, RemovalLocks, Spc, StaticTarget, Target,
    MEDIUM_REMOVAL_PREVENTED, WRITE_ERROR,
};
use snowscsi::mmc::{FlatCdMedium, MmcDrive};

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

fn block_target() -> BlockTarget {
    Target::new(cons(
        LuImpl::new(Spc::new(BlockDevice::new(BlockAttrs::new(16, 512))), 1u8),
        Nil,
    ))
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
