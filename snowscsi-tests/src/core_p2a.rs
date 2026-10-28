//! Core/block acceptance fixtures (write/sync, effects, multi-LUN, host data).
//!
//! These are integration tests in an external crate: they use only the public
//! `snowscsi::core` / `snowscsi::block` surface, with real `SyncStorage` and
//! `SyncHost` adapters (no model `NullHost`, no zero-filled host data).

use snowscsi::block::{BlockAttrs, BlockDevice};
use snowscsi::core::storage::{
    BlockingHost, BlockingStorage, HostBuf, HostReceipt, HostReq, IoBuf, IoReq, StorageReceipt,
    SyncHost, SyncStorage,
};
use snowscsi::core::{
    cons, Change, CommandContext, Completion, Delivery, Direction, Effect, Fault, Here, LuImpl,
    Nil, NoMedium, RunOutcome, Spc, StaticTarget, Target, There, COMMAND_ABORTED, LBA_OUT_OF_RANGE,
    WRITE_ERROR,
};

const BLOCK: u32 = 512;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum LegalOp {
    Read { offset: u64, len: usize },
    Write { offset: u64, len: usize },
    Sync,
}

/// Recording sync plane: an application-owned backing with a deterministic
/// op trace. `fail_io_prefix` injects a short/failed write with a confirmed
/// prefix.
struct Plane {
    ops: [Option<LegalOp>; 8],
    count: usize,
    data: [u8; 4096],
    fail_io_prefix: Option<usize>,
    /// Fail the next read at this byte offset with `Fault::Io`.
    fail_read_offset: Option<u64>,
}

impl Plane {
    fn new() -> Self {
        Self {
            ops: [None; 8],
            count: 0,
            data: [0u8; 4096],
            fail_io_prefix: None,
            fail_read_offset: None,
        }
    }

    fn push(&mut self, op: LegalOp) {
        if self.count < self.ops.len() {
            self.ops[self.count] = Some(op);
            self.count += 1;
        }
    }

    fn ops(&self) -> &[Option<LegalOp>] {
        &self.ops[..self.count]
    }
}

impl SyncStorage for Plane {
    fn exec(&mut self, req: IoReq, buf: IoBuf<'_>) -> StorageReceipt {
        match (req.dir, buf) {
            (Direction::FromHost, IoBuf::Write(bytes)) => {
                self.push(LegalOp::Write {
                    offset: req.offset,
                    len: bytes.len(),
                });
                if let Some(prefix) = self.fail_io_prefix.take() {
                    let n = prefix.min(bytes.len());
                    self.data[req.offset as usize..req.offset as usize + n]
                        .copy_from_slice(&bytes[..n]);
                    return StorageReceipt::failed(Fault::Io, n, Effect::UnknownRemainder);
                }
                let at = req.offset as usize;
                self.data[at..at + bytes.len()].copy_from_slice(bytes);
                StorageReceipt::ok(bytes.len())
            }
            (Direction::ToHost, IoBuf::Read(bytes)) => {
                self.push(LegalOp::Read {
                    offset: req.offset,
                    len: bytes.len(),
                });
                if self.fail_read_offset == Some(req.offset) {
                    self.fail_read_offset = None;
                    return StorageReceipt::failed(Fault::Io, 0, Effect::Known);
                }
                let at = req.offset as usize;
                let take = bytes.len().min(self.data.len().saturating_sub(at));
                bytes[..take].copy_from_slice(&self.data[at..at + take]);
                StorageReceipt::ok(take)
            }
            (Direction::None, IoBuf::None) => {
                self.push(LegalOp::Sync);
                StorageReceipt::ok(0)
            }
            _ => StorageReceipt::failed(Fault::Contract, 0, Effect::Known),
        }
    }
}

/// One recorded host-seam call: proves what the transport saw.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum HostEvent {
    Publish(snowscsi::core::DataPlan),
    Recv(usize),
    Sent(usize),
}

/// Host data plane: records every plan/buffer call, fills WRITE data with
/// 0xa5, and reports configurable accepted prefixes (short send, short receive).
struct TestHost {
    read_accepts: Option<usize>,
    recv_accepts: Option<usize>,
    events: [Option<HostEvent>; 8],
    count: usize,
    /// Bytes actually sent to the host by the device, in order.
    sent_data: [u8; 4096],
    sent_len: usize,
}

impl TestHost {
    fn new() -> Self {
        Self {
            read_accepts: None,
            recv_accepts: None,
            events: [None; 8],
            count: 0,
            sent_data: [0u8; 4096],
            sent_len: 0,
        }
    }

    fn push(&mut self, event: HostEvent) {
        if self.count < self.events.len() {
            self.events[self.count] = Some(event);
            self.count += 1;
        }
    }

    fn events(&self) -> &[Option<HostEvent>] {
        &self.events[..self.count]
    }
}

impl SyncHost for TestHost {
    fn publish(&mut self, plan: snowscsi::core::DataPlan) -> Result<(), Fault> {
        self.push(HostEvent::Publish(plan));
        Ok(())
    }

    fn receive(&mut self, req: HostReq, buf: HostBuf<'_>) -> HostReceipt {
        let len = req.len as usize;
        match buf {
            HostBuf::Recv(bytes) => {
                let accepted = self.recv_accepts.unwrap_or(len).min(len);
                for byte in bytes[..accepted].iter_mut() {
                    *byte = 0xa5;
                }
                self.push(HostEvent::Recv(accepted));
                HostReceipt::from_adapter(accepted, None)
            }
            HostBuf::Send(_) => HostReceipt::from_adapter(0, Some(Fault::Contract)),
        }
    }

    fn send(&mut self, req: HostReq, buf: HostBuf<'_>) -> HostReceipt {
        let len = req.len as usize;
        let accepted = self.read_accepts.unwrap_or(len).min(len);
        if let HostBuf::Send(bytes) = buf {
            let end = self.sent_len + accepted;
            if end <= self.sent_data.len() {
                self.sent_data[self.sent_len..end].copy_from_slice(&bytes[..accepted]);
                self.sent_len = end;
            }
        }
        self.push(HostEvent::Sent(accepted));
        HostReceipt::from_adapter(accepted, None)
    }

    fn delivery(&self) -> Delivery {
        Delivery::Complete
    }
}

fn ctx(lun: u64, direction: Direction, bytes: u64) -> CommandContext {
    CommandContext {
        lun,
        lun_count: 1,
        host_bytes: bytes,
        host_direction: direction,
    }
}

fn write_cdb(lba: u32, blocks: u16) -> [u8; 10] {
    let mut cdb = [0u8; 10];
    cdb[0] = 0x2A;
    cdb[2] = (lba >> 24) as u8;
    cdb[3] = (lba >> 16) as u8;
    cdb[4] = (lba >> 8) as u8;
    cdb[5] = lba as u8;
    cdb[7] = (blocks >> 8) as u8;
    cdb[8] = blocks as u8;
    cdb
}

fn read_cdb(lba: u32, blocks: u16) -> [u8; 10] {
    let mut cdb = write_cdb(lba, blocks);
    cdb[0] = 0x28;
    cdb
}

fn sync_cdb() -> [u8; 10] {
    let mut cdb = [0u8; 10];
    cdb[0] = 0x35;
    cdb
}

fn slot(backing: u8) -> LuImpl<BlockDevice, u8> {
    LuImpl::new(BlockDevice::new(BlockAttrs::new(16, BLOCK)), backing)
}

/// First static slot (type-level `Here`), for probe reads in fixtures.
fn slot0<S>(target: &Target<S>) -> &<S as snowscsi::core::At<Here>>::Slot
where
    S: snowscsi::core::SlotSet + snowscsi::core::At<Here>,
{
    <S as snowscsi::core::At<Here>>::slot(target.slots())
}

/// Complete write + explicit synchronize; no hidden runner Sync.
#[test]
fn write_then_sync_records_the_exact_sequence() {
    let mut target = Target::new(cons(slot(1), Nil));
    let mut storage = BlockingStorage::new(Plane::new());
    let mut host = BlockingHost::new(TestHost::new());
    let mut work = [0u8; 1024];
    let mut scratch = [0u8; 1024];

    assert_eq!(
        target.drive_static_host::<Here>(
            &mut storage,
            &mut host,
            ctx(0, Direction::FromHost, 1024),
            &write_cdb(0, 2),
            &mut work,
            &mut scratch,
        ),
        Ok(Completion::Good)
    );
    assert_eq!(
        storage.inner().ops(),
        &[Some(LegalOp::Write {
            offset: 0,
            len: 1024
        })]
    );
    assert!(storage.inner().data[..1024].iter().all(|b| *b == 0xa5));
    assert_eq!(
        slot0(&target).device_ref().known_effects().confirmed_write,
        1024
    );

    assert_eq!(
        target.drive_static::<Here>(
            &mut storage,
            ctx(0, Direction::None, 0),
            &sync_cdb(),
            &mut work,
            &mut scratch,
        ),
        Ok(Completion::Good)
    );
    assert_eq!(
        storage.inner().ops(),
        &[
            Some(LegalOp::Write {
                offset: 0,
                len: 1024
            }),
            Some(LegalOp::Sync),
        ],
        "the sync is the host's explicit SYNCHRONIZE CACHE, not a hidden runner step"
    );
    assert!(
        slot0(&target).device_ref().known_effects().sync_durable,
        "durable advances only after the explicit sync succeeds"
    );
}

/// A storage error keeps the confirmed prefix and maps to WRITE ERROR;
/// a short host send maps to ABORTED COMMAND without replacing the data fact.
#[test]
fn effect_and_double_error() {
    let mut target = Target::new(cons(slot(1), Nil));
    let mut plane = Plane::new();
    plane.fail_io_prefix = Some(128);
    let mut storage = BlockingStorage::new(plane);
    let mut host = BlockingHost::new(TestHost::new());
    let mut work = [0u8; 1024];
    let mut scratch = [0u8; 1024];

    assert_eq!(
        target.drive_static_host::<Here>(
            &mut storage,
            &mut host,
            ctx(0, Direction::FromHost, 1024),
            &write_cdb(0, 2),
            &mut work,
            &mut scratch,
        ),
        Ok(Completion::Check(WRITE_ERROR))
    );
    let device = slot0(&target).device_ref();
    assert_eq!(device.known_effects().confirmed_write, 128);
    assert!(device.known_effects().unknown_remainder);

    // Short host send: the command fails, the storage read still happened.
    let mut target = Target::new(cons(slot(1), Nil));
    let mut storage = BlockingStorage::new(Plane::new());
    let mut host = TestHost::new();
    host.read_accepts = Some(256);
    let mut host = BlockingHost::new(host);
    assert_eq!(
        target.drive_static_host::<Here>(
            &mut storage,
            &mut host,
            ctx(0, Direction::ToHost, 512),
            &read_cdb(0, 1),
            &mut work,
            &mut scratch,
        ),
        Ok(Completion::Check(COMMAND_ABORTED))
    );
    assert_eq!(slot0(&target).device_ref().io_issues(), 1);
}

/// Two LUNs with independent backing planes; the same `resource: 0`
/// never crosses the LUN boundary (application contract).
#[test]
fn two_luns_use_independent_backings() {
    let mut target = Target::new(cons(slot(1), cons(slot(2), Nil)));
    let mut storage0 = BlockingStorage::new(Plane::new());
    let mut storage1 = BlockingStorage::new(Plane::new());
    let mut host = BlockingHost::new(TestHost::new());
    let mut work = [0u8; 512];
    let mut scratch = [0u8; 512];

    assert_eq!(
        target.drive_static_host::<Here>(
            &mut storage0,
            &mut host,
            ctx(0, Direction::FromHost, 512),
            &write_cdb(0, 1),
            &mut work,
            &mut scratch,
        ),
        Ok(Completion::Good)
    );
    assert_eq!(
        target.drive_static_host::<There<Here>>(
            &mut storage1,
            &mut host,
            ctx(1, Direction::FromHost, 512),
            &write_cdb(0, 1),
            &mut work,
            &mut scratch,
        ),
        Ok(Completion::Good)
    );
    assert_eq!(
        storage0.inner().ops(),
        &[Some(LegalOp::Write {
            offset: 0,
            len: 512
        })]
    );
    assert_eq!(
        storage1.inner().ops(),
        &[Some(LegalOp::Write {
            offset: 0,
            len: 512
        })]
    );
    assert!(storage0.inner().data[..512].iter().all(|b| *b == 0xa5));
    assert!(storage1.inner().data[..512].iter().all(|b| *b == 0xa5));
    assert_eq!(storage0.inner().data[512], 0, "no cross-LUN write");
    assert_eq!(storage1.inner().data[512], 0, "no cross-LUN write");
}

/// Host eject publishes `ResourcesReady` and the pair is taken once.
#[test]
fn host_eject_hands_the_pair_back_once() {
    let mut target = Target::new(cons(slot(7), Nil));
    let mut storage = BlockingStorage::new(Plane::new());
    let mut host = BlockingHost::new(TestHost::new());
    let mut work = [0u8; 512];
    let mut scratch = [0u8; 512];
    assert_eq!(
        target.drive_static_host::<Here>(
            &mut storage,
            &mut host,
            ctx(0, Direction::ToHost, 512),
            &read_cdb(0, 1),
            &mut work,
            &mut scratch,
        ),
        Ok(Completion::Good)
    );
    assert_eq!(
        host.inner().events(),
        &[
            Some(HostEvent::Publish(snowscsi::core::DataPlan {
                direction: Direction::ToHost,
                bytes: 512,
            })),
            Some(HostEvent::Sent(512)),
        ],
        "the transport must see one plan and one natural-length send"
    );
    target
        .host_eject_succeeded_static::<Here>()
        .expect("eject succeeds");
    assert_eq!(target.tick(), RunOutcome::ResourcesReady { lun: 0 });
    let result = target
        .take_static_at::<Here>(0)
        .expect("the old pair is resident");
    assert_eq!(
        result.pair,
        Some(snowscsi::core::Pair {
            medium: NoMedium,
            backing: 7
        })
    );
    assert_eq!(result.local, Ok(()));
    assert_eq!(
        target.take_static_at::<Here>(0),
        Err(snowscsi::core::BoundaryReject::NothingToTake)
    );
}

/// Data integrity: a short host receive must write only the accepted
/// prefix and report CHECK, never a full buffer with GOOD.
#[test]
fn short_receive_writes_only_the_accepted_prefix() {
    let mut target = Target::new(cons(slot(1), Nil));
    let mut storage = BlockingStorage::new(Plane::new());
    let mut host = TestHost::new();
    host.recv_accepts = Some(128);
    let mut host = BlockingHost::new(host);
    let mut work = [0u8; 512];
    let mut scratch = [0u8; 512];
    assert_eq!(
        target.drive_static_host::<Here>(
            &mut storage,
            &mut host,
            ctx(0, Direction::FromHost, 512),
            &write_cdb(0, 1),
            &mut work,
            &mut scratch,
        ),
        Ok(Completion::Check(COMMAND_ABORTED))
    );
    assert_eq!(
        storage.inner().ops(),
        &[Some(LegalOp::Write {
            offset: 0,
            len: 128
        })],
        "only the accepted prefix reaches the backing"
    );
    assert_eq!(
        slot0(&target).device_ref().known_effects().confirmed_write,
        128
    );
}

/// The public Spc wrapper answers the six commands and uses the
/// REPORT LUNS layout.
#[test]
fn spc_six_commands_and_report_luns_layout() {
    let spc = |backing: u8| {
        LuImpl::new(
            Spc::new(BlockDevice::new(BlockAttrs::new(16, BLOCK))),
            backing,
        )
    };
    let mut target = Target::new(cons(spc(1), cons(spc(2), Nil)));
    let mut storage = BlockingStorage::new(Plane::new());
    let mut host = BlockingHost::new(TestHost::new());
    let mut work = [0u8; 64];
    let mut scratch = [0u8; 64];

    // TUR: delegated to the Block profile (0x00 -> GOOD).
    assert_eq!(
        target.drive_static::<Here>(
            &mut storage,
            ctx(0, Direction::None, 0),
            &[0x00, 0, 0, 0, 0, 0],
            &mut work,
            &mut scratch,
        ),
        Ok(Completion::Good)
    );

    // INQUIRY: 36-byte standard response.
    let mut cdb = [0u8; 6];
    cdb[0] = 0x12;
    cdb[3] = 0;
    cdb[4] = 36;
    assert_eq!(
        target.drive_static_host::<Here>(
            &mut storage,
            &mut host,
            ctx(0, Direction::ToHost, 36),
            &cdb,
            &mut work,
            &mut scratch,
        ),
        Ok(Completion::Good)
    );
    assert_eq!(work[0], 0x00, "Block PDT");
    assert_eq!(&work[8..12], b"SNOW");

    // An over-allocated INQUIRY (96) is a legal short Data-In: the runner
    // accepts plan 36 <= host_bytes 96 and the wrapper sends 36 bytes.
    let mut host = BlockingHost::new(TestHost::new());
    let mut cdb = [0u8; 6];
    cdb[0] = 0x12;
    cdb[4] = 96;
    assert_eq!(
        target.drive_static_host::<Here>(
            &mut storage,
            &mut host,
            ctx(0, Direction::ToHost, 96),
            &cdb,
            &mut work,
            &mut scratch,
        ),
        Ok(Completion::Good)
    );
    assert_eq!(&work[8..12], b"SNOW");
    assert_eq!(
        host.inner().events(),
        &[
            Some(HostEvent::Publish(snowscsi::core::DataPlan {
                direction: Direction::ToHost,
                bytes: 36,
            })),
            Some(HostEvent::Sent(36)),
        ],
        "the plan is the natural 36 bytes, not the 96-byte allocation"
    );

    // allocation length 0 transfers no data for INQUIRY and REPORT LUNS.
    let mut cdb = [0u8; 6];
    cdb[0] = 0x12;
    cdb[4] = 0;
    assert_eq!(
        target.drive_static::<Here>(
            &mut storage,
            ctx(0, Direction::ToHost, 0),
            &cdb,
            &mut work,
            &mut scratch,
        ),
        Ok(Completion::Good)
    );
    let mut cdb = [0u8; 10];
    cdb[0] = 0xA0;
    cdb[9] = 0;
    assert_eq!(
        target.drive_static::<Here>(
            &mut storage,
            ctx(0, Direction::ToHost, 0),
            &cdb,
            &mut work,
            &mut scratch,
        ),
        Ok(Completion::Good)
    );

    // REPORT LUNS truncation to 17 bytes keeps the full-response prefix; the
    // second descriptor stops before its LUN byte (byte 17).
    let mut host = BlockingHost::new(TestHost::new());
    // Clear the bank so the truncation assertion is self-contained.
    work.fill(0);
    let mut cdb = [0u8; 10];
    cdb[0] = 0xA0;
    cdb[9] = 17;
    assert_eq!(
        target.drive_static_host::<Here>(
            &mut storage,
            &mut host,
            ctx(0, Direction::ToHost, 17),
            &cdb,
            &mut work,
            &mut scratch,
        ),
        Ok(Completion::Good)
    );
    assert_eq!(
        host.inner().events(),
        &[
            Some(HostEvent::Publish(snowscsi::core::DataPlan {
                direction: Direction::ToHost,
                bytes: 17,
            })),
            Some(HostEvent::Sent(17)),
        ]
    );
    assert_eq!(&work[0..4], &16u32.to_be_bytes());
    assert_eq!(work[16], 0);
    assert_eq!(work[17], 0, "the second descriptor's LUN byte is not sent");

    // REPORT LUNS: 8-byte header + SAM-3 single-level descriptors.
    let mut cdb = [0u8; 10];
    cdb[0] = 0xA0;
    cdb[8] = 0;
    cdb[9] = 24;
    assert_eq!(
        target.drive_static_host::<Here>(
            &mut storage,
            &mut host,
            ctx(0, Direction::ToHost, 24),
            &cdb,
            &mut work,
            &mut scratch,
        ),
        Ok(Completion::Good)
    );
    assert_eq!(&work[0..4], &16u32.to_be_bytes());
    assert_eq!(&work[8..16], &[0x00, 0, 0, 0, 0, 0, 0, 0]);
    assert_eq!(&work[16..24], &[0x00, 1, 0, 0, 0, 0, 0, 0]);

    // PREVENT/ALLOW: SPC-3 two-bit encoding on a Block device.
    let mut cdb = [0u8; 6];
    cdb[0] = 0x1E;
    cdb[4] = 1;
    assert_eq!(
        target.drive_static::<Here>(
            &mut storage,
            ctx(0, Direction::None, 0),
            &cdb,
            &mut work,
            &mut scratch,
        ),
        Ok(Completion::Good)
    );
    assert!(slot0(&target).device_ref().is_prevented());

    // START STOP UNIT stores the start bit only.
    let mut cdb = [0u8; 6];
    cdb[0] = 0x1B;
    cdb[4] = 0;
    assert_eq!(
        target.drive_static::<Here>(
            &mut storage,
            ctx(0, Direction::None, 0),
            &cdb,
            &mut work,
            &mut scratch,
        ),
        Ok(Completion::Good)
    );
    assert!(!slot0(&target).device_ref().is_started());

    // REQUEST SENSE with no saved sense returns a NO SENSE fixed response.
    let mut cdb = [0u8; 6];
    cdb[0] = 0x03;
    cdb[4] = 18;
    assert_eq!(
        target.drive_static_host::<Here>(
            &mut storage,
            &mut host,
            ctx(0, Direction::ToHost, 18),
            &cdb,
            &mut work,
            &mut scratch,
        ),
        Ok(Completion::Good)
    );
    assert_eq!(work[0], 0x70);
    assert_eq!(work[7], 10);

    // A prepare-level CHECK is a real command sense: REQUEST SENSE returns it.
    let mut cdb = [0u8; 10];
    cdb[0] = 0x28;
    cdb[5] = 16; // LBA 16 == capacity
    cdb[8] = 1;
    assert_eq!(
        target.drive_static::<Here>(
            &mut storage,
            ctx(0, Direction::ToHost, 512),
            &cdb,
            &mut work,
            &mut scratch,
        ),
        Ok(Completion::Check(LBA_OUT_OF_RANGE))
    );
    let mut rs = [0u8; 6];
    rs[0] = 0x03;
    rs[4] = 18;
    assert_eq!(
        target.drive_static_host::<Here>(
            &mut storage,
            &mut host,
            ctx(0, Direction::ToHost, 18),
            &rs,
            &mut work,
            &mut scratch,
        ),
        Ok(Completion::Good)
    );
    assert_eq!(work[2], 0x05);
    assert_eq!(work[12], 0x21);

    // The normal PREVENT latch set above is cleared by the host's own EJECT.
    assert!(slot0(&target).device_ref().is_prevented());
    target
        .host_eject_succeeded_static::<Here>()
        .expect("host eject");
    assert!(!slot0(&target).device_ref().is_prevented());
}

/// A takeover/install round trip through the public runtime API.
#[test]
fn runtime_take_and_reinstall_round_trip() {
    use snowscsi::core::Lu;
    let mut slots = [slot(1)];
    let table: [&mut dyn Lu<Pair = snowscsi::core::Pair<NoMedium, u8>>; 1] = [&mut slots[0]];
    let mut target = Target::new(table);
    assert_eq!(target.propose_rt(0, Change::Remove), Ok(()));
    assert_eq!(target.advance_rt(0), Ok(()));
    let old = target.take_rt(0).expect("old pair");
    assert_eq!(
        old.pair,
        Some(snowscsi::core::Pair {
            medium: NoMedium,
            backing: 1
        })
    );
    assert_eq!(target.install_rt(0, old.pair.expect("pair")), Ok(()));
}

/// A READ larger than the caller's bank streams: one normal read, then a
/// speculative prefetch per following chunk, with byte-exact host data.
#[test]
fn read_larger_than_the_bank_streams_with_prefetch() {
    let mut target = Target::new(cons(slot(1), Nil));
    let mut plane = Plane::new();
    for (i, byte) in plane.data.iter_mut().enumerate() {
        *byte = (i & 0xFF) as u8;
    }
    let mut storage = BlockingStorage::new(plane);
    let mut host = BlockingHost::new(TestHost::new());
    let mut work = [0u8; 512];
    let mut scratch = [0u8; 512];

    assert_eq!(
        target.drive_static_host::<Here>(
            &mut storage,
            &mut host,
            ctx(0, Direction::ToHost, 2048),
            &read_cdb(0, 4),
            &mut work,
            &mut scratch,
        ),
        Ok(Completion::Good)
    );
    let device = slot0(&target).device_ref();
    assert_eq!(
        device.io_issues(),
        1,
        "only the first chunk is a normal read"
    );
    assert_eq!(device.prefetch_issues(), 3, "chunks - 1 prefetches");
    assert_eq!(
        &host.inner().sent_data[..host.inner().sent_len],
        &storage.inner().data[..2048],
        "the streamed data is byte-exact"
    );
}

/// A failed speculative read falls back to a normal read of the same range;
/// the completion stays GOOD and the data is complete.
#[test]
fn a_failed_prefetch_falls_back_without_changing_the_completion() {
    let mut target = Target::new(cons(slot(1), Nil));
    let mut plane = Plane::new();
    for (i, byte) in plane.data.iter_mut().enumerate() {
        *byte = (i & 0xFF) as u8;
    }
    plane.fail_read_offset = Some(512);
    let mut storage = BlockingStorage::new(plane);
    let mut host = BlockingHost::new(TestHost::new());
    let mut work = [0u8; 512];
    let mut scratch = [0u8; 512];

    assert_eq!(
        target.drive_static_host::<Here>(
            &mut storage,
            &mut host,
            ctx(0, Direction::ToHost, 1024),
            &read_cdb(0, 2),
            &mut work,
            &mut scratch,
        ),
        Ok(Completion::Good)
    );
    let device = slot0(&target).device_ref();
    assert_eq!(device.io_issues(), 2, "first chunk + fallback re-read");
    assert_eq!(device.prefetch_issues(), 1);
    assert_eq!(
        &host.inner().sent_data[..host.inner().sent_len],
        &storage.inner().data[..1024]
    );
}

/// A WRITE larger than the bank commits every chunk, byte-exact.
#[test]
fn write_larger_than_the_bank_commits_every_chunk() {
    let mut target = Target::new(cons(slot(1), Nil));
    let mut storage = BlockingStorage::new(Plane::new());
    let mut host = BlockingHost::new(TestHost::new());
    let mut work = [0u8; 512];
    let mut scratch = [0u8; 512];

    assert_eq!(
        target.drive_static_host::<Here>(
            &mut storage,
            &mut host,
            ctx(0, Direction::FromHost, 1536),
            &write_cdb(0, 3),
            &mut work,
            &mut scratch,
        ),
        Ok(Completion::Good)
    );
    assert!(storage.inner().data[..1536].iter().all(|b| *b == 0xa5));
    assert_eq!(
        slot0(&target).device_ref().known_effects().confirmed_write,
        1536
    );
    assert_eq!(
        storage.inner().ops(),
        &[
            Some(LegalOp::Write {
                offset: 0,
                len: 512
            }),
            Some(LegalOp::Write {
                offset: 512,
                len: 512
            }),
            Some(LegalOp::Write {
                offset: 1024,
                len: 512
            }),
        ]
    );
}
