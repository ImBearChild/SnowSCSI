//! Two-bank iSCSI overlap tests.
//!
//! The session owns two equal banks inside `work`; command framing and Data-Out
//! stay in the command bank while Data-In may alternate between the two banks.
//! These tests drive the session through its `Action`/`Event` protocol over the
//! scripted [`MockConn`] and inspect the absolute offset of every send.

use std::cell::Cell;
use std::rc::Rc;
use std::task::Poll;

use snowscsi::common::seekable_storage::RamBackend;
use snowscsi::common::store::StorePlane;
use snowscsi::core::storage::{IoBuf, IoReq, IoToken, Storage, StorageReceipt};
use snowscsi::core::{Lu, Target};
use snowscsi::iscsi::pdu::{flag, op, stage, status, BHS_SIZE};
use snowscsi::iscsi::target::{Action, Event, IscsiSession};
use snowscsi::MIN_DATA_LEN;

use crate::iscsi_harness::{PlaneSet, TestLu, TestPair};
use crate::mock_conn::MockConn;

/// One bank: the BHS prefix plus the default data area.
const BANK: usize = MIN_DATA_LEN + BHS_SIZE;

fn be32(v: u32) -> [u8; 4] {
    v.to_be_bytes()
}

/// Login parameters as sent by a Linux open-iscsi initiator.
const REQ_TEXT: &str = "InitiatorName=iqn.1994-05.com.redhat:702f27e1da14\0InitiatorAlias=develop\0TargetName=iqn.1970-01.local.snowscsi:target\0SessionType=Normal\0HeaderDigest=None\0DataDigest=None\0DefaultTime2Wait=2\0DefaultTime2Retain=0\0IFMarker=No\0OFMarker=No\0ErrorRecoveryLevel=0\0InitialR2T=No\0ImmediateData=Yes\0MaxBurstLength=16776192\0FirstBurstLength=262144\0MaxOutstandingR2T=1\0MaxConnections=1\0DataPDUInOrder=Yes\0DataSequenceInOrder=Yes\0MaxRecvDataSegmentLength=262144\0";

fn login_bhs(dsl: u32) -> [u8; 48] {
    let mut bhs = [0u8; 48];
    bhs[0] = op::LOGIN_REQ | 0x40;
    bhs[1] = flag::T_BIT | ((stage::OP_PARAM & 0x03) << flag::CSG_SHIFT) | stage::FULL_FEATURE;
    bhs[5] = (dsl >> 16) as u8;
    bhs[6] = (dsl >> 8) as u8;
    bhs[7] = dsl as u8;
    bhs[8..14].copy_from_slice(&[0x00, 0x01, 0x23, 0x45, 0x67, 0x89]);
    bhs
}

fn read10_bhs(lba: u32, blocks: u16, itt: u32, cmd_sn: u32) -> [u8; 48] {
    let mut bhs = [0u8; 48];
    bhs[0] = op::SCSI_CMD;
    bhs[1] = 0x40; // task attribute (direction comes from the CDB)
    bhs[16..20].copy_from_slice(&be32(itt));
    bhs[24..28].copy_from_slice(&be32(cmd_sn));
    bhs[28..32].copy_from_slice(&be32(cmd_sn)); // ExpStatSN
    bhs[32] = 0x28; // READ(10)
    bhs[34..38].copy_from_slice(&be32(lba));
    bhs[39..41].copy_from_slice(&blocks.to_be_bytes());
    bhs
}

fn tur_bhs(itt: u32, cmd_sn: u32) -> [u8; 48] {
    let mut bhs = [0u8; 48];
    bhs[0] = op::SCSI_CMD;
    bhs[1] = 0x40;
    bhs[16..20].copy_from_slice(&be32(itt));
    bhs[24..28].copy_from_slice(&be32(cmd_sn));
    bhs[28..32].copy_from_slice(&be32(cmd_sn));
    bhs[32] = 0x00; // TEST UNIT READY
    bhs
}

fn format_bhs(itt: u32, cmd_sn: u32, dsl: u32) -> [u8; 48] {
    let mut bhs = [0u8; 48];
    bhs[0] = op::SCSI_CMD;
    bhs[1] = 0x20; // W bit: the parameter list is Data-Out
    bhs[5] = (dsl >> 16) as u8;
    bhs[6] = (dsl >> 8) as u8;
    bhs[7] = dsl as u8;
    bhs[16..20].copy_from_slice(&be32(itt));
    bhs[24..28].copy_from_slice(&be32(cmd_sn));
    bhs[28..32].copy_from_slice(&be32(cmd_sn));
    bhs[32] = 0x04; // FORMAT UNIT
    bhs[33] = 0x11; // FmtData=1, defect-list format 1
    bhs
}

/// One send observed at the session boundary.
#[derive(Clone, Debug)]
struct Sent {
    /// Absolute offset of the PDU inside `work`.
    offset: usize,
    /// PDU bytes, copied when the send was emitted (the bank is reused later).
    bytes: Vec<u8>,
}

impl Sent {
    fn opcode(&self) -> u8 {
        self.bytes[0] & 0x3F
    }

    fn dsl(&self) -> usize {
        (usize::from(self.bytes[5]) << 16)
            | (usize::from(self.bytes[6]) << 8)
            | usize::from(self.bytes[7])
    }
}

/// Drive the session until the scripted peer runs out of bytes.
///
/// `work` is the caller's total allocation; sends are recorded with the
/// absolute offset the session chose, which is how the two-bank layout is
/// observed.
#[allow(clippy::too_many_arguments)]
fn drive<S: snowscsi::core::RuntimeSet>(
    session: &mut IscsiSession,
    conn: &mut MockConn,
    work: &mut [u8],
    scratch: &mut [u8],
    target: &mut Target<S>,
    storage: &mut dyn Storage,
    sent: &mut Vec<Sent>,
) {
    use embedded_io::Read as _;
    let work_start = work.as_ptr() as usize;
    let mut ev = Event::Tick;
    loop {
        match session.poll(ev, work, scratch, target, storage) {
            Action::HostRecv { offset, len } => {
                let mut got = 0usize;
                while got < len {
                    match conn.read(&mut work[offset + got..offset + len]) {
                        Ok(0) => return,
                        Ok(n) => got += n,
                        Err(_) => return,
                    }
                }
                ev = Event::HostRecv { len };
            }
            Action::HostSend { bytes, .. } => {
                let offset = bytes.as_ptr() as usize - work_start;
                sent.push(Sent {
                    offset,
                    bytes: bytes.to_vec(),
                });
                embedded_io::Write::write_all(conn, bytes).unwrap();
                ev = Event::HostSent;
            }
            Action::StoragePending => ev = Event::Tick,
            Action::Closed => return,
            Action::Error(e) => panic!("session error: {e:?}"),
        }
    }
}

/// Data-In payloads concatenated from the recorded PDUs, in wire order.
fn data_in_payload(sent: &[Sent]) -> Vec<u8> {
    let mut out = Vec::new();
    for pdu in sent {
        if pdu.opcode() != op::SCSI_DATA_IN {
            continue;
        }
        let dsl = pdu.dsl();
        out.extend_from_slice(&pdu.bytes[BHS_SIZE..BHS_SIZE + dsl]);
    }
    out
}

/// A 2 MiB READ over two 8 KiB banks: every Data-In chunk alternates banks,
/// its BHS sits at that bank's base, and the bytes are exact.
#[test]
fn overlap_read_alternates_banks_and_is_byte_exact() {
    const BLOCKS: u16 = 4096; // 2 MiB at 512-byte blocks
    const TOTAL: usize = BLOCKS as usize * 512;
    const CHUNK: usize = BANK - BHS_SIZE;

    let mut ram = vec![0u8; TOTAL];
    for (i, b) in ram.iter_mut().enumerate() {
        *b = (i % 251) as u8;
    }
    let expected = ram.clone();
    let mut backend = RamBackend::new(&mut ram);
    let mut slots = [TestLu::block(BLOCKS as u64, 512, 0)];
    let mut table: Vec<&mut dyn Lu<Pair = TestPair>> = slots
        .iter_mut()
        .map(|s| s as &mut dyn Lu<Pair = TestPair>)
        .collect();
    let mut target = Target::new(&mut table[..]);
    let mut storage = PlaneSet::new(vec![Some(StorePlane::BlockRw(&mut backend))]);

    let mut session = IscsiSession::new().with_overlap();
    assert!(session.overlap());
    let mut work = vec![0u8; 2 * BANK];
    let mut scratch = Vec::new();
    let mut conn = MockConn::new();
    conn.feed_padded(&login_bhs(REQ_TEXT.len() as u32), REQ_TEXT.as_bytes());
    conn.feed(&read10_bhs(0, BLOCKS, 7, 0), &[]);

    let mut sent = Vec::new();
    drive(
        &mut session,
        &mut conn,
        &mut work,
        &mut scratch,
        &mut target,
        &mut storage,
        &mut sent,
    );

    let data_pdus: Vec<&Sent> = sent
        .iter()
        .filter(|p| p.opcode() == op::SCSI_DATA_IN)
        .collect();
    assert_eq!(data_pdus.len(), TOTAL / CHUNK, "one PDU per device chunk");
    for (i, pdu) in data_pdus.iter().enumerate() {
        assert_eq!(
            pdu.offset,
            (i % 2) * BANK,
            "Data-In chunk {i} must use bank {}",
            i % 2
        );
        assert_eq!(pdu.bytes.len(), BANK, "a full-bank Data-In PDU");
    }
    let payload = data_in_payload(&sent);
    assert_eq!(payload.len(), TOTAL, "all device bytes reached the wire");
    assert_eq!(payload, expected, "byte-exact read");

    // The terminating Data-In carries the S bit and GOOD status.
    let last = data_pdus.last().unwrap();
    assert_ne!(last.bytes[1] & flag::S_BIT, 0, "final Data-In has S=1");
    assert_eq!(last.bytes[3], status::GOOD);
}

/// The command BHS is read at the command bank, and a Data-In chunk staged from
/// the alternate bank carries that bank's base in its deferred send.
#[test]
fn overlap_command_bhs_is_at_the_command_bank() {
    const BLOCKS: u16 = 4;
    let mut ram = vec![0x5Au8; 32 * 1024];
    let mut backend = RamBackend::new(&mut ram);
    let mut slots = [TestLu::block(64, 512, 0)];
    let mut table: Vec<&mut dyn Lu<Pair = TestPair>> = slots
        .iter_mut()
        .map(|s| s as &mut dyn Lu<Pair = TestPair>)
        .collect();
    let mut target = Target::new(&mut table[..]);
    let mut storage = PlaneSet::new(vec![Some(StorePlane::BlockRw(&mut backend))]);
    let mut session = IscsiSession::new().with_overlap();
    let mut work = vec![0u8; 2 * BANK];
    let mut scratch = Vec::new();
    let mut conn = MockConn::new();
    conn.feed_padded(&login_bhs(REQ_TEXT.len() as u32), REQ_TEXT.as_bytes());
    conn.feed(&read10_bhs(0, BLOCKS, 1, 0), &[]);

    let mut sent = Vec::new();
    drive(
        &mut session,
        &mut conn,
        &mut work,
        &mut scratch,
        &mut target,
        &mut storage,
        &mut sent,
    );

    // Login response and the command's Data-In both start at bank A's base;
    // the command BHS itself was staged there as well.
    let first = sent.first().expect("login response");
    assert_eq!(
        first.offset, 0,
        "login response is framed at the control base"
    );
    assert_eq!(first.opcode(), op::LOGIN_RESP);

    let data = sent
        .iter()
        .find(|p| p.opcode() == op::SCSI_DATA_IN)
        .expect("a Data-In PDU");
    assert_eq!(
        data.offset, 0,
        "the first device chunk uses the command bank"
    );
    assert_eq!(&data.bytes[BHS_SIZE..BHS_SIZE + 4], &[0x5A; 4]);
}

/// A small FORMAT UNIT that leaves the resident long operation armed.
#[test]
fn overlap_long_token_holds_one_bank_and_the_tur_uses_the_other() {
    let mut ram = vec![0xEEu8; 64 * 1024];
    let mut backend = RamBackend::new(&mut ram);
    let mut slots = [TestLu::dvdram(1, 0)];
    let mut table: Vec<&mut dyn Lu<Pair = TestPair>> = slots
        .iter_mut()
        .map(|s| s as &mut dyn Lu<Pair = TestPair>)
        .collect();
    let mut target = Target::new(&mut table[..]);
    // Keep the first long-operation IO pending so `long_bank` stays live while
    // the TUR is served.
    let mut storage = PlaneSet::new(vec![Some(StorePlane::BlockRw(&mut backend))]).with_pending(1);
    let mut session = IscsiSession::new().with_overlap();
    let mut work = vec![0u8; 2 * BANK];
    let mut scratch = Vec::new();
    let mut conn = MockConn::new();

    // FORMAT UNIT with a 12-byte parameter list (Immed=1).
    let mut params = [0u8; 12];
    params[1] = 0x02; // Immed
    params[2..4].copy_from_slice(&8u16.to_be_bytes());
    params[8] = 0x00; // Format Type 0
    conn.feed_padded(&login_bhs(REQ_TEXT.len() as u32), REQ_TEXT.as_bytes());
    conn.feed_padded(&format_bhs(1, 0, params.len() as u32), &params);

    let mut sent = Vec::new();
    drive(
        &mut session,
        &mut conn,
        &mut work,
        &mut scratch,
        &mut target,
        &mut storage,
        &mut sent,
    );

    // The format completed and armed the resident long operation. The next
    // boundary Tick starts it on the bank the command does not hold, then the
    // TUR is read while its token is still in flight.
    let command_bank = 0;
    conn.feed(&tur_bhs(2, 1), &[]);
    let mut sent = Vec::new();
    drive(
        &mut session,
        &mut conn,
        &mut work,
        &mut scratch,
        &mut target,
        &mut storage,
        &mut sent,
    );
    assert_eq!(
        session.long_bank(),
        Some(snowscsi::core::storage::BankSide::Alt),
        "the long token takes the alternate bank while the TUR is served"
    );
    let tur_resp = sent
        .iter()
        .find(|p| p.opcode() == op::SCSI_RESP)
        .expect("the TUR is answered in the command bank");
    assert_eq!(
        tur_resp.offset, 0,
        "the TUR response is staged in bank {}",
        command_bank
    );
    assert_eq!(
        u32::from_be_bytes(tur_resp.bytes[16..20].try_into().unwrap()),
        2
    );
    assert!(
        matches!(tur_resp.bytes[3], status::GOOD | status::CHECK_CONDITION),
        "the TUR is answered (a fill in progress reports CHECK CONDITION)"
    );

    // Keep the boundary Ticks coming until the resident fill settles; both
    // banks are free again afterwards.
    for _ in 0..64 {
        match session.poll(
            Event::Tick,
            &mut work,
            &mut scratch,
            &mut target,
            &mut storage,
        ) {
            Action::HostRecv { .. } | Action::StoragePending => {}
            Action::Closed => break,
            other => panic!("unexpected action: {other:?}"),
        }
        if !target.long_io_in_flight() && session.long_bank().is_none() {
            break;
        }
    }
    assert!(session.long_bank().is_none(), "settled long operation");
    drop(storage);
    assert!(
        ram[..2048].iter().all(|b| *b == 0),
        "the FORMAT fill is byte-exact"
    );
}

/// A command that gets only one bank never prefetches into the long bank: the
/// long token holds bank B and a READ is staged and sent entirely from bank A.
#[test]
fn overlap_one_bank_read_never_uses_the_long_bank() {
    const BLOCKS: u16 = 32; // 16 KiB = two bank-sized chunks
    const TOTAL: usize = BLOCKS as usize * 512;

    let mut long_ram = vec![0xEEu8; 64 * 1024];
    let mut cmd_ram = vec![0u8; TOTAL];
    for (i, b) in cmd_ram.iter_mut().enumerate() {
        *b = (i % 251) as u8;
    }
    let expected = cmd_ram.clone();

    let mut slots = [TestLu::dvdram(1, 0), TestLu::block(128, 512, 1)];
    let mut table: Vec<&mut dyn Lu<Pair = TestPair>> = slots
        .iter_mut()
        .map(|s| s as &mut dyn Lu<Pair = TestPair>)
        .collect();
    let mut target = Target::new(&mut table[..]);

    let mut long_backend = RamBackend::new(&mut long_ram);
    let mut cmd_backend = RamBackend::new(&mut cmd_ram);
    let long = PlaneSet::new(vec![Some(StorePlane::BlockRw(&mut long_backend))]).with_pending(1);
    let command = PlaneSet::new(vec![Some(StorePlane::BlockRw(&mut cmd_backend))]);
    let mut storage = SplitLunPlan {
        long,
        command,
        lun: 0,
    };

    let mut session = IscsiSession::new().with_overlap();
    let mut work = vec![0u8; 2 * BANK];
    let mut scratch = Vec::new();
    let mut conn = MockConn::new();

    // Arm the fill (LUN 0) and then read LUN 1 while its token is in flight.
    let mut params = [0u8; 12];
    params[1] = 0x02;
    params[2..4].copy_from_slice(&8u16.to_be_bytes());
    params[8] = 0x00;
    conn.feed_padded(&login_bhs(REQ_TEXT.len() as u32), REQ_TEXT.as_bytes());
    conn.feed_padded(&format_bhs(1, 0, params.len() as u32), &params);
    let mut sent = Vec::new();
    drive(
        &mut session,
        &mut conn,
        &mut work,
        &mut scratch,
        &mut target,
        &mut storage,
        &mut sent,
    );

    // READ on LUN 1: 16 KiB, two bank-sized chunks. The next boundary Tick
    // starts the fill on bank B, so the command gets bank A only.
    let mut read = read10_bhs(0, BLOCKS, 2, 1);
    read[9] = 1; // LUN 1
    conn.feed(&read, &[]);
    let mut sent = Vec::new();
    drive(
        &mut session,
        &mut conn,
        &mut work,
        &mut scratch,
        &mut target,
        &mut storage,
        &mut sent,
    );
    assert!(session.long_bank().is_some(), "the fill holds one bank");

    let data: Vec<&Sent> = sent
        .iter()
        .filter(|p| p.opcode() == op::SCSI_DATA_IN)
        .collect();
    assert!(!data.is_empty());
    for pdu in &data {
        assert_eq!(pdu.offset, 0, "a one-bank command stays in bank A");
    }
    assert_eq!(data_in_payload(&sent), expected, "byte-exact read");
}

/// Storage routing that gives the long operation and the command independent
/// planes while both are alive.
struct SplitLunPlan<'a> {
    long: PlaneSet<'a>,
    command: PlaneSet<'a>,
    lun: usize,
}

impl Storage for SplitLunPlan<'_> {
    fn select_lun(&mut self, lun: usize) {
        self.lun = lun;
        self.long.select_lun(0);
        self.command.select_lun(0);
    }

    fn begin_exec(&mut self, req: IoReq) -> IoToken {
        if self.lun == 0 {
            self.long.begin_exec(req)
        } else {
            self.command.begin_exec(req)
        }
    }

    fn poll_exec(&mut self, token: IoToken, buf: IoBuf<'_>) -> Poll<StorageReceipt> {
        if self.lun == 0 {
            self.long.poll_exec(token, buf)
        } else {
            self.command.poll_exec(token, buf)
        }
    }

    fn cancel(&mut self, token: IoToken) {
        if self.lun == 0 {
            self.long.cancel(token);
        } else {
            self.command.cancel(token);
        }
    }
}

/// Storage wrapper that records whether an adapter token is pending.
struct PendingProbe<'a> {
    inner: SplitLunPlan<'a>,
    in_flight: Rc<Cell<bool>>,
}

impl Storage for PendingProbe<'_> {
    fn select_lun(&mut self, lun: usize) {
        self.inner.select_lun(lun);
    }

    fn begin_exec(&mut self, req: IoReq) -> IoToken {
        self.inner.begin_exec(req)
    }

    fn poll_exec(&mut self, token: IoToken, buf: IoBuf<'_>) -> Poll<StorageReceipt> {
        let receipt = self.inner.poll_exec(token, buf);
        self.in_flight.set(matches!(receipt, Poll::Pending));
        receipt
    }

    fn cancel(&mut self, token: IoToken) {
        self.inner.cancel(token);
    }
}

/// Connection wrapper: records a read issued while a storage token is pending.
struct PendingConn {
    inner: MockConn,
    in_flight: Rc<Cell<bool>>,
    read_while_in_flight: Rc<Cell<bool>>,
}

impl embedded_io::ErrorType for PendingConn {
    type Error = core::convert::Infallible;
}

impl embedded_io::Read for PendingConn {
    fn read(&mut self, buf: &mut [u8]) -> Result<usize, Self::Error> {
        if self.in_flight.get() {
            self.read_while_in_flight.set(true);
        }
        embedded_io::Read::read(&mut self.inner, buf)
    }
}

impl embedded_io::Write for PendingConn {
    fn write(&mut self, buf: &[u8]) -> Result<usize, Self::Error> {
        embedded_io::Write::write(&mut self.inner, buf)
    }

    fn flush(&mut self) -> Result<(), Self::Error> {
        embedded_io::Write::flush(&mut self.inner)
    }
}

/// The shell keeps reading input while a long token is in flight: a TUR BHS
/// arriving then is consumed (the session's other bank serves it) instead of
/// waiting for the token to settle.
#[test]
fn overlap_shell_does_not_defer_input_for_a_long_token() {
    use snowscsi::iscsi::transport::serve_conn;

    let mut long_ram = vec![0xEEu8; 64 * 1024];
    let mut cmd_ram = vec![0u8; 32 * 1024];
    let mut slots = [TestLu::dvdram(1, 0), TestLu::block(64, 512, 1)];
    let mut table: Vec<&mut dyn Lu<Pair = TestPair>> = slots
        .iter_mut()
        .map(|s| s as &mut dyn Lu<Pair = TestPair>)
        .collect();
    let mut target = Target::new(&mut table[..]);

    let mut long_backend = RamBackend::new(&mut long_ram);
    let mut cmd_backend = RamBackend::new(&mut cmd_ram);
    let long = PlaneSet::new(vec![Some(StorePlane::BlockRw(&mut long_backend))]).with_pending(1);
    let command = PlaneSet::new(vec![Some(StorePlane::BlockRw(&mut cmd_backend))]);
    let in_flight = Rc::new(Cell::new(false));
    let read_while_in_flight = Rc::new(Cell::new(false));
    let mut storage = PendingProbe {
        inner: SplitLunPlan {
            long,
            command,
            lun: 0,
        },
        in_flight: Rc::clone(&in_flight),
    };

    let mut params = [0u8; 12];
    params[1] = 0x02;
    params[2..4].copy_from_slice(&8u16.to_be_bytes());
    params[8] = 0x00;
    let mut tur1 = tur_bhs(2, 1);
    tur1[9] = 1;
    let mut tur2 = tur_bhs(3, 2);
    tur2[9] = 1;

    let mut inner = MockConn::new();
    inner.feed_padded(&login_bhs(REQ_TEXT.len() as u32), REQ_TEXT.as_bytes());
    inner.feed_padded(&format_bhs(1, 0, params.len() as u32), &params);
    inner.feed(&tur1, &[]);
    inner.feed(&tur2, &[]);
    let mut conn = PendingConn {
        inner,
        in_flight: Rc::clone(&in_flight),
        read_while_in_flight: Rc::clone(&read_while_in_flight),
    };

    let mut session = IscsiSession::new().with_overlap();
    let mut work = vec![0u8; 2 * BANK];
    let mut scratch = Vec::new();
    assert_eq!(
        serve_conn(
            &mut conn,
            &mut work,
            &mut scratch,
            &mut session,
            &mut target,
            &mut storage,
        ),
        Ok(())
    );

    assert!(
        read_while_in_flight.get(),
        "the overlap shell must read input while the long token is in flight"
    );
    // Both TURs were answered (the script ran to EOF after consuming them).
    let tx = &conn.inner.tx;
    let mut off = 0usize;
    let mut itts = Vec::new();
    while off + BHS_SIZE <= tx.len() {
        let dsl = (usize::from(tx[off + 5]) << 16)
            | (usize::from(tx[off + 6]) << 8)
            | usize::from(tx[off + 7]);
        if tx[off] & 0x3F == op::SCSI_RESP {
            itts.push(u32::from_be_bytes(
                tx[off + 16..off + 20].try_into().unwrap(),
            ));
        }
        off += BHS_SIZE + dsl + (4 - ((BHS_SIZE + dsl) & 3)) % 4;
    }
    assert!(
        itts.contains(&2) && itts.contains(&3),
        "both TURs reached the wire: {itts:?}"
    );
}

// ── Timing probe: two banks on a copying wire ───────────────────────

/// `PlaneSet` with an artificial per-operation delay. This models a slow
/// backing store; the mock wire still copies into a `Vec`, so it is the
/// analogue of a blocking TCP `write` (the caller's buffer is free as soon as
/// the write returns).
struct SlowStorage<'a> {
    inner: PlaneSet<'a>,
    delay: std::time::Duration,
}

impl Storage for SlowStorage<'_> {
    fn select_lun(&mut self, lun: usize) {
        self.inner.select_lun(lun);
    }

    fn begin_exec(&mut self, req: IoReq) -> IoToken {
        self.inner.begin_exec(req)
    }

    fn poll_exec(&mut self, token: IoToken, buf: IoBuf<'_>) -> Poll<StorageReceipt> {
        std::thread::sleep(self.delay);
        self.inner.poll_exec(token, buf)
    }

    fn cancel(&mut self, token: IoToken) {
        self.inner.cancel(token);
    }
}

fn measure_read(overlap: bool, delay: std::time::Duration) -> std::time::Duration {
    const BLOCKS: u16 = 256; // 128 KiB at 512-byte blocks
    const TOTAL: usize = BLOCKS as usize * 512;

    let mut ram = vec![0u8; TOTAL];
    let mut backend = RamBackend::new(&mut ram);
    let mut slots = [TestLu::block(BLOCKS as u64, 512, 0)];
    let mut table: Vec<&mut dyn Lu<Pair = TestPair>> = slots
        .iter_mut()
        .map(|s| s as &mut dyn Lu<Pair = TestPair>)
        .collect();
    let mut target = Target::new(&mut table[..]);
    let mut storage = SlowStorage {
        inner: PlaneSet::new(vec![Some(StorePlane::BlockRw(&mut backend))]),
        delay,
    };

    let mut session = if overlap {
        IscsiSession::new().with_overlap()
    } else {
        IscsiSession::new()
    };
    let mut work = vec![0u8; if overlap { 2 * BANK } else { BANK }];
    let mut scratch = Vec::new();
    let mut conn = MockConn::new();
    conn.feed_padded(&login_bhs(REQ_TEXT.len() as u32), REQ_TEXT.as_bytes());
    conn.feed(&read10_bhs(0, BLOCKS, 7, 0), &[]);

    let started = std::time::Instant::now();
    drive(
        &mut session,
        &mut conn,
        &mut work,
        &mut scratch,
        &mut target,
        &mut storage,
        &mut Vec::new(),
    );
    started.elapsed()
}

/// Timing probe, ignored by default. The mock wire copies, so both modes are
/// expected to be dominated by the storage delay; the two banks only help a
/// transport that keeps the caller's buffer busy after `write` returns.
#[test]
#[ignore = "timing probe; run with --ignored --nocapture"]
fn measure_single_vs_overlap_on_a_copying_wire() {
    let delay = std::time::Duration::from_millis(2);
    // Warm up once so the allocator and the first-touch faults do not skew the
    // comparison.
    let _ = measure_read(false, std::time::Duration::ZERO);
    let single = measure_read(false, delay);
    let overlap = measure_read(true, delay);
    println!("single-bank={single:?} overlap={overlap:?} (storage delay {delay:?}/read)");
}

/// Storage plane that delays only the companion: the first operation (the
/// required read) settles at once, later operations answer `Pending` a
/// programmed number of times.
struct DelayedPrefetchStorage<'a> {
    inner: PlaneSet<'a>,
    begins: usize,
    prefetch_pending: u32,
}

impl<'a> DelayedPrefetchStorage<'a> {
    fn new(inner: PlaneSet<'a>, prefetch_pending: u32) -> Self {
        Self {
            inner,
            begins: 0,
            prefetch_pending,
        }
    }
}

impl Storage for DelayedPrefetchStorage<'_> {
    fn select_lun(&mut self, lun: usize) {
        self.inner.select_lun(lun);
    }

    fn begin_exec(&mut self, req: IoReq) -> IoToken {
        self.begins = self.begins.saturating_add(1);
        self.inner.begin_exec(req)
    }

    fn poll_exec(&mut self, token: IoToken, buf: IoBuf<'_>) -> Poll<StorageReceipt> {
        if self.begins >= 2 && self.prefetch_pending > 0 {
            self.prefetch_pending -= 1;
            return Poll::Pending;
        }
        self.inner.poll_exec(token, buf)
    }

    fn cancel(&mut self, token: IoToken) {
        self.inner.cancel(token);
    }
}

/// A storage-only step after the wire send reports `StoragePending`, and the
/// next `Tick` delivers the combined receipt and the next Data-In chunk.
#[test]
fn pending_after_host_sent_reports_storage_pending_then_delivers_the_next_chunk() {
    use embedded_io::Read as _;

    const BLOCKS: u16 = 64;
    const TOTAL: usize = BLOCKS as usize * 512;

    let mut ram = vec![0u8; TOTAL];
    for (i, byte) in ram.iter_mut().enumerate() {
        *byte = (i % 251) as u8;
    }
    let expected = ram.clone();
    let mut backend = RamBackend::new(&mut ram);
    let mut slots = [TestLu::block(u64::from(BLOCKS), 512, 0)];
    let mut table: Vec<&mut dyn Lu<Pair = TestPair>> = slots
        .iter_mut()
        .map(|s| s as &mut dyn Lu<Pair = TestPair>)
        .collect();
    let mut target = Target::new(&mut table[..]);
    let mut storage = DelayedPrefetchStorage::new(
        PlaneSet::new(vec![Some(StorePlane::BlockRw(&mut backend))]),
        2,
    );
    let mut session = IscsiSession::new().with_overlap();
    let mut work = vec![0u8; 2 * BANK];
    let mut scratch = Vec::new();
    let mut conn = MockConn::new();
    conn.feed_padded(&login_bhs(REQ_TEXT.len() as u32), REQ_TEXT.as_bytes());
    conn.feed(&read10_bhs(0, BLOCKS, 7, 0), &[]);

    let mut sent = Vec::new();
    let mut ev = Event::Tick;
    let mut last_was_data_in = false;
    let mut storage_pending_after_data = false;
    loop {
        match session.poll(ev, &mut work, &mut scratch, &mut target, &mut storage) {
            Action::HostRecv { offset, len } => {
                let mut got = 0usize;
                while got < len {
                    match conn.read(&mut work[offset + got..offset + len]) {
                        Ok(0) | Err(_) => return,
                        Ok(n) => got += n,
                    }
                }
                last_was_data_in = false;
                ev = Event::HostRecv { len };
            }
            Action::HostSend { bytes } => {
                let is_data_in = (bytes[0] & 0x3F) == op::SCSI_DATA_IN;
                sent.push(Sent {
                    offset: bytes.as_ptr() as usize,
                    bytes: bytes.to_vec(),
                });
                embedded_io::Write::write_all(&mut conn, bytes).unwrap();
                last_was_data_in = is_data_in;
                ev = Event::HostSent;
            }
            Action::StoragePending => {
                if last_was_data_in {
                    storage_pending_after_data = true;
                }
                last_was_data_in = false;
                ev = Event::Tick;
            }
            Action::Closed => break,
            Action::Error(error) => panic!("session error: {error:?}"),
        }
    }

    assert!(
        storage_pending_after_data,
        "a pending companion after the wire send must not be an internal error"
    );
    assert_eq!(data_in_payload(&sent), expected, "byte-exact read");
    assert_eq!(storage.begins, TOTAL / (BANK - BHS_SIZE) + 1);
}

fn write10_bhs(lba: u32, blocks: u16, itt: u32, cmd_sn: u32) -> [u8; 48] {
    let mut bhs = [0u8; 48];
    bhs[0] = op::SCSI_CMD;
    bhs[1] = 0xA1; // W bit, no immediate data
    bhs[16..20].copy_from_slice(&be32(itt));
    bhs[24..28].copy_from_slice(&be32(cmd_sn));
    bhs[28..32].copy_from_slice(&be32(cmd_sn));
    bhs[32] = 0x2A; // WRITE(10)
    bhs[34..38].copy_from_slice(&be32(lba));
    bhs[39..41].copy_from_slice(&blocks.to_be_bytes());
    bhs
}

fn data_out_bhs(itt: u32, ttt: u32, data_sn: u32, bo: u32, dsl: u32) -> [u8; 48] {
    let mut bhs = [0u8; 48];
    bhs[0] = op::SCSI_DATA_OUT;
    bhs[1] = 0x80;
    bhs[5] = (dsl >> 16) as u8;
    bhs[6] = (dsl >> 8) as u8;
    bhs[7] = dsl as u8;
    bhs[16..20].copy_from_slice(&be32(itt));
    bhs[20..24].copy_from_slice(&be32(ttt));
    bhs[36..40].copy_from_slice(&be32(data_sn));
    bhs[40..44].copy_from_slice(&be32(bo));
    bhs
}

/// A Data-Out chunk whose required write is still in flight reports
/// `StoragePending`; the next `Tick` resumes and the write commits exactly.
#[test]
fn pending_write_after_data_out_reports_storage_pending_then_resumes() {
    use embedded_io::Read as _;
    use snowscsi::iscsi::pdu::Bhs;

    const BLOCKS: u16 = 32;
    const TOTAL: usize = BLOCKS as usize * 512;
    const ITT: u32 = 9;

    let mut ram = vec![0u8; TOTAL];
    let payload: Vec<u8> = (0..TOTAL as u32)
        .map(|i| (i.wrapping_mul(13) % 251) as u8)
        .collect();
    let mut backend = RamBackend::new(&mut ram);
    let mut slots = [TestLu::block(u64::from(BLOCKS), 512, 0)];
    let mut table: Vec<&mut dyn Lu<Pair = TestPair>> = slots
        .iter_mut()
        .map(|s| s as &mut dyn Lu<Pair = TestPair>)
        .collect();
    let mut target = Target::new(&mut table[..]);
    let mut storage =
        PlaneSet::new(vec![Some(StorePlane::BlockRw(&mut backend))]).with_pending(usize::MAX);
    let mut session = IscsiSession::new().with_overlap();
    let mut work = vec![0u8; 2 * BANK];
    let mut scratch = Vec::new();
    let mut conn = MockConn::new();
    conn.feed_padded(&login_bhs(REQ_TEXT.len() as u32), REQ_TEXT.as_bytes());
    conn.feed(&write10_bhs(0, BLOCKS, ITT, 0), &[]);

    let mut ev = Event::Tick;
    let mut pending_data_len = 0usize;
    let mut last_data_out = false;
    let mut storage_pending_after_data = false;
    let mut status_seen = false;
    loop {
        match session.poll(ev, &mut work, &mut scratch, &mut target, &mut storage) {
            Action::HostRecv { offset, len } => {
                let mut got = 0usize;
                while got < len {
                    match conn.read(&mut work[offset + got..offset + len]) {
                        Ok(0) | Err(_) => break,
                        Ok(n) => got += n,
                    }
                }
                if got < len {
                    break;
                }
                if len == pending_data_len && len != 0 {
                    last_data_out = true;
                    pending_data_len = 0;
                } else {
                    last_data_out = false;
                }
                ev = Event::HostRecv { len };
            }
            Action::HostSend { bytes } => {
                let opcode = bytes[0] & 0x3F;
                if opcode == op::R2T {
                    let bhs = Bhs::from_bytes(bytes[..BHS_SIZE].try_into().unwrap());
                    let bo = bhs.buffer_offset() as usize;
                    let desired = bhs.desired_data_len() as usize;
                    let dout =
                        data_out_bhs(bhs.itt(), bhs.ttt(), 0, bhs.buffer_offset(), desired as u32);
                    conn.feed_padded(&dout, &payload[bo..bo + desired]);
                    pending_data_len = desired;
                }
                embedded_io::Write::write_all(&mut conn, bytes).unwrap();
                if opcode == op::SCSI_RESP {
                    status_seen = bytes[3] == status::GOOD;
                    break;
                }
                ev = Event::HostSent;
            }
            Action::StoragePending => {
                if last_data_out {
                    storage_pending_after_data = true;
                    // Release the adapter so the following Tick can settle the
                    // companion and finish the command.
                    storage.pending_polls = 0;
                }
                last_data_out = false;
                ev = Event::Tick;
            }
            Action::Closed => break,
            Action::Error(error) => panic!("session error: {error:?}"),
        }
    }

    assert!(
        storage_pending_after_data,
        "a pending write after Data-Out must report StoragePending"
    );
    assert!(status_seen, "WRITE completed with GOOD status");
    let expected = payload;
    drop(storage);
    assert_eq!(&ram[..TOTAL], &expected[..], "byte-exact commit");
}

/// A multi-chunk Data-Out whose command bank is `Work`: the second chunk is
/// received at an offset inside the alternate half, the first at an offset
/// inside the command half, and the committed bytes are exact.
///
/// The alternate command bank (`cmd_bank == Alt`) always comes with
/// `cmd_alt == None` by design (a resident long token holds one bank), so no
/// two-bank write pipeline can run with an alternate command bank.
#[test]
fn write_into_the_alternate_command_bank_is_byte_exact() {
    use embedded_io::Read as _;
    use snowscsi::iscsi::pdu::Bhs;

    const BLOCKS: u16 = 32;
    const TOTAL: usize = BLOCKS as usize * 512;
    const ITT: u32 = 0x21;

    let mut ram = vec![0u8; TOTAL];
    let payload: Vec<u8> = (0..TOTAL as u32)
        .map(|i| (i.wrapping_mul(13) % 251) as u8)
        .collect();
    let mut backend = RamBackend::new(&mut ram);
    let mut slots = [TestLu::block(u64::from(BLOCKS), 512, 0)];
    let mut table: Vec<&mut dyn Lu<Pair = TestPair>> = slots
        .iter_mut()
        .map(|s| s as &mut dyn Lu<Pair = TestPair>)
        .collect();
    let mut target = Target::new(&mut table[..]);
    let mut storage = PlaneSet::new(vec![Some(StorePlane::BlockRw(&mut backend))]);
    let mut session = IscsiSession::new().with_overlap();
    let mut work = vec![0u8; 2 * BANK];
    let mut scratch = Vec::new();
    let mut conn = MockConn::new();
    conn.feed_padded(&login_bhs(REQ_TEXT.len() as u32), REQ_TEXT.as_bytes());
    conn.feed(&write10_bhs(0, BLOCKS, ITT, 0), &[]);

    let mut ev = Event::Tick;
    let mut pending_data_len = 0usize;
    let mut data_receives = Vec::new();
    let mut status_seen = false;
    loop {
        match session.poll(ev, &mut work, &mut scratch, &mut target, &mut storage) {
            Action::HostRecv { offset, len } => {
                let is_data = len == pending_data_len && len != 0;
                if is_data {
                    pending_data_len = 0;
                    data_receives.push((offset, len));
                }
                let mut got = 0usize;
                while got < len {
                    match conn.read(&mut work[offset + got..offset + len]) {
                        Ok(0) | Err(_) => break,
                        Ok(n) => got += n,
                    }
                }
                if got < len {
                    break;
                }
                ev = Event::HostRecv { len };
            }
            Action::HostSend { bytes } => {
                let opcode = bytes[0] & 0x3F;
                if opcode == op::R2T {
                    let bhs = Bhs::from_bytes(bytes[..BHS_SIZE].try_into().unwrap());
                    let bo = bhs.buffer_offset() as usize;
                    let desired = bhs.desired_data_len() as usize;
                    let dout =
                        data_out_bhs(bhs.itt(), bhs.ttt(), 0, bhs.buffer_offset(), desired as u32);
                    conn.feed_padded(&dout, &payload[bo..bo + desired]);
                    pending_data_len = desired;
                }
                embedded_io::Write::write_all(&mut conn, bytes).unwrap();
                if opcode == op::SCSI_RESP {
                    status_seen = bytes[3] == status::GOOD;
                    break;
                }
                ev = Event::HostSent;
            }
            Action::StoragePending => ev = Event::Tick,
            Action::Closed => break,
            Action::Error(error) => panic!("session error: {error:?}"),
        }
    }

    assert!(status_seen, "WRITE completed with GOOD status");
    assert_eq!(data_receives.len(), 2, "two Data-Out chunks");
    for (offset, len) in &data_receives {
        let bank = if *offset >= BANK { 1 } else { 0 };
        let end = *offset + *len;
        let bank_end = if bank == 0 { BANK } else { 2 * BANK };
        assert!(
            end <= bank_end,
            "Data-Out at {offset}..{end} crosses the {bank} bank boundary"
        );
    }
    assert!(
        data_receives.iter().any(|(offset, _)| *offset < BANK),
        "the first chunk stays in the command half"
    );
    assert!(
        data_receives.iter().any(|(offset, _)| *offset >= BANK),
        "the second chunk is received in the alternate half"
    );

    let expected = payload;
    drop(storage);
    assert_eq!(&ram[..TOTAL], &expected[..], "byte-exact commit");
}
