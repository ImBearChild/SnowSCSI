//! Step-level iSCSI target integration tests.
//!
//! Deterministic, single thread: `MockConn` scripted byte stream driven through
//! the `poll`/`Action`/`Event` core by a test-local single-transaction loop.
//! Every test drives a real core `Target` over `TestLu` slots and a
//! `PlaneSet` storage adapter.

#[cfg(test)]
mod tests {
    use crate::iscsi_harness::{PlaneSet, TestLu, TestPair};
    use crate::mock_conn::MockConn;
    use embedded_io::Read as _;
    use snowscsi::common::seekable_storage::RamBackend;
    use snowscsi::common::store::{StoreOp, StorePlane};
    use snowscsi::core::{Delivery, Lu, RuntimeSet, Target};
    use snowscsi::iscsi::conn::write_all;
    use snowscsi::iscsi::pdu::{flag, op, reject, stage, status, tmf, tmf_response, BHS_SIZE};
    use snowscsi::iscsi::target::{Action, Event, IscsiSession, LoginStage, TargetError};
    use snowscsi::MIN_DATA_LEN;

    /// iSCSI target scratch buffer: BHS header + data area.
    const WORK_LEN: usize = MIN_DATA_LEN + BHS_SIZE;

    /// Outcome of one transaction, mirroring the legacy step semantics.
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    enum Outcome {
        /// A PDU was consumed but nothing was sent (out-of-window CmdSN).
        Idle,
        /// A transaction completed and response(s) were sent.
        Processed,
        /// The connection should be closed (Logout / peer closed / reject).
        Closed,
        /// Internal error (caller bug), e.g. work buffer too small.
        Error(TargetError),
    }

    /// One transaction over the `poll`/`Action`/`Event` core.
    fn run_once<S: RuntimeSet>(
        session: &mut IscsiSession,
        conn: &mut MockConn,
        work: &mut [u8],
        scratch: &mut [u8],
        target: &mut Target<S>,
        storage: &mut dyn snowscsi::core::storage::Storage,
    ) -> Outcome {
        let mut ev = Event::Tick;
        let mut wrote = false;
        loop {
            match session.poll(ev, work, scratch, target, storage) {
                Action::HostRecv { offset, len } => {
                    let mut got = 0usize;
                    while got < len {
                        match conn.read(&mut work[offset + got..offset + len]) {
                            Ok(0) if got == 0 => {
                                return if wrote {
                                    Outcome::Processed
                                } else {
                                    Outcome::Idle
                                };
                            }
                            Ok(0) => return Outcome::Closed,
                            Ok(n) => got += n,
                            Err(_) => return Outcome::Closed,
                        }
                    }
                    ev = Event::HostRecv { len };
                }
                Action::HostSend { bytes, .. } => {
                    if write_all(conn, bytes).is_err() {
                        return Outcome::Closed;
                    }
                    wrote = true;
                    ev = Event::HostSent;
                }
                Action::Closed => return Outcome::Closed,
                Action::Error(e) => return Outcome::Error(e),
            }
        }
    }

    /// Login parameters as sent by a Linux open-iscsi initiator.
    const REQ_TEXT: &str = "InitiatorName=iqn.1994-05.com.redhat:702f27e1da14\0InitiatorAlias=develop\0TargetName=iqn.1970-01.local.snowscsi:target\0SessionType=Normal\0HeaderDigest=None\0DataDigest=None\0DefaultTime2Wait=2\0DefaultTime2Retain=0\0IFMarker=No\0OFMarker=No\0ErrorRecoveryLevel=0\0InitialR2T=No\0ImmediateData=Yes\0MaxBurstLength=16776192\0FirstBurstLength=262144\0MaxOutstandingR2T=1\0MaxConnections=1\0DataPDUInOrder=Yes\0DataSequenceInOrder=Yes\0MaxRecvDataSegmentLength=262144\0";

    fn be32(v: u32) -> [u8; 4] {
        v.to_be_bytes()
    }

    /// Login Request BHS: I=1, T=1, CSG=1, NSG=3 (matches Linux initiator).
    fn login_bhs(dsl: u32) -> [u8; 48] {
        let mut bhs = [0u8; 48];
        bhs[0] = op::LOGIN_REQ | 0x40;
        bhs[1] = flag::T_BIT | ((stage::OP_PARAM & 0x03) << flag::CSG_SHIFT) | stage::FULL_FEATURE;
        bhs[5] = (dsl >> 16) as u8;
        bhs[6] = (dsl >> 8) as u8;
        bhs[7] = dsl as u8;
        bhs
    }

    fn read10_bhs(lba: u32, blocks: u16, itt: u32, cmd_sn: u32) -> [u8; 48] {
        let mut bhs = [0u8; 48];
        bhs[0] = op::SCSI_CMD;
        bhs[1] = 0x40;
        bhs[16..20].copy_from_slice(&be32(itt));
        bhs[24..28].copy_from_slice(&be32(cmd_sn));
        bhs[28..32].copy_from_slice(&be32(cmd_sn));
        bhs[32] = 0x28;
        bhs[34..38].copy_from_slice(&be32(lba));
        bhs[39..41].copy_from_slice(&blocks.to_be_bytes());
        bhs
    }

    fn write10_bhs(lba: u32, blocks: u16, itt: u32, cmd_sn: u32, dsl: u32) -> [u8; 48] {
        let mut bhs = [0u8; 48];
        bhs[0] = op::SCSI_CMD;
        bhs[1] = 0xA1;
        bhs[5] = (dsl >> 16) as u8;
        bhs[6] = (dsl >> 8) as u8;
        bhs[7] = dsl as u8;
        bhs[16..20].copy_from_slice(&be32(itt));
        bhs[24..28].copy_from_slice(&be32(cmd_sn));
        bhs[28..32].copy_from_slice(&be32(cmd_sn));
        bhs[32] = 0x2A;
        bhs[34..38].copy_from_slice(&be32(lba));
        bhs[39..41].copy_from_slice(&blocks.to_be_bytes());
        bhs
    }

    fn dataout_bhs(itt: u32, ttt: u32, data_sn: u32, bo: u32, dsl: u32) -> [u8; 48] {
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

    fn inquiry_bhs(lun: u8, alloc: u8, itt: u32, cmd_sn: u32) -> [u8; 48] {
        let mut bhs = [0u8; 48];
        bhs[0] = op::SCSI_CMD;
        bhs[1] = 0x40;
        bhs[9] = lun;
        bhs[16..20].copy_from_slice(&be32(itt));
        bhs[24..28].copy_from_slice(&be32(cmd_sn));
        bhs[28..32].copy_from_slice(&be32(cmd_sn));
        bhs[32] = 0x12;
        bhs[36] = alloc;
        bhs
    }

    fn report_luns_bhs(lun: u8, itt: u32, cmd_sn: u32) -> [u8; 48] {
        let mut bhs = [0u8; 48];
        bhs[0] = op::SCSI_CMD;
        bhs[16..20].copy_from_slice(&be32(itt));
        bhs[24..28].copy_from_slice(&be32(cmd_sn));
        bhs[28..32].copy_from_slice(&be32(cmd_sn));
        bhs[9] = lun;
        bhs[32] = 0xA0;
        bhs[38] = 0x08;
        bhs
    }

    fn tur_bhs(itt: u32, cmd_sn: u32) -> [u8; 48] {
        let mut bhs = [0u8; 48];
        bhs[0] = op::SCSI_CMD;
        bhs[16..20].copy_from_slice(&be32(itt));
        bhs[24..28].copy_from_slice(&be32(cmd_sn));
        bhs[28..32].copy_from_slice(&be32(cmd_sn));
        bhs[32] = 0x00; // TEST UNIT READY
        bhs
    }

    fn request_sense_bhs(alloc: u8, itt: u32, cmd_sn: u32) -> [u8; 48] {
        let mut bhs = [0u8; 48];
        bhs[0] = op::SCSI_CMD;
        bhs[16..20].copy_from_slice(&be32(itt));
        bhs[24..28].copy_from_slice(&be32(cmd_sn));
        bhs[28..32].copy_from_slice(&be32(cmd_sn));
        bhs[32] = 0x03; // REQUEST SENSE
        bhs[36] = alloc;
        bhs
    }

    fn report_luns_bhs_select(lun: u8, itt: u32, cmd_sn: u32, select: u8) -> [u8; 48] {
        let mut bhs = report_luns_bhs(lun, itt, cmd_sn);
        bhs[34] = select;
        bhs
    }

    fn resp_value<'a>(data: &'a [u8], key: &str) -> Option<&'a [u8]> {
        let needle = key.as_bytes();
        let mut p = 0usize;
        while p < data.len() {
            let end = data[p..]
                .iter()
                .position(|&b| b == 0)
                .map_or(data.len(), |i| p + i);
            let entry = &data[p..end];
            if let Some(eq) = entry.iter().position(|&b| b == b'=') {
                if &entry[..eq] == needle {
                    return Some(&entry[eq + 1..]);
                }
            }
            if end >= data.len() {
                break;
            }
            p = end + 1;
        }
        None
    }

    /// Scripted connection that drops the first terminal CHECK CONDITION
    /// status write, modelling a transport failure after the command settled.
    struct StatusDropConn {
        rx: std::collections::VecDeque<u8>,
        drop_status: bool,
    }

    impl StatusDropConn {
        fn new() -> Self {
            Self {
                rx: std::collections::VecDeque::new(),
                drop_status: true,
            }
        }

        fn feed(&mut self, bhs: &[u8; 48], data: &[u8]) {
            self.rx.extend(bhs);
            self.rx.extend(data);
        }

        fn feed_padded(&mut self, bhs: &[u8; 48], data: &[u8]) {
            let dsl = data.len();
            let total = 48 + dsl;
            let pad = (4 - (total & 3)) & 3;
            self.rx.extend(bhs);
            self.rx.extend(data);
            self.rx.resize(self.rx.len() + pad, 0);
        }
    }

    impl embedded_io::ErrorType for StatusDropConn {
        type Error = std::io::Error;
    }

    impl embedded_io::Read for StatusDropConn {
        fn read(&mut self, buf: &mut [u8]) -> Result<usize, Self::Error> {
            let n = buf.len().min(self.rx.len());
            for (out, b) in buf.iter_mut().zip(self.rx.iter()).take(n) {
                *out = *b;
            }
            self.rx.drain(..n);
            Ok(n)
        }
    }

    impl embedded_io::Write for StatusDropConn {
        fn write(&mut self, buf: &[u8]) -> Result<usize, Self::Error> {
            if self.drop_status
                && buf.len() >= 4
                && buf[0] & 0x3F == op::SCSI_RESP
                && buf[3] == status::CHECK_CONDITION
            {
                self.drop_status = false;
                return Err(std::io::Error::new(
                    std::io::ErrorKind::BrokenPipe,
                    "status write dropped",
                ));
            }
            Ok(buf.len())
        }

        fn flush(&mut self) -> Result<(), Self::Error> {
            Ok(())
        }
    }

    /// Build a one-LUN block target and log in; returns the connection and the
    /// login response PDU.
    macro_rules! block_fixture {
        ($ram:ident, $backend:ident, $blocks:expr, $work:ident, $scratch:ident,
         $slots:ident, $table:ident, $conn:ident, $session:ident, $target:ident,
         $storage:ident) => {
            let mut $backend = RamBackend::new(&mut $ram);
            let mut $slots = [TestLu::block($blocks, 512, 0)];
            let mut $table: Vec<&mut dyn Lu<Pair = TestPair>> = $slots
                .iter_mut()
                .map(|s| s as &mut dyn Lu<Pair = TestPair>)
                .collect();
            let mut $target = Target::new(&mut $table[..]);
            let mut $storage = PlaneSet::new(vec![Some(StorePlane::BlockRw(&mut $backend))]);
            let mut $conn = MockConn::new();
            let mut $session = IscsiSession::default();
            let mut $work = vec![0u8; WORK_LEN];
            let mut $scratch = vec![0u8; MIN_DATA_LEN];
        };
    }

    /// Feed the one-stage login and consume its response.
    macro_rules! login {
        ($conn:ident, $session:ident, $work:ident, $scratch:ident, $target:ident, $storage:ident) => {{
            let text = REQ_TEXT.as_bytes();
            let bhs = login_bhs(text.len() as u32);
            $conn.feed_padded(&bhs, text);
            assert_eq!(
                run_once(
                    &mut $session,
                    &mut $conn,
                    &mut $work,
                    &mut $scratch,
                    &mut $target,
                    &mut $storage
                ),
                Outcome::Processed
            );
            $conn.take_pdu().expect("login response")
        }};
    }

    // ── Login Response BHS: RFC 3720 §10.12.2 byte layout ──────────

    #[test]
    fn login_resp_bhs_rfc() {
        let mut ram = vec![0u8; 16 * 1024 * 1024];
        block_fixture!(
            ram, backend, 32768, work, scratch, slots, table, conn, session, target, storage
        );
        let (bhs, _data) = login!(conn, session, work, scratch, target, storage);

        assert_eq!(bhs[0] & 0x3F, op::LOGIN_RESP);
        assert_eq!(bhs[1] & 0x80, 0x80); // T=1
        assert_eq!(bhs[1] & 0x40, 0x00); // C=0
        assert_eq!((bhs[1] >> 2) & 0x03, stage::OP_PARAM); // CSG
        assert_eq!(bhs[1] & 0x03, stage::FULL_FEATURE); // NSG
        assert_eq!(bhs[2], 0x00); // Version-max
        assert_eq!(bhs[3], 0x00); // Version-active
        assert_eq!(bhs[4], 0x00); // TotalAHSLength
        let lreq = login_bhs(REQ_TEXT.len() as u32);
        assert_eq!(&bhs[8..14], &lreq[8..14]); // ISID echoed
        let tsih = (u16::from(bhs[14]) << 8) | u16::from(bhs[15]);
        assert_ne!(tsih, 0);
        assert_eq!(&bhs[16..20], &lreq[16..20]); // ITT echoed
        assert_eq!(&bhs[24..28], &be32(0)); // StatSN = 0
        assert_eq!(bhs[36], 0x00); // Status-Class
        assert_eq!(bhs[37], 0x00); // Status-Detail
    }

    #[test]
    fn login_resp_no_skipped_keys() {
        let mut ram = vec![0u8; 16 * 1024 * 1024];
        block_fixture!(
            ram, backend, 32768, work, scratch, slots, table, conn, session, target, storage
        );
        let (_bhs, data) = login!(conn, session, work, scratch, target, storage);
        for k in [
            "TargetName",
            "InitiatorName",
            "InitiatorAlias",
            "SessionType",
            "AuthMethod",
            "TargetAddress",
        ] {
            assert!(resp_value(&data, k).is_none(), "{k} must not appear");
        }
    }

    #[test]
    fn login_resp_has_required_keys() {
        let mut ram = vec![0u8; 16 * 1024 * 1024];
        block_fixture!(
            ram, backend, 32768, work, scratch, slots, table, conn, session, target, storage
        );
        let (_bhs, data) = login!(conn, session, work, scratch, target, storage);
        assert_eq!(
            resp_value(&data, "TargetAlias"),
            Some(b"SnowSCSI".as_slice())
        );
        assert_eq!(
            resp_value(&data, "TargetPortalGroupTag"),
            Some(b"1".as_slice())
        );
    }

    #[test]
    fn login_resp_echoes_all_keys() {
        let mut ram = vec![0u8; 16 * 1024 * 1024];
        block_fixture!(
            ram, backend, 32768, work, scratch, slots, table, conn, session, target, storage
        );
        let (_bhs, data) = login!(conn, session, work, scratch, target, storage);
        assert_eq!(resp_value(&data, "InitialR2T"), Some(b"Yes".as_slice()));
        assert_eq!(
            resp_value(&data, "MaxBurstLength"),
            Some(b"262144".as_slice())
        );
        assert_eq!(
            resp_value(&data, "FirstBurstLength"),
            Some(b"65536".as_slice())
        );
        assert_eq!(
            resp_value(&data, "MaxRecvDataSegmentLength"),
            Some(b"8192".as_slice())
        );
        assert_eq!(resp_value(&data, "ImmediateData"), Some(b"Yes".as_slice()));
        assert_eq!(
            resp_value(&data, "MaxOutstandingR2T"),
            Some(b"1".as_slice())
        );
    }

    #[test]
    fn multi_stage_login() {
        let mut ram = vec![0u8; 16 * 1024 * 1024];
        block_fixture!(
            ram, backend, 32768, work, scratch, slots, table, conn, session, target, storage
        );

        // Stage 1: CSG=0 (Security), T=1, NSG=3 → target forces NSG=1.
        let mut bhs = [0u8; 48];
        bhs[0] = op::LOGIN_REQ | 0x40;
        bhs[1] = flag::T_BIT | ((stage::SECURITY & 0x03) << flag::CSG_SHIFT) | stage::FULL_FEATURE;
        conn.feed(&bhs, &[]);
        assert_eq!(
            run_once(
                &mut session,
                &mut conn,
                &mut work,
                &mut scratch,
                &mut target,
                &mut storage
            ),
            Outcome::Processed
        );
        let (resp1, _) = conn.take_pdu().unwrap();
        assert_eq!(resp1[1] & 0x80, 0x80);
        assert_eq!((resp1[1] >> 2) & 0x03, stage::SECURITY);
        assert_eq!(resp1[1] & 0x03, stage::OP_PARAM);
        assert_eq!(session.stage(), LoginStage::OpParam);

        // Stage 2: CSG=1 (OpParam), T=1, NSG=3 → Full Feature.
        let mut bhs = [0u8; 48];
        bhs[0] = op::LOGIN_REQ | 0x40;
        bhs[1] = flag::T_BIT | ((stage::OP_PARAM & 0x03) << flag::CSG_SHIFT) | stage::FULL_FEATURE;
        bhs[15] = 0x01;
        conn.feed(&bhs, &[]);
        assert_eq!(
            run_once(
                &mut session,
                &mut conn,
                &mut work,
                &mut scratch,
                &mut target,
                &mut storage
            ),
            Outcome::Processed
        );
        let (resp2, _) = conn.take_pdu().unwrap();
        assert_eq!((resp2[1] >> 2) & 0x03, stage::OP_PARAM);
        assert_eq!(resp2[1] & 0x03, stage::FULL_FEATURE);
        assert_eq!(session.stage(), LoginStage::FullFeature);

        // A SCSI command now works (StatSN = 2 after two login responses).
        let cmd = read10_bhs(0, 1, 0x9999, 0);
        conn.feed(&cmd, &[]);
        assert_eq!(
            run_once(
                &mut session,
                &mut conn,
                &mut work,
                &mut scratch,
                &mut target,
                &mut storage
            ),
            Outcome::Processed
        );
        let (resp, _) = conn.take_pdu().unwrap();
        assert_eq!(resp[0] & 0x3F, op::SCSI_DATA_IN);
        assert_eq!(&resp[24..28], &be32(2));
    }

    // ── READ(10): Data-In BufferOffset / DataSN continuity ─────────

    #[test]
    fn data_in_buffer_offset() {
        let mut ram = vec![0u8; 16 * 1024 * 1024];
        block_fixture!(
            ram, backend, 32768, work, scratch, slots, table, conn, session, target, storage
        );
        // Negotiate a small receive segment so the 9216-byte read spans PDUs.
        let text = b"InitiatorName=iqn.test\0MaxRecvDataSegmentLength=1024\0";
        conn.feed_padded(&login_bhs(text.len() as u32), text);
        assert_eq!(
            run_once(
                &mut session,
                &mut conn,
                &mut work,
                &mut scratch,
                &mut target,
                &mut storage
            ),
            Outcome::Processed
        );
        let _ = conn.take_pdu();

        let pattern: Vec<u8> = (0..4096u32).map(|i| (i & 0xFF) as u8).collect();
        storage
            .exec_raw(StoreOp::Write {
                off: 0,
                buf: &pattern,
            })
            .unwrap();

        // READ 8 blocks (4096 bytes) — four 1024-byte Data-In PDUs.
        let cmd = read10_bhs(0, 8, 0x12345678, 0);
        conn.feed(&cmd, &[]);
        assert_eq!(
            run_once(
                &mut session,
                &mut conn,
                &mut work,
                &mut scratch,
                &mut target,
                &mut storage
            ),
            Outcome::Processed
        );
        let mut count = 0;
        let mut expected_bo = 0u32;
        let mut expected_dsn = 0u32;
        while let Some((bhs, _data)) = conn.take_pdu() {
            if bhs[0] & 0x3F != op::SCSI_DATA_IN {
                continue;
            }
            let bo = u32::from_be_bytes([bhs[40], bhs[41], bhs[42], bhs[43]]);
            let dsn = u32::from_be_bytes([bhs[36], bhs[37], bhs[38], bhs[39]]);
            let dsl = (u32::from(bhs[5]) << 16) | (u32::from(bhs[6]) << 8) | u32::from(bhs[7]);
            assert_eq!(bo, expected_bo, "BufferOffset mismatch");
            assert_eq!(dsn, expected_dsn, "DataSN mismatch");
            if bhs[1] & flag::F_BIT != 0 {
                assert_ne!(bhs[1] & flag::S_BIT, 0, "final Data-In must have S bit");
                assert_eq!(&bhs[24..28], &be32(1)); // StatSN advanced
            }
            expected_bo += dsl;
            expected_dsn += 1;
            count += 1;
        }
        assert!(
            count >= 2,
            "expected >= 2 Data-In PDUs for the 4096-byte read"
        );
        assert_eq!(expected_bo, 4096);
    }

    // ── WRITE(10): immediate data → R2T → Data-Out → status ───────

    #[test]
    fn write_flow_r2t_and_response() {
        let mut ram = vec![0u8; 16 * 1024 * 1024];
        block_fixture!(
            ram, backend, 32768, work, scratch, slots, table, conn, session, target, storage
        );
        login!(conn, session, work, scratch, target, storage);

        let itt = 0x7777_0001;
        let imm: Vec<u8> = (0..512u32).map(|i| (i & 0xFF) as u8).collect();
        let cmd = write10_bhs(10, 3, itt, 0, 512);
        conn.feed_padded(&cmd, &imm);

        let out: Vec<u8> = (0x100..0x500u32).map(|i| (i & 0xFF) as u8).collect();
        let dout = dataout_bhs(itt, 1, 0, 512, 1024);
        conn.feed_padded(&dout, &out);
        assert_eq!(
            run_once(
                &mut session,
                &mut conn,
                &mut work,
                &mut scratch,
                &mut target,
                &mut storage
            ),
            Outcome::Processed
        );

        let (r2t, _) = conn.take_pdu().unwrap();
        assert_eq!(r2t[0] & 0x3F, op::R2T);
        assert_eq!(&r2t[16..20], &be32(itt));
        assert_eq!(&r2t[20..24], &be32(1)); // TTT
        assert_eq!(&r2t[40..44], &be32(512)); // BufferOffset
        assert_eq!(&r2t[44..48], &be32(1024)); // DesiredLen
        assert_eq!(&r2t[36..40], &be32(0)); // R2TSN

        let (resp, _) = conn.take_pdu().unwrap();
        assert_eq!(resp[0] & 0x3F, op::SCSI_RESP);
        assert_eq!(resp[3], status::GOOD);
        assert_eq!(&resp[16..20], &be32(itt));
        assert_eq!(&resp[24..28], &be32(1)); // StatSN
        assert_eq!(&resp[28..32], &be32(1)); // ExpCmdSN
        assert_eq!(&resp[32..36], &be32(1)); // MaxCmdSN

        let mut buf = [0u8; 1536];
        storage
            .exec_raw(StoreOp::Read {
                off: 10 * 512,
                buf: &mut buf,
            })
            .unwrap();
        let mut expect = imm.clone();
        expect.extend_from_slice(&out);
        assert_eq!(&buf, expect.as_slice());
    }

    #[test]
    fn write_larger_than_the_bank_solicits_one_r2t_per_chunk() {
        // The SCSI data area is 8192 bytes; 32 blocks = 16384 bytes streams in
        // two Data-Out chunks. Every chunk gets its own R2T.
        let mut ram = vec![0u8; 16 * 1024];
        block_fixture!(
            ram, backend, 32768, work, scratch, slots, table, conn, session, target, storage
        );
        login!(conn, session, work, scratch, target, storage);

        let itt = 0xB200_0001;
        let cmd = write10_bhs(0, 32, itt, 0, 0);
        conn.feed_padded(&cmd, &[]);
        let mut bo = 0u32;
        let mut pattern = Vec::new();
        for burst in 0..2u32 {
            for dsn in 0..16u32 {
                let fill = (burst * 16 + dsn) as u8;
                let chunk = vec![fill; 512];
                pattern.extend_from_slice(&chunk);
                let dout = dataout_bhs(itt, 1, dsn, bo, 512);
                conn.feed_padded(&dout, &chunk);
                bo += 512;
            }
        }
        assert_eq!(
            run_once(
                &mut session,
                &mut conn,
                &mut work,
                &mut scratch,
                &mut target,
                &mut storage
            ),
            Outcome::Processed
        );
        let r2t1 = conn.take_pdu().unwrap().0;
        assert_eq!(r2t1[0] & 0x3F, op::R2T);
        assert_eq!(&r2t1[36..40], &be32(0), "R2TSN");
        assert_eq!(&r2t1[40..44], &be32(0), "BufferOffset");
        assert_eq!(&r2t1[44..48], &be32(8192), "DesiredLen is one bank");
        let r2t2 = conn.take_pdu().unwrap().0;
        assert_eq!(r2t2[0] & 0x3F, op::R2T);
        assert_eq!(&r2t2[36..40], &be32(1), "R2TSN continues");
        assert_eq!(&r2t2[40..44], &be32(8192), "BufferOffset continues");
        assert_eq!(&r2t2[44..48], &be32(8192));
        let (resp, _) = conn.take_pdu().unwrap();
        assert_eq!(resp[0] & 0x3F, op::SCSI_RESP);
        assert_eq!(resp[3], status::GOOD);

        // Read the same range back through the session: byte-exact.
        conn.feed(&read10_bhs(0, 32, 0xB200_0002, 1), &[]);
        assert_eq!(
            run_once(
                &mut session,
                &mut conn,
                &mut work,
                &mut scratch,
                &mut target,
                &mut storage
            ),
            Outcome::Processed
        );
        let mut readback = Vec::new();
        while let Some((bhs, data)) = conn.take_pdu() {
            if bhs[0] & 0x3F == op::SCSI_DATA_IN {
                readback.extend_from_slice(&data);
            }
        }
        assert_eq!(readback, pattern, "the streamed write is byte-exact");
    }

    #[test]
    fn write_multi_r2t_bounded_by_max_burst() {
        // 600 blocks = 307200 bytes > MaxBurstLength (262144); the transfer is
        // split into R2T bursts even when it fits the caller's bank.
        let mut ram = vec![0u8; 16 * 1024 * 1024];
        let mut backend = RamBackend::new(&mut ram);
        let mut slots = [TestLu::block(32768, 512, 0)];
        let mut table: Vec<&mut dyn Lu<Pair = TestPair>> = slots
            .iter_mut()
            .map(|s| s as &mut dyn Lu<Pair = TestPair>)
            .collect();
        let mut target = Target::new(&mut table[..]);
        let mut storage = PlaneSet::new(vec![Some(StorePlane::BlockRw(&mut backend))]);
        let mut conn = MockConn::new();
        let mut session = IscsiSession::default();
        let mut work = vec![0u8; 384 * 1024];
        let mut scratch = vec![0u8; MIN_DATA_LEN];
        login!(conn, session, work, scratch, target, storage);

        let itt = 0xAAAA_0001;
        let imm = vec![0x5Au8; 8192];
        let cmd = write10_bhs(0, 600, itt, 0, 8192);
        conn.feed_padded(&cmd, &imm);

        let chunk = vec![0x6Bu8; 8192];
        let mut bo = 8192u32;
        for dsn in 0..32 {
            let dout = dataout_bhs(itt, 1, dsn, bo, 8192);
            conn.feed_padded(&dout, &chunk);
            bo += 8192;
        }
        let chunk2 = vec![0x7Cu8; 8192];
        for dsn in 0..(36864 / 8192) {
            let dout = dataout_bhs(itt, 1, dsn, bo, 8192);
            conn.feed_padded(&dout, &chunk2);
            bo += 8192;
        }
        let dout = dataout_bhs(itt, 1, 4, bo, 4096);
        conn.feed_padded(&dout, &vec![0x7Cu8; 4096]);

        assert_eq!(
            run_once(
                &mut session,
                &mut conn,
                &mut work,
                &mut scratch,
                &mut target,
                &mut storage
            ),
            Outcome::Processed
        );

        let r2t1 = conn.take_pdu().unwrap().0;
        assert_eq!(r2t1[0] & 0x3F, op::R2T);
        assert_eq!(&r2t1[40..44], &be32(8192));
        assert_eq!(&r2t1[44..48], &be32(262144));

        let r2t2 = conn.take_pdu().unwrap().0;
        assert_eq!(r2t2[0] & 0x3F, op::R2T);
        assert_eq!(&r2t2[40..44], &be32(8192 + 262144));
        assert_eq!(&r2t2[44..48], &be32(307200 - 8192 - 262144));

        let (resp, _) = conn.take_pdu().unwrap();
        assert_eq!(resp[0] & 0x3F, op::SCSI_RESP);
        assert_eq!(resp[3], status::GOOD);
    }

    // ── NOP-Out keepalive → NOP-In ─────────────────────────────────

    #[test]
    fn nop_in_echoes_ttt() {
        let mut ram = vec![0u8; 16 * 1024 * 1024];
        block_fixture!(
            ram, backend, 32768, work, scratch, slots, table, conn, session, target, storage
        );
        login!(conn, session, work, scratch, target, storage);

        let mut nop = [0u8; 48];
        nop[0] = op::NOP_OUT;
        nop[16..20].copy_from_slice(&be32(0xABCD));
        nop[20..24].copy_from_slice(&be32(0xFFFF_FFFF));
        conn.feed(&nop, &[]);
        assert_eq!(
            run_once(
                &mut session,
                &mut conn,
                &mut work,
                &mut scratch,
                &mut target,
                &mut storage
            ),
            Outcome::Processed
        );
        let (bhs, _) = conn.take_pdu().unwrap();
        assert_eq!(bhs[0] & 0x3F, op::NOP_IN);
        assert_eq!(&bhs[16..20], &be32(0xABCD));
        assert_eq!(&bhs[20..24], &be32(0xFFFF_FFFF));
    }

    // ── Unsupported LUN / malformed LUN / window ───────────────────

    #[test]
    fn unsupported_lun_check_condition() {
        let mut ram = vec![0u8; 16 * 1024 * 1024];
        block_fixture!(
            ram, backend, 32768, work, scratch, slots, table, conn, session, target, storage
        );
        login!(conn, session, work, scratch, target, storage);

        let mut cmd = read10_bhs(0, 1, 0x1111, 0);
        cmd[9] = 5;
        conn.feed(&cmd, &[]);
        assert_eq!(
            run_once(
                &mut session,
                &mut conn,
                &mut work,
                &mut scratch,
                &mut target,
                &mut storage
            ),
            Outcome::Processed
        );
        let (bhs, data) = conn.take_pdu().unwrap();
        assert_eq!(bhs[0] & 0x3F, op::SCSI_RESP);
        assert_eq!(bhs[3], status::CHECK_CONDITION);
        assert_eq!(&bhs[16..20], &be32(0x1111));
        assert_eq!(&data[0..2], &[0x00, 18]);
        assert_eq!(data[2], 0x70);
        assert_eq!(data[4], 0x05);
        assert_eq!(data[14], 0x25);
        assert_eq!(data[15], 0x00);
    }

    #[test]
    fn multi_level_lun_rejected_as_pdu_field() {
        let mut ram = vec![0u8; 16 * 1024 * 1024];
        block_fixture!(
            ram, backend, 32768, work, scratch, slots, table, conn, session, target, storage
        );
        login!(conn, session, work, scratch, target, storage);

        let mut cmd = read10_bhs(0, 1, 0x2222, 0);
        cmd[8] = 0x40;
        cmd[9] = 0;
        conn.feed(&cmd, &[]);
        assert_eq!(
            run_once(
                &mut session,
                &mut conn,
                &mut work,
                &mut scratch,
                &mut target,
                &mut storage
            ),
            Outcome::Closed
        );
        let (bhs, data) = conn.take_pdu().unwrap();
        assert_eq!(bhs[0] & 0x3F, op::REJECT);
        assert_eq!(bhs[2], reject::INVALID_PDU_FIELD);
        assert_eq!(&bhs[16..20], &[0xFF; 4]);
        assert_eq!(data, cmd.to_vec());
    }

    #[test]
    fn cmd_sn_out_of_window_ignored() {
        let mut ram = vec![0u8; 16 * 1024 * 1024];
        block_fixture!(
            ram, backend, 32768, work, scratch, slots, table, conn, session, target, storage
        );
        login!(conn, session, work, scratch, target, storage);

        let cmd = read10_bhs(0, 1, 0x2222, 5);
        conn.feed(&cmd, &[]);
        assert_eq!(
            run_once(
                &mut session,
                &mut conn,
                &mut work,
                &mut scratch,
                &mut target,
                &mut storage
            ),
            Outcome::Idle
        );
        assert!(conn.take_pdu().is_none());

        let cmd = read10_bhs(0, 1, 0x3333, 0);
        conn.feed(&cmd, &[]);
        assert_eq!(
            run_once(
                &mut session,
                &mut conn,
                &mut work,
                &mut scratch,
                &mut target,
                &mut storage
            ),
            Outcome::Processed
        );
        let (bhs, _) = conn.take_pdu().unwrap();
        assert_eq!(bhs[0] & 0x3F, op::SCSI_DATA_IN);
    }

    #[test]
    fn first_command_reuses_login_cmd_sn() {
        let mut ram = vec![0u8; 16 * 1024 * 1024];
        block_fixture!(
            ram, backend, 32768, work, scratch, slots, table, conn, session, target, storage
        );

        let text = REQ_TEXT.as_bytes();
        let mut bhs = login_bhs(text.len() as u32);
        bhs[24..28].copy_from_slice(&be32(0x73dd_e21f));
        conn.feed_padded(&bhs, text);
        assert_eq!(
            run_once(
                &mut session,
                &mut conn,
                &mut work,
                &mut scratch,
                &mut target,
                &mut storage
            ),
            Outcome::Processed
        );
        let (resp, _) = conn.take_pdu().unwrap();
        assert_eq!(&resp[28..32], &be32(0x73dd_e21f));
        assert_eq!(&resp[32..36], &be32(0x73dd_e21f));

        let cmd = read10_bhs(0, 1, 0x9999, 0x73dd_e21f);
        conn.feed(&cmd, &[]);
        assert_eq!(
            run_once(
                &mut session,
                &mut conn,
                &mut work,
                &mut scratch,
                &mut target,
                &mut storage
            ),
            Outcome::Processed
        );
        let (bhs, _) = conn.take_pdu().unwrap();
        assert_eq!(bhs[0] & 0x3F, op::SCSI_DATA_IN);

        let cmd = read10_bhs(0, 1, 0x999A, 0x73dd_e220);
        conn.feed(&cmd, &[]);
        assert_eq!(
            run_once(
                &mut session,
                &mut conn,
                &mut work,
                &mut scratch,
                &mut target,
                &mut storage
            ),
            Outcome::Processed
        );
    }

    // ── Task management ────────────────────────────────────────────

    #[test]
    fn immediate_tmf_abort_task_complete() {
        let mut ram = vec![0u8; 16 * 1024 * 1024];
        block_fixture!(
            ram, backend, 32768, work, scratch, slots, table, conn, session, target, storage
        );
        login!(conn, session, work, scratch, target, storage);

        let mut tmfr = [0u8; 48];
        tmfr[0] = op::SCSI_TASK_REQ | 0x40;
        /* Function in byte 1 (0x80 | function), byte 2 reserved (RFC 3720 §10.5). */
        tmfr[1] = 0x80 | tmf::ABORT_TASK;
        tmfr[16..20].copy_from_slice(&be32(0x5555));
        tmfr[24..28].copy_from_slice(&be32(9));
        conn.feed(&tmfr, &[]);
        assert_eq!(
            run_once(
                &mut session,
                &mut conn,
                &mut work,
                &mut scratch,
                &mut target,
                &mut storage
            ),
            Outcome::Processed
        );
        let (bhs, _) = conn.take_pdu().unwrap();
        assert_eq!(bhs[0] & 0x3F, op::SCSI_TASK_RESP);
        assert_eq!(bhs[2], tmf_response::COMPLETE);
        assert_eq!(&bhs[24..28], &be32(1));
    }

    #[test]
    fn tmf_bad_cmd_sn_ignored() {
        let mut ram = vec![0u8; 16 * 1024 * 1024];
        block_fixture!(
            ram, backend, 32768, work, scratch, slots, table, conn, session, target, storage
        );
        login!(conn, session, work, scratch, target, storage);

        let mut tmfr = [0u8; 48];
        tmfr[0] = op::SCSI_TASK_REQ;
        tmfr[1] = 0x80 | tmf::LOGICAL_UNIT_RESET;
        tmfr[16..20].copy_from_slice(&be32(0x6666));
        tmfr[24..28].copy_from_slice(&be32(7));
        conn.feed(&tmfr, &[]);
        assert_eq!(
            run_once(
                &mut session,
                &mut conn,
                &mut work,
                &mut scratch,
                &mut target,
                &mut storage
            ),
            Outcome::Idle
        );
        assert!(conn.take_pdu().is_none());
    }

    /// LOGICAL UNIT RESET raises `06/29/03`: the next reporting command gets
    /// CHECK CONDITION with the class sense, the iSCSI autosense consumes it,
    /// and the following REQUEST SENSE reports NO SENSE.
    #[test]
    fn logical_unit_reset_raises_a_consumed_unit_attention() {
        let mut ram = vec![0u8; 16 * 1024];
        block_fixture!(
            ram, backend, 32, work, scratch, slots, table, conn, session, target, storage
        );
        login!(conn, session, work, scratch, target, storage);

        let mut tmfr = [0u8; 48];
        tmfr[0] = op::SCSI_TASK_REQ;
        tmfr[1] = 0x80 | tmf::LOGICAL_UNIT_RESET;
        tmfr[16..20].copy_from_slice(&be32(0x7777));
        tmfr[24..28].copy_from_slice(&be32(0));
        conn.feed(&tmfr, &[]);
        assert_eq!(
            run_once(
                &mut session,
                &mut conn,
                &mut work,
                &mut scratch,
                &mut target,
                &mut storage
            ),
            Outcome::Processed
        );
        let (bhs, _) = conn.take_pdu().unwrap();
        assert_eq!(bhs[0] & 0x3F, op::SCSI_TASK_RESP);
        assert_eq!(bhs[2], tmf_response::COMPLETE);

        // TEST UNIT READY reports the reset condition.
        conn.feed(&tur_bhs(0x7101, 1), &[]);
        assert_eq!(
            run_once(
                &mut session,
                &mut conn,
                &mut work,
                &mut scratch,
                &mut target,
                &mut storage
            ),
            Outcome::Processed
        );
        let (bhs, data) = conn.take_pdu().unwrap();
        assert_eq!(bhs[0] & 0x3F, op::SCSI_RESP);
        assert_eq!(bhs[3], status::CHECK_CONDITION);
        assert_eq!(&bhs[16..20], &be32(0x7101));
        // Autosense: 2-byte SenseLength + fixed-format sense.
        assert_eq!(&data[0..2], &[0x00, 18]);
        assert_eq!(data[2], 0x70);
        assert_eq!(data[4], 0x06, "UNIT ATTENTION");
        assert_eq!(data[14], 0x29, "POWER ON, RESET, OR BUS DEVICE RESET");
        assert_eq!(data[15], 0x03, "LOGICAL UNIT RESET");

        // The autosense delivery consumed the instance: REQUEST SENSE reports
        // NO SENSE.
        conn.feed(&request_sense_bhs(18, 0x7102, 2), &[]);
        assert_eq!(
            run_once(
                &mut session,
                &mut conn,
                &mut work,
                &mut scratch,
                &mut target,
                &mut storage
            ),
            Outcome::Processed
        );
        let (bhs, data) = conn.take_pdu().unwrap();
        assert_eq!(bhs[0] & 0x3F, op::SCSI_DATA_IN);
        assert_eq!(bhs[3], status::GOOD);
        assert_eq!(data[2], 0x00, "NO SENSE");
        assert_eq!(data[12], 0x00, "ASC cleared");
    }

    #[test]
    fn tmf_on_unknown_lun_reports_lun_does_not_exist() {
        let mut ram = vec![0u8; 16 * 1024];
        block_fixture!(
            ram, backend, 32, work, scratch, slots, table, conn, session, target, storage
        );
        login!(conn, session, work, scratch, target, storage);

        for (itt, function) in [
            (0x7A01u32, tmf::LOGICAL_UNIT_RESET),
            (0x7A02, tmf::ABORT_TASK),
        ] {
            let mut tmfr = [0u8; 48];
            tmfr[0] = op::SCSI_TASK_REQ | 0x40;
            tmfr[1] = 0x80 | function;
            tmfr[9] = 5; // out-of-range wire LUN
            tmfr[16..20].copy_from_slice(&be32(itt));
            conn.feed(&tmfr, &[]);
            assert_eq!(
                run_once(
                    &mut session,
                    &mut conn,
                    &mut work,
                    &mut scratch,
                    &mut target,
                    &mut storage
                ),
                Outcome::Processed
            );
            let (bhs, _) = conn.take_pdu().unwrap();
            assert_eq!(bhs[0] & 0x3F, op::SCSI_TASK_RESP);
            assert_eq!(
                bhs[2],
                tmf_response::LUN_DOES_NOT_EXIST,
                "function 0x{function:02X} on an absent LUN"
            );
        }
    }

    // ── Logout / text / AHS ────────────────────────────────────────

    #[test]
    fn logout_closes_connection() {
        let mut ram = vec![0u8; 16 * 1024 * 1024];
        block_fixture!(
            ram, backend, 32768, work, scratch, slots, table, conn, session, target, storage
        );
        login!(conn, session, work, scratch, target, storage);

        let mut lo = [0u8; 48];
        lo[0] = op::LOGOUT_REQ;
        lo[16..20].copy_from_slice(&be32(0xCAFE));
        conn.feed(&lo, &[]);
        assert_eq!(
            run_once(
                &mut session,
                &mut conn,
                &mut work,
                &mut scratch,
                &mut target,
                &mut storage
            ),
            Outcome::Closed
        );
        let (bhs, _) = conn.take_pdu().unwrap();
        assert_eq!(bhs[0] & 0x3F, op::LOGOUT_RESP);
        assert_eq!(&bhs[16..20], &be32(0xCAFE));
    }

    #[test]
    fn text_request_rejected() {
        let mut ram = vec![0u8; 16 * 1024 * 1024];
        block_fixture!(
            ram, backend, 32768, work, scratch, slots, table, conn, session, target, storage
        );
        login!(conn, session, work, scratch, target, storage);

        let mut txt = [0u8; 48];
        txt[0] = op::TEXT_REQ;
        txt[16..20].copy_from_slice(&be32(0x1234));
        txt[24..28].copy_from_slice(&be32(1));
        conn.feed(&txt, &[]);
        assert_eq!(
            run_once(
                &mut session,
                &mut conn,
                &mut work,
                &mut scratch,
                &mut target,
                &mut storage
            ),
            Outcome::Closed
        );
        let (bhs, _) = conn.take_pdu().unwrap();
        assert_eq!(bhs[0] & 0x3F, op::REJECT);
        assert_eq!(bhs[2], reject::COMMAND_NOT_SUPPORTED);
    }

    #[test]
    fn sendtargets_all_on_discovery_returns_target_name() {
        let mut ram = vec![0u8; 16 * 1024 * 1024];
        block_fixture!(
            ram, backend, 32768, work, scratch, slots, table, conn, session, target, storage
        );
        let text = b"InitiatorName=iqn.test\0SessionType=Discovery\0TargetName=iqn.1970-01.local.snowscsi:target\0";
        let mut bhs = [0u8; 48];
        bhs[0] = op::LOGIN_REQ | 0x40;
        bhs[1] = flag::T_BIT | ((stage::OP_PARAM & 0x03) << flag::CSG_SHIFT) | stage::FULL_FEATURE;
        let dsl = text.len() as u32;
        bhs[5] = (dsl >> 16) as u8;
        bhs[6] = (dsl >> 8) as u8;
        bhs[7] = dsl as u8;
        conn.feed_padded(&bhs, text);
        assert_eq!(
            run_once(
                &mut session,
                &mut conn,
                &mut work,
                &mut scratch,
                &mut target,
                &mut storage
            ),
            Outcome::Processed
        );
        conn.take_pdu().unwrap();

        let payload = b"SendTargets=All\0";
        let mut txt = [0u8; 48];
        txt[0] = op::TEXT_REQ;
        txt[1] = flag::F_BIT;
        txt[5] = (payload.len() >> 16) as u8;
        txt[6] = (payload.len() >> 8) as u8;
        txt[7] = payload.len() as u8;
        txt[16..20].copy_from_slice(&be32(0x5555));
        txt[20..24].copy_from_slice(&be32(0xFFFF_FFFF));
        txt[24..28].copy_from_slice(&be32(1));
        conn.feed_padded(&txt, payload);
        assert_eq!(
            run_once(
                &mut session,
                &mut conn,
                &mut work,
                &mut scratch,
                &mut target,
                &mut storage
            ),
            Outcome::Processed
        );
        let (bhs, data) = conn.take_pdu().unwrap();
        assert_eq!(bhs[0] & 0x3F, op::TEXT_RESP);
        assert_eq!(bhs[1] & flag::F_BIT, flag::F_BIT);
        assert_eq!(&bhs[16..20], &be32(0x5555));
        assert!(data.windows(11).any(|w| w == b"TargetName="));
        assert!(data.windows(8).any(|w| w == b"snowscsi"));
    }

    #[test]
    fn ahs_rejected() {
        let mut ram = vec![0u8; 16 * 1024 * 1024];
        block_fixture!(
            ram, backend, 32768, work, scratch, slots, table, conn, session, target, storage
        );
        login!(conn, session, work, scratch, target, storage);

        let mut pdu = read10_bhs(0, 1, 0x7777, 0);
        pdu[4] = 1;
        conn.feed(&pdu, &[]);
        conn.feed_bytes(&[0u8; 4]);
        assert_eq!(
            run_once(
                &mut session,
                &mut conn,
                &mut work,
                &mut scratch,
                &mut target,
                &mut storage
            ),
            Outcome::Closed
        );
        let (bhs, _) = conn.take_pdu().unwrap();
        assert_eq!(bhs[0] & 0x3F, op::REJECT);
        assert_eq!(bhs[2], reject::PROTOCOL_ERROR);
    }

    #[test]
    fn linux_kernel_write_flag_layout_accepted() {
        let mut ram = vec![0u8; 16 * 1024 * 1024];
        block_fixture!(
            ram, backend, 32768, work, scratch, slots, table, conn, session, target, storage
        );
        login!(conn, session, work, scratch, target, storage);

        let itt = 0xA100_0001;
        let imm = vec![0x42u8; 512];
        let cmd = write10_bhs(0, 1, itt, 0, 512);
        conn.feed_padded(&cmd, &imm);
        assert_eq!(
            run_once(
                &mut session,
                &mut conn,
                &mut work,
                &mut scratch,
                &mut target,
                &mut storage
            ),
            Outcome::Processed
        );
        let (resp, _) = conn.take_pdu().unwrap();
        assert_eq!(resp[0] & 0x3F, op::SCSI_RESP);
        assert_eq!(resp[3], status::GOOD);

        let itt = 0xA100_0002;
        let mut cmd = write10_bhs(0, 1, itt, 1, 512);
        cmd[1] = 0xA0;
        conn.feed_padded(&cmd, &imm);
        assert_eq!(
            run_once(
                &mut session,
                &mut conn,
                &mut work,
                &mut scratch,
                &mut target,
                &mut storage
            ),
            Outcome::Processed
        );
        let (resp, _) = conn.take_pdu().unwrap();
        assert_eq!(resp[0] & 0x3F, op::SCSI_RESP);
        assert_eq!(resp[3], status::GOOD);
    }

    // ── serve_conn blocking loop ───────────────────────────────────

    #[test]
    fn serve_conn_login_then_logout() {
        use snowscsi::iscsi::transport::serve_conn;

        let mut ram = vec![0u8; 16 * 1024 * 1024];
        let mut backend = RamBackend::new(&mut ram);
        let mut slots = [TestLu::block(32768, 512, 0)];
        let mut table: Vec<&mut dyn Lu<Pair = TestPair>> = slots
            .iter_mut()
            .map(|s| s as &mut dyn Lu<Pair = TestPair>)
            .collect();
        let mut target = Target::new(&mut table[..]);
        let mut storage = PlaneSet::new(vec![Some(StorePlane::BlockRw(&mut backend))]);
        let mut conn = MockConn::new();
        let mut session = IscsiSession::default();
        let mut work = vec![0u8; WORK_LEN];
        let mut scratch = vec![0u8; MIN_DATA_LEN];

        let text = REQ_TEXT.as_bytes();
        conn.feed_padded(&login_bhs(text.len() as u32), text);
        let mut lo = [0u8; 48];
        lo[0] = op::LOGOUT_REQ;
        lo[16..20].copy_from_slice(&be32(1));
        conn.feed(&lo, &[]);

        assert!(serve_conn(
            &mut conn,
            &mut work,
            &mut scratch,
            &mut session,
            &mut target,
            &mut storage
        )
        .is_ok());

        let (bhs, _) = conn.take_pdu().unwrap();
        assert_eq!(bhs[0] & 0x3F, op::LOGIN_RESP);
        let (bhs, _) = conn.take_pdu().unwrap();
        assert_eq!(bhs[0] & 0x3F, op::LOGOUT_RESP);
        assert!(conn.take_pdu().is_none());
    }

    // ── REPORT LUNS ────────────────────────────────────────────────

    #[test]
    fn report_luns_single_lun() {
        let mut ram = vec![0u8; 16 * 1024];
        block_fixture!(
            ram, backend, 32, work, scratch, slots, table, conn, session, target, storage
        );
        login!(conn, session, work, scratch, target, storage);

        conn.feed(&report_luns_bhs(0, 0xA1, 0), &[]);
        assert_eq!(
            run_once(
                &mut session,
                &mut conn,
                &mut work,
                &mut scratch,
                &mut target,
                &mut storage
            ),
            Outcome::Processed
        );
        let (bhs, data) = conn.take_pdu().unwrap();
        assert_eq!(bhs[0] & 0x3F, op::SCSI_DATA_IN);
        assert_eq!(
            bhs[1] & (flag::F_BIT | flag::S_BIT),
            flag::F_BIT | flag::S_BIT
        );
        assert_eq!(bhs[3], status::GOOD);
        assert_eq!(bhs[16..20], be32(0xA1));
        assert_eq!(&data[..4], &[0, 0, 0, 8]);
        assert_eq!(&data[4..8], &[0, 0, 0, 0]);
        assert_eq!(&data[8..16], &[0, 0, 0, 0, 0, 0, 0, 0]);
    }

    #[test]
    fn report_luns_select_01_well_known_only_empty() {
        let mut ram = vec![0u8; 16 * 1024];
        block_fixture!(
            ram, backend, 32, work, scratch, slots, table, conn, session, target, storage
        );
        login!(conn, session, work, scratch, target, storage);

        conn.feed(&report_luns_bhs_select(0, 0xA2, 0, 0x01), &[]);
        assert_eq!(
            run_once(
                &mut session,
                &mut conn,
                &mut work,
                &mut scratch,
                &mut target,
                &mut storage
            ),
            Outcome::Processed
        );
        let (bhs, data) = conn.take_pdu().unwrap();
        assert_eq!(bhs[0] & 0x3F, op::SCSI_DATA_IN);
        assert_eq!(bhs[3], status::GOOD);
        assert_eq!(&data[..4], &[0, 0, 0, 0]);
    }

    #[test]
    fn report_luns_select_02_returns_full_list() {
        let mut ram = vec![0u8; 16 * 1024];
        block_fixture!(
            ram, backend, 32, work, scratch, slots, table, conn, session, target, storage
        );
        login!(conn, session, work, scratch, target, storage);

        conn.feed(&report_luns_bhs_select(0, 0xA3, 0, 0x02), &[]);
        assert_eq!(
            run_once(
                &mut session,
                &mut conn,
                &mut work,
                &mut scratch,
                &mut target,
                &mut storage
            ),
            Outcome::Processed
        );
        let (bhs, data) = conn.take_pdu().unwrap();
        assert_eq!(bhs[3], status::GOOD);
        assert_eq!(&data[..4], &[0, 0, 0, 8]);
        assert_eq!(&data[8..16], &[0, 0, 0, 0, 0, 0, 0, 0]);
    }

    #[test]
    fn report_luns_reserved_select_rejected() {
        let mut ram = vec![0u8; 16 * 1024];
        block_fixture!(
            ram, backend, 32, work, scratch, slots, table, conn, session, target, storage
        );
        login!(conn, session, work, scratch, target, storage);

        conn.feed(&report_luns_bhs_select(0, 0xA4, 0, 0x03), &[]);
        assert_eq!(
            run_once(
                &mut session,
                &mut conn,
                &mut work,
                &mut scratch,
                &mut target,
                &mut storage
            ),
            Outcome::Processed
        );
        let (bhs, data) = conn.take_pdu().unwrap();
        assert_eq!(bhs[0] & 0x3F, op::SCSI_RESP);
        assert_eq!(bhs[3], status::CHECK_CONDITION);
        assert_eq!(&data[0..2], &[0x00, 18]);
        assert_eq!(data[2], 0x70);
        assert_eq!(data[4], 0x05);
        assert_eq!(data[14], 0x24);
    }

    fn kernel_scsilun_to_int(s: &[u8; 8]) -> u64 {
        let mut lun: u64 = 0;
        for i in (0..8).step_by(2) {
            lun |=
                (u64::from(s[i]) << ((i as u64 + 1) * 8)) | (u64::from(s[i + 1]) << (i as u64 * 8));
        }
        lun
    }

    #[test]
    fn report_luns_kernel_scsilun_to_int_alignment() {
        let mut r0 = vec![0u8; 16 * 1024];
        let mut r1 = vec![0u8; 16 * 1024];
        let mut r2 = vec![0u8; 16 * 1024];
        let mut b0 = RamBackend::new(&mut r0);
        let mut b1 = RamBackend::new(&mut r1);
        let mut b2 = RamBackend::new(&mut r2);
        let mut slots = [
            TestLu::block(32, 512, 0),
            TestLu::block(32, 512, 1),
            TestLu::block(32, 512, 2),
        ];
        let mut table: Vec<&mut dyn Lu<Pair = TestPair>> = slots
            .iter_mut()
            .map(|s| s as &mut dyn Lu<Pair = TestPair>)
            .collect();
        let mut target = Target::new(&mut table[..]);
        let mut storage = PlaneSet::new(vec![
            Some(StorePlane::BlockRw(&mut b0)),
            Some(StorePlane::BlockRw(&mut b1)),
            Some(StorePlane::BlockRw(&mut b2)),
        ]);
        let mut conn = MockConn::new();
        let mut session = IscsiSession::default();
        let mut work = vec![0u8; WORK_LEN];
        let mut scratch = vec![0u8; MIN_DATA_LEN];
        login!(conn, session, work, scratch, target, storage);

        conn.feed(&report_luns_bhs(0, 0xBEEF, 0), &[]);
        assert_eq!(
            run_once(
                &mut session,
                &mut conn,
                &mut work,
                &mut scratch,
                &mut target,
                &mut storage
            ),
            Outcome::Processed
        );
        let (_, data) = conn.take_pdu().unwrap();
        let length = u32::from_be_bytes([data[0], data[1], data[2], data[3]]);
        let num_luns = length as usize / 8;
        assert_eq!(num_luns, 3);
        for i in 1..=num_luns {
            let off = i * 8;
            let mut entry = [0u8; 8];
            entry.copy_from_slice(&data[off..off + 8]);
            assert_eq!(kernel_scsilun_to_int(&entry), i as u64 - 1);
        }
    }

    #[test]
    fn report_luns_three_luns_requested_at_lun_1() {
        let mut r0 = vec![0u8; 16 * 1024];
        let mut r1 = vec![0u8; 16 * 1024];
        let mut r2 = vec![0u8; 16 * 1024];
        let mut b0 = RamBackend::new(&mut r0);
        let mut b1 = RamBackend::new(&mut r1);
        let mut b2 = RamBackend::new(&mut r2);
        let mut slots = [
            TestLu::block(32, 512, 0),
            TestLu::block(32, 512, 1),
            TestLu::block(32, 512, 2),
        ];
        let mut table: Vec<&mut dyn Lu<Pair = TestPair>> = slots
            .iter_mut()
            .map(|s| s as &mut dyn Lu<Pair = TestPair>)
            .collect();
        let mut target = Target::new(&mut table[..]);
        let mut storage = PlaneSet::new(vec![
            Some(StorePlane::BlockRw(&mut b0)),
            Some(StorePlane::BlockRw(&mut b1)),
            Some(StorePlane::BlockRw(&mut b2)),
        ]);
        let mut conn = MockConn::new();
        let mut session = IscsiSession::default();
        let mut work = vec![0u8; WORK_LEN];
        let mut scratch = vec![0u8; MIN_DATA_LEN];
        login!(conn, session, work, scratch, target, storage);

        conn.feed(&report_luns_bhs(1, 0xCAFE, 0), &[]);
        assert_eq!(
            run_once(
                &mut session,
                &mut conn,
                &mut work,
                &mut scratch,
                &mut target,
                &mut storage
            ),
            Outcome::Processed
        );
        let (_, data) = conn.take_pdu().unwrap();
        assert_eq!(&data[..4], &[0, 0, 0, 24]);
        let ids: Vec<u8> = (0..3).map(|i| data[8 + i * 8 + 1]).collect();
        assert_eq!(ids, vec![0, 1, 2]);
    }

    #[test]
    fn report_luns_on_unsupported_lun_still_lists_all() {
        let mut ram = vec![0u8; 16 * 1024];
        block_fixture!(
            ram, backend, 32, work, scratch, slots, table, conn, session, target, storage
        );
        login!(conn, session, work, scratch, target, storage);

        let mut cmd = report_luns_bhs(5, 0xDEAD, 0);
        cmd[9] = 5;
        conn.feed(&cmd, &[]);
        assert_eq!(
            run_once(
                &mut session,
                &mut conn,
                &mut work,
                &mut scratch,
                &mut target,
                &mut storage
            ),
            Outcome::Processed
        );
        let (bhs, data) = conn.take_pdu().unwrap();
        assert_eq!(bhs[0] & 0x3F, op::SCSI_DATA_IN);
        assert_eq!(bhs[3], status::GOOD);
        assert_eq!(&bhs[16..20], &be32(0xDEAD));
        assert_eq!(&data[..4], &[0, 0, 0, 8]);
    }

    // ── Mixed block + MMC LUN dispatch ─────────────────────────────

    #[test]
    fn mixed_lun_block_and_cdrom_dispatch() {
        let mut ram = vec![0u8; 16 * 1024 * 1024];
        let mut b0 = RamBackend::new(&mut ram);
        let mut iso_ram = vec![0xCDu8; 2048 * 32];
        let mut b1 = RamBackend::new(&mut iso_ram);

        let mut slots = [TestLu::block(32768, 512, 0), TestLu::cdrom(32, 1)];
        let mut table: Vec<&mut dyn Lu<Pair = TestPair>> = slots
            .iter_mut()
            .map(|s| s as &mut dyn Lu<Pair = TestPair>)
            .collect();
        let mut target = Target::new(&mut table[..]);
        let mut storage = PlaneSet::new(vec![
            Some(StorePlane::BlockRw(&mut b0)),
            Some(StorePlane::BlockRo(&mut b1)),
        ]);
        let mut conn = MockConn::new();
        let mut session = IscsiSession::default();
        let mut work = vec![0u8; WORK_LEN];
        let mut scratch = vec![0u8; MIN_DATA_LEN];
        login!(conn, session, work, scratch, target, storage);

        conn.feed(&inquiry_bhs(0, 96, 0x0101, 0), &[]);
        assert_eq!(
            run_once(
                &mut session,
                &mut conn,
                &mut work,
                &mut scratch,
                &mut target,
                &mut storage
            ),
            Outcome::Processed
        );
        let (bhs, data) = conn.take_pdu().unwrap();
        assert_eq!(bhs[0] & 0x3F, op::SCSI_DATA_IN);
        assert_eq!(bhs[3], status::GOOD);
        assert_eq!(data[0], 0x00, "LUN 0 must report PDT 0x00");

        conn.feed(&inquiry_bhs(1, 96, 0x0102, 1), &[]);
        assert_eq!(
            run_once(
                &mut session,
                &mut conn,
                &mut work,
                &mut scratch,
                &mut target,
                &mut storage
            ),
            Outcome::Processed
        );
        let (bhs, data) = conn.take_pdu().unwrap();
        assert_eq!(bhs[0] & 0x3F, op::SCSI_DATA_IN);
        assert_eq!(data[0], 0x05, "LUN 1 must report PDT 0x05");

        let mut read = read10_bhs(0, 1, 0x0201, 2);
        read[9] = 1;
        conn.feed(&read, &[]);
        assert_eq!(
            run_once(
                &mut session,
                &mut conn,
                &mut work,
                &mut scratch,
                &mut target,
                &mut storage
            ),
            Outcome::Processed
        );
        let (bhs, data) = conn.take_pdu().unwrap();
        assert_eq!(bhs[0] & 0x3F, op::SCSI_DATA_IN);
        assert_eq!(bhs[3], status::GOOD);
        assert_eq!(data.len(), 2048);
        assert_eq!(&data[..4], &[0xCD; 4]);

        let mut write = write10_bhs(0, 1, 0x0301, 3, 0);
        write[9] = 1;
        conn.feed(&write, &[]);
        assert_eq!(
            run_once(
                &mut session,
                &mut conn,
                &mut work,
                &mut scratch,
                &mut target,
                &mut storage
            ),
            Outcome::Processed
        );
        let (bhs, _) = conn.take_pdu().unwrap();
        assert_eq!(bhs[0] & 0x3F, op::SCSI_RESP);
        assert_eq!(bhs[3], status::CHECK_CONDITION);

        conn.feed(&report_luns_bhs(0, 0x0401, 4), &[]);
        assert_eq!(
            run_once(
                &mut session,
                &mut conn,
                &mut work,
                &mut scratch,
                &mut target,
                &mut storage
            ),
            Outcome::Processed
        );
        let (_, data) = conn.take_pdu().unwrap();
        assert_eq!(&data[..4], &[0, 0, 0, 16]);
        assert_eq!(data[8 + 1], 0);
        assert_eq!(data[16 + 1], 1);
    }

    /// A generated live ISO9660 plane served through iSCSI: the LUN is an MMC
    /// drive over the live layout, and READ(10) returns the generated file
    /// bytes (not the raw source tree).
    #[test]
    fn mixed_lun_block_cdrom_flat_and_live_dispatch() {
        use snowscsi::cdrom::media::LiveData;
        use snowscsi::common::seekable_storage::FlatData;
        use snowscsi::scsi::fs_backend::StdFsBackend;

        let dir =
            std::env::temp_dir().join(format!("snowscsi_mock_live_iscsi_{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(dir.join("DATA.BIN"), vec![0x42u8; 4096]).unwrap();

        let mut live = LiveData::new(StdFsBackend::new(&dir.to_string_lossy()), "LIVE")
            .expect("scan the live tree");
        let live_lba = live.layout().extents[0].lba;
        let sectors = live.capacity() / 2048;
        assert!(sectors > 0);

        let mut ram = vec![0u8; 64 * 1024];
        let mut block = RamBackend::new(&mut ram);
        let mut slots = [TestLu::block(128, 512, 0), TestLu::cdrom(sectors, 1)];
        let mut table: Vec<&mut dyn Lu<Pair = TestPair>> = slots
            .iter_mut()
            .map(|s| s as &mut dyn Lu<Pair = TestPair>)
            .collect();
        let mut target = Target::new(&mut table[..]);
        let mut storage = PlaneSet::new(vec![
            Some(StorePlane::BlockRw(&mut block)),
            Some(StorePlane::BlockRo(&mut live)),
        ]);
        let mut conn = MockConn::new();
        let mut session = IscsiSession::default();
        let mut work = vec![0u8; WORK_LEN];
        let mut scratch = vec![0u8; MIN_DATA_LEN];
        login!(conn, session, work, scratch, target, storage);

        // LUN 1 is the live-generated CD-ROM.
        conn.feed(&inquiry_bhs(1, 96, 0x0201, 0), &[]);
        assert_eq!(
            run_once(
                &mut session,
                &mut conn,
                &mut work,
                &mut scratch,
                &mut target,
                &mut storage
            ),
            Outcome::Processed
        );
        let (bhs, data) = conn.take_pdu().unwrap();
        assert_eq!(bhs[0] & 0x3F, op::SCSI_DATA_IN);
        assert_eq!(data[0], 0x05, "LUN 1 reports PDT 0x05");

        // READ(10) at the live file extent returns DATA.BIN's content.
        let mut read = read10_bhs(live_lba, 1, 0x0202, 1);
        read[9] = 1;
        conn.feed(&read, &[]);
        assert_eq!(
            run_once(
                &mut session,
                &mut conn,
                &mut work,
                &mut scratch,
                &mut target,
                &mut storage
            ),
            Outcome::Processed
        );
        let (bhs, data) = conn.take_pdu().unwrap();
        assert_eq!(bhs[0] & 0x3F, op::SCSI_DATA_IN);
        assert_eq!(bhs[3], status::GOOD);
        assert_eq!(data.len(), 2048);
        assert_eq!(&data[..4], &[0x42; 4], "generated extent bytes");

        // Both LUNs are listed.
        conn.feed(&report_luns_bhs(0, 0x0203, 2), &[]);
        assert_eq!(
            run_once(
                &mut session,
                &mut conn,
                &mut work,
                &mut scratch,
                &mut target,
                &mut storage
            ),
            Outcome::Processed
        );
        let (_, data) = conn.take_pdu().unwrap();
        assert_eq!(&data[..4], &[0, 0, 0, 16]);
        assert_eq!(data[8 + 1], 0);
        assert_eq!(data[16 + 1], 1);

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn format_unit_zeroes_the_plane_via_the_resident_operation() {
        // A 4-sector DVD-RAM: FORMAT with a parameter list runs the zero-fill
        // through the command path (synchronous storage), so the plane is
        // zeroed when FORMAT returns GOOD.
        let mut ram = vec![0x5Au8; 4 * 2048];
        let mut be = RamBackend::new(&mut ram);
        let mut slots = [TestLu::dvdram(4, 0)];
        let mut table: Vec<&mut dyn Lu<Pair = TestPair>> = slots
            .iter_mut()
            .map(|s| s as &mut dyn Lu<Pair = TestPair>)
            .collect();
        let mut target = Target::new(&mut table[..]);
        let mut storage = PlaneSet::new(vec![Some(StorePlane::BlockRw(&mut be))]);
        let mut conn = MockConn::new();
        let mut session = IscsiSession::default();
        let mut work = vec![0u8; WORK_LEN];
        let mut scratch = vec![0u8; MIN_DATA_LEN];
        login!(conn, session, work, scratch, target, storage);

        // Consume CmdSN 0 with a no-data INQUIRY.
        conn.feed(&inquiry_bhs(0, 96, 0x0100, 0), &[]);
        assert_eq!(
            run_once(
                &mut session,
                &mut conn,
                &mut work,
                &mut scratch,
                &mut target,
                &mut storage
            ),
            Outcome::Processed
        );
        let _ = conn.take_pdu();

        let mut bhs = [0u8; 48];
        bhs[0] = op::SCSI_CMD;
        bhs[1] = 0xA1;
        bhs[7] = 12;
        bhs[16..20].copy_from_slice(&be32(0x0200));
        bhs[24..28].copy_from_slice(&be32(1));
        bhs[28..32].copy_from_slice(&be32(1));
        bhs[32] = 0x04;
        bhs[33] = 0x11;
        let param = [
            0x00, 0x00, 0x00, 0x08, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x08, 0x00,
        ];
        conn.feed(&bhs, &param);
        assert_eq!(
            run_once(
                &mut session,
                &mut conn,
                &mut work,
                &mut scratch,
                &mut target,
                &mut storage
            ),
            Outcome::Processed
        );
        let (rbhs, _) = conn.take_pdu().unwrap();
        assert_eq!(rbhs[0] & 0x3F, op::SCSI_RESP);
        assert_eq!(rbhs[3], status::GOOD);

        let mut check = vec![0u8; 4 * 2048];
        storage
            .exec_raw(StoreOp::Read {
                off: 0,
                buf: &mut check,
            })
            .unwrap();
        assert!(
            check.iter().all(|&b| b == 0),
            "FORMAT must zero-fill through the runner"
        );
    }

    // ── Data-Out routing by LUN ────────────────────────────────────

    #[test]
    fn data_out_r2t_routes_by_lun() {
        let mut ram0 = vec![0u8; 16 * 1024];
        let mut ram1 = vec![0u8; 16 * 1024];
        let mut b0 = RamBackend::new(&mut ram0);
        let mut b1 = RamBackend::new(&mut ram1);
        let mut slots = [TestLu::block(32, 512, 0), TestLu::block(32, 512, 1)];
        let mut table: Vec<&mut dyn Lu<Pair = TestPair>> = slots
            .iter_mut()
            .map(|s| s as &mut dyn Lu<Pair = TestPair>)
            .collect();
        let mut target = Target::new(&mut table[..]);
        let mut storage = PlaneSet::new(vec![
            Some(StorePlane::BlockRw(&mut b0)),
            Some(StorePlane::BlockRw(&mut b1)),
        ]);
        let mut conn = MockConn::new();
        let mut session = IscsiSession::default();
        let mut work = vec![0u8; WORK_LEN];
        let mut scratch = vec![0u8; MIN_DATA_LEN];
        login!(conn, session, work, scratch, target, storage);

        let itt = 0xC3C3;
        let bhs = write10_bhs(0, 1, itt, 0, 0);
        let mut bhs1 = bhs;
        bhs1[9] = 1;
        conn.feed(&bhs1, &[]);
        let payload = vec![0x5Au8; 512];
        let dout = dataout_bhs(itt, 1, 0, 0, 512);
        conn.feed_padded(&dout, &payload);
        assert_eq!(
            run_once(
                &mut session,
                &mut conn,
                &mut work,
                &mut scratch,
                &mut target,
                &mut storage
            ),
            Outcome::Processed
        );
        let (r2t, _) = conn.take_pdu().unwrap();
        assert_eq!(r2t[0] & 0x3F, op::R2T);
        assert_eq!(&r2t[40..44], &be32(0));
        let (resp, _) = conn.take_pdu().unwrap();
        assert_eq!(resp[0] & 0x3F, op::SCSI_RESP);
        assert_eq!(resp[3], status::GOOD);

        let mut read = read10_bhs(0, 1, 0xD1, 1);
        read[9] = 1;
        conn.feed(&read, &[]);
        assert_eq!(
            run_once(
                &mut session,
                &mut conn,
                &mut work,
                &mut scratch,
                &mut target,
                &mut storage
            ),
            Outcome::Processed
        );
        let (_, data) = conn.take_pdu().unwrap();
        assert_eq!(data, payload);

        let read0 = read10_bhs(0, 1, 0xD2, 2);
        conn.feed(&read0, &[]);
        assert_eq!(
            run_once(
                &mut session,
                &mut conn,
                &mut work,
                &mut scratch,
                &mut target,
                &mut storage
            ),
            Outcome::Processed
        );
        let (_, data0) = conn.take_pdu().unwrap();
        assert_eq!(data0, vec![0u8; 512]);
    }

    // ── Large READ chunking ────────────────────────────────────────

    #[test]
    fn large_read_non_aligned_chunks_via_session() {
        let mut ram = vec![0u8; 2 * 1024 * 1024];
        for (i, b) in ram.iter_mut().enumerate() {
            *b = (i % 251) as u8;
        }
        let expected = ram[0..600 * 512].to_vec();
        let mut backend = RamBackend::new(&mut ram);
        let mut slots = [TestLu::block(4096, 512, 0)];
        let mut table: Vec<&mut dyn Lu<Pair = TestPair>> = slots
            .iter_mut()
            .map(|s| s as &mut dyn Lu<Pair = TestPair>)
            .collect();
        let mut target = Target::new(&mut table[..]);
        let mut storage = PlaneSet::new(vec![Some(StorePlane::BlockRw(&mut backend))]);
        let mut conn = MockConn::new();
        let mut session = IscsiSession::default();
        let mut work = vec![0u8; 384 * 1024];
        let mut scratch = vec![0u8; MIN_DATA_LEN];
        login!(conn, session, work, scratch, target, storage);

        let cmd = read10_bhs(0, 600, 0x7777, 0);
        conn.feed(&cmd, &[]);
        assert_eq!(
            run_once(
                &mut session,
                &mut conn,
                &mut work,
                &mut scratch,
                &mut target,
                &mut storage
            ),
            Outcome::Processed
        );
        let mut collected = Vec::new();
        let mut saw_data_in = 0;
        let mut last_bo = 0u32;
        let mut expected_dsn = 0u32;
        let mut seq_bytes = 0usize;
        let mut sequences = 0;
        // The initiator declared `MaxRecvDataSegmentLength=262144`; 600 blocks
        // are 307200 bytes, so each PDU may carry the full 262144-byte
        // declaration. `MaxBurstLength` is also 262144, which splits the
        // transfer into two sequences: one full PDU, then the 45056-byte tail
        // that also carries S + status.
        const NEGOTIATED_SEGMENT: usize = 262144;
        while let Some((bhs, data)) = conn.take_pdu() {
            if bhs[0] & 0x3F == op::SCSI_DATA_IN {
                let bo = u32::from_be_bytes([bhs[40], bhs[41], bhs[42], bhs[43]]);
                assert_eq!(bo, last_bo, "BufferOffset must be contiguous");
                let dsn = u32::from_be_bytes([bhs[36], bhs[37], bhs[38], bhs[39]]);
                assert_eq!(dsn, expected_dsn, "DataSN must be contiguous");
                last_bo += data.len() as u32;
                expected_dsn += 1;
                collected.extend_from_slice(&data);
                saw_data_in += 1;
                seq_bytes += data.len();
                assert!(
                    seq_bytes <= NEGOTIATED_SEGMENT,
                    "a sequence must not exceed MaxBurstLength"
                );
                if bhs[1] & flag::F_BIT != 0 {
                    sequences += 1;
                    seq_bytes = 0;
                    if bhs[1] & flag::S_BIT != 0 {
                        assert_eq!(
                            data.len(),
                            600 * 512 - NEGOTIATED_SEGMENT,
                            "the last Data-In closes the sequence and carries the transfer remainder"
                        );
                    } else {
                        assert_eq!(
                            data.len(),
                            NEGOTIATED_SEGMENT,
                            "a sequence-ending Data-In exhausts MaxBurstLength"
                        );
                    }
                }
            }
        }
        assert_eq!(saw_data_in, 2, "one full segment + one final Data-In");
        assert_eq!(sequences, 2, "MaxBurstLength splits this transfer in two");
        assert_eq!(collected.len(), 600 * 512);
        assert_eq!(collected, expected);
    }

    /// A 1 MiB read at the 256 KiB `MaxBurstLength`: four sequences, each
    /// closed by an F=1 PDU, with the last one also carrying S + status. The
    /// initiator's 64 KiB `MaxRecvDataSegmentLength` puts four PDUs in every
    /// sequence, so DataSN and BufferOffset must stay contiguous across the
    /// sequence boundaries.
    #[test]
    fn data_in_is_split_into_max_burst_length_sequences() {
        const READ_LEN: usize = 1024 * 1024;
        const MAX_BURST: usize = 256 * 1024;
        const PEER_SEGMENT: usize = 64 * 1024;

        let mut ram = vec![0u8; 2 * 1024 * 1024];
        for (i, b) in ram.iter_mut().enumerate() {
            *b = ((i * 7) % 251) as u8;
        }
        let expected = ram[..READ_LEN].to_vec();
        let mut backend = RamBackend::new(&mut ram);
        let mut slots = [TestLu::block(4096, 512, 0)];
        let mut table: Vec<&mut dyn Lu<Pair = TestPair>> = slots
            .iter_mut()
            .map(|s| s as &mut dyn Lu<Pair = TestPair>)
            .collect();
        let mut target = Target::new(&mut table[..]);
        let mut storage = PlaneSet::new(vec![Some(StorePlane::BlockRw(&mut backend))]);
        let mut conn = MockConn::new();
        let mut session = IscsiSession::default();
        let mut work = vec![0u8; 384 * 1024];
        let mut scratch = vec![0u8; MIN_DATA_LEN];

        let mut text = String::from(REQ_TEXT);
        let key = "MaxRecvDataSegmentLength=";
        let start = text.find(key).unwrap() + key.len();
        let end = text[start..].find('\0').unwrap() + start;
        text.replace_range(start..end, &PEER_SEGMENT.to_string());
        conn.feed_padded(&login_bhs(text.len() as u32), text.as_bytes());
        assert_eq!(
            run_once(
                &mut session,
                &mut conn,
                &mut work,
                &mut scratch,
                &mut target,
                &mut storage
            ),
            Outcome::Processed
        );
        let (bhs, data) = conn.take_pdu().expect("login response");
        assert_eq!(bhs[0] & 0x3F, op::LOGIN_RESP);
        assert_eq!(
            resp_value(&data, "MaxBurstLength"),
            Some(b"262144".as_slice())
        );

        // 2048 blocks x 512 = 1 MiB.
        conn.feed(&read10_bhs(0, 2048, 0x6001, 0), &[]);
        assert_eq!(
            run_once(
                &mut session,
                &mut conn,
                &mut work,
                &mut scratch,
                &mut target,
                &mut storage
            ),
            Outcome::Processed
        );

        let mut collected = Vec::new();
        let mut expected_bo = 0u32;
        let mut expected_dsn = 0u32;
        let mut seq_bytes = 0usize;
        let mut seq_pdus = 0usize;
        let mut sequences: Vec<(usize, usize, bool)> = Vec::new();
        while let Some((bhs, data)) = conn.take_pdu() {
            if bhs[0] & 0x3F != op::SCSI_DATA_IN {
                continue;
            }
            let bo = u32::from_be_bytes([bhs[40], bhs[41], bhs[42], bhs[43]]);
            let dsn = u32::from_be_bytes([bhs[36], bhs[37], bhs[38], bhs[39]]);
            assert_eq!(bo, expected_bo, "BufferOffset must be contiguous");
            assert_eq!(dsn, expected_dsn, "DataSN must be contiguous");
            assert!(
                data.len() <= PEER_SEGMENT,
                "a Data-In PDU must not exceed the initiator's declared segment"
            );
            expected_bo += data.len() as u32;
            expected_dsn += 1;
            seq_bytes += data.len();
            seq_pdus += 1;
            assert!(
                seq_bytes <= MAX_BURST,
                "a sequence must not exceed MaxBurstLength"
            );
            collected.extend_from_slice(&data);
            if bhs[1] & flag::F_BIT != 0 {
                let has_status = bhs[1] & flag::S_BIT != 0;
                if has_status {
                    assert_eq!(bhs[3], status::GOOD);
                }
                sequences.push((seq_bytes, seq_pdus, has_status));
                seq_bytes = 0;
                seq_pdus = 0;
            } else {
                assert_eq!(bhs[1] & flag::S_BIT, 0, "S only on the final PDU");
            }
        }

        assert_eq!(sequences.len(), 4, "four 256 KiB sequences");
        for (bytes, pdus, _) in &sequences {
            assert_eq!(*bytes, MAX_BURST, "every sequence exhausts MaxBurstLength");
            assert!(
                *pdus >= MAX_BURST / PEER_SEGMENT,
                "a sequence needs at least four declared-segment PDUs"
            );
        }
        assert!(
            !sequences[0].2 && !sequences[1].2 && !sequences[2].2 && sequences[3].2,
            "only the last sequence carries status"
        );
        assert_eq!(collected.len(), READ_LEN);
        assert_eq!(collected, expected, "the read data must be byte-exact");
        assert_eq!(expected_bo, READ_LEN as u32);
        assert!(expected_dsn as usize >= 16, "16 PDUs at the minimum");

        // The session is still usable: a one-block read completes.
        conn.feed(&read10_bhs(0, 1, 0x6002, 1), &[]);
        assert_eq!(
            run_once(
                &mut session,
                &mut conn,
                &mut work,
                &mut scratch,
                &mut target,
                &mut storage
            ),
            Outcome::Processed
        );
        let (bhs, data) = conn.take_pdu().expect("short read after the sequences");
        assert_eq!(bhs[0] & 0x3F, op::SCSI_DATA_IN);
        assert_eq!(
            bhs[1] & (flag::F_BIT | flag::S_BIT),
            flag::F_BIT | flag::S_BIT
        );
        assert_eq!(bhs[3], status::GOOD);
        assert_eq!(data, expected[..512].to_vec());
    }

    // ── MaxRecvDataSegmentLength per direction ────────────────────

    #[test]
    fn peer_declared_max_recv_data_segment_below_the_floor_is_clamped_up() {
        let mut ram = vec![0u8; 16 * 1024];
        for (i, b) in ram.iter_mut().enumerate() {
            *b = (i % 251) as u8;
        }
        block_fixture!(
            ram, backend, 32768, work, scratch, slots, table, conn, session, target, storage
        );

        let mut text = String::from(REQ_TEXT);
        let key = "MaxRecvDataSegmentLength=";
        let start = text.find(key).unwrap() + key.len();
        let end = text[start..].find('\0').unwrap() + start;
        text.replace_range(start..end, "1");
        let bhs = login_bhs(text.len() as u32);
        conn.feed_padded(&bhs, text.as_bytes());
        assert_eq!(
            run_once(
                &mut session,
                &mut conn,
                &mut work,
                &mut scratch,
                &mut target,
                &mut storage
            ),
            Outcome::Processed
        );
        let (bhs, data) = conn.take_pdu().expect("login response");
        assert_eq!(bhs[0] & 0x3F, op::LOGIN_RESP);
        assert_eq!(
            resp_value(&data, "MaxRecvDataSegmentLength"),
            Some(b"8192".as_slice()),
            "the response declares our own receive capability, not the offer"
        );

        // The clamp applies to what we send: every Data-In PDU stays within
        // the (clamped-up) 512-byte peer declaration.
        conn.feed(&read10_bhs(0, 4, 0x5151, 0), &[]);
        assert_eq!(
            run_once(
                &mut session,
                &mut conn,
                &mut work,
                &mut scratch,
                &mut target,
                &mut storage
            ),
            Outcome::Processed
        );
        let mut total = 0usize;
        while let Some((bhs, data)) = conn.take_pdu() {
            if bhs[0] & 0x3F == op::SCSI_DATA_IN {
                assert!(data.len() <= 512, "PDU exceeds the peer declaration");
                total += data.len();
            }
        }
        assert_eq!(total, 4 * 512);
    }

    #[test]
    fn data_in_uses_at_most_the_work_bank_when_the_peer_declares_more() {
        // The initiator declares 262144, so Data-In may use up to the 8192-byte
        // work bank; our own 8192 receive declaration plays no part here.
        let mut ram = vec![0u8; 16 * 1024 * 1024];
        block_fixture!(
            ram, backend, 32768, work, scratch, slots, table, conn, session, target, storage
        );
        login!(conn, session, work, scratch, target, storage);

        // 32 blocks = 16384 bytes = two full 8192-byte PDUs across two device
        // chunks.
        conn.feed(&read10_bhs(0, 32, 0x5252, 0), &[]);
        assert_eq!(
            run_once(
                &mut session,
                &mut conn,
                &mut work,
                &mut scratch,
                &mut target,
                &mut storage
            ),
            Outcome::Processed
        );
        let mut sizes = Vec::new();
        while let Some((bhs, data)) = conn.take_pdu() {
            if bhs[0] & 0x3F == op::SCSI_DATA_IN {
                sizes.push(data.len());
            }
        }
        assert_eq!(sizes, vec![8192, 8192], "the bank bounds each Data-In PDU");
    }

    #[test]
    fn peer_declared_max_recv_data_segment_of_512_bounds_every_data_in_pdu() {
        let mut ram = vec![0u8; 16 * 1024];
        block_fixture!(
            ram, backend, 32768, work, scratch, slots, table, conn, session, target, storage
        );

        let mut text = String::from(REQ_TEXT);
        let key = "MaxRecvDataSegmentLength=";
        let start = text.find(key).unwrap() + key.len();
        let end = text[start..].find('\0').unwrap() + start;
        text.replace_range(start..end, "512");
        let bhs = login_bhs(text.len() as u32);
        conn.feed_padded(&bhs, text.as_bytes());
        assert_eq!(
            run_once(
                &mut session,
                &mut conn,
                &mut work,
                &mut scratch,
                &mut target,
                &mut storage
            ),
            Outcome::Processed
        );
        let (bhs, data) = conn.take_pdu().expect("login response");
        assert_eq!(bhs[0] & 0x3F, op::LOGIN_RESP);
        assert_eq!(
            resp_value(&data, "MaxRecvDataSegmentLength"),
            Some(b"8192".as_slice()),
            "our declaration does not echo the initiator's value"
        );

        conn.feed(&read10_bhs(0, 4, 0x5353, 0), &[]);
        assert_eq!(
            run_once(
                &mut session,
                &mut conn,
                &mut work,
                &mut scratch,
                &mut target,
                &mut storage
            ),
            Outcome::Processed
        );
        let mut sizes = Vec::new();
        while let Some((bhs, data)) = conn.take_pdu() {
            if bhs[0] & 0x3F == op::SCSI_DATA_IN {
                sizes.push(data.len());
            }
        }
        assert_eq!(sizes, vec![512; 4], "one PDU per declared segment");
    }

    /// The iSCSI floor bank: the data area is `MIN_DATA_LEN`, so the Login
    /// Response declares `MaxRecvDataSegmentLength = 8192` (the default that
    /// applies during Login, RFC 3720 §6.1) and a two-block READ completes.
    #[test]
    fn default_bank_declares_8192_and_streams_data_in() {
        const READ_LEN: usize = 2 * 512;
        let mut ram = vec![0u8; 16 * 1024];
        for (i, b) in ram.iter_mut().enumerate() {
            *b = (i % 251) as u8;
        }
        let expected = ram[..READ_LEN].to_vec();
        let mut backend = RamBackend::new(&mut ram);
        let mut slots = [TestLu::block(32, 512, 0)];
        let mut table: Vec<&mut dyn Lu<Pair = TestPair>> = slots
            .iter_mut()
            .map(|s| s as &mut dyn Lu<Pair = TestPair>)
            .collect();
        let mut target = Target::new(&mut table[..]);
        let mut storage = PlaneSet::new(vec![Some(StorePlane::BlockRw(&mut backend))]);
        let mut conn = MockConn::new();
        let mut session = IscsiSession::default();
        let mut work = vec![0u8; MIN_DATA_LEN + BHS_SIZE];
        let mut scratch = vec![0u8; MIN_DATA_LEN];

        let mut text = String::from(REQ_TEXT);
        let key = "MaxRecvDataSegmentLength=";
        let start = text.find(key).unwrap() + key.len();
        let end = text[start..].find('\0').unwrap() + start;
        text.replace_range(start..end, "8192");
        conn.feed_padded(&login_bhs(text.len() as u32), text.as_bytes());
        assert_eq!(
            run_once(
                &mut session,
                &mut conn,
                &mut work,
                &mut scratch,
                &mut target,
                &mut storage
            ),
            Outcome::Processed
        );
        let (bhs, data) = conn.take_pdu().expect("login response");
        assert_eq!(bhs[0] & 0x3F, op::LOGIN_RESP);
        assert_eq!(
            resp_value(&data, "MaxRecvDataSegmentLength"),
            Some(b"8192".as_slice()),
            "the floor bank declares the Login default, never less"
        );

        conn.feed(&read10_bhs(0, 2, 0x5454, 0), &[]);
        assert_eq!(
            run_once(
                &mut session,
                &mut conn,
                &mut work,
                &mut scratch,
                &mut target,
                &mut storage
            ),
            Outcome::Processed
        );
        let mut collected = Vec::new();
        while let Some((bhs, data)) = conn.take_pdu() {
            if bhs[0] & 0x3F == op::SCSI_DATA_IN {
                collected.extend_from_slice(&data);
            }
        }
        assert_eq!(collected, expected, "the read is byte-exact");
    }

    /// A bank larger than the cap still declares 8192: the Login Response value
    /// is the protocol maximum, never the caller's buffer size.
    #[test]
    fn a_large_bank_keeps_the_8192_declaration() {
        let mut ram = vec![0u8; 16 * 1024];
        let mut backend = RamBackend::new(&mut ram);
        let mut slots = [TestLu::block(32768, 512, 0)];
        let mut table: Vec<&mut dyn Lu<Pair = TestPair>> = slots
            .iter_mut()
            .map(|s| s as &mut dyn Lu<Pair = TestPair>)
            .collect();
        let mut target = Target::new(&mut table[..]);
        let mut storage = PlaneSet::new(vec![Some(StorePlane::BlockRw(&mut backend))]);
        let mut conn = MockConn::new();
        let mut session = IscsiSession::default();
        let mut work = vec![0u8; 1024 * 1024 + BHS_SIZE];
        let mut scratch = vec![0u8; MIN_DATA_LEN];

        let text = REQ_TEXT.as_bytes();
        conn.feed_padded(&login_bhs(text.len() as u32), text);
        assert_eq!(
            run_once(
                &mut session,
                &mut conn,
                &mut work,
                &mut scratch,
                &mut target,
                &mut storage
            ),
            Outcome::Processed
        );
        let (bhs, data) = conn.take_pdu().expect("login response");
        assert_eq!(bhs[0] & 0x3F, op::LOGIN_RESP);
        assert_eq!(
            resp_value(&data, "MaxRecvDataSegmentLength"),
            Some(b"8192".as_slice()),
            "the declaration is capped at 8192 regardless of the bank size"
        );
    }

    #[test]
    fn data_out_above_our_recv_segment_is_rejected() {
        let mut ram = vec![0u8; 16 * 1024];
        let mut backend = RamBackend::new(&mut ram);
        let mut slots = [TestLu::block(32768, 512, 0)];
        let mut table: Vec<&mut dyn Lu<Pair = TestPair>> = slots
            .iter_mut()
            .map(|s| s as &mut dyn Lu<Pair = TestPair>)
            .collect();
        let mut target = Target::new(&mut table[..]);
        let mut storage = PlaneSet::new(vec![Some(StorePlane::BlockRw(&mut backend))]);
        let mut conn = MockConn::new();
        let mut session = IscsiSession::default();
        let mut work = vec![0u8; 384 * 1024];
        let mut scratch = vec![0u8; MIN_DATA_LEN];
        login!(conn, session, work, scratch, target, storage);

        let itt = 0xD400_0001;
        let cmd = write10_bhs(0, 32, itt, 0, 0);
        conn.feed_padded(&cmd, &[]);
        // The big bank lets 16 KiB segments be framed, but our declared
        // receive segment is 8192: one byte above it is a protocol error.
        let oversized = vec![0x33u8; 8193];
        let dout = dataout_bhs(itt, 1, 0, 0, 8193);
        conn.feed_padded(&dout, &oversized);
        assert_eq!(
            run_once(
                &mut session,
                &mut conn,
                &mut work,
                &mut scratch,
                &mut target,
                &mut storage
            ),
            Outcome::Closed
        );
        let (r2t, _) = conn.take_pdu().expect("R2T before the offending PDU");
        assert_eq!(r2t[0] & 0x3F, op::R2T);
        let (reject, _) = conn.take_pdu().expect("reject for the oversized segment");
        assert_eq!(reject[0] & 0x3F, op::REJECT);
        assert_eq!(reject[2], reject::PROTOCOL_ERROR);
    }

    #[test]
    fn nop_in_echo_is_limited_by_the_peer_receive_segment() {
        let mut ram = vec![0u8; 16 * 1024];
        block_fixture!(
            ram, backend, 32768, work, scratch, slots, table, conn, session, target, storage
        );

        let mut text = String::from(REQ_TEXT);
        let key = "MaxRecvDataSegmentLength=";
        let start = text.find(key).unwrap() + key.len();
        let end = text[start..].find('\0').unwrap() + start;
        text.replace_range(start..end, "512");
        conn.feed_padded(&login_bhs(text.len() as u32), text.as_bytes());
        assert_eq!(
            run_once(
                &mut session,
                &mut conn,
                &mut work,
                &mut scratch,
                &mut target,
                &mut storage
            ),
            Outcome::Processed
        );
        conn.take_pdu().expect("login response");

        // 2048 bytes of ping data, four times what the peer can receive.
        let payload: Vec<u8> = (0..2048).map(|i| (i % 251) as u8).collect();
        let mut nop = [0u8; 48];
        nop[0] = op::NOP_OUT;
        nop[5] = (payload.len() >> 16) as u8;
        nop[6] = (payload.len() >> 8) as u8;
        nop[7] = payload.len() as u8;
        nop[16..20].copy_from_slice(&be32(0xABCD));
        nop[20..24].copy_from_slice(&be32(0xFFFF_FFFF));
        conn.feed_padded(&nop, &payload);
        assert_eq!(
            run_once(
                &mut session,
                &mut conn,
                &mut work,
                &mut scratch,
                &mut target,
                &mut storage
            ),
            Outcome::Processed
        );
        let (bhs, data) = conn.take_pdu().expect("NOP-In response");
        assert_eq!(bhs[0] & 0x3F, op::NOP_IN);
        assert_eq!(
            u32::from_be_bytes([bhs[4], bhs[5], bhs[6], bhs[7]]),
            512,
            "the echo is exactly the peer's declared segment"
        );
        assert_eq!(data, payload[..512].to_vec());
    }

    #[test]
    fn nop_out_above_our_recv_segment_is_rejected() {
        let mut ram = vec![0u8; 16 * 1024];
        block_fixture!(
            ram, backend, 32768, work, scratch, slots, table, conn, session, target, storage
        );
        login!(conn, session, work, scratch, target, storage);

        let payload = vec![0x5Au8; 8193];
        let mut nop = [0u8; 48];
        nop[0] = op::NOP_OUT;
        nop[5] = (payload.len() >> 16) as u8;
        nop[6] = (payload.len() >> 8) as u8;
        nop[7] = payload.len() as u8;
        nop[16..20].copy_from_slice(&be32(0xBCDE));
        nop[20..24].copy_from_slice(&be32(0xFFFF_FFFF));
        conn.feed_padded(&nop, &payload);
        assert_eq!(
            run_once(
                &mut session,
                &mut conn,
                &mut work,
                &mut scratch,
                &mut target,
                &mut storage
            ),
            Outcome::Closed
        );
        let (reject_bhs, rejected) = conn.take_pdu().expect("reject for the oversized NOP");
        assert_eq!(reject_bhs[0] & 0x3F, op::REJECT);
        assert_eq!(reject_bhs[2], reject::PROTOCOL_ERROR);
        assert_eq!(rejected, nop.to_vec());
    }

    #[test]
    fn text_request_above_our_recv_segment_is_rejected() {
        let mut ram = vec![0u8; 16 * 1024];
        block_fixture!(
            ram, backend, 32768, work, scratch, slots, table, conn, session, target, storage
        );
        login!(conn, session, work, scratch, target, storage);

        let mut payload = b"SendTargets=All\0".to_vec();
        payload.resize(8193, 0);
        let mut txt = [0u8; 48];
        txt[0] = op::TEXT_REQ;
        txt[1] = flag::F_BIT;
        txt[5] = (payload.len() >> 16) as u8;
        txt[6] = (payload.len() >> 8) as u8;
        txt[7] = payload.len() as u8;
        txt[16..20].copy_from_slice(&be32(0x3456));
        txt[20..24].copy_from_slice(&be32(0xFFFF_FFFF));
        txt[24..28].copy_from_slice(&be32(1));
        conn.feed_padded(&txt, &payload);
        assert_eq!(
            run_once(
                &mut session,
                &mut conn,
                &mut work,
                &mut scratch,
                &mut target,
                &mut storage
            ),
            Outcome::Closed
        );
        let (reject_bhs, rejected) = conn.take_pdu().expect("reject for the oversized text");
        assert_eq!(reject_bhs[0] & 0x3F, op::REJECT);
        assert_eq!(reject_bhs[2], reject::PROTOCOL_ERROR);
        assert_eq!(rejected, txt.to_vec());
    }

    #[test]
    fn immediate_write_above_our_recv_segment_is_rejected() {
        let mut ram = vec![0u8; 16 * 1024];
        let mut backend = RamBackend::new(&mut ram);
        let mut slots = [TestLu::block(32768, 512, 0)];
        let mut table: Vec<&mut dyn Lu<Pair = TestPair>> = slots
            .iter_mut()
            .map(|s| s as &mut dyn Lu<Pair = TestPair>)
            .collect();
        let mut target = Target::new(&mut table[..]);
        let mut storage = PlaneSet::new(vec![Some(StorePlane::BlockRw(&mut backend))]);
        let mut conn = MockConn::new();
        let mut session = IscsiSession::default();
        let mut work = vec![0u8; 384 * 1024];
        let mut scratch = vec![0u8; MIN_DATA_LEN];
        login!(conn, session, work, scratch, target, storage);

        let payload = vec![0x77u8; 8193];
        let cmd = write10_bhs(0, 17, 0xE400_0001, 0, payload.len() as u32);
        conn.feed_padded(&cmd, &payload);
        assert_eq!(
            run_once(
                &mut session,
                &mut conn,
                &mut work,
                &mut scratch,
                &mut target,
                &mut storage
            ),
            Outcome::Closed
        );
        let (reject_bhs, rejected) = conn.take_pdu().expect("reject for the oversized command");
        assert_eq!(reject_bhs[0] & 0x3F, op::REJECT);
        assert_eq!(reject_bhs[2], reject::PROTOCOL_ERROR);
        assert_eq!(rejected, cmd.to_vec());
    }

    #[test]
    fn immediate_write_above_first_burst_length_is_rejected() {
        let mut ram = vec![0u8; 16 * 1024];
        block_fixture!(
            ram, backend, 32768, work, scratch, slots, table, conn, session, target, storage
        );

        let mut text = String::from(REQ_TEXT);
        let key = "FirstBurstLength=";
        let start = text.find(key).unwrap() + key.len();
        let end = text[start..].find('\0').unwrap() + start;
        text.replace_range(start..end, "512");
        conn.feed_padded(&login_bhs(text.len() as u32), text.as_bytes());
        assert_eq!(
            run_once(
                &mut session,
                &mut conn,
                &mut work,
                &mut scratch,
                &mut target,
                &mut storage
            ),
            Outcome::Processed
        );
        let (login_bhs, login_data) = conn.take_pdu().expect("login response");
        assert_eq!(login_bhs[0] & 0x3F, op::LOGIN_RESP);
        assert_eq!(
            resp_value(&login_data, "FirstBurstLength"),
            Some(b"512".as_slice())
        );

        // 1024 bytes of immediate data, twice FirstBurstLength.
        let payload = vec![0x99u8; 1024];
        let cmd = write10_bhs(0, 2, 0xE500_0001, 0, payload.len() as u32);
        conn.feed_padded(&cmd, &payload);
        assert_eq!(
            run_once(
                &mut session,
                &mut conn,
                &mut work,
                &mut scratch,
                &mut target,
                &mut storage
            ),
            Outcome::Closed
        );
        let (reject_bhs, rejected) = conn.take_pdu().expect("reject for the unsolicited burst");
        assert_eq!(reject_bhs[0] & 0x3F, op::REJECT);
        assert_eq!(reject_bhs[2], reject::PROTOCOL_ERROR);
        assert_eq!(rejected, cmd.to_vec());
    }

    #[test]
    fn immediate_data_without_negotiation_is_rejected() {
        let mut ram = vec![0u8; 16 * 1024];
        block_fixture!(
            ram, backend, 32768, work, scratch, slots, table, conn, session, target, storage
        );

        let text = REQ_TEXT.replace("ImmediateData=Yes", "ImmediateData=No");
        conn.feed_padded(&login_bhs(text.len() as u32), text.as_bytes());
        assert_eq!(
            run_once(
                &mut session,
                &mut conn,
                &mut work,
                &mut scratch,
                &mut target,
                &mut storage
            ),
            Outcome::Processed
        );
        let (login_bhs, _) = conn.take_pdu().expect("login response");
        assert_eq!(login_bhs[0] & 0x3F, op::LOGIN_RESP);

        // ImmediateData=No forbids data in the command PDU.
        let payload = vec![0x5Au8; 512];
        let cmd = write10_bhs(0, 1, 0xE600_0001, 0, payload.len() as u32);
        conn.feed_padded(&cmd, &payload);
        assert_eq!(
            run_once(
                &mut session,
                &mut conn,
                &mut work,
                &mut scratch,
                &mut target,
                &mut storage
            ),
            Outcome::Closed
        );
        let (reject_bhs, rejected) = conn.take_pdu().expect("reject for immediate data");
        assert_eq!(reject_bhs[0] & 0x3F, op::REJECT);
        assert_eq!(reject_bhs[2], reject::PROTOCOL_ERROR);
        assert_eq!(rejected, cmd.to_vec());
    }

    #[test]
    fn first_burst_offer_is_clamped_before_max_burst_is_seen() {
        let mut ram = vec![0u8; 16 * 1024];
        block_fixture!(
            ram, backend, 32768, work, scratch, slots, table, conn, session, target, storage
        );

        // FirstBurstLength precedes MaxBurstLength, so the clamp can only use
        // the pre-scanned burst limit.
        let text = REQ_TEXT.replace(
            "MaxBurstLength=16776192\0FirstBurstLength=262144",
            "FirstBurstLength=1024\0MaxBurstLength=512",
        );
        conn.feed_padded(&login_bhs(text.len() as u32), text.as_bytes());
        assert_eq!(
            run_once(
                &mut session,
                &mut conn,
                &mut work,
                &mut scratch,
                &mut target,
                &mut storage
            ),
            Outcome::Processed
        );
        let (login_bhs, login_data) = conn.take_pdu().expect("login response");
        assert_eq!(login_bhs[0] & 0x3F, op::LOGIN_RESP);
        assert_eq!(
            resp_value(&login_data, "FirstBurstLength"),
            Some(b"512".as_slice())
        );
        assert_eq!(
            resp_value(&login_data, "MaxBurstLength"),
            Some(b"512".as_slice())
        );
    }

    #[test]
    fn login_request_above_our_recv_segment_is_rejected_with_a_login_status() {
        let mut ram = vec![0u8; 16 * 1024];
        block_fixture!(
            ram, backend, 32768, work, scratch, slots, table, conn, session, target, storage
        );

        let payload = vec![0x41u8; 8193];
        conn.feed_padded(&login_bhs(payload.len() as u32), &payload);
        assert_eq!(
            run_once(
                &mut session,
                &mut conn,
                &mut work,
                &mut scratch,
                &mut target,
                &mut storage
            ),
            Outcome::Closed
        );
        let (bhs, data) = conn.take_pdu().expect("login error response");
        assert_eq!(bhs[0] & 0x3F, op::LOGIN_RESP);
        assert_eq!(bhs[36], 0x02, "Initiator Error");
        assert_eq!(bhs[37], 0x0B, "invalid during login");
        assert_eq!(
            u32::from_be_bytes([bhs[4], bhs[5], bhs[6], bhs[7]]),
            0,
            "a login error carries no parameters"
        );
        assert!(data.is_empty());
    }

    #[test]
    fn login_response_stays_within_the_receive_segment() {
        let mut ram = vec![0u8; 16 * 1024];
        let mut backend = RamBackend::new(&mut ram);
        let mut slots = [TestLu::block(32768, 512, 0)];
        let mut table: Vec<&mut dyn Lu<Pair = TestPair>> = slots
            .iter_mut()
            .map(|s| s as &mut dyn Lu<Pair = TestPair>)
            .collect();
        let mut target = Target::new(&mut table[..]);
        let mut storage = PlaneSet::new(vec![Some(StorePlane::BlockRw(&mut backend))]);
        let mut conn = MockConn::new();
        let mut session = IscsiSession::default();
        let mut work = vec![0u8; 384 * 1024];
        let mut scratch = vec![0u8; MIN_DATA_LEN];

        // Short unknown keys expand when answered, so this response would be
        // far larger than one receive segment without a bound.
        let mut text = String::new();
        for _ in 0..2000 {
            text.push_str("a=\0");
        }
        conn.feed_padded(&login_bhs(text.len() as u32), text.as_bytes());
        assert_eq!(
            run_once(
                &mut session,
                &mut conn,
                &mut work,
                &mut scratch,
                &mut target,
                &mut storage
            ),
            Outcome::Processed
        );
        let (bhs, data) = conn.take_pdu().expect("login response");
        assert_eq!(bhs[0] & 0x3F, op::LOGIN_RESP);
        assert_eq!(bhs[36], 0x00);
        assert_eq!(
            u32::from_be_bytes([bhs[4], bhs[5], bhs[6], bhs[7]]) as usize,
            data.len()
        );
        assert!(
            data.len() <= 8192,
            "a login response never exceeds the receive segment"
        );
        assert_eq!(
            data.last(),
            Some(&0),
            "the response ends on an entry boundary"
        );
        assert!(
            data.windows(16).any(|w| w == b"a=NotUnderstood\0"),
            "keys that do not fit are answered as not understood"
        );
    }

    #[test]
    fn oversized_transfer_streams_in_bank_sized_chunks_and_keeps_the_session() {
        // `WORK_LEN` leaves an 8192-byte SCSI data area.
        let mut ram = vec![0u8; 16 * 1024];
        for (i, b) in ram.iter_mut().enumerate() {
            *b = (i % 251) as u8;
        }
        let expected = ram[..16384].to_vec();
        block_fixture!(
            ram, backend, 32768, work, scratch, slots, table, conn, session, target, storage
        );
        login!(conn, session, work, scratch, target, storage);

        // 32 blocks x 512 = 16384 bytes, twice the bank.
        conn.feed(&read10_bhs(0, 32, 0x8101, 0), &[]);
        assert_eq!(
            run_once(
                &mut session,
                &mut conn,
                &mut work,
                &mut scratch,
                &mut target,
                &mut storage
            ),
            Outcome::Processed
        );
        let mut pdus = Vec::new();
        while let Some(pdu) = conn.take_pdu() {
            pdus.push(pdu);
        }
        let data_in: Vec<_> = pdus
            .iter()
            .filter(|(bhs, _)| bhs[0] & 0x3F == op::SCSI_DATA_IN)
            .collect();
        assert_eq!(data_in.len(), 2, "one Data-In PDU per bank-sized chunk");
        let mut offset = 0u32;
        let mut total = Vec::new();
        for (index, (bhs, data)) in data_in.iter().enumerate() {
            let bo = u32::from_be_bytes([bhs[40], bhs[41], bhs[42], bhs[43]]);
            let dsn = u32::from_be_bytes([bhs[36], bhs[37], bhs[38], bhs[39]]);
            assert_eq!(bo, offset, "contiguous BufferOffset");
            assert_eq!(dsn, index as u32, "contiguous DataSN");
            if index + 1 == data_in.len() {
                assert_ne!(bhs[1] & flag::F_BIT, 0, "F only on the final PDU");
                assert_ne!(bhs[1] & flag::S_BIT, 0, "the final PDU carries status");
                assert_eq!(bhs[3], status::GOOD);
            } else {
                assert_eq!(bhs[1] & flag::F_BIT, 0, "intermediate PDU is not final");
            }
            offset += data.len() as u32;
            total.extend_from_slice(data);
        }
        assert_eq!(
            total, expected,
            "the whole transfer is delivered byte-exactly"
        );

        // The connection stays usable for the next command.
        conn.feed(&inquiry_bhs(0, 96, 0x8102, 1), &[]);
        assert_eq!(
            run_once(
                &mut session,
                &mut conn,
                &mut work,
                &mut scratch,
                &mut target,
                &mut storage
            ),
            Outcome::Processed
        );
        let (bhs, data) = conn.take_pdu().unwrap();
        assert_eq!(bhs[0] & 0x3F, op::SCSI_DATA_IN);
        assert_eq!(bhs[3], status::GOOD);
        assert_eq!(data[0], 0x00, "block PDT after the streamed READ");
    }

    // ── Undersized caller banks are caller bugs, not wire errors ──

    #[test]
    fn delivery_is_pending_until_the_status_pdu_is_on_the_wire() {
        use snowscsi::core::storage::HostTransport as _;

        let mut ram = vec![0u8; 16 * 1024];
        block_fixture!(
            ram, backend, 32, work, scratch, slots, table, conn, session, target, storage
        );
        login!(conn, session, work, scratch, target, storage);

        conn.feed(&tur_bhs(0x9101, 0), &[]);
        assert!(matches!(
            session.poll(
                Event::Tick,
                &mut work,
                &mut scratch,
                &mut target,
                &mut storage
            ),
            Action::HostRecv {
                offset: 0,
                len: BHS_SIZE
            }
        ));

        let mut got = 0usize;
        while got < BHS_SIZE {
            match conn.read(&mut work[got..BHS_SIZE]) {
                Ok(0) => panic!("script ended before the command BHS"),
                Ok(n) => got += n,
                Err(_) => panic!("script read failed"),
            }
        }

        // The completion is fixed and its status PDU is staged, but nothing
        // has been observed on the wire yet.
        assert!(matches!(
            session.poll(
                Event::HostRecv { len: BHS_SIZE },
                &mut work,
                &mut scratch,
                &mut target,
                &mut storage
            ),
            Action::HostSend { .. }
        ));
        assert_eq!(session.delivery(), Delivery::Pending);

        assert!(matches!(
            session.poll(
                Event::HostSent,
                &mut work,
                &mut scratch,
                &mut target,
                &mut storage
            ),
            Action::HostRecv { .. }
        ));
        assert_eq!(session.delivery(), Delivery::Complete);

        // A peer/transport failure while the next status PDU is still staged
        // books Failed instead of claiming delivery.
        conn.feed(&tur_bhs(0x9102, 1), &[]);
        assert!(matches!(
            session.poll(
                Event::Tick,
                &mut work,
                &mut scratch,
                &mut target,
                &mut storage
            ),
            Action::HostRecv {
                offset: 0,
                len: BHS_SIZE
            }
        ));
        got = 0;
        while got < BHS_SIZE {
            match conn.read(&mut work[got..BHS_SIZE]) {
                Ok(0) => panic!("script ended before the second command BHS"),
                Ok(n) => got += n,
                Err(_) => panic!("script read failed"),
            }
        }
        assert!(matches!(
            session.poll(
                Event::HostRecv { len: BHS_SIZE },
                &mut work,
                &mut scratch,
                &mut target,
                &mut storage
            ),
            Action::HostSend { .. }
        ));
        assert_eq!(session.delivery(), Delivery::Pending);
        session.connection_lost();
        assert_eq!(session.delivery(), Delivery::Failed);
    }

    #[test]
    fn undersized_banks_are_rejected_before_any_wire_io() {
        let mut ram = vec![0u8; 16 * 1024];
        let mut backend = RamBackend::new(&mut ram);
        let mut slots = [TestLu::block(32, 512, 0)];
        let mut table: Vec<&mut dyn Lu<Pair = TestPair>> = slots
            .iter_mut()
            .map(|s| s as &mut dyn Lu<Pair = TestPair>)
            .collect();
        let mut target = Target::new(&mut table[..]);
        let mut storage = PlaneSet::new(vec![Some(StorePlane::BlockRw(&mut backend))]);
        let mut session = IscsiSession::default();
        let mut work = vec![0u8; WORK_LEN];
        let mut scratch = vec![0u8; MIN_DATA_LEN];

        // The data area must be `MIN_DATA_LEN` plus the BHS: a smaller bank
        // cannot stage a Login Request carrying the default
        // `MaxRecvDataSegmentLength` bytes of text (RFC 3720 §6.1).
        let mut short_work = vec![0u8; MIN_DATA_LEN + BHS_SIZE - 1];
        assert!(matches!(
            session.poll(
                Event::Tick,
                &mut short_work,
                &mut scratch,
                &mut target,
                &mut storage
            ),
            Action::Error(TargetError::WorkBufTooSmall)
        ));

        // A non-4-aligned data area is rejected before any PDU is framed
        // instead of relying on the padding invariant. 8241 - 48 = 8193, the
        // bank whose 1-byte tail used to be rounded up to a 4-byte staging
        // window and read past the end.
        let mut misaligned_work = vec![0u8; MIN_DATA_LEN + BHS_SIZE + 1];
        assert!(matches!(
            session.poll(
                Event::Tick,
                &mut misaligned_work,
                &mut scratch,
                &mut target,
                &mut storage
            ),
            Action::Error(TargetError::WorkBufTooSmall)
        ));

        // The long-operation bank must hold `MIN_DATA_LEN`.
        let mut short_scratch = vec![0u8; MIN_DATA_LEN - 1];
        assert!(matches!(
            session.poll(
                Event::Tick,
                &mut work,
                &mut short_scratch,
                &mut target,
                &mut storage
            ),
            Action::Error(TargetError::WorkBufTooSmall)
        ));

        // A valid pair of banks still starts the login.
        assert!(matches!(
            session.poll(
                Event::Tick,
                &mut work,
                &mut scratch,
                &mut target,
                &mut storage
            ),
            Action::HostRecv {
                offset: 0,
                len: BHS_SIZE
            }
        ));
    }

    // ── Abort settles the active command with 0B/45/00 ─────────────

    #[test]
    fn abort_task_settles_the_active_command_with_aborted_command() {
        use snowscsi::iscsi::transport::serve_conn;

        let mut ram = vec![0u8; 16 * 1024];
        let mut backend = RamBackend::new(&mut ram);
        let mut slots = [TestLu::block(32, 512, 0)];
        let mut table: Vec<&mut dyn Lu<Pair = TestPair>> = slots
            .iter_mut()
            .map(|s| s as &mut dyn Lu<Pair = TestPair>)
            .collect();
        let mut target = Target::new(&mut table[..]);
        let mut storage = PlaneSet::new(vec![Some(StorePlane::BlockRw(&mut backend))]);
        let mut conn = MockConn::new();
        let mut session = IscsiSession::default();
        let mut work = vec![0u8; WORK_LEN];
        let mut scratch = vec![0u8; MIN_DATA_LEN];

        let text = REQ_TEXT.as_bytes();
        conn.feed_padded(&login_bhs(text.len() as u32), text);

        // A WRITE that waits for Data-Out (the R2T is sent, then nothing).
        let itt = 0x0B0B;
        conn.feed(&write10_bhs(0, 1, itt, 0, 0), &[]);
        // ABORT TASK (immediate, so it bypasses the CmdSN window).
        let mut tmf = [0u8; 48];
        tmf[0] = op::SCSI_TASK_REQ | 0x40;
        tmf[1] = 0x80 | tmf::ABORT_TASK;
        tmf[16..20].copy_from_slice(&be32(0x0B0B));
        conn.feed(&tmf, &[]);

        assert!(serve_conn(
            &mut conn,
            &mut work,
            &mut scratch,
            &mut session,
            &mut target,
            &mut storage
        )
        .is_ok());

        let mut pdus = Vec::new();
        while let Some(p) = conn.take_pdu() {
            pdus.push(p);
        }
        assert_eq!(pdus[0].0[0] & 0x3F, op::LOGIN_RESP);
        assert_eq!(pdus[1].0[0] & 0x3F, op::R2T);
        let tmf_resp = pdus
            .iter()
            .find(|(b, _)| b[0] & 0x3F == op::SCSI_TASK_RESP)
            .expect("TMF response");
        assert_eq!(tmf_resp.0[2], tmf_response::COMPLETE);
        let aborted = pdus
            .iter()
            .find(|(b, _)| b[0] & 0x3F == op::SCSI_RESP)
            .expect("aborted command response");
        assert_eq!(aborted.0[3], status::CHECK_CONDITION);
        assert_eq!(&aborted.0[16..20], &be32(itt));
        assert_eq!(&aborted.1[0..2], &[0x00, 18]);
        assert_eq!(aborted.1[2], 0x70);
        assert_eq!(aborted.1[4], 0x0B, "sense key ABORTED COMMAND");
        assert_eq!(aborted.1[14], 0x45, "ASC ABORTED COMMAND");
        assert_eq!(aborted.1[15], 0x00, "ASCQ");
    }

    // ── Transport loss settles the active command ──────────────────

    #[test]
    fn abort_does_not_consume_a_sense_that_survived_a_failed_status_send() {
        use snowscsi::iscsi::transport::serve_conn;

        /// Wire double that reports a failed write for the first CHECK
        /// CONDITION status PDU: the host never receives it.
        struct DropCheckStatus {
            inner: MockConn,
            dropped: bool,
        }

        impl embedded_io::ErrorType for DropCheckStatus {
            type Error = core::convert::Infallible;
        }

        impl embedded_io::Read for DropCheckStatus {
            fn read(&mut self, buf: &mut [u8]) -> Result<usize, Self::Error> {
                embedded_io::Read::read(&mut self.inner, buf)
            }
        }

        impl embedded_io::Write for DropCheckStatus {
            fn write(&mut self, buf: &[u8]) -> Result<usize, Self::Error> {
                if !self.dropped
                    && buf.len() >= BHS_SIZE
                    && buf[0] & 0x3F == op::SCSI_RESP
                    && buf[3] == status::CHECK_CONDITION
                {
                    self.dropped = true;
                    return Ok(0);
                }
                embedded_io::Write::write(&mut self.inner, buf)
            }

            fn flush(&mut self) -> Result<(), Self::Error> {
                embedded_io::Write::flush(&mut self.inner)
            }
        }

        let mut ram = vec![0u8; 16 * 1024];
        let mut backend = RamBackend::new(&mut ram);
        let mut slots = [TestLu::block(32, 512, 0)];
        let mut table: Vec<&mut dyn Lu<Pair = TestPair>> = slots
            .iter_mut()
            .map(|s| s as &mut dyn Lu<Pair = TestPair>)
            .collect();
        let mut storage = PlaneSet::new(vec![Some(StorePlane::BlockRw(&mut backend))]);
        let mut work = vec![0u8; WORK_LEN];
        let mut scratch = vec![0u8; MIN_DATA_LEN];

        // 1. The device CHECKs and its status PDU never reaches the host, so
        //    the saved sense stays resident on the slot.
        {
            let mut target = Target::new(&mut table[..]);
            let mut session = IscsiSession::default();
            let mut conn = DropCheckStatus {
                inner: MockConn::new(),
                dropped: false,
            };
            let text = REQ_TEXT.as_bytes();
            conn.inner.feed_padded(&login_bhs(text.len() as u32), text);
            conn.inner.feed(&read10_bhs(1 << 20, 1, 0x0C0A, 0), &[]);
            assert!(serve_conn(
                &mut conn,
                &mut work,
                &mut scratch,
                &mut session,
                &mut target,
                &mut storage,
            )
            .is_ok());
            assert!(conn.dropped, "the CHECK CONDITION status write failed");
        }

        // 2. Same slots: abort a later command. The runner-fabricated
        //    0B/45/00 completion must not consume the resident sense.
        let mut target = Target::new(&mut table[..]);
        let mut session = IscsiSession::default();
        let mut conn = MockConn::new();
        let text = REQ_TEXT.as_bytes();
        conn.feed_padded(&login_bhs(text.len() as u32), text);
        // No immediate data: the target sends R2T and the command stays live.
        conn.feed(&write10_bhs(0, 1, 0x0C0B, 0, 0), &[]);
        let mut tmf = [0u8; 48];
        tmf[0] = op::SCSI_TASK_REQ | 0x40;
        tmf[1] = 0x80 | tmf::ABORT_TASK;
        tmf[16..20].copy_from_slice(&be32(0x0C0B));
        conn.feed(&tmf, &[]);
        conn.feed(&request_sense_bhs(18, 0x0C0C, 1), &[]);
        assert!(serve_conn(
            &mut conn,
            &mut work,
            &mut scratch,
            &mut session,
            &mut target,
            &mut storage,
        )
        .is_ok());

        let mut pdus = Vec::new();
        while let Some(p) = conn.take_pdu() {
            pdus.push(p);
        }
        let aborted = pdus
            .iter()
            .find(|(b, _)| b[0] & 0x3F == op::SCSI_RESP && b[3] == status::CHECK_CONDITION)
            .expect("aborted command response");
        assert_eq!(&aborted.0[16..20], &be32(0x0C0B));
        assert_eq!(&aborted.1[0..2], &[0x00, 18]);
        assert_eq!(aborted.1[2], 0x70);
        assert_eq!(aborted.1[4], 0x0B, "sense key ABORTED COMMAND");
        assert_eq!(aborted.1[14], 0x45, "ASC ABORTED COMMAND");
        assert_eq!(aborted.1[15], 0x00, "ASCQ");

        // The saved ILLEGAL REQUEST / LBA OUT OF RANGE sense was never
        // delivered, so REQUEST SENSE still reports it.
        let sense_in = pdus
            .iter()
            .find(|(b, _)| b[0] & 0x3F == op::SCSI_DATA_IN)
            .expect("REQUEST SENSE Data-In");
        assert_eq!(&sense_in.0[16..20], &be32(0x0C0C));
        assert_eq!(sense_in.1[0], 0x70);
        assert_eq!(sense_in.1[2], 0x05, "ILLEGAL REQUEST survives the abort");
        assert_eq!(sense_in.1[12], 0x21, "ASC LBA OUT OF RANGE");
        assert_eq!(sense_in.1[13], 0x00);
    }

    // ── Transport loss settles the active command ──────────────────

    #[test]
    fn transport_loss_settles_the_active_command_for_the_next_connection() {
        use snowscsi::iscsi::transport::serve_conn;

        let mut ram = vec![0u8; 16 * 1024];
        let mut backend = RamBackend::new(&mut ram);
        let mut slots = [TestLu::block(32, 512, 0)];
        let mut table: Vec<&mut dyn Lu<Pair = TestPair>> = slots
            .iter_mut()
            .map(|s| s as &mut dyn Lu<Pair = TestPair>)
            .collect();
        let mut storage = PlaneSet::new(vec![Some(StorePlane::BlockRw(&mut backend))]);
        let mut work = vec![0u8; WORK_LEN];
        let mut scratch = vec![0u8; MIN_DATA_LEN];

        let itt = 0x0707;
        {
            let mut target = Target::new(&mut table[..]);
            let mut session = IscsiSession::default();
            let mut conn = MockConn::new();
            let text = REQ_TEXT.as_bytes();
            conn.feed_padded(&login_bhs(text.len() as u32), text);
            // No immediate data: the target sends R2T and waits for Data-Out.
            // The scripted connection then hits EOF.
            conn.feed(&write10_bhs(0, 1, itt, 0, 0), &[]);
            assert!(serve_conn(
                &mut conn,
                &mut work,
                &mut scratch,
                &mut session,
                &mut target,
                &mut storage,
            )
            .is_ok());
        }
        assert!(
            !table[0].active(),
            "transport loss must settle the live command on the slot"
        );

        // Same slots, fresh target and session: the LUN is usable again.
        let mut target = Target::new(&mut table[..]);
        let mut session = IscsiSession::default();
        let mut conn = MockConn::new();
        let text = REQ_TEXT.as_bytes();
        conn.feed_padded(&login_bhs(text.len() as u32), text);
        conn.feed(&tur_bhs(0x0708, 0), &[]);
        assert_eq!(
            run_once(
                &mut session,
                &mut conn,
                &mut work,
                &mut scratch,
                &mut target,
                &mut storage
            ),
            Outcome::Processed
        );
        let mut pdus = Vec::new();
        while let Some(p) = conn.take_pdu() {
            pdus.push(p);
        }
        let tur = pdus
            .iter()
            .find(|(bhs, _)| bhs[0] & 0x3F == op::SCSI_RESP)
            .expect("TUR response");
        assert_eq!(tur.0[3], status::GOOD, "TUR after settlement must be GOOD");
        assert_eq!(&tur.0[16..20], &be32(0x0708));

        // A following WRITE completes instead of answering BUSY.
        conn.feed(&write10_bhs(0, 1, 0x0709, 1, 512), &vec![0xA5; 512]);
        assert_eq!(
            run_once(
                &mut session,
                &mut conn,
                &mut work,
                &mut scratch,
                &mut target,
                &mut storage
            ),
            Outcome::Processed
        );
        let (bhs, _) = conn.take_pdu().expect("WRITE response");
        assert_eq!(bhs[0] & 0x3F, op::SCSI_RESP);
        assert_eq!(bhs[3], status::GOOD);
    }

    // ── A failed autosense send keeps the saved sense ──────────────

    #[test]
    fn failed_status_send_keeps_the_sense_for_the_next_request_sense() {
        use snowscsi::core::storage::HostTransport;
        use snowscsi::iscsi::transport::serve_conn;

        let mut ram = vec![0u8; 16 * 1024];
        let mut backend = RamBackend::new(&mut ram);
        let mut slots = [TestLu::block(32, 512, 0)];
        let mut table: Vec<&mut dyn Lu<Pair = TestPair>> = slots
            .iter_mut()
            .map(|s| s as &mut dyn Lu<Pair = TestPair>)
            .collect();
        let mut storage = PlaneSet::new(vec![Some(StorePlane::BlockRw(&mut backend))]);
        let mut work = vec![0u8; WORK_LEN];
        let mut scratch = vec![0u8; MIN_DATA_LEN];

        {
            let mut target = Target::new(&mut table[..]);
            let mut session = IscsiSession::default();
            let mut conn = StatusDropConn::new();
            let text = REQ_TEXT.as_bytes();
            conn.feed_padded(&login_bhs(text.len() as u32), text);
            // Out-of-range READ: the status is CHECK CONDITION with autosense,
            // whose write the connection drops.
            conn.feed(&read10_bhs(1 << 20, 1, 0x0808, 0), &[]);
            assert!(serve_conn(
                &mut conn,
                &mut work,
                &mut scratch,
                &mut session,
                &mut target,
                &mut storage,
            )
            .is_ok());
            assert_eq!(session.delivery(), Delivery::Failed);
        }

        // A fresh session asks for the sense over a new connection. The failed
        // status send must not have consumed the instance staged for it.
        let mut target = Target::new(&mut table[..]);
        let mut session = IscsiSession::default();
        let mut conn = MockConn::new();
        let text = REQ_TEXT.as_bytes();
        conn.feed_padded(&login_bhs(text.len() as u32), text);
        conn.feed(&request_sense_bhs(18, 0x0809, 0), &[]);
        assert_eq!(
            run_once(
                &mut session,
                &mut conn,
                &mut work,
                &mut scratch,
                &mut target,
                &mut storage
            ),
            Outcome::Processed
        );
        let mut pdus = Vec::new();
        while let Some(p) = conn.take_pdu() {
            pdus.push(p);
        }
        let sense_in = pdus
            .iter()
            .find(|(bhs, _)| bhs[0] & 0x3F == op::SCSI_DATA_IN)
            .expect("REQUEST SENSE Data-In");
        assert_eq!(sense_in.1.len(), 18, "allocation length 18");
        assert_eq!(sense_in.1[0], 0x70, "fixed-format sense response code");
        assert_eq!(sense_in.1[2], 0x05, "ILLEGAL REQUEST survives the failure");
        assert_eq!(sense_in.1[12], 0x21, "LBA OUT OF RANGE");
    }

    // ── A resident long operation is not starved by queries ────────

    #[test]
    fn resident_format_is_advanced_by_idle_entries_while_queries_are_answered() {
        let mut ram = vec![0xA5u8; 4 * 2048];
        let mut backend = RamBackend::new(&mut ram);
        let mut slots = [TestLu::dvdram(4, 0)];
        let mut table: Vec<&mut dyn Lu<Pair = TestPair>> = slots
            .iter_mut()
            .map(|s| s as &mut dyn Lu<Pair = TestPair>)
            .collect();
        let mut target = Target::new(&mut table[..]);
        let mut storage = PlaneSet::new(vec![Some(StorePlane::BlockRw(&mut backend))]);
        let mut conn = MockConn::new();
        let mut session = IscsiSession::default();
        let mut work = vec![0u8; WORK_LEN];
        let mut scratch = vec![0u8; MIN_DATA_LEN];
        login!(conn, session, work, scratch, target, storage);

        // BLANK with IMMED=1 starts the zero-fill and answers GOOD at once;
        // the fill stays resident for the idle entries.
        let mut blank = [0u8; 48];
        blank[0] = op::SCSI_CMD;
        blank[1] = 0x40; // task attribute (W=0: BLANK carries no data out)
        blank[16..20].copy_from_slice(&be32(0x0F0F));
        blank[24..28].copy_from_slice(&be32(0));
        blank[28..32].copy_from_slice(&be32(0));
        blank[32] = 0xA1; // BLANK
        blank[33] = 0x20; // CDB byte 1: IMMED=1
        conn.feed(&blank, &[]);
        assert_eq!(
            run_once(
                &mut session,
                &mut conn,
                &mut work,
                &mut scratch,
                &mut target,
                &mut storage
            ),
            Outcome::Processed
        );
        let (bhs, _) = conn.take_pdu().unwrap();
        assert_eq!(bhs[0] & 0x3F, op::SCSI_RESP);
        assert_eq!(bhs[3], status::GOOD);
        let info = target.snapshot_rt(0).expect("slot 0").long;
        assert_eq!(
            info.phase,
            snowscsi::core::LongPhase::Foreground,
            "IMMED=1 BLANK leaves a resident operation"
        );

        // Every following PDU is answered while the fill advances once per
        // idle entry.
        for (i, itt) in [0x1001u32, 0x1002, 0x1003, 0x1004].into_iter().enumerate() {
            conn.feed(&inquiry_bhs(0, 96, itt, i as u32 + 1), &[]);
            assert_eq!(
                run_once(
                    &mut session,
                    &mut conn,
                    &mut work,
                    &mut scratch,
                    &mut target,
                    &mut storage
                ),
                Outcome::Processed
            );
            let (bhs, data) = conn.take_pdu().unwrap();
            assert_eq!(bhs[0] & 0x3F, op::SCSI_DATA_IN, "query {i} answered");
            assert_eq!(data[0], 0x05, "MMC drive stays discoverable");
        }
        let info = target.snapshot_rt(0).expect("slot 0").long;
        assert!(
            matches!(info.phase, snowscsi::core::LongPhase::Settled),
            "the resident fill completed while queries were answered"
        );
        let mut check = vec![0u8; 4 * 2048];
        storage
            .exec_raw(StoreOp::Read {
                off: 0,
                buf: &mut check,
            })
            .unwrap();
        assert!(check.iter().all(|&b| b == 0));
    }
}
