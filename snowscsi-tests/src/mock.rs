//! Step-level iSCSI target integration tests (port of test_iscsi_mock.cpp
//! semantics). Deterministic, single thread: `MockConn` scripted byte stream
//! driven through the `poll`/`Action`/`Event` core by a test-local
//! single-transaction loop (the old `IscsiSession::step` is gone).

#[cfg(test)]
mod tests {
    use crate::mock_conn::MockConn;
    use embedded_io::Read as _;
    use snowscsi::common::seekable_storage::RamBackend;
    use snowscsi::common::store::{StoreOp, StorePlane};
    use snowscsi::iscsi::conn::write_all;
    use snowscsi::iscsi::pdu::{flag, op, reject, stage, status, tmf, tmf_response, BHS_SIZE};
    use snowscsi::iscsi::target::{Action, Event, IscsiSession, LoginStage, TargetError};
    use snowscsi::scsi::block::BlockDevice;
    use snowscsi::scsi::device::{ScsiDevice, Xfer};
    use snowscsi::scsi::Luns;
    use snowscsi::MIN_DATA_LEN;

    /// iSCSI target scratch buffer: BHS header + data area.
    const WORK_LEN: usize = MIN_DATA_LEN + BHS_SIZE;

    /// Outcome of one [`RunOnce::run_once`] transaction, mirroring the old
    /// `StepResult` semantics.
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

    /// Test-local single-transaction driver over the `poll`/`Action`/`Event`
    /// core (replaces the deleted `IscsiSession::step`).
    ///
    /// `MockConn` reports an empty `rx` as a 0-byte read; at a fresh PDU
    /// boundary that means "no more scripted input" and is reported as
    /// [`Outcome::Idle`] (or [`Outcome::Processed`] if this call already sent a
    /// response), matching the old `step` loop's `Idle`/`Processed` split.
    trait RunOnce {
        fn run_once<D: ScsiDevice>(
            &mut self,
            conn: &mut MockConn,
            work: &mut [u8],
            devs: &mut [D],
            planes: &mut [Option<StorePlane<'_>>],
        ) -> Outcome;
    }

    impl RunOnce for IscsiSession {
        fn run_once<D: ScsiDevice>(
            &mut self,
            conn: &mut MockConn,
            work: &mut [u8],
            devs: &mut [D],
            planes: &mut [Option<StorePlane<'_>>],
        ) -> Outcome {
            let mut ev = Event::Tick;
            let mut wrote = false;
            loop {
                match self.poll(ev, work, devs) {
                    Action::HostRecv { len } => {
                        let mut got = 0usize;
                        while got < len {
                            match conn.read(&mut work[got..len]) {
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
                    Action::Store { lun, op } => {
                        let result = match planes.get_mut(lun).and_then(|p| p.as_mut()) {
                            Some(plane) => plane.do_op(op),
                            None => return Outcome::Error(TargetError::Internal),
                        };
                        ev = Event::StoreDone { result };
                    }
                    Action::Closed => return Outcome::Closed,
                    Action::Error(e) => return Outcome::Error(e),
                }
            }
        }
    }

    /// Login parameters as sent by a Linux open-iscsi initiator
    /// (concatenated literals preserve embedded NUL separators).
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
        // CmdSN stays 0 (RFC 3720 §10.12.8): the first FullFeature command
        // reuses the leading Login Request's CmdSN.
        bhs
    }

    /// SCSI Command BHS for READ(10).
    fn read10_bhs(lba: u32, blocks: u16, itt: u32, cmd_sn: u32) -> [u8; 48] {
        let mut bhs = [0u8; 48];
        bhs[0] = op::SCSI_CMD;
        bhs[1] = 0x40; // task attribute (direction is taken from the CDB)
        bhs[16..20].copy_from_slice(&be32(itt));
        bhs[24..28].copy_from_slice(&be32(cmd_sn));
        bhs[28..32].copy_from_slice(&be32(cmd_sn)); // ExpStatSN
        bhs[32] = 0x28; // READ(10)
        bhs[34..38].copy_from_slice(&be32(lba));
        bhs[39..41].copy_from_slice(&blocks.to_be_bytes());
        bhs
    }

    /// SCSI Command BHS for WRITE(10) with a data segment (`dsl` bytes).
    fn write10_bhs(lba: u32, blocks: u16, itt: u32, cmd_sn: u32, dsl: u32) -> [u8; 48] {
        let mut bhs = [0u8; 48];
        bhs[0] = op::SCSI_CMD;
        // Kernel write layout (§2.3.3): F(0x80) | W(0x20) | ATTR_SIMPLE(0x01) = 0xA1.
        bhs[1] = 0xA1;
        bhs[5] = (dsl >> 16) as u8;
        bhs[6] = (dsl >> 8) as u8;
        bhs[7] = dsl as u8;
        bhs[16..20].copy_from_slice(&be32(itt));
        bhs[24..28].copy_from_slice(&be32(cmd_sn));
        bhs[28..32].copy_from_slice(&be32(cmd_sn)); // ExpStatSN
        bhs[32] = 0x2A; // WRITE(10)
        bhs[34..38].copy_from_slice(&be32(lba));
        bhs[39..41].copy_from_slice(&blocks.to_be_bytes());
        bhs
    }

    /// SCSI Data-Out BHS.
    fn dataout_bhs(itt: u32, ttt: u32, data_sn: u32, bo: u32, dsl: u32) -> [u8; 48] {
        let mut bhs = [0u8; 48];
        bhs[0] = op::SCSI_DATA_OUT;
        bhs[1] = 0x80; // F bit
        bhs[5] = (dsl >> 16) as u8;
        bhs[6] = (dsl >> 8) as u8;
        bhs[7] = dsl as u8;
        bhs[16..20].copy_from_slice(&be32(itt));
        bhs[20..24].copy_from_slice(&be32(ttt));
        bhs[36..40].copy_from_slice(&be32(data_sn));
        bhs[40..44].copy_from_slice(&be32(bo));
        bhs
    }

    fn resp_value<'a>(data: &'a [u8], key: &str) -> Option<&'a [u8]> {
        let k = key.as_bytes();
        let mut p = 0usize;
        while p < data.len() {
            if data[p..].starts_with(k) && p + k.len() < data.len() && data[p + k.len()] == b'=' {
                let start = p + k.len() + 1;
                let end = data[start..]
                    .iter()
                    .position(|&b| b == 0)
                    .map_or(data.len(), |i| start + i);
                return Some(&data[start..end]);
            }
            p = data[p..]
                .iter()
                .position(|&b| b == 0)
                .map_or(data.len(), |i| p + i + 1);
        }
        None
    }

    /// One-PDU login on the given harness; returns the Login Response PDU.
    /// Generic over `D: ScsiDevice` so a homogeneous block array or a mixed
    /// `Device` array both work.
    fn login<D: ScsiDevice>(
        conn: &mut MockConn,
        session: &mut IscsiSession,
        work: &mut [u8],
        devs: &mut [D],
        planes: &mut [Option<StorePlane<'_>>],
    ) -> (Vec<u8>, Vec<u8>) {
        let text = REQ_TEXT.as_bytes();
        let bhs = login_bhs(text.len() as u32);
        conn.feed_padded(&bhs, text);
        assert_eq!(
            session.run_once(conn, work, devs, planes),
            Outcome::Processed
        );
        conn.take_pdu().expect("login response")
    }

    // ── Login Response BHS: RFC 3720 §10.12.2 byte layout ──────────

    #[test]
    fn login_resp_bhs_rfc() {
        let mut conn = MockConn::new();
        let mut session = IscsiSession::default();
        let mut work = vec![0u8; WORK_LEN];
        let mut ram = vec![0u8; 16 * 1024 * 1024];
        let mut backend = RamBackend::new(&mut ram);
        let mut dev = BlockDevice::disk(&mut backend, 512).unwrap();
        let mut devs = [&mut dev as &mut dyn ScsiDevice];
        let mut planes = [Some(StorePlane::BlockRw(&mut backend))];
        let (bhs, _data) = login(&mut conn, &mut session, &mut work, &mut devs, &mut planes);

        assert_eq!(bhs[0] & 0x3F, op::LOGIN_RESP);
        assert_eq!(bhs[1] & 0x80, 0x80); // T=1
        assert_eq!(bhs[1] & 0x40, 0x00); // C=0
        assert_eq!((bhs[1] >> 2) & 0x03, stage::OP_PARAM); // CSG
        assert_eq!(bhs[1] & 0x03, stage::FULL_FEATURE); // NSG
        assert_eq!(bhs[2], 0x00); // Version-max
        assert_eq!(bhs[3], 0x00); // Version-active
        assert_eq!(bhs[4], 0x00); // TotalAHSLength
        let dsl = (u32::from(bhs[5]) << 16) | (u32::from(bhs[6]) << 8) | u32::from(bhs[7]);
        assert!(dsl > 0);

        let lreq = login_bhs(REQ_TEXT.len() as u32);
        assert_eq!(&bhs[8..14], &lreq[8..14]); // ISID echoed
        let tsih = (u16::from(bhs[14]) << 8) | u16::from(bhs[15]);
        assert_ne!(tsih, 0); // new session TSIH non-zero
        assert_eq!(&bhs[16..20], &lreq[16..20]); // ITT echoed
        assert_eq!(&bhs[20..24], &[0, 0, 0, 0]); // reserved
        assert_eq!(&bhs[24..28], &be32(0)); // StatSN = 0
        assert_eq!(&bhs[28..32], &be32(0)); // ExpCmdSN = request CmdSN
        assert_eq!(&bhs[32..36], &be32(0)); // MaxCmdSN
        assert_eq!(bhs[36], 0x00); // Status-Class
        assert_eq!(bhs[37], 0x00); // Status-Detail
        assert_eq!(&bhs[38..48], &[0u8; 10]); // reserved
    }

    // ── Login Response keys ─────────────────────────────────────────

    #[test]
    fn login_resp_no_skipped_keys() {
        let mut conn = MockConn::new();
        let mut session = IscsiSession::default();
        let mut work = vec![0u8; WORK_LEN];
        let mut ram = vec![0u8; 16 * 1024 * 1024];
        let mut backend = RamBackend::new(&mut ram);
        let mut dev = BlockDevice::disk(&mut backend, 512).unwrap();
        let mut devs = [&mut dev as &mut dyn ScsiDevice];
        let mut planes = [Some(StorePlane::BlockRw(&mut backend))];
        let (_bhs, data) = login(&mut conn, &mut session, &mut work, &mut devs, &mut planes);
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
        let mut conn = MockConn::new();
        let mut session = IscsiSession::default();
        let mut work = vec![0u8; WORK_LEN];
        let mut ram = vec![0u8; 16 * 1024 * 1024];
        let mut backend = RamBackend::new(&mut ram);
        let mut dev = BlockDevice::disk(&mut backend, 512).unwrap();
        let mut devs = [&mut dev as &mut dyn ScsiDevice];
        let mut planes = [Some(StorePlane::BlockRw(&mut backend))];
        let (_bhs, data) = login(&mut conn, &mut session, &mut work, &mut devs, &mut planes);
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
        let mut conn = MockConn::new();
        let mut session = IscsiSession::default();
        let mut work = vec![0u8; WORK_LEN];
        let mut ram = vec![0u8; 16 * 1024 * 1024];
        let mut backend = RamBackend::new(&mut ram);
        let mut dev = BlockDevice::disk(&mut backend, 512).unwrap();
        let mut devs = [&mut dev as &mut dyn ScsiDevice];
        let mut planes = [Some(StorePlane::BlockRw(&mut backend))];
        let (_bhs, data) = login(&mut conn, &mut session, &mut work, &mut devs, &mut planes);
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
        assert_eq!(resp_value(&data, "DataPDUInOrder"), Some(b"Yes".as_slice()));
        assert_eq!(
            resp_value(&data, "DataSequenceInOrder"),
            Some(b"Yes".as_slice())
        );
        assert_eq!(resp_value(&data, "DefaultTime2Wait"), Some(b"2".as_slice()));
        assert_eq!(
            resp_value(&data, "DefaultTime2Retain"),
            Some(b"0".as_slice())
        );
        assert_eq!(resp_value(&data, "IFMarker"), Some(b"No".as_slice()));
        assert_eq!(resp_value(&data, "OFMarker"), Some(b"No".as_slice()));
        assert_eq!(resp_value(&data, "HeaderDigest"), Some(b"None".as_slice()));
        assert_eq!(resp_value(&data, "DataDigest"), Some(b"None".as_slice()));
        assert_eq!(resp_value(&data, "ImmediateData"), Some(b"Yes".as_slice()));
        assert_eq!(
            resp_value(&data, "MaxOutstandingR2T"),
            Some(b"1".as_slice())
        );
        assert_eq!(resp_value(&data, "MaxConnections"), Some(b"1".as_slice()));
        assert_eq!(
            resp_value(&data, "ErrorRecoveryLevel"),
            Some(b"0".as_slice())
        );
    }

    // ── Multi-stage login (CSG=0 → CSG=1 → Full Feature) ───────────

    #[test]
    fn multi_stage_login() {
        let mut conn = MockConn::new();
        let mut session = IscsiSession::default();
        let mut work = vec![0u8; WORK_LEN];
        let mut ram = vec![0u8; 16 * 1024 * 1024];
        let mut backend = RamBackend::new(&mut ram);
        let mut dev = BlockDevice::disk(&mut backend, 512).unwrap();
        let mut devs = [&mut dev as &mut dyn ScsiDevice];
        let mut planes = [Some(StorePlane::BlockRw(&mut backend))];

        // Stage 1: CSG=0 (Security), T=1, NSG=3 → target forces NSG=1.
        let mut bhs = [0u8; 48];
        bhs[0] = op::LOGIN_REQ | 0x40;
        bhs[1] = flag::T_BIT | ((stage::SECURITY & 0x03) << flag::CSG_SHIFT) | stage::FULL_FEATURE;
        conn.feed(&bhs, &[]);
        assert_eq!(
            session.run_once(&mut conn, &mut work, &mut devs, &mut planes),
            Outcome::Processed
        );
        let (resp1, _) = conn.take_pdu().unwrap();
        assert_eq!(resp1[1] & 0x80, 0x80); // T=1
        assert_eq!((resp1[1] >> 2) & 0x03, stage::SECURITY);
        assert_eq!(resp1[1] & 0x03, stage::OP_PARAM);
        assert_eq!(session.stage(), LoginStage::OpParam);

        // Stage 2: CSG=1 (OpParam), T=1, NSG=3 → Full Feature.
        let mut bhs = [0u8; 48];
        bhs[0] = op::LOGIN_REQ | 0x40;
        bhs[1] = flag::T_BIT | ((stage::OP_PARAM & 0x03) << flag::CSG_SHIFT) | stage::FULL_FEATURE;
        bhs[15] = 0x01; // TSIH from stage 1 response
        conn.feed(&bhs, &[]);
        assert_eq!(
            session.run_once(&mut conn, &mut work, &mut devs, &mut planes),
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
            session.run_once(&mut conn, &mut work, &mut devs, &mut planes),
            Outcome::Processed
        );
        let (resp, _) = conn.take_pdu().unwrap();
        assert_eq!(resp[0] & 0x3F, op::SCSI_DATA_IN);
        assert_eq!(&resp[24..28], &be32(2)); // StatSN = 2
    }

    // ── READ(10): Data-In BufferOffset / DataSN continuity ─────────

    #[test]
    fn data_in_buffer_offset() {
        let mut conn = MockConn::new();
        let mut session = IscsiSession::default();
        let mut work = vec![0u8; WORK_LEN];
        let mut ram = vec![0u8; 16 * 1024 * 1024];
        let mut backend = RamBackend::new(&mut ram);
        let mut dev = BlockDevice::disk(&mut backend, 512).unwrap();
        let mut devs = [&mut dev as &mut dyn ScsiDevice];
        let mut planes = [Some(StorePlane::BlockRw(&mut backend))];
        login(&mut conn, &mut session, &mut work, &mut devs, &mut planes);

        // Pre-fill the device with a known pattern (LBA 0..18) via the plane.
        let pattern: Vec<u8> = (0..9216u32).map(|i| (i & 0xFF) as u8).collect();
        planes[0]
            .as_mut()
            .unwrap()
            .do_op(StoreOp::Write {
                off: 0,
                buf: &pattern,
            })
            .unwrap();

        // READ 18 blocks (9216 bytes) — crosses 2+ Data-In PDUs.
        let cmd = read10_bhs(0, 18, 0x12345678, 0);
        conn.feed(&cmd, &[]);
        assert_eq!(
            session.run_once(&mut conn, &mut work, &mut devs, &mut planes),
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
        assert!(count >= 2, "expected >= 2 Data-In PDUs for 9216-byte read");
        assert_eq!(expected_bo, 9216);
    }

    // ── WRITE(10): immediate data → R2T → Data-Out → status ───────

    #[test]
    fn write_flow_r2t_and_response() {
        let mut conn = MockConn::new();
        let mut session = IscsiSession::default();
        let mut work = vec![0u8; WORK_LEN];
        let mut ram = vec![0u8; 16 * 1024 * 1024];
        let mut backend = RamBackend::new(&mut ram);
        let mut dev = BlockDevice::disk(&mut backend, 512).unwrap();
        let mut devs = [&mut dev as &mut dyn ScsiDevice];
        let mut planes = [Some(StorePlane::BlockRw(&mut backend))];
        login(&mut conn, &mut session, &mut work, &mut devs, &mut planes);

        // WRITE 3 blocks at LBA 10 with only 512 bytes of immediate data.
        let itt = 0x7777_0001;
        let imm: Vec<u8> = (0..512u32).map(|i| (i & 0xFF) as u8).collect();
        let cmd = write10_bhs(10, 3, itt, 0, 512);
        conn.feed_padded(&cmd, &imm);

        // Pre-feed the solicited Data-Out (1024 bytes): one step consumes the
        // whole transaction (Command → R2T → Data-Out → Response).
        let out: Vec<u8> = (0x100..0x500u32).map(|i| (i & 0xFF) as u8).collect();
        let dout = dataout_bhs(itt, 1, 0, 512, 1024);
        conn.feed_padded(&dout, &out);
        assert_eq!(
            session.run_once(&mut conn, &mut work, &mut devs, &mut planes),
            Outcome::Processed
        );

        // R2T: remaining 1024 bytes.
        let (r2t, _) = conn.take_pdu().unwrap();
        assert_eq!(r2t[0] & 0x3F, op::R2T);
        assert_eq!(&r2t[16..20], &be32(itt));
        assert_eq!(&r2t[20..24], &be32(1)); // TTT
        assert_eq!(&r2t[40..44], &be32(512)); // BufferOffset
        assert_eq!(&r2t[44..48], &be32(1024)); // DesiredLen
        assert_eq!(&r2t[36..40], &be32(0)); // R2TSN

        // Final SCSI Response.
        let (resp, _) = conn.take_pdu().unwrap();
        assert_eq!(resp[0] & 0x3F, op::SCSI_RESP);
        assert_eq!(resp[3], status::GOOD);
        assert_eq!(&resp[16..20], &be32(itt));
        assert_eq!(&resp[24..28], &be32(1)); // StatSN
        assert_eq!(&resp[28..32], &be32(1)); // ExpCmdSN = cmd_sn+1
        assert_eq!(&resp[32..36], &be32(1)); // MaxCmdSN

        // Verify backend content through the plane.
        let mut buf = [0u8; 1536];
        planes[0]
            .as_mut()
            .unwrap()
            .do_op(StoreOp::Read {
                off: 10 * 512,
                buf: &mut buf,
            })
            .unwrap();
        let mut expect = imm.clone();
        expect.extend_from_slice(&out);
        assert_eq!(&buf, expect.as_slice());
    }

    // ── Large write: multiple R2Ts bounded by MaxBurstLength ───────

    #[test]
    fn write_multi_r2t_bounded_by_max_burst() {
        let mut conn = MockConn::new();
        let mut session = IscsiSession::default();
        let mut work = vec![0u8; WORK_LEN];
        let mut ram = vec![0u8; 16 * 1024 * 1024];
        let mut backend = RamBackend::new(&mut ram);
        let mut dev = BlockDevice::disk(&mut backend, 512).unwrap();
        let mut devs = [&mut dev as &mut dyn ScsiDevice];
        let mut planes = [Some(StorePlane::BlockRw(&mut backend))];
        login(&mut conn, &mut session, &mut work, &mut devs, &mut planes);

        // 600 blocks = 307200 bytes > MaxBurstLength (262144).
        let itt = 0xAAAA_0001;
        let imm = vec![0x5Au8; 8192];
        let cmd = write10_bhs(0, 600, itt, 0, 8192);
        conn.feed_padded(&cmd, &imm);

        // Feed the full Data-Out sequence up front: one step consumes the
        // whole transaction (Command → R2T1 → 32×Data-Out → R2T2 → Data-Out).
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
            session.run_once(&mut conn, &mut work, &mut devs, &mut planes),
            Outcome::Processed
        );

        // R2T #1: BO after immediate, DesiredLen bounded by MaxBurstLength.
        let r2t1 = conn.take_pdu().unwrap().0;
        assert_eq!(r2t1[0] & 0x3F, op::R2T);
        assert_eq!(&r2t1[40..44], &be32(8192)); // BO after immediate
        assert_eq!(&r2t1[44..48], &be32(262144)); // DesiredLen ≤ MaxBurstLength

        // R2T #2 for the remainder.
        let r2t2 = conn.take_pdu().unwrap().0;
        assert_eq!(r2t2[0] & 0x3F, op::R2T);
        assert_eq!(&r2t2[40..44], &be32(8192 + 262144)); // BO
        assert_eq!(&r2t2[44..48], &be32(307200 - 8192 - 262144)); // 36864

        let (resp, _) = conn.take_pdu().unwrap();
        assert_eq!(resp[0] & 0x3F, op::SCSI_RESP);
        assert_eq!(resp[3], status::GOOD);
    }

    // ── NOP-Out keepalive → NOP-In ─────────────────────────────────

    #[test]
    fn nop_in_echoes_ttt() {
        let mut conn = MockConn::new();
        let mut session = IscsiSession::default();
        let mut work = vec![0u8; WORK_LEN];
        let mut ram = vec![0u8; 16 * 1024 * 1024];
        let mut backend = RamBackend::new(&mut ram);
        let mut dev = BlockDevice::disk(&mut backend, 512).unwrap();
        let mut devs = [&mut dev as &mut dyn ScsiDevice];
        let mut planes = [Some(StorePlane::BlockRw(&mut backend))];
        login(&mut conn, &mut session, &mut work, &mut devs, &mut planes);

        let mut nop = [0u8; 48];
        nop[0] = op::NOP_OUT;
        nop[16..20].copy_from_slice(&be32(0xABCD));
        nop[20..24].copy_from_slice(&be32(0xFFFF_FFFF));
        conn.feed(&nop, &[]);
        assert_eq!(
            session.run_once(&mut conn, &mut work, &mut devs, &mut planes),
            Outcome::Processed
        );

        let (bhs, _) = conn.take_pdu().unwrap();
        assert_eq!(bhs[0] & 0x3F, op::NOP_IN);
        assert_eq!(&bhs[16..20], &be32(0xABCD));
        assert_eq!(&bhs[20..24], &be32(0xFFFF_FFFF));
    }

    // ── Unsupported LUN → SCSI Check Condition / LOGICAL UNIT NOT SUPPORTED ──
    // ── Malformed (multi-level) LUN → Reject 0x09 with the rejected header ──

    #[test]
    fn unsupported_lun_check_condition() {
        let mut conn = MockConn::new();
        let mut session = IscsiSession::default();
        let mut work = vec![0u8; WORK_LEN];
        let mut ram = vec![0u8; 16 * 1024 * 1024];
        let mut backend = RamBackend::new(&mut ram);
        let mut dev = BlockDevice::disk(&mut backend, 512).unwrap();
        let mut devs = [&mut dev as &mut dyn ScsiDevice];
        let mut planes = [Some(StorePlane::BlockRw(&mut backend))];
        login(&mut conn, &mut session, &mut work, &mut devs, &mut planes);

        let mut cmd = read10_bhs(0, 1, 0x1111, 0);
        cmd[9] = 5; // LUN out of range (only LUN 0 exists)
        conn.feed(&cmd, &[]);
        // A well-formed single-level LUN that is absent is a SCSI-level
        // error, not a session-level protocol failure → the connection
        // stays open (Processed), and the response carries the sense.
        assert_eq!(
            session.run_once(&mut conn, &mut work, &mut devs, &mut planes),
            Outcome::Processed
        );

        let (bhs, data) = conn.take_pdu().unwrap();
        assert_eq!(bhs[0] & 0x3F, op::SCSI_RESP);
        assert_eq!(bhs[3], status::CHECK_CONDITION);
        assert_eq!(&bhs[16..20], &be32(0x1111)); // ITT echoed
                                                 // Data segment: 2-byte SenseLength (18) + fixed sense 70h.
        assert_eq!(&data[0..2], &[0x00, 18]);
        assert_eq!(data[2], 0x70); // response code (fixed format)
        assert_eq!(data[4], 0x05); // ILLEGAL REQUEST
        assert_eq!(data[14], 0x25); // ASC = LOGICAL UNIT NOT SUPPORTED
        assert_eq!(data[15], 0x00); // ASCQ
    }

    #[test]
    fn multi_level_lun_rejected_as_pdu_field() {
        let mut conn = MockConn::new();
        let mut session = IscsiSession::default();
        let mut work = vec![0u8; WORK_LEN];
        let mut ram = vec![0u8; 16 * 1024 * 1024];
        let mut backend = RamBackend::new(&mut ram);
        let mut dev = BlockDevice::disk(&mut backend, 512).unwrap();
        let mut devs = [&mut dev as &mut dyn ScsiDevice];
        let mut planes = [Some(StorePlane::BlockRw(&mut backend))];
        login(&mut conn, &mut session, &mut work, &mut devs, &mut planes);

        // SAM-2 multi-level (logical unit) addressing: byte 8 address
        // method bits 6-3 = 0100b. Byte 9 alone is meaningless for this
        // encoding, so the target must not reinterpret it as a LUN id.
        let mut cmd = read10_bhs(0, 1, 0x2222, 0);
        cmd[8] = 0x40;
        cmd[9] = 0; // would decode to LUN 0 (in range) if mis-read
        conn.feed(&cmd, &[]);
        assert_eq!(
            session.run_once(&mut conn, &mut work, &mut devs, &mut planes),
            Outcome::Closed
        );

        let (bhs, data) = conn.take_pdu().unwrap();
        assert_eq!(bhs[0] & 0x3F, op::REJECT);
        assert_eq!(bhs[2], reject::INVALID_PDU_FIELD);
        assert_eq!(&bhs[16..20], &[0xFF; 4]); // ITT = 0xffffffff (#18)
        assert_eq!(data, cmd.to_vec()); // rejected header in data segment (#18)
    }

    // ── Out-of-window non-immediate CmdSN → silently ignored ───────

    #[test]
    fn cmd_sn_out_of_window_ignored() {
        let mut conn = MockConn::new();
        let mut session = IscsiSession::default();
        let mut work = vec![0u8; WORK_LEN];
        let mut ram = vec![0u8; 16 * 1024 * 1024];
        let mut backend = RamBackend::new(&mut ram);
        let mut dev = BlockDevice::disk(&mut backend, 512).unwrap();
        let mut devs = [&mut dev as &mut dyn ScsiDevice];
        let mut planes = [Some(StorePlane::BlockRw(&mut backend))];
        login(&mut conn, &mut session, &mut work, &mut devs, &mut planes);

        // CmdSN=5 while the next expected is 0 → silent ignore, no PDU.
        let cmd = read10_bhs(0, 1, 0x2222, 5);
        conn.feed(&cmd, &[]);
        assert_eq!(
            session.run_once(&mut conn, &mut work, &mut devs, &mut planes),
            Outcome::Idle
        );
        assert!(conn.take_pdu().is_none());

        // A correct CmdSN=0 command still executes afterwards.
        let cmd = read10_bhs(0, 1, 0x3333, 0);
        conn.feed(&cmd, &[]);
        assert_eq!(
            session.run_once(&mut conn, &mut work, &mut devs, &mut planes),
            Outcome::Processed
        );
        let (bhs, _) = conn.take_pdu().unwrap();
        assert_eq!(bhs[0] & 0x3F, op::SCSI_DATA_IN);
    }

    // ── RFC §10.12.8: first FullFeature command reuses login CmdSN ──

    #[test]
    fn first_command_reuses_login_cmd_sn() {
        let mut conn = MockConn::new();
        let mut session = IscsiSession::default();
        let mut work = vec![0u8; WORK_LEN];
        let mut ram = vec![0u8; 16 * 1024 * 1024];
        let mut backend = RamBackend::new(&mut ram);
        let mut dev = BlockDevice::disk(&mut backend, 512).unwrap();
        let mut devs = [&mut dev as &mut dyn ScsiDevice];
        let mut planes = [Some(StorePlane::BlockRw(&mut backend))];

        // Login carrying a non-zero CmdSN, as a real initiator would.
        let text = REQ_TEXT.as_bytes();
        let mut bhs = login_bhs(text.len() as u32);
        bhs[24..28].copy_from_slice(&be32(0x73dd_e21f));
        conn.feed_padded(&bhs, text);
        assert_eq!(
            session.run_once(&mut conn, &mut work, &mut devs, &mut planes),
            Outcome::Processed
        );
        let (resp, _) = conn.take_pdu().unwrap();
        assert_eq!(&resp[28..32], &be32(0x73dd_e21f)); // ExpCmdSN = login CmdSN
        assert_eq!(&resp[32..36], &be32(0x73dd_e21f)); // MaxCmdSN

        // The first command reuses the same CmdSN (not +1).
        let cmd = read10_bhs(0, 1, 0x9999, 0x73dd_e21f);
        conn.feed(&cmd, &[]);
        assert_eq!(
            session.run_once(&mut conn, &mut work, &mut devs, &mut planes),
            Outcome::Processed
        );
        let (bhs, _) = conn.take_pdu().unwrap();
        assert_eq!(bhs[0] & 0x3F, op::SCSI_DATA_IN);

        // The second command advances to +1.
        let cmd = read10_bhs(0, 1, 0x999A, 0x73dd_e220);
        conn.feed(&cmd, &[]);
        assert_eq!(
            session.run_once(&mut conn, &mut work, &mut devs, &mut planes),
            Outcome::Processed
        );
    }

    // ── Immediate TMF (I=1) accepted out of window (#21) ───────────

    #[test]
    fn immediate_tmf_abort_task_complete() {
        let mut conn = MockConn::new();
        let mut session = IscsiSession::default();
        let mut work = vec![0u8; WORK_LEN];
        let mut ram = vec![0u8; 16 * 1024 * 1024];
        let mut backend = RamBackend::new(&mut ram);
        let mut dev = BlockDevice::disk(&mut backend, 512).unwrap();
        let mut devs = [&mut dev as &mut dyn ScsiDevice];
        let mut planes = [Some(StorePlane::BlockRw(&mut backend))];
        login(&mut conn, &mut session, &mut work, &mut devs, &mut planes);

        let mut tmfr = [0u8; 48];
        tmfr[0] = op::SCSI_TASK_REQ | 0x40; // I bit
        tmfr[1] = 0x80;
        tmfr[2] = tmf::ABORT_TASK;
        tmfr[16..20].copy_from_slice(&be32(0x5555));
        tmfr[24..28].copy_from_slice(&be32(9)); // out of window, but I=1
        conn.feed(&tmfr, &[]);
        assert_eq!(
            session.run_once(&mut conn, &mut work, &mut devs, &mut planes),
            Outcome::Processed
        );

        let (bhs, _) = conn.take_pdu().unwrap();
        assert_eq!(bhs[0] & 0x3F, op::SCSI_TASK_RESP);
        assert_eq!(bhs[2], tmf_response::COMPLETE);
        assert_eq!(&bhs[24..28], &be32(1)); // StatSN
    }

    // ── Non-immediate TMF with bad CmdSN → silently ignored ────────

    #[test]
    fn tmf_bad_cmd_sn_ignored() {
        let mut conn = MockConn::new();
        let mut session = IscsiSession::default();
        let mut work = vec![0u8; WORK_LEN];
        let mut ram = vec![0u8; 16 * 1024 * 1024];
        let mut backend = RamBackend::new(&mut ram);
        let mut dev = BlockDevice::disk(&mut backend, 512).unwrap();
        let mut devs = [&mut dev as &mut dyn ScsiDevice];
        let mut planes = [Some(StorePlane::BlockRw(&mut backend))];
        login(&mut conn, &mut session, &mut work, &mut devs, &mut planes);

        let mut tmfr = [0u8; 48];
        tmfr[0] = op::SCSI_TASK_REQ; // I=0
        tmfr[2] = tmf::LOGICAL_UNIT_RESET;
        tmfr[16..20].copy_from_slice(&be32(0x6666));
        tmfr[24..28].copy_from_slice(&be32(7)); // out of window, I=0 → ignore
        conn.feed(&tmfr, &[]);
        assert_eq!(
            session.run_once(&mut conn, &mut work, &mut devs, &mut planes),
            Outcome::Idle
        );
        assert!(conn.take_pdu().is_none());
    }

    // ── Logout → Logout Response → connection closed ───────────────

    #[test]
    fn logout_closes_connection() {
        let mut conn = MockConn::new();
        let mut session = IscsiSession::default();
        let mut work = vec![0u8; WORK_LEN];
        let mut ram = vec![0u8; 16 * 1024 * 1024];
        let mut backend = RamBackend::new(&mut ram);
        let mut dev = BlockDevice::disk(&mut backend, 512).unwrap();
        let mut devs = [&mut dev as &mut dyn ScsiDevice];
        let mut planes = [Some(StorePlane::BlockRw(&mut backend))];
        login(&mut conn, &mut session, &mut work, &mut devs, &mut planes);

        let mut lo = [0u8; 48];
        lo[0] = op::LOGOUT_REQ;
        lo[16..20].copy_from_slice(&be32(0xCAFE));
        conn.feed(&lo, &[]);
        assert_eq!(
            session.run_once(&mut conn, &mut work, &mut devs, &mut planes),
            Outcome::Closed
        );

        let (bhs, _) = conn.take_pdu().unwrap();
        assert_eq!(bhs[0] & 0x3F, op::LOGOUT_RESP);
        assert_eq!(&bhs[16..20], &be32(0xCAFE));
    }

    // ── Text Request → Reject 0x05 (command not supported) ─────────

    #[test]
    fn text_request_rejected() {
        let mut conn = MockConn::new();
        let mut session = IscsiSession::default();
        let mut work = vec![0u8; WORK_LEN];
        let mut ram = vec![0u8; 16 * 1024 * 1024];
        let mut backend = RamBackend::new(&mut ram);
        let mut dev = BlockDevice::disk(&mut backend, 512).unwrap();
        let mut devs = [&mut dev as &mut dyn ScsiDevice];
        let mut planes = [Some(StorePlane::BlockRw(&mut backend))];
        login(&mut conn, &mut session, &mut work, &mut devs, &mut planes);

        let mut txt = [0u8; 48];
        txt[0] = op::TEXT_REQ;
        txt[16..20].copy_from_slice(&be32(0x1234));
        txt[24..28].copy_from_slice(&be32(1)); // CmdSN (Text uses the window)
        conn.feed(&txt, &[]);
        assert_eq!(
            session.run_once(&mut conn, &mut work, &mut devs, &mut planes),
            Outcome::Closed
        );

        let (bhs, _) = conn.take_pdu().unwrap();
        assert_eq!(bhs[0] & 0x3F, op::REJECT);
        assert_eq!(bhs[2], reject::COMMAND_NOT_SUPPORTED);
    }

    #[test]
    fn sendtargets_all_on_discovery_returns_target_name() {
        let mut conn = MockConn::new();
        let mut session = IscsiSession::default();
        let mut work = vec![0u8; WORK_LEN];
        let mut ram = vec![0u8; 16 * 1024 * 1024];
        let mut backend = RamBackend::new(&mut ram);
        let mut dev = BlockDevice::disk(&mut backend, 512).unwrap();
        let mut devs = [&mut dev as &mut dyn ScsiDevice];
        let mut planes = [Some(StorePlane::BlockRw(&mut backend))];
        // Login with Discovery
        let text = b"InitiatorName=iqn.test\0SessionType=Discovery\0TargetName=iqn.1970-01.local.snowscsi:target\0";
        let bhs = {
            let mut bhs = [0u8; 48];
            bhs[0] = op::LOGIN_REQ | 0x40;
            bhs[1] =
                flag::T_BIT | ((stage::OP_PARAM & 0x03) << flag::CSG_SHIFT) | stage::FULL_FEATURE;
            let dsl = text.len() as u32;
            bhs[5] = (dsl >> 16) as u8;
            bhs[6] = (dsl >> 8) as u8;
            bhs[7] = dsl as u8;
            bhs
        };
        conn.feed_padded(&bhs, text);
        assert_eq!(
            session.run_once(&mut conn, &mut work, &mut devs, &mut planes),
            Outcome::Processed
        );
        conn.take_pdu().unwrap();

        // SendTargets=All
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
            session.run_once(&mut conn, &mut work, &mut devs, &mut planes),
            Outcome::Processed
        );
        let (bhs, data) = conn.take_pdu().unwrap();
        assert_eq!(bhs[0] & 0x3F, op::TEXT_RESP);
        assert_eq!(bhs[1] & flag::F_BIT, flag::F_BIT);
        assert_eq!(&bhs[16..20], &be32(0x5555));
        assert_eq!(&bhs[20..24], &be32(0xFFFF_FFFF));
        assert!(data.windows(11).any(|w| w == b"TargetName="));
        assert!(data.windows(8).any(|w| w == b"snowscsi"));
    }

    // ── AHS defense: TotalAHSLength > 0 → Reject 0x04 ──────────────

    #[test]
    fn ahs_rejected() {
        let mut conn = MockConn::new();
        let mut session = IscsiSession::default();
        let mut work = vec![0u8; WORK_LEN];
        let mut ram = vec![0u8; 16 * 1024 * 1024];
        let mut backend = RamBackend::new(&mut ram);
        let mut dev = BlockDevice::disk(&mut backend, 512).unwrap();
        let mut devs = [&mut dev as &mut dyn ScsiDevice];
        let mut planes = [Some(StorePlane::BlockRw(&mut backend))];
        login(&mut conn, &mut session, &mut work, &mut devs, &mut planes);

        let mut pdu = read10_bhs(0, 1, 0x7777, 0);
        pdu[4] = 1; // TotalAHSLength = 1 (4 bytes of AHS)
        conn.feed(&pdu, &[]);
        conn.feed_bytes(&[0u8; 4]); // the AHS bytes
        assert_eq!(
            session.run_once(&mut conn, &mut work, &mut devs, &mut planes),
            Outcome::Closed
        );

        let (bhs, _) = conn.take_pdu().unwrap();
        assert_eq!(bhs[0] & 0x3F, op::REJECT);
        assert_eq!(bhs[2], reject::PROTOCOL_ERROR);
    }

    // ── Linux-kernel (open-iscsi) write flag layout (RFC 3720 §2.3.3) ──
    // The kernel sends byte 1 = F(0x80) | W(0x20) | ATTR (bits 0-2): 0xA1 for
    // a Simple write, 0xA0 for an untagged write. W is RFC 3720 bit 2 = 0x20
    // (bit 0 is the MSB per the Byte Rule) — the target must accept these
    // writes (regression: a prior fix checked 0x04 and Rejected them 0x04).

    #[test]
    fn linux_kernel_write_flag_layout_accepted() {
        let mut conn = MockConn::new();
        let mut session = IscsiSession::default();
        let mut work = vec![0u8; WORK_LEN];
        let mut ram = vec![0u8; 16 * 1024 * 1024];
        let mut backend = RamBackend::new(&mut ram);
        let mut dev = BlockDevice::disk(&mut backend, 512).unwrap();
        let mut devs = [&mut dev as &mut dyn ScsiDevice];
        let mut planes = [Some(StorePlane::BlockRw(&mut backend))];
        login(&mut conn, &mut session, &mut work, &mut devs, &mut planes);

        // F(0x80) | W(0x20) | ATTR_SIMPLE(0x01) = 0xA1 — write10_bhs default.
        let itt = 0xA100_0001;
        let imm = vec![0x42u8; 512];
        let cmd = write10_bhs(0, 1, itt, 0, 512);
        conn.feed_padded(&cmd, &imm);
        assert_eq!(
            session.run_once(&mut conn, &mut work, &mut devs, &mut planes),
            Outcome::Processed
        );
        let (resp, _) = conn.take_pdu().unwrap();
        assert_eq!(resp[0] & 0x3F, op::SCSI_RESP);
        assert_eq!(resp[3], status::GOOD);

        // F(0x80) | W(0x20), untagged (0x00) = 0xA0.
        let itt = 0xA100_0002;
        let mut cmd = write10_bhs(0, 1, itt, 1, 512);
        cmd[1] = 0xA0;
        conn.feed_padded(&cmd, &imm);
        assert_eq!(
            session.run_once(&mut conn, &mut work, &mut devs, &mut planes),
            Outcome::Processed
        );
        let (resp, _) = conn.take_pdu().unwrap();
        assert_eq!(resp[0] & 0x3F, op::SCSI_RESP);
        assert_eq!(resp[3], status::GOOD);
    }

    // ── serve_conn blocking loop: login + logout → Ok ──────────────

    #[test]
    fn serve_conn_login_then_logout() {
        use snowscsi::iscsi::transport::serve_conn;

        let mut conn = MockConn::new();
        let mut session = IscsiSession::default();
        let mut work = vec![0u8; WORK_LEN];
        let mut ram = vec![0u8; 16 * 1024 * 1024];
        let mut backend = RamBackend::new(&mut ram);
        let mut dev = BlockDevice::disk(&mut backend, 512).unwrap();
        let mut devs = [&mut dev as &mut dyn ScsiDevice];
        let mut planes = [Some(StorePlane::BlockRw(&mut backend))];
        let mut luns = Luns::new(&mut devs, &mut planes);

        let text = REQ_TEXT.as_bytes();
        conn.feed_padded(&login_bhs(text.len() as u32), text);
        let mut lo = [0u8; 48];
        lo[0] = op::LOGOUT_REQ;
        lo[16..20].copy_from_slice(&be32(1));
        conn.feed(&lo, &[]);

        assert!(serve_conn(&mut conn, &mut work, &mut session, &mut luns).is_ok());

        let (bhs, _) = conn.take_pdu().unwrap();
        assert_eq!(bhs[0] & 0x3F, op::LOGIN_RESP);
        let (bhs, _) = conn.take_pdu().unwrap();
        assert_eq!(bhs[0] & 0x3F, op::LOGOUT_RESP);
        assert!(conn.take_pdu().is_none());
    }

    // ── Multi-LUN REPORT LUNS (target-level) ────────────────────────
    // Regression: a single-LUN hardcoded response made the Linux client
    // discover only LUN 0 even when more `--block` specs were given.
    // The fix lives in the target layer (iscsi_target::handle_report_luns),
    // so REPORT LUNS no longer goes through any individual Device.

    fn report_luns_bhs(lun: u8, itt: u32, cmd_sn: u32) -> [u8; 48] {
        let mut bhs = [0u8; 48];
        bhs[0] = op::SCSI_CMD;
        bhs[16..20].copy_from_slice(&be32(itt));
        bhs[24..28].copy_from_slice(&be32(cmd_sn));
        bhs[28..32].copy_from_slice(&be32(cmd_sn));
        bhs[9] = lun; // BHS LUN — does not affect the LUN list
                      // CDB starts at BHS byte 32 (12 bytes for REPORT LUNS, group 5).
        bhs[32] = 0xA0; // REPORT LUNS opcode
                        // CDB bytes 6..10: allocation length (4 bytes BE). 0x0800 = 2048,
                        // comfortably above 4 + 8*256.
        bhs[38] = 0x08;
        bhs[39] = 0x00;
        bhs[40] = 0x00;
        bhs[41] = 0x00;
        bhs
    }

    #[test]
    fn report_luns_single_lun() {
        let mut conn = MockConn::new();
        let mut session = IscsiSession::default();
        let mut work = vec![0u8; WORK_LEN];
        let mut ram = vec![0u8; 16 * 1024];
        let mut backend = RamBackend::new(&mut ram);
        let mut dev = BlockDevice::disk(&mut backend, 512).unwrap();
        let mut devs = [&mut dev as &mut dyn ScsiDevice];
        let mut planes = [Some(StorePlane::BlockRw(&mut backend))];
        login(&mut conn, &mut session, &mut work, &mut devs, &mut planes);

        conn.feed(&report_luns_bhs(0, 0xA1, 0), &[]);
        assert_eq!(
            session.run_once(&mut conn, &mut work, &mut devs, &mut planes),
            Outcome::Processed
        );
        let (bhs, data) = conn.take_pdu().unwrap();
        assert_eq!(bhs[0] & 0x3F, op::SCSI_DATA_IN);
        assert_eq!(
            bhs[1] & (flag::F_BIT | flag::S_BIT),
            flag::F_BIT | flag::S_BIT
        );
        assert_eq!(bhs[3], status::GOOD);
        assert_eq!(bhs[16..20], be32(0xA1)); // ITT echoed
                                             // Header: 4-byte LUN list length = 8.
        assert_eq!(&data[..4], &[0, 0, 0, 8]);
        // 4-byte reserved (zeros) per SPC-4 / Linux kernel layout.
        assert_eq!(&data[4..8], &[0, 0, 0, 0]);
        // One 8-byte LUN 0 entry.
        assert_eq!(&data[8..16], &[0, 0, 0, 0, 0, 0, 0, 0]);
    }

    // ── SELECT REPORT field (SPC-3 §6.21/Table 148) ──────────────
    // 01h = well-known LUs only (→ empty list), 02h = all LUs (→ full
    // list), 03h-FFh reserved → CHECK CONDITION / 05/24.

    fn report_luns_bhs_select(lun: u8, itt: u32, cmd_sn: u32, select: u8) -> [u8; 48] {
        let mut bhs = report_luns_bhs(lun, itt, cmd_sn);
        bhs[34] = select; // CDB byte 2
        bhs
    }

    #[test]
    fn report_luns_select_01_well_known_only_empty() {
        let mut conn = MockConn::new();
        let mut session = IscsiSession::default();
        let mut work = vec![0u8; WORK_LEN];
        let mut ram = vec![0u8; 16 * 1024];
        let mut backend = RamBackend::new(&mut ram);
        let mut dev = BlockDevice::disk(&mut backend, 512).unwrap();
        let mut devs = [&mut dev as &mut dyn ScsiDevice];
        let mut planes = [Some(StorePlane::BlockRw(&mut backend))];
        login(&mut conn, &mut session, &mut work, &mut devs, &mut planes);

        conn.feed(&report_luns_bhs_select(0, 0xA2, 0, 0x01), &[]);
        assert_eq!(
            session.run_once(&mut conn, &mut work, &mut devs, &mut planes),
            Outcome::Processed
        );
        let (bhs, data) = conn.take_pdu().unwrap();
        assert_eq!(bhs[0] & 0x3F, op::SCSI_DATA_IN);
        assert_eq!(bhs[3], status::GOOD);
        assert_eq!(&data[..4], &[0, 0, 0, 0]); // LUN LIST LENGTH = 0
    }

    #[test]
    fn report_luns_select_02_returns_full_list() {
        let mut conn = MockConn::new();
        let mut session = IscsiSession::default();
        let mut work = vec![0u8; WORK_LEN];
        let mut ram = vec![0u8; 16 * 1024];
        let mut backend = RamBackend::new(&mut ram);
        let mut dev = BlockDevice::disk(&mut backend, 512).unwrap();
        let mut devs = [&mut dev as &mut dyn ScsiDevice];
        let mut planes = [Some(StorePlane::BlockRw(&mut backend))];
        login(&mut conn, &mut session, &mut work, &mut devs, &mut planes);

        conn.feed(&report_luns_bhs_select(0, 0xA3, 0, 0x02), &[]);
        assert_eq!(
            session.run_once(&mut conn, &mut work, &mut devs, &mut planes),
            Outcome::Processed
        );
        let (bhs, data) = conn.take_pdu().unwrap();
        assert_eq!(bhs[3], status::GOOD);
        assert_eq!(&data[..4], &[0, 0, 0, 8]);
        assert_eq!(&data[8..16], &[0, 0, 0, 0, 0, 0, 0, 0]);
    }

    #[test]
    fn report_luns_reserved_select_rejected() {
        let mut conn = MockConn::new();
        let mut session = IscsiSession::default();
        let mut work = vec![0u8; WORK_LEN];
        let mut ram = vec![0u8; 16 * 1024];
        let mut backend = RamBackend::new(&mut ram);
        let mut dev = BlockDevice::disk(&mut backend, 512).unwrap();
        let mut devs = [&mut dev as &mut dyn ScsiDevice];
        let mut planes = [Some(StorePlane::BlockRw(&mut backend))];
        login(&mut conn, &mut session, &mut work, &mut devs, &mut planes);

        conn.feed(&report_luns_bhs_select(0, 0xA4, 0, 0x03), &[]);
        assert_eq!(
            session.run_once(&mut conn, &mut work, &mut devs, &mut planes),
            Outcome::Processed
        );
        let (bhs, data) = conn.take_pdu().unwrap();
        assert_eq!(bhs[0] & 0x3F, op::SCSI_RESP);
        assert_eq!(bhs[3], status::CHECK_CONDITION);
        // Autosense data segment: 2-byte SenseLength + fixed sense.
        assert_eq!(&data[0..2], &[0x00, 18]);
        assert_eq!(data[2], 0x70);
        assert_eq!(data[4], 0x05); // ILLEGAL REQUEST
        assert_eq!(data[14], 0x24); // ASC = INVALID FIELD IN CDB
    }

    // ── Linux kernel REPORT LUNS scanner compatibility ─────────────
    // Regression: the prior layout packed the first LUN entry at offset 4,
    // but Linux's `scsi_report_lun_scan` iterates `lun_data[1..=num_luns]`
    // (8-byte stride starting at offset 8). With the wrong layout, LUN 0
    // straddled lun_data[0] and lun_data[1], and `scsilun_to_int` decoded
    // the LUN 0 / LUN 1 boundary as 2^32, which then exceeded the HBA's
    // `max_lun` and produced:
    //   sd 0:0:0:0: lun4294967296 has a LUN larger than allowed ...
    // (only LUN 0 was visible to the Linux initiator). This test mirrors
    // the kernel's `scsilun_to_int` byte ordering and checks every entry.

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
        let mut d0 = BlockDevice::disk(&mut b0, 512).unwrap();
        let mut d1 = BlockDevice::disk(&mut b1, 512).unwrap();
        let mut d2 = BlockDevice::disk(&mut b2, 512).unwrap();
        let mut devs: [&mut dyn ScsiDevice; 3] = [&mut d0, &mut d1, &mut d2];
        let mut planes = [
            Some(StorePlane::BlockRw(&mut b0)),
            Some(StorePlane::BlockRw(&mut b1)),
            Some(StorePlane::BlockRw(&mut b2)),
        ];

        let mut conn = MockConn::new();
        let mut session = IscsiSession::default();
        let mut work = vec![0u8; WORK_LEN];
        login(&mut conn, &mut session, &mut work, &mut devs, &mut planes);

        conn.feed(&report_luns_bhs(0, 0xBEEF, 0), &[]);
        session.run_once(&mut conn, &mut work, &mut devs, &mut planes);
        let (_, data) = conn.take_pdu().unwrap();

        // Replay the kernel's parse loop (drivers/scsi/scsi_scan.c):
        //   num_luns = be32(lun_list_length) / 8;
        //   for (lunp = &lun_data[1]; lunp <= &lun_data[num_luns]; lunp++) {
        //     lun = scsilun_to_int(lunp);
        let length = u32::from_be_bytes([data[0], data[1], data[2], data[3]]);
        let num_luns = length as usize / 8;
        assert_eq!(num_luns, 3, "LUN list length should be 3*8");
        for i in 1..=num_luns {
            let off = i * 8;
            let mut entry = [0u8; 8];
            entry.copy_from_slice(&data[off..off + 8]);
            let lun = kernel_scsilun_to_int(&entry);
            assert_eq!(
                lun,
                i as u64 - 1,
                "lun_data[{i}] must decode to LUN {}",
                i - 1
            );
        }
    }

    #[test]
    fn report_luns_three_luns_requested_at_lun_1() {
        // Same as above but the initiator sent REPORT LUNS to LUN 1 — the
        // target must still list all three LUNs, not just the LUN 1 entry.
        let mut r0 = vec![0u8; 16 * 1024];
        let mut r1 = vec![0u8; 16 * 1024];
        let mut r2 = vec![0u8; 16 * 1024];
        let mut b0 = RamBackend::new(&mut r0);
        let mut b1 = RamBackend::new(&mut r1);
        let mut b2 = RamBackend::new(&mut r2);
        let mut d0 = BlockDevice::disk(&mut b0, 512).unwrap();
        let mut d1 = BlockDevice::disk(&mut b1, 512).unwrap();
        let mut d2 = BlockDevice::disk(&mut b2, 512).unwrap();
        let mut devs: [&mut dyn ScsiDevice; 3] = [&mut d0, &mut d1, &mut d2];
        let mut planes = [
            Some(StorePlane::BlockRw(&mut b0)),
            Some(StorePlane::BlockRw(&mut b1)),
            Some(StorePlane::BlockRw(&mut b2)),
        ];

        let mut conn = MockConn::new();
        let mut session = IscsiSession::default();
        let mut work = vec![0u8; WORK_LEN];
        login(&mut conn, &mut session, &mut work, &mut devs, &mut planes);

        conn.feed(&report_luns_bhs(1, 0xCAFE, 0), &[]);
        assert_eq!(
            session.run_once(&mut conn, &mut work, &mut devs, &mut planes),
            Outcome::Processed
        );
        let (_, data) = conn.take_pdu().unwrap();
        assert_eq!(&data[..4], &[0, 0, 0, 24]);
        // The single-level LUN id bytes — must include 0, 1, 2.
        let ids: Vec<u8> = (0..3).map(|i| data[8 + i * 8 + 1]).collect();
        assert_eq!(ids, vec![0, 1, 2]);
    }

    #[test]
    fn report_luns_on_unsupported_lun_check_condition() {
        // REPORT LUNS is a well-known command (SPC-3 §6.21) and must be
        // served from any LUN, even an unsupported one (M7).
        let mut ram = vec![0u8; 16 * 1024];
        let mut backend = RamBackend::new(&mut ram);
        let mut dev = BlockDevice::disk(&mut backend, 512).unwrap();
        let mut devs = [&mut dev as &mut dyn ScsiDevice];
        let mut planes = [Some(StorePlane::BlockRw(&mut backend))];

        let mut conn = MockConn::new();
        let mut session = IscsiSession::default();
        let mut work = vec![0u8; WORK_LEN];
        login(&mut conn, &mut session, &mut work, &mut devs, &mut planes);

        let mut cmd = report_luns_bhs(5, 0xDEAD, 0); // LUN 5 doesn't exist
        cmd[9] = 5;
        conn.feed(&cmd, &[]);
        assert_eq!(
            session.run_once(&mut conn, &mut work, &mut devs, &mut planes),
            Outcome::Processed
        );
        let (bhs, data) = conn.take_pdu().unwrap();
        assert_eq!(bhs[0] & 0x3F, op::SCSI_DATA_IN);
        assert_eq!(bhs[3], status::GOOD);
        assert_eq!(&bhs[16..20], &be32(0xDEAD)); // ITT echoed
        assert_eq!(&data[..4], &[0, 0, 0, 8]);
        assert_eq!(&data[8..16], &[0, 0, 0, 0, 0, 0, 0, 0]);
    }

    // ── Mixed heterogeneous LUNs: Device enum (Block + CdBlock) ───────

    fn inquiry_bhs(lun: u8, alloc: u8, itt: u32, cmd_sn: u32) -> [u8; 48] {
        let mut bhs = [0u8; 48];
        bhs[0] = op::SCSI_CMD;
        bhs[1] = 0x40;
        bhs[9] = lun; // single-level LUN id (BHS byte 9)
        bhs[16..20].copy_from_slice(&be32(itt));
        bhs[24..28].copy_from_slice(&be32(cmd_sn));
        bhs[28..32].copy_from_slice(&be32(cmd_sn));
        bhs[32] = 0x12; // INQUIRY
        bhs[36] = alloc; // allocation length (CDB byte 4)
        bhs
    }

    #[test]
    fn mixed_lun_block_and_cdblock_dispatch() {
        use snowscsi::common::seekable_storage::FlatRef;
        use snowscsi::scsi::backend::{BlockBackend, FileBackend};

        let dir = std::env::temp_dir();
        let iso = dir.join(format!("snowscsi_mock_cdblock_{}.iso", std::process::id()));
        std::fs::write(&iso, vec![0xCDu8; 2048 * 32]).unwrap();

        let mut ram = vec![0u8; 16 * 1024 * 1024];
        let mut b0 = RamBackend::new(&mut ram);
        let mut d0 = BlockDevice::disk(&mut b0, 512).unwrap();
        // Former `CDBlockDevice`: read-only optical profile over the ISO file.
        let mut bb_iso =
            BlockBackend::File(FileBackend::open(iso.to_str().unwrap(), false).unwrap());
        let mut d1 = BlockDevice::cdrom(&mut FlatRef::new(&mut bb_iso)).unwrap();
        let mut devs: [&mut dyn ScsiDevice; 2] = [&mut d0, &mut d1];
        // LUN 0 is writable RAM; LUN 1 is the read-only optical profile over
        // the ISO file (a `BlockDevice`, so it still yields `Store` ops).
        let mut planes: [Option<StorePlane<'_>>; 2] = [
            Some(StorePlane::BlockRw(&mut b0)),
            Some(StorePlane::BlockRo(&mut bb_iso)),
        ];

        let mut conn = MockConn::new();
        let mut session = IscsiSession::default();
        let mut work = vec![0u8; WORK_LEN];
        login(&mut conn, &mut session, &mut work, &mut devs, &mut planes);

        // INQUIRY LUN 0 → PDT 0x00 (disk).
        conn.feed(&inquiry_bhs(0, 96, 0x0101, 0), &[]);
        assert_eq!(
            session.run_once(&mut conn, &mut work, &mut devs, &mut planes),
            Outcome::Processed
        );
        let (bhs, data) = conn.take_pdu().unwrap();
        assert_eq!(bhs[0] & 0x3F, op::SCSI_DATA_IN);
        assert_eq!(bhs[3], status::GOOD);
        assert_eq!(data[0], 0x00, "LUN 0 must report PDT 0x00");

        // INQUIRY LUN 1 → PDT 0x05 (CD-ROM).
        conn.feed(&inquiry_bhs(1, 96, 0x0102, 1), &[]);
        assert_eq!(
            session.run_once(&mut conn, &mut work, &mut devs, &mut planes),
            Outcome::Processed
        );
        let (bhs, data) = conn.take_pdu().unwrap();
        assert_eq!(bhs[0] & 0x3F, op::SCSI_DATA_IN);
        assert_eq!(data[0], 0x05, "LUN 1 must report PDT 0x05");

        // READ(10) LUN 1, LBA 0, 1 sector → the ISO image bytes stream back.
        let mut read = read10_bhs(0, 1, 0x0201, 2);
        read[9] = 1;
        conn.feed(&read, &[]);
        assert_eq!(
            session.run_once(&mut conn, &mut work, &mut devs, &mut planes),
            Outcome::Processed
        );
        let (bhs, data) = conn.take_pdu().unwrap();
        assert_eq!(bhs[0] & 0x3F, op::SCSI_DATA_IN);
        assert_eq!(bhs[3], status::GOOD);
        assert_eq!(data.len(), 2048);
        assert_eq!(&data[..4], &[0xCD; 4]);

        // WRITE(10) to the read-only CD-ROM LUN → CHECK CONDITION.
        let mut write = write10_bhs(0, 1, 0x0301, 3, 0);
        write[9] = 1;
        conn.feed(&write, &[]);
        assert_eq!(
            session.run_once(&mut conn, &mut work, &mut devs, &mut planes),
            Outcome::Processed
        );
        let (bhs, _) = conn.take_pdu().unwrap();
        assert_eq!(bhs[0] & 0x3F, op::SCSI_RESP);
        assert_eq!(bhs[3], status::CHECK_CONDITION);

        // REPORT LUNS lists both LUNs (target-wide, from LUN 0).
        conn.feed(&report_luns_bhs(0, 0x0401, 4), &[]);
        assert_eq!(
            session.run_once(&mut conn, &mut work, &mut devs, &mut planes),
            Outcome::Processed
        );
        let (_, data) = conn.take_pdu().unwrap();
        assert_eq!(&data[..4], &[0, 0, 0, 16]); /* 2 × 8-byte LUN entries */
        assert_eq!(data[8 + 1], 0); /* LUN 0 id */
        assert_eq!(data[16 + 1], 1); /* LUN 1 id */

        let _ = std::fs::remove_file(&iso);
    }

    // ── Mixed heterogeneous LUNs (Block + CdromDrive Flat + Live) ──

    #[test]
    fn mixed_lun_block_cdrom_flat_and_live_dispatch() {
        use snowscsi::cdrom::drive::CdromDrive;
        use snowscsi::cdrom::media::{CdMedia, LiveData};
        use snowscsi::scsi::backend::{BlockBackend, FileBackend};
        use snowscsi::scsi::fs_backend::StdFsBackend;

        // LUN 1 source: a flat ISO file (0xCD sectors).
        let dir = std::env::temp_dir();
        let iso = dir.join(format!("snowscsi_mock_cdflat_{}.iso", std::process::id()));
        std::fs::write(&iso, vec![0xCDu8; 2048 * 32]).unwrap();

        // LUN 2 source: a live directory tree with one file (DATA.BIN).
        let tree = dir.join(format!("snowscsi_mock_live_{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&tree);
        std::fs::create_dir_all(&tree).unwrap();
        std::fs::write(tree.join("DATA.BIN"), vec![0x42u8; 4096]).unwrap();

        // Extract the live file's LBA before lending the scanner to the drive.
        let mut live = LiveData::new(StdFsBackend::new(&tree.to_string_lossy()), "TEST").unwrap();
        let live_lba = live.layout().extents[0].lba;

        let mut ram = vec![0u8; 16 * 1024 * 1024];
        let mut b0 = RamBackend::new(&mut ram);
        let mut d0 = BlockDevice::disk(&mut b0, 512).unwrap();

        // LUN 1: flat CD-ROM via CdromDrive over the ISO file plane
        let mut bb_flat =
            BlockBackend::File(FileBackend::open(iso.to_str().unwrap(), false).unwrap());
        let mut drive1 = CdromDrive::new();
        drive1.load_quiet(CdMedia::ro(&mut bb_flat));

        // LUN 2: live CD-ROM via CdromDrive over the generated ISO9660 plane
        let mut drive2 = CdromDrive::new();
        drive2.load_quiet(CdMedia::ro(&mut live));

        let mut devs: [&mut dyn ScsiDevice; 3] = [&mut d0, &mut drive1, &mut drive2];
        // The cdrom LUNs now carry real read-only store planes: the drives'
        // READ data phase is handed to the session as `StoreOp::Read` (the
        // media holds only geometry, never the backend).
        let mut planes: [Option<StorePlane<'_>>; 3] = [
            Some(StorePlane::BlockRw(&mut b0)),
            Some(StorePlane::BlockRo(&mut bb_flat)),
            Some(StorePlane::BlockRo(&mut live)),
        ];

        let mut conn = MockConn::new();
        let mut session = IscsiSession::default();
        let mut work = vec![0u8; WORK_LEN];
        login(&mut conn, &mut session, &mut work, &mut devs, &mut planes);

        // INQUIRY: LUN 0 → PDT 0x00, LUN 1/2 → PDT 0x05.
        for (lun, pdt) in [(0u8, 0x00u8), (1, 0x05), (2, 0x05)] {
            conn.feed(&inquiry_bhs(lun, 96, 0x0100 + lun as u32, lun as u32), &[]);
            assert_eq!(
                session.run_once(&mut conn, &mut work, &mut devs, &mut planes),
                Outcome::Processed
            );
            let (bhs, data) = conn.take_pdu().unwrap();
            assert_eq!(bhs[0] & 0x3F, op::SCSI_DATA_IN);
            assert_eq!(bhs[3], status::GOOD);
            assert_eq!(data[0], pdt, "LUN {lun} must report PDT {pdt:#x}");
        }

        // READ(10) LUN 1, LBA 0, 1 sector → the flat ISO bytes stream back.
        let mut read = read10_bhs(0, 1, 0x0201, 3);
        read[9] = 1;
        conn.feed(&read, &[]);
        assert_eq!(
            session.run_once(&mut conn, &mut work, &mut devs, &mut planes),
            Outcome::Processed
        );
        let (bhs, data) = conn.take_pdu().unwrap();
        assert_eq!(bhs[0] & 0x3F, op::SCSI_DATA_IN);
        assert_eq!(bhs[3], status::GOOD);
        assert_eq!(data.len(), 2048);
        assert_eq!(&data[..4], &[0xCD; 4]);

        // READ(10) LUN 2 at the live file's LBA → DATA.BIN content (0x42).
        let mut read = read10_bhs(live_lba, 1, 0x0202, 4);
        read[9] = 2;
        conn.feed(&read, &[]);
        assert_eq!(
            session.run_once(&mut conn, &mut work, &mut devs, &mut planes),
            Outcome::Processed
        );
        let (bhs, data) = conn.take_pdu().unwrap();
        assert_eq!(bhs[0] & 0x3F, op::SCSI_DATA_IN);
        assert_eq!(bhs[3], status::GOOD);
        assert_eq!(data.len(), 2048);
        assert_eq!(&data[..4], &[0x42; 4]);

        // WRITE(10) to either read-only CD-ROM LUN → CHECK CONDITION.
        let mut write = write10_bhs(0, 1, 0x0301, 5, 0);
        write[9] = 2;
        conn.feed(&write, &[]);
        assert_eq!(
            session.run_once(&mut conn, &mut work, &mut devs, &mut planes),
            Outcome::Processed
        );
        let (bhs, _) = conn.take_pdu().unwrap();
        assert_eq!(bhs[0] & 0x3F, op::SCSI_RESP);
        assert_eq!(bhs[3], status::CHECK_CONDITION);

        // REPORT LUNS lists all three LUNs.
        conn.feed(&report_luns_bhs(0, 0x0401, 6), &[]);
        assert_eq!(
            session.run_once(&mut conn, &mut work, &mut devs, &mut planes),
            Outcome::Processed
        );
        let (_, data) = conn.take_pdu().unwrap();
        assert_eq!(&data[..4], &[0, 0, 0, 24]); /* 3 × 8-byte LUN entries */
        assert_eq!(data[8 + 1], 0);
        assert_eq!(data[16 + 1], 1);
        assert_eq!(data[24 + 1], 2);

        let _ = std::fs::remove_file(&iso);
        let _ = std::fs::remove_dir_all(&tree);
    }

    /// FORMAT UNIT's whole-disc `Fill` must run through the iSCSI **session**
    /// agenda (never inline in the device). Pre-fill the plane with a pattern
    /// so a no-op FORMAT is detectable, drive FORMAT through the session, and
    /// assert the plane is zero afterwards. (No iSCSI golden fixture exercises
    /// a non-`None` agenda: they all use `BlockDevice`.)
    #[test]
    fn format_unit_zeroes_the_plane_via_the_iscsi_agenda() {
        use snowscsi::cdrom::dvdram::DvdRamMedia;
        use snowscsi::cdrom::{CdMedia, CdromDrive, HYPER_MULTI_CAPS};

        let mut ram = vec![0x5Au8; 1 << 20];
        let mut be = RamBackend::new(&mut ram);
        let mut drive = CdromDrive::builder().capabilities(HYPER_MULTI_CAPS).build();
        let _ = drive.load_quiet(CdMedia::Rw(DvdRamMedia::open(&mut be)));

        let mut devs: [&mut dyn ScsiDevice; 1] = [&mut drive];
        let mut planes: [Option<StorePlane<'_>>; 1] = [Some(StorePlane::BlockRw(&mut be))];

        let mut conn = MockConn::new();
        let mut session = IscsiSession::default();
        let mut work = vec![0u8; WORK_LEN];
        login(&mut conn, &mut session, &mut work, &mut devs, &mut planes);

        // Consume CmdSN 0 with a no-data INQUIRY.
        conn.feed(&inquiry_bhs(0, 96, 0x0100, 0), &[]);
        assert_eq!(
            session.run_once(&mut conn, &mut work, &mut devs, &mut planes),
            Outcome::Processed
        );
        let _ = conn.take_pdu();

        // FORMAT UNIT (0x04) + its 12-byte format parameter list as immediate
        // data (ImmediateData=Yes).
        let mut bhs = [0u8; 48];
        bhs[0] = op::SCSI_CMD;
        bhs[1] = 0xA1; // F | W | ATTR_SIMPLE
        bhs[7] = 12; // dsl
        bhs[16..20].copy_from_slice(&be32(0x0200));
        bhs[24..28].copy_from_slice(&be32(1)); // CmdSN
        bhs[28..32].copy_from_slice(&be32(1)); // ExpStatSN
        bhs[32] = 0x04; // FORMAT UNIT
        bhs[33] = 0x11; // FMTDAT (matches the USB golden scenario ⑬ CDB)
        let param = [
            0x00, 0x00, 0x00, 0x08, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x08, 0x00,
        ];
        conn.feed(&bhs, &param);
        assert_eq!(
            session.run_once(&mut conn, &mut work, &mut devs, &mut planes),
            Outcome::Processed
        );
        let (rbhs, _) = conn.take_pdu().unwrap();
        assert_eq!(rbhs[0] & 0x3F, op::SCSI_RESP);
        assert_eq!(rbhs[3], status::GOOD);

        // The session drained the FORMAT `Fill` agenda through the plane.
        let mut check = vec![0u8; 1 << 20];
        planes[0]
            .as_mut()
            .unwrap()
            .do_op(StoreOp::Read {
                off: 0,
                buf: &mut check,
            })
            .unwrap();
        assert!(
            check.iter().all(|&b| b == 0),
            "FORMAT must zero-fill the plane through the iSCSI session agenda"
        );
    }

    // ── ParamOut / DataOut LUN routing (O7 regression) ────────────────

    fn mode_select6_bhs(lun: u8, alloc: u8, itt: u32, cmd_sn: u32, dsl: u32) -> [u8; 48] {
        let mut bhs = [0u8; 48];
        bhs[0] = op::SCSI_CMD;
        bhs[1] = 0x20; // W bit
        bhs[5] = (dsl >> 16) as u8;
        bhs[6] = (dsl >> 8) as u8;
        bhs[7] = dsl as u8;
        bhs[9] = lun;
        bhs[16..20].copy_from_slice(&be32(itt));
        bhs[24..28].copy_from_slice(&be32(cmd_sn));
        bhs[28..32].copy_from_slice(&be32(cmd_sn));
        bhs[32] = 0x15; // MODE SELECT(6)
        bhs[36] = alloc;
        bhs
    }

    struct TrackingParamDevice {
        lun: usize,
        calls: std::sync::Arc<std::sync::Mutex<Vec<usize>>>,
        sense: Option<snowscsi::scsi::scsi::Sense>,
    }

    impl snowscsi::scsi::device::ScsiDevice for TrackingParamDevice {
        fn do_cmd(
            &mut self,
            cdb: &[u8],
            data: &mut [u8],
        ) -> Result<snowscsi::scsi::device::CommandOutcome, snowscsi::scsi::device::Error> {
            if data.len() < snowscsi::MIN_DATA_LEN {
                return Err(snowscsi::scsi::device::Error::WorkBufTooSmall);
            }
            if cdb.first() == Some(&0x15) {
                let alloc = cdb[4] as usize;
                if alloc == 0 {
                    return Ok(snowscsi::scsi::device::CommandOutcome::Status);
                }
                return Ok(snowscsi::scsi::device::CommandOutcome::InParam {
                    expected_len: alloc,
                });
            }
            Ok(snowscsi::scsi::device::CommandOutcome::Status)
        }

        fn xfer_out<'a>(&'a mut self, _transfer_offset: u64, buf: &'a mut [u8]) -> Xfer<'a> {
            Xfer::Inline { len: buf.len() }
        }

        fn xfer_in<'a>(&'a mut self, _transfer_offset: u64, buf: &'a [u8]) -> Xfer<'a> {
            Xfer::Inline { len: buf.len() }
        }

        fn peek_sense(&self) -> Option<&snowscsi::scsi::scsi::Sense> {
            self.sense.as_ref()
        }

        fn take_sense(&mut self) -> Option<snowscsi::scsi::scsi::Sense> {
            self.sense.take()
        }

        fn device_type(&self) -> snowscsi::scsi::device::DeviceType {
            snowscsi::scsi::device::DeviceType::Block
        }

        fn complete_param(
            &mut self,
            _cdb: &[u8],
            _data: &[u8],
        ) -> snowscsi::scsi::device::CommandOutcome {
            self.calls.lock().unwrap().push(self.lun);
            snowscsi::scsi::device::CommandOutcome::Status
        }
    }

    #[test]
    fn param_out_immediate_routes_by_lun() {
        let mut conn = MockConn::new();
        let mut session = IscsiSession::default();
        let mut work = vec![0u8; WORK_LEN];
        let calls = std::sync::Arc::new(std::sync::Mutex::new(Vec::new()));
        let mut d0 = TrackingParamDevice {
            lun: 0,
            calls: calls.clone(),
            sense: None,
        };
        let mut d1 = TrackingParamDevice {
            lun: 1,
            calls: calls.clone(),
            sense: None,
        };
        let mut devs: [&mut dyn ScsiDevice; 2] = [&mut d0, &mut d1];
        let mut planes: [Option<StorePlane<'_>>; 2] = [None, None];
        login(&mut conn, &mut session, &mut work, &mut devs, &mut planes);

        // MODE SELECT(6) to LUN 1 with all 12 bytes immediate — handle_scsi_cmd immediate path.
        let itt = 0xA1A1;
        let param = vec![0xAAu8; 12];
        let bhs = mode_select6_bhs(1, 12, itt, 0, 12);
        conn.feed_padded(&bhs, &param);
        assert_eq!(
            session.run_once(&mut conn, &mut work, &mut devs, &mut planes),
            Outcome::Processed
        );
        let (bhs, _) = conn.take_pdu().unwrap();
        assert_eq!(bhs[0] & 0x3F, op::SCSI_RESP);
        assert_eq!(bhs[3], status::GOOD);
        let v = calls.lock().unwrap().clone();
        assert_eq!(
            v,
            vec![1],
            "immediate ParamOut must route to LUN 1, got {v:?}"
        );
    }

    #[test]
    fn param_out_r2t_routes_by_lun() {
        let mut conn = MockConn::new();
        let mut session = IscsiSession::default();
        let mut work = vec![0u8; WORK_LEN];
        let calls = std::sync::Arc::new(std::sync::Mutex::new(Vec::new()));
        let mut d0 = TrackingParamDevice {
            lun: 0,
            calls: calls.clone(),
            sense: None,
        };
        let mut d1 = TrackingParamDevice {
            lun: 1,
            calls: calls.clone(),
            sense: None,
        };
        let mut devs: [&mut dyn ScsiDevice; 2] = [&mut d0, &mut d1];
        let mut planes: [Option<StorePlane<'_>>; 2] = [None, None];
        login(&mut conn, &mut session, &mut work, &mut devs, &mut planes);

        // MODE SELECT(6) to LUN 1 with 6 of 12 bytes immediate — needs R2T.
        let itt = 0xB2B2;
        let imm = vec![0xBBu8; 6];
        let bhs = mode_select6_bhs(1, 12, itt, 0, 6);
        conn.feed_padded(&bhs, &imm);
        // Remaining 6 bytes via Data-Out.
        let rest = vec![0xCCu8; 6];
        let dout = dataout_bhs(itt, 1, 0, 6, 6);
        conn.feed_padded(&dout, &rest);
        assert_eq!(
            session.run_once(&mut conn, &mut work, &mut devs, &mut planes),
            Outcome::Processed
        );
        // Expect R2T then SCSI Response.
        let (r2t, _) = conn.take_pdu().unwrap();
        assert_eq!(r2t[0] & 0x3F, op::R2T);
        assert_eq!(&r2t[16..20], &be32(itt));
        assert_eq!(&r2t[40..44], &be32(6)); // BufferOffset
        let (resp, _) = conn.take_pdu().unwrap();
        assert_eq!(resp[0] & 0x3F, op::SCSI_RESP);
        assert_eq!(resp[3], status::GOOD);
        let v = calls.lock().unwrap().clone();
        assert_eq!(v, vec![1], "R2T ParamOut must route to LUN 1, got {v:?}");
    }

    #[test]
    fn data_out_r2t_routes_by_lun() {
        let mut conn = MockConn::new();
        let mut session = IscsiSession::default();
        let mut work = vec![0u8; WORK_LEN];
        let mut ram0 = vec![0u8; 16 * 1024];
        let mut ram1 = vec![0u8; 16 * 1024];
        let mut b0 = RamBackend::new(&mut ram0);
        let mut b1 = RamBackend::new(&mut ram1);
        let mut d0 = BlockDevice::disk(&mut b0, 512).unwrap();
        let mut d1 = BlockDevice::disk(&mut b1, 512).unwrap();
        let mut devs: [&mut dyn ScsiDevice; 2] = [&mut d0, &mut d1];
        let mut planes = [
            Some(StorePlane::BlockRw(&mut b0)),
            Some(StorePlane::BlockRw(&mut b1)),
        ];
        login(&mut conn, &mut session, &mut work, &mut devs, &mut planes);

        // WRITE(10) LUN 1, LBA 0, 1 block, no immediate — R2T path.
        let itt = 0xC3C3;
        let bhs = write10_bhs(0, 1, itt, 0, 0);
        let mut bhs1 = bhs;
        bhs1[9] = 1;
        conn.feed(&bhs1, &[]);
        let payload = vec![0x5Au8; 512];
        let dout = dataout_bhs(itt, 1, 0, 0, 512);
        conn.feed_padded(&dout, &payload);
        assert_eq!(
            session.run_once(&mut conn, &mut work, &mut devs, &mut planes),
            Outcome::Processed
        );
        let (r2t, _) = conn.take_pdu().unwrap();
        assert_eq!(r2t[0] & 0x3F, op::R2T);
        assert_eq!(&r2t[40..44], &be32(0));
        let (resp, _) = conn.take_pdu().unwrap();
        assert_eq!(resp[0] & 0x3F, op::SCSI_RESP);
        assert_eq!(resp[3], status::GOOD);
        // Verify via READ back.
        let read = read10_bhs(0, 1, 0xD1, 1);
        let mut read1 = read;
        read1[9] = 1;
        conn.feed(&read1, &[]);
        assert_eq!(
            session.run_once(&mut conn, &mut work, &mut devs, &mut planes),
            Outcome::Processed
        );
        let (_, data) = conn.take_pdu().unwrap();
        assert_eq!(data, payload, "LUN 1 data must match written payload");
        // LUN 0 should still be zero.
        let read0 = read10_bhs(0, 1, 0xD2, 2);
        conn.feed(&read0, &[]);
        assert_eq!(
            session.run_once(&mut conn, &mut work, &mut devs, &mut planes),
            Outcome::Processed
        );
        let (_, data0) = conn.take_pdu().unwrap();
        assert_eq!(data0, vec![0u8; 512], "LUN 0 must remain untouched");
    }

    #[test]
    fn large_read_non_aligned_chunks_via_session() {
        // Regression for O1: 262096 % 512 = 464, so a 307200-byte READ
        // (600 blocks) with a 256 KiB work buffer splits as 262096 + 45104.
        // The old `current_lba*512 + offset%512` skipped 512 bytes on the
        // second chunk; the fixed `base*512 + offset` is correct.
        let mut conn = MockConn::new();
        let mut session = IscsiSession::default();
        let mut work = vec![0u8; 256 * 1024];
        let mut ram = vec![0u8; 2 * 1024 * 1024];
        for (i, b) in ram.iter_mut().enumerate() {
            *b = (i % 251) as u8;
        }
        let expected = ram[0..600 * 512].to_vec();
        let mut backend = RamBackend::new(&mut ram);
        let mut dev = BlockDevice::disk(&mut backend, 512).unwrap();
        let mut devs = [&mut dev as &mut dyn ScsiDevice];
        let mut planes = [Some(StorePlane::BlockRw(&mut backend))];
        login(&mut conn, &mut session, &mut work, &mut devs, &mut planes);

        let cmd = read10_bhs(0, 600, 0x7777, 0);
        conn.feed(&cmd, &[]);
        assert_eq!(
            session.run_once(&mut conn, &mut work, &mut devs, &mut planes),
            Outcome::Processed
        );
        let mut collected = Vec::new();
        let mut saw_data_in = 0;
        let mut last_bo = 0u32;
        while let Some((bhs, data)) = conn.take_pdu() {
            if bhs[0] & 0x3F == op::SCSI_DATA_IN {
                let bo = u32::from_be_bytes([bhs[40], bhs[41], bhs[42], bhs[43]]);
                assert_eq!(bo, last_bo, "BufferOffset must be contiguous");
                last_bo += data.len() as u32;
                collected.extend_from_slice(&data);
                saw_data_in += 1;
                if bhs[1] & flag::F_BIT != 0 {
                    assert_ne!(bhs[1] & flag::S_BIT, 0, "final Data-In must have S bit");
                }
            }
        }
        assert!(
            saw_data_in >= 2,
            "expected >=2 Data-In PDUs, got {saw_data_in}"
        );
        assert_eq!(collected.len(), 600 * 512);
        assert_eq!(collected, expected, "large READ must be byte-exact");
    }
}
