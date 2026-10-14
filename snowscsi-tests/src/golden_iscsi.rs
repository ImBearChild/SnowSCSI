//! Golden wire-level scenarios for iSCSI — `__ASYNC_SEP_PLAN.md` §5.1.
//!
//! Each `#[test]` feeds a byte script into [`crate::golden::RecConn`], runs the
//! existing `serve_conn` driver, renders the recorded trace and calls
//! [`crate::golden::bless_or_check`] plus [`crate::golden::assert_well_formed`].
//!
//! The five scenarios (A–E, §5.1) are deterministic: a pinned `# config:`
//! header, a fixed ISID/CmdSN/ITT seed and a fixed login negotiation text.
//! Every script starts with the login exchange (the `kind=iscsi` guard requires
//! the first host→device PDU to be a `LOGIN_REQUEST`) and every script ends by
//! simply running out of bytes — `RecConn` returns EOF, which `serve_conn`
//! treats as a closed connection.
//!
//! The BHS builders below are local copies of `crate::mock`'s (which are
//! private to that module): the golden scenarios build raw wire bytes inline
//! (§5.1) rather than depending on any library builder.

use snowscsi::common::store::StorePlane;
use snowscsi::iscsi::pdu::{flag, op, stage, status, BHS_SIZE};
use snowscsi::iscsi::target::{serve_conn, IscsiSession};
use snowscsi::scsi::backend::RamBackend;
use snowscsi::scsi::block::BlockDevice;
use snowscsi::scsi::device::ScsiDevice;
use snowscsi::scsi::Luns;
use snowscsi::MIN_DATA_LEN;

use crate::golden::{self, RecConn};

/// Login parameters as sent by a Linux open-iscsi initiator (concatenated
/// literal preserves the embedded NUL separators). Identical to
/// `crate::mock::REQ_TEXT`; the negotiated result is `InitialR2T=Yes` /
/// `ImmediateData=Yes` (the target ORs `InitialR2T` with Yes and ANDs
/// `ImmediateData` with Yes), matching [`CONFIG`].
const REQ_TEXT: &str = "InitiatorName=iqn.1994-05.com.redhat:702f27e1da14\0InitiatorAlias=develop\0TargetName=iqn.1970-01.local.snowscsi:target\0SessionType=Normal\0HeaderDigest=None\0DataDigest=None\0DefaultTime2Wait=2\0DefaultTime2Retain=0\0IFMarker=No\0OFMarker=No\0ErrorRecoveryLevel=0\0InitialR2T=No\0ImmediateData=Yes\0MaxBurstLength=16776192\0FirstBurstLength=262144\0MaxOutstandingR2T=1\0MaxConnections=1\0DataPDUInOrder=Yes\0DataSequenceInOrder=Yes\0MaxRecvDataSegmentLength=262144\0";

/// Pinned config header shared by all five scenarios: the ISID matches the
/// login BHS ISID seed; the negotiated login parameters are `InitialR2T=Yes`
/// and `ImmediateData=Yes`.
const CONFIG: &str = "kind=iscsi isid=0x000123456789 initiator=iqn.1994-05.com.redhat:702f27e1da14 initial_r2t=yes immediate_data=yes luns=1";

/// iSCSI target scratch buffer: BHS header + data area.
const WORK_LEN: usize = MIN_DATA_LEN + BHS_SIZE;

/// iSCSI Target Transfer Tag used by the target (mirrors `target::TTT`).
const TTT: u32 = 1;

fn be32(v: u32) -> [u8; 4] {
    v.to_be_bytes()
}

/// Login Request BHS: I=1, T=1, CSG=1 (OpParam), NSG=3 (FullFeature), fixed
/// ISID `00 01 23 45 67 89` (matches [`CONFIG`]).
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

/// SCSI Command BHS for READ(10).
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

/// SCSI Command BHS for WRITE(10) with an immediate data segment (`dsl`).
fn write10_bhs(lba: u32, blocks: u16, itt: u32, cmd_sn: u32, dsl: u32) -> [u8; 48] {
    let mut bhs = [0u8; 48];
    bhs[0] = op::SCSI_CMD;
    // Linux-kernel write layout (RFC 3720 §2.3.3): F(0x80)|W(0x20)|Simple(0x01).
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

/// SCSI Command BHS for REQUEST SENSE(10) (CDB 0x03, allocation length `alloc`).
fn request_sense_bhs(alloc: u8, itt: u32, cmd_sn: u32) -> [u8; 48] {
    let mut bhs = [0u8; 48];
    bhs[0] = op::SCSI_CMD;
    bhs[1] = 0x40;
    bhs[16..20].copy_from_slice(&be32(itt));
    bhs[24..28].copy_from_slice(&be32(cmd_sn));
    bhs[28..32].copy_from_slice(&be32(cmd_sn)); // ExpStatSN
    bhs[32] = 0x03; // REQUEST SENSE
    bhs[36] = alloc;
    bhs
}

/// SCSI Command BHS for TEST UNIT READY (CDB 0x00).
fn tur_bhs(itt: u32, cmd_sn: u32) -> [u8; 48] {
    let mut bhs = [0u8; 48];
    bhs[0] = op::SCSI_CMD;
    bhs[1] = 0x40;
    bhs[16..20].copy_from_slice(&be32(itt));
    bhs[24..28].copy_from_slice(&be32(cmd_sn));
    bhs[28..32].copy_from_slice(&be32(cmd_sn)); // ExpStatSN
    bhs[32] = 0x00; // TEST UNIT READY
    bhs
}

/// SCSI Command BHS for REPORT LUNS (CDB 0xA0, allocation 2048) — target-level.
fn report_luns_bhs(lun: u8, itt: u32, cmd_sn: u32) -> [u8; 48] {
    let mut bhs = [0u8; 48];
    bhs[0] = op::SCSI_CMD;
    bhs[9] = lun; // BHS LUN — does not affect the LUN list
    bhs[16..20].copy_from_slice(&be32(itt));
    bhs[24..28].copy_from_slice(&be32(cmd_sn));
    bhs[28..32].copy_from_slice(&be32(cmd_sn));
    bhs[32] = 0xA0; // REPORT LUNS
    bhs[38] = 0x08; // allocation length = 0x0800 = 2048
    bhs
}

/// Queue the login exchange BHS + negotiation text.
fn feed_login(conn: &mut RecConn) {
    let text = REQ_TEXT.as_bytes();
    conn.feed_padded(&login_bhs(text.len() as u32), text);
}

/// One decoded device→host PDU: `(opcode, BHS(48), data segment)`.
struct RecPdu {
    op: u8,
    bhs: Vec<u8>,
    data: Vec<u8>,
}

impl RecPdu {
    fn be32(&self, off: usize) -> u32 {
        u32::from_be_bytes([
            self.bhs[off],
            self.bhs[off + 1],
            self.bhs[off + 2],
            self.bhs[off + 3],
        ])
    }
}

/// Split the recorded `tx` byte stream into PDUs (BHS + data + padding).
fn pdus(tx: &[u8]) -> Vec<RecPdu> {
    let mut out = Vec::new();
    let mut off = 0usize;
    while off + BHS_SIZE <= tx.len() {
        let bhs = &tx[off..off + BHS_SIZE];
        let dsl = ((bhs[5] as usize) << 16) | ((bhs[6] as usize) << 8) | bhs[7] as usize;
        let data_end = off + BHS_SIZE + dsl;
        if data_end > tx.len() {
            break;
        }
        let pad = (4 - (dsl & 3)) & 3;
        out.push(RecPdu {
            op: bhs[0] & 0x3F,
            bhs: bhs.to_vec(),
            data: tx[off + BHS_SIZE..data_end].to_vec(),
        });
        off = data_end + pad;
    }
    out
}

/// Build the scripted connection, run `serve_conn` to EOF/close, then render,
/// guard and bless/check the fixture. Returns the recorder for wire asserts.
fn run(name: &str, config: &str, ram: &mut [u8], script: impl FnOnce(&mut RecConn)) -> RecConn {
    let mut conn = RecConn::new();
    script(&mut conn);

    let mut work = vec![0u8; WORK_LEN];
    let mut session = IscsiSession::new();
    let mut backend = RamBackend::new(ram);
    let mut dev = BlockDevice::disk(&mut backend, 512).unwrap();
    let mut devs: [&mut dyn ScsiDevice; 1] = [&mut dev];
    let mut planes: [Option<StorePlane<'_>>; 1] = [Some(StorePlane::BlockRw(&mut backend))];
    let mut luns = Luns::new(&mut devs, &mut planes);
    serve_conn(&mut conn, &mut work, &mut session, &mut luns).expect("serve_conn returns Ok");

    let text = golden::render(config, &conn.trace);
    golden::assert_well_formed(name, &text);
    golden::bless_or_check(name, &text);
    conn
}

// ── A: login → FullFeature → logout ─────────────────────────────────

#[test]
fn iscsi_a_login_logout() {
    let mut ram = vec![0u8; 64 * 1024];
    let conn = run("iscsi_a_login_logout", CONFIG, &mut ram, |conn| {
        feed_login(conn);
        let mut lo = [0u8; 48];
        lo[0] = op::LOGOUT_REQ;
        lo[16..20].copy_from_slice(&be32(1)); // ITT
        conn.feed(&lo, &[]);
    });

    let ps = pdus(&conn.tx);
    assert_eq!(
        ps[0].op,
        op::LOGIN_RESP,
        "first response must be LOGIN_RESP"
    );
    assert_eq!(ps[1].op, op::LOGOUT_RESP, "logout must be answered");
    assert_eq!(ps[1].be32(16), 1, "LOGOUT_RESP must echo ITT=1");
    assert_eq!(ps.len(), 2, "no PDP after logout");
}

// ── B: READ(10) → Data-In (F|S, GOOD) ───────────────────────────────

#[test]
fn iscsi_b_read_data_in() {
    const ITT: u32 = 0x0000_0001;
    let mut ram: Vec<u8> = (0..64 * 1024u32).map(|i| (i & 0xFF) as u8).collect();
    let conn = run("iscsi_b_read_data_in", CONFIG, &mut ram, |conn| {
        feed_login(conn);
        conn.feed(&read10_bhs(0, 4, ITT, 0), &[]);
    });

    let ps = pdus(&conn.tx);
    assert_eq!(ps[0].op, op::LOGIN_RESP);
    let din = &ps[1];
    assert_eq!(din.op, op::SCSI_DATA_IN);
    assert_eq!(
        din.bhs[1] & (flag::F_BIT | flag::S_BIT),
        flag::F_BIT | flag::S_BIT,
        "final Data-In must set F|S"
    );
    assert_eq!(din.bhs[3], status::GOOD);
    assert_eq!(din.be32(16), ITT, "Data-In must echo ITT");
    assert_eq!(din.data.len(), 2048, "4 blocks × 512");
    assert_eq!(din.data.as_slice(), &ram[..2048]);
    assert_eq!(ps.len(), 2, "no separate SCSI_RESP after final Data-In");
}

// ── C: WRITE(10) immediate → R2T → Data-Out → response ──────────────

#[test]
fn iscsi_c_write_r2t_dataout() {
    const ITT: u32 = 0x0000_0002;
    let mut ram = vec![0u8; 64 * 1024];
    let imm: Vec<u8> = (0..512u32).map(|i| (i & 0xFF) as u8).collect();
    let out: Vec<u8> = (0x100..0x500u32).map(|i| (i & 0xFF) as u8).collect();
    let imm2 = imm.clone();
    let out2 = out.clone();

    let conn = run("iscsi_c_write_r2t_dataout", CONFIG, &mut ram, |conn| {
        feed_login(conn);
        conn.feed_padded(&write10_bhs(10, 3, ITT, 0, 512), &imm2);
        conn.feed_padded(&dataout_bhs(ITT, TTT, 0, 512, 1024), &out2);
    });

    let ps = pdus(&conn.tx);
    assert_eq!(ps[0].op, op::LOGIN_RESP);

    let r2t = ps
        .iter()
        .find(|p| p.op == op::R2T)
        .expect("R2T after immediate data");
    assert_eq!(r2t.be32(16), ITT, "R2T must echo ITT");
    assert_eq!(r2t.be32(20), TTT, "R2T TTT=1");
    assert_eq!(
        r2t.be32(40),
        512,
        "R2T BufferOffset after 512 immediate bytes"
    );
    assert_eq!(r2t.be32(44), 1024, "R2T DesiredLen = remaining 1024 bytes");

    let resp = ps
        .iter()
        .find(|p| p.op == op::SCSI_RESP)
        .expect("final SCSI_RESP");
    assert_eq!(resp.bhs[3], status::GOOD);
    assert_eq!(resp.be32(16), ITT, "SCSI_RESP must echo ITT");
    assert_eq!(resp.data, Vec::<u8>::new(), "GOOD response has no sense");

    // The write-through reached the backend: immediate + Data-Out bytes.
    let mut expect = imm.clone();
    expect.extend_from_slice(&out);
    assert_eq!(&ram[10 * 512..10 * 512 + 1536], expect.as_slice());
}

// ── D: out-of-range READ → CHECK CONDITION (+sense) → REQUEST SENSE ─

#[test]
fn iscsi_d_check_condition_sense() {
    const ITT_READ: u32 = 0x0000_0003;
    const ITT_SENSE: u32 = 0x0000_0004;
    let mut ram = vec![0u8; 64 * 1024];

    let conn = run("iscsi_d_check_condition_sense", CONFIG, &mut ram, |conn| {
        feed_login(conn);
        // LBA far beyond the 128-sector device.
        conn.feed(&read10_bhs(1 << 20, 1, ITT_READ, 0), &[]);
        conn.feed(&request_sense_bhs(18, ITT_SENSE, 1), &[]);
    });

    let ps = pdus(&conn.tx);
    assert_eq!(ps[0].op, op::LOGIN_RESP);

    let cc = ps
        .iter()
        .find(|p| p.op == op::SCSI_RESP)
        .expect("CHECK CONDITION response");
    assert_eq!(cc.bhs[3], status::CHECK_CONDITION);
    assert_eq!(cc.be32(16), ITT_READ);
    // Autosense data segment: 2-byte SenseLength (18) + fixed sense 70h.
    assert_eq!(&cc.data[0..2], &[0x00, 18]);
    assert_eq!(cc.data[2], 0x70, "fixed-format sense response code");
    assert_eq!(cc.data[4], 0x05, "ILLEGAL REQUEST");
    assert_eq!(cc.data[14], 0x21, "LBA OUT OF RANGE");

    // REQUEST SENSE(10) → GOOD Data-In carrying fixed-format sense data.
    let sense_in = ps
        .iter()
        .find(|p| p.op == op::SCSI_DATA_IN)
        .expect("REQUEST SENSE Data-In");
    assert_eq!(sense_in.bhs[3], status::GOOD);
    assert_eq!(
        sense_in.bhs[1] & (flag::F_BIT | flag::S_BIT),
        flag::F_BIT | flag::S_BIT
    );
    assert_eq!(sense_in.be32(16), ITT_SENSE, "sense Data-In must echo ITT");
    assert_eq!(sense_in.data.len(), 18, "allocation length 18");
    assert_eq!(sense_in.data[0], 0x70, "fixed-format sense response code");
    assert_eq!(sense_in.data[7], 0x0A, "additional sense length");
    // The CHECK CONDITION above carried the sense as iSCSI autosense in the
    // SCSI Response and consumed it (`take_sense()` clears the device — cf.
    // whitebox `out_of_range_sense_is_consumed`), so this REQUEST SENSE
    // reports the cleared (NO SENSE) fixed buffer. The ILLEGAL REQUEST / LBA
    // OUT OF RANGE key is asserted on the autosense above.
    assert_eq!(sense_in.data[2], 0x00, "sense key = NO SENSE (consumed)");
    assert_eq!(sense_in.data[12], 0x00, "ASC cleared");
}

// ── E: TEST UNIT READY → GOOD; REPORT LUNS → one LUN ────────────────

#[test]
fn iscsi_e_tur_report_luns() {
    const ITT_TUR: u32 = 0x0000_0005;
    const ITT_RLUNS: u32 = 0x0000_0006;
    let mut ram = vec![0u8; 64 * 1024];

    let conn = run("iscsi_e_tur_report_luns", CONFIG, &mut ram, |conn| {
        feed_login(conn);
        conn.feed(&tur_bhs(ITT_TUR, 0), &[]);
        conn.feed(&report_luns_bhs(0, ITT_RLUNS, 1), &[]);
    });

    let ps = pdus(&conn.tx);
    assert_eq!(ps[0].op, op::LOGIN_RESP);

    let tur = ps
        .iter()
        .find(|p| p.op == op::SCSI_RESP)
        .expect("TUR response");
    assert_eq!(tur.bhs[3], status::GOOD);
    assert_eq!(tur.be32(16), ITT_TUR);

    let luns = ps
        .iter()
        .find(|p| p.op == op::SCSI_DATA_IN)
        .expect("REPORT LUNS Data-In");
    assert_eq!(luns.bhs[3], status::GOOD);
    assert_eq!(
        luns.bhs[1] & (flag::F_BIT | flag::S_BIT),
        flag::F_BIT | flag::S_BIT
    );
    assert_eq!(luns.be32(16), ITT_RLUNS);
    assert_eq!(&luns.data[..4], &[0, 0, 0, 8], "one 8-byte LUN entry");
    assert_eq!(&luns.data[4..8], &[0, 0, 0, 0]);
    assert_eq!(&luns.data[8..16], &[0, 0, 0, 0, 0, 0, 0, 0], "LUN 0");
}
