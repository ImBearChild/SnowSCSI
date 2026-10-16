//! Golden wire-level scenarios for USB MSC (BOT).
//!
//! Each `#[test]` drives one deterministic scenario through
//! [`crate::golden_drive::serve_usb`] (the library `usb::serve` loop),
//! renders the recorded trace and calls [`crate::golden::bless_or_check`] plus
//! [`crate::golden::assert_well_formed`].
//!
//! Scenarios are authored in `golden_usb`; the CBW/CDB byte helpers are the
//! `pub(crate)`-promoted ones from [`crate::usb_bot`] (raw bytes, not the
//! library's parse-only `Cbw`).
//!
//! The thirteen scenarios are the USB half of the recorded baseline: command
//! sequences (INQUIRY / READ single / READ multi-chunk / WRITE→READ),
//! write-through gating (write short residue, host overrun), the Data-In
//! shortfall policy matrix (Short / ShortNoStall / Pad), the invalid-CBW
//! STALL recovery, a write-protected LUN, multi-LUN alignment, and a DVD-RAM
//! FORMAT→READ→SYNC CACHE sequence.

use crate::golden::{self, InStep, TraceEntry, CSW_MAGIC};
use crate::golden_drive;
use crate::usb_bot::{block_device, raw_cbw, rw10};
use snowscsi::common::store::StorePlane;
use snowscsi::scsi::backend::RamBackend;
use snowscsi::scsi::device::ScsiDevice;
use snowscsi::scsi::Luns;
use snowscsi::usb::{BotSession, ShortfallPolicy, CSW_LEN};

/// Default scenario config: High-Speed BOT, no shortfall STALL, one LUN.
const CONFIG: &str = "kind=bot mps=512 policy=ShortNoStall luns=1";

/// Fixed deterministic backend pattern (`i % 251`), as pinned by §5.1.
fn pattern_ram(len: usize) -> Vec<u8> {
    (0..len).map(|i| (i % 251) as u8).collect()
}

/// Every 13-byte D2H entry carrying the CSW magic, in wire order.
fn csws(io: &golden::RecBotIo) -> Vec<&[u8]> {
    io.trace
        .iter()
        .filter_map(|e| match e {
            TraceEntry::D2H(b) if b.len() == CSW_LEN && b[..4] == CSW_MAGIC => Some(b.as_slice()),
            _ => None,
        })
        .collect()
}

/// Assert a CSW with `tag` exists and reports `residue` / `status`
/// (`tag` = bytes 4..8 LE, `residue` = bytes 8..12 LE, `status` = byte 12).
fn assert_csw(io: &golden::RecBotIo, tag: u32, residue: u32, status: u8) {
    let csw = csws(io)
        .into_iter()
        .find(|b| u32::from_le_bytes([b[4], b[5], b[6], b[7]]) == tag)
        .unwrap_or_else(|| panic!("no CSW with tag {tag}; trace: {:?}", io.trace));
    assert_eq!(
        u32::from_le_bytes([csw[8], csw[9], csw[10], csw[11]]),
        residue,
        "CSW tag {tag}: wrong residue"
    );
    assert_eq!(csw[12], status, "CSW tag {tag}: wrong status");
}

/// All D2H entries that are **not** CSWs, in wire order (data phases, ZLPs).
fn data_entries(io: &golden::RecBotIo) -> Vec<&[u8]> {
    io.trace
        .iter()
        .filter_map(|e| match e {
            TraceEntry::D2H(b) if !(b.len() == CSW_LEN && b[..4] == CSW_MAGIC) => {
                Some(b.as_slice())
            }
            _ => None,
        })
        .collect()
}

/// D2H data entries of exactly `len` bytes (not CSWs), in wire order.
fn data_chunks(io: &golden::RecBotIo, len: usize) -> Vec<&[u8]> {
    data_entries(io)
        .into_iter()
        .filter(|b| b.len() == len)
        .collect()
}

/// Render, guard, then bless-or-compare the recorded trace.
fn finish(name: &str, config: &str, io: &golden::RecBotIo) {
    let text = golden::render(config, &io.trace);
    golden::assert_well_formed(name, &text);
    golden::bless_or_check(name, &text);
}

/// ① INQUIRY (OutInline + CSW).
#[test]
fn usb_01_inquiry() {
    const NAME: &str = "usb_01_inquiry";
    let mut ram = pattern_ram(64 * 1024);
    let mut backend = RamBackend::new(&mut ram);
    let mut dev = block_device(&mut backend);
    let mut session = BotSession::new();
    let mut work = [0u8; snowscsi::MIN_DATA_LEN];
    let cdb = [0x12, 0, 0, 0, 36, 0];
    let (mut io, mut gadget) =
        golden::split(vec![InStep::Bytes(raw_cbw(1, 36, 0x80, 0, &cdb).to_vec())]);
    let mut devs: [&mut dyn ScsiDevice; 1] = [&mut dev];
    let mut planes: [Option<StorePlane<'_>>; 1] = [Some(StorePlane::BlockRw(&mut backend))];
    let mut luns = Luns::new(&mut devs, &mut planes);
    golden_drive::serve_usb(&mut io, &mut gadget, &mut session, &mut work, &mut luns);

    assert_eq!(data_chunks(&io, 36).len(), 1);
    assert_csw(&io, 1, 0, 0x00);
    finish(NAME, CONFIG, &io);
}

/// ② READ single block (512 bytes = one MPS multiple, no ZLP).
#[test]
fn usb_02_read_single_block() {
    const NAME: &str = "usb_02_read_single_block";
    let mut ram = pattern_ram(64 * 1024);
    let mut backend = RamBackend::new(&mut ram);
    let mut dev = block_device(&mut backend);
    let mut session = BotSession::new();
    let mut work = [0u8; snowscsi::MIN_DATA_LEN];
    let (mut io, mut gadget) = golden::split(vec![InStep::Bytes(
        raw_cbw(2, 512, 0x80, 0, &rw10(0x28, 0, 1)).to_vec(),
    )]);
    let mut devs: [&mut dyn ScsiDevice; 1] = [&mut dev];
    let mut planes: [Option<StorePlane<'_>>; 1] = [Some(StorePlane::BlockRw(&mut backend))];
    let mut luns = Luns::new(&mut devs, &mut planes);
    golden_drive::serve_usb(&mut io, &mut gadget, &mut session, &mut work, &mut luns);

    assert_eq!(data_chunks(&io, 512).len(), 1);
    assert_csw(&io, 2, 0, 0x00);
    finish(NAME, CONFIG, &io);
}

/// ③ READ 40 blocks (20480 bytes) → three Data-In chunks (8192, 8192, 4096).
#[test]
fn usb_03_read_three_chunks() {
    const NAME: &str = "usb_03_read_three_chunks";
    let mut ram = pattern_ram(64 * 1024);
    let mut backend = RamBackend::new(&mut ram);
    let mut dev = block_device(&mut backend);
    let mut session = BotSession::new();
    let mut work = [0u8; snowscsi::MIN_DATA_LEN];
    let (mut io, mut gadget) = golden::split(vec![InStep::Bytes(
        raw_cbw(3, 20480, 0x80, 0, &rw10(0x28, 0, 40)).to_vec(),
    )]);
    let mut devs: [&mut dyn ScsiDevice; 1] = [&mut dev];
    let mut planes: [Option<StorePlane<'_>>; 1] = [Some(StorePlane::BlockRw(&mut backend))];
    let mut luns = Luns::new(&mut devs, &mut planes);
    golden_drive::serve_usb(&mut io, &mut gadget, &mut session, &mut work, &mut luns);

    let lens: Vec<usize> = data_entries(&io).iter().map(|b| b.len()).collect();
    assert_eq!(lens, vec![8192, 8192, 4096], "chunk split");
    assert_csw(&io, 3, 0, 0x00);
    finish(NAME, CONFIG, &io);
}

/// ④ WRITE then READ back (locks write-through on one script).
#[test]
fn usb_04_write_then_read() {
    const NAME: &str = "usb_04_write_then_read";
    let mut ram = pattern_ram(64 * 1024);
    let mut backend = RamBackend::new(&mut ram);
    let mut dev = block_device(&mut backend);
    let mut session = BotSession::new();
    let mut work = [0u8; snowscsi::MIN_DATA_LEN];
    let payload: Vec<u8> = (0..512).map(|i| (i * 7 % 256) as u8).collect();
    let (mut io, mut gadget) = golden::split(vec![
        InStep::Bytes(raw_cbw(4, 512, 0x00, 0, &rw10(0x2A, 1, 1)).to_vec()),
        InStep::Bytes(payload.clone()),
        InStep::WouldBlock,
        InStep::Bytes(raw_cbw(5, 512, 0x80, 0, &rw10(0x28, 1, 1)).to_vec()),
    ]);
    let mut devs: [&mut dyn ScsiDevice; 1] = [&mut dev];
    let mut planes: [Option<StorePlane<'_>>; 1] = [Some(StorePlane::BlockRw(&mut backend))];
    let mut luns = Luns::new(&mut devs, &mut planes);
    golden_drive::serve_usb(&mut io, &mut gadget, &mut session, &mut work, &mut luns);

    assert_csw(&io, 4, 0, 0x00);
    assert_csw(&io, 5, 0, 0x00);
    let reads = data_chunks(&io, 512);
    assert_eq!(reads.len(), 1, "one read-back chunk");
    assert_eq!(reads[0], payload.as_slice(), "read-back equals the write");
    finish(NAME, CONFIG, &io);
}

/// ⑤ Write short residue: CBW declares 1024, CDB writes one 512-byte block.
#[test]
fn usb_05_write_short_residue() {
    const NAME: &str = "usb_05_write_short_residue";
    let mut ram = pattern_ram(64 * 1024);
    let mut backend = RamBackend::new(&mut ram);
    let mut dev = block_device(&mut backend);
    let mut session = BotSession::new();
    let mut work = [0u8; snowscsi::MIN_DATA_LEN];
    let payload = vec![0x5Au8; 1024];
    let (mut io, mut gadget) = golden::split(vec![
        InStep::Bytes(raw_cbw(1, 1024, 0x00, 0, &rw10(0x2A, 0, 1)).to_vec()),
        InStep::Bytes(payload),
        InStep::WouldBlock,
    ]);
    let mut devs: [&mut dyn ScsiDevice; 1] = [&mut dev];
    let mut planes: [Option<StorePlane<'_>>; 1] = [Some(StorePlane::BlockRw(&mut backend))];
    let mut luns = Luns::new(&mut devs, &mut planes);
    golden_drive::serve_usb(&mut io, &mut gadget, &mut session, &mut work, &mut luns);

    assert_csw(&io, 1, 512, 0x00);
    finish(NAME, CONFIG, &io);
}

/// ⑥ `Short` Data-In shortfall: 512 data, ZLP, Bulk-In STALL, then the CSW.
#[test]
fn usb_06_shortfall_short() {
    const NAME: &str = "usb_06_shortfall_short";
    const SHORT_CONFIG: &str = "kind=bot mps=512 policy=Short luns=1";
    let mut ram = pattern_ram(64 * 1024);
    let mut backend = RamBackend::new(&mut ram);
    let mut dev = block_device(&mut backend);
    let mut session = BotSession::new().with_shortfall(ShortfallPolicy::Short);
    let mut work = [0u8; snowscsi::MIN_DATA_LEN];
    let (mut io, mut gadget) = golden::split(vec![InStep::Bytes(
        raw_cbw(1, 1024, 0x80, 0, &rw10(0x28, 0, 1)).to_vec(),
    )]);
    let mut devs: [&mut dyn ScsiDevice; 1] = [&mut dev];
    let mut planes: [Option<StorePlane<'_>>; 1] = [Some(StorePlane::BlockRw(&mut backend))];
    let mut luns = Luns::new(&mut devs, &mut planes);
    golden_drive::serve_usb(&mut io, &mut gadget, &mut session, &mut work, &mut luns);

    assert_eq!(data_chunks(&io, 512).len(), 1, "512 relevant bytes");
    assert!(
        data_entries(&io).iter().any(|b| b.is_empty()),
        "empty ZLP before the STALL"
    );
    assert!(
        io.trace.contains(&TraceEntry::Mark("stall_in")),
        "Bulk-In STALL applied"
    );
    assert_csw(&io, 1, 512, 0x00);
    finish(NAME, SHORT_CONFIG, &io);
}

/// ⑦ `ShortNoStall` (default): INQUIRY 95 vs declared 192 → short packet.
#[test]
fn usb_07_shortfall_short_no_stall() {
    const NAME: &str = "usb_07_shortfall_short_no_stall";
    let mut ram = pattern_ram(64 * 1024);
    let mut backend = RamBackend::new(&mut ram);
    let mut dev = block_device(&mut backend);
    let mut session = BotSession::new();
    let mut work = [0u8; snowscsi::MIN_DATA_LEN];
    let (mut io, mut gadget) = golden::split(vec![InStep::Bytes(
        raw_cbw(2, 192, 0x80, 0, &[0x12, 0, 0, 0, 95, 0]).to_vec(),
    )]);
    let mut devs: [&mut dyn ScsiDevice; 1] = [&mut dev];
    let mut planes: [Option<StorePlane<'_>>; 1] = [Some(StorePlane::BlockRw(&mut backend))];
    let mut luns = Luns::new(&mut devs, &mut planes);
    golden_drive::serve_usb(&mut io, &mut gadget, &mut session, &mut work, &mut luns);

    assert_eq!(data_chunks(&io, 95).len(), 1, "short packet is 95 bytes");
    assert_csw(&io, 2, 97, 0x00);
    finish(NAME, CONFIG, &io);
}

/// ⑧ `Pad`: the 95-byte response is zero-padded to 192 in-buffer.
#[test]
fn usb_08_shortfall_pad() {
    const NAME: &str = "usb_08_shortfall_pad";
    const PAD_CONFIG: &str = "kind=bot mps=512 policy=Pad luns=1";
    let mut ram = pattern_ram(64 * 1024);
    let mut backend = RamBackend::new(&mut ram);
    let mut dev = block_device(&mut backend);
    let mut session = BotSession::new().with_shortfall(ShortfallPolicy::Pad);
    let mut work = [0u8; snowscsi::MIN_DATA_LEN];
    let (mut io, mut gadget) = golden::split(vec![InStep::Bytes(
        raw_cbw(2, 192, 0x80, 0, &[0x12, 0, 0, 0, 95, 0]).to_vec(),
    )]);
    let mut devs: [&mut dyn ScsiDevice; 1] = [&mut dev];
    let mut planes: [Option<StorePlane<'_>>; 1] = [Some(StorePlane::BlockRw(&mut backend))];
    let mut luns = Luns::new(&mut devs, &mut planes);
    golden_drive::serve_usb(&mut io, &mut gadget, &mut session, &mut work, &mut luns);

    let padded = data_chunks(&io, 192);
    assert_eq!(padded.len(), 1, "padded wire line is 192 bytes");
    assert!(
        padded[0][95..].iter().all(|&b| b == 0),
        "the 97 fill bytes are zero"
    );
    assert_csw(&io, 2, 97, 0x00);
    finish(NAME, PAD_CONFIG, &io);
}

/// ⑨ Host write overrun: 512 declared, a full extra 8192-byte chunk, then idle.
#[test]
fn usb_09_write_overrun() {
    const NAME: &str = "usb_09_write_overrun";
    let mut ram = pattern_ram(64 * 1024);
    let mut backend = RamBackend::new(&mut ram);
    let mut dev = block_device(&mut backend);
    let mut session = BotSession::new();
    let mut work = [0u8; snowscsi::MIN_DATA_LEN];
    let (mut io, mut gadget) = golden::split(vec![
        InStep::Bytes(raw_cbw(1, 512, 0x00, 0, &rw10(0x2A, 0, 1)).to_vec()),
        InStep::Bytes(vec![0x5A; 512]),
        InStep::Bytes(vec![0x6B; 8192]),
        InStep::WouldBlock,
    ]);
    let mut devs: [&mut dyn ScsiDevice; 1] = [&mut dev];
    let mut planes: [Option<StorePlane<'_>>; 1] = [Some(StorePlane::BlockRw(&mut backend))];
    let mut luns = Luns::new(&mut devs, &mut planes);
    golden_drive::serve_usb(&mut io, &mut gadget, &mut session, &mut work, &mut luns);

    // The extra 8192 bytes were drained, so only the declared 512 were written.
    assert_csw(&io, 1, 0, 0x00);
    finish(NAME, CONFIG, &io);
}

/// ⑩ Invalid CBW → `stall_both` → next valid CBW (implicit clear-halt).
#[test]
fn usb_10_invalid_cbw() {
    const NAME: &str = "usb_10_invalid_cbw";
    let mut ram = pattern_ram(64 * 1024);
    let mut backend = RamBackend::new(&mut ram);
    let mut dev = block_device(&mut backend);
    let mut session = BotSession::new();
    let mut work = [0u8; snowscsi::MIN_DATA_LEN];
    let mut bad = raw_cbw(1, 0, 0, 0, &[0, 0, 0, 0, 0, 0]);
    bad[0] = b'X';
    let (mut io, mut gadget) = golden::split(vec![
        InStep::Bytes(bad.to_vec()),
        InStep::Bytes(raw_cbw(2, 36, 0x80, 0, &[0x12, 0, 0, 0, 36, 0]).to_vec()),
    ]);
    let mut devs: [&mut dyn ScsiDevice; 1] = [&mut dev];
    let mut planes: [Option<StorePlane<'_>>; 1] = [Some(StorePlane::BlockRw(&mut backend))];
    let mut luns = Luns::new(&mut devs, &mut planes);
    golden_drive::serve_usb(&mut io, &mut gadget, &mut session, &mut work, &mut luns);

    assert!(
        io.trace.contains(&TraceEntry::Mark("stall_both")),
        "both pipes STALLed"
    );
    assert_eq!(csws(&io).len(), 1, "no CSW for the invalid CBW");
    assert_csw(&io, 2, 0, 0x00);
    finish(NAME, CONFIG, &io);
}

/// ⑪ Write-protected LUN: Failed (DATA PROTECT), then REQUEST SENSE.
#[test]
fn usb_11_write_read_only() {
    const NAME: &str = "usb_11_write_read_only";
    let mut ram = pattern_ram(64 * 1024);
    let mut backend = RamBackend::new(&mut ram);
    let mut dev = block_device(&mut backend);
    dev.set_writable(false);
    let mut session = BotSession::new();
    let mut work = [0u8; snowscsi::MIN_DATA_LEN];
    let (mut io, mut gadget) = golden::split(vec![
        InStep::Bytes(raw_cbw(1, 512, 0x00, 0, &rw10(0x2A, 0, 1)).to_vec()),
        InStep::Bytes(vec![0u8; 512]),
        InStep::WouldBlock,
        InStep::Bytes(raw_cbw(2, 18, 0x80, 0, &[0x03, 0, 0, 0, 18, 0]).to_vec()),
    ]);
    let mut devs: [&mut dyn ScsiDevice; 1] = [&mut dev];
    let mut planes: [Option<StorePlane<'_>>; 1] = [Some(StorePlane::BlockRw(&mut backend))];
    let mut luns = Luns::new(&mut devs, &mut planes);
    golden_drive::serve_usb(&mut io, &mut gadget, &mut session, &mut work, &mut luns);

    assert_csw(&io, 1, 512, 0x01); // Failed, declared drained (residue = declared)
    let sense = data_chunks(&io, 18);
    assert_eq!(sense.len(), 1, "18-byte sense after REQUEST SENSE");
    assert_eq!(sense[0][2], 0x07, "DATA PROTECT");
    assert_eq!(sense[0][12], 0x27, "WRITE PROTECTED");
    assert_csw(&io, 2, 0, 0x00);
    finish(NAME, CONFIG, &io);
}

/// ⑫ Multi-LUN alignment: write LUN0, then read both LUNs back.
#[test]
fn usb_12_multi_lun() {
    const NAME: &str = "usb_12_multi_lun";
    const TWO_LUNS: &str = "kind=bot mps=512 policy=ShortNoStall luns=2";
    let mut ram0 = vec![0x01u8; 64 * 1024];
    let mut ram1 = vec![0x02u8; 64 * 1024];
    let mut backend0 = RamBackend::new(&mut ram0);
    let mut backend1 = RamBackend::new(&mut ram1);
    let mut dev0 = block_device(&mut backend0);
    let mut dev1 = block_device(&mut backend1);
    let mut session = BotSession::with_luns(2);
    let mut work = [0u8; snowscsi::MIN_DATA_LEN];
    let payload = vec![0xABu8; 512];
    let (mut io, mut gadget) = golden::split(vec![
        InStep::Bytes(raw_cbw(1, 512, 0x00, 0, &rw10(0x2A, 0, 1)).to_vec()),
        InStep::Bytes(payload.clone()),
        InStep::WouldBlock,
        InStep::Bytes(raw_cbw(2, 512, 0x80, 0, &rw10(0x28, 0, 1)).to_vec()),
        InStep::Bytes(raw_cbw(3, 512, 0x80, 1, &rw10(0x28, 0, 1)).to_vec()),
    ]);
    let mut devs: [&mut dyn ScsiDevice; 2] = [&mut dev0, &mut dev1];
    let mut planes: [Option<StorePlane<'_>>; 2] = [
        Some(StorePlane::BlockRw(&mut backend0)),
        Some(StorePlane::BlockRw(&mut backend1)),
    ];
    let mut luns = Luns::new(&mut devs, &mut planes);
    golden_drive::serve_usb(&mut io, &mut gadget, &mut session, &mut work, &mut luns);

    assert_csw(&io, 1, 0, 0x00);
    assert_csw(&io, 2, 0, 0x00);
    assert_csw(&io, 3, 0, 0x00);
    let reads = data_chunks(&io, 512);
    assert_eq!(reads.len(), 2, "one read-back per LUN");
    assert_eq!(reads[0], payload.as_slice(), "LUN0 read-back is the write");
    assert!(
        reads[1].iter().all(|&b| b == 0x02),
        "LUN1 read-back is its own pattern"
    );
    finish(NAME, TWO_LUNS, &io);
}

/// ⑬ DVD-RAM: FORMAT UNIT → REQUEST SENSE → READ zeroed sector → SYNC CACHE.
#[test]
fn usb_13_format_read_sync() {
    const NAME: &str = "usb_13_format_read_sync";
    use snowscsi::cdrom::dvdram::DvdRamMedia;
    use snowscsi::cdrom::{CdMedia, CdromDrive, HYPER_MULTI_CAPS};

    let mut ram = vec![0u8; 1 << 20];
    let mut be = snowscsi::scsi::backend::RamBackend::new(&mut ram);
    let mut drive = CdromDrive::builder().capabilities(HYPER_MULTI_CAPS).build();
    // The media caches only the geometry; the byte plane is handed to the
    // session as the LUN's store plane below (FORMAT's `Fill` and SYNC
    // CACHE's `Sync` agenda ops are executed against it, invisibly on wire).
    let _ = drive.load_quiet(CdMedia::Rw(DvdRamMedia::open(&mut be)));

    let mut session = BotSession::new();
    let mut work = [0u8; snowscsi::MIN_DATA_LEN];
    let (mut io, mut gadget) = golden::split(vec![
        InStep::Bytes(
            raw_cbw(1, 12, 0x00, 0, &[0x04, 0x11, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]).to_vec(),
        ),
        InStep::Bytes(vec![
            0x00, 0x00, 0x00, 0x08, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x08, 0x00,
        ]),
        InStep::WouldBlock,
        InStep::Bytes(raw_cbw(2, 18, 0x80, 0, &[0x03, 0, 0, 0, 18, 0]).to_vec()),
        InStep::Bytes(raw_cbw(3, 2048, 0x80, 0, &rw10(0x28, 0, 1)).to_vec()),
        InStep::Bytes(raw_cbw(4, 0, 0x00, 0, &[0x35, 0, 0, 0, 0, 0, 0, 0, 0, 0]).to_vec()),
    ]);
    let mut devs: [&mut dyn ScsiDevice; 1] = [&mut drive];
    // Real writable plane for the DVD-RAM LUN: the drive yields its FORMAT
    // `Fill` and SYNC CACHE `Sync` maintenance here (agenda), never inline.
    let mut planes: [Option<StorePlane<'_>>; 1] = [Some(StorePlane::BlockRw(&mut be))];
    let mut luns = Luns::new(&mut devs, &mut planes);
    golden_drive::serve_usb(&mut io, &mut gadget, &mut session, &mut work, &mut luns);

    assert_csw(&io, 1, 0, 0x00);
    assert_csw(&io, 2, 0, 0x00);
    assert_csw(&io, 3, 0, 0x00);
    assert_csw(&io, 4, 0, 0x00);
    let reads = data_chunks(&io, 2048);
    assert_eq!(reads.len(), 1, "one 2048-byte sector read");
    assert!(
        reads[0].iter().all(|&b| b == 0),
        "freshly formatted sector is zero"
    );
    finish(NAME, CONFIG, &io);
}
