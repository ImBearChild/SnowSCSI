//! Asynchronous golden replay for USB BOT.
//!
//! Replays the recorded USB bulk-only wire scripts through the asynchronous
//! serve loop ([`serve_async`]) and compares the recorded trace byte-for-byte
//! with the same on-disk fixtures the synchronous replay uses. The scripts, the
//! fixture codec and the control gadget are the shared ones from
//! [`crate::golden`]; only the bulk seam and the serve loop differ.
//!
//! The asynchronous seam wraps the synchronous scripted driver
//! ([`RecBotIo`]) behind shared interior mutability: the receive and send
//! halves are two handles over one script, and each asynchronous method runs
//! its synchronous counterpart to completion (the script is in memory, so no
//! call ever waits). A minimal `block_on` drives the future, since the shell is
//! a plain `async fn` with no runtime dependency.

use core::cell::RefCell;
use core::sync::atomic::{AtomicBool, Ordering};
use std::collections::VecDeque;
use std::rc::Rc;

use snowscsi::common::async_store::{AsyncStorePlane, BlockingAsync};
use snowscsi::common::seekable_storage::StorageError;
use snowscsi::common::store::{StoreOp, StorePlane};
use snowscsi::scsi::device::{CommandOutcome, DeviceType, ScsiDevice, Xfer};
use snowscsi::scsi::scsi::Sense;
use snowscsi::scsi::AsyncLuns;
use snowscsi::usb::serve::serve_async;
use snowscsi::usb::{
    Action, AsyncBotRecv, AsyncBotSend, BotIo, BotIoErr, BotSession, CtrlReq, Event, Gadget,
    RecvMode, ServeError,
};

use crate::golden::{self, CtrlStep, InStep, RecBotIo, RecGadget, TraceEntry, CSW_MAGIC};
use crate::mock_bot::{MockAck, MockReply};
use crate::usb_bot::{block_device, raw_cbw, rw10};

/// Default scenario config: High-Speed BOT, no shortfall STALL, one LUN.
const CONFIG: &str = "kind=bot mps=512 policy=ShortNoStall luns=1";

/// Drive `fut` to completion on the current thread.
///
/// The shell performs no real waiting — every seam call completes inline — so
/// a no-op waker is enough and a single poll is normally sufficient; the loop
/// only covers an implementation that yields once (a chunked fill).
fn block_on<F: core::future::Future>(fut: F) -> F::Output {
    let mut fut = core::pin::pin!(fut);
    let mut cx = core::task::Context::from_waker(core::task::Waker::noop());
    loop {
        if let core::task::Poll::Ready(v) = fut.as_mut().poll(&mut cx) {
            return v;
        }
    }
}

/// Asynchronous bulk seam over the synchronous scripted driver.
///
/// Both directions share one [`RecBotIo`] through [`RefCell`], so the recorded
/// trace and the script queue keep a single order. Receive mirrors the
/// synchronous driver, including its end-of-script convention: a non-probe
/// receive on an exhausted script reports `Ok(0)` (a closed link) while a probe
/// reports `WouldBlock` (nothing pending), which is what ends a finite replay.
pub struct GoldenAsyncBotIo {
    io: Rc<RefCell<RecBotIo>>,
}

impl GoldenAsyncBotIo {
    /// Wrap the shared scripted driver.
    pub fn new(io: Rc<RefCell<RecBotIo>>) -> Self {
        Self { io }
    }
}

impl AsyncBotRecv for GoldenAsyncBotIo {
    async fn recv(&mut self, buf: &mut [u8], mode: RecvMode) -> Result<usize, BotIoErr> {
        let mut io = self.io.borrow_mut();
        match io.steps.pop_front() {
            // Copy-min: deliver `min(step, buf)`. The core may hand a buffer
            // larger than the next packet (a write-ahead receive uses the whole
            // scratch), so the step is never required to equal `buf.len()`.
            Some(InStep::Bytes(b)) => {
                let n = b.len().min(buf.len());
                buf[..n].copy_from_slice(&b[..n]);
                io.trace.push(TraceEntry::H2D(b));
                Ok(n)
            }
            Some(InStep::WouldBlock) => Err(BotIoErr::WouldBlock),
            Some(InStep::Disconnect) => {
                io.trace.push(TraceEntry::Mark("disconnected"));
                Err(BotIoErr::Disconnected)
            }
            Some(InStep::Ctrl(_)) => {
                panic!("RecBotIo: Ctrl step reached the bulk queue (use golden::split)")
            }
            // Exhausted script: a probe reports nothing pending, a blocking
            // receive reports EOF (`Ok(0)`), which ends the finite replay.
            None => match mode {
                RecvMode::Probe => Err(BotIoErr::WouldBlock),
                RecvMode::Until(_) | RecvMode::Forever => Ok(0),
            },
        }
    }

    async fn stall_both(&mut self) -> Result<(), ()> {
        self.io.borrow_mut().stall_both()
    }
}

impl AsyncBotSend for GoldenAsyncBotIo {
    async fn send(&mut self, buf: &[u8]) -> Result<(), BotIoErr> {
        self.io.borrow_mut().send_in(buf)
    }

    async fn stall_in(&mut self) -> Result<(), ()> {
        self.io.borrow_mut().stall_in()
    }

    /// The scripted driver always reports Bulk-In STALL support.
    fn can_stall_in(&self) -> bool {
        true
    }
}

/// Replay one scenario's bulk script to exhaustion through the asynchronous
/// serve loop, leaving the recorded trace in `io` for the caller to compare.
///
/// Mirrors the synchronous [`crate::golden_drive::serve_usb`] replay: the
/// script ends at a command boundary, where the seam reports EOF and the shell
/// surfaces [`ServeError::Closed`] — a clean end for a finite wire script.
pub fn serve_usb_async<P: AsyncStorePlane>(
    io: Rc<RefCell<RecBotIo>>,
    gadget: &mut RecGadget,
    session: &mut BotSession,
    work: &mut [u8],
    scratch: &mut [u8],
    luns: &mut AsyncLuns<'_, P>,
) {
    let stop = AtomicBool::new(false);
    let mut recv = GoldenAsyncBotIo::new(Rc::clone(&io));
    let mut send = GoldenAsyncBotIo::new(io);
    block_on(async {
        match serve_async(
            &mut recv, &mut send, gadget, session, work, scratch, luns, &stop,
        )
        .await
        {
            Ok(()) | Err(ServeError::Closed) => {}
            Err(e) => panic!("usb::serve_async failed: {e}"),
        }
    });
}

/// Fixed deterministic backend pattern (`i % 251`).
fn pattern_ram(len: usize) -> Vec<u8> {
    (0..len).map(|i| (i % 251) as u8).collect()
}

/// Every 13-byte D2H entry carrying the CSW magic, in wire order.
fn csws(io: &RecBotIo) -> Vec<&[u8]> {
    io.trace
        .iter()
        .filter_map(|e| match e {
            TraceEntry::D2H(b) if b.len() == snowscsi::usb::CSW_LEN && b[..4] == CSW_MAGIC => {
                Some(b.as_slice())
            }
            _ => None,
        })
        .collect()
}

/// Assert a CSW with `tag` exists and reports `residue` / `status`.
fn assert_csw(io: &RecBotIo, tag: u32, residue: u32, status: u8) {
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
fn data_entries(io: &RecBotIo) -> Vec<&[u8]> {
    io.trace
        .iter()
        .filter_map(|e| match e {
            TraceEntry::D2H(b) if !(b.len() == snowscsi::usb::CSW_LEN && b[..4] == CSW_MAGIC) => {
                Some(b.as_slice())
            }
            _ => None,
        })
        .collect()
}

/// D2H data entries of exactly `len` bytes (not CSWs), in wire order.
fn data_chunks(io: &RecBotIo, len: usize) -> Vec<&[u8]> {
    data_entries(io)
        .into_iter()
        .filter(|b| b.len() == len)
        .collect()
}

/// Render, guard, then compare the recorded trace with the fixture.
fn finish(name: &str, config: &str, io: &RecBotIo) {
    let text = golden::render(config, &io.trace);
    golden::assert_well_formed(name, &text);
    golden::bless_or_check(name, &text);
}

/// ① INQUIRY (OutInline + CSW).
#[test]
fn usb_async_01_inquiry() {
    const NAME: &str = "usb_01_inquiry";
    let mut ram = pattern_ram(64 * 1024);
    let mut backend = snowscsi::scsi::backend::RamBackend::new(&mut ram);
    let mut dev = block_device(&mut backend);
    let mut session = BotSession::new();
    let mut work = [0u8; snowscsi::MIN_DATA_LEN];
    let mut scratch = [0u8; snowscsi::MIN_DATA_LEN];
    let cdb = [0x12, 0, 0, 0, 36, 0];
    let (io, mut gadget) =
        golden::split(vec![InStep::Bytes(raw_cbw(1, 36, 0x80, 0, &cdb).to_vec())]);
    let io = Rc::new(RefCell::new(io));
    let mut devs: [&mut dyn ScsiDevice; 1] = [&mut dev];
    let mut planes: [Option<BlockingAsync<StorePlane<'_>>>; 1] =
        [Some(BlockingAsync(StorePlane::BlockRw(&mut backend)))];
    let mut luns = AsyncLuns::new(&mut devs, &mut planes);
    serve_usb_async(
        io.clone(),
        &mut gadget,
        &mut session,
        &mut work,
        &mut scratch,
        &mut luns,
    );

    let io = io.borrow();
    assert_eq!(data_chunks(&io, 36).len(), 1);
    assert_csw(&io, 1, 0, 0x00);
    finish(NAME, CONFIG, &io);
}

/// ② READ single block (512 bytes = one MPS multiple, no ZLP).
#[test]
fn usb_async_02_read_single_block() {
    const NAME: &str = "usb_02_read_single_block";
    let mut ram = pattern_ram(64 * 1024);
    let mut backend = snowscsi::scsi::backend::RamBackend::new(&mut ram);
    let mut dev = block_device(&mut backend);
    let mut session = BotSession::new();
    let mut work = [0u8; snowscsi::MIN_DATA_LEN];
    let mut scratch = [0u8; snowscsi::MIN_DATA_LEN];
    let (io, mut gadget) = golden::split(vec![InStep::Bytes(
        raw_cbw(2, 512, 0x80, 0, &rw10(0x28, 0, 1)).to_vec(),
    )]);
    let io = Rc::new(RefCell::new(io));
    let mut devs: [&mut dyn ScsiDevice; 1] = [&mut dev];
    let mut planes: [Option<BlockingAsync<StorePlane<'_>>>; 1] =
        [Some(BlockingAsync(StorePlane::BlockRw(&mut backend)))];
    let mut luns = AsyncLuns::new(&mut devs, &mut planes);
    serve_usb_async(
        io.clone(),
        &mut gadget,
        &mut session,
        &mut work,
        &mut scratch,
        &mut luns,
    );

    let io = io.borrow();
    assert_eq!(data_chunks(&io, 512).len(), 1);
    assert_csw(&io, 2, 0, 0x00);
    finish(NAME, CONFIG, &io);
}

/// ③ READ 40 blocks (20480 bytes) → three Data-In chunks (8192, 8192, 4096).
#[test]
fn usb_async_03_read_three_chunks() {
    const NAME: &str = "usb_03_read_three_chunks";
    let mut ram = pattern_ram(64 * 1024);
    let mut backend = snowscsi::scsi::backend::RamBackend::new(&mut ram);
    let mut dev = block_device(&mut backend);
    let mut session = BotSession::new();
    let mut work = [0u8; snowscsi::MIN_DATA_LEN];
    let mut scratch = [0u8; snowscsi::MIN_DATA_LEN];
    let (io, mut gadget) = golden::split(vec![InStep::Bytes(
        raw_cbw(3, 20480, 0x80, 0, &rw10(0x28, 0, 40)).to_vec(),
    )]);
    let io = Rc::new(RefCell::new(io));
    let mut devs: [&mut dyn ScsiDevice; 1] = [&mut dev];
    let mut planes: [Option<BlockingAsync<StorePlane<'_>>>; 1] =
        [Some(BlockingAsync(StorePlane::BlockRw(&mut backend)))];
    let mut luns = AsyncLuns::new(&mut devs, &mut planes);
    serve_usb_async(
        io.clone(),
        &mut gadget,
        &mut session,
        &mut work,
        &mut scratch,
        &mut luns,
    );

    let io = io.borrow();
    let lens: Vec<usize> = data_entries(&io).iter().map(|b| b.len()).collect();
    assert_eq!(lens, vec![8192, 8192, 4096], "chunk split");
    assert_csw(&io, 3, 0, 0x00);
    finish(NAME, CONFIG, &io);
}

/// ④ WRITE then READ back (locks write-through on one script).
#[test]
fn usb_async_04_write_then_read() {
    const NAME: &str = "usb_04_write_then_read";
    let mut ram = pattern_ram(64 * 1024);
    let mut backend = snowscsi::scsi::backend::RamBackend::new(&mut ram);
    let mut dev = block_device(&mut backend);
    let mut session = BotSession::new();
    let mut work = [0u8; snowscsi::MIN_DATA_LEN];
    let mut scratch = [0u8; snowscsi::MIN_DATA_LEN];
    let payload: Vec<u8> = (0..512).map(|i| (i * 7 % 256) as u8).collect();
    let (io, mut gadget) = golden::split(vec![
        InStep::Bytes(raw_cbw(4, 512, 0x00, 0, &rw10(0x2A, 1, 1)).to_vec()),
        InStep::Bytes(payload.clone()),
        InStep::WouldBlock,
        InStep::Bytes(raw_cbw(5, 512, 0x80, 0, &rw10(0x28, 1, 1)).to_vec()),
    ]);
    let io = Rc::new(RefCell::new(io));
    let mut devs: [&mut dyn ScsiDevice; 1] = [&mut dev];
    let mut planes: [Option<BlockingAsync<StorePlane<'_>>>; 1] =
        [Some(BlockingAsync(StorePlane::BlockRw(&mut backend)))];
    let mut luns = AsyncLuns::new(&mut devs, &mut planes);
    serve_usb_async(
        io.clone(),
        &mut gadget,
        &mut session,
        &mut work,
        &mut scratch,
        &mut luns,
    );

    let io = io.borrow();
    assert_csw(&io, 4, 0, 0x00);
    assert_csw(&io, 5, 0, 0x00);
    let reads = data_chunks(&io, 512);
    assert_eq!(reads.len(), 1, "one read-back chunk");
    assert_eq!(reads[0], payload.as_slice(), "read-back equals the write");
    finish(NAME, CONFIG, &io);
}

/// ⑤ Write short residue: CBW declares 1024, CDB writes one 512-byte block.
#[test]
fn usb_async_05_write_short_residue() {
    const NAME: &str = "usb_05_write_short_residue";
    let mut ram = pattern_ram(64 * 1024);
    let mut backend = snowscsi::scsi::backend::RamBackend::new(&mut ram);
    let mut dev = block_device(&mut backend);
    let mut session = BotSession::new();
    let mut work = [0u8; snowscsi::MIN_DATA_LEN];
    let mut scratch = [0u8; snowscsi::MIN_DATA_LEN];
    let payload = vec![0x5Au8; 1024];
    let (io, mut gadget) = golden::split(vec![
        InStep::Bytes(raw_cbw(1, 1024, 0x00, 0, &rw10(0x2A, 0, 1)).to_vec()),
        InStep::Bytes(payload),
        InStep::WouldBlock,
    ]);
    let io = Rc::new(RefCell::new(io));
    let mut devs: [&mut dyn ScsiDevice; 1] = [&mut dev];
    let mut planes: [Option<BlockingAsync<StorePlane<'_>>>; 1] =
        [Some(BlockingAsync(StorePlane::BlockRw(&mut backend)))];
    let mut luns = AsyncLuns::new(&mut devs, &mut planes);
    serve_usb_async(
        io.clone(),
        &mut gadget,
        &mut session,
        &mut work,
        &mut scratch,
        &mut luns,
    );

    let io = io.borrow();
    assert_csw(&io, 1, 512, 0x00);
    finish(NAME, CONFIG, &io);
}

/// ⑥ `Short` Data-In shortfall: 512 data, ZLP, Bulk-In STALL, then the CSW.
#[test]
fn usb_async_06_shortfall_short() {
    const NAME: &str = "usb_06_shortfall_short";
    const SHORT_CONFIG: &str = "kind=bot mps=512 policy=Short luns=1";
    let mut ram = pattern_ram(64 * 1024);
    let mut backend = snowscsi::scsi::backend::RamBackend::new(&mut ram);
    let mut dev = block_device(&mut backend);
    let mut session = BotSession::new().with_shortfall(snowscsi::usb::ShortfallPolicy::Short);
    let mut work = [0u8; snowscsi::MIN_DATA_LEN];
    let mut scratch = [0u8; snowscsi::MIN_DATA_LEN];
    let (io, mut gadget) = golden::split(vec![InStep::Bytes(
        raw_cbw(1, 1024, 0x80, 0, &rw10(0x28, 0, 1)).to_vec(),
    )]);
    let io = Rc::new(RefCell::new(io));
    let mut devs: [&mut dyn ScsiDevice; 1] = [&mut dev];
    let mut planes: [Option<BlockingAsync<StorePlane<'_>>>; 1] =
        [Some(BlockingAsync(StorePlane::BlockRw(&mut backend)))];
    let mut luns = AsyncLuns::new(&mut devs, &mut planes);
    serve_usb_async(
        io.clone(),
        &mut gadget,
        &mut session,
        &mut work,
        &mut scratch,
        &mut luns,
    );

    let io = io.borrow();
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
fn usb_async_07_shortfall_short_no_stall() {
    const NAME: &str = "usb_07_shortfall_short_no_stall";
    let mut ram = pattern_ram(64 * 1024);
    let mut backend = snowscsi::scsi::backend::RamBackend::new(&mut ram);
    let mut dev = block_device(&mut backend);
    let mut session = BotSession::new();
    let mut work = [0u8; snowscsi::MIN_DATA_LEN];
    let mut scratch = [0u8; snowscsi::MIN_DATA_LEN];
    let (io, mut gadget) = golden::split(vec![InStep::Bytes(
        raw_cbw(2, 192, 0x80, 0, &[0x12, 0, 0, 0, 95, 0]).to_vec(),
    )]);
    let io = Rc::new(RefCell::new(io));
    let mut devs: [&mut dyn ScsiDevice; 1] = [&mut dev];
    let mut planes: [Option<BlockingAsync<StorePlane<'_>>>; 1] =
        [Some(BlockingAsync(StorePlane::BlockRw(&mut backend)))];
    let mut luns = AsyncLuns::new(&mut devs, &mut planes);
    serve_usb_async(
        io.clone(),
        &mut gadget,
        &mut session,
        &mut work,
        &mut scratch,
        &mut luns,
    );

    let io = io.borrow();
    assert_eq!(data_chunks(&io, 95).len(), 1, "short packet is 95 bytes");
    assert_csw(&io, 2, 97, 0x00);
    finish(NAME, CONFIG, &io);
}

/// ⑧ `Pad`: the 95-byte response is zero-padded to 192 in-buffer.
#[test]
fn usb_async_08_shortfall_pad() {
    const NAME: &str = "usb_08_shortfall_pad";
    const PAD_CONFIG: &str = "kind=bot mps=512 policy=Pad luns=1";
    let mut ram = pattern_ram(64 * 1024);
    let mut backend = snowscsi::scsi::backend::RamBackend::new(&mut ram);
    let mut dev = block_device(&mut backend);
    let mut session = BotSession::new().with_shortfall(snowscsi::usb::ShortfallPolicy::Pad);
    let mut work = [0u8; snowscsi::MIN_DATA_LEN];
    let mut scratch = [0u8; snowscsi::MIN_DATA_LEN];
    let (io, mut gadget) = golden::split(vec![InStep::Bytes(
        raw_cbw(2, 192, 0x80, 0, &[0x12, 0, 0, 0, 95, 0]).to_vec(),
    )]);
    let io = Rc::new(RefCell::new(io));
    let mut devs: [&mut dyn ScsiDevice; 1] = [&mut dev];
    let mut planes: [Option<BlockingAsync<StorePlane<'_>>>; 1] =
        [Some(BlockingAsync(StorePlane::BlockRw(&mut backend)))];
    let mut luns = AsyncLuns::new(&mut devs, &mut planes);
    serve_usb_async(
        io.clone(),
        &mut gadget,
        &mut session,
        &mut work,
        &mut scratch,
        &mut luns,
    );

    let io = io.borrow();
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
fn usb_async_09_write_overrun() {
    const NAME: &str = "usb_09_write_overrun";
    let mut ram = pattern_ram(64 * 1024);
    let mut backend = snowscsi::scsi::backend::RamBackend::new(&mut ram);
    let mut dev = block_device(&mut backend);
    let mut session = BotSession::new();
    let mut work = [0u8; snowscsi::MIN_DATA_LEN];
    let mut scratch = [0u8; snowscsi::MIN_DATA_LEN];
    let (io, mut gadget) = golden::split(vec![
        InStep::Bytes(raw_cbw(1, 512, 0x00, 0, &rw10(0x2A, 0, 1)).to_vec()),
        InStep::Bytes(vec![0x5A; 512]),
        InStep::Bytes(vec![0x6B; 8192]),
        InStep::WouldBlock,
    ]);
    let io = Rc::new(RefCell::new(io));
    let mut devs: [&mut dyn ScsiDevice; 1] = [&mut dev];
    let mut planes: [Option<BlockingAsync<StorePlane<'_>>>; 1] =
        [Some(BlockingAsync(StorePlane::BlockRw(&mut backend)))];
    let mut luns = AsyncLuns::new(&mut devs, &mut planes);
    serve_usb_async(
        io.clone(),
        &mut gadget,
        &mut session,
        &mut work,
        &mut scratch,
        &mut luns,
    );

    let io = io.borrow();
    assert_csw(&io, 1, 0, 0x00);
    finish(NAME, CONFIG, &io);
}

/// ⑩ Invalid CBW → `stall_both` → next valid CBW (implicit clear-halt).
#[test]
fn usb_async_10_invalid_cbw() {
    const NAME: &str = "usb_10_invalid_cbw";
    let mut ram = pattern_ram(64 * 1024);
    let mut backend = snowscsi::scsi::backend::RamBackend::new(&mut ram);
    let mut dev = block_device(&mut backend);
    let mut session = BotSession::new();
    let mut work = [0u8; snowscsi::MIN_DATA_LEN];
    let mut scratch = [0u8; snowscsi::MIN_DATA_LEN];
    let mut bad = raw_cbw(1, 0, 0, 0, &[0, 0, 0, 0, 0, 0]);
    bad[0] = b'X';
    let (io, mut gadget) = golden::split(vec![
        InStep::Bytes(bad.to_vec()),
        InStep::Bytes(raw_cbw(2, 36, 0x80, 0, &[0x12, 0, 0, 0, 36, 0]).to_vec()),
    ]);
    let io = Rc::new(RefCell::new(io));
    let mut devs: [&mut dyn ScsiDevice; 1] = [&mut dev];
    let mut planes: [Option<BlockingAsync<StorePlane<'_>>>; 1] =
        [Some(BlockingAsync(StorePlane::BlockRw(&mut backend)))];
    let mut luns = AsyncLuns::new(&mut devs, &mut planes);
    serve_usb_async(
        io.clone(),
        &mut gadget,
        &mut session,
        &mut work,
        &mut scratch,
        &mut luns,
    );

    let io = io.borrow();
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
fn usb_async_11_write_read_only() {
    const NAME: &str = "usb_11_write_read_only";
    let mut ram = pattern_ram(64 * 1024);
    let mut backend = snowscsi::scsi::backend::RamBackend::new(&mut ram);
    let mut dev = block_device(&mut backend);
    dev.set_writable(false);
    let mut session = BotSession::new();
    let mut work = [0u8; snowscsi::MIN_DATA_LEN];
    let mut scratch = [0u8; snowscsi::MIN_DATA_LEN];
    let (io, mut gadget) = golden::split(vec![
        InStep::Bytes(raw_cbw(1, 512, 0x00, 0, &rw10(0x2A, 0, 1)).to_vec()),
        InStep::Bytes(vec![0u8; 512]),
        InStep::WouldBlock,
        InStep::Bytes(raw_cbw(2, 18, 0x80, 0, &[0x03, 0, 0, 0, 18, 0]).to_vec()),
    ]);
    let io = Rc::new(RefCell::new(io));
    let mut devs: [&mut dyn ScsiDevice; 1] = [&mut dev];
    let mut planes: [Option<BlockingAsync<StorePlane<'_>>>; 1] =
        [Some(BlockingAsync(StorePlane::BlockRw(&mut backend)))];
    let mut luns = AsyncLuns::new(&mut devs, &mut planes);
    serve_usb_async(
        io.clone(),
        &mut gadget,
        &mut session,
        &mut work,
        &mut scratch,
        &mut luns,
    );

    let io = io.borrow();
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
fn usb_async_12_multi_lun() {
    const NAME: &str = "usb_12_multi_lun";
    const TWO_LUNS: &str = "kind=bot mps=512 policy=ShortNoStall luns=2";
    let mut ram0 = vec![0x01u8; 64 * 1024];
    let mut ram1 = vec![0x02u8; 64 * 1024];
    let mut backend0 = snowscsi::scsi::backend::RamBackend::new(&mut ram0);
    let mut backend1 = snowscsi::scsi::backend::RamBackend::new(&mut ram1);
    let mut dev0 = block_device(&mut backend0);
    let mut dev1 = block_device(&mut backend1);
    let mut session = BotSession::with_luns(2);
    let mut work = [0u8; snowscsi::MIN_DATA_LEN];
    let mut scratch = [0u8; snowscsi::MIN_DATA_LEN];
    let payload = vec![0xABu8; 512];
    let (io, mut gadget) = golden::split(vec![
        InStep::Bytes(raw_cbw(1, 512, 0x00, 0, &rw10(0x2A, 0, 1)).to_vec()),
        InStep::Bytes(payload.clone()),
        InStep::WouldBlock,
        InStep::Bytes(raw_cbw(2, 512, 0x80, 0, &rw10(0x28, 0, 1)).to_vec()),
        InStep::Bytes(raw_cbw(3, 512, 0x80, 1, &rw10(0x28, 0, 1)).to_vec()),
    ]);
    let io = Rc::new(RefCell::new(io));
    let mut devs: [&mut dyn ScsiDevice; 2] = [&mut dev0, &mut dev1];
    let mut planes: [Option<BlockingAsync<StorePlane<'_>>>; 2] = [
        Some(BlockingAsync(StorePlane::BlockRw(&mut backend0))),
        Some(BlockingAsync(StorePlane::BlockRw(&mut backend1))),
    ];
    let mut luns = AsyncLuns::new(&mut devs, &mut planes);
    serve_usb_async(
        io.clone(),
        &mut gadget,
        &mut session,
        &mut work,
        &mut scratch,
        &mut luns,
    );

    let io = io.borrow();
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
fn usb_async_13_format_read_sync() {
    const NAME: &str = "usb_13_format_read_sync";
    use snowscsi::cdrom::dvdram::DvdRamMedia;
    use snowscsi::cdrom::{CdMedia, CdromDrive, HYPER_MULTI_CAPS};

    let mut ram = vec![0u8; 1 << 20];
    let mut be = snowscsi::scsi::backend::RamBackend::new(&mut ram);
    let mut drive = CdromDrive::builder().capabilities(HYPER_MULTI_CAPS).build();
    // The media caches only the geometry; the byte plane is handed to the
    // session as the LUN's store plane below (FORMAT's `Fill` and SYNC CACHE's
    // `Sync` agenda ops are executed against it, invisibly on wire).
    let _ = drive.load_quiet(CdMedia::Rw(DvdRamMedia::open(&mut be)));

    let mut session = BotSession::new();
    let mut work = [0u8; snowscsi::MIN_DATA_LEN];
    let mut scratch = [0u8; snowscsi::MIN_DATA_LEN];
    let (io, mut gadget) = golden::split(vec![
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
    let io = Rc::new(RefCell::new(io));
    let mut devs: [&mut dyn ScsiDevice; 1] = [&mut drive];
    // Real writable plane for the DVD-RAM LUN: the drive yields its FORMAT
    // `Fill` and SYNC CACHE `Sync` maintenance here (agenda), never inline.
    let mut planes: [Option<BlockingAsync<StorePlane<'_>>>; 1] =
        [Some(BlockingAsync(StorePlane::BlockRw(&mut be)))];
    let mut luns = AsyncLuns::new(&mut devs, &mut planes);
    serve_usb_async(
        io.clone(),
        &mut gadget,
        &mut session,
        &mut work,
        &mut scratch,
        &mut luns,
    );

    let io = io.borrow();
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

// ── Overlap boundary harness ────────────────────────────────────────
//
// The 13 replays above already exercise the read-ahead hit path (a multi-chunk
// Data-In such as the 8192/8192/4096 read speculatively pre-reads the next
// chunk and skips the core's store), but not the write-ahead pre-receive:
// their Data-Out writes always finish within the declared length, so
// `Action::Store.next_recv` is `None` and the shell never pre-receives. The
// tests below drive the shell with a scripted asynchronous seam and a
// recording store plane and assert the **event sequence** — the seam calls and
// the store ops, in order — not just the wire.

/// One bulk-OUT script step for the boundary harness.
#[derive(Clone, Debug)]
enum OutStep {
    /// Deliver `bytes` as one host packet (a receive copies `min(len, buf)`).
    Bytes(Vec<u8>),
    /// No data: `WouldBlock` (a probe miss or a bounded-wait timeout).
    WouldBlock,
    /// Link drop.
    Disconnect,
}

/// Receive mode, recorded without its timeout so events compare equal.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum RecvKind {
    Probe,
    Until,
    Forever,
}

/// Outcome of one scripted receive.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum RecvOut {
    /// `Ok(n)` bytes delivered.
    Bytes(usize),
    WouldBlock,
    Disconnect,
}

/// One recorded seam call, in order.
#[derive(Clone, Debug, PartialEq, Eq)]
enum SeamEvent {
    Recv {
        kind: RecvKind,
        /// The caller's buffer length. A write-ahead receive passes the whole
        /// scratch, so `want` may exceed `got`.
        want: usize,
        got: RecvOut,
    },
    Send {
        len: usize,
    },
    StallIn,
    StallBoth,
}

/// State shared by the two asynchronous seam halves and (optionally) a
/// control-injecting gadget.
#[derive(Default)]
struct SeamState {
    out: VecDeque<OutStep>,
    events: Vec<SeamEvent>,
    wire: Vec<TraceEntry>,
    /// Bulk-OUT receives performed so far (an arming signal for a mid-overlap
    /// control request).
    recv_count: usize,
    /// Bulk-IN sends performed so far.
    send_count: usize,
}

impl SeamState {
    fn new(steps: Vec<OutStep>) -> Rc<RefCell<Self>> {
        Rc::new(RefCell::new(Self {
            out: steps.into(),
            events: Vec::new(),
            wire: Vec::new(),
            recv_count: 0,
            send_count: 0,
        }))
    }
}

/// Bulk-OUT half of the scripted seam.
struct ScriptRecv(Rc<RefCell<SeamState>>);

/// Bulk-IN half of the scripted seam.
struct ScriptSend(Rc<RefCell<SeamState>>);

impl AsyncBotRecv for ScriptRecv {
    async fn recv(&mut self, buf: &mut [u8], mode: RecvMode) -> Result<usize, BotIoErr> {
        let mut s = self.0.borrow_mut();
        let kind = match mode {
            RecvMode::Probe => RecvKind::Probe,
            RecvMode::Until(_) => RecvKind::Until,
            RecvMode::Forever => RecvKind::Forever,
        };
        let (res, got) = match s.out.pop_front() {
            // Copy-min: deliver `min(step, buf)`.
            Some(OutStep::Bytes(b)) => {
                let n = b.len().min(buf.len());
                buf[..n].copy_from_slice(&b[..n]);
                s.wire.push(TraceEntry::H2D(b));
                (Ok(n), RecvOut::Bytes(n))
            }
            Some(OutStep::WouldBlock) => (Err(BotIoErr::WouldBlock), RecvOut::WouldBlock),
            Some(OutStep::Disconnect) => {
                s.wire.push(TraceEntry::Mark("disconnected"));
                (Err(BotIoErr::Disconnected), RecvOut::Disconnect)
            }
            None => match kind {
                RecvKind::Probe => (Err(BotIoErr::WouldBlock), RecvOut::WouldBlock),
                // Exhausted script on a blocking receive: EOF ends the replay.
                RecvKind::Until | RecvKind::Forever => (Ok(0), RecvOut::Bytes(0)),
            },
        };
        s.recv_count += 1;
        s.events.push(SeamEvent::Recv {
            kind,
            want: buf.len(),
            got,
        });
        res
    }

    async fn stall_both(&mut self) -> Result<(), ()> {
        self.0.borrow_mut().events.push(SeamEvent::StallBoth);
        Ok(())
    }
}

impl AsyncBotSend for ScriptSend {
    async fn send(&mut self, buf: &[u8]) -> Result<(), BotIoErr> {
        let mut s = self.0.borrow_mut();
        s.send_count += 1;
        s.wire.push(TraceEntry::D2H(buf.to_vec()));
        s.events.push(SeamEvent::Send { len: buf.len() });
        Ok(())
    }

    async fn stall_in(&mut self) -> Result<(), ()> {
        self.0.borrow_mut().events.push(SeamEvent::StallIn);
        Ok(())
    }

    fn can_stall_in(&self) -> bool {
        true
    }
}

/// One storage op recorded by [`RecPlane`].
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum OpRec {
    Read { off: u64, len: usize },
    Write { off: u64, len: usize },
    Fill { off: u64, len: u64, byte: u8 },
    Sync,
}

/// Recording asynchronous store plane over a deterministic in-memory pattern.
///
/// Reads fill the buffer with `(off + i) % 251` and are recorded; the read at
/// index `fail_read` (0-based, in call order) fails instead, so a speculative
/// read-ahead can fail while the real op still re-reports the failure.
#[derive(Default)]
struct RecPlane {
    ops: Vec<OpRec>,
    /// The bytes of every `Write` op, in call order, so a buffer-ordering bug
    /// that hands a store the wrong chunk would be visible.
    written: Vec<(u64, Vec<u8>)>,
    fail_read: Option<usize>,
    read_calls: usize,
}

impl RecPlane {
    /// Read ops as `(off, len)` pairs, in call order.
    fn reads(&self) -> Vec<(u64, usize)> {
        self.ops
            .iter()
            .filter_map(|o| match o {
                OpRec::Read { off, len } => Some((*off, *len)),
                _ => None,
            })
            .collect()
    }

    /// Write ops as `(off, len)` pairs, in call order.
    fn writes(&self) -> Vec<(u64, usize)> {
        self.ops
            .iter()
            .filter_map(|o| match o {
                OpRec::Write { off, len } => Some((*off, *len)),
                _ => None,
            })
            .collect()
    }

    /// Written `(off, bytes)` pairs, in call order.
    fn written_bytes(&self) -> &[(u64, Vec<u8>)] {
        &self.written
    }
}

impl AsyncStorePlane for RecPlane {
    async fn do_op(&mut self, op: StoreOp<'_>) -> Result<(), StorageError> {
        match op {
            StoreOp::Read { off, buf } => {
                let call = self.read_calls;
                self.read_calls += 1;
                self.ops.push(OpRec::Read {
                    off,
                    len: buf.len(),
                });
                if self.fail_read == Some(call) {
                    return Err(StorageError::Io(embedded_io::ErrorKind::Other));
                }
                for (i, b) in buf.iter_mut().enumerate() {
                    *b = (off as usize).wrapping_add(i).wrapping_rem(251) as u8;
                }
                Ok(())
            }
            StoreOp::Write { off, buf } => {
                self.ops.push(OpRec::Write {
                    off,
                    len: buf.len(),
                });
                self.written.push((off, buf.to_vec()));
                Ok(())
            }
            StoreOp::Fill { off, len, byte } => {
                self.ops.push(OpRec::Fill { off, len, byte });
                Ok(())
            }
            StoreOp::Sync => {
                self.ops.push(OpRec::Sync);
                Ok(())
            }
            StoreOp::FileRead { .. } | StoreOp::FileWrite { .. } | StoreOp::FileRemove { .. } => {
                Err(StorageError::Unsupported)
            }
        }
    }

    async fn sync(&mut self) -> Result<(), StorageError> {
        Ok(())
    }
}

/// Minimal read-only LUN for the read-ahead tests.
///
/// A synthetic CDB opcode (`0xC1`) announces an `OutXfer` of `len` bytes; each
/// `xfer_out` hands the platform a `StoreOp::Read` addressed at
/// `transfer_offset + shift`, and [`ScsiDevice::read_ahead_offset`] reports that
/// same address. `shift` is therefore the media **base offset** of the transfer:
/// a non-zero value must *not* stop the read-ahead from matching — reporting
/// the transfer-relative offset instead was a real bug (every chunk was then
/// read twice). `ahead_skew` is added only to the reported coordinate, modelling
/// a device whose prediction disagrees with the read it later issues, which is
/// what a genuine miss looks like. With `first_inline` the first chunk is served
/// in place (`Inline`), so a read-ahead can be reached even when no store plane
/// is configured; `no_read_ahead` opts out entirely, like a synthesized device
/// with no byte plane.
#[derive(Default)]
struct ReadLun {
    len: u64,
    /// Media base offset added to every transfer offset.
    shift: u64,
    /// Added only to [`ScsiDevice::read_ahead_offset`]'s answer (forces a miss).
    ahead_skew: u64,
    sense: Option<Sense>,
    /// Serve the first `xfer_out` chunk in place (`Inline`); later chunks are
    /// `Store` reads.
    first_inline: bool,
    /// Report `None` from [`ScsiDevice::read_ahead_offset`] (no read-ahead).
    no_read_ahead: bool,
    /// `xfer_out` calls so far.
    calls: usize,
}

impl ScsiDevice for ReadLun {
    fn do_cmd(
        &mut self,
        cdb: &[u8],
        _data: &mut [u8],
    ) -> Result<CommandOutcome, snowscsi::scsi::device::Error> {
        if cdb.first() == Some(&0xC1) {
            return Ok(CommandOutcome::OutXfer { len: self.len });
        }
        Ok(CommandOutcome::Status)
    }

    fn xfer_out<'a>(&'a mut self, transfer_offset: u64, buf: &'a mut [u8]) -> Xfer<'a> {
        let call = self.calls;
        self.calls += 1;
        if self.first_inline && call == 0 {
            for (i, b) in buf.iter_mut().enumerate() {
                *b = (transfer_offset as usize).wrapping_add(i).wrapping_rem(251) as u8;
            }
            return Xfer::Inline { len: buf.len() };
        }
        Xfer::Store(StoreOp::Read {
            off: transfer_offset + self.shift,
            buf,
        })
    }

    fn xfer_in<'a>(&'a mut self, _transfer_offset: u64, _buf: &'a [u8]) -> Xfer<'a> {
        Xfer::Inline { len: 0 }
    }

    fn read_ahead_offset(&self, transfer_offset: u64) -> Option<u64> {
        if self.no_read_ahead {
            return None;
        }
        Some(transfer_offset + self.shift + self.ahead_skew)
    }

    fn peek_sense(&self) -> Option<&Sense> {
        self.sense.as_ref()
    }

    fn take_sense(&mut self) -> Option<Sense> {
        self.sense.take()
    }

    fn device_type(&self) -> DeviceType {
        DeviceType::Block
    }

    fn sync(&mut self) -> Result<(), StorageError> {
        Ok(())
    }
}

/// A scripted control gadget that surfaces its queued requests only once the
/// seam has performed enough receives or sends, so a request can be injected in
/// the window between an overlap `join` and the core's next poll (the shell
/// drains the control plane immediately after every await).
struct ArmedGadget {
    shared: Rc<RefCell<SeamState>>,
    arm: Arm,
    pending: VecDeque<CtrlStep>,
    acks: Vec<MockAck>,
    replies: Vec<MockReply>,
}

/// When an [`ArmedGadget`] starts surfacing its requests.
#[derive(Clone, Copy)]
enum Arm {
    /// After this many bulk-OUT receives.
    Recvs(usize),
    /// After this many bulk-IN sends.
    Sends(usize),
}

impl ArmedGadget {
    fn new(shared: Rc<RefCell<SeamState>>, arm: Arm, steps: Vec<CtrlStep>) -> Self {
        Self {
            shared,
            arm,
            pending: steps.into(),
            acks: Vec::new(),
            replies: Vec::new(),
        }
    }

    fn armed(&self) -> bool {
        let s = self.shared.borrow();
        match self.arm {
            Arm::Recvs(n) => s.recv_count >= n,
            Arm::Sends(n) => s.send_count >= n,
        }
    }
}

impl<'a> Gadget<'a> for ArmedGadget {
    type Ack = MockAck;
    type Reply = MockReply;

    fn try_next_ctrl(&'a mut self) -> Option<CtrlReq<MockAck, MockReply>> {
        if !self.armed() {
            return None;
        }
        match self.pending.pop_front()? {
            CtrlStep::BotReset => {
                let ack = MockAck::new();
                self.acks.push(ack.clone());
                Some(CtrlReq::BotReset { ack })
            }
            CtrlStep::GetMaxLun => {
                let reply = MockReply::new();
                self.replies.push(reply.clone());
                Some(CtrlReq::GetMaxLun { reply })
            }
            CtrlStep::LinkReset => Some(CtrlReq::LinkReset),
        }
    }
}

/// Drive one already-built seam state through `serve_async`, returning the
/// shell's result without asserting it.
fn run_scripted_with<P: AsyncStorePlane, G: for<'a> Gadget<'a>>(
    state: Rc<RefCell<SeamState>>,
    gadget: &mut G,
    session: &mut BotSession,
    work: &mut [u8],
    scratch: &mut [u8],
    luns: &mut AsyncLuns<'_, P>,
) -> Result<(), ServeError> {
    let mut recv = ScriptRecv(Rc::clone(&state));
    let mut send = ScriptSend(Rc::clone(&state));
    let stop = AtomicBool::new(false);
    block_on(async {
        serve_async(
            &mut recv, &mut send, gadget, session, work, scratch, luns, &stop,
        )
        .await
    })
}

/// Drive one scenario through `serve_async`, returning the recorded seam state
/// and the shell's result.
fn run_scripted_shell_result<P: AsyncStorePlane, G: for<'a> Gadget<'a>>(
    steps: Vec<OutStep>,
    gadget: &mut G,
    session: &mut BotSession,
    work: &mut [u8],
    scratch: &mut [u8],
    luns: &mut AsyncLuns<'_, P>,
) -> (Rc<RefCell<SeamState>>, Result<(), ServeError>) {
    let state = SeamState::new(steps);
    let result = run_scripted_with(Rc::clone(&state), gadget, session, work, scratch, luns);
    (state, result)
}

/// Drive one scenario through `serve_async`, treating `Closed` as a clean end
/// and panicking on any other error, and return the recorded seam state.
fn run_scripted_shell<P: AsyncStorePlane, G: for<'a> Gadget<'a>>(
    steps: Vec<OutStep>,
    gadget: &mut G,
    session: &mut BotSession,
    work: &mut [u8],
    scratch: &mut [u8],
    luns: &mut AsyncLuns<'_, P>,
) -> Rc<RefCell<SeamState>> {
    let (state, result) = run_scripted_shell_result(steps, gadget, session, work, scratch, luns);
    match result {
        Ok(()) | Err(ServeError::Closed) => {}
        Err(e) => panic!("usb::serve_async failed: {e}"),
    }
    state
}

/// H2D packet lengths, in wire order.
fn h2d_lens(wire: &[TraceEntry]) -> Vec<usize> {
    wire.iter()
        .filter_map(|e| match e {
            TraceEntry::H2D(b) => Some(b.len()),
            _ => None,
        })
        .collect()
}

/// D2H packet lengths, in wire order.
fn d2h_lens(wire: &[TraceEntry]) -> Vec<usize> {
    wire.iter()
        .filter_map(|e| match e {
            TraceEntry::D2H(b) => Some(b.len()),
            _ => None,
        })
        .collect()
}

/// Assert the wire carries exactly one CSW with `tag`/`residue`/`status`.
fn assert_wire_csw(wire: &[TraceEntry], tag: u32, residue: u32, status: u8) {
    let csw = wire
        .iter()
        .find_map(|e| match e {
            TraceEntry::D2H(b) if b.len() == snowscsi::usb::CSW_LEN && b[..4] == CSW_MAGIC => {
                Some(b.as_slice())
            }
            _ => None,
        })
        .unwrap_or_else(|| panic!("no CSW in wire: {wire:?}"));
    assert_eq!(u32::from_le_bytes([csw[4], csw[5], csw[6], csw[7]]), tag);
    assert_eq!(
        u32::from_le_bytes([csw[8], csw[9], csw[10], csw[11]]),
        residue
    );
    assert_eq!(csw[12], status);
}

/// One core `Action`, reduced to the fields the overlap boundaries care about.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum CoreStep {
    Recv {
        len: usize,
        probe: bool,
    },
    Send {
        len: usize,
        prefetch: Option<(usize, u64, usize)>,
    },
    Store {
        lun: usize,
        next_recv: Option<usize>,
        /// The `(off, len)` of a `StoreOp::Read` op, if the store is a read.
        read: Option<(u64, usize)>,
    },
    StallBoth,
    StallIn,
    Error,
}

/// Poll the core once and reduce its `Action` to a `Copy` [`CoreStep`], so the
/// borrow of `session`/`work` ends before the next poll.
fn poll_core<D: ScsiDevice>(
    session: &mut BotSession,
    ev: Event,
    work: &mut [u8],
    devs: &mut [D],
) -> CoreStep {
    match session.poll(ev, work, devs) {
        Action::HostRecv { len, probe } => CoreStep::Recv { len, probe },
        Action::HostSend { bytes, prefetch } => CoreStep::Send {
            len: bytes.len(),
            prefetch,
        },
        Action::Store { lun, op, next_recv } => {
            let read = match op {
                StoreOp::Read { off, buf } => Some((off, buf.len())),
                _ => None,
            };
            CoreStep::Store {
                lun,
                next_recv,
                read,
            }
        }
        Action::StallBoth => CoreStep::StallBoth,
        Action::StallIn => CoreStep::StallIn,
        Action::Error(_) => CoreStep::Error,
    }
}

/// Drive a WRITE through the core, feeding each requested receive with its own
/// length and each store with a success, and collect the action sequence. The
/// block device hands every write chunk to the plane, so the buffer contents
/// are irrelevant.
fn drive_write_core(declared: u32, blocks: u16) -> Vec<CoreStep> {
    let mut ram = vec![0u8; 64 * 1024];
    let mut backend = snowscsi::scsi::backend::RamBackend::new(&mut ram);
    let mut dev = block_device(&mut backend);
    let mut session = BotSession::new();
    let mut work = [0u8; snowscsi::MIN_DATA_LEN];
    let mut devs: [&mut dyn ScsiDevice; 1] = [&mut dev];
    let cbw = raw_cbw(1, declared, 0x00, 0, &rw10(0x2A, 0, blocks));

    let mut steps = Vec::new();
    let mut ev = Event::Tick;
    let mut cbw_pending = true;
    loop {
        let step = poll_core(&mut session, ev, &mut work, &mut devs);
        steps.push(step);
        ev = match step {
            CoreStep::Recv { len, probe: false } => {
                if cbw_pending {
                    work[..len].copy_from_slice(&cbw[..len]);
                    cbw_pending = false;
                }
                Event::HostRecv { len }
            }
            // A probe ends the phase on `HostIdle`; stop here.
            CoreStep::Recv { probe: true, .. } => break,
            // A CSW ends the transaction; stop here.
            CoreStep::Send { len, .. } if len == snowscsi::usb::CSW_LEN => break,
            CoreStep::Send { .. } => Event::HostSent,
            CoreStep::Store { .. } => Event::StoreDone { result: Ok(()) },
            CoreStep::StallBoth | CoreStep::StallIn | CoreStep::Error => break,
        };
    }
    steps
}

/// Drive a READ through the core (feeding each store as a success) and collect
/// the action sequence. The synthetic `0xC1` opcode serves `transfer_len` bytes
/// as `Store(Read)` chunks.
fn drive_read_core(transfer_len: u64) -> Vec<CoreStep> {
    // A non-zero media base offset: the read-ahead coordinate must be the backend
    // address, not the transfer-relative offset.
    let lun = ReadLun {
        len: transfer_len,
        shift: 4096,
        ..Default::default()
    };
    drive_read_core_with(lun, transfer_len)
}

/// [`drive_read_core`] with a caller-supplied LUN.
fn drive_read_core_with(mut lun: ReadLun, transfer_len: u64) -> Vec<CoreStep> {
    let mut session = BotSession::new();
    let mut work = [0u8; snowscsi::MIN_DATA_LEN];
    let mut devs: [&mut dyn ScsiDevice; 1] = [&mut lun];
    let cbw = raw_cbw(1, transfer_len as u32, 0x80, 0, &[0xC1, 0, 0, 0, 0, 0]);

    let mut steps = Vec::new();
    let mut ev = Event::Tick;
    let mut cbw_pending = true;
    loop {
        let step = poll_core(&mut session, ev, &mut work, &mut devs);
        steps.push(step);
        ev = match step {
            CoreStep::Recv { len, probe: false } => {
                if cbw_pending {
                    work[..len].copy_from_slice(&cbw[..len]);
                    cbw_pending = false;
                }
                Event::HostRecv { len }
            }
            CoreStep::Recv { probe: true, .. } => break,
            // A CSW ends the transaction; stop here.
            CoreStep::Send { len, .. } if len == snowscsi::usb::CSW_LEN => break,
            CoreStep::Send { .. } => Event::HostSent,
            CoreStep::Store { .. } => Event::StoreDone { result: Ok(()) },
            CoreStep::StallBoth | CoreStep::StallIn | CoreStep::Error => break,
        };
    }
    steps
}

/// A Data-Out write spanning three receive cycles: the core's write-ahead
/// budget (`Action::Store::next_recv`) equals the length of the `HostRecv` it
/// asks for next, the last store latches (`None`), and the shell pre-receives
/// the final chunk into the whole scratch so the wire is unchanged.
#[test]
fn overlap_write_three_cycles_next_recv_matches_recv() {
    // 40 blocks = 20480 bytes = 8192 + 8192 + 4096 (three receive cycles).
    let core = drive_write_core(20480, 40);
    let stores: Vec<Option<usize>> = core
        .iter()
        .filter_map(|s| match s {
            CoreStep::Store { next_recv, .. } => Some(*next_recv),
            _ => None,
        })
        .collect();
    assert_eq!(stores, vec![Some(8192), Some(4096), None], "store budgets");
    // Every write-ahead budget equals the length of the receive that follows.
    for (i, step) in core.iter().enumerate() {
        if let CoreStep::Store {
            next_recv: Some(n), ..
        } = step
        {
            match core.get(i + 1) {
                Some(CoreStep::Recv { len, probe: false }) => {
                    assert_eq!(*len, *n, "next_recv must match the next HostRecv")
                }
                other => panic!("expected a HostRecv after a Store, got {other:?}"),
            }
        }
    }

    // The same write through the shell. The final 4096-byte chunk is
    // pre-received into the whole 8192-byte scratch, so its receive has
    // `want == scratch.len()` while delivering 4096 — the write-ahead marker.
    let mut ram = vec![0u8; 64 * 1024];
    let mut backend = snowscsi::scsi::backend::RamBackend::new(&mut ram);
    let mut dev = block_device(&mut backend);
    let mut session = BotSession::new();
    let mut work = [0u8; snowscsi::MIN_DATA_LEN];
    let mut scratch = [0u8; snowscsi::MIN_DATA_LEN];
    let mut gadget = RecGadget::default();
    let steps = vec![
        OutStep::Bytes(raw_cbw(1, 20480, 0x00, 0, &rw10(0x2A, 0, 40)).to_vec()),
        OutStep::Bytes(vec![0x5A; 8192]),
        OutStep::Bytes(vec![0x6B; 8192]),
        OutStep::Bytes(vec![0x7C; 4096]),
        OutStep::WouldBlock,
    ];
    let mut devs: [&mut dyn ScsiDevice; 1] = [&mut dev];
    let mut planes: [Option<RecPlane>; 1] = [Some(RecPlane::default())];
    let mut luns = AsyncLuns::new(&mut devs, &mut planes);
    let state = run_scripted_shell(
        steps,
        &mut gadget,
        &mut session,
        &mut work,
        &mut scratch,
        &mut luns,
    );
    let state = state.borrow();

    assert_eq!(
        h2d_lens(&state.wire),
        vec![31, 8192, 8192, 4096],
        "host packets unchanged"
    );
    assert_wire_csw(&state.wire, 1, 0, 0x00);
    let plane = planes[0].as_ref().unwrap();
    assert_eq!(
        plane.writes(),
        vec![(0, 8192), (8192, 8192), (16384, 4096)],
        "one write per receive cycle"
    );
    // Each store receives its own chunk's bytes: a buffer-ordering bug that
    // swapped the in-flight chunk with the pre-received one would show here.
    assert_eq!(
        plane.written_bytes(),
        [
            (0u64, vec![0x5A; 8192]),
            (8192, vec![0x6B; 8192]),
            (16384, vec![0x7C; 4096]),
        ],
        "each store writes its own chunk"
    );
    assert_eq!(
        state.events,
        vec![
            SeamEvent::Recv {
                kind: RecvKind::Until,
                want: 31,
                got: RecvOut::Bytes(31),
            },
            SeamEvent::Recv {
                kind: RecvKind::Until,
                want: 8192,
                got: RecvOut::Bytes(8192),
            },
            // Write-ahead of the second chunk (budget 8192).
            SeamEvent::Recv {
                kind: RecvKind::Until,
                want: 8192,
                got: RecvOut::Bytes(8192),
            },
            // Write-ahead of the final chunk: the receive is bounded by the
            // latched budget (4096 — the transfer's remainder), not by the
            // scratch (8192). Offering the whole scratch here makes a real
            // transport park on the poll granularity waiting for bytes the
            // host has no more of, one full granularity per command.
            SeamEvent::Recv {
                kind: RecvKind::Until,
                want: 4096,
                got: RecvOut::Bytes(4096),
            },
            // Overrun probe after the declared bytes are consumed.
            SeamEvent::Recv {
                kind: RecvKind::Probe,
                want: 8192,
                got: RecvOut::WouldBlock,
            },
            SeamEvent::Send { len: 13 },
            // The next command receive finds the script exhausted.
            SeamEvent::Recv {
                kind: RecvKind::Until,
                want: 31,
                got: RecvOut::Bytes(0),
            },
        ],
        "overlap event sequence"
    );
}

/// A host packet larger than the write-ahead budget: the shell caps the feed at
/// the budget (not the whole packet), so the declared phase ends exactly and
/// the core returns an overrun probe — the shell must not feed a plain
/// `HostRecv` after `StoreDone`.
#[test]
fn overlap_store_done_probe_not_fed_a_plain_recv() {
    // 40 blocks = 20480 = 8192 + 8192 + 8192 (the host sends 4096 too many).
    let mut ram = vec![0u8; 64 * 1024];
    let mut backend = snowscsi::scsi::backend::RamBackend::new(&mut ram);
    let mut dev = block_device(&mut backend);
    let mut session = BotSession::new();
    let mut work = [0u8; snowscsi::MIN_DATA_LEN];
    let mut scratch = [0u8; snowscsi::MIN_DATA_LEN];
    let mut gadget = RecGadget::default();
    let steps = vec![
        OutStep::Bytes(raw_cbw(1, 20480, 0x00, 0, &rw10(0x2A, 0, 40)).to_vec()),
        OutStep::Bytes(vec![0x11; 8192]),
        OutStep::Bytes(vec![0x22; 8192]),
        OutStep::Bytes(vec![0x33; 8192]),
        OutStep::WouldBlock,
    ];
    let mut devs: [&mut dyn ScsiDevice; 1] = [&mut dev];
    let mut planes: [Option<RecPlane>; 1] = [Some(RecPlane::default())];
    let mut luns = AsyncLuns::new(&mut devs, &mut planes);
    let state = run_scripted_shell(
        steps,
        &mut gadget,
        &mut session,
        &mut work,
        &mut scratch,
        &mut luns,
    );
    let state = state.borrow();

    assert_wire_csw(&state.wire, 1, 0, 0x00);
    assert_eq!(h2d_lens(&state.wire), vec![31, 8192, 8192, 8192]);
    // The write-ahead of the final chunk is bounded by the 4096-byte budget
    // (never the scratch), so the phase ends exactly and the shell probes.
    assert_eq!(
        state.events,
        vec![
            SeamEvent::Recv {
                kind: RecvKind::Until,
                want: 31,
                got: RecvOut::Bytes(31),
            },
            SeamEvent::Recv {
                kind: RecvKind::Until,
                want: 8192,
                got: RecvOut::Bytes(8192),
            },
            SeamEvent::Recv {
                kind: RecvKind::Until,
                want: 8192,
                got: RecvOut::Bytes(8192),
            },
            SeamEvent::Recv {
                kind: RecvKind::Until,
                want: 4096,
                got: RecvOut::Bytes(4096),
            },
            SeamEvent::Recv {
                kind: RecvKind::Probe,
                want: 8192,
                got: RecvOut::WouldBlock,
            },
            SeamEvent::Send { len: 13 },
            SeamEvent::Recv {
                kind: RecvKind::Until,
                want: 31,
                got: RecvOut::Bytes(0),
            },
        ],
        "the shell must probe (not feed a plain HostRecv) after the final chunk"
    );
}

/// A write-ahead receive that times out (`WouldBlock`): the shell feeds only
/// the store result, and the core then asks for the remaining receive normally.
#[test]
fn overlap_prerecv_timeout_feeds_store_done_only() {
    // 32 blocks = 16384 = 8192 + 8192.
    let mut ram = vec![0u8; 64 * 1024];
    let mut backend = snowscsi::scsi::backend::RamBackend::new(&mut ram);
    let mut dev = block_device(&mut backend);
    let mut session = BotSession::new();
    let mut work = [0u8; snowscsi::MIN_DATA_LEN];
    let mut scratch = [0u8; snowscsi::MIN_DATA_LEN];
    let mut gadget = RecGadget::default();
    let steps = vec![
        OutStep::Bytes(raw_cbw(1, 16384, 0x00, 0, &rw10(0x2A, 0, 32)).to_vec()),
        OutStep::Bytes(vec![0x11; 8192]),
        OutStep::WouldBlock,
        OutStep::Bytes(vec![0x22; 8192]),
        OutStep::WouldBlock,
    ];
    let mut devs: [&mut dyn ScsiDevice; 1] = [&mut dev];
    let mut planes: [Option<RecPlane>; 1] = [Some(RecPlane::default())];
    let mut luns = AsyncLuns::new(&mut devs, &mut planes);
    let state = run_scripted_shell(
        steps,
        &mut gadget,
        &mut session,
        &mut work,
        &mut scratch,
        &mut luns,
    );
    let state = state.borrow();

    assert_wire_csw(&state.wire, 1, 0, 0x00);
    assert_eq!(h2d_lens(&state.wire), vec![31, 8192, 8192]);
    // The timeout is followed by a normal receive of the same chunk.
    assert_eq!(
        state.events,
        vec![
            SeamEvent::Recv {
                kind: RecvKind::Until,
                want: 31,
                got: RecvOut::Bytes(31),
            },
            SeamEvent::Recv {
                kind: RecvKind::Until,
                want: 8192,
                got: RecvOut::Bytes(8192),
            },
            // The write-ahead receive times out.
            SeamEvent::Recv {
                kind: RecvKind::Until,
                want: 8192,
                got: RecvOut::WouldBlock,
            },
            // The core re-asks after the store result is fed.
            SeamEvent::Recv {
                kind: RecvKind::Until,
                want: 8192,
                got: RecvOut::Bytes(8192),
            },
            SeamEvent::Recv {
                kind: RecvKind::Probe,
                want: 8192,
                got: RecvOut::WouldBlock,
            },
            SeamEvent::Send { len: 13 },
            SeamEvent::Recv {
                kind: RecvKind::Until,
                want: 31,
                got: RecvOut::Bytes(0),
            },
        ],
        "a timed-out write-ahead receive feeds only the store result"
    );
}

/// Read-ahead **hit**: the speculative read matches the core's next read, so
/// the core's store is skipped — exactly one read per chunk.
///
/// The media has a non-zero base offset (`shift`): the read-ahead coordinate
/// must be the backend address `base + transfer_offset`, not the
/// transfer-relative offset. A core that emitted the latter would miss here and
/// read every chunk twice — the ESP32-P4 in-situ measurement was 4.0 MB/s with
/// the bug and 7.0 MB/s without it.
#[test]
fn overlap_read_prefetch_hit_skips_the_real_op() {
    // 40 blocks = 20480 = 8192 + 8192 + 4096, served as `Store(Read)` chunks.
    let mut lun = ReadLun {
        len: 20480,
        shift: 64,
        ..Default::default()
    };
    let mut session = BotSession::new();
    let mut work = [0u8; snowscsi::MIN_DATA_LEN];
    let mut scratch = [0u8; snowscsi::MIN_DATA_LEN];
    let mut gadget = RecGadget::default();
    let steps = vec![
        OutStep::Bytes(raw_cbw(1, 20480, 0x80, 0, &[0xC1, 0, 0, 0, 0, 0]).to_vec()),
        OutStep::WouldBlock,
    ];
    let mut devs: [&mut dyn ScsiDevice; 1] = [&mut lun];
    let mut planes: [Option<RecPlane>; 1] = [Some(RecPlane::default())];
    let mut luns = AsyncLuns::new(&mut devs, &mut planes);
    let state = run_scripted_shell(
        steps,
        &mut gadget,
        &mut session,
        &mut work,
        &mut scratch,
        &mut luns,
    );
    let state = state.borrow();

    // One read per chunk: a hit skips the core's store, so the chunk is not
    // read a second time (a shell that speculates but does not skip would read
    // six times).
    assert_eq!(
        planes[0].as_ref().unwrap().reads(),
        vec![(64, 8192), (8256, 8192), (16448, 4096)],
        "one read per chunk (a hit skips the core's store)"
    );
    assert_eq!(d2h_lens(&state.wire), vec![8192, 8192, 4096, 13]);
    assert_wire_csw(&state.wire, 1, 0, 0x00);
}

/// Read-ahead **miss**: the device's reported coordinate does not match the read
/// it later issues (`ahead_skew`), so the shell executes the real op after the
/// speculative read.
#[test]
fn overlap_read_prefetch_miss_executes_the_real_op() {
    // The device over-reports its read-ahead address by 64 bytes, so the core's
    // store never matches the coordinate. (A non-zero *base* offset, `shift`, is
    // not a miss: see `overlap_read_prefetch_hit_skips_the_real_op`.)
    let mut lun = ReadLun {
        len: 20480,
        ahead_skew: 64,
        ..Default::default()
    };
    let mut session = BotSession::new();
    let mut work = [0u8; snowscsi::MIN_DATA_LEN];
    let mut scratch = [0u8; snowscsi::MIN_DATA_LEN];
    let mut gadget = RecGadget::default();
    let steps = vec![
        OutStep::Bytes(raw_cbw(1, 20480, 0x80, 0, &[0xC1, 0, 0, 0, 0, 0]).to_vec()),
        OutStep::WouldBlock,
    ];
    let mut devs: [&mut dyn ScsiDevice; 1] = [&mut lun];
    let mut planes: [Option<RecPlane>; 1] = [Some(RecPlane::default())];
    let mut luns = AsyncLuns::new(&mut devs, &mut planes);
    let state = run_scripted_shell(
        steps,
        &mut gadget,
        &mut session,
        &mut work,
        &mut scratch,
        &mut luns,
    );
    let state = state.borrow();

    // chunk 1 is served serially; chunks 2 and 3 each get a speculative read
    // followed by the real op because the coordinate misses.
    assert_eq!(
        planes[0].as_ref().unwrap().reads(),
        vec![
            (0, 8192),
            (8256, 8192),
            (8192, 8192),
            (16448, 4096),
            (16384, 4096),
        ],
        "a miss executes the core's op after the speculative read"
    );
    assert_wire_csw(&state.wire, 1, 0, 0x00);
}

/// Opting out of read-ahead (`read_ahead_offset` -> `None`, the trait default for
/// any `ScsiDevice` that does not implement it) must emit no prefetch at all: the
/// core offers no coordinate, so the shell reads every chunk serially — each one
/// exactly once, at the address `xfer_out` gave.
#[test]
fn overlap_read_prefetch_opt_out_reads_serially() {
    let lun = ReadLun {
        len: 16384,
        shift: 4096,
        no_read_ahead: true,
        ..Default::default()
    };
    let steps = drive_read_core_with(lun, 16384);

    for (i, step) in steps.iter().enumerate() {
        if let CoreStep::Send { prefetch, .. } = step {
            assert_eq!(
                *prefetch, None,
                "step {i}: an opted-out device offers no coordinate"
            );
        }
    }
    let reads: Vec<(u64, usize)> = steps
        .iter()
        .filter_map(|s| match s {
            CoreStep::Store { read: Some(r), .. } => Some(*r),
            _ => None,
        })
        .collect();
    assert_eq!(
        reads,
        vec![(4096, 8192), (12288, 8192)],
        "serial reads at the backend address"
    );
}

/// A failing speculative read is swallowed: the shell executes the real op,
/// which succeeds, and the chunk data on the wire comes from that op.
#[test]
fn overlap_read_prefetch_error_is_swallowed_and_real_op_reruns() {
    let mut lun = ReadLun {
        len: 20480,
        shift: 0,
        ..Default::default()
    };
    let mut session = BotSession::new();
    let mut work = [0u8; snowscsi::MIN_DATA_LEN];
    let mut scratch = [0u8; snowscsi::MIN_DATA_LEN];
    let mut gadget = RecGadget::default();
    let steps = vec![
        OutStep::Bytes(raw_cbw(1, 20480, 0x80, 0, &[0xC1, 0, 0, 0, 0, 0]).to_vec()),
        OutStep::WouldBlock,
    ];
    let mut devs: [&mut dyn ScsiDevice; 1] = [&mut lun];
    // Read call #1 is the speculative read-ahead for the second chunk; failing
    // it must not abort the read.
    let plane = RecPlane {
        fail_read: Some(1),
        ..RecPlane::default()
    };
    let mut planes: [Option<RecPlane>; 1] = [Some(plane)];
    let mut luns = AsyncLuns::new(&mut devs, &mut planes);
    let state = run_scripted_shell(
        steps,
        &mut gadget,
        &mut session,
        &mut work,
        &mut scratch,
        &mut luns,
    );
    let state = state.borrow();

    // The speculative read fails, then the real op re-reads the same chunk.
    assert_eq!(
        planes[0].as_ref().unwrap().reads(),
        vec![(0, 8192), (8192, 8192), (8192, 8192), (16384, 4096)],
        "the real op re-runs after a swallowed speculative error"
    );
    assert_wire_csw(&state.wire, 1, 0, 0x00);
    // The second chunk's wire data came from the successful real op.
    let chunks: Vec<&[u8]> = state
        .wire
        .iter()
        .filter_map(|e| match e {
            TraceEntry::D2H(b) if b.len() == 8192 => Some(b.as_slice()),
            _ => None,
        })
        .collect();
    assert_eq!(chunks.len(), 2, "two full chunks");
    let expected: Vec<u8> = (0..8192).map(|i| ((8192 + i) % 251) as u8).collect();
    assert_eq!(
        chunks[1],
        expected.as_slice(),
        "the real op supplied the chunk data"
    );
}

/// The final chunk's write-ahead budget is `None` (a latch): the shell does not
/// pre-receive, so the data receive is the core's own request.
#[test]
fn overlap_final_chunk_latches_without_prerecv() {
    // A single-chunk write: 16 blocks = 8192 = one receive.
    let core = drive_write_core(8192, 16);
    let stores: Vec<Option<usize>> = core
        .iter()
        .filter_map(|s| match s {
            CoreStep::Store { next_recv, .. } => Some(*next_recv),
            _ => None,
        })
        .collect();
    assert_eq!(stores, vec![None], "the final store latches");

    let mut ram = vec![0u8; 64 * 1024];
    let mut backend = snowscsi::scsi::backend::RamBackend::new(&mut ram);
    let mut dev = block_device(&mut backend);
    let mut session = BotSession::new();
    let mut work = [0u8; snowscsi::MIN_DATA_LEN];
    let mut scratch = [0u8; snowscsi::MIN_DATA_LEN];
    let mut gadget = RecGadget::default();
    let steps = vec![
        OutStep::Bytes(raw_cbw(1, 8192, 0x00, 0, &rw10(0x2A, 0, 16)).to_vec()),
        OutStep::Bytes(vec![0x44; 8192]),
        OutStep::WouldBlock,
    ];
    let mut devs: [&mut dyn ScsiDevice; 1] = [&mut dev];
    let mut planes: [Option<RecPlane>; 1] = [Some(RecPlane::default())];
    let mut luns = AsyncLuns::new(&mut devs, &mut planes);
    let state = run_scripted_shell(
        steps,
        &mut gadget,
        &mut session,
        &mut work,
        &mut scratch,
        &mut luns,
    );
    let state = state.borrow();

    assert_wire_csw(&state.wire, 1, 0, 0x00);
    assert_eq!(h2d_lens(&state.wire), vec![31, 8192]);
    assert_eq!(
        state.events,
        vec![
            SeamEvent::Recv {
                kind: RecvKind::Until,
                want: 31,
                got: RecvOut::Bytes(31),
            },
            // The data receive is the core's own request (want == 8192), not a
            // whole-scratch write-ahead.
            SeamEvent::Recv {
                kind: RecvKind::Until,
                want: 8192,
                got: RecvOut::Bytes(8192),
            },
            SeamEvent::Recv {
                kind: RecvKind::Probe,
                want: 8192,
                got: RecvOut::WouldBlock,
            },
            SeamEvent::Send { len: 13 },
            SeamEvent::Recv {
                kind: RecvKind::Until,
                want: 31,
                got: RecvOut::Bytes(0),
            },
        ],
        "a latched final chunk is not pre-received"
    );
}

/// A `BotReset` that arrives after a write-ahead pre-receive but before the
/// core's next poll drops the overlap state: the pre-received chunk is **not**
/// fed as a plain `HostRecv`, and the core re-emits a fresh command receive.
#[test]
fn overlap_write_reset_drops_prerecv() {
    // 32 blocks = 16384 = 8192 + 8192.
    let mut ram = vec![0u8; 64 * 1024];
    let mut backend = snowscsi::scsi::backend::RamBackend::new(&mut ram);
    let mut dev = block_device(&mut backend);
    let mut session = BotSession::new();
    let mut work = [0u8; snowscsi::MIN_DATA_LEN];
    let mut scratch = [0u8; snowscsi::MIN_DATA_LEN];
    let steps = vec![
        OutStep::Bytes(raw_cbw(1, 16384, 0x00, 0, &rw10(0x2A, 0, 32)).to_vec()),
        OutStep::Bytes(vec![0x11; 8192]),
        OutStep::Bytes(vec![0x22; 8192]),
    ];
    let state = SeamState::new(steps);
    // The reset surfaces only once the write-ahead pre-receive has happened.
    let mut gadget = ArmedGadget::new(Rc::clone(&state), Arm::Recvs(3), vec![CtrlStep::BotReset]);
    let mut devs: [&mut dyn ScsiDevice; 1] = [&mut dev];
    let mut planes: [Option<RecPlane>; 1] = [Some(RecPlane::default())];
    let mut luns = AsyncLuns::new(&mut devs, &mut planes);
    let result = run_scripted_with(
        Rc::clone(&state),
        &mut gadget,
        &mut session,
        &mut work,
        &mut scratch,
        &mut luns,
    );

    assert_eq!(result, Err(ServeError::Closed));
    assert_eq!(gadget.acks.len(), 1);
    assert!(gadget.acks[0].acked.load(Ordering::SeqCst), "reset acked");

    let state = state.borrow();
    // The pre-received chunk is dropped: the shell performs a fresh CBW receive
    // instead of answering the command phase from stale pre-received bytes.
    assert_eq!(
        state.events,
        vec![
            SeamEvent::Recv {
                kind: RecvKind::Until,
                want: 31,
                got: RecvOut::Bytes(31),
            },
            SeamEvent::Recv {
                kind: RecvKind::Until,
                want: 8192,
                got: RecvOut::Bytes(8192),
            },
            SeamEvent::Recv {
                kind: RecvKind::Until,
                want: 8192,
                got: RecvOut::Bytes(8192),
            },
            SeamEvent::Recv {
                kind: RecvKind::Until,
                want: 31,
                got: RecvOut::Bytes(0),
            },
        ],
        "the pre-received chunk is dropped and a fresh command receive follows"
    );
    assert!(
        !state.wire.iter().any(|e| matches!(e, TraceEntry::D2H(_))),
        "no CSW for the aborted write"
    );
}

/// A `GetMaxLun` that arrives mid-overlap does **not** drop the live
/// write-ahead pre-receive: the reply is sent and the pre-received chunk is fed
/// normally, so the write completes without a second receive for that chunk.
#[test]
fn overlap_get_max_lun_mid_prerecv_survives() {
    // 32 blocks = 16384 = 8192 + 8192.
    let mut ram = vec![0u8; 64 * 1024];
    let mut backend = snowscsi::scsi::backend::RamBackend::new(&mut ram);
    let mut dev = block_device(&mut backend);
    let mut session = BotSession::new();
    let mut work = [0u8; snowscsi::MIN_DATA_LEN];
    let mut scratch = [0u8; snowscsi::MIN_DATA_LEN];
    let steps = vec![
        OutStep::Bytes(raw_cbw(1, 16384, 0x00, 0, &rw10(0x2A, 0, 32)).to_vec()),
        OutStep::Bytes(vec![0x11; 8192]),
        OutStep::Bytes(vec![0x22; 8192]),
        OutStep::WouldBlock,
    ];
    let state = SeamState::new(steps);
    let mut gadget = ArmedGadget::new(Rc::clone(&state), Arm::Recvs(3), vec![CtrlStep::GetMaxLun]);
    let mut devs: [&mut dyn ScsiDevice; 1] = [&mut dev];
    let mut planes: [Option<RecPlane>; 1] = [Some(RecPlane::default())];
    let mut luns = AsyncLuns::new(&mut devs, &mut planes);
    let result = run_scripted_with(
        Rc::clone(&state),
        &mut gadget,
        &mut session,
        &mut work,
        &mut scratch,
        &mut luns,
    );

    assert_eq!(result, Err(ServeError::Closed));
    assert_eq!(gadget.replies.len(), 1);
    assert_eq!(
        gadget.replies[0].sent.lock().unwrap().as_slice(),
        &[0u8],
        "Get Max LUN replied"
    );

    let state = state.borrow();
    // No receive for the second chunk: it was answered from the live
    // pre-received bytes.
    assert_eq!(
        state.events,
        vec![
            SeamEvent::Recv {
                kind: RecvKind::Until,
                want: 31,
                got: RecvOut::Bytes(31),
            },
            SeamEvent::Recv {
                kind: RecvKind::Until,
                want: 8192,
                got: RecvOut::Bytes(8192),
            },
            SeamEvent::Recv {
                kind: RecvKind::Until,
                want: 8192,
                got: RecvOut::Bytes(8192),
            },
            SeamEvent::Recv {
                kind: RecvKind::Probe,
                want: 8192,
                got: RecvOut::WouldBlock,
            },
            SeamEvent::Send { len: 13 },
            SeamEvent::Recv {
                kind: RecvKind::Until,
                want: 31,
                got: RecvOut::Bytes(0),
            },
        ],
        "the live pre-receive survives a mid-overlap Get Max LUN"
    );
    assert_wire_csw(&state.wire, 1, 0, 0x00);
}

/// A `BotReset` that arrives after a read-ahead speculative read drops the
/// stale coordinate: the core re-emits a fresh command receive, and no further
/// chunk of the aborted read is sent.
#[test]
fn overlap_read_reset_mid_prefetch_reemits_fresh_action() {
    let mut lun = ReadLun {
        len: 20480,
        shift: 0,
        ..Default::default()
    };
    let mut session = BotSession::new();
    let mut work = [0u8; snowscsi::MIN_DATA_LEN];
    let mut scratch = [0u8; snowscsi::MIN_DATA_LEN];
    let steps = vec![OutStep::Bytes(
        raw_cbw(1, 20480, 0x80, 0, &[0xC1, 0, 0, 0, 0, 0]).to_vec(),
    )];
    let state = SeamState::new(steps);
    // The reset surfaces once the first chunk has been sent; its join also
    // performed the read-ahead speculative read.
    let mut gadget = ArmedGadget::new(Rc::clone(&state), Arm::Sends(1), vec![CtrlStep::BotReset]);
    let mut devs: [&mut dyn ScsiDevice; 1] = [&mut lun];
    let mut planes: [Option<RecPlane>; 1] = [Some(RecPlane::default())];
    let mut luns = AsyncLuns::new(&mut devs, &mut planes);
    let result = run_scripted_with(
        Rc::clone(&state),
        &mut gadget,
        &mut session,
        &mut work,
        &mut scratch,
        &mut luns,
    );

    assert_eq!(result, Err(ServeError::Closed));
    assert!(gadget.acks[0].acked.load(Ordering::SeqCst), "reset acked");

    let state = state.borrow();
    // Only the first chunk went out; the reset re-emits a fresh command
    // receive and the aborted read sends nothing more.
    assert_eq!(
        state.events,
        vec![
            SeamEvent::Recv {
                kind: RecvKind::Until,
                want: 31,
                got: RecvOut::Bytes(31),
            },
            SeamEvent::Send { len: 8192 },
            SeamEvent::Recv {
                kind: RecvKind::Until,
                want: 31,
                got: RecvOut::Bytes(0),
            },
        ],
        "the reset re-emits a fresh command receive after the aborted read"
    );
    assert_eq!(d2h_lens(&state.wire), vec![8192], "no second chunk sent");
}

/// A `BotReset` that surfaces **after** a CBW has already been received must
/// not swallow the command: the bytes are a fact, so the shell resets the
/// session and then dispatches the received CBW (matching the synchronous
/// loop, which drains a reset *before* reading). Dropping the `HostRecv` here
/// leaves the host with no CSW and is fatal under a host that performs reset
/// recovery around every command.
#[test]
fn reset_after_cbw_recv_still_dispatches_the_command() {
    let mut ram = vec![0u8; 64 * 1024];
    let mut backend = snowscsi::scsi::backend::RamBackend::new(&mut ram);
    let mut dev = block_device(&mut backend);
    let mut session = BotSession::new();
    let mut work = [0u8; snowscsi::MIN_DATA_LEN];
    let mut scratch = [0u8; snowscsi::MIN_DATA_LEN];
    // One TEST UNIT READY CBW, then the script is exhausted (the next receive
    // closes the link).
    let steps = vec![OutStep::Bytes(
        raw_cbw(7, 0, 0x00, 0, &[0x00, 0, 0, 0, 0, 0]).to_vec(),
    )];
    let state = SeamState::new(steps);
    // The reset becomes visible as soon as the CBW receive completed, i.e. in
    // the shell's post-await control drain.
    let mut gadget = ArmedGadget::new(Rc::clone(&state), Arm::Recvs(1), vec![CtrlStep::BotReset]);
    let mut devs: [&mut dyn ScsiDevice; 1] = [&mut dev];
    let mut planes: [Option<RecPlane>; 1] = [Some(RecPlane::default())];
    let mut luns = AsyncLuns::new(&mut devs, &mut planes);
    let result = run_scripted_with(
        Rc::clone(&state),
        &mut gadget,
        &mut session,
        &mut work,
        &mut scratch,
        &mut luns,
    );

    assert_eq!(result, Err(ServeError::Closed));
    assert_eq!(gadget.acks.len(), 1);
    assert!(gadget.acks[0].acked.load(Ordering::SeqCst), "reset acked");

    let state = state.borrow();
    // The CBW is dispatched to the reset session: the injected UNIT ATTENTION
    // fails the TUR, so a Failed CSW goes out. A fresh command receive follows.
    assert_eq!(
        state.events,
        vec![
            SeamEvent::Recv {
                kind: RecvKind::Until,
                want: 31,
                got: RecvOut::Bytes(31),
            },
            SeamEvent::Send { len: 13 },
            SeamEvent::Recv {
                kind: RecvKind::Until,
                want: 31,
                got: RecvOut::Bytes(0),
            },
        ],
        "the received CBW survives the reset and is dispatched"
    );
    assert_wire_csw(&state.wire, 7, 0, 0x01);
}

/// The read-ahead hit test is `buf.len() <= prefetch.len`. In the shipped core
/// the read op the shell is asked for next is *exactly* the read-ahead
/// coordinate, so that criterion is always an equality — a strictly-shorter
/// real read (the relaxed prefix case) cannot be produced by the core. This
/// pins the invariant across chunk boundaries.
#[test]
fn overlap_read_prefetch_len_equals_real_op_len() {
    for transfer_len in [16384u64, 20480, 16484] {
        let steps = drive_read_core(transfer_len);
        let mut checked = 0usize;
        for (i, step) in steps.iter().enumerate() {
            if let CoreStep::Send {
                prefetch: Some((_, poff, plen)),
                ..
            } = step
            {
                match steps.get(i + 1) {
                    Some(CoreStep::Store {
                        read: Some((off, len)),
                        ..
                    }) => {
                        assert_eq!(*off, *poff, "prefetch off == read op off ({transfer_len})");
                        assert_eq!(*len, *plen, "prefetch len == read op len ({transfer_len})");
                        checked += 1;
                    }
                    other => panic!("expected a read store after a prefetch, got {other:?}"),
                }
            }
        }
        assert!(checked >= 1, "at least one read-ahead for {transfer_len}");
    }
}

/// A write-ahead pre-receive that reports `Disconnected` resets the session
/// (it is not fed as a plain receive), and the core re-emits a fresh command
/// receive.
#[test]
fn overlap_prerecv_disconnected_resets() {
    // 32 blocks = 16384 = 8192 + 8192.
    let mut ram = vec![0u8; 64 * 1024];
    let mut backend = snowscsi::scsi::backend::RamBackend::new(&mut ram);
    let mut dev = block_device(&mut backend);
    let mut session = BotSession::new();
    let mut work = [0u8; snowscsi::MIN_DATA_LEN];
    let mut scratch = [0u8; snowscsi::MIN_DATA_LEN];
    let steps = vec![
        OutStep::Bytes(raw_cbw(1, 16384, 0x00, 0, &rw10(0x2A, 0, 32)).to_vec()),
        OutStep::Bytes(vec![0x11; 8192]),
        OutStep::Disconnect,
    ];
    let mut gadget = RecGadget::default();
    let mut devs: [&mut dyn ScsiDevice; 1] = [&mut dev];
    let mut planes: [Option<RecPlane>; 1] = [Some(RecPlane::default())];
    let mut luns = AsyncLuns::new(&mut devs, &mut planes);
    let state = run_scripted_shell(
        steps,
        &mut gadget,
        &mut session,
        &mut work,
        &mut scratch,
        &mut luns,
    );
    let state = state.borrow();

    assert_eq!(
        state.events,
        vec![
            SeamEvent::Recv {
                kind: RecvKind::Until,
                want: 31,
                got: RecvOut::Bytes(31),
            },
            SeamEvent::Recv {
                kind: RecvKind::Until,
                want: 8192,
                got: RecvOut::Bytes(8192),
            },
            // The write-ahead receive reports a link drop: reset, not a feed.
            SeamEvent::Recv {
                kind: RecvKind::Until,
                want: 8192,
                got: RecvOut::Disconnect,
            },
            SeamEvent::Recv {
                kind: RecvKind::Until,
                want: 31,
                got: RecvOut::Bytes(0),
            },
        ],
        "a pre-receive disconnect resets (not fed as a plain receive)"
    );
    assert!(
        !state.wire.iter().any(|e| matches!(e, TraceEntry::D2H(_))),
        "no CSW for the aborted write"
    );
}

/// A write-ahead pre-receive that reports `Ok(0)` (link down) closes the loop
/// with [`ServeError::Closed`].
#[test]
fn overlap_prerecv_eof_closes() {
    // 32 blocks = 16384 = 8192 + 8192.
    let mut ram = vec![0u8; 64 * 1024];
    let mut backend = snowscsi::scsi::backend::RamBackend::new(&mut ram);
    let mut dev = block_device(&mut backend);
    let mut session = BotSession::new();
    let mut work = [0u8; snowscsi::MIN_DATA_LEN];
    let mut scratch = [0u8; snowscsi::MIN_DATA_LEN];
    let steps = vec![
        OutStep::Bytes(raw_cbw(1, 16384, 0x00, 0, &rw10(0x2A, 0, 32)).to_vec()),
        OutStep::Bytes(vec![0x11; 8192]),
        // A zero-length pre-receive is a closed link.
        OutStep::Bytes(Vec::new()),
    ];
    let mut gadget = RecGadget::default();
    let mut devs: [&mut dyn ScsiDevice; 1] = [&mut dev];
    let mut planes: [Option<RecPlane>; 1] = [Some(RecPlane::default())];
    let mut luns = AsyncLuns::new(&mut devs, &mut planes);
    let (state, result) = run_scripted_shell_result(
        steps,
        &mut gadget,
        &mut session,
        &mut work,
        &mut scratch,
        &mut luns,
    );

    assert_eq!(result, Err(ServeError::Closed));
    let state = state.borrow();
    assert_eq!(
        state.events,
        vec![
            SeamEvent::Recv {
                kind: RecvKind::Until,
                want: 31,
                got: RecvOut::Bytes(31),
            },
            SeamEvent::Recv {
                kind: RecvKind::Until,
                want: 8192,
                got: RecvOut::Bytes(8192),
            },
            // The write-ahead receive reports EOF: the loop closes.
            SeamEvent::Recv {
                kind: RecvKind::Until,
                want: 8192,
                got: RecvOut::Bytes(0),
            },
        ],
        "a zero-length write-ahead receive closes the loop"
    );
}

/// A read-ahead on a LUN with no store plane: the speculative read is skipped
/// (no plane to read from) and the core's real read then reports the shell's
/// own internal error rather than using stale bytes. The first chunk is served
/// in place so the read-ahead is reached at all.
#[test]
fn overlap_prefetch_no_plane_reports_internal() {
    let mut lun = ReadLun {
        len: 20480,
        shift: 0,
        first_inline: true,
        ..Default::default()
    };
    let mut session = BotSession::new();
    let mut work = [0u8; snowscsi::MIN_DATA_LEN];
    let mut scratch = [0u8; snowscsi::MIN_DATA_LEN];
    let steps = vec![
        OutStep::Bytes(raw_cbw(1, 20480, 0x80, 0, &[0xC1, 0, 0, 0, 0, 0]).to_vec()),
        OutStep::WouldBlock,
    ];
    let mut gadget = RecGadget::default();
    let mut devs: [&mut dyn ScsiDevice; 1] = [&mut lun];
    let mut planes: [Option<RecPlane>; 1] = [None];
    let mut luns = AsyncLuns::new(&mut devs, &mut planes);
    let (state, result) = run_scripted_shell_result(
        steps,
        &mut gadget,
        &mut session,
        &mut work,
        &mut scratch,
        &mut luns,
    );

    // The speculative read is skipped; the real read then reports the shell's
    // own error (there is no plane to execute it against).
    assert_eq!(result, Err(ServeError::Internal));
    let state = state.borrow();
    assert_eq!(
        d2h_lens(&state.wire),
        vec![8192],
        "the in-place first chunk is sent; no chunk after the failed read"
    );
}
