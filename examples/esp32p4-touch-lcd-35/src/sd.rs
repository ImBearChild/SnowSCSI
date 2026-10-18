//! SD card storage.
//!
//! Bridges `esp-hal`'s SDMMC host controller + the `sdio` crate's SD memory
//! card protocol to `snowscsi_common`'s storage seams ([`FlatData`] +
//! [`WritableFlatData`] and the asynchronous [`AsyncFlatData`] +
//! [`AsyncWritableFlatData`]).
//!
//! # Block geometry (512-byte SD blocks vs. 2048-byte logical sectors)
//!
//! An SD memory card is addressed in **512-byte physical blocks**. The CD/MMC
//! layer above this adapter reports **2048-byte logical sectors** (the optical
//! sector size). This adapter therefore presents a byte-addressed plane:
//! callers hand it byte offsets and it converts them to
//! `block = off / SD_BLOCK_SIZE`, `within = off % SD_BLOCK_SIZE`. Runs of full
//! SD blocks are transferred in a single multi-block (CMD18/CMD25) command via
//! a static batch of up to [`BATCH_BLOCKS`] aligned blocks; unaligned head/tail
//! fragments go through the first slot of that same `Aligned<A4, [u8; 512]>`
//! batch (also required because the SDMMC IDMAC cannot DMA from PSRAM, and only
//! the batch is guaranteed to live in internal, DMA-aligned RAM).
//!
//! # Two planes over one card
//!
//! `sdio`'s public block surface is async (`block_device_driver::BlockDevice`)
//! and `esp-hal` only implements `sdio::MmcBus` for the `Async` slot. The card
//! therefore speaks the **asynchronous** storage seams
//! ([`AsyncFlatData`]/[`AsyncWritableFlatData`]) natively — each transfer is
//! awaited directly — and the shell executes the device's `Store` ops against
//! it.
//!
//! The **synchronous** seams ([`FlatData`]/[`WritableFlatData`]) are also
//! implemented, because the DVD-RAM media slot needs a synchronous geometry
//! view ([`DvdRamMedia::open`](snowscsi::cdrom::dvdram::DvdRamMedia::open) reads
//! `capacity()` through a `&mut dyn WritableFlatData`). They delegate to the
//! asynchronous implementation with [`embassy_futures::block_on`]; only the
//! capacity read is exercised on this path at runtime.
#![allow(dead_code)]

use aligned::{Aligned, A4};
use block_device_driver::BlockDevice as _;
use embassy_futures::block_on;
use embedded_hal_async::delay::DelayNs;
use esp_hal::gpio::{Level, Output, OutputConfig};
use esp_hal::sdmmc::{ClockSource, Config as SdmmcConfig, SdHostController, Slot, SlotConfig};
use esp_hal::time::Instant;
use esp_hal::Async;
use static_cell::StaticCell;

use snowscsi_common::async_seekable_storage::{AsyncFlatData, AsyncWritableFlatData};
use snowscsi_common::seekable_storage::{FlatData, StorageError, WritableFlatData};

use core::sync::atomic::{AtomicU32, Ordering};

/// Diagnostics for the status panel (delta-sampled by [`SdMark`]).
///
/// `READ_CALLS`/`READ_BYTES` are what the LUN asked for; `CARD_CMDS` /
/// `CARD_READ_BYTES` / `CACHE_HITS` are what the card actually saw, which is
/// how the read-ahead window's effect is measured.
pub static READ_CALLS: AtomicU32 = AtomicU32::new(0);
pub static READ_BYTES: AtomicU32 = AtomicU32::new(0);
pub static WRITE_BYTES: AtomicU32 = AtomicU32::new(0);

/// Read calls served entirely from the read-ahead window (no SD command).
pub static CACHE_HITS: AtomicU32 = AtomicU32::new(0);

/// SD read commands actually issued to the card.
pub static CARD_CMDS: AtomicU32 = AtomicU32::new(0);

/// Bytes fetched from the card by those commands (≥ [`READ_BYTES`] when the
/// window over-reads, < it as the cache is consumed).
pub static CARD_READ_BYTES: AtomicU32 = AtomicU32::new(0);

/// Microseconds spent inside [`AsyncFlatData::read_at`], whole call.
///
/// This is the storage half of the shell's read overlap: compared against the
/// window length it shows how much wall clock the plane owns, and against the
/// pipe's busy time whether the two actually run concurrently.
pub static READ_NS: AtomicU32 = AtomicU32::new(0);

/// Microseconds of [`READ_NS`] spent inside the SD multi-block command itself
/// (the remainder is the window-to-`buf` copy and the bookkeeping).
pub static READ_SD_NS: AtomicU32 = AtomicU32::new(0);

/// Microseconds spent inside [`AsyncWritableFlatData::write_at`], whole call.
pub static WRITE_NS: AtomicU32 = AtomicU32::new(0);

/// Microseconds of [`WRITE_NS`] spent inside the SD multi-block command.
pub static WRITE_SD_NS: AtomicU32 = AtomicU32::new(0);

/// SD commands that the card/driver rejected, per direction (diagnostics: a
/// non-zero value here is the root of any host-visible medium error).
pub static SD_RD_ERRORS: AtomicU32 = AtomicU32::new(0);
pub static SD_WR_ERRORS: AtomicU32 = AtomicU32::new(0);

/// Short tag for the `sdio` error a failed transfer returned.
///
/// `sdio`'s `MmcError` is `#[non_exhaustive]` and its `defmt::Format` is off in
/// this build, so the variant is spelled out here (and the `Card`/`Sdio`
/// payloads are surfaced separately by [`err_tag`]'s callers when needed).
pub fn err_tag(e: &sdio::MmcError) -> &'static str {
    use sdio::MmcError as M;
    match e {
        M::Timeout => "Timeout",
        M::Crc => "Crc",
        M::Busy => "Busy",
        M::Io => "Io",
        M::BlockSize => "BlockSize",
        M::Signaling => "Signaling",
        M::BusWidth => "BusWidth",
        M::Voltage => "Voltage",
        M::CardType => "CardType",
        M::Unsupported => "Unsupported",
        M::Card(_) => "Card",
        M::Sdio(_) => "Sdio",
        M::Other => "Other",
        _ => "Unknown",
    }
}

/// One refresh window of SD-layer counters, for the status panel.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SdSample {
    /// Bytes actually fetched from the card, KB/s.
    pub card_rd_kbps: u32,
    /// Bytes written to the card, KB/s.
    pub wr_kbps: u32,
    /// Share of read calls served by the read-ahead window without an SD
    /// command, %.
    pub cache_pct: u32,
    /// Mean bytes per SD read command.
    pub cmd_bytes: u32,
    /// Microseconds of the window spent inside `read_at` (SD command plus the
    /// window copy): the storage half of the read overlap.
    pub rd_busy_us: u32,
    /// Microseconds of that spent inside the SD read command itself.
    pub sd_busy_us: u32,
    /// Microseconds of the window spent inside `write_at`.
    pub wr_busy_us: u32,
    /// Microseconds of that spent inside the SD write command itself.
    pub sw_busy_us: u32,
    /// Length of the sampled window, microseconds (denominator for the busy
    /// shares).
    pub wall_us: u32,
}

/// Delta-sampler over the SD-layer counters (see [`SdSample`]).
///
/// The card-level rates are what actually crossed the SD bus; `card_rd_kbps`
/// differs from the shell's TX rate because the bus runs a 32-block window per
/// command while the storage plane hands the shell 8 KiB at a time.
pub struct SdMark {
    prev: Counters,
    at: Instant,
}

/// Snapshot of every SD-layer counter, so the sampler can delta them in one
/// step (a single `load` per field, no interleaving reads).
#[derive(Debug, Clone, Copy)]
struct Counters {
    read_calls: u32,
    write_bytes: u32,
    card_read_bytes: u32,
    card_cmds: u32,
    cache_hits: u32,
    read_ns: u32,
    read_sd_ns: u32,
    write_ns: u32,
    write_sd_ns: u32,
}

impl Counters {
    fn load() -> Self {
        let load = |a: &AtomicU32| a.load(Ordering::Relaxed);
        Self {
            read_calls: load(&READ_CALLS),
            write_bytes: load(&WRITE_BYTES),
            card_read_bytes: load(&CARD_READ_BYTES),
            card_cmds: load(&CARD_CMDS),
            cache_hits: load(&CACHE_HITS),
            read_ns: load(&READ_NS),
            read_sd_ns: load(&READ_SD_NS),
            write_ns: load(&WRITE_NS),
            write_sd_ns: load(&WRITE_SD_NS),
        }
    }

    /// Per-field wrapping delta `self - prev` (immune to a u32 wrap).
    fn delta(&self, prev: Self) -> Self {
        Self {
            read_calls: self.read_calls.wrapping_sub(prev.read_calls),
            write_bytes: self.write_bytes.wrapping_sub(prev.write_bytes),
            card_read_bytes: self.card_read_bytes.wrapping_sub(prev.card_read_bytes),
            card_cmds: self.card_cmds.wrapping_sub(prev.card_cmds),
            cache_hits: self.cache_hits.wrapping_sub(prev.cache_hits),
            read_ns: self.read_ns.wrapping_sub(prev.read_ns),
            read_sd_ns: self.read_sd_ns.wrapping_sub(prev.read_sd_ns),
            write_ns: self.write_ns.wrapping_sub(prev.write_ns),
            write_sd_ns: self.write_sd_ns.wrapping_sub(prev.write_sd_ns),
        }
    }
}

impl SdMark {
    /// Start sampling from the current counter values.
    pub fn new() -> Self {
        Self {
            prev: Counters::load(),
            at: Instant::now(),
        }
    }

    /// Sample the counters and return the rates over the elapsed window.
    pub fn take(&mut self) -> SdSample {
        let us = self.at.elapsed().as_micros().max(1);
        self.at = Instant::now();

        let now = Counters::load();
        let d = now.delta(self.prev);
        self.prev = now;

        let kbps = |b: u32| ((b as u64 * 1_000_000 / us) / 1000) as u32;
        SdSample {
            card_rd_kbps: kbps(d.card_read_bytes),
            wr_kbps: kbps(d.write_bytes),
            cache_pct: (d.cache_hits as u64 * 100 / d.read_calls.max(1) as u64) as u32,
            cmd_bytes: d.card_read_bytes.checked_div(d.card_cmds).unwrap_or(0),
            rd_busy_us: d.read_ns,
            sd_busy_us: d.read_sd_ns,
            wr_busy_us: d.write_ns,
            sw_busy_us: d.write_sd_ns,
            wall_us: us as u32,
        }
    }
}

impl Default for SdMark {
    fn default() -> Self {
        Self::new()
    }
}

/// Copy `dst.len()` bytes out of the block batch starting at byte `start`.
///
/// The batch is an array of 512-byte blocks, so a range can straddle elements.
fn copy_batch(batch: &[Aligned<A4, [u8; SD_BLOCK_SIZE]>], start: usize, dst: &mut [u8]) {
    let mut s = start;
    let mut d = 0;
    while d < dst.len() {
        let blk = s / SD_BLOCK_SIZE;
        let off = s % SD_BLOCK_SIZE;
        let n = core::cmp::min(SD_BLOCK_SIZE - off, dst.len() - d);
        dst[d..d + n].copy_from_slice(&batch[blk][off..off + n]);
        s += n;
        d += n;
    }
}

/// Native SD memory-card block size in bytes.
pub const SD_BLOCK_SIZE: usize = 512;

/// Target SD bus clock handed to `sdio` after bring-up.
///
/// Card initialization always runs at 400 kHz internally (`sdio`'s `INIT_FREQ`);
/// this value is the *operating* clock selected once the card is identified.
/// 40 MHz is the ceiling the default `Pll160m` module source can produce here
/// (module clock 80 MHz, `card = module / (2 * div)`); 50 MHz needs the SDIO PLL
/// module clock, which breaks writes (see [`SD_UHS_PLL`]). `sdio` may still
/// clamp below the request (see [`SdCard::freq`]).
const SD_BUS_FREQ_HZ: u32 = if SD_UHS_PLL { 100_000_000 } else { 40_000_000 };

/// Take the **UHS-I** path: module clock from the 200 MHz SDIO PLL
/// (`module_div: 2` → 100 MHz) and a 100 MHz card-clock request, with the slot
/// reporting 1.8 V support.
///
/// The driver caps the request at **50 MHz** (legal High Speed at 3.3 V, measured
/// working here) until the card has completed the CMD11 switch to 1.8 V, and only
/// then allows 100 MHz (SDR50) — which its `freq_to_card_div` reaches with
/// `card_div = 0`, i.e. by bypassing the divider, not by racing the module clock
/// (`module_div: 1` never gets through init). One build therefore serves both a
/// UHS-I card and a plain DS/HS one.
///
/// Writes only work with the drive-clock-edge fix in `vendor/esp-hal-1.2.2/`
/// (PERFORMANCE.md §5): with the vendored default drive edge the card rejects
/// every host→card write with a data CRC error at *any* card clock. 1.8 V itself
/// is untested here — `sdio` issues CMD11 only for a card that advertises UHS-I
/// and this one does not, so the bus stays at 3.3 V, where 50 MHz is legal High
/// Speed. `false` falls back to the 40 MHz default clock source.
const SD_UHS_PLL: bool = true;

/// SD bring-up / access failures.
#[derive(Debug, Clone, Copy, PartialEq, Eq, defmt::Format)]
pub enum SdError {
    /// `SdHostController::new` rejected the configuration.
    HostInit,
    /// The slot is already taken or otherwise unusable.
    SlotInit,
    /// Card identification / initialization failed.
    CardInit,
    /// A block transfer failed after the card was up.
    Access,
    /// Offset arithmetic left the card's addressable range.
    OutOfBounds,
}

/// The SDMMC host controller must outlive any slot it hands out, but the device
/// (which owns the slot) is what [`SdCard`] stores. There is no safe way to keep
/// a self-referential `host + slot` pair in one struct, so the single controller
/// is parked in a `static` for the lifetime of the program and the slot borrows
/// it. This also makes the adapter `'static`, matching `main`'s `'static`
/// peripheral singletons.
static HOST: StaticCell<SdHostController<'static>> = StaticCell::new();

/// Number of SD blocks in the aligned batch. 32 × 512 B = 16 KiB: the most a
/// single CMD18/CMD25 can carry through esp-hal's 4-entry, 4096-byte IDMAC
/// descriptor ring (`RING_LEN = 4`, `DMA_MAX_BUF_LEN = 4096`).
///
/// Measured on the P4: a 16 KiB command runs the bus at ~17.8 MB/s, an 8 KiB
/// one only ~10.6 MB/s — the per-command overhead is ~360 µs, so the big
/// window is what makes the SD side efficient. The shell still consumes 8 KiB
/// at a time because the write path needs it (see `WORK_LEN`).
const BATCH_BLOCKS: usize = 32;

/// Batch of SD blocks for multi-block (CMD18/CMD25) transfers.
///
/// 64-byte aligned: esp-hal's SDMMC IDMAC on the P4 requires `align(64)`
/// internal buffers (`dma::aligned::InternalMemory` is `repr(C, align(64))`
/// because P4 internal RAM is cached). `block_device_driver` fixes the buffer
/// element type at `Aligned<A4, [u8; 512]>` (4-byte) and is not generic over
/// its alignment, so the array is wrapped here. Without the padding esp-hal
/// **bounces** an unaligned buffer's head/tail through its scratch into extra
/// descriptors; an 8 KiB transfer then already needs all four of the ring's
/// entries, and anything larger overruns it and fails.
#[repr(align(64))]
struct Batch([Aligned<A4, [u8; SD_BLOCK_SIZE]>; BATCH_BLOCKS]);

/// Batch of SD blocks for multi-block (CMD18/CMD25) transfers. Static, because
/// the main task's stack is only 8 KiB.
static BATCH: StaticCell<Batch> = StaticCell::new();

/// Blocking `DelayNs` implemented as a busy-wait on `esp_hal::time::Instant`.
///
/// `sdio` requires the *async* `embedded_hal_async::delay::DelayNs`. Under
/// [`embassy_futures::block_on`] (a waker-less busy loop) a timer that relies on
/// an interrupt to wake it still eventually completes, but a self-contained
/// busy-wait is strictly more robust: it never depends on the embassy time
/// driver being installed or on interrupt delivery, and `Instant` is read
/// straight from the system timer. `esp_hal::delay::Delay` does not implement
/// the async trait, and `embassy_time::Delay` needs the esp-rtos time driver, so
/// neither is used.
#[derive(Debug, Clone, Copy, Default)]
struct BusyDelay;

impl DelayNs for BusyDelay {
    async fn delay_ns(&mut self, ns: u32) {
        // `Instant` has 1 µs resolution, so round sub-microsecond requests up.
        let micros = (ns as u64).div_ceil(1_000);
        let start = Instant::now();
        while start.elapsed().as_micros() < micros {
            core::hint::spin_loop();
        }
    }
}

/// Boot-time SD read benchmark: sequentially reads 50 MiB with 16 KiB
/// (CMD23+CMD18) commands and prints the achieved rate. Read-only, so it never
/// touches card contents.
const SD_READ_TEST: bool = true;

/// Bytes read by [`sd_read_test`]: 50 MiB.
const SD_READ_TEST_BYTES: u64 = 50 * 1024 * 1024;

/// See [`SD_READ_TEST`]. Prints one result line over UART.
async fn sd_read_test(
    dev: &mut sdio::BlockDevice<sdio::sd::Card, Slot<'_, 0, Async>, BusyDelay, SD_BLOCK_SIZE>,
    batch: &mut [Aligned<A4, [u8; SD_BLOCK_SIZE]>],
) {
    let total = SD_READ_TEST_BYTES;
    let mut off: u64 = 0;
    let t0 = Instant::now();
    while off < total {
        let blocks = core::cmp::min(
            batch.len() as u64,
            (total - off) / SD_BLOCK_SIZE as u64,
        ) as usize;
        let block = (off / SD_BLOCK_SIZE as u64) as u32;
        if let Err(e) = dev.read(block, &mut batch[..blocks]).await {
            esp_println::println!("SD read: ERR at {} B: {}", off, err_tag(&e));
            return;
        }
        off += blocks as u64 * SD_BLOCK_SIZE as u64;
    }
    let us = t0.elapsed().as_micros().max(1) as u64;
    esp_println::println!(
        "SD read: {} MiB in {} us = {} kB/s",
        total >> 20,
        us,
        total * 1000 / us
    );
}

/// An initialized SD card presented as a byte-addressed plane.
///
/// The embedded `sdio::BlockDevice` owns the async SD bus; `batch` is the
/// DMA-safe, 4-byte-aligned staging area every transfer passes through.
pub struct SdCard<'d> {
    dev: sdio::BlockDevice<sdio::sd::Card, Slot<'d, 0, Async>, BusyDelay, SD_BLOCK_SIZE>,
    batch: &'static mut [Aligned<A4, [u8; SD_BLOCK_SIZE]>; BATCH_BLOCKS],
    capacity: u64,
    /// Byte offset of `batch[0]` in the read-ahead window (valid only while
    /// `cache_len > 0`).
    cache_off: u64,
    /// Bytes of the read-ahead window currently held in `batch`.
    cache_len: usize,
}

impl<'d: 'static> SdCard<'d> {
    /// Bring up the SDMMC host + slot 0, initialize the card and return the
    /// storage adapter.
    ///
    /// Bus wiring: `SdHostController::new` ->
    /// `slot::<0>(SlotConfig::default())` -> `with_clk/cmd/data0..3` ->
    /// `into_async()`. Card protocol is `sdio`'s `new_sd_card`.
    ///
    /// Slot 0 on the ESP32-P4 uses the **fixed IO_MUX pads**, so these GPIO
    /// numbers are mandated by the silicon (CLK=43, CMD=44, D0..D3=39..42) and
    /// cannot be remapped. The `with_*` calls therefore always compile for this
    /// slot. Before anything else the card is power-cycled in-firmware
    /// (Q1 on GPIO45 + the LDO_VO4 pull-up rail, see the block below), so it
    /// always comes up cold in 3.3 V signalling.
    pub async fn new(
        sdhost: esp_hal::peripherals::SDHOST<'d>,
        clk: esp_hal::peripherals::GPIO43<'d>,
        cmd: esp_hal::peripherals::GPIO44<'d>,
        d0: esp_hal::peripherals::GPIO39<'d>,
        d1: esp_hal::peripherals::GPIO40<'d>,
        d2: esp_hal::peripherals::GPIO41<'d>,
        d3: esp_hal::peripherals::GPIO42<'d>,
        card_power: esp_hal::peripherals::GPIO45<'d>,
    ) -> Result<Self, SdError> {
        // ── Card clean-slate power cycle at boot ───────────────────────────
        //
        // A card left in 1.8 V signalling keeps that latch across CMD0 and a
        // warm reset; only a real VDD cycle returns it to 3.3 V. Cutting Q1
        // (GPIO45 high) *alone* never does: the 51 k bus pull-ups, fed by
        // LDO_VO4 (the SD IO rail), back-feed the card through its IO clamp
        // diodes -- measured: the card still answered every command after a
        // 120 s Q1-only cut with the lines held low. Cutting the pull-up rail
        // together with Q1 removes that feed. 100 ms is enough because at
        // boot the card is still in its power-up activity (mA-level draw),
        // so its own consumption empties C7+C8 (10 uF) inside the window --
        // no bleeder resistor needed. (A card deep in standby would leak
        // only sub-uA and would need minutes; this sequence is deliberately
        // the first thing `new` does.)
        //
        // Restore order matters: LDO_VO4 first (the slot-0 pads are powered
        // from it and the pull-ups must settle the lines), then Q1. The card
        // then cold-boots: the bring-up's ACMD41 shows `bit24 = 1` (S18A=1,
        // a cold card) and CMD11 runs. See `__SD_UHS_HANDOFF.md` §2.
        {
            // High = off, Low = powered (confirmed twice: leaving the pin High
            // fails SD init, and the long-standing firmware leaves it Low and
            // works).
            const POWERED: Level = Level::Low;
            const OFF: Level = Level::High;
            let mut pwr = Output::new(card_power, POWERED, OutputConfig::default());
            let mut d = BusyDelay;

            defmt::info!("Resetting SD");
            pwr.set_level(OFF);
            esp_hal::sdmmc::set_io_power(false);
            d.delay_ms(100).await;
            // Restore: IO rail first (the slot-0 pads need it), then the card.
            esp_hal::sdmmc::set_io_power(true);
            d.delay_ms(100).await;
            pwr.set_level(POWERED);
            d.delay_ms(100).await;
            defmt::info!("Resetting DONE");
        }

        let host = HOST.init(
            SdHostController::new(sdhost, {
                if SD_UHS_PLL {
                    SdmmcConfig::default()
                        .with_clock_source(ClockSource::SdioPll)
                        .with_module_div(2)
                } else {
                    SdmmcConfig::default()
                }
            })
            .map_err(|_| SdError::HostInit)?,
        );

        let slot = host
            .slot::<0>({
                let mut cfg = SlotConfig::default();
                cfg.uhs_1v8 = SD_UHS_PLL;
                cfg
            })
            .map_err(|_| SdError::SlotInit)?
            .with_clk(clk)
            .with_cmd(cmd)
            .with_data0(d0)
            .with_data1(d1)
            .with_data2(d2)
            .with_data3(d3)
            .into_async();

        let mut dev = sdio::BlockDevice::<sdio::sd::Card, _, _, SD_BLOCK_SIZE>::new_sd_card(
            slot,
            SD_BUS_FREQ_HZ,
            BusyDelay,
        )
        .await
        .map_err(|_| SdError::CardInit)?;

        // `size()` needs `&mut self` and is async, so the geometry is read once
        // here and cached; `capacity()`/`capacity_bytes()` are `&self`.
        let capacity = block_on(dev.size()).map_err(|_| SdError::CardInit)?;

        let batch = &mut BATCH
            .init(Batch(
                [const { Aligned([0u8; SD_BLOCK_SIZE]) }; BATCH_BLOCKS],
            ))
            .0;

        if SD_READ_TEST {
            sd_read_test(&mut dev, batch).await;
        }

        Ok(Self {
            dev,
            batch,
            capacity,
            cache_off: 0,
            cache_len: 0,
        })
    }

    /// Total card capacity in bytes, as reported by
    /// `block_device_driver::BlockDevice::size()`.
    pub fn capacity_bytes(&self) -> u64 {
        self.capacity
    }

    /// Negotiated SD bus clock in Hz, as selected by `sdio` during bring-up.
    ///
    /// Thin wrapper over [`sdio::BlockDevice::freq`]; used by the `sdbench`
    /// diagnostic to report the actual clock (which `sdio` may clamp below the
    /// requested [`SD_BUS_FREQ_HZ`]).
    pub fn freq(&self) -> u32 {
        self.dev.freq()
    }

    /// Non-destructive self-test: read the first 512-byte block and return `Ok`
    /// if the transfer succeeds. Never writes user data.
    pub fn read_self_test(&mut self) -> Result<(), SdError> {
        let Self { dev, batch, .. } = self;
        block_on(dev.read(0, &mut batch[..1])).map_err(|_| SdError::Access)
    }
}

impl AsyncFlatData for SdCard<'_> {
    /// Timed wrapper: the whole call is the storage half of the shell's read
    /// overlap, so its wall clock is accumulated (see [`READ_NS`]).
    async fn read_at(&mut self, off: u64, buf: &mut [u8]) -> Result<(), StorageError> {
        let t0 = Instant::now();
        let r = self.read_at_inner(off, buf).await;
        READ_NS.fetch_add(t0.elapsed().as_micros() as u32, Ordering::Relaxed);
        r
    }

    fn capacity(&self) -> u64 {
        self.capacity
    }
}

impl SdCard<'_> {
    async fn read_at_inner(&mut self, off: u64, buf: &mut [u8]) -> Result<(), StorageError> {
        READ_CALLS.fetch_add(1, Ordering::Relaxed);
        READ_BYTES.fetch_add(buf.len() as u32, Ordering::Relaxed);
        let end = off
            .checked_add(buf.len() as u64)
            .ok_or(StorageError::OutOfBounds)?;
        if end > self.capacity {
            return Err(StorageError::OutOfBounds);
        }

        let mut done = 0usize;
        let mut fetched = false;
        while done < buf.len() {
            let pos = off + done as u64;

            // Serve from the read-ahead window when it covers `pos`.
            if pos >= self.cache_off {
                let o = (pos - self.cache_off) as usize;
                if o < self.cache_len {
                    let n = core::cmp::min(self.cache_len - o, buf.len() - done);
                    copy_batch(self.batch, o, &mut buf[done..done + n]);
                    done += n;
                    continue;
                }
            }

            // Miss: fetch a whole window of SD blocks in one command, starting
            // at the block containing `pos`. The 32-block window is what makes
            // a single 16 KiB CMD18 worthwhile even though the shell only asks
            // for 8 KiB at a time (and has to, for the write path).
            let block = pos / SD_BLOCK_SIZE as u64;
            let block_start = block * SD_BLOCK_SIZE as u64;
            let blocks_here = ((self.capacity - block_start) / SD_BLOCK_SIZE as u64) as usize;
            let k = core::cmp::min(BATCH_BLOCKS, blocks_here);
            if k == 0 {
                return Err(StorageError::OutOfBounds);
            }

            let Self {
                dev,
                batch,
                capacity: _,
                cache_off,
                cache_len,
            } = self;
            let t_sd = Instant::now();
            if let Err(e) = dev.read(block as u32, &mut batch[..k]).await {
                SD_RD_ERRORS.fetch_add(1, Ordering::Relaxed);
                esp_println::println!(
                    "SD READ ERR block={} blocks={} err={} total={}",
                    block,
                    k,
                    err_tag(&e),
                    SD_RD_ERRORS.load(Ordering::Relaxed)
                );
                return Err(StorageError::Io(embedded_io::ErrorKind::Other));
            }
            READ_SD_NS.fetch_add(t_sd.elapsed().as_micros() as u32, Ordering::Relaxed);
            CARD_CMDS.fetch_add(1, Ordering::Relaxed);
            CARD_READ_BYTES.fetch_add((k * SD_BLOCK_SIZE) as u32, Ordering::Relaxed);
            *cache_off = block_start;
            *cache_len = k * SD_BLOCK_SIZE;
            fetched = true;
        }
        // A call that never talked to the card was served by the window.
        if !fetched {
            CACHE_HITS.fetch_add(1, Ordering::Relaxed);
        }
        Ok(())
    }
}

impl AsyncWritableFlatData for SdCard<'_> {
    /// Timed wrapper: the whole call is the storage half of the shell's write
    /// overlap, so its wall clock is accumulated (see [`WRITE_NS`]).
    async fn write_at(&mut self, off: u64, buf: &[u8]) -> Result<(), StorageError> {
        let t0 = Instant::now();
        let r = self.write_at_inner(off, buf).await;
        WRITE_NS.fetch_add(t0.elapsed().as_micros() as u32, Ordering::Relaxed);
        r
    }

    /// SD writes are already durable on the card; there is no write cache.
    async fn sync(&mut self) -> Result<(), StorageError> {
        Ok(())
    }
}

impl SdCard<'_> {
    async fn write_at_inner(&mut self, off: u64, buf: &[u8]) -> Result<(), StorageError> {
        WRITE_BYTES.fetch_add(buf.len() as u32, Ordering::Relaxed);
        // A write may change bytes the read-ahead window holds.
        self.cache_len = 0;
        let end = off
            .checked_add(buf.len() as u64)
            .ok_or(StorageError::OutOfBounds)?;
        if end > self.capacity {
            return Err(StorageError::OutOfBounds);
        }

        let Self {
            dev,
            batch,
            capacity: _,
            cache_off: _,
            cache_len: _,
        } = self;
        let mut pos = off;
        let mut done = 0usize;
        while done < buf.len() {
            let block = (pos / SD_BLOCK_SIZE as u64) as u32;
            let within = (pos % SD_BLOCK_SIZE as u64) as usize;
            let remaining = buf.len() - done;

            if within == 0 && remaining >= SD_BLOCK_SIZE {
                // Full-block run: stage up to `BATCH_BLOCKS` blocks and issue
                // one multi-block write.
                let k = (remaining / SD_BLOCK_SIZE).min(BATCH_BLOCKS);
                for i in 0..k {
                    let start = done + i * SD_BLOCK_SIZE;
                    batch[i].copy_from_slice(&buf[start..start + SD_BLOCK_SIZE]);
                }
                let t_sd = Instant::now();
                if let Err(e) = dev.write(block, &batch[..k]).await {
                    SD_WR_ERRORS.fetch_add(1, Ordering::Relaxed);
                    esp_println::println!(
                        "SD WRITE ERR block={} blocks={} err={} total={}",
                        block,
                        k,
                        err_tag(&e),
                        SD_WR_ERRORS.load(Ordering::Relaxed)
                    );
                    return Err(StorageError::Io(embedded_io::ErrorKind::Other));
                }
                WRITE_SD_NS.fetch_add(t_sd.elapsed().as_micros() as u32, Ordering::Relaxed);
                let consumed = k * SD_BLOCK_SIZE;
                pos += consumed as u64;
                done += consumed;
            } else {
                // Partial head/tail: read-modify-write the containing block,
                // preserving the untouched bytes.
                let n = core::cmp::min(SD_BLOCK_SIZE - within, remaining);
                if let Err(e) = dev.read(block, &mut batch[..1]).await {
                    SD_RD_ERRORS.fetch_add(1, Ordering::Relaxed);
                    esp_println::println!(
                        "SD RMW READ ERR block={} err={} total={}",
                        block,
                        err_tag(&e),
                        SD_RD_ERRORS.load(Ordering::Relaxed)
                    );
                    return Err(StorageError::Io(embedded_io::ErrorKind::Other));
                }
                batch[0][within..within + n].copy_from_slice(&buf[done..done + n]);
                let t_sd = Instant::now();
                if let Err(e) = dev.write(block, &batch[..1]).await {
                    SD_WR_ERRORS.fetch_add(1, Ordering::Relaxed);
                    esp_println::println!(
                        "SD RMW WRITE ERR block={} err={} total={}",
                        block,
                        err_tag(&e),
                        SD_WR_ERRORS.load(Ordering::Relaxed)
                    );
                    return Err(StorageError::Io(embedded_io::ErrorKind::Other));
                }
                WRITE_SD_NS.fetch_add(t_sd.elapsed().as_micros() as u32, Ordering::Relaxed);

                pos += n as u64;
                done += n;
            }
        }
        Ok(())
    }
}

// The synchronous seams delegate to the asynchronous implementation: only the
// geometry read (`capacity()`) is used through them at runtime (the DVD-RAM
// media slot's construction), so a `block_on` around the awaited transfer keeps
// the two planes from drifting apart.
impl FlatData for SdCard<'_> {
    fn read_at(&mut self, off: u64, buf: &mut [u8]) -> Result<(), StorageError> {
        block_on(AsyncFlatData::read_at(self, off, buf))
    }

    fn capacity(&self) -> u64 {
        self.capacity
    }
}

impl WritableFlatData for SdCard<'_> {
    fn write_at(&mut self, off: u64, buf: &[u8]) -> Result<(), StorageError> {
        block_on(AsyncWritableFlatData::write_at(self, off, buf))
    }

    /// SD writes are already durable on the card; there is no write cache.
    fn sync(&mut self) -> Result<(), StorageError> {
        Ok(())
    }
}
