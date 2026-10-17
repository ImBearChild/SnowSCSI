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
use esp_hal::sdmmc::{Config as SdmmcConfig, SdHostController, Slot, SlotConfig};
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
}

/// Delta-sampler over the SD-layer counters (see [`SdSample`]).
///
/// The card-level rates are what actually crossed the SD bus; `card_rd_kbps`
/// differs from the shell's TX rate because the bus runs a 32-block window per
/// command while the storage plane hands the shell 8 KiB at a time.
pub struct SdMark {
    prev: (u32, u32, u32, u32, u32),
    at: Instant,
}

impl SdMark {
    /// Start sampling from the current counter values.
    pub fn new() -> Self {
        Self {
            prev: (
                READ_CALLS.load(Ordering::Relaxed),
                WRITE_BYTES.load(Ordering::Relaxed),
                CARD_READ_BYTES.load(Ordering::Relaxed),
                CARD_CMDS.load(Ordering::Relaxed),
                CACHE_HITS.load(Ordering::Relaxed),
            ),
            at: Instant::now(),
        }
    }

    /// Sample the counters and return the rates over the elapsed window.
    pub fn take(&mut self) -> SdSample {
        let us = self.at.elapsed().as_micros().max(1);
        self.at = Instant::now();

        let load = |a: &AtomicU32| a.load(Ordering::Relaxed);
        let calls = load(&READ_CALLS).wrapping_sub(self.prev.0);
        let wr = load(&WRITE_BYTES).wrapping_sub(self.prev.1);
        let card = load(&CARD_READ_BYTES).wrapping_sub(self.prev.2);
        let cmds = load(&CARD_CMDS).wrapping_sub(self.prev.3);
        let hits = load(&CACHE_HITS).wrapping_sub(self.prev.4);
        self.prev = (
            load(&READ_CALLS),
            load(&WRITE_BYTES),
            load(&CARD_READ_BYTES),
            load(&CARD_CMDS),
            load(&CACHE_HITS),
        );

        let kbps = |b: u32| ((b as u64 * 1_000_000 / us) / 1000) as u32;
        SdSample {
            card_rd_kbps: kbps(card),
            wr_kbps: kbps(wr),
            cache_pct: (hits as u64 * 100 / calls.max(1) as u64) as u32,
            cmd_bytes: card.checked_div(cmds).unwrap_or(0),
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
/// 40 MHz is the **cap** for the ESP32-P4 SDMMC peripheral — `sdio`'s
/// `MmcBus::supports_frequency()` for this SoC rejects anything higher, and the
/// on-board slot is wired for SDIO 3.0. `sdio` may still clamp below this value
/// (see [`SdCard::freq`]); fall back to a lower rate only after verifying 4-bit
/// signal integrity on the vendor pins if transfers corrupt.
const SD_BUS_FREQ_HZ: u32 = 40_000_000;

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
    /// slot. The sdmmc driver powers the SD IO rail through on-chip LDO4 itself;
    /// no board-side power/rail setup is required here.
    pub async fn new(
        sdhost: esp_hal::peripherals::SDHOST<'d>,
        clk: esp_hal::peripherals::GPIO43<'d>,
        cmd: esp_hal::peripherals::GPIO44<'d>,
        d0: esp_hal::peripherals::GPIO39<'d>,
        d1: esp_hal::peripherals::GPIO40<'d>,
        d2: esp_hal::peripherals::GPIO41<'d>,
        d3: esp_hal::peripherals::GPIO42<'d>,
    ) -> Result<Self, SdError> {
        let host = HOST.init(
            SdHostController::new(sdhost, SdmmcConfig::default()).map_err(|_| SdError::HostInit)?,
        );

        let slot = host
            .slot::<0>(SlotConfig::default())
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

        Ok(Self {
            dev,
            batch: &mut BATCH
                .init(Batch(
                    [const { Aligned([0u8; SD_BLOCK_SIZE]) }; BATCH_BLOCKS],
                ))
                .0,
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
    async fn read_at(&mut self, off: u64, buf: &mut [u8]) -> Result<(), StorageError> {
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
            dev.read(block as u32, &mut batch[..k])
                .await
                .map_err(|_| StorageError::Io(embedded_io::ErrorKind::Other))?;
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

    fn capacity(&self) -> u64 {
        self.capacity
    }
}

impl AsyncWritableFlatData for SdCard<'_> {
    async fn write_at(&mut self, off: u64, buf: &[u8]) -> Result<(), StorageError> {
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
                dev.write(block, &batch[..k])
                    .await
                    .map_err(|_| StorageError::Io(embedded_io::ErrorKind::Other))?;
                let consumed = k * SD_BLOCK_SIZE;
                pos += consumed as u64;
                done += consumed;
            } else {
                // Partial head/tail: read-modify-write the containing block,
                // preserving the untouched bytes.
                let n = core::cmp::min(SD_BLOCK_SIZE - within, remaining);
                dev.read(block, &mut batch[..1])
                    .await
                    .map_err(|_| StorageError::Io(embedded_io::ErrorKind::Other))?;
                batch[0][within..within + n].copy_from_slice(&buf[done..done + n]);
                dev.write(block, &batch[..1])
                    .await
                    .map_err(|_| StorageError::Io(embedded_io::ErrorKind::Other))?;

                pos += n as u64;
                done += n;
            }
        }
        Ok(())
    }

    /// SD writes are already durable on the card; there is no write cache.
    async fn sync(&mut self) -> Result<(), StorageError> {
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
