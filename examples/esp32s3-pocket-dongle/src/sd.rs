//! SD card storage.
//!
//! Bridges `esp-hal`'s SDMMC host controller + the `sdio` crate's SD memory
//! card protocol to `snowdrive_common`'s synchronous storage seams
//! ([`FlatData`] + [`WritableFlatData`]).
//!
//! # Block geometry (512-byte SD blocks vs. 2048-byte logical sectors)
//!
//! An SD memory card is addressed in **512-byte physical blocks**. The CD/MMC
//! layer above this adapter reports **2048-byte logical sectors** (the optical
//! sector size). This adapter therefore presents a
//! byte-addressed plane: callers hand it byte offsets and it converts them to
//! `block = off / SD_BLOCK_SIZE`, `within = off % SD_BLOCK_SIZE`. Runs of full
//! SD blocks are transferred in a single multi-block (CMD18/CMD25) command via
//! a static batch of up to [`BATCH_BLOCKS`] aligned blocks; unaligned head/tail
//! fragments go through the first slot of that same `Aligned<A4, [u8; 512]>`
//! batch (also required because the SDMMC IDMAC cannot DMA from PSRAM, and only
//! the batch is guaranteed to live in internal, DMA-aligned RAM).
//!
//! # Async to sync
//!
//! `sdio`'s public block surface is async (`block_device_driver::BlockDevice`)
//! and `esp-hal` only implements `sdio::MmcBus` for the `Async` slot, while the
//! storage seams are synchronous. The adapter therefore drives each transfer to
//! completion with [`embassy_futures::block_on`].

use aligned::{Aligned, A4};
use block_device_driver::BlockDevice as _;
use embassy_futures::block_on;
use embedded_hal_async::delay::DelayNs;
use esp_hal::sdmmc::{Config as SdmmcConfig, SdHostController, Slot, SlotConfig};
use esp_hal::time::Instant;
use esp_hal::Async;
use static_cell::StaticCell;

use snowdrive_common::seekable_storage::{FlatData, StorageError, WritableFlatData};

/// Native SD memory-card block size in bytes.
pub const SD_BLOCK_SIZE: usize = 512;

/// Target SD bus clock handed to `sdio` after bring-up.
///
/// Card initialization always runs at 400 kHz internally (`sdio`'s `INIT_FREQ`);
/// this value is the *operating* clock selected once the card is identified.
/// 400 kHz was far too slow for host-side UDF formatting (`mkudffs` never
/// finished); 20 MHz is the standard SD default-speed rate and gives usable
/// throughput. The host supports up to 40 MHz — raise further only after
/// verifying 4-bit signal integrity on the vendor pins (fall back to 10 MHz if
/// transfers corrupt).
const SD_BUS_FREQ_HZ: u32 = 20_000_000;

/// SD bring-up / access failures.
#[derive(Debug, Clone, Copy, PartialEq, Eq, defmt::Format)]
pub enum SdError {
    /// `SdHostController::new` rejected the configuration.
    HostInit,
    /// The slot is already taken or otherwise unusable.
    SlotInit,
    /// Card identification / initialization failed.
    CardInit,
}

/// The SDMMC host controller must outlive any slot it hands out, but the device
/// (which owns the slot) is what [`SdCard`] stores. There is no safe way to keep
/// a self-referential `host + slot` pair in one struct, so the single controller
/// is parked in a `static` for the lifetime of the program and the slot borrows
/// it. This also makes the adapter `'static`, matching `main`'s `'static`
/// peripheral singletons.
static HOST: StaticCell<SdHostController<'static>> = StaticCell::new();

/// Number of SD blocks in the aligned batch. 16 × 512 B = 8 KiB, which covers
/// the full [`snowdrive_scsi::MIN_DATA_LEN`] chunk in one SD command.
const BATCH_BLOCKS: usize = 16;

/// Batch of SD blocks for multi-block (CMD18/CMD25) transfers. 16 × 512 B
/// covers the full 8 KiB `MIN_DATA_LEN` chunk in one command. Static, because
/// the main task's stack is only 8 KiB.
static BATCH: StaticCell<[Aligned<A4, [u8; SD_BLOCK_SIZE]>; BATCH_BLOCKS]> = StaticCell::new();

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

/// An initialized SD card presented as a synchronous byte-addressed plane.
///
/// The embedded `sdio::BlockDevice` owns the async SD bus; `batch` is the
/// DMA-safe, 4-byte-aligned staging area every transfer passes through.
pub struct SdCard<'d> {
    dev: sdio::BlockDevice<sdio::sd::Card, Slot<'d, 0, Async>, BusyDelay, SD_BLOCK_SIZE>,
    batch: &'static mut [Aligned<A4, [u8; SD_BLOCK_SIZE]>; BATCH_BLOCKS],
    capacity: u64,
}

impl<'d: 'static> SdCard<'d> {
    /// Bring up the SDMMC host + slot 0, initialize the card and return the
    /// storage adapter.
    ///
    /// Bus wiring: `SdHostController::new` ->
    /// `slot::<0>(SlotConfig::default())` -> `with_clk/cmd/data0..3` ->
    /// `into_async()`. Card protocol is `sdio`'s `new_sd_card`.
    pub async fn new(
        sdhost: esp_hal::peripherals::SDHOST<'d>,
        clk: esp_hal::peripherals::GPIO17<'d>,
        cmd: esp_hal::peripherals::GPIO18<'d>,
        d0: esp_hal::peripherals::GPIO16<'d>,
        d1: esp_hal::peripherals::GPIO15<'d>,
        d2: esp_hal::peripherals::GPIO48<'d>,
        d3: esp_hal::peripherals::GPIO47<'d>,
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
            batch: BATCH.init([const { Aligned([0u8; SD_BLOCK_SIZE]) }; BATCH_BLOCKS]),
            capacity,
        })
    }

    /// Total card capacity in bytes, as reported by
    /// `block_device_driver::BlockDevice::size()`.
    pub fn capacity_bytes(&self) -> u64 {
        self.capacity
    }
}

impl FlatData for SdCard<'_> {
    fn read_at(&mut self, off: u64, buf: &mut [u8]) -> Result<(), StorageError> {
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
        } = self;
        let mut pos = off;
        let mut done = 0usize;
        while done < buf.len() {
            let block = (pos / SD_BLOCK_SIZE as u64) as u32;
            let within = (pos % SD_BLOCK_SIZE as u64) as usize;
            let remaining = buf.len() - done;

            if within == 0 && remaining >= SD_BLOCK_SIZE {
                // Full-block run: one multi-block read for up to `BATCH_BLOCKS`.
                let k = (remaining / SD_BLOCK_SIZE).min(BATCH_BLOCKS);
                block_on(dev.read(block, &mut batch[..k]))
                    .map_err(|_| StorageError::Io(embedded_io::ErrorKind::Other))?;
                for i in 0..k {
                    let start = done + i * SD_BLOCK_SIZE;
                    buf[start..start + SD_BLOCK_SIZE].copy_from_slice(&batch[i][..]);
                }
                let consumed = k * SD_BLOCK_SIZE;
                pos += consumed as u64;
                done += consumed;
            } else {
                // Partial head/tail: read the containing block and copy the
                // wanted sub-range out of the batch's first slot.
                let n = core::cmp::min(SD_BLOCK_SIZE - within, remaining);
                block_on(dev.read(block, &mut batch[..1]))
                    .map_err(|_| StorageError::Io(embedded_io::ErrorKind::Other))?;
                buf[done..done + n].copy_from_slice(&batch[0][within..within + n]);

                pos += n as u64;
                done += n;
            }
        }
        Ok(())
    }

    fn capacity(&self) -> u64 {
        self.capacity
    }
}

impl WritableFlatData for SdCard<'_> {
    fn write_at(&mut self, off: u64, buf: &[u8]) -> Result<(), StorageError> {
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
                block_on(dev.write(block, &batch[..k]))
                    .map_err(|_| StorageError::Io(embedded_io::ErrorKind::Other))?;
                let consumed = k * SD_BLOCK_SIZE;
                pos += consumed as u64;
                done += consumed;
            } else {
                // Partial head/tail: read-modify-write the containing block,
                // preserving the untouched bytes.
                let n = core::cmp::min(SD_BLOCK_SIZE - within, remaining);
                block_on(dev.read(block, &mut batch[..1]))
                    .map_err(|_| StorageError::Io(embedded_io::ErrorKind::Other))?;
                batch[0][within..within + n].copy_from_slice(&buf[done..done + n]);
                block_on(dev.write(block, &batch[..1]))
                    .map_err(|_| StorageError::Io(embedded_io::ErrorKind::Other))?;

                pos += n as u64;
                done += n;
            }
        }
        Ok(())
    }

    /// SD writes are already synchronous on the card; there is no write cache.
    fn sync(&mut self) -> Result<(), StorageError> {
        Ok(())
    }
}
