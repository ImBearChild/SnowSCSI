//! ESP32-P4-WIFI6-Touch-LCD-3.5 firmware.
//!
//! Presents the on-board microSD card as one whole raw block device to a USB
//! host, as a UDF-RW (DVD-RAM) optical device driven by `snowscsi`.
//!
//! This is the ESP32-P4 port of `examples/esp32s3-pocket-dongle`. The two
//! platform differences that matter:
//!
//! * **USB 2.0 High-Speed** OTG with an integrated UTMI PHY (`Usb::new_hs`,
//!   no D+/D− pins) instead of the S3's Full-Speed PHY — this is the whole
//!   point of moving to the P4 (~10× the bulk throughput); the bulk endpoints
//!   therefore use 512-byte maximum packets.
//! * **SDMMC slot 0** on the board's fixed IO_MUX pins (CLK=43, CMD=44,
//!   D0..D3=39..42), run at up to 40 MHz, with the SD IO rail powered by the
//!   on-chip LDO that the esp-hal sdmmc driver brings up itself.
//!
//! No PHY mux and no console/mode toggle: on the P4 the HS OTG is a dedicated
//! controller, and the debug console is a separate USB-to-UART bridge
//! (CH343P) on UART0, so logging and the gadget coexist. The on-board ST7796
//! 3.5" panel shows the same live status (USB link + BOT shell diagnostics,
//! RX/TX, uptime), so the device is debuggable without the UART cable.
//!
//! Build/flash: `cargo run --release` (RISC-V target, the official Rust
//! toolchain — no `esp`/Xtensa toolchain is involved on the P4).
//!
//! ⚠ Requires ESP32-P4 silicon **revision v3.0+**: esp-hal 1.2.2 enforces a
//! minimum chip revision and aborts at `init` on older parts (e.g. v1.3).

#![no_std]
#![no_main]
#![deny(
    clippy::mem_forget,
    reason = "mem::forget is generally not safe to do with esp_hal types, especially those holding buffers for the duration of a data transfer."
)]

use core::sync::atomic::AtomicBool;

use esp_hal::clock::CpuClock;
use esp_hal::timer::timg::TimerGroup;
use esp_hal::usb::otg::{
    embassy_usb_device::{Config as OtgConfig, Driver},
    Usb,
};

use embassy_executor::Spawner;
use embassy_time::{Duration, Instant, Timer};
use embassy_usb::driver::{EndpointIn, EndpointOut};
use static_cell::StaticCell;

use defmt::{info, warn};

use snowscsi::common::async_store::{AsyncStorePlane, Either};
use snowscsi::common::seekable_storage::ZeroBackend;
use snowscsi::scsi::device::ScsiDevice;
use snowscsi::scsi::AsyncLuns;
use snowscsi::usb::{BotSession, EmbassyBot, ShortfallPolicy};

// Panic handler (`esp-backtrace` with `panic-handler`).
use esp_backtrace as _;
// defmt global logger (`esp-println` with `defmt-espflash`); the `as _` import
// keeps the logger linked in even though we never name the crate.
use esp_println as _;

mod display;
mod drive;
mod msc;
mod sd;

// Creates the app descriptor required by the ESP-IDF bootloader.
// See <https://docs.espressif.com/projects/esp-idf/en/stable/esp32/api-reference/system/app_image_format.html#application-description>
esp_bootloader_esp_idf::esp_app_desc!();

/// 8 KiB SCSI command/data buffer the BOT session works on.
///
/// The `#[esp_rtos::main]` task runs on a **small** stack, so the
/// [`drive::WORK_LEN`] (8192)-byte buffer must not be a stack local.  Parking
/// it in a `StaticCell` places it in `.bss` and lets `main` borrow a
/// `&'static mut [u8]` for the lifetime of the gadget loop.
static WORK: StaticCell<[u8; drive::WORK_LEN]> = StaticCell::new();

/// 8 KiB overlap buffer, same length as [`WORK`].
///
/// The shell pre-receives the next Data-Out chunk (or speculatively pre-reads
/// the next Data-In chunk) into `scratch` while the current chunk is in flight,
/// then swaps the two. Kept off the task stack.
static SCRATCH: StaticCell<[u8; drive::WORK_LEN]> = StaticCell::new();

/// Shutdown flag handed to the BOT serve loop.
///
/// This firmware never tears the gadget down, so the flag is never set; it
/// exists because the shell requires an explicit stop signal alongside the
/// future.
static STOP: AtomicBool = AtomicBool::new(false);

/// Run the whole DVD-RAM gadget concurrently: USB stack, BOT loop, status LCD.
///
/// Never returns. Both `UsbDevice::run` and [`msc::run`] return `!`, so the
/// `join3` below can only ever be *cancelled*, never completed — and nothing
/// here cancels it, so the future runs for the life of the program.
///
/// Borrows are disjoint by construction: the USB stack owns `device`, the BOT
/// loop owns the endpoints/session/buffers/LUNs, and the third arm owns the
/// LCD and only reads the byte counters.
#[allow(
    clippy::large_stack_frames,
    clippy::too_many_arguments,
    reason = "the joined USB-stack + BOT-loop future is intentionally one frame and one call"
)]
async fn gadget<'d, D, O, I, P>(
    device: &mut embassy_usb::UsbDevice<'d, D>,
    bot: &mut EmbassyBot<O, I>,
    session: &mut BotSession,
    work: &mut [u8],
    scratch: &mut [u8],
    luns: &mut AsyncLuns<'_, P>,
    stop: &AtomicBool,
    display: &mut Option<display::Display<'_>>,
    sd_bytes: Option<u64>,
    boot: Instant,
) -> !
where
    D: embassy_usb::driver::Driver<'d>,
    O: EndpointOut,
    I: EndpointIn,
    P: AsyncStorePlane,
{
    esp_println::println!("stage: gadget enter");
    embassy_futures::join::join3(
        device.run(),
        msc::run(bot, session, work, scratch, luns, stop),
        async {
            // Live status on the panel (and the same numbers over the CH343P
            // USB-UART console), delta-sampled once per 500 ms window.
            //
            // The uptime readout only advances because *this* loop runs, so a
            // frozen number is the "MCU hung or panicked" signal; RX/TX appear
            // twice — the **cumulative** bulk byte counts (the diagnostic line,
            // since the first transaction is only tens of bytes and a per-window
            // rate would round to zero) and the per-window KB/s rate.
            //
            // Align the sampler to the current counters so the first window
            // only counts bytes moved after the sampler was created.
            let mut mark = msc::SpeedMark::new();
            let mut sd_mark = sd::SdMark::new();
            // Refresh cadence, in 500 ms ticks. The console shares this
            // executor with the BOT loop, so every character printed is taken
            // straight out of throughput: a ~190-char UART line is ~17 ms at
            // 115200, and the panel band is a 71 KiB SPI write (~14 ms). Both
            // used to run every tick, costing ~71 ms of every 570 ms window
            // (~12%). The panel is the product surface and refreshes every
            // second; the two diagnostic lines are a bring-up aid and print
            // every two.
            const PANEL_EVERY: u32 = 2;
            const LOG_EVERY: u32 = 4;
            let mut tick: u32 = 0;
            loop {
                Timer::after(Duration::from_millis(500)).await;
                tick = tick.wrapping_add(1);
                let sp = mark.take();
                let sd = sd_mark.take();
                let (rx_kbps, tx_kbps) = (sp.rx_kbps, sp.tx_kbps);
                let up = msc::usb_connected();
                if tick % LOG_EVERY == 0 {
                    info!(
                        "usb {} rx={}kB/s tx={}kB/s",
                        if up { "up" } else { "down" },
                        rx_kbps,
                        tx_kbps
                    );
                    esp_println::println!(
                        "DIAG sd_rb={} sd_card={}B/s cache={}% cmd={}B sdr={}kB/s sdw={}kB/s tx_b={}",
                        crate::sd::READ_BYTES.load(core::sync::atomic::Ordering::Relaxed),
                        sd.card_rd_kbps * 1000,
                        sd.cache_pct,
                        sd.cmd_bytes,
                        sd.card_rd_kbps,
                        sd.wr_kbps,
                        msc::tx_bytes(),
                    );
                    // Busy shares: if the shell's `join(send, pread)` is
                    // genuinely concurrent, the pipe's busy time plus the
                    // plane's must exceed the window; if they sum to it
                    // instead, the join is serial.
                    let wall = sd.wall_us.max(1) as u64;
                    let pct = |us: u32| (us as u64 * 100 / wall) as u32;
                    esp_println::println!(
                        "BUSY wall={}us rx={}us/{}% tx={}us/{}% rd={}us/{}% sd={}us/{}% wr={}us/{}% sw={}us/{}%",
                        sd.wall_us,
                        sp.rx_busy_us,
                        pct(sp.rx_busy_us),
                        sp.tx_busy_us,
                        pct(sp.tx_busy_us),
                        sd.rd_busy_us,
                        pct(sd.rd_busy_us),
                        sd.sd_busy_us,
                        pct(sd.sd_busy_us),
                        sd.wr_busy_us,
                        pct(sd.wr_busy_us),
                        sd.sw_busy_us,
                        pct(sd.sw_busy_us),
                    );
                }
                if tick % PANEL_EVERY != 0 {
                    continue;
                }
                if let Some(display) = display.as_mut() {
                    let (in_calls, in_disabled, in_overflow) = msc::tx_diag();
                    let (rx_cbw, rx_other) = msc::rx_diag();
                    display.show(
                        sd_bytes,
                        up,
                        uptime_s(boot),
                        Some((msc::rx_bytes(), msc::tx_bytes())),
                        Some((rx_kbps, tx_kbps)),
                        (sd.card_rd_kbps, sd.wr_kbps, sd.cache_pct, sd.cmd_bytes),
                        (
                            msc::restarts(),
                            msc::bus_resets(),
                            in_calls,
                            in_disabled,
                            in_overflow,
                            rx_cbw,
                            rx_other,
                        ),
                    );
                }
            }
        },
    )
    .await;
    unreachable!()
}

/// Seconds since `boot`, truncated to u32 (wraps after ~136 years of uptime).
fn uptime_s(boot: Instant) -> u32 {
    boot.elapsed().as_secs() as u32
}

#[allow(
    clippy::large_stack_frames,
    reason = "all big buffers live in statics; this frame is small"
)]
#[esp_rtos::main]
async fn main(_spawner: Spawner) -> ! {
    // ESP32-P4: `max()` is 400 MHz (the default preset is only 100 MHz).
    let peripherals = esp_hal::init(esp_hal::Config::default().with_cpu_clock(CpuClock::max()));

    let timg0 = TimerGroup::new(peripherals.TIMG0);
    esp_rtos::start(timg0.timer0, peripherals.FROM_CPU_INTR0);

    // Origin of the on-panel uptime clock (`UPT:` line). Captured right after
    // `esp_rtos::start` so `embassy_time` ticks are already being driven.
    let boot = Instant::now();

    info!("esp32p4-touch-lcd-35: booting (DVD-RAM/USB HS)");

    // ── Status LCD (ST7796 over SPI2) ────────────────────────────────────
    //
    // The LCD is the only on-device feedback when the CH343P UART console is
    // not attached. The SPI interface borrows `lcd_buf`, so it must be
    // declared (and outlive) the `Display`.
    let mut lcd_buf = [0u8; 512];
    let mut display = match display::Display::new(
        peripherals.SPI2,
        peripherals.GPIO21, // SCLK
        peripherals.GPIO20, // MOSI
        peripherals.GPIO22, // MISO (SDO) — used for the liveness probe
        peripherals.GPIO23, // CS
        peripherals.GPIO26, // DC
        peripherals.GPIO27, // RST
        peripherals.GPIO28, // backlight
        &mut lcd_buf,
    ) {
        Ok(display) => {
            info!("LCD: ST7796 ready (320x480, SPI2)");
            Some(display)
        }
        Err(e) => {
            warn!("LCD init failed: {}", e);
            None
        }
    };
    // Plain-ASCII line (not defmt): readable from any serial terminal without
    // espflash's defmt decoder, so a panel bring-up failure is diagnosable
    // even when the host tooling is unavailable.
    esp_println::println!("LCD st7796 ready={}", display.is_some());

    // Boot progress markers: on OTG power the CH343P is dead, so the LCD is
    // the only console. Each stage paints a marker; the last one visible
    // localises a cold-boot stall.
    if let Some(display) = display.as_mut() {
        display.boot_stage("BOOT 1/5 LCD");
    }
    if let Some(display) = display.as_mut() {
        display.boot_stage("BOOT 2/5 SD");
    }

    // ── SD card over SDMMC slot 0 (fixed IO_MUX pins, up to 40 MHz) ──────
    let mut card = match sd::SdCard::new(
        peripherals.SDHOST,
        peripherals.GPIO43, // SD CLK
        peripherals.GPIO44, // SD CMD
        peripherals.GPIO39, // SD D0
        peripherals.GPIO40, // SD D1
        peripherals.GPIO41, // SD D2
        peripherals.GPIO42, // SD D3
        peripherals.GPIO45, // TF slot VDD switch (transistor)
    )
    .await
    {
        Ok(card) => card,
        Err(e) => {
            info!("SD init failed: {}", e);
            if let Some(display) = display.as_mut() {
                display.show(
                    None,
                    false,
                    uptime_s(boot),
                    None,
                    None,
                    (0, 0, 0, 0),
                    (0, 0, 0, 0, 0, 0, 0),
                );
            }
            loop {
                Timer::after(Duration::from_secs(5)).await;
            }
        }
    };
    info!("SD card ready: {} bytes", card.capacity_bytes());
    let sd_bytes = Some(card.capacity_bytes());
    if let Some(display) = display.as_mut() {
        display.boot_stage("BOOT 3/5 SD ok");
    }

    // SD bring-up result (ASCII so it shows without a defmt decoder).
    esp_println::println!("SD clock: {} Hz", card.freq());

    esp_println::println!("stage: sd ok");

    // ── Build the DVD-RAM drive over the SD card (non-destructive) ───────
    //
    // The drive is backend-free: it caches geometry from the card and
    // addresses it only through the LUN's asynchronous store plane, so this
    // borrow of `card` ends here. The card content is used as-is; the media is
    // never reformatted (the host formats the blank DVD-RAM).
    esp_println::println!("stage: drive");
    if let Some(display) = display.as_mut() {
        display.boot_stage("BOOT 4/5 DRV");
    }

    // ── Measurement switch ───────────────────────────────────────────────
    //
    // `true`: back the LUN with an all-zero plane (reads return zeros, writes
    // are discarded) so the USB/BOT path is measured with no SD I/O at all.
    // `false`: the real SD card.
    const ZERO_BACKEND: bool = false;
    esp_println::println!("plane: {}", if ZERO_BACKEND { "zero" } else { "sd" });

    let (mut drive, plane) = if ZERO_BACKEND {
        let mut zero = ZeroBackend::new(64 * 1024 * 1024 * 1024);
        let drive = drive::build(&mut zero);
        (drive, Either::A(zero))
    } else {
        let drive = drive::build(&mut card);
        (drive, Either::B(card))
    };

    // ── LUN view ─────────────────────────────────────────────────────────
    //
    // One LUN: the DVD-RAM drive as the device and the chosen plane as its
    // asynchronous store plane. Both live for the rest of `main`.
    let mut devs: [&mut dyn ScsiDevice; 1] = [&mut drive];
    let mut planes = [Some(plane)];
    let mut luns = AsyncLuns::new(&mut devs, &mut planes);

    // ── USB 2.0 High-Speed OTG device (internal UTMI PHY, no pins) ───────
    let usb = Usb::new_hs(peripherals.USB_HS);
    // The OTG driver carves this buffer per OUT endpoint by max packet size
    // (control EP0 = 64, bulk OUT = 512 at HS ⇒ 576 needed), so 1024 is ample.
    let mut ep_out_buffer = [0u8; 1024];
    // Multi-packet bulk IN (see the vendored driver in `vendor/`): arm the bulk
    // IN endpoint for a whole 2560-byte transfer (5 × 512 B packets) so the core
    // stops NAKing the host between packets. The P4's OTG HS FIFO RAM is 896
    // words; this is the largest transfer that fits (see `bulk_fifo_words`).
    let mut otg_config = OtgConfig::default();
    otg_config.bulk_in_transfer_bytes = 2560;
    let driver = Driver::new(usb, &mut ep_out_buffer, otg_config);

    let mut handler = msc::MscHandler;
    let mut usb_config = embassy_usb::Config::new(0x2E8A, 0x000A);
    usb_config.manufacturer = Some("SnowSCSI");
    usb_config.product = Some("SnowSCSI UDF-RW");
    usb_config.max_packet_size_0 = 64;
    // USB 2.0 (bcdUSB 0x0200), not embassy's 0x0210 default: a `>= 0x0201`
    // claim makes Windows 8+ fetch and validate the BOS descriptor, and the
    // Linux FunctionFS gadget this repo also ships advertises 0x0200. A
    // High-Speed device is still USB 2.0, so 0x0200 is correct here too.
    usb_config.bcd_usb = embassy_usb::UsbVersion::Two;
    // Plain single-function Mass Storage device: no Interface Association
    // Descriptor (the 0xEF/02/01 default is for composite/IAD devices).
    // Device class 0 lets the host bind usb-storage by the interface class
    // (0x08).
    usb_config.composite_with_iads = false;
    usb_config.device_class = 0x00;
    usb_config.device_sub_class = 0x00;
    usb_config.device_protocol = 0x00;

    let mut config_desc = [0u8; 256];
    let mut bos_desc = [0u8; 256];
    let mut msos_desc = [0u8; 64];
    let mut control_buf = [0u8; 64];

    let mut builder = embassy_usb::Builder::new(
        driver,
        usb_config,
        &mut config_desc,
        &mut bos_desc,
        &mut msos_desc,
        &mut control_buf,
    );
    builder.handler(&mut handler);

    let (ep_out, ep_in) = {
        let mut func = builder.function(
            snowscsi::usb::MSC_CLASS,
            snowscsi::usb::MSC_SUBCLASS,
            snowscsi::usb::MSC_PROTOCOL,
        );
        let mut iface = func.interface();
        let mut alt = iface.alt_setting(
            snowscsi::usb::MSC_CLASS,
            snowscsi::usb::MSC_SUBCLASS,
            snowscsi::usb::MSC_PROTOCOL,
            None,
        );
        // High-Speed bulk endpoints use 512-byte max packets.
        let ep_out = alt.endpoint_bulk_out(None, 512);
        let ep_in = alt.endpoint_bulk_in(None, 512);
        (ep_out, ep_in)
    };
    let mut device = builder.build();

    // ── Persistent per-program state ─────────────────────────────────────
    //
    // The 8 KiB work/scratch statics are initialised exactly once (a second
    // `StaticCell::init` panics); the same buffers are reborrowed into the BOT
    // loop for the life of the program. `peripherals` stays alive so `USB_HS`
    // could be reborrowed; the SD singleton was moved out once.
    let work: &'static mut [u8] = WORK.init([0u8; drive::WORK_LEN]);
    let scratch: &'static mut [u8] = SCRATCH.init([0u8; drive::WORK_LEN]);

    // One LUN; High-Speed bulk MPS (512) drives the Data-In short-packet
    // decision. The shortfall policy is pinned explicitly so a future change to
    // the default cannot move the gadget's wire shape.
    //
    // `Pad` rather than `ShortNoStall`: embassy-usb keeps its `Bus` private, so
    // a class driver cannot halt an endpoint and the conformant `Short` (short
    // packet + Bulk-In STALL) is rejected by the serve loop's startup check.
    // `ShortNoStall` leaves the data phase short with no STALL, which
    // Linux/EDK2/FreeBSD/U-Boot tolerate but Windows' usbstor may reject. `Pad`
    // is fully conformant without touching the control plane: the structural
    // shortfalls Windows probes with are padded to the declared length.
    let mut session = BotSession::with_luns(1)
        .with_bulk_mps(512)
        .with_shortfall(ShortfallPolicy::Pad);

    // Bundle the endpoints and the shared reset flag. The serve loop resets
    // the session for each freshly enumerated host.
    let mut bot = msc::bot(ep_out, ep_in);

    if let Some(display) = display.as_mut() {
        display.boot_stage("BOOT 5/5 USB");
    }
    esp_println::println!("stage: run");
    info!("USB HS gadget running");

    gadget(
        &mut device,
        &mut bot,
        &mut session,
        &mut *work,
        &mut *scratch,
        &mut luns,
        &STOP,
        &mut display,
        sd_bytes,
        boot,
    )
    .await
}
