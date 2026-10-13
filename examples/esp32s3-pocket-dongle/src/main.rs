//! ESP32-S3 Pocket-Dongle firmware — M4 integration.
//!
//! Presents the on-board SD card as one whole raw block device to a USB host,
//! as a UDF-RW (DVD-RAM) optical device driven by `snowscsi`.
//!
//! Boots straight into DVDRAM: the USB-OTG gadget runs the Mass Storage
//! Bulk-Only Transport class ([`msc`]) over the internal Full-Speed PHY. The
//! SD card is built once into a persistent [`drive`] (the single LUN).
//!
//! Pressing BOOT toggles between the two owners of the single internal USB
//! PHY: the DVDRAM gadget (USB-OTG) and the USB-Serial-JTAG debug console (the
//! ROM download / `espflash` interface). Each toggle tears the gadget down
//! (dropping the `UsbDevice` disables the OTG core), re-muxes the PHY with
//! [`usb_mode`], and rebuilds. defmt is only emitted while the PHY is on
//! USB-Serial-JTAG (its FIFO cannot be drained on OTG); the LCD is the only
//! on-device feedback in DVDRAM mode.
//!
//! This crate is *detached* from the repository workspace (its own empty
//! `[workspace]` table) and is built with the `esp` (Xtensa) toolchain:
//!
//! ```text
//! cargo +esp build --release
//! ```

#![no_std]
#![no_main]
#![deny(
    clippy::mem_forget,
    reason = "mem::forget is generally not safe to do with esp_hal types, especially those holding buffers for the duration of a data transfer."
)]

use esp_hal::clock::CpuClock;
use esp_hal::timer::timg::TimerGroup;
use esp_hal::usb::otg::{
    embassy_usb_device::{Config as OtgConfig, Driver},
    Usb,
};

use embassy_executor::Spawner;
use embassy_futures::select::{select, Either};
use embassy_time::{Duration, Instant, Timer};
use static_cell::StaticCell;

use defmt::info;

use snowscsi::scsi::device::ScsiDevice;

// Panic handler (`esp-backtrace` with `panic-handler`).
use esp_backtrace as _;
// defmt global logger (`esp-println` with `defmt-espflash`); the `as _` import
// keeps the logger linked in even though we never name the crate.
use esp_println as _;

mod button;
mod display;
mod drive;
mod msc;
mod sd;
mod usb_mode;

// Creates the app descriptor required by the ESP-IDF bootloader.
// See <https://docs.espressif.com/projects/esp-idf/en/stable/esp32/api-reference/system/app_image_format.html#application-description>
esp_bootloader_esp_idf::esp_app_desc!();

/// 8 KiB SCSI command/data scratch buffer shared by every BOT transaction.
///
/// The `#[esp_rtos::main]` task runs on a **small** stack, so the
/// [`drive::WORK_LEN`] (8192)-byte buffer must not be a stack local.  Parking
/// it in a `StaticCell` places it in `.bss` and lets `main` borrow a
/// `&'static mut [u8]` for the lifetime of the gadget loop.
static WORK: StaticCell<[u8; drive::WORK_LEN]> = StaticCell::new();

/// 8 KiB bulk-OUT receive scratch (CBW fragments and Data-Out chunks).
///
/// Separate from [`WORK`] because the BOT session borrows the SCSI data region
/// and the receive scratch at the same time. Also kept off the task stack.
static RECV: StaticCell<[u8; drive::WORK_LEN]> = StaticCell::new();

/// Run the whole DVDRAM gadget concurrently: USB stack, BOT loop, LCD refresh.
///
/// Never returns. Both `UsbDevice::run` and [`msc::run`] return `!`, so the
/// `join3` below can only ever be *cancelled*, never completed. The caller
/// races this future against [`button::BootButton::wait_press`]; when BOOT
/// wins, dropping this future stops the gadget, after which the caller drops
/// the device (disabling the OTG core) and re-muxes the PHY.
///
/// Borrows are disjoint by construction: the USB stack owns `device`, the BOT
/// loop owns the endpoints/session/buffers/LUNs, and the refresh owns the LCD.
#[allow(
    clippy::large_stack_frames,
    clippy::too_many_arguments,
    reason = "the joined USB-stack + BOT-loop future is intentionally one frame and one call"
)]
async fn gadget<'d, D, S>(
    device: &mut embassy_usb::UsbDevice<'d, D>,
    ep_out: &mut D::EndpointOut,
    ep_in: &mut D::EndpointIn,
    session: &mut snowscsi::usb::BotSession,
    work: &mut [u8],
    recv: &mut [u8],
    devs: &mut [S],
    display: &mut Option<display::Display<'_>>,
    sd_bytes: Option<u64>,
    boot: Instant,
) -> !
where
    D: embassy_usb::driver::Driver<'d>,
    S: ScsiDevice,
{
    embassy_futures::join::join3(
        device.run(),
        msc::run(ep_out, ep_in, session, work, recv, devs),
        async {
            // Uptime: seconds since boot, redisplayed every refresh. The
            // readout only advances because *this* loop runs, so a frozen
            // number is exactly the "MCU hung or panicked" signal the old HB
            // tick counter gave — but the value itself is real wall-clock
            // time. RX/TX are the bulk byte counters of the BOT loop,
            // delta-sampled once per refresh — a decimal KB/s readout over
            // the *last* 500 ms window.
            //
            // Align the sampler to the current cumulative counters — each
            // gadget rebuild starts a fresh window, counting only new bytes.
            let mut mark = msc::SpeedMark::new(msc::rx_bytes(), msc::tx_bytes());
            loop {
                Timer::after(Duration::from_millis(500)).await;
                if let Some(display) = display.as_mut() {
                    let (rx, tx) = mark.take(msc::rx_bytes(), msc::tx_bytes());
                    display.show(
                        usb_mode::Mode::DvdRam,
                        sd_bytes,
                        msc::usb_connected(),
                        uptime_s(boot),
                        Some((rx, tx)),
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
    reason = "it's not unusual to allocate larger buffers etc. in main"
)]
#[esp_rtos::main]
async fn main(spawner: Spawner) -> ! {
    // 160 MHz instead of max(240): every esp-hal S3 CpuClock preset keeps the
    // 480 MHz PLL alive, so USB-OTG (48M), the SDMMC host and the fixed
    // 80 MHz APB are all unaffected; CPU dynamic power (the dominant heat
    // source during sustained BOT writes) drops with the core clock. Embassy
    // does not re-scale later, so this is the only clock decision.
    let mut peripherals =
        esp_hal::init(esp_hal::Config::default().with_cpu_clock(CpuClock::_160MHz));

    let timg0 = TimerGroup::new(peripherals.TIMG0);
    esp_rtos::start(timg0.timer0, peripherals.FROM_CPU_INTR0);

    // Origin of the on-panel uptime clock (`UPT:` line). Captured right after
    // `esp_rtos::start` so `embassy_time` ticks are already being driven; the
    // clock is invalidated anyway the moment the refresh loop dies.
    let boot = Instant::now();

    // Nothing is spawned: the USB device and BOT loop are joined directly in
    // `main` so their non-`'static` borrows (session, drive) stay valid.
    let _ = spawner;

    info!("esp32s3-pocket-dongle: M4 booting (DVDRAM/USB-OTG)");

    // The LCD's SPI interface borrows this staging buffer, so it must be
    // declared (and outlive) the `Display` below.
    let mut lcd_buf = [0u8; 512];
    let mut display = display::Display::new(
        peripherals.SPI2,
        peripherals.GPIO10,
        peripherals.GPIO11,
        peripherals.GPIO12,
        peripherals.GPIO13,
        peripherals.GPIO14,
        &mut lcd_buf,
    )
    .ok();

    // Paint a boot screen as soon as the panel is up (before the slower SD
    // bring-up).
    if let Some(display) = display.as_mut() {
        display.show(usb_mode::Mode::DvdRam, None, false, uptime_s(boot), None);
    }

    // SDMMC host + slot 0 on the board's 1-bit/4-bit SD wiring. Bring-up can be
    // slow (400 kHz init clock), hence the boot screen above.
    let mut sd = sd::SdCard::new(
        peripherals.SDHOST,
        peripherals.GPIO17,
        peripherals.GPIO18,
        peripherals.GPIO16,
        peripherals.GPIO15,
        peripherals.GPIO48,
        peripherals.GPIO47,
    )
    .await
    .ok();

    let sd_bytes = sd.as_ref().map(|s| s.capacity_bytes());
    match sd.as_ref() {
        Some(card) => info!("SD card ready: {} bytes", card.capacity_bytes()),
        None => info!("SD card init failed"),
    }

    // The drive (single LUN) must own the card for the whole program.
    let Some(mut card) = sd.take() else {
        info!("M4: no SD card; cannot start the USB gadget");
        if let Some(display) = display.as_mut() {
            display.show(usb_mode::Mode::DvdRam, None, false, uptime_s(boot), None);
        }
        loop {
            Timer::after(Duration::from_secs(1)).await;
        }
    };

    // Build the DVD-RAM drive over the SD card (non-destructive — the existing
    // card content is used as-is). The drive borrows the card for the rest of
    // `main`.
    let mut drive = drive::build(&mut card);

    // ── Persistent per-program state ─────────────────────────────────────
    //
    // The 8 KiB scratch statics are initialised exactly once (a second
    // `StaticCell::init` panics); the same buffers are reborrowed into every
    // gadget build. The BOT session is created once and reset before each
    // (re)start. `peripherals` itself stays alive so USB_FS/GPIO19/GPIO20 can
    // be reborrowed per build; the SPI/SD/BOOT singletons were moved out once.
    //
    // NOTE: `embassy-usb-synopsys-otg` keeps its endpoint-allocator slots in a
    // `'static` `StateStorage` (`State::alloc_slot_write`) that `Bus::drop`
    // never clears, so every rebuild consumes two of the six non-EP0 slots.
    // The BOOT<->DVDRAM toggle is therefore bounded (roughly five re-entries)
    // until allocation would panic; making it unbounded needs library support
    // (fixed endpoints, or retaining the device across the Debug excursion).
    let work: &'static mut [u8] = WORK.init([0u8; drive::WORK_LEN]);
    let recv: &'static mut [u8] = RECV.init([0u8; drive::WORK_LEN]);
    // One LUN, Full-Speed bulk MPS (64) for the Data-In short-packet decision.
    // The shortfall policy is pinned explicitly to its validated behaviour so a
    // future change to the default cannot move the dongle's wire shape.
    let mut session = snowscsi::usb::BotSession::with_luns(1)
        .with_bulk_mps(64)
        .with_shortfall(snowscsi::usb::ShortfallPolicy::ShortNoStall);
    let mut button = button::BootButton::new(peripherals.GPIO0);

    // ── Runtime mode toggle ──────────────────────────────────────────────
    //
    // Boot default is DVDRAM (the product function). BOOT tears the gadget
    // down and yields the shared PHY to USB-Serial-JTAG for a debug console;
    // BOOT again rebuilds the DVDRAM gadget.
    let mut mode = usb_mode::Mode::DvdRam;

    loop {
        match mode {
            usb_mode::Mode::DvdRam => {
                // Route the shared PHY to OTG before building/polling the
                // gadget. esp-hal's `Bus::init` re-applies this on the first
                // poll, but doing it explicitly is what brings the PHY back
                // after a Debug excursion.
                usb_mode::phy_to_otg();

                // ── USB device: one Mass Storage interface, BOT ──────────
                //
                // Full-Speed internal PHY => 64-byte max packet size on every
                // endpoint. All gadget buffers are locals of this arm so they
                // are dropped with the device, before the next PHY switch.
                let usb = Usb::new_fs(
                    peripherals.USB_FS.reborrow(),
                    peripherals.GPIO20.reborrow(),
                    peripherals.GPIO19.reborrow(),
                );
                let mut ep_out_buffer = [0u8; 1024];
                let mut config_desc = [0u8; 256];
                let mut bos_desc = [0u8; 256];
                let mut msos_desc = [0u8; 64];
                let mut control_buf = [0u8; 64];

                let mut handler = msc::MscHandler;
                let mut usb_config = embassy_usb::Config::new(0x2E8A, 0x000A);
                usb_config.manufacturer = Some("SnowSCSI");
                usb_config.product = Some("SnowSCSI UDF-RW");
                usb_config.max_packet_size_0 = 64;
                // Plain single-function Mass Storage device: no Interface
                // Association Descriptor (the 0xEF/02/01 default is for
                // composite/IAD devices). Device class 0 lets the host bind
                // usb-storage by the interface class (0x08).
                usb_config.composite_with_iads = false;
                usb_config.device_class = 0x00;
                usb_config.device_sub_class = 0x00;
                usb_config.device_protocol = 0x00;

                let driver = Driver::new(usb, &mut ep_out_buffer, OtgConfig::default());
                let mut builder = embassy_usb::Builder::new(
                    driver,
                    usb_config,
                    &mut config_desc,
                    &mut bos_desc,
                    &mut msos_desc,
                    &mut control_buf,
                );
                builder.handler(&mut handler);

                let (mut ep_out, mut ep_in) = {
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
                    let ep_out = alt.endpoint_bulk_out(None, 64);
                    let ep_in = alt.endpoint_bulk_in(None, 64);
                    (ep_out, ep_in)
                };
                let mut device = builder.build();

                // Fresh session for the freshly (re)enumerated device.
                session.reset();

                // Status screen: mode + SD size + live USB link bit (the speed
                // line reads `-` until the refresh loop has a first window).
                if let Some(display) = display.as_mut() {
                    display.show(
                        usb_mode::Mode::DvdRam,
                        sd_bytes,
                        msc::usb_connected(),
                        uptime_s(boot),
                        None,
                    );
                }

                // Run the gadget until BOOT is pressed. `gadget` returns `!`,
                // so only the BOOT arm is reachable; `Either::First` carries
                // the never type and can never be constructed.
                match select(
                    gadget(
                        &mut device,
                        &mut ep_out,
                        &mut ep_in,
                        &mut session,
                        &mut *work,
                        &mut *recv,
                        core::slice::from_mut(&mut drive),
                        &mut display,
                        sd_bytes,
                        boot,
                    ),
                    button.wait_press(),
                )
                .await
                {
                    Either::Second(()) => {}
                    Either::First(never) => match never {},
                }

                // Drop the device BEFORE the PHY is re-muxed: `Bus::drop`
                // disables the OTG controller core and releases USB_FS.
                drop(device);
            }

            usb_mode::Mode::Debug => {
                usb_mode::phy_to_usj();

                // Let the host re-enumerate the USB-Serial-JTAG interface
                // before emitting any defmt (its FIFO cannot be drained until
                // the host has it open).
                Timer::after(Duration::from_millis(300)).await;
                info!("mode: DEBUG - PHY on USB-Serial-JTAG; press BOOT for DVDRAM");

                if let Some(display) = display.as_mut() {
                    display.show(usb_mode::Mode::Debug, sd_bytes, false, uptime_s(boot), None);
                }

                // Keep the LCD alive and park until the next BOOT press. The
                // gadget is gone, so `usb_connected` is always reported false.
                loop {
                    match select(
                        button.wait_press(),
                        Timer::after(Duration::from_millis(500)),
                    )
                    .await
                    {
                        Either::First(()) => break,
                        Either::Second(()) => {
                            if let Some(display) = display.as_mut() {
                                display.show(
                                    usb_mode::Mode::Debug,
                                    sd_bytes,
                                    false,
                                    uptime_s(boot),
                                    None,
                                );
                            }
                        }
                    }
                }

                // Give the console a moment to drain before the mux flips back.
                info!("mode: leaving DEBUG, rebuilding DVDRAM gadget");
                Timer::after(Duration::from_millis(100)).await;
            }
        }

        mode = match mode {
            usb_mode::Mode::DvdRam => usb_mode::Mode::Debug,
            usb_mode::Mode::Debug => usb_mode::Mode::DvdRam,
        };
    }
}
