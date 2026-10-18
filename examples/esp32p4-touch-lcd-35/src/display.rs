//! Status LCD (ST7796, 3.5" 320x480) via `mipidsi` + `embedded-graphics`.
//!
//! Shows the SD size / USB state / bulk throughput (cumulative and per-window)
//! / uptime and a one-line BOT shell diagnostic. This is the only on-device
//! feedback: the debug console is a CH343P USB-UART bridge, so a host-side
//! `espflash monitor` needs the UART cable, while the panel works standalone.
//!
//! Wiring (Waveshare ESP32-P4-WIFI6-Touch-LCD-3.5, per the vendor BSP): SPI2
//! SCLK=GPIO21, MOSI=GPIO20, MISO=GPIO22; CS=GPIO23, DC=GPIO26, RST=GPIO27,
//! backlight=GPIO28. The panel is driven in SPI **mode 0** at 40 MHz — see the
//! note in [`Display::new`] about the vendor's mode-3 claim. `mipidsi` drives
//! the panel through an `embedded_hal_bus::spi::ExclusiveDevice` because
//! esp-hal only implements `SpiBus`, not `SpiDevice`.
//!
//! Panel options follow the vendor BSP: colour **inversion on**
//! (`esp_lcd_panel_invert_color(handle, true)` ⇒ `ColorInversion::Inverted`),
//! horizontal **mirror** (`esp_lcd_panel_mirror(handle, true, false)` ⇒
//! `Orientation::new().flip_horizontal()`), and BGR subpixel order. The
//! backlight (GPIO28, active high) is driven on for the life of the panel, and
//! the ST7796 needs its Sitronix extension-command unlock — see
//! [`WaveshareSt7796`].

use core::fmt::Write as _;

use embedded_graphics::{
    mono_font::{
        ascii::{FONT_10X20, FONT_6X10},
        MonoTextStyle,
    },
    pixelcolor::Rgb565,
    prelude::*,
    primitives::{PrimitiveStyle, Rectangle},
    text::{Baseline, Text},
};
use embedded_hal::delay::DelayNs;
use embedded_hal_bus::spi::ExclusiveDevice;
use esp_hal::{
    delay::Delay,
    gpio::{Level, Output, OutputConfig},
    spi::{
        master::{Config as SpiConfig, Spi},
        Mode,
    },
    time::Rate,
    Blocking,
};
use mipidsi::{
    dcs::{ExitSleepMode, InterfaceExt, SetAddressMode, SetDisplayOn, SetInvertMode},
    interface::{Interface, SpiInterface},
    models::{Model, ModelInitError},
    options::{ColorInversion, ColorOrder, ModelOptions, Orientation},
    Builder, Display as MipiDisplay,
};

/// Panel width in pixels (native portrait).
pub const WIDTH: u16 = 320;
/// Panel height in pixels (native portrait).
pub const HEIGHT: u16 = 480;

/// Height of the status-text band, in pixels.
///
/// Only this band is cleared/redrawn each refresh. A full 320x480 clear costs
/// ~120 ms of *blocking* SPI, which starves the USB stack — measured end-to-end
/// read throughput drops from ~4.5 to ~3.5 MB/s with a full-screen clear. The
/// band is sized for the 8 status lines drawn by [`Display::show`].
const TEXT_BAND_H: u32 = 112;

/// SPI clock for the panel (40 MHz is comfortably within spec; the vendor uses
/// up to 80 MHz).
const SPI_FREQ_MHZ: u32 = 40;

/// Errors returned while bringing up the panel.
#[derive(Debug, Clone, Copy, PartialEq, Eq, defmt::Format)]
pub enum InitError {
    /// Configuring the SPI2 bus or wrapping it in an `ExclusiveDevice` failed.
    Spi,
    /// The panel rejected its configuration, or the bus/DC/reset path failed.
    Panel,
}

/// ST7796 init for the Waveshare ESP32-P4-WIFI6-Touch-LCD-3.5 panel.
///
/// mipidsi's built-in [`mipidsi::models::ST7796`] runs the generic ST7789 init,
/// which omits the Sitronix **extension-command unlock** (`0xF0 0xC3` /
/// `0xF0 0x96`) that this glass needs before the power/VCOM/gamma registers are
/// writable. This model replays the vendor sequence from `esp_lcd_st7796`
/// (`panel_st7796_init` + `vendor_specific_init_default`).
struct WaveshareSt7796;

impl Model for WaveshareSt7796 {
    type ColorFormat = Rgb565;
    const FRAMEBUFFER_SIZE: (u16, u16) = (320, 480);
    // The vendor holds reset low for ~10 ms then waits 120 ms before the first
    // command.
    const RESET_DURATION: u32 = 10_000;

    fn init<DELAY, DI>(
        &mut self,
        di: &mut DI,
        delay: &mut DELAY,
        options: &ModelOptions,
    ) -> Result<SetAddressMode, ModelInitError<DI::Error>>
    where
        DELAY: DelayNs,
        DI: Interface,
    {
        // Let the panel settle after the `Builder`'s hardware reset.
        delay.delay_us(120_000);

        // Exit sleep, then set the address mode and pixel format.
        di.write_command(ExitSleepMode)?;
        delay.delay_us(100_000);

        let madctl = SetAddressMode::from(options);
        di.write_command(madctl)?;
        // COLMOD 0x05 (16bpp, DBI field) — the vendor value.
        di.write_raw(0x3A, &[0x05])?;

        // Extension-command enable, then power / VCOM / gamma.
        di.write_raw(0xF0, &[0xC3])?;
        di.write_raw(0xF0, &[0x96])?;
        di.write_raw(0xB4, &[0x01])?;
        di.write_raw(0xB7, &[0xC6])?;
        di.write_raw(0xE8, &[0x40, 0x8A, 0x00, 0x00, 0x29, 0x19, 0xA5, 0x33])?;
        di.write_raw(0xC1, &[0x06])?;
        di.write_raw(0xC2, &[0xA7])?;
        di.write_raw(0xC5, &[0x18])?;
        di.write_raw(
            0xE0,
            &[
                0xF0, 0x09, 0x0B, 0x06, 0x04, 0x15, 0x2F, 0x54, 0x42, 0x3C, 0x17, 0x14, 0x18, 0x1B,
            ],
        )?;
        di.write_raw(
            0xE1,
            &[
                0xF0, 0x09, 0x0B, 0x06, 0x04, 0x03, 0x2D, 0x43, 0x42, 0x3B, 0x16, 0x14, 0x17, 0x1B,
            ],
        )?;
        // Extension-command disable.
        di.write_raw(0xF0, &[0x3C])?;
        di.write_raw(0xF0, &[0x69])?;

        // The BSP applies colour inversion after init, then display on.
        di.write_command(SetInvertMode::new(options.invert_colors))?;
        di.write_command(SetDisplayOn)?;
        delay.delay_us(120_000);

        Ok(madctl)
    }
}

type SpiBus<'d> = Spi<'d, Blocking>;
type SpiDev<'d> = ExclusiveDevice<SpiBus<'d>, Output<'d>, Delay>;
type Di<'d> = SpiInterface<'d, SpiDev<'d>, Output<'d>>;
type Panel<'d> = MipiDisplay<Di<'d>, WaveshareSt7796, Output<'d>>;

/// Status LCD driven over SPI2.
pub struct Display<'d> {
    panel: Panel<'d>,
    /// Backlight enable (GPIO28). Held so the pin stays driven high.
    _backlight: Output<'d>,
}

impl<'d> Display<'d> {
    /// Bring up SPI2 and initialise the ST7796 panel.
    ///
    /// `buffer` is the interface's pixel-staging buffer; a few dozen bytes is
    /// the minimum, larger is faster.
    #[allow(
        clippy::too_many_arguments,
        reason = "one argument per panel signal (bus + CS/DC/RST/backlight), mirroring the board wiring"
    )]
    pub fn new(
        spi2: esp_hal::peripherals::SPI2<'d>,
        sck: esp_hal::peripherals::GPIO21<'d>,
        mosi: esp_hal::peripherals::GPIO20<'d>,
        miso: esp_hal::peripherals::GPIO22<'d>,
        cs: esp_hal::peripherals::GPIO23<'d>,
        dc: esp_hal::peripherals::GPIO26<'d>,
        rst: esp_hal::peripherals::GPIO27<'d>,
        backlight: esp_hal::peripherals::GPIO28<'d>,
        buffer: &'d mut [u8],
    ) -> Result<Self, InitError> {
        // SPI2 master, **mode 0**. NOTE: the vendor BSP declares `spi_mode = 3`,
        // but that does not correspond to esp-hal's `Mode::_3` for this panel —
        // an on-hardware sweep (a uniform-colour fill per mode/frequency) showed
        // only mode 0 driving the panel; mode 3 produced nothing. 40 MHz is fine.
        let spi = Spi::new(
            spi2,
            SpiConfig::default()
                .with_frequency(Rate::from_mhz(SPI_FREQ_MHZ))
                .with_mode(Mode::_0),
        )
        .map_err(|_| InitError::Spi)?
        .with_sck(sck)
        .with_mosi(mosi)
        .with_miso(miso);

        // CS idles high, DC low (command mode), RST high (out of reset).
        let cs = Output::new(cs, Level::High, OutputConfig::default());
        let dc = Output::new(dc, Level::Low, OutputConfig::default());
        let rst = Output::new(rst, Level::High, OutputConfig::default());
        // Backlight on (active high) for the whole program.
        let backlight = Output::new(backlight, Level::High, OutputConfig::default());

        // esp-hal only implements `SpiBus`; `mipidsi` needs a `SpiDevice`.
        let spi_dev = ExclusiveDevice::new(spi, cs, Delay::new()).map_err(|_| InitError::Spi)?;

        let di = SpiInterface::new(spi_dev, dc, buffer);

        // `mipidsi::Builder::init` needs the *blocking* `embedded_hal::delay::DelayNs`,
        // which `esp_hal::delay::Delay` provides.
        let mut delay = Delay::new();
        let panel = Builder::new(WaveshareSt7796, di)
            // Native (portrait) active window; the framebuffer is 320x480.
            .display_size(WIDTH, HEIGHT)
            // Vendor BSP mirrors horizontally (`esp_lcd_panel_mirror(true, false)`):
            // Deg0 + mirrored is exactly MX=1, MY=0.
            .orientation(Orientation::new().flip_horizontal())
            // Vendor BSP inverts colours (`esp_lcd_panel_invert_color(true)`).
            .invert_colors(ColorInversion::Inverted)
            // Vendor BSP colour space is BGR (`LCD_RGB_ELEMENT_ORDER_BGR`).
            .color_order(ColorOrder::Bgr)
            .reset_pin(rst)
            .init(&mut delay)
            .map_err(|_| InitError::Panel)?;

        Ok(Self {
            panel,
            _backlight: backlight,
        })
    }

    /// Show a single large boot-progress line.
    ///
    /// Used to localise a cold-boot hang without a UART console: each startup
    /// stage paints an incrementing marker, so the last one on screen is the
    /// stage that stalled.
    pub fn boot_stage(&mut self, msg: &str) {
        let _ = self.panel.clear(Rgb565::BLACK);
        let style = MonoTextStyle::new(&FONT_10X20, Rgb565::WHITE);
        let _ =
            Text::with_baseline(msg, Point::new(8, 20), style, Baseline::Top).draw(&mut self.panel);
    }

    /// Clear the panel and redraw the status lines.
    ///
    /// `uptime_s` renders as `UPT: h:mm:ss` seconds since boot. The readout
    /// only advances because the caller's refresh loop runs, so a frozen
    /// number is the "MCU hung or panicked" signal; the value itself is real
    /// wall-clock time, not a tick count.
    ///
    /// `bulk` carries the **cumulative** `(RX, TX)` bulk byte counts
    /// (host→device / device→host); `rate` is the per-window `(RX, TX)`
    /// throughput in decimal KB/s over the last refresh. Both lines are hidden
    /// when `None`. The cumulative line is the diagnostic one: the first BOT
    /// transaction is only tens of bytes, which a KB/s rate rounds to zero.
    ///
    /// `sd` is the SD-layer sample `(card_read_kBps, write_kBps, cache_hit_pct,
    /// mean_command_bytes)`: what actually crossed the SD bus, how much of the
    /// LUN's read traffic the read-ahead window served without touching the
    /// card, and the mean size of an SD read command (16 KiB when the window is
    /// engaged, 512 B for a single-block probe).
    ///
    /// `diag` is `(serve_restarts, bus_resets, in_calls, in_disabled,
    /// in_overflow, rx_cbw, rx_other)`. The USB line shows `F`/`R`/`C`/`D`
    /// (only when non-zero); the uptime line shows `cbw`/`oth` when
    /// command-phase reads were seen. `C == 0` with a live host means no
    /// response was generated; `rx_other > 0` means the device read non-`USBC`
    /// bytes (stale endpoint data → rejected CBW → no send).
    #[allow(clippy::too_many_arguments)]
    pub fn show(
        &mut self,
        sd_bytes: Option<u64>,
        usb_connected: bool,
        uptime_s: u32,
        bulk: Option<(u32, u32)>,
        rate: Option<(u32, u32)>,
        sd: (u32, u32, u32, u32),
        diag: (u32, u32, u32, u32, u32, u32, u32),
    ) {
        // Best-effort: a bus error will resurface on the next write anyway.
        //
        // Only the text band is cleared (not the whole 320x480 screen): the
        // full-screen clear costs ~120 ms of blocking SPI each refresh, which
        // starves the USB stack and measurably drops throughput.
        let _ = Rectangle::new(Point::new(0, 0), Size::new(u32::from(WIDTH), TEXT_BAND_H))
            .into_styled(PrimitiveStyle::with_fill(Rgb565::BLACK))
            .draw(&mut self.panel);

        let style = MonoTextStyle::new(&FONT_6X10, Rgb565::WHITE);
        let mut line = heapless::String::<32>::new();

        // UHS-I handshake state, pinned to the bottom of the screen so it never
        // fights the counters above and survives a band refresh. This is what
        // makes a power-cycle test readable without a UART console.
        {
            use esp_hal::sdmmc::diag;
            let style = MonoTextStyle::new(&FONT_6X10, Rgb565::YELLOW);
            let mut l = heapless::String::<32>::new();

            let a = diag::get(&diag::ACMD41_ARG);
            let r = diag::get(&diag::ACMD41_RESP0);
            let _ = write!(
                l,
                "UHS a18r={} s18a={} busy={}",
                (a >> 24) & 1,
                (r >> 24) & 1,
                (r >> 31) & 1
            );
            let _ = Text::with_baseline(&l, Point::new(8, HEIGHT as i32 - 60), style, Baseline::Top)
                .draw(&mut self.panel);

            l.clear();
            let _ = write!(
                l,
                "FG1 {:02x}/{:02x} CMD11={}",
                diag::get(&diag::CMD6_FG1_SUPPORT),
                diag::get(&diag::CMD6_FG1_SELECTED),
                diag::get(&diag::CMD11)
            );
            let _ = Text::with_baseline(&l, Point::new(8, HEIGHT as i32 - 48), style, Baseline::Top)
                .draw(&mut self.panel);

            l.clear();
            let _ = write!(
                l,
                "lastcmd {} arg={:08x}",
                diag::get(&diag::LAST_CMD),
                diag::get(&diag::LAST_CMD_ARG)
            );
            let _ = Text::with_baseline(&l, Point::new(8, HEIGHT as i32 - 36), style, Baseline::Top)
                .draw(&mut self.panel);
        }

        // Title.
        let _ = write!(line, "ESP32-P4 DVD-RAM");
        draw_line(&mut self.panel, style, &line, 3);

        // SD capacity.
        line.clear();
        let _ = write!(line, "SD: ");
        match sd_bytes {
            Some(bytes) => write_size(&mut line, bytes),
            None => {
                let _ = write!(line, "n/a");
            }
        }
        draw_line(&mut self.panel, style, &line, 16);

        // USB link state + serve/IN diagnostics (only non-zero fields, so the
        // normal case stays short).
        line.clear();
        let usb = if usb_connected { "conn" } else { "disc" };
        let (restarts, bus_resets, in_calls, in_disabled, _in_overflow, rx_cbw, rx_other) = diag;
        let _ = write!(line, "USB:{}", usb);
        if restarts > 0 {
            let _ = write!(line, " F{}", restarts);
        }
        if bus_resets > 0 {
            let _ = write!(line, " R{}", bus_resets);
        }
        if in_calls > 0 {
            let _ = write!(line, " C{}", in_calls);
        }
        if in_disabled > 0 {
            let _ = write!(line, " D{}", in_disabled);
        }
        draw_line(&mut self.panel, style, &line, 29);

        // Cumulative USB bulk bytes (measured in the BOT loop). `RX==0` with a
        // host attached means the CBW was never taken off the OUT endpoint.
        line.clear();
        match bulk {
            Some((rx_bytes, tx_bytes)) => {
                let _ = write!(line, "RX:");
                write_tally(&mut line, rx_bytes);
                let _ = write!(line, " TX:");
                write_tally(&mut line, tx_bytes);
            }
            None => {
                let _ = write!(line, "RX/TX: -");
            }
        }
        draw_line(&mut self.panel, style, &line, 42);

        // Instantaneous throughput over the last refresh window (decimal KB/s).
        line.clear();
        match rate {
            Some((rx_kbps, tx_kbps)) => {
                let _ = write!(line, "RX:");
                write_rate(&mut line, rx_kbps);
                let _ = write!(line, "/s TX:");
                write_rate(&mut line, tx_kbps);
            }
            None => {
                let _ = write!(line, "RX/TX: -/s");
            }
        }
        draw_line(&mut self.panel, style, &line, 55);

        // SD-card level: what actually crossed the SD bus (32-block windows that
        // the 8 KiB shell chunk hides), and how much of the LUN read traffic the
        // read-ahead window served for free.
        let (sd_rd_kbps, sd_wr_kbps, cache_pct, cmd_bytes) = sd;
        line.clear();
        let _ = write!(line, "SDrd:");
        write_rate(&mut line, sd_rd_kbps);
        let _ = write!(line, "/s SDwr:");
        write_rate(&mut line, sd_wr_kbps);
        let _ = write!(line, "/s");
        draw_line(&mut self.panel, style, &line, 68);

        // Read-ahead effectiveness + mean SD read-command size (16K when the
        // window is engaged, down to 1K for single-block probes).
        line.clear();
        let _ = write!(line, "cache:{}% cmd:{}K", cache_pct, cmd_bytes / 1024);
        draw_line(&mut self.panel, style, &line, 81);

        // Uptime: hours (unpadded), minutes and seconds (zero-padded). Reads
        // like a clock rather than a tick count; it only advances while this
        // refresh loop is alive.
        line.clear();
        let _ = write!(
            line,
            "UPT: {}:{:02}:{:02}",
            uptime_s / 3600,
            (uptime_s % 3600) / 60,
            uptime_s % 60
        );
        if rx_cbw > 0 || rx_other > 0 {
            let _ = write!(line, " cbw{} oth{}", rx_cbw, rx_other);
        }
        draw_line(&mut self.panel, style, &line, 94);
    }
}

/// Left text margin in pixels. The panel bezel physically covers ~4 px of the
/// glass on each side, so status text is inset to keep glyphs fully visible.
const MARGIN_X: i32 = 6;

/// Draw one line of status text at `(MARGIN_X, y)`.
///
/// Anchored by [`Baseline::Top`] so `y` is the top of the glyphs: `Text::new`
/// defaults to an *alphabetic* baseline, which draws the glyphs above `y` and
/// (because the panel ram wraps at row 0) pushes a top line onto the bottom of
/// the screen.
fn draw_line<D>(target: &mut D, style: MonoTextStyle<'_, Rgb565>, text: &str, y: i32)
where
    D: DrawTarget<Color = Rgb565>,
{
    let _ = Text::with_baseline(text, Point::new(MARGIN_X, y), style, Baseline::Top).draw(target);
}

/// Append a cumulative byte count compactly: `31B`, `4096K`, `12M`.
///
/// Integer units keep the digits stable on a 6x10 font; the diagnostic value
/// is "is it zero / is it moving", not precision.
fn write_tally(out: &mut heapless::String<32>, bytes: u32) {
    const KI: u32 = 1024;
    const MI: u32 = 1024 * 1024;

    if bytes < KI {
        let _ = write!(out, "{}B", bytes);
    } else if bytes < MI {
        let _ = write!(out, "{}K", bytes / KI);
    } else {
        let _ = write!(out, "{}M", bytes / MI);
    }
}

/// Append a throughput as `12345K` or `1.2M` (decimal kilobytes-per-second).
///
/// Below 1000 KB/s the value stays an integer KB count so the digits do not
/// flicker between formats; above it one decimal digit resolves the rates a
/// High-Speed bulk pipe actually delivers.
fn write_rate(out: &mut heapless::String<32>, kbps: u32) {
    const KI: u32 = 1000;

    if kbps < KI {
        let _ = write!(out, "{}K", kbps);
    } else {
        let whole = kbps / KI;
        let tenth = (kbps % KI) * 10 / KI;
        let _ = write!(out, "{}.{}M", whole, tenth);
    }
}

/// Format a byte count as `12.3 GiB` / `456.7 MiB` / `89 KiB`.
fn write_size(out: &mut heapless::String<32>, bytes: u64) {
    const MIB: u64 = 1024 * 1024;
    const GIB: u64 = 1024 * MIB;

    if bytes >= GIB {
        let whole = bytes / GIB;
        let tenth = (bytes % GIB) * 10 / GIB;
        let _ = write!(out, "{}.{} GiB", whole, tenth);
    } else if bytes >= MIB {
        let whole = bytes / MIB;
        let tenth = (bytes % MIB) * 10 / MIB;
        let _ = write!(out, "{}.{} MiB", whole, tenth);
    } else {
        let _ = write!(out, "{} KiB", bytes / 1024);
    }
}
