//! Status LCD (ST7735S, 0.96" 160x80) via `mipidsi` + `embedded-graphics`.
//!
//! Shows the current mode / SD size / USB state / bulk throughput (RX + TX)
//! / bulk throughput (RX + TX) / uptime as text lines.
//!
//! Wiring: SPI2 SCK=GPIO10, MOSI=GPIO11; CS=GPIO12, DC=GPIO13, RST=GPIO14.
//! `mipidsi` drives the panel through an `embedded_hal_bus::spi::ExclusiveDevice`
//! because esp-hal only implements `SpiBus`, not `SpiDevice`.
#![allow(dead_code)]

use core::fmt::Write as _;

use embedded_graphics::{
    mono_font::{ascii::FONT_6X10, MonoTextStyle},
    pixelcolor::Rgb565,
    prelude::*,
    text::Text,
};
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
    interface::SpiInterface,
    models::ST7735s,
    options::{ColorOrder, Orientation, Rotation},
    Builder, Display as MipiDisplay,
};

/// Panel width in pixels (logical, landscape).
pub const WIDTH: u16 = 160;
/// Panel height in pixels (logical, landscape).
pub const HEIGHT: u16 = 80;

/// ST7735S active-window width along its native (portrait) axis.
///
/// This is what must be passed to [`Builder::display_size`]: `mipidsi` validates
/// the size plus offset against the controller's fixed 132x162 framebuffer, so
/// the 160-pixel logical width cannot be used directly. Rotating by 90° (see
/// [`Display::new`]) makes the display report the logical 160x80 frame.
const NATIVE_WIDTH: u16 = 80;
/// ST7735S active-window height along its native (portrait) axis.
const NATIVE_HEIGHT: u16 = 160;
/// Green-tab column offset, in native axes.
///
/// **VERIFY ON HARDWARE.** The plan suggests `(24, 0)`; different green-tab
/// glass revisions use `(24, 0)`, `(26, 1)` or `(0, 0)`.
const DISPLAY_OFFSET: (u16, u16) = (24, 0);

/// Errors returned while bringing up the panel.
#[derive(Debug, Clone, Copy, PartialEq, Eq, defmt::Format)]
pub enum InitError {
    /// Configuring the SPI2 bus or wrapping it in an `ExclusiveDevice` failed.
    Spi,
    /// The panel rejected its configuration, or the bus/DC/reset path failed.
    Panel,
}

type SpiBus<'d> = Spi<'d, Blocking>;
type SpiDev<'d> = ExclusiveDevice<SpiBus<'d>, Output<'d>, Delay>;
type Di<'d> = SpiInterface<'d, SpiDev<'d>, Output<'d>>;
type Panel<'d> = MipiDisplay<Di<'d>, ST7735s, Output<'d>>;

/// Status LCD driven over SPI2.
pub struct Display<'d> {
    panel: Panel<'d>,
}

impl<'d> Display<'d> {
    /// Bring up SPI2 and initialise the ST7735S panel.
    ///
    /// `buffer` is the interface's pixel-staging buffer; a few dozen bytes is
    /// the minimum, larger is faster.
    pub fn new(
        spi2: esp_hal::peripherals::SPI2<'d>,
        sck: esp_hal::peripherals::GPIO10<'d>,
        mosi: esp_hal::peripherals::GPIO11<'d>,
        cs: esp_hal::peripherals::GPIO12<'d>,
        dc: esp_hal::peripherals::GPIO13<'d>,
        rst: esp_hal::peripherals::GPIO14<'d>,
        buffer: &'d mut [u8],
    ) -> Result<Self, InitError> {
        // SPI2 master, mode 0, 40 MHz.
        let spi = Spi::new(
            spi2,
            SpiConfig::default()
                .with_frequency(Rate::from_mhz(40))
                .with_mode(Mode::_0),
        )
        .map_err(|_| InitError::Spi)?
        .with_sck(sck)
        .with_mosi(mosi);

        // CS idles high, DC low (command mode), RST high (out of reset).
        let cs = Output::new(cs, Level::High, OutputConfig::default());
        let dc = Output::new(dc, Level::Low, OutputConfig::default());
        let rst = Output::new(rst, Level::High, OutputConfig::default());

        // esp-hal only implements `SpiBus`; `mipidsi` needs a `SpiDevice`.
        let spi_dev = ExclusiveDevice::new(spi, cs, Delay::new()).map_err(|_| InitError::Spi)?;

        let di = SpiInterface::new(spi_dev, dc, buffer);

        // `mipidsi::Builder::init` needs the *blocking* `embedded_hal::delay::DelayNs`,
        // which `esp_hal::delay::Delay` provides.
        let mut delay = Delay::new();
        let panel = Builder::new(ST7735s, di)
            // Green-tab 160x80 panel; see DISPLAY_OFFSET (verify on hardware).
            .display_offset(DISPLAY_OFFSET.0, DISPLAY_OFFSET.1)
            // Native (portrait) active window; rotated below to the logical frame.
            .display_size(NATIVE_WIDTH, NATIVE_HEIGHT)
            // Rotate the native portrait window so `size()` reports 160x80.
            .orientation(Orientation::new().rotate(Rotation::Deg90))
            // Vendor TFT_eSPI config uses `TFT_RGB_ORDER=TFT_BGR`.
            .color_order(ColorOrder::Bgr)
            .reset_pin(rst)
            .init(&mut delay)
            .map_err(|_| InitError::Panel)?;

        Ok(Self { panel })
    }

    /// Clear the panel and redraw the status lines.
    ///
    /// `uptime_s` renders as `UPT: h:mm:ss` seconds since boot. The readout
    /// only advances because the caller's refresh loop runs, so a frozen
    /// number is the "MCU hung or panicked" signal (the USB console is
    /// unavailable once the PHY is on OTG); the value itself is real
    /// wall-clock time, not a tick count.
    ///
    /// `speed` carries `(RX, TX)` bulk throughput in decimal KB/s over the
    /// last refresh interval (host→device / device→host) while the USB gadget
    /// is the active PHY owner; `None` hides the line (no gadget, e.g. DEBUG).
    pub fn show(
        &mut self,
        mode: crate::usb_mode::Mode,
        sd_bytes: Option<u64>,
        usb_connected: bool,
        uptime_s: u32,
        speed: Option<(u32, u32)>,
    ) {
        // Best-effort: a bus error will resurface on the next write anyway.
        let _ = self.panel.clear(Rgb565::BLACK);

        let style = MonoTextStyle::new(&FONT_6X10, Rgb565::WHITE);
        let mut line = heapless::String::<32>::new();

        // Mode.
        let mode_label = match mode {
            // The M1 interface names the non-DVDRAM variant `Debug`; the current
            // `usb_mode` stub calls it `SerialJtag`, so match the rest loosely.
            crate::usb_mode::Mode::DvdRam => "DVDRAM",
            _ => "DEBUG",
        };
        let _ = write!(line, "MODE: {}", mode_label);
        draw_line(&mut self.panel, style, &line, 10);

        // SD capacity.
        line.clear();
        let _ = write!(line, "SD: ");
        match sd_bytes {
            Some(bytes) => write_size(&mut line, bytes),
            None => {
                let _ = write!(line, "n/a");
            }
        }
        draw_line(&mut self.panel, style, &line, 26);

        // USB link state.
        line.clear();
        let usb = if usb_connected {
            "connected"
        } else {
            "disconnected"
        };
        let _ = write!(line, "USB: {}", usb);
        draw_line(&mut self.panel, style, &line, 42);

        // USB bulk throughput since the previous refresh (decimal KB/s,
        // measured in the BOT loop) — only meaningful while the USB gadget is
        // running.
        line.clear();
        match speed {
            Some((rx_kbps, tx_kbps)) => {
                let _ = write!(line, "RX:");
                write_rate(&mut line, rx_kbps);
                let _ = write!(line, " TX:");
                write_rate(&mut line, tx_kbps);
            }
            None => {
                let _ = write!(line, "RX/TX: -");
            }
        }
        draw_line(&mut self.panel, style, &line, 56);

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
        draw_line(&mut self.panel, style, &line, 70);
    }
}

/// Draw one line of status text at `(2, y)`.
fn draw_line<D>(target: &mut D, style: MonoTextStyle<'_, Rgb565>, text: &str, y: i32)
where
    D: DrawTarget<Color = Rgb565>,
{
    let _ = Text::new(text, Point::new(2, y), style).draw(target);
}

/// Append a KB/s rate as `12345KB` or `1.2MB` (decimal kilobytes, no/s).
///
/// Below 1000 KB/s the value stays an integer KB count so the digits do not
/// flicker between formats; above it one decimal digit resolves the rates a
/// Full-Speed bulk pipe actually delivers.
fn write_rate(out: &mut heapless::String<32>, kbps: u32) {
    const KI: u32 = 1000;

    if kbps < KI {
        let _ = write!(out, "{}KB", kbps);
    } else {
        let whole = kbps / KI;
        let tenth = (kbps % KI) * 10 / KI;
        let _ = write!(out, "{}.{}MB", whole, tenth);
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
