//! Runtime mux for the ESP32-S3 internal USB FSLS PHY.
//!
//! The ESP32-S3 has **one** internal Full-Speed/Low-Speed USB PHY shared by two
//! controllers:
//!
//! * the USB-OTG (DWC) controller, which drives the UDF-RW gadget (normal
//!   product mode, [`Mode::Udfrw`]); and
//! * the USB-Serial-JTAG controller, which the ROM exposes as the
//!   `esptool`/`espflash` download + console interface ([`Mode::Debug`]).
//!
//! By default the PHY is wired to USB-Serial-JTAG; the `USB_PHY_SEL` eFuse (or
//! esp-hal's OTG init, which we mirror) can move it to USB-OTG. At reset both
//! software mux bits are `0`, so the hardware follows the eFuse.
//!
//! `esp-hal` 1.2.2 exposes **no supported API** to move the internal PHY
//! between the two controllers at runtime (upstream esp-hal issue #1991,
//! "Support USB External PHY and USB-SERIAL-JTAG coexistence", is still open).
//! We therefore drive the three PAC register blocks directly. The writes go
//! through the safe [`regs()`] accessors and the PAC's safe `set_bit()` /
//! `clear_bit()` bit writers, so **no `unsafe` is used**; the HAL simply has no
//! abstraction over these fields yet.
//!
//! Register semantics (ESP-IDF
//! `components/esp_hal_usb/esp32s3/include/hal/usb_serial_jtag_ll.h:209-220`
//! and `usb_wrap_ll.h:56-67`):
//!
//! * `LPWR.USB_CONF.SW_HW_USB_PHY_SEL` (`1`) makes software own the mux.
//! * `LPWR.USB_CONF.SW_USB_PHY_SEL`: `0` routes the internal FSLS PHY to the
//!   USB-Serial-JTAG controller (USJ), `1` routes it to the USB-OTG wrap. The
//!   file header above it is unambiguous:
//!   `0 - Internal USB FSLS PHY is mapped to the USJ. USB Wrap mapped to external PHY`
//!   `1 - Internal USB FSLS PHY is mapped to the USB Wrap. USJ mapped to external PHY`
//! * `USB_WRAP.OTG_CONF.PHY_SEL`: `0` = OTG uses the internal PHY, `1` =
//!   external; `.USB_PAD_ENABLE` gates the OTG pads.
//! * `USB_DEVICE.CONF0.PHY_SEL`: `0` = USJ uses the internal PHY, `1` =
//!   external; `.USB_PAD_ENABLE` gates the USJ pads.
//!
//! The actual pad-level round trip cannot be exercised off-target: the
//! register *values* are cited from ESP-IDF, but the ordering, pad contention
//! and whether the mux flip alone exposes the ROM's download interface are only
//! confirmed by a hardware spike. Until
//! then these functions are the reference implementation of the mux, not a
//! verified sequence.
//!
//! [`regs()`]: esp_hal::peripherals::LPWR::regs
#![allow(dead_code)]

use esp_hal::peripherals::{LPWR, USB_DEVICE, USB_WRAP};

/// Which controller currently owns the shared USB PHY.
#[derive(Debug, Clone, Copy, PartialEq, Eq, defmt::Format)]
pub enum Mode {
    /// USB-OTG drives the UDF-RW gadget (normal product mode).
    Udfrw,
    /// USB-Serial-JTAG drives the port (ROM download / `espflash` console).
    Debug,
}

/// Route the internal FSLS PHY to the **USB-OTG** controller (USB wrap).
///
/// Mirrors esp-hal's own OTG init (`fs_common_init` + `common_init`): software
/// owns the mux (`SW_HW_USB_PHY_SEL = 1`), the internal PHY goes to the wrap
/// (`SW_USB_PHY_SEL = 1`), the wrap's `PHY_SEL = 0` selects the internal PHY
/// and its pads are enabled; the USB-Serial-JTAG controller is pointed at the
/// external PHY with its pads released (`CONF0.PHY_SEL = 1`,
/// `CONF0.USB_PAD_ENABLE = 0`).
pub fn phy_to_otg() {
    // RTC/low-power shared mux: software control, internal PHY -> USB wrap.
    LPWR::regs().usb_conf().modify(|_, w| {
        w.sw_hw_usb_phy_sel().set_bit(); // bit 20 = 1 (software owns the mux)
        w.sw_usb_phy_sel().set_bit() // bit 19 = 1 -> OTG/USB wrap
    });

    // OTG wrap: internal PHY, pads on.
    USB_WRAP::regs().otg_conf().modify(|_, w| {
        w.phy_sel().clear_bit(); // bit 2  = 0 -> OTG uses internal PHY
        w.usb_pad_enable().set_bit() // bit 18 = 1 -> OTG pads on
    });

    // Point USB-Serial-JTAG away from the PHY and release its pads.
    USB_DEVICE::regs().conf0().modify(|_, w| {
        w.phy_sel().set_bit(); // bit 0  = 1 -> USJ external PHY
        w.usb_pad_enable().clear_bit() // bit 14 = 0 -> USJ pads off
    });
}

/// Route the internal FSLS PHY to the **USB-Serial-JTAG** controller.
///
/// This is the direction esp-hal does *not* support (the ROM/esptool download
/// interface needs the internal PHY). Software owns the mux
/// (`SW_HW_USB_PHY_SEL = 1`), `SW_USB_PHY_SEL = 0` maps the internal PHY to
/// USJ, and `USB_DEVICE.CONF0` selects the internal PHY with its pads enabled;
/// the OTG wrap is pointed at the external PHY with its pads released
/// (`OTG_CONF.PHY_SEL = 1`, `OTG_CONF.USB_PAD_ENABLE = 0`).
pub fn phy_to_usj() {
    // RTC/low-power shared mux: software control, internal PHY -> USJ.
    LPWR::regs().usb_conf().modify(|_, w| {
        w.sw_hw_usb_phy_sel().set_bit(); // bit 20 = 1 (software owns the mux)
        w.sw_usb_phy_sel().clear_bit() // bit 19 = 0 -> internal PHY to USJ
    });

    // USB-Serial-JTAG: internal PHY, pads on.
    USB_DEVICE::regs().conf0().modify(|_, w| {
        w.phy_sel().clear_bit(); // bit 0  = 0 -> USJ uses internal PHY
        w.usb_pad_enable().set_bit() // bit 14 = 1 -> USJ pads on
    });

    // Point the OTG wrap away from the PHY and release its pads.
    USB_WRAP::regs().otg_conf().modify(|_, w| {
        w.phy_sel().set_bit(); // bit 2  = 1 -> OTG external PHY
        w.usb_pad_enable().clear_bit() // bit 18 = 0 -> OTG pads off
    });
}
