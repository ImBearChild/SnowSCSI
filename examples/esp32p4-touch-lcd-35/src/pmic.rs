//! AXP2101 PMIC access (Waveshare ESP32-P4 boards).
//!
//! The board's main PMIC is an X-Powers **AXP2101** on the P4's I2C bus, slave
//! address `0x34`, with **SDA = GPIO7** and **SCL = GPIO8**.
//!
//! Its `ESP_3V3` output (DCDC1) supplies the P4's `VDDPST1`/`VDDPST2` and --
//! through the Q1 load switch on GPIO45 -- the TF-slot VDD. So a PMIC
//! *software restart* is a genuine power cycle for the SD card as well, which
//! is the only way to clear a card's sticky 1.8 V signalling latch (a warm
//! reset does not, and the card VDD node has no discharge path so cutting Q1
//! alone takes minutes).
//!
//! `COMMON_CONFIG` (0x10): bit0 = software shutdown (all rails off, only VRTC
//! kept), **bit1 = software restart (`POWOFF`/`POWON`)**, bit2 = PWRON shuts
//! the PMIC, bit3 = PWROK pull-low, bit5 = internal discharge.
//!
//! See <https://github.com/lewisxhe/XPowersLib> (`XPowersAXP2101.hpp`).

use esp_hal::i2c::master::{Config as I2cConfig, Error as I2cError, I2c};
use esp_hal::peripherals::{GPIO7, GPIO8, I2C0};
use esp_hal::Blocking;

/// AXP2101 7-bit I2C slave address.
const ADDR: u8 = 0x34;
/// `IC_TYPE` -- read-only identity register, used as a presence probe.
const REG_IC_TYPE: u8 = 0x03;
/// `STATUS1` -- power-on source / battery presence.
const REG_STATUS1: u8 = 0x00;
/// `COMMON_CONFIG`.
const REG_COMMON_CONFIG: u8 = 0x10;

/// `COMMON_CONFIG` bit 1: software restart (`POWOFF`/`POWON`).
const COMMON_CONFIG_RESTART: u8 = 1 << 1;

/// AXP2101 handle over the board's I2C bus.
pub struct Pmic<'d> {
    i2c: I2c<'d, Blocking>,
}

impl<'d> Pmic<'d> {
    /// Bring up I2C0 on the PMIC pins. `None` if the bus cannot be configured.
    pub fn new(i2c: I2C0<'d>, sda: GPIO7<'d>, scl: GPIO8<'d>) -> Option<Self> {
        let i2c = I2c::new(i2c, I2cConfig::default())
            .ok()?
            .with_sda(sda)
            .with_scl(scl);
        Some(Self { i2c })
    }

    fn read_reg(&mut self, reg: u8) -> Result<u8, I2cError> {
        let mut v = [0u8; 1];
        self.i2c.write_read(ADDR, &[reg], &mut v)?;
        Ok(v[0])
    }

    fn write_reg(&mut self, reg: u8, value: u8) -> Result<(), I2cError> {
        self.i2c.write(ADDR, &[reg, value])
    }

    /// Read `IC_TYPE`; `Ok` only means the PMIC answered on the bus.
    pub fn ic_type(&mut self) -> Result<u8, I2cError> {
        self.read_reg(REG_IC_TYPE)
    }

    /// Read `STATUS1` (power-on source).
    pub fn status1(&mut self) -> Result<u8, I2cError> {
        self.read_reg(REG_STATUS1)
    }

    /// Ask the PMIC to power-cycle the whole board (`POWOFF`/`POWON`).
    ///
    /// The call does not return in practice: the PMIC drops every rail and
    /// brings them back, so the P4 reboots from flash -- and the SD card, on
    /// the same `ESP_3V3` rail, comes back at 3.3 V.
    pub fn restart(&mut self) -> Result<(), I2cError> {
        let v = self.read_reg(REG_COMMON_CONFIG)?;
        self.write_reg(REG_COMMON_CONFIG, v | COMMON_CONFIG_RESTART)
    }
}
