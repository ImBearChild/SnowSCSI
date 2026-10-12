//! BOOT button (GPIO0) handling: pull-up input, debounce, mode toggle.
//!
//! The BOOT button is wired to GPIO0 and is active-low (pressed = low) with an
//! external pull-up; the internal pull-up is enabled as well so the line is
//! never left floating.
#![allow(dead_code)]

use embassy_time::{Duration, Timer};
use esp_hal::gpio::{Input, InputConfig, Pull};

/// Debounce interval in milliseconds.
pub const DEBOUNCE_MS: u64 = 30;

/// BOOT button on GPIO0 (active low, pulled up).
pub struct BootButton<'d> {
    pin: Input<'d>,
}

impl<'d> BootButton<'d> {
    /// Wrap the GPIO0 peripheral as a pulled-up digital input.
    pub fn new(pin: esp_hal::peripherals::GPIO0<'d>) -> Self {
        let pin = Input::new(pin, InputConfig::default().with_pull(Pull::Up));
        Self { pin }
    }

    /// Resolve after a debounced press.
    ///
    /// Starts from a known-released state, blocks on a falling edge, re-checks
    /// after [`DEBOUNCE_MS`] to reject contact bounce, then waits for the
    /// debounced release. Waiting for the release means one physical click
    /// produces exactly one completion even if the button is held down.
    pub async fn wait_press(&mut self) {
        // Start from a known-released state (the button may already be down
        // when this future is first polled).
        while self.pin.is_low() {
            self.pin.wait_for_rising_edge().await;
        }

        // Wait for a falling edge that is still low after the debounce window.
        loop {
            self.pin.wait_for_falling_edge().await;
            Timer::after(Duration::from_millis(DEBOUNCE_MS)).await;
            if self.pin.is_low() {
                break;
            }
        }

        // Consume the release so a held button does not immediately retrigger.
        loop {
            self.pin.wait_for_rising_edge().await;
            Timer::after(Duration::from_millis(DEBOUNCE_MS)).await;
            if self.pin.is_high() {
                break;
            }
        }
    }
}
