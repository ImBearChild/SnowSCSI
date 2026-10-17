# esp32p4-touch-lcd-35

Presents the on-board microSD card of a **Waveshare ESP32-P4-WIFI6-Touch-LCD-3.5**
as one whole raw block device to a USB host, as a **UDF-RW (DVD-RAM) optical
device** driven by `snowscsi`.

This is the ESP32-P4 port of [`esp32s3-pocket-dongle`](../esp32s3-pocket-dongle).
The reason to move to the P4 is the **USB 2.0 High-Speed** OTG port (480 Mbit/s,
internal UTMI PHY): the ESP32-S3's Full-Speed PHY caps the whole gadget at
~0.5 MB/s regardless of firmware, while the P4's HS port lifts that ceiling.

| | ESP32-S3 dongle | this example |
|---|---|---|
| USB | Full-Speed 12 Mbit/s (64 B MPS) | **High-Speed 480 Mbit/s (512 B MPS)** |
| SD bus | SDMMC @ 20 MHz | **SDIO 3.0 @ 40 MHz** |
| Console | shared PHY (mode toggle) | separate CH343P USB-UART |

## Build / flash

Detached crate (own empty `[workspace]`), RISC-V Tier-2 target, **official Rust
toolchain** — the ESP32-P4 is RISC-V, so no `esp`/Xtensa toolchain is involved
(unlike `esp32s3-pocket-dongle`). One-time setup:

```bash
rustup target add riscv32imafc-unknown-none-elf
rustup component add rust-src          # for `build-std = ["core"]`
```

Then:

```bash
cd examples/esp32p4-touch-lcd-35
cargo run --release               # builds, flashes via espflash, opens the monitor
```

`cargo build --release` alone produces
`target/riscv32imafc-unknown-none-elf/release/esp32p4-touch-lcd-35`.

Then, on the host, the device enumerates as an optical drive (`/dev/srX`):

```bash
sudo dd if=/dev/zero of=/dev/sr0 bs=1M count=20 oflag=direct status=progress
sudo dd if=/dev/sr0 of=/dev/null bs=1M count=20 iflag=direct status=progress
```

Live status is shown on the on-board ST7796 panel and logged over the CH343P
UART every 500 ms (`usb up rx=…kB/s tx=…kB/s`). The panel is the feedback path
that needs no cable:

```
ESP32-P4 DVD-RAM
SD: 14.8 GiB
USB:conn F0 R0 C0 D0
RX:4096K TX:12M
RX:123K/s TX:4567K/s
UPT: 0:00:07 cbw3 oth0
```

`USB:` shows the link plus the BOT shell diagnostics (`F` serve-loop restarts,
`R` USB bus resets, `C`/`D` bulk-IN calls / `Disabled`), and `cbw`/`oth` classify
command-phase reads by the `USBC` signature.

During startup the panel also paints `BOOT x/5` stage markers (LCD → SD → drive →
USB); the last one visible localises a hang (useful because the CH343P UART is
dead whenever the board is powered only through the OTG port).

### ST7796 bring-up notes

Three non-obvious details, all found on hardware:

1. **SPI mode 0**, not the vendor's `spi_mode = 3`. The vendor BSP's "3" does not
   correspond to esp-hal's `Mode::_3` for this panel — a per-mode uniform-colour
   sweep showed only mode 0 driving it (40 MHz is fine).
2. **The panel needs the vendor init sequence** (`esp_lcd_st7796`): the Sitronix
   extension unlock (`0xF0 0xC3` / `0xF0 0x96`) plus `C1=0x06` / `C5=0x18` /
   `COLMOD=0x05` and its gamma tables. mipidsi's generic ST7789 init (its built-in
   `ST7796` model) leaves the panel blank; `src/display.rs` supplies a custom
   `Model` with the vendor sequence.
3. **`embedded-graphics::Text::new` uses an *alphabetic* baseline** by default, so
   text drawn near `y = 0` renders above the top edge and wraps to the bottom of
   the panel. Anchor with `Baseline::Top` (done in `draw_line`).

Status text is inset 6 px from the left because the bezel physically covers ~4 px
of glass on each side.

## Throughput

Measured on the P4 (High-Speed link, `dd` with direct I/O):

| path | starting point | now |
|---|---|---|
| read (device → host) | 3.4 MB/s | **7.6–7.7 MB/s** |
| write (host → device) | 1.5 MB/s | **4.1–4.3 MB/s** |

Four limits stack up to produce the starting numbers — the one-packet-per-transfer USB
device driver, a read-ahead coordinate bug that read every chunk **twice**, a mis-aligned
SD DMA buffer that capped SD commands at 8 KiB, and the 3.3 V / 40 MHz SD bus ceiling.
Each is measured, explained and (where possible) fixed in
**[PERFORMANCE.md](PERFORMANCE.md)**; that file also documents the diagnostics the firmware
prints and the config knobs that matter.

What the fixes are, in one breath:

- **USB**: a vendored `embassy-usb-synopsys-otg` arms the bulk IN endpoint for a whole
  5-packet transfer instead of one packet at a time — USB IN ceiling **6.6 → 14.2 MB/s**
  (`[patch.crates-io]` + `OtgConfig::bulk_in_transfer_bytes`). Writes are still one packet
  per transfer; that is the remaining write-side limit.
- **Shell read-ahead**: `ScsiDevice::read_ahead_offset` (new, default `None`) tells the
  transport which backend address to pre-fetch, so the speculative read is actually used
  instead of being repeated serially — read **4.0 → 7.0 MB/s**.
- **SD**: the block batch is 64-byte aligned (the P4's cached internal RAM requires it, and
  esp-hal's 4-descriptor DMA ring otherwise overruns above 8 KiB), and the storage seam
  keeps a 16 KiB read-ahead window so the SD bus runs 32-block commands while the BOT shell
  still works in 8 KiB chunks (which the write path needs).
- **Panel**: `Display::show` clears only the text band. A full 320x480 clear is ~120 ms of
  blocking SPI and measurably starves the USB stack.

## Hardware (Waveshare ESP32-P4-WIFI6-Touch-LCD-3.5)

| Function | GPIO / pin | Notes |
|---|---|---|
| SD CLK / CMD | 43 / 44 | SDMMC slot 0, fixed IO_MUX pads |
| SD D0..D3 | 39 / 40 / 41 / 42 | 4-bit, SDIO 3.0 |
| SD power gate | 45 | P-MOSFET, default ON (leave low) |
| USB OTG HS | `USB_DM`/`USB_DP` | dedicated pins, Type-C, device-capable |
| UART0 (console) | 37 / 38 | CH343P USB-to-UART bridge |
| LCD (ST7796, SPI2) | MOSI 20, SCLK 21, MISO 22, CS 23, DC 26, RST 27, BL 28 | status panel (SPI **mode 0**, inverted, mirrored) |
| Touch (FT6336, I2C) | SDA 7, SCL 8, RST 29, INT 50 | **not used yet** |

The SD IO rail is powered by the on-chip LDO4 that the esp-hal `sdmmc` driver
brings up itself; no board-side power code is needed. The LCD backlight (GPIO28,
active high) is driven on by `src/display.rs`; the panel itself needs no extra
rail enable on this board.

## Not implemented (follow-ups)

- **Touch**: the FT6336 capacitive controller is not driven (the display is a
  plain status panel, no input).
- **Diagnostic bins**: the S3 example shipped `sdbench` (SD-only throughput) and
  `cdc` (USB bring-up isolation). Not ported yet.

## Caveats

- **Needs adequate USB power.** The LCD backlight, the SD card and the HS USB
  bursts together draw more than a weak host port can supply; on a marginal port
  the board browns out and *appears* not to boot (it starts only after a
  UART-triggered reset, once the rail is stable). Use a good port, a powered hub
  or a dedicated supply.
- **Silicon revision ≥ v3.0 required.** esp-hal 1.2.2 enforces a minimum chip
  revision and aborts at `init` on older ESP32-P4 parts (some early Waveshare P4
  boards are v1.3). Check the boot log / silkscreen before assuming a hang is a
  firmware bug.
- **40 MHz SD clock** is the P4 cap and the board is wired for SDIO 3.0, but
  4-bit signal integrity on the vendor pins is unverified here: if transfers
  corrupt, lower `SD_BUS_FREQ_HZ` in `src/sd.rs` (e.g. 20 MHz). `SdCard::freq()`
  reports the clock `sdio` actually negotiated.
- The HS USB path uses the same `embassy-usb-synopsys-otg` driver family as the
  S3 build; the ESP32-P4 HS *device* throughput should be re-measured on
  hardware (the S3 findings do not carry over — HS MPS is 512 B, not 64 B).
