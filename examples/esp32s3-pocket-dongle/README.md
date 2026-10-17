# esp32s3-pocket-dongle

Presents the on-board SD card of a **Pocket-Dongle-S3** (an AliExpress
"ESP32-S3 0.96 LCD dongle") as one whole raw block device to a USB host, as a
**UDF-RW (DVD-RAM) optical device** driven by `snowscsi`.


## Device / board

| | |
|---|---|
| **Device (chip)** | **ESP32-S3** — Xtensa LX7 dual-core, `xtensa-esp32s3-none-elf` |
| **Development board** | **Pocket-Dongle-S3** — AliExpress "ESP32-S3 0.96 LCD dongle", vendor repo [`ronenkr/Pocket-Dongle-S3`](https://github.com/ronenkr/Pocket-Dongle-S3) |
| **Module** | **ESP32-S3 N16R8** — 16 MB flash, 8 MB PSRAM, 512 KB SRAM |
| **USB** | chip-internal Full-Speed/Low-Speed PHY on GPIO19/20, **shared** by USB-OTG and USB-Serial-JTAG |
| **Storage** | on-board microSD, SDMMC 4-bit |
| **Status panel** | ST7735S 0.96" 160×80 (SPI) |
| **Buttons** | BOOT on GPIO0 |

The panel's vendor build flags (`ST7735_DRIVER`, `ST7735_GREENTAB160x80`,
`TFT_RGB_ORDER=TFT_BGR`, 80×160 @ 40 MHz) are reproduced in `src/display.rs`.

## Build / flash

Detached crate (own empty `[workspace]`), **Xtensa** target, **`esp`
toolchain** — unlike the P4 example, this one needs Espressif's Xtensa LLVM +
GCC, installed by `espup`. One-time setup:

```bash
cargo install espup --locked
espup install -t esp32s3          # esp fork toolchain + Xtensa LLVM + GCC + rust-src
source ~/export-esp.sh            # add to your shell profile
cargo install espflash --locked   # the `.cargo/config.toml` runner
```

Then (the crate's `.cargo/config.toml` selects the target and wires `espflash`
as the runner):

```bash
cd examples/esp32s3-pocket-dongle
cargo +esp run --release          # builds, flashes via espflash, opens the monitor
```

`cargo +esp build --release` alone produces
`target/xtensa-esp32s3-none-elf/release/esp32s3-pocket-dongle`. `espflash` resets
the chip into the ROM download interface first, so flashing works even though the
product firmware normally owns the USB PHY.

Then, on the host, the device enumerates as an optical drive (`/dev/srX`):

```bash
sudo dd if=/dev/zero of=/dev/sr0 bs=1M count=20 oflag=direct status=progress
sudo dd if=/dev/sr0 of=/dev/null bs=1M count=20 iflag=direct status=progress
```

## Runtime behaviour

Boots straight into **DVDRAM**: the USB-OTG gadget runs the Mass Storage
Bulk-Only Transport class (`src/msc.rs`) over the internal Full-Speed PHY, and
the SD card is built once into a persistent drive (`src/drive.rs`) — the single
LUN (`Get Max LUN` = 0).

Pressing **BOOT** toggles between the two owners of the single internal USB PHY:

- **DVDRAM** (product mode) — USB-OTG drives the DVD-RAM gadget;
- **DEBUG** — the PHY is handed to the chip's **USB-Serial-JTAG** controller, so
  `esptool`/`espflash` can talk to the ROM download/console interface *without
  re-plugging*.

Each toggle tears the gadget down, re-muxes the PHY (`src/usb_mode.rs`), and
rebuilds. Because the PHY is shared, defmt logging is only emitted while the PHY
is on USB-Serial-JTAG (its FIFO cannot be drained on OTG); in DVDRAM mode the
**LCD is the only on-device feedback**. The mux is driven through the PAC
registers directly (esp-hal 1.2.2 has no supported API for it), using only safe
`set_bit`/`clear_bit` accessors — no `unsafe`.

The LCD (`src/display.rs`) refreshes every 500 ms:

```
MODE: DVDRAM
SD: 14.8 GiB
USB:conn F0 R0 C0 D0
RX:4096K TX:12M
RX:123K/s TX:4567K/s
UPT: 0:00:07 cbw3 oth0
```

`USB:` shows the link plus the BOT shell diagnostics (`F` serve-loop restarts,
`R` USB bus resets, `C`/`D` bulk-IN calls / `Disabled`), and `cbw`/`oth` classify
command-phase reads by the `USBC` signature. The uptime line only advances while
the refresh loop runs, so a frozen clock is the "MCU hung or panicked" signal.

## Hardware (Pocket-Dongle-S3)

| Function | GPIO / pin | Notes |
|---|---|---|
| SD CLK / CMD | 17 / 18 | SDMMC slot 0, 4-bit @ 20 MHz |
| SD D0..D3 | 16 / 15 / 48 / 47 | 4-bit |
| LCD (ST7735S, SPI2) | SCK 10, MOSI 11, CS 12, DC 13, RST 14 | status panel; backlight not wired (assumed always-on) |
| BOOT | 0 | active-low, pulled up; DVDRAM ↔ DEBUG toggle |
| USB | internal PHY, `GPIO19`/`GPIO20` | shared: USB-OTG ↔ USB-Serial-JTAG |

`SD_BUS_FREQ_HZ` in `src/sd.rs` is 20 MHz (the SD default-speed rate); the host
supports up to 40 MHz but the vendor pins' 4-bit signal integrity is only
verified at 20 MHz here.

## Throughput

Measured over USB Full-Speed with `dd` on Linux (and a Windows cross-check):

| path | reading |
|---|---|
| read (device → host) | **~1.1 MB/s** — the USB 1.1 Full-Speed ceiling |
| write (host → device) | **~450–710 KB/s** |

Read is pinned by the Full-Speed link itself (FS bulk max ≈ 1.19 MB/s). Write is
USB-OUT bound as well. The SD card is *not* the limit — the same card sustains
~7 MB/s read / 3.4–4.2 MB/s write over its bus.
