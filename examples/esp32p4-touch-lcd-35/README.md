# esp32p4-touch-lcd-35

Presents the on-board microSD card of a **Waveshare ESP32-P4-WIFI6-Touch-LCD-3.5**
as one whole raw block device to a USB host, as a **UDF-RW (DVD-RAM) optical
device** driven by `snowscsi`.

## Device / board

| | |
|---|---|
| **Device (chip)** | **ESP32-P4** — RISC-V, dual-core, `riscv32imafc-unknown-none-elf` (silicon rev ≥ v3.0 required; measured on v3.2) |
| **Development board** | **Waveshare ESP32-P4-WIFI6-Touch-LCD-3.5** |
| **USB** | USB 2.0 **High-Speed** OTG (480 Mbit/s, internal UTMI PHY, 512 B MPS) |
| **Storage** | on-board microSD, SDIO 3.0 4-bit @ 40 MHz |
| **Status panel** | ST7796 3.5" 320×480 (SPI) |
| **Console** | separate CH343P USB-UART bridge (independent of the OTG port) |

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

The crate is checked in-tree with `cargo +nightly check` from this directory
(the RISC-V target is installed; no `esp` toolchain is involved on the P4).

### Firmware layout

The firmware builds its SCSI target from the same core seams as
`snowscsi-cli` — there is no `AsyncLuns`/`ScsiDevice` device shell:

- `src/drive.rs` — the single LUN as
  `LuImpl<Spc<MmcDrive<DvdRamMedium>>, u32>`. The blank DVD-RAM's geometry
  comes from the SD card's byte capacity; the host formats it.
- `src/store.rs` — `SdStore` + `sd_task`: a native-async storage pair over the
  library's `SlotPool`. The BOT side is the `Storage + AsyncWake` handle; the
  worker future awaits the card's `AsyncFlatData`/`AsyncWritableFlatData`
  transfers and posts the completion. One staging buffer (one bank) travels
  store → job → worker → done, so a read is copied once into the caller's bank
  and a write once out of it. `Backing` selects the plane: `Sd` (plaintext),
  `SdCipher` (the same card behind hardware AES-256-CTR) or `Zero` (the
  `ZERO_BACKEND` measurement plane, never encrypted, which completes without
  awaiting).
- `src/aes.rs` — `P4Aes`: the AES-DMA engine as a `BlockCipher16` + `CtrAccel`
  (see [Encryption](#encryption-hardware-aes-256-ctr) below).
- `src/main.rs` — one `Target` over `[&mut dyn Lu<Pair = DvdRamPair>; 1]`, the
  card backing and the staging buffer, all threaded into the gadget.
- `src/msc.rs` — the BOT restart loop around `BotSession::poll(Event::Reset,
  work, scratch, target, storage)` and
  `usb::serve::serve_async(..., target, storage, stop)`.
- `gadget()` joins four futures: the USB stack, the BOT loop, `store::sd_task`
  and the LCD refresh (no spawned task, no `'static` bound).

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

## Encryption (hardware AES-256-CTR)

The SD plane can be served **encrypted** with the ESP32-P4's AES accelerator.
It is off by default: `CIPHER_KEY` in `src/main.rs` is `None`, and the card is
served byte-for-byte as stored.

```rust
/// Replace with the key/nonce from the host-side `image.enc.SNOWBUNDLE`.
/// `None` serves the card plaintext (the default).
const CIPHER_KEY: Option<([u8; 32], [u8; 8])> = None;
```

Setting it to `Some((key, nonce))` switches the backing to
`store::Backing::SdCipher`, which wraps the card in
`common::cipher::AsyncCipherPlane` exactly the way the CLI serves an encrypted
image/bundle LUN. The cipher layer is length-preserving: no header, trailer or
reserved sector is added, and the medium's geometry is unchanged.

### Where the key and nonce come from

This firmware serves the card's **raw bytes**. The SD card must therefore
contain a raw ciphertext image, not a bundle directory: a `snowscsi` flat or
CD-R bundle (`bundle-create`) is a directory/chunk layout that only the CLI
knows how to interpret, so it is **not usable** by this firmware.

Encrypt a plaintext image with a raw-key manifest and write the ciphertext to
the card as-is:

```bash
snowscsi crypt --cipher aes-ctr --key-file key.bin image.img image.enc
sudo dd if=image.enc of=/dev/sdX bs=1M oflag=direct status=progress
```

`snowscsi crypt` writes the sidecar `image.enc.SNOWBUNDLE` next to the output.
It is plain text: its `nonce = <16 hex digits>` line is the 8-byte nonce, and
`key.bin` (32 raw bytes, `kdf = none`) is the key. Copy both values into
`CIPHER_KEY`. The sidecar is host-side metadata and is not needed on the card;
without it the key/nonce cannot be recovered. A password-based sidecar
(`--password-file`) records a salt and iteration count instead of a raw key, so
it cannot fill `CIPHER_KEY` directly — use `--key-file` for this firmware.

`const CIPHER_KEY` puts the key in the firmware image: the bytes are linked
into `.rodata` (and copied into ordinary RAM by `P4Aes`), visible in the flashed
ESP32-P4 image and in a RAM dump. There is no zeroize; protect the flash and
do not treat this constant as a secret store.

The counter block for absolute byte offset `off` is
`nonce || BE64(off / 16)`, and the counter increments big-endian over all 128
bits. That is the same layout `AesCtr` uses everywhere in the tree, so a host
that knows the key/nonce sees the expected bytes.

**Never reuse a `(key, nonce)` pair for two different images.** CTR is a stream
cipher: repeating a keystream leaks the XOR of the two plaintexts. There is also
**no authentication** — a wrong key/nonce or a modified ciphertext simply
decrypts to garbage, with no error reported.

### Hardware path and caveats

- The engine is `esp_hal::aes::Aes::new(AES).with_dma(DMA_AXI_CH0)`. On the
  P4 the AES peripheral is connected to the **AXI GDMA** engine; the AHB
  `DMA_CH0` cannot serve it.
- TX and RX use two **statically allocated** DMA buffers (`dma_tx_buffer!` /
  `dma_rx_buffer!`, `AES_BUF` = 2 KiB each, `.bss`). The statics are linked
  even when `CIPHER_KEY = None`, so disabling encryption saves AES work, not
  the 4 KiB. They travel through `AesDma::process` → `AesTransfer::wait()` and
  are put back with `Option` take/restore, so a DMA error never panics and
  never leaves the driver partially moved; setup errors are returned as
  `Result`.
- The hardware CTR mode is **INC_32**, not INC_128: vendored esp-hal clears
  `inc_sel` for CTR, so only the low 32 counter bits carry inside the
  peripheral. `ctr_xor_aligned` caps every hardware run at the next 32-bit
  boundary and advances the full 128-bit counter itself.
- `wait()` is a **busy-wait poll loop** on the peripheral status register, but
  it is bounded: the engine polls `is_done()` with a 100 ms deadline and then
  requires the RX byte count to match. A transfer that times out is dropped,
  the primitive is poisoned, and every later operation returns a backend
  error — a stuck peripheral becomes I/O errors instead of a hung executor.
  `process` resets the AES peripheral on every call, and the firmware is
  single-threaded, so this is a short block of CPU inside the storage worker,
  not a lost wakeup; a larger chunk size amortises it (see
  `CIPHER_SCRATCH` in `src/store.rs`).
- Boot runs a **known-answer self-test** (`P4Aes::self_test`) against the NIST
  SP 800-38A F.5.5 AES-256-CTR keystream, the `nonce || BE64(1)` counter block,
  the composed `AesCtr` path at byte offset 17 (head + DMA middle + tail), a
  four-block vector crossing the low-32-bit counter wrap, and an
  `AES_BUF + 16` run (129 blocks, one wrap) checked at the wrap-adjacent
  blocks and the last block. A failure logs `AES hardware KAT: FAIL` /
  `AES hardware self-test FAILED` and parks the firmware at `BOOT FAIL AES`
  instead of enumerating a card that would decrypt to garbage.
- `XorMix` is **not encryption**: it is a fixed byte pattern XOR that exists
  only to exercise the cipher plumbing. Do not use it for confidentiality.

The all-zero measurement plane (`ZERO_BACKEND = true`) is never encrypted — it
is a measurement of the USB/BOT path.

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
