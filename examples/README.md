# SnowSCSI example firmware

Bare-metal reference firmware that runs the `snowscsi` SCSI/MMC core on a
microcontroller. Each example is a **detached crate** (its own empty `[workspace]`
table), so `cargo build --workspace` at the repository root never tries to build
them; build them from their own directory with the toolchain noted below.

Both examples do the same job on different silicon: they present the board's
**on-board SD / microSD card as one whole raw block device** to a USB host, as a
**blank DVD-RAM (UDF-RW) optical drive** — PDT `0x05`, DVD-RAM profile — driven
by `snowscsi`. The device never writes file-system structures; the host owns the
filesystem and formats the medium (FORMAT UNIT + its own UDF `mkfs`).

## Examples

| Example | Device (chip) | Development board | Module |
|---|---|---|---|
| [`esp32p4-touch-lcd-35`](esp32p4-touch-lcd-35/) | **ESP32-P4** (RISC-V, dual-core) | **Waveshare ESP32-P4-WIFI6-Touch-LCD-3.5** | ESP32-P4 (silicon rev ≥ v3.0 required; measured on v3.2) |
| [`esp32s3-pocket-dongle`](esp32s3-pocket-dongle/) | **ESP32-S3** (Xtensa LX7, dual-core) | **Pocket-Dongle-S3** (AliExpress "ESP32-S3 0.96 LCD dongle", vendor repo [`ronenkr/Pocket-Dongle-S3`](https://github.com/ronenkr/Pocket-Dongle-S3)) | ESP32-S3 N16R8 (16 MB flash, 8 MB PSRAM, 512 KB SRAM) |

