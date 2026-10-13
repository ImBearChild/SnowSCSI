# SnowDrive

SCSI device emulation toolkit — Rust workspace (cargo).

## Overview

SnowDrive emulates SCSI storage devices (block devices, CD/DVD-ROM, writable
DVD-RAM) and exposes them to a host machine over iSCSI (TCP) or USB Mass
Storage (Bulk-Only Transport).

The device and transport layers are platform-agnostic, so the same core backs a
Linux FunctionFS gadget, an iSCSI target, and bare-metal firmware. See
[`examples/esp32s3-pocket-dongle`](examples/esp32s3-pocket-dongle) — an
ESP32-S3 that presents its SD card as a UDF-RW USB optical drive. The library
crates are `no_std` and zero-alloc (no heap, no async runtime).

| Component | Crate | Description |
|-----------|-------|-------------|
| **Common** | `snowdrive-common` | Zero-alloc storage seams (`FlatData` / `WritableFlatData` / `SeekableStorage`, `FsStorage`) + unified logging macros |
| **Disc** | `snowdrive-disc` | ISO9660 + Joliet live-generation algorithms (`live.rs`) |
| **SCSI core** | `snowdrive-scsi` | SCSI emulation (SBC/SPC/MMC), block/CD-ROM devices, iSCSI target, platform-agnostic USB MSC (BOT) core, blank (host-formatted) DVD-RAM media |
| **CLI** | `snowdrive-cli` | `snowdrive serve` runs the iSCSI target or the USB MSC gadget; `snowdrive mkisofs` generates an ISO image from a directory |

## Build

```bash
cargo build --workspace
```

## Test

```bash
cargo test --workspace
```

## Usage

### Block device (iSCSI)

```bash
snowdrive serve --block img=disk.img --iscsi 0.0.0.0:3260
```

### Multi-LUN

```bash
snowdrive serve --block img=disk.img --block ram=16M --iscsi 0.0.0.0:3260
```

### USB Mass Storage gadget (Linux, `dummy_hcd` or real UDC)

`serve --usb` binds a FunctionFS MSC gadget to a UDC; the host kernel's
`usb-storage` driver attaches and creates `/dev/sdX` (or `/dev/srX` for
CD-ROM LUNs). The UDC is chosen by the `--usb` selector (`auto` default,
`dummy`, a UDC name, or a driver prefix). Requires root (gadget + configfs +
aio) — with `dummy_hcd` loaded this needs no USB hardware:

```bash
# as root: expose a 16 MiB RAM disk as /dev/sdX
sudo snowdrive serve --usb --block ram=16M

# expose a read-only ISO as a USB CD-ROM
sudo snowdrive serve --usb --cdrom img=out.iso
```

`--iscsi` and `--usb` are mutually exclusive; exactly one transport is
required. `--vid` / `--pid` / `--serial` (defaults `0x1209:0x0001` /
"SNOWSCSI") override the gadget identity.

### Embedded firmware (ESP32-S3)

[`examples/esp32s3-pocket-dongle`](examples/esp32s3-pocket-dongle) runs the SCSI
core on bare metal: an ESP32-S3 turns its on-board SD card into a **UDF-RW USB
optical drive** over USB-OTG (Full Speed), with a small SPI status LCD and a
BOOT-toggled USB-Serial-JTAG debug console. It is a detached crate (not a
workspace member) built with the `esp` (Xtensa) toolchain:

```bash
cd examples/esp32s3-pocket-dongle
cargo +esp build --release   # .cargo/config.toml wires espflash as the runner
```

### ISO image generation

```bash
snowdrive mkisofs src_dir out.iso --label MYDISC
```

### Connect from host

```bash
# Linux (open-iscsi)
iscsiadm -m node -T iqn.1970-01.local.snowscsi:target -p 127.0.0.1:3260 --login
```

(Or pass `--iscsi auto` to `serve` and let it perform the open-iscsi
login/logout itself.)

## Project Status

- [x] `snowdrive-scsi` lib: SCSI core + block/CD-ROM devices (SBC/SPC/MMC) + iSCSI target + platform-agnostic USB MSC (BOT) core + blank (host-formatted) DVD-RAM media
- [x] `snowdrive-cli serve`: `--block` / `--cdrom` device planes + multi-LUN + graceful shutdown
- [x] iSCSI transport (TCP), including `--iscsi auto` open-iscsi loopback
- [x] USB Mass Storage transport (`serve --usb`, FunctionFS gadget on Linux): verified end-to-end against the real kernel (`dummy_hcd` + `usb-storage`, ext4 format/mount/fsck)
- [x] ISO9660 image generation (`mkisofs`): cross-validated by `file`, `isoinfo`, `7z`, `bsdtar`
- [x] Writable DVD-RAM (`--cdrom dvdram=`, feature `dvdram`): a blank random-writable medium that the *host* formats (FORMAT UNIT + its own UDF `mkfs`)
- [x] Embedded reference firmware (`examples/esp32s3-pocket-dongle`): an ESP32-S3 exposes an SD card as a UDF-RW USB optical drive (`no_std` + embassy)

## Project Structure

```
SnowDrive/                          # cargo workspace (resolver = "2")
├── Cargo.toml                      # workspace members
├── snowdrive-common/               # storage seams + logging macros
├── snowdrive-disc/                 # ISO9660/Joliet live-generation algorithms
├── snowdrive-scsi/                 # SCSI core + iSCSI + USB MSC + CD-ROM + UDF
│   └── src/{scsi, cdrom, iscsi, usb}
├── snowdrive-cli/                  # `snowdrive` binary (serve + mkisofs)
├── tests/                          # snowdrive-tests: non-published test harness (integration + whitebox)
├── tools/                          # NOT a cargo member: ext-test/, libvirt-usb-helper, usbms-pcap.py
├── examples/esp32s3-pocket-dongle/ # ESP32-S3 firmware: SD card as a UDF-RW USB drive (detached crate)
├── LICENSE-APACHE                  # Apache-2.0
└── LICENSE-MIT                    # MIT
```

## Library Usage

The SCSI emulation core lives in the `snowdrive-scsi` crate; pick only the
features you need:

```toml
# SCSI core only (embedded block device)
snowdrive-scsi = { version = "0.1", default-features = false, features = ["scsi"] }

# SCSI + iSCSI over TCP (network block device)
snowdrive-scsi = { version = "0.1", default-features = false, features = ["std", "scsi", "iscsi"] }

# USB MSC Bulk-Only Transport core (no platform I/O; drivers plug a BotIo/Gadget)
snowdrive-scsi = { version = "0.1", default-features = false, features = ["usb"] }

# Live ISO9660 directory backend (CD-ROM)
snowdrive-scsi = { version = "0.1", default-features = false, features = ["std", "cdrom", "livefs"] }

# Full feature set (note: `snowdrive-scsi` default is just `std`; opt in explicitly;
# `log` / `defmt` select the logging backend instead)
snowdrive-scsi = { version = "0.1", features = ["std", "scsi", "iscsi", "usb", "cdrom", "livefs", "dvdram", "bundle"] }
```

## Legacy C Code

The original C implementation (CMake + Unity) is archived on the `legacy` branch:

```bash
git checkout legacy
cmake -B build && cmake --build build
```

## License

Dual-licensed under either [Apache-2.0](LICENSE-APACHE) or [MIT](LICENSE-MIT), at your option.
