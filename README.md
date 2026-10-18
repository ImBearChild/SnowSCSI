# SnowSCSI

**A `no_std`, zero-alloc SCSI target library for bare-metal embedded, which
also runs on Linux and over iSCSI.**

SnowSCSI exposes an embedded device's own storage (an SD card, flash, a RAM
region, or a filesystem) to a host as a standard SCSI device: a direct-access
block disk, a read-only CD/DVD-ROM, or a writable DVD-RAM optical drive. The
protocol core is written for bare metal first; the same devices run on Linux
without a separate implementation.

![no_std](https://img.shields.io/badge/no__std-ready-blue)
![zero-alloc](https://img.shields.io/badge/heap-none-brightgreen)
![rustc 1.87+](https://img.shields.io/badge/rust-1.87%2B-orange)
![license MIT OR Apache-2.0](https://img.shields.io/badge/license-MIT%20OR%20Apache--2.0-blue)

## Features

- **Embedded-first core.** The device, protocol and transport layers are
  `no_std` and zero-alloc: no heap, no async runtime, no OS, and no `unsafe`
  (`#![deny(unsafe_code)]`). A transport needs only a caller-provided work
  buffer.
- **Storage behind traits.** The stack is written against seams rather than
  concrete drivers. Implement `SeekableStorage` for an SD/flash/RAM backend or
  `FsStorage` for a filesystem such as LittleFS or FatFs, and the SCSI layers
  work unchanged.
- **SCSI command coverage.** SPC-4/SBC-3 block commands plus the MMC-6 optical
  surface: INQUIRY, MODE SENSE, REQUEST SENSE, READ TOC, GET CONFIGURATION,
  READ DISC INFORMATION, READ BUFFER CAPACITY, DVD physical format,
  prevent/allow removal, tray exchange, and pending Unit Attention.
- **One core, several transports.** The same devices run as bare-metal
  firmware, a Linux FunctionFS USB gadget, and an iSCSI target (RFC 3720). The
  transports are non-blocking state machines; only the platform shell differs.
- **Extensible devices.** `ScsiDevice` is the seam every transport drives.
  Wrapping a built-in device to add a vendor opcode is a small, documented
  change (see the wrapper example in the `ScsiDevice` docs).
- **Checked against real hosts.** The USB and iSCSI paths are exercised
  end-to-end by a Linux kernel initiator (`usb-storage` over `dummy_hcd`,
  ext4 format/mount/fsck; `iscsiadm`/`iscsi_tcp` loopback), and generated ISOs
  are cross-validated by `file`, `isoinfo`, `7z` and `bsdtar`.

## Quick start

```bash
cargo build --workspace
```

Serve a RAM disk over iSCSI and connect from a Linux initiator:

```bash
snowscsi serve --block ram=16M --iscsi 0.0.0.0:3260

# in another shell (or add `--iscsi auto` and let serve log in itself)
iscsiadm -m node -T iqn.1970-01.local.snowscsi:target -p 127.0.0.1:3260 --login
```

Serve as a Linux USB gadget. This needs root; `dummy_hcd` lets it run with no
USB hardware. The host kernel attaches `usb-storage` and creates `/dev/sdX`
(or `/dev/srX` for CD-ROM LUNs):

```bash
# a 16 MiB RAM disk as /dev/sdX
sudo snowscsi serve --usb --block ram=16M

# a read-only ISO as a USB CD-ROM
sudo snowscsi serve --usb --cdrom img=out.iso

# a live ISO9660 view of a directory, as a USB CD-ROM
sudo snowscsi serve --usb --cdrom live=./src_dir
```

`--iscsi` and `--usb` are mutually exclusive; exactly one transport is
required. `--block`/`--cdrom` are repeatable (multi-LUN), and the USB gadget
identity is set with `--vid` / `--pid` / `--serial`. Generate a standalone ISO
from a directory with:

```bash
snowscsi mkisofs src_dir out.iso --label MYDISC
```

## Embedded example

[`examples/esp32s3-pocket-dongle`](examples/esp32s3-pocket-dongle) is a
reference firmware: an ESP32-S3 presents its on-board SD card as a DVD-RAM USB
optical drive over USB-OTG, with an SPI status LCD and a BOOT-toggled
USB-Serial-JTAG debug console. It is a detached crate (not a workspace member)
built with the `esp` (Xtensa) toolchain:

```bash
cd examples/esp32s3-pocket-dongle
cargo +esp build --release   # .cargo/config.toml wires espflash as the runner
```

The firmware implements the storage seam over the SD driver and runs the USB
MSC core from `snowscsi::usb` in an embassy loop without a heap.

## Library usage

The SCSI emulation core is in the `snowscsi` crate. The default feature is just
`std`, so features are opted into explicitly:

```toml
# SCSI core only — embedded block device, no_std
snowscsi = { version = "0.2", default-features = false, features = ["scsi"] }

# USB MSC Bulk-Only Transport core (no platform I/O; drivers plug a BotIo/Gadget)
snowscsi = { version = "0.2", default-features = false, features = ["usb"] }

# SCSI + iSCSI over TCP (network block device)
snowscsi = { version = "0.2", default-features = false, features = ["std", "scsi", "iscsi"] }

# Live ISO9660 directory backend (CD-ROM)
snowscsi = { version = "0.2", default-features = false, features = ["std", "cdrom", "livefs"] }

# Full feature set (`log` / `defmt` select the logging backend instead)
snowscsi = { version = "0.2", features = ["std", "scsi", "iscsi", "usb", "cdrom", "livefs", "dvdram", "bundle"] }
```

A minimal embedded block device needs a backend and a work buffer:

```rust,ignore
use snowscsi::scsi::backend::RamBackend;
use snowscsi::scsi::block::BlockDevice;
use snowscsi::common::seekable_storage::SeekableStorage;
use snowscsi::MIN_DATA_LEN;

let mut media = [0u8; 64 * 1024];
let mut lun = BlockDevice::disk(&mut RamBackend::new(&mut media), 512)?;

let mut work = [0u8; MIN_DATA_LEN];
let cdb = [0x12, 0, 0, 0, 36, 0]; // INQUIRY
let _outcome = lun.do_cmd(&cdb, &mut work)?;
```

Both transports drive any `impl ScsiDevice` through
`poll::<…, D>(devs: &mut [D])`: a homogeneous array of one device type, or
`[&mut dyn ScsiDevice]` to mix them.

## Project status

- [x] `snowscsi` lib: SCSI core + block/CD-ROM devices (SPC/SBC/MMC) + iSCSI target + platform-agnostic USB MSC (BOT) core + blank (host-formatted) DVD-RAM media
- [x] `snowscsi-cli serve`: `--block` / `--cdrom` device planes + multi-LUN + graceful shutdown
- [x] iSCSI transport (TCP), including `--iscsi auto` open-iscsi loopback
- [x] USB Mass Storage transport (`serve --usb`, FunctionFS gadget on Linux): verified end-to-end against the real kernel (`dummy_hcd` + `usb-storage`, ext4 format/mount/fsck)
- [x] ISO9660 image generation (`mkisofs`): cross-validated by `file`, `isoinfo`, `7z`, `bsdtar`
- [x] Writable DVD-RAM (`--cdrom dvdram=`, feature `dvdram`): a blank random-writable medium that the *host* formats (FORMAT UNIT + its own UDF `mkfs`)
- [x] Embedded reference firmware (`examples/esp32s3-pocket-dongle`)

## Project structure

```
SnowSCSI/                          # cargo workspace (resolver = "2")
├── Cargo.toml                      # workspace members
├── snowscsi-common/                # storage seams + logging macros (always no_std)
├── snowscsi-iso9660/               # ISO9660/Joliet live-generation algorithms
├── snowscsi/                       # SCSI core + iSCSI + USB MSC + CD-ROM + DVD-RAM
│   └── src/{scsi, cdrom, iscsi, usb}
├── snowscsi-cli/                   # `snowscsi` binary (serve + mkisofs)
├── snowscsi-tests/                 # non-published test harness (integration + whitebox)
├── tools/                          # NOT a cargo member: ext-test/ + USB helpers
├── examples/esp32s3-pocket-dongle/ # ESP32-S3 firmware: SD card as a DVD-RAM USB drive
├── LICENSE-APACHE                  # Apache-2.0
└── LICENSE-MIT                     # MIT
```

## Testing

```bash
cargo test --workspace                 # in-process integration + libiscsi whitebox
python3 tools/ext-test/run.py          # black-box ISO cross-validation (no root)
sudo -E env PATH=$PATH python3 tools/ext-test/test_usb_loopback.py   # real kernel USB
sudo -E env PATH=$PATH python3 tools/ext-test/test_iscsi_loopback.py # real kernel iSCSI
```

The external suites drive the built binary as a black box against independent
tools and a real kernel initiator. See `HACKING.md` for the full checklist and
contributor workflow.

## Legacy C code

The original C implementation (CMake + Unity) is archived on the `legacy`
branch:

```bash
git checkout legacy
cmake -B build && cmake --build build
```

## License

Dual-licensed under either [Apache-2.0](LICENSE-APACHE) or [MIT](LICENSE-MIT),
at your option.
