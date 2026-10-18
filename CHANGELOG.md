# Changelog

All notable changes to this project are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.2.0] - 2026-10-18

### ⚠️ Breaking changes

- **scsi**: the data phase now yields an `Xfer`. `ScsiDevice::xfer_out`/`xfer_in`
  return `Xfer<'a>` (`Inline { len }` | `Store(StoreOp<'a>)`) instead of
  `XferOutcome`; `XferError` is removed and `XferOutcome` becomes
  `{ Ok, Error(StorageError) }`. Adds `sense_for_storage_error` and a default
  `next_store_op`.
- **scsi**: the USB BOT session is reworked to `Action`/`Event` + `poll`, with the
  shell loop moved into `usb::serve`. `BlockDevice` lost its backend generic,
  `CdMedia`/`Tray`/`CdromDrive` lost their lifetime, and transports now take
  `Luns`.
- **iscsi**: the session converges to `Action`/`Event` + `poll`.
  `IscsiSession::step` and `SessionStep`/`SessionEvent`/`StepResult` are removed;
  `poll` now takes an `Event` and returns an `Action`.
- **common**: `Fill` is pushed down to the storage seam via the new default
  methods `SeekableStorage::fill_at` and `WritableFlatData::fill_at`.
- **usb**: a `Short` Data-In shortfall now fails fast instead of degrading into a
  reset storm. `ServeError` gains a `PolicyNeedsStall` variant and
  `BotIo::can_stall_in` declares Bulk-In STALL capability.

### Added

- Async storage and USB IO seams (`async-io`) — model-agnostic, no runtime.
- `snowscsi` async facade features `async-io` and `embassy`, plus embassy-usb
  adapters.
- USB async serial `serve` shell; bulk IO overlapped with the storage plane;
  overlap coordinates on `Action`.
- `common`: an all-zero storage backend; a two-store op vocabulary
  (`StoreOp`/`StorePlane`/`FsPlane`).
- Wire-level golden baseline recorder with 18 scenario fixtures (tests).
- Examples: an ESP32-P4 touch-LCD-35 USB optical drive; the ESP32-S3 dongle on the
  async shell; ESP32-P4 microSD UHS-I SDR25/SDR50 tuning.

### Changed

- README rewritten as the SnowSCSI project overview.
- `hex_of` moved to `scsi::util`; rustfmt applied to the async seams;
  planning-document references dropped from source comments.

### Fixed

- **usb**: dispatch a received CBW across a control reset.
- **usb**: emit the read-ahead coordinate in backend address space.
- **usb**: bound the write-ahead receive by its latched budget.
- **usb**: `RecvHalf` receives consolidated (reset deviation noted).
- **cdrom**: allow `large_enum_variant` on the media slot.
- **examples**: run the P4 UHS-I 1.8 V switch through the SDMMC handshake;
  sequence the CMD11 handshake the way esp-idf does; pin the microSD clock source
  (the SDIO PLL breaks writes); use drive clock edge 0; keep the microSD at
  40 MHz UHS-I SDR25.

## [0.1.0] - 2026-10-13

Initial release: the workspace and crates are renamed to `snowscsi`
(`snowscsi-common`, `snowscsi-iso9660`, `snowscsi`, `snowscsi-cli`,
`snowscsi-tests`).

[Unreleased]: https://github.com/ImBearChild/SnowSCSI/compare/v0.2.0...HEAD
[0.2.0]: https://github.com/ImBearChild/SnowSCSI/compare/v0.1.0...v0.2.0
[0.1.0]: https://github.com/ImBearChild/SnowSCSI/releases/tag/v0.1.0
