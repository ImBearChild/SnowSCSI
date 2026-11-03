# Changelog

All notable changes to this project are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### ⚠️ Breaking changes

- **core**: transport loops return `Result<ServeExit, _>`; `Flow` replaces the
  `&AtomicBool` stop flag on USB; `Target::settle_transport_end` is replaced by
  `link_lost`; `RunEnd::TransportEnded` is removed.
- **core**: `Device` gains defaulted `admits_without_medium`; `Lu` gains
  defaulted `take_eject_request`; `MmcDrive::empty` now takes `MmcCaps`.
- **block**: `BlockAttrs` gains `removable`; struct literals must add the
  field (use `BlockAttrs::new(..)` and `with_removable()` instead).
- **mmc**: `MmcOp::Close` carries the close function and `MmcOp::ReserveTrack`
  is added; `MmcAttrs` gains `profile`/`current_features`; `DiscInfo` gains the
  recordable-media fields. The default Hyper-Multi drive now lists the CD-R
  profile (`0x09`) in its profile list.

### Added

- **mmc**: recordable-medium vocabulary — `TrackStatus`, `TrackInfo`,
  `TrackInfoRequest`, and the defaulted `MmcMedium::track_info`; the
  `cdr-bundle` feature gate for a sequential CD-R medium.
- **mmc**: `CdrBundleMedium` (`cdr-bundle`) — an in-memory sequential
  write-once CD-R medium model over per-track storage resources: implicit and
  reserved tracks, NWA-ordered writes, track/session close and finalize,
  zero-filled pre-gap/padding/unwritten reads, and `SYNCHRONIZE CACHE` closing
  the open track. This is medium behaviour only; the MMC drive still does not
  expose RESERVE TRACK or the close functions. `TrackInfo::start_lba` and the
  `DiscInfo` lead-in/lead-out are now signed so the CD lead-in address is
  representable.
- **core**: `Flow`/`ServeExit` and a target that outlives the transport link
  (host eject hands the medium back through `ResourcesReady`).
- **mmc**: `MmcCaps` (drive capabilities are LU state; the default `MmcDrive`
  is a Hyper-Multi recorder) and an empty tray that still answers MODE
  SENSE/GET CONFIGURATION; `MmcDrive::empty(caps)` and
  `LuImpl::empty(device)`.
- **core**: `Spc::with_identity` for per-LU INQUIRY identity strings.
- **cli**: `--cdrom empty` serves an enumerated drive with no medium.
- **block**: removable block media — `BlockAttrs::with_removable()` reports
  INQUIRY RMB=1 and lets a host START STOP UNIT eject the pair; the LUN stays
  enumerated as empty (`3A/00`) and the application installs a new pair at the
  same LUN and raises `UaClass::MediumChanged`.
- **cli**: `--block img=<file>,removable` USB card-reader demo (one removable
  slot, `profile=block`, `img=` only, not with `--banks dual`): eject drops
  the plane and a background watcher installs a stable replacement file.

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
