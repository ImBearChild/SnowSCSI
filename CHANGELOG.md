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
- **mmc**: `MmcOp` gains `Blank { blanking, immediate }` (exhaustive matches
  must handle it) and `MmcMedium` gains a defaulted `blank_supported`. The
  default Hyper-Multi drive now also lists the CD-RW profile (`0x0A`).
- **mmc**: the `cdr-bundle` TOC body gains `disc_type = cdrw` (the existing
  `disc_type = cdr` still loads unchanged); `CdrBundleMedium` gains
  `with_disc`/`blank_disc`/`kind` and `DiscKind`, and the CLI `medium=` option
  accepts `cdrw74|cdrw80|cdrw90|cdrw99`.
- **mmc**: `TocError` gains `WriteProtected`; exhaustive matches must handle it.
- **mmc**: the `cdr-bundle` capacity presets now report the real media lead-out
  (`minutes * 60 * 75 - 151`: 74 → 332 849, 80 → 359 849, 90 → 404 849,
  99 → 445 349 sectors instead of 333 000/360 000/405 000/445 500), so the
  addressable extent of a preset disc shrinks by 151 blocks. The 90- and
  99-minute presets report a lead-out above MMC's recommended maximum of
  `79:59:74`, like real high-capacity media; their `A1` capacity-extension
  encoding is not modeled.
- **mmc**: `DiscInfo::last_possible_lead_out` of a blank/appendable `cdr-bundle`
  disc is the medium capacity (the ATIP lead-out), not `capacity - 2`.
  READ CAPACITY reports `last_possible_lead_out - 1` (the ATIP extent minus
  one) whenever the write-once disc is not finalized, so a reserved-only or
  partially burned disc keeps the full device size; a finalized disc reports
  the last recorded LBA.

### Added

- **core**: `MmcDrive::companion_issues()` and `BlockDevice::companion_issues()`
  count the prefetches issued *together with* a data-in send. `prefetch_issues`
  also counts the serial single-bank read-ahead steps, so it cannot prove that
  a read overlaps the wire; `companion_issues` can (a single-bank caller always
  reports zero).
- **core**: the send after a standalone prefetch now carries the next
  read-ahead whenever a second caller bank exists (`FlatCdMedium`,
  `DvdRamMedium`, `VendorMedium`, `BlockDevice`). A command that fell back to
  the serial read-ahead no longer stays serial for the rest of the transfer.
- **iscsi**: blocking `transport::serve_with_release` adds an eject callback
  that receives a host handback's `take_rt` result before the pair is dropped.
  The CLI uses it for `--wire blocking` (both inline and `--banks dual`), so an
  ejected `--cdrom bundle=` LUN snapshots its TOC like the USB and async iSCSI
  paths; none of the generic storage seams can pre-flush track data, so a
  clean `CLOSE`/`SYNCHRONIZE CACHE` is still required for durability. `serve`
  remains a thin wrapper with a no-op callback.
- **mmc**: the drive now distinguishes unsupported opcodes from bad CDB
  fields: READ SUB-CHANNEL (`0x42`), READ HEADER (`0x44`) and every unknown
  opcode answer ILLEGAL REQUEST / INVALID COMMAND OPERATION CODE (`20/00`);
  SEND CUE SHEET (`0x5D`, SAO only) answers ILLEGAL REQUEST / COMMAND SEQUENCE
  ERROR (`2C/00`); READ DISC STRUCTURE (`0xAD`, DVD/BD only) stays ILLEGAL
  REQUEST / INVALID FIELD IN CDB (`24/00`).
- **mmc**: CD-DA audio tracks for the persistent `cdr-bundle` medium.
  Write Parameters page 0x05 now parses Track Mode 0 + Data Block Type 0 as
  2352-byte audio alongside Track Mode 4 + DBT 8/10 as 2048-byte data; all
  other Track Mode/DBT combinations are newly rejected with `24/00` (including
  pre-emphasised Track Mode 1 and copy-controlled Track Mode 2, which the
  control nibble does not model). MODE SENSE reports the current mode and the
  selection is cleared on medium install. An audio track stores 2352 bytes
  per logical block in `track_<n>.bin` while capacity, LBA/NWA, track length
  and the TOC stay in 2048-byte blocks. WRITE(10) in audio mode uses
  `MmcOp::WriteSectors { kind: Audio2352 }` and validates the Data-Out length
  against the selected block size (`24/00` on a mismatch); READ CD CD-DA (and
  all-types expected sector type, resolved from the starting track) reads the
  audio back, while READ(10) (and a data READ CD) over an audio track is
  `05/64/00`. A read may not span differently sized tracks, gaps still
  zero-fill, and mixed-mode discs plus close/finalize/persist/restore keep
  each track's kind and payload. Test Write simulates the audio byte count
  without recording.
- **mmc**: multi-session CD-R/CD-RW for the persistent `cdr-bundle` medium.
  Write Parameters page 0x05 byte 3 bits 7-6 is parsed (`00b`/`01b` accepted
  as finalize-compatible, `11b` allows another session, `10b` → `24/00`), and
  Data Block Type 8 (Mode 1) and 10 (Mode 2 Form 1, used by
  `wodim -multi -tao`) are both accepted as 2048-byte user blocks. The
  field is forwarded through a new defaulted `MmcMedium::set_multi_session`,
  reflected by MODE SENSE and cleared on medium install. `CLOSE TRACK/SESSION 010b`
  with `11b` closes the open track and the session but leaves the disc
  Appendable; `00b`/`01b` finalizes as before. The next session's lead-in
  starts at the previous lead-out, its first track preamble at
  `lead-in + 4500` and its user data 150 blocks later (`READ TRACK
  INFORMATION 0xFF` reports that NWA). READ TOC formats 0/1/2 describe the
  last complete session even while a later session is open; format 2 uses
  the 11-byte MMC-6 Table 483 descriptors with B0 at the next program area
  while appendable and at the lead-out once finalized, and READ DISC
  INFORMATION counts complete sessions plus an open one and reports the last
  closed session's lead-out as the next lead-in. A restored TOC keeps the
  disc appendable for the next session. Tests cover close/append/third
  session/finalize, the layout, TOC/DISC INFO reporting, mode-page
  round-trip and a CLI `set_multi_session` forward.
- **mmc**: CD-RW media for the persistent `cdr-bundle` — `DiscKind` is stored
  in the TOC (`disc_type = cdr`/`cdrw`, the old body still loads), the medium
  reports `MmcWriteMode::Rewritable` + profile `0x0A`, DISC INFORMATION sets
  the Erasable bit, ATIP reports disc type 1, and GET CONFIGURATION lists
  `0x0A` as Current. BLANK all/minimal resets an (even finalized) CD-RW to
  Blank and saves a fresh TOC slot without zero-filling or touching track
  payload, so the next TAO burn starts at LBA 0; a CD-R answers `24/00` and a
  read-only recovery answers `07/27`. READ HEADER (`0x44`) stays unimplemented
  (MMC-6 no longer defines it; it is packet-writing vocabulary). Recordable-CD
  behavior is selected by profile (`0x09`/`0x0A`), so CD-RW also gets the TAO
  Write Parameters page, Test Write, recordable track encoding, and ATIP
  extent capacity; FORMAT UNIT is `24/00` on both kinds.
- **mmc**: a blank write-once CD reports its ATIP extent in READ CAPACITY,
  so the host sizes the block device before the first session; READ TOC
  formats 0-2 stay `24h/00` until a session completes (format 4 is independent
  of session state). An unfinalized disc keeps reporting that extent after a
  track is reserved or partially burned, so a mid-burn re-probe cannot shrink
  the block device; only a finalized disc reports the recorded last LBA.
- **mmc**: READ TOC format 4 (ATIP) on a `cdr-bundle` CD-R — the 28-byte block
  (ATIP Data Length 26 plus the 24-byte descriptor, no optional S4 values) with
  binary M/S/F lead-in/lead-out times, so `wodim -atip`, `cdrecord -atip` and
  `cd-info` work on a blank, appendable or finalized disc. `AtipInfo` and the
  defaulted `MmcMedium::atip` carry the descriptor; a medium with no ATIP
  (stamped CD, DVD) answers `ILLEGAL REQUEST / INVALID FIELD IN CDB`. The
  descriptor's lead-out equals DISC INFORMATION's last possible lead-out until
  the disc is finalized (a finalized disc reports `FF`).
- **mmc**: recordable-medium vocabulary — `TrackStatus`, `TrackInfo`,
  `TrackInfoRequest`, and the defaulted `MmcMedium::track_info`; the
  `cdr-bundle` feature gate for a sequential CD-R medium.
- **mmc**: `CdrBundleMedium` (`cdr-bundle`) — a sequential write-once CD-R
  medium model over per-track storage resources: implicit and
  reserved tracks, NWA-ordered writes, track/session close and finalize,
  zero-filled pre-gap/padding/unwritten reads, and `SYNCHRONIZE CACHE` closing
  the open track. This is medium behaviour only; the MMC drive routes the
  close functions and descriptor commands to it. `TrackInfo::start_lba` and the
  `DiscInfo` lead-in/lead-out are now signed so the CD lead-in address is
  representable.
- **mmc**: `MmcDrive` now serves a CD-R through `CdrBundleMedium`: FORMAT
  UNIT/BLANK reject write-once media, CLOSE TRACK SESSION routes close
  functions 001b/010b to the medium, READ DISC/TRACK INFORMATION encode the
  recordable disc and track state (MMC-6 DIB/TIB), READ CAPACITY reports the
  medium extent until the disc is finalized, then the last recorded block, GET
  CONFIGURATION reports profile `0x09` with the incremental-streaming and
  CD-track-at-once features, and READ TOC formats 0, 1 and 2 walk the recorded
  track/session layout and the raw lead-in. The ATIP
  format 4 is covered separately under the format-4 entry above.
- **mmc**: persistent TOC for the `cdr-bundle` CD-R medium — the track/session
  layout is written to two alternating INI slots (`toc.0`/`toc.1`, storage
  resources 1/2) with a strict header/body parser, `Delete`/`ReadOnly`
  interrupted-save recovery, and a save state machine that formats the body
  directly into the caller's bank. The body is written before the header; the
  header carries the body length, CRC-32 and physical slot index, so a torn
  save is rejected and the last valid slot survives. `CLOSE` and
  `SYNCHRONIZE CACHE` order the aggregate data sync before the TOC body/header
  and slot sync (`RESERVE TRACK` skips the data sync). A failed save keeps
  `needs_save` latched for the next close/commit/reserve; a failed reserve
  rolls the new track back. The default slot is `TOC_SLOT_MAX` (64 KiB) and
  creation is capped by `max_tracks_for_slot`; `TocHeader::parse`,
  `CdrBundleMedium::open`/`open_at`, `slot_size`, `toc_seq`, `current_slot` and
  `track_numbers` expose the persisted state.
- **mmc**: `CdrBundleMedium::eject_needs_save` and `toc_image` render a
  pre-eject TOC snapshot into a caller bank: the medium seals an open track
  exactly like `SYNCHRONIZE CACHE`, writes the next alternating slot image
  (header, body, padding) without touching storage, and advances
  `toc_seq`/`current_slot`/`saved`/`needs_save` as a completed save would.
  `toc_image` refuses a read-only recovery medium with
  `TocError::WriteProtected`.
- **mmc**: `RESERVE TRACK` (`0x53`) decoding in `MmcDrive`: ARSV is rejected
  with `ILLEGAL REQUEST / INVALID FIELD IN CDB`, reserved CDB fields are
  validated, and the reservation size reaches the medium's capacity and
  open-track checks through `MmcOp::ReserveTrack`.
- **mmc**: recorder-control commands — MODE SENSE page 0x05 reports
  Track-at-Once/2048-byte Mode 1 parameters on a CD-R (and no TAO claim on
  read-only/rewritable media), MODE SELECT(6/10) validates and accepts that
  page (rejecting SAO/raw/packet), SET CD SPEED records the requested
  read/write speeds, SEND OPC INFORMATION accepts eight-byte tables, and READ
  TOC format 2 serves the raw A0/A1/A2/B0 lead-in descriptors plus the track
  and lead-out entries.
- **mmc**: Write Parameters Test Write (`wodim -dummy -tao`) on a
  `cdr-bundle` CD-R. MODE SELECT page 0x05 keeps the Test Write bit (byte 2
  bit 4) and MODE SENSE round-trips it; while it is set the medium consumes a
  range-checked WRITE data phase without recording it, and SYNCHRONIZE CACHE,
  CLOSE TRACK SESSION and RESERVE TRACK are GOOD no-ops, so the disc stays
  blank (no implicit track, no NWA advance, no TOC slot write). Clearing the
  bit leaves a real burn byte-identical to one that was never simulated. The
  new defaulted `MmcMedium::set_test_write` carries the drive's mode to the
  medium, and the CLI's `CliMedium` forwards it to the bundle.
- **core**: `Flow`/`ServeExit` and a target that outlives the transport link
  (host eject hands the medium back through `ResourcesReady`).
- **mmc**: `MmcCaps` (drive capabilities are LU state; the default `MmcDrive`
  is a Hyper-Multi recorder) and an empty tray that still answers MODE
  SENSE/GET CONFIGURATION; `MmcDrive::empty(caps)` and
  `LuImpl::empty(device)`.
- **core**: `Spc::with_identity` for per-LU INQUIRY identity strings.
- **core**: `Storage::resources_released` (default no-op) reports a host eject
  after the detached pair has been taken, so an adapter can drop a backend
  that is no longer addressable.
- **cli**: `--cdrom empty` serves an enumerated drive with no medium.
- **block**: removable block media — `BlockAttrs::with_removable()` reports
  INQUIRY RMB=1 and lets a host START STOP UNIT eject the pair; the LUN stays
  enumerated as empty (`3A/00`) and the application installs a new pair at the
  same LUN and raises `UaClass::MediumChanged`.
- **cli**: `--block img=<file>,removable` USB card-reader demo (one removable
  slot, `profile=block`, `img=` only, not with `--banks dual`): eject drops
  the plane and a background watcher installs a stable replacement file.
- **cli**: `--cdrom bundle=<dir>[,medium=cdr74|cdr80|cdr90|cdr99][,slot=<bytes>]
  [,recovery=delete|readonly]` (`cdr-bundle` feature) serves a persistent CD-R
  whose alternating TOC slots and track payloads live in the directory as
  `toc.0`/`toc.1` and `track_<n>.bin`. The LUN is restored from the newer valid
  TOC slot with `open_at`, so a copied/restored slot is rejected and
  `current_slot` matches the file it came from. A **stored TOC wins** over the
  `medium=` hint (the CLI passes capacity `0` on reopen and warns on a
  mismatch); `medium=`/`slot=` only describe a new blank bundle. A missing
  directory still starts a blank disc with a warning, but `recovery=readonly`
  requires an existing TOC, and an unreadable/malformed slot is an error rather
  than a silent overwrite. Track reads return the readable prefix followed by
  zeros (a missing track file is empty), and the first write at offset `0`
  truncates a reused track id. A resource `Sync` fsyncs that track or TOC slot,
  and `CLOSE`/`SYNCHRONIZE CACHE` fsync every dirty track plus the TOC slot
  before reporting GOOD. On host eject the paths that own the store (USB inline
  and USB `--banks dual`) flush the
  bundle's track data, then render the next alternating TOC slot and install it
  atomically via a fsynced `toc.<slot>.tmp` rename; the async iSCSI accept loop
  snapshots too, and the blocking iSCSI wire does so through
  `serve_with_release` (the CLI passes the same bundle hook). None of those
  generic paths can pre-flush track data through their storage seam, so they
  rely on the host's CLOSE/SYNCHRONIZE CACHE. A snapshot preserves an open
  track or an unsaved transition best effort: nothing after the snapshot is lost, but the disc is
  left Appendable (not finalized), and a host that never issued CLOSE may leave
  a partially recorded track. The same resource mapping covers `--banks dual`,
  so a bundle LUN can run on the worker path.
- **cli**: a `recovery=delete` CD-R bundle open reconciles the directory
  against the restored TOC: a `track_<n>.bin` is kept only when its canonical
  `track_file(n)` spelling is referenced by the TOC and `n` fits the slot, so
  unreferenced files, ids above `max_tracks_for_slot`, and non-canonical
  spellings are removed (one summary log line; a failed removal only warns).
  `toc.0`/`toc.1` are never touched, and a `recovery=readonly` open deletes
  nothing. Cleanup runs only when the newest readable slot is restored with no
  skipped/unreadable candidate; a TOC-less directory is never wiped (leftover
  track files are counted and reported). The scan restarts at the first entry
  (the seam has no cursor) and grows its `read_dir` batch up to 1024 entries,
  warning when the directory is too large for a complete reconciliation.
- **common**: `FsStorage::sync_file` (defaults to the backend-wide sync) and
  `FsPlane::sync_file` (defaults to the plane-wide sync) expose per-file fsync,
  so a resource-addressed backend can make one file durable; `StdFsBackend`
  implements it with `File::sync_all` and fsyncs its root directory on `sync`.
- **common**: `FsPlane::len` (seek-to-end size) and `FsPlane::truncate`
  (create/truncate), both defaulting to `Unsupported`, so a path-addressed
  backend can expose resource reuse without a new store-op variant.
- **mmc**: `cdr_bundle::max_tracks_for_slot` exposes the TOC track capacity, so
  applications can bound `16 + n` resource ids to the configured slot.
- **tests**: `cdr_cdrkit_tao_trace` replays the `wodim -tao` command sequence
  (GET CONFIGURATION, disc/track information, MODE SELECT page 0x05, SET CD
  SPEED, SEND OPC, a NWA write without RESERVE TRACK, SYNCHRONIZE CACHE and
  CLOSE TRACK/SESSION), pins the payload resource/offset and restores both
  saved TOC slots through `open_at`. `HACKING.md` gains a manual CD-R bundle
  burn/read-back recipe with its troubleshooting notes.
- **tests**: READ CAPACITY of a blank, reserved-only, partially burned and
  finalized write-once disc, plus the `recovery=delete`/`recovery=readonly`
  orphan-track reconciliation of the CLI bundle directory.
- **cli**: `--print-config` reports the resolved backing per LUN after the
  existing fields (`… backing=ram,bundle`); a smoke test pins the `bundle=`
  help text and the backing token.
- **docs**: the README lists the persistent CD-R bundle (`--cdrom bundle=<dir>`,
  feature `cdr-bundle`) in its project status and full-feature example, and
  points at `HACKING.md` for the directory/durability contract.

### Documentation

- **docs/tests**: `tools/ext-test/test_cdr_bundle.py` now covers a read-only
  mount payload check, a server restart over the same bundle directory
  (mounted volume plus alternating TOC sequence), CD-RW `blank=fast`/`blank=all`
  reburns, and an opt-in eject-snapshot case driven through `sg_raw`.
  `HACKING.md` documents that the bundle is TAO-only: SAO/DAO would need a raw
  2352-byte mastering path and an SAO capability page, so SEND CUE SHEET is
  `2C/00` and Write Type 2 is `24/00`; it also records the MMC-2 legacy
  READ SUB-CHANNEL/READ HEADER (`20/00`) and DVD/BD-only READ DISC STRUCTURE
  (`24/00`) answers. README, HACKING and the CLI help describe the CD-RW
  BLANK, multi-session and CD-DA audio workflows.

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
