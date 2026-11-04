# Agents

This file contains instructions **exclusively for AI agents**. Human-oriented
documentation (build, test, format, commit conventions) lives in `HACKING.md` —
agents must read it before making changes.

## Cross-session Memory

Agent can create, write and modify `__*.md` as notice, reference or any other
things required for cross session memory. These files are ephemeral — clean them
up when they are no longer relevant to active work, and must never appear in
staged changes or commits.

Agent should download standard files (RFC, ISO9660, etc) to `__REF_XXX.*` and
refer to them when necessary. Those files can be downloaded even when agent is
required not to modify any files, since they are reference and will not be
tracked by git.

### Current Reference Files

| File | Standard | Description | Source |
|------|----------|-------------|--------|
| `__REF_RFC3720.txt` | RFC 3720 | iSCSI Protocol (mandatory, DO NOT follow RFC 7143) | https://www.rfc-editor.org/rfc/rfc3720.txt |
| `__REF_ECMA119.pdf.md` | ECMA-119 / ISO 9660 | Volume and File Structure of CD-ROM (Annex J covers Joliet) | https://www.ecma-international.org/wp-content/uploads/ECMA-119_4th_edition_june_2019.pdf |
| `__REF_SPC3.pdf.md` | T10/INCITS 513 (SPC-3) | SCSI Primary Commands - 3: INQUIRY, MODE SENSE, REQUEST SENSE, REPORT LUNS (closest public draft; SPC-4 r37 is T10 members-only) | http://www.13thmonkey.org/documentation/SCSI/spc3r23.pdf |
| `__REF_SBC3.pdf.md` | T10/INCITS 514 (SBC-3) | SCSI Block Commands - 3: READ(10), WRITE(10), READ CAPACITY, etc. (r25; r28 is T10 members-only) | http://www.13thmonkey.org/documentation/SCSI/sbc3r25.pdf |
| `__REF_MMC6.pdf.md` | T10/INCITS 522 (MMC-6) | SCSI Multi-Media Commands - 6: READ TOC, GET CONFIGURATION, CD-R/RW commands | http://www.13thmonkey.org/documentation/SCSI/mmc6r02g.pdf |
| `__REF_ELTORITO.pdf.md` | El Torito | Bootable CD-ROM BIOS specification | http://www.13thmonkey.org/documentation/SCSI/el-torito.pdf |
| `__REF_USB_MSC_Overview_v1.4.pdf.md` | USB MSC Overview 1.4 | USB Mass Storage Class overview (all transports, command sets) | https://www.usb.org/sites/default/files/Mass_Storage_Specification_Overview_v1.4_2-19-2010.pdf |
| `__REF_USB_MSC_BulkOnly_v1.0.md` | USB MSC Bulk-Only 1.0 | Bulk-Only Transport (BBB) — primary MSC transport | https://www.usb.org/sites/default/files/usbmassbulk_10.pdf |
| `__REF_USB_MSC_CBI_v1.1.pdf.md` | USB MSC CBI 1.1 | Control/Bulk/Interrupt Transport (legacy, floppy only) | https://www.usb.org/sites/default/files/usb_msc_cbi_1.1.pdf |
| `__REF_USB_MSC_UFI_v1.0.pdf.md` | USB MSC UFI 1.0 | USB Floppy Interface command set (based on SCSI-2) | https://www.usb.org/sites/default/files/usbmass-ufi10.pdf |
| `__REF_USB_MSC_Bootability_v1.0.pdf.md` | USB MSC Bootability 1.0 | Bootable USB mass storage device specification | https://www.usb.org/sites/default/files/usb_msc_boot_1.0.pdf |
| `__REF_T10_UAS_r0.pdf.md` | T10/08-221r0 (UAS) | USB Attached SCSI transport protocol (T10 draft) | https://www.t10.org/ftp/t10/document.08/08-221r0.pdf |
| `__REF_USB_UASP_v1.0.pdf.md` | USB UASP 1.0 | UAS implementation guide for USB 2.0/3.0 (USB-IF) | https://www.usb.org/sites/default/files/uasp_1_0.zip |

## Critical Rules

- DO NOT implement iSCSI per RFC 7143 — it is not widely accepted. Follow
  RFC 3720 instead.

## Workspace

Multi-crate cargo workspace (resolver = "2"); the `snowscsi` binary lives in
`snowscsi-cli`. The **full layout, per-crate roles, module map and feature
matrices** are documented in `HACKING.md` (Project Structure) — read it before
making changes. Crate names at a glance:

- `snowscsi-common` — storage seams + logging macros (always available)
- `snowscsi-iso9660` — ISO9660/Joliet live-generation algorithms
- `snowscsi` — SCSI core + iSCSI + USB MSC + CD-ROM + blank DVD-RAM media
- `snowscsi-cli` — the `snowscsi` binary (`serve`, `mkisofs`, `bundle-create`, `bundle-info`)
- `snowscsi-tests` — integration tests (the only crate allowing `unsafe`)
- `tools/` — not a workspace member: external Python black-box tests + helpers

## LIB / CLI / examples boundary

The library crates (`snowscsi-common`, `snowscsi-iso9660`, `snowscsi`) are
**runtime-agnostic**: they must not depend on Tokio, embassy, a platform flash
or file driver, an executor/waker, or `spawn_blocking`. They provide the
poll/step core and the runtime-agnostic seams (`Storage`, `HostTransport`,
`PendingKind`/`Action::StoragePending`, `AsyncWake`, `AsyncConn`,
`serve_conn_async`, `serve_async`).

Platform adapters belong to the application:

- `snowscsi-cli` may own a runtime (e.g. Tokio), file/block I/O and the
  `AsyncConn` / `Storage + AsyncWake` implementations for that runtime.
- `examples/` own embassy USB, flash/DMA slot registration and board glue.

They are not workspace members and must not be pulled into the library.

## Implementation Status

| Component | Status |
|-----------|--------|
| `snowscsi-common` | Done — capability ladder `FlatData`(① read) → `WritableFlatData`(② write+sync) → `SeekableStorage`(③ embedded-io entry; blankets lift ③ into ①/②) + erased slot refs `FlatRef`/`RwRef`; plus `FsStorage` seam and logging macros. |
| `snowscsi-iso9660` | Done — ISO9660/Joliet live-generation (`live.rs`), moved out of the old `iso9660` module. `LiveData`/`LiveDataBuilder`/`compute_layout`. |
| `snowscsi::scsi` | Done — seam-first rewrite: one `BlockDevice<D: FlatData>` with two profiles (`disk()` writable PDT 0x00 / `cdrom()` read-only PDT 0x05, the former `CDBlockDevice`, over ANY plane incl. user backends); transports are generic over `D: ScsiDevice` (+ blanket for `&mut T`) so users implement their own LUNs; the closed `Device` enum is removed. |
| `snowscsi::core` | Done — seams + adapters: `BlockingStorage`/`BlockingHost` (four fixed slots), `BlockingStorage::from_plane`/`from_read_plane` (byte plane → `SyncStorage`), `Fault: From<StorageError>` + `StorageReceipt::failed_for(dir, err)`, and the runtime-free async adapter `slots::SlotPool` → `SlotStore` (`Storage` + `AsyncWake`) / `SlotTask` (`next_job`/`complete`) over one staging buffer and two wakers (dropping a `Job` returns the buffer; `reset()` clears a dropped shell's leftovers). |
| `snowscsi::cdrom` | Done — `CdromDrive` dispatches all MMC commands; media types `FlatMedia` (full MMC), `LiveData`/`LiveDataBuilder` (livefs), `DvdRamMedia` (DVD-RAM, `dvdram`). Full MMC surface: READ TOC, GET CONFIGURATION, READ DISC INFORMATION, READ BUFFER CAPACITY, READ CAPACITY, DVD physical format, prevent/allow removal, tray exchange, pending Unit Attention. Legacy `CdromDevice`/`CdLiveFsDevice`/`DvdRamDevice` removed. |
| `snowscsi::iscsi` | Done — PDU codec, `Conn` trait, session state machine driving `core::Target` through the host data seam, BSD `TcpStream` transport behind `std`. Data phase, R2T/Data-Out, task management, unit-attention reporting and transport-loss settlement are covered by mock, golden and libiscsi suites. |
| `snowscsi::usb` | Done — MSC Bulk-Only Transport core: `bot.rs` (CBW/CSW), `io.rs` (`BotIo`/`recv_exact`), `gadget.rs` (`Gadget`/`CtrlReq`), `target.rs` (`BotSession` driving `core::Target` through the host data seam, all BOT data-phase cases). Linux FunctionFS bridge (`FfsBot`/`FfsGadget`) lives only in `snowscsi-cli` under `cfg(target_os = "linux")`. |
| `snowscsi::dvdram` | Done (feature `dvdram`) — `cdrom::dvdram::DvdRamMedia`, a **blank** random-writable DVD-RAM over any `WritableFlatData`: FORMAT UNIT (zero-fill) + byte-plane read/write; the **host** formats it (the device never writes UDF structures). Exposed via CLI `--cdrom dvdram=`. |
| `snowscsi-cli` | Done — `serve` (`--block`/`--cdrom` planes + `--iscsi`/`--usb` transports, mutually exclusive; `--iscsi auto` open-iscsi loopback auto-config), `mkisofs` (directory → ISO image), and the bundle verbs: `bundle-create flat|cdr` writes the directory `SNOWBUNDLE` manifest (and, for `cdr`, the initial TOC slot) but never chunk/track data; `bundle-info` classifies a directory or `<image>.SNOWBUNDLE` sidecar. `serve` opens `bundle=<dir>` and never creates the directory, manifest or TOC (it does create chunk/track files and write TOC snapshots while serving); the manifest `kind` selects flat vs CD-R, and bundle directories are canonicalized so aliases are rejected. |
| `snowscsi-tests` | Done — mock + libiscsi whitebox (`has_libiscsi` gated) + ISO cross-validation. |
| `snowscsi::capi` | **Removed** — the `capi`/`cbindgen` feature and module no longer exist anywhere in the tree (no C ABI). |
| `snow9660` | Removed — folded into `snowscsi-cli` as `mkisofs` (the disc crate *generates* ISOs; it does not parse them). |

## Legacy C Code

The original C implementation lives on the `legacy` branch:
```bash
git checkout legacy
```

## Agent-Only Context

- **Logging**: `snowscsi` re-exports `snowscsi-common` as `common` and the
  unified logging macros (`trace!`/`debug!`/`info!`/`warn!`/`error!`) at crate
  root, so `use snowscsi::{info, common::…};` works. Log output routing is
  the caller's responsibility (the CLI wires `env_logger`). Select `log` vs
  `defmt` via the per-crate `log`/`defmt` features.
- **Tests**: `cargo test --workspace`. In-process integration tests live in the
  `snowscsi-tests` crate (mocks + libiscsi whitebox; some gated on `cfg(has_libiscsi)`).
  External black-box tests live in `tools/ext-test` (Python, run with
  `python3 tools/ext-test/run.py`; skip without root/tools).
- **no_std verification**: the lib crates must stay `no_std`-clean without
  `std`:
  `cargo build -p snowscsi --no-default-features`,
  `cargo build -p snowscsi-iso9660 --no-default-features`,
  `cargo build -p snowscsi-common --no-default-features`.
  The `defmt` backend is a **separate** gate (it is a different format-string
  grammar, not just a backend swap): run
  `cargo build -p snowscsi --no-default-features --features 'scsi,cdrom,usb,dvdram,defmt'`
  for every change that touches a log call. One literal is forwarded to both
  `log` and `defmt`, so a message must stay in the portable subset: positional
  arguments only (no `{name}` captures) and `{}`/`{:?}` (`{:?}` needs
  `defmt::Format`, add it with `#[cfg_attr(feature = "defmt", derive(defmt::Format))]`);
  integer type/hint specs like `{=u8:02x}` break `log` and `{:02x}` is not a
  defmt hint.
  `cargo test -p snowscsi --no-default-features --features scsi` is green
  (verified 2026-10-31; the previous std-prelude gap is closed).
- **Transport layer**: `Conn` = blanket `embedded_io::Read + Write`; `AsyncConn`
  is the runtime-agnostic async mirror behind `async-io` and
  `serve_conn_async` awaits both the connection and a `Storage + AsyncWake`
  adapter. `serve_async` is the USB mirror. Neither implies a runtime; the
  caller's executor drives them. USB MSC: `BotIo`/`Gadget` seams in
  `snowscsi::usb` — the non-blocking `BotSession` core never does platform I/O;
  the Linux FunctionFS bridge (`FfsBot`/`FfsGadget`, `usb-gadget` crate) lives
  only in `snowscsi-cli` under `cfg(target_os = "linux")`.
- **Serve-loop contract**: the transport loops own **no device lifetime**. They
  return `Result<ServeExit, _>` (`core::serve`): `Paused`/`Outcome` are handed
  back at a point where no I/O is in flight (the action is re-emitted on
  re-entry), `Stopped`/`WireGone` settle the live command first. Only
  `Target::stop()` and `fatal` end a target; a lost link calls
  `Target::link_lost(storage, host, work, scratch)` (no terminal latch) so the
  same target serves the next link. It also feeds a retained long operation its
  cancelled receipt (with the caller's bank), otherwise the device would stay
  `Foreground` forever. Application → loop control is `core::Flow`
  (`Run`/`Pause`/`Stop`); `Pause` waits for `Target::management_boundary()`.
  `serve_conn*` has no Flow yet (iSCSI pause needs a read wake); a
  `ResourcesReady` handback is only reported when `Target::take_ready(lun)`
  accepts it (the long-token/command checks are per LUN, so another LUN's token
  never blocks the take).
- **Media change**: a host `START STOP UNIT` with `LoEj=1, Start=0` records an
  eject intent on the `Device` (`take_eject_request`); the runner detaches the
  pair at the completion point and publishes `ResourcesReady`. `LoEj=1,
  Start=1` (load) is a no-op, as is `LoEj` on non-removable media. An empty slot
  admits START STOP UNIT (a retried eject is a no-op GOOD) but not
  PREVENT/ALLOW (its unlock-flush would sync a stale binding). A manual
  `impl Lu` wrapper must forward `take_eject_request` or host ejection is
  silently disabled (`CliLu` forwards it for both the block and MMC arms).
  A **removable block LUN** gets RMB from `BlockAttrs::with_removable()`
  (`BlockDevice::inquiry_data`); `removable` is a slot/LUN property, not a
  medium property, so it survives a swap. Eject detaches the pair and
  publishes `ResourcesReady`; the LUN stays enumerated as an empty slot
  (`3A/00` for media commands including READ CAPACITY, PREVENT/ALLOW still
  rejected) and the application installs a new pair at the same LUN. The core
  does **not** raise `UaClass::MediumChanged` on install: the application
  raises it (sense `06/28/00`) so the host re-reads the medium. Because
  `BlockDevice` owns the geometry, a capacity change rebuilds the whole slot
  device (the CLI replaces its `CliLu`). CLI demo: `--block
  img=<file>,removable` (USB only, `profile=block`, `img=` only, at most one
  removable slot — other non-removable LUNs may coexist — and not with
  `--banks dual`); the serve loop drops the plane on eject, a 200 ms
  watcher thread — armed **only while the slot is empty**, so host writes to a
  loaded card cannot self-eject it — detects a stable new regular file and
  calls `Flow::pause()`, and the clean `ServeExit::Paused` boundary swaps in a
  fully built `CliLu` (pending `MediumChanged` included) before `Flow::run()`.
  `ResourcesReady` never drops the `Target`/`Runner`: another LUN may still
  have a resident long-operation receipt.
- **INQUIRY identity / empty LUN**: `Spc::with_identity(vendor, product, revision)`
  sets only the strings; the PDT/removable bit stay the device's, and
  `Spc::effective_inquiry` is the single read used by the encoder, the device
  projection and the `LoEj` gate (an outer `Device` wrapper cannot retarget
  INQUIRY). `MmcDrive::empty(caps)` + `LuImpl::empty(device)` build an enumerated
  drive with no medium (queries answer, media commands are `MEDIUM NOT
  PRESENT`); fill it with `install_rt`, no eject/rebuild needed.
- **Drive vs medium**: `mmc::MmcCaps` is the **LU's** capability (supported
  profiles, mode page 0x2A, random-writable features) and lives on `MmcDrive`;
  `MmcAttrs` is the **disc** (capacity, write protection, current write mode).
  `MmcDrive::new(medium)` is a **Hyper-Multi** drive by default (reads
  CD/DVD, writes CD-R/RW and DVD±R/RAM); the installed medium only drives the
  Current bits (current profile/features, capacity). Use
  `new_with_caps`/`empty(caps)` to narrow the drive class. MODE SENSE is a
  drive query and answers on an empty tray (all pages, 0x05 with defaults);
  `Device::admits_without_medium` (default `false`, `MmcDrive` opts in for
  0x1A/0x5A, `Spc` forwards) keeps the empty-slot gate from rejecting it, while
  media-description commands stay `MEDIUM NOT PRESENT`. Empty DVD-RAM still
  lists profile 0x12/0x08 and features 0x20/0x24 with Current=0.
- **Async storage adapters**: `core::slots::SlotPool` is the runtime-free
  bridge for a backend whose I/O completes elsewhere (SD card, flash, DMA).
  Split it into `SlotStore` (implements `Storage` + `AsyncWake`) and
  `SlotTask` (`next_job().await` / `complete(job, result)`), then `join!` both
  futures in one task. It owns the slot table, one staging buffer and two
  wakers; it is `!Send`, so a spawned (multi-task) store needs a
  runtime-specific synchronisation primitive, not this type. Do not re-grow a
  per-application copy of that state machine in examples or the CLI.
- **Banks**: `work` is the command/data bank; an optional alternate bank holds
  a prefetched Data-In chunk. An empty `scratch` shares the command bank with
  the resident long operation; a non-empty one keeps the split long-op bank.
  `--overlap` splits `work` into two equal banks (USB and iSCSI) and uses the
  alternate for prefetch; `HostBuf` carries `BankSide` so a transport frames a
  PDU in the bank that holds it. The core only ever sees bank-relative slices.
- **Red lines**: `#![deny(unsafe_code)]` on `snowscsi-common`, `snowscsi-iso9660`
  and `snowscsi`; `snowscsi-cli` uses `#![forbid(unsafe_code)]`.
  `snowscsi-tests` is the only crate that allows `unsafe` (libiscsi FFI).
  RFC 3720 only, no RFC 7143. `__*` files never committed.
- **LUN model**: both transports drive a `core::Target<S>` where
  `S: RuntimeSet`, i.e. a homogeneous-pair slot table. A transport's `poll`
  takes `work`/`scratch` banks plus `&mut Target<S>` and `&mut dyn Storage`,
  and implements `HostTransport` itself; storage IO runs inside the runner.
  Applications wrap a device in `LuImpl<D, B>` (optionally `Spc<D>`) or
  implement `Lu` directly; heterogeneous LUN kinds need one pair type (the CLI
  uses `CliLu`/`CliPair` in `snowscsi-cli/src/stack.rs`). Per-LUN storage
  routing goes through `Storage::select_lun`. The legacy `scsi::ScsiDevice`
  path still exists for the `snowscsi::scsi` profiles but no longer drives the
  transports. The seam is documented in-tree (`snowscsi/src/core/lu.rs`,
  `snowscsi/src/core/runner.rs`, `snowscsi/src/core/device.rs`).
  Dual-mount of the same path across planes is warned but permitted (each LUN
  is an independent SCSI device).
