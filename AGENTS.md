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
- `snowscsi-cli` — the `snowscsi` binary (`serve` + `mkisofs`)
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
| `snowscsi::cdrom` | Done — `CdromDrive` dispatches all MMC commands; media types `FlatMedia` (full MMC), `LiveData`/`LiveDataBuilder` (livefs), `DvdRamMedia` (DVD-RAM, `dvdram`). Full MMC surface: READ TOC, GET CONFIGURATION, READ DISC INFORMATION, READ BUFFER CAPACITY, READ CAPACITY, DVD physical format, prevent/allow removal, tray exchange, pending Unit Attention. Legacy `CdromDevice`/`CdLiveFsDevice`/`DvdRamDevice` removed. |
| `snowscsi::iscsi` | Done — PDU codec, `Conn` trait, session state machine driving `core::Target` through the host data seam, BSD `TcpStream` transport behind `std`. Data phase, R2T/Data-Out, task management, unit-attention reporting and transport-loss settlement are covered by mock, golden and libiscsi suites. |
| `snowscsi::usb` | Done — MSC Bulk-Only Transport core: `bot.rs` (CBW/CSW), `io.rs` (`BotIo`/`recv_exact`), `gadget.rs` (`Gadget`/`CtrlReq`), `target.rs` (`BotSession` driving `core::Target` through the host data seam, all BOT data-phase cases). Linux FunctionFS bridge (`FfsBot`/`FfsGadget`) lives only in `snowscsi-cli` under `cfg(target_os = "linux")`. |
| `snowscsi::dvdram` | Done (feature `dvdram`) — `cdrom::dvdram::DvdRamMedia`, a **blank** random-writable DVD-RAM over any `WritableFlatData`: FORMAT UNIT (zero-fill) + byte-plane read/write; the **host** formats it (the device never writes UDF structures). Exposed via CLI `--cdrom dvdram=`. |
| `snowscsi-cli` | Done — `serve` (`--block`/`--cdrom` planes + `--iscsi`/`--usb` transports, mutually exclusive; `--iscsi auto` open-iscsi loopback auto-config) and `mkisofs` (directory → ISO image). |
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
  transports. See `__SEAM_REWRITE.md` (agent memory) for the full design.
  Dual-mount of the same path across planes is warned but permitted (each LUN
  is an independent SCSI device).
