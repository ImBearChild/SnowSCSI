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

## Implementation Status

| Component | Status |
|-----------|--------|
| `snowscsi-common` | Done — capability ladder `FlatData`(① read) → `WritableFlatData`(② write+sync) → `SeekableStorage`(③ embedded-io entry; blankets lift ③ into ①/②) + erased slot refs `FlatRef`/`RwRef`; plus `FsStorage` seam and logging macros. |
| `snowscsi-iso9660` | Done — ISO9660/Joliet live-generation (`live.rs`), moved out of the old `iso9660` module. `LiveData`/`LiveDataBuilder`/`compute_layout`. |
| `snowscsi::scsi` | Done — seam-first rewrite: one `BlockDevice<D: FlatData>` with two profiles (`disk()` writable PDT 0x00 / `cdrom()` read-only PDT 0x05, the former `CDBlockDevice`, over ANY plane incl. user backends); transports are generic over `D: ScsiDevice` (+ blanket for `&mut T`) so users implement their own LUNs; the closed `Device` enum is removed. |
| `snowscsi::cdrom` | Done — `CdromDrive` dispatches all MMC commands; media types `FlatMedia` (full MMC), `LiveData`/`LiveDataBuilder` (livefs), `DvdRamMedia` (DVD-RAM, `dvdram`). Full MMC surface: READ TOC, GET CONFIGURATION, READ DISC INFORMATION, READ BUFFER CAPACITY, READ CAPACITY, DVD physical format, prevent/allow removal, tray exchange, pending Unit Attention. Legacy `CdromDevice`/`CdLiveFsDevice`/`DvdRamDevice` removed. |
| `snowscsi::iscsi` | Done — PDU codec, `Conn` trait, session state machine, BSD `TcpStream` transport behind `std`. Recent fixes: StatSN/DataSN/BufferOffset sequencing and the R2T/Data-In state machine. |
| `snowscsi::usb` | Done — MSC Bulk-Only Transport core: `bot.rs` (CBW/CSW), `io.rs` (`BotIo`/`recv_exact`), `gadget.rs` (`Gadget`/`CtrlReq`), `target.rs` (non-blocking `BotSession::poll`). Linux FunctionFS bridge (`FfsBot`/`FfsGadget`) lives only in `snowscsi-cli` under `cfg(target_os = "linux")`. |
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
  (Known gap: `cargo test -p snowscsi --no-default-features --features scsi`
  does not compile — unit tests use `Vec`/`String` without pulling in `std`.)
- **Transport layer**: `Conn` trait = blanket impl of `embedded_io::Read + Write`.
  BSD transport (`TcpStream`) behind `std` feature in `snowscsi::iscsi`.
  USB MSC transport: `BotIo`/`Gadget` seams in `snowscsi::usb` — the
  non-blocking `BotSession` core never does platform I/O; the Linux FunctionFS
  bridge (`FfsBot`/`FfsGadget`, `usb-gadget` crate) lives only in `snowscsi-cli`
  under `cfg(target_os = "linux")`.
- **Red lines**: `#![deny(unsafe_code)]` on `snowscsi-common`, `snowscsi-iso9660`
  and `snowscsi`; `snowscsi-cli` uses `#![forbid(unsafe_code)]`.
  `snowscsi-tests` is the only crate that allows `unsafe` (libiscsi FFI).
  RFC 3720 only, no RFC 7143. `__*` files never committed.
- **LUN model**: both transports drive any `D: ScsiDevice` via
  `poll<…, D>(devs: &mut [D])`. Homogeneous arrays use concrete types
  (`&mut [BlockDevice<B>]`); heterogeneous mixing uses
  `[&mut dyn ScsiDevice]`. Users implement `ScsiDevice` directly or wrap
  built-ins (see `ScsiDevice` doc for the canonical wrapper pattern).
  The CLI owns typed vectors (`disks`/`drives`/`backends`/`lives`) and
  builds a `Vec<&mut dyn ScsiDevice>`; shutdown flushes via
  `ScsiDevice::sync()`. See `__SEAM_REWRITE.md` (agent memory) for the
  full design. Dual-mount of the same path
  across planes is warned but permitted (each LUN is an independent SCSI device).
