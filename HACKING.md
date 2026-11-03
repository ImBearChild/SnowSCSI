# Contributing to SnowSCSI

## Project Structure

SCSI device emulation toolkit — a **multi-crate cargo workspace** (resolver = "2").
The old unified `snowscsi` lib+bin crate has been split into focused crates;
the `snowscsi` binary lives in `snowscsi-cli`.

| Component | Crate | Description |
|-----------|-------|-------------|
| **Common** | `snowscsi-common` | Zero-alloc `SeekableStorage` / `FsStorage` seams + unified logging macros (always available, no feature gate) |
| **Disc** | `snowscsi-iso9660` | ISO9660 + Joliet live-generation algorithms (`live.rs`) |
| **SCSI core** | `snowscsi` | SCSI core, block/CD-ROM devices (SBC/SPC/MMC), iSCSI target, USB MSC (BOT) core, blank (host-formatted) DVD-RAM media |
| — storage seams | `snowscsi::common` (= `snowscsi-common`) | Re-exported `SeekableStorage`/`FsStorage` + logging macros |
| — SCSI | `snowscsi::scsi` | Legacy `BlockDevice` (disk/cdrom profiles), SPC/SBC layers, file/fs backends, `ScsiDevice` LUN trait (kept for the profile path; the transports no longer use it) |
| — CD-ROM | `snowscsi::cdrom` | `CdromDrive` + media (`FlatMedia` / `LiveData` / `DvdRamMedia`), full MMC |
| — iSCSI | `snowscsi::iscsi` | iSCSI PDU codec, connection, target state machine driving `core::Target`, TCP transport |
| — USB MSC | `snowscsi::usb` | Bulk-Only Transport core: CBW/CSW codec, `BotIo`/`Gadget` seams, `BotSession` driving `core::Target` |
| — DVD-RAM | `snowscsi::dvdram` (feature `dvdram`) | Blank, host-formatted random-writable DVD-RAM media (`cdrom::dvdram::DvdRamMedia`) |
| **CLI** | `snowscsi-cli` (`src/main.rs`) | `snowscsi serve` runs the iSCSI target or the USB MSC (BOT) gadget; `snowscsi mkisofs` generates an ISO image from a directory |
| **Tests** | `snowscsi-tests` (`tests/`) | Integration tests (mock + libiscsi whitebox + ISO cross-validation) |
| **Tools** | `tools/` (not a workspace member) | External Python black-box tests (`ext-test/`) + USB passthrough helper |

```
SnowSCSI/                          # cargo workspace (resolver = "2")
├── Cargo.toml                      # workspace: members listed below
├── snowscsi-common/               # crate: storage seams + logging macros
│   ├── Cargo.toml
│   └── src/{lib.rs, seekable_storage.rs, fs_storage.rs, logging.rs}
├── snowscsi-iso9660/                 # crate: ISO9660/Joliet live-generation algorithms
│   ├── Cargo.toml
│   └── src/{lib.rs, mod.rs, live.rs}
├── snowscsi/                 # crate: SCSI core + iSCSI + USB MSC + CD-ROM
│   ├── Cargo.toml
│   └── src/
│       ├── lib.rs                 # #![deny(unsafe_code)]; re-exports common + logging macros
│       ├── scsi/                  # feature "scsi": backend, block, device,
│       │                         #            fs_backend, sbc, spc, scsi
│       ├── cdrom/                 # feature "cdrom": common, drive, media,
│       │                         #            dvdram (gated by "dvdram")
│       ├── iscsi/                 # feature "iscsi": conn, pdu, target, transport
│       ├── usb/                   # feature "usb": bot, gadget, io, target
│       └── dvdram.rs            # feature "dvdram": blank, host-formatted DVD-RAM media
├── snowscsi-cli/                 # crate: `snowscsi` binary (src/main.rs)
│   ├── Cargo.toml                # features: full/std/scsi/dvdram/iscsi/cdrom/livefs/usb/bundle/cdr-bundle/log/tokio/defmt
│   └── src/main.rs               # #![forbid(unsafe_code)]; serve + mkisofs subcommands
├── tests/                         # crate: snowscsi-tests (integration tests)
│   ├── Cargo.toml
│   ├── build.rs                  # probes libiscsi (cfg has_libiscsi), compiles c/iscsi_access.c
│   ├── c/iscsi_access.c
│   └── src/{lib.rs, mock.rs, mock_conn.rs, mock_bot.rs, usb_bot.rs, whitebox.rs, iso_cross.rs}
└── tools/                         # NOT a cargo member: external black-box tests + helpers
    ├── ext-test/*.py             # iso / iscsi-loopback / usb-loopback black-box tests (Python)
    └── libvirt-usb-helper        # USB passthrough helper
```

Dependency chain:

```
snowscsi-cli (bin) ──▶ snowscsi (lib) ◀──┐
                          ▲                      │
snowscsi-tests ──────────┘                      │
                          │                      │
snowscsi ──▶ snowscsi-common              │
               └─▶ snowscsi-iso9660 ──▶ snowscsi-common
```

Feature maps:

- **`snowscsi-common`** — `std` (default), `log`, `defmt`, `async-io`. The
  core seams are always compiled (no feature gate). `async-io` adds the
  asynchronous storage seams (`async fn` in trait, no runtime). `defmt` forwards
  to `embedded-io/defmt` so `embedded_io::ErrorKind` implements `defmt::Format`;
  `std` + `defmt` is rejected at compile time (see below).
- **`snowscsi-iso9660`** — `std` (default).
- **`snowscsi`** — `std` (default), `scsi`, `dvdram`,
  `iscsi` (→`scsi`), `cdrom` (→`scsi`),
  `livefs` (→`cdrom`), `usb` (→`scsi`),
  `bundle` (→`snowscsi-common/bundle`), `cdr-bundle` (sequential CD-R/CD-RW
  medium with an alternating persistent TOC), `async-io` (→`usb` +
  `snowscsi-common/async-io`), `embassy`
  (→`async-io` plus the embassy-usb/embassy-time adapters), `log`, `defmt`.
  `defmt` forwards to `embedded-io/defmt` and
  `snowscsi-common/defmt` (no `snowscsi-iso9660` propagation: that crate has
  no `defmt` feature). `std` + `defmt` is unsupported — `std::io::Error`
  cannot implement `defmt::Format` — and is guarded by a `compile_error!` in
  `snowscsi-common/src/logging.rs` (the `defmt` macro branch is also
  `no_std`-only, so the guard is the single reported error). No
  platform-specific dependencies: the Linux FunctionFS
  USB bridge lives only in `snowscsi-cli`, which declares its own
  Linux-only `usb-gadget`/`bytes` deps under
  `[target.'cfg(target_os = "linux")'.dependencies]`.
- **`snowscsi-cli`** — `full` (default) pulls `std` +
  `scsi`/`dvdram`/`iscsi`/`cdrom`/`livefs`/`usb`/`bundle`/`cdr-bundle`/`log`/
  `tokio` plus
  std-only deps (clap/ctrlc/env_logger). Builds against `snowscsi` with
  `default-features = false`. The `serve --usb` FunctionFS bridge pulls in the
  Linux-only `usb-gadget` (>= 1.1) and `bytes` crates via
  `[target.'cfg(target_os = "linux")'.dependencies]` — never compiled on other
  targets.
- **`tests`** (`snowscsi-tests`) — depends on `snowscsi` with
  `std, scsi, iscsi, cdrom, livefs, usb, dvdram, bundle, cdr-bundle, async-io,
  embassy`; enables `has_libiscsi` only when the `libiscsi` system library is
  present (probed in `build.rs`).

`snowscsi`'s `no_std` surface is feature-gated; without `std` it stays
`no_std`-clean so embedded consumers can pull in only `scsi`/`usb`/`iscsi`.

### CD-R/CD-RW storage resource contract

The `cdr-bundle` medium (`CdrBundleMedium`) models either a write-once CD-R or
an erasable CD-RW; both use the same Track-at-Once path and persistent TOC, and
the media kind (`disc_type = cdr` or `disc_type = cdrw` in the TOC body) is
stored so a reopen restores it. `BLANK` (all or minimal) on a CD-RW resets the
in-memory track/session state to Blank and saves a fresh TOC slot; it never
zero-fills or removes a track file. The application's storage is addressed with
these resource ids:

- `0` — aggregate flush. `Sync { resource: 0 }` must flush every track
  resource.
- `1` / `2` — the two TOC slots (`toc.0` / `toc.1`).
- `16 + n` — track `n` (`track_<n>.bin`).
- Any other id is a contract fault; the medium never emits one.

A track resource is created/truncated by its first write at offset `0`, and a
short read zero-fills. A TOC save creates the target slot lazily with the
body/padding write at offset 256, rewrites the 256-byte header at offset 0
last, and then fsyncs the slot, so a plain write at offset 0 must **not**
truncate an existing resource. A FUA write syncs its data, and both CLOSE TRACK
SESSION and SYNCHRONIZE CACHE sync the aggregate data (`Sync { resource: 0 }`)
before writing and syncing the TOC slot. The medium never deletes track files;
the application reconciles orphans with `CdrBundleMedium::track_numbers`.
Serve at most one writer per bundle directory: the alternating TOC slots and
the orphan cleanup assume a single serving process.

The CLI application maps that contract onto a host directory with
`--cdrom bundle=<dir>` (`cdr-bundle` feature):

- **CLI bundle backing** — `OwnedPlane::CdrBundle` owns an
  `FsPlaneAdapter<StdFsBackend>` plus the preset's sector count, and its
  `exec(resource, …)` routes `1`/`2` to `toc.0`/`toc.1` and `16 + n`
  (`1 <= n <= max_tracks_for_slot(slot_size)`) to `track_<n>.bin`. Track reads
  return the readable prefix and zero-fill only the suffix (a missing file is
  empty); a reused track id is truncated by its first write at offset `0`. TOC
  slots stay strict. `open_cdr_medium` performs the documented two-step read
  (256-byte header of both slots, then the newer valid slot in full) and uses
  `open_at` with the physical index, so a copied slot is rejected. A missing
  slot is a blank start, but an unreadable/malformed slot is an error unless
  the other slot is valid. A stored TOC always wins over `medium=`: the CLI
  passes the preset as a hint and warns when the stored capacity or disc kind
  differs, so `medium=` and `slot=` only describe a new blank bundle (a fresh
  directory with no TOC uses the hint, default CD-R; a restored one uses the
  stored kind). A missing directory is created
  with a warning for `recovery=delete`; `recovery=readonly` requires an
  existing TOC and never creates one. A resource `Sync` fsyncs the addressed
  track or TOC slot, and the aggregate `Sync { resource: 0 }` fsyncs every
  dirty track and TOC file before `SYNCHRONIZE CACHE`/`CLOSE` reports GOOD.
  Orphan `track_<n>.bin` files are removed when a bundle is reopened with
  `recovery=delete` (never with `recovery=readonly`); stale tails are ignored
  because the TOC bounds every read. On host eject the serve paths that own the
  storage handle snapshot the ejected medium before its plane is dropped: USB inline
  (`CliStorage`) and USB `--banks dual` (`WorkerStore`) first flush the bundle's
  track data, then render the next alternating slot (`CdrBundleMedium::toc_image`
  -> `toc.<slot>`) as a fsynced temp file renamed into place, so the slot switch
  is atomic. The async iSCSI accept loop also snapshots, but its generic
  `Storage + AsyncWake` seam has no sync entry point, so it cannot pre-flush
  track data: a power loss right after that eject may still lose the last
  unsynced track bytes. The blocking iSCSI wire (the default `--wire blocking`)
  takes the pair inside `iscsi::serve` and has no snapshot hook, so it still
  relies on the host's `CLOSE`/`SYNCHRONIZE CACHE`. A snapshot preserves an open
  track or an unsaved transition best effort: nothing after the snapshot is
  lost, but the disc is left **Appendable**, not finalized, and a host that
  never issued `CLOSE` may leave a partially recorded track. The LUN stays empty
  (no automatic reinsert). The same `exec` drives the inline and `--banks dual`
  worker paths, so a bundle LUN is resource-correct on both.

## Commit Messages

This project follows [Conventional Commits](https://www.conventionalcommits.org/en/v1.0.0/).

### Format

```
<type>[optional scope]: <description>

[optional body]

[optional footer(s)]
```

### Types

| Type | Description |
|------|-------------|
| `feat` | New feature |
| `fix` | Bug fix |
| `docs` | Documentation only |
| `refactor` | Code change that neither fixes a bug nor adds a feature |
| `test` | Adding or correcting tests |
| `chore` | Other changes that don't modify src or test files |

Scopes should name the crate and/or module, e.g. `scsi`, `cdrom`, `iscsi`,
`usb`, `disc`, `common`, `cli`, `tests`.

### Examples

```
feat(scsi): add WRITE(10) command support
fix(iscsi): correct StatSN sequence numbering
docs: update API usage examples
test(cdrom): add READ TOC format 0 tests
refactor(scsi): introduce generic SenseState for pending sense
```

### Breaking Changes

Append `!` after the type/scope and add `BREAKING CHANGE:` in the footer:

```
feat(api)!: change do_cmd return type

BREAKING CHANGE: do_cmd now returns CommandOutcome instead of int.
```

## Building

```bash
cargo build --workspace
```

## Testing

```bash
cargo test --workspace
```

### External Tool Tests

Beyond the cargo suites, `tools/ext-test/` cross-validates the `snowscsi`
binary as a **black box** with independent external tools, driven by pure
standard-library Python (no pytest dependency):

- `tools/ext-test/test_iso.py` — `snowscsi mkisofs` output is read by
  `file`, `isoinfo` (PVD **and** Joliet trees), `7z` and `bsdtar`
  (libarchive); names, sizes and file content must match the source tree.
  Tests skip when a tool is absent.
- `tools/ext-test/test_iscsi_loopback.py` — a real kernel initiator
  (`iscsiadm` + `iscsi_tcp`) logs into `snowscsi serve`, formats the RAM
  disk with ext4, mounts it, writes/reads through the real block layer and
  fsck-checks it. Skipped unless root and the module/daemon are available.
- `tools/ext-test/test_usb_loopback.py` — a real kernel `usb-storage`
  initiator attaches to `snowscsi serve --usb` through a `dummy_hcd`
  UDC (FunctionFS gadget) and exercises the same checklist
  (capacity, `dd`/`badblocks` roundtrip, ext4 format/mount/write/fsck,
  read-only backend write protection) via `/dev/sdX`. Skipped unless root,
  a `dummy_udc.0` UDC and writable configfs are present; auto-loads
  `dummy_hcd` + `libcomposite` and auto-mounts configfs. The runtime must
  allow Linux native aio (a seccomp/container ban surfaces as a failed
  first bulk transfer).

```bash
# Fast, no privileges needed (ISO cross-validation)
python3 tools/ext-test/run.py

# A single file / test
python3 tools/ext-test/test_iso.py

# Kernel loopback tests (need root)
sudo -E env PATH=$PATH python3 tools/ext-test/test_iscsi_loopback.py
sudo -E env PATH=$PATH python3 tools/ext-test/test_usb_loopback.py

# Point at a specific binary (default: target/release or target/debug)
SNOWSCSI_BIN=./target/debug/snowscsi python3 tools/ext-test/run.py
```

Design notes:

- These tests are **not** compiled into cargo tests: they spawn the binary
  as a subprocess and use tools that may not exist in a Rust toolchain, so
  a missing tool skips (never fails) its test.
- The oracle is the host directory tree, never another ISO generator: we
  assert that independent readers reproduce the same names/sizes/content,
  not that our layout is byte-identical to `mkisofs`.
- The PVD-tree assertions (`isoinfo -l`) are the regression net for the
  dual-tree (PVD 8.3 + Joliet UCS-2) layout — the Rust cross-reader
  (`iso9660-no-std`) prefers the Joliet SVD, so only external tools exercise
  the PVD tree.

### Manual CD-R/CD-RW bundle check

`--cdrom bundle=<dir>` serves a persistent CD-R (or, with `medium=cdrwNN`, an
erasable CD-RW). The medium model, the recorder-control commands and the
alternating TOC slots are covered in-process (`cdr_cdrkit_tao_trace` follows
the exact `wodim -tao` sequence), but a manual burn catches host/driver
interaction the harness cannot.

Serve the disc over USB (FunctionFS; `<udc>` is a controller name, `auto`
picks one, `dummy` auto-loads `dummy_hcd`):

```bash
cargo run -p snowscsi-cli -- serve --usb <udc> \
    --cdrom bundle=/tmp/cdr,medium=cdr80
```

or over iSCSI (`auto` binds the loopback portal and logs in through
open-iscsi; an explicit `--iscsi 127.0.0.1:3260` needs a manual `iscsiadm`
login):

```bash
cargo run -p snowscsi-cli -- serve --iscsi auto \
    --cdrom bundle=/tmp/cdr,medium=cdr80
```

`medium=`/`slot=` only describe a **new blank** bundle; once a TOC exists the
stored geometry and media kind win. `medium=cdr74|cdr80|cdr90|cdr99` creates a
write-once CD-R; `medium=cdrw74|cdrw80|cdrw90|cdrw99` creates an erasable
CD-RW with the same capacity presets.

Burn with cdrkit in Track-at-Once:

```bash
wodim -v -tao dev=/dev/sr0 /path/image.iso
```

`-tao` is mandatory: `-dao` (SAO), packet/raw write modes are rejected by
MODE SELECT page 0x05 with ILLEGAL REQUEST. `-dummy` (Test Write) is accepted
in TAO: the disc simulates the burn — the host's data phase is consumed, every
recording command (WRITE, SYNCHRONIZE CACHE, CLOSE TRACK SESSION, RESERVE TRACK)
reports GOOD, and the disc stays blank (no track, no NWA advance, no TOC slot
write). Only the Test Write bit changes, so clearing it with a later MODE
SELECT leaves the disc ready for a real burn exactly as before. Make sure
the host has completed `SYNCHRONIZE CACHE` / `CLOSE TRACK SESSION` before
ejecting: on eject the server snapshots the current TOC into an alternating
slot, so the disc restarts Appendable (a host that never issued CLOSE may leave
a partially recorded track).

A CD-RW additionally supports BLANK: Blanking Type 0 (blank all) and 1 (minimal
blank) both return the disc to Blank synchronously and save a fresh TOC slot;
IMMED is accepted because the medium completes before GOOD. After a blank the
next TAO burn starts again at LBA 0, and a finalized CD-RW becomes blank again.
The precedence is fixed: a write-once CD-R answers `24/00`, a read-only
recovery latch answers `07/27`, and an unsupported blanking type `24/00`.
FORMAT UNIT is `24/00` on both kinds (only BLANK changes a CD-RW); BLANK never
zero-fills the medium or deletes a track file: a reused `track_<n>.bin` is
truncated by its first new write at offset 0, so old payload cannot leak into
the new disc. The drive advertises profile `0x0A` (CD-RW) as Current and
`0x09` (CD-R) stays in the supported list. READ HEADER (`0x44`) is deliberately
not implemented: MMC-6 no longer defines it for this command set (it belongs to
packet writing, which the bundle does not model), so it stays `24/00`.

Read the disc back:

```bash
dmesg | tail                  # kernel SCSI/optical messages
isoinfo -d -i /dev/sr0        # PVD: volume id, block size, volume space
blkid /dev/sr0                # ISO9660 signature / label
mount -o ro /dev/sr0 /mnt     # or mount the raw device
```

A blank CD-R or CD-RW reports its ATIP extent in READ CAPACITY, so the block
device is sized for the full disc before the first session and keeps that size
until the disc is finalized. READ TOC formats 0-2 stay `24h/00` while no
complete session exists, which keeps the kernel's last-session probe at LBA 0;
format 4 (ATIP) is independent of session state. The finalize also reports a medium-change
unit attention, although a burner's own `TEST UNIT READY` can consume it first.

READ TOC format 4 answers the ATIP descriptor in every disc state (blank,
appendable and finalized), so `wodim -atip`, `cdrecord -atip` and `cd-info`
work before the first write. The response is the 28-byte block (a 4-byte
header declaring an ATIP Data Length of 26 plus the 24-byte descriptor, no
optional S4 values) with binary, not BCD, M/S/F bytes. The descriptor's
lead-out is the same address READ DISC INFORMATION reports as the last
possible lead-out while the disc is blank or appendable (a finalized disc
reports `FF`), and READ CAPACITY reports that extent minus one while the
disc is not finalized; a finalized disc reports the last recorded LBA. The
ATIP descriptor's disc-type bit distinguishes the media: `0` for CD-R, `1` for
CD-RW (sub-type `0` for both).

The bundle directory holds the durable state:

| Path | Content |
|------|---------|
| `toc.0`, `toc.1` | Alternating TOC slots; the newer valid one wins |
| `track_1.bin`, … | Track payload (`16 + n` storage resource) |

Stop the server and start it again on the same directory to prove the TOC is
re-read (`open_at` checks each slot against its physical index, so a copied
slot is rejected). A `recovery=delete` reopen removes orphan `track_<n>.bin`
files only when the TOC was restored from a readable slot with no skipped
candidate; a file is kept only in its canonical `track_file(n)` spelling when
the TOC references it and the slot can persist it. An unreadable slot disables
cleanup, and a TOC-less directory is never wiped (leftover track files are
counted and reported). `toc.0`/`toc.1` are never touched. A `recovery=readonly`
reopen never deletes anything.

Troubleshooting:

- **Profile** — GET CONFIGURATION must report current profile `0x09` (CD-R)
  or `0x0A` (CD-RW), with `0x21` (Incremental Streaming) and `0x2D` (CD Track
  at Once) Current; `0x20` (Random Writable) and `0x24` (Defect Management)
  are not.
- **`Cannot init drive`** at burn startup — MODE SELECT page 0x05 was
  rejected. It must request Write Type 1 (Track-at-Once), Track Mode 4
  (data) and Data Block Type 8 (Mode 1 / 2048-byte blocks); SAO, packet and
  raw are refused. The Test Write bit (`-dummy`) is accepted and simulated.
- **`SET CD SPEED`** — accepted and remembered, but the emulated drive has
  no spindle to retune; SEND OPC tables are consumed and discarded.
- **TOC corrupt or missing** — the two slots alternate, so a torn save leaves
  the other valid slot usable. An unreadable/malformed slot is an error
  unless the other is valid. A missing directory starts a blank disc with a
  warning; `recovery=readonly` requires an existing TOC and never creates
  one.
- **`recovery=readonly`** — restores the written prefix as complete tracks,
  finalizes the disc and rejects later writes (`WRITE PROTECTED`).
- **Geometry presets** — `medium=cdr74|cdr80|cdr90|cdr99` (write-once CD-R) or
  `medium=cdrw74|cdrw80|cdrw90|cdrw99` (erasable CD-RW), and `slot=<bytes>`
  (4 KiB..64 KiB), only apply to a new blank bundle; the number of track
  files is bounded by `max_tracks_for_slot(slot)`. The presets are the real
  media lead-out addresses (`minutes * 60 * 75 - 151`, so 74 → 332 849,
  80 → 359 849, 90 → 404 849, 99 → 445 349 sectors). The 90- and 99-minute
  presets report a lead-out above MMC's recommended maximum of `79:59:74`,
  like real high-capacity media; their `A1` capacity-extension encoding is not
  modeled.

## Browsing Documentation

```bash
RUSTDOCFLAGS="-D warnings" cargo doc --no-deps --open
```

rustdoc names output directories after the **crate target**, not the
package. Entry points under `target/doc/`:

| Path | Content |
|------|---------|
| `index.html` | workspace overview (all crates) |
| `snowscsi/index.html` | **main API** — SCSI core, iSCSI, USB MSC, CD-ROM |
| `snowscsi_common/index.html` | storage seams (`FlatData`/`FsStorage`) + logging macros |
| `snowscsi_iso9660/index.html` | ISO9660/Joliet live generation |

The `snowscsi-cli` package's binary target carries `doc = false`: its
docs would be an empty shell named `target/doc/snowscsi/` (after the
*bin* target), which only caused confusion.

## Code Coverage

Coverage is measured with [cargo-llvm-cov](https://github.com/taiki-e/cargo-llvm-cov)
(LLVM source-based instrumentation — the compiler's own counters, no ptrace).

```bash
# One-time setup
rustup component add llvm-tools-preview
cargo install cargo-llvm-cov --locked

# Whole workspace (lib + bin + tests)
cargo llvm-cov --workspace

# Lib-only coverage (exclude the thin bin shell)
cargo llvm-cov --workspace --ignore-filename-regex 'snowscsi-cli/src/main.rs'

# HTML report (writes target/llvm-cov-html/)
cargo llvm-cov --workspace --html --output-dir target/llvm-cov-html

# lcov for CI / Codecov (writes target/coverage.lcov)
cargo llvm-cov --workspace --lcov --output-path target/coverage.lcov
```

Baseline (Aug 2026, `cargo llvm-cov --workspace`): **TOTAL ~90% lines**, with
`snowscsi-iso9660/src/live.rs` (99%), `snowscsi/src/scsi/spc.rs` (99%),
`snowscsi/src/iscsi/pdu.rs` (97%) the strongest modules.

Notes:

- `--no-default-features` builds only the always-on `snowscsi-common` module
  (~3%); meaningful feature-matrix runs must enable `--features scsi` etc. on
  `snowscsi`.
- **Pre-existing gap**: `cargo test -p snowscsi --no-default-features
  --features scsi` does not compile (unit tests use `Vec`/`String` without
  pulling in `std`). This predates coverage tooling and is a separate bug.
- Coverage artifacts land under `target/` (already gitignored).

## Pre-commit Workflow

1. `cargo build --workspace`
2. `cargo test --workspace`
3. `cargo fmt --check`
4. `cargo clippy --workspace -- -D warnings`
5. `RUSTDOCFLAGS="-D warnings" cargo doc --no-deps` — rustdoc must stay
   warning-free (broken intra-doc links, links to private items, stale
   paths)
6. `cargo clippy -p snowscsi --features 'scsi,cdrom,iscsi,usb,dvdram,async-io,embassy' --
   -D warnings` — the feature-gated modules are not compiled by the
   workspace-wide pass (dependencies of `snowscsi-tests` are only
   *compiled*, never linted), so lint them explicitly
7. `cargo build -p snowscsi --no-default-features` — the lib must stay
   `no_std`-clean (feature-gated std surface only)
8. `cargo build -p snowscsi --no-default-features --features
   'scsi,cdrom,usb,dvdram,defmt'` — the `defmt` backend must stay buildable
   `no_std` (it is rejected together with `std`; see the guard in
   `snowscsi-common/src/logging.rs`)

## Code Formatting

This project uses `rustfmt` (via `cargo fmt`). No configuration file is required — the default Rust style is used.

## Versioning

This project follows [Semantic Versioning](https://semver.org/).

- **MAJOR** (`X.0.0`) — incompatible API changes
- **MINOR** (`0.X.0`) — new functionality, backward compatible
- **PATCH** (`0.0.X`) — backward compatible bug fixes

### Pre-1.0 policy (current)

While the crate is `0.x`, cargo treats every minor bump as potentially
breaking; we still keep changes reviewable:

- **Exhaustive-by-design enums stay exhaustive.** Protocol-core outcome and
  session enums — `CommandOutcome`, `XferOutcome`, `SessionStep`,
  `SessionNeed`, `BotStepResult`, `StepResult`, `TargetError`,
  `BotTargetError` — deliberately carry **no** `#[non_exhaustive]`: driver
  code matches them totally, and a new variant must be a conscious,
  compiler-enforced migration for every downstream driver.
- Error domains (`MediaError`, `StorageError`, …) may gain variants in
  a minor release; consider `#[non_exhaustive]` when stabilizing toward 1.0.
- Trait additions (new required or default methods on `Lu`, `Device`,
  `Storage`, `HostTransport`, `ScsiDevice`, `FlatData`, …) are breaking while
  `0.x`; batch them and document them under a `BREAKING CHANGE:` footer.

## Legacy C Code

The original C implementation is archived on the `legacy` branch (CMake + Unity).
Check it out for reference:

```bash
git checkout legacy
```
