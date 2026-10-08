# Contributing to SnowDrive

## Project Structure

SCSI device emulation toolkit — a **multi-crate cargo workspace** (resolver = "2").
The old unified `snowdrive` lib+bin crate has been split into focused crates;
the `snowdrive` binary lives in `snowdrive-cli`.

| Component | Crate | Description |
|-----------|-------|-------------|
| **Common** | `snowdrive-common` | Zero-alloc `SeekableStorage` / `FsStorage` seams + unified logging macros (always available, no feature gate) |
| **Disc** | `snowdrive-disc` | ISO9660 + Joliet live-generation algorithms (`live.rs`) |
| **SCSI core** | `snowdrive-scsi` | SCSI core, block/CD-ROM devices (SBC/SPC/MMC), iSCSI target, USB MSC (BOT) core, UDF volume skeleton |
| — storage seams | `snowdrive-scsi::common` (= `snowdrive-common`) | Re-exported `SeekableStorage`/`FsStorage` + logging macros |
| — SCSI | `snowdrive-scsi::scsi` | One `BlockDevice` (disk/cdrom profiles), SPC/SBC layers, file/fs backends, trait-driven LUNs (`ScsiDevice`) |
| — CD-ROM | `snowdrive-scsi::cdrom` | `CdromDrive` + media (`FlatMedia` / `LiveData` / `UdfRwMedia`), full MMC |
| — iSCSI | `snowdrive-scsi::iscsi` | iSCSI PDU codec, connection, target state machine, TCP transport |
| — USB MSC | `snowdrive-scsi::usb` | Bulk-Only Transport core: CBW/CSW codec, `BotIo`/`Gadget` seams, non-blocking `BotSession` state machine |
| — UDF | `snowdrive-scsi::udfrw` (feature `udfrw`) | Pure UDF 2.01 volume skeleton backing `cdrom::udfrw` |
| **CLI** | `snowdrive-cli` (`src/main.rs`) | `snowdrive serve` runs the iSCSI target or the USB MSC (BOT) gadget; `snowdrive mkisofs` generates an ISO image from a directory |
| **Tests** | `snowdrive-tests` (`tests/`) | Integration tests (mock + libiscsi whitebox + ISO cross-validation) |
| **Tools** | `tools/` (not a workspace member) | External Python black-box tests (`ext-test/`) + USB passthrough helper |

```
SnowDrive/                          # cargo workspace (resolver = "2")
├── Cargo.toml                      # workspace: members listed below
├── snowdrive-common/               # crate: storage seams + logging macros
│   ├── Cargo.toml
│   └── src/{lib.rs, seekable_storage.rs, fs_storage.rs, logging.rs}
├── snowdrive-disc/                 # crate: ISO9660/Joliet live-generation algorithms
│   ├── Cargo.toml
│   └── src/{lib.rs, mod.rs, live.rs}
├── snowdrive-scsi/                 # crate: SCSI core + iSCSI + USB MSC + CD-ROM
│   ├── Cargo.toml
│   └── src/
│       ├── lib.rs                 # #![deny(unsafe_code)]; re-exports common + logging macros
│       ├── scsi/                  # feature "scsi": backend, block, device,
│       │                         #            fs_backend, sbc, spc, scsi
│       ├── cdrom/                 # feature "cdrom": common, drive, media,
│       │                         #            udfrw (gated by "udfrw")
│       ├── iscsi/                 # feature "iscsi": conn, pdu, target, transport
│       ├── usb/                   # feature "usb": bot, gadget, io, target
│       └── udfrw.rs            # feature "udfrw": UDF 2.01 volume skeleton
├── snowdrive-cli/                 # crate: `snowdrive` binary (src/main.rs)
│   ├── Cargo.toml                # features: full/std/scsi/udfrw/iscsi/cdrom/livefs/usb/log/defmt
│   └── src/main.rs               # #![forbid(unsafe_code)]; serve + mkisofs subcommands
├── tests/                         # crate: snowdrive-tests (integration tests)
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
snowdrive-cli (bin) ──▶ snowdrive-scsi (lib) ◀──┐
                          ▲                      │
snowdrive-tests ──────────┘                      │
                          │                      │
snowdrive-scsi ──▶ snowdrive-common              │
               └─▶ snowdrive-disc ──▶ snowdrive-common
```

Feature maps:

- **`snowdrive-common`** — `std` (default), `log`, `defmt`. No feature gate on
  the crate itself; the seams are always compiled. `defmt` forwards to
  `embedded-io/defmt` so `embedded_io::ErrorKind` implements `defmt::Format`;
  `std` + `defmt` is rejected at compile time (see below).
- **`snowdrive-disc`** — `std` (default).
- **`snowdrive-scsi`** — `std` (default), `scsi`, `udfrw`,
  `iscsi` (→`scsi`), `cdrom` (→`scsi`),
  `livefs` (→`cdrom`), `usb` (→`scsi`),
  `log`, `defmt`. `defmt` forwards to `embedded-io/defmt` and
  `snowdrive-common/defmt` (no `snowdrive-disc` propagation: that crate has
  no `defmt` feature). `std` + `defmt` is unsupported — `std::io::Error`
  cannot implement `defmt::Format` — and is guarded by a `compile_error!` in
  `snowdrive-common/src/logging.rs` (the `defmt` macro branch is also
  `no_std`-only, so the guard is the single reported error). No
  platform-specific dependencies: the Linux FunctionFS
  USB bridge lives only in `snowdrive-cli`, which declares its own
  Linux-only `usb-gadget`/`bytes` deps under
  `[target.'cfg(target_os = "linux")'.dependencies]`.
- **`snowdrive-cli`** — `full` (default) pulls `std` +
  `scsi`/`udfrw`/`iscsi`/`cdrom`/`livefs`/`usb`/`log` plus
  std-only deps (clap/ctrlc/env_logger). Builds against `snowdrive-scsi` with
  `default-features = false`. The `serve --usb` FunctionFS bridge pulls in the
  Linux-only `usb-gadget` (>= 1.1) and `bytes` crates via
  `[target.'cfg(target_os = "linux")'.dependencies]` — never compiled on other
  targets.
- **`tests`** (`snowdrive-tests`) — depends on `snowdrive-scsi` with
  `std, scsi, iscsi, cdrom, livefs, usb`; enables `has_libiscsi`
  only when the `libiscsi` system library is present (probed in `build.rs`).

`snowdrive-scsi`'s `no_std` surface is feature-gated; without `std` it stays
`no_std`-clean so embedded consumers can pull in only `scsi`/`usb`/`iscsi`.

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

Beyond the cargo suites, `tools/ext-test/` cross-validates the `snowdrive`
binary as a **black box** with independent external tools, driven by pure
standard-library Python (no pytest dependency):

- `tools/ext-test/test_iso.py` — `snowdrive mkisofs` output is read by
  `file`, `isoinfo` (PVD **and** Joliet trees), `7z` and `bsdtar`
  (libarchive); names, sizes and file content must match the source tree.
  Tests skip when a tool is absent.
- `tools/ext-test/test_iscsi_loopback.py` — a real kernel initiator
  (`iscsiadm` + `iscsi_tcp`) logs into `snowdrive serve`, formats the RAM
  disk with ext4, mounts it, writes/reads through the real block layer and
  fsck-checks it. Skipped unless root and the module/daemon are available.
- `tools/ext-test/test_usb_loopback.py` — a real kernel `usb-storage`
  initiator attaches to `snowdrive serve --usb` through a `dummy_hcd`
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
SNOWDRIVE_BIN=./target/debug/snowdrive python3 tools/ext-test/run.py
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

## Browsing Documentation

```bash
RUSTDOCFLAGS="-D warnings" cargo doc --no-deps --open
```

rustdoc names output directories after the **crate target**, not the
package. Entry points under `target/doc/`:

| Path | Content |
|------|---------|
| `index.html` | workspace overview (all crates) |
| `snowdrive_scsi/index.html` | **main API** — SCSI core, iSCSI, USB MSC, CD-ROM |
| `snowdrive_common/index.html` | storage seams (`FlatData`/`FsStorage`) + logging macros |
| `snowdrive_disc/index.html` | ISO9660/Joliet live generation |

The `snowdrive-cli` package's binary target carries `doc = false`: its
docs would be an empty shell named `target/doc/snowdrive/` (after the
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
cargo llvm-cov --workspace --ignore-filename-regex 'snowdrive-cli/src/main.rs'

# HTML report (writes target/llvm-cov-html/)
cargo llvm-cov --workspace --html --output-dir target/llvm-cov-html

# lcov for CI / Codecov (writes target/coverage.lcov)
cargo llvm-cov --workspace --lcov --output-path target/coverage.lcov
```

Baseline (Aug 2026, `cargo llvm-cov --workspace`): **TOTAL ~90% lines**, with
`snowdrive-disc/src/live.rs` (99%), `snowdrive-scsi/src/scsi/spc.rs` (99%),
`snowdrive-scsi/src/iscsi/pdu.rs` (97%) the strongest modules.

Notes:

- `--no-default-features` builds only the always-on `snowdrive-common` module
  (~3%); meaningful feature-matrix runs must enable `--features scsi` etc. on
  `snowdrive-scsi`.
- **Pre-existing gap**: `cargo test -p snowdrive-scsi --no-default-features
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
6. `cargo clippy -p snowdrive-scsi --features 'scsi,cdrom,iscsi,usb,udfrw' --
   -D warnings` — the feature-gated modules are not compiled by the
   workspace-wide pass (dependencies of `snowdrive-tests` are only
   *compiled*, never linted), so lint them explicitly
7. `cargo build -p snowdrive-scsi --no-default-features` — the lib must stay
   `no_std`-clean (feature-gated std surface only)
8. `cargo build -p snowdrive-scsi --no-default-features --features
   'scsi,cdrom,usb,udfrw,defmt'` — the `defmt` backend must stay buildable
   `no_std` (it is rejected together with `std`; see the guard in
   `snowdrive-common/src/logging.rs`)

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
- Trait additions (new required or default methods on `ScsiDevice`,
  `SpcDevice`, `FlatData`, …) are breaking while `0.x`; batch them and
  document them under a `BREAKING CHANGE:` footer.

## Legacy C Code

The original C implementation is archived on the `legacy` branch (CMake + Unity).
Check it out for reference:

```bash
git checkout legacy
```
