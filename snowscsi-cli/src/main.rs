#![forbid(unsafe_code)]
//! `snowscsi` CLI — SnowSCSI SCSI target and ISO9660 image tools
//! (`snowscsi_main.c`).
//!
//! Subcommands:
//! - `serve`: run the iSCSI target (serial accept loop)
//! - `mkisofs`: generate an ISO9660/Joliet image from a host directory
//!   (the live-generation algorithm, dumped sector-by-sector to a file)
//! - `bundle-create`: create a flat or recordable-CD bundle directory
//!   (the **only** creator of its `SNOWBUNDLE` manifest and initial CD-R TOC;
//!   it writes no chunk/track data)
//! - `bundle-info`: report what a bundle directory or image sidecar describes
//! - `crypt`: encrypt or decrypt one regular image file and its
//!   `<file>.SNOWBUNDLE` sidecar
//!
//! Devices are declared with two repeatable flags sharing one grammar
//! (`<backing>[=<value>][,<option>...]`): `--block` and `--cdrom`.
//!
//! - `--block` drives `BlockDevice`: `img=<file>[,ro][,removable][,cipher]`,
//!   `bundle=<dir>` (directory-chunked flat disk from its `SNOWBUNDLE`
//!   manifest; `bundle` feature), `ram=<size>` (K/M/G suffixes), or a
//!   `profile=cd` optical variant (read-only PDT 0x05, 2048 B sectors).
//!   `removable` (USB only, `img=` only) is the card-reader demo.
//! - `--cdrom` drives the core `MmcDrive` profile (full MMC): `img=<iso>`,
//!   `live=<dir>` (live ISO9660 over a directory),
//!   `dvdram=<path|ram:<size>>[,size=…]` (blank random-writable DVD-RAM;
//!   `size=` creates a new zeroed file — the host formats it, the device
//!   never writes file-system structures), `bundle=<dir>` (a flat ISO or a
//!   persistent CD-R/CD-RW bundle; the manifest's `kind` selects the backing,
//!   and a recordable bundle's `toc.0`/`toc.1` plus `track_<n>.bin` live in
//!   the directory), or `empty` (an enumerated drive with no medium; the
//!   application installs the first one). Recordable bundles are written only
//!   in Track-at-Once: `wodim -tao` (also `-audio` for CD-DA and `-multi` for
//!   another session) and, on a CD-RW, `wodim blank=fast|all`. SAO/DAO is not
//!   implemented.
//!
//! `cipher` on an `img=` or `bundle=` LUN reads the manifest (the
//! `<file>.SNOWBUNDLE` sidecar, `<dir>/SNOWBUNDLE`, or an explicit
//! `cipher=<path>`), turns the global password (`--password-file`, or stdin
//! **with echo**) or `key=<path>` into the KEK that unwraps the manifest's
//! volume master key, and serves the bytes through the cipher plane. It is
//! never a plaintext fallback: a missing,
//! malformed or cipher-less manifest is a hard error. A recordable-CD bundle
//! encrypts only its track resources (`nonce XOR resource`); the
//! `toc.0`/`toc.1` slots stay plaintext, so capacity and sessions are visible
//! without a key.
//!
//! `serve` never creates the bundle directory or manifest: `snowscsi
//! bundle-create flat …` or `snowscsi bundle-create cdr …` must create them
//! first (serving does create chunk/track files and write TOC snapshots).
//! All backing keys are explicit — there is no bare-value or suffix
//! auto-typing. Unknown or duplicate options are rejected. LUN numbering is
//! all `--block` devices first, then all `--cdrom` devices (the two planes
//! cannot interleave). The same host path may appear on several LUNs; each
//! is an independent SCSI device with its own LBA semantics, so a dual-mount
//! warning is printed to stderr. SIGINT / SIGTERM trigger a graceful
//! shutdown: the blocking `accept()` is woken by a probe connection, the async
//! loop by a runtime notification, the serve call returns, and every store
//! plane is `sync()`ed before exit.

#[cfg(feature = "cipher")]
mod cipher;
mod spec;
mod stack;

use std::fs::File;
use std::io::{BufWriter, Write};
use std::net::{SocketAddr, TcpListener};
use std::path::Path;
#[cfg(feature = "cipher")]
use std::path::PathBuf;
#[cfg(target_os = "linux")]
use std::process::Command;
use std::process::ExitCode;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::thread::JoinHandle;
#[cfg(target_os = "linux")]
use std::time::Duration;

use clap::{Args, Parser};
use snowscsi::block::{BlockAttrs, BlockDevice as CoreBlockDevice};
#[cfg(feature = "bundle")]
use snowscsi::bundle::{identify_dir, identify_manifest, Identified};
#[cfg(feature = "dvdram")]
use snowscsi::cdrom::media::LiveData;
#[cfg(any(feature = "bundle", feature = "cipher"))]
use snowscsi::common::bundle::CipherAlg;
#[cfg(feature = "cipher")]
use snowscsi::common::bundle::CipherMeta;
#[cfg(any(feature = "bundle", feature = "cipher"))]
use snowscsi::common::bundle::KdfKind;
#[cfg(feature = "bundle")]
use snowscsi::common::bundle::MANIFEST_NAME;
#[cfg(any(feature = "bundle", feature = "cdr-bundle", feature = "cipher"))]
use snowscsi::common::bundle::{BundleKind, BundleMeta};
#[cfg(any(feature = "bundle", feature = "cipher"))]
use snowscsi::common::bundle::{MAX_MANIFEST, SIDECAR_SUFFIX};
#[cfg(all(feature = "bundle", feature = "cipher"))]
use snowscsi::common::cipher::CipherPlane;
#[cfg(feature = "bundle")]
use snowscsi::common::flat_bundle::{validate_geometry, FlatBundle};
#[cfg(all(feature = "bundle", feature = "cdr-bundle"))]
use snowscsi::common::fs_plane::FsPlaneAdapter;
use snowscsi::common::seekable_storage::FlatData;
#[cfg(feature = "tokio")]
use snowscsi::common::seekable_storage::StorageError;
#[cfg(feature = "tokio")]
use snowscsi::core::slots::{SlotPool, SlotTask};
#[cfg(feature = "tokio")]
use snowscsi::core::storage::IoReq;
use snowscsi::core::storage::Storage;
#[cfg(feature = "tokio")]
use snowscsi::core::Direction;
use snowscsi::core::{Lu, Spc, Writability};
use snowscsi::iscsi::pdu::BHS_SIZE;
#[cfg(feature = "tokio")]
use snowscsi::iscsi::target::IscsiSession;
#[cfg(feature = "tokio")]
use snowscsi::iscsi::target::TargetError;
#[cfg(feature = "tokio")]
use snowscsi::iscsi::transport::serve_conn_async;
use snowscsi::iscsi::transport::{serve_with_release, DEFAULT_READ_TIMEOUT};
#[cfg(feature = "cdr-bundle")]
use snowscsi::mmc::cdr_bundle::{
    toc_file, CdrBundleMedium, CdrCapacity, DiscKind, TOC_SLOT_DEFAULT, TOC_SLOT_MAX, TOC_SLOT_MIN,
};
#[cfg(feature = "dvdram")]
use snowscsi::mmc::DvdRamMedium;
use snowscsi::mmc::{FlatCdMedium, MmcDrive};
use snowscsi::scsi::backend::FileBackend;
use snowscsi::scsi::fs_backend::StdFsBackend;
use snowscsi::{MIN_DATA_AREA, MIN_DATA_LEN};
use spec::{Backing, DeviceRole, DeviceSpec};
#[cfg(feature = "tokio")]
use stack::tokio_conn::TokioConn;
use stack::worker::WorkerStore;
#[cfg(all(feature = "bundle", feature = "cdr-bundle"))]
use stack::BundleStore;
#[cfg(all(feature = "bundle", feature = "cdr-bundle"))]
use stack::CdrStore;
use stack::{CliLu, CliMedium, CliPair, CliStorage, OwnedPlane};
#[cfg(feature = "tokio")]
use tokio::io::{AsyncReadExt, AsyncSeekExt, AsyncWriteExt};

#[cfg(target_os = "linux")]
use snowscsi::usb::{
    serve as usb_serve, BotIo, BotIoErr, BotSession, CtrlAck, CtrlReply, CtrlReq, Gadget,
    ShortfallPolicy,
};
#[cfg(target_os = "linux")]
use usb_gadget::function::custom::{
    CtrlReceiver, CtrlSender, Custom, Endpoint, EndpointDirection, EndpointReceiver,
    EndpointSender, Event, Interface,
};
#[cfg(target_os = "linux")]
use usb_gadget::{udcs, Class, Config, Gadget as UsbGadget, Id, Strings, Udc};

/// Default work buffer size (1 MiB).
///
/// The core devices publish the whole host transfer as one data plan and read
/// it from (or write it into) the caller's bank, so the bank must cover the
/// largest host transfer the initiator issues; 1 MiB covers the kernel's
/// default iSCSI transfer cap.
const DEFAULT_WORK_BUF_SIZE: usize = 1024 * 1024;
/// Default `work` total for USB dual-bank mode (two equal 8 KiB banks).
///
/// `--banks dual` treats `--work-buf-size` as the **total** of two banks, so
/// this stays at 16 KiB: larger halves buy no prefetch benefit over the USB
/// wire chunk while doubling the cache footprint of the session.
const DUAL_WORK_BUF_SIZE: usize = 16 * 1024;
/// Default `work` total for iSCSI dual-bank mode: two `BHS_SIZE + 8192` banks.
///
/// Each bank carries its own 48-byte BHS prefix, so the two-bank total is
/// 2 × 8240 = 16480; this is also the minimum (two `MIN_DATA_LEN` data areas).
const ISCSI_DUAL_WORK_BUF_SIZE: usize = 2 * (MIN_DATA_LEN + BHS_SIZE);
/// CD-ROM logical sector size (Mode 1 data).
const ISO_SECTOR_SIZE: u32 = 2048;

/// USB bulk endpoint maximum packet size (high-speed). FunctionFS aio reads
/// require an MPS-multiple buffer.
#[cfg(target_os = "linux")]
const USB_MPS: usize = 512;

#[derive(Debug, Parser)]
#[command(
    name = "snowscsi",
    about = "SnowSCSI SCSI target and ISO9660 tools",
    version
)]
enum Cli {
    /// Start the iSCSI target server
    Serve(ServeArgs),
    /// Generate an ISO9660/Joliet image from a directory
    Mkisofs(MkisofsArgs),
    /// Report the manifest (and CD-R TOC, when present) of a bundle
    BundleInfo(BundleInfoArgs),
    /// Create a flat or recordable-CD bundle directory
    BundleCreate(BundleCreateArgs),
    /// Encrypt or decrypt a single image file and its `SNOWBUNDLE` sidecar
    #[cfg(feature = "cipher")]
    Crypt(CryptArgs),
    /// Re-wrap the volume master key under a new password/key file
    #[cfg(feature = "cipher")]
    Rekey(RekeyArgs),
}

/// Host transport execution model.
#[derive(Clone, Copy, Debug, PartialEq, Eq, clap::ValueEnum)]
enum Wire {
    /// Run the transport loop on the calling thread.
    Blocking,
    /// Run the transport loop on the caller's asynchronous executor.
    Async,
}

impl Wire {
    const fn as_str(self) -> &'static str {
        match self {
            Self::Blocking => "blocking",
            Self::Async => "async",
        }
    }
}

/// Number of data banks carved out of `work`.
#[derive(Clone, Copy, Debug, PartialEq, Eq, clap::ValueEnum)]
enum Banks {
    /// One bank shared by the command path and the resident long operation.
    Single,
    /// Two equal banks inside `work`.
    Dual,
}

impl Banks {
    const fn as_str(self) -> &'static str {
        match self {
            Self::Single => "single",
            Self::Dual => "dual",
        }
    }
}

#[derive(Args, Debug)]
#[command(group = clap::ArgGroup::new("transport").required(true).multiple(false))]
struct ServeArgs {
    /// Block device (`BlockDevice`): `img=<file>[,ro][,removable]`,
    /// `ram=<size>`, `bundle=<dir>` (a directory-chunked flat disk described
    /// by its `SNOWBUNDLE` manifest; create it with `snowscsi bundle-create
    /// flat`), or `img=<file>,profile=cd` / `bundle=<dir>,profile=cd`
    /// (read-only optical profile). `removable` is a USB card-reader demo:
    /// `--block img=<file>,removable` reports RMB and lets the host eject the
    /// card; replacing the file installs a new card at the same LUN.
    /// Add `,cipher` (and optionally `,key=<path>`) to serve an encrypted
    /// image or flat bundle (`--password-file`, or an echoed stdin prompt).
    /// Repeatable; `--block` LUNs come first in declaration order.
    #[arg(long = "block", value_name = "SPEC")]
    block: Vec<String>,

    /// CD-ROM device (core `MmcDrive`, full MMC): `img=<iso>`, `live=<dir>`
    /// (live ISO9660 over a directory), `dvdram=<path|ram:<size>>[,size=…]`
    /// (random-writable DVD-RAM), `bundle=<dir>` (a directory carrying a
    /// `SNOWBUNDLE` manifest: `kind = flat` serves a flat ISO, `kind = cdr`
    /// serves a persistent CD-R/CD-RW whose `toc.0`/`toc.1` and
    /// `track_<n>.bin` live in the directory), or `empty` (an enumerated
    /// drive with no medium). `serve` never creates the bundle directory,
    /// manifest or TOC: create it with `snowscsi bundle-create flat` or
    /// `snowscsi bundle-create cdr` first (serving does create chunk/track
    /// files and write TOC snapshots).
    /// A recordable bundle is written only in Track-at-Once: `wodim -tao`
    /// (also `-audio` for CD-DA and `-multi` for another session) and, on a
    /// CD-RW, `wodim blank=fast|all`; SAO/DAO is not implemented. Add
    /// `,cipher` to an `img=` or `bundle=` LUN to serve it encrypted; on a
    /// recordable bundle only the track resources are encrypted (the
    /// `toc.0`/`toc.1` slots stay readable without a key).
    /// Repeatable; these LUNs follow the `--block` LUNs.
    #[arg(long = "cdrom", value_name = "SPEC")]
    cdrom: Vec<String>,

    /// iSCSI listen address (ADDR:PORT) or `auto` for loopback auto-config
    /// (127.0.0.1:3260, fallback to ephemeral, plus open-iscsi login to
    /// expose a block device). Mutually exclusive with `--usb`; exactly one
    /// transport is required.
    #[arg(long = "iscsi", value_name = "ADDR:PORT|auto", group = "transport")]
    iscsi: Option<String>,

    /// Serve the devices over USB Mass Storage (Bulk-Only Transport) by
    /// binding a FunctionFS gadget to a UDC (Linux only). Mutually
    /// exclusive with `--iscsi`. Optional UDC selector: `auto` (default —
    /// prefer a real controller over the test-only `dummy_udc`), `dummy`
    /// (auto-load `dummy_hcd`, ensure configfs and bind `dummy_udc.0`), a
    /// UDC name, or a driver prefix.
    #[arg(
        long = "usb",
        num_args = 0..=1,
        default_missing_value = "auto",
        group = "transport"
    )]
    usb: Option<String>,

    /// Data-In shortfall policy for `--usb`: `short` (default; conformant:
    /// short packet + STALL Bulk-In, then the CSW once the host clears the
    /// halt), `pad` (conformant: fill zeros to `dCBWDataTransferLength`,
    /// capped — needs no control plane), or `short-no-stall` (max-compat: plain
    /// short packet, no STALL).
    #[arg(long = "usb-shortfall", value_name = "MODE", default_value = "short")]
    usb_shortfall: String,

    /// USB vendor ID (hex).
    #[arg(long = "vid", value_name = "VID", default_value = "1209", value_parser = parse_hex_u16)]
    vid: u16,

    /// USB product ID (hex).
    #[arg(long = "pid", value_name = "PID", default_value = "0001", value_parser = parse_hex_u16)]
    pid: u16,

    /// USB serial number.
    #[arg(long = "serial", value_name = "SERIAL", default_value = "SNOWSCSI")]
    serial: String,

    /// Verbose logging: -v = debug, -vv = trace.
    #[arg(long, short, action = clap::ArgAction::Count)]
    verbose: u8,

    /// Work buffer size in bytes (accepts K/M/G suffixes; minimum 8240 for
    /// iSCSI, 512 for USB; default 1M). It bounds one data chunk, not the
    /// transfer: the SCSI data area is this size minus the 48-byte iSCSI BHS,
    /// and a larger READ/WRITE is streamed in bank-sized chunks rather than
    /// rejected. With `--banks single` this is the one bank; with `--banks
    /// dual` it is the **total** of two equal banks (USB default 16K, iSCSI
    /// default 16480).
    #[arg(long = "work-buf-size", value_name = "BYTES")]
    work_buf_size: Option<String>,

    /// Host transport execution: `blocking` (default) or `async`.
    ///
    /// `async` runs the iSCSI accept and session loops on a Tokio runtime and
    /// needs this build's `tokio` feature. USB has no asynchronous endpoint
    /// adapter yet, so `--wire async --usb` is rejected before any setup. The
    /// async path has no idle read timeout: an open but idle connection parks
    /// the serial accept loop.
    #[arg(long = "wire", value_name = "MODE", default_value = "blocking")]
    wire: Wire,

    /// Split `work` into two equal banks (`--work-buf-size` is the total in
    /// this mode) or keep one bank.
    ///
    /// `dual` enables prefetching the next chunk into the alternate bank while
    /// the current one is on the wire, and gives the resident long operation
    /// its own bank. With a blocking wire the storage runs on per-LUN worker
    /// threads; with `--wire async` over file or memory LUNs the library slot
    /// pool drives it in the wire's own task (`--print-config` reports which:
    /// `storage=pool|worker|inline`).
    /// The total must be even; each half must clear its transport's floor (512
    /// bytes for USB, 8240 with a 4-aligned data area for iSCSI). Defaults:
    /// USB 16K, iSCSI 16480. Cannot be combined with `--scratch-buffer`.
    #[arg(long = "banks", value_name = "MODE", default_value = "single")]
    banks: Banks,

    /// Print the resolved configuration as one line and exit 0 (`bundle=`
    /// directories are validated, but no transport is started).
    #[arg(long = "print-config")]
    print_config: bool,

    /// Password for encrypted (`cipher`) LUNs, read from a file (one line,
    /// at most 1024 bytes). The password is global to every encrypted LUN;
    /// each manifest supplies its own salt and nonce. Without this flag the
    /// password is read from stdin: prompted on a terminal (echo enabled —
    /// there is no termios dependency) or a single line from a pipe. `--help`
    /// warns that a terminal echo is visible.
    #[arg(long = "password-file", value_name = "PATH")]
    password_file: Option<String>,

    /// Allocate a separate long-operation buffer (`--banks single` only).
    ///
    /// By default one buffer is shared: a query waits at most one
    /// long-operation chunk. With this flag the resident long operation gets
    /// its own bank (rounded up to at least 8192 bytes, default 1M), so
    /// queries stay serviceable while it runs.
    #[arg(
        long = "scratch-buffer",
        value_name = "BYTES",
        num_args = 0..=1,
        default_missing_value = "1M"
    )]
    scratch_buffer: Option<String>,
}

/// Arguments for `snowscsi mkisofs`: build an ISO9660/Joliet image from a
/// host directory (the live-generation algorithm dumped to a file).
#[derive(Args, Debug)]
struct MkisofsArgs {
    /// Source directory to scan into the image.
    #[arg(value_name = "DIR")]
    dir: String,
    /// Output ISO image file path.
    #[arg(value_name = "OUT.iso")]
    out: String,
    /// Volume label (default: the source directory name, max 16 chars).
    #[arg(long, value_name = "NAME")]
    label: Option<String>,
    /// Verbose logging: -v = debug, -vv = trace.
    #[arg(long, short, action = clap::ArgAction::Count)]
    verbose: u8,
}

/// Arguments for `snowscsi bundle-info`: classify a bundle directory or a
/// single-file image's `<path>.SNOWBUNDLE` sidecar.
#[derive(Args, Debug)]
struct BundleInfoArgs {
    /// Bundle directory, or image file whose `<path>.SNOWBUNDLE` is read.
    #[arg(value_name = "PATH")]
    path: String,
}

/// Arguments for `snowscsi bundle-create`.
#[derive(Args, Debug)]
struct BundleCreateArgs {
    #[command(subcommand)]
    kind: BundleCreateKind,
}

/// The two bundle families `bundle-create` can write.
#[derive(clap::Subcommand, Debug)]
enum BundleCreateKind {
    /// Create a directory-chunked flat bundle (`kind = flat`)
    Flat(CreateFlatArgs),
    /// Create a recordable CD bundle (`kind = cdr`) with its initial TOC
    Cdr(CreateCdrArgs),
}

/// Arguments for `bundle-create flat`.
#[derive(Args, Debug, Default)]
struct CreateFlatArgs {
    /// Bundle directory (created when missing).
    #[arg(long, value_name = "DIR")]
    dir: String,
    /// Logical device size (accepts K/M/G suffixes).
    #[arg(long, value_name = "SIZE")]
    size: String,
    /// Chunk file size (accepts K/M/G suffixes; default 100 MiB).
    #[arg(long, value_name = "BYTES")]
    chunk: Option<String>,
    /// Logical sector size (512 or 2048; default 512).
    #[arg(long, value_name = "512|2048", default_value = "512")]
    sector: u32,
    /// Encrypt the bundle: `chacha8`, `chacha12`, `chacha20`, `aes-ctr`, or
    /// `xor` (obfuscation only). Without this flag the manifest is plaintext.
    /// An encrypted bundle needs `--password-file`, `--key-file`, or a
    /// two-line password prompt. Change credentials later with `rekey`;
    /// rebuilding a bundle means deleting its directory.
    #[cfg(feature = "cipher")]
    #[arg(long, value_name = "ALG")]
    cipher: Option<String>,
    /// PBKDF2-HMAC-SHA256 iteration count (1000..=2000000; default 600000).
    #[cfg(feature = "cipher")]
    #[arg(long, value_name = "N")]
    iterations: Option<u32>,
    /// Raw 32-byte key file; selects `kdf = none` (no password; the keyslot
    /// still gets a fresh salt).
    #[cfg(feature = "cipher")]
    #[arg(long = "key-file", value_name = "PATH")]
    key_file: Option<String>,
    /// Encrypt the bundle under this password file (one line). The password
    /// is used to wrap the volume master key; it is never stored.
    #[cfg(feature = "cipher")]
    #[arg(long = "password-file", value_name = "PATH")]
    password_file: Option<String>,
}

/// Arguments for `bundle-create cdr`.
#[derive(Args, Debug, Default)]
struct CreateCdrArgs {
    /// Bundle directory (created when missing).
    #[arg(long, value_name = "DIR")]
    dir: String,
    /// Blank disc preset (default cdr80).
    #[arg(long, value_name = "MEDIUM")]
    medium: Option<String>,
    /// TOC slot size in bytes (accepts K/M/G suffixes; default 64 KiB).
    #[arg(long, value_name = "BYTES")]
    slot: Option<String>,
    /// Encrypt the bundle: `chacha8`, `chacha12`, `chacha20`, `aes-ctr`, or
    /// `xor` (obfuscation only). The CD-R TOC stays plaintext; track payloads
    /// are encrypted per resource. Needs `--password-file`, `--key-file`, or a
    /// two-line password prompt; serve it with the same credential. Change
    /// credentials later with `rekey`; rebuilding means deleting the directory.
    #[cfg(feature = "cipher")]
    #[arg(long, value_name = "ALG")]
    cipher: Option<String>,
    /// PBKDF2-HMAC-SHA256 iteration count (1000..=2000000; default 600000).
    #[cfg(feature = "cipher")]
    #[arg(long, value_name = "N")]
    iterations: Option<u32>,
    /// Raw 32-byte key file; selects `kdf = none` (no password; the keyslot
    /// still gets a fresh salt).
    #[cfg(feature = "cipher")]
    #[arg(long = "key-file", value_name = "PATH")]
    key_file: Option<String>,
    /// Encrypt the bundle under this password file (one line). The password
    /// is used to wrap the volume master key; it is never stored.
    #[cfg(feature = "cipher")]
    #[arg(long = "password-file", value_name = "PATH")]
    password_file: Option<String>,
}

/// Arguments for `snowscsi crypt`.
///
/// Encryption writes `<out>` plus `<out>.SNOWBUNDLE`; `--in-place` writes the
/// sidecar first and then replaces `<in>`. Decryption reads `<in>.SNOWBUNDLE`,
/// validates its image size, and writes plaintext to `<out>` (never a
/// sidecar). The manifest carries the only copy of the keyslot that unwraps
/// the volume master key: keep it with the data and back it up.
///
/// The keyslot tag detects a wrong credential before any output is written.
/// There is **no payload authentication**: a tampered ciphertext still exits 0
/// and writes garbage plaintext. Keep the input until the result is verified.
#[cfg(feature = "cipher")]
#[derive(Args, Debug)]
#[command(
    after_help = "SECURITY: the keyslot tag rejects a wrong password/key or a tampered manifest \
before any output is written, but the payload itself is unauthenticated: a tampered ciphertext \
still produces garbage output with exit status 0. Keep the input and verify the result before \
deleting anything. The <out>.SNOWBUNDLE manifest is the only copy of the key material; back it up \
with the image. Crypt operations take an exclusive `<target>.lock` file next to the target; a \
crash can leave a stale lock (remove it if no process is running). Temporary files are created with \
mode 0600 where the platform supports it; SIGKILL can leave one behind. --force may replace an \
existing output only when it has no <out>.SNOWBUNDLE sidecar."
)]
struct CryptArgs {
    /// Decrypt `<in>` using its required `<in>.SNOWBUNDLE` sidecar. The
    /// manifest, not a flag, selects the cipher; its `kind = image` size must
    /// match `<in>` before any plaintext is written. A wrong password or a
    /// tampered keyslot fails before output; a tampered ciphertext still exits
    /// 0 and writes garbage (the payload is not authenticated).
    #[arg(long)]
    decrypt: bool,
    /// Cipher for encryption (`chacha8`, `chacha12`, `chacha20`, `aes-ctr`,
    /// or `xor`). Required unless `--decrypt` is given. `xor` is obfuscation
    /// only and is reported as such.
    #[arg(long, value_name = "ALG")]
    cipher: Option<String>,
    /// Read one password line from this file (default: prompt on stdin; with
    /// echo on a terminal). Encryption confirms the password twice unless a
    /// key file or this flag is used. Only used when the manifest's `kdf` is
    /// PBKDF2; `kdf = none` requires `--key-file`.
    #[arg(long = "password-file", value_name = "PATH")]
    password_file: Option<String>,
    /// Use a raw 32-byte key file instead of a password (`kdf = none`). This
    /// is required (never prompted for) when the manifest's `kdf` is `none`.
    /// For encryption a wrong-length or missing file is rejected before any
    /// output is written.
    #[arg(long = "key-file", value_name = "PATH")]
    key_file: Option<String>,
    /// PBKDF2-HMAC-SHA256 iteration count (1000..=2000000; default 600000).
    /// Mutually exclusive with `--key-file` and rejected with `--decrypt`.
    #[arg(long, value_name = "N")]
    iterations: Option<u32>,
    /// Encrypt `<in>` in place: write `<in>.SNOWBUNDLE` first, then replace
    /// `<in>` atomically. Refused when the sidecar already exists, when the
    /// input is a symlink, or when it has multiple hard links. The input's
    /// permissions are copied to the replacement; owner, xattrs and ACLs are
    /// not preserved. Cannot be combined with `--force`.
    #[arg(long = "in-place")]
    in_place: bool,
    /// Overwrite an existing `<out>` **only** when it has no
    /// `<out>.SNOWBUNDLE`. An existing sidecar is always refused (it is the
    /// only copy of that image's key material). Cannot be combined with
    /// `--in-place`.
    #[arg(long)]
    force: bool,
    /// Input image file (must be a regular file).
    #[arg(value_name = "IN")]
    input: String,
    /// Output image file (required unless `--in-place`).
    #[arg(value_name = "OUT")]
    output: Option<String>,
}

/// `snowscsi rekey` — re-wrap the VMK under a new password/key file.
///
/// Only the keyslot changes: the data cipher, data nonce, geometry and image
/// bytes are untouched. A wrong old credential fails before writing. Old
/// manifest copies remain alternate keyslots for the same VMK; destroy them to
/// revoke a credential, or re-encrypt if the VMK itself leaked.
#[cfg(feature = "cipher")]
#[derive(Args, Debug)]
struct RekeyArgs {
    /// Image file (`<path>.SNOWBUNDLE`), bundle directory (`SNOWBUNDLE`), or a
    /// direct `*.SNOWBUNDLE` path.
    #[arg(value_name = "PATH")]
    path: String,
    /// Password file for the current keyslot (PBKDF2 only).
    #[arg(long = "current-password-file", value_name = "PATH")]
    current_password_file: Option<String>,
    /// Password file for the new keyslot (PBKDF2 only).
    #[arg(long = "new-password-file", value_name = "PATH")]
    new_password_file: Option<String>,
    /// 32-byte key file for the current keyslot (`kdf = none` only).
    #[arg(long = "current-key-file", value_name = "PATH")]
    current_key_file: Option<String>,
    /// 32-byte key file for the new keyslot (selects `kdf = none`).
    #[arg(long = "new-key-file", value_name = "PATH")]
    new_key_file: Option<String>,
    /// PBKDF2 iteration count for the new keyslot (1000..=2000000; default
    /// 600000). Rejected with `--new-key-file`.
    #[arg(long = "new-iterations", value_name = "N")]
    new_iterations: Option<u32>,
}

fn main() -> ExitCode {
    match Cli::parse() {
        Cli::Serve(args) => run_serve(args),
        Cli::Mkisofs(args) => run_mkisofs(args),
        Cli::BundleInfo(args) => run_bundle_info(args),
        Cli::BundleCreate(args) => run_bundle_create(args),
        #[cfg(feature = "cipher")]
        Cli::Crypt(args) => run_crypt(args),
        #[cfg(feature = "cipher")]
        Cli::Rekey(args) => run_rekey(args),
    }
}

/// Resolved serve configuration: the two switches plus the buffers they imply.
#[derive(Debug)]
struct ServeConfig {
    wire: Wire,
    banks: Banks,
    /// `work` total: the one bank for `single`, two equal banks for `dual`.
    work_size: usize,
    /// Separate long-operation bank (`single` only).
    scratch_len: Option<usize>,
}

impl ServeConfig {
    /// Bytes of one bank: all of `work` for `single`, one half for `dual`.
    fn per_bank(&self) -> usize {
        match self.banks {
            Banks::Single => self.work_size,
            Banks::Dual => self.work_size / 2,
        }
    }

    /// Whether the transport sessions run in two-bank mode.
    fn overlap(&self) -> bool {
        self.banks == Banks::Dual
    }

    /// Storage execution model derived from the two switches.
    ///
    /// `pool` is the caller's answer to "can the library slot pool drive these
    /// LUNs?": a dual-bank async session over file or memory planes runs
    /// storage in the same task as the wire, everything else needs the
    /// thread-bridged worker or the inline adapter.
    fn storage(&self, pool: bool) -> &'static str {
        match (self.wire, self.banks) {
            (Wire::Async, Banks::Dual) if pool => "pool",
            (_, Banks::Dual) => "worker",
            (_, Banks::Single) => "inline",
        }
    }

    /// The stable one-line `--print-config` rendering.
    fn line(&self, lun: usize, backing: &str, pool: bool) -> String {
        format!(
            "wire={} banks={} storage={} per_bank={} work={} scratch={} lun={lun} backing={backing}",
            self.wire.as_str(),
            self.banks.as_str(),
            self.storage(pool),
            self.per_bank(),
            self.work_size,
            self.scratch_len.unwrap_or(0),
        )
    }
}

#[allow(clippy::needless_return)]
fn run_serve(args: ServeArgs) -> ExitCode {
    init_logging(args.verbose);

    // Resolve and validate the switches before any listener bind or gadget
    // setup.
    let config = match resolve_config(&args) {
        Ok(c) => c,
        Err(msg) => {
            eprintln!("snowscsi: {msg}");
            return ExitCode::FAILURE;
        }
    };

    // The device pipeline is shared by both transports: parse the specs,
    // validate sources, allocate RAM disks and build the LUN list.
    let specs = match spec::parse_all(&args.block, &args.cdrom) {
        Ok(s) => s,
        Err(msg) => {
            eprintln!("snowscsi: {msg}");
            return ExitCode::FAILURE;
        }
    };
    // The return value is only consumed by the USB loop; validate on every
    // platform so a non-Linux `--usb` build still rejects bad combinations
    // without an unused-variable warning.
    #[cfg(target_os = "linux")]
    let removable_lun = match validate_removable(&args, &specs, &config) {
        Ok(lun) => lun,
        Err(msg) => {
            eprintln!("snowscsi: {msg}");
            return ExitCode::FAILURE;
        }
    };
    #[cfg(not(target_os = "linux"))]
    if let Err(msg) = validate_removable(&args, &specs, &config) {
        eprintln!("snowscsi: {msg}");
        return ExitCode::FAILURE;
    }
    if args.print_config {
        if validate_bundle_specs(&specs).is_err() {
            return ExitCode::FAILURE;
        }
        println!(
            "{}",
            config.line(
                specs.len(),
                &backing_names(&specs),
                pool_capable(&specs, &config)
            )
        );
        return ExitCode::SUCCESS;
    }

    // Password handling happens after `--print-config` (which must not
    // prompt) and before any plane is built. A password is only needed when an
    // encrypted LUN has no `key=` file.
    let mut password = match read_serve_password(&args, &specs) {
        Ok(password) => password,
        Err(msg) => {
            eprintln!("snowscsi: {msg}");
            return ExitCode::FAILURE;
        }
    };

    // Both transports drive the seam-first core `Target`: only one transport
    // is selected at a time.
    if args.usb.is_none() {
        run_serve_iscsi(args, &specs, &config, &mut password)
    } else {
        #[cfg(target_os = "linux")]
        {
            let selector = args.usb.as_deref().unwrap_or("auto");
            run_serve_usb(
                &args,
                &specs,
                &config,
                selector,
                removable_lun,
                &mut password,
            )
        }
        #[cfg(not(target_os = "linux"))]
        {
            if let Some(bytes) = password.as_mut() {
                crate::wipe(bytes);
            }
            eprintln!("snowscsi: --usb is only supported on Linux");
            ExitCode::FAILURE
        }
    }
}

/// Resolve the (single, global) password for encrypted LUNs.
///
/// `None` means no encrypted LUN needs one: either there is no `cipher` LUN or
/// every encrypted LUN supplies `key=<path>`. `--password-file` with no
/// encrypted LUN is a configuration error rather than a silent no-op.
fn read_serve_password(args: &ServeArgs, specs: &[DeviceSpec]) -> Result<Option<Vec<u8>>, String> {
    let any_cipher = specs.iter().any(|spec| spec.cipher.is_some());
    let needs_password = specs
        .iter()
        .any(|spec| spec.cipher.is_some() && spec.key.is_none());
    match args.password_file.as_deref() {
        Some(path) => {
            if !any_cipher {
                return Err("--password-file was given but no LUN uses cipher".to_string());
            }
            if !needs_password {
                return Err(
                    "--password-file was given but every encrypted LUN uses key=<path>".to_string(),
                );
            }
            read_password_file(path).map(Some)
        }
        None if needs_password => read_password_prompt().map(Some),
        None => Ok(None),
    }
}

/// Best-effort overwrite of secret bytes.
///
/// This is **not** `zeroize`: the compiler is only discouraged from eliding
/// the store, copies made elsewhere are untouched, and the operating system may
/// have swapped or logged the memory. It exists so a password/key buffer does
/// not stay in a live stack frame for the rest of the process.
pub(crate) fn wipe(bytes: &mut [u8]) {
    bytes.fill(0);
    core::hint::black_box(bytes);
}

/// Maximum accepted password length (bytes, after one trailing newline).
const MAX_PASSWORD: usize = 1024;

/// Read one password line from `path`.
fn read_password_file(path: &str) -> Result<Vec<u8>, String> {
    use std::io::Read as _;

    let file = File::open(path).map_err(|e| format!("cannot read password file '{path}': {e}"))?;
    let mut bytes = Vec::new();
    // Read two extra bytes so a maximum-length password followed by CRLF is
    // accepted while a line one byte too long is still detected.
    file.take(MAX_PASSWORD as u64 + 2)
        .read_to_end(&mut bytes)
        .map_err(|e| format!("cannot read password file '{path}': {e}"))?;
    strip_password_newline(&mut bytes);
    if bytes.len() > MAX_PASSWORD {
        return Err(format!(
            "password file '{path}' is larger than {MAX_PASSWORD} bytes"
        ));
    }
    if bytes.iter().any(|&b| b == b'\n' || b == b'\r') {
        return Err(format!(
            "password file '{path}' must contain one line without embedded newlines"
        ));
    }
    if bytes.contains(&0) {
        return Err(format!("password file '{path}' contains a NUL byte"));
    }
    if bytes.is_empty() {
        return Err(format!("password file '{path}' is empty"));
    }
    Ok(bytes)
}

/// Read one password line from stdin.
///
/// On a terminal the prompt echoes (no termios dependency); a pipe is read
/// without a prompt. The line is capped at [`MAX_PASSWORD`].
fn read_password_prompt() -> Result<Vec<u8>, String> {
    use std::io::{BufRead as _, IsTerminal as _, Read as _, Write as _};

    let terminal = std::io::stdin().is_terminal();
    if terminal {
        eprint!("password: ");
        let _ = std::io::stderr().flush();
    }
    let mut bytes = Vec::new();
    std::io::stdin()
        .lock()
        .take(MAX_PASSWORD as u64 + 2)
        .read_until(b'\n', &mut bytes)
        .map_err(|e| format!("failed to read the password from stdin: {e}"))?;
    strip_password_newline(&mut bytes);
    if bytes.len() > MAX_PASSWORD {
        return Err(format!(
            "password is larger than {MAX_PASSWORD} bytes (streams: use --password-file for a file)"
        ));
    }
    if bytes.iter().any(|&b| b == b'\n' || b == b'\r') {
        return Err("password contains an embedded newline".to_string());
    }
    if bytes.contains(&0) {
        return Err("password contains a NUL byte".to_string());
    }
    if bytes.is_empty() {
        return Err("empty password".to_string());
    }
    Ok(bytes)
}

/// Drop one trailing `\n` or `\r\n`.
fn strip_password_newline(bytes: &mut Vec<u8>) {
    if bytes.last() == Some(&b'\n') {
        bytes.pop();
        if bytes.last() == Some(&b'\r') {
            bytes.pop();
        }
    }
}

/// Resolve the two switches into a [`ServeConfig`], rejecting combinations the
/// transports cannot honor.
fn resolve_config(args: &ServeArgs) -> Result<ServeConfig, String> {
    // The USB async endpoints are still blocking, so `async` is iSCSI-only.
    if args.wire == Wire::Async && args.usb.is_some() {
        return Err("async USB is not implemented; use --wire blocking".to_string());
    }
    // Without the Tokio binding there is no iSCSI async adapter in this build;
    // fail before any listener is bound.
    #[cfg(not(feature = "tokio"))]
    if args.wire == Wire::Async {
        return Err(
            "async wire requires the `tokio` feature: rebuild with --features tokio".to_string(),
        );
    }
    check_banks(args)?;

    let dual = args.banks == Banks::Dual;
    let default = if !dual {
        DEFAULT_WORK_BUF_SIZE
    } else if args.usb.is_none() {
        ISCSI_DUAL_WORK_BUF_SIZE
    } else {
        DUAL_WORK_BUF_SIZE
    };
    let work_size = if dual {
        parse_work_size_or(args.work_buf_size.as_deref(), default)?
    } else {
        parse_work_size(args.work_buf_size.as_deref())?
    };
    let scratch_len = parse_scratch_size(args.scratch_buffer.as_deref())?;

    let usb = args.usb.is_some();
    match (dual, usb) {
        (true, true) => check_usb_dual_work_size(work_size)?,
        (true, false) => check_iscsi_dual_work_size(work_size)?,
        (false, true) => check_usb_work_size(work_size)?,
        (false, false) => check_iscsi_work_size(work_size)?,
    }

    Ok(ServeConfig {
        wire: args.wire,
        banks: args.banks,
        work_size,
        scratch_len,
    })
}

/// Validate the transport/plane constraints of the `removable` demo and
/// return the single removable LUN, if any.
///
/// The demo is deliberately narrow: one `--block img=<file>` slot, USB only,
/// and not in the dual-bank (`WorkerStore`) path. Spec-level legality
/// (`profile=block`, `img=` backing) is already enforced by [`spec`].
fn validate_removable(
    args: &ServeArgs,
    specs: &[DeviceSpec],
    config: &ServeConfig,
) -> Result<Option<usize>, String> {
    let mut removable = None;
    for (lun, spec) in specs.iter().enumerate() {
        if !spec.removable {
            continue;
        }
        if removable.is_some() {
            return Err("removable supports at most one --block slot".to_string());
        }
        removable = Some(lun);
    }
    if removable.is_some() {
        if args.usb.is_none() {
            return Err("removable is only supported with --usb (the iSCSI path \
                        has no pause/insert handback)"
                .to_string());
        }
        if config.overlap() {
            return Err("removable cannot be combined with --banks dual \
                        (the worker path moves the planes out of the serve loop)"
                .to_string());
        }
    }
    Ok(removable)
}

/// Build the per-LUN core slots and their storage planes.
///
/// Produces `Spc<BlockDevice>` / `Spc<MmcDrive<CliMedium>>` slots and their
/// matching store planes. One owned [`OwnedPlane`] is built per LUN in
/// specification order; the slot keeps the geometry, the plane keeps the bytes.
fn build_core_slots(
    specs: &[DeviceSpec],
    planes: &mut Vec<Option<OwnedPlane>>,
    slots: &mut Vec<CliLu>,
    password: Option<&[u8]>,
) -> Result<(), ()> {
    if specs.is_empty() {
        eprintln!("snowscsi: --block or --cdrom is required (at least one device)");
        return Err(());
    }
    for w in spec::check_dual_mount(specs) {
        eprintln!("{w}");
    }
    let built = build_planes(specs, password)?;

    planes.clear();
    slots.clear();
    let mut built = built.into_iter();
    for (lun, spec) in specs.iter().enumerate() {
        let backing = lun as u32;
        log::debug!("LUN {lun}: {}", spec.raw);
        let Some(plane) = built.next() else {
            eprintln!("snowscsi: internal: plane pool exhausted");
            return Err(());
        };
        let cap = plane.capacity();
        // A `bundle=` manifest may describe a recordable CD, which is an MMC
        // medium only. Fail with the actual kind instead of the generic
        // unsupported-spec fallback.
        if matches!(&spec.backing, Backing::Bundle { .. })
            && plane.is_cdr_bundle()
            && matches!(spec.role, DeviceRole::BlockDisk | DeviceRole::BlockCd)
        {
            eprintln!(
                "snowscsi: bundle: LUN {lun}: manifest kind is 'cdr'; --block accepts only a \
                 'flat' bundle (use `--cdrom bundle=<dir>`)"
            );
            return Err(());
        }
        match (spec.role, &spec.backing) {
            (DeviceRole::BlockDisk, Backing::Bundle { .. }) => {
                // The manifest owns the geometry, including the sector size.
                let sector = plane.sector_size().unwrap_or(spec.plane.sector);
                let mut attrs = BlockAttrs::new(cap / u64::from(sector), sector);
                if spec.plane.read_only {
                    attrs.write_mode = Writability::ReadOnly;
                }
                planes.push(Some(plane));
                slots.push(CliLu::Block(snowscsi::core::LuImpl::new(
                    Spc::new(CoreBlockDevice::new(attrs)),
                    backing,
                )));
                log::debug!("LUN {lun}: flat bundle block device ({cap} bytes)");
            }
            (DeviceRole::BlockCd, Backing::Bundle { .. }) => {
                let sector = plane.sector_size().unwrap_or(ISO_SECTOR_SIZE);
                let mut attrs = BlockAttrs::new(cap / u64::from(sector), sector);
                attrs.write_mode = Writability::ReadOnly;
                planes.push(Some(plane));
                slots.push(CliLu::Block(snowscsi::core::LuImpl::new(
                    Spc::new(CoreBlockDevice::new(attrs)),
                    backing,
                )));
                log::debug!("LUN {lun}: flat bundle CD profile ({cap} bytes)");
            }
            (DeviceRole::BlockDisk, Backing::Img { .. } | Backing::Ram { .. }) => {
                let mut attrs =
                    BlockAttrs::new(cap / u64::from(spec.plane.sector), spec.plane.sector);
                if spec.removable {
                    attrs = attrs.with_removable();
                }
                if spec.plane.read_only {
                    attrs.write_mode = Writability::ReadOnly;
                }
                planes.push(Some(plane));
                slots.push(CliLu::Block(snowscsi::core::LuImpl::new(
                    Spc::new(CoreBlockDevice::new(attrs)),
                    backing,
                )));
                log::debug!("LUN {lun}: block device ({cap} bytes)");
            }
            (DeviceRole::BlockCd, Backing::Img { .. } | Backing::Ram { .. }) => {
                let mut attrs = BlockAttrs::new(cap / u64::from(ISO_SECTOR_SIZE), ISO_SECTOR_SIZE);
                attrs.write_mode = Writability::ReadOnly;
                planes.push(Some(plane));
                slots.push(CliLu::Block(snowscsi::core::LuImpl::new(
                    Spc::new(CoreBlockDevice::new(attrs)),
                    backing,
                )));
                log::debug!("LUN {lun}: CD profile ({cap} bytes)");
            }
            (DeviceRole::MmcCd, Backing::Img { path }) => {
                let medium = CliMedium::Flat(FlatCdMedium::new(cap));
                planes.push(Some(plane));
                slots.push(CliLu::Mmc(snowscsi::core::LuImpl::new(
                    Spc::new(MmcDrive::new(medium)),
                    backing,
                )));
                log::debug!("LUN {lun}: {path} flat CD-ROM ({cap} bytes)");
            }
            (DeviceRole::MmcCd, Backing::Live { dir }) => {
                let medium = CliMedium::Flat(FlatCdMedium::new(cap));
                planes.push(Some(plane));
                slots.push(CliLu::Mmc(snowscsi::core::LuImpl::new(
                    Spc::new(MmcDrive::new(medium)),
                    backing,
                )));
                log::debug!(
                    "LUN {lun}: {dir} live ISO9660 CD-ROM ({} sectors)",
                    cap / u64::from(ISO_SECTOR_SIZE)
                );
            }
            (DeviceRole::MmcCd, Backing::Empty) => {
                planes.push(None);
                slots.push(CliLu::Mmc(snowscsi::core::LuImpl::empty(Spc::new(
                    MmcDrive::<CliMedium>::empty(snowscsi::mmc::MmcCaps::hyper_multi()),
                ))));
                log::debug!("LUN {lun}: empty CD-ROM tray (no medium)");
            }
            (DeviceRole::MmcCd, Backing::DvdRam { .. }) => {
                let medium = CliMedium::DvdRam(DvdRamMedium::new(cap / u64::from(ISO_SECTOR_SIZE)));
                planes.push(Some(plane));
                slots.push(CliLu::Mmc(snowscsi::core::LuImpl::new(
                    Spc::new(MmcDrive::new(medium)),
                    backing,
                )));
                log::debug!("LUN {lun}: DvdRam DVD-RAM ({cap} bytes)");
            }
            #[cfg(all(feature = "bundle", feature = "cdr-bundle"))]
            (DeviceRole::MmcCd, Backing::Bundle { .. }) if plane.is_cdr_bundle() => {
                // The TOC read needs the filesystem plane, so the medium is
                // restored here rather than in `build_planes`. The stored TOC
                // owns capacity and kind; the CLI passes no hints.
                let mut plane = plane;
                let medium = match plane.open_cdr_medium(
                    0,
                    None,
                    snowscsi::mmc::cdr_bundle::Recovery::Delete,
                ) {
                    Ok(medium) => medium,
                    Err(e) => {
                        eprintln!("snowscsi: bundle: LUN {lun}: {e}");
                        return Err(());
                    }
                };
                // An encrypted CD-RW would reuse the track-1 keystream after
                // BLANK (resource 17 at offset 0 under the same key/nonce).
                // v1 therefore refuses encrypted erasable media entirely.
                if let OwnedPlane::CdrBundle(store) = &plane {
                    if store.is_ciphered() && medium.kind() == DiscKind::Cdrw {
                        eprintln!(
                            "snowscsi: bundle: LUN {lun}: encrypted recordable bundles require \
                             write-once CD-R (the stored medium is CD-RW)"
                        );
                        return Err(());
                    }
                }
                let sectors = medium.capacity_sectors();
                planes.push(Some(plane));
                slots.push(CliLu::Mmc(snowscsi::core::LuImpl::new(
                    Spc::new(MmcDrive::new(CliMedium::CdrBundle(medium))),
                    backing,
                )));
                // A host eject detaches the pair and leaves the LUN empty (no
                // automatic reinsert). Before dropping the plane the serve
                // path snapshots the ejected medium's TOC best effort, so an
                // open track or unsaved transition survives; restarting the
                // server re-reads the directory.
                log::debug!("LUN {lun}: recordable CD bundle ({sectors} sectors)");
            }
            #[cfg(feature = "bundle")]
            (DeviceRole::MmcCd, Backing::Bundle { .. }) if !plane.is_cdr_bundle() => {
                let medium = CliMedium::Flat(FlatCdMedium::new(cap));
                planes.push(Some(plane));
                slots.push(CliLu::Mmc(snowscsi::core::LuImpl::new(
                    Spc::new(MmcDrive::new(medium)),
                    backing,
                )));
                log::debug!("LUN {lun}: flat bundle CD-ROM ({cap} bytes)");
            }
            _ => {
                eprintln!("snowscsi: internal: unsupported device spec '{}'", spec.raw);
                return Err(());
            }
        }
    }
    debug_assert_eq!(specs.len(), planes.len());
    debug_assert_eq!(specs.len(), slots.len());
    Ok(())
}

/// `snowscsi serve --iscsi`: bind the portal, build the core target and drive
/// the session shell until shutdown.
fn run_serve_iscsi(
    args: ServeArgs,
    specs: &[DeviceSpec],
    config: &ServeConfig,
    password: &mut Option<Vec<u8>>,
) -> ExitCode {
    let mut planes: Vec<Option<OwnedPlane>> = Vec::new();
    let mut slots: Vec<CliLu> = Vec::new();
    let built = build_core_slots(specs, &mut planes, &mut slots, password.as_deref()).is_ok();
    // Best effort (not zeroize): every plane/cipher has copied what it needs.
    if let Some(bytes) = password.as_mut() {
        crate::wipe(bytes);
    }
    if !built {
        return ExitCode::FAILURE;
    }
    let mut table: Vec<&mut dyn Lu<Pair = CliPair>> = slots
        .iter_mut()
        .map(|s| s as &mut dyn Lu<Pair = CliPair>)
        .collect();

    let is_auto = args.iscsi.as_deref() == Some("auto");
    let (listener, bound) = if is_auto {
        match bind_iscsi_auto() {
            Ok(v) => v,
            Err(msg) => {
                eprintln!("snowscsi: {msg}");
                return ExitCode::FAILURE;
            }
        }
    } else {
        let addr = match args.iscsi.as_deref() {
            None => {
                eprintln!("snowscsi: --iscsi is required");
                return ExitCode::FAILURE;
            }
            Some(s) => match s.parse::<SocketAddr>() {
                Ok(a) => a,
                Err(_) => {
                    eprintln!("snowscsi: invalid --iscsi address: {s}");
                    return ExitCode::FAILURE;
                }
            },
        };
        let listener = match TcpListener::bind(addr) {
            Ok(l) => l,
            Err(e) => {
                eprintln!("snowscsi: failed to bind {addr}: {e}");
                return ExitCode::FAILURE;
            }
        };
        let bound = listener.local_addr().unwrap_or(addr);
        (listener, bound)
    };

    let stop = Arc::new(AtomicBool::new(false));
    // The blocking accept loop is woken by a probe connection; the async loop
    // awaits a notification instead.
    #[cfg(feature = "tokio")]
    let shutdown: Option<Arc<tokio::sync::Notify>> =
        (config.wire == Wire::Async).then(|| Arc::new(tokio::sync::Notify::new()));
    let probe = (config.wire == Wire::Blocking)
        .then(|| listener.local_addr().ok())
        .flatten();
    {
        let stop = Arc::clone(&stop);
        #[cfg(feature = "tokio")]
        let shutdown = shutdown.clone();
        if let Err(e) = ctrlc::set_handler(move || {
            stop.store(true, Ordering::SeqCst);
            if let Some(addr) = probe {
                let _ = std::net::TcpStream::connect(addr);
            }
            #[cfg(feature = "tokio")]
            if let Some(shutdown) = shutdown.as_ref() {
                // `notify_one` stores a permit when no waiter is registered,
                // so a signal that lands between two `select!`s is not lost.
                shutdown.notify_one();
            }
        }) {
            eprintln!("snowscsi: failed to install signal handler: {e}");
            return ExitCode::FAILURE;
        }
    }

    let mut work = vec![0u8; config.work_size];
    let mut scratch = split_bank(config.scratch_len);
    log::info!(
        "listening on {bound} with {} LUN(s) (wire={}, banks={}, storage={}, per_bank={})",
        table.len(),
        config.wire.as_str(),
        config.banks.as_str(),
        config.storage(pool_capable(specs, config)),
        config.per_bank(),
    );

    let auto_handle = if is_auto {
        spawn_iscsi_auto_helper(bound, Arc::clone(&stop))
    } else {
        None
    };

    if config.wire == Wire::Async {
        #[cfg(feature = "tokio")]
        {
            let res = serve_iscsi_async(
                listener,
                &stop,
                shutdown.expect("async wire installs a shutdown signal"),
                &mut work,
                &mut scratch,
                &mut table[..],
                planes,
                config,
                specs,
            );
            if let Some(handle) = auto_handle {
                stop.store(true, Ordering::SeqCst);
                let _ = handle.join();
                teardown_iscsi_auto(bound);
            }
            return match res {
                Ok(()) => {
                    log::info!("shutting down");
                    ExitCode::SUCCESS
                }
                Err(e) => {
                    eprintln!("snowscsi: server error: {e}");
                    ExitCode::FAILURE
                }
            };
        }
        #[cfg(not(feature = "tokio"))]
        {
            unreachable!("async wire is rejected during configuration");
        }
    }

    let serve_res = if config.overlap() {
        let per_bank = config.per_bank();
        std::thread::scope(|scope| {
            let mut store = WorkerStore::new(scope, planes, per_bank);
            let res = serve_with_release(
                listener,
                &stop,
                &mut work,
                &mut scratch,
                &mut table[..],
                &mut store,
                Some(DEFAULT_READ_TIMEOUT),
                true,
                &mut |lun, taken| preserve_ejected_cdr(specs, lun, taken),
            );
            if let Err((i, e)) = store.sync() {
                eprintln!("snowscsi: sync failed for LUN {i}: {e}");
            }
            drop(store);
            res
        })
    } else {
        let mut storage = CliStorage::new(planes);
        let res = serve_with_release(
            listener,
            &stop,
            &mut work,
            &mut scratch,
            &mut table[..],
            &mut storage,
            Some(DEFAULT_READ_TIMEOUT),
            false,
            &mut |lun, taken| preserve_ejected_cdr(specs, lun, taken),
        );
        if let Err((i, e)) = storage.sync() {
            eprintln!("snowscsi: sync failed for LUN {i}: {e}");
        }
        res
    };

    if let Some(handle) = auto_handle {
        stop.store(true, Ordering::SeqCst);
        let _ = handle.join();
        teardown_iscsi_auto(bound);
    }

    if let Err(e) = serve_res {
        eprintln!("snowscsi: server error: {e}");
        return ExitCode::FAILURE;
    }

    log::info!("shutting down");
    ExitCode::SUCCESS
}

/// `--print-config`'s `backing=` token: the CLI backing key of every LUN, in
/// LUN order (`ram`, `img`, `bundle`, …), so a smoke check can tell which
/// plane kind the resolved configuration will build.
fn backing_names(specs: &[DeviceSpec]) -> String {
    specs
        .iter()
        .map(|spec| match &spec.backing {
            Backing::Img { .. } => "img",
            Backing::Bundle { .. } => "bundle",
            Backing::Ram { .. } => "ram",
            Backing::Live { .. } => "live",
            Backing::DvdRam { .. } => "dvdram",
            Backing::Empty => "empty",
        })
        .collect::<Vec<_>>()
        .join(",")
}

/// Whether `--print-config` should report `storage=pool`.
///
/// The library slot pool needs a dual-bank asynchronous session over planes it
/// can drive without blocking the runtime: a file/block device (re-registered
/// with Tokio) or a memory plane. A live ISO scan, a chunked bundle, or a
/// persistent CD-R bundle reads through its own blocking filesystem plane, so
/// those configurations keep the thread-bridged worker.
fn pool_capable(specs: &[DeviceSpec], config: &ServeConfig) -> bool {
    if config.wire != Wire::Async || config.banks != Banks::Dual {
        return false;
    }
    specs.iter().all(|spec| match &spec.backing {
        Backing::Img { .. } | Backing::Ram { .. } => true,
        #[cfg(feature = "dvdram")]
        Backing::DvdRam { path } => path.is_some(),
        #[cfg(not(feature = "dvdram"))]
        Backing::DvdRam { .. } => false,
        _ => false,
    })
}

/// Whether every built plane can be handed to the asynchronous backend.
#[cfg(feature = "tokio")]
fn supports_async(planes: &[Option<OwnedPlane>]) -> bool {
    planes
        .iter()
        .all(|plane| plane.as_ref().is_some_and(plane_is_async))
}

/// Whether one plane has an asynchronous byte backend.
#[cfg(feature = "tokio")]
fn plane_is_async(plane: &OwnedPlane) -> bool {
    match plane {
        OwnedPlane::BlockRo(_) | OwnedPlane::BlockRw(_) | OwnedPlane::Ram { .. } => true,
        #[cfg(feature = "cipher")]
        OwnedPlane::Cipher(plane) => plane_is_async(plane.inner()),
        _ => false,
    }
}

/// One asynchronous byte plane behind a LUN.
#[cfg(feature = "tokio")]
enum AsyncPlane {
    /// A file or block device registered with the runtime.
    File {
        /// The handle; every operation is positional (seek + read/write).
        file: tokio::fs::File,
        /// Whether the LUN may write (media policy is separate).
        writable: bool,
    },
    /// An in-memory plane; nothing to await.
    Mem {
        /// Backing bytes.
        bytes: Vec<u8>,
        /// Whether the LUN may write.
        writable: bool,
    },
}

/// Map a `std` I/O error onto the byte-plane vocabulary.
#[cfg(feature = "tokio")]
fn io_err(e: std::io::Error) -> StorageError {
    use embedded_io::ErrorKind;
    let kind = match e.kind() {
        std::io::ErrorKind::NotFound => ErrorKind::NotFound,
        std::io::ErrorKind::PermissionDenied => ErrorKind::PermissionDenied,
        std::io::ErrorKind::InvalidInput => ErrorKind::InvalidInput,
        std::io::ErrorKind::InvalidData => ErrorKind::InvalidData,
        _ => ErrorKind::Other,
    };
    StorageError::Io(kind)
}

/// Per-LUN asynchronous planes, executed by [`drive_async_backend`].
#[cfg(feature = "tokio")]
struct AsyncBackends {
    luns: Vec<Option<AsyncPlane>>,
    /// One stream cipher per LUN, when the plane was wrapped.
    #[cfg(feature = "cipher")]
    ciphers: Vec<Option<crate::cipher::CliCipher>>,
}

/// Apply (or remove) the LUN's cipher over `buf` at absolute offset `off`.
#[cfg(all(feature = "tokio", feature = "cipher"))]
fn apply_cipher(
    ciphers: &mut [Option<crate::cipher::CliCipher>],
    lun: usize,
    off: u64,
    buf: &mut [u8],
) -> Result<(), StorageError> {
    use snowscsi::common::cipher::StreamCipher as _;

    if let Some(cipher) = ciphers.get_mut(lun).and_then(Option::as_mut) {
        cipher.xor(off, buf).map_err(StorageError::from)?;
    }
    Ok(())
}

#[cfg(feature = "tokio")]
impl AsyncBackends {
    /// Take ownership of the built planes, splitting off any cipher wrapper.
    fn new(planes: Vec<Option<OwnedPlane>>) -> Self {
        let mut luns = Vec::with_capacity(planes.len());
        #[cfg(feature = "cipher")]
        let mut ciphers = Vec::with_capacity(planes.len());

        for plane in planes {
            let Some(plane) = plane else {
                luns.push(None);
                #[cfg(feature = "cipher")]
                ciphers.push(None);
                continue;
            };
            #[cfg(feature = "cipher")]
            let (plane, cipher) = match plane {
                OwnedPlane::Cipher(plane) => {
                    let (inner, cipher) = plane.into_parts();
                    (inner, Some(cipher))
                }
                other => (other, None),
            };
            let async_plane = match plane {
                OwnedPlane::BlockRo(backend) => AsyncPlane::File {
                    file: tokio::fs::File::from_std(backend.into_file()),
                    writable: false,
                },
                OwnedPlane::BlockRw(backend) => AsyncPlane::File {
                    file: tokio::fs::File::from_std(backend.into_file()),
                    writable: true,
                },
                OwnedPlane::Ram { bytes, writable } => AsyncPlane::Mem { bytes, writable },
                _ => unreachable!("supports_async rejects planes without an async backend"),
            };
            luns.push(Some(async_plane));
            #[cfg(feature = "cipher")]
            ciphers.push(cipher);
        }
        Self {
            luns,
            #[cfg(feature = "cipher")]
            ciphers,
        }
    }

    /// Execute one request against `lun`.
    async fn exec(
        &mut self,
        lun: usize,
        req: IoReq,
        buf: &mut [u8],
    ) -> Result<usize, StorageError> {
        let len = req.len as usize;
        let Self {
            luns,
            #[cfg(feature = "cipher")]
            ciphers,
        } = self;
        let Some(plane) = luns.get_mut(lun).and_then(Option::as_mut) else {
            return Err(StorageError::Unsupported);
        };
        match plane {
            AsyncPlane::File { file, writable } => match req.dir {
                Direction::ToHost => {
                    file.seek(std::io::SeekFrom::Start(req.offset))
                        .await
                        .map_err(io_err)?;
                    file.read_exact(&mut buf[..len]).await.map_err(io_err)?;
                    #[cfg(feature = "cipher")]
                    apply_cipher(ciphers, lun, req.offset, &mut buf[..len])?;
                    Ok(len)
                }
                Direction::FromHost => {
                    if !*writable {
                        return Err(StorageError::NotWritable);
                    }
                    #[cfg(feature = "cipher")]
                    apply_cipher(ciphers, lun, req.offset, &mut buf[..len])?;
                    file.seek(std::io::SeekFrom::Start(req.offset))
                        .await
                        .map_err(io_err)?;
                    file.write_all(&buf[..len]).await.map_err(io_err)?;
                    Ok(len)
                }
                Direction::None => {
                    file.sync_all().await.map_err(io_err)?;
                    Ok(0)
                }
            },
            AsyncPlane::Mem { bytes, writable } => match req.dir {
                Direction::ToHost => {
                    stack::ram_read(bytes, req.offset, &mut buf[..len])?;
                    #[cfg(feature = "cipher")]
                    apply_cipher(ciphers, lun, req.offset, &mut buf[..len])?;
                    Ok(len)
                }
                Direction::FromHost => {
                    if !*writable {
                        return Err(StorageError::NotWritable);
                    }
                    #[cfg(feature = "cipher")]
                    apply_cipher(ciphers, lun, req.offset, &mut buf[..len])?;
                    stack::ram_write(bytes, req.offset, &buf[..len])?;
                    Ok(len)
                }
                Direction::None => Ok(0),
            },
        }
    }

    /// Flush every writable file plane once the session ended.
    async fn sync(&mut self) {
        for (lun, plane) in self.luns.iter_mut().enumerate() {
            if let Some(AsyncPlane::File {
                file,
                writable: true,
            }) = plane
            {
                if let Err(e) = file.sync_all().await {
                    eprintln!("snowscsi: sync failed for LUN {lun}: {e}");
                }
            }
        }
    }
}

/// Storage task: await a job from the pool, run it, report the result.
///
/// One future in the same task as the wire, so the pool's `!Send` store and
/// this task share one executor without a thread or a channel.
#[cfg(feature = "tokio")]
async fn drive_async_backend(backends: &mut AsyncBackends, task: &SlotTask<'_, Vec<u8>>) -> ! {
    loop {
        let mut job = task.next_job().await;
        let req = job.req();
        let lun = job.lun();
        let result = {
            let data = job.data();
            backends.exec(lun, req, data).await
        };
        task.complete(job, result);
    }
}

/// `--wire async` iSCSI: serve one connection at a time on a Tokio runtime.
///
/// Storage follows the planes: file and memory LUNs run on the library slot
/// pool, joined with the accept loop in one task (`storage=pool`); a live ISO
/// scan or a chunked bundle reads through its own blocking scanner, so those
/// configurations keep the scoped-thread worker (`storage=worker`). `--banks
/// single` runs the inline adapter, which never pends (`storage=inline`).
#[cfg(feature = "tokio")]
#[allow(clippy::too_many_arguments)]
fn serve_iscsi_async(
    listener: TcpListener,
    stop: &Arc<AtomicBool>,
    shutdown: Arc<tokio::sync::Notify>,
    work: &mut [u8],
    scratch: &mut [u8],
    table: &mut [&mut dyn Lu<Pair = CliPair>],
    planes: Vec<Option<OwnedPlane>>,
    config: &ServeConfig,
    specs: &[DeviceSpec],
) -> Result<(), TargetError> {
    if let Err(e) = listener.set_nonblocking(true) {
        log::error!("failed to make the listener non-blocking: {e}");
        return Err(TargetError::Io);
    }
    let runtime = match tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
    {
        Ok(runtime) => runtime,
        Err(e) => {
            log::error!("failed to start the async runtime: {e}");
            return Err(TargetError::Io);
        }
    };
    // `from_std` registers the socket with the runtime's reactor, so it must
    // run inside the runtime context.
    let listener = {
        let _guard = runtime.enter();
        match tokio::net::TcpListener::from_std(listener) {
            Ok(listener) => listener,
            Err(e) => {
                log::error!("failed to register the listener with the runtime: {e}");
                return Err(TargetError::Io);
            }
        }
    };

    let per_bank = config.per_bank();
    if config.overlap() && supports_async(&planes) {
        // The library slot pool drives storage in the *same* task as the wire:
        // `join!` the accept loop with the backend. `SlotStore` is `!Send`, so
        // this is the only shape that works — and one connection at a time is
        // exactly what the serial accept loop does.
        let pool = SlotPool::new(vec![0u8; per_bank]);
        let (mut storage, task) = pool.split();
        let mut backends = AsyncBackends::new(planes);
        return runtime.block_on(async {
            let res = {
                let mut serve = core::pin::pin!(accept_loop(
                    &listener,
                    stop,
                    &shutdown,
                    work,
                    scratch,
                    table,
                    &mut storage,
                    true,
                    specs,
                ));
                let mut backend = core::pin::pin!(drive_async_backend(&mut backends, &task));
                tokio::select! {
                    res = &mut serve => res,
                    // The backend loop never completes; it ends only when this
                    // future is dropped.
                    () = &mut backend => unreachable!("the storage backend runs forever"),
                }
            };
            // Both futures are dropped here, so no operation is in flight and
            // the planes can be flushed.
            backends.sync().await;
            res
        });
    }
    if config.overlap() {
        std::thread::scope(|scope| {
            let mut store = WorkerStore::new(scope, planes, per_bank);
            let res = runtime.block_on(accept_loop(
                &listener, stop, &shutdown, work, scratch, table, &mut store, true, specs,
            ));
            if let Err((i, e)) = store.sync() {
                eprintln!("snowscsi: sync failed for LUN {i}: {e}");
            }
            res
        })
    } else {
        let mut storage = CliStorage::new(planes);
        let res = runtime.block_on(accept_loop(
            &listener,
            stop,
            &shutdown,
            work,
            scratch,
            table,
            &mut storage,
            false,
            specs,
        ));
        if let Err((i, e)) = storage.sync() {
            eprintln!("snowscsi: sync failed for LUN {i}: {e}");
        }
        res
    }
}

/// Serial accept loop on a Tokio listener, stopped by a notification.
///
/// A fresh [`IscsiSession`] (and a fresh core target over the same slots) is
/// built per connection, exactly as the blocking loop does. One connection is
/// served at a time: `Target` owns the mutable slot table.
#[cfg(feature = "tokio")]
#[allow(clippy::too_many_arguments)]
async fn accept_loop<W>(
    listener: &tokio::net::TcpListener,
    stop: &AtomicBool,
    shutdown: &tokio::sync::Notify,
    work: &mut [u8],
    scratch: &mut [u8],
    table: &mut [&mut dyn Lu<Pair = CliPair>],
    storage: &mut W,
    overlap: bool,
    specs: &[DeviceSpec],
) -> Result<(), TargetError>
where
    W: snowscsi::core::storage::Storage + snowscsi::core::async_wake::AsyncWake,
{
    loop {
        if stop.load(Ordering::SeqCst) {
            return Ok(());
        }
        let accepted = tokio::select! {
            _ = shutdown.notified() => return Ok(()),
            accepted = listener.accept() => accepted,
        };
        let (stream, peer) = match accepted {
            Ok(accepted) => accepted,
            Err(e) => {
                if stop.load(Ordering::SeqCst) {
                    return Ok(());
                }
                // A transient accept failure (EMFILE, a peer reset before
                // accept) must not kill the server; back off like the blocking
                // loop, but stay cancellable.
                log::warn!("accept failed: {e}, retrying");
                tokio::select! {
                    _ = shutdown.notified() => return Ok(()),
                    _ = tokio::time::sleep(std::time::Duration::from_millis(100)) => continue,
                }
            }
        };
        log::info!("accepted connection from {peer}");
        // Same reason as `TcpConn::new`: iSCSI is request/response, so Nagle
        // only adds a delayed-ACK stall per Data-In tail.
        if let Err(e) = stream.set_nodelay(true) {
            log::warn!("failed to disable Nagle on {peer}: {e}");
        }
        let mut conn = TokioConn::new(stream);
        let mut session = if overlap {
            IscsiSession::new().with_overlap()
        } else {
            IscsiSession::new()
        };
        let mut target = snowscsi::core::Target::new(&mut *table);
        // A signal that arrived between accept and this select must not strand
        // the connection: the `Notify` may already have fired.
        if stop.load(Ordering::SeqCst) {
            session.connection_lost();
            target.link_lost(&mut *storage, &mut session, work, scratch);
            return Ok(());
        }
        tokio::select! {
            r = serve_conn_async(
                &mut conn,
                work,
                scratch,
                &mut session,
                &mut target,
                &mut *storage,
            ) => if let snowscsi::core::ServeExit::Outcome(
                snowscsi::core::RunOutcome::ResourcesReady { lun },
            ) = r?
            {
                // The target is per-connection here; take the detached pair so
                // the slot does not keep a resident result, preserving a CD-R
                // TOC snapshot before the plane is released.
                let mut taken = target.take_rt(lun);
                preserve_ejected_cdr(specs, lun, &mut taken);
                drop(taken);
                storage.resources_released(lun);
            },
            _ = shutdown.notified() => {
                session.connection_lost();
                target.link_lost(&mut *storage, &mut session, work, scratch);
                return Ok(());
            }
        }
        log::info!("connection from {peer} ended");
    }
}

// ── iSCSI auto-config (open-iscsi) ─────────────────────────────────────

#[cfg(target_os = "linux")]
const ISCSI_TARGET_NAME: &str = "iqn.1970-01.local.snowscsi:target";
const ISCSI_STANDARD_PORT: u16 = 3260;

/// Bind for `--iscsi auto`: try the standard loopback portal
/// `127.0.0.1:3260` (avoids Fedora SELinux `iscsi_port_t` labeling), fall
/// back to an ephemeral `127.0.0.1:0` if it is in use.
fn bind_iscsi_auto() -> Result<(TcpListener, SocketAddr), String> {
    let std_addr: SocketAddr = format!("127.0.0.1:{ISCSI_STANDARD_PORT}").parse().unwrap();
    match TcpListener::bind(std_addr) {
        Ok(l) => {
            let bound = l
                .local_addr()
                .map_err(|e| format!("getsockname failed: {e}"))?;
            log::info!("auto: bound standard portal {bound}");
            Ok((l, bound))
        }
        Err(e) if e.kind() == std::io::ErrorKind::AddrInUse => {
            log::warn!("auto: {std_addr} in use ({e}), falling back to ephemeral");
            let fb: SocketAddr = "127.0.0.1:0".parse().unwrap();
            let l = TcpListener::bind(fb).map_err(|e| format!("failed to bind {fb}: {e}"))?;
            let bound = l
                .local_addr()
                .map_err(|e| format!("getsockname failed: {e}"))?;
            log::info!("auto: bound ephemeral portal {bound}");
            Ok((l, bound))
        }
        Err(e) => Err(format!("failed to bind {std_addr}: {e}")),
    }
}

#[cfg(target_os = "linux")]
fn have_tool(name: &str) -> bool {
    if let Ok(path) = std::env::var("PATH") {
        for dir in path.split(':') {
            if dir.is_empty() {
                continue;
            }
            let cand = Path::new(dir).join(name);
            if cand.is_file() {
                // Check executable bit via metadata permissions (best-effort).
                if let Ok(md) = std::fs::metadata(&cand) {
                    #[cfg(unix)]
                    {
                        use std::os::unix::fs::PermissionsExt;
                        if md.permissions().mode() & 0o111 != 0 {
                            return true;
                        }
                    }
                    #[cfg(not(unix))]
                    {
                        let _ = &md;
                        return true;
                    }
                }
            }
        }
    }
    false
}

#[cfg(target_os = "linux")]
fn is_root() -> bool {
    // Cheap check via `id -u` to avoid a libc dependency.
    if let Ok(o) = Command::new("id").arg("-u").output() {
        if o.status.success() {
            return String::from_utf8_lossy(&o.stdout).trim() == "0";
        }
    }
    false
}

#[cfg(target_os = "linux")]
fn selinux_enforcing() -> bool {
    if !have_tool("getenforce") {
        return false;
    }
    match Command::new("getenforce").output() {
        Ok(o) => o.status.success() && String::from_utf8_lossy(&o.stdout).trim() == "Enforcing",
        Err(_) => false,
    }
}

#[cfg(target_os = "linux")]
fn selinux_allow_port(port: u16) -> bool {
    if !selinux_enforcing() || !have_tool("semanage") {
        return false;
    }
    let s = Command::new("timeout")
        .args([
            "30",
            "semanage",
            "port",
            "-a",
            "-t",
            "iscsi_port_t",
            "-p",
            "tcp",
            &port.to_string(),
        ])
        .status();
    match s {
        Ok(st) if st.success() => {
            log::info!("auto: labeled {port}/tcp as iscsi_port_t");
            true
        }
        _ => {
            log::warn!("auto: semanage port -a failed for {port} (ignored)");
            false
        }
    }
}

#[cfg(target_os = "linux")]
fn selinux_deny_port(port: u16) {
    if !selinux_enforcing() || !have_tool("semanage") {
        return;
    }
    let _ = Command::new("timeout")
        .args([
            "30",
            "semanage",
            "port",
            "-d",
            "-p",
            "tcp",
            &port.to_string(),
        ])
        .status();
}

#[cfg(target_os = "linux")]
fn iscsid_running() -> bool {
    if have_tool("systemctl") {
        if let Ok(o) = Command::new("systemctl")
            .args(["is-active", "iscsid"])
            .output()
        {
            if o.status.success() && String::from_utf8_lossy(&o.stdout).trim() == "active" {
                return true;
            }
        }
    }
    // Fallback: pgrep
    if have_tool("pgrep") {
        if let Ok(st) = Command::new("pgrep").args(["-x", "iscsid"]).status() {
            return st.success();
        }
    }
    false
}

#[cfg(target_os = "linux")]
fn ensure_iscsid() {
    if iscsid_running() {
        return;
    }
    log::info!("auto: iscsid not running, starting");
    if have_tool("systemctl") {
        let _ = Command::new("systemctl").args(["start", "iscsid"]).status();
        if iscsid_running() {
            return;
        }
    }
    if have_tool("iscsid") {
        let _ = Command::new("iscsid").status();
    }
}

#[cfg(target_os = "linux")]
fn iscsi_portal(bound: SocketAddr) -> String {
    // iscsiadm expects "IP:PORT" (no brackets for IPv4 loopback).
    // For IPv6 loopback, bracket the IP.
    match bound {
        SocketAddr::V4(v4) => format!("{}:{}", v4.ip(), v4.port()),
        SocketAddr::V6(v6) => format!("[{}]:{}", v6.ip(), v6.port()),
    }
}

#[cfg(target_os = "linux")]
fn find_iscsi_device(portal: &str) -> Option<String> {
    // /dev/disk/by-path/ip-<portal>-iscsi-<iqn>-lun-*
    // portal contains ':', so escape for glob via directory read.
    let dir = Path::new("/dev/disk/by-path");
    let entries = std::fs::read_dir(dir).ok()?;
    let prefix = format!("ip-{portal}-iscsi-{ISCSI_TARGET_NAME}-lun-");
    for ent in entries.flatten() {
        let name = ent.file_name().to_string_lossy().to_string();
        if name.starts_with(&prefix) {
            if let Ok(real) = std::fs::read_link(ent.path()) {
                let abs = if real.is_absolute() {
                    real
                } else {
                    dir.join(real)
                };
                // Resolve .. components and return /dev/sdX
                if let Ok(canon) = abs.canonicalize() {
                    return Some(canon.to_string_lossy().to_string());
                }
                return Some(abs.to_string_lossy().to_string());
            }
            // Fallback: resolve via realpath of the symlink's target
            if let Ok(canon) = ent.path().canonicalize() {
                return Some(canon.to_string_lossy().to_string());
            }
        }
    }
    None
}

#[cfg(not(target_os = "linux"))]
fn spawn_iscsi_auto_helper(_bound: SocketAddr, _stop: Arc<AtomicBool>) -> Option<JoinHandle<()>> {
    log::warn!("auto: open-iscsi auto-login is only supported on Linux");
    None
}

#[cfg(target_os = "linux")]
fn spawn_iscsi_auto_helper(bound: SocketAddr, stop: Arc<AtomicBool>) -> Option<JoinHandle<()>> {
    let portal = iscsi_portal(bound);
    let port = bound.port();
    let needs_semanage = port != ISCSI_STANDARD_PORT;
    // Spawn a helper thread so `serve` can start accepting immediately.
    Some(std::thread::spawn(move || {
        if !have_tool("iscsiadm") {
            log::warn!("auto: iscsiadm not found; target listening on {portal} — manual login required: iscsiadm -m node -o new -T {ISCSI_TARGET_NAME} -p {portal} && iscsiadm -m node -T {ISCSI_TARGET_NAME} -p {portal} --login");
            return;
        }
        if !is_root() {
            log::warn!("auto: not running as root; skipping iscsiadm auto-login (target listening on {portal})");
            log::info!("auto: manual login: iscsiadm -m node -o new -T {ISCSI_TARGET_NAME} -p {portal} && iscsiadm -m node -T {ISCSI_TARGET_NAME} -p {portal} --login");
            return;
        }
        ensure_iscsid();
        // Give `serve` a moment to enter its accept loop.
        std::thread::sleep(Duration::from_millis(200));
        if stop.load(Ordering::SeqCst) {
            return;
        }
        let mut selinux_added = false;
        if needs_semanage {
            selinux_added = selinux_allow_port(port);
        }
        let _ = selinux_added; // recorded for teardown via port check
                               // Register the node explicitly (no SendTargets discovery).
        let new_st = Command::new("iscsiadm")
            .args([
                "-m",
                "node",
                "-o",
                "new",
                "-T",
                ISCSI_TARGET_NAME,
                "-p",
                &portal,
            ])
            .status();
        match new_st {
            Ok(st) if st.success() => {
                log::info!("auto: iscsiadm new node {ISCSI_TARGET_NAME}@{portal}")
            }
            Ok(st) => log::warn!("auto: iscsiadm new failed ({st}); trying login anyway"),
            Err(e) => log::warn!("auto: iscsiadm new exec failed: {e}"),
        }
        if stop.load(Ordering::SeqCst) {
            return;
        }
        let login_st = Command::new("iscsiadm")
            .args([
                "-m",
                "node",
                "-T",
                ISCSI_TARGET_NAME,
                "-p",
                &portal,
                "--login",
            ])
            .status();
        match login_st {
            Ok(st) if st.success() => log::info!("auto: iscsiadm login {portal}"),
            Ok(st) => {
                log::warn!(
                    "auto: iscsiadm login failed ({st}); target still listening on {portal}"
                );
                log::info!("auto: manual retry: iscsiadm -m node -T {ISCSI_TARGET_NAME} -p {portal} --login");
                return;
            }
            Err(e) => {
                log::warn!("auto: iscsiadm login exec failed: {e}");
                return;
            }
        }
        // Wait for udev to create the block device (no mount).
        let deadline = std::time::Instant::now() + Duration::from_secs(15);
        while std::time::Instant::now() < deadline {
            if stop.load(Ordering::SeqCst) {
                break;
            }
            if let Some(dev) = find_iscsi_device(&portal) {
                log::info!("auto: iSCSI block ready: {dev} (portal {portal})");
                return;
            }
            std::thread::sleep(Duration::from_millis(500));
        }
        if stop.load(Ordering::SeqCst) {
            return;
        }
        log::warn!("auto: iSCSI device did not appear under /dev/disk/by-path for {portal} (login succeeded, udev pending)");
    }))
}

#[cfg(not(target_os = "linux"))]
fn teardown_iscsi_auto(_bound: SocketAddr) {}

#[cfg(target_os = "linux")]
fn teardown_iscsi_auto(bound: SocketAddr) {
    if !have_tool("iscsiadm") || !is_root() {
        return;
    }
    let portal = iscsi_portal(bound);
    let port = bound.port();
    log::info!("auto: logging out {ISCSI_TARGET_NAME}@{portal}");
    let _ = Command::new("iscsiadm")
        .args([
            "-m",
            "node",
            "-T",
            ISCSI_TARGET_NAME,
            "-p",
            &portal,
            "--logout",
        ])
        .status();
    let _ = Command::new("iscsiadm")
        .args([
            "-m",
            "node",
            "-o",
            "delete",
            "-T",
            ISCSI_TARGET_NAME,
            "-p",
            &portal,
        ])
        .status();
    if port != ISCSI_STANDARD_PORT {
        selinux_deny_port(port);
    }
}

/// Reject an encrypted manifest when the CLI was built without `cipher`.
///
/// A missing manifest is plaintext; a `cipher = none` manifest is plaintext.
/// Anything with a keyslot must not be served by a build that cannot unlock
/// it: the raw ciphertext would be exposed as a writable block device.
#[cfg(not(feature = "cipher"))]
fn reject_encrypted_manifest_file(path: &str) -> Result<(), ()> {
    use snowscsi::common::bundle::{BundleMeta, MAX_MANIFEST};

    if !Path::new(path).is_file() {
        return Ok(());
    }
    let bytes = match read_capped(path, MAX_MANIFEST + 1) {
        Ok(bytes) => bytes,
        Err(e) => {
            eprintln!("snowscsi: cipher: cannot read manifest '{path}': {e}");
            return Err(());
        }
    };
    let meta = match BundleMeta::parse(&bytes) {
        Ok(meta) => meta,
        Err(e) => {
            eprintln!("snowscsi: cipher: invalid manifest '{path}': {e}");
            return Err(());
        }
    };
    if meta.cipher.is_some() {
        eprintln!(
            "snowscsi: cipher: '{path}' describes an encrypted image, but this binary was \
             built without the `cipher` feature; refusing to serve the raw ciphertext"
        );
        return Err(());
    }
    Ok(())
}

/// Open one flat image file as an owned plane.
///
/// `writable` selects `Rw`; a read-only image is opened `rb` so it also works
/// on read-only media. The caller has already decided the role's policy.
fn open_img_plane(path: &str, writable: bool) -> Result<OwnedPlane, ()> {
    #[cfg(not(feature = "cipher"))]
    reject_encrypted_manifest_file(&format!("{path}.SNOWBUNDLE"))?;
    if !Path::new(path).is_file() {
        eprintln!("snowscsi: file not found: {path}");
        return Err(());
    }
    let backend = FileBackend::open(path, writable)
        .map_err(|e| eprintln!("snowscsi: failed to open {path}: {e}"))?;
    Ok(if writable {
        OwnedPlane::BlockRw(backend)
    } else {
        OwnedPlane::BlockRo(backend)
    })
}

/// Validate `bundle=` directories for `--print-config`.
///
/// `--print-config` never builds a plane (and never allocates a RAM disk), but
/// a bundle's manifest/TOC decides whether `serve` could open it at all, so
/// this performs the same identification step as `build_planes` for bundle
/// LUNs only.
#[cfg(feature = "bundle")]
fn validate_bundle_specs(specs: &[DeviceSpec]) -> Result<(), ()> {
    for spec in specs {
        let Backing::Bundle { dir } = &spec.backing else {
            continue;
        };
        if !Path::new(dir).is_dir() {
            eprintln!(
                "snowscsi: bundle: directory not found: {dir} (create it with \
                 `snowscsi bundle-create ...`)"
            );
            return Err(());
        }
        let mut fs = StdFsBackend::new(dir);
        let identified = match identify_dir(&mut fs) {
            Ok(identified) => identified,
            Err(e) => {
                eprintln!("snowscsi: bundle: {dir}: cannot read the SNOWBUNDLE manifest: {e}");
                return Err(());
            }
        };
        match identified {
            Identified::NotBundle { found } => {
                let names = found.as_slice().join(", ");
                eprintln!(
                    "snowscsi: bundle: no SNOWBUNDLE manifest in {dir}; create it with \
                     `snowscsi bundle-create ...` (found: {names})"
                );
                return Err(());
            }
            Identified::Image { .. } => {
                eprintln!(
                    "snowscsi: bundle: {dir} carries a single-file image manifest, not a \
                     directory bundle"
                );
                return Err(());
            }
            Identified::Flat { meta } => {
                #[cfg(feature = "cipher")]
                let _ = meta;
                #[cfg(not(feature = "cipher"))]
                if meta.cipher.is_some() {
                    eprintln!(
                        "snowscsi: cipher: {dir}/SNOWBUNDLE describes an encrypted bundle, but \
                         this binary was built without the `cipher` feature; refusing to serve \
                         the raw ciphertext"
                    );
                    return Err(());
                }
            }
            Identified::Cdr { meta, toc } => {
                #[cfg(feature = "cipher")]
                let _ = meta;
                #[cfg(not(feature = "cipher"))]
                if meta.cipher.is_some() {
                    eprintln!(
                        "snowscsi: cipher: {dir}/SNOWBUNDLE describes an encrypted recordable \
                         bundle, but this binary was built without the `cipher` feature; \
                         refusing to serve the raw ciphertext"
                    );
                    return Err(());
                }
                #[cfg(feature = "cdr-bundle")]
                {
                    if matches!(spec.role, DeviceRole::BlockDisk | DeviceRole::BlockCd) {
                        eprintln!(
                            "snowscsi: bundle: {dir} is a recordable CD (manifest kind 'cdr'); \
                             --block accepts only a 'flat' bundle (use `--cdrom bundle=<dir>`)"
                        );
                        return Err(());
                    }
                    if toc.is_none() {
                        eprintln!(
                            "snowscsi: bundle: no recordable-CD TOC in {dir}; create it with \
                             `snowscsi bundle-create cdr`"
                        );
                        return Err(());
                    }
                    if spec.plane.read_only {
                        eprintln!(
                            "snowscsi: bundle: {dir} is a recordable CD (writable-only); `ro` \
                             is not supported"
                        );
                        return Err(());
                    }
                }
                #[cfg(not(feature = "cdr-bundle"))]
                {
                    let _ = toc;
                    eprintln!(
                        "snowscsi: bundle: {dir} is a recordable CD; serving it requires the \
                         `cdr-bundle` feature"
                    );
                    return Err(());
                }
            }
        }
    }
    Ok(())
}

#[cfg(not(feature = "bundle"))]
fn validate_bundle_specs(_specs: &[DeviceSpec]) -> Result<(), ()> {
    Ok(())
}

/// Build one owned plane per LUN, in specification order.
///
/// Every plane owns its bytes — file handles and RAM disks included — so the
/// same value can be moved onto a worker thread or an asynchronous backend
/// task later.
fn build_planes(specs: &[DeviceSpec], password: Option<&[u8]>) -> Result<Vec<OwnedPlane>, ()> {
    if let Some(dir) = spec::duplicate_bundle_dir(specs) {
        eprintln!(
            "snowscsi: bundle directory '{dir}' is served by more than one LUN; \
             use one directory per bundle"
        );
        return Err(());
    }
    // The cheap exact check above misses aliases such as `dir` vs `dir/` or a
    // symlink. Once the directories exist, canonicalize them so two writers
    // can never reach the same bundle through different spellings.
    #[cfg(feature = "bundle")]
    {
        let mut seen = std::collections::HashSet::new();
        for spec in specs {
            if let Backing::Bundle { dir } = &spec.backing {
                let canonical = std::fs::canonicalize(dir)
                    .map(|path| path.to_string_lossy().into_owned())
                    .unwrap_or_else(|_| dir.clone());
                if !seen.insert(canonical) {
                    eprintln!(
                        "snowscsi: bundle directory '{dir}' is served by more than one LUN; \
                         use one directory per bundle"
                    );
                    return Err(());
                }
            }
        }
    }
    let mut planes = Vec::with_capacity(specs.len());
    for spec in specs {
        planes.push(open_plane_for(spec, password)?);
    }
    Ok(planes)
}

/// Build one plane for `spec`, wrapping the backing in a cipher when the spec
/// carries `cipher`.
fn open_plane_for(spec: &DeviceSpec, password: Option<&[u8]>) -> Result<OwnedPlane, ()> {
    // Validate and build the cipher before touching any backing: a doomed
    // invocation must not create/open the base plane first.
    #[cfg(feature = "cipher")]
    let cipher = prepare_cipher(spec, password)?;
    #[cfg(not(feature = "cipher"))]
    if spec.cipher.is_some() {
        eprintln!("snowscsi: cipher= requires the `cipher` feature");
        return Err(());
    }
    #[cfg(not(feature = "cipher"))]
    let _ = password;

    let base = match &spec.backing {
        #[cfg(feature = "bundle")]
        Backing::Bundle { dir } => {
            if !Path::new(dir).is_dir() {
                eprintln!(
                    "snowscsi: bundle: directory not found: {dir} (create it with \
                         `snowscsi bundle-create ...`)"
                );
                return Err(());
            }
            let mut fs = StdFsBackend::new(dir);
            let identified = match identify_dir(&mut fs) {
                Ok(identified) => identified,
                Err(e) => {
                    eprintln!("snowscsi: bundle: {dir}: cannot read the SNOWBUNDLE manifest: {e}");
                    return Err(());
                }
            };
            match identified {
                Identified::NotBundle { found } => {
                    let names = found.as_slice().join(", ");
                    eprintln!(
                        "snowscsi: bundle: no SNOWBUNDLE manifest in {dir}; create it with \
                             `snowscsi bundle-create ...` (found: {names})"
                    );
                    return Err(());
                }
                Identified::Flat { meta } => {
                    // No overrides: the manifest owns the whole geometry.
                    // A flat bundle under `--cdrom` is optical media and
                    // must open read-only; `--block` honours an explicit
                    // `ro`, otherwise it stays writable.
                    let manifest_path = format!("{}/{}", dir.trim_end_matches('/'), MANIFEST_NAME);
                    // Unlock before the flat store is opened: a wrong password
                    // must not create or touch a chunk file.
                    #[cfg(feature = "cipher")]
                    let cipher = bundle_cipher(spec, password, &meta, &manifest_path)?;
                    #[cfg(not(feature = "cipher"))]
                    {
                        let _ = &manifest_path;
                        if meta.cipher.is_some() {
                            eprintln!(
                                "snowscsi: cipher: {manifest_path} describes an encrypted \
                                 bundle, but this binary was built without the `cipher` \
                                 feature; refusing to serve the raw ciphertext"
                            );
                            return Err(());
                        }
                    }
                    let read_only = spec.plane.read_only || spec.role == DeviceRole::MmcCd;
                    let bundle = if read_only {
                        FlatBundle::open_read_only(fs, None, None, None)
                    } else {
                        FlatBundle::open(fs, None, None, None)
                    }
                    .map_err(|e| eprintln!("snowscsi: bundle: failed to open {dir}: {e}"))?;
                    #[cfg(feature = "cipher")]
                    let base = match cipher {
                        Some((cipher, _nonce)) => OwnedPlane::Cipher(Box::new(CipherPlane::new(
                            OwnedPlane::Bundle(bundle),
                            cipher,
                        ))),
                        None => OwnedPlane::Bundle(bundle),
                    };
                    #[cfg(not(feature = "cipher"))]
                    let base = OwnedPlane::Bundle(bundle);
                    base
                }
                Identified::Cdr { meta, toc } => {
                    #[cfg(feature = "cdr-bundle")]
                    {
                        // A recordable CD is an MMC medium: report the
                        // wrong role before any read-only complaint, so
                        // `--block bundle=<cdr>` (even with `ro` or
                        // `profile=cd`) suggests the right flag.
                        if matches!(spec.role, DeviceRole::BlockDisk | DeviceRole::BlockCd) {
                            eprintln!(
                                "snowscsi: bundle: {dir} is a recordable CD (manifest kind \
                                     'cdr'); --block accepts only a 'flat' bundle (use `--cdrom \
                                     bundle=<dir>`)"
                            );
                            return Err(());
                        }
                        if toc.is_none() {
                            eprintln!(
                                "snowscsi: bundle: no recordable-CD TOC in {dir}; create it \
                                     with `snowscsi bundle-create cdr`"
                            );
                            return Err(());
                        }
                        if spec.plane.read_only {
                            eprintln!(
                                "snowscsi: bundle: {dir} is a recordable CD (writable-only); \
                                     `ro` is not supported"
                            );
                            return Err(());
                        }
                        let manifest_path =
                            format!("{}/{}", dir.trim_end_matches('/'), MANIFEST_NAME);
                        // Unlock before any backing store is built, so a wrong
                        // password cannot create a chunk or TOC write.
                        #[cfg(feature = "cipher")]
                        let cipher = bundle_cipher(spec, password, &meta, &manifest_path)?;
                        #[cfg(not(feature = "cipher"))]
                        {
                            let _ = &manifest_path;
                            if meta.cipher.is_some() {
                                eprintln!(
                                    "snowscsi: cipher: {manifest_path} describes an encrypted \
                                     recordable bundle, but this binary was built without the \
                                     `cipher` feature; refusing to serve the raw ciphertext"
                                );
                                return Err(());
                            }
                        }
                        let fs = FsPlaneAdapter::new(StdFsBackend::new(dir));
                        // Capacity and disc kind come from the stored TOC;
                        // no CLI hints are applied.
                        let store = BundleStore::new(fs, 0, None);
                        #[cfg(feature = "cipher")]
                        let store = match cipher {
                            Some((cipher, nonce)) => CdrStore::new_cipher(store, cipher, nonce),
                            None => CdrStore::new(store),
                        };
                        #[cfg(not(feature = "cipher"))]
                        let store = CdrStore::new(store);
                        OwnedPlane::CdrBundle(store)
                    }
                    #[cfg(not(feature = "cdr-bundle"))]
                    {
                        let _ = (meta, toc);
                        eprintln!(
                            "snowscsi: bundle: {dir} is a recordable CD; serving it requires \
                                 the `cdr-bundle` feature"
                        );
                        return Err(());
                    }
                }
                Identified::Image { .. } => {
                    eprintln!(
                        "snowscsi: bundle: {dir} carries a single-file image manifest, not a \
                             directory bundle"
                    );
                    return Err(());
                }
            }
        }
        #[cfg(not(feature = "bundle"))]
        Backing::Bundle { dir } => {
            eprintln!("snowscsi: bundle= requires the `bundle` feature: {dir}");
            return Err(());
        }
        Backing::Ram { size } => {
            let bytes = usize::try_from(*size).map_err(|_| {
                eprintln!("snowscsi: RAM size {size} too large for this platform");
            })?;
            OwnedPlane::Ram {
                bytes: vec![0u8; bytes],
                writable: !spec.plane.read_only,
            }
        }
        Backing::Img { path } => {
            // Read-only is enforced at BOTH layers: the plane is opened
            // `rb` (so it works on read-only media; never `r+b`), and the
            // LUN is built with `disk_read_only` (locked write policy).
            let writable = spec.role == DeviceRole::BlockDisk && !spec.plane.read_only;
            open_img_plane(path, writable)?
        }
        Backing::Empty => {
            // One plane per spec keeps LUN/plane alignment; the empty-CDR
            // arm in `build_core_slots` drops it and pushes `None`.
            OwnedPlane::Ram {
                bytes: Vec::new(),
                writable: false,
            }
        }
        Backing::Live { dir } => {
            let fs = StdFsBackend::new(dir);
            let label = Path::new(dir)
                .file_name()
                .and_then(|n| n.to_str())
                .unwrap_or("SNOWSCSI");
            let live = LiveData::new(fs, label).map_err(|e| {
                eprintln!("snowscsi: failed to scan live directory {dir}: {e}");
            })?;
            OwnedPlane::Live(live)
        }
        #[cfg(feature = "dvdram")]
        Backing::DvdRam { path } => match path.as_deref() {
            Some(path) => {
                let existed = Path::new(path).exists();
                if existed && spec.plane.size.is_some() {
                    eprintln!("snowscsi: dvdram: size= is only valid for a new file: {path}");
                    return Err(());
                }
                if !existed {
                    let Some(sz) = spec.plane.size else {
                        eprintln!(
                            "snowscsi: dvdram: file not found, use size= to create it: {path}"
                        );
                        return Err(());
                    };
                    create_sparse(path, sz).map_err(|e| {
                        eprintln!("snowscsi: dvdram: failed to create {path}: {e}");
                    })?;
                }
                let backend = FileBackend::open(path, true).map_err(|e| {
                    eprintln!("snowscsi: dvdram: failed to open {path}: {e}");
                })?;
                OwnedPlane::BlockRw(backend)
            }
            None => {
                let bytes = spec.plane.size.ok_or_else(|| {
                    eprintln!("snowscsi: dvdram=ram: requires size=");
                })?;
                let bytes = usize::try_from(bytes).map_err(|_| {
                    eprintln!("snowscsi: dvdram=ram: size too large");
                })?;
                OwnedPlane::Ram {
                    bytes: vec![0u8; bytes],
                    writable: true,
                }
            }
        },
        #[cfg(not(feature = "dvdram"))]
        Backing::DvdRam { .. } => {
            eprintln!("snowscsi: dvdram= requires the `dvdram` feature");
            return Err(());
        }
    };
    #[cfg(feature = "cipher")]
    {
        use snowscsi::common::cipher::CipherPlane;
        Ok(match cipher {
            Some(cipher) => OwnedPlane::Cipher(Box::new(CipherPlane::new(base, cipher))),
            None => base,
        })
    }
    #[cfg(not(feature = "cipher"))]
    {
        Ok(base)
    }
}

/// Validate the manifest and build the spec's cipher for an `img=` LUN.
///
/// A `bundle=` LUN resolves its cipher from the already-identified manifest
/// inside [`open_plane_for`], so this returns `None` for it.
///
/// For an `img=` LUN it runs before the image is opened, so a
/// missing/incorrect sidecar never leaves a half-opened backing (or creates a
/// file) behind. Without `,cipher` an encrypted sidecar is a hard error, never
/// a plaintext fallback.
#[cfg(feature = "cipher")]
fn prepare_cipher(
    spec: &DeviceSpec,
    password: Option<&[u8]>,
) -> Result<Option<crate::cipher::CliCipher>, ()> {
    let Backing::Img { path } = &spec.backing else {
        return Ok(None);
    };
    let Some(cipher_spec) = &spec.cipher else {
        let sidecar = format!("{path}{SIDECAR_SUFFIX}");
        return match read_capped(&sidecar, MAX_MANIFEST + 1) {
            Ok(bytes) => {
                let meta = match BundleMeta::parse(&bytes) {
                    Ok(meta) => meta,
                    Err(e) => {
                        eprintln!("snowscsi: cipher: invalid manifest '{sidecar}': {e}");
                        return Err(());
                    }
                };
                if meta.cipher.is_some() {
                    eprintln!(
                        "snowscsi: cipher: EncryptedManifest: '{sidecar}' is encrypted; add \
                         `,cipher` to the LUN spec"
                    );
                    return Err(());
                }
                Ok(None)
            }
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
            Err(e) => {
                eprintln!("snowscsi: cipher: cannot read manifest '{sidecar}': {e}");
                Err(())
            }
        };
    };

    let (meta, manifest_path) = match load_cipher_meta(spec, cipher_spec) {
        Ok(meta) => meta,
        Err(e) => {
            eprintln!("snowscsi: cipher: {e}");
            return Err(());
        }
    };
    let Some(cipher_meta) = meta.cipher else {
        eprintln!(
            "snowscsi: cipher: NotEncrypted: '{manifest_path}' does not describe a cipher; \
             remove `,cipher` from the LUN spec"
        );
        return Err(());
    };
    build_cli_cipher(
        cipher_meta,
        &meta.kind,
        spec,
        password,
        &manifest_path,
        meta.has_crc,
    )
    .map(Some)
}

/// Validate a cipher block and unlock the CLI cipher from the supplied
/// credential.
#[cfg(feature = "cipher")]
fn build_cli_cipher(
    cipher_meta: CipherMeta,
    kind: &BundleKind,
    spec: &DeviceSpec,
    password: Option<&[u8]>,
    manifest_path: &str,
    has_crc: bool,
) -> Result<crate::cipher::CliCipher, ()> {
    if !has_crc {
        log::debug!("cipher: {manifest_path} has no crc line; it detects damage only");
    }
    if cipher_meta.cipher == CipherAlg::Xor {
        log::warn!("cipher: xor is obfuscation, not encryption");
    }
    let mut credential = match cipher_meta.slot.kdf {
        KdfKind::Pbkdf2HmacSha256 => {
            if spec.key.is_some() {
                eprintln!(
                    "snowscsi: cipher: {manifest_path} uses PBKDF2; key= is only valid with \
                     kdf = none"
                );
                return Err(());
            }
            let Some(password) = password else {
                eprintln!(
                    "snowscsi: cipher: {manifest_path} uses PBKDF2; pass --password-file <path>"
                );
                return Err(());
            };
            crate::cipher::Credential::Password(password.to_vec())
        }
        KdfKind::None => {
            let Some(path) = spec.key.as_deref() else {
                eprintln!(
                    "snowscsi: cipher: {manifest_path} uses kdf = none; pass key=<path> on the \
                     LUN spec"
                );
                return Err(());
            };
            match crate::cipher::read_key_file(path) {
                Ok(key) => crate::cipher::Credential::Key(key),
                Err(e) => {
                    eprintln!("snowscsi: cipher: {e}");
                    return Err(());
                }
            }
        }
    };
    let unlocked = crate::cipher::unlock(&cipher_meta, kind, &credential);
    credential.wipe();
    let vmk = match unlocked {
        Ok(vmk) => vmk,
        Err(e) => {
            eprintln!("snowscsi: cipher: {manifest_path}: {e}");
            return Err(());
        }
    };
    let cipher = match crate::cipher::CliCipher::from_meta(&cipher_meta, &vmk) {
        Ok(cipher) => cipher,
        Err(e) => {
            eprintln!("snowscsi: cipher: {e}");
            return Err(());
        }
    };
    log::debug!(
        "using cipher {} ({manifest_path})",
        crate::cipher::cipher_meta_name(&cipher_meta)
    );
    Ok(cipher)
}

/// Resolve a directory bundle's cipher block from its identified manifest.
///
/// The identified manifest is authoritative. With `,cipher` an encrypted
/// manifest is required; without it a plaintext manifest is required. A
/// `cipher=<path>` override may only select an equivalent manifest: same kind
/// (including geometry), cipher, data nonce and key id, but its keyslot may
/// differ (a rekeyed copy). The override's keyslot unlocks the VMK and its
/// cipher block supplies the data nonce.
#[cfg(all(feature = "bundle", feature = "cipher"))]
fn bundle_cipher(
    spec: &DeviceSpec,
    password: Option<&[u8]>,
    identified: &BundleMeta,
    manifest_path: &str,
) -> Result<Option<(crate::cipher::CliCipher, [u8; 8])>, ()> {
    let Some(cipher_spec) = &spec.cipher else {
        if identified.cipher.is_some() {
            eprintln!(
                "snowscsi: cipher: EncryptedManifest: '{manifest_path}' is encrypted; add \
                 `,cipher` to the LUN spec"
            );
            return Err(());
        }
        return Ok(None);
    };
    let Some(identified_cipher) = identified.cipher else {
        eprintln!(
            "snowscsi: cipher: NotEncrypted: '{manifest_path}' does not describe a cipher; \
             remove `,cipher` from the LUN spec"
        );
        return Err(());
    };
    let (cipher_meta, path, has_crc) = match cipher_spec.meta.as_deref() {
        Some(explicit) => {
            let bytes = match read_capped(explicit, MAX_MANIFEST + 1) {
                Ok(bytes) => bytes,
                Err(e) => {
                    eprintln!("snowscsi: cipher: cannot read manifest '{explicit}': {e}");
                    return Err(());
                }
            };
            let meta = match BundleMeta::parse(&bytes) {
                Ok(meta) => meta,
                Err(e) => {
                    eprintln!("snowscsi: cipher: invalid manifest '{explicit}': {e}");
                    return Err(());
                }
            };
            if meta.kind != identified.kind {
                eprintln!(
                    "snowscsi: cipher: manifest '{explicit}' does not describe the identified \
                     bundle kind/geometry (refusing to serve)"
                );
                return Err(());
            }
            let Some(override_meta) = meta.cipher else {
                eprintln!(
                    "snowscsi: cipher: manifest '{explicit}' does not describe a cipher \
                     (refusing to serve)"
                );
                return Err(());
            };
            if override_meta.cipher != identified_cipher.cipher
                || override_meta.nonce != identified_cipher.nonce
                || override_meta.key_id != identified_cipher.key_id
            {
                eprintln!(
                    "snowscsi: cipher: manifest '{explicit}' wraps a different cipher/nonce/key \
                     id than the identified manifest (refusing to serve)"
                );
                return Err(());
            }
            (override_meta, explicit, meta.has_crc)
        }
        None => (identified_cipher, manifest_path, identified.has_crc),
    };
    let cipher = build_cli_cipher(cipher_meta, &identified.kind, spec, password, path, has_crc)?;
    Ok(Some((cipher, cipher_meta.nonce)))
}

/// Read and validate the manifest that describes a cipher-bearing `img=` LUN.
///
/// `Backing::Bundle` never reaches this function: the bundle path resolves its
/// cipher from the manifest it already identified ([`bundle_cipher`]).
#[cfg(feature = "cipher")]
fn load_cipher_meta(
    spec: &DeviceSpec,
    cipher_spec: &spec::CipherSpec,
) -> Result<(BundleMeta, String), String> {
    let Backing::Img { path } = &spec.backing else {
        return Err(
            "cipher metadata is only loaded for img=; a bundle uses its identified manifest"
                .to_string(),
        );
    };
    let sidecar = cipher_spec
        .meta
        .clone()
        .unwrap_or_else(|| format!("{path}{SIDECAR_SUFFIX}"));
    let bytes = read_capped(&sidecar, MAX_MANIFEST + 1)
        .map_err(|e| format!("cannot read manifest '{sidecar}': {e}"))?;
    let meta =
        BundleMeta::parse(&bytes).map_err(|e| format!("invalid manifest '{sidecar}': {e}"))?;
    // If the image's own sidecar exists, an explicit `cipher=<path>` must
    // describe the same image identity. The keyslot may differ (a rekeyed
    // copy), but kind/size, cipher, data nonce and key id must match.
    let default_sidecar = format!("{path}{SIDECAR_SUFFIX}");
    if cipher_spec.meta.is_some() && Path::new(&default_sidecar).is_file() {
        let default_bytes = read_capped(&default_sidecar, MAX_MANIFEST + 1)
            .map_err(|e| format!("cannot read manifest '{default_sidecar}': {e}"))?;
        let default_meta = BundleMeta::parse(&default_bytes)
            .map_err(|e| format!("invalid manifest '{default_sidecar}': {e}"))?;
        if default_meta.kind != meta.kind {
            return Err(format!(
                "manifest '{sidecar}' does not describe the same image as '{default_sidecar}' \
                 (kind/size mismatch)"
            ));
        }
        match (default_meta.cipher, meta.cipher) {
            (Some(default_cipher), Some(chosen))
                if default_cipher.cipher == chosen.cipher
                    && default_cipher.nonce == chosen.nonce
                    && default_cipher.key_id == chosen.key_id => {}
            _ => {
                return Err(format!(
                    "manifest '{sidecar}' wraps a different cipher/nonce/key id than \
                     '{default_sidecar}' (refusing to serve)"
                ))
            }
        }
    }
    let image_size = std::fs::metadata(path)
        .map_err(|e| format!("cannot stat image '{path}': {e}"))?
        .len();
    match meta.kind {
        BundleKind::Image { size } if size == image_size => {}
        BundleKind::Image { size } => {
            return Err(format!(
                "manifest '{sidecar}' declares image size {size}, but '{path}' is \
                 {image_size} bytes"
            ))
        }
        _ => {
            return Err(format!(
                "manifest '{sidecar}' is not a single-file image manifest"
            ))
        }
    }
    Ok((meta, sidecar))
}

fn create_sparse(path: &str, size: u64) -> std::io::Result<()> {
    let f = File::create(path)?;
    f.set_len(size)?;
    Ok(())
}

/// Identity of the "card" file at one observation: length and mtime.
///
/// A partially-written card changes on the next poll, so an install waits for
/// two consecutive identical observations.
#[cfg(target_os = "linux")]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct CardStamp {
    len: u64,
    mtime: Option<std::time::SystemTime>,
}

/// One filesystem observation of the card path.
#[cfg(target_os = "linux")]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum CardObservation {
    /// No path (or an unreadable one).
    Missing,
    /// The path exists but is not a regular file (directory, device, …).
    NotRegular,
    /// A regular file with its stamp.
    Regular(CardStamp),
}

/// What the watcher should do after one observation.
#[cfg(target_os = "linux")]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum CardDecision {
    /// Keep waiting (missing/not regular, first sighting, unchanged).
    Wait,
    /// Leave the slot empty and log this reason.
    Reject(&'static str),
    /// Two consecutive identical sightings of a valid new card.
    Insert(CardStamp),
}

/// Pure watcher state machine (no filesystem, no threads).
///
/// It is armed only while the LUN is empty. A card swap while a card is
/// installed is deliberately **not** detected: the host must eject first, so
/// host WRITEs to the mounted image cannot self-eject it.
#[cfg(target_os = "linux")]
struct CardWatch {
    baseline: Option<CardStamp>,
    absent: bool,
    candidate: Option<CardStamp>,
    min_bytes: u64,
}

#[cfg(target_os = "linux")]
impl CardWatch {
    fn new(baseline: Option<CardStamp>, min_bytes: u64) -> Self {
        Self {
            baseline,
            absent: baseline.is_none(),
            candidate: None,
            min_bytes,
        }
    }

    fn observe(&mut self, observation: CardObservation) -> CardDecision {
        match observation {
            CardObservation::Missing | CardObservation::NotRegular => {
                self.absent = true;
                self.candidate = None;
                CardDecision::Wait
            }
            CardObservation::Regular(stamp) if stamp.len < self.min_bytes => {
                self.absent = false;
                self.candidate = None;
                if self.baseline == Some(stamp) {
                    // The same too-small file is not retried every poll; only
                    // a changed/replaced file is tested again.
                    CardDecision::Wait
                } else {
                    self.baseline = Some(stamp);
                    CardDecision::Reject("image is smaller than one logical sector")
                }
            }
            CardObservation::Regular(stamp) => {
                if self.candidate == Some(stamp) {
                    self.candidate = None;
                    self.absent = false;
                    CardDecision::Insert(stamp)
                } else if self.absent || Some(stamp) != self.baseline {
                    self.absent = false;
                    self.candidate = Some(stamp);
                    CardDecision::Wait
                } else {
                    self.candidate = None;
                    CardDecision::Wait
                }
            }
        }
    }
}

#[cfg(target_os = "linux")]
fn observe_card(path: &str) -> CardObservation {
    match std::fs::metadata(path) {
        Ok(meta) if meta.is_file() => CardObservation::Regular(CardStamp {
            len: meta.len(),
            mtime: meta.modified().ok(),
        }),
        Ok(_) => CardObservation::NotRegular,
        Err(_) => CardObservation::Missing,
    }
}

#[cfg(target_os = "linux")]
fn card_stamp(path: &str) -> Option<CardStamp> {
    match observe_card(path) {
        CardObservation::Regular(stamp) => Some(stamp),
        CardObservation::Missing | CardObservation::NotRegular => None,
    }
}

/// The watcher is only meaningful while a removable slot is empty. A loaded
/// card is watched by the host filesystem, not by us.
#[cfg(target_os = "linux")]
fn should_arm_card_watcher(removable: bool, slot_empty: bool) -> bool {
    removable && slot_empty
}

/// Start the background card watcher for an **empty** slot.
///
/// It polls `path` every 200 ms (never in the serve loop), ignores anything
/// that is not a regular file, and publishes an insert only after the same
/// non-baseline stamp is seen twice in a row. On detection it sets `insert`,
/// calls `flow.pause()` and exits; the serve loop performs the install at the
/// next clean `ServeExit::Paused`. A same-size/same-mtime replacement is not
/// detected (the host must still eject first).
#[cfg(target_os = "linux")]
#[allow(clippy::too_many_arguments)]
fn spawn_card_watcher(
    path: String,
    baseline: Option<CardStamp>,
    min_bytes: u64,
    insert: Arc<AtomicBool>,
    flow: Arc<snowscsi::core::Flow>,
    stop: Arc<AtomicBool>,
) -> JoinHandle<()> {
    std::thread::spawn(move || {
        let mut watch = CardWatch::new(baseline, min_bytes);
        while !stop.load(Ordering::Relaxed) {
            std::thread::sleep(Duration::from_millis(200));
            if stop.load(Ordering::Relaxed) {
                break;
            }
            match watch.observe(observe_card(&path)) {
                CardDecision::Wait => {}
                CardDecision::Reject(reason) => {
                    log::warn!("card watcher: {path}: {reason}");
                }
                CardDecision::Insert(_) => {
                    // Keep re-requesting the pause until the serve loop
                    // consumes the flag or stops us: this closes the race with
                    // a concurrent `flow.run()` on a non-insert pause.
                    insert.store(true, Ordering::Release);
                    while !stop.load(Ordering::Relaxed) && insert.load(Ordering::Acquire) {
                        flow.pause();
                        std::thread::sleep(Duration::from_millis(200));
                    }
                    break;
                }
            }
        }
    })
}

/// Arm the watcher only when the slot is actually empty.
#[cfg(target_os = "linux")]
fn arm_card_watcher(
    path: &str,
    sector: u32,
    removable: bool,
    slot_empty: bool,
    insert: &Arc<AtomicBool>,
    flow: &Arc<snowscsi::core::Flow>,
) -> Option<(JoinHandle<()>, Arc<AtomicBool>)> {
    if !should_arm_card_watcher(removable, slot_empty) {
        return None;
    }
    let stop = Arc::new(AtomicBool::new(false));
    let handle = spawn_card_watcher(
        path.to_string(),
        card_stamp(path),
        u64::from(sector),
        Arc::clone(insert),
        Arc::clone(flow),
        Arc::clone(&stop),
    );
    Some((handle, stop))
}

#[cfg(target_os = "linux")]
fn stop_card_watcher(watch: &mut Option<(JoinHandle<()>, Arc<AtomicBool>)>) {
    if let Some((handle, stop)) = watch.take() {
        stop.store(true, Ordering::Relaxed);
        let _ = handle.join();
    }
}

/// Build the block attributes for a card of `len` bytes.
///
/// A zero-length or sub-sector image is refused rather than becoming a
/// zero-block device (whose `READ CAPACITY` would report one bogus sector).
#[cfg(target_os = "linux")]
fn card_attrs(len: u64, sector: u32, read_only: bool) -> Result<BlockAttrs, &'static str> {
    if sector == 0 {
        return Err("invalid zero logical sector size");
    }
    let sector = u64::from(sector);
    if len < sector {
        return Err("image is smaller than one logical sector");
    }
    let mut attrs = BlockAttrs::new(len / sector, sector as u32).with_removable();
    if read_only {
        attrs.write_mode = Writability::ReadOnly;
    }
    Ok(attrs)
}

/// Directory of a `--cdrom bundle=` LUN, if any.
#[cfg(feature = "cdr-bundle")]
fn cdr_bundle_dir(specs: &[DeviceSpec], lun: usize) -> Option<&str> {
    match specs.get(lun).map(|spec| &spec.backing) {
        Some(Backing::Bundle { dir }) => Some(dir),
        _ => None,
    }
}

/// Snapshot an ejected CD-R bundle before its plane is dropped.
///
/// The taken pair still owns the medium's in-memory state; a clean or
/// finalized disc writes nothing. Snapshot failures are reported and never
/// abort the eject.
#[cfg(feature = "cdr-bundle")]
fn preserve_ejected_cdr(
    specs: &[DeviceSpec],
    lun: usize,
    taken: &mut Result<snowscsi::core::ChangeResult<CliPair>, snowscsi::core::BoundaryReject>,
) {
    let Some(pair) = taken.as_mut().ok().and_then(|result| result.pair.as_mut()) else {
        return;
    };
    let Some(dir) = cdr_bundle_dir(specs, lun) else {
        return;
    };
    match stack::snapshot_cdr_eject(pair, dir) {
        Ok(true) => log::info!("LUN {lun}: recordable-CD TOC snapshot written to {dir}"),
        Ok(false) => {}
        Err(e) => log::warn!("LUN {lun}: recordable-CD TOC snapshot failed: {e}"),
    }
}

/// No-op without the `cdr-bundle` feature.
#[cfg(not(feature = "cdr-bundle"))]
fn preserve_ejected_cdr(
    _specs: &[DeviceSpec],
    _lun: usize,
    _taken: &mut Result<snowscsi::core::ChangeResult<CliPair>, snowscsi::core::BoundaryReject>,
) {
}

/// Build the fully installed slot for a newly inserted "card".
///
/// The slot is replaced wholesale because `BlockDevice` owns the geometry, so a
/// capacity change is a new device. `MediumChanged` is raised on the new `Spc`
/// before it is wrapped/handed to the target; the caller swaps the slot and its
/// plane at the clean pause boundary, so there is no fallible install step.
#[cfg(target_os = "linux")]
fn build_card_insert(
    lun: usize,
    spec: &DeviceSpec,
    path: &str,
) -> Result<(CliLu, OwnedPlane), String> {
    if spec.cipher.is_some() {
        // Parse already rejects it; this keeps the insert path from silently
        // installing a plaintext card at an encrypted slot.
        return Err(format!(
            "LUN {lun}: cipher is not supported with removable media"
        ));
    }
    let plane = open_img_plane(path, !spec.plane.read_only)
        .map_err(|_| format!("could not open new card '{path}'"))?;
    let attrs = card_attrs(plane.capacity(), spec.plane.sector, spec.plane.read_only)?;
    let mut spc = Spc::new(CoreBlockDevice::new(attrs));
    spc.raise_unit_attention(snowscsi::core::UaClass::MediumChanged);
    let lu = CliLu::Block(snowscsi::core::LuImpl::new(spc, lun as u32));
    Ok((lu, plane))
}

#[cfg(target_os = "linux")]
/// `snowscsi serve --usb`: assemble the MSC FunctionFS gadget, bind it to a
/// UDC, build the core `Target` over the parsed specs and drive the library
/// BOT loop ([`usb_serve`]).
fn run_serve_usb(
    args: &ServeArgs,
    specs: &[DeviceSpec],
    config: &ServeConfig,
    selector: &str,
    removable_lun: Option<usize>,
    password: &mut Option<Vec<u8>>,
) -> ExitCode {
    let mut planes: Vec<Option<OwnedPlane>> = Vec::new();
    let mut slots: Vec<CliLu> = Vec::new();
    let built = build_core_slots(specs, &mut planes, &mut slots, password.as_deref()).is_ok();
    // Best effort (not zeroize): the planes/ciphers have copied what they need.
    if let Some(bytes) = password.as_mut() {
        crate::wipe(bytes);
    }
    if !built {
        return ExitCode::FAILURE;
    }

    // Gadget assembly: a single MSC interface (class 08/06/50) with
    // one bulk OUT + one bulk IN endpoint.
    let (ep_out, out_dir) = EndpointDirection::host_to_device();
    let (ep_in, in_dir) = EndpointDirection::device_to_host();

    let (custom, handle) = Custom::builder()
        .with_interface(
            Interface::new(Class::MASS_STORAGE_SCSI_BULK, "snowscsi msc")
                .with_endpoint(Endpoint::bulk(out_dir))
                .with_endpoint(Endpoint::bulk(in_dir)),
        )
        .build();

    let choice = match resolve_udc(selector) {
        Ok(c) => c,
        Err(e) => {
            eprintln!("snowscsi: {e}");
            return ExitCode::FAILURE;
        }
    };
    let UdcChoice { udc, owns_configfs } = choice;
    log::info!("binding USB gadget to UDC {:?}", udc.name());
    let reg = match UsbGadget::new(
        Class::INTERFACE_SPECIFIC,
        Id::new(args.vid, args.pid),
        Strings::new("SnowSCSI", "SnowSCSI USB Disk", &args.serial),
    )
    .with_config(Config::new("config").with_function(handle))
    .bind(&udc)
    {
        Ok(r) => r,
        Err(e) => {
            eprintln!("snowscsi: failed to bind USB gadget: {e}");
            return ExitCode::FAILURE;
        }
    };

    let flow = Arc::new(snowscsi::core::Flow::new());
    {
        let flow = Arc::clone(&flow);
        if let Err(e) = ctrlc::set_handler(move || flow.stop()) {
            eprintln!("snowscsi: failed to install signal handler: {e}");
            return ExitCode::FAILURE;
        }
    }

    let mut ffs_bot = FfsBot::new(ep_out, ep_in);
    let mut ffs_gadget = FfsGadget { custom };
    // Data-In shortfall policy (`--usb-shortfall`): `short` (conformant short
    // packet + STALL Bulk-In), `pad` (conformant fill, no control plane), or
    // `short-no-stall` (max-compat short packet, no STALL).
    let shortfall = match args.usb_shortfall.as_str() {
        "pad" => ShortfallPolicy::Pad,
        "short" => ShortfallPolicy::Short,
        "short-no-stall" => ShortfallPolicy::ShortNoStall,
        other => {
            eprintln!(
                "snowscsi: invalid --usb-shortfall '{other}' \
                 (expected pad, short, or short-no-stall)"
            );
            return ExitCode::FAILURE;
        }
    };
    let lun_count = slots.len();
    let mut session = BotSession::with_luns(lun_count).with_shortfall(shortfall);
    if config.overlap() {
        // Two equal banks inside `work`: command framing/Data-Out in one,
        // prefetch and the resident long operation in the other.
        session = session.with_overlap();
    }
    let mut work = vec![0u8; config.work_size];
    let mut scratch = split_bank(config.scratch_len);

    log::info!(
        "serving {lun_count} LUN(s) over USB (wire={}, banks={}, storage={}, per_bank={})",
        config.wire.as_str(),
        config.banks.as_str(),
        config.storage(pool_capable(specs, config)),
        config.per_bank(),
    );
    let serve_res = if config.overlap() {
        let per_bank = config.per_bank();
        std::thread::scope(|scope| {
            let mut store = WorkerStore::new(scope, planes, per_bank);
            // The target/table stay alive across `ResourcesReady` and
            // non-rebuild `Paused` returns. This path has no slot swap, so one
            // scoped target is the whole lifetime.
            let res = {
                let mut table: Vec<&mut dyn Lu<Pair = CliPair>> = slots
                    .iter_mut()
                    .map(|s| s as &mut dyn Lu<Pair = CliPair>)
                    .collect();
                let mut target = snowscsi::core::Target::new(&mut table[..]);
                loop {
                    match usb_serve(
                        &mut ffs_bot,
                        &mut ffs_gadget,
                        &mut session,
                        &mut work,
                        &mut scratch,
                        &mut target,
                        &mut store,
                        &flow,
                    ) {
                        Ok(snowscsi::core::ServeExit::Outcome(
                            snowscsi::core::RunOutcome::ResourcesReady { lun },
                        )) => {
                            // The host ejected: flush the bundle's track data,
                            // take the pair so the slot is not left with a
                            // resident result, preserve a CD-R TOC snapshot,
                            // then keep serving with the SAME target/runner:
                            // another LUN may still have a resident
                            // long-operation receipt.
                            #[cfg(feature = "cdr-bundle")]
                            if cdr_bundle_dir(specs, lun).is_some() {
                                if let Err((i, e)) = store.sync() {
                                    log::warn!(
                                        "LUN {lun}: recordable-CD pre-eject flush failed for LUN {i}: {e}"
                                    );
                                }
                            }
                            let mut taken = target.take_rt(lun);
                            preserve_ejected_cdr(specs, lun, &mut taken);
                            drop(taken);
                            store.resources_released(lun);
                            log::info!("LUN {lun}: medium ejected by the host");
                        }
                        Ok(snowscsi::core::ServeExit::Paused) => {
                            // A pause is only a handback; there is no rebuild
                            // in the dual-bank path, so resume immediately.
                            if flow.state() == snowscsi::core::FlowState::Pause {
                                flow.run();
                            }
                        }
                        other => break other,
                    }
                }
            };
            if let Err((i, e)) = store.sync() {
                eprintln!("snowscsi: sync failed for LUN {i}: {e}");
            }
            drop(store);
            res
        })
    } else {
        let mut storage = CliStorage::new(planes);
        let removable_path = removable_lun.and_then(|lun| match &specs[lun].backing {
            Backing::Img { path } => Some(path.clone()),
            _ => None,
        });
        let insert_pending = Arc::new(AtomicBool::new(false));
        let mut card_watch: Option<(JoinHandle<()>, Arc<AtomicBool>)> = None;
        let res = 'outer: loop {
            // The target lives across `ResourcesReady` and non-rebuild
            // `Paused` returns; dropping it would lose another LUN's resident
            // `long_feedback`/`long_pending`. It is dropped only at the clean
            // insert boundary below.
            let exit = {
                let mut table: Vec<&mut dyn Lu<Pair = CliPair>> = slots
                    .iter_mut()
                    .map(|s| s as &mut dyn Lu<Pair = CliPair>)
                    .collect();
                let mut target = snowscsi::core::Target::new(&mut table[..]);
                loop {
                    match usb_serve(
                        &mut ffs_bot,
                        &mut ffs_gadget,
                        &mut session,
                        &mut work,
                        &mut scratch,
                        &mut target,
                        &mut storage,
                        &flow,
                    ) {
                        Ok(snowscsi::core::ServeExit::Outcome(
                            snowscsi::core::RunOutcome::ResourcesReady { lun },
                        )) => {
                            // `ResourcesReady` is not a rebuild point: flush
                            // the bundle's track data, take the pair, preserve a
                            // CD-R TOC snapshot, and keep the same
                            // target/runner serving.
                            #[cfg(feature = "cdr-bundle")]
                            if cdr_bundle_dir(specs, lun).is_some() {
                                if let Err((i, e)) = storage.sync() {
                                    log::warn!(
                                        "LUN {lun}: recordable-CD pre-eject flush failed for LUN {i}: {e}"
                                    );
                                }
                            }
                            let mut taken = target.take_rt(lun);
                            preserve_ejected_cdr(specs, lun, &mut taken);
                            drop(taken);
                            storage.resources_released(lun);
                            log::info!("LUN {lun}: medium ejected by the host");
                            if Some(lun) == removable_lun {
                                storage.set_plane(lun, None);
                                insert_pending.store(false, Ordering::Release);
                                stop_card_watcher(&mut card_watch);
                                if let Some(path) = removable_path.as_deref() {
                                    card_watch = arm_card_watcher(
                                        path,
                                        specs[lun].plane.sector,
                                        true,
                                        true,
                                        &insert_pending,
                                        &flow,
                                    );
                                    log::info!(
                                    "LUN {lun}: card removed; waiting for a new image at {path}"
                                );
                                }
                            }
                        }
                        Ok(snowscsi::core::ServeExit::Paused) => {
                            // `Paused` is only produced when `pause_requested` saw
                            // `management_boundary().is_ok()`, i.e. the safe point
                            // to drop the runner and swap the slot.
                            let insert_ready = insert_pending.load(Ordering::Acquire);
                            if removable_lun.is_some()
                                && insert_ready
                                && target.management_boundary().is_ok()
                            {
                                insert_pending.store(false, Ordering::Release);
                                break None;
                            }
                            // Do not clobber `Stop`: it must end the loop.
                            if !insert_ready && flow.state() == snowscsi::core::FlowState::Pause {
                                flow.run();
                            }
                        }
                        other => break Some(other),
                    }
                }
            };
            let Some(result) = exit else {
                // Clean boundary: the target/table block is closed, so `slots`
                // is free to mutate. The new slot is fully installed (`CliLu`
                // carries the plane's geometry and a pending MediumChanged UA),
                // so there is no fallible install step afterwards.
                stop_card_watcher(&mut card_watch);
                if let (Some(lun), Some(path)) = (removable_lun, removable_path.as_deref()) {
                    match build_card_insert(lun, &specs[lun], path) {
                        Ok((lu, plane)) => {
                            slots[lun] = lu;
                            storage.set_plane(lun, Some(plane));
                            log::info!("LUN {lun}: new card installed from {path}");
                            // Deliberately do not re-arm: a loaded card is not
                            // watched, so host writes cannot self-eject it.
                        }
                        Err(msg) => {
                            eprintln!("snowscsi: LUN {lun}: {msg}");
                            // The slot is still empty; keep watching for a
                            // valid replacement.
                            card_watch = arm_card_watcher(
                                path,
                                specs[lun].plane.sector,
                                true,
                                true,
                                &insert_pending,
                                &flow,
                            );
                        }
                    }
                }
                if flow.state() == snowscsi::core::FlowState::Pause {
                    flow.run();
                }
                continue 'outer;
            };
            stop_card_watcher(&mut card_watch);
            break 'outer result;
        };
        if let Err((i, e)) = storage.sync() {
            eprintln!("snowscsi: sync failed for LUN {i}: {e}");
        }
        res
    };

    if let Err(e) = serve_res {
        eprintln!("snowscsi: usb serve error: {e}");
        drop(reg);
        release_configfs(owns_configfs);
        return ExitCode::FAILURE;
    }

    // Graceful exit: unregister the gadget (RAII), then unmount configfs again
    // if the `dummy` auto-config mounted it.
    drop(reg);
    release_configfs(owns_configfs);
    log::info!("shutting down");
    ExitCode::SUCCESS
}

#[cfg(target_os = "linux")]
/// The result of [`resolve_udc`]: the selected controller plus the configfs
/// mount ownership recorded by the `dummy` auto-config path.
struct UdcChoice {
    udc: Udc,
    /// True when `resolve_udc("dummy")` mounted configfs — the caller must
    /// unmount it again via [`release_configfs`] on exit.
    owns_configfs: bool,
}

#[cfg(target_os = "linux")]
/// Pick the UDC to bind from the `--usb` selector: `auto` (default — prefer
/// a real controller over the test-only `dummy_udc`), `dummy` (auto-load
/// `dummy_hcd` + `libcomposite`, ensure configfs and bind `dummy_udc.0`), a
/// UDC name, or a driver prefix.
fn resolve_udc(selector: &str) -> Result<UdcChoice, String> {
    match selector {
        "dummy" => ensure_dummy_udc(),
        "auto" => {
            let all = udcs().map_err(|e| format!("failed to enumerate UDCs: {e}"))?;
            let chosen = all
                .iter()
                .find(|u| is_real_udc(u))
                .or_else(|| all.first())
                .ok_or_else(|| {
                    "no USB device controller (UDC) available; load dummy_hcd or pass `--usb dummy`"
                        .to_string()
                })?;
            if all.len() > 1 {
                log::info!(
                    "auto-selected UDC {:?} (available: {})",
                    chosen.name(),
                    describe_udcs(&all)
                );
            }
            Ok(UdcChoice {
                udc: chosen.clone(),
                owns_configfs: false,
            })
        }
        sel => {
            let all = udcs().map_err(|e| format!("failed to enumerate UDCs: {e}"))?;
            all.into_iter()
                .find(|u| udc_matches(u, sel))
                .map(|u| UdcChoice {
                    udc: u,
                    owns_configfs: false,
                })
                .ok_or_else(|| {
                    format!(
                        "UDC not found: {sel} (available: {})",
                        describe_udcs(&udcs().unwrap_or_default())
                    )
                })
        }
    }
}

#[cfg(target_os = "linux")]
/// `auto` heuristic: a controller with a real kernel driver, not the
/// test-only `dummy_hcd`'s `dummy_udc`.
fn is_real_udc(u: &Udc) -> bool {
    u.driver()
        .map(|d| d.to_string_lossy() != "dummy_udc")
        .unwrap_or(true)
}

#[cfg(target_os = "linux")]
/// Selector match: exact UDC name, exact driver name, or UDC name prefix
/// (`--usb dwc2` matches `dwc2.0`).
fn udc_matches(u: &Udc, sel: &str) -> bool {
    let name = u.name().to_string_lossy();
    name == sel
        || name.starts_with(sel)
        || u.driver()
            .map(|d| d.to_string_lossy() == sel)
            .unwrap_or(false)
}

#[cfg(target_os = "linux")]
/// `name (driver)` for each controller, for error / log messages.
fn describe_udcs(all: &[Udc]) -> String {
    all.iter()
        .map(|u| format!("{:?} ({:?})", u.name(), u.driver().ok()))
        .collect::<Vec<_>>()
        .join(", ")
}

#[cfg(target_os = "linux")]
/// The `--usb dummy` auto-config: modprobe `dummy_hcd` + `libcomposite`
/// (idempotent; never unloaded — the module may be a shared resource),
/// ensure configfs is mounted, and return `dummy_udc.0` with the configfs
/// mount ownership flag.
fn ensure_dummy_udc() -> Result<UdcChoice, String> {
    for module in ["dummy_hcd", "libcomposite"] {
        match std::process::Command::new("modprobe").arg(module).status() {
            Ok(s) if s.success() => {}
            _ => {
                return Err(format!(
                    "failed to load kernel module '{module}' \
                     (is modprobe available and are you root?)"
                ));
            }
        }
    }
    let owns_configfs = ensure_configfs()?;
    let udc = udcs()
        .map_err(|e| format!("failed to enumerate UDCs: {e}"))?
        .into_iter()
        .find(|u| u.name().to_str() == Some("dummy_udc.0"))
        .ok_or_else(|| "dummy_udc.0 not available after loading dummy_hcd".to_string())?;
    Ok(UdcChoice { udc, owns_configfs })
}

#[cfg(target_os = "linux")]
/// Ensure configfs is mounted at `/sys/kernel/config` (most distros do not
/// mount it by default; `libcomposite` registers `/sys/kernel/config/
/// usb_gadget` when loaded). Returns `true` when this call mounted it — the
/// caller must unmount it again via [`release_configfs`].
fn ensure_configfs() -> Result<bool, String> {
    if Path::new("/sys/kernel/config/usb_gadget").is_dir() {
        return Ok(false);
    }
    let _ = std::fs::create_dir_all("/sys/kernel/config");
    match std::process::Command::new("mount")
        .args(["-t", "configfs", "none", "/sys/kernel/config"])
        .status()
    {
        Ok(s) if s.success() => Ok(true),
        // Lost a race: someone else mounted configfs while we tried.
        _ if Path::new("/sys/kernel/config/usb_gadget").is_dir() => Ok(false),
        _ => Err("failed to mount configfs at /sys/kernel/config \
             (is 'mount' available and are you root?)"
            .to_string()),
    }
}

#[cfg(target_os = "linux")]
/// Unmount configfs again after the serve loop, but only when this process
/// mounted it (never touch a pre-existing mount).
fn release_configfs(owned: bool) {
    if owned {
        let _ = std::process::Command::new("umount")
            .arg("/sys/kernel/config")
            .status();
    }
}

#[cfg(target_os = "linux")]
/// bulk I/O bridge: FunctionFS endpoint <-> [`BotIo`].
///
/// The crate's bulk endpoints use Linux native aio with `Bytes`/`BytesMut`
/// buffers; each receive copies the aio buffer into the caller's slice
/// `halt` reports success as `Err(-EBADMSG)` (errno 74), so
/// `stall_both` treats it as success and ignores the error.
struct FfsBot {
    out: EndpointReceiver,
    in_: EndpointSender,
    /// Marker for the single read currently in flight on the aio receive
    /// queue. FunctionFS fills reads in queue order, so a mix of stale /
    /// leftover buffers of different sizes (accumulated by enqueue-on-timeout
    /// polling) corrupts the chunked data phase: reads complete out of sync
    /// with the core's byte accounting and the transfer stalls. Keeping at
    /// most one read in flight and re-enqueuing only after a completion
    /// avoids that entirely.
    pending: bool,
}

/// Errno values that mean the USB host disconnected: FunctionFS disables the
/// endpoints on unplug, failing the pending transfers with `ESHUTDOWN`
/// (108), `ENOTCONN` (107), `ECONNRESET` (104), `ECONNABORTED` (103) or
/// `EPIPE` (32). Unlike other I/O failures these are expected and
/// recoverable — the serve loop resets the session and re-arms.
#[cfg(target_os = "linux")]
fn is_link_down_err(e: &std::io::Error) -> bool {
    matches!(e.raw_os_error(), Some(32 | 103 | 104 | 107 | 108))
}

#[cfg(target_os = "linux")]
impl FfsBot {
    fn new(out: EndpointReceiver, in_: EndpointSender) -> Self {
        Self {
            out,
            in_,
            pending: false,
        }
    }

    /// Round `n` up to the next multiple of the USB bulk MPS (minimum one
    /// MPS). FunctionFS aio reads require an MPS-multiple buffer, so this
    /// platform quirk lives here rather than in the
    /// platform-agnostic library `usb::serve` loop.
    fn round_up_mps(n: usize) -> usize {
        (n + USB_MPS - 1) & !(USB_MPS - 1)
    }

    /// Enqueue one read of `size` bytes (rounded up to the USB MPS) unless a
    /// read is already in flight.
    fn ensure_read(&mut self, size: usize) -> Result<(), BotIoErr> {
        if self.pending {
            return Ok(());
        }
        let size = Self::round_up_mps(size.max(1));
        self.out
            .try_recv(bytes::BytesMut::zeroed(size))
            .map_err(|e| {
                log::error!("aio read enqueue failed: {e} (buf.len={size})");
                BotIoErr::Io
            })?;
        self.pending = true;
        Ok(())
    }

    /// Receive into `buf`: wait for the in-flight read (`None` timeout blocks,
    /// `Some(t)` waits up to `t`), then copy the received bytes out.
    fn recv_impl(&mut self, buf: &mut [u8], timeout: Option<Duration>) -> Result<usize, BotIoErr> {
        self.ensure_read(buf.len())?;
        let fetch = |out: &mut EndpointReceiver| match timeout {
            Some(t) => out.fetch_timeout(t),
            None => out.fetch(),
        };
        let d = match fetch(&mut self.out) {
            Ok(Some(d)) => d,
            Ok(None) => return Err(BotIoErr::WouldBlock),
            // The completion was consumed on error, so no read is in flight
            // anymore: clear `pending` or the next receive would wait forever
            // for a completion that never comes.
            Err(e) => {
                self.pending = false;
                if is_link_down_err(&e) {
                    log::info!("USB link down: {e} (buf.len={})", buf.len());
                    return Err(BotIoErr::Disconnected);
                }
                log::error!("aio fetch failed: {e} (buf.len={})", buf.len());
                return Err(BotIoErr::Io);
            }
        };
        self.pending = false;
        let n = d.len().min(buf.len());
        buf[..n].copy_from_slice(&d[..n]);
        Ok(n)
    }
}

#[cfg(target_os = "linux")]
impl BotIo for FfsBot {
    fn try_recv_out(&mut self, buf: &mut [u8]) -> Result<usize, BotIoErr> {
        self.recv_impl(buf, Some(Duration::ZERO))
    }

    fn recv_out(&mut self, buf: &mut [u8], timeout: Option<Duration>) -> Result<usize, BotIoErr> {
        self.recv_impl(buf, timeout)
    }

    fn send_in(&mut self, buf: &[u8]) -> Result<(), BotIoErr> {
        self.in_
            .send(bytes::Bytes::copy_from_slice(buf))
            .map_err(|e| {
                if is_link_down_err(&e) {
                    log::info!("USB link down: {e}");
                    BotIoErr::Disconnected
                } else {
                    log::error!("bulk IN send failed: {e}");
                    BotIoErr::Io
                }
            })
    }

    fn stall_both(&mut self) -> Result<(), ()> {
        // halt() succeeds by returning Err(-EBADMSG) (errno 74) — treated as
        // success; discard in-flight aio first.
        let _ = self.out.control().and_then(|c| {
            let _ = c.discard_fifo();
            c.halt()
        });
        let _ = self.in_.control().and_then(|c| {
            let _ = c.discard_fifo();
            c.halt()
        });
        Ok(())
    }

    /// STALL the Bulk-In endpoint for a `ShortfallPolicy::Short` Data-In
    /// shortfall (BOT §6.7.2). `usb_ep_set_halt` returns `-EAGAIN` while a
    /// request is still queued or the FIFO holds bytes the host has not
    /// collected, so retry within a bounded budget (draining in-flight sends
    /// first) exactly like the in-kernel `halt_bulk_in_endpoint`. The benign
    /// `-EBADMSG` (errno 74) success quirk is `Ok(())`; a real fault, or the
    /// deadline, is `Err(())` so the serve loop aborts via reset.
    fn stall_in(&mut self) -> Result<(), ()> {
        // `usb_ep_set_halt` is a synchronous control op: it returns -EAGAIN
        // while a request is still queued or the FIFO holds bytes the host has
        // not collected. Retry within a bounded budget, draining in-flight
        // sends first (mirrors the kernel's `halt_bulk_in_endpoint`).
        let deadline = std::time::Instant::now() + Duration::from_millis(500);
        loop {
            while !self.in_.is_empty() {
                if std::time::Instant::now() >= deadline {
                    break;
                }
                let _ = self.in_.flush_timeout(Duration::from_millis(10));
            }
            let control = self.in_.control().map_err(|e| {
                log::error!("bulk-IN control unavailable: {e}");
            })?;
            let _ = control.discard_fifo();
            match control.halt() {
                Ok(()) => return Ok(()),
                // halt() reports success as Err(-EBADMSG) (errno 74).
                Err(e) if e.raw_os_error() == Some(74) => return Ok(()),
                Err(e) if e.raw_os_error() == Some(11) => {
                    // -EAGAIN: transient (endpoint still busy) — let it drain
                    // and retry, exactly like the in-kernel gadget.
                    if std::time::Instant::now() >= deadline {
                        log::error!("bulk-IN endpoint halt timed out (-EAGAIN)");
                        return Err(());
                    }
                    std::thread::sleep(Duration::from_millis(2));
                }
                Err(e) => {
                    log::error!("bulk-IN endpoint halt failed: {e}");
                    return Err(());
                }
            }
        }
    }

    fn can_stall_in(&self) -> bool {
        // `stall_in` is implemented above over FunctionFS endpoint halt.
        true
    }
}

#[cfg(target_os = "linux")]
/// Bulk-Only Reset ack handle: completing the control status stage is the
/// drop of the FunctionFS receiver.
struct FfsAck<'a> {
    /// Held for its drop side-effect; never read.
    #[allow(dead_code)]
    receiver: Option<CtrlReceiver<'a>>,
}

#[cfg(target_os = "linux")]
impl CtrlAck for FfsAck<'_> {
    fn ack(self) {}
}

#[cfg(target_os = "linux")]
/// Get Max LUN reply handle.
struct FfsReply<'a> {
    sender: Option<CtrlSender<'a>>,
}

#[cfg(target_os = "linux")]
impl CtrlReply for FfsReply<'_> {
    fn send(&mut self, data: &[u8]) -> Result<(), ()> {
        // CtrlSender::send consumes itself; the short write (≤ wLength) is
        // tolerated. Never STALL Get Max LUN.
        self.sender
            .take()
            .map(|s| s.send(data))
            .unwrap_or(Ok(0))
            .map(|_| ())
            .map_err(|_| ())
    }
}

#[cfg(target_os = "linux")]
/// Control-plane bridge: FunctionFS ep0 setup events -> [`CtrlReq`].
struct FfsGadget {
    custom: Custom,
}

#[cfg(target_os = "linux")]
impl<'a> Gadget<'a> for FfsGadget {
    type Ack = FfsAck<'a>;
    type Reply = FfsReply<'a>;

    fn try_next_ctrl(&'a mut self) -> Option<CtrlReq<Self::Ack, Self::Reply>> {
        let ev = self.custom.try_event().ok()??;
        match ev {
            Event::SetupHostToDevice(receiver)
                if receiver.ctrl_req().request == snowscsi::usb::BOT_RESET =>
            {
                Some(CtrlReq::BotReset {
                    ack: FfsAck {
                        receiver: Some(receiver),
                    },
                })
            }
            Event::SetupDeviceToHost(sender)
                if sender.ctrl_req().request == snowscsi::usb::GET_MAX_LUN =>
            {
                Some(CtrlReq::GetMaxLun {
                    reply: FfsReply {
                        sender: Some(sender),
                    },
                })
            }
            Event::Bind | Event::Enable | Event::Disable => Some(CtrlReq::LinkReset),
            _ => None,
        }
    }
}

/// `snowscsi bundle-create <flat|cdr>` dispatch.
fn run_bundle_create(args: BundleCreateArgs) -> ExitCode {
    init_logging(0);
    match args.kind {
        BundleCreateKind::Flat(args) => create_flat_bundle(args),
        BundleCreateKind::Cdr(args) => create_cdr_bundle(args),
    }
}

/// Resolve `bundle-create`'s optional cipher flags.
///
/// Without `--cipher` every other cipher flag is rejected (a plaintext
/// manifest carries no cipher block). With it a credential is required:
/// `--key-file` selects `kdf = none`, `--password-file` selects PBKDF2, and
/// without either the password is prompted twice. The credential wraps a fresh
/// random VMK; only the keyslot is stored, never the password or the key.
#[cfg(all(feature = "cipher", feature = "bundle"))]
fn create_bundle_cipher(
    cipher: Option<&str>,
    iterations: Option<u32>,
    key_file: Option<&str>,
    password_file: Option<&str>,
    kind: &BundleKind,
) -> Result<Option<CipherMeta>, String> {
    let Some(name) = cipher else {
        for (flag, present) in [
            ("--iterations", iterations.is_some()),
            ("--key-file", key_file.is_some()),
            ("--password-file", password_file.is_some()),
        ] {
            if present {
                return Err(format!("{flag} requires --cipher"));
            }
        }
        return Ok(None);
    };
    if key_file.is_some() && iterations.is_some() {
        return Err("--key-file and --iterations are mutually exclusive".to_string());
    }
    let alg = crate::cipher::parse_alg(name)?;
    let kdf = if key_file.is_some() {
        KdfKind::None
    } else {
        KdfKind::Pbkdf2HmacSha256
    };
    let iterations = match kdf {
        KdfKind::None => None,
        KdfKind::Pbkdf2HmacSha256 => Some(iterations.unwrap_or(600_000)),
    };
    let mut credential = crate::cipher::read_credential(password_file, key_file, true)?;
    let nonce = crate::cipher::random_nonce()?;
    let created = crate::cipher::new_keyslot(alg, nonce, kdf, iterations, &credential, kind);
    credential.wipe();
    created.map(|(meta, _vmk)| Some(meta))
}

/// Short success suffix: the cipher name, or `plaintext`.
#[cfg(all(feature = "cipher", feature = "bundle"))]
fn cipher_summary(cipher: Option<&CipherMeta>) -> String {
    match cipher {
        Some(meta) if meta.cipher == CipherAlg::Xor => {
            log::warn!("xor is obfuscation, not encryption");
            "obfuscated with xor".to_string()
        }
        Some(meta) => format!("encrypted with {}", crate::cipher::cipher_meta_name(meta)),
        None => "plaintext".to_string(),
    }
}

/// `snowscsi bundle-create flat` — write a `kind = flat` manifest.
#[cfg(feature = "bundle")]
fn create_flat_bundle(args: CreateFlatArgs) -> ExitCode {
    let size = match spec::parse_size(&args.size) {
        Some(size) => size,
        None => {
            eprintln!("snowscsi: bundle-create: invalid --size '{}'", args.size);
            return ExitCode::FAILURE;
        }
    };
    let chunk = match args.chunk.as_deref() {
        None => snowscsi::common::flat_bundle::DEFAULT_CHUNK_SIZE,
        Some(raw) => match spec::parse_size(raw) {
            Some(chunk) => chunk,
            None => {
                eprintln!("snowscsi: bundle-create: invalid --chunk '{raw}'");
                return ExitCode::FAILURE;
            }
        },
    };
    if args.sector != 512 && args.sector != 2048 {
        eprintln!(
            "snowscsi: bundle-create: invalid --sector {} (512 or 2048)",
            args.sector
        );
        return ExitCode::FAILURE;
    }
    let dir = Path::new(&args.dir);
    let existed = dir.exists();
    if existed {
        for existing in [MANIFEST_NAME, "BUNDLE"] {
            if dir.join(existing).exists() {
                eprintln!(
                    "snowscsi: bundle-create: {} already contains {existing}; refusing to \
                     overwrite it (rekey changes credentials in place; delete the directory to \
                     rebuild the bundle)",
                    args.dir
                );
                return ExitCode::FAILURE;
            }
        }
        if let Some(name) = first_chunk_file(dir) {
            eprintln!(
                "snowscsi: bundle-create: {} already contains chunk {name}; a flat bundle \
                 requires an empty directory (delete the directory or use a new one)",
                args.dir
            );
            return ExitCode::FAILURE;
        }
    }
    // Validate before creating the directory so a bad `--size` cannot leave an
    // empty directory behind.
    if let Err(e) = validate_geometry(chunk, size, args.sector) {
        eprintln!(
            "snowscsi: bundle-create: invalid geometry (--size {}, --chunk {chunk}, \
             --sector {}): {e}",
            args.size, args.sector
        );
        return ExitCode::FAILURE;
    }
    let kind = BundleKind::Flat {
        virtual_size: size,
        chunk_size: chunk,
        sector_size: args.sector,
    };
    #[cfg(feature = "cipher")]
    let cipher = match create_bundle_cipher(
        args.cipher.as_deref(),
        args.iterations,
        args.key_file.as_deref(),
        args.password_file.as_deref(),
        &kind,
    ) {
        Ok(cipher) => cipher,
        Err(e) => {
            eprintln!("snowscsi: bundle-create: {e}");
            return ExitCode::FAILURE;
        }
    };
    #[cfg(not(feature = "cipher"))]
    let cipher = None;
    let meta = BundleMeta {
        kind,
        cipher,
        has_crc: false,
    };
    #[cfg(feature = "cipher")]
    let security = cipher_summary(meta.cipher.as_ref());
    #[cfg(not(feature = "cipher"))]
    let security = "plaintext";
    if let Err(e) = std::fs::create_dir_all(&args.dir) {
        eprintln!(
            "snowscsi: bundle-create: failed to create directory {}: {e}",
            args.dir
        );
        return ExitCode::FAILURE;
    }
    // The CLI writes the manifest atomically itself: `create_with_meta` writes
    // through the filesystem seam, which has no rename, and a torn keyslot
    // manifest is the only copy of the VMK.
    let manifest = match meta.encode() {
        Ok(manifest) => manifest,
        Err(e) => {
            if !existed {
                let _ = std::fs::remove_dir_all(&args.dir);
            }
            eprintln!("snowscsi: bundle-create: cannot encode the manifest: {e}");
            return ExitCode::FAILURE;
        }
    };
    if let Err(e) = write_manifest_atomic(&dir.join(MANIFEST_NAME), &manifest) {
        let _ = std::fs::remove_file(dir.join(MANIFEST_NAME));
        if !existed {
            let _ = std::fs::remove_dir_all(&args.dir);
        }
        eprintln!(
            "snowscsi: bundle-create: failed to write {}/SNOWBUNDLE: {e}",
            args.dir
        );
        return ExitCode::FAILURE;
    }
    match FlatBundle::open(StdFsBackend::new(&args.dir), None, None, None) {
        Ok(_) => {
            println!(
                "snowscsi: created flat bundle {} ({} bytes, {} byte chunks, {} byte sectors, \
                 {security})",
                args.dir, size, chunk, args.sector
            );
            ExitCode::SUCCESS
        }
        Err(e) => {
            let _ = std::fs::remove_file(dir.join(MANIFEST_NAME));
            if !existed {
                let _ = std::fs::remove_dir_all(&args.dir);
            }
            eprintln!("snowscsi: bundle-create: {}: {e}", args.dir);
            ExitCode::FAILURE
        }
    }
}

/// The first canonical chunk file (`NNNNNN.img`) in `dir`, if any.
#[cfg(feature = "bundle")]
fn first_chunk_file(dir: &Path) -> Option<String> {
    for entry in std::fs::read_dir(dir).ok()?.flatten() {
        let name = entry.file_name();
        let name = name.to_string_lossy();
        if let Some(stem) = name.strip_suffix(".img") {
            if stem.len() == 6 && stem.bytes().all(|b| b.is_ascii_digit()) {
                return Some(name.into_owned());
            }
        }
    }
    None
}

/// The first canonical track file (`track_<n>.bin`) in `dir`, if any.
#[cfg(feature = "cdr-bundle")]
fn first_track_file(dir: &Path) -> Option<String> {
    for entry in std::fs::read_dir(dir).ok()?.flatten() {
        let name = entry.file_name();
        let name = name.to_string_lossy();
        if let Some(digits) = name
            .strip_prefix("track_")
            .and_then(|rest| rest.strip_suffix(".bin"))
        {
            if !digits.is_empty() && digits.parse::<u16>().is_ok() {
                return Some(name.into_owned());
            }
        }
    }
    None
}

#[cfg(not(feature = "bundle"))]
fn create_flat_bundle(_args: CreateFlatArgs) -> ExitCode {
    eprintln!("snowscsi: bundle-create flat requires the `bundle` feature");
    ExitCode::FAILURE
}

/// `snowscsi bundle-create cdr` — write a `kind = cdr` manifest and the
/// initial TOC slot so `serve` can open the directory.
#[cfg(feature = "cdr-bundle")]
fn create_cdr_bundle(args: CreateCdrArgs) -> ExitCode {
    let (capacity, kind) = match args.medium.as_deref() {
        None => (CdrCapacity::Cdr80, DiscKind::Cdr),
        Some(raw) => match parse_medium(raw) {
            Ok(preset) => preset,
            Err(e) => {
                eprintln!("snowscsi: bundle-create: {e}");
                return ExitCode::FAILURE;
            }
        },
    };
    let slot = match args.slot.as_deref() {
        None => TOC_SLOT_DEFAULT,
        Some(raw) => match parse_slot(raw) {
            Ok(slot) => slot,
            Err(e) => {
                eprintln!("snowscsi: bundle-create: {e}");
                return ExitCode::FAILURE;
            }
        },
    };
    let dir = Path::new(&args.dir);
    let existed = dir.exists();
    if existed {
        for existing in [MANIFEST_NAME, "BUNDLE", "toc.0", "toc.1"] {
            if dir.join(existing).exists() {
                eprintln!(
                    "snowscsi: bundle-create: {} already contains {existing}; refusing to \
                     overwrite it (rekey changes credentials in place; delete the directory to \
                     rebuild the disc)",
                    args.dir
                );
                return ExitCode::FAILURE;
            }
        }
        // Leftover track data cannot be reconciled without a TOC, so refuse
        // before writing a manifest that would make it look authoritative.
        if let Some(name) = first_track_file(dir) {
            eprintln!(
                "snowscsi: bundle-create: {} already contains track data ({name}); a \
                 recordable-CD bundle requires an empty directory (move the track files away \
                 or use a new directory)",
                args.dir
            );
            return ExitCode::FAILURE;
        }
    }
    let bundle_kind = BundleKind::Cdr;
    #[cfg(feature = "cipher")]
    let cipher = match create_bundle_cipher(
        args.cipher.as_deref(),
        args.iterations,
        args.key_file.as_deref(),
        args.password_file.as_deref(),
        &bundle_kind,
    ) {
        Ok(cipher) => cipher,
        Err(e) => {
            eprintln!("snowscsi: bundle-create: {e}");
            return ExitCode::FAILURE;
        }
    };
    #[cfg(not(feature = "cipher"))]
    let cipher = None;
    // A CD-RW can be blanked and track 1 would reuse resource 17 at offset 0
    // under the same (key, nonce), repeating a keystream. v1 therefore requires
    // write-once CD-R for every encrypted recordable bundle.
    #[cfg(feature = "cipher")]
    if cipher.is_some() && kind == DiscKind::Cdrw {
        eprintln!(
            "snowscsi: bundle-create: encrypted recordable bundles require write-once CD-R \
             (--medium cdrw* is not supported with --cipher)"
        );
        return ExitCode::FAILURE;
    }
    if let Err(e) = std::fs::create_dir_all(&args.dir) {
        eprintln!(
            "snowscsi: bundle-create: failed to create directory {}: {e}",
            args.dir
        );
        return ExitCode::FAILURE;
    }

    let meta = BundleMeta {
        kind: bundle_kind,
        cipher,
        has_crc: false,
    };
    #[cfg(feature = "cipher")]
    let security = cipher_summary(meta.cipher.as_ref());
    #[cfg(not(feature = "cipher"))]
    let security = "plaintext";
    let manifest = match meta.encode() {
        Ok(manifest) => manifest,
        Err(e) => {
            eprintln!("snowscsi: bundle-create: cannot encode the manifest: {e}");
            return ExitCode::FAILURE;
        }
    };
    if let Err(e) = write_manifest_atomic(&dir.join(MANIFEST_NAME), &manifest) {
        let _ = std::fs::remove_file(dir.join(MANIFEST_NAME));
        if !existed {
            let _ = std::fs::remove_dir_all(&args.dir);
        }
        eprintln!(
            "snowscsi: bundle-create: failed to write {}/SNOWBUNDLE: {e}",
            args.dir
        );
        return ExitCode::FAILURE;
    }

    let mut medium = match CdrBundleMedium::with_disc(capacity.sectors(), kind, slot) {
        Ok(medium) => medium,
        Err(e) => {
            let _ = std::fs::remove_file(dir.join(MANIFEST_NAME));
            if !existed {
                let _ = std::fs::remove_dir_all(&args.dir);
            }
            eprintln!("snowscsi: bundle-create: cannot build the blank disc: {e}");
            return ExitCode::FAILURE;
        }
    };
    let mut image = vec![0u8; medium.slot_size() as usize];
    let slot_index = match medium.toc_image(&mut image) {
        Ok(slot) => slot,
        Err(e) => {
            let _ = std::fs::remove_file(dir.join(MANIFEST_NAME));
            if !existed {
                let _ = std::fs::remove_dir_all(&args.dir);
            }
            eprintln!("snowscsi: bundle-create: cannot render the initial TOC: {e}");
            return ExitCode::FAILURE;
        }
    };
    let name = toc_file(slot_index);
    if let Err(e) = write_manifest_atomic(&dir.join(name), &image) {
        // Do not leave a manifest that points at a missing TOC: a retry with
        // the same directory must start clean.
        let _ = std::fs::remove_file(dir.join(MANIFEST_NAME));
        if !existed {
            let _ = std::fs::remove_dir_all(&args.dir);
        }
        eprintln!(
            "snowscsi: bundle-create: writing {}/{name} failed: {e}; removed the manifest so \
             the directory can be retried",
            args.dir
        );
        return ExitCode::FAILURE;
    }
    println!(
        "snowscsi: created recordable-CD bundle {} ({:?}, {slot} byte TOC slot, {name}, \
         {security})",
        args.dir, kind
    );
    ExitCode::SUCCESS
}

#[cfg(not(feature = "cdr-bundle"))]
fn create_cdr_bundle(_args: CreateCdrArgs) -> ExitCode {
    eprintln!("snowscsi: bundle-create cdr requires the `cdr-bundle` feature");
    ExitCode::FAILURE
}

/// Write one file through a random `0600` temp in the same directory, fsync
/// it, rename it into place and fsync the parent.
///
/// Used for both the manifest and the initial CD-R TOC. The temp is
/// mispredicted (`create_new`), so two concurrent writers can never share it,
/// and a failure removes it so a retry starts clean.
#[cfg(feature = "bundle")]
fn write_manifest_atomic(path: &Path, bytes: &[u8]) -> std::io::Result<()> {
    use std::io::Write as _;
    use std::sync::atomic::{AtomicU64, Ordering};

    static COUNTER: AtomicU64 = AtomicU64::new(0);

    fn suffix() -> u64 {
        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_nanos() as u64)
            .unwrap_or(0);
        let count = COUNTER.fetch_add(1, Ordering::Relaxed);
        let mut value =
            nanos ^ ((std::process::id() as u64) << 32) ^ count.wrapping_mul(0x9E37_79B9_7F4A_7C15);
        value ^= value >> 33;
        value = value.wrapping_mul(0xFF51_AFD7_ED55_8CCD);
        value ^= value >> 29;
        value
    }

    let parent = match path.parent() {
        Some(parent) if !parent.as_os_str().is_empty() => parent,
        _ => Path::new("."),
    };
    let name = path
        .file_name()
        .ok_or_else(|| std::io::Error::new(std::io::ErrorKind::InvalidInput, "missing file name"))?
        .to_string_lossy();
    let mut attempt = 0u32;
    loop {
        let tmp = parent.join(format!(".{name}.tmp.{:016x}", suffix()));
        let mut options = std::fs::OpenOptions::new();
        options.write(true).create_new(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt as _;
            options.mode(0o600);
        }
        match options.open(&tmp) {
            Ok(mut file) => {
                let write = (|| {
                    file.write_all(bytes)?;
                    file.sync_all()?;
                    drop(file);
                    std::fs::rename(&tmp, path)?;
                    // Checked: a manifest that is not durable is not a
                    // successful manifest write.
                    std::fs::File::open(parent)?.sync_all()?;
                    Ok(())
                })();
                if write.is_err() {
                    let _ = std::fs::remove_file(&tmp);
                }
                return write;
            }
            Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists && attempt < 64 => {
                attempt += 1;
            }
            Err(e) => return Err(e),
        }
    }
}

#[cfg(feature = "cdr-bundle")]
fn parse_medium(raw: &str) -> Result<(CdrCapacity, DiscKind), String> {
    let invalid = || {
        format!(
            "invalid --medium '{raw}' (cdr74, cdr80, cdr90, cdr99, cdrw74, cdrw80, cdrw90, cdrw99)"
        )
    };
    let (prefix, kind) = if let Some(rest) = raw.strip_prefix("cdrw") {
        (rest, DiscKind::Cdrw)
    } else if let Some(rest) = raw.strip_prefix("cdr") {
        (rest, DiscKind::Cdr)
    } else {
        return Err(invalid());
    };
    let capacity = match prefix {
        "74" => CdrCapacity::Cdr74,
        "80" => CdrCapacity::Cdr80,
        "90" => CdrCapacity::Cdr90,
        "99" => CdrCapacity::Cdr99,
        _ => return Err(invalid()),
    };
    Ok((capacity, kind))
}

#[cfg(feature = "cdr-bundle")]
fn parse_slot(raw: &str) -> Result<u32, String> {
    let bytes = spec::parse_size(raw).ok_or_else(|| format!("invalid --slot '{raw}'"))?;
    let bytes = u32::try_from(bytes).map_err(|_| format!("--slot {bytes} is too large"))?;
    if !(TOC_SLOT_MIN..=TOC_SLOT_MAX).contains(&bytes) {
        return Err(format!(
            "--slot {bytes} is outside {TOC_SLOT_MIN}..={TOC_SLOT_MAX}"
        ));
    }
    Ok(bytes)
}

/// `snowscsi crypt` — encrypt or decrypt one image file and its sidecar.
#[cfg(feature = "cipher")]
fn run_crypt(args: CryptArgs) -> ExitCode {
    init_logging(0);
    match crypt_run(args) {
        Ok(line) => {
            println!("snowscsi: {line}");
            ExitCode::SUCCESS
        }
        Err(msg) => {
            eprintln!("snowscsi: crypt: {msg}");
            ExitCode::FAILURE
        }
    }
}

/// Resolve the manifest a `rekey` path names.
#[cfg(feature = "cipher")]
fn rekey_manifest_path(path: &str) -> Result<String, String> {
    if Path::new(path).is_dir() {
        return Ok(format!("{}/SNOWBUNDLE", path.trim_end_matches('/')));
    }
    if path.ends_with(".SNOWBUNDLE")
        || Path::new(path).file_name().and_then(|name| name.to_str()) == Some("SNOWBUNDLE")
    {
        if !Path::new(path).is_file() {
            return Err(format!("manifest '{path}' not found"));
        }
        return Ok(path.to_string());
    }
    let sidecar = format!("{path}{SIDECAR_SUFFIX}");
    if !Path::new(&sidecar).is_file() {
        return Err(format!(
            "manifest '{sidecar}' not found (not an encrypted image or bundle)"
        ));
    }
    Ok(sidecar)
}

/// Read the credential for one side of a rekey, honoring the keyslot's KDF.
#[cfg(feature = "cipher")]
fn rekey_read_credential(
    kdf: KdfKind,
    password_file: Option<&str>,
    key_file: Option<&str>,
    confirm: bool,
    which: &str,
) -> Result<crate::cipher::Credential, String> {
    match kdf {
        KdfKind::None => {
            if password_file.is_some() {
                return Err(format!(
                    "{which} keyslot uses kdf = none; pass --{which}-key-file, not a password"
                ));
            }
            let key_file = key_file.ok_or_else(|| {
                format!("{which} keyslot uses kdf = none; pass --{which}-key-file")
            })?;
            crate::cipher::read_credential(None, Some(key_file), confirm)
        }
        KdfKind::Pbkdf2HmacSha256 => {
            if key_file.is_some() {
                return Err(format!(
                    "{which} keyslot uses PBKDF2; pass --{which}-password-file or omit it \
                     to prompt"
                ));
            }
            crate::cipher::read_credential(password_file, None, confirm)
        }
    }
}

/// `snowscsi rekey`: re-wrap the VMK; data bytes and identity stay unchanged.
#[cfg(feature = "cipher")]
fn run_rekey(args: RekeyArgs) -> ExitCode {
    init_logging(0);
    match rekey_run(args) {
        Ok(line) => {
            println!("snowscsi: {line}");
            ExitCode::SUCCESS
        }
        Err(msg) => {
            eprintln!("snowscsi: rekey: {msg}");
            ExitCode::FAILURE
        }
    }
}

#[cfg(feature = "cipher")]
fn rekey_run(args: RekeyArgs) -> Result<String, String> {
    let manifest = rekey_manifest_path(&args.path)?;
    let metadata = std::fs::symlink_metadata(&manifest)
        .map_err(|e| format!("cannot stat manifest '{manifest}': {e}"))?;
    if metadata.file_type().is_symlink() {
        return Err(format!(
            "manifest '{manifest}' is a symlink; refusing to rewrite it"
        ));
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt as _;
        if metadata.nlink() > 1 {
            return Err(format!(
                "manifest '{manifest}' has multiple hard links; refusing to rewrite it"
            ));
        }
    }
    let bytes = read_capped(&manifest, MAX_MANIFEST + 1)
        .map_err(|e| format!("cannot read manifest '{manifest}': {e}"))?;
    let parsed = BundleMeta::parse(&bytes).map_err(|e| format!("invalid manifest: {e}"))?;
    let Some(old_cipher) = parsed.cipher else {
        return Err(format!(
            "NotEncrypted: manifest '{manifest}' has no keyslot (cipher = none); \
             encryption is a data operation"
        ));
    };
    if !args.path.ends_with(".SNOWBUNDLE")
        && Path::new(&args.path)
            .file_name()
            .and_then(|name| name.to_str())
            != Some("SNOWBUNDLE")
    {
        if Path::new(&args.path).is_dir() && matches!(parsed.kind, BundleKind::Image { .. }) {
            return Err(format!(
                "manifest '{manifest}' describes a single-file image, but '{}' is a directory",
                args.path
            ));
        }
        if !Path::new(&args.path).is_dir() && !matches!(parsed.kind, BundleKind::Image { .. }) {
            return Err(format!(
                "manifest '{manifest}' describes a directory bundle, not an image"
            ));
        }
    }

    let mut old_credential = rekey_read_credential(
        old_cipher.slot.kdf,
        args.current_password_file.as_deref(),
        args.current_key_file.as_deref(),
        false,
        "current",
    )?;

    let (new_kdf, new_iterations, mut new_credential) =
        if let Some(key_file) = args.new_key_file.as_deref() {
            if args.new_password_file.is_some() {
                return Err(
                    "--new-password-file and --new-key-file are mutually exclusive".to_string(),
                );
            }
            if args.new_iterations.is_some() {
                return Err("--new-iterations is not valid with --new-key-file".to_string());
            }
            (
                KdfKind::None,
                None,
                crate::cipher::read_credential(None, Some(key_file), false)?,
            )
        } else {
            let iterations = args.new_iterations.unwrap_or(600_000);
            if !(1_000..=2_000_000).contains(&iterations) {
                return Err(format!(
                    "invalid PBKDF2 iteration count {iterations} (1000..=2000000)"
                ));
            }
            (
                KdfKind::Pbkdf2HmacSha256,
                Some(iterations),
                crate::cipher::read_credential(args.new_password_file.as_deref(), None, true)?,
            )
        };

    let (new_cipher, vmk) = crate::cipher::rewrap_keyslot(
        &parsed.kind,
        &old_cipher,
        &old_credential,
        new_kdf,
        new_iterations,
        &new_credential,
    )?;
    let new_manifest = BundleMeta {
        kind: parsed.kind,
        cipher: Some(new_cipher),
        has_crc: true,
    };
    let encoded = new_manifest
        .encode()
        .map_err(|e| format!("cannot encode the new manifest: {e}"))?;

    // Re-parse and unlock with the new credential before publishing: a bug or
    // a mistyped new password must never replace the old keyslot.
    let reparsed =
        BundleMeta::parse(&encoded).map_err(|e| format!("cannot parse the new manifest: {e}"))?;
    let Some(reparsed_cipher) = reparsed.cipher else {
        return Err("internal: the new manifest lost its keyslot".to_string());
    };
    if reparsed.kind != parsed.kind
        || reparsed_cipher.cipher != old_cipher.cipher
        || reparsed_cipher.nonce != old_cipher.nonce
        || reparsed_cipher.key_id != old_cipher.key_id
    {
        return Err(
            "internal: the new keyslot changed the data cipher/nonce/key id or geometry"
                .to_string(),
        );
    }
    let checked_vmk = crate::cipher::unlock(&reparsed_cipher, &reparsed.kind, &new_credential)?;
    if checked_vmk.as_bytes() != vmk.as_bytes() {
        return Err("internal: the new keyslot does not unwrap to the same VMK".to_string());
    }

    let lock = crypt_lock(&manifest)?;
    let permissions = std::fs::metadata(&manifest).ok().map(|m| m.permissions());
    crypt_write_atomic(&manifest, &encoded)?;
    if let Some(permissions) = permissions {
        let _ = std::fs::set_permissions(&manifest, permissions);
    }
    drop(lock);

    old_credential.wipe();
    new_credential.wipe();
    let kind = match parsed.kind {
        BundleKind::Image { .. } => "image",
        BundleKind::Flat { .. } => "flat bundle",
        BundleKind::Cdr => "recordable bundle",
    };
    Ok(format!(
        "rekeyed {kind} '{manifest}' (keyslot only; data unchanged)"
    ))
}

/// Stream chunk size for `crypt` (one MiB; no whole-file allocation).
#[cfg(feature = "cipher")]
const CRYPT_CHUNK: usize = 1024 * 1024;

/// `<path>.SNOWBUNDLE` (literal suffix, never `with_extension`).
#[cfg(feature = "cipher")]
fn crypt_sidecar(path: &str) -> String {
    format!("{path}{SIDECAR_SUFFIX}")
}

/// `crypt`'s temporary path (`<path>.tmp.<random>`).
///
/// The suffix is random (not the PID) and the file is created with `create_new`
/// so two concurrent runs can never share a temp. Unix temps are mode `0600`.
#[cfg(feature = "cipher")]
fn crypt_tmp(path: &str) -> Result<String, String> {
    use std::fmt::Write as _;

    let mut suffix = [0u8; 8];
    getrandom::fill(&mut suffix)
        .map_err(|e| format!("cannot read random bytes for a temporary name: {e}"))?;
    let mut hex = String::with_capacity(16);
    for byte in suffix {
        let _ = write!(hex, "{byte:02x}");
    }
    Ok(format!("{path}.tmp.{hex}"))
}

/// Create a fresh `0600` temp next to `path` (`create_new`, so it is ours).
#[cfg(feature = "cipher")]
fn crypt_create_temp(path: &str) -> Result<(File, String), String> {
    let tmp = crypt_tmp(path)?;
    let mut options = std::fs::OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt as _;
        options.mode(0o600);
    }
    let file = options
        .open(&tmp)
        .map_err(|e| format!("cannot create temporary file '{tmp}': {e}"))?;
    Ok((file, tmp))
}

/// Identity of a crypt path, resolved before any payload I/O.
#[cfg(feature = "cipher")]
struct CryptPathIdentity {
    /// Canonical target when it exists; otherwise the canonical parent plus the
    /// file name (so `./`, `.`/`..` and symlinked directories still compare).
    resolved: PathBuf,
    /// `(dev, ino)` when the path exists, so hard links compare equal even
    /// though their canonical paths differ.
    #[cfg(unix)]
    file_id: Option<(u64, u64)>,
}

#[cfg(feature = "cipher")]
fn crypt_path_identity(path: &str) -> Result<CryptPathIdentity, String> {
    let raw = Path::new(path);
    let resolved = match std::fs::canonicalize(raw) {
        Ok(resolved) => resolved,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            let parent = raw
                .parent()
                .filter(|parent| !parent.as_os_str().is_empty())
                .unwrap_or_else(|| Path::new("."));
            let parent = std::fs::canonicalize(parent)
                .map_err(|e| format!("cannot resolve the directory of '{path}': {e}"))?;
            let name = raw
                .file_name()
                .ok_or_else(|| format!("'{path}' has no file name"))?;
            parent.join(name)
        }
        Err(e) => return Err(format!("cannot resolve '{path}': {e}")),
    };
    #[cfg(unix)]
    let file_id = std::fs::metadata(raw).ok().map(|meta| {
        use std::os::unix::fs::MetadataExt as _;
        (meta.dev(), meta.ino())
    });
    Ok(CryptPathIdentity {
        resolved,
        #[cfg(unix)]
        file_id,
    })
}

#[cfg(feature = "cipher")]
fn crypt_same_file(a: &CryptPathIdentity, b: &CryptPathIdentity) -> bool {
    if a.resolved == b.resolved {
        return true;
    }
    #[cfg(unix)]
    if let (Some(a), Some(b)) = (a.file_id, b.file_id) {
        if a == b {
            return true;
        }
    }
    false
}

/// Reject any pair of crypt paths that resolves to the same file.
///
/// This runs before the lock, the cipher or any payload I/O, and is what stops
/// `out == in` through `./`, `.`/`..`, a symlink or a hard link, as well as an
/// output that is exactly `<in>.SNOWBUNDLE`.
#[cfg(feature = "cipher")]
fn crypt_reject_aliases(entries: &[(&str, &str)]) -> Result<(), String> {
    let mut ids = Vec::with_capacity(entries.len());
    for &(label, path) in entries {
        ids.push((label, path, crypt_path_identity(path)?));
    }
    for i in 0..ids.len() {
        for j in (i + 1)..ids.len() {
            let (label_a, path_a, id_a) = &ids[i];
            let (label_b, path_b, id_b) = &ids[j];
            if crypt_same_file(id_a, id_b) {
                return Err(format!(
                    "{label_a} '{path_a}' and {label_b} '{path_b}' refer to the same file; \
                     they must differ"
                ));
            }
        }
    }
    Ok(())
}

/// Exclusive, existence-based lock for one crypt target.
///
/// The lock is `<canonical target>.lock`; it is removed by [`Drop`] on every
/// ordinary exit path. A SIGKILL/crash can leave it behind, in which case the
/// operator must remove the file once no crypt process is running.
#[cfg(feature = "cipher")]
struct CryptLock {
    path: PathBuf,
}

#[cfg(feature = "cipher")]
impl Drop for CryptLock {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.path);
    }
}

#[cfg(feature = "cipher")]
fn crypt_lock(target: &str) -> Result<CryptLock, String> {
    let identity = crypt_path_identity(target)?;
    let mut lock_name = identity.resolved.into_os_string();
    lock_name.push(".lock");
    let path = PathBuf::from(lock_name);

    let mut options = std::fs::OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt as _;
        options.mode(0o600);
    }
    match options.open(&path) {
        Ok(mut file) => {
            let _ = writeln!(file, "{}", std::process::id());
            Ok(CryptLock { path })
        }
        Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => Err(format!(
            "another crypt operation is already using '{target}' (lock file '{}' exists); \
             if no crypt process is running, remove that stale lock file and retry",
            path.display()
        )),
        Err(e) => Err(format!(
            "cannot create the lock file '{}': {e}",
            path.display()
        )),
    }
}

/// Refuse an in-place target that is a symlink or has multiple hard links.
///
/// A symlink would encrypt the target while replacing the link name; a hard
/// link would silently change the other name's contents too. Both are safe
/// out of place (the caller decides what to replace).
#[cfg(feature = "cipher")]
fn crypt_in_place_input(path: &str) -> Result<(), String> {
    let meta = std::fs::symlink_metadata(path).map_err(|e| format!("cannot stat '{path}': {e}"))?;
    if meta.file_type().is_symlink() {
        return Err(format!(
            "refusing --in-place on '{path}': it is a symbolic link (encrypt out of place instead)"
        ));
    }
    if !meta.is_file() {
        return Err(format!("'{path}' is not a regular file"));
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt as _;
        if meta.nlink() > 1 {
            return Err(format!(
                "refusing --in-place on '{path}': it has {} hard links (encrypt out of place instead)",
                meta.nlink()
            ));
        }
    }
    Ok(())
}

/// Reject everything that is not a regular file and return its length.
///
/// `symlink_metadata` does **not** follow symlinks: a symlink to a regular
/// file is refused (out of place and in place alike), as is a directory or a
/// block device.
#[cfg(feature = "cipher")]
fn crypt_input_len(path: &str) -> Result<u64, String> {
    let meta = std::fs::symlink_metadata(path).map_err(|e| format!("cannot stat '{path}': {e}"))?;
    if meta.file_type().is_symlink() {
        return Err(format!(
            "'{path}' is a symbolic link; crypt accepts regular files only"
        ));
    }
    if !meta.is_file() {
        return Err(format!("'{path}' is not a regular file"));
    }
    Ok(meta.len())
}

/// Flush the containing directory after a rename (best effort).
#[cfg(feature = "cipher")]
fn crypt_sync_parent(path: &str) {
    let Some(parent) = Path::new(path).parent() else {
        return;
    };
    let parent = if parent.as_os_str().is_empty() {
        Path::new(".")
    } else {
        parent
    };
    if let Ok(dir) = File::open(parent) {
        let _ = dir.sync_all();
    }
}

/// Write `bytes` to `path` through a random `0600` temp, fsync it, then rename.
#[cfg(feature = "cipher")]
fn crypt_write_atomic(path: &str, bytes: &[u8]) -> Result<(), String> {
    use std::io::Write as _;

    let (mut file, tmp) = crypt_create_temp(path)?;
    let result = (|| {
        file.write_all(bytes)
            .map_err(|e| format!("cannot write '{tmp}': {e}"))?;
        file.sync_all()
            .map_err(|e| format!("cannot sync '{tmp}': {e}"))?;
        drop(file);
        std::fs::rename(&tmp, path)
            .map_err(|e| format!("cannot rename '{tmp}' to '{path}': {e}"))?;
        Ok(())
    })();
    if result.is_err() {
        let _ = std::fs::remove_file(&tmp);
    } else {
        crypt_sync_parent(path);
    }
    result
}

/// Write the sidecar after the image, removing the image if the sidecar fails.
///
/// The sidecar carries the only keyslot that can unwrap the image's VMK, so a
/// ciphertext image without one is useless: a failed sidecar write removes the
/// newly written image and reports the cleanup.
#[cfg(feature = "cipher")]
fn crypt_commit_sidecar(out: &str, sidecar: &str, manifest: &[u8]) -> Result<(), String> {
    if let Err(e) = crypt_write_atomic(sidecar, manifest) {
        let _ = std::fs::remove_file(out);
        return Err(format!("{e}; removed the newly written '{out}'"));
    }
    Ok(())
}

/// Stream `input` through `cipher` into `output`, deleting `output` on failure.
///
/// The cipher is length-preserving and symmetric: encryption and decryption
/// are the same call. One [`CRYPT_CHUNK`] buffer is reused for the whole file.
/// `output` must be a fresh temp created by the caller; this function creates
/// it with `create_new` and mode `0600` on Unix.
#[cfg(feature = "cipher")]
fn crypt_file(
    input: &str,
    output: &str,
    mut cipher: crate::cipher::CliCipher,
) -> Result<u64, String> {
    use snowscsi::common::cipher::StreamCipher as _;
    use std::io::{Read as _, Write as _};

    let result = (|| {
        let mut src =
            File::open(input).map_err(|e| format!("cannot open '{input}' for reading: {e}"))?;
        let mut options = std::fs::OpenOptions::new();
        options.write(true).create_new(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt as _;
            options.mode(0o600);
        }
        let mut dst = options
            .open(output)
            .map_err(|e| format!("cannot create '{output}': {e}"))?;
        let mut buf = vec![0u8; CRYPT_CHUNK];
        let mut offset = 0u64;
        loop {
            let n = src
                .read(&mut buf)
                .map_err(|e| format!("cannot read '{input}': {e}"))?;
            if n == 0 {
                break;
            }
            cipher
                .xor(offset, &mut buf[..n])
                .map_err(|e| format!("cipher failed at offset {offset}: {e}"))?;
            dst.write_all(&buf[..n])
                .map_err(|e| format!("cannot write '{output}': {e}"))?;
            offset += n as u64;
        }
        dst.flush()
            .map_err(|e| format!("cannot flush '{output}': {e}"))?;
        dst.sync_all()
            .map_err(|e| format!("cannot sync '{output}': {e}"))?;
        Ok(offset)
    })();
    if result.is_err() {
        let _ = std::fs::remove_file(output);
    }
    result
}

/// Log that `xor` is obfuscation, never encryption.
#[cfg(feature = "cipher")]
fn crypt_warn_xor(alg: CipherAlg) {
    if alg == CipherAlg::Xor {
        log::warn!("crypt: xor is obfuscation, not encryption");
    }
}

/// Success verb for `crypt`; `xor` is never called encryption.
#[cfg(feature = "cipher")]
fn crypt_verb(alg: CipherAlg) -> &'static str {
    if alg == CipherAlg::Xor {
        "obfuscated with xor"
    } else {
        "encrypted"
    }
}

/// Read the credential for an existing manifest and unlock its VMK.
///
/// `kdf = pbkdf2` needs a password (file or prompt); `kdf = none` needs an
/// explicit key file and never prompts. A wrong credential fails here, before
/// any output is created.
#[cfg(feature = "cipher")]
fn crypt_unlock_cipher(
    meta: &CipherMeta,
    kind: &BundleKind,
    args: &CryptArgs,
) -> Result<crate::cipher::CliCipher, String> {
    let (password_file, key_file) = match meta.slot.kdf {
        KdfKind::None => {
            if args.password_file.is_some() {
                return Err(
                    "the manifest uses kdf = none; pass --key-file <path> instead of \
                     --password-file"
                        .to_string(),
                );
            }
            if args.key_file.is_none() {
                return Err(
                    "the manifest uses kdf = none; pass --key-file <path> (a password is \
                     never prompted for this manifest)"
                        .to_string(),
                );
            }
            (None, args.key_file.as_deref())
        }
        KdfKind::Pbkdf2HmacSha256 => {
            if args.key_file.is_some() {
                return Err(
                    "the manifest uses PBKDF2; pass --password-file <path> (or omit both to \
                     prompt), not --key-file"
                        .to_string(),
                );
            }
            (args.password_file.as_deref(), None)
        }
    };
    let mut credential = crate::cipher::read_credential(password_file, key_file, false)?;
    let unlocked = crate::cipher::unlock(meta, kind, &credential);
    credential.wipe();
    let vmk = unlocked?;
    crate::cipher::CliCipher::from_meta(meta, &vmk)
}

/// Build the keyslot and stream cipher for a new encrypted image.
///
/// `--key-file` selects `kdf = none`; otherwise the password (file or
/// two-line prompt) selects PBKDF2. Fresh VMK, data nonce, salt and wrap nonce
/// are generated here.
#[cfg(feature = "cipher")]
fn crypt_encrypt_cipher(
    args: &CryptArgs,
    alg: CipherAlg,
    kind: &BundleKind,
) -> Result<(CipherMeta, crate::cipher::CliCipher), String> {
    let kdf = if args.key_file.is_some() {
        KdfKind::None
    } else {
        KdfKind::Pbkdf2HmacSha256
    };
    if kdf == KdfKind::None && args.iterations.is_some() {
        return Err("--key-file and --iterations are mutually exclusive".to_string());
    }
    let iterations = match kdf {
        KdfKind::None => None,
        KdfKind::Pbkdf2HmacSha256 => Some(args.iterations.unwrap_or(600_000)),
    };
    let mut credential = crate::cipher::read_credential(
        args.password_file.as_deref(),
        args.key_file.as_deref(),
        true,
    )?;
    let nonce = crate::cipher::random_nonce()?;
    let created = (|| {
        let (meta, vmk) =
            crate::cipher::new_keyslot(alg, nonce, kdf, iterations, &credential, kind)?;
        let cipher = crate::cipher::CliCipher::from_meta(&meta, &vmk)?;
        Ok((meta, cipher))
    })();
    credential.wipe();
    created
}

/// Build the manifest block for a new encrypted image.
#[cfg(feature = "cipher")]
fn crypt_manifest(size: u64, meta: CipherMeta) -> Result<Vec<u8>, String> {
    let bundle = BundleMeta {
        kind: BundleKind::Image { size },
        cipher: Some(meta),
        has_crc: true,
    };
    bundle
        .encode()
        .map(|bytes| bytes.to_vec())
        .map_err(|e| format!("cannot encode the manifest: {e}"))
}

/// Validate and execute one `snowscsi crypt` invocation.
#[cfg(feature = "cipher")]
fn crypt_run(args: CryptArgs) -> Result<String, String> {
    if args.in_place && args.force {
        return Err("--force cannot be used with --in-place".to_string());
    }
    if args.decrypt {
        return crypt_decrypt(&args);
    }

    let Some(name) = args.cipher.as_deref() else {
        return Err("--cipher is required for encryption (use --decrypt to decrypt)".to_string());
    };
    if args.key_file.is_some() && args.password_file.is_some() {
        return Err("--key-file and --password-file are mutually exclusive".to_string());
    }
    if args.key_file.is_some() && args.iterations.is_some() {
        return Err("--key-file and --iterations are mutually exclusive".to_string());
    }

    if args.in_place {
        if args.output.is_some() {
            return Err("--in-place takes no output path".to_string());
        }
        crypt_in_place_input(&args.input)?;
        let sidecar = crypt_sidecar(&args.input);
        // An in-place target and its sidecar must be two different files.
        crypt_reject_aliases(&[("input", &args.input), ("input sidecar", &sidecar)])?;
        let _lock = crypt_lock(&args.input)?;
        let input_len = crypt_input_len(&args.input)?;
        if Path::new(&sidecar).exists() {
            return Err(format!(
                "{sidecar} already exists; refusing to replace a sidecar that may describe a \
                 different nonce (remove it first or use an out-of-place run)"
            ));
        }

        let alg = crate::cipher::parse_alg(name)?;
        crypt_warn_xor(alg);
        let kind = BundleKind::Image { size: input_len };
        let (meta, cipher) = crypt_encrypt_cipher(&args, alg, &kind)?;
        let alg_name = crate::cipher::cipher_meta_name(&meta);
        let manifest = crypt_manifest(input_len, meta)?;
        // The sidecar goes first: a crash before the image rename leaves the
        // original plaintext intact with a stale sidecar, which is recoverable
        // by removing that sidecar.
        crypt_write_atomic(&sidecar, &manifest)?;
        let tmp = crypt_tmp(&args.input)?;
        let encrypted = match crypt_file(&args.input, &tmp, cipher) {
            Ok(len) => len,
            Err(e) => {
                let _ = std::fs::remove_file(&sidecar);
                return Err(format!("{e}; the original file is untouched"));
            }
        };
        if encrypted != input_len {
            let _ = std::fs::remove_file(&tmp);
            let _ = std::fs::remove_file(&sidecar);
            return Err(format!(
                "input '{}' changed size while reading (expected {input_len} bytes, processed \
                 {encrypted}); the original file is untouched",
                args.input
            ));
        }
        // Preserve permissions across the replacement; ownership, xattrs and
        // ACLs are deliberately not copied (the temp belongs to this user).
        let permissions = std::fs::metadata(&args.input)
            .map_err(|e| format!("cannot stat '{}': {e}", args.input))?
            .permissions();
        if let Err(e) = std::fs::set_permissions(&tmp, permissions) {
            let _ = std::fs::remove_file(&tmp);
            let _ = std::fs::remove_file(&sidecar);
            return Err(format!(
                "cannot preserve permissions on '{}': {e}; the original file is untouched",
                args.input
            ));
        }
        if let Err(e) = std::fs::rename(&tmp, &args.input) {
            let _ = std::fs::remove_file(&tmp);
            let _ = std::fs::remove_file(&sidecar);
            return Err(format!(
                "cannot replace '{}': {e}; the original file is untouched",
                args.input
            ));
        }
        crypt_sync_parent(&args.input);
        return Ok(format!(
            "{} {} in place ({encrypted} bytes, {alg_name})",
            crypt_verb(alg),
            args.input
        ));
    }

    let Some(out) = args.output.as_deref() else {
        return Err("an output path is required unless --in-place is given".to_string());
    };
    let in_sidecar = crypt_sidecar(&args.input);
    let out_sidecar = crypt_sidecar(out);
    // Check every path pair before the lock, the cipher or any payload I/O.
    crypt_reject_aliases(&[
        ("input", &args.input),
        ("input sidecar", &in_sidecar),
        ("output", out),
        ("output sidecar", &out_sidecar),
    ])?;
    let _lock = crypt_lock(out)?;
    let input_len = crypt_input_len(&args.input)?;
    if Path::new(&in_sidecar).exists() {
        return Err(format!(
            "input '{}' already has '{in_sidecar}' (it looks encrypted); refusing to encrypt it \
             again",
            args.input
        ));
    }

    let alg = crate::cipher::parse_alg(name)?;
    crypt_warn_xor(alg);
    // The output sidecar is the only copy of the new VMK; never overwrite a
    // different keyslot, not even with --force.
    if Path::new(&out_sidecar).exists() {
        return Err(format!(
            "'{out_sidecar}' already exists; refusing to overwrite a sidecar (it is the only \
             copy of that image's key material), even with --force"
        ));
    }
    if Path::new(out).exists() && !args.force {
        return Err(format!(
            "'{out}' already exists (use --force to replace it when it has no sidecar)"
        ));
    }

    let kind = BundleKind::Image { size: input_len };
    let (meta, cipher) = crypt_encrypt_cipher(&args, alg, &kind)?;
    let alg_name = crate::cipher::cipher_meta_name(&meta);
    // Encode the manifest before the image rename: an encode failure must not
    // leave an orphan ciphertext file.
    let manifest = crypt_manifest(input_len, meta)?;
    let tmp = crypt_tmp(out)?;
    let encrypted = crypt_file(&args.input, &tmp, cipher)?;
    if encrypted != input_len {
        let _ = std::fs::remove_file(&tmp);
        return Err(format!(
            "input '{}' changed size while reading (expected {input_len} bytes, processed \
             {encrypted}); refusing to commit",
            args.input
        ));
    }
    if let Err(e) = std::fs::rename(&tmp, out) {
        let _ = std::fs::remove_file(&tmp);
        return Err(format!("cannot rename '{tmp}' to '{out}': {e}"));
    }
    crypt_sync_parent(out);
    // The image goes first; a failed sidecar write removes it again, so an
    // orphan ciphertext is never left behind.
    crypt_commit_sidecar(out, &out_sidecar, &manifest)?;
    Ok(format!(
        "{} {} -> {} ({encrypted} bytes, {alg_name})",
        crypt_verb(alg),
        args.input,
        out
    ))
}

/// Decrypt `<in>` into `<out>` after validating its sidecar.
#[cfg(feature = "cipher")]
fn crypt_decrypt(args: &CryptArgs) -> Result<String, String> {
    if args.cipher.is_some() {
        return Err("--decrypt does not take --cipher (the sidecar decides)".to_string());
    }
    if args.iterations.is_some() {
        return Err("--decrypt does not take --iterations (the sidecar decides)".to_string());
    }
    if args.in_place {
        return Err("--in-place is encryption-only; decrypt to a separate output".to_string());
    }
    if args.key_file.is_some() && args.password_file.is_some() {
        return Err("--key-file and --password-file are mutually exclusive".to_string());
    }
    let Some(out) = args.output.as_deref() else {
        return Err("an output path is required with --decrypt".to_string());
    };
    let sidecar = crypt_sidecar(&args.input);
    let out_sidecar = crypt_sidecar(out);
    crypt_reject_aliases(&[
        ("input", &args.input),
        ("input sidecar", &sidecar),
        ("output", out),
        ("output sidecar", &out_sidecar),
    ])?;
    let _lock = crypt_lock(out)?;
    let input_len = crypt_input_len(&args.input)?;
    if !Path::new(&sidecar).is_file() {
        return Err(format!(
            "missing manifest '{sidecar}' (decryption needs the sidecar written by encryption)"
        ));
    }
    let bytes = read_capped(&sidecar, MAX_MANIFEST + 1)
        .map_err(|e| format!("cannot read manifest '{sidecar}': {e}"))?;
    let parsed =
        BundleMeta::parse(&bytes).map_err(|e| format!("invalid manifest '{sidecar}': {e}"))?;
    let size = match parsed.kind {
        BundleKind::Image { size } => size,
        _ => {
            return Err(format!(
                "manifest '{sidecar}' is not a single-file image manifest"
            ))
        }
    };
    if size != input_len {
        return Err(format!(
            "manifest '{sidecar}' declares image size {size}, but '{}' is {input_len} bytes",
            args.input
        ));
    }
    let Some(meta) = parsed.cipher else {
        return Err(format!(
            "NotEncrypted: manifest '{sidecar}' does not describe a cipher; nothing to decrypt"
        ));
    };
    if !parsed.has_crc {
        log::debug!("crypt: manifest '{sidecar}' has no crc line; it detects damage only");
    }
    // A plaintext output must not sit next to another image's keyslot: that
    // sidecar is the only copy of a different VMK.
    if Path::new(&out_sidecar).exists() {
        return Err(format!(
            "'{out_sidecar}' already exists; refusing to overwrite a sidecar (it is the only \
             copy of that image's key material), even with --force"
        ));
    }
    if Path::new(out).exists() && !args.force {
        return Err(format!(
            "'{out}' already exists (use --force to replace it when it has no sidecar)"
        ));
    }
    // Build the key/cipher before touching the output: an invalid key or
    // manifest must never leave plaintext behind.
    let cipher = crypt_unlock_cipher(&meta, &parsed.kind, args)?;
    let tmp = crypt_tmp(out)?;
    let decrypted = crypt_file(&args.input, &tmp, cipher)?;
    if decrypted != input_len {
        let _ = std::fs::remove_file(&tmp);
        return Err(format!(
            "input '{}' changed size while reading (expected {input_len} bytes, processed \
             {decrypted}); no plaintext was written",
            args.input
        ));
    }
    if let Err(e) = std::fs::rename(&tmp, out) {
        let _ = std::fs::remove_file(&tmp);
        return Err(format!("cannot rename '{tmp}' to '{out}': {e}"));
    }
    crypt_sync_parent(out);
    // `--decrypt` never writes or deletes a sidecar; the encrypted input keeps
    // its manifest.
    let verb = if meta.cipher == CipherAlg::Xor {
        "deobfuscated"
    } else {
        "decrypted"
    };
    Ok(format!(
        "{verb} {} -> {} ({decrypted} bytes, {})",
        args.input,
        out,
        crate::cipher::cipher_meta_name(&meta)
    ))
}

/// `snowscsi bundle-info <path>` — report the manifest (and CD-R TOC header).
#[cfg(feature = "bundle")]
fn run_bundle_info(args: BundleInfoArgs) -> ExitCode {
    if !Path::new(&args.path).exists() {
        eprintln!("snowscsi: bundle-info: path not found: {}", args.path);
        return ExitCode::FAILURE;
    }
    let identified = if Path::new(&args.path).is_dir() {
        let mut fs = StdFsBackend::new(&args.path);
        match identify_dir(&mut fs) {
            Ok(identified) => identified,
            Err(e) => {
                eprintln!("snowscsi: bundle-info: {}: {e}", args.path);
                return ExitCode::FAILURE;
            }
        }
    } else {
        // Use an explicit sidecar path as-is; otherwise append the suffix
        // without replacing the image's extension.
        let sidecar = if args.path.ends_with(SIDECAR_SUFFIX) {
            args.path.clone()
        } else {
            format!("{}{}", args.path, SIDECAR_SUFFIX)
        };
        let bytes = match read_capped(&sidecar, MAX_MANIFEST + 1) {
            Ok(bytes) => bytes,
            // A regular file without a sidecar is simply not a bundle (exit
            // 2), not an I/O failure. The path itself was already checked.
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                println!("not a bundle");
                println!("found = none");
                return ExitCode::from(2);
            }
            Err(e) => {
                eprintln!("snowscsi: bundle-info: {sidecar}: {e}");
                return ExitCode::FAILURE;
            }
        };
        match identify_manifest(&bytes) {
            Ok(identified) => identified,
            Err(e) => {
                eprintln!("snowscsi: bundle-info: {sidecar}: {e}");
                return ExitCode::FAILURE;
            }
        }
    };

    match identified {
        Identified::NotBundle { found } => {
            println!("not a bundle");
            let names = found.as_slice().join(", ");
            if names.is_empty() {
                println!("found = none");
            } else {
                println!("found = {names}");
            }
            ExitCode::from(2)
        }
        Identified::Image { meta } => {
            print_bundle_meta(&meta);
            ExitCode::SUCCESS
        }
        Identified::Flat { meta } => {
            print_bundle_meta(&meta);
            ExitCode::SUCCESS
        }
        Identified::Cdr { meta, toc } => {
            print_bundle_meta(&meta);
            if let Some(toc) = toc {
                println!("seq = {}", toc.seq);
                println!("slot_size = {}", toc.slot_size);
                println!("max_tracks = {}", toc.max_tracks);
                println!("capacity = {}", toc.capacity_sectors);
                println!("sessions = {}", toc.sessions);
                println!("tracks = {}", toc.tracks);
                println!("profile = 0x{:04x}", toc.profile);
            } else {
                println!("toc = missing");
            }
            ExitCode::SUCCESS
        }
    }
}

/// Read at most `limit` bytes, so a sidecar cannot be slurped whole.
fn read_capped(path: &str, limit: usize) -> std::io::Result<Vec<u8>> {
    use std::io::Read as _;

    let file = std::fs::File::open(path)?;
    let mut bytes = Vec::new();
    file.take(limit as u64).read_to_end(&mut bytes)?;
    Ok(bytes)
}

#[cfg(not(feature = "bundle"))]
fn run_bundle_info(_args: BundleInfoArgs) -> ExitCode {
    eprintln!("snowscsi: bundle-info requires the `bundle` feature");
    ExitCode::FAILURE
}

#[cfg(feature = "bundle")]
fn print_bundle_meta(meta: &BundleMeta) {
    match meta.kind {
        BundleKind::Image { size } => {
            println!("kind = image");
            println!("size = {size}");
        }
        BundleKind::Flat {
            virtual_size,
            chunk_size,
            sector_size,
        } => {
            println!("kind = flat");
            println!("virtual_size = {virtual_size}");
            println!("chunk_size = {chunk_size}");
            println!("sector_size = {sector_size}");
        }
        BundleKind::Cdr => println!("kind = cdr"),
    }
    if let Some(cipher) = meta.cipher {
        println!("cipher = {}", cipher_text(cipher.cipher));
        println!("kdf = {}", kdf_text(cipher.slot.kdf));
        if let Some(iterations) = cipher.slot.iterations {
            println!("iterations = {iterations}");
        }
        // Never print the nonce, salt, wrapped key, tag or key-id bytes: they
        // are key material or a fingerprint of it.
        println!("keyslot = wrapped");
        println!("tag = present");
        println!("key_id = present");
    } else {
        println!("cipher = none");
    }
    println!("crc = {}", if meta.has_crc { "present" } else { "absent" });
}

#[cfg(feature = "bundle")]
fn cipher_text(cipher: CipherAlg) -> &'static str {
    match cipher {
        CipherAlg::ChaCha8 => "chacha8",
        CipherAlg::ChaCha12 => "chacha12",
        CipherAlg::ChaCha20 => "chacha20",
        CipherAlg::AesCtr => "aes-ctr",
        CipherAlg::Xor => "xor",
    }
}

#[cfg(feature = "bundle")]
fn kdf_text(kdf: KdfKind) -> &'static str {
    match kdf {
        KdfKind::Pbkdf2HmacSha256 => "pbkdf2-hmac-sha256",
        KdfKind::None => "none",
    }
}

/// `snowscsi mkisofs <DIR> <OUT.iso>` — scan a host directory and write a
/// standalone ISO9660/Joliet image to disk.
///
/// Reuses the live-generation pipeline (`LiveData`: scan → layout → sector
/// synthesis) and dumps every sector through its `FlatData::read_at`, so the
/// on-disk image is byte-identical to what `serve --cdrom live=<dir>`
/// would expose. The image is padded to whole 2048-byte sectors.
fn run_mkisofs(args: MkisofsArgs) -> ExitCode {
    init_logging(args.verbose);

    let dir = Path::new(&args.dir);
    if !dir.is_dir() {
        eprintln!("snowscsi: directory not found: {}", args.dir);
        return ExitCode::FAILURE;
    }
    if args.out.is_empty() {
        eprintln!("snowscsi: empty output path");
        return ExitCode::FAILURE;
    }
    if Path::new(&args.out).is_dir() {
        eprintln!("snowscsi: output path is a directory: {}", args.out);
        return ExitCode::FAILURE;
    }

    let label = match &args.label {
        Some(l) => l.clone(),
        None => dir
            .file_name()
            .and_then(|n| n.to_str())
            .unwrap_or("SNOWSCSI")
            .to_string(),
    };

    let fs = StdFsBackend::new(&args.dir);
    let mut live = match LiveData::new(fs, &label) {
        Ok(d) => d,
        Err(e) => {
            eprintln!("snowscsi: failed to scan {}: {e}", args.dir);
            return ExitCode::FAILURE;
        }
    };
    let total_sectors = live.layout().total;

    let file = match File::create(&args.out) {
        Ok(f) => f,
        Err(e) => {
            eprintln!("snowscsi: failed to create {}: {e}", args.out);
            return ExitCode::FAILURE;
        }
    };
    let mut writer = BufWriter::new(file);
    let mut sector = [0u8; ISO_SECTOR_SIZE as usize];
    for lba in 0..total_sectors {
        if snowscsi::common::seekable_storage::FlatData::read_at(
            &mut live,
            u64::from(lba) * u64::from(ISO_SECTOR_SIZE),
            &mut sector,
        )
        .is_err()
        {
            eprintln!("snowscsi: failed to read sector {lba}");
            return ExitCode::FAILURE;
        }
        if writer.write_all(&sector).is_err() {
            eprintln!("snowscsi: failed to write {}", args.out);
            return ExitCode::FAILURE;
        }
    }
    if writer.flush().is_err() {
        eprintln!("snowscsi: failed to flush {}", args.out);
        return ExitCode::FAILURE;
    }

    log::info!(
        "wrote {} sectors ({} bytes) to {}",
        total_sectors,
        u64::from(total_sectors) * u64::from(ISO_SECTOR_SIZE),
        args.out
    );
    ExitCode::SUCCESS
}

/// Install the CLI log output: a plain `log` backend (env_logger) writing
/// to stderr. `-v` selects the debug level, `-vv` (or more) the trace
/// level; `RUST_LOG` overrides both.
fn init_logging(verbose: u8) {
    let level = match verbose {
        0 => log::LevelFilter::Info,
        1 => log::LevelFilter::Debug,
        _ => log::LevelFilter::Trace,
    };
    let mut builder = env_logger::Builder::new();
    builder.filter_level(level);
    builder.parse_default_env();
    // try_init: a logger may already be set when tests drive the handlers
    // in-process (parallel test threads share the process logger).
    let _ = builder.try_init();
}

/// Resolve the work buffer size (default 1M): the raw parse plus the absolute
/// floor both transports share ([`MIN_DATA_AREA`]).
///
/// Each transport then enforces its own minimum:
/// [`check_iscsi_work_size`] (BHS + Login text) or [`check_usb_work_size`].
/// A transfer larger than the buffer is streamed in bank-sized chunks, so this
/// is a throughput/latency knob rather than a maximum transfer size.
fn parse_work_size(s: Option<&str>) -> Result<usize, String> {
    parse_work_size_or(s, DEFAULT_WORK_BUF_SIZE)
}

/// [`parse_work_size`] with an explicit default: dual-bank mode uses the
/// two-bank total ([`DUAL_WORK_BUF_SIZE`] / [`ISCSI_DUAL_WORK_BUF_SIZE`]).
fn parse_work_size_or(s: Option<&str>, default: usize) -> Result<usize, String> {
    let bytes = match s {
        None => default as u64,
        Some(v) => spec::parse_size(v).ok_or_else(|| format!("invalid --work-buf-size: {v}"))?,
    };
    let n = usize::try_from(bytes).map_err(|_| format!("--work-buf-size {bytes} is too large"))?;
    if n < MIN_DATA_AREA {
        return Err(format!(
            "--work-buf-size {n} is below the minimum {MIN_DATA_AREA}"
        ));
    }
    Ok(n)
}

/// Reject bank combinations the selected transport cannot honor.
///
/// Checked by [`resolve_config`] before any listener is bound or gadget
/// assembled, so a rejected invocation exits instead of hanging in an
/// accept/serve loop:
/// - the dual banks live inside `work`, so a separate `--scratch-buffer`
///   would be a third buffer with no defined owner.
fn check_banks(args: &ServeArgs) -> Result<(), String> {
    if args.banks != Banks::Dual {
        return Ok(());
    }
    if args.scratch_buffer.is_some() {
        return Err(
            "--banks dual cannot be combined with --scratch-buffer: the two banks \
             already live inside --work-buf-size (the long operation gets one of them)"
                .to_string(),
        );
    }
    Ok(())
}

/// Resolve the optional split-mode long-operation bank.
///
/// `None` (flag absent) selects the shared bank: `work` serves both the command
/// path and the resident long operation, so a query waits at most one
/// long-operation chunk. `Some` allocates the separate bank of the split mode,
/// rounded up to [`MIN_DATA_LEN`].
fn parse_scratch_size(s: Option<&str>) -> Result<Option<usize>, String> {
    let Some(v) = s else {
        return Ok(None);
    };
    let bytes = spec::parse_size(v).ok_or_else(|| format!("invalid --scratch-buffer: {v}"))?;
    let n = usize::try_from(bytes).map_err(|_| format!("--scratch-buffer {bytes} is too large"))?;
    Ok(Some(scratch_size(n)))
}

/// Split-mode long-operation bank size: never below [`MIN_DATA_LEN`].
fn scratch_size(requested: usize) -> usize {
    requested.max(MIN_DATA_LEN)
}

/// Allocate the long-operation bank: an empty vector selects the shared mode.
fn split_bank(requested: Option<usize>) -> Vec<u8> {
    match requested {
        Some(n) => vec![0u8; n],
        None => Vec::new(),
    }
}

/// iSCSI `work` floor: [`MIN_DATA_LEN`] plus the 48-byte BHS, and a data area
/// that is a multiple of 4 (every Data-In PDU is padded to a 4-byte boundary).
///
/// The floor covers a Login Request carrying the default
/// `MaxRecvDataSegmentLength` (RFC 3720 §6.1) bytes of text; a smaller bank
/// could not stage a conformant first Login Request.
fn check_iscsi_work_size(n: usize) -> Result<(), String> {
    let min = MIN_DATA_LEN + BHS_SIZE;
    if n < min {
        return Err(format!(
            "--work-buf-size {n} is below the iSCSI minimum {min}"
        ));
    }
    if !(n - BHS_SIZE).is_multiple_of(4) {
        return Err(format!(
            "--work-buf-size {n} leaves a data area that is not a multiple of 4"
        ));
    }
    Ok(())
}

/// iSCSI dual-bank `work` bounds: the total is split into two equal banks,
/// each bank carrying its own 48-byte BHS prefix.
///
/// The total must be even, each half at least [`MIN_DATA_LEN`] + [`BHS_SIZE`],
/// and each half's data area (`half - BHS_SIZE`) a multiple of 4.
fn check_iscsi_dual_work_size(n: usize) -> Result<(), String> {
    if !n.is_multiple_of(2) {
        return Err(format!(
            "--work-buf-size {n} must be even with --banks dual (two equal banks)"
        ));
    }
    let half = n / 2;
    let min = MIN_DATA_LEN + BHS_SIZE;
    if half < min {
        return Err(format!(
            "--work-buf-size {n} leaves a {half}-byte bank below the iSCSI minimum \
             {min} (total must be at least {})",
            2 * min
        ));
    }
    if !(half - BHS_SIZE).is_multiple_of(4) {
        return Err(format!(
            "--work-buf-size {n} leaves a {half}-byte bank whose data area is not a multiple of 4"
        ));
    }
    Ok(())
}

/// USB BOT `work` floor: [`MIN_DATA_AREA`], with no header prefix and no
/// alignment requirement.
fn check_usb_work_size(n: usize) -> Result<(), String> {
    if n < MIN_DATA_AREA {
        return Err(format!(
            "--work-buf-size {n} is below the USB minimum {MIN_DATA_AREA}"
        ));
    }
    Ok(())
}

/// USB dual-bank `work` bounds: the total is split into two equal banks, so it
/// must be even and each half must still clear [`MIN_DATA_AREA`].
fn check_usb_dual_work_size(n: usize) -> Result<(), String> {
    if !n.is_multiple_of(2) {
        return Err(format!(
            "--work-buf-size {n} must be even with --banks dual (two equal banks)"
        ));
    }
    let half = n / 2;
    if half < MIN_DATA_AREA {
        return Err(format!(
            "--work-buf-size {n} leaves a {half}-byte bank below the USB minimum \
             {MIN_DATA_AREA} (total must be at least {})",
            2 * MIN_DATA_AREA
        ));
    }
    Ok(())
}

/// Parse a hexadecimal u16 (with optional `0x` prefix) for `--vid`/`--pid`.
fn parse_hex_u16(s: &str) -> Result<u16, String> {
    let body = s.trim_start_matches("0x").trim_start_matches("0X");
    u16::from_str_radix(body, 16).map_err(|_| format!("invalid hex value: {s}"))
}

#[cfg(test)]
mod tests {
    #![allow(clippy::needless_update)]

    use super::*;

    #[cfg(target_os = "linux")]
    #[test]
    fn link_down_errno_classification() {
        use std::io::ErrorKind;
        // ESHUTDOWN (the VM-migration failure), ENOTCONN, ECONNRESET,
        // ECONNABORTED, EPIPE.
        for errno in [108, 107, 104, 103, 32] {
            let e = std::io::Error::from_raw_os_error(errno);
            assert!(is_link_down_err(&e), "errno {errno} must be link-down");
        }
        // Genuine failures are not treated as a disconnect.
        for e in [
            std::io::Error::from_raw_os_error(22), // EINVAL
            std::io::Error::new(ErrorKind::TimedOut, "timeout"),
        ] {
            assert!(!is_link_down_err(&e), "{e:?} must not be link-down");
        }
    }

    #[test]
    fn parse_work_size_defaults_and_validation() {
        assert_eq!(parse_work_size(None).unwrap(), DEFAULT_WORK_BUF_SIZE);
        assert_eq!(parse_work_size(Some("128K")).unwrap(), 128 * 1024);
        assert!(parse_work_size(Some("511")).is_err()); // below the USB floor
        assert_eq!(parse_work_size(Some("512")).unwrap(), MIN_DATA_AREA);
        assert!(parse_work_size(Some("bogus")).is_err());
    }

    /// Parse a `serve` invocation with a RAM block device plus `extra` flags.
    fn parse_serve(extra: &[&str]) -> ServeArgs {
        let mut argv = vec!["snowscsi", "serve", "--block", "ram=1M"];
        argv.extend_from_slice(extra);
        match Cli::try_parse_from(argv).expect("parse") {
            Cli::Serve(a) => a,
            other => panic!("expected Serve, got {other:?}"),
        }
    }

    #[test]
    fn cli_wire_and_banks_parse() {
        let args = parse_serve(&["--usb", "--banks", "dual"]);
        assert_eq!(args.usb.as_deref(), Some("auto"));
        assert_eq!(args.wire, Wire::Blocking);
        assert_eq!(args.banks, Banks::Dual);
        assert!(!args.print_config);

        let args = parse_serve(&["--usb"]);
        assert_eq!(args.wire, Wire::Blocking, "blocking is the default wire");
        assert_eq!(args.banks, Banks::Single, "single is the default banks");

        let args = parse_serve(&["--iscsi", "127.0.0.1:0", "--wire", "async"]);
        assert_eq!(args.wire, Wire::Async);
    }

    #[test]
    fn cli_overlap_flag_is_rejected() {
        // `--overlap` is gone, with no alias.
        assert!(Cli::try_parse_from([
            "snowscsi",
            "serve",
            "--block",
            "ram=1M",
            "--usb",
            "--overlap"
        ])
        .is_err());
    }

    #[cfg(target_os = "linux")]
    fn stamp(len: u64, secs: u64) -> CardStamp {
        CardStamp {
            len,
            mtime: Some(std::time::SystemTime::UNIX_EPOCH + Duration::from_secs(secs)),
        }
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn card_watch_decision_is_pure_and_stable() {
        let mut watch = CardWatch::new(Some(stamp(4096, 10)), 512);
        assert_eq!(watch.observe(CardObservation::Missing), CardDecision::Wait);
        assert_eq!(
            watch.observe(CardObservation::NotRegular),
            CardDecision::Wait,
            "a directory is not a card"
        );

        let sub_sector = stamp(511, 10);
        assert_eq!(
            watch.observe(CardObservation::Regular(sub_sector)),
            CardDecision::Reject("image is smaller than one logical sector")
        );
        assert_eq!(
            watch.observe(CardObservation::Regular(sub_sector)),
            CardDecision::Wait,
            "the same rejected file is not retried every poll"
        );

        let new = stamp(8192, 20);
        assert_eq!(
            watch.observe(CardObservation::Regular(new)),
            CardDecision::Wait,
            "one changed sighting is not enough"
        );
        assert_eq!(
            watch.observe(CardObservation::Regular(new)),
            CardDecision::Insert(new),
            "two stable sightings install the card"
        );

        assert!(
            !should_arm_card_watcher(true, false),
            "a loaded card is never watched"
        );
        assert!(should_arm_card_watcher(true, true));
        assert!(!should_arm_card_watcher(false, true));
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn card_watch_detects_a_file_after_it_was_missing() {
        let old = stamp(4096, 10);
        let mut watch = CardWatch::new(Some(old), 512);
        assert_eq!(watch.observe(CardObservation::Missing), CardDecision::Wait);
        assert_eq!(
            watch.observe(CardObservation::Regular(old)),
            CardDecision::Wait,
            "reappearance resets the absent flag"
        );
        assert_eq!(
            watch.observe(CardObservation::Regular(old)),
            CardDecision::Insert(old)
        );
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn card_attrs_reject_sub_sector_images() {
        assert!(card_attrs(0, 512, false).is_err());
        assert!(card_attrs(511, 512, false).is_err());
        assert_eq!(card_attrs(2048, 2048, false).unwrap().capacity_blocks, 1);
        assert_eq!(card_attrs(2048, 512, false).unwrap().capacity_blocks, 4);
    }

    #[test]
    fn removable_demo_is_usb_single_slot_only() {
        let specs = spec::parse_all(&["img=/tmp/card.img,removable".to_string()], &[]).unwrap();
        let args = parse_serve(&["--usb"]);
        let cfg = resolve_config(&args).unwrap();
        assert_eq!(validate_removable(&args, &specs, &cfg), Ok(Some(0)));

        let iscsi = parse_serve(&["--iscsi", "127.0.0.1:0"]);
        let cfg = resolve_config(&iscsi).unwrap();
        assert!(
            validate_removable(&iscsi, &specs, &cfg).is_err(),
            "iSCSI has no pause/insert handback"
        );

        let dual = parse_serve(&["--usb", "--banks", "dual"]);
        let cfg = resolve_config(&dual).unwrap();
        assert!(
            validate_removable(&dual, &specs, &cfg).is_err(),
            "the worker path moves the planes out of the serve loop"
        );

        let two = spec::parse_all(
            &[
                "img=/tmp/a.img,removable".to_string(),
                "img=/tmp/b.img,removable".to_string(),
            ],
            &[],
        )
        .unwrap();
        let args = parse_serve(&["--usb"]);
        let cfg = resolve_config(&args).unwrap();
        assert!(
            validate_removable(&args, &two, &cfg).is_err(),
            "at most one removable card slot"
        );
    }

    #[test]
    fn print_config_line_is_stable() {
        let args = parse_serve(&["--usb", "--banks", "dual"]);
        let cfg = resolve_config(&args).unwrap();
        assert_eq!(
            cfg.line(2, "ram", false),
            "wire=blocking banks=dual storage=worker per_bank=8192 work=16384 scratch=0 lun=2 \
             backing=ram"
        );

        let args = parse_serve(&["--iscsi", "127.0.0.1:0", "--banks", "dual"]);
        let cfg = resolve_config(&args).unwrap();
        assert_eq!(
            cfg.line(1, "ram", false),
            "wire=blocking banks=dual storage=worker per_bank=8240 work=16480 scratch=0 lun=1 \
             backing=ram"
        );

        let args = parse_serve(&["--usb"]);
        let cfg = resolve_config(&args).unwrap();
        assert_eq!(
            cfg.line(1, "ram", false),
            format!(
                "wire=blocking banks=single storage=inline per_bank={DEFAULT_WORK_BUF_SIZE} \
                 work={DEFAULT_WORK_BUF_SIZE} scratch=0 lun=1 backing=ram"
            )
        );

        let args = parse_serve(&["--usb", "--scratch-buffer", "16K"]);
        let cfg = resolve_config(&args).unwrap();
        assert_eq!(
            cfg.line(1, "ram", false),
            format!(
                "wire=blocking banks=single storage=inline per_bank={DEFAULT_WORK_BUF_SIZE} \
                 work={DEFAULT_WORK_BUF_SIZE} scratch={} lun=1 backing=ram",
                16 * 1024
            )
        );
    }

    #[test]
    fn print_config_flag_parses() {
        let args = parse_serve(&["--usb", "--print-config"]);
        assert!(args.print_config);
    }

    fn temp_dir(tag: &str) -> std::path::PathBuf {
        let dir = std::env::temp_dir().join(format!(
            "snowscsi_cli_{tag}_{}_{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_nanos())
                .unwrap_or(0)
        ));
        let _ = std::fs::remove_dir_all(&dir);
        dir
    }

    /// The CLI's `CdrBundleMedium` is large (fixed track/session tables), so a
    /// debug-build call graph can exceed the default 2 MiB test-thread stack.
    #[allow(dead_code)]
    fn run_with_large_stack<T: Send + 'static>(f: impl FnOnce() -> T + Send + 'static) -> T {
        std::thread::Builder::new()
            .stack_size(32 * 1024 * 1024)
            .spawn(f)
            .expect("spawn large-stack thread")
            .join()
            .expect("large-stack thread")
    }

    #[test]
    fn print_config_accepts_a_bundle() {
        let Cli::Serve(args) = Cli::try_parse_from([
            "snowscsi",
            "serve",
            "--cdrom",
            "bundle=/tmp/disc",
            "--usb",
            "--print-config",
        ])
        .unwrap() else {
            panic!("expected Serve");
        };
        assert!(args.print_config);
        let specs = spec::parse_all(&args.block, &args.cdrom).unwrap();
        assert_eq!(specs.len(), 1);
        assert_eq!(specs[0].role, DeviceRole::MmcCd);
        let cfg = resolve_config(&args).unwrap();
        assert_eq!(
            cfg.line(specs.len(), "bundle", pool_capable(&specs, &cfg)),
            format!(
                "wire=blocking banks=single storage=inline per_bank={DEFAULT_WORK_BUF_SIZE} \
                 work={DEFAULT_WORK_BUF_SIZE} scratch=0 lun=1 backing=bundle"
            )
        );

        // A bundle always owns a blocking filesystem scanner, so even the
        // dual-bank async switches cannot hand it to the library slot pool.
        let async_dual = ServeConfig {
            wire: Wire::Async,
            banks: Banks::Dual,
            work_size: ISCSI_DUAL_WORK_BUF_SIZE,
            scratch_len: None,
        };
        assert!(!pool_capable(&specs, &async_dual));
    }

    #[test]
    fn bundle_help_and_print_config_mention_the_backing() {
        use clap::CommandFactory;

        // `serve --help` documents the unified bundle backing and the
        // directory artifacts the CLI owns.
        let mut command = Cli::command();
        let serve = command
            .find_subcommand_mut("serve")
            .expect("the serve subcommand");
        let help = serve.render_long_help().to_string();
        assert!(help.contains("bundle=<dir>"), "help text:\n{help}");
        assert!(help.contains("toc.0"), "help text:\n{help}");
        assert!(help.contains("track_<n>.bin"), "help text:\n{help}");
        assert!(help.contains("CD-RW"), "help text:\n{help}");
        assert!(help.contains("Track-at-Once"), "help text:\n{help}");
        assert!(help.contains("blank="), "help text:\n{help}");
        assert!(help.contains("-audio"), "help text:\n{help}");
        assert!(help.contains("bundle-create"), "help text:\n{help}");

        // `--print-config` resolves the same backing without touching the
        // filesystem: the token lists every LUN's backing in LUN order.
        let args = parse_serve(&["--usb", "--print-config", "--cdrom", "bundle=/tmp/disc"]);
        let specs = spec::parse_all(&args.block, &args.cdrom).unwrap();
        assert_eq!(backing_names(&specs), "ram,bundle");
        let cfg = resolve_config(&args).unwrap();
        let line = cfg.line(
            specs.len(),
            &backing_names(&specs),
            pool_capable(&specs, &cfg),
        );
        assert!(
            line.ends_with("lun=2 backing=ram,bundle"),
            "print-config line: {line}"
        );
    }

    #[cfg(feature = "bundle")]
    #[test]
    fn build_planes_rejects_a_missing_bundle_dir() {
        let dir = temp_dir("missing_bundle");
        let specs = spec::parse_all(&[], &[format!("bundle={}", dir.display())]).unwrap();
        assert!(build_planes(&specs, None).is_err());
        assert!(!dir.exists(), "serve must never create a bundle directory");
    }

    #[cfg(feature = "bundle")]
    #[test]
    fn build_planes_opens_a_created_flat_bundle() {
        let dir = temp_dir("flat_bundle");
        let created = create_flat_bundle(CreateFlatArgs {
            dir: dir.display().to_string(),
            size: "8M".to_string(),
            chunk: Some("1M".to_string()),
            sector: 512,
            ..CreateFlatArgs::default()
        });
        assert_eq!(created, ExitCode::SUCCESS);
        let specs = spec::parse_all(&[], &[format!("bundle={}", dir.display())]).unwrap();
        let planes = build_planes(&specs, None).expect("flat bundle plane");
        assert_eq!(planes.len(), 1);
        assert_eq!(planes[0].capacity(), 8 << 20);
        assert_eq!(planes[0].sector_size(), Some(512));
        assert!(!planes[0].is_cdr_bundle());
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[cfg(feature = "bundle")]
    #[test]
    fn cdrom_opens_a_flat_bundle_read_only() {
        let dir = temp_dir("flat_cdrom_ro");
        let created = create_flat_bundle(CreateFlatArgs {
            dir: dir.display().to_string(),
            size: "8M".to_string(),
            chunk: None,
            sector: 512,
            ..CreateFlatArgs::default()
        });
        assert_eq!(created, ExitCode::SUCCESS);

        let cd = spec::parse_all(&[], &[format!("bundle={}", dir.display())]).unwrap();
        let planes = build_planes(&cd, None).expect("cdrom flat bundle plane");
        assert!(
            !planes[0].is_writable(),
            "--cdrom bundle=<flat> must open read-only"
        );

        let block = spec::parse_all(&[format!("bundle={}", dir.display())], &[]).unwrap();
        let planes = build_planes(&block, None).expect("block flat bundle plane");
        assert!(
            planes[0].is_writable(),
            "--block bundle=<flat> stays writable"
        );

        let block_ro = spec::parse_all(&[format!("bundle={},ro", dir.display())], &[]).unwrap();
        let planes = build_planes(&block_ro, None).expect("read-only block flat bundle plane");
        assert!(
            !planes[0].is_writable(),
            "`ro` opens the block plane read-only"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[cfg(feature = "bundle")]
    #[test]
    fn bundle_info_reports_a_created_flat_bundle() {
        let dir = temp_dir("info_flat");
        let created = create_flat_bundle(CreateFlatArgs {
            dir: dir.display().to_string(),
            size: "8M".to_string(),
            chunk: None,
            sector: 512,
            ..CreateFlatArgs::default()
        });
        assert_eq!(created, ExitCode::SUCCESS);
        assert_eq!(
            run_bundle_info(BundleInfoArgs {
                path: dir.display().to_string()
            }),
            ExitCode::SUCCESS
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[cfg(feature = "bundle")]
    #[test]
    fn bundle_info_exits_two_for_a_non_bundle() {
        let dir = temp_dir("info_not_bundle");
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(dir.join("000000.img"), b"chunk").unwrap();
        assert_eq!(
            run_bundle_info(BundleInfoArgs {
                path: dir.display().to_string()
            }),
            ExitCode::from(2)
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[cfg(feature = "cdr-bundle")]
    #[test]
    fn build_planes_opens_a_created_cdr_bundle() {
        let dir = temp_dir("cdr_bundle");
        let created = create_cdr_bundle(CreateCdrArgs {
            dir: dir.display().to_string(),
            medium: Some("cdr74".to_string()),
            slot: None,
            ..CreateCdrArgs::default()
        });
        assert_eq!(created, ExitCode::SUCCESS);
        assert!(dir.join("SNOWBUNDLE").is_file());
        assert!(dir.join("toc.0").is_file());

        let specs = spec::parse_all(&[], &[format!("bundle={}", dir.display())]).unwrap();
        let planes = build_planes(&specs, None).expect("cdr bundle plane");
        assert_eq!(planes.len(), 1);
        assert!(planes[0].is_cdr_bundle());

        // The stored TOC owns the geometry, so the slot builds end to end.
        let specs_for_slots = specs.clone();
        assert!(
            run_with_large_stack(move || {
                let mut planes = Vec::new();
                let mut slots = Vec::new();
                build_core_slots(&specs_for_slots, &mut planes, &mut slots, None).is_ok()
                    && slots.len() == 1
            }),
            "a kind=cdr bundle must build an MMC slot"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[cfg(feature = "cdr-bundle")]
    #[test]
    fn cdr_bundle_is_rejected_under_block() {
        let dir = temp_dir("cdr_under_block");
        let created = create_cdr_bundle(CreateCdrArgs {
            dir: dir.display().to_string(),
            medium: None,
            slot: None,
            ..CreateCdrArgs::default()
        });
        assert_eq!(created, ExitCode::SUCCESS);
        let specs = spec::parse_all(&[format!("bundle={}", dir.display())], &[]).unwrap();
        assert!(
            run_with_large_stack(move || {
                let mut planes = Vec::new();
                let mut slots = Vec::new();
                build_core_slots(&specs, &mut planes, &mut slots, None).is_err()
            }),
            "a kind=cdr manifest cannot back --block"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[cfg(feature = "cdr-bundle")]
    #[test]
    fn cdr_bundle_rejects_read_only() {
        let dir = temp_dir("cdr_read_only");
        let created = create_cdr_bundle(CreateCdrArgs {
            dir: dir.display().to_string(),
            medium: None,
            slot: None,
            ..CreateCdrArgs::default()
        });
        assert_eq!(created, ExitCode::SUCCESS);
        let specs = spec::parse_all(&[], &[format!("bundle={},ro", dir.display())]).unwrap();
        assert!(build_planes(&specs, None).is_err());
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[cfg(feature = "cdr-bundle")]
    #[test]
    fn cdr_bundle_without_a_toc_is_rejected() {
        let dir = temp_dir("cdr_no_toc");
        let created = create_cdr_bundle(CreateCdrArgs {
            dir: dir.display().to_string(),
            medium: None,
            slot: None,
            ..CreateCdrArgs::default()
        });
        assert_eq!(created, ExitCode::SUCCESS);
        std::fs::remove_file(dir.join("toc.0")).unwrap();
        let _ = std::fs::remove_file(dir.join("toc.1"));

        let specs = spec::parse_all(&[], &[format!("bundle={}", dir.display())]).unwrap();
        assert!(
            build_planes(&specs, None).is_err(),
            "a TOC-less recordable bundle must not open"
        );
        assert!(!dir.join("toc.0").exists(), "serve must not create a TOC");
        assert!(!dir.join("toc.1").exists(), "serve must not create a TOC");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[cfg(feature = "cdr-bundle")]
    #[test]
    fn cdr_bundle_create_refuses_leftover_tracks() {
        let dir = temp_dir("cdr_leftover_track");
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(dir.join("track_1.bin"), b"leftover").unwrap();

        let args = CreateCdrArgs {
            dir: dir.display().to_string(),
            medium: None,
            slot: None,
            ..CreateCdrArgs::default()
        };
        assert_eq!(create_cdr_bundle(args), ExitCode::FAILURE);
        assert!(
            dir.join("track_1.bin").is_file(),
            "the leftover track data must survive the refusal"
        );
        assert!(!dir.join("SNOWBUNDLE").exists());
        assert!(!dir.join("toc.0").exists());
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[cfg(feature = "bundle")]
    #[test]
    fn flat_bundle_create_refuses_a_legacy_header() {
        let dir = temp_dir("flat_legacy");
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(dir.join("BUNDLE"), b"legacy").unwrap();
        let args = CreateFlatArgs {
            dir: dir.display().to_string(),
            size: "8M".to_string(),
            chunk: None,
            sector: 512,
            ..CreateFlatArgs::default()
        };
        assert_eq!(create_flat_bundle(args), ExitCode::FAILURE);
        assert!(!dir.join("SNOWBUNDLE").exists());
        assert_eq!(std::fs::read(dir.join("BUNDLE")).unwrap(), b"legacy");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[cfg(feature = "bundle")]
    #[test]
    fn bundle_create_force_flag_is_gone() {
        for args in [
            vec![
                "snowscsi",
                "bundle-create",
                "flat",
                "--dir",
                "/tmp/disc",
                "--size",
                "8M",
                "--force",
            ],
            vec![
                "snowscsi",
                "bundle-create",
                "cdr",
                "--dir",
                "/tmp/cdr",
                "--force",
            ],
        ] {
            assert!(
                Cli::try_parse_from(args).is_err(),
                "bundle-create must no longer accept --force"
            );
        }
    }

    #[cfg(feature = "bundle")]
    #[test]
    fn flat_bundle_create_validates_before_mkdir() {
        let dir = temp_dir("flat_bad_geometry");
        let args = CreateFlatArgs {
            dir: dir.display().to_string(),
            size: "1".to_string(),
            chunk: None,
            sector: 512,
            ..CreateFlatArgs::default()
        };
        assert_eq!(create_flat_bundle(args), ExitCode::FAILURE);
        assert!(!dir.exists(), "a bad --size must not create the directory");
    }

    #[cfg(feature = "bundle")]
    #[test]
    fn flat_bundle_create_refuses_leftover_chunks() {
        let dir = temp_dir("flat_leftover_chunk");
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(dir.join("000000.img"), b"leftover").unwrap();
        let args = CreateFlatArgs {
            dir: dir.display().to_string(),
            size: "8M".to_string(),
            chunk: None,
            sector: 512,
            ..CreateFlatArgs::default()
        };
        assert_eq!(create_flat_bundle(args), ExitCode::FAILURE);
        assert!(dir.join("000000.img").is_file());
        assert!(!dir.join("SNOWBUNDLE").exists());
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[cfg(all(unix, feature = "bundle"))]
    #[test]
    fn build_planes_rejects_bundle_aliases() {
        let dir = temp_dir("alias_bundle");
        let created = create_flat_bundle(CreateFlatArgs {
            dir: dir.display().to_string(),
            size: "8M".to_string(),
            chunk: None,
            sector: 512,
            ..CreateFlatArgs::default()
        });
        assert_eq!(created, ExitCode::SUCCESS);

        // A trailing slash is the same directory but a different raw string.
        let slash = format!("{}/", dir.display());
        let specs = spec::parse_all(
            &[
                format!("bundle={}", dir.display()),
                format!("bundle={slash}"),
            ],
            &[],
        )
        .unwrap();
        assert!(
            build_planes(&specs, None).is_err(),
            "slash alias must be rejected"
        );

        // A symlink is also the same directory after canonicalization.
        let link = temp_dir("alias_link");
        let _ = std::fs::remove_dir_all(&link);
        std::os::unix::fs::symlink(&dir, &link).unwrap();
        let specs = spec::parse_all(
            &[
                format!("bundle={}", dir.display()),
                format!("bundle={}", link.display()),
            ],
            &[],
        )
        .unwrap();
        assert!(
            build_planes(&specs, None).is_err(),
            "symlink alias must be rejected"
        );

        let _ = std::fs::remove_file(&link);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[cfg(feature = "bundle")]
    #[test]
    fn bundle_info_handles_missing_toc_sidecar_and_missing_path() {
        let missing = temp_dir("info_missing");
        assert_eq!(
            run_bundle_info(BundleInfoArgs {
                path: missing.display().to_string()
            }),
            ExitCode::FAILURE
        );

        let dir = temp_dir("info_sidecar");
        let created = create_flat_bundle(CreateFlatArgs {
            dir: dir.display().to_string(),
            size: "8M".to_string(),
            chunk: None,
            sector: 512,
            ..CreateFlatArgs::default()
        });
        assert_eq!(created, ExitCode::SUCCESS);
        let manifest = std::fs::read(dir.join("SNOWBUNDLE")).unwrap();
        let image = dir.join("image.iso");
        std::fs::write(&image, b"image").unwrap();
        let sidecar = format!("{}{SIDECAR_SUFFIX}", image.display());
        std::fs::write(&sidecar, &manifest).unwrap();
        assert_eq!(
            run_bundle_info(BundleInfoArgs {
                path: image.display().to_string()
            }),
            ExitCode::SUCCESS
        );
        // An explicit sidecar path is used as-is, never suffixed twice.
        assert_eq!(
            run_bundle_info(BundleInfoArgs { path: sidecar }),
            ExitCode::SUCCESS
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[cfg(feature = "cdr-bundle")]
    #[test]
    fn bundle_info_reports_a_toc_less_cdr_bundle() {
        let dir = temp_dir("info_cdr_no_toc");
        let created = create_cdr_bundle(CreateCdrArgs {
            dir: dir.display().to_string(),
            medium: None,
            slot: None,
            ..CreateCdrArgs::default()
        });
        assert_eq!(created, ExitCode::SUCCESS);
        std::fs::remove_file(dir.join("toc.0")).unwrap();
        assert_eq!(
            run_bundle_info(BundleInfoArgs {
                path: dir.display().to_string()
            }),
            ExitCode::SUCCESS
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[cfg(feature = "cdr-bundle")]
    #[test]
    fn cdr_bundle_create_refuses_an_existing_manifest_and_toc() {
        let dir = temp_dir("cdr_existing");
        let first = CreateCdrArgs {
            dir: dir.display().to_string(),
            medium: Some("cdr74".to_string()),
            slot: None,
            ..CreateCdrArgs::default()
        };
        assert_eq!(create_cdr_bundle(first), ExitCode::SUCCESS);
        let manifest_before = std::fs::read(dir.join("SNOWBUNDLE")).unwrap();
        let toc_before = std::fs::read(dir.join("toc.0")).unwrap();
        let again = CreateCdrArgs {
            dir: dir.display().to_string(),
            medium: Some("cdr90".to_string()),
            slot: None,
            ..CreateCdrArgs::default()
        };
        assert_eq!(create_cdr_bundle(again), ExitCode::FAILURE);
        assert_eq!(
            std::fs::read(dir.join("SNOWBUNDLE")).unwrap(),
            manifest_before
        );
        assert_eq!(std::fs::read(dir.join("toc.0")).unwrap(), toc_before);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[cfg(feature = "cdr-bundle")]
    #[test]
    fn cdr_bundle_create_refuses_recorded_tracks_without_destroying_them() {
        let dir = temp_dir("cdr_recorded_refusal");
        let first = CreateCdrArgs {
            dir: dir.display().to_string(),
            medium: None,
            slot: None,
            ..CreateCdrArgs::default()
        };
        assert_eq!(create_cdr_bundle(first), ExitCode::SUCCESS);
        std::fs::write(dir.join("track_1.bin"), b"recorded").unwrap();
        let manifest_before = std::fs::read(dir.join("SNOWBUNDLE")).unwrap();
        let again = CreateCdrArgs {
            dir: dir.display().to_string(),
            medium: None,
            slot: None,
            ..CreateCdrArgs::default()
        };
        assert_eq!(create_cdr_bundle(again), ExitCode::FAILURE);
        assert_eq!(
            std::fs::read(dir.join("track_1.bin")).unwrap(),
            b"recorded",
            "recorded data must survive the refusal"
        );
        assert_eq!(
            std::fs::read(dir.join("SNOWBUNDLE")).unwrap(),
            manifest_before
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[cfg(feature = "cdr-bundle")]
    #[test]
    fn bundle_info_reports_missing_for_a_corrupt_toc_body() {
        let dir = temp_dir("info_cdr_corrupt");
        let created = create_cdr_bundle(CreateCdrArgs {
            dir: dir.display().to_string(),
            medium: None,
            slot: None,
            ..CreateCdrArgs::default()
        });
        assert_eq!(created, ExitCode::SUCCESS);
        let _ = std::fs::remove_file(dir.join("toc.1"));
        // A valid header over a body whose checksum no longer matches.
        let mut toc = std::fs::read(dir.join("toc.0")).unwrap();
        toc[256] ^= 0xFF;
        std::fs::write(dir.join("toc.0"), &toc).unwrap();
        assert_eq!(
            run_bundle_info(BundleInfoArgs {
                path: dir.display().to_string()
            }),
            ExitCode::SUCCESS,
            "a corrupt body is a missing TOC, not an identification failure"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[cfg(feature = "bundle")]
    #[test]
    fn bundle_info_exits_two_for_a_regular_file_without_a_sidecar() {
        let dir = temp_dir("info_no_sidecar");
        std::fs::create_dir_all(&dir).unwrap();
        let file = dir.join("plain.img");
        std::fs::write(&file, b"not a bundle").unwrap();
        assert_eq!(
            run_bundle_info(BundleInfoArgs {
                path: file.display().to_string()
            }),
            ExitCode::from(2)
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[cfg(feature = "bundle")]
    #[test]
    fn bundle_create_refuses_to_overwrite() {
        let dir = temp_dir("overwrite");
        let flat = CreateFlatArgs {
            dir: dir.display().to_string(),
            size: "8M".to_string(),
            chunk: None,
            sector: 512,
            ..CreateFlatArgs::default()
        };
        assert_eq!(create_flat_bundle(flat), ExitCode::SUCCESS);
        let again = CreateFlatArgs {
            dir: dir.display().to_string(),
            size: "8M".to_string(),
            chunk: None,
            sector: 512,
            ..CreateFlatArgs::default()
        };
        assert_eq!(create_flat_bundle(again), ExitCode::FAILURE);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[cfg(feature = "cdr-bundle")]
    #[test]
    fn cdr_bundle_create_refuses_to_overwrite() {
        let dir = temp_dir("cdr_overwrite");
        let first = CreateCdrArgs {
            dir: dir.display().to_string(),
            medium: None,
            slot: None,
            ..CreateCdrArgs::default()
        };
        assert_eq!(create_cdr_bundle(first), ExitCode::SUCCESS);
        let again = CreateCdrArgs {
            dir: dir.display().to_string(),
            medium: None,
            slot: None,
            ..CreateCdrArgs::default()
        };
        assert_eq!(create_cdr_bundle(again), ExitCode::FAILURE);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn cli_bundle_verbs_parse() {
        match Cli::try_parse_from(["snowscsi", "bundle-info", "/tmp/disc"]).unwrap() {
            Cli::BundleInfo(args) => assert_eq!(args.path, "/tmp/disc"),
            other => panic!("expected BundleInfo, got {other:?}"),
        }
        match Cli::try_parse_from([
            "snowscsi",
            "bundle-create",
            "flat",
            "--dir",
            "/tmp/disc",
            "--size",
            "8M",
            "--sector",
            "2048",
        ])
        .unwrap()
        {
            Cli::BundleCreate(args) => match args.kind {
                BundleCreateKind::Flat(flat) => {
                    assert_eq!(flat.dir, "/tmp/disc");
                    assert_eq!(flat.size, "8M");
                    assert_eq!(flat.sector, 2048);
                }
                other => panic!("expected Flat, got {other:?}"),
            },
            other => panic!("expected BundleCreate, got {other:?}"),
        }
        match Cli::try_parse_from([
            "snowscsi",
            "bundle-create",
            "cdr",
            "--dir",
            "/tmp/cdr",
            "--medium",
            "cdrw80",
            "--slot",
            "16K",
        ])
        .unwrap()
        {
            Cli::BundleCreate(args) => match args.kind {
                BundleCreateKind::Cdr(cdr) => {
                    assert_eq!(cdr.dir, "/tmp/cdr");
                    assert_eq!(cdr.medium.as_deref(), Some("cdrw80"));
                    assert_eq!(cdr.slot.as_deref(), Some("16K"));
                }
                other => panic!("expected Cdr, got {other:?}"),
            },
            other => panic!("expected BundleCreate, got {other:?}"),
        }
    }

    #[test]
    fn dual_work_size_defaults_and_bounds() {
        // The dual default is the *total* of two equal banks, not the 1M
        // single-bank default.
        assert_eq!(DUAL_WORK_BUF_SIZE, 16384);
        assert_eq!(ISCSI_DUAL_WORK_BUF_SIZE, 16480);

        let args = parse_serve(&["--usb", "--banks", "dual"]);
        let cfg = resolve_config(&args).unwrap();
        assert_eq!(cfg.work_size, DUAL_WORK_BUF_SIZE);
        assert_eq!(cfg.per_bank(), 8192);

        let args = parse_serve(&["--usb", "--banks", "dual", "--work-buf-size", "32K"]);
        let cfg = resolve_config(&args).unwrap();
        assert_eq!(cfg.work_size, 32 * 1024);
        assert_eq!(cfg.per_bank(), 16 * 1024);

        // Two banks of MIN_DATA_AREA each is the floor (1024 total).
        assert_eq!(check_usb_dual_work_size(2 * MIN_DATA_AREA), Ok(()));
        assert_eq!(check_usb_dual_work_size(DUAL_WORK_BUF_SIZE), Ok(()));
        assert_eq!(check_usb_dual_work_size(2 * MIN_DATA_AREA + 2), Ok(()));
        // Each half must clear the 512-byte USB data-area floor.
        assert!(check_usb_dual_work_size(2 * MIN_DATA_AREA - 2).is_err());
        assert!(check_usb_dual_work_size(MIN_DATA_AREA).is_err());
        // The total must split evenly.
        assert!(check_usb_dual_work_size(DUAL_WORK_BUF_SIZE + 1).is_err());
        assert!(check_usb_dual_work_size(2 * MIN_DATA_AREA - 1).is_err());

        let args = parse_serve(&["--usb", "--banks", "dual", "--work-buf-size", "1023"]);
        assert!(resolve_config(&args).is_err(), "an odd total is rejected");
        let args = parse_serve(&["--usb", "--banks", "dual", "--work-buf-size", "1022"]);
        assert!(resolve_config(&args).is_err(), "a short half is rejected");
    }

    #[test]
    fn iscsi_dual_work_size_has_its_own_floor() {
        let args = parse_serve(&["--iscsi", "127.0.0.1:0", "--banks", "dual"]);
        let cfg = resolve_config(&args).unwrap();
        assert_eq!(cfg.work_size, ISCSI_DUAL_WORK_BUF_SIZE);
        assert_eq!(cfg.per_bank(), MIN_DATA_LEN + BHS_SIZE);

        assert_eq!(
            check_iscsi_dual_work_size(2 * (MIN_DATA_LEN + BHS_SIZE)),
            Ok(())
        );
        // One byte below the floor (odd and too short) is rejected.
        assert!(check_iscsi_dual_work_size(16479).is_err());
        assert!(check_iscsi_dual_work_size(16478).is_err());
        assert!(check_iscsi_dual_work_size(MIN_DATA_LEN + BHS_SIZE).is_err());
        // Each half's data area must be 4-aligned.
        assert!(check_iscsi_dual_work_size(16482).is_err());
        assert!(check_iscsi_dual_work_size(16484).is_err());
        assert_eq!(check_iscsi_dual_work_size(16488), Ok(()));
    }

    #[test]
    fn dual_conflicts_with_scratch_buffer() {
        // The dual banks live inside `work`, so a third scratch bank is
        // rejected instead of silently ignored.
        let args = parse_serve(&["--usb", "--banks", "dual", "--scratch-buffer"]);
        let err = check_banks(&args).expect_err("scratch + dual must be refused");
        assert!(
            err.contains("--scratch-buffer"),
            "message must name the conflicting flag: {err}"
        );
        assert!(resolve_config(&args).is_err());
        let args = parse_serve(&[
            "--iscsi",
            "127.0.0.1:0",
            "--banks",
            "dual",
            "--scratch-buffer",
        ]);
        assert!(resolve_config(&args).is_err());

        // `single` + scratch remains the split long-operation bank.
        let args = parse_serve(&["--usb", "--scratch-buffer"]);
        assert!(check_banks(&args).is_ok());
        let args = parse_serve(&["--iscsi", "127.0.0.1:0", "--scratch-buffer"]);
        assert!(check_banks(&args).is_ok());
    }

    #[test]
    fn async_wire_rejects_usb_before_binding() {
        // USB has no asynchronous endpoint adapter yet, so the combination is
        // refused for both feature sets.
        let args = parse_serve(&["--wire", "async", "--usb"]);
        assert_eq!(
            resolve_config(&args).unwrap_err(),
            "async USB is not implemented; use --wire blocking"
        );
    }

    #[cfg(feature = "tokio")]
    #[test]
    fn async_iscsi_resolves_and_prints_its_config() {
        let args = parse_serve(&["--iscsi", "127.0.0.1:0", "--wire", "async"]);
        let cfg = resolve_config(&args).unwrap();
        assert_eq!(cfg.wire, Wire::Async);
        assert_eq!(
            cfg.line(1, "ram", false),
            format!(
                "wire=async banks=single storage=inline per_bank={DEFAULT_WORK_BUF_SIZE} \
                 work={DEFAULT_WORK_BUF_SIZE} scratch=0 lun=1 backing=ram"
            )
        );

        let args = parse_serve(&[
            "--iscsi",
            "127.0.0.1:0",
            "--wire",
            "async",
            "--banks",
            "dual",
        ]);
        let cfg = resolve_config(&args).unwrap();
        assert_eq!(
            cfg.line(1, "ram", false),
            "wire=async banks=dual storage=worker per_bank=8240 work=16480 scratch=0 lun=1 \
             backing=ram"
        );

        // A RAM or file LUN can be driven by the library slot pool, so the
        // derived storage model becomes `pool` (same switches, same buffers).
        let specs = spec::parse_all(&args.block, &args.cdrom).unwrap();
        assert!(pool_capable(&specs, &cfg));
        assert_eq!(
            cfg.line(
                specs.len(),
                &backing_names(&specs),
                pool_capable(&specs, &cfg)
            ),
            "wire=async banks=dual storage=pool per_bank=8240 work=16480 scratch=0 lun=1 \
             backing=ram"
        );
    }

    #[cfg(not(feature = "tokio"))]
    #[test]
    fn async_without_the_tokio_feature_is_rejected() {
        let args = parse_serve(&["--iscsi", "127.0.0.1:0", "--wire", "async"]);
        let err = resolve_config(&args).expect_err("async needs the tokio binding");
        assert!(err.contains("rebuild with --features tokio"), "{err}");
    }

    #[test]
    fn single_work_size_uses_the_one_bank_default() {
        let args = parse_serve(&["--usb", "--work-buf-size", "511"]);
        assert!(resolve_config(&args).is_err(), "below the 512-byte floor");
        let args = parse_serve(&["--iscsi", "127.0.0.1:0", "--work-buf-size", "8240"]);
        assert_eq!(resolve_config(&args).unwrap().work_size, 8240);
        let args = parse_serve(&["--iscsi", "127.0.0.1:0", "--work-buf-size", "8241"]);
        assert!(resolve_config(&args).is_err(), "data area not 4-aligned");
    }

    #[test]
    fn work_size_minimums_are_transport_specific() {
        // iSCSI: MIN_DATA_LEN + BHS (the Login text must fit) and a 4-aligned
        // data area.
        assert_eq!(
            check_iscsi_work_size(MIN_DATA_LEN + BHS_SIZE),
            Ok(()),
            "8240 is the iSCSI floor"
        );
        assert!(
            check_iscsi_work_size(MIN_DATA_LEN + BHS_SIZE - 1).is_err(),
            "8239 cannot stage the Login text"
        );
        assert!(
            check_iscsi_work_size(560).is_err(),
            "a 560-byte bank is below the iSCSI floor"
        );
        assert!(
            check_iscsi_work_size(MIN_DATA_LEN + BHS_SIZE + 1).is_err(),
            "the iSCSI data area must be a multiple of 4"
        );

        // USB: the 512-byte data area needs neither a header prefix nor
        // alignment.
        assert_eq!(check_usb_work_size(MIN_DATA_AREA), Ok(()));
        assert!(check_usb_work_size(MIN_DATA_AREA - 1).is_err());
        assert_eq!(check_usb_work_size(513), Ok(()));

        // The split-mode bank keeps its own 8192-byte requirement.
        assert_eq!(scratch_size(MIN_DATA_AREA), MIN_DATA_LEN);
        assert_eq!(
            scratch_size(MIN_DATA_LEN + BHS_SIZE),
            MIN_DATA_LEN + BHS_SIZE
        );
        assert_eq!(scratch_size(DEFAULT_WORK_BUF_SIZE), DEFAULT_WORK_BUF_SIZE);
    }

    #[test]
    fn scratch_buffer_flag_selects_the_split_mode() {
        // Absent: no split bank at all, so the transports run in shared mode.
        assert_eq!(parse_scratch_size(None), Ok(None));
        assert!(split_bank(None).is_empty());

        // Present with a value: the split bank, rounded up to the floor.
        assert_eq!(parse_scratch_size(Some("512")), Ok(Some(MIN_DATA_LEN)));
        assert_eq!(parse_scratch_size(Some("16K")), Ok(Some(16 * 1024)));
        assert_eq!(split_bank(Some(16 * 1024)).len(), 16 * 1024);
        assert!(parse_scratch_size(Some("bogus")).is_err());

        // Present without a value: the 1M default.
        assert_eq!(parse_scratch_size(Some("1M")), Ok(Some(1024 * 1024)));
    }

    #[test]
    fn scratch_buffer_flag_is_optional_in_the_cli() {
        let base = [
            "snowscsi",
            "serve",
            "--block",
            "ram=1M",
            "--iscsi",
            "127.0.0.1:3260",
        ];
        let Cli::Serve(args) = Cli::try_parse_from(base).expect("parse") else {
            panic!("expected serve");
        };
        assert_eq!(args.scratch_buffer, None, "one buffer by default");

        let mut with = base.to_vec();
        with.push("--scratch-buffer");
        let Cli::Serve(args) = Cli::try_parse_from(with).expect("parse") else {
            panic!("expected serve");
        };
        assert_eq!(args.scratch_buffer.as_deref(), Some("1M"));
    }

    #[test]
    fn cli_accepts_multiple_block_and_cdrom_specs() {
        let cli = Cli::try_parse_from([
            "snowscsi",
            "serve",
            "--block",
            "ram=1M",
            "--block",
            "img=disk.img,ro",
            "--block",
            "img=boot.iso,profile=cd",
            "--cdrom",
            "img=boot.iso",
            "--cdrom",
            "live=tree",
            "--iscsi",
            "127.0.0.1:3260",
            "--work-buf-size",
            "256K",
            "--verbose",
        ])
        .unwrap();
        match cli {
            Cli::Serve(a) => {
                assert_eq!(
                    a.block,
                    vec![
                        "ram=1M".to_string(),
                        "img=disk.img,ro".to_string(),
                        "img=boot.iso,profile=cd".to_string()
                    ]
                );
                assert_eq!(
                    a.cdrom,
                    vec!["img=boot.iso".to_string(), "live=tree".to_string()]
                );
                assert_eq!(a.iscsi.as_deref(), Some("127.0.0.1:3260"));
                assert_eq!(a.work_buf_size.as_deref(), Some("256K"));
                assert_eq!(a.verbose, 1);
            }
            other => panic!("expected Serve, got {other:?}"),
        }
    }

    #[test]
    fn cli_rejects_removed_flags() {
        // `--disk` / `--cdblock` were removed in the device/backing split.
        assert!(Cli::try_parse_from(["snowscsi", "serve", "--disk", "ram=1M"]).is_err());
        assert!(Cli::try_parse_from(["snowscsi", "serve", "--cdblock", "x.iso"]).is_err());
    }

    #[test]
    fn cli_usb_transport_parses() {
        match Cli::try_parse_from(["snowscsi", "serve", "--usb", "--block", "ram=1M"]).unwrap() {
            Cli::Serve(a) => {
                // `--usb` without a value defaults to the `auto` selector.
                assert_eq!(a.usb.as_deref(), Some("auto"));
                assert_eq!(a.iscsi, None);
                assert_eq!(a.vid, 0x1209);
                assert_eq!(a.pid, 0x0001);
                assert_eq!(a.serial, "SNOWSCSI");
            }
            other => panic!("expected Serve, got {other:?}"),
        }
    }

    #[test]
    fn cli_rejects_both_transports() {
        // `--iscsi` + `--usb` are mutually exclusive (ArgGroup).
        assert!(
            Cli::try_parse_from(["snowscsi", "serve", "--usb", "--iscsi", "127.0.0.1:3260"])
                .is_err()
        );
    }

    #[test]
    fn cli_usb_shortfall_parses_and_defaults() {
        match Cli::try_parse_from([
            "snowscsi",
            "serve",
            "--usb",
            "--block",
            "ram=1M",
            "--usb-shortfall",
            "pad",
        ])
        .unwrap()
        {
            Cli::Serve(a) => assert_eq!(a.usb_shortfall, "pad"),
            other => panic!("expected Serve, got {other:?}"),
        }
        match Cli::try_parse_from(["snowscsi", "serve", "--usb", "--block", "ram=1M"]).unwrap() {
            Cli::Serve(a) => assert_eq!(a.usb_shortfall, "short"),
            other => panic!("expected Serve, got {other:?}"),
        }
    }

    #[test]
    fn cli_iscsi_auto_parses() {
        match Cli::try_parse_from(["snowscsi", "serve", "--iscsi", "auto", "--block", "ram=1M"])
            .unwrap()
        {
            Cli::Serve(a) => assert_eq!(a.iscsi.as_deref(), Some("auto")),
            other => panic!("expected Serve, got {other:?}"),
        }
    }

    #[test]
    fn cli_requires_a_transport() {
        // serve without `--iscsi`/`--usb` fails at parse time.
        assert!(Cli::try_parse_from(["snowscsi", "serve", "--block", "ram=1M"]).is_err());
    }

    #[test]
    fn cli_usb_descriptor_overrides() {
        match Cli::try_parse_from([
            "snowscsi",
            "serve",
            "--usb",
            "dummy_udc.0",
            "--vid",
            "1d6b",
            "--pid",
            "0105",
            "--serial",
            "SNOWSCSI-1",
        ])
        .unwrap()
        {
            Cli::Serve(a) => {
                assert_eq!(a.usb.as_deref(), Some("dummy_udc.0"));
                assert_eq!(a.vid, 0x1d6b);
                assert_eq!(a.pid, 0x0105);
                assert_eq!(a.serial, "SNOWSCSI-1");
            }
            other => panic!("expected Serve, got {other:?}"),
        }
    }

    #[test]
    fn cli_help_is_displayed() {
        match Cli::try_parse_from(["snowscsi", "--help"]) {
            Err(e) if e.kind() == clap::error::ErrorKind::DisplayHelp => {}
            other => panic!("expected DisplayHelp, got {other:?}"),
        }
    }

    #[test]
    fn cli_mkisofs_parses_positional_and_label() {
        match Cli::try_parse_from(["snowscsi", "mkisofs", "tree", "out.iso", "--label", "DISC"])
            .unwrap()
        {
            Cli::Mkisofs(a) => {
                assert_eq!(a.dir, "tree");
                assert_eq!(a.out, "out.iso");
                assert_eq!(a.label.as_deref(), Some("DISC"));
            }
            other => panic!("unexpected CLI: {other:?}"),
        }
    }

    #[test]
    fn cli_mkisofs_label_optional() {
        match Cli::try_parse_from(["snowscsi", "mkisofs", "tree", "out.iso"]).unwrap() {
            Cli::Mkisofs(a) => assert_eq!(a.label, None),
            other => panic!("unexpected CLI: {other:?}"),
        }
    }

    #[test]
    fn cli_mkisofs_requires_two_positionals() {
        assert!(Cli::try_parse_from(["snowscsi", "mkisofs", "tree"]).is_err());
        assert!(Cli::try_parse_from(["snowscsi", "mkisofs"]).is_err());
    }

    #[test]
    fn run_mkisofs_writes_whole_sectors() {
        let dir = std::env::temp_dir().join(format!("snowscsi_mkisofs_{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(dir.join("DATA.BIN"), vec![0x42u8; 2048]).unwrap();

        let out = std::env::temp_dir().join(format!("snowscsi_mkisofs_{}.iso", std::process::id()));
        let _ = std::fs::remove_file(&out);
        let args = MkisofsArgs {
            dir: dir.to_string_lossy().to_string(),
            out: out.to_string_lossy().to_string(),
            label: Some("TEST".to_string()),
            verbose: 0,
        };
        assert_eq!(run_mkisofs(args), ExitCode::SUCCESS);

        let meta = std::fs::metadata(&out).unwrap();
        assert_eq!(meta.len() % u64::from(ISO_SECTOR_SIZE), 0);
        assert!(meta.len() >= u64::from(ISO_SECTOR_SIZE) * 16);

        let bytes = std::fs::read(&out).unwrap();
        // PVD at sector 16: "CD001" at bytes 1..6 (ISO9660 signature).
        assert_eq!(&bytes[16 * 2048 + 1..16 * 2048 + 6], b"CD001");

        // The file data extent must carry the source content.
        assert!(bytes.windows(4).any(|w| w == [0x42, 0x42, 0x42, 0x42]));

        let _ = std::fs::remove_dir_all(&dir);
        let _ = std::fs::remove_file(&out);
    }

    #[test]
    fn run_mkisofs_missing_dir_fails() {
        let args = MkisofsArgs {
            dir: "/nonexistent/snowscsi-mkisofs".to_string(),
            out: "/tmp/out.iso".to_string(),
            label: None,
            verbose: 0,
        };
        assert_eq!(run_mkisofs(args), ExitCode::FAILURE);
    }

    // ── Cipher-bearing planes ───────────────────────────────────────────

    #[cfg(feature = "cipher")]
    fn cipher_key_file(tag: &str) -> std::path::PathBuf {
        let path = std::env::temp_dir().join(format!(
            "snowscsi_cli_key_{tag}_{}_{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_nanos())
                .unwrap_or(0)
        ));
        std::fs::write(&path, [0x11u8; 32]).expect("write key file");
        path
    }

    /// A keyslot-free cipher block, enough for `CliCipher::from_meta` tests
    /// that only exercise the stream cipher.
    #[cfg(feature = "cipher")]
    fn cipher_meta(
        alg: snowscsi::common::bundle::CipherAlg,
    ) -> snowscsi::common::bundle::CipherMeta {
        snowscsi::common::bundle::CipherMeta {
            cipher: alg,
            nonce: [0x5Au8; 8],
            key_id: [0u8; 8],
            slot: snowscsi::common::bundle::KeySlot {
                kdf: snowscsi::common::bundle::KdfKind::None,
                iterations: None,
                salt: [0u8; 16],
                wrap_nonce: [0u8; 8],
                wrapped_key: [0u8; 32],
                tag: [0u8; 16],
            },
        }
    }

    /// Build a real `kdf = none` keyslot for `key_bytes` and `kind`.
    #[cfg(feature = "cipher")]
    fn none_keyslot(
        alg: snowscsi::common::bundle::CipherAlg,
        kind: BundleKind,
        key_bytes: [u8; 32],
    ) -> snowscsi::common::bundle::CipherMeta {
        let credential = cipher::Credential::Key(
            snowscsi::common::cipher::CipherKey::from_bytes(&key_bytes).unwrap(),
        );
        let (meta, _vmk) = cipher::new_keyslot(
            alg,
            [0x5Au8; 8],
            snowscsi::common::bundle::KdfKind::None,
            None,
            &credential,
            &kind,
        )
        .unwrap();
        meta
    }

    #[cfg(feature = "cipher")]
    fn write_image_manifest(path: &Path, alg: snowscsi::common::bundle::CipherAlg) {
        let kind = BundleKind::Image {
            size: std::fs::metadata(path).unwrap().len(),
        };
        let meta = BundleMeta {
            kind,
            cipher: Some(none_keyslot(alg, kind, [0x11u8; 32])),
            has_crc: false,
        };
        std::fs::write(
            format!("{}{SIDECAR_SUFFIX}", path.display()),
            meta.encode().unwrap(),
        )
        .expect("write sidecar");
    }

    #[cfg(feature = "cipher")]
    #[test]
    fn cipher_plane_round_trips_over_an_image() {
        use snowscsi::common::seekable_storage::WritableFlatData;

        let image = temp_dir("cipher_image");
        std::fs::create_dir_all(&image).unwrap();
        let image = image.join("disk.img");
        std::fs::write(&image, vec![0u8; 4096]).unwrap();
        write_image_manifest(&image, snowscsi::common::bundle::CipherAlg::ChaCha20);
        let key = cipher_key_file("image");
        let key_arg = key.display().to_string();
        let specs = spec::parse_all(
            &[format!("img={},cipher,key={key_arg}", image.display())],
            &[],
        )
        .unwrap();
        let mut plane = open_plane_for(&specs[0], None).expect("cipher plane");
        assert!(matches!(plane, OwnedPlane::Cipher(_)));
        assert!(plane.is_writable());
        assert_eq!(plane.capacity(), 4096);
        assert_eq!(plane.sector_size(), None);

        let plain = [0xA5u8; 16];
        WritableFlatData::write_at(&mut plane, 512, &plain).unwrap();
        let mut out = [0u8; 16];
        FlatData::read_at(&mut plane, 512, &mut out).unwrap();
        assert_eq!(out, plain);

        // The file on disk holds ciphertext, not the plaintext.
        let raw = std::fs::read(&image).unwrap();
        assert_ne!(&raw[512..528], &plain);

        // A read-only spec still decrypts but refuses writes.
        let ro = spec::parse_all(
            &[format!("img={},cipher,key={key_arg},ro", image.display())],
            &[],
        )
        .unwrap();
        let mut plane = open_plane_for(&ro[0], None).expect("read-only cipher plane");
        assert!(!plane.is_writable());
        let mut out = [0u8; 16];
        FlatData::read_at(&mut plane, 512, &mut out).unwrap();
        assert_eq!(out, plain);
        assert_eq!(
            WritableFlatData::write_at(&mut plane, 512, &plain),
            Err(snowscsi::common::seekable_storage::StorageError::NotWritable)
        );

        let _ = std::fs::remove_file(&image);
        let _ = std::fs::remove_file(format!("{}{SIDECAR_SUFFIX}", image.display()));
        let _ = std::fs::remove_file(&key);
    }

    #[cfg(all(feature = "cipher", feature = "cdr-bundle"))]
    fn create_encrypted_cdr(tag: &str) -> (std::path::PathBuf, std::path::PathBuf) {
        let dir = temp_dir(tag);
        let password = std::path::PathBuf::from(format!("{}.pw", dir.display()));
        std::fs::write(&password, b"hunter2\n").expect("write password file");
        let created = create_cdr_bundle(CreateCdrArgs {
            dir: dir.display().to_string(),
            medium: None,
            slot: None,
            cipher: Some("chacha12".to_string()),
            iterations: Some(1_000),
            password_file: Some(password.display().to_string()),
            ..CreateCdrArgs::default()
        });
        assert_eq!(created, ExitCode::SUCCESS);
        (dir, password)
    }

    #[cfg(all(feature = "cipher", feature = "cdr-bundle"))]
    #[test]
    fn encrypted_cdr_bundle_encrypts_tracks_and_keeps_the_toc_plaintext() {
        use snowscsi::core::storage::{IoBuf, IoReq};
        use snowscsi::core::Direction;

        let (dir, password) = create_encrypted_cdr("cdr_cipher");
        let toc0_before = std::fs::read(dir.join("toc.0")).expect("initial TOC slot");
        let toc1_before = std::fs::read(dir.join("toc.1")).ok();
        assert!(
            toc0_before
                .windows(b"snow_cdr_bnd".len())
                .any(|w| w == b"snow_cdr_bnd"),
            "the TOC slot must stay a readable plaintext TOC"
        );

        let specs = spec::parse_all(&[], &[format!("bundle={},cipher", dir.display())]).unwrap();
        let mut plane = open_plane_for(&specs[0], Some(b"hunter2")).expect("encrypted CD-R plane");
        assert!(plane.is_cdr_bundle());

        let plain: Vec<u8> = (0..2048).map(|i| (i % 251) as u8).collect();
        let mut input = plain.clone();
        assert_eq!(
            plane.exec(
                IoReq {
                    resource: 17,
                    offset: 0,
                    len: 2048,
                    dir: Direction::FromHost,
                },
                IoBuf::Write(&mut input),
            ),
            Ok(2048)
        );
        let track_1 = std::fs::read(dir.join("track_1.bin")).expect("track file");
        assert_ne!(&track_1[..2048], &plain[..], "track must be ciphertext");

        let mut out = vec![0u8; 2048];
        assert_eq!(
            plane.exec(
                IoReq {
                    resource: 17,
                    offset: 0,
                    len: 2048,
                    dir: Direction::ToHost,
                },
                IoBuf::Read(&mut out),
            ),
            Ok(2048)
        );
        assert_eq!(out, plain, "the read must decrypt back to plaintext");

        // The TOC resources were never touched, byte for byte.
        assert_eq!(std::fs::read(dir.join("toc.0")).unwrap(), toc0_before);
        assert_eq!(std::fs::read(dir.join("toc.1")).ok(), toc1_before);

        // A second track at the same offset uses its own nonce domain.
        let mut second = plain.clone();
        assert_eq!(
            plane.exec(
                IoReq {
                    resource: 18,
                    offset: 0,
                    len: 2048,
                    dir: Direction::FromHost,
                },
                IoBuf::Write(&mut second),
            ),
            Ok(2048)
        );
        let track_2 = std::fs::read(dir.join("track_2.bin")).expect("second track file");
        assert_ne!(
            &track_2[..2048],
            &track_1[..2048],
            "two tracks at the same offset must not reuse the keystream"
        );
        assert_eq!(
            std::fs::read(dir.join("toc.0")).unwrap(),
            toc0_before,
            "a track write must not rewrite the TOC"
        );

        drop(plane);
        let _ = std::fs::remove_dir_all(&dir);
        let _ = std::fs::remove_file(&password);
    }

    #[cfg(all(feature = "cipher", feature = "cdr-bundle"))]
    #[test]
    fn encrypted_cdr_bundle_reopens_after_a_track_write() {
        use snowscsi::core::storage::{IoBuf, IoReq};
        use snowscsi::core::Direction;

        let (dir, password) = create_encrypted_cdr("cdr_cipher_reopen");
        let specs = spec::parse_all(&[], &[format!("bundle={},cipher", dir.display())]).unwrap();
        let plain: Vec<u8> = (0..4096).map(|i| (i % 241) as u8).collect();

        let mut plane = open_plane_for(&specs[0], Some(b"hunter2")).expect("encrypted CD-R plane");
        let mut input = plain.clone();
        assert_eq!(
            plane.exec(
                IoReq {
                    resource: 17,
                    offset: 0,
                    len: plain.len() as u32,
                    dir: Direction::FromHost,
                },
                IoBuf::Write(&mut input),
            ),
            Ok(plain.len())
        );
        drop(plane);

        let at_rest = std::fs::read(dir.join("track_1.bin")).expect("track file");
        assert_ne!(&at_rest[..plain.len()], &plain[..]);

        // Reopening through the real spec path resolves the manifest again
        // and must use the same key/nonce domain.
        let mut reopened =
            open_plane_for(&specs[0], Some(b"hunter2")).expect("reopened encrypted CD-R plane");
        let mut out = vec![0u8; plain.len()];
        assert_eq!(
            reopened.exec(
                IoReq {
                    resource: 17,
                    offset: 0,
                    len: plain.len() as u32,
                    dir: Direction::ToHost,
                },
                IoBuf::Read(&mut out),
            ),
            Ok(plain.len())
        );
        assert_eq!(out, plain);
        assert!(
            dir.join("toc.0").is_file(),
            "the TOC slot survives the reopen"
        );

        drop(reopened);
        let _ = std::fs::remove_dir_all(&dir);
        let _ = std::fs::remove_file(&password);
    }

    #[cfg(all(feature = "cipher", feature = "bundle"))]
    #[test]
    fn cipher_override_must_match_the_identified_bundle() {
        use snowscsi::common::bundle::KdfKind;
        use snowscsi::common::cipher::keyslot::{derive_kek, wrap_slot};
        use snowscsi::common::cipher::CipherKey;

        let dir = temp_dir("cipher_override");
        std::fs::create_dir_all(&dir).unwrap();
        let key = cipher_key_file("override");
        let key_bytes = [0x11u8; 32];
        let credential = cipher::Credential::Key(CipherKey::from_bytes(&key_bytes).unwrap());
        let kind = BundleKind::Flat {
            virtual_size: 8 << 20,
            chunk_size: 1 << 20,
            sector_size: 512,
        };
        let (identified_cipher, vmk) = cipher::new_keyslot(
            snowscsi::common::bundle::CipherAlg::Xor,
            [0x5Au8; 8],
            KdfKind::None,
            None,
            &credential,
            &kind,
        )
        .unwrap();
        let identified = BundleMeta {
            kind,
            cipher: Some(identified_cipher),
            has_crc: false,
        };
        let spec_for = |explicit: &Path| {
            spec::parse_all(
                &[format!(
                    "bundle={},cipher={},key={}",
                    dir.display(),
                    explicit.display(),
                    key.display()
                )],
                &[],
            )
            .unwrap()
            .remove(0)
        };
        let write = |name: &str, meta: &BundleMeta| {
            let path = dir.join(name);
            std::fs::write(&path, meta.encode().unwrap()).unwrap();
            path
        };

        // An equivalent manifest is accepted.
        let matching = write("matching", &identified);
        assert!(bundle_cipher(&spec_for(&matching), None, &identified, "identified").is_ok());

        // A rekeyed copy (same identity, fresh salt/wrap nonce/tag) is
        // accepted: the override owns the keyslot.
        let mut rekeyed_cipher = identified_cipher;
        rekeyed_cipher.slot.salt = [0xA1u8; 16];
        rekeyed_cipher.slot.wrap_nonce = [0xB2u8; 8];
        let kek = derive_kek(&rekeyed_cipher.slot, None, credential.key()).unwrap();
        wrap_slot(&kind, &mut rekeyed_cipher, &kek, &vmk).unwrap();
        let rekeyed = BundleMeta {
            cipher: Some(rekeyed_cipher),
            ..identified
        };
        let rekeyed_path = write("rekeyed", &rekeyed);
        assert!(
            bundle_cipher(&spec_for(&rekeyed_path), None, &identified, "identified").is_ok(),
            "a different keyslot wrapping the same VMK must be accepted"
        );

        // Geometry is part of the kind: a different flat size is refused.
        let mut geometry = identified;
        if let BundleKind::Flat { virtual_size, .. } = &mut geometry.kind {
            *virtual_size += 1;
        }
        let geometry_path = write("geometry", &geometry);
        assert!(bundle_cipher(&spec_for(&geometry_path), None, &identified, "identified").is_err());

        // A different kind (cdr instead of flat) is refused.
        let other_kind = BundleMeta {
            kind: BundleKind::Cdr,
            cipher: identified.cipher,
            has_crc: false,
        };
        let kind_path = write("kind", &other_kind);
        assert!(bundle_cipher(&spec_for(&kind_path), None, &identified, "identified").is_err());

        // A different nonce repeats a keystream on the same resources.
        let mut nonce = identified;
        if let Some(cipher) = nonce.cipher.as_mut() {
            cipher.nonce[0] ^= 0x01;
        }
        let nonce_path = write("nonce", &nonce);
        assert!(bundle_cipher(&spec_for(&nonce_path), None, &identified, "identified").is_err());

        // A different key id wraps a different VMK.
        let mut key_id = identified;
        if let Some(cipher) = key_id.cipher.as_mut() {
            cipher.key_id[0] ^= 0x01;
        }
        let key_id_path = write("key_id", &key_id);
        assert!(bundle_cipher(&spec_for(&key_id_path), None, &identified, "identified").is_err());

        // The identified manifest is authoritative: a cipher-less override
        // cannot rescue an encrypted one.
        let plain = BundleMeta {
            kind,
            cipher: None,
            has_crc: false,
        };
        let plain_path = write("plain", &plain);
        assert!(bundle_cipher(&spec_for(&plain_path), None, &identified, "identified").is_err());

        // An encrypted manifest without `,cipher` is never served plaintext.
        let no_cipher = spec::parse_all(&[format!("bundle={}", dir.display())], &[])
            .unwrap()
            .remove(0);
        assert!(bundle_cipher(&no_cipher, None, &identified, "identified").is_err());

        // A plaintext manifest with `,cipher` is refused too.
        let encrypted_spec = spec::parse_all(
            &[format!(
                "bundle={},cipher,key={}",
                dir.display(),
                key.display()
            )],
            &[],
        )
        .unwrap()
        .remove(0);
        assert!(bundle_cipher(&encrypted_spec, None, &plain, "identified").is_err());

        let _ = std::fs::remove_dir_all(&dir);
        let _ = std::fs::remove_file(&key);
    }

    #[cfg(all(feature = "cipher", feature = "cdr-bundle"))]
    #[test]
    fn encrypted_cdrw_bundle_is_refused_at_create_and_serve() {
        let key = cipher_key_file("cdrw");

        // Creation refuses a CD-RW preset with --cipher before making the
        // directory.
        let create_dir = temp_dir("cdrw_create");
        let created = create_cdr_bundle(CreateCdrArgs {
            dir: create_dir.display().to_string(),
            medium: Some("cdrw80".to_string()),
            slot: None,
            cipher: Some("xor".to_string()),
            key_file: Some(key.display().to_string()),
            ..CreateCdrArgs::default()
        });
        assert_eq!(created, ExitCode::FAILURE);
        assert!(
            !create_dir.exists(),
            "a refused encrypted CD-RW must not create the directory"
        );

        // Serving a stored CD-RW with a cipher manifest is refused after the
        // medium is opened (the TOC says cdrw, not cdr).
        let dir = temp_dir("cdrw_serve");
        let created = create_cdr_bundle(CreateCdrArgs {
            dir: dir.display().to_string(),
            medium: Some("cdrw80".to_string()),
            slot: None,
            ..CreateCdrArgs::default()
        });
        assert_eq!(created, ExitCode::SUCCESS);
        let kind = BundleKind::Cdr;
        let meta = BundleMeta {
            kind,
            cipher: Some(none_keyslot(
                snowscsi::common::bundle::CipherAlg::Xor,
                kind,
                [0x11u8; 32],
            )),
            has_crc: false,
        };
        std::fs::write(dir.join(MANIFEST_NAME), meta.encode().unwrap()).unwrap();
        let specs = spec::parse_all(
            &[],
            &[format!(
                "bundle={},cipher,key={}",
                dir.display(),
                key.display()
            )],
        )
        .unwrap();
        assert!(
            run_with_large_stack(move || {
                let mut planes = Vec::new();
                let mut slots = Vec::new();
                build_core_slots(&specs, &mut planes, &mut slots, None).is_err()
            }),
            "encrypted CD-RW must be refused by the CD-R slot builder"
        );

        let _ = std::fs::remove_dir_all(&dir);
        let _ = std::fs::remove_file(&key);
    }

    #[cfg(all(feature = "cipher", feature = "cdr-bundle"))]
    #[test]
    fn encrypted_cdr_bundle_requires_the_key_material() {
        let (dir, password) = create_encrypted_cdr("cdr_cipher_keys");
        let specs = spec::parse_all(&[], &[format!("bundle={},cipher", dir.display())]).unwrap();

        // PBKDF2 without a password is a hard error, never a plaintext fallback.
        assert!(open_plane_for(&specs[0], None).is_err());

        // kdf = none requires an explicit key= file.
        let meta = BundleMeta {
            kind: BundleKind::Cdr,
            cipher: Some(cipher_meta(snowscsi::common::bundle::CipherAlg::ChaCha12)),
            has_crc: false,
        };
        std::fs::write(dir.join(MANIFEST_NAME), meta.encode().unwrap()).unwrap();
        let specs = spec::parse_all(&[], &[format!("bundle={},cipher", dir.display())]).unwrap();
        assert!(open_plane_for(&specs[0], Some(b"hunter2")).is_err());

        // A wrong-length key file is rejected.
        let key = cipher_key_file("cdr_none");
        std::fs::write(&key, [0u8; 31]).unwrap();
        let specs = spec::parse_all(
            &[],
            &[format!(
                "bundle={},cipher,key={}",
                dir.display(),
                key.display()
            )],
        )
        .unwrap();
        assert!(open_plane_for(&specs[0], None).is_err());

        // A cipher-less manifest is never served plaintext.
        std::fs::write(
            dir.join(MANIFEST_NAME),
            BundleMeta {
                kind: BundleKind::Cdr,
                cipher: None,
                has_crc: false,
            }
            .encode()
            .unwrap(),
        )
        .unwrap();
        assert!(open_plane_for(&specs[0], None).is_err());

        let _ = std::fs::remove_dir_all(&dir);
        let _ = std::fs::remove_file(&password);
        let _ = std::fs::remove_file(&key);
    }

    #[cfg(all(feature = "cipher", feature = "cdr-bundle"))]
    #[test]
    fn encrypted_cdr_bundle_info_reports_cipher_and_toc() {
        let (dir, password) = create_encrypted_cdr("cdr_cipher_info");
        let manifest = std::fs::read_to_string(dir.join(MANIFEST_NAME)).unwrap();
        assert!(manifest.contains("cipher = chacha12"), "{manifest}");
        assert!(manifest.contains("kdf = pbkdf2-hmac-sha256"), "{manifest}");
        assert!(dir.join("toc.0").is_file(), "the TOC summary needs a slot");
        assert_eq!(
            run_bundle_info(BundleInfoArgs {
                path: dir.display().to_string()
            }),
            ExitCode::SUCCESS
        );

        let _ = std::fs::remove_dir_all(&dir);
        let _ = std::fs::remove_file(&password);
    }

    #[cfg(all(feature = "cipher", feature = "bundle"))]
    #[test]
    fn cipher_plane_delegates_the_flat_bundle_sector_size() {
        let dir = temp_dir("cipher_bundle");
        let created = create_flat_bundle(CreateFlatArgs {
            dir: dir.display().to_string(),
            size: "8M".to_string(),
            chunk: Some("1M".to_string()),
            sector: 2048,
            ..CreateFlatArgs::default()
        });
        assert_eq!(created, ExitCode::SUCCESS);
        let kind = BundleKind::Flat {
            virtual_size: 8 << 20,
            chunk_size: 1 << 20,
            sector_size: 2048,
        };
        let meta = BundleMeta {
            kind,
            cipher: Some(none_keyslot(
                snowscsi::common::bundle::CipherAlg::Xor,
                kind,
                [0x11u8; 32],
            )),
            has_crc: false,
        };
        std::fs::write(dir.join(MANIFEST_NAME), meta.encode().unwrap()).unwrap();
        let key = cipher_key_file("bundle");
        let specs = spec::parse_all(
            &[format!(
                "bundle={},cipher,key={}",
                dir.display(),
                key.display()
            )],
            &[],
        )
        .unwrap();
        let plane = open_plane_for(&specs[0], None).expect("cipher bundle plane");
        assert!(plane.is_writable());
        assert_eq!(plane.sector_size(), Some(2048));
        assert_eq!(plane.capacity(), 8 << 20);
        assert!(!plane.is_cdr_bundle());

        let _ = std::fs::remove_dir_all(&dir);
        let _ = std::fs::remove_file(&key);
    }

    #[cfg(all(feature = "cipher", feature = "bundle"))]
    #[test]
    fn encrypted_flat_bundle_round_trips_and_stores_ciphertext() {
        use snowscsi::common::seekable_storage::{FlatData, WritableFlatData};

        let dir = temp_dir("flat_cipher_e2e");
        std::fs::create_dir_all(&dir).unwrap();
        let password = dir.join("password.txt");
        std::fs::write(&password, b"hunter2\n").unwrap();
        let created = create_flat_bundle(CreateFlatArgs {
            dir: dir.display().to_string(),
            size: "8M".to_string(),
            chunk: Some("1M".to_string()),
            sector: 512,
            cipher: Some("chacha12".to_string()),
            iterations: Some(1_000),
            password_file: Some(password.display().to_string()),
            ..CreateFlatArgs::default()
        });
        assert_eq!(created, ExitCode::SUCCESS);

        let specs = spec::parse_all(&[format!("bundle={},cipher", dir.display())], &[]).unwrap();
        let plain: Vec<u8> = (0..4096).map(|i| (i % 251) as u8).collect();

        let mut plane = open_plane_for(&specs[0], Some(b"hunter2")).expect("encrypted flat plane");
        assert!(matches!(plane, OwnedPlane::Cipher(_)));
        WritableFlatData::write_at(&mut plane, 0, &plain).unwrap();
        let mut out = vec![0u8; plain.len()];
        FlatData::read_at(&mut plane, 0, &mut out).unwrap();
        assert_eq!(out, plain);
        drop(plane);

        let raw = std::fs::read(dir.join("000000.img")).expect("first chunk");
        assert_ne!(
            &raw[..plain.len()],
            &plain[..],
            "the chunk file must hold ciphertext, not plaintext"
        );

        // Drop and reopen through the same spec path: the manifest-derived
        // key/nonce domain must reproduce the plaintext.
        let mut reopened =
            open_plane_for(&specs[0], Some(b"hunter2")).expect("reopened encrypted flat plane");
        let mut out = vec![0u8; plain.len()];
        FlatData::read_at(&mut reopened, 0, &mut out).unwrap();
        assert_eq!(out, plain);

        drop(reopened);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[cfg(feature = "cipher")]
    #[test]
    fn cipher_plane_rejects_a_missing_sidecar_and_a_bad_key() {
        let dir = temp_dir("cipher_missing");
        std::fs::create_dir_all(&dir).unwrap();
        let image = dir.join("disk.img");
        std::fs::write(&image, vec![0u8; 4096]).unwrap();
        let key = cipher_key_file("missing");

        // No sidecar: never fall back to plaintext.
        let specs = spec::parse_all(
            &[format!(
                "img={},cipher,key={}",
                image.display(),
                key.display()
            )],
            &[],
        )
        .unwrap();
        assert!(build_planes(&specs, None).is_err());

        // A wrong-length key file is an error, not a truncated key.
        write_image_manifest(&image, snowscsi::common::bundle::CipherAlg::Xor);
        std::fs::write(&key, [0u8; 31]).unwrap();
        assert!(build_planes(&specs, None).is_err());

        // A manifest without a cipher block is never served plaintext.
        let plain = BundleMeta {
            kind: BundleKind::Image { size: 4096 },
            cipher: None,
            has_crc: false,
        };
        std::fs::write(
            format!("{}{SIDECAR_SUFFIX}", image.display()),
            plain.encode().unwrap(),
        )
        .unwrap();
        std::fs::write(&key, [0u8; 32]).unwrap();
        assert!(build_planes(&specs, None).is_err());

        let _ = std::fs::remove_dir_all(&dir);
        let _ = std::fs::remove_file(&key);
    }

    #[cfg(feature = "cipher")]
    #[test]
    fn prepare_cipher_requires_matching_encryption_state() {
        let dir = temp_dir("cipher_state");
        std::fs::create_dir_all(&dir).unwrap();
        let image = dir.join("disk.img");
        std::fs::write(&image, vec![0u8; 4096]).unwrap();
        let key = cipher_key_file("state");
        write_image_manifest(&image, snowscsi::common::bundle::CipherAlg::ChaCha20);

        // Encrypted manifest without `,cipher` is a hard error.
        let plain_spec = spec::parse_all(&[format!("img={}", image.display())], &[])
            .unwrap()
            .remove(0);
        assert!(prepare_cipher(&plain_spec, None).is_err());

        // With `,cipher` and the key file it unlocks.
        let encrypted_spec = spec::parse_all(
            &[format!(
                "img={},cipher,key={}",
                image.display(),
                key.display()
            )],
            &[],
        )
        .unwrap()
        .remove(0);
        assert!(prepare_cipher(&encrypted_spec, None).is_ok());

        // A plaintext manifest with `,cipher` is refused, not served plaintext.
        let plain = BundleMeta {
            kind: BundleKind::Image { size: 4096 },
            cipher: None,
            has_crc: true,
        };
        std::fs::write(
            format!("{}{SIDECAR_SUFFIX}", image.display()),
            plain.encode().unwrap(),
        )
        .unwrap();
        assert!(prepare_cipher(&encrypted_spec, None).is_err());

        // A plaintext manifest without `,cipher` serves plaintext.
        assert!(prepare_cipher(&plain_spec, None).is_ok());

        let _ = std::fs::remove_dir_all(&dir);
        let _ = std::fs::remove_file(&key);
    }

    #[cfg(all(feature = "cipher", feature = "bundle"))]
    #[test]
    fn wrong_password_fails_before_creating_flat_chunks() {
        let root = temp_dir("cipher_wrong_flat");
        std::fs::create_dir_all(&root).unwrap();
        let bundle = root.join("bundle");
        let password = root.join("pw");
        std::fs::write(&password, b"hunter2\n").unwrap();
        let created = create_flat_bundle(CreateFlatArgs {
            dir: bundle.display().to_string(),
            size: "8M".to_string(),
            chunk: Some("1M".to_string()),
            sector: 512,
            cipher: Some("chacha12".to_string()),
            iterations: Some(1_000),
            password_file: Some(password.display().to_string()),
            ..CreateFlatArgs::default()
        });
        assert_eq!(created, ExitCode::SUCCESS);
        assert!(!bundle.join("000000.img").exists());

        let specs = spec::parse_all(&[format!("bundle={},cipher", bundle.display())], &[]).unwrap();
        assert!(
            open_plane_for(&specs[0], Some(b"wrong password")).is_err(),
            "a wrong password must fail before the flat store opens any chunk"
        );
        assert!(
            !bundle.join("000000.img").exists(),
            "a failed unlock must not create chunk files"
        );
        assert!(open_plane_for(&specs[0], Some(b"hunter2")).is_ok());

        let _ = std::fs::remove_dir_all(&root);
    }

    #[cfg(feature = "cipher")]
    #[test]
    fn failed_sidecar_write_removes_the_new_image() {
        let dir = temp_dir("cipher_sidecar_fail");
        std::fs::create_dir_all(&dir).unwrap();
        let out = dir.join("out.img");
        std::fs::write(&out, b"ciphertext").unwrap();
        let sidecar = dir.join(format!("out.img{SIDECAR_SUFFIX}"));
        // A directory at the sidecar path makes the final rename fail after
        // the temp was written.
        std::fs::create_dir_all(&sidecar).unwrap();

        let err = crypt_commit_sidecar(
            &out.display().to_string(),
            &sidecar.display().to_string(),
            b"manifest",
        )
        .unwrap_err();
        assert!(err.contains("removed the newly written"), "{err}");
        assert!(!out.exists(), "the orphan ciphertext must be removed");
        assert!(sidecar.is_dir(), "the pre-existing path is not replaced");
        assert!(
            std::fs::read_dir(&dir)
                .unwrap()
                .flatten()
                .all(|entry| !entry.file_name().to_string_lossy().contains(".tmp.")),
            "no temporary file is left behind"
        );

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[cfg(feature = "cipher")]
    #[test]
    fn cipher_manifest_bound_is_768() {
        assert_eq!(MAX_MANIFEST, 768);
        let kind = BundleKind::Flat {
            virtual_size: u64::MAX,
            chunk_size: u64::MAX,
            sector_size: 2048,
        };
        // The longest legal block: PBKDF2, maximum iterations and every
        // field at its widest. No derivation is needed to test the bound.
        let cipher_meta = CipherMeta {
            cipher: CipherAlg::ChaCha12,
            nonce: [0xFFu8; 8],
            key_id: [0xFFu8; 8],
            slot: snowscsi::common::bundle::KeySlot {
                kdf: KdfKind::Pbkdf2HmacSha256,
                iterations: Some(2_000_000),
                salt: [0xFFu8; 16],
                wrap_nonce: [0xFFu8; 8],
                wrapped_key: [0xFFu8; 32],
                tag: [0xFFu8; 16],
            },
        };
        let meta = BundleMeta {
            kind,
            cipher: Some(cipher_meta),
            has_crc: false,
        };
        let encoded = meta.encode().unwrap();
        assert!(encoded.len() <= MAX_MANIFEST);
        assert!(BundleMeta::parse(&encoded).is_ok());

        let mut too_large = vec![b' '; MAX_MANIFEST];
        too_large.push(b'\n');
        assert_eq!(
            BundleMeta::parse(&too_large),
            Err(snowscsi::common::bundle::ManifestError::TooLarge)
        );
    }

    #[cfg(feature = "cipher")]
    #[test]
    fn cipher_print_config_does_not_read_a_password() {
        let dir = temp_dir("cipher_print");
        std::fs::create_dir_all(&dir).unwrap();
        let image = dir.join("disk.img");
        std::fs::write(&image, vec![0u8; 4096]).unwrap();
        let password = dir.join("password.txt");
        std::fs::write(&password, b"hunter2\n").unwrap();

        let Cli::Serve(args) = Cli::try_parse_from([
            "snowscsi",
            "serve",
            "--block",
            &format!("img={},cipher", image.display()),
            "--password-file",
            &password.display().to_string(),
            "--usb",
            "--print-config",
        ])
        .expect("parse serve") else {
            panic!("expected serve");
        };
        // The early return happens before any prompt: no TTY is required.
        assert_eq!(run_serve(args), ExitCode::SUCCESS);

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[cfg(feature = "cipher")]
    #[test]
    fn password_file_is_capped_and_stripped() {
        let dir = temp_dir("cipher_password");
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("pw");
        std::fs::write(&path, b"secret\r\n").unwrap();
        assert_eq!(
            read_password_file(&path.display().to_string()).unwrap(),
            b"secret"
        );

        std::fs::write(&path, b"\n").unwrap();
        assert!(read_password_file(&path.display().to_string()).is_err());
        std::fs::write(&path, b"a\0b").unwrap();
        assert!(read_password_file(&path.display().to_string()).is_err());
        // More than one line is rejected instead of silently becoming a
        // password with an embedded newline.
        std::fs::write(&path, b"first\nsecond\n").unwrap();
        assert!(read_password_file(&path.display().to_string()).is_err());
        std::fs::write(&path, b"secret\n\n").unwrap();
        assert!(read_password_file(&path.display().to_string()).is_err());
        std::fs::write(&path, vec![b'x'; MAX_PASSWORD + 2]).unwrap();
        assert!(read_password_file(&path.display().to_string()).is_err());

        // A full-length password followed by CRLF is accepted (the two extra
        // bytes are read so the CRLF can be stripped), while a line one byte
        // over the cap is rejected.
        let mut max_crlf = vec![b'x'; MAX_PASSWORD];
        max_crlf.extend_from_slice(b"\r\n");
        std::fs::write(&path, &max_crlf).unwrap();
        let read = read_password_file(&path.display().to_string()).unwrap();
        assert_eq!(read.len(), MAX_PASSWORD);
        let mut one_over = vec![b'x'; MAX_PASSWORD + 1];
        one_over.push(b'\n');
        std::fs::write(&path, &one_over).unwrap();
        assert!(read_password_file(&path.display().to_string()).is_err());

        // `--password-file` without an encrypted LUN is a configuration error.
        let specs = spec::parse_all(&["ram=1M".to_string()], &[]).unwrap();
        let args = parse_serve(&["--usb", "--password-file", "/tmp/unused"]);
        assert!(read_serve_password(&args, &specs).is_err());

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[cfg(all(unix, feature = "cipher"))]
    #[test]
    fn crypt_rejects_a_symlink_input_out_of_place_and_in_place() {
        let dir = temp_dir("crypt_symlink");
        std::fs::create_dir_all(&dir).unwrap();
        let target = dir.join("real.img");
        std::fs::write(&target, b"plaintext").unwrap();
        let link = dir.join("link.img");
        std::os::unix::fs::symlink(&target, &link).unwrap();
        let key = cipher_key_file("symlink");

        let input = link.display().to_string();
        let err = crypt_run(CryptArgs {
            decrypt: false,
            cipher: Some("xor".to_string()),
            password_file: None,
            key_file: Some(key.display().to_string()),
            iterations: None,
            in_place: false,
            force: false,
            input: input.clone(),
            output: Some(dir.join("out.img").display().to_string()),
        })
        .unwrap_err();
        assert!(err.contains("symbolic link"), "{err}");

        let err = crypt_run(CryptArgs {
            decrypt: false,
            cipher: Some("xor".to_string()),
            password_file: None,
            key_file: Some(key.display().to_string()),
            iterations: None,
            in_place: true,
            force: false,
            input,
            output: None,
        })
        .unwrap_err();
        assert!(err.contains("symbolic link"), "{err}");

        let _ = std::fs::remove_dir_all(&dir);
        let _ = std::fs::remove_file(&key);
    }

    #[cfg(feature = "cipher")]
    #[test]
    fn crypt_file_matches_a_one_shot_cipher_past_two_chunks() {
        use snowscsi::common::cipher::{CipherKey, StreamCipher as _};

        let dir = temp_dir("cipher_chunks");
        std::fs::create_dir_all(&dir).unwrap();
        let len = CRYPT_CHUNK * 2 + 12_345;
        let plain: Vec<u8> = (0..len)
            .map(|i| (i as u64).wrapping_mul(31).wrapping_add(7) as u8)
            .collect();
        let key = CipherKey::from_bytes(&[0x42u8; 32]).unwrap();

        for alg in [
            CipherAlg::ChaCha8,
            CipherAlg::ChaCha12,
            CipherAlg::ChaCha20,
            CipherAlg::AesCtr,
            CipherAlg::Xor,
        ] {
            let meta = cipher_meta(alg);
            let input = dir.join(format!("{alg:?}.in"));
            let output = dir.join(format!("{alg:?}.out"));
            std::fs::write(&input, &plain).unwrap();

            let cipher = cipher::CliCipher::from_meta(&meta, &key).unwrap();
            let processed =
                crypt_file(input.to_str().unwrap(), output.to_str().unwrap(), cipher).unwrap();
            assert_eq!(processed as usize, len, "{alg:?} byte count");

            let mut expected = plain.clone();
            let mut one_shot = cipher::CliCipher::from_meta(&meta, &key).unwrap();
            one_shot.xor(0, &mut expected).unwrap();
            assert_eq!(
                std::fs::read(&output).unwrap(),
                expected,
                "{alg:?} must use absolute offsets across chunk boundaries"
            );

            std::fs::remove_file(&input).unwrap();
            std::fs::remove_file(&output).unwrap();
        }
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[cfg(all(feature = "tokio", feature = "cipher"))]
    #[test]
    fn supports_async_recurses_through_cipher_wrappers() {
        use snowscsi::common::cipher::CipherPlane;

        run_with_large_stack(|| {
            let key = snowscsi::common::cipher::CipherKey::from_bytes(&[0x33u8; 32]).unwrap();
            let meta = cipher_meta(snowscsi::common::bundle::CipherAlg::Xor);
            let wrap = |plane| {
                OwnedPlane::Cipher(Box::new(CipherPlane::new(
                    plane,
                    cipher::CliCipher::from_meta(&meta, &key).unwrap(),
                )))
            };

            let ram = wrap(OwnedPlane::Ram {
                bytes: vec![0u8; 1024],
                writable: true,
            });
            assert!(supports_async(&[Some(ram)]));

            let dir = temp_dir("cipher_async_file");
            std::fs::create_dir_all(&dir).unwrap();
            let image = dir.join("disk.img");
            std::fs::write(&image, vec![0u8; 4096]).unwrap();
            let file = FileBackend::open(&image.display().to_string(), true).unwrap();
            assert!(supports_async(&[Some(wrap(OwnedPlane::BlockRw(file)))]));
            let _ = std::fs::remove_dir_all(&dir);

            let dir = temp_dir("cipher_async_live");
            std::fs::create_dir_all(&dir).unwrap();
            let live = snowscsi::cdrom::media::LiveData::new(
                StdFsBackend::new(&dir.display().to_string()),
                "LIVE",
            )
            .unwrap();
            assert!(!supports_async(&[Some(wrap(OwnedPlane::Live(live)))]));
            let _ = std::fs::remove_dir_all(&dir);

            #[cfg(feature = "bundle")]
            {
                let dir = temp_dir("cipher_async_bundle");
                let created = create_flat_bundle(CreateFlatArgs {
                    dir: dir.display().to_string(),
                    size: "8M".to_string(),
                    chunk: Some("1M".to_string()),
                    sector: 512,
                    ..CreateFlatArgs::default()
                });
                assert_eq!(created, ExitCode::SUCCESS);
                let bundle = FlatBundle::open(
                    StdFsBackend::new(&dir.display().to_string()),
                    None,
                    None,
                    None,
                )
                .unwrap();
                assert!(!supports_async(&[Some(wrap(OwnedPlane::Bundle(bundle)))]));
                let _ = std::fs::remove_dir_all(&dir);
            }
        });
    }

    #[cfg(all(feature = "tokio", feature = "cipher"))]
    #[test]
    fn async_backend_applies_and_removes_the_cipher() {
        use snowscsi::common::cipher::CipherPlane;

        let key = snowscsi::common::cipher::CipherKey::from_bytes(&[0x44u8; 32]).unwrap();
        let meta = cipher_meta(snowscsi::common::bundle::CipherAlg::AesCtr);
        let cipher = cipher::CliCipher::from_meta(&meta, &key).unwrap();
        let plane = OwnedPlane::Cipher(Box::new(CipherPlane::new(
            OwnedPlane::Ram {
                bytes: vec![0u8; 1024],
                writable: true,
            },
            cipher,
        )));
        let mut backends = AsyncBackends::new(vec![Some(plane)]);
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .expect("runtime");

        runtime.block_on(async {
            let plain = [0x5Au8; 32];
            let mut data = plain;
            assert_eq!(
                backends
                    .exec(
                        0,
                        IoReq {
                            resource: 0,
                            offset: 100,
                            len: 32,
                            dir: Direction::FromHost,
                        },
                        &mut data,
                    )
                    .await,
                Ok(32)
            );
            // The RAM plane holds ciphertext.
            match backends.luns[0].as_ref().unwrap() {
                AsyncPlane::Mem { bytes, .. } => assert_ne!(&bytes[100..132], &plain),
                AsyncPlane::File { .. } => panic!("expected a RAM plane"),
            }

            let mut out = [0u8; 32];
            assert_eq!(
                backends
                    .exec(
                        0,
                        IoReq {
                            resource: 0,
                            offset: 100,
                            len: 32,
                            dir: Direction::ToHost,
                        },
                        &mut out,
                    )
                    .await,
                Ok(32)
            );
            assert_eq!(out, plain);
        });
    }
    /// The async storage path end to end: a `SlotPool` in one Tokio task
    /// (`!Send`, no thread) driving [`AsyncBackends`] through the same
    /// `Storage`/`AsyncWake` contract the wire side uses.
    #[cfg(feature = "tokio")]
    #[test]
    fn async_backend_serves_io_through_the_slot_pool() {
        use snowscsi::core::storage::{IoBuf, Storage};

        let path = std::env::temp_dir().join(format!("snowscsi_pool_{}.img", std::process::id()));
        std::fs::write(&path, [0u8; 4096]).expect("create image");
        let backend = FileBackend::open(&path.to_string_lossy(), true).expect("open image");
        let planes = vec![Some(OwnedPlane::BlockRw(backend))];
        assert!(supports_async(&planes));

        let pool = SlotPool::new(vec![0u8; 1024]);
        let (mut store, task) = pool.split();
        let mut backends = AsyncBackends::new(planes);
        let runtime = tokio::runtime::Builder::new_multi_thread()
            .enable_all()
            .build()
            .expect("runtime");

        runtime.block_on(async {
            let client = async {
                // One writable chunk, staged into the pool by `poll_exec`.
                let write = store.begin_exec(IoReq {
                    resource: 0,
                    offset: 512,
                    len: 4,
                    dir: Direction::FromHost,
                });
                let mut data = [7u8; 4];
                loop {
                    match store.poll_exec(write, IoBuf::Write(&mut data)) {
                        std::task::Poll::Ready(receipt) => {
                            assert_eq!(receipt.error, None);
                            assert_eq!(receipt.confirmed, 4);
                            break;
                        }
                        std::task::Poll::Pending => {
                            snowscsi::core::async_wake::wait(&mut store).await;
                        }
                    }
                }

                // Read it back through the same pool.
                let read = store.begin_exec(IoReq {
                    resource: 0,
                    offset: 512,
                    len: 4,
                    dir: Direction::ToHost,
                });
                let mut out = [0u8; 4];
                loop {
                    match store.poll_exec(read, IoBuf::Read(&mut out)) {
                        std::task::Poll::Ready(receipt) => {
                            assert_eq!(receipt.error, None);
                            break;
                        }
                        std::task::Poll::Pending => {
                            snowscsi::core::async_wake::wait(&mut store).await;
                        }
                    }
                }
                out
            };

            let mut serve = core::pin::pin!(client);
            let mut backend = core::pin::pin!(drive_async_backend(&mut backends, &task));
            tokio::select! {
                out = &mut serve => out,
                () = &mut backend => unreachable!("the storage backend runs forever"),
            }
        });

        let bytes = std::fs::read(&path).expect("read image");
        assert_eq!(&bytes[512..516], &[7u8; 4], "the write reached the file");
        let _ = std::fs::remove_file(&path);
    }
}
