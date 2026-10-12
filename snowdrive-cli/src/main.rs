#![forbid(unsafe_code)]
//! `snowdrive` CLI — SnowDrive SCSI target and ISO9660 image tools
//! (`snowdrive_main.c`).
//!
//! Subcommands:
//! - `serve`: run the iSCSI target (serial accept loop)
//! - `mkisofs`: generate an ISO9660/Joliet image from a host directory
//!   (the live-generation algorithm, dumped sector-by-sector to a file)
//!
//! Devices are declared with two repeatable flags sharing one grammar
//! (`<backing>[=<value>][,<option>...]`): `--block` and `--cdrom`.
//!
//! - `--block` drives `BlockDevice`: `img=<file>[,ro]`,
//!   `imgdir=<dir>[,chunk=…][,size=…][,sector=…][,ro]` (directory-chunked
//!   disk, `bundle` feature), `ram=<size>` (K/M/G suffixes), or a
//!   `profile=cd` optical variant (read-only PDT 0x05, 2048 B sectors).
//! - `--cdrom` drives `CdromDrive` (full MMC): `img=<iso>`, `live=<dir>`
//!   (live ISO9660 over a directory), or
//!   `udfrw=<path|ram:<size>>[,size=…][,mkfs]` (random-writable DVD-RAM;
//!   `size=` creates a new file and writes the volume structure, `mkfs`
//!   forces a fresh UDF volume).
//!
//! All backing keys are explicit — there is no bare-value or suffix
//! auto-typing. Unknown or duplicate options are rejected. LUN numbering is
//! all `--block` devices first, then all `--cdrom` devices (the two planes
//! cannot interleave). The same host path may appear on several LUNs; each
//! is an independent SCSI device with its own LBA semantics, so a dual-mount
//! warning is printed to stderr. SIGINT / SIGTERM trigger a graceful
//! shutdown: the blocking `accept()` is woken by a probe connection,
//! `serve()` returns, and every backend is `sync()`ed before exit.

mod spec;

use std::fs::File;
use std::io::{BufWriter, Write};
use std::net::{SocketAddr, TcpListener};
use std::path::Path;
use std::process::{Command, ExitCode};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::thread::JoinHandle;
use std::time::Duration;

use clap::{Args, Parser};
use snowdrive_scsi::cdrom::drive::CdromDrive;
use snowdrive_scsi::cdrom::media::{CdMedia, FlatMedia, LiveData};
#[cfg(feature = "udfrw")]
use snowdrive_scsi::cdrom::udfrw::{OpenMode, UdfRwMedia, UdfRwOptions};
use snowdrive_scsi::common::flat_bundle::FlatBundle;
#[cfg(feature = "bundle")]
use snowdrive_scsi::common::fs_storage::OpenOptions;
use snowdrive_scsi::common::seekable_storage::RwRef;
use snowdrive_scsi::iscsi::transport::{serve, DEFAULT_READ_TIMEOUT};
use snowdrive_scsi::scsi::backend::{BlockBackend, FileBackend, RamBackend, SeekableStorage};
use snowdrive_scsi::scsi::block::BlockDevice;
use snowdrive_scsi::scsi::device::ScsiDevice;
use snowdrive_scsi::scsi::fs_backend::{FsStorage, StdFsBackend};
use snowdrive_scsi::MIN_DATA_LEN;
use spec::{Backing, DeviceRole, DeviceSpec};

#[cfg(target_os = "linux")]
use snowdrive_scsi::usb::{
    BotIo, BotIoErr, BotSession, BotStepResult, CtrlAck, CtrlReply, CtrlReq, Gadget, SessionEvent,
    SessionNeed, SessionStep, ShortfallPolicy,
};
#[cfg(target_os = "linux")]
use usb_gadget::function::custom::{
    CtrlReceiver, CtrlSender, Custom, Endpoint, EndpointDirection, EndpointReceiver,
    EndpointSender, Event, Interface,
};
#[cfg(target_os = "linux")]
use usb_gadget::{udcs, Class, Config, Gadget as UsbGadget, Id, Strings, Udc};

/// Default work buffer size (256 KiB).
const DEFAULT_WORK_BUF_SIZE: usize = 256 * 1024;
/// Sector size for block devices exposed by the CLI (like the C CLI).
const SECTOR_SIZE: u32 = 512;
/// CD-ROM logical sector size (Mode 1 data).
const ISO_SECTOR_SIZE: u32 = 2048;
/// Serve loop re-checks the control pipe / stop flag at this granularity
/// (bounds Bulk-Only Reset / Get Max LUN response latency, §6.3).
#[cfg(target_os = "linux")]
const BOT_POLL_GRANULARITY: Duration = Duration::from_millis(50);

/// USB bulk endpoint maximum packet size (high-speed). FunctionFS aio reads
/// require an MPS-multiple buffer (§6.2 / §1.4).
#[cfg(target_os = "linux")]
const USB_MPS: usize = 512;

/// Round `n` up to the next multiple of the USB bulk MPS (minimum one MPS).
#[cfg(target_os = "linux")]
fn round_up_mps(n: usize) -> usize {
    (n + USB_MPS - 1) & !(USB_MPS - 1)
}

#[derive(Debug, Parser)]
#[command(
    name = "snowdrive",
    about = "SnowDrive SCSI target and ISO9660 tools",
    version
)]
enum Cli {
    /// Start the iSCSI target server
    Serve(ServeArgs),
    /// Generate an ISO9660/Joliet image from a directory
    Mkisofs(MkisofsArgs),
}

#[derive(Args, Debug)]
#[command(group = clap::ArgGroup::new("transport").required(true).multiple(false))]
struct ServeArgs {
    /// Block device (`BlockDevice`): `img=<file>[,ro]`, `ram=<size>`,
    /// `imgdir=<dir>[,chunk=…][,size=…][,sector=…][,ro]` (directory-chunked
    /// disk), or `img=<file>,profile=cd` (read-only optical profile).
    /// Repeatable; `--block` LUNs come first in declaration order.
    #[arg(long = "block", value_name = "SPEC")]
    block: Vec<String>,

    /// CD-ROM device (`CdromDrive`, full MMC): `img=<iso>`, `live=<dir>`
    /// (live ISO9660 over a directory), or `udfrw=<path|ram:<size>>[,size=…][,mkfs]`
    /// (random-writable DVD-RAM). Repeatable; these LUNs follow the `--block` LUNs.
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

    /// Work buffer size in bytes (accepts K/M/G suffixes; default 256K).
    #[arg(long = "work-buf-size", value_name = "BYTES")]
    work_buf_size: Option<String>,
}

/// Arguments for `snowdrive mkisofs`: build an ISO9660/Joliet image from a
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

fn main() -> ExitCode {
    match Cli::parse() {
        Cli::Serve(args) => run_serve(args),
        Cli::Mkisofs(args) => run_mkisofs(args),
    }
}

fn run_serve(args: ServeArgs) -> ExitCode {
    init_logging(args.verbose);

    let work_size = match parse_work_size(args.work_buf_size.as_deref()) {
        Ok(n) => n,
        Err(msg) => {
            eprintln!("snowdrive: {msg}");
            return ExitCode::FAILURE;
        }
    };

    // The device pipeline is shared by both transports: parse the specs,
    // validate sources, allocate RAM disks and build the LUN list.
    let specs = match spec::parse_all(&args.block, &args.cdrom) {
        Ok(s) => s,
        Err(msg) => {
            eprintln!("snowdrive: {msg}");
            return ExitCode::FAILURE;
        }
    };
    let mut ram_disks: Vec<Vec<u8>> = Vec::new();
    let mut backends: Vec<BlockBackend> = Vec::new();
    let mut lives: Vec<LiveData<StdFsBackend>> = Vec::new();
    let mut bundles: Vec<FlatBundle<StdFsBackend>> = Vec::new();
    let mut disks: Vec<BlockDevice<RwRef>> = Vec::new();
    let mut drives: Vec<CdromDrive> = Vec::new();
    if build_devices(
        &specs,
        &mut ram_disks,
        &mut backends,
        &mut lives,
        &mut bundles,
        &mut disks,
        &mut drives,
    )
    .is_err()
    {
        return ExitCode::FAILURE;
    }
    // LUN array in protocol order: all --block LUNs, then all --cdrom LUNs.
    let mut luns: Vec<&mut dyn ScsiDevice> = disks
        .iter_mut()
        .map(|d| d as &mut dyn ScsiDevice)
        .chain(drives.iter_mut().map(|d| d as &mut dyn ScsiDevice))
        .collect();

    if let Some(selector) = args.usb.as_deref() {
        #[cfg(target_os = "linux")]
        {
            return run_serve_usb(&args, &mut luns, work_size, selector);
        }
        #[cfg(not(target_os = "linux"))]
        {
            eprintln!("snowdrive: --usb is only supported on Linux");
            return ExitCode::FAILURE;
        }
    }

    // iSCSI transport: the ArgGroup guarantees --iscsi when --usb is absent.
    let is_auto = args.iscsi.as_deref() == Some("auto");
    let (listener, bound) = if is_auto {
        match bind_iscsi_auto() {
            Ok(v) => v,
            Err(msg) => {
                eprintln!("snowdrive: {msg}");
                return ExitCode::FAILURE;
            }
        }
    } else {
        let addr = match args.iscsi.as_deref() {
            None => {
                eprintln!("snowdrive: --iscsi is required");
                return ExitCode::FAILURE;
            }
            Some(s) => match s.parse::<SocketAddr>() {
                Ok(a) => a,
                Err(_) => {
                    eprintln!("snowdrive: invalid --iscsi address: {s}");
                    return ExitCode::FAILURE;
                }
            },
        };
        let listener = match TcpListener::bind(addr) {
            Ok(l) => l,
            Err(e) => {
                eprintln!("snowdrive: failed to bind {addr}: {e}");
                return ExitCode::FAILURE;
            }
        };
        let bound = listener.local_addr().unwrap_or(addr);
        (listener, bound)
    };

    // Graceful shutdown: SIGINT/SIGTERM set `stop`;
    // a probe connection wakes the blocking accept() so serve() can observe
    // it and return (transport serves one connection at a time).
    let stop = Arc::new(AtomicBool::new(false));
    {
        let stop = Arc::clone(&stop);
        let probe = listener.local_addr().ok();
        if let Err(e) = ctrlc::set_handler(move || {
            stop.store(true, Ordering::SeqCst);
            if let Some(addr) = probe {
                let _ = std::net::TcpStream::connect(addr);
            }
        }) {
            eprintln!("snowdrive: failed to install signal handler: {e}");
            return ExitCode::FAILURE;
        }
    }

    let mut work = vec![0u8; work_size];
    // Report the actual bound address: `--iscsi 127.0.0.1:0` picks an
    // ephemeral port, so callers (tests) must learn it from this line.
    log::info!("listening on {bound} with {} LUN(s)", luns.len());

    // Auto-config: use open-iscsi to log in and expose a block device.
    // Runs in a helper thread so the blocking `serve` loop can start
    // accepting immediately.
    let auto_handle = if is_auto {
        spawn_iscsi_auto_helper(bound, Arc::clone(&stop))
    } else {
        None
    };

    let serve_res = serve(
        listener,
        &stop,
        &mut work,
        &mut luns,
        Some(DEFAULT_READ_TIMEOUT),
    );

    // Tear down the auto-config session (logout, delete node, SELinux).
    if let Some(handle) = auto_handle {
        // Wake the helper if it is still waiting for the device.
        stop.store(true, Ordering::SeqCst);
        let _ = handle.join();
        teardown_iscsi_auto(bound);
    }

    if let Err(e) = serve_res {
        eprintln!("snowdrive: server error: {e}");
        return ExitCode::FAILURE;
    }

    // Graceful exit: flush backends.
    sync_devices(&mut luns);
    log::info!("shutting down");
    ExitCode::SUCCESS
}

/// Flush every backend; errors are reported to stderr but not fatal.
fn sync_devices(luns: &mut [&mut dyn ScsiDevice]) {
    for (i, lun) in luns.iter_mut().enumerate() {
        if let Err(e) = ScsiDevice::sync(lun) {
            eprintln!("snowdrive: sync failed for LUN {i}: {e}");
        }
    }
}

// ── iSCSI auto-config (open-iscsi) ─────────────────────────────────────

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
                        return true;
                    }
                }
            }
        }
    }
    false
}

fn is_root() -> bool {
    // Cheap check via `id -u` to avoid a libc dependency.
    if let Ok(o) = Command::new("id").arg("-u").output() {
        if o.status.success() {
            return String::from_utf8_lossy(&o.stdout).trim() == "0";
        }
    }
    false
}

fn selinux_enforcing() -> bool {
    if !have_tool("getenforce") {
        return false;
    }
    match Command::new("getenforce").output() {
        Ok(o) => o.status.success() && String::from_utf8_lossy(&o.stdout).trim() == "Enforcing",
        Err(_) => false,
    }
}

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

fn iscsi_portal(bound: SocketAddr) -> String {
    // iscsiadm expects "IP:PORT" (no brackets for IPv4 loopback).
    // For IPv6 loopback, bracket the IP.
    match bound {
        SocketAddr::V4(v4) => format!("{}:{}", v4.ip(), v4.port()),
        SocketAddr::V6(v6) => format!("[{}]:{}", v6.ip(), v6.port()),
    }
}

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

/// Shared device pipeline: build every parsed [`DeviceSpec`] into a backing
/// plane and a typed LUN, in order (all `--block` devices first, then all
/// `--cdrom` devices).
///
/// Ownership model: the caller owns every resource — RAM slots
/// (`ram_disks`), block/optical backends, live scanners and bundles — and
/// the two typed LUN vectors borrow from them; the caller then lends the
/// LUNs to a transport as `&mut dyn ScsiDevice`. On failure prints the
/// error and returns `Err(())`.
fn build_devices<'a>(
    specs: &[DeviceSpec],
    ram_disks: &'a mut Vec<Vec<u8>>,
    backends: &'a mut Vec<BlockBackend<'a>>,
    lives: &'a mut Vec<LiveData<StdFsBackend>>,
    bundles: &'a mut Vec<FlatBundle<StdFsBackend>>,
    disks: &mut Vec<BlockDevice<RwRef<'a>>>,
    drives: &mut Vec<CdromDrive<'a>>,
) -> Result<(), ()> {
    if specs.is_empty() {
        eprintln!("snowdrive: --block or --cdrom is required (at least one device)");
        return Err(());
    }

    for w in spec::check_dual_mount(specs) {
        eprintln!("{w}");
    }

    // ── Phase A: own every resource, in LUN order ──────────────────
    // Exactly one byte-plane backend per non-Live LUN; Live owns its
    // scanner. RAM slots are consumed from `ram_disks` via a walking
    // split cursor (no reallocation, disjoint borrows).
    ram_disks.clear();
    // Pre-allocate RAM slot vectors so the cursor below can split them.
    for spec in specs {
        let size = match &spec.backing {
            Backing::Ram { size } => Some(*size),
            #[cfg(feature = "udfrw")]
            Backing::UdfRw { path: None } => spec.plane.size,
            _ => None,
        };
        if let Some(size) = size {
            match usize::try_from(size) {
                Ok(n) => ram_disks.push(vec![0u8; n]),
                Err(_) => {
                    eprintln!("snowdrive: RAM size {size} too large for this platform");
                    return Err(());
                }
            }
        }
    }
    backends.clear();
    lives.clear();
    bundles.clear();
    let mut ram_cursor: &'a mut [Vec<u8>] = ram_disks;

    for spec in specs {
        match &spec.backing {
            #[cfg(feature = "bundle")]
            Backing::ImgDir { dir } => {
                if !Path::new(dir).is_dir() {
                    if spec.plane.read_only {
                        eprintln!("snowdrive: bundle: read-only directory not found: {dir}");
                        return Err(());
                    }
                    // The FsStorage seam has no mkdir — the host (CLI) owns
                    // directory creation (__FLAT_BUN.md §4.2/§5.2).
                    std::fs::create_dir_all(dir).map_err(|e| {
                        eprintln!("snowdrive: bundle: failed to create directory {dir}: {e}");
                    })?;
                }
                let mut fs = StdFsBackend::new(dir);
                let bundle = if spec.plane.read_only {
                    // Data-plane RO (works on read-only media); never writes a
                    // header here.
                    FlatBundle::open_read_only(
                        fs,
                        spec.plane.chunk,
                        spec.plane.size,
                        Some(spec.plane.sector),
                    )
                    .map_err(|e| {
                        eprintln!("snowdrive: bundle: failed to open read-only {dir}: {e}")
                    })?
                } else {
                    // Headless directory (empty / chunk files only) → create a
                    // new bundle (writes the BUNDLE header); otherwise open +
                    // override.
                    let has_header = fs.open("BUNDLE", OpenOptions::read_only()).is_ok();
                    if !has_header {
                        let sz = spec.plane.size.ok_or_else(|| {
                            eprintln!(
                                "snowdrive: bundle: size= required to create a new bundle in {dir}"
                            );
                        })?;
                        FlatBundle::create(
                            fs,
                            spec.plane
                                .chunk
                                .unwrap_or(snowdrive_scsi::common::flat_bundle::DEFAULT_CHUNK_SIZE),
                            sz,
                            spec.plane.sector,
                        )
                        .map_err(|e| eprintln!("snowdrive: bundle: failed to create {dir}: {e}"))?
                    } else {
                        FlatBundle::open(
                            fs,
                            spec.plane.chunk,
                            spec.plane.size,
                            Some(spec.plane.sector),
                        )
                        .map_err(|e| eprintln!("snowdrive: bundle: failed to open {dir}: {e}"))?
                    }
                };
                bundles.push(bundle);
            }
            #[cfg(not(feature = "bundle"))]
            Backing::ImgDir { .. } => {
                eprintln!("snowdrive: imgdir= requires the `bundle` feature");
                return Err(());
            }
            Backing::Ram { size } => {
                let bytes = usize::try_from(*size).map_err(|_| {
                    eprintln!("snowdrive: RAM size {size} too large for this platform");
                })?;
                let (slot, tail) = ram_cursor.split_first_mut().unwrap();
                ram_cursor = tail;
                slot.resize(bytes, 0);
                backends.push(BlockBackend::Ram(RamBackend::new(slot)));
            }
            Backing::Img { path } => {
                if !Path::new(path).is_file() {
                    eprintln!("snowdrive: file not found: {path}");
                    return Err(());
                }
                // Read-only is enforced at BOTH layers: the plane is opened
                // `rb` (so it works on read-only media; never `r+b`), and the
                // LUN is locked below (`set_writable(false)`).
                let writable = spec.role == DeviceRole::BlockDisk && !spec.plane.read_only;
                let b = FileBackend::open(path, writable)
                    .map_err(|e| eprintln!("snowdrive: failed to open {path}: {e}"))?;
                backends.push(BlockBackend::File(b));
            }
            Backing::Live { dir } => {
                let fs = StdFsBackend::new(dir);
                let label = Path::new(dir)
                    .file_name()
                    .and_then(|n| n.to_str())
                    .unwrap_or("SNOWDRIVE");
                let live = LiveData::new(fs, label).map_err(|e| {
                    eprintln!("snowdrive: failed to scan live directory {dir}: {e}");
                })?;
                lives.push(live);
            }
            #[cfg(feature = "udfrw")]
            Backing::UdfRw { path } => match path.as_deref() {
                Some(path) => {
                    let existed = Path::new(path).exists();
                    if existed && spec.plane.size.is_some() {
                        eprintln!("snowdrive: udfrw: size= is only valid for a new file: {path}");
                        return Err(());
                    }
                    if !existed {
                        let Some(sz) = spec.plane.size else {
                            eprintln!(
                                "snowdrive: udfrw: file not found, use size= to create it: {path}"
                            );
                            return Err(());
                        };
                        create_sparse(path, sz).map_err(|e| {
                            eprintln!("snowdrive: udfrw: failed to create {path}: {e}");
                        })?;
                    }
                    let b = FileBackend::open(path, true).map_err(|e| {
                        eprintln!("snowdrive: udfrw: failed to open {path}: {e}");
                    })?;
                    backends.push(BlockBackend::File(b));
                }
                None => {
                    let bytes = spec.plane.size.ok_or_else(|| {
                        eprintln!("snowdrive: udfrw=ram: requires size=");
                    })?;
                    let bytes = usize::try_from(bytes).map_err(|_| {
                        eprintln!("snowdrive: udfrw=ram: size too large");
                    })?;
                    let (slot, tail) = ram_cursor.split_first_mut().unwrap();
                    ram_cursor = tail;
                    slot.resize(bytes, 0);
                    backends.push(BlockBackend::Ram(RamBackend::new(slot)));
                }
            },
            #[cfg(not(feature = "udfrw"))]
            Backing::UdfRw { .. } => {
                eprintln!("snowdrive: udfrw= requires the `udfrw` feature");
                return Err(());
            }
        }
    }

    // ── Phase B: lend each backend exactly once, build LUNs ────────
    disks.clear();
    drives.clear();
    let mut be_iter = backends.iter_mut();
    let mut live_iter = lives.iter_mut();
    #[cfg(feature = "bundle")]
    let mut bundle_iter = bundles.iter_mut();
    for (lun, spec) in specs.iter().enumerate() {
        log::debug!("LUN {lun}: {}", spec.raw);
        match (spec.role, &spec.backing) {
            #[cfg(feature = "bundle")]
            (DeviceRole::BlockDisk, Backing::ImgDir { dir }) => {
                let be = bundle_iter
                    .next()
                    .ok_or_else(|| eprintln!("snowdrive: internal: bundle pool exhausted"))?;
                let cap = be.capacity();
                let mut dev = BlockDevice::disk(RwRef::new(be), spec.plane.sector)
                    .map_err(|e| eprintln!("snowdrive: bundle: invalid geometry for {dir}: {e}"))?;
                if spec.plane.read_only {
                    // Device layer RO (immediate DATA PROTECT); the plane is
                    // already read-only, so both layers agree.
                    dev.set_writable(false);
                }
                log::debug!(
                    "LUN {lun}: bundle block device ({cap} bytes, sector {})",
                    spec.plane.sector
                );
                disks.push(dev);
            }
            #[cfg(feature = "bundle")]
            (DeviceRole::BlockCd, Backing::ImgDir { dir }) => {
                let be = bundle_iter
                    .next()
                    .ok_or_else(|| eprintln!("snowdrive: internal: bundle pool exhausted"))?;
                let cap = be.capacity();
                let dev = BlockDevice::cdrom(RwRef::new(be)).map_err(|e| {
                    eprintln!("snowdrive: bundle: invalid CD geometry for {dir}: {e}")
                })?;
                log::debug!("LUN {lun}: bundle CD profile ({cap} bytes)");
                disks.push(dev);
            }
            (DeviceRole::BlockDisk, Backing::Img { .. } | Backing::Ram { .. }) => {
                let be = be_iter
                    .next()
                    .ok_or_else(|| eprintln!("snowdrive: internal: backend pool exhausted"))?;
                let cap = be.capacity();
                let mut dev =
                    BlockDevice::disk(RwRef::new(be), SECTOR_SIZE).expect("SECTOR_SIZE is nonzero");
                if spec.plane.read_only {
                    dev.set_writable(false);
                }
                log::debug!(
                    "LUN {lun}: block device ({cap} bytes{})",
                    if spec.plane.read_only {
                        ", read-only"
                    } else {
                        ""
                    }
                );
                disks.push(dev);
            }
            (DeviceRole::BlockCd, Backing::Img { .. } | Backing::Ram { .. }) => {
                let be = be_iter
                    .next()
                    .ok_or_else(|| eprintln!("snowdrive: internal: backend pool exhausted"))?;
                let cap = be.capacity();
                // Optical image profile (PDT 0x05): writes rejected at the
                // profile level; the erased plane type stays uniform.
                let dev = BlockDevice::cdrom(RwRef::new(be)).expect("nonzero sectors");
                log::debug!("LUN {lun}: CD profile ({cap} bytes)");
                disks.push(dev);
            }
            (DeviceRole::MmcCd, Backing::Img { path }) => {
                let be = be_iter
                    .next()
                    .ok_or_else(|| eprintln!("snowdrive: internal: backend pool exhausted"))?;
                let cap = be.capacity();
                let mut drive = CdromDrive::new();
                drive.load(CdMedia::ro(be));
                log::debug!("LUN {lun}: {path} flat CD-ROM ({cap} bytes)");
                drives.push(drive);
            }
            (DeviceRole::MmcCd, Backing::Live { dir }) => {
                let live = live_iter
                    .next()
                    .ok_or_else(|| eprintln!("snowdrive: internal: live pool exhausted"))?;
                let total = live.layout().total;
                let mut drive = CdromDrive::new();
                drive.load(CdMedia::ro(live));
                log::debug!("LUN {lun}: {dir} live ISO9660 CD-ROM ({total} sectors)");
                drives.push(drive);
            }
            #[cfg(feature = "udfrw")]
            (DeviceRole::MmcCd, Backing::UdfRw { path }) => {
                let be = be_iter
                    .next()
                    .ok_or_else(|| eprintln!("snowdrive: internal: backend pool exhausted"))?;
                let label = path
                    .as_deref()
                    .and_then(|p| Path::new(p).file_name().and_then(|n| n.to_str()))
                    .unwrap_or("SNOWDRIVE")
                    .to_string();
                let mut scratch = [0u8; 256];
                let opts = UdfRwOptions {
                    mode: if spec.plane.mkfs {
                        OpenMode::Materialize
                    } else {
                        OpenMode::AsIs
                    },
                    scratch: &mut scratch,
                };
                let media = UdfRwMedia::open_or_materialize(RwRef::new(be), &label, opts)
                    .map_err(|e| eprintln!("snowdrive: udfrw: {e}"))?;
                log::debug!("LUN {lun}: UdfRw DVD+RW ({} bytes)", media.capacity());
                let mut drive = CdromDrive::builder()
                    .capabilities(snowdrive_scsi::cdrom::HYPER_MULTI_CAPS)
                    .build();
                drive.load(CdMedia::Rw(media));
                drives.push(drive);
            }
            _ => {
                eprintln!(
                    "snowdrive: internal: unsupported device spec '{}'",
                    spec.raw
                );
                return Err(());
            }
        }
    }
    Ok(())
}

fn create_sparse(path: &str, size: u64) -> std::io::Result<()> {
    let f = File::create(path)?;
    f.set_len(size)?;
    Ok(())
}

#[cfg(target_os = "linux")]
/// `snowdrive serve --usb`: assemble the MSC FunctionFS gadget, bind it to a
/// UDC and run the BOT poll loop (§6).
fn run_serve_usb(
    args: &ServeArgs,
    luns: &mut [&mut dyn ScsiDevice],
    work_size: usize,
    selector: &str,
) -> ExitCode {
    // Gadget assembly (§6.1): a single MSC interface (class 08/06/50) with
    // one bulk OUT + one bulk IN endpoint.
    let (ep_out, out_dir) = EndpointDirection::host_to_device();
    let (ep_in, in_dir) = EndpointDirection::device_to_host();

    let (custom, handle) = Custom::builder()
        .with_interface(
            Interface::new(Class::MASS_STORAGE_SCSI_BULK, "snowdrive msc")
                .with_endpoint(Endpoint::bulk(out_dir))
                .with_endpoint(Endpoint::bulk(in_dir)),
        )
        .build();

    let choice = match resolve_udc(selector) {
        Ok(c) => c,
        Err(e) => {
            eprintln!("snowdrive: {e}");
            return ExitCode::FAILURE;
        }
    };
    let UdcChoice { udc, owns_configfs } = choice;
    log::info!("binding USB gadget to UDC {:?}", udc.name());
    let reg = match UsbGadget::new(
        Class::INTERFACE_SPECIFIC,
        Id::new(args.vid, args.pid),
        Strings::new("SnowDrive", "SnowDrive USB Disk", &args.serial),
    )
    .with_config(Config::new("config").with_function(handle))
    .bind(&udc)
    {
        Ok(r) => r,
        Err(e) => {
            eprintln!("snowdrive: failed to bind USB gadget: {e}");
            return ExitCode::FAILURE;
        }
    };

    let stop = Arc::new(AtomicBool::new(false));
    {
        let stop = Arc::clone(&stop);
        if let Err(e) = ctrlc::set_handler(move || stop.store(true, Ordering::SeqCst)) {
            eprintln!("snowdrive: failed to install signal handler: {e}");
            return ExitCode::FAILURE;
        }
    }

    let mut ffs_bot = FfsBot::new(ep_out, ep_in);
    let mut ffs_gadget = FfsGadget { custom };
    // The function's control plane does not provide a reliable Bulk-In STALL +
    // CLEAR_FEATURE(ENDPOINT_HALT) observation over Linux FunctionFS with the
    // current usb-gadget crate, so select the max-compat default (a plain short
    // packet, no STALL). The `stall_in` seam remains for transports that can
    // implement it.
    let mut session =
        BotSession::with_luns(luns.len()).with_shortfall(ShortfallPolicy::ShortNoStall);
    let mut work = vec![0u8; work_size];
    let mut recv = vec![0u8; round_up_mps(work_size)];

    log::info!("serving {} LUN(s) over USB", luns.len());
    if let Err(e) = serve_bot(
        &mut ffs_bot,
        &mut ffs_gadget,
        &mut session,
        &mut recv,
        &mut work,
        luns,
        &stop,
    ) {
        eprintln!("snowdrive: usb serve error: {e}");
        return ExitCode::FAILURE;
    }

    // Graceful exit: flush backends, unregister the gadget (RAII), then
    // unmount configfs again if the `dummy` auto-config mounted it.
    sync_devices(luns);
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
/// (§6.2). `halt()` reports success as `Err(-EBADMSG)` (errno 74), so
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

    /// Enqueue one read of `size` bytes (rounded up to the USB MPS) unless a
    /// read is already in flight.
    fn ensure_read(&mut self, size: usize) -> Result<(), BotIoErr> {
        if self.pending {
            return Ok(());
        }
        let size = round_up_mps(size.max(1));
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
        // success; discard in-flight aio first (§4.7).
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
    /// shortfall (BOT §6.7.2). Mirrors the IN side of `stall_both`
    /// (`discard_fifo()` then `halt()`), mapping **only** the benign
    /// `-EBADMSG` (errno 74) success quirk to `Ok(())`; every other errno is a
    /// real fault and becomes `Err(())` so the serve loop reaches the reset
    /// abort instead of swallowing it.
    ///
    /// **Not currently selected by the CLI.** Verification (dummy_hcd + Linux
    /// 6.18) showed the requested STALL is not reliably seen by the host and
    /// `CLEAR_FEATURE(ENDPOINT_HALT)` is not reliably observable through
    /// FunctionFS with this crate, so the serve loop wedges in `DataInStall`;
    /// the CLI therefore runs `ShortNoStall`. Kept as the platform half of the
    /// [`BotIo::stall_in`] seam.
    fn stall_in(&mut self) -> Result<(), ()> {
        let control = self.in_.control().map_err(|e| {
            log::error!("bulk-IN control unavailable: {e}");
        })?;
        // Empty the endpoint request queue first (crate doc for `halt`).
        let _ = control.discard_fifo();
        match control.halt() {
            Ok(()) => Ok(()),
            // halt() reports success as Err(-EBADMSG) (errno 74).
            Err(e) if e.raw_os_error() == Some(74) => Ok(()),
            Err(e) => {
                log::error!("bulk-IN endpoint halt failed: {e}");
                Err(())
            }
        }
    }
}

/// Bulk-In endpoint address as assigned by the `Custom` descriptor builder in
/// [`run_serve_usb`]: endpoints are numbered in declaration order, so the bulk
/// OUT (declared first) is `0x01` and the bulk IN (declared second) is `0x82`.
/// The CLI is the one that built the descriptors, so it owns this knowledge
/// and filters CLEAR_FEATURE(ENDPOINT_HALT) on it before calling
/// `BotSession::clear_feature_halt`.
#[cfg(target_os = "linux")]
const BULK_IN_EP_ADDR: u8 = 0x82;

#[cfg(target_os = "linux")]
/// Bulk-Only Reset ack handle: completing the control status stage is the
/// drop of the FunctionFS receiver (§6.2).
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
        // tolerated. Never STALL Get Max LUN (§4.3).
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
                if receiver.ctrl_req().request == snowdrive_scsi::usb::BOT_RESET =>
            {
                Some(CtrlReq::BotReset {
                    ack: FfsAck {
                        receiver: Some(receiver),
                    },
                })
            }
            Event::SetupDeviceToHost(sender)
                if sender.ctrl_req().request == snowdrive_scsi::usb::GET_MAX_LUN =>
            {
                Some(CtrlReq::GetMaxLun {
                    reply: FfsReply {
                        sender: Some(sender),
                    },
                })
            }
            // CLEAR FEATURE(ENDPOINT_HALT): bmRequestType 0x02 = Recipient=
            // Endpoint, Host-to-Device, Standard. request=0x01 (CLEAR_FEATURE),
            // value=0x00 (ENDPOINT_HALT). index=endpoint address.
            // BOT §3.1: BotReset preserves STALL; the host must send this to
            // clear it and resume operation.
            Event::SetupHostToDevice(receiver)
                if receiver.ctrl_req().request_type == 0x02
                    && receiver.ctrl_req().request == 0x01
                    && receiver.ctrl_req().value == 0x00 =>
            {
                // wIndex is the endpoint address; the serve loop filters it to
                // our own Bulk-In.
                Some(CtrlReq::ClearFeatureHalt {
                    addr: receiver.ctrl_req().index as u8,
                })
            }
            Event::Bind | Event::Enable | Event::Disable => Some(CtrlReq::LinkReset),
            _ => None,
        }
    }
}

#[cfg(target_os = "linux")]
/// The PC poll driver (§6.3): control requests first, then one bulk step of
/// the non-blocking `BotSession` core, bounded by the stop flag.
fn serve_bot(
    ffs_bot: &mut FfsBot,
    ffs_gadget: &mut FfsGadget,
    session: &mut BotSession,
    recv: &mut [u8],
    work: &mut [u8],
    devs: &mut [&mut dyn ScsiDevice],
    stop: &AtomicBool,
) -> Result<(), String> {
    if work.len() < MIN_DATA_LEN {
        return Err(format!("work buffer smaller than {MIN_DATA_LEN}"));
    }
    let mut stalled = false;
    // Dedicated transient-STALL dedupe for `ShortfallPolicy::Short`: the data
    // stall is a *recurring* need (unlike the terminal invalid-CBW `stalled`),
    // so sharing a flag would suppress a later STALL. Set when `stall_in()` is
    // attempted; cleared on a matching CLEAR_FEATURE, any reset, disconnect, or
    // a `stall_in` failure abort.
    let mut stalled_short = false;
    loop {
        if stop.load(Ordering::SeqCst) {
            return Ok(());
        }
        // 1) Control requests first (arrive at any time, even mid data phase).
        if let Some(req) = ffs_gadget.try_next_ctrl() {
            match req {
                CtrlReq::BotReset { ack } => {
                    session.reset();
                    ack.ack();
                    stalled_short = false;
                    // BOT §3.1: BotReset preserves STALL. The core keeps the
                    // STALLed state; clear_feature_halt() transitions out.
                    // Only clear our local flag if the core did not stay STALLed.
                    if !matches!(session.need(), SessionNeed::Done(BotStepResult::Stalled)) {
                        stalled = false;
                    }
                }
                CtrlReq::GetMaxLun { mut reply } => {
                    reply
                        .send(&[session.max_lun()])
                        .map_err(|_| "Get Max LUN reply failed".to_string())?;
                }
                CtrlReq::LinkReset => {
                    session.reset();
                    stalled_short = false;
                    if !matches!(session.need(), SessionNeed::Done(BotStepResult::Stalled)) {
                        stalled = false;
                    }
                }
                CtrlReq::ClearFeatureHalt { addr } => {
                    // Only our own Bulk-In endpoint releases the halt; a clear
                    // for any other endpoint is ignored.
                    if addr == BULK_IN_EP_ADDR {
                        session.clear_feature_halt();
                        stalled = false;
                        stalled_short = false;
                    }
                }
            }
            continue;
        }
        // 2) STALLed: only control events until the host resets (§4.5).
        if stalled {
            continue;
        }
        match session.need() {
            SessionNeed::NeedOut { len, probe } => {
                // probe = non-blocking overrun drain (no wait); everything
                // else bounds the ctrl/stop check latency.
                let timeout = if probe {
                    Duration::ZERO
                } else {
                    BOT_POLL_GRANULARITY
                };
                // FunctionFS aio reads need an MPS-multiple buffer: a smaller
                // one (e.g. the 31-byte CBW request) overflows when the host
                // sends a full MPS packet (-EOVERFLOW).
                let aio_len = round_up_mps(len);
                match ffs_bot.recv_out(&mut recv[..aio_len], Some(timeout)) {
                    Ok(n) => {
                        let step =
                            session.poll(SessionEvent::OutRecv { data: &recv[..n] }, work, devs);
                        if let SessionStep::Done(r) = step {
                            handle_done(r, &mut stalled, ffs_bot)?;
                        }
                    }
                    Err(BotIoErr::WouldBlock) => {
                        if probe {
                            let step = session.poll(SessionEvent::OutIdle, work, devs);
                            if let SessionStep::Done(r) = step {
                                handle_done(r, &mut stalled, ffs_bot)?;
                            }
                        }
                    }
                    Err(BotIoErr::Disconnected) => {
                        // Host unplug / VM migration: reset and keep serving.
                        // The next NeedOut re-arms the read (pending was
                        // cleared by FfsBot); a re-attach is announced by
                        // FunctionFS Bind/Enable events.
                        log::info!("USB host disconnected; resetting session");
                        session.reset();
                        stalled = false;
                        stalled_short = false;
                    }
                    Err(BotIoErr::Io) => return Err("bulk OUT I/O failure".to_string()),
                }
            }
            SessionNeed::NeedIn { len } => {
                let data = session.out_slice(&work[..]);
                if data.len() != len {
                    return Err("internal: out_slice length mismatch".to_string());
                }
                match ffs_bot.send_in(data) {
                    Ok(()) => {}
                    Err(BotIoErr::Disconnected) => {
                        log::info!("USB host disconnected; resetting session");
                        session.reset();
                        stalled = false;
                        stalled_short = false;
                        continue;
                    }
                    Err(BotIoErr::Io) => return Err("bulk IN send failed".to_string()),
                    Err(BotIoErr::WouldBlock) => {
                        return Err("unexpected WouldBlock on bulk IN send".to_string());
                    }
                }
                let step = session.poll(SessionEvent::InSent, work, devs);
                if let SessionStep::Done(r) = step {
                    handle_done(r, &mut stalled, ffs_bot)?;
                }
            }
            SessionNeed::NeedStall => {
                if !stalled_short {
                    match ffs_bot.stall_in() {
                        Ok(()) => stalled_short = true,
                        Err(()) => {
                            // A `Short`-without-`stall_in` mismatch aborts
                            // deterministically (reset drops the withheld CSW).
                            log::error!(
                                "fatal: ShortfallPolicy::Short selected but bulk-IN STALL \
                                 unavailable; aborting transaction"
                            );
                            session.reset();
                            stalled = false;
                            stalled_short = false;
                        }
                    }
                }
            }
            SessionNeed::Done(r) => handle_done(r, &mut stalled, ffs_bot)?,
        }
    }
}

#[cfg(target_os = "linux")]
/// React to a transaction-end result from the core.
fn handle_done(
    result: BotStepResult,
    stalled: &mut bool,
    ffs_bot: &mut FfsBot,
) -> Result<(), String> {
    match result {
        BotStepResult::Stalled => {
            if !*stalled {
                let _ = ffs_bot.stall_both();
                *stalled = true;
            }
            Ok(())
        }
        BotStepResult::Error(e) => Err(format!("BOT core error: {e}")),
        // Emitted only by the blocking `step()` wrapper, which this poll loop
        // does not use; unreachable here.
        BotStepResult::Unsupported => Ok(()),
        BotStepResult::Processed | BotStepResult::Closed => Ok(()),
    }
}

/// `snowdrive mkisofs <DIR> <OUT.iso>` — scan a host directory and write a
/// standalone ISO9660/Joliet image to disk.
///
/// Reuses the live-generation pipeline (`CdLiveFsDevice`: scan → layout →
/// sector synthesis) and dumps every sector through `read_data`, so the
/// on-disk image is byte-identical to what `serve --cdrom live=<dir>`
/// would expose. The image is padded to whole 2048-byte sectors.
fn run_mkisofs(args: MkisofsArgs) -> ExitCode {
    init_logging(args.verbose);

    let dir = Path::new(&args.dir);
    if !dir.is_dir() {
        eprintln!("snowdrive: directory not found: {}", args.dir);
        return ExitCode::FAILURE;
    }
    if args.out.is_empty() {
        eprintln!("snowdrive: empty output path");
        return ExitCode::FAILURE;
    }
    if Path::new(&args.out).is_dir() {
        eprintln!("snowdrive: output path is a directory: {}", args.out);
        return ExitCode::FAILURE;
    }

    let label = match &args.label {
        Some(l) => l.clone(),
        None => dir
            .file_name()
            .and_then(|n| n.to_str())
            .unwrap_or("SNOWDRIVE")
            .to_string(),
    };

    let fs = StdFsBackend::new(&args.dir);
    let live = match LiveData::new(fs, &label) {
        Ok(d) => d,
        Err(e) => {
            eprintln!("snowdrive: failed to scan {}: {e}", args.dir);
            return ExitCode::FAILURE;
        }
    };
    let total_sectors = live.layout().total;
    let mut flat = FlatMedia::new(live);

    let file = match File::create(&args.out) {
        Ok(f) => f,
        Err(e) => {
            eprintln!("snowdrive: failed to create {}: {e}", args.out);
            return ExitCode::FAILURE;
        }
    };
    let mut writer = BufWriter::new(file);
    let mut sector = [0u8; ISO_SECTOR_SIZE as usize];
    for lba in 0..total_sectors {
        if flat
            .read_data(u64::from(lba) * u64::from(ISO_SECTOR_SIZE), &mut sector)
            .is_err()
        {
            eprintln!("snowdrive: failed to read sector {lba}");
            return ExitCode::FAILURE;
        }
        if writer.write_all(&sector).is_err() {
            eprintln!("snowdrive: failed to write {}", args.out);
            return ExitCode::FAILURE;
        }
    }
    if writer.flush().is_err() {
        eprintln!("snowdrive: failed to flush {}", args.out);
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

/// Resolve the work buffer size (default 256K), validating it against
/// [`MIN_DATA_LEN`].
fn parse_work_size(s: Option<&str>) -> Result<usize, String> {
    let bytes = match s {
        None => DEFAULT_WORK_BUF_SIZE as u64,
        Some(v) => spec::parse_size(v).ok_or_else(|| format!("invalid --work-buf-size: {v}"))?,
    };
    let n = usize::try_from(bytes).map_err(|_| format!("--work-buf-size {bytes} is too large"))?;
    if n < MIN_DATA_LEN {
        return Err(format!(
            "--work-buf-size {n} is below the minimum {MIN_DATA_LEN}"
        ));
    }
    Ok(n)
}

/// Parse a hexadecimal u16 (with optional `0x` prefix) for `--vid`/`--pid`.
fn parse_hex_u16(s: &str) -> Result<u16, String> {
    let body = s.trim_start_matches("0x").trim_start_matches("0X");
    u16::from_str_radix(body, 16).map_err(|_| format!("invalid hex value: {s}"))
}

#[cfg(test)]
mod tests {
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
        assert!(parse_work_size(Some("1000")).is_err()); // below MIN_DATA_LEN
        assert!(parse_work_size(Some("bogus")).is_err());
    }

    #[test]
    fn cli_accepts_multiple_block_and_cdrom_specs() {
        let cli = Cli::try_parse_from([
            "snowdrive",
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
            Cli::Mkisofs(_) => panic!("expected Serve, got Mkisofs"),
        }
    }

    #[test]
    fn cli_rejects_removed_flags() {
        // `--disk` / `--cdblock` were removed in the device/backing split.
        assert!(Cli::try_parse_from(["snowdrive", "serve", "--disk", "ram=1M"]).is_err());
        assert!(Cli::try_parse_from(["snowdrive", "serve", "--cdblock", "x.iso"]).is_err());
    }

    #[test]
    fn cli_usb_transport_parses() {
        match Cli::try_parse_from(["snowdrive", "serve", "--usb", "--block", "ram=1M"]).unwrap() {
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
            Cli::try_parse_from(["snowdrive", "serve", "--usb", "--iscsi", "127.0.0.1:3260"])
                .is_err()
        );
    }

    #[test]
    fn cli_iscsi_auto_parses() {
        match Cli::try_parse_from(["snowdrive", "serve", "--iscsi", "auto", "--block", "ram=1M"])
            .unwrap()
        {
            Cli::Serve(a) => assert_eq!(a.iscsi.as_deref(), Some("auto")),
            other => panic!("expected Serve, got {other:?}"),
        }
    }

    #[test]
    fn cli_requires_a_transport() {
        // serve without `--iscsi`/`--usb` fails at parse time.
        assert!(Cli::try_parse_from(["snowdrive", "serve", "--block", "ram=1M"]).is_err());
    }

    #[test]
    fn cli_usb_descriptor_overrides() {
        match Cli::try_parse_from([
            "snowdrive",
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
        match Cli::try_parse_from(["snowdrive", "--help"]) {
            Err(e) if e.kind() == clap::error::ErrorKind::DisplayHelp => {}
            other => panic!("expected DisplayHelp, got {other:?}"),
        }
    }

    #[test]
    fn cli_mkisofs_parses_positional_and_label() {
        match Cli::try_parse_from(["snowdrive", "mkisofs", "tree", "out.iso", "--label", "DISC"])
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
        match Cli::try_parse_from(["snowdrive", "mkisofs", "tree", "out.iso"]).unwrap() {
            Cli::Mkisofs(a) => assert_eq!(a.label, None),
            other => panic!("unexpected CLI: {other:?}"),
        }
    }

    #[test]
    fn cli_mkisofs_requires_two_positionals() {
        assert!(Cli::try_parse_from(["snowdrive", "mkisofs", "tree"]).is_err());
        assert!(Cli::try_parse_from(["snowdrive", "mkisofs"]).is_err());
    }

    #[test]
    fn run_mkisofs_writes_whole_sectors() {
        let dir = std::env::temp_dir().join(format!("snowdrive_mkisofs_{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(dir.join("DATA.BIN"), vec![0x42u8; 2048]).unwrap();

        let out =
            std::env::temp_dir().join(format!("snowdrive_mkisofs_{}.iso", std::process::id()));
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
            dir: "/nonexistent/snowdrive-mkisofs".to_string(),
            out: "/tmp/out.iso".to_string(),
            label: None,
            verbose: 0,
        };
        assert_eq!(run_mkisofs(args), ExitCode::FAILURE);
    }
}
