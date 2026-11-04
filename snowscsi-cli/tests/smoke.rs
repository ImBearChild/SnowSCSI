//! Process-level smoke tests for the `snowscsi` CLI (`snowscsi_main.c`).

use std::process::{Command, Output};

fn run(args: &[&str]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_snowscsi"))
        .args(args)
        .output()
        .expect("run snowscsi")
}

/// Spawn `snowscsi serve`, wait for the `listening` line, SIGINT, assert exit 0.
#[cfg(unix)]
fn run_serve_until_ready_then_sigint(args: &[&str]) {
    use std::io::BufRead;
    use std::sync::mpsc;
    use std::time::Duration;

    let mut child = Command::new(env!("CARGO_BIN_EXE_snowscsi"))
        .args(args)
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::piped())
        .spawn()
        .expect("spawn snowscsi");

    let (ready_tx, ready_rx) = mpsc::channel();
    {
        let stderr = child.stderr.take().expect("child stderr");
        std::thread::spawn(move || {
            let mut line = String::new();
            let mut reader = std::io::BufReader::new(stderr);
            while reader.read_line(&mut line).map(|n| n > 0).unwrap_or(false) {
                if line.contains("listening") {
                    let _ = ready_tx.send(());
                    return;
                }
                line.clear();
            }
        });
    }

    if ready_rx.recv_timeout(Duration::from_secs(5)).is_err() {
        let _ = Command::new("kill")
            .arg("-KILL")
            .arg(child.id().to_string())
            .status();
        let _ = child.wait();
        panic!("snowscsi did not announce 'listening' for {args:?}");
    }

    let sent = Command::new("kill")
        .arg("-INT")
        .arg(child.id().to_string())
        .status()
        .map(|s| s.success())
        .unwrap_or(false);
    assert!(sent, "kill -INT failed");
    let status = child.wait().expect("wait for snowscsi");
    assert!(
        status.success(),
        "expected exit 0 after SIGINT for {args:?}, got {status:?}"
    );
}

/// True if this process cannot write to a `0444` file (i.e. not root), so a
/// read-only medium can actually be simulated.
#[cfg(unix)]
fn can_simulate_read_only() -> bool {
    use std::os::unix::fs::PermissionsExt;
    use std::sync::atomic::{AtomicUsize, Ordering};
    // Unique per call: several tests probe read-only support concurrently.
    static NEXT: AtomicUsize = AtomicUsize::new(0);
    let dir = std::env::temp_dir().join(format!(
        "snowscsi_roprobe_{}_{}",
        std::process::id(),
        NEXT.fetch_add(1, Ordering::Relaxed)
    ));
    let _ = std::fs::create_dir_all(&dir);
    let probe = dir.join("probe");
    if std::fs::write(&probe, b"x").is_err() {
        return false;
    }
    std::fs::set_permissions(&probe, std::fs::Permissions::from_mode(0o444)).unwrap();
    let writable = std::fs::OpenOptions::new().write(true).open(&probe).is_ok();
    let _ = std::fs::remove_dir_all(&dir);
    !writable
}

#[test]
fn help_exits_zero_and_lists_serve() {
    let out = run(&["--help"]);
    assert!(out.status.success());
    let text = String::from_utf8_lossy(&out.stdout);
    assert!(text.contains("serve"));
}

#[test]
fn no_subcommand_fails() {
    assert!(!run(&[]).status.success());
}

#[test]
fn serve_requires_iscsi() {
    let out = run(&["serve", "--block", "ram=1M"]);
    assert!(!out.status.success());
    let err = String::from_utf8_lossy(&out.stderr);
    assert!(err.contains("--iscsi"));
}

#[test]
fn serve_requires_block() {
    let out = run(&["serve", "--iscsi", "127.0.0.1:3260"]);
    assert!(!out.status.success());
    let err = String::from_utf8_lossy(&out.stderr);
    assert!(err.contains("--block"));
}

#[test]
fn serve_rejects_invalid_ram_size() {
    let out = run(&["serve", "--block", "ram=bogus", "--iscsi", "127.0.0.1:3260"]);
    assert!(!out.status.success());
}

#[test]
fn serve_rejects_missing_file() {
    let out = run(&[
        "serve",
        "--block",
        "img=/nonexistent/snowscsi-missing.img",
        "--iscsi",
        "127.0.0.1:3260",
    ]);
    assert!(!out.status.success());
    let err = String::from_utf8_lossy(&out.stderr);
    assert!(err.contains("file not found"));
}

#[test]
fn serve_rejects_invalid_address() {
    let out = run(&["serve", "--block", "ram=1M", "--iscsi", "not-an-address"]);
    assert!(!out.status.success());
}

#[test]
fn serve_rejects_unknown_option() {
    let out = run(&["serve", "--bogus", "x"]);
    assert!(!out.status.success());
}

#[test]
fn serve_rejects_work_buf_too_small() {
    // 560 is legal for USB but below the iSCSI floor (MIN_DATA_LEN + BHS): the
    // process must fail fast with a clear error instead of binding and serving.
    let out = run(&[
        "serve",
        "--block",
        "ram=1M",
        "--iscsi",
        "127.0.0.1:3260",
        "--work-buf-size",
        "560",
    ]);
    assert!(!out.status.success());
    let err = String::from_utf8_lossy(&out.stderr);
    assert!(
        err.contains("iSCSI minimum 8240"),
        "expected a clear iSCSI floor message, got: {err}"
    );

    // Below the absolute (USB) floor both transports reject it.
    let out = run(&[
        "serve",
        "--block",
        "ram=1M",
        "--iscsi",
        "127.0.0.1:3260",
        "--work-buf-size",
        "511",
    ]);
    assert!(!out.status.success());
}

/// Run the binary with a wall-clock bound so a CLI bug that binds/serves
/// instead of rejecting a flag combination fails the test instead of hanging
/// the suite.
fn run_with_timeout(args: &[&str], secs: u64) -> Output {
    use std::sync::mpsc;
    use std::time::Duration;

    let child = Command::new(env!("CARGO_BIN_EXE_snowscsi"))
        .args(args)
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .spawn()
        .expect("spawn snowscsi");
    let pid = child.id();
    let (tx, rx) = mpsc::channel();
    std::thread::spawn(move || {
        let _ = tx.send(child.wait_with_output());
    });
    match rx.recv_timeout(Duration::from_secs(secs)) {
        Ok(out) => out.expect("wait for snowscsi"),
        Err(_) => {
            let _ = Command::new("kill")
                .args(["-KILL", &pid.to_string()])
                .status();
            panic!("snowscsi hung on {args:?}; expected a fast rejection");
        }
    }
}

#[test]
fn print_config_prints_one_line_and_exits() {
    let out = run(&[
        "serve",
        "--block",
        "ram=1M",
        "--block",
        "ram=1M",
        "--iscsi",
        "127.0.0.1:0",
        "--banks",
        "dual",
        "--print-config",
    ]);
    assert!(out.status.success());
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert_eq!(
        stdout.trim_end(),
        "wire=blocking banks=dual storage=worker per_bank=8240 work=16480 scratch=0 lun=2 \
         backing=ram,ram"
    );
}

/// `--print-config` reports the async wire without binding anything.
#[cfg(feature = "tokio")]
#[test]
fn print_config_reports_the_async_wire() {
    let out = run(&[
        "serve",
        "--block",
        "ram=1M",
        "--iscsi",
        "127.0.0.1:0",
        "--wire",
        "async",
        "--print-config",
    ]);
    assert!(out.status.success());
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert_eq!(
        stdout.trim_end(),
        "wire=async banks=single storage=inline per_bank=1048576 work=1048576 scratch=0 \
         lun=1 backing=ram"
    );
}

/// The `bundle=` backing is discoverable from both surfaces: `serve --help`
/// documents it, and `--print-config` names it (validating `bundle=` inputs
/// but not starting a transport).
#[cfg(feature = "cdr-bundle")]
#[test]
fn cdr_bundle_help_and_print_config_mention_the_backing() {
    let out = run(&["serve", "--help"]);
    assert!(out.status.success());
    let help = String::from_utf8_lossy(&out.stdout);
    assert!(help.contains("bundle=<dir>"), "help text:\n{help}");
    assert!(help.contains("toc.0"), "help text:\n{help}");
    assert!(help.contains("track_<n>.bin"), "help text:\n{help}");
    assert!(help.contains("bundle-create"), "help text:\n{help}");

    let dir = std::env::temp_dir().join(format!("snowscsi_helpcfg_{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    let path = dir.to_string_lossy().to_string();
    assert!(run(&["bundle-create", "cdr", "--dir", &path])
        .status
        .success());
    let out = run(&[
        "serve",
        "--block",
        "ram=1M",
        "--cdrom",
        &format!("bundle={path}"),
        "--usb",
        "--print-config",
    ]);
    assert!(
        out.status.success(),
        "print-config failed:\n{}",
        String::from_utf8_lossy(&out.stderr)
    );
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(
        stdout.trim_end().ends_with("lun=2 backing=ram,bundle"),
        "print-config line:\n{stdout}"
    );
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn serve_rejects_iscsi_dual_below_the_two_bank_floor() {
    // One byte below 2 × 8240 is refused before the portal is bound.
    let out = run(&[
        "serve",
        "--block",
        "ram=1M",
        "--iscsi",
        "127.0.0.1:0",
        "--banks",
        "dual",
        "--work-buf-size",
        "16479",
    ]);
    assert!(!out.status.success());
    let err = String::from_utf8_lossy(&out.stderr);
    assert!(
        err.contains("16479"),
        "expected the rejected total in the message, got: {err}"
    );
}

#[cfg(unix)]
#[test]
fn serve_starts_with_iscsi_dual_banks() {
    // The two-bank total is accepted and the portal starts serving.
    run_serve_until_ready_then_sigint(&[
        "serve",
        "--block",
        "ram=1M",
        "--iscsi",
        "127.0.0.1:0",
        "--banks",
        "dual",
    ]);
}

#[cfg(target_os = "linux")]
#[test]
fn serve_rejects_dual_with_scratch_buffer() {
    let out = run_with_timeout(
        &[
            "serve",
            "--block",
            "ram=1M",
            "--usb",
            "--banks",
            "dual",
            "--scratch-buffer",
        ],
        10,
    );
    assert!(!out.status.success());
    let err = String::from_utf8_lossy(&out.stderr);
    assert!(
        err.contains("--scratch-buffer"),
        "expected the conflicting flag to be named, got: {err}"
    );
}

#[cfg(target_os = "linux")]
#[test]
fn serve_rejects_odd_dual_work_size_before_gadget_setup() {
    // Validation runs before the UDC lookup/gadget bind, so this needs no USB
    // device.
    let out = run_with_timeout(
        &[
            "serve",
            "--block",
            "ram=1M",
            "--usb",
            "--banks",
            "dual",
            "--work-buf-size",
            "1025",
        ],
        10,
    );
    assert!(!out.status.success());
    let err = String::from_utf8_lossy(&out.stderr);
    assert!(
        err.contains("must be even"),
        "expected an even-total rejection, got: {err}"
    );
}

/// SIGINT → graceful shutdown → exit 0: the accept
/// loop is woken, `serve()` returns, backends are sync()ed, process exits 0.
#[cfg(unix)]
#[test]
fn serve_exits_cleanly_on_sigint() {
    use std::io::BufRead;
    use std::sync::mpsc;
    use std::time::Duration;

    let mut child = Command::new(env!("CARGO_BIN_EXE_snowscsi"))
        .args(["serve", "--block", "ram=1M", "--iscsi", "127.0.0.1:0"])
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::piped())
        .spawn()
        .expect("spawn snowscsi");

    // Wait until the server announces readiness on stderr (the log line is
    // emitted after the signal handler is installed).
    let (ready_tx, ready_rx) = mpsc::channel();
    {
        let stderr = child.stderr.take().expect("child stderr");
        std::thread::spawn(move || {
            let mut line = String::new();
            let mut reader = std::io::BufReader::new(stderr);
            while reader.read_line(&mut line).map(|n| n > 0).unwrap_or(false) {
                if line.contains("listening") {
                    let _ = ready_tx.send(());
                    return;
                }
                line.clear();
            }
        });
    }

    if ready_rx.recv_timeout(Duration::from_secs(5)).is_err() {
        let _ = Command::new("kill")
            .arg("-KILL")
            .arg(child.id().to_string())
            .status();
        let _ = child.wait();
        panic!("snowscsi did not announce 'listening'");
    }

    let sent = Command::new("kill")
        .arg("-INT")
        .arg(child.id().to_string())
        .status()
        .map(|s| s.success())
        .unwrap_or(false);
    assert!(sent, "kill -INT failed");

    let status = child.wait().expect("wait for snowscsi");
    assert!(status.success(), "snowscsi should exit 0 after SIGINT");
}

/// The same file path on two `--block` LUNs emits a dual-mount warning on
/// stderr while the server still starts and exits 0 after SIGINT.
#[cfg(unix)]
#[test]
fn serve_warns_on_dual_mount() {
    use std::io::BufRead;
    use std::sync::mpsc;
    use std::time::Duration;

    let dir = std::env::temp_dir();
    let img = dir.join(format!("snowscsi_dual_{}.img", std::process::id()));
    std::fs::write(&img, [0u8; 512]).unwrap();
    let path = img.to_string_lossy().to_string();

    let mut child = Command::new(env!("CARGO_BIN_EXE_snowscsi"))
        .args([
            "serve",
            "--block",
            &format!("img={path}"),
            "--block",
            &format!("img={path}"),
            "--iscsi",
            "127.0.0.1:0",
        ])
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::piped())
        .spawn()
        .expect("spawn snowscsi");

    // Collect dual-mount warnings until the server is ready (the warning is
    // emitted before bind, the "listening" line after the signal handler).
    let (ready_tx, ready_rx) = mpsc::channel();
    {
        let stderr = child.stderr.take().expect("child stderr");
        std::thread::spawn(move || {
            let mut line = String::new();
            let mut reader = std::io::BufReader::new(stderr);
            let mut warnings = Vec::new();
            while reader.read_line(&mut line).map(|n| n > 0).unwrap_or(false) {
                if line.contains("warning:") {
                    warnings.push(line.clone());
                }
                if line.contains("listening") {
                    let _ = ready_tx.send(warnings);
                    return;
                }
                line.clear();
            }
            let _ = ready_tx.send(warnings);
        });
    }

    let warnings = ready_rx
        .recv_timeout(Duration::from_secs(5))
        .unwrap_or_else(|_| {
            let _ = Command::new("kill")
                .arg("-KILL")
                .arg(child.id().to_string())
                .status();
            let _ = child.wait();
            panic!("snowscsi did not announce 'listening'");
        });
    assert!(
        warnings.iter().any(|w| w.contains(&path)),
        "expected a dual-mount warning for {path}, got {warnings:?}"
    );

    let sent = Command::new("kill")
        .arg("-INT")
        .arg(child.id().to_string())
        .status()
        .map(|s| s.success())
        .unwrap_or(false);
    assert!(sent, "kill -INT failed");

    let status = child.wait().expect("wait for snowscsi");
    assert!(status.success(), "snowscsi should exit 0 after SIGINT");

    let _ = std::fs::remove_file(&img);
}

/// `serve --block img=<iso>,profile=cd` starts with a lazy CD-ROM LUN,
/// announces 'listening' and exits 0 after SIGINT (graceful shutdown syncs
/// the read-only backend).
#[cfg(unix)]
#[test]
fn serve_starts_with_cdblock() {
    use std::io::BufRead;
    use std::sync::mpsc;
    use std::time::Duration;

    let dir = std::env::temp_dir();
    let iso = dir.join(format!("snowscsi_cdblock_{}.iso", std::process::id()));
    // 2048 * 64 bytes = 64 sectors; sparse is fine (only capacity is read).
    let f = std::fs::File::create(&iso).unwrap();
    f.set_len(2048 * 64).unwrap();
    drop(f);
    let path = iso.to_string_lossy().to_string();

    let mut child = Command::new(env!("CARGO_BIN_EXE_snowscsi"))
        .args([
            "serve",
            "--block",
            &format!("img={path},profile=cd"),
            "--iscsi",
            "127.0.0.1:0",
        ])
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::piped())
        .spawn()
        .expect("spawn snowscsi");

    let (ready_tx, ready_rx) = mpsc::channel();
    {
        let stderr = child.stderr.take().expect("child stderr");
        std::thread::spawn(move || {
            let mut line = String::new();
            let mut reader = std::io::BufReader::new(stderr);
            while reader.read_line(&mut line).map(|n| n > 0).unwrap_or(false) {
                if line.contains("listening") {
                    let _ = ready_tx.send(());
                    return;
                }
                line.clear();
            }
        });
    }

    if ready_rx.recv_timeout(Duration::from_secs(5)).is_err() {
        let _ = Command::new("kill")
            .arg("-KILL")
            .arg(child.id().to_string())
            .status();
        let _ = child.wait();
        panic!("snowscsi did not announce 'listening'");
    }

    let sent = Command::new("kill")
        .arg("-INT")
        .arg(child.id().to_string())
        .status()
        .map(|s| s.success())
        .unwrap_or(false);
    assert!(sent, "kill -INT failed");

    let status = child.wait().expect("wait for snowscsi");
    assert!(status.success(), "snowscsi should exit 0 after SIGINT");

    let _ = std::fs::remove_file(&iso);
}

/// `serve --cdrom img=<iso>` starts a flat CD-ROM LUN (full MMC), announces
/// 'listening' and exits 0 after SIGINT.
#[cfg(unix)]
#[test]
fn serve_starts_with_cdrom_flat() {
    use std::io::BufRead;
    use std::sync::mpsc;
    use std::time::Duration;

    let dir = std::env::temp_dir();
    let iso = dir.join(format!("snowscsi_cdrom_{}.iso", std::process::id()));
    let f = std::fs::File::create(&iso).unwrap();
    f.set_len(2048 * 64).unwrap();
    drop(f);
    let path = iso.to_string_lossy().to_string();

    let mut child = Command::new(env!("CARGO_BIN_EXE_snowscsi"))
        .args([
            "serve",
            "--cdrom",
            &format!("img={path}"),
            "--iscsi",
            "127.0.0.1:0",
        ])
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::piped())
        .spawn()
        .expect("spawn snowscsi");

    let (ready_tx, ready_rx) = mpsc::channel();
    {
        let stderr = child.stderr.take().expect("child stderr");
        std::thread::spawn(move || {
            let mut line = String::new();
            let mut reader = std::io::BufReader::new(stderr);
            while reader.read_line(&mut line).map(|n| n > 0).unwrap_or(false) {
                if line.contains("listening") {
                    let _ = ready_tx.send(());
                    return;
                }
                line.clear();
            }
        });
    }

    if ready_rx.recv_timeout(Duration::from_secs(5)).is_err() {
        let _ = Command::new("kill")
            .arg("-KILL")
            .arg(child.id().to_string())
            .status();
        let _ = child.wait();
        panic!("snowscsi did not announce 'listening'");
    }

    let sent = Command::new("kill")
        .arg("-INT")
        .arg(child.id().to_string())
        .status()
        .map(|s| s.success())
        .unwrap_or(false);
    assert!(sent, "kill -INT failed");

    let status = child.wait().expect("wait for snowscsi");
    assert!(status.success(), "snowscsi should exit 0 after SIGINT");

    let _ = std::fs::remove_file(&iso);
}

/// `serve --cdrom live=<dir>` scans the directory into a live ISO9660
/// CD-ROM, announces 'listening' and exits 0 after SIGINT.
#[cfg(unix)]
#[test]
fn serve_starts_with_cdrom_live() {
    use std::io::BufRead;
    use std::sync::mpsc;
    use std::time::Duration;

    let dir = std::env::temp_dir().join(format!("snowscsi_live_{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    std::fs::write(dir.join("DATA.BIN"), vec![0x42u8; 2048]).unwrap();
    let path = dir.to_string_lossy().to_string();

    let mut child = Command::new(env!("CARGO_BIN_EXE_snowscsi"))
        .args([
            "serve",
            "--cdrom",
            &format!("live={path}"),
            "--iscsi",
            "127.0.0.1:0",
        ])
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::piped())
        .spawn()
        .expect("spawn snowscsi");

    let (ready_tx, ready_rx) = mpsc::channel();
    {
        let stderr = child.stderr.take().expect("child stderr");
        std::thread::spawn(move || {
            let mut line = String::new();
            let mut reader = std::io::BufReader::new(stderr);
            while reader.read_line(&mut line).map(|n| n > 0).unwrap_or(false) {
                if line.contains("listening") {
                    let _ = ready_tx.send(());
                    return;
                }
                line.clear();
            }
        });
    }

    if ready_rx.recv_timeout(Duration::from_secs(5)).is_err() {
        let _ = Command::new("kill")
            .arg("-KILL")
            .arg(child.id().to_string())
            .status();
        let _ = child.wait();
        panic!("snowscsi did not announce 'listening'");
    }

    let sent = Command::new("kill")
        .arg("-INT")
        .arg(child.id().to_string())
        .status()
        .map(|s| s.success())
        .unwrap_or(false);
    assert!(sent, "kill -INT failed");

    let status = child.wait().expect("wait for snowscsi");
    assert!(status.success(), "snowscsi should exit 0 after SIGINT");

    let _ = std::fs::remove_dir_all(&dir);
}

/// The removed `imgdir=` backing is rejected (the flat bundle spelling is
/// `bundle=`) and the error names the flag it came from.
#[test]
fn serve_rejects_removed_imgdir() {
    let out = run(&["serve", "--cdrom", "imgdir=/tmp", "--iscsi", "127.0.0.1:0"]);
    assert!(!out.status.success());
    let err = String::from_utf8_lossy(&out.stderr);
    assert!(
        err.contains("imgdir") && err.contains("--cdrom"),
        "expected an imgdir/--cdrom error, got: {err}"
    );
}

/// `serve` never creates a bundle: a `--block bundle=<dir>` without a
/// `SNOWBUNDLE` manifest is rejected with a create hint, and a missing
/// directory is not created.
#[cfg(feature = "bundle")]
#[test]
fn serve_rejects_bundle_without_manifest() {
    let dir = std::env::temp_dir().join(format!("snowscsi_bundleno_{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();

    let out = run(&[
        "serve",
        "--block",
        &format!("bundle={}", dir.display()),
        "--iscsi",
        "127.0.0.1:0",
    ]);
    assert!(!out.status.success());
    let err = String::from_utf8_lossy(&out.stderr);
    assert!(
        err.contains("SNOWBUNDLE") && err.contains("bundle-create"),
        "expected a missing-manifest error, got: {err}"
    );
    let _ = std::fs::remove_dir_all(&dir);

    let missing = std::env::temp_dir().join(format!("snowscsi_bundlemiss_{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&missing);
    let out = run(&[
        "serve",
        "--block",
        &format!("bundle={}", missing.display()),
        "--iscsi",
        "127.0.0.1:0",
    ]);
    assert!(!out.status.success());
    assert!(
        !missing.exists(),
        "serve must not create a bundle directory"
    );
    let _ = std::fs::remove_dir_all(&missing);
}

/// `bundle-create flat` writes the manifest, then `serve --block bundle=`
/// opens a directory-chunked disk, announces 'listening' and exits 0 after
/// SIGINT. Chunks only materialize on the first host write.
#[cfg(all(unix, feature = "bundle"))]
#[test]
fn serve_starts_with_bundle_disk() {
    use std::io::BufRead;
    use std::sync::mpsc;
    use std::time::Duration;

    let dir = std::env::temp_dir().join(format!("snowscsi_bundle_{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    let path = dir.to_string_lossy().to_string();

    let created = run(&[
        "bundle-create",
        "flat",
        "--dir",
        &path,
        "--size",
        "8M",
        "--sector",
        "512",
    ]);
    assert!(
        created.status.success(),
        "bundle-create failed:\n{}",
        String::from_utf8_lossy(&created.stderr)
    );
    assert!(dir.join("SNOWBUNDLE").is_file());

    let mut child = Command::new(env!("CARGO_BIN_EXE_snowscsi"))
        .args([
            "serve",
            "--block",
            &format!("bundle={path}"),
            "--iscsi",
            "127.0.0.1:0",
        ])
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::piped())
        .spawn()
        .expect("spawn snowscsi");

    let (ready_tx, ready_rx) = mpsc::channel();
    {
        let stderr = child.stderr.take().expect("child stderr");
        std::thread::spawn(move || {
            let mut line = String::new();
            let mut reader = std::io::BufReader::new(stderr);
            while reader.read_line(&mut line).map(|n| n > 0).unwrap_or(false) {
                if line.contains("listening") {
                    let _ = ready_tx.send(());
                    return;
                }
                line.clear();
            }
        });
    }

    if ready_rx.recv_timeout(Duration::from_secs(5)).is_err() {
        let _ = Command::new("kill")
            .arg("-KILL")
            .arg(child.id().to_string())
            .status();
        let _ = child.wait();
        panic!("snowscsi did not announce 'listening'");
    }

    let sent = Command::new("kill")
        .arg("-INT")
        .arg(child.id().to_string())
        .status()
        .map(|s| s.success())
        .unwrap_or(false);
    assert!(sent, "kill -INT failed");

    let status = child.wait().expect("wait for snowscsi");
    assert!(status.success(), "snowscsi should exit 0 after SIGINT");

    // `bundle-create` wrote the manifest; `serve` only opened it.
    let header = std::fs::read(dir.join("SNOWBUNDLE")).unwrap_or_default();
    let header = String::from_utf8_lossy(&header);
    assert!(
        header.contains("magic = snow_bundle"),
        "SNOWBUNDLE magic missing: {header}"
    );
    assert!(
        header.contains("kind = flat"),
        "SNOWBUNDLE kind missing: {header}"
    );
    assert!(
        header.contains("virtual_size = 8388608"),
        "SNOWBUNDLE size missing: {header}"
    );
    assert!(
        header.contains("sector_size = 512"),
        "SNOWBUNDLE sector missing: {header}"
    );

    let _ = std::fs::remove_dir_all(&dir);
}

/// `bundle-info` reports a created flat bundle and exits 2 for a plain
/// directory carrying no manifest.
#[cfg(feature = "bundle")]
#[test]
fn bundle_info_reports_a_bundle() {
    let dir = std::env::temp_dir().join(format!("snowscsi_bundleinfo_{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    let path = dir.to_string_lossy().to_string();
    let created = run(&[
        "bundle-create",
        "flat",
        "--dir",
        &path,
        "--size",
        "8M",
        "--chunk",
        "1M",
    ]);
    assert!(created.status.success());

    let out = run(&["bundle-info", &path]);
    assert!(out.status.success());
    let text = String::from_utf8_lossy(&out.stdout);
    assert!(text.contains("kind = flat"), "info output:\n{text}");
    assert!(text.contains("virtual_size = 8388608"), "info:\n{text}");
    assert!(text.contains("chunk_size = 1048576"), "info:\n{text}");
    assert!(text.contains("sector_size = 512"), "info:\n{text}");
    assert!(text.contains("crc = present"), "info:\n{text}");

    let _ = std::fs::remove_dir_all(&dir);

    let plain = std::env::temp_dir().join(format!("snowscsi_plaininfo_{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&plain);
    std::fs::create_dir_all(&plain).unwrap();
    let out = run(&["bundle-info", &plain.to_string_lossy()]);
    assert_eq!(out.status.code(), Some(2));
    let text = String::from_utf8_lossy(&out.stdout);
    assert!(text.contains("not a bundle"), "info output:\n{text}");
    let _ = std::fs::remove_dir_all(&plain);
}

/// `--block img=<file>,ro` opens the plane read-only: on a read-only file the
/// old `r+b` open would fail outright, so `listening` proves the fix. Skipped
/// when running as root (permissions are not enforced for root).
#[cfg(unix)]
#[test]
fn serve_starts_with_read_only_img() {
    use std::os::unix::fs::PermissionsExt;

    if !can_simulate_read_only() {
        eprintln!("skipping: cannot simulate read-only media (running as root)");
        return;
    }
    let img = std::env::temp_dir().join(format!("snowscsi_ro_img_{}.img", std::process::id()));
    std::fs::write(&img, [0u8; 512]).unwrap();
    std::fs::set_permissions(&img, std::fs::Permissions::from_mode(0o444)).unwrap();
    let spec = format!("img={},ro", img.to_string_lossy());

    run_serve_until_ready_then_sigint(&["serve", "--block", &spec, "--iscsi", "127.0.0.1:0"]);

    let _ = std::fs::set_permissions(&img, std::fs::Permissions::from_mode(0o644));
    let _ = std::fs::remove_file(&img);
}

/// `--block bundle=<dir>,ro` opens the plane read-only so it works on a
/// read-only directory (simulated here). Skipped when running as root.
#[cfg(all(unix, feature = "bundle"))]
#[test]
fn serve_starts_with_read_only_bundle() {
    use std::os::unix::fs::PermissionsExt;

    if !can_simulate_read_only() {
        eprintln!("skipping: cannot simulate read-only media (running as root)");
        return;
    }
    let dir = std::env::temp_dir().join(format!("snowscsi_ro_bundle_{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    let path = dir.to_string_lossy().to_string();

    // Materialize the bundle + manifest with `bundle-create`.
    let created = run(&[
        "bundle-create",
        "flat",
        "--dir",
        &path,
        "--size",
        "8M",
        "--sector",
        "512",
    ]);
    assert!(created.status.success());
    assert!(dir.join("SNOWBUNDLE").is_file());

    // Simulate read-only media.
    std::fs::set_permissions(
        dir.join("SNOWBUNDLE"),
        std::fs::Permissions::from_mode(0o444),
    )
    .unwrap();
    std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o555)).unwrap();

    let ro = format!("bundle={path},ro");
    run_serve_until_ready_then_sigint(&["serve", "--block", &ro, "--iscsi", "127.0.0.1:0"]);

    let _ = std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o755));
    let _ = std::fs::remove_dir_all(&dir);
}

/// `--cdrom bundle=<flat>` is optical media, so it opens read-only even
/// without `ro`: a 0444 chunk and a 0555 directory must still serve.
/// Skipped when running as root.
#[cfg(all(unix, feature = "bundle", feature = "cdrom"))]
#[test]
fn serve_starts_with_read_only_flat_cdrom_bundle() {
    use std::os::unix::fs::PermissionsExt;

    if !can_simulate_read_only() {
        eprintln!("skipping: cannot simulate read-only media (running as root)");
        return;
    }
    let dir = std::env::temp_dir().join(format!("snowscsi_ro_cdbundle_{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    let path = dir.to_string_lossy().to_string();

    let created = run(&[
        "bundle-create",
        "flat",
        "--dir",
        &path,
        "--size",
        "8M",
        "--chunk",
        "1M",
        "--sector",
        "2048",
    ]);
    assert!(
        created.status.success(),
        "bundle-create flat failed:\n{}",
        String::from_utf8_lossy(&created.stderr)
    );
    // A read-only chunk proves the optical plane never opens it for writing.
    std::fs::write(dir.join("000000.img"), [0u8; 4096]).unwrap();

    for name in ["SNOWBUNDLE", "000000.img"] {
        std::fs::set_permissions(dir.join(name), std::fs::Permissions::from_mode(0o444)).unwrap();
    }
    std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o555)).unwrap();

    // No `ro`: `--cdrom` implies it for a flat bundle.
    run_serve_until_ready_then_sigint(&[
        "serve",
        "--cdrom",
        &format!("bundle={path}"),
        "--iscsi",
        "127.0.0.1:0",
    ]);

    let _ = std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o755));
    let _ = std::fs::remove_dir_all(&dir);
}

/// `serve --cdrom dvdram=ram:<size>` materializes an in-memory UDF 2.01
/// DVD+RW, announces 'listening' and exits 0 after SIGINT.
#[cfg(all(unix, feature = "dvdram"))]
#[test]
fn serve_starts_with_dvdram_ram() {
    use std::io::BufRead;
    use std::sync::mpsc;
    use std::time::Duration;

    let mut child = Command::new(env!("CARGO_BIN_EXE_snowscsi"))
        .args([
            "serve",
            "--cdrom",
            "dvdram=ram:16M",
            "--iscsi",
            "127.0.0.1:0",
        ])
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::piped())
        .spawn()
        .expect("spawn snowscsi");

    let (ready_tx, ready_rx) = mpsc::channel();
    {
        let stderr = child.stderr.take().expect("child stderr");
        std::thread::spawn(move || {
            let mut line = String::new();
            let mut reader = std::io::BufReader::new(stderr);
            while reader.read_line(&mut line).map(|n| n > 0).unwrap_or(false) {
                if line.contains("listening") {
                    let _ = ready_tx.send(());
                    return;
                }
                line.clear();
            }
        });
    }

    if ready_rx.recv_timeout(Duration::from_secs(5)).is_err() {
        let _ = Command::new("kill")
            .arg("-KILL")
            .arg(child.id().to_string())
            .status();
        let _ = child.wait();
        panic!("snowscsi did not announce 'listening'");
    }

    let sent = Command::new("kill")
        .arg("-INT")
        .arg(child.id().to_string())
        .status()
        .map(|s| s.success())
        .unwrap_or(false);
    assert!(sent, "kill -INT failed");

    let status = child.wait().expect("wait for snowscsi");
    assert!(status.success(), "snowscsi should exit 0 after SIGINT");
}

/// `dvdram=<file>` on a blank existing file opens as-is: the device presents a
/// blank random-writable DVD-RAM and the host formats it.
#[cfg(all(unix, feature = "dvdram"))]
#[test]
fn serve_dvdram_file_opens_as_is() {
    use std::io::BufRead;
    use std::sync::mpsc;
    use std::time::Duration;

    let dir = std::env::temp_dir();
    let img = dir.join(format!("snowscsi_dvdram_{}.img", std::process::id()));
    let f = std::fs::File::create(&img).unwrap();
    f.set_len(16 * 1024 * 1024).unwrap();
    drop(f);
    let path = img.to_string_lossy().to_string();

    // Blank file + no mkfs → opens as-is, announces 'listening'.
    let mut child = Command::new(env!("CARGO_BIN_EXE_snowscsi"))
        .args([
            "serve",
            "--cdrom",
            &format!("dvdram={path}"),
            "--iscsi",
            "127.0.0.1:0",
        ])
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::piped())
        .spawn()
        .expect("spawn snowscsi");

    let (ready_tx, ready_rx) = mpsc::channel();
    {
        let stderr = child.stderr.take().expect("child stderr");
        std::thread::spawn(move || {
            let mut line = String::new();
            let mut reader = std::io::BufReader::new(stderr);
            while reader.read_line(&mut line).map(|n| n > 0).unwrap_or(false) {
                if line.contains("listening") {
                    let _ = ready_tx.send(());
                    return;
                }
                line.clear();
            }
        });
    }

    if ready_rx.recv_timeout(Duration::from_secs(5)).is_err() {
        let _ = Command::new("kill")
            .arg("-KILL")
            .arg(child.id().to_string())
            .status();
        let _ = child.wait();
        panic!("snowscsi did not announce 'listening'");
    }

    let sent = Command::new("kill")
        .arg("-INT")
        .arg(child.id().to_string())
        .status()
        .map(|s| s.success())
        .unwrap_or(false);
    assert!(sent, "kill -INT failed");

    let status = child.wait().expect("wait for snowscsi");
    assert!(status.success(), "snowscsi should exit 0 after SIGINT");

    let _ = std::fs::remove_file(&img);
}

/// The same file path as both `--block` and `--cdrom` emits a dual-mount
/// warning on stderr before the server starts.
#[cfg(unix)]
#[test]
fn serve_warns_on_block_and_cdrom_dual_mount() {
    use std::io::BufRead;
    use std::sync::mpsc;
    use std::time::Duration;

    let dir = std::env::temp_dir();
    let img = dir.join(format!("snowscsi_dualcdrom_{}.iso", std::process::id()));
    // Not a valid ISO, but existence is all the CLI checks up front.
    std::fs::write(&img, [0u8; 2048]).unwrap();
    let path = img.to_string_lossy().to_string();

    let mut child = Command::new(env!("CARGO_BIN_EXE_snowscsi"))
        .args([
            "serve",
            "--block",
            &format!("img={path}"),
            "--cdrom",
            &format!("img={path}"),
            "--iscsi",
            "127.0.0.1:0",
        ])
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::piped())
        .spawn()
        .expect("spawn snowscsi");

    let (ready_tx, ready_rx) = mpsc::channel();
    {
        let stderr = child.stderr.take().expect("child stderr");
        std::thread::spawn(move || {
            let mut line = String::new();
            let mut reader = std::io::BufReader::new(stderr);
            let mut warnings = Vec::new();
            while reader.read_line(&mut line).map(|n| n > 0).unwrap_or(false) {
                if line.contains("warning:") {
                    warnings.push(line.clone());
                }
                if line.contains("listening") {
                    let _ = ready_tx.send(warnings);
                    return;
                }
                line.clear();
            }
            let _ = ready_tx.send(warnings);
        });
    }

    let warnings = ready_rx
        .recv_timeout(Duration::from_secs(5))
        .unwrap_or_else(|_| {
            let _ = Command::new("kill")
                .arg("-KILL")
                .arg(child.id().to_string())
                .status();
            let _ = child.wait();
            panic!("snowscsi did not announce 'listening'");
        });
    assert!(
        warnings.iter().any(|w| w.contains(&path)),
        "expected a dual-mount warning for {path}, got {warnings:?}"
    );

    let sent = Command::new("kill")
        .arg("-INT")
        .arg(child.id().to_string())
        .status()
        .map(|s| s.success())
        .unwrap_or(false);
    assert!(sent, "kill -INT failed");

    let status = child.wait().expect("wait for snowscsi");
    assert!(status.success(), "snowscsi should exit 0 after SIGINT");

    let _ = std::fs::remove_file(&img);
}

/// Start an async-wire server with `extra`, connect once, then SIGINT it.
#[cfg(all(unix, feature = "tokio"))]
fn run_async_serve_then_sigint(extra: &[&str]) {
    use std::io::BufRead;
    use std::net::{SocketAddr, TcpStream};
    use std::sync::mpsc;
    use std::time::Duration;

    let mut args = vec![
        "serve",
        "--block",
        "ram=1M",
        "--iscsi",
        "127.0.0.1:0",
        "--wire",
        "async",
    ];
    args.extend_from_slice(extra);
    let mut child = Command::new(env!("CARGO_BIN_EXE_snowscsi"))
        .args(&args)
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::piped())
        .spawn()
        .expect("spawn snowscsi");

    // The listening line carries the ephemeral portal: `listening on ADDR with
    // …`. Report the address once the server is ready.
    let (ready_tx, ready_rx) = mpsc::channel();
    {
        let stderr = child.stderr.take().expect("child stderr");
        std::thread::spawn(move || {
            let mut line = String::new();
            let mut reader = std::io::BufReader::new(stderr);
            while reader.read_line(&mut line).map(|n| n > 0).unwrap_or(false) {
                if let Some(rest) = line.split("listening on ").nth(1) {
                    let addr = rest.split_whitespace().next().and_then(|a| a.parse().ok());
                    if let Some(addr) = addr {
                        let _ = ready_tx.send(addr);
                        return;
                    }
                }
                line.clear();
            }
        });
    }

    let addr: SocketAddr = ready_rx
        .recv_timeout(Duration::from_secs(5))
        .unwrap_or_else(|_| {
            let _ = Command::new("kill")
                .arg("-KILL")
                .arg(child.id().to_string())
                .status();
            let _ = child.wait();
            panic!("snowscsi did not announce 'listening' for the async wire");
        });

    // Open a connection and leave it idle: the server parks in the session
    // loop (or the accept loop) until the signal arrives.
    let conn = TcpStream::connect(addr).expect("connect to the async portal");
    std::thread::sleep(Duration::from_millis(100));

    let sent = Command::new("kill")
        .arg("-INT")
        .arg(child.id().to_string())
        .status()
        .map(|s| s.success())
        .unwrap_or(false);
    assert!(sent, "kill -INT failed");

    let status = child.wait().expect("wait for snowscsi");
    assert!(
        status.success(),
        "the async wire should exit 0 after SIGINT for {args:?}, got {status:?}"
    );
    drop(conn);
}

/// `--wire async` binds, accepts a TCP connection and shuts down cleanly on
/// SIGINT. The async accept loop is stopped by a notification rather than the
/// blocking path's probe connection; both storage models are exercised.
#[cfg(all(unix, feature = "tokio"))]
#[test]
fn serve_async_wire_accepts_and_exits_cleanly_on_sigint() {
    for extra in [&[][..], &["--banks", "dual"][..]] {
        run_async_serve_then_sigint(extra);
    }
}

/// The same file path as both `--block img=` and
/// `--block img=…,profile=cd` emits a dual-mount warning on stderr before the
/// server starts.
#[cfg(unix)]
#[test]
fn serve_warns_on_block_and_cdblock_dual_mount() {
    use std::io::BufRead;
    use std::sync::mpsc;
    use std::time::Duration;

    let dir = std::env::temp_dir();
    let img = dir.join(format!("snowscsi_dualcd_{}.img", std::process::id()));
    std::fs::write(&img, [0u8; 512]).unwrap();
    let path = img.to_string_lossy().to_string();

    let mut child = Command::new(env!("CARGO_BIN_EXE_snowscsi"))
        .args([
            "serve",
            "--block",
            &format!("img={path}"),
            "--block",
            &format!("img={path},profile=cd"),
            "--iscsi",
            "127.0.0.1:0",
        ])
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::piped())
        .spawn()
        .expect("spawn snowscsi");

    let (ready_tx, ready_rx) = mpsc::channel();
    {
        let stderr = child.stderr.take().expect("child stderr");
        std::thread::spawn(move || {
            let mut line = String::new();
            let mut reader = std::io::BufReader::new(stderr);
            let mut warnings = Vec::new();
            while reader.read_line(&mut line).map(|n| n > 0).unwrap_or(false) {
                if line.contains("warning:") {
                    warnings.push(line.clone());
                }
                if line.contains("listening") {
                    let _ = ready_tx.send(warnings);
                    return;
                }
                line.clear();
            }
            let _ = ready_tx.send(warnings);
        });
    }

    let warnings = ready_rx
        .recv_timeout(Duration::from_secs(5))
        .unwrap_or_else(|_| {
            let _ = Command::new("kill")
                .arg("-KILL")
                .arg(child.id().to_string())
                .status();
            let _ = child.wait();
            panic!("snowscsi did not announce 'listening'");
        });
    assert!(
        warnings.iter().any(|w| w.contains(&path)),
        "expected a dual-mount warning for {path}, got {warnings:?}"
    );

    let sent = Command::new("kill")
        .arg("-INT")
        .arg(child.id().to_string())
        .status()
        .map(|s| s.success())
        .unwrap_or(false);
    assert!(sent, "kill -INT failed");

    let status = child.wait().expect("wait for snowscsi");
    assert!(status.success(), "snowscsi should exit 0 after SIGINT");

    let _ = std::fs::remove_file(&img);
}

#[cfg(all(unix, feature = "cdr-bundle"))]
#[test]
fn serve_starts_with_cdr_bundle() {
    let dir = std::env::temp_dir().join(format!("snowscsi_cdrbundle_{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    let path = dir.to_string_lossy().to_string();

    let created = run(&["bundle-create", "cdr", "--dir", &path, "--medium", "cdr74"]);
    assert!(
        created.status.success(),
        "bundle-create cdr failed:\n{}",
        String::from_utf8_lossy(&created.stderr)
    );
    assert!(dir.join("SNOWBUNDLE").is_file());
    assert!(dir.join("toc.0").is_file());

    run_serve_until_ready_then_sigint(&[
        "serve",
        "--cdrom",
        &format!("bundle={path}"),
        "--iscsi",
        "127.0.0.1:0",
    ]);

    let _ = std::fs::remove_dir_all(&dir);
}

/// A `kind = cdr` directory without any TOC slot is not a blank disc: serve
/// fails with a create hint and writes no TOC.
#[cfg(feature = "cdr-bundle")]
#[test]
fn serve_rejects_a_toc_less_cdr_bundle() {
    let dir = std::env::temp_dir().join(format!("snowscsi_notoc_{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    let path = dir.to_string_lossy().to_string();

    let created = run(&["bundle-create", "cdr", "--dir", &path]);
    assert!(created.status.success());
    std::fs::remove_file(dir.join("toc.0")).unwrap();
    let _ = std::fs::remove_file(dir.join("toc.1"));

    let out = run(&[
        "serve",
        "--cdrom",
        &format!("bundle={path}"),
        "--iscsi",
        "127.0.0.1:0",
    ]);
    assert!(!out.status.success());
    let err = String::from_utf8_lossy(&out.stderr);
    assert!(
        err.contains("no recordable-CD TOC") && err.contains("bundle-create cdr"),
        "expected a TOC-less error, got: {err}"
    );
    assert!(!dir.join("toc.0").exists(), "serve must not write a TOC");
    assert!(!dir.join("toc.1").exists(), "serve must not write a TOC");
    let _ = std::fs::remove_dir_all(&dir);
}

/// A `kind = cdr` bundle is MMC-only: `--block` reports the kind and points at
/// `--cdrom` even when `ro` (or `profile=cd`) is also present.
#[cfg(feature = "cdr-bundle")]
#[test]
fn serve_reports_a_cdr_bundle_under_block() {
    let dir = std::env::temp_dir().join(format!("snowscsi_cdrblock_{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    let path = dir.to_string_lossy().to_string();
    assert!(run(&["bundle-create", "cdr", "--dir", &path])
        .status
        .success());

    for spec in [
        format!("bundle={path},ro"),
        format!("bundle={path},profile=cd"),
    ] {
        let out = run(&["serve", "--block", &spec, "--iscsi", "127.0.0.1:0"]);
        assert!(!out.status.success());
        let err = String::from_utf8_lossy(&out.stderr);
        assert!(
            err.contains("kind 'cdr'") && err.contains("--cdrom"),
            "expected the kind/suggestion, got: {err}"
        );
    }
    let _ = std::fs::remove_dir_all(&dir);
}

/// `--print-config` returns before the password is read, so an encrypted LUN
/// never prompts (and does not need a sidecar) in that mode.
#[cfg(feature = "cipher")]
#[test]
fn cipher_print_config_does_not_prompt() {
    let dir = std::env::temp_dir().join(format!("snowscsi_ciphercfg_{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    let image = dir.join("disk.img");
    std::fs::write(&image, [0u8; 4096]).unwrap();
    let password = dir.join("pw");
    std::fs::write(&password, b"secret\n").unwrap();

    let out = run(&[
        "serve",
        "--block",
        &format!("img={},cipher", image.display()),
        "--password-file",
        &password.display().to_string(),
        "--usb",
        "--print-config",
    ]);
    assert!(
        out.status.success(),
        "print-config failed:\n{}",
        String::from_utf8_lossy(&out.stderr)
    );
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(
        stdout.contains("backing=img"),
        "print-config line:\n{stdout}"
    );
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        !stderr.contains("password:"),
        "print-config must not prompt:\n{stderr}"
    );

    let _ = std::fs::remove_dir_all(&dir);
}

/// A cipher-bearing image without its sidecar and one with a wrong-length key
/// both fail hard instead of serving plaintext.
#[cfg(feature = "cipher")]
#[test]
fn cipher_serve_rejects_missing_sidecar_and_bad_key() {
    let dir = std::env::temp_dir().join(format!("snowscsi_cipherbad_{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    let image = dir.join("disk.img");
    std::fs::write(&image, [0u8; 4096]).unwrap();
    let password = dir.join("pw");
    std::fs::write(&password, b"secret\n").unwrap();

    let out = run(&[
        "serve",
        "--block",
        &format!("img={},cipher", image.display()),
        "--password-file",
        &password.display().to_string(),
        "--iscsi",
        "127.0.0.1:0",
    ]);
    assert!(!out.status.success());
    let err = String::from_utf8_lossy(&out.stderr);
    assert!(err.contains("cannot read manifest"), "got: {err}");

    std::fs::write(
        format!("{}.SNOWBUNDLE", image.display()),
        b"magic = snow_bundle\nversion = 1\nkind = image\nsize = 4096\ncipher = xor\nkdf = none\nnonce = 0000000000000000\n",
    )
    .unwrap();
    let key = dir.join("key.bin");
    std::fs::write(&key, [0u8; 31]).unwrap();
    let out = run(&[
        "serve",
        "--block",
        &format!("img={},cipher,key={}", image.display(), key.display()),
        "--iscsi",
        "127.0.0.1:0",
    ]);
    assert!(!out.status.success());
    let err = String::from_utf8_lossy(&out.stderr);
    assert!(err.contains("exactly 32 bytes"), "got: {err}");

    let _ = std::fs::remove_dir_all(&dir);
}

/// The cipher option is rejected at parse time for the removable-card demo and
/// for non-file backings.
#[cfg(feature = "cipher")]
#[test]
fn cipher_serve_rejects_removable_and_ram() {
    let out = run(&[
        "serve",
        "--block",
        "img=/tmp/card.img,removable,cipher",
        "--iscsi",
        "127.0.0.1:0",
    ]);
    assert!(!out.status.success());
    let err = String::from_utf8_lossy(&out.stderr);
    assert!(
        err.contains("removable is not supported with cipher"),
        "got: {err}"
    );

    let out = run(&[
        "serve",
        "--block",
        "ram=1M,cipher",
        "--iscsi",
        "127.0.0.1:0",
    ]);
    assert!(!out.status.success());
    let err = String::from_utf8_lossy(&out.stderr);
    assert!(
        err.contains("only valid with img= or bundle="),
        "got: {err}"
    );
}
