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
    let dir = std::env::temp_dir().join(format!("snowscsi_roprobe_{}", std::process::id()));
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
    let out = run(&[
        "serve",
        "--block",
        "ram=1M",
        "--iscsi",
        "127.0.0.1:3260",
        "--work-buf-size",
        "1000",
    ]);
    assert!(!out.status.success());
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

/// An `imgdir=` backing is block-only: `--cdrom imgdir=<dir>` is rejected.
#[test]
fn serve_rejects_imgdir_cdrom() {
    let out = run(&["serve", "--cdrom", "imgdir=/tmp", "--iscsi", "127.0.0.1:0"]);
    assert!(!out.status.success());
    let err = String::from_utf8_lossy(&out.stderr);
    assert!(
        err.contains("imgdir") && err.contains("--cdrom"),
        "expected an imgdir/--cdrom error, got: {err}"
    );
}

/// A fresh `--block imgdir=<dir>` without `size=` is rejected: creating a new
/// bundle needs a virtual size.
#[cfg(feature = "bundle")]
#[test]
fn serve_rejects_bundle_without_size() {
    let dir = std::env::temp_dir().join(format!("snowscsi_bundlesz_{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    let path = dir.to_string_lossy().to_string();

    let out = run(&[
        "serve",
        "--block",
        &format!("imgdir={path}"),
        "--iscsi",
        "127.0.0.1:0",
    ]);
    assert!(!out.status.success());
    let err = String::from_utf8_lossy(&out.stderr);
    assert!(
        err.contains("size=") || err.contains("virtual_size"),
        "expected a missing-size error, got: {err}"
    );
    let _ = std::fs::remove_dir_all(&dir);
}

/// `serve --block imgdir=<dir>,size=8M` creates a directory-chunked disk,
/// announces 'listening' and exits 0 after SIGINT; the BUNDLE header and the
/// first chunk appear on disk.
#[cfg(all(unix, feature = "bundle"))]
#[test]
fn serve_starts_with_bundle_disk() {
    use std::io::BufRead;
    use std::sync::mpsc;
    use std::time::Duration;

    let dir = std::env::temp_dir().join(format!("snowscsi_bundle_{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    let path = dir.to_string_lossy().to_string();

    let mut child = Command::new(env!("CARGO_BIN_EXE_snowscsi"))
        .args([
            "serve",
            "--block",
            &format!("imgdir={path},size=8M"),
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

    // The directory was created (host-owned) and the BUNDLE header written by
    // the serve run. Chunks only materialize on first write (no initiator
    // traffic in this smoke), so only the header is asserted.
    let header = std::fs::read(dir.join("BUNDLE")).unwrap_or_default();
    let header = String::from_utf8_lossy(&header);
    assert!(
        header.contains("magic = snow_flat_bnd"),
        "BUNDLE magic missing: {header}"
    );
    assert!(
        header.contains("virtual_size = 8388608"),
        "BUNDLE size missing: {header}"
    );
    assert!(
        header.contains("sector_size = 512"),
        "BUNDLE sector missing: {header}"
    );

    let _ = std::fs::remove_dir_all(&dir);
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

/// `--block imgdir=<dir>,ro` opens the plane read-only so it works on a
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

    // Materialize the bundle + header with a writable run.
    let rw = format!("imgdir={path},size=8M");
    run_serve_until_ready_then_sigint(&["serve", "--block", &rw, "--iscsi", "127.0.0.1:0"]);
    assert!(dir.join("BUNDLE").is_file());

    // Simulate read-only media.
    std::fs::set_permissions(dir.join("BUNDLE"), std::fs::Permissions::from_mode(0o444)).unwrap();
    std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o555)).unwrap();

    let ro = format!("imgdir={path},ro");
    run_serve_until_ready_then_sigint(&["serve", "--block", &ro, "--iscsi", "127.0.0.1:0"]);

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
