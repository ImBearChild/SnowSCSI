#!/usr/bin/env python3
"""Shared helpers for the SnowSCSI external test suite.

Pure standard library. The suite treats the `snowscsi` binary as a black
box: it spawns `snowscsi serve` / `snowscsi mkisofs` as subprocesses and
drives them with external tools (`file`, `7z`, `isoinfo`, `bsdtar`,
`iscsiadm`, ...). Nothing here is compiled into cargo tests.

The initiator scaffolding (block-device discovery, `iscsiadm` session
lifecycle, ext4 mount helpers) lives here so the loopback tests share one
implementation instead of three drifting copies. Device detection uses a
`/sys/class/block/sd*` snapshot diff — the kernel-created device is the one
that appeared after the attach, never a stale entry matched by name.
"""

import collections
import os
import re
import shutil
import signal
import subprocess
import threading
import time

# Repo root = three dirs up from this file (tools/ext-test/harness.py).
REPO_ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

# The target name the server reports (mirrors `transport.rs` / target tests).
TARGET_NAME = "iqn.1970-01.local.snowscsi:target"

# Standard iSCSI loopback portal (`--iscsi auto` binds it when free).
ISCSI_STANDARD_PORT = 3260


def have_tool(name):
    """True if `name` is on PATH."""
    return shutil.which(name) is not None


def find_binary():
    """Locate the `snowscsi` binary.

    `SNOWSCSI_BIN` overrides; otherwise `target/{debug,release}/snowscsi`
    under the repo root (debug preferred, since `cargo build` is the default
    workflow). Raise if none is found.
    """
    override = os.environ.get("SNOWSCSI_BIN")
    if override:
        if not os.path.isfile(override):
            raise FileNotFoundError(f"SNOWSCSI_BIN is not a file: {override}")
        return override
    for profile in ("debug", "release"):
        cand = os.path.join(REPO_ROOT, "target", profile, "snowscsi")
        if os.path.isfile(cand):
            return cand
    raise FileNotFoundError(
        "snowscsi binary not found; build with `cargo build --workspace` "
        "or set SNOWSCSI_BIN"
    )


def is_root():
    """True if running as root (kernel loopback tests need it)."""
    return hasattr(os, "geteuid") and os.geteuid() == 0


# ── subprocess helper ───────────────────────────────────────────────

class CommandError(AssertionError):
    """A command exited non-zero under `sh(..., check=True)`."""

    def __init__(self, argv, returncode, stdout, stderr):
        self.argv = list(argv)
        self.returncode = returncode
        self.stdout = stdout
        self.stderr = stderr
        super().__init__(
            f"command failed (rc={returncode}): {' '.join(str(a) for a in argv)}\n"
            f"--- stdout ---\n{stdout[-2000:]}\n"
            f"--- stderr ---\n{stderr[-2000:]}"
        )


def sh(*argv, check=True, timeout=60, **kw):
    """Run a command, returning the completed process.

    `check` is honored explicitly (do not forward it through `**kw` into a
    different call shape): on a non-zero exit with `check=True` this raises
    [`CommandError`] carrying argv + stdout + stderr, so a failing step
    reports the real error instead of a misleading follow-up assertion.
    """
    r = subprocess.run(argv, capture_output=True, text=True, timeout=timeout, **kw)
    if check and r.returncode != 0:
        raise CommandError(argv, r.returncode, r.stdout, r.stderr)
    return r


# ── block device discovery ──────────────────────────────────────────

def sd_snapshot():
    """Names (`sdX`) of the SCSI block devices currently present."""
    try:
        return {n for n in os.listdir("/sys/class/block") if n.startswith("sd")}
    except OSError:
        return set()


def _device_size_or_none(dev):
    """`blockdev --getsize64`, or None if the node is not openable (yet)."""
    r = sh("blockdev", "--getsize64", dev, check=False)
    if r.returncode != 0:
        return None
    try:
        return int(r.stdout.strip())
    except ValueError:
        return None


def device_size(dev):
    """Capacity of `dev` in bytes (`blockdev --getsize64`)."""
    return int(sh("blockdev", "--getsize64", dev).stdout.strip())


def wait_new_sd(before, timeout=30, expected_bytes=None):
    """Wait for a *usable* new `sdX` (not in `before`); return its `/dev` path.

    A `/sys/class/block` entry can appear before the device node is openable
    (and a dead node can linger), so every candidate is probed with
    `blockdev --getsize64`. Unopenable candidates are skipped and re-tried;
    candidates whose capacity does not match `expected_bytes` are foreign
    devices and are skipped too. On timeout the error lists the candidates
    seen and the live iSCSI sessions.
    """
    deadline = time.monotonic() + timeout
    seen = {}
    while time.monotonic() < deadline:
        for name in sorted(sd_snapshot() - before):
            dev = f"/dev/{name}"
            size = _device_size_or_none(dev)
            if size is None:
                continue  # node not created / not attachable yet
            seen[name] = size
            if expected_bytes is None or size == expected_bytes:
                return dev
        time.sleep(0.2)
    detail = f"; candidates seen: {seen}" if seen else ""
    sessions = sh("iscsiadm", "-m", "session", "-P", "2", check=False).stdout
    raise AssertionError(
        f"no usable new /dev/sdX appeared within {timeout}s "
        f"(expected_bytes={expected_bytes}){detail}\n"
        f"--- iscsiadm sessions ---\n{sessions[-2000:]}"
    )


def wait_sd_gone(names, timeout=15):
    """Wait until every `sdX` in `names` has disappeared from the kernel."""
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if not any(os.path.exists(f"/sys/class/block/{n}") for n in names):
            return
        time.sleep(0.2)


def wait_sd_settled(timeout=10, quiet=1.0):
    """Wait until the `sd*` set stops changing for `quiet` seconds.

    Used after purging sessions: logout unregisters devices asynchronously,
    and taking the `before` snapshot too early would let the kernel reuse a
    removed device name for the next attach (hiding it from the diff).
    Returns the settled set.
    """
    deadline = time.monotonic() + timeout
    last = None
    stable_since = None
    while time.monotonic() < deadline:
        cur = sd_snapshot()
        if cur == last:
            if stable_since is None:
                stable_since = time.monotonic()
            elif time.monotonic() - stable_since >= quiet:
                return cur
        else:
            last = cur
            stable_since = None
        time.sleep(0.2)
    return sd_snapshot()


def device_size(dev):
    """Capacity of `dev` in bytes (`blockdev --getsize64`)."""
    return int(sh("blockdev", "--getsize64", dev).stdout.strip())


# ── ext4 mount helpers ──────────────────────────────────────────────

def make_mountpoint(prefix="snowscsi"):
    """Create and return a per-process mountpoint under `/mnt`."""
    path = f"/mnt/{prefix}-{os.getpid()}"
    os.makedirs(path, exist_ok=True)
    return path


def is_mounted(mount):
    r = sh("findmnt", "-n", "-o", "SOURCE", mount, check=False)
    return r.returncode == 0 and r.stdout.strip() != ""


def mount_ext4(dev, mount=None):
    """`mkfs.ext4` + `mount`; return the mountpoint.

    On a mount failure, raise with `mount`'s output plus a `dmesg` tail
    (kernel SCSI errors show up there, not in mount's stderr).
    """
    mount = mount or make_mountpoint()
    mk = sh("mkfs.ext4", "-q", dev, check=False, timeout=120)
    if mk.returncode != 0:
        raise AssertionError(
            f"mkfs.ext4 {dev} failed (rc={mk.returncode}):\n"
            f"--- stdout ---\n{mk.stdout}\n--- stderr ---\n{mk.stderr}\n"
            f"--- dmesg tail ---\n{sh('dmesg', check=False).stdout[-3000:]}"
        )
    mnt = sh("mount", dev, mount, check=False)
    if mnt.returncode != 0 or not is_mounted(mount):
        raise AssertionError(
            f"mount {dev} {mount} failed (rc={mnt.returncode}):\n"
            f"--- stdout ---\n{mnt.stdout}\n--- stderr ---\n{mnt.stderr}\n"
            f"--- dmesg tail ---\n{sh('dmesg', check=False).stdout[-3000:]}"
        )
    return mount


def unmount(mount, check=False):
    """Unmount `mount` (best-effort) and wait for it to settle."""
    if mount and is_mounted(mount):
        sh("umount", mount, check=check)
        time.sleep(0.5)


def raw_roundtrip(dev, size, block=1 << 20):
    """Write a per-offset pattern across `dev` and read it back.

    A `badblocks` substitute (it is often not installed): full-device raw
    READ/WRITE through the real block layer. Any failure includes a `dmesg`
    tail so the kernel's SCSI verdict is visible.
    """
    def pattern(off, n):
        return bytes(((off + j) * 31 + (off >> 20)) & 0xFF for j in range(n))

    def dmesg():
        return sh("dmesg", check=False).stdout[-3000:]

    try:
        with open(dev, "wb") as f:
            off = 0
            while off < size:
                n = min(block, size - off)
                f.write(pattern(off, n))
                off += n
        sh("sync")
        with open(dev, "rb") as f:
            off = 0
            while off < size:
                n = min(block, size - off)
                got = f.read(n)
                exp = pattern(off, n)
                if got != exp:
                    bad = next(i for i in range(n) if got[i] != exp[i])
                    raise AssertionError(
                        f"raw roundtrip mismatch on {dev} at byte {off + bad}"
                    )
                off += n
    except OSError as e:
        raise AssertionError(
            f"raw I/O to {dev} failed: {e}\n--- dmesg tail ---\n{dmesg()}"
        ) from None


def full_disk_test(dev, size):
    """`badblocks -wsv` when available, else a raw pattern roundtrip."""
    if have_tool("badblocks"):
        sh("badblocks", "-wsv", dev, timeout=300)
    else:
        print("  (badblocks not installed; using a raw pattern roundtrip)")
        raw_roundtrip(dev, size)


# ── SELinux / iscsid ────────────────────────────────────────────────

def selinux_enforcing():
    if not have_tool("getenforce"):
        return False
    r = sh("getenforce", check=False)
    return r.returncode == 0 and r.stdout.strip() == "Enforcing"


def selinux_allow_port(port):
    """Label `port` as `iscsi_port_t` so the iscsid_t domain may connect.

    Fedora only lets `iscsid_t` `name_connect` to `iscsi_port_t`
    (default 3260); an ephemeral test portal needs an explicit label.
    Returns True if a label was added. `timeout` guards a known
    `semanage` hang in this environment.
    """
    if not selinux_enforcing() or not have_tool("semanage"):
        return False
    r = sh(
        "timeout", "30", "semanage", "port", "-a",
        "-t", "iscsi_port_t", "-p", "tcp", str(port),
        check=False,
    )
    return r.returncode == 0


def selinux_deny_port(port):
    """Undo [`selinux_allow_port`] (best-effort; a missing entry is fine)."""
    if not selinux_enforcing() or not have_tool("semanage"):
        return
    sh(
        "timeout", "30", "semanage", "port", "-d",
        "-p", "tcp", str(port),
        check=False,
    )


def iscsid_running():
    if have_tool("systemctl"):
        r = sh("systemctl", "is-active", "iscsid", check=False)
        if r.returncode == 0 and r.stdout.strip() == "active":
            return True
    if have_tool("pgrep"):
        return sh("pgrep", "-x", "iscsid", check=False).returncode == 0
    return False


def start_iscsid():
    """Ensure `iscsid` runs. Returns True if this call started it."""
    if iscsid_running():
        return False
    if have_tool("systemctl"):
        sh("systemctl", "start", "iscsid", check=False)
    elif have_tool("iscsid"):
        sh("iscsid", check=False)
    return iscsid_running()


def stop_iscsid():
    if have_tool("systemctl"):
        sh("systemctl", "stop", "iscsid", check=False)


def iscsiadm_node_ok():
    """True if `iscsiadm -m node` works (empty node DB is fine)."""
    if not have_tool("iscsiadm"):
        return False
    # ISCSI_ERR_NO_OBJS_FOUND (21): readable but empty.
    return sh("iscsiadm", "-m", "node", check=False).returncode in (0, 21)


def _parse_session_portals(output, target):
    """Portals (`host:port`) of the sessions for `target` in iscsiadm output."""
    portals = set()
    for line in output.splitlines():
        if target not in line:
            continue
        for tok in line.split():
            host, _, port = tok.partition(":")
            port = port.split(",")[0]
            if host and port.isdigit():
                portals.add(f"{host}:{port}")
                break
    return portals


def wait_no_session(target=TARGET_NAME, timeout=15):
    """True once no session for `target` remains (or iscsiadm is unusable)."""
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        r = sh("iscsiadm", "-m", "session", "-P", "0", check=False)
        if r.returncode != 0 or target not in r.stdout:
            return True
        time.sleep(0.3)
    return False


def purge_target_sessions(target=TARGET_NAME, timeout=10):
    """Best-effort: log out + delete every session for `target` (any portal).

    A prior run can leave a logged-in session whose server is gone; its
    device then looks live while I/O fails. Each iscsiadm call is bounded by
    `timeout` so a hung kernel session cannot stall the suite.
    """
    if not have_tool("iscsiadm"):
        return
    r = sh("iscsiadm", "-m", "session", "-P", "0", check=False, timeout=timeout)
    purged = False
    for portal in _parse_session_portals(r.stdout, target):
        purged = True
        sh(
            "timeout", str(timeout), "iscsiadm", "-m", "node",
            "-T", target, "-p", portal, "--logout",
            check=False,
        )
        sh(
            "iscsiadm", "-m", "node", "-o", "delete",
            "-T", target, "-p", portal,
            check=False, timeout=timeout,
        )
    wait_no_session(target, timeout=timeout)
    if purged:
        # Let the kernel finish unregistering the removed devices, so the
        # next snapshot does not race a name being freed and reused.
        wait_sd_settled(timeout=10)


# ── iSCSI session (manual open-iscsi login) ─────────────────────────

class IscsiSession:
    """Manually drive one open-iscsi session to a snowscsi target.

    Register the node explicitly (the target rejects SendTargets), log in,
    and detect the resulting device by a `/sys/class/block` snapshot diff.
    `logout()` tears the session, node record and SELinux label down and
    waits for the kernel to drop the device. Every method is idempotent so
    it is safe to call from `tearDown`.
    """

    def __init__(self, portal, target=TARGET_NAME):
        # `portal` is the server's bound `host:port` (e.g. "127.0.0.1:3260").
        self.portal = portal
        self.target = target
        self.before = None
        self.device = None
        self._node_registered = False
        self._logged_in = False
        self._selinux_added = False

    def _portal_port(self):
        host, _, port = self.portal.rpartition(":")
        try:
            return int(port)
        except ValueError:
            return None

    def login(self, timeout=30, expected_bytes=None):
        """Register + login + wait for the device; return `/dev/sdX`."""
        # Clear any session left by a prior run first: a live session whose
        # server is gone yields a device that looks fine but fails I/O, and
        # would otherwise be a false candidate during detection.
        purge_target_sessions(self.target)
        self.before = sd_snapshot()
        sh(
            "iscsiadm", "-m", "node", "-o", "new",
            "-T", self.target, "-p", self.portal,
        )
        self._node_registered = True
        port = self._portal_port()
        if port is not None:
            self._selinux_added = selinux_allow_port(port)
        sh(
            "iscsiadm", "-m", "node",
            "-T", self.target, "-p", self.portal,
            "--login",
        )
        self._logged_in = True
        self.device = wait_new_sd(
            self.before, timeout=timeout, expected_bytes=expected_bytes
        )
        return self.device

    def logout(self):
        """Best-effort teardown, safe to call repeatedly."""
        if self._logged_in:
            sh(
                "iscsiadm", "-m", "node",
                "-T", self.target, "-p", self.portal,
                "--logout", check=False, timeout=30,
            )
            self._logged_in = False
        if self._node_registered:
            sh(
                "iscsiadm", "-m", "node", "-o", "delete",
                "-T", self.target, "-p", self.portal,
                check=False, timeout=30,
            )
            self._node_registered = False
        if self.device:
            wait_sd_gone([os.path.basename(self.device)], timeout=15)
            self.device = None
        if self._selinux_added and self._portal_port() is not None:
            selinux_deny_port(self._portal_port())
            self._selinux_added = False

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc, tb):
        self.logout()
        return False


# ── server lifecycle ────────────────────────────────────────────────

class ServerHandle:
    """Lifecycle of a `snowscsi serve` subprocess.

    By default starts the server on an ephemeral loopback port
    (`--iscsi 127.0.0.1:0`) and the caller drives open-iscsi manually (see
    [`IscsiSession`]). With `iscsi_auto=True` it instead passes
    `--iscsi auto`: the server binds the standard loopback portal
    (`127.0.0.1:3260`, falling back to an ephemeral port), registers and
    logs in the open-iscsi node itself, and waits for udev to expose the
    block device.

    stderr is drained by a background thread into a bounded ring buffer, so
    a chatty server can never block on a full pipe, and it is available for
    diagnostics. `self.addr` / `self.port` come from the `listening on
    <addr>` line. `__exit__` asserts a clean exit (0), so a graceful-shutdown
    regression fails the test even when the body passed.
    """

    def __init__(self, *serve_args, work_buf_size=None, iscsi_auto=False, verbose=None):
        self.serve_args = list(serve_args)
        self.work_buf_size = work_buf_size
        self.iscsi_auto = iscsi_auto
        # Log verbosity: 0 info, 1 debug, 2 trace. `SNOWSCSI_TEST_VERBOSE`
        # raises it for diagnostics without touching the tests.
        if verbose is None:
            try:
                verbose = int(os.environ.get("SNOWSCSI_TEST_VERBOSE", "0"))
            except ValueError:
                verbose = 0
        self.verbose = verbose
        self.proc = None
        self.addr = None
        self.port = None
        self._lines = collections.deque(maxlen=4000 if verbose else 400)
        self._ready = threading.Event()
        self._reader = None

    def __enter__(self):
        transport = "auto" if self.iscsi_auto else "127.0.0.1:0"
        cmd = [find_binary(), "serve", "--iscsi", transport]
        if self.verbose:
            cmd.append("-" + "v" * self.verbose)
        cmd.extend(self.serve_args)
        if self.work_buf_size:
            cmd += ["--work-buf-size", str(self.work_buf_size)]
        self.proc = subprocess.Popen(
            cmd,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.PIPE,
            text=True,
        )
        self._reader = threading.Thread(
            target=self._pump_stderr, name="snowscsi-stderr", daemon=True
        )
        self._reader.start()
        self._wait_ready()
        return self

    def _pump_stderr(self):
        try:
            for line in self.proc.stderr:
                self._lines.append(line)
                if self.addr is None:
                    m = re.search(r"listening on ([0-9.:]+)", line)
                    if m:
                        hostport = m.group(1)
                        if hostport.startswith("[") and "]" in hostport:
                            _, _, port = hostport[1:].partition("]:")
                        else:
                            _, _, port = hostport.rpartition(":")
                        self.addr = hostport
                        try:
                            self.port = int(port)
                        except ValueError:
                            self.port = None
                        self._ready.set()
        finally:
            # EOF (process exit) must also release `_wait_ready`.
            self._ready.set()

    def _wait_ready(self, timeout=10.0):
        """Wait for `listening on <addr>`; raise on early exit or timeout."""
        if not self._ready.wait(timeout):
            tail = self._tail()
            self._kill()
            raise TimeoutError(
                f"snowscsi did not announce 'listening' in {timeout}s; "
                f"stderr:\n{tail}"
            )
        if self.addr is None:
            rc = self.proc.poll()
            tail = self._tail()
            self._kill()
            raise RuntimeError(
                f"snowscsi exited early (rc={rc}) before 'listening':\n{tail}"
            )

    def log_tail(self, n=4096):
        """Recent server stderr (bounded ring buffer)."""
        return self._tail(n)

    def _tail(self, n=1024):
        return "".join(self._lines)[-n:]

    def _kill(self):
        if self.proc and self.proc.poll() is None:
            self.proc.kill()
            self.proc.wait()
        self._join_reader()

    def _join_reader(self):
        if self._reader is not None:
            self._reader.join(timeout=2)
            self._reader = None
        if self.proc and self.proc.stderr is not None:
            try:
                self.proc.stderr.close()
            except OSError:
                pass

    def __exit__(self, exc_type, exc, tb):
        self.stop()
        return False

    def stop(self):
        """SIGINT (graceful shutdown) then assert exit 0."""
        if self.proc is None:
            return
        try:
            if self.proc.poll() is None:
                self.proc.send_signal(signal.SIGINT)
                try:
                    self.proc.wait(timeout=10)
                except subprocess.TimeoutExpired:
                    self._kill()
                    raise AssertionError("snowscsi did not exit after SIGINT")
            if self.proc.returncode != 0:
                raise AssertionError(
                    f"snowscsi exited {self.proc.returncode} (expected 0 after "
                    f"SIGINT); tail:\n{self._tail()}"
                )
        finally:
            self._join_reader()
            self.proc = None


def run_snowscsi(args, cwd=None, timeout=120):
    """Run `snowscsi <args...>`, return CompletedProcess (check=False)."""
    return subprocess.run(
        [find_binary(), *args],
        cwd=cwd,
        capture_output=True,
        text=True,
        timeout=timeout,
    )


def mkisofs(src_dir, out_iso, label=None):
    """Run `snowscsi mkisofs`; return CompletedProcess."""
    args = ["mkisofs", src_dir, out_iso]
    if label:
        args += ["--label", label]
    return run_snowscsi(args)
