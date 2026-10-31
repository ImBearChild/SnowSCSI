#!/usr/bin/env python3
"""Real-kernel USB Mass Storage (BOT) loopback test (root).

Spawns `snowscsi serve --usb`, binds a FunctionFS gadget to a `dummy_hcd`
UDC, and lets the kernel's own `usb-storage` host driver attach and create a
`/dev/sdX`. Then exercises the full checklist through the real block layer:
capacity matches the backend, a `dd`/`badblocks` full-disk roundtrip, ext4
format / mount / write / read / fsck, and read-only backend write
protection.

Skipped unless: running as root, a `dummy_udc.0` UDC is present, and
configfs (`/sys/kernel/config/usb_gadget`) is writable. The test
auto-loads the test-only `dummy_hcd` module via `modprobe` (idempotent:
no-op if already loaded) and never unloads it, and auto-mounts configfs
at `/sys/kernel/config` if the distro has not already mounted it (most
do not), unmounting it again afterward. The runtime must also allow
Linux native aio (`io_setup`/`io_submit`/`io_getevents`); a
seccomp/container ban is not detectable up front and surfaces as a
failed first bulk transfer.

A `snowscsi serve --usb` killed without running its RAII cleanup leaves
its gadget bound to `dummy_udc.0`, and a UDC binds one gadget at a time:
the next run creates a new gadget, fails to bind and exits, which used to
show up only as an opaque "no usable new /dev/sdX" after 20 s. The suite
therefore reclaims stale test gadgets at class setup/teardown (and on a
failed bind) and reports a dead server's stderr immediately.
"""

import os
import re
import signal
import subprocess
import tempfile
import time
import unittest

from harness import (
    device_size,
    find_binary,
    have_tool,
    is_root,
    mount_ext4,
    sd_paths,
    sd_snapshot,
    sh,
    unmount,
    wait_sd_settled,
)

# Backend image: 32 MiB (enough for ext4), matching the iSCSI loopback RAM size.
IMG_SIZE = 32 * 1024 * 1024


def _usb_udc_present():
    return os.path.isdir("/sys/class/udc/dummy_udc.0")


def _configfs_writable():
    return os.path.isdir("/sys/kernel/config/usb_gadget")


def _ensure_configfs():
    """Ensure configfs is mounted at /sys/kernel/config (most distros do not
    mount it by default). Returns True if we mounted it — the caller must
    unmount it again via [`_release_configfs`].
    """
    if _configfs_writable() or not have_tool("mount"):
        return False
    os.makedirs("/sys/kernel/config", exist_ok=True)
    r = sh("mount", "-t", "configfs", "none", "/sys/kernel/config", check=False)
    return r.returncode == 0 and _configfs_writable()


def _release_configfs(mounted):
    if mounted:
        sh("umount", "/sys/kernel/config", check=False)


# ── stale-gadget reclamation ────────────────────────────────────────

# configfs gadget root (libcomposite) and the test-only UDC from dummy_hcd.
GADGET_ROOT = "/sys/kernel/config/usb_gadget"
TEST_UDC = "dummy_udc.0"


def _read_text(path):
    try:
        with open(path) as f:
            return f.read()
    except OSError:
        return None


def _log_tail(path, n=4096):
    """Tail of a server log file, or a placeholder if it is gone."""
    try:
        with open(path, errors="replace") as f:
            return f.read()[-n:]
    except OSError:
        return "<no server log>"


def _rmdir(path, retries=0, quiet=False):
    """`rmdir` a configfs directory (best effort).

    configfs removes its own attribute files on `rmdir`, so a plain
    `os.rmdir` is the correct teardown primitive here. Default groups such
    as `strings`/`configs` are not removable on their own and disappear
    with their parent, so those are removed quietly.
    """
    for attempt in range(retries + 1):
        try:
            os.rmdir(path)
            return True
        except FileNotFoundError:
            return True
        except OSError as e:
            if attempt < retries:
                time.sleep(0.1)
                continue
            if not quiet:
                print(f"    warning: could not rmdir {path}: {e}")
            return False
    return False


def _mounts_of_type(fstype):
    """Mountpoints of `fstype` from `/proc/mounts` (octal escapes decoded)."""
    try:
        with open("/proc/mounts") as f:
            lines = f.read().splitlines()
    except OSError:
        return []
    out = []
    for line in lines:
        fields = line.split()
        if len(fields) < 3 or fields[2] != fstype:
            continue
        out.append(
            re.sub(
                r"\\([0-7]{3})",
                lambda m: chr(int(m.group(1), 8)),
                fields[1],
            )
        )
    return out


def _unmount(path):
    """Unmount `path`, lazily as a fallback. True once it is gone."""
    if not os.path.ismount(path):
        return False
    r = sh("umount", path, check=False)
    if r.returncode != 0:
        sh("umount", "-l", path, check=False)
    return not os.path.ismount(path)


def _gadget_functions(gadget):
    """Function names (real directories, not symlinks) of a gadget."""
    fn_dir = os.path.join(gadget, "functions")
    try:
        names = os.listdir(fn_dir)
    except OSError:
        return []
    return [n for n in names if os.path.isdir(os.path.join(fn_dir, n))]


def _is_test_gadget(name):
    """True if the gadget is one of ours.

    The `usb-gadget` crate names its directories `usb-gadget<N>` and the CLI
    never overrides that. Requiring the prefix keeps another FunctionFS
    gadget a developer bound to the same test UDC untouched, even though it
    also carries an `ffs.` function.
    """
    return name.startswith("usb-gadget")


def _teardown_gadget(gadget, ffs_mounts):
    """Tear one gadget down in the order the kernel requires.

    Returns True when the gadget directory is gone.
    """
    # 1. Unbind from the UDC: a bound gadget cannot be dismantled.
    udc_path = os.path.join(gadget, "UDC")
    try:
        with open(udc_path, "w") as f:
            f.write("\n")
    except OSError as e:
        print(f"    warning: could not unbind {udc_path}: {e}")

    functions = _gadget_functions(gadget)

    # 2. Detach the FunctionFS mount (`ffs.<fn>` -> /dev/ffs-<fn>), which
    #    holds a reference to the ffs instance and blocks function removal.
    for fn in functions:
        if not fn.startswith("ffs."):
            continue
        mount = f"/dev/ffs-{fn[len('ffs.'):]}"
        candidates = {mount}
        candidates.update(
            m for m in ffs_mounts if os.path.basename(m) == os.path.basename(mount)
        )
        for candidate in sorted(candidates):
            if _unmount(candidate):
                print(f"    unmounted {candidate}")

    # 3. Drop the function symlink from every config.
    configs = os.path.join(gadget, "configs")
    try:
        config_dirs = [
            c
            for c in sorted(os.listdir(configs))
            if os.path.isdir(os.path.join(configs, c))
        ]
    except OSError:
        config_dirs = []
    for cfg in config_dirs:
        cfg_path = os.path.join(configs, cfg)
        try:
            entries = os.listdir(cfg_path)
        except OSError:
            continue
        for entry in entries:
            entry_path = os.path.join(cfg_path, entry)
            if not os.path.islink(entry_path):
                continue
            try:
                os.unlink(entry_path)
                print(f"    removed function link {entry_path}")
            except OSError as e:
                print(f"    warning: could not remove {entry_path}: {e}")

    # 4. Functions, then strings, then configs, then the gadget itself.
    for fn in functions:
        _rmdir(os.path.join(gadget, "functions", fn), retries=5)

    strings = os.path.join(gadget, "strings")
    try:
        langs = sorted(os.listdir(strings))
    except OSError:
        langs = []
    for lang in langs:
        _rmdir(os.path.join(strings, lang))
    _rmdir(strings, quiet=True)  # default group: goes with the gadget

    for cfg in config_dirs:
        cfg_path = os.path.join(configs, cfg)
        cfg_strings = os.path.join(cfg_path, "strings")
        try:
            langs = sorted(os.listdir(cfg_strings))
        except OSError:
            langs = []
        for lang in langs:
            _rmdir(os.path.join(cfg_strings, lang))
        _rmdir(cfg_strings, quiet=True)  # default group
        _rmdir(cfg_path)
    _rmdir(configs, quiet=True)  # default group
    _rmdir(gadget, retries=5)
    return not os.path.isdir(gadget)


def reclaim_stale_gadgets(udc=TEST_UDC):
    """Tear down test gadgets left bound to `udc` by a crashed/killed run.

    Only `dummy_udc.0` is ever touched, and that UDC belongs to the
    test-only `dummy_hcd` module, so no real controller and no gadget
    outside this loopback test can own it. A gadget is reclaimed only when
    it is still bound to that UDC *and* looks like ours (a `usb-gadget*`
    directory from the gadget crate, or an `ffs.` function); anything else
    is reported and left alone.

    Teardown order mirrors what the kernel requires: unbind the UDC,
    detach the FunctionFS mount, remove the function symlink from every
    config, then `rmdir` the function, the strings, the config and the
    gadget. Best effort throughout (a missing mount/symlink is fine).
    Returns the names of the reclaimed gadgets.
    """
    if not os.path.isdir(GADGET_ROOT):
        return []
    try:
        names = sorted(os.listdir(GADGET_ROOT))
    except OSError:
        return []
    ffs_mounts = _mounts_of_type("functionfs")
    reclaimed = []
    for name in names:
        gadget = os.path.join(GADGET_ROOT, name)
        if not os.path.isdir(gadget):
            continue
        bound = (_read_text(os.path.join(gadget, "UDC")) or "").strip()
        if bound != udc:
            continue
        if not _is_test_gadget(name):
            print(
                f"  note: {name} is bound to {udc} but does not look like a "
                f"test gadget; leaving it alone"
            )
            continue
        print(f"  reclaiming stale USB gadget {name} (bound to {udc})")
        if _teardown_gadget(gadget, ffs_mounts):
            reclaimed.append(name)
        else:
            print(f"    warning: {gadget} still exists after teardown")
    return reclaimed


class _UsbScenario:
    """Scenario shared by the per-mode test cases below."""

    # Extra `serve` arguments for this mode.
    EXTRA = ()

    @classmethod
    def setUpClass(cls):
        # Auto-load the test-only UDC module and the configfs gadget
        # framework (idempotent; we never unload them — they may be shared
        # with other tests/setups). libcomposite registers the
        # /sys/kernel/config/usb_gadget directory when loaded.
        if have_tool("modprobe"):
            sh("modprobe", "dummy_hcd", check=False)
            sh("modprobe", "libcomposite", check=False)
        if not _usb_udc_present():
            raise unittest.SkipTest(
                "dummy_hcd unavailable (modprobe dummy_hcd failed)"
            )
        # Mount configfs if the distro has not already (most do not); release
        # it again on the skip path since tearDownClass is not called then.
        cls._configfs_mounted = _ensure_configfs()
        if not _configfs_writable():
            _release_configfs(cls._configfs_mounted)
            raise unittest.SkipTest(
                "configfs not writable at /sys/kernel/config/usb_gadget"
            )
        # A run killed without its RAII cleanup leaves `usb-gadget0` bound to
        # dummy_udc.0; the next run creates `usb-gadget1`, cannot get the
        # (exclusive) UDC and exits. Reclaim before binding anything.
        try:
            if reclaim_stale_gadgets():
                # Dropping the stale gadget makes usb-storage remove its
                # device asynchronously; let the `sd*` set settle so setUp's
                # "before" snapshot cannot race a freed name being reused.
                wait_sd_settled(timeout=10)
        except Exception:
            # tearDownClass is not called when setUpClass raises.
            _release_configfs(cls._configfs_mounted)
            raise

    @classmethod
    def tearDownClass(cls):
        # Best effort: never leave a gadget bound to the test-only UDC, even
        # when the test body failed before its own cleanup could run.
        try:
            reclaim_stale_gadgets()
            wait_sd_settled(timeout=15)
        except Exception as e:  # never mask the test result
            print(f"  warning: stale gadget reclaim failed: {e}")
        _release_configfs(getattr(cls, "_configfs_mounted", False))

    def setUp(self):
        # Failure count at entry: tearDown keeps the server log when the
        # runner recorded a failure during this test.
        self._failures_at_setup = self._result_failure_count()
        self._logs = []
        # Snapshot the block devices before the server binds, so the device
        # usb-storage creates is unambiguously ours. Keep this snapshot for
        # the whole test: after a rebind the same device name may reappear.
        # The previous class's gadget/device may still be tearing down; taking
        # the snapshot too early lets a reused `sdX` name hide the new device.
        reclaim_stale_gadgets()
        wait_sd_settled(timeout=15)
        self.before = sd_snapshot()
        self.before_paths = sd_paths()
        fd, self.img = tempfile.mkstemp(prefix="snowscsi-usb-", suffix=".img")
        os.close(fd)
        os.truncate(self.img, IMG_SIZE)
        self.addCleanup(self._discard_image)
        self.mount = None
        self.server = None
        self.server = UsbServer(self.img, extra=self.EXTRA)
        self._logs.append(self.server.log_path)

    def tearDown(self):
        unmount(self.mount)
        self.mount = None
        try:
            if self.server:
                try:
                    self.server.stop()
                except AssertionError:
                    # A body failure is already recorded; a shutdown failure
                    # on an otherwise passing body must still be reported.
                    if not self._test_failed():
                        raise
                self.server = None
        finally:
            self._release_logs()

    def _release_logs(self):
        """Keep the CLI's stderr when the result is a failure.

        It carries the reason (a failed gadget bind, for instance) that the
        test-level assertion cannot see. Delete it only after a clean result.
        """
        for path in getattr(self, "_logs", []):
            if not path:
                continue
            if self._test_failed():
                print(
                    f"\n--- snowscsi USB server stderr (log kept: {path}) ---\n"
                    f"{_log_tail(path)}\n"
                    f"--- end server stderr ---"
                )
            else:
                try:
                    os.unlink(path)
                except OSError:
                    pass

    def _discard_image(self):
        try:
            os.unlink(self.img)
        except OSError:
            pass

    # ── helpers ─────────────────────────────────────────────────────

    def _result_failure_count(self):
        """Failures+errors the runner has recorded so far (0 outside a run)."""
        outcome = getattr(self, "_outcome", None)
        result = getattr(outcome, "result", None)
        if result is None:
            return 0
        return len(getattr(result, "failures", ())) + len(
            getattr(result, "errors", ())
        )

    def _test_failed(self):
        """True if the runner recorded a failure for this test.

        `self._outcome.success` cannot be used: modern unittest resets it
        to True for the tearDown part, so compare recorded failure counts.
        """
        return self._result_failure_count() > getattr(
            self, "_failures_at_setup", 0
        )

    def _wait_device(self, timeout=20):
        """Wait for our new `/dev/sdX`, failing fast if the server died.

        The server's exit status is polled alongside the block-device set:
        a failed gadget bind exits `snowscsi` immediately, and reporting
        its return code plus stderr here beats a 20 s wait that can only
        say "no usable new /dev/sdX".
        """
        deadline = time.monotonic() + timeout
        seen = {}
        while time.monotonic() < deadline:
            proc = getattr(self.server, "proc", None)
            rc = proc.poll() if proc is not None else None
            if rc is not None:
                raise AssertionError(
                    f"snowscsi serve --usb exited (rc={rc}) before the USB "
                    f"host device appeared (did the gadget bind fail?); "
                    f"server stderr:\n{self.server.log_tail()}"
                )
            current = sd_snapshot()
            paths = sd_paths()
            fresh = {
                n
                for n in current
                if n not in self.before
                or paths.get(n) != self.before_paths.get(n)
            }
            for name in sorted(fresh):
                dev = f"/dev/{name}"
                try:
                    size = device_size(dev)
                except (AssertionError, OSError):
                    continue  # node not created / not openable yet
                seen[name] = size
                if size == IMG_SIZE:
                    return dev
            time.sleep(0.2)
        raise AssertionError(
            f"no usable new /dev/sdX appeared within {timeout}s "
            f"(expected {IMG_SIZE} bytes; candidates seen: {seen})\n"
            f"before: {sorted(self.before)} paths: {self.before_paths}\n"
            f"after:  {sorted(sd_snapshot())} paths: {sd_paths()}\n"
            f"--- server stderr ---\n"
            f"{self.server.log_tail() if self.server else '<server stopped>'}"
        )

    # ── test ────────────────────────────────────────────────────────

    def test_loopback_end_to_end(self):
        dev = self._wait_device()

        # Capacity must match the backend file.
        self.assertEqual(
            device_size(dev), IMG_SIZE, "device capacity must match the backend"
        )

        # Full-disk destructive pattern test (like the iSCSI loopback).
        if have_tool("badblocks"):
            sh("badblocks", "-wsv", dev, timeout=300)
        else:
            print("  (badblocks not installed; skipping full-disk pattern test)")

        # Format as ext4, mount, write/read through the real filesystem.
        self.mount = mount_ext4(dev)
        payload = os.urandom(1 << 20)  # 1 MiB
        with open(os.path.join(self.mount, "payload.bin"), "wb") as f:
            f.write(payload)
        sh("sync")
        with open(os.path.join(self.mount, "payload.bin"), "rb") as f:
            self.assertEqual(f.read(), payload)
        unmount(self.mount, check=True)
        self.mount = None
        sh("fsck.ext4", "-fn", dev)

        # Read-only backend: rebind the same image read-only, verify reads
        # work and writes are rejected.
        self.server.stop()
        self.server = UsbServer(self.img, read_only=True, extra=self.EXTRA)
        self._logs.append(self.server.log_path)
        dev = self._wait_device()
        sh("dd", f"if={dev}", "of=/dev/null", "bs=1M", "count=1")
        # Direct I/O so the write error (WRITE PROTECTED) surfaces in dd's
        # write() instead of being absorbed by the page cache.
        r = sh(
            "dd",
            "if=/dev/zero",
            f"of={dev}",
            "bs=512",
            "count=1",
            "oflag=direct",
            check=False,
        )
        self.assertNotEqual(
            r.returncode, 0, "write to a read-only backend must be rejected"
        )
        self.server.stop()
        self.server = None


class UsbServer:
    """Lifecycle of `snowscsi serve --usb` over a backend image.

    No "listening on" line to wait for (unlike iSCSI): readiness is the
    appearance of the host-side device. Shutdown is SIGINT (graceful exit,
    assert 0). stderr goes to a temp file so the first bulk failure's
    message is available for diagnostics.

    Construction waits out a short startup grace: `serve --usb` either
    binds the gadget and stays up, or exits at once (the usual cause is a
    stale gadget still holding the exclusive UDC). An early exit raises
    with the CLI's stderr and runs the stale-gadget reclaim, so both this
    failure and the next run are diagnosable instead of turning into a
    device timeout.
    """

    def __init__(self, img, read_only=False, startup_grace=1.0, extra=()):
        spec = f"img={img},ro" if read_only else f"img={img}"
        self.log_path = tempfile.mktemp(prefix="snowscsi-usb-log-")
        self.log = open(self.log_path, "w")
        self.proc = subprocess.Popen(
            [find_binary(), "serve", "--usb", "--block", spec, *extra],
            stdout=subprocess.DEVNULL,
            stderr=self.log,
            text=True,
        )
        self._wait_started(startup_grace)

    def _wait_started(self, grace):
        """Return once the server has outlived `grace`; raise if it exited."""
        deadline = time.monotonic() + grace
        while time.monotonic() < deadline:
            if self.proc.poll() is not None:
                break
            time.sleep(0.02)
        rc = self.proc.poll()
        if rc is None:
            return
        tail = self.log_tail()
        try:
            self.log.close()
        except OSError:
            pass
        # Best effort: a stale gadget is the likely reason the bind failed;
        # do not mask the failure if reclamation itself has trouble.
        try:
            reclaimed = reclaim_stale_gadgets()
        except Exception as e:
            print(f"  warning: stale gadget reclaim failed: {e}")
        else:
            if not reclaimed:
                print(
                    f"  note: no test gadget was bound to {TEST_UDC}; the "
                    f"bind failure is not a stale-gadget collision"
                )
        try:
            os.unlink(self.log_path)
        except OSError:
            pass
        raise RuntimeError(
            f"snowscsi serve --usb exited (rc={rc}) during startup — the "
            f"gadget could not be bound; server stderr:\n{tail}"
        )

    def log_tail(self, n=4096):
        """Tail of the CLI's stderr log (available until tearDown removes it)."""
        return _log_tail(self.log_path, n)

    def stop(self):
        if self.proc is None:
            return
        try:
            if self.proc.poll() is None:
                self.proc.send_signal(signal.SIGINT)
                try:
                    self.proc.wait(timeout=10)
                except subprocess.TimeoutExpired:
                    self.proc.kill()
                    self.proc.wait()
                    raise AssertionError("snowscsi did not exit after SIGINT")
            if self.proc.returncode != 0:
                raise AssertionError(
                    f"snowscsi exited {self.proc.returncode} (expected 0 after "
                    f"SIGINT); stderr:\n{self.log_tail()}"
                )
        finally:
            self.log.close()
            self.proc = None


@unittest.skipUnless(
    is_root(),
    "requires root (to modprobe dummy_hcd and drive the loopback)",
)
class UsbLoopbackTest(_UsbScenario, unittest.TestCase):
    """Single-bank, blocking wire (the default)."""


@unittest.skipUnless(
    is_root(),
    "requires root (to modprobe dummy_hcd and drive the loopback)",
)
class UsbLoopbackDualTest(_UsbScenario, unittest.TestCase):
    """Two banks and the per-LUN storage worker."""

    EXTRA = ("--banks", "dual")


if __name__ == "__main__":
    unittest.main()
