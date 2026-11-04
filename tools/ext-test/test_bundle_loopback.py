#!/usr/bin/env python3
"""Real-kernel iSCSI loopback test over a FlatBundle disk (root).

Same initiator stack as `test_iscsi_loopback.py` (`iscsiadm` + `iscsi_tcp`,
manual login through `harness.IscsiSession`), but the served LUN is a
**directory-chunked FlatBundle** (`--block bundle=<dir>`) instead of a RAM
disk. The directory is created up front by `snowscsi bundle-create flat`; the
manifest exists before serving, while `serve` creates chunk files on demand
(it never creates the directory or manifest). On top of the usual
login/format/mount/write/read/fsck checklist it asserts the FlatBundle side
effects:

- the `SNOWBUNDLE` manifest written by `bundle-create` is still canonical;
- chunk files materialize on demand (`000000.img` after the first write and
  more chunks once the whole device has been written);
- the directory is re-openable (`--block bundle=<dir>` reloads the geometry
  from the manifest).

The device is detected by the `/sys/class/block` snapshot diff in
`harness.wait_new_sd`, so a stale device from a previous run can never be
picked.

Skipped unless: root, `iscsiadm` present, and the node DB works.
"""

import os
import shutil
import tempfile
import unittest
import zlib

from harness import (
    IscsiSession,
    ServerHandle,
    find_binary,
    full_disk_test,
    have_tool,
    is_root,
    iscsiadm_node_ok,
    mount_ext4,
    sh,
    start_iscsid,
    stop_iscsid,
    unmount,
)

# Bundle disk: 32 MiB = 65536 × 512 B sectors (enough for ext4).
SIZE = "32M"
SIZE_BYTES = 32 * 1024 * 1024
CHUNK = "1M"
CHUNK_BYTES = 1 * 1024 * 1024


class _BundleScenario:
    """Scenario shared by the per-mode test cases below."""

    # Extra `serve` arguments for this mode.
    EXTRA = ()

    @classmethod
    def setUpClass(cls):
        cls.iscsid_started = start_iscsid()
        if not iscsiadm_node_ok():
            raise unittest.SkipTest("iscsiadm -m node failed")

    @classmethod
    def tearDownClass(cls):
        if cls.iscsid_started:
            stop_iscsid()

    def setUp(self):
        self.bundle_dir = tempfile.mkdtemp(prefix="snowscsi-bundle-")
        # `serve` never creates a bundle: write the manifest first.
        sh(
            find_binary(),
            "bundle-create",
            "flat",
            "--dir",
            self.bundle_dir,
            "--size",
            SIZE,
            "--chunk",
            CHUNK,
        )
        self.server = ServerHandle(
            "--block",
            f"bundle={self.bundle_dir}",
            *self.EXTRA,
        )
        self.server.__enter__()
        self.session = IscsiSession(self.server.addr)
        self.mount = None

    def tearDown(self):
        unmount(self.mount)
        self.mount = None
        self.session.logout()
        try:
            self.server.__exit__(None, None, None)
        except AssertionError:
            pass  # the test body already recorded its own failure
        shutil.rmtree(self.bundle_dir, ignore_errors=True)

    # ── helpers ─────────────────────────────────────────────────────

    def _chunk_names(self):
        return sorted(n for n in os.listdir(self.bundle_dir) if n != "SNOWBUNDLE")

    def _check_manifest(self, content):
        """The manifest is canonical and its optional CRC covers the body."""
        lines = content.splitlines(keepends=True)
        self.assertTrue(lines, "empty manifest")
        self.assertTrue(lines[-1].startswith("crc = "), "manifest has no CRC line")
        body = "".join(lines[:-1]).encode("utf-8")
        expected = int(lines[-1].split("=", 1)[1].strip(), 16)
        self.assertEqual(
            zlib.crc32(body) & 0xFFFFFFFF, expected, "manifest CRC mismatch"
        )
        self.assertIn("virtual_size =", content)
        self.assertIn("chunk_size =", content)
        self.assertIn("sector_size =", content)

    # ── tests ───────────────────────────────────────────────────────

    def test_login_format_mount_write_read_fsck_chunks(self):
        try:
            self._login_format_mount_write_read_fsck_chunks()
        except AssertionError:
            print("\n--- server log tail ---\n" + self.server.log_tail(20000))
            raise

    def _login_format_mount_write_read_fsck_chunks(self):
        # `bundle-create` wrote the manifest up front; `serve` only opened it.
        header = os.path.join(self.bundle_dir, "SNOWBUNDLE")
        self.assertTrue(os.path.isfile(header), "SNOWBUNDLE manifest missing")
        with open(header, encoding="utf-8") as f:
            content = f.read()
        self.assertIn("magic = snow_bundle", content)
        self.assertIn("kind = flat", content)
        self._check_manifest(content)

        dev = self.session.login(expected_bytes=SIZE_BYTES)
        self.assertTrue(os.path.exists(dev), f"device {dev} missing")

        # Full-disk pattern write/read across the whole LBA range.
        full_disk_test(dev, SIZE_BYTES)

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

        # The full-disk writes must have materialized chunk files on demand.
        chunks = self._chunk_names()
        self.assertTrue(
            any(n == "000000.img" for n in chunks), f"chunk 0 missing: {chunks}"
        )
        self.assertGreaterEqual(
            len(chunks), 2,
            f"full-disk write should touch several chunks, got: {chunks}",
        )
        # Every chunk file is ≤ chunk_size (1 MiB).
        for name in chunks:
            size = os.path.getsize(os.path.join(self.bundle_dir, name))
            self.assertLessEqual(size, CHUNK_BYTES, f"{name} exceeds chunk size")

    def test_reopen_after_restart(self):
        # Write data, then tear the session down cleanly (logout + node
        # delete + device removal), restart on the same bundle directory, and
        # verify the data persists.
        dev = self.session.login(expected_bytes=SIZE_BYTES)
        sh(
            "dd", "if=/dev/zero", f"of={dev}", "bs=512", "count=1", "seek=100"
        )
        sh("sync")
        self.session.logout()
        self.server.stop()

        # Restart the server on the same bundle directory (no size=/chunk=
        # needed: the SNOWBUNDLE manifest carries the geometry).
        self.server = ServerHandle(
            "--block", f"bundle={self.bundle_dir}", *self.EXTRA
        )
        self.server.__enter__()
        self.session = IscsiSession(self.server.addr)
        dev = self.session.login(expected_bytes=SIZE_BYTES)
        sh("dd", f"if={dev}", "bs=512", "count=1", "skip=100")


@unittest.skipUnless(
    is_root() and have_tool("iscsiadm"),
    "requires root + iscsiadm (open-iscsi)",
)
class BundleLoopbackTest(_BundleScenario, unittest.TestCase):
    """Single-bank, blocking wire (the default)."""


@unittest.skipUnless(
    is_root() and have_tool("iscsiadm"),
    "requires root + iscsiadm (open-iscsi)",
)
class BundleLoopbackDualTest(_BundleScenario, unittest.TestCase):
    """Two banks and the per-LUN storage worker."""

    EXTRA = ("--banks", "dual")


if __name__ == "__main__":
    unittest.main()
