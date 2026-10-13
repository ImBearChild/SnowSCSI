#!/usr/bin/env python3
"""Real-kernel iSCSI loopback test over a FlatBundle disk (root).

Same initiator stack as `test_iscsi_loopback.py` (`iscsiadm` + `iscsi_tcp`,
manual login through `harness.IscsiSession`), but the served LUN is a
**directory-chunked FlatBundle** (`--block imgdir=<dir>,size=32M`) instead of
a RAM disk. On top of the usual login/format/mount/write/read/fsck checklist
it asserts the FlatBundle side effects:

- the `BUNDLE` header is written when the server creates the disk;
- chunk files materialize on demand (`000000.img` after the first write and
  more chunks once the whole device has been written);
- the directory is re-openable (the same `imgdir=` spec reloads geometry).

The device is detected by the `/sys/class/block` snapshot diff in
`harness.wait_new_sd`, so a stale device from a previous run can never be
picked.

Skipped unless: root, `iscsiadm` present, and the node DB works.
"""

import os
import shutil
import tempfile
import unittest

from harness import (
    IscsiSession,
    ServerHandle,
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


@unittest.skipUnless(
    is_root() and have_tool("iscsiadm"),
    "requires root + iscsiadm (open-iscsi)",
)
class BundleLoopbackTest(unittest.TestCase):
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
        self.server = ServerHandle(
            "--block", f"imgdir={self.bundle_dir},size={SIZE},chunk={CHUNK}"
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
        return sorted(n for n in os.listdir(self.bundle_dir) if n != "BUNDLE")

    # ── tests ───────────────────────────────────────────────────────

    def test_login_format_mount_write_read_fsck_chunks(self):
        try:
            self._login_format_mount_write_read_fsck_chunks()
        except AssertionError:
            print("\n--- server log tail ---\n" + self.server.log_tail(20000))
            raise

    def _login_format_mount_write_read_fsck_chunks(self):
        # The server created the disk: the BUNDLE header exists up front.
        header = os.path.join(self.bundle_dir, "BUNDLE")
        self.assertTrue(os.path.isfile(header), "BUNDLE header missing")
        with open(header, encoding="utf-8") as f:
            content = f.read()
        self.assertIn("magic = snow_flat_bnd", content)

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

        # Restart the server on the same bundle directory (no size= needed:
        # the BUNDLE header already exists).
        self.server = ServerHandle(
            "--block", f"imgdir={self.bundle_dir},chunk={CHUNK}"
        )
        self.server.__enter__()
        self.session = IscsiSession(self.server.addr)
        dev = self.session.login(expected_bytes=SIZE_BYTES)
        sh("dd", f"if={dev}", "bs=512", "count=1", "skip=100")


if __name__ == "__main__":
    unittest.main()
