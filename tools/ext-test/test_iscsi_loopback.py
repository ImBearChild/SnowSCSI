#!/usr/bin/env python3
"""Real-kernel iSCSI loopback test (root).

A genuine Linux initiator (`iscsiadm`, the open-iscsi userspace driving the
`iscsi_tcp` kernel module) logs into `snowscsi serve` over loopback, brings
the device up as a block device, formats it with ext4, mounts it, writes and
reads data through the real block layer, and fsck-checks it.

This is the strongest possible black-box validation of the iSCSI target:
the kernel's SCSI midlayer + ext4 + VFS all exercise the emulated target,
covering login negotiation, REPORT LUNS, READ/WRITE(10), MODE SENSE and
sense handling that a userspace initiator would gloss over.

The initiator lifecycle comes from `harness.IscsiSession` (manual login,
snapshot-diff device detection, deterministic teardown); this file only owns
the RAM-disk scenario and the filesystem checklist. `--iscsi auto` has its
own smoke test in `test_iscsi_auto.py`.

Skipped unless: running as root, `iscsiadm` present, and the `iscsiadm`
node DB works. The test never loads or unloads kernel modules.
"""

import os
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

# RAM disk: 32 MiB = 65536 × 512 B sectors (enough for ext4).
RAM_SIZE = "32M"
RAM_BYTES = 32 * 1024 * 1024


@unittest.skipUnless(
    is_root() and have_tool("iscsiadm"),
    "requires root + iscsiadm (open-iscsi)",
)
class IscsiLoopbackTest(unittest.TestCase):
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
        self.server = ServerHandle("--block", f"ram={RAM_SIZE}")
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

    def test_login_format_mount_write_read_fsck(self):
        dev = self.session.login(expected_bytes=RAM_BYTES)
        self.assertTrue(os.path.exists(dev), f"device {dev} missing")

        # Full-disk destructive pattern test on the raw device: exercises
        # READ/WRITE across the entire LBA range (the fs payload below only
        # touches a small region).
        full_disk_test(dev, RAM_BYTES)

        # Format as ext4 and mount, then write/read through the filesystem.
        self.mount = mount_ext4(dev)
        payload = os.urandom(1 << 20)  # 1 MiB
        with open(os.path.join(self.mount, "payload.bin"), "wb") as f:
            f.write(payload)
        sh("sync")
        with open(os.path.join(self.mount, "payload.bin"), "rb") as f:
            self.assertEqual(f.read(), payload)

        # Unmount then fsck the filesystem read-only.
        unmount(self.mount, check=True)
        self.mount = None
        sh("fsck.ext4", "-fn", dev)


if __name__ == "__main__":
    unittest.main()
