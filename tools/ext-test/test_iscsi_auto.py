#!/usr/bin/env python3
"""`--iscsi auto` smoke test (root).

`--iscsi auto` makes the server bind the standard loopback portal
(`127.0.0.1:3260`, falling back to an ephemeral port), register + log in the
open-iscsi node itself, and wait for udev to expose the block device. This
test validates exactly that mechanism: a new `/dev/sdX` with the right
capacity appears, and it disappears when the server shuts down.

The filesystem-level behavior is covered by `test_iscsi_loopback.py` and
`test_bundle_loopback.py` over manual login; keeping auto separate avoids
coupling its asynchronous timing to the FS checklist.

Skipped unless: root and `iscsiadm` present.
"""

import os
import unittest

from harness import (
    ServerHandle,
    have_tool,
    is_root,
    purge_target_sessions,
    sd_snapshot,
    start_iscsid,
    stop_iscsid,
    wait_new_sd,
    wait_sd_gone,
)

RAM_SIZE = "8M"
RAM_BYTES = 8 * 1024 * 1024


class _IscsiAutoScenario:
    """Scenario shared by the per-mode test cases below."""

    # Extra `serve` arguments for this mode.
    EXTRA = ()

    @classmethod
    def setUpClass(cls):
        cls.iscsid_started = start_iscsid()

    @classmethod
    def tearDownClass(cls):
        if cls.iscsid_started:
            stop_iscsid()

    def setUp(self):
        # Snapshot before the server starts: `auto` logs in on its own, so
        # the device we want is whatever appears after this point. Clear a
        # session left by a prior run first so it cannot be mistaken for it.
        purge_target_sessions()
        self.before = sd_snapshot()
        self.server = ServerHandle(
            "--block", f"ram={RAM_SIZE}", iscsi_auto=True, *self.EXTRA
        )
        self.server.__enter__()
        self.device = None

    def tearDown(self):
        try:
            self.server.__exit__(None, None, None)
        except AssertionError:
            pass  # the test body already recorded its own failure
        if self.device:
            wait_sd_gone([os.path.basename(self.device)], timeout=15)
            self.device = None

    def test_auto_attaches_and_reports_capacity(self):
        self.device = wait_new_sd(
            self.before, timeout=30, expected_bytes=RAM_BYTES
        )
        self.assertTrue(os.path.exists(self.device), f"device {self.device} missing")


@unittest.skipUnless(
    is_root() and have_tool("iscsiadm"),
    "requires root + iscsiadm (open-iscsi)",
)
class IscsiAutoTest(_IscsiAutoScenario, unittest.TestCase):
    """Single-bank, blocking wire (the default)."""


@unittest.skipUnless(
    is_root() and have_tool("iscsiadm"),
    "requires root + iscsiadm (open-iscsi)",
)
class IscsiAutoDualTest(_IscsiAutoScenario, unittest.TestCase):
    """Two banks and the per-LUN storage worker."""

    EXTRA = ("--banks", "dual")


if __name__ == "__main__":
    unittest.main()
