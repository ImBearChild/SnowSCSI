#!/usr/bin/env python3
"""Black-box checks for the `serve` execution-mode surface.

No root and no kernel modules: every case either prints the resolved
configuration (`--print-config`, which binds nothing) or is rejected before a
listener/gadget exists. The data-path variants live in the loopback tests
(`test_iscsi_loopback.py`, `test_usb_loopback.py`, `test_bundle_loopback.py`,
`test_iscsi_auto.py`).
"""

import subprocess
import sys
import unittest

from harness import find_binary, have_async_wire

ISCSI = ("--iscsi", "127.0.0.1:0")
RAM = ("--block", "ram=1M")


def run(*args, timeout=20):
    return subprocess.run(
        [find_binary(), "serve", *args],
        capture_output=True,
        text=True,
        timeout=timeout,
    )


class ModeConfigTest(unittest.TestCase):
    def _config(self, *extra):
        proc = run(*RAM, *ISCSI, "--print-config", *extra)
        self.assertEqual(proc.returncode, 0, proc.stderr)
        lines = [ln for ln in proc.stdout.splitlines() if ln.strip()]
        self.assertEqual(len(lines), 1, f"expected one config line, got {lines!r}")
        return dict(part.split("=", 1) for part in lines[0].split())

    def test_single_defaults(self):
        cfg = self._config()
        self.assertEqual(cfg["wire"], "blocking")
        self.assertEqual(cfg["banks"], "single")
        self.assertEqual(cfg["storage"], "inline")
        self.assertEqual(cfg["per_bank"], cfg["work"])

    def test_dual_uses_the_worker_and_two_banks(self):
        cfg = self._config("--banks", "dual")
        self.assertEqual(cfg["wire"], "blocking")
        self.assertEqual(cfg["banks"], "dual")
        self.assertEqual(cfg["storage"], "worker")
        self.assertEqual(int(cfg["per_bank"]) * 2, int(cfg["work"]))

    @unittest.skipUnless(have_async_wire(), "requires the tokio feature")
    def test_async_dual_uses_the_worker(self):
        cfg = self._config("--banks", "dual", "--wire", "async")
        self.assertEqual(cfg["wire"], "async")
        self.assertEqual(cfg["storage"], "worker")
        self.assertEqual(int(cfg["per_bank"]) * 2, int(cfg["work"]))

    @unittest.skipUnless(have_async_wire(), "requires the tokio feature")
    def test_async_single_stays_inline(self):
        cfg = self._config("--wire", "async")
        self.assertEqual(cfg["wire"], "async")
        self.assertEqual(cfg["storage"], "inline")


class ModeValidationTest(unittest.TestCase):
    def assert_rejected(self, *args, needle):
        proc = run(*RAM, *ISCSI, *args)
        self.assertNotEqual(proc.returncode, 0, "expected a startup rejection")
        self.assertIn(needle, proc.stderr, proc.stderr)

    def test_overlap_flag_is_gone(self):
        proc = run(*RAM, *ISCSI, "--overlap")
        self.assertNotEqual(proc.returncode, 0)
        self.assertIn("--overlap", proc.stderr)

    def test_dual_rejects_scratch_buffer(self):
        self.assert_rejected("--banks", "dual", "--scratch-buffer",
                             needle="cannot be combined")

    def test_dual_total_must_be_even(self):
        self.assert_rejected("--banks", "dual", "--work-buf-size", "16481",
                             needle="must be even")

    def test_dual_half_must_clear_the_floor(self):
        self.assert_rejected("--banks", "dual", "--work-buf-size", "10000",
                             needle="work-buf-size")

    @unittest.skipUnless(sys.platform.startswith("linux"), "USB is Linux-only")
    @unittest.skipUnless(have_async_wire(), "requires the tokio feature")
    def test_async_usb_is_rejected(self):
        proc = run("--usb", "auto", "--wire", "async")
        self.assertNotEqual(proc.returncode, 0)
        self.assertIn("async USB is not implemented", proc.stderr)


if __name__ == "__main__":
    unittest.main()
