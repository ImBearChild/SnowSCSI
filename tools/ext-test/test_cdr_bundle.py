#!/usr/bin/env python3
"""Black-box burn/read-back check for a CD-R bundle served by the CLI.

This test does **not** start a server: it expects an already-served optical
device (for example `snowscsi serve --usb dummy --cdrom
bundle=/tmp/cdr,medium=cdr80`) and a blank CD-R bundle behind it. Point
`SNOWSCSI_CDR_DEV` at the host block device that server exposes:

    SNOWSCSI_CDR_DEV=/dev/sr0 python3 tools/ext-test/test_cdr_bundle.py

It burns a small ISO with `wodim -tao` (the cdrkit Track-at-Once sequence the
`cdr_cdrkit_tao_trace` in-process test replays) and verifies an independent
reader can see the volume and its files again: `isoinfo -d` for the PVD,
`isoinfo -f` for the tree, and `isoinfo -x` for the payload bytes. The burn
consumes the write-once disc, so use a fresh bundle.

Skipped unless `SNOWSCSI_CDR_DEV` names an existing block device **and** both
`wodim` and `isoinfo` are installed. No device is opened otherwise.
"""

import os
import shutil
import stat
import subprocess
import tempfile
import unittest

from harness import have_tool, mkisofs, sh

LABEL = "CDRTEST"
DEV = os.environ.get("SNOWSCSI_CDR_DEV")


def _extract(path):
    """Bytes of one ISO9660 file (`isoinfo -x`, binary safe)."""
    return subprocess.run(
        ["isoinfo", "-i", DEV, "-x", path],
        capture_output=True,
        check=True,
    ).stdout


def _device_ready():
    """True only for an explicitly requested, existing block device."""
    if not DEV:
        return False
    try:
        return stat.S_ISBLK(os.stat(DEV).st_mode)
    except OSError:
        return False


@unittest.skipUnless(
    _device_ready() and have_tool("wodim") and have_tool("isoinfo"),
    "set SNOWSCSI_CDR_DEV to a blank /dev/srX served by "
    "`snowscsi serve --cdrom bundle=…` and install wodim + isoinfo",
)
class CdrBundleBurnTest(unittest.TestCase):
    """Burn one ISO at the next writable address and read it back."""

    def setUp(self):
        self.tmp = tempfile.mkdtemp(prefix="snowscsi-cdr-")
        self.src = os.path.join(self.tmp, "src")
        os.makedirs(self.src)
        self.text = b"SnowSCSI CD-R bundle read-back\n" * 8
        self.payload = bytes((i * 37 + 11) & 0xFF for i in range(1024))
        with open(os.path.join(self.src, "hello.txt"), "wb") as f:
            f.write(self.text)
        with open(os.path.join(self.src, "payload.bin"), "wb") as f:
            f.write(self.payload)
        self.iso = os.path.join(self.tmp, "test.iso")

    def tearDown(self):
        shutil.rmtree(self.tmp, ignore_errors=True)

    def test_burn_and_read_back(self):
        made = mkisofs(self.src, self.iso, label=LABEL)
        self.assertEqual(made.returncode, 0, made.stderr)
        self.assertTrue(os.path.isfile(self.iso))

        # `-tao` is the only supported recording mode; `-dao` and `-dummy`
        # are rejected by MODE SELECT page 0x05. wodim closes the session at
        # the end, which is what stores the final TOC.
        sh("wodim", "-v", "-tao", f"dev={DEV}", self.iso, timeout=300)

        # An independent reader must see the finalized volume.
        disc = sh("isoinfo", "-d", "-i", DEV)
        self.assertIn(LABEL, disc.stdout)
        tree = sh("isoinfo", "-f", "-i", DEV).stdout.splitlines()
        self.assertIn("/HELLO.TXT;1", tree)
        self.assertIn("/PAYLOAD.BIN;1", tree)

        hello = _extract("/HELLO.TXT;1")
        self.assertEqual(hello, self.text)
        payload = _extract("/PAYLOAD.BIN;1")
        self.assertEqual(payload, self.payload)


if __name__ == "__main__":
    unittest.main()
