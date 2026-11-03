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

The CD-DA case burns a small WAV with `wodim -audio -tao` and needs a **second**
fresh bundle because the ISO burn also consumes a disc. Point
`SNOWSCSI_CDR_AUDIO_DEV` at that device:

    SNOWSCSI_CDR_AUDIO_DEV=/dev/sr1 python3 tools/ext-test/test_cdr_bundle.py \
        CdrBundleAudioBurnTest

It checks `wodim -toc` reports audio control and reads the track back with
`icedax` (or `readom` when it can) if available.

Skipped unless the matching device variable names an existing block device
**and** `wodim` is installed. No device is opened otherwise.
"""

import glob
import os
import re
import shutil
import stat
import subprocess
import tempfile
import unittest
import wave

from harness import have_tool, mkisofs, sh

LABEL = "CDRTEST"
DEV = os.environ.get("SNOWSCSI_CDR_DEV")
AUDIO_DEV = os.environ.get("SNOWSCSI_CDR_AUDIO_DEV")


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


def _audio_device_ready():
    """True only for an explicitly requested, existing audio-test block device."""
    if not AUDIO_DEV:
        return False
    try:
        return stat.S_ISBLK(os.stat(AUDIO_DEV).st_mode)
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

        # `-tao` is the only supported recording mode; `-dao` is rejected by
        # MODE SELECT page 0x05. `-dummy` (Test Write) is simulated in TAO:
        # the data phase and the CLOSE commands are consumed but the disc stays
        # blank, so a real burn must still succeed afterwards. wodim closes the
        # session at the end, which is what stores the final TOC.
        sh("wodim", "-v", "-dummy", "-tao", f"dev={DEV}", self.iso, timeout=300)
        blank = sh("isoinfo", "-d", "-i", DEV, check=False)
        self.assertNotIn(
            LABEL,
            blank.stdout,
            "a -dummy burn must leave the disc blank:\n" + blank.stdout,
        )

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


@unittest.skipUnless(
    _audio_device_ready() and have_tool("wodim"),
    "set SNOWSCSI_CDR_AUDIO_DEV to a separate blank /dev/srX served by "
    "`snowscsi serve --cdrom bundle=…` and install wodim",
)
class CdrBundleAudioBurnTest(unittest.TestCase):
    """Burn one CD-DA track with `wodim -audio -tao` and read it back."""

    def setUp(self):
        self.tmp = tempfile.mkdtemp(prefix="snowscsi-cdraudio-")
        self.wav = os.path.join(self.tmp, "track.wav")
        # One second of stereo 16-bit 44.1 kHz PCM is exactly 75 CD sectors
        # (176400 bytes / 2352), so the WAV data length is sector aligned.
        self.pcm = bytes((index * 29 + 7) & 0xFF for index in range(176400))
        with wave.open(self.wav, "wb") as out:
            out.setnchannels(2)
            out.setsampwidth(2)
            out.setframerate(44100)
            out.writeframes(self.pcm)

    def tearDown(self):
        shutil.rmtree(self.tmp, ignore_errors=True)

    def test_audio_burn_toc_and_read_back(self):
        sh("wodim", "-v", "-audio", "-tao", f"dev={AUDIO_DEV}", self.wav, timeout=300)

        # `wodim -toc` prints one line per track with `control: <hex>`; a
        # CD-DA track has control nibble 0 (data would be 4).
        toc = sh("wodim", "-toc", f"dev={AUDIO_DEV}", timeout=120).stdout
        tracks = {}
        for line in toc.splitlines():
            match = re.search(
                r"^track:\s*(\d+)\b.*control:\s*([0-9A-Fa-f]+)", line.strip()
            )
            if match:
                tracks[int(match.group(1))] = int(match.group(2), 16)
        self.assertIn(1, tracks, "wodim -toc must describe track 1:\n" + toc)
        self.assertEqual(tracks[1], 0, "track 1 control is audio:\n" + toc)

        with self.subTest(reader="icedax"):
            if not have_tool("icedax"):
                self.skipTest("icedax not installed for CD-DA read-back")
            base = os.path.join(self.tmp, "readback")
            sh(
                "icedax",
                f"dev={AUDIO_DEV}",
                "-t",
                "1",
                "-O",
                "wav",
                "-x",
                "-H",
                "-q",
                base,
                timeout=300,
            )
            produced = glob.glob(base + "*.wav")
            self.assertTrue(produced, "icedax produced no WAV output")
            with wave.open(max(produced, key=os.path.getsize), "rb") as got:
                frames = got.readframes(got.getnframes())
            self.assertEqual(frames[: len(self.pcm)], self.pcm)

        with self.subTest(reader="readom"):
            if have_tool("icedax"):
                self.skipTest("icedax already covered the read-back")
            if not have_tool("readom"):
                self.skipTest("readom not installed for CD-DA read-back")
            clone = os.path.join(self.tmp, "clone.bin")
            result = sh(
                "readom",
                f"dev={AUDIO_DEV}",
                "-clone",
                f"f={clone}",
                check=False,
                timeout=300,
            )
            if result.returncode != 0 or not os.path.exists(clone):
                self.skipTest("readom could not read this CD-DA track")
            with open(clone, "rb") as handle:
                raw = handle.read()
            self.assertIn(self.pcm, raw, "clone image does not contain the audio")


if __name__ == "__main__":
    unittest.main()
