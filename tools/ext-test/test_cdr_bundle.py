#!/usr/bin/env python3
"""Black-box burn/read-back check for CD-R/CD-RW bundles served by the CLI.

Most cases do **not** start a server: they expect an already-served optical
device (for example `snowscsi bundle-create cdr --dir /tmp/cdr --medium cdr80`
followed by `snowscsi serve --usb dummy --cdrom bundle=/tmp/cdr`) and a blank
CD-R bundle behind it. Point
`SNOWSCSI_CDR_DEV` at the host block device that server exposes:

    SNOWSCSI_CDR_DEV=/dev/sr0 python3 tools/ext-test/test_cdr_bundle.py

It burns a small ISO with `wodim -tao` (the cdrkit Track-at-Once sequence the
`cdr_cdrkit_tao_trace` in-process test replays) and verifies an independent
reader can see the volume and its files again: `isoinfo -d` for the PVD,
`isoinfo -f` for the tree, `isoinfo -x` for the payload bytes, and a read-only
mount for a second, kernel-level byte-for-byte check. The burn consumes the
write-once disc, so use a fresh bundle.

The CD-DA case burns a small WAV with `wodim -audio -tao` and needs a **second**
fresh bundle because the ISO burn also consumes a disc. Point
`SNOWSCSI_CDR_AUDIO_DEV` at that device:

    SNOWSCSI_CDR_AUDIO_DEV=/dev/sr1 python3 tools/ext-test/test_cdr_bundle.py \
        CdrBundleAudioBurnTest

It checks `wodim -toc` reports audio control and reads the track back with
`icedax` (or `readom` when it can) if available.

The CD-RW case needs a blank erasable disc (`SNOWSCSI_CDRW_DEV`) and burns,
`wodim blank=fast`, burns again, then `wodim blank=all` and burns a third time.

Two cases are self-contained and start their own `serve --usb dummy` on a
temporary bundle directory (so they need root and a `dummy_hcd`-capable
kernel): the persistence case burns, stops the server, restarts it on the same
directory and checks the mounted volume plus the alternating TOC sequence; the
opt-in eject case (`SNOWSCSI_CDR_EJECT_TEST=1`) writes one raw block, ejects,
checks the persisted TOC, restarts and verifies the appendable disc with
`sg_raw`, then finalizes it. Every server is stopped in cleanup.

Skipped unless the matching device/tool is present. No device is opened
otherwise.
"""

import glob
import os
import re
import shutil
import signal
import stat
import subprocess
import tempfile
import time
import unittest
import wave
import zlib

from harness import find_binary, have_tool, is_root, mkisofs, sh

LABEL = "CDRTEST"
DEV = os.environ.get("SNOWSCSI_CDR_DEV")
AUDIO_DEV = os.environ.get("SNOWSCSI_CDR_AUDIO_DEV")
CDRW_DEV = os.environ.get("SNOWSCSI_CDRW_DEV")
EJECT_TEST = os.environ.get("SNOWSCSI_CDR_EJECT_TEST") == "1"

# The alternating TOC slot format (see `snowscsi/src/mmc/cdr_bundle/toc.rs`).
TOC_MAGIC = "snow_cdr_bnd"
TOC_VERSION = 1
TOC_HEADER_LEN = 256


# ── device / tool gating ────────────────────────────────────────────

def _is_block_device(path):
    if not path:
        return False
    try:
        return stat.S_ISBLK(os.stat(path).st_mode)
    except OSError:
        return False


def _device_ready():
    """True only for an explicitly requested, existing block device."""
    return _is_block_device(DEV)


def _audio_device_ready():
    """True only for an explicitly requested, existing audio-test block device."""
    return _is_block_device(AUDIO_DEV)


def _cdrw_device_ready():
    """True only for an explicitly requested, existing CD-RW block device."""
    return _is_block_device(CDRW_DEV)


def _usb_dummy_ready():
    """True when `serve --usb dummy` can plausibly bind its gadget."""
    if not is_root():
        return False
    state = "/sys/class/udc/dummy_udc.0/state"
    if os.path.exists(state):
        try:
            with open(state, encoding="utf-8") as handle:
                if handle.read().strip() not in ("", "not attached", "not_attached"):
                    return False
        except OSError:
            return True
        return True
    # `--usb dummy` auto-loads dummy_hcd when the module exists.
    return have_tool("modprobe")


# ── ISO payload helpers ─────────────────────────────────────────────

def _pattern(tag, n=1024):
    """Deterministic bytes that differ per burn tag."""
    seed = sum(tag.encode()) & 0xFF
    return bytes((index * 37 + seed) & 0xFF for index in range(n))


def _make_iso(tmp, tag, label):
    """Build one source tree and ISO image; return (proc, iso, text, payload)."""
    src = os.path.join(tmp, "src-" + tag)
    os.makedirs(src)
    text = f"SnowSCSI CD-R bundle {tag} read-back\n".encode() * 8
    payload = _pattern(tag)
    with open(os.path.join(src, "hello.txt"), "wb") as handle:
        handle.write(text)
    with open(os.path.join(src, "payload.bin"), "wb") as handle:
        handle.write(payload)
    iso = os.path.join(tmp, tag + ".iso")
    return mkisofs(src, iso, label=label), iso, text, payload


def _extract(dev, path):
    """Bytes of one ISO9660 file (`isoinfo -x`, binary safe)."""
    return subprocess.run(
        ["isoinfo", "-i", dev, "-x", path],
        capture_output=True,
        check=True,
    ).stdout


class _IsoReadBack:
    """Assertions shared by every burn/read-back case."""

    def verify_iso(self, dev, label, text, payload):
        # An independent reader must see the finalized volume.
        disc = sh("isoinfo", "-d", "-i", dev)
        self.assertIn(label, disc.stdout)
        tree = sh("isoinfo", "-f", "-i", dev).stdout.splitlines()
        self.assertIn("/HELLO.TXT;1", tree)
        self.assertIn("/PAYLOAD.BIN;1", tree)
        self.assertEqual(_extract(dev, "/HELLO.TXT;1"), text)
        self.assertEqual(_extract(dev, "/PAYLOAD.BIN;1"), payload)

    def verify_mount(self, dev, text, payload):
        """Mount read-only and compare the payload again through the kernel."""
        with self.subTest(check="mount-read-only"):
            if not have_tool("mount") or not have_tool("umount"):
                self.skipTest("mount/umount not installed for the read-only check")
            mount = tempfile.mkdtemp(prefix="snowscsi-cdrmnt-")
            try:
                mounted = sh(
                    "mount", "-o", "ro", "-t", "iso9660", dev, mount, check=False
                )
                if mounted.returncode != 0:
                    self.skipTest(
                        f"could not mount {dev} read-only "
                        f"(mount unavailable or not permitted): "
                        f"{mounted.stderr.strip()}"
                    )
                found = {}
                for root, _dirs, files in os.walk(mount):
                    for name in files:
                        path = os.path.join(root, name)
                        rel = os.path.relpath(path, mount)
                        key = rel.lower()
                        if key.endswith(";1"):
                            key = key[:-2]
                        with open(path, "rb") as handle:
                            found[key] = handle.read()
                self.assertEqual(
                    found.get("hello.txt"), text, "mounted hello.txt differs"
                )
                self.assertEqual(
                    found.get("payload.bin"), payload, "mounted payload.bin differs"
                )
            finally:
                if os.path.ismount(mount):
                    sh("umount", mount, check=False)
                shutil.rmtree(mount, ignore_errors=True)


# ── TOC slot helpers ────────────────────────────────────────────────

def _parse_header(blob):
    """Parse the fixed 256-byte INI header, or return None if unusable."""
    fields = {}
    try:
        text = blob.decode("ascii")
    except UnicodeDecodeError:
        return None
    for line in text.splitlines():
        line = line.strip()
        if not line or line.startswith(("#", ";")):
            continue
        key, sep, value = line.partition("=")
        if not sep:
            return None
        fields[key.strip()] = value.strip()
    if fields.get("magic") != TOC_MAGIC:
        return None
    try:
        version = int(fields["version"])
        slot = int(fields["slot"])
        body_len = int(fields["body_len"])
        checksum = int(fields["checksum"])
        seq = int(fields["seq"])
    except (KeyError, ValueError):
        return None
    if version != TOC_VERSION or slot not in (0, 1) or seq == 0:
        return None
    return {
        "version": version,
        "slot": slot,
        "body_len": body_len,
        "checksum": checksum,
        "seq": seq,
    }


def _toc_slot(bundle, slot):
    """One valid TOC slot (body checksum included), or None."""
    path = os.path.join(bundle, f"toc.{slot}")
    try:
        with open(path, "rb") as handle:
            image = handle.read()
    except OSError:
        return None
    if len(image) < TOC_HEADER_LEN:
        return None
    header = _parse_header(image[:TOC_HEADER_LEN])
    if header is None or header["slot"] != slot:
        return None
    body = image[TOC_HEADER_LEN : TOC_HEADER_LEN + header["body_len"]]
    if len(body) != header["body_len"]:
        return None
    if zlib.crc32(body) & 0xFFFFFFFF != header["checksum"]:
        return None
    return {
        "slot": slot,
        "seq": header["seq"],
        "body": body.decode("ascii", "replace"),
    }


def _toc_slots(bundle):
    """The valid alternating slots present in a bundle directory."""
    slots = {}
    for slot in (0, 1):
        parsed = _toc_slot(bundle, slot)
        if parsed is not None:
            slots[slot] = parsed
    return slots


def _newest_slot(slots):
    """Selection policy: higher seq wins, then the higher physical slot."""
    return max(slots.values(), key=lambda header: (header["seq"], header["slot"]))


# ── raw SCSI / device helpers ───────────────────────────────────────

def _sg_raw_proc(dev, cdb, reply=0, infile=None, readonly=None, check=True):
    """Send one raw command; return the `CompletedProcess`."""
    if readonly is None:
        # A data-in command only reads, so open the device read-only: the
        # kernel marks a finalized CD-R read-only and would reject O_RDWR.
        readonly = reply > 0
    argv = ["sg_raw", "-b"]
    if readonly:
        argv.append("-R")
    if reply:
        argv += ["-r", str(reply)]
    if infile:
        argv += ["-s", str(os.path.getsize(infile)), "-i", infile]
    argv.append(dev)
    argv.extend(f"{byte:02X}" for byte in cdb)
    proc = subprocess.run(argv, capture_output=True)
    if check and proc.returncode != 0:
        raise AssertionError(
            "sg_raw failed (rc={}): {}\n--- stdout ---\n{}\n--- stderr ---\n{}".format(
                proc.returncode,
                " ".join(argv),
                proc.stdout[-2000:],
                proc.stderr[-2000:].decode("utf-8", "replace"),
            )
        )
    return proc


def _sg_raw(dev, cdb, reply=0, infile=None, readonly=None, check=True):
    """Send one raw command; return stdout (binary for a data-in command)."""
    return _sg_raw_proc(dev, cdb, reply, infile, readonly, check).stdout


def _consume_unit_attention(dev):
    """Retry TEST UNIT READY until a pending unit attention is consumed."""
    for _ in range(3):
        if (
            _sg_raw_proc(
                dev,
                [0x00, 0x00, 0x00, 0x00, 0x00, 0x00],
                readonly=True,
                check=False,
            ).returncode
            == 0
        ):
            return


def _sr_devices():
    """Map each `srX` name to its sysfs realpath (a reused name still differs)."""
    try:
        names = [name for name in os.listdir("/sys/class/block") if name.startswith("sr")]
    except OSError:
        return {}
    return {
        name: os.path.realpath(os.path.join("/sys/class/block", name))
        for name in names
    }


def _wait_new_sr(before, proc, log_tail, timeout=30):
    """Wait for a usable `/dev/srX` that was not in `before`; return its path."""
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if proc.poll() is not None:
            raise AssertionError(
                f"snowscsi serve --usb exited early (rc={proc.returncode}):\n"
                f"{log_tail()}"
            )
        for name, path in sorted(_sr_devices().items()):
            if before.get(name) == path:
                continue
            dev = f"/dev/{name}"
            if not os.path.exists(dev):
                continue
            probed = sh("blockdev", "--getsize64", dev, check=False)
            if probed.returncode != 0:
                continue
            return dev
        time.sleep(0.2)
    raise AssertionError(
        f"no usable /dev/srX appeared within {timeout}s\n{log_tail()}"
    )


def _wait_sr_gone(names, timeout=15):
    """Wait until every `srX` name disappeared from the kernel."""
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        present = _sr_devices()
        if not any(name in present for name in names):
            return
        time.sleep(0.2)


def _wait_for(predicate, timeout=15.0):
    """Poll `predicate` until true or the timeout expires."""
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if predicate():
            return True
        time.sleep(0.2)
    return bool(predicate())


class _UsbCdrServer:
    """A `serve --usb dummy --cdrom <spec>` subprocess and its block device."""

    def __init__(self, spec, *extra_args):
        self.spec = spec
        self.extra_args = list(extra_args)
        self.proc = None
        self.device = None
        self._log_file = None
        self._log_path = None

    def log_tail(self, n=4000):
        if self._log_path is None:
            return "<no server log>"
        try:
            with open(self._log_path, errors="replace") as handle:
                return handle.read()[-n:]
        except OSError:
            return "<no server log>"

    def start(self):
        binary = find_binary()
        before = _sr_devices()
        self._log_file = tempfile.NamedTemporaryFile(
            prefix="snowscsi-cdr-usb-", suffix=".log", mode="w+", delete=False
        )
        self._log_path = self._log_file.name
        argv = [
            binary,
            "serve",
            "--usb",
            "dummy",
            "--cdrom",
            self.spec,
            *self.extra_args,
        ]
        self.proc = subprocess.Popen(
            argv, stdout=subprocess.DEVNULL, stderr=self._log_file, text=True
        )
        try:
            self.device = _wait_new_sr(before, self.proc, self.log_tail)
        except BaseException:
            if self.proc is not None and self.proc.poll() is None:
                self.proc.kill()
                self.proc.wait()
            self._close_log()
            self.proc = None
            raise
        return self.device

    def stop(self):
        """SIGINT (graceful shutdown), assert exit 0 and wait for the device."""
        if self.proc is None:
            return
        proc = self.proc
        names = [os.path.basename(self.device)] if self.device else []
        self.proc = None
        self.device = None
        try:
            if proc.poll() is None:
                proc.send_signal(signal.SIGINT)
                try:
                    proc.wait(timeout=15)
                except subprocess.TimeoutExpired:
                    proc.kill()
                    proc.wait()
                    raise AssertionError(
                        "snowscsi did not exit after SIGINT; log:\n" + self.log_tail()
                    )
            if proc.returncode != 0:
                raise AssertionError(
                    f"snowscsi exited {proc.returncode} (expected 0 after SIGINT); "
                    f"log:\n{self.log_tail()}"
                )
        finally:
            self._close_log()
            _wait_sr_gone(names)

    def _close_log(self):
        if self._log_file is not None:
            try:
                self._log_file.close()
            except OSError:
                pass
            self._log_file = None
        if self._log_path is not None:
            try:
                os.unlink(self._log_path)
            except OSError:
                pass
            self._log_path = None


class _SelfServedMixin:
    """A temporary bundle plus restartable `serve --usb dummy` processes."""

    def setUp(self):
        self.tmp = tempfile.mkdtemp(prefix="snowscsi-cdr-self-")
        self.addCleanup(shutil.rmtree, self.tmp, True)
        self.bundle = os.path.join(self.tmp, "bundle")
        # `serve` never creates a bundle directory or manifest: create them
        # (and the initial TOC) up front.
        sh(
            find_binary(),
            "bundle-create",
            "cdr",
            "--dir",
            self.bundle,
            "--medium",
            "cdr80",
        )
        self.server = None

    def start_server(self, spec):
        if self.server is not None:
            self.server.stop()
            self.server = None
        server = _UsbCdrServer(spec)
        self.addCleanup(server.stop)
        self.server = server
        return server.start()


# ── burn cases ──────────────────────────────────────────────────────

@unittest.skipUnless(
    _device_ready() and have_tool("wodim") and have_tool("isoinfo"),
    "set SNOWSCSI_CDR_DEV to a blank /dev/srX served by "
    "`snowscsi serve --cdrom bundle=…` and install wodim + isoinfo",
)
class CdrBundleBurnTest(_IsoReadBack, unittest.TestCase):
    """Burn one ISO at the next writable address and read it back."""

    def setUp(self):
        self.tmp = tempfile.mkdtemp(prefix="snowscsi-cdr-")
        self.addCleanup(shutil.rmtree, self.tmp, True)
        made, self.iso, self.text, self.payload = _make_iso(self.tmp, "iso", LABEL)
        self.assertEqual(made.returncode, 0, made.stderr)
        self.assertTrue(os.path.isfile(self.iso))

    def test_burn_and_read_back(self):
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

        self.verify_iso(DEV, LABEL, self.text, self.payload)
        self.verify_mount(DEV, self.text, self.payload)


@unittest.skipUnless(
    _audio_device_ready() and have_tool("wodim"),
    "set SNOWSCSI_CDR_AUDIO_DEV to a separate blank /dev/srX served by "
    "`snowscsi serve --cdrom bundle=…` and install wodim",
)
class CdrBundleAudioBurnTest(unittest.TestCase):
    """Burn one CD-DA track with `wodim -audio -tao` and read it back."""

    def setUp(self):
        self.tmp = tempfile.mkdtemp(prefix="snowscsi-cdraudio-")
        self.addCleanup(shutil.rmtree, self.tmp, True)
        self.wav = os.path.join(self.tmp, "track.wav")
        # One second of stereo 16-bit 44.1 kHz PCM is exactly 75 CD sectors
        # (176400 bytes / 2352), so the WAV data length is sector aligned.
        self.pcm = bytes((index * 29 + 7) & 0xFF for index in range(176400))
        with wave.open(self.wav, "wb") as out:
            out.setnchannels(2)
            out.setsampwidth(2)
            out.setframerate(44100)
            out.writeframes(self.pcm)

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


@unittest.skipUnless(
    _cdrw_device_ready() and have_tool("wodim") and have_tool("isoinfo"),
    "set SNOWSCSI_CDRW_DEV to a blank, erasable /dev/srX served by "
    "`snowscsi bundle-create cdr --medium cdrw80` plus `snowscsi serve --cdrom "
    "bundle=…` and install wodim + isoinfo",
)
class CdrBundleCdrwTest(_IsoReadBack, unittest.TestCase):
    """Blank a CD-RW (fast and all) between three Track-at-Once burns."""

    def setUp(self):
        self.tmp = tempfile.mkdtemp(prefix="snowscsi-cdrw-")
        self.addCleanup(shutil.rmtree, self.tmp, True)

    def test_fast_and_full_blank_allow_reburns(self):
        for tag, label, blanking in (
            ("fast1", "CDRWFAST", None),
            ("fast2", "CDRWSECOND", "fast"),
            ("all3", "CDRWFINAL", "all"),
        ):
            with self.subTest(phase=tag):
                if blanking:
                    sh(
                        "wodim",
                        f"dev={CDRW_DEV}",
                        f"blank={blanking}",
                        timeout=300,
                    )

                made, iso, text, payload = _make_iso(self.tmp, tag, label)
                self.assertEqual(made.returncode, 0, made.stderr)
                sh("wodim", "-v", "-tao", f"dev={CDRW_DEV}", iso, timeout=300)
                self.verify_iso(CDRW_DEV, label, text, payload)


# ── self-contained restart cases ────────────────────────────────────

@unittest.skipUnless(
    _usb_dummy_ready() and have_tool("wodim") and have_tool("isoinfo") and have_tool("sg_raw"),
    "requires root, wodim, isoinfo, sg_raw and a free dummy_hcd UDC "
    "(`serve --usb dummy` auto-loads it)",
)
class CdrBundlePersistenceTest(_SelfServedMixin, _IsoReadBack, unittest.TestCase):
    """Burn, restart on the same directory, and prove the newest TOC won."""

    LABEL = "CDRPERSIST"

    def setUp(self):
        super().setUp()
        made, self.iso, self.text, self.payload = _make_iso(
            self.tmp, "persist", self.LABEL
        )
        self.assertEqual(made.returncode, 0, made.stderr)

    def test_restart_keeps_mount_and_newest_toc(self):
        dev = self.start_server(f"bundle={self.bundle}")
        sh("wodim", "-v", "-tao", f"dev={dev}", self.iso, timeout=300)
        self.verify_iso(dev, self.LABEL, self.text, self.payload)
        self.verify_mount(dev, self.text, self.payload)

        # Stop the server and inspect what the burn left on disk.
        self.server.stop()
        self.server = None
        before = _toc_slots(self.bundle)
        self.assertTrue(before, "the burn must persist at least one TOC slot")
        for slot, header in before.items():
            self.assertEqual(header["slot"], slot)
        newest = _newest_slot(before)
        self.assertIn("[track.1]", newest["body"], newest["body"])
        self.assertIn("disc_state = finalized", newest["body"], newest["body"])
        self.assertEqual(newest["seq"], max(h["seq"] for h in before.values()))

        # Reopen the same directory: the stored TOC (not a CLI hint) must
        # restore the disc.
        dev = self.start_server(f"bundle={self.bundle}")
        self.verify_iso(dev, self.LABEL, self.text, self.payload)
        self.verify_mount(dev, self.text, self.payload)

        # The directory still carries a consistent TOC, and the restored
        # medium reports the finalized state that the newest slot records (an
        # older, pre-finalize slot would report appendable).
        after = _toc_slots(self.bundle)
        self.assertTrue(after, "the reopened bundle lost its TOC slots")
        latest = _newest_slot(after)
        self.assertGreaterEqual(latest["seq"], newest["seq"])
        self.assertIn("disc_state = finalized", latest["body"])
        _consume_unit_attention(dev)
        info = _sg_raw(
            dev,
            [0x51, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x22, 0x00],
            reply=34,
        )
        self.assertEqual(len(info), 34, f"short READ DISC INFORMATION: {len(info)} bytes")
        self.assertEqual(
            info[2] & 0x03,
            2,
            "the restart must restore the finalized TOC, not an older slot: "
            f"{info.hex()}",
        )


@unittest.skipUnless(
    EJECT_TEST
    and _usb_dummy_ready()
    and have_tool("sg_raw")
    and have_tool("eject"),
    "set SNOWSCSI_CDR_EJECT_TEST=1 and install sg_raw + eject; requires root "
    "and a free dummy_hcd UDC (`serve --usb dummy` auto-loads it)",
)
class CdrBundleEjectTest(_SelfServedMixin, unittest.TestCase):
    """Write one raw block, eject, restart and verify the TOC snapshot."""

    def setUp(self):
        super().setUp()
        self.block = os.path.join(self.tmp, "block.bin")
        with open(self.block, "wb") as handle:
            handle.write(b"\x5a" * 2048)

    def test_eject_snapshot_restores_appendable_disc(self):
        dev = self.start_server(f"bundle={self.bundle}")
        _consume_unit_attention(dev)
        # WRITE(10) one 2048-byte block at LBA 0.
        _sg_raw(
            dev,
            [0x2A, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00],
            infile=self.block,
        )

        track = os.path.join(self.bundle, "track_1.bin")
        self.assertTrue(
            _wait_for(lambda: os.path.isfile(track)),
            f"the raw write did not create {track}",
        )

        sh("eject", dev, timeout=60)
        self.assertTrue(
            _wait_for(
                lambda: os.path.isfile(track) and bool(_toc_slots(self.bundle))
            ),
            "eject did not snapshot a valid toc.* next to track_1.bin",
        )
        self.assertGreater(os.path.getsize(track), 0)

        snapshot = _toc_slots(self.bundle)
        self.assertTrue(snapshot, "the eject snapshot is not a valid TOC slot")
        self.assertIn("disc_state = appendable", _newest_slot(snapshot)["body"])
        self.assertIn("[track.1]", _newest_slot(snapshot)["body"])

        # Restart on the same directory and inspect the appendable disc.
        dev = self.start_server(f"bundle={self.bundle}")
        _consume_unit_attention(dev)

        # READ DISC INFORMATION (0x51), 34-byte standard payload: byte 2
        # bits 1-0 = disc status, 01b = incomplete/appendable.
        info = _sg_raw(dev, [0x51, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x22, 0x00], reply=34)
        self.assertEqual(len(info), 34, f"short READ DISC INFORMATION: {len(info)} bytes")
        self.assertEqual(
            info[2] & 0x03, 1, f"restored disc must be appendable: disc info {info.hex()}"
        )

        # READ TRACK INFORMATION (0x52), type 1 (track number), track 1,
        # 48-byte payload: byte 2 = track, byte 3 = session, byte 6 bit 7 =
        # RT, bytes 8-11 = start LBA, bytes 24-27 = track size.
        track_info = _sg_raw(
            dev,
            [0x52, 0x01, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x30, 0x00],
            reply=48,
        )
        self.assertEqual(
            len(track_info), 48, f"short READ TRACK INFORMATION: {len(track_info)} bytes"
        )
        self.assertEqual(track_info[2], 1, "track number")
        self.assertEqual(track_info[3], 1, "session number")
        self.assertTrue(
            track_info[6] & 0x80,
            f"the snapshot-closed track must be complete: {track_info.hex()}",
        )
        self.assertEqual(int.from_bytes(track_info[8:12], "big"), 0, "track start LBA")
        self.assertGreaterEqual(
            int.from_bytes(track_info[24:28], "big"), 1, "track length"
        )

        # Finalize (CLOSE TRACK/SESSION 010b) and verify the new state.
        _sg_raw(dev, [0x5B, 0x00, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00])
        _consume_unit_attention(dev)
        info = _sg_raw(
            dev, [0x51, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x22, 0x00], reply=34
        )
        self.assertEqual(
            info[2] & 0x03, 2, f"finalize must report a finalized disc: {info.hex()}"
        )
        final = _toc_slots(self.bundle)
        self.assertTrue(final, "finalize did not persist a TOC slot")
        self.assertIn("disc_state = finalized", _newest_slot(final)["body"])


@unittest.skipUnless(
    _usb_dummy_ready() and have_tool("wodim") and have_tool("isoinfo"),
    "requires root, wodim, isoinfo and a free dummy_hcd UDC to burn an "
    "encrypted CD-R bundle served by `snowscsi serve --usb dummy`",
)
class CdrBundleCipherBurnTest(_IsoReadBack, unittest.TestCase):
    """Burn an ISO through an encrypted CD-R bundle and verify both views.

    The host sees plaintext through the emulated drive, while the on-disk
    ``track_1.bin`` must be ciphertext (no ISO ``CD001`` PVD signature at
    ``0x8001``) and ``toc.0`` must stay a plaintext TOC.
    """

    def setUp(self):
        self.tmp = tempfile.mkdtemp(prefix="snowscsi-cdr-cipher-burn-")
        self.addCleanup(shutil.rmtree, self.tmp, True)
        self.bundle = os.path.join(self.tmp, "bundle")
        self.password = os.path.join(self.tmp, "pw")
        with open(self.password, "w", encoding="utf-8") as handle:
            handle.write("secret\n")
        help_text = sh(find_binary(), "bundle-create", "cdr", "--help").stdout
        if "--cipher" not in help_text:
            self.skipTest("binary built without the cipher feature")
        created = sh(
            find_binary(),
            "bundle-create",
            "cdr",
            "--dir",
            self.bundle,
            "--medium",
            "cdr80",
            "--cipher",
            "chacha12",
            "--password-file",
            self.password,
            check=False,
            timeout=300,
        )
        if created.returncode != 0:
            if "requires the `cdr-bundle` feature" in created.stderr:
                self.skipTest("binary built without the cdr-bundle feature")
            self.fail(
                "encrypted bundle-create failed:\n"
                f"{created.stdout}\n{created.stderr}"
            )
        made, self.iso, self.text, self.payload = _make_iso(self.tmp, "cipher", LABEL)
        if made.returncode != 0:
            self.skipTest(f"mkisofs failed: {made.stderr}")
        self.server = _UsbCdrServer(
            f"bundle={self.bundle},cipher", "--password-file", self.password
        )
        self.device = self.server.start()
        self.addCleanup(self.server.stop)

    def test_burn_and_read_back_are_plaintext_but_storage_is_not(self):
        sh("wodim", "-v", "-tao", f"dev={self.device}", self.iso, timeout=300)
        self.verify_iso(self.device, LABEL, self.text, self.payload)

        track = os.path.join(self.bundle, "track_1.bin")
        self.assertTrue(os.path.isfile(track), "the burn must create track_1.bin")
        with open(track, "rb") as handle:
            raw = handle.read()
        self.assertGreater(len(raw), 0x8006, "track_1.bin is too short for a PVD")
        self.assertNotEqual(
            raw[0x8001:0x8006],
            b"CD001",
            "track_1.bin must not contain the plaintext ISO PVD signature",
        )
        with open(os.path.join(self.bundle, "toc.0"), "rb") as handle:
            self.assertIn(
                TOC_MAGIC.encode("ascii"),
                handle.read(),
                "the TOC must stay plaintext",
            )


class CdrBundleCipherCreateTest(unittest.TestCase):
    """Non-root: an encrypted CD-R bundle keeps a plaintext TOC.

    No device or burn is involved: this only checks what `bundle-create cdr
    --cipher` writes. Skipped when the binary was built without `cipher`.
    """

    def test_cipher_block_and_plaintext_toc(self):
        help_text = sh(find_binary(), "bundle-create", "cdr", "--help").stdout
        if "--cipher" not in help_text:
            self.skipTest("binary built without the cipher feature")

        tmp = tempfile.mkdtemp(prefix="snowscsi-cdr-cipher-")
        self.addCleanup(shutil.rmtree, tmp, True)
        bundle = os.path.join(tmp, "bundle")
        password = os.path.join(tmp, "pw")
        with open(password, "w", encoding="utf-8") as handle:
            handle.write("secret\n")

        created = sh(
            find_binary(),
            "bundle-create",
            "cdr",
            "--dir",
            bundle,
            "--cipher",
            "chacha12",
            "--password-file",
            password,
            timeout=300,
            check=False,
        )
        if created.returncode != 0:
            if "requires the `cdr-bundle` feature" in created.stderr:
                self.skipTest("binary built without the cdr-bundle feature")
            self.fail(
                "bundle-create cdr --cipher failed:\n"
                f"{created.stdout}\n{created.stderr}"
            )

        with open(os.path.join(bundle, "SNOWBUNDLE"), encoding="ascii") as handle:
            manifest = handle.read()
        self.assertIn("kind = cdr", manifest)
        self.assertIn("cipher = chacha12", manifest)
        self.assertIn("kdf = pbkdf2-hmac-sha256", manifest)
        self.assertIn("iterations = ", manifest)
        for field in ("nonce", "key_id", "salt", "wrap_nonce", "wrapped_key", "tag"):
            self.assertIn(f"{field} = ", manifest, f"missing keyslot field {field}")

        with open(os.path.join(bundle, "toc.0"), "rb") as handle:
            toc = handle.read()
        self.assertIn(TOC_MAGIC.encode("ascii"), toc, "the TOC must stay plaintext")

        leftovers = sorted(name for name in os.listdir(bundle) if name.endswith(".tmp"))
        self.assertEqual(leftovers, [], f"temporary files left behind: {leftovers}")


if __name__ == "__main__":
    unittest.main()
