#!/usr/bin/env python3
"""Encrypted-image tests for `snowscsi crypt` and `serve --block img=,cipher`.

Two layers:

- `CryptRoundTripTest` is unprivileged. It drives the real binary through
  `crypt` (out-of-place, `--in-place`, key-file) and checks the sidecar and
  the at-rest bytes.
- `CipherIscsiLoopbackTest` is root-gated. It creates a raw image, encrypts
  it with `snowscsi crypt`, serves it with `--block img=<enc>,cipher`, and
  runs the usual login/format/mount/write/read/fsck checklist. It also
  verifies that the raw file does **not** contain the ext4 magic while the
  mounted device works, and that `crypt --decrypt` restores an image that
  still passes `fsck`.

The stream ciphers are unauthenticated: a wrong password produces garbage
with exit 0 (documented), so this test always keeps the plaintext image for
comparison.
"""

import os
import shutil
import subprocess
import tempfile
import unittest

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

SIZE = "32M"
SIZE_BYTES = 32 * 1024 * 1024
EXT4_MAGIC = b"\x53\xef"  # s_magic at offset 0x438


def _write_pattern(path, size, seed=0x5A):
    chunk = bytes(((i * 31 + seed) & 0xFF) for i in range(64 * 1024))
    with open(path, "wb") as f:
        written = 0
        while written < size:
            n = min(len(chunk), size - written)
            f.write(chunk[:n])
            written += n


def _crypt(*args):
    return sh(find_binary(), "crypt", *args, check=False, timeout=300)


class CryptRoundTripTest(unittest.TestCase):
    """Unprivileged `crypt` checks."""

    def setUp(self):
        self.dir = tempfile.mkdtemp(prefix="snowscsi-crypt-")
        self.plain = os.path.join(self.dir, "plain.img")
        self.enc = os.path.join(self.dir, "enc.img")
        self.dec = os.path.join(self.dir, "dec.img")
        self.password = os.path.join(self.dir, "password.txt")
        # 65_537 is deliberately not 16- or 64-aligned.
        _write_pattern(self.plain, 65_537)
        with open(self.password, "wb") as f:
            f.write(b"test-password\n")

    def tearDown(self):
        shutil.rmtree(self.dir, ignore_errors=True)

    def test_roundtrip_and_sidecar(self):
        r = _crypt(
            "--cipher",
            "chacha12",
            "--password-file",
            self.password,
            self.plain,
            self.enc,
        )
        self.assertEqual(r.returncode, 0, r.stderr)
        sidecar = self.enc + ".SNOWBUNDLE"
        self.assertTrue(os.path.isfile(sidecar), "sidecar missing")
        with open(sidecar, encoding="utf-8") as f:
            manifest = f.read()
        self.assertIn("kind = image", manifest)
        self.assertIn("size = 65537", manifest)
        self.assertIn("cipher = chacha12", manifest)
        self.assertIn("crc = ", manifest)

        with open(self.plain, "rb") as f:
            plain = f.read()
        with open(self.enc, "rb") as f:
            enc = f.read()
        self.assertNotEqual(plain, enc, "the image must be ciphertext at rest")

        r = _crypt("--decrypt", "--password-file", self.password, self.enc, self.dec)
        self.assertEqual(r.returncode, 0, r.stderr)
        with open(self.dec, "rb") as f:
            self.assertEqual(f.read(), plain)

        leftovers = [n for n in os.listdir(self.dir) if ".tmp." in n or n.endswith(".lock")]
        self.assertEqual(leftovers, [], f"leftover temp/lock files: {leftovers}")

    def test_in_place_and_key_file(self):
        key = os.path.join(self.dir, "key.bin")
        with open(key, "wb") as f:
            f.write(bytes(range(32)))
        r = _crypt(
            "--cipher", "aes-ctr", "--key-file", key, "--in-place", self.plain
        )
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertTrue(os.path.isfile(self.plain + ".SNOWBUNDLE"))
        with open(self.plain + ".SNOWBUNDLE", encoding="utf-8") as f:
            self.assertIn("kdf = none", f.read())
        r = _crypt("--decrypt", "--key-file", key, self.plain, self.dec)
        self.assertEqual(r.returncode, 0, r.stderr)
        with open(self.dec, "rb") as f:
            self.assertEqual(len(f.read()), 65_537)

    def test_missing_sidecar_is_a_hard_error(self):
        r = _crypt("--decrypt", "--password-file", self.password, self.plain, self.dec)
        self.assertNotEqual(r.returncode, 0)
        self.assertFalse(os.path.exists(self.dec))


@unittest.skipUnless(
    is_root() and have_tool("iscsiadm") and have_tool("mkfs.ext4"),
    "requires root + iscsiadm + mkfs.ext4",
)
class CipherIscsiLoopbackTest(unittest.TestCase):
    """Serve an encrypted raw image over iSCSI and mount it."""

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
        self.dir = tempfile.mkdtemp(prefix="snowscsi-cipher-")
        self.plain = os.path.join(self.dir, "plain.img")
        self.enc = os.path.join(self.dir, "enc.img")
        self.password = os.path.join(self.dir, "password.txt")
        _write_pattern(self.plain, SIZE_BYTES)
        with open(self.password, "wb") as f:
            f.write(b"loopback-password\n")
        r = _crypt(
            "--cipher",
            "chacha20",
            "--password-file",
            self.password,
            "--force",
            self.plain,
            self.enc,
        )
        self.assertEqual(r.returncode, 0, r.stderr)
        self.server = ServerHandle(
            "--block",
            f"img={self.enc},cipher",
            "--password-file",
            self.password,
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
            pass
        shutil.rmtree(self.dir, ignore_errors=True)

    def test_mount_write_fsck_and_at_rest(self):
        dev = self.session.login(expected_bytes=SIZE_BYTES)
        full_disk_test(dev, SIZE_BYTES)
        self.mount = mount_ext4(dev)
        payload = os.urandom(1 << 20)
        with open(os.path.join(self.mount, "payload.bin"), "wb") as f:
            f.write(payload)
        sh("sync")
        with open(os.path.join(self.mount, "payload.bin"), "rb") as f:
            self.assertEqual(f.read(), payload)
        unmount(self.mount, check=True)
        self.mount = None
        sh("fsck.ext4", "-fn", dev)

        # The ext4 superblock magic must not be visible in the raw file.
        with open(self.enc, "rb") as f:
            f.seek(0x438)
            self.assertNotEqual(f.read(2), EXT4_MAGIC, "raw image contains the ext4 magic")

        # Decrypting the served image restores a valid filesystem image.
        # The server only reads the ciphertext while it is idle.
        dec = os.path.join(self.dir, "dec.img")
        r = _crypt("--decrypt", "--password-file", self.password, self.enc, dec)
        self.assertEqual(r.returncode, 0, r.stderr)
        sh("fsck.ext4", "-fn", dec)


@unittest.skipUnless(have_tool("iscsiadm") and is_root(), "requires root + iscsiadm")
class CipherMissingSidecarTest(unittest.TestCase):
    def test_serve_refuses_without_the_sidecar(self):
        d = tempfile.mkdtemp(prefix="snowscsi-nosidecar-")
        try:
            img = os.path.join(d, "disk.img")
            _write_pattern(img, 1 << 20)
            r = subprocess.run(
                [
                    find_binary(),
                    "serve",
                    "--iscsi",
                    "127.0.0.1:0",
                    "--block",
                    f"img={img},cipher",
                ],
                capture_output=True,
                text=True,
                timeout=30,
            )
            self.assertNotEqual(r.returncode, 0)
            self.assertIn("SNOWBUNDLE", r.stderr)
        finally:
            shutil.rmtree(d, ignore_errors=True)


if __name__ == "__main__":
    unittest.main()
