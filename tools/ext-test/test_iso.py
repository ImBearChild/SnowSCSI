#!/usr/bin/env python3
"""External-tool cross-validation of `snowscsi mkisofs`.

The Rust suite already cross-checks the live generator against the pure-Rust
`iso9660-no-std` reader. These tests add independent, spec-strict readers
that parse the **PVD tree** (8.3 uppercase identifiers) as well as the
Joliet tree, exercising the generated on-disk image as a black box:

- `file`      identifies the image as ISO 9660.
- `isoinfo -l` reads the PVD directory tree (8.3 names).
- `isoinfo -J -l` reads the Joliet (SVD) tree (UCS-2BE names).
- `7z l`      opens the image as an ISO archive.
- `bsdtar -tf` / `-x` lists and extracts through libarchive.

Every tool reads the same image produced once per class; tests skip when a
tool is absent. The oracle is the host directory tree: each tool must
reproduce the same names, sizes and content.
"""

import os
import shutil
import subprocess
import tempfile
import unittest

from harness import mkisofs

ROOT_FILES = {
    "README.TXT": b"hello root",
}
SUBDIR_FILES = {
    "docs/manual.pdf": b"\x41" * 2049,          # crosses a sector boundary
    "docs/deep/notes.txt": b"\x42" * 100,
    "images/photo.png": b"\x43" * 4096,
}


def build_tree(base):
    """Materialize ROOT_FILES + SUBDIR_FILES under `base`."""
    for rel, content in {**ROOT_FILES, **SUBDIR_FILES}.items():
        path = os.path.join(base, rel)
        os.makedirs(os.path.dirname(path), exist_ok=True)
        with open(path, "wb") as f:
            f.write(content)


class MkisofsExternalToolsTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tmp = tempfile.TemporaryDirectory()
        cls.tree = os.path.join(cls.tmp.name, "tree")
        os.makedirs(cls.tree)
        build_tree(cls.tree)
        cls.iso = os.path.join(cls.tmp.name, "out.iso")
        res = mkisofs(cls.tree, cls.iso, label="CROSS")
        assert res.returncode == 0, f"mkisofs failed: {res.stderr}"

    @classmethod
    def tearDownClass(cls):
        cls.tmp.cleanup()

    # ── helpers ─────────────────────────────────────────────────────

    def skip_unless(self, *tools):
        missing = [t for t in tools if shutil.which(t) is None]
        if missing:
            self.skipTest(f"missing tools: {missing}")

    def run_tool(self, argv):
        return subprocess.run(argv, capture_output=True, text=True)

    # ── file ────────────────────────────────────────────────────────

    def test_file_identifies_iso9660(self):
        self.skip_unless("file")
        r = self.run_tool(["file", self.iso])
        self.assertIn("ISO 9660", r.stdout)

    # ── isoinfo: PVD tree ───────────────────────────────────────────

    def test_isoinfo_pvd_lists_83_names(self):
        self.skip_unless("isoinfo")
        r = self.run_tool(["isoinfo", "-l", "-i", self.iso])
        self.assertEqual(r.returncode, 0, r.stderr)
        # PVD identifiers are Level 1 8.3, uppercase, with the ";1" version.
        self.assertIn("README.TXT;1", r.stdout)
        self.assertIn("DOCS", r.stdout)
        self.assertIn("MANUAL.PDF;1", r.stdout)
        self.assertIn("PHOTO.PNG;1", r.stdout)
        self.assertNotIn("manual.pdf", r.stdout)  # lowercase is Joliet-only

    # ── isoinfo: Joliet (SVD) tree ──────────────────────────────────

    def test_isoinfo_joliet_lists_original_names(self):
        self.skip_unless("isoinfo")
        r = self.run_tool(["isoinfo", "-J", "-l", "-i", self.iso])
        self.assertEqual(r.returncode, 0, r.stderr)
        for name in ("README.TXT", "docs", "manual.pdf", "photo.png"):
            self.assertIn(name, r.stdout)

    def test_isoinfo_extracts_file_content(self):
        self.skip_unless("isoinfo")
        r = self.run_tool(["isoinfo", "-J", "-x", "/docs/manual.pdf", "-i", self.iso])
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertEqual(r.stdout.encode(), SUBDIR_FILES["docs/manual.pdf"])

    # ── 7z ──────────────────────────────────────────────────────────

    def test_7z_lists_image(self):
        self.skip_unless("7z")
        r = self.run_tool(["7z", "l", self.iso])
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertNotIn("ERROR", r.stdout)
        for name in ("README.TXT", "docs/manual.pdf", "images/photo.png"):
            self.assertIn(name, r.stdout)

    def test_7z_extracts_file_content(self):
        self.skip_unless("7z")
        # `7z x -so` writes the single matched file to stdout.
        r = self.run_tool(["7z", "x", "-so", self.iso, "docs/manual.pdf"])
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertEqual(r.stdout.encode(), SUBDIR_FILES["docs/manual.pdf"])

    # ── bsdtar (libarchive) ─────────────────────────────────────────

    def test_bsdtar_lists_image(self):
        self.skip_unless("bsdtar")
        r = self.run_tool(["bsdtar", "-tf", self.iso])
        self.assertEqual(r.returncode, 0, r.stderr)
        for name in ("README.TXT", "docs/manual.pdf", "docs/deep/notes.txt",
                     "images/photo.png"):
            self.assertIn(name, r.stdout)

    def test_bsdtar_extracts_all_content(self):
        self.skip_unless("bsdtar")
        extract = os.path.join(self.tmp.name, "bsdtar-x")
        os.makedirs(extract, exist_ok=True)
        r = self.run_tool(["bsdtar", "-xf", self.iso, "-C", extract])
        self.assertEqual(r.returncode, 0, r.stderr)
        for rel, content in {**ROOT_FILES, **SUBDIR_FILES}.items():
            with open(os.path.join(extract, rel), "rb") as f:
                self.assertEqual(f.read(), content)


if __name__ == "__main__":
    unittest.main()
