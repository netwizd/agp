#!/usr/bin/env python3
"""Packaging contract tests; fixture ELF files are never executed."""
import hashlib
import importlib.util
import json
from pathlib import Path
import struct
import tarfile
import tempfile
import unittest

SPEC = importlib.util.spec_from_file_location("release_package", Path(__file__).with_name("package-release.py"))
PACKAGE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(PACKAGE)


def fixture_elf():
    raw = bytearray(128)
    raw[:7] = b"\x7fELF\x02\x01\x01"
    struct.pack_into("<HHI", raw, 16, 2, 62, 1)
    struct.pack_into("<Q", raw, 32, 64)
    struct.pack_into("<HHH", raw, 52, 64, 56, 1)
    struct.pack_into("<I", raw, 64, 1)  # fixture PT_LOAD
    return bytes(raw)


class Packaging(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="agp-package-test-")
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.source = self.root / "source"
        self.binaries = self.root / "bin"
        self.binaries.mkdir()
        (self.source / "deploy/systemd").mkdir(parents=True)
        for role in PACKAGE.ROLES:
            (self.binaries / role).write_bytes(fixture_elf())
        for unit in PACKAGE.UNITS:
            (self.source / "deploy/systemd" / unit).write_text("[Service]\nExecStart=/fixture-only\n")
        (self.source / "go.mod").write_text("module fixture.invalid/test\n")
        (self.source / "go.sum").write_text("fixture inventory only\n")
        for name in ("install.sh", "update.sh"):
            (self.source / name).write_text("#!/usr/bin/env bash\n# fixture only\nexit 1\n")
        migration = self.source / "internal/storage/sqlite/migrations/001.sql"
        migration.parent.mkdir(parents=True)
        migration.write_text("CREATE TABLE example(id INTEGER PRIMARY KEY);\n")

    def package(self, output="out", version="v0.0.0-test.1", commit="f" * 40):
        return PACKAGE.package(self.source, self.binaries, self.root / output, version, commit, 0)

    def test_complete_archive_and_every_digest(self):
        archive, expected = self.package()
        self.assertEqual(expected, hashlib.sha256(archive.read_bytes()).hexdigest())
        with tarfile.open(archive) as tar:
            manifest = json.load(tar.extractfile("release.json"))
            files = {entry["path"]: entry for entry in manifest["files"]}
            self.assertEqual(set(files), {f"bin/{r}" for r in PACKAGE.ROLES} | {f"systemd/{u}" for u in PACKAGE.UNITS})
            self.assertEqual(set(tar.getnames()), set(files) | {"release.json"})
            for name, entry in files.items():
                raw = tar.extractfile(name).read()
                self.assertEqual(entry["size"], len(raw))
                self.assertEqual(entry["sha256"], hashlib.sha256(raw).hexdigest())
                self.assertEqual(tar.getmember(name).mode, int(entry["mode"], 8))
            self.assertEqual(manifest["database"]["rollback"], "manual-database-restore")
        inv = json.loads((archive.parent / "agp_v0.0.0-test.1_inventory.json").read_bytes())
        self.assertEqual(len(inv["migrations"]), 1)
        self.assertIn("not a TUF", inv["qualification"])
        for name in ("install.sh", "update.sh"):
            self.assertEqual((archive.parent / name).read_bytes(), (self.source / name).read_bytes())

    def test_reproducible_across_directories_and_input_mtimes(self):
        first, sha1 = self.package()
        for binary in self.binaries.iterdir():
            binary.touch()
        second, sha2 = self.package("another")
        self.assertEqual(sha1, sha2)
        self.assertEqual(first.read_bytes(), second.read_bytes())

    def test_refuses_to_overwrite(self):
        path, _ = self.package()
        before = path.read_bytes()
        with self.assertRaises(ValueError):
            self.package()
        self.assertEqual(path.read_bytes(), before)

    def test_missing_role_refused_before_output(self):
        (self.binaries / "agp-helper").unlink()
        with self.assertRaises(OSError):
            self.package()
        self.assertFalse((self.root / "out").exists())

    def test_symlink_binary_refused(self):
        target = self.binaries / "agp"
        target.unlink()
        target.symlink_to("agpctl")
        with self.assertRaises(OSError):
            self.package()

    def test_script_and_wrong_arch_refused(self):
        for raw in (b"#!/bin/sh\nexit 0\n", fixture_elf()[:18] + b"\xb7\x00" + fixture_elf()[20:]):
            with self.subTest(raw=raw[:20]):
                (self.binaries / "agp").write_bytes(raw)
                with self.assertRaises(ValueError):
                    self.package()

    def test_dynamic_loader_or_library_refused(self):
        for ptype in (2, 3):
            raw = bytearray(fixture_elf())
            struct.pack_into("<I", raw, 64, ptype)
            (self.binaries / "agp").write_bytes(raw)
            with self.assertRaisesRegex(ValueError, "dynamic runtime dependency"):
                self.package()

    def test_invalid_versions_or_missing_full_identity(self):
        for version, commit in (("latest", "f" * 40), ("v1.0.0/../x", "f" * 40),
                                ("v1.0.0", "unknown"), ("v1.0.0", "f" * 7)):
            with self.subTest(version=version, commit=commit):
                with self.assertRaises(ValueError):
                    self.package(version=version, commit=commit)


if __name__ == "__main__":
    unittest.main()
