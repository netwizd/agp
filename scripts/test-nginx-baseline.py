#!/usr/bin/env python3
"""Regression tests for source pin drift and fail-closed native entry points.

Synthetic -V producers only test gate rejection. They never qualify a Nginx
runtime or replace the mandatory real native request/HTTP integration suite.
"""
import importlib.util
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch


REPO = Path(__file__).resolve().parents[1]
sys.dont_write_bytecode = True
SPEC = importlib.util.spec_from_file_location("nginx_baseline", REPO / "scripts/check-nginx-baseline.py")
BASELINE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(BASELINE)
FLAGS = "--with-http_auth_request_module --with-http_ssl_module --with-http_v2_module"


class BaselineTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix="agp-nginx-baseline-")
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        (self.root / "scripts").mkdir()
        (self.root / "configs").mkdir()
        self.env_file = self.root / "scripts/nginx-toolchain.env"
        self.lock_file = self.root / "configs/waf-native.lock.json"
        shutil.copyfile(REPO / "scripts/nginx-toolchain.env", self.env_file)
        shutil.copyfile(REPO / "configs/waf-native.lock.json", self.lock_file)
        self.environment = patch.dict(os.environ, {"NGINX_VERSION": ""})
        self.environment.start()
        self.addCleanup(self.environment.stop)

    def replace_env(self, key, value):
        lines = self.env_file.read_text().splitlines()
        self.env_file.write_text("\n".join(key + "=" + value if line.startswith(key + "=") else line for line in lines) + "\n")

    def replace_lock(self, update):
        lock = json.loads(self.lock_file.read_text())
        update(lock)
        self.lock_file.write_text(json.dumps(lock))

    def binary(self, version="1.30.8", flags=FLAGS, extra="", status=0, raw=None):
        binary = self.root / "nginx"
        if binary.exists():
            binary.chmod(0o700)
        output = raw if raw is not None else "nginx version: nginx/" + version + "\nbuilt by GCC\n" + extra + "configure arguments: " + flags + "\n"
        # repr is Python source, not shell interpolation; no untrusted expansion.
        binary.write_text("#!/usr/bin/env python3\nimport sys\nif sys.argv != ['" + str(binary) + "', '-V']: sys.exit(90)\nsys.stderr.write(" + repr(output) + ")\nsys.exit(" + str(status) + ")\n")
        binary.chmod(0o500)
        return binary

    def test_reviewed_source_and_runtime_pass(self):
        self.assertEqual(BASELINE.check_source(self.root), "1.30.8")
        binary, output = BASELINE.check_runtime(self.binary(), "1.30.8")
        self.assertEqual(binary, str(self.root / "nginx"))
        self.assertIn("nginx/1.30.8", output)

    def test_old_source_pin_fails_security_floor(self):
        self.replace_env("AGP_NGINX_QUALIFIED_VERSION", "1.30.6")
        with self.assertRaisesRegex(ValueError, "below the security floor"):
            BASELINE.check_source(self.root)

    def test_lowering_configured_security_floor_is_rejected(self):
        self.replace_env("AGP_NGINX_SECURITY_FLOOR", "1.30.6")
        with self.assertRaisesRegex(ValueError, "security floor differs"):
            BASELINE.check_source(self.root)

    def test_new_version_cannot_self_qualify_by_changing_env_and_lock(self):
        self.replace_env("AGP_NGINX_QUALIFIED_VERSION", "1.30.9")
        self.replace_lock(lambda lock: lock["tuple"].update(nginx="1.30.9"))
        with self.assertRaisesRegex(ValueError, "no native qualification"):
            BASELINE.check_source(self.root)

    def test_pin_lock_mismatch_rejected(self):
        self.replace_lock(lambda lock: lock["tuple"].update(nginx="1.30.6"))
        with self.assertRaisesRegex(ValueError, "version mismatch"):
            BASELINE.check_source(self.root)

    def test_archive_hash_mismatch_rejected(self):
        self.replace_lock(lambda lock: lock["sources"][0].update(sha256="0" * 64))
        with self.assertRaisesRegex(ValueError, "digest/native lock mismatch"):
            BASELINE.check_source(self.root)

    def test_signature_hash_mismatch_rejected(self):
        self.replace_lock(lambda lock: lock["sources"][1].update(sha256="0" * 64))
        with self.assertRaisesRegex(ValueError, "digest/native lock mismatch"):
            BASELINE.check_source(self.root)

    def test_archive_url_mismatch_rejected(self):
        self.replace_lock(lambda lock: lock["sources"][0].update(url="https://example.invalid/nginx-1.30.8.tar.gz"))
        with self.assertRaisesRegex(ValueError, "URL/version mismatch"):
            BASELINE.check_source(self.root)

    def test_source_signer_mismatch_rejected(self):
        self.replace_lock(lambda lock: lock["signers"].update(nginx="0" * 40))
        with self.assertRaisesRegex(ValueError, "source signer/native lock mismatch"):
            BASELINE.check_source(self.root)

    def test_locked_source_requires_h2(self):
        self.replace_lock(lambda lock: lock["nginxConfigure"].remove("--with-http_v2_module"))
        with self.assertRaisesRegex(ValueError, "lacks required"):
            BASELINE.check_source(self.root)

    def test_required_env_flags_cannot_drop_h2(self):
        self.replace_env("AGP_NGINX_REQUIRED_MODULES", "'--with-http_auth_request_module --with-http_ssl_module'")
        with self.assertRaisesRegex(ValueError, "differ from reviewed baseline"):
            BASELINE.check_source(self.root)

    def test_shell_expression_in_env_is_never_evaluated(self):
        self.replace_env("AGP_NGINX_QUALIFIED_VERSION", "'$(touch never-evaluate)'")
        with self.assertRaisesRegex(ValueError, "invalid Nginx pin value"):
            BASELINE.check_source(self.root)
        self.assertFalse((self.root / "never-evaluate").exists())

    def test_duplicate_env_assignment_rejected(self):
        self.env_file.write_text(self.env_file.read_text() + "AGP_NGINX_QUALIFIED_VERSION=1.30.8\n")
        with self.assertRaisesRegex(ValueError, "unknown or duplicate"):
            BASELINE.check_source(self.root)

    def test_duplicate_lock_field_rejected(self):
        self.lock_file.write_text('{"format":"agp.waf-native-lock/v1","format":"agp.waf-native-lock/v1"}')
        with self.assertRaisesRegex(ValueError, "duplicate JSON field"):
            BASELINE.check_source(self.root)

    def test_runtime_old_new_mainline_prerelease_and_malformed_rejected(self):
        for version in ("1.30.6", "1.30.7", "1.30.9", "1.31.10", "1.30.8-rc1", "01.30.8", "1.30.8 extra", "garbage"):
            with self.subTest(version=version):
                with self.assertRaises(ValueError):
                    BASELINE.check_runtime(self.binary(version), "1.30.8")

    def test_runtime_requires_every_exact_configure_flag(self):
        for flag in FLAGS.split():
            with self.subTest(missing=flag):
                with self.assertRaisesRegex(ValueError, "required Nginx configure flag missing"):
                    BASELINE.check_runtime(self.binary(flags=FLAGS.replace(flag, "")), "1.30.8")

    def test_flag_elsewhere_in_output_does_not_count(self):
        with self.assertRaisesRegex(ValueError, "required Nginx configure flag missing"):
            BASELINE.check_runtime(self.binary(flags=FLAGS.replace("--with-http_v2_module", ""),
                                                extra="built with --with-http_v2_module\n"), "1.30.8")

    def test_configure_flag_value_is_not_the_required_module(self):
        with self.assertRaisesRegex(ValueError, "required Nginx configure flag missing"):
            BASELINE.check_runtime(self.binary(flags=FLAGS.replace("--with-http_v2_module", "--with-http_v2_module=no")), "1.30.8")

    def test_ambiguous_or_missing_version_and_arguments_rejected(self):
        for output in ("nginx version: nginx/1.30.8\n",
                       "nginx version: nginx/1.30.8\nnginx version: nginx/1.30.6\nconfigure arguments: " + FLAGS + "\n",
                       "nginx version: nginx/1.30.8\nconfigure arguments: " + FLAGS + "\nconfigure arguments: " + FLAGS + "\n",
                       "configure arguments: " + FLAGS + "\nnginx version: nginx/1.30.8\n"):
            with self.subTest(output=output):
                with self.assertRaises(ValueError):
                    BASELINE.check_runtime(self.binary(raw=output), "1.30.8")

    def test_failed_version_command_rejected(self):
        with self.assertRaisesRegex(ValueError, "Nginx -V failed"):
            BASELINE.check_runtime(self.binary(status=1), "1.30.8")

    def test_wrong_override_rejected(self):
        with patch.dict(os.environ, {"NGINX_VERSION": "1.30.6"}):
            with self.assertRaisesRegex(ValueError, "NGINX_VERSION differs"):
                BASELINE.check_source(self.root)

    def test_native_entry_points_reject_old_runtime_before_tests(self):
        # A fake PG tool directory satisfies read-only preflight only. All entry
        # points must stop at the Nginx gate before Go, database or npm work.
        pgbin = self.root / "pg"
        pgbin.mkdir()
        for name in ("initdb", "pg_ctl", "postgres", "psql", "createdb", "pg_dump", "pg_restore"):
            shutil.copyfile("/bin/false", pgbin / name)
            (pgbin / name).chmod(0o500)
        environment = dict(os.environ, AGP_TEST_NGINX_BIN=str(self.binary("1.30.6")),
                           AGP_TEST_PG_BINDIR=str(pgbin), AGP_TEST_POSTGRES_DSN="not-used")
        for entry in ("test-nginx.sh", "test-s0-full.sh", "release-check.sh"):
            with self.subTest(entry=entry):
                result = subprocess.run(["bash", str(REPO / "scripts" / entry)], cwd=REPO,
                                        env=environment, capture_output=True, text=True, timeout=20)
                self.assertNotEqual(result.returncode, 0)
                self.assertIn("Nginx runtime is below the security floor", result.stderr)

    def test_native_suite_rejects_successful_go_exit_with_skip_or_missing_case(self):
        fake_go = self.root / "go"
        environment = dict(os.environ, AGP_TEST_NGINX_BIN=str(self.binary()), GO=str(fake_go))
        identity = "--- PASS: TestNativeIdentityHeaderSpoofing (0.01s)\n"
        management = "--- PASS: TestNativeManagementHostIsolation (0.01s)\n"
        for output in (identity + management,
                       identity + management + "--- SKIP: TestNativeEdgeAuthIsolation (0.01s)\n",
                       "ok example.test/package 0.01s\n"):
            with self.subTest(output=output):
                fake_go.write_text("#!/usr/bin/env python3\nprint(" + repr(output) + ", end='')\n")
                fake_go.chmod(0o700)
                result = subprocess.run(["sh", str(REPO / "scripts/test-nginx.sh")], cwd=REPO,
                                        env=environment, capture_output=True, text=True, timeout=20)
                self.assertNotEqual(result.returncode, 0)
                self.assertIn("native cases must all pass without SKIP", result.stderr)


if __name__ == "__main__":
    unittest.main(verbosity=2)
