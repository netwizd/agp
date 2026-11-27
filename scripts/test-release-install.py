#!/usr/bin/env python3
"""Offline installer adversarial/transaction tests; never touches systemd or host paths."""

import contextlib
import hashlib
import importlib.util
import io
import json
import os
from pathlib import Path
import sqlite3
import subprocess
import sys
import tarfile
import tempfile
import unittest
from unittest import mock


ROOT = Path(__file__).resolve().parent.parent
SPEC = importlib.util.spec_from_file_location("agp_release", ROOT / "scripts/lib/agp_release.py")
release = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(release)
COMMIT = "a" * 40
try:
    release.ctypes.CDLL("libpq.so.5")
    LIBPQ_AVAILABLE = True
except OSError:
    LIBPQ_AVAILABLE = False


def bundle(directory, version="v1.0.0", transform=None, entries=None):
    contents = {}
    for name in release.PAYLOAD:
        if name.startswith("bin/"):
            header = bytearray(64)
            header[:6] = b"\x7fELF\x02\x01"
            header[18:20] = b"\x3e\x00"
            data = bytes(header) + version.encode() + name.encode()
        else:
            data = b"[Service]\nExecStart=/usr/local/bin/agp\n"
        contents[name] = data
    manifest = {"schema": 1, "version": version, "commit": COMMIT, "platform": release.PLATFORM,
                "database": {"startup_migrations": True, "rollback": "manual-database-restore"},
                "files": [{"path": name, "mode": mode, "sha256": hashlib.sha256(contents[name]).hexdigest(),
                           "size": len(contents[name])} for name, mode in release.PAYLOAD.items()]}
    if transform:
        transform(manifest, contents)
    contents["release.json"] = json.dumps(manifest).encode()
    archive = directory / (version + ".tar.gz")
    with tarfile.open(archive, "w:gz") as stream:
        for name, data in contents.items():
            info = tarfile.TarInfo(name)
            info.mode = int(release.PAYLOAD.get(name, "0644"), 8)
            info.size = len(data)
            stream.addfile(info, io.BytesIO(data))
        if entries:
            entries(stream)
    return archive, release.digest(archive), manifest


class FakeHost(release.Host):
    def __init__(self, root):
        super().__init__(root)
        self.uid, self.gid = os.getuid(), os.getgid()
        self.running = False
        self.events = []
        self.fail_backup = False
        self.fail_ready = False
        self.fail_start = False
        self.fail_reload = False
        self.ancillary_active = False
        self.startup_markers = []
        self.enabled = False

    def preflight(self):
        self.events.append("preflight")

    def account(self):
        self.agp_uid, self.agp_gid = self.uid, self.gid

    def ancillary_check(self):
        if self.ancillary_active:
            release.fail("active ancillary role requires coordinated upgrade")

    def version_check(self, staged, manifest):
        self.events.append("version")

    def active(self):
        return self.running

    def systemctl(self, *args):
        self.events.append(args[0])
        if args[0] == "stop":
            self.running = False
        if args[0] == "start":
            if self.path("/var/lib/agp-release/recovery-blocked.json").exists():
                release.fail("systemd startup is blocked pending recovery")
            self.startup_markers.append(self.host_marker_exists())
            self.running = True
            # Model startup migrations creating a SQLite database.
            database = self.path("/var/lib/agp/agp.db")
            if not database.exists():
                with sqlite3.connect(database) as connection:
                    connection.execute("CREATE TABLE IF NOT EXISTS bootstrap_migrations (id INTEGER)")
            if self.fail_start:
                release.fail("injected startup failure after migration")
        if args[0] == "daemon-reload" and self.fail_reload:
            self.fail_reload = False
            release.fail("injected daemon-reload failure")
        if args[0] == "enable":
            self.enabled = True

    def host_marker_exists(self):
        return self.path("/var/lib/agp-release/recovery-required.json").is_file()

    def backup_database(self, config, destination, allow_absent=False):
        self.events.append("backup")
        if self.running:
            raise AssertionError("backup while service is active")
        if self.fail_backup:
            release.fail("injected backup failure")
        return super().backup_database(config, destination, allow_absent)

    def ready(self, config):
        self.events.append("ready")
        if self.fail_ready:
            release.fail("injected readiness failure")


class InstallerTests(unittest.TestCase):
    def setUp(self):
        previous_umask = os.umask(0o077)
        self.addCleanup(os.umask, previous_umask)
        self.temp = tempfile.TemporaryDirectory(prefix="agp-installer-test-")
        self.addCleanup(self.temp.cleanup)
        self.directory = Path(self.temp.name)
        self.host = FakeHost(self.directory / "host")
        self.host.root.mkdir()
        self.host.path("/root").mkdir(mode=0o700)
        self.config = self.host.path("/root/prepared.env")
        self.config.write_text("AGP_DATABASE_DRIVER=sqlite\nAGP_DATABASE_PATH=/var/lib/agp/agp.db\n"
                               "AGP_HTTP_ADDR=127.0.0.1:8080\nSECRET='literal $dollar `backtick`'\n")
        self.config.chmod(0o600)
        self.output = io.StringIO()

    def staged(self, version="v1.0.0", transform=None, entries=None):
        archive, sha, _ = bundle(self.directory, version, transform, entries)
        target = self.directory / ("staged-" + version)
        manifest = release.verify_extract(archive, target, version, sha)
        return target, manifest, sha

    def apply(self, version="v1.0.0", mode="install"):
        staged, manifest, sha = self.staged(version)
        with contextlib.redirect_stdout(self.output), contextlib.redirect_stderr(self.output):
            release.install_release(self.host, staged, manifest, sha, mode,
                                    self.config if mode == "install" else None)
        return manifest, sha

    def test_bootstraps_are_exact_standalone_copies(self):
        for mode in ("install", "update"):
            self.assertEqual((ROOT / (mode + ".sh")).read_text(), release.bootstrap(mode))

    def test_complete_bundle_verified(self):
        staged, manifest, sha = self.staged()
        self.assertEqual(len(manifest["files"]), 12)
        self.assertEqual({str(p.relative_to(staged)) for p in staged.rglob("*") if p.is_file()},
                         {*release.PAYLOAD, "release.json"})

    def test_wrong_archive_pin_fails_before_extraction(self):
        archive, sha, _ = bundle(self.directory)
        target = self.directory / "untrusted"
        with self.assertRaisesRegex(release.ReleaseError, "SHA256 mismatch"):
            release.verify_extract(archive, target, "v1.0.0", "0" * 64)
        self.assertFalse(target.exists())

    def test_wrong_payload_digest_fails(self):
        def corrupt(manifest, contents):
            contents["bin/agp"] += b"tampered"
            manifest["files"][0]["size"] = len(contents["bin/agp"])
        with self.assertRaisesRegex(release.ReleaseError, "payload checksum mismatch"):
            self.staged(transform=corrupt)

    def test_offline_archive_replacement_after_snapshot_cannot_change_extraction(self):
        archive, sha, _ = bundle(self.directory)
        original = release.extract_snapshot
        def mutate_original(snapshot, destination, version):
            archive.write_bytes(b"attacker replaces the original after its pin was checked")
            return original(snapshot, destination, version)
        with mock.patch.object(release, "extract_snapshot", side_effect=mutate_original):
            manifest = release.verify_extract(archive, self.directory / "snapshot-extract", "v1.0.0", sha)
        self.assertEqual(manifest["version"], "v1.0.0")

    def test_huge_extended_metadata_and_declared_payload_rejected_before_body(self):
        for index, kind in enumerate((tarfile.XHDTYPE, tarfile.XGLTYPE, tarfile.GNUTYPE_LONGNAME,
                                      tarfile.GNUTYPE_SPARSE, tarfile.REGTYPE)):
            archive = self.directory / ("huge-" + str(index) + ".tar.gz")
            entry = tarfile.TarInfo("hostile")
            entry.type = kind
            entry.size = 2 ** 40
            # A compressed header only: no terabyte body is allocated or read.
            import gzip
            with gzip.open(archive, "wb") as output:
                output.write(entry.tobuf(format=tarfile.GNU_FORMAT))
            with self.subTest(kind=kind), self.assertRaises(release.ReleaseError):
                release.verify_extract(archive, self.directory / ("huge-out-" + str(index)),
                                       "v1.0.0", release.digest(archive))

    def test_excessive_entries_rejected_incrementally(self):
        def append(stream):
            for index in range(4):
                entry = tarfile.TarInfo("extra-" + str(index))
                entry.type = tarfile.DIRTYPE
                stream.addfile(entry)
        with self.assertRaises(release.ReleaseError):
            self.staged(entries=append)

    def test_platform_migration_contract_missing_role_fail(self):
        cases = (
            lambda m, c: m.update(platform="ubuntu26.04-linux-amd64"),
            lambda m, c: m["database"].update(rollback="automatic"),
            lambda m, c: m["database"].update(startup_migrations=1),
            lambda m, c: m["files"].pop(),
            lambda m, c: m["files"][0].update(mode="04755"),
            lambda m, c: m["files"][0].update(sha256="not-a-hash"),
            lambda m, c: m["files"].append(m["files"][0]),
        )
        for i, transform in enumerate(cases):
            with self.subTest(case=i), self.assertRaises(release.ReleaseError):
                self.staged(version="v1.0." + str(i), transform=transform)

    def test_traversal_symlink_hardlink_special_duplicate_rejected(self):
        cases = (("../escape", tarfile.REGTYPE), ("/absolute", tarfile.REGTYPE),
                 ("bin/agp", tarfile.SYMTYPE), ("bin/evil", tarfile.LNKTYPE),
                 ("device", tarfile.CHRTYPE), ("release.json", tarfile.REGTYPE))
        for i, (name, kind) in enumerate(cases):
            def append(stream):
                entry = tarfile.TarInfo(name)
                entry.type = kind
                entry.linkname = "/etc/shadow" if kind in (tarfile.SYMTYPE, tarfile.LNKTYPE) else ""
                stream.addfile(entry)
            with self.subTest(case=i), self.assertRaises(release.ReleaseError):
                self.staged("v1.1." + str(i), entries=append)
        self.assertFalse((self.directory / "escape").exists())

    def test_duplicate_json_rejected(self):
        with self.assertRaisesRegex(release.ReleaseError, "duplicate JSON key"):
            release.read_json('{"schema":1,"schema":1}')

    def test_redirects_only_approved_https_hosts(self):
        for url in ("http://github.com/a", "https://evil.test/a", "file:///etc/shadow",
                    "https://user:secret@github.com/a", "https://github.com:444/a"):
            with self.subTest(url=url), self.assertRaises(release.ReleaseError):
                release.validate_download_url(url)
        release.validate_download_url("https://release-assets.githubusercontent.com/path?signed=1")

    def test_environment_never_executes_shell(self):
        marker = self.directory / "must-not-exist"
        self.config.write_text("AGP_DATABASE_DRIVER=postgres\nAGP_DATABASE_DSN='postgres://user:$(touch " +
                               str(marker) + ")@127.0.0.1/db'\n")
        values = release.parse_environment(self.config)
        self.assertIn("$(touch ", values["AGP_DATABASE_DSN"])
        self.assertFalse(marker.exists())

    @unittest.skipUnless(LIBPQ_AVAILABLE, "requires installed PostgreSQL client libpq.so.5")
    def test_postgres_uri_credentials_tls_and_quoting_map_without_argv(self):
        values = release.postgres_environment("postgresql://user%20name:p%40ss%3Aword@db.example:6432/app%20db"
                                              "?sslmode=verify-full&sslrootcert=%2Froot%2Fca.pem"
                                              "&connect_timeout=7&application_name=release%20test")
        self.assertEqual(values["PGUSER"], "user name")
        self.assertEqual(values["PGPASSWORD"], "p@ss:word")
        self.assertEqual(values["PGHOST"], "db.example")
        self.assertEqual(values["PGPORT"], "6432")
        self.assertEqual(values["PGDATABASE"], "app db")
        self.assertEqual(values["PGSSLMODE"], "verify-full")
        self.assertEqual(values["PGSSLROOTCERT"], "/root/ca.pem")
        self.assertEqual(values["PGCONNECT_TIMEOUT"], "7")
        self.assertEqual(values["PGAPPNAME"], "release test")

    @unittest.skipUnless(LIBPQ_AVAILABLE, "requires installed PostgreSQL client libpq.so.5")
    def test_postgres_keyword_socket_spaces_and_password_escapes(self):
        values = release.postgres_environment("host='/tmp/socket with space' port=55361 dbname='app db' "
                                              "user=release_user password='p\\'ss with space' sslmode=disable")
        self.assertEqual(values["PGHOST"], "/tmp/socket with space")
        self.assertEqual(values["PGPORT"], "55361")
        self.assertEqual(values["PGDATABASE"], "app db")
        self.assertEqual(values["PGPASSWORD"], "p'ss with space")

    @unittest.skipUnless(LIBPQ_AVAILABLE, "requires installed PostgreSQL client libpq.so.5")
    def test_postgres_bad_dsn_does_not_print_secrets_or_accept_unmapped_options(self):
        with self.assertRaises(release.ReleaseError) as error:
            release.postgres_environment("postgresql://user:super-secret@%invalid")
        self.assertNotIn("super-secret", str(error.exception))
        with self.assertRaisesRegex(release.ReleaseError, "no safe environment mapping"):
            release.postgres_environment("dbname=app fallback_application_name=unsupported")

    @unittest.skipUnless(LIBPQ_AVAILABLE, "requires installed PostgreSQL client libpq.so.5")
    def test_postgres_dump_argv_contains_no_password_or_full_dsn(self):
        self.host.account()
        backup = self.directory / "postgres-backup"
        backup.mkdir()
        calls = []
        def command(args, env=None, timeout=None, capture=False):
            calls.append((args, env))
            if args[0].endswith("pg_dump"):
                target = Path(next(item.removeprefix("--file=") for item in args if item.startswith("--file=")))
                target.write_bytes(b"PGDMP test fixture")
        self.host.command = command
        self.host.backup_database({"AGP_DATABASE_DRIVER": "postgres",
                                   "AGP_DATABASE_DSN": "postgresql://user:password-secret@127.0.0.1:5433/app"}, backup)
        self.assertEqual(calls[0][1]["PGDATABASE"], "app")
        self.assertEqual(calls[0][1]["PGPASSWORD"], "password-secret")
        self.assertNotIn("password-secret", str([item[0] for item in calls]))
        self.assertNotIn("postgresql://", str([item[0] for item in calls]))

    def test_ambiguous_environment_rejected(self):
        for data in ("AGP_DATABASE_DRIVER=sqlite\nAGP_DATABASE_PATH=../../etc/secret\n",
                     "AGP_DATABASE_DRIVER=postgres\nAGP_DATABASE_DSN=x\nAGP_DATABASE_DSN=y\n",
                     "AGP_DATABASE_DRIVER=postgres\nAGP_DATABASE_DSN='unterminated\n",
                     "AGP_DATABASE_DRIVER=postgres\nAGP_DATABASE_DSN=x\\\ny\n",
                     "AGP_DATABASE_DRIVER=postgres\nAGP_DATABASE_DSN=x\nAGP_HTTP_ADDR=0.0.0.0:8080\n"):
            self.config.write_text(data)
            with self.subTest(data=data), self.assertRaises(release.ReleaseError):
                release.parse_environment(self.config)

    def test_install_installs_all_roles_and_only_enables_controlplane(self):
        manifest, sha = self.apply()
        for role in release.ROLES:
            self.assertEqual(os.readlink(self.host.path("/usr/local/bin/" + role)), "/opt/agp/current/bin/" + role)
        for unit in release.UNITS:
            self.assertTrue(self.host.path("/etc/systemd/system/" + unit).is_symlink())
        self.assertTrue(self.host.running)
        self.assertEqual(self.host.events.count("enable"), 1)
        self.assertEqual(self.host.path("/etc/agp/agp.env").read_bytes(), self.config.read_bytes())
        state = json.loads(self.host.path("/var/lib/agp-release/current.json").read_text())
        self.assertEqual(state["sha256"], sha)
        self.assertLess(self.host.events.index("backup"), self.host.events.index("start"))
        self.assertEqual(self.host.startup_markers, [True])
        self.assertFalse(self.host.host_marker_exists())

    def test_configuration_parse_backup_and_install_use_one_snapshot(self):
        original = self.config.read_bytes()
        def change_source_after_parse(staged, manifest):
            self.config.write_text("AGP_DATABASE_DRIVER=postgres\nAGP_DATABASE_DSN=other-database\n")
        self.host.version_check = change_source_after_parse
        self.apply()
        self.assertEqual(self.host.path("/etc/agp/agp.env").read_bytes(), original)
        state = json.loads(self.host.path("/var/lib/agp-release/current.json").read_text())
        self.assertEqual((Path(state["backup"]) / "agp.env").read_bytes(), original)

    def test_sqlite_backup_before_upgrade_and_config_preservation(self):
        self.apply()
        database = self.host.path("/var/lib/agp/agp.db")
        with sqlite3.connect(database) as connection:
            connection.execute("CREATE TABLE facts (value TEXT)")
            connection.execute("INSERT INTO facts VALUES ('before upgrade')")
        original_env = self.host.path("/etc/agp/agp.env").read_bytes()
        self.host.events.clear()
        self.apply("v1.1.0", "update")
        state = json.loads(self.host.path("/var/lib/agp-release/current.json").read_text())
        with sqlite3.connect(Path(state["backup"]) / "database.sqlite3") as backup:
            self.assertEqual(backup.execute("SELECT * FROM facts").fetchall(), [("before upgrade",)])
        self.assertEqual(self.host.path("/etc/agp/agp.env").read_bytes(), original_env)
        self.assertEqual(self.host.events[:4], ["preflight", "version", "stop", "backup"])
        self.assertEqual(os.readlink(self.host.path("/opt/agp/current")), "releases/v1.1.0-" + COMMIT)

    def test_sqlite_backup_includes_uncheckpointed_wal(self):
        self.apply()
        database = self.host.path("/var/lib/agp/agp.db")
        with contextlib.closing(sqlite3.connect(database)) as connection:
            connection.execute("PRAGMA journal_mode=WAL")
            connection.execute("PRAGMA wal_autocheckpoint=0")
            connection.execute("CREATE TABLE wal_facts (value TEXT)")
            connection.execute("INSERT INTO wal_facts VALUES ('only in WAL')")
            connection.commit()
            self.apply("v1.1.0", "update")
            state = json.loads(self.host.path("/var/lib/agp-release/current.json").read_text())
            with sqlite3.connect(Path(state["backup"]) / "database.sqlite3") as backup:
                self.assertEqual(backup.execute("SELECT * FROM wal_facts").fetchall(), [("only in WAL",)])

    @unittest.skipIf(os.geteuid() == 0, "permission probe must run without root DAC override")
    def test_sqlite_fixed_fd_transport_does_not_reopen_private_destination(self):
        work = self.host.path("/var/lib/agp")
        work.mkdir(parents=True)
        source = work / "facts.db"
        with sqlite3.connect(source) as database:
            database.execute("CREATE TABLE facts (value TEXT)")
            database.execute("INSERT INTO facts VALUES ('through fixed FD')")
        private = self.directory / "inaccessible-backup"
        private.mkdir(mode=0o700)
        target = private / "database.sqlite3"
        descriptor = os.open(target, os.O_CREAT | os.O_EXCL | os.O_RDWR, 0o600)
        try:
            private.chmod(0)
            result = subprocess.run([sys.executable, "-I", "-c", release.SQLITE_BACKUP_CHILD,
                                     str(source), str(descriptor), str(work)], pass_fds=(descriptor,),
                                    stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=15)
        finally:
            private.chmod(0o700)
            os.close(descriptor)
        self.assertEqual(result.returncode, 0, result.stderr.decode())
        with sqlite3.connect(target) as database:
            self.assertEqual(database.execute("SELECT * FROM facts").fetchall(), [("through fixed FD",)])

    def test_missing_installed_sqlite_database_does_not_reinitialize(self):
        self.apply()
        self.host.path("/var/lib/agp/agp.db").unlink()
        with self.assertRaisesRegex(release.ReleaseError, "database is missing"):
            self.apply("v1.1.0", "update")
        self.assertEqual(os.readlink(self.host.path("/opt/agp/current")), "releases/v1.0.0-" + COMMIT)

    def test_root_owned_config_in_writable_directory_is_rejected(self):
        self.config.parent.chmod(0o777)
        with self.assertRaisesRegex(release.ReleaseError, "unsafe protected-file ancestor"):
            self.apply()

    def test_noop_same_pin_no_backup_restart_or_migration(self):
        self.apply()
        archive = self.directory / "v1.0.0.tar.gz"
        sha = release.digest(archive)
        staged = self.directory / "staged-v1.0.0"
        manifest = json.loads((staged / "release.json").read_text())
        self.host.events.clear()
        with contextlib.redirect_stdout(self.output):
            release.install_release(self.host, staged, manifest, sha, "update")
        self.assertEqual(self.host.events, ["preflight"])

    def test_backup_failure_does_not_swap_and_restarts_previous(self):
        self.apply()
        before = os.readlink(self.host.path("/opt/agp/current"))
        self.host.events.clear()
        self.host.fail_backup = True
        with self.assertRaisesRegex(release.ReleaseError, "backup failure"):
            self.apply("v1.1.0", "update")
        self.assertEqual(os.readlink(self.host.path("/opt/agp/current")), before)
        self.assertTrue(self.host.running)
        self.assertFalse(self.host.path("/var/lib/agp-release/recovery-required.json").exists())
        self.assertNotIn("enable", self.host.events)

    def test_prestart_failure_restores_atomic_release_and_previous_service(self):
        self.apply()
        before = os.readlink(self.host.path("/opt/agp/current"))
        self.host.fail_reload = True
        with self.assertRaisesRegex(release.ReleaseError, "daemon-reload failure"):
            self.apply("v1.1.0", "update")
        self.assertEqual(os.readlink(self.host.path("/opt/agp/current")), before)
        self.assertTrue(self.host.running)
        self.assertFalse(self.host.path("/var/lib/agp-release/recovery-required.json").exists())

    def test_poststart_failure_never_restarts_old_code_and_requires_manual_database_recovery(self):
        self.apply()
        before = os.readlink(self.host.path("/opt/agp/current"))
        self.host.events.clear()
        self.host.fail_ready = True
        with self.assertRaisesRegex(release.ReleaseError, "readiness failure"):
            self.apply("v1.1.0", "update")
        self.assertEqual(os.readlink(self.host.path("/opt/agp/current")), "releases/v1.1.0-" + COMMIT)
        self.assertFalse(self.host.running)
        self.assertEqual(self.host.events.count("start"), 1)
        self.assertEqual(self.host.startup_markers, [True, True])
        marker = self.host.path("/var/lib/agp-release/recovery-required.json")
        self.assertTrue(marker.exists())
        self.assertTrue(json.loads(marker.read_text())["database_may_have_migrated"])
        self.assertTrue(self.host.path("/var/lib/agp-release/recovery-blocked.json").is_file())
        self.assertTrue(self.host.enabled)
        with self.assertRaisesRegex(release.ReleaseError, "startup is blocked"):
            self.host.systemctl("start", "agp.service")
        self.assertFalse(self.host.running)
        self.host.fail_ready = False
        with self.assertRaisesRegex(release.ReleaseError, "manual recovery"):
            self.apply("v1.2.0", "update")
        self.assertFalse(self.host.running)

    def test_start_failure_also_requires_manual_database_recovery(self):
        self.apply()
        self.host.fail_start = True
        with self.assertRaisesRegex(release.ReleaseError, "startup failure"):
            self.apply("v1.1.0", "update")
        self.assertFalse(self.host.running)
        self.assertTrue(self.host.path("/var/lib/agp-release/recovery-required.json").exists())

    def test_guard_persistence_failure_still_stops_new_service_without_schema_downgrade(self):
        self.apply()
        self.host.fail_ready = True
        original = release.atomic_json
        def blocked_write_failure(path, value):
            if path.name == "recovery-blocked.json":
                raise OSError("injected full filesystem")
            return original(path, value)
        with mock.patch.object(release, "atomic_json", side_effect=blocked_write_failure):
            with self.assertRaisesRegex(release.ReleaseError, "readiness failure"):
                self.apply("v1.1.0", "update")
        self.assertFalse(self.host.running)
        self.assertEqual(os.readlink(self.host.path("/opt/agp/current")), "releases/v1.1.0-" + COMMIT)
        self.assertIn("manual isolation required", self.output.getvalue())

    def test_recovery_start_block_is_checked_by_systemd_manager(self):
        unit = (ROOT / "deploy/systemd/agp.service").read_text()
        self.assertIn("ConditionPathExists=!/var/lib/agp-release/recovery-blocked.json", unit)

    def test_no_downgrade_or_tag_replacement(self):
        self.apply("v2.0.0")
        with self.assertRaisesRegex(release.ReleaseError, "downgrade"):
            self.apply("v1.9.0", "update")
        archive, sha, _ = bundle(self.directory, "v2.0.0")
        staged = self.directory / "staged-v2.0.0"
        manifest = json.loads((staged / "release.json").read_text())
        with self.assertRaisesRegex(release.ReleaseError, "different bytes"):
            release.install_release(self.host, staged, manifest, "0" * 64, "update")

    def test_active_ancillary_role_blocks_upgrade_before_stop(self):
        self.apply()
        self.host.events.clear()
        self.host.ancillary_active = True
        with self.assertRaisesRegex(release.ReleaseError, "coordinated upgrade"):
            self.apply("v1.1.0", "update")
        self.assertTrue(self.host.running)
        self.assertNotIn("stop", self.host.events)

    def test_unmanaged_install_and_symlinked_config_rejected(self):
        self.host.path("/usr/local/bin").mkdir(parents=True)
        self.host.path("/usr/local/bin/agp").write_text("unmanaged")
        with self.assertRaisesRegex(release.ReleaseError, "existing binary"):
            self.apply()
        self.assertEqual(self.host.path("/usr/local/bin/agp").read_text(), "unmanaged")
        self.host.path("/usr/local/bin/agp").unlink()
        original = self.config.read_bytes()
        other = self.host.path("/root/other.env")
        self.config.rename(other)
        self.config.symlink_to(other)
        staged = self.directory / "staged-v1.0.0"
        manifest = json.loads((staged / "release.json").read_text())
        with self.assertRaisesRegex(release.ReleaseError, "unsafe ownership"):
            release.install_release(self.host, staged, manifest, "0" * 64, "install", self.config)
        self.assertEqual(other.read_bytes(), original)

    def test_symlink_data_directory_cannot_redirect_root_write(self):
        self.host.account()
        self.host.path("/var/lib").mkdir(parents=True)
        outside = self.directory / "outside"
        outside.mkdir()
        self.host.path("/var/lib/agp").symlink_to(outside)
        with self.assertRaises(OSError):
            self.host.data_directories()
        self.assertFalse((outside / "downloads").exists())

    def test_semver_prereleases(self):
        versions = ("v1.0.0-1", "v1.0.0-alpha", "v1.0.0-rc.2", "v1.0.0-rc.10", "v1.0.0", "v1.1.0")
        self.assertEqual(sorted(reversed(versions), key=release.version_key), list(versions))


if __name__ == "__main__":
    unittest.main(verbosity=2)
