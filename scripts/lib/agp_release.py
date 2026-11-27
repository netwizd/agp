#!/usr/bin/env python3
"""Operator-pinned public GitHub release installer. Embedded into both entrypoints.

This bootstrap deliberately does not implement or replace WAF TUF trust.
The archive SHA256 must be obtained independently of the downloaded archive.
"""

import argparse
import contextlib
import ctypes
import datetime
import fcntl
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import platform
import pwd
import re
import shlex
import shutil
import sqlite3
import stat
import subprocess
import sys
import tarfile
import tempfile
import time
import urllib.error
import urllib.parse
import urllib.request
import uuid


ROLES = ("agp", "agpctl", "agp-security-journal", "agp-edge-auth", "agp-agent",
         "agp-helper", "agp-issuer", "agp-agent-identity", "agp-agent-validate")
UNITS = ("agp.service", "agp-security-journal.service", "agp-edge-auth@.service")
PAYLOAD = {**{"bin/" + name: "0755" for name in ROLES},
           **{"systemd/" + name: "0644" for name in UNITS}}
PLATFORM = "ubuntu24.04-linux-amd64"
MAX_ARCHIVE = 268435456
MAX_FILE = 134217728
MAX_UNPACKED = 805306368
MAX_MANIFEST = 65536
VERSION_RE = re.compile(r"v[0-9]+\.[0-9]+\.[0-9]+(?:-[A-Za-z0-9]+(?:[.-][A-Za-z0-9]+)*)?\Z")
SHA_RE = re.compile(r"[0-9a-f]{64}\Z")
COMMIT_RE = re.compile(r"(?:[0-9a-f]{40}|[0-9a-f]{64})\Z")
RELEASE_HOSTS = frozenset(("github.com", "release-assets.githubusercontent.com",
                           "objects.githubusercontent.com", "github-releases.githubusercontent.com"))
SQLITE_BACKUP_CHILD = r'''
import contextlib, os, sqlite3, sys, tempfile, time, urllib.parse
source, descriptor, work_parent = sys.argv[1], int(sys.argv[2]), sys.argv[3]
started = time.monotonic()
def progress(status, remaining, total):
    if time.monotonic() - started > 120:
        raise RuntimeError("SQLite backup exceeded deadline")
uri = "file:" + urllib.parse.quote(source, safe="/") + "?mode=ro"
with tempfile.TemporaryDirectory(prefix=".release-db-backup-", dir=work_parent) as temporary:
    backup_path = os.path.join(temporary, "snapshot.db")
    with contextlib.closing(sqlite3.connect(uri, uri=True, timeout=15)) as original:
        page_size = original.execute("PRAGMA page_size").fetchone()[0]
        if original.execute("PRAGMA page_count").fetchone()[0] * page_size > 2147483648:
            raise RuntimeError("SQLite backup source exceeds size limit")
        with contextlib.closing(sqlite3.connect(backup_path)) as backup:
            original.backup(backup, pages=512, progress=progress, sleep=0.05)
            if backup.execute("PRAGMA quick_check").fetchall() != [("ok",)]:
                raise RuntimeError("SQLite backup integrity check failed")
    total = 0
    with open(backup_path, "rb") as snapshot:
        while True:
            block = snapshot.read(1048576)
            if not block:
                break
            total += len(block)
            if total > 2147483648 or time.monotonic() - started > 140:
                raise RuntimeError("SQLite backup exceeded size/time limit")
            pending = memoryview(block)
            while pending:
                written = os.write(descriptor, pending)
                if written <= 0:
                    raise RuntimeError("SQLite backup write failed")
                pending = pending[written:]
os.fsync(descriptor)
'''


class ReleaseError(Exception):
    pass


class StrictTarInfo(tarfile.TarInfo):
    def _proc_member(self, archive):
        # Reject extended/PAX/sparse/longname records BEFORE tarfile reads their
        # attacker-declared metadata bodies into memory. Packaging uses USTAR.
        if self.type not in (tarfile.REGTYPE, tarfile.AREGTYPE, tarfile.DIRTYPE):
            fail("unsupported archive metadata or special entry")
        if self.size > MAX_FILE:
            fail("archive entry exceeds per-file size limit")
        return super()._proc_member(archive)


def fail(message):
    raise ReleaseError(message)


def digest(path):
    value = hashlib.sha256()
    with open(path, "rb") as stream:
        for block in iter(lambda: stream.read(1048576), b""):
            value.update(block)
    return value.hexdigest()


def unique_object(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            fail("duplicate JSON key: " + key)
        result[key] = value
    return result


def read_json(data):
    try:
        return json.loads(data, object_pairs_hook=unique_object)
    except (ValueError, UnicodeError) as exc:
        fail("invalid release JSON: " + str(exc))


def exact_keys(obj, expected, description):
    if not isinstance(obj, dict) or set(obj) != set(expected):
        fail("unexpected " + description + " fields")


class ReleaseRedirect(urllib.request.HTTPRedirectHandler):
    max_redirections = 6
    max_repeats = 2

    def redirect_request(self, request, fp, code, msg, headers, newurl):
        validate_download_url(newurl)
        return super().redirect_request(request, fp, code, msg, headers, newurl)


def validate_download_url(url):
    parsed = urllib.parse.urlsplit(url)
    if (parsed.scheme != "https" or parsed.hostname not in RELEASE_HOSTS or
            parsed.username is not None or parsed.password is not None or
            parsed.port not in (None, 443) or parsed.fragment):
        fail("release download redirected outside approved HTTPS GitHub hosts")


def download(version, destination):
    url = ("https://github.com/netwizd/agp/releases/download/" + version +
           "/agp_" + version + "_linux_amd64.tar.gz")
    validate_download_url(url)
    # Ignore proxy environment and netrc credentials in a privileged bootstrap.
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}), ReleaseRedirect())
    started = time.monotonic()
    request = urllib.request.Request(url, headers={"User-Agent": "AGP-release-bootstrap/1"})
    try:
        with opener.open(request, timeout=30) as response, open(destination, "xb") as output:
            length = response.headers.get("Content-Length")
            if length is not None and (not length.isdigit() or int(length) > MAX_ARCHIVE):
                fail("release archive exceeds download limit")
            total = 0
            while True:
                block = response.read(1048576)
                if not block:
                    break
                total += len(block)
                if total > MAX_ARCHIVE or time.monotonic() - started > 300:
                    fail("release download exceeds size or time limit")
                output.write(block)
    except (OSError, urllib.error.URLError) as exc:
        # Signed CDN URL query strings must not leak in diagnostics.
        fail("GitHub release download failed (" + type(exc).__name__ + ")")


def verify_extract(archive, destination, version, expected_sha):
    # Snapshot the local/offline input into a private inode. Hash and extraction
    # read that same inode, even if another account replaces/mutates the input.
    descriptor = os.open(archive, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    with os.fdopen(descriptor, "rb") as source, tempfile.TemporaryFile(dir=destination.parent) as snapshot:
        info = os.fstat(source.fileno())
        if not stat.S_ISREG(info.st_mode) or info.st_size > MAX_ARCHIVE:
            fail("release archive must be a bounded regular file")
        value = hashlib.sha256()
        total = 0
        while True:
            block = source.read(1048576)
            if not block:
                break
            total += len(block)
            if total > MAX_ARCHIVE:
                fail("release archive exceeds size limit")
            snapshot.write(block)
            value.update(block)
        if value.hexdigest() != expected_sha:
            fail("release archive SHA256 mismatch")
        snapshot.seek(0)
        return extract_snapshot(snapshot, destination, version)


def extract_snapshot(snapshot, destination, version):
    destination.mkdir(mode=0o700)
    try:
        with tarfile.open(fileobj=snapshot, mode="r:gz", tarinfo=StrictTarInfo) as package:
            files = {}
            seen = set()
            total = 0
            for index, entry in enumerate(package):
                if index >= len(PAYLOAD) + 3:
                    fail("unexpected archive entry count")
                name = entry.name
                if name in seen:
                    fail("duplicate archive entry: " + name)
                seen.add(name)
                if (name.startswith("/") or "\\" in name or
                        any(part in ("", ".", "..") for part in name.split("/")) or
                        str(PurePosixPath(name)) != name):
                    fail("unsafe archive path")
                if entry.isdir() and name in ("bin", "systemd"):
                    continue
                if not entry.isfile() or name not in {*PAYLOAD, "release.json"}:
                    fail("unexpected archive entry: " + name)
                if entry.mode & 0o7000 or not 1 <= entry.size <= MAX_FILE:
                    fail("unsafe archive mode or empty file: " + name)
                total += entry.size
                if total > MAX_UNPACKED or (name == "release.json" and entry.size > MAX_MANIFEST):
                    fail("unpacked release exceeds size limit")
                files[name] = entry
            if set(files) != {*PAYLOAD, "release.json"}:
                fail("release does not contain the complete role and systemd set")
            raw = package.extractfile(files["release.json"]).read(MAX_MANIFEST + 1)
            manifest = read_json(raw)
            exact_keys(manifest, ("schema", "version", "commit", "platform", "database", "files"), "manifest")
            if (type(manifest["schema"]) is not int or manifest["schema"] != 1 or
                    manifest["version"] != version or manifest["platform"] != PLATFORM or
                    not isinstance(manifest["commit"], str) or not COMMIT_RE.fullmatch(manifest["commit"])):
                fail("release version, commit, schema or platform mismatch")
            if (manifest["database"] != {"startup_migrations": True, "rollback": "manual-database-restore"} or
                    type(manifest["database"].get("startup_migrations")) is not bool):
                fail("unsupported database migration contract")
            if not isinstance(manifest["files"], list) or len(manifest["files"]) != len(PAYLOAD):
                fail("invalid release file manifest")
            described = set()
            for item in manifest["files"]:
                exact_keys(item, ("path", "sha256", "size", "mode"), "file manifest")
                name = item["path"]
                if not isinstance(name, str) or name not in PAYLOAD or name in described:
                    fail("invalid or duplicate file manifest path")
                described.add(name)
                if (not isinstance(item["sha256"], str) or not SHA_RE.fullmatch(item["sha256"]) or
                        type(item["size"]) is not int or item["size"] != files[name].size or
                        item["mode"] != PAYLOAD[name] or files[name].mode & 0o777 != int(item["mode"], 8)):
                    fail("file manifest size, mode or digest is invalid: " + name)
                target = destination / name
                target.parent.mkdir(mode=0o700, exist_ok=True)
                value = hashlib.sha256()
                with package.extractfile(files[name]) as source, open(target, "xb") as output:
                    for block in iter(lambda: source.read(1048576), b""):
                        output.write(block)
                        value.update(block)
                if value.hexdigest() != item["sha256"]:
                    fail("release payload checksum mismatch: " + name)
                if name.startswith("bin/"):
                    with open(target, "rb") as binary:
                        header = binary.read(20)
                    if (len(header) < 20 or header[:6] != b"\x7fELF\x02\x01" or header[18:20] != b"\x3e\x00"):
                        fail("release binary is not Linux x86-64 ELF: " + name)
                target.chmod(int(item["mode"], 8))
            (destination / "release.json").write_bytes(raw)
            (destination / "release.json").chmod(0o644)
            return manifest
    except (tarfile.TarError, EOFError) as exc:
        fail("invalid release archive (" + type(exc).__name__ + ")")


def parse_environment(path):
    return parse_environment_bytes(path.read_bytes())


def parse_environment_bytes(raw):
    values = {}
    try:
        data = raw.decode("utf-8")
    except (OSError, UnicodeError):
        fail("cannot read the protected AGP environment file")
    if len(data) > 1048576 or "\x00" in data:
        fail("invalid AGP environment file")
    for line in data.splitlines():
        line = line.strip()
        if not line or line.startswith(("#", ";")):
            continue
        if "=" not in line:
            fail("environment file must contain one NAME=value assignment per line")
        key, value = line.split("=", 1)
        if not re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*", key) or key in values:
            fail("invalid or duplicate environment variable")
        # Systemd performs no shell expansion: dollar signs and backticks are
        # literal data. Reject escapes/continuations rather than reinterpreting
        # their meaning differently from EnvironmentFile.
        if "\\" in value:
            fail("environment escapes/continuations are unsupported")
        if value.startswith(("'", '"')):
            try:
                parts = shlex.split(value, posix=True)
            except ValueError:
                fail("invalid quoted environment value")
            if len(parts) != 1:
                fail("invalid quoted environment value")
            value = parts[0]
        values[key] = value
    if values.get("AGP_DATABASE_DRIVER") not in ("postgres", "sqlite"):
        fail("explicit AGP_DATABASE_DRIVER=postgres or sqlite is required")
    if values["AGP_DATABASE_DRIVER"] == "postgres" and not values.get("AGP_DATABASE_DSN"):
        fail("AGP_DATABASE_DSN is required")
    if values["AGP_DATABASE_DRIVER"] == "sqlite":
        value = values.get("AGP_DATABASE_PATH", "")
        if not value.startswith("/var/lib/agp/") or ".." in Path(value).parts:
            fail("SQLite database must have an absolute path beneath /var/lib/agp")
    address = values.get("AGP_HTTP_ADDR", "127.0.0.1:8080")
    if not re.fullmatch(r"127\.0\.0\.1:[0-9]{1,5}", address) or not 1 <= int(address.rsplit(":", 1)[1]) <= 65535:
        fail("bootstrap requires a loopback AGP_HTTP_ADDR=127.0.0.1:<port>")
    return values


def postgres_environment(dsn):
    """Use libpq's own URI/conninfo parser; secrets never appear in argv.

    PGDATABASE is a database name, not a reliable conninfo expansion point.
    PQconninfoParse returns only explicitly supplied values and their libpq
    environment names. Defaults and the caller's PG* environment are excluded.
    """
    class Option(ctypes.Structure):
        _fields_ = [("keyword", ctypes.c_char_p), ("envvar", ctypes.c_char_p),
                    ("compiled", ctypes.c_char_p), ("val", ctypes.c_char_p),
                    ("label", ctypes.c_char_p), ("dispchar", ctypes.c_char_p),
                    ("dispsize", ctypes.c_int)]
    if not isinstance(dsn, str) or not dsn or "\x00" in dsn:
        fail("invalid PostgreSQL connection configuration")
    try:
        library = ctypes.CDLL("libpq.so.5")
    except OSError:
        fail("PostgreSQL client libpq.so.5 is required")
    library.PQconninfoParse.argtypes = (ctypes.c_char_p, ctypes.POINTER(ctypes.c_void_p))
    library.PQconninfoParse.restype = ctypes.POINTER(Option)
    library.PQconninfoFree.argtypes = (ctypes.POINTER(Option),)
    library.PQconninfoFree.restype = None
    library.PQfreemem.argtypes = (ctypes.c_void_p,)
    library.PQfreemem.restype = None
    error = ctypes.c_void_p()
    options = library.PQconninfoParse(dsn.encode("utf-8"), ctypes.byref(error))
    if not options:
        if error.value:
            library.PQfreemem(error)
        # libpq's detailed error can contain the original credential/DSN.
        fail("invalid PostgreSQL connection configuration")
    environment = {"PATH": "/usr/bin:/bin", "LANG": "C", "PGCONNECT_TIMEOUT": "15",
                   "PGAPPNAME": "agp-release-backup"}
    try:
        index = 0
        while options[index].keyword is not None:
            option = options[index]
            if option.val is not None:
                if option.envvar is None or not re.fullmatch(rb"PG[A-Z0-9_]+", option.envvar):
                    fail("PostgreSQL connection option has no safe environment mapping")
                environment[option.envvar.decode("ascii")] = option.val.decode("utf-8", "surrogateescape")
            index += 1
    finally:
        library.PQconninfoFree(options)
    if error.value:
        library.PQfreemem(error)
    return environment


class Host:
    """All privileged effects in one adapter; tests substitute a temporary host."""

    def __init__(self, root=Path("/")):
        self.root = Path(root)
        self.uid = 0
        self.gid = 0
        self.agp_uid = None
        self.agp_gid = None

    def path(self, value):
        return self.root / value.lstrip("/")

    def protected(self, path, private=False):
        path = Path(path).absolute()
        try:
            relative = path.relative_to(self.root)
        except ValueError:
            fail("protected file is outside the trusted filesystem root")
        current = self.root
        for component in relative.parts[:-1]:
            current = current / component
            info = current.lstat()
            if not stat.S_ISDIR(info.st_mode) or info.st_uid != self.uid or info.st_mode & 0o022:
                fail("unsafe protected-file ancestor: " + str(current))
        try:
            info = path.lstat()
        except OSError:
            fail("missing protected file: " + str(path))
        if (not stat.S_ISREG(info.st_mode) or info.st_uid != self.uid or
                info.st_mode & (0o037 if private else 0o022)):
            fail("unsafe ownership or permissions: " + str(path))

    def protected_snapshot(self, path):
        self.protected(path, private=True)
        descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
        with os.fdopen(descriptor, "rb") as source:
            info = os.fstat(source.fileno())
            if not stat.S_ISREG(info.st_mode) or info.st_uid != self.uid or info.st_mode & 0o037:
                fail("unsafe protected environment file")
            raw = source.read(1048577)
            if len(raw) > 1048576:
                fail("environment file exceeds size limit")
            return raw

    def directory(self, path, mode=0o755, owner=None):
        # Reject writable or linked ancestors before privileged filesystem work.
        relative = path.relative_to(self.root)
        current = self.root
        for part in relative.parts:
            current = current / part
            if current.exists() or current.is_symlink():
                info = current.lstat()
                if (not stat.S_ISDIR(info.st_mode) or info.st_mode & 0o022 or
                        info.st_uid not in (self.uid, owner if current == path else self.uid)):
                    fail("unsafe directory ancestor: " + str(current))
            else:
                current.mkdir(mode=mode if current == path else 0o755)
        if owner is not None:
            os.chown(path, owner, self.agp_gid)
        path.chmod(mode)

    def command(self, args, env=None, timeout=60, capture=False):
        try:
            result = subprocess.run(args, env=env, check=True, timeout=timeout,
                                    stdin=subprocess.DEVNULL, stdout=subprocess.PIPE if capture else subprocess.DEVNULL,
                                    stderr=subprocess.PIPE, text=True)
            return result.stdout if capture else None
        except (OSError, subprocess.SubprocessError):
            # Never log DSNs, application output or subprocess credentials.
            fail("command failed: " + Path(args[0]).name + " (consult service logs privately)")

    def systemctl(self, *args):
        return self.command(["/usr/bin/systemctl", *args])

    def active(self):
        return subprocess.run(["/usr/bin/systemctl", "is-active", "--quiet", "agp.service"],
                              stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=15).returncode == 0

    def ancillary_check(self):
        output = self.command(["/usr/bin/systemctl", "list-units", "--type=service", "--state=active",
                               "--no-legend", "--plain", "--no-pager"], capture=True)
        for line in output.splitlines():
            unit = line.split()[0] if line.split() else ""
            if unit.startswith("agp-") and unit.endswith(".service"):
                fail("active ancillary role requires a coordinated upgrade: " + unit)
        for process in self.path("/proc").glob("[0-9]*/exe"):
            try:
                executable = os.readlink(process)
            except (FileNotFoundError, ProcessLookupError):
                continue
            if (executable.startswith("/opt/agp/releases/") and
                    Path(executable).name in set(ROLES) - {"agp", "agpctl"}):
                fail("running ancillary AGP binary requires a coordinated upgrade")

    def preflight(self):
        if os.geteuid() != 0:
            fail("run this installer with sudo/root; --verify-only does not require root")
        release = self.path("/etc/os-release").read_text()
        facts = dict(line.split("=", 1) for line in release.splitlines() if "=" in line)
        if (facts.get("ID", "").strip('"') != "ubuntu" or
                facts.get("VERSION_ID", "").strip('"') != "24.04" or
                platform.system() != "Linux" or platform.machine() not in ("x86_64", "amd64")):
            fail("release installation is qualified only for Ubuntu 24.04 amd64")
        for name in ("systemctl", "useradd", "pg_dump", "pg_restore"):
            if shutil.which(name) is None:
                fail("required preinstalled command: " + name)
        if not self.path("/run/systemd/system").is_dir():
            fail("a running systemd host is required")

    def account(self):
        try:
            account = pwd.getpwnam("agp")
        except KeyError:
            self.command(["/usr/sbin/useradd", "--system", "--home", "/var/lib/agp",
                          "--shell", "/usr/sbin/nologin", "agp"])
            account = pwd.getpwnam("agp")
        if account.pw_uid == 0 or account.pw_gid == 0 or account.pw_shell not in ("/usr/sbin/nologin", "/bin/false"):
            fail("existing agp account must be a non-login unprivileged service account")
        self.agp_uid, self.agp_gid = account.pw_uid, account.pw_gid

    def data_directories(self):
        # Open service-writable directories without following links, and use
        # dirfds for nested paths so the service cannot redirect a root write.
        for parent, name in (("/var/lib", "agp"), ("/var/log", "agp")):
            parent_path = self.path(parent)
            self.directory(parent_path)
            with contextlib.ExitStack() as stack:
                parent_fd = os.open(parent_path, os.O_DIRECTORY | os.O_NOFOLLOW | os.O_RDONLY)
                stack.callback(os.close, parent_fd)
                try:
                    os.mkdir(name, 0o750, dir_fd=parent_fd)
                except FileExistsError:
                    pass
                data_fd = os.open(name, os.O_DIRECTORY | os.O_NOFOLLOW | os.O_RDONLY, dir_fd=parent_fd)
                stack.callback(os.close, data_fd)
                info = os.fstat(data_fd)
                if info.st_uid not in (self.uid, self.agp_uid) or info.st_mode & 0o022:
                    fail("unsafe AGP data directory")
                os.fchown(data_fd, self.agp_uid, self.agp_gid)
                os.fchmod(data_fd, 0o750)
                if parent == "/var/lib":
                    try:
                        os.mkdir("downloads", 0o750, dir_fd=data_fd)
                    except FileExistsError:
                        pass
                    downloads_fd = os.open("downloads", os.O_DIRECTORY | os.O_NOFOLLOW | os.O_RDONLY, dir_fd=data_fd)
                    stack.callback(os.close, downloads_fd)
                    info = os.fstat(downloads_fd)
                    if info.st_uid not in (self.uid, self.agp_uid) or info.st_mode & 0o022:
                        fail("unsafe AGP downloads directory")
                    os.fchown(downloads_fd, self.agp_uid, self.agp_gid)
                    os.fchmod(downloads_fd, 0o750)

    def version_check(self, staged, manifest):
        output = self.command([str(staged / "bin/agp"), "--version"], capture=True, timeout=15)
        if not output.startswith("agp " + manifest["version"] + " commit=" + manifest["commit"] + " "):
            fail("verified agp binary identity differs from release manifest")

    def backup_database(self, config, destination, allow_absent=False):
        if config["AGP_DATABASE_DRIVER"] == "postgres":
            # libpq receives credentials through its environment, never argv.
            environment = postgres_environment(config["AGP_DATABASE_DSN"])
            target = destination / "database.dump"
            self.command(["/usr/bin/pg_dump", "--no-password", "--format=custom", "--file=" + str(target)],
                         env=environment, timeout=600)
            if not target.is_file() or target.stat().st_size == 0:
                fail("PostgreSQL backup is empty or missing")
            target.chmod(0o600)
            self.command(["/usr/bin/pg_restore", "--list", str(target)], timeout=60)
        else:
            source = self.path(config["AGP_DATABASE_PATH"])
            if not source.exists():
                if source.is_symlink():
                    fail("SQLite database path is a dangling symlink")
                if not allow_absent:
                    fail("existing SQLite database is missing; update stopped")
                (destination / "database-absent.json").write_text('{"database_was_absent":true}\n')
                return
            if source.is_symlink() or not source.is_file():
                fail("SQLite database must be a regular file")
            current = self.root
            for component in source.relative_to(self.root).parts[:-1]:
                current = current / component
                if not stat.S_ISDIR(current.lstat().st_mode):
                    fail("SQLite database ancestor must not be a symlink")
            target = destination / "database.sqlite3"
            descriptor = os.open(target, os.O_CREAT | os.O_EXCL | os.O_RDWR | os.O_NOFOLLOW, 0o600)
            try:
                # The DB directory belongs to the service. Read it as that
                # identity, so a file/link race can never make root read a
                # database unavailable to the service. The output inode is
                # already fixed in the private backup directory.
                identity = ({"user": self.agp_uid, "group": self.agp_gid, "extra_groups": ()}
                            if os.geteuid() == 0 else {})
                try:
                    subprocess.run([sys.executable, "-I", "-c", SQLITE_BACKUP_CHILD, str(source), str(descriptor),
                                    str(self.path("/var/lib/agp"))],
                                   pass_fds=(descriptor,), env={"PATH": "/usr/bin:/bin", "LANG": "C"},
                                   stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                                   check=True, timeout=150, **identity)
                except (OSError, subprocess.SubprocessError):
                    fail("unprivileged SQLite backup failed")
            finally:
                os.fchmod(descriptor, 0o600)
                os.fsync(descriptor)
                os.close(descriptor)

    def ready(self, config):
        class NoRedirect(urllib.request.HTTPRedirectHandler):
            def redirect_request(self, *args, **kwargs):
                return None
        opener = urllib.request.build_opener(urllib.request.ProxyHandler({}), NoRedirect())
        # Readiness must be served directly by the local process, without redirects.
        base = "http://" + config.get("AGP_HTTP_ADDR", "127.0.0.1:8080")
        for _ in range(45):
            if not self.active():
                fail("AGP stopped during startup/readiness")
            try:
                for endpoint in ("/healthz", "/readyz"):
                    with opener.open(base + endpoint, timeout=2) as response:
                        if response.status != 200 or response.url != base + endpoint:
                            raise OSError("unexpected health response")
                        response.read(65537)
                return
            except (OSError, urllib.error.URLError):
                time.sleep(1)
        fail("AGP did not pass local health and readiness checks")


def atomic_json(path, value):
    temporary = path.with_name("." + path.name + "." + uuid.uuid4().hex)
    try:
        with open(temporary, "x", encoding="utf-8") as stream:
            os.chmod(temporary, 0o600)
            json.dump(value, stream, sort_keys=True, indent=2)
            stream.write("\n")
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, path)
        sync_directory(path.parent)
    finally:
        temporary.unlink(missing_ok=True)


def atomic_link(path, target):
    temporary = path.with_name("." + path.name + "." + uuid.uuid4().hex)
    try:
        temporary.symlink_to(target)
        os.replace(temporary, path)
        sync_directory(path.parent)
    finally:
        temporary.unlink(missing_ok=True)


def sync_directory(path):
    descriptor = os.open(path, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def sync_tree(path):
    directories = [path]
    for item in path.rglob("*"):
        if item.is_file():
            with open(item, "rb") as stream:
                os.fsync(stream.fileno())
        elif item.is_dir():
            directories.append(item)
    for directory in reversed(directories):
        sync_directory(directory)


def install_release(host, staged, manifest, sha, mode, config_path=None):
    host.preflight()
    root = host.path("/opt/agp")
    releases = root / "releases"
    state_dir = host.path("/var/lib/agp-release")
    for directory, permissions in ((root, 0o755), (releases, 0o755), (state_dir, 0o700)):
        host.directory(directory, permissions)
    descriptor = os.open(state_dir / "install.lock", os.O_CREAT | os.O_RDWR | os.O_NOFOLLOW, 0o600)
    with os.fdopen(descriptor, "a+") as lock:
        lock_info = os.fstat(lock.fileno())
        if not stat.S_ISREG(lock_info.st_mode) or lock_info.st_uid != host.uid or lock_info.st_mode & 0o077:
            fail("unsafe installation lock")
        try:
            fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError:
            fail("another AGP installation/update holds the release lock")
        return locked_install(host, staged, manifest, sha, mode, config_path, root, state_dir)


def locked_install(host, staged, manifest, sha, mode, config_path, root, state_dir):
    current = root / "current"
    state_path = state_dir / "current.json"
    recovery = state_dir / "recovery-required.json"
    startup_block = state_dir / "recovery-blocked.json"
    env_path = host.path("/etc/agp/agp.env")
    if recovery.exists() or startup_block.exists():
        fail("previous startup may have migrated the database; manual recovery is required: " + str(recovery))
    target_name = manifest["version"] + "-" + manifest["commit"]
    target = root / "releases" / target_name
    old_target = None
    old_state = None
    if mode == "update":
        host.protected(state_path, private=True)
        old_state = read_json(state_path.read_bytes())
        if not current.is_symlink():
            fail("unmanaged installation: /opt/agp/current is not a managed release link")
        old_target = os.readlink(current)
        expected = "releases/" + old_state["version"] + "-" + old_state["commit"]
        if old_target != expected or not (root / old_target).is_dir():
            fail("installed release state and current link differ")
        if old_state["version"] == manifest["version"]:
            if old_state["commit"] == manifest["commit"] and old_state["sha256"] == sha:
                print("AGP is already at the pinned release; no restart or migration performed.")
                return
            fail("refusing to replace an existing release tag with different bytes")
        if version_key(manifest["version"]) <= version_key(old_state["version"]):
            fail("updater refuses version downgrade or same-version replacement")
        host.protected(env_path, private=True)
        if config_path is not None:
            fail("update preserves /etc/agp/agp.env; --config is install-only")
        config_path = env_path
    else:
        if current.exists() or current.is_symlink() or state_path.exists() or env_path.exists() or env_path.is_symlink():
            fail("existing installation/configuration detected; use the managed updater or explicit migration")
        if config_path is None:
            fail("install requires --config pointing to a prepared, protected environment file")
        host.protected(config_path, private=True)
    config_snapshot = host.protected_snapshot(config_path)
    config = parse_environment_bytes(config_snapshot)
    host.ancillary_check()
    if target.exists() or target.is_symlink():
        fail("release directory already exists; refusing to overwrite an artifact")
    links = {host.path("/usr/local/bin/" + name): "/opt/agp/current/bin/" + name for name in ROLES}
    links.update({host.path("/etc/systemd/system/" + name): "/opt/agp/current/systemd/" + name for name in UNITS})
    for link, expected in links.items():
        if mode == "update":
            if not link.is_symlink() or os.readlink(link) != expected:
                fail("unmanaged binary or systemd unit: " + str(link))
        elif link.exists() or link.is_symlink():
            fail("refusing to replace existing binary or systemd unit: " + str(link))
    host.version_check(staged, manifest)
    host.account()
    host.data_directories()
    host.directory(env_path.parent, 0o750)
    os.chown(env_path.parent, host.uid, host.agp_gid)
    for parent in {link.parent for link in links}:
        host.directory(parent)
    backup_root = host.path("/var/backups/agp/updates")
    host.directory(backup_root, 0o700)
    backup = backup_root / (datetime.datetime.now(datetime.timezone.utc).strftime("%Y%m%dT%H%M%SZ-") + uuid.uuid4().hex[:12])
    backup.mkdir(mode=0o700)
    (backup / "agp.env").write_bytes(config_snapshot)
    (backup / "agp.env").chmod(0o600)
    if old_state is not None:
        atomic_json(backup / "previous-release.json", old_state)
        shutil.copytree(root / old_target, backup / "previous-release", symlinks=False)
    was_active = host.active()
    startup_attempted = False
    swapped = False
    created_links = []
    installed_config = False
    try:
        host.systemctl("stop", "agp.service") if mode == "update" else None
        if host.active():
            fail("AGP must be stopped before database backup")
        host.backup_database(config, backup, allow_absent=mode == "install")
        atomic_json(backup / "backup.json", {
            "old_release": old_state, "new_version": manifest["version"], "new_commit": manifest["commit"],
            "driver": config["AGP_DATABASE_DRIVER"], "automatic_database_restore": False,
            "files": {path.name: digest(path) for path in backup.iterdir() if path.is_file()},
        })
        sync_tree(backup)
        sync_directory(backup.parent)
        # Staging is on the target filesystem; the version directory is never overwritten.
        pending = root / "releases" / (".pending-" + uuid.uuid4().hex)
        shutil.copytree(staged, pending)
        for item in pending.rglob("*"):
            if item.is_dir():
                item.chmod(0o755)
        pending.chmod(0o755)
        sync_tree(pending)
        os.rename(pending, target)
        sync_directory(target.parent)
        if mode == "install":
            with open(env_path, "xb") as output:
                output.write(config_snapshot)
                output.flush()
                os.fsync(output.fileno())
            installed_config = True
            os.chown(env_path, host.uid, host.agp_gid)
            env_path.chmod(0o640)
            sync_directory(env_path.parent)
            for link, expected in links.items():
                link.symlink_to(expected)
                created_links.append(link)
        atomic_link(current, "releases/" + target_name)
        swapped = True
        host.systemctl("daemon-reload")
        # Durable BEFORE startup, including failed start, SIGKILL and power loss.
        # An interrupted transaction blocks the next update pending manual DB
        # recovery; it never authorizes an automatic database downgrade.
        atomic_json(recovery, {"database_may_have_migrated": True, "backup": str(backup),
                               "previous_release": old_state, "attempted_version": manifest["version"],
                               "service_must_remain_stopped": True, "cleanup_errors": []})
        # Set this BEFORE invoking start: even a failing start can run migrations.
        startup_attempted = True
        host.systemctl("start", "agp.service")
        host.ready(config)
        atomic_json(state_path, {"schema": 1, "version": manifest["version"], "commit": manifest["commit"],
                                 "sha256": sha, "platform": PLATFORM, "backup": str(backup)})
        host.systemctl("enable", "agp.service")
        recovery.unlink()
        sync_directory(state_dir)
        print("AGP " + manifest["version"] + " installed and passed local health/readiness.")
        print("Database/configuration backup: " + str(backup))
        print("Only agp.service is enabled. Configure other roles and qualified WAF/TLS separately.")
    except BaseException:
        cleanup_errors = []
        if startup_attempted:
            try:
                atomic_json(startup_block, {"database_may_have_migrated": True, "backup": str(backup),
                                            "attempted_version": manifest["version"]})
            except (OSError, ReleaseError):
                cleanup_errors.append("could not persist the systemd startup block; manual isolation required")
        try:
            host.systemctl("stop", "agp.service")
        except ReleaseError:
            cleanup_errors.append("stop failed; inspect agp.service before recovery")
        if swapped and not startup_attempted:
            if old_target is not None:
                atomic_link(current, old_target)
            else:
                current.unlink(missing_ok=True)
        if not startup_attempted:
            for link in created_links:
                link.unlink(missing_ok=True)
        if installed_config and not startup_attempted:
            env_path.unlink(missing_ok=True)
        try:
            host.systemctl("daemon-reload")
        except ReleaseError:
            cleanup_errors.append("systemd daemon-reload failed")
        if old_state is not None and not startup_attempted:
            atomic_json(state_path, old_state)
        elif state_path.exists() and not startup_attempted:
            state_path.unlink()
        if startup_attempted:
            atomic_json(recovery, {"database_may_have_migrated": True, "backup": str(backup),
                                   "previous_release": old_state, "attempted_version": manifest["version"],
                                   "service_must_remain_stopped": True, "cleanup_errors": cleanup_errors})
            print("STARTUP FAILED: database may have migrated. No automatic database rollback; verify service is stopped.", file=sys.stderr)
            print("Recovery backup: " + str(backup), file=sys.stderr)
            print("Manual recovery required: " + str(recovery), file=sys.stderr)
            print("New release remains selected; old code is never restarted against a possibly migrated database.", file=sys.stderr)
        elif was_active:
            recovery.unlink(missing_ok=True)
            sync_directory(state_dir)
            try:
                host.systemctl("start", "agp.service")
                host.ready(config)
            except ReleaseError:
                cleanup_errors.append("previous service did not recover")
        for message in cleanup_errors:
            print("Recovery attention: " + message, file=sys.stderr)
        raise


def version_key(value):
    if not isinstance(value, str) or not VERSION_RE.fullmatch(value):
        fail("invalid installed release version")
    main, separator, pre = value[1:].partition("-")
    # SemVer numeric prerelease identifiers sort below alphabetic identifiers.
    prerelease = tuple((0, int(item)) if item.isdigit() else (1, item) for item in pre.split("."))
    return tuple(int(item) for item in main.split(".")), not bool(separator), prerelease


def bootstrap(mode):
    source = Path(__file__).read_text()
    return ("#!/usr/bin/env bash\nset -Eeuo pipefail\n"
            "# Generated from scripts/lib/agp_release.py; keep both standalone entrypoints in sync.\n"
            "# Obtain the release SHA256 through an independent trusted channel before running as root.\n"
            "command -v python3 >/dev/null 2>&1 || { echo 'Python 3 is required' >&2; exit 1; }\n"
            "export PATH=/usr/sbin:/usr/bin:/sbin:/bin\n"
            "unset PYTHONPATH PYTHONHOME\n"
            "exec python3 -I - " + mode + " \"$@\" <<'AGP_RELEASE_BOOTSTRAP_PY'\n" + source +
            "\nAGP_RELEASE_BOOTSTRAP_PY\n")


def main(argv=None):
    parser = argparse.ArgumentParser(description="Install/update an operator-pinned public netwizd/agp GitHub release")
    parser.add_argument("mode", choices=("install", "update"))
    parser.add_argument("--version", required=True, help="explicit immutable release tag, e.g. v1.0.0")
    parser.add_argument("--sha256", required=True, help="archive SHA256 obtained through an independent trusted channel")
    parser.add_argument("--archive", type=Path, help="verify/install an already downloaded release archive")
    parser.add_argument("--config", type=Path, help="install only: prepared private root-owned AGP environment file")
    parser.add_argument("--verify-only", action="store_true", help="download and verify without system changes; no root required")
    args = parser.parse_args(argv)
    if not VERSION_RE.fullmatch(args.version) or not SHA_RE.fullmatch(args.sha256):
        fail("invalid explicit version or SHA256")
    if args.mode == "update" and args.config is not None:
        fail("update preserves existing configuration; --config is install-only")
    os.umask(0o077)
    with tempfile.TemporaryDirectory(prefix="agp-release-") as work:
        directory = Path(work)
        archive = args.archive
        if archive is None:
            archive = directory / "release.tar.gz"
            download(args.version, archive)
        staged = directory / "staged"
        manifest = verify_extract(archive, staged, args.version, args.sha256)
        print("Verified operator-pinned release: " + manifest["version"] + " commit=" + manifest["commit"])
        if args.verify_only:
            return
        install_release(Host(), staged, manifest, args.sha256, args.mode, args.config)


if __name__ == "__main__":
    try:
        if len(sys.argv) == 3 and sys.argv[1] == "--render-bootstrap":
            if sys.argv[2] not in ("install", "update"):
                fail("unknown bootstrap mode")
            sys.stdout.write(bootstrap(sys.argv[2]))
        else:
            main()
    except (ReleaseError, OSError, ValueError, KeyError, TypeError) as error:
        print("AGP release operation failed: " + str(error), file=sys.stderr)
        sys.exit(1)
