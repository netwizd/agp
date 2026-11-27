#!/usr/bin/env python3
"""Package operator-pinned application releases; does not sign or publish them.

The native WAF repository, TUF state and installation secrets are deliberately
outside this archive. build-release.sh supplies the independently checked Git
identity. A supplied --commit alone is metadata, not proof of provenance.
"""
import argparse
import gzip
import hashlib
import io
import json
import os
from pathlib import Path
import re
import struct
import tarfile
import tempfile

ROLES = (
    "agp", "agpctl", "agp-security-journal", "agp-edge-auth", "agp-agent",
    "agp-helper", "agp-issuer", "agp-agent-identity", "agp-agent-validate",
)
UNITS = ("agp.service", "agp-security-journal.service", "agp-edge-auth@.service")
VERSION_RE = re.compile(r"v[0-9]+\.[0-9]+\.[0-9]+(?:-[0-9A-Za-z]+(?:[.-][0-9A-Za-z]+)*)?")
MAX_FILE = 128 << 20
MAX_TOTAL = 768 << 20
MAX_ARCHIVE = 256 << 20


def digest(raw):
    return hashlib.sha256(raw).hexdigest()


def canonical(value):
    return (json.dumps(value, sort_keys=True, separators=(",", ":")) + "\n").encode()


def read_regular(path, limit=MAX_FILE):
    """Do not package symlinks, devices or unexpectedly large files."""
    with open(os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK), "rb") as stream:
        st = os.fstat(stream.fileno())
        import stat
        if not stat.S_ISREG(st.st_mode) or not 0 < st.st_size <= limit:
            raise ValueError(f"not a bounded regular file: {path}")
        raw = stream.read(limit + 1)
        if len(raw) != st.st_size:
            raise ValueError(f"file changed while reading: {path}")
        return raw


def static_amd64_elf(raw, name):
    """A release cannot silently depend on the builder's libc/ELF loader."""
    if len(raw) < 64 or raw[:7] != b"\x7fELF\x02\x01\x01":
        raise ValueError(f"not Linux ELF64 little endian: {name}")
    kind, machine, elf_version = struct.unpack_from("<HHI", raw, 16)
    phoff = struct.unpack_from("<Q", raw, 32)[0]
    ehsize, phsize, phcount = struct.unpack_from("<HHH", raw, 52)
    if kind not in (2, 3) or machine != 62 or elf_version != 1 or ehsize != 64:
        raise ValueError(f"not an amd64 executable: {name}")
    if phcount < 1 or phsize != 56 or phoff < 64 or phoff + phcount * phsize > len(raw):
        raise ValueError(f"invalid ELF program headers: {name}")
    for index in range(phcount):
        ptype = struct.unpack_from("<I", raw, phoff + index * phsize)[0]
        if ptype in (2, 3):  # PT_DYNAMIC, PT_INTERP
            raise ValueError(f"undeclared dynamic runtime dependency: {name}")


def inventory(source, manifest, epoch):
    entries = []
    for backend in ("sqlite", "postgres"):
        directory = source / "internal" / "storage" / backend / "migrations"
        for path in sorted(directory.glob("*.sql")):
            raw = read_regular(path, 4 << 20)
            entries.append({"path": path.relative_to(source).as_posix(),
                            "sha256": digest(raw), "size": len(raw)})
    notices = []
    for app in ("auth", "config", "directory"):
        path = source / "internal" / "frontend" / "static" / app / "3rdpartylicenses.txt"
        if path.exists():
            raw = read_regular(path, 4 << 20)
            notices.append({"path": path.relative_to(source).as_posix(),
                            "sha256": digest(raw), "text": raw.decode("utf-8")})
    return {"schema": 1, "purpose": "application-build-inventory",
            "version": manifest["version"], "commit": manifest["commit"],
            "platform": manifest["platform"], "source_date_epoch": epoch,
            "release_manifest_sha256": digest(canonical(manifest)),
            "go_mod": read_regular(source / "go.mod", 4 << 20).decode(),
            "go_sum_sha256": digest(read_regular(source / "go.sum", 4 << 20)),
            "migrations": entries, "frontend_notices": notices,
            "qualification": "operator-pinned bootstrap; not a TUF release or complete license audit"}


def publish_file(path, raw):
    # No replacement of an already packaged version. Never leave a partial file.
    fd, staging = tempfile.mkstemp(prefix=".agp-package-", dir=path.parent)
    try:
        with os.fdopen(fd, "wb") as stream:
            stream.write(raw)
            stream.flush()
            os.fsync(stream.fileno())
        os.chmod(staging, 0o644)
        os.link(staging, path)
    finally:
        os.unlink(staging)


def package(source, binaries, output, version, commit, epoch):
    if not VERSION_RE.fullmatch(version) or not re.fullmatch(r"[0-9a-f]{40}|[0-9a-f]{64}", commit):
        raise ValueError("explicit release version and full lowercase Git commit are required")
    if not 0 <= epoch <= 0xFFFFFFFF:
        raise ValueError("source epoch outside the reproducible gzip range")
    data = {}
    modes = {}
    for role in ROLES:
        raw = read_regular(binaries / role)
        static_amd64_elf(raw, role)
        data[f"bin/{role}"] = raw
        modes[f"bin/{role}"] = "0755"
    for unit in UNITS:
        data[f"systemd/{unit}"] = read_regular(source / "deploy" / "systemd" / unit, 64 << 10)
        modes[f"systemd/{unit}"] = "0644"
    if sum(map(len, data.values())) > MAX_TOTAL:
        raise ValueError("application archive exceeds unpacked limit")
    manifest = {"schema": 1, "version": version, "commit": commit,
                "platform": "ubuntu24.04-linux-amd64",
                "database": {"startup_migrations": True, "rollback": "manual-database-restore"},
                "files": [{"path": name, "sha256": digest(raw), "size": len(raw), "mode": modes[name]}
                          for name, raw in sorted(data.items())]}
    data["release.json"] = canonical(manifest)
    modes["release.json"] = "0644"
    archive = io.BytesIO()
    with gzip.GzipFile(fileobj=archive, mode="wb", filename="", mtime=epoch) as gz:
        with tarfile.open(fileobj=gz, mode="w", format=tarfile.USTAR_FORMAT) as tar:
            for name, raw in sorted(data.items()):
                info = tarfile.TarInfo(name)
                info.size, info.mode, info.mtime = len(raw), int(modes[name], 8), epoch
                info.uid = info.gid = 0
                info.uname = info.gname = "root"
                tar.addfile(info, io.BytesIO(raw))
    raw = archive.getvalue()
    if len(raw) > MAX_ARCHIVE:
        raise ValueError("application archive exceeds download limit")
    output.mkdir(parents=True, exist_ok=True)
    name = f"agp_{version}_linux_amd64.tar.gz"
    sidecar = f"agp_{version}_inventory.json"
    inv = canonical(inventory(source, manifest, epoch))
    # Standalone entrypoints are release assets as well. Their hashes must be
    # authenticated before sudo; downloading SHA256SUMS beside them is not trust.
    entrypoints = {script: read_regular(source / script, 1 << 20)
                   for script in ("install.sh", "update.sh")}
    for target in (name, sidecar, f"agp_{version}_SHA256SUMS", *entrypoints):
        if (output / target).exists() or (output / target).is_symlink():
            raise ValueError(f"refusing to overwrite release artifact: {target}")
    publish_file(output / name, raw)
    publish_file(output / sidecar, inv)
    sums = f"{digest(raw)}  {name}\n{digest(inv)}  {sidecar}\n"
    for script, script_raw in entrypoints.items():
        publish_file(output / script, script_raw)
        (output / script).chmod(0o755)
        sums += f"{digest(script_raw)}  {script}\n"
    sums = sums.encode()
    publish_file(output / f"agp_{version}_SHA256SUMS", sums)
    return output / name, digest(raw)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source-dir", type=Path, default=Path(__file__).resolve().parent.parent)
    parser.add_argument("--bin-dir", type=Path, required=True)
    parser.add_argument("--output-dir", type=Path, required=True)
    parser.add_argument("--version", required=True)
    parser.add_argument("--commit", required=True)
    parser.add_argument("--epoch", type=int, required=True)
    args = parser.parse_args()
    try:
        archive, sha = package(args.source_dir, args.bin_dir, args.output_dir,
                               args.version, args.commit, args.epoch)
    except (ValueError, OSError, UnicodeError) as exc:
        parser.exit(1, f"release packaging refused: {exc}\n")
    print(f"{sha}  {archive}")
    print("Operator pin only. No signing, GitHub publication or native qualification was performed.")


if __name__ == "__main__":
    main()
