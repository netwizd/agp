#!/usr/bin/env python3
"""Pinned, unprivileged Ubuntu 24 userspace build. No host package installation.

Requires ptrace permission for PRoot, GCC/make are extracted into the private
rootfs. Package maintainer hooks and service managers are never invoked.
Unsigned build records are evidence, not publication/qualification authority.
"""
import argparse
import concurrent.futures
import hashlib
import json
import os
from pathlib import Path
import platform
import re
import shutil
import subprocess
import sys
import tarfile
import urllib.request
from licenses import inventory as license_inventory

REPO = Path(__file__).resolve().parents[2]


def sha(path):
    with path.open("rb") as stream:
        return hashlib.file_digest(stream, "sha256").hexdigest()


def run(args, **kwargs):
    return subprocess.run([str(x) for x in args], check=True, **kwargs)


def fetch(item, cache, offline):
    dest = cache / item["file"]
    if not dest.exists():
        if offline:
            raise ValueError("offline cache missing: " + item["file"])
        part = dest.with_suffix(dest.suffix + ".partial")
        request = urllib.request.Request(item["url"], headers={"User-Agent": "AGP-native-build/1"})
        with urllib.request.urlopen(request, timeout=120) as response, part.open("wb") as output:
            shutil.copyfileobj(response, output)
        part.replace(dest)
    if dest.is_symlink() or dest.stat().st_size != item["length"] or sha(dest) != item["sha256"]:
        raise ValueError("locked artifact integrity failed: " + item["file"])
    return dest


def git_hash(kind, content):
    return hashlib.sha1(kind.encode() + b" " + str(len(content)).encode() + b"\0" + content).hexdigest()


def connector_tree(archive):
    root = {}
    with tarfile.open(archive) as source:
        for entry in source:
            if entry.isdir():
                continue
            relative = entry.name.split("/", 1)[1]
            if not relative or relative.startswith("/") or ".." in Path(relative).parts:
                raise ValueError("unsafe connector archive path")
            if entry.isfile():
                content = source.extractfile(entry).read()
                mode = "100755" if entry.mode & 0o111 else "100644"
            elif entry.issym():
                content, mode = entry.linkname.encode(), "120000"
            else:
                raise ValueError("unsupported connector archive entry")
            node = root
            parts = relative.split("/")
            for part in parts[:-1]:
                node = node.setdefault(part, {})
            node[parts[-1]] = (mode, git_hash("blob", content))

    def digest(tree):
        entries = []
        for name, value in tree.items():
            mode, oid = ("40000", digest(value)) if isinstance(value, dict) else value
            entries.append((name + ("/" if mode == "40000" else ""),
                            mode.encode() + b" " + name.encode() + b"\0" + bytes.fromhex(oid)))
        return git_hash("tree", b"".join(value for _, value in sorted(entries)))
    return digest(root)


def verify_sources(lock, cache, work):
    home = work / "gnupg"
    home.mkdir(mode=0o700, exist_ok=True)
    gpg = ["gpg", "--homedir", str(home), "--batch", "--no-autostart"]
    keys = ["nginx-source-key.asc", "modsecurity-key.asc", "crs-security.asc",
            "connector-key.asc", "ubuntu-cdimage-key.asc"]
    run(gpg + ["--import"] + [cache / name for name in keys], stdout=subprocess.DEVNULL)

    def verify(signature, artifact, signer):
        result = run(gpg + ["--status-fd", "1", "--verify", signature, artifact],
                     stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        valid = [line.split()[2] for line in result.stdout.splitlines() if line.startswith("[GNUPG:] VALIDSIG ")]
        if valid != [signer]:
            raise ValueError("unexpected release signature identity")

    for name, source in [("nginx", "nginx-1.30.8.tar.gz"),
                         ("modsecurity", "modsecurity-v3.0.17.tar.gz"), ("crs", "crs.tar.gz")]:
        verify(cache / (source + ".asc"), cache / source, lock["signers"][name])
    verify(cache / "SHA256SUMS.gpg", cache / "SHA256SUMS", lock["signers"]["ubuntuBase"])
    image = "ubuntu-base-24.04.5-base-amd64.tar.gz"
    sums = (cache / "SHA256SUMS").read_text().splitlines()
    expected = [line.split()[0] for line in sums if line.endswith(" *" + image) or line.endswith("  " + image)]
    if expected != [sha(cache / image)]:
        raise ValueError("Ubuntu image not covered by signed SHA256SUMS")
    for name in ["connector-tag", "connector-commit"]:
        data = json.loads((cache / (name + ".json")).read_text())
        value = data["verification"]
        payload, signature = work / (name + ".payload"), work / (name + ".asc")
        payload.write_text(value["payload"])
        signature.write_text(value["signature"])
        verify(signature, payload, lock["signers"]["connector"])
        if name == "connector-tag":
            if not value["payload"].startswith("object " + lock["connectorCommit"] + "\n"):
                raise ValueError("signed connector tag points to another commit")
        else:
            header, message = value["payload"].split("\n\n", 1)
            content = (header + "\ngpgsig " + value["signature"].rstrip("\n").replace("\n", "\n ") + "\n\n" + message).encode()
            if git_hash("commit", content) != lock["connectorCommit"]:
                raise ValueError("connector signed commit digest mismatch")
            if not header.startswith("tree " + lock["connectorTree"] + "\n"):
                raise ValueError("connector signed commit tree mismatch")
    if connector_tree(cache / "connector.tar.gz") != lock["connectorTree"]:
        raise ValueError("connector archive differs from signed commit tree")


def build(args, lock, cache, work):
    root, toolroot = work / "rootfs", work / "tools/root"
    if root.exists() and not args.resume:
        raise ValueError("scratch rootfs already exists; use a fresh --work or explicit --resume")
    if not root.exists():
        root.mkdir()
        run(["tar", "--no-same-owner", "-xzf", cache / "ubuntu-base-24.04.5-base-amd64.tar.gz", "-C", root])
        for item in lock["packages"]:
            target = toolroot if item["role"] == "build-tool-host" else root
            target.mkdir(parents=True, exist_ok=True)
            run(["dpkg-deb", "-x", cache / item["file"], target])
    proot = toolroot / "usr/bin/proot"
    env = dict(PATH="/usr/bin:/bin", LANG="C", PROOT_NO_SECCOMP="1", LC_ALL="C", TZ="UTC",
               SOURCE_DATE_EPOCH=str(lock["sourceDateEpoch"]),
               LD_LIBRARY_PATH=str(toolroot / "usr/lib/x86_64-linux-gnu"))
    # No host /etc, /sys, /home or device tree bind. The fake root UID stays
    # the caller's real unprivileged UID. Network is unnecessary after fetch.
    base = [proot, "-0", "-r", root, "-b", "/proc", "-b", "/dev/null", "-b", "/dev/urandom"]
    run(base + ["-w", "/", "/bin/true"], env=env)
    src = root / "build/src"
    src.mkdir(parents=True, exist_ok=True)
    for archive, dirname in [("modsecurity-v3.0.17.tar.gz", "modsecurity-v3.0.17"),
                              ("nginx-1.30.8.tar.gz", "nginx-1.30.8"), ("connector.tar.gz", "ModSecurity-nginx-1.0.4")]:
        if not (src / dirname).exists():
            run(["tar", "--no-same-owner", "-xzf", cache / archive, "-C", src])
        # A resumed build may reuse compiler outputs, but never silently reuse
        # modified source files while claiming the locked source provenance.
        with tarfile.open(cache / archive) as source:
            for member in source:
                # The upstream release contains dependency placeholders that
                # make legitimately rewrites; they are compiler bookkeeping,
                # not source or generated parser inputs.
                generated_dependency = ".deps" in Path(member.name).parts and member.name.endswith(".Plo")
                if member.isfile() and not generated_dependency:
                    actual = src / member.name
                    if not actual.is_file() or actual.is_symlink() or actual.read_bytes() != source.extractfile(member).read():
                        raise ValueError("extracted source differs from signed archive: " + member.name)

    inside_env = []

    def command(directory, label, command):
        print(label, flush=True)
        with (root / "build" / (label + ".log")).open("wb") as output:
            run(base + ["-w", directory] + inside_env + command, env=env, stdout=output, stderr=subprocess.STDOUT)

    command("/build/src/modsecurity-v3.0.17", "modsecurity-configure", ["./configure"] + lock["modsecurityConfigure"])
    command("/build/src/modsecurity-v3.0.17", "modsecurity-make", ["make", "-j" + str(args.jobs)])
    command("/build/src/modsecurity-v3.0.17", "modsecurity-check", ["make", "check", "-j" + str(args.jobs)])
    command("/build/src/modsecurity-v3.0.17", "modsecurity-install", ["make", "install"])
    inside_env = ["/usr/bin/env", "MODSECURITY_INC=/opt/agp-waf/include",
                  "MODSECURITY_LIB=/opt/agp-waf/lib", "LD_LIBRARY_PATH=/opt/agp-waf/lib"]
    command("/build/src/nginx-1.30.8", "nginx-configure", ["./configure"] + lock["nginxConfigure"])
    command("/build/src/nginx-1.30.8", "nginx-make", ["make", "-j" + str(args.jobs)])
    output = Path(args.output).resolve()
    if output.exists():
        raise ValueError("refusing to overwrite existing bundle: " + str(output))
    for dirname in ["bin", "modules", "lib", "share/crs", "share/modsecurity", "share/licenses", "provenance"]:
        (output / dirname).mkdir(parents=True, exist_ok=True)
    shutil.copy2(src / "nginx-1.30.8/objs/nginx", output / "bin/nginx")
    shutil.copy2(src / "nginx-1.30.8/objs/ngx_http_modsecurity_module.so", output / "modules/ngx_http_modsecurity_module.so")
    shutil.copy2(src / "modsecurity-v3.0.17/unicode.mapping", output / "share/modsecurity/unicode.mapping")
    run(["tar", "--no-same-owner", "-xzf", cache / "crs.tar.gz", "--strip-components=1", "-C", output / "share/crs"])
    # These upstream zero-byte examples are not included by the fixed renderer
    # (which loads rules/*.conf only), and are not release runtime artifacts.
    omitted = []
    for name in ["empty-config.conf", "empty-before.conf", "empty-after.conf"]:
        placeholder = output / "share/crs/plugins" / name
        if not placeholder.is_file() or placeholder.read_bytes() != b"":
            raise ValueError("unexpected locked CRS placeholder contents")
        placeholder.unlink()
        omitted.append(str(placeholder.relative_to(output)))
    (output / "provenance/omitted-empty-runtime-placeholders.json").write_text(json.dumps(omitted, indent=2) + "\n")
    # Use readelf (not ldd) for dependency discovery. Each ELF is selected from
    # Ubuntu24 rootfs or this exact ModSecurity build, never the host libraries.
    search = [root / "opt/agp-waf/lib", root / "usr/lib/x86_64-linux-gnu", root / "lib/x86_64-linux-gnu"]
    queue = [output / "bin/nginx", output / "modules/ngx_http_modsecurity_module.so"]
    needed = {"ld-linux-x86-64.so.2"}
    while queue or needed:
        while queue:
            elf = queue.pop()
            info = subprocess.check_output(["readelf", "-d", str(elf)], text=True)
            needed.update(re.findall(r"\(NEEDED\).*?\[(.*?)\]", info))
        for name in sorted(needed):
            dest = output / "lib" / name
            if dest.exists():
                continue
            source = next((directory / name for directory in search if (directory / name).exists()), None)
            if source is None:
                raise ValueError("runtime dependency missing in Ubuntu24 closure: " + name)
            shutil.copy2(source.resolve(), dest)
            queue.append(dest)
        needed.clear()
    for source, name in [(src / "nginx-1.30.8/LICENSE", "nginx.txt"),
                         (src / "modsecurity-v3.0.17/LICENSE", "modsecurity.txt"),
                         (src / "ModSecurity-nginx-1.0.4/LICENSE", "connector.txt"),
                         (src / "modsecurity-v3.0.17/others/libinjection/COPYING", "libinjection.txt"),
                         (src / "modsecurity-v3.0.17/others/mbedtls/LICENSE", "mbedtls.txt"),
                         (src / "modsecurity-v3.0.17/others/mbedtls/tf-psa-crypto/LICENSE", "tf-psa-crypto.txt")]:
        shutil.copy2(source, output / "share/licenses" / name)
    for package in lock["packages"]:
        if package["role"] != "ubuntu24-build-dependency":
            continue
        copyright_file = root / "usr/share/doc" / package["name"] / "copyright"
        if copyright_file.exists() and copyright_file.resolve().is_relative_to(root):
            shutil.copy2(copyright_file, output / "share/licenses" / (package["name"] + ".copyright"))
    shutil.copytree(root / "usr/share/common-licenses", output / "share/licenses/common", symlinks=False)
    license_inventory(root, output, cache, lock)
    for file in (root / "build").glob("*.log"):
        shutil.copy2(file, output / "provenance" / file.name)
    shutil.copy2(args.lock, output / "provenance/waf-native.lock.json")
    loader = output / "lib/ld-linux-x86-64.so.2"
    version = subprocess.check_output([loader, "--library-path", output / "lib", output / "bin/nginx", "-V"],
                                      stderr=subprocess.STDOUT, text=True,
                                      env={"PATH": "/usr/bin:/bin", "LANG": "C", "LC_ALL": "C"})
    test_summary = {}
    check_log = (root / "build/modsecurity-check.log").read_text(errors="replace")
    for key in ["TOTAL", "PASS", "SKIP", "XFAIL", "FAIL", "XPASS", "ERROR"]:
        matches = re.findall(r"^# " + key + r":\s+(\d+)\s*$", check_log, flags=re.MULTILINE)
        if len(matches) != 1:
            raise ValueError("upstream test summary missing/ambiguous: " + key)
        test_summary[key.lower()] = int(matches[0])
    if test_summary["fail"] or test_summary["error"] or not test_summary["pass"]:
        raise ValueError("mandatory upstream test execution failed")
    record = {"format": "agp.waf-native-build/v1", "platform": lock["platform"], "tuple": lock["tuple"],
              "userspace": {"id": "ubuntu", "versionId": "24.04", "imageVersion": lock["ubuntuBase"]},
              "host": {"kernel": platform.release(), "machine": platform.machine(), "osRelease": Path("/etc/os-release").read_text()},
              "isolation": "unprivileged-proot-userspace-shared-host-kernel", "nginxVersionOutput": version,
              "nginxConfigure": lock["nginxConfigure"], "modsecurityConfigure": lock["modsecurityConfigure"],
              "lockDigest": "sha256:" + sha(Path(args.lock)), "publicationAuthority": False,
              "licenseInventoryDigest": "sha256:" + sha(output / "licenses.json"),
              "resumedBuild": args.resume,
              "upstreamTests": {"modsecurity": test_summary,
                                "scope": "optional disabled Lua/remote/GeoIP/etc cases remain upstream SKIP; they are not PASS and do not qualify those features"},
              "dependencies": lock["packages"], "sources": lock["sources"]}
    (output / "build.json").write_text(json.dumps(record, indent=2) + "\n")
    checksums = {str(path.relative_to(output)): {"sha256": sha(path), "length": path.stat().st_size}
                 for path in sorted(output.rglob("*")) if path.is_file()}
    (output / "checksums.json").write_text(json.dumps(checksums, indent=2) + "\n")
    print("BUILD PASS " + str(output), flush=True)


def agent_lab(args, lock, cache, work):
    """Reuse the locked Ubuntu image for the read-only agent acceptance lab."""
    image = "ubuntu-base-24.04.5-base-amd64.tar.gz"
    names = {image, "SHA256SUMS", "SHA256SUMS.gpg"}
    if not args.ubuntu_keyring:
        names.add("ubuntu-cdimage-key.asc")
    sources = [item for item in lock["sources"] if item["file"] in names]
    tools = [item for item in lock["packages"] if item["role"] == "build-tool-host"]
    for item in sources + tools:
        fetch(item, cache, args.offline)
    home = work / "gnupg"
    home.mkdir(mode=0o700)
    gpg = ["gpg", "--homedir", str(home), "--batch", "--no-autostart"]
    # An explicitly supplied distribution keyring avoids mutable keyserver
    # armor. The accepted image signer remains the exact fingerprint in lock.
    keyring = Path(args.ubuntu_keyring) if args.ubuntu_keyring else cache / "ubuntu-cdimage-key.asc"
    run(gpg + ["--import", keyring], stdout=subprocess.DEVNULL)
    verified = run(gpg + ["--status-fd", "1", "--verify", cache / "SHA256SUMS.gpg", cache / "SHA256SUMS"],
                   stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    signers = [line.split()[2] for line in verified.stdout.splitlines() if line.startswith("[GNUPG:] VALIDSIG ")]
    if signers != [lock["signers"]["ubuntuBase"]]:
        raise ValueError("unexpected Ubuntu image signer")
    sums = [line.split()[0] for line in (cache / "SHA256SUMS").read_text().splitlines()
            if line.endswith(" *" + image) or line.endswith("  " + image)]
    if sums != [sha(cache / image)]:
        raise ValueError("Ubuntu image not covered by signed checksums")
    root, toolroot = work / "rootfs", work / "tools/root"
    root.mkdir(mode=0o700)
    toolroot.mkdir(parents=True)
    run(["tar", "--no-same-owner", "-xzf", cache / image, "-C", root])
    root.chmod(0o700)
    for item in tools:
        run(["dpkg-deb", "-x", cache / item["file"], toolroot])
    record = {"rootfs": str(root), "proot": str(toolroot / "usr/bin/proot"),
              "hostLibraryPath": str(toolroot / "usr/lib/x86_64-linux-gnu"),
              "isolation": "unprivileged-proot-userspace-shared-host-kernel",
              "imageSHA256": sha(cache / image)}
    Path(args.output).write_text(json.dumps(record, indent=2) + "\n")
    print("AGENT USERSPACE PASS " + str(args.output), flush=True)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--lock", default=str(REPO / "configs/waf-native.lock.json"))
    parser.add_argument("--work", required=True, help="private, caller-owned build scratch")
    parser.add_argument("--output", required=True, help="new output directory; never overwritten")
    parser.add_argument("--jobs", type=int, choices=range(1, 17), default=4)
    parser.add_argument("--offline", action="store_true")
    parser.add_argument("--download-only", action="store_true")
    parser.add_argument("--resume", action="store_true", help="explicitly reuse private scratch; original source bytes are reverified")
    parser.add_argument("--agent-lab-only", action="store_true", help="prepare only the signed Ubuntu image and PRoot for read-only agent acceptance")
    parser.add_argument("--ubuntu-keyring", help="explicit public Ubuntu keyring for agent lab only; exact locked signer still required")
    args = parser.parse_args()
    if os.geteuid() == 0 or platform.machine() != "x86_64":
        raise ValueError("requires an unprivileged x86_64 caller")
    if not args.download_only and Path(args.output).exists():
        raise ValueError("refusing to overwrite existing bundle")
    work = Path(args.work).resolve()
    work.mkdir(mode=0o700, parents=True, exist_ok=True)
    cache = work / "downloads"
    cache.mkdir(exist_ok=True)
    lock = json.loads(Path(args.lock).read_text())
    if lock["format"] != "agp.waf-native-lock/v1" or lock["platform"] != "ubuntu24.04amd64":
        raise ValueError("unsupported lock format/platform")
    if args.agent_lab_only:
        if args.resume or args.download_only:
            raise ValueError("agent lab requires fresh private scratch")
        agent_lab(args, lock, cache, work)
        return
    items = lock["sources"] + lock["packages"]
    with concurrent.futures.ThreadPoolExecutor(max_workers=4) as pool:
        for _ in pool.map(lambda item: fetch(item, cache, args.offline), items):
            pass
    verify_sources(lock, cache, work)
    if args.download_only:
        print("LOCKED DOWNLOAD AND SIGNATURES PASS; no build performed")
        return
    build(args, lock, cache, work)


if __name__ == "__main__":
    try:
        main()
    except (ValueError, OSError, subprocess.CalledProcessError) as error:
        print("native WAF preparation failed: " + str(error), file=sys.stderr)
        sys.exit(1)
