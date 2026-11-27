#!/usr/bin/env python3
"""Byte-backed native runtime license provenance; no legal SPDX inference.

Called during preparation, before the candidate is sealed/tested/signed. It
never alters runtime ELF/CRS bytes and requires the original verified scratch.
"""
import argparse
import hashlib
import json
from pathlib import Path
import shutil
import subprocess
import tarfile


def digest(path):
    with path.open("rb") as stream:
        return hashlib.file_digest(stream, "sha256").hexdigest()


def stanzas(text):
    for value in text.split("\n\n"):
        fields = {}
        for line in value.splitlines():
            if line and not line[0].isspace() and ": " in line:
                key, content = line.split(": ", 1)
                fields[key] = content
        if "Package" in fields:
            yield fields


def notice_inventory(root, bundle, cache, lock, entries):
    sources = {item["file"]: item for item in lock["sources"]}
    for name in ["nginx-1.30.8.tar.gz", "connector.tar.gz", "modsecurity-v3.0.17.tar.gz", "ubuntu-base-24.04.5-base-amd64.tar.gz"]:
        if digest(cache / name) != sources[name]["sha256"]:
            raise ValueError("source integrity lost before notice attribution")
    embedded = "embedded-in-modsecurity-" + lock["tuple"]["modsecurity"]
    for target, package, version, archive, member in [
        ("nginx.txt", "nginx", lock["tuple"]["nginx"], "nginx-1.30.8.tar.gz", "nginx-1.30.8/LICENSE"),
        ("connector.txt", "modsecurity-nginx", lock["tuple"]["connector"], "connector.tar.gz", "ModSecurity-nginx-1.0.4/LICENSE"),
        ("modsecurity.txt", "modsecurity", lock["tuple"]["modsecurity"], "modsecurity-v3.0.17.tar.gz", "modsecurity-v3.0.17/LICENSE"),
        ("libinjection.txt", "libinjection", embedded, "modsecurity-v3.0.17.tar.gz", "modsecurity-v3.0.17/others/libinjection/COPYING"),
        ("mbedtls.txt", "mbedtls", embedded, "modsecurity-v3.0.17.tar.gz", "modsecurity-v3.0.17/others/mbedtls/LICENSE"),
        ("tf-psa-crypto.txt", "tf-psa-crypto", embedded, "modsecurity-v3.0.17.tar.gz", "modsecurity-v3.0.17/others/mbedtls/tf-psa-crypto/LICENSE"),
    ]:
        relative = "share/licenses/" + target
        with tarfile.open(cache / archive) as source:
            content = source.extractfile(member).read()
        if hashlib.sha256(content).hexdigest() != digest(bundle / relative):
            raise ValueError("source notice differs from signed upstream bytes")
        entries[relative] = {"sourcePackage": package, "sourceVersion": version,
                             "sourceArtifactDigest": "sha256:" + sources[archive]["sha256"],
                             "sourceMember": member, "license": "LicenseRef-" + package,
                             "noticePaths": [relative]}

    pending = {}
    for path in (bundle / "share/licenses").rglob("*"):
        if path.is_file() and str(path.relative_to(bundle)) not in entries:
            pending.setdefault(digest(path), []).append(str(path.relative_to(bundle)))
    for item in lock["packages"]:
        if item["role"] != "ubuntu24-build-dependency":
            continue
        archive = cache / item["file"]
        if digest(archive) != item["sha256"]:
            raise ValueError("package integrity lost before copyright attribution")
        fields = next(stanzas(subprocess.check_output(["dpkg-deb", "-f", str(archive)], text=True)))
        package = fields.get("Source", fields["Package"]).split(" ", 1)[0]
        process = subprocess.Popen(["dpkg-deb", "--fsys-tarfile", str(archive)], stdout=subprocess.PIPE)
        with tarfile.open(fileobj=process.stdout, mode="r|") as source:
            for member in source:
                if not member.isfile() or Path(member.name).name != "copyright":
                    continue
                content_digest = hashlib.sha256(source.extractfile(member).read()).hexdigest()
                targets = [target for target in pending.get(content_digest, []) if target.endswith(".copyright")]
                for target in targets:
                    entries[target] = {"sourcePackage": package, "sourceVersion": fields["Version"],
                                       "sourceArtifactDigest": "sha256:" + item["sha256"], "sourceMember": member.name,
                                       "license": "LicenseRef-" + package, "noticePaths": [target]}
                    pending[content_digest].remove(target)
                if content_digest in pending and not pending[content_digest]:
                    del pending[content_digest]
        process.stdout.close()
        if process.wait() != 0:
            raise ValueError("cannot inspect dependency notice archive")
    if pending:
        base_name = "ubuntu-base-24.04.5-base-amd64.tar.gz"
        status = {value["Package"]: value for value in stanzas((root / "var/lib/dpkg/status").read_text())}
        owners = {}
        for file in (root / "var/lib/dpkg/info").glob("*.list"):
            package = file.name.removesuffix(".list").split(":", 1)[0]
            for line in file.read_text(errors="replace").splitlines():
                owners[line.lstrip("/")] = package
        with tarfile.open(cache / base_name) as source:
            for member in source:
                if not member.isfile() or (Path(member.name).name != "copyright" and "usr/share/common-licenses/" not in member.name):
                    continue
                content_digest = hashlib.sha256(source.extractfile(member).read()).hexdigest()
                if content_digest not in pending:
                    continue
                normalized = member.name.removeprefix("./").lstrip("/")
                owner = owners.get(normalized)
                if owner is None or owner not in status:
                    raise ValueError("base notice missing actual dpkg ownership: " + normalized)
                fields = status[owner]
                package = fields.get("Source", owner).split(" ", 1)[0]
                for target in pending.pop(content_digest):
                    entries[target] = {"sourcePackage": package, "sourceVersion": fields["Version"],
                                       "sourceArtifactDigest": "sha256:" + sources[base_name]["sha256"], "sourceMember": member.name,
                                       "license": "LicenseRef-" + package, "noticePaths": [target]}
    if pending:
        raise ValueError("unproven license notice bytes: " + ",".join(target for targets in pending.values() for target in targets))


def inventory(root, bundle, cache, lock):
    if (bundle / "licenses.json").exists():
        raise ValueError("license inventory already finalized")
    entries = {}
    by_file = {item["file"]: item for item in lock["sources"]}

    def entry(package, version, source_digest, notices):
        return {"sourcePackage": package, "sourceVersion": version,
                "sourceArtifactDigest": "sha256:" + source_digest,
                "license": "LicenseRef-" + package,
                "noticePaths": notices}

    entries["bin/nginx"] = entry("nginx", lock["tuple"]["nginx"], by_file["nginx-1.30.8.tar.gz"]["sha256"], ["share/licenses/nginx.txt"])
    entries["modules/ngx_http_modsecurity_module.so"] = entry("modsecurity-nginx", lock["tuple"]["connector"], by_file["connector.tar.gz"]["sha256"], ["share/licenses/connector.txt"])
    modsec = entry("modsecurity", lock["tuple"]["modsecurity"], by_file["modsecurity-v3.0.17.tar.gz"]["sha256"],
                   ["share/licenses/modsecurity.txt", "share/licenses/libinjection.txt", "share/licenses/mbedtls.txt", "share/licenses/tf-psa-crypto.txt"])
    modsec["license"] = "LicenseRef-modsecurity AND LicenseRef-libinjection AND LicenseRef-mbedtls AND LicenseRef-tf-psa-crypto"
    entries["lib/libmodsecurity.so.3"] = modsec
    entries["share/modsecurity/unicode.mapping"] = entry("modsecurity", lock["tuple"]["modsecurity"], by_file["modsecurity-v3.0.17.tar.gz"]["sha256"], ["share/licenses/modsecurity.txt"])
    for path in (bundle / "share/crs").rglob("*"):
        if path.is_file():
            entries[str(path.relative_to(bundle))] = entry("coreruleset", lock["tuple"]["crs"], by_file["crs.tar.gz"]["sha256"], ["share/crs/LICENSE"])

    runtime = {}
    for path in (bundle / "lib").iterdir():
        if path.name != "libmodsecurity.so.3":
            source = next((directory / path.name for directory in [root / "usr/lib/x86_64-linux-gnu", root / "lib/x86_64-linux-gnu"]
                           if (directory / path.name).exists()), None)
            if source is None or not source.resolve().is_relative_to(root) or digest(source.resolve()) != digest(path):
                raise ValueError("runtime library differs from Ubuntu24 build scratch: " + path.name)
            runtime[source.resolve().name] = ("lib/" + path.name, digest(path))

    def copy_notice(binary_package):
        source = root / "usr/share/doc" / binary_package / "copyright"
        if not source.exists() or not source.resolve().is_relative_to(root):
            raise ValueError("actual package copyright unavailable: " + binary_package)
        destination = bundle / "share/licenses" / (binary_package + ".copyright")
        if destination.exists() and digest(source) != digest(destination):
            raise ValueError("candidate copyright bytes differ from build scratch")
        if not destination.exists():
            shutil.copy2(source, destination)
        return str(destination.relative_to(bundle))

    for item in lock["packages"]:
        if item["role"] != "ubuntu24-build-dependency" or not runtime:
            continue
        archive = cache / item["file"]
        if digest(archive) != item["sha256"]:
            raise ValueError("package integrity lost before license inventory")
        control = subprocess.check_output(["dpkg-deb", "-f", str(archive)], text=True)
        fields = next(stanzas(control))
        source_package = fields.get("Source", fields["Package"]).split(" ", 1)[0]
        process = subprocess.Popen(["dpkg-deb", "--fsys-tarfile", str(archive)], stdout=subprocess.PIPE)
        matched = []
        with tarfile.open(fileobj=process.stdout, mode="r|") as source:
            for member in source:
                name = Path(member.name).name
                if member.isfile() and name in runtime:
                    content = source.extractfile(member).read()
                    relative, expected = runtime[name]
                    if hashlib.sha256(content).hexdigest() == expected:
                        notice = copy_notice(fields["Package"])
                        entries[relative] = entry(source_package, fields["Version"], item["sha256"], [notice])
                        entries[relative]["binaryPackage"] = fields["Package"]
                        matched.append(name)
        process.stdout.close()
        if process.wait() != 0:
            raise ValueError("cannot inspect verified dependency package")
        for name in matched:
            del runtime[name]

    # Libraries already installed in the signed Ubuntu base image may not have
    # been downloaded by apt. Bind their exact current bytes to the original
    # image member, original dpkg ownership and image digest, not host metadata.
    if runtime:
        base_name = "ubuntu-base-24.04.5-base-amd64.tar.gz"
        base = cache / base_name
        if digest(base) != by_file[base_name]["sha256"]:
            raise ValueError("base image integrity lost before license inventory")
        owners = {}
        for file in (root / "var/lib/dpkg/info").glob("*.list"):
            package = file.name.removesuffix(".list").split(":", 1)[0]
            for line in file.read_text(errors="replace").splitlines():
                if Path(line).name in runtime:
                    owners[Path(line).name] = package
        status = {value["Package"]: value for value in stanzas((root / "var/lib/dpkg/status").read_text())}
        with tarfile.open(base) as source:
            for member in source:
                name = Path(member.name).name
                if member.isfile() and name in runtime:
                    relative, expected = runtime[name]
                    if hashlib.sha256(source.extractfile(member).read()).hexdigest() != expected:
                        continue
                    package = owners.get(name)
                    if package is None or package not in status:
                        raise ValueError("base library has no signed dpkg owner")
                    fields = status[package]
                    source_package = fields.get("Source", package).split(" ", 1)[0]
                    entries[relative] = entry(source_package, fields["Version"], by_file[base_name]["sha256"], [copy_notice(package)])
                    entries[relative]["binaryPackage"] = package
                    entries[relative]["sourceContainer"] = base_name
                    del runtime[name]
    if runtime:
        raise ValueError("unproven runtime library license provenance: " + ",".join(runtime))

    notice_inventory(root, bundle, cache, lock, entries)

    for relative, value in entries.items():
        value["digest"] = "sha256:" + digest(bundle / relative)
        for notice in value["noticePaths"]:
            if not (bundle / notice).is_file():
                raise ValueError("runtime license notice missing: " + notice)
    result = {"format": "agp.waf-native-license-inventory/v1",
              "scope": "actual upstream/package notice provenance; LicenseRef labels do not assert SPDX legal conclusions",
              "files": entries}
    (bundle / "licenses.json").write_text(json.dumps(result, indent=2) + "\n")
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--rootfs", required=True)
    parser.add_argument("--bundle", required=True)
    parser.add_argument("--cache", required=True)
    parser.add_argument("--lock", required=True)
    args = parser.parse_args()
    result = inventory(Path(args.rootfs).resolve(), Path(args.bundle).resolve(), Path(args.cache).resolve(), json.loads(Path(args.lock).read_text()))
    print("runtime license provenance PASS", len(result["files"]))


if __name__ == "__main__":
    main()
