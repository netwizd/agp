#!/usr/bin/env python3
"""Offline, fail-closed source pin and selected Nginx runtime acceptance.

This checks reviewed local pins, not the availability of newer upstream releases
or the provenance of an arbitrary executable. Native qualification and installer
signature verification remain mandatory. No downloads or system changes occur.
"""
import argparse
import json
import os
from pathlib import Path
import re
import shlex
import shutil
import subprocess
import sys


# A coordinated version/env/lock edit alone cannot bless an unqualified build.
# Advance these only after reviewing upstream advisories and native acceptance.
SECURITY_FLOOR = "1.30.8"
QUALIFIED_VERSIONS = frozenset({"1.30.8"})
REQUIRED_MODULES = frozenset({
    "--with-http_auth_request_module", "--with-http_ssl_module", "--with-http_v2_module",
})
ENV_KEYS = frozenset({
    "AGP_NGINX_QUALIFIED_VERSION", "AGP_NGINX_SECURITY_FLOOR",
    "AGP_NGINX_REQUIRED_MODULES", "AGP_NGINX_SIGNING_FINGERPRINT",
    "AGP_NGINX_SOURCE_SIGNING_FINGERPRINT", "AGP_NGINX_SOURCE_SHA256",
    "AGP_NGINX_SOURCE_SIGNATURE_SHA256",
})
VERSION = re.compile(r"(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)\Z")


def require(condition, message):
    if not condition:
        raise ValueError(message)


def stable_version(value):
    require(isinstance(value, str) and VERSION.fullmatch(value), "malformed or prerelease Nginx version")
    parts = tuple(int(part) for part in value.split("."))
    require(parts[0] == 1 and parts[1] % 2 == 0, "only the qualified stable Nginx branch is supported")
    return parts


def unique_object(pairs):
    result = {}
    for key, value in pairs:
        require(key not in result, "duplicate JSON field in native lock: " + key)
        result[key] = value
    return result


def check_source(repo_root):
    """Parse the env file as data; never source or evaluate shell expressions."""
    env = {}
    for line in (repo_root / "scripts/nginx-toolchain.env").read_text().splitlines():
        if not line.strip() or line.lstrip().startswith("#"):
            continue
        key, separator, raw = line.partition("=")
        require(separator and key in ENV_KEYS and key not in env, "unknown or duplicate Nginx pin assignment")
        values = shlex.split(raw)
        require(len(values) == 1 and not any(char in values[0] for char in "`$\n\r\0"), "invalid Nginx pin value")
        env[key] = values[0]
    require(env.keys() == ENV_KEYS, "Nginx toolchain pin is incomplete")
    version = env["AGP_NGINX_QUALIFIED_VERSION"]
    require(stable_version(version) >= stable_version(SECURITY_FLOOR), "Nginx pin is below the security floor")
    require(env["AGP_NGINX_SECURITY_FLOOR"] == SECURITY_FLOOR, "Nginx security floor differs from reviewed baseline")
    require(version in QUALIFIED_VERSIONS, "Nginx version has no native qualification; update the reviewed baseline first")
    requested = os.environ.get("NGINX_VERSION")
    require(not requested or requested == version, "NGINX_VERSION differs from the qualified pin")
    modules = shlex.split(env["AGP_NGINX_REQUIRED_MODULES"])
    require(len(modules) == len(REQUIRED_MODULES) and set(modules) == REQUIRED_MODULES,
            "required Nginx auth_request/ssl/h2 modules differ from reviewed baseline")
    for key in ("AGP_NGINX_SIGNING_FINGERPRINT", "AGP_NGINX_SOURCE_SIGNING_FINGERPRINT"):
        require(re.fullmatch(r"[A-F0-9]{40}", env[key]), "malformed Nginx signing fingerprint")
    for key in ("AGP_NGINX_SOURCE_SHA256", "AGP_NGINX_SOURCE_SIGNATURE_SHA256"):
        require(re.fullmatch(r"[a-f0-9]{64}", env[key]), "malformed Nginx source digest")

    lock = json.loads((repo_root / "configs/waf-native.lock.json").read_text(), object_pairs_hook=unique_object)
    require(lock["format"] == "agp.waf-native-lock/v1", "unsupported native lock format")
    require(lock["tuple"]["nginx"] == version, "Nginx pin/native lock version mismatch")
    require(lock["signers"]["nginx"] == env["AGP_NGINX_SOURCE_SIGNING_FINGERPRINT"],
            "Nginx source signer/native lock mismatch")
    require(REQUIRED_MODULES.issubset(lock["nginxConfigure"]), "native source build lacks required auth_request/ssl/h2 flags")
    sources = lock["sources"]
    names = [item["file"] for item in sources]
    require(len(set(names)) == len(names), "duplicate native source artifact")
    by_name = {item["file"]: item for item in sources}
    for suffix, digest_key in ((".tar.gz", "AGP_NGINX_SOURCE_SHA256"),
                               (".tar.gz.asc", "AGP_NGINX_SOURCE_SIGNATURE_SHA256")):
        name = "nginx-" + version + suffix
        item = by_name.get(name, {})
        require(item.get("url") == "https://nginx.org/download/" + name, "Nginx source URL/version mismatch")
        require(item.get("sha256") == env[digest_key], "Nginx source digest/native lock mismatch")
        require(type(item.get("length")) is int and 0 < item["length"] <= 32 * 1024 * 1024,
                "invalid Nginx source length")
    return version


def check_runtime(binary, expected):
    resolved = shutil.which(str(binary))
    require(resolved is not None, "selected Nginx executable not found")
    resolved = str(Path(resolved).absolute())
    require(os.access(resolved, os.X_OK), "selected Nginx binary is not executable")
    result = subprocess.run([resolved, "-V"], stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                            timeout=15, check=False)
    require(result.returncode == 0, "Nginx -V failed")
    require(len(result.stdout) <= 64 * 1024, "Nginx -V output exceeds limit")
    output = result.stdout.decode("utf-8", errors="strict")
    require("\0" not in output and "\r" not in output, "malformed Nginx -V output")
    lines = output.splitlines()
    require(bool(lines) and lines[0].startswith("nginx version: nginx/"), "missing Nginx version header")
    actual = lines[0].removeprefix("nginx version: nginx/")
    require(stable_version(actual) >= stable_version(SECURITY_FLOOR), "Nginx runtime is below the security floor")
    require(actual == expected, "Nginx runtime differs from the exact qualified version " + expected)
    require(sum(line.startswith("nginx version:") for line in lines) == 1, "ambiguous Nginx version output")
    configure = [line.removeprefix("configure arguments: ") for line in lines if line.startswith("configure arguments: ")]
    require(len(configure) == 1, "missing or ambiguous Nginx configure arguments")
    flags = set(shlex.split(configure[0]))
    missing = sorted(REQUIRED_MODULES - flags)
    require(not missing, "required Nginx configure flag missing: " + ", ".join(missing))
    return resolved, output


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("--binary", help="explicit native Nginx executable (or verified loader wrapper)")
    group.add_argument("--source-only", action="store_true", help="check repository pins without executing a binary")
    args = parser.parse_args()
    try:
        version = check_source(Path(__file__).resolve().parents[1])
        if args.binary:
            binary, output = check_runtime(args.binary, version)
            print(output, end="" if output.endswith("\n") else "\n")
            print("Nginx baseline PASS: " + version + "; auth_request/ssl/h2; " + binary)
        else:
            print("Nginx source baseline PASS: " + version + "; runtime not checked")
    except (ValueError, KeyError, TypeError, OSError, UnicodeError, subprocess.SubprocessError) as error:
        print("Nginx baseline: " + str(error), file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
