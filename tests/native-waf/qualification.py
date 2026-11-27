#!/usr/bin/env python3
"""Actual Nginx + ModSecurity + CRS tests, never a publication authority.

Every corpus case is mandatory. Missing binaries, denied sockets, a failed case,
invalid bundle or missing response inspection fail the entire run (no skips).
The Ubuntu24 dynamic loader and complete flat library closure are used directly;
the host kernel is recorded separately from the built Ubuntu24 userspace.
"""
import argparse
import copy
import datetime
import hashlib
import http.client
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
import os
from pathlib import Path
import platform
import re
import shutil
import socket
import subprocess
import sys
import tempfile
import threading
import time
import urllib.parse

HERE = Path(__file__).resolve().parent
ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_-]{0,127}$")
RENDERER = None
RENDER_SEQUENCE = 0
SAFE_ENV = {"PATH": "/usr/bin:/bin", "LANG": "C", "LC_ALL": "C"}


def sha(path):
    with path.open("rb") as stream:
        return "sha256:" + hashlib.file_digest(stream, "sha256").hexdigest()


def now():
    return datetime.datetime.now(datetime.timezone.utc).isoformat(timespec="microseconds").replace("+00:00", "Z")


def exact(obj, keys):
    if not isinstance(obj, dict) or set(obj) != set(keys):
        raise ValueError("unknown or missing policy fields")


def validate_policy(policy):
    exact(policy, ["apiVersion", "kind", "metadata", "spec"])
    if policy["apiVersion"] != "agp.waf/v1alpha1" or policy["kind"] != "WafPolicy":
        raise ValueError("policy kind/version")
    meta = policy["metadata"]
    exact(meta, ["id", "name", "siteId"])
    if not ID.fullmatch(meta["id"]) or not ID.fullmatch(meta["siteId"]) or not isinstance(meta["name"], str) or not 1 <= len(meta["name"]) <= 128:
        raise ValueError("policy metadata")
    spec = policy["spec"]
    exact(spec, ["engine", "rulesetVersionId", "paranoiaLevel", "inboundAnomalyThreshold", "outboundAnomalyThreshold", "exceptions"])
    if spec["engine"] != "modsecurity" or not ID.fullmatch(spec["rulesetVersionId"]):
        raise ValueError("policy engine/ruleset")
    for key, maximum in [("paranoiaLevel", 4), ("inboundAnomalyThreshold", 100), ("outboundAnomalyThreshold", 100)]:
        if type(spec[key]) is not int or not 1 <= spec[key] <= maximum:
            raise ValueError("policy integer range")
    if not isinstance(spec["exceptions"], list) or len(spec["exceptions"]) > 100:
        raise ValueError("policy exception list")
    for exception in spec["exceptions"]:
        exact(exception, ["id", "routeId", "ruleIds", "match", "ownerId", "reason", "reviewAt", "expiresAt"])
        expiry = datetime.datetime.fromisoformat(exception["expiresAt"].replace("Z", "+00:00"))
        if expiry.tzinfo is None or expiry <= datetime.datetime.now(datetime.timezone.utc):
            raise ValueError("expired exception")
    # This corpus qualifies the base policy. Route-specific exception execution
    # requires separately frozen route bindings, never a caller supplied regex.
    if spec["exceptions"]:
        raise ValueError("route-specific exceptions require a qualified binding")
    return spec


def policy():
    return {"apiVersion": "agp.waf/v1alpha1", "kind": "WafPolicy",
            "metadata": {"id": "native_policy", "name": "Native corpus", "siteId": "native_site"},
            "spec": {"engine": "modsecurity", "rulesetVersionId": "crs_4_30_0", "paranoiaLevel": 1,
                     "inboundAnomalyThreshold": 5, "outboundAnomalyThreshold": 4, "exceptions": []}}


def path_value(path):
    text = str(path)
    if not re.fullmatch(r"[A-Za-z0-9/_.+-]+", text):
        raise ValueError("native scratch/bundle path must contain only simple ASCII path characters")
    return text


def render_policy(value, mode, bundle, work):
    global RENDER_SEQUENCE
    if RENDERER is not None:
        RENDER_SEQUENCE += 1
        source = work / ("typed-policy-" + str(RENDER_SEQUENCE) + ".json")
        source.write_text(json.dumps(value) + "\n")
        os.chmod(source, 0o600)
        rendered = subprocess.run([str(bundle / "lib/ld-linux-x86-64.so.2"),
                                   "--library-path", str(bundle / "lib"),
                                   str(RENDERER), "waf-render", "--policy", str(source),
                                   "--bundle", str(bundle), "--work", str(work), "--mode", mode],
                                  capture_output=True, text=True, timeout=30, env=SAFE_ENV)
        if rendered.returncode != 0:
            raise ValueError("typed renderer rejected policy: " + rendered.stderr[:240].strip())
        return rendered.stdout
    spec = validate_policy(value)
    engine = {"off": "Off", "detection": "DetectionOnly", "blocking": "On"}.get(mode)
    if engine is None:
        raise ValueError("invalid WAF mode")
    rules = path_value(bundle / "share/crs/rules")
    unicode = path_value(bundle / "share/modsecurity/unicode.mapping")
    scratch = path_value(work)
    return f'''SecRuleEngine {engine}
SecRequestBodyAccess On
SecRequestBodyLimit 65536
SecRequestBodyNoFilesLimit 65536
SecRequestBodyLimitAction Reject
SecRequestBodyJsonDepthLimit 64
SecArgumentsLimit 1000
SecResponseBodyAccess On
SecResponseBodyMimeType text/plain text/html application/json
SecResponseBodyLimit 65536
SecResponseBodyLimitAction Reject
SecTmpDir {scratch}
SecDataDir {scratch}
SecUploadKeepFiles Off
SecAuditEngine Off
SecUnicodeMapFile {unicode} 20127
SecDefaultAction "phase:1,log,auditlog,pass"
SecDefaultAction "phase:2,log,auditlog,pass"
SecRule REQUEST_HEADERS:Content-Type "^application/(?:[a-z0-9.-]+[+])?json(?:;|$)" "id:200001,phase:1,t:none,t:lowercase,pass,nolog,ctl:requestBodyProcessor=JSON"
SecRule REQBODY_ERROR "!@eq 0" "id:200002,phase:2,t:none,log,deny,status:400,msg:'Failed to parse request body'"
SecRule MULTIPART_STRICT_ERROR "!@eq 0" "id:200003,phase:2,t:none,log,deny,status:400,msg:'Multipart strict validation failed'"
SecRule MULTIPART_UNMATCHED_BOUNDARY "@eq 1" "id:200004,phase:2,t:none,log,deny,status:400,msg:'Multipart unmatched boundary'"
SecAction "id:900000,phase:1,pass,t:none,nolog,setvar:tx.blocking_paranoia_level={spec['paranoiaLevel']},setvar:tx.detection_paranoia_level={spec['paranoiaLevel']}"
SecAction "id:900110,phase:1,pass,t:none,nolog,setvar:tx.inbound_anomaly_score_threshold={spec['inboundAnomalyThreshold']},setvar:tx.outbound_anomaly_score_threshold={spec['outboundAnomalyThreshold']}"
SecAction "id:900990,phase:1,pass,t:none,nolog,setvar:tx.crs_setup_version=4300"
Include {rules}/*.conf
'''


class Upstream(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"
    records = []
    lock = threading.Lock()
    leak = b""

    def setup(self):
        super().setup()
        self.rfile = CountingInput(self.rfile, self.server)

    def log_message(self, *_):
        pass

    def do_GET(self):
        self.reply()

    def do_POST(self):
        self.reply()

    def reply(self):
        size = int(self.headers.get("Content-Length", "0"))
        with self.lock:
            record = {"path": self.path.split("?", 1)[0], "bodyBytes": 0}
            self.records.append(record)
        body = self.rfile.read(size)
        with self.lock:
            record["bodyBytes"] = len(body)
        response = self.leak if self.path.startswith("/response-leak") else b"upstream-ok"
        self.send_response(200)
        self.send_header("Content-Type", "Text/Plain" if self.path.startswith("/response-leak-mixed") else "text/plain")
        self.send_header("Content-Length", str(len(response)))
        self.end_headers()
        self.wfile.write(response)


class CountingInput:
    def __init__(self, stream, server):
        self.stream, self.server = stream, server

    def read(self, *args):
        value = self.stream.read(*args)
        with Upstream.lock:
            self.server.received_bytes += len(value)
        return value

    def readline(self, *args):
        value = self.stream.readline(*args)
        with Upstream.lock:
            self.server.received_bytes += len(value)
        return value

    def __getattr__(self, key):
        return getattr(self.stream, key)


class CountingServer(ThreadingHTTPServer):
    connections = 0
    received_bytes = 0

    def get_request(self):
        value = super().get_request()
        with Upstream.lock:
            self.connections += 1
        return value


def request(port, host, path="/normal", body=None, content_type=None, allow_closed=False):
    connection = http.client.HTTPConnection("127.0.0.1", port, timeout=10)
    headers = {"Host": host, "User-Agent": "AGP-native-corpus/1", "Accept": "text/plain"}
    if content_type:
        headers["Content-Type"] = content_type
    try:
        connection.request("POST" if body is not None else "GET", path, body, headers)
        try:
            result = connection.getresponse()
        except http.client.RemoteDisconnected:
            # This exception is raised only for EOF before any status-line
            # bytes. Partial headers or a partial body remain hard failures.
            if allow_closed:
                return 0, b""
            raise
        return result.status, result.read()
    finally:
        connection.close()


def main():
    global RENDERER
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--bundle", required=True)
    parser.add_argument("--evidence", required=True)
    parser.add_argument("--work", help="optional new private scratch directory; retained for failed-run diagnosis")
    parser.add_argument("--renderer", default=os.environ.get("AGP_TEST_WAF_RENDERER"),
                        help="agpctl executable; invoke its real waf-render for every policy and negative case")
    parser.add_argument("--reference-renderer", action="store_true",
                        help="explicit engine-only diagnostic using the Python reference; does not qualify the Go renderer")
    args = parser.parse_args()
    if os.geteuid() == 0:
        raise ValueError("native harness must not run as root")
    if bool(args.renderer) == bool(args.reference_renderer):
        raise ValueError("select --renderer/AGP_TEST_WAF_RENDERER or explicit --reference-renderer")
    RENDERER = Path(args.renderer).resolve() if args.renderer else None
    bundle = Path(args.bundle).resolve()
    evidence_path = Path(args.evidence).resolve()
    if evidence_path.exists():
        raise ValueError("refusing to overwrite existing evidence")
    path_value(bundle)
    checksums = json.loads((bundle / "checksums.json").read_text())
    for name, item in checksums.items():
        path = bundle / name
        if path.is_symlink() or not path.is_file() or path.resolve().is_relative_to(bundle) is False or path.stat().st_size != item["length"] or sha(path) != "sha256:" + item["sha256"]:
            raise ValueError("bundle checksum mismatch: " + name)
    build = json.loads((bundle / "build.json").read_text())
    expected_tuple = {"nginx": "1.30.8", "modsecurity": "3.0.17", "connector": "1.0.4", "crs": "4.30.0"}
    if build["platform"] != "ubuntu24.04amd64" or build["tuple"] != expected_tuple or build["userspace"]["versionId"] != "24.04":
        raise ValueError("unsupported native platform/tuple")
    corpus = json.loads((HERE / "corpus.json").read_text())
    started = now()
    results = []
    work = Path(args.work).resolve() if args.work else Path(tempfile.mkdtemp(prefix="agp-waf-native-"))
    if args.work:
        work.mkdir(mode=0o700, parents=True, exist_ok=False)
    os.chmod(work, 0o700)
    path_value(work)
    process = None
    upstream = None
    upstream_thread = None
    port_reservation = None
    error = None
    loader = bundle / "lib/ld-linux-x86-64.so.2"
    command = [str(loader), "--library-path", str(bundle / "lib"), str(bundle / "bin/nginx")]
    version = subprocess.check_output(command + ["-V"], stderr=subprocess.STDOUT, text=True, env=SAFE_ENV)
    library_version = subprocess.check_output([loader, "--version"], stderr=subprocess.STDOUT, text=True, env=SAFE_ENV).splitlines()[0]
    if "nginx/1.30.8" not in version or "2.39" not in library_version:
        raise ValueError("actual executable/loader version mismatch")

    def check(case_id, condition, **detail):
        passed = bool(condition)
        results.append({"id": case_id, "passed": passed, **detail})
        print(("PASS " if passed else "FAIL ") + case_id, flush=True)
        if not passed:
            raise ValueError("mandatory native case failed: " + case_id)

    def config(module=None, invalid=False):
        servers = []
        for name in ["blocking", "detection", "off", "threshold", "paranoia", "pl3", "pl4"]:
            servers.append(f'''server {{ listen 127.0.0.1:{port}; server_name {name}.test;
modsecurity on; modsecurity_rules_file {work}/{name}.conf;
location = /__ready {{ modsecurity off; return 200; }}
location / {{ proxy_pass http://127.0.0.1:{upstream.server_port}; proxy_request_buffering on; proxy_buffering on; }} }}''')
        return f'''load_module {module or bundle / 'modules/ngx_http_modsecurity_module.so'};
daemon off;
master_process off;
pid {work}/nginx.pid;
error_log {work}/error.log info;
events {{ worker_connections 64; }}
http {{ access_log off; client_max_body_size 128k;
client_body_temp_path {work}/body; proxy_temp_path {work}/proxy;
{' '.join(servers)}
{'unexpected_native_directive on;' if invalid else ''}
}}
'''

    try:
        Upstream.records, Upstream.leak = [], corpus["responseLeak"].encode()
        upstream = CountingServer(("127.0.0.1", 0), Upstream)
        upstream.daemon_threads = True
        upstream_thread = threading.Thread(target=upstream.serve_forever, daemon=True)
        upstream_thread.start()
        port_reservation = socket.socket()
        port_reservation.bind(("127.0.0.1", 0))
        port = port_reservation.getsockname()[1]
        for name in ["blocking", "detection", "off", "threshold", "paranoia", "pl3", "pl4"]:
            value = policy()
            if name == "threshold":
                value["spec"]["inboundAnomalyThreshold"] = 100
                value["spec"]["outboundAnomalyThreshold"] = 100
            if name == "paranoia":
                value["spec"]["paranoiaLevel"] = 2
            if name in ["pl3", "pl4"]:
                value["spec"]["paranoiaLevel"] = 3 if name == "pl3" else 4
                value["spec"]["inboundAnomalyThreshold"] = 3
            (work / (name + ".conf")).write_text(render_policy(value, name if name in ("detection", "off") else "blocking", bundle, work))
        for name in ["body", "proxy"]:
            (work / name).mkdir()
        nginx_conf = work / "nginx.conf"
        nginx_conf.write_text(config())
        validation = subprocess.run(command + ["-p", str(work) + "/", "-c", str(nginx_conf), "-t"], capture_output=True, text=True, timeout=30, env=SAFE_ENV)
        check("nginx_config_valid", validation.returncode == 0, exitCode=validation.returncode)
        (work / "invalid.conf").write_text(config(invalid=True))
        invalid = subprocess.run(command + ["-p", str(work) + "/", "-c", str(work / "invalid.conf"), "-t"], capture_output=True, text=True, timeout=30, env=SAFE_ENV)
        check("invalid_config_rejected", invalid.returncode != 0 and "unexpected_native_directive" in invalid.stderr, exitCode=invalid.returncode)
        module = (bundle / "modules/ngx_http_modsecurity_module.so").read_bytes()
        match = re.search(rb"8,4,8,[01]{20,}", module)
        if match is None:
            raise ValueError("cannot locate exact Nginx dynamic module ABI signature")
        mutated = bytearray(module)
        mutated[match.end() - 1] = ord("0") if mutated[match.end() - 1] == ord("1") else ord("1")
        (work / "wrong-abi.so").write_bytes(mutated)
        (work / "wrong-abi.conf").write_text(config(module=work / "wrong-abi.so"))
        mismatch = subprocess.run(command + ["-p", str(work) + "/", "-c", str(work / "wrong-abi.conf"), "-t"], capture_output=True, text=True, timeout=30, env=SAFE_ENV)
        check("wrong_module_abi", mismatch.returncode != 0 and "not binary compatible" in mismatch.stderr, exitCode=mismatch.returncode)
        injection = policy()
        injection["spec"]["rawDirectives"] = "SecRuleEngine Off\n"
        rejected = False
        try:
            render_policy(injection, "blocking", bundle, work)
        except ValueError:
            rejected = True
        check("raw_directive_rejected", rejected)
        expired = policy()
        expired["spec"]["exceptions"] = [{"id": "expired", "routeId": "native_route", "ruleIds": ["941100"],
            "match": {"field": "query_arg", "name": "q"}, "ownerId": "native_owner", "reason": "Expired corpus exception",
            "reviewAt": "2020-01-01T00:00:00Z", "expiresAt": "2020-02-01T00:00:00Z"}]
        rejected = False
        try:
            render_policy(expired, "blocking", bundle, work)
        except ValueError as exc:
            rejected = str(exc) == "expired exception" or str(exc).startswith("typed renderer rejected policy:")
        check("expired_exception_rejected", rejected)
        output = (work / "nginx-output.log").open("wb")
        port_reservation.close()
        port_reservation = None
        process = subprocess.Popen(command + ["-p", str(work) + "/", "-c", str(nginx_conf)], stdout=output, stderr=subprocess.STDOUT, env=SAFE_ENV)
        deadline = time.monotonic() + 15
        while True:
            if process.poll() is not None:
                raise ValueError("Nginx exited before serving native corpus")
            try:
                if request(port, "blocking.test", "/__ready")[0] == 200:
                    break
            except OSError:
                pass
            if time.monotonic() >= deadline:
                raise ValueError("Nginx did not become ready")
            time.sleep(0.05)

        blocked = []

        def exercise(case_id, host, expected_status, forwarded, path="/normal", body=None, content_type=None, need_rules=False):
            with Upstream.lock:
                before = len(Upstream.records)
                before_bytes = sum(item["bodyBytes"] for item in Upstream.records)
                before_connections = upstream.connections
                before_received = upstream.received_bytes
            log = work / "error.log"
            offset = log.stat().st_size if log.exists() else 0
            status, response = request(port, host, path, body, content_type, allow_closed=case_id == "response_body")
            if forwarded == 0:
                time.sleep(0.05)
            with Upstream.lock:
                after = len(Upstream.records)
                after_bytes = sum(item["bodyBytes"] for item in Upstream.records)
                connections = upstream.connections - before_connections
                received = upstream.received_bytes - before_received
            logged = log.read_text(errors="replace")[offset:] if log.exists() else ""
            rule_ids = sorted(set(re.findall(r'\[id "([0-9]+)"\]', logged)))
            allowed_status = expected_status if isinstance(expected_status, tuple) else (expected_status,)
            condition = status in allowed_status and after - before == forwarded and (not need_rules or any(len(x) == 6 and x.startswith("9") for x in rule_ids))
            if forwarded == 0:
                condition = condition and connections == 0 and received == 0
            if case_id == "response_body":
                condition = condition and "959100" in rule_ids and corpus["responseLeak"].encode() not in response
            if case_id == "request_body_limit":
                condition = condition and "Request body limit is marked to reject the request" in logged
            check(case_id, condition, status=status, upstreamRequests=after - before,
                  upstreamBodyBytes=after_bytes - before_bytes, matchedRuleIds=rule_ids,
                  upstreamConnections=connections, upstreamReceivedBytes=received,
                  transport="eof_before_status_line" if status == 0 else "http", clientResponseBodyBytes=len(response))
            if forwarded == 0:
                blocked.append({"id": case_id, "requests": after - before, "bodyBytes": after_bytes - before_bytes,
                                "connections": connections, "receivedBytes": received})
            return status

        attack = corpus["requestAttack"]
        query = "/search?q=" + urllib.parse.quote(attack, safe="")
        exercise("benign_allow", "blocking.test", 200, 1, "/normal?q=welcome")
        benign_boundary = "AGPBenignBoundary12345"
        benign_multipart = ("--" + benign_boundary + '\r\nContent-Disposition: form-data; name="q"\r\n\r\nwelcome\r\n--' + benign_boundary + "--\r\n").encode()
        for control, control_type in [(b"q=welcome", "application/x-www-form-urlencoded"),
                                       (b'{"q":"welcome"}', "application/json"),
                                       (benign_multipart, "multipart/form-data; boundary=" + benign_boundary)]:
            with Upstream.lock:
                before = len(Upstream.records)
            status, response = request(port, "blocking.test", "/benign-body", control, control_type)
            with Upstream.lock:
                forwarded = len(Upstream.records) - before
            if status != 200 or response != b"upstream-ok" or forwarded != 1:
                raise ValueError("benign structured request body control failed")
        exercise("detection_logs_attack", "detection.test", 200, 1, query, need_rules=True)
        exercise("blocking_query", "blocking.test", 403, 0, query, need_rules=True)
        encoded = urllib.parse.urlencode({"q": attack}).encode()
        exercise("blocking_urlencoded", "blocking.test", 403, 0, "/form", encoded, "application/x-www-form-urlencoded", True)
        exercise("blocking_json", "blocking.test", 403, 0, "/json", json.dumps({"q": attack}).encode(), "application/json", True)
        boundary = "AGPNativeBoundary12345"
        multipart = ("--" + boundary + '\r\nContent-Disposition: form-data; name="q"\r\n\r\n' + attack + "\r\n--" + boundary + "--\r\n").encode()
        exercise("blocking_multipart", "blocking.test", 403, 0, "/multipart", multipart, "multipart/form-data; boundary=" + boundary, True)
        exercise("blocking_sql_query", "blocking.test", 403, 0, "/search?q=" + urllib.parse.quote("1 OR 1=1 --", safe=""), need_rules=True)
        exercise("response_body", "blocking.test", (0, 403), 1, "/response-leak", need_rules=True)
        status, response = request(port, "blocking.test", "/response-leak-mixed", allow_closed=True)
        if status not in (0, 403) or corpus["responseLeak"].encode() in response:
            raise ValueError("mixed-case response Content-Type inspection failed")
        results[-1]["mixedCaseStatus"] = status
        results[-1]["mixedCaseTransport"] = "eof_before_status_line" if status == 0 else "http"
        exercise("off_mode", "off.test", 200, 1, query)
        # A neighbouring virtual Gateway has an independent effective mode. A
        # request blocked on one cannot alter or disable the neighbour's rules.
        exercise("neighbour_isolation", "detection.test", 200, 1, query, need_rules=True)
        exercise("threshold_effect", "threshold.test", 200, 1, query, need_rules=True)
        exercise("outbound_threshold_effect", "threshold.test", 200, 1, "/response-leak", need_rules=True)
        exercise("detection_response_body", "detection.test", 200, 1, "/response-leak", need_rules=True)
        pl_input = "/search?q=" + urllib.parse.quote(corpus["paranoiaInput"], safe="")
        status, _ = request(port, "blocking.test", pl_input)
        if status != 200:
            raise ValueError("PL1 control did not allow PL2 corpus input")
        exercise("paranoia_effect", "paranoia.test", 403, 0, pl_input, need_rules=True)
        for case_id, server, input_value, control_server in [
            ("paranoia_level_3", "pl3.test", "foo....", "paranoia.test"),
            ("paranoia_level_4", "pl4.test", "foo!bar@baz", "pl3.test"),
        ]:
            target = "/search?q=" + urllib.parse.quote(input_value, safe="")
            status, _ = request(port, control_server, target)
            if status != 200:
                raise ValueError("lower-paranoia control unexpectedly blocked " + case_id)
            exercise(case_id, server, 403, 0, target, need_rules=True)
        exercise("malformed_json_rejected", "blocking.test", 400, 0, "/json", b'{"q":', "application/json")
        limit_control = b"q=" + b"a" * 64000
        with Upstream.lock:
            control_before = len(Upstream.records)
        status, response = request(port, "blocking.test", "/large-control", limit_control, "application/x-www-form-urlencoded")
        with Upstream.lock:
            control_forwarded = len(Upstream.records) - control_before
        if status != 200 or response != b"upstream-ok" or control_forwarded != 1:
            raise ValueError("request body limit lower-bound control failed")
        # The pinned connector returns 403 for the native reject action. Require
        # the actual body-limit diagnostic in addition to zero upstream bytes.
        exercise("request_body_limit", "blocking.test", 403, 0, "/large", b"q=" + b"a" * 70000, "application/x-www-form-urlencoded")
        results[-1]["allowedControlBodyBytes"] = len(limit_control)
        results[-1]["nativeBodyLimitRejected"] = True
        check("upstream_not_reached", len(blocked) >= 8 and all(item["requests"] == 0 and item["connections"] == 0 for item in blocked), cases=len(blocked))
        check("body_bytes_not_forwarded", all(item["bodyBytes"] == 0 and item["receivedBytes"] == 0 for item in blocked), cases=len(blocked))
        if {item["id"] for item in results} != set(corpus["cases"]):
            raise ValueError("corpus and executed mandatory cases differ")
    except Exception as exc:
        error = str(exc)
    finally:
        if port_reservation is not None:
            port_reservation.close()
        if process is not None:
            process.terminate()
            try:
                process.wait(timeout=10)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait(timeout=5)
        if upstream is not None:
            upstream.shutdown()
            upstream.server_close()
            upstream_thread.join(timeout=5)
        completed = now()
        report = {"format": "agp.waf-native-evidence/v1", "publicationAuthority": False,
                  "platform": {"os": "ubuntu", "osVersion": "24.04", "arch": "amd64"},
                  "tuple": expected_tuple, "userspace": build["userspace"],
                  "hostKernel": platform.release(), "hostOsRelease": Path("/etc/os-release").read_text(),
                  "runtime": "Ubuntu24 loader and complete flat ELF library closure on shared host kernel",
                  "startedAt": started, "completedAt": completed, "checks": results,
                  "passed": error is None and len(results) == len(corpus["cases"]), "error": error,
                  "harnessDigest": sha(Path(__file__)), "corpusDigest": sha(HERE / "corpus.json"),
                  "buildDigest": sha(bundle / "build.json"), "checksumsDigest": sha(bundle / "checksums.json"),
                  "nginxVersionOutput": version, "loaderVersion": library_version,
                  "policyRenderer": {"implementation": "agpctl-waf-render" if RENDERER else "harness-reference",
                                     "digest": sha(RENDERER) if RENDERER else sha(Path(__file__))},
                  "artifactChecksums": {name: checksums[name] for name in sorted(checksums)
                                        if name.startswith(("bin/", "modules/", "lib/", "share/crs/", "share/modsecurity/"))}}
        evidence_path.parent.mkdir(parents=True, exist_ok=True)
        evidence_path.write_text(json.dumps(report, indent=2) + "\n")
        if not args.work and error is None:
            shutil.rmtree(work)
    if error is not None:
        raise ValueError(error + "; native scratch retained: " + str(work))
    print("NATIVE WAF PASS (" + str(len(corpus["cases"])) + " mandatory cases, zero SKIP); unsigned evidence: " + str(evidence_path))


if __name__ == "__main__":
    try:
        main()
    except (ValueError, OSError, subprocess.CalledProcessError) as exc:
        print("native WAF qualification failed: " + str(exc), file=sys.stderr)
        sys.exit(1)
