#!/usr/bin/env python3
"""Mr. iPat R6.1: explicit-owner-gated, SINGLE-device, GET-only RouterOS HTTPS probe.

No automatic discovery, config writes, raw device payload logging or enrollment.
Defaults to offline preflight. Real traffic only after separately enabled on Mac.
"""
import argparse
import base64
from datetime import datetime, timezone
import http.client
import ipaddress
import json
import netrc
import os
from pathlib import Path
import re
import socket
import ssl
import stat
import sys

ROOT = Path(__file__).resolve().parents[4]
CONFIG_KEYS = {
    "target_id", "expected_model", "expected_routeros", "management_ipv4",
    "tls_name", "ca_cert_path", "netrc_path", "owner_permission",
    "isolated_lab_route_confirmed",
}
LAB_PRIVATE = tuple(ipaddress.ip_network(v) for v in
                    ("10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16"))
TLS_DNS = re.compile(r"^(?=.{1,200}$)[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?"
                     r"(?:\.[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)*$")
SAFE_NAME = re.compile(r"^[A-Za-z0-9._ /()+-]{1,80}$")

class Rejected(ValueError):
    pass

def unique(pairs):
    out = {}
    for key, val in pairs:
        if key in out:
            raise Rejected("duplicate fields")
        out[key] = val
    return out

def protected_file(path_text, name, must_0600=True):
    if not isinstance(path_text, str):
        raise Rejected("path type")
    p = Path(path_text).expanduser()
    if not p.is_absolute() or p.is_symlink() or not p.is_file():
        raise Rejected("private file missing")
    p = p.resolve(strict=True)
    if p == ROOT or ROOT in p.parents:
        raise Rejected("private file cannot be in Git repository")
    if must_0600 and stat.S_IMODE(p.stat().st_mode) != 0o600:
        raise Rejected(name + " must have exactly 0600 permissions")
    if p.stat().st_size > (8192 if name == "CA" else 2048):
        raise Rejected(name + " exceeds limits")
    return p

def validated(config_path):
    cfg = protected_file(config_path, "config")
    try:
        data = json.loads(cfg.read_text(encoding="utf-8"), object_pairs_hook=unique)
    except (UnicodeError, json.JSONDecodeError) as exc:
        raise Rejected("invalid config") from exc
    if not isinstance(data, dict) or set(data) != CONFIG_KEYS:
        raise Rejected("unexpected config fields")
    if (data["target_id"] != "DEV-08" or
            data["expected_model"] != "RB951Ui-2HnD" or
            data["expected_routeros"] != "7.23.7"):
        raise Rejected("review this exact model and firmware separately")
    if data["owner_permission"] != "confirmed_by_operator":
        raise Rejected("explicit owner's consent missing")
    if data["isolated_lab_route_confirmed"] is not True:
        raise Rejected("isolated lab route not confirmed")
    ip = ipaddress.ip_address(data["management_ipv4"])
    if not isinstance(ip, ipaddress.IPv4Address) or not any(
            ip in subnet for subnet in LAB_PRIVATE):
        raise Rejected("management address must be explicitly selected RFC1918 IPv4")
    dns = data["tls_name"]
    if not isinstance(dns, str) or TLS_DNS.fullmatch(dns) is None or "." not in dns:
        raise Rejected("independent TLS DNS name required")
    ca = protected_file(data["ca_cert_path"], "CA", must_0600=False)
    nfile = protected_file(data["netrc_path"], "netrc")
    # Config must contain no inline credentials; never include in diagnostics.
    try:
        auth = netrc.netrc(str(nfile)).authenticators(dns)
    except (OSError, netrc.NetrcParseError) as exc:
        raise Rejected("netrc malformed") from exc
    if not auth or not auth[0] or not auth[2]:
        raise Rejected("dedicated restricted lab credentials missing")
    if any("\r" in part or "\n" in part for part in (auth[0], auth[2])):
        raise Rejected("untrusted credential characters")
    return data, ca, (auth[0], auth[2])

def approved_routeros_version(observed, expected):
    # RouterOS REST may include a release channel suffix. This whitelist does
    # NOT authorize a different build or imply that a real device was read.
    return observed in (expected, expected + " (stable)",
                        expected + " (long-term)")

def sanitize_resource(payload, expected_model, expected_version):
    if isinstance(payload, list):
        if len(payload) != 1:
            raise Rejected("unexpected resource cardinality")
        payload = payload[0]
    if not isinstance(payload, dict):
        raise Rejected("unexpected resource shape")
    names = ("board-name", "architecture-name", "version")
    if not all(isinstance(payload.get(k), str)
               and SAFE_NAME.fullmatch(payload[k]) for k in names):
        raise Rejected("invalid returned platform metadata")
    if (payload["board-name"] != expected_model or
            payload["architecture-name"] != "mipsbe" or
            not approved_routeros_version(payload["version"], expected_version)):
        raise Rejected("observed identity or firmware mismatch")
    # Explicit allowlist. Drop even if response includes serials, IPs, routes,
    # PPPoE secrets or any other sensitive fields.
    return {
        "target_id": "DEV-08", "model": payload["board-name"],
        "architecture": payload["architecture-name"],
        "routeros": payload["version"],
        "test_scope": "one_authenticated_read_only_rest_get",
        "method": "GET", "resource": "/rest/system/resource",
        "read_observed": True, "operator_review_complete": False,
        "physical_device_enrolled": False, "tenant_binding_verified": False,
        "compatibility_verified": False, "configuration_modified": False,
        "hardware_revision": "NOT_OBSERVED",
        "observed_at_utc": datetime.now(timezone.utc).isoformat(),
    }

class FixedPrivateTLS(http.client.HTTPSConnection):
    def __init__(self, ip, dns, ctx):
        super().__init__(host=dns, port=443, timeout=5, context=ctx)
        self._private_ip = str(ip)
        self._expected_dns = dns

    def connect(self):
        # No DNS resolution, proxy, redirects or arbitrary user-chosen URL.
        sock = socket.create_connection((self._private_ip, 443), timeout=5)
        self.sock = self._context.wrap_socket(sock, server_hostname=self._expected_dns)

def read_one(config, ca, auth, connection_factory=FixedPrivateTLS):
    context = ssl.create_default_context(cafile=str(ca))
    context.minimum_version = ssl.TLSVersion.TLSv1_2
    token = base64.b64encode(f"{auth[0]}:{auth[1]}".encode()).decode()
    conn = connection_factory(config["management_ipv4"], config["tls_name"], context)
    try:
        conn.request("GET", "/rest/system/resource",
                     headers={"Accept": "application/json",
                              "Authorization": "Basic " + token})
        response = conn.getresponse()
        if response.status != 200:
            raise Rejected("device rejected read-only GET")
        if int(response.getheader("Content-Length", "0")) > 32768:
            raise Rejected("oversized response")
        body = response.read(32769)
        if len(body) > 32768:
            raise Rejected("response exceeds limit")
        try:
            obj = json.loads(body, object_pairs_hook=unique)
        except (ValueError, UnicodeDecodeError) as exc:
            raise Rejected("invalid JSON response") from exc
        return sanitize_resource(obj, config["expected_model"],
                                 config["expected_routeros"])
    finally:
        conn.close()

def validate_output_path(path_text):
    if not isinstance(path_text, str):
        raise Rejected("missing output path")
    path = Path(path_text).expanduser()
    if not path.is_absolute() or path.exists() or path.is_symlink():
        raise Rejected("output must be a new private file")
    path = path.resolve(strict=False)
    if ROOT in path.parents:
        raise Rejected("output cannot enter Git")
    if not path.parent.is_dir() or stat.S_IMODE(path.parent.stat().st_mode) != 0o700:
        raise Rejected("private output directory must be mode 0700")
    return path

def private_output(path_text, result):
    # Revalidate even after pre-read validation to avoid stale destination.
    path = validate_output_path(path_text)
    flags = os.O_CREAT | os.O_EXCL | os.O_WRONLY | getattr(os, "O_NOFOLLOW", 0)
    fd = os.open(path, flags, 0o600)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as out:
            json.dump(result, out, sort_keys=True)
            out.write("\n")
            out.flush()
            os.fsync(out.fileno())
    except BaseException:
        path.unlink(missing_ok=True)
        raise

def main():
    parser = argparse.ArgumentParser(description="Single DEV-08 strictly private RouterOS read")
    parser.add_argument("--config", required=True)
    actions = parser.add_mutually_exclusive_group(required=True)
    actions.add_argument("--preflight", action="store_true")
    actions.add_argument("--read", action="store_true")
    parser.add_argument("--output")
    args = parser.parse_args()
    try:
        config, ca, auth = validated(args.config)
        # Never perform traffic by default, even with a valid config.
        if args.preflight:
            if args.output:
                raise Rejected("preflight cannot write evidence")
            print("R61_OFFLINE_PREFLIGHT=PASS; REAL_CONNECTION=NOT_ATTEMPTED")
            return 0
        if (sys.platform != "darwin" or os.environ.get("IPAT_R61_REAL_READ") != "YES"
                or os.environ.get("IPAT_R61_OWNER_CONFIRMS_SINGLE_GET") != "YES"
                or not args.output):
            raise Rejected("real probe requires two explicit Mac-local approvals")
        # Reject unsafe evidence destinations BEFORE any authorized network I/O.
        approved_output = validate_output_path(args.output)
        result = read_one(config, ca, auth)
        private_output(str(approved_output), result)
        print("R61_SINGLE_DEVICE_READ_EVIDENCE_STAGED=YES;"
              " REVIEW_REQUIRED=YES; ENROLLED=NO; COMPATIBILITY=UNVERIFIED")
        return 0
    except (Rejected, OSError, ssl.SSLError, http.client.HTTPException,
            TimeoutError, ValueError) as exc:
        # No URL, endpoint IP, raw payload, user or credential in logs.
        print("R61_PROBE_DENIED: " + type(exc).__name__, file=sys.stderr)
        return 4

if __name__ == "__main__":
    raise SystemExit(main())
