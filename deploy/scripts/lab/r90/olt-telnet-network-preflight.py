#!/usr/bin/env python3
"""Exact operator-approved ZTE candidate transport preflight, NO LOGIN.
One TCP connect, a bounded passive receive, no transmitted application bytes.
This does not verify device identity, health, firmware or adopt any hardware.
"""
import argparse
from datetime import datetime, timezone
import ipaddress
import json
import os
from pathlib import Path
import socket
import stat
import sys

ROOT = Path(__file__).resolve().parents[4]
OPT_IN = "IPAT_R90_APPROVE_SINGLE_NOAUTH_TELNET_PREFLIGHT"

def probe(host, port, source, *, timeout=5, connector=socket.create_connection):
    """Exactly one TCP connect, at most 512 inbound bytes, ZERO client writes."""
    result = dict(target_slot="DEV-01", evidence_type="passive_transport_only",
                  source_label=source, credential_bytes_sent=0,
                  host_identity_verified=False, device_adopted=False,
                  physical_read_test="NOT_RUN", connectivity="UNKNOWN",
                  health="NOT_MEASURED", safe_for_credentials=False)
    try:
        with connector((host, port), timeout=timeout) as connection:
            connection.settimeout(min(timeout, 2))
            try:
                sample = connection.recv(512)
            except socket.timeout:
                sample = b""
        result.update(tcp_reachable=True, telnet_iac_observed=sample.startswith(b"\xff"),
                      bytes_received=len(sample))
    except OSError as exc:
        kind = ("TIMEOUT" if isinstance(exc, (TimeoutError, socket.timeout))
                else "REFUSED" if isinstance(exc, ConnectionRefusedError)
                else "NETWORK_ERROR")
        result.update(tcp_reachable=False, failure_class=kind)
    return result

def store_redacted(folder, record):
    if not folder.is_absolute() or any(p in (".", "..") for p in folder.parts):
        raise ValueError("absolute owner directory required")
    actual = folder.resolve(strict=True)
    if folder == ROOT or ROOT in folder.parents or actual == ROOT or ROOT in actual.parents:
        raise ValueError("cannot write inside Git")
    metadata = folder.lstat()
    if not stat.S_ISDIR(metadata.st_mode) or metadata.st_uid != os.getuid() or (
        stat.S_IMODE(metadata.st_mode) != 0o700):
        raise ValueError("only owner-controlled 0700 directory")
    filename = "dev01-noauth-link-" + datetime.now(timezone.utc).strftime(
        "%Y%m%dT%H%M%S%fZ") + ".json"
    target = folder / filename
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0)
    with os.fdopen(os.open(target, flags, 0o600), "w", encoding="ascii") as stream:
        json.dump(record, stream, sort_keys=True)
        stream.write("\n")
        stream.flush()
        os.fsync(stream.fileno())
    return target

def main():
    parser = argparse.ArgumentParser(description=__doc__)
    mode = parser.add_mutually_exclusive_group(required=True)
    mode.add_argument("--requirements", action="store_true")
    mode.add_argument("--preflight", action="store_true")
    parser.add_argument("--target-ipv4")
    parser.add_argument("--port", type=int, default=321)
    parser.add_argument("--source-label", choices=("owner-mac", "ipat-vps"),
                        default="owner-mac")
    parser.add_argument("--report-dir", type=Path)
    options = parser.parse_args()
    if options.requirements:
        print(json.dumps({"mode": "single_noauth_tcp321_receive_only",
                          "operator_opt_in": OPT_IN, "real_olt_read": "NOT_RUN",
                          "safe_for_credentials": False}, sort_keys=True))
        return 0
    if os.geteuid() == 0 or os.environ.get(OPT_IN) != "YES":
        parser.error("owner nonroot explicit no-auth approval required")
    try:
        address = ipaddress.IPv4Address(options.target_ipv4 or "")
    except ipaddress.AddressValueError:
        parser.error("explicit numeric IPv4 required; no DNS, ranges or scans")
    if not address.is_global or options.port != 321:
        parser.error("exact user-approved public IPv4 and TCP321 only")
    output = probe(str(address), options.port, options.source_label)
    # Do not print address, terminal banner, credentials, serial or device IDs.
    output["observed_at_utc"] = datetime.now(timezone.utc).isoformat(
        timespec="seconds")
    if options.report_dir is not None:
        try:
            store_redacted(options.report_dir, output)
        except (OSError, ValueError):
            parser.error("owner-only encrypted evidence directory is invalid")
    print(json.dumps(output, sort_keys=True))
    return 0 if output["tcp_reachable"] else 3

if __name__ == "__main__":
    sys.exit(main())
