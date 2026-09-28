#!/usr/bin/env python3
"""Mr. iPat IPAT R6.3: SINGLE SSH host key preflight; NEVER authenticates.

A changed SSH host key is a STOP condition until the owner independently
verifies the device from a different trusted path (e.g. direct local LAN).
This script NEVER inserts, deletes or ignores existing known_hosts entries.
"""
import argparse
import ipaddress
import os
from pathlib import Path
import re
import stat
import subprocess
import sys

SOURCE_ROOT = Path(__file__).resolve().parents[4]
FP = re.compile(r"^SHA256:[A-Za-z0-9+/]{43}$")
FP_FIND = re.compile(r"SHA256:[A-Za-z0-9+/]{43}")

class Rejected(ValueError):
    pass

def single_fingerprint(text):
    matches = set(FP_FIND.findall(text))
    if len(matches) != 1:
        raise Rejected("zero or ambiguous RSA SSH fingerprints")
    result = matches.pop()
    if not FP.fullmatch(result):
        raise Rejected("invalid SSH fingerprint")
    return result

def explicit_public_ipv4(address, port):
    try:
        ip = ipaddress.IPv4Address(address)
    except ipaddress.AddressValueError as exc:
        raise Rejected("only a single literal IPv4 address") from exc
    if not ip.is_global or ip.is_multicast or ip.is_unspecified:
        raise Rejected("requires explicit single globally routable target")
    if not isinstance(port, int) or not 1 <= port <= 65535:
        raise Rejected("invalid single target port")
    return str(ip)

def run_command(args, stdin=None):
    try:
        result = subprocess.run(
            args, input=stdin, stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL, timeout=8, check=False,
        )
    except (subprocess.TimeoutExpired, OSError) as exc:
        raise Rejected("read-only host key retrieval failed") from exc
    if result.returncode != 0 or len(result.stdout) > 65_536:
        raise Rejected("host key query failed or returned too much data")
    return result.stdout.decode("ascii", "replace")

def observed_rsa_fingerprint(address, port):
    scan = run_command([
        "ssh-keyscan", "-T", "5", "-p", str(port), "-t", "rsa", address,
    ])
    allowed = f"[{address}]:{port} ssh-rsa "
    keys = {row for row in scan.splitlines() if row.startswith(allowed)}
    if len(keys) != 1:
        raise Rejected("server key unavailable or ambiguous")
    return single_fingerprint(
        run_command(["ssh-keygen", "-lf", "-", "-E", "sha256"],
                    stdin=(keys.pop() + "\n").encode("ascii"))
    )

def historical_rsa_fingerprint(address, port):
    try:
        output = run_command([
            "ssh-keygen", "-F", f"[{address}]:{port}",
            "-l", "-E", "sha256",
        ])
    except Rejected:
        return None
    rsa_lines = [row for row in output.splitlines() if " RSA " in row]
    if not rsa_lines:
        return None
    return single_fingerprint("\n".join(rsa_lines))

def independently_verified_private_fingerprint(file_name):
    candidate = Path(file_name).expanduser()
    if not candidate.is_absolute() or candidate.is_symlink():
        raise Rejected("independent owner-controlled fingerprint file required")
    source = candidate.resolve(strict=True)
    if source == SOURCE_ROOT or SOURCE_ROOT in source.parents:
        raise Rejected("trust proof must never be in source repository")
    stat_file = source.stat()
    stat_parent = source.parent.stat()
    if (not source.is_file()
        or stat_file.st_uid != os.getuid()
        or stat_parent.st_uid != os.getuid()
        or stat.S_IMODE(stat_file.st_mode) != 0o600
        or stat.S_IMODE(stat_parent.st_mode) != 0o700
        or stat_file.st_size > 100):
        raise Rejected("independent fingerprint proof permissions invalid")
    text = source.read_text(encoding="ascii").strip()
    if not FP.fullmatch(text):
        raise Rejected("independent fingerprint proof invalid")
    return text

def assess(current, historical, independently_verified=None):
    if historical and current == historical:
        if independently_verified is not None and independently_verified != current:
            return "INDEPENDENT_FINGERPRINT_CONFLICT", False
        return "HISTORICAL_HOST_KEY_MATCH", True
    if independently_verified is None:
        return ("HOST_KEY_CHANGED_UNVERIFIED" if historical
                else "NO_HISTORICAL_HOST_KEY"), False
    if independently_verified != current:
        return "INDEPENDENT_FINGERPRINT_MISMATCH", False
    return "INDEPENDENT_MATCH_REPIN_SEPARATELY", True

def main():
    parser = argparse.ArgumentParser(
        description="Read-only single-host SSH RSA key verification (NO LOGIN)"
    )
    parser.add_argument("--target-ipv4", required=True)
    parser.add_argument("--port", required=True, type=int)
    parser.add_argument("--independent-fingerprint-file")
    args = parser.parse_args()
    try:
        address = explicit_public_ipv4(args.target_ipv4, args.port)
        trusted = None
        if args.independent_fingerprint_file:
            if os.environ.get("IPAT_R63_VERIFIED_FROM_TRUSTED_LAN") != "YES":
                raise Rejected("missing independent device identity confirmation")
            trusted = independently_verified_private_fingerprint(
                args.independent_fingerprint_file)
        current = observed_rsa_fingerprint(address, args.port)
        historical = historical_rsa_fingerprint(address, args.port)
        label, approved = assess(current, historical, trusted)
        print("CURRENT_UNVERIFIED_RSA_FINGERPRINT=" + current)
        print("SAVED_PREVIOUS_RSA_FINGERPRINT=" + (historical or "NONE"))
        print("SSH_HOST_IDENTITY_GATE=" + label)
        print("PASSWORD_SENT=NO; ROUTER_COMMANDS_RUN=NO; KNOWN_HOSTS_MODIFIED=NO")
        if approved:
            print("This is HOST KEY comparison only; no account authentication.")
            return 0
        return 4
    except (Rejected, OSError, UnicodeError) as exc:
        print("R63_SSH_HOST_IDENTITY_GATE=DENIED:" + type(exc).__name__,
              file=sys.stderr)
        return 4

if __name__ == "__main__":
    raise SystemExit(main())
