#!/usr/bin/env python3
"""Opt-in remote C320 two-command SSH read candidate; no physical L1 cable.
No OLT password, telnet, firmware action or unsupported TR-069 assumption.
Actual read requires independently pinned SSH key + private route + operator.
"""
import argparse
import ipaddress
import json
import os
from pathlib import Path
import re
import stat
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[4]
COMMANDS = (("show card", "cards.txt", "Rack Shelf Slot"),
            ("show version-running", "versions.txt", "PhyLoc FileType VerType"))
GATES = ("owner_approves_readonly", "dedicated_readonly_account",
         "host_key_independently_verified", "private_route_verified",
         "firmware_supports_noninteractive_exec", "capture_storage_encrypted")
FIELDS = set(GATES) | {"target_id", "environment", "transport", "profile",
                       "private_ipv4", "ssh_port", "ssh_user"}
RFC1918 = tuple(map(ipaddress.ip_network,
    ("10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16")))
class Denied(ValueError): pass

def unique(pairs):
    result = {}
    for name, value in pairs:
        if name in result: raise Denied("duplicate JSON field")
        result[name] = value
    return result

def owner_dir(p, empty=False):
    if not p.is_absolute() or any(c in (".", "..") for c in p.parts):
        raise Denied("private directory requires absolute canonical path")
    real = p.resolve(strict=True)
    if p == ROOT or ROOT in p.parents or real == ROOT or ROOT in real.parents:
        raise Denied("private directory must not be in Git")
    m = p.lstat()
    if not stat.S_ISDIR(m.st_mode) or m.st_uid != os.getuid() or (
        stat.S_IMODE(m.st_mode) != 0o700):
        raise Denied("owner 0700 folder required")
    if empty and any(p.iterdir()): raise Denied("output must start empty")
    return p

def owner_read(p, limit=8192):
    m = p.lstat()
    if not stat.S_ISREG(m.st_mode) or m.st_uid != os.getuid() or (
        m.st_nlink != 1 or stat.S_IMODE(m.st_mode) != 0o600
        or not 0 < m.st_size <= limit):
        raise Denied("owner 0600 single-link regular file required")
    fd = os.open(p, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
    with os.fdopen(fd, "rb") as f:
        after = os.fstat(f.fileno())
        if (m.st_dev, m.st_ino) != (after.st_dev, after.st_ino):
            raise Denied("private file changed during opening")
        raw = f.read(limit + 1)
    if len(raw) > limit: raise Denied("private file too large")
    return raw

def validate(plan):
    if type(plan) is not dict or set(plan) != FIELDS:
        raise Denied("unexpected plan fields")
    for key, value in {
        "target_id": "DEV-01", "environment": "isolated_lab",
        "profile": "zte-c320-exact-two-readonly-show-candidate",
    }.items():
        if type(plan[key]) is not str or plan[key] != value:
            raise Denied("unapproved device or protocol")
    if plan["transport"] not in (
        "ssh-strict-pinned-publickey",
        "ssh-strict-pinned-publickey-legacy-rsa-cbc",
        "ssh-strict-pinned-publickey-legacy-rsa-cbc-group14-sha256",
    ):
        raise Denied("unsupported SSH transport profile")
    ip = ipaddress.IPv4Address(plan["private_ipv4"])
    if not any(ip in cidr for cidr in RFC1918):
        raise Denied("private tunnel or RFC1918 management address required")
    if type(plan["ssh_port"]) is not int or not 1 <= plan["ssh_port"] <= 65535:
        raise Denied("bad port")
    if type(plan["ssh_user"]) is not str or not re.fullmatch(
        r"[a-z_][a-z0-9_-]{0,31}", plan["ssh_user"]):
        raise Denied("bad read-only user")
    if plan["ssh_user"] in {"zte", "root", "admin", "administrator"}:
        raise Denied("factory or privileged user forbidden for live-read mode")
    if any(type(plan[k]) is not bool for k in GATES):
        raise Denied("explicit boolean declarations needed")
    return [k for k in GATES if plan[k] is not True]

def packet(folder):
    owner_dir(folder)
    if {p.name for p in folder.iterdir()} != {
        "plan.json", "known_hosts", "id_readonly"}:
        raise Denied("exactly three private operator files needed")
    plan = json.loads(owner_read(folder / "plan.json"), object_pairs_hook=unique)
    missing = validate(plan)
    host = plan["private_ipv4"] if plan["ssh_port"] == 22 else (
        f"[{plan['private_ipv4']}]:{plan['ssh_port']}")
    pins = owner_read(folder / "known_hosts").decode("ascii").splitlines()
    actual = [line for line in pins if line and not line.startswith("#")]
    if not actual: raise Denied("missing independent host key pin")
    for line in actual:
        items = line.split()
        if len(items) != 3 or items[0] != host or items[1] not in (
            "ssh-ed25519", "ssh-rsa", "ecdsa-sha2-nistp256"):
            raise Denied("unexpected pin or host alias")
        if not re.fullmatch("[A-Za-z0-9+/]+={0,2}", items[2]):
            raise Denied("invalid pinned key")
    if plan["transport"] in (
        "ssh-strict-pinned-publickey-legacy-rsa-cbc",
        "ssh-strict-pinned-publickey-legacy-rsa-cbc-group14-sha256",
    ):
        # The device key MUST be independently pinned; a network banner
        # or ssh-keyscan result alone cannot satisfy this policy.
        if any(line.split()[1] != "ssh-rsa" for line in actual):
            raise Denied("legacy profile requires exact pinned RSA host key")
    owner_read(folder / "id_readonly", limit=16384)
    return plan, missing

def command_argv(folder, plan, command):
    if plan["transport"] not in (
        "ssh-strict-pinned-publickey",
        "ssh-strict-pinned-publickey-legacy-rsa-cbc",
        "ssh-strict-pinned-publickey-legacy-rsa-cbc-group14-sha256",
    ):
        raise Denied("unsupported SSH mode")
    if command not in {item[0] for item in COMMANDS}:
        raise Denied("only two fixed read-only commands permitted")
    legacy = plan["transport"] in (
        "ssh-strict-pinned-publickey-legacy-rsa-cbc",
        "ssh-strict-pinned-publickey-legacy-rsa-cbc-group14-sha256",
    )
    # Only the exact DEV-01 firmware candidate demonstrated an actual
    # credentials-free group14-sha256/RSA/aes128-cbc handshake. Process-
    # scoped compatibility MUST NOT relax global client SSH policy.
    group14 = plan["transport"] == (
        "ssh-strict-pinned-publickey-legacy-rsa-cbc-group14-sha256"
    )
    compat = (["-o", "HostKeyAlgorithms=ssh-rsa",
               "-o", "Ciphers=aes128-cbc"] if legacy else [])
    if group14:
        compat += ["-o", "KexAlgorithms=diffie-hellman-group14-sha256"]
    return ["ssh", "-F", "/dev/null", "-T", "-n", *compat,
        "-o", "BatchMode=yes", "-o", "IdentitiesOnly=yes",
        "-o", "IdentityAgent=none", "-o", "PasswordAuthentication=no",
        "-o", "KbdInteractiveAuthentication=no",
        "-o", "PreferredAuthentications=publickey",
        "-o", "StrictHostKeyChecking=yes",
        "-o", "GlobalKnownHostsFile=/dev/null",
        "-o", "UserKnownHostsFile=" + str(folder / "known_hosts"),
        "-o", "ProxyCommand=none", "-o", "ProxyJump=none",
        "-o", "CanonicalizeHostname=no", "-o", "ClearAllForwardings=yes",
        "-o", "ControlMaster=no", "-o", "ConnectionAttempts=1",
        "-o", "ConnectTimeout=5", "-o", "ServerAliveInterval=3",
        "-o", "ServerAliveCountMax=1",
        "-i", str(folder / "id_readonly"), "-p", str(plan["ssh_port"]),
        plan["ssh_user"] + "@" + plan["private_ipv4"], command]

def collect(folder, output, plan, first_read_only=False):
    if os.getenv("IPAT_R79_OPERATOR_APPROVES_REMOTE_READ") != "YES":
        raise Denied("separate execution approval absent")
    owner_dir(output, empty=True)
    staged = []
    approved_commands = COMMANDS[:1] if first_read_only else COMMANDS
    try:
        for command, filename, heading in approved_commands:
            result = subprocess.run(command_argv(folder, plan, command),
                capture_output=True, timeout=12, check=False)
            data = result.stdout
            if result.returncode or not 0 < len(data) <= 32768:
                raise Denied("remote command failed or oversized result")
            if any(b in data for b in (b"\x00", b"\x1b")):
                raise Denied("unsafe output control characters")
            if heading not in data.decode("utf-8").replace("\r", ""):
                raise Denied("firmware output requires separate review")
            staged.append((filename, data))
        for filename, data in staged:
            fd = os.open(output / filename,
                os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
            with os.fdopen(fd, "wb") as stream:
                stream.write(data)
                stream.flush()
                os.fsync(stream.fileno())
    except Exception:
        for filename, _ in staged:
            (output / filename).unlink(missing_ok=True)
        raise
    return {"result": "PRIVATE_RAW_CAPTURE_NEEDS_REDACTION_AND_REVIEW",
            "commands": len(approved_commands), "compatibility_verified": False,
            "tenant_enrolled": False, "firmware_enabled": False}

def main():
    parser = argparse.ArgumentParser(description=__doc__)
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("--requirements", action="store_true")
    group.add_argument("--check-plan", type=Path)
    group.add_argument("--collect", type=Path)
    group.add_argument("--first-read", type=Path)
    parser.add_argument("--out", type=Path)
    args = parser.parse_args()
    if args.requirements:
        print("R79=PRIVATE_SSH_READONLY_C320_FIRST_READ_ONE_OR_REVIEWED_TWO_SHOW_COMMANDS")
        print("NO_NETWORK_WITHOUT_EXPLICIT_OPTIN_NO_WRITES_NO_FIRMWARE")
        return 0
    if bool(args.collect or args.first_read) != bool(args.out):
        print("R79_DENIED:collect requires --out", file=sys.stderr)
        return 4
    try:
        folder = args.collect or args.first_read or args.check_plan
        plan, missing = packet(folder)
        if args.check_plan:
            print(json.dumps({"status": "BLOCKED" if missing else "HUMAN_REVIEW_REQUIRED",
                "missing_prerequisites": missing, "network_performed": False,
                "physical_interop_verified": False, "firmware_enabled": False},
                sort_keys=True))
            return 4 if missing else 0
        if missing: raise Denied("declared remote-read prerequisites incomplete")
        print(json.dumps(collect(folder,args.out,plan,first_read_only=bool(args.first_read)),sort_keys=True))
        return 0
    except (Denied, OSError, UnicodeError, ValueError, subprocess.TimeoutExpired):
        print("R79_DENIED:remote C320 plan or firmware needs review",
              file=sys.stderr)
        return 4

if __name__ == "__main__": sys.exit(main())
