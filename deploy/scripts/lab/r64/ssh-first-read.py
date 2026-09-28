#!/usr/bin/env python3
"""IPAT R6.4 single DEV-08 SSH read, OFF by default; password auth forbidden.

May attempt one real SSH read ONLY after separate independent trusted-LAN
fingerprint proof, approved recovery/scope, a DEDICATED restricted SSH key,
and multiple explicit local opt-ins. Never changes router or known_hosts.
"""
import argparse
import importlib.util
from datetime import datetime, timezone
import ipaddress
import json
import os
from pathlib import Path
import re
import resource
import stat
import subprocess
import sys
import tempfile

ROOT = Path(__file__).resolve().parents[4]
CHECKER = ROOT / "deploy/scripts/lab/r63/ssh-host-trust-check.py"
SPEC = importlib.util.spec_from_file_location("ipat_r63", CHECKER)
assert SPEC and SPEC.loader
TRUST = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(TRUST)
REQUIRED = {
    "target_id", "expected_model", "expected_routeros", "public_ipv4",
    "ssh_port", "dedicated_username", "dedicated_private_key",
    "trusted_lan_fingerprint_file", "owner_permission",
    "trusted_lan_independently_checked", "customer_backup_recovery_confirmed",
}
USER = re.compile(r"^[a-zA-Z][a-zA-Z0-9_.-]{1,30}$")
OUTPUT_FIELD = re.compile(r"^[A-Za-z0-9][A-Za-z0-9 ._()+-]{0,79}$")
REMOTE_COMMAND = (
    ":put ([/system resource get board-name]); "
    ":put ([/system resource get architecture-name]); "
    ":put ([/system resource get version])"
)

class Rejected(ValueError):
    pass

def strict_object(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise Rejected("duplicate configuration field")
        result[key] = value
    return result

def private_file(path_text, *, max_size=4096):
    if not isinstance(path_text, str):
        raise Rejected("private file path type")
    path = Path(path_text).expanduser()
    if not path.is_absolute() or path.is_symlink():
        raise Rejected("private file must be an absolute non-symlink")
    final = path.resolve(strict=True)
    if final == ROOT or ROOT in final.parents:
        raise Rejected("private file must not be source controlled")
    obj, parent = final.stat(), final.parent.stat()
    if (not final.is_file() or obj.st_uid != os.getuid()
            or parent.st_uid != os.getuid()
            or stat.S_IMODE(obj.st_mode) != 0o600
            or stat.S_IMODE(parent.st_mode) != 0o700
            or obj.st_size == 0 or obj.st_size > max_size):
        raise Rejected("private file ownership, size or mode invalid")
    return final

def load_private_config(path):
    p = private_file(path, max_size=2048)
    try:
        cfg = json.loads(p.read_bytes(), object_pairs_hook=strict_object)
    except (ValueError, UnicodeError) as exc:
        raise Rejected("malformed private config") from exc
    if not isinstance(cfg, dict) or set(cfg) != REQUIRED:
        raise Rejected("unexpected private config fields")
    if (cfg["target_id"] != "DEV-08" or cfg["expected_model"] != "RB951Ui-2HnD"
            or cfg["expected_routeros"] != "7.23.7"
            or cfg["owner_permission"] != "confirmed_by_operator"
            or cfg["trusted_lan_independently_checked"] is not True
            or cfg["customer_backup_recovery_confirmed"] is not True):
        raise Rejected("specific target or independent safety gates unmet")
    if not isinstance(cfg["ssh_port"], int) or isinstance(cfg["ssh_port"], bool):
        raise Rejected("invalid port type")
    try:
        ip = TRUST.explicit_public_ipv4(cfg["public_ipv4"], cfg["ssh_port"])
    except (TRUST.Rejected, TypeError, ValueError) as exc:
        raise Rejected("invalid single management endpoint") from exc
    cfg["public_ipv4"] = ip
    if not isinstance(cfg["dedicated_username"], str) or not USER.fullmatch(
            cfg["dedicated_username"]):
        raise Rejected("dedicated restricted account username required")
    key = private_file(cfg["dedicated_private_key"], max_size=16384)
    independent = TRUST.independently_verified_private_fingerprint(
        cfg["trusted_lan_fingerprint_file"])
    return cfg, key, independent

def validate_output_path(file_name):
    if not isinstance(file_name, str):
        raise Rejected("missing output file")
    path = Path(file_name).expanduser()
    if not path.is_absolute() or path.is_symlink() or path.exists():
        raise Rejected("evidence output must be new")
    canonical = path.resolve(strict=False)
    if canonical == ROOT or ROOT in canonical.parents:
        raise Rejected("evidence cannot enter repository")
    parent = canonical.parent
    if (not parent.is_dir() or parent.is_symlink()
            or parent.stat().st_uid != os.getuid()
            or stat.S_IMODE(parent.stat().st_mode) != 0o700):
        raise Rejected("evidence directory must be private")
    return canonical

def scan_single_rsa(ip, port):
    try:
        scan = TRUST.run_command(
            ["ssh-keyscan", "-T", "5", "-p", str(port), "-t", "rsa", ip])
        exact = f"[{ip}]:{port} ssh-rsa "
        lines = {line.strip() for line in scan.splitlines()
                 if line.startswith(exact)}
        if len(lines) != 1:
            raise Rejected("untrusted server key missing or ambiguous")
        line = lines.pop()
        words = line.split()
        if len(words) != 3 or words[0] != f"[{ip}]:{port}" or words[1] != "ssh-rsa":
            raise Rejected("unexpected public key scan shape")
        fp = TRUST.single_fingerprint(
            TRUST.run_command(["ssh-keygen", "-lf", "-", "-E", "sha256"],
                              stdin=(line + "\n").encode("ascii")))
        return line, fp
    except (TRUST.Rejected, UnicodeError, ValueError) as exc:
        raise Rejected("single server RSA fingerprint unavailable") from exc

def sanitize_ssh_read(raw):
    if not isinstance(raw, bytes) or len(raw) > 4096:
        raise Rejected("SSH output too large")
    try:
        lines = raw.decode("ascii").splitlines()
    except UnicodeError as exc:
        raise Rejected("non-ASCII identity output") from exc
    if len(lines) != 3 or not all(OUTPUT_FIELD.fullmatch(line) for line in lines):
        raise Rejected("unexpected SSH resource reply cardinality/syntax")
    model, arch, version = lines
    if (model != "RB951Ui-2HnD" or arch != "mipsbe"
            or version not in ("7.23.7", "7.23.7 (stable)",
                               "7.23.7 (long-term)")):
        raise Rejected("physical identity/firmware did not match planned tuple")
    return {
        "target_id": "DEV-08", "model": model, "architecture": arch,
        "routeros": version,
        "test_scope": "one_authenticated_read_only_ssh_exec",
        "method": "SSH_EXEC",
        "resource": "/system/resource:board-name,architecture-name,version",
        "read_observed": True, "operator_review_complete": False,
        "physical_device_enrolled": False, "tenant_binding_verified": False,
        "compatibility_verified": False, "configuration_modified": False,
        "hardware_revision": "NOT_OBSERVED",
        "observed_at_utc": datetime.now(timezone.utc).isoformat(),
    }

def pin_and_read(cfg, key_path, trusted_fingerprint, output, *, scan=scan_single_rsa,
                 launcher=subprocess.run):
    # Independent proof is a human-attested DIFFERENT trusted path; the
    # public key fetched below has NO trust until its fingerprint matches.
    line, observed = scan(cfg["public_ipv4"], cfg["ssh_port"])
    if observed != trusted_fingerprint:
        raise Rejected("public SSH key differs from independent LAN proof")
    try:
        previous = TRUST.historical_rsa_fingerprint(
            cfg["public_ipv4"], cfg["ssh_port"])
    except TRUST.Rejected as exc:
        raise Rejected("historical SSH key ambiguous") from exc
    if previous != observed and os.environ.get(
            "IPAT_R64_ACKNOWLEDGE_PREVIOUS_KEY_CHANGED") != "YES":
        raise Rejected("previous host key conflict requires separate approval")
    # Never change ~/.ssh/known_hosts. Ephemeral pin has exact ONE verified
    # key and the SSH client uses strict checking BEFORE public-key auth.
    with tempfile.TemporaryDirectory(prefix="ipat-r64-hostpin-") as temp:
        secure_dir = Path(temp)
        secure_dir.chmod(0o700)
        pin = secure_dir / "hostkey"
        fd = os.open(pin, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
        with os.fdopen(fd, "w", encoding="ascii") as out:
            out.write(line + "\n")
        args = [
            "ssh", "-F", "/dev/null", "-T", "-p", str(cfg["ssh_port"]),
            "-i", str(key_path),
            "-o", "BatchMode=yes",
            "-o", "NumberOfPasswordPrompts=0",
            "-o", "PasswordAuthentication=no",
            "-o", "KbdInteractiveAuthentication=no",
            "-o", "PreferredAuthentications=publickey",
            "-o", "PubkeyAuthentication=yes",
            "-o", "IdentitiesOnly=yes", "-o", "IdentityAgent=none",
            "-o", "StrictHostKeyChecking=yes",
            "-o", "HostKeyAlgorithms=rsa-sha2-512,rsa-sha2-256",
            "-o", "UserKnownHostsFile=" + str(pin),
            "-o", "GlobalKnownHostsFile=/dev/null",
            "-o", "UpdateHostKeys=no",
            "-o", "ProxyCommand=none", "-o", "ProxyJump=none",
            "-o", "ControlMaster=no", "-o", "ClearAllForwardings=yes",
            "-o", "PermitLocalCommand=no", "-o", "ConnectTimeout=5",
            "-o", "LogLevel=ERROR", "-o", "RequestTTY=no",
            cfg["dedicated_username"] + "@" + cfg["public_ipv4"],
            REMOTE_COMMAND,
        ]
        # Bound disk bytes even if a malicious server floods stdout.
        with tempfile.TemporaryFile() as stdout:
            def file_limit():
                resource.setrlimit(resource.RLIMIT_FSIZE, (4096, 4096))
            try:
                child = launcher(
                    args, stdout=stdout, stderr=subprocess.DEVNULL,
                    timeout=12, check=False, stdin=subprocess.DEVNULL,
                    preexec_fn=file_limit,
                    env={"PATH": "/usr/bin:/bin", "LC_ALL": "C",
                         "SSH_ASKPASS_REQUIRE": "never"})
            except (subprocess.TimeoutExpired, OSError, ValueError) as exc:
                raise Rejected("strict key-only first read could not finish") from exc
            if child.returncode != 0:
                raise Rejected("strict key-only first read denied")
            stdout.seek(0)
            result = sanitize_ssh_read(stdout.read(4097))
    # Evidence destination has already been validated BEFORE any network.
    output = validate_output_path(str(output))
    fd = os.open(output, os.O_CREAT | os.O_EXCL | os.O_WRONLY
                 | getattr(os, "O_NOFOLLOW", 0), 0o600)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as out:
            json.dump(result, out, sort_keys=True, separators=(",", ":"))
            out.write("\n")
            out.flush()
            os.fsync(out.fileno())
    except BaseException:
        output.unlink(missing_ok=True)
        raise
    return result

def main():
    parser = argparse.ArgumentParser(description="Offline by default; one exact SSH inventory read")
    parser.add_argument("--config")
    action = parser.add_mutually_exclusive_group(required=True)
    action.add_argument("--requirements", action="store_true")
    action.add_argument("--preflight", action="store_true")
    action.add_argument("--read", action="store_true")
    parser.add_argument("--output")
    args = parser.parse_args()
    if args.requirements:
        print("R64_REQUIRED=independent_trusted_LAN_host_key,private_recovery,"
              "dedicated_restricted_public_key_account,three_local_opt_ins")
        print("NO_PUBLIC_ENDPOINT_LOGIN_OR_NETWORK_TRAFFIC")
        return 0
    try:
        if not args.config:
            raise Rejected("owner-local config required")
        cfg, key, proof = load_private_config(args.config)
        if args.preflight:
            if args.output:
                raise Rejected("preflight may not write output")
            print("R64_OFFLINE_PREFLIGHT=PASS; SSH_LOGIN=NOT_ATTEMPTED")
            return 0
        # No live I/O unless EVERY independent owner-controlled gate is met.
        if (sys.platform != "darwin" or os.environ.get(
                "IPAT_R64_OWNER_APPROVES_SINGLE_SSH_READ") != "YES"
                or os.environ.get("IPAT_R63_VERIFIED_FROM_TRUSTED_LAN") != "YES"
                or os.environ.get("IPAT_R64_ACKNOWLEDGE_PREVIOUS_KEY_CHANGED") != "YES"
                or not args.output):
            raise Rejected("independent proof and explicit run opt-ins required")
        dest = validate_output_path(args.output)
        pin_and_read(cfg, key, proof, dest)
        print("R64_PRIVATE_UNREVIEWED_ONE_SSH_READ_STAGED;"
              " TENANT_NOT_ENROLLED; NO_WRITES; INDEPENDENT_REVIEW_REQUIRED")
        return 0
    except (Rejected, TRUST.Rejected, OSError, UnicodeError, ValueError) as exc:
        # NEVER print account, destination, fingerprint, credential or payload.
        print("R64_STRICT_SSH_READ_DENIED:" + type(exc).__name__, file=sys.stderr)
        return 4

if __name__ == "__main__":
    raise SystemExit(main())
