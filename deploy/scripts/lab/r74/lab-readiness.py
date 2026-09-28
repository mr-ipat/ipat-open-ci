#!/usr/bin/env python3
"""Strict offline DEV-01 isolated-lab first-read PACKET preflight.

No device sockets, credential loading, host pinning, or firmware actuator.
Owner declarations and JSON syntax are NOT independent physical evidence.
"""
import argparse
import json
import os
from pathlib import Path
import re
import stat
import sys

ROOT = Path(__file__).resolve().parents[4]
EXPECTED = {
    "target_id": "DEV-01",
    "environment": "isolated_lab",
    "protocol": "vendor-cli-readonly",
}
GATES = (
    "equipment_owner_authorized_lab_read",
    "isolated_from_live_subscriber_network",
    "dedicated_read_only_account_prepared",
    "independent_device_console_available",
    "independent_host_identity_verified",
    "private_management_route_verified",
    "candidate_read_commands_verified_on_exact_device",
    "configuration_backup_stored_privately",
)
FIELDS = set(EXPECTED) | set(GATES)
SAFE_VALUE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9 ._()+/-]{1,95}$")

class Rejected(ValueError):
    pass

def unique(pairs):
    obj = {}
    for key, value in pairs:
        if key in obj:
            raise Rejected("duplicate JSON field")
        obj[key] = value
    return obj

def private_packet(path):
    if not path.is_absolute() or any(
        x in (".", "..") for x in path.parts
    ) or path.is_symlink():
        raise Rejected("private packet must be an absolute nonlinked path")
    full = path.resolve(strict=True)
    if ROOT == full or ROOT in full.parents:
        raise Rejected("private packet must remain outside repository")
    meta = full.stat()
    if not full.is_dir() or meta.st_uid != os.getuid() or (
        stat.S_IMODE(meta.st_mode) != 0o700
    ):
        raise Rejected("owner-only directory 0700 required")
    if {p.name for p in full.iterdir()} != {"stage.json", "plan.json"}:
        raise Rejected("exactly two fixed metadata files are permitted")
    return full

def read_private_file(directory, filename):
    path = directory / filename
    before = path.lstat()
    if (not stat.S_ISREG(before.st_mode)
            or before.st_uid != os.getuid()
            or before.st_nlink != 1
            or stat.S_IMODE(before.st_mode) != 0o600
            or not 0 < before.st_size <= 4096):
        raise Rejected("owner-only regular file 0600 required")
    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0)
    fd = os.open(path, flags)
    with os.fdopen(fd, "rb") as f:
        after = os.fstat(f.fileno())
        if (after.st_dev, after.st_ino) != (before.st_dev, before.st_ino):
            raise Rejected("file replaced during inspection")
        raw = f.read(4097)
    if len(raw) > 4096:
        raise Rejected("metadata exceeds size limit")
    try:
        data = json.loads(raw, object_pairs_hook=unique)
    except (ValueError, UnicodeDecodeError) as exc:
        raise Rejected("invalid JSON") from exc
    if not isinstance(data, dict):
        raise Rejected("metadata must be an object")
    return data

def validate(stage, plan):
    stage_keys = {
        "schema", "intake_type", "target_id", "category", "vendor",
        "family", "exact_model", "hardware_revision", "firmware_build",
        "protocol_candidate", "physical_connection_performed",
        "compatibility_verified", "tenant_binding_verified",
        "high_risk_writes_enabled", "status",
    }
    if set(stage) != stage_keys:
        raise Rejected("unexpected intake schema or unsafe extra fields")
    for name, value in {
        "schema": 1, "intake_type": "unverified_offline_metadata_only",
        "target_id": "DEV-01", "category": "OLT", "vendor": "ZTE",
        "family": "C320", "protocol_candidate": "vendor-cli-readonly",
        "physical_connection_performed": False,
        "compatibility_verified": False, "tenant_binding_verified": False,
        "high_risk_writes_enabled": False,
        "status": "awaiting_separate_authorization_and_physical_test",
    }.items():
        if type(stage.get(name)) is not type(value) or stage[name] != value:
            raise Rejected("stage provenance cannot attest real device")
    if stage["exact_model"] not in ("C320", "ZXA10 C320"):
        raise Rejected("stage is not the initial C320 target")
    for name in ("hardware_revision", "firmware_build"):
        v = stage[name]
        if not isinstance(v, str) or not SAFE_VALUE.fullmatch(v):
            raise Rejected("bounded operator-observed metadata required")
    if set(plan) != FIELDS or any(plan.get(k) != v for k, v in EXPECTED.items()):
        raise Rejected("unexpected plan fields, device or environment")
    if any(type(plan.get(g)) is not bool for g in GATES):
        raise Rejected("read-only gate fields must be explicit booleans")
    failed = [g for g in GATES if plan[g] is not True]
    return {
        "target_id": "DEV-01",
        "environment": "operator_declared_isolated_lab",
        "declared_first_read_prerequisites_complete": not failed,
        "pending_owner_prerequisites": failed,
        "packet_review": "HUMAN_REVIEW_REQUIRED" if not failed else "BLOCKED",
        "physical_test_executed": False,
        "device_compatibility_verified": False,
        "tenant_enrollment_authorized": False,
        "firmware_update_authorized": False,
        "network_operations_performed": False,
    }

def main():
    parser = argparse.ArgumentParser(description=__doc__)
    mode = parser.add_mutually_exclusive_group(required=True)
    mode.add_argument("--requirements", action="store_true")
    mode.add_argument("--check-packet", type=Path)
    args = parser.parse_args()
    if args.requirements:
        print("R74=DEV-01,OFFLINE_ONLY,OWNER_PRIVATE_0700_PACKET,"
              "FIXED_0600_STAGE_AND_PLAN,8_DECLARED_PREREQUISITES")
        print("NO_DEVICE_NETWORK_NO_CREDENTIALS_NO_FIRMWARE")
        return 0
    try:
        root = private_packet(args.check_packet)
        report = validate(
            read_private_file(root, "stage.json"),
            read_private_file(root, "plan.json"))
        print(json.dumps(report, sort_keys=True, separators=(",", ":")))
        return 0 if report["declared_first_read_prerequisites_complete"] else 4
    except (Rejected, OSError, UnicodeError) as exc:
        print("R74_DENIED:" + type(exc).__name__, file=sys.stderr)
        return 4

if __name__ == "__main__":
    raise SystemExit(main())
