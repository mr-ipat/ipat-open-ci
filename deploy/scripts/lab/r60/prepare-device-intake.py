#!/usr/bin/env python3
"""Mr. iPat IPAT R6.0: private offline device metadata intake; never scans devices."""
import argparse
import json
import os
from pathlib import Path
import re
import stat
import sys

ROOT = Path(__file__).resolve().parents[4]
CATALOG = ROOT / "web/lab/device-targets.json"
KEYS = {"target_id", "exact_model", "hardware_revision", "firmware_build", "protocol_candidate"}
SAFE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9 ._+()/-]{0,94}[A-Za-z0-9)]$")
SENSITIVE = re.compile(
    r"(?i)(password|passwd|secret|credential|serial|token|apikey|private|"
    r"bearer|https?://|[0-9]{1,3}(?:\.[0-9]{1,3}){3})"
)
PROTOCOLS = {
    "OLT": {"snmpv3", "vendor-cli-readonly"},
    "ONT": {"cwmp", "usp"},
    "ROUTER_DISTRIBUTION": {"routeros-api-ssl", "routeros-https"},
    "CUSTOMER_ROUTER": {"routeros-api-ssl", "routeros-https"},
}

class IntakeRejected(ValueError):
    pass

def unique_json_object(pairs):
    value = {}
    for key, item in pairs:
        if key in value:
            raise IntakeRejected("duplicate JSON metadata field")
        value[key] = item
    return value

def parse_intake(raw: bytes) -> dict:
    if len(raw) > 2048:
        raise IntakeRejected("unbounded metadata")
    try:
        data = json.loads(raw, object_pairs_hook=unique_json_object)
    except (ValueError, UnicodeDecodeError) as exc:
        raise IntakeRejected("malformed JSON") from exc
    if not isinstance(data, dict) or set(data) != KEYS:
        raise IntakeRejected("unknown/secret/serial/address fields are forbidden")
    catalog = json.loads(CATALOG.read_text(encoding="utf-8"))
    if catalog["physical_devices_enrolled"] != 0:
        raise IntakeRejected("unsafe catalog provenance")
    target = next((t for t in catalog["targets"] if t["id"] == data["target_id"]), None)
    if target is None:
        raise IntakeRejected("target not approved for initial test matrix")
    for key in ("exact_model", "hardware_revision", "firmware_build"):
        value = data[key]
        if not isinstance(value, str) or not 2 <= len(value) <= 96:
            raise IntakeRejected("bounded actual metadata required")
        if SAFE.fullmatch(value) is None or SENSITIVE.search(value):
            raise IntakeRejected("unsafe metadata")
        if value.casefold() in {"tbd", "unknown", "sample", "test", "none", "placeholder"}:
            raise IntakeRejected("placeholder is not observed device metadata")
    protocol = data["protocol_candidate"]
    if not isinstance(protocol, str) or protocol not in PROTOCOLS[target["category"]]:
        raise IntakeRejected("unlisted protocol candidate")
    return {
        "schema": 1, "intake_type": "unverified_offline_metadata_only",
        "target_id": target["id"], "category": target["category"],
        "vendor": target["vendor"], "family": target["family"],
        "exact_model": data["exact_model"],
        "hardware_revision": data["hardware_revision"],
        "firmware_build": data["firmware_build"],
        "protocol_candidate": protocol,
        "physical_connection_performed": False,
        "compatibility_verified": False,
        "tenant_binding_verified": False,
        "high_risk_writes_enabled": False,
        "status": "awaiting_separate_authorization_and_physical_test",
    }

def main() -> int:
    parser = argparse.ArgumentParser(description="Offline, credential-free device metadata intake")
    parser.add_argument("--input", required=True, type=Path)
    parser.add_argument("--output", required=True, type=Path)
    args = parser.parse_args()
    try:
        if args.input.is_symlink() or not args.input.is_file():
            raise IntakeRejected("input must be regular, not symlink")
        output = args.output.expanduser().absolute()
        canonical_output = output.resolve(strict=False)
        if ROOT == canonical_output or ROOT in canonical_output.parents:
            raise IntakeRejected("output inside source repository")
        if not output.parent.is_dir() or output.exists() or output.is_symlink():
            raise IntakeRejected("output parent unavailable or file exists")
        if output.parent.stat().st_mode & (stat.S_IRWXG | stat.S_IRWXO):
            raise IntakeRejected("output directory must be private mode 0700")
        record = parse_intake(args.input.read_bytes())
        os.umask(0o077)
        flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0)
        fd = os.open(output, flags, 0o600)
        try:
            with os.fdopen(fd, "w", encoding="utf-8") as file:
                json.dump(record, file, sort_keys=True, separators=(",", ":"))
                file.write("\n")
                file.flush()
                os.fsync(file.fileno())
        except BaseException:
            output.unlink(missing_ok=True)
            raise
        print("R60_OFFLINE_METADATA_STAGED="
              + record["target_id"] + "; PHYSICAL_CONNECTION=NO; TEST=NOT_RUN")
        return 0
    except (IntakeRejected, OSError) as exc:
        print(f"R60_INTAKE_DENIED: {type(exc).__name__}", file=sys.stderr)
        return 4

if __name__ == "__main__":
    raise SystemExit(main())
