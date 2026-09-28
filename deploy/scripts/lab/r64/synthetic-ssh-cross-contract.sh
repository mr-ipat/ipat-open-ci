#!/usr/bin/env bash
# Mr. iPat: OFFLINE Python SSH identity sanitizer to strict Rust evidence.
# No SSH login, account credentials, production endpoint or router traffic.
set -Eeuo pipefail
umask 077
repo="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../../.." && pwd)"
cd "$repo"
tmp="$(mktemp -d)"
chmod 0700 "$tmp"
cleanup() { rm -rf -- "$tmp"; }
trap cleanup EXIT

python3 - "$repo" "$tmp" <<'PY'
import importlib.util
import json
import os
from pathlib import Path
import sys

repo, tmp = Path(sys.argv[1]), Path(sys.argv[2])
script = repo / "deploy/scripts/lab/r64/ssh-first-read.py"
spec = importlib.util.spec_from_file_location("ipat_r64_cross", script)
assert spec and spec.loader
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)

# Synthetic fixed three-line non-privileged RouterOS read, not actual hardware.
redacted = module.sanitize_ssh_read(
    b"RB951Ui-2HnD\nmipsbe\n7.23.7 (stable)\n")
redacted["observed_at_utc"] = "2026-09-26T05:52:00+00:00"
assert redacted["method"] == "SSH_EXEC"
assert redacted["read_observed"] and not redacted["physical_device_enrolled"]
assert not redacted["tenant_binding_verified"]
for name, obj in (
    ("redacted.json", redacted),
    ("tenant-forged.json", dict(redacted, tenant_binding_verified=True)),
    ("write-forged.json", dict(redacted, resource="/system/resource/set")),
    ("method-forged.json", dict(redacted, method="POST")),
    ("pii-forged.json", dict(redacted, **{"serial-number": "FAKE_SERIAL"})),
):
    fd = os.open(tmp / name, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, "w", encoding="utf-8") as output:
        json.dump(obj, output, sort_keys=True)
        output.write("\n")
PY

cargo run --quiet --locked --offline -p routeros-core \
  --bin routeros-lab-evidence -- --input "$tmp/redacted.json" \
  >"$tmp/accepted.stdout" 2>"$tmp/accepted.stderr"
grep -Fq 'PHYSICAL_READ_AUTHENTICATED=NO' "$tmp/accepted.stdout"
grep -Fq 'COMPATIBILITY=UNVERIFIED' "$tmp/accepted.stdout"
for invalid in tenant-forged.json write-forged.json method-forged.json pii-forged.json; do
  if cargo run --quiet --locked --offline -p routeros-core \
      --bin routeros-lab-evidence -- --input "$tmp/$invalid" \
      >"$tmp/result.stdout" 2>"$tmp/result.stderr"; then
    echo 'R64_FORGED_ROUTEROS_SSH_EVIDENCE_ACCEPTED' >&2
    exit 1
  fi
  test ! -s "$tmp/result.stdout"
  grep -Fxq 'R62_OFFLINE_EVIDENCE_DENIED' "$tmp/result.stderr"
done
echo 'R64_SYNTHETIC_KEY_ONLY_SSH_TO_RUST_UNREVIEWED_EVIDENCE=PASS'
