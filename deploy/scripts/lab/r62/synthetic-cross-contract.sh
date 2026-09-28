#!/usr/bin/env bash
# Mr. iPat: strictly OFFLINE Python R6.1 -> Rust R6.2 redacted evidence contract.
# This creates a disposable synthetic fixture, NEVER contacts an actual router.
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
script = repo / "deploy/scripts/lab/r61/readonly-rest-probe.py"
spec = importlib.util.spec_from_file_location("ipat_r61_cross",script)
assert spec and spec.loader
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)

# Entirely fabricated fixture: proves only parser structure + leak isolation.
raw = [{
    "board-name": "RB951Ui-2HnD",
    "architecture-name": "mipsbe",
    "version": "7.23.7 (stable)",
    "serial-number": "FAKE_SERIAL_NEVER_PERSIST",
    "ip-address": "FAKE_IP_NEVER_PERSIST",
    "password": "FAKE_SECRET_NEVER_PERSIST",
}]
evidence = module.sanitize_resource(raw,"RB951Ui-2HnD","7.23.7")
assert all(x not in json.dumps(evidence)
           for x in ("FAKE_SERIAL", "FAKE_IP", "FAKE_SECRET"))
evidence["observed_at_utc"] = "2026-09-26T05:52:00+00:00"
for name, obj in (
    ("redacted.json",evidence),
    ("forged.json",dict(evidence, tenant_binding_verified=True)),
    ("leaked.json",dict(evidence, **{"serial-number":"FAKE_SERIAL"})),
):
    path=tmp/name
    fd=os.open(path,os.O_CREAT|os.O_EXCL|os.O_WRONLY,0o600)
    with os.fdopen(fd,"w",encoding="utf-8") as f:
        json.dump(obj,f,sort_keys=True)
        f.write("\n")
PY

cargo run --quiet --locked --offline -p routeros-core \
  --bin routeros-lab-evidence -- --input "$tmp/redacted.json"
for invalid in forged.json leaked.json; do
  if cargo run --quiet --locked --offline -p routeros-core \
    --bin routeros-lab-evidence -- --input "$tmp/$invalid" \
    >"$tmp/result.stdout" 2>"$tmp/result.stderr"; then
    echo 'R62_UNTRUSTED_EVIDENCE_INCORRECTLY_ACCEPTED' >&2
    exit 1
  fi
  test ! -s "$tmp/result.stdout"
  grep -Fxq 'R62_OFFLINE_EVIDENCE_DENIED' "$tmp/result.stderr"
done
echo 'R62_PYTHON_TO_RUST_OFFLINE_NO_PII_NO_AUTO_ENROLL_CROSS_CONTRACT=PASS'
