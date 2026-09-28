# IPAT R6.0 — Device intake and real-hardware test readiness

**Developer:** Mr. iPat
**Scope:** Eight first-stage hardware *target slots* from the already approved
`docs/DEVICE_MATRIX.md`, verified only as project data. **ZERO real devices
enrolled, connected, scanned, authenticated or declared compatible** until
independent, authorized, device-specific evidence has actually been produced.

## Delivered

- First-party planned-target inventory:
  `web/lab/device-targets.json` holds DEV-01 through DEV-08 (ZTE C320,
  C-DATA OLT, VSOL/ZTE ONTs, MikroTik x86/CCR/distribution RB/customer RB).
  Incomplete exact models/firmware are shown as incomplete; generic product
  families cannot imply hardware or protocol compatibility.
- The original Rust Axum Control API serves `GET /lab/device-targets`
  only when the owner-enabled browser preview is explicitly loopback-only.
  Default and K3s-bound versions still return 404 for the catalog. POST/PUT
  remain denied. Data is sanitized project test-planning metadata,
  not a `/v1/devices` customer endpoint and not an actual live inventory.
- The private browser lists all eight initial targets with
  `physical_devices_enrolled=0`, `physical_interoperability_verified=0`,
  `network_discovery_enabled=false` and `compatibility_claim=false`.
  Browser JavaScript rejects provenance drift and safely renders fields with
  `textContent` only. No credential entry, actual IP, sensitive serial,
  network probes, privileged device write or physical-support assertion.
- Separate `deploy/scripts/lab/r60/prepare-device-intake.py` provides
  credential-free offline private metadata collection. It accepts an exact
  target ID, a real observed model, hardware revision, firmware build and
  *candidate* interface only. The tool validates allowlisted device family
  and protocol, disallows unrecognized/secret/network-address fields and
  placeholders, fails closed on duplicate JSON keys, limits input size,
  rejects unsafe output paths, never overwrites, and writes mode-0600
  metadata only inside a pre-created mode-0700 directory **outside Git**.
  Output explicitly remains `unverified_offline_metadata_only`, with all
  authorization/connection/compatibility and high-risk write fields false.
  It neither imports the record into public HTTP nor contacts a device.

## How the owner can prepare one physical device *without sending secrets*

On the authorized Mac, create a private mode-0700 folder outside the repo
and write an input JSON file there, based on this example. The values below
are **ILLUSTRATIVE ONLY**; do not pass them off as observations from any
actual unit:

```json
{
  "target_id": "DEV-01",
  "exact_model": "C320",
  "hardware_revision": "REPLACE_WITH_ACTUAL_BOARD_REV",
  "firmware_build": "REPLACE_WITH_ACTUAL_FIRMWARE",
  "protocol_candidate": "snmpv3"
}
```

Use a real locally observed hardware revision and firmware rather than
template values. Protocol candidate is *not* an observation of supported
protocol. Only exact known target IDs are accepted; any additional field
such as `password`, `serial`, `management_ip`, `token` or `secret`
is rejected. Do not store secrets in the input file or ChatGPT.

```bash
mkdir -p -m 0700 "$HOME/.local/share/ipat/device-intake"
# Use a local editor to create INPUT.json privately (never commit it).
cd "$HOME/Projects/ipat-current"
python3 deploy/scripts/lab/r60/prepare-device-intake.py \
  --input "$HOME/.local/share/ipat/device-intake/INPUT.json" \
  --output "$HOME/.local/share/ipat/device-intake/DEV-01-staged.json"
```

The resulting file is a **private staging artifact only**, not permission
for a real network scan. Store real credentials only through a separately
approved secret manager; do not paste them into CLI flags, Git or chat.

## Physical test promotion requires distinct review

To mark DEV-01..DEV-08 as physically registered or ready, obtain each
device's precise model, actual firmware and relevant board revisions;
confirm explicit equipment/tenant owner permission and a separate isolated
reachable lab management channel; verify TLS/certificate and access scope
without putting management addresses or credentials into this repository.
Add signed/reviewed read-only adapter and identity tests, a device-specific
negative isolation test and sanitized physical evidence record
(`DEVICE_MATRIX.md` test tuple and source/run IDs) *before* an authenticated
backend exposes a true tenant-bound device. Unknown hardware and
unverified USP/MikroTik/SNMP capabilities must remain `untested`.

First physical acceptance should be read-only OLT inventory for the exact
ZTE C320/C-DATA firmware or a safe authenticated VSOL/ZTE ONT CWMP Inform
with positive device-to-tenant assignment and a verified parameter read;
all writes remain disabled until plan/dry-run, approval, rollback and audit
exist. Simulated CWMP tests cannot satisfy these physical acceptance gates.

## Acceptance and evidence boundaries

1. Actual review tests check eight target IDs, zero physical evidence and
   sensitive-field/duplicate-key/unsafe-output/oversized denial.
2. Original Rust unit tests verify private GET, false public route and 405
   write denial; GitHub CI repeats with the existing real disposable K3s
   tests. Existing R5.8 K3s chart is unchanged and cannot expose this UI.
3. Actual Ubuntu VPS test may compile the software in an unprivileged isolated
   checkout without any device I/O or privileged live installation.
4. After reviewed merge, synchronize private GitHub/Mac/VPS exact SHA,
   retest the same Mac-local SSH browser URL, independently encrypt/recover
   the exact Git source and selected existing root config. Never edit shared
   provider firewall or enable live K3s to test this inventory page.

**Current physical-test notification trigger:** a real DEV-01..DEV-08
record with safely recorded *observed* model/firmware/board, approved
isolated-lab reachability, identity binding and an independently logged
device-specific physical read/Inform test. A planned target row or
offline metadata file alone must not trigger a “device added” notification.

### R6.0 reviewed feature, nonprivileged Ubuntu and recovery checkpoint

- Feature [PR #51](https://github.com/mr-ipat/ipat/pull/51) merged as
  `2184cda657bea315de455e8e9249c82aba8e55e4`; actual reviewed PR
  workflow `36219353933` returned SUCCESS in all four jobs: Rust+static,
  real isolated Ubuntu26 K3s Node/etcd/DNS + real existing health-only app pods
  and ingress policy denial, PostgreSQL synthetic logical+physical recovery.
- Private GitHub/Mac/actual Ubuntu 26.04.1 VPS clean source aligned exactly
  at the feature SHA. Actual host, with no new privileged installation,
  passed Rust formatting and 83 locked offline Rust tests, 42 base static,
  6 R5.7, 6 R5.8, 6 R5.9, 6 R6.0, 14 DB static and 5 admission static tests.
  Actual VPS K3s/PostgreSQL/nftables all remained INACTIVE.
- Mac FileVault ON. Encrypted feature-main Git source snapshot `4b2a0b99`
  and separately encrypted selected root-readable snapshot `abaa9827`
  were independently SHA-256/SSH-sudoers restored, with complete Restic data
  check PASS and plaintext temporary artifacts removed. This does NOT prove
  a complete replacement VPS/production PostgreSQL restore.
- Next actual physical test still requires real exact hardware+firmware
  evidence, equipment-owner authorization and isolated lab connectivity.
  Eight software candidate records are NOT eight connected devices;
  simulator/protocol tests must not be relabelled as physical evidence.

- Post-feature-merge canonical main CI `36219447245` independently
  returned SUCCESS in all four jobs, repeating real disposable Ubuntu26
  K3s application/network-policy and both synthetic PostgreSQL checks.
  No device was connected or probed by this CI run.
