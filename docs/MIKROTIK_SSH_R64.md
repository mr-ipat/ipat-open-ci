# IPAT R6.4 — Safe, restricted first SSH read for customer RouterOS (prepared)

**Developer:** Mr. iPat
**Scope:** initial pilot DEV-08, owner-reported MikroTik RB951Ui-2HnD /
RouterOS 7.23.7, using a *single read-only SSH inventory command*.
**Actual physical router access: BLOCKED until independent identity proof.**
This is a lab-only Mac-local helper, NOT the multi-tenant production
Rust RouterOS network adapter, and no router configuration is changed.

## Why a real login is still blocked

The authorized owner Mac has a **historically pinned RSA SSH key** for
the explicitly owner-supplied public endpoint. Its current RSA SSH key
differs. Strict OpenSSH correctly refused to log in before transmitting
any password. The current SSH software banner resembles RouterOS, but
neither this banner nor a repeat scan of the same public endpoint
authenticates the actual customer's device.

R6.4 advances the product without bypassing that existing R6.3
`HOST_KEY_CHANGED_UNVERIFIED` stop. The private lab dashboard shows
a **static last-reviewed security blocker**, not realtime telemetry or
a verified connected device. The new optional first-read transport
remains OFF by default; the password disclosed in conversation is
**never embedded, read, requested or transmitted**.

## Completed technical design

- `deploy/scripts/lab/r64/ssh-first-read.py`: one exact target,
  explicit expected DEV-08 board/CPU/version, owner-controlled local
  mode-0600 JSON and dedicated SSH private key, direct-LAN-verified
  mode-0600 RSA fingerprint, and independent backup/recovery and
  permission declarations. No URL, arbitrary command, subnet or
  password field is accepted.
- `--requirements` shows the outstanding security requirements
  **without reading files or opening a network connection**.
  `--preflight` validates locally held files, expected model,
  permissions and owner declarations but **does not open a socket**.
- The `--read` action runs ONLY on the authorized Mac and requires
  THREE explicit environment flags confirming approval, independent
  trusted-LAN verification and separate acceptance of the changed
  historical host key. It validates the evidence output directory
  **before** scanning even one endpoint.
- Only after the above preconditions, exactly one unauthenticated
  RSA public keyscan is permitted. Its fingerprint must exactly
  match the independently supplied *direct-LAN* fingerprint.
  A mismatch aborts **before** SSH login. The existing historical
  key remains untouched and a changed historical pin requires an
  additional explicit approval.
- After positive independent verification, a temporary private
  mode-0600 `known_hosts` file pins the verified **exact public key
  and single endpoint** for that one connection. OpenSSH runs with
  `-F /dev/null`, strict host-key checking, RSA SHA-2 host
  algorithm allowlist, a dedicated local SSH identity, key-only
  auth with BatchMode, SSH agent disabled, no password/kbd-interactive,
  no proxy/jump, no port forward and fixed timeouts.
  This ephemeral pin **never rewrites the owner's old known_hosts**.
  If the device cannot negotiate the approved RSA SHA-2 algorithms,
  the test FAILS rather than downgrading to SHA-1.
- The ONLY remote RouterOS command is three `/system resource get`
  read expressions for `board-name`, `architecture-name` and
  `version`, each printed as one line. No config export, read of
  customer identifiers, enable/disable, firmware update or
  credential-management command is present. Exactly three
  bounded, ASCII-safe lines matching the approved hardware/version
  tuple are accepted; raw output and SSH stderr are never logged.
  Malformed, extra or unexpected output causes the test to fail.
- Only an existing private directory can receive a **new**, exclusive
  mode-0600 sanitized result. All human approval, tenant binding,
  physical enrollment, interoperability, and configuration-write
  status bits remain FALSE; the result is UNREVIEWED even if a later
  real read succeeds. This is deliberate defense in depth.

## Owner-local preparations, NO private information in the repo/chat

An operator must separately authenticate the physical router through
an independent trusted direct-LAN/WinBox path and verify the actual
RSA SSH fingerprint of that exact device. They must investigate
why the historical public-port host key changed (expected key
regeneration versus a wrong forwarding destination/intermediary),
back up the customer router and independently confirm a tested
non-disruptive recovery. Using trusted management, rotate the old
password disclosed in chat and create a distinct, time-limited,
custom least-privileged SSH public-key test identity restricted
to the safe management path. Do not reuse the admin account.

The authorized Mac has an owner-private directory
`~/.local/share/ipat/router-lab`. A placeholder template may be
stored here, but it must have unusable TEST-NET addresses and false
permissions until all facts are independently confirmed. Example
schema with INTENTIONALLY INVALID placeholders:

```json
{
  "target_id": "DEV-08",
  "expected_model": "RB951Ui-2HnD",
  "expected_routeros": "7.23.7",
  "public_ipv4": "198.51.100.42",
  "ssh_port": 2222,
  "dedicated_username": "lab_readonly",
  "dedicated_private_key": "/REPLACE/LOCAL/DEDICATED_PRIVATE_KEY",
  "trusted_lan_fingerprint_file": "/REPLACE/LOCAL/TRUSTED_DIRECT_LAN_RSA_SHA256",
  "owner_permission": "not_confirmed",
  "trusted_lan_independently_checked": false,
  "customer_backup_recovery_confirmed": false
}
```

Do NOT put the real public management endpoint, historical/current
fingerprint file, device credentials, RouterOS exports or subscriber
identifiers into the IPAT repository, this chat or GitHub actions.

After verifying the physical unit through separate trusted LAN
access, the operator may build their own mode-0600 private
`ssh-read.json` and local dedicated SSH key; the fingerprint
file must be populated from that **independent trusted path**,
not copied from the unverified public keyscan. A valid PIN match
is a technical check; it does not independently prove the
human declaration that the fingerprint came from a trusted path.

## Safe execution order on the authorized Mac

```bash
cd ~/Projects/ipat-current
python3 deploy/scripts/lab/r64/ssh-first-read.py --requirements
```

After actual owner-only files and recovery/identity attestations
exist, run the **offline** preflight:

```bash
python3 deploy/scripts/lab/r64/ssh-first-read.py \
  --config "$HOME/.local/share/ipat/router-lab/ssh-read.json" --preflight
```

Only if the owner separately reviews the actual target, trusted
direct-LAN fingerprint, dedicated read-only key, key rotation,
recovery and approved scope should the owner authorize ONE real
read on the Mac:

```bash
IPAT_R64_OWNER_APPROVES_SINGLE_SSH_READ=YES \
IPAT_R63_VERIFIED_FROM_TRUSTED_LAN=YES \
IPAT_R64_ACKNOWLEDGE_PREVIOUS_KEY_CHANGED=YES \
python3 deploy/scripts/lab/r64/ssh-first-read.py \
  --config "$HOME/.local/share/ipat/router-lab/ssh-read.json" --read \
  --output "$HOME/.local/share/ipat/router-lab/DEV-08-ssh-evidence.json"
```

The flags are not commands to perform a device change and must
NEVER be placed in CI or automatically set by IPAT. During the
first real device test, stop after ONE read. If the SSH host
algorithm is unsupported, the actual router output differs,
or the independent key fingerprint conflicts, leave the
device UNTESTED and review the issue; never weaken checking.

The local native Rust evidence gate can parse the output file
*offline* after a genuine authorized read:

```bash
cargo run --locked --offline -p routeros-core \
  --bin routeros-lab-evidence -- \
  --input "$HOME/.local/share/ipat/router-lab/DEV-08-ssh-evidence.json"
```

The Rust parser recognizes only either the narrow read-only
REST or read-only SSH evidence tuple with the same bounded
model, architecture, version and FALSE privilege flags.
A locally fabricated result can satisfy both parsers: only
a separate operator reviewing the actual device and transport
evidence can promote this exact narrow firmware feature to
real physical TESTED. Neither helper registers a real tenant
or enables network-wide configuration management.

## Tests and remaining product blockers

```bash
python3 -m unittest discover deploy/scripts/lab/r64 -p 'test_r64_review.py' -v
bash deploy/scripts/lab/r64/synthetic-ssh-cross-contract.sh
cargo test --workspace --locked --offline
```

All SSH subprocesses, network keyscans and independent
verification in unit tests are mocked. The cross-contract
fabricates a three-line synthetic RouterOS response, uses
the R6.4 Python output sanitizer and R6.2 strict Rust CLI,
and rejects forged tenant rights, write methods and added
serial fields. It makes **ZERO real router connections**.

Production-capable RouterOS integration, trusted multi-tenant
device identity, OIDC+RBAC/ABAC, time-bound read permissions,
SSH key custody/revocation and all PPPoE, Wi-Fi, subscriber,
firewall, firmware and configuration writes are NOT covered.
Live VPS K3s/PostgreSQL/firewall and the external shared
provider security policy must not be changed for this test.
