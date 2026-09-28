# IPAT R6.1 — First customer MikroTik, DEV-08

**Developer:** Mr. iPat
**Current state:** Owner-reported model and RouterOS version only.
**No physical router connection, login, trusted identity, tenant enrollment or
model/firmware compatibility has been verified.**

## 1. Scope and first evidence

The operator reports this test unit as **MikroTik RB951Ui-2HnD,
RouterOS 7.23.7**, customer-router target **DEV-08**. MikroTik's model
catalog confirms this family has **MIPSBE**, one core and **128 MB RAM**:
https://mikrotik.com/product/RB951Ui-2HnD .
RouterOS version is user-supplied, not an independently observed result.
Hardware board revision and RouterBOOT firmware are still unknown.

MikroTik documentation:
- https://manual.mikrotik.com/docs/developer-guides/rest-api/
- https://manual.mikrotik.com/docs/authentication-authorization-accounting/user/

The original IPAT health-only Rust API and prior K3s/backup tests are not
a real MikroTik adapter. R6.1 adds a separate **single-purpose guarded
first HTTPS GET**; it does not implement provisioning, Wi-Fi control, PPPoE,
firewall rules, firmware update, complete RouterOS API support or OIDC.

## 2. Safety gates before touching the real customer router

1. The owner confirms written permission to test this specific unit,
   verifies its use on a separate test path and establishes independent
   console/WinBox recovery. Back up the router **privately outside Git**
   before any *operator*-performed RouterOS service/user changes.
   Do not disrupt an active customer connection.
2. From the locally authorized Mac, verify a private, explicitly approved
   management route to **this single exact router**. No subnet discovery,
   Internet exposure, shared provider/firewall modification, or direct
   production VPS access is approved by this milestone.
3. In WinBox, a qualified authorized operator configures a **custom**
   least-privileged user group with only the required read and rest-api
   policies, and a dedicated test account; do **not** reuse admin
   credentials or the built-in `read` group, which has extra permissions.
   This project NEVER automates user/service changes on the router.
4. If REST is explicitly approved, manually configure `www-ssl` on
   the private management path using a CA-signed TLS certificate containing
   the router's dedicated lab DNS name in SAN. Restrict service source
   addresses and the router's actual firewall to the test Mac/subnet.
   Never disable certificate verification, expose `www` HTTP or change
   an active customer device without a safe maintenance plan.
5. Keep the certificate authority PEM and a mode-0600 `netrc` credential
   file **locally outside the repository** in an owner-only directory.
   Never send passwords, serials, private management IPs, device exports
   or certificate private keys to ChatGPT or a GitHub issue.
6. Conduct the separate explicitly approved operator preflight before
   real traffic. A successful *offline* preflight **does not** confirm
   network reachability, credentials, TLS interoperability or hardware
   compatibility.

## 3. Operator-local exact-target config (not saved in Git)

Create `~/.local/share/ipat/router-lab/` with mode 0700.
Create a mode-0600 `probe.json` containing exactly these keys, replacing
all placeholder values **on the Mac** with independently checked facts:

```json
{
  "target_id": "DEV-08",
  "expected_model": "RB951Ui-2HnD",
  "expected_routeros": "7.23.7",
  "management_ipv4": "192.168.88.42",
  "tls_name": "rb951.lab.internal",
  "ca_cert_path": "/LOCAL_PRIVATE_DIRECTORY/lab-ca.pem",
  "netrc_path": "/LOCAL_PRIVATE_DIRECTORY/credentials.netrc",
  "owner_permission": "confirmed_by_operator",
  "isolated_lab_route_confirmed": true
}
```

**192.168.88.42 and rb951.lab.internal are illustrative placeholders**,
NOT observed router addresses or DNS names, and must not be used unless
those exact values are independently confirmed for your isolated lab.
The trusted certificate must cover `tls_name`; the script opens a
single hardcoded HTTPS TCP connection to the selected private IPv4 address,
uses the independent TLS name as SNI/hostname verification and never
resolves DNS, follows redirects or uses a proxy. Only port **443** is
currently supported. The operator must review any different port
separately rather than weaken this test.

Create a distinct mode-0600 netrc file with a single
`machine rb951.lab.internal login LOCAL_TEST_USERNAME password LOCAL_TEST_PASSWORD`
record, replacing the illustrative strings **only locally**. Ensure the
hostname matches `tls_name` and the account is restricted as above.
The script never accepts a password command-line parameter or writes
credentials to its output. The CA PEM need not contain private keys.

## 4. Strictly offline preflight (does not contact router)

```bash
cd ~/Projects/ipat-current
python3 deploy/scripts/lab/r61/readonly-rest-probe.py \
  --config "$HOME/.local/share/ipat/router-lab/probe.json" --preflight
```

The preflight checks exact DEV-08/model/version, valid RFC1918 IPv4,
valid dedicated lab TLS hostname, explicit operator permission/isolated
route declarations, allowlisted JSON structure, CA-file path and a
restricted owner-only netrc with an account. It does not try TLS, inspect
the device or validate that the human declarations are true.

## 5. Actual first read — only after all gates are independently satisfied

Execute only from the **authorized Mac** and only after reviewing the
actual target, verified lab permissions, TLS certificate and management
route. With both explicit run-time approvals the script makes exactly
one HTTPS **GET `/rest/system/resource`**; there are no other HTTP
methods, no route discovery, no automatic retry and no configuration
write. It validates RouterOS board-name, architecture and version
against this precise owner-reported model/version and writes **only
allowlisted**, non-secret results to a new private mode-0600 file.
A mismatched value is rejected and raw responses (which may contain
sensitive fields) are discarded without logging.

```bash
IPAT_R61_REAL_READ=YES IPAT_R61_OWNER_CONFIRMS_SINGLE_GET=YES \
python3 deploy/scripts/lab/r61/readonly-rest-probe.py \
  --config "$HOME/.local/share/ipat/router-lab/probe.json" --read \
  --output "$HOME/.local/share/ipat/router-lab/DEV-08-evidence.json"
```

The output explicitly sets
`physical_device_enrolled=false`,
`tenant_binding_verified=false`,
`compatibility_verified=false`,
`operator_review_complete=false`,
`configuration_modified=false`; board/hardware revision remains
`NOT_OBSERVED`. An authorized reviewer must compare redacted evidence,
actual firmware/build and management identity, tenant permission,
certificate and device backup before promoting **this exact read-only
feature tuple** to a physically tested status. Never upload raw result
files or infer compatibility with all MIPSBE firmware/device combinations.

The local first-party browser catalog may show DEV-08's model/version
as **reported by owner, not physically connected**. It deliberately
maintains zero physical enrollment/interop proof until a separately
reviewed secure tenant-bound product integration exists.

## 6. Negative and regression tests

Run on a disposable checkout without touching physical devices:

```bash
python3 -m unittest discover deploy/scripts/lab/r61 -p 'test_r61*.py' -v
python3 -m unittest discover deploy/scripts/lab/r60 -p 'test_r60_review.py' -v
```

The R6.1 unit suite mocks one exact GET and tests unsafe output paths BEFORE any network request, unexpected responses,
payloads with synthetic serial/credentials/addresses, unapproved modes,
wrong model/version, unsafe destinations/permissions and zero enrollment.
Only the later **real authorized** network test can establish successful
readability for this actual customer router, and only a reviewed identity
binding can allow onboarding in the production app.

**Additional synthetic TLS test:** `test_r61_tls.py` generates an ephemeral local test CA and signed server certificate, connects only to a loopback HTTP fixture while intercepting the expected sample RFC1918/443 socket, confirms the real Python TLS client accepts valid CA/SAN and makes only one GET, then fails closed on a different TLS hostname. The first local run with a deficient synthetic CA keyUsage extension failed; the test certificate generator was corrected and the full 11-test local run subsequently passed. This is not the real router or proof of a real certificate/route.

## Reviewed feature implementation and strict evidence boundaries

GitHub PR #53 (`dcacc1a5e93e04b5ce58d43a34b168b231d42da3`) feature CI `36221642643` and post-feature-main CI `36221754351` each passed all four jobs. On the actual unchanged Ubuntu 26.04.1 VPS as a read-only source checkout, 83 original Rust tests and 11 R6.1 guarded synthetic/negative tests passed. A real ephemeral locally signed synthetic HTTPS server validated the Python probe's CA/SAN handshake and independent rejection of a wrong TLS name; synthetic metadata containing a fake serial never enters output. This is a test of the tool, not the actual RB951.

Private Mac UI → SSH tunnel → real unprivileged Rust loopback served the owner-reported DEV-08 exact model/version and *zero* enrolled physical devices. Direct catalog POST was denied and the still-unauthenticated protected device API returned 401. All live device test claims remain prohibited before a separately authorized one-target physical read and human review.

## R6.2 compatible offline Rust normalization (no new actual hardware result)

The approved R6.1 single-GET lab helper now permits exact RouterOS
version 7.23.7 or the identical build with a documented stable/
long-term channel suffix; unexpected development/testing suffixes,
other versions, model or architecture remain rejected. The new
standalone Rust `routeros-core` independently applies the
same narrow identity policy and validates only redacted,
strict-schema, owner-private R6.1 evidence with an offline CLI;
it cannot register or mutate a router or authenticate a local
file's physical provenance. See
[separate R6.2 Rust tests and boundaries](ROUTEROS_RUST_R62.md).
