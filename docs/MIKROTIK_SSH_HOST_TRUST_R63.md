# IPAT R6.3 — DEV-08 SSH host identity mismatch: do not authenticate

**Developer:** Mr. iPat
**As-of:** 2026-09-26 Asia/Jakarta
**Status:** STOP / independent identity verification needed.
**Security classification:** the current endpoint's SSH host key does NOT match
the host key previously stored on the owner Mac. No password was used, no
authenticated RouterOS command executed, and no `known_hosts` record changed.

## Verified read-only observations and their limits

The owner authorized one specific public SSH endpoint and supplied credentials
in chat. To limit exposure, the endpoint address/port combination and all
supplied credentials are **never recorded in this repo or test fixtures**.

On the authorized Mac, an explicit single-port TCP connection worked and the
untrusted SSH banner identified the service family as MikroTik RouterOS
(`ROSSSH`). The default strict SSH host-key check refused the connection
with the standard **REMOTE HOST IDENTIFICATION HAS CHANGED** error before
any authentication. A separate unauthenticated, one-host RSA key scan
showed a different SHA-256 RSA host fingerprint from the owner's previously
pinned `~/.ssh/known_hosts`. The same mismatch was independently repeated
by the fail-closed R6.3 preflight on the owner Mac. An SSH banner or
`ssh-keyscan` of the **same public network path** cannot authenticate
the router or distinguish SSH key rotation, misdirected NAT/port
forwarding or an adversary in the path.

The exact fingerprints were provided directly to the owner in the current
chat for independent comparison. **They are deliberately not embedded in
source-controlled artifacts**, alongside no real network-management IPs,
serials, device passwords or public test endpoint identity.

## Delivered: no-credential host-key trust validator

`deploy/scripts/lab/r63/ssh-host-trust-check.py` accepts ONE explicit
globally routable IPv4 literal and ONE port. By default it runs only
`ssh-keyscan` for the RSA **public** host key and `ssh-keygen` for
SHA-256 fingerprint extraction/comparison with the existing pinned
owner-Mac `known_hosts` record. It never invokes the `ssh` login
client, asks for or transmits a password, runs RouterOS commands,
imports a key, enables `StrictHostKeyChecking=no`, removes or
modifies the existing trusted key or changes a router configuration.
A changed/missing historical key causes exit code 4. It prints the
saved and currently observed fingerprint but labels the latter
**UNVERIFIED**, never approved.

Use the one-host **observation only** on the Mac (replace placeholders
locally with the router address and forwarded SSH port):

```bash
cd ~/Projects/ipat-current
python3 deploy/scripts/lab/r63/ssh-host-trust-check.py \
  --target-ipv4 "$ROUTER_PUBLIC_IPV4" --port "$ROUTER_PUBLIC_SSH_PORT"
```

Exit 4 with `HOST_KEY_CHANGED_UNVERIFIED` is **correct for the
currently observed incident**, and prevents password transmission.

## Independent verification required before ANY account login

A qualified operator should first **independently identify the actual
RB951Ui-2HnD through a trusted direct LAN management path**, existing
WinBox access with known MAC/hardware label, or a trusted local
console. Do not treat the public endpoint as proof of device identity.

From the trusted direct LAN (using the actual *LAN SSH port* from the
operator's existing RouterOS management configuration, which may differ
from the public forwarding port), a qualified operator can compare
the direct router's RSA SSH fingerprint **without logging in over
the public path**:

```bash
# Run only from a Mac physically on the known router's trusted LAN:
ssh-keyscan -T 5 -t rsa -p "$TRUSTED_LAN_SSH_PORT" \
  "$VERIFIED_ROUTER_LAN_IPV4" 2>/dev/null | ssh-keygen -lf - -E sha256
```

Read the displayed fingerprint privately. **Compare it with the new
UNVERIFIED public-endpoint fingerprint shown by R6.3.** If different,
do not proceed: the public endpoint may forward to another SSH
server or an intermediary. If identical, independently recheck the
router's MAC/model using existing trusted management and consult
your security owner. Merely scanning the same untrusted public
endpoint a second time is NOT independent verification.

Only **after** independent verification, create an owner-mode-0600
local text file in the existing private mode-0700 folder, using
the fingerprint from the trusted direct LAN rather than copying
any unverified public scan:

```bash
umask 077
# Replace this placeholder locally ONLY after trusted direct-LAN verification:
printf '%s\n' "$INDEPENDENT_DIRECT_LAN_RSA_SHA256" \
  > "$HOME/.local/share/ipat/router-lab/ssh-host-fingerprint.verified"
chmod 0600 "$HOME/.local/share/ipat/router-lab/ssh-host-fingerprint.verified"

IPAT_R63_VERIFIED_FROM_TRUSTED_LAN=YES \
python3 deploy/scripts/lab/r63/ssh-host-trust-check.py \
  --target-ipv4 "$ROUTER_PUBLIC_IPV4" --port "$ROUTER_PUBLIC_SSH_PORT" \
  --independent-fingerprint-file \
    "$HOME/.local/share/ipat/router-lab/ssh-host-fingerprint.verified"
```

The owner-asserted independent match only clears the **fingerprint
comparison**; it does not itself authenticate physical ownership or
change `known_hosts`. Until an operator separately approves an
ephemeral strict pinned-host connection, **do not ignore the old
host-key conflict or send the chat-disclosed password**. Prefer
manually rotating the already-shared password through independently
trusted local management, then using a dedicated, restricted SSH
public-key account. MikroTik's built-in `read` group includes additional
privileges; any dedicated account/group must be explicitly reviewed
for the read-only test scope.

Do **not** execute `/ip ssh export-host-key` simply to check a
fingerprint: this RouterOS command exports the **private host key
as well as the public key** and introduces a separate sensitive-key
handling risk.

## Read-only hardware test remains blocked

The R6.1 HTTPS first-GET path is a separate prerequisite requiring
verified management transport, a real trusted TLS CA, a dedicated
restricted account and non-disruptive recovery. Having an accessible
public SSH port is **not** permission to enable HTTPS, expand router
rights, export configuration, create device users, scan subnets or
change an active customer's settings. After independently verifying
identity and approving one safe read-only session, collect only the
exact board-name, architecture and RouterOS version through a
single reviewed command; sanitize all evidence outside Git.
All other physical hardware features and production-wide RouterOS
management remain `untested`.

## Safety review and acceptance

- Positive: same stored/observed host fingerprint, or a mismatch
  separately verified by a genuine trusted direct-LAN fingerprint,
  results in an explicit status message **without authenticating**.
- Negative: new/missing/malformed/ambiguous public SSH key without
  independent proof, lack of the owner approval flag, untrusted
  plaintext/symlink file, private/multicast/hostname/range input,
  and conflicting local fingerprints all fail closed.
- The script's unit tests mock all key scans; the only real
  endpoint probe in this milestone is a one-host, unauthenticated
  public RSA fingerprint check. No password was used and no
  real device hardware/model/firmware was verified.

## R6.3 tested feature checkpoint (physical authentication STILL BLOCKED)

Security code [PR #57](https://github.com/mr-ipat/ipat/pull/57) merged at `017adfc382be86aec742cf24299eac794ba886be`. The feature PR four-job CI `36224036550` and independent post-feature-main four-job CI `36224159513` succeeded (Rust and negative tests, disposable real Ubuntu26 K3s, two separate ephemeral PostgreSQL recovery paths). Ten R6.3 offline/mocked tests succeeded on the actual unchanged Ubuntu 26.04.1 VPS, as did the earlier 99 Rust tests and RouterOS Python-to-Rust fake-secret/forged-tenant contract. The exact feature-main source encrypted Restic snapshot `6bc581b5` was isolated restored and verified by SHA-256; separately selected root-readable backup `abaa9827` was independently recovered. Real owner-Mac unauthenticated RSA fingerprint comparison conclusively **BLOCKED** login due to existing-key mismatch. None of these tests identifies the actual customer RB951 or establishes real SSH management permission or firmware compatibility.
