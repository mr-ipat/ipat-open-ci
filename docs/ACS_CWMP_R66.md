# IPAT R6.6 — original Rust CWMP read-only RPC and sealed synthetic session

**Developer:** Mr. iPat
**Scope:** meaningful S1 protocol milestone, **not completed commercial ACS**.
**Target reference:** Broadband Forum TR-069a6c1; the current tested
subset remains **SOAP 1.1 / CWMP 1.0**, no version negotiation yet.
No actual CPE, real tenant, real CA or real subscriber traffic is
used by any new R6.6 test or runtime.
Standards: <https://www.broadband-forum.org/technical-library>.

## 1. Product acceptance: MUST, SHOULD, LATER

**MUST — delivered, offline/loopback synthetic only**

- Native original Rust `crates/cwmp-protocol` preserves bounded
  DTD-free SOAP 1.1/CWMP 1.0 Inform and InformResponse, with new
  strictly allowlisted one-parameter `GetParameterValues` serializer
  and correlated response/numeric-only fault parser. Only
  `Device.DeviceInfo.SoftwareVersion` can be requested in this
  laboratory feature. Arbitrary parameter and write RPCs fail closed.
- `crates/cwmp-admission` keeps the **sealed synthetic trusted-peer
  boundary**. Its new read stage starts ONLY after a previously
  accepted Inform and a validated truly empty CPE POST without
  SOAPAction or Content-Type. Same peer + internal lease must
  issue/read/correlate/finish or explicitly abort; mismatched tenant,
  peer, correlation, concurrent device session, duplicate issue,
  replay and malformed method are denied. A server-generated
  per-lease correlation ID is checked. Faults are converted to a
  bounded numeric code, while returned values are excluded
  from session evidence or logs.
- Actual compilable original Rust `apps/cwmp-gateway` process
  only starts with `IPAT_RUN_OFFLINE_CWMP_LAB=1`, binds ONLY
  `127.0.0.1:3300`, exposes `/healthz` and the deliberately
  harmless `POST /lab/parse-inform` route, and unconditionally
  returns HTTP 503 for **all `/cwmp` requests**. Lab parser
  response includes NO device identifiers and explicitly sets
  `peer_authenticated=false`, `tenant_bound=false`,
  `device_enrolled=false`, `cwmp_response_sent=false`.
  Spoofed client certificate or tenant HTTP headers have no effect.
- `deploy/scripts/lab/r66/cwmp-loopback-http-smoke.sh` runs the
  **real** loopback executable temporarily under opt-in,
  verifies real HTTP valid/malformed/unsafe/oversized XML,
  synthetic forged-header denial on /cwmp and exact
  127.0.0.1-only listening, then stops its own process.

**MUST — NOT YET DELIVERED (commercial/product release blockers)**

- Complete independently verified server TLS + CPE client mTLS,
  trust-anchor/expiry/revocation/client-SPKI verification and
  independently authenticated tenant-device enrollment from
  persistent operator-approved records. No proxy-supplied
  `X-Client-Cert` or hostname/serial header is trusted.
  This requires a separately reviewed network adapter that
  mints the previously sealed `AuthenticatedPeer` only
  after genuine transport proof, never based on SOAP claims.
- Actual authenticated `/cwmp` ingress with CWMP HTTP binding
  semantics; persistent bounded session/nonce/replay, distributed
  owner locking, restart recovery and explicit failure/timeout.
  HTTP CPE empty POST must have neither SOAPAction nor
  Content-Type, and the ACS SOAP request is sent on the
  **corresponding HTTP response**, never as a new unsolicited
  HTTP request to a CPE.
- Authenticated durable, tenant/POP-scoped enrollment/API
  and read-result retention under non-BYPASSRLS DB roles;
  approved per-device parameter allowlists, safe correlation
  and least-privileged operator permissions; real audit
  and redaction without serials/credentials in telemetry.
- Physical interoperability on actual known exact VSOL/ZTE
  ONT model + firmware with operator consent, lab trusted
  ACS URL/certificate, independent backup and one
  authenticated read-only device parameter RPC.
  `TC-CWMP-01`, PRD `AC-03` real physical condition
  and broader FR-009/010 remain NOT PASSED.

**SHOULD**

Support additional validated CWMP negotiated versions, safe
GetParameterNames, normalized per-vendor TR-181/TR-098 model
capabilities, explicit session limits and instrumented
redacted HTTP semantics with peer-certificate test harness.
All are planned, not proven by an R6.6 green CI.

**LATER**

Large-scale parameter writes, factory resets, firmware
campaigns, WAN connection requests, broad multi-firmware
compatibility and rollout automation require approval,
maintenance windows, restoration tests and a verified
per-device feature matrix before activation.

## 2. Trust boundaries and lifecycle

```text
Future HTTPS mTLS edge + verified enrollment    NOT IMPLEMENTED
              |
     sealed AuthenticatedPeer (Rust type)
              |
cwmp-admission::begin(peer, trusted_tenant, untrusted_Inform)
              |
       InformResponse; opaque internal Lease
              |
       genuine empty CPE HTTP POST
              |
        issue_one_read -> SOAP GetParameterValues
              |
same authenticated CPE subsequent SOAP response or CWMP Fault
              |
        accept_one_read -> numeric-only read evidence
              |
          finish OR explicit abort
```

Only the *offline synthetic Rust tests* can construct a peer
at this milestone. The separate running HTTP parser gateway
does **not** have access to any constructor and MUST NOT
bridge an untrusted public request into the sealed type.

Read evidence fields `operator_reviewed`,
`physical_device_verified` and
`tenant_approved_for_live_provisioning` remain FALSE
even for successful **synthetic** RPCs; no physical or
commercial compatibility claim is created.

## 3. Paths and repeatable test commands

- `crates/cwmp-protocol/src/rpc.rs`: strict allowlisted
  serializer and response/fault parser.
- `crates/cwmp-protocol/tests/rpc.rs`: explicit
  response ID, DTD, namespace, method, value, type,
  duplicate/oversize and fault tests.
- `crates/cwmp-admission/src/read.rs`: lease-bound
  one-read state machine and bounded, sanitized evidence.
- `crates/cwmp-admission/src/read_tests.rs`: trusted
  synthetic Inform→empty POST→RPC→response/fault/abort
  and wrong-tenant, peer or replay rejections.
- `apps/cwmp-gateway/{Cargo.toml,src/main.rs}`: new
  loopback-only Rust process with 503 on real /cwmp.
- `deploy/scripts/lab/r66/cwmp-loopback-http-smoke.sh`:
  exact local HTTP test against the actual executable.

On an authorized disposable development machine, with
the pinned Rust toolchain and offline Cargo cache already
present, using **only synthetic fixtures**:

```bash
cargo fmt --all -- --check
cargo test --workspace --locked --offline
cargo build --locked --offline -p cwmp-gateway
IPAT_R66_EXACT_LOOPBACK_SMOKE=YES \
  bash deploy/scripts/lab/r66/cwmp-loopback-http-smoke.sh
```

Never expose port 3300 on a public interface; the binary
has no flag to change its bind address. The above test
explicitly stops its own loopback listener. It does not
start K3s, create a PostgreSQL server or touch routers.

## 4. Risk and acceptance evidence classification

The synthetic admission registry retains bounded
**in-memory** session and replay state only; restarts
lose this data. Synthetic certificates are manufactured
inside tests and must not be mistaken for real mTLS
handshakes or interop results. The HTTP parser accepts
untrusted Inform XML but intentionally does not
authenticate, enroll, return CWMP SOAP envelopes or
execute any RPC. The SQL multi-tenant job and RLS
tests elsewhere are separate disposable laboratory
artifacts, not an ACS runtime database adapter.

No new architecture decision changes ADR-001 or
ADR-002: native Rust ACS and separate native
USP Controller remain required. An actual ACS release
must link evidence for the **real gateway trust
boundary**, durable tenant-scoped sessions and
one physical per-firmware device test.

## 5. Reviewed R6.6 feature results on the unchanged Ubuntu development host

Feature [PR #61](https://github.com/mr-ipat/ipat/pull/61) merged at `380633f68b38a83b8607d3042944ef4e5aaf41a8`. Independent PR CI `36237639478` and new main CI `36237754400` passed all four jobs each (locked Rust, disposable Ubuntu26 K3s, ephemeral RLS/logical backup and separate physical PostgreSQL recovery). The real unchanged Ubuntu 26.04.1 VPS **source checkout** passed 121 locked/offline Rust tests, previous three CWMP static trust tests and existing R6.3/R6.4 security tests. The compiled original Rust Axum gateway passed **real** temporary localhost HTTP acceptance: fixed 127.0.0.1:3300 only, /cwmp HTTP 503 even spoofed client identity headers, safe synthetic parser-only response, negative content/malformed/DTD/oversize denial and process cleanup. There was no live CPE TLS handshake or real device session.

The separately authorized owner Mac saved exact-feature encrypted Restic source snapshot `034c20c9`, independently restored with source SHA256 and read-all-packs PASS. Previously selected encrypted root-readable configuration was also independently restored and its encrypted packs verified, but these do NOT cover full server recovery, new PostgreSQL PITR or real ACS customer state. The live VPS K3s, PostgreSQL and nftables remain inactive; no external hosting-provider network integration or public ACS exposure exists.
