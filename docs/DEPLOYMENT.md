# IPAT — Deployment & Operations Runbook Specification v0.1

**Status (R4.8):** Ubuntu Stage 1 toolchain and Stage 2 key-only SSH are independently verified. A selected ROOT-READABLE Ubuntu configuration tar was encrypted directly into the Mac Restic repository as actual snapshot `abaa9827`, then independently restored with full read-data integrity and required root-only file checks. This is a **partial configuration restore**, not a VM/block snapshot or PostgreSQL/K3s recovery. Optional IPAT-native host firewall policy **dry-run** code exists without an apply mechanism. External service firewall APIs are not product integrations; no host firewall rule, provider perimeter rule or K3s service has been changed. Independent console recovery is still unverified; actual firewall rollout/K3s/stateful customer services remain blocked. See [native host firewall design](FIREWALL_CONTROL_PLANE.md) and latest [status](PROJECT_STATUS.md).

## 1. Target environments and prerequisites

- **Lab OS:** Ubuntu Server 26.04 LTS. **Provisional sizing:** 16 vCPU, 64 GiB-class RAM, ~1 TB NVMe SSD + private network and external backups. Not an HA system. All-in-one heavy test 16 vCPU/128 GB/~2 TB is provisional, not obligatory. VPS virtual CPUs can differ from dedicated CPU.
- **Dev path:** local Compose for PostgreSQL, queue, IdP, emulator and Rust services, if chosen; use synthetic secrets. Version-pin images, Compose and PostgreSQL release. K3s test in isolated lab before production.
- **Cluster path:** separate K3s control plane/node joins and external stateful PostgreSQL HA plane before production. Define private VLAN/VPN, time sync/DNS, firewall, network policy, egress allowlist, observability/backup endpoints, trusted ingress/certificates and independent out-of-band rescue.
- **Preflight:** provider allows required UDP/TCP tunnels and persistent disks; capacity and IOPS adequate under measured workload; domain ownership actually verified; storage offsite and data residency reviewed; all secrets generated/stored outside Git.

## 2. Infrastructure repository plan (to implement, not present today)

| Planned path | Responsibility | Required verification |
|---|---|---|
| `deploy/ansible/playbooks/bootstrap-ubuntu.yml` | OS hardening, users, time/NTP, firewall, container/K3s deps | Idempotent repeated dry-run and restart; no secret console logging |
| `deploy/ansible/playbooks/k3s-server.yml` | K3s initial control plane, approved datastore mode | Bootstrap success and readiness; recovery and version pin |
| `deploy/ansible/playbooks/k3s-agent.yml` | Heterogeneous node join with secret vault | Node labeled, schedulable, correct requests/limits |
| `deploy/ansible/playbooks/k3s-drain-remove.yml` | Cordoned safe drain/removal | No ongoing write jobs, graceful lease handoff, stateful data safe |
| `deploy/terraform/providers/` | Supported VPS APIs, network and block storage | Plan reviewed, reproducible import/destroy protection |
| `deploy/helm/ipat/` | Axum/CWMP/USP/worker Helm chart | SecurityContext, network policy, readiness/drain, requests/limits |
| `deploy/gitops/` | Version-pinned cluster desired state | Protected PR approval, drift detection and rollback rehearsal |
| `deploy/scripts/backup-restore/` | PostgreSQL WAL/PITR and restore verification | Isolated restore and checksum/RPO-RTO report |
| `deploy/compose/` | Laboratory local services | End-to-end synthetic demo and no production creds |

## 3. Safe planned bootstrap/join/validate/drain/remove flow

**Bootstrap:** (a) approve architecture/ADR secrets and provider; (b) provision Ubuntu and patch with tested versions; (c) separate OS/service accounts and network rules; (d) configure private remote management, time and certificates; (e) bootstrap K3s control-plane per selected HA plan; (f) pin and apply GitOps/Helm with default-deny policies; (g) deploy monitoring, audit sink and secret manager; (h) initialize DB migrations using dedicated migration identity, never runtime account.

**Join:** (a) register node inventory/capacity and failure domain; (b) permit private K3s traffic; (c) use *short-lived externally managed* K3s join credential; (d) verify node is Ready/allocatable and label architecture/role; (e) validate worker constraints, capacity policy, device network reachability and service authorization; (f) add worker budget gradually then record queue age and real CPU/IO curves.

**Validate:** run health/readiness, app/worker logs, policy tenant-negative tests, queue worker lease crash replay and safe dry-run, metrics/alert/rate-limit checks, K3s scheduling and node failure network/CPU/IO observations. With node B, compare workloads and throughput *as measured*; no target exact equal CPU.

**Drain:** pause/limit new risky provisioning, verify in-flight jobs and device locks, enforce lease expiry/fencing and safe reconciliation after cutover; `kubectl cordon NODE` then, **only after verifying persistent data workloads and disruption budgets**, use an appropriate `kubectl drain NODE --ignore-daemonsets` option set. `--delete-emptydir-data` can destroy ephemeral state and must not be blindly used. Validate no dangling writes before removing hardware.

**Remove:** confirm no remaining workloads/local volumes/secrets, revoke join credentials and host/service access, remove node safely, scrub media following policy and update asset registry; platform/backup/DB state must not depend silently on the removed worker.

**Rollback:** GitOps revert tested manifests, application migration compatibility or forward-only recovery documented; if a job sent unknown router commands, **do not retry blindly**. Isolate queue, read actual device state and follow controlled rollback plan.

## 4. PostgreSQL backup/restore and HA requirements

**S1:** backup selected PostgreSQL lab tables/database; restore into a separately isolated instance and verify tenant counts, FK constraints, selected sample hash and app smoke tests. Retain job/audit recovery integrity. Capture start/end, DB version, data size, backup checksum, restore verification result, log redacted. Producing backup file without restore is **not** passed AC-07.

**Commercial:** PostgreSQL primary+standby design, WAL archiving/PITR, encrypted external independent backup, retention/immutability, restore into clean staging, failover drills and approved measured RPO/RTO; database replicas are **not** assumed to shard write throughput. Test tenant isolation in backup exports/restore and protect cross-tenant physical backup. Select operator/tool and control-plane approach in ADR-010.

**Emergency:** service/DB outage → determine if data-plane degraded vs stateful unavailable; temporarily stop risky writes to avoid unknown effects; avoid two active primaries (split brain); restore from tested point; reconcile outbox/jobs vs actual network state after DB recovery; keep tenant impact/audit evidence.

## 5. Test gates and operator handoff

- Every runbook becomes executable only after code review, placeholder-free secrets and tested rollback; support `--check`/dry run when tool permits.
- Required observability: request/trace ID, CWMP/USP sessions, permission-denied alerts, oldest queue age, retries/DLQ, router timeouts, lease/fencing conflicts, per-node CPU steal/memory/IO, database WAL/archive lag, backups success **and restore recency**.
- CI/integration and operator physical lab reports are separate. Document node type, installed version, exact test time, all observed results and deviation from acceptance gates. If provider/system unavailable, mark `BLOCKED` in `PROJECT_STATUS.md`.

**Never commit**: live credentials, TLS private keys, K3s join tokens, actual private device configs, raw ONT credentials, PPPoE secrets or patient/subscriber identifiers. All credentials in docs are explanatory placeholders only.

**Restricted lab stage 1:** [reviewable helper and no-snapshot safety plan](../deploy/scripts/lab/README.md). Read-only checks and verified user-only Rust installation are independent of privileged package/SSH/network changes.

**R4.3 (2026-09-25):** Real Ubuntu 26.04.1 Stage-1 compiler bootstrap passed and the existing 23 locked unit/simulator tests were independently rerun successfully. [Stage-2 key-only SSH hardening](../deploy/scripts/lab/STAGE2-SSH.md) is **PREPARED ONLY**, with an owner-operated timed rollback; no provider snapshot or complete encrypted off-host recovery backup exists, and no firewall or K3s change has been made.

**R4.4 (2026-09-25):** The owner applied key-only SSH Stage 2 with a six-minute recovery timer and its independent new-session check; an additional Mac-assisted fresh-key login and password-only denial were verified. [Real Ubuntu rootless K3s prerequisites and security/recovery blockers](LAB_K3S_READ_ONLY_2026-09-25.md) are recorded. `deploy/scripts/lab/k3s-readonly-preflight.sh --report` is **inspection only**. K3s has NOT been installed; no public firewall rule, provider ingress, PostgreSQL or subscriber-data action was executed. Previous Stage-2 'PREPARED' wording is chronological history and is superseded by this later verification.


**R4.5 (2026-09-25):** Actual restic v0.19.1 encryption of prior PARTIAL config and canonical source on the separate Mac, with Keychain-only password command, read-all-packs integrity and isolated tar/sha256 restore, is recorded in [the actual lab backup and external provider firewall report](LAB_ENCRYPTED_BACKUP_EDGE_R45.md). Guest and external read-only network checks do not show provider Managed Firewall rules. FileVault is OFF, recovery secret is not separately escrowed, and root-only full config/DB/K3s datastore backups are not complete. K3s installation/host firewall/provider ACL modifications remain prohibited pending distinct recovery/network/ADR reviews.


**R4.6 (2026-09-25):** Owner screenshots and independent probes confirmed FileVault is now ON and current external provider `allow-all` security-group inbound rules admit arbitrary IPv4 **and** IPv6; the VPS has global IPv6 and SSH bound on both families. The existing temporary Mac encrypted Restic backups were independently verified again after FileVault activation. [Proposed staged external provider group change and rollback](EDGE_SECURITY_GROUP_R46.md) is **NOT APPLIED**: affected VM/group assignments, actual live VNC rescue login, static management CIDR, independently escrowed Restic secret and provider-managed IPv4+IPv6 firewall context remain unverified. No K3s/DB/ACS/USP public listener has been deployed.


**R4.7 (2026-09-25):** Owner says actual external provider VNC Console login has not succeeded, Restic password was stored outside the Mac and `allow-all` group is shared by multiple VPSs. No firewall/security-group mutation is allowed until independent recovery and per-VPS security-group design are verified. Prepared [fixed-purpose direct encrypted root configuration streaming with real unprivileged SSH, Restic isolated-restore and negative producer-failure tests](ROOT_CONFIG_STREAM_R47.md). The root-privileged capture requires the owner's local sudo prompt and is **NOT YET EXECUTED**, and full K3s/PostgreSQL storage recovery remains blocked.


**R4.9 current implementation:** The selected-root-readable configuration snapshot was already created (`abaa9827`) and restored with full Restic data integrity; the historical R4.7 text above is retained as a dated milestone, not current state. The new native Rust `cwmp-admission` crate is exclusively offline synthetic/test-only, with no real mTLS/HTTPS gateway, live enrollment database or public ACS listener. It must **NOT** be exposed through Kubernetes ingress, reverse proxy or public service until independently verified TLS device identity and tenant binding, durable sessions/replay/timeout behavior and end-to-end denial tests are implemented. Run `cargo fmt --all -- --check && cargo test --workspace --locked --offline` in the existing unprivileged Ubuntu source checkout; see [R4.9 CWMP admission tests and limitations](CWMP_ADMISSION_R49.md). Host firewall activation and K3s remain blocked pending genuine out-of-band recovery and ADR-017.


**R5.0:** A separate native Rust `usp-core` synthetic test-only tenant/agent/reply-correlation module and `apps/usp-controller` explicit opt-in **loopback-health-only** binary were added. No actual TR-369 USP schema/record/protobuf, broker/MTP, TLS verifier, agent communication or data operation is implemented, so **do not deploy or expose** the binary via external routes, systemd/K3s or node firewall. Run only `cargo test --workspace --locked --offline` as non-root until independently verified out-of-band recovery, transport trust and selected standards are approved. See [R5.0 exact synthetic scope](USP_SYNTHETIC_R50.md). Selected-root-config encrypted backup `abaa9827` remains independently tested, but full VPS/PostgreSQL/K3s recovery is still not verified.

## R5.5 verified infrastructure admission and recovery stop
Run the read-only `python3 deploy/scripts/production/readiness.py` only from a clean Mac Git `main`. An exit code of 3 is intentional: it records verified automatic facts while independently evidenced out-of-band console, encrypted full-host rebuild, dedicated dual-stack perimeter, approved ADR-005/010/017 and PostgreSQL base-backup+WAL PITR restoration remain blocked. Do not bypass the report with an installer; do not change externally shared ingress groups. Exact ordered milestones and rollback tests are in [R5.5 recovery prerequisites](PRODUCTION_INFRA_RECOVERY_R55.md). There is still no authorized production PostgreSQL install, first-party host nftables execution or live K3s service.

## R5.7 K3s restore and native-firewall laboratory proof
A two-VM Ubuntu 26.04 QEMU rehearsal now proves a pinned K3s systemd node can snapshot embedded etcd and restore the synthetic cluster state onto a different disposable VM when the original mode-0600 server token is supplied. The recovery runbook must remove stale source Node/pod objects, wait for CoreDNS to be recreated, and validate runtime recovery with a newly created pod after service restart rather than trusting stale Pod Ready state. A separate nftables drill proved both K3s coexistence and an intentional SSH lockout followed by automatic deletion of only the IPAT lab table using a precise systemd timer. See `K3S_CROSS_HOST_RECOVERY_R57.md`. Do not transpose QEMU addresses or rules to the live VPS; production still requires OOB rescue, full host restore, dedicated dual-stack ingress and approved ADR-017/018.

## R5.9 SSH-only private browser preview

After reviewed Git `main` matches GitHub, Mac and the actual VPS, opt in
*on the authorized FileVault-enabled Mac only* with
`IPAT_R59_ENABLE_PRIVATE_WEB=YES bash deploy/scripts/lab/r59/start-private-web-mac.sh`.
The guard independently verifies Git identity and strict SSH, builds the
unprivileged Rust API offline from the exact reviewed main and tests private
server/tunnel health. The resulting URL
`http://127.0.0.1:48765/lab` works ONLY on the connected Mac and is never
an external/public endpoint. Opt-in teardown:
`IPAT_R59_STOP_PRIVATE_WEB=YES bash deploy/scripts/lab/r59/stop-private-web-mac.sh`.
See [R5.9 scope and production gates](WEB_PRIVATE_PREVIEW_R59.md). Do not
add K3s ingress, real customer data or public HTTP/TLS until all independent
production gates actually pass.

## R6.0 credential-free hardware metadata staging

`GET /lab/device-targets` is available only through the already guarded
owner-Mac loopback SSH tunnel at `http://127.0.0.1:48765/lab`. This static
planning catalog never contacts hardware and always reports zero physical
registrations. Use `docs/DEVICE_TESTING_R60.md` to prepare a single
sanitized target metadata file entirely offline in a private mode-0700
directory outside the repository; `prepare-device-intake.py` creates a
new unapproved mode-0600 JSON file and refuses network addresses, secrets,
serials, unknown target IDs and unsafe paths. No live VPS privilege, network
firewall, actual device read/probe, production ingress or K3s deployment
is authorized by this step. A reviewed real-hardware plan is separate.

## R6.1 first customer MikroTik test (no real connection by default)

Owner-reported DEV-08 RB951Ui-2HnD / RouterOS 7.23.7 has
a separate private, opt-in **one-GET-only** lab validation
workflow in [MIKROTIK_CUSTOMER_R61.md](MIKROTIK_CUSTOMER_R61.md).
This is a local operator-controlled script and not a new
open device listener, deployed K3s adapter, public control API
or customer login. Do not paste the router's real management IP,
CA private keys or test-account password into Git/chat. Leave the
live VPS infrastructure, provider/shared perimeter and production
identity gates unchanged.

## R6.2 native Rust offline evidence contract

A new `routeros-core` crate is added to the original locked
Rust workspace; there is no new production service or live VPS
network port. On an authorized offline-capable development host,
run `cargo test --workspace --locked --offline` and
`bash deploy/scripts/lab/r62/synthetic-cross-contract.sh` to
verify that synthetic Python redacted R6.1 evidence satisfies
the strict Rust schema and that forged tenant elevation and
secret-containing records fail closed. If *later* an authorized
real one-GET R6.1 read produces a private redacted mode-0600
file, run the Rust `routeros-lab-evidence` CLI against that
file locally with `--input` as detailed in
[ROUTEROS_RUST_R62.md](ROUTEROS_RUST_R62.md). Its success
is not real source authentication or device enrollment.
Do not copy raw RouterOS output or management secrets to Git,
start live K3s or change any externally shared perimeter.

## R6.3 unexpected customer SSH host key: fail closed

Never run the real customer MikroTik probe or log in with a
chat-posted password when OpenSSH reports host-key change.
The owner-Mac one-host, unauthenticated
`deploy/scripts/lab/r63/ssh-host-trust-check.py`
reproduces the saved-vs-current fingerprint conflict
without credentials or any changes to `known_hosts`.
Refer to [R6.3 independent direct-LAN verification and
password-rotation runbook](MIKROTIK_SSH_HOST_TRUST_R63.md).
Do not pin unverified public scans, disable SSH host
checking, modify live router services, change a shared
provider perimeter or install production K3s to
work around the blocked connection.

## R6.4 first SSH read requires independent device identity

On the authorized FileVault Mac, use only the owner-private
mode-0700 `~/.local/share/ipat/router-lab/` directory
outside Git. R6.4 creates an intentionally unusable,
mode-0600 `ssh-read.template.json` there for operator
preparation; it is not a real authorized probe configuration.
Run `python3 deploy/scripts/lab/r64/ssh-first-read.py
--requirements` with no network and consult
[the R6.4 independent fingerprint and safe first-read
runbook](MIKROTIK_SSH_R64.md). No real SSH read is
allowed until actual separate direct-LAN host
fingerprint proof, restricted dedicated key, trusted
identity, backup/recovery and operator opt-ins.
The previous pinned host key is NEVER deleted,
overwritten or ignored, and there is no fallback
to chat-shared password authentication. No live
VPS firewall/K3s/PostgreSQL or shared provider
perimeter change is part of this preparation.

## R6.6 original CWMP loopback parser-only runtime

The new `apps/cwmp-gateway` binary is NOT
a real ACS endpoint and refuses to start
without `IPAT_RUN_OFFLINE_CWMP_LAB=1`.
Its only listener is literal 127.0.0.1:3300;
public /cwmp always returns HTTP 503.
To verify a temporary executable, run from
a disposable source checkout with Rust
dependencies already pinned/cached:

```bash
cargo build --locked --offline -p cwmp-gateway
IPAT_R66_EXACT_LOOPBACK_SMOKE=YES \
  bash deploy/scripts/lab/r66/cwmp-loopback-http-smoke.sh
```

The smoke script stops its temporary process
and refuses to run without explicit opt-in.
Never add this binary or its parser route
to public ingress. The actual ACS service,
authentic client mTLS proof, persistent
multi-tenant session binding, TLS secrets
and hardware compatibility are NOT

implemented. No changes to host firewall,
shared perimeter, K3s or live PostgreSQL
are authorized by this milestone.

## R6.7 opt-in real private mutual TLS *test*, bukan deploy ACS pelanggan

Jalankan hanya di checkout
pengujian Ubuntu 26.04 dengan
Rust terkunci dan sertifikat
OpenSSL **sintetis sekali pakai**.
Tidak perlu menggunakan atau
menginstal sertifikat/router
pelanggan:

```bash
cargo build --locked --offline -p cwmp-gateway --bin cwmp-mtls-lab
python3 -m unittest discover deploy/scripts/lab/r67 -p test_r67_review.py -v
IPAT_R67_RUN_SYNTHETIC_MTLS_TEST=YES \
  bash deploy/scripts/lab/r67/mtls-loopback-contract.sh
```

Biner menolak start tanpa flag
`IPAT_RUN_PRIVATE_CWMP_MTLS_LAB=YES`
dan ketiga file CA/cert/key
di private owner-only folder
yang memenuhi syarat. Jangan
menambahkan listener ini ke
Helm production/ingress publik:

biner sengaja tidak memiliki
enrollment tenant, revocation
production dan real CWMP RPC.
Tidak ada apply firewall,
K3s, PostgreSQL di server
nyata atau perubahan
perangkat dalam milestone ini.
[Runbook R6.7](ACS_MTLS_R67.md).

## R6.8 preview dashboard terpisah dari login dan produksi

R6.8 menambahkan
`/lab/dashboard-preview`
beserta CSS/JS dan
tautan dari halaman lab.
Proses hanya dapat
menampilkannya bila
`IPAT_LAB_WEB=1`
dan `IPAT_RUN_K3S_LAB`
tidak dinyalakan;
literal bind nonroot
127.0.0.1:3000
tetap menjadi sumber
private Mac SSH tunnel.
Untuk menguji kode
di checkout development:

```bash
cargo fmt --all -- --check
cargo test --workspace --locked --offline
python3 -m unittest discover deploy/scripts/lab/r68 -p test_dashboard_preview.py -v
node --check web/lab/dashboard-preview.js
node deploy/scripts/lab/r68/test_dashboard_preview.mjs

```

Jangan memasang
dashboard sebagai
portal publik, menambah
custom domain tanpa
verifikasi atau
menggunakan selector
UI lab sebagai
pengganti OIDC, RBAC
dan RLS. Proses
lama restart hanya
setelah source canonical
sudah clean dan CI
independen lulus.
Tidak ada apply
production K3s/PG/
host firewall.
[Lingkup R6.8](DASHBOARDS_R68.md).

## R6.9 private pinned JWT proof only — no SaaS dashboard login

On an isolated checkout, `identity-core` contains
no network I/O: its public key MUST originate
from a separately reviewed issuer, never from
untrusted request headers/JWT. The optional
proof route is created only when the existing
operator loopback preview is opted in and
`IPAT_LAB_OIDC_VERIFY=YES`, plus an owner-only
`IPAT_LAB_OIDC_PUBLIC_KEY_FILE` PEM file
in a 0700 directory with file mode 0600,
`IPAT_LAB_OIDC_ISSUER`, `IPAT_LAB_OIDC_AUDIENCE`
and `IPAT_LAB_OIDC_KID`. Without those,
the private test path does not exist;
K3s never receives a lab identity route.

Reproduce **synthetic** code and HTTP tests on a
disposable host with localhost identity-probe port 3001 free,
not on a running IPAT preview:

```bash
cargo fmt --all -- --check
cargo test --workspace --locked --offline

cargo build --locked --offline -p control-api
python3 -m unittest discover deploy/scripts/lab/r69 -p test_r69_review.py -v
IPAT_R69_RUN_SYNTHETIC_HTTP=YES bash \
  deploy/scripts/lab/r69/oidc-private-http-smoke.sh
```

This does NOT run Keycloak, create an authenticated
tenant session, configure any production issuer,
enroll customers or enable business APIs.
Real IdP configuration, verified tenant membership,
MFA, PostgreSQL RLS application integration
and actual device access remain release gates.
[Identity protocol documentation](IDENTITY_OIDC_R69.md).

## R7.1 ZTE C320 owner-local offline importer ONLY

Only after a trusted device operator has independently gathered
and reviewed two READ-ONLY candidate CLI outputs, save redacted
transcripts as cards.txt and versions.txt in a non-repository
owner directory mode 0700, each file mode 0600 (no symlinks).
First build/test the new olt-core Rust package using locked Cargo.
Run c320-offline-review --requirements for its no-network
preflight instructions. To analyze the two already-collected
files, set IPAT_R71_OWNER_CONFIRMS_REDACTED_OFFLINE_CAPTURE=YES
and pass --parse plus the absolute private directory path.
This reports syntactic parsing only and marks physical device
identity UNVERIFIED, interoperability UNTESTED and firmware
execution DISABLED; no device is contacted or automatically
enrolled. Unknown output is denied, not guessed.
Live OLT access and firmware update are NOT available.
