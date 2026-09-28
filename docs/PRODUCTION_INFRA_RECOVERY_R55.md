# IPAT R5.5 — production infrastructure safety and recovery gates

**Developer:** Mr. iPat
**Dated:** 2026-09-25 Asia/Jakarta
**Status:** Read-only readiness assessment and deployment design; NO live production activation approved or executed.

## 1. What was actually checked and why production remains blocked

The authorized Mac, private GitHub `main`, and nonprivileged Ubuntu 26.04.1 VPS checkout were checked against the same canonical commit. The actual guest still listens for SSH on IPv4 and IPv6; PostgreSQL and K3s services are inactive. A previous independent encrypted Restic restore of the exact Git source, historical readable configuration and **selected** privileged root-readable configuration passed. None of those facts proves a complete independent host rebuild, usable out-of-band rescue-console login, independent PostgreSQL PITR or private Kubernetes node routing.

Prior operator evidence showed that the existing external **shared** allow-all group permits all inbound IPv4 and IPv6 and is attached to other VPSs. It is an external operational dependency, NOT an IPAT product integration. Never edit/reassign that shared group as an unsupervised shortcut. A new, **dedicated IPAT-only** perimeter must be created and its complete IPv4/IPv6 *effective* rule union/attachment verified by the operator before changing the server. No third-party hosting-provider API integration will be developed.

## 2. Executable read-only go/no-go report

From the Mac's clean canonical `main`, run:

```bash
cd ~/Projects/ipat-current
python3 deploy/scripts/production/readiness.py
# A NO_GO result intentionally exits 3, even if every SSH/backup-source test passes.
python3 deploy/scripts/production/readiness.py --json
```

The script independently checks local clean Git `main`, exact private GitHub and VPS SHA, strict-host-key key-only SSH, Ubuntu release, SSH rollback marker, Mac FileVault and the existing encrypted Restic snapshot for **the exact current Git commit**. It does not print or export sensitive backup passwords, fetch VPS credentials or inspect provider APIs. Neither the script nor an uploaded JSON file can independently prove actual console login, another host's encrypted restoration, private perimeter enforcement, independently rebuilt PostgreSQL PITR, approved architecture or a rollback drill. External evidence is always `BLOCKED_UNVERIFIED`; this command **never invokes installation or applies rules** and cannot issue a GO signal.

## 3. Recovery prerequisites: independently complete these before live changes

1. **Out-of-band rescue:** the operator must actually log into the correct live VPS through a separately accessible console/rescue environment, establish a usable login session and rehearse a safe recovery path; menu presence or a screenshot without a login is inadequate. Keep the recovery channel available for later timed rollback and record redacted proof outside Git.
2. **Complete encrypted host recovery:** capture a separately held, complete, restorable host/application configuration and state backup, including a deliberate strategy for SSH host keys and later PostgreSQL/K3s secrets. Do not upload plaintext `/etc`, `/root`, host private keys, K3s tokens, device credentials or real subscriber data into Git/issue trackers. An isolated **different** recovery environment must decrypt/rebuild, check file ownership/permissions and demonstrate boot/SSH/app operation. The current selected-root Restic snapshot alone is explicitly insufficient.
3. **Second independent encrypted copy:** verify storage and recovery-password custody independent of the Mac and test an actual isolated read/decryption using independently held credentials. Off-Mac password escrow reported previously is not a verified second full off-host backup.
4. **Network provenance and rollback:** inventory actual interfaces, IPv4+IPv6 public/private ingress, VM-to-group attachments, rule union, NAT path, route and a stable SSH management source or tested private VPN. Confirm a dedicated IPAT-only perimeter without changing other tenants/VPSs. Record the existing effective state and a separately controlled, tested rollback route before any change.
5. **Formal architecture/security review:** ADR-005, ADR-008, ADR-010, ADR-017 and optional ADR-018 need a decision record, approved trust boundaries, owners and measured recovery objectives. An unpublished draft is not approval.

## 4. PostgreSQL commercial topology — PROPOSED, not installed

- Keep PostgreSQL stateful storage separate from horizontally scaled K3s workers. **Production target** requires a dedicated primary plus one or more standbys on independently recoverable hosts/failure domains and a controlled failover coordinator chosen after ADR-010 review. One currently available 16-vCPU/30-GiB/250-GiB VPS cannot prove database HA, independent failure domains or the approved pilot capacity baseline.
- Select a PostgreSQL major version, pin repositories/package digests and test its extensions on Ubuntu 26.04. Provision private-only PostgreSQL listener and mTLS/TLS client trust, least-privilege migration/runtime/replication roles and deny public TCP/5432 from both IPv4 and IPv6. Verify the actual listener, external exposure and role flags. Do not store production secrets in source control.
- Select and test a supported **physical base backup + uninterrupted WAL archive** with encryption, immutable/off-host retention, monitoring of archive lag and an operator-approved restore destination. A synthetic GitHub `pg_dump`/new-database restore **does not** establish PITR, because logical dumps lack the WAL chain required for point-in-time replay. See PostgreSQL's [official PITR design](https://www.postgresql.org/docs/16/continuous-archiving.html).
- On an **independently isolated** database recovery host, replay WAL to a selected timestamp, verify tenant/POP RLS, cross-tenant denial, subscriber/device scoped FK, durable job/outbox consistency, database permissions, backup manifests and measured RPO/RTO. Test primary isolation/failover without dual-active writers. Only after this succeeds and the trusted OIDC/POP authorization layer exists may real customer data or operational writers be enabled.
- The new separate disposable GitHub CI job `postgres-physical-recovery-lab` additionally rehearses a **physical** PostgreSQL 16.9 base backup with streamed WAL, verifies its backup manifest and boots a second isolated PostgreSQL 16 server *process* on the same ephemeral runner for a synthetic data SHA-256/RLS comparison. The new safety-tested script is `deploy/db/tests/physical_restore_ephemeral.sh`; execution must not be claimed successful until its actual GitHub job is verified. This does **not** prove archived-WAL point-in-time replay, an independently recoverable second machine, data durability across availability zones or production PITR. The original `0001`/`0002` logical CI restores remain separate checks.

## 5. First-party firewall — PROPOSED, never applied yet

- Keep the product's `crates/firewall-policy` as a **non-executable** validator until ADR-018 approval and complete rescue gates. The eventual privileged nftables agent must live outside unprivileged tenant/app containers, only change IPAT's own dedicated nftables table and reject any request that lacks strong host identity, platform-scoped authorization, MFA where applicable and maker/checker approvals.
- On a separate disposable Ubuntu machine, test `nft -c` on the *complete proposed transaction*; verify nftables/CNI coexistence, IPv4+IPv6 source-specific SSH, CNI forwarding and kube-proxy/NetworkPolicy interactions before writing any host rules. Capture old rulesets, routes and independent SSH checks.
- A persistent, **actually tested** rollback independent of the affected SSH path must survive partial command failure and reboot. Execute a deliberately failing rule/automatic rollback scenario on a disposable node, then a real fresh key-only SSH login from approved management networks and independent dual-stack ingress tests. A silent unused-port connection failure is not evidence that the perimeter blocks a public listener.
- A dedicated perimeter may still be required around the VPS before native host firewall activation; IPAT must not manage external hosting security groups. Never use the existing shared allow-all group as an isolated change target.

## 6. K3s network/HA prerequisites — PROPOSED, not installed

- Record ADR-017's exact private node connectivity, NAT/overlay/CNI choice, pod/service CIDRs, node identity/hostname conventions, cross-node route acceptance and selected control-plane datastore. Do not treat the current host's `eth0` private address alone as proof of private, provider-isolated inter-node routing.
- The first **disposable, separately recoverable node** can validate a SHA-256-pinned installer/binary, isolated node bootstrap, pod DNS, failure cleanup and manual node teardown. No production multi-node proof may be inferred from a single host; real HA requires separately provisioned quorum/control-plane capacity plus failure drills.
- Keep Kubernetes TCP/6443 restricted to verified private members/admin VPN; allow CNI-specific traffic only between authorized nodes. With Flannel VXLAN, UDP/8472 must NEVER be exposed publicly. Restrict kubelet TCP/10250 and etcd TCP/2379–2380 as appropriate. These are documented [official K3s network requirements](https://docs.k3s.io/installation/requirements); actual port needs vary with CNI and datastore choices.
- Protect the real K3s server token and datastore in an independently restorable encrypted backup. Rehearse clean-cluster restore and tenant workload recovery *before* putting persistent tenant services under orchestration. Node addition/drain tests must prove jobs are not duplicated under lease expiry and connectivity failures.
- Do not point an installer at the current live VPS while the out-of-band rescue, independent full recovery and private dual-stack ingress checks are blocked.

## 7. Execution sequence / rollback transactions

| Stage | What is verified | Explicit stop/rollback |
|---|---|---|
| P0 | Read-only report, dedicated host inventory, real independent rescue login and complete off-host recovery rehearsal | If rescue or restored data fails, NO host/service mutation |
| P1 | Disposable independent PostgreSQL PITR + isolated private K3s/nftables compatibility drills; approved ADRs and version locks | Delete disposable environments, do not touch live VPS |
| P2 | Separately supervised, dedicated perimeter change with rollback and **both** IPv4/IPv6 external tests | Restore only the dedicated IPAT perimeter to recorded state; never alter other shared groups |
| P3 | Separately supervised native firewall transaction (if ADR-018 approved), first on isolated disposable node; then only on independently recoverable live node | Tested out-of-band rollback, fresh SSH and dual-stack verification |
| P4 | Only after previous gates, independently backed-up production PostgreSQL HA/PITR, tested failover, then private K3s control plane and worker join | Stop customer writes, preserve evidence and restore independently verified states before proceeding |

**Current milestone result:** read-only preparations can pass, but production install/firewall/K3s status remains **BLOCKED** until actual independent recovery/perimeter/approval evidence exists. Never convert this document into an assumed deployment success or infer vendor/device compatibility.

## Verified R5.5 feature checkpoint (source-merge evidence)
- Developer: **Mr. iPat**. [Feature PR #41](https://github.com/mr-ipat/ipat/pull/41) merged to `main` `9c2187649714a00d09e0478c7ed3065a19ddaa19`, with successful three-job PR CI `36156542785` and post-merge CI `36156779897`. New disposable physical PostgreSQL CI **actually passed**: the restored separate server process preserved synthetic job/outbox SHA-256 and RLS denial after verified streamed-WAL base backup. Do not reinterpret this as an independent machine, continuous WAL archive, timestamp PITR or production HA proof.
- The exact same Git commit was checked independently on private GitHub, the Mac and real Ubuntu 26.04.1 VPS, which passed 76 offline Rust unit tests, 37 existing lab source contracts, 14 database contracts, five new read-only gate tests and Rust formatting. PostgreSQL/K3s/nftables remained INACTIVE on the VPS.
- After an encrypted source snapshot `11bc5931` and separate selected-root snapshot `abaa9827` passed independent isolated restores and full Restic pack reading, the actual clean Git `main` read-only admission produced **8 automatic PASS** and **7 independent external BLOCKED / NO_GO**. Latest evidence following any documentation-only merge belongs in that PR's discussion to avoid changing Git HEAD recursively. Live production deployment is NOT COMPLETE.
