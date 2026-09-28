# IPAT R5.7 — K3s cross-host recovery and nftables rollback laboratory

**Developer:** Mr. iPat
**Date:** 2026-09-26 Asia/Jakarta
**Scope:** real K3s systemd, embedded-etcd restore and native nftables rollback on two disposable QEMU Ubuntu 26.04 VMs on the authorized Mac. This is NOT installation on the IPAT VPS and does not approve ADR-017/018 for production.

## 1. Why this milestone exists

R5.6 proved that pinned K3s can run on a disposable Ubuntu 26.04 environment, but it did not prove a service-style install survives restart, that an embedded-etcd snapshot can be moved to a different host, or that a first-party nftables transaction can coexist with K3s and recover from a bad rule. R5.7 targets those missing recovery properties without changing the production VPS.

The live VPS remains outside this experiment. Its K3s, PostgreSQL and host nftables services remain inactive. The externally shared allow-all security group is not integrated, queried or modified by IPAT.

## 2. Exact disposable platform

- Host: authorized arm64 Mac, QEMU 11.0.3 with HVF acceleration.
- Guest image: official Ubuntu Server 26.04 arm64 cloud image.
- Image SHA-256 verified against the official release file before boot:
  `8dc812bc6356d0abf825d8029f25f1b71f02cb103e1d0cc5c17fbb2572322972`.
- Every destructive script requires `/etc/ipat-disposable-vm=R57_QEMU_UBUNTU26_DISPOSABLE_ONLY`, `systemd-detect-virt=qemu`, Ubuntu 26.04 and the exact expected synthetic hostname.
- Source VM hostname: `ipat-r57-a`; restore VM hostname: `ipat-r57-b`.
- K3s: `v1.36.4+k3s1` arm64, binary SHA-256 pinned to
  `c920706346d5ad4e5cd3c7bf1bb09ce71ebe07fec829e513e40f1caf98aed8bb`.
- QEMU user networking was intentionally isolated per VM. Both guests observed an RFC1918 address; they were not treated as proof of a production private overlay or provider-isolated L2/L3 network.

No GitHub token, customer data, RouterOS credential, subscriber secret or production server token was used.

## 3. Source VM — exact repository script execution

`deploy/scripts/lab/r57/source-systemd-k3s.sh` was copied directly from the working branch to a fresh VM and executed as root only after its disposable guards passed.

Actual result:

- K3s installed as a real systemd service with `UMask=0022`.
- `ipat-r57-a` became `Ready` with roles `control-plane,etcd`.
- CoreDNS became Ready and a BusyBox 1.37.0 pod resolved
  `kubernetes.default.svc.cluster.local`.
- API port `16443` was present on the VM's RFC1918 node address plus loopback; no wildcard `0.0.0.0:16443` or `[::]:16443` listener was accepted by the script.
- A synthetic restore marker `MR_IPAT_R57_RESTORE_PROOF` was committed into etcd.
- Embedded-etcd snapshot `r57-cross-host` was created with an explicit `--etcd-server`; the source server token was exported separately with mode 0600 and was **never printed**.
- Fresh exact-script snapshot SHA-256:
  `c76105bc5c818f70b2c4cad53e0f371345d889b4148260afef7c3abaa0da67b2`.
- A real `systemctl restart k3s` completed and the source node returned Ready.

The token itself is deliberately absent from Git, chat evidence and this document.

## 4. Different-host embedded-etcd restore

`deploy/scripts/lab/r57/restore-systemd-k3s.sh` was then tested from the repository on fresh restore VMs.

The first manual engineering attempt exposed an important K3s new-host requirement: supplying only a custom `--token-file` did not satisfy the new-host restore path. The original source server token must be available at K3s' expected server-token location so the restored bootstrap data can be decrypted. The repository script now places the imported original token root-only at the standard server path before `--cluster-reset --cluster-reset-restore-path`.

A later fresh exact-script run found a second recovery race: the old Node object could disappear only after more than 30 seconds, and pod objects restored from etcd could remain bound to that stale Node. The final script waits up to 90 seconds for old-node removal and explicitly deletes only pod objects whose `spec.nodeName=ipat-r57-a`, allowing controllers to recreate CoreDNS/local-path pods on VM B.

A third fresh run exposed a post-systemd-restart race: an old Pod Ready condition can briefly remain true while container-runtime exec is not yet usable. The final script therefore creates a **new** BusyBox pod after restart and proves DNS through that new container.

Final fresh exact-repository execution PASS:

- cluster-reset restore success marker found in the root-only restore log;
- synthetic etcd ConfigMap marker restored on VM B;
- `ipat-r57-b` Ready;
- stale `ipat-r57-a` Node removed;
- stale pods bound to VM A removed and controller-managed pods recreated on VM B;
- CoreDNS Ready;
- new post-restore pod scheduled on VM B and cluster DNS PASS;
- API private-address/no-wildcard assertion PASS;
- `systemctl restart k3s` followed by a newly created post-restart pod and DNS PASS;
- a new `r57-post-restore` etcd snapshot created successfully.

This is a real cross-VM restore of synthetic cluster state. It is not a production multi-node HA failover, externally encrypted K3s-token backup, or proof that provider networking is private.

## 5. Native nftables failure and rollback drill

On the successfully restored VM B, R5.7 also exercised the first real IPAT-owned nftables transaction. The dedicated test table was only `inet ipat_r57_lab`; no pre-existing host or external perimeter rules were flushed.

The safe test validated the ruleset using `nft -c`, then used a default-drop input chain while preserving established connections, loopback, the synthetic management path, the private K3s API scope, pod CIDR, ICMP/IPv6-ICMP and DHCP. K3s remained Ready and pod DNS continued working.

The intentional-failure drill then omitted the SSH new-connection allow. A fresh SSH connection correctly failed while the existing management session remained established. The first timer experiment exposed another safety issue: `systemd-run --on-active=20s` inherited the default systemd timer `AccuracySec=1min`, so the rollback was delayed well beyond twenty seconds.

The final repository script `deploy/scripts/lab/r57/nft-rollback-drill.sh` fixes this by requiring explicit opt-in and using:

- `--on-active=10s`
- `--timer-property=AccuracySec=1s`
- `--timer-property=RandomizedDelaySec=0`
- a rollback program that deletes **only** `inet ipat_r57_lab`.

Final exact-script result:

- rollback timer armed with one-second accuracy;
- a fresh SSH session was intentionally blocked;
- after the rollback window, a new SSH session succeeded;
- the IPAT test nft table no longer existed;
- K3s node remained Ready;
- a new post-rollback BusyBox pod became Ready and cluster DNS PASS.

The observed default timer accuracy bug is specifically why a mere "rollback timer exists" claim is not sufficient for production.

## 6. Repository safety controls

Paths introduced for R5.7:

- `deploy/scripts/lab/r57/source-systemd-k3s.sh`
- `deploy/scripts/lab/r57/restore-systemd-k3s.sh`
- `deploy/scripts/lab/r57/nft-rollback-drill.sh`
- `deploy/scripts/lab/r57/test_r57_review.py`

All destructive paths require the exact disposable VM marker and QEMU environment. The firewall failure drill additionally requires
`IPAT_R57_INTENTIONAL_SSH_ROLLBACK_DRILL=YES`.
Static tests reject mutable `get.k3s.io` installation, live VPS references, external security-group integration, wildcard K3s API binding, token printing and imprecise nft rollback.

## 7. What this changes — and what it does not

R5.7 materially upgrades K3s evidence:

- real systemd K3s install on Ubuntu 26.04 arm64;
- different-VM embedded-etcd restore using the original token;
- stale-node/pod reconciliation;
- K3s restart recovery;
- post-restore snapshot creation;
- real nftables/K3s coexistence;
- intentional SSH lockout plus deterministic automatic rollback.

It still does **not** authorize installation on the live VPS. The remaining live-host gates are independent of whether K3s itself works:

1. usable out-of-band console/recovery login on the real VPS;
2. complete independently restorable real-host recovery, not selected config only;
3. a dedicated effective IPv4+IPv6 ingress boundary that does not modify shared external groups;
4. an explicit ADR-017 production network/CNI/control-plane design;
5. production datastore/token backup custody and restore target;
6. approved ADR-018 if IPAT's native host firewall is to be active on the live node.

ADR-017 and ADR-018 therefore remain OPEN/PROPOSED. QEMU user networking is laboratory evidence, not the selected production topology.

## 8. Cleanup

All R5.7 clusters contain synthetic data only. After evidence collection, the disposable QEMU VMs, their temporary cluster token, copied snapshot and dedicated disposable SSH key must be powered off and removed from the Mac working directory. The official checksum-verified Ubuntu base image may be retained as a non-secret cache. No K3s token or snapshot is committed to Git.

## 9. Verified merge and cleanup evidence

- Feature PR #45 merged as `8e6f51714b4160a85d3d760ad3c142163445f4fb`; PR CI `36185362020` and post-merge main CI `36185478592` SUCCESS in all four jobs.
- GitHub, Mac and actual Ubuntu 26.04.1 VPS source SHA matched. The live VPS passed 76 Rust offline tests, 42 existing lab static checks, 14 DB contracts and six R5.7 static safety tests while K3s/PostgreSQL/nftables remained inactive.
- Encrypted exact merged-source Restic snapshot `2974580c` and selected privileged-root-config snapshot `abaa9827` separately restored with full pack-data verification.
- After the QEMU evidence was captured, the synthetic K3s server-token copies, cross-host snapshots, dedicated disposable SSH private key and all secret-bearing QEMU overlay disks were deleted from the Mac lab directory. The official checksum-verified Ubuntu base image may remain as a non-secret cache.
- This closes R5.7 laboratory evidence only. It does not change ADR-017/018 or authorize a live VPS K3s/firewall transaction.
