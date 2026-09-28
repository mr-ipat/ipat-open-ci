# IPAT — K3s prerequisite and recovery gate (real VPS, read-only)

**Recorded 2026-09-25 (Asia/Jakarta).** Read-only inspection of `openai@hub.example.invalid` using authorized Mac SSH. This is an environmental snapshot, **not** K3s installation, approved ADR-017, public firewall validation, HA, or evidence of a full recovery strategy.

## 1. Stage-2 SSH: post-owner-execution verification

The owner supplied terminal output from `apply-stage2-from-mac.sh` including a fresh public-key session test, privileged confirmation, disarmed rollback timer and final independent public-key login. We independently verified the following in a **new** connection with strict host key matching, disabled multiplexing, no password/keyboard-interactive authentication and no cached SSH session:

- Ubuntu `openai` authenticates successfully using the approved Mac public key.
- Root-owned drop-in `/etc/ssh/sshd_config.d/00-ipat-lab-hardening.conf` exists with mode `0644`. It sets `PermitRootLogin no`, `PasswordAuthentication no`, `PubkeyAuthentication yes` and `KbdInteractiveAuthentication no`.
- The six-minute Stage-2 pending marker `/run/ipat-ssh-stage2.active` is **absent** and the SSH service is **active**.
- A separate password-only/no-public-key client diagnostic offered **only publickey** to the real `openai` connection and failed as expected; **no password was sent**.
- Stage-2 root script had already performed privileged `sshd -t` and synthetic root/openai effective-policy checks prior to the owner's confirmation, according to the operator's successful transcript. We have **not** independently repeated privileged `sshd -T` from every possible real source or performed a timed-rollback failure drill.
- TCP listeners remained SSH/22 plus loopback DNS. The host firewall, provider ACL and K3s settings were **not changed**. Do not claim firewall hardening solely from successful SSH hardening.

**No provider snapshot exists**; do not treat a six-minute transient SSH rollback or the earlier partial Mac archive as complete disaster recovery.

## 2. Observed single-node K3s host prerequisites

A new rootless script at `deploy/scripts/lab/k3s-readonly-preflight.sh --report` was run through SSH **without sudo**. Observations:

| Area | Actual observed result | Interpretation |
|---|---|---|
| OS / CPU | Ubuntu 26.04.1 LTS, kernel 7.0.0-34-generic, KVM x86_64, 16 logical CPUs | Source environment verified; not K3s certification |
| Memory | 31,804,836 KiB guest memory; **0 KiB swap** | Restricted lab budget; monitor reservations and future workload |
| Root disk | ext4, 242,757,608 KiB free at sample time | No separate stateful volume or tested persistent class |
| Cgroup | cgroup v2, controllers `cpuset cpu io memory hugetlb pids rdma misc dmem` | Initial cgroup visibility only |
| Time | `NTPSynchronized=yes` | Source-side time sync observed |
| Kernel network | `overlay`, `br_netfilter`, `vxlan`, `nf_conntrack` not currently visible under `/sys/module` | **Do not infer unsupported**; built-in or auto-load capability needs privileged/CNI validation |
| Forwarding | `net.ipv4.ip_forward=0`; bridge netfilter sysctl path not currently readable | Likely needs approved CNI/bootstrap prerequisites; do not manually flip in this preflight |
| Network | `eth0=10.0.0.230/24`, default next-hop `10.0.0.1` | Guest private address; provider NAT/firewall/public ingress routing **unverified** |
| K3s ports | No sampled TCP listeners on 6443/6444/10250/2379/2380 and no sampled UDP 8472/51820/51821 | No observed collisions; not proof of provider filtering |
| Software | `k3s`, `kubectl`, `iptables`, `nft`, `ufw` absent on non-root PATH | Do not install/enable firewall before K3s networking is designed |
| Recovery | VPS console available per owner; no provider snapshot; only partial off-host config archive | **Full independent encrypted backup and restore are not verified** |

## 3. Security/design gates to resolve BEFORE root K3s installation

1. **Provider exposure:** independently confirm the provider's actual public ingress path and source-restricted SSH management rule (with successful new SSH + tested VPS console fallback). Do **not** allow public TCP/6443 Kubernetes API, public UDP/8472 Flannel VXLAN, or public node metrics/kubelet ports. Neither the private `eth0` address nor `ss` results verify provider ACLs.
2. **Recovery:** create a separately held *encrypted and recoverable* full **app/config/datastore-oriented** backup design; do an isolated integrity/decryption/restore rehearsal before deploying any stateful subscriber/tenant PostgreSQL data. Reproducible OS bootstrap and provider console are still necessary because no VM snapshot/block-level recovery exists. Do not save root/private keys or secrets to GitHub.
3. **ADR-017:** distinguish a disposable *one-server lab* from later multi-node/multi-provider K3s architecture. Compare private overlay/tunnel options, default CNI, cluster/datastore recovery, pod/service CIDRs and provider NAT before setting CNI or binding `6443`. Do not silently adopt an unapproved production datastore/overlay.
4. **Capacity:** keep this node at restricted **16-vCPU / ~30-GiB / 250-GB** scope. ADR-013 pilot baseline remains **16 vCPU / 64 GiB-class / ~1-TB NVMe**; no benchmarking or scaling claim from K3s prerequisites.
5. **Next changes:** prepare staged, SHA-256-pinned and reviewable root bootstrap with no public device ingress; owner supplies sudo locally. Install *only after* network and restore gates are recorded. Re-run SSH/public-port/cluster readiness checks and record actual results after each authorized step.

References verified 2026-09-25: [K3s system and firewall requirements](https://docs.k3s.io/installation/requirements), [K3s network options](https://docs.k3s.io/networking/basic-network-options), [datastore strategies](https://docs.k3s.io/datastore), [official K3s backup/restore](https://docs.k3s.io/datastore/backup-restore), and project [ADR register](DECISIONS.md). The K3s server token must be protected as part of K3s datastore recovery, but no K3s token has yet been issued or backed up.

**Acceptance:** Stage-2 SSH post-confirmation **verified for current key and current client source**; K3s rootless preflight **PASS as inspection only**; network/firewall, privileged module configuration, encrypted independent recovery, cluster datastore/overlay selection, real device tests and K3s install **NOT DONE**.
