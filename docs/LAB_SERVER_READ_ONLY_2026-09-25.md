# IPAT — Laboratory server read-only preflight

**Date:** 2026-09-25 (Asia/Jakarta); **evidence:** direct SSH commands on the target machine through authorized Mac `operator.example.invalid`. **Scope:** inspection only; no Ubuntu configuration, packages, services, firewall, SSH authorization, or deployment were changed.

## 1. Connection and host identity

| Item | Directly observed result |
|---|---|
| SSH target | `ipat-lab` alias: `openai@hub.example.invalid:22` |
| Login | Dedicated Ed25519 public-key authentication **PASS**; `ssh -T -o BatchMode=yes -o StrictHostKeyChecking=yes ipat-lab` |
| SSH trust | ED25519 server host key matched the pre-existing local `known_hosts` entry; this does not independently attest provider ownership |
| User | UID 1000, group `openai`, member of `sudo` |
| Local hostname | `ipat` |
| OS | Ubuntu **26.04.1 LTS** (`VERSION_ID=26.04`) |
| Kernel | `7.0.0-34-generic`, `x86_64` |
| Virtualization | KVM; virtual CPU model `Intel Core Processor (Broadwell, IBRS)` |
| Time synchronization | `NTP=yes`, `NTPSynchronized=yes`, `systemd-timesyncd=active`, timezone `Asia/Jakarta` |

## 2. Observed capacity

| Resource | Read-only observation |
|---|---|
| Logical CPUs | **16 vCPU**, `nproc=16`; this is a KVM virtual allocation, not measured dedicated CPU capacity |
| Memory | `free -h`: **30 GiB** reported total and about **29 GiB** available at inspection time |
| Swap | **0 bytes** configured; evaluate workload budgets/K3s swap policy before changing this |
| Primary disk | `/dev/sda` **250G**, `/dev/sda3` **249.8G ext4** mounted as `/` |
| Root file system | `df -hT`: **246G total, 3.1G used, 233G available (2% use)** |
| Boot disk | `/dev/sda2` 200M EFI FAT; no separate data volume observed in `lsblk` |
| Inode use | About **1%** of root inode capacity |
| Reboot-required marker | Not present at inspection time |

**Capacity interpretation:** this is the previously discussed *constrained* 16-vCPU / approximately 32-GB-class RAM / 250-GB VPS. It is **below** the provisional 16-vCPU / 64-GiB-class / ~1-TB-NVMe pilot baseline recorded in `IPAT_PROJECT_BRIEF.md` and ADR-013. Pilot sizing decisions are NOT silently changed. Use only scoped laboratory workloads with explicit telemetry retention/storage limits and monitor capacity before adding stateful components. Disk type/IOPS and independent offsite backups are NOT verified.

## 3. Network and security observations

- Interface: `eth0` up with private address `10.0.0.230/24`; default route via `10.0.0.1`. Public DNS resolution and successful remote SSH do **not** establish whether the host is exposed through NAT, provider firewall or a different routing arrangement.
- Listening TCP sockets at sampling time: OpenSSH port `22` bound on all IPv4/IPv6 addresses; local resolver port `53` bound to loopback addresses. No IPAT HTTP/ACS/USP listener was observed.
- `ssh` service was active; `systemd-timesyncd` active. No active service was reported for PostgreSQL, Docker/containerd, K3s, reverse proxies or fail2ban; absence of active state alone does not prove a package is uninstalled.
- `ufw`, `nft`, `fail2ban-client` were not available on the command path. This **does not prove no firewall exists**: kernel/provider/NAT policies were not inspected. The effective SSH daemon policy was not retrievable without privileged access; do not assume password or root login is disabled.
- User home mode `0750`, `~/.ssh` mode `0700`, `authorized_keys` mode `0600`. Public-key login succeeded. Membership in the `sudo` group was seen, but noninteractive `sudo -n -l` did not succeed; unattended privileged provisioning is not yet authorized/verified.
- `apt-daily.timer` and `apt-daily-upgrade.timer` were enabled, but an `unattended-upgrades` unit was not found. Actual security-patch posture and provider image maintenance history are NOT verified.

## 4. Installed-tool observations

Found: `git`, `jq`, `curl`, `openssl`, `python3`, OpenSSH. Not found in the account's command path: `cargo`, `rustc`, `rustup`, `docker`, `podman`, `k3s`, `kubectl`, `helm`, `ansible`, `psql`, `pg_dump`. No installation was attempted. A command missing from PATH is not conclusive proof the binary is nowhere on disk.

## 5. Gated next steps (none executed here)

1. Report these observations to the product owner **before modifying the server**. Confirm that the smaller VPS is an intentional restricted laboratory environment rather than substituting it for the commercial pilot sizing baseline.
2. Obtain explicit approval for the change plan and a recovery path: VPS console/snapshot, source IP allowlisting/provider firewall validation, SSH credential handling and rollback. Inspect the effective `sshd` policy using approved privileged read-only access; do not disable password auth or change firewall until verified public-key access **and** rescue route are demonstrated.
3. Agree on a bounded lab service/storage plan; pin Rust and K3s versions using the repository, then provision in reviewed stages only after separate permission to change host configuration.
4. Validate off-host backup destination, isolated restore procedure, tenant identity plan and exact physical inventory; no lab device has been accessed/tested during this preflight.
5. Repeat and record post-change verification (identity, login, firewall, service health, disk/memory) after each authorized deployment stage.

**Acceptance state:** SSH read-only access and OS/capacity/network baseline **PASS**; host hardening, automated provisioning, real-device interoperability, native USP, tenant E2E security, performance, HA and backup/restore tests are **NOT RUN / NOT VERIFIED**.
