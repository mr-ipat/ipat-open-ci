# IPAT native host firewall control plane — vendor-neutral design (R4.8)

**Status:** `PROPOSED / LAB DRY-RUN ONLY`. The product MUST NOT depend on or integrate with any external hosting provider's firewall API. Its optional native firewall capability will manage **only** explicitly enrolled Ubuntu hosts using a separately authorized local node agent. Network perimeter controls outside those hosts remain an operational dependency, not part of the IPAT product.

**Evidence snapshot:** An independent, authorized Mac-to-Ubuntu check previously observed an existing shared external `allow-all` security group admitting inbound IPv4 and IPv6 and a public dual-stack SSH listener. The group is shared with other virtual machines; do not edit it. Actual independent out-of-band console login is still unsuccessful. No provider-side firewall and no guest host firewall change is made in R4.8.

## 1. Product boundary and safe architecture

```text
IPAT platform operators (MFA / RBAC+ABAC deny-by-default)
   -> proposed policy with immutable diff and approved scope
   -> dual authorization for global ingress / risky changes
   -> durable audit and bounded asynchronous change request
   -> narrowly scoped privileged IPAT host-firewall agent
   -> dedicated, namespaced Linux nftables-owned table (planned)
           no global ruleset flush
           preserve external rules and K3s/CNI ownership
           independent watchdog and rollback
   -> independent IPv4 and IPv6 login/ingress tests
   -> validated policy state, audit outcome and expiry reconciliation
```

The `firewall-policy` Rust crate introduced in this milestone is only a **pure proposal validator**. It does not parse arbitrary nft commands, access the kernel, execute shell commands, hold root credentials, configure guest/provider firewalls, or open K3s ports. IPAT must never advertise live firewall deployment from this crate alone.

Future node-side execution must be a *separate root-isolated service* with a mutually authenticated Unix-socket or certificate-based narrow API, host identity, signed bounded policy digest and least privilege. The web/API/tenant containers must not have `CAP_NET_ADMIN`, `hostNetwork` or host firewall socket access. Separate `platform.network.read`, `platform.network.propose`, `platform.network.approve`, `platform.network.apply`, and `platform.network.rollback` grants are **PROPOSED** and require signed role/approval matrix decisions; tenant operators cannot change host-global firewall ingress.

## 2. Default-deny proposed policy

- **IPv4 + IPv6:** default-deny new inbound guest-host traffic in a planned **dedicated** inet-family host table; preserve loopback, established/related flows, necessary IPv6 ICMPv6 neighbor discovery/router advertisement/PMTU, and actual validated DNS/NTP/management dependencies. Nothing is installed until tested.
- **SSH management:** source CIDRs must be explicit single-host IPv4 /32 or IPv6 /128; no `0.0.0.0/0` or `::/0`. Dynamic client source addresses need a reviewed stable VPN or management bastion before lockdown. An allowed /32 is not evidence that the client address is static; confirm fresh egress immediately before transaction.
- **Public HTTPS:** proposed only after verified tenant-domain ownership, TLS policy and controlled ingress. No other protocol ports inherit an arbitrary public allow.
- **K3s control plane:** TCP/6443 only over a separately validated private cluster interface/subnet; TCP/10250 and TCP/2379–2380 only on required trusted node relationships; UDP/8472 for Flannel VXLAN (or actual selected WireGuard/CNI paths) must not be exposed publicly. Never blindly copy a proposed single-node template into later multi-node CNI/forwarding. Reference official K3s requirements: https://docs.k3s.io/installation/requirements .
- **Non-interference:** host firewall design may use native nftables on Ubuntu, but `nftables` can overlap with iptables-nft and K3s CNI rules. Do not enable both competing rule managers blindly, do not use `flush ruleset`, and do not impose a global `forward` chain before selecting/validating the actual CNI and container networking. Ubuntu documentation: https://documentation.ubuntu.com/security/security-features/network/firewall/nftables/ .
- **Tenant-boundary caution:** host policy is shared infrastructure and cannot substitute for Kubernetes NetworkPolicies, application RBAC+ABAC, authenticated USP/CWMP device identities, PostgreSQL RLS, queue isolation or certificate boundaries. IPAT's high-risk policy changes require immutable diff, reason, time-bound approval, audit actor and independent result evidence.

## 3. Implementation status, safety gates and rollback

| Phase | Prerequisite | Status |
|---|---|---|
| Provider-neutral sources and docs | No provider firewall API integration in current repository | **PASS for current tracked HEAD**; older Git revisions remain historical |
| Selected root-config encrypted backup | Real sudo stream snapshot plus read-data isolated restore | **PASS** (Restic snapshot `abaa9827` verified independently) |
| Full system data recovery | Independent recovery of Mac repository/key, root host private keys strategy, later K3s datastore and PostgreSQL backups | **NOT VERIFIED** |
| External out-of-band console | Actual owner login or independently demonstrated equivalent | **BLOCKED** |
| Dry-run Rust validation | Explicit management CIDR, public TLS evidence and verified private-cluster scope; always `executable=false` | **PASS for nine unit tests on real Ubuntu 26.04.1 and GitHub CI**; not real packet filtering |
| Privileged host agent | Actual nftables coexistence analysis, minimal privileges, signed requests, time-limited rollback and fresh dual-stack management verification | **NOT IMPLEMENTED** |
| On-host rollout | Out-of-band recovery and complete scenario testing; documented rollback verified before any enable | **PROHIBITED NOW** |
| K3s/DB/customer data | Approved ADR-017 networking and appropriate stateful restore gates | **NOT STARTED** |

**Required future rollback design:** first capture existing host ruleset, route, SSH/listener baseline and hash it in encrypted backup; perform a controlled `nft -c` validation with the selected OS/CNI and an independently reachable console. Arm a *persistent*, out-of-band verified rollback mechanism **before** any state change, apply only the IPAT-owned table atomically, verify a **new independent SSH session** and both IP families from authorized vantage points, confirm before timeout and log results. A timer alone is not a substitute for tested rescue access; planned maintenance must handle reboot midway. Test rollback against an intentionally failing lab rule on a disposable node first. No such action was performed in this milestone.

## 4. Current Rust crate contract

`crates/firewall-policy/src/lib.rs` validates proposals with explicit `Zone::Management`, `Zone::PrivateCluster` and `Zone::PublicTls`. It rejects public SSH/Kubernetes port allow-all, unverified overlay scopes, unverified public TLS, missing management rule, duplicates and excessive requests; outputs a non-executable dual-stack default-deny **intent**. It has no network write API and its caller still needs strong host/source ownership checks before policy application. The Rust unit tests exercise only pure validation, not actual nftables or CNI behavior.

**No external provider integration is in scope.** The project's formerly provider-named laboratory documents and read-only utility names are being renamed/sanitized to generic `external`/`edge` terms without erasing technical observations; Git's existing historical commits remain immutable records. No network policy has been deployed on any host.


### Actual R4.8 source verification

PR #27 merged to private `main` as `620651aedfbd273a35f5493ab2004283a4c9710e`, with final GitHub-hosted CI PASS. A fresh real Ubuntu 26.04.1 run of the canonical merged SHA passed all **32 Rust synthetic/unit tests** (including nine in `firewall-policy`), Rust formatting, and 28 existing Python static checks. No actual Linux nftables or Kubernetes CNI operation was run. Latest source `49f546b4` and the previously captured selected-root-config `abaa9827` were separately recovered from Restic encrypted snapshots with full integrity checks (12 snapshots/22 packs). A successful selected-config archive recovery is **not** a complete host/disk or future database disaster recovery test.
