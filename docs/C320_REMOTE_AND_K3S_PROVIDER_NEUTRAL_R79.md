# R7.9 — Real network path candidate to remote C320; provider-neutral K3s

**Date:** 2026-09-27 · **Developer:** Mr. iPat
**Scope:** SSH READ-ONLY transport candidate plus provider-neutral OFFLINE
K3s topology plan. Neither a physical C320 interop pass nor live
cross-provider cluster installation is claimed.

## Owner-requested clarification and independent source boundaries

The owner explicitly requires IPAT to reach the ZTE C320 remotely
over a supported management interface, not a Layer-1 physical
connection at the IPAT VPS. This is compatible with the existing PRD:
ZTE's historical C320 product description names SSH CLI, SNMP
v1/v2/v3 and vendor NetNumen U31 management. Historical manuals
are NOT evidence that the owner's present board/firmware enables
SSH public-key login, noninteractive SSH exec, SNMPv3 or a REST API.
For DEV-01 choose verified remote SSH CLI FIRST as one fixed
read-only inventory candidate and SNMPv3 as a separately testable
telemetry adapter candidate. No unproven generic OLT TR-069
controller endpoint is claimed; CWMP remains targeted at ONTs/CPEs.
Reference: https://en.cdr.pl/download/ZTE/ZXA10_C320_(v1.2.0)_product_description.pdf

The owner's K3s requirement is provider independence, NOT
dependency on any given vendor's security-group or firewall API.
The official K3s multicloud documentation permits heterogeneous
agents through private / WireGuard network designs, but explicitly
warns against cross-network multi-server embedded etcd HA. See:
https://docs.k3s.io/networking/distributed-multicloud
https://docs.k3s.io/installation/requirements
https://docs.k3s.io/networking/basic-network-options
**Absence of a host firewall is NEVER equivalent to proof of
protected API/CNI ingress.** Separate private encrypted transport,
node identity, port reachability, exposed-interface checks,
recovery and security review remain mandatory. No live VPS
firewall, external provider integration or K3s installation
was needed to generate or test the R7.9 plans.

## Implemented code and tests (synthetic, reproducible)

- `deploy/scripts/lab/r79/c320-ssh-readonly.py` checks a private
  owner 0700 directory containing exactly three owner 0600 files:
  `plan.json`, `known_hosts`, `id_readonly`. It accepts only
  an RFC1918 management IP through a privately reachable route,
  one explicitly approved SSH nonroot read-only account, and
  an independently pinned EXACT SSH host key (never ssh-keyscan
  self-approval). By default `--requirements` and `--check-plan`
  perform NO network activity and `--check-plan` returns only
  HUMAN_REVIEW_REQUIRED at its most permissive.
- A bounded `--collect` exists but requires ALL six explicit
  operator declarations and a SEPARATE environment opt-in.
  It runs only fixed `show card` and `show version-running`
  OpenSSH commands (no password, ssh-agent, telnet,
  proxy commands, port forwarding, config mode, upload,
  reboot or firmware). `-F /dev/null` avoids ambient SSH
  config; strict explicit known_hosts and short timeouts
  fail closed. Firmware lacking SSH key/noninteractive exec
  will FAIL and require separately reviewed SNMPv3
  or operator-owned transport alternative, NOT weaker fallback.
- Raw CLI capture is written only into an EMPTY private
  0700 directory as fixed owner 0600 files, and must remain
  on a verified encrypted owner filesystem. NO raw output
  or IP/host key/username is printed by the script.
  The operator must redact any real SN/account identifiers
  before invoking the existing offline Rust parser or
  putting any evidence into Git/ChatGPT. Any successful
  collection remains review-only until independently
  checked physical tuple and device evidence are recorded.
- `deploy/scripts/lab/r79/k3s-provider-neutral-plan.py`
  generates an OFFLINE, provider-agnostic single-node or
  one-server/multi-provider-worker topology using fixed
  RFC1918 pod/service/private CIDRs. The multi-provider
  profile requires an independently created and trusted
  `wg-ipat` encrypted VPN interface on EACH node;
  it plans Flannel VXLAN OVER that existing private
  tunnel, with K3s API reachable only via the tunnel.
  Worker architectures may mix x86_64 and aarch64.
  ALL plans return `installation_authorized=false`,
  reject overlapping CIDRs, unsafe public/duplicate IPs,
  unsupported multi-cloud embedded-etcd control-plane HA,
  and list independent external prerequisites.
  No provider API, shared security group or host
  firewall installation is part of this generator.

## Commands (no real device or privileged K3s operation)

    # On the authorized Mac or existing nonroot Ubuntu repository:
    python3 deploy/scripts/lab/r79/c320-ssh-readonly.py --requirements
    python3 deploy/scripts/lab/r79/c320-ssh-readonly.py \
      --check-plan "$HOME/.local/share/ipat/c320-r79-private"
    python3 deploy/scripts/lab/r79/k3s-provider-neutral-plan.py \
      --example > "$HOME/private-provider-neutral-plan.json"
    python3 deploy/scripts/lab/r79/k3s-provider-neutral-plan.py \
      --plan "$HOME/private-provider-neutral-plan.json"
    bash deploy/scripts/lab/k3s-readonly-preflight.sh --report
    python3 -m unittest discover deploy/scripts/lab/r79 \
      -p test_c320_ssh_readonly.py -v
    python3 -m unittest discover deploy/scripts/lab/r79 \
      -p test_k3s_provider_neutral.py -v
    # After real locked Rust CLI build in a disposable test checkout:
    python3 -m unittest discover deploy/scripts/lab/r79 \
      -p test_remote_ssh_to_rust_contract.py -v

The provided example has VPN/recovery/rescue assertions FALSE,
so it can NEVER grant deployment. The remote SSH packet and
optional `--collect` contain real identity material and MUST
be assembled locally by the authorized operator OUTSIDE Git;
do not send it to the chat. No collection was executed
against a real device during R7.9.

## Evidence obtained during this milestone

The previous final canonical release at commit 38a2299
independently finished GitHub run 36288374221 SUCCESS 4/4.
Actual nonroot Ubuntu 26.04.1 VPS read-only K3s inventory:
x86_64 / 16 logical CPUs / KVM / cgroup2. Several CNI
kernel modules were not CURRENTLY VISIBLE; this is
not proof they are unavailable or an installation failure.
Actual network and external provider isolation are
UNVERIFIED. The existing K3s live install gate remains
blocked until independent console, offsite full restore,
approved transport and separate safe rollout.

R7.9 code was executed in an ISOLATED nonroot Ubuntu
VPS Git worktree with no changes to live K3s/firewall
or physical OLT. In that worktree a real locked Rust
C320 offline parser was built, and 17/17 Python tests
including fake SSH→REAL Rust parser PASSED.
Synthetic results are NOT evidence of actual
remote ZTE C320 compatibility. PR CI final results
must be appended only AFTER their real execution.

## Next prerequisites and acceptance

MUST before real C320 test: owner provides privately
a routable RFC1918 management endpoint over approved
management VLAN/VPN, real separate read-only identity
with independently pinned host key, and verification
that actual firmware supports noninteractive SSH exec.
If it does not, use an independently designed SNMPv3
read-only probe with its exact device MIB and real
firmware model; never fall back to Telnet or unknown
API/TR-069. A physical serial/L1 connection is
NOT required for read-only remote management,
but independent recovery becomes mandatory for
future disruptive firmware or provisioning writes.

MUST before live hetero K3s: owner supplies a second
VPS/private-VPN node and independent full-host/offsite
restore + rescue console evidence, approved private
inter-node CIDR/IP/route and overlay reachability.
K3s will NOT activate on a live host merely because
a plan JSON boolean claims readiness; integration
must independently measure true peer routes, API
binding, network policy and worker join/unjoin.
One cloud/provider is NOT a mandatory dependency.
Multi-server etcd HA stays within low-latency
private network, not assumed across arbitrary
clouds; PostgreSQL HA/PITR is a separate workstream.

**RED PRD DEVIATION / INCOMPLETE:** live C320
TC-OLT-01 NOT RUN; no tested firmware upgrade,
real SaaS tenant operator onboarding, live
multi-provider K3s deployment, independent
whole-host disaster recovery or public-domain
customer dashboard. No product-complete claim.


## Creating the operator-private remote C320 packet

Prepare a 0700 folder OUTSIDE Git on the owner-controlled
encrypted capture machine. Add these exactly three
single-link owner 0600 files: `plan.json`,
`known_hosts` and `id_readonly`. DO NOT commit or
send any of their content, even if it seems harmless.

Example `plan.json` (SYNTHETIC IPv4; replace
privately with a real privately routed OLT
management address; booleans begin FALSE):

```json
{
  "target_id": "DEV-01",
  "environment": "isolated_lab",
  "transport": "ssh-strict-pinned-publickey",
  "profile": "zte-c320-exact-two-readonly-show-candidate",
  "private_ipv4": "10.72.4.10",
  "ssh_port": 22,
  "ssh_user": "onlyread",
  "owner_approves_readonly": false,
  "dedicated_readonly_account": false,
  "host_key_independently_verified": false,
  "private_route_verified": false,
  "firmware_supports_noninteractive_exec": false,
  "capture_storage_encrypted": false
}
```

Obtain the ACTUAL remote SSH host public key using
an independent pre-established trusted management
channel or authorized device administrator,
then independently verify its SHA256 fingerprint;
do NOT use `ssh-keyscan` from the same untrusted
route as its own host-key authenticity proof.
The fixed OpenSSH known_hosts line must contain
the exact literal management IPv4 (port 22)
or `[IPv4]:port` for a nonstandard port,
one supported public host key type and key.
`id_readonly` is a separate dedicated
private SSH identity compatible with the
actual firmware (public-key support is STILL
unknown, so do not claim login success).
Owner verifies all six declarations separately.

Only after trusted reviewer approval and
all prerequisites, on actual encrypted private
capture storage with a NEW EMPTY 0700 out folder:

```sh
IPAT_R79_OPERATOR_APPROVES_REMOTE_READ=YES \
  python3 deploy/scripts/lab/r79/c320-ssh-readonly.py \
    --collect "$HOME/.local/share/ipat/c320-r79-private" \
    --out "$HOME/.local/share/ipat/c320-r79-raw"
```

This is a ONE-TIME, opt-in read of TWO fixed
command candidates and never logs their
raw output. If noninteractive SSH exec is
unsupported, it returns failure; never
enable an untested CLI profile or downgrade
to insecure transport automatically.
Real outputs may contain subscriber serials:
keep privately encrypted and redact a
COPY before passing its fixed `cards.txt`
and `versions.txt` to existing R7.1
offline Rust evidence review. Zero real
sessions have been run in this milestone.


## Verified R7.9 code release and exact scope

Original feature PR #87
`370aa6863bb1f5d6f6de09435ea8e2a2cd580e3b`
passed run `36289356652` (all 4 jobs);
it merged to code main
`6ce2e79686caddcaeafa275255b67b49a9befabe`.
Separate post-code-main run `36289553986`
also PASSED all 4 jobs. New 17 R7.9
tests ran in locked Rust job including
the ACTUAL compiled Rust C320 parser
but only SYNTHETIC mocked SSH input.
The disposable Ubuntu26 K3s job ran
the new multi-provider PRIVATE PLAN
tests and existing real SINGLE-NODE
K3s smoke. No real second node joined.

Owner Mac Restic source-only
`0e5eda33` was completely checked
(130/130 encrypted packs) and
isolated exact code SHA256 source
restored; separately selected
historical PARTIAL root config
also restored, NOT a whole-server
offsite replacement test.
SHA256-verified Git bundle safely
moved the exact code SHA to
clean real nonroot Ubuntu26 VPS
checkout, where full locked Rust
workspace, real C320 offline
binary, and all 17 synthetic R7.9
cross-contract tests PASSED again.
Read-only modinfo located both
WireGuard and VXLAN kernel
module files on that host,
without loading either module.
Existing private lab localhost
web service was restarted,
business API forged-Host/
tenant/role HTTP401 reverified.
Product physical and public
K3s deployment gates remain
explicitly UNFINISHED.
