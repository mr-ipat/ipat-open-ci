# IPAT R4.5 — hosting provider VPS security preflight and temporary encrypted Mac backup

**Date:** 2026-09-25, Asia/Jakarta. **Lab only.** Reviewed against the current project brief, PRD AC-07, SECURITY, DECISIONS and R4.4 live-host status.

## 1. Actual temporary encrypted backup performed on the authorized Mac

**Host:** the authorized Mac `operator.example.invalid` (separate host from hosting provider VPS). Official Homebrew `restic 0.19.1` was installed under user-controlled Homebrew, with no Ubuntu package, root, firewall or network-service changes.

- Repository directory: `~/IPAT-secure-backups/restic-lab-v1` with mode `0700`. Restic v2 encrypted format was initialized, repo identifier beginning `8b539c4534bf`.
- A cryptographically generated high-entropy repository passphrase was stored only as an item in the user's **macOS login Keychain**, service `id.ipat.lab.restic.backup.v1`, account `ipat-lab-backup`. It is provided to restic using `RESTIC_PASSWORD_COMMAND` and the native `security find-generic-password` command. **No passphrase is printed here, saved in Git, placed directly in environment variables, or copied to the VPS.**
- First snapshot `c5447733`: encrypted copy of the earlier **PARTIAL** Mac-local VPS configuration tar archive, including the owner-readable Stage-1 config set. Restored separately to a private disposable Mac directory and verified archive SHA-256 equals the previously confirmed `2d74782d0e418262701107be01e91c0ea87d3b7406803ca58acdb91a57338a77`; tar archive content listing succeeded.
- Second snapshot `f38403d0`: streamed canonical Git `main` as a tar through `restic backup --stdin-from-command`, revision `d5ac374eec5fff27a2f58bbc1f8887768050e2f4` at the time of capture. Restored separately into a private disposable directory, checked full archive SHA-256 against a freshly computed `git archive main` stream, and verified the brief, decisions and project status paths exist.
- `restic check --read-data` read all repository packs and returned **no errors** with both snapshots present. The temporary decrypted test restore directories were removed after verification. Use `deploy/scripts/lab/backup-mac-restic.sh --backup-source` after each approved main merge, then `--verify` to verify the current main snapshot and the partial config.
- **IMPORTANT:** The original unencrypted PARTIAL tar file still exists in a mode-0600 folder from the previous milestone. macOS **FileVault is currently OFF** according to `fdesetup status`; the encrypted restic repository and its Keychain passphrase are stored on the SAME Mac. This setup protects each restic snapshot cryptographically, but **does not establish independently recoverable key custody or Mac whole-disk encryption**. Before placing root SSH host private keys or any actual tenant data into backup, the owner must enable FileVault and keep a copy of the restic recovery password in an independently protected password manager/offline vault. Do not paste it into ChatGPT or store it inside this repo. Do not automatically delete the original partial archive until a replacement and recovery plan are explicitly accepted.
- The user selected Mac as a **temporary** destination. It is off the VPS, but a loss/compromise of both the Mac backup repository and its local-only Keychain item can make recovery impossible. A second independent encrypted copy/destination is REQUIRED before any production-like stateful data.

**Coverage limits:** This is a successful encrypted **partial configuration + Git-source** backup and isolated restore exercise. Root-only cloud-init files, root-owned configuration, VPS filesystem/block image, future K3s datastore/server token and PostgreSQL application data **are not backed up by these two restic snapshots**. It **DOES NOT** meet the PRD's AC-07 PostgreSQL backup/isolated-restore acceptance condition; PostgreSQL and K3s have not been installed.

### Source-safe repeatable commands (Mac only)

```bash
# Only on reviewed, clean local 'main':
bash deploy/scripts/lab/backup-mac-restic.sh --status
bash deploy/scripts/lab/backup-mac-restic.sh --backup-source
bash deploy/scripts/lab/backup-mac-restic.sh --verify
```

No cron/launchd recurrence or unattended Keychain-unlock guarantee has been implemented. Do not claim automated backups until they are separately tested. `--backup-partial` intentionally backs up only the previously integrity-verified historical config archive.

## 2. External ingress and Ubuntu guest observations

- Hosting provider intentionally omitted from product documentation. Public DNS `hub.example.invalid` resolved to an IPv4 address and **no AAAA** result was returned in the inspected DNS lookup; this does not prove the provider's IPv6 firewall rules are secure.
- A small, authorized TCP connection-only test from the Mac **accepted port 22**. Ports **80, 443, 6443, 10250, 2379 and 2380 did not complete connections** from this one source at inspection time. Because K3s and HTTP services were not running, this is **NOT proof** that external provider Managed Firewall denies those ports.
- UDP VXLAN/8472 and WireGuard/51820+ were **not scanned**. external provider's actual provider-managed IPv4 and IPv6 rules have not been inspected in the owner's panel. Ubuntu `ufw`, `nft` and Kubernetes network controls have not been installed or changed during R4.5.
- Ubuntu's internal `eth0` is on a private subnet and uses a private gateway. DNS/public access does not establish the exact NAT or rule chain. SSH Stage-2 live key-only access is already verified separately; keep it untouched until a separate provider network safety gate.

### External perimeter dependency observed (not an IPAT integration)

Historic owner-provided evidence showed a shared external security group allowing all inbound IPv4 and IPv6. Host SSH public-key authentication alone does not restrict ingress to source networks. This is an **external operational prerequisite**; IPAT does not control any hosting provider firewall API.

Host-based firewall and network-policy design is tracked in `FIREWALL_CONTROL_PLANE.md`. No external security group, host rules or Kubernetes network settings were changed. Do not change externally shared security groups; keep out-of-band recovery working before any host firewall application.

K3s official network prerequisites and prohibition on public VXLAN/8472: https://docs.k3s.io/installation/requirements . Any pod-network CIDR, K3s datastore layout, private overlay/VPN or HA network decision requires an explicit reviewed ADR-017 entry.

## 3. Decision / acceptance state

| Gate | Actual status |
|---|---|
| Encrypted restic repository on distinct Mac | **PASS** (temporary lab only) |
| Mac historical partial VPS config snapshot | **PASS** encrypted, isolated restore SHA verified |
| Canonical source snapshot at recorded revision | **PASS** encrypted, isolated restore SHA verified; repeat after next main merge |
| Repository full-pack integrity check | **PASS**, two snapshots and four packs at verification |
| Mac FileVault | **OFF** — **BLOCKER** for storing root private host keys/customer material on this Mac |
| Independent passphrase escrow / second backup location | **NOT VERIFIED** |
| Root-owned full VPS config / database / K3s restore | **NOT DONE** |
| Provider firewall current rule inventory | **NOT AVAILABLE** without owner's external provider panel evidence |
| External port availability check | **OBSERVATION ONLY**; 22 responded, other sampled TCP did not |
| external provider firewall change / K3s install | **NOT PERFORMED** |
| PRD AC-07 PostgreSQL isolated restore | **BLOCKED** until an actual database, backup and clean restore test exist |

Next: obtain redacted external provider Managed Firewall rule inventory and tested recovery-console evidence from the owner; enable FileVault and independently escrow the Keychain-held restic secret; then design a one-time privileged **streamed-to-encrypted-repository** config backup without leaving plaintext root files on the Mac. Only after validated recovery/network gates prepare a pinned, isolated/disposable K3s single-node lab bootstrap. Do not claim production HA or tested physical ZTE/C-DATA/VSOL/MikroTik compatibility.


## 4. Follow-up after R4.5 code merge

- R4.5 implementation PR #22 merged into private GitHub `main` as `deecfed13bfa6d453816e89af0b3592c8a541067`.
- Mac-only repeatable backup script was then executed with `--backup-source` on that clean exact `main`; latest canonical source snapshot at this checkpoint is `2ee0cc82`.
- Its `--verify` mode **ACTUALLY PASSED** `restic check --read-data` on **three snapshots and six packs**; restored the new canonical Git tar and original PARTIAL config tar into separate private throwaway directories; compared both actual restored SHA-256 values with independent expected source/archive hashes, verified known archive entries and removed test directories.
- Final R4.5 PR GitHub-hosted main CI `36115936092` **SUCCESS**, including nine new source-only backup/external provider static checks, nine previous static SSH/K3s checks, formatting and 23 locked Rust synthetic/unit tests.
- The exact reviewed private GitHub `main` commit was synchronized to the Mac and Ubuntu lab non-root workspace via an authenticated temporary Git bundle; independent SHA comparison succeeded; SSH still active and the Stage-2 pending marker was absent. There was **NO privileged backup, external provider ACL/firewall, host firewall, K3s or PostgreSQL modification** in this checkpoint.
- As this report itself may be committed in a subsequent documentation-only revision, use `--backup-source` and `--verify` again after that revision to encrypt/check the final latest `main`. The milestone does not claim any complete root-only config, database or K3s recovery readiness.


## R4.8 superseding note

Later evidence confirms an actual additional encrypted and independently restored **selected root-readable** configuration archive (`abaa9827`) as documented in [the latest status](PROJECT_STATUS.md); the partial-user-config-only gap described above is historical. The native [host firewall policy design](FIREWALL_CONTROL_PLANE.md) replaces provider-specific firewall ideas in the product roadmap; this file preserves generic historical exposure facts only.
