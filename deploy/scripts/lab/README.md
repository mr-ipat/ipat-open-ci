# IPAT Ubuntu laboratory — staged bootstrap

Status: **Stage 1 executed and independently verified on Ubuntu 26.04.1 on 2026-09-25.** Owner authorizes the staged toolchain only by entering their Linux sudo password in their own Mac Terminal. The assistant never receives the password. Historical Stage-1 details follow; this helper should not be rerun unless a new change review requires it. Server is 16 KVM vCPU / 30 GiB guest RAM / 250G disk, below the provisional 16 / 64 GiB / ~1 TB pilot baseline. Keep this as a bounded lab, not a commercial deployment.

## Changes already executed without root

- Dedicated Ed25519 Mac SSH alias authenticates to the existing non-root `openai` account with pinned host-key verification.
- User-only official Rust 1.98.1 toolchain and rustfmt were installed from a TLS-downloaded `rustup-init` checked against its published SHA-256. No APT packages or global environment files were changed by this installer.
- Canonical GitHub private `main` was transferred as a verified Git bundle to `/home/openai/workspaces/ipat`. No GitHub credential, PAT, GitHub deploy token or private SSH key was copied to the VPS. Git bundle remote was removed; future updates require a new verified transfer.
- A **PARTIAL** pre-change backup of user-readable SSH/apt config and `authorized_keys` was saved to the Mac at `~/IPAT-secure-backups/` with private filesystem modes and archive integrity checked. Root-only `50-cloud-init.conf`, host SSH private keys, VM block storage, and application/database data are NOT in this backup.
- Local `cargo fmt --all -- --check` on actual Ubuntu passed, but initial `cargo test --workspace --locked` **failed** because Ubuntu image lacks the system linker `cc`. GitHub runner tests are separate evidence, not an Ubuntu-local pass.

## Stage 1: one-time, narrowly approved privileged action

Prerequisites: owner access to the provider's *functional* out-of-band console, intact Mac private key and partial backup, and approved restricted lab scope. **No provider snapshot exists.** Keep a separate provider console tab open while running the script.

From the authorized Mac's **interactive Terminal** (not inside ChatGPT):

```bash
bash ~/Projects/ipat-current/deploy/scripts/lab/apply-stage1-from-mac.sh
```

The helper checks the off-host partial archive, verifies the Mac main exactly matches private GitHub without auto-updating it, and checks fixed reviewed SHA-256 values for the Mac partial backup and root script, transfers the verified main Git bundle to the non-root account, and runs a read-only Ubuntu `--check`. It then explains the exact change and prompts you to type **APPLY**. Only then it creates a root-owned copy of the SHA-256-verified root script and requests the Linux `openai` user's sudo password **locally in that Terminal**.

The root script checks Ubuntu 26.04, disk headroom, existing SSH access and `sshd -t`; makes a 0700 **local root-only** config/package baseline in `/var/backups/ipat-lab/stage1-*/`; refreshes existing signed Ubuntu APT sources; simulates `build-essential` package resolution, aborts if removals or upgrades of existing packages are planned; installs only `build-essential`; writes a sanitized, clearly synthetic-context `sshd -T` report to `~/.cache/ipat/stage1-sshd-policy.txt` for the follow-up review; verifies `cc` and SSH health. It deliberately does **NOT** modify SSH policy, root login, password authentication, firewall, routing, K3s, DNS, systemd services, database, secrets or user permissions, and does not request a reboot.

After successful installation, the helper runs `cargo fmt --all -- --check` and `cargo test --workspace --locked` as the non-root user on the actual Ubuntu VPS, printing the results. It can be rerun; it will create another dated root backup and repeat an idempotent APT install if invoked again, so avoid unnecessary repeats.

## Stage 2: security hardening requires its own checked change plan

- With approved elevated read-only access, record real effective `sshd -T` including all root-only Ubuntu cloud-init drop-ins and root/openai match context. The *readable main file* currently contains `PermitRootLogin yes` and `PasswordAuthentication yes`, but a root-only early include may override them. Do **not** claim these are effective until verified.
- Establish and **test** the provider console recovery path. Export a complete **encrypted off-host** backup appropriate for the sensitivity of privileged config, and verify that it can be restored; the current partial Mac backup and same-disk root copy are not full disaster recovery.
- Plan key-only SSH with an automatic timed rollback and an independent second session test. Do not change the port, deny password login or disable root SSH in the same transaction as untested firewall changes; preserve known-good access throughout.
- Verify provider ingress controls. K3s networking/CNI and default UFW rules require joint design; avoid exposing control-plane, VXLAN or metrics ports to the public internet. No externally accessible ACS/USP/API listener until tenant/agent auth, TLS, rate limits and server network boundaries are tested.
- PostgreSQL HA/PITR, external backup destination, restore drills, telemetry retention and K3s production configuration remain separate gated milestones. No snapshot means **no stateful real subscriber or device data yet**.

## File paths and verification

- `stage1-root-preflight-and-toolchain.sh --check`: safe rootless read-only preflight.
- `stage1-root-preflight-and-toolchain.sh --apply`: requires root, two independent explicit owner/backup gate variables and is invoked only by the Mac helper.
- `apply-stage1-from-mac.sh`: interactive, prevents dirty repo overwrite, transfers a verified source bundle, validates root-script SHA-256, then requests sudo interactively.
- Actual run evidence and blockers belong in `docs/PROJECT_STATUS.md` and `docs/LAB_SERVER_READ_ONLY_2026-09-25.md`. These shell scripts do not claim production hardening or network-device interoperability.

## Next controlled action

[Stage-2 SSH hardening with six-minute timed rollback](STAGE2-SSH.md) is prepared but **NOT YET APPLIED**. The actual privileged Stage-1 policy report showed synthetic-context root and password SSH enabled; Stage 2 requires independent provider-console login, fresh key-only SSH tests and a separate interactive authorization from the owner. It does **not** enable host firewall or K3s.

## R4.4: Stage-2 completed; next K3s gate

The owner executed the reviewed Stage-2 script and independently confirmed the timer-disarmed public-key-only SSH session. A separate fresh Mac SSH session and a password-only negative probe also behaved as expected; see [execution evidence](../../../docs/LAB_K3S_READ_ONLY_2026-09-25.md). The earlier Stage-2 'NOT YET APPLIED' instructions on this page are chronological preparation history. No provider firewall or Kubernetes port change has been performed.

Run the *read-only* K3s prerequisite inventory with `bash deploy/scripts/lab/k3s-readonly-preflight.sh --report`. It cannot approve a K3s install: private multi-node network, provider firewall, full encrypted independent backup with restore test, and ADR-017 remain unresolved. [Rootless evidence and decision gates](../../../docs/LAB_K3S_READ_ONLY_2026-09-25.md).


## R4.5 temporary encrypted Mac backup and external provider firewall read-only assessment

Use [the actual backup/restore report and provider firewall gate](../../../docs/LAB_ENCRYPTED_BACKUP_EDGE_R45.md). Reviewed Mac-only scripts are `backup-mac-restic.sh --status|--backup-source|--backup-partial|--verify` and `external-readonly-network-check.sh --report`. A high-entropy restic passphrase is held only in the Mac Keychain; repository snapshots of the prior PARTIAL VPS config and canonical Git source passed isolated restore and full read-data integrity checks. **The Mac FileVault is OFF; no root-only VPS config, future PostgreSQL data or K3s datastore is backed up.** Actual external provider Managed Firewall rules were NOT read, and no firewall/K3s change was made. Do not call this production disaster recovery.


## R4.6 external provider dual-stack ingress — observation only

The provider screen reveals `allow-all` inbound IPv4 and **global IPv6**. FileVault is now independently confirmed ON, but a same-Mac Restic Keychain secret still needs independent escrow. [Staged rule-change/rollback design](../../../docs/EDGE_SECURITY_GROUP_R46.md). From the authorized Mac, run `bash deploy/scripts/lab/edge-r46-gate-check.sh --report` to see a current `<MAC_IPv4>/32` **candidate only**, real global guest IPv6 and fresh strict SSH checks. Do not automatically apply this CIDR: the Mac's public ISP IP is not proven static. Do not edit a group shared with other external provider resources; verify group attachments and test the VPS VNC console before any provider ACL action.


## R4.7 — encrypted root configuration streaming, owner-interactive

[Implementation and actual smoke/failure test evidence](../../../docs/ROOT_CONFIG_STREAM_R47.md). Mac-only `mac-root-config-backup.sh` drives `root-config-stream.py` through Restic's failure-aware `--stdin-from-command`. The **unprivileged** live SSH stream, encrypted snapshot, real isolated tar restore and negative producer-failure test have passed. **A real ROOT PRIVILEGED snapshot has NOT been taken**; it requires one local user-entered Linux sudo password from an interactive Mac Terminal after this exact reviewed code merges into private GitHub `main`:

```bash
bash ~/Projects/ipat-current/deploy/scripts/lab/mac-root-config-backup.sh --backup-root
```

This script will prompt for `ESCROW_CONFIRMED_AND_BACKUP_ROOT` and the Ubuntu `openai` sudo password **locally**. It deliberately **does not need external provider VNC** to create the encrypted backup, and never changes a firewall or SSH rule. Its `--verify-root` operation will check an actual root-config snapshot *only after one exists*. Root host private SSH keys and future database/K3s data are excluded; do not describe this as full VPS recovery.


### Root backup prompt visibility (R4.7.1)

If Restic displays **0 files / 0 B** and no visible password prompt, this is NOT proof of completion: the Python producer may be waiting for its **local Mac TTY** sudo-password prompt. Press `Ctrl+C` in the original Mac Terminal to stop that attempt; do not run a second backup while the first is still running. Use the updated reviewed helper on `main`: it suppresses Restic's progress display during the privileged stream and announces the **Ubuntu `openai` sudo password** prompt explicitly. Do not re-enable direct root SSH or send any password to chat. See [actual status and explanation](../../../docs/ROOT_CONFIG_STREAM_R47.md).
