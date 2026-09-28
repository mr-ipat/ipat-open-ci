# Stage 2 — guarded SSH key-only hardening (COMPLETED; HISTORICAL PROCEDURE)

**Current outcome, 2026-09-25:** The owner applied this step and confirmed a fresh key-only connection before disarming the timer. A further independent Mac SSH login and negative password-only diagnostic succeeded. **DO NOT RE-RUN this procedure.** Live verification and next security gates are in [the newer lab report](../../../docs/LAB_K3S_READ_ONLY_2026-09-25.md). The historical pre-application instructions below remain for reproducibility, not as an instruction to apply them again.

**Dependency:** Stage 1 is now independently verified on the actual Ubuntu 26.04.1 VPS: `build-essential`, `cc` and Rust 1.98.1 installed; formatting and all 23 locked unit/simulator tests pass. A **partial** off-host Mac backup and root-only local stage-1 package/config backup exist, but **there is NO VPS snapshot or complete disaster recovery backup**. Do not deploy stateful customer data yet.

Why this stage: the privileged stage-1 report at `/home/openai/.cache/ipat/stage1-sshd-policy.txt` showed effective `PermitRootLogin yes` and `PasswordAuthentication yes` for synthetic loopback contexts for both `openai` and `root`. These synthetic contexts do not replace independently testing a real new SSH connection. Ubuntu's OpenSSH uses the first matching directive in early lexical drop-ins; an early `00-` managed snippet is used rather than appending to the main file.

**Reviewed source:** `stage2-ssh-key-only.sh` is the only root script. `apply-stage2-from-mac.sh` is the one-time interactive authorized Mac operator. The helper refuses dirty/non-main/unverified Git source, requires the pinned root-script SHA-256 and verified partial Mac backup digest, and transfers source via an authenticated Git bundle without storing GitHub credentials on the VPS. Do not execute root scripts directly from a writable user checkout.

**Scope:** Only `/etc/ssh/sshd_config.d/00-ipat-lab-hardening.conf` is introduced. Intended policy: `PermitRootLogin no`, `PasswordAuthentication no`, `PubkeyAuthentication yes`, and `KbdInteractiveAuthentication no`. Disabling password SSH affects *every account*, not just `openai`. This does **not** change Linux passwords, console access, SSH port, firewall, routing, fail2ban, service packages or authorized keys.

**No-snapshot safety:** The stage-2 script uses a root-only baseline archive of the existing SSH configuration. **BEFORE** installing the new snippet, it schedules a transient systemd timer to revert the snippet and reload SSH in six minutes. It validates `sshd -t`, synthetic-context `sshd -T`, and service state before returning. A newly established **independent** Mac public-key SSH connection is mandatory; then the owner enters **CONFIRM** and supplies sudo authentication in the local Mac Terminal to disarm the timer. If verification or confirmation fails, **do not confirm**: allow the timer to restore previous SSH behavior, and use the independently accessible VPS provider console if needed. A reboot during the six-minute window can interrupt the transient timer; **do not reboot** until confirmation. This is a timed configuration safety net, not a disk/snapshot rollback guarantee.

Operator steps:
1. Test *actual* rescue-console login in the VPS provider's browser panel; leave that console open throughout.
2. Keep access to the Mac-local verified partial archive; read this runbook and the script. Be prepared for global password-SSH denial.
3. In the *authorized Mac interactive Terminal only*, run:
   ```bash
   bash ~/Projects/ipat-current/deploy/scripts/lab/apply-stage2-from-mac.sh
   ```
4. Type `CONSOLE_READY` and `DISABLE_PASSWORD_SSH` only after reviewing scope. Enter the **Linux sudo password locally** when prompted; never paste it into ChatGPT or GitHub.
5. The helper establishes an independent new key-only session and then prompts `CONFIRM`. Complete confirmation promptly within six minutes. If uncertain, **do not confirm**; let the timer revert. Afterward, verify again that `ssh ipat-lab` works.

Verification already executed **before privileged application**: Mac `bash -n` for root script and helper, root-script SHA-256 vs helper, Ubuntu `--check` (read-only) and non-root `--apply` denial **PASS**. GitHub CI includes syntax/digest/static policy-order tests. The actual privileged stage and timer behavior are **NOT RUN** until the user follows the local interactive procedure. Log results in `docs/PROJECT_STATUS.md`; do not claim hardening merely because this file was committed.

Next separate gates: secure provider ingress/source allowlisting, audited host firewall, K3s network/CNI design, independently recoverable encrypted offsite backup and restore rehearsal. **Never enable firewall + SSH changes together** on this snapshotless VPS.
