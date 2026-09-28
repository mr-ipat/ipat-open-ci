#!/usr/bin/env python3
"""Mr. iPat / IPAT production readiness: strictly READ ONLY; cannot authorize apply.

This tool deliberately never declares production GO. OOB-console evidence,
independent full recovery and perimeter/architecture approvals cannot be
independently established using the guest's own SSH connection.
"""
from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
import subprocess
import sys
from typing import Any

ROOT = Path(__file__).resolve().parents[3]
SHA_LENGTH = 40

# Required independent, human-verified evidence is NOT inferable from SSH.
# Do not add a command line option to mark these passed automatically.
EXTERNAL_GATES = {
    "independent_out_of_band_console_login": "Actual rescue-console login/recovery must be demonstrated independently.",
    "independent_full_host_restore": "Boot/rebuild an isolated host from a separately held encrypted and complete backup, with tested credentials.",
    "dedicated_ipv4_ipv6_perimeter": "Confirm independently a dedicated node-only ingress boundary, full IPv4+IPv6 rule inventory, new SSH and tested rollback.",
    "approved_private_k3s_network_adr017": "Approve private node overlay/CNI, control-plane binding, public ingress denial, and backup plan.",
    "approved_production_database_adr005_010": "Approve tenancy, independent PostgreSQL HA nodes, credentials, SLO/RPO/RTO and WAL/PITR ownership.",
    "independent_postgresql_pitr_restore": "Prove an off-host base backup+WAL chain restores into an independent isolated PostgreSQL host.",
    "native_host_firewall_approval_and_rollback": "Approve non-shared nftables plan; independently rehearse console-accessible rollback and verify both IP families.",
}

def run_readonly(args: list[str], timeout: int = 12, env: dict[str,str] | None = None) -> str:
    completed = subprocess.run(args, cwd=ROOT, capture_output=True, text=True,
                               check=False, timeout=timeout, env=env)
    if completed.returncode != 0:
        # Do not print arbitrary stderr; it could contain local paths/user metadata.
        raise RuntimeError(f"Read-only check failed ({args[0]} exit {completed.returncode})")
    return completed.stdout.strip()

def evaluate(facts: dict[str, Any]) -> dict[str, Any]:
    """Offline deterministic admission; operator claims never upgrade host checks."""
    required_automatic = {
        "clean_git_main": "Mac local canonical main is clean",
        "github_matches_mac": "Private GitHub main SHA matches Mac",
        "vps_matches_mac": "Actual VPS nonprivileged main SHA matches GitHub/Mac",
        "mac_filevault_on": "Mac FileVault is enabled",
        "latest_source_encrypted_snapshot_exists": "Current exact Git SHA has an encrypted Restic source snapshot",
        "key_only_ssh_reachable": "Strict-known-host, BatchMode key-only SSH is reachable",
        "ubuntu_2604": "Actual VPS uses Ubuntu Server 26.04 LTS",
        "no_pending_ssh_rollback": "No Stage-2 SSH rollback marker is pending",
    }
    automatic = [
        {"gate": name, "pass": facts.get(name) is True, "description": description}
        for name, description in required_automatic.items()
    ]
    external = [
        {"gate": name, "status": "BLOCKED_UNVERIFIED", "requirement": description}
        for name, description in EXTERNAL_GATES.items()
    ]
    blockers = [g["gate"] for g in automatic if not g["pass"]]
    blockers.extend(EXTERNAL_GATES.keys())
    return {
        "project": "IPAT",
        "developer": "Mr. iPat",
        "evaluation": "NO_GO",
        "production_db_apply": False,
        "native_firewall_apply": False,
        "k3s_install": False,
        "automatic_checks": automatic,
        "external_independent_gates": external,
        "blocker_ids": blockers,
        "disclaimer": "Passing SSH/Git/source backup is not independent VPS rescue or PostgreSQL PITR recovery.",
    }

def collect() -> dict[str, Any]:
    facts: dict[str, Any] = {}
    try:
        branch = run_readonly(["git", "branch", "--show-current"])
        sha = run_readonly(["git", "rev-parse", "HEAD"])
        status = run_readonly(["git", "status", "--porcelain"])
        facts["clean_git_main"] = branch == "main" and not status and len(sha) == SHA_LENGTH
    except (RuntimeError, subprocess.TimeoutExpired):
        sha = ""
        facts["clean_git_main"] = False

    try:
        remote = run_readonly(["gh", "api", "repos/mr-ipat/ipat/commits/main", "--jq", ".sha"])
        facts["github_matches_mac"] = len(sha) == SHA_LENGTH and remote == sha
    except (RuntimeError, FileNotFoundError, subprocess.TimeoutExpired):
        facts["github_matches_mac"] = False

    try:
        fv = run_readonly(["/usr/bin/fdesetup", "status"])
        facts["mac_filevault_on"] = fv == "FileVault is On."
    except (RuntimeError, FileNotFoundError, subprocess.TimeoutExpired):
        facts["mac_filevault_on"] = False

    # Existing encrypted Mac lab repository only. Never print the Keychain
    # secret or read/write backup data from this preflight.
    repo = Path.home() / "IPAT-secure-backups/restic-lab-v1"
    try:
        env = os.environ.copy()
        env["RESTIC_PASSWORD_COMMAND"] = (
            "/usr/bin/security find-generic-password -a ipat-lab-backup "
            "-s id.ipat.lab.restic.backup.v1 -w"
        )
        raw = run_readonly(["restic", "-r", str(repo), "snapshots", "--json"],
                           timeout=25, env=env)
        snaps = json.loads(raw)
        expected_path = f"/ipat-canonical-main-{sha}.tar"
        facts["latest_source_encrypted_snapshot_exists"] = (
            len(sha) == SHA_LENGTH and isinstance(snaps, list) and
            any("canonical-source-main" in (s.get("tags") or [])
                and expected_path in (s.get("paths") or [])
                for s in snaps)
        )
    except (RuntimeError, FileNotFoundError, subprocess.TimeoutExpired,
            ValueError, TypeError):
        facts["latest_source_encrypted_snapshot_exists"] = False

    # Fixed SSH command: no host firewall, service, route, sudo or file writes.
    remote_cmd = (
        "printf 'SHA='; git -C /home/openai/workspaces/ipat rev-parse HEAD; "
        "printf 'BRANCH='; git -C /home/openai/workspaces/ipat branch --show-current; "
        "printf 'STATUS='; test -z \"$(git -C /home/openai/workspaces/ipat status --porcelain)\" "
        "&& echo CLEAN || echo DIRTY; "
        "printf 'OS='; . /etc/os-release; echo \"$ID:$VERSION_ID\"; "
        "printf 'ROLLBACK='; test ! -e /run/ipat-ssh-stage2.active "
        "&& echo NONE || echo PRESENT"
    )
    try:
        result = run_readonly([
            "ssh", "-T", "-o", "BatchMode=yes", "-o", "ConnectTimeout=8",
            "-o", "StrictHostKeyChecking=yes", "ipat-lab", remote_cmd
        ], timeout=12)
        lines = dict(line.split("=", 1) for line in result.splitlines() if "=" in line)
        facts["key_only_ssh_reachable"] = True
        facts["vps_matches_mac"] = (
            len(sha) == SHA_LENGTH and lines.get("SHA") == sha and
            lines.get("BRANCH") == "main" and lines.get("STATUS") == "CLEAN"
        )
        facts["ubuntu_2604"] = lines.get("OS") in {"ubuntu:26.04", "ubuntu:26.04.1"}
        facts["no_pending_ssh_rollback"] = lines.get("ROLLBACK") == "NONE"
    except (RuntimeError, FileNotFoundError, subprocess.TimeoutExpired, ValueError):
        for key in ("key_only_ssh_reachable", "vps_matches_mac",
                    "ubuntu_2604", "no_pending_ssh_rollback"):
            facts[key] = False
    return facts

def main() -> int:
    parser = argparse.ArgumentParser(description="IPAT read-only production NO-GO evidence")
    parser.add_argument("--json", action="store_true", help="print redacted machine-readable report")
    ns = parser.parse_args()
    report = evaluate(collect())
    if ns.json:
        print(json.dumps(report, indent=2, sort_keys=True))
    else:
        print("IPAT production infrastructure: NO_GO (read-only verification)")
        for item in report["automatic_checks"]:
            print(f"  {'PASS' if item['pass'] else 'BLOCKED'}: {item['description']}")
        for item in report["external_independent_gates"]:
            print(f"  BLOCKED: {item['requirement']}")
        print("No PostgreSQL install, network rules or K3s activation was attempted.")
    return 3  # Never automatically authorize a production change.

if __name__ == "__main__":
    sys.exit(main())
