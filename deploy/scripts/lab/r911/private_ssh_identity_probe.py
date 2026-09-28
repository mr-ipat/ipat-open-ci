#!/usr/bin/env python3
"""Single bounded PRIVATE legacy SSH no-auth fingerprint observation.
NOT independent identity verification, device admission or a live CLI read.
"""
import argparse
import ipaddress
import json
import os
import re
import subprocess
import sys

OPT_IN = "IPAT_R911_APPROVE_ONE_NOAUTH_PRIVATE_SSH_PROBE"
RFC1918 = tuple(ipaddress.ip_network(c) for c in
    ("10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16"))
FINGERPRINT = re.compile(r"Server host key: ssh-rsa (SHA256:[A-Za-z0-9+/]{43})")

def accepted_target(host, port):
    addr = ipaddress.IPv4Address(host)
    if not any(addr in cidr for cidr in RFC1918) or type(port) is not int or not 1 <= port <= 65535:
        raise ValueError("exact private IPv4 and TCP port required")
    return str(addr)

def argv(host, port):
    host = accepted_target(host, port)
    return ["ssh", "-vv", "-F", "/dev/null", "-n", "-T", "-p", str(port),
            "-o", "BatchMode=yes", "-o", "NumberOfPasswordPrompts=0",
            "-o", "PubkeyAuthentication=no", "-o", "PasswordAuthentication=no",
            "-o", "KbdInteractiveAuthentication=no", "-o", "GSSAPIAuthentication=no",
            "-o", "HostKeyAlgorithms=ssh-rsa", "-o", "Ciphers=aes128-cbc",
            "-o", "StrictHostKeyChecking=yes",
            "-o", "UserKnownHostsFile=/dev/null",
            "-o", "GlobalKnownHostsFile=/dev/null",
            "-o", "ConnectTimeout=5", "-o", "ConnectionAttempts=1",
            "-o", "ClearAllForwardings=yes", "-o", "ProxyCommand=none",
            "-o", "ProxyJump=none", "-o", "IdentityAgent=none",
            "-o", "PreferredAuthentications=none",
            "unprivileged-noauth-probe@" + host]

def observe(host, port, runner=subprocess.run):
    """A single SSH transport handshake; no password, user key or commands."""
    try:
        result = runner(argv(host, port), capture_output=True, text=True,
                        timeout=20, check=False)
    except (OSError, subprocess.TimeoutExpired):
        return {"target_slot": "DEV-01", "result": "TRANSPORT_UNAVAILABLE",
                "host_identity_verified": False, "device_adopted": False,
                "credentials_sent": False, "olt_commands_executed": 0}
    diagnostic = result.stderr[:32768]
    banner = re.search(r"Remote protocol version 2\.0, remote software version ([A-Za-z0-9_.-]{1,50})", diagnostic)
    fingerprint = FINGERPRINT.search(diagnostic)
    # Never claim host identity even if the same key was seen earlier.
    untrusted = ("Host key verification failed" in diagnostic
                 and result.returncode != 0)
    return {"target_slot": "DEV-01", "result":
            "UNVERIFIED_PRIVATE_SSH_HOST_KEY" if untrusted and fingerprint
            else "TRANSPORT_INCONCLUSIVE",
            "ssh_banner": banner.group(1) if banner else None,
            "observed_rsa_fingerprint": fingerprint.group(1) if fingerprint else None,
            "host_identity_verified": False, "device_adopted": False,
            "credentials_sent": False, "olt_commands_executed": 0}

def main():
    parser = argparse.ArgumentParser(description=__doc__)
    action = parser.add_mutually_exclusive_group(required=True)
    action.add_argument("--requirements", action="store_true")
    action.add_argument("--probe", action="store_true")
    parser.add_argument("--private-ipv4")
    parser.add_argument("--port", type=int)
    args = parser.parse_args()
    if args.requirements:
        print(json.dumps({"mode": "one_private_ssh_handshake_only",
                          "credentials_sent": False, "olt_commands_executed": 0,
                          "independent_fingerprint_verification_required": True}))
        return 0
    if os.geteuid() == 0 or os.environ.get(OPT_IN) != "YES":
        parser.error("requires nonroot and explicit one-shot owner approval")
    try:
        accepted_target(args.private_ipv4 or "", args.port)
    except ValueError:
        parser.error("must specify exact RFC1918 private IPv4 and TCP port")
    print(json.dumps(observe(args.private_ipv4, args.port), sort_keys=True))
    return 0

if __name__ == "__main__":
    sys.exit(main())
