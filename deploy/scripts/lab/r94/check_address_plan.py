#!/usr/bin/env python3
"""Offline-only route overlap preflight; no network I/O or configuration changes."""
import argparse
import ipaddress
import json


def evaluate(vpn, olt, existing):
    tunnel = ipaddress.ip_network(vpn, strict=True)
    target = ipaddress.ip_address(olt)
    networks = [ipaddress.ip_network(n, strict=False) for n in existing]
    if tunnel.version != 4 or target.version != 4:
        raise ValueError("initial lab design requires IPv4")
    if not target.is_private:
        raise ValueError("OLT target must be a private management IPv4")
    if target in tunnel:
        raise ValueError("OLT private management IP must be outside VPN subnet")
    if any(tunnel.overlaps(net) for net in networks):
        raise ValueError("VPN subnet overlaps an existing site/VPS network")
    # The private OLT is expected to be inside an existing site VLAN.
    # Route/firewall reachability and VLAN trust require separate human review.
    return {"result": "PLAN_ONLY", "eligible_for_live_deployment": False,
            "requires_independent_route_and_recovery_review": True}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--vpn-subnet", required=True)
    parser.add_argument("--olt-private-ip", required=True)
    parser.add_argument("--existing-network", action="append", default=[])
    args = parser.parse_args()
    try:
        print(json.dumps(evaluate(args.vpn_subnet, args.olt_private_ip,
                                  args.existing_network), sort_keys=True))
    except ValueError as exc:
        parser.exit(2, "INVALID PLAN: " + str(exc) + "\n")

if __name__ == "__main__":
    main()
