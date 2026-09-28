#!/usr/bin/env bash
# Mac-only read-only TCP connection + DNS inspection from THIS source.
# This cannot read or certify external provider firewall rules.
set -Eeuo pipefail
[[ "$#" -eq 1 && "${1:-}" == "--report" ]] ||
    { echo "Usage: $0 --report" >&2; exit 2; }
[[ "$(uname -s)" == Darwin ]] ||
    { echo "Use the authorized Mac to obtain an external observation" >&2; exit 3; }
for program in dig nc; do
    command -v "$program" >/dev/null || { echo "$program unavailable"; exit 4; }
done
target=hub.example.invalid
echo "IPAT_EDGE_EXTERNAL_TCP_OBSERVATION_ONLY"
echo "DNS_A_RECORDS:"
dig +short +time=2 +tries=1 "$target" A | grep -E '^[0-9]+(\.[0-9]+){3}$' || true
if dig +short +time=2 +tries=1 "$target" AAAA | grep -q ':'; then
    echo "DNS_AAAA=present; IPv6 rule review is REQUIRED"
else
    echo "DNS_AAAA=not returned in this lookup; provider IPv6 rule review still required"
fi
for port in 22 80 443 6443 10250 2379 2380; do
    if nc -G 2 -w 2 -z "$target" "$port" </dev/null >/dev/null 2>&1; then
        printf 'TCP_%s=ACCEPTED_FROM_THIS_MAC\n' "$port"
    else
        printf 'TCP_%s=NO_CONNECTION; cannot distinguish provider filtering from absent service\n' "$port"
    fi
done
echo "UDP_8472=NOT_SCANNED; no UDP/Flannel public exposure conclusion"
echo "EDGE_PROVIDER_MANAGED_FIREWALL=NOT_VISIBLE_FROM_GUEST_OR_THIS_TCP_PROBE"
echo "HOST_FIREWALL_RULESET=NOT_INSPECTED_BY_THIS_MAC_PROBE"
echo "NO_FIREWALL_OR_SERVER_CONFIGURATION_CHANGED"
