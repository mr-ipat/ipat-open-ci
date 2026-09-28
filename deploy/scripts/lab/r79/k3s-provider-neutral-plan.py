#!/usr/bin/env python3
"""Provider-independent, NO-INSTALL K3s plan for single VPS or encrypted
private inter-provider VPN workers. Host firewall is NOT a required provider API.
Actual connectivity, recoverability and identity gates remain external.
"""
import argparse
import ipaddress
import json
from pathlib import Path
import re
import sys

RFC1918 = tuple(map(ipaddress.ip_network, (
    "10.0.0.0/8","172.16.0.0/12","192.168.0.0/16")))
SAMPLE = {
    "schema": 1, "mode": "multi-vps-private-overlay",
    "pod_cidr": "10.42.0.0/16", "service_cidr": "10.43.0.0/16",
    "overlay_cidr": "10.77.0.0/24",
    "vpn_end_to_end_prepared": False,
    "private_peer_reachability_verified": False,
    "offsite_full_restore_verified": False,
    "rescue_console_verified": False,
    "nodes": [
        {"name":"ipat-cp-1","role":"server","arch":"x86_64",
         "provider_label":"provider-a","private_ip":"10.77.0.10","interface":"wg-ipat"},
        {"name":"ipat-w1","role":"agent","arch":"aarch64",
         "provider_label":"provider-b","private_ip":"10.77.0.20","interface":"wg-ipat"},
    ]
}
NAME = re.compile(r"^[a-z][a-z0-9-]{1,29}[a-z0-9]$")
IFACE = re.compile(r"^[a-z][a-z0-9._-]{0,14}$")
FLAGS = ("vpn_end_to_end_prepared","private_peer_reachability_verified",
         "offsite_full_restore_verified","rescue_console_verified")
NODE_FIELDS = {"name","role","arch","provider_label","private_ip","interface"}
FIELDS = {"schema","mode","pod_cidr","service_cidr","overlay_cidr",
          "nodes",*FLAGS}

class Denied(ValueError): pass

def unique(pairs):
    out = {}
    for k, v in pairs:
        if k in out: raise Denied("duplicate JSON field")
        out[k] = v
    return out

def rfc1918(addr):
    ip = ipaddress.IPv4Address(addr)
    if not any(ip in n for n in RFC1918):
        raise Denied("K3s inter-node addresses must be RFC1918 private")
    return ip

def plan(spec):
    if type(spec) is not dict or set(spec) != FIELDS or (
        type(spec["schema"]) is not int or spec["schema"] != 1):
        raise Denied("unknown or incomplete topology plan")
    mode = spec["mode"]
    if mode not in ("single-vps-private", "multi-vps-private-overlay"):
        raise Denied("unsupported network mode")
    if any(type(spec[k]) is not bool for k in FLAGS):
        raise Denied("external approval fields must be booleans")
    cidrs = [ipaddress.IPv4Network(spec[name],strict=True)
             for name in ("pod_cidr","service_cidr","overlay_cidr")]
    if any(not any(c.subnet_of(r) for r in RFC1918) for c in cidrs):
        raise Denied("K3s networks must be RFC1918")
    if any(a.overlaps(b) for i,a in enumerate(cidrs) for b in cidrs[i+1:]):
        raise Denied("pod/service/private network overlap")
    nodes = spec["nodes"]
    if type(nodes) is not list or not 1 <= len(nodes) <= 32:
        raise Denied("bounded explicit node inventory required")
    seen_ip,seen_name = set(),set()
    servers,agents = [],[]
    for node in nodes:
        if type(node) is not dict or set(node) != NODE_FIELDS:
            raise Denied("unknown node keys")
        if any(type(node[k]) is not str for k in NODE_FIELDS):
            raise Denied("node values must be explicit strings")
        if not NAME.fullmatch(node["name"]) or not NAME.fullmatch(node["provider_label"]):
            raise Denied("invalid node or provider label")
        if node["arch"] not in ("x86_64","aarch64") or (
            node["role"] not in ("server","agent")):
            raise Denied("unsupported node architecture/role")
        if not IFACE.fullmatch(node["interface"]):
            raise Denied("invalid private network interface")
        if mode == "multi-vps-private-overlay" and node["interface"] != "wg-ipat":
            raise Denied("encrypted overlay must use explicit wg-ipat interface")
        ip = rfc1918(node["private_ip"])
        if ip not in cidrs[2] or ip in (
            cidrs[2].network_address,cidrs[2].broadcast_address):
            raise Denied("node address must be inside usable private network")
        if ip in seen_ip or node["name"] in seen_name:
            raise Denied("duplicate node name/IP")
        seen_name.add(node["name"]);seen_ip.add(ip)
        (servers if node["role"]=="server" else agents).append(node)
    if len(servers) != 1:
        raise Denied("cross-cloud embedded-etcd HA NOT supported by this plan")
    if (mode == "single-vps-private" and (len(nodes)!=1 or agents)) or (
        mode == "multi-vps-private-overlay" and not agents):
        raise Denied("topology inconsistent with selected profile")
    server=servers[0]
    blockers = [
        k for k in ("offsite_full_restore_verified","rescue_console_verified")
        if not spec[k]
    ]
    if mode=="multi-vps-private-overlay":
        blockers += [k for k in ("vpn_end_to_end_prepared",
            "private_peer_reachability_verified") if not spec[k]]
    # Even all declarations true are NOT an independent audit/approval.
    configs=[]
    for node in nodes:
        args = ["server"] if node["role"]=="server" else ["agent"]
        if node["role"]=="server":
            args += ["--bind-address",node["private_ip"],
                "--advertise-address",node["private_ip"],
                "--cluster-cidr",str(cidrs[0]),"--service-cidr",str(cidrs[1]),
                "--flannel-backend","vxlan","--secrets-encryption",
                "--write-kubeconfig-mode","0600",
                "--disable","traefik","--disable","servicelb"]
        else:
            args += ["--server",
                "https://"+server["private_ip"]+":6443"]
        args += ["--node-ip",node["private_ip"],"--node-name",node["name"]]
        if mode=="multi-vps-private-overlay":
            args += ["--flannel-iface",node["interface"]]
        # Do not interpolate public hostnames, tokens or executable commands.
        configs.append({"node_name":node["name"],"role":node["role"],
            "arch":node["arch"],"provider_label":node["provider_label"],
            "review_only_k3s_args":args})
    return {
        "mode":mode,"provider_api_required":False,
        "provider_firewall_api_required":False,"host_firewall_dependency":False,
        "network_isolation_required":True,
        "private_transport":("operator-enforced-private-interface" if
            mode=="single-vps-private" else
            "operator-prepared-encrypted-WireGuard-interface"),
        "reachability_requirements":[
            "6443/TCP: agents-to-server on private interface only",
            "8472/UDP: Flannel VXLAN BETWEEN NODES inside encrypted VPN only"
            if mode=="multi-vps-private-overlay" else
            "single node: no inter-node VXLAN opening",
            "10250/TCP: only between authorized nodes if metrics enabled"],
        "external_blockers":blockers,
        "installation_authorized":False,
        "multi_cloud_etcd_ha_supported":False,
        "nodes":configs,
        "evidence": "OFFLINE_TOPOLOGY_ONLY_NOT_LIVE_NETWORK_OR_FIREWALL_TEST"
    }

def main():
    ap=argparse.ArgumentParser(description=__doc__)
    mode=ap.add_mutually_exclusive_group(required=True)
    mode.add_argument("--example",action="store_true")
    mode.add_argument("--plan",type=Path)
    args=ap.parse_args()
    if args.example:
        print(json.dumps(SAMPLE,indent=2))
        return 0
    try:
        if args.plan.stat().st_size>16384:
            raise Denied("oversized network plan")
        obj=json.loads(args.plan.read_bytes(),object_pairs_hook=unique)
        print(json.dumps(plan(obj),sort_keys=True,indent=2))
        return 0
    except (Denied,ValueError,TypeError,OSError):
        print("R79_K3S_PLAN_DENIED:invalid or unsafe private topology",
              file=sys.stderr)
        return 4

if __name__=="__main__":sys.exit(main())
