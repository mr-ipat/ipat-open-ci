#!/usr/bin/env python3
"""Pure Site A/hub to Site B/spoke topology review; never pushes config."""
import ipaddress
import json

PRIVATE = tuple(map(ipaddress.ip_network, (
    '10.0.0.0/8', '172.16.0.0/12', '192.168.0.0/16')))
REQUIRED = {'mode', 'site_a_endpoint', 'site_b_gateway', 'management_host',
            'vpn_subnet', 'site_a_networks', 'site_b_networks',
            'private_path_verified', 'site_b_recovery_verified'}

def ip(v):
    if type(v) is not str or not 7 <= len(v) <= 15:
        raise ValueError('canonical dotted IPv4 text required')
    a = ipaddress.ip_address(v)
    if str(a) != v or a.version != 4:
        raise ValueError('IPv4 only')
    return a

def private(a):
    return any(a in n for n in PRIVATE)

def review(data):
    if type(data) is not dict or set(data) != REQUIRED:
        raise ValueError('unexpected fields / secret inputs denied')
    if data['mode'] not in ('direct_private', 'wireguard', 'ipsec'):
        raise ValueError('unsupported connection mode')
    if data['site_b_gateway'] not in ('routeros7', 'linux'):
        raise ValueError('unsupported site B platform')
    a, host = ip(data['site_a_endpoint']), ip(data['management_host'])
    if (a.is_loopback or a.is_multicast or a.is_unspecified or a.is_link_local
        or a.is_reserved):
        raise ValueError('Site A must use an actual valid unicast endpoint')
    if not private(host):
        raise ValueError('site OLT address must be private IPv4')
    if type(data['private_path_verified']) is not bool or type(data['site_b_recovery_verified']) is not bool:
        raise ValueError('invalid evidence flags')
    nets = []
    for key in ('site_a_networks', 'site_b_networks'):
        v = data[key]
        if (type(v) is not list or not 1 <= len(v) <= 24 or
            any(type(item) is not str or len(item) > 32 for item in v)
            or len(set(v)) != len(v)):
            raise ValueError('explicit canonical nonduplicate network lists required')
        part = [ipaddress.ip_network(n, strict=True) for n in v]
        if any(n.version != 4 for n in part):
            raise ValueError('IPv4 networks only')
        nets.append(part)
    if not any(host in n for n in nets[1]):
        raise ValueError('OLT management LAN not declared at site B')
    if private(a) and not any(a in n for n in nets[0]):
        raise ValueError('private hub must belong to a declared Site A network')
    if data['mode'] == 'wireguard' and any(x.overlaps(y) for x in nets[0] for y in nets[1]):
        raise ValueError('overlapping A/B networks need separately designed NAT; deny direct tunnel')
    vpn = ipaddress.ip_network(data['vpn_subnet'], strict=True)
    if vpn.version != 4 or vpn.prefixlen != 30 or not private(vpn.network_address):
        raise ValueError('isolated RFC1918 /30 is required')
    if host in vpn or any(vpn.overlaps(n) for part in nets for n in part):
        raise ValueError('tunnel network conflict')
    if data['mode'] == 'direct_private':
        if not private(a) or not data['private_path_verified']:
            raise ValueError('direct requires independently verified private path')
    elif data['mode'] == 'wireguard' and private(a) and not data['private_path_verified']:
        raise ValueError('outside spoke cannot reach unverified private hub address')
    x, y = list(vpn.hosts())
    flags = ['real_tenant_mfa', 'independent_approval', 'site_b_firmware_verified', 'trusted_device_key',
             'isolated_last_hop', 'verified_return_route',
             'live_distribution_baseline', 'actual_worker_path']
    if not data['site_b_recovery_verified']:
        flags.append('site_b_console_recovery')
    return {'schema': 1, 'state': 'REVIEW_ONLY',
            'site_a_role': ('EXISTING_PRIVATE_SITE_A_NO_TUNNEL' if data['mode']=='direct_private'
                            else 'CENTRAL_HUB_LISTENER'),
            'site_b_role': ('EXISTING_PRIVATE_SITE_B_NO_TUNNEL' if data['mode']=='direct_private'
                            else 'SELF_CONFIGURED_SPOKE'),
            'site_a_endpoint_kind': 'PRIVATE' if private(a) else 'PUBLIC',
            'link_mode': data['mode'],
            'a_tunnel_host': str(x), 'b_tunnel_host': str(y),
            'target_host_route': str(host) + '/32',
            'site_a_allowed_peer_routes': [str(y) + '/32', str(host) + '/32'],
            'site_b_allowed_peer_routes': [str(x) + '/32'],
            'site_b_configuration_owner': 'SITE_B_OPERATOR',
            'missing_independent_evidence': flags,
            'ip_reachability_actually_measured': False,
            'router_push_enabled': False, 'config_generated': False,
            'secrets_accepted': False, 'network_actions': 0,
            'device_adopted': False}

def main():
    import argparse
    import os
    import stat
    from pathlib import Path
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--local-reviewed-topology-json',type=Path,required=True)
    args=parser.parse_args()
    path=args.local_reviewed_topology_json
    try:
        info=path.lstat()
        repo=Path(__file__).resolve().parents[4]
        if (os.geteuid()==0 or not path.is_absolute()
            or repo == path or repo in path.parents
            or not stat.S_ISREG(info.st_mode)
            or info.st_uid!=os.getuid() or info.st_nlink!=1
            or stat.S_IMODE(info.st_mode)!=0o600 or not 1 <= info.st_size <= 8192):
            raise ValueError('owner-only file outside repository required')
        fd=os.open(path,os.O_RDONLY|getattr(os,'O_NOFOLLOW',0))
        with os.fdopen(fd,'rb') as stream:
            after=os.fstat(stream.fileno())
            if (info.st_dev,info.st_ino)!=(after.st_dev,after.st_ino):
                raise ValueError('topology file inode changed during open')
            payload=stream.read(8193)
        if len(payload)>8192:
            raise ValueError('topology input exceeded limit')
        result=review(json.loads(payload))
        print(json.dumps(result,sort_keys=True))
    except (ValueError,TypeError,KeyError,OSError):
        parser.exit(2,'DENIED: topology needs independent review; no configuration generated\n')

if __name__=='__main__':main()
