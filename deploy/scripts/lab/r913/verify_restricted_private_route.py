#!/usr/bin/env python3
"""Local read-only route-table gate for an EXACT private OLT candidate.
No network packets, firewall changes, credentials or actual tunnel probes.
A route-table candidate is NOT proof of reachable/isolated management.
"""
import argparse
import ipaddress
import json
import os
import subprocess
import sys

RFC1918=tuple(map(ipaddress.ip_network,
    ('10.0.0.0/8','172.16.0.0/12','192.168.0.0/16')))

def parse(ip, route, defaults):
    target=ipaddress.IPv4Address(ip)
    if not any(target in subnet for subnet in RFC1918):
        raise ValueError('RFC1918 exact candidate required')
    if len(route)!=1 or route[0].get('dst')!=str(target):
        raise ValueError('route-table response does not match exact candidate')
    entry=route[0]
    interface=entry.get('dev')
    if not isinstance(interface,str) or not interface.isascii() or not interface:
        raise ValueError('missing safe route interface')
    for item in defaults:
        if item.get('dst')=='default' and item.get('gateway')==entry.get('gateway') \
           and item.get('dev')==interface:
            return {'route_candidate':'DEFAULT_ROUTE_ONLY',
                'isolated_management_route_verified':False,'network_packets_sent':0}
    return {'route_candidate':'NONDEFAULT_ROUTE_REQUIRES_PROOF',
        'isolated_management_route_verified':False,'network_packets_sent':0}

def inspect(ip, runner=subprocess.run):
    target=ipaddress.IPv4Address(ip)
    if not any(target in subnet for subnet in RFC1918):
        raise ValueError('private IPv4 required')
    commands=(['ip','-j','-4','route','get',str(target)],
              ['ip','-j','-4','route','show','default'])
    results=[]
    for command in commands:
        response=runner(command,capture_output=True,text=True,check=False,timeout=3)
        if response.returncode or len(response.stdout)>16384:
            raise ValueError('route query denied or oversized')
        results.append(json.loads(response.stdout))
    return parse(str(target),*results)

def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--private-ipv4',required=True)
    args=parser.parse_args()
    if os.geteuid()==0: parser.error('nonroot read-only probe only')
    try: print(json.dumps(inspect(args.private_ipv4),sort_keys=True))
    except (ValueError,OSError,subprocess.TimeoutExpired,json.JSONDecodeError):
        print(json.dumps({'route_candidate':'INCONCLUSIVE',
            'isolated_management_route_verified':False,
            'network_packets_sent':0}))
        return 4
    return 0

if __name__=='__main__': sys.exit(main())
