#!/usr/bin/env python3
"""Exact user-approved private C320 TCP 323 passive Telnet proof (NO LOGIN).

One connection, at most 512 inbound bytes, ZERO writes, no banner saved,
no Telnet option responses, never a basis for physical device trust.
"""
import argparse
from datetime import datetime, timezone
import ipaddress
import json
import os
import socket
import sys

APPROVAL='IPAT_R928_APPROVE_ONE_NOAUTH_PRIVATE_TELNET323'
EXACT_TARGET='10.77.13.233'
EXACT_PORT=323

def probe(*,connector=socket.create_connection):
    record={'target_slot':'DEV-01','observation':'EXACT_PRIVATE_TCP323_NOAUTH_PASSIVE_ONLY',
            'source':'nonroot_owner_vps','tcp_reachable':False,
            'telnet_iac_observed':False,'bytes_received':0,
            'credential_bytes_sent':0,'telnet_option_responses_sent':0,
            'olt_commands_executed':0,'olt_configuration_changes':0,
            'server_identity_verified':False,
            'encrypted_transport':False,
            'safe_for_password':False,'device_adopted':False,
            'physical_read_performed':False}
    try:
        with connector((EXACT_TARGET,EXACT_PORT),timeout=5) as channel:
            channel.settimeout(2)
            try:data=channel.recv(512)
            except socket.timeout:data=b''
        record['tcp_reachable']=True
        record['bytes_received']=len(data)
        record['telnet_iac_observed']=data.startswith(b'\xff')
    except OSError as exc:
        record['failure_class']=('TIMEOUT' if isinstance(exc,(TimeoutError,socket.timeout))
             else 'REFUSED' if isinstance(exc,ConnectionRefusedError) else 'NETWORK_ERROR')
    return record

def main():
    p=argparse.ArgumentParser(description=__doc__)
    group=p.add_mutually_exclusive_group(required=True)
    group.add_argument('--requirements',action='store_true')
    group.add_argument('--one-passive-check',action='store_true')
    a=p.parse_args()
    if a.requirements:
        print(json.dumps({'mode':'EXACT_C320_PRIVATE_NOAUTH_TCP323','approval_env':APPROVAL,
                          'root_allowed':False,'network_writes':0,'password_allowed':False},sort_keys=True))
        return 0
    if (os.geteuid()==0 or os.environ.get(APPROVAL)!='YES' or
        not ipaddress.IPv4Address(EXACT_TARGET).is_private):
        p.error('explicit nonroot exact-private single passive check required')
    result=probe()
    result['observed_at_utc']=datetime.now(timezone.utc).isoformat(timespec='seconds')
    print(json.dumps(result,sort_keys=True))
    return 0 if result['tcp_reachable'] else 3
if __name__=='__main__':sys.exit(main())
