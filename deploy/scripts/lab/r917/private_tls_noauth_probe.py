#!/usr/bin/env python3
"""Optional ONE exact private OLT TCP/443 authenticated TLS preflight.
No HTTP requests, no credentials, no commands and no certificate bypass.
Even a verified cert cannot establish vendor management API support.
"""
import argparse
import ipaddress
import json
import os
import socket
import ssl
import sys


def probe(host,connect=socket.create_connection,wrap=None):
    ip=ipaddress.IPv4Address(host)
    if not ip.is_private or ip.is_loopback or ip.is_link_local or ip.is_multicast or ip.is_unspecified or ip.is_reserved:
        raise ValueError('exact private routable OLT address required')
    # ssl.create_default_context checks the operating-system trust store
    # AND server identity; a private IP usually needs a matching IP SAN.
    # Never disable verification just to collect a self-signed cert.
    context=ssl.create_default_context(purpose=ssl.Purpose.SERVER_AUTH)
    result={'candidate_transport':'TLS_HTTPS_TCP_443',
      'address_class':'PRIVATE_CANDIDATE_NOT_ISOLATION_PROOF',
      'tcp_reachable':False,'tls_identity_verified':False,
      'olt_api_supported':False,'device_adopted':False,
      'credentials_sent':False,'application_requests_sent':0,
      'management_segment_isolated':False,
      'out_of_band_chassis_identity_verified':False}
    try:
        with connect((host,443),timeout=3) as raw:
            result['tcp_reachable']=True
            tls=wrap or context.wrap_socket
            with tls(raw,server_hostname=host) as connection:
                result['tls_identity_verified']=True
                result['tls_version']=connection.version()
    except (OSError,ssl.SSLError,socket.timeout):
        # Keep reachability distinct from strict TLS identity. Never retry
        # without verify or opportunistically downgrade to plaintext HTTP.
        pass
    return result


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--private-ipv4',required=True)
    parser.add_argument('--requirements',action='store_true')
    parser.add_argument('--probe',action='store_true')
    args=parser.parse_args()
    if args.requirements:
        print(json.dumps({'tcp_port':443,'strict_tls_verification':True,
            'max_tcp_connections':1,'http_requests':0,'credentials':False}))
        return 0
    if os.geteuid()==0 or not args.probe or os.environ.get('IPAT_R917_APPROVE_ONE_PRIVATE_TLS_443_PROBE')!='YES':
        parser.error('nonroot explicit one-time owner-approved TLS probe only')
    try:print(json.dumps(probe(args.private_ipv4),sort_keys=True))
    except ValueError: return 4
    return 0

if __name__=='__main__':sys.exit(main())
