#!/usr/bin/env python3
"""LOCAL-only owner-console RSA verification and restricted known_hosts export.

A public key supplied by the owner is NOT automatically trusted merely
because its fingerprint matches the historically observed network key.
This command cannot approve physical adoption or execute OLT commands.
"""
import argparse
import base64
import hashlib
import importlib.util
import ipaddress
import json
import os
from pathlib import Path
import re
import stat
import sys

ROOT=Path(__file__).resolve().parents[4]
BASE=ROOT/'deploy/scripts/lab/r914/verify_owner_console_host_key.py'
spec=importlib.util.spec_from_file_location('r914_console_verifier',BASE)
verify_mod=importlib.util.module_from_spec(spec)
spec.loader.exec_module(verify_mod)

class Denied(ValueError):pass

def output_dir(folder):
    if not folder.is_absolute() or folder.resolve()!=folder or ROOT==folder or ROOT in folder.parents:
        raise Denied('canonical absolute output outside repository required')
    m=folder.lstat()
    if not stat.S_ISDIR(m.st_mode) or m.st_uid!=os.getuid() or stat.S_IMODE(m.st_mode)!=0o700:
        raise Denied('current owner 0700 output directory required')
    if any(folder.iterdir()):raise Denied('output must start empty')

def render_pin(source,folder,ipv4,port):
    address=ipaddress.IPv4Address(ipv4)
    if not any(address in ipaddress.IPv4Network(cidr) for cidr in
       ('10.0.0.0/8','172.16.0.0/12','192.168.0.0/16')):
        raise Denied('only owner-approved private C320 address allowed')
    if type(port) is not int or not 1<=port<=65535:raise Denied('invalid port')
    parent=source.parent
    if parent.resolve()!=parent or ROOT==parent or ROOT in parent.parents:
        raise Denied('trusted RSA public key must originate from canonical private folder outside Git')
    meta=parent.lstat()
    if not stat.S_ISDIR(meta.st_mode) or meta.st_uid!=os.getuid() or stat.S_IMODE(meta.st_mode)!=0o700:
        raise Denied('owner-only 0700 console evidence folder required')
    raw=verify_mod.trusted_file(source)
    result=verify_mod.verify(source)
    if not result['owner_asserted_console_key_matches_observed']:
        raise Denied('independent console RSA does not match network observation')
    text=raw.decode('ascii').strip().split()
    if len(text) not in (2,3) or text[0]!='ssh-rsa':
        raise Denied('exact RSA key required')
    try:key=base64.b64decode(text[1],validate=True)
    except Exception:raise Denied('invalid console RSA encoding') from None
    if not 256<=len(key)<=1024:raise Denied('unexpected RSA public key size')
    output_dir(folder)
    host=f'[{address}]:{port}' if port!=22 else str(address)
    known=f'{host} ssh-rsa {text[1]}\n'.encode('ascii')
    file=folder/'known_hosts'
    fd=os.open(file,os.O_CREAT|os.O_EXCL|os.O_WRONLY|getattr(os,'O_NOFOLLOW',0),0o600)
    try:
        with os.fdopen(fd,'wb') as stream:
            stream.write(known);stream.flush();os.fsync(stream.fileno())
    except Exception:
        file.unlink(missing_ok=True)
        raise
    return {
        'result':'OWNER_ASSERTED_CONSOLE_RSA_MATCHES_HISTORICAL_NETWORK',
        'console_public_key_sha256':hashlib.sha256(raw).hexdigest(),
        'known_hosts_sha256':hashlib.sha256(known).hexdigest(),
        'independent_provenance_cryptographically_verified':False,
        'independent_reviewer_approved':False,
        'live_baseline_verified':False,
        'restricted_device_account_verified':False,
        'tenant_mfa_verified':False,
        'real_c320_login_performed':False,
        'physical_read_permitted':False,
        'device_adopted':False,'network_packets_sent':0,'olt_commands_executed':0}

def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--trusted-console-rsa-public-key',type=Path,required=True)
    parser.add_argument('--empty-private-output',type=Path,required=True)
    parser.add_argument('--private-ipv4',required=True)
    parser.add_argument('--ssh-port',required=True,type=int)
    parser.add_argument('--owner-attests-independent-console-source',action='store_true')
    args=parser.parse_args()
    if os.geteuid()==0 or not args.owner_attests_independent_console_source:
        parser.error('owner assertion and nonroot private evidence required')
    try:
        result=render_pin(args.trusted_console_rsa_public_key,args.empty_private_output,
                          args.private_ipv4,args.ssh_port)
    except (Denied,ValueError,OSError,UnicodeError,json.JSONDecodeError):
        print('C320_TRUSTED_CONSOLE_PIN_PREPARATION_DENIED_NO_DEVICE_ACTIONS',file=sys.stderr)
        return 4
    print(json.dumps(result,sort_keys=True))
    return 0

if __name__=='__main__':sys.exit(main())
