#!/usr/bin/env python3
"""Offline comparison of OLT RSA key from a separately trusted site console.
NEVER fetches key over network, NEVER trusts ssh-keyscan/TOFU, no login.
A MATCH means owner-asserted console key MATCHES previously observed SSH,
NOT proof that the file was actually exported from the real chassis.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import subprocess
import sys

ROOT=Path(__file__).resolve().parents[4]
OBSERVATION=ROOT/'web/lab/physical-intake-evidence.json'
B64=re.compile(r'^ssh-rsa [A-Za-z0-9+/]+={0,2}(?: [A-Za-z0-9_.@-]{1,80})?$')
FP=re.compile(r'^\d+ (SHA256:[A-Za-z0-9+/]{43}) .+ \(RSA\)$')

def trusted_file(path):
    if not path.is_absolute() or any(x in ('.','..') for x in path.parts):
        raise ValueError('absolute trusted out-of-repository console key file required')
    if path==ROOT or ROOT in path.parents or ROOT in path.resolve().parents:
        raise ValueError('trusted console key cannot originate in repository')
    meta=path.lstat()
    if not stat.S_ISREG(meta.st_mode) or meta.st_uid!=os.getuid() or meta.st_nlink!=1 \
       or stat.S_IMODE(meta.st_mode)!=0o600 or not 80<=meta.st_size<=8192:
        raise ValueError('private 0600 non-symlink one-link console key required')
    fd=os.open(path,os.O_RDONLY|getattr(os,'O_NOFOLLOW',0))
    with os.fdopen(fd,'rb') as stream:
        after=os.fstat(stream.fileno())
        if (meta.st_dev,meta.st_ino)!=(after.st_dev,after.st_ino):
            raise ValueError('console key file changed during read')
        raw=stream.read(8193)
    if len(raw)>8192 or raw.count(b'\n')>1:
        raise ValueError('expected exactly one RSA public key line')
    text=raw.decode('ascii').strip()
    if not B64.fullmatch(text):
        raise ValueError('only one RSA public key from trusted console is permitted')
    return raw

def verify(path,runner=subprocess.run):
    raw=trusted_file(path)
    observation=json.loads(OBSERVATION.read_text())
    if observation.get('target_slot')!='DEV-01' or observation.get('device_adopted') is not False \
       or observation.get('out_of_band_host_key_verified') is not False:
        raise ValueError('cannot use stale or overclaiming network observation')
    expected=observation.get('observed_rsa_fingerprint')
    if not isinstance(expected,str) or not re.fullmatch(r'SHA256:[A-Za-z0-9+/]{43}',expected):
        raise ValueError('observed fingerprint must be verified by a separate site source')
    result=runner(['ssh-keygen','-lf',str(path)],capture_output=True,text=True,timeout=5,check=False)
    match=FP.fullmatch(result.stdout.strip()) if result.returncode==0 else None
    if not match:
        raise ValueError('trusted console RSA public key parse failed')
    return {'target_slot':'DEV-01','owner_asserted_console_key_matches_observed':
            match.group(1)==expected,
            'observed_fingerprint':expected,
            'trusted_console_public_key_sha256':hashlib.sha256(raw).hexdigest(),
            'network_packets_sent':0,'credentials_sent':False,
            'device_adopted':False,'independent_reviewer_approval_recorded':False}

def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--trusted-console-rsa-public-key',required=True,type=Path)
    parser.add_argument('--owner-attests-independent-console-source',action='store_true')
    args=parser.parse_args()
    if os.geteuid()==0 or not args.owner_attests_independent_console_source:
        parser.error('nonroot explicit trusted-console provenance assertion required')
    try:
        result=verify(args.trusted_console_rsa_public_key)
    except (ValueError,OSError,UnicodeError,json.JSONDecodeError,subprocess.TimeoutExpired):
        print('R914_TRUSTED_CONSOLE_KEY_CHECK_DENIED',file=sys.stderr)
        return 4
    print(json.dumps(result,sort_keys=True))
    return 0 if result['owner_asserted_console_key_matches_observed'] else 5

if __name__=='__main__':sys.exit(main())
