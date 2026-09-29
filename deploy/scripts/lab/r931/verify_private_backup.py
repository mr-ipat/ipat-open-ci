#!/usr/bin/env python3
"""Offline check ACTUAL owner-only full C320 show running-config receipt.

Never prints CLI lines, credentials, passwords, raw backup or vendor PII.
No network, no copying, no encrypted backup claim, no device enrollment.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import sys

EXPECTED=('running-config-full-owner-private.capture','running-config-private-receipt.json')
class Denied(ValueError):pass

def bounded_private(path,limit):
    s=path.lstat()
    if not stat.S_ISREG(s.st_mode) or s.st_uid!=os.getuid() or s.st_nlink!=1 \
       or stat.S_IMODE(s.st_mode)!=0o600 or not 1<=s.st_size<=limit:
        raise Denied('single-link owner-only regular bounded evidence required')
    fd=os.open(path,os.O_RDONLY|getattr(os,'O_NOFOLLOW',0))
    with os.fdopen(fd,'rb') as f:
        observed=os.fstat(f.fileno())
        if (observed.st_dev,observed.st_ino)!=(s.st_dev,s.st_ino):
            raise Denied('evidence swapped while opening')
        data=f.read(limit+1)
    if len(data)>limit:raise Denied('oversized evidence')
    return data

def verify(folder):
    if not folder.is_absolute() or folder.resolve()!=folder:
        raise Denied('absolute canonical path required')
    s=folder.lstat()
    if not stat.S_ISDIR(s.st_mode) or s.st_uid!=os.getuid() or stat.S_IMODE(s.st_mode)!=0o700:
        raise Denied('real owner-only 0700 directory required')
    raw=bounded_private(folder/EXPECTED[0],524288)
    receipt=json.loads(bounded_private(folder/EXPECTED[1],4096))
    if not isinstance(receipt,dict) or receipt.get('source')!='ACTUAL_MANUAL_INTERACTIVE_ENCRYPTED_PRIVATE_SSH_CLI' \
       or receipt.get('device_adopted') is not False or receipt.get('on_olt_configuration_writes') != 0 \
       or receipt.get('vendor_restorability_tested') is not False \
       or receipt.get('complete_running_config_marker_verified') is not True:
        raise Denied('private receipt must never claim complete adoption/restore')
    if receipt.get('bytes')!=len(raw) or receipt.get('sha256')!=hashlib.sha256(raw).hexdigest():
        raise Denied('source digest/size mismatched')
    if not raw.startswith(b'Building configuration') or len(raw)<32768 \
       or not re.search(rb'(?m)^[ ]*end\r?\s*$',raw) \
       or b'--More--' in raw or b'\x1b' in raw or b'\x00' in raw:
        raise Denied('unrecognized/truncated terminal capture')
    return {'source':'OWNER_PRIVATE_CONFIG_CAPTURE','integrity':'SHA256_MATCH_AND_VENDOR_END_MARKER',
            'bytes':len(raw),'sha256':receipt['sha256'],
            'off_host_encrypted_backup_restored':False,
            'device_restore_tested':False,
            'physical_chassis_out_of_band_verified':False,
            'restricted_account_verified':False,
            'production_worker_authorized':False,
            'device_adopted':False,'network_actions':0,'device_config_writes':0}

def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('--owner-private-folder',type=Path,required=True)
    args=p.parse_args()
    if os.geteuid()==0:
        p.error('root forbidden')
    try:r=verify(args.owner_private_folder)
    except (Denied,OSError,UnicodeError,ValueError):
        print('R931_PRIVATE_BACKUP_INTEGRITY_DENIED_NO_SECRET_OUTPUT',file=sys.stderr)
        return 4
    print(json.dumps(r,sort_keys=True))
    return 0
if __name__=='__main__':sys.exit(main())
