#!/usr/bin/env python3
"""Offline read-only assessment of actual privately collected C320 evidence.

No network, no credentials, no enrollment, no physical commands, no claims
that an owner-asserted RSA public key proves actual chassis provenance.
"""
import argparse
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import re
import stat
import sys

ROOT=Path(__file__).resolve().parents[4]
VERIFIER=ROOT/'deploy/scripts/lab/r914/verify_owner_console_host_key.py'
spec=importlib.util.spec_from_file_location('r914_independent_console_rsa',VERIFIER)
keymod=importlib.util.module_from_spec(spec)
spec.loader.exec_module(keymod)
STATUS=ROOT/'deploy/scripts/lab/r921/inspect_show_ssh.py'
spec=importlib.util.spec_from_file_location('r921_owner_ssh_status',STATUS)
sshm=importlib.util.module_from_spec(spec)
spec.loader.exec_module(sshm)

EXPECTED=frozenset({'console-host-rsa.pub','show-ssh.txt','cards.txt',
                    'versions.txt','plan.json'})
CLI_HEADER={'cards.txt':b'Rack Shelf Slot','versions.txt':b'PhyLoc FileType VerType'}
class Denied(ValueError): pass

def folder_allowed(folder):
    if not folder.is_absolute() or folder.resolve()!=folder or ROOT==folder or ROOT in folder.parents:
        raise Denied('private canonical owner folder outside Git required')
    record=folder.lstat()
    if not stat.S_ISDIR(record.st_mode) or record.st_uid!=os.getuid() or stat.S_IMODE(record.st_mode)!=0o700:
        raise Denied('0700 current-user owned real folder required')
    entries=list(folder.iterdir())
    if any(p.name not in EXPECTED for p in entries):
        raise Denied('unexpected actual evidence file: fail closed')
    if any(p.is_symlink() or not p.is_file() for p in entries):
        raise Denied('non-regular or linked operator evidence forbidden')

def bounded(path,limit=32768):
    meta=path.lstat()
    if not stat.S_ISREG(meta.st_mode) or meta.st_uid!=os.getuid() or meta.st_nlink!=1 or stat.S_IMODE(meta.st_mode)!=0o600:
        raise Denied('owner-only 0600 single-link regular evidence required')
    if not 1<=meta.st_size<=limit:raise Denied('bounded nonempty private evidence required')
    fd=os.open(path,os.O_RDONLY|getattr(os,'O_NOFOLLOW',0))
    with os.fdopen(fd,'rb') as source:
        inside=os.fstat(source.fileno())
        if (inside.st_ino,inside.st_dev)!=(meta.st_ino,meta.st_dev):
            raise Denied('private file swapped while opening')
        data=source.read(limit+1)
    if len(data)>limit or any(c in data for c in (b'\x00',b'\x1b')):
        raise Denied('oversized or terminal-control capture')
    return data

def classify(folder):
    folder_allowed(folder)
    facts={
       'target_slot':'DEV-01',
       'stage':'OFFLINE_SITE_EVIDENCE_ONLY',
       'actual_chassis_identity_independently_verified':False,
       'actual_restricted_role_verified':False,
       'true_tenant_admin_mfa_verified':False,
       'reviewer_approval_verified':False,
       'live_baseline_verified':False,
       'physical_worker_enabled':False,
       'device_adopted':False,
       'physical_olt_commands_executed_by_tool':0,
       'network_packets_sent_by_tool':0,
    }
    missing=[]
    proof={}
    if not (folder/'console-host-rsa.pub').exists():
        missing.append('INDEPENDENT_PHYSICAL_CHASSIS_RSA_PUBLIC_KEY')
    else:
        try:
            verify=keymod.verify(folder/'console-host-rsa.pub')
            proof['owner_claimed_console_rsa_matches_historical_network_key']=bool(
                verify['owner_asserted_console_key_matches_observed'])
            proof['console_public_key_sha256']=verify['trusted_console_public_key_sha256']
            if not verify['owner_asserted_console_key_matches_observed']:
                missing.append('CHASSIS_RSA_MISMATCH_STOP')
            else:
                missing.append('INDEPENDENT_CONSOLE_SOURCE_AND_REVIEWER_ATTESTATION')
        except (ValueError,OSError,UnicodeError,json.JSONDecodeError):
            missing.append('UNSAFE_OR_UNPARSABLE_CONSOLE_RSA_PUBLIC_KEY')
    if not (folder/'show-ssh.txt').exists():
        missing.append('ACTUAL_TRUSTED_CONSOLE_SHOW_SSH')
    else:
        try:
            capture=bounded(folder/'show-ssh.txt',8192)
            if re.search(rb'(?i)(?:password|private.?key|secret|username)\s*[:=]',capture):
                raise Denied('console transcript contains possible credentials')
            text=capture.decode('ascii')
            info=sshm.analyze(text)
            proof['ssh_console_capture_sha256']=hashlib.sha256(capture).hexdigest()
            proof['ssh_server_reported_enabled']=info['ssh_daemon_reported_enabled']
            proof['ssh_server_version_reported']=info['ssh_version_reported']
            proof['ssh_server_key_status_interpretation']=info['preauthentication_triage']
            missing.append('INDEPENDENT_CONSOLE_SOURCE_AND_FIRMWARE_CONFIRMATION')
        except (ValueError,UnicodeError,sshm.Denied):
            missing.append('UNSAFE_OR_UNRECOGNIZED_SSH_CONSOLE_CAPTURE')
    for filename in CLI_HEADER:
        file=folder/filename
        if not file.exists():
            missing.append('ACTUAL_VERIFIED_'+filename.upper().replace('.','_'))
            continue
        try:
            raw=bounded(file)
            if CLI_HEADER[filename] not in raw or re.search(
                rb'(?i)(?:password|secret|private.?key)\s*[:=]',raw):
                raise Denied('not an approved bounded read-only capture')
            proof[filename.replace('.','_')+'_sha256']=hashlib.sha256(raw).hexdigest()
            missing.append('FIRMWARE_EXACT_RUST_PARSER_AND_INDEPENDENT_CAPTURE_REVIEW_'+filename.upper().replace('.','_'))
        except (Denied,OSError):
            missing.append('UNSAFE_'+filename.upper().replace('.','_'))
    for check in ('DEDICATED_RESTRICTED_ROLE_ACTUALLY_PROVEN',
                  'PRODUCTION_TENANT_MFA_AND_POP_ISOLATION_PROVEN',
                  'LIVE_SUBSCRIBER_BASELINE_AND_INDEPENDENT_REVIEW',
                  'PRODUCTION_SCOPED_AUDITED_WORKER_ACTUALLY_VALIDATED'):
        missing.append(check)
    facts['verified_offline_properties']=proof
    facts['outstanding']=missing
    facts['site_files_present']=sorted(p.name for p in folder.iterdir())
    facts['status']='BLOCKED_REQUIRES_EXTERNAL_SITE_EVIDENCE_AND_APPROVAL'
    return facts

def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--private-owner-folder',required=True,type=Path)
    args=parser.parse_args()
    if os.geteuid()==0:parser.error('refuse root for private device evidence')
    try:info=classify(args.private_owner_folder)
    except (Denied,OSError):
        print('R926_SITE_PACKET_DENIED_UNSAFE_SOURCE_NO_NETWORK',file=sys.stderr)
        return 4
    print(json.dumps(info,sort_keys=True))
    return 0
if __name__=='__main__':sys.exit(main())
