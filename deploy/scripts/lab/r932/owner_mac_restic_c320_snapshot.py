#!/usr/bin/env python3
"""OWNER-OPERATED ONLY: encrypt actual PRIVATE C320 CLI reference off-VPS.

Default `--requirements` is OFFLINE. `--backup-and-restore` requires owner
sitting at their trusted Mac Terminal with unlocked Keychain and direct
consent. ChatGPT's remote execution MUST NEVER run that sensitive action
or transfer actual OLT configuration through alternate remote channels.
No OLT login, SSH private-key export, device config/write, or worker enable.
"""
import argparse
from datetime import datetime,timezone
import hashlib
import json
import os
from pathlib import Path
import platform
import re
import shlex
import shutil
import stat
import subprocess
import sys
import tempfile

EXPECTED_SHA='5b21f96b7b81dc9a771cc24e6369bc55433748b637bf0e98a3fb0a03e1989ba3'
EXPECTED_LENGTH=119980
SNAPSHOT_NAME='ipat-c320-r931-actual-cli-output-reference.capture'
SNAPSHOT_TAG='c320-r931-private-complete-cli'
VPS_SOURCE='/home/openai/.local/share/ipat/r931-private-olt-backup'
REMOTE_PRODUCER=r'''
from pathlib import Path
import hashlib,json,os,re,stat,sys
root=Path('/home/openai/.local/share/ipat/r931-private-olt-backup')
assert root.is_dir() and not root.is_symlink()
assert root.stat().st_uid==os.getuid() and stat.S_IMODE(root.stat().st_mode)==0o700
p=root/'running-config-full-owner-private.capture'
receipt=root/'running-config-private-receipt.json'
for x in (p,receipt):
 s=x.lstat()
 assert stat.S_ISREG(s.st_mode) and s.st_uid==os.getuid() and s.st_nlink==1
 assert stat.S_IMODE(s.st_mode)==0o600
r=json.loads(receipt.read_text())
with p.open('rb') as f:content=f.read(524289)
assert len(content)==119980
assert hashlib.sha256(content).hexdigest()=='5b21f96b7b81dc9a771cc24e6369bc55433748b637bf0e98a3fb0a03e1989ba3'
assert r.get('bytes')==len(content) and r.get('sha256')==hashlib.sha256(content).hexdigest()
assert r.get('source')=='ACTUAL_MANUAL_INTERACTIVE_ENCRYPTED_PRIVATE_SSH_CLI'
assert r.get('complete_running_config_marker_verified') is True
assert r.get('device_adopted') is False and r.get('vendor_restorability_tested') is False
assert content.startswith(b'Building configuration')
assert re.search(rb'(?m)^[ ]*end\r?\s*$',content)
assert b'--More--' not in content and b'\x1b' not in content
sys.stdout.buffer.write(content)
sys.stdout.buffer.flush()
'''.strip()

class Refused(ValueError):pass

def private_dir(path):
    if not path.is_absolute() or path.resolve()!=path:
        raise Refused('canonical owner-private absolute path required')
    s=path.lstat()
    if not stat.S_ISDIR(s.st_mode) or s.st_uid!=os.getuid() or stat.S_IMODE(s.st_mode)!=0o700:
        raise Refused('0700 owner-private real directory required')

def check_mac(repo,receipt_dir,*,require_tty=True):
    if platform.system()!='Darwin' or os.geteuid()==0 or (require_tty and not sys.stdin.isatty()):
        raise Refused('trusted human owner Mac Terminal only, not remote automation')
    if subprocess.run(['/usr/bin/fdesetup','status'],capture_output=True,text=True,timeout=10).stdout.strip()!='FileVault is On.':
        raise Refused('FileVault ON required')
    private_dir(repo)
    private_dir(receipt_dir)
    c=repo/'config'
    if not c.is_file() or c.is_symlink() or stat.S_IMODE(c.stat().st_mode)!=0o400:
        raise Refused('existing reviewed encrypted Restic repository expected')
    if shutil.which('restic') is None or shutil.which('ssh') is None:
        raise Refused('installed Restic and OpenSSH required')
    if not (repo/'data').is_dir():raise Refused('existing encrypted repository data missing')
    if subprocess.run(['/usr/bin/security','find-generic-password',
        '-a','ipat-lab-backup','-s','id.ipat.lab.restic.backup.v1'],
        capture_output=True,timeout=10).returncode!=0:
        raise Refused('previous reviewed macOS Keychain escrow record unavailable')

def snapshots(repo,env):
    p=subprocess.run(['restic','-r',str(repo),'snapshots','--json'],env=env,
        capture_output=True,timeout=180,check=True)
    rows=json.loads(p.stdout)
    return {row['id']:row for row in rows if SNAPSHOT_TAG in row.get('tags',[])
        and ('/'+SNAPSHOT_NAME) in row.get('paths',[])}

def verify_existing(repo,env,snap,receipt_dir):
    # This is byte-restoration of the captured CLI reference, NOT device recovery.
    subprocess.run(['restic','-r',str(repo),'check','--read-data'],env=env,
                   stdout=subprocess.DEVNULL,check=True,timeout=3600)
    tmp=Path(tempfile.mkdtemp(prefix='ipat-c320-r931-restore-',dir=receipt_dir))
    try:
        subprocess.run(['restic','-r',str(repo),'restore',snap,
             '--target',str(tmp)],env=env,stdout=subprocess.DEVNULL,
             check=True,timeout=300)
        restored=tmp/SNAPSHOT_NAME
        if restored.is_symlink() or not restored.is_file():
            raise Refused('isolated restore missing or linked')
        # Stream safely inside trusted current-owner Mac, never to ChatGPT.
        hashobj=hashlib.sha256();count=0
        with restored.open('rb') as stream:
            while True:
                part=stream.read(65536)
                if not part:break
                count+=len(part);hashobj.update(part)
        if count!=EXPECTED_LENGTH or hashobj.hexdigest()!=EXPECTED_SHA:
            raise Refused('isolated restored bytes mismatch actual captured reference')
    finally:
        shutil.rmtree(tmp)
    return {'restic_snapshot_id':snap,'sha256':EXPECTED_SHA,
      'bytes':EXPECTED_LENGTH,'encrypted_off_vps_snapshot_verified':True,
      'isolated_restic_restore_identical':True,'plain_restore_deleted':True,
      'actual_vendor_native_import_verified':False,
      'device_side_restore_rehearsed':False,
      'independent_second_site_replication_verified':False,
      'temporary_default_credential_rotated':False,
      'dedicated_restricted_service_account_verified':False,
      'actual_auto_device_adopted':False}

def reverify_existing_receipt(path,result):
    s=path.lstat()
    if not stat.S_ISREG(s.st_mode) or s.st_uid!=os.getuid() or s.st_nlink!=1 \
       or stat.S_IMODE(s.st_mode)!=0o600 or not 1<=s.st_size<=4096:
        raise Refused('previous backup receipt ownership/mode invalid')
    previous=json.loads(path.read_text())
    if any(previous.get(k)!=v for k,v in result.items() if k!='verified_utc'):
        raise Refused('previous operator receipt contradicts fresh isolated restore')

def run(mode):
    if mode=='--requirements':
        print(json.dumps({'mode':'HUMAN_OWNER_MAC_TERMINAL_ONLY',
          'device_commands':0,'exposed_passwords':0,
          'external_encrypted_backup_performed_by_this_check':False,
          'actual_device_adopted':False,'requires_tty':True},sort_keys=True))
        return
    home=Path.home()
    repo=home/'IPAT-secure-backups/restic-lab-v1'
    receipt_dir=home/'.local/share/ipat/c320-real-read-20260929'
    check_mac(repo,receipt_dir,require_tty=(mode!='--local-readiness'))
    if mode=='--local-readiness':
        print('OWNER_MAC_FILEVAULT_RESTIC_REPO_KEYCHAIN_METADATA_PRESENT')
        print('OFF_VPS_C320_ENCRYPTED_BACKUP_AND_RESTORE_NOT_PERFORMED_BY_READINESS')
        return
    receipt=receipt_dir/'r932-verified-restic-snapshot-receipt.json'
    if mode=='--backup-and-restore' and (receipt.exists() or receipt.is_symlink()):
        raise Refused('existing immutable backup receipt; no duplicate silent backup')
    print('OFF-VPS encrypted backup of real SENSITIVE CLI transcript;')
    print('no device commands; still NOT vendor-native restore or production adoption.')
    confirmation=input('Type ENCRYPT_AND_TEST_OFF_VPS_LAB_CONFIG to authorize: ').strip()
    if confirmation!='ENCRYPT_AND_TEST_OFF_VPS_LAB_CONFIG':raise Refused('consent not given')
    env=os.environ.copy()
    for k in ('RESTIC_PASSWORD','RESTIC_PASSWORD_FILE','RESTIC_PASSWORD_COMMAND'):
        env.pop(k,None)
    env['RESTIC_PASSWORD_COMMAND']='/usr/bin/security find-generic-password -a ipat-lab-backup -s id.ipat.lab.restic.backup.v1 -w'
    before=snapshots(repo,env)
    if mode=='--backup-and-restore':
        producer=['ssh','-T','-o','BatchMode=yes','-o','StrictHostKeyChecking=yes',
          '-o','ControlMaster=no','-o','ControlPath=none','-o','ConnectTimeout=7',
          '-o','ConnectionAttempts=1','ipat-lab',
          'python3 -c '+shlex.quote(REMOTE_PRODUCER)]
        subprocess.run(['restic','-r',str(repo),'backup','--tag',SNAPSHOT_TAG,
          '--stdin-filename',SNAPSHOT_NAME,'--stdin-from-command','--',*producer],
          env=env,check=True,timeout=240,stdout=subprocess.DEVNULL)
    after=snapshots(repo,env)
    fresh=set(after)-set(before)
    if mode=='--backup-and-restore' and len(fresh)!=1:
        raise Refused('ambiguous new encrypted backup; refuse unsupported restore claim')
    if mode=='--verify-only' and len(after)!=1:
        raise Refused('verify-only requires exactly one pinned C320 backup snapshot')
    snap=next(iter(fresh)) if mode=='--backup-and-restore' else next(iter(after))
    if not re.fullmatch(r'[a-f0-9]{64}',snap):
        raise Refused('unexpected encrypted repository snapshot identifier')
    result=verify_existing(repo,env,snap,receipt_dir)
    result['verified_utc']=datetime.now(timezone.utc).isoformat(timespec='seconds')
    if receipt.exists() or receipt.is_symlink():
        reverify_existing_receipt(receipt,result)
    else:
        fd=os.open(receipt,os.O_WRONLY|os.O_CREAT|os.O_EXCL|getattr(os,'O_NOFOLLOW',0),0o600)
        with os.fdopen(fd,'w') as out:
            json.dump(result,out,sort_keys=True,indent=2)
            out.write('\n');out.flush();os.fsync(out.fileno())
    print('OWNER_MAC_ENCRYPTED_OFF_VPS_C320_CAPTURE_ISOLATED_RESTORE_VERIFIED')
    print('PUBLIC_SAFE_BACKUP_STATE: RECOVERABLE_READABLE_REFERENCE_ONLY')
    print('DEVICE_NATIVE_RESTORE: NOT_TESTED, DEVICE_AUTO_ADOPTED: FALSE')

if __name__=='__main__':
    parser=argparse.ArgumentParser(description=__doc__)
    group=parser.add_mutually_exclusive_group(required=True)
    group.add_argument('--requirements',action='store_true')
    group.add_argument('--local-readiness',action='store_true')
    group.add_argument('--backup-and-restore',action='store_true')
    group.add_argument('--verify-only',action='store_true')
    arg=parser.parse_args()
    option=('--requirements' if arg.requirements else
            '--local-readiness' if arg.local_readiness else
            '--backup-and-restore' if arg.backup_and_restore else '--verify-only')
    try:run(option)
    except (Refused,OSError,subprocess.SubprocessError,ValueError):
        print('OWNER_OFF_VPS_BACKUP_NOT_VERIFIED_FAIL_CLOSED_NO_SECRETS_PRINTED',file=sys.stderr)
        sys.exit(4)
