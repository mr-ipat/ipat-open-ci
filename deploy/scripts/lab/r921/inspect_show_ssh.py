#!/usr/bin/env python3
"""Strict offline review of operator-owned ZTE C320 `show ssh` transcript.
Never connects to the OLT, consumes credentials, updates server keys or
concludes a real device is identified from unverified owner-supplied text.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import sys

ROOT=Path(__file__).resolve().parents[4]
LINE=re.compile(r'^SSH ([A-Za-z -]+)\s*:\s*(.*?)\s*$')
FIELDS={
 'enable-flag configuration': ('enable','disable'),
 'version': ('ver1.0','ver2.0','ver1','ver2'),
 'only configuration': ('enable','disable'),
 'init server key': ('not initialized','initialized','disable','enable'),
 'auth mode': ('local','aaa','radius'),
 'auth type': ('pap','chap','public-key','password'),
}
class Denied(ValueError):pass

def owner_input(file):
    if not file.is_absolute() or not file.is_file():raise Denied('absolute owner-only console transcript required')
    if ROOT==file or ROOT in file.parents:raise Denied('no real console transcript inside Git')
    parent=file.parent
    if parent.resolve()!=parent:raise Denied('symlinked parent not allowed')
    p=parent.lstat();f=file.lstat()
    if not stat.S_ISDIR(p.st_mode) or p.st_uid!=os.getuid() or stat.S_IMODE(p.st_mode)!=0o700:
        raise Denied('real 0700 owner directory required')
    if not stat.S_ISREG(f.st_mode) or f.st_uid!=os.getuid() or f.st_nlink!=1 or stat.S_IMODE(f.st_mode)!=0o600 or not 20<=f.st_size<=8192:
        raise Denied('0600 single-link small regular transcript required')
    fd=os.open(file,os.O_RDONLY|getattr(os,'O_NOFOLLOW',0))
    with os.fdopen(fd,'rb') as stream:
        after=os.fstat(stream.fileno())
        if (f.st_dev,f.st_ino)!=(after.st_dev,after.st_ino):raise Denied('file changed during read')
        data=stream.read(8193)
    if len(data)>8192 or any(byte in data for byte in (b'\x00',b'\x1b')):
        raise Denied('unsafe or oversized transcript')
    try:txt=data.decode('ascii')
    except UnicodeDecodeError:raise Denied('console must be ASCII') from None
    if re.search(r'(?i)(?:password|private.?key|secret|username)\s*[:=]',txt):
        raise Denied('console transcript must not expose credentials')
    return txt,data

def analyze(text):
    if not re.search(r'(?m)^SSH configuration:\s*$',text):
        raise Denied('exact ZTE show ssh header required')
    evidence={}
    for line in text.replace('\r','').splitlines():
        match=LINE.fullmatch(line.strip())
        if not match:continue
        name=match.group(1).strip().lower();value=match.group(2).strip().lower()
        if name not in FIELDS:continue
        if name in evidence:raise Denied('duplicate SSH setting forbidden')
        if value not in FIELDS[name]:raise Denied('unexpected vendor SSH setting requires manual review')
        evidence[name]=value
    required=('enable-flag configuration','version','init server key','auth mode','auth type')
    if any(key not in evidence for key in required):raise Denied('incomplete exact vendor show ssh report')
    key=evidence['init server key']
    if evidence['enable-flag configuration']=='disable':phase='SSH_DAEMON_REPORTED_DISABLED'
    elif evidence['version'] in ('ver1','ver1.0'):phase='SSH_V1_REPORTED_REQUIRES_SITE_SECURITY_REVIEW'
    elif key=='not initialized':phase='SSHV2_HOST_KEY_INITIALIZATION_FIELD_AMBIGUOUS'
    elif key=='disable':phase='SSHV2_HOST_KEY_INITIALIZATION_FIELD_AMBIGUOUS'
    else:phase='HOST_KEY_REPORTED_PRESENT_KEX_STILL_NEEDS_DIAGNOSIS'
    return {
       'mode':'OWNER_ASSERTED_OFFLINE_C320_SSH_SETTINGS_ONLY',
       'ssh_daemon_reported_enabled':evidence['enable-flag configuration']=='enable',
       'ssh_version_reported':evidence['version'],
       'ssh_host_key_state_reported':key,
       'ssh_auth_mode_reported':evidence['auth mode'],
       'ssh_auth_type_reported':evidence['auth type'],
       'preauthentication_triage':phase,
       'ssh_host_key_from_physical_console_obtained':False,
       'real_chassis_identity_verified':False,
       'firmware_verified':False,
       'site_security_review_required':True,
       'live_ssh_config_changes_authorized':False,
       'real_olt_login_attempted':False,
       'olt_commands_executed':0,
       'network_packets_sent':0,
       'device_adopted':False,
       'operational_read_enabled':False
    }

def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('--trusted-console-show-ssh-output',type=Path,required=True)
    p.add_argument('--owner-attests-independent-console-source',action='store_true')
    args=p.parse_args()
    if os.geteuid()==0 or not args.owner_attests_independent_console_source:
        p.error('nonroot owner assertion required for local console transcript')
    try:
        raw,data=owner_input(args.trusted_console_show_ssh_output)
        result=analyze(raw)
        result['console_capture_sha256']=hashlib.sha256(data).hexdigest()
    except (Denied,OSError):
        print('R921_ZTE_CONSOLE_SSH_STATUS_REJECTED_NO_NETWORK_ACTIONS',file=sys.stderr)
        return 4
    print(json.dumps(result,sort_keys=True))
    return 0
if __name__=='__main__':sys.exit(main())
