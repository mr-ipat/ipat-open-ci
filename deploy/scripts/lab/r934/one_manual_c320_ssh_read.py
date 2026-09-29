#!/usr/bin/env python3
"""One ephemeral owner-authorized ACTUAL lab C320 SSH `show card` read.

INTERACTIVE one-time LAB only; no persistent privileged credential,
no daemon/queue/retry, no device config/firmware/ONT command, no
production SaaS adoption. Uses owner-supplied TEST login only at a TTY.
NOT the commercial restricted production worker.
"""
import argparse
from datetime import datetime, timezone
import getpass
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import subprocess
import sys
import tempfile

TARGET='10.77.13.233'
PORT=321
TEMPORARY_LAB_USER='zte'
KNOWN_HOSTS=Path('/home/openai/.local/share/ipat/r930-network-only-ssh-pin/network_observed_known_hosts')
NORMALIZER=Path('/home/openai/.cache/ipat/r930-partial-cli/target/debug/olt-evidence')
CAPTURE_PARENT=Path('/home/openai/.local/share/ipat')
AUTH='IPAT_R934_APPROVE_EPHEMERAL_OWNER_LAB_READ'
PROMPT=re.compile(rb'(?m)^[-_.A-Za-z0-9]{1,32}#\s*$')
class Refused(ValueError):pass

def owner_private_file(p,expected_mode=0o600):
    s=p.lstat()
    if not stat.S_ISREG(s.st_mode) or s.st_uid!=os.getuid() \
       or s.st_nlink!=1 or stat.S_IMODE(s.st_mode)!=expected_mode:
        raise Refused('trusted owner-only existing evidence mode denied')

def accept_one_actual_card_cli(raw):
    if not isinstance(raw,bytes) or not 64<=len(raw)<=65536:
        raise Refused('bounded real card output required')
    if b'\x00' in raw or b'\x1b' in raw or b'--More--' in raw \
       or b'Invalid command' in raw or b'Error:' in raw:
        raise Refused('vendor result rejected or paged')
    if b'Rack' not in raw or b'Shelf' not in raw or b'Slot' not in raw \
       or b'INSERVICE' not in raw:
        raise Refused('actual C320 card table not recognized')
    # No untrusted byte escaping and no arbitrary CLI command slots.
    return raw

def one_read():
    os.umask(0o077)
    if os.geteuid()==0 or not sys.stdin.isatty() or os.environ.get(AUTH)!='YES':
        raise Refused('actual one-time read requires nonroot human TTY and explicit owner opt-in')
    if not CAPTURE_PARENT.is_dir() or CAPTURE_PARENT.is_symlink():
        raise Refused('nonroot private snapshot parent missing')
    owner_private_file(KNOWN_HOSTS)
    known=KNOWN_HOSTS.read_text('ascii')
    if not known.startswith(f'[{TARGET}]:{PORT} ssh-rsa ') or len(known)>8192:
        raise Refused('exact previously observed private RSA network pin required')
    if not NORMALIZER.is_file() or not os.access(NORMALIZER,os.X_OK):
        raise Refused('audited offline Rust card parser not installed')
    # The owner must explicitly acknowledge LAB exception for the
    # previously shared TEMPORARY level15 account. Never an unattended
    # environment variable, password CLI arg or Git repository secret.
    phrase=input('Type OWNER_LAB_ONLY_ONE_SHOW_CARD_NO_AUTOMATION: ').strip()
    if phrase!='OWNER_LAB_ONLY_ONE_SHOW_CARD_NO_AUTOMATION':
        raise Refused('not approved for one ephemeral LAB read')
    secret=getpass.getpass('Temporary TEST account password (not stored): ')
    if not 1<=len(secret)<=128:raise Refused('invalid owner test credential input')
    import pexpect
    cmd=['ssh','-F','/dev/null','-tt','-p',str(PORT),
       '-o','HostKeyAlgorithms=ssh-rsa',
       '-o','Ciphers=aes128-cbc',
       '-o','KexAlgorithms=diffie-hellman-group14-sha256',
       '-o','StrictHostKeyChecking=yes',
       '-o','UserKnownHostsFile='+str(KNOWN_HOSTS),
       '-o','GlobalKnownHostsFile=/dev/null',
       '-o','PreferredAuthentications=password',
       '-o','PubkeyAuthentication=no',
       '-o','KbdInteractiveAuthentication=no',
       '-o','IdentityAgent=none',
       '-o','NumberOfPasswordPrompts=1',
       '-o','ConnectionAttempts=1','-o','ConnectTimeout=8',
       '-o','ProxyCommand=none','-o','ClearAllForwardings=yes',
       f'{TEMPORARY_LAB_USER}@{TARGET}']
    out=Path(tempfile.mkdtemp(prefix='r934-one-read-',dir=CAPTURE_PARENT))
    out.chmod(0o700)
    c=None
    try:
        c=pexpect.spawn(cmd[0],cmd[1:],encoding=None,timeout=9,maxread=4096,echo=False)
        c.delaybeforesend=0.02
        # Never let invalid host/prompt reach a password send.
        matched=c.expect([rb'(?i)password:\s*$',rb'(?i)host key verification failed',pexpect.EOF,pexpect.TIMEOUT])
        if matched!=0:raise Refused('strict encrypted SSH login challenge not verified')
        c.sendline(secret.encode('utf-8'))
        secret=''
        index=c.expect([PROMPT,rb'(?i)permission denied',pexpect.EOF,pexpect.TIMEOUT])
        if index!=0:raise Refused('LAB authenticated privileged CLI prompt not verified')
        c.sendline(b'show card')
        index=c.expect([PROMPT,pexpect.EOF,pexpect.TIMEOUT],timeout=12)
        if index!=0:raise Refused('CLI first card read timed out without full prompt')
        raw=accept_one_actual_card_cli(c.before)
        # Persist ONLY bounded owner-private CLI command response; never
        # the login banner/credential exchange or device console session.
        source=out/'cards.txt'
        fd=os.open(source,os.O_WRONLY|os.O_CREAT|os.O_EXCL,0o600)
        with os.fdopen(fd,'wb') as stream:
            stream.write(raw);stream.flush();os.fsync(stream.fileno())
        normalized=out/'normalized.json'
        subprocess.run([str(NORMALIZER),'--cards',str(source),'--out',str(normalized)],
            check=True,stdin=subprocess.DEVNULL,stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,timeout=8)
        owner_private_file(normalized)
        observation=json.loads(normalized.read_text())
        if observation.get('card_count')!=3 \
           or [(x['location'],x['observed_type'],x['state']) for x in observation['cards']]!=[
               ('1/1/1','GTGHK','INSERVICE'),
               ('1/1/3','PRAM','INSERVICE'),
               ('1/1/4','SMXA','INSERVICE')]:
            raise Refused('first real board layout changed; stop and review privately')
        audit={
            'mode':'EPHEMERAL_ACTUAL_OWNER_LAB_SSH_ONE_SHOW_CARD',
            'observed_utc':datetime.now(timezone.utc).isoformat(timespec='seconds'),
            'owner_attests_lab_only':True,
            'host_key_source':'MATCHING_OWNER_NETWORK_OBSERVATION_NOT_OOB',
            'cli_commands_sent':['show card','exit'],
            'config_commands_sent':0,
            'physical_slots_observed':3,
            'all_reported_inservice':True,
            'raw_cards_sha256':hashlib.sha256(raw).hexdigest(),
            'raw_cards_bytes':len(raw),
            'credential_persisted':False,
            'device_auto_adopted':False,
            'production_worker_enabled':False,
            'vendor_native_restore_approved':False,
        }
        receipt=out/'manual-one-read-result.json'
        fd=os.open(receipt,os.O_WRONLY|os.O_CREAT|os.O_EXCL,0o600)
        with os.fdopen(fd,'w') as stream:
            json.dump(audit,stream,indent=2,sort_keys=True)
            stream.write('\n');stream.flush();os.fsync(stream.fileno())
        print('R934_REAL_BOUNDED_SSH_CARD_READ_PASS 3/3 VERIFIED LAYOUT; NO DEVICE WRITES')
        print('PRIVATE_AUDIT_RECEIPT_DIR',out)
    finally:
        secret=''
        if c is not None and c.isalive():
            try:c.sendline(b'exit');c.expect(pexpect.EOF,timeout=3)
            except Exception:c.close(force=True)
        # No raw CLI or secret is echoed to tool stdout/stderr.

def main():
    p=argparse.ArgumentParser(description=__doc__)
    modes=p.add_mutually_exclusive_group(required=True)
    modes.add_argument('--requirements',action='store_true')
    modes.add_argument('--one-manual-lab-read',action='store_true')
    args=p.parse_args()
    if args.requirements:
        print(json.dumps({'mode':'HUMAN_INTERACTIVE_ONE_SHOT_LAB_ONLY',
          'requires_owner_lab_approval':True,'does_not_persist_credential':True,
          'default_network_actions':0,'automated_production_adoption':False}))
        return
    try:one_read()
    except (Refused,OSError,subprocess.SubprocessError,ValueError):
        print('R934_ONE_TIME_LAB_READ_DENIED_OR_UNVERIFIED_NO_SECRET_OUTPUT',file=sys.stderr)
        sys.exit(4)
if __name__=='__main__':main()
