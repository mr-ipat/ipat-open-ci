#!/usr/bin/env python3
"""R9.13 bounded Mac->VPS owner-ONLY AF_UNIX reverse SSH relay.
ONE inbound SSH banner read from owner-approved private candidate,
ZERO credentials, ZERO OLT commands, NO gateway changes. NOT production.
"""
import argparse
import ipaddress
import json
import os
import shlex
import subprocess
import sys
import time
import uuid

ROOT='/home/openai/.cache/ipat/r913-preview'
ENV='IPAT_R913_APPROVE_ONESHOT_PRIVATE_SSH_RELAY'
RFC1918=tuple(map(ipaddress.ip_network,
    ('10.0.0.0/8','172.16.0.0/12','192.168.0.0/16')))

def approved_target(ip,port):
    address=ipaddress.IPv4Address(ip)
    if not any(address in net for net in RFC1918) or type(port)!=int or not 1<=port<=65535:
        raise ValueError('exact RFC1918 host and TCP port required')
    return str(address)

def remote_ssh(command):
    return ['ssh','-T','-o','BatchMode=yes','-o','StrictHostKeyChecking=yes',
            '-o','ConnectTimeout=5','ipat-lab',command]

def relay_args(target,port,sock):
    return ['ssh','-T','-N','-o','BatchMode=yes',
            '-o','StrictHostKeyChecking=yes','-o','ExitOnForwardFailure=yes',
            '-o','ConnectTimeout=5','-o','ControlMaster=no',
            '-o','StreamLocalBindUnlink=no',
            '-R',sock+':'+approved_target(target,port)+':'+str(port),'ipat-lab']

def perform(target,port,run=subprocess.run,popen=subprocess.Popen):
    ip=approved_target(target,port)
    sock=ROOT+'/olt-one-shot-'+uuid.uuid4().hex+'.sock'
    probe='''import json,socket
s=socket.socket(socket.AF_UNIX)
s.settimeout(6)
s.connect(PATH)
try:
    banner=s.recv(96)
    print(json.dumps({"ssh_transport_observed":banner.startswith(b"SSH-"),
      "zte_ssh_banner_observed":b"ZTE_SSH.1.0" in banner,
      "bytes_received":len(banner),"credentials_sent":False,
      "olt_commands_executed":0,"device_adopted":False,
      "trusted_last_hop_verified":False,"long_lived_worker_route_verified":False}))
finally:s.close()
'''.replace('PATH',repr(sock))
    before=run(remote_ssh('test -d '+shlex.quote(ROOT)+' && test "$(stat -c %a '+shlex.quote(ROOT)+')" = 700 && test ! -e '+shlex.quote(sock)),
               capture_output=True,text=True,timeout=9,check=False)
    if before.returncode:
        raise ValueError('private owner socket collision or unreachable VPS')
    bridge=popen(relay_args(ip,port,sock),stdin=subprocess.DEVNULL,
                 stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
    try:
        for _ in range(25):
            if bridge.poll() is not None:
                raise ValueError('owner SSH reverse relay declined')
            exists=run(remote_ssh('test -S '+shlex.quote(sock)),
                       capture_output=True,text=True,timeout=9,check=False)
            if exists.returncode==0:break
            time.sleep(.2)
        else:raise ValueError('owner socket never appeared')
        command='python3 -c '+shlex.quote(probe)
        result=run(remote_ssh(command),capture_output=True,text=True,
                   timeout=15,check=False)
        if result.returncode:
            raise ValueError('private owner relay banner check unavailable')
        data=json.loads(result.stdout)
        if (data.get('credentials_sent') is not False
                or data.get('olt_commands_executed')!=0
                or data.get('device_adopted') is not False
                or data.get('long_lived_worker_route_verified') is not False):
            raise ValueError('private relay output fails safety assertions')
        return data
    finally:
        bridge.terminate()
        try:bridge.wait(timeout=5)
        except subprocess.TimeoutExpired:
            bridge.kill();bridge.wait(timeout=5)
        # Unlink only our own randomly named socket, never any gateway rule.
        cleanup=run(remote_ssh('rm -f '+shlex.quote(sock)+' && test ! -e '+shlex.quote(sock)),
            capture_output=True,text=True,timeout=9,check=False)
        if cleanup.returncode:
            raise ValueError('temporary private relay socket cleanup unverified')

def main():
    parser=argparse.ArgumentParser(description=__doc__)
    mode=parser.add_mutually_exclusive_group(required=True)
    mode.add_argument('--requirements',action='store_true')
    mode.add_argument('--probe',action='store_true')
    parser.add_argument('--private-ipv4')
    parser.add_argument('--port',type=int)
    args=parser.parse_args()
    if args.requirements:
        print(json.dumps({'mode':'EPHEMERAL_OWNER_MAC_RELAY_NOAUTH',
            'actual_device_adopted':False,'olt_commands_executed':0,
            'long_lived_private_route_verified':False}))
        return 0
    if os.geteuid()==0 or os.environ.get(ENV)!='YES':
        parser.error('nonroot operator and explicit bounded one-shot opt-in required')
    try:
        result=perform(args.private_ipv4 or '',args.port)
    except (ValueError,OverflowError,OSError,subprocess.TimeoutExpired,
            json.JSONDecodeError):
        print('R913_TEMP_PRIVATE_RELAY_DENIED_OR_INCONCLUSIVE',file=sys.stderr)
        return 4
    print(json.dumps(dict(result,ephemeral_relay_stopped=True),sort_keys=True))
    return 0

if __name__=='__main__':sys.exit(main())
