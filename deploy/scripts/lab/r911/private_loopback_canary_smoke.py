#!/usr/bin/env python3
"""Run and STOP an isolated R9.11 127.0.0.1:3002 canary; no device I/O.
Never changes firewall, existing :3000 service, tenants or gateway routes.
"""
import json
import os
from pathlib import Path
import socket
import subprocess
import sys
import time
from urllib.error import HTTPError
from urllib.request import Request, urlopen

BIN = Path('/home/openai/.cache/ipat/r911-canary/target/debug/control-api')
BASE = 'http://127.0.0.1:'

def get(port, path, method='GET'):
    try:
        with urlopen(Request(BASE+str(port)+path, method=method), timeout=2) as response:
            return response.status, dict(response.headers), response.read(20000)
    except HTTPError as exc:
        return exc.code, dict(exc.headers), exc.read(1000)

def require(condition):
    if not condition:
        raise RuntimeError('canary private HTTP safety assertion failed')


def main():
    require(os.geteuid() != 0 and os.environ.get('IPAT_R911_CANARY_SMOKE') == 'YES')
    require(BIN.is_file() and BIN.stat().st_uid == os.getuid())
    require(get(3000, '/healthz')[0] == 200)
    with socket.socket() as sock:
        # Reuse TIME_WAIT only; listen() still rejects any active listener.
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        sock.bind(('127.0.0.1', 3002))
        sock.listen(1)
    env=os.environ.copy()
    for name in ('IPAT_LAB_OIDC_VERIFY','IPAT_LAB_SCOPED_MEMBERSHIP',
                 'IPAT_R83_REGISTRY_WRITE','IPAT_R84_SIMULATED_REVIEW',
                 'IPAT_R86_BROWSER_FLOW','IPAT_RUN_K3S_LAB'):
        env.pop(name, None)
    env.update(IPAT_LAB_WEB='1', IPAT_R911_PRIVATE_CANARY='YES')
    proc=subprocess.Popen([str(BIN)], env=env, stdin=subprocess.DEVNULL,
                          stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    try:
        for _ in range(20):
            try:
                if get(3002, '/healthz')[0] == 200:
                    break
            except OSError:
                time.sleep(.2)
        else:
            raise RuntimeError('isolated private canary never became healthy')
        code, headers, data=get(3002, '/lab/device-physical-evidence')
        require(code == 200 and headers.get('cache-control') == 'no-store')
        evidence=json.loads(data)
        require(evidence['target_slot'] == 'DEV-01')
        require(evidence['private_ssh_transport_observed'] is True)
        require(evidence['device_adopted'] is False)
        require(evidence['credentials_sent'] is False)
        require(evidence['olt_commands_executed'] == 0)
        require(evidence['out_of_band_host_key_verified'] is False)
        require(evidence['actual_worker_private_route_verified'] is False)
        require(evidence['health'] == 'NOT_MEASURED')
        code, _, html=get(3002, '/lab/device-workbench')
        require(code == 200 and b'physical-evidence-gates' in html)
        require(get(3002, '/lab/device-physical-evidence','POST')[0] == 405)
        require(get(3002, '/v1/devices/DEV-01')[0] == 401)
        require(get(3002, '/v1/tenant/overview')[0] == 401)
        listening=subprocess.check_output(['ss','-lnt'], text=True)
        require('127.0.0.1:3002' in listening)
        require('0.0.0.0:3002' not in listening)
        require(get(3000, '/healthz')[0] == 200)
    finally:
        proc.terminate()
        try:
            proc.wait(timeout=5)
        except subprocess.TimeoutExpired:
            proc.kill(); proc.wait(timeout=5)
    require(get(3000, '/healthz')[0] == 200)
    listening=subprocess.check_output(['ss','-lnt'], text=True)
    require('127.0.0.1:3002' not in listening)
    print('PRIVATE_R911_CANARY_SMOKE_PASS; old lab stayed healthy; canary stopped')

if __name__ == '__main__':
    try:
        main()
    except (OSError, RuntimeError, KeyError, ValueError):
        print('PRIVATE_R911_CANARY_SMOKE_FAILED; inspect owner-only console',file=sys.stderr)
        sys.exit(2)
