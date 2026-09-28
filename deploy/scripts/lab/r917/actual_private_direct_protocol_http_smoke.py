#!/usr/bin/env python3
"""Actual VPS :3002 dev-only central Site A/B public-key review HTTP test.
Uses SYNTHETIC B public key generated in memory, NO real customer/router I/O.
"""
import json
import os
import subprocess
import sys
from urllib.request import Request,build_opener,ProxyHandler
from urllib.error import HTTPError
from cryptography.hazmat.primitives.asymmetric import x25519
from cryptography.hazmat.primitives import serialization
import base64

BASE='http://127.0.0.1:3002'
OPENER=build_opener(ProxyHandler({}))

def call(path,payload=None,auth=True):
    headers={'Content-Type':'application/json'}
    if auth:
        headers.update({'Origin':BASE,'X-IPAT-Demo-Only':'1'})
    request=Request(BASE+path,headers=headers,
        data=json.dumps(payload).encode() if payload is not None else None,
        method='POST' if payload is not None else 'GET')
    try:
        with OPENER.open(request,timeout=3) as res:
            return res.status,dict(res.headers),res.read(32768)
    except HTTPError as exc:
        return exc.code,dict(exc.headers),exc.read(4096)

def run():
    if os.geteuid()==0 or os.environ.get('IPAT_R917_ACTUAL_PRIVATE_HTTP_SMOKE')!='YES':
        raise ValueError('nonroot explicit one-time developer-only HTTP check required')
    code,headers,body=call('/lab/dev-site-a-public-key')
    if code!=200 or headers.get('cache-control')!='no-store':
        raise ValueError('dev Site A public key unavailable / HTTP cache unsafe')
    key=json.loads(body)
    assert key['mode']=='DEV_ONLY_PUBLIC_SITE_A_KEY_NOT_AN_ACTIVE_TUNNEL'
    assert key['site_a_private_key_exported'] is False
    assert key['backup_verified'] is False and key['tunnel_active'] is False
    assert key['router_push_enabled'] is False and key['network_actions']==0
    public=key['site_a_public_key']
    assert len(base64.b64decode(public,validate=True))==32
    synthetic=x25519.X25519PrivateKey.generate().public_key().public_bytes(
        serialization.Encoding.Raw,serialization.PublicFormat.Raw)
    body={'site_slug':'dev01-lab','hub_endpoint':'198.51.100.9',
          'external_site_b':True,'a_tunnel_host':'10.253.77.1',
          'b_tunnel_host':'10.253.77.2','olt_private_host':'192.168.77.10',
          'site_b_public_key':base64.b64encode(synthetic).decode(),
          'udp_port':51820}
    status,headers,reply=call('/lab/demo/site-a-manual-pairing',body)
    assert status==200 and headers.get('cache-control')=='no-store'
    pairing=json.loads(reply)
    assert pairing['site_a_public_key']==public
    assert pairing['config_applied'] is False and pairing['network_actions']==0
    assert pairing['router_push_enabled'] is False and pairing['site_a_listener_active'] is False
    assert pairing['backup_verified'] is False and pairing['real_tenant_mfa_verified'] is False
    assert pairing['return_route_independently_verified'] is False
    assert pairing['last_hop_isolation_verified'] is False
    assert pairing['device_adopted'] is False
    commands=pairing['site_b_routeros_disabled_review_commands']
    assert len(commands)==3 and all(c.startswith('/') and 'disabled=yes' in c for c in commands)
    assert public in commands[2]
    assert 'private-key' not in str(pairing) and '0.0.0.0/0' not in str(pairing)
    assert call('/lab/demo/site-a-manual-pairing',body,auth=False)[0]==403
    assert call('/lab/demo/site-a-manual-pairing',dict(body,private_key='FORBIDDEN'))[0] in (400,422)
    assert call('/lab/demo/site-a-manual-pairing',dict(body,site_b_public_key=public))[0]==400
    assert call('/lab/demo/site-a-manual-pairing',dict(body,hub_endpoint='10.99.0.10'))[0]==400
    direct_c320={'device_profile':'zte_c320','candidate_protocol':'ssh_pinned',
                 'network_evidence':'observed_private'}
    status,headers,body=call('/lab/demo/direct-protocol-review',direct_c320)
    assert status==200 and headers.get('cache-control')=='no-store'
    direct=json.loads(body)
    assert direct['preferred_path']=='DIRECT_OVER_EXISTING_NETWORK'
    assert direct['wireguard_required'] is False
    assert direct['network_transport_observed_historically'] is True
    assert direct['actual_protocol_compatibility_verified'] is False
    assert direct['device_adopted'] is False and direct['network_actions']==0
    assert 'routeros_api_ssl' not in direct['available_candidate_protocols']
    assert call('/lab/demo/direct-protocol-review',dict(direct_c320,
       candidate_protocol='routeros_api_ssl'))[0]==400
    assert call('/lab/demo/direct-protocol-review',dict(direct_c320,
       password='FORBIDDEN'))[0] in (400,422)
    assert call('/lab/demo/direct-protocol-review',direct_c320,auth=False)[0]==403
    router={'device_profile':'mikrotik_routeros7',
            'candidate_protocol':'routeros_api_ssl','network_evidence':'unverified'}
    status,headers,payload=call('/lab/demo/direct-protocol-review',router)
    assert status==200 and json.loads(payload)['wireguard_required'] is False
    evidence=call('/lab/device-physical-evidence')
    assert evidence[0]==200
    history=json.loads(evidence[2])
    assert history['device_adopted'] is False
    assert history['direct_private_vps_tls443_noauth_checked'] is True
    assert history['direct_private_vps_tls443_tcp_reachable'] is False
    assert history['direct_private_vps_tls443_credentials_sent'] is False
    assert history['direct_private_vps_tls443_http_requests_sent']==0
    html=call('/lab/device-workbench')
    assert html[0]==200 and b'manual-site-b-form' in html[2] and b'direct-protocol-panel' in html[2]
    js=call('/lab/device-workbench.js')
    assert js[0]==200 and b'DEV_ONLY_DISABLED_MANUAL_SITE_B_PAIRING' in js[2] and b'DIRECT_MANAGEMENT_PROTOCOL_REVIEW_ONLY' in js[2]
    assert call('/v1/devices/DEV-01')[0]==401
    assert call('/v1/tenant/overview')[0]==401
    with OPENER.open('http://127.0.0.1:3000/healthz',timeout=3) as original:
        assert original.status==200
    listen=subprocess.check_output(['ss','-lntu'],text=True)
    assert '127.0.0.1:3002' in listen and '0.0.0.0:3002' not in listen
    print('R917_ACTUAL_PRIVATE_DIRECT_PROTOCOL_AND_OPTIONAL_TUNNEL_LAB_HTTP_PASS')
    print('OLT_COMMANDS=0;ROUTER_B_PUSH=FALSE;WG_ACTIVE=FALSE;ORIGINAL_3000=OK')

if __name__=='__main__':
    try:run()
    except (ValueError,AssertionError,KeyError,TypeError,OSError):
        print('R917_PRIVATE_HTTP_FAIL_CLOSED',file=sys.stderr)
        sys.exit(4)
