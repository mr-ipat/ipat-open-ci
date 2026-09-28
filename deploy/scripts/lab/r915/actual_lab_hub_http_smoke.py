#!/usr/bin/env python3
"""R9.15 real loopback HTTP check of central Site A plan and historical observation.
No authentication, device traffic, live VPN or host config mutation.
"""
import json
import subprocess
import os
import sys
from urllib.request import build_opener, ProxyHandler, Request
from urllib.error import HTTPError

BASE='http://127.0.0.1:3002'
OPENER=build_opener(ProxyHandler({}))
MOCK={'gateway':'routeros7_x86','segmentation':'same_shared_lan',
      'recovery':'console_available_untested','service_baseline':'unmeasured'}

def call(path, payload=None, origin=True):
    headers={'Host':'127.0.0.1:3002','Content-Type':'application/json'}
    if origin:
        headers.update({'Origin':BASE,'X-IPAT-Demo-Only':'1'})
    req=Request(BASE+path,data=json.dumps(payload).encode() if payload is not None else None,
                headers=headers,method='POST' if payload is not None else 'GET')
    try:
        with OPENER.open(req,timeout=3) as resp:
            return resp.status,dict(resp.headers),resp.read(32768)
    except HTTPError as exc:
        return exc.code,dict(exc.headers),exc.read(4096)

def main():
    if os.geteuid()==0 or os.environ.get('IPAT_R915_LAB_HTTP_SMOKE')!='YES':
        raise ValueError('explicit nonroot opt-in required')
    status,headers,payload=call('/lab/demo/tunnel-review',MOCK)
    assert status==200 and headers.get('cache-control')=='no-store'
    body=json.loads(payload)
    assert body['lab_only'] is True and body['synthetic_only'] is True
    assert body['preflight_status']=='BLOCKED_PENDING_REAL_REVIEW'
    for name in ('config_generated','secrets_accepted','tunnel_created',
                 'worker_dispatch_enabled','device_adopted','service_impact_measured'):
        assert body[name] is False,name
    assert body['network_actions']==0
    assert 'MANAGEMENT_LAST_HOP_ISOLATION_NOT_VERIFIED' in body['missing_evidence']
    assert 'INDEPENDENT_APPROVAL_REQUIRED' in body['missing_evidence']
    ideal=dict(MOCK,segmentation='verified_isolated',recovery='console_restore_tested',
               service_baseline='approved_measured')
    code,_,data=call('/lab/demo/tunnel-review',ideal)
    assert code==200
    result=json.loads(data)
    assert result['preflight_status']=='BLOCKED_PENDING_REAL_REVIEW'
    assert len(result['missing_evidence'])==4
    assert result['network_actions']==0 and result['tunnel_created'] is False
    assert call('/lab/demo/tunnel-review',MOCK,origin=False)[0]==403
    for bad in (dict(MOCK,private_key='INJECTED'),dict(MOCK,endpoint='10.77.13.233'),
                dict(MOCK,gateway='routeros6',segmentation='wrong')):
        assert call('/lab/demo/tunnel-review',bad)[0] in (400,422)
    html=call('/lab/device-workbench')
    assert html[0]==200 and b'check-wg-review' in html[2]
    evidence=call('/lab/device-physical-evidence')
    assert evidence[0]==200 and json.loads(evidence[2])['device_adopted'] is False
    history=json.loads(evidence[2]);assert history['candidate_inventory_state']=='OBSERVED_NOT_ADOPTED'
    assert history['owner_reported_pop']=='UNVERIFIED'
    assert history['worker_route_observation']=='DEFAULT_ROUTE_ONLY'
    assert history['direct_private_vps_ssh_transport_observed'] is True
    assert history['direct_private_vps_ssh_banner']=='ZTE_SSH.1.0'
    assert history['direct_private_vps_ssh_credentials_sent'] is False
    assert history['direct_private_vps_ssh_olt_commands_executed']==0
    assert history['direct_private_vps_ssh_host_identity_verified'] is False
    assert history['direct_private_vps_ssh_last_hop_isolation_verified'] is False
    assert history['worker_route_check_packets_sent']==0
    assert history['actual_worker_private_route_verified'] is False
    assert history['temporary_owner_mac_vps_ssh_relay_observed'] is True
    assert history['temporary_owner_mac_vps_ssh_relay_closed'] is True
    assert history['temporary_relay_credentials_sent'] is False
    assert history['temporary_relay_olt_commands_executed']==0
    assert history['temporary_relay_trusted_last_hop_verified'] is False
    js=call('/lab/device-workbench.js')
    assert js[0]==200 and b'physical-observed-row' in js[2]
    assert b'BELUM DIADOPSI' in js[2]
    assert b'worker_route_observation' in js[2]
    assert b'site-a-hub-panel' in html[2]
    assert b'/lab/demo/site-a-plan' in js[2]
    hub={'method':'wireguard','hub_address_scope':'public',
         'site_b_path':'external','site_b_gateway':'routeros7'}
    code,headers,response=call('/lab/demo/site-a-plan',hub)
    assert code==200 and headers.get('cache-control')=='no-store'
    result=json.loads(response)
    assert result['topology_candidate']=='PUBLIC_HUB_WG_SITE_B_INITIATES'
    assert result['site_a_role']=='IPAT_CENTRAL_CONFIGURATION_AUTHORITY'
    assert result['site_b_role']=='SITE_OPERATOR_SELF_CONFIGURES_NO_PUSH'
    assert result['state']=='REVIEW_ONLY_NOT_DEPLOYABLE'
    assert result['router_push_enabled'] is False
    assert result['secrets_accepted'] is False
    assert result['config_generated'] is False
    assert result['network_actions']==0
    assert result['device_adopted'] is False
    private=dict(hub,hub_address_scope='private',site_b_path='verified_private')
    code,_,response=call('/lab/demo/site-a-plan',private)
    assert code==200 and json.loads(response)['topology_candidate']=='PRIVATE_HUB_WG_SITE_B_INITIATES'
    assert call('/lab/demo/site-a-plan',hub,origin=False)[0]==403
    for injected in (dict(hub,password='FORBIDDEN'), dict(hub,endpoint='10.77.13.233')):
        assert call('/lab/demo/site-a-plan',injected)[0] in (400,422)
    assert call('/v1/devices/DEV-01')[0]==401
    assert call('/v1/tenant/overview')[0]==401
    actual_listeners=subprocess.check_output(['ss','-lnt'],text=True)
    assert '127.0.0.1:3002' in actual_listeners
    assert '0.0.0.0:3002' not in actual_listeners
    assert '[::]:3002' not in actual_listeners
    req=Request('http://127.0.0.1:3000/healthz')
    with OPENER.open(req,timeout=3) as old:
        assert old.status==200
    print('R915_ACTUAL_PRIVATE_HUB_HTTP=PASS; old :3000 OK')

if __name__=='__main__':
    try: main()
    except (AssertionError,OSError,ValueError,KeyError,TypeError):
        print('R915_PRIVATE_HTTP_FAIL_CLOSED',file=sys.stderr)
        sys.exit(4)
