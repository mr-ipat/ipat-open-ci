#!/usr/bin/env python3
"""One-shot actual localhost C320 catalog assertion. No OLT network traffic."""
import json
import os
import sys
from urllib.request import Request,build_opener,ProxyHandler
from urllib.error import HTTPError

BASE='http://127.0.0.1:3002'
OPENER=build_opener(ProxyHandler({}))

def get(path):
    try:
        with OPENER.open(Request(BASE+path,headers={'Cache-Control':'no-store'}),timeout=4) as response:
            return response.status,dict(response.headers),response.read(32768)
    except HTTPError as e:
        return e.code,dict(e.headers),e.read(4096)

def run():
    if os.geteuid()==0 or os.environ.get('IPAT_R930_APPROVE_PRIVATE_LAB_SMOKE')!='YES':
        raise ValueError('nonroot explicit private LAB smoke only')
    status,headers,body=get('/lab/c320-action-readiness')
    assert status==200 and headers.get('cache-control')=='no-store'
    result=json.loads(body)
    assert result['mode']=='PHYSICAL_C320_PRE_ADOPTION_ACTION_CATALOG'
    assert result['target']=='DEV-01'
    assert result['adoption_state']=='AUTHENTICATED_LAB_READ_OBSERVED_ADOPTION_PENDING'
    assert result['preferred_connection']=='ENCRYPTED_LEGACY_SSH_OBSERVED_NETWORK_KEY_LAB_ONLY'
    assert result['transport']=='OWNER_APPROVED_AUTHENTICATED_LAB_SSH_AND_TELNET_FIRST_READ'
    assert result['tested_legacy_ssh_profile']=='RSA_AES128CBC_GROUP14SHA256_ONLY'
    assert result['actual_transport_authentication_stage_reached'] is True
    assert result['observed_network_host_key_still_untrusted'] is True
    assert result['credential_free_test_no_timeout'] is True
    assert result['physical_test_actual_login_performed'] is True
    assert result['credentials_sent_during_transport_test'] is False
    assert result['olt_commands_during_transport_test']==0
    assert result['observed_test_account_ssh_auth_methods']==['password']
    assert result['publickey_offer_observed_for_test_account'] is False
    assert result['password_sent_to_physical_olt'] is True
    assert result['real_device_authenticated'] is True
    assert result['model_and_firmware_read_from_real_hardware'] is True
    assert result['observed_lab_ssh_password_session_authenticated'] is True
    assert result['observed_lab_telnet_password_session_authenticated'] is True
    assert result['owner_attests_no_customer_connections_in_test_lab'] is True
    assert result['actual_cards_reported']==3
    assert result['actual_cards_reported_inservice']==3
    assert result['actual_version_rows_reported']==5
    assert result['actual_firmware_filetype_alias_unresolved'] is True
    assert result['actual_pram_running_mvr_not_reported'] is True
    assert result['observed_ssh_network_rsa_is_not_independent_physical_attestation'] is True
    assert result['temporary_default_test_credential_needs_rotation'] is True
    assert result['lab_manual_successful_read_commands']==5
    assert result['lab_unsupported_read_command_rejected']==1
    assert result['production_auto_adoption_approved'] is False
    assert result['alternate_telnet323_passive_tcp_reachable'] is True
    assert result['alternate_telnet323_real_telnet_iac_observed'] is True
    assert result['alternate_telnet323_observed_inbound_bytes']==15
    assert result['alternate_telnet323_credentials_sent'] is False
    assert result['alternate_telnet323_host_identity_unverified'] is True
    assert result['alternate_telnet323_unencrypted_not_approved_for_login'] is False
    assert result['alternate_telnet323_olt_commands_executed']==0
    for field in ('independent_oob_olt_host_key_verified',
      'dedicated_device_readonly_account_verified','management_last_hop_isolated',
      'live_distribution_baseline_approved',
      'genuine_tenant_admin_mfa_verified','independent_reviewer_approved',
      'worker_enabled','device_adopted'):
        assert result[field] is False,field
    assert result['network_actions']==0
    capabilities=result['capabilities'];assert len(capabilities)==8
    assert len({item['action'] for item in capabilities})==8
    assert all(item['enabled'] is False and item['can_run_on_live_device'] is False for item in capabilities)
    assert capabilities[0]['state']=='ACTUAL_MANUAL_LAB_FIRST_READ_VERIFIED_WORKER_BLOCKED'
    assert capabilities[7]['state']=='HIGH_IMPACT_LOCKED'
    for action in ('READ_CARD_INVENTORY','READ_RUNNING_FIRMWARE','UPGRADE_OLT_FIRMWARE','unrecognized'):
        request=Request(BASE+'/lab/c320-actions/'+action,method='POST',
          data=b'{}',headers={'Origin':BASE,'X-IPAT-Demo-Only':'1','Content-Type':'application/json'})
        try:
            OPENER.open(request,timeout=3)
            raise ValueError('unsafe OLT action POST accepted')
        except HTTPError as e:
            assert e.code==403
            denied=json.load(e)
            assert denied['device_adopted'] is False and denied['network_actions']==0
    code,_,page=get('/lab/device-workbench')
    assert code==200 and b'c320-operations' in page
    code,_,js=get('/lab/device-workbench.js')
    assert code==200 and b'PHYSICAL_C320_PRE_ADOPTION_ACTION_CATALOG' in js
    code,_,old=get('/lab/device-physical-evidence')
    assert code==200
    historical=json.loads(old)
    assert historical['device_adopted'] is False
    first=historical['r930_owner_lab_first_read']
    assert first['temporary_telnet_authenticated_interactive'] is True
    assert first['temporary_ssh_authenticated_interactive'] is True
    assert first['observed_cards_insvc']==3
    assert first['observed_running_version_rows']==5
    assert first['ssh_independent_chassis_identity_verified'] is False
    assert first['configuration_changes']==0 and first['adopted'] is False
    assert historical['direct_private_vps_group14_auth_stage_observed_on']=='2026-09-29'
    assert historical['direct_private_vps_group14_kex']=='diffie-hellman-group14-sha256'
    assert historical['direct_private_vps_group14_server_hostkey_packet_received'] is True
    assert historical['direct_private_vps_group14_auth_methods_advertised'] is True
    assert historical['direct_private_vps_group14_actual_login_verified'] is False
    assert historical['direct_private_vps_group14_hostkey_oob_verified'] is False
    assert historical['direct_private_vps_group14_credentials_sent'] is False
    assert historical['direct_private_vps_group14_olt_commands_executed']==0
    with OPENER.open('http://127.0.0.1:3000/healthz',timeout=3) as baseline:
        assert baseline.status==200
    print('R930_OWNER_VPS_PRIVATE_C320_CATALOG_HTTP_PASS')
    print('ALL_EIGHT_ACTIONS_DISABLED;ACTUAL_MANUAL_LAB_READS=5;CONFIG_WRITES=0;OLD_3000_OK')

if __name__=='__main__':
    try:run()
    except (AssertionError,KeyError,TypeError,OSError,ValueError):
        print('R930_FAIL_CLOSED_HTTP_SMOKE',file=sys.stderr)
        sys.exit(4)
