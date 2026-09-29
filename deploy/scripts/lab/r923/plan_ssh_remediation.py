#!/usr/bin/env python3
"""No-network, no-write OLT change proposal based on a trusted-console show ssh file.

Never runs CLI, asks for credentials, creates tickets or approves maintenance.
Any real action requires exact firmware support and independently authorized
site engineer with working chassis console and measured service baseline.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import sys

HERE=Path(__file__).resolve().parent
sys.path.insert(0,str(HERE.parent/'r921'))
from inspect_show_ssh import owner_input,analyze,Denied

READONLY=("show ssh", "show card", "show version-running")


def create_plan(raw, captured):
    result=analyze(raw)
    triage=result['preauthentication_triage']
    if result['ssh_version_reported'] in ('ver1','ver1.0'):
        candidate=("ssh server version 2",)
        reason='V1_REPORTED_SITE_APPROVAL_REQUIRED'
    elif not result['ssh_daemon_reported_enabled']:
        candidate=("ssh server enable",)
        reason='DISABLED_REPORTED_SITE_APPROVAL_REQUIRED'
    elif triage=='HOST_KEY_NOT_INITIALIZED_INDICATED_REQUIRES_SITE_REVIEW':
        candidate=()
        reason='NO_AUTOMATIC_SERVER_KEY_GENERATION_FOR_SSHV2'
    else:
        candidate=()
        reason='CLIENT_COMPATIBILITY_SUFFICIENT_DO_NOT_CHANGE_OLT_SSH'
    return {
       'device_slot':'DEV-01',
       'input_kind':'OWNER_ASSERTED_OFFLINE_TRUSTED_CONSOLE_SHOW_SSH',
       'raw_evidence_sha256':hashlib.sha256(captured).hexdigest(),
       'source_independently_attested':False,
       'actual_firmware_independently_verified':False,
       'old_config':{'ssh_version':result['ssh_version_reported'],
                     'ssh_enabled':result['ssh_daemon_reported_enabled'],
                     'server_key_status':result['ssh_host_key_state_reported']},
       'decision':reason,
       'approved_read_only_cli_candidates':list(READONLY),
       'proposed_config_cli_requires_site_console_and_change_approval':list(candidate),
       'configuration_commands_executed':[],
       'rollback':'RESTORE_DOCUMENTED_PRE_CHANGE_STATUS_FROM_LOCAL_CONSOLE_ONLY_AFTER_SITE_APPROVAL',
       'never_use_ssh_server_generate_key_for_unverified_sshv2':True,
       'client_only_working_profile':{
           'hostkey_algorithm':'ssh-rsa',
           'cipher':'aes128-cbc',
           'kex':'diffie-hellman-group14-sha256',
           'exact_device_process_only':True},
       'site_console_recovery_tested':False,
       'service_baseline_compared':False,
       'independent_reviewer_signed':False,
       'production_mfa_authorized':False,
       'actual_olt_login_verified':False,
       'device_adopted':False,
       'physical_commands_sent':0,
       'network_packets_sent':0}


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--trusted-console-show-ssh-output',type=Path,required=True)
    parser.add_argument('--owner-attests-independent-console-source',action='store_true')
    args=parser.parse_args()
    if os.geteuid()==0 or not args.owner_attests_independent_console_source:
        parser.error('nonroot owner-attested private console capture required')
    try:
        text,raw=owner_input(args.trusted_console_show_ssh_output)
        plan=create_plan(text,raw)
    except (Denied,OSError,ValueError):
        print('R923_C320_NO_CHANGE_PLAN_UNSAFE_OR_UNVERIFIED',file=sys.stderr)
        return 4
    print(json.dumps(plan,sort_keys=True))
    return 0
if __name__=='__main__':sys.exit(main())
