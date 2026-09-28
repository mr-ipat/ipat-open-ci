#!/usr/bin/env python3
"""Build Site A-owned, DISABLED Site B pairing from locally held Site A key.
No SSH, RouterOS API, WireGuard activation, firewall or route modifications.
Topology, real Site B PUBLIC key and output remain owner-only local files.
"""
import argparse
import json
import os
import re
from pathlib import Path
import stat
import sys

HERE=Path(__file__).resolve().parent
sys.path.insert(0,str(HERE.parent/'r915'))
from site_a_plan import review
from pairing_bundle_review import render,public_key
from site_a_keypair import public_from_folder, _strict_private_folder, SLUG

ROOT=HERE.parents[3]

def read_private_input(path,upper):
    if not path.is_absolute() or not path.exists():
        raise ValueError('required absolute owner-only input missing')
    real=path.resolve()
    if (ROOT/'IPAT_PROJECT_BRIEF.md').is_file() and (real==ROOT or ROOT in real.parents):
        raise ValueError('real topology/key inputs forbidden inside project')
    st=path.lstat()
    if not stat.S_ISREG(st.st_mode) or st.st_uid!=os.getuid() or st.st_nlink!=1 or stat.S_IMODE(st.st_mode)!=0o600 or not 2<=st.st_size<=upper:
        raise ValueError('owner-only 0600 one-link file required')
    fd=os.open(path,os.O_RDONLY|getattr(os,'O_NOFOLLOW',0))
    with os.fdopen(fd,'rb') as stream:
        after=os.fstat(stream.fileno())
        if (st.st_dev,st.st_ino)!=(after.st_dev,after.st_ino):
            raise ValueError('input changed during read')
        raw=stream.read(upper+1)
    if len(raw)>upper:
        raise ValueError('input too large')
    return raw

def reconcile(key_parent,site_slug,topology_path,b_public_file,udp_port):
    if os.geteuid()==0 or not SLUG.fullmatch(site_slug) or site_slug.endswith('-'):
        raise ValueError('nonroot exact site slug required')
    data=json.loads(read_private_input(topology_path,8192))
    plan=review(data)
    if plan['link_mode']=='direct_private':
        # An independently verified private site connection needs NO VPN.
        result=render(data,site_slug,'','',udp_port)
    else:
        if plan['link_mode']!='wireguard' or b_public_file is None:
            raise ValueError('IPsec unsupported and real Site B PUBLIC key required')
        site_a=public_from_folder(key_parent,site_slug)['site_a_public_key']
        remote=read_private_input(b_public_file,128).decode('ascii').strip()
        result=render(data,site_slug,site_a,public_key(remote),udp_port)
    if result['network_actions']!=0 or result['router_push_enabled'] is not False or result['device_adopted'] is not False:
        raise ValueError('refusing unsafe pairing renderer')
    return result

def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--site-a-owner-key-folder',type=Path,required=True)
    parser.add_argument('--site-slug',required=True)
    parser.add_argument('--topology-json',type=Path,required=True)
    parser.add_argument('--site-b-public-key-file',type=Path)
    parser.add_argument('--reviewed-udp-port',type=int,required=True)
    parser.add_argument('--output-parent',type=Path,required=True)
    parser.add_argument('--output-name',default='disabled-site-b-review.json')
    args=parser.parse_args()
    if os.geteuid()==0 or not re.fullmatch(r'[a-z][a-z0-9_-]{0,40}\.json',args.output_name):
        parser.error('nonroot safe output file required')
    try:
        folder=_strict_private_folder(args.output_parent)
        result=reconcile(args.site_a_owner_key_folder,args.site_slug,
                         args.topology_json,args.site_b_public_key_file,args.reviewed_udp_port)
        target=folder/args.output_name
        payload=(json.dumps(result,sort_keys=True,indent=2)+'\n').encode()
        fd=os.open(target,os.O_WRONLY|os.O_CREAT|os.O_EXCL|getattr(os,'O_NOFOLLOW',0),0o600)
        try:
            with os.fdopen(fd,'wb') as stream:
                stream.write(payload)
                stream.flush();os.fsync(stream.fileno())
        except BaseException:
            target.unlink(missing_ok=True)
            raise
        print(json.dumps({'status':result['mode'],
            'site_b_config_requires_local_operator':True,
            'router_push_enabled':False,'network_actions':0,
            'device_adopted':False,'output_private_owner_only':True},sort_keys=True))
    except (ValueError,OSError,UnicodeError,TypeError,KeyError,json.JSONDecodeError):
        print('SITE_A_RECONCILIATION_DENIED_NO_ROUTER_ACTIONS',file=sys.stderr)
        return 4
    return 0

if __name__=='__main__':sys.exit(main())
