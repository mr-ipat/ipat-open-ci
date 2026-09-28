#!/usr/bin/env python3
"""Generate and seal a dev-only Site A X25519/WireGuard peer keypair LOCALLY.
No Router B connection, no tunnel, no firewall or active network change.
Do not treat this developer key store as production vault/backup custody.
"""
import argparse
import base64
import json
import os
from pathlib import Path
import re
import stat
import sys
from cryptography.hazmat.primitives.asymmetric import x25519
from cryptography.hazmat.primitives import serialization

SLUG=re.compile(r'^[a-z][a-z0-9-]{0,30}$')

def _strict_private_folder(path):
    if not path.is_absolute() or not path.exists():
        raise ValueError('existing absolute owner-only private folder required')
    st=path.lstat()
    if not stat.S_ISDIR(st.st_mode) or stat.S_IMODE(st.st_mode)!=0o700 or st.st_uid!=os.getuid():
        raise ValueError('private folder must be owned by nonroot user, 0700 and not a symlink')
    # Deployment may copy this script to an owner-only staging folder.
    # Treat the inferred parent as a repository ONLY when project sentinels
    # are actually present; otherwise '/home' could be a false positive.
    root=Path(__file__).resolve().parents[4]
    if (root/'IPAT_PROJECT_BRIEF.md').is_file() and (root/'Cargo.toml').is_file():
        if path.resolve()==root or root in path.resolve().parents:
            raise ValueError('never write actual private keys inside source repository')
    return path

def _persist(fd,contents):
    with os.fdopen(fd,'wb') as f:
        f.write(contents)
        f.flush();os.fsync(f.fileno())

def create(folder,slug):
    if os.geteuid()==0 or not SLUG.fullmatch(slug) or slug.endswith('-'):
        raise ValueError('nonroot and safe unique site label required')
    parent=_strict_private_folder(folder)
    key_dir=parent/('site-a-'+slug)
    if key_dir.exists() or key_dir.is_symlink():
        raise ValueError('refuse to overwrite or rotate existing keypair')
    key_dir.mkdir(mode=0o700)
    try:
        private=x25519.X25519PrivateKey.generate()
        secret=private.private_bytes(serialization.Encoding.Raw,
            serialization.PrivateFormat.Raw,serialization.NoEncryption())
        public=private.public_key().public_bytes(serialization.Encoding.Raw,
            serialization.PublicFormat.Raw)
        private_fd=os.open(key_dir/'private.key',os.O_WRONLY|os.O_CREAT|os.O_EXCL|getattr(os,'O_NOFOLLOW',0),0o600)
        _persist(private_fd,base64.b64encode(secret)+b'\n')
        public_fd=os.open(key_dir/'public.key',os.O_WRONLY|os.O_CREAT|os.O_EXCL|getattr(os,'O_NOFOLLOW',0),0o600)
        _persist(public_fd,base64.b64encode(public)+b'\n')
        # Sidecar does not disclose endpoint or tenant, never contains keys.
        dirfd=os.open(key_dir,os.O_RDONLY)
        try:os.fsync(dirfd)
        finally:os.close(dirfd)
        return {'status':'SITE_A_LOCAL_KEY_MATERIAL_STAGED_NOT_ACTIVE',
            'site_slug':slug, 'site_a_public_key':base64.b64encode(public).decode(),
            'private_key_exported':False,'config_applied':False,
            'router_b_push':False,'tunnel_active':False,'network_actions':0,
            'backup_verified':False,'production_vault_verified':False}
    except BaseException:
        # Incomplete keypair must never become an apparently valid site.
        for name in ('public.key','private.key'):
            (key_dir/name).unlink(missing_ok=True)
        key_dir.rmdir()
        raise

def public_from_folder(folder,slug):
    if not SLUG.fullmatch(slug) or slug.endswith('-'):
        raise ValueError('invalid site slug')
    parent=_strict_private_folder(folder)
    site=parent/('site-a-'+slug)
    st=site.lstat()
    if not stat.S_ISDIR(st.st_mode) or stat.S_IMODE(st.st_mode)!=0o700 or st.st_uid!=os.getuid():
        raise ValueError('site key folder is not private')
    def read_file(filename):
        path=site/filename
        before=path.lstat()
        if not stat.S_ISREG(before.st_mode) or stat.S_IMODE(before.st_mode)!=0o600 or before.st_uid!=os.getuid() or before.st_nlink!=1 or before.st_size>128:
            raise ValueError('private key custody file invalid')
        fd=os.open(path,os.O_RDONLY|getattr(os,'O_NOFOLLOW',0))
        with os.fdopen(fd,'rb') as stream:
            after=os.fstat(stream.fileno())
            if (before.st_dev,before.st_ino)!=(after.st_dev,after.st_ino):
                raise ValueError('key changed during open')
            return stream.read(129).strip()
    private=base64.b64decode(read_file('private.key'),validate=True)
    public=base64.b64decode(read_file('public.key'),validate=True)
    if len(private)!=32 or len(public)!=32:
        raise ValueError('unexpected WireGuard key material')
    actual=x25519.X25519PrivateKey.from_private_bytes(private).public_key().public_bytes(
        serialization.Encoding.Raw,serialization.PublicFormat.Raw)
    if public!=actual:
        raise ValueError('Site A private/public keys do not match')
    return {'status':'SITE_A_PUBLIC_KEY_READ_LOCAL_ONLY',
        'site_a_public_key':base64.b64encode(public).decode(),
        'config_applied':False,'network_actions':0,'backup_verified':False}

def main():
    parser=argparse.ArgumentParser(description=__doc__)
    group=parser.add_mutually_exclusive_group(required=True)
    group.add_argument('--create',action='store_true')
    group.add_argument('--show-public',action='store_true')
    parser.add_argument('--owner-only-folder',type=Path,required=True)
    parser.add_argument('--site-slug',required=True)
    args=parser.parse_args()
    if os.geteuid()==0:
        parser.error('nonroot Site A operator only')
    if args.create and os.environ.get('IPAT_R916_APPROVE_SITE_A_DEV_KEY_GENERATION')!='YES':
        parser.error('explicit DEV-only key-generation opt-in required')
    try:
        out=(create(args.owner_only_folder,args.site_slug) if args.create else
             public_from_folder(args.owner_only_folder,args.site_slug))
        print(json.dumps(out,sort_keys=True))
    except (ValueError,OSError,OverflowError,base64.binascii.Error):
        print('SITE_A_KEY_STORE_DENIED_OR_INCOMPLETE',file=sys.stderr)
        return 4
    return 0

if __name__=='__main__':sys.exit(main())
