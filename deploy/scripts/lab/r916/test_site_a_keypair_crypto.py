"""Actual X25519 development-only key custody integration. Requires cryptography.
Run as unprivileged user on disposable/private filesystem, not production vault.
"""
import base64
import importlib.util
import os
from pathlib import Path
import tempfile
import unittest
from cryptography.hazmat.primitives.asymmetric import x25519
from cryptography.hazmat.primitives import serialization

P=Path(__file__).with_name('site_a_keypair.py')
spec=importlib.util.spec_from_file_location('sitea',P)
M=importlib.util.module_from_spec(spec);spec.loader.exec_module(M)

class TestActualX25519(unittest.TestCase):
    def setUp(self):
        if os.geteuid()==0:self.skipTest('never run as root')
        tmp=tempfile.TemporaryDirectory(prefix='ipat-r916-')
        self.addCleanup(tmp.cleanup)
        self.folder=Path(tmp.name);self.folder.chmod(0o700)

    def test_known_rfc7748_vector(self):
        private=bytes.fromhex('77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a')
        expected=bytes.fromhex('8520f0098930a754748b7ddcb43ef75a0dbf3a0d26381af4eba4a98eaa9b4e6a')
        observed=x25519.X25519PrivateKey.from_private_bytes(private).public_key().public_bytes(
            serialization.Encoding.Raw,serialization.PublicFormat.Raw)
        self.assertEqual(observed,expected)

    def test_real_key_generation_0600_no_clobber_and_public_only(self):
        result=M.create(self.folder,'labsitea')
        self.assertFalse(result['config_applied'])
        self.assertFalse(result['tunnel_active'])
        self.assertFalse(result['router_b_push'])
        self.assertFalse(result['backup_verified'])
        site=self.folder/'site-a-labsitea'
        self.assertEqual(site.stat().st_mode&0o777,0o700)
        key=site/'private.key'
        self.assertEqual(key.stat().st_mode&0o777,0o600)
        self.assertEqual((site/'public.key').stat().st_mode&0o777,0o600)
        secret=base64.b64decode(key.read_text().strip(),validate=True)
        self.assertEqual(len(secret),32)
        self.assertEqual(result['site_a_public_key'],M.public_from_folder(self.folder,'labsitea')['site_a_public_key'])
        self.assertNotIn(base64.b64encode(secret).decode(),str(result))
        with self.assertRaises(ValueError):M.create(self.folder,'labsitea')
        self.assertEqual(len(list(site.iterdir())),2)
        key.chmod(0o644)
        with self.assertRaises(ValueError):M.public_from_folder(self.folder,'labsitea')

    def test_rejects_symlinked_folder_without_creating_key(self):
        link=self.folder.parent/(self.folder.name+'-alias')
        link.symlink_to(self.folder,target_is_directory=True)
        self.addCleanup(link.unlink)
        with self.assertRaises(ValueError):M.create(link,'labsiteb')
        self.assertFalse((self.folder/'site-a-labsiteb').exists())

if __name__=='__main__':unittest.main()
