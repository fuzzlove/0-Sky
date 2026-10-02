"""Exercise native asset integrity and repeatable worker deployment."""
import hashlib,plistlib,tempfile,unittest
from pathlib import Path
from unittest.mock import patch
import native_srd_installer as native
import sync_srd_installers as deployment

class NativeAssetsTests(unittest.TestCase):
    def fixture(self,root):
        assets={}
        for key in ('CryptexInfoPlist','GenericDmg','GenericTrustCache','GenericVolume'):
            raw=key.encode();(root/key).write_bytes(raw)
            assets['Cryptex1,'+key]={'Info':{'Path':key},'Digest':hashlib.sha384(raw).digest()}
        value={'BuildIdentities':[{'Info':{'Variant':'research'},'Manifest':assets}]}
        manifest=root/'BuildManifest.plist';manifest.write_bytes(plistlib.dumps(value))
        return manifest,value

    def test_verified_assets_reject_changed_image(self):
        with tempfile.TemporaryDirectory() as directory:
            root=Path(directory);manifest,_=self.fixture(root)
            self.assertEqual(len(native.assets_from_manifest(manifest)[1]),4)
            (root/'GenericDmg').write_bytes(b'changed image')
            with self.assertRaisesRegex(ValueError,'digest mismatch'):native.assets_from_manifest(manifest)

    def test_assets_cannot_escape_restore_tree(self):
        with tempfile.TemporaryDirectory() as directory:
            root=Path(directory)/'Restore';root.mkdir();manifest,value=self.fixture(root)
            outside=root.parent/'outside';outside.write_bytes(b'outside')
            item=value['BuildIdentities'][0]['Manifest']['Cryptex1,GenericDmg']
            item['Info']['Path']='../outside';item['Digest']=hashlib.sha384(b'outside').digest()
            manifest.write_bytes(plistlib.dumps(value))
            with self.assertRaisesRegex(ValueError,'Unsafe'):native.assets_from_manifest(manifest)

    def test_rejects_ambiguous_research_identity(self):
        with tempfile.TemporaryDirectory() as directory:
            manifest,value=self.fixture(Path(directory));value['BuildIdentities']*=2
            manifest.write_bytes(plistlib.dumps(value))
            with self.assertRaisesRegex(ValueError,'one research'):native.assets_from_manifest(manifest)

    def test_trust_cache_envelope_preserves_binary_payload(self):
        raw=bytes(range(256))*3
        envelope=native.der(0x30,native.der(0x16,b'IM4P')+native.der(0x16,b'gtcd')+native.der(4,raw))
        self.assertEqual(native.trust_payload(envelope),raw)

class DeploymentTests(unittest.TestCase):
    def setup_tree(self,root):
        source=root/'bridge/KitScripts/automation/CrypStoreAutomation/native-install';source.mkdir(parents=True)
        (source/'build_and_install.sh').write_bytes(b'#!/bin/zsh\nexit 0\n')
        (source/'install_cryptex_native.py').write_bytes(b'pass\n')
        worker=root/'instance/crypstore_worker.py';worker.parent.mkdir();worker.touch()
        return {'ProgramArguments':['python',str(worker)]},source,worker.parent/'native-install'

    def test_deployment_preserves_backups_and_is_idempotent(self):
        with tempfile.TemporaryDirectory() as directory:
            root=Path(directory);value,source,target=self.setup_tree(root)
            target.mkdir();(target/'install_cryptex_native.py').write_bytes(b'old\n')
            with patch.object(deployment,'HERE',root/'addons/PoC'):
                result=deployment.sync_host_installers(value,root/'reports')
                self.assertTrue(result['changed'])
                self.assertEqual(next(Path(result['backup']).glob('*install_cryptex_native.py')).read_bytes(),b'old\n')
                self.assertEqual(deployment.sync_host_installers(value,root/'reports'),{'changed':False})

    def test_failed_write_restores_existing_builder(self):
        with tempfile.TemporaryDirectory() as directory:
            root=Path(directory);value,source,target=self.setup_tree(root);target.mkdir()
            (target/'build_and_install.sh').write_bytes(b'original\n')
            write=deployment.atomic_write
            def fail(path,raw,*args):
                if path==target/'install_cryptex_native.py':raise OSError('write failure')
                return write(path,raw,*args)
            with patch.object(deployment,'HERE',root/'addons/PoC'),patch.object(deployment,'atomic_write',side_effect=fail):
                with self.assertRaisesRegex(OSError,'write failure'):deployment.sync_host_installers(value,root/'reports')
            self.assertEqual((target/'build_and_install.sh').read_bytes(),b'original\n')
            self.assertFalse((target/'install_cryptex_native.py').exists())

if __name__=='__main__':unittest.main()
