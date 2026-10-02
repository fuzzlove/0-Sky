"""Exercise import validation, deployment idempotence, and failure preservation."""
import base64,hashlib,json,pathlib,subprocess,sys,tempfile,unittest
from sync_runtime_dependencies import PROGRAM,manifest

class RuntimeDependencies(unittest.TestCase):
    def deploy(self,root,request):
        source=PROGRAM.replace('/var/jb/usr/local/libexec',str(root/'libexec')).replace('/var/jb/var/lib/0-sky/dependency-backups',str(root/'backups')).replace('/var/jb/usr/bin/python3',sys.executable)
        source=source.replace('from zero_sky_compat.environment import detect;detect()', 'from zero_sky_compat.environment import detect')
        return subprocess.run([sys.executable,'-c',source],input=json.dumps(request).encode(),capture_output=True)
    def test_actual_package_imports_and_second_deployment_changes_nothing(self):
        with tempfile.TemporaryDirectory() as folder:
            root=pathlib.Path(folder);(root/'libexec').mkdir()
            first=self.deploy(root,manifest());self.assertEqual(first.returncode,0,first.stderr.decode())
            self.assertTrue(json.loads(first.stdout)['changed'])
            before={p.name:p.read_bytes() for p in (root/'libexec/zero_sky_compat').glob('*.py')}
            second=self.deploy(root,manifest());self.assertEqual(second.returncode,0,second.stderr.decode())
            self.assertFalse(json.loads(second.stdout)['changed'])
            self.assertEqual(before,{p.name:p.read_bytes() for p in (root/'libexec/zero_sky_compat').glob('*.py')})
    def test_import_failure_preserves_installed_package(self):
        with tempfile.TemporaryDirectory() as folder:
            root=pathlib.Path(folder);(root/'libexec').mkdir()
            self.assertEqual(self.deploy(root,manifest()).returncode,0)
            target=root/'libexec/zero_sky_compat/integration.py';original=target.read_bytes()
            request=manifest();broken=b'raise RuntimeError("incompatible dependency")\n'
            request['files']['integration.py']={'data':base64.b64encode(broken).decode(),'sha256':hashlib.sha256(broken).hexdigest()}
            result=self.deploy(root,request)
            self.assertNotEqual(result.returncode,0)
            self.assertEqual(target.read_bytes(),original)
            self.assertFalse(list((root/'libexec').glob('.dependencies-*')))
    def test_archive_escape_is_rejected(self):
        with tempfile.TemporaryDirectory() as folder:
            root=pathlib.Path(folder);(root/'libexec').mkdir()
            request=manifest();request['files']['../escaped.py']=request['files']['__init__.py']
            self.assertNotEqual(self.deploy(root,request).returncode,0)
            self.assertFalse((root/'libexec/escaped.py').exists())

if __name__=='__main__':unittest.main()
