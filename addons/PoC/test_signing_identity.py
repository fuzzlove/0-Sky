"""Verify helper identity and entitlements survive actual codesign calls."""
import pathlib,plistlib,runpy,subprocess,tempfile,unittest
from repair_device_connection import HERE

class SigningIdentityTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.worker=runpy.run_path(str(HERE.parents[1]/'bridge/KitScripts/automation/CrypStoreAutomation/crypstore_worker.py'))

    def test_resigning_preserves_helper_identifier_and_entitlements(self):
        with tempfile.TemporaryDirectory() as folder:
            root=pathlib.Path(folder);source=root/'helper.c';binary=root/'helper';entitlements=root/'entitlements.plist'
            source.write_text('int main(void) { return 0; }\n')
            subprocess.run(['xcrun','clang',str(source),'-o',str(binary)],capture_output=True,check=True,timeout=30)
            values={'get-task-allow':True}
            entitlements.write_bytes(plistlib.dumps(values))
            subprocess.run(['/usr/bin/codesign','--force','--sign','-','--identifier','com.example.original-helper',
                            '--entitlements',str(entitlements),str(binary)],capture_output=True,check=True,timeout=30)
            self.worker['codesign'](binary,entitlements)
            display=subprocess.run(['/usr/bin/codesign','-dvvv',str(binary)],capture_output=True,text=True,check=True,timeout=30)
            self.assertIn('Identifier=com.example.original-helper',display.stderr)
            subprocess.run(['/usr/bin/codesign','--verify','--strict',str(binary)],capture_output=True,check=True,timeout=30)
            actual=subprocess.check_output([str(self.worker['LDID']),'-e',str(binary)],timeout=30)
            self.assertEqual(plistlib.loads(actual),values)

if __name__=='__main__':unittest.main()
