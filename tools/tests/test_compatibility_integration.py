"""Core IPC and release gates use the same engine and never trust client PASS claims."""
import hashlib
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import time
import unittest

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / 'bridge/DeviceRuntime'))


class CoreCompatibilityTests(unittest.TestCase):
    def test_read_details_and_activation_gate(self):
        from zero_sky_core import CoreRuntime
        with tempfile.TemporaryDirectory() as directory:
            runtime = CoreRuntime(Path(directory), telemetry_owner=False)
            def call(operation, parameters=None):
                return runtime.handle_ipc({'protocolVersion': 1, 'requestId': 'test-compatibility',
                    'timestamp': time.time(), 'operation': operation, 'parameters': parameters or {}})
            summary = call('getCompatibility')
            self.assertTrue(summary['success'])
            self.assertEqual(summary['result']['components'], [])
            detail = call('getCompatibilityDetail', {'registryKey': '../invalid-key'})
            self.assertEqual(detail['errorCode'], 'INVALID_PARAMETERS')
            activation = call('unfreezeApp', {'bundleID': 'org.example.fixture'})
            self.assertEqual(activation['errorCode'], 'COMPATIBILITY_BLOCKED')
            launch = call('getCompatibilityAdmission', {'component': 'org.example.fixture', 'action': 'launch', 'status': 'PASS'})
            self.assertTrue(launch['success'])
            self.assertFalse(launch['result']['allowed'])

    def test_source_route_coverage(self):
        from tools.audit_compatibility_routes import audit
        self.assertEqual(audit(ROOT)['unresolved'], [])


class ReleaseCompatibilityTests(unittest.TestCase):
    def test_engine_bytes_manifest_idempotency_and_legacy_guards(self):
        from tools import prepare_release_kit as release
        retired = ('automation/CrypStoreAutomation/crypstore_keeper.py',
                   'automation/CrypStoreAutomation/sileo-package-bridge-v8.py',
                   'automation/CrypStoreAutomation/sileo-research-bridge.py')
        with tempfile.TemporaryDirectory() as directory:
            kit = Path(directory)
            rows = []
            for relative in sorted(set(release.OVERRIDES) | set(retired)):
                path = kit / relative
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_text("raise RuntimeError('legacy route executed')\n")
                rows.append(hashlib.sha256(path.read_bytes()).hexdigest() + '  ./' + relative)
            (kit / 'SHA256SUMS').write_text('\n'.join(rows) + '\n')
            release.apply_portability_overrides(kit)
            first = (kit / 'SHA256SUMS').read_bytes()
            release.apply_portability_overrides(kit)
            self.assertEqual((kit / 'SHA256SUMS').read_bytes(), first)
            for row in first.decode().splitlines():
                expected, relative = row.split(None, 1)
                self.assertEqual(hashlib.sha256((kit / relative).read_bytes()).hexdigest(), expected)
            self.assertEqual((kit / 'host-mac/bootstrap_device.py').read_bytes(),
                             (ROOT / 'bridge/HostTools/bootstrap_device.py').read_bytes())
            for relative in ('srdssh/bootstrap.py',
                             'srdssh/install_cryptex_native.py',
                             'filza/install_cryptex_native.py',
                             'filza/generate_trust_cache.py'):
                self.assertEqual(
                    (kit / relative).read_bytes(),
                    release.OVERRIDES[relative].read_bytes(),
                )
            for relative in retired:
                result = subprocess.run([sys.executable, str(kit / relative)], stdout=subprocess.PIPE,
                                        stderr=subprocess.PIPE, timeout=10, check=False)
                self.assertEqual(result.returncode, 193, result.stderr.decode())
                self.assertIn('Compatibility UNKNOWN', result.stderr.decode())
            for source in (ROOT / 'bridge/DeviceRuntime/zero_sky_compat').glob('*.py'):
                for destination in ('automation/CrypStoreAutomation/zero_sky_compat',
                                    'automation/tools/srd-runtime-manager/zero_sky_compat'):
                    self.assertEqual((kit / destination / source.name).read_bytes(), source.read_bytes())


if __name__ == '__main__':
    unittest.main()
