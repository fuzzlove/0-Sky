"""Behavior tests for canonical compatibility decisions and transactional rollback."""
from dataclasses import asdict
import io
import json
from pathlib import Path
import plistlib
import shutil
import struct
import sys
import tarfile
import tempfile
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / 'bridge/DeviceRuntime'))
from zero_sky_compat import CompatibilityEngine, Engine, Environment, Report, STATES
from zero_sky_compat.classification import static_state
from zero_sky_compat.orchestrator import RepairEngine
from zero_sky_compat.analysis import inspect, service
from zero_sky_compat.discovery import tree_hash
from zero_sky_compat.environment import _architecture_from_mach
from zero_sky_compat.failures import fingerprint
from zero_sky_compat.intake import extract_tar
from zero_sky_compat.integration import (CompatibilityBlocked,
    analyze_registry_entry, record_runtime_validation, require_install_adapter)
from zero_sky_compat.transaction import atomic_json, mutation_lock, recover
from zero_sky_compat.validation import DataTreeBackend, outcome
from tools.compatibility_acceptance import run_acceptance


def binary(path, cpu=0x100000c, loads=(), rpaths=()):
    commands = []
    for name in loads:
        data = name.encode() + b'\0'
        commands.append(struct.pack('<6I', 0xc, 24 + len(data), 24, 0, 0, 0) + data)
    for name in rpaths:
        data = name.encode() + b'\0'
        commands.append(struct.pack('<3I', 0x8000001c, 12 + len(data), 12) + data)
    commands.append(struct.pack('<6I', 0x32, 24, 2, 0x1b0000, 0x1b0000, 0))
    header = struct.pack('<8I', 0xfeedfacf, cpu, 0, 2, len(commands), sum(map(len, commands)), 0, 0)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(header + b''.join(commands))
    path.chmod(0o755)


class CompatibilityTests(unittest.TestCase):
    def test_mutation_lock_rejects_symlink_without_changing_target(self):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            target = root / 'original.txt'
            target.write_text('untouched')
            (root / 'mutation.lock').symlink_to(target)
            with self.assertRaises(OSError):
                with mutation_lock(root):
                    self.fail('symbolic lock was acquired')
            self.assertEqual(target.read_text(), 'untouched')

    def test_mutation_lock_rejects_symbolic_state_directory(self):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            target = root / 'real-state'
            target.mkdir()
            linked = root / 'linked-state'
            linked.symlink_to(target, target_is_directory=True)
            with self.assertRaisesRegex(ValueError, 'symbolic'):
                with mutation_lock(linked):
                    self.fail('symbolic state was locked')
            self.assertFalse((target / 'mutation.lock').exists())

    def test_atomic_journal_rejects_symlink_without_changing_target(self):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            target = root / 'original.json'
            target.write_text('{"phase":"ORIGINAL"}')
            journal = root / 'transaction.json'
            journal.symlink_to(target)
            with self.assertRaisesRegex(ValueError, 'symbolic'):
                atomic_json(journal, {'phase': 'COMMITTED'})
            self.assertEqual(target.read_text(), '{"phase":"ORIGINAL"}')

    def test_ios_cpu_subtype_detection_uses_mach_values(self):
        self.assertEqual(_architecture_from_mach(0x0100000C, 2), 'arm64e')
        self.assertEqual(_architecture_from_mach(0x0100000C, 0x02000002), 'arm64e')
        self.assertEqual(_architecture_from_mach(0x0100000C, 1), 'arm64')
        self.assertEqual(_architecture_from_mach(None, None), 'unknown')
        self.assertEqual(_architecture_from_mach(0x0100000C, 99), 'unknown')

    def test_legacy_debian_architecture_defers_to_macho_slices(self):
        package = self.base / 'legacy-arch-package'
        control = package / 'DEBIAN'
        control.mkdir(parents=True)
        (control / 'control').write_text(
            'Package: org.example.legacy\nVersion: 1.0\n'
            'Architecture: iphoneos-arm\n')
        binary(package / 'var/jb/usr/bin/fixture')
        report = Engine(self.base / 'legacy-state', self.env).evaluate(package)[0]
        self.assertNotIn('ARCHITECTURE_MISMATCH', self.codes(report))

    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.base = Path(self.temp.name)
        self.env = Environment('27.0', 'TESTBUILD', 'test-device', 'arm64', 'rootless', '/var/jb', 0, 0,
                               {'var_jb': True, 'root': True, 'launchctl': False, 'system_launchctl': True})
        self.engine = Engine(self.base / 'state', self.env)
        self.source = self.base / 'component'
        self.source.mkdir()
        (self.source / 'settings.json').write_text('{"enabled":true}')

    def codes(self, report):
        return {issue['code'] for issue in report.issues}

    def analyze(self, adapters=()):
        return self.engine.evaluate(self.source, adapters)[0]

    def test_native_ios27_component_requires_functional_validation(self):
        report = self.analyze()
        self.assertEqual(report.preflight, 'ELIGIBLE')
        self.assertEqual(report.status, 'UNKNOWN')
        self.assertEqual(report.compatibility_state, 'NATIVE_COMPATIBLE')
        installed = self.engine.install(self.source, DataTreeBackend(self.base / 'installed'))
        self.assertEqual(installed.status, 'PASS')
        self.assertEqual(installed.compatibility_state, 'COMPATIBLE')
        self.assertTrue(installed.runtime_validation['functional_test']['passed'])

    def test_v2_states_do_not_contain_generic_incompatible(self):
        self.assertNotIn('INCOMPATIBLE', STATES)
        self.assertIn('UNKNOWN', STATES)
        self.assertIn('COMPATIBLE_WITH_ADAPTER', STATES)

    def test_analyze_preserves_exact_runtime_evidence(self):
        report = self.analyze()
        partial = record_runtime_validation(report.key, {
            'result': 'PASS', 'functional': False,
            'detail': 'loader verified; functional UAT pending'},
            self.base / 'state')
        self.assertEqual(partial['compatibility_state'], 'PARTIALLY_COMPATIBLE')
        refreshed = analyze_registry_entry(report.key, self.base / 'state')
        self.assertEqual(refreshed['compatibility_state'], 'PARTIALLY_COMPATIBLE')
        failed = record_runtime_validation(report.key, {
            'result': 'FAIL', 'functional': False,
            'detail': 'bounded runtime install failed'}, self.base / 'state')
        self.assertEqual(failed['compatibility_state'], 'ADAPTATION_REQUIRED')
        refreshed = analyze_registry_entry(report.key, self.base / 'state')
        self.assertEqual(refreshed['compatibility_state'], 'ADAPTATION_REQUIRED')
        blocked = record_runtime_validation(report.key, {
            'result': 'FAIL', 'functional': False,
            'failure_class': 'CRYPTEX_SERVICE_UNRESPONSIVE'}, self.base / 'state')
        self.assertEqual(blocked['compatibility_state'], 'BLOCKED_BY_PLATFORM')
        refreshed = analyze_registry_entry(report.key, self.base / 'state')
        self.assertEqual(refreshed['compatibility_state'], 'BLOCKED_BY_PLATFORM')

    def test_acceptance_report_demonstrates_unknown_success_and_blocker(self):
        value = run_acceptance()
        self.assertEqual(value['result'], 'PASS')
        states = {name: row['compatibility_state']
                  for name, row in value['cases'].items()}
        self.assertEqual(states, {
            'unknown_method': 'UNKNOWN',
            'adaptation_success': 'COMPATIBLE_WITH_ADAPTER',
            'evidence_blocker': 'BLOCKED_BY_ENTITLEMENT',
        })

    def test_unknown_installation_method_remains_unknown(self):
        result = CompatibilityEngine(self.base / 'pipeline', self.env).process(self.source)
        self.assertEqual(result.report.compatibility_state, 'UNKNOWN')
        self.assertIn('INSTALL_METHOD_UNKNOWN', self.codes(result.report))
        self.assertFalse(any(item['result'] == 'INCOMPATIBLE'
                             for item in result.report.evidence))

    def test_rootless_assumption_requests_adaptation(self):
        (self.source / 'Library').mkdir()
        (self.source / 'Library/example').write_text('data')
        report = self.analyze()
        self.assertEqual(report.compatibility_state, 'ADAPTATION_REQUIRED')
        self.assertEqual(report.adaptation_plan['adaptations'][0]['adapter'], 'rootless-v1')

    def test_previously_rejected_rootful_data_is_adapted_and_verified(self):
        (self.source / 'etc').mkdir()
        (self.source / 'etc/example.conf').write_text('enabled=1')
        result = CompatibilityEngine(self.base / 'pipeline', self.env).process(
            self.source, DataTreeBackend(self.base / 'installed'))
        self.assertEqual(result.report.compatibility_state, 'COMPATIBLE_WITH_ADAPTER')
        self.assertEqual(result.report.transaction['phase'], 'COMMITTED')
        self.assertTrue((self.base / 'installed/var/jb/etc/example.conf').is_file())

    def test_adapted_package_can_reach_specific_evidence_blocker(self):
        (self.source / 'etc').mkdir()
        (self.source / 'etc/example.conf').write_text('enabled=1')
        class EntitlementFailure(DataTreeBackend):
            def validate(self, staged, report):
                return {
                    'install': {'passed': True},
                    'dependencies': {'passed': True},
                    'privilege_contract': {'passed': True},
                    'functional_test': {'passed': False,
                                        'detail': 'missing required entitlement'},
                }
        result = CompatibilityEngine(self.base / 'pipeline', self.env).process(
            self.source, EntitlementFailure(self.base / 'installed'))
        self.assertEqual(result.report.compatibility_state,
                         'BLOCKED_BY_ENTITLEMENT')
        self.assertIn('MISSING_ENTITLEMENT', self.codes(result.report))
        self.assertEqual(result.report.transaction['phase'], 'ROLLED_BACK')

    def test_concrete_architecture_evidence_blocks_specifically(self):
        binary(self.source / 'tool', cpu=0x1000007)
        report = self.analyze()
        self.assertEqual(report.compatibility_state, 'BLOCKED_BY_ARCHITECTURE')
        self.assertIn('ARCHITECTURE_MISMATCH', self.codes(report))

    def test_undiagnosed_runtime_failure_requests_repair(self):
        report = self.analyze()
        evidence = {'install': {'passed': True}, 'dependencies': {'passed': True},
                    'functional_test': {'passed': False, 'detail': 'process exited -9'},
                    'privilege_contract': {'passed': True}}
        from zero_sky_compat.classification import runtime_state
        self.assertEqual(runtime_state(report, evidence), 'ADAPTATION_REQUIRED')

    def test_repair_loop_rejects_duplicate_strategy_and_is_bounded(self):
        repair = RepairEngine(3)
        history = [{'strategy': ['rootless-v1'], 'result': 'FAILED'}]
        self.assertFalse(repair.may_retry(history, ['rootless-v1']))
        self.assertTrue(repair.may_retry(history, ['different-adapter']))
        self.assertFalse(repair.may_retry(history * 3, ['third-adapter']))

    def test_batch_analysis_reuses_common_adapter_classification(self):
        second = self.base / 'component-two'
        (second / 'Library').mkdir(parents=True)
        (second / 'Library/two').write_text('2')
        (self.source / 'Library').mkdir()
        (self.source / 'Library/one').write_text('1')
        results = CompatibilityEngine(self.base / 'batch', self.env).analyze_batch(
            [self.source, second], workers=2)
        self.assertEqual([item.report.compatibility_state for item in results],
                         ['ADAPTATION_REQUIRED', 'ADAPTATION_REQUIRED'])
        for item in results:
            self.assertEqual(item.report.adaptation_plan['adaptations'][0]['adapter'],
                             'rootless-v1')

    def test_unknown_issue_cannot_become_blocker(self):
        report = Report('fixture', '1', '0' * 64, self.env.summary(),
                        self.env.fingerprint)
        report.add('UNFAMILIAR_SRD_METHOD', '', 'not in the rule database', 'unknown')
        self.assertEqual(static_state(report), 'UNKNOWN')

    def test_legacy_rootful_package(self):
        (self.source / 'Library').mkdir()
        (self.source / 'Library/config').write_text('data')
        report = self.analyze()
        self.assertEqual(report.root_requirement, 'ROOT_REQUIRED_ADAPTABLE')
        self.assertIn('BOOTSTRAP_PATH_FAILURE', self.codes(report))

    def test_rootless_package(self):
        (self.source / 'var/jb/etc').mkdir(parents=True)
        report = self.analyze()
        self.assertEqual(report.root_requirement, 'ROOTLESS_COMPATIBLE')
        self.assertEqual(report.preflight, 'ELIGIBLE')

    def test_missing_dependency(self):
        self.control('Depends: missing-library (>= 2)\n')
        report = self.analyze()
        self.assertIn('DEPENDENCY_MISSING', self.codes(report))
        self.assertEqual(report.status, 'BLOCKED')
        self.assertEqual(report.compatibility_state, 'BLOCKED_BY_DEPENDENCY')

    def control(self, extra=''):
        (self.source / 'DEBIAN').mkdir(exist_ok=True)
        (self.source / 'DEBIAN/control').write_text(
            'Package: org.example.fixture\nVersion: 1.0\nArchitecture: iphoneos-arm64\n' + extra)

    def test_broken_daemon(self):
        path = self.source / 'var/jb/Library/LaunchDaemons/org.example.test.plist'
        path.parent.mkdir(parents=True)
        path.write_bytes(plistlib.dumps({'Label': 'org.example.test', 'ProgramArguments': ['/var/jb/usr/bin/missing']}))
        report = self.analyze()
        self.assertIn('EXECUTABLE_NOT_FOUND', self.codes(report))
        self.assertEqual(report.status, 'BLOCKED')

    def test_xpc_registration_failure_pid_does_not_pass(self):
        report = self.analyze()
        report.components.append({'kind': 'xpc_service', 'path': 'a.xpc'})
        evidence = {name: {'passed': True} for name in ('install', 'dependencies', 'functional_test', 'launch', 'registration', 'communication')}
        evidence['pid'] = {'passed': True}
        evidence['xpc_registration'] = {'passed': False}
        self.assertEqual(outcome(report, evidence), 'BLOCKED')
        self.assertIn('RUNTIME_VALIDATION_FAILED', self.codes(report))

    def test_missing_dylib(self):
        binary(self.source / 'tool', loads=['/var/jb/usr/lib/libmissing.dylib'])
        report = self.analyze()
        self.assertTrue(any(d['state'] == 'MISSING' and 'libmissing' in d['name'] for d in report.dependencies))

    def test_incorrect_rpath(self):
        binary(self.source / 'tool', loads=['@rpath/libmissing.dylib'], rpaths=['@loader_path/broken'])
        self.assertIn('RPATH_INCORRECT', self.codes(self.analyze()))

    def test_shared_cache_rpath_is_unknown_instead_of_incompatible(self):
        binary(self.source / 'tool', loads=['@rpath/libswiftCore.dylib'],
               rpaths=['/usr/lib/swift'])
        report = self.analyze()
        self.assertIn('DEPENDENCY_UNKNOWN', self.codes(report))
        self.assertNotIn('RPATH_INCORRECT', self.codes(report))
        dependency_issue = next(issue for issue in report.issues
                                if issue['code'] == 'DEPENDENCY_UNKNOWN')
        self.assertEqual(dependency_issue['severity'], 'unknown')

    def test_architecture_mismatch(self):
        binary(self.source / 'tool', cpu=0x1000007)
        self.assertIn('ARCHITECTURE_MISMATCH', self.codes(self.analyze()))

    def test_missing_entitlement(self):
        binary(self.source / 'tool')
        self.env.capabilities['granted_entitlements'] = []
        class Result:
            stdout = plistlib.dumps({'com.apple.private.example': True})
        with patch('zero_sky_compat.analysis.shutil.which', return_value='/mock/codesign'), \
             patch('zero_sky_compat.analysis.command', return_value={'returncode': 0}), \
             patch('zero_sky_compat.analysis.subprocess.run', return_value=Result()):
            report = self.analyze()
        self.assertIn('MISSING_ENTITLEMENT', self.codes(report))
        self.assertEqual(report.root_requirement, 'UNKNOWN_ROOT_REQUIREMENT')

    def test_obsolete_script_filesystem_path_not_replaced(self):
        path = self.source / 'tool'
        path.write_text('#!/bin/sh\n/usr/bin/legacy --option\n')
        path.chmod(0o755)
        original = path.read_bytes()
        self.assertIn('LEGACY_SCRIPT_PATH', self.codes(self.analyze()))
        self.assertEqual(path.read_bytes(), original)

    def test_invalid_package_metadata(self):
        self.control('Package: repeated\n')
        self.assertIn('INVALID_PACKAGE_METADATA', self.codes(self.analyze()))

    def test_successful_adaptation_and_original_preserved(self):
        (self.source / 'etc').mkdir()
        (self.source / 'etc/example.conf').write_text('setting=1')
        original = tree_hash(self.source)
        report = self.engine.install(self.source, DataTreeBackend(self.base / 'installed'), ['rootless-v1'])
        self.assertEqual(report.status, 'ADAPTED')
        self.assertEqual(tree_hash(self.source), original)
        self.assertTrue((self.base / 'installed/var/jb/etc/example.conf').is_file())

    def test_failed_install_rolls_back_previous_state(self):
        destination = self.base / 'installed'
        destination.mkdir()
        (destination / 'old').write_text('previous state')
        before = tree_hash(destination)
        class Broken(DataTreeBackend):
            def validate(self, staged, report):
                return {'functional_test': {'passed': False, 'detail': 'XPC registration failed'}}
        report = self.engine.install(self.source, Broken(destination))
        self.assertEqual(report.status, 'BLOCKED')
        self.assertEqual(report.transaction['phase'], 'ROLLED_BACK')
        self.assertEqual(tree_hash(destination), before)

    def test_failed_adaptation_is_reversible(self):
        (self.source / 'etc').mkdir()
        (self.source / 'etc/config').write_text('rootful')
        (self.source / 'var/jb/etc').mkdir(parents=True)
        (self.source / 'var/jb/etc/config').write_text('collision')
        original = tree_hash(self.source)
        report, root, work = self.engine.evaluate(self.source, ['rootless-v1'])
        self.assertEqual(report.status, 'UNKNOWN')
        self.assertEqual(report.compatibility_state, 'ADAPTATION_REQUIRED')
        self.assertEqual(tree_hash(self.source), original)
        self.assertEqual(tree_hash(root), tree_hash(work / 'before-adaptation'))

    def test_already_compatible_rerun_is_idempotent(self):
        backend = DataTreeBackend(self.base / 'installed')
        first = self.engine.install(self.source, backend)
        before = tree_hash(backend.destination)
        second = self.engine.install(self.source, backend)
        self.assertEqual(first.key, second.key)
        self.assertEqual(before, tree_hash(backend.destination))
        self.assertEqual(second.status, 'PASS')

    def test_upgraded_package_requires_revalidation(self):
        backend = DataTreeBackend(self.base / 'installed')
        first = self.engine.install(self.source, backend)
        (self.source / 'settings.json').write_text('{"enabled":false}')
        second = self.analyze()
        self.assertNotEqual(first.key, second.key)
        self.assertEqual(second.status, 'UNKNOWN')
        self.assertEqual(self.engine.registry.get(first.key)['status'], 'PASS')

    def test_failure_fingerprints_reused_across_packages(self):
        first = self.engine.registry.learn('launchctl: symbol not found _launch_active_user_switch in package-a')
        second = self.engine.registry.learn('launchctl: symbol not found _launch_active_user_switch in package-b')
        self.assertEqual(first['fingerprint'], second['fingerprint'])
        self.assertEqual(first['codes'], ['LAUNCHCTL_ABI_INCOMPATIBLE'])

    def test_archive_traversal_and_link_escape_rejected(self):
        for name, link in [('../outside', None), ('link', '../../outside')]:
            stream = io.BytesIO()
            with tarfile.open(fileobj=stream, mode='w') as archive:
                entry = tarfile.TarInfo(name)
                if link:
                    entry.type = tarfile.SYMTYPE
                    entry.linkname = link
                archive.addfile(entry)
            stream.seek(0)
            with self.assertRaises(ValueError):
                extract_tar(stream, self.base / 'extract')

    def test_known_incompatible_mechanism_is_not_retried(self):
        report = self.analyze()
        report.components.append({'kind': 'service', 'path': 'service.plist'})
        class Spy(DataTreeBackend):
            called = False
            def install(self, root):
                self.called = True
        backend = Spy(self.base / 'installed')
        from zero_sky_compat.transaction import install
        work = self.base / 'work'
        work.mkdir()
        install(self.engine, report, self.source, work, backend)
        self.assertFalse(backend.called)

    def test_gate_cannot_trust_claimed_pass(self):
        with self.assertRaises(CompatibilityBlocked):
            require_install_adapter(self.source, 'install', self.base / 'gate', self.env)
        self.assertFalse((self.base / 'installed').exists())

    def test_environment_change_invalidates_evidence(self):
        first = self.analyze()
        self.env.build_version = 'NEWBUILD'
        second = self.analyze()
        self.assertNotEqual(first.key, second.key)

    def test_interrupted_install_recovery(self):
        backend = DataTreeBackend(self.base / 'installed')
        report, root, work = self.engine.evaluate(self.source)
        snapshot = backend.snapshot(work)
        backend.install(root)
        atomic_json(self.engine.state / 'transaction.json', {'phase': 'INSTALLING', 'backend': backend.name,
            'snapshot': snapshot, 'work': str(work.relative_to(self.engine.state))})
        result = recover(self.engine, backend)
        self.assertEqual(result['phase'], 'ROLLED_BACK')
        self.assertFalse(backend.destination.exists())

    def test_procursus_symlink_descriptions_are_not_missing_files(self):
        from zero_sky_compat.inventory import audit_installed
        target = self.base / 'real'
        target.write_text('data')
        link = self.base / 'link'
        link.symlink_to('real')
        class Result:
            returncode = 0
            stderr = b''
            def __init__(self, stdout):
                self.stdout = stdout
        responses = [Result(b'org.example.fixture\t1.0\tinstall ok installed\n'),
                     Result((str(link) + ' -> real\n' + str(target) + '\n').encode())]
        with patch('zero_sky_compat.inventory.subprocess.run', side_effect=responses):
            value = audit_installed(self.env, self.base / 'inventory')
        report = next(item for item in value['components'] if item['component'] == 'org.example.fixture')
        self.assertFalse(any(i['code'] == 'EXPECTED_FILE_MISSING' for i in report['issues']))
        self.assertEqual(report['status'], 'UNKNOWN')

    def test_bundled_service_path_context_is_unknown(self):
        from zero_sky_compat.inventory import audit_paths
        path = self.base / 'Example.app/Library/LaunchDaemons/test.plist'
        path.parent.mkdir(parents=True)
        path.write_bytes(plistlib.dumps({'Label': 'org.example.test', 'ProgramArguments': ['/usr/bin/unknown-context-runner']}))
        report = audit_paths('org.example.test', '1', [path], self.env)
        self.assertEqual(report.status, 'UNKNOWN')
        self.assertIn('SERVICE_PATH_CONTEXT_UNKNOWN', self.codes(report))

    def test_importable_code_is_not_a_data_only_payload(self):
        (self.source / 'module.py').write_text('print("module")')
        report = self.engine.install(self.source, DataTreeBackend(self.base / 'installed'))
        self.assertNotEqual(report.status, 'PASS')
        self.assertFalse((self.base / 'installed').exists())

    def test_rollback_failure_blocks_subsequent_installations(self):
        class Broken(DataTreeBackend):
            def validate(self, root, report):
                raise RuntimeError('dyld: library not loaded')
            def rollback(self, snapshot, work):
                raise RuntimeError('cannot restore state')
        result = self.engine.install(self.source, Broken(self.base / 'installed'))
        self.assertEqual(result.transaction['phase'], 'ROLLBACK_FAILED')
        repeated = self.engine.install(self.source, DataTreeBackend(self.base / 'other'))
        self.assertEqual(repeated.status, 'BLOCKED')
        self.assertIn('RECOVERY_REQUIRED', self.codes(repeated))
        self.assertFalse((self.base / 'other').exists())

    def test_known_runtime_failure_is_not_retried(self):
        class Broken(DataTreeBackend):
            name = 'broken-reviewed-backend-v1'
            attempts = 0
            def install(self, root):
                self.attempts += 1
                super().install(root)
            def validate(self, root, report):
                return {'functional_test': {'passed': False, 'detail': 'XPC registration failed'}}
        backend = Broken(self.base / 'installed')
        first = self.engine.install(self.source, backend)
        self.assertIn('XPC_REGISTRATION_FAILED', self.codes(first))
        second = self.engine.install(self.source, backend)
        self.assertEqual(backend.attempts, 1)
        self.assertIn('KNOWN_FAILURE_REUSED', self.codes(second))
        self.assertFalse(backend.destination.exists())

    def test_arm64e_is_not_silently_treated_as_arm64(self):
        binary(self.source / 'tool')
        data = bytearray((self.source / 'tool').read_bytes())
        struct.pack_into('<I', data, 8, 2)
        (self.source / 'tool').write_bytes(data)
        self.assertIn('ARCHITECTURE_CAPABILITY_UNKNOWN', self.codes(self.analyze()))

    def test_environment_inventory_is_not_duplicated_in_component_reports(self):
        self.env.packages = {'org.example.fixture': {'version': '1.0', 'installed': True}}
        report = self.analyze()
        self.assertNotIn('packages', report.environment)
        self.assertEqual(report.environment_hash, self.env.fingerprint)

    def test_failed_archive_intake_has_preserved_manifest(self):
        package = self.base / 'invalid.deb'
        package.write_bytes(b'not a Debian archive')
        report, root, work = self.engine.evaluate(package, dpkg_deb='/usr/bin/false')
        self.assertEqual(report.status, 'BLOCKED')
        self.assertIn('INTAKE_FAILED', self.codes(report))
        self.assertEqual((work / 'original').read_bytes(), package.read_bytes())
        self.assertTrue((work / 'compatibility.json').is_file())


if __name__ == '__main__':
    unittest.main()
