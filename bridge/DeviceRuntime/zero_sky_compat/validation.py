"""Evidence obligations are derived from component type, not installation exit status."""
from pathlib import Path
from .discovery import file_hash
from .failures import fingerprint


def obligations(report):
    required = {'install', 'dependencies', 'functional_test'}
    kinds = {item['kind'] for item in report.components}
    if kinds & {'application', 'plugin', 'xpc_service'}:
        required.update(('registration', 'launch', 'communication'))
    if 'service' in kinds:
        required.update(('launch', 'persistence', 'service_registration', 'communication', 'ownership'))
    if 'xpc_service' in kinds or any(item.get('mach_services') for item in report.dependencies):
        required.update(('xpc_registration', 'xpc_communication'))
    if kinds & {'macho', 'library', 'framework'}:
        required.update(('dependency_loading', 'signature', 'entitlements', 'sandbox'))
    if kinds & {'bundle', 'framework', 'plugin'}:
        required.add('bundle_loading')
    if any('MobileSubstrate' in item['path'] or '/Tweak' in item['path'] for item in report.components):
        required.add('tweak_function')
    if report.root_requirement != 'NO_ROOT_REQUIRED':
        required.add('privilege_contract')
    return sorted(required)


def outcome(report, evidence, acknowledge_degraded=False):
    report.runtime_validation = evidence
    required = obligations(report)
    missing = [name for name in required if name not in evidence or evidence[name].get('passed') is not True]
    if missing:
        for name in missing:
            value = evidence.get(name, {})
            if value.get('passed') is False:
                failure = fingerprint(value.get('detail', '') + '\n' + value.get('stderr', ''), name)
                for code in failure['codes']:
                    if code != 'UNCLASSIFIED_FAILURE':
                        report.add(code, name, value.get('detail', 'functional failure'))
            report.add('RUNTIME_VALIDATION_FAILED' if value.get('passed') is False else 'RUNTIME_VALIDATION_UNKNOWN',
                       name, value.get('detail', 'functional evidence unavailable'),
                       'mandatory' if value.get('passed') is False else 'unknown')
        return 'BLOCKED' if any(evidence.get(name, {}).get('passed') is False for name in missing) else 'UNKNOWN'
    optional = [item for item in report.issues if item['severity'] == 'optional']
    if optional:
        return 'DEGRADED'
    return 'ADAPTED' if report.adaptations else 'PASS'


class DataTreeBackend:
    """Transactional data/configuration adapter. Never launches code or services.

    Used for reviewed data-only components and deterministic transaction tests.
    Executables, bundles, package metadata and maintainer scripts are rejected.
    The destination is an explicitly configured application-owned directory.
    """
    name = 'data-tree-v1'

    def __init__(self, destination):
        self.destination = Path(destination)

    def eligible(self, report):
        return not report.components and report.root_requirement in ('NO_ROOT_REQUIRED', 'ROOTLESS_COMPATIBLE')

    def snapshot(self, work):
        import shutil
        if self.destination.is_symlink():
            raise ValueError('destination cannot be a symlink')
        backup = work / 'installed-before'
        existed = self.destination.exists()
        if existed:
            shutil.copytree(self.destination, backup, symlinks=True)
        return {'existed': existed, 'backup': backup.name, 'destination': str(self.destination.resolve())}

    def install(self, staged):
        import shutil
        import os
        if self.destination.exists():
            shutil.rmtree(self.destination)
        self.destination.parent.mkdir(parents=True, exist_ok=True)
        shutil.copytree(staged, self.destination, symlinks=True)
        for path in self.destination.rglob('*'):
            if path.is_file() and not path.is_symlink():
                with path.open('rb') as stream:
                    os.fsync(stream.fileno())

    def validate(self, staged, report):
        from .discovery import tree_hash
        equal = tree_hash(staged) == tree_hash(self.destination)
        return {key: {'passed': equal, 'detail': 'installed data tree equals staged tree in configured data directory'}
                for key in ('install', 'dependencies', 'functional_test', 'privilege_contract')}

    def rollback(self, snapshot, work):
        import shutil
        if snapshot['destination'] != str(self.destination.resolve()):
            raise ValueError('rollback backend destination mismatch')
        if self.destination.exists():
            shutil.rmtree(self.destination)
        if snapshot['existed']:
            shutil.copytree(work / snapshot['backup'], self.destination, symlinks=True)

    def verify_rollback(self, snapshot, work):
        from .discovery import tree_hash
        return tree_hash(self.destination) == tree_hash(work / snapshot['backup']) if snapshot['existed'] else not self.destination.exists()
