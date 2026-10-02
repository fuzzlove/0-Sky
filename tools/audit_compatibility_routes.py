#!/usr/bin/env python3
"""Audit declared 0-Sky entry boundaries and canonical engine packaging.

This is a source coverage check, not a claim that arbitrary administrator shell
commands or historical binaries can be prevented from bypassing application code.
"""
import argparse
import ast
import json
from pathlib import Path

PYTHON_ROUTES = {
    'addons/PoC/install_0sky_apps.py': ('main', 'compatibility_stop'),
    'addons/PoC/install_built_cryptex.py': ('main', 'compatibility_stop'),
    'addons/PoC/register_mounted_app.py': ('main', 'compatibility_stop'),
    'addons/PoC/restore_srd_bootstrap.py': ('main', 'compatibility_stop'),
}
SHELL_ROUTES = ('addons/install_0sky.sh',)


def audit(root):
    findings = []
    for relative, (boundary, gate) in PYTHON_ROUTES.items():
        path = root / relative
        tree = ast.parse(path.read_text())
        function = next((n for n in tree.body if isinstance(n, ast.FunctionDef) and n.name == boundary), None)
        calls = [n for n in ast.walk(function) if isinstance(n, ast.Call) and isinstance(n.func, ast.Name) and n.func.id == gate] if function else []
        findings.append({'path': relative, 'boundary': boundary, 'gate': gate,
                         'state': 'GATED' if calls else 'UNRESOLVED'})
    for relative in SHELL_ROUTES:
        lines = (root / relative).read_text().splitlines()
        before = '\n'.join(lines[:7])
        findings.append({'path': relative, 'state': 'RETIRED' if 'exit 193' in before else 'UNRESOLVED'})
    # These user-restored SRD routes retain format/architecture/identity checks.
    # They do not issue compatibility PASS or use transactional admission.
    restored = {
        # ``queue_install`` now accepts an optional, worker-verified launch
        # contract.  Keep this source audit aligned with that stronger route
        # instead of requiring the obsolete one-argument spelling.
        'bridge/DeviceRuntime/trollstorelite-srd-bridge.py': (
            'def install_deb(path):', 'Architecture mismatch:',
            'def queue_install(args, launch_validation=None):'),
        'bridge/KitScripts/automation/CrypStoreAutomation/crypstore_worker.py': ('preflight_workspace(ipa)', 'normalize_ipa_archive(ipa)', 'verify_foreground_launch('),
        'bridge/KitScripts/automation/CrypStoreAutomation/native-install/install_cryptex_native.py': ('Exact-device identity mismatch', 'Apple did not authorize', 'assets_from_manifest'),
        'bridge/KitScripts/runtime-generation/install_cryptex_native.py': ('Exact-device identity mismatch', 'Apple did not authorize', 'assets_from_manifest'),
    }
    for relative, required in restored.items():
        content = (root / relative).read_text()
        findings.append({'path': relative, 'state': 'RESTORED_SRD_INSTALLER' if all(value in content for value in required) else 'UNRESOLVED',
                         'transactional_admission': False})
    native = root / 'addons/PoC/cryptex_native.py'
    findings.append({'path': str(native.relative_to(root)),
                     'state': 'GATED' if 'compatibility_stop("native-cryptex-install")' in native.read_text() else 'UNRESOLVED'})
    release = (root / 'tools/prepare_release_kit.py').read_text()
    findings.append({'path': 'tools/prepare_release_kit.py', 'state': 'GATED' if (
        'zero_sky_compat' in release and 'compatibility_guard.py' in release and 'legacy route missing' in release) else 'UNRESOLVED'})
    return {'schema_version': 1, 'authoritative_engine': 'bridge/DeviceRuntime/zero_sky_compat',
            'scope': 'source install boundaries and newly prepared release kits', 'routes': findings,
            'historical_artifacts': 'Existing artifacts require rebuilding/redeployment. RESTORED_SRD_INSTALLER routes intentionally run outside transactional admission; this audit does not certify compatibility.',
            'unresolved': [item for item in findings if item['state'] == 'UNRESOLVED']}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--root', type=Path, default=Path(__file__).resolve().parents[1])
    args = parser.parse_args()
    value = audit(args.root)
    print(json.dumps(value, sort_keys=True, indent=2))
    return 1 if value['unresolved'] else 0


if __name__ == '__main__':
    raise SystemExit(main())
