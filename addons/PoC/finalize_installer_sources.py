"""Align source audits and documentation with the restored SRD installers."""
from pathlib import Path
from repair_device_connection import HERE,atomic_write

def main():
 root=HERE.parents[1]
 path=root/'tools/tests/test_compatibility_integration.py'
 text=path.read_text().replace("'filza/install_cryptex_native.py', 'runtime-generation/install_cryptex_native.py',", "'filza/install_cryptex_native.py',")
 for row in ("                   'automation/CrypStoreAutomation/native-install/install_cryptex_native.py',\n",
             "                   'automation/tools/srd-runtime-manager/sync_runtime_cryptex.py',\n",
             "                   'automation/tools/srd-runtime-manager/srd_runtime_manager.py',\n"):
  text=text.replace(row,'')
 atomic_write(path,text.encode(),0o644)
 path=root/'tools/audit_compatibility_routes.py';text=path.read_text()
 text=text.replace("    'bridge/KitScripts/automation/CrypStoreAutomation/crypstore_worker.py': ('process', 'compatibility_intake'),\n",'')
 text=text.replace("    'bridge/DeviceRuntime/trollstorelite-srd-bridge.py': ('install_deb', 'require_install_adapter'),\n",'')
 text=text.replace("SHELL_ROUTES = ('addons/install_0sky.sh',\n                'bridge/KitScripts/automation/CrypStoreAutomation/native-install/build_and_install.sh',\n                'bridge/KitScripts/runtime-generation/build_and_install.sh')", "SHELL_ROUTES = ('addons/install_0sky.sh',)")
 anchor='    native = root / \'addons/PoC/cryptex_native.py\'\n'
 rows="""    # These user-restored SRD routes retain format/architecture/identity checks.
    # They do not issue compatibility PASS or use transactional admission.
    restored = {
        'bridge/DeviceRuntime/trollstorelite-srd-bridge.py': ('def install_deb(path):', 'Architecture mismatch:', 'def queue_install(args):'),
        'bridge/KitScripts/automation/CrypStoreAutomation/crypstore_worker.py': ('preflight_workspace(ipa)', 'normalize_ipa_archive(ipa)', 'verify_foreground_launch('),
        'bridge/KitScripts/automation/CrypStoreAutomation/native-install/install_cryptex_native.py': ('Exact-device identity mismatch', 'Apple did not authorize', 'assets_from_manifest'),
        'bridge/KitScripts/runtime-generation/install_cryptex_native.py': ('Exact-device identity mismatch', 'Apple did not authorize', 'assets_from_manifest'),
    }
    for relative, required in restored.items():
        content = (root / relative).read_text()
        findings.append({'path': relative, 'state': 'RESTORED_SRD_INSTALLER' if all(value in content for value in required) else 'UNRESOLVED',
                         'transactional_admission': False})
"""
 if rows not in text:text=text.replace(anchor,rows+anchor)
 text=text.replace("'historical_artifacts': 'Existing deployed workers, IPAs and external vendor input kits require rebuilding/redeployment; not covered by source gates.'", "'historical_artifacts': 'Existing artifacts require rebuilding/redeployment. RESTORED_SRD_INSTALLER routes intentionally run outside transactional admission; this audit does not certify compatibility.'")
 atomic_write(path,text.encode(),0o644)
 path=root/'docs/COMPATIBILITY.md';text=path.read_text()
 section='''## Restored SRD installation paths

The researcher selected restoration of the earlier DEB and IPA installers.
The authenticated device bridge again uses Procursus apt/dpkg for DEBs and
the paired Mac worker for IPAs. These routes run outside the compatibility
engine's transactional admission. Successful installation does not create a
compatibility PASS record or establish that arbitrary packages work.

DEBs retain archive, metadata, architecture and dependency checks. IPAs retain
bounded archive validation, signing, exact-device identity, live Apple research
authorization, registration and a foreground launch check. Native installers
use SDK-prepared raw APFS Cryptex assets with verified manifest digests.
Release preparation overlays these restored builders and workers; other
retired entry points keep their admission stops.

Live verification on the repaired SRD installed a data-only DEB and a small
UIKit IPA. The IPA registered in its application container and stayed running
for eight seconds. Reboot persistence and arbitrary tweak/app functionality
were not tested by these fixtures.

'''
 if section not in text:text=text.replace('## Current support and limitations\n',section+'## Current support and limitations\n')
 text=text.replace('Their installation paths remain blocked until a reviewed\nadapter can snapshot, validate and reverse them.', 'The explicitly restored SRD install paths are documented above; other\nretired paths remain blocked until a reviewed adapter can snapshot, validate\nand reverse them.')
 atomic_write(path,text.encode(),0o644)
 print('Source audit, release expectations and compatibility documentation updated.')

if __name__=='__main__':main()
