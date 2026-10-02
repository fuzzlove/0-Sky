#!/usr/bin/env python3
"""Pause the shared injector and stage a bounded Crane quarantine repair."""
from __future__ import annotations
import argparse, asyncio, plistlib, shutil, sys
from datetime import datetime, timezone
from pathlib import Path

HERE=Path(__file__).resolve().parent
ROOT=HERE.parents[1]
INSTALLER=ROOT/'bridge/KitScripts/runtime-generation'
IDENTIFIER='com.liquidsky.crane.runtime-prepare6'
VERSION='1.0.0'

def main():
    ap=argparse.ArgumentParser();ap.add_argument('--udid',required=True);a=ap.parse_args()
    out=HERE/'crane-repair'/('runtime-prepare-'+datetime.now(timezone.utc).strftime('%Y%m%d%H%M%S'))
    root=out/'root';(root/'usr/bin').mkdir(parents=True);(root/'Library/LaunchDaemons').mkdir(parents=True)
    kit=HERE/'srdsh-work/components/zero-sky/kit/srdssh/payload-root'
    for n in ('toybox','cryptex-run'):shutil.copy2(kit/'usr/bin'/n,root/'usr/bin'/n)
    script=root/'usr/bin/prepare-crane-runtime'
    script.write_text(r'''#!/bin/sh
set -eu
T="$CRYPTEX_MOUNT_PATH/usr/bin/toybox"
STATE=/var/jb/var/lib/srd-runtime
PAUSE=/var/mobile/pl/srd-runtime-paused
ALLOW="$STATE/tweak-targets/com.opa334.crane.json"
BACKUP="$STATE/tweak-targets/com.opa334.crane.json.0sky-runtime-repair"
"$T" mkdir -p /var/mobile/pl "$STATE"
"$T" touch "$PAUSE"
if [ -f "$ALLOW" ]; then "$T" mv -f "$ALLOW" "$BACKUP"; fi
TMP="$STATE/quarantine-clear.request.json.0sky-tmp"
"$T" printf '%s\n' '{"package":"com.opa334.crane","target":null}' > "$TMP"
"$T" chmod 600 "$TMP"
"$T" chown 0:0 "$TMP"
"$T" mv -f "$TMP" "$STATE/quarantine-clear.request.json"
"$T" touch "$STATE/rescan.request"
"$T" printf '%s\n' '{"status":"PREPARED","runtime_paused":true,"crane_target_deferred":true,"quarantine_clear_requested":true}' > /var/jb/var/log/0sky-crane-runtime-prepare.json
''');script.chmod(0o755)
    launch={'Label':IDENTIFIER,'ProgramArguments':['/usr/bin/cryptex-run','toybox','sh','-c','exec "$CRYPTEX_MOUNT_PATH/usr/bin/toybox" sh "$CRYPTEX_MOUNT_PATH/usr/bin/prepare-crane-runtime"'],'RunAtLoad':True,'KeepAlive':False}
    (root/'Library/LaunchDaemons/prepare.plist').write_bytes(plistlib.dumps(launch))
    shutil.copy2(ROOT/'bridge/KitScripts/automation/CrypStoreAutomation/native-install/generate_trust_cache.py',out/'generate_trust_cache.py')
    sys.path.insert(0,str(INSTALLER));from install_cryptex_native import build,install
    manifest=build(root,IDENTIFIER,VERSION,out);asyncio.run(install(manifest,IDENTIFIER,a.udid));print(manifest)

if __name__=='__main__':main()
