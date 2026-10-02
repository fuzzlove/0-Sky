#!/usr/bin/env python3
"""Export a fixed whitelist of SRD runtime state through the Crane report endpoint."""
from __future__ import annotations

import argparse
import asyncio
import plistlib
import shutil
import sys
from datetime import datetime, timezone
from pathlib import Path

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[1]
INSTALLER = ROOT / "bridge/KitScripts/runtime-generation"
IDENTIFIER = "com.liquidsky.crane.repair6"
VERSION = "1.0.2-diagnostic"


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--udid", required=True)
    args = parser.parse_args()
    output = HERE / "crane-repair" / (
        "runtime-diag-export-" + datetime.now(timezone.utc).strftime("%Y%m%d%H%M%S")
    )
    root = output / "root"
    (root / "usr/bin").mkdir(parents=True)
    (root / "Library/LaunchDaemons").mkdir(parents=True)
    kit = HERE / "srdsh-work/components/zero-sky/kit/srdssh/payload-root"
    for name in ("toybox", "cryptex-run"):
        shutil.copy2(kit / "usr/bin" / name, root / "usr/bin" / name)
    script = root / "usr/bin/export-runtime-diag"
    script.write_text(r'''#!/bin/sh
set -eu
T="$CRYPTEX_MOUNT_PATH/usr/bin/toybox"
OUT=/var/jb/var/log/0sky-crane-repair6.json
TMP="$OUT.runtime-diag.tmp"
: > "$TMP"
for p in \
 /var/jb/var/lib/srd-runtime/registry.json \
 /var/jb/var/lib/srd-runtime/injection-state.json \
 /var/jb/var/lib/srd-runtime/injection-quarantine.json \
 /var/jb/var/lib/srd-runtime/events.jsonl \
 /var/mobile/Library/Logs/srd-runtime-manager.log \
 /var/jb/var/log/srd-runtime-manager.log \
 /var/jb/var/log/cranehelperd.stdout.log \
 /var/jb/var/log/cranehelperd.stderr.log
do
 "$T" printf '\n===== %s =====\n' "$p" >> "$TMP"
 if [ -f "$p" ]; then "$T" tail -c 4194304 "$p" >> "$TMP"; "$T" printf '\n' >> "$TMP"; else "$T" printf 'MISSING\n' >> "$TMP"; fi
done
"$T" chmod 600 "$TMP"
"$T" chown 0:0 "$TMP"
"$T" mv -f "$TMP" "$OUT"
''')
    script.chmod(0o755)
    launch = {
        "Label": IDENTIFIER,
        "ProgramArguments": ["/usr/bin/cryptex-run", "toybox", "sh", "-c",
                             "exec \"$CRYPTEX_MOUNT_PATH/usr/bin/toybox\" sh \"$CRYPTEX_MOUNT_PATH/usr/bin/export-runtime-diag\""],
        "RunAtLoad": True,
        "KeepAlive": False,
    }
    (root / "Library/LaunchDaemons/export.plist").write_bytes(plistlib.dumps(launch))
    shutil.copy2(
        ROOT / "bridge/KitScripts/automation/CrypStoreAutomation/native-install/generate_trust_cache.py",
        output / "generate_trust_cache.py",
    )
    sys.path.insert(0, str(INSTALLER))
    from install_cryptex_native import build, install
    manifest = build(root, IDENTIFIER, VERSION, output)
    asyncio.run(install(manifest, IDENTIFIER, args.udid))
    print(manifest)


if __name__ == "__main__":
    main()
