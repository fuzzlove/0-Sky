#!/usr/bin/env python3
import argparse,asyncio,json,plistlib,shutil,sys
from pathlib import Path
HERE=Path(__file__).resolve().parent;ROOT=HERE.parents[1];INSTALLER=ROOT/'bridge/KitScripts/runtime-generation'
IDENTIFIER='com.liquidsky.crane.report-export6';VERSION='1.0.0'
def main():
 ap=argparse.ArgumentParser();ap.add_argument('--udid',required=True);ap.add_argument('--output',type=Path,required=True);a=ap.parse_args();a.output.mkdir(parents=True,mode=0o700)
 root=a.output/'root';(root/'usr/bin').mkdir(parents=True);(root/'Library/LaunchDaemons').mkdir(parents=True)
 kit=HERE/'srdsh-work/components/zero-sky/kit/srdssh/payload-root'
 for n in ('toybox','cryptex-run'):shutil.copy2(kit/'usr/bin'/n,root/'usr/bin'/n)
 start=root/'usr/bin/export-crane-report';start.write_text('#!/bin/sh\nset -eu\nT="$CRYPTEX_MOUNT_PATH/usr/bin/toybox"\nfor n in 0sky-crane-repair6.json 0sky-crane-repair6.stdout.log cranehelperd.stdout.log cranehelperd.stderr.log; do\n p="/var/jb/var/log/$n"\n if [ -f "$p" ]; then "$T" cp "$p" "/var/mobile/Media/$n"; "$T" chown 501:501 "/var/mobile/Media/$n"; "$T" chmod 600 "/var/mobile/Media/$n"; fi\ndone\n');start.chmod(0o755)
 launch={'Label':IDENTIFIER,'ProgramArguments':['/usr/bin/cryptex-run','toybox','sh','-c','exec "$CRYPTEX_MOUNT_PATH/usr/bin/toybox" sh "$CRYPTEX_MOUNT_PATH/usr/bin/export-crane-report"'],'RunAtLoad':True,'KeepAlive':False}
 (root/'Library/LaunchDaemons/export.plist').write_bytes(plistlib.dumps(launch))
 shutil.copy2(ROOT/'bridge/KitScripts/automation/CrypStoreAutomation/native-install/generate_trust_cache.py',a.output/'generate_trust_cache.py')
 sys.path.insert(0,str(INSTALLER));from install_cryptex_native import build,install
 manifest=build(root,IDENTIFIER,VERSION,a.output);asyncio.run(install(manifest,IDENTIFIER,a.udid));print(json.dumps({'installed':True,'manifest':str(manifest)},indent=2))
if __name__=='__main__':main()
