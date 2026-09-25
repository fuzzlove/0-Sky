#!/bin/zsh
set -euo pipefail

UDID=${CRYPTEXCTL_UDID:-}
IDENTIFIER=${SRDSH_IDENTIFIER:-com.jonpalmisc.srdsh}
VERSION=${SRDSH_VERSION:-1.0.0}
WORK=${0:A:h}
EXPLOITDEV=${WORK:h:h}
ROOT=${SRDSH_ROOT:-$WORK/../srdsh/build/com.jonpalmisc.srdsh.root}
TEMPLATE=${SRDSH_BUILD_MANIFEST:-$EXPLOITDEV/example-cryptex/retry-apfs/com.example.cryptex.cxbd/Restore/BuildManifest.plist}
CTL=${SRD_CRYPTEXCTL:-/System/Library/SecurityResearch/usr/bin/cryptexctl}
PYTHON=${SRD_PYTHON:-$(command -v python3.13 || true)}
PYTHONPATH_VALUE=${SRD_PYTHONPATH:-}
IMAGE_SIZE=${SRDSH_IMAGE_SIZE:-384m}

RW_DMG="$WORK/srdsh-apfs-rw.dmg"
SEALED_DMG="$WORK/srdsh-apfs-sealed.dmg"
FINAL_DMG="$WORK/srdsh-apfs-sealed-udzo.dmg"
HASH="$WORK/srdsh-apfs-sealed.hash"
TRUST_DER="$WORK/srdsh.trustcache"
TRUST_IM4P="$WORK/srdsh.gtcd"
PROC_TRUST="$WORK/procursus.trustcache"
MOUNT="$WORK/mnt"

[[ -d "$ROOT" ]] || { print -u2 "missing payload root: $ROOT"; exit 1; }
[[ -f "$TEMPLATE" ]] || { print -u2 "missing BuildManifest template: $TEMPLATE"; exit 1; }
[[ -x "$CTL" ]] || { print -u2 "missing SRD cryptexctl: $CTL"; exit 1; }
[[ -n "$PYTHON" && -x "$PYTHON" ]] || { print -u2 'missing Python 3.13; set SRD_PYTHON'; exit 1; }
[[ $($PYTHON --version) == Python\ 3.13.* ]] || { print -u2 'SRD_PYTHON must be Python 3.13'; exit 1; }
[[ -n "$UDID" ]] || { print -u2 'set CRYPTEXCTL_UDID to the exact SRD'; exit 1; }
export PYTHONNOUSERSITE=1

cleanup_mounts() {
  if mount | grep -Fq " on $MOUNT "; then
    hdiutil detach "$MOUNT" >/dev/null 2>&1 || true
  fi
}
trap cleanup_mounts EXIT INT TERM

"$PYTHON" - "$RW_DMG" "$SEALED_DMG" "$FINAL_DMG" "$HASH" "$TRUST_DER" "$TRUST_IM4P" "$MOUNT" <<'PY'
import pathlib, shutil, subprocess, sys
for value in sys.argv[1:7]:
    path = pathlib.Path(value)
    if path.is_dir():
        shutil.rmtree(path)
    elif path.exists():
        path.unlink()
mount = pathlib.Path(sys.argv[7])
if mount.exists():
    subprocess.run(["hdiutil", "detach", str(mount)], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    shutil.rmtree(mount, ignore_errors=True)
mount.mkdir(parents=True)
PY

print '== generating trust cache =='
if [[ ${SRDSH_TRUST_CACHE_MODE:-payload} == apple-signed && \
      -x "$WORK/generate_trust_cache.py" ]]; then
  # A preserved App Store signature already has Apple execution trust.  If
  # its CDHash is also inserted into a loadable trust cache, the kernel marks
  # the process as a platform binary.  iOS 26+ then applies Mach IPC platform
  # restrictions which make older Crashlytics builds abort at launch.
  "$PYTHON" "$WORK/generate_trust_cache.py" --empty "$ROOT" "$TRUST_DER"
elif [[ -x "$WORK/generate_trust_cache.py" && ! -f "$PROC_TRUST" ]]; then
  # cryptexctl initializes MobileDevice even for local trust-cache generation;
  # a stale device personalization session can therefore deadlock a purely
  # local build. This bounded generator hashes the embedded CodeDirectories
  # directly and emits the same loadable IM4P format without device I/O.
  "$PYTHON" "$WORK/generate_trust_cache.py" "$ROOT" "$TRUST_DER"
elif [[ -f "$PROC_TRUST" ]]; then
  print "including Procursus base trust cache: $PROC_TRUST"
  "$CTL" generate-trust-cache -o "$TRUST_DER" -t loadable -b "$PROC_TRUST" "$ROOT"
else
  "$CTL" generate-trust-cache -o "$TRUST_DER" -t loadable "$ROOT"
fi

"$PYTHON" - "$TRUST_DER" "$TRUST_IM4P" <<'PY'
from pathlib import Path
import sys
source, output = map(Path, sys.argv[1:3])
buf = source.read_bytes()
def dl(n):
    if n < 128: return bytes([n])
    b = n.to_bytes((n.bit_length()+7)//8, 'big')
    return bytes([0x80 | len(b)]) + b
def ia(s):
    b=s.encode('ascii'); return b'\x16'+dl(len(b))+b
def oc(b): return b'\x04'+dl(len(b))+b
def sq(*parts):
    body=b''.join(parts); return b'\x30'+dl(len(body))+body
def parse_len(data, off):
    b=data[off]; off += 1
    if b < 128: return b, off
    n=b & 0x7f
    return int.from_bytes(data[off:off+n], 'big'), off+n
length, off = parse_len(buf, 1)
end=off+length; last=None
while off < end:
    tag=buf[off]; off += 1
    length, off = parse_len(buf, off)
    value=buf[off:off+length]; off += length
    if tag == 0x04: last=value
if last is None: raise RuntimeError('no trust-cache octet string')
wrapped=sq(ia('IM4P'), ia('gtcd'), ia('1'), oc(last))
output.write_bytes(wrapped)
print('trust', len(buf), len(last), len(wrapped))
PY

print '== building APFS cryptex image =='
hdiutil create -size "$IMAGE_SIZE" -fs APFS -volname srdsh -layout NONE "$RW_DMG"
ATTACH_OUTPUT=$(hdiutil attach -nobrowse -mountpoint "$MOUNT" "$RW_DMG")
print -r -- "$ATTACH_OUTPUT"
DEVICE=$(print -r -- "$ATTACH_OUTPUT" | awk '/Apple_APFS/ {print $1; found=1; exit} /^\/dev\/disk/ {d=$1} END{if(!found && d) print d}')
[[ -n "$DEVICE" ]] || { print -u2 'unable to identify attached APFS device'; exit 1; }
ditto "$ROOT" "$MOUNT"
hdiutil detach "$DEVICE"

cp "$RW_DMG" "$SEALED_DMG"
hdiutil attach -nomount "$SEALED_DMG" > "$WORK/attach-nomount.txt"
CATALYST_DEVICE=$(awk '/Apple_APFS/ {print $1}' "$WORK/attach-nomount.txt" | tail -1)
[[ -n "$CATALYST_DEVICE" ]] || CATALYST_DEVICE=$(awk '/\/dev\/disk/ {print $1}' "$WORK/attach-nomount.txt" | tail -1)
[[ -n "$CATALYST_DEVICE" ]] || { print -u2 'unable to identify sealing device'; exit 1; }
/System/Library/Filesystems/apfs.fs/Contents/Resources/apfs_prepare_cryptex -p -M "$HASH" "$CATALYST_DEVICE"
BASE_DEVICE=$(print -r -- "$CATALYST_DEVICE" | sed 's/s[0-9]*$//')
hdiutil detach "$BASE_DEVICE" >/dev/null 2>&1 || hdiutil detach "$CATALYST_DEVICE" >/dev/null
hdiutil convert "$SEALED_DMG" -format UDZO -o "$FINAL_DMG"

ls -lh "$FINAL_DMG" "$HASH" "$TRUST_IM4P"
true # 0-Sky Control app payloads contain no SSH key
if [[ ${SRDSH_BUILD_ONLY:-0} == 1 ]]; then
  print '== build-only requested; RemoteXPC install skipped =='
  exit 0
fi
print '== installing over native RemoteXPC tunnel =='
PYTHONPATH="$PYTHONPATH_VALUE" "$PYTHON" "$WORK/install_cryptex_native.py" \
    "$IDENTIFIER" "$FINAL_DMG" "$TRUST_IM4P" "$HASH" "$VERSION" "$UDID" "$TEMPLATE"
