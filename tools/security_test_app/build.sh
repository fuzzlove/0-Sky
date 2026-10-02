#!/bin/zsh
set -euo pipefail

HERE=${0:A:h}
ROOT=${HERE:h:h}
OUT=${ZERO_SKY_TEST_APP_OUTPUT:-"$HERE/dist"}
VERSION=${ZERO_SKY_TEST_APP_VERSION:-"1.1.0"}
EMBED_CRANE=${ZERO_SKY_EMBED_CRANE_DIR:-}
SUBSTRATE_SHIM=${ZERO_SKY_SUBSTRATE_SHIM:-}
WORK=$(/usr/bin/mktemp -d /tmp/0sky-security-test.XXXXXX)
APP="$WORK/Payload/ZeroSkySecurityTest.app"
cleanup() { [[ -d "$WORK" ]] && /bin/rm -rf "$WORK"; }
trap cleanup EXIT INT TERM

SDK=$(/usr/bin/xcrun --sdk iphoneos --show-sdk-path)
CLANG=$(/usr/bin/xcrun --sdk iphoneos --find clang)
mkdir -p "$APP" "$OUT"
CRANE_DEFINE=0
[[ -n "$EMBED_CRANE" ]] && CRANE_DEFINE=1
"$CLANG" -fobjc-arc -DZERO_SKY_EMBED_CRANE=$CRANE_DEFINE \
  -target arm64-apple-ios17.0 -isysroot "$SDK" -Os \
  -framework UIKit -framework Foundation "$HERE/main.m" -o "$APP/ZeroSkySecurityTest"
cp "$HERE/Info.plist" "$APP/Info.plist"
/usr/libexec/PlistBuddy -c "Set :CFBundleShortVersionString $VERSION" "$APP/Info.plist"
if [[ -n "$EMBED_CRANE" ]]; then
  [[ -f "$ZERO_SKY_EMBED_CRANE_DYLIB" ]] || { print -u2 "Missing reviewed Crane dylib"; exit 2; }
  for library in libellekit.dylib libcrane.dylib libsandy.dylib; do
    [[ -f "$EMBED_CRANE/$library" ]] || { print -u2 "Missing $library"; exit 2; }
  done
  mkdir -p "$APP/Frameworks"
  cp "$ZERO_SKY_EMBED_CRANE_DYLIB" "$APP/Frameworks/Crane.dylib"
  cp "$EMBED_CRANE"/libcrane.dylib "$EMBED_CRANE"/libsandy.dylib \
    "$APP/Frameworks/"
  if [[ -n "$SUBSTRATE_SHIM" ]]; then
    [[ -f "$SUBSTRATE_SHIM" ]] || { print -u2 "Missing Substrate function shim"; exit 2; }
    cp "$SUBSTRATE_SHIM" "$APP/Frameworks/lib0SkySubstrateFunctionShim.dylib"
    /usr/bin/install_name_tool -change \
      @rpath/CydiaSubstrate.framework/CydiaSubstrate \
      @rpath/lib0SkySubstrateFunctionShim.dylib "$APP/Frameworks/Crane.dylib"
  else
    cp "$EMBED_CRANE"/libellekit.dylib "$APP/Frameworks/"
    /usr/bin/install_name_tool -change \
      @rpath/CydiaSubstrate.framework/CydiaSubstrate @rpath/libellekit.dylib \
      "$APP/Frameworks/Crane.dylib"
  fi
  /usr/bin/install_name_tool -rpath /var/jb/usr/lib @loader_path \
    "$APP/Frameworks/Crane.dylib"
  for library in "$APP"/Frameworks/*.dylib; do
    /usr/bin/codesign --force --sign - --timestamp=none "$library"
  done
  /usr/bin/python3 - "$APP/0SkyCraneAdapter.plist" <<'PY'
import pathlib, plistlib, sys
path = pathlib.Path(sys.argv[1])
path.write_bytes(plistlib.dumps({
    "Schema": 1,
    "Adapter": "crane-pre-main-v1",
    "BundleIdentifier": "com.liquidsky.SecurityTest",
    "StateTransport": "private-data-handoff-v1",
    "Runtime": "embedded-reviewed-crane",
}, fmt=plistlib.FMT_BINARY, sort_keys=True))
PY
fi
/usr/bin/xattr -cr "$APP"
SIGN_ARGUMENTS=(--force --sign - --timestamp=none --identifier com.liquidsky.SecurityTest)
if [[ -n "$EMBED_CRANE" ]]; then
  SIGN_ARGUMENTS+=(--entitlements "$HERE/crane-fixture.entitlements.plist")
fi
/usr/bin/codesign "${SIGN_ARGUMENTS[@]}" "$APP"
/usr/bin/codesign --verify --deep --strict "$APP"
/usr/bin/python3 "$ROOT/tools/deterministic_zip.py" "$WORK" "$OUT/0-Sky-Security-Test-$VERSION.ipa"
(
  cd "$OUT"
  /usr/bin/shasum -a 256 "0-Sky-Security-Test-$VERSION.ipa" > SHA256SUMS
)
print "Built controlled 0-Sky Security Test App"
