#!/bin/zsh
set -euo pipefail

HERE=${0:A:h}
OUT=${LINK_OUTPUT:-"$HERE/dist"}
VERSION=$(/usr/libexec/PlistBuddy -c 'Print :CFBundleShortVersionString' "$HERE/Info.plist")
BUILD_NUMBER=$(/usr/libexec/PlistBuddy -c 'Print :CFBundleVersion' "$HERE/Info.plist")
BUNDLE_ID=$(/usr/libexec/PlistBuddy -c 'Print :CFBundleIdentifier' "$HERE/Info.plist")
WORK=$(/usr/bin/mktemp -d /tmp/0sky-link-source.XXXXXX)
APP="$WORK/Payload/ZeroSky.app"

cleanup() { [[ -d "$WORK" ]] && /bin/rm -rf "$WORK"; }
trap cleanup EXIT INT TERM

SDK=$(/usr/bin/xcrun --sdk iphoneos --show-sdk-path)
CLANG=$(/usr/bin/xcrun --sdk iphoneos --find clang)
mkdir -p "$APP" "$OUT"

"$CLANG" -fobjc-arc -target arm64-apple-ios17.0 -isysroot "$SDK" -Os \
  -framework UIKit -framework Foundation -framework QuartzCore \
  -framework CoreGraphics "$HERE/main.m" -I"$HERE" -o "$APP/ZeroSky"
cp "$HERE/Info.plist" "$APP/Info.plist"
cp "$HERE/Assets/ZeroSky.png" "$APP/ZeroSky.png"
cp "$HERE/CREDITS.txt" "$APP/CREDITS.txt"

for spec in '120 AppIcon60x60@2x.png' '180 AppIcon60x60@3x.png'; do
  size=${spec%% *}; name=${spec#* }
  /usr/bin/sips -z "$size" "$size" "$HERE/Assets/ZeroSky.png" \
    --out "$APP/$name" >/dev/null
done

if [[ -n ${ZERO_SKY_KIT_SOURCE:-${ZEROSKY_KIT_SOURCE:-}} ]]; then
  KIT_SOURCE=${ZERO_SKY_KIT_SOURCE:-${ZEROSKY_KIT_SOURCE:-}}
  KIT_SOURCE=${KIT_SOURCE:A}
  [[ -d "$KIT_SOURCE" ]] || { print -u2 'ZEROSKY_KIT_SOURCE is not a directory'; exit 2; }
  case "$KIT_SOURCE" in
    *'/state'|*'/state/'*|*'/logs'|*'/logs/'*|*'/evidence'|*'/evidence/'*)
      print -u2 'refusing to bundle state, logs, or evidence'; exit 3 ;;
  esac
  /usr/bin/ditto --noqtn "$KIT_SOURCE" "$APP/SRDKit"
  find "$APP/SRDKit" -type l -delete
  find "$APP/SRDKit" -type f \( -name '*.key' -o -name '*.p12' -o \
    -name '*.mobileprovision' -o -name '*pairing*record*' -o -name '*.token' \) -delete
  (cd "$APP/SRDKit" && find . -type f ! -name SHA256SUMS -exec \
    /usr/bin/shasum -a 256 {} \; | LC_ALL=C sort > SHA256SUMS)
fi

/usr/bin/xattr -cr "$APP"
/usr/bin/codesign --force --sign - --timestamp=none \
  --entitlements "$HERE/entitlements.plist" --identifier "$BUNDLE_ID" "$APP"
/usr/bin/codesign --verify --deep --strict "$APP"

IPA="$OUT/0-Sky-Link-${VERSION}-source.ipa"
/bin/rm -f "$IPA"
(cd "$WORK" && /usr/bin/zip -qry "$IPA" Payload)
(
  cd "$OUT"
  /usr/bin/shasum -a 256 "${IPA:t}" > "SHA256SUMS-${VERSION}-source"
)
print "Built 0-Sky Link $VERSION ($BUILD_NUMBER): ${IPA:t}"
