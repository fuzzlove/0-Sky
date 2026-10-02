#!/bin/zsh
set -euo pipefail

HERE=${0:A:h}
OUT=${LINK_OUTPUT:-"$HERE/dist"}
VERSION=$(/usr/libexec/PlistBuddy -c 'Print :CFBundleShortVersionString' "$HERE/Info.plist")
BUILD_NUMBER=$(/usr/libexec/PlistBuddy -c 'Print :CFBundleVersion' "$HERE/Info.plist")
BUNDLE_ID=$(/usr/libexec/PlistBuddy -c 'Print :CFBundleIdentifier' "$HERE/Info.plist")
WORK=$(/usr/bin/mktemp -d /tmp/0sky-link-source.XXXXXX)
APP="$WORK/Payload/ZeroSky.app"
APP_ICON="$HERE/Assets/LinkAppIcon.png"

cleanup() { [[ -d "$WORK" ]] && /bin/rm -rf "$WORK"; }
trap cleanup EXIT INT TERM

SDK=$(/usr/bin/xcrun --sdk iphoneos --show-sdk-path)
CLANG=$(/usr/bin/xcrun --sdk iphoneos --find clang)
mkdir -p "$APP" "$OUT"

"$CLANG" -fobjc-arc -target arm64-apple-ios17.0 -isysroot "$SDK" -Os \
  -framework UIKit -framework Foundation -framework QuartzCore \
  -framework CoreGraphics "$HERE/main.m" "$HERE/BootSplash/ZSSplashController.m" \
  "$HERE/Theme/ZSLinkTheme.m" "$HERE/Start/ZSStartController.m" -I"$HERE" -o "$APP/ZeroSky"
cp "$HERE/Info.plist" "$APP/Info.plist"
cp "$HERE/Assets/ZeroSky.png" "$APP/ZeroSky.png"
cp "$HERE/CREDITS.txt" "$APP/CREDITS.txt"

for spec in '120 AppIcon60x60@2x.png' '180 AppIcon60x60@3x.png'; do
  size=${spec%% *}; name=${spec#* }
  /usr/bin/sips -z "$size" "$size" "$APP_ICON" \
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
  /usr/bin/python3 "$HERE/../tools/prune_release_artifacts.py" "$APP/SRDKit"
  if find "$APP/SRDKit" \( -type f -o -type l \) \( -name '*.key' -o -name '*.p12' -o \
    -name '*.mobileprovision' -o -name '*pairing*record*' -o -name '*.token' \) \
    -print -quit | /usr/bin/grep -q .; then
    print -u2 'verified kit unexpectedly contains secret-bearing files'; exit 4
  fi
  /usr/bin/python3 "$HERE/../tools/rebuild_sha_manifest.py" "$APP/SRDKit"
  CONTROL_IPA="$APP/SRDKit/packages/Commissary-Universal.ipa"
  [[ -f "$CONTROL_IPA" && ! -L "$CONTROL_IPA" ]] || {
    print -u2 'verified kit has no canonical Control IPA'; exit 5
  }
  /usr/bin/python3 "$HERE/../tools/generate_control_payload.py" \
    "$CONTROL_IPA" "$APP/ControlPayload/manifest.json"
fi

/usr/bin/xattr -cr "$APP"
/usr/bin/codesign --force --sign - --timestamp=none \
  --entitlements "$HERE/entitlements.plist" --identifier "$BUNDLE_ID" "$APP"
/usr/bin/codesign --verify --deep --strict "$APP"

IPA="$OUT/0-Sky-Link-${VERSION}-source.ipa"
/usr/bin/python3 "$HERE/../tools/deterministic_zip.py" "$WORK" "$IPA"
(
  cd "$OUT"
  /usr/bin/shasum -a 256 "${IPA:t}" > "SHA256SUMS-${VERSION}-source"
)
print "Built 0-Sky Link $VERSION ($BUILD_NUMBER): ${IPA:t}"
