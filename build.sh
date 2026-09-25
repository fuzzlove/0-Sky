#!/bin/bash
# Build an unsigned universal macOS Bridge bundle for Intel and Apple silicon.
# Sign and notarize with caller-owned credentials before public distribution.
set -euo pipefail

project_root=$(cd "$(dirname "$0")" && pwd)
derived="${ZERO_SKY_DERIVED_DATA:-$project_root/.build/release}"
kit="${ZERO_SKY_KIT_SOURCE:-$project_root/bridge/0SkyBridge/Resources/Scripts/kit}"
project="$project_root/bridge/0SkyBridge.xcodeproj"
python3 "$project_root/tools/verify_eula.py"

while (( $# )); do
  case "$1" in
    --kit) [[ $# -ge 2 ]] || { echo "--kit requires a path" >&2; exit 64; }
      kit=$2; shift 2 ;;
    --derived-data) [[ $# -ge 2 ]] || { echo "--derived-data requires a path" >&2; exit 64; }
      derived=$2; shift 2 ;;
    *) echo "Unknown build option: $1" >&2; exit 64 ;;
  esac
done
[[ -f "$kit/SHA256SUMS" && -f "$kit/PORTABILITY.json" ]] || {
  echo "Prepared release kit is missing; run tools/prepare_release_kit.py, then pass --kit PATH" >&2; exit 2;
}
python3 "$project_root/tools/verify_prepared_kit.py" "$kit"
preflight_scan=(python3 "$project_root/tools/release_sanitize.py" "$kit")
if [[ -n ${ZERO_SKY_RELEASE_DENY_FILE:-} ]]; then
  preflight_scan+=(--deny-file "$ZERO_SKY_RELEASE_DENY_FILE")
fi
"${preflight_scan[@]}"
kit=$(cd "$(dirname "$kit")" && pwd)/$(basename "$kit")
mkdir -p "$derived"
derived=$(cd "$derived" && pwd)

ZERO_SKY_KIT_SOURCE="$kit" xcodebuild -project "$project" -scheme 0SkyBridge -configuration Release \
  -derivedDataPath "$derived" -sdk macosx \
  ARCHS="arm64 x86_64" ONLY_ACTIVE_ARCH=NO CODE_SIGNING_ALLOWED=NO -quiet build

app="$derived/Build/Products/Release/0SkyBridge.app"
python3 "$project_root/tools/verify_eula.py" --bundle "$app"
binary="$app/Contents/MacOS/0SkyBridge"
link_ipa="$app/Contents/Resources/Kit/payloads/0-Sky-Link-1.9.0-universal.ipa"
controller="$app/Contents/Resources/Scripts/0sky_project_setup.py"
[[ -f "$binary" && -f "$app/Contents/Resources/Kit/SHA256SUMS" \
   && -f "$controller" && -f "$link_ipa" ]] || {
  echo "Universal build is missing the app, setup controller, Link IPA, or verified kit" >&2; exit 1;
}
# This build is unsigned; remove DWARF/source paths before the app-wide gate.
/usr/bin/strip -S "$binary"
python3 "$project_root/tools/verify_link_ipa.py" "$link_ipa"
xcrun lipo "$binary" -verify_arch x86_64 arm64
xcrun lipo "$app/Contents/Resources/Kit/host-mac/zero-sky-bluetooth-tunnel" \
  -verify_arch x86_64 arm64
sanitize=(python3 "$project_root/tools/release_sanitize.py" "$app")
if [[ -n ${ZERO_SKY_RELEASE_DENY_FILE:-} ]]; then
  sanitize+=(--deny-file "$ZERO_SKY_RELEASE_DENY_FILE")
fi
"${sanitize[@]}"
echo "Universal app built in configured derived-data directory"
echo "This local build is unsigned. Sign and notarize it with your release identity."
