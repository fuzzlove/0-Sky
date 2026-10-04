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
[[ -f "$kit/SHA256SUMS" ]] || {
  echo "Authorized kit is missing SHA256SUMS: $kit" >&2; exit 2;
}
if [[ ! -f "$kit/PORTABILITY.json" ]]; then
  prepared="${derived}.prepared-kit"
  echo "Preparing and sanitizing the verified external kit…"
  python3 "$project_root/tools/prepare_release_kit.py" "$kit" "$prepared"
  kit=$prepared
fi
python3 "$project_root/tools/verify_prepared_kit.py" "$kit"
python3 "$project_root/tools/host_runtime_manifest.py" "$kit"
python3 "$project_root/tools/kit_manifest.py" verify "$kit"
python3 "$project_root/tools/wheel_inventory.py" "$kit" --verify
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
  ARCHS="arm64 x86_64" ONLY_ACTIVE_ARCH=NO CODE_SIGNING_ALLOWED=NO \
  OTHER_SWIFT_FLAGS="-debug-prefix-map $project_root=./source -file-prefix-map $project_root=./source -debug-prefix-map $derived=./build -file-prefix-map $derived=./build" \
  OTHER_CFLAGS="-fdebug-prefix-map=$project_root=./source -ffile-prefix-map=$project_root=./source -fdebug-prefix-map=$derived=./build -ffile-prefix-map=$derived=./build" \
  -quiet build

app="$derived/Build/Products/Release/0SkyBridge.app"
python3 "$project_root/tools/verify_eula.py" --bundle "$app"
binary="$app/Contents/MacOS/0SkyBridge"
link_ipa="$app/Contents/Resources/Kit/payloads/0-Sky-Link-1.9.0-universal.ipa"
controller="$app/Contents/Resources/Scripts/0sky_project_setup.py"
afc2_mount_controller="$app/Contents/Resources/Scripts/afc2_root_mount.py"
[[ -f "$binary" && -f "$app/Contents/Resources/Kit/SHA256SUMS" \
   && -f "$controller" && -f "$afc2_mount_controller" && -f "$link_ipa" ]] || {
  echo "Universal build is missing the app, setup controller, AFC2 mount controller, Link IPA, or verified kit" >&2; exit 1;
}
# This build is unsigned; keep internal dSYMs in DerivedData, not in the app.
for native in "$binary" "$app/Contents/MacOS/0SkyBridgeService" \
  "$app/Contents/Library/LaunchServices/0SkyBridgeHelper"; do
  /usr/bin/strip -S "$native"
done
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
