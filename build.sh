#!/bin/bash
# Build an unsigned universal macOS Bridge bundle for Intel and Apple silicon.
# Sign and notarize with caller-owned credentials before public distribution.
set -euo pipefail

project_root=$(cd "$(dirname "$0")" && pwd)
if ! command -v python3 >/dev/null 2>&1; then
  cat >&2 <<'EOF'
BUILD=BLOCKED requirement=python3
Required action:
  Install the universal2 Python 3 package from https://www.python.org/downloads/macos/
  or run `brew install python`, open a new Terminal, verify `python3 --version`,
  then rerun this build. This interpreter is a source-build tool only; end users
  receive the pinned Python runtime inside 0SkyBridge.app.
EOF
  exit 2
fi
derived="${ZERO_SKY_DERIVED_DATA:-$project_root/.build/release}"
kit="${ZERO_SKY_KIT_SOURCE:-$project_root/bridge/0SkyBridge/Resources/Scripts/kit}"
project="$project_root/bridge/0SkyBridge.xcodeproj"
python3 "$project_root/tools/verify_eula.py"

choose_directory() {
  local prompt=$1
  [[ -t 0 && -x /usr/bin/osascript ]] || return 1
  /usr/bin/osascript - "$prompt" <<'APPLESCRIPT'
on run argv
  try
    set chosenFolder to choose folder with prompt (item 1 of argv)
    return POSIX path of chosenFolder
  on error number -128
    return ""
  end try
end run
APPLESCRIPT
}

while (( $# )); do
  case "$1" in
    --kit) [[ $# -ge 2 ]] || { echo "--kit requires a path" >&2; exit 64; }
      kit=$2; shift 2 ;;
    --derived-data) [[ $# -ge 2 ]] || { echo "--derived-data requires a path" >&2; exit 64; }
      derived=$2; shift 2 ;;
    --theos) [[ $# -ge 2 ]] || { echo "--theos requires a path" >&2; exit 64; }
      export THEOS=$2; shift 2 ;;
    *) echo "Unknown build option: $1" >&2; exit 64 ;;
  esac
done
if [[ -z ${THEOS:-} ]]; then
  echo "The locked Theos source toolchain path was not provided."
  echo "Choose the Theos checkout directory itself; it must contain makefiles/common.mk."
  selected=$(choose_directory "Select the locked 0-Sky Theos checkout. It must contain makefiles/common.mk and the pinned recursive submodules." || true)
  [[ -n "$selected" ]] && export THEOS=${selected%/}
fi
[[ -n ${THEOS:-} ]] || {
  cat >&2 <<'EOF'
BUILD=BLOCKED requirement=locked-theos
Required action:
  git clone --recursive https://github.com/theos/theos.git '/absolute/path/to/theos'
  git -C '/absolute/path/to/theos' checkout dd5c14bb9d91311e221d51b5bfb8c9e5948156db
  git -C '/absolute/path/to/theos' submodule update --init --recursive
  Rerun this command with: --theos '/absolute/path/to/theos'
Use a new checkout; do not reset a Theos tree that contains uncommitted work.
EOF
  exit 2;
}
python3 "$project_root/tools/theos_preflight.py" --theos "$THEOS"
if [[ ! -f "$kit/SHA256SUMS" ]]; then
  echo "The authorized offline kit path is missing or incomplete: $kit" >&2
  echo "Choose the kit directory itself; it must directly contain SHA256SUMS," >&2
  echo "host-mac, payloads, and the offline wheelhouse." >&2
  selected=$(choose_directory "Select the verified 0-Sky kit directory. It must directly contain SHA256SUMS, host-mac, payloads, and the offline wheelhouse." || true)
  [[ -n "$selected" ]] && kit=${selected%/}
fi
[[ -f "$kit/SHA256SUMS" ]] || {
  cat >&2 <<EOF
BUILD=BLOCKED requirement=authorized-kit
The selected kit is missing its signed inventory: $kit/SHA256SUMS
Required action:
  Obtain the complete authorized offline kit from the project release owner,
  copy it to a writable directory outside this repository, and rerun with:
    --kit '/absolute/path/to/authorized kit'
The source repository cannot download Apple SRD assets, signed device payloads,
pairing material, or publisher-only dependencies, and an installed app's kit
must not be copied back into a release build.
EOF
  exit 2;
}
if [[ ! -f "$kit/RELEASE_KIT_MANIFEST.json" || ! -f "$kit/RELEASE_KIT_APPROVAL.json" ]]; then
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
  -derivedDataPath "$derived" -sdk macosx -destination 'generic/platform=macOS' \
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
