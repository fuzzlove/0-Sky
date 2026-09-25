#!/bin/bash
# Xcode build phase: embed the manifest-verified, PII-audited dual-architecture kit.
set -euo pipefail

source_root=${SRCROOT:?}
legal="$source_root/0SkyBridge/Resources/Legal"
/usr/bin/python3 "$source_root/../tools/verify_eula.py" --source "$legal"
kit="${ZERO_SKY_KIT_SOURCE:-$source_root/0SkyBridge/Resources/Scripts/kit}"
[[ -f "$kit/SHA256SUMS" && -f "$kit/PORTABILITY.json" ]] || {
  echo "Prepared 0-Sky kit is missing; run tools/prepare_release_kit.py" >&2; exit 1;
}
/usr/bin/python3 "$source_root/../tools/verify_prepared_kit.py" "$kit"
resources="${TARGET_BUILD_DIR:?}/${CONTENTS_FOLDER_PATH:?}/Resources"
mkdir -p "$resources/Scripts" "$resources/Legal"
/usr/bin/ditto --noqtn "$legal/EULA.md" "$resources/Legal/EULA.md"
/usr/bin/ditto --noqtn "$legal/EULA.json" "$resources/Legal/EULA.json"
/usr/bin/python3 "$source_root/../tools/verify_eula.py" --source "$legal" \
  --bundle "${TARGET_BUILD_DIR}/${WRAPPER_NAME:?}"
/usr/bin/python3 "$source_root/../tools/stage_verified_kit.py" \
  "$kit" "$resources/Kit" --release
sanitize=(/usr/bin/python3 "$source_root/../tools/release_sanitize.py"
  "$resources/Kit" "$source_root/macos_host_setup.py"
  "$source_root/0SkyBridge/Resources/Scripts/0sky_project_setup.py"
  "$source_root/zero_sky_user_config.py"
  "$source_root/0SkyBridge/Resources/Scripts/Install 0-Sky Dependencies.command")
if [[ -n ${ZERO_SKY_RELEASE_DENY_FILE:-} ]]; then
  sanitize+=(--deny-file "$ZERO_SKY_RELEASE_DENY_FILE")
fi
"${sanitize[@]}"
/usr/bin/lipo "$resources/Kit/host-mac/zero-sky-bluetooth-tunnel" -verify_arch x86_64 arm64
/usr/bin/lipo "$resources/Kit/automation/CrypStoreAutomation/device_bridge_supervisor" \
  -verify_arch x86_64 arm64
/usr/bin/ditto --noqtn "$source_root/macos_host_setup.py" "$resources/Scripts/macos_host_setup.py"
/usr/bin/ditto --noqtn "$source_root/0SkyBridge/Resources/Scripts/0sky_project_setup.py" \
  "$resources/Scripts/0sky_project_setup.py"
/usr/bin/ditto --noqtn "$source_root/zero_sky_user_config.py" "$resources/Scripts/zero_sky_user_config.py"
/usr/bin/ditto --noqtn \
  "$source_root/0SkyBridge/Resources/Scripts/Install 0-Sky Dependencies.command" \
  "$resources/Scripts/Install 0-Sky Dependencies.command"
chmod -R u=rwX,go=rX "$resources"
