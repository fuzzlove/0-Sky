#!/usr/bin/env bash
# Install caller-supplied, already signed 0-Sky IPAs on one explicitly selected SRD.
# Signing keys and passwords are never stored in this script or passed on argv.
set -euo pipefail

usage() {
  echo "usage: $0 --udid DEVICE_UDID --link-ipa PATH --control-ipa PATH" >&2
  exit 64
}

udid=""
link_ipa=""
control_ipa=""
while (( $# )); do
  case "$1" in
    --udid|--link-ipa|--control-ipa)
      (( $# >= 2 )) || usage
      case "$1" in
        --udid) udid=$2 ;;
        --link-ipa) link_ipa=$2 ;;
        --control-ipa) control_ipa=$2 ;;
      esac
      shift 2 ;;
    *) usage ;;
  esac
done

[[ "$udid" =~ ^[A-Fa-f0-9-]{20,80}$ ]] || usage
[[ -f "$link_ipa" && -f "$control_ipa" ]] || usage
command -v ios-deploy >/dev/null || { echo "ios-deploy is required" >&2; exit 69; }
command -v idevice_id >/dev/null || { echo "idevice_id is required" >&2; exit 69; }
command -v idevicepair >/dev/null || { echo "idevicepair is required" >&2; exit 69; }
idevice_id -l | /usr/bin/grep -Fxq "$udid" || {
  echo "Selected device is not visible over USB" >&2; exit 69;
}
idevicepair -u "$udid" validate >/dev/null || {
  echo "Existing Apple pairing did not validate for the selected device" >&2; exit 69;
}

ios-deploy -i "$udid" -b "$link_ipa"
ios-deploy -i "$udid" -b "$control_ipa"
echo "Installed both signed apps on the exact selected device."
