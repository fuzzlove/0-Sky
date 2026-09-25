#!/bin/zsh
# Compatibility entry point; select the exact SRD in the guided installer.
set -euo pipefail
root=${0:A:h}
exec /usr/bin/python3 "$root/bridge/macos_host_setup.py" --setup "$@"
