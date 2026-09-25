#!/bin/bash
# Compatibility entry point; the project has one exact-device Mac installer.
set -euo pipefail
root=$(cd "$(dirname "$0")" && pwd)
exec /usr/bin/python3 "$root/bridge/macos_host_setup.py" --setup "$@"
