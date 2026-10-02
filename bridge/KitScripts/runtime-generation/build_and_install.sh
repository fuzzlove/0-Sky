#!/bin/zsh
set -euo pipefail
WORK=${0:A:h}
PYTHON=${SRD_PYTHON:-$(command -v python3)}
[[ -n ${CRYPTEXCTL_UDID:-} ]] || { print -u2 'exact SRD UDID is required'; exit 1; }
[[ -n ${SRDSH_IDENTIFIER:-} && -d ${SRDSH_ROOT:-} ]] || { print -u2 'Cryptex identifier and payload are required'; exit 1; }
"$PYTHON" -c 'import sys; raise SystemExit(0 if sys.version_info >= (3,12) else 1)'
exec "$PYTHON" "$WORK/install_cryptex_native.py" --build-and-install
