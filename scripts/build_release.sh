#!/bin/bash
set -euo pipefail
root=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
python=${ZERO_SKY_RELEASE_PYTHON:-$(command -v python3 || true)}
if [[ -z "$python" || ! -x "$python" ]]; then
  cat >&2 <<'EOF'
RELEASE_GATE=BLOCKED stage=PREREQUISITES error=PYTHON3_MISSING
Required action:
  1. Install Python 3 for macOS from https://www.python.org/downloads/macos/
     (choose the universal2 installer), or install it with: brew install python
  2. Open a new Terminal and verify: python3 --version
  3. Rerun this exact scripts/build_release.sh command.
The compiled 0-Sky application does not require this developer Python; it is
needed only to build a release from source.
EOF
  exit 2
fi
exec "$python" "$root/tools/build_release.py" "$@"
