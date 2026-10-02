#!/bin/bash
set -euo pipefail
root=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
python=${ZERO_SKY_RELEASE_PYTHON:-$(command -v python3 || true)}
[[ -n "$python" && -x "$python" ]] || { echo "python3 is required" >&2; exit 2; }
exec "$python" "$root/tools/build_release.py" "$@"
