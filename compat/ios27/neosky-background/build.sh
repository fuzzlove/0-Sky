#!/bin/sh
set -eu

THEOS_COMMIT=dd5c14bb9d91311e221d51b5bfb8c9e5948156db
SDK_VERSION=26.5
SOURCE_DATE_EPOCH=1791064800
PACKAGE_NAME=xyz.0sky.neoskybackground_1.0.0+0sky27.2_iphoneos-arm64.deb

SCRIPT_DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
REPO_ROOT=$(git -C "$SCRIPT_DIR" rev-parse --show-toplevel)
BUILD_ROOT=${NEOSKY_BUILD_ROOT:-"$REPO_ROOT/.build/neosky-background-ios27"}
SOURCE_DIR="$BUILD_ROOT/source"
OUTPUT_DIR="$BUILD_ROOT/output"
THEOS=${THEOS:-"$REPO_ROOT/artifacts/compatibility/toolchains/theos"}
DRY_RUN=0

usage() { echo "usage: $0 [--dry-run] [--help]" >&2; }
while [ "$#" -gt 0 ]; do
    case "$1" in
        --dry-run) DRY_RUN=1 ;;
        --help|-h) usage; exit 0 ;;
        *) usage; exit 2 ;;
    esac
    shift
done

for tool in git make xcrun shasum dpkg-deb python3 ldid; do
    command -v "$tool" >/dev/null 2>&1 || { echo "error: missing $tool" >&2; exit 1; }
done
[ -d "$THEOS/.git" ] || { echo "error: Theos checkout not found: $THEOS" >&2; exit 1; }
[ "$(git -C "$THEOS" rev-parse HEAD)" = "$THEOS_COMMIT" ] || {
    echo "error: unexpected Theos revision" >&2; exit 1;
}
[ "$(xcrun --sdk iphoneos --show-sdk-version)" = "$SDK_VERSION" ] || {
    echo "error: expected iPhoneOS SDK $SDK_VERSION" >&2; exit 1;
}

if [ "$DRY_RUN" -eq 1 ]; then
    printf 'NeoSky Background build preflight passed.\noutput: %s\n' "$OUTPUT_DIR/$PACKAGE_NAME"
    exit 0
fi

rm -rf "$SOURCE_DIR"
mkdir -p "$SOURCE_DIR" "$OUTPUT_DIR"
cp -R "$SCRIPT_DIR/files/." "$SOURCE_DIR/"
export THEOS SOURCE_DATE_EPOCH ZERO_AR_DATE=1 TZ=UTC
make -C "$SOURCE_DIR" clean package FINALPACKAGE=1
package="$SOURCE_DIR/packages/$PACKAGE_NAME"
[ -f "$package" ] || { echo "error: package not built: $package" >&2; exit 1; }

NORMALIZED_DIR="$BUILD_ROOT/normalized-package"
NORMALIZED_PACKAGE="$BUILD_ROOT/$PACKAGE_NAME"
rm -rf "$NORMALIZED_DIR"
dpkg-deb -R "$package" "$NORMALIZED_DIR" >/dev/null
python3 - "$NORMALIZED_DIR" "$SOURCE_DATE_EPOCH" <<'PY'
from pathlib import Path
import os, sys
root = Path(sys.argv[1]); epoch = int(sys.argv[2])
for path in sorted(root.rglob('*')):
    try: os.utime(path, (epoch, epoch), follow_symlinks=False)
    except (FileNotFoundError, NotImplementedError): pass
os.utime(root, (epoch, epoch))
PY
dpkg-deb --root-owner-group --uniform-compression -Zgzip -z9 --build \
    "$NORMALIZED_DIR" "$NORMALIZED_PACKAGE" >/dev/null
python3 "$SCRIPT_DIR/validate_package.py" "$NORMALIZED_PACKAGE"
cp "$NORMALIZED_PACKAGE" "$OUTPUT_DIR/$PACKAGE_NAME"
echo "package: $OUTPUT_DIR/$PACKAGE_NAME"
shasum -a 256 "$OUTPUT_DIR/$PACKAGE_NAME"
