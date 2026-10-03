#!/bin/sh
set -eu

UPSTREAM_URL=https://github.com/ren7995/Atria.git
UPSTREAM_COMMIT=f9668422b7f7143ac8d038feb05199fe4690d792
UPSTREAM_TREE=3f5a5818ed6573c87ae1b4871c4f230730d0fa48
UPSTREAM_ARCHIVE_SHA256=bbcb6929b4477990214c1e135b401354940b5eb9ab37c388469cff1e6f228842
THEOS_COMMIT=dd5c14bb9d91311e221d51b5bfb8c9e5948156db
SDK_VERSION=26.5
SOURCE_DATE_EPOCH=1687460877
PACKAGE_NAME=me.lau.atria_1.4.1+0sky27.3_iphoneos-arm64.deb

SCRIPT_DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
REPO_ROOT=$(git -C "$SCRIPT_DIR" rev-parse --show-toplevel)
BUILD_ROOT=${ATRIA_BUILD_ROOT:-"$REPO_ROOT/.build/atria-ios27"}
SOURCE_DIR="$BUILD_ROOT/source"
OUTPUT_DIR="$BUILD_ROOT/output"
THEOS=${THEOS:-"$REPO_ROOT/artifacts/compatibility/toolchains/theos"}
DRY_RUN=0

usage() {
    echo "usage: $0 [--dry-run] [--help]" >&2
}

while [ "$#" -gt 0 ]; do
    case "$1" in
        --dry-run) DRY_RUN=1 ;;
        --help|-h) usage; exit 0 ;;
        *) usage; exit 2 ;;
    esac
    shift
done

for tool in git make xcrun shasum dpkg-deb python3; do
    command -v "$tool" >/dev/null 2>&1 || {
        echo "error: required tool not found: $tool" >&2
        exit 1
    }
done

if [ ! -d "$THEOS/.git" ]; then
    echo "error: repository Theos checkout not found: $THEOS" >&2
    exit 1
fi

actual_theos=$(git -C "$THEOS" rev-parse HEAD)
[ "$actual_theos" = "$THEOS_COMMIT" ] || {
    echo "error: Theos commit $actual_theos; expected $THEOS_COMMIT" >&2
    exit 1
}

actual_sdk=$(xcrun --sdk iphoneos --show-sdk-version)
[ "$actual_sdk" = "$SDK_VERSION" ] || {
    echo "error: iPhoneOS SDK $actual_sdk; expected $SDK_VERSION" >&2
    exit 1
}

if [ "$DRY_RUN" -eq 1 ]; then
    cat <<EOF
Atria iOS 27 build preflight passed.
upstream: $UPSTREAM_URL
commit:   $UPSTREAM_COMMIT
tree:     $UPSTREAM_TREE
theos:    $THEOS_COMMIT
sdk:      $SDK_VERSION
work:     $BUILD_ROOT
output:   $OUTPUT_DIR/$PACKAGE_NAME
No source, build, package, device, or Git state was changed.
EOF
    exit 0
fi

mkdir -p "$BUILD_ROOT" "$OUTPUT_DIR"
if [ ! -d "$SOURCE_DIR/.git" ]; then
    git clone --no-checkout "$UPSTREAM_URL" "$SOURCE_DIR"
fi

git -C "$SOURCE_DIR" fetch --quiet origin "$UPSTREAM_COMMIT"
git -C "$SOURCE_DIR" checkout --quiet --detach "$UPSTREAM_COMMIT"
git -C "$SOURCE_DIR" reset --quiet --hard "$UPSTREAM_COMMIT"
git -C "$SOURCE_DIR" clean -q -fdx

actual_commit=$(git -C "$SOURCE_DIR" rev-parse HEAD)
actual_tree=$(git -C "$SOURCE_DIR" rev-parse 'HEAD^{tree}')
actual_archive=$(git -C "$SOURCE_DIR" archive --format=tar HEAD | shasum -a 256 | awk '{print $1}')
[ "$actual_commit" = "$UPSTREAM_COMMIT" ] || { echo "error: source commit mismatch" >&2; exit 1; }
[ "$actual_tree" = "$UPSTREAM_TREE" ] || { echo "error: source tree mismatch" >&2; exit 1; }
[ "$actual_archive" = "$UPSTREAM_ARCHIVE_SHA256" ] || { echo "error: source archive hash mismatch" >&2; exit 1; }

git -C "$SOURCE_DIR" apply --check "$SCRIPT_DIR/patches/0001-ios27-root-folder-controller.patch"
git -C "$SOURCE_DIR" apply "$SCRIPT_DIR/patches/0001-ios27-root-folder-controller.patch"
cp "$SCRIPT_DIR/files/Makefile" "$SOURCE_DIR/Makefile"
mkdir -p "$SOURCE_DIR/packaging" "$SOURCE_DIR/stubs/Preferences.framework" \
    "$SOURCE_DIR/Prefs/Resources"
cp "$SCRIPT_DIR/files/packaging/AtriaPrefs.plist" "$SOURCE_DIR/packaging/AtriaPrefs.plist"
cp "$SCRIPT_DIR/files/stubs/Preferences.framework/Preferences.tbd" "$SOURCE_DIR/stubs/Preferences.framework/Preferences.tbd"
cp "$SCRIPT_DIR/files/Prefs/Resources/Root.plist" "$SOURCE_DIR/Prefs/Resources/Root.plist"

export THEOS
export SOURCE_DATE_EPOCH
export ZERO_AR_DATE=1
export TZ=UTC
make -C "$SOURCE_DIR" clean package FINALPACKAGE=1
package="$SOURCE_DIR/packages/$PACKAGE_NAME"
[ -f "$package" ] || { echo "error: expected package was not built: $package" >&2; exit 1; }

# Theos' legacy dm.pl packager preserves the wall-clock build time in the ar
# and tar members. Normalize the already-built filesystem tree so identical
# source inputs produce an identical final DEB and hash.
NORMALIZED_DIR="$BUILD_ROOT/normalized-package"
NORMALIZED_PACKAGE="$BUILD_ROOT/$PACKAGE_NAME"
python3 - "$NORMALIZED_DIR" <<'PY'
from pathlib import Path
import shutil
import sys

path = Path(sys.argv[1])
if path.exists():
    shutil.rmtree(path)
path.mkdir(parents=True)
PY
dpkg-deb -R "$package" "$NORMALIZED_DIR" >/dev/null
python3 - "$NORMALIZED_DIR" "$SOURCE_DATE_EPOCH" <<'PY'
from pathlib import Path
import os
import sys

root = Path(sys.argv[1])
epoch = int(sys.argv[2])
for path in sorted(root.rglob("*")):
    try:
        os.utime(path, (epoch, epoch), follow_symlinks=False)
    except (FileNotFoundError, NotImplementedError):
        pass
os.utime(root, (epoch, epoch))
PY
dpkg-deb --root-owner-group --uniform-compression -Zgzip -z9 \
    --build "$NORMALIZED_DIR" "$NORMALIZED_PACKAGE" >/dev/null

python3 "$SCRIPT_DIR/validate_package.py" "$NORMALIZED_PACKAGE"
cp "$NORMALIZED_PACKAGE" "$OUTPUT_DIR/$PACKAGE_NAME"
echo "package: $OUTPUT_DIR/$PACKAGE_NAME"
shasum -a 256 "$OUTPUT_DIR/$PACKAGE_NAME"
