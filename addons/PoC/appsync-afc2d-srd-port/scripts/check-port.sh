#!/bin/sh
set -eu

if [ "$#" -ne 4 ]; then
    echo "usage: $0 DPKG_DEB IOS_MIN APPSYNC_DEB AFC2D_DEB" >&2
    exit 64
fi

dpkg_deb=$1
ios_min=$2
appsync_deb=$3
afc2d_deb=$4
check_root=$(mktemp -d "${TMPDIR:-/tmp}/0sky-appsync-afc2d-check.XXXXXX")
trap 'rm -rf "$check_root"' EXIT HUP INT TERM

check_field() {
    package=$1
    field=$2
    expected=$3
    actual=$($dpkg_deb --field "$package" "$field" | sed -e "s/^$field: //")
    if [ "$actual" != "$expected" ]; then
        echo "$package: $field is '$actual', expected '$expected'" >&2
        exit 1
    fi
}

check_macho() {
    binary=$1
    archs=$(lipo -archs "$binary")
    if [ "$archs" != "arm64 arm64e" ]; then
        echo "$binary: unexpected architectures: $archs" >&2
        exit 1
    fi
    build=$(xcrun vtool -show-build "$binary")
    ios_count=$(printf '%s\n' "$build" | grep -c 'platform IOS')
    min_count=$(printf '%s\n' "$build" | grep -c "minos $ios_min")
    if [ "$ios_count" -ne 2 ] || [ "$min_count" -ne 2 ]; then
        echo "$binary: expected two iOS slices at minimum $ios_min" >&2
        printf '%s\n' "$build" >&2
        exit 1
    fi
    if ! codesign --verify --strict "$binary" 2>/dev/null; then
        echo "$binary: ad-hoc CodeDirectory verification failed" >&2
        exit 1
    fi
    # dyld on iOS 27 rejects injected images without LC_UUID.  Do not trade
    # loadability for a linker-level reproducibility shortcut.
    uuid_count=$(otool -arch all -l "$binary" | grep -c 'cmd LC_UUID')
    if [ "$uuid_count" -ne 2 ]; then
        echo "$binary: expected one LC_UUID in each architecture slice" >&2
        exit 1
    fi
    if otool -L "$binary" | grep -E '/(Users|Volumes)/' >/dev/null; then
        echo "$binary: host library path found" >&2
        exit 1
    fi
}

check_field "$appsync_deb" Package ai.akemi.appsyncunified
check_field "$appsync_deb" Architecture iphoneos-arm64
check_field "$appsync_deb" Version 116.0+0sky26.1
check_field "$afc2d_deb" Package com.cannathea.afc2d-arm64
check_field "$afc2d_deb" Architecture iphoneos-arm64
check_field "$afc2d_deb" Version 1.2.0+0sky27.5

$dpkg_deb --raw-extract "$appsync_deb" "$check_root/appsync"
$dpkg_deb --raw-extract "$afc2d_deb" "$check_root/afc2d"

if find "$check_root/appsync/DEBIAN" "$check_root/afc2d/DEBIAN" -type f \
        ! -name control -print | grep .; then
    echo "unexpected maintainer script or control member" >&2
    exit 1
fi

appsync_payload=$(find "$check_root/appsync/var/jb" -type f | sed "s|$check_root/appsync||" | sort)
expected_appsync='/var/jb/Library/MobileSubstrate/DynamicLibraries/AppSyncUnified-FrontBoard.dylib
/var/jb/Library/MobileSubstrate/DynamicLibraries/AppSyncUnified-FrontBoard.plist
/var/jb/Library/MobileSubstrate/DynamicLibraries/AppSyncUnified-installd.dylib
/var/jb/Library/MobileSubstrate/DynamicLibraries/AppSyncUnified-installd.plist'
if [ "$appsync_payload" != "$expected_appsync" ]; then
    echo "unexpected AppSync payload" >&2
    printf '%s\n' "$appsync_payload" >&2
    exit 1
fi

afc2d_payload=$(find "$check_root/afc2d/var/jb" -type f | sed "s|$check_root/afc2d||" | sort)
expected_afc2d='/var/jb/Library/MobileSubstrate/DynamicLibraries/afc2dService.dylib
/var/jb/Library/MobileSubstrate/DynamicLibraries/afc2dService.plist
/var/jb/usr/lib/afc2d-xpc-shim.dylib
/var/jb/usr/libexec/afc2d'
if [ "$afc2d_payload" != "$expected_afc2d" ]; then
    echo "unexpected AFC2D payload" >&2
    printf '%s\n' "$afc2d_payload" >&2
    exit 1
fi

for binary in \
    "$check_root/appsync/var/jb/Library/MobileSubstrate/DynamicLibraries/AppSyncUnified-FrontBoard.dylib" \
    "$check_root/appsync/var/jb/Library/MobileSubstrate/DynamicLibraries/AppSyncUnified-installd.dylib" \
    "$check_root/afc2d/var/jb/Library/MobileSubstrate/DynamicLibraries/afc2dService.dylib" \
    "$check_root/afc2d/var/jb/usr/lib/afc2d-xpc-shim.dylib"
do
    check_macho "$binary"
done

afc2d_helper="$check_root/afc2d/var/jb/usr/libexec/afc2d"
if [ "$(lipo -archs "$afc2d_helper")" != "arm64e" ]; then
    echo "AFC2D helper is not the exact arm64e system derivative" >&2
    exit 1
fi
if ! xcrun vtool -show-build "$afc2d_helper" | grep -F 'minos 27.0' >/dev/null; then
    echo "AFC2D helper is not built for the target iOS 27 runtime" >&2
    exit 1
fi
if ! codesign --verify --strict "$afc2d_helper" 2>/dev/null; then
    echo "AFC2D helper CodeDirectory verification failed" >&2
    exit 1
fi
if strings -a "$afc2d_helper" | grep -F '/private/var/mobile/Media' >/dev/null; then
    echo "AFC2D helper retains the jailed media root" >&2
    exit 1
fi
if ! otool -L "$afc2d_helper" | grep -F '/var/jb/usr/lib/afc2d-xpc-shim.dylib' >/dev/null; then
    echo "AFC2D helper does not load its lockdownd service-name shim" >&2
    exit 1
fi
if ! otool -l "$check_root/afc2d/var/jb/usr/lib/afc2d-xpc-shim.dylib" \
        | grep -F 'LC_REEXPORT_DYLIB' >/dev/null; then
    echo "AFC2D shim does not re-export CoreFoundation" >&2
    exit 1
fi

if strings -a "$check_root/afc2d/var/jb/Library/MobileSubstrate/DynamicLibraries/afc2dService.dylib" \
        | grep -E 'appldnld|iOS7/' >/dev/null; then
    echo "AFC2D retains the legacy network downloader" >&2
    exit 1
fi
if ! strings -a "$check_root/afc2d/var/jb/Library/MobileSubstrate/DynamicLibraries/afc2dService.dylib" \
        | grep -F '/usr/libexec/afc2d' >/dev/null; then
    echo "AFC2D does not reference its rootless iOS 27 helper" >&2
    exit 1
fi

afc2d_dylib="$check_root/afc2d/var/jb/Library/MobileSubstrate/DynamicLibraries/afc2dService.dylib"
afc2d_links=$(otool -L "$afc2d_dylib")
if printf '%s\n' "$afc2d_links" \
        | grep -F '@rpath/CydiaSubstrate.framework/CydiaSubstrate' >/dev/null; then
    echo "AFC2D retains the inaccessible CydiaSubstrate dependency" >&2
    exit 1
fi
if nm -u "$afc2d_dylib" | grep -E '_MSHookFunction|_CFPropertyListCreateWithData' >/dev/null; then
    echo "AFC2D retains an executable-page hook dependency" >&2
    exit 1
fi

plutil -lint \
    "$check_root/appsync/var/jb/Library/MobileSubstrate/DynamicLibraries/AppSyncUnified-FrontBoard.plist" \
    "$check_root/appsync/var/jb/Library/MobileSubstrate/DynamicLibraries/AppSyncUnified-installd.plist" \
    "$check_root/afc2d/var/jb/Library/MobileSubstrate/DynamicLibraries/afc2dService.plist" >/dev/null

shasum -a 256 "$appsync_deb" "$afc2d_deb"
echo "Host-side package checks passed; see VALIDATION.md for device results."
