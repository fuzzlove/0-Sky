SHELL := /bin/sh

ROOT := $(abspath ../../..)
THEOS ?= $(ROOT)/artifacts/compatibility/toolchains/theos
DPKG_DEB ?= $(shell command -v dpkg-deb 2>/dev/null)
CURL ?= $(shell command -v curl 2>/dev/null)

IOS_SDK_VERSION ?= 26.5
IOS_MIN_VERSION ?= 26.0
ARCHS ?= arm64 arm64e

DOWNLOAD_DIR := $(CURDIR)/downloads
BUILD_DIR := $(CURDIR)/build
DIST_DIR := $(CURDIR)/dist
REJECTED_DIR := $(CURDIR)/rejected

APPSYNC_COMMIT := 235aca6cddfbdc9fa87fcb5b2aec2df37ed6d65a
APPSYNC_ARCHIVE := $(DOWNLOAD_DIR)/appsync-$(APPSYNC_COMMIT).tar.gz
APPSYNC_URL := https://github.com/akemin-dayo/AppSync/archive/$(APPSYNC_COMMIT).tar.gz
APPSYNC_SHA256 := f816f6e63dc2f8852855f4bce3e047487a2876f92484ae1fc90caf9dd6eea1e7
APPSYNC_SOURCE := $(BUILD_DIR)/appsync
APPSYNC_DEB := $(APPSYNC_SOURCE)/debs/ai.akemi.appsyncunified_116.0+0sky26.1_iphoneos-arm64.deb
APPSYNC_DIST := $(DIST_DIR)/ai.akemi.appsyncunified_116.0+0sky26.1_iphoneos-arm64.deb

AFC2D_COMMIT := 7587154c9eed60636fe9d8d2ca0b286b59177b0a
AFC2D_ARCHIVE := $(DOWNLOAD_DIR)/afc2d-$(AFC2D_COMMIT).tar.gz
AFC2D_URL := https://github.com/Cannathea/afc2d-arm64/archive/$(AFC2D_COMMIT).tar.gz
AFC2D_SHA256 := 92b804570960798f82a42beffa430d55cb1271b5e87f68272d3881ad5d33e80a
AFC2D_SOURCE := $(BUILD_DIR)/afc2d
AFC2D_SYSTEM_AFCD := $(CURDIR)/inputs/afcd-iPhone13,2-24A5390f
AFC2D_HELPER := $(AFC2D_SOURCE)/layout/usr/libexec/afc2d
AFC2D_SHIM_SOURCE := $(CURDIR)/helpers/afc2d-xpc-shim.c
AFC2D_SHIM := $(AFC2D_SOURCE)/layout/usr/lib/afc2d-xpc-shim.dylib
AFC2D_DEB := $(AFC2D_SOURCE)/packages/com.cannathea.afc2d-arm64_1.2.0+0sky27.5_iphoneos-arm64.deb
AFC2D_DIST := $(DIST_DIR)/com.cannathea.afc2d-arm64_1.2.0+0sky27.5_iphoneos-arm64.deb

.PHONY: all download source patch build package check clean distclean

all: check

download: $(APPSYNC_ARCHIVE) $(AFC2D_ARCHIVE)

$(DOWNLOAD_DIR):
	mkdir -p "$@"

$(APPSYNC_ARCHIVE): | $(DOWNLOAD_DIR)
	test -n "$(CURL)"
	$(CURL) -fL --retry 3 -o "$@.tmp" "$(APPSYNC_URL)"
	printf '%s  %s\n' "$(APPSYNC_SHA256)" "$@.tmp" | shasum -a 256 -c -
	mv "$@.tmp" "$@"

$(AFC2D_ARCHIVE): | $(DOWNLOAD_DIR)
	test -n "$(CURL)"
	$(CURL) -fL --retry 3 -o "$@.tmp" "$(AFC2D_URL)"
	printf '%s  %s\n' "$(AFC2D_SHA256)" "$@.tmp" | shasum -a 256 -c -
	mv "$@.tmp" "$@"

source: $(APPSYNC_SOURCE)/.source $(AFC2D_SOURCE)/.source

$(APPSYNC_SOURCE)/.source: $(APPSYNC_ARCHIVE)
	mkdir -p "$(BUILD_DIR)"
	rm -rf "$(APPSYNC_SOURCE)" "$(BUILD_DIR)/AppSync-$(APPSYNC_COMMIT)"
	tar -xzf "$<" -C "$(BUILD_DIR)"
	mv "$(BUILD_DIR)/AppSync-$(APPSYNC_COMMIT)" "$(APPSYNC_SOURCE)"
	touch "$@"

$(AFC2D_SOURCE)/.source: $(AFC2D_ARCHIVE)
	mkdir -p "$(BUILD_DIR)"
	rm -rf "$(AFC2D_SOURCE)" "$(BUILD_DIR)/afc2d-arm64-$(AFC2D_COMMIT)"
	tar -xzf "$<" -C "$(BUILD_DIR)"
	mv "$(BUILD_DIR)/afc2d-arm64-$(AFC2D_COMMIT)" "$(AFC2D_SOURCE)"
	touch "$@"

patch: $(APPSYNC_SOURCE)/.patched $(AFC2D_SOURCE)/.patched

$(APPSYNC_SOURCE)/.patched: $(APPSYNC_SOURCE)/.source patches/appsync/0001-0sky-ios26-rootless.patch
	cd "$(APPSYNC_SOURCE)" && patch --batch --remove-empty-files -p1 < "$(CURDIR)/patches/appsync/0001-0sky-ios26-rootless.patch"
	touch "$@"

$(AFC2D_SOURCE)/.patched: $(AFC2D_SOURCE)/.source patches/afc2d/0001-0sky-ios26-system-afcd.patch
	cd "$(AFC2D_SOURCE)" && patch --batch --remove-empty-files -p1 < "$(CURDIR)/patches/afc2d/0001-0sky-ios26-system-afcd.patch"
	touch "$@"

build: $(APPSYNC_DEB) $(AFC2D_DEB)

$(APPSYNC_DEB): $(APPSYNC_SOURCE)/.patched
	test -d "$(THEOS)"
	$(MAKE) -C "$(APPSYNC_SOURCE)" clean package \
		THEOS="$(THEOS)" THEOS_PACKAGE_SCHEME=rootless FINALPACKAGE=1 \
		ARCHS="$(ARCHS)" TARGET="iphone:clang:$(IOS_SDK_VERSION):$(IOS_MIN_VERSION)" \
		TARGET_CODESIGN=/usr/bin/codesign TARGET_CODESIGN_FLAGS="--force --sign -"

$(AFC2D_SOURCE)/.helper: $(AFC2D_SOURCE)/.patched $(AFC2D_SYSTEM_AFCD) scripts/build-afc2d-helper.py patches/afc2d/afcd-entitlements.plist $(AFC2D_SHIM_SOURCE) $(CURDIR)/Makefile
	./scripts/build-afc2d-helper.py "$(AFC2D_SYSTEM_AFCD)" "$(AFC2D_HELPER)"
	mkdir -p "$(dir $(AFC2D_SHIM))"
	SDK="$$(xcrun --sdk iphoneos --show-sdk-path)"; \
	CLANG="$$(xcrun --sdk iphoneos --find clang)"; \
	"$$CLANG" -arch arm64 -isysroot "$$SDK" -miphoneos-version-min=$(IOS_MIN_VERSION) -Os -dynamiclib \
		-Wl,-install_name,/var/jb/usr/lib/afc2d-xpc-shim.dylib -Wl,-reexport_framework,CoreFoundation \
		"$(AFC2D_SHIM_SOURCE)" -o "$(AFC2D_SOURCE)/.afc2d-xpc-shim.arm64"; \
	"$$CLANG" -arch arm64e -isysroot "$$SDK" -miphoneos-version-min=$(IOS_MIN_VERSION) -Os -dynamiclib \
		-Wl,-install_name,/var/jb/usr/lib/afc2d-xpc-shim.dylib -Wl,-reexport_framework,CoreFoundation \
		"$(AFC2D_SHIM_SOURCE)" -o "$(AFC2D_SOURCE)/.afc2d-xpc-shim.arm64e"
	lipo -create "$(AFC2D_SOURCE)/.afc2d-xpc-shim.arm64" \
		"$(AFC2D_SOURCE)/.afc2d-xpc-shim.arm64e" -output "$(AFC2D_SHIM)"
	/usr/bin/codesign --force --sign - --timestamp=none --identifier ai.akemi.afc2d-xpc-shim "$(AFC2D_SHIM)"
	install_name_tool -change /System/Library/Frameworks/CoreFoundation.framework/CoreFoundation \
		/var/jb/usr/lib/afc2d-xpc-shim.dylib "$(AFC2D_HELPER)"
	rm -f "$(AFC2D_HELPER).orig"
	/usr/bin/codesign --force --sign - --timestamp=none \
		--entitlements "$(CURDIR)/patches/afc2d/afcd-entitlements.plist" "$(AFC2D_HELPER)"
	/usr/bin/codesign --verify --strict "$(AFC2D_SHIM)"
	/usr/bin/codesign --verify --strict "$(AFC2D_HELPER)"
	touch "$@"

$(AFC2D_DEB): $(AFC2D_SOURCE)/.helper
	test -d "$(THEOS)"
	$(MAKE) -C "$(AFC2D_SOURCE)" clean package \
		THEOS="$(THEOS)" THEOS_PACKAGE_SCHEME=rootless FINALPACKAGE=1 \
		ARCHS="$(ARCHS)" TARGET="iphone:clang:$(IOS_SDK_VERSION):$(IOS_MIN_VERSION)" \
		TARGET_CODESIGN=/usr/bin/codesign TARGET_CODESIGN_FLAGS="--force --sign -"

package: $(APPSYNC_DIST) $(AFC2D_DIST)

$(DIST_DIR):
	mkdir -p "$@"

$(REJECTED_DIR):
	mkdir -p "$@"

$(APPSYNC_DIST): $(APPSYNC_DEB) | $(DIST_DIR)
	cp "$<" "$@"

$(AFC2D_DIST): $(AFC2D_DEB) | $(REJECTED_DIR)
	cp "$<" "$@"

check: package
	test -n "$(DPKG_DEB)"
	./scripts/check-port.sh "$(DPKG_DEB)" "$(IOS_MIN_VERSION)" "$(APPSYNC_DIST)" "$(AFC2D_DIST)"

clean:
	rm -rf "$(BUILD_DIR)" "$(DIST_DIR)"

distclean: clean
	rm -rf "$(DOWNLOAD_DIR)"
