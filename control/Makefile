SHELL := /bin/zsh
.DEFAULT_GOAL := control

# Callers may supply a package-manager-independent prefix.  Homebrew is only a
# source-build discovery fallback and is never consulted by the compiled app.
LIBARCHIVE_PREFIX ?= $(shell pkg-config --variable=prefix libarchive 2>/dev/null || command -v brew >/dev/null && brew --prefix libarchive 2>/dev/null)

.PHONY: preflight control test clean

preflight:
	@test -n "$(THEOS)" || (echo "THEOS must point to a Theos installation" >&2; exit 2)
	@test -f "$(THEOS)/makefiles/common.mk" || (echo "THEOS does not contain makefiles/common.mk" >&2; exit 2)
	@command -v xcrun >/dev/null
	@command -v ldid >/dev/null
	@command -v pkg-config >/dev/null
	@pkg-config --exists openssl || (echo "pkg-config cannot resolve openssl" >&2; exit 2)
	@test -f "$(LIBARCHIVE_PREFIX)/include/archive.h" || (echo "Set LIBARCHIVE_PREFIX to a libarchive development prefix" >&2; exit 2)

control: preflight
	@$(MAKE) -C RootHelper DEBUG=0 TROLLSTORE_LITE=1 LIBARCHIVE_PREFIX="$(LIBARCHIVE_PREFIX)" clean
	@$(MAKE) -C RootHelper DEBUG=0 TROLLSTORE_LITE=1 LIBARCHIVE_PREFIX="$(LIBARCHIVE_PREFIX)"
	@rm -f TrollStoreLite/Resources/trollstorehelper
	@cp RootHelper/.theos/obj/trollstorehelper_lite TrollStoreLite/Resources/trollstorehelper
	@$(MAKE) -C TrollStoreLite package FINALPACKAGE=1 THEOS_PACKAGE_SCHEME=rootless LIBARCHIVE_PREFIX="$(LIBARCHIVE_PREFIX)"
	@echo "0-Sky Control package: TrollStoreLite/packages/"

test:
	@python3 TrollStoreLite/tests/test_device_compatibility.py

clean:
	@$(MAKE) -C RootHelper TROLLSTORE_LITE=1 clean || true
	@$(MAKE) -C TrollStoreLite clean || true
	@rm -f TrollStoreLite/Resources/trollstorehelper
