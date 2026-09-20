SHELL := /bin/zsh
.DEFAULT_GOAL := control

.PHONY: preflight control test clean

preflight:
	@test -n "$(THEOS)" || (echo "THEOS must point to a Theos installation" >&2; exit 2)
	@command -v xcrun >/dev/null
	@command -v ldid >/dev/null
	@command -v pkg-config >/dev/null
	@command -v brew >/dev/null
	@test -d "$$(brew --prefix libarchive)"
	@test -d "$$(brew --prefix openssl@3)"

control: preflight
	@$(MAKE) -C RootHelper DEBUG=0 TROLLSTORE_LITE=1 clean
	@$(MAKE) -C RootHelper DEBUG=0 TROLLSTORE_LITE=1
	@rm -f TrollStoreLite/Resources/trollstorehelper
	@cp RootHelper/.theos/obj/trollstorehelper_lite TrollStoreLite/Resources/trollstorehelper
	@$(MAKE) -C TrollStoreLite package FINALPACKAGE=1 THEOS_PACKAGE_SCHEME=rootless
	@echo "0-Sky Control package: TrollStoreLite/packages/"

test:
	@python3 TrollStoreLite/tests/test_device_compatibility.py

clean:
	@$(MAKE) -C RootHelper TROLLSTORE_LITE=1 clean || true
	@$(MAKE) -C TrollStoreLite clean || true
	@rm -f TrollStoreLite/Resources/trollstorehelper
