# Prevent any included targets from becoming the default target.
.PHONY: all
all:

PROJECT_PATH 	?= $(realpath $(dir $(firstword $(MAKEFILE_LIST))))
BUILD_DIR 	?= $(abspath $(PROJECT_PATH)/build)

include mk/toolchain.mk
include mk/graft.mk
include mk/log.mk

CRYPTEX_ID	?= com.liquidsky.srdssh
CRYPTEX_VERSION	?= 1.0.0

CRYPTEX		?= $(BUILD_DIR)/$(CRYPTEX_ID).cptx
CRYPTEX_ROOT	?= $(BUILD_DIR)/$(CRYPTEX_ID).root
CRYPTEX_IMAGE	?= $(BUILD_DIR)/$(CRYPTEX_ID).dmg

ROOT_DAEMON_DIR	:= $(CRYPTEX_ROOT)/Library/LaunchDaemons
ROOT_AGENT_DIR	:= $(CRYPTEX_ROOT)/Library/LaunchAgents
ROOT_BIN_DIR	:= $(CRYPTEX_ROOT)/usr/bin

all: $(CRYPTEX)

CRYPTEX_CONTENTS	:=

# Keep the reproducible image deliberately small: Dropbear plus the tools and
# early-boot Procursus link it needs.  Experimental Sileo/Frida/debugserver
# modules are not part of this PoC.
SRDSH_MODULES ?= run toybox dropbear procursus
include $(foreach module,$(SRDSH_MODULES),apps/$(module)/module.mk)

$(CRYPTEX_ROOT):
	@$(call log_info, "Creating cryptex root...")
	mkdir -p $(ROOT_DAEMON_DIR)
	mkdir -p $(ROOT_AGENT_DIR)
	mkdir -p $(ROOT_BIN_DIR)

$(CRYPTEX_CONTENTS): $(CRYPTEX_ROOT)

$(CRYPTEX_IMAGE): $(CRYPTEX_CONTENTS)
	@$(call log, "Creating cryptex disk image...")
	@rm -fr $@
	hdiutil create -fs hfs+ -srcfolder $(CRYPTEX_ROOT) $@ $(HUSH)

$(CRYPTEX): $(CRYPTEX_IMAGE)
	@$(call log, "Creating/signing cryptex with CryptexManager...")
	rm -rf $(CRYPTEX)
	CryptexManager -u $(CRYPTEXCTL_UDID) create \
		-i $(CRYPTEX_ID) -v $(CRYPTEX_VERSION) \
		$(CRYPTEX_IMAGE) $(CRYPTEX_ROOT) $(CRYPTEX)

.PHONY: install
install: $(CRYPTEX)
	@$(call log, "Installing cryptex on device with CryptexManager...")
	CryptexManager -u $(CRYPTEXCTL_UDID) uninstall $(CRYPTEX_ID) $(HUSH) || true
	CryptexManager -u $(CRYPTEXCTL_UDID) install $(CRYPTEX)
	CryptexManager -u $(CRYPTEXCTL_UDID) list

.PHONY: clean
clean:
	rm -fr $(BUILD_DIR)
