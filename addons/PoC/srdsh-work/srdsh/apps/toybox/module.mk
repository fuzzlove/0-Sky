TOYBOX_APP_DIR		:= apps/toybox
TOYBOX_SRC_DIR		:= vendor/toybox

TOYBOX_BIN		:= $(TOYBOX_SRC_DIR)/toybox
TOYBOX_CONFIG		:= $(TOYBOX_SRC_DIR)/.config
TOYBOX_PREBUILT		:= prebuilt/toybox-arm64e

TOYBOX_HOSTCC		:= $(HOSTCC) $(HOSTCFLAGS)
TOYBOX_MAKE_FLAGS	:= HOSTCC="$(TOYBOX_HOSTCC)" CC="$(CC)" CFLAGS="$(CFLAGS)" \
				LDFLAGS="$(LDFLAGS)" ARCH="$(ARCH)"

$(TOYBOX_SRC_DIR)/instlist: $(TOYBOX_BIN) $(TOYBOX_CONFIG)
	@$(call log_info, "Preparing toybox installation...")
	$(HOSTCC) $(HOSTCFLAGS) -I $(TOYBOX_SRC_DIR) $(TOYBOX_SRC_DIR)/scripts/install.c -o $@ || exit 1

$(TOYBOX_CONFIG):
	@$(call log_info, "Freezing toybox configuration...")
	@env -vi PATH="$(PATH)" $(MAKE) -C $(TOYBOX_SRC_DIR) macos_defconfig HOSTCC="$(TOYBOX_HOSTCC)" $(HUSH)

# Prefer the reviewed arm64e binary.  It targets iOS 17 and avoids rebuilding
# Toybox against a newer host SDK whose private header surface may have moved.
# The source build remains available when preparing a replacement prebuilt.
ifneq ($(wildcard $(TOYBOX_PREBUILT)),)
$(TOYBOX_BIN): $(TOYBOX_PREBUILT) $(TOYBOX_CONFIG)
	@$(call log_info, "Generating Toybox install metadata...")
	$(MAKE) -C $(TOYBOX_SRC_DIR) toybox $(TOYBOX_MAKE_FLAGS) NOBUILD=1 $(HUSH)
	@$(call log_info, "Installing reviewed Toybox arm64e binary...")
	cp $(TOYBOX_PREBUILT) $@
	chmod 775 $@
	codesign --verify --strict $@
else
# Toybox needs `sys/disk.h` to build.
$(TOYBOX_BIN): $(GRAFT_INCLUDE_DIR)/sys/disk.h $(TOYBOX_CONFIG)
	@$(call log_info, "Building main toybox binary...")
	$(MAKE) -C $(TOYBOX_SRC_DIR) toybox $(TOYBOX_MAKE_FLAGS) $(HUSH)

	codesign -s - --entitlements $(TOYBOX_APP_DIR)/entitlements.plist $(TOYBOX_BIN)
	chmod 775 $(TOYBOX_BIN)
endif

# ===------------------------------------------------------------------------===

CRYPTEX_CONTENTS	+= $(ROOT_BIN_DIR)/toybox

$(ROOT_BIN_DIR)/toybox: $(TOYBOX_SRC_DIR)/instlist
	@$(call log_info, "Creating toybox app links...")
	$(MAKE) -C $(TOYBOX_SRC_DIR) install_flat $(TOYBOX_MAKE_FLAGS) PREFIX="$(ROOT_BIN_DIR)" $(HUSH)

	cp $(TOYBOX_BIN) $@

# ===------------------------------------------------------------------------===

.PHONY: toybox-clean
toybox-clean:
	$(MAKE) -C $(TOYBOX_SRC_DIR) clean $(HUSH)
	rm -f $(TOYBOX_CONFIG)

clean: toybox-clean
