DROPBEAR_APP_DIR	:= apps/dropbear
DROPBEAR_SRC_DIR	:= vendor/dropbear

DROPBEAR_BIN		:= $(DROPBEAR_SRC_DIR)/dropbear
DROPBEAR_KEY_BIN	:= $(DROPBEAR_SRC_DIR)/dropbearkey
DROPBEAR_CONFIG_H	:= $(DROPBEAR_SRC_DIR)/config.h
DROPBEAR_START		:= $(DROPBEAR_APP_DIR)/start.sh
SRDSH_AUTHORIZED_KEY	?= $(HOME)/.ssh/srdsh_ed25519.pub
ROOT_ETC_DIR		:= $(CRYPTEX_ROOT)/etc

DROPBEAR_CONFIG_FLAGS	:= --host arm-apple-darwin --disable-utmpx --disable-utmp \
				--disable-wtmp --disable-wtmpx --disable-zlib \
				--disable-pam --enable-bundled-libtom

# ===------------------------------------------------------------------------===

$(DROPBEAR_CONFIG_H):
	@$(call log_info, "Configuring Dropbear build...")

	cd $(DROPBEAR_SRC_DIR) && autoreconf $(HUSH)
	cd $(DROPBEAR_SRC_DIR) && ./configure $(DROPBEAR_CONFIG_FLAGS) $(HUSH)

$(DROPBEAR_BIN): $(DROPBEAR_CONFIG_H)
	@$(call log, "Building Dropbear...")

	$(MAKE) --quiet -C $(DROPBEAR_SRC_DIR) dropbear $(HUSH)

$(DROPBEAR_KEY_BIN): $(DROPBEAR_CONFIG_H)
	@$(call log, "Building Dropbear key utility...")

	$(MAKE) --quiet -C $(DROPBEAR_SRC_DIR) dropbearkey $(HUSH)

# ===------------------------------------------------------------------------===

CRYPTEX_CONTENTS	+= $(ROOT_BIN_DIR)/dropbear $(ROOT_BIN_DIR)/dropbearkey \
	$(ROOT_BIN_DIR)/srdsh-dropbear-start $(ROOT_ETC_DIR)/srdsh_authorized_key \
	$(ROOT_DAEMON_DIR)/dropbear.plist

$(ROOT_BIN_DIR)/dropbear: $(DROPBEAR_BIN)
	codesign -s - --entitlements $(DROPBEAR_APP_DIR)/entitlements.plist $(DROPBEAR_BIN)
	chmod 775 $(DROPBEAR_BIN)
	cp $(DROPBEAR_BIN) $@

$(ROOT_BIN_DIR)/dropbearkey: $(DROPBEAR_KEY_BIN)
	codesign -s - --entitlements $(DROPBEAR_APP_DIR)/entitlements.plist $(DROPBEAR_KEY_BIN)
	chmod 775 $(DROPBEAR_KEY_BIN)
	cp $(DROPBEAR_KEY_BIN) $@

$(ROOT_BIN_DIR)/srdsh-dropbear-start: $(DROPBEAR_START)
	cp $< $@
	chmod 755 $@

$(ROOT_ETC_DIR)/srdsh_authorized_key: $(SRDSH_AUTHORIZED_KEY)
	@grep -Eq '^(ssh-ed25519|ecdsa-sha2-|sk-ssh-|ssh-rsa )' $< || \
		(echo "invalid SSH public key: $<" >&2; exit 1)
	mkdir -p $(ROOT_ETC_DIR)
	awk 'NF { print; exit }' $< > $@
	chmod 644 $@

$(ROOT_DAEMON_DIR)/dropbear.plist: $(DROPBEAR_APP_DIR)/dropbear.plist
	cp $< $@

# ===------------------------------------------------------------------------===

.PHONY: dropbear-clean
dropbear-clean:
	$(MAKE) -C $(DROPBEAR_SRC_DIR) clean $(HUSH)
	rm -f $(DROPBEAR_CONFIG_H)

clean: dropbear-clean
