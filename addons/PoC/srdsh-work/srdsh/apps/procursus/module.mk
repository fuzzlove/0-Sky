PROCursus_APP_DIR := apps/procursus

CRYPTEX_CONTENTS += $(ROOT_DAEMON_DIR)/procursus-link.plist

$(ROOT_DAEMON_DIR)/procursus-link.plist: $(PROCursus_APP_DIR)/procursus-link.plist
	cp $< $@
