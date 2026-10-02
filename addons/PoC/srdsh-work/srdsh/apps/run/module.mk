CRYPTEX_CONTENTS	+= $(ROOT_BIN_DIR)/cryptex-run

# Create the graft include tree before the first target compilation. This
# prevents a harmless-but-confusing missing search-path warning on clean builds.
$(ROOT_BIN_DIR)/cryptex-run: apps/run/run.c | $(GRAFT_INCLUDE_DIR)/sys/disk.h
	@$(call log, "Building cryptex binary runner...")

	$(CC) $(CFLAGS) $(LDFLAGS) $< -o $@
	codesign -s - --entitlements apps/run/entitlements.plist $@

# A "clean" target is not necessary for this module since the output lives
# directly in the build directory.
