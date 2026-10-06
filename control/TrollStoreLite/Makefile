TARGET := iphone:clang:latest:14.0
INSTALL_TARGET_PROCESSES = CrypStore
ARCHS = arm64

include $(THEOS)/makefiles/common.mk

APPLICATION_NAME = CrypStore

CrypStore_FILES = $(wildcard ../TrollStore/*.m) $(wildcard ../Shared/*.m)
CrypStore_FRAMEWORKS = UIKit CoreGraphics CoreServices CoreTelephony CoreBluetooth Security
CrypStore_PRIVATE_FRAMEWORKS = Preferences MobileIcons MobileContainerManager
CrypStore_LIBRARIES = archive
CrypStore_CFLAGS = -fobjc-arc -I../Shared -I$(LIBARCHIVE_PREFIX)/include -DTROLLSTORE_LITE
CrypStore_LDFLAGS = -F../build-stubs -Wl,-rpath,@executable_path/Frameworks -Wl,-rpath,/var/jb/usr/lib
CrypStore_CODESIGN_FLAGS = -Sentitlements.plist

include $(THEOS_MAKE_PATH)/application.mk

# The paired-Mac Control installer preserves entitlements from signatures that
# Apple's codesign tooling can validate.  Theos' default ldid output is valid
# on-device but is not readable by that host-side preservation step, which can
# silently strip the private Settings/LaunchServices permissions.  Seal the
# staged main executable with the reviewed entitlement file before packaging.
after-CrypStore-stage::
	@/usr/bin/codesign --force --sign - --timestamp=none \
		--generate-entitlement-der --identifier com.liquidsky.CrypStore \
		--entitlements entitlements.plist \
		"$(THEOS_STAGING_DIR)/Applications/CrypStore.app/CrypStore"
	@/usr/bin/codesign --verify --strict \
		"$(THEOS_STAGING_DIR)/Applications/CrypStore.app/CrypStore"

# A paid Crane license is never committed or bundled in ordinary releases.
# An authorized private build may point CRANE_RUNTIME_DIR at an isolated
# extraction containing the exact installed Crane and dependency artifacts.
ifneq ($(strip $(CRANE_RUNTIME_DIR)),)
after-CrypStore-stage::
	@test -f "$(CRANE_RUNTIME_DIR)/libcrane.dylib"
	@test -f "$(CRANE_RUNTIME_DIR)/libsandy.dylib"
	@test -f "$(CRANE_RUNTIME_DIR)/libellekit.dylib"
	@test -f "$(CRANE_RUNTIME_DIR)/AltList.framework/AltList"
	@test -f "$(CRANE_RUNTIME_DIR)/CranePrefs.bundle/CranePrefs"
	@mkdir -p "$(THEOS_STAGING_DIR)/Applications/CrypStore.app/Frameworks"
	@cp "$(CRANE_RUNTIME_DIR)/libcrane.dylib" "$(THEOS_STAGING_DIR)/Applications/CrypStore.app/Frameworks/"
	@cp "$(CRANE_RUNTIME_DIR)/libsandy.dylib" "$(THEOS_STAGING_DIR)/Applications/CrypStore.app/Frameworks/"
	@cp "$(CRANE_RUNTIME_DIR)/libellekit.dylib" "$(THEOS_STAGING_DIR)/Applications/CrypStore.app/Frameworks/"
	@cp -R "$(CRANE_RUNTIME_DIR)/AltList.framework" "$(THEOS_STAGING_DIR)/Applications/CrypStore.app/Frameworks/"
	@cp -R "$(CRANE_RUNTIME_DIR)/CranePrefs.bundle" "$(THEOS_STAGING_DIR)/Applications/CrypStore.app/"
	@/usr/bin/codesign --verify --strict \
		"$(THEOS_STAGING_DIR)/Applications/CrypStore.app/CranePrefs.bundle/CranePrefs" || \
		(echo "CRANE_RUNTIME_DIR must contain the reviewed signed CranePrefs executable" >&2; exit 1)
endif
