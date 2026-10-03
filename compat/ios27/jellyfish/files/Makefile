ARCHS = arm64 arm64e
TARGET = iphone:clang:latest:14.0
THEOS_PACKAGE_SCHEME = rootless
PACKAGE_VERSION = 1.6.5+0sky27.3

include $(THEOS)/makefiles/common.mk

TWEAK_NAME = Jellyfish27
Jellyfish27_FILES = Tweak.m
Jellyfish27_CFLAGS = -fobjc-arc -Wall -Wextra
Jellyfish27_FRAMEWORKS = UIKit Foundation CoreFoundation
Jellyfish27_LIBRARIES = substrate

BUNDLE_NAME = Jellyfish27Preferences
Jellyfish27Preferences_FILES = NativePrefs/Jellyfish27PreferencesRootListController.m
Jellyfish27Preferences_CFLAGS = -fobjc-arc -Wall -Wextra
Jellyfish27Preferences_FRAMEWORKS = UIKit Foundation CoreFoundation
Jellyfish27Preferences_LDFLAGS = -F$(CURDIR)/NativePrefs/stubs -framework Preferences
Jellyfish27Preferences_INSTALL_PATH = /Library/PreferenceBundles

include $(THEOS_MAKE_PATH)/tweak.mk
include $(THEOS_MAKE_PATH)/bundle.mk

TOOL_NAME = jellyfish27ctl
jellyfish27ctl_FILES = jellyfish27ctl.m
jellyfish27ctl_CFLAGS = -fobjc-arc -Wall -Wextra
jellyfish27ctl_FRAMEWORKS = Foundation CoreFoundation
jellyfish27ctl_INSTALL_PATH = /usr/bin

include $(THEOS_MAKE_PATH)/tool.mk

before-package::
	@mkdir -p $(THEOS_STAGING_DIR)/Library/MobileSubstrate/DynamicLibraries
	@cp packaging/Jellyfish27.plist $(THEOS_STAGING_DIR)/Library/MobileSubstrate/DynamicLibraries/Jellyfish27.plist
	@mkdir -p $(THEOS_STAGING_DIR)/Library/PreferenceLoader/Preferences
	@cp packaging/Jellyfish27Preferences.plist $(THEOS_STAGING_DIR)/Library/PreferenceLoader/Preferences/Jellyfish27Preferences.plist
	@mkdir -p $(THEOS_STAGING_DIR)/Library/PreferenceBundles/Jellyfish27Preferences.bundle/Resources
	@cp packaging/Info.plist $(THEOS_STAGING_DIR)/Library/PreferenceBundles/Jellyfish27Preferences.bundle/Info.plist
	@cp packaging/Root.plist $(THEOS_STAGING_DIR)/Library/PreferenceBundles/Jellyfish27Preferences.bundle/Resources/Root.plist
	@plutil -convert binary1 $(THEOS_STAGING_DIR)/Library/PreferenceBundles/Jellyfish27Preferences.bundle/Info.plist
	@plutil -convert binary1 $(THEOS_STAGING_DIR)/Library/PreferenceBundles/Jellyfish27Preferences.bundle/Resources/Root.plist
	@/usr/bin/codesign --force --sign - --timestamp=none --identifier xyz.0sky.jellyfish27.preferences $(THEOS_STAGING_DIR)/Library/PreferenceBundles/Jellyfish27Preferences.bundle

