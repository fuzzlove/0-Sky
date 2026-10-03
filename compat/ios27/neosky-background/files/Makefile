ARCHS = arm64 arm64e
TARGET = iphone:clang:latest:14.0
THEOS_PACKAGE_SCHEME = rootless
PACKAGE_VERSION = 1.0.0+0sky27.2

include $(THEOS)/makefiles/common.mk

TWEAK_NAME = NeoSkyBackground
NeoSkyBackground_FILES = Tweak.m
NeoSkyBackground_CFLAGS = -fobjc-arc -Wall -Wextra
NeoSkyBackground_FRAMEWORKS = UIKit Foundation CoreFoundation
NeoSkyBackground_LIBRARIES = substrate

BUNDLE_NAME = NeoSkyBackgroundPreferences
NeoSkyBackgroundPreferences_FILES = NativePrefs/NeoSkyBackgroundPreferencesRootListController.m
NeoSkyBackgroundPreferences_CFLAGS = -fobjc-arc -Wall -Wextra
NeoSkyBackgroundPreferences_FRAMEWORKS = UIKit Foundation CoreFoundation
NeoSkyBackgroundPreferences_LDFLAGS = -F$(CURDIR)/NativePrefs/stubs -framework Preferences
NeoSkyBackgroundPreferences_INSTALL_PATH = /Library/PreferenceBundles

include $(THEOS_MAKE_PATH)/tweak.mk
include $(THEOS_MAKE_PATH)/bundle.mk

TOOL_NAME = neoskyctl
neoskyctl_FILES = neoskyctl.m
neoskyctl_CFLAGS = -fobjc-arc -Wall -Wextra
neoskyctl_FRAMEWORKS = Foundation CoreFoundation
neoskyctl_INSTALL_PATH = /usr/bin

include $(THEOS_MAKE_PATH)/tool.mk

before-package::
	@mkdir -p $(THEOS_STAGING_DIR)/Library/MobileSubstrate/DynamicLibraries
	@cp packaging/NeoSkyBackground.plist $(THEOS_STAGING_DIR)/Library/MobileSubstrate/DynamicLibraries/NeoSkyBackground.plist
	@mkdir -p $(THEOS_STAGING_DIR)/Library/PreferenceLoader/Preferences
	@cp packaging/NeoSkyBackgroundPreferences.plist $(THEOS_STAGING_DIR)/Library/PreferenceLoader/Preferences/NeoSkyBackgroundPreferences.plist
	@mkdir -p $(THEOS_STAGING_DIR)/Library/PreferenceBundles/NeoSkyBackgroundPreferences.bundle/Resources
	@cp packaging/Info.plist $(THEOS_STAGING_DIR)/Library/PreferenceBundles/NeoSkyBackgroundPreferences.bundle/Info.plist
	@cp packaging/Root.plist $(THEOS_STAGING_DIR)/Library/PreferenceBundles/NeoSkyBackgroundPreferences.bundle/Resources/Root.plist
	@plutil -convert binary1 $(THEOS_STAGING_DIR)/Library/PreferenceBundles/NeoSkyBackgroundPreferences.bundle/Info.plist
	@plutil -convert binary1 $(THEOS_STAGING_DIR)/Library/PreferenceBundles/NeoSkyBackgroundPreferences.bundle/Resources/Root.plist
	@/usr/bin/codesign --force --sign - --timestamp=none --identifier xyz.0sky.neoskybackground.preferences $(THEOS_STAGING_DIR)/Library/PreferenceBundles/NeoSkyBackgroundPreferences.bundle
