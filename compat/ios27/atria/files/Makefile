ARCHS = arm64 arm64e
TARGET = iphone:clang:latest:14.0
THEOS_PACKAGE_SCHEME = rootless
PACKAGE_VERSION = 1.4.1+0sky27.3

include $(THEOS)/makefiles/common.mk

TWEAK_NAME = Atria
Atria_FILES = $(wildcard src/Hooks/*.xm) \
  $(wildcard src/Manager/*.m) \
  $(wildcard src/Editor/*.m) \
  $(wildcard src/Options/*.m) \
  $(wildcard src/UI/*.m) \
  $(wildcard src/UI/Effect/*.m) \
  $(wildcard src/UI/Label/*.m) \
  $(wildcard src/UI/Splash/*.m)
Atria_CFLAGS = -fobjc-arc -DPACKAGE_VERSION='@"$(PACKAGE_VERSION)"' -DPACKAGE_TYPE='@"0-Sky iOS 27"'
Atria_FRAMEWORKS = UIKit Foundation CoreFoundation CoreGraphics CoreText QuartzCore

BUNDLE_NAME = AtriaPrefs
AtriaPrefs_FILES = $(wildcard Prefs/src/*.m)
AtriaPrefs_CFLAGS = -fobjc-arc -DPACKAGE_VERSION='"$(PACKAGE_VERSION)"' -DPACKAGE_TYPE='"0-Sky iOS 27"'
AtriaPrefs_FRAMEWORKS = UIKit Foundation CoreFoundation QuartzCore
AtriaPrefs_LIBRARIES = colorpicker
AtriaPrefs_LDFLAGS = -F$(CURDIR)/stubs -framework Preferences
AtriaPrefs_INSTALL_PATH = /Library/PreferenceBundles

include $(THEOS_MAKE_PATH)/tweak.mk
include $(THEOS_MAKE_PATH)/bundle.mk

before-package::
	@mkdir -p $(THEOS_STAGING_DIR)/Library/MobileSubstrate/DynamicLibraries
	@cp Atria.plist $(THEOS_STAGING_DIR)/Library/MobileSubstrate/DynamicLibraries/Atria.plist
	@mkdir -p $(THEOS_STAGING_DIR)/Library/PreferenceLoader/Preferences
	@cp packaging/AtriaPrefs.plist $(THEOS_STAGING_DIR)/Library/PreferenceLoader/Preferences/AtriaPrefs.plist
	@cp -R Prefs/Resources/. $(THEOS_STAGING_DIR)/Library/PreferenceBundles/AtriaPrefs.bundle/

after-install::
	install.exec "killall -9 SpringBoard"
