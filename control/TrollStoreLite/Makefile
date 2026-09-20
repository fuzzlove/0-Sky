TARGET := iphone:clang:16.5:14.0
INSTALL_TARGET_PROCESSES = CrypStore
ARCHS = arm64

include $(THEOS)/makefiles/common.mk

APPLICATION_NAME = CrypStore

CrypStore_FILES = $(wildcard ../TrollStore/*.m) $(wildcard ../Shared/*.m)
CrypStore_FRAMEWORKS = UIKit CoreGraphics CoreServices CoreTelephony CoreBluetooth Security
CrypStore_PRIVATE_FRAMEWORKS = Preferences MobileIcons MobileContainerManager
CrypStore_LIBRARIES = archive
CrypStore_CFLAGS = -fobjc-arc -I../Shared -I$(shell brew --prefix)/opt/libarchive/include -DTROLLSTORE_LITE
CrypStore_LDFLAGS = -F../build-stubs
CrypStore_CODESIGN_FLAGS = -Sentitlements.plist

include $(THEOS_MAKE_PATH)/application.mk
