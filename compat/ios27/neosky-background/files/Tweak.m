#import <UIKit/UIKit.h>
#import <Foundation/Foundation.h>
#import <CoreFoundation/CoreFoundation.h>
#import <mach/mach.h>
#import <objc/runtime.h>
#import <substrate.h>
#import <sys/mount.h>
#import <sys/sysctl.h>
#import <sys/utsname.h>

static NSString *const NSDomain = @"xyz.0sky.neoskybackground";
static NSString *const NSExpectedBuild = @"24A5390f";
static void (*NSOriginalHomeLayout)(id, SEL);
static void (*NSOriginalLockLayout)(id, SEL);
static NSHashTable<UIView *> *NSHomeHosts;
static NSHashTable<UIView *> *NSLockHosts;
static dispatch_source_t NSRefreshTimer;
static NSAttributedString *NSCurrentText;
static BOOL NSHomeActive;
static BOOL NSLockActive;
static const void *NSHomeLabelKey = &NSHomeLabelKey;
static const void *NSLockLabelKey = &NSLockLabelKey;

@interface SBHomeScreenView : UIView
- (UIView *)iconContentView;
@end

@interface CSProminentDisplayView : UIView
@end

static id NSPreference(NSString *key, id fallback) {
    CFPropertyListRef value = CFPreferencesCopyAppValue((__bridge CFStringRef)key,
                                                        (__bridge CFStringRef)NSDomain);
    if (!value) return fallback;
    return CFBridgingRelease(value);
}

static BOOL NSBool(NSString *key, BOOL fallback) {
    id value = NSPreference(key, @(fallback));
    return [value respondsToSelector:@selector(boolValue)] ? [value boolValue] : fallback;
}

static CGFloat NSPrefNumber(NSString *key, CGFloat fallback) {
    id value = NSPreference(key, @(fallback));
    return [value respondsToSelector:@selector(doubleValue)] ? [value doubleValue] : fallback;
}

static NSString *NSBuildVersion(void) {
    size_t size = 0;
    if (sysctlbyname("kern.osversion", NULL, &size, NULL, 0) != 0 || size < 2) return @"unknown";
    char *buffer = calloc(1, size);
    if (!buffer) return @"unknown";
    NSString *result = @"unknown";
    if (sysctlbyname("kern.osversion", buffer, &size, NULL, 0) == 0)
        result = [NSString stringWithUTF8String:buffer] ?: @"unknown";
    free(buffer);
    return result;
}

static NSString *NSSysctlString(const char *name) {
    size_t size = 0;
    if (sysctlbyname(name, NULL, &size, NULL, 0) != 0 || size < 2) return @"unknown";
    char *buffer = calloc(1, size);
    if (!buffer) return @"unknown";
    NSString *result = @"unknown";
    if (sysctlbyname(name, buffer, &size, NULL, 0) == 0)
        result = [NSString stringWithUTF8String:buffer] ?: @"unknown";
    free(buffer);
    return result;
}

static uint64_t NSUsedMemory(void) {
    mach_msg_type_number_t count = HOST_VM_INFO64_COUNT;
    vm_statistics64_data_t statistics = {0};
    if (host_statistics64(mach_host_self(), HOST_VM_INFO64,
                          (host_info64_t)&statistics, &count) != KERN_SUCCESS) return 0;
    vm_size_t pageSize = 0;
    host_page_size(mach_host_self(), &pageSize);
    return ((uint64_t)statistics.active_count +
            (uint64_t)statistics.wire_count +
            (uint64_t)statistics.compressor_page_count) * (uint64_t)pageSize;
}

static NSString *NSDuration(NSTimeInterval seconds) {
    NSUInteger total = (NSUInteger)MAX(0, seconds);
    NSUInteger days = total / 86400;
    NSUInteger hours = (total % 86400) / 3600;
    NSUInteger minutes = (total % 3600) / 60;
    return days ? [NSString stringWithFormat:@"%lud %luh %lum",
                   (unsigned long)days, (unsigned long)hours, (unsigned long)minutes]
                : [NSString stringWithFormat:@"%luh %lum",
                   (unsigned long)hours, (unsigned long)minutes];
}

static UIColor *NSAccentColor(void) {
    NSInteger scheme = (NSInteger)NSPrefNumber(@"colorScheme", 0);
    if (scheme == 1) return UIColor.whiteColor;
    if (scheme == 2) return [UIColor colorWithRed:0.35 green:1.0 blue:0.52 alpha:1.0];
    return [UIColor colorWithRed:0.24 green:0.78 blue:1.0 alpha:1.0];
}

static NSAttributedString *NSBuildStatsText(void) {
    struct utsname uts = {0};
    uname(&uts);
    NSString *hardware = NSSysctlString("hw.machine");
    int cpuCount = 0;
    size_t cpuSize = sizeof(cpuCount);
    sysctlbyname("hw.ncpu", &cpuCount, &cpuSize, NULL, 0);
    uint64_t totalMemory = NSProcessInfo.processInfo.physicalMemory;
    uint64_t usedMemory = NSUsedMemory();
    struct statfs disk = {0};
    uint64_t diskTotal = 0, diskUsed = 0;
    if (statfs("/var/mobile", &disk) == 0) {
        diskTotal = (uint64_t)disk.f_blocks * (uint64_t)disk.f_bsize;
        uint64_t freeBytes = (uint64_t)disk.f_bavail * (uint64_t)disk.f_bsize;
        diskUsed = diskTotal > freeBytes ? diskTotal - freeBytes : 0;
    }
    UIDevice.currentDevice.batteryMonitoringEnabled = YES;
    float battery = UIDevice.currentDevice.batteryLevel;
    NSString *logo = NSBool(@"showLogo", YES) ?
        @"  0-SKY\n  =====\n\n" : @"";
    NSString *batteryLine = battery >= 0.0f ?
        [NSString stringWithFormat:@"Battery: %ld%%\n", (long)lroundf(battery * 100.0f)] : @"";
    NSString *plain = [NSString stringWithFormat:
        @"%@mobile@iphone\n"
         "─────────────\n"
         "OS: iOS %@ (%@)\n"
         "Host: %@\n"
         "Kernel: Darwin %s\n"
         "Uptime: %@\n"
         "CPU: Apple SoC (%d cores)\n"
         "Memory: %lluMiB / %lluMiB\n"
         "Storage: %.1fGiB / %.1fGiB\n"
         "%@Runtime: 0-Sky SRD",
        logo, UIDevice.currentDevice.systemVersion, NSBuildVersion(), hardware,
        uts.release, NSDuration(NSProcessInfo.processInfo.systemUptime), MAX(cpuCount, 1),
        usedMemory / (1024ULL * 1024ULL), totalMemory / (1024ULL * 1024ULL),
        (double)diskUsed / (1024.0 * 1024.0 * 1024.0),
        (double)diskTotal / (1024.0 * 1024.0 * 1024.0), batteryLine];
    CGFloat size = MAX(8.0, MIN(18.0, NSPrefNumber(@"fontSize", 11.0)));
    NSMutableParagraphStyle *paragraph = [NSMutableParagraphStyle new];
    paragraph.lineSpacing = 1.0;
    NSDictionary *attributes = @{
        NSFontAttributeName: [UIFont monospacedSystemFontOfSize:size weight:UIFontWeightRegular],
        NSForegroundColorAttributeName: NSAccentColor(),
        NSParagraphStyleAttributeName: paragraph
    };
    return [[NSAttributedString alloc] initWithString:plain attributes:attributes];
}

static UILabel *NSNewLabel(void) {
    UILabel *label = [UILabel new];
    label.numberOfLines = 0;
    label.userInteractionEnabled = NO;
    label.backgroundColor = UIColor.clearColor;
    label.layer.shadowColor = UIColor.blackColor.CGColor;
    label.layer.shadowOpacity = 0.85;
    label.layer.shadowRadius = 2.0;
    label.layer.shadowOffset = CGSizeMake(0, 1);
    label.accessibilityIdentifier = @"0-Sky NeoSky Background";
    return label;
}

static void NSConfigureLabel(UILabel *label, UIView *container, CGFloat y) {
    if (!label || !container) return;
    CGFloat opacity = MAX(0.20, MIN(1.0, NSPrefNumber(@"opacityPercent", 78.0) / 100.0));
    label.alpha = opacity;
    label.attributedText = NSCurrentText ?: NSBuildStatsText();
    CGFloat width = MAX(40.0, CGRectGetWidth(container.bounds) - 36.0);
    label.frame = CGRectMake(18.0, MAX(0.0, y), width,
                             MAX(80.0, CGRectGetHeight(container.bounds) - MAX(0.0, y) - 16.0));
}

static void NSWriteDiagnostics(NSString *status) {
    NSDictionary *diagnostics = @{
        @"build": NSBuildVersion(),
        @"expectedBuild": NSExpectedBuild,
        @"exactBuild": @([NSBuildVersion() isEqualToString:NSExpectedBuild]),
        @"homeActive": @(NSHomeActive),
        @"lockActive": @(NSLockActive),
        @"status": status,
        @"timestamp": @([NSDate.date timeIntervalSince1970])
    };
    [diagnostics writeToFile:@"/var/mobile/Library/Preferences/xyz.0sky.neoskybackground.diagnostics.plist"
                  atomically:YES];
}

static void NSUpdateAllLabels(void) {
    NSCurrentText = NSBuildStatsText();
    BOOL enabled = NSBool(@"enabled", NO);
    for (UIView *host in NSHomeHosts.allObjects) {
        UILabel *label = objc_getAssociatedObject(host, NSHomeLabelKey);
        label.hidden = !(enabled && NSBool(@"homeEnabled", YES));
        NSConfigureLabel(label, host, NSPrefNumber(@"homeY", 120.0));
        [host setNeedsLayout];
    }
    for (UIView *host in NSLockHosts.allObjects) {
        UILabel *label = objc_getAssociatedObject(host, NSLockLabelKey);
        label.hidden = !(enabled && NSBool(@"lockEnabled", NO));
        NSConfigureLabel(label, label.superview, NSPrefNumber(@"lockY", 620.0));
    }
}

static void NSInstallHomeLabel(SBHomeScreenView *host) {
    if (!host) return;
    [NSHomeHosts addObject:host];
    BOOL visible = NSBool(@"enabled", NO) && NSBool(@"homeEnabled", YES);
    UILabel *label = objc_getAssociatedObject(host, NSHomeLabelKey);
    if (!label) {
        label = NSNewLabel();
        objc_setAssociatedObject(host, NSHomeLabelKey, label, OBJC_ASSOCIATION_RETAIN_NONATOMIC);
    }
    UIView *icons = [host respondsToSelector:@selector(iconContentView)] ? host.iconContentView : nil;
    if (label.superview != host) {
        [label removeFromSuperview];
        if (icons && icons.superview == host) [host insertSubview:label belowSubview:icons];
        else [host insertSubview:label atIndex:0];
    } else if (icons && icons.superview == host) {
        [host insertSubview:label belowSubview:icons];
    }
    label.hidden = !visible;
    NSConfigureLabel(label, host, NSPrefNumber(@"homeY", 120.0));
    if (visible && !NSHomeActive) {
        NSHomeActive = YES;
        NSWriteDiagnostics(NSLockActive ? @"active-lock-and-home" : @"active-home");
    }
}

static void NSFindExistingHomeViews(UIView *view) {
    if (!view) return;
    Class homeClass = NSClassFromString(@"SBHomeScreenView");
    if (homeClass && [view isKindOfClass:homeClass])
        NSInstallHomeLabel((SBHomeScreenView *)view);
    for (UIView *child in view.subviews) NSFindExistingHomeViews(child);
}

static void NSAttachToExistingHomeViews(void) {
    for (UIWindow *window in UIApplication.sharedApplication.windows)
        NSFindExistingHomeViews(window);
}

static void NSHomeLayout(id self, SEL selector) {
    NSOriginalHomeLayout(self, selector);
    NSInstallHomeLabel((SBHomeScreenView *)self);
}

static void NSLockLayout(id self, SEL selector) {
    NSOriginalLockLayout(self, selector);
    CSProminentDisplayView *host = (CSProminentDisplayView *)self;
    [NSLockHosts addObject:host];
    BOOL visible = NSBool(@"enabled", NO) && NSBool(@"lockEnabled", NO);
    UILabel *label = objc_getAssociatedObject(host, NSLockLabelKey);
    if (!label) {
        label = NSNewLabel();
        objc_setAssociatedObject(host, NSLockLabelKey, label, OBJC_ASSOCIATION_RETAIN_NONATOMIC);
    }
    UIView *container = host.superview ?: host;
    if (label.superview != container) {
        [label removeFromSuperview];
        if (host.superview == container)
            [container insertSubview:label aboveSubview:host];
        else
            [container addSubview:label];
    } else if (host.superview == container) {
        [container insertSubview:label aboveSubview:host];
    }
    label.hidden = !visible;
    CGFloat screenY = NSPrefNumber(@"lockY", 620.0);
    CGPoint origin = host.window ? [container convertPoint:CGPointMake(18.0, screenY)
                                                   fromView:host.window]
                                 : CGPointMake(18.0, screenY);
    NSConfigureLabel(label, container, origin.y);
    CGRect frame = label.frame;
    frame.origin.x = origin.x;
    label.frame = frame;
    if (visible && !NSLockActive) {
        NSLockActive = YES;
        NSWriteDiagnostics(NSHomeActive ? @"active-lock-and-home" : @"active-lock");
    }
}

static void NSPreferencesChanged(CFNotificationCenterRef center, void *observer,
                                 CFStringRef name, const void *object,
                                 CFDictionaryRef userInfo) {
    (void)center; (void)observer; (void)name; (void)object; (void)userInfo;
    CFPreferencesAppSynchronize((__bridge CFStringRef)NSDomain);
    dispatch_async(dispatch_get_main_queue(), ^{
        NSUpdateAllLabels();
        NSAttachToExistingHomeViews();
    });
}

static void NSStartTimer(void) {
    NSRefreshTimer = dispatch_source_create(DISPATCH_SOURCE_TYPE_TIMER, 0, 0,
                                            dispatch_get_main_queue());
    dispatch_source_set_timer(NSRefreshTimer, dispatch_time(DISPATCH_TIME_NOW, 0),
                              30ULL * NSEC_PER_SEC, 2ULL * NSEC_PER_SEC);
    __block NSTimeInterval lastRefresh = 0;
    dispatch_source_set_event_handler(NSRefreshTimer, ^{
        NSTimeInterval now = NSDate.date.timeIntervalSince1970;
        NSTimeInterval interval = MAX(30.0, MIN(300.0, NSPrefNumber(@"refreshInterval", 60.0)));
        if (lastRefresh == 0 || now - lastRefresh >= interval - 1.0) {
            lastRefresh = now;
            NSUpdateAllLabels();
        }
    });
    dispatch_resume(NSRefreshTimer);
}

__attribute__((constructor)) static void NSInitialize(void) {
    @autoreleasepool {
        dispatch_async(dispatch_get_main_queue(), ^{
            NSString *build = NSBuildVersion();
            Class homeClass = NSClassFromString(@"SBHomeScreenView");
            Class lockClass = NSClassFromString(@"CSProminentDisplayView");
            Method homeLayout = homeClass ? class_getInstanceMethod(homeClass, @selector(layoutSubviews)) : NULL;
            Method lockLayout = lockClass ? class_getInstanceMethod(lockClass, @selector(layoutSubviews)) : NULL;
            BOOL exact = [build isEqualToString:NSExpectedBuild];
            if (!exact || !homeLayout || !lockLayout) {
                NSWriteDiagnostics(exact ? @"missing-ios27-target" : @"unsupported-build");
                return;
            }
            NSHomeHosts = [NSHashTable weakObjectsHashTable];
            NSLockHosts = [NSHashTable weakObjectsHashTable];
            NSCurrentText = NSBuildStatsText();
            MSHookMessageEx(homeClass, @selector(layoutSubviews), (IMP)NSHomeLayout,
                            (IMP *)&NSOriginalHomeLayout);
            MSHookMessageEx(lockClass, @selector(layoutSubviews), (IMP)NSLockLayout,
                            (IMP *)&NSOriginalLockLayout);
            CFNotificationCenterAddObserver(CFNotificationCenterGetDarwinNotifyCenter(), NULL,
                NSPreferencesChanged, CFSTR("xyz.0sky.neoskybackground.changed"), NULL,
                CFNotificationSuspensionBehaviorDeliverImmediately);
            NSWriteDiagnostics(@"hook-installed");
            NSStartTimer();
            // Runtime-manager injection occurs after SpringBoard may have built
            // its Home Screen. Attach directly to the exact guarded host instead
            // of forcing a UIKit layout pass through unrelated tweak hooks.
            dispatch_after(dispatch_time(DISPATCH_TIME_NOW, (int64_t)(1.0 * NSEC_PER_SEC)),
                           dispatch_get_main_queue(), ^{ NSAttachToExistingHomeViews(); });
        });
    }
}
