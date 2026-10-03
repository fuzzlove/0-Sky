#import <UIKit/UIKit.h>
#import <Foundation/Foundation.h>
#import <CoreFoundation/CoreFoundation.h>
#import <objc/runtime.h>
#import <substrate.h>
#import <sys/sysctl.h>

static NSString *const JFDomain = @"xyz.royalapps.jellyfish";
static NSString *const JFExpectedBuild = @"24A5390f";
static void (*JFOriginalLayoutSubviews)(id, SEL);

static id JFPreference(NSString *key, id fallback) {
    CFPropertyListRef value = CFPreferencesCopyAppValue((__bridge CFStringRef)key,
                                                        (__bridge CFStringRef)JFDomain);
    return CFBridgingRelease(value) ?: fallback;
}

static BOOL JFBool(NSString *key, BOOL fallback) {
    id value = JFPreference(key, @(fallback));
    return [value respondsToSelector:@selector(boolValue)] ? [value boolValue] : fallback;
}

static CGFloat JFNumber(NSString *key, CGFloat fallback) {
    id value = JFPreference(key, @(fallback));
    return [value respondsToSelector:@selector(doubleValue)] ? [value doubleValue] : fallback;
}

static NSString *JFBuildVersion(void) {
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

static void JFCollectLabels(UIView *view, NSMutableArray<UILabel *> *labels) {
    for (UIView *candidate in view.subviews) {
        if ([candidate isKindOfClass:UILabel.class]) [labels addObject:(UILabel *)candidate];
        JFCollectLabels(candidate, labels);
    }
}

static void JFApplyLabelLayout(UILabel *label, UIView *host, NSInteger alignment,
                               CGFloat padding, CGFloat scale, BOOL shadow) {
    if (!label || !host) return;
    NSTextAlignment textAlignment = alignment == 0 ? NSTextAlignmentLeft :
                                      alignment == 2 ? NSTextAlignmentRight : NSTextAlignmentCenter;
    label.textAlignment = textAlignment;
    CGFloat width = MAX(0.0, CGRectGetWidth(host.bounds) - padding * 2.0);
    CGRect frame = label.frame;
    frame.origin.x = padding;
    frame.size.width = width;
    label.frame = frame;
    NSNumber *base = objc_getAssociatedObject(label, @selector(JFApplyLabelLayout));
    if (!base) {
        base = @(label.font.pointSize);
        objc_setAssociatedObject(label, @selector(JFApplyLabelLayout), base,
                                 OBJC_ASSOCIATION_RETAIN_NONATOMIC);
    }
    label.font = [label.font fontWithSize:MAX(8.0, base.doubleValue * scale)];
    label.layer.shadowColor = UIColor.blackColor.CGColor;
    label.layer.shadowOpacity = shadow ? 0.35f : 0.0f;
    label.layer.shadowRadius = shadow ? 2.0f : 0.0f;
    label.layer.shadowOffset = CGSizeMake(0, 1);
}

static void JFUpdateDateAndBattery(NSArray<UILabel *> *labels) {
    if (labels.count < 2) return;
    UILabel *subtitle = labels[1];
    if (JFBool(@"useCustomDateFormat", NO)) {
        NSString *format = JFPreference(@"customDateFormat", @"EEEE, MMMM d");
        if (![format isKindOfClass:NSString.class] || format.length == 0 || format.length > 80)
            format = @"EEEE, MMMM d";
        NSDateFormatter *formatter = [NSDateFormatter new];
        formatter.locale = NSLocale.currentLocale;
        formatter.dateFormat = format;
        subtitle.text = [formatter stringFromDate:NSDate.date];
    }
    if (JFBool(@"alwaysShowBatteryPercentage", NO)) {
        UIDevice.currentDevice.batteryMonitoringEnabled = YES;
        NSInteger percent = lround(MAX(0.0, UIDevice.currentDevice.batteryLevel) * 100.0);
        if (percent >= 0) subtitle.text = [NSString stringWithFormat:@"%@  •  %ld%%",
            subtitle.text ?: @"", (long)percent];
    }
}

static void JFLayoutSubviews(id self, SEL selector) {
    JFOriginalLayoutSubviews(self, selector);
    if (!JFBool(@"enabled", NO) || ![self isKindOfClass:UIView.class]) return;
    UIView *host = (UIView *)self;
    NSMutableArray<UILabel *> *labels = [NSMutableArray array];
    JFCollectLabels(host, labels);
    [labels sortUsingComparator:^NSComparisonResult(UILabel *a, UILabel *b) {
        if (a.font.pointSize > b.font.pointSize) return NSOrderedAscending;
        if (a.font.pointSize < b.font.pointSize) return NSOrderedDescending;
        return NSOrderedSame;
    }];
    NSInteger alignment = (NSInteger)JFNumber(@"alignment", 1);
    alignment = MAX(0, MIN(2, alignment));
    CGFloat padding = MAX(0.0, MIN(40.0, JFNumber(@"xpadding", 16.0)));
    CGFloat scale = MAX(0.70, MIN(1.20, JFNumber(@"fontSize", 100.0) / 100.0));
    BOOL shadow = JFBool(@"showTextShadow", YES);
    for (UILabel *label in labels) JFApplyLabelLayout(label, host, alignment, padding, scale, shadow);
    JFUpdateDateAndBattery(labels);
}

static void JFPreferencesChanged(CFNotificationCenterRef center, void *observer,
                                 CFStringRef name, const void *object,
                                 CFDictionaryRef userInfo) {
    (void)center; (void)observer; (void)name; (void)object; (void)userInfo;
    dispatch_async(dispatch_get_main_queue(), ^{
        for (UIWindow *window in UIApplication.sharedApplication.windows)
            [window setNeedsLayout];
    });
}

static void JFWriteDiagnostics(NSDictionary *details) {
    NSString *path = @"/var/mobile/Library/Preferences/xyz.0sky.jellyfish27.diagnostics.plist";
    NSMutableDictionary *sanitized = [details mutableCopy];
    sanitized[@"timestamp"] = @([[NSDate date] timeIntervalSince1970]);
    [sanitized writeToFile:path atomically:YES];
}

__attribute__((constructor)) static void JFInitialize(void) {
    @autoreleasepool {
        NSString *build = JFBuildVersion();
        NSOperatingSystemVersion version = NSProcessInfo.processInfo.operatingSystemVersion;
        BOOL exactBuild = version.majorVersion == 27 && [build isEqualToString:JFExpectedBuild];
        Class dateView = NSClassFromString(@"SBFLockScreenDateView");
        Method layout = dateView ? class_getInstanceMethod(dateView, @selector(layoutSubviews)) : NULL;
        JFWriteDiagnostics(@{
            @"build": build,
            @"expectedBuild": JFExpectedBuild,
            @"exactBuild": @(exactBuild),
            @"dateViewPresent": @(dateView != Nil),
            @"layoutMethodPresent": @(layout != NULL),
            @"hookInstalled": @(exactBuild && layout != NULL),
            @"status": exactBuild ? (layout ? @"ready-disabled-by-default" : @"missing-target-class") : @"unsupported-build"
        });
        if (!exactBuild || !layout) return;
        MSHookMessageEx(dateView, @selector(layoutSubviews), (IMP)JFLayoutSubviews,
                        (IMP *)&JFOriginalLayoutSubviews);
        CFNotificationCenterAddObserver(CFNotificationCenterGetDarwinNotifyCenter(),
            NULL, JFPreferencesChanged, CFSTR("xyz.royalapps.jellyfish.changed"), NULL,
            CFNotificationSuspensionBehaviorDeliverImmediately);
    }
}

