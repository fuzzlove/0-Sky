#import <UIKit/UIKit.h>
#import <Foundation/Foundation.h>
#import <CoreFoundation/CoreFoundation.h>
#import <objc/runtime.h>
#import <substrate.h>
#import <sys/sysctl.h>

static NSString *const JFDomain = @"xyz.royalapps.jellyfish";
static NSString *const JFExpectedBuild = @"24A5390f";
static void (*JFOriginalLayoutSubviews)(id, SEL);
static NSHashTable<UIView *> *JFDateViews;
static NSUInteger JFLayoutCalls;
static NSUInteger JFEnabledLayoutCalls;
static BOOL JFWroteActiveDiagnostics;
static char JFBaseFontKey;
static char JFManagedSubtitleKey;

@interface SBUILegibilityLabel : UIView
- (UIFont *)font;
- (void)setFont:(UIFont *)font;
- (void)setTextAlignment:(NSTextAlignment)alignment;
@end

@interface SBFLockScreenDateSubtitleDateView : UIView
- (NSDate *)date;
- (void)setDate:(NSDate *)date;
- (NSString *)string;
- (void)setString:(NSString *)string;
- (UIFont *)font;
- (void)setFont:(UIFont *)font;
- (double)alignmentPercent;
- (void)setAlignmentPercent:(double)alignmentPercent;
@end

@interface SBFLockScreenDateView : UIView
- (NSDate *)date;
- (SBUILegibilityLabel *)_timeLabel;
- (double)alignmentPercent;
- (void)setAlignmentPercent:(double)alignmentPercent;
- (double)maximumSubtitleWidth;
- (void)setMaximumSubtitleWidth:(double)width;
@end

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

static SBFLockScreenDateSubtitleDateView *JFDateSubtitleInView(UIView *view) {
    Class subtitleClass = NSClassFromString(@"SBFLockScreenDateSubtitleDateView");
    for (UIView *candidate in view.subviews) {
        if (subtitleClass && [candidate isKindOfClass:subtitleClass])
            return (SBFLockScreenDateSubtitleDateView *)candidate;
        SBFLockScreenDateSubtitleDateView *nested = JFDateSubtitleInView(candidate);
        if (nested) return nested;
    }
    return nil;
}

static void JFApplyFont(id label, CGFloat scale) {
    if (!label || ![label respondsToSelector:@selector(font)] ||
        ![label respondsToSelector:@selector(setFont:)]) return;
    UIFont *base = objc_getAssociatedObject(label, &JFBaseFontKey);
    if (!base) {
        base = [label font];
        if (base) objc_setAssociatedObject(label, &JFBaseFontKey, base,
                                            OBJC_ASSOCIATION_RETAIN_NONATOMIC);
    }
    CGFloat targetSize = base ? MAX(8.0, base.pointSize * scale) : 0.0;
    UIFont *current = [label font];
    if (base && (!current || fabs(current.pointSize - targetSize) > 0.05))
        [label setFont:[base fontWithSize:targetSize]];
}

static void JFApplyShadow(UIView *view, BOOL shadow) {
    if (!view) return;
    view.layer.masksToBounds = NO;
    view.layer.shadowColor = UIColor.blackColor.CGColor;
    view.layer.shadowOpacity = shadow ? 0.55f : 0.0f;
    view.layer.shadowRadius = shadow ? 3.0f : 0.0f;
    view.layer.shadowOffset = CGSizeMake(0, 1.5);
}

static void JFUpdateSubtitle(SBFLockScreenDateView *host,
                             SBFLockScreenDateSubtitleDateView *subtitle) {
    if (!host || !subtitle) return;
    BOOL custom = JFBool(@"useCustomDateFormat", NO);
    BOOL battery = JFBool(@"alwaysShowBatteryPercentage", NO);
    NSDate *date = host.date ?: subtitle.date ?: NSDate.date;
    if (!custom && !battery) {
        if ([objc_getAssociatedObject(subtitle, &JFManagedSubtitleKey) boolValue]) {
            [subtitle setDate:date];
            objc_setAssociatedObject(subtitle, &JFManagedSubtitleKey, @NO,
                                     OBJC_ASSOCIATION_RETAIN_NONATOMIC);
        }
        return;
    }
    NSString *format = custom ? JFPreference(@"customDateFormat", @"EEEE, MMMM d")
                              : @"EEEE, MMMM d";
    if (![format isKindOfClass:NSString.class] || format.length == 0 || format.length > 80)
        format = @"EEEE, MMMM d";
    NSDateFormatter *formatter = [NSDateFormatter new];
    formatter.locale = NSLocale.currentLocale;
    formatter.dateFormat = format;
    NSString *string = [formatter stringFromDate:date] ?: @"";
    if (battery) {
        UIDevice.currentDevice.batteryMonitoringEnabled = YES;
        float level = UIDevice.currentDevice.batteryLevel;
        if (level >= 0.0f)
            string = [string stringByAppendingFormat:@"  •  %ld%%", (long)lround(level * 100.0f)];
    }
    if (![[subtitle string] isEqualToString:string]) [subtitle setString:string];
    objc_setAssociatedObject(subtitle, &JFManagedSubtitleKey, @YES,
                             OBJC_ASSOCIATION_RETAIN_NONATOMIC);
}

static void JFWriteDiagnostics(NSDictionary *details);

static void JFLayoutSubviews(id self, SEL selector) {
    JFOriginalLayoutSubviews(self, selector);
    JFLayoutCalls++;
    if (!JFBool(@"enabled", NO) || ![self isKindOfClass:UIView.class]) return;
    JFEnabledLayoutCalls++;
    SBFLockScreenDateView *host = (SBFLockScreenDateView *)self;
    [JFDateViews addObject:host];
    NSInteger alignment = (NSInteger)JFNumber(@"alignment", 0);
    alignment = MAX(0, MIN(2, alignment));
    double alignmentPercent = alignment == 0 ? 0.0 : alignment == 2 ? 1.0 : 0.5;
    CGFloat padding = MAX(0.0, MIN(40.0, JFNumber(@"xpadding", 16.0)));
    CGFloat scale = MAX(0.70, MIN(1.20, JFNumber(@"fontSize", 100.0) / 100.0));
    BOOL shadow = JFBool(@"showTextShadow", YES);
    if (fabs(host.alignmentPercent - alignmentPercent) > 0.001)
        [host setAlignmentPercent:alignmentPercent];
    double subtitleWidth = MAX(40.0, CGRectGetWidth(host.bounds) - padding * 2.0);
    if (fabs(host.maximumSubtitleWidth - subtitleWidth) > 0.05)
        [host setMaximumSubtitleWidth:subtitleWidth];
    SBUILegibilityLabel *timeLabel = [host _timeLabel];
    SBFLockScreenDateSubtitleDateView *subtitle = JFDateSubtitleInView(host);
    JFApplyFont(timeLabel, scale);
    JFApplyFont(subtitle, scale);
    [timeLabel setTextAlignment:alignment == 0 ? NSTextAlignmentLeft :
                                    alignment == 2 ? NSTextAlignmentRight : NSTextAlignmentCenter];
    if (subtitle && fabs(subtitle.alignmentPercent - alignmentPercent) > 0.001)
        [subtitle setAlignmentPercent:alignmentPercent];
    JFApplyShadow(timeLabel, shadow);
    JFApplyShadow(subtitle, shadow);
    JFUpdateSubtitle(host, subtitle);
    if (!JFWroteActiveDiagnostics && timeLabel && subtitle) {
        JFWroteActiveDiagnostics = YES;
        JFWriteDiagnostics(@{
            @"build": JFBuildVersion(),
            @"expectedBuild": JFExpectedBuild,
            @"exactBuild": @YES,
            @"dateViewPresent": @YES,
            @"layoutMethodPresent": @YES,
            @"hookInstalled": @YES,
            @"directTimeTargetPresent": @YES,
            @"directSubtitleTargetPresent": @YES,
            @"layoutCalls": @(JFLayoutCalls),
            @"enabledLayoutCalls": @(JFEnabledLayoutCalls),
            @"status": @"active-direct-ios27-targets"
        });
    }
}

static void JFPreferencesChanged(CFNotificationCenterRef center, void *observer,
                                 CFStringRef name, const void *object,
                                 CFDictionaryRef userInfo) {
    (void)center; (void)observer; (void)name; (void)object; (void)userInfo;
    dispatch_async(dispatch_get_main_queue(), ^{
        for (UIView *dateView in JFDateViews.allObjects) {
            [dateView setNeedsLayout];
            [dateView layoutIfNeeded];
        }
        for (UIWindow *window in UIApplication.sharedApplication.windows) {
            [window setNeedsLayout];
        }
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
        Class legibilityLabel = NSClassFromString(@"SBUILegibilityLabel");
        Class subtitleView = NSClassFromString(@"SBFLockScreenDateSubtitleDateView");
        BOOL directAPIsPresent = dateView && legibilityLabel && subtitleView &&
            class_getInstanceMethod(dateView, @selector(_timeLabel)) &&
            class_getInstanceMethod(dateView, @selector(setAlignmentPercent:)) &&
            class_getInstanceMethod(subtitleView, @selector(setString:)) &&
            class_getInstanceMethod(legibilityLabel, @selector(setFont:));
        JFWriteDiagnostics(@{
            @"build": build,
            @"expectedBuild": JFExpectedBuild,
            @"exactBuild": @(exactBuild),
            @"dateViewPresent": @(dateView != Nil),
            @"layoutMethodPresent": @(layout != NULL),
            @"directAPIsPresent": @(directAPIsPresent),
            @"hookInstalled": @(exactBuild && layout != NULL && directAPIsPresent),
            @"status": exactBuild ? ((layout && directAPIsPresent) ? @"hook-installed" : @"missing-direct-ios27-target") : @"unsupported-build"
        });
        if (!exactBuild || !layout || !directAPIsPresent) return;
        JFDateViews = [NSHashTable weakObjectsHashTable];
        MSHookMessageEx(dateView, @selector(layoutSubviews), (IMP)JFLayoutSubviews,
                        (IMP *)&JFOriginalLayoutSubviews);
        CFNotificationCenterAddObserver(CFNotificationCenterGetDarwinNotifyCenter(),
            NULL, JFPreferencesChanged, CFSTR("xyz.royalapps.jellyfish.changed"), NULL,
            CFNotificationSuspensionBehaviorDeliverImmediately);
    }
}
