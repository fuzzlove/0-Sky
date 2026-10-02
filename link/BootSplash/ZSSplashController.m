#import "ZSSplashController.h"
#import <QuartzCore/QuartzCore.h>
#import "../Theme/ZSLinkTheme.h"

static NSString *const ZSStatusURL = @"http://127.0.0.1:48654/v1/bootsplash/status";
// /var/jb/etc/0sky is root-only in the existing Core runtime.  This separate
// nonsecret rootless configuration can be read by the mobile UI process.
static NSString *const ZSConfigPath = @"/var/jb/etc/0sky-bootsplash.json";

@interface ZSSplashController ()
@property (nonatomic, strong) NSMutableDictionary<NSString *, UILabel *> *values;
@property (nonatomic, strong) UILabel *uidName;
@property (nonatomic, strong) UILabel *footer;
@property (nonatomic, strong) UILabel *activity;
@property (nonatomic, strong) UIActivityIndicatorView *spinner;
@property (nonatomic, strong) UIProgressView *checkProgress;
@property (nonatomic, strong) NSURLSessionDataTask *task;
@property (nonatomic, assign) CFTimeInterval started;
@property (nonatomic, assign) BOOL dismissed;
@property (nonatomic, assign) NSUInteger minimumMS;
@property (nonatomic, assign) NSUInteger maximumMS;
@property (nonatomic, strong) NSDictionary *configuration;
@property (nonatomic, assign) NSUInteger attempts;
@property (nonatomic, copy, readwrite, nullable) NSDictionary *lastSnapshot;
@end

@implementation ZSSplashController

+ (NSDictionary *)settings {
    NSMutableDictionary *settings = [@{@"enabled": @YES,
        @"minimum_display_ms": @3000, @"maximum_display_ms": @5000,
        @"show_uid": @YES, @"show_bootstrap": @YES,
        @"show_trusted_host": @YES, @"show_ssh": @YES,
        @"show_runtime": @YES, @"show_control": @YES} mutableCopy];
    NSData *data = [NSData dataWithContentsOfFile:ZSConfigPath options:0 error:nil];
    NSDictionary *file = data ? [NSJSONSerialization JSONObjectWithData:data options:0 error:nil] : nil;
    NSDictionary *overrides = [file[@"bootsplash"] isKindOfClass:NSDictionary.class] ? file[@"bootsplash"] : file;
    if ([overrides isKindOfClass:NSDictionary.class]) {
        for (NSString *key in [settings.allKeys copy]) {
            id value = overrides[key];
            if ([value isKindOfClass:NSNumber.class]) settings[key] = value;
        }
    }
    NSInteger maximum = MAX(100, MIN(5000, [settings[@"maximum_display_ms"] integerValue]));
    NSInteger minimum = MAX(0, MIN(maximum, [settings[@"minimum_display_ms"] integerValue]));
    settings[@"maximum_display_ms"] = @(maximum);
    settings[@"minimum_display_ms"] = @(minimum);
    return settings;
}

+ (BOOL)isEnabled { return [[self settings][@"enabled"] boolValue]; }

- (void)viewDidLoad {
    [super viewDidLoad];
    self.configuration = [ZSSplashController settings];
    self.minimumMS = [self.configuration[@"minimum_display_ms"] unsignedIntegerValue];
    self.maximumMS = [self.configuration[@"maximum_display_ms"] unsignedIntegerValue];
    self.view.backgroundColor = UIColor.blackColor;
    self.values = [NSMutableDictionary dictionary];
    [self render];
    self.started = CACurrentMediaTime();
    NSLog(@"[0-Sky Splash] started");
    [self.view.layer addAnimation:[self fadeFrom:0 to:1 duration:0.18] forKey:@"fade-in"];
    __weak typeof(self) weakSelf = self;
    dispatch_after(dispatch_time(DISPATCH_TIME_NOW, (int64_t)(self.maximumMS * NSEC_PER_MSEC)),
                   dispatch_get_main_queue(), ^{ [weakSelf finish:YES]; });
    [self requestSnapshot];
}

- (BOOL)prefersStatusBarHidden { return YES; }

- (CABasicAnimation *)fadeFrom:(CGFloat)from to:(CGFloat)to duration:(CFTimeInterval)duration {
    CABasicAnimation *fade = [CABasicAnimation animationWithKeyPath:@"opacity"];
    fade.fromValue = @(from); fade.toValue = @(to); fade.duration = duration;
    return fade;
}

- (UILabel *)label:(NSString *)text size:(CGFloat)size weight:(UIFontWeight)weight {
    UILabel *label = [UILabel new];
    label.text = text;
    label.textColor = UIColor.whiteColor;
    label.font = [UIFont monospacedSystemFontOfSize:size weight:weight];
    label.adjustsFontSizeToFitWidth = YES;
    label.minimumScaleFactor = .7;
    return label;
}

- (void)render {
    UIStackView *screen = [[UIStackView alloc] initWithFrame:CGRectZero];
    screen.axis = UILayoutConstraintAxisVertical;
    screen.alignment = UIStackViewAlignmentFill;
    screen.spacing = 14;
    screen.translatesAutoresizingMaskIntoConstraints = NO;
    [self.view addSubview:screen];

    UILabel *title = [self label:@"0-SKY" size:37 weight:UIFontWeightBold];
    title.textAlignment = NSTextAlignmentCenter;
    [screen addArrangedSubview:title];
    UILabel *subtitle = [self label:@"RESEARCH ENVIRONMENT" size:15 weight:UIFontWeightMedium];
    subtitle.textAlignment = NSTextAlignmentCenter;
    subtitle.textColor = [UIColor colorWithWhite:.75 alpha:1];
    [screen addArrangedSubview:subtitle];
    UIView *gap = [UIView new]; [gap.heightAnchor constraintEqualToConstant:19].active = YES;
    [screen addArrangedSubview:gap];
    NSArray<NSArray<NSString *> *> *rows = @[
        @[@"ROOT", @"root_status"], @[@"UID", @"uid"],
        @[@"BOOTSTRAP", @"bootstrap_status"],
        @[@"TRUSTED MAC", @"trusted_host_status"], @[@"SSH", @"ssh_status"],
        @[@"RUNTIME", @"runtime_status"], @[@"CONTROL", @"control_status"]];
    for (NSArray<NSString *> *row in rows) {
        NSString *key = row[1];
        NSString *flag = [@{@"uid": @"show_uid", @"bootstrap_status": @"show_bootstrap",
            @"trusted_host_status": @"show_trusted_host", @"ssh_status": @"show_ssh",
            @"runtime_status": @"show_runtime", @"control_status": @"show_control"} objectForKey:key];
        if (flag && ![self.configuration[flag] boolValue]) continue;
        UIStackView *line = [UIStackView new];
        line.axis = UILayoutConstraintAxisHorizontal;
        line.alignment = UIStackViewAlignmentCenter;
        line.distribution = UIStackViewDistributionFillEqually;
        UILabel *name = [self label:row[0] size:14 weight:UIFontWeightMedium];
        UILabel *value = [self label:@"CHECKING" size:14 weight:UIFontWeightRegular];
        value.textColor = [UIColor colorWithWhite:.7 alpha:1];
        value.textAlignment = NSTextAlignmentRight;
        [line addArrangedSubview:name]; [line addArrangedSubview:value];
        [screen addArrangedSubview:line];
        self.values[key] = value;
        if ([key isEqualToString:@"uid"]) self.uidName = name;
    }
    UIView *lowerGap = [UIView new];
    [lowerGap.heightAnchor constraintEqualToConstant:8].active = YES;
    [screen addArrangedSubview:lowerGap];
    UIStackView *progress = [UIStackView new];
    progress.axis = UILayoutConstraintAxisHorizontal;
    progress.alignment = UIStackViewAlignmentCenter;
    progress.spacing = 9;
    self.spinner = [[UIActivityIndicatorView alloc] initWithActivityIndicatorStyle:UIActivityIndicatorViewStyleMedium];
    self.spinner.color = [UIColor colorWithWhite:.6 alpha:1];
    [self.spinner startAnimating];
    [progress addArrangedSubview:self.spinner];
    self.activity = [self label:@"CHECKING 0-SKY COMPONENTS" size:11 weight:UIFontWeightRegular];
    self.activity.textColor = [UIColor colorWithWhite:.62 alpha:1];
    [progress addArrangedSubview:self.activity];
    UIView *progressHolder = [UIView new];
    progress.translatesAutoresizingMaskIntoConstraints = NO;
    [progressHolder addSubview:progress];
    [NSLayoutConstraint activateConstraints:@[
        [progress.centerXAnchor constraintEqualToAnchor:progressHolder.centerXAnchor],
        [progress.topAnchor constraintEqualToAnchor:progressHolder.topAnchor],
        [progress.bottomAnchor constraintEqualToAnchor:progressHolder.bottomAnchor]
    ]];
    [screen addArrangedSubview:progressHolder];
    self.checkProgress = [[UIProgressView alloc] initWithProgressViewStyle:UIProgressViewStyleDefault];
    self.checkProgress.progress = 0;
    self.checkProgress.progressTintColor = [ZSLinkTheme currentTheme].accentColor;
    self.checkProgress.trackTintColor = [UIColor colorWithWhite:.22 alpha:1];
    UIView *barHolder = [UIView new];
    self.checkProgress.translatesAutoresizingMaskIntoConstraints = NO;
    [barHolder addSubview:self.checkProgress];
    [NSLayoutConstraint activateConstraints:@[
        [self.checkProgress.centerXAnchor constraintEqualToAnchor:barHolder.centerXAnchor],
        [self.checkProgress.centerYAnchor constraintEqualToAnchor:barHolder.centerYAnchor],
        [self.checkProgress.widthAnchor constraintEqualToConstant:250],
        [barHolder.heightAnchor constraintEqualToConstant:12]
    ]];
    [screen addArrangedSubview:barHolder];
    self.footer = [self label:@"0-SKY RESEARCH ENVIRONMENT" size:11 weight:UIFontWeightRegular];
    self.footer.textColor = [UIColor colorWithWhite:.57 alpha:1];
    self.footer.textAlignment = NSTextAlignmentCenter;
    [screen addArrangedSubview:self.footer];
    UILayoutGuide *safe = self.view.safeAreaLayoutGuide;
    [NSLayoutConstraint activateConstraints:@[
        [screen.centerYAnchor constraintEqualToAnchor:safe.centerYAnchor],
        [screen.leadingAnchor constraintGreaterThanOrEqualToAnchor:safe.leadingAnchor constant:25],
        [screen.trailingAnchor constraintLessThanOrEqualToAnchor:safe.trailingAnchor constant:-25],
        [screen.centerXAnchor constraintEqualToAnchor:safe.centerXAnchor],
        [screen.widthAnchor constraintLessThanOrEqualToConstant:440]
    ]];
}

- (void)requestSnapshot {
    if (self.dismissed) return;
    self.attempts += 1;
    NSString *token = [NSString stringWithContentsOfFile:@"/var/jb/etc/trollstorelite-srd-bridge.token"
                                                encoding:NSUTF8StringEncoding error:nil];
    token = [token stringByTrimmingCharactersInSet:NSCharacterSet.whitespaceAndNewlineCharacterSet];
    if (!token.length) { [self unavailable]; return; }
    NSMutableURLRequest *request = [NSMutableURLRequest requestWithURL:[NSURL URLWithString:ZSStatusURL]];
    request.timeoutInterval = MIN(1.1, self.maximumMS / 1000.0);
    [request setValue:token forHTTPHeaderField:@"X-TrollStore-Bridge-Token"];
    __weak typeof(self) weakSelf = self;
    self.task = [NSURLSession.sharedSession dataTaskWithRequest:request completionHandler:
        ^(NSData *data, NSURLResponse *response, NSError *error) {
            NSDictionary *json = (!error && [(NSHTTPURLResponse *)response statusCode] == 200 && data)
                ? [NSJSONSerialization JSONObjectWithData:data options:0 error:nil] : nil;
            dispatch_async(dispatch_get_main_queue(), ^{
                ZSSplashController *strongSelf = weakSelf;
                if (!strongSelf || strongSelf.dismissed) return;
                if (![json isKindOfClass:NSDictionary.class]) { [strongSelf unavailable]; return; }
                [strongSelf applySnapshot:json];
                BOOL needsRecheck = ![json[@"trusted_host_status"] isEqual:@"VERIFIED"] ||
                    ![json[@"ssh_status"] isEqual:@"READY"] ||
                    ![json[@"bootstrap_status"] isEqual:@"ACTIVE"] ||
                    ![json[@"runtime_status"] isEqual:@"ACTIVE"] ||
                    ![json[@"control_status"] isEqual:@"ACTIVE"];
                if (needsRecheck) {
                    if ([json[@"trusted_host_status"] isEqual:@"PAIRED"])
                        strongSelf.activity.text = @"RECHECKING SAVED MAC PAIRING";
                    else if (![json[@"trusted_host_status"] isEqual:@"VERIFIED"])
                        strongSelf.activity.text = @"CHECKING TRUSTED MAC";
                    else if (![json[@"ssh_status"] isEqual:@"READY"])
                        strongSelf.activity.text = @"RECHECKING SSH ENDPOINT";
                    else if (![json[@"bootstrap_status"] isEqual:@"ACTIVE"])
                        strongSelf.activity.text = @"RECHECKING BOOTSTRAP";
                    else strongSelf.activity.text = @"CHECKING RESEARCH SERVICES";
                    [strongSelf retryOrFinish];
                } else {
                    strongSelf.activity.text = @"COMPONENT CHECK COMPLETE";
                    [strongSelf.spinner stopAnimating];
                    [strongSelf finish:NO];
                }
            });
        }];
    [self.task resume];
}

- (void)applySnapshot:(NSDictionary *)snapshot {
    self.lastSnapshot = snapshot;
    NSUInteger checked = 0;
    for (NSString *key in @[@"root_status", @"bootstrap_status", @"trusted_host_status",
                            @"ssh_status", @"runtime_status", @"control_status"]) {
        NSString *value = [snapshot[key] isKindOfClass:NSString.class] ? snapshot[key] : @"UNKNOWN";
        static NSSet *allowed;
        static dispatch_once_t once;
        dispatch_once(&once, ^{ allowed = [NSSet setWithArray:@[@"UNKNOWN", @"CHECKING", @"ACTIVE",
            @"INACTIVE", @"READY", @"VERIFIED", @"PAIRED", @"NOT_VERIFIED",
            @"DEGRADED", @"FAILED", @"TIMEOUT", @"STARTING"]]; });
        if (![allowed containsObject:value]) value = @"UNKNOWN";
        if (![value isEqualToString:@"UNKNOWN"] && ![value isEqualToString:@"CHECKING"] &&
            ![value isEqualToString:@"TIMEOUT"]) checked += 1;
        self.values[key].text = [value isEqualToString:@"NOT_VERIFIED"] ? @"NOT VERIFIED" : value;
        if ([value isEqualToString:@"ACTIVE"] || [value isEqualToString:@"READY"] ||
            [value isEqualToString:@"VERIFIED"]) self.values[key].textColor = [ZSLinkTheme currentTheme].accentColor;
    }
    [self.checkProgress setProgress:checked / 6.0f animated:YES];
    self.checkProgress.accessibilityValue = [NSString stringWithFormat:@"%lu of 6 checks complete",
        (unsigned long)checked];
    NSNumber *uid = [snapshot[@"uid"] isKindOfClass:NSNumber.class] ? snapshot[@"uid"] : nil;
    NSNumber *euid = [snapshot[@"euid"] isKindOfClass:NSNumber.class] ? snapshot[@"euid"] : nil;
    if (uid && euid && ![uid isEqual:euid]) {
        self.uidName.text = @"UID / EUID";
        self.values[@"uid"].text = [NSString stringWithFormat:@"%@ / %@", uid, euid];
    } else {
        self.values[@"uid"].text = uid ? uid.stringValue : @"UNKNOWN";
    }
    if ([snapshot[@"device_mode"] isEqual:@"AUTHORIZED_SRD"])
        self.footer.text = @"AUTHORIZED SECURITY RESEARCH DEVICE";
}

- (void)unavailable {
    if (self.dismissed) return;
    for (UILabel *value in self.values.allValues) value.text = @"UNKNOWN";
    self.footer.text = @"0-SKY RESEARCH ENVIRONMENT";
    NSLog(@"[0-Sky Splash] bridge=unavailable");
    self.activity.text = @"RECONNECTING TO LOCAL BRIDGE";
    [self retryOrFinish];
}

- (void)retryOrFinish {
    NSTimeInterval elapsed = (CACurrentMediaTime() - self.started) * 1000.0;
    if (self.attempts >= 3 || elapsed + 850 >= self.maximumMS) {
        [self.spinner stopAnimating];
        [self finish:NO];
        return;
    }
    __weak typeof(self) weakSelf = self;
    dispatch_after(dispatch_time(DISPATCH_TIME_NOW, 650 * NSEC_PER_MSEC),
                   dispatch_get_main_queue(), ^{ [weakSelf requestSnapshot]; });
}

- (BOOL)needsRecoveryChoice {
    NSDictionary *state = self.lastSnapshot;
    return ![state[@"root_status"] isEqual:@"ACTIVE"] ||
        ![state[@"bootstrap_status"] isEqual:@"ACTIVE"] ||
        ![state[@"trusted_host_status"] isEqual:@"VERIFIED"] ||
        ![state[@"ssh_status"] isEqual:@"READY"] ||
        ![state[@"runtime_status"] isEqual:@"ACTIVE"] ||
        ![state[@"control_status"] isEqual:@"ACTIVE"];
}

- (void)finish:(BOOL)immediate {
    if (self.dismissed) return;
    NSTimeInterval elapsed = (CACurrentMediaTime() - self.started) * 1000.0;
    NSUInteger remaining = immediate ? 0 : (elapsed < self.minimumMS ? self.minimumMS - (NSUInteger)elapsed : 0);
    // The absolute watchdog always wins, even if the configured minimum is met late.
    if (elapsed + remaining > self.maximumMS) remaining = 0;
    if (remaining) {
        __weak typeof(self) weakSelf = self;
        dispatch_after(dispatch_time(DISPATCH_TIME_NOW, (int64_t)(remaining * NSEC_PER_MSEC)),
                       dispatch_get_main_queue(), ^{ [weakSelf finish:YES]; });
        return;
    }
    self.dismissed = YES;
    [self.task cancel];
    NSLog(@"[0-Sky Splash] duration_ms=%ld dismissed", (long)elapsed);
    [UIView animateWithDuration:0.12 animations:^{ self.view.alpha = 0; }
                     completion:^(BOOL finished) {
        if (self.onDismiss) self.onDismiss();
    }];
}

@end
