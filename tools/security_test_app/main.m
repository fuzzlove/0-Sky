#import <UIKit/UIKit.h>
#import <dlfcn.h>
#import <stdlib.h>
#import <string.h>

#if ZERO_SKY_EMBED_CRANE
static NSString *ZSPreMainCraneState = @"Crane preload pending";
static char *ZSInjectedCraneContainerEnvironment;
static char *ZSInjectedCraneProtectEnvironment;
static char *ZSInjectedCraneSandboxEnvironment;

static void ZSPutPersistentEnvironment(NSString *assignment, char **storage) {
    free(*storage);
    *storage = strdup(assignment.UTF8String);
    if(*storage) {
        putenv(*storage);
    }
}

__attribute__((constructor)) static void ZSLoadEmbeddedCrane(void) {
    @autoreleasepool {
        NSString *bundleIdentifier = NSBundle.mainBundle.bundleIdentifier;
        NSString *settingsKey = [@"appSettings_" stringByAppendingString:
            bundleIdentifier ?: @""];
        CFPropertyListRef value = CFPreferencesCopyAppValue(
            (__bridge CFStringRef)settingsKey,
            CFSTR("com.opa334.craneprefs"));
        NSDictionary *settings = CFBridgingRelease(value);
        NSString *container = [settings isKindOfClass:NSDictionary.class] ?
            settings[@"activeContainer"] : nil;
        if(!container.length || [container isEqualToString:@"DEFAULT"]) {
            NSString *handoff = [NSHomeDirectory() stringByAppendingPathComponent:
                @"Library/0Sky/Crane/active-container"];
            NSString *candidate = [[NSString stringWithContentsOfFile:handoff
                encoding:NSASCIIStringEncoding error:nil]
                stringByTrimmingCharactersInSet:NSCharacterSet.whitespaceAndNewlineCharacterSet];
            NSRegularExpression *uuid = [NSRegularExpression
                regularExpressionWithPattern:
                    @"^[0-9A-F]{8}-[0-9A-F]{4}-[0-9A-F]{4}-[0-9A-F]{4}-[0-9A-F]{12}$"
                options:0 error:nil];
            if([uuid numberOfMatchesInString:candidate ?: @"" options:0
                range:NSMakeRange(0, candidate.length)] == 1) {
                container = candidate;
            }
        }
        if(container.length && ![container isEqualToString:@"DEFAULT"]) {
            // Crane retains getenv() pointers across unsetenv().  Values added
            // with setenv() may be freed by that unsetenv() call, leaving an
            // empty container identifier.  putenv() uses caller-owned storage,
            // matching the stable exec-time environment Crane normally sees.
            ZSPutPersistentEnvironment([
                @"CRANE_CONTAINER_IDENTIFIER=" stringByAppendingString:container],
                &ZSInjectedCraneContainerEnvironment);
            ZSPutPersistentEnvironment(@"CRANE_PROTECT_CONTAINERS=1",
                &ZSInjectedCraneProtectEnvironment);
            ZSPutPersistentEnvironment(@"CRANE_SPOOF_SANDBOX_LOOKUPS=1",
                &ZSInjectedCraneSandboxEnvironment);
        }
        NSString *path = [[NSBundle mainBundle].bundlePath
            stringByAppendingPathComponent:@"Frameworks/Crane.dylib"];
        void *handle = dlopen(path.fileSystemRepresentation, RTLD_NOW | RTLD_GLOBAL);
        ZSPreMainCraneState = handle ? [NSString stringWithFormat:
            @"Crane preload ready (%@)", container ?: @"DEFAULT"] :
            [NSString stringWithFormat:@"Crane preload failed: %s", dlerror() ?: "unknown"];
    }
}
#else
static NSString *ZSPreMainCraneState = @"External injection fixture";
#endif

// A fixed, harmless Objective-C surface for attach and RPC checks. The app
// never selects or instruments another process.
@interface ZSSecurityProbe : NSObject
- (NSString *)echo:(NSString *)value;
- (NSNumber *)add:(NSNumber *)left to:(NSNumber *)right;
@end

@implementation ZSSecurityProbe
- (NSString *)echo:(NSString *)value {
    return [@"0sky-test:" stringByAppendingString:value ?: @""];
}
- (NSNumber *)add:(NSNumber *)left to:(NSNumber *)right {
    return @((left.integerValue) + (right.integerValue));
}
@end

@interface ZSTestController : UIViewController
@end

@implementation ZSTestController
- (void)viewDidLoad {
    [super viewDidLoad];
    self.view.backgroundColor = UIColor.blackColor;
    UILabel *label = [UILabel new];
    label.translatesAutoresizingMaskIntoConstraints = NO;
    label.textColor = UIColor.whiteColor;
    label.numberOfLines = 0;
    label.textAlignment = NSTextAlignmentCenter;
    label.font = [UIFont monospacedSystemFontOfSize:17 weight:UIFontWeightMedium];
    label.text = [NSString stringWithFormat:@"0-Sky Security Test App\n%@\n%@\nControlled research fixture",
                  [[ZSSecurityProbe new] echo:@"ready"], ZSPreMainCraneState];
    label.accessibilityIdentifier = @"zeroSkySecurityTestReady";
    [self.view addSubview:label];
    [NSLayoutConstraint activateConstraints:@[
        [label.centerXAnchor constraintEqualToAnchor:self.view.centerXAnchor],
        [label.centerYAnchor constraintEqualToAnchor:self.view.centerYAnchor],
        [label.leadingAnchor constraintGreaterThanOrEqualToAnchor:self.view.leadingAnchor constant:20],
        [label.trailingAnchor constraintLessThanOrEqualToAnchor:self.view.trailingAnchor constant:-20]
    ]];
}
@end

@interface ZSTestDelegate : UIResponder <UIApplicationDelegate>
@property(nonatomic, strong) UIWindow *window;
@end

@implementation ZSTestDelegate
- (BOOL)application:(UIApplication *)application didFinishLaunchingWithOptions:(NSDictionary *)options {
    (void)application; (void)options;
    self.window = [[UIWindow alloc] initWithFrame:UIScreen.mainScreen.bounds];
    self.window.rootViewController = [ZSTestController new];
    [self.window makeKeyAndVisible];
    return YES;
}

- (BOOL)application:(UIApplication *)application openURL:(NSURL *)url
            options:(NSDictionary<UIApplicationOpenURLOptionsKey,id> *)options {
    (void)application; (void)options;
    if(![url.scheme isEqualToString:@"zeroskytest"] ||
       ![url.host isEqualToString:@"write"]) return NO;
    NSString *token = url.lastPathComponent;
    NSCharacterSet *invalid = [[NSCharacterSet
        characterSetWithCharactersInString:
        @"abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-"] invertedSet];
    if(!token.length || token.length > 80 || [token rangeOfCharacterFromSet:invalid].location != NSNotFound)
        return NO;
    NSString *documents = [NSHomeDirectory() stringByAppendingPathComponent:@"Documents"];
    NSError *error = nil;
    if(![[NSFileManager defaultManager] createDirectoryAtPath:documents
        withIntermediateDirectories:YES attributes:nil error:&error]) return NO;
    NSString *marker = [documents stringByAppendingPathComponent:@"0sky-crane-uat.txt"];
    unsigned long (*hookCount)(void) = dlsym(RTLD_DEFAULT,
        "OSkySubstrateFunctionHookCount");
    // Always emit the same evidence shape.  A missing compatibility shim is
    // the expected default-container result and therefore means zero hooks,
    // rather than an unparsable marker.
    unsigned long hooks = hookCount ? hookCount() : 0;
    NSString *evidence = [NSString stringWithFormat:@"%@|hooks=%lu", token, hooks];
    return [evidence writeToFile:marker atomically:YES
        encoding:NSUTF8StringEncoding error:&error];
}
@end

int main(int argc, char *argv[]) {
    @autoreleasepool {
        return UIApplicationMain(argc, argv, nil, NSStringFromClass(ZSTestDelegate.class));
    }
}
