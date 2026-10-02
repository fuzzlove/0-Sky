#import <Foundation/Foundation.h>
#import <dlfcn.h>
#import <stdlib.h>
#import <string.h>

static char *OSkyCraneContainerEnvironment;
static char *OSkyCraneProtectEnvironment;
static char *OSkyCraneSandboxEnvironment;
static NSInteger OSkyCraneBootstrapResult;

static void OSkyPutPersistentEnvironment(NSString *assignment, char **storage) {
    free(*storage);
    *storage = strdup(assignment.UTF8String);
    if(*storage) putenv(*storage);
}

__attribute__((constructor)) static void OSkyLoadCraneBeforeMain(void) {
    @autoreleasepool {
        NSString *handoff = [NSHomeDirectory() stringByAppendingPathComponent:
            @"Library/0Sky/Crane/active-container"];
        NSString *container = [[NSString stringWithContentsOfFile:handoff
            encoding:NSASCIIStringEncoding error:nil]
            stringByTrimmingCharactersInSet:
                NSCharacterSet.whitespaceAndNewlineCharacterSet];
        NSRegularExpression *uuid = [NSRegularExpression
            regularExpressionWithPattern:
                @"^[0-9A-Fa-f]{8}(?:-[0-9A-Fa-f]{4}){3}-[0-9A-Fa-f]{12}$"
            options:0 error:nil];
        if([uuid numberOfMatchesInString:container ?: @"" options:0
            range:NSMakeRange(0, container.length)] != 1) {
            OSkyCraneBootstrapResult = 1;
            return;
        }
        OSkyPutPersistentEnvironment([
            @"CRANE_CONTAINER_IDENTIFIER=" stringByAppendingString:container],
            &OSkyCraneContainerEnvironment);
        OSkyPutPersistentEnvironment(@"CRANE_PROTECT_CONTAINERS=1",
            &OSkyCraneProtectEnvironment);
        OSkyPutPersistentEnvironment(@"CRANE_SPOOF_SANDBOX_LOOKUPS=1",
            &OSkyCraneSandboxEnvironment);
        NSString *crane = [[NSBundle mainBundle].bundlePath
            stringByAppendingPathComponent:@"Frameworks/Crane.dylib"];
        OSkyCraneBootstrapResult = dlopen(crane.fileSystemRepresentation,
            RTLD_NOW | RTLD_GLOBAL) ? 0 : 2;
    }
}

NSInteger OSkyCraneBootstrapStatus(void) {
    return OSkyCraneBootstrapResult;
}
