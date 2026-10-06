#import <Foundation/Foundation.h>
#import <CoreFoundation/CoreFoundation.h>
#import <unistd.h>

static NSString *const Domain = @"xyz.royalapps.jellyfish";

static int becomeMobile(void) {
    if (geteuid() == 501) return 0;
    if (geteuid() != 0) return 1;
    if (setgid(501) != 0 || setuid(501) != 0) return 1;
    return 0;
}

int main(int argc, const char *argv[]) {
    @autoreleasepool {
        if (argc != 2) {
            fprintf(stderr, "usage: jellyfish27ctl enable|disable|status\n");
            return 2;
        }
        if (becomeMobile() != 0) {
            fprintf(stderr, "could not enter the mobile preference domain\n");
            return 1;
        }
        NSString *action = [NSString stringWithUTF8String:argv[1]];
        if ([action isEqualToString:@"enable"] || [action isEqualToString:@"disable"]) {
            BOOL enabled = [action isEqualToString:@"enable"];
            CFPreferencesSetAppValue(CFSTR("enabled"),
                enabled ? kCFBooleanTrue : kCFBooleanFalse,
                (__bridge CFStringRef)Domain);
            if (!CFPreferencesAppSynchronize((__bridge CFStringRef)Domain)) {
                fprintf(stderr, "preference synchronization failed\n");
                return 1;
            }
            CFNotificationCenterPostNotification(
                CFNotificationCenterGetDarwinNotifyCenter(),
                CFSTR("xyz.royalapps.jellyfish.changed"), NULL, NULL, true);
            printf("enabled=%s\n", enabled ? "true" : "false");
            return 0;
        }
        if ([action isEqualToString:@"status"]) {
            CFPropertyListRef value = CFPreferencesCopyAppValue(
                CFSTR("enabled"), (__bridge CFStringRef)Domain);
            BOOL enabled = value && CFGetTypeID(value) == CFBooleanGetTypeID()
                ? CFBooleanGetValue(value) : false;
            if (value) CFRelease(value);
            printf("enabled=%s\n", enabled ? "true" : "false");
            return 0;
        }
        fprintf(stderr, "unknown action\n");
        return 2;
    }
}

