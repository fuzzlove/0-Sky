#import "TSRootlessPaths.h"

@implementation TSRootlessPaths

+ (NSString*)rootPrefix { return @"/var/jb"; }

+ (NSString*)jailbreakPath:(NSString*)absoluteSuffix
{
    if(![absoluteSuffix hasPrefix:@"/"] ||
       [absoluteSuffix.pathComponents containsObject:@".."]) {
        [NSException raise:NSInvalidArgumentException
                    format:@"Rootless path must be absolute and canonical: %@",
                           absoluteSuffix ?: @"(null)"];
    }
    if([absoluteSuffix isEqualToString:@"/"]) return self.rootPrefix;
    return [self.rootPrefix stringByAppendingString:absoluteSuffix];
}

+ (NSString*)configDirectory { return [self jailbreakPath:@"/etc/0sky"]; }
+ (NSString*)stateDirectory { return [self jailbreakPath:@"/var/lib/0sky"]; }
+ (NSString*)logDirectory { return [self jailbreakPath:@"/var/log/0sky"]; }
+ (NSString*)snapshotDirectory { return [self.stateDirectory stringByAppendingPathComponent:@"snapshots"]; }
+ (NSString*)databasePath { return [self.stateDirectory stringByAppendingPathComponent:@"core.sqlite3"]; }
+ (NSString*)temporaryDirectory { return [self jailbreakPath:@"/var/tmp/0sky"]; }
+ (NSString*)bridgeTokenPath
{
    // A Cryptex-registered app remains sandboxed on iOS 27 even when its
    // authorized signature carries the legacy no-sandbox entitlement. The
    // device broker publishes a mode-0600 copy into Control's dedicated data
    // directory, while retaining the root-owned source as a fallback for
    // older SRD registrations that can legitimately read /var/jb.
    NSMutableArray<NSString*>* candidates = [NSMutableArray array];
    NSString* home = NSHomeDirectory();
    if(home.length)
        [candidates addObject:[[home stringByAppendingPathComponent:@"Documents/.0sky"]
            stringByAppendingPathComponent:@"bridge.token"]];
    NSString* documents = NSSearchPathForDirectoriesInDomains(
        NSDocumentDirectory, NSUserDomainMask, YES).firstObject;
    if(documents.length)
        [candidates addObject:[[documents stringByAppendingPathComponent:@".0sky"]
            stringByAppendingPathComponent:@"bridge.token"]];
    [candidates addObject:@"/var/mobile/Library/Application Support/Containers/"
        @"com.liquidsky.CrypStore/Documents/.0sky/bridge.token"];
    for(NSString* candidate in candidates)
    {
        if([[NSFileManager defaultManager] isReadableFileAtPath:candidate])
            return candidate;
    }
    return [self jailbreakPath:@"/etc/trollstorelite-srd-bridge.token"];
}
+ (NSURL*)coreEndpointURL { return [NSURL URLWithString:@"http://127.0.0.1:48654/v1/core"]; }

@end
