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
+ (NSString*)bridgeTokenPath { return [self jailbreakPath:@"/etc/trollstorelite-srd-bridge.token"]; }
+ (NSURL*)coreEndpointURL { return [NSURL URLWithString:@"http://127.0.0.1:48654/v1/core"]; }

@end
