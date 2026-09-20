#import <Foundation/Foundation.h>

NS_ASSUME_NONNULL_BEGIN

/// Central path resolver for new 0-Sky Control/0-Sky features. Existing legacy
/// paths are migrated into this boundary incrementally.
@interface TSRootlessPaths : NSObject
+ (NSString*)rootPrefix;
+ (NSString*)jailbreakPath:(NSString*)absoluteSuffix;
+ (NSString*)configDirectory;
+ (NSString*)stateDirectory;
+ (NSString*)logDirectory;
+ (NSString*)snapshotDirectory;
+ (NSString*)databasePath;
+ (NSString*)temporaryDirectory;
+ (NSString*)bridgeTokenPath;
+ (NSURL*)coreEndpointURL;
@end

NS_ASSUME_NONNULL_END
