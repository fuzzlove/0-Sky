#import <Foundation/Foundation.h>

NS_ASSUME_NONNULL_BEGIN

@interface TSBluetoothFallback : NSObject
+ (instancetype)sharedFallback;
- (void)start;
- (void)stop;
@property (nonatomic, readonly, getter=isAdvertising) BOOL advertising;
@property (nonatomic, readonly, getter=isAuthenticated) BOOL authenticated;
@property (nonatomic, readonly) NSString *statusText;
@end

NS_ASSUME_NONNULL_END
