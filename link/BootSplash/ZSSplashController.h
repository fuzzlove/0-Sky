#import <UIKit/UIKit.h>

NS_ASSUME_NONNULL_BEGIN

@interface ZSSplashController : UIViewController
@property (nonatomic, copy) void (^onDismiss)(void);
@property (nonatomic, copy, readonly, nullable) NSDictionary *lastSnapshot;
+ (BOOL)isEnabled;
- (BOOL)needsRecoveryChoice;
@end

NS_ASSUME_NONNULL_END
