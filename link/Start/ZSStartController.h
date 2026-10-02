#import <UIKit/UIKit.h>

NS_ASSUME_NONNULL_BEGIN

@interface ZSStartController : UIViewController
@property (nonatomic, copy, nullable) void (^onStart)(void);
@end

NS_ASSUME_NONNULL_END
