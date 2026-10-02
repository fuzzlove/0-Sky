#import <UIKit/UIKit.h>

NS_ASSUME_NONNULL_BEGIN

// Presentation only. Theme selection never changes a runtime or trust state.
@interface ZSLinkTheme : NSObject
@property (nonatomic, copy, readonly) NSString *identifier;
@property (nonatomic, copy, readonly) NSString *name;
@property (nonatomic, strong, readonly) UIColor *backgroundColor;
@property (nonatomic, strong, readonly) UIColor *panelColor;
@property (nonatomic, strong, readonly) UIColor *accentColor;
@property (nonatomic, strong, readonly) UIColor *trackColor;
@property (nonatomic, strong, readonly) UIColor *borderColor;

+ (NSArray<ZSLinkTheme *> *)availableThemes;
+ (ZSLinkTheme *)currentTheme;
+ (void)selectTheme:(ZSLinkTheme *)theme;
+ (void)presentPickerFrom:(UIViewController *)controller
                   anchor:(UIView *)anchor
                 onChange:(void (^)(void))onChange;
@end

NS_ASSUME_NONNULL_END
