#import <Preferences/PSListController.h>

@interface NeoSkyBackgroundPreferencesRootListController : PSListController
@end

@implementation NeoSkyBackgroundPreferencesRootListController
- (NSArray *)specifiers {
    if (!_specifiers) {
        _specifiers = [self loadSpecifiersFromPlistName:@"Root" target:self];
    }
    return _specifiers;
}
@end

