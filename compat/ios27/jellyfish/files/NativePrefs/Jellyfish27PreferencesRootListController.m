#import <Preferences/PSListController.h>

@interface Jellyfish27PreferencesRootListController : PSListController
@end

@implementation Jellyfish27PreferencesRootListController
- (NSArray *)specifiers {
    if (!_specifiers) {
        _specifiers = [self loadSpecifiersFromPlistName:@"Root" target:self];
    }
    return _specifiers;
}
@end

