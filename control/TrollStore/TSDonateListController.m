#import "TSDonateListController.h"
#import <Preferences/PSSpecifier.h>

@implementation TSDonateListController

- (void)openDonateLink
{
    NSURL *url = [NSURL URLWithString:@"https://www.youtube.com/watch?v=dQw4w9WgXcQ"];
    [[UIApplication sharedApplication] openURL:url options:@{} completionHandler:nil];
}

- (NSMutableArray*)specifiers
{
    if (!_specifiers) {
        _specifiers = [NSMutableArray new];
        [_specifiers addObject:[PSSpecifier emptyGroupSpecifier]];
        PSSpecifier *project = [PSSpecifier preferenceSpecifierNamed:@"Donate"
            target:self set:nil get:nil detail:nil cell:PSButtonCell edit:nil];
        project.identifier = @"openDonateLink";
        [project setProperty:@YES forKey:@"enabled"];
        project.buttonAction = @selector(openDonateLink);
        [_specifiers addObject:project];
    }
    self.navigationItem.title = @"0-Sky Project";
    return _specifiers;
}

@end
