#import "TSDonateListController.h"
#import <Preferences/PSSpecifier.h>

@implementation TSDonateListController

- (void)openProjectRepository
{
    NSURL *url = [NSURL URLWithString:@"https://github.com/fuzzlove/0-Sky"];
    [[UIApplication sharedApplication] openURL:url options:@{} completionHandler:nil];
}

- (NSMutableArray*)specifiers
{
    if (!_specifiers) {
        _specifiers = [NSMutableArray new];
        [_specifiers addObject:[PSSpecifier emptyGroupSpecifier]];
        PSSpecifier *project = [PSSpecifier preferenceSpecifierNamed:@"Project Repository"
            target:self set:nil get:nil detail:nil cell:PSButtonCell edit:nil];
        project.identifier = @"openProjectRepository";
        [project setProperty:@YES forKey:@"enabled"];
        project.buttonAction = @selector(openProjectRepository);
        [_specifiers addObject:project];
    }
    self.navigationItem.title = @"0-Sky Project";
    return _specifiers;
}

@end
