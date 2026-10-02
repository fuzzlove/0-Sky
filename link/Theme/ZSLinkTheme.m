#import "ZSLinkTheme.h"

static NSString *const ZSThemePreference = @"ZeroSkyLinkThemeID";

static UIColor *ZSColor(unsigned int rgb) {
    return [UIColor colorWithRed:((rgb >> 16) & 255) / 255.0
                           green:((rgb >> 8) & 255) / 255.0
                            blue:(rgb & 255) / 255.0 alpha:1];
}

@interface ZSLinkTheme ()
@property (nonatomic, copy, readwrite) NSString *identifier;
@property (nonatomic, copy, readwrite) NSString *name;
@property (nonatomic, strong, readwrite) UIColor *backgroundColor;
@property (nonatomic, strong, readwrite) UIColor *panelColor;
@property (nonatomic, strong, readwrite) UIColor *accentColor;
@property (nonatomic, strong, readwrite) UIColor *trackColor;
@property (nonatomic, strong, readwrite) UIColor *borderColor;
@end

@implementation ZSLinkTheme

- (instancetype)initWithID:(NSString *)identifier name:(NSString *)name
                background:(unsigned int)background panel:(unsigned int)panel
                    accent:(unsigned int)accent track:(unsigned int)track
                    border:(unsigned int)border {
    if ((self = [super init])) {
        _identifier = [identifier copy];
        _name = [name copy];
        _backgroundColor = ZSColor(background);
        _panelColor = ZSColor(panel);
        _accentColor = ZSColor(accent);
        _trackColor = ZSColor(track);
        _borderColor = ZSColor(border);
    }
    return self;
}

+ (NSArray<ZSLinkTheme *> *)availableThemes {
    static NSArray<ZSLinkTheme *> *themes;
    static dispatch_once_t once;
    dispatch_once(&once, ^{
        themes = @[
            [[ZSLinkTheme alloc] initWithID:@"ocean" name:@"Ocean Blue"
                background:0x061422 panel:0x0B253A accent:0x68C7FF
                track:0x17384F border:0x37688A],
            [[ZSLinkTheme alloc] initWithID:@"classic" name:@"Classic Green"
                background:0x000000 panel:0x06170C accent:0x5DFF8B
                track:0x0D3B1D border:0x358456],
            [[ZSLinkTheme alloc] initWithID:@"ember" name:@"Ember Red"
                background:0x190C09 panel:0x2A1711 accent:0xFF9C75
                track:0x4A281D border:0x9A5A44],
            [[ZSLinkTheme alloc] initWithID:@"violet" name:@"Violet"
                background:0x110B20 panel:0x201433 accent:0xC8A8FF
                track:0x392454 border:0x77559E],
            [[ZSLinkTheme alloc] initWithID:@"mono" name:@"Monochrome"
                background:0x050505 panel:0x171717 accent:0xF2F2F2
                track:0x303030 border:0x707070],
        ];
    });
    return themes;
}

+ (ZSLinkTheme *)currentTheme {
    NSString *selected = [NSUserDefaults.standardUserDefaults stringForKey:ZSThemePreference];
    for (ZSLinkTheme *theme in self.availableThemes) {
        if ([theme.identifier isEqualToString:selected]) return theme;
    }
    // Keep the established 0-Sky look until the researcher chooses a theme.
    for (ZSLinkTheme *theme in self.availableThemes) {
        if ([theme.identifier isEqualToString:@"classic"]) return theme;
    }
    return self.availableThemes.firstObject;
}

+ (void)selectTheme:(ZSLinkTheme *)theme {
    for (ZSLinkTheme *candidate in self.availableThemes) {
        if ([candidate.identifier isEqualToString:theme.identifier]) {
            [NSUserDefaults.standardUserDefaults setObject:candidate.identifier
                                                   forKey:ZSThemePreference];
            return;
        }
    }
}

+ (void)presentPickerFrom:(UIViewController *)controller
                   anchor:(UIView *)anchor
                 onChange:(void (^)(void))onChange {
    UIAlertController *picker = [UIAlertController alertControllerWithTitle:@"0-Sky Color Theme"
        message:@"Choose the look you prefer. Status and trust checks stay the same."
        preferredStyle:UIAlertControllerStyleActionSheet];
    NSString *selected = self.currentTheme.identifier;
    for (ZSLinkTheme *theme in self.availableThemes) {
        NSString *title = [theme.identifier isEqualToString:selected]
            ? [@"✓ " stringByAppendingString:theme.name] : theme.name;
        [picker addAction:[UIAlertAction actionWithTitle:title
            style:UIAlertActionStyleDefault handler:^(UIAlertAction *action) {
                [self selectTheme:theme];
                if (onChange) onChange();
            }]];
    }
    [picker addAction:[UIAlertAction actionWithTitle:@"Cancel"
        style:UIAlertActionStyleCancel handler:nil]];
    UIPopoverPresentationController *popover = picker.popoverPresentationController;
    if (popover) {
        popover.sourceView = anchor;
        popover.sourceRect = anchor.bounds;
    }
    [controller presentViewController:picker animated:YES completion:nil];
}

@end
