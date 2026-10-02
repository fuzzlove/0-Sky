#import "TSInlinePreferenceTableViewController.h"
#import "TSDoodlePatternRecorderViewController.h"
#import <TSUtil.h>

@interface TSInlinePreferenceTableViewController ()
@property(nonatomic,copy) NSString* descriptorPath;
@property(nonatomic,strong) NSArray<NSDictionary*>* items;
@property(nonatomic,assign) BOOL bundleHosted;
@property(nonatomic,assign) BOOL doodleBundle;
@property(nonatomic,assign) BOOL doodleIncompatible;
@end

@implementation TSInlinePreferenceTableViewController

+ (NSDictionary*)descriptorAtPath:(NSString*)path
{
    if(!path.length) return nil;
    NSString* resolved = path.stringByResolvingSymlinksInPath;
    NSArray<NSString*>* permittedDirectories = @[
        @"/var/jb/Library/PreferenceLoader/Preferences",
        @"/var/jb/Library/PreferenceBundles"
    ];
    NSString* bundledDoodle = [NSBundle.mainBundle pathForResource:@"DoodleControl" ofType:@"plist"];
    BOOL permitted = bundledDoodle && [resolved isEqualToString:bundledDoodle.stringByResolvingSymlinksInPath];
    for(NSString* directory in permittedDirectories) {
        NSString* resolvedDirectory = directory.stringByResolvingSymlinksInPath;
        if([resolved hasPrefix:[resolvedDirectory stringByAppendingString:@"/"]]) {
            permitted = YES;
            break;
        }
    }
    if(!permitted || ![[NSFileManager defaultManager] isReadableFileAtPath:resolved])
        return nil;
    NSData* data = [NSData dataWithContentsOfFile:resolved];
    if(!data || data.length > 128 * 1024) return nil;
    NSError* error = nil;
    id value = [NSPropertyListSerialization propertyListWithData:data
        options:NSPropertyListImmutable format:nil error:&error];
    return [value isKindOfClass:NSDictionary.class] ? value : nil;
}

+ (NSArray<NSDictionary*>*)itemsForDescriptor:(NSDictionary*)descriptor
                         bundleHosted:(BOOL*)bundleHosted
{
    NSArray* direct = descriptor[@"items"];
    if([direct isKindOfClass:NSArray.class] && direct.count && direct.count <= 256) {
        if(bundleHosted) *bundleHosted = NO;
        return direct;
    }
    NSDictionary* entry = [descriptor[@"entry"] isKindOfClass:NSDictionary.class]
        ? descriptor[@"entry"] : nil;
    NSString* bundle = [entry[@"bundle"] isKindOfClass:NSString.class]
        ? entry[@"bundle"] : nil;
    if(![bundle isKindOfClass:NSString.class] || !bundle.length || bundle.length > 100) return nil;
    NSCharacterSet* allowed = [NSCharacterSet characterSetWithCharactersInString:
        @"abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789._-"];
    if([bundle rangeOfCharacterFromSet:allowed.invertedSet].location != NSNotFound ||
       [bundle isEqualToString:@"."] || [bundle isEqualToString:@".."])
        return nil;
    NSString* path = [NSString stringWithFormat:
        @"/var/jb/Library/PreferenceBundles/%@.bundle/Root.plist", bundle];
    NSDictionary* root = [self descriptorAtPath:path];
    NSArray* items = root[@"items"];
    if(![items isKindOfClass:NSArray.class] || !items.count || items.count > 256) return nil;
    if(bundleHosted) *bundleHosted = YES;
    return items;
}

+ (BOOL)isEditableSpecifier:(NSDictionary*)item
{
    NSString* domain = item[@"defaults"];
    NSString* key = item[@"key"];
    if(![domain isKindOfClass:NSString.class] || !domain.length || domain.length > 128 ||
       ![key isKindOfClass:NSString.class] || !key.length || key.length > 128)
        return NO;
    NSString* cell = item[@"cell"];
    NSString* custom = item[@"cellClass"];
    if([cell isEqualToString:@"PSSwitchCell"] ||
       [cell isEqualToString:@"PSEditTextCell"] ||
       [cell isEqualToString:@"PSSecureEditTextCell"] ||
       [custom isEqualToString:@"DDLStepperCell"])
        return YES;
    NSArray* values = [item[@"values"] isKindOfClass:NSArray.class] ? item[@"values"] : nil;
    NSArray* titles = [item[@"titles"] isKindOfClass:NSArray.class] ? item[@"titles"] : nil;
    return (values.count && values.count == titles.count && values.count <= 32 &&
            ([cell isEqualToString:@"PSLinkListCell"] ||
             [custom isEqualToString:@"DDLSelectorCell"]));
}

+ (BOOL)canOpenDescriptorAtPath:(NSString*)descriptorPath
{
    NSString* bundledDoodle = [NSBundle.mainBundle pathForResource:@"DoodleControl" ofType:@"plist"];
    BOOL ownDoodle = bundledDoodle && [descriptorPath.stringByResolvingSymlinksInPath
        isEqualToString:bundledDoodle.stringByResolvingSymlinksInPath];
    BOOL bundleHosted = NO;
    NSArray* items = [self itemsForDescriptor:[self descriptorAtPath:descriptorPath]
                               bundleHosted:&bundleHosted];
    if(![items isKindOfClass:NSArray.class] || !items.count) return NO;
    NSSet* supported = [NSSet setWithArray:@[
        @"PSGroupCell", @"PSSwitchCell", @"PSEditTextCell", @"PSSecureEditTextCell"
    ]];
    for(id candidate in items) {
        if(![candidate isKindOfClass:NSDictionary.class]) return NO;
        NSString* cell = candidate[@"cell"];
        if(bundleHosted) continue;
        if(ownDoodle && [candidate[@"id"] isEqualToString:@"recordingController"] &&
           [candidate[@"defaults"] isEqualToString:@"com.nahtedetihw.doodleprefs"] &&
           [cell isEqualToString:@"PSLinkCell"]) continue;
        if(ownDoodle && [self isEditableSpecifier:candidate]) continue;
        if(![cell isKindOfClass:NSString.class] || ![supported containsObject:cell]) return NO;
        if(![cell isEqualToString:@"PSGroupCell"] && ![self isEditableSpecifier:candidate]) return NO;
    }
    if(!bundleHosted) return YES;
    for(NSDictionary* item in items)
        if([item isKindOfClass:NSDictionary.class] && [self isEditableSpecifier:item]) return YES;
    return NO;
}

- (instancetype)initWithDescriptorPath:(NSString*)descriptorPath title:(NSString*)title
{
    self = [super initWithStyle:UITableViewStyleInsetGrouped];
    if(self) {
        _descriptorPath = descriptorPath.copy;
        NSDictionary* descriptor = [self.class descriptorAtPath:descriptorPath];
        BOOL bundleHosted = NO;
        NSArray* items = [self.class itemsForDescriptor:descriptor bundleHosted:&bundleHosted];
        _items = [items isKindOfClass:NSArray.class] ? items : @[];
        _bundleHosted = bundleHosted;
        NSDictionary* entry = [descriptor[@"entry"] isKindOfClass:NSDictionary.class]
            ? descriptor[@"entry"] : nil;
        NSString* bundledDoodle = [NSBundle.mainBundle pathForResource:@"DoodleControl" ofType:@"plist"];
        _doodleBundle = [entry[@"bundle"] isEqualToString:@"doodleprefs"] ||
            (bundledDoodle && [descriptorPath.stringByResolvingSymlinksInPath
                isEqualToString:bundledDoodle.stringByResolvingSymlinksInPath]);
        _doodleIncompatible = _doodleBundle &&
            NSProcessInfo.processInfo.operatingSystemVersion.majorVersion >= 27;
        self.title = title.length ? title : @"Tweak Settings";
        if(_doodleIncompatible)
            self.navigationItem.prompt = @"Doodle iOS 27 runtime test pending";
    }
    return self;
}

- (id)valueForSpecifier:(NSDictionary*)specifier
{
    NSString* domain = specifier[@"defaults"];
    NSString* key = specifier[@"key"];
    NSUserDefaults* defaults = [[NSUserDefaults alloc] initWithSuiteName:domain];
    id value = [defaults objectForKey:key];
    return value ?: specifier[@"default"];
}

- (BOOL)isChoiceSpecifier:(NSDictionary*)item
{
    return [item[@"values"] isKindOfClass:NSArray.class] &&
        [item[@"titles"] isKindOfClass:NSArray.class] &&
        [item[@"values"] count] == [item[@"titles"] count] &&
        [self.class isEditableSpecifier:item] &&
        ![item[@"cell"] isEqualToString:@"PSSwitchCell"];
}

- (BOOL)isDoodleRecorderSpecifier:(NSDictionary*)item
{
    return self.doodleBundle &&
        [item[@"id"] isEqualToString:@"recordingController"] &&
        [item[@"defaults"] isEqualToString:@"com.nahtedetihw.doodleprefs"];
}

- (void)setValue:(id)value forSpecifier:(NSDictionary*)specifier
{
    NSString* domain = specifier[@"defaults"];
    NSString* key = specifier[@"key"];
    if(![domain isKindOfClass:NSString.class] || ![key isKindOfClass:NSString.class] ||
       !domain.length || !key.length || [domain hasPrefix:@"com.apple."])
        return;
    NSUserDefaults* defaults = [[NSUserDefaults alloc] initWithSuiteName:domain];
    [defaults setObject:value forKey:key];
    [defaults synchronize];
    NSString* notification = specifier[@"PostNotification"];
    if([notification isKindOfClass:NSString.class] &&
       [notification hasPrefix:domain] && notification.length > domain.length) {
        CFNotificationCenterPostNotification(CFNotificationCenterGetDarwinNotifyCenter(),
            (__bridge CFStringRef)notification, NULL, NULL, true);
    }
}

- (NSInteger)numberOfSectionsInTableView:(UITableView*)tableView
{
    (void)tableView;
    return 1;
}

- (NSString*)tableView:(UITableView*)tableView titleForFooterInSection:(NSInteger)section
{
    (void)tableView; (void)section;
    if(self.doodleIncompatible)
        return self.doodlePortVerified
            ? @"The private iOS 27 port passed this device's lock-screen checks. "
              @"The normal passcode keypad remains available."
            : @"Doodle's iOS 27 lock-screen behavior needs a successful local test. "
              @"You can record a pattern here while runtime verification is pending.";
    return self.bundleHosted ? @"Custom controls that need the tweak's native code are shown as unavailable." : nil;
}

- (void)viewWillAppear:(BOOL)animated
{
    [super viewWillAppear:animated];
    if(self.doodleIncompatible)
        self.navigationItem.prompt = self.doodlePortVerified
            ? @"Doodle verified on this device"
            : @"Doodle iOS 27 runtime test pending";
    [self.tableView reloadData];
}

- (NSInteger)tableView:(UITableView*)tableView numberOfRowsInSection:(NSInteger)section
{
    (void)tableView; (void)section;
    return self.items.count;
}

- (UITableViewCell*)tableView:(UITableView*)tableView cellForRowAtIndexPath:(NSIndexPath*)indexPath
{
    NSDictionary* item = self.items[indexPath.row];
    NSString* cellType = item[@"cell"];
    NSString* custom = item[@"cellClass"];
    UITableViewCell* cell = [[UITableViewCell alloc] initWithStyle:UITableViewCellStyleSubtitle
        reuseIdentifier:nil];
    cell.textLabel.text = [item[@"label"] isKindOfClass:NSString.class] ? item[@"label"] : @"";
    cell.selectionStyle = UITableViewCellSelectionStyleNone;
    cell.detailTextLabel.text = self.bundleHosted && [item[@"subtitle"] isKindOfClass:NSString.class]
        ? item[@"subtitle"] : nil;
    cell.detailTextLabel.numberOfLines = 2;

    if([cellType isEqualToString:@"PSGroupCell"]) {
        cell.textLabel.font = [UIFont preferredFontForTextStyle:UIFontTextStyleFootnote];
        cell.textLabel.textColor = UIColor.secondaryLabelColor;
    } else if([cellType isEqualToString:@"PSSwitchCell"]) {
        UISwitch* toggle = [UISwitch new];
        toggle.tag = indexPath.row;
        id value = [self valueForSpecifier:item];
        toggle.on = [value respondsToSelector:@selector(boolValue)] ? [value boolValue] : NO;
        if(self.doodleIncompatible && !self.doodlePortVerified &&
           [item[@"key"] isEqualToString:@"enabled"]) {
            toggle.enabled = NO;
            cell.detailTextLabel.text = @"Available after this device passes lock-screen UAT";
        }
        [toggle addTarget:self action:@selector(switchChanged:) forControlEvents:UIControlEventValueChanged];
        cell.accessoryView = toggle;
    } else if([self isDoodleRecorderSpecifier:item]) {
        cell.detailTextLabel.text = @"Draw and save three matching patterns in 0-Sky Control";
        cell.accessoryType = UITableViewCellAccessoryDisclosureIndicator;
        cell.selectionStyle = UITableViewCellSelectionStyleDefault;
    } else if([self isChoiceSpecifier:item]) {
        NSArray* values = item[@"values"];
        NSArray* titles = item[@"titles"];
        NSUInteger position = [values indexOfObject:[self valueForSpecifier:item] ?: [NSNull null]];
        cell.detailTextLabel.text = position < titles.count && [titles[position] isKindOfClass:NSString.class]
            ? titles[position] : @"Choose a value";
        cell.accessoryType = UITableViewCellAccessoryDisclosureIndicator;
        cell.selectionStyle = UITableViewCellSelectionStyleDefault;
    } else if([custom isEqualToString:@"DDLStepperCell"] &&
              [self.class isEditableSpecifier:item]) {
        UIStepper* stepper = [UIStepper new];
        stepper.tag = indexPath.row;
        stepper.minimumValue = [item[@"min"] respondsToSelector:@selector(doubleValue)]
            ? [item[@"min"] doubleValue] : 0;
        stepper.maximumValue = [item[@"max"] respondsToSelector:@selector(doubleValue)]
            ? [item[@"max"] doubleValue] : 100;
        stepper.value = [[self valueForSpecifier:item] doubleValue];
        [stepper addTarget:self action:@selector(stepperChanged:)
            forControlEvents:UIControlEventValueChanged];
        UILabel* value = [UILabel new];
        value.text = [NSString stringWithFormat:@"%.0f", stepper.value];
        UIStackView* controls = [[UIStackView alloc] initWithArrangedSubviews:@[value, stepper]];
        controls.axis = UILayoutConstraintAxisHorizontal;
        controls.spacing = 8;
        cell.accessoryView = controls;
    } else if([cellType isEqualToString:@"PSEditTextCell"] ||
              [cellType isEqualToString:@"PSSecureEditTextCell"]) {
        UITextField* field = [[UITextField alloc] initWithFrame:CGRectMake(0, 0, 260, 34)];
        field.tag = indexPath.row;
        field.delegate = self;
        field.textAlignment = NSTextAlignmentRight;
        field.autocorrectionType = UITextAutocorrectionTypeNo;
        field.autocapitalizationType = UITextAutocapitalizationTypeNone;
        field.clearButtonMode = UITextFieldViewModeWhileEditing;
        field.secureTextEntry = [cellType isEqualToString:@"PSSecureEditTextCell"];
        id value = [self valueForSpecifier:item];
        if([value isKindOfClass:NSString.class]) field.text = value;
        cell.accessoryView = field;
    } else {
        cell.detailTextLabel.text = @"Requires the tweak's native iOS 27 preference controller";
        cell.detailTextLabel.textColor = UIColor.secondaryLabelColor;
        cell.selectionStyle = UITableViewCellSelectionStyleDefault;
    }
    return cell;
}

- (void)stepperChanged:(UIStepper*)sender
{
    if(sender.tag < 0 || sender.tag >= (NSInteger)self.items.count) return;
    [self setValue:@(sender.value) forSpecifier:self.items[sender.tag]];
    [self.tableView reloadRowsAtIndexPaths:@[[NSIndexPath indexPathForRow:sender.tag inSection:0]]
        withRowAnimation:UITableViewRowAnimationNone];
}

- (void)tableView:(UITableView*)tableView didSelectRowAtIndexPath:(NSIndexPath*)indexPath
{
    [tableView deselectRowAtIndexPath:indexPath animated:YES];
    NSDictionary* item = self.items[indexPath.row];
    if([self isDoodleRecorderSpecifier:item]) {
        [self.navigationController pushViewController:
            [TSDoodlePatternRecorderViewController new] animated:YES];
    } else if([self isChoiceSpecifier:item]) {
        UIAlertController* picker = [UIAlertController alertControllerWithTitle:item[@"label"]
            message:nil preferredStyle:UIAlertControllerStyleActionSheet];
        NSArray* values = item[@"values"];
        NSArray* titles = item[@"titles"];
        for(NSUInteger index = 0; index < values.count; index++) {
            id value = values[index];
            NSString* title = [titles[index] isKindOfClass:NSString.class]
                ? titles[index] : [value description];
            [picker addAction:[UIAlertAction actionWithTitle:title
                style:UIAlertActionStyleDefault handler:^(UIAlertAction* action) {
                    (void)action;
                    [self setValue:value forSpecifier:item];
                    [self.tableView reloadRowsAtIndexPaths:@[indexPath]
                        withRowAnimation:UITableViewRowAnimationNone];
                }]];
        }
        [picker addAction:[UIAlertAction actionWithTitle:@"Cancel"
            style:UIAlertActionStyleCancel handler:nil]];
        picker.popoverPresentationController.sourceView = tableView;
        picker.popoverPresentationController.sourceRect = [tableView rectForRowAtIndexPath:indexPath];
        [self presentViewController:picker animated:YES completion:nil];
    } else if(![self.class isEditableSpecifier:item] &&
              ![item[@"cell"] isEqualToString:@"PSGroupCell"]) {
        UIAlertController* alert = [UIAlertController alertControllerWithTitle:item[@"label"] ?: @"Custom control"
            message:@"This control needs the tweak's native preference code. It cannot be used until an iOS 27 adaptation passes testing."
            preferredStyle:UIAlertControllerStyleAlert];
        [alert addAction:[UIAlertAction actionWithTitle:@"OK" style:UIAlertActionStyleDefault handler:nil]];
        [self presentViewController:alert animated:YES completion:nil];
    }
}

- (void)switchChanged:(UISwitch*)sender
{
    if(sender.tag < 0 || sender.tag >= (NSInteger)self.items.count) return;
    NSDictionary* item = self.items[sender.tag];
    if(self.doodleBundle && [item[@"key"] isEqualToString:@"enabled"]) {
        if(!self.doodlePortVerified) {
            [sender setOn:NO animated:YES];
            return;
        }
        BOOL requested = sender.on;
        UIAlertController* alert = [UIAlertController alertControllerWithTitle:
            requested ? @"Enable Doodle" : @"Disable Doodle"
            message:@"SpringBoard must restart to apply this change. The normal passcode keypad remains available."
            preferredStyle:UIAlertControllerStyleAlert];
        [alert addAction:[UIAlertAction actionWithTitle:@"Cancel"
            style:UIAlertActionStyleCancel handler:^(UIAlertAction* action) {
                (void)action;
                [sender setOn:!requested animated:YES];
            }]];
        [alert addAction:[UIAlertAction actionWithTitle:@"Apply and Restart"
            style:UIAlertActionStyleDefault handler:^(UIAlertAction* action) {
                (void)action;
                [self setValue:@(requested) forSpecifier:item];
                NSUserDefaults* check = [[NSUserDefaults alloc]
                    initWithSuiteName:@"com.nahtedetihw.doodleprefs"];
                [check synchronize];
                if([[check objectForKey:@"enabled"] boolValue] != requested) {
                    [sender setOn:!requested animated:YES];
                    UIAlertController* failure = [UIAlertController alertControllerWithTitle:
                        @"Doodle setting not saved" message:@"The preference could not be verified. Try again."
                        preferredStyle:UIAlertControllerStyleAlert];
                    [failure addAction:[UIAlertAction actionWithTitle:@"OK"
                        style:UIAlertActionStyleDefault handler:nil]];
                    [self presentViewController:failure animated:YES completion:nil];
                    return;
                }
                respring();
            }]];
        [self presentViewController:alert animated:YES completion:nil];
        return;
    }
    [self setValue:@(sender.on) forSpecifier:item];
}

- (void)textFieldDidEndEditing:(UITextField*)textField
{
    if(textField.tag < 0 || textField.tag >= (NSInteger)self.items.count) return;
    [self setValue:textField.text ?: @"" forSpecifier:self.items[textField.tag]];
}

- (BOOL)textFieldShouldReturn:(UITextField*)textField
{
    [textField resignFirstResponder];
    return YES;
}

@end
