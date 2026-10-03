#import "TSInlinePreferenceTableViewController.h"
#import "TSDoodlePatternRecorderViewController.h"
#import <TSUtil.h>

@interface TSInlinePreferenceTableViewController ()
@property(nonatomic,copy) NSString* descriptorPath;
@property(nonatomic,strong) NSArray<NSDictionary*>* items;
@property(nonatomic,assign) BOOL bundleHosted;
@property(nonatomic,copy) NSString* bundleRoot;
@property(nonatomic,strong) NSDictionary<NSString*,NSString*>* localizations;
@property(nonatomic,assign) BOOL doodleBundle;
@property(nonatomic,assign) BOOL doodleIncompatible;
+ (NSDictionary*)descriptorAtPath:(NSString*)path;
+ (NSArray<NSDictionary*>*)itemsForDescriptor:(NSDictionary*)descriptor
                         bundleHosted:(BOOL*)bundleHosted
                            bundleRoot:(NSString**)bundleRoot;
+ (NSArray*)valuesForSpecifier:(NSDictionary*)item;
+ (NSArray*)titlesForSpecifier:(NSDictionary*)item;
+ (BOOL)isEditableSpecifier:(NSDictionary*)item;
+ (NSDictionary<NSString*,NSString*>*)localizationsForBundleRoot:(NSString*)bundleRoot;
@end

@interface TSAxonLocationViewController : UITableViewController
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
                            bundleRoot:(NSString**)bundleRoot
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
    NSString* bundleName = [bundle.pathExtension isEqualToString:@"bundle"]
        ? bundle : [bundle stringByAppendingPathExtension:@"bundle"];
    NSString* rootPath = [[@"/var/jb/Library/PreferenceBundles"
        stringByAppendingPathComponent:bundleName] stringByStandardizingPath];
    NSMutableArray<NSString*>* plistNames = [NSMutableArray array];
    NSString* requestedPlist = [entry[@"plist"] isKindOfClass:NSString.class]
        ? entry[@"plist"] : nil;
    if(requestedPlist.length && requestedPlist.length <= 100 &&
       ![requestedPlist containsString:@"/"] && ![requestedPlist isEqualToString:@"."] &&
       ![requestedPlist isEqualToString:@".."]) {
        [plistNames addObject:[requestedPlist.pathExtension isEqualToString:@"plist"]
            ? requestedPlist : [requestedPlist stringByAppendingPathExtension:@"plist"]];
    }
    // PreferenceLoader conventionally uses Root.plist, but older panes such
    // as Axon publish their data-only form as Prefs.plist instead.
    for(NSString* fallback in @[@"Root.plist", @"Prefs.plist"])
        if(![plistNames containsObject:fallback]) [plistNames addObject:fallback];
    for(NSString* plistName in plistNames) {
        NSDictionary* root = [self descriptorAtPath:
            [rootPath stringByAppendingPathComponent:plistName]];
        NSArray* items = root[@"items"];
        if(![items isKindOfClass:NSArray.class] || !items.count || items.count > 256)
            continue;
        if(bundleHosted) *bundleHosted = YES;
        if(bundleRoot) *bundleRoot = rootPath;
        return items;
    }
    return nil;
}

+ (NSArray*)valuesForSpecifier:(NSDictionary*)item
{
    NSArray* values = [item[@"values"] isKindOfClass:NSArray.class] ? item[@"values"] : nil;
    if(!values.count)
        values = [item[@"validValues"] isKindOfClass:NSArray.class]
            ? item[@"validValues"] : nil;
    return values;
}

+ (NSArray*)titlesForSpecifier:(NSDictionary*)item
{
    NSArray* titles = [item[@"titles"] isKindOfClass:NSArray.class] ? item[@"titles"] : nil;
    if(!titles.count)
        titles = [item[@"validTitles"] isKindOfClass:NSArray.class]
            ? item[@"validTitles"] : nil;
    return titles;
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
    if([cell isEqualToString:@"PSSliderCell"] &&
       [item[@"min"] respondsToSelector:@selector(doubleValue)] &&
       [item[@"max"] respondsToSelector:@selector(doubleValue)] &&
       [item[@"max"] doubleValue] > [item[@"min"] doubleValue])
        return YES;
    NSArray* values = [self valuesForSpecifier:item];
    NSArray* titles = [self titlesForSpecifier:item];
    return (values.count && values.count == titles.count && values.count <= 32 &&
            ([cell isEqualToString:@"PSLinkListCell"] ||
             [cell isEqualToString:@"PSSegmentCell"] ||
             [custom isEqualToString:@"DDLSelectorCell"]));
}

+ (BOOL)canOpenDescriptorAtPath:(NSString*)descriptorPath
{
    NSString* bundledDoodle = [NSBundle.mainBundle pathForResource:@"DoodleControl" ofType:@"plist"];
    BOOL ownDoodle = bundledDoodle && [descriptorPath.stringByResolvingSymlinksInPath
        isEqualToString:bundledDoodle.stringByResolvingSymlinksInPath];
    BOOL bundleHosted = NO;
    NSArray* items = [self itemsForDescriptor:[self descriptorAtPath:descriptorPath]
                               bundleHosted:&bundleHosted bundleRoot:nil];
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
        NSString* bundleRoot = nil;
        NSArray* items = [self.class itemsForDescriptor:descriptor bundleHosted:&bundleHosted
                                             bundleRoot:&bundleRoot];
        _items = [items isKindOfClass:NSArray.class] ? items : @[];
        _bundleHosted = bundleHosted;
        _bundleRoot = bundleRoot;
        _localizations = [self.class localizationsForBundleRoot:bundleRoot];
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

+ (NSDictionary<NSString*,NSString*>*)localizationsForBundleRoot:(NSString*)bundleRoot
{
    if(!bundleRoot.length) return @{};
    NSMutableDictionary<NSString*,NSString*>* result = [NSMutableDictionary dictionary];
    NSMutableArray<NSString*>* languages = [NSMutableArray arrayWithObject:@"en"];
    for(NSString* preferred in NSLocale.preferredLanguages) {
        NSString* language = [[preferred componentsSeparatedByString:@"-"] firstObject].lowercaseString;
        NSCharacterSet* safe = [NSCharacterSet alphanumericCharacterSet];
        if(language.length && language.length <= 12 &&
           [language rangeOfCharacterFromSet:safe.invertedSet].location == NSNotFound &&
           ![languages containsObject:language])
            [languages addObject:language];
    }
    // Merge the English fallback first and the active language last.
    for(NSString* language in languages) {
        for(NSString* table in @[@"Root.strings", @"Prefs.strings"]) {
            NSString* path = [[[bundleRoot stringByAppendingPathComponent:
                [language stringByAppendingPathExtension:@"lproj"]]
                stringByAppendingPathComponent:table] stringByStandardizingPath];
            NSDictionary* strings = [self descriptorAtPath:path];
            if(![strings isKindOfClass:NSDictionary.class] || strings.count > 512) continue;
            [strings enumerateKeysAndObjectsUsingBlock:^(id key, id value, BOOL* stop) {
                (void)stop;
                if([key isKindOfClass:NSString.class] && [value isKindOfClass:NSString.class] &&
                   [key length] <= 128 && [value length] <= 512)
                    result[key] = value;
            }];
        }
    }
    return result.copy;
}

- (NSString*)localizedString:(id)value
{
    if(![value isKindOfClass:NSString.class]) return @"";
    return self.localizations[value] ?: value;
}

- (NSString*)displayLabelForItemAtIndex:(NSUInteger)index
{
    NSString* label = [self localizedString:self.items[index][@"label"]];
    if(label.length) return label;
    for(NSInteger prior = (NSInteger)index - 1; prior >= 0; prior--) {
        NSDictionary* item = self.items[(NSUInteger)prior];
        if(![item[@"cell"] isEqualToString:@"PSGroupCell"]) continue;
        label = [self localizedString:item[@"label"]];
        if(label.length) return label;
        break;
    }
    NSString* key = self.items[index][@"key"];
    return [key isKindOfClass:NSString.class] ? key : @"";
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
    NSArray* values = [self.class valuesForSpecifier:item];
    NSArray* titles = [self.class titlesForSpecifier:item];
    return values.count && values.count == titles.count &&
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
    cell.textLabel.text = [self displayLabelForItemAtIndex:indexPath.row];
    cell.selectionStyle = UITableViewCellSelectionStyleNone;
    cell.detailTextLabel.text = self.bundleHosted && [item[@"subtitle"] isKindOfClass:NSString.class]
        ? item[@"subtitle"] : nil;
    cell.detailTextLabel.numberOfLines = 2;

    if([cellType isEqualToString:@"PSGroupCell"]) {
        cell.textLabel.font = [UIFont preferredFontForTextStyle:UIFontTextStyleFootnote];
        cell.textLabel.textColor = UIColor.secondaryLabelColor;
        NSString* footer = [self localizedString:item[@"footerText"]];
        if(footer.length) cell.detailTextLabel.text = footer;
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
        NSArray* values = [self.class valuesForSpecifier:item];
        NSArray* titles = [self.class titlesForSpecifier:item];
        NSUInteger position = [values indexOfObject:[self valueForSpecifier:item] ?: [NSNull null]];
        cell.detailTextLabel.text = position < titles.count && [titles[position] isKindOfClass:NSString.class]
            ? [self localizedString:titles[position]] : @"Choose a value";
        cell.accessoryType = UITableViewCellAccessoryDisclosureIndicator;
        cell.selectionStyle = UITableViewCellSelectionStyleDefault;
    } else if([cellType isEqualToString:@"PSSliderCell"] &&
              [self.class isEditableSpecifier:item]) {
        UISlider* slider = [[UISlider alloc] initWithFrame:CGRectMake(0, 0, 180, 34)];
        slider.tag = indexPath.row;
        slider.minimumValue = [item[@"min"] floatValue];
        slider.maximumValue = [item[@"max"] floatValue];
        slider.value = [[self valueForSpecifier:item] floatValue];
        [slider.widthAnchor constraintEqualToConstant:150].active = YES;
        [slider addTarget:self action:@selector(sliderChanged:)
            forControlEvents:UIControlEventValueChanged];
        UILabel* value = [UILabel new];
        value.font = [UIFont monospacedDigitSystemFontOfSize:14 weight:UIFontWeightRegular];
        value.text = [NSString stringWithFormat:@"%.0f", slider.value];
        UIStackView* controls = [[UIStackView alloc] initWithArrangedSubviews:@[slider, value]];
        controls.axis = UILayoutConstraintAxisHorizontal;
        controls.spacing = 8;
        cell.accessoryView = controls;
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
    } else if([item[@"detail"] isEqualToString:@"AXNLocationController"] &&
              [self.bundleRoot.lastPathComponent isEqualToString:@"AxonPrefs.bundle"]) {
        cell.detailTextLabel.text = @"Auto layout, edge, and vertical position";
        cell.accessoryType = UITableViewCellAccessoryDisclosureIndicator;
        cell.selectionStyle = UITableViewCellSelectionStyleDefault;
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

- (void)sliderChanged:(UISlider*)sender
{
    if(sender.tag < 0 || sender.tag >= (NSInteger)self.items.count) return;
    NSDictionary* item = self.items[sender.tag];
    [self setValue:@(sender.value) forSpecifier:item];
    UITableViewCell* cell = [self.tableView cellForRowAtIndexPath:
        [NSIndexPath indexPathForRow:sender.tag inSection:0]];
    if([cell.accessoryView isKindOfClass:UIStackView.class]) {
        UIStackView* controls = (UIStackView*)cell.accessoryView;
        UILabel* label = [controls.arrangedSubviews.lastObject isKindOfClass:UILabel.class]
            ? (UILabel*)controls.arrangedSubviews.lastObject : nil;
        label.text = [NSString stringWithFormat:@"%.0f", sender.value];
    }
}

- (void)tableView:(UITableView*)tableView didSelectRowAtIndexPath:(NSIndexPath*)indexPath
{
    [tableView deselectRowAtIndexPath:indexPath animated:YES];
    NSDictionary* item = self.items[indexPath.row];
    if([self isDoodleRecorderSpecifier:item]) {
        [self.navigationController pushViewController:
            [TSDoodlePatternRecorderViewController new] animated:YES];
    } else if([self isChoiceSpecifier:item]) {
        UIAlertController* picker = [UIAlertController alertControllerWithTitle:
            [self displayLabelForItemAtIndex:indexPath.row]
            message:nil preferredStyle:UIAlertControllerStyleActionSheet];
        NSArray* values = [self.class valuesForSpecifier:item];
        NSArray* titles = [self.class titlesForSpecifier:item];
        for(NSUInteger index = 0; index < values.count; index++) {
            id value = values[index];
            NSString* title = [titles[index] isKindOfClass:NSString.class]
                ? [self localizedString:titles[index]] : [value description];
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
    } else if([item[@"detail"] isEqualToString:@"AXNLocationController"] &&
              [self.bundleRoot.lastPathComponent isEqualToString:@"AxonPrefs.bundle"]) {
        [self.navigationController pushViewController:[TSAxonLocationViewController new]
            animated:YES];
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

@implementation TSAxonLocationViewController

static NSString* const TSAxonDomain = @"me.nepeta.axon";
static NSString* const TSAxonNotification = @"me.nepeta.axon/ReloadPrefs";

- (instancetype)init
{
    self = [super initWithStyle:UITableViewStyleInsetGrouped];
    if(self) self.title = @"Location";
    return self;
}

- (NSUserDefaults*)axonDefaults
{
    return [[NSUserDefaults alloc] initWithSuiteName:TSAxonDomain];
}

- (id)valueForKey:(NSString*)key fallback:(id)fallback
{
    id value = [[self axonDefaults] objectForKey:key];
    return value ?: fallback;
}

- (void)setAxonValue:(id)value forKey:(NSString*)key
{
    NSUserDefaults* defaults = [self axonDefaults];
    [defaults setObject:value forKey:key];
    [defaults synchronize];
    CFNotificationCenterPostNotification(CFNotificationCenterGetDarwinNotifyCenter(),
        (__bridge CFStringRef)TSAxonNotification, NULL, NULL, true);
}

- (NSInteger)numberOfSectionsInTableView:(UITableView*)tableView
{ (void)tableView; return 1; }

- (NSInteger)tableView:(UITableView*)tableView numberOfRowsInSection:(NSInteger)section
{ (void)tableView; (void)section; return 2; }

- (NSString*)tableView:(UITableView*)tableView titleForFooterInSection:(NSInteger)section
{
    (void)tableView; (void)section;
    return @"Auto Layout uses a fixed top or bottom position. Turn it off to choose the vertical offset manually.";
}

- (UITableViewCell*)tableView:(UITableView*)tableView cellForRowAtIndexPath:(NSIndexPath*)indexPath
{
    (void)tableView;
    UITableViewCell* cell = [[UITableViewCell alloc] initWithStyle:UITableViewCellStyleValue1
        reuseIdentifier:nil];
    if(indexPath.row == 0) {
        cell.textLabel.text = @"Auto Layout";
        UISwitch* toggle = [UISwitch new];
        toggle.on = [[self valueForKey:@"autoLayout" fallback:@YES] boolValue];
        [toggle addTarget:self action:@selector(autoLayoutChanged:)
            forControlEvents:UIControlEventValueChanged];
        cell.accessoryView = toggle;
        cell.selectionStyle = UITableViewCellSelectionStyleNone;
        return cell;
    }
    BOOL automatic = [[self valueForKey:@"autoLayout" fallback:@YES] boolValue];
    if(automatic) {
        cell.textLabel.text = @"Location";
        NSInteger location = [[self valueForKey:@"location" fallback:@1] integerValue];
        cell.detailTextLabel.text = location == 0 ? @"Top" : @"Bottom (Beta)";
        cell.accessoryType = UITableViewCellAccessoryDisclosureIndicator;
        cell.selectionStyle = UITableViewCellSelectionStyleDefault;
    } else {
        cell.textLabel.text = @"Y-Axis";
        UISlider* slider = [[UISlider alloc] initWithFrame:CGRectMake(0, 0, 190, 34)];
        slider.minimumValue = 0;
        slider.maximumValue = UIScreen.mainScreen.bounds.size.height;
        slider.value = [[self valueForKey:@"yAxis" fallback:@500] floatValue];
        [slider addTarget:self action:@selector(yAxisChanged:)
            forControlEvents:UIControlEventValueChanged];
        cell.accessoryView = slider;
        cell.selectionStyle = UITableViewCellSelectionStyleNone;
    }
    return cell;
}

- (void)autoLayoutChanged:(UISwitch*)sender
{
    [self setAxonValue:@(sender.on) forKey:@"autoLayout"];
    [self.tableView reloadRowsAtIndexPaths:@[[NSIndexPath indexPathForRow:1 inSection:0]]
        withRowAnimation:UITableViewRowAnimationAutomatic];
}

- (void)yAxisChanged:(UISlider*)sender
{
    [self setAxonValue:@(sender.value) forKey:@"yAxis"];
}

- (void)tableView:(UITableView*)tableView didSelectRowAtIndexPath:(NSIndexPath*)indexPath
{
    [tableView deselectRowAtIndexPath:indexPath animated:YES];
    if(indexPath.row != 1 ||
       ![[self valueForKey:@"autoLayout" fallback:@YES] boolValue]) return;
    UIAlertController* picker = [UIAlertController alertControllerWithTitle:@"Location"
        message:nil preferredStyle:UIAlertControllerStyleActionSheet];
    NSArray<NSString*>* titles = @[@"Top", @"Bottom (Beta)"];
    for(NSUInteger index = 0; index < titles.count; index++) {
        [picker addAction:[UIAlertAction actionWithTitle:titles[index]
            style:UIAlertActionStyleDefault handler:^(UIAlertAction* action) {
                (void)action;
                [self setAxonValue:@(index) forKey:@"location"];
                [self.tableView reloadRowsAtIndexPaths:@[indexPath]
                    withRowAnimation:UITableViewRowAnimationNone];
            }]];
    }
    [picker addAction:[UIAlertAction actionWithTitle:@"Cancel"
        style:UIAlertActionStyleCancel handler:nil]];
    picker.popoverPresentationController.sourceView = tableView;
    picker.popoverPresentationController.sourceRect = [tableView rectForRowAtIndexPath:indexPath];
    [self presentViewController:picker animated:YES completion:nil];
}

@end
