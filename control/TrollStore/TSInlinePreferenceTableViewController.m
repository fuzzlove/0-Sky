#import "TSInlinePreferenceTableViewController.h"

@interface TSInlinePreferenceTableViewController ()
@property(nonatomic,copy) NSString* descriptorPath;
@property(nonatomic,strong) NSArray<NSDictionary*>* items;
@end

@implementation TSInlinePreferenceTableViewController

+ (NSDictionary*)descriptorAtPath:(NSString*)path
{
    if(!path.length) return nil;
    NSData* data = [NSData dataWithContentsOfFile:path];
    if(!data) return nil;
    NSError* error = nil;
    id value = [NSPropertyListSerialization propertyListWithData:data
        options:NSPropertyListImmutable format:nil error:&error];
    return [value isKindOfClass:NSDictionary.class] ? value : nil;
}

+ (BOOL)canOpenDescriptorAtPath:(NSString*)descriptorPath
{
    NSArray* items = [self descriptorAtPath:descriptorPath][@"items"];
    if(![items isKindOfClass:NSArray.class] || !items.count) return NO;
    NSSet* supported = [NSSet setWithArray:@[
        @"PSGroupCell", @"PSSwitchCell", @"PSEditTextCell", @"PSSecureEditTextCell"
    ]];
    for(id candidate in items) {
        if(![candidate isKindOfClass:NSDictionary.class]) return NO;
        NSString* cell = candidate[@"cell"];
        if(![cell isKindOfClass:NSString.class] || ![supported containsObject:cell]) return NO;
        if(![cell isEqualToString:@"PSGroupCell"] &&
           (! [candidate[@"defaults"] isKindOfClass:NSString.class] ||
            ! [candidate[@"key"] isKindOfClass:NSString.class])) return NO;
    }
    return YES;
}

- (instancetype)initWithDescriptorPath:(NSString*)descriptorPath title:(NSString*)title
{
    self = [super initWithStyle:UITableViewStyleInsetGrouped];
    if(self) {
        _descriptorPath = descriptorPath.copy;
        NSDictionary* descriptor = [self.class descriptorAtPath:descriptorPath];
        NSArray* items = descriptor[@"items"];
        _items = [items isKindOfClass:NSArray.class] ? items : @[];
        self.title = title.length ? title : @"Tweak Settings";
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

- (void)setValue:(id)value forSpecifier:(NSDictionary*)specifier
{
    NSString* domain = specifier[@"defaults"];
    NSString* key = specifier[@"key"];
    if(!domain.length || !key.length) return;
    NSUserDefaults* defaults = [[NSUserDefaults alloc] initWithSuiteName:domain];
    [defaults setObject:value forKey:key];
    [defaults synchronize];
    NSString* notification = specifier[@"PostNotification"];
    if([notification isKindOfClass:NSString.class] && notification.length) {
        CFNotificationCenterPostNotification(CFNotificationCenterGetDarwinNotifyCenter(),
            (__bridge CFStringRef)notification, NULL, NULL, true);
    }
}

- (NSInteger)numberOfSectionsInTableView:(UITableView*)tableView
{
    (void)tableView;
    return 1;
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
    NSString* reuse = [@"InlinePreference-" stringByAppendingString:cellType ?: @"Unknown"];
    UITableViewCell* cell = [tableView dequeueReusableCellWithIdentifier:reuse];
    if(!cell) cell = [[UITableViewCell alloc] initWithStyle:UITableViewCellStyleDefault
        reuseIdentifier:reuse];
    cell.textLabel.text = [item[@"label"] isKindOfClass:NSString.class] ? item[@"label"] : @"";
    cell.selectionStyle = UITableViewCellSelectionStyleNone;

    if([cellType isEqualToString:@"PSGroupCell"]) {
        cell.textLabel.font = [UIFont preferredFontForTextStyle:UIFontTextStyleFootnote];
        cell.textLabel.textColor = UIColor.secondaryLabelColor;
        cell.accessoryView = nil;
    } else if([cellType isEqualToString:@"PSSwitchCell"]) {
        UISwitch* toggle = [UISwitch new];
        toggle.tag = indexPath.row;
        id value = [self valueForSpecifier:item];
        toggle.on = [value respondsToSelector:@selector(boolValue)] ? [value boolValue] : NO;
        [toggle addTarget:self action:@selector(switchChanged:) forControlEvents:UIControlEventValueChanged];
        cell.accessoryView = toggle;
    } else {
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
    }
    return cell;
}

- (void)switchChanged:(UISwitch*)sender
{
    if(sender.tag < 0 || sender.tag >= (NSInteger)self.items.count) return;
    [self setValue:@(sender.on) forSpecifier:self.items[sender.tag]];
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
