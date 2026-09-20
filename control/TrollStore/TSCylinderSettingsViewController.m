#import "TSCylinderSettingsViewController.h"

static NSString* const TSCylinderDomain = @"com.ryannair05.cylinder";
static NSString* const TSCylinderNotification = @"com.ryannair05.cylinder/settingsChanged";
static NSString* const TSCylinderEffectsRoot = @"/var/jb/Library/Cylinder";

static NSUserDefaults* TSCylinderDefaults(void)
{
    return [[NSUserDefaults alloc] initWithSuiteName:TSCylinderDomain];
}

static NSArray* TSCylinderDefaultEffects(void)
{
    return @[@{@"effect": @"Cube (inside)", @"effectFolder": @"rweichler"}];
}

static void TSCylinderCommit(NSString* key, id value)
{
    NSUserDefaults* defaults = TSCylinderDefaults();
    if(value) [defaults setObject:value forKey:key];
    else [defaults removeObjectForKey:key];
    [defaults synchronize];
    CFNotificationCenterPostNotification(CFNotificationCenterGetDarwinNotifyCenter(),
        (__bridge CFStringRef)TSCylinderNotification, NULL, NULL, true);
}

@interface TSCylinderEffectsViewController : UITableViewController
@property(nonatomic,strong) NSArray<NSDictionary*>* effects;
@property(nonatomic,strong) NSMutableArray<NSDictionary*>* selected;
@end

@interface TSCylinderFormulasViewController : UITableViewController
@property(nonatomic,strong) NSMutableDictionary<NSString*,NSArray*>* formulas;
@property(nonatomic,copy) NSString* selectedFormula;
@end

@implementation TSCylinderSettingsViewController

+ (BOOL)supportsPackage:(NSString*)package descriptorPath:(NSString*)descriptorPath
{
    if(![package isEqualToString:TSCylinderDomain] || !descriptorPath.length) return NO;
    // `dictionaryWithContentsOfFile:` silently returned nil for the binary
    // PreferenceLoader plist on the current SRD.  Use the same explicit
    // property-list decoder as the working data-only preference host.
    NSData* data = [NSData dataWithContentsOfFile:descriptorPath];
    if(!data) return NO;
    id decoded = [NSPropertyListSerialization propertyListWithData:data
        options:NSPropertyListImmutable format:nil error:nil];
    NSDictionary* descriptor = [decoded isKindOfClass:NSDictionary.class] ? decoded : nil;
    NSDictionary* entry = descriptor[@"entry"];
    return [entry[@"bundle"] isEqualToString:@"CylinderSettings"] &&
           [entry[@"detail"] isEqualToString:@"CylinderSettingsListController"];
}

- (instancetype)initWithTitle:(NSString*)title
{
    self = [super initWithStyle:UITableViewStyleInsetGrouped];
    if(self) self.title = title.length ? title : @"Cylinder Reborn";
    return self;
}

- (void)viewWillAppear:(BOOL)animated
{
    [super viewWillAppear:animated];
    [self.tableView reloadData];
}

- (NSInteger)numberOfSectionsInTableView:(UITableView*)tableView
{ (void)tableView; return 2; }

- (NSInteger)tableView:(UITableView*)tableView numberOfRowsInSection:(NSInteger)section
{ (void)tableView; return section == 0 ? 4 : 1; }

- (NSString*)tableView:(UITableView*)tableView titleForFooterInSection:(NSInteger)section
{
    (void)tableView;
    return section == 0 ? @"Native 0-Sky Control compatibility panel. Changes are sent directly to Cylinder Reborn."
                        : nil;
}

- (UITableViewCell*)tableView:(UITableView*)tableView cellForRowAtIndexPath:(NSIndexPath*)indexPath
{
    NSString* reuse = indexPath.section == 0 && (indexPath.row == 0 || indexPath.row == 3)
        ? @"CylinderSwitch" : @"CylinderLink";
    UITableViewCell* cell = [tableView dequeueReusableCellWithIdentifier:reuse];
    if(!cell) cell = [[UITableViewCell alloc] initWithStyle:UITableViewCellStyleValue1
        reuseIdentifier:reuse];
    cell.accessoryView = nil;
    cell.accessoryType = UITableViewCellAccessoryNone;
    cell.selectionStyle = UITableViewCellSelectionStyleDefault;
    NSUserDefaults* defaults = TSCylinderDefaults();

    if(indexPath.section == 1) {
        cell.textLabel.text = @"Reset Cylinder Settings";
        cell.textLabel.textColor = UIColor.systemRedColor;
        cell.detailTextLabel.text = nil;
        return cell;
    }
    cell.textLabel.textColor = UIColor.labelColor;
    if(indexPath.row == 0 || indexPath.row == 3) {
        BOOL enabled = indexPath.row == 0;
        cell.textLabel.text = enabled ? @"Enabled" : @"Randomize";
        UISwitch* toggle = [UISwitch new];
        toggle.tag = indexPath.row;
        id stored = [defaults objectForKey:enabled ? @"enabled" : @"randomized"];
        toggle.on = stored ? [stored boolValue] : enabled;
        [toggle addTarget:self action:@selector(toggleChanged:)
            forControlEvents:UIControlEventValueChanged];
        cell.accessoryView = toggle;
        cell.selectionStyle = UITableViewCellSelectionStyleNone;
        cell.detailTextLabel.text = nil;
    } else if(indexPath.row == 1) {
        cell.textLabel.text = @"Effects";
        NSArray* effects = [defaults arrayForKey:@"effect"] ?: TSCylinderDefaultEffects();
        cell.detailTextLabel.text = effects.count == 1 ? @"1 selected"
            : [NSString stringWithFormat:@"%lu selected", (unsigned long)effects.count];
        cell.accessoryType = UITableViewCellAccessoryDisclosureIndicator;
    } else {
        cell.textLabel.text = @"Formulas";
        NSString* selected = [defaults stringForKey:@"selectedFormula"];
        cell.detailTextLabel.text = selected.length ? selected : @"None";
        cell.accessoryType = UITableViewCellAccessoryDisclosureIndicator;
    }
    return cell;
}

- (void)toggleChanged:(UISwitch*)sender
{
    TSCylinderCommit(sender.tag == 0 ? @"enabled" : @"randomized", @(sender.on));
}

- (void)tableView:(UITableView*)tableView didSelectRowAtIndexPath:(NSIndexPath*)indexPath
{
    [tableView deselectRowAtIndexPath:indexPath animated:YES];
    if(indexPath.section == 1) {
        UIAlertController* alert = [UIAlertController alertControllerWithTitle:@"Reset Cylinder Reborn?"
            message:@"This restores the default effect and clears saved formulas."
            preferredStyle:UIAlertControllerStyleAlert];
        [alert addAction:[UIAlertAction actionWithTitle:@"Cancel" style:UIAlertActionStyleCancel handler:nil]];
        [alert addAction:[UIAlertAction actionWithTitle:@"Reset" style:UIAlertActionStyleDestructive
            handler:^(UIAlertAction* action) {
                (void)action;
                NSUserDefaults* defaults = TSCylinderDefaults();
                for(NSString* key in @[@"enabled", @"randomized", @"effect", @"formula", @"selectedFormula"])
                    [defaults removeObjectForKey:key];
                [defaults synchronize];
                CFNotificationCenterPostNotification(CFNotificationCenterGetDarwinNotifyCenter(),
                    (__bridge CFStringRef)TSCylinderNotification, NULL, NULL, true);
                [self.tableView reloadData];
            }]];
        [self presentViewController:alert animated:YES completion:nil];
    } else if(indexPath.row == 1) {
        [self.navigationController pushViewController:[TSCylinderEffectsViewController new] animated:YES];
    } else if(indexPath.row == 2) {
        [self.navigationController pushViewController:[TSCylinderFormulasViewController new] animated:YES];
    }
}

@end

@implementation TSCylinderEffectsViewController

- (void)viewDidLoad
{
    [super viewDidLoad];
    self.title = @"Effects";
    self.navigationItem.rightBarButtonItem = [[UIBarButtonItem alloc] initWithTitle:@"Clear"
        style:UIBarButtonItemStylePlain target:self action:@selector(clearEffects)];
    NSMutableArray* found = [NSMutableArray array];
    NSFileManager* manager = NSFileManager.defaultManager;
    NSArray* folders = [manager contentsOfDirectoryAtPath:TSCylinderEffectsRoot error:nil];
    for(NSString* folder in folders) {
        NSString* directory = [TSCylinderEffectsRoot stringByAppendingPathComponent:folder];
        BOOL isDirectory = NO;
        if(![manager fileExistsAtPath:directory isDirectory:&isDirectory] || !isDirectory) continue;
        for(NSString* filename in [manager contentsOfDirectoryAtPath:directory error:nil]) {
            if(![[filename.pathExtension lowercaseString] isEqualToString:@"lua"]) continue;
            [found addObject:@{@"effect": filename.stringByDeletingPathExtension,
                               @"effectFolder": folder}];
        }
    }
    self.effects = [found sortedArrayUsingComparator:^NSComparisonResult(NSDictionary* left, NSDictionary* right) {
        return [left[@"effect"] localizedCaseInsensitiveCompare:right[@"effect"]];
    }];
    NSArray* stored = [TSCylinderDefaults() arrayForKey:@"effect"] ?: TSCylinderDefaultEffects();
    self.selected = [stored mutableCopy];
}

- (void)clearEffects
{
    [self.selected removeAllObjects];
    TSCylinderCommit(@"effect", self.selected.copy);
    TSCylinderCommit(@"selectedFormula", nil);
    [self.tableView reloadData];
}

- (NSInteger)tableView:(UITableView*)tableView numberOfRowsInSection:(NSInteger)section
{ (void)tableView; (void)section; return self.effects.count; }

- (NSString*)tableView:(UITableView*)tableView titleForFooterInSection:(NSInteger)section
{ (void)tableView; (void)section; return @"Tap effects in the order they should be combined. Some 3D combinations may cause lag."; }

- (UITableViewCell*)tableView:(UITableView*)tableView cellForRowAtIndexPath:(NSIndexPath*)indexPath
{
    UITableViewCell* cell = [tableView dequeueReusableCellWithIdentifier:@"CylinderEffect"];
    if(!cell) cell = [[UITableViewCell alloc] initWithStyle:UITableViewCellStyleSubtitle
        reuseIdentifier:@"CylinderEffect"];
    NSDictionary* effect = self.effects[indexPath.row];
    NSUInteger selectedIndex = [self.selected indexOfObject:effect];
    cell.textLabel.text = effect[@"effect"];
    cell.detailTextLabel.text = selectedIndex == NSNotFound ? effect[@"effectFolder"]
        : [NSString stringWithFormat:@"%@ • position %lu", effect[@"effectFolder"],
           (unsigned long)selectedIndex + 1];
    cell.accessoryType = selectedIndex == NSNotFound ? UITableViewCellAccessoryNone
                                                     : UITableViewCellAccessoryCheckmark;
    return cell;
}

- (void)tableView:(UITableView*)tableView didSelectRowAtIndexPath:(NSIndexPath*)indexPath
{
    [tableView deselectRowAtIndexPath:indexPath animated:YES];
    NSDictionary* effect = self.effects[indexPath.row];
    NSUInteger selectedIndex = [self.selected indexOfObject:effect];
    if(selectedIndex == NSNotFound) [self.selected addObject:effect];
    else [self.selected removeObjectAtIndex:selectedIndex];
    TSCylinderCommit(@"effect", self.selected.copy);
    TSCylinderCommit(@"selectedFormula", nil);
    [self.tableView reloadData];
}

@end

@implementation TSCylinderFormulasViewController

- (void)viewDidLoad
{
    [super viewDidLoad];
    self.title = @"Formulas";
    NSDictionary* stored = [TSCylinderDefaults() dictionaryForKey:@"formula"];
    self.formulas = stored ? stored.mutableCopy : [NSMutableDictionary dictionary];
    self.selectedFormula = [TSCylinderDefaults() stringForKey:@"selectedFormula"];
    self.navigationItem.rightBarButtonItem = [[UIBarButtonItem alloc]
        initWithBarButtonSystemItem:UIBarButtonSystemItemAdd target:self action:@selector(addFormula)];
}

- (NSArray<NSString*>*)names
{
    return [self.formulas.allKeys sortedArrayUsingSelector:@selector(localizedCaseInsensitiveCompare:)];
}

- (void)addFormula
{
    NSArray* effects = [TSCylinderDefaults() arrayForKey:@"effect"] ?: TSCylinderDefaultEffects();
    if(!effects.count) {
        UIAlertController* alert = [UIAlertController alertControllerWithTitle:@"No effects selected"
            message:@"Select at least one effect before creating a formula."
            preferredStyle:UIAlertControllerStyleAlert];
        [alert addAction:[UIAlertAction actionWithTitle:@"OK" style:UIAlertActionStyleDefault handler:nil]];
        [self presentViewController:alert animated:YES completion:nil];
        return;
    }
    UIAlertController* alert = [UIAlertController alertControllerWithTitle:@"New Formula"
        message:@"The formula will contain the currently selected effects."
        preferredStyle:UIAlertControllerStyleAlert];
    [alert addTextFieldWithConfigurationHandler:^(UITextField* field) { field.placeholder = @"Formula name"; }];
    [alert addAction:[UIAlertAction actionWithTitle:@"Cancel" style:UIAlertActionStyleCancel handler:nil]];
    [alert addAction:[UIAlertAction actionWithTitle:@"Save" style:UIAlertActionStyleDefault
        handler:^(UIAlertAction* action) {
            (void)action;
            NSString* name = [alert.textFields.firstObject.text stringByTrimmingCharactersInSet:
                NSCharacterSet.whitespaceAndNewlineCharacterSet];
            if(!name.length) return;
            self.formulas[name] = effects;
            self.selectedFormula = name;
            TSCylinderCommit(@"formula", self.formulas.copy);
            TSCylinderCommit(@"selectedFormula", name);
            TSCylinderCommit(@"effect", effects);
            [self.tableView reloadData];
        }]];
    [self presentViewController:alert animated:YES completion:nil];
}

- (NSInteger)tableView:(UITableView*)tableView numberOfRowsInSection:(NSInteger)section
{ (void)tableView; (void)section; return self.names.count; }

- (UITableViewCell*)tableView:(UITableView*)tableView cellForRowAtIndexPath:(NSIndexPath*)indexPath
{
    UITableViewCell* cell = [tableView dequeueReusableCellWithIdentifier:@"CylinderFormula"];
    if(!cell) cell = [[UITableViewCell alloc] initWithStyle:UITableViewCellStyleSubtitle
        reuseIdentifier:@"CylinderFormula"];
    NSString* name = self.names[indexPath.row];
    NSArray* effects = self.formulas[name];
    cell.textLabel.text = name;
    cell.detailTextLabel.text = [NSString stringWithFormat:@"%lu effect%@", (unsigned long)effects.count,
        effects.count == 1 ? @"" : @"s"];
    cell.accessoryType = [name isEqualToString:self.selectedFormula]
        ? UITableViewCellAccessoryCheckmark : UITableViewCellAccessoryNone;
    return cell;
}

- (void)tableView:(UITableView*)tableView didSelectRowAtIndexPath:(NSIndexPath*)indexPath
{
    [tableView deselectRowAtIndexPath:indexPath animated:YES];
    NSString* name = self.names[indexPath.row];
    self.selectedFormula = name;
    NSArray* effects = self.formulas[name];
    TSCylinderCommit(@"selectedFormula", name);
    TSCylinderCommit(@"effect", effects);
    [self.tableView reloadData];
}

- (BOOL)tableView:(UITableView*)tableView canEditRowAtIndexPath:(NSIndexPath*)indexPath
{ (void)tableView; (void)indexPath; return YES; }

- (void)tableView:(UITableView*)tableView commitEditingStyle:(UITableViewCellEditingStyle)style
    forRowAtIndexPath:(NSIndexPath*)indexPath
{
    if(style != UITableViewCellEditingStyleDelete) return;
    NSString* name = self.names[indexPath.row];
    [self.formulas removeObjectForKey:name];
    if([self.selectedFormula isEqualToString:name]) {
        self.selectedFormula = nil;
        TSCylinderCommit(@"selectedFormula", nil);
    }
    TSCylinderCommit(@"formula", self.formulas.copy);
    [tableView reloadData];
}

@end
