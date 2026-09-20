#import "TSInventoryTableViewController.h"
#import "TSApplicationsManager.h"
#import "TSInlinePreferenceTableViewController.h"
#import "TSCylinderSettingsViewController.h"
#import <TSPresentationDelegate.h>
@import UniformTypeIdentifiers;

@interface TSInventoryTableViewController ()
@property(nonatomic,strong) NSArray* tweaks;
@property(nonatomic,strong) UIRefreshControl* pullRefresh;
@property(nonatomic,strong) UIBarButtonItem* exportButton;
@property(nonatomic,strong) UIBarButtonItem* removeButton;
@property(nonatomic,strong) NSDictionary* packageHealth;
@end

static NSString* const TSTweakSettingsRequestPath = @"/var/mobile/pl/open-tweak-settings.json";

@implementation TSInventoryTableViewController

- (instancetype)init
{
    self = [super initWithStyle:UITableViewStyleInsetGrouped];
    if(self) _tweaks = @[];
    return self;
}

- (void)viewDidLoad
{
    [super viewDidLoad];
    UIBarButtonItem* addButton = [[UIBarButtonItem alloc]
        initWithBarButtonSystemItem:UIBarButtonSystemItemAdd target:self action:@selector(selectDeb)];
    self.exportButton = [[UIBarButtonItem alloc] initWithTitle:@"Export"
        style:UIBarButtonItemStylePlain target:nil action:nil];
    self.exportButton.enabled = NO;
    self.removeButton = [[UIBarButtonItem alloc]
        initWithImage:[UIImage systemImageNamed:@"trash"]
        style:UIBarButtonItemStylePlain target:nil action:nil];
    self.removeButton.enabled = NO;
    self.removeButton.accessibilityLabel = @"Remove installed tweak";
    self.removeButton.accessibilityIdentifier = @"ZeroSkyControlRemoveTweakMenu";
    // Preserve the existing package-import button while making export
    // and removal discoverable. The first item is the trailing button.
    self.navigationItem.rightBarButtonItems =
        @[addButton, self.exportButton, self.removeButton];
    self.navigationItem.leftBarButtonItem = [[UIBarButtonItem alloc]
        initWithTitle:@"Fix Menus" style:UIBarButtonItemStylePlain
        target:self action:@selector(repairPreferenceMenus)];
    self.pullRefresh = [UIRefreshControl new];
    [self.pullRefresh addTarget:self action:@selector(refresh) forControlEvents:UIControlEventValueChanged];
    self.refreshControl = self.pullRefresh;
    [self refresh];
}

- (void)repairPreferenceMenus
{
    self.navigationItem.leftBarButtonItem.enabled = NO;
    self.navigationItem.prompt = @"Converting and refreshing tweak preference menus…";
    [TSPresentationDelegate startActivity:@"Fixing preference menus"];
    dispatch_async(dispatch_get_global_queue(QOS_CLASS_USER_INITIATED, 0), ^{
        NSString* log = nil;
        int status = [[TSApplicationsManager sharedInstance]
            repairPreferenceMenusForPackage:nil log:&log];
        dispatch_async(dispatch_get_main_queue(), ^{
            [TSPresentationDelegate stopActivityWithCompletion:^{
                self.navigationItem.leftBarButtonItem.enabled = YES;
                self.navigationItem.prompt = status == 0
                    ? @"Preference conversion complete • Tap for settings is refreshed"
                    : [NSString stringWithFormat:@"Preference repair failed (%d): %@",
                       status, log.length ? log : @"No diagnostics returned"];
                [self refresh];
            }];
        });
    });
}

- (void)refresh
{
    dispatch_async(dispatch_get_global_queue(QOS_CLASS_USER_INITIATED, 0), ^{
        NSDictionary* inventory = [[TSApplicationsManager sharedInstance] srdInventory];
        NSError* coreError = nil;
        NSDictionary* envelope = [[TSApplicationsManager sharedInstance]
            coreRequestOperation:@"getPackages" parameters:@{@"limit": @512} error:&coreError];
        NSArray* packages = [envelope[@"result"][@"packages"] isKindOfClass:NSArray.class]
            ? envelope[@"result"][@"packages"] : @[];
        NSMutableDictionary* packageHealth = [NSMutableDictionary dictionary];
        for(NSDictionary* row in packages) {
            NSString* identifier = [row[@"package"] isKindOfClass:NSString.class]
                ? row[@"package"] : nil;
            if(identifier.length) packageHealth[identifier] = row;
        }
        NSArray* tweaks = [inventory[@"tweaks"] isKindOfClass:NSArray.class] ? inventory[@"tweaks"] : nil;
        dispatch_async(dispatch_get_main_queue(), ^{
            if(tweaks) self.tweaks = tweaks;
            self.packageHealth = packageHealth;
            [self rebuildExportMenu];
            [self rebuildRemovalMenu];
            [self.pullRefresh endRefreshing];
            [self.tableView reloadData];
            self.navigationItem.prompt = inventory
                ? [NSString stringWithFormat:@"%lu installed package payloads", (unsigned long)self.tweaks.count]
                : @"Local inventory service unavailable";
        });
    });
}

- (BOOL)isProtectedPackage:(NSString*)package
{
    static NSSet<NSString*>* protectedPackages;
    static dispatch_once_t onceToken;
    dispatch_once(&onceToken, ^{
        protectedPackages = [NSSet setWithArray:@[
            @"apt", @"dpkg", @"ellekit", @"preferenceloader", @"sileo",
            @"org.coolstar.sileo", @"com.liquidskysecurity.srd-runtime-manager"
        ]];
    });
    return [protectedPackages containsObject:package.lowercaseString];
}

- (NSString*)displayTitleForTweak:(NSDictionary*)tweak
{
    NSString* package = [tweak[@"package"] isKindOfClass:NSString.class]
        ? tweak[@"package"] : @"Unknown package";
    NSString* title = [tweak[@"preference_title"] isKindOfClass:NSString.class]
        ? tweak[@"preference_title"] : nil;
    if(!title.length) {
        NSString* dylib = [tweak[@"dylib"] isKindOfClass:NSString.class]
            ? [tweak[@"dylib"] lastPathComponent].stringByDeletingPathExtension : nil;
        title = dylib.length ? dylib : package;
    }
    return title;
}

- (void)rebuildRemovalMenu
{
    NSMutableArray<UIMenuElement*>* actions = [NSMutableArray array];
    NSMutableSet<NSString*>* includedPackages = [NSMutableSet set];
    for(NSDictionary* tweak in self.tweaks) {
        NSString* package = [tweak[@"package"] isKindOfClass:NSString.class]
            ? tweak[@"package"] : nil;
        if(!package.length || [includedPackages containsObject:package] ||
           [self isProtectedPackage:package]) continue;
        [includedPackages addObject:package];
        NSString* title = [self displayTitleForTweak:tweak];
        UIAction* action = [UIAction actionWithTitle:title
            image:[UIImage systemImageNamed:@"trash"] identifier:nil
            handler:^(__kindof UIAction* selectedAction) {
                (void)selectedAction;
                [self confirmRemovalOfPackage:package displayName:title];
            }];
        action.attributes = UIMenuElementAttributesDestructive;
        if(@available(iOS 15.0, *)) action.subtitle = package;
        [actions addObject:action];
    }
    self.removeButton.menu = [UIMenu menuWithTitle:
        @"Choose a tweak package to remove. Core package-management and runtime packages are protected."
        children:actions];
    self.removeButton.enabled = actions.count > 0;
}

- (NSString*)boundedRemovalMessage:(NSString*)log status:(int)status
{
    NSString* message = log.length ? log : [NSString stringWithFormat:@"Status %d", status];
    const NSUInteger limit = 4000;
    if(message.length > limit) {
        message = [@"…\n" stringByAppendingString:
            [message substringFromIndex:message.length - limit]];
    }
    return message;
}

- (void)confirmRemovalOfPackage:(NSString*)package displayName:(NSString*)displayName
{
    if(!package.length || [self isProtectedPackage:package]) {
        [self showTitle:@"Protected package"
            message:@"0-Sky Control cannot remove this foundational runtime package."];
        return;
    }
    NSString* message = [NSString stringWithFormat:
        @"Remove %@ (%@) from this device?\n\n"
         @"The package-owned tweak and preference menu will be removed. "
         @"0-Sky Control will then refresh the SRD runtime and safely restart affected apps. "
         @"The package's saved preference values may remain.",
        displayName.length ? displayName : package, package];
    UIAlertController* alert = [UIAlertController alertControllerWithTitle:@"Remove tweak?"
        message:message preferredStyle:UIAlertControllerStyleAlert];
    [alert addAction:[UIAlertAction actionWithTitle:@"Cancel"
        style:UIAlertActionStyleCancel handler:nil]];
    [alert addAction:[UIAlertAction actionWithTitle:@"Remove Tweak"
        style:UIAlertActionStyleDestructive handler:^(UIAlertAction* action) {
            (void)action;
            self.removeButton.enabled = NO;
            self.navigationItem.prompt = [NSString stringWithFormat:@"Removing %@…", package];
            [TSPresentationDelegate startActivity:@"Removing tweak package"];
            dispatch_async(dispatch_get_global_queue(QOS_CLASS_USER_INITIATED, 0), ^{
                NSString* log = nil;
                int status = [[TSApplicationsManager sharedInstance]
                    removeTweakPackage:package log:&log];
                dispatch_async(dispatch_get_main_queue(), ^{
                    [TSPresentationDelegate stopActivityWithCompletion:^{
                        self.navigationItem.prompt = status == 0
                            ? [NSString stringWithFormat:@"%@ removed", package]
                            : [NSString stringWithFormat:@"Removal failed (%d)", status];
                        [self showTitle:status == 0 ? @"Tweak removed" : @"Removal failed"
                            message:[self boundedRemovalMessage:log status:status]];
                        [self refresh];
                    }];
                });
            });
        }]];
    [self presentViewController:alert animated:YES completion:nil];
}

- (void)rebuildExportMenu
{
    NSMutableArray<UIMenuElement*>* packageActions = [NSMutableArray array];
    for(NSDictionary* tweak in self.tweaks) {
        NSString* package = [tweak[@"package"] isKindOfClass:NSString.class]
            ? tweak[@"package"] : nil;
        if(!package.length) continue;
        NSString* title = [tweak[@"preference_title"] isKindOfClass:NSString.class]
            ? tweak[@"preference_title"] : nil;
        if(!title.length) {
            NSString* dylib = [tweak[@"dylib"] isKindOfClass:NSString.class]
                ? [tweak[@"dylib"] lastPathComponent].stringByDeletingPathExtension : nil;
            title = dylib.length ? dylib : package;
        }
        BOOL hasSettings = [tweak[@"settings_available"] boolValue];
        UIImage* icon = [UIImage systemImageNamed:hasSettings ? @"gearshape.2" : @"shippingbox"];
        UIAction* action = [UIAction actionWithTitle:title image:icon identifier:nil
            handler:^(__kindof UIAction* selectedAction) {
                (void)selectedAction;
                NSUInteger row = [self.tweaks indexOfObjectPassingTest:
                    ^BOOL(NSDictionary* candidate, NSUInteger index, BOOL* stop) {
                        (void)index;
                        NSString* candidatePackage = [candidate[@"package"] isKindOfClass:NSString.class]
                            ? candidate[@"package"] : nil;
                        BOOL match = [candidatePackage isEqualToString:package];
                        if(match) *stop = YES;
                        return match;
                    }];
                if(row == NSNotFound) {
                    self.navigationItem.prompt = @"Refresh the tweak list before exporting.";
                    return;
                }
                [self exportDebForRowAtIndexPath:[NSIndexPath indexPathForRow:row inSection:0]];
            }];
        if(@available(iOS 15.0, *)) {
            action.subtitle = hasSettings
                ? [NSString stringWithFormat:@"%@ • includes settings menu", package]
                : [NSString stringWithFormat:@"%@ • package payload", package];
        }
        [packageActions addObject:action];
    }

    UIMenu* menu = [UIMenu menuWithTitle:
        @"Exported DEBs include package-owned PreferenceLoader descriptors and bundles. Personal setting values are not exported."
        children:packageActions];
    self.exportButton.menu = menu;
    self.exportButton.enabled = packageActions.count > 0;
    self.exportButton.accessibilityLabel = @"Export tweak package with settings menu";
}

- (void)selectDeb
{
    UTType* deb = [UTType typeWithFilenameExtension:@"deb" conformingToType:UTTypeData];
    UIDocumentPickerViewController* picker = [[UIDocumentPickerViewController alloc]
        initForOpeningContentTypes:@[deb]];
    picker.delegate = self;
    picker.allowsMultipleSelection = NO;
    [self presentViewController:picker animated:YES completion:nil];
}

- (void)documentPicker:(UIDocumentPickerViewController*)controller didPickDocumentsAtURLs:(NSArray<NSURL*>*)urls
{
    NSURL* source = urls.firstObject;
    if(!source) return;
    BOOL scoped = [source startAccessingSecurityScopedResource];
    NSURL* staged = [[NSURL fileURLWithPath:NSTemporaryDirectory() isDirectory:YES]
        URLByAppendingPathComponent:[NSUUID.UUID.UUIDString stringByAppendingPathExtension:@"deb"]];
    NSError* copyError = nil;
    BOOL copied = [[NSFileManager defaultManager] copyItemAtURL:source toURL:staged error:&copyError];
    if(scoped) [source stopAccessingSecurityScopedResource];
    if(!copied) { [self showTitle:@"Import failed" message:copyError.localizedDescription]; return; }
    [TSPresentationDelegate startActivity:@"Installing package"];
    dispatch_async(dispatch_get_global_queue(QOS_CLASS_USER_INITIATED, 0), ^{
        NSString* log = nil;
        int status = [[TSApplicationsManager sharedInstance] installDeb:staged.path log:&log];
        [[NSFileManager defaultManager] removeItemAtURL:staged error:nil];
        dispatch_async(dispatch_get_main_queue(), ^{
            [TSPresentationDelegate stopActivityWithCompletion:^{
                self.navigationItem.prompt = status == 0
                    ? @"Package installed • preferences converted • Tap for settings refreshed"
                    : [NSString stringWithFormat:@"Install failed (%d): %@", status,
                       log.length ? log : @"No diagnostic output was returned."];
                [self refresh];
            }];
        });
    });
}

- (void)showTitle:(NSString*)title message:(NSString*)message
{
    UIAlertController* alert = [UIAlertController alertControllerWithTitle:title message:message
        preferredStyle:UIAlertControllerStyleAlert];
    [alert addAction:[UIAlertAction actionWithTitle:@"Close" style:UIAlertActionStyleDefault handler:nil]];
    [self presentViewController:alert animated:YES completion:nil];
}

- (void)exportDebForRowAtIndexPath:(NSIndexPath*)indexPath
{
    if(indexPath.row >= self.tweaks.count) return;
    NSDictionary* tweak = self.tweaks[indexPath.row];
    NSString* package = [tweak[@"package"] isKindOfClass:NSString.class]
        ? tweak[@"package"] : nil;
    if(!package.length) {
        self.navigationItem.prompt = @"This row has no package identity to export.";
        return;
    }
    NSCharacterSet* invalidFilenameCharacters = [[NSCharacterSet
        characterSetWithCharactersInString:
        @"abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-_."] invertedSet];
    NSString* safePackage = [[package componentsSeparatedByCharactersInSet:
        invalidFilenameCharacters] componentsJoinedByString:@"-"];
    NSString* filename = [safePackage stringByAppendingPathExtension:@"deb"];
    // Foundation returns different NSDocumentDirectory values depending on
    // whether 0-Sky Control is currently user- or system-registered. Use the
    // stable, broker-approved export container so renewal cannot make an
    // otherwise valid export fail with "outside an approved container".
    NSString* directory = @"/var/mobile/Documents/Commissary Exports";
    [[NSFileManager defaultManager] createDirectoryAtPath:directory
        withIntermediateDirectories:YES attributes:nil error:nil];
    NSString* destination = [directory stringByAppendingPathComponent:filename];
    [[NSFileManager defaultManager] removeItemAtPath:destination error:nil];
    BOOL hasSettings = [tweak[@"settings_available"] boolValue];
    self.navigationItem.prompt = [NSString stringWithFormat:@"Exporting %@%@…", package,
        hasSettings ? @" with its settings menu" : @""];
    dispatch_async(dispatch_get_global_queue(QOS_CLASS_USER_INITIATED, 0), ^{
        NSString* log = nil;
        int result = [[TSApplicationsManager sharedInstance]
            exportPackage:package toDeb:destination log:&log];
        dispatch_async(dispatch_get_main_queue(), ^{
            if(result != 0 || ![[NSFileManager defaultManager] fileExistsAtPath:destination]) {
                self.navigationItem.prompt = [NSString stringWithFormat:@"Export failed: %@",
                    log.length ? log : [NSString stringWithFormat:@"status %d", result]];
                return;
            }
            self.navigationItem.prompt = [NSString stringWithFormat:
                hasSettings ? @"%@ and its settings menu are ready to save or share."
                            : @"%@ is ready to save or share.", filename];
            UIActivityViewController* share = [[UIActivityViewController alloc]
                initWithActivityItems:@[[NSURL fileURLWithPath:destination]] applicationActivities:nil];
            share.popoverPresentationController.sourceView = self.tableView;
            share.popoverPresentationController.sourceRect =
                [self.tableView rectForRowAtIndexPath:indexPath];
            share.completionWithItemsHandler = ^(UIActivityType activityType,
                BOOL completed, NSArray* returnedItems, NSError* error) {
                (void)activityType; (void)completed; (void)returnedItems; (void)error;
                [[NSFileManager defaultManager] removeItemAtPath:destination error:nil];
                self.navigationItem.prompt = nil;
            };
            [TSPresentationDelegate presentViewController:share animated:YES completion:nil];
        });
    });
}

- (NSInteger)tableView:(UITableView*)tableView numberOfRowsInSection:(NSInteger)section
{ return self.tweaks.count; }

- (UITableViewCell*)tableView:(UITableView*)tableView cellForRowAtIndexPath:(NSIndexPath*)indexPath
{
    UITableViewCell* cell = [tableView dequeueReusableCellWithIdentifier:@"TweakCell"];
    if(!cell) cell = [[UITableViewCell alloc] initWithStyle:UITableViewCellStyleSubtitle
        reuseIdentifier:@"TweakCell"];
    NSDictionary* tweak = self.tweaks[indexPath.row];
    NSString* package = [tweak[@"package"] isKindOfClass:NSString.class] ? tweak[@"package"] : @"Unknown package";
    NSString* dylib = [tweak[@"dylib"] lastPathComponent] ?: @"Unknown dylib";
    NSArray* bundles = [tweak[@"bundles"] isKindOfClass:NSArray.class] ? tweak[@"bundles"] : @[];
    NSArray* executables = [tweak[@"executables"] isKindOfClass:NSArray.class] ? tweak[@"executables"] : @[];
    NSString* preferenceTitle = [tweak[@"preference_title"] isKindOfClass:NSString.class]
        ? tweak[@"preference_title"] : nil;
    BOOL settingsAvailable = [tweak[@"settings_available"] boolValue] && preferenceTitle.length;
    BOOL preferenceOnly = [tweak[@"preference_only"] boolValue];
    NSArray* preferenceEntries = [tweak[@"preference_entries"] isKindOfClass:NSArray.class]
        ? tweak[@"preference_entries"] : @[];
    NSString* descriptor = [preferenceEntries.firstObject[@"descriptor"] isKindOfClass:NSString.class]
        ? preferenceEntries.firstObject[@"descriptor"] : nil;
    BOOL inlineSettings = [TSInlinePreferenceTableViewController canOpenDescriptorAtPath:descriptor];
    BOOL cylinderSettings = [TSCylinderSettingsViewController supportsPackage:package
        descriptorPath:descriptor];
    BOOL converted = preferenceEntries.count && [preferenceEntries.firstObject[@"converted"] boolValue];
    cell.textLabel.text = preferenceTitle.length ? preferenceTitle : dylib;
    NSMutableArray* filters = [NSMutableArray arrayWithArray:bundles];
    [filters addObjectsFromArray:executables];
    NSString* targetDescription = preferenceOnly ? @"preference-only menu" :
        (filters.count ? [filters componentsJoinedByString:@", "] : @"no process filter");
    NSString* health = [self.packageHealth[package][@"health"] isKindOfClass:NSString.class]
        ? self.packageHealth[package][@"health"] : @"Unknown";
    cell.detailTextLabel.text = [NSString stringWithFormat:@"%@ • %@ • %@%@%@", package,
        health, targetDescription, converted ? @" • converted for iOS 27" : @"",
        settingsAvailable ? ((inlineSettings || cylinderSettings)
            ? @" • Settings in 0-Sky Control" : @" • Tap for settings") : @""];
    cell.detailTextLabel.numberOfLines = 2;
    cell.accessoryType = settingsAvailable ? UITableViewCellAccessoryDisclosureIndicator
                                           : UITableViewCellAccessoryNone;
    cell.selectionStyle = settingsAvailable ? UITableViewCellSelectionStyleDefault
                                             : UITableViewCellSelectionStyleNone;
    return cell;
}

- (void)showPackageDetails:(NSString*)package
{
    if(!package.length) return;
    self.navigationItem.prompt = [NSString stringWithFormat:@"Reading %@ details…", package];
    dispatch_async(dispatch_get_global_queue(QOS_CLASS_UTILITY, 0), ^{
        NSError* error = nil;
        NSDictionary* envelope = [[TSApplicationsManager sharedInstance]
            coreRequestOperation:@"getPackageDetail" parameters:@{@"package": package} error:&error];
        NSDictionary* detail = [envelope[@"result"][@"package"] isKindOfClass:NSDictionary.class]
            ? envelope[@"result"][@"package"] : nil;
        dispatch_async(dispatch_get_main_queue(), ^{
            self.navigationItem.prompt = nil;
            if(!detail) {
                [self showTitle:@"Package details unavailable"
                    message:error.localizedDescription ?: @"The package is no longer installed."];
                return;
            }
            NSArray* dependencies = [detail[@"dependencies"] isKindOfClass:NSArray.class]
                ? detail[@"dependencies"] : @[];
            NSString* message = [NSString stringWithFormat:
                @"Version: %@\nArchitecture: %@\nHealth: %@\nFiles: %@%@\nServices: %@\nTweaks: %@\nQuarantined: %@\nDependency groups: %@",
                detail[@"version"] ?: @"Unknown", detail[@"architecture"] ?: @"Unknown",
                detail[@"health"] ?: @"Unknown", detail[@"fileCount"] ?: @0,
                [detail[@"filesTruncated"] boolValue] ? @"+" : @"",
                detail[@"serviceCount"] ?: @0, detail[@"tweakCount"] ?: @0,
                detail[@"quarantinedCount"] ?: @0, @(dependencies.count)];
            [self showTitle:detail[@"name"] ?: package message:message];
        });
    });
}

- (void)tableView:(UITableView*)tableView didSelectRowAtIndexPath:(NSIndexPath*)indexPath
{
    [tableView deselectRowAtIndexPath:indexPath animated:YES];
    NSDictionary* tweak = self.tweaks[indexPath.row];
    NSString* title = [tweak[@"preference_title"] isKindOfClass:NSString.class]
        ? tweak[@"preference_title"] : nil;
    if(![tweak[@"settings_available"] boolValue] || !title.length) {
        self.navigationItem.prompt = @"This package does not publish a PreferenceLoader pane.";
        return;
    }

    NSString* package = [tweak[@"package"] isKindOfClass:NSString.class] ? tweak[@"package"] : @"";
    NSArray* preferenceEntries = [tweak[@"preference_entries"] isKindOfClass:NSArray.class]
        ? tweak[@"preference_entries"] : @[];
    NSString* descriptor = [preferenceEntries.firstObject[@"descriptor"] isKindOfClass:NSString.class]
        ? preferenceEntries.firstObject[@"descriptor"] : nil;
    if([TSCylinderSettingsViewController supportsPackage:package descriptorPath:descriptor]) {
        TSCylinderSettingsViewController* controller =
            [[TSCylinderSettingsViewController alloc] initWithTitle:title];
        [self.navigationController pushViewController:controller animated:YES];
        self.navigationItem.prompt = nil;
        return;
    }
    if([TSInlinePreferenceTableViewController canOpenDescriptorAtPath:descriptor]) {
        TSInlinePreferenceTableViewController* controller =
            [[TSInlinePreferenceTableViewController alloc] initWithDescriptorPath:descriptor title:title];
        [self.navigationController pushViewController:controller animated:YES];
        self.navigationItem.prompt = nil;
        return;
    }
    NSDictionary* request = @{
        @"schema": @1,
        @"title": title,
        @"package": package,
        @"token": NSUUID.UUID.UUIDString,
        @"created_at": @([NSDate.date timeIntervalSince1970]),
    };
    NSError* error = nil;
    NSData* data = [NSJSONSerialization dataWithJSONObject:request options:0 error:&error];
    NSURL* destination = [NSURL fileURLWithPath:TSTweakSettingsRequestPath];
    [[NSFileManager defaultManager] createDirectoryAtPath:destination.URLByDeletingLastPathComponent.path
                              withIntermediateDirectories:YES attributes:nil error:&error];
    if(!data || error || ![data writeToURL:destination options:NSDataWritingAtomic error:&error]) {
        self.navigationItem.prompt = [NSString stringWithFormat:@"Could not hand %@ to Settings: %@",
            title, error.localizedDescription ?: @"write failed"];
        return;
    }

    self.navigationItem.prompt = [NSString stringWithFormat:@"Opening %@ settings…", title];
    // iOS 27's Settings application still registers the private `prefs:` route;
    // `App-prefs:` can report success without foregrounding Settings on an SRD.
    NSURL* settingsURL = [NSURL URLWithString:@"prefs:"];
    [UIApplication.sharedApplication openURL:settingsURL options:@{}
        completionHandler:^(BOOL success) {
            if(!success) {
                [UIApplication.sharedApplication openURL:[NSURL URLWithString:@"App-prefs:"]
                    options:@{} completionHandler:nil];
            }
        }];
}

- (BOOL)tableView:(UITableView*)tableView canEditRowAtIndexPath:(NSIndexPath*)indexPath
{ return YES; }

- (UISwipeActionsConfiguration*)tableView:(UITableView*)tableView
    leadingSwipeActionsConfigurationForRowAtIndexPath:(NSIndexPath*)indexPath
{
    UIContextualAction* export = [UIContextualAction contextualActionWithStyle:UIContextualActionStyleNormal
        title:[self.tweaks[indexPath.row][@"settings_available"] boolValue]
            ? @"Export + Menu" : @"Export DEB"
        handler:^(UIContextualAction* action, UIView* sourceView,
                                      void (^completionHandler)(BOOL)) {
            (void)action; (void)sourceView;
            [self exportDebForRowAtIndexPath:indexPath];
            completionHandler(YES);
        }];
    export.backgroundColor = UIColor.systemBlueColor;
    export.image = [UIImage systemImageNamed:@"square.and.arrow.up"];
    UIContextualAction* details = [UIContextualAction contextualActionWithStyle:UIContextualActionStyleNormal
        title:@"Details" handler:^(UIContextualAction* action, UIView* sourceView,
                                   void (^completionHandler)(BOOL)) {
            (void)action; (void)sourceView;
            NSString* package = [self.tweaks[indexPath.row][@"package"] isKindOfClass:NSString.class]
                ? self.tweaks[indexPath.row][@"package"] : nil;
            [self showPackageDetails:package];
            completionHandler(package.length > 0);
        }];
    details.backgroundColor = UIColor.systemIndigoColor;
    details.image = [UIImage systemImageNamed:@"info.circle"];
    UISwipeActionsConfiguration* configuration =
        [UISwipeActionsConfiguration configurationWithActions:@[export, details]];
    configuration.performsFirstActionWithFullSwipe = NO;
    return configuration;
}

- (void)tableView:(UITableView*)tableView commitEditingStyle:(UITableViewCellEditingStyle)style
    forRowAtIndexPath:(NSIndexPath*)indexPath
{
    if(style != UITableViewCellEditingStyleDelete) return;
    NSDictionary* tweak = self.tweaks[indexPath.row];
    NSString* package = tweak[@"package"];
    [self confirmRemovalOfPackage:package displayName:[self displayTitleForTweak:tweak]];
}

@end
