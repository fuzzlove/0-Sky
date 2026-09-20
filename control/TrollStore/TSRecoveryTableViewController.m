#import "TSRecoveryTableViewController.h"
#import "TSApplicationsManager.h"

@interface TSRecoveryTableViewController ()
@property(nonatomic,strong) NSDictionary* recovery;
@property(nonatomic,copy) NSArray* crashes;
@property(nonatomic,copy) NSArray* conflicts;
@property(nonatomic,copy) NSArray* recoveryOptions;
@property(nonatomic,strong) UIRefreshControl* pullRefresh;
@property(nonatomic,assign) BOOL loading;
@end

@implementation TSRecoveryTableViewController

- (instancetype)init { return [super initWithStyle:UITableViewStyleInsetGrouped]; }

- (void)viewDidLoad
{
    [super viewDidLoad];
    self.title = @"Recovery";
    self.pullRefresh = [UIRefreshControl new];
    [self.pullRefresh addTarget:self action:@selector(refresh)
        forControlEvents:UIControlEventValueChanged];
    self.refreshControl = self.pullRefresh;
    self.navigationItem.rightBarButtonItem = [[UIBarButtonItem alloc]
        initWithBarButtonSystemItem:UIBarButtonSystemItemRefresh
        target:self action:@selector(refresh)];
    [[NSNotificationCenter defaultCenter] addObserver:self selector:@selector(refresh)
        name:UIApplicationDidBecomeActiveNotification object:nil];
    [self refresh];
}

- (void)dealloc { [[NSNotificationCenter defaultCenter] removeObserver:self]; }

- (NSDictionary*)resultForOperation:(NSString*)operation parameters:(NSDictionary*)parameters
    error:(NSError**)error
{
    NSDictionary* envelope = [[TSApplicationsManager sharedInstance]
        coreRequestOperation:operation parameters:parameters error:error];
    if(![envelope[@"success"] boolValue]) {
        if(error && !*error) *error = [NSError errorWithDomain:@"com.liquidsky.CrypStore.Core"
            code:1 userInfo:@{NSLocalizedDescriptionKey:
                envelope[@"errorMessage"] ?: @"The Core request failed."}];
        return nil;
    }
    return [envelope[@"result"] isKindOfClass:NSDictionary.class] ? envelope[@"result"] : nil;
}

- (void)refresh
{
    if(self.loading) { [self.pullRefresh endRefreshing]; return; }
    self.loading = YES;
    self.navigationItem.rightBarButtonItem.enabled = NO;
    self.navigationItem.prompt = @"Reading crash and conflict evidence…";
    dispatch_async(dispatch_get_global_queue(QOS_CLASS_UTILITY, 0), ^{
        NSDictionary* recovery = [self resultForOperation:@"getRecoveryStatus" parameters:@{} error:nil];
        NSDictionary* crashResult = [self resultForOperation:@"getCrashes"
            parameters:@{@"limit": @100} error:nil];
        NSDictionary* conflictResult = [self resultForOperation:@"getConflicts"
            parameters:@{@"limit": @100} error:nil];
        NSDictionary* optionResult = [self resultForOperation:@"getRecoveryOptions"
            parameters:@{} error:nil];
        dispatch_async(dispatch_get_main_queue(), ^{
            self.recovery = recovery;
            self.crashes = [crashResult[@"crashes"] isKindOfClass:NSArray.class]
                ? crashResult[@"crashes"] : @[];
            self.conflicts = [conflictResult[@"conflicts"] isKindOfClass:NSArray.class]
                ? conflictResult[@"conflicts"] : @[];
            self.recoveryOptions = [optionResult[@"options"] isKindOfClass:NSArray.class]
                ? optionResult[@"options"] : @[];
            self.loading = NO;
            self.navigationItem.rightBarButtonItem.enabled = YES;
            [self.pullRefresh endRefreshing];
            self.navigationItem.prompt = recovery
                ? (recovery[@"requestPending"] ? @"A recovery action is pending…"
                                               : @"Safe Mode 2.0 • no package is deleted")
                : @"0-Sky Core is temporarily unavailable";
            [self.tableView reloadData];
        });
    });
}

- (NSArray*)targets
{ return [self.recovery[@"targets"] isKindOfClass:NSArray.class] ? self.recovery[@"targets"] : @[]; }
- (NSArray*)episodes
{ return [self.recovery[@"episodes"] isKindOfClass:NSArray.class] ? self.recovery[@"episodes"] : @[]; }

- (NSInteger)numberOfSectionsInTableView:(UITableView*)tableView
{ (void)tableView; return 5; }

- (NSInteger)tableView:(UITableView*)tableView numberOfRowsInSection:(NSInteger)section
{
    (void)tableView;
    if(section == 0) return 2;
    if(section == 1) return MAX(1, (NSInteger)self.targets.count);
    if(section == 2) return MAX(1, (NSInteger)self.conflicts.count);
    if(section == 3) return MAX(1, (NSInteger)self.crashes.count);
    return MAX(1, (NSInteger)self.recoveryOptions.count);
}

- (NSString*)tableView:(UITableView*)tableView titleForHeaderInSection:(NSInteger)section
{
    (void)tableView;
    return @[@"Safe Mode", @"Recovery Targets", @"Conflict Evidence", @"Crash Reports",
             @"Recovery Framework"][section];
}

- (NSString*)tableView:(UITableView*)tableView titleForFooterInSection:(NSInteger)section
{
    (void)tableView;
    if(section == 0) return @"Recovery actions are paired-Mac authenticated, exact-target bounded, reversible, and never uninstall a package.";
    if(section == 2) return @"Shared process filters alone are informational. Possible and probable conflicts require stronger evidence.";
    if(section == 3) return @"Only bounded Apple crash metadata is shown. Configured-for-process is not proof that a tweak caused a crash.";
    if(section == 4) return @"Host-only and unsupported operations are labeled explicitly. Database reset is never exposed through app IPC.";
    return nil;
}

- (UITableViewCell*)emptyCellWithTitle:(NSString*)title detail:(NSString*)detail
{
    UITableViewCell* cell = [[UITableViewCell alloc]
        initWithStyle:UITableViewCellStyleSubtitle reuseIdentifier:nil];
    cell.textLabel.text = title;
    cell.detailTextLabel.text = detail;
    cell.detailTextLabel.numberOfLines = 2;
    cell.textLabel.font = [UIFont preferredFontForTextStyle:UIFontTextStyleBody];
    cell.detailTextLabel.font = [UIFont preferredFontForTextStyle:UIFontTextStyleFootnote];
    cell.textLabel.adjustsFontForContentSizeCategory = YES;
    cell.detailTextLabel.adjustsFontForContentSizeCategory = YES;
    cell.selectionStyle = UITableViewCellSelectionStyleNone;
    return cell;
}

- (UITableViewCell*)tableView:(UITableView*)tableView cellForRowAtIndexPath:(NSIndexPath*)indexPath
{
    (void)tableView;
    UITableViewCell* cell = [[UITableViewCell alloc]
        initWithStyle:UITableViewCellStyleSubtitle reuseIdentifier:nil];
    cell.detailTextLabel.numberOfLines = 2;
    if(indexPath.section == 0) {
        if(indexPath.row == 0) {
            cell.textLabel.text = @"Injection";
            cell.detailTextLabel.text = [self.recovery[@"injectionPaused"] boolValue]
                ? @"Globally paused" : @"Normal global state";
            cell.imageView.image = [UIImage systemImageNamed:@"syringe"];
        } else {
            NSDictionary* safe = [self.recovery[@"safeMode"] isKindOfClass:NSDictionary.class]
                ? self.recovery[@"safeMode"] : @{};
            NSDictionary* active = [safe[@"targets"] isKindOfClass:NSDictionary.class]
                ? safe[@"targets"] : @{};
            cell.textLabel.text = @"Temporary Overrides";
            cell.detailTextLabel.text = [NSString stringWithFormat:@"%lu active • %@",
                (unsigned long)active.count,
                [self.recovery[@"actionsAvailable"] boolValue] ? @"Actions available" : @"Unavailable"];
            cell.imageView.image = [UIImage systemImageNamed:@"cross.case"];
        }
        cell.selectionStyle = UITableViewCellSelectionStyleNone;
        return cell;
    }
    if(indexPath.section == 1) {
        if(!self.targets.count) return [self emptyCellWithTitle:@"No current tweak target"
            detail:self.recovery[@"message"] ?: @"Pull to refresh"];
        NSDictionary* target = self.targets[indexPath.row];
        NSString* process = target[@"process"] ?: @"Unknown target";
        NSDictionary* episode = nil;
        for(NSDictionary* value in self.episodes)
            if([value[@"process"] isEqual:process]) { episode = value; break; }
        cell.textLabel.text = process;
        cell.detailTextLabel.text = [NSString stringWithFormat:@"%@ • %@ packages%@",
            target[@"kind"] ?: @"target", target[@"packageCount"] ?: @0,
            episode ? [NSString stringWithFormat:@" • %@ crashes/10 min", episode[@"crashCount"]] : @""];
        cell.imageView.image = [UIImage systemImageNamed:[episode[@"triggered"] boolValue]
            ? @"exclamationmark.triangle.fill" : @"lifepreserver"];
        cell.accessoryType = UITableViewCellAccessoryDisclosureIndicator;
        return cell;
    }
    if(indexPath.section == 2) {
        if(!self.conflicts.count) return [self emptyCellWithTitle:@"No current conflict evidence"
            detail:@"No evidence-backed conflicts are active"];
        NSDictionary* row = self.conflicts[indexPath.row];
        cell.textLabel.text = row[@"target"] ?: @"Unknown target";
        NSDictionary* evidence = [row[@"evidence"] isKindOfClass:NSDictionary.class] ? row[@"evidence"] : @{};
        NSArray* providers = [evidence[@"providers"] isKindOfClass:NSArray.class] ? evidence[@"providers"] : @[];
        cell.detailTextLabel.text = [NSString stringWithFormat:@"%@ • %@",
            row[@"severity"] ?: @"informational",
            providers.count ? [providers componentsJoinedByString:@", "] : (row[@"process"] ?: @"no package attribution")];
        cell.imageView.image = [UIImage systemImageNamed:@"exclamationmark.2"];
        cell.selectionStyle = UITableViewCellSelectionStyleNone;
        return cell;
    }
    if(indexPath.section == 4) {
        if(!self.recoveryOptions.count) return [self emptyCellWithTitle:@"Recovery capabilities unavailable"
            detail:@"Pull to refresh the 0-Sky Core status"];
        NSDictionary* row = self.recoveryOptions[indexPath.row];
        NSString* identifier = [row[@"id"] stringByReplacingOccurrencesOfString:@"-" withString:@" "];
        cell.textLabel.text = [NSString stringWithFormat:@"%@ — %@", row[@"state"] ?: @"Unknown",
            identifier.capitalizedString ?: @"Recovery"];
        cell.detailTextLabel.text = row[@"reason"] ?: @"No capability evidence";
        cell.imageView.image = [UIImage systemImageNamed:[row[@"state"] isEqual:@"Supported"]
            ? @"checkmark.shield" : @"info.circle"];
        cell.selectionStyle = UITableViewCellSelectionStyleNone;
        cell.isAccessibilityElement = YES;
        cell.accessibilityLabel = cell.textLabel.text;
        cell.accessibilityValue = cell.detailTextLabel.text;
        return cell;
    }
    if(!self.crashes.count) return [self emptyCellWithTitle:@"No validated crash metadata"
        detail:@"The crash collector has not stored a report"];
    NSDictionary* row = self.crashes[indexPath.row];
    cell.textLabel.text = row[@"process"] ?: @"Unknown process";
    NSDictionary* evidence = [row[@"evidence"] isKindOfClass:NSDictionary.class] ? row[@"evidence"] : @{};
    cell.detailTextLabel.text = [NSString stringWithFormat:@"%@ • %@",
        row[@"signal"] ?: row[@"reason"] ?: @"Crash",
        evidence[@"attribution"] ?: @"unattributed"];
    cell.imageView.image = [UIImage systemImageNamed:@"doc.text.magnifyingglass"];
    cell.accessoryType = UITableViewCellAccessoryDisclosureIndicator;
    return cell;
}

- (void)showMessage:(NSString*)title message:(NSString*)message
{
    UIAlertController* alert = [UIAlertController alertControllerWithTitle:title message:message
        preferredStyle:UIAlertControllerStyleAlert];
    [alert addAction:[UIAlertAction actionWithTitle:@"Close" style:UIAlertActionStyleDefault handler:nil]];
    [self presentViewController:alert animated:YES completion:nil];
}

- (void)queueAction:(NSString*)operation process:(NSString*)process package:(NSString*)package
{
    NSMutableDictionary* parameters = [@{@"process": process} mutableCopy];
    if(package.length) parameters[@"package"] = package;
    self.navigationItem.prompt = [NSString stringWithFormat:@"Queuing %@…", operation];
    dispatch_async(dispatch_get_global_queue(QOS_CLASS_USER_INITIATED, 0), ^{
        NSError* error = nil;
        NSDictionary* result = [self resultForOperation:operation parameters:parameters error:&error];
        dispatch_async(dispatch_get_main_queue(), ^{
            if(result) {
                [self showMessage:@"Recovery queued"
                    message:@"The manager will apply this reversible action to the exact target. No package will be deleted."];
            } else {
                [self showMessage:@"Recovery not queued"
                    message:error.localizedDescription ?: @"The request was rejected."];
            }
            [self refresh];
        });
    });
}

- (void)presentActionsForTarget:(NSDictionary*)target source:(UITableViewCell*)source
{
    NSString* process = target[@"process"];
    NSArray* packages = [target[@"packages"] isKindOfClass:NSArray.class] ? target[@"packages"] : @[];
    if(!process.length) return;
    UIAlertController* sheet = [UIAlertController alertControllerWithTitle:process
        message:@"Temporary recovery only. Installed packages and preference data are preserved."
        preferredStyle:UIAlertControllerStyleActionSheet];
    [sheet addAction:[UIAlertAction actionWithTitle:@"Restart Normally"
        style:UIAlertActionStyleDefault handler:^(UIAlertAction* action) {
            (void)action; [self queueAction:@"restartNormally" process:process package:nil];
        }]];
    [sheet addAction:[UIAlertAction actionWithTitle:@"Disable Recent Tweaks"
        style:UIAlertActionStyleDefault handler:^(UIAlertAction* action) {
            (void)action; [self queueAction:@"disableRecentTweaks" process:process package:nil];
        }]];
    [sheet addAction:[UIAlertAction actionWithTitle:@"Start Without Tweaks"
        style:UIAlertActionStyleDestructive handler:^(UIAlertAction* action) {
            (void)action; [self queueAction:@"startWithoutTweaks" process:process package:nil];
        }]];
    for(NSString* package in packages) {
        if(![package isKindOfClass:NSString.class]) continue;
        [sheet addAction:[UIAlertAction actionWithTitle:
            [NSString stringWithFormat:@"Disable %@", package]
            style:UIAlertActionStyleDestructive handler:^(UIAlertAction* action) {
                (void)action; [self queueAction:@"disableSelectedTweak" process:process package:package];
            }]];
    }
    [sheet addAction:[UIAlertAction actionWithTitle:@"Cancel" style:UIAlertActionStyleCancel handler:nil]];
    sheet.popoverPresentationController.sourceView = source;
    sheet.popoverPresentationController.sourceRect = source.bounds;
    [self presentViewController:sheet animated:YES completion:nil];
}

- (void)tableView:(UITableView*)tableView didSelectRowAtIndexPath:(NSIndexPath*)indexPath
{
    UITableViewCell* cell = [tableView cellForRowAtIndexPath:indexPath];
    [tableView deselectRowAtIndexPath:indexPath animated:YES];
    if(indexPath.section == 1 && indexPath.row < (NSInteger)self.targets.count) {
        [self presentActionsForTarget:self.targets[indexPath.row] source:cell];
    } else if(indexPath.section == 3 && indexPath.row < (NSInteger)self.crashes.count) {
        NSDictionary* row = self.crashes[indexPath.row];
        NSDictionary* evidence = [row[@"evidence"] isKindOfClass:NSDictionary.class] ? row[@"evidence"] : @{};
        NSArray* packages = [row[@"package_candidates"] isKindOfClass:NSArray.class] ? row[@"package_candidates"] : @[];
        NSString* message = [NSString stringWithFormat:
            @"Signal: %@\nReason: %@\nIncident: %@\nAttribution: %@\nCandidates: %@\n\nReport: %@",
            row[@"signal"] ?: @"Unavailable", row[@"reason"] ?: @"Unavailable",
            row[@"incident_id"] ?: @"Unavailable", evidence[@"attribution"] ?: @"Unattributed",
            packages.count ? [packages componentsJoinedByString:@", "] : @"None",
            row[@"report_path"] ?: @"Unavailable"];
        [self showMessage:@"Crash Report" message:message];
    }
}

@end
