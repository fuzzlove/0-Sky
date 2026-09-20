#import "TSSnapshotsTableViewController.h"
#import "TSApplicationsManager.h"

@interface TSSnapshotsTableViewController ()
@property(nonatomic,strong) NSDictionary* capability;
@property(nonatomic,copy) NSArray* applications;
@property(nonatomic,copy) NSArray* snapshots;
@property(nonatomic,copy) NSArray* changes;
@property(nonatomic,copy) NSString* query;
@property(nonatomic,strong) UIRefreshControl* pullRefresh;
@property(nonatomic,assign) BOOL loading;
@end

@implementation TSSnapshotsTableViewController

- (instancetype)init { return [super initWithStyle:UITableViewStyleInsetGrouped]; }

- (void)viewDidLoad
{
    [super viewDidLoad];
    self.title = @"Snapshots";
    self.pullRefresh = [UIRefreshControl new];
    [self.pullRefresh addTarget:self action:@selector(refresh)
        forControlEvents:UIControlEventValueChanged];
    self.refreshControl = self.pullRefresh;
    self.navigationItem.rightBarButtonItem = [[UIBarButtonItem alloc]
        initWithBarButtonSystemItem:UIBarButtonSystemItemRefresh target:self
        action:@selector(refresh)];
    UISearchController* search = [[UISearchController alloc] initWithSearchResultsController:nil];
    search.obscuresBackgroundDuringPresentation = NO;
    search.searchResultsUpdater = self;
    search.searchBar.placeholder = @"Search applications";
    self.navigationItem.searchController = search;
    self.navigationItem.hidesSearchBarWhenScrolling = YES;
    self.definesPresentationContext = YES;
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
    self.navigationItem.prompt = @"Reading integrity-protected snapshots…";
    dispatch_async(dispatch_get_global_queue(QOS_CLASS_UTILITY, 0), ^{
        NSDictionary* capability = [self resultForOperation:@"getSnapshotCapability"
            parameters:@{} error:nil];
        NSDictionary* apps = [self resultForOperation:@"getSnapshotApps"
            parameters:@{} error:nil];
        NSDictionary* snapshots = [self resultForOperation:@"getSnapshots"
            parameters:@{@"limit": @200} error:nil];
        NSDictionary* changes = [self resultForOperation:@"getRecentChanges"
            parameters:@{@"limit": @50} error:nil];
        dispatch_async(dispatch_get_main_queue(), ^{
            self.capability = capability;
            self.applications = [apps[@"applications"] isKindOfClass:NSArray.class]
                ? apps[@"applications"] : @[];
            self.snapshots = [snapshots[@"snapshots"] isKindOfClass:NSArray.class]
                ? snapshots[@"snapshots"] : @[];
            self.changes = [changes[@"changes"] isKindOfClass:NSArray.class]
                ? changes[@"changes"] : @[];
            self.loading = NO;
            self.navigationItem.rightBarButtonItem.enabled = YES;
            [self.pullRefresh endRefreshing];
            self.navigationItem.prompt = capability
                ? [NSString stringWithFormat:@"%@ • keychain excluded",
                    capability[@"state"] ?: @"Unknown"]
                : @"0-Sky Core is temporarily unavailable";
            [self.tableView reloadData];
        });
    });
}

- (void)updateSearchResultsForSearchController:(UISearchController*)searchController
{
    self.query = searchController.searchBar.text ?: @"";
    [self.tableView reloadSections:[NSIndexSet indexSetWithIndex:1]
        withRowAnimation:UITableViewRowAnimationAutomatic];
}

- (NSArray*)visibleApplications
{
    if(!self.query.length) return self.applications ?: @[];
    NSString* needle = self.query.lowercaseString;
    NSPredicate* predicate = [NSPredicate predicateWithBlock:^BOOL(NSDictionary* app,
        NSDictionary* bindings) {
        (void)bindings;
        return [[app[@"name"] ?: @"" lowercaseString] containsString:needle] ||
               [[app[@"bundleID"] ?: @"" lowercaseString] containsString:needle];
    }];
    return [self.applications filteredArrayUsingPredicate:predicate];
}

- (NSString*)size:(NSNumber*)value
{
    return [NSByteCountFormatter stringFromByteCount:value.longLongValue
        countStyle:NSByteCountFormatterCountStyleFile];
}

- (NSString*)date:(NSNumber*)value
{
    if(![value isKindOfClass:NSNumber.class]) return @"Unknown time";
    NSDateFormatter* formatter = [NSDateFormatter new];
    formatter.dateStyle = NSDateFormatterMediumStyle;
    formatter.timeStyle = NSDateFormatterShortStyle;
    return [formatter stringFromDate:[NSDate dateWithTimeIntervalSince1970:value.doubleValue]];
}

- (NSInteger)numberOfSectionsInTableView:(UITableView*)tableView
{ (void)tableView; return 4; }

- (NSInteger)tableView:(UITableView*)tableView numberOfRowsInSection:(NSInteger)section
{
    (void)tableView;
    if(section == 0) return 1;
    if(section == 1) return MAX(1, (NSInteger)self.visibleApplications.count);
    if(section == 2) return MAX(1, (NSInteger)self.snapshots.count);
    return MAX(1, (NSInteger)self.changes.count);
}

- (NSString*)tableView:(UITableView*)tableView titleForHeaderInSection:(NSInteger)section
{ (void)tableView; return @[@"Snapshot Safety", @"Create Snapshot", @"Saved Snapshots", @"Recent Changes"][section]; }

- (NSString*)tableView:(UITableView*)tableView titleForFooterInSection:(NSInteger)section
{
    (void)tableView;
    if(section == 0) return @"Only Documents, Preferences, Application Support, and Saved Application State are included. Keychain databases, caches, temporary data, and other containers are never copied.";
    if(section == 2) return @"Restore verifies every SHA-256 hash, stops only the exact target app, and creates a safety snapshot first. Deletion always requires confirmation.";
    if(section == 3) return @"Undo is offered only for a validated reversible restore and is rejected if application state changed afterward.";
    return nil;
}

- (UITableViewCell*)empty:(NSString*)title detail:(NSString*)detail
{
    UITableViewCell* cell = [[UITableViewCell alloc]
        initWithStyle:UITableViewCellStyleSubtitle reuseIdentifier:nil];
    cell.textLabel.text = title;
    cell.detailTextLabel.text = detail;
    cell.detailTextLabel.numberOfLines = 2;
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
        cell.textLabel.text = self.capability[@"state"] ?: @"Unavailable";
        cell.detailTextLabel.text = self.capability[@"reason"] ?: @"Pull to refresh";
        cell.imageView.image = [UIImage systemImageNamed:[self.capability[@"state"] isEqual:@"Supported"]
            ? @"checkmark.shield.fill" : @"exclamationmark.triangle.fill"];
        cell.selectionStyle = UITableViewCellSelectionStyleNone;
    } else if(indexPath.section == 1) {
        NSArray* apps = self.visibleApplications;
        if(!apps.count) return [self empty:@"No compatible application"
            detail:@"Only exact current third-party data containers are eligible"];
        NSDictionary* app = apps[indexPath.row];
        cell.textLabel.text = app[@"name"] ?: app[@"bundleID"];
        cell.detailTextLabel.text = [NSString stringWithFormat:@"%@ • %@",
            app[@"bundleID"] ?: @"Unknown bundle", app[@"version"] ?: @"Unknown version"];
        cell.imageView.image = [UIImage systemImageNamed:@"camera.on.rectangle"];
        cell.accessoryType = UITableViewCellAccessoryDisclosureIndicator;
    } else if(indexPath.section == 2) {
        if(!self.snapshots.count) return [self empty:@"No snapshots"
            detail:@"Select an application above to create one"];
        NSDictionary* snapshot = self.snapshots[indexPath.row];
        cell.textLabel.text = snapshot[@"bundle_id"] ?: @"Unknown application";
        cell.detailTextLabel.text = [NSString stringWithFormat:@"%@ • %@ • %@ files",
            [self date:snapshot[@"created_at"]], [self size:snapshot[@"total_size"] ?: @0],
            snapshot[@"file_count"] ?: @0];
        cell.imageView.image = [UIImage systemImageNamed:@"clock.arrow.circlepath"];
        cell.accessoryType = UITableViewCellAccessoryDisclosureIndicator;
    } else {
        if(!self.changes.count) return [self empty:@"No recent changes"
            detail:@"0-Sky actions will appear here"];
        NSDictionary* change = self.changes[indexPath.row];
        cell.textLabel.text = [change[@"action"] stringByReplacingOccurrencesOfString:@"_" withString:@" "];
        cell.detailTextLabel.text = [NSString stringWithFormat:@"%@ • %@",
            change[@"target"] ?: @"Unknown target", [self date:change[@"timestamp"]]];
        BOOL undo = [change[@"reversible"] boolValue] && !change[@"undone_at"] &&
            [change[@"undo_operation"] isEqual:@"restoreSnapshot"];
        cell.imageView.image = [UIImage systemImageNamed:undo ? @"arrow.uturn.backward.circle" : @"list.bullet.rectangle"];
        cell.accessoryType = undo ? UITableViewCellAccessoryDisclosureIndicator : UITableViewCellAccessoryNone;
        cell.selectionStyle = undo ? UITableViewCellSelectionStyleDefault : UITableViewCellSelectionStyleNone;
    }
    return cell;
}

- (void)showError:(NSError*)error
{
    UIAlertController* alert = [UIAlertController alertControllerWithTitle:@"Snapshot Action Failed"
        message:error.localizedDescription ?: @"The operation could not be completed."
        preferredStyle:UIAlertControllerStyleAlert];
    [alert addAction:[UIAlertAction actionWithTitle:@"OK" style:UIAlertActionStyleCancel handler:nil]];
    [self presentViewController:alert animated:YES completion:nil];
}

- (void)runOperation:(NSString*)operation parameters:(NSDictionary*)parameters
{
    self.navigationItem.prompt = @"Working… keep 0-Sky Control open";
    self.navigationItem.rightBarButtonItem.enabled = NO;
    dispatch_async(dispatch_get_global_queue(QOS_CLASS_USER_INITIATED, 0), ^{
        NSError* error = nil;
        NSDictionary* result = [self resultForOperation:operation parameters:parameters error:&error];
        dispatch_async(dispatch_get_main_queue(), ^{
            self.navigationItem.rightBarButtonItem.enabled = YES;
            if(!result) { [self showError:error]; [self refresh]; return; }
            [self refresh];
        });
    });
}

- (void)presentActions:(UIAlertController*)sheet source:(UITableViewCell*)cell
{
    UIPopoverPresentationController* popover = sheet.popoverPresentationController;
    if(popover) { popover.sourceView = cell; popover.sourceRect = cell.bounds;
        popover.permittedArrowDirections = UIPopoverArrowDirectionAny; }
    [self presentViewController:sheet animated:YES completion:nil];
}

- (void)tableView:(UITableView*)tableView didSelectRowAtIndexPath:(NSIndexPath*)indexPath
{
    [tableView deselectRowAtIndexPath:indexPath animated:YES];
    UITableViewCell* cell = [tableView cellForRowAtIndexPath:indexPath];
    if(indexPath.section == 1 && self.visibleApplications.count) {
        NSDictionary* app = self.visibleApplications[indexPath.row];
        UIAlertController* sheet = [UIAlertController alertControllerWithTitle:@"Create Snapshot?"
            message:[NSString stringWithFormat:@"Create an integrity-protected snapshot of %@? Protected and unrelated data will be excluded.", app[@"name"] ?: app[@"bundleID"]]
            preferredStyle:UIAlertControllerStyleActionSheet];
        [sheet addAction:[UIAlertAction actionWithTitle:@"Create Snapshot"
            style:UIAlertActionStyleDefault handler:^(UIAlertAction* action) {
                (void)action; [self runOperation:@"createSnapshot"
                    parameters:@{@"bundleID": app[@"bundleID"]}];
            }]];
        [sheet addAction:[UIAlertAction actionWithTitle:@"Cancel" style:UIAlertActionStyleCancel handler:nil]];
        [self presentActions:sheet source:cell];
    } else if(indexPath.section == 2 && self.snapshots.count) {
        NSDictionary* snapshot = self.snapshots[indexPath.row];
        NSNumber* snapshotID = snapshot[@"id"];
        UIAlertController* sheet = [UIAlertController alertControllerWithTitle:snapshot[@"bundle_id"]
            message:@"Restore verifies all files and creates a safety snapshot before changing application state."
            preferredStyle:UIAlertControllerStyleActionSheet];
        [sheet addAction:[UIAlertAction actionWithTitle:@"Verify Integrity"
            style:UIAlertActionStyleDefault handler:^(UIAlertAction* action) {
                (void)action; [self runOperation:@"getSnapshotDetail"
                    parameters:@{@"snapshotID": snapshotID, @"verify": @YES}];
            }]];
        [sheet addAction:[UIAlertAction actionWithTitle:@"Restore Snapshot"
            style:UIAlertActionStyleDefault handler:^(UIAlertAction* action) {
                (void)action; [self runOperation:@"restoreSnapshot"
                    parameters:@{@"snapshotID": snapshotID}];
            }]];
        [sheet addAction:[UIAlertAction actionWithTitle:@"Delete Snapshot"
            style:UIAlertActionStyleDestructive handler:^(UIAlertAction* action) {
                (void)action; [self runOperation:@"deleteSnapshot"
                    parameters:@{@"snapshotID": snapshotID}];
            }]];
        [sheet addAction:[UIAlertAction actionWithTitle:@"Cancel" style:UIAlertActionStyleCancel handler:nil]];
        [self presentActions:sheet source:cell];
    } else if(indexPath.section == 3 && self.changes.count) {
        NSDictionary* change = self.changes[indexPath.row];
        BOOL undo = [change[@"reversible"] boolValue] && !change[@"undone_at"] &&
            [change[@"undo_operation"] isEqual:@"restoreSnapshot"];
        if(!undo) return;
        UIAlertController* sheet = [UIAlertController alertControllerWithTitle:@"Undo Restore?"
            message:@"Undo proceeds only if the application state still matches the recorded restore. A new safety snapshot is created first."
            preferredStyle:UIAlertControllerStyleActionSheet];
        [sheet addAction:[UIAlertAction actionWithTitle:@"Undo"
            style:UIAlertActionStyleDestructive handler:^(UIAlertAction* action) {
                (void)action; [self runOperation:@"undoChange"
                    parameters:@{@"changeID": change[@"id"]}];
            }]];
        [sheet addAction:[UIAlertAction actionWithTitle:@"Cancel" style:UIAlertActionStyleCancel handler:nil]];
        [self presentActions:sheet source:cell];
    }
}

@end
