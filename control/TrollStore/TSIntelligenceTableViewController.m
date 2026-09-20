#import "TSIntelligenceTableViewController.h"
#import "TSApplicationsManager.h"

@interface TSIntelligenceTableViewController ()
@property(nonatomic,strong) NSDictionary* storage;
@property(nonatomic,strong) NSDictionary* notifications;
@property(nonatomic,strong) NSDictionary* permissionCapability;
@property(nonatomic,copy) NSArray* timeouts;
@property(nonatomic,copy) NSArray* applications;
@property(nonatomic,strong) UIRefreshControl* pullRefresh;
@property(nonatomic,assign) BOOL loading;
@end

@implementation TSIntelligenceTableViewController
- (instancetype)init { return [super initWithStyle:UITableViewStyleInsetGrouped]; }
- (void)viewDidLoad {
    [super viewDidLoad]; self.title = @"Insights";
    self.pullRefresh = [UIRefreshControl new];
    [self.pullRefresh addTarget:self action:@selector(refresh) forControlEvents:UIControlEventValueChanged];
    self.refreshControl = self.pullRefresh;
    self.navigationItem.rightBarButtonItem = [[UIBarButtonItem alloc]
        initWithBarButtonSystemItem:UIBarButtonSystemItemRefresh target:self action:@selector(refresh)];
    [[NSNotificationCenter defaultCenter] addObserver:self selector:@selector(refresh)
        name:UIApplicationDidBecomeActiveNotification object:nil];
    [self refresh];
}
- (void)dealloc { [[NSNotificationCenter defaultCenter] removeObserver:self]; }
- (NSDictionary*)result:(NSString*)operation parameters:(NSDictionary*)parameters error:(NSError**)error {
    NSDictionary* envelope = [[TSApplicationsManager sharedInstance]
        coreRequestOperation:operation parameters:parameters error:error];
    if(![envelope[@"success"] boolValue]) {
        if(error && !*error) *error = [NSError errorWithDomain:@"com.liquidsky.CrypStore.Core"
            code:1 userInfo:@{NSLocalizedDescriptionKey: envelope[@"errorMessage"] ?: @"Core request failed."}];
        return nil;
    }
    return [envelope[@"result"] isKindOfClass:NSDictionary.class] ? envelope[@"result"] : nil;
}
- (void)refresh {
    if(self.loading) { [self.pullRefresh endRefreshing]; return; }
    self.loading = YES; self.navigationItem.rightBarButtonItem.enabled = NO;
    self.navigationItem.prompt = @"Classifying locally…";
    dispatch_async(dispatch_get_global_queue(QOS_CLASS_UTILITY, 0), ^{
        NSDictionary* storage = [self result:@"getStorageIntelligence" parameters:@{} error:nil];
        NSDictionary* notifications = [self result:@"getNotificationAnalytics" parameters:@{} error:nil];
        NSDictionary* permissions = [self result:@"getPermissionTimeouts"
            parameters:@{@"activeOnly": @NO, @"limit": @100} error:nil];
        NSDictionary* apps = [self result:@"getFrozenApps" parameters:@{} error:nil];
        dispatch_async(dispatch_get_main_queue(), ^{
            self.storage = storage; self.notifications = notifications;
            self.permissionCapability = [permissions[@"capability"] isKindOfClass:NSDictionary.class] ? permissions[@"capability"] : nil;
            self.timeouts = [permissions[@"timeouts"] isKindOfClass:NSArray.class] ? permissions[@"timeouts"] : @[];
            self.applications = [apps[@"applications"] isKindOfClass:NSArray.class] ? apps[@"applications"] : @[];
            self.loading = NO; self.navigationItem.rightBarButtonItem.enabled = YES;
            [self.pullRefresh endRefreshing];
            self.navigationItem.prompt = @"Local metadata • no notification content";
            [self.tableView reloadData];
        });
    });
}
- (NSArray*)categories { return @[@"Applications", @"Application Data", @"Application Caches",
    @"Package Archives", @"Logs", @"Crash Reports", @"Snapshots", @"0-Sky Data", @"Temporary Data"]; }
- (NSInteger)numberOfSectionsInTableView:(UITableView*)tableView { (void)tableView; return 5; }
- (NSInteger)tableView:(UITableView*)tableView numberOfRowsInSection:(NSInteger)section {
    (void)tableView;
    if(section == 0) return 2;
    if(section == 1) return self.categories.count;
    if(section == 2) return MAX(1, (NSInteger)[self.notifications[@"mostFrequentApps"] count]);
    if(section == 3) return MAX(1, (NSInteger)self.timeouts.count);
    return [self.permissionCapability[@"state"] isEqual:@"Supported"] ? MAX(1, (NSInteger)self.applications.count) : 1;
}
- (NSString*)tableView:(UITableView*)tableView titleForHeaderInSection:(NSInteger)section {
    (void)tableView; return @[@"Capabilities", @"Storage", @"Notification Frequency", @"Permission Timeouts", @"New Timeout"][section];
}
- (NSString*)tableView:(UITableView*)tableView titleForFooterInSection:(NSInteger)section {
    (void)tableView;
    if(section == 1) return @"Every candidate has an exact path, owner, estimated size, and safety class. This view is read-only and never recursively deletes by path substring.";
    if(section == 2) return @"Only local application, timestamp, frequency, and optional category identifiers are accepted. Notification title, body, attachments, and userInfo are never stored or uploaded.";
    if(section == 4) return @"Once, 5 minutes, 15 minutes, 1 hour, until app exit, and until screen lock restore the original policy. Controls remain disabled without a reviewed enforcement provider.";
    return nil;
}
- (UITableViewCell*)empty:(NSString*)title detail:(NSString*)detail {
    UITableViewCell* cell = [[UITableViewCell alloc] initWithStyle:UITableViewCellStyleSubtitle reuseIdentifier:nil];
    cell.textLabel.text = title; cell.detailTextLabel.text = detail; cell.detailTextLabel.numberOfLines = 3;
    cell.selectionStyle = UITableViewCellSelectionStyleNone; return cell;
}
- (NSString*)size:(NSNumber*)number { return [NSByteCountFormatter stringFromByteCount:number.longLongValue countStyle:NSByteCountFormatterCountStyleFile]; }
- (UITableViewCell*)tableView:(UITableView*)tableView cellForRowAtIndexPath:(NSIndexPath*)indexPath {
    (void)tableView; UITableViewCell* cell = [[UITableViewCell alloc] initWithStyle:UITableViewCellStyleSubtitle reuseIdentifier:nil];
    cell.detailTextLabel.numberOfLines = 3;
    if(indexPath.section == 0) {
        if(indexPath.row == 0) { cell.textLabel.text = @"Storage Intelligence";
            cell.detailTextLabel.text = self.storage ? @"Supported • bounded exact-root classification" : @"Unavailable";
            cell.imageView.image = [UIImage systemImageNamed:@"internaldrive.fill"]; }
        else { cell.textLabel.text = @"Permission Timeouts";
            cell.detailTextLabel.text = self.permissionCapability[@"reason"] ?: @"Unavailable";
            cell.imageView.image = [UIImage systemImageNamed:[self.permissionCapability[@"state"] isEqual:@"Supported"] ? @"timer" : @"eye.fill"]; }
        cell.selectionStyle = UITableViewCellSelectionStyleNone;
    } else if(indexPath.section == 1) {
        NSString* category = self.categories[indexPath.row]; NSNumber* total = self.storage[@"categoryTotals"][category] ?: @0;
        NSArray* candidates = [self.storage[@"candidates"] filteredArrayUsingPredicate:
            [NSPredicate predicateWithBlock:^BOOL(NSDictionary* row, NSDictionary* bindings){ (void)bindings; return [row[@"category"] isEqual:category]; }]];
        cell.textLabel.text = category; cell.detailTextLabel.text = [NSString stringWithFormat:@"%@ • %lu candidate(s)", [self size:total], (unsigned long)candidates.count];
        cell.imageView.image = [UIImage systemImageNamed:@"folder.fill"]; cell.selectionStyle = UITableViewCellSelectionStyleNone;
    } else if(indexPath.section == 2) {
        NSArray* rows = self.notifications[@"mostFrequentApps"];
        if(![rows isKindOfClass:NSArray.class] || !rows.count) return [self empty:@"No reviewed notification metadata" detail:self.notifications[@"message"] ?: @"Unsupported never means zero notifications"];
        NSDictionary* row = rows[indexPath.row]; cell.textLabel.text = row[@"bundle_id"];
        cell.detailTextLabel.text = [NSString stringWithFormat:@"%@ in 24 hours • %@ category identifier(s)", row[@"count"] ?: @0, row[@"category_count"] ?: @0];
        cell.imageView.image = [UIImage systemImageNamed:@"bell.badge.fill"]; cell.selectionStyle = UITableViewCellSelectionStyleNone;
    } else if(indexPath.section == 3) {
        if(!self.timeouts.count) return [self empty:@"No permission timeouts" detail:@"Active and expired reversible policies appear here"];
        NSDictionary* row = self.timeouts[indexPath.row]; cell.textLabel.text = [NSString stringWithFormat:@"%@ • %@", row[@"resource"], row[@"requested_policy"]];
        cell.detailTextLabel.text = [NSString stringWithFormat:@"%@ • %@ • %@", row[@"bundle_id"], row[@"duration"], row[@"state"]];
        BOOL active = [row[@"state"] isEqual:@"Active"]; cell.accessoryType = active ? UITableViewCellAccessoryDisclosureIndicator : UITableViewCellAccessoryNone;
        cell.selectionStyle = active ? UITableViewCellSelectionStyleDefault : UITableViewCellSelectionStyleNone;
    } else {
        if(![self.permissionCapability[@"state"] isEqual:@"Supported"]) return [self empty:@"Monitor Only" detail:self.permissionCapability[@"reason"] ?: @"No reviewed provider"];
        if(!self.applications.count) return [self empty:@"No compatible applications" detail:@"No exact third-party app registration is available"];
        NSDictionary* app = self.applications[indexPath.row]; cell.textLabel.text = app[@"name"] ?: app[@"bundleID"];
        cell.detailTextLabel.text = app[@"bundleID"]; cell.accessoryType = UITableViewCellAccessoryDisclosureIndicator;
    }
    return cell;
}
- (void)showError:(NSError*)error { UIAlertController* alert = [UIAlertController alertControllerWithTitle:@"Intelligence Action Failed" message:error.localizedDescription ?: @"The action failed." preferredStyle:UIAlertControllerStyleAlert]; [alert addAction:[UIAlertAction actionWithTitle:@"OK" style:UIAlertActionStyleCancel handler:nil]]; [self presentViewController:alert animated:YES completion:nil]; }
- (void)run:(NSString*)operation parameters:(NSDictionary*)parameters { dispatch_async(dispatch_get_global_queue(QOS_CLASS_USER_INITIATED, 0), ^{ NSError* error=nil; NSDictionary* result=[self result:operation parameters:parameters error:&error]; dispatch_async(dispatch_get_main_queue(), ^{ if(!result) [self showError:error]; [self refresh]; }); }); }
- (void)presentSheet:(UIAlertController*)sheet cell:(UITableViewCell*)cell { UIPopoverPresentationController* popover=sheet.popoverPresentationController; if(popover){popover.sourceView=cell;popover.sourceRect=cell.bounds;popover.permittedArrowDirections=UIPopoverArrowDirectionAny;} [self presentViewController:sheet animated:YES completion:nil]; }
- (void)chooseDurationForApp:(NSDictionary*)app resource:(NSString*)resource policy:(NSString*)policy cell:(UITableViewCell*)cell {
    UIAlertController* sheet=[UIAlertController alertControllerWithTitle:@"Temporary Duration" message:@"The original policy is stored and restored on expiration." preferredStyle:UIAlertControllerStyleActionSheet];
    for(NSString* duration in @[@"once",@"5 minutes",@"15 minutes",@"1 hour",@"until app exits",@"until screen locks"]) [sheet addAction:[UIAlertAction actionWithTitle:duration style:UIAlertActionStyleDefault handler:^(UIAlertAction* a){(void)a;[self run:@"setTemporaryPermission" parameters:@{@"bundleID":app[@"bundleID"],@"resource":resource,@"policy":policy,@"duration":duration}];}]];
    [sheet addAction:[UIAlertAction actionWithTitle:@"Cancel" style:UIAlertActionStyleCancel handler:nil]]; [self presentSheet:sheet cell:cell];
}
- (void)choosePolicyForApp:(NSDictionary*)app resource:(NSString*)resource cell:(UITableViewCell*)cell {
    UIAlertController* sheet=[UIAlertController alertControllerWithTitle:resource message:@"Choose a temporary policy." preferredStyle:UIAlertControllerStyleActionSheet];
    for(NSString* policy in @[@"System Default",@"Allow",@"Ask",@"Block"]) [sheet addAction:[UIAlertAction actionWithTitle:policy style:UIAlertActionStyleDefault handler:^(UIAlertAction* a){(void)a;[self chooseDurationForApp:app resource:resource policy:policy cell:cell];}]];
    [sheet addAction:[UIAlertAction actionWithTitle:@"Cancel" style:UIAlertActionStyleCancel handler:nil]]; [self presentSheet:sheet cell:cell];
}
- (void)tableView:(UITableView*)tableView didSelectRowAtIndexPath:(NSIndexPath*)indexPath {
    [tableView deselectRowAtIndexPath:indexPath animated:YES]; UITableViewCell* cell=[tableView cellForRowAtIndexPath:indexPath];
    if(indexPath.section==3 && self.timeouts.count) { NSDictionary* row=self.timeouts[indexPath.row]; if(![row[@"state"] isEqual:@"Active"]) return; UIAlertController* sheet=[UIAlertController alertControllerWithTitle:@"Revert Now?" message:@"Restore the exact policy recorded before this timeout?" preferredStyle:UIAlertControllerStyleActionSheet]; [sheet addAction:[UIAlertAction actionWithTitle:@"Revert" style:UIAlertActionStyleDestructive handler:^(UIAlertAction* a){(void)a;[self run:@"revertPermissionTimeout" parameters:@{@"timeoutID":row[@"id"]}];}]]; [sheet addAction:[UIAlertAction actionWithTitle:@"Cancel" style:UIAlertActionStyleCancel handler:nil]]; [self presentSheet:sheet cell:cell]; }
    else if(indexPath.section==4 && [self.permissionCapability[@"state"] isEqual:@"Supported"] && self.applications.count) { NSDictionary* app=self.applications[indexPath.row]; UIAlertController* sheet=[UIAlertController alertControllerWithTitle:app[@"name"] message:@"Choose a capability-backed permission." preferredStyle:UIAlertControllerStyleActionSheet]; NSDictionary* resources=self.permissionCapability[@"resources"]; for(NSString* resource in resources) if([resources[resource] isEqual:@"Supported"]) [sheet addAction:[UIAlertAction actionWithTitle:resource style:UIAlertActionStyleDefault handler:^(UIAlertAction* a){(void)a;[self choosePolicyForApp:app resource:resource cell:cell];}]]; [sheet addAction:[UIAlertAction actionWithTitle:@"Cancel" style:UIAlertActionStyleCancel handler:nil]]; [self presentSheet:sheet cell:cell]; }
}
@end
