#import "TSAutomationTableViewController.h"
#import "TSApplicationsManager.h"

@interface TSAutomationTableViewController ()
@property(nonatomic,strong) NSDictionary* capability;
@property(nonatomic,strong) NSDictionary* activeProfile;
@property(nonatomic,copy) NSArray* profiles;
@property(nonatomic,copy) NSArray* applications;
@property(nonatomic,copy) NSArray* rules;
@property(nonatomic,copy) NSArray* runs;
@property(nonatomic,strong) UIRefreshControl* pullRefresh;
@property(nonatomic,assign) BOOL loading;
@end

@implementation TSAutomationTableViewController

- (instancetype)init { return [super initWithStyle:UITableViewStyleInsetGrouped]; }

- (void)viewDidLoad
{
    [super viewDidLoad];
    self.title = @"Automate";
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

- (NSDictionary*)result:(NSString*)operation parameters:(NSDictionary*)parameters error:(NSError**)error
{
    NSDictionary* envelope = [[TSApplicationsManager sharedInstance]
        coreRequestOperation:operation parameters:parameters error:error];
    if(![envelope[@"success"] boolValue]) {
        if(error && !*error) *error = [NSError errorWithDomain:@"com.liquidsky.CrypStore.Core"
            code:1 userInfo:@{NSLocalizedDescriptionKey: envelope[@"errorMessage"] ?: @"The Core request failed."}];
        return nil;
    }
    return [envelope[@"result"] isKindOfClass:NSDictionary.class] ? envelope[@"result"] : nil;
}

- (void)refresh
{
    if(self.loading) { [self.pullRefresh endRefreshing]; return; }
    self.loading = YES;
    self.navigationItem.rightBarButtonItem.enabled = NO;
    self.navigationItem.prompt = @"Reading transactional policy state…";
    dispatch_async(dispatch_get_global_queue(QOS_CLASS_UTILITY, 0), ^{
        NSDictionary* capability = [self result:@"getProfileCapability" parameters:@{} error:nil];
        NSDictionary* profiles = [self result:@"getProfiles" parameters:@{} error:nil];
        NSDictionary* apps = [self result:@"getFrozenApps" parameters:@{} error:nil];
        NSDictionary* rules = [self result:@"getAutomationRules" parameters:@{@"limit": @100} error:nil];
        NSDictionary* history = [self result:@"getAutomationHistory" parameters:@{@"limit": @20} error:nil];
        dispatch_async(dispatch_get_main_queue(), ^{
            self.capability = capability;
            self.activeProfile = [profiles[@"active"] isKindOfClass:NSDictionary.class] ? profiles[@"active"] : nil;
            self.profiles = [profiles[@"profiles"] isKindOfClass:NSArray.class] ? profiles[@"profiles"] : @[];
            self.applications = [apps[@"applications"] isKindOfClass:NSArray.class] ? apps[@"applications"] : @[];
            self.rules = [rules[@"rules"] isKindOfClass:NSArray.class] ? rules[@"rules"] : @[];
            self.runs = [history[@"runs"] isKindOfClass:NSArray.class] ? history[@"runs"] : @[];
            self.loading = NO;
            self.navigationItem.rightBarButtonItem.enabled = YES;
            [self.pullRefresh endRefreshing];
            self.navigationItem.prompt = capability ? [NSString stringWithFormat:@"%@ • no shell actions",
                capability[@"state"] ?: @"Unknown"] : @"0-Sky Core is unavailable";
            [self.tableView reloadData];
        });
    });
}

- (NSInteger)numberOfSectionsInTableView:(UITableView*)tableView
{ (void)tableView; return 5; }

- (NSInteger)tableView:(UITableView*)tableView numberOfRowsInSection:(NSInteger)section
{
    (void)tableView;
    if(section == 0) return 1;
    NSArray* groups = @[self.profiles ?: @[], self.applications ?: @[],
        self.rules ?: @[], self.runs ?: @[]];
    NSArray* values = groups[section - 1];
    return MAX(1, (NSInteger)values.count);
}

- (NSString*)tableView:(UITableView*)tableView titleForHeaderInSection:(NSInteger)section
{ (void)tableView; return @[@"Status", @"Profiles", @"App Freeze", @"Rules", @"History"][section]; }

- (NSString*)tableView:(UITableView*)tableView titleForFooterInSection:(NSInteger)section
{
    (void)tableView;
    if(section == 0) return @"Profiles use validate → snapshot → apply → verify → commit. A failed apply rolls back. Unsupported controls never report success.";
    if(section == 2) return @"Freeze currently suppresses 0-Sky automation only. Background, launch, and networking remain visibly Unsupported until a reviewed provider is installed. App data is never modified.";
    if(section == 3) return @"Rules are structured and bounded. Arbitrary commands, scripts, and shell actions are prohibited.";
    return nil;
}

- (UITableViewCell*)empty:(NSString*)title detail:(NSString*)detail
{
    UITableViewCell* cell = [[UITableViewCell alloc] initWithStyle:UITableViewCellStyleSubtitle reuseIdentifier:nil];
    cell.textLabel.text = title; cell.detailTextLabel.text = detail;
    cell.detailTextLabel.numberOfLines = 2; cell.selectionStyle = UITableViewCellSelectionStyleNone;
    return cell;
}

- (UITableViewCell*)tableView:(UITableView*)tableView cellForRowAtIndexPath:(NSIndexPath*)indexPath
{
    (void)tableView;
    UITableViewCell* cell = [[UITableViewCell alloc] initWithStyle:UITableViewCellStyleSubtitle reuseIdentifier:nil];
    cell.detailTextLabel.numberOfLines = 2;
    if(indexPath.section == 0) {
        cell.textLabel.text = self.activeProfile ? [NSString stringWithFormat:@"%@ Profile", self.activeProfile[@"name"]] : @"Profile unavailable";
        cell.detailTextLabel.text = self.capability[@"reason"] ?: @"Pull to refresh";
        cell.imageView.image = [UIImage systemImageNamed:@"slider.horizontal.3"];
        cell.selectionStyle = UITableViewCellSelectionStyleNone;
    } else if(indexPath.section == 1) {
        if(!self.profiles.count) return [self empty:@"No profiles" detail:@"0-Sky Core has not returned profile state"];
        NSDictionary* profile = self.profiles[indexPath.row];
        cell.textLabel.text = profile[@"name"];
        cell.detailTextLabel.text = [profile[@"active"] boolValue] ? @"Active • verified" : ([profile[@"built_in"] boolValue] ? @"Built-in" : @"Custom");
        cell.accessoryType = [profile[@"active"] boolValue] ? UITableViewCellAccessoryCheckmark : UITableViewCellAccessoryDisclosureIndicator;
    } else if(indexPath.section == 2) {
        if(!self.applications.count) return [self empty:@"No compatible applications" detail:@"Only exact current third-party registrations are listed"];
        NSDictionary* app = self.applications[indexPath.row];
        cell.textLabel.text = app[@"name"] ?: app[@"bundleID"];
        cell.detailTextLabel.text = [NSString stringWithFormat:@"%@ • %@", app[@"state"] ?: @"Active", app[@"bundleID"] ?: @""];
        cell.imageView.image = [UIImage systemImageNamed:[app[@"state"] isEqual:@"Frozen"] ? @"snowflake" : @"app.fill"];
        cell.accessoryType = UITableViewCellAccessoryDisclosureIndicator;
    } else if(indexPath.section == 3) {
        if(!self.rules.count) return [self empty:@"No automation rules" detail:@"Rules can be provisioned through the authenticated paired-Mac API"];
        NSDictionary* rule = self.rules[indexPath.row];
        cell.textLabel.text = rule[@"name"] ?: @"Rule";
        cell.detailTextLabel.text = [NSString stringWithFormat:@"%@ • %@ run(s)", [rule[@"enabled"] boolValue] ? @"Enabled" : @"Disabled", rule[@"run_count"] ?: @0];
        UISwitch* toggle = [UISwitch new]; toggle.on = [rule[@"enabled"] boolValue]; toggle.tag = indexPath.row;
        [toggle addTarget:self action:@selector(ruleSwitch:) forControlEvents:UIControlEventValueChanged];
        cell.accessoryView = toggle; cell.selectionStyle = UITableViewCellSelectionStyleNone;
    } else {
        if(!self.runs.count) return [self empty:@"No automation history" detail:@"Validated rule runs and visible failures appear here"];
        NSDictionary* run = self.runs[indexPath.row]; NSDictionary* result = run[@"result"];
        cell.textLabel.text = [result[@"state"] isKindOfClass:NSString.class] ? result[@"state"] : ([run[@"success"] boolValue] ? @"Completed" : @"Failed");
        cell.detailTextLabel.text = [NSString stringWithFormat:@"Rule %@ • %@", run[@"rule_id"] ?: @"?", result[@"message"] ?: @"recorded result"];
        cell.imageView.image = [UIImage systemImageNamed:[run[@"success"] boolValue] ? @"checkmark.circle.fill" : @"exclamationmark.triangle.fill"];
        cell.selectionStyle = UITableViewCellSelectionStyleNone;
    }
    return cell;
}

- (void)showError:(NSError*)error
{
    UIAlertController* alert = [UIAlertController alertControllerWithTitle:@"Policy Action Failed"
        message:error.localizedDescription ?: @"The action could not be completed."
        preferredStyle:UIAlertControllerStyleAlert];
    [alert addAction:[UIAlertAction actionWithTitle:@"OK" style:UIAlertActionStyleCancel handler:nil]];
    [self presentViewController:alert animated:YES completion:nil];
}

- (void)run:(NSString*)operation parameters:(NSDictionary*)parameters
{
    self.navigationItem.prompt = @"Applying and verifying…";
    dispatch_async(dispatch_get_global_queue(QOS_CLASS_USER_INITIATED, 0), ^{
        NSError* error = nil; NSDictionary* result = [self result:operation parameters:parameters error:&error];
        dispatch_async(dispatch_get_main_queue(), ^{ if(!result) [self showError:error]; [self refresh]; });
    });
}

- (void)ruleSwitch:(UISwitch*)sender
{
    if(sender.tag >= (NSInteger)self.rules.count) return;
    NSDictionary* rule = self.rules[sender.tag];
    [self run:@"setAutomationRuleEnabled" parameters:@{@"ruleID": rule[@"id"], @"enabled": @(sender.on)}];
}

- (void)presentSheet:(UIAlertController*)sheet cell:(UITableViewCell*)cell
{
    UIPopoverPresentationController* popover = sheet.popoverPresentationController;
    if(popover) { popover.sourceView = cell; popover.sourceRect = cell.bounds; popover.permittedArrowDirections = UIPopoverArrowDirectionAny; }
    [self presentViewController:sheet animated:YES completion:nil];
}

- (void)tableView:(UITableView*)tableView didSelectRowAtIndexPath:(NSIndexPath*)indexPath
{
    [tableView deselectRowAtIndexPath:indexPath animated:YES];
    UITableViewCell* cell = [tableView cellForRowAtIndexPath:indexPath];
    if(indexPath.section == 1 && self.profiles.count) {
        NSDictionary* profile = self.profiles[indexPath.row];
        if([profile[@"active"] boolValue]) return;
        UIAlertController* sheet = [UIAlertController alertControllerWithTitle:[NSString stringWithFormat:@"Apply %@?", profile[@"name"]]
            message:@"0-Sky will validate, snapshot current policy, apply, verify, and either commit or roll back."
            preferredStyle:UIAlertControllerStyleActionSheet];
        [sheet addAction:[UIAlertAction actionWithTitle:@"Apply Profile" style:UIAlertActionStyleDefault handler:^(UIAlertAction* a){
            (void)a; [self run:@"applyProfile" parameters:@{@"name": profile[@"name"]}]; }]];
        [sheet addAction:[UIAlertAction actionWithTitle:@"Cancel" style:UIAlertActionStyleCancel handler:nil]];
        [self presentSheet:sheet cell:cell];
    } else if(indexPath.section == 2 && self.applications.count) {
        NSDictionary* app = self.applications[indexPath.row]; NSString* bundleID = app[@"bundleID"];
        UIAlertController* sheet = [UIAlertController alertControllerWithTitle:app[@"name"] ?: bundleID
            message:@"Only capability-backed controls are applied. No application data is changed."
            preferredStyle:UIAlertControllerStyleActionSheet];
        if([app[@"state"] isEqual:@"Frozen"]) {
            [sheet addAction:[UIAlertAction actionWithTitle:@"Temporarily Active (15 min)" style:UIAlertActionStyleDefault handler:^(UIAlertAction* a){
                (void)a; [self run:@"temporarilyActivateApp" parameters:@{@"bundleID": bundleID, @"durationSeconds": @900}]; }]];
            [sheet addAction:[UIAlertAction actionWithTitle:@"Unfreeze" style:UIAlertActionStyleDestructive handler:^(UIAlertAction* a){
                (void)a; [self run:@"unfreezeApp" parameters:@{@"bundleID": bundleID}]; }]];
        } else if([app[@"state"] isEqual:@"Temporarily Active"]) {
            [sheet addAction:[UIAlertAction actionWithTitle:@"Freeze Now" style:UIAlertActionStyleDefault handler:^(UIAlertAction* a){
                (void)a; [self run:@"freezeApp" parameters:@{@"bundleID": bundleID}]; }]];
            [sheet addAction:[UIAlertAction actionWithTitle:@"Unfreeze" style:UIAlertActionStyleDestructive handler:^(UIAlertAction* a){
                (void)a; [self run:@"unfreezeApp" parameters:@{@"bundleID": bundleID}]; }]];
        } else {
            [sheet addAction:[UIAlertAction actionWithTitle:@"Freeze Automation" style:UIAlertActionStyleDefault handler:^(UIAlertAction* a){
                (void)a; [self run:@"freezeApp" parameters:@{@"bundleID": bundleID}]; }]];
        }
        [sheet addAction:[UIAlertAction actionWithTitle:@"Cancel" style:UIAlertActionStyleCancel handler:nil]];
        [self presentSheet:sheet cell:cell];
    }
}
@end
