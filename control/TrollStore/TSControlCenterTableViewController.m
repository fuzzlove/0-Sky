#import "TSControlCenterTableViewController.h"
#import <TSBranding.h>
#import "TSApplicationsManager.h"
#import "TSAppTableViewController.h"
#import "TSInventoryTableViewController.h"
#import "TSHealthTableViewController.h"
#import "TSActivityTableViewController.h"
#import "TSRecoveryTableViewController.h"
#import "TSSnapshotsTableViewController.h"
#import "TSAutomationTableViewController.h"
#import "TSIntelligenceTableViewController.h"
#import "TSSettingsListController.h"
#import "TSTrustedMacViewController.h"

@interface TSControlCenterTableViewController ()
@property(nonatomic,strong) NSDictionary* summary;
@property(nonatomic,strong) UIRefreshControl* pullRefresh;
@property(nonatomic,assign) BOOL loading;
@end

@implementation TSControlCenterTableViewController

- (instancetype)init { return [super initWithStyle:UITableViewStyleInsetGrouped]; }

- (void)viewDidLoad
{
    [super viewDidLoad];
    self.title = TS_CONTROL_PRODUCT_NAME;
    self.navigationItem.largeTitleDisplayMode = UINavigationItemLargeTitleDisplayModeAlways;
    self.pullRefresh = [UIRefreshControl new];
    self.pullRefresh.accessibilityLabel = @"Refresh 0-Sky status";
    [self.pullRefresh addTarget:self action:@selector(refresh) forControlEvents:UIControlEventValueChanged];
    self.refreshControl = self.pullRefresh;
    self.navigationItem.rightBarButtonItem = [[UIBarButtonItem alloc]
        initWithBarButtonSystemItem:UIBarButtonSystemItemRefresh target:self action:@selector(refresh)];
    self.navigationItem.rightBarButtonItem.accessibilityLabel = @"Refresh 0-Sky status";
    [[NSNotificationCenter defaultCenter] addObserver:self selector:@selector(refresh)
        name:UIApplicationDidBecomeActiveNotification object:nil];
    [self refresh];
}

- (void)dealloc { [[NSNotificationCenter defaultCenter] removeObserver:self]; }

- (NSDictionary*)currentPowerTelemetry
{
    UIDevice* device = UIDevice.currentDevice;
    device.batteryMonitoringEnabled = YES;
    NSMutableDictionary* payload = [@{
        @"observedAt": @([NSDate date].timeIntervalSince1970)
    } mutableCopy];
    UIDeviceBatteryState batteryState = device.batteryState;
    float level = device.batteryLevel;
    if(level >= 0.0f && level <= 1.0f && batteryState != UIDeviceBatteryStateUnknown) {
        NSString* state = @"Unplugged";
        if(batteryState == UIDeviceBatteryStateCharging) state = @"Charging";
        else if(batteryState == UIDeviceBatteryStateFull) state = @"Full";
        BOOL charging = batteryState == UIDeviceBatteryStateCharging ||
            batteryState == UIDeviceBatteryStateFull;
        payload[@"battery"] = @{
            @"levelPercent": @(level * 100.0f),
            @"charging": @(charging),
            @"state": state,
            @"lowPowerMode": @(NSProcessInfo.processInfo.lowPowerModeEnabled)
        };
    }
    NSString* thermalState = nil;
    switch(NSProcessInfo.processInfo.thermalState) {
        case NSProcessInfoThermalStateNominal: thermalState = @"Nominal"; break;
        case NSProcessInfoThermalStateFair: thermalState = @"Fair"; break;
        case NSProcessInfoThermalStateSerious: thermalState = @"Serious"; break;
        case NSProcessInfoThermalStateCritical: thermalState = @"Critical"; break;
    }
    if(thermalState) payload[@"thermal"] = @{ @"state": thermalState };
    return payload;
}

- (void)refresh
{
    if(self.loading) { [self.pullRefresh endRefreshing]; return; }
    self.loading = YES;
    self.navigationItem.rightBarButtonItem.enabled = NO;
    self.navigationItem.prompt = @"Checking current problems…";
    NSDictionary* powerTelemetry = [self currentPowerTelemetry];
    dispatch_async(dispatch_get_global_queue(QOS_CLASS_UTILITY, 0), ^{
        NSError* error = nil;
        if(powerTelemetry[@"battery"] || powerTelemetry[@"thermal"])
            [[TSApplicationsManager sharedInstance]
                coreRequestOperation:@"publishPowerTelemetry"
                parameters:powerTelemetry error:nil];
        NSDictionary* envelope = [[TSApplicationsManager sharedInstance]
            coreRequestOperation:@"getControlCenterSummary" parameters:@{} error:&error];
        NSDictionary* result = [envelope[@"success"] boolValue] &&
            [envelope[@"result"] isKindOfClass:NSDictionary.class] ? envelope[@"result"] : nil;
        dispatch_async(dispatch_get_main_queue(), ^{
            self.summary = result;
            self.loading = NO;
            self.navigationItem.rightBarButtonItem.enabled = YES;
            [self.pullRefresh endRefreshing];
            self.navigationItem.prompt = result
                ? @"Problem-first status • refreshes only on open or request"
                : @"0-Sky Core is unavailable";
            [self.tableView reloadData];
            UIAccessibilityPostNotification(UIAccessibilityLayoutChangedNotification, self.tableView);
        });
    });
}

- (NSArray*)problems
{ return [self.summary[@"problems"] isKindOfClass:NSArray.class] ? self.summary[@"problems"] : @[]; }

- (NSArray*)rowsForSection:(NSInteger)section
{
    switch(section) {
        case 1: return @[
            @{ @"title": @"Trusted Mac", @"detail": @"Pair, verify, reconnect, and inspect transport", @"icon": @"laptopcomputer.and.iphone", @"destination": @"trustedMac" },
            @{ @"title": @"Health", @"detail": @"Timeline, battery, thermal, and collectors", @"icon": @"heart.text.square.fill", @"destination": @"health" },
            @{ @"title": @"Battery & Thermal", @"detail": @"Measured and capability-aware state", @"icon": @"battery.75percent", @"destination": @"health" },
            @{ @"title": @"Storage", @"detail": @"Read-only safety classification", @"icon": @"internaldrive.fill", @"destination": @"intelligence" }];
        case 2: return @[
            @{ @"title": @"Privacy", @"detail": @"Local observable access history", @"icon": @"hand.raised.fill", @"destination": @"activity" },
            @{ @"title": @"Network", @"detail": @"Current attributed connections", @"icon": @"network", @"destination": @"activity" },
            @{ @"title": @"Firewall", @"detail": @"Capability state and reviewed controls", @"icon": @"shield.lefthalf.filled", @"destination": @"activity" }];
        case 3: return @[
            @{ @"title": @"Apps", @"detail": @"Installed application management", @"icon": @"square.stack.3d.up.fill", @"destination": @"apps" },
            @{ @"title": @"Freeze", @"detail": @"Reversible capability-backed policy", @"icon": @"snowflake", @"destination": @"automation" },
            @{ @"title": @"Snapshots", @"detail": @"Verified application rollback", @"icon": @"clock.arrow.circlepath", @"destination": @"snapshots" },
            @{ @"title": @"Permissions", @"detail": @"Temporary policies when supported", @"icon": @"timer", @"destination": @"intelligence" }];
        case 4: return @[
            @{ @"title": @"Packages & Tweaks", @"detail": @"Health, services, files, and conflicts", @"icon": @"shippingbox.fill", @"destination": @"inventory" },
            @{ @"title": @"Conflicts", @"detail": @"Evidence-based hook analysis", @"icon": @"exclamationmark.2", @"destination": @"recovery" },
            @{ @"title": @"Crashes", @"detail": @"Validated metadata and attribution", @"icon": @"doc.text.magnifyingglass", @"destination": @"recovery" },
            @{ @"title": @"Safe Mode", @"detail": @"Reversible exact-target recovery", @"icon": @"cross.case.fill", @"destination": @"recovery" }];
        case 5: return @[
            @{ @"title": @"Profiles", @"detail": @"Transactional everyday modes", @"icon": @"person.crop.circle.badge.checkmark", @"destination": @"automation" },
            @{ @"title": @"Rules", @"detail": @"Structured triggers and actions", @"icon": @"gearshape.2.fill", @"destination": @"automation" },
            @{ @"title": @"History", @"detail": @"Automation outcomes and failures", @"icon": @"list.bullet.clipboard", @"destination": @"automation" }];
        case 6: return @[
            @{ @"title": @"Processes", @"detail": @"Bounded Activity Monitor view", @"icon": @"cpu", @"destination": @"health" },
            @{ @"title": @"Sensors", @"detail": @"Running, degraded, unsupported, or failed", @"icon": @"waveform.path.ecg", @"destination": @"health" },
            @{ @"title": @"Recovery", @"detail": @"Safe Mode and recovery capabilities", @"icon": @"lifepreserver", @"destination": @"recovery" },
            @{ @"title": @"Settings", @"detail": @"0-Sky Control and platform preferences", @"icon": @"gear", @"destination": @"settings" }];
        default: return @[];
    }
}

- (NSInteger)numberOfSectionsInTableView:(UITableView*)tableView { (void)tableView; return 7; }
- (NSInteger)tableView:(UITableView*)tableView numberOfRowsInSection:(NSInteger)section
{
    (void)tableView;
    if(section == 0) return MAX(1, (NSInteger)self.problems.count);
    return [self rowsForSection:section].count;
}
- (NSString*)tableView:(UITableView*)tableView titleForHeaderInSection:(NSInteger)section
{
    (void)tableView;
    return @[@"CURRENT STATUS", @"DEVICE", @"SECURITY", @"APPLICATIONS",
             @"JAILBREAK", @"AUTOMATION", @"SYSTEM"][section];
}
- (NSString*)tableView:(UITableView*)tableView titleForFooterInSection:(NSInteger)section
{
    (void)tableView;
    if(section == 0) return @"Missing telemetry is shown as unavailable or degraded, never as zero activity.";
    if(section == 6) return @"Advanced details stay off the primary screen. All privileged actions use authenticated, bounded Core operations.";
    return nil;
}

- (UITableViewCell*)tableView:(UITableView*)tableView cellForRowAtIndexPath:(NSIndexPath*)indexPath
{
    (void)tableView;
    UITableViewCell* cell = [[UITableViewCell alloc] initWithStyle:UITableViewCellStyleSubtitle reuseIdentifier:nil];
    cell.textLabel.font = [UIFont preferredFontForTextStyle:UIFontTextStyleBody];
    cell.detailTextLabel.font = [UIFont preferredFontForTextStyle:UIFontTextStyleFootnote];
    cell.textLabel.adjustsFontForContentSizeCategory = YES;
    cell.detailTextLabel.adjustsFontForContentSizeCategory = YES;
    cell.detailTextLabel.numberOfLines = 0;
    if(indexPath.section == 0) {
        if(!self.summary) {
            cell.textLabel.text = @"Core Status Unavailable";
            cell.detailTextLabel.text = @"Pull to refresh or verify the paired 0-Sky service";
            cell.imageView.image = [UIImage systemImageNamed:@"questionmark.circle"];
            cell.selectionStyle = UITableViewCellSelectionStyleNone;
        } else if(!self.problems.count) {
            NSString* state = self.summary[@"state"] ?: @"Healthy";
            cell.textLabel.text = [NSString stringWithFormat:@"%@ — No Current Problems", state];
            cell.detailTextLabel.text = @"Database and available collectors report no actionable warning";
            cell.imageView.image = [UIImage systemImageNamed:@"checkmark.shield.fill"];
            cell.selectionStyle = UITableViewCellSelectionStyleNone;
        } else {
            NSDictionary* row = self.problems[indexPath.row];
            NSString* severity = [row[@"severity"] uppercaseString] ?: @"NOTICE";
            cell.textLabel.text = [NSString stringWithFormat:@"%@: %@", severity, row[@"title"] ?: @"Attention"];
            cell.detailTextLabel.text = row[@"detail"] ?: @"Open details";
            cell.imageView.image = [UIImage systemImageNamed:[row[@"severity"] isEqual:@"critical"]
                ? @"exclamationmark.octagon.fill" : @"exclamationmark.triangle.fill"];
            cell.accessoryType = UITableViewCellAccessoryDisclosureIndicator;
        }
    } else {
        NSDictionary* row = [self rowsForSection:indexPath.section][indexPath.row];
        cell.textLabel.text = row[@"title"];
        cell.detailTextLabel.text = row[@"detail"];
        cell.imageView.image = [UIImage systemImageNamed:row[@"icon"]];
        cell.accessoryType = UITableViewCellAccessoryDisclosureIndicator;
    }
    cell.isAccessibilityElement = YES;
    cell.accessibilityLabel = cell.textLabel.text;
    cell.accessibilityValue = cell.detailTextLabel.text;
    if(cell.accessoryType == UITableViewCellAccessoryDisclosureIndicator)
        cell.accessibilityHint = @"Opens details";
    return cell;
}

- (UIViewController*)controllerForDestination:(NSString*)destination
{
    if([destination isEqual:@"apps"]) return [TSAppTableViewController new];
    if([destination isEqual:@"inventory"]) return [TSInventoryTableViewController new];
    if([destination isEqual:@"health"]) return [TSHealthTableViewController new];
    if([destination isEqual:@"activity"]) return [TSActivityTableViewController new];
    if([destination isEqual:@"recovery"]) return [TSRecoveryTableViewController new];
    if([destination isEqual:@"snapshots"]) return [TSSnapshotsTableViewController new];
    if([destination isEqual:@"automation"]) return [TSAutomationTableViewController new];
    if([destination isEqual:@"intelligence"]) return [TSIntelligenceTableViewController new];
    if([destination isEqual:@"settings"]) return [TSSettingsListController new];
    if([destination isEqual:@"trustedMac"]) return [TSTrustedMacViewController new];
    return nil;
}

- (void)tableView:(UITableView*)tableView didSelectRowAtIndexPath:(NSIndexPath*)indexPath
{
    [tableView deselectRowAtIndexPath:indexPath animated:!UIAccessibilityIsReduceMotionEnabled()];
    NSString* destination = nil;
    if(indexPath.section == 0 && self.problems.count)
        destination = self.problems[indexPath.row][@"destination"];
    else if(indexPath.section > 0)
        destination = [self rowsForSection:indexPath.section][indexPath.row][@"destination"];
    UIViewController* controller = [self controllerForDestination:destination];
    if(controller) [self.navigationController pushViewController:controller
        animated:!UIAccessibilityIsReduceMotionEnabled()];
}

@end
