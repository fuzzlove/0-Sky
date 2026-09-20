#import "TSActivityTableViewController.h"
#import "TSApplicationsManager.h"

@interface TSPrivacyHistoryTableViewController : UITableViewController
@property(nonatomic,copy) NSString* resource;
@property(nonatomic,copy) NSArray* events;
- (instancetype)initWithResource:(NSString*)resource events:(NSArray*)events;
@end

@implementation TSPrivacyHistoryTableViewController

- (instancetype)initWithResource:(NSString*)resource events:(NSArray*)events
{
    self = [super initWithStyle:UITableViewStyleInsetGrouped];
    if(self) {
        _resource = [resource copy];
        NSPredicate* predicate = [NSPredicate predicateWithBlock:
            ^BOOL(NSDictionary* event, NSDictionary* bindings) {
                (void)bindings;
                return [event[@"resource"] isEqualToString:resource];
            }];
        _events = [[events filteredArrayUsingPredicate:predicate]
            sortedArrayUsingComparator:^NSComparisonResult(NSDictionary* left,
                                                             NSDictionary* right) {
                return [right[@"timestamp"] compare:left[@"timestamp"]];
            }];
    }
    return self;
}

- (void)viewDidLoad
{
    [super viewDidLoad];
    self.title = [self.resource capitalizedString];
}

- (NSInteger)numberOfSectionsInTableView:(UITableView*)tableView
{ (void)tableView; return 1; }

- (NSInteger)tableView:(UITableView*)tableView numberOfRowsInSection:(NSInteger)section
{ (void)tableView; (void)section; return MAX(1, (NSInteger)self.events.count); }

- (NSString*)tableView:(UITableView*)tableView titleForFooterInSection:(NSInteger)section
{
    (void)tableView; (void)section;
    return @"Reviewed event metadata only. Unsupported or missing history never means zero accesses.";
}

- (UITableViewCell*)tableView:(UITableView*)tableView cellForRowAtIndexPath:(NSIndexPath*)indexPath
{
    UITableViewCell* cell = [[UITableViewCell alloc]
        initWithStyle:UITableViewCellStyleSubtitle reuseIdentifier:nil];
    cell.selectionStyle = UITableViewCellSelectionStyleNone;
    if(!self.events.count) {
        cell.textLabel.text = @"No reviewed history in this window";
        cell.detailTextLabel.text = @"The provider did not return event metadata";
        return cell;
    }
    NSDictionary* event = self.events[indexPath.row];
    cell.textLabel.text = [event[@"bundle_id"] isKindOfClass:NSString.class]
        ? event[@"bundle_id"] : @"Unknown process";
    NSDate* date = [NSDate dateWithTimeIntervalSince1970:[event[@"timestamp"] doubleValue]];
    NSDateFormatter* formatter = [NSDateFormatter new];
    formatter.dateStyle = NSDateFormatterShortStyle;
    formatter.timeStyle = NSDateFormatterMediumStyle;
    cell.detailTextLabel.text = [NSString stringWithFormat:@"%@ • %@",
        event[@"decision"] ?: @"Observed", [formatter stringFromDate:date]];
    cell.imageView.image = [UIImage systemImageNamed:@"clock.arrow.circlepath"];
    return cell;
}

@end

@interface TSActivityTableViewController ()
@property(nonatomic,strong) UISegmentedControl* mode;
@property(nonatomic,strong) UIRefreshControl* pullRefresh;
@property(nonatomic,strong) NSDictionary* capabilities;
@property(nonatomic,strong) NSDictionary* network;
@property(nonatomic,strong) NSDictionary* privacy;
@property(nonatomic,strong) NSDictionary* privacySummary;
@property(nonatomic,assign) BOOL loading;
@end

@implementation TSActivityTableViewController

- (instancetype)init { return [super initWithStyle:UITableViewStyleInsetGrouped]; }

- (void)viewDidLoad
{
    [super viewDidLoad];
    self.title = @"Activity";
    self.mode = [[UISegmentedControl alloc] initWithItems:@[@"Network", @"Privacy"]];
    self.mode.selectedSegmentIndex = 0;
    [self.mode addTarget:self action:@selector(modeChanged)
        forControlEvents:UIControlEventValueChanged];
    self.navigationItem.titleView = self.mode;
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
- (void)modeChanged { [self.tableView reloadData]; }

- (NSDictionary*)resultForOperation:(NSString*)operation parameters:(NSDictionary*)parameters
{
    NSError* error = nil;
    NSDictionary* envelope = [[TSApplicationsManager sharedInstance]
        coreRequestOperation:operation parameters:parameters error:&error];
    if(![envelope[@"success"] boolValue]) return nil;
    return [envelope[@"result"] isKindOfClass:NSDictionary.class] ? envelope[@"result"] : nil;
}

- (void)refresh
{
    if(self.loading) { [self.pullRefresh endRefreshing]; return; }
    self.loading = YES;
    self.navigationItem.rightBarButtonItem.enabled = NO;
    self.navigationItem.prompt = @"Reading capability-gated activity…";
    dispatch_async(dispatch_get_global_queue(QOS_CLASS_UTILITY, 0), ^{
        NSDictionary* capabilities = [self resultForOperation:@"getCapabilities" parameters:@{}];
        NSDictionary* network = [self resultForOperation:@"getConnections"
            parameters:@{@"limit": @100}];
        NSDictionary* privacy = [self resultForOperation:@"getPrivacyEvents"
            parameters:@{@"limit": @100}];
        NSDictionary* summary = [self resultForOperation:@"getPrivacySummary"
            parameters:@{@"hours": @24}];
        dispatch_async(dispatch_get_main_queue(), ^{
            self.capabilities = capabilities;
            self.network = network;
            self.privacy = privacy;
            self.privacySummary = summary;
            self.loading = NO;
            self.navigationItem.rightBarButtonItem.enabled = YES;
            [self.pullRefresh endRefreshing];
            self.navigationItem.prompt = capabilities
                ? @"Read-only observation • refreshes on open or pull"
                : @"0-Sky Core is temporarily unavailable";
            [self.tableView reloadData];
        });
    });
}

- (NSString*)capability:(NSString*)name
{
    NSDictionary* all = [self.capabilities[@"capabilities"] isKindOfClass:NSDictionary.class]
        ? self.capabilities[@"capabilities"] : nil;
    NSString* value = [all[name][@"state"] isKindOfClass:NSString.class]
        ? all[name][@"state"] : nil;
    if([value isEqualToString:@"MonitorOnly"]) return @"Monitor Only";
    return value.length ? value : @"Unavailable";
}

- (NSArray*)connections
{
    return [self.network[@"connections"] isKindOfClass:NSArray.class]
        ? self.network[@"connections"] : @[];
}

- (NSArray*)privacyEvents
{
    return [self.privacy[@"events"] isKindOfClass:NSArray.class]
        ? self.privacy[@"events"] : @[];
}

- (NSInteger)numberOfSectionsInTableView:(UITableView*)tableView
{ (void)tableView; return 2; }

- (NSInteger)tableView:(UITableView*)tableView numberOfRowsInSection:(NSInteger)section
{
    (void)tableView;
    if(section == 0) return 2;
    if(self.mode.selectedSegmentIndex == 0) return MAX(1, (NSInteger)self.connections.count);
    NSArray* summary = [self.privacySummary[@"resources"] isKindOfClass:NSArray.class]
        ? self.privacySummary[@"resources"] : @[];
    return MAX(1, (NSInteger)(summary.count ? summary.count : self.privacyEvents.count));
}

- (NSString*)tableView:(UITableView*)tableView titleForHeaderInSection:(NSInteger)section
{
    (void)tableView;
    if(section == 0) return @"Capability";
    return self.mode.selectedSegmentIndex == 0 ? @"Current Observed Endpoints" : @"Privacy Today";
}

- (NSString*)tableView:(UITableView*)tableView titleForFooterInSection:(NSInteger)section
{
    (void)tableView;
    if(section != 1) return nil;
    return self.mode.selectedSegmentIndex == 0
        ? @"Current sockets only. Transport type, hostnames, closed flows, and byte totals are not inferred. No firewall control is presented."
        : @"Only events from a reviewed provider are shown. Unsupported never means zero accesses.";
}

- (UITableViewCell*)tableView:(UITableView*)tableView cellForRowAtIndexPath:(NSIndexPath*)indexPath
{
    UITableViewCell* cell = [[UITableViewCell alloc]
        initWithStyle:UITableViewCellStyleSubtitle reuseIdentifier:nil];
    cell.selectionStyle = UITableViewCellSelectionStyleNone;
    if(indexPath.section == 0) {
        BOOL networkMode = self.mode.selectedSegmentIndex == 0;
        if(indexPath.row == 0) {
            cell.textLabel.text = networkMode ? @"Network Observation" : @"Privacy Observation";
            cell.detailTextLabel.text = [self capability:networkMode ? @"networkObservation" : @"privacyObservation"];
            cell.imageView.image = [UIImage systemImageNamed:networkMode ? @"network" : @"hand.raised"];
        } else {
            cell.textLabel.text = networkMode ? @"Network Enforcement" : @"Privacy Enforcement";
            cell.detailTextLabel.text = [self capability:networkMode ? @"networkEnforcement" : @"privacyEnforcement"];
            cell.imageView.image = [UIImage systemImageNamed:@"lock.shield"];
        }
        return cell;
    }

    if(self.mode.selectedSegmentIndex == 0) {
        NSArray* rows = self.connections;
        if(!rows.count) {
            cell.textLabel.text = self.network ? @"No current endpoints" : @"Network data unavailable";
            cell.detailTextLabel.text = self.network[@"message"] ?: @"Pull to refresh";
            return cell;
        }
        NSDictionary* row = rows[indexPath.row];
        NSDictionary* metadata = [row[@"metadata"] isKindOfClass:NSDictionary.class] ? row[@"metadata"] : @{};
        NSString* owner = [row[@"bundle_id"] isKindOfClass:NSString.class] ? row[@"bundle_id"] : nil;
        if(!owner.length) owner = [metadata[@"executable"] lastPathComponent] ?: @"Unknown process";
        cell.textLabel.text = owner;
        cell.detailTextLabel.text = [NSString stringWithFormat:@"%@:%@ • %@ • %@",
            row[@"destination"] ?: @"Unknown", row[@"port"] ?: @"?",
            [row[@"protocol"] uppercaseString] ?: @"?", metadata[@"scope"] ?: @"unknown scope"];
        cell.imageView.image = [UIImage systemImageNamed:@"point.3.connected.trianglepath.dotted"];
    } else {
        NSArray* summary = [self.privacySummary[@"resources"] isKindOfClass:NSArray.class]
            ? self.privacySummary[@"resources"] : @[];
        if(summary.count) {
            NSDictionary* row = summary[indexPath.row];
            cell.textLabel.text = [row[@"resource"] capitalizedString];
            cell.detailTextLabel.text = [NSString stringWithFormat:@"%@ observed", row[@"count"] ?: @0];
            cell.selectionStyle = UITableViewCellSelectionStyleDefault;
            cell.accessoryType = UITableViewCellAccessoryDisclosureIndicator;
        } else if(self.privacyEvents.count) {
            NSDictionary* row = self.privacyEvents[indexPath.row];
            cell.textLabel.text = [row[@"resource"] capitalizedString];
            cell.detailTextLabel.text = [NSString stringWithFormat:@"%@ • %@",
                row[@"bundle_id"] ?: @"Unknown process", row[@"decision"] ?: @"Observed"];
            cell.selectionStyle = UITableViewCellSelectionStyleDefault;
            cell.accessoryType = UITableViewCellAccessoryDisclosureIndicator;
        } else {
            cell.textLabel.text = self.privacy ? @"No reviewed privacy events" : @"Privacy data unavailable";
            cell.detailTextLabel.text = self.privacy[@"message"] ?: @"Pull to refresh";
        }
        cell.imageView.image = [UIImage systemImageNamed:@"eye"];
    }
    return cell;
}

- (void)tableView:(UITableView*)tableView didSelectRowAtIndexPath:(NSIndexPath*)indexPath
{
    [tableView deselectRowAtIndexPath:indexPath animated:YES];
    if(indexPath.section != 1 || self.mode.selectedSegmentIndex != 1) return;
    NSArray* summary = [self.privacySummary[@"resources"] isKindOfClass:NSArray.class]
        ? self.privacySummary[@"resources"] : @[];
    NSString* resource = nil;
    if(summary.count && indexPath.row < (NSInteger)summary.count)
        resource = summary[indexPath.row][@"resource"];
    else if(indexPath.row < (NSInteger)self.privacyEvents.count)
        resource = self.privacyEvents[indexPath.row][@"resource"];
    if(![resource isKindOfClass:NSString.class] || !resource.length) return;
    TSPrivacyHistoryTableViewController* history =
        [[TSPrivacyHistoryTableViewController alloc] initWithResource:resource
            events:self.privacyEvents];
    [self.navigationController pushViewController:history animated:YES];
}

@end
