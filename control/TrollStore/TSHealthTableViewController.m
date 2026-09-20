#import "TSHealthTableViewController.h"
#import "TSApplicationsManager.h"

@interface TSHealthTableViewController ()
@property(nonatomic,strong) NSDictionary* health;
@property(nonatomic,strong) NSDictionary* processes;
@property(nonatomic,strong) NSDictionary* battery;
@property(nonatomic,strong) NSDictionary* thermal;
@property(nonatomic,strong) NSDictionary* capabilities;
@property(nonatomic,strong) NSDictionary* timeline;
@property(nonatomic,strong) UISegmentedControl* rangeControl;
@property(nonatomic,assign) NSInteger selectedDays;
@property(nonatomic,strong) UIRefreshControl* pullRefresh;
@property(nonatomic,assign) BOOL loading;
@end

@implementation TSHealthTableViewController

- (instancetype)init
{
    self = [super initWithStyle:UITableViewStyleInsetGrouped];
    return self;
}

- (void)viewDidLoad
{
    [super viewDidLoad];
    self.title = @"Health";
    self.selectedDays = 1;
    self.rangeControl = [[UISegmentedControl alloc] initWithItems:@[@"Today", @"7 Days", @"30 Days"]];
    self.rangeControl.selectedSegmentIndex = 0;
    self.rangeControl.accessibilityLabel = @"Device health history range";
    [self.rangeControl addTarget:self action:@selector(rangeChanged:) forControlEvents:UIControlEventValueChanged];
    UIView* rangeContainer = [[UIView alloc] initWithFrame:CGRectMake(0, 0, 1, 54)];
    self.rangeControl.translatesAutoresizingMaskIntoConstraints = NO;
    [rangeContainer addSubview:self.rangeControl];
    [NSLayoutConstraint activateConstraints:@[
        [self.rangeControl.leadingAnchor constraintEqualToAnchor:rangeContainer.layoutMarginsGuide.leadingAnchor],
        [self.rangeControl.trailingAnchor constraintEqualToAnchor:rangeContainer.layoutMarginsGuide.trailingAnchor],
        [self.rangeControl.centerYAnchor constraintEqualToAnchor:rangeContainer.centerYAnchor]
    ]];
    self.tableView.tableHeaderView = rangeContainer;
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

- (void)rangeChanged:(UISegmentedControl*)sender
{
    NSArray<NSNumber*>* ranges = @[@1, @7, @30];
    self.selectedDays = [ranges[sender.selectedSegmentIndex] integerValue];
    [self refresh];
}

- (void)dealloc
{
    [[NSNotificationCenter defaultCenter] removeObserver:self];
}

- (NSDictionary*)resultForOperation:(NSString*)operation parameters:(NSDictionary*)parameters
{
    NSError* error = nil;
    NSDictionary* envelope = [[TSApplicationsManager sharedInstance]
        coreRequestOperation:operation parameters:parameters error:&error];
    if(![envelope[@"success"] boolValue]) return nil;
    NSDictionary* result = [envelope[@"result"] isKindOfClass:NSDictionary.class]
        ? envelope[@"result"] : nil;
    return result;
}

- (NSDictionary*)currentPowerTelemetry
{
    // These are public iOS APIs and report the state of this exact device.
    // Unknown battery readings are omitted instead of being turned into 0%.
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
    self.navigationItem.prompt = @"Reading bounded device telemetry…";
    // UIKit device state is captured on the main thread. The authenticated
    // Core request and all subsequent reads run off-main.
    NSDictionary* powerTelemetry = [self currentPowerTelemetry];
    dispatch_async(dispatch_get_global_queue(QOS_CLASS_UTILITY, 0), ^{
        if(powerTelemetry[@"battery"] || powerTelemetry[@"thermal"])
            [self resultForOperation:@"publishPowerTelemetry" parameters:powerTelemetry];
        // These requests are independent and all use fixed read-only Core
        // operations. No UIKit or synchronous network work occurs on main.
        NSDictionary* health = [self resultForOperation:@"getDeviceHealth" parameters:@{}];
        NSDictionary* processes = [self resultForOperation:@"getProcesses"
            parameters:@{@"limit": @25}];
        NSDictionary* battery = [self resultForOperation:@"getBatteryState" parameters:@{}];
        NSDictionary* thermal = [self resultForOperation:@"getThermalState" parameters:@{}];
        NSDictionary* capabilities = [self resultForOperation:@"getCapabilities" parameters:@{}];
        NSDictionary* timeline = [self resultForOperation:@"getHealthTimeline"
            parameters:@{@"days": @(self.selectedDays)}];
        dispatch_async(dispatch_get_main_queue(), ^{
            self.health = health;
            self.processes = processes;
            self.battery = battery;
            self.thermal = thermal;
            self.capabilities = capabilities;
            self.timeline = timeline;
            self.loading = NO;
            self.navigationItem.rightBarButtonItem.enabled = YES;
            [self.pullRefresh endRefreshing];
            self.navigationItem.prompt = health
                ? @"0-Sky Core • refreshes on open or pull"
                : @"0-Sky Core is temporarily unavailable";
            [self.tableView reloadData];
        });
    });
}

- (NSDictionary*)metricNamed:(NSString*)name
{
    NSArray* metrics = [self.health[@"metrics"] isKindOfClass:NSArray.class]
        ? self.health[@"metrics"] : @[];
    for(NSDictionary* metric in metrics)
        if([metric[@"metric"] isEqual:name]) return metric;
    return nil;
}

- (NSString*)formattedBytes:(NSNumber*)number
{
    if(![number isKindOfClass:NSNumber.class]) return @"Unavailable";
    return [NSByteCountFormatter stringFromByteCount:number.longLongValue
        countStyle:NSByteCountFormatterCountStyleFile];
}

- (NSString*)capabilityState:(NSString*)name fallback:(NSString*)fallback
{
    NSDictionary* all = [self.capabilities[@"capabilities"] isKindOfClass:NSDictionary.class]
        ? self.capabilities[@"capabilities"] : nil;
    NSString* state = [all[name][@"state"] isKindOfClass:NSString.class]
        ? all[name][@"state"] : nil;
    if([state isEqualToString:@"MonitorOnly"]) return @"Monitor Only";
    return state.length ? state : fallback;
}

- (NSInteger)numberOfSectionsInTableView:(UITableView*)tableView { (void)tableView; return 4; }

- (NSInteger)tableView:(UITableView*)tableView numberOfRowsInSection:(NSInteger)section
{
    (void)tableView;
    if(section == 0) return 4;
    if(section == 1) return 3;
    if(section == 2) return 3;
    NSArray* sensors = [self.health[@"sensors"] isKindOfClass:NSArray.class]
        ? self.health[@"sensors"] : @[];
    return MAX(1, (NSInteger)sensors.count);
}

- (NSString*)tableView:(UITableView*)tableView titleForHeaderInSection:(NSInteger)section
{
    (void)tableView;
    return @[@"Device", @"Processes", @"Power & Thermal", @"Collector Health"][section];
}

- (NSString*)tableView:(UITableView*)tableView titleForFooterInSection:(NSInteger)section
{
    (void)tableView;
    if(section == 2)
        return @"Unavailable means the device exposed no reviewed evidence source; 0-Sky never substitutes fake readings. Charging thresholds remain Monitor Only without a reviewed controller.";
    if(section == 3)
        return @"Process samples run at most once per minute. Power and thermal checks run at most every five minutes.";
    return nil;
}

- (UITableViewCell*)tableView:(UITableView*)tableView cellForRowAtIndexPath:(NSIndexPath*)indexPath
{
    UITableViewCell* cell = [[UITableViewCell alloc]
        initWithStyle:UITableViewCellStyleValue1 reuseIdentifier:nil];
    cell.selectionStyle = UITableViewCellSelectionStyleNone;
    cell.textLabel.adjustsFontSizeToFitWidth = YES;
    cell.detailTextLabel.adjustsFontSizeToFitWidth = YES;
    cell.textLabel.font = [UIFont preferredFontForTextStyle:UIFontTextStyleBody];
    cell.detailTextLabel.font = [UIFont preferredFontForTextStyle:UIFontTextStyleFootnote];
    cell.textLabel.adjustsFontForContentSizeCategory = YES;
    cell.detailTextLabel.adjustsFontForContentSizeCategory = YES;
    if(indexPath.section == 0) {
        if(indexPath.row == 0) {
            cell.textLabel.text = @"Overall";
            NSArray* sensors = [self.health[@"sensors"] isKindOfClass:NSArray.class]
                ? self.health[@"sensors"] : @[];
            BOOL bad = NO;
            for(NSDictionary* sensor in sensors)
                if([@[@"Degraded", @"Failed"] containsObject:sensor[@"state"]]) bad = YES;
            cell.detailTextLabel.text = self.health ? (bad ? @"Attention" : @"Healthy") : @"Unavailable";
            cell.imageView.image = [UIImage systemImageNamed:bad ? @"exclamationmark.triangle" : @"checkmark.shield"];
        } else if(indexPath.row == 1) {
            cell.textLabel.text = @"Free Storage";
            cell.detailTextLabel.text = [self formattedBytes:[self metricNamed:@"storage.free_bytes"][@"value_real"]];
            cell.imageView.image = [UIImage systemImageNamed:@"internaldrive"];
        } else if(indexPath.row == 2) {
            cell.textLabel.text = @"Core Uptime";
            NSNumber* value = [self metricNamed:@"core.uptime_seconds"][@"value_real"];
            cell.detailTextLabel.text = value ? [NSString stringWithFormat:@"%.0f min", value.doubleValue / 60.0] : @"Unavailable";
            cell.imageView.image = [UIImage systemImageNamed:@"clock.arrow.circlepath"];
        } else {
            NSDictionary* crashes = [self.timeline[@"crashes"] isKindOfClass:NSDictionary.class]
                ? self.timeline[@"crashes"] : @{};
            cell.textLabel.text = [NSString stringWithFormat:@"%ld-Day Timeline", (long)self.selectedDays];
            cell.detailTextLabel.text = self.timeline
                ? [NSString stringWithFormat:@"%@ crashes • %@ SpringBoard • %@ health samples",
                   crashes[@"total"] ?: @0, crashes[@"springboard"] ?: @0,
                   @([self.timeline[@"healthSamples"] count])]
                : @"Unavailable";
            cell.imageView.image = [UIImage systemImageNamed:@"chart.xyaxis.line"];
        }
    } else if(indexPath.section == 1) {
        NSArray* rows = [self.processes[@"processes"] isKindOfClass:NSArray.class]
            ? self.processes[@"processes"] : @[];
        if(indexPath.row == 0) {
            cell.textLabel.text = @"Visible Processes";
            cell.detailTextLabel.text = [self capabilityState:@"processInspection"
                fallback:self.processes ? [NSString stringWithFormat:@"%lu", (unsigned long)rows.count] : @"Unavailable"];
            if(rows.count) cell.detailTextLabel.text = [NSString stringWithFormat:@"%lu sampled", (unsigned long)rows.count];
            cell.imageView.image = [UIImage systemImageNamed:@"list.bullet.rectangle"];
        } else if(indexPath.row == 1) {
            NSDictionary* top = rows.firstObject;
            cell.textLabel.text = @"Top CPU";
            cell.detailTextLabel.text = top
                ? [NSString stringWithFormat:@"%@ • %.1f%%", top[@"process"] ?: @"Unknown", [top[@"cpu"] doubleValue]]
                : @"Awaiting sample";
            cell.imageView.image = [UIImage systemImageNamed:@"cpu"];
        } else {
            NSDictionary* top = rows.firstObject;
            cell.textLabel.text = @"Battery Impact";
            cell.detailTextLabel.text = top
                ? [NSString stringWithFormat:@"Correlated estimate • %@ at %.1f%% CPU",
                   top[@"process"] ?: @"Unknown", [top[@"cpu"] doubleValue]]
                : @"Unavailable • no process sample";
            cell.imageView.image = [UIImage systemImageNamed:@"bolt.heart"];
        }
    } else if(indexPath.section == 2) {
        if(indexPath.row == 0) {
            cell.textLabel.text = @"Battery";
            NSDictionary* sample = [self.battery[@"sample"] isKindOfClass:NSDictionary.class]
                ? self.battery[@"sample"] : nil;
            NSDictionary* metadata = [sample[@"metadata"] isKindOfClass:NSDictionary.class]
                ? sample[@"metadata"] : @{};
            NSString* powerMode = [metadata[@"lowPowerMode"] boolValue] ? @" • Low Power" : @"";
            cell.detailTextLabel.text = sample
                ? [NSString stringWithFormat:@"%.0f%%%@%@", [sample[@"level"] doubleValue],
                   [sample[@"charging"] boolValue] ? @" • Charging" : @"", powerMode]
                : [self capabilityState:@"batteryMonitoring" fallback:@"Unavailable"];
            cell.imageView.image = [UIImage systemImageNamed:@"battery.75percent"];
        } else if(indexPath.row == 1) {
            cell.textLabel.text = @"Thermal";
            NSDictionary* sample = [self.thermal[@"sample"] isKindOfClass:NSDictionary.class]
                ? self.thermal[@"sample"] : nil;
            cell.detailTextLabel.text = sample[@"state"] ?: [self capabilityState:@"thermalMonitoring" fallback:@"Unavailable"];
            cell.imageView.image = [UIImage systemImageNamed:@"thermometer.medium"];
        } else {
            NSString* chargeState = [self capabilityState:@"chargeControl" fallback:@"Unavailable"];
            cell.textLabel.text = @"Charging Management";
            cell.detailTextLabel.text = [chargeState isEqual:@"Supported"]
                ? @"Supported • open provider settings"
                : [chargeState isEqual:@"Monitor Only"] ? @"Monitor Only • iOS managed"
                : chargeState;
            cell.imageView.image = [UIImage systemImageNamed:@"battery.100percent.bolt"];
        }
    } else {
        NSArray* sensors = [self.health[@"sensors"] isKindOfClass:NSArray.class]
            ? self.health[@"sensors"] : @[];
        if(!sensors.count) {
            cell.textLabel.text = @"Collectors";
            cell.detailTextLabel.text = self.health ? @"Awaiting first sample" : @"Unavailable";
        } else {
            NSDictionary* sensor = sensors[indexPath.row];
            cell.textLabel.text = [sensor[@"sensor"] stringByReplacingOccurrencesOfString:@"_" withString:@" "];
            cell.detailTextLabel.text = sensor[@"state"] ?: @"Unknown";
        }
        cell.imageView.image = [UIImage systemImageNamed:@"waveform.path.ecg"];
    }
    cell.isAccessibilityElement = YES;
    cell.accessibilityLabel = cell.textLabel.text;
    cell.accessibilityValue = cell.detailTextLabel.text;
    return cell;
}

@end
