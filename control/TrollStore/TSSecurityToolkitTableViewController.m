#import "TSSecurityToolkitTableViewController.h"
#import "TSApplicationsManager.h"
#import <CommonCrypto/CommonDigest.h>

@interface TSSecurityToolkitTableViewController ()
@property(nonatomic,copy) NSString* category;
@property(nonatomic,strong) NSDictionary* snapshot;
@property(nonatomic,strong) NSArray<NSDictionary*>* sections;
@property(nonatomic,strong) UIRefreshControl* pullRefresh;
@property(nonatomic,assign) BOOL busy;
@end

@implementation TSSecurityToolkitTableViewController

- (instancetype)initWithCategory:(NSString*)category
{
    self = [super initWithStyle:UITableViewStyleInsetGrouped];
    if(self) _category = [category copy];
    return self;
}

- (void)viewDidLoad
{
    [super viewDidLoad];
    self.title = [self.category isEqualToString:@"UAT"] ? @"Toolkit UAT" :
        [self.category isEqualToString:@"Sources"] ? @"Research Sources" :
        self.category.length ? @"Security Research" : @"Research Tools";
    self.pullRefresh = [UIRefreshControl new];
    [self.pullRefresh addTarget:self action:@selector(refresh) forControlEvents:UIControlEventValueChanged];
    self.refreshControl = self.pullRefresh;
    if([self.category isEqualToString:@"UAT"]) {
        self.navigationItem.rightBarButtonItem = [[UIBarButtonItem alloc]
            initWithTitle:@"Actions" menu:[self uatMenu]];
    } else {
        UIBarButtonItem* sources = [[UIBarButtonItem alloc] initWithTitle:@"Sources"
            style:UIBarButtonItemStylePlain target:self action:@selector(openSources)];
        UIBarButtonItem* uat = [[UIBarButtonItem alloc] initWithTitle:@"UAT"
            style:UIBarButtonItemStylePlain target:self action:@selector(openUAT)];
        self.navigationItem.rightBarButtonItems = @[uat, sources];
    }
    [self refresh];
}

- (void)openSources
{
    [self.navigationController pushViewController:
        [[TSSecurityToolkitTableViewController alloc] initWithCategory:@"Sources"] animated:YES];
}

- (void)openUAT
{
    [self.navigationController pushViewController:
        [[TSSecurityToolkitTableViewController alloc] initWithCategory:@"UAT"] animated:YES];
}

- (void)refresh
{
    if(self.busy) { [self.pullRefresh endRefreshing]; return; }
    self.busy = YES;
    dispatch_async(dispatch_get_global_queue(QOS_CLASS_USER_INITIATED, 0), ^{
        NSError* error = nil;
        NSDictionary* envelope = [[TSApplicationsManager sharedInstance]
            coreRequestOperation:@"getResearchToolkit" parameters:@{} error:&error];
        NSDictionary* result = [envelope[@"success"] boolValue] &&
            [envelope[@"result"] isKindOfClass:NSDictionary.class] ? envelope[@"result"] : nil;
        dispatch_async(dispatch_get_main_queue(), ^{
            self.busy = NO;
            self.snapshot = result;
            self.sections = [self makeSections:result];
            [self.pullRefresh endRefreshing];
            self.navigationItem.prompt = result ? @"Evidence-based state • pull to refresh" :
                (error.localizedDescription ?: envelope[@"errorMessage"] ?: @"Toolkit service unavailable");
            [self.tableView reloadData];
        });
    });
}

- (NSArray<NSDictionary*>*)makeSections:(NSDictionary*)snapshot
{
    NSArray* components = [snapshot[@"components"] isKindOfClass:NSArray.class]
        ? snapshot[@"components"] : @[];
    if([self.category isEqualToString:@"UAT"]) {
        NSDictionary* environment = [snapshot[@"environment"] isKindOfClass:NSDictionary.class]
            ? snapshot[@"environment"] : @{};
        NSDictionary* latest = [snapshot[@"uat_summary"] isKindOfClass:NSDictionary.class]
            ? snapshot[@"uat_summary"] : @{};
        NSArray* rows = @[
            @{ @"name": @"Environment", @"detail": [NSString stringWithFormat:@"iOS %@ • %@ • %@",
                environment[@"ios_version"] ?: @"?", environment[@"architecture"] ?: @"?",
                environment[@"bootstrap"] ?: @"?"] },
            @{ @"name": @"Apps Tested", @"detail": [self countForCategory:@"Apps/Security Research" in:components] },
            @{ @"name": @"Tweaks Tested", @"detail": [self countForCategory:@"Tweaks/Security Research" in:components] },
            @{ @"name": @"CLI Tools Tested", @"detail": [self countForCategory:@"Research Tools/Command Line" in:components] },
            @{ @"name": @"Host Tools Tested", @"detail": [self countForCategory:@"Host Security Tools" in:components] },
            @{ @"name": @"Smoke", @"detail": [self countSummary:latest[@"smoke"] result:latest[@"smoke_result"]] },
            @{ @"name": @"UAT", @"detail": [self countSummary:latest[@"uat"] result:latest[@"uat_result"]] },
            @{ @"name": @"Overall", @"detail": [self combinedResultWithSmoke:latest[@"smoke_result"]
                uat:latest[@"uat_result"]] },
            @{ @"name": @"Last Test", @"detail": latest[@"timestamp"] ?
                [[NSDate dateWithTimeIntervalSince1970:[latest[@"timestamp"] doubleValue]] description] : @"Never run" },
        ];
        return @[@{ @"title": @"Automated Evidence", @"rows": rows }];
    }
    if([self.category isEqualToString:@"Sources"]) {
        return @[@{ @"title": @"Upstream and Package Sources", @"rows": components }];
    }
    NSArray* categories = self.category.length ? @[self.category] : @[
        @"Research Tools/Instrumentation", @"Research Tools/Command Line", @"Host Security Tools"];
    NSMutableArray* sections = [NSMutableArray array];
    for(NSString* category in categories) {
        NSPredicate* match = [NSPredicate predicateWithBlock:^BOOL(NSDictionary* row, NSDictionary* bindings) {
            (void)bindings; return [row[@"category"] isEqualToString:category] &&
                (![category isEqualToString:@"Tweaks/Security Research"] ||
                 [row[@"type"] isEqualToString:@"TWEAK"]);
        }];
        NSArray* rows = [components filteredArrayUsingPredicate:match];
        NSString* title = [category componentsSeparatedByString:@"/"].lastObject;
        [sections addObject:@{ @"title": title ?: category, @"rows": rows }];
    }
    return sections;
}

- (NSString*)countForCategory:(NSString*)category in:(NSArray*)components
{
    NSUInteger listed = 0;
    NSUInteger tested = 0;
    for(NSDictionary* row in components) {
        if(![row[@"category"] isEqualToString:category]) continue;
        listed++;
        NSString* state = row[@"facets"][@"uat"];
        if([state isKindOfClass:NSString.class] &&
           ![state isEqualToString:@"SKIP"] && ![state isEqualToString:@"UNTESTED"])
            tested++;
    }
    return [NSString stringWithFormat:@"%lu tested / %lu listed",
            (unsigned long)tested, (unsigned long)listed];
}

- (NSString*)displayString:(id)value fallback:(NSString*)fallback
{
    return [value isKindOfClass:NSString.class] && [value length] ? value : fallback;
}

- (NSDictionary*)displayDictionary:(id)value
{
    return [value isKindOfClass:NSDictionary.class] ? value : @{};
}

- (NSArray*)displayArray:(id)value
{
    return [value isKindOfClass:NSArray.class] ? value : @[];
}

- (NSString*)symbolForComponent:(NSDictionary*)row
{
    NSString* type = [self displayString:row[@"type"] fallback:@""];
    NSString* scope = [self displayString:row[@"scope"] fallback:@""];
    if([type isEqualToString:@"APP"]) return @"app.fill";
    if([type isEqualToString:@"TWEAK"]) return @"puzzlepiece.extension.fill";
    if([type isEqualToString:@"DEPENDENCY"]) return @"shippingbox.fill";
    if([type isEqualToString:@"FRAMEWORK"] || [type isEqualToString:@"LIBRARY"])
        return @"square.stack.3d.up.fill";
    if([type isEqualToString:@"RUNTIME"] || [type isEqualToString:@"DAEMON"])
        return @"gearshape.2.fill";
    if([type isEqualToString:@"CLI"]) return @"terminal.fill";
    if([scope isEqualToString:@"HOST"]) return @"desktopcomputer";
    if([scope isEqualToString:@"DEVICE_AND_HOST"]) return @"cable.connector";
    return @"wrench.and.screwdriver.fill";
}

- (NSString*)countSummary:(NSDictionary*)counts result:(NSString*)result
{
    if(![counts isKindOfClass:NSDictionary.class]) return @"Not run";
    return [NSString stringWithFormat:@"%@ • PASS %@  FAIL %@  DEGRADED %@  BLOCKED %@  SKIP %@",
        result ?: @"UNTESTED", counts[@"PASS"] ?: @0, counts[@"FAIL"] ?: @0,
        counts[@"DEGRADED"] ?: @0, counts[@"BLOCKED"] ?: @0, counts[@"SKIP"] ?: @0];
}

- (NSString*)combinedResultWithSmoke:(NSString*)smoke uat:(NSString*)uat
{
    if(![smoke isKindOfClass:NSString.class]) return @"UNTESTED";
    NSArray<NSString*>* severity = @[@"BLOCKED", @"FAIL", @"DEGRADED", @"SKIP", @"PASS"];
    if(![severity containsObject:smoke] ||
       ([uat isKindOfClass:NSString.class] && ![severity containsObject:uat]))
        return @"BLOCKED";
    for(NSString* state in severity)
        if([smoke isEqualToString:state] ||
           ([uat isKindOfClass:NSString.class] && [uat isEqualToString:state]))
            return state;
    return @"BLOCKED";
}

- (UIMenu*)uatMenu
{
    __weak typeof(self) weakSelf = self;
    UIAction* all = [UIAction actionWithTitle:@"Run All" image:[UIImage systemImageNamed:@"checklist"]
        identifier:nil handler:^(__kindof UIAction* action) { (void)action; [weakSelf runSuite:@"runToolkitUAT"]; }];
    UIAction* smoke = [UIAction actionWithTitle:@"Run Smoke Tests" image:[UIImage systemImageNamed:@"waveform.path.ecg"]
        identifier:nil handler:^(__kindof UIAction* action) { (void)action; [weakSelf runSuite:@"runToolkitSmoke"]; }];
    UIAction* export = [UIAction actionWithTitle:@"Export Report" image:[UIImage systemImageNamed:@"square.and.arrow.up"]
        identifier:nil handler:^(__kindof UIAction* action) { (void)action; [weakSelf exportReport]; }];
    return [UIMenu menuWithTitle:@"Security Toolkit UAT" children:@[all, smoke, export]];
}

- (void)runSuite:(NSString*)operation
{
    if(self.busy) return;
    self.busy = YES;
    self.navigationItem.prompt = @"Running bounded toolkit checks…";
    dispatch_async(dispatch_get_global_queue(QOS_CLASS_USER_INITIATED, 0), ^{
        NSError* error = nil;
        NSDictionary* envelope = [[TSApplicationsManager sharedInstance]
            coreRequestOperation:operation parameters:@{} error:&error];
        NSDictionary* value = [envelope[@"result"] isKindOfClass:NSDictionary.class] ? envelope[@"result"] : nil;
        dispatch_async(dispatch_get_main_queue(), ^{
            self.busy = NO;
            NSDictionary* smoke = [value[@"smoke"] isKindOfClass:NSDictionary.class] ? value[@"smoke"] : @{};
            NSDictionary* uat = [value[@"uat"] isKindOfClass:NSDictionary.class] ? value[@"uat"] : @{};
            NSString* result = [self combinedResultWithSmoke:smoke[@"result"] uat:uat[@"result"]];
            NSString* message = error.localizedDescription ?: envelope[@"errorMessage"] ?:
                [NSString stringWithFormat:@"Automated result: %@. Manual researcher evaluation is required.", result];
            UIAlertController* alert = [UIAlertController alertControllerWithTitle:@"Toolkit Test Result"
                message:message preferredStyle:UIAlertControllerStyleAlert];
            [alert addAction:[UIAlertAction actionWithTitle:@"Done" style:UIAlertActionStyleCancel handler:nil]];
            [self presentViewController:alert animated:YES completion:nil];
            [self refresh];
        });
    });
}

- (void)exportReport
{
    dispatch_async(dispatch_get_global_queue(QOS_CLASS_USER_INITIATED, 0), ^{
        NSError* error = nil;
        NSDictionary* envelope = [[TSApplicationsManager sharedInstance]
            coreRequestOperation:@"getToolkitReport" parameters:@{} error:&error];
        NSDictionary* value = [envelope[@"result"] isKindOfClass:NSDictionary.class] ? envelope[@"result"] : nil;
        NSString* encoded = [value[@"base64"] isKindOfClass:NSString.class] ? value[@"base64"] : nil;
        NSData* contents = [[NSData alloc] initWithBase64EncodedString:encoded ?: @"" options:0];
        unsigned char digest[CC_SHA256_DIGEST_LENGTH];
        if(contents.length) CC_SHA256(contents.bytes, (CC_LONG)contents.length, digest);
        NSMutableString* observed = [NSMutableString new];
        if(contents.length) for(int index = 0; index < CC_SHA256_DIGEST_LENGTH; index++)
            [observed appendFormat:@"%02x", digest[index]];
        BOOL verified = contents.length && [observed isEqualToString:value[@"sha256"]];
        NSURL* documents = [NSFileManager.defaultManager URLsForDirectory:NSDocumentDirectory
            inDomains:NSUserDomainMask].firstObject;
        NSURL* output = [documents URLByAppendingPathComponent:@"0sky-uat.zip"];
        if(verified) verified = [contents writeToURL:output options:NSDataWritingAtomic error:&error];
        dispatch_async(dispatch_get_main_queue(), ^{
            if(!verified) {
                UIAlertController* alert = [UIAlertController alertControllerWithTitle:@"Report Unavailable"
                    message:error.localizedDescription ?: envelope[@"errorMessage"] ?: @"Report integrity check failed"
                    preferredStyle:UIAlertControllerStyleAlert];
                [alert addAction:[UIAlertAction actionWithTitle:@"Done" style:UIAlertActionStyleCancel handler:nil]];
                [self presentViewController:alert animated:YES completion:nil];
                return;
            }
            UIActivityViewController* share = [[UIActivityViewController alloc] initWithActivityItems:@[output]
                applicationActivities:nil];
            share.popoverPresentationController.barButtonItem = self.navigationItem.rightBarButtonItem;
            [self presentViewController:share animated:YES completion:nil];
        });
    });
}

- (NSInteger)numberOfSectionsInTableView:(UITableView*)tableView
{ (void)tableView; return self.sections.count; }
- (NSInteger)tableView:(UITableView*)tableView numberOfRowsInSection:(NSInteger)section
{ (void)tableView; return [self.sections[section][@"rows"] count]; }
- (NSString*)tableView:(UITableView*)tableView titleForHeaderInSection:(NSInteger)section
{ (void)tableView; return self.sections[section][@"title"]; }

- (UITableViewCell*)tableView:(UITableView*)tableView cellForRowAtIndexPath:(NSIndexPath*)indexPath
{
    UITableViewCell* cell = [tableView dequeueReusableCellWithIdentifier:@"ToolkitCell"];
    if(!cell) cell = [[UITableViewCell alloc] initWithStyle:UITableViewCellStyleSubtitle
        reuseIdentifier:@"ToolkitCell"];
    NSDictionary* row = self.sections[indexPath.section][@"rows"][indexPath.row];
    BOOL dashboard = [self.category isEqualToString:@"UAT"];
    NSString* name = [self displayString:row[@"name"] fallback:
        [self displayString:row[@"display_name"] fallback:
            [self displayString:row[@"id"] fallback:@"Unknown component"]]];
    NSString* badge = [self displayString:row[@"badge"] fallback:@"UNTESTED"];
    cell.textLabel.text = dashboard ? name :
        [NSString stringWithFormat:@"%@  %@", name, badge];
    NSDictionary* facets = [self displayDictionary:row[@"facets"]];
    NSString* installedVersion = [self displayString:row[@"installed_version"] fallback:nil];
    NSString* versionLabel = installedVersion ?
        [@"v" stringByAppendingString:installedVersion] : @"No installed version";
    cell.detailTextLabel.text = dashboard ?
        [self displayString:row[@"detail"] fallback:@"No evidence recorded"] :
        [self.category isEqualToString:@"Sources"] ?
            [NSString stringWithFormat:@"%@ • package %@ • %@",
                [self displayString:row[@"source_trust"] fallback:@"UNVERIFIED"],
                [self displayString:row[@"package_source_trust"] fallback:@"UNVERIFIED"],
                [self displayString:row[@"upstream_project"] fallback:@"No upstream recorded"]] :
            [NSString stringWithFormat:@"%@ • %@ • %@ • runtime %@ • smoke %@ • UAT %@",
                [self displayString:row[@"scope"] fallback:@"UNKNOWN SCOPE"], versionLabel,
                [self displayString:facets[@"compatibility"] fallback:@"UNVERIFIED"],
                [self displayString:facets[@"runtime"] fallback:@"UNTESTED"],
                [self displayString:facets[@"smoke"] fallback:@"SKIP"],
                [self displayString:facets[@"uat"] fallback:@"SKIP"]];
    cell.detailTextLabel.numberOfLines = 3;
    cell.imageView.image = [UIImage systemImageNamed:dashboard ? @"checklist" :
        [self symbolForComponent:row]];
    cell.imageView.tintColor = UIColor.systemBlueColor;
    cell.accessoryType = dashboard ? UITableViewCellAccessoryNone : UITableViewCellAccessoryDisclosureIndicator;
    cell.textLabel.textColor = [badge isEqualToString:@"READY"] ? UIColor.systemGreenColor :
        ([badge isEqualToString:@"FAILED"] || [badge isEqualToString:@"REPAIR REQUIRED"] ||
         [badge hasPrefix:@"BLOCKED"]) ? UIColor.systemRedColor :
        ([badge isEqualToString:@"COMPATIBILITY UNKNOWN"] ||
         [badge isEqualToString:@"ADAPTATION REQUIRED"] ||
         [badge isEqualToString:@"BUILD REQUIRED"]) ? UIColor.systemOrangeColor : UIColor.labelColor;
    return cell;
}

- (void)tableView:(UITableView*)tableView didSelectRowAtIndexPath:(NSIndexPath*)indexPath
{
    [tableView deselectRowAtIndexPath:indexPath animated:YES];
    if([self.category isEqualToString:@"UAT"]) return;
    NSDictionary* row = self.sections[indexPath.section][@"rows"][indexPath.row];
    NSDictionary* facets = [self displayDictionary:row[@"facets"]];
    NSString* dependencies = [[self displayArray:row[@"missing_dependencies"]]
        componentsJoinedByString:@", "];
    NSString* details = [NSString stringWithFormat:
        @"Type: %@ • %@\nInstalled: %@\nSource: %@\nCompatibility: %@\nDependencies: %@\nRuntime: %@\nSmoke: %@\nUAT: %@\nReason: %@\nAvailable actions: %@\nUnavailable actions: %@",
        [self displayString:row[@"type"] fallback:@"UNKNOWN"],
        [self displayString:row[@"scope"] fallback:@"UNKNOWN"],
        [self displayString:facets[@"installation"] fallback:@"UNKNOWN"],
        [self displayString:facets[@"source"] fallback:@"UNVERIFIED"],
        [self displayString:facets[@"compatibility"] fallback:@"UNVERIFIED"],
        dependencies.length ? dependencies : @"Resolved",
        [self displayString:facets[@"runtime"] fallback:@"UNTESTED"],
        [self displayString:facets[@"smoke"] fallback:@"SKIP"],
        [self displayString:facets[@"uat"] fallback:@"SKIP"],
        [self displayString:row[@"runtime_reason"] fallback:
            [self displayString:row[@"compatibility_reason"] fallback:@"No current evidence"]],
        [[self displayArray:row[@"actions"]] componentsJoinedByString:@", "].length ?
            [[self displayArray:row[@"actions"]] componentsJoinedByString:@", "] : @"None",
        [[self displayArray:row[@"unavailable_actions"]] componentsJoinedByString:@", "].length ?
            [[self displayArray:row[@"unavailable_actions"]] componentsJoinedByString:@", "] : @"None"];
    NSString* sourceGit = [self displayString:row[@"source_git"] fallback:nil];
    if(sourceGit.length) details = [details stringByAppendingFormat:@"\nSource Git: %@", sourceGit];
    UIAlertController* alert = [UIAlertController alertControllerWithTitle:
        [self displayString:row[@"name"] fallback:
            [self displayString:row[@"id"] fallback:@"Component"]]
        message:details preferredStyle:UIAlertControllerStyleActionSheet];
    NSString* upstream = [self displayString:row[@"upstream_project"] fallback:nil];
    NSURL* source = [NSURL URLWithString:upstream ?: @""];
    if([source.scheme isEqualToString:@"https"]) {
        [alert addAction:[UIAlertAction actionWithTitle:@"View Source" style:UIAlertActionStyleDefault
            handler:^(UIAlertAction* action) { (void)action; [UIApplication.sharedApplication openURL:source
                options:@{} completionHandler:nil]; }]];
    }
    NSURL* mirror = [NSURL URLWithString:[self displayString:row[@"source_mirror"] fallback:@""]];
    if([mirror.scheme isEqualToString:@"https"]) {
        [alert addAction:[UIAlertAction actionWithTitle:@"View Source Mirror" style:UIAlertActionStyleDefault
            handler:^(UIAlertAction* action) { (void)action; [UIApplication.sharedApplication openURL:mirror
                options:@{} completionHandler:nil]; }]];
    }
    [alert addAction:[UIAlertAction actionWithTitle:@"Run Smoke Tests" style:UIAlertActionStyleDefault
        handler:^(UIAlertAction* action) { (void)action; [self runSuite:@"runToolkitSmoke"]; }]];
    [alert addAction:[UIAlertAction actionWithTitle:@"Cancel" style:UIAlertActionStyleCancel handler:nil]];
    alert.popoverPresentationController.sourceView = tableView;
    alert.popoverPresentationController.sourceRect = [tableView rectForRowAtIndexPath:indexPath];
    [self presentViewController:alert animated:YES completion:nil];
}

@end
