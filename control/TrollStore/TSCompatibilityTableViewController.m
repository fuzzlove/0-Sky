#import "TSCompatibilityTableViewController.h"
#import "TSApplicationsManager.h"

@interface TSCompatibilityTableViewController ()
@property(nonatomic, strong) NSArray<NSDictionary*>* components;
@property(nonatomic, assign) BOOL loading;
@property(nonatomic, strong) NSDictionary* selectedManifest;
@end

@implementation TSCompatibilityTableViewController

- (instancetype)init { return [super initWithStyle:UITableViewStyleInsetGrouped]; }

- (void)viewDidLoad
{
    [super viewDidLoad];
    self.title = @"Compatibility";
    self.components = @[];
    self.refreshControl = [UIRefreshControl new];
    [self.refreshControl addTarget:self action:@selector(refresh) forControlEvents:UIControlEventValueChanged];
    self.navigationItem.rightBarButtonItem = [[UIBarButtonItem alloc]
        initWithBarButtonSystemItem:UIBarButtonSystemItemRefresh target:self action:@selector(refresh)];
    [self refresh];
}

- (void)refresh
{
    if(self.loading) return;
    self.loading = YES;
    self.navigationItem.rightBarButtonItem.enabled = NO;
    dispatch_async(dispatch_get_global_queue(QOS_CLASS_UTILITY, 0), ^{
        NSError* error = nil;
        NSDictionary* envelope = [[TSApplicationsManager sharedInstance]
            coreRequestOperation:@"getCompatibility" parameters:@{} error:&error];
        NSDictionary* result = [envelope[@"success"] boolValue] &&
            [envelope[@"result"] isKindOfClass:NSDictionary.class] ? envelope[@"result"] : nil;
        NSArray* entries = [result[@"components"] isKindOfClass:NSArray.class] ? result[@"components"] : @[];
        dispatch_async(dispatch_get_main_queue(), ^{
            self.components = entries;
            self.navigationItem.prompt = result ? @"Functional validation required"
                : @"Compatibility evidence is unavailable";
            self.loading = NO;
            self.navigationItem.rightBarButtonItem.enabled = YES;
            [self.refreshControl endRefreshing];
            [self.tableView reloadData];
        });
    });
}

- (NSInteger)tableView:(UITableView*)tableView numberOfRowsInSection:(NSInteger)section
{ (void)tableView; (void)section; return MAX(1, (NSInteger)self.components.count); }

- (NSString*)tableView:(UITableView*)tableView titleForFooterInSection:(NSInteger)section
{
    (void)tableView; (void)section;
    return @"Unknown means investigate. Compatible and Compatible — 0-Sky Adapter require functional evidence for this exact artifact and environment.";
}

- (UITableViewCell*)tableView:(UITableView*)tableView cellForRowAtIndexPath:(NSIndexPath*)indexPath
{
    (void)tableView;
    UITableViewCell* cell = [[UITableViewCell alloc] initWithStyle:UITableViewCellStyleSubtitle reuseIdentifier:nil];
    cell.textLabel.numberOfLines = 0;
    cell.detailTextLabel.numberOfLines = 0;
    if(!self.components.count) {
        cell.textLabel.text = @"No compatibility evidence yet";
        cell.detailTextLabel.text = @"Run the installed-component audit from the paired Mac.";
        return cell;
    }
    NSDictionary* component = self.components[indexPath.row];
    NSString* state = component[@"compatibility_state"] ?: component[@"status"] ?: @"UNKNOWN";
    cell.textLabel.text = [NSString stringWithFormat:@"%@ • %@", component[@"component"] ?: @"Component", [state stringByReplacingOccurrencesOfString:@"_" withString:@" "]];
    NSDictionary* environment = component[@"environment"];
    BOOL services = NO;
    for(NSDictionary* item in component[@"components"])
        if([item[@"kind"] isEqual:@"service"] || [item[@"kind"] isEqual:@"xpc_service"]) services = YES;
    NSString* serviceState = services
        ? ([component[@"runtime_validation"][@"communication"][@"passed"] boolValue] ? @"Verified" : @"Unverified")
        : @"Not required";
    cell.detailTextLabel.text = [NSString stringWithFormat:@"iOS %@ • %@\nService: %@",
        environment[@"ios_version"] ?: @"Unknown", component[@"root_requirement"] ?: @"Unknown root requirement", serviceState];
    cell.accessoryType = UITableViewCellAccessoryDisclosureIndicator;
    cell.isAccessibilityElement = YES;
    cell.accessibilityLabel = cell.textLabel.text;
    cell.accessibilityValue = cell.detailTextLabel.text;
    return cell;
}

- (void)tableView:(UITableView*)tableView didSelectRowAtIndexPath:(NSIndexPath*)indexPath
{
    [tableView deselectRowAtIndexPath:indexPath animated:YES];
    if(indexPath.row >= self.components.count) return;
    NSDictionary* component = self.components[indexPath.row];
    UIViewController* detail = [UIViewController new];
    detail.title = component[@"component"] ?: @"Component diagnostics";
    UITextView* text = [UITextView new];
    text.editable = NO;
    text.font = [UIFont preferredFontForTextStyle:UIFontTextStyleBody];
    text.backgroundColor = UIColor.systemBackgroundColor;
    NSString* state = component[@"compatibility_state"] ?: component[@"status"] ?: @"UNKNOWN";
    NSMutableString* diagnostics = [NSMutableString stringWithFormat:@"Compatibility: %@\nPipeline: %@\nRoot requirement: %@\n\n",
        state, component[@"pipeline_phase"] ?: @"DISCOVER", component[@"root_requirement"] ?: @"Unknown"];
    for(NSDictionary* issue in component[@"issues"])
        [diagnostics appendFormat:@"%@\n%@\n\n", issue[@"code"], issue[@"detail"]];
    self.selectedManifest = component;
    UIBarButtonItem* advanced = [[UIBarButtonItem alloc]
        initWithTitle:@"Evidence" style:UIBarButtonItemStylePlain target:self action:@selector(showAdvancedManifest)];
    UIBarButtonItem* analyze = [[UIBarButtonItem alloc]
        initWithTitle:@"Analyze" style:UIBarButtonItemStylePlain target:self action:@selector(analyzeSelectedManifest)];
    detail.navigationItem.rightBarButtonItems = @[advanced, analyze];
    text.text = diagnostics;
    detail.view = text;
    [self.navigationController pushViewController:detail animated:YES];
}
- (void)analyzeSelectedManifest
{
    NSString* key = self.selectedManifest[@"registry_key"];
    if(!key.length) return;
    dispatch_async(dispatch_get_global_queue(QOS_CLASS_UTILITY, 0), ^{
        NSError* error = nil;
        NSDictionary* envelope = [[TSApplicationsManager sharedInstance]
            coreRequestOperation:@"analyzeCompatibility"
            parameters:@{@"registryKey": key} error:&error];
        NSDictionary* component = [envelope[@"result"][@"component"] isKindOfClass:NSDictionary.class]
            ? envelope[@"result"][@"component"] : nil;
        dispatch_async(dispatch_get_main_queue(), ^{
            NSString* state = component[@"compatibility_state"] ?: @"UNKNOWN";
            UIAlertController* alert = [UIAlertController alertControllerWithTitle:@"Compatibility Analysis"
                message:component ? [state stringByReplacingOccurrencesOfString:@"_" withString:@" "]
                                  : error.localizedDescription ?: envelope[@"errorMessage"] ?: @"Analysis unavailable"
                preferredStyle:UIAlertControllerStyleAlert];
            [alert addAction:[UIAlertAction actionWithTitle:@"Done" style:UIAlertActionStyleCancel handler:nil]];
            [self presentViewController:alert animated:YES completion:nil];
            [self refresh];
        });
    });
}
- (void)showAdvancedManifest
{
    NSString* key = self.selectedManifest[@"registry_key"];
    if(!key.length) return;
    dispatch_async(dispatch_get_global_queue(QOS_CLASS_UTILITY, 0), ^{
        NSDictionary* envelope = [[TSApplicationsManager sharedInstance]
            coreRequestOperation:@"getCompatibilityDetail" parameters:@{@"registryKey": key} error:nil];
        NSDictionary* manifest = envelope[@"result"][@"component"];
        dispatch_async(dispatch_get_main_queue(), ^{
            UIViewController* detail = [UIViewController new];
            detail.title = @"Validation Manifest";
            UITextView* text = [UITextView new];
            text.editable = NO;
            text.font = [UIFont monospacedSystemFontOfSize:12 weight:UIFontWeightRegular];
            NSData* data = [manifest isKindOfClass:NSDictionary.class]
                ? [NSJSONSerialization dataWithJSONObject:manifest options:NSJSONWritingPrettyPrinted error:nil] : nil;
            text.text = data ? [[NSString alloc] initWithData:data encoding:NSUTF8StringEncoding]
                : @"Detailed compatibility evidence is unavailable.";
            detail.view = text;
            [self.navigationController pushViewController:detail animated:YES];
        });
    });
}

@end
