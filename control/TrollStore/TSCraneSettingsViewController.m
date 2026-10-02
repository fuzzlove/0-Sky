#import "TSCraneSettingsViewController.h"
#import "TSApplicationsManager.h"
#import <dlfcn.h>
#import <objc/runtime.h>

static NSString* const TSCranePackage = @"com.opa334.crane";
static NSString* const TSCraneCleanupNotification = @"TSCraneCleanupNotification";
static void (*TSCraneOriginalDeleteContainer)(id, SEL, NSString*, NSString*);

@interface NSObject (TSCraneContainerInventory)
+ (instancetype)sharedManager;
- (NSArray*)containerIdentifiersOfApplicationWithIdentifier:(NSString*)bundleID;
- (NSDictionary*)pathsAssociatedToContainerWithIdentifier:(NSString*)containerID
                               ofApplicationWithIdentifier:(NSString*)bundleID;
@end

static BOOL TSLoadCraneRuntime(NSString** errorOut)
{
    NSString* frameworks = [NSBundle.mainBundle.bundlePath
        stringByAppendingPathComponent:@"Frameworks"];
    BOOL embedded = [[NSFileManager defaultManager]
        fileExistsAtPath:[frameworks stringByAppendingPathComponent:@"libcrane.dylib"]];
    NSArray<NSString*>* dependencies = embedded ? @[
        [frameworks stringByAppendingPathComponent:@"libellekit.dylib"],
        [frameworks stringByAppendingPathComponent:@"libsandy.dylib"],
        [frameworks stringByAppendingPathComponent:@"libcrane.dylib"],
        [frameworks stringByAppendingPathComponent:@"AltList.framework/AltList"],
    ] : @[
        @"/var/jb/Library/Frameworks/CydiaSubstrate.framework/CydiaSubstrate",
        @"/var/jb/usr/lib/libsandy.dylib",
        @"/var/jb/usr/lib/libcrane.dylib",
        @"/var/jb/Library/Frameworks/AltList.framework/AltList",
    ];
    for(NSString* path in dependencies) {
        if(![[NSFileManager defaultManager] isReadableFileAtPath:path]) {
            if(errorOut) *errorOut = [NSString stringWithFormat:
                @"Required Crane dependency is missing: %@", path.lastPathComponent];
            return NO;
        }
        if(!dlopen(path.fileSystemRepresentation, RTLD_NOW | RTLD_GLOBAL)) {
            const char* error = dlerror();
            if(errorOut) *errorOut = [NSString stringWithFormat:
                @"%@ could not be loaded: %s", path.lastPathComponent,
                error ?: "unknown dynamic-loader error"];
            return NO;
        }
    }
    return YES;
}

static NSString* TSValidatedMCMDataRoot(NSString* value)
{
    if(![value isKindOfClass:NSString.class]) return nil;
    NSString* standardized = value.stringByStandardizingPath;
    if([standardized hasPrefix:@"/var/mobile/"])
        standardized = [@"/private" stringByAppendingString:standardized];
    NSString* prefix = @"/private/var/mobile/Containers/Data/Application/";
    if(![standardized hasPrefix:prefix]) return nil;
    NSString* identifier = [standardized substringFromIndex:prefix.length];
    if([identifier containsString:@"/"] || ![[NSUUID alloc] initWithUUIDString:identifier])
        return nil;
    return standardized;
}

static void TSCraneDeleteContainer(id object, SEL selector, NSString* containerID,
                                   NSString* bundleID)
{
    NSDictionary* paths = [object respondsToSelector:
        @selector(pathsAssociatedToContainerWithIdentifier:ofApplicationWithIdentifier:)]
        ? [object pathsAssociatedToContainerWithIdentifier:containerID
                               ofApplicationWithIdentifier:bundleID] : nil;
    NSString* selectedPath = [paths[bundleID] isKindOfClass:NSString.class]
        ? [paths[bundleID] stringByStandardizingPath] : nil;
    NSString* suffix = [NSString stringWithFormat:
        @"/Library/___Crane_Containers/%@", containerID ?: @""];
    NSString* dataRoot = [selectedPath hasSuffix:suffix]
        ? [selectedPath substringToIndex:selectedPath.length - suffix.length] : nil;
    TSCraneOriginalDeleteContainer(object, selector, containerID, bundleID);
    if(!containerID.length || !bundleID.length || !dataRoot.length) {
        [NSNotificationCenter.defaultCenter
            postNotificationName:TSCraneCleanupNotification object:nil
            userInfo:@{@"success": @NO,
                       @"detail": @"Crane did not provide a safe container path; its data was preserved for repair."}];
        return;
    }
    NSString* capturedContainer = containerID.copy;
    NSString* capturedBundle = bundleID.copy;
    dispatch_async(dispatch_get_global_queue(QOS_CLASS_USER_INITIATED, 0), ^{
        NSError* error = nil;
        NSDictionary* envelope = [[TSApplicationsManager sharedInstance]
            coreRequestOperation:@"cleanupCraneContainer"
            parameters:@{@"package": TSCranePackage,
                         @"bundleID": capturedBundle,
                         @"containerID": capturedContainer,
                         @"dataRoot": dataRoot} error:&error];
        dispatch_async(dispatch_get_main_queue(), ^{
            BOOL bridgeSuccess = [envelope[@"success"] boolValue];
            BOOL metadataRemoved = NO;
            if(bridgeSuccess) {
                // Crane's first delete attempt can leave metadata behind when
                // iOS MAC refuses the directory removal.  The Bridge has now
                // removed that exact directory, so repeat the vendor method
                // to complete its normal metadata/preferences transaction.
                TSCraneOriginalDeleteContainer(object, selector,
                                                capturedContainer, capturedBundle);
                NSArray* remaining = [object respondsToSelector:
                    @selector(containerIdentifiersOfApplicationWithIdentifier:)]
                    ? [object containerIdentifiersOfApplicationWithIdentifier:capturedBundle]
                    : nil;
                metadataRemoved = remaining && ![remaining containsObject:capturedContainer];
            }
            BOOL success = bridgeSuccess && metadataRemoved;
            NSString* detail = success
                ? @"Deleted Crane container files and metadata were verified by the trusted Mac."
                : (error.localizedDescription ?: envelope[@"errorMessage"] ?:
                   @"The container could not be removed completely; its data was preserved for repair.");
            [NSNotificationCenter.defaultCenter
                postNotificationName:TSCraneCleanupNotification object:nil
                userInfo:@{@"success": @(success), @"detail": detail}];
        });
    });
}

static BOOL TSInstallCraneDeleteAdapter(NSString** errorOut)
{
    static dispatch_once_t once;
    static BOOL installed = NO;
    static NSString* failure = nil;
    dispatch_once(&once, ^{
        Class manager = NSClassFromString(@"CraneManager");
        SEL selector = NSSelectorFromString(
            @"deleteContainerWithIdentifier:forApplicationWithIdentifier:");
        Method method = manager ? class_getInstanceMethod(manager, selector) : NULL;
        if(!method) {
            failure = @"Crane's container deletion API is unavailable.";
            return;
        }
        TSCraneOriginalDeleteContainer = (void*)method_getImplementation(method);
        method_setImplementation(method, (IMP)TSCraneDeleteContainer);
        installed = YES;
    });
    if(!installed && errorOut) *errorOut = failure;
    return installed;
}

@interface TSCraneSettingsViewController ()
@property(nonatomic,copy) NSString* descriptorPath;
@property(nonatomic,strong) NSArray<NSDictionary*>* applications;
@property(nonatomic,strong) NSMutableSet<NSString*>* selectedBundles;
@property(nonatomic,assign) BOOL loading;
@end

@implementation TSCraneSettingsViewController

- (instancetype)initWithDescriptorPath:(NSString*)descriptorPath
{
    self = [super initWithStyle:UITableViewStyleInsetGrouped];
    if(self) {
        _descriptorPath = descriptorPath.copy;
        _applications = @[];
        _selectedBundles = [NSMutableSet set];
        self.title = @"Crane";
    }
    return self;
}

- (void)viewDidLoad
{
    [super viewDidLoad];
    self.refreshControl = [UIRefreshControl new];
    [self.refreshControl addTarget:self action:@selector(loadTargets)
                  forControlEvents:UIControlEventValueChanged];
    [NSNotificationCenter.defaultCenter addObserver:self
        selector:@selector(craneCleanupCompleted:)
        name:TSCraneCleanupNotification object:nil];
    [self loadTargets];
}

- (void)dealloc
{
    [NSNotificationCenter.defaultCenter removeObserver:self];
}

- (void)craneCleanupCompleted:(NSNotification*)notification
{
    BOOL success = [notification.userInfo[@"success"] boolValue];
    NSString* detail = notification.userInfo[@"detail"];
    self.navigationItem.prompt = success ? @"Container deletion verified by 0-Sky Bridge"
        : @"Container cleanup requires attention";
    if(!success && self.view.window) {
        UIAlertController* alert = [UIAlertController
            alertControllerWithTitle:@"Crane Container Cleanup Incomplete"
            message:detail preferredStyle:UIAlertControllerStyleAlert];
        [alert addAction:[UIAlertAction actionWithTitle:@"OK"
            style:UIAlertActionStyleDefault handler:nil]];
        [self presentViewController:alert animated:YES completion:nil];
    }
}

- (void)viewWillAppear:(BOOL)animated
{
    [super viewWillAppear:animated];
    if(self.isViewLoaded && self.applications.count) [self loadTargets];
}

- (void)loadTargets
{
    if(self.loading) return;
    self.loading = YES;
    self.navigationItem.prompt = @"Reading Crane's explicit application targets…";
    dispatch_async(dispatch_get_global_queue(QOS_CLASS_USER_INITIATED, 0), ^{
        NSError* error = nil;
        NSDictionary* envelope = [[TSApplicationsManager sharedInstance]
            coreRequestOperation:@"getTweakTargetApps"
            parameters:@{@"package": TSCranePackage} error:&error];
        NSDictionary* result = [envelope[@"result"] isKindOfClass:NSDictionary.class]
            ? envelope[@"result"] : nil;
        NSArray* applications = [result[@"applications"] isKindOfClass:NSArray.class]
            ? result[@"applications"] : nil;
        NSArray* selected = [result[@"selected"] isKindOfClass:NSArray.class]
            ? result[@"selected"] : nil;
        if(applications && selected) {
            NSMutableSet<NSString*>* converted = [NSMutableSet set];
            for(NSDictionary* app in applications) {
                if([app[@"compatibility"] isEqual:@"COMPATIBLE_WITH_ADAPTER"] &&
                   [app[@"bundleID"] isKindOfClass:NSString.class]) {
                    [converted addObject:app[@"bundleID"]];
                }
            }
            NSMutableArray<NSString*>* reconciled = [NSMutableArray array];
            for(NSString* bundle in selected) {
                if([converted containsObject:bundle]) [reconciled addObject:bundle];
            }
            selected = [reconciled sortedArrayUsingSelector:@selector(compare:)];
        }
        dispatch_async(dispatch_get_main_queue(), ^{
            self.loading = NO;
            [self.refreshControl endRefreshing];
            if(applications && selected) {
                self.applications = applications;
                self.selectedBundles = [NSMutableSet setWithArray:selected];
                self.navigationItem.prompt = self.selectedBundles.count
                    ? [NSString stringWithFormat:@"%lu explicit target%@ • relaunch an app after changes",
                       (unsigned long)self.selectedBundles.count,
                       self.selectedBundles.count == 1 ? @"" : @"s"]
                    : @"Select an authorized app before Crane's app hook is enabled";
            } else {
                self.navigationItem.prompt = error.localizedDescription ?:
                    envelope[@"errorMessage"] ?: @"Crane target inventory is unavailable";
            }
            [self.tableView reloadData];
        });
    });
}

- (NSInteger)numberOfSectionsInTableView:(UITableView*)tableView
{
    (void)tableView;
    return 3;
}

- (NSInteger)tableView:(UITableView*)tableView numberOfRowsInSection:(NSInteger)section
{
    (void)tableView;
    if(section == 0) return 1;
    if(section == 1) return self.applications.count ?: 1;
    return 1;
}

- (NSString*)tableView:(UITableView*)tableView titleForHeaderInSection:(NSInteger)section
{
    (void)tableView;
    if(section == 0) return @"Runtime";
    if(section == 1) return @"Authorized Applications";
    return @"Preferences";
}

- (NSString*)tableView:(UITableView*)tableView titleForFooterInSection:(NSInteger)section
{
    (void)tableView;
    if(section == 1)
        return @"Crane is injected only into applications selected here. Relaunch a selected app to apply the change.";
    return nil;
}

- (UITableViewCell*)tableView:(UITableView*)tableView
        cellForRowAtIndexPath:(NSIndexPath*)indexPath
{
    UITableViewCell* cell = [[UITableViewCell alloc]
        initWithStyle:UITableViewCellStyleSubtitle reuseIdentifier:nil];
    if(indexPath.section == 0) {
        cell.textLabel.text = @"Paid Crane iOS 27 Adapter";
        cell.detailTextLabel.text = self.selectedBundles.count
            ? @"System hooks verified; configured app hooks are enabled on relaunch"
            : @"System hooks verified; application selection is required";
        cell.detailTextLabel.numberOfLines = 2;
        cell.selectionStyle = UITableViewCellSelectionStyleNone;
        return cell;
    }
    if(indexPath.section == 2) {
        cell.textLabel.text = @"Native Crane Settings";
        cell.detailTextLabel.text = @"Manage app containers, shortcuts, notifications, and Crane options";
        cell.accessoryType = UITableViewCellAccessoryDisclosureIndicator;
        return cell;
    }
    if(!self.applications.count) {
        cell.textLabel.text = self.loading ? @"Loading applications…" : @"No eligible applications";
        cell.selectionStyle = UITableViewCellSelectionStyleNone;
        return cell;
    }
    NSDictionary* app = self.applications[indexPath.row];
    NSString* bundle = [app[@"bundleID"] isKindOfClass:NSString.class] ? app[@"bundleID"] : @"";
    cell.textLabel.text = [app[@"name"] isKindOfClass:NSString.class] ? app[@"name"] : bundle;
    NSString* version = [app[@"version"] isKindOfClass:NSString.class]
        ? app[@"version"] : @"unknown";
    BOOL converted = [app[@"compatibility"] isEqual:@"COMPATIBLE_WITH_ADAPTER"];
    cell.detailTextLabel.text = [NSString stringWithFormat:@"%@ • %@ • %@", bundle,
        version, converted ? @"0-Sky adapter ready" : @"conversion required"];
    cell.detailTextLabel.numberOfLines = 2;
    cell.accessoryType = converted && [self.selectedBundles containsObject:bundle]
        ? UITableViewCellAccessoryCheckmark : UITableViewCellAccessoryNone;
    cell.textLabel.enabled = converted;
    cell.detailTextLabel.enabled = converted;
    return cell;
}

- (void)showNativeControllerError:(NSString*)detail
{
    UIAlertController* alert = [UIAlertController
        alertControllerWithTitle:@"Crane Container Manager Unavailable"
        message:detail.length ? detail : @"The native Crane preference controller could not be loaded."
        preferredStyle:UIAlertControllerStyleAlert];
    [alert addAction:[UIAlertAction actionWithTitle:@"OK"
        style:UIAlertActionStyleDefault handler:nil]];
    [self presentViewController:alert animated:YES completion:nil];
}

- (void)openNativeContainerManager
{
    // NSBundle's optional privateFrameworksPath can be nil for an SRD app
    // registered from a Cryptex-backed payload even when the sealed Frameworks
    // directory is present in its MCM copy. Resolve from the canonical bundle
    // root so the availability check and dlopen use the same installed path.
    NSString* frameworks = [NSBundle.mainBundle.bundlePath
        stringByAppendingPathComponent:@"Frameworks"];
    NSString* bundledPreferences = [NSBundle.mainBundle.bundlePath
        stringByAppendingPathComponent:@"CranePrefs.bundle"];
    BOOL hasPrivateRuntime = [[NSFileManager defaultManager]
        fileExistsAtPath:[frameworks stringByAppendingPathComponent:@"libcrane.dylib"]];
    NSString* bundlePath = hasPrivateRuntime ? bundledPreferences
        : @"/var/jb/Library/PreferenceBundles/CranePrefs.bundle";
    NSString* runtimeError = nil;
    if(!TSLoadCraneRuntime(&runtimeError)) {
        [self showNativeControllerError:runtimeError];
        return;
    }

    NSBundle* bundle = [NSBundle bundleWithPath:bundlePath];
    NSError* loadError = nil;
    if(!bundle || (![bundle isLoaded] && ![bundle loadAndReturnError:&loadError])) {
        [self showNativeControllerError:loadError.localizedDescription ?:
            @"CranePrefs.bundle could not be loaded."];
        return;
    }
    NSString* adapterError = nil;
    if(!TSInstallCraneDeleteAdapter(&adapterError)) {
        [self showNativeControllerError:adapterError];
        return;
    }
    Class controllerClass = NSClassFromString(@"CRPRootListController");
    if(!controllerClass || ![controllerClass isSubclassOfClass:UIViewController.class]) {
        [self showNativeControllerError:
            @"Crane's CRPRootListController is absent from the installed preference bundle."];
        return;
    }
    @try {
        UIViewController* controller = [[controllerClass alloc] init];
        if(!controller) {
            [self showNativeControllerError:@"Crane's container manager did not initialize."];
            return;
        }
        controller.title = @"Crane Containers";
        [self.navigationController pushViewController:controller animated:YES];
    } @catch(NSException* exception) {
        [self showNativeControllerError:[NSString stringWithFormat:
            @"Crane's container manager rejected this environment: %@",
            exception.reason ?: exception.name]];
    }
}

- (void)applyBundle:(NSString*)bundle enabled:(BOOL)enabled
{
    NSMutableSet* updated = self.selectedBundles.mutableCopy;
    if(enabled) [updated addObject:bundle]; else [updated removeObject:bundle];
    self.loading = YES;
    self.tableView.userInteractionEnabled = NO;
    self.navigationItem.prompt = @"Updating Crane's verified runtime target list…";
    dispatch_async(dispatch_get_global_queue(QOS_CLASS_USER_INITIATED, 0), ^{
        NSError* error = nil;
        NSString* runtimeError = nil;
        NSDictionary* envelope = nil;
        if(!TSLoadCraneRuntime(&runtimeError)) {
            error = [NSError errorWithDomain:@"com.liquidsky.control.crane" code:1
                userInfo:@{NSLocalizedDescriptionKey: runtimeError ?:
                    @"Crane's runtime could not be loaded."}];
        } else {
            NSMutableSet<NSString*>* affected = self.selectedBundles.mutableCopy;
            [affected unionSet:updated];
            NSMutableDictionary<NSString*,NSString*>* dataRoots = [NSMutableDictionary dictionary];
            id manager = [NSClassFromString(@"CraneManager") sharedManager];
            for(NSString* identifier in affected) {
                NSDictionary* paths = [manager respondsToSelector:
                    @selector(pathsAssociatedToContainerWithIdentifier:ofApplicationWithIdentifier:)]
                    ? [manager pathsAssociatedToContainerWithIdentifier:@"DEFAULT"
                                         ofApplicationWithIdentifier:identifier] : nil;
                NSString* root = TSValidatedMCMDataRoot(paths[identifier]);
                if(!root) {
                    error = [NSError errorWithDomain:@"com.liquidsky.control.crane" code:2
                        userInfo:@{NSLocalizedDescriptionKey:
                            [NSString stringWithFormat:
                            @"Crane could not resolve %@'s exact data container.", identifier]}];
                    break;
                }
                dataRoots[identifier] = root;
            }
            if(!error) {
                envelope = [[TSApplicationsManager sharedInstance]
                    coreRequestOperation:@"setTweakTargets"
                    parameters:@{@"package": TSCranePackage,
                                 @"bundleIDs": [updated.allObjects sortedArrayUsingSelector:
                                     @selector(compare:)],
                                 @"dataRoots": dataRoots} error:&error];
            }
        }
        NSDictionary* result = [envelope[@"result"] isKindOfClass:NSDictionary.class]
            ? envelope[@"result"] : nil;
        dispatch_async(dispatch_get_main_queue(), ^{
            self.loading = NO;
            self.tableView.userInteractionEnabled = YES;
            if(result) {
                self.selectedBundles = [NSMutableSet setWithArray:result[@"selected"] ?: @[]];
                self.navigationItem.prompt = enabled
                    ? @"Target enabled • launch or relaunch the app for runtime verification"
                    : @"Target disabled • relaunch the app to unload Crane";
            } else {
                self.navigationItem.prompt = error.localizedDescription ?:
                    envelope[@"errorMessage"] ?: @"Crane target update failed";
            }
            [self.tableView reloadData];
        });
    });
}

- (void)tableView:(UITableView*)tableView didSelectRowAtIndexPath:(NSIndexPath*)indexPath
{
    [tableView deselectRowAtIndexPath:indexPath animated:YES];
    if(indexPath.section == 2) {
        [self openNativeContainerManager];
        return;
    }
    if(indexPath.section != 1 || indexPath.row >= (NSInteger)self.applications.count || self.loading)
        return;
    NSDictionary* app = self.applications[indexPath.row];
    NSString* bundle = app[@"bundleID"];
    NSString* name = app[@"name"] ?: bundle;
    BOOL enabling = ![self.selectedBundles containsObject:bundle];
    if(enabling && ![app[@"compatibility"] isEqual:@"COMPATIBLE_WITH_ADAPTER"]) {
        UIAlertController* required = [UIAlertController
            alertControllerWithTitle:@"Crane Conversion Required"
            message:@"This app must pass the 0-Sky pre-main Crane conversion and runtime test before it can be enabled. Convert its authorized IPA in 0-Sky Converter, then reinstall it."
            preferredStyle:UIAlertControllerStyleAlert];
        [required addAction:[UIAlertAction actionWithTitle:@"OK"
            style:UIAlertActionStyleDefault handler:nil]];
        [self presentViewController:required animated:YES completion:nil];
        return;
    }
    if(!enabling) {
        [self applyBundle:bundle enabled:NO];
        return;
    }
    UIAlertController* confirmation = [UIAlertController
        alertControllerWithTitle:[NSString stringWithFormat:@"Enable Crane for %@?", name]
        message:@"0-Sky will add this exact application to Crane's injection allowlist. Relaunch the app to test it."
        preferredStyle:UIAlertControllerStyleAlert];
    [confirmation addAction:[UIAlertAction actionWithTitle:@"Cancel"
        style:UIAlertActionStyleCancel handler:nil]];
    [confirmation addAction:[UIAlertAction actionWithTitle:@"Enable"
        style:UIAlertActionStyleDefault handler:^(UIAlertAction* action) {
            (void)action;
            [self applyBundle:bundle enabled:YES];
        }]];
    [self presentViewController:confirmation animated:YES completion:nil];
}

@end
