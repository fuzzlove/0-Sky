#import "TSInventoryTableViewController.h"
#import "TSApplicationsManager.h"
#import "TSInlinePreferenceTableViewController.h"
#import "TSCylinderSettingsViewController.h"
#import "TSCraneSettingsViewController.h"
#import "TSSecurityToolkitTableViewController.h"
#import <TSPresentationDelegate.h>
#import <CommonCrypto/CommonDigest.h>
#import <sys/sysctl.h>
#import <sys/stat.h>
@import UniformTypeIdentifiers;

@interface TSInventoryTableViewController ()
@property(nonatomic,strong) NSArray* tweaks;
@property(nonatomic,strong) UIRefreshControl* pullRefresh;
@property(nonatomic,strong) UIBarButtonItem* exportButton;
@property(nonatomic,strong) UIBarButtonItem* removeButton;
@property(nonatomic,strong) UIBarButtonItem* quarantineButton;
@property(nonatomic,strong) NSDictionary* packageHealth;
@property(nonatomic,strong) NSArray* quarantines;
@end

static NSString* const TSTweakSettingsRequestPath = @"/var/mobile/pl/open-tweak-settings.json";
static NSString* const TSQuarantineWarningFingerprintKey =
    @"ZeroSkyControlAcknowledgedQuarantineFingerprint";

static NSString* TSQuarantineFingerprint(NSArray* quarantines)
{
    NSMutableArray<NSString*>* identities = [NSMutableArray array];
    for(NSDictionary* item in quarantines) {
        NSString* package = [item[@"package"] isKindOfClass:NSString.class]
            ? item[@"package"] : @"";
        NSString* target = [item[@"target"] isKindOfClass:NSString.class]
            ? item[@"target"] : @"";
        NSString* dylib = [item[@"dylib"] isKindOfClass:NSString.class]
            ? item[@"dylib"] : @"";
        NSString* stamp = [item[@"time"] isKindOfClass:NSString.class]
            ? item[@"time"] : @"";
        [identities addObject:[NSString stringWithFormat:@"%@|%@|%@|%@",
                               package, target, dylib, stamp]];
    }
    [identities sortUsingSelector:@selector(compare:)];
    NSData* data = [[identities componentsJoinedByString:@"\n"]
        dataUsingEncoding:NSUTF8StringEncoding];
    if(!data.length) return nil;
    unsigned char digest[CC_SHA256_DIGEST_LENGTH];
    CC_SHA256(data.bytes, (CC_LONG)data.length, digest);
    NSMutableString* result = [NSMutableString stringWithCapacity:CC_SHA256_DIGEST_LENGTH * 2];
    for(NSUInteger index = 0; index < CC_SHA256_DIGEST_LENGTH; index++)
        [result appendFormat:@"%02x", digest[index]];
    return result;
}

static NSString* TSDeviceSysctlString(const char* name)
{
    size_t size = 0;
    if(sysctlbyname(name, NULL, &size, NULL, 0) != 0 || size < 2 || size > 256)
        return nil;
    char* bytes = calloc(size, 1);
    if(!bytes) return nil;
    NSString* value = sysctlbyname(name, bytes, &size, NULL, 0) == 0
        ? [NSString stringWithUTF8String:bytes] : nil;
    free(bytes);
    return value;
}

static NSString* TSDoodleInstalledHash(NSString* path)
{
    static NSString* const expectedPath =
        @"/var/jb/Library/MobileSubstrate/DynamicLibraries/Doodle.dylib";
    if(![path isEqualToString:expectedPath]) return nil;
    struct stat info;
    if(lstat(path.fileSystemRepresentation, &info) != 0 ||
       !S_ISREG(info.st_mode) || info.st_size < 1024 || info.st_size > 16 * 1024 * 1024)
        return nil;
    NSData* data = [NSData dataWithContentsOfFile:path options:NSDataReadingMappedIfSafe error:nil];
    if(!data || data.length != (NSUInteger)info.st_size) return nil;
    unsigned char digest[CC_SHA256_DIGEST_LENGTH];
    CC_SHA256(data.bytes, (CC_LONG)data.length, digest);
    NSMutableString* value = [NSMutableString stringWithCapacity:CC_SHA256_DIGEST_LENGTH * 2];
    for(NSUInteger index = 0; index < CC_SHA256_DIGEST_LENGTH; index++)
        [value appendFormat:@"%02x", digest[index]];
    return value;
}

static NSString* TSPreferenceMatchKey(NSString* value)
{
    NSString* key = value.lowercaseString.stringByDeletingPathExtension;
    for(NSString* suffix in @[@"preferences", @"preference", @"prefs", @"settings"])
        if([key hasSuffix:suffix] && key.length > suffix.length)
            key = [key substringToIndex:key.length - suffix.length];
    return key;
}

static NSString* TSPreferenceIconPath(NSDictionary* entry, NSString* descriptorPath)
{
    if(![entry isKindOfClass:NSDictionary.class] || !descriptorPath.length) return nil;
    NSString* icon = [entry[@"icon"] isKindOfClass:NSString.class] ? entry[@"icon"] : nil;
    NSString* bundle = [entry[@"bundle"] isKindOfClass:NSString.class] ? entry[@"bundle"] : nil;
    NSMutableArray<NSString*>* candidates = [NSMutableArray array];
    if(icon.length && icon.isAbsolutePath) [candidates addObject:icon];
    NSString* preferenceRoot = @"/var/jb/Library/PreferenceBundles";
    if(bundle.length && ![bundle containsString:@"/"]) {
        NSString* bundleName = [bundle.pathExtension isEqualToString:@"bundle"]
            ? bundle : [bundle stringByAppendingPathExtension:@"bundle"];
        NSString* bundleRoot = [preferenceRoot stringByAppendingPathComponent:bundleName];
        if(icon.length && !icon.isAbsolutePath)
            [candidates addObject:[bundleRoot stringByAppendingPathComponent:icon]];
        for(NSString* fallback in @[@"Icon@3x.png", @"Icon@2x.png", @"Icon.png",
                                    @"icon@3x.png", @"icon@2x.png", @"icon.png"])
            [candidates addObject:[bundleRoot stringByAppendingPathComponent:fallback]];
    }
    if(icon.length && !icon.isAbsolutePath)
        [candidates addObject:[descriptorPath.stringByDeletingLastPathComponent
            stringByAppendingPathComponent:icon]];
    NSFileManager* files = NSFileManager.defaultManager;
    for(NSString* candidate in candidates) {
        NSString* path = candidate.stringByStandardizingPath;
        BOOL approved = [path hasPrefix:[preferenceRoot stringByAppendingString:@"/"]] ||
            [path hasPrefix:@"/var/jb/Library/PreferenceLoader/"];
        BOOL directory = NO;
        if(approved && [files fileExistsAtPath:path isDirectory:&directory] && !directory)
            return path;
    }
    return nil;
}

@implementation TSInventoryTableViewController

- (NSDictionary*)localPackageMetadata
{
    NSString* contents = [NSString stringWithContentsOfFile:@"/var/jb/Library/dpkg/status"
        encoding:NSUTF8StringEncoding error:nil];
    if(!contents.length) return @{};
    NSMutableDictionary* result = [NSMutableDictionary dictionary];
    for(NSString* stanza in [contents componentsSeparatedByString:@"\n\n"]) {
        NSMutableDictionary* fields = [NSMutableDictionary dictionary];
        for(NSString* line in [stanza componentsSeparatedByCharactersInSet:
             NSCharacterSet.newlineCharacterSet]) {
            NSRange separator = [line rangeOfString:@":"];
            if(separator.location == NSNotFound) continue;
            NSString* key = [line substringToIndex:separator.location];
            NSString* value = [[line substringFromIndex:separator.location + 1]
                stringByTrimmingCharactersInSet:NSCharacterSet.whitespaceCharacterSet];
            if(value.length) fields[key] = value;
        }
        NSString* package = fields[@"Package"];
        if(package.length && [fields[@"Status"] isEqualToString:@"install ok installed"])
            result[package] = fields.copy;
    }
    return result;
}

- (NSDictionary*)localPackageOwners
{
    NSString* root = @"/var/jb/Library/dpkg/info";
    NSArray* files = [[NSFileManager defaultManager] contentsOfDirectoryAtPath:root error:nil];
    NSMutableDictionary* owners = [NSMutableDictionary dictionary];
    for(NSString* file in files) {
        if(![file.pathExtension isEqualToString:@"list"]) continue;
        NSString* package = file.stringByDeletingPathExtension;
        package = [package componentsSeparatedByString:@":"].firstObject;
        NSString* contents = [NSString stringWithContentsOfFile:
            [root stringByAppendingPathComponent:file] encoding:NSUTF8StringEncoding error:nil];
        for(NSString* path in [contents componentsSeparatedByCharactersInSet:
             NSCharacterSet.newlineCharacterSet])
            if([path hasPrefix:@"/"]) owners[path] = package;
    }
    return owners;
}

- (NSArray*)localTweakInventory
{
    NSFileManager* files = NSFileManager.defaultManager;
    NSDictionary* metadata = [self localPackageMetadata];
    NSDictionary* owners = [self localPackageOwners];
    NSMutableDictionary<NSString*, NSMutableArray*>* preferences = [NSMutableDictionary dictionary];
    NSString* preferenceRoot = @"/var/jb/Library/PreferenceLoader/Preferences";
    NSDirectoryEnumerator* preferenceFiles = [files enumeratorAtPath:preferenceRoot];
    for(NSString* relative in preferenceFiles) {
        if(![relative.pathExtension isEqualToString:@"plist"]) continue;
        NSString* path = [preferenceRoot stringByAppendingPathComponent:relative];
        NSDictionary* descriptor = [NSDictionary dictionaryWithContentsOfFile:path];
        NSDictionary* entry = [descriptor[@"entry"] isKindOfClass:NSDictionary.class]
            ? descriptor[@"entry"] : nil;
        NSString* title = [entry[@"label"] isKindOfClass:NSString.class]
            ? entry[@"label"] : nil;
        if(!title.length) continue;
        NSString* package = [owners[path] isKindOfClass:NSString.class] ? owners[path] : nil;
        NSString* key = package.length ? package : TSPreferenceMatchKey(relative.lastPathComponent);
        if(!preferences[key]) preferences[key] = [NSMutableArray array];
        NSMutableDictionary* preference = [@{@"title": title, @"descriptor": path,
            @"converted": @([path containsString:@"/0-Sky-Auto/"])} mutableCopy];
        NSString* iconPath = TSPreferenceIconPath(entry, path);
        if(iconPath.length) preference[@"icon_path"] = iconPath;
        [preferences[key] addObject:preference.copy];
    }
    NSMutableArray* result = [NSMutableArray array];
    NSMutableSet* packagesWithDylibs = [NSMutableSet set];
    NSMutableSet* matchedPreferenceKeys = [NSMutableSet set];
    for(NSString* root in @[@"/var/jb/Library/MobileSubstrate/DynamicLibraries",
                            @"/var/jb/usr/lib/TweakInject"]) {
        for(NSString* filename in [files contentsOfDirectoryAtPath:root error:nil]) {
            if(![filename.pathExtension isEqualToString:@"dylib"]) continue;
            NSString* path = [root stringByAppendingPathComponent:filename];
            NSString* canonical = [path stringByReplacingOccurrencesOfString:
                @"/var/jb/usr/lib/TweakInject/" withString:
                @"/var/jb/Library/MobileSubstrate/DynamicLibraries/"];
            NSString* package = [owners[canonical] isKindOfClass:NSString.class]
                ? owners[canonical] : ([owners[path] isKindOfClass:NSString.class] ? owners[path] : nil);
            NSString* stem = filename.stringByDeletingPathExtension;
            if(!package.length) package = [@"local." stringByAppendingString:stem.lowercaseString];
            NSDictionary* packageInfo = [metadata[package] isKindOfClass:NSDictionary.class]
                ? metadata[package] : @{};
            NSDictionary* sidecar = [NSDictionary dictionaryWithContentsOfFile:
                [[root stringByAppendingPathComponent:stem] stringByAppendingPathExtension:@"plist"]];
            NSDictionary* filter = [sidecar[@"Filter"] isKindOfClass:NSDictionary.class]
                ? sidecar[@"Filter"] : ([sidecar isKindOfClass:NSDictionary.class] ? sidecar : @{});
            NSString* preferenceKey = preferences[package] ? package : TSPreferenceMatchKey(stem);
            NSArray* entries = preferences[preferenceKey] ?: @[];
            if(entries.count) [matchedPreferenceKeys addObject:preferenceKey];
            NSMutableDictionary* row = [@{
                @"package": package, @"dylib": canonical,
                @"name": [packageInfo[@"Name"] isKindOfClass:NSString.class]
                    ? packageInfo[@"Name"] : stem,
                @"bundles": [filter[@"Bundles"] isKindOfClass:NSArray.class]
                    ? filter[@"Bundles"] : @[],
                @"executables": [filter[@"Executables"] isKindOfClass:NSArray.class]
                    ? filter[@"Executables"] : @[],
                @"settings_available": @(entries.count > 0),
                @"preference_entries": entries,
            } mutableCopy];
            if([packageInfo[@"Version"] isKindOfClass:NSString.class])
                row[@"version"] = packageInfo[@"Version"];
            if([packageInfo[@"Description"] isKindOfClass:NSString.class])
                row[@"description"] = packageInfo[@"Description"];
            if(entries.count) row[@"preference_title"] = entries.firstObject[@"title"];
            NSString* iconPath = [entries.firstObject[@"icon_path"] isKindOfClass:NSString.class]
                ? entries.firstObject[@"icon_path"] : nil;
            if(iconPath.length) row[@"icon_path"] = iconPath;
            [result addObject:row.copy];
            [packagesWithDylibs addObject:package];
        }
    }
    for(NSString* key in preferences) {
        if([packagesWithDylibs containsObject:key] || [matchedPreferenceKeys containsObject:key]) continue;
        NSArray* entries = preferences[key];
        NSDictionary* packageInfo = [metadata[key] isKindOfClass:NSDictionary.class]
            ? metadata[key] : @{};
        [result addObject:@{
            @"package": key, @"dylib": @"", @"bundles": @[], @"executables": @[],
            @"name": [packageInfo[@"Name"] isKindOfClass:NSString.class]
                ? packageInfo[@"Name"] : entries.firstObject[@"title"],
            @"settings_available": @YES, @"preference_only": @YES,
            @"preference_title": entries.firstObject[@"title"],
            @"preference_entries": entries,
        }];
    }
    return [result sortedArrayUsingComparator:^NSComparisonResult(NSDictionary* left,
                                                                    NSDictionary* right) {
        NSString* one = [left[@"name"] isKindOfClass:NSString.class] ? left[@"name"] : @"";
        NSString* two = [right[@"name"] isKindOfClass:NSString.class] ? right[@"name"] : @"";
        return [one localizedStandardCompare:two];
    }];
}

- (NSArray*)aggregateTweakInventoryByPackage:(NSArray*)rows
{
    NSMutableDictionary<NSString*, NSMutableDictionary*>* grouped =
        [NSMutableDictionary dictionary];
    for(id raw in rows) {
        if(![raw isKindOfClass:NSDictionary.class]) continue;
        NSDictionary* row = raw;
        NSString* package = [row[@"package"] isKindOfClass:NSString.class]
            ? row[@"package"] : nil;
        if(!package.length) continue;
        NSMutableDictionary* merged = grouped[package];
        if(!merged) {
            merged = row.mutableCopy;
            merged[@"bundles"] = [NSMutableOrderedSet orderedSetWithArray:
                [row[@"bundles"] isKindOfClass:NSArray.class] ? row[@"bundles"] : @[]];
            merged[@"executables"] = [NSMutableOrderedSet orderedSetWithArray:
                [row[@"executables"] isKindOfClass:NSArray.class] ? row[@"executables"] : @[]];
            merged[@"preference_entries"] = [NSMutableArray arrayWithArray:
                [row[@"preference_entries"] isKindOfClass:NSArray.class]
                    ? row[@"preference_entries"] : @[]];
            NSMutableArray* dylibs = [NSMutableArray array];
            if([row[@"dylib"] isKindOfClass:NSString.class] && [row[@"dylib"] length])
                [dylibs addObject:row[@"dylib"]];
            merged[@"dylibs"] = dylibs;
            grouped[package] = merged;
            continue;
        }
        [(NSMutableOrderedSet*)merged[@"bundles"] addObjectsFromArray:
            [row[@"bundles"] isKindOfClass:NSArray.class] ? row[@"bundles"] : @[]];
        [(NSMutableOrderedSet*)merged[@"executables"] addObjectsFromArray:
            [row[@"executables"] isKindOfClass:NSArray.class] ? row[@"executables"] : @[]];
        NSString* dylib = [row[@"dylib"] isKindOfClass:NSString.class] ? row[@"dylib"] : nil;
        if(dylib.length && ![merged[@"dylibs"] containsObject:dylib])
            [merged[@"dylibs"] addObject:dylib];
        NSArray* entries = [row[@"preference_entries"] isKindOfClass:NSArray.class]
            ? row[@"preference_entries"] : @[];
        NSMutableSet* descriptors = [NSMutableSet set];
        for(NSDictionary* entry in merged[@"preference_entries"]) {
            NSString* descriptor = [entry[@"descriptor"] isKindOfClass:NSString.class]
                ? entry[@"descriptor"] : nil;
            if(descriptor.length) [descriptors addObject:descriptor];
        }
        for(NSDictionary* entry in entries) {
            NSString* descriptor = [entry[@"descriptor"] isKindOfClass:NSString.class]
                ? entry[@"descriptor"] : nil;
            if(!descriptor.length || ![descriptors containsObject:descriptor]) {
                [merged[@"preference_entries"] addObject:entry];
                if(descriptor.length) [descriptors addObject:descriptor];
            }
        }
        if([row[@"settings_available"] boolValue]) merged[@"settings_available"] = @YES;
        for(NSString* key in @[@"name", @"version", @"description", @"preference_title",
                                @"icon_path"]) {
            NSString* current = [merged[key] isKindOfClass:NSString.class] ? merged[key] : nil;
            NSString* candidate = [row[key] isKindOfClass:NSString.class] ? row[key] : nil;
            if(!current.length && candidate.length) merged[key] = candidate;
        }
    }
    NSMutableArray* result = [NSMutableArray arrayWithCapacity:grouped.count];
    for(NSMutableDictionary* merged in grouped.allValues) {
        merged[@"bundles"] = [(NSMutableOrderedSet*)merged[@"bundles"] array];
        merged[@"executables"] = [(NSMutableOrderedSet*)merged[@"executables"] array];
        merged[@"component_count"] = @([merged[@"dylibs"] count]);
        [result addObject:merged.copy];
    }
    return [result sortedArrayUsingComparator:^NSComparisonResult(NSDictionary* left,
                                                                    NSDictionary* right) {
        NSString* one = [left[@"name"] isKindOfClass:NSString.class]
            ? left[@"name"] : left[@"package"];
        NSString* two = [right[@"name"] isKindOfClass:NSString.class]
            ? right[@"name"] : right[@"package"];
        return [one localizedStandardCompare:two];
    }];
}

- (instancetype)init
{
    self = [super initWithStyle:UITableViewStyleInsetGrouped];
    if(self) {
        _tweaks = @[];
        _quarantines = @[];
    }
    return self;
}

- (void)viewDidLoad
{
    [super viewDidLoad];
    UIBarButtonItem* addButton = [[UIBarButtonItem alloc]
        initWithBarButtonSystemItem:UIBarButtonSystemItemAdd target:self action:@selector(selectDeb)];
    self.exportButton = [[UIBarButtonItem alloc] initWithTitle:@"Export"
        style:UIBarButtonItemStylePlain target:nil action:nil];
    self.exportButton.enabled = NO;
    self.removeButton = [[UIBarButtonItem alloc]
        initWithImage:[UIImage systemImageNamed:@"trash"]
        style:UIBarButtonItemStylePlain target:nil action:nil];
    self.removeButton.enabled = NO;
    self.removeButton.accessibilityLabel = @"Remove installed tweak";
    self.removeButton.accessibilityIdentifier = @"ZeroSkyControlRemoveTweakMenu";
    self.quarantineButton = [[UIBarButtonItem alloc]
        initWithImage:[UIImage systemImageNamed:@"shield.lefthalf.filled"]
        style:UIBarButtonItemStylePlain target:nil action:nil];
    self.quarantineButton.enabled = NO;
    self.quarantineButton.accessibilityLabel = @"Review quarantined tweaks";
    self.quarantineButton.accessibilityIdentifier = @"ZeroSkyControlQuarantineMenu";
    // Preserve the existing package-import button while making export
    // and removal discoverable. The first item is the trailing button.
    self.navigationItem.rightBarButtonItems =
        @[addButton, self.exportButton, self.quarantineButton, self.removeButton];
    UIBarButtonItem* fixMenus = [[UIBarButtonItem alloc]
        initWithTitle:@"Fix Menus" style:UIBarButtonItemStylePlain
        target:self action:@selector(repairPreferenceMenus)];
    UIBarButtonItem* research = [[UIBarButtonItem alloc]
        initWithTitle:@"Research" style:UIBarButtonItemStylePlain
        target:self action:@selector(openSecurityResearch)];
    self.navigationItem.leftBarButtonItems = @[research, fixMenus];
    self.pullRefresh = [UIRefreshControl new];
    [self.pullRefresh addTarget:self action:@selector(refresh) forControlEvents:UIControlEventValueChanged];
    self.refreshControl = self.pullRefresh;
    [self refresh];
}

- (void)openSecurityResearch
{
    [self.navigationController pushViewController:
        [[TSSecurityToolkitTableViewController alloc]
            initWithCategory:@"Tweaks/Security Research"] animated:YES];
}

- (void)repairPreferenceMenus
{
    self.navigationItem.leftBarButtonItems.lastObject.enabled = NO;
    self.navigationItem.prompt = @"Converting and refreshing tweak preference menus…";
    [TSPresentationDelegate startActivity:@"Fixing preference menus"];
    dispatch_async(dispatch_get_global_queue(QOS_CLASS_USER_INITIATED, 0), ^{
        NSString* log = nil;
        int status = [[TSApplicationsManager sharedInstance]
            repairPreferenceMenusForPackage:nil log:&log];
        dispatch_async(dispatch_get_main_queue(), ^{
            [TSPresentationDelegate stopActivityWithCompletion:^{
                self.navigationItem.leftBarButtonItems.lastObject.enabled = YES;
                self.navigationItem.prompt = status == 0
                    ? @"Preference conversion complete • Tap for settings is refreshed"
                    : [NSString stringWithFormat:@"Preference repair failed (%d): %@",
                       status, log.length ? log : @"No diagnostics returned"];
                [self refresh];
            }];
        });
    });
}

- (void)refresh
{
    dispatch_async(dispatch_get_global_queue(QOS_CLASS_USER_INITIATED, 0), ^{
        NSDictionary* inventory = [[TSApplicationsManager sharedInstance] srdInventory];
        NSError* coreError = nil;
        NSDictionary* envelope = [[TSApplicationsManager sharedInstance]
            coreRequestOperation:@"getPackages" parameters:@{@"limit": @512} error:&coreError];
        NSDictionary* quarantineEnvelope = [[TSApplicationsManager sharedInstance]
            coreRequestOperation:@"getQuarantinedTweaks"
            parameters:@{@"limit": @256} error:nil];
        NSArray* quarantines = [quarantineEnvelope[@"result"][@"quarantines"]
            isKindOfClass:NSArray.class]
            ? quarantineEnvelope[@"result"][@"quarantines"] : @[];
        NSArray* packages = [envelope[@"result"][@"packages"] isKindOfClass:NSArray.class]
            ? envelope[@"result"][@"packages"] : @[];
        NSMutableDictionary* packageHealth = [NSMutableDictionary dictionary];
        for(NSDictionary* row in packages) {
            NSString* identifier = [row[@"package"] isKindOfClass:NSString.class]
                ? row[@"package"] : nil;
            if(identifier.length) packageHealth[identifier] = row;
        }
        NSArray* tweaks = [inventory[@"tweaks"] isKindOfClass:NSArray.class] ? inventory[@"tweaks"] : nil;
        NSArray* localTweaks = [self localTweakInventory];
        if(tweaks.count && localTweaks.count)
            tweaks = [tweaks arrayByAddingObjectsFromArray:localTweaks];
        else if(!tweaks.count)
            tweaks = localTweaks;
        tweaks = [self aggregateTweakInventoryByPackage:tweaks ?: @[]];
        dispatch_async(dispatch_get_main_queue(), ^{
            if(tweaks) self.tweaks = tweaks;
            self.packageHealth = packageHealth;
            self.quarantines = quarantines;
            [self rebuildExportMenu];
            [self rebuildRemovalMenu];
            [self rebuildQuarantineMenu];
            [self.pullRefresh endRefreshing];
            [self.tableView reloadData];
            self.navigationItem.prompt = inventory
                ? [NSString stringWithFormat:@"%lu installed package payloads", (unsigned long)self.tweaks.count]
                : @"Local inventory service unavailable";
            [self presentNewQuarantineWarningIfNeeded];
        });
    });
}

- (BOOL)isProtectedPackage:(NSString*)package
{
    static NSSet<NSString*>* protectedPackages;
    static dispatch_once_t onceToken;
    dispatch_once(&onceToken, ^{
        protectedPackages = [NSSet setWithArray:@[
            @"apt", @"dpkg", @"ellekit", @"preferenceloader", @"sileo",
            @"org.coolstar.sileo", @"com.liquidskysecurity.srd-runtime-manager"
        ]];
    });
    return [protectedPackages containsObject:package.lowercaseString];
}

- (BOOL)isVerifiedDoodlePort:(NSDictionary*)tweak
{
    NSString* package = [tweak[@"package"] isKindOfClass:NSString.class]
        ? tweak[@"package"] : nil;
    if(![package isEqualToString:@"com.nahtedetihw.doodle"]) return NO;
    NSDictionary* installed = [self.packageHealth[package] isKindOfClass:NSDictionary.class]
        ? self.packageHealth[package] : nil;
    NSString* dylibHash = TSDoodleInstalledHash(tweak[@"dylib"]);
    if(![installed[@"version"] isEqualToString:@"1:1.1+0sky27.2"] ||
       [installed[@"quarantinedCount"] integerValue] != 0 ||
       ![dylibHash isEqualToString:
           @"64eae513d7a96e691ba177660141fcaa26327d0b3b5f862338584b28f7522086"])
        return NO;
    NSUserDefaults* defaults = [[NSUserDefaults alloc]
        initWithSuiteName:@"com.0sky.doodle-uat"];
    [defaults synchronize];
    NSDictionary* receipt = [defaults persistentDomainForName:@"com.0sky.doodle-uat"];
    if(![receipt isKindOfClass:NSDictionary.class] ||
       [receipt[@"schema"] integerValue] != 1 ||
       ![receipt[@"package_version"] isEqualToString:installed[@"version"]] ||
       ![receipt[@"dylib_sha256"] isEqualToString:dylibHash] ||
       ![receipt[@"ios_build"] isEqualToString:TSDeviceSysctlString("kern.osversion")] ||
       ![receipt[@"device_model"] isEqualToString:TSDeviceSysctlString("hw.machine")])
        return NO;
    for(NSString* check in @[@"native_authentication", @"pattern_unlock",
                            @"wrong_pattern_rejected", @"keypad_fallback",
                            @"repeat_pattern_unlock", @"springboard_stable"])
        if(![receipt[check] isEqual:@YES]) return NO;
    return YES;
}

- (NSString*)displayTitleForTweak:(NSDictionary*)tweak
{
    NSString* package = [tweak[@"package"] isKindOfClass:NSString.class]
        ? tweak[@"package"] : @"Unknown package";
    NSString* title = [tweak[@"preference_title"] isKindOfClass:NSString.class]
        ? tweak[@"preference_title"] : nil;
    if(!title.length) {
        NSString* dylib = [tweak[@"dylib"] isKindOfClass:NSString.class]
            ? [tweak[@"dylib"] lastPathComponent].stringByDeletingPathExtension : nil;
        title = dylib.length ? dylib : package;
    }
    return title;
}

- (NSString*)displayNameForPackage:(NSString*)package
{
    for(NSDictionary* tweak in self.tweaks) {
        if([tweak[@"package"] isEqualToString:package])
            return [self displayTitleForTweak:tweak];
    }
    return package.length ? package : @"Unknown tweak";
}

- (void)retryQuarantine:(NSDictionary*)item
{
    NSString* package = [item[@"package"] isKindOfClass:NSString.class]
        ? item[@"package"] : nil;
    NSString* target = [item[@"target"] isKindOfClass:NSString.class]
        ? item[@"target"] : nil;
    if(!package.length || !target.length || [self isProtectedPackage:package]) return;
    self.quarantineButton.enabled = NO;
    self.navigationItem.prompt = [NSString stringWithFormat:@"Retrying %@…", package];
    [TSPresentationDelegate startActivity:@"Retrying quarantined tweak"];
    dispatch_async(dispatch_get_global_queue(QOS_CLASS_USER_INITIATED, 0), ^{
        NSError* error = nil;
        NSDictionary* envelope = [[TSApplicationsManager sharedInstance]
            coreRequestOperation:@"clearTweakQuarantine"
            parameters:@{@"package": package, @"target": target} error:&error];
        BOOL success = [envelope[@"success"] boolValue];
        NSString* message = success
            ? (envelope[@"result"][@"message"] ?: @"The retry was queued.")
            : (error.localizedDescription ?: envelope[@"errorMessage"] ?:
               @"The quarantine state changed before it could be retried.");
        dispatch_async(dispatch_get_main_queue(), ^{
            [TSPresentationDelegate stopActivityWithCompletion:^{
                self.navigationItem.prompt = success
                    ? @"Retry queued • runtime protection remains active"
                    : @"Tweak retry failed";
                [self showTitle:success ? @"Retry queued" : @"Retry failed"
                    message:message];
                dispatch_after(dispatch_time(DISPATCH_TIME_NOW,
                    (int64_t)(1.0 * NSEC_PER_SEC)), dispatch_get_main_queue(), ^{
                    [self refresh];
                });
            }];
        });
    });
}

- (void)presentQuarantineDetail:(NSDictionary*)item
{
    NSString* package = [item[@"package"] isKindOfClass:NSString.class]
        ? item[@"package"] : @"Unknown package";
    NSString* target = [item[@"target"] isKindOfClass:NSString.class]
        ? item[@"target"] : @"Unknown process";
    NSString* reason = [item[@"reason"] isKindOfClass:NSString.class]
        ? item[@"reason"] : @"The runtime stopped this tweak after a failed load.";
    NSString* dylib = [item[@"dylib"] isKindOfClass:NSString.class]
        ? item[@"dylib"] : @"Unknown component";
    NSString* name = [self displayNameForPackage:package];
    BOOL protected = [self isProtectedPackage:package];
    NSString* message = [NSString stringWithFormat:
        @"0-Sky quarantined %@ to protect the device.\n\n"
         @"Package: %@\nTarget: %@\nComponent: %@\nReason: %@\n\n"
         @"Retrying may destabilize the affected process. If it fails again, "
         @"runtime protection will quarantine it again.%@",
        name, package, target, dylib, reason,
        protected ? @"\n\nThis foundational package must be repaired from the paired Mac." : @""];
    UIAlertController* alert = [UIAlertController alertControllerWithTitle:@"Tweak quarantined"
        message:message preferredStyle:UIAlertControllerStyleAlert];
    [alert addAction:[UIAlertAction actionWithTitle:@"Cancel"
        style:UIAlertActionStyleCancel handler:nil]];
    if(!protected) {
        [alert addAction:[UIAlertAction actionWithTitle:@"Remove Tweak"
            style:UIAlertActionStyleDestructive handler:^(UIAlertAction* action) {
                (void)action;
                dispatch_async(dispatch_get_main_queue(), ^{
                    [self confirmRemovalOfPackage:package displayName:name];
                });
            }]];
        [alert addAction:[UIAlertAction actionWithTitle:@"Retry Tweak"
            style:UIAlertActionStyleDefault handler:^(UIAlertAction* action) {
                (void)action;
                [self retryQuarantine:item];
            }]];
    }
    [self presentViewController:alert animated:YES completion:nil];
}

- (void)presentQuarantineChooser
{
    if(!self.quarantines.count) return;
    if(self.quarantines.count == 1) {
        [self presentQuarantineDetail:self.quarantines.firstObject];
        return;
    }
    UIAlertController* chooser = [UIAlertController alertControllerWithTitle:@"Quarantined Tweaks"
        message:@"Choose a protected process to review, retry, or remove its tweak."
        preferredStyle:UIAlertControllerStyleActionSheet];
    for(NSDictionary* item in self.quarantines) {
        NSString* package = [item[@"package"] isKindOfClass:NSString.class]
            ? item[@"package"] : @"Unknown package";
        NSString* target = [item[@"target"] isKindOfClass:NSString.class]
            ? item[@"target"] : @"Unknown process";
        NSString* title = [NSString stringWithFormat:@"%@ — %@",
                           [self displayNameForPackage:package], target];
        [chooser addAction:[UIAlertAction actionWithTitle:title
            style:UIAlertActionStyleDefault handler:^(UIAlertAction* action) {
                (void)action;
                dispatch_async(dispatch_get_main_queue(), ^{
                    [self presentQuarantineDetail:item];
                });
            }]];
    }
    [chooser addAction:[UIAlertAction actionWithTitle:@"Cancel"
        style:UIAlertActionStyleCancel handler:nil]];
    chooser.popoverPresentationController.sourceView = self.view;
    chooser.popoverPresentationController.sourceRect = CGRectMake(
        CGRectGetMidX(self.view.bounds), CGRectGetMinY(self.view.bounds), 1, 1);
    [self presentViewController:chooser animated:YES completion:nil];
}

- (void)rebuildQuarantineMenu
{
    NSMutableArray<UIMenuElement*>* actions = [NSMutableArray array];
    for(NSDictionary* item in self.quarantines) {
        NSString* package = [item[@"package"] isKindOfClass:NSString.class]
            ? item[@"package"] : nil;
        NSString* target = [item[@"target"] isKindOfClass:NSString.class]
            ? item[@"target"] : nil;
        if(!package.length || !target.length) continue;
        NSString* title = [NSString stringWithFormat:@"%@ — %@",
                           [self displayNameForPackage:package], target];
        UIAction* action = [UIAction actionWithTitle:title
            image:[UIImage systemImageNamed:[self isProtectedPackage:package]
                ? @"lock.shield" : @"shield.slash"] identifier:nil
            handler:^(__kindof UIAction* selectedAction) {
                (void)selectedAction;
                [self presentQuarantineDetail:item];
            }];
        if(@available(iOS 15.0, *)) {
            NSString* reason = [item[@"reason"] isKindOfClass:NSString.class]
                ? item[@"reason"] : @"Protected after a failed load";
            action.subtitle = reason;
        }
        [actions addObject:action];
    }
    self.quarantineButton.menu = [UIMenu menuWithTitle:
        @"Quarantined tweaks are disabled automatically after failed runtime loads."
        children:actions];
    self.quarantineButton.enabled = actions.count > 0;
    self.quarantineButton.tintColor = actions.count > 0
        ? UIColor.systemOrangeColor : nil;
}

- (void)presentNewQuarantineWarningIfNeeded
{
    NSUserDefaults* defaults = NSUserDefaults.standardUserDefaults;
    NSString* fingerprint = TSQuarantineFingerprint(self.quarantines);
    if(!fingerprint.length) {
        [defaults removeObjectForKey:TSQuarantineWarningFingerprintKey];
        return;
    }
    if([[defaults stringForKey:TSQuarantineWarningFingerprintKey]
        isEqualToString:fingerprint] || self.presentedViewController) return;
    NSMutableOrderedSet<NSString*>* names = [NSMutableOrderedSet orderedSet];
    for(NSDictionary* item in self.quarantines) {
        NSString* package = [item[@"package"] isKindOfClass:NSString.class]
            ? item[@"package"] : nil;
        if(package.length) [names addObject:[self displayNameForPackage:package]];
    }
    NSArray* visible = names.array.count > 5
        ? [names.array subarrayWithRange:NSMakeRange(0, 5)] : names.array;
    NSString* list = [visible componentsJoinedByString:@", "];
    NSString* more = names.count > visible.count
        ? [NSString stringWithFormat:@" and %lu more",
           (unsigned long)(names.count - visible.count)] : @"";
    NSString* message = [NSString stringWithFormat:
        @"0-Sky placed %@%@ in quarantine after a failed runtime load to protect the device. "
         @"The tweak remains installed but disabled for the affected process.\n\n"
         @"Review it to retry or remove the incompatible tweak.", list, more];
    UIAlertController* alert = [UIAlertController alertControllerWithTitle:
        @"Tweak protection activated" message:message
        preferredStyle:UIAlertControllerStyleAlert];
    [alert addAction:[UIAlertAction actionWithTitle:@"Later"
        style:UIAlertActionStyleCancel handler:nil]];
    [alert addAction:[UIAlertAction actionWithTitle:@"Review Quarantine"
        style:UIAlertActionStyleDefault handler:^(UIAlertAction* action) {
            (void)action;
            dispatch_async(dispatch_get_main_queue(), ^{
                [self presentQuarantineChooser];
            });
        }]];
    [defaults setObject:fingerprint forKey:TSQuarantineWarningFingerprintKey];
    [self presentViewController:alert animated:YES completion:nil];
}

- (void)rebuildRemovalMenu
{
    NSMutableArray<UIMenuElement*>* actions = [NSMutableArray array];
    NSMutableSet<NSString*>* includedPackages = [NSMutableSet set];
    for(NSDictionary* tweak in self.tweaks) {
        NSString* package = [tweak[@"package"] isKindOfClass:NSString.class]
            ? tweak[@"package"] : nil;
        if(!package.length || [includedPackages containsObject:package] ||
           [self isProtectedPackage:package]) continue;
        [includedPackages addObject:package];
        NSString* title = [self displayTitleForTweak:tweak];
        UIAction* action = [UIAction actionWithTitle:title
            image:[UIImage systemImageNamed:@"trash"] identifier:nil
            handler:^(__kindof UIAction* selectedAction) {
                (void)selectedAction;
                [self confirmRemovalOfPackage:package displayName:title];
            }];
        action.attributes = UIMenuElementAttributesDestructive;
        if(@available(iOS 15.0, *)) action.subtitle = package;
        [actions addObject:action];
    }
    self.removeButton.menu = [UIMenu menuWithTitle:
        @"Choose a tweak package to remove. Core package-management and runtime packages are protected."
        children:actions];
    self.removeButton.enabled = actions.count > 0;
}

- (NSString*)boundedRemovalMessage:(NSString*)log status:(int)status
{
    NSString* message = log.length ? log : [NSString stringWithFormat:@"Status %d", status];
    const NSUInteger limit = 4000;
    if(message.length > limit) {
        message = [@"…\n" stringByAppendingString:
            [message substringFromIndex:message.length - limit]];
    }
    return message;
}

- (void)confirmRemovalOfPackage:(NSString*)package displayName:(NSString*)displayName
{
    if(!package.length || [self isProtectedPackage:package]) {
        [self showTitle:@"Protected package"
            message:@"0-Sky Control cannot remove this foundational runtime package."];
        return;
    }
    NSString* message = [NSString stringWithFormat:
        @"Remove %@ (%@) from this device?\n\n"
         @"The package-owned tweak and preference menu will be removed. "
         @"0-Sky Control will then refresh the SRD runtime and safely restart affected apps. "
         @"The package's saved preference values may remain.",
        displayName.length ? displayName : package, package];
    UIAlertController* alert = [UIAlertController alertControllerWithTitle:@"Remove tweak?"
        message:message preferredStyle:UIAlertControllerStyleAlert];
    [alert addAction:[UIAlertAction actionWithTitle:@"Cancel"
        style:UIAlertActionStyleCancel handler:nil]];
    [alert addAction:[UIAlertAction actionWithTitle:@"Remove Tweak"
        style:UIAlertActionStyleDestructive handler:^(UIAlertAction* action) {
            (void)action;
            self.removeButton.enabled = NO;
            self.navigationItem.prompt = [NSString stringWithFormat:@"Removing %@…", package];
            [TSPresentationDelegate startActivity:@"Removing tweak package"];
            dispatch_async(dispatch_get_global_queue(QOS_CLASS_USER_INITIATED, 0), ^{
                NSString* log = nil;
                int status = [[TSApplicationsManager sharedInstance]
                    removeTweakPackage:package log:&log];
                dispatch_async(dispatch_get_main_queue(), ^{
                    [TSPresentationDelegate stopActivityWithCompletion:^{
                        self.navigationItem.prompt = status == 0
                            ? [NSString stringWithFormat:@"%@ removed", package]
                            : [NSString stringWithFormat:@"Removal failed (%d)", status];
                        [self showTitle:status == 0 ? @"Tweak removed" : @"Removal failed"
                            message:[self boundedRemovalMessage:log status:status]];
                        [self refresh];
                    }];
                });
            });
        }]];
    [self presentViewController:alert animated:YES completion:nil];
}

- (void)rebuildExportMenu
{
    NSMutableArray<UIMenuElement*>* packageActions = [NSMutableArray array];
    for(NSDictionary* tweak in self.tweaks) {
        NSString* package = [tweak[@"package"] isKindOfClass:NSString.class]
            ? tweak[@"package"] : nil;
        if(!package.length) continue;
        NSString* title = [tweak[@"preference_title"] isKindOfClass:NSString.class]
            ? tweak[@"preference_title"] : nil;
        if(!title.length) {
            NSString* dylib = [tweak[@"dylib"] isKindOfClass:NSString.class]
                ? [tweak[@"dylib"] lastPathComponent].stringByDeletingPathExtension : nil;
            title = dylib.length ? dylib : package;
        }
        BOOL hasSettings = [tweak[@"settings_available"] boolValue];
        UIImage* icon = [UIImage systemImageNamed:hasSettings ? @"gearshape.2" : @"shippingbox"];
        UIAction* action = [UIAction actionWithTitle:title image:icon identifier:nil
            handler:^(__kindof UIAction* selectedAction) {
                (void)selectedAction;
                NSUInteger row = [self.tweaks indexOfObjectPassingTest:
                    ^BOOL(NSDictionary* candidate, NSUInteger index, BOOL* stop) {
                        (void)index;
                        NSString* candidatePackage = [candidate[@"package"] isKindOfClass:NSString.class]
                            ? candidate[@"package"] : nil;
                        BOOL match = [candidatePackage isEqualToString:package];
                        if(match) *stop = YES;
                        return match;
                    }];
                if(row == NSNotFound) {
                    self.navigationItem.prompt = @"Refresh the tweak list before exporting.";
                    return;
                }
                [self exportDebForRowAtIndexPath:[NSIndexPath indexPathForRow:row inSection:0]];
            }];
        if(@available(iOS 15.0, *)) {
            action.subtitle = hasSettings
                ? [NSString stringWithFormat:@"%@ • includes settings menu", package]
                : [NSString stringWithFormat:@"%@ • package payload", package];
        }
        [packageActions addObject:action];
    }

    UIMenu* menu = [UIMenu menuWithTitle:
        @"Exported DEBs include package-owned PreferenceLoader descriptors and bundles. Personal setting values are not exported."
        children:packageActions];
    self.exportButton.menu = menu;
    self.exportButton.enabled = packageActions.count > 0;
    self.exportButton.accessibilityLabel = @"Export tweak package with settings menu";
}

- (void)selectDeb
{
    UTType* deb = [UTType typeWithFilenameExtension:@"deb" conformingToType:UTTypeData];
    UIDocumentPickerViewController* picker = [[UIDocumentPickerViewController alloc]
        initForOpeningContentTypes:@[deb]];
    picker.delegate = self;
    picker.allowsMultipleSelection = NO;
    [self presentViewController:picker animated:YES completion:nil];
}

- (void)documentPicker:(UIDocumentPickerViewController*)controller didPickDocumentsAtURLs:(NSArray<NSURL*>*)urls
{
    NSURL* source = urls.firstObject;
    if(!source) return;
    BOOL scoped = [source startAccessingSecurityScopedResource];
    NSURL* staged = [[NSURL fileURLWithPath:NSTemporaryDirectory() isDirectory:YES]
        URLByAppendingPathComponent:[NSUUID.UUID.UUIDString stringByAppendingPathExtension:@"deb"]];
    NSError* copyError = nil;
    BOOL copied = [[NSFileManager defaultManager] copyItemAtURL:source toURL:staged error:&copyError];
    if(scoped) [source stopAccessingSecurityScopedResource];
    if(!copied) { [self showTitle:@"Import failed" message:copyError.localizedDescription]; return; }
    [TSPresentationDelegate startActivity:@"Installing package"];
    dispatch_async(dispatch_get_global_queue(QOS_CLASS_USER_INITIATED, 0), ^{
        NSString* log = nil;
        int status = [[TSApplicationsManager sharedInstance] installDeb:staged.path log:&log];
        [[NSFileManager defaultManager] removeItemAtURL:staged error:nil];
        dispatch_async(dispatch_get_main_queue(), ^{
            [TSPresentationDelegate stopActivityWithCompletion:^{
                self.navigationItem.prompt = status == 0
                    ? @"Package installed • preferences converted • Tap for settings refreshed"
                    : [NSString stringWithFormat:@"Install failed (%d): %@", status,
                       log.length ? log : @"No diagnostic output was returned."];
                [self refresh];
            }];
        });
    });
}

- (void)showTitle:(NSString*)title message:(NSString*)message
{
    UIAlertController* alert = [UIAlertController alertControllerWithTitle:title message:message
        preferredStyle:UIAlertControllerStyleAlert];
    [alert addAction:[UIAlertAction actionWithTitle:@"Close" style:UIAlertActionStyleDefault handler:nil]];
    [self presentViewController:alert animated:YES completion:nil];
}

- (void)exportDebForRowAtIndexPath:(NSIndexPath*)indexPath
{
    if(indexPath.row >= self.tweaks.count) return;
    NSDictionary* tweak = self.tweaks[indexPath.row];
    NSString* package = [tweak[@"package"] isKindOfClass:NSString.class]
        ? tweak[@"package"] : nil;
    if(!package.length) {
        self.navigationItem.prompt = @"This row has no package identity to export.";
        return;
    }
    NSCharacterSet* invalidFilenameCharacters = [[NSCharacterSet
        characterSetWithCharactersInString:
        @"abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-_."] invertedSet];
    NSString* safePackage = [[package componentsSeparatedByCharactersInSet:
        invalidFilenameCharacters] componentsJoinedByString:@"-"];
    NSString* filename = [safePackage stringByAppendingPathExtension:@"deb"];
    // Foundation returns different NSDocumentDirectory values depending on
    // whether 0-Sky Control is currently user- or system-registered. Use the
    // stable, broker-approved export container so renewal cannot make an
    // otherwise valid export fail with "outside an approved container".
    NSString* directory = @"/var/mobile/Documents/Commissary Exports";
    [[NSFileManager defaultManager] createDirectoryAtPath:directory
        withIntermediateDirectories:YES attributes:nil error:nil];
    NSString* destination = [directory stringByAppendingPathComponent:filename];
    [[NSFileManager defaultManager] removeItemAtPath:destination error:nil];
    BOOL hasSettings = [tweak[@"settings_available"] boolValue];
    self.navigationItem.prompt = [NSString stringWithFormat:@"Exporting %@%@…", package,
        hasSettings ? @" with its settings menu" : @""];
    dispatch_async(dispatch_get_global_queue(QOS_CLASS_USER_INITIATED, 0), ^{
        NSString* log = nil;
        int result = [[TSApplicationsManager sharedInstance]
            exportPackage:package toDeb:destination log:&log];
        dispatch_async(dispatch_get_main_queue(), ^{
            if(result != 0 || ![[NSFileManager defaultManager] fileExistsAtPath:destination]) {
                self.navigationItem.prompt = [NSString stringWithFormat:@"Export failed: %@",
                    log.length ? log : [NSString stringWithFormat:@"status %d", result]];
                return;
            }
            self.navigationItem.prompt = [NSString stringWithFormat:
                hasSettings ? @"%@ and its settings menu are ready to save or share."
                            : @"%@ is ready to save or share.", filename];
            UIActivityViewController* share = [[UIActivityViewController alloc]
                initWithActivityItems:@[[NSURL fileURLWithPath:destination]] applicationActivities:nil];
            share.popoverPresentationController.sourceView = self.tableView;
            share.popoverPresentationController.sourceRect =
                [self.tableView rectForRowAtIndexPath:indexPath];
            share.completionWithItemsHandler = ^(UIActivityType activityType,
                BOOL completed, NSArray* returnedItems, NSError* error) {
                (void)activityType; (void)completed; (void)returnedItems; (void)error;
                [[NSFileManager defaultManager] removeItemAtPath:destination error:nil];
                self.navigationItem.prompt = nil;
            };
            [TSPresentationDelegate presentViewController:share animated:YES completion:nil];
        });
    });
}

- (NSInteger)tableView:(UITableView*)tableView numberOfRowsInSection:(NSInteger)section
{ return self.tweaks.count; }

- (UITableViewCell*)tableView:(UITableView*)tableView cellForRowAtIndexPath:(NSIndexPath*)indexPath
{
    UITableViewCell* cell = [tableView dequeueReusableCellWithIdentifier:@"TweakCell"];
    if(!cell) cell = [[UITableViewCell alloc] initWithStyle:UITableViewCellStyleSubtitle
        reuseIdentifier:@"TweakCell"];
    NSDictionary* tweak = self.tweaks[indexPath.row];
    NSString* package = [tweak[@"package"] isKindOfClass:NSString.class] ? tweak[@"package"] : @"Unknown package";
    NSString* dylibPath = [tweak[@"dylib"] isKindOfClass:NSString.class] ? tweak[@"dylib"] : nil;
    NSString* dylib = dylibPath.lastPathComponent.stringByDeletingPathExtension;
    if(!dylib.length) dylib = @"Tweak";
    NSString* packageName = [tweak[@"name"] isKindOfClass:NSString.class] ? tweak[@"name"] : nil;
    NSString* packageVersion = [tweak[@"version"] isKindOfClass:NSString.class] ? tweak[@"version"] : nil;
    NSString* packageDescription = [tweak[@"description"] isKindOfClass:NSString.class]
        ? tweak[@"description"] : nil;
    NSArray* bundles = [tweak[@"bundles"] isKindOfClass:NSArray.class] ? tweak[@"bundles"] : @[];
    NSArray* executables = [tweak[@"executables"] isKindOfClass:NSArray.class] ? tweak[@"executables"] : @[];
    BOOL doodle = [package isEqualToString:@"com.nahtedetihw.doodle"];
    NSString* preferenceTitle = [tweak[@"preference_title"] isKindOfClass:NSString.class]
        ? tweak[@"preference_title"] : nil;
    if(doodle) preferenceTitle = @"Doodle";
    BOOL settingsAvailable = [tweak[@"settings_available"] boolValue] && preferenceTitle.length;
    BOOL preferenceOnly = [tweak[@"preference_only"] boolValue];
    NSArray* preferenceEntries = [tweak[@"preference_entries"] isKindOfClass:NSArray.class]
        ? tweak[@"preference_entries"] : @[];
    NSString* descriptor = [preferenceEntries.firstObject[@"descriptor"] isKindOfClass:NSString.class]
        ? preferenceEntries.firstObject[@"descriptor"] : nil;
    if(doodle) {
        descriptor = [NSBundle.mainBundle pathForResource:@"DoodleControl" ofType:@"plist"];
        settingsAvailable = descriptor.length > 0;
    }
    BOOL inlineSettings = [TSInlinePreferenceTableViewController canOpenDescriptorAtPath:descriptor];
    BOOL cylinderSettings = [TSCylinderSettingsViewController supportsPackage:package
        descriptorPath:descriptor];
    BOOL converted = preferenceEntries.count && [preferenceEntries.firstObject[@"converted"] boolValue];
    cell.textLabel.text = preferenceTitle.length ? preferenceTitle
        : (packageName.length ? packageName : dylib);
    NSMutableArray* filters = [NSMutableArray arrayWithArray:bundles];
    [filters addObjectsFromArray:executables];
    NSString* targetDescription = preferenceOnly ? @"preference-only menu" :
        (filters.count ? [filters componentsJoinedByString:@", "] : @"no process filter");
    NSString* health = [self.packageHealth[package][@"health"] isKindOfClass:NSString.class]
        ? self.packageHealth[package][@"health"] : @"Unknown";
    NSString* runtimeState = [self.packageHealth[package][@"runtimeState"] isKindOfClass:NSString.class]
        ? self.packageHealth[package][@"runtimeState"] : nil;
    NSNumber* quarantinedCount = [self.packageHealth[package][@"quarantinedCount"]
        isKindOfClass:NSNumber.class] ? self.packageHealth[package][@"quarantinedCount"] : nil;
    if(quarantinedCount.integerValue > 0)
        health = @"QUARANTINED FOR SAFETY • use the shield menu to retry or remove";
    else if(doodle && NSProcessInfo.processInfo.operatingSystemVersion.majorVersion >= 27)
        health = [self isVerifiedDoodlePort:tweak]
            ? @"VERIFIED on this device • pattern and keypad UAT passed"
            : [self.packageHealth[package][@"version"] isEqualToString:@"1:1.1+0sky27.2"]
                ? @"UNVERIFIED iOS 27 port • lock-screen test pending"
                : @"ADAPTATION REQUIRED on iOS 27 • original build";
    else if([runtimeState isEqualToString:@"PASS"])
        health = @"READY • required runtime components loaded";
    else if([runtimeState isEqualToString:@"FAILED"])
        health = @"RUNTIME FAILED • inspect quarantine evidence";
    else if([runtimeState isEqualToString:@"DEGRADED"])
        health = @"DEGRADED • only part of the required runtime is loaded";
    else if([health isEqualToString:@"Healthy"])
        health = @"Installed • runtime unverified";
    NSNumber* recentCrashCount = [self.packageHealth[package][@"recentCrashCount"]
        isKindOfClass:NSNumber.class] ? self.packageHealth[package][@"recentCrashCount"] : nil;
    if(recentCrashCount.integerValue > 0)
        health = [health stringByAppendingFormat:@" • %@ recent crash report%@ retained",
            recentCrashCount, recentCrashCount.integerValue == 1 ? @"" : @"s"];
    NSMutableArray<NSString*>* details = [NSMutableArray array];
    [details addObject:package];
    if(packageVersion.length) [details addObject:packageVersion];
    [details addObject:health];
    [details addObject:targetDescription];
    if(packageDescription.length) [details addObject:packageDescription];
    cell.detailTextLabel.text = [NSString stringWithFormat:@"%@%@%@",
        [details componentsJoinedByString:@" • "], converted ? @" • converted for iOS 27" : @"",
        settingsAvailable ? ((inlineSettings || cylinderSettings)
            ? @" • Settings in 0-Sky Control" : @" • Tap for settings") : @""];
    cell.detailTextLabel.numberOfLines = 3;
    NSString* iconPath = [tweak[@"icon_path"] isKindOfClass:NSString.class]
        ? tweak[@"icon_path"] : nil;
    UIImage* packageIcon = iconPath.length ? [UIImage imageWithContentsOfFile:iconPath] : nil;
    NSString* symbol = preferenceOnly ? @"slider.horizontal.3"
        : (settingsAvailable ? @"gearshape.2.fill" : @"puzzlepiece.extension.fill");
    cell.imageView.image = packageIcon ?: [UIImage systemImageNamed:symbol];
    cell.imageView.tintColor = packageIcon ? nil : UIColor.systemBlueColor;
    cell.imageView.layer.cornerRadius = 8;
    cell.imageView.layer.masksToBounds = YES;
    cell.accessoryType = settingsAvailable ? UITableViewCellAccessoryDisclosureIndicator
                                           : UITableViewCellAccessoryNone;
    cell.selectionStyle = settingsAvailable ? UITableViewCellSelectionStyleDefault
                                             : UITableViewCellSelectionStyleNone;
    return cell;
}

- (void)showPackageDetails:(NSString*)package
{
    if(!package.length) return;
    self.navigationItem.prompt = [NSString stringWithFormat:@"Reading %@ details…", package];
    dispatch_async(dispatch_get_global_queue(QOS_CLASS_UTILITY, 0), ^{
        NSError* error = nil;
        NSDictionary* envelope = [[TSApplicationsManager sharedInstance]
            coreRequestOperation:@"getPackageDetail" parameters:@{@"package": package} error:&error];
        NSDictionary* detail = [envelope[@"result"][@"package"] isKindOfClass:NSDictionary.class]
            ? envelope[@"result"][@"package"] : nil;
        dispatch_async(dispatch_get_main_queue(), ^{
            self.navigationItem.prompt = nil;
            if(!detail) {
                [self showTitle:@"Package details unavailable"
                    message:error.localizedDescription ?: @"The package is no longer installed."];
                return;
            }
            NSArray* dependencies = [detail[@"dependencies"] isKindOfClass:NSArray.class]
                ? detail[@"dependencies"] : @[];
            NSString* packageState = [detail[@"health"] isKindOfClass:NSString.class]
                ? detail[@"health"] : @"Unknown";
            if([package isEqualToString:@"com.nahtedetihw.doodle"] &&
               NSProcessInfo.processInfo.operatingSystemVersion.majorVersion >= 27)
                packageState = [detail[@"version"] isEqualToString:@"1:1.1+0sky27.2"]
                    ? @"Private iOS 27 port; inspect Doodle settings for local UAT status"
                    : @"ADAPTATION REQUIRED on iOS 27; original build";
            else if([packageState isEqualToString:@"Healthy"])
                packageState = @"No known package fault; runtime unverified";
            NSString* message = [NSString stringWithFormat:
                @"Version: %@\nArchitecture: %@\nPackage state: %@\nFiles: %@%@\nServices: %@\nTweaks: %@\nQuarantined: %@\nDependency groups: %@",
                detail[@"version"] ?: @"Unknown", detail[@"architecture"] ?: @"Unknown",
                packageState, detail[@"fileCount"] ?: @0,
                [detail[@"filesTruncated"] boolValue] ? @"+" : @"",
                detail[@"serviceCount"] ?: @0, detail[@"tweakCount"] ?: @0,
                detail[@"quarantinedCount"] ?: @0, @(dependencies.count)];
            [self showTitle:detail[@"name"] ?: package message:message];
        });
    });
}

- (void)tableView:(UITableView*)tableView didSelectRowAtIndexPath:(NSIndexPath*)indexPath
{
    [tableView deselectRowAtIndexPath:indexPath animated:YES];
    NSDictionary* tweak = self.tweaks[indexPath.row];
    NSString* package = [tweak[@"package"] isKindOfClass:NSString.class] ? tweak[@"package"] : @"";
    BOOL doodle = [package isEqualToString:@"com.nahtedetihw.doodle"];
    NSString* title = [tweak[@"preference_title"] isKindOfClass:NSString.class]
        ? tweak[@"preference_title"] : nil;
    if(doodle) title = @"Doodle";
    if((![tweak[@"settings_available"] boolValue] && !doodle) || !title.length) {
        self.navigationItem.prompt = @"This package does not publish a PreferenceLoader pane.";
        return;
    }

    NSArray* preferenceEntries = [tweak[@"preference_entries"] isKindOfClass:NSArray.class]
        ? tweak[@"preference_entries"] : @[];
    NSString* descriptor = [preferenceEntries.firstObject[@"descriptor"] isKindOfClass:NSString.class]
        ? preferenceEntries.firstObject[@"descriptor"] : nil;
    if(doodle) descriptor = [NSBundle.mainBundle pathForResource:@"DoodleControl" ofType:@"plist"];
    if([package isEqualToString:@"com.opa334.crane"]) {
        [self.navigationController pushViewController:
            [[TSCraneSettingsViewController alloc] initWithDescriptorPath:descriptor]
            animated:YES];
        self.navigationItem.prompt = nil;
        return;
    }
    if([TSCylinderSettingsViewController supportsPackage:package descriptorPath:descriptor]) {
        TSCylinderSettingsViewController* controller =
            [[TSCylinderSettingsViewController alloc] initWithTitle:title];
        [self.navigationController pushViewController:controller animated:YES];
        self.navigationItem.prompt = nil;
        return;
    }
    if([TSInlinePreferenceTableViewController canOpenDescriptorAtPath:descriptor]) {
        TSInlinePreferenceTableViewController* controller =
            [[TSInlinePreferenceTableViewController alloc] initWithDescriptorPath:descriptor title:title];
        if(doodle) controller.doodlePortVerified = [self isVerifiedDoodlePort:tweak];
        [self.navigationController pushViewController:controller animated:YES];
        self.navigationItem.prompt = nil;
        return;
    }
    NSDictionary* request = @{
        @"schema": @1,
        @"title": title,
        @"package": package,
        @"token": NSUUID.UUID.UUIDString,
        @"created_at": @([NSDate.date timeIntervalSince1970]),
    };
    NSError* error = nil;
    NSData* data = [NSJSONSerialization dataWithJSONObject:request options:0 error:&error];
    NSURL* destination = [NSURL fileURLWithPath:TSTweakSettingsRequestPath];
    [[NSFileManager defaultManager] createDirectoryAtPath:destination.URLByDeletingLastPathComponent.path
                              withIntermediateDirectories:YES attributes:nil error:&error];
    if(!data || error || ![data writeToURL:destination options:NSDataWritingAtomic error:&error]) {
        self.navigationItem.prompt = [NSString stringWithFormat:@"Could not hand %@ to Settings: %@",
            title, error.localizedDescription ?: @"write failed"];
        return;
    }

    self.navigationItem.prompt = [NSString stringWithFormat:@"Opening %@ settings…", title];
    // Prefer the same LaunchServices path as tapping Settings on the Home
    // Screen.  The reviewed PreferenceLoader adapter consumes the bounded
    // request above after Settings launches.  This avoids iOS 27's sensitive-
    // URL permission alert; retain the URL routes only as a compatibility
    // fallback for builds where the system application is not discoverable.
    if([[TSApplicationsManager sharedInstance]
        openApplicationWithBundleID:@"com.apple.Preferences"]) return;
    NSURL* settingsURL = [NSURL URLWithString:@"prefs:"];
    [UIApplication.sharedApplication openURL:settingsURL options:@{}
        completionHandler:^(BOOL success) {
            if(!success) {
                [UIApplication.sharedApplication openURL:[NSURL URLWithString:@"App-prefs:"]
                    options:@{} completionHandler:nil];
            }
        }];
}

- (BOOL)tableView:(UITableView*)tableView canEditRowAtIndexPath:(NSIndexPath*)indexPath
{ return YES; }

- (UISwipeActionsConfiguration*)tableView:(UITableView*)tableView
    leadingSwipeActionsConfigurationForRowAtIndexPath:(NSIndexPath*)indexPath
{
    UIContextualAction* export = [UIContextualAction contextualActionWithStyle:UIContextualActionStyleNormal
        title:[self.tweaks[indexPath.row][@"settings_available"] boolValue]
            ? @"Export + Menu" : @"Export DEB"
        handler:^(UIContextualAction* action, UIView* sourceView,
                                      void (^completionHandler)(BOOL)) {
            (void)action; (void)sourceView;
            [self exportDebForRowAtIndexPath:indexPath];
            completionHandler(YES);
        }];
    export.backgroundColor = UIColor.systemBlueColor;
    export.image = [UIImage systemImageNamed:@"square.and.arrow.up"];
    UIContextualAction* details = [UIContextualAction contextualActionWithStyle:UIContextualActionStyleNormal
        title:@"Details" handler:^(UIContextualAction* action, UIView* sourceView,
                                   void (^completionHandler)(BOOL)) {
            (void)action; (void)sourceView;
            NSString* package = [self.tweaks[indexPath.row][@"package"] isKindOfClass:NSString.class]
                ? self.tweaks[indexPath.row][@"package"] : nil;
            [self showPackageDetails:package];
            completionHandler(package.length > 0);
        }];
    details.backgroundColor = UIColor.systemIndigoColor;
    details.image = [UIImage systemImageNamed:@"info.circle"];
    UISwipeActionsConfiguration* configuration =
        [UISwipeActionsConfiguration configurationWithActions:@[export, details]];
    configuration.performsFirstActionWithFullSwipe = NO;
    return configuration;
}

- (void)tableView:(UITableView*)tableView commitEditingStyle:(UITableViewCellEditingStyle)style
    forRowAtIndexPath:(NSIndexPath*)indexPath
{
    if(style != UITableViewCellEditingStyleDelete) return;
    NSDictionary* tweak = self.tweaks[indexPath.row];
    NSString* package = tweak[@"package"];
    [self confirmRemovalOfPackage:package displayName:[self displayTitleForTweak:tweak]];
}

@end
