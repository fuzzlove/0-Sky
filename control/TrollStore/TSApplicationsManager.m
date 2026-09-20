#import "TSApplicationsManager.h"
#import <TSUtil.h>
#import <TSRootlessPaths.h>
extern NSUserDefaults* trollStoreUserDefaults();

@implementation TSApplicationsManager

+ (instancetype)sharedInstance
{
    static TSApplicationsManager *sharedInstance = nil;
    static dispatch_once_t onceToken;
    dispatch_once(&onceToken, ^{
        sharedInstance = [[TSApplicationsManager alloc] init];
    });
    return sharedInstance;
}

- (NSArray*)installedAppPaths
{
    NSDictionary* inventory = [self srdInventory];
    NSArray* applications = [inventory[@"applications"] isKindOfClass:NSArray.class]
        ? inventory[@"applications"] : @[];
    NSMutableArray* paths = [NSMutableArray new];
    for(NSDictionary* app in applications)
    {
        if(![app isKindOfClass:NSDictionary.class]) continue;
        NSString* path = [app[@"path"] isKindOfClass:NSString.class] ? app[@"path"] : nil;
        BOOL system = [app[@"system"] boolValue];
        BOOL removed = [app[@"removed"] boolValue];
        if(path.length && !system && !removed && [[NSFileManager defaultManager] fileExistsAtPath:path])
            [paths addObject:path];
    }
    // Keep the old marker-based view as a fallback if the local bridge is
    // temporarily restarting. This prevents a blank screen without hiding a
    // successfully fetched empty inventory.
    return inventory ? paths.copy : trollStoreInstalledAppBundlePaths();
}

- (NSDictionary*)srdInventory
{
    NSMutableURLRequest* request = [NSMutableURLRequest requestWithURL:
        [NSURL URLWithString:@"http://127.0.0.1:48654/v1/inventory"]
        cachePolicy:NSURLRequestReloadIgnoringLocalCacheData timeoutInterval:8.0];
    dispatch_semaphore_t finished = dispatch_semaphore_create(0);
    __block NSData* data = nil;
    __block NSError* transportError = nil;
    NSURLSessionDataTask* task = [NSURLSession.sharedSession
        dataTaskWithRequest:request completionHandler:^(NSData* responseData,
            NSURLResponse* response, NSError* error) {
            (void)response;
            data = responseData;
            transportError = error;
            dispatch_semaphore_signal(finished);
        }];
    [task resume];
    if(dispatch_semaphore_wait(finished,
        dispatch_time(DISPATCH_TIME_NOW, (int64_t)(9.0 * NSEC_PER_SEC))) != 0) {
        [task cancel];
        return nil;
    }
    if(!data || transportError) return nil;
    NSError* error = nil;
    NSDictionary* result = [NSJSONSerialization JSONObjectWithData:data options:0 error:&error];
    return [result isKindOfClass:NSDictionary.class] ? result : nil;
}

- (NSDictionary*)coreRequestOperation:(NSString*)operation
    parameters:(NSDictionary*)parameters error:(NSError**)errorOut
{
    if(!operation.length || ![parameters isKindOfClass:NSDictionary.class]) {
        if(errorOut) *errorOut = [NSError errorWithDomain:@"com.liquidsky.CrypStore.Core"
            code:1 userInfo:@{NSLocalizedDescriptionKey: @"Invalid core request."}];
        return nil;
    }
    NSString* token = [[NSString stringWithContentsOfFile:TSRootlessPaths.bridgeTokenPath
        encoding:NSASCIIStringEncoding error:errorOut]
        stringByTrimmingCharactersInSet:NSCharacterSet.whitespaceAndNewlineCharacterSet];
    if(token.length < 64) return nil;

    NSDictionary* envelope = @{
        @"protocolVersion": @1,
        @"requestId": NSUUID.UUID.UUIDString,
        @"operation": operation,
        @"timestamp": @([NSDate date].timeIntervalSince1970),
        @"parameters": parameters,
    };
    NSData* body = [NSJSONSerialization dataWithJSONObject:envelope options:0 error:errorOut];
    if(!body) return nil;
    NSSet* longOperations = [NSSet setWithArray:@[@"createSnapshot", @"restoreSnapshot",
        @"deleteSnapshot", @"undoChange"]];
    NSTimeInterval timeout = [longOperations containsObject:operation] ? 300.0 : 15.0;
    NSMutableURLRequest* request = [NSMutableURLRequest
        requestWithURL:TSRootlessPaths.coreEndpointURL
        cachePolicy:NSURLRequestReloadIgnoringLocalCacheData timeoutInterval:timeout];
    request.HTTPMethod = @"POST";
    request.HTTPBody = body;
    [request setValue:@"application/json" forHTTPHeaderField:@"Content-Type"];
    [request setValue:token forHTTPHeaderField:@"X-TrollStore-Bridge-Token"];

    dispatch_semaphore_t finished = dispatch_semaphore_create(0);
    __block NSData* responseData = nil;
    __block NSError* transportError = nil;
    NSURLSessionDataTask* task = [NSURLSession.sharedSession
        dataTaskWithRequest:request completionHandler:^(NSData* data,
            NSURLResponse* response, NSError* error) {
            (void)response;
            responseData = data;
            transportError = error;
            dispatch_semaphore_signal(finished);
        }];
    [task resume];
    if(dispatch_semaphore_wait(finished,
        dispatch_time(DISPATCH_TIME_NOW, (int64_t)((timeout + 1.0) * NSEC_PER_SEC))) != 0) {
        [task cancel];
        transportError = [NSError errorWithDomain:@"com.liquidsky.CrypStore.Core"
            code:2 userInfo:@{NSLocalizedDescriptionKey: @"Core request timed out."}];
    }
    if(transportError || !responseData) {
        if(errorOut) *errorOut = transportError;
        return nil;
    }
    NSDictionary* response = [NSJSONSerialization JSONObjectWithData:responseData
        options:0 error:errorOut];
    return [response isKindOfClass:NSDictionary.class] ? response : nil;
}

- (int)installDeb:(NSString*)path log:(NSString**)logOut
{
    if(!path) return -200;
    return spawnRoot(rootHelperPath(), @[@"install-deb", path], logOut, logOut);
}

- (int)removeTweakPackage:(NSString*)package log:(NSString**)logOut
{
    if(!package) return -200;
    return spawnRoot(rootHelperPath(), @[@"remove-package", package], logOut, logOut);
}

- (int)exportAppBundle:(NSString*)appPath toIPA:(NSString*)destination log:(NSString**)logOut
{
    if(!appPath.length || !destination.length) return -200;
    return spawnRoot(rootHelperPath(), @[@"export-app", appPath, destination], logOut, logOut);
}

- (int)exportAppBundle:(NSString*)appPath toDeb:(NSString*)destination log:(NSString**)logOut
{
    if(!appPath.length || !destination.length) return -200;
    return spawnRoot(rootHelperPath(), @[@"export-app-deb", appPath, destination], logOut, logOut);
}

- (int)exportPackage:(NSString*)package toDeb:(NSString*)destination log:(NSString**)logOut
{
    if(!package.length || !destination.length) return -200;
    return spawnRoot(rootHelperPath(), @[@"export-package", package, destination], logOut, logOut);
}

- (int)repairPreferenceMenusForPackage:(NSString*)package log:(NSString**)logOut
{
    NSMutableArray* arguments = [NSMutableArray arrayWithObject:@"repair-preferences"];
    if(package.length) [arguments addObject:package];
    return spawnRoot(rootHelperPath(), arguments, logOut, logOut);
}

- (NSError*)errorForCode:(int)code
{
    NSString* errorDescription = @"Unknown Error";
    switch(code)
    {
        // IPA install errors
        case 166:
        errorDescription = @"The IPA file does not exist or is not accessible.";
        break;
        case 167:
        errorDescription = @"The IPA file does not appear to contain an app.";
        break;
        case 168:
        errorDescription = @"Failed to extract IPA file.";
        break;
        case 169:
        errorDescription = @"Failed to extract update tar file.";
        break;
        // App install errors
        case 170:
        errorDescription = @"Failed to create container for app bundle.";
        break;
        case 171:
        errorDescription = @"A non "APP_NAME@" or a "OTHER_APP_NAME@" app with the same identifier is already installed. If you are absolutely sure it is not, you can force install it.";
        break;
        case 172:
        errorDescription = @"The app does not contain an Info.plist file.";
        break;
        case 173:
        errorDescription = @"The app is not signed with a fake CoreTrust certificate and ldid is not installed. Install ldid in the settings tab and try again.";
        break;
        case 174:
        errorDescription = @"The app's main executable does not exist.";
        break;
        case 175: {
            //if (@available(iOS 16, *)) {
            //    errorDescription = @"Failed to sign the app.";
            //}
            //else {
                errorDescription = @"Failed to sign the app. ldid returned a non zero status code.";
            //}
        }
        break;
        case 176:
        errorDescription = @"The app's Info.plist is missing required values.";
        break;
        case 177:
        errorDescription = @"Failed to mark app as Commissary app.";
        break;
        case 178:
        errorDescription = @"Failed to copy app bundle.";
        break;
        case 179:
        errorDescription = @"The app you tried to install has the same identifier as a system app already installed on the device. The installation has been prevented to protect you from possible bootloops or other issues.";
        break;
        case 180:
        errorDescription = @"The app you tried to install has an encrypted main binary, which cannot have the CoreTrust bypass applied to it. Please ensure you install decrypted apps.";
        break;
        case 181:
        errorDescription = @"Failed to add app to icon cache.";
        break;
        case 182:
        errorDescription = @"The app was installed successfully, but requires developer mode to be enabled to run. After rebooting, select \"Turn On\" to enable developer mode.";
        break;
        case 183:
        errorDescription = @"Failed to enable developer mode.";
        break;
        case 184:
        errorDescription = @"The app was installed successfully, but has additional binaries that are encrypted (e.g. extensions, plugins). The app itself should work, but you may experience broken functionality as a result.";
        break;
        case 185:
        errorDescription = @"Failed to sign the app. The CoreTrust bypass returned a non zero status code.";
    }

    NSError* error = [NSError errorWithDomain:TrollStoreErrorDomain code:code userInfo:@{NSLocalizedDescriptionKey : errorDescription}];
    return error;
}

- (int)installIpa:(NSString*)pathToIpa force:(BOOL)force log:(NSString**)logOut
{
    NSMutableArray* args = [NSMutableArray new];
    [args addObject:@"install"];
    if(force)
    {
        [args addObject:@"force"];
    }
    NSNumber* installationMethodToUseNum = [trollStoreUserDefaults() objectForKey:@"installationMethod"];
    int installationMethodToUse = installationMethodToUseNum ? installationMethodToUseNum.intValue : 1;
    if(installationMethodToUse == 1)
    {
        [args addObject:@"custom"];
    }
    else
    {
        [args addObject:@"installd"];
    }
    [args addObject:pathToIpa];

    int ret = spawnRoot(rootHelperPath(), args, nil, logOut);
    [[NSNotificationCenter defaultCenter] postNotificationName:@"ApplicationsChanged" object:nil];
    return ret;
}

- (int)installIpa:(NSString*)pathToIpa
{
    return [self installIpa:pathToIpa force:NO log:nil];
}

- (int)uninstallApp:(NSString*)appId
{
    if(!appId) return -200;

    NSMutableArray* args = [NSMutableArray new];
    [args addObject:@"uninstall"];

    NSNumber* uninstallationMethodToUseNum = [trollStoreUserDefaults() objectForKey:@"uninstallationMethod"];
    int uninstallationMethodToUse = uninstallationMethodToUseNum ? uninstallationMethodToUseNum.intValue : 0;
    if(uninstallationMethodToUse == 1)
    {
        [args addObject:@"custom"];
    }
    else
    {
        [args addObject:@"installd"];
    }

    [args addObject:appId];

    int ret = spawnRoot(rootHelperPath(), args, nil, nil);
    [[NSNotificationCenter defaultCenter] postNotificationName:@"ApplicationsChanged" object:nil];
    return ret;
}

- (int)uninstallAppByPath:(NSString*)path
{
    if(!path) return -200;

    NSMutableArray* args = [NSMutableArray new];
    [args addObject:@"uninstall-path"];

    NSNumber* uninstallationMethodToUseNum = [trollStoreUserDefaults() objectForKey:@"uninstallationMethod"];
    int uninstallationMethodToUse = uninstallationMethodToUseNum ? uninstallationMethodToUseNum.intValue : 0;
    if(uninstallationMethodToUse == 1)
    {
        [args addObject:@"custom"];
    }
    else
    {
        [args addObject:@"installd"];
    }

    [args addObject:path];

    int ret = spawnRoot(rootHelperPath(), args, nil, nil);
    [[NSNotificationCenter defaultCenter] postNotificationName:@"ApplicationsChanged" object:nil];
    return ret;
}

- (BOOL)openApplicationWithBundleID:(NSString *)appId
{
    return [[LSApplicationWorkspace defaultWorkspace] openApplicationWithBundleID:appId];
}

- (int)enableJITForBundleID:(NSString *)appId
{
    return spawnRoot(rootHelperPath(), @[@"enable-jit", appId], nil, nil);
}

- (int)changeAppRegistration:(NSString*)appPath toState:(NSString*)newState
{
    if(!appPath || !newState) return -200;
    return spawnRoot(rootHelperPath(), @[@"modify-registration", appPath, newState], nil, nil);
}

@end
