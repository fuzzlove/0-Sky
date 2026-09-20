#import "TSUtil.h"
#import "TSRootlessPaths.h"

#import <Foundation/Foundation.h>
#import <spawn.h>
#import <sys/sysctl.h>
#import <mach-o/dyld.h>
#import <libroot.h>

static EXPLOIT_TYPE gPlatformVulnerabilities;

void* _CTServerConnectionCreate(CFAllocatorRef, void *, void *);
int64_t _CTServerConnectionSetCellularUsagePolicy(CFTypeRef* ct, NSString* identifier, NSDictionary* policies);

#define POSIX_SPAWN_PERSONA_FLAGS_OVERRIDE 1
extern int posix_spawnattr_set_persona_np(const posix_spawnattr_t* __restrict, uid_t, uint32_t);
extern int posix_spawnattr_set_persona_uid_np(const posix_spawnattr_t* __restrict, uid_t);
extern int posix_spawnattr_set_persona_gid_np(const posix_spawnattr_t* __restrict, uid_t);

void chineseWifiFixup(void)
{
	_CTServerConnectionSetCellularUsagePolicy(
		_CTServerConnectionCreate(kCFAllocatorDefault, NULL, NULL),
		NSBundle.mainBundle.bundleIdentifier,
		@{
			@"kCTCellularDataUsagePolicy" : @"kCTCellularDataUsagePolicyAlwaysAllow",
			@"kCTWiFiDataUsagePolicy" : @"kCTCellularDataUsagePolicyAlwaysAllow"
		}
	);
}

NSString *getExecutablePath(void)
{
	uint32_t len = PATH_MAX;
	char selfPath[len];
	_NSGetExecutablePath(selfPath, &len);
	return [NSString stringWithUTF8String:selfPath];
}

#ifdef TROLLSTORE_LITE

BOOL shouldRegisterAsUserByDefault(void)
{
	if ([[NSFileManager defaultManager] fileExistsAtPath:JBROOT_PATH(@"/Library/MobileSubstrate/DynamicLibraries/AppSyncUnified-FrontBoard.dylib")]) {
		return YES;
	}
	return NO;
}

#else

BOOL shouldRegisterAsUserByDefault(void)
{
	return NO;
}

#endif

#ifdef EMBEDDED_ROOT_HELPER
NSString* rootHelperPath(void)
{
	return getExecutablePath();
}
#else
NSString* rootHelperPath(void)
{
	return [[NSBundle mainBundle].bundlePath stringByAppendingPathComponent:@"trollstorehelper"];
}
#endif

int fd_is_valid(int fd)
{
	return fcntl(fd, F_GETFD) != -1 || errno != EBADF;
}

NSString* getNSStringFromFile(int fd)
{
	NSMutableString* ms = [NSMutableString new];
	ssize_t num_read;
	char c;
	if(!fd_is_valid(fd)) return @"";
	while((num_read = read(fd, &c, sizeof(c))))
	{
		[ms appendString:[NSString stringWithFormat:@"%c", c]];
		if(c == '\n') break;
	}
	return ms.copy;
}

void printMultilineNSString(NSString* stringToPrint)
{
	NSCharacterSet *separator = [NSCharacterSet newlineCharacterSet];
	NSArray* lines = [stringToPrint componentsSeparatedByCharactersInSet:separator];
	for(NSString* line in lines)
	{
		NSLog(@"%@", line);
	}
}

int spawnRoot(NSString* path, NSArray* args, NSString** stdOut, NSString** stdErr)
{
	(void)path;
	NSString *tokenPath = TSRootlessPaths.bridgeTokenPath;
	NSString *token = [[NSString stringWithContentsOfFile:tokenPath
		encoding:NSASCIIStringEncoding error:nil]
		stringByTrimmingCharactersInSet:NSCharacterSet.whitespaceAndNewlineCharacterSet];
	if(token.length < 64)
	{
		if(stdErr) *stdErr = @"0-Sky Control bridge token is missing or invalid.";
		return 126;
	}

	NSError *jsonError = nil;
	NSData *body = [NSJSONSerialization dataWithJSONObject:@{@"arguments": args ?: @[]}
		options:0 error:&jsonError];
	if(!body)
	{
		if(stdErr) *stdErr = jsonError.localizedDescription ?: @"Unable to encode request.";
		return 126;
	}

	NSMutableURLRequest *request = [NSMutableURLRequest
		requestWithURL:[NSURL URLWithString:@"http://127.0.0.1:48654/v1/trollstore"]
		cachePolicy:NSURLRequestReloadIgnoringLocalCacheData timeoutInterval:1850.0];
	request.HTTPMethod = @"POST";
	request.HTTPBody = body;
	[request setValue:@"application/json" forHTTPHeaderField:@"Content-Type"];
	[request setValue:token forHTTPHeaderField:@"X-TrollStore-Bridge-Token"];

	dispatch_semaphore_t finished = dispatch_semaphore_create(0);
	__block NSData *responseData = nil;
	__block NSError *transportError = nil;
	NSURLSessionDataTask *task = [NSURLSession.sharedSession
		dataTaskWithRequest:request completionHandler:^(NSData *data, NSURLResponse *response, NSError *error)
	{
		(void)response;
		responseData = data;
		transportError = error;
		dispatch_semaphore_signal(finished);
	}];
	[task resume];
	if(dispatch_semaphore_wait(finished,
		dispatch_time(DISPATCH_TIME_NOW, (int64_t)(1860.0 * NSEC_PER_SEC))) != 0)
	{
		[task cancel];
		if(stdErr) *stdErr = @"0-Sky Control bridge request timed out.";
		return 124;
	}
	if(transportError || !responseData)
	{
		if(stdErr) *stdErr = transportError.localizedDescription ?: @"0-Sky Control bridge returned no data.";
		return -200;
	}

	NSDictionary *result = [NSJSONSerialization JSONObjectWithData:responseData options:0 error:&jsonError];
	if(![result isKindOfClass:NSDictionary.class])
	{
		if(stdErr) *stdErr = jsonError.localizedDescription ?: @"0-Sky Control bridge response was invalid.";
		return 125;
	}
	NSString *output = [result[@"stdout"] isKindOfClass:NSString.class] ? result[@"stdout"] : @"";
	NSString *errorOutput = [result[@"stderr"] isKindOfClass:NSString.class] ? result[@"stderr"] : @"";
	if(stdOut) *stdOut = output;
	if(stdErr) *stdErr = errorOutput;
	NSNumber *status = [result[@"status"] isKindOfClass:NSNumber.class] ? result[@"status"] : nil;
	return status ? status.intValue : 125;
}

int setDeviceAccountPassword(NSString* account, NSString* password, NSString** stdErr)
{
	if(![account isEqualToString:@"root"] && ![account isEqualToString:@"mobile"])
	{
		if(stdErr) *stdErr = @"Unsupported device account.";
		return 22;
	}
	NSData *passwordData = [password dataUsingEncoding:NSUTF8StringEncoding];
	if(passwordData.length < 8 || passwordData.length > 128 ||
	   [password rangeOfCharacterFromSet:NSCharacterSet.newlineCharacterSet].location != NSNotFound)
	{
		if(stdErr) *stdErr = @"Password must be 8-128 UTF-8 bytes without line breaks.";
		return 22;
	}

	NSString *token = [[NSString stringWithContentsOfFile:TSRootlessPaths.bridgeTokenPath
		encoding:NSASCIIStringEncoding error:nil]
		stringByTrimmingCharactersInSet:NSCharacterSet.whitespaceAndNewlineCharacterSet];
	if(token.length < 64)
	{
		if(stdErr) *stdErr = @"0-Sky Control bridge token is missing or invalid.";
		return 126;
	}

	NSError *jsonError = nil;
	NSData *body = [NSJSONSerialization dataWithJSONObject:@{
		@"account": account, @"password": password
	} options:0 error:&jsonError];
	if(!body)
	{
		if(stdErr) *stdErr = jsonError.localizedDescription ?: @"Unable to encode password request.";
		return 126;
	}

	NSMutableURLRequest *request = [NSMutableURLRequest
		requestWithURL:[NSURL URLWithString:@"http://127.0.0.1:48654/v1/device-password"]
		cachePolicy:NSURLRequestReloadIgnoringLocalCacheData timeoutInterval:30.0];
	request.HTTPMethod = @"POST";
	request.HTTPBody = body;
	[request setValue:@"application/json" forHTTPHeaderField:@"Content-Type"];
	[request setValue:token forHTTPHeaderField:@"X-TrollStore-Bridge-Token"];

	dispatch_semaphore_t finished = dispatch_semaphore_create(0);
	__block NSData *responseData = nil;
	__block NSError *transportError = nil;
	NSURLSessionDataTask *task = [NSURLSession.sharedSession
		dataTaskWithRequest:request completionHandler:^(NSData *data, NSURLResponse *response, NSError *error)
	{
		(void)response;
		responseData = data;
		transportError = error;
		dispatch_semaphore_signal(finished);
	}];
	[task resume];
	if(dispatch_semaphore_wait(finished,
		dispatch_time(DISPATCH_TIME_NOW, (int64_t)(35.0 * NSEC_PER_SEC))) != 0)
	{
		[task cancel];
		if(stdErr) *stdErr = @"Password update timed out.";
		return 124;
	}
	if(transportError || !responseData)
	{
		if(stdErr) *stdErr = transportError.localizedDescription ?: @"0-Sky Control bridge returned no data.";
		return 125;
	}
	NSDictionary *result = [NSJSONSerialization JSONObjectWithData:responseData options:0 error:&jsonError];
	if(![result isKindOfClass:NSDictionary.class])
	{
		if(stdErr) *stdErr = jsonError.localizedDescription ?: @"Password update response was invalid.";
		return 125;
	}
	NSString *errorOutput = [result[@"stderr"] isKindOfClass:NSString.class] ? result[@"stderr"] : @"";
	if(stdErr) *stdErr = errorOutput;
	NSNumber *status = [result[@"status"] isKindOfClass:NSNumber.class] ? result[@"status"] : nil;
	return status ? status.intValue : 125;
}

void enumerateProcessesUsingBlock(void (^enumerator)(pid_t pid, NSString* executablePath, BOOL* stop))
{
	static int maxArgumentSize = 0;
	if (maxArgumentSize == 0) {
		size_t size = sizeof(maxArgumentSize);
		if (sysctl((int[]){ CTL_KERN, KERN_ARGMAX }, 2, &maxArgumentSize, &size, NULL, 0) == -1) {
			perror("sysctl argument size");
			maxArgumentSize = 4096; // Default
		}
	}
	int mib[3] = { CTL_KERN, KERN_PROC, KERN_PROC_ALL};
	struct kinfo_proc *info;
	size_t length;
	int count;

	if (sysctl(mib, 3, NULL, &length, NULL, 0) < 0)
		return;
	if (!(info = malloc(length)))
		return;
	if (sysctl(mib, 3, info, &length, NULL, 0) < 0) {
		free(info);
		return;
	}
	count = length / sizeof(struct kinfo_proc);
	for (int i = 0; i < count; i++) {
		@autoreleasepool {
		pid_t pid = info[i].kp_proc.p_pid;
		if (pid == 0) {
			continue;
		}
		size_t size = maxArgumentSize;
		char* buffer = (char *)malloc(length);
		if (sysctl((int[]){ CTL_KERN, KERN_PROCARGS2, pid }, 3, buffer, &size, NULL, 0) == 0) {
			NSString* executablePath = [NSString stringWithCString:(buffer+sizeof(int)) encoding:NSUTF8StringEncoding];

			BOOL stop = NO;
			enumerator(pid, executablePath, &stop);
			if(stop)
			{
				free(buffer);
				break;
			}
		}
		free(buffer);
		}
	}
	free(info);
}

void killall(NSString* processName, BOOL softly)
{
	enumerateProcessesUsingBlock(^(pid_t pid, NSString* executablePath, BOOL* stop)
	{
		if([executablePath.lastPathComponent isEqualToString:processName])
		{
			if(softly)
			{
				kill(pid, SIGTERM);
			}
			else
			{
				kill(pid, SIGKILL);
			}
		}
	});
}

void respring(void)
{
	killall(@"SpringBoard", YES);
	exit(0);
}

void github_fetchLatestVersion(NSString* repo, void (^completionHandler)(NSString* latestVersion))
{
	NSString* urlString = [NSString stringWithFormat:@"https://api.github.com/repos/%@/releases/latest", repo];
	NSURL* githubLatestAPIURL = [NSURL URLWithString:urlString];

	NSURLSessionDataTask* task = [NSURLSession.sharedSession dataTaskWithURL:githubLatestAPIURL completionHandler:^(NSData *data, NSURLResponse *response, NSError *error)
	{
		if(!error)
		{
			if ([response isKindOfClass:[NSHTTPURLResponse class]])
			{
				NSError *jsonError;
				NSDictionary *jsonResponse = [NSJSONSerialization JSONObjectWithData:data options:0 error:&jsonError];

				if (!jsonError)
				{
					completionHandler(jsonResponse[@"tag_name"]);
				}
			}
		}
	}];

	[task resume];
}

void fetchLatestTrollStoreVersion(void (^completionHandler)(NSString* latestVersion))
{
	github_fetchLatestVersion(@"opa334/TrollStore", completionHandler);
}

void fetchLatestLdidVersion(void (^completionHandler)(NSString* latestVersion))
{
	github_fetchLatestVersion(@"opa334/ldid", completionHandler);
}

NSArray* trollStoreInstalledAppContainerPathsInternal(NSString *marker)
{
	NSMutableArray* appContainerPaths = [NSMutableArray new];

	NSString* appContainersPath = @"/var/containers/Bundle/Application";

	NSError* error;
	NSArray* containers = [[NSFileManager defaultManager] contentsOfDirectoryAtPath:appContainersPath error:&error];
	if(error)
	{
		NSLog(@"error getting app bundles paths %@", error);
	}
	if(!containers) return nil;

	for(NSString* container in containers)
	{
		NSString* containerPath = [appContainersPath stringByAppendingPathComponent:container];
		BOOL isDirectory = NO;
		BOOL exists = [[NSFileManager defaultManager] fileExistsAtPath:containerPath isDirectory:&isDirectory];
		if(exists && isDirectory)
		{
			NSString* trollStoreMark = [containerPath stringByAppendingPathComponent:marker];
			if([[NSFileManager defaultManager] fileExistsAtPath:trollStoreMark])
			{
				NSString* trollStoreApp = [containerPath stringByAppendingPathComponent:@"TrollStore.app"];
				NSString* trollStoreLiteApp = [containerPath stringByAppendingPathComponent:@"TrollStoreLite.app"];
				if(![[NSFileManager defaultManager] fileExistsAtPath:trollStoreApp] && ![[NSFileManager defaultManager] fileExistsAtPath:trollStoreLiteApp])
				{
					[appContainerPaths addObject:containerPath];
				}
			}
		}
	}

	return appContainerPaths.copy;
}

NSArray *trollStoreInstalledAppContainerPaths(void)
{
	return trollStoreInstalledAppContainerPathsInternal(TS_ACTIVE_MARKER);
}

NSArray* trollStoreInstalledAppBundlePathsInternal(NSString *marker)
{
	NSMutableArray* appPaths = [NSMutableArray new];
	for(NSString* containerPath in trollStoreInstalledAppContainerPathsInternal(marker))
	{
		NSArray* items = [[NSFileManager defaultManager] contentsOfDirectoryAtPath:containerPath error:nil];
		if(!items) return nil;

		for(NSString* item in items)
		{
			if([item.pathExtension isEqualToString:@"app"])
			{
				[appPaths addObject:[containerPath stringByAppendingPathComponent:item]];
			}
		}
	}
	return appPaths.copy;
}

NSArray *trollStoreInstalledAppBundlePaths(void)
{
	return trollStoreInstalledAppBundlePathsInternal(TS_ACTIVE_MARKER);
}

NSArray *trollStoreInactiveInstalledAppBundlePaths(void)
{
	return trollStoreInstalledAppBundlePathsInternal(TS_INACTIVE_MARKER);
}

NSString* trollStorePath()
{
	NSError* mcmError;
	MCMAppContainer* appContainer = [MCMAppContainer containerWithIdentifier:APP_ID createIfNecessary:NO existed:NULL error:&mcmError];
	if(!appContainer) return nil;
	return appContainer.url.path;
}

NSString* trollStoreAppPath()
{
	return [trollStorePath() stringByAppendingPathComponent:@"TrollStore.app"];
}

BOOL isRemovableSystemApp(NSString* appId)
{
	return [[NSFileManager defaultManager] fileExistsAtPath:[@"/System/Library/AppSignatures" stringByAppendingPathComponent:appId]];
}

LSApplicationProxy* findPersistenceHelperApp(PERSISTENCE_HELPER_TYPE allowedTypes)
{
	__block LSApplicationProxy* outProxy;

	void (^searchBlock)(LSApplicationProxy* appProxy) = ^(LSApplicationProxy* appProxy)
	{
		if(appProxy.installed && !appProxy.restricted)
		{
			if([appProxy.bundleURL.path hasPrefix:@"/private/var/containers"])
			{
				NSURL* trollStorePersistenceMarkURL = [appProxy.bundleURL URLByAppendingPathComponent:@".TrollStorePersistenceHelper"];
				if([trollStorePersistenceMarkURL checkResourceIsReachableAndReturnError:nil])
				{
					outProxy = appProxy;
				}
			}
		}
	};

	if(allowedTypes & PERSISTENCE_HELPER_TYPE_USER)
	{
		[[LSApplicationWorkspace defaultWorkspace] enumerateApplicationsOfType:0 block:searchBlock];
	}
	if(allowedTypes & PERSISTENCE_HELPER_TYPE_SYSTEM)
	{
		[[LSApplicationWorkspace defaultWorkspace] enumerateApplicationsOfType:1 block:searchBlock];
	}

	return outProxy;
}

SecStaticCodeRef getStaticCodeRef(NSString *binaryPath)
{
	if(binaryPath == nil)
	{
		return NULL;
	}

	CFURLRef binaryURL = CFURLCreateWithFileSystemPath(kCFAllocatorDefault, (__bridge CFStringRef)binaryPath, kCFURLPOSIXPathStyle, false);
	if(binaryURL == NULL)
	{
		NSLog(@"[getStaticCodeRef] failed to get URL to binary %@", binaryPath);
		return NULL;
	}

	SecStaticCodeRef codeRef = NULL;
	OSStatus result;

	result = SecStaticCodeCreateWithPathAndAttributes(binaryURL, kSecCSDefaultFlags, NULL, &codeRef);

	CFRelease(binaryURL);

	if(result != errSecSuccess)
	{
		NSLog(@"[getStaticCodeRef] failed to create static code for binary %@", binaryPath);
		return NULL;
	}

	return codeRef;
}

NSDictionary* dumpEntitlements(SecStaticCodeRef codeRef)
{
	if(codeRef == NULL)
	{
		NSLog(@"[dumpEntitlements] attempting to dump entitlements without a StaticCodeRef");
		return nil;
	}

	CFDictionaryRef signingInfo = NULL;
	OSStatus result;

	result = SecCodeCopySigningInformation(codeRef, kSecCSRequirementInformation, &signingInfo);

	if(result != errSecSuccess)
	{
		NSLog(@"[dumpEntitlements] failed to copy signing info from static code");
		return nil;
	}

	NSDictionary *entitlementsNSDict = nil;

	CFDictionaryRef entitlements = CFDictionaryGetValue(signingInfo, kSecCodeInfoEntitlementsDict);
	if(entitlements == NULL)
	{
		NSLog(@"[dumpEntitlements] no entitlements specified");
	}
	else if(CFGetTypeID(entitlements) != CFDictionaryGetTypeID())
	{
		NSLog(@"[dumpEntitlements] invalid entitlements");
	}
	else
	{
		entitlementsNSDict = (__bridge NSDictionary *)(entitlements);
		NSLog(@"[dumpEntitlements] dumped %@", entitlementsNSDict);
	}

	CFRelease(signingInfo);
	return entitlementsNSDict;
}

NSDictionary* dumpEntitlementsFromBinaryAtPath(NSString *binaryPath)
{
	// This function is intended for one-shot checks. Main-event functions should retain/release their own SecStaticCodeRefs

	if(binaryPath == nil)
	{
		return nil;
	}

	SecStaticCodeRef codeRef = getStaticCodeRef(binaryPath);
	if(codeRef == NULL)
	{
		return nil;
	}

	NSDictionary *entitlements = dumpEntitlements(codeRef);
	CFRelease(codeRef);

	return entitlements;
}

NSDictionary* dumpEntitlementsFromBinaryData(NSData* binaryData)
{
	NSDictionary* entitlements;
	NSString* tmpPath = [NSTemporaryDirectory() stringByAppendingPathComponent:[NSUUID UUID].UUIDString];
	NSURL* tmpURL = [NSURL fileURLWithPath:tmpPath];
	if([binaryData writeToURL:tmpURL options:NSDataWritingAtomic error:nil])
	{
		entitlements = dumpEntitlementsFromBinaryAtPath(tmpPath);
		[[NSFileManager defaultManager] removeItemAtURL:tmpURL error:nil];
	}
	return entitlements;
}

EXPLOIT_TYPE getDeclaredExploitTypeFromInfoDictionary(NSDictionary *infoDict)
{
    NSObject *tsPreAppliedExploitType = infoDict[@"TSPreAppliedExploitType"];
    if([tsPreAppliedExploitType isKindOfClass:[NSNumber class]])
    {
        NSNumber *tsPreAppliedExploitTypeNum = (NSNumber *)tsPreAppliedExploitType;
        int exploitTypeInt = [tsPreAppliedExploitTypeNum intValue];

        if(exploitTypeInt > 0)
        {
            // Convert versions 1, 2, etc... for use with bitmasking
            return (1 << (exploitTypeInt - 1));
        }
        else
        {
            NSLog(@"[getDeclaredExploitTypeFromInfoDictionary] rejecting TSPreAppliedExploitType Info.plist value (%i) which is out of range", exploitTypeInt);
        }
    }

    // Legacy Info.plist flag - now deprecated, but we treat it as a custom root cert if present
    NSObject *tsBundleIsPreSigned = infoDict[@"TSBundlePreSigned"];
    if([tsBundleIsPreSigned isKindOfClass:[NSNumber class]])
    {
        NSNumber *tsBundleIsPreSignedNum = (NSNumber *)tsBundleIsPreSigned;
        if([tsBundleIsPreSignedNum boolValue] == YES)
        {
            return EXPLOIT_TYPE_CUSTOM_ROOT_CERTIFICATE_V1;
        }
    }

    // No declarations
    return 0;
}

void determinePlatformVulnerableExploitTypes(void *context) {
	size_t size = 0;

	// Get the current build number
	int mib[2] = {CTL_KERN, KERN_OSVERSION};

	// Get size of buffer
	sysctl(mib, 2, NULL, &size, NULL, 0);

	// Get the actual value
	char *os_build = malloc(size);
	if(!os_build)
	{
		// malloc failed
		perror("malloc buffer for KERN_OSVERSION");
		return;
	}

	if (sysctl(mib, 2, os_build, &size, NULL, 0) != 0)
	{
		// sysctl failed
		perror("sysctl KERN_OSVERSION");
		free(os_build);
		return;
	}


    if(strncmp(os_build, "18A5319i", 8) < 0) {
        // Below iOS 14.0 beta 2
        gPlatformVulnerabilities = 0;
    }
    else if(strncmp(os_build, "21A326", 6) >= 0 && strncmp(os_build, "21A331", 6) <= 0)
    {
        // iOS 17.0 final
        gPlatformVulnerabilities = EXPLOIT_TYPE_CMS_SIGNERINFO_V1;
    }
    else if(strncmp(os_build, "21A5248v", 8) >= 0 && strncmp(os_build, "21A5326a", 8) <= 0)
    {
        // iOS 17.0 beta 1 - 8
        gPlatformVulnerabilities = EXPLOIT_TYPE_CMS_SIGNERINFO_V1;
    }
    else if(strncmp(os_build, "19G5027e", 8) >= 0 && strncmp(os_build, "19G5063a", 8) <= 0)
    {
        // iOS 15.6 beta 1 - 5
        gPlatformVulnerabilities = (EXPLOIT_TYPE_CUSTOM_ROOT_CERTIFICATE_V1 | EXPLOIT_TYPE_CMS_SIGNERINFO_V1);
    }
    else if(strncmp(os_build, "19F5070b", 8) <= 0)
    {
        // iOS 14.0 beta 2 - 15.5 beta 4
        gPlatformVulnerabilities = (EXPLOIT_TYPE_CUSTOM_ROOT_CERTIFICATE_V1 | EXPLOIT_TYPE_CMS_SIGNERINFO_V1);
    }
    else if(strncmp(os_build, "20H18", 5) <= 0)
    {
        // iOS 14.0 - 16.6.1, 16.7 RC (if CUSTOM_ROOT_CERTIFICATE_V1 not supported)
        gPlatformVulnerabilities = EXPLOIT_TYPE_CMS_SIGNERINFO_V1;
    }

	free(os_build);
}

bool isPlatformVulnerableToExploitType(EXPLOIT_TYPE exploitType) {
	// Find out what we are vulnerable to
	static dispatch_once_t once;
	dispatch_once_f(&once, NULL, determinePlatformVulnerableExploitTypes);

	return (exploitType & gPlatformVulnerabilities) != 0;
}
