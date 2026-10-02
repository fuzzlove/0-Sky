#import "TSAppDelegate.h"
#import "TSRootViewController.h"
#import "TSSceneDelegate.h"
#import "TSBluetoothFallback.h"

@implementation TSAppDelegate

- (BOOL)application:(UIApplication *)application didFinishLaunchingWithOptions:(NSDictionary *)launchOptions {
	[[TSBluetoothFallback sharedFallback] start];
	return YES;
}

- (UISceneConfiguration *)application:(UIApplication *)application configurationForConnectingSceneSession:(UISceneSession *)connectingSceneSession options:(UISceneConnectionOptions *)options {
	// A newly allocated configuration has no delegate even when Info.plist
	// names one. On SRD builds that leaves UIKit displaying the legacy launch
	// storyboard and none of Control's live inventory controllers are attached.
	UISceneConfiguration* configuration = [[UISceneConfiguration alloc]
		initWithName:@"Default Configuration" sessionRole:connectingSceneSession.role];
	configuration.delegateClass = TSSceneDelegate.class;
	return configuration;
}


- (void)application:(UIApplication *)application didDiscardSceneSessions:(NSSet<UISceneSession *> *)sceneSessions {
    // Called when the user discards a scene session.
    // If any sessions were discarded while the application was not running, this will be called shortly after application:didFinishLaunchingWithOptions.
    // Use this method to release any resources that were specific to the discarded scenes, as they will not return.
}

@end
