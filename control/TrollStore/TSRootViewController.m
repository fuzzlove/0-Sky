#import "TSRootViewController.h"
#import "TSAppTableViewController.h"
#import "TSSettingsListController.h"
#import "TSInventoryTableViewController.h"
#import "TSHealthTableViewController.h"
#import "TSActivityTableViewController.h"
#import "TSRecoveryTableViewController.h"
#import "TSSnapshotsTableViewController.h"
#import "TSAutomationTableViewController.h"
#import "TSIntelligenceTableViewController.h"
#import "TSControlCenterTableViewController.h"
#import "TSSecurityToolkitTableViewController.h"
#import "TSCraneSettingsViewController.h"
#import <TSPresentationDelegate.h>

@implementation TSRootViewController

- (void)openCraneSettings
{
	if(self.viewControllers.count <= 2) return;
	void (^route)(void) = ^{
		self.selectedIndex = 2;
		UIViewController* selected = self.viewControllers[2];
		if(![selected isKindOfClass:UINavigationController.class]) return;
		UINavigationController* navigationController = (UINavigationController*)selected;
		[navigationController popToRootViewControllerAnimated:NO];
		NSString* descriptor = @"/var/jb/Library/PreferenceLoader/Preferences/CranePrefs.plist";
		TSCraneSettingsViewController* controller =
			[[TSCraneSettingsViewController alloc] initWithDescriptorPath:descriptor];
		[navigationController pushViewController:controller animated:NO];
		dispatch_async(dispatch_get_main_queue(), ^{
			[controller openNativeContainerManager];
		});
	};
	if(self.presentedViewController) {
		[self dismissViewControllerAnimated:NO completion:route];
	} else {
		route();
	}
}

- (void)loadView {
	[super loadView];

	TSControlCenterTableViewController* controlCenterVC = [[TSControlCenterTableViewController alloc] init];
	UINavigationController* controlCenterNavigationController = [[UINavigationController alloc]
		initWithRootViewController:controlCenterVC];
	controlCenterNavigationController.navigationBar.prefersLargeTitles = YES;

	TSAppTableViewController* appTableVC = [[TSAppTableViewController alloc] init];
	appTableVC.title = @"Apps";

	TSSettingsListController* settingsListVC = [[TSSettingsListController alloc] init];
	settingsListVC.title = @"Settings";

	UINavigationController* appNavigationController = [[UINavigationController alloc] initWithRootViewController:appTableVC];
	UINavigationController* settingsNavigationController = [[UINavigationController alloc] initWithRootViewController:settingsListVC];
	TSInventoryTableViewController* inventoryVC = [[TSInventoryTableViewController alloc] init];
	inventoryVC.title = @"Tweaks";
	UINavigationController* inventoryNavigationController = [[UINavigationController alloc] initWithRootViewController:inventoryVC];
	TSSecurityToolkitTableViewController* toolkitVC =
		[[TSSecurityToolkitTableViewController alloc] initWithCategory:nil];
	UINavigationController* toolkitNavigationController = [[UINavigationController alloc]
		initWithRootViewController:toolkitVC];

	controlCenterNavigationController.tabBarItem.title = @"Control";
	controlCenterNavigationController.tabBarItem.image = [UIImage systemImageNamed:@"gauge.with.dots.needle.67percent"];
	appNavigationController.tabBarItem.image = [UIImage systemImageNamed:@"square.stack.3d.up.fill"];
	settingsNavigationController.tabBarItem.image = [UIImage systemImageNamed:@"gear"];
	inventoryNavigationController.tabBarItem.image = [UIImage systemImageNamed:@"shippingbox.fill"];
	toolkitNavigationController.tabBarItem.title = @"Research";
	toolkitNavigationController.tabBarItem.image = [UIImage systemImageNamed:@"checkmark.shield.fill"];

	self.title = @"Root View Controller";
	// Keep the everyday surface compact on both iPhone and iPad. Advanced
	// feature controllers remain available from the central problem-first view.
	self.viewControllers = @[controlCenterNavigationController, appNavigationController,
		inventoryNavigationController, toolkitNavigationController, settingsNavigationController];
}

- (void)viewDidLoad
{
	[super viewDidLoad];

	TSPresentationDelegate.presentationViewController = self;
}

@end
