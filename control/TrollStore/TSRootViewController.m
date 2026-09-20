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
#import <TSPresentationDelegate.h>

@implementation TSRootViewController

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

	controlCenterNavigationController.tabBarItem.title = @"Control";
	controlCenterNavigationController.tabBarItem.image = [UIImage systemImageNamed:@"gauge.with.dots.needle.67percent"];
	appNavigationController.tabBarItem.image = [UIImage systemImageNamed:@"square.stack.3d.up.fill"];
	settingsNavigationController.tabBarItem.image = [UIImage systemImageNamed:@"gear"];
	inventoryNavigationController.tabBarItem.image = [UIImage systemImageNamed:@"shippingbox.fill"];

	self.title = @"Root View Controller";
	// Keep the everyday surface compact on both iPhone and iPad. Advanced
	// feature controllers remain available from the central problem-first view.
	self.viewControllers = @[controlCenterNavigationController, appNavigationController,
		inventoryNavigationController, settingsNavigationController];
}

- (void)viewDidLoad
{
	[super viewDidLoad];

	TSPresentationDelegate.presentationViewController = self;
}

@end
