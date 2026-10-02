#import <UIKit/UIKit.h>

// 0-Sky-owned host for Crane's application allowlist. Crane's historical
// PreferenceLoader application picker cannot be trusted as an iOS 27 runtime
// contract, so Control records the researcher's exact selected bundle IDs.
@interface TSCraneSettingsViewController : UITableViewController

- (instancetype)initWithDescriptorPath:(NSString*)descriptorPath;
- (void)openNativeContainerManager;

@end
