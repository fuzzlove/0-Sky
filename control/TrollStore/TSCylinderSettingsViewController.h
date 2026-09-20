#import <UIKit/UIKit.h>

// Native compatibility host for Cylinder Reborn's legacy executable
// PreferenceBundle.  The old controller remains installed, but is not loaded
// into 0-Sky Control's process on current SRD builds.
@interface TSCylinderSettingsViewController : UITableViewController
+ (BOOL)supportsPackage:(NSString*)package descriptorPath:(NSString*)descriptorPath;
- (instancetype)initWithTitle:(NSString*)title;
@end
