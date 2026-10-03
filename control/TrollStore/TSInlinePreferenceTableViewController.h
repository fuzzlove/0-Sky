#import <UIKit/UIKit.h>

// Native host for data-only PreferenceLoader specifiers, including supported
// rows from an installed bundle's Root.plist or legacy Prefs.plist.
// Third-party preference code is never loaded into 0-Sky Control's process.
@interface TSInlinePreferenceTableViewController : UITableViewController <UITextFieldDelegate>

// Set only after the installed package, dylib hash, device build and local
// lock-screen UAT receipt have all matched.
@property(nonatomic,assign) BOOL doodlePortVerified;

- (instancetype)initWithDescriptorPath:(NSString*)descriptorPath
                                  title:(NSString*)title;

+ (BOOL)canOpenDescriptorAtPath:(NSString*)descriptorPath;

@end
