#import <UIKit/UIKit.h>

// Native host for legacy, data-only PreferenceLoader descriptors.  This is
// intentionally limited to plist specifiers and never loads a third-party
// PreferenceBundle into 0-Sky Control's process.
@interface TSInlinePreferenceTableViewController : UITableViewController <UITextFieldDelegate>

- (instancetype)initWithDescriptorPath:(NSString*)descriptorPath
                                  title:(NSString*)title;

+ (BOOL)canOpenDescriptorAtPath:(NSString*)descriptorPath;

@end
