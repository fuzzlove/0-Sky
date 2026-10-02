//
//  TSIPAInfo.h
//  IPAInfo
//
//  Created by Lars Fröder on 22.10.22.
//

#import <Foundation/Foundation.h>
#import <archive.h>
#import <archive_entry.h>
@import UIKit;

@interface TSAppInfo : NSObject
{
	NSString* _path;
	BOOL _isArchive;
	struct archive* _archive;

	NSString* _cachedAppBundleName;
	NSString* _cachedRegistrationState;
	NSDictionary* _cachedInfoDictionary;
	NSDictionary* _cachedInfoDictionariesByPluginSubpaths;
	NSDictionary* _cachedEntitlementsByBinarySubpaths;
	UIImage* _cachedPreviewIcon;
	int64_t _cachedSize;
}

- (instancetype)initWithIPAPath:(NSString*)ipaPath;
- (instancetype)initWithAppBundlePath:(NSString*)bundlePath;
- (NSError*)determineAppBundleName;
- (NSError*)loadInfoDictionary;
- (NSError*)loadEntitlements;
- (NSError*)loadPreviewIcon;

- (NSError*)sync_loadBasicInfo;
- (NSError*)sync_loadInfo;

// The iOS 27 application sandbox may prevent Control from reading another
// application's Info.plist even though the SRD inventory service can inspect
// it. Merge that trusted inventory record into the local model so identity and
// version never degrade to nil merely because the bundle is cross-container.
- (void)applyInventoryMetadata:(NSDictionary*)metadata;

- (void)loadBasicInfoWithCompletion:(void (^)(NSError*))completionHandler;
- (void)loadInfoWithCompletion:(void (^)(NSError*))completionHandler;

- (NSString*)displayName;
- (NSString*)bundleIdentifier;
- (NSString*)versionString;
- (NSString*)sizeString;
- (NSString*)bundlePath;
- (NSString*)registrationState;
- (BOOL)isHiddenApplication;

- (UIImage*)iconForSize:(CGSize)size;

- (NSAttributedString*)detailedInfoTitle;
- (NSAttributedString*)detailedInfoDescription;
//- (UIImage*)image;
- (BOOL)isDebuggable;
- (void)log;

@end
