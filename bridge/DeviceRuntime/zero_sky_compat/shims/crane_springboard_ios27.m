#import <Foundation/Foundation.h>
#import <CommonCrypto/CommonDigest.h>
#import <dispatch/dispatch.h>
#import <dlfcn.h>
#import <mach-o/dyld.h>
#import <objc/message.h>
#import <objc/runtime.h>
#import <stdlib.h>
#import <unistd.h>

/*
 * Diagnostic companion for Crane 1.3.9 on the measured iOS 27 SRD build.
 *
 * Runtime evidence from the preceding diagnostic build showed both candidate
 * methods executing without observing the sentinel. Crane's hook therefore
 * sits above the early compatibility hook and inserts the sentinel after the
 * compatibility implementation returns. Install once after tweak setup has
 * settled so this implementation wraps Crane's final producer.
 */

static NSString *const OSkyCraneContainerSentinel =
    @"com.opa334.crane.to-replace-with-container-selection";
static NSString *const OSkyDiagnosticsPath =
    @"/var/mobile/Library/Logs/0-Sky/CraneMenuDiagnostics.json";
static NSString *const OSkyFallbackDiagnosticsPath =
    @"/tmp/0sky-crane-menu.json";

static NSArray *(*OSkyOriginalApplicationShortcutItems)(id, SEL);
static NSArray *(*OSkyOriginalEffectiveShortcutItems)(id, SEL, id);
static NSArray *(*OSkyOriginalMenuChildren)(id, SEL);
static id (*OSkyCraneReplacementMenu)(void);
static NSInteger OSkyCompatState;
static NSUInteger OSkyInstallAttempts;
static NSUInteger OSkyProducerCalls;
static NSUInteger OSkyProviderCalls;
static NSUInteger OSkySentinelsSeen;
static NSUInteger OSkyReplacementCount;
static NSUInteger OSkyEmptyContainerResults;
static NSUInteger OSkyMenuChildrenCalls;
static BOOL OSkyIconViewFound;
static BOOL OSkyIconViewShortcutFound;
static BOOL OSkyIconViewContainersFound;
static BOOL OSkyProviderFound;
static BOOL OSkyProviderSelectorFound;
static BOOL OSkyCraneImageLoaded;
static BOOL OSkyCraneImageVerified;
static BOOL OSkyReplacementSymbolFound;
static BOOL OSkyMenuChildrenFound;
static NSString *OSkyLastReceiverClass;
static NSString *OSkyLastProducerClass;
static NSArray *OSkyContainerSelectorOwners;
static NSArray *OSkyIconViewRelevantMethods;
static NSArray *OSkyProviderRelevantMethods;
static const void *OSkyReplacementChildrenKey = &OSkyReplacementChildrenKey;

static NSString *const OSkyReviewedCraneSBHash =
    @"3b1773763336606936e140ca21087197f0c2746a563cadf089ed608f2899f523";

static BOOL OSkyRelevantMethodName(NSString *name) {
    if (!name.length) return NO;
    NSArray *needles = @[@"Shortcut", @"shortcut", @"crane", @"ContextMenu",
                         @"contextMenu"];
    for (NSString *needle in needles) {
        if ([name containsString:needle]) return YES;
    }
    return NO;
}

static NSArray *OSkyRelevantMethodsForClass(Class cls) {
    if (!cls) return @[];
    NSMutableArray *result = [NSMutableArray array];
    unsigned int count = 0;
    Method *methods = class_copyMethodList(cls, &count);
    unsigned int limit = MIN(count, 1024U);
    for (unsigned int index = 0; index < limit && result.count < 96; index++) {
        const char *name = sel_getName(method_getName(methods[index]));
        NSString *value = name ? [NSString stringWithUTF8String:name] : nil;
        if (OSkyRelevantMethodName(value)) [result addObject:value];
    }
    free(methods);
    return result;
}

static NSArray *OSkyDirectOwnersOfSelector(SEL selector) {
    NSMutableArray *owners = [NSMutableArray array];
    int total = objc_getClassList(NULL, 0);
    if (total <= 0) return owners;
    int capacity = MIN(total, 16384);
    Class *classes = (Class *)calloc((size_t)capacity, sizeof(Class));
    if (!classes) return owners;
    int found = objc_getClassList(classes, capacity);
    int limit = MIN(found, capacity);
    for (int index = 0; index < limit && owners.count < 64; index++) {
        unsigned int methodCount = 0;
        Method *methods = class_copyMethodList(classes[index], &methodCount);
        unsigned int methodLimit = MIN(methodCount, 2048U);
        for (unsigned int methodIndex = 0; methodIndex < methodLimit; methodIndex++) {
            if (method_getName(methods[methodIndex]) == selector) {
                const char *name = class_getName(classes[index]);
                if (name) [owners addObject:[NSString stringWithUTF8String:name]];
                break;
            }
        }
        free(methods);
    }
    free(classes);
    return owners;
}

static NSString *OSkySHA256ForFile(NSString *path) {
    NSData *data = [NSData dataWithContentsOfFile:path options:NSDataReadingMappedIfSafe
                                            error:nil];
    if (!data) return nil;
    unsigned char digest[CC_SHA256_DIGEST_LENGTH];
    CC_SHA256(data.bytes, (CC_LONG)data.length, digest);
    NSMutableString *value = [NSMutableString stringWithCapacity:64];
    for (NSUInteger index = 0; index < sizeof(digest); index++) {
        [value appendFormat:@"%02x", digest[index]];
    }
    return value;
}

static void OSkyRefreshImageState(void) {
    OSkyCraneImageLoaded = NO;
    OSkyCraneImageVerified = NO;
    OSkyReplacementSymbolFound = NO;
    OSkyCraneReplacementMenu = NULL;
    uint32_t count = _dyld_image_count();
    for (uint32_t index = 0; index < count; index++) {
        const char *name = _dyld_get_image_name(index);
        if (!name) continue;
        NSString *path = [NSString stringWithUTF8String:name];
        if ([[path lastPathComponent] isEqualToString:@"CraneSB.dylib"]) {
            OSkyCraneImageLoaded = YES;
            OSkyCraneImageVerified = [[OSkySHA256ForFile(path) lowercaseString]
                isEqualToString:OSkyReviewedCraneSBHash];
            if (OSkyCraneImageVerified) {
                void *handle = dlopen(path.fileSystemRepresentation,
                                      RTLD_NOW | RTLD_NOLOAD);
                if (handle) {
                    OSkyCraneReplacementMenu =
                        (id (*)(void))dlsym(handle, "crane_replacementMenu");
                }
                if (!OSkyCraneReplacementMenu) {
                    OSkyCraneReplacementMenu =
                        (id (*)(void))dlsym(RTLD_DEFAULT,
                                           "crane_replacementMenu");
                }
                OSkyReplacementSymbolFound = OSkyCraneReplacementMenu != NULL;
            }
            break;
        }
    }
}

static void OSkyWriteDiagnostics(void) {
    @autoreleasepool {
        NSDictionary *report = @{
            @"schema": @1,
            @"adapter": @"ios27-springboard-menu-children-v6",
            @"timestamp": @([[NSDate date] timeIntervalSince1970]),
            @"pid": @(getpid()),
            @"state": @(OSkyCompatState),
            @"install_attempts": @(OSkyInstallAttempts),
            @"crane_image_loaded": @(OSkyCraneImageLoaded),
            @"crane_image_verified": @(OSkyCraneImageVerified),
            @"replacement_symbol_found": @(OSkyReplacementSymbolFound),
            @"menu_children_found": @(OSkyMenuChildrenFound),
            @"icon_view_found": @(OSkyIconViewFound),
            @"icon_view_shortcut_found": @(OSkyIconViewShortcutFound),
            @"icon_view_containers_found": @(OSkyIconViewContainersFound),
            @"provider_found": @(OSkyProviderFound),
            @"provider_selector_found": @(OSkyProviderSelectorFound),
            @"container_selector_direct_owners": OSkyContainerSelectorOwners ?: @[],
            @"icon_view_relevant_methods": OSkyIconViewRelevantMethods ?: @[],
            @"provider_relevant_methods": OSkyProviderRelevantMethods ?: @[],
            @"producer_calls": @(OSkyProducerCalls),
            @"provider_calls": @(OSkyProviderCalls),
            @"menu_children_calls": @(OSkyMenuChildrenCalls),
            @"sentinels_seen": @(OSkySentinelsSeen),
            @"replacements": @(OSkyReplacementCount),
            @"empty_container_results": @(OSkyEmptyContainerResults),
            @"last_receiver_class": OSkyLastReceiverClass ?: @"",
            @"last_container_producer_class": OSkyLastProducerClass ?: @"",
        };
        NSError *error = nil;
        NSData *json = [NSJSONSerialization dataWithJSONObject:report
                                                       options:NSJSONWritingPrettyPrinted
                                                         error:&error];
        if (!json || error) return;
        NSString *directory = [OSkyDiagnosticsPath stringByDeletingLastPathComponent];
        [[NSFileManager defaultManager] createDirectoryAtPath:directory
                                  withIntermediateDirectories:YES
                                                   attributes:nil
                                                        error:nil];
        if (![json writeToFile:OSkyDiagnosticsPath
                       options:NSDataWritingAtomic
                         error:nil]) {
            [json writeToFile:OSkyFallbackDiagnosticsPath
                      options:NSDataWritingAtomic
                        error:nil];
        }
    }
}

static id OSkyContainerProducer(id receiver, id secondary) {
    SEL selector = sel_registerName("craneContainersApplicationShortcutItems");
    if ([receiver respondsToSelector:selector]) return receiver;
    if ([secondary respondsToSelector:selector]) return secondary;
    return nil;
}

static NSArray *OSkyReplaceSentinels(NSArray *items, id receiver, id secondary) {
    if (![items isKindOfClass:NSArray.class]) return items;
    id producer = OSkyContainerProducer(receiver, secondary);
    NSMutableArray *replacement = nil;
    NSUInteger index = 0;
    for (id item in items) {
        NSString *type = nil;
        SEL typeSelector = sel_registerName("type");
        if ([item respondsToSelector:typeSelector]) {
            type = ((id (*)(id, SEL))objc_msgSend)(item, typeSelector);
        }
        if ([type isEqualToString:OSkyCraneContainerSentinel]) {
            OSkySentinelsSeen += 1;
            if (producer) {
                OSkyLastProducerClass = NSStringFromClass([producer class]);
                SEL containersSelector = sel_registerName(
                    "craneContainersApplicationShortcutItems");
                NSArray *containers = ((id (*)(id, SEL))objc_msgSend)(
                    producer, containersSelector);
                if ([containers isKindOfClass:NSArray.class] && containers.count) {
                    if (!replacement) replacement = [items mutableCopy];
                    [replacement removeObjectAtIndex:index];
                    NSIndexSet *indexes = [NSIndexSet indexSetWithIndexesInRange:
                        NSMakeRange(index, containers.count)];
                    [replacement insertObjects:containers atIndexes:indexes];
                    index += containers.count;
                    OSkyReplacementCount += 1;
                    OSkyCompatState = 4;
                    continue;
                }
                OSkyEmptyContainerResults += 1;
            }
        }
        index += 1;
    }
    return replacement ?: items;
}

static NSArray *OSkyApplicationShortcutItems(id self, SEL selector) {
    OSkyProducerCalls += 1;
    OSkyLastReceiverClass = NSStringFromClass([self class]);
    NSArray *items = OSkyOriginalApplicationShortcutItems(self, selector);
    NSArray *result = OSkyReplaceSentinels(items, self, nil);
    OSkyWriteDiagnostics();
    return result;
}

static NSArray *OSkyEffectiveShortcutItems(id self, SEL selector, id iconView) {
    OSkyProviderCalls += 1;
    OSkyLastReceiverClass = NSStringFromClass([self class]);
    NSArray *items = OSkyOriginalEffectiveShortcutItems(self, selector, iconView);
    NSArray *result = OSkyReplaceSentinels(items, self, iconView);
    OSkyWriteDiagnostics();
    return result;
}

static NSArray *OSkyMenuChildren(id self, SEL selector) {
    OSkyMenuChildrenCalls += 1;
    NSArray *cached = objc_getAssociatedObject(self, OSkyReplacementChildrenKey);
    if (cached) return cached;
    NSArray *children = OSkyOriginalMenuChildren(self, selector);
    if (![children isKindOfClass:NSArray.class] || !OSkyCraneReplacementMenu) {
        return children;
    }
    NSMutableArray *replacement = nil;
    NSUInteger index = 0;
    for (id child in children) {
        NSString *title = nil;
        SEL titleSelector = sel_registerName("title");
        if ([child respondsToSelector:titleSelector]) {
            title = ((id (*)(id, SEL))objc_msgSend)(child, titleSelector);
        }
        if ([title isEqualToString:OSkyCraneContainerSentinel]) {
            OSkySentinelsSeen += 1;
            id menu = OSkyCraneReplacementMenu();
            if (menu) {
                if (!replacement) replacement = [children mutableCopy];
                replacement[index] = menu;
                OSkyReplacementCount += 1;
                OSkyCompatState = 4;
                OSkyLastProducerClass = @"CraneSB.crane_replacementMenu";
            } else {
                OSkyEmptyContainerResults += 1;
            }
        }
        index += 1;
    }
    if (replacement) {
        NSArray *immutable = [replacement copy];
        objc_setAssociatedObject(self, OSkyReplacementChildrenKey, immutable,
                                 OBJC_ASSOCIATION_RETAIN_NONATOMIC);
        OSkyWriteDiagnostics();
        return immutable;
    }
    return children;
}

static void OSkyInstallCraneSpringBoardCompat(void) {
    OSkyInstallAttempts += 1;
    OSkyRefreshImageState();

    Class iconView = objc_getClass("SBIconView");
    Class provider = objc_getClass(
        "SBHIconViewApplicationShortcutsContextMenuProvider");
    Class menu = objc_getClass("UIMenu");
    SEL shortcutSelector = sel_registerName("applicationShortcutItems");
    SEL containersSelector = sel_registerName(
        "craneContainersApplicationShortcutItems");
    SEL providerSelector = sel_registerName(
        "effectiveApplicationShortcutItemsForIconView:");
    SEL childrenSelector = sel_registerName("children");

    OSkyIconViewFound = iconView != Nil;
    OSkyProviderFound = provider != Nil;
    Method shortcutMethod = iconView ?
        class_getInstanceMethod(iconView, shortcutSelector) : NULL;
    Method containersMethod = iconView ?
        class_getInstanceMethod(iconView, containersSelector) : NULL;
    Method providerMethod = provider ?
        class_getInstanceMethod(provider, providerSelector) : NULL;
    Method menuChildrenMethod = menu ?
        class_getInstanceMethod(menu, childrenSelector) : NULL;
    OSkyIconViewShortcutFound = shortcutMethod != NULL;
    OSkyIconViewContainersFound = containersMethod != NULL;
    OSkyProviderSelectorFound = providerMethod != NULL;
    OSkyMenuChildrenFound = menuChildrenMethod != NULL;
    OSkyContainerSelectorOwners = OSkyDirectOwnersOfSelector(containersSelector);
    OSkyIconViewRelevantMethods = OSkyRelevantMethodsForClass(iconView);
    OSkyProviderRelevantMethods = OSkyRelevantMethodsForClass(provider);

    BOOL active = NO;
    if (shortcutMethod) {
        IMP current = method_getImplementation(shortcutMethod);
        if (current != (IMP)OSkyApplicationShortcutItems) {
            OSkyOriginalApplicationShortcutItems =
                (NSArray *(*)(id, SEL))current;
            method_setImplementation(shortcutMethod,
                                     (IMP)OSkyApplicationShortcutItems);
        }
        active = YES;
    }
    if (providerMethod) {
        IMP current = method_getImplementation(providerMethod);
        if (current != (IMP)OSkyEffectiveShortcutItems) {
            OSkyOriginalEffectiveShortcutItems =
                (NSArray *(*)(id, SEL, id))current;
            method_setImplementation(providerMethod,
                                     (IMP)OSkyEffectiveShortcutItems);
        }
        active = YES;
    }
    if (menuChildrenMethod && OSkyCraneImageVerified &&
            OSkyCraneReplacementMenu) {
        IMP current = method_getImplementation(menuChildrenMethod);
        if (current != (IMP)OSkyMenuChildren) {
            OSkyOriginalMenuChildren = (NSArray *(*)(id, SEL))current;
            method_setImplementation(menuChildrenMethod, (IMP)OSkyMenuChildren);
        }
        active = YES;
    }
    OSkyCompatState = active ? 2 : 1;
    OSkyWriteDiagnostics();
}

__attribute__((constructor)) static void OSkyScheduleCraneSpringBoardCompat(void) {
    @autoreleasepool {
        dispatch_after(dispatch_time(DISPATCH_TIME_NOW,
                                     (int64_t)(5 * NSEC_PER_SEC)),
                       dispatch_get_main_queue(), ^{
            OSkyInstallCraneSpringBoardCompat();
        });
    }
}

__attribute__((visibility("default")))
NSInteger OSkyCraneSpringBoardCompatStatus(void) {
    return OSkyCompatState;
}

__attribute__((visibility("default")))
NSUInteger OSkyCraneSpringBoardCompatReplacementCount(void) {
    return OSkyReplacementCount;
}
