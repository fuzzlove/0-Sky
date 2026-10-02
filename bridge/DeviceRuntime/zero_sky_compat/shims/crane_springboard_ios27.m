#import <Foundation/Foundation.h>
#import <objc/message.h>
#import <objc/runtime.h>

/*
 * Crane 1.3.9 inserts a synthetic shortcut whose type is
 * com.opa334.crane.to-replace-with-container-selection.  On older iOS builds
 * Crane replaced that marker while UIMenu built its interface action group.
 * iOS 27 removed that UIMenu method and now asks SpringBoardHome's application
 * shortcut provider for the effective SBSApplicationShortcutItem array.
 *
 * CraneSB already installs -craneContainersApplicationShortcutItems on
 * SBIconView and that method returns the correctly named, actionable items.
 * This exact-build companion moves only the replacement point to the current
 * provider method; it does not implement container lookup or activation.
 */

static NSArray *(*OSkyOriginalEffectiveShortcutItems)(id, SEL, id);
static NSInteger OSkyCraneSpringBoardCompatState;

static NSArray *OSkyEffectiveShortcutItems(id self, SEL selector, id iconView) {
    NSArray *items = OSkyOriginalEffectiveShortcutItems(self, selector, iconView);
    if (![items isKindOfClass:NSArray.class]) return items;

    SEL containersSelector = sel_registerName(
        "craneContainersApplicationShortcutItems");
    if (!class_getInstanceMethod(object_getClass(iconView) ? [iconView class] : Nil,
                                 containersSelector)) {
        return items;
    }

    NSMutableArray *replacement = nil;
    NSUInteger index = 0;
    for (id item in items) {
        NSString *type = nil;
        SEL typeSelector = sel_registerName("type");
        if ([item respondsToSelector:typeSelector]) {
            type = ((id (*)(id, SEL))objc_msgSend)(item, typeSelector);
        }
        if ([type isEqualToString:
                @"com.opa334.crane.to-replace-with-container-selection"]) {
            NSArray *containers = ((id (*)(id, SEL))objc_msgSend)(
                iconView, containersSelector);
            if ([containers isKindOfClass:NSArray.class] && containers.count) {
                if (!replacement) {
                    replacement = [items mutableCopy];
                }
                [replacement removeObjectAtIndex:index];
                NSIndexSet *indexes = [NSIndexSet
                    indexSetWithIndexesInRange:NSMakeRange(index, containers.count)];
                [replacement insertObjects:containers atIndexes:indexes];
                index += containers.count;
                continue;
            }
        }
        index += 1;
    }
    return replacement ?: items;
}

__attribute__((constructor)) static void OSkyInstallCraneSpringBoardCompat(void) {
    @autoreleasepool {
        Class provider = objc_getClass(
            "SBHIconViewApplicationShortcutsContextMenuProvider");
        SEL selector = sel_registerName(
            "effectiveApplicationShortcutItemsForIconView:");
        Method method = provider ? class_getInstanceMethod(provider, selector) : NULL;
        Class iconView = objc_getClass("SBIconView");
        SEL containersSelector = sel_registerName(
            "craneContainersApplicationShortcutItems");
        if (!method || !iconView ||
                !class_getInstanceMethod(iconView, containersSelector)) {
            OSkyCraneSpringBoardCompatState = 1;
            return;
        }
        OSkyOriginalEffectiveShortcutItems =
            (NSArray *(*)(id, SEL, id))method_getImplementation(method);
        method_setImplementation(method, (IMP)OSkyEffectiveShortcutItems);
        OSkyCraneSpringBoardCompatState = 2;
    }
}

__attribute__((visibility("default")))
NSInteger OSkyCraneSpringBoardCompatStatus(void) {
    return OSkyCraneSpringBoardCompatState;
}
