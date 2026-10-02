#import <Foundation/Foundation.h>
#import <objc/runtime.h>
#import <dlfcn.h>

static NSArray<NSDictionary *> *methodsForClass(Class cls) {
    unsigned int count = 0;
    Method *methods = class_copyMethodList(cls, &count);
    NSMutableArray *result = [NSMutableArray arrayWithCapacity:count];
    for (unsigned int index = 0; index < count; index++) {
        SEL selector = method_getName(methods[index]);
        const char *types = method_getTypeEncoding(methods[index]);
        [result addObject:@{
            @"selector": NSStringFromSelector(selector),
            @"types": types ? [NSString stringWithUTF8String:types] : @"",
        }];
    }
    free(methods);
    [result sortUsingComparator:^NSComparisonResult(NSDictionary *left, NSDictionary *right) {
        return [left[@"selector"] compare:right[@"selector"]];
    }];
    return result;
}

int main(int argc, const char *argv[]) {
    @autoreleasepool {
        const char *libraryPath = "/var/jb/usr/lib/libcrane.dylib";
        void *handle = dlopen(libraryPath, RTLD_NOW | RTLD_LOCAL);
        if (!handle) {
            fprintf(stderr, "libcrane load failed: %s\n", dlerror());
            return 2;
        }

        Class craneManager = NSClassFromString(@"CraneManager");
        if (!craneManager) {
            fprintf(stderr, "CraneManager class is unavailable\n");
            return 3;
        }

        NSDictionary *report = @{
            @"class": NSStringFromClass(craneManager),
            @"instance_methods": methodsForClass(craneManager),
            @"class_methods": methodsForClass(object_getClass(craneManager)),
        };
        NSData *json = [NSJSONSerialization dataWithJSONObject:report options:NSJSONWritingPrettyPrinted error:nil];
        fwrite(json.bytes, 1, json.length, stdout);
        fputc('\n', stdout);
        dlclose(handle);
    }
    return 0;
}
