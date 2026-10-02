/* AFC2 - the original definition of "jailbreak"
 * Copyright (C) 2014  Jay Freeman (saurik)
 * Copyright (C) 2018  Cannathea
*/

/* GNU General Public License, Version 3 {{{ */
/*
 * Cydia is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published
 * by the Free Software Foundation, either version 3 of the License,
 * or (at your option) any later version.
 *
 * Cydia is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with Cydia.  If not, see <http://www.gnu.org/licenses/>.
**/
/* }}} */

#import <CoreFoundation/CoreFoundation.h>
#import <Foundation/Foundation.h>
#import <dlfcn.h>
#import <mach-o/dyld.h>
#import <mach-o/loader.h>
#import <ptrauth.h>
#import <rootless.h>

#include <string.h>
#include <sys/mman.h>
#include <unistd.h>

// This authenticated import slot is build-specific. Do not touch an unknown lockdownd.
static const uintptr_t kCFDictionaryGetValueSlotOffset = 0xd0eb8;
static const uint8_t kExpectedLockdownUUID[16] = {
    0xc5, 0x9e, 0x0b, 0xd6, 0x8b, 0x64, 0x32, 0xdd,
    0xa3, 0x3a, 0x26, 0x70, 0x80, 0x1c, 0xd9, 0xe4,
};

typedef const void *(*CFDictionaryGetValueFunction)(CFDictionaryRef dictionary, const void *key);
static CFDictionaryGetValueFunction OriginalCFDictionaryGetValue;

static NSDictionary *AFC2ServiceDefinition(void)
{
    static NSDictionary *service;
    static dispatch_once_t onceToken;
    dispatch_once(&onceToken, ^{
        service = @{
            @"AllowUnactivatedService": @true,
            @"Label": @"com.apple.afc2",
            @"ProgramArguments": @[ROOT_PATH_NS(@"/usr/libexec/afc2d")],
        };
    });
    return service;
}

static bool AFC2ServiceKey(CFStringRef key)
{
    return key != NULL
        && CFGetTypeID(key) == CFStringGetTypeID()
        && CFStringCompare(key, CFSTR("com.apple.afc2"), 0) == kCFCompareEqualTo;
}

static bool LockdownBuildMatches(const struct mach_header_64 *header)
{
    if (header == NULL || header->magic != MH_MAGIC_64) {
        return false;
    }

    const uint8_t *cursor = (const uint8_t *)header + sizeof(*header);
    for (uint32_t index = 0; index < header->ncmds; ++index) {
        const struct load_command *command = (const struct load_command *)cursor;
        if (command->cmdsize < sizeof(*command)) {
            return false;
        }
        if (command->cmd == LC_UUID && command->cmdsize >= sizeof(struct uuid_command)) {
            const struct uuid_command *uuid = (const struct uuid_command *)command;
            return memcmp(uuid->uuid, kExpectedLockdownUUID, sizeof(kExpectedLockdownUUID)) == 0;
        }
        cursor += command->cmdsize;
    }
    return false;
}

static const void *AFC2CFDictionaryGetValue(CFDictionaryRef dictionary, const void *key)
{
    const void *value = OriginalCFDictionaryGetValue(dictionary, key);
    if (value == NULL && AFC2ServiceKey((CFStringRef)key)) {
        return (__bridge const void *)AFC2ServiceDefinition();
    }
    return value;
}

%ctor
{
    const struct mach_header_64 *header =
        (const struct mach_header_64 *)_dyld_get_image_header(0);
    if (!LockdownBuildMatches(header)) {
        return;
    }

    void **slot = (void **)((uint8_t *)header + kCFDictionaryGetValueSlotOffset);
    void *resolved = dlsym(RTLD_DEFAULT, "CFDictionaryGetValue");
    if (resolved == NULL
        || ptrauth_strip(*slot, ptrauth_key_function_pointer)
            != ptrauth_strip(resolved, ptrauth_key_function_pointer)) {
        return;
    }

    OriginalCFDictionaryGetValue = (CFDictionaryGetValueFunction)resolved;
    long pageSize = sysconf(_SC_PAGESIZE);
    if (pageSize <= 0) {
        return;
    }
    uintptr_t page = (uintptr_t)slot & ~((uintptr_t)pageSize - 1);
    if (mprotect((void *)page, (size_t)pageSize, PROT_READ | PROT_WRITE) != 0) {
        return;
    }

    void *replacement = ptrauth_sign_unauthenticated(
        (void *)&AFC2CFDictionaryGetValue,
        ptrauth_key_function_pointer,
        ptrauth_blend_discriminator(slot, 0)
    );
    __atomic_store_n(slot, replacement, __ATOMIC_RELEASE);
    mprotect((void *)page, (size_t)pageSize, PROT_READ);
}
