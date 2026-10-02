#include <dispatch/dispatch.h>
#include <os/log.h>
#include <stdint.h>
#include <stdlib.h>
#include <xpc/xpc.h>

// Referenced by the launcher so the runtime cryptex dependency scanner carries
// and trusts this dylib before the helper's subsequent exec.
void AFC2ShimAnchor(void) {}

extern xpc_connection_t AFC2OriginalCreateMachService(
    const char *, dispatch_queue_t, uint64_t)
    __asm("_xpc_connection_create_mach_service");

static xpc_connection_t AFC2CreateMachService(
    const char *name, dispatch_queue_t queue, uint64_t flags)
{
    const char *service = getenv("LOCKDOWN_MACH_SERVICE");
    if (service == NULL || service[0] == '\0') {
        service = name;
    }
    os_log_error(OS_LOG_DEFAULT,
        "[AFC2] using lockdown Mach service %{public}s", service);
    return AFC2OriginalCreateMachService(service, queue, flags);
}

#define DYLD_INTERPOSE(_replacement, _replacee) \
    __attribute__((used)) static struct { const void *replacement; const void *replacee; } \
    _afc2_interpose_##_replacee __attribute__((section("__DATA,__interpose"))) = { \
        (const void *)(uintptr_t)&_replacement, (const void *)(uintptr_t)&_replacee \
    }

DYLD_INTERPOSE(AFC2CreateMachService, AFC2OriginalCreateMachService);
