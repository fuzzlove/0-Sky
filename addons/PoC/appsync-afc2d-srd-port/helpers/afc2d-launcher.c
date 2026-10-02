#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

extern void AFC2ShimAnchor(void);

int main(void)
{
    AFC2ShimAnchor();
    const char *service = getenv("LOCKDOWN_MACH_SERVICE");
    if (service == NULL || service[0] == '\0') {
        fputs("afc2d-launcher: LOCKDOWN_MACH_SERVICE is missing\n", stderr);
        return 2;
    }

    if (setenv("DYLD_INSERT_LIBRARIES",
            "/var/jb/usr/lib/afc2d-xpc-shim.dylib", 1) != 0) {
        fprintf(stderr, "afc2d-launcher: setenv failed: %s\n", strerror(errno));
        return 3;
    }

    char *const arguments[] = {
        "/var/jb/usr/libexec/afc2d",
        NULL,
    };
    execv(arguments[0], arguments);
    fprintf(stderr, "afc2d-launcher: execv failed: %s\n", strerror(errno));
    return 4;
}
