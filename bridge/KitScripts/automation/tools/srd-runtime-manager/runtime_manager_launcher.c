#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

/*
 * launchd starts this tiny, trust-cached executable from the sealed Cryptex.
 * The exact same signed bytes are also copied to /var/jb/usr/bin under the
 * names srd-runtime-manager and crypstore-appctl. iOS 27 refuses direct exec
 * of otherwise valid #! scripts from the rootless prefix, so this native
 * multiplexer gives both tools a normal, stable command-line entry point.
 *
 * The policy and Python programs remain in /var/jb so package upgrades do not
 * require embedding policy in the launcher. KeepAlive retries only in daemon
 * mode while /var/jb is unavailable during early boot.
 */
static const char *basename_of(const char *path) {
    const char *slash = strrchr(path ? path : "", '/');
    return slash ? slash + 1 : path;
}

static int run_cli(const char *python, const char *program, int argc,
                   char *const original_argv[]) {
    /* python, program, original arguments excluding argv[0], NULL */
    char **child = calloc((size_t)argc + 2, sizeof(char *));
    if (child == NULL) {
        fprintf(stderr, "0-Sky runtime launcher: out of memory\n");
        return 71;
    }
    child[0] = (char *)python;
    child[1] = (char *)program;
    for (int index = 1; index < argc; ++index) {
        child[index + 1] = original_argv[index];
    }
    child[argc + 1] = NULL;
    execv(python, child);
    fprintf(stderr, "0-Sky runtime launcher: execv failed: %s\n",
            strerror(errno));
    free(child);
    return 126;
}

int main(int argc, char *argv[]) {
    const char *python = "/var/jb/usr/bin/python3";
    const char *manager = "/var/jb/usr/local/libexec/srd-runtime-manager.py";
    const char *appctl = "/var/jb/usr/local/libexec/crypstore-appctl.py";
    const char *name = basename_of(argc > 0 ? argv[0] : "");

    setenv("HOME", "/var/jb/var/root", 1);
    setenv("PATH", "/var/jb/usr/bin:/var/jb/usr/sbin:/var/jb/bin:/var/jb/sbin:/usr/bin:/bin:/usr/sbin:/sbin", 1);

    if (strcmp(name, "crypstore-appctl") == 0) {
        return run_cli(python, appctl, argc, argv);
    }
    if (strcmp(name, "srd-runtime-manager") == 0 || argc > 1) {
        return run_cli(python, manager, argc, argv);
    }

    char *const daemon_argv[] = {
        (char *)python, (char *)manager, (char *)"daemon", NULL
    };
    for (;;) {
        if (access(python, X_OK) == 0 && access(manager, R_OK) == 0) {
            execv(python, daemon_argv);
            fprintf(stderr, "srd-runtime-manager launcher: execv failed: %s\n",
                    strerror(errno));
        } else {
            fprintf(stderr, "srd-runtime-manager launcher: waiting for /var/jb\n");
        }
        sleep(5);
    }
}
