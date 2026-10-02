#!/usr/bin/env python3
"""Install a read-only, fixed-path SRD runtime diagnostics endpoint."""
from __future__ import annotations

import argparse
import asyncio
import plistlib
import shutil
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path


HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[1]
INSTALLER = ROOT / "bridge/KitScripts/runtime-generation"
IDENTIFIER = "com.liquidsky.runtime.diag6"
VERSION = "1.0.2"

SOURCE = r'''
#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <unistd.h>

static const char *paths[] = {
    "/var/jb/var/lib/srd-runtime/registry.json",
    "/var/jb/var/lib/srd-runtime/injection-state.json",
    "/var/jb/var/lib/srd-runtime/injection-quarantine.json",
    "/var/jb/var/lib/srd-runtime/events.jsonl",
    "/var/mobile/Library/Logs/srd-runtime-manager.log",
    "/var/jb/var/log/srd-runtime-manager.log",
    "/var/jb/var/log/cranehelperd.stdout.log",
    "/var/jb/var/log/cranehelperd.stderr.log",
    "/var/jb/usr/local/libexec/srd-runtime-manager.py",
    "/var/jb/etc/srd-runtime-manager.json",
    "/var/jb/usr/lib/libcrane.dylib",
    "/var/jb/usr/lib/libsandy.dylib",
    "/var/jb/usr/lib/libellekit.dylib",
    "/var/jb/Library/MobileSubstrate/DynamicLibraries/CraneSB.dylib",
    "/var/jb/Library/MobileSubstrate/DynamicLibraries/CraneSupport.dylib",
    NULL
};

static void send_all(int fd, const void *buffer, size_t length) {
    const char *cursor = (const char *)buffer;
    while (length) {
        ssize_t sent = send(fd, cursor, length, 0);
        if (sent <= 0) return;
        cursor += sent;
        length -= (size_t)sent;
    }
}

static void serve(int client) {
    char header[1024];
    char buffer[16384];
    for (size_t index = 0; paths[index]; index++) {
        struct stat st;
        int fd = open(paths[index], O_RDONLY | O_NOFOLLOW);
        if (fd < 0 || fstat(fd, &st) || !S_ISREG(st.st_mode) || st.st_size > 8 * 1024 * 1024) {
            if (fd >= 0) close(fd);
            int count = snprintf(header, sizeof(header), "\n===== %s =====\nERROR %d\n", paths[index], errno);
            send_all(client, header, (size_t)count);
            continue;
        }
        int count = snprintf(header, sizeof(header), "\n===== %s (%lld bytes) =====\n", paths[index], (long long)st.st_size);
        send_all(client, header, (size_t)count);
        ssize_t got;
        while ((got = read(fd, buffer, sizeof(buffer))) > 0) send_all(client, buffer, (size_t)got);
        close(fd);
        send_all(client, "\n", 1);
    }
}

int main(void) {
    int server = socket(AF_INET, SOCK_STREAM, 0);
    if (server < 0) return 2;
    int yes = 1;
    setsockopt(server, SOL_SOCKET, SO_REUSEADDR, &yes, sizeof(yes));
    struct sockaddr_in address = {0};
    address.sin_family = AF_INET;
    address.sin_port = htons(22027);
    address.sin_addr.s_addr = htonl(INADDR_ANY);
    if (bind(server, (struct sockaddr *)&address, sizeof(address)) || listen(server, 4)) return 3;
    for (;;) {
        int client = accept(server, NULL, NULL);
        if (client >= 0) { serve(client); close(client); }
    }
}
'''


def run(arguments: list[str]) -> None:
    subprocess.run(arguments, check=True, timeout=180)


def build(output: Path) -> Path:
    root = output / "root"
    (root / "usr/bin").mkdir(parents=True)
    (root / "Library/LaunchDaemons").mkdir(parents=True)
    source = output / "runtime-diag.c"
    source.write_text(SOURCE)
    sdk = subprocess.check_output(["xcrun", "--sdk", "iphoneos", "--show-sdk-path"], text=True).strip()
    binary = root / "usr/bin/runtime-diag"
    run(["xcrun", "--sdk", "iphoneos", "clang", "-target", "arm64e-apple-ios17.0",
         "-isysroot", sdk, "-Os", str(source), "-o", str(binary)])
    run(["codesign", "-s", "-", "--force", str(binary)])
    kit = HERE / "srdsh-work/components/zero-sky/kit/srdssh/payload-root"
    shutil.copy2(kit / "usr/bin/cryptex-run", root / "usr/bin/cryptex-run")
    launch = {
        "Label": IDENTIFIER,
        "ProgramArguments": ["/usr/bin/cryptex-run", "runtime-diag"],
        "RunAtLoad": True,
        "KeepAlive": True,
        "ThrottleInterval": 3,
    }
    (root / "Library/LaunchDaemons/runtime-diag.plist").write_bytes(plistlib.dumps(launch))
    shutil.copy2(
        ROOT / "bridge/KitScripts/automation/CrypStoreAutomation/native-install/generate_trust_cache.py",
        output / "generate_trust_cache.py",
    )
    sys.path.insert(0, str(INSTALLER))
    from install_cryptex_native import build as build_cryptex
    return Path(build_cryptex(root, IDENTIFIER, VERSION, output))


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--udid", required=True)
    parser.add_argument("--output", type=Path)
    args = parser.parse_args()
    output = args.output or HERE / "crane-repair" / (
        "runtime-diag-" + datetime.now(timezone.utc).strftime("%Y%m%d%H%M%S")
    )
    output.mkdir(parents=True, mode=0o700)
    manifest = build(output)
    sys.path.insert(0, str(INSTALLER))
    from install_cryptex_native import install
    asyncio.run(install(manifest, IDENTIFIER, args.udid))
    print(manifest)


if __name__ == "__main__":
    main()
