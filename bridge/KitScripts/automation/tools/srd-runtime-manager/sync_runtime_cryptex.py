#!/usr/bin/env python3
"""Rebuild the persistent SRD runtime trust cache from installed tweak metadata.

Credits: 0-Sky Project.
"""

from __future__ import annotations

import argparse
import atexit
import hashlib
import json
import os
import pathlib
import plistlib
import re
import shlex
import shutil
import subprocess
import sys
import tarfile
import time
import io
import tempfile


REPO = pathlib.Path(__file__).resolve().parents[2]
BASE_ROOT = REPO / "PreferenceLoader/dist/ios27-srd/support-root"
NATIVE = REPO / "CrypStoreAutomation/native-install"
MANAGER_DIR = REPO / "tools/srd-runtime-manager"
SANDBOXED_INJECTOR_DIR = MANAGER_DIR / "sandboxed-injector"
PACKAGE_NAME_PATTERN = re.compile(r"[A-Za-z0-9][A-Za-z0-9.+-]{0,254}\Z")
HOST_TOOL_DIRS = tuple(pathlib.Path(value) for value in (
    "/opt/homebrew/bin", "/usr/local/bin", "/usr/bin", "/bin"
))
CRANE_LITE_HELPER_ENTITLEMENTS = {
    "platform-application": True,
    "com.apple.private.security.container-required": False,
    "task_for_pid-allow": True,
    "get-task-allow": True,
    "com.apple.private.security.no-container": True,
    "com.apple.multitasking.termination": True,
    "com.apple.security.exception.mach-lookup.global-name": [
        "jailbreakd",
        "com.apple.cfprefsd.daemon",
        "com.apple.containermanagerd",
        "com.apple.securityd",
        "com.apple.pluginkit.pkd",
        "com.apple.lsd.xpc",
        "com.apple.accountsd.accountmanager",
        "com.apple.apsd",
    ],
}
CRANE_PAID_HELPER_ENTITLEMENTS = {
    **{key: value for key, value in CRANE_LITE_HELPER_ENTITLEMENTS.items()
       if key != "get-task-allow"},
    "com.apple.security.exception.mach-lookup.global-name": [
        "jailbreakd",
        "com.apple.mobilegestalt.xpc",
        "com.apple.cfprefsd.daemon",
        "com.apple.containermanagerd",
        "com.apple.securityd",
        "com.apple.pluginkit.pkd",
        "com.apple.lsd.xpc",
        "com.apple.accountsd.accountmanager",
        "com.apple.apsd",
    ],
}


PREFERENCE_ROOT = pathlib.PurePosixPath(
    "/var/jb/Library/PreferenceLoader/Preferences"
)


def validated_package_names(values: list[str] | None) -> list[str]:
    """Return deterministic exact dpkg identifiers supplied by the worker.

    These names describe why a full runtime rebuild was requested. They are
    deliberately not used to limit discovery because a generation must always
    contain the complete installed tweak set, including dependencies. A
    rollback may also request a rebuild after its named package was removed.
    """
    answer: set[str] = set()
    for raw in values or []:
        if not isinstance(raw, str):
            raise ValueError("runtime sync package name must be text")
        for value in raw.split(","):
            value = value.strip()
            if not value or not PACKAGE_NAME_PATTERN.fullmatch(value):
                raise ValueError("runtime sync request has an invalid package name")
            answer.add(value)
    return sorted(answer, key=str.casefold)


def find_host_tool(name: str) -> str | None:
    """Find one executable in PATH or a standard package-manager prefix.

    launchd intentionally supplies a small PATH. Build dependencies installed
    by 0-Sky's host setup therefore need bounded discovery without embedding a
    developer home directory or invoking a shell.
    """
    if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._+-]{0,63}", name):
        return None
    candidates = []
    discovered = shutil.which(name)
    if discovered:
        candidates.append(pathlib.Path(discovered))
    candidates.extend(directory / name for directory in HOST_TOOL_DIRS)
    seen: set[pathlib.Path] = set()
    for candidate in candidates:
        try:
            resolved = candidate.resolve(strict=True)
        except (OSError, RuntimeError):
            continue
        if resolved in seen:
            continue
        seen.add(resolved)
        if resolved.is_file() and os.access(resolved, os.X_OK):
            return str(resolved)
    return None


def host_tool_environment(names: tuple[str, ...]) -> tuple[dict[str, str], dict[str, str]]:
    """Resolve helper executables and expose their directories to subprocesses."""
    tools: dict[str, str] = {}
    directories: list[str] = []
    for name in names:
        tool = find_host_tool(name)
        if tool is None:
            raise RuntimeError(f"{name} is required to stage the offline Python trust payload")
        tools[name] = tool
        directory = str(pathlib.Path(tool).parent)
        if directory not in directories:
            directories.append(directory)
    for directory in os.environ.get("PATH", "").split(os.pathsep):
        if directory and directory not in directories:
            directories.append(directory)
    environment = os.environ.copy()
    environment["PATH"] = os.pathsep.join(directories)
    return tools, environment


def preference_descriptor_relative(raw: str) -> pathlib.PurePosixPath | None:
    """Return a bounded rootless descriptor path, never a parent escape."""
    if not isinstance(raw, str) or len(raw) > 512 or "\x00" in raw:
        return None
    path = pathlib.PurePosixPath(raw)
    if (not path.is_absolute() or ".." in path.parts or
            not path.is_relative_to(PREFERENCE_ROOT) or path.suffix != ".plist"):
        return None
    relative = path.relative_to(PREFERENCE_ROOT)
    return relative if len(relative.parts) <= 4 else None


def read_preference_descriptor(base: list[str], remote: str) -> bytes:
    """Read one package-listed plist without following a final symlink."""
    code = """import os,pathlib,stat,sys
root=pathlib.Path('/var/jb/Library/PreferenceLoader/Preferences').resolve()
path=pathlib.Path(sys.argv[1])
if not path.resolve(strict=True).is_relative_to(root): raise SystemExit(3)
fd=os.open(path,os.O_RDONLY|os.O_NOFOLLOW)
try:
 info=os.fstat(fd)
 if not stat.S_ISREG(info.st_mode) or info.st_size>65536: raise SystemExit(4)
 data=os.read(fd,65537)
 if len(data)>65536: raise SystemExit(5)
 sys.stdout.buffer.write(data)
finally: os.close(fd)
"""
    result = ssh(base, "/var/jb/usr/bin/python3 -c " + shlex.quote(code) +
                 " " + shlex.quote(remote), show_output=False)
    if len(result.stdout) > 65536:
        raise RuntimeError("preference descriptor exceeds 64 KiB")
    return result.stdout


def include_offline_python(root: pathlib.Path) -> None:
    """Trust the immutable first-install Python payload.

    Procursus accepts and unpacks these packages before the runtime trust
    Cryptex exists, but AMFI cannot execute their binaries until the exact
    CodeDirectories are present in a research trust cache. Copy their verified
    bytes into the generation solely so generate-trust-cache admits the
    byte-identical /var/jb files used after mount.
    """
    offline = REPO.parent / "offline-python"
    packages = [
        "libgdbm6_1.23_iphoneos-arm64.deb",
        "libpython3.9_3.9.9-1_iphoneos-arm64.deb",
        "python3.9_3.9.9-1_iphoneos-arm64.deb",
        "python3_3.9.9-1_iphoneos-arm64.deb",
    ]
    tools, tool_environment = host_tool_environment(("dpkg-deb", "zstd"))
    dpkg_deb = tools["dpkg-deb"]
    with tempfile.TemporaryDirectory(prefix="0sky-python-", dir=root.parent) as temporary:
        stage = pathlib.Path(temporary)
        for name in packages:
            package = offline / name
            if not package.is_file() or package.is_symlink():
                raise RuntimeError(f"immutable offline Python package is unavailable: {package}")
            destination = stage / package.stem
            destination.mkdir()
            run([dpkg_deb, "-x", package, destination], env=tool_environment,
                show_output=False)
            payload = destination / "var/jb"
            if not payload.is_dir() or payload.is_symlink():
                raise RuntimeError(f"offline Python package has no rootless payload: {package}")
            shutil.copytree(payload, root, dirs_exist_ok=True, symlinks=True)
    marker = root / "usr/share/0-sky/offline-python-trust-ready"
    marker.parent.mkdir(parents=True, exist_ok=True)
    marker.write_text("python3.9 immutable payload admitted\n", encoding="utf-8")


def run(argv, *, data=None, timeout=1200, cwd=None, env=None, check=True, show_output=True):
    print("+", " ".join(shlex.quote(str(item)) for item in argv), flush=True)
    result = subprocess.run([str(item) for item in argv], input=data, stdout=subprocess.PIPE,
                            stderr=subprocess.STDOUT, timeout=timeout, cwd=cwd, env=env,
                            check=False)
    if result.stdout and show_output:
        print(result.stdout.decode("utf-8", "replace"), end="", flush=True)
    if check and result.returncode:
        raise RuntimeError(f"command failed with status {result.returncode}: {argv}")
    return result


def ssh_base(host: str, port: int, key: pathlib.Path, *,
             known_hosts: pathlib.Path, host_alias: str) -> list[str]:
    if (not host_alias or not known_hosts.is_file() or known_hosts.is_symlink() or
            known_hosts.stat().st_mode & 0o077):
        raise RuntimeError("device SSH host-key pin is missing or unsafe")
    answer = ["/usr/bin/ssh", "-o", "BatchMode=yes", "-o", "ConnectTimeout=10",
              "-o", "LogLevel=ERROR",
              "-o", "StrictHostKeyChecking=yes",
              "-o", f'UserKnownHostsFile="{known_hosts}"',
              "-o", "GlobalKnownHostsFile=/dev/null", "-o", f"HostKeyAlias={host_alias}",
              "-o", "IdentitiesOnly=yes", "-o", "PasswordAuthentication=no",
              "-o", "KbdInteractiveAuthentication=no",
              "-i", str(key)]
    if port:
        answer += ["-p", str(port)]
    return answer + [f"root@{host}"]


def ssh(base: list[str], command: str, *, data=None, timeout=300, check=True, show_output=True):
    return run(base + [command], data=data, timeout=timeout, check=check,
               show_output=show_output)


def reviewed_package_runtime_adapter(base: list[str], package: str) -> dict | None:
    """Read one typed package adapter and return only its reviewed runtime part."""
    if package not in ("com.opa334.crane", "com.opa334.cranelite"):
        return None
    path = f"/var/jb/usr/share/0-sky/package-adapters/{package}.json"
    command = ("/var/jb/usr/bin/python3 -c " + shlex.quote(
        "import os,stat,sys; p=sys.argv[1]; s=os.lstat(p); "
        "assert stat.S_ISREG(s.st_mode) and s.st_uid==0 and not s.st_mode&0o022 "
        "and s.st_size<=65536; sys.stdout.buffer.write(open(p,'rb').read())") +
        " " + shlex.quote(path))
    result = ssh(base, command, check=False, show_output=False)
    if result.returncode:
        return None
    try:
        value = json.loads(result.stdout)
    except (UnicodeError, ValueError) as error:
        raise RuntimeError(f"invalid typed runtime adapter for {package}") from error
    root = "/var/jb/Library/MobileSubstrate/DynamicLibraries"
    target_source = ({
        "kind": "plist-string",
        "path": "/var/mobile/Library/Preferences/com.opa334.craneliteprefs.plist",
        "key": "selectedApplication",
    } if package == "com.opa334.cranelite" else {
        "kind": "control-app-allowlist",
        "path": "/var/jb/var/lib/srd-runtime/tweak-targets/com.opa334.crane.json",
    })
    expected = {
        "required_dylibs": [root + "/CraneSB.dylib", root + "/CraneSupport.dylib"],
        "configuration_dependent": [{
            "dylib": root + "/ Crane.dylib",
            "legacy_filter": "com.apple.Foundation",
            "target_source": target_source,
            "sandbox_dependencies": [
                "/var/jb/usr/lib/libcrane.dylib",
                "/var/jb/usr/lib/libsandy.dylib",
                "/var/jb/usr/lib/libellekit.dylib",
            ],
        }],
        "process_selectors": [{
            "dylib": root + "/CraneSB.dylib",
            "executable": "/System/Library/CoreServices/SpringBoard.app/SpringBoard",
            "sandbox_dependencies": [
                "/var/jb/usr/lib/libcrane.dylib",
                "/var/jb/usr/lib/libsandy.dylib",
                "/var/jb/usr/lib/libellekit.dylib",
            ],
        }, {
            "dylib": root + "/CraneSupport.dylib",
            "executable": "/usr/sbin/cfprefsd",
            "environment": {
                "XPC_SERVICE_NAME": "com.apple.cfprefsd.xpc.daemon",
            },
            "sandbox_dependencies": [
                "/var/jb/usr/lib/libcrane.dylib",
                "/var/jb/usr/lib/libsandy.dylib",
                "/var/jb/usr/lib/libellekit.dylib",
            ],
        }],
    }
    if (not isinstance(value, dict) or value.get("schema") != 1 or
            value.get("adapter") != "crane-family-v2" or
            value.get("package") != package or value.get("runtime") != expected):
        raise RuntimeError(f"typed runtime adapter differs for {package}")
    return expected


def build_native_launcher(output: pathlib.Path, root: pathlib.Path) -> pathlib.Path:
    """Build the sealed daemon/CLI entry point whose exact bytes are trusted."""
    developer_env = os.environ.copy()
    probe = run(["/usr/bin/xcrun", "--sdk", "iphoneos", "--show-sdk-path"],
                env=developer_env, check=False, show_output=False)
    if probe.returncode:
        # xcode-select may intentionally target CommandLineTools. Discover a
        # full Xcode dynamically rather than requiring a global host change or
        # assuming the application name.
        candidates = sorted(
            (path for path in pathlib.Path("/Applications").glob("*.app/Contents/Developer")
             if (path / "Platforms/iPhoneOS.platform/Developer/SDKs").is_dir()),
            key=lambda path: (path.stat().st_mtime, str(path)),
            reverse=True,
        )
        if not candidates:
            raise RuntimeError("a full Xcode installation with an iPhoneOS SDK is required")
        developer_env["DEVELOPER_DIR"] = str(candidates[0])
        probe = run(["/usr/bin/xcrun", "--sdk", "iphoneos", "--show-sdk-path"],
                    env=developer_env, show_output=False)
    sdk = probe.stdout.decode().strip()
    clang = run(["/usr/bin/xcrun", "--sdk", "iphoneos", "--find", "clang"],
                env=developer_env, show_output=False).stdout.decode().strip()
    slices = []
    for architecture in ("arm64", "arm64e"):
        destination = output / f"srd-runtime-manager-launcher.{architecture}"
        run([clang, "-target", f"{architecture}-apple-ios15.0", "-isysroot", sdk,
             "-Os", MANAGER_DIR / "runtime_manager_launcher.c", "-o", destination])
        slices.append(destination)
    launcher = root / "usr/libexec/ellekit/srd-runtime-manager-launcher"
    launcher.parent.mkdir(parents=True, exist_ok=True)
    run(["/usr/bin/lipo", "-create", *slices, "-output", launcher])
    run(["/usr/bin/codesign", "--force", "--sign", "-", "--timestamp=none",
         "--identifier", "codes.openai.research.srd-runtime-manager-launcher",
         launcher])
    os.chmod(launcher, 0o755)
    return launcher


def build_sandboxed_injector(output: pathlib.Path, root: pathlib.Path) -> dict:
    """Build the reviewed sandbox-extension injection backend for the SRD.

    The ordinary ElleKit loader remains the default. This second backend is
    present solely for typed adapters whose exact daemon identity was reviewed
    and whose sandbox prevents mapping the package-owned dylib. Its entitlement
    set is the already measured 0-Sky loader role, and the resulting bytes are
    admitted by the same Apple-authorized research Cryptex transaction.
    """
    required = (
        "main.m", "dyld.m", "shellcode_inject.m", "rop_inject.m",
        "thread_utils.m", "task_utils.m", "arm64.m",
    )
    if any(not (SANDBOXED_INJECTOR_DIR / name).is_file() for name in required):
        raise RuntimeError("sandboxed injector source snapshot is incomplete")
    entitlements = SANDBOXED_INJECTOR_DIR / "entitlements.plist"
    expected_entitlements = {
        "com.apple.private.security.no-container": True,
        "com.apple.private.security.no-sandbox": True,
        "com.apple.security.get-movable-control-port": True,
        "com.apple.security.get-task-allow": True,
        "com.apple.system-task-ports.control": True,
        "com.apple.system-task-ports.token.control": True,
        "get-task-allow": True,
        "platform-application": True,
        "task_for_pid-allow": True,
    }
    if plistlib.loads(entitlements.read_bytes()) != expected_entitlements:
        raise RuntimeError("sandboxed injector entitlement role differs from measured loader")
    developer_env = os.environ.copy()
    sdk = run(["/usr/bin/xcrun", "--sdk", "iphoneos", "--show-sdk-path"],
              env=developer_env, show_output=False).stdout.decode().strip()
    clang = run(["/usr/bin/xcrun", "--sdk", "iphoneos", "--find", "clang"],
                env=developer_env, show_output=False).stdout.decode().strip()
    slices = []
    for architecture in ("arm64", "arm64e"):
        destination = output / f"sandboxed-injector.{architecture}"
        run([clang, "-arch", architecture, "-isysroot", sdk,
             "-miphoneos-version-min=17.0", "-fobjc-arc", "-fmodules", "-O2",
             "-I", SANDBOXED_INJECTOR_DIR,
             *(SANDBOXED_INJECTOR_DIR / name for name in required),
             "-framework", "Foundation", "-framework", "CoreFoundation",
             "-o", destination], env=developer_env)
        slices.append(destination)
    destination = root / "usr/libexec/ellekit/sandboxed-injector"
    destination.parent.mkdir(parents=True, exist_ok=True)
    run(["/usr/bin/lipo", "-create", *slices, "-output", destination])
    run(["/usr/bin/codesign", "--force", "--sign", "-", "--timestamp=none",
         "--identifier", "codes.openai.research.sandboxed-injector",
         "--entitlements", entitlements, destination])
    run(["/usr/bin/codesign", "--verify", "--strict", destination])
    os.chmod(destination, 0o755)
    return {
        "path": "/usr/libexec/ellekit/sandboxed-injector",
        "sha256": hashlib.sha256(destination.read_bytes()).hexdigest(),
        "architectures": ["arm64", "arm64e"],
        "upstream": "opa334/opainject",
        "commit": "6308f6006ee1bf548d5b58bd8ab7fb4e5a687eaf",
        "adapter": "sandbox-extension-rop-v1",
    }


def deploy_native_cli(base: list[str], launcher: pathlib.Path) -> None:
    """Install exact trust-cached launcher bytes under both rootless CLI names.

    A normal shebang script in /var/jb currently fails direct execution with
    EPERM on the iOS 27 SRD image even though invoking it through ``sh`` works.
    The sealed Cryptex authorizes this launcher's CodeDirectory, so installing
    byte-identical copies makes both public commands directly executable while
    keeping their Python implementations independently upgradeable by dpkg.
    """
    payload = launcher.read_bytes()
    digest = hashlib.sha256(payload).hexdigest()
    for destination in ("/var/jb/usr/bin/srd-runtime-manager",
                        "/var/jb/usr/bin/crypstore-appctl"):
        # The running manager may repair the same command as soon as cryptexd
        # publishes the new mount. Use a per-process staging name so the host
        # transfer and daemon self-heal cannot truncate each other's file.
        temporary = destination + f".0-sky-new.{os.getpid()}"
        ssh(base, f"cat > {shlex.quote(temporary)} && chmod 0755 {shlex.quote(temporary)}",
            data=payload, show_output=False)
        remote_digest = ssh(
            base, f"/var/jb/usr/bin/sha256sum {shlex.quote(temporary)} | /var/jb/usr/bin/cut -d' ' -f1",
            show_output=False).stdout.decode().strip()
        if remote_digest != digest:
            raise RuntimeError(f"native CLI transfer verification failed: {destination}")
        ssh(base, f"mv -f {shlex.quote(temporary)} {shlex.quote(destination)}",
            show_output=False)


def copy_preference_bundle(base: list[str], bundle_name: str, root: pathlib.Path,
                           *, repair_device: bool) -> dict:
    """Copy and authorize one installed PreferenceLoader bundle.

    The bundle name comes from an installed descriptor but is still treated as
    untrusted input.  The small tar transport is unpacked manually: paths must
    remain below the requested bundle, links and special files are rejected,
    and both member count and expanded size are bounded.
    """
    if not bundle_name or not all(c.isalnum() or c in "._+-" for c in bundle_name):
        raise RuntimeError(f"unsafe PreferenceLoader bundle name: {bundle_name!r}")
    relative = f"{bundle_name}.bundle"
    remote_root = "/var/jb/Library/PreferenceBundles"
    archive = ssh(base,
        f"/var/jb/usr/bin/tar -C {remote_root} -cf - {shlex.quote(relative)}",
        timeout=180, show_output=False).stdout
    destination_root = root / "Library/PreferenceBundles"
    destination = destination_root / relative
    shutil.rmtree(destination, ignore_errors=True)
    count = 0
    total = 0
    with tarfile.open(fileobj=io.BytesIO(archive), mode="r:") as incoming:
        for member in incoming.getmembers():
            count += 1
            total += max(member.size, 0)
            pure = pathlib.PurePosixPath(member.name)
            if (count > 10000 or total > 128 * 1024 * 1024 or pure.is_absolute()
                    or ".." in pure.parts or not pure.parts
                    or pure.parts[0] != relative
                    or not (member.isdir() or member.isfile())):
                raise RuntimeError(f"unsafe PreferenceLoader bundle member: {member.name!r}")
            output = destination_root.joinpath(*pure.parts)
            if member.isdir():
                output.mkdir(parents=True, exist_ok=True)
                output.chmod(member.mode & 0o777)
                continue
            output.parent.mkdir(parents=True, exist_ok=True)
            stream = incoming.extractfile(member)
            if stream is None:
                raise RuntimeError(f"missing tar payload: {member.name!r}")
            with output.open("wb") as handle:
                shutil.copyfileobj(stream, handle)
            output.chmod(member.mode & 0o777)

    info_path = destination / "Info.plist"
    try:
        info = plistlib.loads(info_path.read_bytes())
    except Exception as error:
        raise RuntimeError(f"invalid {relative}/Info.plist: {error}") from error
    executable_name = info.get("CFBundleExecutable") if isinstance(info, dict) else None
    if (not isinstance(executable_name, str) or not executable_name
            or "/" in executable_name or executable_name in (".", "..")):
        raise RuntimeError(f"{relative} has no safe CFBundleExecutable")
    executable = destination / executable_name
    if not executable.is_file():
        raise RuntimeError(f"{relative} executable is missing: {executable_name}")

    source_sha256 = hashlib.sha256(executable.read_bytes()).hexdigest()
    verify = run(["/usr/bin/codesign", "--verify", "--strict", executable], check=False)
    resigned = verify.returncode != 0
    if resigned:
        identifier = info.get("CFBundleIdentifier") if isinstance(info, dict) else None
        if not isinstance(identifier, str) or not identifier:
            identifier = "codes.openai.research.preference." + bundle_name
        run(["/usr/bin/codesign", "--force", "--sign", "-", "--timestamp=none",
             "--identifier", identifier, executable])
        if repair_device:
            remote = f"{remote_root}/{relative}/{executable_name}"
            ssh(base, f"cat > {shlex.quote(remote)} && chmod 0755 {shlex.quote(remote)}",
                data=executable.read_bytes(), timeout=180, show_output=False)
    run(["/usr/bin/codesign", "--verify", "--strict", executable])
    return {"bundle": bundle_name, "executable": executable_name,
            "sha256": hashlib.sha256(executable.read_bytes()).hexdigest(),
            "source_sha256": source_sha256,
            "resigned": resigned}


def copy_support_library(base: list[str], remote: str, root: pathlib.Path,
                         *, repair_device: bool) -> dict:
    """Authorize an installed package's top-level rootless support dylib."""
    name = pathlib.PurePosixPath(remote).name
    if (not remote.startswith("/var/jb/usr/lib/") or "/" in
            remote.removeprefix("/var/jb/usr/lib/") or not name.endswith(".dylib")):
        raise RuntimeError(f"unsafe support library path: {remote!r}")
    payload = ssh(base, f"cat {shlex.quote(remote)}", show_output=False).stdout
    source_sha256 = hashlib.sha256(payload).hexdigest()
    destination = root / "usr/lib" / name
    destination.parent.mkdir(parents=True, exist_ok=True)
    destination.write_bytes(payload)
    verify = run(["/usr/bin/codesign", "--verify", "--strict", destination], check=False)
    resigned = verify.returncode != 0
    if resigned:
        digest = hashlib.sha256(payload).hexdigest()
        run(["/usr/bin/codesign", "--force", "--sign", "-", "--timestamp=none",
             "--identifier", "codes.openai.research.support." + digest[:20], destination])
        if repair_device:
            ssh(base, f"cat > {shlex.quote(remote)} && chmod 0755 {shlex.quote(remote)}",
                data=destination.read_bytes(), timeout=180, show_output=False)
    run(["/usr/bin/codesign", "--verify", "--strict", destination])
    return {"path": remote,
            "sha256": hashlib.sha256(destination.read_bytes()).hexdigest(),
            "source_sha256": source_sha256,
            "resigned": resigned}


def companion_executable_path(raw: str) -> bool:
    """Accept one package-owned daemon or top-level jailbreak app executable."""
    if (not isinstance(raw, str) or len(raw) > 1024 or "\x00" in raw
            or ".." in pathlib.PurePosixPath(raw).parts):
        return False
    daemon = re.fullmatch(
        r"/var/jb/usr/(?:libexec|local/libexec|local/bin)/[A-Za-z0-9._+-]+",
        raw,
    )
    app = re.fullmatch(
        r"/var/jb/Applications/[A-Za-z0-9._+-]+\.app/[A-Za-z0-9._+-]+", raw
    )
    return bool(daemon or app)


def reviewed_legacy_companion_entitlements(package: str | None, remote: str,
                                            reviewed_adapter: bool) -> dict | None:
    """Return one exact entitlement contract from a reviewed typed adapter."""
    if reviewed_adapter and remote == "/var/jb/usr/local/libexec/cranehelperd":
        if package == "com.opa334.crane":
            return CRANE_PAID_HELPER_ENTITLEMENTS
        if package == "com.opa334.cranelite":
            return CRANE_LITE_HELPER_ENTITLEMENTS
    return None


def bundle_tree_sha256(root: pathlib.Path) -> str:
    digest = hashlib.sha256()
    for path in sorted(root.rglob("*"), key=lambda item: str(item.relative_to(root))):
        relative = str(path.relative_to(root)).encode()
        if path.is_symlink():
            kind, value = b"L", os.readlink(path).encode()
        elif path.is_file():
            kind, value = b"F", hashlib.sha256(path.read_bytes()).digest()
        elif path.is_dir():
            kind, value = b"D", b""
        else:
            kind, value = b"O", b""
        digest.update(kind + b"\0" + relative + b"\0" + value + b"\n")
    return digest.hexdigest()


def enrolled_companion_state(base: list[str], bundle_id: str,
                             app_name: str) -> dict | None:
    """Return current signed Cryptex enrollment for an exact package app."""
    if (not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9.-]{0,254}", bundle_id)
            or not re.fullmatch(r"[A-Za-z0-9._+-]+\.app", app_name)):
        return None
    probe = r'''import json,os,pathlib,re,stat,subprocess,sys
bundle,app_name=sys.argv[1:]
p=pathlib.Path('/var/jb/var/lib/crypstore')/(bundle+'.json')
try:
 m=p.lstat()
 if p.is_symlink() or not stat.S_ISREG(m.st_mode) or m.st_uid!=0 or m.st_mode&0o022 or m.st_size>65536:raise ValueError()
 s=json.loads(p.read_text())
 q=subprocess.run(['/var/jb/usr/bin/uicache','-l'],capture_output=True,text=True,timeout=30)
 prefix=bundle+' : '; paths=[x[len(prefix):].strip() for x in q.stdout.splitlines() if x.startswith(prefix)]
 if q.returncode or len(paths)!=1:raise ValueError()
 registered=os.path.realpath(paths[0])
 identifier=s.get('cryptex_identifier')
 if not isinstance(identifier,str) or not re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9.-]{0,254}',identifier):raise ValueError()
 mount_root=pathlib.Path('/private/var/run/com.apple.security.cryptexd/mnt')
 mounts=[]
 for candidate in mount_root.glob(identifier+'.*'):
  resolved=os.path.realpath(candidate)
  if (resolved.startswith(str(mount_root)+'/'+identifier+'.') and os.path.ismount(resolved) and
      (pathlib.Path(resolved)/'Applications'/app_name).is_dir()):mounts.append(resolved)
 if len(set(mounts))!=1:raise ValueError()
 mount=mounts[0]
 recorded={os.path.realpath(str(s.get(k,''))) for k in ('registered_path','observed_registered_path')}
 if (s.get('bundle_id')!=bundle or registered not in recorded or
     not registered.startswith('/private/var/containers/Bundle/Application/') or
     pathlib.Path(registered).name!=app_name or not pathlib.Path(registered).is_dir() or
     not mount.startswith('/private/var/run/com.apple.security.cryptexd/mnt/')):raise ValueError()
 out={'registered_path':registered,'expected_bundle_sha256':s.get('expected_bundle_sha256'),
      'expected_info_plist_hash':s.get('expected_info_plist_hash'),'current_mount':mount}
 if not all(isinstance(out[k],str) and len(out[k])==64 for k in ('expected_bundle_sha256','expected_info_plist_hash')):raise ValueError()
 print(json.dumps(out,separators=(',',':')))
except Exception:raise SystemExit(1)'''
    completed = ssh(
        base, "/var/jb/usr/bin/python3 -c " + shlex.quote(probe) + " " +
        shlex.quote(bundle_id) + " " + shlex.quote(app_name),
        timeout=60, check=False, show_output=False)
    if completed.returncode:
        return None
    try:
        result = json.loads(completed.stdout)
    except (ValueError, UnicodeError):
        return None
    return result if isinstance(result, dict) else None


def copy_remote_app_bundle(base: list[str], remote_app: str,
                           destination_root: pathlib.Path,
                           app_name: str) -> pathlib.Path:
    parent = str(pathlib.PurePosixPath(remote_app).parent)
    if (pathlib.PurePosixPath(remote_app).name != app_name or
            not remote_app.startswith(("/var/jb/Applications/",
                                       "/private/var/containers/Bundle/Application/"))):
        raise RuntimeError("unsafe companion app source")
    archive = ssh(base, f"/var/jb/usr/bin/tar -C {shlex.quote(parent)} -cf - "
                  f"{shlex.quote(app_name)}", timeout=180,
                  show_output=False).stdout
    destination = destination_root / app_name
    shutil.rmtree(destination, ignore_errors=True)
    count = 0
    total = 0
    with tarfile.open(fileobj=io.BytesIO(archive), mode="r:") as incoming:
        for member in incoming.getmembers():
            count += 1
            total += max(member.size, 0)
            member_path = pathlib.PurePosixPath(member.name)
            if (count > 10000 or total > 128 * 1024 * 1024
                    or member_path.is_absolute() or ".." in member_path.parts
                    or not member_path.parts or member_path.parts[0] != app_name
                    or not (member.isdir() or member.isfile())):
                raise RuntimeError(f"unsafe companion app member: {member.name!r}")
            output = destination_root.joinpath(*member_path.parts)
            if member.isdir():
                output.mkdir(parents=True, exist_ok=True)
                output.chmod(member.mode & 0o777)
                continue
            output.parent.mkdir(parents=True, exist_ok=True)
            stream = incoming.extractfile(member)
            if stream is None:
                raise RuntimeError(f"missing companion app payload: {member.name!r}")
            with output.open("wb") as handle:
                shutil.copyfileobj(stream, handle)
            output.chmod(member.mode & 0o777)
    return destination


def copy_companion_executable(base: list[str], remote: str,
                              trust_root: pathlib.Path, *,
                              package: str | None = None,
                              reviewed_adapter: bool = False) -> dict | None:
    """Copy signed app/daemon code without changing its entitlements."""
    if not companion_executable_path(remote):
        raise RuntimeError(f"unsafe companion executable path: {remote!r}")
    # dpkg-query lists bundle directories alongside files.  A top-level app
    # directory (notably _CodeSignature) matches the deliberately narrow path
    # grammar but is not a candidate executable.
    regular = ssh(base, f"test -f {shlex.quote(remote)}", check=False,
                  show_output=False)
    if regular.returncode:
        return None
    payload = ssh(base, f"cat {shlex.quote(remote)}", show_output=False).stdout
    if payload[:4] not in (b"\xcf\xfa\xed\xfe", b"\xca\xfe\xba\xbe",
                           b"\xbe\xba\xfe\xca"):
        return None
    digest = hashlib.sha256(payload).hexdigest()
    if "/Applications/" in remote:
        # An application executable's CodeDirectory contains an Info.plist
        # special slot.  Verifying a byte-identical executable after moving it
        # outside its bundle therefore fails even though the installed bundle
        # is valid.  Preserve the bounded app bundle in the trust payload and
        # verify that bundle without re-signing or changing its entitlements.
        pure_remote = pathlib.PurePosixPath(remote)
        app_name = pure_remote.parent.name
        executable_name = pure_remote.name
        destination_root = trust_root / "companions" / digest
        destination = copy_remote_app_bundle(
            base, str(pure_remote.parent), destination_root, app_name)

        try:
            info = plistlib.loads((destination / "Info.plist").read_bytes())
        except Exception as error:
            raise RuntimeError(f"invalid {app_name}/Info.plist: {error}") from error
        if (not isinstance(info, dict)
                or info.get("CFBundleExecutable") != executable_name):
            raise RuntimeError(f"{app_name} executable metadata does not match")
        local_executable = destination / executable_name
        if (not local_executable.is_file()
                or hashlib.sha256(local_executable.read_bytes()).hexdigest() != digest):
            raise RuntimeError(f"{app_name} executable changed during bundle copy")
        verification = run(
            ["/usr/bin/codesign", "--verify", "--strict", destination],
            check=False, show_output=False,
        )
        if verification.returncode:
            bundle_id = info.get("CFBundleIdentifier")
            state = (enrolled_companion_state(base, bundle_id, app_name)
                     if isinstance(bundle_id, str) else None)
            if state is None:
                raise RuntimeError(
                    "package companion app has no valid entitlement-preserving "
                    f"bundle signature and no verified Cryptex enrollment: {remote}"
                )
            destination = copy_remote_app_bundle(
                base, state["registered_path"], destination_root, app_name)
            try:
                signed_info = plistlib.loads((destination / "Info.plist").read_bytes())
            except Exception as error:
                raise RuntimeError("enrolled companion metadata is invalid") from error
            local_executable = destination / executable_name
            if (signed_info.get("CFBundleIdentifier") != bundle_id or
                    signed_info.get("CFBundleExecutable") != executable_name or
                    not local_executable.is_file() or
                    hashlib.sha256((destination / "Info.plist").read_bytes()).hexdigest() !=
                    state["expected_info_plist_hash"] or
                    bundle_tree_sha256(destination) != state["expected_bundle_sha256"]):
                raise RuntimeError(
                    "enrolled companion differs from verified Cryptex evidence")
            verification = run(
                ["/usr/bin/codesign", "--verify", "--strict", destination],
                check=False, show_output=False)
            if verification.returncode:
                raise RuntimeError("enrolled companion bundle signature is invalid")
            digest = hashlib.sha256(local_executable.read_bytes()).hexdigest()
            return {"path": remote, "sha256": digest, "kind": "application",
                    "bundle": app_name, "source": "verified-cryptex-enrollment"}
        return {"path": remote, "sha256": digest, "kind": "application",
                "bundle": app_name, "source": "package"}

    source_digest = digest
    destination = (trust_root / "companions" / source_digest /
                   pathlib.PurePosixPath(remote).name)
    destination.parent.mkdir(parents=True, exist_ok=True)
    destination.write_bytes(payload)
    # Executable mode is part of the sealed runtime contract. Path.write_bytes
    # creates a 0644 file, which made a valid signed daemon impossible for the
    # post-install service backend to launch from the Cryptex.
    destination.chmod(0o755)
    verification = run(
        ["/usr/bin/codesign", "--verify", "--strict", destination],
        check=False, show_output=False,
    )
    signature_state = "codesign-verified"
    if verification.returncode:
        expected_legacy = reviewed_legacy_companion_entitlements(
            package, remote, reviewed_adapter)
        if expected_legacy is None:
            raise RuntimeError(
                f"package companion has no valid entitlement-preserving signature: {remote}"
            )
        ldid = find_host_tool("ldid")
        if ldid is None:
            raise RuntimeError("ldid is required to verify the reviewed Crane helper")
        extracted = subprocess.run(
            [ldid, "-e", str(destination)], stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=30, check=False)
        try:
            entitlements = plistlib.loads(extracted.stdout)
        except Exception as error:
            raise RuntimeError("Crane helper entitlements could not be decoded") from error
        if extracted.returncode or entitlements != expected_legacy:
            raise RuntimeError("Crane helper entitlement set differs from the reviewed adapter")
        # The upstream helper carries the exact reviewed entitlement set in a
        # legacy ldid blob that current codesign rejects.  Preserve that set,
        # but encode it in a valid ad-hoc CodeDirectory inside the immutable
        # Cryptex copy.  The dpkg-owned input remains byte-for-byte unchanged.
        with tempfile.NamedTemporaryFile(suffix=".plist") as entitlement_file:
            entitlement_file.write(plistlib.dumps(expected_legacy,
                                                   fmt=plistlib.FMT_XML,
                                                   sort_keys=True))
            entitlement_file.flush()
            run(["/usr/bin/codesign", "--force", "--sign", "-",
                 "--timestamp=none", "--identifier", "com.opa334.cranehelperd",
                 "--entitlements", entitlement_file.name, destination])
        run(["/usr/bin/codesign", "--verify", "--strict", destination])
        signature_state = "resigned-reviewed-entitlements"
    digest = hashlib.sha256(destination.read_bytes()).hexdigest()
    if digest != source_digest:
        final_destination = (trust_root / "companions" / digest /
                             pathlib.PurePosixPath(remote).name)
        final_destination.parent.mkdir(parents=True, exist_ok=True)
        destination.replace(final_destination)
        destination = final_destination
    return {"path": remote, "sha256": digest, "source_sha256": source_digest,
            "kind": "daemon",
            "signature_state": signature_state}


def copy_support_framework(base: list[str], remote: str, root: pathlib.Path,
                           *, repair_device: bool) -> tuple[dict, pathlib.Path]:
    """Copy and authorize one top-level rootless framework.

    Preference bundles frequently link compatibility shims from ``usr/lib``
    which then link a real framework from ``Library/Frameworks``.  Copying
    only the shim leaves Settings with a pane controller that can be created
    but whose view cannot load.  Framework names and archive members are kept
    deliberately narrow because this data originates on the device.
    """
    prefix = "/var/jb/Library/Frameworks/"
    relative = remote.removeprefix(prefix)
    if (not remote.startswith(prefix) or "/" in relative
            or not relative.endswith(".framework")
            or not all(c.isalnum() or c in "._+-" for c in relative)):
        raise RuntimeError(f"unsafe support framework path: {remote!r}")
    archive = ssh(base,
        f"/var/jb/usr/bin/tar -C {prefix.rstrip('/')} -cf - {shlex.quote(relative)}",
        timeout=180, show_output=False).stdout
    destination_root = root / "Library/Frameworks"
    destination = destination_root / relative
    shutil.rmtree(destination, ignore_errors=True)
    count = 0
    total = 0
    with tarfile.open(fileobj=io.BytesIO(archive), mode="r:") as incoming:
        for member in incoming.getmembers():
            count += 1
            total += max(member.size, 0)
            pure = pathlib.PurePosixPath(member.name)
            if (count > 10000 or total > 128 * 1024 * 1024 or pure.is_absolute()
                    or ".." in pure.parts or not pure.parts
                    or pure.parts[0] != relative
                    or not (member.isdir() or member.isfile())):
                raise RuntimeError(f"unsafe support framework member: {member.name!r}")
            output = destination_root.joinpath(*pure.parts)
            if member.isdir():
                output.mkdir(parents=True, exist_ok=True)
                output.chmod(member.mode & 0o777)
                continue
            output.parent.mkdir(parents=True, exist_ok=True)
            stream = incoming.extractfile(member)
            if stream is None:
                raise RuntimeError(f"missing framework payload: {member.name!r}")
            with output.open("wb") as handle:
                shutil.copyfileobj(stream, handle)
            output.chmod(member.mode & 0o777)

    try:
        info = plistlib.loads((destination / "Info.plist").read_bytes())
    except Exception as error:
        raise RuntimeError(f"invalid {relative}/Info.plist: {error}") from error
    executable_name = info.get("CFBundleExecutable") if isinstance(info, dict) else None
    if (not isinstance(executable_name, str) or not executable_name
            or "/" in executable_name or executable_name in (".", "..")):
        raise RuntimeError(f"{relative} has no safe CFBundleExecutable")
    executable = destination / executable_name
    if not executable.is_file():
        raise RuntimeError(f"{relative} executable is missing: {executable_name}")
    source_sha256 = hashlib.sha256(executable.read_bytes()).hexdigest()
    verify = run(["/usr/bin/codesign", "--verify", "--strict", executable], check=False)
    resigned = verify.returncode != 0
    if resigned:
        identifier = info.get("CFBundleIdentifier") if isinstance(info, dict) else None
        if not isinstance(identifier, str) or not identifier:
            identifier = "codes.openai.research.framework." + relative[:-10]
        run(["/usr/bin/codesign", "--force", "--sign", "-", "--timestamp=none",
             "--identifier", identifier, executable])
        if repair_device:
            remote_executable = remote + "/" + executable_name
            ssh(base, f"cat > {shlex.quote(remote_executable)} && chmod 0755 "
                      f"{shlex.quote(remote_executable)}",
                data=executable.read_bytes(), timeout=180, show_output=False)
    run(["/usr/bin/codesign", "--verify", "--strict", executable])
    return ({"path": remote, "executable": executable_name,
             "sha256": hashlib.sha256(executable.read_bytes()).hexdigest(),
             "source_sha256": source_sha256,
             "resigned": resigned}, executable)


def macho_dependencies(path: pathlib.Path) -> list[str]:
    """Return dylib install names from a local Mach-O without executing it."""
    result = run(["/usr/bin/otool", "-L", path], check=False, show_output=False)
    if result.returncode:
        return []
    answer = []
    for raw in result.stdout.decode("utf-8", "replace").splitlines()[1:]:
        line = raw.strip()
        if not line:
            continue
        answer.append(line.split(" (compatibility version", 1)[0])
    return answer


def rootless_dependency_candidate(install_name: str) -> tuple[str, str] | None:
    """Map a safe rootless install name to (kind, device path).

    Only top-level rootless libraries and frameworks are accepted. Apple
    platform libraries, loader-relative files, and malformed paths are not
    copied into the research Cryptex.
    """
    name = install_name
    if name.startswith("@rpath/"):
        name = name[len("@rpath/"):]
    elif name.startswith("/var/jb/usr/lib/"):
        name = name[len("/var/jb/usr/lib/"):]
    elif name.startswith("/var/jb/Library/Frameworks/"):
        name = name[len("/var/jb/Library/Frameworks/"):]
    else:
        return None
    pure = pathlib.PurePosixPath(name)
    if pure.is_absolute() or ".." in pure.parts or not pure.parts:
        return None
    if len(pure.parts) == 1 and pure.name.endswith(".dylib"):
        if all(c.isalnum() or c in "._+-" for c in pure.name):
            return "library", "/var/jb/usr/lib/" + pure.name
        return None
    if (len(pure.parts) == 2 and pure.parts[0].endswith(".framework")
            and pure.parts[1] == pure.parts[0][:-len(".framework")]
            and all(c.isalnum() or c in "._+-" for c in pure.parts[0])):
        return "framework", "/var/jb/Library/Frameworks/" + pure.parts[0]
    return None


def copy_rootless_dependency_closure(base: list[str], seeds: list[pathlib.Path],
                                     root: pathlib.Path, *, repair_device: bool
                                     ) -> tuple[list[dict], list[dict]]:
    """Copy/sign the transitive rootless dependencies of trusted entry points."""
    queue = list(seeds)
    scanned: set[str] = set()
    copied: set[tuple[str, str]] = set()
    libraries: list[dict] = []
    frameworks: list[dict] = []
    while queue:
        local = queue.pop(0)
        local_key = str(local)
        if local_key in scanned:
            continue
        scanned.add(local_key)
        for install_name in macho_dependencies(local):
            candidate = rootless_dependency_candidate(install_name)
            if not candidate or candidate in copied:
                continue
            kind, remote = candidate
            if kind == "library":
                existence_check = f"test -f {shlex.quote(remote)}"
            else:
                # Rootless substrate compatibility stubs may look like a
                # framework but consist only of an absolute symlink and have
                # no bundle metadata. They resolve to ElleKit already present
                # in the base runtime and must not be archived as a framework.
                existence_check = (f"test -d {shlex.quote(remote)} && test -f "
                                   f"{shlex.quote(remote + '/Info.plist')}")
            exists = ssh(base, existence_check, check=False, show_output=False)
            if exists.returncode:
                continue
            copied.add(candidate)
            if kind == "library":
                record = copy_support_library(base, remote, root,
                                              repair_device=repair_device)
                libraries.append(record)
                queue.append(root / pathlib.PurePosixPath(remote).relative_to("/var/jb"))
            else:
                record, executable = copy_support_framework(
                    base, remote, root, repair_device=repair_device)
                frameworks.append(record)
                queue.append(executable)
    return libraries, frameworks


def cleanup_transient_build_files(output: pathlib.Path, root: pathlib.Path) -> None:
    """Keep reinstallable sealed artifacts while removing large scratch images."""
    for name in ("srdsh-apfs-rw.dmg", "srdsh-apfs-sealed.dmg"):
        (output / name).unlink(missing_ok=True)
    shutil.rmtree(output / "mnt", ignore_errors=True)
    # The compressed sealed image is the authoritative recovery payload. Its
    # expanded root is reproducible from tracked sources + the tweak manifest.
    shutil.rmtree(root, ignore_errors=True)
    for item in output.glob("srd-runtime-manager-launcher.*"):
        item.unlink(missing_ok=True)


def copy_frida_payload(source_root: pathlib.Path, root: pathlib.Path) -> dict:
    """Add the reviewed Frida server/agent bytes to this trust generation.

    Installing the upstream Debian payload directly is insufficient on an SRD:
    executables added after a Cryptex was mounted are not present in that
    generation's trust cache and are terminated by AMFI.  Keep each reviewed
    payload's signatures intact, verify them on the host, and place the exact
    manifest-bound bytes in both the runtime image and its generated trust
    cache.  Payloads may be either verified upstream release archives or a
    reproducible, source-built compatibility candidate.
    """
    legacy_manifest_path = source_root / "0sky-frida-manifest.json"
    build_manifest_path = source_root / "manifest.json"
    if legacy_manifest_path.is_file():
        manifest_path = legacy_manifest_path
        source_prefix = pathlib.PurePosixPath("var/jb")
        manifest_prefix = pathlib.PurePosixPath("var/jb")
    elif build_manifest_path.is_file():
        manifest_path = build_manifest_path
        source_prefix = pathlib.PurePosixPath("root")
        manifest_prefix = pathlib.PurePosixPath("root")
    else:
        raise RuntimeError("Frida payload has no supported manifest")
    try:
        manifest = json.loads(manifest_path.read_text())
    except Exception as error:
        raise RuntimeError(f"invalid Frida payload manifest: {error}") from error
    version = None
    if isinstance(manifest, dict):
        version = manifest.get("version") or manifest.get("frida_version")
    if not isinstance(version, str) or not version or len(version) > 64:
        raise RuntimeError("Frida payload manifest has no safe version")
    relative_files = (
        ("usr/sbin/frida-server", 0o755),
        ("usr/lib/frida-1.0/frida-agent.dylib", 0o755),
        ("Library/LaunchDaemons/re.frida.server.plist", 0o644),
    )
    records = []
    for relative_name, mode in relative_files:
        source_name = str(source_prefix / relative_name)
        destination_name = relative_name
        source = source_root / source_name
        if source.is_symlink() or not source.is_file():
            raise RuntimeError(f"Frida payload is missing regular file: {source_name}")
        files = manifest.get("files", {})
        manifest_name = str(manifest_prefix / relative_name)
        expected = files.get("/" + manifest_name)
        if expected is None:
            expected = files.get(manifest_name)
        if isinstance(expected, dict):
            expected = expected.get("sha256")
        digest = hashlib.sha256(source.read_bytes()).hexdigest()
        if not isinstance(expected, str) or digest != expected:
            raise RuntimeError(f"Frida payload digest mismatch: {source_name}")
        if source.suffix in ("", ".dylib"):
            run(["/usr/bin/codesign", "--verify", "--strict", source])
        destination = root / destination_name
        destination.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(source, destination)
        destination.chmod(mode)
        records.append({"path": "/var/jb/" + destination_name,
                        "sha256": digest})
    plist = plistlib.loads(
        (root / "Library/LaunchDaemons/re.frida.server.plist").read_bytes()
    )
    if (not isinstance(plist, dict) or plist.get("Label") != "re.frida.server"
            or plist.get("Program") != "/var/jb/usr/sbin/frida-server"):
        raise RuntimeError("Frida launch definition is not the reviewed service")
    return {"version": version, "files": records,
            "package_sha256": manifest.get("package_sha256"),
            "patch_sha256": manifest.get("patch_sha256"),
            "frida_commit": manifest.get("frida_commit"),
            "frida_gum_base_commit": manifest.get("frida_gum_base_commit"),
            "frida_gum_upstream_pr_commit":
                manifest.get("frida_gum_upstream_pr_commit"),
            "frida_gum_upstream_pr": manifest.get("frida_gum_upstream_pr"),
            "compatibility_provider": manifest.get("compatibility_provider")}


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--host", default=os.environ.get("CRYPSTORE_DEVICE_HOST", "127.0.0.1"))
    parser.add_argument("--port", type=int, default=int(os.environ.get("CRYPSTORE_DEVICE_PORT", "2222")))
    parser.add_argument("--key", type=pathlib.Path, default=pathlib.Path(
        os.environ.get("CRYPSTORE_DEVICE_KEY", "~/.ssh/srdsh_ed25519")).expanduser())
    parser.add_argument("--udid", default=os.environ.get(
        "CRYPSTORE_DEVICE_UDID", ""))
    parser.add_argument("--known-hosts", type=pathlib.Path, default=pathlib.Path(
        os.environ.get("CRYPSTORE_DEVICE_KNOWN_HOSTS", "device-known-hosts")).expanduser())
    parser.add_argument("--host-alias", default=os.environ.get(
        "CRYPSTORE_DEVICE_HOST_ALIAS", ""))
    parser.add_argument("--output", type=pathlib.Path)
    parser.add_argument("--base-root", type=pathlib.Path,
                        help="known-good runtime root to extend (defaults to source snapshot)")
    parser.add_argument("--frida-root", type=pathlib.Path,
                        help="verified extracted Frida iOS payload to trust and seal")
    parser.add_argument("--package", action="append", default=[],
                        help="exact package identifier that triggered this full runtime rebuild")
    parser.add_argument("--build-only", action="store_true")
    args = parser.parse_args()
    try:
        requested_packages = validated_package_names(args.package)
    except ValueError as error:
        parser.error(str(error))
    if not args.build_only and not args.udid:
        parser.error("--udid or CRYPSTORE_DEVICE_UDID is required for device deployment")
    stamp = time.strftime("%Y%m%dT%H%M%SZ", time.gmtime())
    latest_file = REPO / "artifacts/srd-runtime-poc/LATEST.txt"
    if latest_file.exists():
        artifact_root = REPO / latest_file.read_text().strip()
    else:
        artifact_root = REPO / "artifacts/srd-runtime-poc"
    # The build helper is launched with cwd=output below.  Resolve the path up
    # front so a caller-provided relative --output cannot be interpreted a
    # second time relative to itself (for example out/out/build_and_install.sh).
    output = (args.output or artifact_root / "runtime-generations" / stamp).resolve()
    root = output / "root"
    if output.exists():
        raise SystemExit(f"refusing to reuse output directory: {output}")
    output.mkdir(parents=True)
    base_root = (args.base_root or BASE_ROOT).resolve()
    if base_root.is_symlink() or not base_root.is_dir():
        raise SystemExit(f"known-good runtime base root is unavailable: {base_root}")
    shutil.copytree(base_root, root, symlinks=True)
    include_offline_python(root)
    base = ssh_base(args.host, args.port, args.key,
                    known_hosts=args.known_hosts, host_alias=args.host_alias)

    frida_payload = None
    if args.frida_root:
        frida_payload = copy_frida_payload(args.frida_root.resolve(), root)

    # A build-only run is a strictly read-only device snapshot. Deployment can
    # pause injection and repair package bytes, but an offline candidate build
    # must never mutate device state merely to produce an image for review.
    if not args.build_only:
        ssh(base, "mkdir -p /var/mobile/pl; : > /var/mobile/pl/srd-runtime-paused")
    # Errors can occur while collecting the inventory or assembling the image,
    # before the narrower installer try/except below. Never leave the runtime
    # globally paused on a deployment exit path.
    def unpause_runtime() -> None:
        if args.build_only:
            return
        try:
            ssh(base, "rm -f /var/mobile/pl/srd-runtime-paused", check=False,
                show_output=False)
        except Exception:
            pass
    if not args.build_only:
        atexit.register(unpause_runtime)
    inventory_result = ssh(
        base,
        "/var/jb/usr/bin/python3 /var/jb/usr/local/libexec/crypstore-appctl.py list --json 2>/dev/null",
        show_output=False,
        check=False,
    )
    if inventory_result.returncode:
        # First installation has package files in /var/jb but AMFI cannot
        # launch their Python interpreter until this very Cryptex generation
        # admits those CodeDirectories. Permit an empty dynamic inventory only
        # when no ElleKit runtime is mounted yet. Once a runtime exists, a
        # broken inventory remains a hard failure rather than silently losing
        # installed dynamic tweaks from a replacement generation.
        trusted_python_generation = ssh(
            base,
            "for M in /private/var/run/com.apple.security.cryptexd/mnt/"
            "codes.openai.research.ellekitloader.*; do "
            "test -f \"$M/usr/share/0-sky/offline-python-trust-ready\" && exit 0; "
            "done; exit 1",
            check=False,
            show_output=False,
        )
        if trusted_python_generation.returncode == 0:
            raise RuntimeError(
                "device tweak inventory failed while a Python-trusted runtime Cryptex is mounted"
            )
        print("[0-Sky runtime] first-install inventory unavailable; building the verified base generation")
        inventory = {"tweaks": []}
    else:
        inventory = json.loads(inventory_result.stdout)
    trust_root = root / "usr/libexec/ellekit/trust-payloads"
    trust_root.mkdir(parents=True, exist_ok=True)
    manifest = []
    for tweak in inventory.get("tweaks", []):
        remote = tweak.get("dylib")
        if not isinstance(remote, str) or not remote.startswith("/var/jb/"):
            continue
        payload = ssh(base, f"cat {shlex.quote(remote)}", show_output=False).stdout
        digest = hashlib.sha256(payload).hexdigest()
        source_digest = digest
        destination = trust_root / source_digest / pathlib.PurePosixPath(remote).name
        destination.parent.mkdir(parents=True, exist_ok=True)
        destination.write_bytes(payload)
        verify = run(["/usr/bin/codesign", "--verify", "--strict", destination], check=False)
        resigned = False
        if verify.returncode:
            run(["/usr/bin/codesign", "--force", "--sign", "-", "--timestamp=none",
                 "--identifier", "codes.openai.research.dynamic." + digest[:20], destination])
            payload = destination.read_bytes()
            digest = hashlib.sha256(payload).hexdigest()
            # Write the exact signed bytes back to the dpkg path. Trust cache
            # and injected file must reference the same CodeDirectory.
            if not args.build_only:
                ssh(base, f"cat > {shlex.quote(remote)} && chmod 0755 {shlex.quote(remote)}",
                    data=payload)
            resigned = True
        run(["/usr/bin/codesign", "--verify", "--strict", destination])
        if digest != source_digest:
            final_destination = (trust_root / digest /
                                 pathlib.PurePosixPath(remote).name)
            final_destination.parent.mkdir(parents=True, exist_ok=True)
            destination.replace(final_destination)
            destination = final_destination
        manifest.append({"package": tweak.get("package"), "dylib": remote,
                         "sha256": hashlib.sha256(destination.read_bytes()).hexdigest(),
                         "source_sha256": source_digest,
                         "resigned": resigned, "bundles": tweak.get("bundles", []),
                         "executables": tweak.get("executables", [])})

    # Preference panes are executable bundles too.  Copy every bundle named by
    # an installed, package-owned PreferenceLoader descriptor into this exact
    # trust generation.  This is deliberately inventory-driven: Doodle (and a
    # newly installed future tweak) must not depend on a hard-coded support-root
    # snapshot made before that package existed.
    preference_bundles: dict[str, dict] = {}
    preference_descriptors: list[dict] = []
    for tweak in inventory.get("tweaks", []):
        for preference in tweak.get("preference_entries", []) or []:
            descriptor = preference.get("descriptor") if isinstance(preference, dict) else None
            relative = preference_descriptor_relative(descriptor)
            if relative is None:
                raise RuntimeError("tweak inventory contains an unsafe preference descriptor")
            payload = read_preference_descriptor(base, descriptor)
            try:
                value = plistlib.loads(payload)
                entry = value.get("entry") if isinstance(value, dict) else None
                bundle_name = entry.get("bundle") if isinstance(entry, dict) else None
            except (ValueError, TypeError, plistlib.InvalidFileException) as error:
                raise RuntimeError(f"invalid preference descriptor: {descriptor}") from error
            if not isinstance(entry, dict):
                raise RuntimeError(f"preference descriptor has no entry: {descriptor}")
            if bundle_name is not None and not isinstance(bundle_name, str):
                raise RuntimeError(f"preference descriptor has an invalid bundle: {descriptor}")
            descriptor_relative = pathlib.PurePosixPath(descriptor).relative_to("/var/jb")
            descriptor_destination = root / descriptor_relative
            descriptor_destination.parent.mkdir(parents=True, exist_ok=True)
            descriptor_destination.write_bytes(payload)
            preference_descriptors.append({
                "package": tweak.get("package"), "descriptor": descriptor,
                "sha256": hashlib.sha256(payload).hexdigest(),
                "kind": "bundle" if bundle_name else "direct_plist",
            })
            if isinstance(bundle_name, str) and bundle_name:
                preference_bundles[bundle_name] = {"package": tweak.get("package"),
                                                   "descriptor": descriptor,
                                                   "descriptor_sha256":
                                                       hashlib.sha256(payload).hexdigest()}
    preference_manifest = []
    for bundle_name in sorted(preference_bundles, key=str.casefold):
        record = copy_preference_bundle(base, bundle_name, root,
                                        repair_device=not args.build_only)
        record.update(preference_bundles[bundle_name])
        preference_manifest.append(record)

    # A tweak and its pane often link a companion library by @rpath.  Trusting
    # only the entry-point dylib produces a silent dlopen failure after that
    # library is upgraded (PreferenceLoader's libprefs is the concrete iOS 27
    # case).  Include top-level /var/jb/usr/lib dylibs owned by every discovered
    # tweak package; package names and paths are validated before shell use.
    packages = sorted({item.get("package") for item in inventory.get("tweaks", [])
                       if isinstance(item, dict)
                       and isinstance(item.get("package"), str)
                       and item.get("package")
                       and all(c.isalnum() or c in ".+-" for c in item["package"])})
    runtime_adapters = {}
    for package in packages:
        adapter = reviewed_package_runtime_adapter(base, package)
        if adapter is not None:
            runtime_adapters[package] = adapter
    support_paths: set[str] = set()
    companion_paths: dict[str, str] = {}
    for package in packages:
        listing = ssh(base,
            f"/var/jb/usr/bin/dpkg-query -L {shlex.quote(package)} 2>/dev/null || true",
            show_output=False).stdout.decode("utf-8", "replace")
        for line in listing.splitlines():
            suffix = line.removeprefix("/var/jb/usr/lib/")
            if line.startswith("/var/jb/usr/lib/") and "/" not in suffix and suffix.endswith(".dylib"):
                support_paths.add(line)
            if companion_executable_path(line):
                prior_owner = companion_paths.get(line)
                if prior_owner is not None and prior_owner != package:
                    raise RuntimeError(f"companion executable has multiple package owners: {line}")
                companion_paths[line] = package
    support_manifest = [copy_support_library(
                            base, path, root,
                            repair_device=not args.build_only)
                        for path in sorted(support_paths)]
    companion_manifest = []
    for path in sorted(companion_paths):
        package = companion_paths[path]
        record = copy_companion_executable(
            base, path, trust_root, package=package,
            reviewed_adapter=package in runtime_adapters)
        if record is not None:
            record["package"] = package
            companion_manifest.append(record)

    # Follow the actual Mach-O graph rather than assuming every dependency is
    # owned by the entry-point package. Atria, for example, owns its preference
    # bundle while ws.hbang.alderis owns @rpath/libcolorpicker.dylib and the
    # Alderis framework behind that shim. Both must be signed, trust-cached,
    # and present in the mounted generation for its Settings view to render.
    dependency_seeds = [path for path in trust_root.rglob("*") if path.is_file()]
    dependency_seeds += [
        root / "Library/PreferenceBundles" / f"{item['bundle']}.bundle" /
        item["executable"] for item in preference_manifest
    ]
    dependency_seeds += [
        root / pathlib.PurePosixPath(item["path"]).relative_to("/var/jb")
        for item in support_manifest
    ]
    dependency_libraries, support_frameworks = copy_rootless_dependency_closure(
        base, dependency_seeds, root, repair_device=not args.build_only)
    support_by_path = {item["path"]: item for item in support_manifest}
    for item in dependency_libraries:
        support_by_path[item["path"]] = item
    support_manifest = [support_by_path[path] for path in sorted(support_by_path)]

    # The manager package is writable/updateable; the persistent Cryptex owns
    # only its launch definition and the code hashes required by the test.
    launcher = build_native_launcher(output, root)
    sandboxed_injector = build_sandboxed_injector(output, root)
    launch = root / "Library/LaunchDaemons"
    old = launch / "codes.openai.research.preferenceloader-monitor.plist"
    new = launch / "codes.openai.research.srd-runtime-manager.plist"
    new.unlink(missing_ok=True)
    launch_payload = plistlib.loads(
        (MANAGER_DIR / "codes.openai.research.srd-runtime-manager.plist").read_bytes()
    )
    # SRD launchd retains the label enrolled by an earlier Cryptex generation;
    # reuse it while changing only ProgramArguments. New arbitrary labels are
    # not bootstrapped by cryptexd on this image.
    launch_payload["Label"] = "codes.openai.research.preferenceloader-monitor"
    old.write_bytes(plistlib.dumps(launch_payload, fmt=plistlib.FMT_XML,
                                   sort_keys=True))
    # ``artifact_root`` already resolves both the optional LATEST pointer and
    # the canonical in-tree build directory.  Falling back to ``/`` here made
    # a fresh checkout reject the test payload immediately after build_poc.py
    # had successfully produced it.
    latest_root = artifact_root
    host_candidates = [output.parent.parent / "build/native/srd-runtime-test-host",
                       latest_root / "build/native/srd-runtime-test-host"]
    test_host = next((item for item in host_candidates if item.exists()), None)
    if not test_host:
        raise RuntimeError("build_poc.py must be run before runtime synchronization")
    shutil.copy2(test_host, root / "usr/libexec/ellekit/srd-runtime-test-host")
    # Always authorize the deterministic test payload. Installation/removal of
    # its Debian package remains the dynamic registry trigger.
    test_dylib_candidates = [
        output.parent.parent / "build/native/SRDRuntimeTest.dylib",
        latest_root / "build/native/SRDRuntimeTest.dylib",
    ]
    test_dylib = next((item for item in test_dylib_candidates if item.exists()), None)
    if test_dylib:
        test_trust = root / "usr/libexec/ellekit/trust-payloads/poc/SRDRuntimeTest.dylib"
        test_trust.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(test_dylib, test_trust)
    manifest_payload = {"schema": 1, "generated_at": stamp,
                        "requested_packages": requested_packages, "tweaks": manifest,
                        "preference_descriptors": preference_descriptors,
                        "preference_bundles": preference_manifest,
                        "support_libraries": support_manifest,
                        "support_frameworks": support_frameworks,
                        "companion_executables": companion_manifest,
                        "runtime_adapters": runtime_adapters,
                        "sandboxed_injector": sandboxed_injector,
                        "frida": frida_payload}
    encoded_manifest = json.dumps(manifest_payload, indent=2, sort_keys=True) + "\n"
    atomic = output / "dynamic-tweak-manifest.json"
    atomic.write_text(encoded_manifest)
    # The running device manager uses this sealed copy to repair only the exact
    # pre-signing bytes recorded by this generation.  A genuinely updated
    # package has a different hash and is left untouched until the host builds
    # a fresh generation, while a dpkg reinstall of the same package is healed
    # back to the already trust-cached signed bytes.
    sealed_manifest = root / "usr/share/0-sky/dynamic-tweak-manifest.json"
    sealed_manifest.parent.mkdir(parents=True, exist_ok=True)
    sealed_manifest.write_text(encoded_manifest)

    shutil.copy2(NATIVE / "build_and_install.sh", output / "build_and_install.sh")
    shutil.copy2(NATIVE / "install_cryptex_native.py", output / "install_cryptex_native.py")
    shutil.copy2(NATIVE / "BuildManifest.plist", output / "BuildManifest.plist")
    os.chmod(output / "build_and_install.sh", 0o755)
    env = os.environ.copy()
    # The generated installer imports pymobiledevice3.  Keep it on the same
    # reviewed interpreter/environment that launched this coordinator instead
    # of falling back to an unrelated Homebrew Python on one device family.
    # Always use the interpreter that successfully imported this coordinator's
    # dependencies.  A stale inherited SRD_PYTHON can otherwise select a clean
    # Homebrew interpreter that lacks pymobiledevice3 after the sealed image is
    # built, causing installation to fail before any device mutation.
    env["SRD_PYTHON"] = sys.executable
    env.update({"CRYPTEXCTL_UDID": args.udid,
                "SRDSH_IDENTIFIER": "codes.openai.research.ellekitloader",
                "SRDSH_VERSION": f"6.0.{int(time.time())}",
                "SRDSH_ROOT": str(root),
                "SRDSH_BUILD_MANIFEST": str(output / "BuildManifest.plist"),
                # The complete first-install generation includes the immutable
                # offline Python payload as well as PreferenceLoader/CatVNC.
                # 64 MiB cannot hold that reviewed set; keep one bounded image
                # size for both base and Frida-extended generations.
                "SRDSH_IMAGE_SIZE": "192m",
                "SRDSH_BUILD_ONLY": "1" if args.build_only else "0"})
    try:
        run([output / "build_and_install.sh"], cwd=output, env=env, timeout=1200)
    except Exception:
        if not args.build_only:
            ssh(base, "rm -f /var/mobile/pl/srd-runtime-paused", check=False)
        cleanup_transient_build_files(output, root)
        raise
    if not args.build_only:
        # cryptexd has now enrolled the launcher's CodeDirectory. Deploy the
        # byte-identical CLI copies only after the trust update succeeds.
        deploy_native_cli(base, launcher)
        ssh(base, "rm -f /var/mobile/pl/srd-runtime-paused; "
             "/var/jb/usr/bin/killall -TERM Preferences SpringBoard 2>/dev/null || true; "
             "/var/jb/usr/bin/python3 /var/jb/usr/local/libexec/srd-runtime-manager.py sync || true")
        time.sleep(4)
        verification = ssh(base,
            "ps ax -o pid=,command= | grep -E '[s]rd-runtime-manager|[c]atvnc|[l]ocalfenced'; "
            "tail -30 /var/mobile/Library/Logs/srd-runtime-manager.log 2>/dev/null || true",
            check=False)
        (output / "device-verification.txt").write_bytes(verification.stdout)
    cleanup_transient_build_files(output, root)
    print(f"RUNTIME_SYNC_SUCCESS={output}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
