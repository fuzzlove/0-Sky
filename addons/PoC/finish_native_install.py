#!/usr/bin/env python3
"""Finish a worker-staged IPA through native registration and exact-code trust."""
import argparse
import asyncio
import hashlib
import json
import pathlib
import plistlib
import shlex
import subprocess
import sys
import tarfile
import time
import zipfile

from repair_device_connection import (HOST_TOOLS, atomic_write, profiles,
                                      usb_identity, worker_namespace)

FIND_MOUNT = """import glob,json,os,plistlib,subprocess,sys
bundle_id,version=sys.argv[1:]
mounted=subprocess.check_output(['mount'],text=True)
found=[]
for info in glob.glob('/private/var/run/com.apple.security.cryptexd/mnt/*/Applications/*.app/Info.plist'):
 try:
  app=os.path.dirname(info)
  mount=app.split('/Applications/',1)[0]
  if (' on '+mount+' (') not in mounted:continue
  with open(info,'rb') as stream:value=plistlib.load(stream)
  if value.get('CFBundleIdentifier')!=bundle_id or str(value.get('CFBundleVersion'))!=version:continue
  exe=value.get('CFBundleExecutable')
  if not isinstance(exe,str) or not os.path.isfile(os.path.join(app,exe)):continue
  found.append(app)
 except (OSError,ValueError):pass
print(json.dumps(found))
"""


def source_identity(ipa: pathlib.Path) -> tuple[str, str, str]:
    with zipfile.ZipFile(ipa) as archive:
        infos = [name for name in archive.namelist()
                 if name.startswith("Payload/") and name.endswith(".app/Info.plist")
                 and name.count("/") == 2]
        if len(infos) != 1:
            raise ValueError("IPA must have one top-level app")
        info = plistlib.loads(archive.read(infos[0]))
    bundle_id = info.get("CFBundleIdentifier")
    executable = info.get("CFBundleExecutable")
    version = str(info.get("CFBundleVersion", ""))
    if (not isinstance(bundle_id, str) or not bundle_id or "/" in bundle_id
            or not isinstance(executable, str) or not executable
            or "/" in executable or not version):
        raise ValueError("IPA app identity is incomplete")
    return bundle_id, executable, version


def run(command: list[str], timeout: int = 180) -> subprocess.CompletedProcess:
    return subprocess.run(command, check=True, timeout=timeout)


def resign_bundle(bundle: pathlib.Path, bundle_id: str) -> None:
    run(["/usr/bin/codesign", "--force", "--sign", "-", "--timestamp=none",
         "--identifier", bundle_id, "--generate-entitlement-der",
         "--preserve-metadata=entitlements", str(bundle)], timeout=120)


MACHO_MAGICS = {
    b"\xfe\xed\xfa\xce", b"\xce\xfa\xed\xfe", b"\xfe\xed\xfa\xcf", b"\xcf\xfa\xed\xfe",
    b"\xca\xfe\xba\xbe", b"\xbe\xba\xfe\xca", b"\xca\xfe\xba\xbf", b"\xbf\xba\xfe\xca",
}


def is_macho(path: pathlib.Path) -> bool:
    if path.is_symlink() or not path.is_file():
        return False
    try:
        return path.read_bytes()[:4] in MACHO_MAGICS
    except OSError:
        return False


def resign_embedded_machos(app: pathlib.Path) -> None:
    """Sign every nested executable image before sealing its containing bundle."""
    main = app / plistlib.loads((app / "Info.plist").read_bytes())["CFBundleExecutable"]
    for binary in sorted((path for path in app.rglob("*")
                          if is_macho(path) and path != main), key=lambda path: len(path.parts),
                         reverse=True):
        run(["/usr/bin/codesign", "--force", "--sign", "-", "--timestamp=none",
             "--generate-entitlement-der", "--preserve-metadata=entitlements",
             str(binary)], timeout=120)
        run(["/usr/bin/codesign", "--verify", "--strict", str(binary)], timeout=120)


def prepare_signed_ipa(app: pathlib.Path, bundle_id: str, output: pathlib.Path) -> pathlib.Path:
    run(["/usr/bin/codesign", "--verify", "--deep", "--strict", str(app)], timeout=120)
    marker = app / ".appregistrard"
    if marker.is_symlink() or (marker.exists() and (not marker.is_file() or marker.stat().st_size)):
        raise RuntimeError("Unexpected appregistrard marker")
    marker.touch(exist_ok=True)
    resign_embedded_machos(app)
    nested = sorted((path for path in app.rglob("*")
                     if path.is_dir() and path.suffix.lower() in
                     (".app", ".appex", ".xpc", ".framework", ".bundle")),
                    key=lambda path: len(path.parts), reverse=True)
    for bundle in nested:
        info = bundle / "Info.plist"
        if not info.is_file():
            continue
        metadata = plistlib.loads(info.read_bytes())
        if not metadata.get("CFBundleExecutable"):
            continue
        identity = metadata.get("CFBundleIdentifier")
        if not isinstance(identity, str) or not identity:
            raise RuntimeError(f"Nested bundle identity is missing: {bundle}")
        resign_bundle(bundle, identity)
    resign_bundle(app, bundle_id)
    run(["/usr/bin/codesign", "--verify", "--deep", "--strict", str(app)], timeout=120)
    ipa = output / "native-signed.ipa"
    run(["/usr/bin/ditto", "-c", "-k", "--keepParent",
         str(app.parent), str(ipa)], timeout=600)
    return ipa


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source-ipa", type=pathlib.Path, required=True)
    parser.add_argument("--udid", required=True)
    parser.add_argument("--instance-name", required=True)
    parser.add_argument("--output", type=pathlib.Path, required=True)
    args = parser.parse_args()
    source = args.source_ipa.resolve(strict=True)
    bundle_id, executable, version = source_identity(source)
    asyncio.run(usb_identity(args.udid))
    configured = profiles(instance_name=args.instance_name)
    if args.udid not in configured:
        parser.error("Selected profile does not match the exact USB UDID")
    profile = configured[args.udid][1]
    env = profile["EnvironmentVariables"]
    if env.get("CRYPSTORE_DEVICE_HOST") != "127.0.0.1":
        parser.error("Selected profile is not routed through the paired USB tunnel")
    namespace = worker_namespace(profile)
    find = ("/var/jb/usr/bin/python3 -c " + shlex.quote(FIND_MOUNT) + " " +
            shlex.quote(bundle_id) + " " + shlex.quote(version))
    matches = json.loads(namespace["ssh"](find, timeout=60).stdout)
    if len(matches) != 1:
        raise RuntimeError(f"Expected one mounted worker-signed app for {bundle_id} {version}; found {len(matches)}")
    remote_app = matches[0]
    output = args.output.resolve()
    output.mkdir(parents=True, exist_ok=False)
    sys.path.insert(0, str(HOST_TOOLS))
    import pair
    base = pair.ssh_base(
        "127.0.0.1", env["CRYPSTORE_DEVICE_PORT"],
        pathlib.Path(env["CRYPSTORE_DEVICE_KEY"]),
        known_hosts=pathlib.Path(env["CRYPSTORE_DEVICE_KNOWN_HOSTS"]),
        host_alias=env["CRYPSTORE_DEVICE_HOST_ALIAS"])
    archive = output / "signed-app.tar"
    tar_command = ("/var/jb/usr/bin/tar -C " + shlex.quote(str(pathlib.PurePosixPath(remote_app).parent))
                   + " -cf - " + shlex.quote(pathlib.PurePosixPath(remote_app).name))
    with archive.open("wb") as stream:
        subprocess.run(base + [tar_command], stdout=stream, check=True, timeout=1200)
    payload = output / "Payload"
    payload.mkdir()
    with tarfile.open(archive) as source_tar:
        names = source_tar.getnames()
        expected = pathlib.PurePosixPath(remote_app).name
        if not names or any(name != expected and not name.startswith(expected + "/") for name in names):
            raise RuntimeError("Signed app archive contains an unexpected path")
        source_tar.extractall(payload, filter="data")
    app = payload / pathlib.PurePosixPath(remote_app).name
    info = plistlib.loads((app / "Info.plist").read_bytes())
    if (info.get("CFBundleIdentifier") != bundle_id
            or info.get("CFBundleExecutable") != executable
            or str(info.get("CFBundleVersion")) != version):
        raise RuntimeError("Worker-signed Cryptex app identity differs from the requested IPA")
    ipa = prepare_signed_ipa(app, bundle_id, output)
    trust_command = [
        sys.executable, str(pathlib.Path(__file__).with_name("restore_app_trust.py")),
        "--app", str(app), "--bundle-id", bundle_id,
        "--udid", args.udid, "--instance-name", args.instance_name,
        "--output", str(output / "trust"), "--install",
    ]
    run(trust_command, timeout=1200)
    run([sys.executable, "-m", "pymobiledevice3", "apps", "install", str(ipa),
         "--native", "--udid", args.udid], timeout=1800)
    listing = namespace["ssh"](
        "/var/jb/usr/bin/uicache -i " + shlex.quote(bundle_id), timeout=30).stdout.decode()
    if f"Executable Name: {executable}\n" not in listing:
        raise RuntimeError("Native app registration lacks the expected executable")
    rows = [line.partition(": ")[2].strip() for line in listing.splitlines()
            if line.startswith("Path: ")]
    if len(rows) != 1 or not rows[0].endswith("/" + app.name):
        raise RuntimeError("Native app registration path is incomplete")
    expected_path = rows[0] + "/" + executable
    namespace["ssh"]("/var/jb/usr/bin/uiopen --bundleid " + shlex.quote(bundle_id),
                     timeout=30)
    deadline = time.monotonic() + 12
    running = False
    while time.monotonic() < deadline:
        result = namespace["ssh"]("ps -axo command=", timeout=30, check=False)
        running = any(line.strip().split(None, 1)[0] in
                      (expected_path, expected_path.removeprefix("/private"))
                      for line in result.stdout.decode("utf-8", "replace").splitlines()
                      if line.strip())
        if running:
            break
        time.sleep(0.5)
    if not running:
        raise RuntimeError(f"Native {bundle_id} app did not reach a running state")
    report = {
        "udid": args.udid, "bundle_id": bundle_id, "version": version,
        "source_sha256": hashlib.sha256(source.read_bytes()).hexdigest(),
        "registered_path": rows[0], "executable": executable,
        "running": True, "checked_at": int(time.time()),
    }
    atomic_write(output / "result.json", (json.dumps(report, indent=2) + "\n").encode())
    print(json.dumps(report, indent=2))


if __name__ == "__main__":
    main()
