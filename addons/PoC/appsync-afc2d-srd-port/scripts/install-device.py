#!/usr/bin/env python3
"""Install the reviewed AppSync port on one exact 0-Sky SRD."""
from __future__ import annotations

import argparse
import asyncio
import hashlib
import json
from pathlib import Path
import shlex
import sys
import time
import uuid


POC = Path(__file__).resolve().parents[2]
if str(POC) not in sys.path:
    sys.path.insert(0, str(POC))

from install_doodle_private_uat import cleanup, install, stage  # noqa: E402
from repair_device_connection import profiles, usb_identity, worker_namespace  # noqa: E402
from compatibility import load_profiles, validate_profile  # noqa: E402


PROJECT = Path(__file__).resolve().parents[1]
DEFAULT_PROFILE_DIR = PROJECT / "profiles"
_DEFAULT_PROFILE = json.loads(
    (DEFAULT_PROFILE_DIR / "iPhone13,2-24A5390f.json").read_text()
)
# Backward-compatible exports used by host checks; main() resolves all profiles.
SUPPORTED_DEVICE = _DEFAULT_PROFILE["device"]
SYSTEM_BINARIES = _DEFAULT_PROFILE["system_binaries"]
SPECS = tuple(_DEFAULT_PROFILE["packages"])


def remote_json(worker: dict, code: str, *, timeout: int = 90) -> dict:
    result = worker["ssh"](
        "/var/jb/usr/bin/python3 -c " + shlex.quote(code),
        timeout=timeout,
        check=False,
    )
    if result.returncode:
        raise RuntimeError(
            "device probe failed: "
            + result.stderr.decode("utf-8", "replace")[-800:]
        )
    return json.loads(result.stdout.decode("utf-8", "replace"))


def system_binary_identities(worker: dict, paths=None) -> dict:
    """Read the exact system Mach-O identities used to build this port."""
    code = r'''import hashlib,json,pathlib,struct,uuid
paths=%s
def inspect(raw_path):
 path=pathlib.Path(raw_path)
 if not path.is_file():
  raise RuntimeError('required system binary is missing: '+raw_path)
 data=path.read_bytes()
 if len(data)<32:
  raise RuntimeError('truncated Mach-O: '+raw_path)
 magic,cputype,cpusubtype,filetype,ncmds,sizeofcmds,flags,reserved=struct.unpack_from('<IiiIIIII',data,0)
 if magic!=0xfeedfacf or ncmds>4096 or 32+sizeofcmds>len(data):
  raise RuntimeError('unexpected 64-bit Mach-O header: '+raw_path)
 cursor=32; image_uuid=None
 for index in range(ncmds):
  if cursor+8>len(data):
   raise RuntimeError('truncated Mach-O load commands: '+raw_path)
  command,size=struct.unpack_from('<II',data,cursor)
  if size<8 or cursor+size>len(data):
   raise RuntimeError('invalid Mach-O load command: '+raw_path)
  if command==0x1b:
   if size<24 or image_uuid is not None:
    raise RuntimeError('invalid LC_UUID command: '+raw_path)
   image_uuid=str(uuid.UUID(bytes=data[cursor+8:cursor+24])).upper()
  cursor+=size
 if image_uuid is None:
  raise RuntimeError('Mach-O has no LC_UUID: '+raw_path)
 if cputype!=0x0100000c or cpusubtype&0x00ffffff!=2:
  raise RuntimeError('required system binary is not arm64e: '+raw_path)
 return {'uuid':image_uuid,'sha256':hashlib.sha256(data).hexdigest(),'size':len(data),'architecture':'arm64e'}
print(json.dumps({path:inspect(path) for path in paths},sort_keys=True))
''' % repr(list(paths or SYSTEM_BINARIES))
    return remote_json(worker, code)


def dyld_shared_cache_identities(worker: dict) -> list[dict]:
    code = r'''import ctypes,json,uuid
library=ctypes.CDLL(None)
value=(ctypes.c_ubyte*16)()
get_uuid=library._dyld_get_shared_cache_uuid
get_uuid.argtypes=[ctypes.POINTER(ctypes.c_ubyte)]
get_uuid.restype=ctypes.c_bool
size=ctypes.c_size_t()
get_range=library._dyld_get_shared_cache_range
get_range.argtypes=[ctypes.POINTER(ctypes.c_size_t)]
get_range.restype=ctypes.c_void_p
base=get_range(ctypes.byref(size))
if not get_uuid(value) or not base or not size.value:
 raise RuntimeError('dyld shared cache identity is unavailable')
print(json.dumps([{'kind':'process_primary_shared_cache','uuid':str(uuid.UUID(bytes=bytes(value))).upper(),'mapped_size':size.value}]))
'''
    return remote_json(worker, code)


def compatibility_mismatches(identity: dict, binaries: dict | None = None,
                             profile: dict | None = None,
                             shared_caches: list[dict] | None = None) -> list[str]:
    """Return public-identity and, when supplied, binary-identity mismatches."""
    mismatches = []
    profile = profile or _DEFAULT_PROFILE
    for key, expected in profile["device"].items():
        observed = identity.get(key)
        if observed != expected:
            mismatches.append(f"{key} expected {expected!r}, observed {observed!r}")
    if binaries is None:
        return mismatches
    for path, expected in profile["system_binaries"].items():
        observed = binaries.get(path)
        if not isinstance(observed, dict):
            mismatches.append(f"{path} identity is missing")
            continue
        for key in ("uuid", "sha256"):
            actual = observed.get(key)
            wanted = expected[key]
            if not isinstance(actual, str) or actual.lower() != wanted.lower():
                mismatches.append(
                    f"{path} {key} expected {wanted!r}, observed {actual!r}"
                )
        if observed.get("architecture") != expected.get("architecture"):
            mismatches.append(
                f"{path} architecture expected {expected.get('architecture')!r}, "
                f"observed {observed.get('architecture')!r}"
            )
        if observed.get("size") != expected.get("size"):
            mismatches.append(
                f"{path} size expected {expected.get('size')!r}, "
                f"observed {observed.get('size')!r}"
            )
    if shared_caches is None:
        mismatches.append("dyld shared-cache identity evidence is missing")
    else:
        expected_caches = {
            (item.get("kind"), str(item.get("uuid", "")).upper(),
             item.get("mapped_size"))
            for item in profile.get("dyld_shared_caches", [])
        }
        observed_caches = {
            (item.get("kind"), str(item.get("uuid", "")).upper(),
             item.get("mapped_size"))
            for item in shared_caches
        }
        if observed_caches != expected_caches:
            mismatches.append(
                f"dyld shared-cache identities expected {sorted(expected_caches)!r}, "
                f"observed {sorted(observed_caches)!r}"
            )
    return mismatches


def validate_compatibility(identity: dict, binaries: dict | None = None,
                           profile: dict | None = None,
                           shared_caches: list[dict] | None = None) -> None:
    """Fail closed unless the supplied compatibility evidence exactly matches."""
    mismatches = compatibility_mismatches(
        identity, binaries, profile, shared_caches
    )
    if mismatches:
        raise RuntimeError(
            "UNSUPPORTED_DEVICE_BUILD: exact-build preflight failed: "
            + "; ".join(mismatches)
        )


def compatibility_preflight(worker: dict, identity: dict,
                            available_profiles: list[dict] | None = None) -> dict:
    available_profiles = available_profiles or load_profiles(DEFAULT_PROFILE_DIR)
    for profile in available_profiles:
        try:
            validate_profile(profile)
        except ValueError as error:
            raise RuntimeError(
                "INVALID_COMPATIBILITY_PROFILE: " + str(error)
            ) from error
    public_matches = [profile for profile in available_profiles
                      if not compatibility_mismatches(identity, profile=profile)]
    if not public_matches:
        raise RuntimeError(
            "UNSUPPORTED_DEVICE_BUILD: no profile matches the product/version/build"
        )
    paths = sorted({path for profile in public_matches
                    for path in profile["system_binaries"]})
    binaries = system_binary_identities(worker, paths)
    shared_caches = dyld_shared_cache_identities(worker)
    exact_matches = [profile for profile in public_matches
                     if not compatibility_mismatches(
                         identity, binaries, profile, shared_caches
                     )]
    if len(exact_matches) != 1:
        raise RuntimeError(
            "UNSUPPORTED_DEVICE_BUILD: no unique profile matches the exact "
            "system-binary and dyld shared-cache identities"
        )
    profile = exact_matches[0]
    if profile.get("status") != "reviewed":
        raise RuntimeError(
            "COMPATIBILITY_PROFILE_NOT_REVIEWED: offsets were discovered for "
            f"{identity.get('product')} {identity.get('build')}, but the profile "
            "has not been approved for package construction or installation"
        )
    if not profile.get("packages"):
        raise RuntimeError("COMPATIBILITY_PROFILE_HAS_NO_BOUND_PACKAGES")
    return {
        "result": "EXACT_BUILD_MATCH",
        "profile": profile,
        "profile_path": profile.get("_path"),
        "system_binaries": binaries,
        "dyld_shared_caches": shared_caches,
    }


def state(worker: dict, spec: dict) -> dict:
    code = r'''import hashlib,json,os,pathlib,subprocess,time
package=%s
paths=%s
query=subprocess.run(['/var/jb/usr/bin/dpkg-query','-W','-f=${Version}\t${db:Status-Abbrev}',package],capture_output=True,text=True)
files={}
for raw in paths:
 path=pathlib.Path(raw)
 files[raw]=hashlib.sha256(path.read_bytes()).hexdigest() if path.is_file() else None
apt=subprocess.run(['/var/jb/usr/bin/apt-get','check','-o','Dpkg::Use-Pty=0','-o','APT::Sandbox::User=root'],capture_output=True,text=True)
audit=subprocess.run(['/var/jb/usr/bin/dpkg','--audit'],capture_output=True,text=True)
def read(name):
 path=pathlib.Path('/var/jb/var/lib/srd-runtime')/name
 try:return json.loads(path.read_text())
 except Exception:return {}
registry=read('registry.json'); injection=read('injection-state.json'); quarantine=read('injection-quarantine.json')
expected=[]
for target in (registry.get('targets',{}) or {}).values():
 if not isinstance(target,dict):continue
 for dylib in target.get('dylibs',[]):
  if isinstance(dylib,dict) and dylib.get('package')==package:
   expected.append({'target':target.get('name'),'dylib':os.path.realpath(str(dylib.get('path') or '')),'sha256':dylib.get('sha256')})
loaded_rows=[x for x in (injection.get('loaded',{}) or {}).values() if isinstance(x,dict)]
loaded=[]
for requirement in expected:
 for item in loaded_rows:
  if item.get('target')==requirement['target'] and os.path.realpath(str(item.get('dylib') or ''))==requirement['dylib'] and item.get('sha256')==requirement['sha256'] and isinstance(item.get('pid'),int):
   try:os.kill(item['pid'],0)
   except OSError:continue
   loaded.append({**requirement,'pid':item['pid']});break
quarantined=[{'target':x.get('target'),'reason':str(x.get('reason') or '')[:300]} for x in (quarantine.get('entries',{}) or {}).values() if isinstance(x,dict) and x.get('package')==package]
heartbeat=pathlib.Path('/var/jb/var/run/crypstore-worker.json')
try:
 worker=json.loads(heartbeat.read_text());worker={'age_seconds':time.time()-worker['timestamp'],'pairing':worker.get('apple_pairing_verified'),'identity':worker.get('host_identity_verified')}
except Exception as error:worker={'error':type(error).__name__}
owned_dylibs=[os.path.realpath(path) for path in paths
              if path.endswith('.dylib') and path.startswith((
                  '/var/jb/Library/MobileSubstrate/DynamicLibraries/',
                  '/var/jb/usr/lib/TweakInject/'))]
print(json.dumps({'version_status':query.stdout.strip() if query.returncode==0 else None,'files':files,'apt_check_exit':apt.returncode,'apt_check_error':apt.stderr[-1000:],'dpkg_audit_exit':audit.returncode,'dpkg_audit':audit.stdout[-4000:],'owned_dylibs':owned_dylibs,'runtime_generation':registry.get('generation'),'runtime_expected':expected,'runtime_loaded':loaded,'runtime_quarantine':quarantined,'worker':worker}))
''' % (repr(spec["package"]), repr(list(spec["files"])))
    return remote_json(worker, code)


def remove(worker: dict, package: str) -> dict:
    code = r'''import json,pathlib,urllib.error,urllib.request
package=%s
token=pathlib.Path('/var/jb/etc/trollstorelite-srd-bridge.token').read_text().strip()
request=urllib.request.Request('http://127.0.0.1:48654/v1/trollstore',data=json.dumps({'arguments':['remove-package',package]}).encode(),headers={'Content-Type':'application/json','X-TrollStore-Bridge-Token':token},method='POST')
try:
 with urllib.request.urlopen(request,timeout=1100) as response:value=json.load(response)
except urllib.error.HTTPError as error:value=json.load(error)
print(json.dumps({'status':value.get('status'),'stdout':str(value.get('stdout') or '')[-3000:],'stderr':str(value.get('stderr') or '')[-3000:]}))
''' % repr(package)
    return remote_json(worker, code, timeout=1200)


def verified(after: dict, spec: dict) -> bool:
    expected_dylibs = set(after.get("owned_dylibs", []))
    registered_dylibs = {
        row.get("dylib") for row in after.get("runtime_expected", [])
    }
    return bool(
        after.get("version_status") == spec["version"] + "\tii"
        and after.get("files") == spec["files"]
        and after.get("apt_check_exit") == 0
        and not after.get("runtime_quarantine")
        and expected_dylibs <= registered_dylibs
        and bool(after.get("runtime_expected"))
        and len(after.get("runtime_loaded", [])) == len(after.get("runtime_expected", []))
        and after.get("worker", {}).get("age_seconds", 999) < 30
        and after.get("worker", {}).get("pairing") is True
        and after.get("worker", {}).get("identity") is True
    )


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--udid", required=True)
    parser.add_argument("--instance", required=True)
    parser.add_argument("--dist", type=Path, required=True)
    parser.add_argument("--report", type=Path, required=True)
    parser.add_argument("--profiles-dir", type=Path, default=DEFAULT_PROFILE_DIR)
    parser.add_argument(
        "--package",
        action="append",
        help="install only the selected package; repeat to select more than one",
    )
    args = parser.parse_args()
    if args.report.exists() or args.report.is_symlink():
        raise FileExistsError("refusing to overwrite transaction evidence")
    identity = asyncio.run(usb_identity(args.udid))
    available_profiles = load_profiles(args.profiles_dir)
    if not any(not compatibility_mismatches(identity, profile=profile)
               for profile in available_profiles):
        raise RuntimeError("UNSUPPORTED_DEVICE_BUILD: no public identity profile")
    selected = profiles(instance_name=args.instance)
    if args.udid not in selected:
        raise RuntimeError("paired worker does not match the exact USB identity")
    worker = worker_namespace(selected[args.udid][1])
    preflight = compatibility_preflight(worker, identity, available_profiles)
    selected_profile = preflight.pop("profile")
    specs = tuple(selected_profile["packages"])
    known_packages = {spec["package"] for spec in specs}
    unknown_packages = set(args.package or ()) - known_packages
    if unknown_packages:
        raise ValueError("selected profile has no package definition for: "
                         + ", ".join(sorted(unknown_packages)))
    report = {"schema": 1, "device": identity, "preflight": preflight,
              "started_at": int(time.time()),
              "result": "UNTESTED", "packages": []}
    exit_code = 0
    selected_packages = set(args.package or (
        spec["package"] for spec in specs if spec.get("installable", True)
    ))
    for spec in (item for item in specs if item["package"] in selected_packages):
        if not spec.get("installable", True):
            raise RuntimeError(
                spec["package"]
                + " is rejected on iPhone13,2 iOS 27.0; see VALIDATION.md"
            )
        package_path = (args.dist / spec["filename"]).resolve(strict=True)
        digest = hashlib.sha256(package_path.read_bytes()).hexdigest()
        if digest != spec["package_sha256"]:
            raise ValueError(spec["package"] + " differs from the reviewed artifact")
        item = {"package": spec["package"], "version": spec["version"],
                "package_sha256": digest, "result": "UNTESTED",
                "rollback": "NOT_NEEDED"}
        report["packages"].append(item)
        remote_path = "/var/mobile/tmp/0sky-port-" + uuid.uuid4().hex + ".deb"
        before = state(worker, spec)
        item["before"] = before
        if before["version_status"] is not None or any(before["files"].values()):
            item["result"] = "PREEXISTING_STATE"
            exit_code = 1
            break
        try:
            stage(worker, package_path, remote_path)
            response = install(worker, remote_path)
            item["install_response"] = response
            # A full runtime renewal re-evaluates every pre-existing tweak.
            # On a populated SRD, unrelated SpringBoard failures may need to
            # be quarantined and the process restarted before this package's
            # stable loaded state can be persisted.
            deadline = time.monotonic() + 240
            after = state(worker, spec)
            while response.get("status") == 0 and not verified(after, spec) and time.monotonic() < deadline:
                time.sleep(2)
                after = state(worker, spec)
            item["after"] = after
            if response.get("status") != 0 or not verified(after, spec):
                raise RuntimeError("package, dependency, process, or live-injection verification failed")
            item["result"] = "INSTALLED_AND_LOADED"
        except Exception as error:
            item["result"] = "FAILED"
            item["error"] = type(error).__name__ + ": " + str(error)[:800]
            try:
                current = state(worker, spec)
                if current["version_status"] is not None:
                    item["rollback_response"] = remove(worker, spec["package"])
                restored = state(worker, spec)
                item["restored"] = restored
                item["rollback"] = "VERIFIED" if (
                    restored["version_status"] is None
                    and not any(restored["files"].values())
                    and not restored["runtime_expected"]
                    and not restored["runtime_quarantine"]
                    and restored["apt_check_exit"] == 0
                ) else "FAILED"
            except Exception as rollback_error:
                item["rollback"] = "FAILED: " + type(rollback_error).__name__
            exit_code = 1
            break
        finally:
            cleanup(worker, [remote_path])
    report["finished_at"] = int(time.time())
    report["result"] = ("INSTALLED_AND_LOADED" if not exit_code and
                        all(item["result"] == "INSTALLED_AND_LOADED"
                            for item in report["packages"]) else "FAILED")
    args.report.parent.mkdir(parents=True, exist_ok=True)
    args.report.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n")
    print(json.dumps({"result": report["result"], "report": str(args.report),
                      "packages": [{"package": item["package"],
                                    "result": item["result"],
                                    "rollback": item["rollback"]}
                                   for item in report["packages"]]}, sort_keys=True))
    return exit_code


if __name__ == "__main__":
    raise SystemExit(main())
