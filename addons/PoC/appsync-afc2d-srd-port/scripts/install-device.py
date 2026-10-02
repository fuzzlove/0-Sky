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


SPECS = (
    {
        "package": "ai.akemi.appsyncunified",
        "installable": True,
        "version": "116.0+0sky26.1",
        "filename": "ai.akemi.appsyncunified_116.0+0sky26.1_iphoneos-arm64.deb",
        "package_sha256": "0aa9de47e00fe58940027d6af3efef56aae5060731d82de64ade6b63e910a597",
        "files": {
            "/var/jb/Library/MobileSubstrate/DynamicLibraries/AppSyncUnified-FrontBoard.dylib":
                "6e85f950c22c2faa9d127dbe59403582ce5b049da19ce30cb7f1928142ee5d30",
            "/var/jb/Library/MobileSubstrate/DynamicLibraries/AppSyncUnified-FrontBoard.plist":
                "eff0e07afd4afa6713eea91fde32a92d420c39361f2ee021548dc3e01cb552ea",
            "/var/jb/Library/MobileSubstrate/DynamicLibraries/AppSyncUnified-installd.dylib":
                "c911785e41c7cde4edffbe0af8a10acc99d68b3810dc6eb15a38518384424111",
            "/var/jb/Library/MobileSubstrate/DynamicLibraries/AppSyncUnified-installd.plist":
                "98d31c678ba9eec7e15cfdc849c2bd26da866d19d5b2e880be5e7cd9c95e3385",
        },
    },
    {
        "package": "com.cannathea.afc2d-arm64",
        "installable": True,
        "version": "1.2.0+0sky27.5",
        "filename": "com.cannathea.afc2d-arm64_1.2.0+0sky27.5_iphoneos-arm64.deb",
        "package_sha256": "50c2d7dd3fd53ed399c88a0ef748a1553a2cba49780219260624a764f61fe049",
        "files": {
            "/var/jb/Library/MobileSubstrate/DynamicLibraries/afc2dService.dylib":
                "a6820ed1a222a58aebab2f32a85c5a2aca585a81245fac429cba70ae285bd7a4",
            "/var/jb/Library/MobileSubstrate/DynamicLibraries/afc2dService.plist":
                "81221171550150d8cdb6bb341284741d2f02118bcee7dbaaccec0e71ef3e29a2",
            "/var/jb/usr/lib/afc2d-xpc-shim.dylib":
                "152b2f68129eb04bb89572d1100e40478b77e8f539c34631dfaddee510bdfeff",
            "/var/jb/usr/libexec/afc2d":
                "c900211619e202e1469f049ad7e721897396f3b0e6b27cfa9c9378ffe0b2284e",
        },
    },
)


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
owned_dylibs=[os.path.realpath(path) for path in paths if path.endswith('.dylib')]
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
    parser.add_argument(
        "--package",
        action="append",
        choices=[spec["package"] for spec in SPECS],
        help="install only the selected package; repeat to select more than one",
    )
    args = parser.parse_args()
    if args.report.exists() or args.report.is_symlink():
        raise FileExistsError("refusing to overwrite transaction evidence")
    identity = asyncio.run(usb_identity(args.udid))
    if identity.get("product") != "iPhone13,2":
        raise RuntimeError("selected USB device is not the confirmed iPhone 12")
    selected = profiles(instance_name=args.instance)
    if args.udid not in selected:
        raise RuntimeError("paired worker does not match the exact USB identity")
    worker = worker_namespace(selected[args.udid][1])
    report = {"schema": 1, "device": identity, "started_at": int(time.time()),
              "result": "UNTESTED", "packages": []}
    exit_code = 0
    selected_packages = set(args.package or (
        spec["package"] for spec in SPECS if spec.get("installable", True)
    ))
    for spec in (item for item in SPECS if item["package"] in selected_packages):
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
