#!/usr/bin/env python3
"""Collect bounded, read-only LocalFence service diagnostics over paired SSH."""
import argparse
import json
from pathlib import Path
import shlex
import subprocess

from register_mounted_app import paired_ssh


REMOTE = r'''
import base64, glob, json, os, plistlib, stat, subprocess
from pathlib import Path

def command(args):
    try:
        value = subprocess.run(args, capture_output=True, timeout=8,
            env={"PATH":"/var/jb/usr/bin:/usr/bin:/bin:/usr/sbin", "LANG":"C"})
        return {"exit":value.returncode,
                "stdout":value.stdout.decode("utf-8","replace")[:4096],
                "stderr":value.stderr.decode("utf-8","replace")[:4096]}
    except (OSError, subprocess.TimeoutExpired) as error:
        return {"error":type(error).__name__}

result = {"files":{}, "plists":{}}
paths = ["/var/jb/usr/bin/localfencectl",
         "/var/jb/usr/libexec/localfence/localfenced",
         "/var/jb/Library/LaunchDaemons/com.emp0ry.localfenced.plist",
         "/var/jb/bin/launchctl", "/var/jb/usr/bin/launchctl", "/bin/launchctl"]
for name in paths:
    path = Path(name)
    if path.exists():
        info = path.stat()
        result["files"][name] = {"mode":oct(stat.S_IMODE(info.st_mode)),
            "uid":info.st_uid, "gid":info.st_gid, "size":info.st_size,
            "resolved":str(path.resolve())}
        if name.endswith(".plist"):
            value = plistlib.loads(path.read_bytes())
            result["plists"][name] = {key:value[key] for key in
                ("Label","Program","ProgramArguments","RunAtLoad","KeepAlive",
                 "MachServices","Sockets","UserName","StandardOutPath","StandardErrorPath")
                if key in value}
    else:
        result["files"][name] = {"missing":True}
result["package"] = command(["/var/jb/usr/bin/dpkg-query","-W",
    "-f=${Package} ${Version} ${Status}\n", "xyz.cypwn.localfence"])
result["status"] = command(["/var/jb/usr/bin/localfencectl","status"])
result["crashes"] = []
for directory in ["/var/mobile/Library/Logs/CrashReporter", "/Library/Logs/CrashReporter"]:
    for name in sorted(glob.glob(directory+"/*")):
        if any(term in Path(name).name.lower() for term in ("localfence", "launchctl")):
            result["crashes"].append({"name":Path(name).name,
                "modified":Path(name).stat().st_mtime})
result["crashes"] = sorted(result["crashes"],key=lambda v:v["modified"],reverse=True)[:12]
result["launchctl_crash"] = {}
for directory in ["/var/mobile/Library/Logs/CrashReporter", "/Library/Logs/CrashReporter"]:
    candidates = list(Path(directory).glob("launchctl*.ips"))
    if candidates:
        latest = max(candidates,key=lambda p:p.stat().st_mtime)
        text = latest.read_text(errors="replace")[:262144]
        try:
            body = json.loads(text[text.index("\n")+1:])
            result["launchctl_crash"] = {key:body[key] for key in
                ("exception","termination","faultingThread","asi") if key in body}
        except (ValueError, KeyError):
            result["launchctl_crash"] = {"parse":"unavailable"}
        break
result["binaries"] = {name:base64.b64encode(Path(name).read_bytes()).decode()
    for name in paths if Path(name).is_file() and not name.endswith(".plist")}
print(json.dumps(result,sort_keys=True))
'''


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--udid", required=True)
    parser.add_argument("--output", type=Path, required=True)
    options = parser.parse_args()
    result = paired_ssh(options.udid)(
        "/var/jb/usr/bin/python3 -c " + shlex.quote(REMOTE), timeout=45, check=False)
    if result.returncode:
        raise RuntimeError(f"Diagnostic SSH command failed ({result.returncode})")
    report = json.loads(result.stdout)
    options.output.parent.mkdir(parents=True, exist_ok=True)
    import base64
    report["host_signature_checks"] = {}
    for name, encoded in report.pop("binaries").items():
        local = options.output.parent / "localfence-binaries" / Path(name).name
        local.parent.mkdir(parents=True, exist_ok=True)
        local.write_bytes(base64.b64decode(encoded, validate=True))
        verified = subprocess.run(["/usr/bin/codesign", "--verify", "--strict", str(local)],
            capture_output=True, text=True, timeout=15, check=False)
        display = subprocess.run(["/usr/bin/codesign", "-dvv", str(local)],
            capture_output=True, text=True, timeout=15, check=False)
        report["host_signature_checks"][name] = {
            "verify_exit":verified.returncode,
            "verify_diagnostics":verified.stderr.replace(str(local), Path(name).name)[:2048],
            "signing": [line for line in display.stderr.splitlines()
                if line.startswith(("Identifier=", "Signature=", "Authority=", "CodeDirectory "))]}
    # Reuse the authoritative compatibility taxonomy; this tool never installs
    # or treats host signature verification as device trust authorization.
    import sys
    for ancestor in Path(__file__).resolve().parents:
        runtime = ancestor / "bridge" / "DeviceRuntime"
        if (runtime / "zero_sky_compat").is_dir():
            sys.path.insert(0, str(runtime))
            break
    from zero_sky_compat.failures import fingerprint
    report["failure_signatures"] = [fingerprint(
        json.dumps(report["launchctl_crash"], sort_keys=True), "service_launch")]
    report["assessment"] = {
        "status": "BLOCKED" if report["status"].get("exit") not in (None, 0) else "UNKNOWN",
        "functional_validation": False,
        "signature_trust": "UNVERIFIED",
        "device_modified": False,
        "detail": "A successful status exit alone does not establish functional compatibility."}
    options.output.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n")
    print(json.dumps(report, indent=2, sort_keys=True))


if __name__ == "__main__":
    main()
