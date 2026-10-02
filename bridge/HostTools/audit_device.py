#!/usr/bin/env python3
"""Run the post-install/post-reboot 0-Sky acceptance audit over SRDssh.

Credits: 0-Sky Project.
"""

from __future__ import annotations
import argparse, datetime, hashlib, json, os, pathlib, re, subprocess, sys, time
from instance import resolve as resolve_support

EXPECTED_PL = "689b4a2dd7169033fcb653bad25ba8ec7858d2574f353ec64789f65364fd266f"


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--support", type=pathlib.Path,
                        default=pathlib.Path.home()/"Library/Application Support/0-Sky")
    parser.add_argument("--instance-name")
    parser.add_argument("--output", type=pathlib.Path)
    parser.add_argument("--no-settings-relaunch", action="store_true")
    parser.add_argument("--settings-wait", type=float, default=10.0,
                        help=argparse.SUPPRESS)
    parser.add_argument("--ssh-program", default="/usr/bin/ssh", help=argparse.SUPPRESS)
    args = parser.parse_args()
    support=resolve_support(args.support, args.instance_name)
    config_path = support / "config.json"
    if config_path.is_file():
        config=json.loads(config_path.read_text())
    else:
        # Multidevice installs created by the SRD worker may retain the
        # verified pairing record while an older host installer omitted the
        # per-instance config.json. Reconstruct only the transport fields from
        # that caller-owned record; do not guess a UDID or port.
        pairing_path = support / "pairing-state.json"
        if not pairing_path.is_file():
            raise SystemExit(f"missing companion config and pairing record: {support}")
        pairing = json.loads(pairing_path.read_text())
        if not pairing.get("verified") or not pairing.get("worker_verified"):
            raise SystemExit(f"pairing record is not verified: {pairing_path}")
        config={
            "schema": 2,
            "instance": pairing.get("instance_name") or support.name,
            "udid": pairing["device_udid"],
            "ssh_host": os.environ.get("CRYPSTORE_DEVICE_HOST", "127.0.0.1"),
            "ssh_port": str(pairing["ssh_port"]),
            "ssh_key": os.environ.get("CRYPSTORE_DEVICE_KEY", str(pathlib.Path.home()/".ssh/srdsh_ed25519")),
            "ssh_known_hosts": str(support/"device-known-hosts"),
            "ssh_host_alias": os.environ.get("CRYPSTORE_DEVICE_HOST_ALIAS", ""),
        }
    known_hosts = pathlib.Path(config.get("ssh_known_hosts", support/"device-known-hosts"))
    host_alias = config.get("ssh_host_alias")
    if (not host_alias or not known_hosts.is_file() or known_hosts.is_symlink() or
            known_hosts.stat().st_mode & 0o077):
        raise SystemExit("device SSH host-key pin is missing or unsafe; repair pairing over USB")
    known_hosts_value = str(known_hosts).replace("\\", "\\\\").replace(" ", "\\ ")
    base=[args.ssh_program,"-o","BatchMode=yes","-o","ConnectTimeout=10",
          "-o","LogLevel=ERROR","-o","StrictHostKeyChecking=yes",
          "-o",f"UserKnownHostsFile={known_hosts_value}",
          "-o","GlobalKnownHostsFile=/dev/null","-o",f"HostKeyAlias={host_alias}",
          "-o","IdentitiesOnly=yes","-o","PasswordAuthentication=no",
          "-o","KbdInteractiveAuthentication=no","-i",config["ssh_key"],
          "-p",config["ssh_port"],f"root@{config['ssh_host']}"]

    def ssh(command: str, timeout: int = 30) -> str:
        result=subprocess.run(base+[command],stdout=subprocess.PIPE,stderr=subprocess.PIPE,
                              text=True,timeout=timeout,check=False)
        if result.returncode:
            # Keep diagnostics actionable without echoing the full remote
            # command (future audit commands may contain sensitive values).
            target = command.lstrip().split(None, 1)[0] if command.strip() else "<empty>"
            detail = result.stderr.strip()
            suffix = f": {detail[-1000:]}" if detail else ""
            raise RuntimeError(
                f"SSH command {target} exited {result.returncode}{suffix}"
            )
        return result.stdout

    def bridge_get_json(endpoint: str) -> dict:
        """Read one fixed loopback broker endpoint without exporting its token."""
        if endpoint not in ("/v1/runtime", "/v1/pairing/status"):
            raise ValueError("unsupported bridge audit endpoint")
        command = (
            "/var/jb/usr/bin/python3 - <<'PY'\n"
            "import pathlib,urllib.request\n"
            "secret=pathlib.Path('/var/jb/etc/trollstorelite-srd-bridge.token').read_text(encoding='ascii').strip()\n"
            f"request=urllib.request.Request('http://127.0.0.1:48654{endpoint}',"
            "headers={'X-TrollStore-Bridge-Token':secret})\n"
            "with urllib.request.urlopen(request,timeout=10) as response:\n"
            " print(response.read().decode('utf-8'))\n"
            "PY"
        )
        value = json.loads(ssh(command))
        if not isinstance(value, dict):
            raise RuntimeError("device broker returned a non-object response")
        return value

    report={"schema":1,"time":datetime.datetime.now(datetime.timezone.utc).isoformat(),
            "credit":"0-Sky Project",
            "udid":config["udid"],"checks":{}}
    measured_uid = ssh("id -u").strip()
    report["measured_uid"] = measured_uid
    report["checks"]["ssh_root"] = measured_uid == "0"
    if report["checks"]["ssh_root"]:
        print("[0-Sky Link audit] ROOT OBTAINED — authenticated device uid=0", flush=True)
    else:
        print(f"[0-Sky Link audit] ROOT NOT OBTAINED — measured uid={measured_uid or 'unknown'}",
              flush=True)
    versions=ssh("/var/jb/usr/bin/dpkg-query -W -f='${Package}=${Version}\\n' "
                 "com.liquidskysecurity.srd-runtime-manager preferenceloader")
    report["versions"] = dict(line.split("=",1) for line in versions.splitlines() if "=" in line)
    # 0-Sky is normally delivered as an IPA through 0-Sky Control, so dpkg may be
    # absent or may retain the version of an older optional .deb installation.
    # LaunchServices plus the registered app's signed Info.plist is the live
    # assertion surface for the app version.
    app = json.loads(ssh("/var/jb/usr/bin/python3 - <<'PY'\n"
        "import json,pathlib,plistlib,subprocess\n"
        "prefix='codes.liquidsky.research.zerosky : '\n"
        "lines=subprocess.check_output(['/var/jb/usr/bin/uicache','-l'],text=True).splitlines()\n"
        "paths=[line[len(prefix):].strip() for line in lines if line.startswith(prefix)]\n"
        "answer={}\n"
        "if len(paths)==1:\n"
        " p=pathlib.Path(paths[0]); info=plistlib.loads((p/'Info.plist').read_bytes())\n"
        " answer={'path':str(p),'version':str(info.get('CFBundleShortVersionString','')),'build':str(info.get('CFBundleVersion',''))}\n"
        "print(json.dumps(answer))\n"
        "PY"))
    report["app"] = app
    report["versions"]["codes.liquidsky.research.zerosky"] = app.get("version", "")
    crypstore = json.loads(ssh("/var/jb/usr/bin/python3 - <<'PY'\n"
        "import json,pathlib,plistlib,subprocess\n"
        "prefix='com.liquidsky.CrypStore : '\n"
        "lines=subprocess.check_output(['/var/jb/usr/bin/uicache','-l'],text=True).splitlines()\n"
        "paths=[line[len(prefix):].strip() for line in lines if line.startswith(prefix)]\n"
        "answer={}\n"
        "if len(paths)==1:\n"
        " p=pathlib.Path(paths[0]); info=plistlib.loads((p/'Info.plist').read_bytes())\n"
        " answer={'path':str(p),'version':str(info.get('CFBundleShortVersionString','')),'build':str(info.get('CFBundleVersion',''))}\n"
        "print(json.dumps(answer))\n"
        "PY"))
    report["crypstore_app"] = crypstore
    report["versions"]["com.liquidsky.CrypStore"] = crypstore.get("version", "")
    report["checks"]["versions"] = (
        app.get("version")=="1.9.0" and app.get("build")=="48" and
        crypstore.get("version")=="3.3.0" and crypstore.get("build")=="3.3.0.2" and
        report["versions"].get("com.liquidskysecurity.srd-runtime-manager")=="2.4.3" and
        report["versions"].get("preferenceloader","").startswith("2.4.3"))
    report["checks"]["pause_absent"] = ssh(
        "if [ -e /var/mobile/pl/srd-runtime-paused ]; then echo no; else echo yes; fi").strip()=="yes"
    # Procursus/iPhone layouts normally use TweakInject while the iPad SRD
    # compatibility image can retain MobileSubstrate's directory. Resolve the
    # same bounded candidates used by the manager instead of treating one
    # package-valid layout as a missing component.
    pl_info=json.loads(ssh("/var/jb/usr/bin/python3 - <<'PY'\n"
        "import hashlib,json,pathlib\n"
        "candidates=(pathlib.Path('/var/jb/usr/lib/TweakInject/PreferenceLoader.dylib'),"
        "pathlib.Path('/var/jb/Library/MobileSubstrate/DynamicLibraries/PreferenceLoader.dylib'))\n"
        "answer={}\n"
        "for path in candidates:\n"
        " if path.is_file(): answer={'path':str(path),'sha256':hashlib.sha256(path.read_bytes()).hexdigest()}; break\n"
        "print(json.dumps(answer))\n"
        "PY"))
    pl=str(pl_info.get("sha256", ""))
    report["preference_loader_path"]=pl_info.get("path")
    report["preference_loader_sha256"]=pl
    report["checks"]["preference_loader_hash"]=pl==EXPECTED_PL
    runtime=bridge_get_json("/v1/runtime")
    report["runtime"]=runtime
    report["checks"]["runtime_full"] = all((runtime.get("ok"),runtime.get("ellekit_ok"),
        runtime.get("manager_active"),not runtime.get("paused"),runtime.get("crypstore_ok"),
        runtime.get("loaded_dylibs",0)>=1,runtime.get("loaded_targets",0)>=1))

    # 0-Sky Control must derive preference links from package-owned descriptors,
    # not a compiled tweak list. Doodle is the live compatibility regression
    # target, while every published entry must carry its source descriptor.
    # Invoke the Python implementation directly for the inventory assertion.
    # The app itself uses the trust-cached native multiplexer, but an audit can
    # run during the few seconds in which cryptexd swaps runtime generations
    # and the manager atomically refreshes that launcher.  Preference
    # discovery is independent of that transport and deserves its own gate.
    inventory_command=(
        "/var/jb/usr/bin/python3 "
        "/var/jb/usr/local/libexec/crypstore-appctl.py list --json"
    )
    inventory_error=None
    for attempt in range(2):
        try:
            inventory=json.loads(ssh(inventory_command, timeout=90))
            break
        except (RuntimeError, subprocess.TimeoutExpired, json.JSONDecodeError) as error:
            inventory_error=error
            if attempt == 0:
                time.sleep(2)
    else:
        raise RuntimeError(f"0-Sky Control inventory unavailable: {inventory_error}")
    installed_tweaks=[item for item in inventory.get("tweaks",[])
                      if isinstance(item,dict)]
    preference_tweaks=[item for item in installed_tweaks
                       if item.get("settings_available")]
    doodle=next((item for item in preference_tweaks
                 if item.get("package")=="com.nahtedetihw.doodle"),None)
    doodle_installed=any(item.get("package")=="com.nahtedetihw.doodle"
                         for item in installed_tweaks)
    # Keep the gate data-driven: a fresh research device may have a different
    # number of installed tweaks. Every item which publishes pane metadata must
    # be linked; Doodle is checked only when that package is actually present.
    unlinked_panes=[item.get("package") for item in installed_tweaks
                    if item.get("preference_entries") and
                    not item.get("settings_available")]
    report["crypstore_preferences"]={
        "linked_packages":[item.get("package") for item in preference_tweaks],
        "linked_count":len(preference_tweaks),
        "doodle_title":doodle.get("preference_title") if doodle else None,
        "unlinked_pane_packages":unlinked_panes,
    }
    report["checks"]["crypstore_preference_links"] = bool(
        preference_tweaks and not unlinked_panes and
        (not doodle_installed or
         (doodle and doodle.get("preference_title")=="Doodle")) and
        all(item.get("preference_entries") and
            all(entry.get("descriptor") for entry in item["preference_entries"])
            for item in preference_tweaks))

    if not args.no_settings_relaunch:
        ssh(": > /var/mobile/pl/rootlist.log; killall -9 Preferences 2>/dev/null || true; "
            "/var/jb/usr/bin/uiopen 'prefs:root' >/dev/null 2>&1 || true")
        report["settings_launch_transport"] = "device-uiopen"
        # uiopen can return success without foregrounding Settings immediately
        # after an iOS 27 reboot. Detect that condition rather than producing a
        # false PreferenceLoader failure, then use pymobiledevice3 (already a
        # pinned HostKit dependency) as the paired-Mac launch transport.
        deadline = time.monotonic() + min(3.0, max(0.0, args.settings_wait))
        running = False
        while time.monotonic() < deadline:
            running = ssh(
                "ps ax -o command= | grep -q '[/]Applications/Preferences.app/Preferences' "
                "&& echo yes || echo no"
            ).strip() == "yes"
            if running:
                break
            time.sleep(0.5)
        if not running:
            # The standalone controller owns a pinned pymobiledevice3 venv.
            # Do not accidentally use an older package imported by whichever
            # system Python happened to invoke this audit helper.
            pymobile_python = support / "venv/bin/python3"
            if not pymobile_python.is_file():
                pymobile_python = pathlib.Path(sys.executable)
            launched = subprocess.run(
                [str(pymobile_python), "-m", "pymobiledevice3", "developer", "dvt", "launch",
                 "--native", "--udid", config["udid"], "com.apple.Preferences"],
                stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True,
                timeout=60, check=False,
            )
            report["settings_launch_transport"] = "host-pymobiledevice3-native"
            report["settings_launch_output"] = launched.stdout[-2000:]
            if launched.returncode:
                raise RuntimeError(
                    "Settings did not launch through uiopen and the host fallback failed: "
                    + launched.stdout.strip()
                )
        time.sleep(max(0.0, args.settings_wait))
        rootlog=ssh("cat /var/mobile/pl/rootlist.log 2>/dev/null || true")
        row_counts = [int(value) for value in re.findall(r"holds (\d+) row\(s\)", rootlog)]
        report["settings"]={"injector_installs":rootlog.count("[injector] installed"),
                            "row_mutations":len(row_counts),
                            "maximum_dynamic_rows":max(row_counts, default=0)}
        report["checks"]["settings_rows"]=(report["settings"]["injector_installs"]>=1 and
                                              report["settings"]["maximum_dynamic_rows"]>=1)
        # Injection is asynchronous. Refresh the status after the Settings
        # snapshot so this report measures the new process rather than the
        # pre-launch runtime sample.
        runtime=bridge_get_json("/v1/runtime")
        report["runtime"]=runtime
        report["checks"]["runtime_full"] = all((
            runtime.get("ok"), runtime.get("ellekit_ok"),
            runtime.get("manager_active"), not runtime.get("paused"),
            runtime.get("crypstore_ok"), runtime.get("loaded_dylibs",0)>=1,
            runtime.get("loaded_targets",0)>=1))
    report["passed"]=all(report["checks"].values())
    encoded=json.dumps(report,indent=2,sort_keys=True)+"\n"
    if report["passed"]:
        if args.no_settings_relaunch:
            print("[0-Sky Link audit] BASE ACCEPTANCE PASSED — root, ElleKit, live targets, "
                  "and 0-Sky Control passed; Settings relaunch was not requested", flush=True)
        else:
            print("[0-Sky Link audit] FULL INJECTION OBTAINED — root, ElleKit, live targets, "
                  "0-Sky Control, and Settings passed", flush=True)
    else:
        print("[0-Sky Link audit] FULL INJECTION NOT OBTAINED — acceptance gate failed",
              flush=True)
    print(encoded,end="")
    if args.output:
        args.output.expanduser().write_text(encoded)
    return 0 if report["passed"] else 1


def fail_with_evidence(error: Exception) -> int:
    """Convert an expected transport/audit failure into bounded evidence."""
    value = {
        "schema": 1,
        "time": datetime.datetime.now(datetime.timezone.utc).isoformat(),
        "passed": False,
        "result": "FAIL",
        "error_class": type(error).__name__,
        "diagnostic": str(error)[-2000:],
        "checks": {},
    }
    encoded = json.dumps(value, indent=2, sort_keys=True) + "\n"
    try:
        if "--output" in sys.argv:
            index = sys.argv.index("--output") + 1
            destination = pathlib.Path(sys.argv[index]).expanduser()
            destination.parent.mkdir(parents=True, exist_ok=True)
            destination.write_text(encoded, encoding="utf-8")
    except (IndexError, OSError):
        pass
    print("[0-Sky Link audit] FAILED — " + type(error).__name__, file=sys.stderr,
          flush=True)
    print(encoded, end="")
    return 2


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (RuntimeError, subprocess.TimeoutExpired, OSError,
            json.JSONDecodeError) as error:
        raise SystemExit(fail_with_evidence(error))
