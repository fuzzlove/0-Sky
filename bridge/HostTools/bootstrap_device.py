#!/usr/bin/env python3
"""Bootstrap bundled 0-Sky components onto an authorized, rootless SRD.

The outer 0-Sky controller establishes SRDssh/Dropbear and `/var/jb` first.
This post-SSH stage does not exploit or jailbreak a stock device. It installs the bundled
manager/PreferenceLoader packages, renews their SRD trust Cryptex, and can then
submit bundled apps to the authenticated 0-Sky Control worker.

Credits: 0-Sky Project.
"""

from __future__ import annotations
import argparse, hashlib, json, pathlib, shlex, subprocess, sys, time
from instance import resolve as resolve_support


def log(message: str) -> None:
    print(f"[0-Sky Link device bootstrap] {message}", flush=True)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--support", type=pathlib.Path,
                        default=pathlib.Path.home()/"Library/Application Support/0-Sky")
    parser.add_argument("--instance-name")
    parser.add_argument("--extras", action="store_true",
                        help="also install bundled LocalFence and CatVNC packages")
    parser.add_argument("--catvnc", action="store_true",
                        help="install CatVNC and refresh the shared SRD runtime Cryptex")
    parser.add_argument("--commissary", action="store_true",
                        help="install the bundled Commissary-branded 0-Sky Control IPA as its own Cryptex")
    parser.add_argument("--crypstore", dest="commissary", action="store_true",
                        help=argparse.SUPPRESS)
    parser.add_argument("--apps", action="store_true",
                        help="also install bundled 0-Sky Control and Sileo IPAs")
    parser.add_argument("--zero-sky-ipa", type=pathlib.Path,
                        help="optionally install the outer 0-Sky Link IPA itself")
    parser.add_argument("--force-apps", action="store_true",
                        help="reinstall selected apps even when version metadata matches (for asset-only releases)")
    parser.add_argument("--apps-only", action="store_true",
                        help="skip package convergence and update only selected apps after verifying the live runtime")
    parser.add_argument("--link-only", action="store_true",
                        help="install/verify only 0-Sky Link; never refresh packages or Cryptexes")
    parser.add_argument("--ssh-host-override",
                        help="use a verified temporary RemoteXPC tunnel address without changing the enrolled instance")
    parser.add_argument("--ssh-port-override", type=int,
                        help="SSH port paired with --ssh-host-override")
    parser.add_argument("--dry-run", action="store_true")
    args = parser.parse_args()
    if bool(args.ssh_host_override) != bool(args.ssh_port_override):
        parser.error("--ssh-host-override and --ssh-port-override must be supplied together")
    if args.apps_only and (args.extras or args.catvnc):
        parser.error("--apps-only cannot be combined with --extras or --catvnc")
    if args.link_only and (not args.zero_sky_ipa or args.apps or args.commissary
                           or args.extras or args.catvnc or args.apps_only):
        parser.error("--link-only requires --zero-sky-ipa and no other component selection")
    support = resolve_support(args.support, args.instance_name)
    config = json.loads((support/"config.json").read_text())
    ssh_host = args.ssh_host_override or config["ssh_host"]
    ssh_port = str(args.ssh_port_override or config["ssh_port"])
    known_hosts = pathlib.Path(config.get("ssh_known_hosts", support/"device-known-hosts"))
    host_alias = config.get("ssh_host_alias")
    if (not host_alias or not known_hosts.is_file() or known_hosts.is_symlink() or
            known_hosts.stat().st_mode & 0o077):
        raise SystemExit("device SSH host-key pin is missing or unsafe; repair pairing over USB")
    known_hosts_value = str(known_hosts).replace("\\", "\\\\").replace(" ", "\\ ")
    ssh = ["/usr/bin/ssh", "-o", "BatchMode=yes", "-o", "ConnectTimeout=10",
           "-o", "LogLevel=ERROR", "-o", "StrictHostKeyChecking=yes",
           "-o", f"UserKnownHostsFile={known_hosts_value}",
           "-o", "GlobalKnownHostsFile=/dev/null", "-o", f"HostKeyAlias={host_alias}",
           "-o", "IdentitiesOnly=yes", "-o", "PasswordAuthentication=no",
           "-o", "KbdInteractiveAuthentication=no", "-i", config["ssh_key"],
           "-p", ssh_port, f"root@{ssh_host}"]

    def remote(command: str, data: bytes | None = None, *, check: bool = True,
               capture: bool = False, timeout: int = 60) -> subprocess.CompletedProcess | None:
        log("device: " + command.splitlines()[0])
        if args.dry_run:
            return None
        return subprocess.run(
            ssh+[command], input=data, check=check,
            stdout=subprocess.PIPE if capture else None,
            stderr=subprocess.PIPE if capture else None,
            timeout=timeout,
        )

    # Do not display the root milestone merely because the SSH account is named
    # "root".  Measure the effective uid on the device and fail closed before
    # any package, Cryptex, or application mutation.
    if args.dry_run:
        log("ROOT PROOF PLANNED — authenticated device id -u must return 0")
    else:
        root_proof = remote('test "$(id -u)" = 0', check=False)
        assert root_proof is not None
        if root_proof.returncode:
            log("ROOT NOT OBTAINED — refusing device bootstrap")
            return 1
        log("ROOT OBTAINED — authenticated device id -u returned 0")

    packages = support/"packages"
    def package_name(exact: str | None, pattern: str) -> str:
        if exact and (packages/exact).is_file():
            return exact
        matches = sorted(path.name for path in packages.glob(pattern))
        if not matches:
            raise SystemExit(f"missing bundled package matching {pattern}")
        return matches[-1]

    names = [] if args.apps_only or args.link_only else [
             package_name("ellekit_1.2_iphoneos-arm64.deb",
                          "ellekit_*_iphoneos-arm64.deb"),
             package_name("wget_1.24.5_iphoneos-arm64.deb",
                          "wget_*_iphoneos-arm64.deb"),
             package_name("srd-runtime-manager_2.4.10_iphoneos-arm64.deb",
                          "srd-runtime-manager_*_iphoneos-arm64.deb"),
             package_name("preferenceloader_2.4.3-1+debug_iphoneos-arm64.deb",
                          "preferenceloader_*_iphoneos-arm64.deb")]
    if args.extras:
        names += [package_name(None, "LocalFence*.deb")]
    if args.extras or args.catvnc:
        names += [package_name(None, "CatVNC*.deb")]
    for name in names:
        if not (packages/name).is_file(): raise SystemExit(f"missing bundled package: {name}")
    if names:
        remote("mkdir -p /var/jb/var/tmp/0sky-bootstrap")
    remote_paths=[]
    for name in names:
        destination=f"/var/jb/var/tmp/0sky-bootstrap/{name}"
        log(f"uploading {name}")
        remote(f"cat > {shlex.quote(destination)}", (packages/name).read_bytes())
        remote_paths.append(destination)
    # Preserve a newer installed package instead of silently downgrading it to
    # a bundled recovery copy. Build an apt argument list on-device from exact
    # dpkg metadata, then install only equal/newer recovery candidates.
    selection = r'''set -eu
SELECTED=""
for DEB in "$@"; do
  PACKAGE=$(/var/jb/usr/bin/dpkg-deb -f "$DEB" Package)
  CANDIDATE=$(/var/jb/usr/bin/dpkg-deb -f "$DEB" Version)
  INSTALLED=$(/var/jb/usr/bin/dpkg-query -W -f='${Version}' "$PACKAGE" 2>/dev/null || true)
  if [ -n "$INSTALLED" ] && /var/jb/usr/bin/dpkg --compare-versions "$INSTALLED" ge "$CANDIDATE"; then
    echo "[0-Sky Link packages] preserving installed $PACKAGE $INSTALLED (bundle: $CANDIDATE)"
  else
    SELECTED="$SELECTED $DEB"
  fi
done
if [ -n "$SELECTED" ]; then
  /var/jb/usr/bin/apt-get install -y --no-remove $SELECTED
  echo 'PACKAGE_CHANGES=1'
else
  echo '[0-Sky Link packages] every installed package is newer than its recovery copy'
  echo 'PACKAGE_CHANGES=0'
fi
'''
    package_changes = False
    if remote_paths:
        package_result = remote("/var/jb/usr/bin/sh -s -- " +
                                " ".join(shlex.quote(path) for path in remote_paths) +
                                " <<'SH'\n" + selection + "SH", capture=not args.dry_run)
        package_changes = True
        if package_result is not None:
            package_text = package_result.stdout.decode("utf-8", "replace")
            print(package_text, end="", flush=True)
            package_changes = "PACKAGE_CHANGES=0" not in package_text
    else:
        log("app-only update: package convergence intentionally skipped")

    python = support/"venv/bin/python3"
    sync = support/"automation/tools/srd-runtime-manager/sync_runtime_cryptex.py"
    command=[str(python),str(sync),"--host",ssh_host,"--port",ssh_port,
             "--key",config["ssh_key"],"--udid",config["udid"],
             "--known-hosts",str(known_hosts),"--host-alias",host_alias]
    def injection_ready(payload: dict) -> bool:
        """The ElleKit milestone is independent from 0-Sky Control app health."""
        return bool(payload.get("ellekit_ok") and payload.get("manager_active") and
                    not payload.get("paused") and payload.get("loaded_dylibs", 0) >= 1 and
                    payload.get("loaded_targets", 0) >= 1)

    def runtime_snapshot() -> dict:
        # Every broker endpoint is token-authenticated, including read-only
        # health reads.  Keep the token on-device rather than exporting it to
        # the Mac process or placing it in the SSH argument vector.
        script = '''import pathlib,urllib.request
secret=pathlib.Path('/var/jb/etc/trollstorelite-srd-bridge.token').read_text(encoding='ascii').strip()
request=urllib.request.Request('http://127.0.0.1:48654/v1/runtime',headers={'X-TrollStore-Bridge-Token':secret})
with urllib.request.urlopen(request,timeout=10) as response:
 print(response.read().decode('utf-8'))
'''
        status = remote("/var/jb/usr/bin/python3 - <<'PY'\n" + script + "PY",
                        check=False, capture=True)
        assert status is not None
        if status.returncode:
            return {}
        try:
            return json.loads(status.stdout.decode("utf-8", "replace"))
        except ValueError:
            return {}

    runtime_healthy = False
    app_runtime_healthy = False
    if not args.dry_run and not package_changes and not args.link_only:
        snapshot = runtime_snapshot()
        runtime_healthy = injection_ready(snapshot)
        # An app-only Control update needs the authenticated installer broker,
        # not a fresh ElleKit generation.  Treating a healthy broker with a
        # temporarily incomplete injection snapshot as a rebuild request can
        # replace an otherwise stable runtime before the IPA is even uploaded.
        app_runtime_healthy = bool(args.apps_only and snapshot.get("crypstore_ok"))
    if args.link_only:
        # A missing Link icon must not trigger an unrelated runtime/Cryptex
        # reinstall. Require the existing authenticated broker to be usable.
        if not args.dry_run and not runtime_snapshot():
            raise SystemExit("Link-only repair requires the existing authenticated device bridge")
        log("LINK_ONLY=PASS; existing runtime left unchanged")
    elif app_runtime_healthy:
        log("APP_ONLY_RUNTIME=PASS — authenticated Control installer is healthy; runtime left unchanged")
    elif runtime_healthy:
        log("FULL INJECTION OBTAINED — healthy ElleKit generation preserved; no unsafe reinstall")
    else:
        log("renewing dpkg/filter-derived SRD runtime trust")
        if not args.dry_run:
            subprocess.run(command,check=True)
            # A successful installer process is not itself proof of injection.
            # Wait for the live endpoint to confirm ElleKit and at least one
            # dylib/target before printing the success milestone.
            deadline = time.monotonic() + 90
            while time.monotonic() < deadline:
                if injection_ready(runtime_snapshot()):
                    runtime_healthy = True
                    break
                time.sleep(2)
            if not runtime_healthy:
                log("FULL INJECTION NOT OBTAINED — live ElleKit target gate failed")
                return 1
            log("FULL INJECTION OBTAINED — refreshed ElleKit live-target gate passed")

    def app_info(bundle_id: str) -> dict:
        if args.dry_run:
            return {}
        script = f'''import json,pathlib,plistlib,subprocess
prefix={bundle_id!r}+' : '
rows=subprocess.check_output(['/var/jb/usr/bin/uicache','-l'],text=True).splitlines()
paths=[row[len(prefix):].strip() for row in rows if row.startswith(prefix)]
answer={{}}
if len(paths)==1:
 p=pathlib.Path(paths[0]); path=str(p)
 allowed=path.startswith(('/private/var/containers/Bundle/Application/','/var/containers/Bundle/Application/','/private/var/run/com.apple.security.cryptexd/mnt/'))
 info=plistlib.loads((p/'Info.plist').read_bytes()) if allowed else {{}}
 executable=str(info.get('CFBundleExecutable',''))
 icons=info.get('CFBundleIcons',{{}}).get('CFBundlePrimaryIcon',{{}}).get('CFBundleIconFiles',[])
 icon=bool(isinstance(icons,list) and any(isinstance(name,str) and '/' not in name and any((p/(name+suffix)).is_file() and (p/(name+suffix)).stat().st_size>8 for suffix in ('@2x.png','@3x.png','.png')) for name in icons))
 answer={{'path':path,'version':str(info.get('CFBundleShortVersionString','')),
 'build':str(info.get('CFBundleVersion','')),
 'zero_sky':str(info.get('ZeroSkyDistributionName','')),
 'registered':bool(allowed and info.get('CFBundleIdentifier')=={bundle_id!r}),
 'executable':bool(executable and '/' not in executable and (p/executable).is_file()),
 'icon':icon}}
print(json.dumps(answer))
'''
        result = remote("/var/jb/usr/bin/python3 - <<'PY'\n"+script+"PY",
                        capture=True)
        assert result is not None
        if result.returncode:
            return {}
        try:
            return json.loads(result.stdout.decode("utf-8", "replace"))
        except ValueError:
            return {}

    def install_ipa(path: pathlib.Path, bundle_id: str, *, version: str,
                    build: str | None = None, zero_sky: bool = False) -> None:
        if not path.is_file(): raise SystemExit(f"missing app payload: {path}")
        current = app_info(bundle_id)
        matches = current.get("version") == version
        if build is not None:
            matches = matches and current.get("build") == build
        if zero_sky:
            matches = (matches and current.get("zero_sky") == "0-Sky Link"
                       and current.get("registered") is True
                       and current.get("executable") is True
                       and current.get("icon") is True)
        if matches and not args.force_apps:
            log(f"preserving verified {bundle_id} {version or build}; reinstall is unnecessary")
            return
        # The device-side Cryptex installer caches extraction workspaces by
        # input pathname. A stable filename can therefore resurrect the prior
        # application after an asset-only or version update. Content-address
        # the bounded, project-owned upload so new bytes always get a new
        # workspace while retries of identical bytes remain idempotent.
        payload = path.read_bytes()
        payload_id = hashlib.sha256(payload).hexdigest()[:16]
        remote_path=f"/var/mobile/0sky-bootstrap-{payload_id}-{path.name}"
        log(f"uploading app {path.name}")
        remote(f"cat > {shlex.quote(remote_path)}", payload)
        script=f'''import json,urllib.request
token=open('/var/jb/etc/trollstorelite-srd-bridge.token').read().strip()
data=json.dumps({{"arguments":["install",{remote_path!r}]}}).encode()
request=urllib.request.Request('http://127.0.0.1:48654/v1/trollstore',data=data,headers={{'Content-Type':'application/json','X-TrollStore-Bridge-Token':token}})
result=json.load(urllib.request.urlopen(request,timeout=1800))
print(json.dumps({{"status":result.get("status"),"stdout":result.get("stdout"),"stderr":result.get("stderr")}},indent=2))
raise SystemExit(0 if result.get('status')==0 else 1)
'''
        if args.dry_run:
            remote("/var/jb/usr/bin/python3 - <<'PY'\n"+script+"PY")
            return
        result = remote("/var/jb/usr/bin/python3 - <<'PY'\n"+script+"PY",
                        check=False, timeout=1830)
        assert result is not None
        if result.returncode:
            raise SystemExit(f"app install command failed ({result.returncode}): {bundle_id}")
        deadline = time.monotonic() + 60
        while time.monotonic() < deadline:
            observed = app_info(bundle_id)
            health = runtime_snapshot()
            if (observed.get("version") == version and
                    (build is None or observed.get("build") == build) and
                    (not zero_sky or (observed.get("registered") is True
                                      and observed.get("executable") is True
                                      and observed.get("icon") is True)) and
                    (bundle_id != "com.liquidsky.CrypStore" or health.get("crypstore_ok"))):
                log(f"verified app install: {bundle_id} {version or build}")
                return
            time.sleep(2)
        raise SystemExit(f"app install completed but health did not converge: {bundle_id}")

    if args.apps or args.commissary or args.zero_sky_ipa:
        if not args.link_only:
            remote("touch /var/jb/.installed_0-sky___")
        if not args.dry_run:
            for _ in range(30):
                # Reuse the authenticated runtime read rather than treating a
                # broker 403 as evidence that the bridge is unavailable.
                if runtime_snapshot(): break
                time.sleep(1)
            else: raise SystemExit("0-Sky Control bridge did not become ready")
        if args.apps or args.commissary:
            install_ipa(packages/"Commissary-Universal.ipa",
                        "com.liquidsky.CrypStore", version="3.5.28", build="3.5.28.0")
        if args.apps:
            sileo = support/"apps/Sileo-0-Sky.ipa"
            if sileo.is_file():
                install_ipa(sileo, "org.coolstar.SileoStore",
                            version="2.5.1", build="4", zero_sky=True)
    if args.zero_sky_ipa:
        install_ipa(args.zero_sky_ipa.expanduser().resolve(),
                    "codes.liquidsky.research.zerosky", version="1.9.0", build="48",
                    zero_sky=True)
    log("bootstrap complete")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
