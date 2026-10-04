#!/usr/bin/env python3
"""Rebuild/install or inspect the 0-Sky runtime over authorized SRD channels.

Credits: 0-Sky Project.
"""

from __future__ import annotations
import argparse, json, pathlib, subprocess, sys
from instance import resolve as resolve_support


class RefreshError(RuntimeError):
    pass


def run(argv: list[str], *, timeout: int, **kwargs) -> subprocess.CompletedProcess:
    try:
        return subprocess.run(argv, timeout=timeout, **kwargs)
    except subprocess.TimeoutExpired as error:
        raise RefreshError(f"{pathlib.Path(argv[0]).name} timed out after {timeout} seconds") from error
    except OSError as error:
        raise RefreshError(f"could not start {pathlib.Path(argv[0]).name}") from error


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--support", type=pathlib.Path,
                        default=pathlib.Path.home()/"Library/Application Support/0-Sky")
    parser.add_argument("--instance-name")
    parser.add_argument("--status", action="store_true")
    parser.add_argument("--registry-only", action="store_true",
                        help="request a device rescan without rebuilding trust")
    args = parser.parse_args()
    support = resolve_support(args.support, args.instance_name)
    config = json.loads((support/"config.json").read_text())
    known_hosts = pathlib.Path(config.get("ssh_known_hosts", support/"device-known-hosts"))
    host_alias = config.get("ssh_host_alias")
    if (not host_alias or not known_hosts.is_file() or known_hosts.is_symlink() or
            known_hosts.stat().st_mode & 0o077):
        raise SystemExit("device SSH host-key pin is missing or unsafe; repair pairing over USB")
    ssh = ["/usr/bin/ssh", "-o", "BatchMode=yes", "-o", "ConnectTimeout=10",
           "-o", "LogLevel=ERROR",
           "-o", "StrictHostKeyChecking=yes",
           "-o", f'UserKnownHostsFile="{known_hosts}"',
           "-o", "GlobalKnownHostsFile=/dev/null", "-o", f"HostKeyAlias={host_alias}",
           "-o", "IdentitiesOnly=yes", "-o", "PasswordAuthentication=no",
           "-o", "KbdInteractiveAuthentication=no",
           "-i", config["ssh_key"], "-p", config["ssh_port"],
           f"root@{config['ssh_host']}"]
    root = run(ssh + ['test "$(id -u)" = 0'], timeout=30, check=False)
    if root.returncode:
        print("[0-Sky Link refresh] ROOT NOT OBTAINED — refusing runtime mutation", flush=True)
        return root.returncode
    print("[0-Sky Link refresh] ROOT OBTAINED — authenticated device uid=0", flush=True)

    def bridge_get(endpoint: str) -> subprocess.CompletedProcess:
        """Read a fixed authenticated broker endpoint without exporting its token."""
        if endpoint not in ("/v1/runtime", "/v1/status"):
            raise ValueError("unsupported bridge endpoint")
        program = (
            "import pathlib,urllib.request\n"
            "secret=pathlib.Path('/var/jb/etc/trollstorelite-srd-bridge.token').read_text(encoding='ascii').strip()\n"
            f"request=urllib.request.Request('http://127.0.0.1:48654{endpoint}',"
            "headers={'X-TrollStore-Bridge-Token':secret})\n"
            "with urllib.request.urlopen(request,timeout=10) as response:\n"
            " print(response.read().decode('utf-8'))\n"
        )
        command = "/var/jb/usr/bin/python3 - <<'PY'\n" + program + "PY"
        return run(
            ssh + [command], stdout=subprocess.PIPE, stderr=subprocess.PIPE,
            text=True, check=False, timeout=30,
        )

    if args.status:
        command = "/var/jb/usr/bin/python3 /var/jb/usr/local/libexec/srd-runtime-manager.py status"
        print("[0-Sky Link refresh] device command: " + command, flush=True)
        result = run(ssh + [command], timeout=120, check=False)
        return result.returncode
    if args.registry_only:
        command = ("/var/jb/usr/bin/python3 /var/jb/usr/local/libexec/"
                   "srd-runtime-manager.py sync; /var/jb/usr/bin/python3 "
                   "/var/jb/usr/local/libexec/crypstore-appctl.py "
                   "repair-preferences --json; /var/jb/usr/bin/python3 "
                   "/var/jb/usr/local/libexec/crypstore-appctl.py list --json")
        print("[0-Sky Link refresh] device command: " + command, flush=True)
        result = run(ssh + [command], timeout=180, check=False)
        return result.returncode

    sync = support/"automation/tools/srd-runtime-manager/sync_runtime_cryptex.py"
    companion_python = support/"venv/bin/python3"
    python = str(companion_python if companion_python.is_file() else pathlib.Path(sys.executable))
    command = [python, str(sync), "--host", config["ssh_host"],
               "--port", config["ssh_port"], "--key", config["ssh_key"],
               "--udid", config["udid"], "--known-hosts", str(known_hosts),
               "--host-alias", host_alias]
    print("[0-Sky Link refresh] rebuilding the dpkg/filter-derived trust runtime", flush=True)
    result = run(command, timeout=1800, check=False)
    if result.returncode:
        return result.returncode
    proof = bridge_get("/v1/runtime")
    try:
        state = json.loads(proof.stdout)
    except ValueError:
        state = {}
    full = bool(proof.returncode == 0 and state.get("ok") and state.get("ellekit_ok") and
                state.get("manager_active") and not state.get("paused") and
                state.get("loaded_dylibs", 0) >= 1 and state.get("loaded_targets", 0) >= 1)
    if not full:
        print("[0-Sky Link refresh] FULL INJECTION NOT OBTAINED — live gate failed", flush=True)
        return 1
    print("[0-Sky Link refresh] FULL INJECTION OBTAINED — ElleKit live-target gate passed", flush=True)
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (RefreshError, OSError, ValueError, KeyError, json.JSONDecodeError) as error:
        print(f"[0-Sky Link refresh] FAILED: {error}", file=sys.stderr)
        raise SystemExit(2)
