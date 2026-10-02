#!/usr/bin/env python3
"""Build the reviewed mitmproxy release for the 0-Sky Mac host.

This builds from a pinned upstream commit and activates a versioned virtual
environment. Dependency versions and the locally built wheel hash are recorded
for review; they are not treated as a release lockfile.
"""

from __future__ import annotations

import argparse
from datetime import datetime, timezone
import hashlib
from http.client import HTTPConnection
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
import os
from pathlib import Path
import re
import shutil
import socket
import subprocess
import sys
import tempfile
import threading
import time


UPSTREAM = "https://github.com/mitmproxy/mitmproxy.git"
RELEASE = "v12.2.3"
VERSION = "12.2.3"
REVISION = "6c09d56e4c29a92f5ad01b03199977584b8ea14f"


def checked(argv: list[str], *, timeout: int = 300, cwd: Path | None = None,
            env: dict[str, str] | None = None) -> str:
    result = subprocess.run(argv, cwd=cwd, stdin=subprocess.DEVNULL,
                            stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                            text=True, timeout=timeout, check=False, env=env)
    if result.returncode:
        error = re.sub(r"https?://[^/@\s]+:[^/@\s]+@", "https://<redacted>@",
                       result.stderr[-1500:])
        error = re.sub(r"/Users/[^/\s]+", "/Users/<redacted>", error)
        error = re.sub(r"(?i)(token|password|secret)=\S+", r"\1=<redacted>", error)
        raise RuntimeError(f"{Path(argv[0]).name} failed ({result.returncode}): "
                           f"{error}")
    return result.stdout.strip()


def verify_source(source: Path) -> None:
    if source.is_symlink() or not source.is_dir():
        raise RuntimeError("source directory is missing or symbolic")
    revision = checked(["git", "rev-parse", "HEAD"], cwd=source)
    origin = checked(["git", "remote", "get-url", "origin"], cwd=source)
    dirty = checked(["git", "status", "--porcelain", "--untracked-files=no"], cwd=source)
    if revision != REVISION or origin.rstrip("/") not in {
            UPSTREAM, UPSTREAM.removesuffix(".git")} or dirty:
        raise RuntimeError("mitmproxy source does not match the reviewed upstream revision")


def build_wheel(python: Path, source: Path, wheel_dir: Path) -> Path:
    epoch = checked(["git", "log", "-1", "--format=%ct"], cwd=source)
    if not epoch.isdecimal():
        raise RuntimeError("source commit timestamp is invalid")
    environment = pip_environment()
    environment["SOURCE_DATE_EPOCH"] = epoch
    checked([str(python), "-m", "pip", "wheel", "--no-deps", "--wheel-dir",
             str(wheel_dir), "--index-url", "https://pypi.org/simple",
             str(source)], timeout=900, env=environment)
    matches = list(wheel_dir.glob(f"mitmproxy-{VERSION}-py3-none-any.whl"))
    if len(matches) != 1 or matches[0].is_symlink():
        raise RuntimeError("reviewed mitmproxy wheel was not produced")
    return matches[0]


def pip_environment() -> dict[str, str]:
    environment = {key: value for key, value in os.environ.items()
                   if not key.startswith("PIP_")}
    environment.update(PIP_CONFIG_FILE=os.devnull,
                       PIP_DISABLE_PIP_VERSION_CHECK="1", PIP_NO_INPUT="1")
    return environment


def verify_install(target: Path) -> None:
    for command in ("mitmproxy", "mitmdump"):
        output = checked([str(target / "bin" / command), "--version"], timeout=20)
        if f"Mitmproxy: {VERSION}" not in output:
            raise RuntimeError(f"{command} did not report reviewed version {VERSION}")
    checked([str(target / "bin" / "python"), "-m", "compileall", "-q",
             str(target / "lib")], timeout=120)


def smoke_proxy(target: Path) -> None:
    class Probe(BaseHTTPRequestHandler):
        def do_GET(self) -> None:
            if self.path != "/0sky-mitmproxy-probe":
                self.send_error(404)
                return
            self.send_response(200)
            self.end_headers()
            self.wfile.write(b"0sky-mitmproxy-ok")

        def log_message(self, *_args: object) -> None:
            return

    upstream = ThreadingHTTPServer(("127.0.0.1", 0), Probe)
    threading.Thread(target=upstream.serve_forever, daemon=True).start()
    with socket.socket() as available:
        available.bind(("127.0.0.1", 0))
        proxy_port = available.getsockname()[1]
    try:
        with tempfile.TemporaryDirectory(prefix="0sky-mitmproxy-smoke-") as config:
            proxy = subprocess.Popen([
                str(target / "bin" / "mitmdump"), "--listen-host", "127.0.0.1",
                "--listen-port", str(proxy_port), "--set", f"confdir={config}"],
                stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL)
            try:
                ready = False
                for _ in range(100):
                    if proxy.poll() is not None:
                        break
                    try:
                        with socket.create_connection(("127.0.0.1", proxy_port), timeout=0.1):
                            ready = True
                            break
                    except OSError:
                        time.sleep(0.1)
                if not ready:
                    raise RuntimeError("mitmdump did not start a localhost listener")
                connection = HTTPConnection("127.0.0.1", proxy_port, timeout=10)
                try:
                    connection.request("GET", f"http://127.0.0.1:{upstream.server_port}/0sky-mitmproxy-probe")
                    response = connection.getresponse()
                    body = response.read()
                    if response.status != 200 or body != b"0sky-mitmproxy-ok":
                        raise RuntimeError("mitmdump localhost proxy response failed")
                finally:
                    connection.close()
            finally:
                proxy.terminate()
                try:
                    proxy.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    proxy.kill()
                    proxy.wait(timeout=5)
    finally:
        upstream.shutdown()
        upstream.server_close()


def activate(target: Path, current: Path) -> Path | None:
    backup = None
    if current.is_symlink():
        pass
    elif current.exists():
        stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
        backup = current.with_name(current.name + ".backup-" + stamp)
        if backup.exists():
            raise RuntimeError("activation backup already exists")
        current.rename(backup)
    temporary = current.with_name("." + current.name + ".next")
    try:
        if temporary.exists() or temporary.is_symlink():
            raise RuntimeError("activation temporary path already exists")
        temporary.symlink_to(target.name, target_is_directory=True)
        os.replace(temporary, current)
    except Exception:
        if temporary.is_symlink():
            temporary.unlink()
        if backup is not None and not current.exists():
            backup.rename(current)
        raise
    return backup


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--python", type=Path, default=Path(sys.executable),
                        help="Python 3.12+ with pip")
    parser.add_argument("--source", type=Path,
                        help="existing clean checkout of the pinned upstream commit")
    parser.add_argument("--tool-root", type=Path,
                        default=Path.home() / "Library/Application Support/0-Sky/tools")
    args = parser.parse_args()
    python = args.python.expanduser().resolve(strict=True)
    version = checked([str(python), "-c", "import sys; print(sys.version_info.major, sys.version_info.minor)"])
    if tuple(map(int, version.split())) < (3, 12):
        raise RuntimeError("mitmproxy requires Python 3.12 or newer")
    raw_root = args.tool_root.expanduser()
    if raw_root.is_symlink():
        raise RuntimeError("tool root must not be symbolic")
    root = raw_root.resolve()
    root.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(prefix="0sky-mitmproxy-build-") as temporary:
        workspace = Path(temporary)
        if args.source:
            raw_source = args.source.expanduser()
            if raw_source.is_symlink():
                raise RuntimeError("source directory must not be symbolic")
            source = raw_source.resolve(strict=True)
            verify_source(source)
            clean_source = workspace / "reviewed-source"
            checked(["git", "clone", "--quiet", "--no-hardlinks", str(source),
                     str(clean_source)], timeout=300)
            checked(["git", "checkout", "--quiet", "--detach", REVISION],
                    cwd=clean_source)
            source = clean_source
        else:
            source = workspace / "source"
            checked(["git", "clone", "--depth", "1", "--single-branch", "--branch",
                     RELEASE, UPSTREAM, str(source)], timeout=300)
            verify_source(source)
        if checked(["git", "rev-parse", "HEAD"], cwd=source) != REVISION:
            raise RuntimeError("clean build source revision changed")
        wheel = build_wheel(python, source, workspace / "wheels")
        digest = hashlib.sha256(wheel.read_bytes()).hexdigest()
        target = root / f"mitmproxy-{VERSION}-{REVISION[:12]}-{digest[:12]}"
        if target.is_symlink():
            raise RuntimeError("versioned environment must not be symbolic")
        if not target.exists():
            try:
                checked([str(python), "-m", "venv", str(target)], timeout=120)
                checked([str(target / "bin" / "python"), "-m", "pip", "install",
                         "--only-binary=:all:", "--index-url", "https://pypi.org/simple",
                         str(wheel)], timeout=900, env=pip_environment())
                verify_install(target)
                smoke_proxy(target)
            except Exception:
                shutil.rmtree(target, ignore_errors=True)
                raise
        else:
            verify_install(target)
            smoke_proxy(target)
            provenance = target / "0sky-provenance.json"
            if (not provenance.is_file() or
                    json.loads(provenance.read_text()).get("built_wheel_sha256") != digest):
                raise RuntimeError("existing environment has different build provenance")
        packages = json.loads(checked([str(target / "bin" / "python"), "-m", "pip",
                                       "list", "--format=json"], timeout=30,
                                      env=pip_environment()))
        if not isinstance(packages, list) or not all(
                isinstance(item, dict) and isinstance(item.get("name"), str) and
                isinstance(item.get("version"), str) for item in packages):
            raise RuntimeError("installed package inventory is malformed")
        evidence = {"schema": 1, "upstream": UPSTREAM, "release": RELEASE,
                    "source_revision": REVISION, "version": VERSION,
                    "built_wheel_sha256": digest,
                    "localhost_proxy_smoke": "PASS",
                    "installed_packages": sorted(packages, key=lambda item: item["name"].lower()),
                    "checked_at": datetime.now(timezone.utc).isoformat()}
        (target / "0sky-provenance.json").write_text(json.dumps(evidence, indent=2) + "\n")
        backup = activate(target, root / "mitmproxy-current")
    print(json.dumps({"result": "INSTALLED", "version": VERSION,
                      "source_revision": REVISION, "wheel_sha256": digest,
                      "previous_environment_saved": backup is not None}, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
