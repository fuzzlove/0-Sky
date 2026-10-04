#!/usr/bin/env python3
"""Fetch pinned Python archives and assemble the self-contained dual-architecture host runtime."""
from __future__ import annotations
import argparse, hashlib, json, os, pathlib, shutil, subprocess, tarfile, urllib.error, urllib.parse, urllib.request

ROOT=pathlib.Path(__file__).resolve().parents[1]
SOURCES=ROOT/"manifests/host-runtime-sources.json"
ARCHS=("arm64","x86_64")


class RuntimeBuildError(RuntimeError):
    def __init__(self, detail: str, remediation: str):
        super().__init__(detail)
        self.detail=detail; self.remediation=remediation


def digest(path: pathlib.Path) -> str:
    value=hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda:stream.read(1024*1024),b""): value.update(block)
    return value.hexdigest()


def download(url: str, expected: str, destination: pathlib.Path, *, offline: bool=False) -> None:
    if destination.is_file() and digest(destination)==expected: return
    action=(f"Download the pinned archive from:\n  {url}\nPlace it at:\n  {destination}\n"
            f"Verify it with:\n  shasum -a 256 '{destination}'\nExpected SHA-256:\n  {expected}\n"
            "Then rerun the same host-runtime build command. Do not use a different version.")
    if offline:
        raise RuntimeBuildError(f"verified cached runtime archive is missing: {destination.name}",action)
    temporary=destination.with_suffix(destination.suffix+".partial")
    if temporary.exists(): temporary.unlink()
    request=urllib.request.Request(url,headers={"User-Agent":"0-Sky-release-builder/1"})
    try:
        with urllib.request.urlopen(request,timeout=60) as response, temporary.open("wb") as output:
            if response.geturl().split(":",1)[0] != "https":
                raise RuntimeBuildError("runtime download left HTTPS",action)
            shutil.copyfileobj(response,output)
    except (OSError, urllib.error.URLError) as error:
        temporary.unlink(missing_ok=True)
        raise RuntimeBuildError(f"could not download {destination.name}: {type(error).__name__}",action) from error
    if digest(temporary)!=expected:
        temporary.unlink()
        raise RuntimeBuildError(f"runtime archive digest mismatch: {destination.name}",action)
    os.replace(temporary,destination)


def safe_extract(archive: pathlib.Path, destination: pathlib.Path) -> None:
    with tarfile.open(archive,"r:gz") as bundle:
        for member in bundle.getmembers():
            value=pathlib.PurePosixPath(member.name)
            if value.is_absolute() or ".." in value.parts:
                raise RuntimeError("unsafe Python archive path")
            if member.isdev() or member.isfifo(): raise RuntimeError("unsupported Python archive member")
            if member.issym() or member.islnk():
                target=pathlib.PurePosixPath(member.linkname)
                if target.is_absolute() or ".." in target.parts: raise RuntimeError("unsafe Python archive link")
        bundle.extractall(destination,filter="data")


def write_executable(path: pathlib.Path, data: bytes) -> None:
    path.write_bytes(data); path.chmod(0o755)


def component(name: str, path: pathlib.Path, root: pathlib.Path, license_path: pathlib.Path,
              version: str, verification: str="sha256+script", payloads: dict|None=None,
              notices: list[pathlib.Path]|None=None) -> dict:
    answer={"name":name,"path":path.relative_to(root).as_posix(),"sha256":digest(path),
            "architectures":list(ARCHS),"version":version,
            "license":license_path.relative_to(root).as_posix(),
            "runtime_requirements":["macOS 15 or newer"],
            "destination":"application-bundled","verification":verification}
    if payloads: answer["payloads"]=payloads
    if notices: answer["notices"]=[item.relative_to(root).as_posix() for item in notices]
    return answer


def build(kit: pathlib.Path, cache: pathlib.Path, *, offline: bool=False) -> pathlib.Path:
    try: kit=kit.resolve(strict=True)
    except OSError as error:
        raise RuntimeBuildError(f"kit directory is unavailable: {kit}",
                                "Pass the absolute path to a writable copy of the authorized kit containing SHA256SUMS.") from error
    if not (kit/"SHA256SUMS").is_file():
        raise RuntimeBuildError("kit is missing SHA256SUMS",
                                "Restore the complete authorized kit, verify its provenance, and pass its directory to this command.")
    host=kit/"host-mac"; runtime=host/"runtime"
    if runtime.exists(): shutil.rmtree(runtime)
    runtime.mkdir(parents=True); (runtime/"bin").mkdir(); cache.mkdir(parents=True,exist_ok=True)
    source=json.loads(SOURCES.read_text())["python"]
    payloads={}
    license_source=None
    for arch in ARCHS:
        row=source["archives"][arch]; archive=cache/pathlib.Path(urllib.parse.unquote(row["url"])).name
        download(row["url"],row["sha256"],archive,offline=offline)
        target=runtime/"python"/arch; target.mkdir(parents=True)
        safe_extract(archive,target)
        python=target/"python/bin/python3.12"
        if not python.is_file(): raise RuntimeError("Python archive layout is unsupported")
        inspection=subprocess.run(["/usr/bin/lipo","-archs",str(python)],capture_output=True,
                                  text=True,timeout=15,check=False)
        observed=inspection.stdout.split() if inspection.returncode == 0 else []
        if observed != [arch]: raise RuntimeError(f"Python payload architecture mismatch: {arch}")
        payloads[arch]={"path":python.relative_to(kit).as_posix(),"sha256":digest(python)}
        candidate=target/"python/lib/python3.12/LICENSE.txt"
        if candidate.is_file(): license_source=candidate
    if license_source is None: raise RuntimeError("Python license is missing")
    licenses=runtime/"licenses"; licenses.mkdir()
    license_path=licenses/"PYTHON.txt"; shutil.copy2(license_source,license_path)
    builder_license=licenses/"PYTHON-BUILD-STANDALONE-MPL-2.0.txt"
    shutil.copy2(ROOT/"bridge/HostRuntime/LICENSE.python-build-standalone.txt",builder_license)
    first_party_license=licenses/"0-SKY-EULA.md"
    shutil.copy2(ROOT/"bridge/0SkyBridge/Resources/Legal/EULA.md",first_party_license)
    wrapper=runtime/"bin/python3"
    write_executable(wrapper,b'''#!/bin/sh\nset -eu\nhere=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)\ncase "$(uname -m)" in arm64|x86_64) arch=$(uname -m);; *) echo "Unsupported Mac architecture" >&2; exit 64;; esac\nexec "$here/python/$arch/python/bin/python3.12" "$@"\n''')
    components=[component("python3",wrapper,kit,license_path,source["version"],payloads=payloads,
                          notices=[builder_license])]
    for name,source_path in (("iproxy",ROOT/"bridge/HostRuntime/usbmux_tool.py"),
                             ("idevice_id",ROOT/"bridge/HostRuntime/usbmux_tool.py"),
                             ("dpkg-deb",ROOT/"bridge/HostRuntime/dpkg_deb.py")):
        target=runtime/"bin"/name; shutil.copy2(source_path,target); target.chmod(0o755)
        components.append(component(name,target,kit,first_party_license,"0-Sky compatibility 1.0"))
    manifest={"schema":2,"platform":"macOS","components":components,
              "source_lock":"manifests/host-runtime-sources.json"}
    manifest_path=host/"HOST_RUNTIME_MANIFEST.json"
    manifest_path.write_text(json.dumps(manifest,indent=2,sort_keys=True)+"\n")
    hashes=kit/"SHA256SUMS"
    rows=[row for row in hashes.read_text(encoding="utf-8").splitlines()
          if not row.split(None,1)[-1].removeprefix("./").startswith("host-mac/runtime/")
          and row.split(None,1)[-1].removeprefix("./") != "host-mac/HOST_RUNTIME_MANIFEST.json"]
    for path in sorted([manifest_path,*[item for item in runtime.rglob("*") if item.is_file()] ]):
        rows.append(f"{digest(path)}  ./{path.relative_to(kit).as_posix()}")
    hashes.write_text("\n".join(sorted(rows))+"\n",encoding="utf-8")
    return manifest_path


def main()->int:
    parser=argparse.ArgumentParser(description=__doc__); parser.add_argument("kit",type=pathlib.Path)
    parser.add_argument("--cache",type=pathlib.Path,default=ROOT/".build/host-runtime-cache")
    parser.add_argument("--offline",action="store_true",
                        help="use only already verified archives in --cache")
    args=parser.parse_args()
    try: print(f"HOST_RUNTIME_BUILD=PASS manifest={build(args.kit,args.cache,offline=args.offline)}")
    except RuntimeBuildError as error:
        print(f"HOST_RUNTIME_BUILD=FAIL {error.detail}")
        print("REQUIRED_ACTION:")
        for line in error.remediation.splitlines(): print(f"  {line}")
        return 2
    except Exception as error:
        print(f"HOST_RUNTIME_BUILD=FAIL {type(error).__name__}: {error}")
        print("REQUIRED_ACTION:")
        print("  Restore the authorized kit and pinned cache, confirm /usr/bin/lipo is available, then rerun with --offline to isolate download failures.")
        return 2
    return 0
if __name__=="__main__": raise SystemExit(main())
