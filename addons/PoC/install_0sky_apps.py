#!/usr/bin/env python3
"""Install 0-Sky Control and 0-Sky Link as research cryptexes.

This script builds and optionally installs both apps as research cryptexes
on an Apple Security Research Device (SRD).

Usage examples:

# Build both cryptexes without installing
python3 install_0sky_apps.py

# Install on a paired device using its exact UDID
python3 install_0sky_apps.py --install --udid YOUR_UDID

# Build and install with explicit device
python3 install_0sky_apps.py --install --udid YOUR_UDID

# Build with custom IPA paths and install
python3 install_0sky_apps.py --control-ipa /path/to/control.ipa \
    --link-ipa /path/to/link.ipa --install --udid YOUR_UDID

# Build, install, then reboot to refresh SpringBoard icons
python3 install_0sky_apps.py --install --reboot-for-icons

# Run diagnostics only
python3 install_0sky_apps.py --doctor

Environment variables:
- SRD_UDID: Override the default device UDID
- SRD_PYTHON: Path to Python with pymobiledevice3 11.3.1
- SRD_DEVICE_CONFIG: Path to device configuration directory
"""

import argparse
import hashlib
import json
import os
import pathlib
import plistlib
import re
import runpy
import shutil
import subprocess
import sys
import tempfile
import time
import zipfile

from restore_srd_bootstrap import DEFAULT_SRDSH_KIT, validate_srdsh_kit


def detect_srd_udid() -> str | None:
    """Detect the first available Apple Security Research Device UDID."""
    try:
        python_path = find_device_python()
        result = subprocess.run(
            [python_path, "-m", "pymobiledevice3", "remote", "browse", "--native"],
            capture_output=True,
            text=True,
            timeout=30
        )
        if result.returncode == 0:
            lines = result.stdout.strip().split('\n')
            for line in lines:
                match = re.search(r'[0-9A-F]{8}-[0-9A-F]{4}-[0-9A-F]{6}-[0-9A-F]{12}', line, re.IGNORECASE)
                if match:
                    return match.group(0).upper()
    except Exception:
        pass
    return None


def find_device_python(explicit: str | None = None) -> str:
    """Find a suitable Python with pymobiledevice3 11.3.1."""
    override = explicit or os.environ.get("SRD_PYTHON")
    
    if override:
        candidate = pathlib.Path(override).expanduser()
        if candidate.is_file():
            return str(candidate.absolute())
    
    common_paths = [
        pathlib.Path(__file__).resolve().parents[2] / ".venv/bin/python",
        pathlib.Path.home() / "Desktop" / "0-Sky" / ".venv/bin/python",
        pathlib.Path.home() / "0-Sky" / ".venv/bin/python",
    ]
    
    REQUIRED_PYMOBILEDEVICE3 = "11.3.1"
    PROBE = (
        "import importlib.metadata, pymobiledevice3; "
        "from pymobiledevice3.remote.native_tunnel import NativeRemotedTunnel; "
        "from pymobiledevice3.services.cryptexd import CryptexdService; "
        "from pymobiledevice3.restore.tss import TSSRequest; "
        "print(importlib.metadata.version('pymobiledevice3'))"
    )
    
    failures = []
    for candidate in common_paths:
        if not candidate.is_file():
            failures.append(f"{candidate}: missing")
            continue
        try:
            result = subprocess.run(
                [str(candidate), "-c", PROBE], capture_output=True, text=True,
                timeout=30,
            )
            version = result.stdout.strip()
            if result.returncode == 0 and version == REQUIRED_PYMOBILEDEVICE3:
                return str(candidate.absolute())
            failures.append(f"{candidate}: pymobiledevice3 {version or 'unavailable'}")
        except Exception as e:
            failures.append(f"{candidate}: {e}")
    
    current_python = pathlib.Path(sys.executable)
    try:
        result = subprocess.run(
            [str(current_python), "-c", PROBE], capture_output=True, text=True,
            timeout=30,
        )
        version = result.stdout.strip()
        if result.returncode == 0 and version == REQUIRED_PYMOBILEDEVICE3:
            return str(current_python.absolute())
        failures.append(f"current python: pymobiledevice3 {version or 'unavailable'}")
    except Exception:
        failures.append("current python: not available")
    
    raise ValueError(
        f"No Python with pinned pymobiledevice3 {REQUIRED_PYMOBILEDEVICE3} found. "
        f"Set SRD_PYTHON environment variable or install requirements. "
        f"Checked: " + "; ".join(failures)
    )


def cryptexctl_path(explicit: str | None = None) -> str:
    """Get the Apple Security Research cryptexctl path."""
    tool = explicit or shutil.which("cryptexctl")
    if not tool:
        fallback = pathlib.Path("/System/Library/SecurityResearch/usr/bin/cryptexctl")
        if fallback.is_file():
            tool = str(fallback)
    if not tool or not shutil.which(tool):
        raise ValueError("Apple Security Research cryptexctl not found. Install Xcode or the Security Research tools.")
    return tool


def find_device_config() -> pathlib.Path | None:
    """Find device configuration directory."""
    env_path = os.environ.get("SRD_DEVICE_CONFIG")
    if env_path:
        return pathlib.Path(env_path).expanduser()
    
    common_paths = [
        pathlib.Path.home() / "Library/Application Support/0-Sky/instances",
        pathlib.Path.home() / ".0-sky/instances",
        pathlib.Path.home() / "Library/Application Support/io.0sky/instances",
    ]
    
    for path in common_paths:
        if path.is_dir():
            return path
    
    return None


def ipa_app(ipa: pathlib.Path, temporary: pathlib.Path) -> pathlib.Path:
    """Extract app from IPA archive."""
    with zipfile.ZipFile(ipa) as archive:
        names = archive.namelist()
        for name in names:
            parts = pathlib.PurePosixPath(name).parts
            if name.startswith("/") or ".." in parts or "\\" in parts:
                raise ValueError(f"Unsafe IPA archive member: {name}")
        apps = {parts[1] for name in names if (parts := pathlib.PurePosixPath(name).parts)
                and len(parts) >= 2 and parts[0] == "Payload" and parts[1].endswith(".app")}
        if len(apps) != 1:
            raise ValueError(f"Expected exactly one Payload/*.app in {ipa}; found {len(apps)}")
    
    subprocess.run(["ditto", "-x", "-k", str(ipa), str(temporary)], check=True)
    return temporary / "Payload" / next(iter(apps))


def get_bundle_info(app: pathlib.Path) -> dict:
    """Extract bundle information from an .app directory."""
    if not app.is_dir() or app.suffix.lower() != ".app":
        raise ValueError(f"Expected an .app bundle: {app}")
    
    plist_path = app / "Info.plist"
    if not plist_path.is_file():
        raise ValueError(f"Missing Info.plist: {app}")
    
    info = plistlib.loads(plist_path.read_bytes())
    
    return {
        "bundle_id": info.get("CFBundleIdentifier"),
        "executable": info.get("CFBundleExecutable"),
        "version": info.get("CFBundleShortVersionString"),
        "build": info.get("CFBundleVersion"),
        "display_name": info.get("CFBundleDisplayName", app.name),
    }


def make_cryptex(identifier: str, version: str, dstroot: pathlib.Path, 
                 output: pathlib.Path, cryptexctl: str):
    """Build a research cryptex bundle with Apple's cryptexctl."""
    output.mkdir(parents=True, exist_ok=True)
    
    command = [cryptexctl]
    command += ["create", "--use-cryptex1-format"]
    command += ["--identifier", identifier]
    command += ["--version", version]
    command += ["--variant", "research"]
    command += ["--output-directory", str(output)]
    command += [str(dstroot)]
    
    subprocess.run(command, check=True)
    
    bundles = list(output.glob("*.cxbd"))
    if len(bundles) != 1:
        raise ValueError(f"Expected one .cxbd bundle, found {len(bundles)} in {output}")
    
    bundle = bundles[0]
    restore_dir = bundle / "Restore"
    manifest_path = restore_dir / "BuildManifest.plist"
    manifest = plistlib.loads(manifest_path.read_bytes())
    
    if not isinstance(manifest, dict) or not manifest.get("BuildIdentities"):
        raise ValueError("Invalid BuildManifest.plist")
    
    identities = [item for item in manifest["BuildIdentities"]
                  if item.get("Info", {}).get("Variant") == "research"]
    if len(identities) != 1:
        raise ValueError(f"Expected one research build identity")
    
    entries = identities[0].get("Manifest", {})
    
    required_assets = {
        "Cryptex1,GenericDmg": "Cryptex1,GenericDmg",
        "Cryptex1,GenericTrustCache": "Cryptex1,GenericTrustCache", 
        "Cryptex1,GenericVolume": "Cryptex1,GenericVolume",
        "Cryptex1,CryptexInfoPlist": "Cryptex1,CryptexInfoPlist"
    }
    
    asset_paths = {}
    for name, entry_name in required_assets.items():
        if entry_name not in entries:
            raise ValueError(f"Missing required asset: {entry_name}")
        
        entry = entries[entry_name]
        relative = entry.get("Info", {}).get("Path")
        if not isinstance(relative, str):
            raise ValueError(f"Missing path for {entry_name}")
        
        path = (restore_dir / relative).resolve()
        if not path.is_file() or not path.stat().st_size:
            raise ValueError(f"Missing or empty asset: {relative}")
        
        digest = hashlib.sha384()
        with path.open("rb") as asset:
            for chunk in iter(lambda: asset.read(1024 * 1024), b""):
                digest.update(chunk)
        
        if digest.digest() != entry.get("Digest"):
            raise ValueError(f"Cryptex asset digest mismatch: {relative}")
        
        asset_paths[name] = str(path)
    
    assets_json = {
        "identifier": identifier,
        "version": version,
        "bundle": str(bundle.resolve()),
        "assets": asset_paths
    }
    
    (output / "assets.json").write_text(json.dumps(assets_json, indent=2) + "\n")
    
    return bundle, assets_json


def check_dependencies(doctor: bool = False, srdsh_kit: pathlib.Path = DEFAULT_SRDSH_KIT,
                       ssh_only: bool = False) -> dict:
    """Check system dependencies and configuration."""
    results = {
        "checks": [],
        "errors": [],
        "warnings": [],
        "success": True
    }

    try:
        kit = validate_srdsh_kit(srdsh_kit, ssh_only=ssh_only)
        results["checks"].append(f"SRD SSH kit: {kit} (checksums verified)")
    except (OSError, ValueError, RuntimeError, KeyError) as error:
        results["errors"].append(f"SRD SSH kit: {error}")
        results["success"] = False

    try:
        results["checks"].append(f"Staged app signing helper: {signing_worker_path()} (exists)")
    except ValueError as error:
        results["errors"].append(str(error))
        results["success"] = False
    
    try:
        tool_path = cryptexctl_path()
        results["checks"].append(f"cryptexctl: {tool_path} (OK)")
    except ValueError as e:
        results["errors"].append(f"cryptexctl: {e}")
        results["success"] = False
    
    for tool in ["ditto", "codesign", "ldid", "otool", "xattr"]:
        if shutil.which(tool):
            results["checks"].append(f"{tool}: found")
        else:
            results["checks"].append(f"{tool}: not found (optional)")
    
    try:
        python_path = find_device_python()
        results["checks"].append(f"Device Python: {python_path} (OK)")
    except ValueError as e:
        results["errors"].append(f"Device Python: {e}")
        results["success"] = False
    
    control_ipa_found = False
    control_locations = [
        pathlib.Path(__file__).resolve().parent.parent / "Commissary-Universal-signed.ipa",
        pathlib.Path.home() / "Desktop" / "0-Sky" / "addons" / "Commissary-Universal-signed.ipa",
        pathlib.Path.home() / "Desktop" / "0-Sky" / "Commissary-Universal-signed.ipa",
    ]
    
    for ipa in control_locations:
        if ipa.exists():
            results["checks"].append(f"Control IPA: {ipa} (exists)")
            control_ipa_found = True
            break
    if not control_ipa_found:
        results["errors"].append("Control IPA not found. Place Commissary-Universal-signed.ipa in the parent directory.")
        results["success"] = False
    
    poc_dir = pathlib.Path(__file__).resolve().parent
    link_ipa = preferred_link_ipa()
    if link_ipa.exists():
        results["checks"].append(f"Link IPA: {link_ipa} (exists)")
    else:
        results["warnings"].append("Link IPA not found. Place 0-Sky-Link-1.9.0-universal.ipa in the PoC directory.")
    
    appregistrard_path = poc_dir / "appregistrard-build" / "stage-zero" / "dstroot" / "System" / "Applications" / "ZeroSky.app" / "SRDKit"
    if appregistrard_path.exists():
        results["checks"].append(f"appregistrard: {appregistrard_path} (exists)")
    else:
        results["warnings"].append("appregistrard not found at expected location. Install appregistrard on device first.")
    
    config_dir = find_device_config()
    if config_dir:
        results["checks"].append(f"Device config directory: {config_dir} (exists)")
    else:
        results["warnings"].append("Device config directory not found. Set SRD_DEVICE_CONFIG environment variable.")
    
    ssh_keys = [
        pathlib.Path.home() / ".ssh/srdsh_ed25519",
        pathlib.Path.home() / ".ssh/id_ed25519",
    ]
    ssh_found = False
    for ssh_key in ssh_keys:
        if ssh_key.exists():
            results["checks"].append(f"SSH key: {ssh_key} (exists)")
            ssh_found = True
            break
    if not ssh_found:
        results["warnings"].append("SSH key not found. Set up pairing with your SRD first.")
    
    if doctor and not results["success"]:
        print("\n=== DEPENDENCY CHECK FAILED ===")
        for error in results["errors"]:
            print(f"ERROR: {error}")
        for warning in results["warnings"]:
            print(f"WARNING: {warning}")
        print()
    
    return results


def get_device_udid(udid_arg: str | None = None) -> str:
    """Get device UDID from argument or auto-detect."""
    env_udid = os.environ.get("SRD_UDID")
    if env_udid:
        return env_udid
    
    if udid_arg:
        return udid_arg
    
    detected = detect_srd_udid()
    if detected:
        return detected
    
    raise ValueError(
        "Device UDID not specified and no device detected. "
        "Set SRD_UDID environment variable, pass --udid, or connect a device."
    )


def install_built_cryptex(identifier: str, bundle_path: pathlib.Path, assets: dict,
                          udid: str, device_python: str, cryptexctl: str,
                          output_dir: pathlib.Path) -> dict:
    """Install a built cryptex on the device."""
    result = {"success": False, "message": ""}
    
    try:
        check_command = [
            device_python, "-m", "pymobiledevice3", "apps", "query",
            "--udid", udid
        ]
        check_result = subprocess.run(check_command, capture_output=True, text=True)
        if check_result.returncode == 0:
            installed = json.loads(check_result.stdout)
            if identifier in installed:
                result["message"] = f"App {identifier} already installed"
                result["success"] = True
                return result
    except Exception:
        pass
    
    try:
        if "Cryptex1,GenericDmg" in assets:
            from make_cryptex import inspect_bundle

            # Verify the bundle's manifest and digests before using its assets.
            assets = inspect_bundle(bundle_path, "research")
            info = plistlib.loads(
                pathlib.Path(assets["Cryptex1,CryptexInfoPlist"]).read_bytes()
            )
            if info.get("CFBundleIdentifier") != identifier:
                raise ValueError("Cryptex info plist does not match identifier")
            helper = pathlib.Path(__file__).with_name("research_cryptex_poc.py")
            subprocess.run(
                [device_python, str(helper), "install",
                 "--identifier", identifier, "--version", info["CFBundleVersion"],
                 "--udid", udid, "--device-python", device_python,
                 "--image", assets["Cryptex1,GenericDmg"],
                 "--trust-cache", assets["Cryptex1,GenericTrustCache"],
                 "--volume-hash", assets["Cryptex1,GenericVolume"],
                 "--build-manifest", assets["build_manifest"]],
                check=True, timeout=1020,
            )
            result["success"] = True
            result["message"] = f"Successfully installed {identifier}"
            return result

        target = output_dir / "personalized"
        attempt = 1
        while target.exists():
            target = output_dir / f"personalized-{attempt}"
            attempt += 1
        target.mkdir(parents=True)
        
        base = [cryptexctl, "--udid", udid]
        subprocess.run(
            base + ["personalize", "--variant", "research", "--persist",
                   "--output-directory", str(target), str(bundle_path)],
            check=True
        )
        
        signed = list(target.glob("*.cxbd"))
        if len(signed) != 1:
            raise ValueError(f"Expected one personalized .cxbd in {target}")
        
        subprocess.run(
            base + ["install", "--variant", "research", "--persist", str(signed[0])],
            check=True
        )
        
        result["success"] = True
        result["message"] = f"Successfully installed {identifier}"
        
    except subprocess.CalledProcessError as e:
        result["message"] = f"Installation failed: {e}"
    except Exception as e:
        result["message"] = f"Installation error: {e}"
    
    return result


def register_app(bundle_id: str, identifier: str, app_name: str,
                 udid: str, device_python: str) -> dict:
    """Register an app from an installed cryptex."""
    result = {"success": False, "message": ""}
    
    try:
        helper_script = pathlib.Path(__file__).resolve().parent / "register_mounted_app.py"
        if not helper_script.exists():
            result["message"] = "Registration helper not found"
            return result
        
        command = [
            device_python, str(helper_script),
            "--udid", udid,
            "--cryptex-id", identifier,
            "--app-name", app_name
        ]
        
        result_proc = subprocess.run(command, capture_output=True, text=True, timeout=240)
        
        if result_proc.returncode == 0:
            for attempt in range(6):
                query = subprocess.run(
                    [device_python, "-m", "pymobiledevice3", "apps", "query",
                     bundle_id, "--udid", udid],
                    capture_output=True, text=True, check=True, timeout=30,
                )
                installed = json.loads(query.stdout)
                if not isinstance(installed, dict):
                    raise ValueError("App registry query returned an unexpected result")
                if bundle_id in installed:
                    result["success"] = True
                    result["message"] = f"Successfully registered {bundle_id}"
                    break
                if attempt < 5:
                    time.sleep(2)
            if not result["success"]:
                detail = (result_proc.stderr.strip() or result_proc.stdout.strip())
                result["message"] = (
                    f"Registrar exited successfully, but {bundle_id} is absent from the app registry"
                    + (f": {detail}" if detail else "")
                )
        else:
            result["message"] = f"Registration failed: {result_proc.stderr}"
            
    except Exception as e:
        result["message"] = f"Registration error: {e}"
    
    return result


def check_app_icon(bundle_id: str, udid: str, device_python: str) -> dict:
    """Check if an app icon appears in SpringBoard."""
    result = {"success": False, "message": ""}
    
    try:
        helper_script = pathlib.Path(__file__).resolve().parent / "check_app_icon.py"
        if not helper_script.exists():
            result["message"] = "Icon check helper not found"
            return result
        
        command = [
            device_python, str(helper_script),
            "--udid", udid,
            "--bundle-id", bundle_id
        ]
        
        result_proc = subprocess.run(command, capture_output=True, text=True, timeout=30)
        
        if result_proc.returncode == 0:
            result["success"] = True
            result["message"] = f"Icon found for {bundle_id}"
        else:
            detail = result_proc.stderr.strip() or result_proc.stdout.strip()
            result["message"] = f"Icon verification failed for {bundle_id}: {detail}"
            
    except subprocess.CalledProcessError:
        result["message"] = f"Icon not found for {bundle_id}"
    except Exception as e:
        result["message"] = f"Icon check error: {e}"
    
    return result


def signing_worker_path() -> pathlib.Path:
    worker = pathlib.Path(__file__).resolve().parents[2] / (
        "bridge/KitScripts/automation/CrypStoreAutomation/crypstore_worker.py")
    if not worker.is_file():
        raise ValueError(f"Missing 0-Sky signing helper: {worker}")
    return worker


def preferred_link_ipa() -> pathlib.Path:
    """Select the current Link build with the research splash when available."""
    source = pathlib.Path(__file__).resolve().parents[2] / "link/dist/0-Sky-Link-1.9.0-source.ipa"
    return source if source.is_file() else pathlib.Path(__file__).resolve().parent / "0-Sky-Link-1.9.0-universal.ipa"


def installed_app_is_current(source: pathlib.Path, instance_name: str, udid: str) -> bool:
    """Require a real executable, matching build, and live process before skipping."""
    from repair_device_connection import profiles, worker_namespace

    with zipfile.ZipFile(source) as archive:
        names = [name for name in archive.namelist()
                 if name.startswith("Payload/") and name.endswith(".app/Info.plist")
                 and name.count("/") == 2]
        if len(names) != 1:
            raise ValueError(f"Expected one top-level app in {source}")
        info = plistlib.loads(archive.read(names[0]))
    bundle_id = info["CFBundleIdentifier"]
    executable = info["CFBundleExecutable"]
    build = str(info["CFBundleVersion"])
    script = r'''import json,pathlib,plistlib,subprocess,sys
bundle_id,executable,build=sys.argv[1:]
prefix=bundle_id+' : '
listing=subprocess.run(['/var/jb/usr/bin/uicache','-l'],capture_output=True,text=True,timeout=15)
paths=[line[len(prefix):].strip() for line in listing.stdout.splitlines() if line.startswith(prefix)]
valid=False
if listing.returncode==0 and len(paths)==1:
 app=pathlib.Path(paths[0])
 try:
  info=plistlib.loads((app/'Info.plist').read_bytes())
  binary=app/executable
  processes=subprocess.check_output(['/bin/ps','-axo','command='],text=True,timeout=10).splitlines()
  valid=(info.get('CFBundleIdentifier')==bundle_id and
         info.get('CFBundleExecutable')==executable and
         str(info.get('CFBundleVersion'))==build and binary.is_file() and
         any(line.strip().split(None,1)[0].removeprefix('/private')==str(binary).removeprefix('/private')
             for line in processes if line.strip()))
 except (OSError,ValueError,subprocess.SubprocessError):pass
print(json.dumps({'current':bool(valid)}))'''
    import shlex
    namespace = worker_namespace(profiles(instance_name=instance_name)[udid][1])
    command = ("/var/jb/usr/bin/python3 -c " + shlex.quote(script) + " " +
               " ".join(shlex.quote(value) for value in (bundle_id, executable, build)))
    result = namespace["ssh"](command, timeout=40, check=False)
    return result.returncode == 0 and json.loads(result.stdout).get("current") is True


def sign_staged_app(app: pathlib.Path, work: pathlib.Path) -> None:
    """Reuse 0-Sky's signing helper on staged copies, preserving the input IPA."""
    worker = signing_worker_path()
    work.mkdir(parents=True, exist_ok=True)
    previous = os.environ.get("CRYPSTORE_INSTANCE_DIR")
    os.environ["CRYPSTORE_INSTANCE_DIR"] = str(work)
    try:
        namespace = runpy.run_path(str(worker), run_name="poc_staged_signing")
    finally:
        if previous is None:
            os.environ.pop("CRYPSTORE_INSTANCE_DIR", None)
        else:
            os.environ["CRYPSTORE_INSTANCE_DIR"] = previous
    namespace["sign_app"](app, work)


def build_cryptexes(control_ipa: pathlib.Path, link_ipa: pathlib.Path,
                   output_dir: pathlib.Path) -> dict:
    """Build both cryptexes."""
    results = {
        "control": {"success": False, "message": ""},
        "link": {"success": False, "message": ""}
    }
    
    output_dir = output_dir.expanduser().resolve()
    output_dir.mkdir(parents=True, exist_ok=True)
    run_dir = pathlib.Path(tempfile.mkdtemp(prefix="cryptex-build-0sky-", dir=output_dir))
    print(f"Build output: {run_dir}", flush=True)
    control_cryptex_dir = run_dir / "control"
    link_cryptex_dir = run_dir / "link"
    
    device_python = find_device_python()
    
    # Build Control cryptex
    with tempfile.TemporaryDirectory(prefix="0sky-build-control-") as temp_dir:
        staging = pathlib.Path(temp_dir)
        
        try:
            control_app = ipa_app(control_ipa, staging / "control")
            control_info = get_bundle_info(control_app)
            
            control_dstroot = staging / "control-dstroot"
            control_dstroot.mkdir()
            apps_dir = control_dstroot / "System" / "Applications"
            apps_dir.mkdir(parents=True)
            shutil.copytree(control_app, apps_dir / control_app.name, symlinks=True)
            sign_staged_app(apps_dir / control_app.name, staging / "signing")
            
            control_id = "org.example.research.native.commissary"
            control_cryptex_dir.mkdir(parents=True, exist_ok=True)
            
            bundle, assets = make_cryptex(
                control_id, "3.4.4", control_dstroot,
                control_cryptex_dir, cryptexctl_path()
            )
            
            control_assets = {
                "identifier": control_id,
                "version": "3.4.4",
                "bundle": str(bundle),
                "apps": [{
                    "source": str(control_ipa),
                    "app": control_app.name,
                    "bundle_id": control_info["bundle_id"],
                    "executable": control_info["executable"]
                }],
                "assets": assets["assets"]
            }
            (control_cryptex_dir / "assets.json").write_text(
                json.dumps(control_assets, indent=2) + "\n"
            )
            
            results["control"]["success"] = True
            results["control"]["message"] = f"Built Control cryptex: {control_id}"
            results["control"]["bundle_id"] = control_info["bundle_id"]
            results["control"]["bundle_path"] = str(bundle)
            
        except Exception as e:
            results["control"]["message"] = f"Control build failed: {e}"
    
    # Build Link cryptex
    with tempfile.TemporaryDirectory(prefix="0sky-build-link-") as temp_dir:
        staging = pathlib.Path(temp_dir)
        
        try:
            link_app = ipa_app(link_ipa, staging / "link")
            link_info = get_bundle_info(link_app)
            
            link_dstroot = staging / "link-dstroot"
            link_dstroot.mkdir()
            apps_dir = link_dstroot / "System" / "Applications"
            apps_dir.mkdir(parents=True)
            shutil.copytree(link_app, apps_dir / link_app.name, symlinks=True)
            sign_staged_app(apps_dir / link_app.name, staging / "signing")
            
            link_id = "org.example.research.native.zerosky"
            link_cryptex_dir.mkdir(parents=True, exist_ok=True)
            
            bundle, assets = make_cryptex(
                link_id, "1.9.0", link_dstroot,
                link_cryptex_dir, cryptexctl_path()
            )
            
            link_assets = {
                "identifier": link_id,
                "version": "1.9.0",
                "bundle": str(bundle),
                "apps": [{
                    "source": str(link_ipa),
                    "app": link_app.name,
                    "bundle_id": link_info["bundle_id"],
                    "executable": link_info["executable"]
                }],
                "assets": assets["assets"]
            }
            (link_cryptex_dir / "assets.json").write_text(
                json.dumps(link_assets, indent=2) + "\n"
            )
            
            results["link"]["success"] = True
            results["link"]["message"] = f"Built Link cryptex: {link_id}"
            results["link"]["bundle_id"] = link_info["bundle_id"]
            results["link"]["bundle_path"] = str(bundle)
            
        except Exception as e:
            results["link"]["message"] = f"Link build failed: {e}"
    
    return results


def install_cryptexes(control_bundle_path: str, link_bundle_path: str,
                      control_id: str, link_id: str,
                      udid: str, output_dir: pathlib.Path) -> dict:
    """Install both cryptexes on the device."""
    results = {
        "control": {"success": False, "message": ""},
        "link": {"success": False, "message": ""}
    }
    
    device_python = find_device_python()
    cryptexctl = cryptexctl_path()
    
    try:
        control_cryptex_dir = pathlib.Path(control_bundle_path).parent
        bundle_path = pathlib.Path(control_bundle_path)
        
        with open(control_cryptex_dir / "assets.json") as f:
            control_assets = json.load(f)
        
        result = install_built_cryptex(
            control_id, bundle_path, control_assets.get("assets", {}),
            udid, device_python, cryptexctl, output_dir
        )
        results["control"] = result
        
    except Exception as e:
        results["control"]["message"] = f"Control install error: {e}"
    
    try:
        link_cryptex_dir = pathlib.Path(link_bundle_path).parent
        bundle_path = pathlib.Path(link_bundle_path)
        
        with open(link_cryptex_dir / "assets.json") as f:
            link_assets = json.load(f)
        
        result = install_built_cryptex(
            link_id, bundle_path, link_assets.get("assets", {}),
            udid, device_python, cryptexctl, output_dir
        )
        results["link"] = result
        
    except Exception as e:
        results["link"]["message"] = f"Link install error: {e}"
    
    return results


def register_apps(control_id: str, link_id: str,
                  control_bundle_id: str, link_bundle_id: str,
                  udid: str) -> dict:
    """Register both apps on the device."""
    results = {
        "control": {"success": False, "message": ""},
        "link": {"success": False, "message": ""}
    }
    
    device_python = find_device_python()
    
    result = register_app(
        control_bundle_id, control_id, "CrypStore.app",
        udid, device_python
    )
    results["control"] = result
    
    result = register_app(
        link_bundle_id, link_id, "ZeroSky.app",
        udid, device_python
    )
    results["link"] = result
    
    return results


def verify_icons(control_bundle_id: str, link_bundle_id: str,
                 udid: str) -> dict:
    """Verify app icons in SpringBoard."""
    results = {
        "control": {"success": False, "message": ""},
        "link": {"success": False, "message": ""}
    }
    
    device_python = find_device_python()
    
    result = check_app_icon(control_bundle_id, udid, device_python)
    results["control"] = result
    
    result = check_app_icon(link_bundle_id, udid, device_python)
    results["link"] = result
    
    return results


def compatibility_stop(operation):
    import pathlib
    import sys
    for ancestor in pathlib.Path(__file__).resolve().parents:
        runtime = ancestor / "bridge" / "DeviceRuntime"
        if (runtime / "zero_sky_compat").is_dir():
            sys.path.insert(0, str(runtime))
            break
    from zero_sky_compat.integration import block_legacy_mutation
    block_legacy_mutation(operation)


def install_via_supported_backend(args, udid: str) -> int:
    """Use the maintained, paired-Mac IPA installer instead of the retired PoC path."""
    if args.ssh_only:
        raise ValueError("--ssh-only applies to the retired cryptex installer; omit it for the supported app installer")

    root = pathlib.Path(__file__).resolve().parents[2]
    poc_dir = pathlib.Path(__file__).resolve().parent
    registrar_backend = poc_dir / "setup_appregistrard.py"
    ipa_backend = poc_dir / "retry_install_file.py"
    native_backend = poc_dir / "finish_native_install.py"
    if not registrar_backend.is_file() or not ipa_backend.is_file() or not native_backend.is_file():
        raise ValueError("Supported 0-Sky registrar or IPA installer is missing")

    support = pathlib.Path.home() / "Library/Application Support/0-Sky"
    configs = sorted((support / "instances").glob("*/config.json"))
    candidates = []
    for path in configs:
        if args.instance_name and path.parent.name != args.instance_name:
            continue
        try:
            config = json.loads(path.read_text())
            if config.get("udid", "").upper() != udid.upper():
                continue
            hosts = pathlib.Path(config["ssh_known_hosts"]).expanduser()
            key = pathlib.Path(config["ssh_key"]).expanduser()
            if (not hosts.is_file() or hosts.is_symlink() or
                    hosts.stat().st_mode & 0o077 or not key.is_file() or
                    not config.get("ssh_host_alias")):
                continue
            candidates.append(path.parent.name)
        except (OSError, ValueError, KeyError, TypeError):
            continue
    if len(candidates) != 1:
        names = ", ".join(candidates) or "none"
        raise ValueError(
            f"Expected one complete paired profile for {udid}; found {names}. "
            "Pass --instance-name if more than one is ready, or repair pairing first."
        )
    instance_name = candidates[0]
    device_python = find_device_python(args.device_python)
    print(f"Using paired 0-Sky installer for {udid} (instance: {instance_name})", flush=True)
    try:
        subprocess.run(
            [device_python, str(registrar_backend), "--udid", udid,
             "--instance-name", instance_name, "--kit", str(args.srdsh_kit.parent / "appregistrard")],
            check=True, timeout=1020,
        )
        reports = args.output.resolve() / "installer-verification"
        reports.mkdir(parents=True, exist_ok=True)
        for name, source in (("control", args.control_ipa), ("link", args.link_ipa)):
            if not args.force and installed_app_is_current(source, instance_name, udid):
                print(f"{name} is already installed at the requested build and running", flush=True)
                continue
            report = reports / f"{name}-install-{int(time.time())}.json"
            print(f"Installing {name} from {source}", flush=True)
            staged = subprocess.run(
                [device_python, str(ipa_backend), "--udid", udid,
                 "--instance-name", instance_name, "--file", str(source.resolve()),
                 "--output", str(report)],
                check=False, timeout=2400,
            )
            if staged.returncode:
                print(f"Completing {name} with native registration and exact-code trust", flush=True)
                subprocess.run(
                    [device_python, str(native_backend), "--source-ipa", str(source.resolve()),
                     "--udid", udid, "--instance-name", instance_name,
                     "--output", str(reports / f"{name}-native-{int(time.time())}")],
                    check=True, timeout=2400,
                )
            if not installed_app_is_current(source, instance_name, udid):
                raise RuntimeError(f"{name} installer did not leave the requested build running")
    except (subprocess.CalledProcessError, subprocess.TimeoutExpired) as error:
        print(f"Supported app installer failed: {error}", file=sys.stderr)
        return 1

    if args.reboot_for_icons:
        subprocess.run([device_python, "-m", "pymobiledevice3", "diagnostics",
                        "restart", "--udid", udid, "--reconnect"],
                       check=True, timeout=300)
        print("Device restart requested; unlock it before checking the icons.")
    return 0


def main():
    parser = argparse.ArgumentParser(
        description="Install 0-Sky Control and 0-Sky Link as research cryptexes",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__
    )
    
    poc_dir = pathlib.Path(__file__).resolve().parent
    
    control_ipa_default = None
    control_locations = [
        poc_dir.parent / "Commissary-Universal-signed.ipa",
        pathlib.Path.home() / "Desktop" / "0-Sky" / "addons" / "Commissary-Universal-signed.ipa",
        pathlib.Path.home() / "Desktop" / "0-Sky" / "Commissary-Universal-signed.ipa",
    ]
    for ipa in control_locations:
        if ipa.exists():
            control_ipa_default = ipa
            break
    
    link_ipa_default = preferred_link_ipa()
    
    parser.add_argument("--control-ipa", type=pathlib.Path,
                       default=control_ipa_default,
                       help=f"Control IPA path (auto-detected)")
    parser.add_argument("--link-ipa", type=pathlib.Path,
                       default=link_ipa_default,
                       help=f"Link IPA path (default: {link_ipa_default})")
    parser.add_argument("--output", type=pathlib.Path,
                       default=poc_dir,
                       help=f"Parent for a fresh build directory on each run (default: {poc_dir})")
    parser.add_argument("--device-python", type=str,
                       help="Device Python interpreter path (overrides SRD_PYTHON)")
    parser.add_argument("--srdsh-kit", type=pathlib.Path, default=DEFAULT_SRDSH_KIT,
                        help="SSH bootstrap kit (default: bundled srdsh-work kit)")
    parser.add_argument("--ssh-only", action="store_true",
                        help="Set up SSH without installing bootstrap_1900.tar.zst")
    parser.add_argument("--udid", type=str,
                       default=None,
                       help="Device UDID (auto-detected if omitted, or use SRD_UDID env var)")
    parser.add_argument("--instance-name", type=str,
                        help="Exact paired 0-Sky instance when more than one matches the UDID")
    parser.add_argument("--doctor", action="store_true",
                       help="Run dependency checks only")
    parser.add_argument("--install", action="store_true",
                       help="Install cryptexes on device")
    parser.add_argument("--reboot-for-icons", action="store_true",
                       help="Reboot device after installation to refresh icons")
    parser.add_argument("--force", action="store_true",
                       help="Force installation even if app already registered")
    
    args = parser.parse_args()
    if args.device_python:
        os.environ["SRD_PYTHON"] = args.device_python
    
    try:
        if args.doctor:
            print("=== DEPENDENCY CHECK ===")
            results = check_dependencies(doctor=True, srdsh_kit=args.srdsh_kit,
                                         ssh_only=args.ssh_only)
            for check in results["checks"]:
                print(f"  [OK] {check}")
            for warning in results["warnings"]:
                print(f"  [WARNING] {warning}")
            if results["errors"]:
                print("\n=== ERRORS ===")
                for error in results["errors"]:
                    print(f"  [ERROR] {error}")
                return 1
            print("\nAll dependency checks passed!")
            return 0
        
        # Validate IPA files
        if not args.control_ipa or not args.control_ipa.exists():
            print(f"ERROR: Control IPA not found: {args.control_ipa}")
            print("Use --control-ipa to specify the Control IPA path.")
            return 1
        
        if not args.link_ipa or not args.link_ipa.exists():
            print(f"ERROR: Link IPA not found: {args.link_ipa}")
            print("Use --link-ipa to specify the Link IPA path.")
            return 1

        if args.install:
            udid = args.udid or os.environ.get("SRD_UDID")
            if not udid:
                raise ValueError("Pass --udid with the exact paired SRD UDID for installation")
            return install_via_supported_backend(args, udid)
        
        compatibility_stop("legacy-cryptex-build")
        # Get device UDID
        udid = get_device_udid(args.udid)
        
        # Build cryptexes
        print(f"=== BUILDING CRYPTEXES (UDID: {udid}) ===")
        build_results = build_cryptexes(
            args.control_ipa, args.link_ipa, args.output
        )
        
        for app, result in build_results.items():
            if result["success"]:
                print(f"[OK] {app}: {result['message']}")
            else:
                print(f"[ERROR] {app}: {result['message']}")
        
        if not build_results["control"]["success"] or not build_results["link"]["success"]:
            print("\nBuild failed. Aborting.")
            return 1
        
        if not args.install:
            print("\nBuild complete. Use --install to install on device.")
            return 0
        
    except ValueError as e:
        print(f"Configuration error: {e}")
        return 1
    except Exception as e:
        print(f"Unexpected error: {e}")
        return 1


if __name__ == "__main__":
    sys.exit(main())
