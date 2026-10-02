#!/usr/bin/env python3
"""Install and activate the managed one-shot 0-Sky startup job on selected SRDs."""
import argparse
import importlib.util
import json
from pathlib import Path
import tempfile

from repair_device_connection import HERE, profiles, worker_namespace
from update_device_bridge import update as update_bridge

ROOT = HERE.parents[1]
SETUP = ROOT / "bridge/0SkyBridge/Resources/Scripts/0sky_project_setup.py"
SOURCE = ROOT / "bridge/DeviceRuntime"


def setup_module(kit):
    spec = importlib.util.spec_from_file_location("zero_sky_project_setup_splash", SETUP)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    module.KIT = kit
    return module


def deploy(udid):
    _, profile = profiles()[udid]
    env = profile["EnvironmentVariables"]
    instance = Path(env["CRYPSTORE_INSTANCE_DIR"]).name
    target = {"udid": udid, "instance": instance,
              "port": int(env["CRYPSTORE_DEVICE_PORT"])}
    identity = Path(env["CRYPSTORE_DEVICE_KEY"])
    with tempfile.TemporaryDirectory(prefix="0sky-splash-", dir="/private/tmp") as directory:
        kit = Path(directory) / "kit"
        stage = kit / "automation/CrypStoreAutomation"
        stage.mkdir(parents=True)
        (stage / "bootsplash-launch.py").write_bytes(
            (SOURCE / "bootsplash_launch.py").read_bytes())
        module = setup_module(kit)
        module.ensure_bootsplash_launcher(target, identity, Path(directory))
    namespace = worker_namespace(profile)
    result = update_bridge(namespace)
    return {"udid": udid, "startup": "persistent bridge", "bridge": result}


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--udid", required=True)
    args = parser.parse_args()
    print(json.dumps(deploy(args.udid), indent=2))
