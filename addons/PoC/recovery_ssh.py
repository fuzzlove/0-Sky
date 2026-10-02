"""Strict SSH through a temporary exact-UDID tunnel to the recovery service."""
import argparse
import asyncio
from contextlib import contextmanager
import json
from pathlib import Path
import shutil
import socket
import subprocess
import sys
import time

from device_python import ensure_device_python
from repair_device_connection import HOST_TOOLS,profiles,usb_identity,atomic_write


@contextmanager
def channel(udid, instance_name=None, remote_port=22024):
    asyncio.run(usb_identity(udid))
    sys.path.insert(0,str(HOST_TOOLS))
    import pair
    _,value=profiles(instance_name=instance_name)[udid]
    env=value["EnvironmentVariables"]
    with socket.socket() as reservation:
        reservation.bind(("127.0.0.1",0));port=reservation.getsockname()[1]
    proxy=subprocess.Popen([shutil.which("iproxy"),"-s","127.0.0.1","-u",udid,
                            f"{port}:{int(remote_port)}"],
                           stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
    try:
        deadline=time.monotonic()+5
        while not pair.tcp_open("127.0.0.1",str(port)):
            if proxy.poll() is not None or time.monotonic()>=deadline:
                raise RuntimeError("Recovery tunnel did not bind")
            time.sleep(.1)
        base=pair.ssh_base("127.0.0.1",str(port),Path(env["CRYPSTORE_DEVICE_KEY"]),
            known_hosts=Path(env["CRYPSTORE_DEVICE_KNOWN_HOSTS"]),host_alias=env["CRYPSTORE_DEVICE_HOST_ALIAS"])
        def ssh(command, *, timeout=45, check=True, data=None):
            return pair.run(base+[command], input_data=data, timeout=timeout, check=check)
        yield ssh
    finally:
        proxy.terminate()
        try: proxy.wait(timeout=5)
        except subprocess.TimeoutExpired: proxy.kill();proxy.wait()


def repair_host_key(udid, instance_name, remote_port=22024):
    """Re-pin only the recovered exact-USB service, then prove root or roll back."""
    asyncio.run(usb_identity(udid))
    sys.path.insert(0,str(HOST_TOOLS))
    import pair
    _,value=profiles(instance_name=instance_name)[udid]
    env=value["EnvironmentVariables"]
    pin=Path(env["CRYPSTORE_DEVICE_KNOWN_HOSTS"])
    if (not pin.is_file() or pin.is_symlink() or pin.stat().st_mode & 0o077 or
            pin != Path(env["CRYPSTORE_INSTANCE_DIR"])/"device-known-hosts"):
        raise RuntimeError("Existing profile pin is unavailable or unsafe")
    before=pin.read_bytes()
    with socket.socket() as reservation:
        reservation.bind(("127.0.0.1",0));port=reservation.getsockname()[1]
    proxy=subprocess.Popen([shutil.which("iproxy"),"-s","127.0.0.1","-u",udid,
                            f"{port}:{int(remote_port)}"],
                           stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
    replaced=False
    try:
        deadline=time.monotonic()+5
        while not pair.tcp_open("127.0.0.1",str(port)):
            if proxy.poll() is not None or time.monotonic()>=deadline:
                raise RuntimeError("Recovery tunnel did not bind")
            time.sleep(.1)
        if not pair.exact_iproxy_present(udid,str(port),str(int(remote_port))):
            raise RuntimeError("Recovery tunnel is not bound to the exact USB device")
        fingerprints=pair.ensure_device_host_key_pin(
            host="127.0.0.1",port=str(port),udid=udid,known_hosts=pin,
            allow_create=False,allow_replace=True)
        replaced=pin.read_bytes()!=before
        base=pair.ssh_base("127.0.0.1",str(port),Path(env["CRYPSTORE_DEVICE_KEY"]),
            known_hosts=pin,host_alias=env["CRYPSTORE_DEVICE_HOST_ALIAS"])
        if pair.ssh(base,"id -u").stdout.strip()!=b"0":
            raise RuntimeError("Recovered SSH service did not prove root")
        return {"udid":udid,"instance":instance_name,"fingerprints":fingerprints,
                "root_verified":True,"pin_changed":replaced}
    except Exception:
        if replaced:
            atomic_write(pin,before)
        raise
    finally:
        proxy.terminate()
        try: proxy.wait(timeout=5)
        except subprocess.TimeoutExpired: proxy.kill();proxy.wait()


if __name__=="__main__":
    ensure_device_python()
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--udid",required=True)
    parser.add_argument("--instance-name")
    parser.add_argument("--remote-port", type=int, default=22024)
    parser.add_argument("--repair-host-key",action="store_true",
                        help="explicitly re-pin the recovered exact-USB SSH service")
    args=parser.parse_args()
    if args.repair_host_key:
        if not args.instance_name: parser.error("--repair-host-key requires --instance-name")
        print(json.dumps(repair_host_key(args.udid,args.instance_name,args.remote_port),indent=2))
        raise SystemExit(0)
    with channel(args.udid,args.instance_name,args.remote_port) as ssh:
        uid=ssh("id -u").stdout.strip()
        if uid!=b"0": raise RuntimeError("Recovery SSH is not root")
        from verify_device_core import check
        print(json.dumps({"udid":args.udid,"recovery_ssh_root":True,"core":check({"ssh":ssh})},indent=2))
