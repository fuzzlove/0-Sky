"""Apply reviewed remote-port support to host tools and installed workers."""
from pathlib import Path
import hashlib
import json
import py_compile
import time
from repair_device_connection import HERE, profiles, atomic_write

def edit(text, old, new):
    if text.count(old) != 1:
        raise RuntimeError('Unexpected source for '+old[:80])
    return text.replace(old,new)

def main():
    root=HERE.parents[1]
    pair=root/'bridge/HostTools/pair.py'
    source=pair.read_text()
    source=edit(source,'def exact_iproxy_present(udid: str, port: str) -> bool:',
        'def exact_iproxy_present(udid: str, port: str, remote_port: str = "22") -> bool:')
    source=edit(source,'if "iproxy" in line and f"{port}:22" in line:',
        'fields = shlex.split(line)\n        if ("iproxy" in line and f"{port}:{remote_port}" in fields\n                and any(fields[i:i+2] == ["-u", udid] for i in range(len(fields)))):')
    source=edit(source,'and f"forward {port} 22" in line):','and f"forward {port} {remote_port}" in line):')
    source=edit(source,'if ("ncat" in line and "coredevice_ssh_forward.sh" in line',
        'if (remote_port == "22" and "ncat" in line and "coredevice_ssh_forward.sh" in line')
    source=edit(source,'def prepare_loopback_tunnel(host: str, port: str, udid: str) -> subprocess.Popen | None:',
        'def prepare_loopback_tunnel(host: str, port: str, udid: str,\n                            remote_port: str = "22") -> subprocess.Popen | None:')
    source=edit(source,'if not exact_iproxy_present(udid, port):','if not exact_iproxy_present(udid, port, remote_port):')
    source=edit(source,'f"{port}:22"],','f"{port}:{remote_port}"],')
    source=edit(source,'repair_device_host_key: bool = False) -> dict:',
        'repair_device_host_key: bool = False,\n                               remote_port: str = "22") -> dict:')
    source=edit(source,'temporary_iproxy = prepare_loopback_tunnel(host, port, udid)',
        'temporary_iproxy = prepare_loopback_tunnel(host, port, udid, remote_port)')
    source=edit(source,'"ssh_port": str(port), "paired_at": int(time.time()),',
        '"ssh_port": str(port), "ssh_remote_port": str(remote_port), "paired_at": int(time.time()),')
    changes={pair:source}
    workers=[root/'bridge/KitScripts/automation/CrypStoreAutomation/crypstore_worker.py']
    workers += [next(Path(a) for a in v['ProgramArguments'] if a.endswith('/crypstore_worker.py')) for _,v in profiles().values()]
    for path in set(workers):
        text=path.read_text()
        text=edit(text,'DEVICE_PORT = os.environ.get("CRYPSTORE_DEVICE_PORT")',
            'DEVICE_PORT = os.environ.get("CRYPSTORE_DEVICE_PORT")\nDEVICE_REMOTE_PORT = os.environ.get("CRYPSTORE_DEVICE_REMOTE_PORT", "22")')
        text=edit(text,'ssh_base_for(bonjour, "22", "bonjour")','ssh_base_for(bonjour, DEVICE_REMOTE_PORT, "bonjour")')
        text=edit(text,'ssh_base_for(f"{DEVICE_UDID}.coredevice.local", "22", "wireless")',
            'ssh_base_for(f"{DEVICE_UDID}.coredevice.local", DEVICE_REMOTE_PORT, "wireless")')
        text=edit(text,'provision_wireless=True)','provision_wireless=True, remote_port=DEVICE_REMOTE_PORT)')
        changes[path]=text
    setup=root/'bridge/macos_host_setup.py'
    text=setup.read_text()
    text=edit(text,'f"{port}:22" in arguments',
        'f"{port}:{environment.get(\"CRYPSTORE_DEVICE_REMOTE_PORT\", \"22\")}" in arguments')
    changes[setup]=text
    backup=HERE/'connection-repair'/('source-before-'+str(time.time_ns()))
    backup.mkdir(mode=0o700)
    records=[]
    for path,text in changes.items():
        compile(text,str(path),'exec')
        data=path.read_bytes()
        saved=backup/(hashlib.sha256(str(path).encode()).hexdigest()[:16]+'.py')
        atomic_write(saved,data)
        records.append({'path':str(path),'backup':str(saved)})
    atomic_write(backup/'index.json',json.dumps(records,indent=2).encode())
    for path,text in changes.items():
        atomic_write(path,text.encode(),path.stat().st_mode & 0o777)
    print(json.dumps({'updated':len(changes),'backup':str(backup)}))

if __name__=='__main__':main()
