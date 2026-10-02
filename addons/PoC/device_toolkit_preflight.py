#!/usr/bin/env python3
"""Read-only, exact-profile SRD toolkit evidence probe."""
import asyncio
import json
from pathlib import Path
import sys

from repair_device_connection import profiles, usb_identity, worker_namespace


REMOTE = r'''
import hashlib, json, os, platform, plistlib, socket, subprocess
from pathlib import Path

def run(argv, timeout=20):
    try:
        result = subprocess.run(argv, stdin=subprocess.DEVNULL,
                                stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                text=True, timeout=timeout, check=False)
        return result.returncode, result.stdout, result.stderr
    except (OSError, subprocess.TimeoutExpired) as error:
        return None, "", type(error).__name__

system = plistlib.loads(Path('/System/Library/CoreServices/SystemVersion.plist').read_bytes())
code, apps_text, _ = run(['/var/jb/usr/bin/uicache', '-l'])
apps = {}
registered_paths = {}
for line in apps_text.splitlines():
    if ' : ' in line:
        bundle, path = line.split(' : ', 1)
        if bundle in ('codes.liquidsky.research.zerosky', 'com.liquidsky.CrypStore',
                      'com.tigisoftware.Filza', 'org.coolstar.SileoStore',
                      'xyz.willy.Zebra', 'com.opa334.trollstore'):
            app = Path(path)
            try:
                info = plistlib.loads((app / 'Info.plist').read_bytes())
                executable = info.get('CFBundleExecutable')
                validated = (info.get('CFBundleIdentifier') == bundle and
                             isinstance(executable, str) and '/' not in executable and
                             (app / executable).is_file())
                version = info.get('CFBundleShortVersionString')
            except (OSError, ValueError, TypeError):
                validated, version = False, None
            apps[bundle] = {'registered': True, 'bundle_present': app.is_dir(),
                            'identity_executable_valid': validated, 'version': version}
            registered_paths[bundle] = Path(path)
audit_code, audit, audit_error = run(['/var/jb/usr/bin/dpkg', '--audit'])
apt_check_code, apt_check_output, apt_check_error = run(['/var/jb/usr/bin/apt-get', 'check'], 30)
audit_lines = audit.splitlines()
audit_nonvirtual = [line.strip() for line in audit_lines
                    if line.startswith(' ') and not line.strip().startswith(('cy+', 'gsc.'))]
package_ids = ('com.catvnc.server', 'com.tigisoftware.filza', 'org.coolstar.sileo',
               'xyz.willy.zebra', 'com.opa334.choicy', 'ellekit', 'preferenceloader',
               'openssh-server', 'dpkg', 'apt')
package_code, packages, _ = run(['/var/jb/usr/bin/dpkg-query', '-W',
                                '-f=${Package}\\t${Version}\\t${db:Status-Abbrev}\\n', *package_ids])
package_records = []
for line in packages.splitlines():
    fields = line.split('\t', 2)
    if len(fields) == 3:
        package_records.append({'package': fields[0], 'version': fields[1],
                                'dpkg_status': fields[2].strip(),
                                'installed': fields[2].startswith('ii')})
frida_present = Path('/var/jb/usr/sbin/frida-server').is_file()
frida_hash = None
if frida_present:
    digest = hashlib.sha256()
    with Path('/var/jb/usr/sbin/frida-server').open('rb') as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b''):
            digest.update(chunk)
    frida_hash = digest.hexdigest()
try:
    with socket.create_connection(('127.0.0.1', 48654), timeout=2):
        bridge_listener = True
except OSError:
    bridge_listener = False
cli_specs = {
    'ssh': ('/var/jb/usr/bin/ssh', '-V'),
    'ldid': ('/var/jb/usr/bin/ldid', '-h'),
    'nm': ('/var/jb/usr/bin/nm', '--version'),
    'strings': ('/var/jb/usr/bin/strings', '--version'),
    'file': ('/var/jb/usr/bin/file', '--version'),
    'plutil': ('/usr/bin/plutil', '-help'),
    'sqlite3': ('/var/jb/usr/bin/sqlite3', '--version'),
    'tcpdump': ('/var/jb/usr/bin/tcpdump', '--version'),
    'curl': ('/var/jb/usr/bin/curl', '--version'),
    'git': ('/var/jb/usr/bin/git', '--version'),
    'dpkg': ('/var/jb/usr/bin/dpkg', '--version'),
    'apt': ('/var/jb/usr/bin/apt-get', '--version'),
}
cli = {}
for name, (path, argument) in cli_specs.items():
    if not Path(path).is_file():
        cli[name] = {'status': 'ABSENT'}
        continue
    status, output, error = run([path, argument], 5)
    cli[name] = {'status': 'PASS' if status == 0 else 'FAIL',
                 'exit': status, 'version_line': (output or error).splitlines()[:1]}
control_path = registered_paths.get('com.liquidsky.CrypStore')
if cli['ldid']['status'] != 'ABSENT' and control_path:
    try:
        info = plistlib.loads((control_path / 'Info.plist').read_bytes())
        binary = control_path / info['CFBundleExecutable']
        if binary.is_file():
            status, entitlements, _ = run(['/var/jb/usr/bin/ldid', '-e', str(binary)], 10)
            cli['ldid'] = {'status': 'PASS' if status == 0 and bool(entitlements.strip()) else 'FAIL',
                           'exit': status, 'probe': 'Control entitlements read'}
    except (OSError, ValueError, KeyError):
        cli['ldid'] = {'status': 'FAIL', 'probe': 'Control executable unavailable'}
ps_code, processes, _ = run(['/bin/ps', '-axo', 'command'])
services = {name: bool(ps_code == 0 and any(any(name in token for token in line.split())
             for line in processes.splitlines() if line.split()))
            for name in ('dropbear', 'frida-server', 'trollstorelite-srd-bridge.py')}
arm64e_code, arm64e_text = None, ''
for sysctl in ('/var/jb/usr/bin/sysctl', '/var/jb/usr/sbin/sysctl',
               '/usr/bin/sysctl', '/usr/sbin/sysctl'):
    if Path(sysctl).is_file():
        arm64e_code, arm64e_text, _ = run([sysctl, '-n', 'hw.optional.arm64e'])
        break
cpu_sysctl = {}
if arm64e_code is None:
    try:
        import ctypes
        call = ctypes.CDLL(None).sysctlbyname
        call.argtypes = (ctypes.c_char_p, ctypes.c_void_p,
                         ctypes.POINTER(ctypes.c_size_t), ctypes.c_void_p, ctypes.c_size_t)
        for key in ('hw.optional.arm64e', 'hw.cputype', 'hw.cpusubtype'):
            value = ctypes.c_int()
            size = ctypes.c_size_t(ctypes.sizeof(value))
            code = call(key.encode(), ctypes.byref(value), ctypes.byref(size), None, 0)
            cpu_sysctl[key] = value.value if code == 0 else None
        arm64e_code = 0 if cpu_sysctl['hw.optional.arm64e'] is not None else None
        arm64e_text = str(cpu_sysctl['hw.optional.arm64e'] or '')
    except (AttributeError, OSError, ImportError):
        pass
heartbeat = Path('/var/jb/var/run/crypstore-worker.json')
try:
    value = json.loads(heartbeat.read_text())
    raw_tools = value.get('host_tools', {})
    allowed_tools = ('frida_cli', 'objection', 'lldb', 'mitmproxy', 'wireshark',
                     'libimobiledevice', 'ghidra', 'burp_suite', 'hopper', 'ida')
    tools = {name: {'detected': item.get('detected') is True,
                    'probe': str(item.get('probe', 'UNTESTED'))[:24],
                    'version': str(item.get('version'))[:40] if item.get('version') else None}
             for name in allowed_tools
             if isinstance(item := raw_tools.get(name), dict)}
    host = {'age_seconds': max(0, __import__('time').time() - value['timestamp']),
            'pairing_verified': value.get('apple_pairing_verified') is True,
            'identity_verified': value.get('host_identity_verified') is True,
            'tool_ids': sorted(raw_tools), 'tools': tools}
except (OSError, ValueError, KeyError, TypeError):
    host = {'available': False}
print(json.dumps({'os': system.get('ProductVersion'), 'build': system.get('ProductBuildVersion'),
                  'architecture': platform.machine(), 'bootstrap': Path('/var/jb').is_dir(),
                  'arm64e_available': arm64e_text.strip() == '1' if arm64e_code == 0 else None,
                  'cpu_sysctl': cpu_sysctl,
                  'registered_apps': apps, 'app_inventory_exit': code,
                  'dpkg_audit_exit': audit_code, 'dpkg_audit_lines': len(audit_lines),
                  'dpkg_audit_text': audit[:65536],
                  'dpkg_audit_sample': audit_lines[:5],
                  'dpkg_audit_nonvirtual_count': len(audit_nonvirtual),
                  'dpkg_audit_nonvirtual_sample': audit_nonvirtual[:8],
                  'dpkg_audit_error': audit_error[:80],
                  'apt_check_exit': apt_check_code,
                  'apt_check_error': apt_check_error[:80],
                  'package_query_exit': package_code, 'packages': package_records,
                  'frida_server_file_present': frida_present,
                  'frida_server_sha256': frida_hash,
                  'bridge_listener': bridge_listener,
                  'cli': cli, 'services': services,
                  'host': host}, sort_keys=True))
'''


def main() -> int:
    if len(sys.argv) != 3:
        raise SystemExit('usage: device_toolkit_preflight.py INSTANCE_NAME EXACT_UDID')
    instance, udid = sys.argv[1:]
    selected = profiles(instance_name=instance)
    if udid not in selected:
        raise SystemExit('exact device profile unavailable')
    usb = asyncio.run(usb_identity(udid))
    worker = worker_namespace(selected[udid][1])
    result = worker['ssh']('/var/jb/usr/bin/python3 -',
                           input_data=REMOTE.encode('utf-8'), timeout=60, check=False)
    if result.returncode:
        print(json.dumps({'ssh_exit': result.returncode,
                          'error': result.stderr.decode('utf-8', 'replace')[:180]}))
        return 2
    observed = json.loads(result.stdout.decode('utf-8', 'replace'))
    if not isinstance(observed, dict):
        raise RuntimeError('device probe did not return an evidence object')
    observed['usb_identity_suffix'] = udid[-8:]
    observed['usb_identity_verified'] = usb['udid'] == udid
    observed['usb_product'] = usb.get('product')
    output = Path(__file__).resolve().parent / 'installer-verification' / (
        'toolkit-preflight-' + udid[-8:].lower() + '.json')
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(json.dumps(observed, sort_keys=True, indent=2) + '\n', encoding='utf-8')
    print(json.dumps({'device': udid[-8:], 'evidence': str(output),
                      'os': observed.get('os'), 'model': observed.get('architecture'),
                      'audit_lines': observed.get('dpkg_audit_lines'),
                      'cli': {key: value.get('status') for key, value in observed.get('cli', {}).items()}},
                     sort_keys=True))
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
