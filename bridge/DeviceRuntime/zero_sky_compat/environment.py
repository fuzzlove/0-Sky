"""Read-only device capability probes. A tool's presence is not its capability."""
import ctypes
import hashlib
import json
import os
from pathlib import Path
import platform
import plistlib
import shutil
import subprocess
from .model import Environment


TRUSTED_LAUNCHCTL_SHA256 = "a2d095b681cd4bf1ac819a7052b5b376516ed663bd989edc60d25297fa1e9bbc"


def _sha256(path):
    digest = hashlib.sha256()
    with path.open('rb') as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b''):
            digest.update(block)
    return digest.hexdigest()


def _sysctl_integer(name):
    """Read a kernel CPU property without depending on an optional sysctl CLI."""
    try:
        value = ctypes.c_int()
        length = ctypes.c_size_t(ctypes.sizeof(value))
        function = ctypes.CDLL(None).sysctlbyname
        function.argtypes = [ctypes.c_char_p, ctypes.c_void_p,
                             ctypes.POINTER(ctypes.c_size_t), ctypes.c_void_p,
                             ctypes.c_size_t]
        function.restype = ctypes.c_int
        if function(name.encode("ascii"), ctypes.byref(value),
                    ctypes.byref(length), None, 0) == 0 and length.value == ctypes.sizeof(value):
            return value.value
    except (AttributeError, OSError, ValueError):
        pass
    return None


def _architecture_from_mach(cpu_type, cpu_subtype):
    # Values are from the selected Apple SDK's mach/machine.h.
    if cpu_type != 0x0100000C or cpu_subtype is None:
        return "unknown"
    subtype = cpu_subtype & 0x00FFFFFF
    return "arm64e" if subtype == 2 else "arm64" if subtype in (0, 1) else "unknown"


def command(argv, timeout=10):
    try:
        result = subprocess.run(argv, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                stdin=subprocess.DEVNULL, timeout=timeout, check=False)
        return {'returncode': result.returncode,
                'stdout': result.stdout.decode('utf-8', 'replace')[:65536],
                'stderr': result.stderr.decode('utf-8', 'replace')[:4000]}
    except (OSError, subprocess.TimeoutExpired) as error:
        return {'returncode': None, 'stdout': '', 'stderr': type(error).__name__}


def detect(prefix='/var/jb'):
    version = Path('/System/Library/CoreServices/SystemVersion.plist')
    values = plistlib.loads(version.read_bytes()) if version.is_file() else {}
    if 'iPhone OS' not in str(values.get('ProductName', '')) and not Path('/System/Library/PrivateFrameworks/MobileInstallation.framework').exists():
        raise ValueError('environment detection must run on the target iOS device')
    cpu_type = _sysctl_integer('hw.cputype')
    cpu_subtype = _sysctl_integer('hw.cpusubtype')
    env = Environment(ios_version=values.get('ProductVersion', 'unknown'),
                      build_version=values.get('ProductBuildVersion', 'unknown'),
                      device_model=platform.machine(),
                      architecture=_architecture_from_mach(cpu_type, cpu_subtype), bootstrap_prefix=prefix,
                      uid=os.geteuid(), gid=os.getegid())
    env.evidence['cpu_mach'] = {'type': cpu_type, 'subtype': cpu_subtype}
    caps = env.capabilities
    caps.update(var_jb=Path(prefix).is_dir(), root=os.geteuid() == 0,
                ssh=shutil.which('sshd') is not None or Path(prefix + '/usr/sbin/dropbear').exists(),
                developer_mode=None, srd=None, remote_xpc=None,
                sandbox_policy=None, granted_entitlements=None,
                application_registration=None, xpc_communication=None,
                restart_validation=None, dyld_shared_cache_inventory=None)
    env.bootstrap_type = 'rootless' if caps['var_jb'] else 'unknown'
    for name, argv in {
        'dpkg': [prefix + '/usr/bin/dpkg', '--version'],
        'dpkg_state': [prefix + '/usr/bin/dpkg', '--audit'],
        'procursus': [prefix + '/usr/bin/apt-get', 'check'],
        'launchctl': [prefix + '/usr/bin/launchctl', 'help'],
        'system_launchctl': ['/bin/launchctl', 'help'],
    }.items():
        result = command(argv)
        caps[name] = result['returncode'] == 0
        if name == 'dpkg_state':
            caps[name] = caps[name] and not result['stdout'].strip()
        env.evidence[name] = result
    env.evidence['launchd'] = command(['/bin/launchctl', 'print', 'system'])
    caps['launchd'] = env.evidence['launchd']['returncode'] == 0
    caps['mobile_installation'] = Path('/System/Library/PrivateFrameworks/MobileInstallation.framework').exists()
    mounts = Path('/private/var/run/com.apple.security.cryptexd/mnt')
    launch_helpers = []
    for pattern in ('com.emp0ry.localfence.srd-repair2.*/usr/bin/launchctl-srd',
                    'com.liquidsky.launch-helper.recovery-*/usr/bin/launchctl-srd'):
        for path in mounts.glob(pattern):
            try:
                if (path.is_file() and not path.is_symlink() and
                        _sha256(path) == TRUSTED_LAUNCHCTL_SHA256):
                    launch_helpers.append(path)
            except OSError:
                pass
    if len(set(launch_helpers)) == 1:
        helper = str(launch_helpers[0])
        result = command([helper, 'version'])
        caps['srd_launchctl'] = result['returncode'] == 0
        env.evidence['srd_launchctl'] = {
            'path': helper, 'sha256': TRUSTED_LAUNCHCTL_SHA256,
            'probe': result,
        }
    else:
        caps['srd_launchctl'] = False
        env.evidence['srd_launchctl'] = {'candidate_count': len(set(launch_helpers))}
    for name, pattern in [('appregistrard', 'codes.rambo.research.appregistrard.*/usr/bin/appregistrard'),
                          ('srdinstalld', '*/usr/bin/srdinstalld')]:
        caps[name] = any(path.is_file() and os.access(path, os.X_OK) for path in mounts.glob(pattern))
    packages = command([prefix + '/usr/bin/dpkg-query', '-W', '-f=${Package}\t${Version}\t${Status}\n'])
    for row in packages['stdout'].splitlines():
        fields = row.split('\t')
        if len(fields) == 3:
            env.packages[fields[0]] = {'version': fields[1], 'installed': fields[2] == 'install ok installed'}
    caps.update({
        'profile_schema': 2,
        'filesystem_model': 'rootless' if caps['var_jb'] else 'unknown',
        'filesystem_visibility': {
            'bootstrap': Path(prefix).is_dir(),
            'mobile': Path('/var/mobile').is_dir(),
            'cryptex_mounts': Path('/private/var/run/com.apple.security.cryptexd/mnt').is_dir(),
        },
        'writable_locations': [path for path in (prefix + '/var/tmp', '/var/mobile/Library')
                               if os.access(path, os.W_OK)],
        'process_execution': True,
        'uid_gid_behavior': {'effective_uid': os.geteuid(), 'effective_gid': os.getegid()},
        'code_signing_state': 'MEASURE_PER_BINARY',
        'entitlement_behavior': 'MEASURE_PER_BINARY',
        'available_package_managers': sorted(name for name in ('apt', 'dpkg', 'sileo', 'zebra')
            if name in env.packages or Path(prefix + '/usr/bin/' + name).exists()),
        'hooking_backend': ('ellekit' if any(name.lower() == 'ellekit' for name in env.packages)
                            else 'unknown'),
        'service_backend': ('srd-launchctl-cryptex' if caps.get('srd_launchctl') else
                            'system-launchctl' if caps.get('system_launchctl') else
                            'bootstrap-launchctl' if caps.get('launchctl') else 'unknown'),
    })
    # A separate file capture is used for complete large package inventories.
    env.evidence['package_inventory_truncated'] = len(packages['stdout']) >= 65536
    env.libraries = sorted(str(path) for folder in (prefix + '/usr/lib', '/usr/lib')
                           for path in Path(folder).glob('*.dylib'))
    env.frameworks = sorted(str(path) for folder in (
        '/System/Library/Frameworks', '/System/Library/PrivateFrameworks', prefix + '/Library/Frameworks')
        for path in Path(folder).glob('*.framework'))
    env.evidence['scope'] = 'filesystem and read-only capability probes; untested services remain unknown'
    return env


def load(path):
    value = json.loads(Path(path).read_text())
    allowed = Environment.__dataclass_fields__
    if set(value) - set(allowed):
        raise ValueError('unrecognized environment fields')
    return Environment(**value)
