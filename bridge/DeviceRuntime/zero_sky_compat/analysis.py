"""Root, service, binary, entitlement and dependency analysis share one report."""
import os
from pathlib import Path, PurePosixPath
import plistlib
import re
import shutil
import subprocess
from .discovery import discover
from .environment import command
from . import macho

ROOTS = ('Library', 'usr', 'etc', 'Applications', 'bin', 'sbin')
PRIVILEGED = ('com.apple.private.', 'platform-application', 'task_for_pid-allow',
              'com.apple.security.exception.', 'get-task-allow')
ASSUMPTION_PATH = re.compile(
    r'(?<![A-Za-z0-9_])/(?:Library|Applications|usr|bin|sbin|etc|var|private/var|Users)'
    r'(?:/[A-Za-z0-9._+@%${}-]+)*')
HOOK_MARKERS = ('MobileSubstrate', 'CydiaSubstrate', 'Substitute', 'ElleKit',
                'libhooker', 'fishhook')
PACKAGE_MANAGERS = ('launchctl', 'uicache', 'dpkg', 'apt', 'Sileo', 'Zebra')


def record_assumptions(path, root, report):
    try:
        data = path.read_bytes()[:1024 * 1024]
    except OSError:
        return
    text = data.decode('utf-8', 'replace')
    relative = path.relative_to(root).as_posix()
    values = set()
    for match in ASSUMPTION_PATH.findall(text):
        if match.startswith('/Users/'):
            match = '/Users/<redacted>'
        values.add(('filesystem', match))
    for marker in HOOK_MARKERS:
        if marker in text:
            values.add(('hooking_framework', marker))
    for marker in PACKAGE_MANAGERS:
        if re.search(r'(?<![A-Za-z0-9_])' + re.escape(marker) + r'(?![A-Za-z0-9_])', text,
                     re.IGNORECASE):
            values.add(('mechanism', marker.lower()))
    for kind, value in sorted(values)[:128]:
        report.assumptions.append({'kind': kind, 'value': value, 'source': relative})
    if any(kind == 'mechanism' and value == 'uicache' for kind, value in values):
        report.add('OBSOLETE_REGISTRATION_COMMAND', relative,
                   'uicache reference requires registration-backend analysis', 'unknown')


def metadata(root):
    control = root / 'DEBIAN/control'
    if control.exists():
        values = {}
        current = None
        for line in control.read_text().splitlines():
            if line.startswith((' ', '\t')) and current:
                values[current] += ' ' + line.strip()
            elif ':' in line:
                current, value = line.split(':', 1)
                if current in values:
                    raise ValueError('duplicate package metadata')
                values[current] = value.strip()
            elif line.strip():
                raise ValueError('malformed package metadata')
        for key in ('Package', 'Version', 'Architecture'):
            if not values.get(key):
                raise ValueError('missing package metadata: ' + key)
        if not re.fullmatch(r'[a-z0-9][a-z0-9+.-]+', values['Package']):
            raise ValueError('invalid package identifier')
        if not re.fullmatch(r'[0-9][A-Za-z0-9.+:~_-]*', values['Version']):
            raise ValueError('invalid package version')
        return values['Package'], values['Version'], values
    apps = sorted(root.glob('**/*.app/Info.plist'))
    if apps:
        info = plistlib.loads(apps[0].read_bytes())
        identity = info.get('CFBundleIdentifier', '')
        executable = info.get('CFBundleExecutable', '')
        if not re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9._-]*', identity) or not executable or '/' in executable:
            raise ValueError('invalid application metadata')
        if not (apps[0].parent / executable).is_file():
            raise ValueError('application executable not found')
        return identity, str(info.get('CFBundleVersion', 'unknown')), info
    return root.parent.name, 'unknown', {}


def compare_version(actual, operator, requested, dpkg):
    if not operator:
        return True
    if not dpkg:
        return None
    return command([dpkg, '--compare-versions', actual, operator, requested])['returncode'] == 0


def package_dependencies(value, env, report, dpkg=None):
    for group in value.split(','):
        if not group.strip():
            continue
        alternatives = []
        for choice in group.split('|'):
            match = re.fullmatch(r'\s*([a-z0-9][a-z0-9+.-]+)(?::[a-z0-9-]+)?\s*(?:\((<<|<=|=|>=|>>)\s*([^()]+)\))?\s*', choice)
            if not match:
                report.add('INVALID_PACKAGE_METADATA', 'DEBIAN/control', 'unsupported dependency expression')
                continue
            name, operator, version = match.groups()
            installed = env.packages.get(name)
            state = 'MISSING'
            if installed and installed.get('installed'):
                valid = compare_version(installed['version'], operator, version, dpkg)
                state = 'PRESENT' if valid is True else ('UNKNOWN' if valid is None else 'VERSION_INCOMPATIBLE')
            alternatives.append({'name': name, 'version': version, 'operator': operator, 'state': state})
        state = 'PRESENT' if any(x['state'] == 'PRESENT' for x in alternatives) else (
            'UNKNOWN' if any(x['state'] == 'UNKNOWN' for x in alternatives) else 'MISSING')
        report.dependencies.append({'kind': 'package', 'alternatives': alternatives, 'state': state, 'mandatory': True})
        if state != 'PRESENT':
            report.add('DEPENDENCY_MISSING' if state == 'MISSING' else 'DEPENDENCY_UNKNOWN', 'DEBIAN/control', group.strip(),
                       'mandatory' if state == 'MISSING' else 'unknown')


def resolve_library(name, binary, rpaths, root, env):
    def expand(path):
        path = path.replace('@loader_path', str(binary.parent))
        apps = [p for p in binary.parents if p.suffix in ('.app', '.xpc', '.appex')]
        if '@executable_path' in path:
            if not apps:
                return None
            path = path.replace('@executable_path', str(apps[0]))
        if path.startswith('@'):
            return None
        return path
    candidates = []
    if name.startswith('@rpath/'):
        candidates = [expand(value + name[len('@rpath'):]) for value in rpaths]
    elif name.startswith('@'):
        candidates = [expand(name)]
    else:
        candidates = [name]
    unknown = False
    for value in candidates:
        if value is None:
            continue
        path = Path(value)
        if path.is_absolute() and str(path).startswith(str(root) + '/'):
            if path.resolve().is_relative_to(root.resolve()) and path.is_file():
                return 'PRESENT'
        elif path.is_absolute():
            staged = root / str(path).lstrip('/')
            if staged.is_file() and staged.resolve().is_relative_to(root.resolve()):
                return 'PRESENT'
            if value in env.libraries:
                return 'PRESENT'
            # Framework directories alone cannot prove a particular binary/API;
            # many Apple libraries are only in the dyld shared cache.
            if value.startswith(('/System/Library/', '/usr/lib/')):
                unknown = True
    return 'UNKNOWN' if unknown else 'MISSING'


def service(path, root, env, report):
    relative = path.relative_to(root).as_posix()
    try:
        value = plistlib.loads(path.read_bytes())
        if not isinstance(value, dict) or not isinstance(value.get('Label'), str):
            raise ValueError('missing service label')
        args = value.get('ProgramArguments')
        program = value.get('Program') or (args[0] if isinstance(args, list) and args else None)
        if not isinstance(program, str) or not program.startswith('/'):
            raise ValueError('missing absolute executable path')
        target = root / program.lstrip('/')
        if not target.is_file() or target.is_symlink():
            report.add('EXECUTABLE_NOT_FOUND', relative, program)
        elif not target.stat().st_mode & 0o111:
            report.add('PERMISSION_FAILURE', relative, 'service executable is not executable')
        if path.stat().st_mode & 0o022:
            report.add('PERMISSION_FAILURE', relative, 'service plist is writable by group or others')
        launch = (env.capabilities.get('srd_launchctl') or
                  env.capabilities.get('system_launchctl') or
                  env.capabilities.get('launchctl'))
        if launch is False:
            report.add('LAUNCHCTL_ABI_INCOMPATIBLE', relative, 'no verified working launchctl')
        elif launch is None:
            report.add('LAUNCH_MECHANISM_UNKNOWN', relative, 'launchctl capability untested', 'unknown')
        report.dependencies.append({'kind': 'service', 'name': value['Label'],
                                    'state': 'UNKNOWN', 'mandatory': True,
                                    'mach_services': sorted(value.get('MachServices', {}))})
    except (ValueError, TypeError, plistlib.InvalidFileException) as error:
        report.add('SERVICE_PLIST_INVALID', relative, str(error))


def inspect(root, env, report, dpkg=None):
    report.components = discover(root)
    try:
        _, _, meta = metadata(root)
    except (ValueError, OSError, plistlib.InvalidFileException) as error:
        report.add('INVALID_PACKAGE_METADATA', 'metadata', str(error))
        meta = {}
    if env.ios_version == 'unknown' or not env.ios_version.startswith('27.'):
        report.add('TARGET_ENVIRONMENT_UNKNOWN', '', 'verified iOS 27 environment required', 'unknown')
    if (root / 'DEBIAN/control').exists():
        report.components.append({'kind': 'package', 'path': 'DEBIAN/control'})
    arch = meta.get('Architecture')
    expected = 'iphoneos-arm64' if env.architecture in ('arm64', 'arm64e') else env.architecture
    accepted_package_arches = {'all', expected}
    if env.architecture in ('arm64', 'arm64e'):
        # iphoneos-arm is historical Debian metadata used by fat packages. It
        # is not proof of an incompatible CPU. Mach-O slices below remain the
        # authoritative executable architecture check.
        accepted_package_arches.add('iphoneos-arm')
    if arch and arch not in accepted_package_arches:
        report.add('ARCHITECTURE_MISMATCH', 'DEBIAN/control', 'package architecture does not match target')
    for field in ('Pre-Depends', 'Depends'):
        package_dependencies(meta.get(field, ''), env, report, dpkg)
    rootful = any((root / name).exists() for name in ROOTS)
    rootless = (root / env.bootstrap_prefix.lstrip('/')).exists()
    if rootful:
        report.add('BOOTSTRAP_PATH_FAILURE', '', 'legacy rootful payload needs relocation')
        report.root_reasons.append('legacy path assumption')
    if rootless and env.capabilities.get('var_jb') is not True:
        report.add('BOOTSTRAP_PATH_FAILURE', '', 'rootless bootstrap unavailable')
    for item in report.components:
        kind, relative = item['kind'], item['path']
        path = root / relative
        if path.is_file() and kind in ('macho', 'executable', 'maintainer_script'):
            record_assumptions(path, root, report)
        if kind == 'service':
            report.root_reasons.append('daemon installation')
            service(path, root, env, report)
        elif kind == 'maintainer_script':
            report.add('MAINTAINER_SCRIPT_REVIEW_REQUIRED', relative,
                       'package scripts require a trusted transactional adapter', 'unknown')
            report.root_reasons.append('privileged file access')
            text = path.read_text(errors='replace')[:65536]
            if re.search(r'\b(?:kmem|kernel_task|task_for_pid|sandbox-exec)\b', text):
                report.root_reasons.append('kernel or sandbox capability assumption')
                report.add('UNSUPPORTED_SECURITY_ASSUMPTION', relative, 'kernel/sandbox requirements need explicit supported capabilities')
        elif kind == 'macho':
            try:
                slices = macho.parse(path)
                item['binary'] = slices
                matching = [x for x in slices if x['architecture'] == env.architecture or (
                    env.architecture == 'arm64e' and x['architecture'] == 'arm64')]
                if not matching:
                    if env.architecture == 'arm64' and any(x['architecture'] == 'arm64e' for x in slices):
                        report.add('ARCHITECTURE_CAPABILITY_UNKNOWN', relative, 'arm64e ABI acceptance unverified', 'unknown')
                    else:
                        report.add('ARCHITECTURE_MISMATCH', relative, 'no target CPU slice')
                for binary in matching:
                    if binary['platform'] not in (None, 2):
                        report.add('UNSUPPORTED_PLATFORM', relative, 'binary is not built for iOS')
                    if env.ios_version != 'unknown' and binary['minimum_os'] and tuple(map(int, binary['minimum_os'].split('.'))) > tuple(
                        map(int, (env.ios_version + '.0.0').split('.')[:3])):
                        report.add('UNSUPPORTED_API', relative, 'minimum OS newer than target')
                    if not binary['signed']:
                        report.add('SIGNATURE_MISSING', relative, 'code signature absent')
                    for dependency in binary['dependencies']:
                        state = resolve_library(dependency['name'], path, binary['rpaths'], root, env)
                        mandatory = not dependency['optional']
                        report.dependencies.append({'kind': 'library', 'name': dependency['name'],
                                                    'consumer': relative, 'state': state, 'mandatory': mandatory})
                        if state != 'PRESENT':
                            # An @rpath candidate that expands into Apple's
                            # dyld shared-cache namespace is unverified by a
                            # filesystem scan; it is not evidence of a broken
                            # rpath. Reserve RPATH_INCORRECT for a concrete
                            # missing path so UNKNOWN never becomes a blocker.
                            if state == 'UNKNOWN':
                                code = 'DEPENDENCY_UNKNOWN'
                            else:
                                code = ('RPATH_INCORRECT'
                                        if dependency['name'].startswith('@rpath/')
                                        else 'DEPENDENCY_MISSING')
                            report.add(code, relative, dependency['name'],
                                       ('mandatory' if state == 'MISSING' else 'unknown') if mandatory else 'optional')
                signer = shutil.which('codesign')
                if signer:
                    verification = command([signer, '--verify', '--strict', str(path)])
                    if verification['returncode'] != 0:
                        report.add('SIGNATURE_INVALID', relative, 'codesign verification failed')
                    result = subprocess.run([signer, '-d', '--entitlements', ':-', str(path)],
                                            stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, timeout=10, check=False)
                    if result.stdout.strip():
                        entitlements = plistlib.loads(result.stdout)
                        item['entitlements'] = sorted(entitlements)
                        for name in entitlements:
                            if name.startswith(PRIVILEGED) and entitlements[name]:
                                report.root_reasons.append('entitlement requirement')
                                granted = env.capabilities.get('granted_entitlements')
                                if granted is None:
                                    report.add('ENTITLEMENT_UNVERIFIED', relative, name, 'unknown')
                                elif name not in granted:
                                    report.add('MISSING_ENTITLEMENT', relative, name)
                else:
                    report.add('SIGNATURE_UNVERIFIED', relative, 'signature validation tool unavailable', 'unknown')
            except (ValueError, OSError, plistlib.InvalidFileException) as error:
                report.add('MACHO_INVALID', relative, str(error))
        elif kind == 'executable':
            text = path.read_bytes()[:65536].decode('utf-8', 'replace')
            if text.startswith('#!'):
                first = text.splitlines()[0][2:].strip().split()[0]
                report.dependencies.append({'kind': 'interpreter', 'name': first, 'state':
                                           'PRESENT' if first in env.libraries else 'UNKNOWN', 'mandatory': True})
                if re.search(r'(?<![\w])/(?:usr/(?:bin|sbin)|Library|etc|Applications)/', text):
                    report.add('LEGACY_SCRIPT_PATH', relative, 'script path assumptions require reviewed adapter', 'unknown')
    report.root_reasons = sorted(set(report.root_reasons))
    if 'entitlement requirement' in report.root_reasons:
        report.root_requirement = 'UNKNOWN_ROOT_REQUIREMENT'
    elif rootful:
        report.root_requirement = 'ROOT_REQUIRED_ADAPTABLE'
    elif 'daemon installation' in report.root_reasons or 'privileged file access' in report.root_reasons:
        report.root_requirement = 'ROOT_REQUIRED_AVAILABLE' if env.capabilities.get('root') is True else 'ROOT_REQUIRED_UNAVAILABLE'
    elif rootless:
        report.root_requirement = 'ROOTLESS_COMPATIBLE'
    else:
        report.root_requirement = 'NO_ROOT_REQUIRED'
    if report.root_requirement == 'ROOT_REQUIRED_UNAVAILABLE':
        report.add('ROOT_UNAVAILABLE', '', 'required privileged operation unavailable')
    report.preflight = 'BLOCKED' if any(x['severity'] == 'mandatory' for x in report.issues) else (
        'UNKNOWN' if any(x['severity'] == 'unknown' for x in report.issues) else 'ELIGIBLE')
    report.status = 'BLOCKED' if report.preflight == 'BLOCKED' else 'UNKNOWN'
    return report
