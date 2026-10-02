"""Read-only installed component audit. No installation success is inferred as PASS."""
import json
import os
from pathlib import Path
import plistlib
import subprocess
from .discovery import MAGICS, file_hash
from .failures import fingerprint
from .classification import legacy_status, static_state
from .model import Report, STATES, digest
from .registry import Registry
from . import macho


def audit_installed(environment, state, extra_roots=()):
    registry = Registry(Path(state) / 'registry.sqlite3')
    registry.save_environment(environment)
    prefix = environment.bootstrap_prefix
    query = prefix + '/usr/bin/dpkg-query'
    result = subprocess.run([query, '-W', '-f=${Package}\t${Version}\t${Status}\n'],
                            stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=30, check=False)
    if result.returncode:
        raise RuntimeError('installed package inventory unavailable')
    reports = []
    paths_seen = set()
    for row in result.stdout.decode('utf-8', 'replace').splitlines():
        fields = row.split('\t')
        if len(fields) != 3:
            continue
        identity, version, status = fields
        payload = subprocess.run([query, '-L', identity], stdout=subprocess.PIPE,
                                 stderr=subprocess.PIPE, timeout=30, check=False)
        paths = []
        for line in payload.stdout.decode('utf-8', 'replace').splitlines():
            if not line.startswith('/'):
                continue
            # Procursus dpkg-query includes descriptive link targets. Confirm
            # the real link instead of treating the description as a filename.
            name, separator, target = line.partition(' -> ')
            path = Path(name)
            if separator and path.is_symlink() and os.readlink(path) == target:
                paths.append(path)
            else:
                paths.append(Path(line))
        for info in (Path(prefix + '/var/lib/dpkg/info'), Path(prefix + '/Library/dpkg/info')):
            for suffix in ('preinst', 'postinst', 'prerm', 'postrm', 'triggers'):
                script = info / (identity + '.' + suffix)
                if script.is_file():
                    paths.append(script)
        report = audit_paths(identity, version, paths, environment)
        if status != 'install ok installed':
            report.add('DPKG_STATE_INVALID', '', 'package is not fully configured')
            report.set_compatibility('BROKEN_UPSTREAM', 'CLASSIFY',
                                     'installed package database state is incomplete')
            report.status = 'BLOCKED'
        if payload.returncode:
            report.add('PAYLOAD_INVENTORY_FAILED', '', 'dpkg-query file list unavailable', 'unknown')
        paths_seen.update(str(p) for p in paths)
        registry.save(report)
        reports.append(report.to_dict())
    # Discover unmanaged mounted apps, helpers and services independently of dpkg.
    roots = [Path(prefix + '/Applications'), Path(prefix + '/Library/LaunchDaemons'),
             Path(prefix + '/usr/local/libexec'), Path('/private/var/run/com.apple.security.cryptexd/mnt')]
    roots += [Path(p) for p in extra_roots]
    for root in roots:
        if not root.is_dir() or root.is_symlink():
            continue
        for base, dirs, files in os.walk(root, followlinks=False):
            dirs.sort()
            for name in list(dirs):
                path = Path(base) / name
                if path.suffix in ('.app', '.framework', '.xpc', '.bundle', '.appex', '.plugin'):
                    dirs.remove(name)
                    fileset = [p for p in path.rglob('*') if not p.is_dir() and not p.is_symlink()]
                    if str(path) not in paths_seen:
                        identity = 'unmanaged:' + path.name
                        info = path / 'Info.plist'
                        if info.is_file():
                            try:
                                identity = plistlib.loads(info.read_bytes()).get('CFBundleIdentifier', identity)
                            except Exception:
                                pass
                        report = audit_paths(identity, 'unknown', fileset, environment)
                        registry.save(report)
                        reports.append(report.to_dict())
            for name in sorted(files):
                path = Path(base) / name
                if str(path) in paths_seen or path.is_symlink():
                    continue
                if path.suffix == '.plist' or path.stat().st_mode & 0o111:
                    report = audit_paths('unmanaged:' + name, 'unknown', [path], environment)
                    registry.save(report)
                    reports.append(report.to_dict())
    groups = {state: [] for state in STATES}
    for report in reports:
        groups[report.get('compatibility_state', 'UNKNOWN')].append(report)
    return {'schema_version': 2, 'environment': environment.canonical(),
            'scope': 'dpkg payloads and unmanaged apps, helpers, services in configured roots; read-only',
            'components': reports, 'groups': groups}


def audit_paths(identity, version, paths, environment):
    hashes = []
    report = Report(identity, version, '', environment.summary(), environment.fingerprint)
    for path in sorted(set(paths)):
        try:
            if path.is_symlink():
                hashes.append([str(path), 'symlink', os.readlink(path)])
                if not path.exists():
                    report.add('SYMLINK_TARGET_MISSING', str(path), 'declared link target absent')
            elif path.is_file():
                hashes.append([str(path), file_hash(path)])
                with path.open('rb') as stream:
                    magic = stream.read(4)
                if magic in MAGICS:
                    slices = macho.parse(path)
                    report.components.append({'kind': 'macho', 'path': str(path), 'binary': slices})
                    matching = [s for s in slices if s['architecture'] in (environment.architecture, 'arm64')]
                    if not matching:
                        if environment.architecture == 'arm64' and any(s['architecture'] == 'arm64e' for s in slices):
                            report.add('ARCHITECTURE_CAPABILITY_UNKNOWN', str(path), 'arm64e ABI acceptance unverified', 'unknown')
                        else:
                            report.add('ARCHITECTURE_MISMATCH', str(path), 'no compatible CPU slice')
                    for item in matching:
                        if not item['signed']:
                            report.add('SIGNATURE_MISSING', str(path), 'signature absent')
                    report.add('RUNTIME_AUDIT_PENDING', str(path), 'signature acceptance and functional behavior untested', 'unknown')
                elif path.suffix == '.plist' and any(p in path.parts for p in ('LaunchDaemons', 'LaunchAgents')):
                    info = plistlib.loads(path.read_bytes())
                    args = info.get('ProgramArguments') or []
                    executable = info.get('Program') or (args[0] if args else None)
                    if not executable:
                        report.add('EXECUTABLE_NOT_FOUND', str(path), 'daemon program absent')
                    elif not Path(executable).is_file():
                        if str(executable).startswith(environment.bootstrap_prefix + '/'):
                            report.add('EXECUTABLE_NOT_FOUND', str(path), 'bootstrap daemon program absent')
                        else:
                            # Mounted cryptex and embedded kit plists may refer
                            # to launch-context paths. A host-root lookup cannot
                            # establish that those services are broken.
                            report.add('SERVICE_PATH_CONTEXT_UNKNOWN', str(path),
                                       'service launch context has not been resolved', 'unknown')
                    report.components.append({'kind': 'service', 'path': str(path), 'label': info.get('Label')})
                elif path.stat().st_mode & 0o111:
                    report.components.append({'kind': 'executable', 'path': str(path)})
            elif not path.exists():
                # Ancestor directory placeholders from dpkg -L are not components.
                report.add('EXPECTED_FILE_MISSING', str(path), 'declared package file absent')
        except (OSError, ValueError, plistlib.InvalidFileException) as error:
            report.add('AUDIT_READ_FAILED', str(path), type(error).__name__, 'unknown')
    report.source_hash = digest(hashes)
    report.add('FUNCTIONAL_AUDIT_PENDING', '', 'no functional validation or restart evidence', 'unknown')
    report.set_compatibility(static_state(report), 'CLASSIFY',
                             'read-only inventory cannot establish runtime compatibility')
    if report.compatibility_state == 'NATIVE_COMPATIBLE':
        report.set_compatibility('UNKNOWN', 'CLASSIFY',
                                 'functional audit evidence is pending')
    report.status = legacy_status(report.compatibility_state)
    report.root_requirement = 'UNKNOWN_ROOT_REQUIREMENT'
    return report
