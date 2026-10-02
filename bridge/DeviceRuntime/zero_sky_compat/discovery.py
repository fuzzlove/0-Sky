"""Generic, non-executing artifact discovery with bounded traversal."""
import hashlib
import os
import stat
from pathlib import Path

BUNDLES = {'.app': 'application', '.framework': 'framework', '.xpc': 'xpc_service',
           '.bundle': 'bundle', '.appex': 'plugin', '.plugin': 'plugin'}
MAGICS = (b'\xcf\xfa\xed\xfe', b'\xce\xfa\xed\xfe', b'\xfe\xed\xfa\xcf',
          b'\xfe\xed\xfa\xce', b'\xca\xfe\xba\xbe', b'\xca\xfe\xba\xbf',
          b'\xbe\xba\xfe\xca', b'\xbf\xba\xfe\xca')
MAX_FILES = 100000
MAX_BYTES = 4 * 1024 ** 3


def file_hash(path):
    h = hashlib.sha256()
    with Path(path).open('rb') as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b''):
            h.update(chunk)
    return h.hexdigest()


def entries(root):
    root = Path(root)
    count = size = 0
    for base, dirs, files in os.walk(root, followlinks=False):
        dirs.sort()
        files.sort()
        for name in sorted(dirs + files):
            path = Path(base) / name
            if not (path.is_symlink() or path.is_dir() or stat.S_ISREG(path.lstat().st_mode)):
                raise ValueError('special filesystem entry requires reviewed adapter')
            count += 1
            if count > MAX_FILES:
                raise ValueError('artifact exceeds file limit')
            if path.is_file() and not path.is_symlink():
                size += path.stat().st_size
                if size > MAX_BYTES:
                    raise ValueError('artifact exceeds expansion limit')
            yield path


def tree_hash(root):
    root = Path(root)
    h = hashlib.sha256()
    for path in sorted(entries(root), key=lambda p: p.relative_to(root).as_posix()):
        relative = path.relative_to(root).as_posix()
        mode = path.lstat().st_mode & 0o7777
        value = ('link', os.readlink(path)) if path.is_symlink() else (
            ('directory', '') if path.is_dir() else ('file', file_hash(path)))
        h.update(repr((relative, mode, value)).encode() + b'\0')
    return h.hexdigest()


def discover(root):
    output = []
    for path in entries(root):
        relative = path.relative_to(root).as_posix()
        if path.is_symlink():
            output.append({'kind': 'symlink', 'path': relative, 'target': os.readlink(path)})
        elif path.is_dir() and path.suffix in BUNDLES:
            output.append({'kind': BUNDLES[path.suffix], 'path': relative})
        elif path.is_file():
            with path.open('rb') as stream:
                magic = stream.read(4)
            if magic in MAGICS:
                kind = 'macho'
            elif path.suffix == '.deb':
                kind = 'package'
            elif path.suffix == '.plist' and any(x in path.parts for x in ('LaunchDaemons', 'LaunchAgents')):
                kind = 'service'
            elif path.parent.name == 'DEBIAN' and path.name in ('preinst', 'postinst', 'prerm', 'postrm', 'config', 'triggers'):
                kind = 'maintainer_script'
            elif path.stat().st_mode & 0o111 or path.suffix in ('.py', '.sh', '.js', '.lua', '.so'):
                kind = 'executable'
            elif path.suffix == '.dylib':
                kind = 'library'
            else:
                continue
            output.append({'kind': kind, 'path': relative})
    return output
