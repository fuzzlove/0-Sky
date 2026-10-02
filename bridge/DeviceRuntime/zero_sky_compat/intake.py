"""Copy originals, validate archive boundaries, extract without running scripts."""
import os
from pathlib import Path, PurePosixPath
import shutil
import stat
import subprocess
import tarfile
import zipfile
from .discovery import MAX_BYTES, MAX_FILES, file_hash, tree_hash


def safe_name(name):
    path = PurePosixPath(name)
    if path.is_absolute() or '..' in path.parts or '\\' in name or '\x00' in name:
        raise ValueError('unsafe archive path')
    return path


def extract_tar(stream, root):
    size = count = 0
    pending = []
    names = set()
    with tarfile.open(fileobj=stream, mode='r|*') as archive:
        for member in archive:
            relative = safe_name(member.name)
            if relative.as_posix() in ('.', ''):
                continue
            key = relative.as_posix()
            if key in names:
                raise ValueError('duplicate archive entry')
            names.add(key)
            count += 1
            size += member.size
            if count > MAX_FILES or size > MAX_BYTES:
                raise ValueError('archive expansion limit exceeded')
            target = root / key
            if member.isdir():
                target.mkdir(parents=True, exist_ok=True)
                os.chmod(target, member.mode & 0o777)
            elif member.isfile():
                target.parent.mkdir(parents=True, exist_ok=True)
                with archive.extractfile(member) as source, target.open('xb') as output:
                    shutil.copyfileobj(source, output)
                os.chmod(target, member.mode & 0o777)
                if member.mode & 0o7000:
                    raise ValueError('special permission bits require reviewed ownership policy')
            elif member.issym():
                # Defer links until every regular file is extracted. No extraction
                # ever traverses a link; external links need an explicit adapter.
                link = member.linkname
                if PurePosixPath(link).is_absolute():
                    raise ValueError('external archive symlink requires adapter')
                resolved = os.path.normpath(str(relative.parent / link))
                safe_name(resolved)
                pending.append((target, link))
            else:
                raise ValueError('hard links and special archive members require adapter')
    for target, link in pending:
        target.parent.mkdir(parents=True, exist_ok=True)
        target.symlink_to(link)


def extract_zip(source, root):
    with zipfile.ZipFile(source) as archive:
        members = archive.infolist()
        if len(members) > MAX_FILES or sum(x.file_size for x in members) > MAX_BYTES:
            raise ValueError('archive expansion limit exceeded')
        names = set()
        pending = []
        for member in members:
            relative = safe_name(member.filename)
            key = relative.as_posix()
            if key in names:
                raise ValueError('duplicate archive entry')
            names.add(key)
            mode = member.external_attr >> 16
            if stat.S_ISLNK(mode):
                raw = archive.read(member)
                if len(raw) > 4096 or b'\0' in raw:
                    raise ValueError('invalid ZIP symlink target')
                link = raw.decode('utf-8', 'strict')
                if PurePosixPath(link).is_absolute():
                    raise ValueError('external ZIP symlink requires adapter')
                resolved = os.path.normpath(str(relative.parent / link))
                safe_name(resolved)
                pending.append((root / key, link))
                continue
            target = root / key
            if member.is_dir():
                target.mkdir(parents=True, exist_ok=True)
            else:
                target.parent.mkdir(parents=True, exist_ok=True)
                with archive.open(member) as data, target.open('xb') as output:
                    shutil.copyfileobj(data, output)
                os.chmod(target, (mode & 0o777) or 0o644)
        # Create links only after regular members so extraction never follows a
        # package-controlled link. The normalized target cannot escape root.
        for target, link in pending:
            target.parent.mkdir(parents=True, exist_ok=True)
            target.symlink_to(link)


def dpkg_stream(tool, option, source, root):
    # dpkg-deb parses data; package maintainer scripts are never executed here.
    import tempfile
    with tempfile.TemporaryFile() as output, tempfile.TemporaryFile() as error:
        result = subprocess.run([tool, option, str(source)], stdout=output, stderr=error,
                                timeout=120, check=False)
        if result.returncode:
            raise ValueError('dpkg-deb archive inspection failed')
        if output.tell() > MAX_BYTES:
            raise ValueError('package expansion limit exceeded')
        output.seek(0)
        extract_tar(output, root)


def stage(source, work, dpkg_deb=None):
    source, work = Path(source), Path(work)
    if source.is_symlink() or not source.exists():
        raise ValueError('source must be a real artifact')
    work.mkdir(parents=True, exist_ok=False)
    original = work / 'original'
    root = work / 'staged'
    root.mkdir()
    if source.is_dir():
        source_hash = tree_hash(source)
        # Preserve source bundle identity and symlinks, then verify containment.
        shutil.copytree(source, original, symlinks=True)
        if source.suffix in ('.app', '.framework', '.xpc', '.bundle', '.appex', '.plugin'):
            shutil.copytree(original, root / source.name, symlinks=True)
        else:
            shutil.copytree(original, root, symlinks=True, dirs_exist_ok=True)
        for base, dirs, files in os.walk(root):
            for name in dirs + files:
                path = Path(base) / name
                if path.is_symlink() and not path.resolve().is_relative_to(root.resolve()):
                    raise ValueError('bundle symlink escapes staged root')
    else:
        source_hash = file_hash(source)
        shutil.copy2(source, original)
        if source.suffix.lower() == '.deb':
            tool = dpkg_deb or shutil.which('dpkg-deb')
            if not tool:
                raise ValueError('dpkg-deb unavailable')
            dpkg_stream(tool, '--fsys-tarfile', original, root)
            control = root / 'DEBIAN'
            if control.exists():
                raise ValueError('package payload overlaps DEBIAN metadata')
            control.mkdir()
            dpkg_stream(tool, '--ctrl-tarfile', original, control)
        elif zipfile.is_zipfile(original):
            extract_zip(original, root)
        elif tarfile.is_tarfile(original):
            with original.open('rb') as stream:
                extract_tar(stream, root)
        else:
            shutil.copy2(original, root / source.name)
    if (tree_hash(original) if original.is_dir() else file_hash(original)) != source_hash:
        raise ValueError('source changed during intake')
    return root, source_hash
