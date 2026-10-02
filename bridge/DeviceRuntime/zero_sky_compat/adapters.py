"""Reversible staging adapters; protected Apple paths and binary bytes are untouched."""
import json
from pathlib import Path
import plistlib
import shutil
from .analysis import ROOTS
from .discovery import file_hash, tree_hash
from .paths import RootlessPaths


def normalize_rootless(root, env):
    paths = RootlessPaths.from_environment(env)
    prefix = paths.prefix
    if prefix != '/var/jb' or env.capabilities.get('var_jb') is not True:
        raise ValueError('verified /var/jb bootstrap required')
    changes = []
    present = [name for name in ROOTS if (root / name).exists()]
    # Only paths owned by this payload are translated, never arbitrary /usr/lib
    # references that may intentionally refer to Apple system libraries.
    owned = set()
    for name in present:
        for path in (root / name).rglob('*'):
            owned.add('/' + path.relative_to(root).as_posix())
    for plist in sorted(root.rglob('*.plist')):
        if plist.is_symlink() or not plist.is_file():
            continue
        if not any(name in plist.parts for name in ('LaunchDaemons', 'LaunchAgents')):
            continue
        value = plistlib.loads(plist.read_bytes())
        before = file_hash(plist)
        rewritten = []
        # No shell ProgramArguments are interpreted or string-replaced.
        for key in ('Program', 'WorkingDirectory', 'StandardOutPath', 'StandardErrorPath'):
            old = value.get(key)
            if isinstance(old, str) and old in owned:
                value[key] = paths.translate_owned(old, owned)
                rewritten.append(key)
        args = value.get('ProgramArguments')
        if isinstance(args, list) and args and args[0] in owned:
            args[0] = paths.translate_owned(args[0], owned)
            rewritten.append('ProgramArguments[0]')
        if rewritten:
            plist.write_bytes(plistlib.dumps(value, sort_keys=True))
            changes.append({'adapter': 'rootless-service-path-v1', 'path': plist.relative_to(root).as_posix(),
                            'fields': rewritten, 'before_hash': before, 'after_hash': file_hash(plist)})
    for name in present:
        source = root / name
        target = root / prefix.lstrip('/') / name
        if target.exists():
            raise ValueError('rootless relocation collides with existing payload')
        target.parent.mkdir(parents=True, exist_ok=True)
        source.rename(target)
        changes.append({'adapter': 'rootless-payload-v1', 'from': name,
                        'to': target.relative_to(root).as_posix()})
    return changes


def apply(root, work, env, report, adapter_names):
    allowed = {'rootless-v1': normalize_rootless}
    if set(adapter_names) - set(allowed):
        raise ValueError('unsupported adapter')
    if not adapter_names:
        return []
    # A byte-preserving backup supplies reversal and a reproducible diff basis.
    backup = work / 'before-adaptation'
    shutil.copytree(root, backup, symlinks=True)
    before = tree_hash(root)
    changes = []
    try:
        for name in adapter_names:
            changes.extend(allowed[name](root, env))
        (work / 'transformations.json').write_text(json.dumps({
            'schema_version': 1, 'before_hash': before, 'after_hash': tree_hash(root),
            'changes': changes}, sort_keys=True, indent=2) + '\n')
    except Exception:
        shutil.rmtree(root)
        shutil.copytree(backup, root, symlinks=True)
        if tree_hash(root) != before:
            raise RuntimeError('adaptation rollback integrity failure')
        raise
    report.adaptations = changes
    return changes
