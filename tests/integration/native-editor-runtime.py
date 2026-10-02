#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-only
"""Package reviewed existing runtimes for one guest trial; no download or execution."""
import argparse
import hashlib
import importlib.util
import io
import json
import os
from pathlib import Path, PurePosixPath
import re
import shutil
import stat
import subprocess
import tarfile

HERE = Path(__file__).resolve().parent
MANIFEST = 'runtime/NATIVE_EDITOR_BUNDLE.json'
MAX_BYTES = 2 * 1024 ** 3
MAX_FILES = 10000
MAX_MANIFEST = 4 * 1024 ** 2


def require(value, message):
    if not value:
        raise ValueError(message)


def digest(path):
    with path.open('rb') as stream:
        return hashlib.file_digest(stream, 'sha256').hexdigest()


def pins():
    return json.loads((HERE / 'agent-native-editor-pins.json').read_text())


def inventory_digest(value):
    return hashlib.sha256(json.dumps(value, sort_keys=True, separators=(',', ':')).encode()).hexdigest()


def safe_name(name):
    path = PurePosixPath(name)
    require(str(path) == name and not path.is_absolute() and len(path.parts) > 1
            and path.parts[0] in ('code', 'runtime', 'editor')
            and all(part not in ('', '.', '..') for part in path.parts)
            and '\\' not in name and all(32 <= ord(c) < 127 for c in name), 'unsafe bundle name')
    return path


def file_record(path, mode=None):
    info = path.lstat()
    require(stat.S_ISREG(info.st_mode) and not path.is_symlink(), 'regular input required')
    return dict(bytes=info.st_size, sha256=digest(path),
                mode=mode if mode is not None else (0o555 if info.st_mode & 0o111 else 0o444))


def inventory(root):
    require(root.is_dir() and not root.is_symlink(), 'input directory required')
    result = {}
    for path in sorted(root.rglob('*')):
        require(not path.is_symlink(), 'symlink input refused')
        if not path.is_dir():
            name = path.relative_to(root).as_posix()
            safe_name('runtime/' + name)
            result[name] = file_record(path)
            require(len(result) < MAX_FILES, 'input file bound')
    return result


def authority(revision):
    require(re.fullmatch('[0-9a-f]{40}', revision), 'exact core revision required')
    pin = pins()
    return dict(version=1, kind='volparossa-native-editor-bundle', core_revision=revision,
                code_revision=pin['code_revision'], code_tree=pin['code_tree'],
                native=pin['native'], editor=pin['editor'], existing_runtime_reused=True,
                downloads_performed=False, binaries_executed=False,
                development_host_installation=False)


def validate_inventory(files):
    pin = pins()
    require(type(files) is dict and 0 < len(files) < MAX_FILES, 'inventory bound')
    total = 0
    groups = {'code': {}, 'runtime': {}, 'editor': {}}
    for name, row in files.items():
        parts = safe_name(name).parts
        require(type(row) is dict and set(row) == {'bytes', 'sha256', 'mode'}
                and type(row['bytes']) is int and 0 <= row['bytes'] <= MAX_BYTES
                and type(row['mode']) is int and row['mode'] in (0o444, 0o555)
                and type(row['sha256']) is str and re.fullmatch('[0-9a-f]{64}', row['sha256']),
                'inventory record')
        total += row['bytes']
        groups[parts[0]]['/'.join(parts[1:])] = row
    require(total <= MAX_BYTES, 'bundle byte bound')
    require(groups['code'] == pin['code_files'], 'Code source inventory differs')
    require(inventory_digest(groups['editor']) == pin['editor']['inventory_sha256']
            and len(groups['editor']) == pin['editor']['files']
            and sum(x['bytes'] for x in groups['editor'].values()) == pin['editor']['bytes'],
            'installed editor inventory differs')
    runtime = groups['runtime']
    notices = {name[len('notices/'):]: row for name, row in runtime.items() if name.startswith('notices/')}
    require(inventory_digest(notices) == pin['native']['notices_inventory_sha256'], 'native notices differ')
    require(set(runtime) == {'runtime/codex-app-server', 'BUILD_REPORT.json', 'prompt.md'}
            | {'notices/' + name for name in notices}, 'runtime inventory differs')
    for name, field in (('runtime/codex-app-server', 'binary_sha256'),
                        ('BUILD_REPORT.json', 'build_report_sha256'), ('prompt.md', 'prompt_sha256')):
        require(runtime[name]['sha256'] == pin['native'][field]
                and runtime[name]['mode'] == (0o555 if name.startswith('runtime/') else 0o444),
                'native runtime binding differs')


def pack(archive, revision, code, runtime, editor, prompt):
    require(os.getuid() != 0, 'unprivileged pack required')
    require(archive.is_absolute() and archive.parent.resolve(strict=True) == archive.parent
            and not archive.exists() and not archive.is_symlink(), 'fresh archive required')
    # This is a local verified-input packaging step, not another source build.
    pin = pins()
    for ref, expected in (('HEAD', pin['code_revision']), ('HEAD^{tree}', pin['code_tree'])):
        actual = subprocess.check_output(['git', '-C', str(code), 'rev-parse', ref], timeout=10)
        require(actual.decode().strip() == expected, 'Code revision differs')
    sources = {'code/' + name: code / name for name in pin['code_files']}
    files = {name: file_record(path, 0o444) for name, path in sources.items()}
    for prefix, root in (('editor', editor), ('runtime/notices', runtime / 'notices')):
        for name, row in inventory(root).items():
            sources[prefix + '/' + name] = root / name
            files[prefix + '/' + name] = row
    for name, path, mode in [('runtime/runtime/codex-app-server', runtime / 'runtime/codex-app-server', 0o555),
                              ('runtime/BUILD_REPORT.json', runtime / 'BUILD_REPORT.json', 0o444),
                              ('runtime/prompt.md', prompt, 0o444)]:
        sources[name] = path
        files[name] = file_record(path, mode)
    validate_inventory(files)
    # Independently use the pinned product validator for source/lock/patch/notices binding.
    spec = importlib.util.spec_from_file_location('native_editor_verified_build', code / 'scripts/smoke_native_coding.py')
    validator = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(validator)
    validator.verified_build(str(runtime / 'BUILD_REPORT.json'), runtime / 'runtime/codex-app-server',
                             pin['native']['binary_sha256'])
    require(shutil.disk_usage(archive.parent).free >= sum(row['bytes'] for row in files.values()) + 1024 ** 3,
            'insufficient packaging space')
    receipt = dict(authority(revision), files=files)
    encoded = (json.dumps(receipt, sort_keys=True, indent=2) + '\n').encode()
    require(len(encoded) <= MAX_MANIFEST, 'manifest bound')
    with tarfile.open(archive, 'x:gz', compresslevel=1) as bundle:
        for name, path in sorted(sources.items()):
            record = files[name]
            info = tarfile.TarInfo(name)
            info.size, info.mode = record['bytes'], record['mode']
            with path.open('rb') as source:
                bundle.addfile(info, source)
        info = tarfile.TarInfo(MANIFEST)
        info.size, info.mode = len(encoded), 0o444
        bundle.addfile(info, io.BytesIO(encoded))
    verify(archive, revision)
    print(json.dumps(dict(packed=True, bytes=archive.stat().st_size, sha256=digest(archive),
                          files=len(files), existing_runtime_reused=True, binaries_executed=False)))


def verify(archive, revision):
    require(archive.is_file() and not archive.is_symlink() and archive.stat().st_size <= MAX_BYTES,
            'invalid bundle')
    expected = authority(revision)
    entries = {}
    total = 0
    with tarfile.open(archive, 'r:gz') as stream:
        for entry in stream:
            safe_name(entry.name)
            require(entry.name not in entries and entry.isfile() and not entry.issparse()
                    and not entry.linkname and not entry.pax_headers.get('linkpath')
                    and entry.mode in (0o444, 0o555) and entry.uid == entry.gid == 0,
                    'invalid bundle member')
            total += entry.size
            require(0 <= entry.size <= MAX_BYTES and total <= MAX_BYTES + MAX_MANIFEST
                    and len(entries) < MAX_FILES, 'bundle resource bound')
            entries[entry.name] = entry
        require(MANIFEST in entries and entries[MANIFEST].size <= MAX_MANIFEST
                and entries[MANIFEST].mode == 0o444, 'bounded receipt required')
        receipt = json.load(stream.extractfile(entries[MANIFEST]))
        require(set(receipt) == set(expected) | {'files'}
                and {key: receipt[key] for key in expected} == expected, 'bundle authority differs')
        files = receipt['files']
        validate_inventory(files)
        require(set(entries) == set(files) | {MANIFEST}, 'bundle inventory differs')
        for name, row in files.items():
            entry = entries[name]
            require(entry.size == row['bytes'] and entry.mode == row['mode']
                    and hashlib.file_digest(stream.extractfile(entry), 'sha256').hexdigest() == row['sha256'],
                    'bundle content differs')
    return receipt


def stage(archive, revision):
    require(os.getuid() == 0 and Path('/etc/hostname').read_text().strip() == 'volparossa-alpha'
            and subprocess.check_output(['/usr/bin/systemd-detect-virt', '--vm'], timeout=5).strip() == b'kvm',
            'disposable KVM guest required')
    verify(archive, revision)
    roots = {'code': Path('/home/vpci/code'), 'runtime': Path('/opt/volparossa-codex-runtime'),
             'editor': Path('/opt/volparossa-editor')}
    require(all(not root.exists() and not root.is_symlink() for root in roots.values()), 'fresh guest stage required')
    for root in roots.values():
        root.mkdir(mode=0o755)
    with tarfile.open(archive, 'r:gz') as stream:
        for entry in stream:
            parts = safe_name(entry.name).parts
            target = roots[parts[0]].joinpath(*parts[1:])
            target.parent.mkdir(parents=True, exist_ok=True, mode=0o755)
            with target.open('xb') as output, stream.extractfile(entry) as source:
                shutil.copyfileobj(source, output, 65536)
            target.chmod(entry.mode)
    # A guest umask of 077 must not make immutable input parents inaccessible.
    for root in roots.values():
        root.chmod(0o755)
        for path in root.rglob('*'):
            if path.is_dir():
                path.chmod(0o755)
    import pwd
    owner = pwd.getpwnam('vpci')
    work = roots['code'] / 'build'
    work.mkdir(mode=0o700)
    os.chown(work, owner.pw_uid, owner.pw_gid)
    print(json.dumps(dict(staged=True, binaries_executed=False)))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('mode', choices=('pack', 'verify', 'stage'))
    parser.add_argument('--bundle', required=True, type=Path)
    parser.add_argument('--expected-commit', required=True)
    parser.add_argument('--code', type=Path)
    parser.add_argument('--runtime', type=Path)
    parser.add_argument('--editor', type=Path)
    parser.add_argument('--prompt', type=Path)
    parser.add_argument('--yes', action='store_true')
    args = parser.parse_args()
    if args.mode == 'pack':
        require(args.yes and all((args.code, args.runtime, args.editor, args.prompt)), 'explicit packaging inputs required')
        pack(args.bundle, args.expected_commit, args.code, args.runtime, args.editor, args.prompt)
    elif args.mode == 'stage':
        require(args.yes, 'explicit stage confirmation required')
        stage(args.bundle, args.expected_commit)
    else:
        verify(args.bundle, args.expected_commit)


if __name__ == '__main__':
    main()
