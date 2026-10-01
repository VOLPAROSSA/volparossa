#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-only
"""Explicit CI source build and closed, verified guest staging; never execute the model/runtime."""
import argparse
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import re
import shutil
import stat
import subprocess
import tarfile
import urllib.request

HERE = Path(__file__).resolve().parent
CODE_REVISION = '7e35ba8d56df8ec43715119ceb0a1ae3f02f1f63'
CODE_TREE = '23cbaf7602f7db84b70be8264b30fa22d627a2d2'
MAIL_REVISION = '92dac0280ab741000199f342876644341c83f127'
MAIL_FILES = {
    'scripts/prepare_stalwart.py': 'a9272b1fb6015635f4937049d211c1c03d1cade86f42f9285db38ecd130dcce1',
    'scripts/prepare_stalwart_toolchain.py': '11458ee37e5180cf94259988fb9a7ed07b07e559479896de4b71bcb699246386',
    'third_party/stalwart-rust-toolchain.json': '55cc3bb0a456a7e010fc02a27fc9ce512b5f4c8d1fff3790fdea6d1ae83334c1',
}
TOOLCHAIN_SHA = 'f994b853cae209236bd522735903f66a4a01f5cc8c04632d36aa45449ca367ac'
CODEX_REVISION = '67727e7cf114cf3e1b71db368d74b24e32f6cb12'
CODEX_TREE = 'ea880e9a6ce9277531a9ab88be06f40a7ddf7b6f'
PROMPT_SHA = 'ac8ae107a0d72fe3476b430afb161ea4e67da2e446d778aefc44828160559807'
CODE_LICENSE_SHA = '3972dc9744f6499f0f9b2dbf76696f2ae7ad8af9b23dde66d6af86c9dfb36986'
MANIFEST = 'runtime/NATIVE_RUNTIME_BUNDLE.json'
MAX_BUNDLE = 1024 ** 3
MAX_ENTRIES = 10000
BUILD_ROOT = Path('/opt/volparossa-native-coding-build')


def require(value, message):
    if not value:
        raise ValueError(message)


def digest(path):
    with path.open('rb') as stream:
        return hashlib.file_digest(stream, 'sha256').hexdigest()


def safe_name(name):
    path = PurePosixPath(name)
    require(str(path) == name and not path.is_absolute() and len(path.parts) > 1
            and path.parts[0] in ('code', 'runtime')
            and all(part not in ('', '.', '..') for part in path.parts)
            and '\\' not in name and all(32 <= ord(c) < 127 for c in name), 'unsafe bundle name')
    return path


def write_json(path, value):
    with path.open('x') as stream:
        json.dump(value, stream, sort_keys=True, indent=2)
        stream.write('\n')


def code_files():
    pin = json.loads((HERE / 'agent-native-coding-pins.json').read_text())
    require(pin['revision'] == CODE_REVISION, 'Code fixture revision differs')
    require(pin['files']['LICENSE']['sha256'] == CODE_LICENSE_SHA, 'Code license differs')
    return {name: record['sha256'] for name, record in pin['files'].items()}


def checked_command(argv, *, cwd=None, seconds=120):
    env = {'PATH': '/usr/bin:/bin', 'LANG': 'C.UTF-8', 'GIT_CONFIG_NOSYSTEM': '1',
           'GIT_CONFIG_GLOBAL': '/dev/null', 'GIT_TERMINAL_PROMPT': '0', 'PYTHONDONTWRITEBYTECODE': '1'}
    return subprocess.check_output(argv, cwd=cwd, env=env, timeout=seconds)


def build_failure_diagnostic(state):
    # This stage contains only public pinned sources/dependencies. It has never
    # loaded a model, owner workspace or credentials. Never inspect guest logs.
    logs = []
    for path in sorted(state.glob('*.log')):
        if not re.fullmatch(r'(fetch|metadata|compile)-[0-9]+\.log', path.name):
            continue
        info = path.lstat()
        if not stat.S_ISREG(info.st_mode) or info.st_size > 64 * 1024 ** 2:
            continue
        with path.open('rb') as stream:
            stream.seek(max(0, info.st_size - 8192))
            tail = stream.read(8192)
        logs.append(dict(name=path.name, bytes=info.st_size, tail_bytes=len(tail),
                         truncated=info.st_size > len(tail), text=tail.decode('utf-8', errors='replace')))
        if len(logs) == 6:
            break
    return dict(kind='native-public-source-build-failure', model_executed=False,
                private_input_loaded=False, logs=logs)


def checkout(path, repository, revision, tree=None):
    path.mkdir(mode=0o700)
    checked_command(['/usr/bin/git', 'init', '--quiet', str(path)])
    checked_command(['/usr/bin/git', '-C', str(path), 'fetch', '--quiet', '--depth=1',
                     repository, revision], seconds=600)
    checked_command(['/usr/bin/git', '-C', str(path), 'checkout', '--quiet', '--detach', 'FETCH_HEAD'])
    require(checked_command(['/usr/bin/git', '-C', str(path), 'rev-parse', 'HEAD']).decode().strip() == revision,
            'source revision differs')
    if tree:
        require(checked_command(['/usr/bin/git', '-C', str(path), 'rev-parse', 'HEAD^{tree}']).decode().strip() == tree,
                'source tree differs')


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *args, **kwargs):
        raise ValueError('source redirects forbidden')


def mail_toolchain(root):
    # Reuse the reviewed, deterministic receipt producer unchanged. No Stalwart
    # source/server is fetched: only its already-reviewed Rust provisioner/helper/pin.
    root.mkdir(mode=0o700)
    for name, sha in MAIL_FILES.items():
        target = root / name
        target.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        url = f'https://raw.githubusercontent.com/VOLPAROSSA/volparossa-mail/{MAIL_REVISION}/{name}'
        with urllib.request.build_opener(NoRedirect()).open(url, timeout=30) as response:
            require(response.geturl() == url, 'unexpected source origin')
            data = response.read(1024 * 1024 + 1)
        require(len(data) <= 1024 * 1024 and hashlib.sha256(data).hexdigest() == sha, 'toolchain source differs')
        with target.open('xb') as stream:
            stream.write(data)
    (root / 'build').mkdir(mode=0o700)
    stage = root / 'build/rust'
    checked_command(['/usr/bin/python3', '-B', str(root / 'scripts/prepare_stalwart_toolchain.py'),
                     '--fetch', '--output', str(stage)], seconds=2100)
    require(digest(stage / 'TOOLCHAIN_REPORT.json') == TOOLCHAIN_SHA, 'deterministic toolchain receipt differs')
    return stage


def build(revision):
    require(os.environ.get('GITHUB_ACTIONS') == 'true' and os.getuid() != 0,
            'source build is restricted to the explicitly selected disposable CI runner')
    require(re.fullmatch('[0-9a-f]{40}', revision), 'exact core revision required')
    require(BUILD_ROOT.resolve() == BUILD_ROOT and BUILD_ROOT.is_dir()
            and BUILD_ROOT.stat().st_uid == os.getuid() and not list(BUILD_ROOT.iterdir()), 'fresh owned CI build root required')
    available = shutil.disk_usage(BUILD_ROOT).free
    print(json.dumps({'source_build_preflight': True, 'available_bytes': available,
                      'required_bytes': 48 * 1024 ** 3, 'downloads_started': False}), flush=True)
    require(available >= 48 * 1024 ** 3, 'less than 48GiB free for explicit source build')
    code = BUILD_ROOT / 'code'
    checkout(code, 'https://github.com/VOLPAROSSA/volparossa-code.git', CODE_REVISION, CODE_TREE)
    for name, sha in code_files().items():
        require(digest(code / name) == sha, 'Code fixture source differs')
    upstream = BUILD_ROOT / 'upstream-codex'
    checkout(upstream, 'https://github.com/openai/codex.git', CODEX_REVISION, CODEX_TREE)
    compiler = mail_toolchain(BUILD_ROOT / 'mail-toolchain')
    # This unmodified builder validates Git blobs, Cargo.lock, the one recorded
    # source patch and every compiler file; compilation itself is offline in bwrap.
    state = code / 'build/codex-runtime'
    try:
        checked_command(['/usr/bin/python3', '-B', str(code / 'scripts/build_codex_runtime.py'),
                         '--build', '--fetch', '--source', str(upstream), '--toolchain', str(compiler)], seconds=5100)
    except (subprocess.CalledProcessError, subprocess.TimeoutExpired):
        print(json.dumps(build_failure_diagnostic(state)), flush=True)
        raise
    build_report = json.loads((state / 'BUILD_REPORT.json').read_text())
    binary = state / 'runtime/codex-app-server'
    require(build_report['app_server_built'] is True and build_report['app_server_executed'] is False
            and build_report['source_revision'] == CODEX_REVISION and build_report['source_tree'] == CODEX_TREE
            and build_report['toolchain_report_sha256'] == TOOLCHAIN_SHA
            and build_report['binary'] == {'path': 'runtime/codex-app-server', 'bytes': binary.stat().st_size,
                                          'sha256': digest(binary)}, 'source build receipt differs')
    require(digest(upstream / 'codex-rs/models-manager/prompt.md') == PROMPT_SHA, 'full upstream prompt differs')
    dynamic = checked_command(['/usr/bin/readelf', '-d', str(binary)]).decode()
    versions = checked_command(['/usr/bin/readelf', '--version-info', str(binary)]).decode()
    needed = sorted(set(re.findall(r'Shared library: \[([^\]]+)\]', dynamic)))
    glibc = sorted(set(re.findall(r'\bGLIBC_([0-9.]+)\b', versions)),
                   key=lambda value: tuple(map(int, value.split('.'))))
    require(needed and set(needed) <= {'libssl.so.3', 'libcrypto.so.3', 'libgcc_s.so.1',
            'libm.so.6', 'libc.so.6', 'ld-linux-x86-64.so.2'} and glibc
            and tuple(map(int, glibc[-1].split('.'))) <= (2, 41), 'Debian 13 runtime ABI not supported')
    write_json(state / 'ABI_REPORT.json', dict(version=1, needed_libraries=needed,
               glibc_required=glibc, target_glibc='2.41', binary_sha256=digest(binary),
               app_server_executed=False, guest_execution_still_required=True))
    bundle = BUILD_ROOT / 'bundle'
    bundle.mkdir(mode=0o700)
    sources = {f'code/{name}': code / name for name in code_files()}
    sources.update({f'runtime/{name}': state / name for name in
                    ('BUILD_REPORT.json', 'BUILD_OWNER.json', 'ABI_REPORT.json', 'runtime/codex-app-server')})
    sources['runtime/TOOLCHAIN_REPORT.json'] = compiler / 'TOOLCHAIN_REPORT.json'
    sources['runtime/prompt.md'] = upstream / 'codex-rs/models-manager/prompt.md'
    for path in (state / 'notices').rglob('*'):
        if path.is_file():
            sources['runtime/' + path.relative_to(state).as_posix()] = path
    for path in state.glob('*.json'):
        if re.fullmatch(r'(fetch|metadata|compile)-[0-9]+\.json', path.name):
            sources['runtime/build-receipts/' + path.name] = path
    require(len(sources) <= MAX_ENTRIES - 1, 'bundle entry bound')
    files = {}
    for name, source in sorted(sources.items()):
        safe_name(name)
        require(source.is_file() and not source.is_symlink(), 'bundle source must be regular')
        target = bundle / name
        target.parent.mkdir(parents=True, exist_ok=True, mode=0o755)
        shutil.copyfile(source, target)
        mode = 0o555 if name == 'runtime/runtime/codex-app-server' else 0o444
        target.chmod(mode)
        files[name] = dict(bytes=target.stat().st_size, sha256=digest(target), mode=mode)
    receipt = dict(version=1, kind='volparossa-native-coding-runtime-bundle', core_revision=revision,
                   code_revision=CODE_REVISION, code_tree=CODE_TREE, codex_revision=CODEX_REVISION,
                   codex_tree=CODEX_TREE, toolchain_report_sha256=TOOLCHAIN_SHA,
                   binary_sha256=digest(binary), build_report_sha256=digest(state / 'BUILD_REPORT.json'),
                   prompt_sha256=PROMPT_SHA, source_build=True, existing_binary_reused=False,
                   bit_reproducibility_proven=False, app_server_executed=False, files=files)
    write_json(bundle / MANIFEST, receipt)
    (bundle / MANIFEST).chmod(0o444)
    require(sum(record['bytes'] for record in files.values()) <= MAX_BUNDLE, 'bundle size bound')
    archive = BUILD_ROOT / 'native-runtime.tar.gz'
    with tarfile.open(archive, 'x:gz') as output:
        for name in sorted([*files, MANIFEST]):
            output.add(bundle / name, arcname=name, recursive=False)
    verify(archive, revision)
    print(json.dumps({'source_build_complete': True, 'bundle': str(archive), 'bundle_sha256': digest(archive),
                      'binary_sha256': receipt['binary_sha256'], 'bit_reproducibility_proven': False}))


def verify(archive, revision):
    require(archive.is_file() and not archive.is_symlink() and archive.stat().st_size <= MAX_BUNDLE, 'invalid bundle')
    with tarfile.open(archive, 'r:gz') as stream:
        entries = {}
        total = 0
        for entry in stream:
            safe_name(entry.name)
            require(entry.name not in entries and entry.isfile() and not entry.issparse()
                    and not entry.pax_headers.get('linkpath') and 0 <= entry.size <= MAX_BUNDLE, 'invalid bundle entry')
            total += entry.size
            require(total <= MAX_BUNDLE and len(entries) < MAX_ENTRIES, 'bundle resource bound')
            entries[entry.name] = entry
        require(MANIFEST in entries and entries[MANIFEST].size <= 8 * 1024 ** 2, 'missing bounded bundle receipt')
        receipt = json.load(stream.extractfile(entries[MANIFEST]))
        require(receipt.get('version') == 1 and receipt.get('kind') == 'volparossa-native-coding-runtime-bundle'
                and receipt.get('core_revision') == revision and receipt.get('code_revision') == CODE_REVISION
                and receipt.get('code_tree') == CODE_TREE and receipt.get('codex_revision') == CODEX_REVISION
                and receipt.get('codex_tree') == CODEX_TREE and receipt.get('toolchain_report_sha256') == TOOLCHAIN_SHA
                and receipt.get('prompt_sha256') == PROMPT_SHA and receipt.get('source_build') is True
                and receipt.get('existing_binary_reused') is False and receipt.get('app_server_executed') is False
                and receipt.get('bit_reproducibility_proven') is False, 'bundle authority differs')
        require(set(entries) == set(receipt['files']) | {MANIFEST}, 'bundle inventory differs')
        for name, record in receipt['files'].items():
            entry = entries[name]
            mode = 0o555 if name == 'runtime/runtime/codex-app-server' else 0o444
            require(record['bytes'] == entry.size and record['mode'] == mode == entry.mode
                    and record['sha256'] == hashlib.file_digest(stream.extractfile(entry), 'sha256').hexdigest(),
                    'bundle bytes or mode differ')
        for name, sha in code_files().items():
            require(receipt['files'][f'code/{name}']['sha256'] == sha, 'bundled Code source differs')
        for name, key in [('runtime/codex-app-server', 'binary_sha256'), ('BUILD_REPORT.json', 'build_report_sha256'),
                          ('TOOLCHAIN_REPORT.json', 'toolchain_report_sha256'), ('prompt.md', 'prompt_sha256')]:
            require(receipt['files']['runtime/' + name]['sha256'] == receipt[key], 'bundled runtime binding differs')
    return receipt


def stage(archive, revision):
    require(os.getuid() == 0 and Path('/etc/hostname').read_text().strip() == 'volparossa-alpha'
            and checked_command(['/usr/bin/systemd-detect-virt']).decode().strip() == 'kvm', 'disposable KVM guest required')
    receipt = verify(archive, revision)
    targets = {'code': Path('/home/vpci/code'), 'runtime': Path('/opt/volparossa-codex-runtime')}
    require(all(not path.exists() and not path.is_symlink() for path in targets.values()), 'guest stage already exists')
    for path in targets.values():
        path.mkdir(mode=0o755)
    with tarfile.open(archive, 'r:gz') as stream:
        for entry in stream:
            parts = safe_name(entry.name).parts
            target = targets[parts[0]].joinpath(*parts[1:])
            target.parent.mkdir(parents=True, exist_ok=True, mode=0o755)
            with target.open('xb') as output, stream.extractfile(entry) as source:
                shutil.copyfileobj(source, output, 65536)
            target.chmod(0o555 if entry.name == 'runtime/runtime/codex-app-server' else 0o444)
    # The guest driver uses umask 077; public immutable source/runtime parents
    # must still be traversable by vpci. Private build output is the sole exception.
    for root in targets.values():
        root.chmod(0o755)
        for path in root.rglob('*'):
            if path.is_dir():
                path.chmod(0o755)
    import pwd
    owner = pwd.getpwnam('vpci')
    work = targets['code'] / 'build'
    work.mkdir(mode=0o700)
    os.chown(work, owner.pw_uid, owner.pw_gid)
    print(json.dumps({'staged': True, 'code_revision': receipt['code_revision'],
                      'binary_sha256': receipt['binary_sha256'], 'app_server_executed': False}))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('mode', choices=('build', 'verify', 'stage'))
    parser.add_argument('--expected-commit', required=True)
    parser.add_argument('--bundle', type=Path)
    parser.add_argument('--yes', action='store_true')
    args = parser.parse_args()
    require(re.fullmatch('[0-9a-f]{40}', args.expected_commit), 'exact core revision required')
    if args.mode == 'build':
        require(args.yes and args.bundle is None, 'explicit build confirmation required')
        build(args.expected_commit)
    else:
        require(args.bundle is not None, 'bundle required')
        if args.mode == 'stage':
            require(args.yes, 'explicit guest stage confirmation required')
            stage(args.bundle, args.expected_commit)
        else:
            verify(args.bundle, args.expected_commit)


if __name__ == '__main__':
    main()
