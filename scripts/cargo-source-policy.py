#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-only
"""Public crates.io input boundary for the known-unpatched old Cargo profiles.

This excludes alternate-registry/auth/SSH operating modes; it patches no binary.
Never inspect ambient config/credential contents or echo rejected input values.
"""
import hashlib
import io
import json
import os
from pathlib import Path
from functools import wraps
import re
import stat
import subprocess
import sys
import tarfile
import tomllib
import urllib.request

ROOT = Path(__file__).resolve().parents[1]
REGISTRY = 'registry+https://github.com/rust-lang/crates.io-index'
SEV = 'a966d06d9bf0e68afe2733e7bfbf278fd7fd65b5'
PATCHES = {name: {'path': 'third_party/rust/vendor/' + directory} for name, directory in (
    ('ctutils', 'ctutils-0.4.5'), ('hickory-proto', 'hickory-proto-0.25.2'),
    ('hickory-resolver', 'hickory-resolver-0.25.2'), ('libp2p-yamux', 'libp2p-yamux-0.47.0'),
    ('time', 'time-0.3.41'))}
CONFIG = b'[registries.crates-io]\nprotocol = "sparse"\n\n[registry]\ndefault = "crates-io"\nglobal-credential-providers = []\n\n[net]\ngit-fetch-with-cli = true\n'
GIT_ENV = {'GIT_CONFIG_NOSYSTEM': '1', 'GIT_CONFIG_SYSTEM': '/dev/null',
           'GIT_CONFIG_GLOBAL': '/dev/null', 'GIT_ALLOW_PROTOCOL': 'https',
           'GIT_TERMINAL_PROMPT': '0', 'GIT_ASKPASS': '/usr/bin/false'}
MARKER = '.volparossa-public-source-v1.json'
HOME_NAME = 'volparossa-cargo-public-v1'
BACKPORT_CONFIG = b'[resolver]\nincompatible-rust-versions = "fallback"\n'
BACKPORT_CONFIG_SHA256 = 'aabd2af12e26033cb8de9b63841b54574718406e4479b47e41bc0d92fc6f14e0'
ALLOWED_ENV = {'CARGO_HOME', 'CARGO_TERM_COLOR', 'CARGO_TARGET_DIR', 'CARGO_BUILD_JOBS',
               'CARGO_TARGET_I686_UNKNOWN_LINUX_MUSL_LINKER', 'CARGO_AUDIT'}
TOOL_PINS = {
    'cargo-deny': ('0.18.6', '26b71559c7a61f3e31d68466265e430e0d728fd76f5ce95738e5f9d5e5baf37a',
                   '6e718ae4e2b9332ac5c3462a22d9ae4e19f9e21bc6d249e04a9a70b0813d8a11',
                   'faeccb48ccb7d8cad13a18d6deac064a37bbfb61cce7cba8833e18d0e628d5cc'),
    'cargo-audit': ('0.22.1', '2f4e27b0ab2d116c87c29db159ad42565cdcdccf77eb62ef0486ddd017a02da6',
                    '58fe380ec4823e1dae91f0371f71d2ebddfac69eb65a240cd4fef0a321774e0c',
                    '34959759819e0d0e1babbb39cef44bd76d04dad0f4558303c80d2e2173726ba4')}


class PolicyError(ValueError):
    pass


def sanitized(function):
    @wraps(function)
    def call(*args, **kwargs):
        try:
            return function(*args, **kwargs)
        except PolicyError:
            raise
        except (OSError, ValueError, KeyError, TypeError, AttributeError, RecursionError,
                tarfile.TarError, subprocess.SubprocessError):
            raise PolicyError('CARGO_PUBLIC_SOURCE_POLICY_V1=rejected') from None
    return call


def require(value, category):
    if not value:
        raise PolicyError('CARGO_PUBLIC_SOURCE_POLICY_V1=' + category)


def digest(raw):
    return hashlib.sha256(raw).hexdigest()


def exists(path):
    return path.exists() or path.is_symlink()


def check_environment(env):
    # Presence alone is enough to reject credentials/config indirection. Values
    # are neither inspected nor included in errors, receipts or debug output.
    for name in env:
        require(not (name.startswith('CARGO_') and name not in ALLOWED_ENV), 'environment')
        upper = name.upper()
        if upper.startswith(('GIT_', 'SSH_')):
            require(name in GIT_ENV and env[name] == GIT_ENV[name], 'environment')
        require(upper not in {
            'HTTP_PROXY', 'HTTPS_PROXY', 'ALL_PROXY', 'CURL_CA_BUNDLE', 'SSL_CERT_FILE',
            'SSL_CERT_DIR', 'NETRC', 'CARGO_CONFIG', 'CARGO_CONFIG_PATH', 'RUSTUP_TOOLCHAIN',
            'RUSTUP_DIST_SERVER', 'RUSTUP_UPDATE_ROOT', 'RUSTC_WRAPPER', 'RUSTC_WORKSPACE_WRAPPER'}, 'environment')
    account = Path(env.get('HOME', ''))
    require(account.is_absolute() and account.resolve() == account, 'home')
    if 'RUSTUP_HOME' in env:
        require(env['RUSTUP_HOME'] == str(account/'.rustup'), 'compiler-environment')
    if 'CARGO_AUDIT' in env:
        require(env['CARGO_AUDIT'] == 'cargo-audit' or env['CARGO_AUDIT'] ==
                str(Path(env.get('RUNNER_TEMP', ''))/'quality-audit-tools/bin/cargo-audit'), 'environment')
    prefixes = {Path(env.get('HOME', ''))/'.local/volparossa-rust-1.89.0'}
    if 'RUNNER_TEMP' in env:
        prefixes.add(Path(env['RUNNER_TEMP'])/'volparossa-rust-1.89.0')
    for name, binary in (('RUSTC', 'rustc'), ('RUSTDOC', 'rustdoc')):
        if name in env:
            require(env[name] in {str(prefix/'bin'/binary) for prefix in prefixes}, 'compiler-environment')
    if 'CARGO_TARGET_I686_UNKNOWN_LINUX_MUSL_LINKER' in env:
        require(env['CARGO_TARGET_I686_UNKNOWN_LINUX_MUSL_LINKER'] in {
            str(prefix/'lib/rustlib/x86_64-unknown-linux-gnu/bin/rust-lld') for prefix in prefixes}, 'compiler-environment')


def check_discovery(cwd, env, own_home=None, *, diagnostic=False):
    require(cwd.is_absolute() and cwd.resolve() == cwd, 'working-directory')
    for directory in (cwd, *cwd.parents):
        configuration = directory/'.cargo'
        if exists(configuration):
            info = configuration.lstat()
            require(stat.S_ISDIR(info.st_mode) and info.st_uid in (0, os.geteuid())
                    and not info.st_mode & 0o022, 'ancestor-config')
        for name in ('config', 'config.toml'):
            config = directory/'.cargo'/name
            if diagnostic and directory == cwd and name == 'config.toml':
                require(config.is_file() and not config.is_symlink()
                        and config.stat().st_nlink == 1 and config.stat().st_size == len(BACKPORT_CONFIG), 'diagnostic-config')
                raw = config.read_bytes()
                require(raw == BACKPORT_CONFIG and digest(raw) == BACKPORT_CONFIG_SHA256, 'diagnostic-config')
            else:
                require(not exists(config), 'ancestor-config')
    homes = {Path(env.get('HOME', '')) / '.cargo'}
    if 'CARGO_HOME' in env:
        homes.add(Path(env['CARGO_HOME']))
    for home in homes:
        for name in ('credentials', 'credentials.toml'):
            require(not exists(home / name), 'credentials')
        for name in ('config', 'config.toml'):
            if home != own_home:
                require(not exists(home / name), 'home-config')
    for name in ('.netrc', '_netrc'):
        require(not exists(Path(env.get('HOME', '')) / name), 'credentials')


def lock_sources(raw):
    try:
        value = tomllib.loads(raw.decode())
        require(value.get('version') in (3, 4) and isinstance(value.get('package'), list), 'lock')
        for item in value['package']:
            if 'source' in item:
                require(item['source'] == REGISTRY and re.fullmatch('[0-9a-f]{64}', item.get('checksum', '')), 'lock-source')
    except (UnicodeError, tomllib.TOMLDecodeError, TypeError, KeyError):
        raise PolicyError('CARGO_PUBLIC_SOURCE_POLICY_V1=lock') from None


def manifest_sources(value, base, *, sev=False, paths=True):
    members = value.get('workspace', {}).get('members', [])
    require(members == ['crates/*'] if sev else members in ([], ['.']), 'workspace-members')
    known_paths = {path.parent for path in ROOT.glob('crates/*/Cargo.toml')} | {
        ROOT/v['path'] for v in PATCHES.values()} | {
        ROOT/'third_party/rust/vendor/ctutils-0.4.4', ROOT/'third_party/rust/vendor/sev-8.0.0'}
    def dependencies(item):
        for key, child in item.items():
            if key in ('dependencies', 'dev-dependencies', 'build-dependencies'):
                for name, declaration in child.items():
                    if not isinstance(declaration, dict):
                        continue
                    require('registry' not in declaration and 'registry-index' not in declaration, 'manifest-source')
                    if 'git' in declaration:
                        require(sev and name == 'sev' and declaration == dict(version='=8.0.0',
                            git='https://github.com/virtee/sev', rev=SEV,
                            **{'default-features': False}, features=['snp', 'crypto_nossl']), 'manifest-git')
                    if 'path' in declaration:
                        path = base / declaration['path']
                        require(paths and path.resolve() in known_paths and not path.is_symlink(), 'manifest-path')
            elif isinstance(child, dict):
                dependencies(child)
    dependencies(value)
    require('replace' not in value, 'manifest-source')
    for origin, patches in value.get('patch', {}).items():
        require(origin == 'crates-io' or (sev and origin == 'https://github.com/virtee/sev'), 'patches')
        allowed = {ROOT/v['path'] for v in PATCHES.values()} | {
            ROOT/'third_party/rust/vendor/ctutils-0.4.4', ROOT/'third_party/rust/vendor/sev-8.0.0'}
        for declaration in patches.values():
            require(paths and set(declaration) == {'path'} and
                    (base/declaration['path']).resolve() in allowed, 'patches')


def input_bytes(path):
    require(path.is_absolute() and path.resolve() == path and path.is_file()
            and not path.is_symlink() and path.stat().st_nlink == 1
            and path.stat().st_size <= 4*1024*1024, 'source-input')
    with path.open('rb') as stream:
        raw = stream.read(4*1024*1024+1)
    require(len(raw) <= 4*1024*1024, 'source-input')
    return raw


@sanitized
def repository_sources():
    hashes = {}
    manifests = [ROOT/'Cargo.toml', ROOT/'fuzz/Cargo.toml', *sorted(ROOT.glob('crates/*/Cargo.toml')),
                 *sorted(ROOT.glob('third_party/rust/vendor/*/Cargo.toml')),
                 *sorted(ROOT.glob('third_party/rust/*regressions/Cargo.toml'))]
    for path in manifests:
        raw = input_bytes(path)
        value = tomllib.loads(raw.decode())
        manifest_sources(value, path.parent, sev=path == ROOT/'Cargo.toml')
        if path == ROOT/'Cargo.toml':
            require(value.get('patch') == {'crates-io': PATCHES,
                'https://github.com/virtee/sev': {'sev': {'path': 'third_party/rust/vendor/sev-8.0.0'}}}, 'patches')
        elif path == ROOT/'fuzz/Cargo.toml':
            require(value.get('patch') == {'crates-io': {k: {'path': '../'+v['path']} for k, v in PATCHES.items()}}, 'patches')
        hashes[str(path.relative_to(ROOT))] = digest(raw)
    locks = [ROOT/'Cargo.lock', ROOT/'fuzz/Cargo.lock', *sorted(ROOT.glob('third_party/rust/*regressions/Cargo.lock')),
             *sorted(ROOT.glob('third_party/rust/vendor/*/Cargo.lock'))]
    for path in locks:
        raw = input_bytes(path); lock_sources(raw)
        hashes[str(path.relative_to(ROOT))] = digest(raw)
    config = ROOT/'third_party/rust/backport-regressions/.cargo/config.toml'
    raw = input_bytes(config)
    require(raw == BACKPORT_CONFIG and digest(raw) == BACKPORT_CONFIG_SHA256, 'diagnostic-config')
    hashes[str(config.relative_to(ROOT))] = digest(raw)
    return hashes


@sanitized
def check_graph(manifest):
    raw = input_bytes(manifest)
    manifest_sources(tomllib.loads(raw.decode()), manifest.parent, sev=manifest == ROOT/'Cargo.toml')
    lock_sources(input_bytes(manifest.with_name('Cargo.lock')))


@sanitized
def check_command(arguments, cwd=ROOT):
    # Actual callers choose fixed built-in subcommands. After --, test/compiler
    # arguments have no Cargo source authority.
    options = arguments[:arguments.index('--')] if '--' in arguments else arguments
    require(bool(options) and options[0] in {'fetch', 'test', 'rustc', 'metadata', 'clippy', 'fmt', 'build', 'check'}, 'command-source')
    manifest = cwd/'Cargo.toml'
    for index, argument in enumerate(options):
        require(not argument.startswith(('--config', '--git', '--index', '--registry', '--path', '-Z')), 'command-source')
        if argument == '--manifest-path':
            require(index + 1 < len(options), 'command-source')
            manifest = Path(options[index + 1])
            if not manifest.is_absolute(): manifest = cwd/manifest
        elif argument.startswith('--manifest-path='):
            manifest = Path(argument.split('=', 1)[1])
            if not manifest.is_absolute(): manifest = cwd/manifest
    check_graph(manifest)


def runtime(mode, env):
    require(os.geteuid() != 0, 'location')
    if mode == 'runner':
        require(env.get('GITHUB_ACTIONS') == 'true' and env.get('RUNNER_ENVIRONMENT') == 'github-hosted', 'location')
        parent = Path(env.get('RUNNER_TEMP', ''))
    else:
        require(mode in ('guest', 'alpha-guest'), 'location')
        account = Path('/home/vpci' if mode == 'alpha-guest' else '/home/volparossa')
        require(Path.home() == account and Path('/proc/1/comm').read_text().strip() == 'systemd', 'location')
        release = dict(line.split('=', 1) for line in Path('/etc/os-release').read_text().splitlines() if '=' in line)
        require(release.get('VERSION_ID', '').strip('"') == '13'
                and release.get('ID', '').strip('"') == 'debian', 'location')
        require(subprocess.check_output(['systemd-detect-virt'], text=True).strip() == 'kvm', 'location')
        parent = account/'.local'
    require(parent.is_absolute() and parent.resolve() == parent and parent.is_dir() and not parent.is_symlink(), 'location')
    require(re.fullmatch(r'/[A-Za-z0-9_./-]+', str(parent)), 'location')
    require(parent.stat().st_uid == os.geteuid() and not parent.stat().st_mode & 0o022, 'location')
    return parent


def private_file(path):
    info = path.lstat()
    require(stat.S_ISREG(info.st_mode) and info.st_uid == os.geteuid() and info.st_nlink == 1
            and stat.S_IMODE(info.st_mode) == 0o600 and info.st_size <= 1024*1024, 'context')


def marker_values(home, hashes, mode):
    info = home.lstat()
    origin = json.dumps([str(home), info.st_dev, info.st_ino, info.st_uid], separators=(',', ':')).encode()
    return dict(schema=1, execution_location=mode, policy_sha256=digest(Path(__file__).read_bytes()), source_inputs=hashes,
        config_sha256=digest(CONFIG), origin_sha256=digest(origin), fresh_private_origin=True,
        git_process_policy_sha256=digest(json.dumps(GIT_ENV, sort_keys=True).encode()), git_metadata_https_only=True,
        canonical_public_only=True, registry_authentication=False, ssh_sources=False,
        git_resolved_sources=False, cargo_binary_patched=False)


@sanitized
def validate_active(cwd, env):
    check_environment(env)
    require(all(env.get(name) == value for name, value in GIT_ENV.items()), 'git-process-policy')
    home = Path(env.get('CARGO_HOME', ''))
    require(home.is_absolute() and home.resolve() == home and not home.is_symlink(), 'context')
    info = home.lstat()
    require(stat.S_ISDIR(info.st_mode) and info.st_uid == os.geteuid() and stat.S_IMODE(info.st_mode) == 0o700, 'context')
    for name in (MARKER, 'config.toml'):
        private_file(home/name)
    require(not exists(home/'config'), 'context')
    require((home/'config.toml').read_bytes() == CONFIG, 'context')
    marker = json.loads((home/MARKER).read_text())
    require(isinstance(marker, dict) and marker.get('execution_location') in ('runner', 'guest', 'alpha-guest'), 'context')
    parent = runtime(marker['execution_location'], env)
    require(home.is_relative_to(parent), 'context')
    require(marker == marker_values(home, repository_sources(), marker['execution_location']), 'context')
    check_discovery(cwd, env, home)
    return dict(env)


@sanitized
def activate(mode, *, env=None, home=None, cwd=None, reuse=False):
    env = dict(os.environ if env is None else env)
    cwd = ROOT if cwd is None else cwd
    parent = runtime(mode, env)
    selected = parent/HOME_NAME if home is None else home
    require(selected.is_absolute() and selected.resolve() == selected and selected.is_relative_to(parent), 'context')
    require(re.fullmatch(r'/[A-Za-z0-9_./-]+', str(selected)), 'context')
    if reuse:
        require(env.get('CARGO_HOME') == str(selected), 'context')
        return validate_active(cwd, env)
    check_environment(env)
    inherited = Path(env['CARGO_HOME']) if 'CARGO_HOME' in env else None
    if inherited is not None and exists(inherited/MARKER):
        validate_active(cwd, env)
        check_discovery(cwd, env, inherited)
    else:
        check_discovery(cwd, env)
    hashes = repository_sources()
    require(not exists(selected), 'fresh-home')
    selected.mkdir(mode=0o700)
    for name, raw in (('config.toml', CONFIG), (MARKER, (json.dumps(marker_values(selected, hashes, mode), sort_keys=True)+'\n').encode())):
        with (selected/name).open('xb') as stream: stream.write(raw)
        (selected/name).chmod(0o600)
    env['CARGO_HOME'] = str(selected)
    env.update(GIT_ENV)
    return validate_active(cwd, env)


@sanitized
def write_scope(env, destination, *, cwd=ROOT, graphs=None, tool=None):
    """Bounded public text sidecar, separate from immutable compiler receipts."""
    validate_active(cwd, env)
    require(destination.name in {'cargo-source-policy.json', 'cargo-source-policy-cargo-deny.json',
                                  'cargo-source-policy-cargo-audit.json'}, 'scope-output')
    require(destination.is_absolute() and destination.resolve() == destination
            and destination.parent.is_dir(), 'scope-output')
    record = json.loads((Path(env['CARGO_HOME'])/MARKER).read_text())
    record['scope'] = 'public-source-operating-profile-not-a-cargo-binary-fix'
    record['effective_working_directory_sha256'] = digest(str(cwd).encode())
    record['additional_graphs'] = {}
    for name, manifest in (graphs or {}).items():
        require(name in {'ctutils-upstream', 'ctutils-consumers', 'zbus-upstream'}, 'scope-graph')
        check_graph(manifest)
        record['additional_graphs'][name] = dict(manifest_sha256=digest(input_bytes(manifest)),
                                               lock_sha256=digest(input_bytes(manifest.with_name('Cargo.lock'))))
    if tool is not None:
        require(tool in TOOL_PINS, 'scope-tool')
        version, archive, manifest, lock = TOOL_PINS[tool]
        record['verified_tool_archive'] = dict(name=tool, version=version, archive_sha256=archive,
                                               manifest_sha256=manifest, lock_sha256=lock)
    raw = (json.dumps(record, sort_keys=True)+'\n').encode()
    require(len(raw) <= 65536, 'scope-output')
    if exists(destination):
        private_file(destination)
        require(destination.read_bytes() == raw, 'scope-output')
    else:
        with destination.open('xb') as stream: stream.write(raw)
        destination.chmod(0o600)
    return digest(raw)


@sanitized
def validate_diagnostic(cwd, env):
    """Only the existing owned offline backport copy admits its fixed resolver leaf."""
    validate_active(ROOT, env)
    require(tuple(cwd.parts[-3:]) == ('third_party', 'rust', 'backport-regressions'), 'diagnostic-location')
    scratch = cwd.parents[2]
    require(re.fullmatch(r'volparossa-lock-diagnostic-[a-z0-9_]{8}', scratch.name), 'diagnostic-location')
    info = scratch.lstat()
    require(stat.S_ISDIR(info.st_mode) and info.st_uid == os.geteuid()
            and stat.S_IMODE(info.st_mode) == 0o700, 'diagnostic-location')
    check_discovery(cwd, env, Path(env['CARGO_HOME']), diagnostic=True)
    for filename in ('Cargo.toml', 'Cargo.lock'):
        require(input_bytes(cwd/filename) == input_bytes(ROOT/'third_party/rust/backport-regressions'/filename), 'diagnostic-source')
    for name in ('hickory-proto-0.25.2', 'hickory-resolver-0.25.2', 'libp2p-yamux-0.47.0', 'time-0.3.41'):
        relative = Path('third_party/rust/vendor')/name/'Cargo.toml'
        require(input_bytes(scratch/relative) == input_bytes(ROOT/relative), 'diagnostic-source')
    return dict(env)


@sanitized
def verify_tool_archive(name, raw):
    version, checksum, manifest_hash, lock_hash = TOOL_PINS[name]
    require(len(raw) <= 4*1024**2 and digest(raw) == checksum, 'audit-archive')
    with tarfile.open(fileobj=io.BytesIO(raw), mode='r:gz') as archive:
        values = {}
        for filename in ('Cargo.toml', 'Cargo.lock'):
            selected = [member for member in archive.getmembers() if member.name == name+'-'+version+'/'+filename]
            require(len(selected) == 1 and selected[0].isfile() and selected[0].size <= 1024*1024, 'audit-archive')
            values[filename] = archive.extractfile(selected[0]).read()
    require(digest(values['Cargo.toml']) == manifest_hash and digest(values['Cargo.lock']) == lock_hash, 'audit-archive')
    manifest_sources(tomllib.loads(values['Cargo.toml'].decode()), ROOT, paths=False)
    lock_sources(values['Cargo.lock'])


@sanitized
def audit_tool(name):
    version = TOOL_PINS[name][0]
    # Fixed HTTPS source only. Redirects cannot introduce another registry.
    class NoRedirect(urllib.request.HTTPRedirectHandler):
        def redirect_request(self, *args):
            raise PolicyError('CARGO_PUBLIC_SOURCE_POLICY_V1=audit-origin')
    opener = urllib.request.build_opener(NoRedirect())
    with opener.open('https://static.crates.io/crates/'+name+'/'+name+'-'+version+'.crate', timeout=60) as response:
        raw = response.read(4*1024**2+1)
    verify_tool_archive(name, raw)


@sanitized
def derive_deny_home(destination, env):
    # This is a one-use alias of an already validated fresh origin, never a
    # selector for an arbitrary inherited Cargo cache/config/Git directory.
    validate_active(ROOT, env)
    origin = Path(env['CARGO_HOME'])
    require(destination.is_absolute() and destination.resolve() == destination
            and destination.name == 'cargo-home'
            and re.fullmatch(r'volparossa-rustsec\.[A-Za-z0-9]{6}', destination.parent.name), 'context')
    parent = destination.parent.lstat()
    require(stat.S_ISDIR(parent.st_mode) and parent.st_uid == os.geteuid()
            and stat.S_IMODE(parent.st_mode) == 0o700, 'context')
    require(not exists(destination), 'fresh-home')
    registry = origin/'registry'
    require(registry.is_dir() and not registry.is_symlink(), 'context')
    destination.mkdir(mode=0o700)
    (destination/'config.toml').write_bytes(CONFIG)
    (destination/'config.toml').chmod(0o600)
    (destination/'registry').symlink_to(registry, target_is_directory=True)
    receipt = dict(schema=1, origin_marker_sha256=digest((origin/MARKER).read_bytes()),
                   policy_sha256=digest(Path(__file__).read_bytes()), canonical_public_only=True)
    (destination/'.volparossa-deny-origin-v1.json').write_text(json.dumps(receipt, sort_keys=True)+'\n')
    (destination/'.volparossa-deny-origin-v1.json').chmod(0o600)


def main():
    if len(sys.argv) == 3 and sys.argv[1] == 'deny-home':
        derive_deny_home(Path(sys.argv[2]), os.environ)
        return
    require(sys.argv[1:] == ['check'], 'arguments')
    validate_active(Path.cwd(), os.environ)
    print('CARGO_PUBLIC_SOURCE_POLICY_V1=pass')


if __name__ == '__main__':
    try:
        main()
    except (OSError, ValueError, KeyError, TypeError, AttributeError, RecursionError,
            tarfile.TarError, subprocess.SubprocessError):
        # All failures are closed and sanitized, including library parse errors.
        print('CARGO_PUBLIC_SOURCE_POLICY_V1=rejected', file=sys.stderr)
        raise SystemExit(1) from None
