#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-only
"""Resolve a reviewed Debian guest lock from isolated, authenticated APT lists.

Reads existing lists only, prints package URIs without downloading/installing,
and emits JSON on stdout. Only the exact configuration below is accepted, in a
private caller-owned directory, before any APT process. No host setup is performed.
This resolution record is not evidence of a bootable OS or model execution.
"""
import argparse
from datetime import datetime, timezone
from email.utils import parsedate_to_datetime
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import re
import shlex
import stat
import subprocess
from urllib.parse import unquote

KEYRING = Path('/usr/share/keyrings/debian-archive-keyring.gpg')
RUNTIME = ('busybox-static', 'cryptsetup-bin', 'dmsetup', 'kmod', 'bubblewrap',
           'util-linux', 'coreutils', 'python3.13', 'python3.13-venv', 'libstdc++6',
           'libgomp1', 'libssl3t64')
# The pinned build image already has curl, whose exact libcurl dependency must
# move with the build closure's libcurl4t64; runtime does not select that library.
BUILD = tuple(sorted(set(RUNTIME) | {'build-essential', 'ca-certificates', 'cargo',
    'cmake', 'curl', 'git', 'iproute2', 'nftables', 'pkg-config', 'python3-venv', 'rustc',
    'protobuf-compiler', 'libssl-dev'}))
SOURCES = (
    ('trixie', 'https://deb.debian.org/debian', 'deb.debian.org_debian_dists_trixie'),
    ('trixie-security', 'https://deb.debian.org/debian-security',
     'deb.debian.org_debian-security_dists_trixie-security'),
    ('trixie-updates', 'https://deb.debian.org/debian', 'deb.debian.org_debian_dists_trixie-updates'))
APT_CONFIG_TEMPLATE = '''Dir::Etc "{root}/etc";
Dir::Etc::main "/dev/null";
Dir::Etc::parts "parts";
Dir::Etc::sourcelist "sources.list";
Dir::Etc::sourceparts "sources.list.d";
Dir::Etc::preferences "/dev/null";
Dir::Etc::preferencesparts "parts";
Dir::State "{root}/state";
Dir::State::status "{root}/status";
Dir::Cache "{root}/cache";
Dir::Cache::pkgcache "";
Dir::Cache::srcpkgcache "";
Dir::Log "{root}/log";
Dir::Bin::dpkg "/usr/bin/false";
APT::Architecture "amd64";
APT::Architectures {{ "amd64"; }};
APT::Install-Recommends "false";
APT::Install-Suggests "false";
APT::Get::Download-Only "true";
APT::Get::AllowUnauthenticated "false";
Acquire::AllowInsecureRepositories "false";
Acquire::AllowWeakRepositories "false";
Acquire::Languages "none";
Acquire::Retries "0";
Acquire::https::Timeout "30";
'''


def require(condition, reason):
    if not condition:
        raise ValueError(reason)


def configuration_file(path, maximum):
    with os.fdopen(os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK), 'rb') as stream:
        info = os.fstat(stream.fileno())
        require(stat.S_ISREG(info.st_mode) and info.st_uid == os.geteuid()
                and info.st_nlink == 1 and info.st_size <= maximum, 'apt_configuration_file')
        raw = stream.read(maximum + 1)
        require(len(raw) <= maximum, 'apt_configuration_size')
        return raw


def isolated_configuration(directory):
    """Reject all alternate APT inputs; not a boundary against concurrent same-UID writes."""
    root = str(directory)
    require(directory.is_absolute() and all(ord(c) >= 32 and ord(c) != 127 for c in root)
            and not any(c in root for c in ('"', '\\')), 'apt_configuration_path')
    info = directory.lstat()
    require(stat.S_ISDIR(info.st_mode) and info.st_uid == os.geteuid()
            and stat.S_IMODE(info.st_mode) == 0o700, 'resolution_owner')
    for suffix in ('etc', 'etc/parts', 'etc/sources.list.d', 'state', 'state/lists',
                   'state/lists/partial', 'cache', 'cache/archives', 'cache/archives/partial', 'log'):
        info = (directory / suffix).lstat()
        require(stat.S_ISDIR(info.st_mode) and info.st_uid == os.geteuid(), 'apt_directory')
    config = directory / 'apt.conf'
    # Exact bytes intentionally reject comments, includes, hooks, custom methods,
    # duplicate keys and absolute nested overrides before apt-config can parse them.
    require(configuration_file(config, 16384) == APT_CONFIG_TEMPLATE.format(root=root).encode(),
            'apt_configuration_schema')
    sources = ''.join(f'deb [arch=amd64 signed-by={KEYRING}] {base} {suite} main\n'
                      for suite, base, _ in SOURCES).encode()
    require(configuration_file(directory / 'etc/sources.list', 4096) == sources, 'apt_sources_schema')
    require(configuration_file(directory / 'status', 1) == b'', 'apt_empty_status')
    for suffix in ('etc/parts', 'etc/sources.list.d'):
        require(next((directory / suffix).iterdir(), None) is None, 'apt_config_fragments')
    return config


def fields(text):
    result, key = {}, None
    for line in text.splitlines():
        if line.startswith((' ', '\t')):
            require(key is not None, 'orphan_continuation')
            result[key] += '\n' + line[1:]
        else:
            key, separator, value = line.partition(':')
            require(separator and key and key not in result, 'duplicate_or_invalid_field')
            result[key] = value.strip()
    return result


def release_payload(raw):
    text = raw.decode('utf-8')
    require(text.startswith('-----BEGIN PGP SIGNED MESSAGE-----\n'), 'signed_release_header')
    payload = text.split('\n\n', 1)[1].split('\n-----BEGIN PGP SIGNATURE-----\n', 1)[0]
    return fields('\n'.join(line[2:] if line.startswith('- ') else line for line in payload.splitlines()))


def checked_index(release, raw):
    entries = [line.split() for line in release['SHA256'].splitlines() if line.strip()]
    matches = [item for item in entries if len(item) == 3 and item[2] == 'main/binary-amd64/Packages']
    require(len(matches) == 1, 'index_binding')
    digest, count, _ = matches[0]
    require(re.fullmatch('[0-9a-f]{64}', digest) and count.isdecimal(), 'index_shape')
    require(len(raw) == int(count) <= 128 * 1024 ** 2 and hashlib.sha256(raw).hexdigest() == digest,
            'index_hash')
    return {'path': 'main/binary-amd64/Packages', 'bytes': len(raw), 'sha256': digest}


def package_record(record, suite, base):
    filename = record['Filename']
    path = PurePosixPath(filename)
    require(not path.is_absolute() and '..' not in path.parts and filename.startswith('pool/')
            and str(path) == filename and '\n' not in filename, 'package_path')
    require(re.fullmatch('[a-z0-9][a-z0-9+.-]*', record['Package']) is not None, 'package_name')
    require(record['Architecture'] in ('amd64', 'all') and record['Size'].isdecimal()
            and 0 < int(record['Size']) <= 1024 ** 3
            and re.fullmatch('[0-9a-f]{64}', record['SHA256']), 'package_shape')
    return dict(version=record['Version'], architecture=record['Architecture'], filename=filename,
        url=base + '/' + filename, bytes=int(record['Size']), sha256=record['SHA256'], index=suite,
        depends=record.get('Depends', ''), pre_depends=record.get('Pre-Depends', ''))


def selected_uris(text):
    result = {}
    for line in text.splitlines():
        if not line.startswith("'https://"):
            continue
        parts = shlex.split(line)
        require(len(parts) in (3, 4) and parts[2].isdecimal(), 'uri_shape')
        url = unquote(parts[0])
        require(url not in result, 'uri_duplicate')
        result[url] = int(parts[2])
    require(result and len(result) <= 512, 'uri_count')
    return result


def command(argv, env=None, maximum=16 * 1024 ** 2):
    result = subprocess.run(argv, env=env, check=True, capture_output=True, timeout=90)
    require(len(result.stdout) <= maximum and len(result.stderr) <= 1024 ** 2, 'command_output')
    return result.stdout


def resolve(directory):
    directory = directory.resolve(strict=True)
    config = isolated_configuration(directory)
    env = dict(os.environ, APT_CONFIG=str(config), LC_ALL='C', LANG='C')
    configuration = command(['/usr/bin/apt-config', 'dump'], env).decode()
    for key, suffix in (('Dir::State', '/state'), ('Dir::Cache', '/cache'),
                        ('Dir::Etc', '/etc'), ('Dir::Log', '/log'),
                        ('Dir::State::status', '/status')):
        require(f'{key} "{directory}{suffix}";' in configuration, 'apt_path_isolation')
    for setting in ('Dir::Etc::main "/dev/null";', 'Dir::Etc::parts "parts";',
                    'Dir::Bin::dpkg "/usr/bin/false";', 'APT::Get::Download-Only "true";',
                    'APT::Get::AllowUnauthenticated "false";', 'APT::Architecture "amd64";'):
        require(setting in configuration, 'apt_execution_guard')
    require((directory / 'status').read_bytes() == b'', 'apt_empty_status')
    require(not list((directory / 'etc/parts').iterdir()), 'apt_config_fragments')
    selections = {name: selected_uris(command(['/usr/bin/apt-get', '--print-uris', '--download-only',
        '--no-install-recommends', '--yes', '--no-remove', 'install', *roots], env).decode())
        for name, roots in (('runtime', RUNTIME), ('build', BUILD))}
    wanted = set().union(*(set(value) for value in selections.values()))
    matched, sources = {}, {}
    now = datetime.now(timezone.utc)
    for suite, base, prefix in SOURCES:
        signed = directory / 'state/lists' / (prefix + '_InRelease')
        raw_release = signed.read_bytes()
        status = command(['gpgv', '--status-fd', '1', '--keyring', str(KEYRING), str(signed)]).decode()
        signers = re.findall(r'^\[GNUPG:\] VALIDSIG ([0-9A-F]{40,64}) ', status, re.M)
        require(signers, 'release_signature')
        release = release_payload(raw_release)
        require(release['Origin'] == 'Debian' and release['Codename'] == suite, 'release_identity')
        require(parsedate_to_datetime(release['Date']) <= now, 'future_release')
        if 'Valid-Until' in release:
            require(now < parsedate_to_datetime(release['Valid-Until']), 'expired_release')
        index_path = directory / 'state/lists' / (prefix + '_main_binary-amd64_Packages')
        raw_index = index_path.read_bytes()
        index = checked_index(release, raw_index)
        sources[suite] = dict(base_url=base, suite=suite, component='main', index=index,
            release_url=base + '/dists/' + suite + '/InRelease',
            inrelease_sha256=hashlib.sha256(raw_release).hexdigest(), inrelease_bytes=len(raw_release),
            valid_signers=sorted(set(signers)), date=release['Date'], valid_until=release.get('Valid-Until'))
        for stanza in raw_index.decode('utf-8').strip().split('\n\n'):
            record = fields(stanza)
            url = base + '/' + record.get('Filename', '')
            if url not in wanted:
                continue
            package = package_record(record, suite, base)
            require(url not in matched or matched[url][1]['sha256'] == package['sha256'], 'ambiguous_package')
            matched.setdefault(url, (record['Package'], package))
    require(set(matched) == wanted, 'unmatched_selected_package')
    profiles, packages = {}, {}
    for profile, selection in selections.items():
        names = []
        for url, count in selection.items():
            name, package = matched[url]
            require(package['bytes'] == count, 'selected_package_size')
            require(name not in packages or packages[name] == package, 'profile_version_conflict')
            packages[name] = package
            names.append(name)
        require(len(names) == len(set(names)), 'profile_package_duplicate')
        profiles[profile] = dict(roots=list(RUNTIME if profile == 'runtime' else BUILD), packages=sorted(names))
    require((directory / 'status').read_bytes() == b'', 'host_package_state_changed')
    require(not list((directory / 'cache/archives').glob('*.deb')), 'unexpected_package_download')
    return dict(version=1, kind='protected-resident-debian-package-lock', architecture='amd64',
        resolved_at=now.isoformat(), apt_version=command(['/usr/bin/apt-get', '--version'], env).decode().splitlines()[0],
        empty_status=True, install_recommends=False, profiles=profiles, sources=sources,
        trusted_keyring_sha256=hashlib.sha256(KEYRING.read_bytes()).hexdigest(),
        packages=dict(sorted(packages.items())), packages_downloaded=False, host_installation=False,
        guest_boot=False, model_execution=False)


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('isolated_apt_directory', type=Path)
    args = parser.parse_args()
    print(json.dumps(resolve(args.isolated_apt_directory), sort_keys=True, indent=2))
