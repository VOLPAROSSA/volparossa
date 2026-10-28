#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-only
"""Hosted-only compilation. No GPSD/native test execution or system installation."""
import argparse
import hashlib
import os
from pathlib import Path
import shutil
import tarfile
import time
import urllib.request

from common import (clean_environment, command, digest, hosted, pins,
                    private_directory, source_binding, write_json)

OPTIONS = ['-j2',
           'xgps=no', 'qt=no', 'ncurses=no', 'libgpsmm=no', 'dbus_export=no',
           'bluez=no', 'usb=no', 'systemd=no', 'shm_export=no', 'magic_hat=no',
           'timeservice=no', 'manbuild=no', 'shared=no', 'debug=yes', 'nostrip=yes']
SANITIZERS = '-O1 -g -fsanitize=address,undefined -fno-sanitize-recover=all -fno-omit-frame-pointer'
PYTHON_CARRIER = '''#!/usr/bin/python3
# SPDX-License-Identifier: GPL-3.0-only
# Fixed private carrier: GPSD's SCons environment drops inherited PYTHONPATH.
import os
from pathlib import Path
import runpy
import site
import sys
support = str(Path(__file__).resolve().parent / 'support/usr/lib/python3/dist-packages')
sys.dont_write_bytecode = True
sys.path.insert(0, support)
site.addsitedir(support)
os.environ['PYTHONPATH'] = support
os.environ['PYTHONDONTWRITEBYTECODE'] = '1'
os.environ['PYTHONNOUSERSITE'] = '1'
sys.argv = sys.argv[1:]
if not sys.argv:
    raise SystemExit('fixed GPSD Python carrier requires a script')
if sys.argv[0] in ('-V', '--version'):
    print(sys.version)
elif sys.argv == ['-tt', '-m', 'py_compile', 'tmp.py']:
    # Exact mandatory GPSD python-compilation-regress invocation. Python3
    # already rejects inconsistent indentation; compile without executing input.
    import py_compile
    py_compile.compile('tmp.py', doraise=True)
elif sys.argv[0] == '-c' and len(sys.argv) >= 2:
    code = sys.argv[1]
    sys.argv = ['-c', *sys.argv[2:]]
    exec(compile(code, '<gpsd-helper>', 'exec'), {'__name__': '__main__'})
elif sys.argv[0].startswith('-'):
    raise SystemExit('unsupported GPSD Python carrier interpreter arguments')
else:
    path = str(Path(sys.argv[0]).resolve())
    sys.path.insert(0, str(Path(path).parent))
    runpy.run_path(path, run_name='__main__')
'''


def build_options(prefix):
    return [*OPTIONS, 'target_python=' + str(prefix / 'python')]


def build_environment():
    return dict(clean_environment(), CC='/usr/bin/clang', CXX='/usr/bin/clang++', SHLINK='/usr/bin/clang')


def download(item, directory, deadline):
    destination = directory / Path(item['url']).name
    total = 0
    value = hashlib.sha256()
    with urllib.request.urlopen(item['url'], timeout=min(30, max(1, deadline-time.monotonic()))) as response:
        if response.geturl() != item['url']:
            raise ValueError('unreviewed source/package redirect')
        with destination.open('xb') as output:
            os.chmod(destination, 0o600)
            while chunk := response.read(64 * 1024):
                total += len(chunk)
                if total > item['size'] or time.monotonic() >= deadline:
                    raise ValueError('source/package exceeded byte/time bound')
                value.update(chunk)
                output.write(chunk)
    if total != item['size'] or value.hexdigest() != item['sha256']:
        raise ValueError('source/package differs from fixed SHA256 authority')
    return destination


def unpack(archive_path, destination, expected_root):
    """No links/devices, traversal, duplicate paths, or unbounded expansion."""
    with tarfile.open(archive_path) as archive:
        members = archive.getmembers()
        if len(members) > 1024 or sum(m.size for m in members) > 64 * 1024 * 1024:
            raise ValueError('source archive expansion bound')
        seen = set()
        for member in members:
            path = Path(member.name)
            if (path.is_absolute() or '..' in path.parts or not path.parts or
                    path.parts[0] != expected_root or member.name in seen or
                    not (member.isfile() or member.isdir())):
                raise ValueError('unsafe source archive member')
            seen.add(member.name)
        for member in members:
            target = destination / member.name
            if member.isdir():
                target.mkdir(mode=0o700, parents=True, exist_ok=True)
            else:
                target.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
                with archive.extractfile(member) as source, target.open('xb') as output:
                    shutil.copyfileobj(source, output, 64 * 1024)
                os.chmod(target, 0o700 if member.mode & 0o111 else 0o600)


def tree_hash(directory):
    result = hashlib.sha256()
    for path in sorted(directory.rglob('*')):
        if path.is_symlink():
            if directory not in path.resolve().parents:
                raise ValueError('support/source link escapes its private tree')
            result.update(str(path.relative_to(directory)).encode() + b'\0L' + os.readlink(path).encode())
            continue
        if path.is_file():
            result.update(str(path.relative_to(directory)).encode() + b'\0')
            result.update(bytes.fromhex(digest(path)))
    return result.hexdigest()


def build(evidence, revision):
    hosted()
    source = source_binding(revision)
    evidence = private_directory(evidence)
    metadata = pins()
    prefix = private_directory(Path(os.environ['RUNNER_TEMP']) / ('dps-gpsd-' + revision[:12]), create=True)
    deadline = time.monotonic() + 600
    report = {'schema_version': 1, 'status': 'failed', 'source': source,
              'source_version': metadata['version'], 'prefix': str(prefix),
              'gpsd_native_execution': False, 'upstream_tests_executed': False,
              'sanitizer_execution': False, 'system_installation': False}
    step = 'download'
    try:
        downloads = prefix / 'downloads'
        downloads.mkdir(mode=0o700)
        files = {item['file']: download(item, downloads, deadline) for item in metadata['sources']}
        support = prefix / 'support'
        support.mkdir(mode=0o700)
        env = build_environment()
        for item in metadata['support_packages']:
            archive = download(item, downloads, deadline)
            command(['/usr/bin/dpkg-deb', '--extract', str(archive), str(support)],
                    cwd=prefix, env=env, deadline=deadline,
                    log_path=evidence / (item['package'] + '-extract.log'), limit=65536)
        env['PYTHONPATH'] = str(support / 'usr/lib/python3/dist-packages')
        carrier = prefix / 'python'
        carrier.write_text(PYTHON_CARRIER)
        os.chmod(carrier, 0o700)
        scons = support / 'usr/bin/scons'
        report['support_packages'] = metadata['support_packages']
        report['support_tree_sha256'] = tree_hash(support)
        report['python_carrier'] = {'path': str(carrier), 'sha256': digest(carrier)}
        step = 'prepare-full-debian-series'
        unpack(files['gpsd_3.25.orig.tar.gz'], prefix, 'gpsd-3.25')
        normal = prefix / 'gpsd-3.25'
        unpack(files['gpsd_3.25-5+deb13u2.debian.tar.xz'], normal, 'debian')
        expected_series = [Path(item['path']).name for item in metadata['series']]
        if (normal / 'debian/patches/series').read_text().splitlines() != expected_series:
            raise ValueError('full Debian series differs')
        for index, item in enumerate(metadata['series']):
            patch = normal / item['path']
            if digest(patch) != item['sha256']:
                raise ValueError('Debian patch hash differs')
            command(['/usr/bin/patch', '--batch', '--forward', '--fuzz=0', '-p1', '-i', str(patch)],
                    cwd=normal, env=env, deadline=deadline,
                    log_path=evidence / ('patch-' + str(index) + '.log'), limit=65536)
        report['patched_source_tree_sha256'] = tree_hash(normal)
        sanitized = prefix / 'sanitized'
        shutil.copytree(normal, sanitized)
        step = 'record-existing-host-tools'
        report['compiler_files'] = {}
        for name in ('clang', 'clang++'):
            executable = Path('/usr/bin', name).resolve(strict=True)
            report['compiler_files'][name] = {'path': str(executable), 'sha256': digest(executable)}
        for label, argv in [('clang', ['/usr/bin/clang', '--version']),
                            ('python', ['/usr/bin/python3', '--version']),
                            ('scons', [str(carrier), str(scons), '--version']),
                            ('base-packages', ['/usr/bin/dpkg-query', '-W', '-f=${binary:Package}\t${Version}\n',
                                               'python3', 'libc6:amd64', 'dpkg', 'patch'])]:
            command(argv, cwd=prefix, env=env, deadline=deadline,
                    log_path=evidence / (label + '.log'), limit=65536)
        step = 'compile-normal'
        command([str(carrier), str(scons), *build_options(prefix), 'python=yes', 'build-all'],
                cwd=normal, env=env, deadline=deadline, log_path=evidence / 'build-normal.log')
        step = 'compile-address-undefined-sanitizers'
        sanitized_env = dict(env, CFLAGS=SANITIZERS, CXXFLAGS=SANITIZERS,
                             LDFLAGS='-fsanitize=address,undefined')
        command([str(carrier), str(scons), *build_options(prefix), 'python=no', 'build'],
                cwd=sanitized, env=sanitized_env, deadline=deadline,
                log_path=evidence / 'build-sanitized.log')
        report['binaries'] = {}
        for kind, directory in [('normal', normal), ('sanitized', sanitized)]:
            variant = directory / 'gpsd-3.25'
            row = {'source_directory': str(directory), 'variant_directory': str(variant)}
            for name, relative in [('gpsd', 'gpsd/gpsd'), ('gpspipe', 'clients/gpspipe')]:
                path = variant / relative
                if kind == 'sanitized':
                    raw = path.read_bytes()
                    if b'__asan_init' not in raw or b'__ubsan_handle' not in raw:
                        raise ValueError('native binary lacks both sanitizer symbol families')
                row[name] = {'path': str(path), 'sha256': digest(path)}
            report['binaries'][kind] = row
        report['scons'] = str(scons)
        report['build_options'] = build_options(prefix)
        report['compiler_environment'] = {key: env[key] for key in ('CC', 'CXX', 'SHLINK')}
        report['sanitizer_flags'] = SANITIZERS
        report['status'] = 'compiled_only'
        step = 'complete'
    finally:
        report['phase'] = step
        write_json(evidence / 'build-receipt.json', report)


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--evidence-dir', required=True, type=Path)
    parser.add_argument('--source-revision', required=True)
    args = parser.parse_args()
    build(args.evidence_dir, args.source_revision)
