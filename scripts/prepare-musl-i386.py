#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-only
"""Fixed Debian musl-dev data input, never a package install or host activation."""
import hashlib
import io
import json
import lzma
import os
from pathlib import Path, PurePosixPath
import re
import struct
import tarfile
import urllib.parse
import urllib.request

PINS = Path(__file__).with_name('musl-i386-input.json')
PINS_SHA256 = '9e8e31d579c4a41242cf5d436351a5340ac8f05533359920f8a52d6b9003a739'
ARCHIVE_SHA256 = '7c6500215eeb2d7479f238969b8e38daafc23d5c746044764a47c80bfe24415f'
SPEC_SHA256 = '33bdd08bcecd6366f2ed9e141b42a48be0332dbdcc70ca6aac45e26f35bb997f'
PROBE = b'''#include <stdint.h>
#include <stdio.h>
int main(void) {
    uint64_t value = UINT64_C(0x123456789) * 7;
    if (sizeof(void *) != 4 || value != UINT64_C(34207028415)) return 1;
    return puts("musl-i386-static") < 0;
}
'''


def pins():
    raw = PINS.read_bytes()
    if hashlib.sha256(raw).hexdigest() != PINS_SHA256:
        raise ValueError('musl input pins changed')
    return json.loads(raw)


def package_files(raw, expected):
    if len(raw) != 618216 or hashlib.sha256(raw).hexdigest() != ARCHIVE_SHA256:
        raise ValueError('musl archive identity')
    if not raw.startswith(b'!<arch>\n'):
        raise ValueError('musl ar header')
    members, offset = {}, 8
    while offset < len(raw):
        header = raw[offset:offset + 60]
        if len(header) != 60 or header[58:] != b'`\n':
            raise ValueError('musl ar member')
        name = header[:16].decode('ascii').strip().removesuffix('/')
        size = int(header[48:58])
        if name in members or size < 0 or offset + 60 + size > len(raw):
            raise ValueError('musl ar size/duplicate')
        members[name] = raw[offset + 60:offset + 60 + size]
        offset += 60 + size + size % 2
    if offset != len(raw) or set(members) != {'debian-binary', 'control.tar.xz', 'data.tar.xz'} or members['debian-binary'] != b'2.0\n':
        raise ValueError('musl ar inventory')
    decoder = lzma.LZMADecompressor()
    unpacked = decoder.decompress(members['data.tar.xz'], max_length=8 * 1024**2 + 1)
    if len(unpacked) > 8 * 1024**2 or not decoder.eof or decoder.unused_data:
        raise ValueError('musl decompression bound')
    return tar_files(unpacked, expected)


def tar_files(raw, expected):
    inventory, files, total = {}, {}, 0
    with tarfile.open(fileobj=io.BytesIO(raw), mode='r:') as source:
        for entry in source:
            name = entry.name
            path = PurePosixPath(name)
            if path.is_absolute() or '..' in path.parts or name in inventory or entry.linkname or not (entry.isfile() or entry.isdir()):
                raise ValueError('musl unsafe member')
            if len(inventory) >= 256 or entry.size < 0 or entry.size > 8 * 1024**2 or entry.mode & 0o7000:
                raise ValueError('musl member bound/mode')
            total += entry.size
            if total > 8 * 1024**2:
                raise ValueError('musl total bound')
            item = dict(path=name, bytes=entry.size, kind='0' if entry.isfile() else '5', target='')
            if entry.isfile():
                data = source.extractfile(entry).read(entry.size + 1)
                if len(data) != entry.size: raise ValueError('musl member size')
                item['sha256'] = hashlib.sha256(data).hexdigest()
                files[str(path)] = data
            inventory[name] = item
    if list(inventory.values()) != expected:
        raise ValueError('musl closed inventory changed')
    return files


def stage(raw, prefix):
    expected = pins()
    files = package_files(raw, expected['files'])  # Complete validation before any write.
    if not prefix.is_absolute() or prefix.resolve() != prefix or prefix.exists() or prefix.is_symlink():
        raise ValueError('musl prefix must be fresh and canonical')
    prefix.mkdir(mode=0o700)
    for name, data in files.items():
        path = prefix / name
        parent = prefix
        for part in Path(name).parts[:-1]:
            parent /= part
            parent.mkdir(mode=0o700, exist_ok=True)
        with path.open('xb') as stream: stream.write(data)
        path.chmod(0o600)
    original = files['usr/lib/i386-linux-musl/musl-gcc.specs']
    if hashlib.sha256(original).hexdigest() != SPEC_SHA256:
        raise ValueError('musl original specs')
    # Only these two original absolute include/library prefixes are relocated.
    adapted = original.decode().replace('/usr/include/i386-linux-musl', str(prefix / 'usr/include/i386-linux-musl')).replace('/usr/lib/i386-linux-musl', str(prefix / 'usr/lib/i386-linux-musl'))
    specs = prefix / 'musl-gcc.specs'
    with specs.open('x') as stream: stream.write(adapted)
    specs.chmod(0o600)
    wrapper = prefix / 'musl-gcc'
    with wrapper.open('x') as stream:
        stream.write('#!/bin/sh\nexec /usr/bin/gcc "$@" -m32 -static -specs="' + str(specs) + '"\n')
    wrapper.chmod(0o700)
    return dict(package=expected['package'], version=expected['version'], architecture='i386',
        archive=expected['archive'], inrelease_sha256=expected['inrelease_sha256'],
        index_sha256=expected['index_sha256'], files=len(files),
        original_specs_sha256=SPEC_SHA256, adapted_specs_sha256=hashlib.sha256(adapted.encode()).hexdigest(),
        wrapper_sha256=hashlib.sha256(wrapper.read_bytes()).hexdigest(),
        probe_source_sha256=hashlib.sha256(PROBE).hexdigest(), package_installed=False)


class SnapshotRedirect(urllib.request.HTTPRedirectHandler):
    max_redirections = 3
    def redirect_request(self, req, fp, code, msg, headers, url):
        value = urllib.parse.urlsplit(url)
        if value.scheme != 'https' or value.netloc != 'snapshot.debian.org' or value.query or value.fragment:
            raise ValueError('musl snapshot redirect')
        return super().redirect_request(req, fp, code, msg, headers, url)


def static_i386(raw):
    if len(raw) < 52 or raw[:7] != b'\x7fELF\x01\x01\x01' or struct.unpack_from('<H', raw, 18)[0] != 3:
        raise ValueError('musl probe not ELF32/i386')
    offset, = struct.unpack_from('<I', raw, 28)
    size, count = struct.unpack_from('<HH', raw, 42)
    if size != 32 or not 0 < count <= 64 or offset + size * count > len(raw):
        raise ValueError('musl probe program headers')
    if any(struct.unpack_from('<I', raw, offset + i * size)[0] == 3 for i in range(count)):
        raise ValueError('musl probe must have no interpreter')


def prepare(prefix, output, run):
    # The caller's hosted/revision guard precedes all package/compiler operations.
    # No caller URL, compiler, prefix override or captured digest is authority.
    revision = os.environ.get('GITHUB_SHA', '')
    if (os.environ.get('GITHUB_ACTIONS') != 'true' or os.environ.get('RUNNER_ENVIRONMENT') != 'github-hosted'
            or not re.fullmatch('[0-9a-f]{40}', revision)
            or os.environ.get('CTUTILS_CORE_REVISION') != revision or os.getuid() == 0):
        raise ValueError('musl requires exact assigned hosted revision')
    fixed = Path(os.environ['RUNNER_TEMP']) / 'ctutils-musl-i386'
    if prefix != fixed or not re.fullmatch(r'/[A-Za-z0-9_./-]+', str(prefix)):
        raise ValueError('musl fixed prefix')
    opener = urllib.request.build_opener(SnapshotRedirect())
    with opener.open(pins()['archive']['url'], timeout=60) as response:
        raw = response.read(1024**2 + 1)
    receipt = stage(raw, prefix)
    source = prefix / 'probe.c'; source.write_bytes(PROBE); source.chmod(0o600)
    binary = prefix / 'probe'
    run(['/usr/bin/gcc', '--version'], 'musl-gcc-version')
    run([str(prefix / 'musl-gcc'), str(source), '-o', str(binary)], 'musl-probe-compile')
    if binary.is_symlink() or not 0 < binary.stat().st_size <= 1024**2:
        raise ValueError('musl probe binary bound')
    data = binary.read_bytes(); static_i386(data)
    run([str(binary)], 'musl-probe-execute')
    if (output / 'musl-probe-execute.log').read_bytes() != b'musl-i386-static\n':
        raise ValueError('musl actual C probe result')
    receipt.update(static_i386_probe_passed=True, probe_binary_sha256=hashlib.sha256(data).hexdigest())
    (output / 'musl-input.log').write_text(json.dumps(receipt, sort_keys=True) + '\n')
    return receipt
