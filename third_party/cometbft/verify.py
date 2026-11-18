# SPDX-License-Identifier: GPL-3.0-only
"""Offline verification of the verbatim ABCI schema and notice inputs."""
import hashlib
import json
from pathlib import Path, PurePosixPath
import re


def require(condition):
    if not condition:
        raise ValueError('ABCI_UPSTREAM_INPUT_MISMATCH')


def unique(pairs):
    result = {}
    for key, value in pairs:
        require(key not in result)
        result[key] = value
    return result


def verify(root):
    root = Path(root)
    require(root.is_dir() and not root.is_symlink())
    manifest_path = root / 'sources.json'
    require(manifest_path.is_file() and not manifest_path.is_symlink())
    raw = manifest_path.read_bytes()
    require(len(raw) <= 32768)
    manifest = json.loads(raw, object_pairs_hook=unique)
    require(type(manifest) is dict and set(manifest) == {'version', 'scope', 'sources', 'files'})
    require(type(manifest['version']) is int and manifest['version'] == 1)
    require(type(manifest['scope']) is str and len(manifest['scope']) <= 256)
    sources = manifest['sources']
    require(type(sources) is list and len(sources) == 3)
    origins = set()
    for source in sources:
        require(type(source) is dict and set(source) == {
            'id', 'repository', 'revision', 'release', 'license', 'patches'})
        require(source['patches'] == [] and type(source['repository']) is str
                and source['repository'].startswith('https://github.com/'))
        require(type(source['revision']) is str and re.fullmatch('[0-9a-f]{40}', source['revision']))
        pair = source['repository'], source['revision']
        require(pair not in origins)
        origins.add(pair)
    files = manifest['files']
    require(type(files) is list and len(files) == 13)
    expected, byte_count = set(), 0
    for record in files:
        require(type(record) is dict and set(record) == {
            'path', 'repository', 'revision', 'upstream_path', 'git_blob', 'bytes', 'sha256'})
        name = record['path']
        require(type(name) is str and 0 < len(name) <= 160)
        relative = PurePosixPath(name)
        require(not relative.is_absolute() and name == str(relative)
                and '..' not in relative.parts and relative.parts[0] in {'proto', 'vendor', 'licenses'})
        require(name not in expected and (record['repository'], record['revision']) in origins)
        expected.add(name)
        path = root
        for part in relative.parts:
            path = path / part
            require(not path.is_symlink())
        require(path.is_file() and type(record['bytes']) is int and 0 < record['bytes'] <= 65536)
        require(path.stat().st_size == record['bytes'])
        data = path.read_bytes()
        require(len(data) == record['bytes'] and hashlib.sha256(data).hexdigest() == record['sha256'])
        blob = b'blob ' + str(len(data)).encode('ascii') + b'\0' + data
        require(hashlib.sha1(blob, usedforsecurity=False).hexdigest() == record['git_blob'])
        byte_count += len(data)
    observed = set()
    for prefix in ('proto', 'vendor', 'licenses'):
        for path in (root / prefix).rglob('*'):
            require(not path.is_symlink())
            if path.is_file():
                observed.add(path.relative_to(root).as_posix())
            else:
                require(path.is_dir())
    require(observed == expected)
    for name in expected:
        if not name.endswith('.proto'):
            continue
        for imported in re.findall(r'^import\s+"([^"]+)";', (root / name).read_text(), re.MULTILINE):
            require(sum(prefix + '/' + imported in expected for prefix in ('proto', 'vendor')) == 1)
    return dict(version=1, verified_files=len(expected), verified_bytes=byte_count,
                network_access=False, consensus_execution=False)


if __name__ == '__main__':
    print(json.dumps(verify(Path(__file__).resolve().parent), sort_keys=True))
