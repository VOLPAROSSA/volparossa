#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-only
"""Recover the exact public Browser checkpoint produced by hosted run 45517799338."""
import hashlib
import io
import json
from pathlib import Path
import runpy
import sys
from zipfile import ZipFile

PEER = runpy.run_path(str(Path(__file__).with_name('public-peer-recovery.py')))
require = PEER['require']
NAME = 'degoog-public-browser-documents'
ARCHIVE_SHA = '4e50894f929421797406bd5b600636a2d2cec443f1f02875ac2ad045f8a11712'
INDEX_SHA = '7ec92c63b697c290d7634027be4e41e2eaab237459100782910183dd62fe12e3'
INDEX_SIZE = 45056
UPSTREAM = '1f7d2f172aad3ed5e5a69aa227b384573203742c'


def read_index(stream):
    raw = stream.read(2047)
    require(len(raw) == 2046 and hashlib.sha256(raw).hexdigest() == ARCHIVE_SHA,
            'unexpected public Browser checkpoint archive')
    with ZipFile(io.BytesIO(raw)) as archive:
        require(sorted(archive.namelist()) == ['degoog-result.json', 'index.db'], 'unexpected checkpoint members')
        contents = archive.read('index.db')
        require(len(contents) == INDEX_SIZE and hashlib.sha256(contents).hexdigest() == INDEX_SHA,
                'unexpected enrolled index content')
        require(json.loads(archive.read('degoog-result.json')) == {
            'restored': {'urls': 3, 'hits': 3}, 'known_queries': 3, 'unmatched_queries': 1,
            'external_requests': 0, 'snapshot_sha256': INDEX_SHA, 'snapshot_bytes': INDEX_SIZE,
            'corrupt_copy_rejected': True, 'producer_state_removed': True, 'source_revision': UPSTREAM,
        }, 'original Browser receipt differs')
    return contents


def make_source(source):
    with sys.stdin.buffer as stream:
        contents = read_index(stream)
    artifact = source / 'index.db'
    artifact.write_bytes(contents)
    return artifact


def inspect_download(_root, downloaded, sha):
    require(sha == INDEX_SHA and downloaded.stat().st_size == INDEX_SIZE
            and PEER['digest'](downloaded) == INDEX_SHA, 'delivered index differs from Browser enrollment')


def verify_host(receipt, topology, source, output):
    require(receipt['sha256'] == INDEX_SHA and receipt['downloaded_bytes'] == INDEX_SIZE
            and len(receipt['received']) == INDEX_SIZE * 2, 'download differs from enrolled Browser checkpoint')
    contents = bytes.fromhex(receipt['received'])
    PEER['verify_peer'](receipt, topology, source, NAME, contents, INDEX_SHA)
    with output.open('xb') as destination:
        destination.write(contents)


if __name__ == '__main__':
    if sys.argv[1] == 'verify-host':
        receipt, topology, source, output = sys.argv[2:]
        require(Path(receipt).stat().st_size <= 131072, 'oversized public index receipt')
        verify_host(json.loads(Path(receipt).read_bytes()), json.loads(Path(topology).read_bytes()), source, Path(output))
    else:
        cli, control, parent, cache, key, peer = sys.argv[1:]
        print(json.dumps(PEER['recover'](cli, control, Path(parent), Path(cache), key, peer,
                                         NAME, make_source, inspect_download)))
