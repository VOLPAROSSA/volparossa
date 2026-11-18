#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-only
"""Inert exact-package notice tests; never invokes Cargo or a compiler.

Archives must already be present in Cargo's cache, or in --archive-directory.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import tarfile
import tempfile
import tomllib

from notice_test_fixtures import graph_fixture

ROOT = Path(__file__).resolve().parents[1]
NAMES = {'libp2p-gossipsub', 'libp2p-metrics', 'libp2p-upnp', 'prometheus-client-derive-encode',
         'r-efi', 'valuable'}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--archive-directory', type=Path)
    args = parser.parse_args()
    packages = tomllib.loads((ROOT / 'Cargo.lock').read_text())['package']
    rows = [line.split('\t') for line in
            (ROOT / 'third_party/rust/licenses/registry-fallbacks.tsv').read_text().splitlines()
            if not line.startswith('#') and line.split('\t')[0] in NAMES]
    assert len(rows) == 7
    cases = 0
    for name, version, license_expression, commit, directory, checksum, vcs_path in rows:
        package = next(p for p in packages if p['name'] == name and p['version'] == version)
        assert package['checksum'] == checksum
        if args.archive_directory:
            archive = args.archive_directory / f'{name}-{version}.crate'
        else:
            cargo_home = Path(os.environ.get('CARGO_HOME', Path.home() / '.cargo'))
            archives = list((cargo_home / 'registry/cache').glob(f'*/{name}-{version}.crate'))
            assert len(archives) == 1, f'exact cached archive required: {name} {version}'
            archive = archives[0]
        data = archive.read_bytes()
        assert hashlib.sha256(data).hexdigest() == checksum
        with tarfile.open(archive, 'r:gz') as published:
            vcs = json.load(published.extractfile(f'{name}-{version}/.cargo_vcs_info.json'))
        assert vcs['git']['sha1'] == commit
        assert vcs['path_in_vcs'] == ('' if vcs_path == '.' else vcs_path)
        if name == 'libp2p-gossipsub':
            provenance = json.loads((ROOT / 'third_party/rust/licenses/registry-fallback/full-notice-provenance.json').read_text())
            binding = next(p for p in provenance if p['package'] == f'{name}-{version}')
            with tarfile.open(archive, 'r:gz') as published:
                sources = {p.name.split('/', 1)[1] for p in published.getmembers()
                           if p.isfile() and p.name.endswith('.rs')}
                assert sources == {p['archive_path'] for p in binding['files']}
                for original in binding['files']:
                    data_in_archive = published.extractfile(f'{name}-{version}/' + original['archive_path']).read()
                    stored = ROOT / 'third_party/rust/licenses/registry-fallback' / directory / original['notice_file']
                    assert stored.read_bytes() == data_in_archive
                    assert hashlib.sha256(data_in_archive).hexdigest() == original['sha256']
        for mutation in ('none', 'archive', 'missing-archive', 'vcs', 'vcs-path',
                         'name', 'version', 'license', 'source', 'notice'):
            with tempfile.TemporaryDirectory(prefix='full-notice-test-') as temporary:
                base = Path(temporary)
                # Isolate notice tampering; the real vendor verifier is independently
                # covered by the enclosing packaging test, not replaced in production.
                repo = base / 'repo'
                (repo / 'packaging').mkdir(parents=True)
                shutil.copyfile(ROOT / 'packaging/cargo-notice-closure.py',
                                repo / 'packaging/cargo-notice-closure.py')
                shutil.copyfile(ROOT / 'packaging/collect-cargo-licenses.sh',
                                repo / 'packaging/collect-cargo-licenses.sh')
                (repo / 'scripts').mkdir()
                verifier = repo / 'scripts/check-rust-dependencies.sh'
                verifier.write_text('#!/bin/sh\n[ "$#" = 1 ] && [ "$1" = --verify-vendor-only ]\n')
                verifier.chmod(0o755)
                shutil.copytree(ROOT / 'third_party/rust/licenses', repo / 'third_party/rust/licenses')
                if mutation == 'notice':
                    notice_dir = repo / 'third_party/rust/licenses/registry-fallback' / directory
                    notice = next(p for p in notice_dir.iterdir() if p.name != 'SHA256SUMS')
                    notice.write_bytes(notice.read_bytes() + b'\nchanged\n')
                source = base / 'registry/src/test-index' / f'{name}-{version}'
                source.mkdir(parents=True)
                (source / 'Cargo.toml').write_text('')
                observed = json.loads(json.dumps(vcs))
                if mutation == 'vcs':
                    observed['git']['sha1'] = '0' * 40
                if mutation == 'vcs-path':
                    observed['path_in_vcs'] += '-unexpected'
                (source / '.cargo_vcs_info.json').write_text(json.dumps(observed))
                cache = base / 'registry/cache/test-index'
                cache.mkdir(parents=True)
                if mutation != 'missing-archive':
                    (cache / archive.name).write_bytes(b'corrupt' if mutation == 'archive' else data)
                selected = dict(id='test', name=name, version=version, license=license_expression,
                                license_file=None, manifest_path=str(source / 'Cargo.toml'),
                                source='registry+https://github.com/rust-lang/crates.io-index')
                if mutation in ('name', 'version', 'license'):
                    selected[mutation] += '-unreviewed'
                if mutation == 'source':
                    selected['source'] = 'registry+https://github.com/rust-lang/crates.io-index-unreviewed'
                metadata = base / 'metadata.json'
                metadata.write_text(json.dumps(graph_fixture([selected])))
                result = subprocess.run(['sh', str(repo / 'packaging/collect-cargo-licenses.sh'),
                                         str(metadata), str(base / 'notices')],
                                        text=True, capture_output=True, check=False)
                assert (result.returncode == 0) == (mutation == 'none'), (name, version, mutation, result.stderr)
                if mutation == 'none':
                    notices = ROOT / 'third_party/rust/licenses/registry-fallback' / directory
                    for notice in notices.iterdir():
                        if notice.name != 'SHA256SUMS':
                            assert (base / 'notices' / f'{name}-{version}' / notice.name).read_bytes() == notice.read_bytes()
                cases += 1
    # Existing basename patterns are case-insensitive; preserve original filenames/bytes.
    for basename, accepted in [('license-mit', True), ('LiCeNsE.ApAcHe', True),
                               ('notice', True), ('CoPyInG-extra', True),
                               ('LICENSE_unmatched', False), ('not-a-license', False)]:
        with tempfile.TemporaryDirectory(prefix='notice-basename-test-') as temporary:
            base = Path(temporary)
            source = base / 'source'
            source.mkdir()
            (source / basename).write_bytes(b'unchanged original notice fixture\n')
            metadata = base / 'metadata.json'
            metadata.write_text(json.dumps(graph_fixture([dict(
                id='fixture', name='notice-fixture', version='1.0.0', license='MIT',
                license_file=None, manifest_path=str(source / 'Cargo.toml'),
                source='registry+https://github.com/rust-lang/crates.io-index') ])))
            result = subprocess.run(['sh', str(ROOT / 'packaging/collect-cargo-licenses.sh'),
                                     str(metadata), str(base / 'notices')],
                                    text=True, capture_output=True, check=False)
            assert (result.returncode == 0) == accepted, (basename, result.stderr)
            if accepted:
                assert (base / 'notices/notice-fixture-1.0.0' / basename).read_bytes() == (source / basename).read_bytes()
            cases += 1
    print(f'PASS {cases} exact archive/source/package/VCS/path/original-notice cases; no Cargo execution')


if __name__ == '__main__':
    main()
