#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-only
"""Exercise the exact JNI notice fallbacks with real locked source archives."""
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import tempfile

from notice_test_fixtures import graph_fixture

ROOT = Path(__file__).resolve().parents[1]
metadata = json.loads(subprocess.check_output(['cargo', 'metadata', '--locked', '--offline', '--format-version', '1'], cwd=ROOT))
for name, version in (('jni', '0.22.4'), ('jni-macros', '0.22.4'), ('jni-sys-macros', '0.4.1')):
    package = next(p for p in metadata['packages'] if p['name'] == name and p['version'] == version)
    source = Path(package['manifest_path']).parent
    archive = source.parents[2] / 'cache' / source.parent.name / (name + '-' + version + '.crate')
    for mutation in ('none', 'archive', 'vcs', 'version', 'license'):
        with tempfile.TemporaryDirectory(prefix='jni-license-') as temporary:
            base = Path(temporary); clone = base / 'registry/src/test-index' / source.name
            clone.mkdir(parents=True)
            (clone / 'Cargo.toml').write_text('')
            vcs = json.loads((source / '.cargo_vcs_info.json').read_text())
            if mutation == 'vcs': vcs['git']['sha1'] = '0' * 40
            (clone / '.cargo_vcs_info.json').write_text(json.dumps(vcs))
            cache = base / 'registry/cache/test-index'; cache.mkdir(parents=True)
            cached = cache / archive.name
            cached.write_bytes(b'corrupt' if mutation == 'archive' else archive.read_bytes())
            selected = dict(package, manifest_path=str(clone / 'Cargo.toml'))
            if mutation == 'version': selected['version'] = '0.22.5'
            if mutation == 'license': selected['license'] = 'MIT'
            input_path = base / 'metadata.json'
            input_path.write_text(json.dumps(graph_fixture([selected])))
            result = subprocess.run([str(ROOT / 'packaging/collect-cargo-licenses.sh'), str(input_path), str(base / 'notices')],
                                    cwd=ROOT, text=True, capture_output=True, check=False)
            assert (result.returncode == 0) == (mutation == 'none'), (name, mutation, result.stderr)
            if mutation == 'none':
                destination = base / 'notices' / source.name
                for notice in ('LICENSE-APACHE', 'LICENSE-MIT'):
                    assert (destination / notice).is_file()
                assert 'crates.io+vcs-license-' in (base / 'notices/DEPENDENCIES.tsv').read_text()
print('PASS exact JNI archives/VCS/version/license bindings and original notice fallbacks')
