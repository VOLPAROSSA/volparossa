#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-only
"""Exact source/lock scope for the explicit GPSD route, separate from ABI reuse."""
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess
import tomllib

ROOT = Path(__file__).resolve().parents[1]
BASE = '545d5295fb5e36dbbf4dd2c3926867837b4fcf6a'
OWNED = {
    '.github/workflows/dps-native-quality.yml', 'Cargo.lock', 'THIRD_PARTY_LICENSES.md',
    'crates/volparossa/Cargo.toml', 'crates/volparossa/src/main.rs',
    'crates/volparossa/src/dps.rs', 'crates/volparossa/src/dps/gpsd.rs',
    'crates/volparossa/src/dps/gpsd/tests.rs', 'docs/services/DPS.md',
    'scripts/run-isolated-test.sh', 'scripts/test-cargo-source-policy.py',
    'scripts/check-dps-gpsd-source.py', 'scripts/dps-gpsd-host-state.py',
    'scripts/test-dps-gpsd-wrapper.py',
    'tests/dps/gpsd/README.md', 'tests/dps/gpsd/common.py',
    'tests/dps/gpsd/fixture.py', 'tests/dps/gpsd/test_proof.py',
    'tests/dps/gpsd/build.py', 'tests/dps/gpsd/prove.py', 'tests/dps/gpsd/manifest.json',
    'third_party/gpsd/README.md', 'third_party/gpsd/debian-copyright',
    'third_party/gpsd/debian-patch-series', 'third_party/gpsd/COPYING',
    'third_party/gpsd/file-notices.json', 'third_party/gpsd/pins.json',
    'third_party/gpsd/debian-source-entry.txt',
}


def git(*args):
    return subprocess.check_output(['/usr/bin/git', '-C', str(ROOT), *args], timeout=10, text=True).strip()


def verify():
    revision = os.environ['GITHUB_SHA']
    if (not re.fullmatch('[0-9a-f]{40}', revision) or
            revision != os.environ['GITHUB_WORKFLOW_SHA'] or git('rev-parse', 'HEAD') != revision or
            git('status', '--porcelain', '--untracked-files=all')):
        raise ValueError('source/workflow/head/clean binding differs')
    subprocess.run(['/usr/bin/git', '-C', str(ROOT), 'merge-base', '--is-ancestor', BASE, 'HEAD'],
                   timeout=10, check=True)
    changed = set(git('diff', '--name-only', BASE, 'HEAD').splitlines())
    if changed != OWNED:
        raise ValueError('GPSD source delta differs from its exact owned inventory')
    old = tomllib.loads(git('show', BASE + ':Cargo.lock'))
    current = tomllib.loads((ROOT / 'Cargo.lock').read_text())
    for package in old['package']:
        if package['name'] == 'volparossa':
            if 'chrono' in package['dependencies']:
                raise ValueError('base CLI dependency membership changed')
            package['dependencies'].append('chrono')
            package['dependencies'].sort()
    if old != current:
        raise ValueError('locked records differ beyond existing chrono CLI membership')
    manifest = tomllib.loads(git('show', BASE + ':crates/volparossa/Cargo.toml'))
    manifest['dependencies']['chrono'] = {'workspace': True}
    if manifest != tomllib.loads((ROOT / 'crates/volparossa/Cargo.toml').read_text()):
        raise ValueError('CLI manifest differs beyond existing workspace chrono membership')
    policy_before = subprocess.check_output(
        ['/usr/bin/git', '-C', str(ROOT), 'show', BASE + ':scripts/test-cargo-source-policy.py'],
        timeout=10, text=True)
    policy_now = (ROOT / 'scripts/test-cargo-source-policy.py').read_text()
    if policy_now != policy_before.replace('self.assertEqual(count,19)', 'self.assertEqual(count,20)'):
        raise ValueError('Cargo source policy tests changed beyond new fixed caller inventory')
    return dict(schema_version=1, source_commit=revision, source_tree=git('rev-parse', 'HEAD^{tree}'),
                workflow_commit=os.environ['GITHUB_WORKFLOW_SHA'], base_commit=BASE,
                changed_paths=sorted(changed),
                source_sha256={name: hashlib.sha256((ROOT / name).read_bytes()).hexdigest()
                               for name in sorted(OWNED)},
                scope='synthetic-pinned-gpsd-to-one-shot-cli',
                physical_positioning_acceptance=False, native_debian13_acceptance=False,
                daemon_or_mobile_acceptance=False)


if __name__ == '__main__':
    print(json.dumps(verify(), sort_keys=True))
