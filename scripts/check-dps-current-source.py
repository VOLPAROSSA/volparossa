#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-only
"""Exact current-compiler source binding for the existing hosted DPS ABI harness."""
import json
import os
from pathlib import Path
import re
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[1]
NATIVE_BASE = '89d3aea585ed8a1e4d7db3beac76846d3d3e2dc1'
SHARED_BASE = 'c11d97f4265834218500ba7ec7e2aff1e66c55db'
DPS = tuple('crates/volparossa-dps-ffi/' + name for name in (
    'Cargo.toml', 'README.md', 'src/lib.rs', 'src/ffi.rs', 'src/ffi/tests.rs',
    'include/volparossa_dps.h', 'tests/contracts.rs', 'tests/native_smoke.c',
    'tests/fixtures/manifest.json', 'tests/fixtures/relative_consistent.pb',
    'tests/fixtures/relative_conflict.pb', 'tests/fixtures/stale.pb', 'tests/fixtures/empty.pb'))
SHARED = tuple('crates/volparossa-local-control/' + name for name in (
    'Cargo.toml', 'src/lib.rs', 'src/dps.rs', 'src/dps/tests.rs'))
CURRENT = ('Cargo.lock', 'Cargo.toml', 'rust-toolchain.toml', 'scripts/provision-rust189.py', 'scripts/rust189-components.json',
           'scripts/cargo-source-policy.py', 'scripts/test-cargo-source-policy.py',
           '.github/workflows/dps-native-quality.yml')


def admission(env, revision):
    if os.geteuid() == 0:
        raise ValueError('current DPS proof must be unprivileged')
    if not re.fullmatch(r'refs/heads/[A-Za-z0-9_./-]+', env.get('GITHUB_REF', '')):
        raise ValueError('current DPS proof requires an explicit branch ref')
    if any(env.get(key) != value for key, value in dict(GITHUB_ACTIONS='true',
            RUNNER_ENVIRONMENT='github-hosted', RUNNER_OS='Linux', RUNNER_ARCH='X64',
            GITHUB_REPOSITORY='VOLPAROSSA/volparossa', GITHUB_EVENT_NAME='workflow_dispatch',
            DPS_MODE='current-compiler').items()):
        raise ValueError('current DPS proof requires assigned disposable hosted dispatch')
    if not re.fullmatch('[0-9a-f]{40}', revision) or any(env.get(key) != revision for key in (
            'CORE_REVISION', 'GITHUB_SHA', 'GITHUB_WORKFLOW_SHA')):
        raise ValueError('exact current DPS source/workflow mismatch')


def source_receipt(env, git):
    revision = git('rev-parse', 'HEAD')
    admission(env, revision)
    git('check-ref-format', env['GITHUB_REF'])
    if git('status', '--porcelain', '--untracked-files=all'):
        raise ValueError('DPS source is not clean')
    git('merge-base', '--is-ancestor', NATIVE_BASE, 'HEAD')
    git('merge-base', '--is-ancestor', SHARED_BASE, 'HEAD')
    blobs = {name: git('rev-parse', 'HEAD:' + name) for name in (*DPS, *SHARED, *CURRENT)}
    for name in DPS:
        expected = git('rev-parse', NATIVE_BASE + ':' + name)
        if expected != git('rev-parse', SHARED_BASE + ':' + name):
            raise ValueError('reviewed DPS/native baselines changed: ' + name)
        if blobs[name] != expected:
            raise ValueError('reviewed DPS/native fixture changed: ' + name)
    for name in SHARED:
        expected = git('rev-parse', SHARED_BASE + ':' + name)
        # Only the fixed C11 test assertion differs from the original base.
        # The three production shared files must match both reviewed baselines.
        if name != 'crates/volparossa-local-control/src/dps/tests.rs' and expected != git('rev-parse', NATIVE_BASE + ':' + name):
            raise ValueError('reviewed production shared baselines changed: ' + name)
        if blobs[name] != expected:
            raise ValueError('reviewed shared service/test changed: ' + name)
    return dict(schema=1, mode='current-compiler', source_commit=revision,
        workflow_commit=env['GITHUB_WORKFLOW_SHA'], source_tree=git('rev-parse', 'HEAD^{tree}'),
        base_commit=NATIVE_BASE, shared_base=SHARED_BASE, source_blobs=blobs, shared_blobs={name: blobs[name] for name in SHARED},
        scope='synthetic-core-native-quality-abi', actual_android_acceptance=False,
        physical_positioning_acceptance=False)


if __name__ == '__main__':
    def git(*args):
        return subprocess.check_output(['git', *args], cwd=ROOT, text=True).strip()
    if os.getuid() == 0:
        raise SystemExit('current DPS proof must be unprivileged')
    if sys.argv[1:] not in ([], ['--check']):
        raise SystemExit('usage: check-dps-current-source.py [--check]')
    record = source_receipt(os.environ, git)
    if sys.argv[1:] == ['--check']:
        print(json.dumps(record, sort_keys=True))
        raise SystemExit(0)
    with (ROOT / 'dps-native-evidence/source.json').open('x') as stream:
        stream.write(json.dumps(record, sort_keys=True) + '\n')
