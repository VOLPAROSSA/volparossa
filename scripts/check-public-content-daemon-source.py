#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-only
"""Bound source-only daemon consumer evidence; production and locks stay exact."""
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess

ROOT = Path(__file__).resolve().parents[1]
BASE = 'abd16f8962fde44012b22e86cb876000ab3e8f08'
REQUIRED = {'.github/workflows/public-content-daemon.yml',
            'scripts/check-public-content-daemon-source.py', 'scripts/test-cargo-source-policy.py',
            'crates/volparossa-agent/tests/public_content_daemon.rs'}
OWNED = REQUIRED | {
    'crates/volparossa-agent/tests/public_content_daemon/fixture.rs',
    'crates/volparossa-agent/tests/public_content_daemon/process.rs',
    'crates/volparossa-agent/tests/public_content_daemon/scenario.rs',
    'crates/volparossa-agent/tests/public_content_daemon/tests.rs',
}


def git(*args):
    return subprocess.check_output(['/usr/bin/git', '-C', str(ROOT), *args], timeout=10)


def verify():
    source = os.environ['GITHUB_SHA']
    if (not re.fullmatch('[0-9a-f]{40}', source) or source != os.environ['GITHUB_WORKFLOW_SHA'] or
            git('rev-parse', 'HEAD').decode().strip() != source or
            git('status', '--porcelain', '--untracked-files=all')):
        raise ValueError('source/workflow/head/clean binding differs')
    subprocess.run(['/usr/bin/git', '-C', str(ROOT), 'merge-base', '--is-ancestor', BASE, 'HEAD'],
                   timeout=10, check=True)
    changed = set(git('diff', '--name-only', BASE, 'HEAD').decode().splitlines())
    if changed != OWNED:
        raise ValueError('public consumer source inventory differs')
    old = git('show', BASE + ':scripts/test-cargo-source-policy.py')
    if (ROOT / 'scripts/test-cargo-source-policy.py').read_bytes() != old.replace(
            b'self.assertEqual(count,19)', b'self.assertEqual(count,20)'):
        raise ValueError('Cargo source policy changed beyond its fixed caller inventory')
    files = {}
    for path in sorted(changed):
        info = git('ls-tree', 'HEAD', '--', path).decode()
        if not info.startswith('100644 blob ') or not info.rstrip().endswith('\t' + path):
            raise ValueError('owned source must be an ordinary tracked non-executable file')
        files[path] = hashlib.sha256((ROOT / path).read_bytes()).hexdigest()
    return dict(schema_version=1, source_commit=source,
                source_tree=git('rev-parse', 'HEAD^{tree}').decode().strip(),
                workflow_commit=os.environ['GITHUB_WORKFLOW_SHA'], base_commit=BASE,
                changed_source_sha256=files,
                cargo_lock_sha256=hashlib.sha256((ROOT / 'Cargo.lock').read_bytes()).hexdigest(),
                upstream_lock_sha256=hashlib.sha256((ROOT / 'third_party/upstream.lock.json').read_bytes()).hexdigest(),
                scope='public-offline-cli-normal-daemon-import-crash-restart-export',
                protected_route_acceptance=False, named_cache_only_site_open=False,
                independent_peer_or_hosting_acceptance=False, power_loss_acceptance=False,
                production_code_changed_since_base=False)


if __name__ == '__main__':
    print(json.dumps(verify(), sort_keys=True))
