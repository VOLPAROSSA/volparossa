#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-only
"""Record which checked-out source, locks and test fixture produce the recovery proof."""
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess

ROOT = Path(__file__).resolve().parents[1]
TEST = Path('crates/volparossa-agent/tests/public_content_daemon.rs')


def git(*args):
    return subprocess.check_output(['/usr/bin/git', '-C', str(ROOT), *args], timeout=10)


def verify():
    source = os.environ['GITHUB_SHA']
    if (not re.fullmatch('[0-9a-f]{40}', source)
            or source != os.environ['GITHUB_WORKFLOW_SHA']
            or source != git('rev-parse', 'HEAD').decode().strip()
            or git('status', '--porcelain', '--untracked-files=all')):
        raise ValueError('source, workflow and clean checkout must match')
    paths = [Path(name) for name in git('ls-files', '-z', '--', str(TEST), str(TEST.with_suffix('')))
             .decode().split('\0') if name]
    if TEST not in paths or len(paths) < 2:
        raise ValueError('missing tracked public daemon recovery fixture')
    def digest(path):
        return hashlib.sha256((ROOT / path).read_bytes()).hexdigest()
    return dict(schema_version=2, source_commit=source,
                source_tree=git('rev-parse', 'HEAD^{tree}').decode().strip(),
                workflow_commit=os.environ['GITHUB_WORKFLOW_SHA'],
                test_sha256={str(path): digest(path) for path in paths},
                cargo_lock_sha256=digest('Cargo.lock'),
                upstream_lock_sha256=digest('third_party/upstream.lock.json'),
                scope='public-offline-cli-normal-daemon-import-crash-restart-export')


if __name__ == '__main__':
    print(json.dumps(verify(), sort_keys=True))
