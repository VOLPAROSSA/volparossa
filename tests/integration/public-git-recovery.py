#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-only
"""Restore a disposable, owner-enrolled public Git history from independent custody peers."""
import json
from pathlib import Path
import runpy
import subprocess
import sys
import tempfile

PEER = runpy.run_path(str(Path(__file__).with_name('public-peer-recovery.py')))
require, digest = PEER['require'], PEER['digest']

REPOSITORY = '851dc721-4b71-4cea-a819-883a7eaf576e'
NAME = 'public-git-' + REPOSITORY
REF = 'refs/heads/main'
COMMITS = ['0c14d282024543994a2ee8c625048932e419da04', '655f50114b90ca929db4097da36d577bd4215243']
HISTORY = (b'First public edition\n', b'Second public edition\n')
AUTHOR = 'VOLPAROSSA recovery fixture'
EMAIL = 'public-git@example.invalid'
DATE = '2001-01-01T00:00:00+00:00'


def git(repo, *args, data=None):
    env = {'PATH': '/usr/bin:/bin', 'LC_ALL': 'C', 'GIT_CONFIG_GLOBAL': '/dev/null',
           'GIT_CONFIG_NOSYSTEM': '1', 'GIT_NO_REPLACE_OBJECTS': '1', 'GIT_TERMINAL_PROMPT': '0',
           'GIT_AUTHOR_NAME': AUTHOR, 'GIT_COMMITTER_NAME': AUTHOR, 'GIT_AUTHOR_EMAIL': EMAIL,
           'GIT_COMMITTER_EMAIL': EMAIL, 'GIT_AUTHOR_DATE': DATE, 'GIT_COMMITTER_DATE': DATE}
    return subprocess.run(['/usr/bin/git', '-c', 'core.hooksPath=/dev/null', '-c', 'protocol.allow=never',
                           *args], cwd=repo, env=env, input=data or b'', stdout=subprocess.PIPE,
                          timeout=10, check=True).stdout


def bare(parent, name):
    repo = parent / name
    repo.mkdir(mode=0o700)
    git(repo, 'init', '--bare', '--quiet', '--object-format=sha1', '--initial-branch=main', '--template=', '.')
    return repo


def create_bundle(source):
    repo = bare(source, 'publisher.git')
    revisions = []
    for index, content in enumerate(HISTORY):
        blob = git(repo, 'hash-object', '-w', '--stdin', data=content).strip()
        tree = git(repo, 'mktree', data=b'100644 blob ' + blob + b'\tREADME\n').strip()
        parents = ['-p', revisions[-1]] if revisions else []
        revision = git(repo, 'commit-tree', tree, *parents, data=f'Public edition {index+1}\n'.encode()).strip().decode()
        revisions.append(revision)
    git(repo, 'update-ref', REF, revisions[-1])
    bundle = source / 'history.bundle'
    git(repo, 'bundle', 'create', '--version=2', bundle, REF)
    require(revisions == COMMITS, 'synthetic history differs from its pre-enrolled source')
    return bundle


def restore(root, bundle, expected_hash, revisions):
    require(digest(bundle) == expected_hash, 'unexpected bundle digest')
    repo = bare(root, 'recovered.git')
    require(not git(repo, 'for-each-ref') and not git(repo, 'cat-file', '--batch-all-objects', '--batch-check'),
            'receiver already contains Git objects or references')
    git(repo, 'bundle', 'verify', bundle)
    expected = f'{revisions[-1]} {REF}\n'.encode()
    require(git(repo, 'bundle', 'list-heads', bundle) == expected, 'unexpected bundle references')
    require(git(repo, 'bundle', 'unbundle', bundle) == expected, 'unexpected imported references')
    git(repo, 'fsck', '--strict', '--full', revisions[-1])
    require(git(repo, 'rev-list', '--reverse', revisions[-1]).decode().splitlines() == revisions,
            'history differs from enrolled commits')
    for revision, content in zip(revisions, HISTORY, strict=True):
        require(git(repo, 'show', f'{revision}:README') == content, 'public source differs')
    git(repo, 'update-ref', REF, revisions[-1], '0' * 40)
    require(git(repo, 'rev-parse', REF).decode().strip() == revisions[-1], 'restored ref differs')


def trial(cli, control, parent, cache, holder_key, holder_peer):
    def inspect(root, downloaded, sha):
        restore(root, downloaded, sha, COMMITS)

    proof = PEER['recover'](cli, control, parent, cache, holder_key, holder_peer, NAME, create_bundle, inspect)
    return dict(repository_id=REPOSITORY, ref=REF, revisions=COMMITS,
                bundle_sha256=proof.pop('sha256'), received_bundle=proof.pop('received'),
                empty_receiver=True, strict_fsck=True, mirror_inaccessible=True, **proof)


def verify_host(receipt, topology, source):
    require(receipt['repository_id'] == REPOSITORY and receipt['ref'] == REF and receipt['revisions'] == COMMITS,
            'repository enrollment differs')
    require(all(receipt[field] is True for field in ('empty_receiver', 'strict_fsck', 'mirror_inaccessible')),
            'guest did not complete isolated Git recovery')
    contents = bytes.fromhex(receipt['received_bundle'])
    sha = receipt['bundle_sha256']
    PEER['verify_peer'](receipt, topology, source, NAME, contents, sha)
    with tempfile.TemporaryDirectory(prefix='git-recovery-host-') as work:
        root = Path(work)
        bundle = root / 'received.bundle'
        bundle.write_bytes(contents)
        restore(root, bundle, sha, COMMITS)


if __name__ == '__main__':
    if sys.argv[1] == 'verify-host':
        receipt, topology, source = sys.argv[2:]
        require(Path(receipt).stat().st_size <= 131072, 'oversized Git recovery receipt')
        verify_host(json.loads(Path(receipt).read_bytes()), json.loads(Path(topology).read_bytes()), source)
    else:
        cli, control, parent, cache, key, peer = sys.argv[1:]
        print(json.dumps(trial(cli, control, Path(parent), Path(cache), key, peer)))
