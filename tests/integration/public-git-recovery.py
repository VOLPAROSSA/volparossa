#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-only
"""Restore a disposable, owner-enrolled public Git history from independent custody peers."""
import hashlib
import json
import os
from pathlib import Path
import re
import runpy
import secrets
import socket
import subprocess
import sys
import tempfile
import time


REPOSITORY = '851dc721-4b71-4cea-a819-883a7eaf576e'
NAME = 'public-git-' + REPOSITORY
REF = 'refs/heads/main'
COMMITS = ['0c14d282024543994a2ee8c625048932e419da04', '655f50114b90ca929db4097da36d577bd4215243']
HISTORY = (b'First public edition\n', b'Second public edition\n')
AUTHOR = 'VOLPAROSSA recovery fixture'
EMAIL = 'public-git@example.invalid'
DATE = '2001-01-01T00:00:00+00:00'


def require(condition, reason):
    if not condition:
        raise ValueError(reason)


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


def digest(path):
    require(path.is_file() and not path.is_symlink() and 0 < path.stat().st_size <= 65536, 'invalid fixture file')
    return hashlib.sha256(path.read_bytes()).hexdigest()


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
    require(os.geteuid() != 0 and [n for _, n in socket.if_nameindex()] == ['lo'],
            'requires an unprivileged disposable receiver without an external interface')
    require(re.fullmatch(r'[0-9a-f]{64}', holder_key) and holder_peer,
            'fresh agent cache and enrolled custody holder required')

    def command(*args):
        return subprocess.run([cli, '--control-socket', control, *args], stdin=subprocess.DEVNULL,
                              stdout=subprocess.PIPE, timeout=240, check=True).stdout

    with tempfile.TemporaryDirectory(prefix='public-git-recovery-', dir=parent) as work:
        root = Path(work)
        with tempfile.TemporaryDirectory(dir=root) as origin:
            source = Path(origin)
            bundle = create_bundle(source)
            sha = digest(bundle)
            identity, secret = source / 'identity.key', source / 'passphrase'
            secret.write_text(secrets.token_hex(24) + '\n')
            secret.chmod(0o600)
            unlock = ['--identity', identity, '--passphrase-file', secret]
            command('init', *unlock)
            key = json.loads(command('content', 'recipient-key', *unlock))['identity_public_key_hex']
            manifest, store = source / 'manifest.bin', source / 'chunks'
            published = json.loads(command('content', 'publish', '--input', bundle, '--expected-input-sha256', sha,
                '--expected-publisher-key', key, '--cache', store, '--manifest', manifest, '--name', NAME,
                '--revision', '1', '--lifetime-seconds', '7200', *unlock))
            mid = digest(manifest)
            manifest_bytes = manifest.read_bytes().hex()
            require(published['manifest_id'] == mid and published['publisher_key_hex'] == key,
                    'publication differs from local enrollment')
            deposit = json.loads(command('content', 'custody', 'deposit', '--manifest', manifest, '--cache', store,
                                          '--provider-key', holder_key, *unlock))
            observed_at = int(time.time())
            require(deposit['manifest_id'] == mid and deposit['complete'] is True and
                    deposit['confirmed_complete_providers'] == 1 and deposit['observations'][0]['provider_key_hex'] == holder_key
                    and deposit['observations'][0]['state'] == 'complete', 'independent holder did not confirm custody')
        require(not source.exists(), 'publisher directory survived shutdown')
        downloaded = root / 'received.bundle'
        fetched = json.loads(command('content', 'fetch-name', '--publisher-key', key, '--name', NAME,
            '--min-revision', '1', '--cache', cache, '--local-output', downloaded))
        require(fetched['manifest_id'] == mid and fetched['revision'] == 1 and fetched['publisher_key'] == key
                and fetched['name'] == NAME and fetched['sha256'] == sha and fetched['provider_peer_ids'] == [holder_peer]
                and fetched['providers_used'] == 1 and 0 < fetched['bytes'] == fetched['peer_bytes'], 'fresh download did not match the enrolled holder and publication')
        restore(root, downloaded, sha, COMMITS)
        raw_bundle = downloaded.read_bytes().hex()
    require(not root.exists(), 'owner fixture cleanup incomplete')
    return dict(repository_id=REPOSITORY, ref=REF, revisions=COMMITS, bundle_sha256=sha, manifest_id=mid,
                publisher_key=key, holder_key=holder_key, holder_peer=holder_peer,
                signed_manifest=manifest_bytes, verified_at=observed_at, received_bundle=raw_bundle,
                fetch={k: fetched[k] for k in ('operation', 'publisher_key', 'name', 'revision', 'manifest_id',
                    'sha256', 'bytes', 'peer_bytes', 'provider_peer_ids', 'providers_used', 'publication_expires_unix_seconds')},
                custody_receipt=deposit['observations'][0]['signed_receipt_hex'],
                downloaded_bytes=fetched['bytes'], publisher_removed=True, empty_receiver=True,
                strict_fsck=True, mirror_inaccessible=True, fixture_removed=True)


def verify_host(receipt, topology, source):
    # Use the canonical field decoder and Ed25519 verifier from the existing custody checker.
    checks = runpy.run_path(str(Path(__file__).with_name('content-retain-smoke.py')))
    fields = checks['fields']
    require(topology['source_revision'] == source and topology['success'] is True, 'host topology/source mismatch')
    require(receipt['repository_id'] == REPOSITORY and receipt['ref'] == REF and receipt['revisions'] == COMMITS,
            'repository enrollment differs')
    require(all(receipt[field] is True for field in ('empty_receiver', 'mirror_inaccessible', 'strict_fsck',
            'publisher_removed', 'fixture_removed')), 'guest did not complete isolated recovery')
    custody = topology['custody']
    holder = custody['replacement']['state']['confirmed_holders'][0]
    nodes = [n for n,k in custody['layout']['provider_keys'].items() if k == holder]
    require(len(nodes) == 1, 'missing independently enrolled holder')
    peer = custody['expected_peers'][nodes[0]]
    require(holder == receipt['holder_key'] == checks['C']['peer_key'](peer) and peer == receipt['holder_peer'],
            'unexpected custody source')
    contents = bytes.fromhex(receipt['received_bundle'])
    require(0 < len(contents) <= 65536, 'Git fixture exceeds its enrolled size bound')
    sha = hashlib.sha256(contents).digest()
    signed = bytes.fromhex(receipt['signed_manifest'])
    manifest_id = hashlib.sha256(signed).digest()
    envelope = fields(signed, 4096)
    body = fields(envelope[1], 4096)
    key, at = bytes.fromhex(receipt['publisher_key']), receipt['verified_at']
    require(set(envelope) == {1, 2} and set(body) == set(range(1, 9)) and body[1] == body[6] == 1
            and body[2] == key and len(body[5]) == 32 and body[3] <= at < body[4] and body[4] - body[3] == 7200
            and hashlib.sha256(body[8]).digest() == body[7], 'publication identity or validity differs')
    checks['verify_signature'](envelope[1], envelope[2], key, b'VOLPAROSSA/native-content-manifest/v1\0')
    metadata = fields(body[8], 4096)
    require(metadata == {1: NAME.encode(), 2: 1, 3: b'application/octet-stream', 4: len(contents),
                         5: metadata[5], 6: sha} and fields(metadata[5], 256) == {1: sha, 2: len(contents)},
            'signed publication differs from the downloaded Git bundle')
    _, claim = checks['envelope'](bytes.fromhex(receipt['custody_receipt']), holder, 3, at)
    require(set(claim) == {1, 2, 3, 4, 6, 7, 8, 9, 10, 11} and len(claim[1]) == len(claim[2]) == 32
            and claim[3] == bytes.fromhex(holder) and claim[4] == key and claim[6] == 2 and claim[7] == manifest_id
            and claim[8] == sha and claim[9] == len(contents) and claim[10] == 1 and claim[11] == body[4],
            'signed deposit receipt differs from the holder, publisher or bundle')
    require(receipt['fetch'] == dict(operation='named_content_download', publisher_key=key.hex(), name=NAME,
            revision=1, manifest_id=manifest_id.hex(), sha256=sha.hex(), bytes=len(contents), peer_bytes=len(contents),
            provider_peer_ids=[peer], providers_used=1, publication_expires_unix_seconds=body[4])
            and receipt['manifest_id'] == manifest_id.hex() and receipt['bundle_sha256'] == sha.hex()
            and receipt['downloaded_bytes'] == len(contents), 'original fetch and signed custody evidence differ')
    with tempfile.TemporaryDirectory(prefix='git-recovery-host-') as work:
        root = Path(work)
        bundle = root / 'received.bundle'
        bundle.write_bytes(contents)
        restore(root, bundle, sha.hex(), COMMITS)


if __name__ == '__main__':
    if sys.argv[1] == 'verify-host':
        receipt, topology, source = sys.argv[2:]
        require(Path(receipt).stat().st_size <= 131072, 'oversized Git recovery receipt')
        verify_host(json.loads(Path(receipt).read_bytes()), json.loads(Path(topology).read_bytes()), source)
    else:
        cli, control, parent, cache, key, peer = sys.argv[1:]
        print(json.dumps(trial(cli, control, Path(parent), Path(cache), key, peer)))
