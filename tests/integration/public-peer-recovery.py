#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-only
"""Publish and recover one bounded public artifact through a pre-enrolled custody peer."""
import hashlib
import json
import os
from pathlib import Path
import re
import runpy
import secrets
import socket
import subprocess
import tempfile
import time


def require(condition, reason):
    if not condition:
        raise ValueError(reason)


def digest(path):
    require(path.is_file() and not path.is_symlink() and 0 < path.stat().st_size <= 65536, 'invalid fixture file')
    return hashlib.sha256(path.read_bytes()).hexdigest()


def require_independent_publisher(publisher_key, holder_key):
    require(re.fullmatch(r'[0-9a-f]{64}', publisher_key) and publisher_key != holder_key,
            'publication and custody must use distinct enrolled keys')


def recover(cli, control, parent, cache, holder_key, holder_peer, name, make_source, inspect_download):
    require(os.geteuid() != 0 and [n for _, n in socket.if_nameindex()] == ['lo'],
            'requires an unprivileged disposable receiver without an external interface')
    require(re.fullmatch(r'[0-9a-f]{64}', holder_key) and holder_peer,
            'fresh agent cache and enrolled custody holder required')

    def command(*args):
        return subprocess.run([cli, '--control-socket', control, *args], stdin=subprocess.DEVNULL,
                              stdout=subprocess.PIPE, timeout=240, check=True).stdout

    with tempfile.TemporaryDirectory(prefix='public-peer-recovery-', dir=parent) as work:
        root = Path(work)
        with tempfile.TemporaryDirectory(dir=root) as origin:
            source = Path(origin)
            artifact = make_source(source)
            sha = digest(artifact)
            identity, secret = source / 'identity.key', source / 'passphrase'
            secret.write_text(secrets.token_hex(24) + '\n')
            secret.chmod(0o600)
            unlock = ['--identity', identity, '--passphrase-file', secret]
            command('init', *unlock)
            key = json.loads(command('content', 'recipient-key', *unlock))['identity_public_key_hex']
            require_independent_publisher(key, holder_key)
            manifest, store = source / 'manifest.bin', source / 'chunks'
            published = json.loads(command('content', 'publish', '--input', artifact, '--expected-input-sha256', sha,
                '--expected-publisher-key', key, '--cache', store, '--manifest', manifest, '--name', name,
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
        downloaded = root / 'received.bin'
        fetched = json.loads(command('content', 'fetch-name', '--publisher-key', key, '--name', name,
            '--min-revision', '1', '--cache', cache, '--local-output', downloaded))
        require(fetched['manifest_id'] == mid and fetched['revision'] == 1 and fetched['publisher_key'] == key
                and fetched['name'] == name and fetched['sha256'] == sha and fetched['provider_peer_ids'] == [holder_peer]
                and fetched['providers_used'] == 1 and 0 < fetched['bytes'] == fetched['peer_bytes'], 'fresh download did not match the enrolled holder and publication')
        inspect_download(root, downloaded, sha)
        raw = downloaded.read_bytes()
        require(hashlib.sha256(raw).hexdigest() == sha, 'downloaded bytes differ from the published artifact')
    require(not root.exists(), 'owner fixture cleanup incomplete')
    return dict(sha256=sha, manifest_id=mid,
                publisher_key=key, holder_key=holder_key, holder_peer=holder_peer,
                signed_manifest=manifest_bytes, verified_at=observed_at, received=raw.hex(),
                fetch={k: fetched[k] for k in ('operation', 'publisher_key', 'name', 'revision', 'manifest_id',
                    'sha256', 'bytes', 'peer_bytes', 'provider_peer_ids', 'providers_used', 'publication_expires_unix_seconds')},
                custody_receipt=deposit['observations'][0]['signed_receipt_hex'],
                downloaded_bytes=fetched['bytes'], publisher_removed=True, fixture_removed=True)


def verify_peer(receipt, topology, source, name, contents, expected_sha):
    # Use the canonical field decoder and Ed25519 verifier from the existing custody checker.
    checks = runpy.run_path(str(Path(__file__).with_name('content-retain-smoke.py')))
    fields = checks['fields']
    require(topology['source_revision'] == source and topology['success'] is True, 'host topology/source mismatch')
    require(receipt['publisher_removed'] is True and receipt['fixture_removed'] is True,
            'publisher or receiver cleanup missing')
    custody = topology['custody']
    holder = custody['replacement']['state']['confirmed_holders'][0]
    nodes = [n for n,k in custody['layout']['provider_keys'].items() if k == holder]
    require(len(nodes) == 1, 'missing independently enrolled holder')
    peer = custody['expected_peers'][nodes[0]]
    require(holder == receipt['holder_key'] == checks['C']['peer_key'](peer) and peer == receipt['holder_peer'],
            'unexpected custody source')
    require_independent_publisher(receipt['publisher_key'], holder)
    require(0 < len(contents) <= 65536, 'public fixture exceeds its size bound')
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
    require(metadata == {1: name.encode(), 2: 1, 3: b'application/octet-stream', 4: len(contents),
                         5: metadata[5], 6: sha} and fields(metadata[5], 256) == {1: sha, 2: len(contents)},
            'signed publication differs from the downloaded public object')
    _, claim = checks['envelope'](bytes.fromhex(receipt['custody_receipt']), holder, 3, at)
    require(set(claim) == {1, 2, 3, 4, 6, 7, 8, 9, 10, 11} and len(claim[1]) == len(claim[2]) == 32
            and claim[3] == bytes.fromhex(holder) and claim[4] == key and claim[6] == 2 and claim[7] == manifest_id
            and claim[8] == sha and claim[9] == len(contents) and claim[10] == 1 and claim[11] == body[4],
            'signed deposit receipt differs from the holder, publisher or object')
    require(receipt['fetch'] == dict(operation='named_content_download', publisher_key=key.hex(), name=name,
            revision=1, manifest_id=manifest_id.hex(), sha256=sha.hex(), bytes=len(contents), peer_bytes=len(contents),
            provider_peer_ids=[peer], providers_used=1, publication_expires_unix_seconds=body[4])
            and receipt['manifest_id'] == manifest_id.hex() and expected_sha == sha.hex()
            and receipt['downloaded_bytes'] == len(contents), 'original fetch and signed custody evidence differ')
