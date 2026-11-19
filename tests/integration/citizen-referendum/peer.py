# SPDX-License-Identifier: GPL-3.0-only
"""Publish a public Citizen proof and read it from a fresh independent Core client."""
import base64
import hashlib
import json
import os
import runpy
from pathlib import Path
import secrets
import stat
import subprocess
import sys
import tempfile

NAME = 'citizen-fictional-library-proof'
SIZE = 28782
DIGEST = 'e37b90d9573d068696e1d334f2165e21f6cdd5d6351dae32f18c0564dd17e9d1'


def require(condition, message):
    if not condition:
        raise ValueError(message)


def run(mode, binary, socket, argument, cache=None):
    require(os.getuid() != 0, 'the client must run as a regular user')
    with tempfile.TemporaryDirectory() as tmp:
        work = Path(tmp)

        def cli(*args):
            result = subprocess.run([binary, '--control-socket', socket, *args], cwd=work,
                                    stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, timeout=115, check=True)
            return json.loads(result.stdout)

        if mode == 'publish':
            credential = work / 'passphrase'
            with os.fdopen(os.open(credential, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600), 'w') as password:
                password.write(secrets.token_urlsafe(40))
            unlock = ['--identity', work / 'identity', '--passphrase-file', credential]
            cli('init', *unlock)
            key = cli('content', 'recipient-key', *unlock)['identity_public_key_hex']
            result = cli('content', 'publish', '--contribute', '--input', argument, '--expected-input-sha256', DIGEST,
                         '--expected-publisher-key', key, '--name', NAME, '--revision', '1', '--content-type',
                         'application/zip', '--manifest', work / 'manifest', '--cache', work / 'cache', *unlock)
            require(result['operation'] == 'content_publish' and result['network_publication'] is True
                    and result['serving'] is True and result['publisher_key_hex'] == key
                    and result['bytes'] == SIZE and result['chunks'] == 1, 'public proof contribution incomplete')
            return {'publisher_key': key, 'publication': result, 'namespace': os.readlink('/proc/self/ns/net')}
        require(mode == 'receive' and cache, 'reader cache path required')
        path = work / 'public-referenda.zip'
        result = cli('content', 'fetch-name', '--publisher-key', argument, '--name', NAME,
                     '--min-revision', '1', '--cache', cache, '--local-output', path)
        require(path.stat().st_size == SIZE and stat.S_IMODE(path.stat().st_mode) == 0o600, 'unexpected reader output')
        received = path.read_bytes()
        require(hashlib.sha256(received).hexdigest() == result['sha256'] == DIGEST and result['bytes'] == SIZE
                and result['operation'] == 'named_content_download' and result['publisher_key'] == argument
                and result['name'] == NAME and result['revision'] == 1 and result['local_delivery'] is True
                and result['cache_only'] is False and result['peer_bytes'] == SIZE and result['providers_used'] == 1
                and result['origin_body_bytes'] == result['origin_range_requests'] == 0, 'proof did not arrive from a peer')
        return {'download': result, 'namespace': os.readlink('/proc/self/ns/net'),
                'public_zip_base64': base64.b64encode(received).decode('ascii')}


def verify(folder, output):
    folder = Path(folder)
    def read(name):
        return json.loads((folder / f'content-replication-{name}.json').read_bytes())

    report = read('smoke')
    require(report['success'] is True and report['host_state']['unchanged'] is True and
            report['cleanup']['remaining_owned_objects'] == 0, 'guest proof or cleanup incomplete')
    peers = report['transfer']['expected_peers']
    offered, received = read('citizen-publish'), read('citizen-receive')
    pub, fetch = offered['publication'], received['download']
    require(offered['namespace'] != received['namespace'] and offered['publisher_key'] == pub['publisher_key_hex']
            == fetch['publisher_key'] and pub['manifest_id'] == fetch['manifest_id']
            and pub['expires_unix_seconds'] == fetch['publication_expires_unix_seconds']
            and fetch['provider_peer_ids'] == [peers['relay4']] and fetch['peer_bytes'] == SIZE
            and fetch['origin_body_bytes'] == 0, 'signed publisher or serving peer differs')
    proof = runpy.run_path(str(Path(__file__).resolve().parents[1] / 'content-replication-smoke.py'))
    layout, route = read('citizen-fetch-layout'), read('citizen-final-live-selection')
    proof['CAPTURE']['validate_layout'](layout)
    proof['validate_route'](route, peers)
    relays = sorted(layout['relays'])
    require(fetch['control_relay_peer_id'] not in {peers['relay4'], peers['client'], peers['exit'],
            *(peers[node] for node in relays)}, 'control relay overlaps a data role')
    require(layout['phase'] == 'reserve-fetch' and layout['client']['node'] == 'client'
            and layout['provider']['node'] == 'relay4' and set(relays) == {slot['relay_node'] for slot in route['benchmark_slots']},
            'wrong physical capture endpoints')
    for role, node in zip(('receiver', 'relay-a', 'relay-b', 'exit', 'provider'), ('client', *relays, 'exit', 'relay4')):
        capture = read('citizen-fetch-' + role)
        proof['validate_capture'](capture, layout, node)
        if role in ('exit', 'provider'):
            require(capture['provider_request_packets'] > 0 and capture['provider_response_payload_bytes'] >= SIZE,
                    'original peer response missing on provider leg')
        else:
            require(capture['provider_request_packets'] == capture['provider_response_packets'] == 0,
                    'provider traffic outside expected leg')
    raw = base64.b64decode(received['public_zip_base64'], validate=True)
    require(len(raw) == SIZE and hashlib.sha256(raw).hexdigest() == DIGEST == fetch['sha256'], 'unexpected received ZIP')
    with Path(output).open('xb') as handle:
        handle.write(raw)


if __name__ == '__main__':
    if sys.argv[1] == 'verify':
        verify(*sys.argv[2:])
    else:
        print(json.dumps(run(*sys.argv[1:]), sort_keys=True))
