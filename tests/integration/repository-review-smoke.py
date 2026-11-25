#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-only
"""Prepare one new, bounded public proposal from the original independently recovered source."""
import hashlib
import json
from pathlib import Path
import runpy
import sys
import tempfile
import subprocess


HERE = Path(__file__).resolve().parent
REPO = HERE.parents[1]
GIT = runpy.run_path(str(HERE / 'public-git-recovery.py'))
SUBJECT = runpy.run_path(str(REPO / 'scripts/repository-review-subject.py'))['subject']
ORIGINAL = 'addb3501ee1ee865281fd87b32411573c10c73d43aa79f2bf42946a645bae5da'
BASE = GIT['COMMITS'][-1]
CANDIDATE = '1018ac066c68b52fefa029aa7f3bd4c2bc271dfe'
NEW = b"Second public edition\nAsk for permission before sharing another person's contact details.\n"


def create(root):
    receipt = json.loads((REPO / 'docs/development/evidence/public-git-45512807081/content-custody-git-recovery.json').read_bytes())
    original = root / 'original.bundle'
    original.write_bytes(bytes.fromhex(receipt['received_bundle']))
    GIT['restore'](root, original, ORIGINAL, GIT['COMMITS'])
    repo = root / 'recovered.git'
    git = GIT['git']
    blob = git(repo, 'hash-object', '-w', '--stdin', data=NEW).strip()
    tree = git(repo, 'mktree', data=b'100644 blob ' + blob + b'\tREADME\n').strip()
    candidate = git(repo, 'commit-tree', tree, '-p', BASE, data=b'Require consent to share contact details\n').strip().decode()
    if candidate != CANDIDATE:
        raise ValueError('candidate differs from enrollment')
    git(repo, 'update-ref', 'refs/heads/proposal', candidate)
    bundle = root / 'public-proposal.bundle'
    git(repo, 'bundle', 'create', '--version=2', bundle, 'refs/heads/main', 'refs/heads/proposal')
    digest = hashlib.sha256(bundle.read_bytes()).hexdigest()
    proposed = SUBJECT(bundle, digest, GIT['REPOSITORY'], BASE, candidate, 'README')
    return bundle, proposed, candidate



SUBJECT_SHA = 'b97903cfbb2b913c00f0996327d01a59b15543903fe4e30508c94ac3413aaf63'
PREFIX = 'agent-repository-review-'


def require(ok, message):
    if not ok:
        raise ValueError(message)


def sha(data):
    return hashlib.sha256(data).hexdigest()


def recompute(bundle, expected):
    proposal = SUBJECT(bundle, expected, GIT['REPOSITORY'], BASE, CANDIDATE, 'README')
    require(sha(proposal) == SUBJECT_SHA, 'enrolled Git proposal changed')
    return proposal


def prepare(directory):
    with tempfile.TemporaryDirectory() as temp:
        bundle, proposed, _ = create(Path(temp))
        require(sha(proposed) == SUBJECT_SHA, 'enrollment changed')
        (directory / 'git.bundle').write_bytes(bundle.read_bytes())
        (directory / 'subject.txt').write_bytes(proposed)


def verify_publication(checks, manifest, publisher, payload):
    fields = checks['fields']
    envelope = fields(manifest, 8192)
    body = fields(envelope[1], 8192)
    require(body[1] == body[6] == 1 and body[2] == bytes.fromhex(publisher)
            and hashlib.sha256(body[8]).digest() == body[7], 'signed publication body/authority changed')
    checks['verify_signature'](envelope[1], envelope[2], body[2], b'VOLPAROSSA/native-content-manifest/v1\0')
    # The canonical Manifest ends with field 6, the SHA-256 of all bytes regardless of chunk count.
    require(body[8].endswith(b'\x32\x20' + hashlib.sha256(payload).digest()), 'payload differs from signed manifest')
    return body


def verify_deposit(checks, retained, manifest, publisher, holder, payload, export):
    signed = bytes.fromhex(retained['observations'][0]['signed_receipt_hex'])
    fields = checks['fields']
    at = fields(fields(signed, 65536)[1], 65536)[3]
    _, claim = checks['envelope'](signed, holder, 3, at)
    body = verify_publication(checks, manifest, publisher, payload)
    require(claim[3] == bytes.fromhex(holder) and claim[4] == bytes.fromhex(publisher) and claim[6] == 2
            and claim[7].hex() == sha(manifest) and claim[8].hex() == sha(payload)
            and claim[9] == len(payload) and claim[10] == 1 and claim[11] == body[4]
            and body[3] <= at < body[4] and retained['manifest_id'] == export['manifest_id'] == sha(manifest)
            and retained['complete'] is True and export['complete'] is True and export['operation'] == 'content_export'
            and export['public_content'] is True and export['content_bytes'] == len(payload),
            'original custody or holder export differs from recovered bytes')


def verify_transcript(checks, stage, reviewer, requester):
    proof = json.loads(bytes.fromhex(stage['provider_transcript']))
    require(proof['requester_key'] == requester, 'foreign requester transcript')
    fields = checks['fields']
    transcript = fields(bytes.fromhex(proof['transcript_hex']), 96 * 1024)
    bodies = []
    for kind, signer in enumerate((reviewer, requester, reviewer), 1):
        record = fields(transcript[kind + 1], 96 * 1024)
        body = fields(record[1], 96 * 1024)
        require(body[1] == 1 and body[2] == bytes.fromhex(signer) and body[6] == kind
                and body[7] == hashlib.sha256(body.get(8, b'')).digest(), 'signed stage differs from enrollment')
        checks['verify_signature'](record[1], record[2], body[2], b'VOLPAROSSA/compute-control/v1\0')
        bodies.append(body)
    challenge, request, reply = bodies
    require(reply[9].hex() == sha(transcript[3]) and request[10] == reply[10] == hashlib.sha256(transcript[2]).digest()
            and challenge[5] == request[5] == reply[5] and challenge[4] == request[4] == reply[4]
            and challenge[3] <= request[3] <= reply[3] < challenge[4], 'original exchange linkage differed')


def verify_originals(directory):
    def read(name):
        return json.loads((directory / (PREFIX + name + '.json')).read_bytes())

    checks = runpy.run_path(str(HERE / 'content-retain-smoke.py'))
    selection = read('selection')
    packed = (directory / (PREFIX + 'portable.json')).read_bytes()
    require(0 < len(packed) <= 2 * 1024 ** 2, 'invalid original package size')
    package = json.loads(packed)
    with tempfile.TemporaryDirectory() as temp:
        bundle = Path(temp) / 'public.bundle'
        git_bytes = bytes.fromhex(read('source')['git_bundle_hex'])
        bundle.write_bytes(git_bytes)
        subject = recompute(bundle, selection['git_sha256'])
    require(selection['proposal_sha256'] == SUBJECT_SHA and bytes.fromhex(package['subject']) == subject,
            'receipt subject differs from the reconstructed Git change')
    signer = selection['author']
    reviewers = selection['providers']
    require(len(reviewers) == 2 and len(set([signer, selection['requester'], *reviewers])) == 4,
            'expected distinct author, original requester and two reviewers')
    received = read('verified')
    enrollment = json.loads(bytes.fromhex(package['enrollment']))
    result = json.loads(bytes.fromhex(package['result']))
    require(package['requester_key'] == selection['requester'] and enrollment['providers'] == reviewers
            and enrollment['scope'] == received['scope'] and received['providers'] == reviewers
            and enrollment['scope']['source_publisher_key'] == signer
            and sha(bytes.fromhex(package['subject_manifest'])) == selection['subject_manifest']
            and enrollment['scope']['source_manifest_id'] == selection['subject_manifest']
            and enrollment['scope']['source_sha256'] == SUBJECT_SHA
            and received['review'] == result and result['complete'] is True
            and result['network_policy_activation'] is False and len(package['stages']) == 4
            and all(json.loads(bytes.fromhex(stage['provider_transcript']))['transcript_hex'] for stage in package['stages'])
            and received['repository_ref_updated'] is False and received['release_authorized'] is False,
            'inconsistent signed claim, selected authorities or native replay')
    verify_publication(checks, bytes.fromhex(package['subject_manifest']), signer, subject)
    for index, stage in enumerate(package['stages']):
        verify_transcript(checks, stage, reviewers[index % 2], selection['requester'])
    for kind, payload in (('git', git_bytes), ('assessment', packed)):
        verify_deposit(checks, read(kind + '-deposit'), bytes.fromhex(read('source')[kind + '_manifest_hex']),
                       signer, selection['holder'], payload, read(kind + '-export'))
    require(selection['holder'] in reviewers and selection['holder'] != selection['requester']
            and sha(packed) == selection['received_review_sha256']
            and read('rejections') == {'author_selection': 'compute_repository_proposal_binding',
                                       'recipient_selection': 'compute_repository_proposal_binding'},
            'original participant, receiver bytes or rejected bindings missing')


def status(directory, revision):
    report = json.loads((directory / (PREFIX + 'smoke.json')).read_bytes())
    require(report['revision'] == revision and report['status'] == 0 and report['cleanup'] is True
            and report['remaining'] == 0 and report['host_state']['unchanged'] is True,
            'run or cleanup incomplete')
    for when in ('before', 'after'):
        require(sha((directory / f'host-state-{when}.json').read_bytes()) == report['host_state'][when + '_sha256'],
                'host snapshot changed')
    verify_originals(directory)


def self_test():
    with tempfile.TemporaryDirectory() as temp:
        root = Path(temp)
        prepare(root)
        bundle = root / 'git.bundle'
        digest = sha(bundle.read_bytes())
        require(recompute(bundle, digest) == (root / 'subject.txt').read_bytes(), 'fresh selection mismatch')
        for expected, base, candidate, path in (
                ('f' * 64, BASE, CANDIDATE, 'README'), (digest, GIT['COMMITS'][0], CANDIDATE, 'README'),
                (digest, BASE, CANDIDATE, 'other.txt'), (digest, BASE, BASE, 'README')):
            try:
                SUBJECT(bundle, expected, GIT['REPOSITORY'], base, candidate, path)
            except (ValueError, subprocess.SubprocessError):
                continue
            raise ValueError('wrong Git binding unexpectedly accepted')


def main():
    action, *args = sys.argv[1:]
    if action == 'prepare':
        prepare(Path(args[0]))
    elif action == 'self-test':
        self_test()
    elif action == 'report':
        status(Path(args[0]), args[1])
    elif action == 'evidence':
        verify_originals(Path(args[0]))
    else:
        raise ValueError('unknown action')


if __name__ == '__main__':
    main()
