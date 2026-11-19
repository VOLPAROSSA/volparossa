#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-only
"""Private handoff boundaries and exact synthetic-vs-owner profile acceptance."""
import json
import os
from pathlib import Path
import runpy
import tempfile
import unittest

HERE = Path(__file__).resolve().parent
SECURE = runpy.run_path(str(HERE / 'image-topology-input.py'))
BASE = runpy.run_path(str(HERE / 'test-image-snapshot-smoke.py'))
CHECK = BASE['CHECK']
DIGEST = SECURE['sha']


def write(path, data):
    path.write_bytes(data)
    path.chmod(0o600)


def owner_evidence(size, digest):
    evidence = BASE['fixture']()
    revision, hashes = CHECK['revision_hashes'](True)
    prepare = evidence['prepare']
    del prepare['plaintext_sha256'], prepare['plaintext_bytes']
    prepare.update(input_kind='owner-immich', image_revision=revision, source_sha256=hashes,
                   ciphertext_bytes=size, cipher_sha256=digest, archive_encryption_proven=False)
    plan = CHECK['configure'](prepare)
    prepare['grant_payload_bytes'] = list(plan['PROVIDER_BYTES'])
    for role in ('prepare', 'upload', 'restore', 'finish'):
        evidence[role]['original_plaintext_preserved'] = False
    evidence['archive_encryption_proven'] = False
    evidence['upload'].update(logical_ciphertext_bytes=size, physical_payload_charge=2 * size)
    evidence['restore'].update(actual_gpg_decryptions=0, plaintext_sha256=[], openpgp_integrity_verified=False,
                               manifest_verified=False, physical_payload_charge=2 * size)
    evidence['private_cleanup'].update(recovery_keys_removed=False, private_plaintext_removed=False)
    for role in ('uploaded_usage', 'restored_usage'):
        evidence[role] = [dict(reserved_bytes=0, committed_bytes=n, leases=count)
                          for n, count in zip(plan['PROVIDER_BYTES'], (3, 3, 2))]
    pins = SECURE['OWNER_PINS']
    evidence['provision'].update(pins=json.loads(pins.read_bytes()), pins_sha256=DIGEST(pins.read_bytes()))
    return evidence


class PrivatePeerSnapshot(unittest.TestCase):
    def setUp(self):
        root = tempfile.TemporaryDirectory()
        self.addCleanup(root.cleanup)
        self.root = Path(root.name)
        self.source, self.output, self.topology = [self.root / n for n in ('in', 'out', 'topology')]
        for path in (self.source, self.output, self.topology):
            path.mkdir(mode=0o700)
        data = bytes(range(251)) * 204 + b'owner'
        self.digest, self.size = DIGEST(data), len(data)
        self.core, self.image = 'a' * 40, 'b' * 40
        receipt = dict(version=1, kind='volparossa-immich-snapshot', cipher_file='snapshot.pgp',
                       cipher_sha256=self.digest, cipher_bytes=self.size, encryption='OpenPGP-AES256',
                       source_consistency='operator-asserted-quiesced-copy')
        write(self.source / 'receipt.json', json.dumps(receipt).encode())
        write(self.source / 'snapshot.pgp', data)
        write(self.output / 'snapshot.pgp', data)
        evidence = owner_evidence(self.size, self.digest)
        state = b'{"state":"synthetic"}\n'
        for phase in ('before', 'after'):
            write(self.topology / f'host-state-{phase}.json', state)
        self.report = dict(schema_version=2, report_kind='volparossa-image-snapshot', source_revision=self.core,
                           success=True, runner_exit_status=0, phase='image-snapshot-complete', observed_blocker=None,
                           cleanup=dict(complete=True, remaining_owned_objects=0),
                           host_state=dict(unchanged=True, before_sha256=DIGEST(state), after_sha256=DIGEST(state)), image=evidence)
        write(self.topology / 'image-snapshot-smoke.json', json.dumps(self.report).encode())
        write(self.topology / 'image-vm-cleanup.json', json.dumps(dict(schema_version=1, source_revision=self.core,
              qemu_started=True, qemu_joined=True, private_guest_state_removed=True)).encode())

    def joined_receipt(self):
        return SECURE['host_receipt'](self.source, self.output, self.topology, self.core, self.image, '1234', '2')

    def test_source_removed_and_independent_return_verified(self):
        self.assertEqual(SECURE['verify'](self.source)['cipher_sha256'], self.digest)
        with self.assertRaises(ValueError):
            self.joined_receipt()
        (self.source / 'snapshot.pgp').unlink()
        record = self.joined_receipt()
        self.assertEqual((record['cipher_bytes'], record['cipher_sha256'], record['peer_restores']), (self.size, self.digest, 2))
        self.assertTrue(record['providers_final_usage_zero'])
        self.assertNotIn('plaintext', json.dumps(record))
        write(self.output / 'snapshot.pgp', b'other')
        with self.assertRaises(ValueError):
            self.joined_receipt()

    def test_guest_admission_consumes_only_original_input(self):
        storage = self.root / 'private-owner'
        storage.mkdir(mode=0o700)
        with self.assertRaises(ValueError):
            CHECK['admit_owner_bundle'](storage, self.source, 'f' * 64)
        self.assertEqual(set(p.name for p in self.source.iterdir()), {'snapshot.pgp', 'receipt.json'})
        record = CHECK['admit_owner_bundle'](storage, self.source, self.digest)
        self.assertEqual(record['input_kind'], 'owner-immich')
        self.assertEqual(SECURE['verify'](storage / 'bundle')['cipher_bytes'], self.size)
        self.assertEqual(list(self.source.iterdir()), [])
        CHECK['verify_source'](storage, record)
        write(storage / 'bundle/recovery.key', b'never received')
        with self.assertRaises(ValueError):
            CHECK['verify_source'](storage, record)

    def test_capture_profile_and_charge_are_bound(self):
        with self.assertRaises(ValueError):
            CHECK['validate_report'](self.report, self.core)
        for field in ('source_ciphertext_absent', 'reads_nonconsuming'):
            restore = self.report['image']['restore']
            restore[field] = False
            with self.assertRaises(ValueError):
                CHECK['validate_report'](self.report, self.core, joined=True)
            restore[field] = True
        self.report['image']['deleted_usage'][0]['leases'] = 1
        with self.assertRaises(ValueError):
            CHECK['validate_report'](self.report, self.core, joined=True)

    def test_private_closed_shape_and_link_count(self):
        write(self.source / 'recovery.key', b'forbidden')
        with self.assertRaises(ValueError):
            SECURE['verify'](self.source)
        (self.source / 'recovery.key').unlink()
        os.link(self.source / 'snapshot.pgp', self.root / 'alias')
        with self.assertRaises(ValueError):
            SECURE['verify'](self.source)
        (self.root / 'alias').unlink()
        (self.source / 'snapshot.pgp').chmod(0o644)
        with self.assertRaises(ValueError):
            SECURE['verify'](self.source)

    def test_four_distinct_fragment_lengths_and_caps(self):
        for size in (16, 17, 51283, 1048576):
            evidence = owner_evidence(size, self.digest)
            plan = CHECK['configure'](evidence['prepare'])
            self.assertEqual(len(plan['LENGTHS']), 4)
            self.assertEqual(sum(plan['LENGTHS']), size)
            self.assertEqual(sum(plan['PROVIDER_BYTES']), 2 * size)
            self.assertTrue(all(0 < n <= 262144 for n in plan['LENGTHS']))
        for size in (15, 1048577):
            with self.assertRaises(ValueError):
                owner_evidence(size, self.digest)


if __name__ == '__main__':
    unittest.main()
