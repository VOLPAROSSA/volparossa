#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-only
"""Pure v2 dispatch/evidence contracts; these are not live daemon/overlay proof."""
from pathlib import Path
import runpy
import subprocess
import tarfile
import tempfile
import unittest

HERE = Path(__file__).parent
ADAPTIVE = runpy.run_path(str(HERE / 'private-storage-adaptive-maintenance-smoke.py'))['G']
OLD = runpy.run_path(str(HERE / 'test-private-storage-maintenance-smoke.py'))
WIRING = runpy.run_path(str(HERE / 'test-private-storage-maintenance-wiring.py'))
SCENARIO = 'private-storage-adaptive-maintenance'


def fixture():
    value = OLD['fixture']()
    value['upload'].update(enrollment_version=2, authorized_source_indexes=[0, 1, 2],
        fixed_a_v1_enrollment_preserved=True)
    value['restore'].update(survivor_provider_indexes=[0, 2],
        fixed_a_v1_turn_observed_b_failure=True, fixed_a_v1_new_placements=0,
        fixed_a_v1_physical_payload_charge=2 * ADAPTIVE['BYTES'], selected_source_provider_index=1)
    value['withdrawal'].pop('first_provider_stopped_before_restore')
    value['withdrawal'].pop('first_store_retained')
    value['withdrawal'].update(withdrawn_provider_index=1, withdrawn_provider_node='relay5',
        withdrawn_provider_stopped_before_restore=True, withdrawn_store_retained=True)
    for label in ('uploaded_usage', 'restored_usage'):
        value[label][0], value[label][1] = value[label][1], value[label][0]
    traffic = value['network']['restore']['privacy']['exit']['provider_application']
    traffic['relay4'], traffic['relay5'] = traffic['relay5'], traffic['relay4']
    return value


def report(value):
    result = OLD['report'](value)
    result.update(report_kind='volparossa-' + SCENARIO, phase=SCENARIO + '-complete')
    return result


class AdaptiveMaintenanceContracts(unittest.TestCase):
    def test_separate_v1_and_v2_receipts_do_not_substitute_for_each_other(self):
        value = fixture()
        ADAPTIVE['validate_evidence'](value)
        ADAPTIVE['validate_report'](report(value), '1' * 40)
        OLD['CHECK']['validate_report'](OLD['report'](OLD['fixture']()), '1' * 40)
        with self.assertRaises(ValueError):
            ADAPTIVE['validate_evidence'](OLD['fixture']())
        with self.assertRaises(ValueError):
            OLD['CHECK']['validate_evidence'](value)
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            OLD['OLD']['write_evidence'](root, value)
            self.assertEqual(ADAPTIVE['evidence'](root), value)

    def test_fixed_a_baseline_b_repair_authority_accounting_and_network_are_required(self):
        for mutate in (
            lambda v: v['upload'].update(enrollment_version=1),
            lambda v: v['upload'].update(authorized_source_indexes=[0]),
            lambda v: v['upload'].update(fixed_a_v1_enrollment_preserved=False),
            lambda v: v['restore'].update(fixed_a_v1_turn_observed_b_failure=False),
            lambda v: v['restore'].update(fixed_a_v1_new_placements=1),
            lambda v: v['restore'].update(fixed_a_v1_physical_payload_charge=0),
            lambda v: v['restore'].update(selected_source_provider_index=0),
            lambda v: v['restore'].update(survivor_provider_indexes=[1, 2]),
            lambda v: v['restore'].update(uncertain_payload_charge=0),
            lambda v: v['restored_usage'][1].update(committed_bytes=0),
            lambda v: v['withdrawal'].update(withdrawn_provider_node='relay4'),
            lambda v: v['network']['restore']['privacy']['exit']['provider_application']['relay5'].update(response_payload_bytes=1),
            lambda v: v['network']['restore']['privacy']['client'].update(direct_client_exit_packets=1),
            lambda v: v['private_cleanup'].update(enrollment_checkpoint_removed=False),
        ):
            value = fixture()
            mutate(value)
            with self.assertRaises(ValueError):
                ADAPTIVE['validate_evidence'](value)

    def test_retirement_fresh_readback_is_not_a_new_placement(self):
        before = dict(placement_authorizations=3, retained_copy_records=11)
        for fresh in (0, 1):
            ADAPTIVE['validate_retirement_progress'](before, dict(before),
                dict(freshly_verified_replacements=fresh))
        for value, detail in ((dict(before, placement_authorizations=4), {}),
                              (dict(before, retained_copy_records=12), {}),
                              (dict(before), dict(freshly_verified_replacements=2))):
            with self.assertRaises(ValueError):
                ADAPTIVE['validate_retirement_progress'](before, value, detail)

    def test_actual_b_loss_geometry_requires_two_surviving_reconstructions(self):
        value = fixture()
        traffic = value['network']['restore']['privacy']['exit']['provider_application']
        minimum_a = 2 * (ADAPTIVE['CHUNK'] + ADAPTIVE['LENGTHS'][-1])
        minimum_c = 4 * ADAPTIVE['CHUNK']
        traffic['relay4']['response_payload_bytes'] = minimum_a
        traffic['relay3']['response_payload_bytes'] = minimum_c
        ADAPTIVE['validate_evidence'](value)
        for node, minimum in (('relay4', minimum_a), ('relay3', minimum_c)):
            traffic[node]['response_payload_bytes'] = minimum - 1
            with self.assertRaises(ValueError):
                ADAPTIVE['validate_evidence'](value)
            traffic[node]['response_payload_bytes'] = minimum

    def test_both_scenarios_preview_and_reset_without_a_vm(self):
        for script in ('kvm-alpha-topology.sh', 'run-alpha-topology-vm.sh'):
            for previous, selected in ((SCENARIO, 'private-storage-maintenance'),
                                       ('private-storage-maintenance', SCENARIO),
                                       (SCENARIO, 'private-storage-fragments')):
                result = subprocess.run(['sh', str(HERE / script), '--preview', '--scenario', previous,
                    '--scenario', selected], capture_output=True, text=True, timeout=10, check=True)
                self.assertIn('PREVIEW ONLY', result.stdout)
                self.assertIn(selected, result.stdout.lower())
                self.assertNotIn(previous, result.stdout.lower())

    def test_adaptive_exports_and_physical_withdrawal_are_explicit(self):
        diagnostic = WIRING['diagnostics']()
        self.assertEqual(set(ADAPTIVE['EXPORT_NAMES']), diagnostic['ADAPTIVE_MAINTENANCE_NAMES'])
        self.assertNotIn('private-storage-maintenance-smoke.json', ADAPTIVE['EXPORT_NAMES'])
        source = (HERE / 'private-storage-fragments-smoke.sh').read_text()
        self.assertIn('storage_withdrawn_node=relay5', source)
        self.assertIn('storage_survivor_node=relay4', source)
        self.assertIn('content_custody_cli "$storage_withdrawn_node" content status', source)
        self.assertIn('private_storage_fragments_reopen "$storage_survivor_node" relay3', source)
        guest = (HERE / 'kvm-alpha-topology.sh').read_text()
        self.assertIn(SCENARIO + ') scenario=content-custody; private_storage_fragments=yes; private_storage_maintenance=yes; private_storage_adaptive_maintenance=yes;', guest)
        self.assertIn('"$WORK/bin/private-storage-adaptive-maintenance-smoke.py"', guest)
        driver = (HERE / 'run-alpha-topology-vm.sh').read_text()
        self.assertIn('[ "$scenario" != ' + SCENARIO + ' ] || driver_time_bound=3600s', driver)
        workflow = (HERE.parents[1] / '.github/workflows/alpha-topology.yml').read_text()
        self.assertIn('          - ' + SCENARIO + '\n', workflow)

    def test_interrupted_adaptive_export_excludes_private_enrollments(self):
        diagnostic = WIRING['diagnostics']()
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            home = root / 'home'
            published = home / 'alpha-output'
            published.mkdir(parents=True)
            for name in ADAPTIVE['EXPORT_NAMES']:
                (published / name).write_text('{}\n')
            for name in ('enrollment.json', 'private-storage-maintenance-smoke.json',
                         'private-storage-adaptive-maintenance-owner.json', 'placement-authorizations.json'):
                (published / name).write_text('PRIVATE_SENTINEL_DO_NOT_EXPORT')
            archive = diagnostic['collect'](home, root / 'missing-opt', 'a' * 40, SCENARIO, 124,
                cgroups=root / 'missing-cgroups', proc=root / 'missing-proc')
            with tarfile.open(archive, 'r:gz') as bundle:
                self.assertEqual(set(bundle.getnames()),
                    {'published/' + name for name in ADAPTIVE['EXPORT_NAMES']} | {'vm-incomplete.json'})
                for member in bundle.getmembers():
                    with bundle.extractfile(member) as stream:
                        self.assertNotIn(b'PRIVATE_SENTINEL_DO_NOT_EXPORT', stream.read())


if __name__ == '__main__':
    unittest.main()
