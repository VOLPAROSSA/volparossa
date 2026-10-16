#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-only
"""Inert shell orchestration checks; no guest, privileges or provider execution."""
import json
import os
from pathlib import Path
import runpy
import subprocess
import tempfile
import unittest

HERE = Path(__file__).resolve().parent
SCRIPT = HERE / 'cloud-upload-maintenance-smoke.sh'
SOURCE = SCRIPT.read_text()
E = runpy.run_path(str(HERE / 'cloud-upload-maintenance-evidence.py'))


class Wiring(unittest.TestCase):
    def test_syntax_and_source_has_no_immediate_actions(self):
        result = subprocess.run(['sh', '-n', str(SCRIPT)], capture_output=True, timeout=5)
        self.assertEqual(result.returncode, 0, result.stderr)
        result = subprocess.run(['sh', '-c', '. "$1"', 'inert', str(SCRIPT)], capture_output=True, timeout=5)
        self.assertEqual((result.returncode, result.stdout, result.stderr), (0, b'', b''))

    def test_explicit_profile_and_existing_completed_consumer_are_required(self):
        for existing, new, joined, failure in [('no', 'yes', 'yes', 'CLOUD_UPLOAD_PROFILE_INVALID'),
                ('yes', 'no', 'yes', 'CLOUD_UPLOAD_PROFILE_INVALID'),
                ('yes', 'yes', 'no', 'CLOUD_UPLOAD_PRIOR_CONSUMER_NOT_JOINED')]:
            script = '. "$1"; fail() { echo "$1"; exit 1; }; private_storage_maintenance=$2; cloud_upload_maintenance=$3; consumer_private_cleanup_complete=$4; private_cloud_upload_run'
            result = subprocess.run(['sh', '-c', script, 'inert', str(SCRIPT), existing, new, joined],
                capture_output=True, text=True, timeout=5)
            self.assertEqual((result.returncode, result.stdout.strip()), (1, failure))

    def test_actual_phase_function_uses_new_capture_and_dynamic_owned_minimum(self):
        with tempfile.TemporaryDirectory() as temporary:
            # The only subprocess is sh with all operation functions replaced
            # by inert trace functions, not a simulated network proof.
            script = '''. "$1"
WORK=$2; upload_user=$WORK/u/a; storage_user=$WORK/client-fixtures/private-storage-user
fail() { echo "$1" >&2; exit 1; }
private_cloud_upload_private() {
  if [ "$1" = flow-minimum ]; then
    [ "$2" = finish ] && [ "$3" = "$upload_user" ] || exit 99
    echo 9
  else printf '%s\n' "$*"; fi
}
private_cloud_upload_phase_start() { echo "begin:$upload_phase"; }
private_cloud_upload_phase_finish() { echo "end:$1"; }
private_cloud_upload_phase finish
'''
            result = subprocess.run(['sh', '-c', script, 'inert', str(SCRIPT), temporary],
                capture_output=True, text=True, timeout=5)
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertEqual(result.stdout, 'begin:finish\nend:9\n')
            self.assertEqual((Path(temporary) / 'cloud-upload-finish.json').read_text(),
                f'finish {temporary}/u/a {temporary}/runtime-exit/control/agent.sock {temporary}/client-fixtures/private-storage-user\n')

    def test_failure_keeps_primary_phase_and_skips_successful_capture_finish(self):
        with tempfile.TemporaryDirectory() as temporary:
            script = '''. "$1"
WORK=$2; upload_user=$WORK/u/a; storage_user=$WORK/client-fixtures/private-storage-user
fail() { echo "$1"; exit 1; }
private_cloud_upload_private() { if [ "$1" = flow-minimum ]; then echo 24; else return 1; fi; }
private_cloud_upload_phase_start() { :; }
private_cloud_upload_phase_finish() { echo FALSE_SUCCESS; }
private_cloud_upload_phase upload
'''
            result = subprocess.run(['sh', '-c', script, 'inert', str(SCRIPT), temporary],
                capture_output=True, text=True, timeout=5)
            self.assertEqual((result.returncode, result.stdout.strip()), (1, 'CLOUD_UPLOAD_APPLICATION_FAILED'))

    def test_real_sequence_uses_same_stores_zero_gate_and_new_mount_probe(self):
        tokens = ['CLOUD_UPLOAD_INITIAL_STORE_NOT_EMPTY', 'upload_user=$WORK/u/a',
            'CLOUD_UPLOAD_POSITIVE_ISOLATION_FAILED', 'CLOUD_UPLOAD_LOCAL_SHORTCUT',
            'private_cloud_upload_private prepare', 'private_cloud_upload_phase upload',
            'private_storage_fragments_usage cloud_upload_uploaded_usage',
            'private_storage_fragments_reopen relay5 relay3', 'CLOUD_UPLOAD_SOURCE_STILL_SERVING',
            'private_cloud_upload_phase exercise', 'private_storage_fragments_usage cloud_upload_restored_usage',
            'private_cloud_upload_phase finish', 'private_storage_fragments_usage cloud_upload_deleted_usage',
            'CLOUD_UPLOAD_PROVIDER_CLEANUP_INCOMPLETE', 'private_cloud_upload_cleanup ||',
            'evidence-v8 "$WORK" "$WORK/cloud-upload-evidence.json"']
        offsets = [SOURCE.index(token) for token in tokens]
        self.assertEqual(offsets, sorted(offsets))
        self.assertIn('runtime-client/control/agent.sock', SOURCE)
        self.assertIn('--bounding-set=-all --no-new-privs', SOURCE)
        self.assertIn('--signal=TERM --kill-after=30s 2400s', SOURCE)
        self.assertNotIn('rm -rf', SOURCE)
        self.assertNotIn('storage-consumer-maintenance-provision.py', SOURCE)

    def test_current_wrapper_selects_only_dynamic_network_and_original_deadline(self):
        script = '''. "$1"
WORK=/inert; WORKER_UID=2001; WORKER_GID=2001; custody_control_gid=2002
provider_baseline_ms=123; upload_route_policy=policy; upload_underlay_sha=digest
timeout() {
  printf '%s|%s|%s|%s\n' "$STORAGE_PROOF_BASELINE_MS" "$STORAGE_PROOF_ROUTE_POLICY" "$STORAGE_PROOF_UNDERLAY_SHA256" "$*"
}
private_cloud_upload_private upload /inert/u/a
'''
        result = subprocess.run(['sh', '-eu', '-c', script, 'inert', str(SCRIPT)],
            capture_output=True, text=True, check=True, timeout=5)
        self.assertEqual(result.stdout, '123|policy|digest|--signal=TERM --kill-after=30s 2400s setpriv '
            '--reuid=2001 --regid=2001 --groups=2002 --inh-caps=-all --ambient-caps=-all '
            '--bounding-set=-all --no-new-privs -- python3 -B /inert/bin/cloud-upload-maintenance-smoke.py '
            'upload /inert/u/a --profile-version 6 --network-version 2\n')
        self.assertNotIn('STORAGE_PROOF_ROUTE_SCOPE', SOURCE)
        self.assertIn("jq -e '.schema_version == 10'", SOURCE)
        self.assertIn('finalize-report-v8', SOURCE)
        self.assertIn('check-report-v8', SOURCE)
        for old_selector in ('--profile-version 3', '--profile-version 4',
                'evidence-v5', 'finalize-report-v5', 'check-report-v5', 'export-names-v5',
                'evidence-v6', 'finalize-report-v6', 'check-report-v6', 'export-names-v6'):
            self.assertNotIn(old_selector, SOURCE)

    def test_current_prior_profile_gate_rejects_legacy_before_any_owner_or_service_action(self):
        for version in (1, 2, 3, 4, 5, 6, 7, 8, True, 9, 10, 11):
            with tempfile.TemporaryDirectory() as temporary:
                root = Path(temporary)
                (root / 'storage-consumer-evidence.json').write_text(
                    json.dumps({'schema_version': version}))
                (root / 'private-storage-fragments-consumer_deleted_usage.json').write_text(
                    json.dumps([dict(reserved_bytes=0, committed_bytes=0, leases=0)] * 3))
                script = '''. "$1"
WORK=$2; source_directory=/inert; WORKER_UID=2001; WORKER_GID=2001
private_storage_maintenance=yes; cloud_upload_maintenance=yes; consumer_private_cleanup_complete=yes
fail() { echo "$1"; exit 1; }
# Isolate the explicit version gate; the real evidence validator has its own
# closed-schema tests. Stop at the first owner-creation operation without I/O.
python3() { [ "$3" = check ]; }
install() { echo REACHED_OWNER_BOUNDARY; exit 73; }
private_cloud_upload_run
'''
                result = subprocess.run(['sh', '-eu', '-c', script, 'inert', str(SCRIPT), temporary],
                    capture_output=True, text=True, timeout=5)
                expected = (73, 'REACHED_OWNER_BOUNDARY') if type(version) is int and version == 10 else (
                    1, 'CLOUD_UPLOAD_PRIOR_CONSUMER_PROFILE_INVALID')
                self.assertEqual((result.returncode, result.stdout.strip()), expected, result.stderr)
                self.assertFalse((root / 'u').exists())

    def test_network_phase_failure_cannot_proceed_as_application_success(self):
        with tempfile.TemporaryDirectory() as temporary:
            for stage, expected in (('start', 'CLOUD_UPLOAD_NETWORK_START_FAILED'),
                    ('finish', 'CLOUD_UPLOAD_NETWORK_FINISH_FAILED')):
                script = '''. "$1"
WORK=$2; upload_user=$WORK/u/a; storage_user=$WORK/client-fixtures/private-storage-user
failed=$3
fail() { echo "$1"; exit 1; }
private_cloud_upload_private() { if [ "$1" = flow-minimum ]; then echo 24; else echo '{}'; fi; }
private_cloud_upload_phase_start() { [ "$failed" != start ]; }
private_cloud_upload_phase_finish() { [ "$failed" != finish ]; }
private_cloud_upload_phase upload
echo FALSE_SUCCESS
'''
                result = subprocess.run(['sh', '-c', script, 'inert', str(SCRIPT), temporary, stage],
                    capture_output=True, text=True, timeout=5)
                self.assertEqual((result.returncode, result.stdout.strip()), (1, expected))

    def test_finish_joins_both_capture_families_before_allowing_gates(self):
        with tempfile.TemporaryDirectory() as temporary:
            for failed in ('privacy', 'control', 'none'):
                script = '''. "$1"
WORK=$2; failed=$3; storage_user=$WORK/client-fixtures/private-storage-user
storage_phase=cloud-upload-exercise; upload_phase=exercise; provider_baseline_ms=123
benchmark_capture_paths() { echo "paths:$*"; }
python3() { echo "python:$*"; }
private_cloud_upload_readback() { echo "readback:$1"; }
stop_privacy_observers() { echo privacy; [ "$failed" != privacy ]; }
storage_consumer_stop_captures() { echo control; [ "$failed" != control ]; }
private_cloud_upload_phase_finish 16
'''
                result = subprocess.run(['sh', '-c', script, 'inert', str(SCRIPT), temporary, failed],
                    capture_output=True, text=True, timeout=5)
                self.assertEqual(result.returncode, 0 if failed == 'none' else 1, result.stderr)
                self.assertTrue(result.stdout.endswith('readback:after\nprivacy\ncontrol\n'))
                self.assertIn('flow-cloud-upload-exercise.json', result.stdout)
                gate = Path(temporary) / 'private-storage-fragments-cloud-upload-exercise-gates.json'
                self.assertEqual(gate.exists(), failed == 'none')

    def test_capture_pids_registered_before_readiness_failure(self):
        with tempfile.TemporaryDirectory() as temporary:
            script = '''. "$1"
WORK=$2; upload_phase=upload; cloud_upload_maintenance=yes; private_storage_maintenance=yes
PROVIDER_CONTROL_PID=; CONSUMER_CONTROL_0_PID=; CONSUMER_CONTROL_1_PID=; CONSUMER_CONTROL_2_PID=
content_provider_node() { provider_ns=inert; provider_ip=$1; }
ip() { printf '%s\n' "$*"; }
wait_observer() {
  case "$2" in
    *-relay0.ready) [ "$1" = "$CONSUMER_CONTROL_0_PID" ] || exit 99 ;;
    *-relay1.ready) [ "$1" = "$CONSUMER_CONTROL_1_PID" ] || exit 98; return 1 ;;
    *) exit 97 ;;
  esac
}
result=0
private_cloud_upload_start_captures || result=$?
[ "$result" = 1 ] && [ -n "$CONSUMER_CONTROL_0_PID" ] && [ -n "$CONSUMER_CONTROL_1_PID" ] && [ -z "$CONSUMER_CONTROL_2_PID" ] || exit 96
wait "$CONSUMER_CONTROL_0_PID"
wait "$CONSUMER_CONTROL_1_PID"
'''
            subprocess.run(['sh', '-eu', '-c', script, 'inert', str(SCRIPT), temporary],
                capture_output=True, text=True, check=True, timeout=5)
            for broker in (0, 1):
                text = (Path(temporary) / f'cloud-upload-upload-control-relay{broker}.log').read_text()
                self.assertIn(f'--consumer-control=relay{broker}', text)
                self.assertIn(f'cc{broker}0 cc{broker}1 cc{broker}2', text)
            self.assertFalse((Path(temporary) / 'cloud-upload-upload-control-relay2.log').exists())

    def test_readback_never_overwrites_original_or_existing_proof(self):
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / 'cloud-upload-finish-control-before.json'
            path.write_text('retained proof')
            script = '''. "$1"
WORK=$2; upload_phase=finish
storage_consumer_control_snapshot() { :; }
jq() { echo FALSE_REPLACEMENT; }
private_cloud_upload_readback before
'''
            result = subprocess.run(['sh', '-eu', '-c', script, 'inert', str(SCRIPT), temporary],
                capture_output=True, text=True, timeout=5)
            self.assertEqual(result.returncode, 1)
            self.assertEqual(path.read_text(), 'retained proof')
            self.assertIn('cloud-upload-$upload_phase-control-$upload_readback_stage.json', SOURCE)

    def test_current_export_keeps_large_joined_proof_only_at_exact_name(self):
        for name, version, size, passed in (
                ('cloud-upload-evidence.json', 3, 1050000, True),
                ('cloud-upload-evidence.json', 4, 1050000, True),
                ('cloud-upload-evidence.json', 5, 1050000, True),
                ('cloud-upload-evidence.json', 6, 1050000, True),
                ('cloud-upload-evidence.json', 7, 1050000, True),
                ('cloud-upload-evidence.json', 8, 1050000, True),
                ('cloud-upload-evidence.json', 9, 1050000, False),
                ('cloud-upload-evidence.json', 2, 1050000, False),
                ('cloud-upload-evidence.json', 3, 2097153, False),
                ('cloud-upload-evidence.json', 4, 2097153, False),
                ('cloud-upload-evidence.json', 5, 2097153, False),
                ('cloud-upload-evidence.json', 6, 2097153, False),
                ('cloud-upload-evidence.json', 7, 2097153, False),
                ('cloud-upload-evidence.json', 8, 2097153, False),
                ('cloud-upload-prepare.json', 8, 1050000, False),
                ('cloud-upload-prepare.json', 6, 1050000, False),
                ('cloud-upload-prepare.json', 7, 1050000, False),
                ('cloud-upload-prepare.json', 3, 1050000, False)):
            with tempfile.TemporaryDirectory() as temporary:
                root = Path(temporary); output = root / 'export'; output.mkdir()
                raw = json.dumps(dict(schema_version=version, kind='cloud-upload-maintenance-evidence',
                    padding='x' * size)).encode()
                (root / name).write_bytes(raw)
                script = '''. "$1"
WORK=$2; output_directory=$WORK/export; export_name=$3
OUTPUT_UID=$4; OUTPUT_GID=$5; source_directory=/inert
expected_commit=inert; RUN_ID=inert; PHASE=inert; CLEANUP_COMPLETE=true
REMAINING_OWNED_OBJECTS=0; OBSERVED_BLOCKER=NONE
python3() { if [ "$3" = export-names-v8 ]; then printf '%s\n' "$export_name"; fi; }
private_cloud_upload_finalize_report 0
'''
                result = subprocess.run(['sh', '-eu', '-c', script, 'inert', str(SCRIPT), temporary,
                    name, str(os.getuid()), str(os.getgid())], capture_output=True, text=True, timeout=5)
                self.assertEqual(result.returncode == 0, passed, result.stderr)
                self.assertEqual((output / name).exists(), passed)
                if passed:
                    self.assertEqual((output / name).read_bytes(), raw)

    def test_cleanup_idempotent_and_preserves_unknown_sibling(self):
        with tempfile.TemporaryDirectory() as temporary:
            work = Path(temporary)
            (work / 'u').mkdir()
            (work / 'u/sibling').mkdir()
            script = '''. "$1"
WORK=$2; upload_user=$WORK/u/a
private_cloud_upload_private() { echo '{}'; }
private_cloud_upload_cleanup
'''
            result = subprocess.run(['sh', '-c', script, 'inert', str(SCRIPT), temporary],
                capture_output=True, timeout=5)
            self.assertNotEqual(result.returncode, 0)
            self.assertTrue((work / 'u/sibling').exists())
            (work / 'u/sibling').rmdir()
            result = subprocess.run(['sh', '-c', script + '\nprivate_cloud_upload_cleanup\n', 'inert', str(SCRIPT), temporary],
                capture_output=True, timeout=5)
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertFalse((work / 'u').exists())

    def test_exact_static_proof_union_is_measured_before_runner_wiring(self):
        previous = runpy.run_path(str(HERE / 'private-storage-maintenance-smoke.py'))['EXPORT_NAMES']
        self.assertEqual(len(set(previous)), 115)
        self.assertIn('private-storage-provider-activity.json', previous)
        self.assertIn('private-storage-fixture-correlation.json', previous)
        self.assertIn('private-storage-maintenance-helper-acquire.json', previous)
        self.assertEqual(len(set(E['EXPORT_NAMES']) - set(previous)), 40)
        self.assertEqual(len(set(E['EXPORT_NAMES']) | set(previous)), 155)
        current = set(E['EXPORT_NAMES']) | set(E['CURRENT_EXPORT_NAMES'])
        self.assertEqual(len(current | set(previous)), 170)
        # This deliberately excludes emergency driver/current-phase/duplicate
        # receipts; it is NOT a claim that all recovery files fit that cap.
        self.assertNotIn('guest-phase.txt', E['EXPORT_NAMES'])

    def test_kvm_opt_in_preview_and_last_scenario_wins_without_running_it(self):
        guest = HERE / 'kvm-alpha-topology.sh'
        for first, last in (('private-storage-maintenance', 'cloud-upload-maintenance'),
                ('cloud-upload-maintenance', 'private-storage-maintenance')):
            result = subprocess.run(['sh', str(guest), '--preview', '--scenario', first, '--scenario', last],
                capture_output=True, text=True, timeout=5)
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertIn(last + ' protected network smoke plan:', result.stdout)
            self.assertNotIn(first + ' protected network smoke plan:', result.stdout)
            self.assertIn('PREVIEW ONLY', result.stdout)

    def test_exact_new_closure_preflight_and_new_capture_gate(self):
        guest = (HERE / 'kvm-alpha-topology.sh').read_text()
        start = guest.index('if [ "$cloud_upload_maintenance" = yes ]; then\n    for upload_fixture')
        block = guest[start:guest.index('\nfi', start) + 3]
        names = ('cloud-upload-maintenance-smoke.sh', 'cloud-upload-maintenance-smoke.py',
            'cloud-upload-maintenance.mjs', 'cloud-upload-maintenance-pins.json', 'cloud-upload-maintenance-pins-v2.json',
            'cloud-upload-maintenance-pins-v3.json',
            'cloud-upload-maintenance-pins-v4.json',
            'cloud-upload-maintenance-pins-v5.json',
            'cloud-upload-maintenance-pins-v6.json',
            'cloud-upload-maintenance-evidence.py', 'cloud-upload-maintenance-provision.py')
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            target = root / 'tests/integration'
            target.mkdir(parents=True)
            for name in names:
                (target / name).touch()
            def check():
                return subprocess.run(['sh', '-c', 'source_directory=$1; cloud_upload_maintenance=yes;\n' + block,
                    'inert', str(root)], capture_output=True, timeout=5).returncode
            self.assertEqual(check(), 0)
            for name in names:
                path = target / name
                path.unlink()
                self.assertEqual(check(), 69)
                path.symlink_to(target / names[(names.index(name) + 1) % len(names)])
                self.assertEqual(check(), 69)
                path.unlink(); path.touch()
        privacy = 'private-storage-fragments-cloud-upload-upload-privacy|private-storage-fragments-cloud-upload-exercise-privacy|private-storage-fragments-cloud-upload-finish-privacy)\n            [ "$cloud_upload_maintenance" = yes ] || return 1 ;;'
        self.assertIn(privacy, guest)

    def test_hook_follows_old_consumer_before_disconnect_and_cleanup_is_early(self):
        fragments = (HERE / 'private-storage-fragments-smoke.sh').read_text()
        self.assertIn('private_storage_consumer_run\n        if [ "${cloud_upload_maintenance:-no}" = yes ]; then\n            private_cloud_upload_run\n        fi', fragments)
        self.assertLess(fragments.index('            private_cloud_upload_run\n'), fragments.index('    benchmark_disconnect_route private-storage-fragments'))
        guest = (HERE / 'kvm-alpha-topology.sh').read_text()
        self.assertLess(guest.index('        private_cloud_upload_cleanup || original_status=1'),
            guest.index('        private_storage_fragments_cleanup || original_status=1'))
        self.assertIn('private_storage_maintenance_finalize_report "$original_status" || original_status=1\n        if [ "$cloud_upload_maintenance" = yes ]; then\n            private_cloud_upload_finalize_report "$original_status" || original_status=1', guest)
        self.assertIn('cloud-upload-maintenance-smoke.sh"', guest)
        self.assertIn('cloud-upload-maintenance-pins.json"', guest)
        self.assertIn('"$WORK/bin/cloud-upload-maintenance-pins-v3.json"', guest)
        self.assertIn('"$WORK/bin/cloud-upload-maintenance-pins-v4.json"', guest)


if __name__ == '__main__':
    unittest.main()
