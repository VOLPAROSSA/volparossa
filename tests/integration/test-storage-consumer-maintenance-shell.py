#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-only
"""Inert orchestration contracts; not actual application or network evidence."""
from pathlib import Path
import subprocess
import unittest

HERE = Path(__file__).resolve().parent
SCRIPT = HERE / 'storage-consumer-maintenance-smoke.sh'
TEXT = SCRIPT.read_text()


class ConsumerShell(unittest.TestCase):
    def test_joined_consumer_capacity_fits_both_objects_without_changing_other_profiles(self):
        script = '''
. "$1"
WORK=/synthetic/fixture
content_custody_endpoint() { custody_address=192.0.2.1; custody_hostname=synthetic.invalid; }
content_custody_cli() { printf '%s\\n' "$@" >&2; }
if [ "$2" != unset ]; then private_storage_maintenance=$2; fi
private_storage_replicas_serve relay4 "$3"
'''
        for profile in ('unset', 'no', 'yes'):
            for reuse in ('no', 'yes'):
                with self.subTest(profile=profile, reuse=reuse):
                    result = subprocess.run(['sh', '-eu', '-c', script, 'inert',
                        str(HERE / 'private-storage-replicas-smoke.sh'), profile, reuse],
                        check=True, capture_output=True, text=True, timeout=5)
                    arguments = result.stderr.splitlines()
                    self.assertEqual(arguments[:4], ['relay4', 'storage', 'peer', 'serve'])
                    self.assertIn('/synthetic/fixture/state-relay4/private-store', arguments)
                    if reuse == 'yes':
                        self.assertEqual(arguments[-1], '--reuse-store')
                        self.assertNotIn('--capacity-bytes', arguments)
                    else:
                        capacity = 2 * 1048576 if profile == 'yes' else 1048576
                        self.assertEqual(arguments[-4:], ['--capacity-bytes', str(capacity),
                            '--min-free-bytes', '268435456'])
                    self.assertEqual(result.stdout, '')

    def test_parses_and_sourcing_does_not_start_or_provision_anything(self):
        subprocess.run(['sh', '-n', str(SCRIPT)], check=True, capture_output=True, timeout=5)
        result = subprocess.run(['sh', '-eu', '-c', '. "$1"', 'inert', str(SCRIPT)],
            check=True, capture_output=True, timeout=5)
        self.assertEqual((result.stdout, result.stderr), (b'', b''))

    def test_worker_loses_privileges_and_has_bounded_cancellation(self):
        runner = TEXT.split('private_storage_consumer_private() {', 1)[1].split('\n}', 1)[0]
        for required in ('--kill-after=30s 2400s setpriv', '--reuid="$WORKER_UID"',
                '--regid="$WORKER_GID"', '--groups="$custody_control_gid"',
                '--inh-caps=-all --ambient-caps=-all --bounding-set=-all --no-new-privs',
                'STORAGE_PROOF_BASELINE_MS', 'STORAGE_PROOF_ROUTE_SCOPE'):
            self.assertIn(required, runner)
        self.assertNotIn('eval ', TEXT)
        self.assertNotIn('sudo ', TEXT)

    def test_current_consumer_explicitly_selects_matching_profile_at_all_boundaries(self):
        runner = (HERE / 'run-alpha-topology-vm.sh').read_text()
        guest = (HERE / 'kvm-alpha-topology.sh').read_text()
        self.assertIn('storage-consumer-maintenance-provision.py provision --download --profile-version 9', runner)
        self.assertIn('consumer_profile_version=${storage_consumer_profile_version-7}', TEXT)
        self.assertIn('storage-consumer-maintenance-smoke.py" "$@" --profile-version "$consumer_profile_version"', TEXT)
        self.assertIn('"evidence-v$consumer_profile_version" "$WORK" "$WORK/storage-consumer-evidence.json"', TEXT)
        for name in ('storage-consumer-maintenance-pins.json', 'storage-consumer-maintenance-pins-v2.json',
                'storage-consumer-maintenance-pins-v3.json', 'storage-consumer-maintenance-pins-v4.json',
                'storage-consumer-maintenance-pins-v5.json', 'storage-consumer-maintenance-pins-v6.json',
                'storage-consumer-maintenance-pins-v7.json', 'storage-consumer-maintenance-pins-v8.json',
                'storage-consumer-maintenance-pins-v9.json'):
            self.assertIn(f'"$source_directory/tests/integration/{name}"', guest)
            self.assertIn(f'"$WORK/bin/{name}"', guest)

    def test_explicit_profiles_eight_and_nine_keep_privilege_deadline_and_default_unchanged(self):
        script = '''
. "$1"
WORK=/synthetic/fixture
WORKER_UID=123
WORKER_GID=124
custody_control_gid=125
fail() { printf '%s\\n' "$1" >&2; return 1; }
timeout() { printf '%s\\n' "$@"; }
if [ "$2" != unset ]; then storage_consumer_profile_version=$2; fi
private_storage_consumer_private publish /synthetic/owner
'''
        for profile in ('unset', '7', '8', '9', '1', '10', 'true', '', '8 --untrusted'):
            result = subprocess.run(['sh', '-eu', '-c', script, 'inert', str(SCRIPT), profile],
                capture_output=True, text=True, timeout=5)
            if profile in ('unset', '7', '8', '9'):
                self.assertEqual(result.returncode, 0, result.stderr)
                args = result.stdout.splitlines()
                self.assertEqual(args[:4], ['--signal=TERM', '--kill-after=30s', '2400s', 'setpriv'])
                self.assertEqual(args[-4:], ['--profile-version', '7' if profile == 'unset' else profile, '--network-version', '2'])
                self.assertEqual(args.count('--profile-version'), 1)
            else:
                self.assertNotEqual(result.returncode, 0)
                self.assertEqual(result.stdout, '')
                self.assertEqual(result.stderr.strip(), 'CONSUMER_PROFILE_INVALID')

    def test_each_consumer_phase_gets_its_own_actual_network_observation(self):
        phase = TEXT.split('private_storage_consumer_phase() {', 1)[1].split('\n}', 1)[0]
        self.assertIn('case $1 in publish|exercise|finish)', phase)
        self.assertIn('flow-minimum "$consumer_phase"', phase)
        self.assertIn('storage_consumer_phase_start || fail CONSUMER_NETWORK_START_FAILED', phase)
        self.assertIn('"$WORK/runtime-exit/control/agent.sock" "$storage_user"', phase)
        self.assertLess(phase.index('storage_consumer_phase_start'),
            phase.index('private_storage_consumer_private "$consumer_phase"'))
        self.assertLess(phase.index('private_storage_consumer_private "$consumer_phase"'),
            phase.index('storage_consumer_phase_finish "$consumer_minimum"'))

    def test_same_provider_stores_are_withdrawn_before_read_and_reopened_before_delete(self):
        run = TEXT.split('private_storage_consumer_run() {', 1)[1]
        ordered = ('CONSUMER_INITIAL_STORE_NOT_EMPTY', 'CONSUMER_OWNER_PARENT_NOT_NEW',
            'private_storage_fragments_reopen relay4 relay5 relay3',
            'private_storage_consumer_private prepare', 'private_storage_consumer_phase publish',
            'private_storage_fragments_usage consumer_uploaded_usage',
            'private_storage_fragments_reopen relay5 relay3', 'CONSUMER_SOURCE_STILL_SERVING',
            'CONSUMER_SURVIVOR_NOT_SERVING', 'private_storage_consumer_phase exercise',
            'private_storage_fragments_usage consumer_restored_usage',
            'private_storage_fragments_reopen relay4 relay5 relay3',
            'private_storage_consumer_phase finish', 'private_storage_fragments_usage consumer_deleted_usage',
            'CONSUMER_PROVIDER_CLEANUP_INCOMPLETE', 'private_storage_consumer_cleanup')
        offset = 0
        for fragment in ordered:
            offset = run.index(fragment, offset) + len(fragment)
        self.assertEqual(run.count('all(.[]; . == {reserved_bytes:0,committed_bytes:0,leases:0})'), 2)

    def test_local_cleanup_does_not_claim_remote_deletion_or_remove_a_broad_tree(self):
        cleanup = TEXT.split('private_storage_consumer_cleanup() {', 1)[1].split('\n}', 1)[0]
        self.assertIn('consumer_private_cleanup_complete:-no', cleanup)
        self.assertIn('private_storage_consumer_private cleanup "$consumer_user"', cleanup)
        self.assertIn('rmdir "$WORK/u" || return 1', cleanup)
        cleanup = TEXT.split('private_storage_consumer_cleanup() {', 1)[1].split('\n}', 1)[0]
        self.assertNotIn('rm -', cleanup)
        self.assertEqual([line.strip() for line in TEXT.splitlines() if 'rm -' in line],
            ['rm -f -- "$WORK/provider-activity.part" || true'])
        self.assertNotIn('consumer-binding.json', TEXT)
        self.assertNotIn('remote_cleanup_confirmed:true', TEXT)

    def test_current_agent_cannot_read_new_owner_root_or_any_provider_store(self):
        run = TEXT.split('private_storage_consumer_run() {', 1)[1]
        self.assertIn('--property=MainPID --value volparossa-alpha-agent@client.service', run)
        self.assertIn('--target "$consumer_client_pid" --mount setpriv', run)
        self.assertIn('-- test -r "$WORK/state-client/identity.key" || fail CONSUMER_POSITIVE_ISOLATION_FAILED', run)
        self.assertIn('for consumer_private in "$consumer_user"', run)
        for peer in ('relay4', 'relay5', 'relay3'):
            self.assertIn(f'"$WORK/state-{peer}/private-store"', run)
        self.assertIn('-- test -r "$consumer_private"; then fail CONSUMER_LOCAL_SHORTCUT', run)
        self.assertLess(run.index('CONSUMER_LOCAL_SHORTCUT'), run.index('private_storage_consumer_private prepare'))
        self.assertIn('"$WORK/storage-consumer-isolation.json"', run)


if __name__ == '__main__':
    unittest.main()
