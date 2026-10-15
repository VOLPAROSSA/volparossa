#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-only
"""Inert dispatch/export/child-lifecycle tests, never real core or network proof."""
import copy
import hashlib
import io
import json
import os
from pathlib import Path
import runpy
import select
import signal
import stat
import subprocess
import sys
import tarfile
import tempfile
import time
import unittest
from unittest.mock import patch

HERE = Path(__file__).resolve().parent
SCENARIO = 'private-storage-maintenance'
M = runpy.run_path(str(HERE / (SCENARIO + '-smoke.py')))
FIXTURE = runpy.run_path(str(HERE / ('test-' + SCENARIO + '-smoke.py')))
DIAGNOSTICS = runpy.run_path(str(HERE / 'test-private-storage-fragments-wiring.py'))['diagnostics']


def retained_private_fixture(root, pending=True):
    """Synthetic bound private files, not signatures, provider I/O or kernel proof."""
    value, _, keys = FIXTURE['OLD']['cli_fixture']('committed')
    value['operation'] = 'private_storage_fragments_status'
    now = int(time.time())
    owner = [77] * 32
    grants = [b'synthetic grant ' + bytes([index]) for index in range(3)]

    def save(path, data):
        path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        path.write_bytes(data if isinstance(data, bytes) else json.dumps(data, sort_keys=True).encode())
        path.chmod(0o600)

    fragments = []
    children = []
    for index, length in enumerate(M['LENGTHS']):
        copies, records = [], []
        digest = list(hashlib.sha256(bytes([index]) * length).digest())
        for copy_index in range(2):
            provider = (index + copy_index) % 3
            archive = [index * 2 + copy_index + 1] * 32
            journal = dict(version=1, provider_key=list(bytes.fromhex(keys[provider])), owner_key=owner,
                grant_hex=grants[provider].hex(), archive_id=archive, ciphertext_bytes=length, sha256=digest,
                requested_expiry=now + 1800, lease='synthetic-lease-' + str(2 * index + copy_index),
                last_stored_bytes=length, last_expiry=now + 3600, last_state=3)
            save(root / f'fragment-set/fragment-{index:04}/copy-{copy_index}/archive.json', journal)
            copies.append(dict(provider=provider, archive_id=archive))
            records.append(dict(provider_key=journal['provider_key'], archive_id=archive,
                grant_sha256=list(hashlib.sha256(grants[provider]).digest()), charge='committed'))
        fragments.append(dict(offset=sum(M['LENGTHS'][:index]), length=length, sha256=digest, copies=copies))
        children.append(dict(version=1, owner_key=owner, ciphertext_bytes=length, sha256=digest, copies=records))
    save(root / 'fragment-set/fragments.json', dict(manifest=dict(owner_key=owner, fragments=fragments),
        signature='SYNTHETIC_NOT_CRYPTOGRAPHIC_EVIDENCE'))
    original = (root / 'fragment-set/fragments.json').read_bytes()
    en = dict(version=1, owner=owner, root=list(hashlib.sha256(original).digest()),
        source=list(bytes.fromhex(keys[0])), providers=[list(bytes.fromhex(key)) for key in keys[1:]],
        grants=[grant.hex() for grant in grants[1:]], created=now - 60, expires=now + 5940,
        maximum_charged=M['MAX_CHARGE'])
    save(root / 'maintenance/enrollment.json', dict(enrollment=en, signature='SYNTHETIC_NOT_A_SIGNATURE'))
    for label, grant in zip('abc', grants):
        save(root / f'grant-{label}.bin', grant)
    if pending:
        initial = dict(version=1, provider_key=list(bytes.fromhex(keys[2])), owner_key=owner,
            grant_hex=grants[2].hex(), archive_id=[99] * 32, ciphertext_bytes=M['LENGTHS'][0],
            sha256=fragments[0]['sha256'], requested_expiry=now + 5400,
            lease=None, last_stored_bytes=0, last_expiry=0, last_state=None)
        intent = dict(from_=0, to=2, phase='copying', initial_journal=initial)
        intent['from'] = intent.pop('from_')
        save(root / 'fragment-set/placement-authorizations.json', dict(authority=dict(version=1,
            root_sha256=en['root'], placements=[dict(fragment=0, handoff=intent)]),
            signature='SYNTHETIC_NOT_A_SIGNATURE'))
        children[0].update(version=2, handoff=intent)
        children[0]['copies'].append(dict(provider_key=initial['provider_key'], archive_id=initial['archive_id'],
            grant_sha256=list(hashlib.sha256(grants[2]).digest()), charge='unattempted'))
        save(root / 'fragment-set/fragment-0000/copy-2/archive.json', initial)
        value.update(report_version=2, placement_authorizations=1, retained_copy_records=9,
            pending_retirements=1, desired_copies_per_fragment=2, replacement_overhead_included=True)
        value['fragments'][0]['copies'].append(dict(provider_key=keys[2], charge='unattempted',
            last_confirmed_state=None, last_confirmed_stored_bytes=0, last_confirmed_expiry=0))
        for index, copy_index in ((0, 1), (3, 0), (3, 1)):
            value['fragments'][index]['copies'][copy_index]['charge'] = 'uncertain'
            children[index]['copies'][copy_index]['charge'] = 'uncertain'
        value.update(committed_payload_bytes=5 * M['CHUNK'], uncertain_payload_bytes=M['CHUNK'] + 146)
    for index, child in enumerate(children):
        save(root / f'fragment-set/fragment-{index:04}/replicas.json', child)
    save(root / 'identities.sha256', M['F']['identity_digest'](root))
    for path in root.rglob('*'):
        if path.is_dir():
            path.chmod(0o700)
    return value, keys, (root / 'maintenance/enrollment.json').read_bytes(), save


class Wiring(unittest.TestCase):
    def test_preview_is_explicit_and_last_scenario_wins(self):
        for script in ('kvm-alpha-topology.sh', 'run-alpha-topology-vm.sh'):
            for first, last in ((SCENARIO, 'private-storage-peer'), ('private-storage-peer', SCENARIO)):
                result = subprocess.run(['sh', str(HERE / script), '--preview', '--scenario', first,
                    '--scenario', last], text=True, capture_output=True, check=True, timeout=5)
                self.assertIn(last, result.stdout.lower())
                self.assertNotIn(first, result.stdout.lower())
                self.assertIn('PREVIEW ONLY', result.stdout)

    def test_exact_dependency_preflight_rejects_missing_and_symlink(self):
        guest = (HERE / 'kvm-alpha-topology.sh').read_text()
        start = guest.index('if [ "$private_storage_maintenance" = yes ]; then\n    for maintenance_fixture')
        block = guest[start:guest.index('\nfi', start) + 3]
        names = ('private-storage-maintenance-smoke.sh', 'private-storage-maintenance-smoke.py',
            'private-storage-log-sampler.py', 'content-provider-readiness.py', 'storage-provider-activity-sampler.py',
            'storage-consumer-maintenance-smoke.sh', 'storage-consumer-maintenance-smoke.py',
            'storage-consumer-maintenance.mjs', 'storage-consumer-maintenance-pins.json', 'storage-consumer-maintenance-pins-v2.json',
            'storage-consumer-maintenance-pins-v3.json', 'storage-consumer-maintenance-pins-v4.json',
            'storage-consumer-maintenance-pins-v5.json', 'storage-consumer-maintenance-pins-v6.json',
            'storage-consumer-maintenance-pins-v7.json', 'storage-consumer-maintenance-pins-v8.json',
            'storage-consumer-maintenance-pins-v9.json',
            'storage-consumer-control-underlay.sh', 'storage-consumer-control-underlay.py',
            'storage-consumer-network.sh', 'storage-consumer-network.py', 'storage-consumer-route-sampler.py',
            'storage-consumer-maintenance-evidence.py', 'storage-consumer-maintenance-provision.py',
            'image-snapshot-provision.py', 'agent-private-task-code.py', 'agent-private-task-code-pins.json')
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            directory = root / 'tests/integration'
            directory.mkdir(parents=True)
            for name in names:
                (directory / name).touch()
            def invoke():
                return subprocess.run(['sh', '-c', 'source_directory=$1; private_storage_maintenance=yes;\n' + block,
                    'test', str(root)], check=False, timeout=5).returncode
            self.assertEqual(invoke(), 0)
            for name in names:
                path = directory / name
                path.unlink()
                self.assertEqual(invoke(), 69)
                path.symlink_to(directory / names[(names.index(name) + 1) % len(names)])
                self.assertEqual(invoke(), 69)
                path.unlink()
                path.touch()

    def test_current_readiness_and_owned_guest_service_are_preserved(self):
        guest = (HERE / 'kvm-alpha-topology.sh').read_text()
        smoke = (HERE / (SCENARIO + '-smoke.sh')).read_text()
        self.assertNotIn('storage-route-readiness.py', guest + smoke)
        self.assertIn('content-provider-readiness.py', smoke)
        self.assertIn('benchmark_select_route private-storage-maintenance-reconnect mptcp', smoke)
        self.assertIn('retire_unit volparossa-alpha-agent@client.service', smoke)
        self.assertIn('launch_agent client "$CLIENT"', smoke)
        self.assertIn('"/proc/$maintenance_old_pid/ns/net"', smoke)
        self.assertIn('"/proc/$maintenance_new_pid/ns/net"', smoke)
        self.assertIn('[ "$maintenance_control_peer" = "$provider_control_peer" ]', smoke)
        self.assertLess(guest.index('        private_storage_maintenance_join || original_status=1'),
            guest.index('        private_storage_fragments_cleanup || original_status=1'))
        self.assertLess(guest.index('    private_storage_maintenance_run\n'),
            guest.index('    private_storage_fragments_run\n'))
        self.assertIn('private-storage-fragments-lifecycle-privacy)', guest)

    def test_initial_inventory_precedes_connect_only_for_maintenance_and_preserves_failure(self):
        helper = runpy.run_path(str(HERE / 'content-provider-readiness.py'))
        ready = helper['new_record']()
        ready.update(attempts=1, last_query_outcome='complete', outcome='ready', ready=True,
            last_valid_presence={name: True for name in helper['INVENTORY_ROLES']})
        failed = helper['new_record']()
        failed.update(attempts=1, last_query_outcome='partial', outcome='deadline',
            last_valid_presence={name: name != 'exit' for name in helper['INVENTORY_ROLES']})
        guest = (HERE / 'kvm-alpha-topology.sh').read_text()
        start = guest.index('if [ "$private_storage_maintenance" = yes ]; then\n    private_storage_maintenance_run')
        dispatch = guest[start:guest.index('\nif [ "$private_storage_handoff"', start)]
        script = r'''
set -eu
. "$source_directory/tests/integration/private-storage-maintenance-smoke.sh"
fail() { printf '%s\n' "$1" >&2; exit 7; }
ip() { printf '[{"linkinfo":{"info_kind":"veth"},"flags":["UP"]}]\n'; }
python3() {
    if [ "$3" = "$WORK/bin/content-provider-readiness.py" ]; then
        cat "$TEST_INVENTORY"
        return "$TEST_INVENTORY_STATUS"
    fi
    if [ "$3" = inventory-check ]; then
        # Execute the real validator and its original source closure; only the
        # read-only agent inventory is a synthetic fixture in this test.
        command python3 -B "$source_directory/tests/integration/private-storage-maintenance-smoke.py" "$3" "$4" "$5"
        return
    fi
    command python3 "$@"
}
private_storage_fragments_run() {
    if [ "$private_storage_maintenance" = yes ]; then
        test -f "$WORK/private-storage-maintenance-inventory.json"
        test ! -e "$WORK/maintenance-initial-inventory.part"
    fi
    printf 'CONNECT_REACHED\n'
}
''' + dispatch
        cases = ((True, ready, 0, True), (True, failed, 1, True),
            (True, ready, 1, False), (True, {**ready, 'private_extra': 'forbidden'}, 0, False),
            (True, 'x' * 8193, 1, False), (False, failed, 1, False))
        for enabled, value, status, published in cases:
            with self.subTest(enabled=enabled, status=status, value=str(value)[:40]), tempfile.TemporaryDirectory() as temporary:
                work = Path(temporary)
                source = work / 'input.private'
                source.write_text(value if isinstance(value, str) else json.dumps(value))
                source.chmod(0o600)
                result = subprocess.run(['sh', '-c', script], capture_output=True, text=True, timeout=5,
                    env=dict(PATH='/usr/bin:/bin', WORK=str(work), source_directory=str(HERE.parents[1]),
                        CLIENT='inert-no-network', private_storage_maintenance='yes' if enabled else 'no',
                        private_storage_fragments='yes', TEST_INVENTORY=str(source), TEST_INVENTORY_STATUS=str(status)))
                reached = not enabled or value == ready and status == 0
                self.assertEqual(result.returncode, 0 if reached else 7, result.stderr)
                self.assertEqual('CONNECT_REACHED' in result.stdout, reached)
                self.assertFalse((work / 'maintenance-initial-inventory.part').exists())
                output = work / 'private-storage-maintenance-inventory.json'
                self.assertEqual(output.exists(), published)
                if published:
                    self.assertEqual(M['inventory_file'](output, str(status)), value)
                    self.assertEqual(output.stat().st_mode & 0o777, 0o600)
                if enabled and not reached:
                    self.assertIn('MAINTENANCE_INVENTORY_UNAVAILABLE' if published
                        else 'MAINTENANCE_INVENTORY_INVALID', result.stderr)

    def test_current_scenario_bounds_tests_and_source_gate(self):
        driver = (HERE / 'run-alpha-topology-vm.sh').read_text()
        self.assertIn('[ "$scenario" != private-storage-maintenance ] || driver_time_bound=7200s', driver)
        self.assertIn('cargo test --locked -p volparossa --bin volparossa storage::peer::replicas::fragments::maintenance', driver)
        self.assertIn('private-storage-maintenance-smoke.py owner-test-output', driver)
        self.assertIn('test "$(cat /home/vpci/storage-maintenance-tests.status)" = 0', driver)
        self.assertIn('cargo test --locked -p volparossa-agent --lib maintenance', driver)
        self.assertIn('cargo test --locked -p volparossa-content --lib private_storage::wire', driver)
        self.assertIn('CARGO_BUILD_JOBS=1', driver)
        workflow = (HERE.parents[1] / '.github/workflows/alpha-topology.yml').read_text()
        self.assertIn('          - private-storage-maintenance\n', workflow)
        start = workflow.index('      - name: Require actual owner-private storage maintenance')
        gate = workflow[start:workflow.index('\n      - name:', start + 1)]
        self.assertIn('test "$TOPOLOGY_EXIT_CODE" = 0', gate)
        self.assertIn('private-storage-maintenance-smoke.py report-consumer-v9 "$report" "$GITHUB_SHA"', gate)
        self.assertIn('host-state-before.json', gate)
        self.assertIn('host-state-after.json', gate)

    def test_background_budget_config_is_scoped_to_maintenance(self):
        for selected, ceiling, interface in (('yes', 10, 'cr0'), ('no', 1, 'cr2')):
            result = subprocess.run(['sh', '-eu', '-c',
                '. "$1"; scenario=content-custody; node=client; private_storage_maintenance=$2; content_custody_config',
                'test', str(HERE / 'content-custody-smoke.sh'), selected], text=True,
                capture_output=True, check=True, timeout=5)
            self.assertEqual(result.stdout, f'sharing:\n  enabled: true\n  interface: cr0\n'
                f'  total_upload_mbps: 100\n  contribution_upload_ceiling_mbps: {ceiling}\n'
                f'download_sharing:\n  enabled: true\n  interface: {interface}\n'
                f'  total_download_mbps: 100\n  contribution_download_ceiling_mbps: {ceiling}\n')

    def test_closed_export_parity_and_private_sentinels(self):
        diagnostics = DIAGNOSTICS()
        names = set(M['EXPORT_NAMES'])
        self.assertEqual(names, diagnostics['MAINTENANCE_NAMES'])
        self.assertEqual(len(names), len(M['EXPORT_NAMES']))
        self.assertLess(len(names), 128)
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            home = root / 'home'
            published = home / 'alpha-output'
            published.mkdir(parents=True)
            for name in names:
                (published / name).write_text('{}')
            for name in ('maintenance-owner-lifecycle.private', 'lifecycle-result.json',
                    'identity.key', 'enrollment.json', 'checkpoint.json', 'logs-client.txt',
                    'private-storage-maintenance-selection-route-diagnostic.json',
                    'private-storage-maintenance-selection-start.private',
                    'private-storage-maintenance-selection-end.private',
                    'private-storage-maintenance-selection-phase.private', 'ready.json'):
                (published / name).write_text('PRIVATE_MUST_NOT_EXPORT')
            archive = diagnostics['collect'](home, root / 'missing-opt', 'a' * 40, SCENARIO, 124,
                cgroups=root / 'missing-cgroups', proc=root / 'missing-proc')
            with tarfile.open(archive, 'r:gz') as bundle:
                self.assertEqual(set(bundle.getnames()), {f'published/{name}' for name in names} | {'vm-incomplete.json'})
                for entry in bundle.getmembers():
                    self.assertNotIn(b'PRIVATE_MUST_NOT_EXPORT', bundle.extractfile(entry).read())
                receipt = json.load(bundle.extractfile('vm-incomplete.json'))
                self.assertFalse(receipt['success'])
                self.assertFalse(receipt['cleanup']['verified'])
                self.assertIsNone(receipt['host_state']['unchanged'])

    def test_emergency_deduplicates_only_identical_named_receipts(self):
        diagnostics, names = DIAGNOSTICS(), set(M['EXPORT_NAMES'])
        with tempfile.TemporaryDirectory() as temporary:
            base = Path(temporary)
            home, opt = base / 'home', base / 'opt'
            published = home / 'alpha-output'
            work = opt / ('va.' + 'a' * 32 + '.Abc123')
            for root in (published, work):
                root.mkdir(parents=True)
                for name in names:
                    (root / name).write_text('{}\n')
                (root / 'consumer-binding.json').write_text('PRIVATE_MUST_NOT_EXPORT')
            distinct = 'storage-consumer-finish.json'
            (work / distinct).write_text('{"passed":false}\n')
            archive = diagnostics['collect'](home, opt, 'a' * 40, SCENARIO, 124,
                cgroups=base / 'missing-cgroups', proc=base / 'missing-proc')
            with tarfile.open(archive, 'r:gz') as bundle:
                self.assertEqual(set(bundle.getnames()), {f'published/{name}' for name in names}
                    | {f'work-1/{distinct}', 'vm-incomplete.json'})
                for entry in bundle.getmembers():
                    self.assertNotIn(b'PRIVATE_MUST_NOT_EXPORT', bundle.extractfile(entry).read())

    def test_emergency_keeps_terminal_receipts_first_without_raising_bounds(self):
        diagnostics = DIAGNOSTICS()
        self.assertEqual(len(diagnostics['CONSUMER_CONTROL_NAMES']), 16)
        self.assertFalse(diagnostics['CONSUMER_CONTROL_NAMES'] & diagnostics['MAINTENANCE_PRIORITY_NAMES'])
        with tempfile.TemporaryDirectory() as temporary:
            base = Path(temporary)
            home, opt = base / 'home', base / 'opt'
            roots = [home / 'alpha-output', *(opt / ('va.' + str(i) * 32 + '.Abc123') for i in range(4))]
            names = set(M['EXPORT_NAMES'])
            for index, root in enumerate(roots):
                root.mkdir(parents=True)
                for name in names:
                    (root / name).write_text(json.dumps({'root': index}))
                (root / 'current-phase').write_text('storage-consumer-exercise\n')
                # Never export an unfinished JSON object or its truncated tail.
                (root / 'storage-consumer-prepare.json').write_text('{"partial":')
                (root / 'storage-consumer-publish.json').write_text('x' * (diagnostics['FILE_LIMIT'] + 1))
            archive = diagnostics['collect'](home, opt, 'a' * 40, SCENARIO, 124,
                cgroups=base / 'missing-cgroups', proc=base / 'missing-proc')
            with tarfile.open(archive, 'r:gz') as bundle:
                receipt = json.load(bundle.extractfile('vm-incomplete.json'))
                self.assertLessEqual(len(receipt['diagnostics']['files']), 128)
                self.assertLessEqual(receipt['diagnostics']['captured_bytes'], diagnostics['TOTAL_LIMIT'])
                self.assertTrue(all(not item['truncated'] for item in receipt['diagnostics']['files']))
                for label in ('published', *(f'work-{i}' for i in range(1, 5))):
                    for name in ('storage-consumer-finish.json', 'private-storage-maintenance-lifecycle-failure.json',
                            'private-storage-fragments-consumer_deleted_usage.json'):
                        self.assertIn(f'{label}/{name}', bundle.getnames())
                self.assertFalse(any(name.endswith(('storage-consumer-prepare.json', 'storage-consumer-publish.json'))
                    for name in bundle.getnames()))


class ControlRebind(unittest.TestCase):
    """Run real fixture orchestration with inert, exact-command network doubles."""
    def trial(self, *, same=False, failure='', stale_link=False, invalid_peer=False, observer=False):
        script = r'''
set -eu
umask 077
. "$source_directory/tests/integration/content-provider-smoke.sh"
. "$source_directory/tests/integration/private-storage-maintenance-smoke.sh"
R0=ns0; R1=ns1; R2=ns2; R3=ns3; R4=ns4; R5=ns5
provider_control_peer=peer0; provider_control_node=relay0
provider_control_ns=ns0; provider_control_ip=42.158.0.1
provider_control_ips=42.158.0.1,48.164.4.1,49.165.5.1,50.166.6.1
PROVIDER_CONTROL_PID=$TEST_OBSERVER
maintenance_control_peer=$TEST_PEER
maintenance_control_relation=$TEST_RELATION
record() { printf '%s\n' "$*" >>"$WORK/events"; [ "$TEST_FAIL" != "$*" ] || return 37; }
private_storage_maintenance_supervisor_stage() { record "stage:$1"; }
private_storage_maintenance_control_snapshot() {
    record "snapshot:$1" || return "$?"
    printf '{"nodes":{},"route_checks":null,"test_stage":"%s"}\n' "$1" >"$WORK/maintenance-control-$1.private"
}
python3() {
    [ "$1:$2:$3:$4" = "-B:$WORK/bin/private-storage-maintenance-smoke.py:control-transition-check:$WORK" ] || return 93
    record "check:$6" || return "$?"
    # The complete validator is tested separately with kernel-shaped fixtures.
    # Here preserve the actual file/phase ordering and closed command interface.
    command jq -e --arg stage "$6" 'if $stage == "before" then .before.test_stage == "before" and .after == null
        elif $stage == "detached" then .detached.test_stage == "detached" and .after == null
        else .after.test_stage == "after" end' "$5" >/dev/null
}
ip() {
    record "ip:$*" || return "$?"
    if [ "$1" = -n ]; then
        case "$2" in ns0|ns1|ns2|ns3|ns4|ns5) ;; *) return 93 ;; esac
        shift 2
        case "$*" in
            'link delete ac0'|'link delete ac1'|'link delete ac2') ;;
            '-j link show')
                if [ "$TEST_STALE" = yes ]; then printf '[{"ifname":"ap0"}]\n'; else printf '[]\n'; fi ;;
            'link add ac0 type veth peer name ap0 netns ns3'|\
            'link add ac1 type veth peer name ap1 netns ns4'|\
            'link add ac2 type veth peer name ap2 netns ns5') ;;
            'address add 10.241.83.1/30 dev ac0'|'address add 10.241.83.2/30 dev ap0'|\
            'address add 10.241.84.1/30 dev ac1'|'address add 10.241.84.2/30 dev ap1'|\
            'address add 10.241.85.1/30 dev ac2'|'address add 10.241.85.2/30 dev ap2') ;;
            'link set ac0 up'|'link set ap0 up'|'link set ac1 up'|'link set ap1 up'|\
            'link set ac2 up'|'link set ap2 up') ;;
            'route replace '*) ;;
            '-j route get '*) printf '[]\n' ;;
            *) return 93 ;;
        esac
    elif [ "$1:$2" = netns:exec ]; then
        case "$3" in ns0|ns3|ns4|ns5) ;; *) return 93 ;; esac
        shift 3
        case "$*" in 'nft delete table inet vpa_content_control_adaptive_'[012]) ;; *) return 93 ;; esac
    else return 93; fi
}
content_provider_filter_link() { record "filter:$*"; }
content_custody_cli() { record current-query || return "$?"; printf '{"control_relay_peer_id":"%s"}\n' "$TEST_PEER"; }
private_storage_maintenance_control_transition
'''
        with tempfile.TemporaryDirectory() as temporary:
            work = Path(temporary)
            (work / 'events').touch()
            (work / 'a01-expected-peers.json').write_text(json.dumps({f'relay{i}': f'peer{i}' for i in range(6)}))
            layout = b'{"control_relay_peer_id":"peer0","provider_nodes":["relay4","relay5","relay3"]}\n'
            (work / 'private-storage-fragments-layout.json').write_bytes(layout)
            original_names = [f'content-provider-adaptive-control-relay{i}-{direction}.json'
                for i in range(3, 6) for direction in ('out', 'back')]
            for name in original_names:
                (work / name).write_text('ORIGINAL UPLOAD ROUTE\n')
            result = subprocess.run(['sh', '-c', script], capture_output=True, timeout=10, env=dict(
                PATH='/usr/bin:/bin', WORK=str(work), source_directory=str(HERE.parents[1]),
                TEST_RELATION='same' if same else 'different', TEST_PEER='unknown' if invalid_peer else 'peer0' if same else 'peer2',
                TEST_FAIL=failure, TEST_STALE='yes' if stale_link else 'no', TEST_OBSERVER='123' if observer else ''))
            events = (work / 'events').read_text().splitlines()
            for name in original_names:
                self.assertEqual((work / name).read_text(), 'ORIGINAL UPLOAD ROUTE\n')
            self.assertEqual((work / 'private-storage-fragments-layout.json').read_bytes(), layout)
            path = work / 'private-storage-maintenance-control-transition.json'
            value = json.loads(path.read_text()) if path.exists() else None
            if path.exists():
                self.assertEqual(stat.S_IMODE(path.stat().st_mode), 0o600)
                self.assertEqual(path.read_bytes(), json.dumps(value, sort_keys=True, separators=(',', ':')).encode())
            return result, events, value

    def test_changed_broker_removes_all_old_links_before_filters_and_filters_new_links_before_up(self):
        result, events, value = self.trial()
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(value['relation'], 'different')
        self.assertEqual(value['previous_control_relay_peer_id'], 'peer0')
        self.assertEqual(value['current_control_relay_peer_id'], 'peer2')
        deletes = [i for i, s in enumerate(events) if 'link delete' in s]
        filter_deletes = [i for i, s in enumerate(events) if 'nft delete table' in s]
        creates = [i for i, s in enumerate(events) if 'link add' in s]
        self.assertEqual(len(deletes), 3)
        self.assertEqual(len(filter_deletes), 6)
        self.assertEqual(len(creates), 3)
        self.assertLess(events.index('check:before'), min(deletes))
        self.assertLess(max(deletes), min(filter_deletes))
        self.assertLess(max(filter_deletes), events.index('check:detached'))
        self.assertLess(events.index('check:detached'), min(creates))
        for slot in range(3):
            broker = events.index(f'filter:ns2 adaptive_{slot} ac{slot} 45.161.2.1 {("48.164.4.1", "49.165.5.1", "50.166.6.1")[slot]}')
            peer = next(i for i, s in enumerate(events) if s.startswith(f'filter:ns{slot + 3} adaptive_{slot} ap{slot} '))
            self.assertLess(max(broker, peer), events.index(f'ip:-n ns2 link set ac{slot} up'))
            self.assertLess(max(broker, peer), events.index(f'ip:-n ns{slot + 3} link set ap{slot} up'))
        self.assertEqual(events[-1], 'check:complete')

    def test_same_broker_is_observed_without_link_route_or_filter_mutation(self):
        result, events, value = self.trial(same=True)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIsNone(value['detached'])
        self.assertFalse(any(s.startswith(('ip:', 'filter:')) for s in events))
        self.assertEqual([s for s in events if s.startswith('check:')], ['check:before', 'check:complete'])

    def test_original_before_snapshot_and_validator_failures_have_distinct_closed_stages(self):
        for failure, stage in (('snapshot:before', 'control_snapshot'),
                ('check:before', 'control_validate_before')):
            with self.subTest(failure=failure):
                result, events, value = self.trial(same=True, failure=failure)
                self.assertNotEqual(result.returncode, 0)
                self.assertIsNone(value)
                self.assertEqual([s for s in events if s.startswith('stage:')][-1], 'stage:' + stage)
                self.assertFalse(any(s.startswith(('ip:', 'filter:')) for s in events))
                self.assertNotIn('stage:control_rebind', events)

    def test_rejected_readback_or_partial_mutation_never_publishes_success(self):
        for failure in ('snapshot:before', 'check:before', 'ip:-n ns0 link delete ac1',
                'ip:netns exec ns0 nft delete table inet vpa_content_control_adaptive_1',
                'check:detached', 'ip:-n ns2 link add ac1 type veth peer name ap1 netns ns4',
                'filter:ns4 adaptive_1 ap1 49.165.5.1 45.161.2.1', 'current-query', 'check:complete'):
            with self.subTest(failure=failure):
                result, events, value = self.trial(failure=failure)
                self.assertNotEqual(result.returncode, 0)
                self.assertIsNone(value)
                if failure in ('snapshot:before', 'check:before'):
                    self.assertFalse(any('link delete' in s for s in events))
                if failure == 'check:detached':
                    self.assertFalse(any('link add' in s for s in events))
                if failure.startswith('filter:ns4'):
                    self.assertNotIn('ip:-n ns2 link set ac1 up', events)
        result, events, value = self.trial(stale_link=True)
        self.assertNotEqual(result.returncode, 0)
        self.assertIsNone(value)
        self.assertFalse(any('nft delete' in s or 'link add' in s for s in events))

    def test_unknown_broker_or_live_observer_is_rejected_before_mutation(self):
        for options in ({'invalid_peer': True}, {'observer': True}):
            result, events, value = self.trial(**options)
            self.assertNotEqual(result.returncode, 0)
            self.assertIsNone(value)
            self.assertFalse(any(s.startswith(('ip:', 'filter:')) for s in events))

    def test_snapshot_keeps_only_fixed_kernel_projections_and_reads_actual_six_routes(self):
        answers = {}
        for node in range(6):
            answers[f'-n ns{node} -j -d link show'] = [
                dict(ifindex=1, ifname='underlay', address='PRIVATE_NON_CONTROL_MAC'),
                dict(ifindex=10, ifname='ac0' if node == 0 else 'ap0', link_index=11,
                    flags=['UP'], linkinfo=dict(info_kind='veth'), address='PRIVATE_MAC')]
            answers[f'-n ns{node} -j -d -4 route show'] = [
                dict(dst='default', dev='underlay', gateway='PRIVATE_NON_CONTROL_ROUTE'),
                dict(dst='48.164.4.1', dev='ac0', gateway='10.241.83.2', prefsrc='42.158.0.1',
                    protocol='boot', scope='global', uid=0, private_field='PRIVATE_ROUTE_FIELD')]
            answers[f'netns exec ns{node} nft -j list tables'] = dict(nftables=[
                dict(table=dict(family='inet', name='unrelated_fixture_table'))])
        answers['netns exec ns0 nft -j list tables']['nftables'].append(
            dict(table=dict(family='inet', name='vpa_content_control_adaptive_0')))
        table = dict(nftables=[dict(table=dict(family='inet', name='vpa_content_control_adaptive_0'))])
        answers['netns exec ns0 nft -j list table inet vpa_content_control_adaptive_0'] = table
        for slot, address in enumerate(('48.164.4.1', '49.165.5.1', '50.166.6.1')):
            answers[f'-n ns0 -j route get {address}'] = [dict(dst=address, dev=f'ac{slot}',
                gateway=f'10.241.{83 + slot}.2', prefsrc='42.158.0.1', uid=0, cache=[])]
            answers[f'-n ns{slot + 3} -j route get 42.158.0.1'] = [dict(dst='42.158.0.1', dev=f'ap{slot}',
                gateway=f'10.241.{83 + slot}.1', prefsrc=address, uid=0, cache=[])]
        script = r'''
set -eu
umask 077
. "$source_directory/tests/integration/content-provider-smoke.sh"
. "$source_directory/tests/integration/private-storage-maintenance-smoke.sh"
R0=ns0; R1=ns1; R2=ns2; R3=ns3; R4=ns4; R5=ns5
provider_control_ns=ns0; provider_control_ip=42.158.0.1
ip() {
    printf '%s\n' "$*" >>"$WORK/events"
    command jq -ce --arg key "$*" 'if has($key) then .[$key] else error("unexpected mock command") end' "$WORK/answers.json"
}
private_storage_maintenance_control_snapshot "$TEST_STAGE"
'''
        with tempfile.TemporaryDirectory() as temporary:
            work = Path(temporary)
            (work / 'answers.json').write_text(json.dumps(answers))
            def invoke(stage):
                return subprocess.run(['sh', '-c', script], capture_output=True, timeout=5,
                    env=dict(PATH='/usr/bin:/bin', WORK=str(work), TEST_STAGE=stage, source_directory=str(HERE.parents[1])))
            for stage in ('before', 'detached', 'after'):
                result = invoke(stage)
                self.assertEqual(result.returncode, 0, result.stderr)
                raw = (work / f'maintenance-control-{stage}.private').read_bytes()
                value = json.loads(raw)
                self.assertNotIn(b'PRIVATE_', raw)
                self.assertEqual(set(value['nodes']), {f'relay{i}' for i in range(6)})
                self.assertEqual(value['nodes']['relay0']['tables'], {'vpa_content_control_adaptive_0': table})
                self.assertEqual(set(value['nodes']['relay0']['links'][0]), {'ifindex', 'ifname', 'link_index', 'flags', 'kind'})
                self.assertEqual(set(value['nodes']['relay0']['routes'][0]), {'dst', 'dev', 'gateway', 'prefsrc', 'scope', 'protocol'})
                if stage == 'after':
                    self.assertEqual(set(value['route_checks']), {'relay3', 'relay4', 'relay5'})
                    for item in value['route_checks'].values():
                        self.assertEqual(set(item), {'out', 'back'})
                        self.assertEqual(set(item['out'][0]), {'dst', 'dev', 'gateway', 'prefsrc'})
                else:
                    self.assertIsNone(value['route_checks'])
            calls = (work / 'events').read_text().splitlines()
            self.assertEqual(len([call for call in calls if 'route get' in call]), 6)
            self.assertFalse(any('unrelated_fixture_table' in call for call in calls))
            self.assertNotEqual(invoke('arbitrary').returncode, 0)
            answers['-n ns0 -j -d link show'] = 'x' * 65536
            (work / 'answers.json').write_text(json.dumps(answers))
            self.assertNotEqual(invoke('before').returncode, 0)

    def test_actual_shell_readback_and_phase_hash_pass_actual_transition_cli(self):
        fixtures = runpy.run_path(str(HERE / 'test-storage-consumer-maintenance-evidence.py'))
        evidence = fixtures['M']
        source = fixtures['fixture']()
        script = r'''
set -eu
umask 077
. "$source_directory/tests/integration/content-provider-smoke.sh"
. "$source_directory/tests/integration/private-storage-maintenance-smoke.sh"
R0=ns0; R1=ns1; R2=ns2; R3=ns3; R4=ns4; R5=ns5
provider_control_ns=$TEST_NS; provider_control_ip=$TEST_IP; provider_control_peer=$TEST_PEER
ip() { command jq -ce --arg key "$*" 'if has($key) then .[$key] else error("unexpected inert command") end' "$WORK/answers.json"; }
content_custody_cli() { printf '{"control_relay_peer_id":"%s"}\n' "$TEST_OBSERVED"; }
if [ "$TEST_STAGE" = phase ]; then
    storage_route_scope=$TEST_SCOPE
    private_storage_maintenance_phase_layout "$TEST_PHASE"
else private_storage_maintenance_control_snapshot "$TEST_STAGE"; fi
'''
        for changed in (False, True):
            with self.subTest(changed=changed), tempfile.TemporaryDirectory() as temporary:
                work = Path(temporary)
                value = copy.deepcopy(source)
                fixtures['attach_transition'](value, changed=changed)
                transition = value['control_transition']
                for name, data in (('a01-expected-peers.json', value['expected_peers']),
                        ('private-storage-fragments-layout.json', value['layout'])):
                    (work / name).write_bytes(evidence['encoded'](data))
                    (work / name).chmod(0o600)
                def invoke(stage, broker, *, phase='', observed=None):
                    return subprocess.run(['sh', '-c', script], capture_output=True, timeout=8, env=dict(
                        PATH='/usr/bin:/bin', WORK=str(work), source_directory=str(HERE.parents[1]),
                        TEST_STAGE=stage, TEST_PHASE=phase, TEST_NS='ns' + broker[-1],
                        TEST_IP=evidence['NET']['PUBLIC_IPS'][broker],
                        TEST_PEER=value['expected_peers'][broker],
                        TEST_OBSERVED=observed or value['expected_peers'][broker],
                        TEST_SCOPE=json.dumps(value['layout']['route_scope'])))
                current = next(node for node in evidence['CONTROL_NODES'][:3]
                    if value['expected_peers'][node] == transition['current_control_relay_peer_id'])
                previous = next(node for node in evidence['CONTROL_NODES'][:3]
                    if value['expected_peers'][node] == transition['previous_control_relay_peer_id'])
                for stage in ('before', 'detached', 'after'):
                    if stage == 'detached' and not changed: continue
                    snapshot = transition[stage]
                    broker = previous if stage == 'before' else current
                    answers = {}
                    for node, row in snapshot['nodes'].items():
                        ns = 'ns' + node[-1]
                        answers[f'-n {ns} -j -d link show'] = [dict(
                            (key, item) for key, item in link.items() if key != 'kind')
                            | dict(linkinfo=dict(info_kind=link['kind'])) for link in row['links']]
                        answers[f'-n {ns} -j -d -4 route show'] = [dict(route,
                            scope='global' if route['scope'] is None else route['scope']) for route in row['routes']]
                        answers[f'netns exec {ns} nft -j list tables'] = dict(nftables=[
                            dict(table=dict(family='inet', name=name)) for name in row['tables']])
                        for name, table in row['tables'].items():
                            answers[f'netns exec {ns} nft -j list table inet {name}'] = table
                    if stage == 'after':
                        for node, routes in snapshot['route_checks'].items():
                            answers[f'-n ns{current[-1]} -j route get {evidence["NET"]["PUBLIC_IPS"][node]}'] = routes['out']
                            answers[f'-n ns{node[-1]} -j route get {evidence["NET"]["PUBLIC_IPS"][current]}'] = routes['back']
                    (work / 'answers.json').write_text(json.dumps(answers))
                    result = invoke(stage, broker)
                    self.assertEqual(result.returncode, 0, result.stderr)
                    transition[stage] = json.loads((work / f'maintenance-control-{stage}.private').read_bytes())
                    partial = copy.deepcopy(transition)
                    if stage == 'before': partial.update(detached=None, after=None)
                    if stage == 'detached': partial['after'] = None
                    path = work / evidence['TRANSITION_NAME']
                    path.write_bytes(evidence['canonical'](partial))
                    path.chmod(0o600)
                    result = subprocess.run([sys.executable, '-B', str(HERE / 'private-storage-maintenance-smoke.py'),
                        'control-transition-check', str(work), str(path), 'complete' if stage == 'after' else stage],
                        capture_output=True, timeout=8)
                    self.assertEqual(result.returncode, 0, result.stderr)
                for phase in ('upload', 'lifecycle', 'restore', 'finish', 'consumer-publish'):
                    result = invoke('phase', current, phase=phase)
                    self.assertEqual(result.returncode, 0, result.stderr)
                    expected = dict(route_scope=value['layout']['route_scope'])
                    if phase != 'upload':
                        expected['control_transition_sha256'] = hashlib.sha256(path.read_bytes()).hexdigest()
                    self.assertEqual(json.loads(result.stdout), expected)
                    self.assertNotEqual(invoke('phase', current, phase=phase, observed='different-peer').returncode, 0)


class OwnerLifecycle(unittest.TestCase):
    def supervisor_trial(self, failure='', relation='same', *, hard_exit=False, diagnostic_failure=False):
        script = r'''
set -eu
umask 077
. "$source_directory/tests/integration/private-storage-maintenance-smoke.sh"
gate() { printf '%s\n' "$1" >>"$WORK/events"; [ "$TEST_FAIL" != "$1" ] || return 37; }
python3() {
    if [ "$3" = supervisor-record ]; then
        [ "$TEST_DIAGNOSTIC_FAILURE" != yes ] || return 77
        shift 2
        command python3 -B "$source_directory/tests/integration/private-storage-maintenance-smoke.py" "$@"
    else command python3 "$@"; fi
}
benchmark_bind_slots() { gate bind_slots; }
content_custody_cli() {
    gate control_query || return "$?"
    printf '%s\n' "$TEST_CONTROL"
}
jq() {
    case "$1:$2" in
        '-ce:{exit_peer_id:'*) gate route_scope || return "$?" ;;
        '-cn:--argjson') gate ready_payload || return "$?" ;;
        '-ce:. + '*) gate lifecycle_receipt || return "$?" ;;
    esac
    command jq "$@"
}
private_storage_fragments_phase_start() {
    if [ "$TEST_HARD_EXIT" = yes ]; then exit 43; fi
    gate start_observers
}
private_storage_maintenance_control_transition() {
    private_storage_maintenance_supervisor_stage broker_validated
    [ -n "$maintenance_control_peer" ] || return 1
    gate broker_validated || return "$?"
    private_storage_maintenance_supervisor_stage control_snapshot
    gate control_snapshot || return "$?"
    private_storage_maintenance_supervisor_stage control_validate_before
    gate control_validate_before || return "$?"
    private_storage_maintenance_supervisor_stage control_rebind
    gate control_rebind || return "$?"
    provider_control_peer=$maintenance_control_peer
    private_storage_maintenance_supervisor_stage control_verified
    gate control_verified
}
private_storage_maintenance_publish_ready() { gate publish_ready; }
private_storage_fragments_phase_finish() { gate finish_observers; }
private_storage_maintenance_join() { gate coordinator_cleanup; }
cleanup() { printf 'cleanup\n' >>"$WORK/events"; wait "$test_owner" || true; }
trap cleanup EXIT
sh -c 'exit "$TEST_OWNER_STATUS"' &
test_owner=$!; MAINTENANCE_OWNER_PID=$test_owner
provider_control_peer=PRIVATE_ORIGINAL_RELAY
provider_baseline_ms=123
status=0
private_storage_maintenance_post_reconnect || status=$?
exit "$status"
'''
        with tempfile.TemporaryDirectory() as temporary:
            work = Path(temporary)
            (work / 'private-storage-maintenance-reconnect-selection.json').write_text(json.dumps({
                'exact_selected_exit': 'PRIVATE_EXIT', 'paths': [{'path_id': 1, 'relay_peer_id': 'PRIVATE_PATH'}]}))
            (work / 'maintenance-owner-lifecycle.private').write_text('{}')
            peer = {'same': 'PRIVATE_ORIGINAL_RELAY', 'different': 'PRIVATE_OTHER_RELAY', 'empty': ''}[relation]
            result = subprocess.run(['sh', '-c', script], capture_output=True, timeout=15,
                env=dict(PATH='/usr/bin:/bin', WORK=str(work), source_directory=str(HERE.parents[1]),
                    TEST_FAIL=failure, TEST_CONTROL=json.dumps({'control_relay_peer_id': peer}),
                    TEST_OWNER_STATUS='37' if failure == 'join_owner' else '0',
                    TEST_HARD_EXIT='yes' if hard_exit else 'no',
                    TEST_DIAGNOSTIC_FAILURE='yes' if diagnostic_failure else 'no'))
            self.assertEqual((work / 'events').read_text().splitlines()[-1], 'cleanup')
            path = work / 'private-storage-maintenance-supervisor.json'
            self.assertFalse((work / 'maintenance-supervisor.part').exists())
            if diagnostic_failure:
                self.assertFalse(path.exists())
                return result, None
            raw = path.read_bytes()
            self.assertNotIn(b'PRIVATE_', raw)
            self.assertLessEqual(len(raw), 1024)
            self.assertEqual(stat.S_IMODE(path.stat().st_mode), 0o600)
            value = M['supervisor_file'](path)
            self.assertFalse(value['acceptance_evidence'])
            return result, value

    def test_post_reconnect_retains_each_gate_failure_before_cleanup(self):
        for stage in M['SUPERVISOR_STAGES']:
            if stage == 'control_match':
                continue  # Strictly readable historical diagnostic, no longer an active identity gate.
            with self.subTest(stage=stage):
                result, value = self.supervisor_trial(stage)
                self.assertEqual(result.returncode, 1, result.stderr)
                self.assertEqual(value['stage'], stage)
                self.assertEqual(value['outcome'], 'failed')
                # The query retains its original pipeline exit (jq sees EOF),
                # while explicit test failure and child wait retain status37.
                self.assertEqual(value['exit_status'], 4 if stage == 'control_query' else 37)
                self.assertEqual(value['control_relay_relation'],
                    'unobserved' if stage in ('bind_slots', 'control_query') else 'same')

    def test_post_reconnect_success_empty_control_and_hard_exit_do_not_invent_acceptance(self):
        result, value = self.supervisor_trial()
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual((value['stage'], value['outcome'], value['exit_status']),
            ('coordinator_cleanup', 'complete', 0))
        result, value = self.supervisor_trial(relation='different')
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(value['control_relay_relation'], 'different')
        result, value = self.supervisor_trial(relation='empty')
        self.assertEqual(result.returncode, 1)
        self.assertEqual((value['stage'], value['control_relay_relation'], value['exit_status']),
            ('broker_validated', 'empty', 1))
        result, value = self.supervisor_trial(hard_exit=True)
        self.assertEqual(result.returncode, 43)
        self.assertEqual((value['stage'], value['outcome'], value['exit_status']),
            ('start_observers', 'pending', None))
        result, value = self.supervisor_trial('bind_slots', diagnostic_failure=True)
        self.assertEqual(result.returncode, 1)
        self.assertIsNone(value)

    def test_actual_term_is_distinct_from_local_io_without_exporting_signal_text(self):
        script = '''import json,os,runpy,select,signal,sys
m=runpy.run_path(sys.argv[1])
signal.signal(signal.SIGTERM,m['interrupted'])
read_fd,write_fd=os.pipe2(os.O_NONBLOCK|os.O_CLOEXEC)
previous_wakeup=signal.set_wakeup_fd(write_fd)
try:
 print('ready',flush=True)
 # A signal received before select remains readable; pause has no such memory.
 if not select.select([read_fd],[],[],3)[0]:
  raise TimeoutError('TERM was not observed')
 raise AssertionError('TERM handler did not raise')
except InterruptedError as error:
 print(json.dumps({'code':m['failure_code'](error)}),flush=True)
finally:
 signal.set_wakeup_fd(previous_wakeup)
 os.close(read_fd)
 os.close(write_fd)
'''
        process = subprocess.Popen([sys.executable, '-B', '-c', script,
            str(HERE / 'private-storage-maintenance-smoke.py')], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        try:
            self.assertTrue(select.select([process.stdout], [], [], 5)[0])
            self.assertEqual(process.stdout.readline(), b'ready\n')
            process.send_signal(signal.SIGTERM)
            stdout, stderr = process.communicate(timeout=5)
            self.assertEqual(process.returncode, 0, stderr)
            self.assertEqual(json.loads(stdout), {'code': 'termination_signal'})
        finally:
            if process.poll() is None:
                process.kill(); process.communicate(timeout=5)
        self.assertEqual(M['failure_code'](InterruptedError('OS EINTR, not our handler')), 'local_io')
        self.assertEqual(M['failure_code'](PermissionError('PRIVATE_PATH')), 'local_io')

    def test_supervisor_export_validation_preserves_primary_failure_and_rejects_raw_data(self):
        source = (HERE / 'private-storage-maintenance-smoke.sh').read_text()
        start = source.index('    # Already published at the original supervisor gate')
        block = source[start:source.index('    # Cleanup has already captured', start)]
        valid = M['supervisor_record']('control_match', 'failed', '1', 'different')
        for raw in (json.dumps(valid), json.dumps({**valid, 'private': 'PRIVATE_DATA'}), 'x' * 1025):
            with self.subTest(raw=raw[:50]), tempfile.TemporaryDirectory() as temporary:
                work = Path(temporary)
                path = work / 'private-storage-maintenance-supervisor.json'
                path.write_text(raw); path.chmod(0o600)
                result = subprocess.run(['sh', '-eu', '-c',
                    'maintenance_status=7\n' + block + '\ntest "$maintenance_status" -eq 7'],
                    capture_output=True, timeout=5,
                    env=dict(PATH='/usr/bin:/bin', WORK=str(work), source_directory=str(HERE.parents[1])))
                self.assertEqual(result.returncode, 0, result.stderr)
                self.assertEqual(path.exists(), raw == json.dumps(valid))
                if path.exists(): self.assertEqual(M['supervisor_file'](path), valid)

    def test_ready_publication_is_atomic_after_bytes_and_metadata_and_partial_cleanup(self):
        # Execute the real publisher/cleanup functions with only install replaced:
        # no root chown is attempted, but its exact arguments remain mandatory.
        # Pause its writer after partial content and before the final mode change.
        installer = '''import os,sys
from pathlib import Path
assert sys.argv[1:7] == ['-o', 'root', '-g', str(os.getgid()), '-m', '0640']
source, target = map(Path, sys.argv[7:])
data = source.read_bytes()
with target.open('xb') as stream:
    os.fchmod(stream.fileno(), 0o600)
    stream.write(data[:len(data)//2])
    stream.flush()
    print('partial', flush=True)
    assert sys.stdin.readline() == 'continue\\n'
    if os.environ['INSTALL_FAIL'] == 'yes':
        sys.exit(7)
    stream.write(data[len(data)//2:])
    stream.flush()
    os.fchmod(stream.fileno(), 0o640)
'''
        for failed in (False, True):
            with self.subTest(failed=failed), tempfile.TemporaryDirectory() as temporary:
                work = Path(temporary)
                coordinator = work / 'maintenance-coordinator'
                coordinator.mkdir(mode=0o750)
                source = work / 'maintenance-coordinator-ready.private'
                raw = b'{"baseline":123,"scope":{"synthetic":"closed fixture"}}\n'
                source.write_bytes(raw)
                script = work / 'install-fixture.py'
                script.write_text(installer)
                ready, part = coordinator / 'ready.json', coordinator / 'ready.part'
                environment = dict(PATH='/usr/bin:/bin', WORK=str(work), WORKER_GID=str(os.getgid()),
                    INSTALL_FAIL='yes' if failed else 'no')
                command = ['sh', '-eu', '-c', '. "$1"; install() { python3 -B "$WORK/install-fixture.py" "$@"; }; '
                    'private_storage_maintenance_publish_ready', 'test', str(HERE / (SCENARIO + '-smoke.sh'))]
                process = subprocess.Popen(command, env=environment, stdin=subprocess.PIPE,
                    stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
                try:
                    self.assertTrue(select.select([process.stdout], [], [], 5)[0], 'installer did not reach publication barrier')
                    self.assertEqual(process.stdout.readline(), 'partial\n')
                    self.assertEqual(part.read_bytes(), raw[:len(raw)//2])
                    self.assertEqual(stat.S_IMODE(part.stat().st_mode), 0o600)
                    self.assertFalse(ready.exists(), 'watcher saw unfinished bytes or metadata')
                    stdout, stderr = process.communicate('continue\n', timeout=5)
                    self.assertEqual(stdout, '')
                    self.assertEqual(stderr, '')
                    self.assertEqual(process.returncode, 1 if failed else 0)
                    if failed:
                        self.assertFalse(ready.exists())
                        self.assertTrue(part.is_file())
                    else:
                        info = ready.stat()
                        self.assertEqual(ready.read_bytes(), raw)
                        self.assertEqual((info.st_uid, info.st_gid, stat.S_IMODE(info.st_mode), info.st_nlink),
                            (os.getuid(), os.getgid(), 0o640, 1))
                        self.assertFalse(part.exists())
                finally:
                    if process.poll() is None:
                        # Release the finite fixture writer before joining the shell.
                        process.communicate('continue\n', timeout=5)
                subprocess.run(['sh', '-eu', '-c', '. "$1"; private_storage_maintenance_join',
                    'test', str(HERE / (SCENARIO + '-smoke.sh'))], env=environment,
                    check=True, capture_output=True, timeout=5)
                self.assertFalse(coordinator.exists())
                self.assertEqual(source.read_bytes(), raw)

    @staticmethod
    def owner_test_stdout():
        names = sorted(M['OWNER_REQUIRED_TESTS'])
        return ('\nrunning ' + str(len(names)) + ' tests\n' + ''.join(
            f"test {M['OWNER_TEST_PREFIX']}{name} ... ok\n" for name in names)
            + f'\ntest result: ok. {len(names)} passed; 0 failed; 0 ignored; 0 measured; 601 filtered out; finished in 2.00s\n\n').encode()

    def test_owner_gate_requires_actual_named_passes_not_zero_listing_or_partial(self):
        valid = self.owner_test_stdout()
        self.assertEqual(M['owner_test_output'](io.BytesIO(valid))['required_passed'], 13)
        for invalid in (b'\nrunning 0 tests\ntest result: ok. 0 passed; 0 failed; 0 ignored; 0 measured; 614 filtered out; finished in 0.00s\n',
                valid.replace(b' ... ok', b': test'), valid.replace(b' ... ok', b' ... ignored', 1),
                valid.replace(b' ... ok', b' ... FAILED', 1), valid.replace(b'13 passed', b'12 passed'),
                valid.replace(b'enrollment_signature_private_mode_and_restart_cursor_are_retained', b'wrong_test'),
                valid + b'x' * 65537):
            with self.subTest(invalid=invalid[:40]), self.assertRaises(ValueError):
                M['owner_test_output'](io.BytesIO(invalid))
        for invalid in (valid.replace(b' ... ok', b' ... FAILED', 1), b'x' * 65537):
            diagnostic = io.BytesIO()
            with self.assertRaises(ValueError):
                M['owner_test_output'](io.BytesIO(invalid), diagnostic)
            self.assertLessEqual(len(diagnostic.getvalue()), 65536)
            self.assertIn(b'FAILED' if len(invalid) < 65536 else b'OWNER_TEST_OUTPUT_LIMIT_EXCEEDED', diagnostic.getvalue())

    def test_actual_guest_gate_checks_cargo_exit_even_with_a_successful_output_parser(self):
        source = (HERE / 'run-alpha-topology-vm.sh').read_text()
        start = source.index('    test ! -e /home/vpci/storage-maintenance-tests.status')
        end = source.index('    CARGO_BUILD_JOBS=1 CARGO_TARGET_DIR=/home/vpci/target timeout --signal=TERM --kill-after=15s 900s', start)
        block = source[start:end].replace('tests/integration/private-storage-maintenance-smoke.py',
            str(HERE / 'private-storage-maintenance-smoke.py'))
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            executable = root / 'cargo'
            executable.write_text('#!/usr/bin/python3\nimport os,sys\nfrom pathlib import Path\n'
                'assert "storage::peer::replicas::fragments::maintenance" in sys.argv\n'
                'sys.stdout.buffer.write(Path(os.environ["TEST_OUTPUT"]).read_bytes())\n'
                'sys.exit(int(os.environ["TEST_EXIT"]))\n')
            executable.chmod(0o700)
            for index, (raw, exit_code, passed) in enumerate(((self.owner_test_stdout(), 0, True),
                    (self.owner_test_stdout(), 7, False), (b'running 0 tests\n', 0, False), (b'x' * 65537, 0, False))):
                output = root / f'output-{index}'
                output.write_bytes(raw)
                actual = block.replace('/home/vpci/storage-maintenance-tests.status', str(root / f'status-{index}'))
                result = subprocess.run(['sh', '-eu', '-c', actual], capture_output=True, timeout=5,
                    env={'PATH': f'{root}:/usr/bin:/bin', 'TEST_OUTPUT': str(output), 'TEST_EXIT': str(exit_code)})
                self.assertEqual(result.returncode == 0, passed)
                if passed:
                    self.assertEqual(json.loads(result.stdout)['required_passed'], 13)

    def test_route_diagnostic_export_does_not_replace_primary_failed_report(self):
        script = r'''
set -eu
umask 077
. "$source_directory/tests/integration/private-storage-maintenance-smoke.sh"
optional_json_evidence() { printf 'null\n'; }
python3() {
    if { [ "$3" = route-diagnostic ] || [ "$3" = route-diagnostic-v3 ]; } && [ "$TEST_DIAGNOSTIC_FAILURE" = yes ]; then return 77; fi
    command python3 "$@"
}
private_storage_maintenance_finalize_report 7
'''
        for profile, diagnostic_failure in ((7, False), (7, True), (8, False), (8, True)):
            with self.subTest(profile=profile, diagnostic_failure=diagnostic_failure), tempfile.TemporaryDirectory() as temporary:
                work = Path(temporary)
                output = work / 'output'
                output.mkdir()
                route = FIXTURE['MaintenanceEvidence'].selection_route()
                # SELECTED must not erase a later route-scope extraction failure.
                route.update(stage='complete', reason='SELECTED', last_connect_reason='CONNECTED',
                    connect_exit_status=0, path_status=0)
                raw = work / 'private-storage-maintenance-selection-route-diagnostic.json'
                raw.write_text(json.dumps(route))
                raw.chmod(0o600)
                result = subprocess.run(['sh', '-c', script], capture_output=True, text=True, timeout=5,
                    env=dict(PATH='/usr/bin:/bin', WORK=str(work), source_directory=str(HERE.parents[1]),
                        output_directory=str(output), OUTPUT_UID=str(os.getuid()), OUTPUT_GID=str(os.getgid()),
                        expected_commit='1' * 40, RUN_ID='inert', PHASE='private-storage-fragments-prepare',
                        OBSERVED_BLOCKER='FRAGMENTS_ROUTE_UNAVAILABLE', CLEANUP_COMPLETE='true',
                        REMAINING_OWNED_OBJECTS='0', TEST_DIAGNOSTIC_FAILURE='yes' if diagnostic_failure else 'no',
                        storage_consumer_profile_version=str(profile)))
                self.assertEqual(result.returncode, 1)
                report = json.loads((output / 'private-storage-maintenance-smoke.json').read_text())
                self.assertEqual(report['schema_version'], profile - 1)
                self.assertEqual(report['runner_exit_status'], 7)
                self.assertEqual(report['observed_blocker'], 'FRAGMENTS_ROUTE_UNAVAILABLE')
                self.assertFalse(report['success'])
                self.assertFalse((work / 'maintenance-route-diagnostic.part').exists())
                exported = output / 'private-storage-maintenance-route-diagnostic.json'
                self.assertEqual(exported.exists(), not diagnostic_failure)
                if exported.exists():
                    value = json.loads(exported.read_text())
                    M['validate_route_diagnostic'](value)
                    self.assertEqual(value['route'], route)
                    self.assertFalse(value['acceptance_evidence'])
                    self.assertEqual(exported.stat().st_mode & 0o777, 0o600)
                    provider = json.loads((output / M['PROVIDER_EVENTS_NAME']).read_text())
                    M['validate_provider_events'](provider)
                    self.assertEqual(provider['version'], 3 if profile == 8 else 2)
                self.assertFalse((output / raw.name).exists())

    def test_provider_snapshot_reuses_exact_cleanup_query_and_never_changes_exit(self):
        guest = (HERE / 'kvm-alpha-topology.sh').read_text()
        start = guest.index('            cleanup_logs_status=0\n')
        end = guest.index('                peers >"$WORK/peers-', start)
        end = guest.rindex('            "$binary_directory/volparossa"', start, end)
        block = guest[start:end].replace('"$binary_directory/volparossa"', 'fake_cli')
        self.assertEqual(block.count('fake_cli'), 1)
        self.assertNotIn('timeout', block)
        script = r'''
set -eu
umask 077
fake_cli() {
    test "$3" = logs && test "$4" = --limit && test "$5" = 400
    printf 'called\n' >>"$WORK/calls"
    printf 'PRIVATE_QUERY_OUTPUT\n'
    return "$TEST_STATUS"
}
''' + block + '\nexit 7\n'
        for node, status, blocked in (('client', 0, False), ('relay3', 77, False),
                ('relay0', 255, False), ('bootstrap1', 0, False), ('client', 0, True)):
            with self.subTest(node=node, status=status, blocked=blocked), tempfile.TemporaryDirectory() as temporary:
                root = Path(temporary)
                marker = root / f'logs-{node}-cleanup-status.private'
                if blocked:
                    marker.mkdir()
                result = subprocess.run(['sh', '-c', script], capture_output=True, text=True, timeout=5,
                    env=dict(PATH='/usr/bin:/bin', WORK=str(root), cleanup_node=node,
                        cleanup_socket='/synthetic/socket', TEST_STATUS=str(status), private_storage_maintenance='yes'))
                self.assertEqual(result.returncode, 7)
                self.assertEqual((root / 'calls').read_text(), 'called\n')
                self.assertEqual(result.stderr, '')
                if node == 'bootstrap1':
                    self.assertFalse(marker.exists())
                elif blocked:
                    self.assertTrue(marker.is_dir())
                else:
                    self.assertEqual(marker.read_text(), f'{status}\n')
                    self.assertEqual(marker.stat().st_mode & 0o777, 0o600)

    def test_provider_sidecar_failure_keeps_route_primary_blocker_and_export_closed(self):
        script = r'''
set -eu
umask 077
. "$source_directory/tests/integration/private-storage-maintenance-smoke.sh"
optional_json_evidence() { printf 'null\n'; }
private_storage_maintenance_finalize_report 7
'''
        for blocked in (False, True):
            with self.subTest(blocked=blocked), tempfile.TemporaryDirectory() as temporary:
                work = Path(temporary); output = work / 'output'; output.mkdir()
                if blocked:
                    (work / 'maintenance-provider-events.part').mkdir()
                for name, raw in (('logs-client-cleanup-status.private', '0\n'),
                        ('logs-client.txt', '101\tlevel=1\tevent=CONTENT_DISCOVERY_PRIVATE_SENTINEL'
                         '\tsession=' + 'deadbeef' * 8 + '\tpath=7\n'),
                        ('logs-relay3-cleanup-status.private', '0\n'),
                        ('logs-relay3.txt', 'PRIVATE_PATH /never/export\n')):
                    (work / name).write_text(raw); (work / name).chmod(0o600)
                result = subprocess.run(['sh', '-c', script], capture_output=True, text=True, timeout=5,
                    env=dict(PATH='/usr/bin:/bin', WORK=str(work), source_directory=str(HERE.parents[1]),
                        output_directory=str(output), OUTPUT_UID=str(os.getuid()), OUTPUT_GID=str(os.getgid()),
                        expected_commit='1' * 40, RUN_ID='inert', PHASE='storage-consumer-publish',
                        provider_baseline_ms='100', OBSERVED_BLOCKER='CONSUMER_APPLICATION_FAILED',
                        CLEANUP_COMPLETE='true', REMAINING_OWNED_OBJECTS='0'))
                self.assertEqual(result.returncode, 1)
                report = json.loads((output / 'private-storage-maintenance-smoke.json').read_text())
                self.assertEqual(report['runner_exit_status'], 7)
                self.assertEqual(report['observed_blocker'], 'CONSUMER_APPLICATION_FAILED')
                M['validate_route_diagnostic'](json.loads((output / 'private-storage-maintenance-route-diagnostic.json').read_text()))
                sidecar = output / M['PROVIDER_EVENTS_NAME']
                self.assertEqual(sidecar.exists(), not blocked)
                if sidecar.exists():
                    value = M['provider_events_file'](sidecar)
                    self.assertEqual(value['roles']['client']['unrecognized_event_records'], 1)
                    self.assertEqual(value['roles']['provider_relay3']['state'], 'invalid')
                for path in output.iterdir():
                    raw = path.read_text()
                    for private in ('PRIVATE_SENTINEL', 'deadbeef', 'PRIVATE_PATH', '/never/export'):
                        self.assertNotIn(private, raw)
                self.assertFalse(any(path.name.startswith('logs-') for path in output.iterdir()))

    def test_failed_lifecycle_is_exported_only_through_exact_bounded_schema(self):
        source = (HERE / 'private-storage-maintenance-smoke.sh').read_text()
        start = source.index('    if [ "$maintenance_status" -ne 0 ]',
            source.index('private_storage_maintenance_finalize_report()'))
        block = source[start:source.index('\n    optional_json_evidence', start)]
        value = dict(version=1, success=False, kind='private-storage-maintenance-lifecycle-failure',
            stage='start_sampler', code='sampler_failure', cursor_before=3, cursor_last=5,
            checkpoint_stage='waiting_for_core', owner_exit_status=0, owner_joined=True, cleanup_error=None,
            sampler=dict(phase='initial', operation='route_query', code='process', samples=0, completed=0, failed=0,
                paths_process=dict(exit_status=1, diagnostic='CLIENT_ROUTE_BUSY', stderr_state='bounded')))
        with tempfile.TemporaryDirectory() as temporary:
            work = Path(temporary)
            private = work / 'maintenance-owner-lifecycle.private'
            exported = work / 'private-storage-maintenance-lifecycle-failure.json'
            current = dict(value, version=2, retained_status=M['retained_status_diagnostic']({}, 100))
            cancelled = dict(current, stage='await_coordinator', code='termination_signal', sampler=None)
            valid = (value, current, cancelled)
            cases = (*map(json.dumps, valid), json.dumps(dict(value, private='SECRET')),
                json.dumps(dict(value, code='SECRET_PATH')), json.dumps(dict(value, cursor_last=True)),
                json.dumps(dict(value, sampler=dict(value['sampler'], raw_stderr='SECRET'))),
                json.dumps(dict(current, retained_status=dict(current['retained_status'], private='SECRET'))), 'x' * 8193)
            for index, raw in enumerate(cases):
                private.write_text(raw)
                private.chmod(0o600)
                subprocess.run(['sh', '-eu', '-c', block], check=True, capture_output=True, timeout=5,
                    env={'PATH': '/usr/bin:/bin', 'WORK': str(work), 'source_directory': str(HERE.parents[1]),
                        'maintenance_status': '1'})
                if index < len(valid):
                    self.assertEqual(json.loads(exported.read_text()), valid[index])
                    exported.unlink()
                else:
                    self.assertFalse(exported.exists())
                self.assertFalse((work / 'maintenance-lifecycle-failure.part').exists())

    def test_retained_charge_accepts_original_v1_without_v2_history(self):
        value, _, _ = FIXTURE['OLD']['cli_fixture']('committed')
        self.assertNotIn('retained_copy_records', value)
        self.assertNotIn('placement_authorizations', value)
        M['retained_during_core_loss'](value)
        for mutate in (
                lambda v: v.update(physical_payload_charge_upper_bound=0),
                lambda v: v.update(placement_authorizations=1),
                lambda v: v['fragments'][0]['copies'].pop()):
            invalid = copy.deepcopy(value)
            mutate(invalid)
            with self.assertRaises(ValueError):
                M['retained_during_core_loss'](invalid)

    def test_current_retained_intent_matches_observed_projection_without_claiming_crypto(self):
        for pending in (False, True):
            with self.subTest(pending=pending), tempfile.TemporaryDirectory() as temporary:
                root = Path(temporary)
                value, keys, enrollment, save = retained_private_fixture(root, pending)
                binding = M['retained_current_during_core_loss'](root, value, keys, enrollment)
                self.assertEqual(binding['pending'] is not None, pending)
                save(root / M['RETAINED_INTENT_FILE'], binding)
                M['retained_intent_continuity'](root)
                self.assertLess((root / M['RETAINED_INTENT_FILE']).stat().st_size, 2048)
                self.assertNotIn(M['RETAINED_INTENT_FILE'], M['EXPORT_NAMES'])
                if pending:
                    actual = M['retained_status_diagnostic'](value, int(time.time()))
                    self.assertEqual(actual['copy_counts'], [3, 2, 2, 2])
                    self.assertEqual(actual['charge_states'], dict(committed=5, uncertain=3,
                        unattempted=1, reserved=0, deleted=0, unknown=0))
                    self.assertEqual(actual['physical_payload_charge_upper_bound'], 1573010)
                    with self.assertRaises(ValueError):
                        M['retained_during_core_loss'](value)  # Historical counter gate is unchanged.

    def test_current_retained_intent_rejects_unverified_or_changed_custody(self):
        mutations = (
            lambda v: v.update(owner_signature_verified=False),
            lambda v: v.pop('owner_signature_verified'),
            lambda v: v.update(operation='private_storage_fragments_deposit'),
            lambda v: v['fragments'][0]['copies'][0].update(provider_key='ff' * 32),
            lambda v: v['fragments'][0]['copies'][0].update(charge='deleted'),
            lambda v: v['fragments'][0]['copies'][0].update(charge='unattempted'),
            lambda v: v['fragments'][0]['copies'][0].update(last_confirmed_stored_bytes=0),
            lambda v: v['fragments'][0]['copies'][0].update(last_confirmed_expiry=1),
            lambda v: v['fragments'][0]['copies'][2].update(charge='committed'),
            lambda v: v['fragments'][0]['copies'].append(copy.deepcopy(v['fragments'][0]['copies'][2])),
            lambda v: v['fragments'][3]['copies'].pop(),
            lambda v: v.update(placement_authorizations=2),
            lambda v: v.update(committed_payload_bytes=v['committed_payload_bytes'] - 1),
            lambda v: v['providers'][0].update(physical_payload_charge_upper_bound=0),
        )
        for index, mutate in enumerate(mutations):
            with self.subTest(index=index), tempfile.TemporaryDirectory() as temporary:
                root = Path(temporary)
                value, keys, enrollment, _ = retained_private_fixture(root)
                mutate(value)
                with self.assertRaises((ValueError, KeyError)):
                    M['retained_current_during_core_loss'](root, value, keys, enrollment)

    def test_current_retained_intent_rejects_private_identity_authority_or_phase_changes(self):
        for change in ('original', 'enrollment', 'grant', 'child', 'journal', 'duplicate',
                'missing', 'phase', 'expired', 'shortened', 'foreign', 'reuse'):
            with self.subTest(change=change), tempfile.TemporaryDirectory() as temporary:
                root = Path(temporary)
                value, keys, enrollment, save = retained_private_fixture(root)
                placement = root / 'fragment-set/placement-authorizations.json'
                child_path = root / 'fragment-set/fragment-0000/replicas.json'
                journal_path = root / 'fragment-set/fragment-0000/copy-2/archive.json'
                signed, child, journal = (json.loads(path.read_bytes()) for path in (placement, child_path, journal_path))
                intent = signed['authority']['placements'][0]['handoff']
                if change == 'original':
                    path = root / 'fragment-set/fragment-0000/copy-0/archive.json'
                    changed = json.loads(path.read_bytes())
                    changed['lease'] = 'changed-original-lease'
                    save(path, changed)
                elif change == 'enrollment':
                    changed = json.loads(enrollment)
                    changed['enrollment']['expires'] += 1
                    save(root / 'maintenance/enrollment.json', changed)
                elif change == 'grant':
                    save(root / 'grant-c.bin', b'different')
                elif change == 'child':
                    child['copies'][2]['archive_id'] = [123] * 32
                    save(child_path, child)
                elif change == 'journal':
                    journal['archive_id'] = [123] * 32
                    save(journal_path, journal)
                elif change == 'duplicate':
                    signed['authority']['placements'] *= 2
                    save(placement, signed)
                elif change == 'missing':
                    placement.unlink()
                else:
                    if change == 'phase':
                        intent['phase'] = 'complete'
                    elif change == 'expired':
                        intent['initial_journal']['requested_expiry'] = json.loads(enrollment)['enrollment']['expires'] + 1
                    elif change == 'shortened':
                        intent['initial_journal']['requested_expiry'] = int(time.time()) + 1
                    elif change == 'foreign':
                        intent['initial_journal']['grant_hex'] = b'foreign'.hex()
                    elif change == 'reuse':
                        intent['initial_journal']['archive_id'] = [1] * 32
                    child['handoff'] = copy.deepcopy(intent)
                    child['copies'][2]['archive_id'] = intent['initial_journal']['archive_id']
                    save(placement, signed)
                    save(child_path, child)
                    save(journal_path, intent['initial_journal'])
                with self.assertRaises((ValueError, FileNotFoundError)):
                    M['retained_current_during_core_loss'](root, value, keys, enrollment)

    def test_pending_identity_survives_resume_three_placements_and_delete_only_privately(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary) / 'private-storage-user'
            root.mkdir(mode=0o700)
            value, keys, enrollment, save = retained_private_fixture(root)
            binding = M['retained_current_during_core_loss'](root, value, keys, enrollment)
            save(root / M['RETAINED_INTENT_FILE'], binding)
            placement = root / 'fragment-set/placement-authorizations.json'
            signed = json.loads(placement.read_bytes())
            journal_path = root / 'fragment-set/fragment-0000/copy-2/archive.json'
            journal = json.loads(journal_path.read_bytes())
            # Mutable provider confirmations change; the initial identity/intent does not.
            for state, stored in ((3, M['CHUNK']), (4, 0)):
                journal.update(lease='new-confirmed-synthetic-lease', last_state=state,
                    last_stored_bytes=stored, last_expiry=int(time.time()) + 5400 if stored else 0)
                save(journal_path, journal)
                M['retained_intent_continuity'](root)
            for index in (2, 3):
                signed['authority']['placements'].append(dict(fragment=index, handoff={}))
            save(placement, signed)
            M['retained_intent_continuity'](root)  # Other placements are checked by the real CLI/full final gate.
            journal['requested_expiry'] += 1
            save(journal_path, journal)
            with self.assertRaises(ValueError):
                M['retained_intent_continuity'](root)
            journal['requested_expiry'] -= 1
            save(journal_path, journal)
            signed['authority']['placements'][0]['handoff']['initial_journal']['archive_id'] = [111] * 32
            save(placement, signed)
            with self.assertRaises(ValueError):
                M['retained_intent_continuity'](root)
            placement.unlink()
            with self.assertRaises(FileNotFoundError):
                M['retained_intent_continuity'](root)
            result = M['cleanup'](str(root))
            self.assertTrue(result['user_directory_removed'])
            self.assertFalse(root.exists())

    def test_current_intent_check_is_wired_without_new_public_fields_or_execution(self):
        source = (HERE / (SCENARIO + '-smoke.py')).read_text()
        lifecycle = source.split('\ndef lifecycle(', 1)[1].split('\ndef prepare(', 1)[0]
        self.assertIn('retained_current_during_core_loss(root, retained, keys, enrollment)', lifecycle)
        self.assertNotIn('retained_during_core_loss(retained)', lifecycle)
        self.assertLess(lifecycle.index('retained_intent_continuity(root)'), lifecycle.index('pre_withdrawal(root'))
        restore = source.split('\ndef restore(', 1)[1].split('\ndef validate_retirement_progress(', 1)[0]
        self.assertEqual(restore.count('retained_intent_continuity(root)'), 2)
        finish = source.split('\ndef finish(', 1)[1].split('\ndef cleanup(', 1)[0]
        self.assertEqual(finish.count('retained_intent_continuity(root)'), 2)

    def test_route_comparison_is_closed_and_only_valid_for_relay_scope_failure(self):
        value = dict(version=2, success=False, kind='private-storage-maintenance-lifecycle-failure',
            stage='start_sampler', code='sampler_failure', cursor_before=3, cursor_last=5,
            checkpoint_stage='waiting_for_core', owner_exit_status=0, owner_joined=True, cleanup_error=None,
            retained_status=None, sampler=dict(phase='sampling', operation='route_scope', code='invalid',
                samples=2, completed=1, failed=0, route_mismatch='relays_changed'))
        for context in ('same', 'changed', 'unobserved'):
            for relay in ('same', 'changed'):
                value['sampler']['route_comparison'] = dict(context_relation=context, relay_set_relation=relay)
                M['validate_lifecycle_failure'](value)
        for mutate in (
            lambda v: v['sampler'].update(operation='route_query'),
            lambda v: v['sampler'].update(code='process'),
            lambda v: v['sampler'].update(route_mismatch='path_ids_changed'),
            lambda v: v['sampler'].update(route_comparison=None),
            lambda v: v['sampler']['route_comparison'].update(context_relation='SECRET'),
            lambda v: v['sampler']['route_comparison'].update(relay_set_relation='unobserved'),
            lambda v: v['sampler']['route_comparison'].update(raw_ids=['SECRET']),
            lambda v: v['sampler']['route_comparison'].pop('relay_set_relation'),
        ):
            invalid = copy.deepcopy(value)
            mutate(invalid)
            with self.assertRaises(ValueError):
                M['validate_lifecycle_failure'](invalid)

    def test_retained_failure_codes_distinguish_each_unchanged_predicate(self):
        value, _, _ = FIXTURE['OLD']['cli_fixture']('committed')
        mutations = (
            (lambda v: v.update(physical_payload_charge_upper_bound=0), 'lifecycle_charge_changed'),
            (lambda v: v['fragments'].pop(), 'lifecycle_fragment_count_changed'),
            (lambda v: v['fragments'][0]['copies'].append(dict(charge='unattempted', last_confirmed_expiry=0)),
                'lifecycle_copy_count_changed'),
            (lambda v: v.update(placement_authorizations=1), 'lifecycle_placement_count_changed'))
        for mutate, code in mutations:
            invalid = copy.deepcopy(value)
            mutate(invalid)
            diagnostic = {}
            with patch.dict(M['retained_during_core_loss'].__globals__, LIFECYCLE_DIAGNOSTIC=diagnostic):
                with self.assertRaises(ValueError) as error:
                    M['retained_during_core_loss'](invalid)
            self.assertEqual(M['failure_code'](error.exception), code)
            M['validate_retained_status'](diagnostic['retained_status'])
            self.assertEqual(diagnostic['retained_status']['physical_payload_charge_upper_bound'],
                invalid['physical_payload_charge_upper_bound'])
        # Uncertainty/retention changes alone do not change the original total
        # charge/geometry acceptance, nor prove live remote availability.
        value['fragments'][0]['copies'][0].update(charge='uncertain', last_confirmed_expiry=99)
        value['fragments'][0]['copies'][1]['last_confirmed_expiry'] = 101
        M['retained_during_core_loss'](value)
        diagnostic = M['retained_status_diagnostic'](value, 100)
        self.assertEqual(diagnostic['charge_states']['uncertain'], 1)
        self.assertGreaterEqual(diagnostic['retained_expiries']['expired'], 1)
        self.assertGreaterEqual(diagnostic['retained_expiries']['unexpired'], 1)

    def test_retained_status_projection_is_bounded_closed_and_missing_is_unknown(self):
        value, _, _ = FIXTURE['OLD']['cli_fixture']('committed')
        value['private_path'] = 'PRIVATE_CANARY'
        value['fragments'][0]['copies'][0].update(provider_key='PRIVATE_CANARY',
            charge=['PRIVATE_CANARY'], last_confirmed_expiry=True)
        projected = M['retained_status_diagnostic'](value, 100)
        self.assertNotIn('PRIVATE_CANARY', json.dumps(projected))
        self.assertEqual(projected['charge_states']['unknown'], 1)
        self.assertGreaterEqual(projected['retained_expiries']['unknown'], 1)
        self.assertFalse(projected['placement_field_present'])
        self.assertEqual(projected['placement_authorizations'], 0)  # Original v1 report shape.
        for invalid in (None, {}, dict(fragments=[{}]), dict(fragments=[{}] * 65),
                dict(fragments=[dict(copies=[{}] * 65)]),
                dict(value, physical_payload_charge_upper_bound=2**64, placement_authorizations=True)):
            diagnostic = M['retained_status_diagnostic'](invalid, 100)
            M['validate_retained_status'](diagnostic)
            self.assertLess(len(json.dumps(diagnostic)), 8192)
        self.assertIsNone(M['retained_status_diagnostic'](None, 100)['placement_authorizations'])
        for mutate in (lambda v: v.update(private_path='PRIVATE_CANARY'),
                lambda v: v.update(fragment_count=True), lambda v: v['copy_counts'].append(2),
                lambda v: v['charge_states'].update(unknown=4097),
                lambda v: v['retained_expiries'].update(expired=True)):
            invalid = copy.deepcopy(projected)
            mutate(invalid)
            with self.assertRaises(ValueError):
                M['validate_retained_status'](invalid)

    def test_lifecycle_v3_exports_only_projected_status_and_keeps_v1_v2_distinct(self):
        value, _, _ = FIXTURE['OLD']['cli_fixture']('committed')
        context = dict(stage='verify_retained', cursor_before=3, cursor_last=4,
            checkpoint_stage='core_unavailable', owner_exit_status=0, owner_joined=True,
            cleanup_error=None, retained_status=M['retained_status_diagnostic'](value, 100),
            retained_status_scope='core_loss', reconcile_status=None, fresh_turn_detail=None,
            baseline_reason=None)
        with patch.dict(M['failure_receipt'].__globals__, LIFECYCLE_DIAGNOSTIC=context, SAMPLER_DIAGNOSTIC={}):
            receipt = M['failure_receipt'](ValueError('core loss changed copy count'))
        self.assertEqual(receipt['version'], 3)
        M['validate_lifecycle_failure'](receipt)
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / 'failure.json'
            path.write_text(json.dumps(receipt)); path.chmod(0o600)
            result = subprocess.run([sys.executable, '-B', str(HERE / 'private-storage-maintenance-smoke.py'),
                'lifecycle-failure', str(path)], capture_output=True, check=True, timeout=5)
            self.assertEqual(json.loads(result.stdout), receipt)
        historical_v2 = dict(receipt, version=2)
        for key in ('retained_status_scope', 'reconcile_status', 'fresh_turn_detail', 'baseline_reason'):
            del historical_v2[key]
        M['validate_lifecycle_failure'](historical_v2)
        historical = dict(historical_v2, version=1, code='lifecycle_charge_changed')
        del historical['retained_status']
        M['validate_lifecycle_failure'](historical)
        for invalid in (dict(receipt, version=1), dict(receipt, version=2), dict(historical, version=2),
                dict(receipt, retained_status=dict(receipt['retained_status'], private='SECRET'))):
            with self.assertRaises(ValueError):
                M['validate_lifecycle_failure'](invalid)

    def test_every_lifecycle_flag_and_cursor_is_required(self):
        value = FIXTURE['fixture']()['lifecycle']
        M['validate_lifecycle'](value)
        for key, entry in value.items():
            invalid = copy.deepcopy(value)
            invalid[key] = False if type(entry) is bool else -1
            with self.subTest(key=key), self.assertRaises(ValueError):
                M['validate_lifecycle'](invalid)
        for mutate in (
                lambda v: v.update(cursor_after_resume=v['cursor_at_pause']),
                lambda v: v.update(cursor_at_core_loss=v['cursor_after_reconnect']),
                lambda v: v.update(cursor_after_resume=True),
                lambda v: v.update(secret='forbidden')):
            invalid = copy.deepcopy(value)
            mutate(invalid)
            with self.assertRaises(ValueError):
                M['validate_lifecycle'](invalid)

    def test_real_owned_python_child_joins_on_sigterm_and_drains(self):
        # This executes Python only, not the core, Rust, a network or a VM.
        code = ('import signal,sys,time\n'
            'signal.signal(signal.SIGTERM, lambda *_: sys.exit(0))\n'
            'print(\'{"stage":"ready","turns":1}\',flush=True)\n'
            'while True: time.sleep(.1)\n')
        child = M['OwnerProcess']([sys.executable, '-I', '-B', '-c', code])
        try:
            M['wait_owner'](child, lambda: child.reports(), seconds=3)
            child.stop()
            self.assertEqual(child.process.returncode, 0)
            self.assertTrue(all(not thread.is_alive() for thread in child.threads))
            self.assertEqual(child.reports(), [dict(stage='ready', turns=1)])
        finally:
            child.close()

    def test_output_is_bounded_and_still_drained(self):
        child = M['OwnerProcess']([sys.executable, '-I', '-B', '-c',
            'import sys; sys.stdout.buffer.write(b"x"*600000); sys.stderr.buffer.write(b"y"*600000)'])
        child.process.wait(timeout=5)
        try:
            with self.assertRaises(ValueError):
                child.join()
            self.assertTrue(all(not thread.is_alive() for thread in child.threads))
            self.assertTrue(all(len(buffer) <= child.LIMIT for buffer in child.buffers))
            self.assertTrue(all(child.overflow))
        finally:
            try:
                child.close()
            except ValueError:
                pass

    def test_regular_coordinator_turn_records_remain_count_and_byte_bounded(self):
        for count, accepted in ((34, True), (M['MAX_LIFECYCLE_CURSOR'], True),
                (M['MAX_LIFECYCLE_CURSOR'] + 1, False)):
            with self.subTest(count=count):
                child = M['OwnerProcess']([sys.executable, '-I', '-B', '-c',
                    'import json,sys\nfor index in range(int(sys.argv[1])):\n'
                    ' print(json.dumps(dict(stage="turn_completed",turns=index+1)),flush=True)\n', str(count)])
                try:
                    child.process.wait(timeout=5)
                    child.join()
                    self.assertLessEqual(len(child.buffers[0]), child.LIMIT)
                    if accepted:
                        self.assertEqual(len(child.reports()), count)
                    else:
                        with self.assertRaisesRegex(ValueError, 'bounded owner output'):
                            child.reports()
                finally:
                    child.close()


if __name__ == '__main__':
    unittest.main()
