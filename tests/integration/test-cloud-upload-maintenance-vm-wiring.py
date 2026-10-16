#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-only
"""Inert VM dispatch/export contracts, never Cloud/core/network acceptance."""
import json
import os
from pathlib import Path
import runpy
import shlex
import subprocess
import tarfile
import tempfile
import unittest

HERE = Path(__file__).resolve().parent
RUNNER = HERE / 'run-alpha-topology-vm.sh'
TEXT = RUNNER.read_text()
WORKFLOW = (HERE.parents[1] / '.github/workflows/alpha-topology.yml').read_text()
SCENARIO = 'cloud-upload-maintenance'
OLD_SCENARIO = 'private-storage-maintenance'
GUEST = TEXT.split("<<'GUEST_DRIVER_SCRIPT'\n", 1)[1].split('\nGUEST_DRIVER_SCRIPT', 1)[0]
SIDECAR_HELPERS = {
    'private-storage-fixture-correlation.json': 'storage-fixture-correlation-sampler.py',
    'private-storage-maintenance-helper-acquire.json': 'storage-acquire-diagnostic.py',
}


def sidecar_fixtures(home):
    result = {}
    for name, helper_name in SIDECAR_HELPERS.items():
        helper = home / 'source/tests/integration' / helper_name
        helper.parent.mkdir(parents=True, exist_ok=True)
        helper.write_bytes((HERE / helper_name).read_bytes())
        module = runpy.run_path(str(helper))
        value = module['Samples']('publish').report() if 'Samples' in module else module['empty']('absent')
        result[name] = module['encoded'](value)
    return result


def diagnostics():
    code = TEXT.split("<<'GUEST_DIAGNOSTICS_PYTHON'\n", 1)[1].split('\nGUEST_DIAGNOSTICS_PYTHON', 1)[0]
    namespace = {'__name__': 'inert_cloud_upload_diagnostics'}
    exec(compile(code, 'closed_guest_diagnostics', 'exec'), namespace)
    return namespace


def collect(module, home, opt, scenario):
    return module['collect'](home, opt, 'a' * 40, scenario, 124,
        cgroups=home / 'no-cgroups', proc=home / 'no-proc')


class Wiring(unittest.TestCase):
    def test_preview_is_explicit_and_repeated_selection_is_not_additive(self):
        for first, last in ((SCENARIO, OLD_SCENARIO), (OLD_SCENARIO, SCENARIO)):
            result = subprocess.run(['sh', str(RUNNER), '--preview', '--scenario', first,
                '--scenario', last], capture_output=True, text=True, check=True, timeout=5)
            self.assertIn('PREVIEW ONLY', result.stdout)
            self.assertIn(last, result.stdout.lower())
            self.assertNotIn(first, result.stdout.lower())
        self.assertIn('two cold decrypted reads', result.stdout)

    def test_topology_selection_resets_both_scenarios_without_diagnostic_optin_leak(self):
        # Stop before preview/execute dispatch: only original argument parsing runs.
        prefix = (HERE / 'kvm-alpha-topology.sh').read_text().split('if [ "$mode" = preview ]; then', 1)[0]
        for choices, expected in (
                ((SCENARIO,), 'yes no yes 9'),
                ((OLD_SCENARIO,), 'no yes yes 9'),
                ((SCENARIO, OLD_SCENARIO), 'no yes yes 9'),
                ((OLD_SCENARIO, SCENARIO), 'yes no yes 9'),
                ((SCENARIO, OLD_SCENARIO, 'private-storage-peer'), 'no no no 9')):
            arguments = [argument for choice in choices for argument in ('--scenario', choice)]
            result = subprocess.run(['sh', '-eu', '-c', prefix
                + '\nprintf "%s %s %s %s\\n" "$cloud_upload_maintenance" "$storage_fixture_correlation"'
                + ' "$private_storage_maintenance" "$storage_consumer_profile_version"', 'inert', *arguments],
                capture_output=True, text=True, check=True, timeout=5)
            self.assertEqual(result.stdout, expected + '\n')

    def test_generated_guest_parses_and_forwards_exact_scenario(self):
        subprocess.run(['sh', '-n', str(RUNNER)], check=True, capture_output=True, timeout=5)
        subprocess.run(['sh', '-n'], input=GUEST, text=True, check=True, capture_output=True, timeout=5)
        code = GUEST.split('topology_scenario=alpha\n', 1)[1].split('\nguest_phase topology', 1)[0]
        result = subprocess.run(['sh', '-eu', '-c', 'scenario=$1; topology_scenario=alpha;\n' + code
            + '\nprintf "%s\\n" "$topology_scenario"', 'inert', SCENARIO],
            text=True, capture_output=True, check=True, timeout=5)
        self.assertEqual(result.stdout, SCENARIO + '\n')

    def test_new_provision_is_additive_and_guest_only_without_old_pin_changes(self):
        start = GUEST.index('if [ "$scenario" = signal-backup ]', GUEST.index('test -x tests/packaging'))
        end = GUEST.index('\nguest_phase build', start)
        code = GUEST[start:end].replace('/opt/volparossa-node/bin/node', 'inert_node')
        # Only the fixed launch boundaries are inert doubles; real dispatch runs.
        prefix = 'guest_phase() { :; }; sudo() { printf "sudo %s\\n" "$*"; }; inert_node() { printf "node %s\\n" "$*"; };\n'
        for scenario, expected in ((OLD_SCENARIO, 2), (SCENARIO, 4)):
            result = subprocess.run(['sh', '-eu', '-c', 'scenario=$1;\n' + prefix + code,
                'inert', scenario], text=True, capture_output=True, check=True, timeout=5)
            calls = result.stdout.splitlines()
            self.assertEqual(len(calls), expected)
            self.assertEqual(calls[:2], [
                'sudo -n python3 -B tests/integration/storage-consumer-maintenance-provision.py provision --download --profile-version 9',
                'node --test tests/integration/test-storage-consumer-maintenance.mjs'])
            if scenario == SCENARIO:
                self.assertEqual(calls[2:], [
                    'sudo -n python3 -B tests/integration/cloud-upload-maintenance-provision.py provision --download --profile-version 5',
                    'node --test tests/integration/test-cloud-upload-maintenance.mjs'])
        self.assertIn('private-storage-maintenance ] || [ "$scenario" = cloud-upload-maintenance ]; then\n    guest_phase storage-maintenance-targeted-tests', GUEST)
        self.assertIn('storage::peer::replicas::fragments::maintenance', GUEST)
        self.assertIn('private-storage-maintenance-smoke.py owner-test-output', GUEST)
        self.assertIn('test "$(cat /home/vpci/storage-maintenance-tests.status)" = 0', GUEST)

    def test_only_new_outer_deadline_changes_never_finite_authority(self):
        start = TEXT.index('driver_time_bound=2400s\n')
        code = TEXT[start:TEXT.index('\n[ "$scenario" != weather-decoder-abi ]', start)]
        for scenario, seconds in ((SCENARIO, '14400s'), (OLD_SCENARIO, '7200s'), ('datapath', '2400s')):
            result = subprocess.run(['sh', '-eu', '-c', 'scenario=$1;\n' + code
                + '\nprintf "%s\\n" "$driver_time_bound"', 'inert', scenario],
                text=True, capture_output=True, check=True, timeout=5)
            self.assertEqual(result.stdout, seconds + '\n')
        line = next(line for line in WORKFLOW.splitlines() if 'timeout-minutes:' in line)
        self.assertIn("inputs.scenario == 'cloud-upload-maintenance' && 270", line)
        self.assertIn("(inputs.scenario == 'signal-backup' || inputs.scenario == 'signal-backup-fragments' || inputs.scenario == 'private-storage-maintenance') && 150", line)
        self.assertNotIn('authorization-expires-at', GUEST)

    def test_workflow_has_separate_failclosed_gate_and_source_checks(self):
        self.assertIn('          - cloud-upload-maintenance\n', WORKFLOW)
        start = WORKFLOW.index('      - name: Require actual automatic Cloud upload maintenance continuation')
        gate = WORKFLOW[start:WORKFLOW.index('\n      - name:', start + 1)]
        for required in ("if: always() && env.VOLPAROSSA_ALPHA_SCENARIO == 'cloud-upload-maintenance'",
                'test "$TOPOLOGY_EXIT_CODE" = 0',
                'cloud-upload-maintenance-evidence.py check-report-v7 "$report" "$GITHUB_SHA"',
                'private-storage-maintenance-smoke.py report-consumer-v9 "$original" "$GITHUB_SHA"',
                'host-state-before.json', 'host-state-after.json'):
            self.assertIn(required, gate)
        self.assertNotIn('check-report-v5', gate)
        self.assertNotIn('check-report-v6', gate)
        self.assertNotIn('report-consumer-v7', gate)
        self.assertNotIn('report-consumer-v8', gate)
        self.assertEqual(WORKFLOW.count("&& env.VOLPAROSSA_ALPHA_SCENARIO != 'cloud-upload-maintenance'"), 2)
        for suite in ('provision', 'smoke', 'evidence', 'shell', 'vm-wiring'):
            self.assertIn(f'python3 -B tests/integration/test-cloud-upload-maintenance-{suite}.py', WORKFLOW)
        self.assertIn("if: always() && env.VOLPAROSSA_ALPHA_SCENARIO == 'private-storage-maintenance'", WORKFLOW)

    def test_exact_normal_and_emergency_closure_counts_all_recovery_slots(self):
        module = diagnostics()
        old = runpy.run_path(str(HERE / 'private-storage-maintenance-smoke.py'))
        new = runpy.run_path(str(HERE / 'cloud-upload-maintenance-evidence.py'))
        self.assertEqual(set(old['EXPORT_NAMES']), module['MAINTENANCE_NAMES'])
        self.assertEqual(set(old['EXPORT_NAMES']) | set(new['EXPORT_NAMES'])
            | set(new['CURRENT_EXPORT_NAMES']), module['CLOUD_UPLOAD_NAMES'])
        self.assertEqual(len(module['MAINTENANCE_NAMES']), 115)
        self.assertEqual(len(module['CLOUD_UPLOAD_NAMES']), 170)
        self.assertIn('private-storage-provider-activity.json', module['CLOUD_UPLOAD_NAMES'])
        self.assertTrue(set(SIDECAR_HELPERS) <= module['CLOUD_UPLOAD_NAMES'])
        recovery = {'guest-phase.txt', 'current-phase', 'guest-exit-status', 'host-state-before.json', 'host-state-after.json'}
        self.assertFalse(module['CLOUD_UPLOAD_NAMES'] & recovery)
        self.assertEqual(module['CLOUD_UPLOAD_FILE_COUNT_LIMIT'], len(module['CLOUD_UPLOAD_NAMES'] | recovery))
        self.assertEqual(module['TOTAL_LIMIT'], 8388608)
        self.assertEqual(module['FILE_LIMIT'], 131072)
        self.assertEqual(module['FILE_COUNT_LIMIT'], 64)
        start = GUEST.index('elif [ "$scenario" = cloud-upload-maintenance ]; then\n    {')
        block = GUEST[start:GUEST.index('\nelif ', start + 1)]
        self.assertIn('private-storage-maintenance-smoke.py export-names', block)
        self.assertIn('cloud-upload-maintenance-evidence.py export-names-v7', block)
        self.assertIn('sort -u', block)
        self.assertIn('[ ! -L "$retained_path" ]', block)
        self.assertIn('retained_limit=1048576', block)
        self.assertIn('[ "$retained" = cloud-upload-evidence.json ]', block)
        self.assertIn('[ "$retained_size" -le 2097152 ]', block)
        self.assertIn('(.schema_version == 3 or .schema_version == 4 or .schema_version == 5 or .schema_version == 6 or .schema_version == 7) and .kind == "cloud-upload-maintenance-evidence"', block)
        self.assertNotIn(' -czf /home/vpci/alpha-output.tar.gz .', block)

    def test_all_original_named_bytes_survive_duplicate_published_work_roots(self):
        module = diagnostics()
        with tempfile.TemporaryDirectory() as temporary:
            base = Path(temporary); home, opt = base / 'home', base / 'opt'
            roots = [home / 'alpha-output', opt / ('va.' + 'a' * 32 + '.Abc123')]
            (home / 'alpha-output').mkdir(parents=True)
            (home / 'guest-phase.txt').write_text('topology\n')
            sidecars = sidecar_fixtures(home)
            for root in roots:
                root.mkdir(parents=True, exist_ok=True)
                for name in module['CLOUD_UPLOAD_NAMES'] | {'host-state-before.json', 'host-state-after.json'}:
                    (root / name).write_text('{}\n')
                (root / 'guest-exit-status').write_text('1\n')
                (root / 'current-phase').write_text('cloud-upload-exercise\n')
                for name, raw in sidecars.items():
                    (root / name).write_bytes(raw)
                for private in ('identity.key', 'service.json', 'cloud-upload-private.log', 'cloud-upload-new.json'):
                    (root / private).write_text('NEVER_EXPORT_PRIVATE')
            archive = collect(module, home, opt, SCENARIO)
            with tarfile.open(archive, 'r:gz') as bundle:
                summary = json.load(bundle.extractfile('vm-incomplete.json'))
                self.assertEqual(len(summary['diagnostics']['files']), 175)
                self.assertFalse(summary['success'])
                self.assertFalse(summary['cleanup']['verified'])
                self.assertTrue(all(not item['truncated'] for item in summary['diagnostics']['files']))
                self.assertEqual({Path(item['file']).name for item in summary['diagnostics']['files']},
                    module['CLOUD_UPLOAD_NAMES'] | {'guest-phase.txt', 'current-phase', 'guest-exit-status',
                        'host-state-before.json', 'host-state-after.json'})
                self.assertFalse(any(b'NEVER_EXPORT_PRIVATE' in bundle.extractfile(m).read() for m in bundle.getmembers()))
                for name, raw in sidecars.items():
                    retained = next(item for item in bundle.getmembers() if Path(item.name).name == name)
                    self.assertEqual(bundle.extractfile(retained).read(), raw)
            old = collect(module, home, opt, OLD_SCENARIO)
            with tarfile.open(old, 'r:gz') as bundle:
                self.assertFalse(any(Path(name).name.startswith('cloud-upload-') for name in bundle.getnames()))
                self.assertLessEqual(len(json.load(bundle.extractfile('vm-incomplete.json'))['diagnostics']['files']), 128)

    def test_joined_emergency_sidecars_require_original_closed_validators(self):
        module = diagnostics()
        for scenario in (OLD_SCENARIO, SCENARIO):
            for name, helper in SIDECAR_HELPERS.items():
                for variant in ('valid', 'malformed', 'private-field', 'oversize', 'missing-validator', 'symlink', 'fifo'):
                    with self.subTest(scenario=scenario, name=name, variant=variant), tempfile.TemporaryDirectory() as temporary:
                        home, opt = Path(temporary) / 'home', Path(temporary) / 'opt'
                        root = home / 'alpha-output'; root.mkdir(parents=True)
                        raw = sidecar_fixtures(home)[name]
                        if variant == 'malformed':
                            raw = b'{"unfinished":'
                        elif variant == 'private-field':
                            value = json.loads(raw); value['private_identifier'] = 'NEVER_EXPORT_PRIVATE'
                            raw = json.dumps(value).encode()
                        elif variant == 'oversize':
                            raw += b' ' * 16385
                        if variant == 'missing-validator':
                            (home / 'source/tests/integration' / helper).unlink()
                        path = root / name
                        if variant == 'symlink':
                            target = home / 'private-target'; target.write_bytes(raw); path.symlink_to(target)
                        elif variant == 'fifo':
                            os.mkfifo(path)
                        else:
                            path.write_bytes(raw)
                        (root / 'private-storage-maintenance-smoke.json').write_text('{}\n')
                        archive = collect(module, home, opt, scenario)
                        with tarfile.open(archive, 'r:gz') as bundle:
                            self.assertEqual('published/' + name in bundle.getnames(), variant == 'valid')
                            if variant == 'valid':
                                self.assertEqual(bundle.extractfile('published/' + name).read(), raw)
                            self.assertEqual(bundle.extractfile('published/private-storage-maintenance-smoke.json').read(), b'{}\n')
                            summary = json.load(bundle.extractfile('vm-incomplete.json'))
                            self.assertFalse(summary['success'])
                            self.assertFalse(summary['cleanup']['verified'])
                            self.assertFalse(any(b'NEVER_EXPORT_PRIVATE' in bundle.extractfile(item).read()
                                for item in bundle.getmembers()))

    def test_normal_cloud_sidecars_are_optional_closed_projections_not_raw_exports(self):
        start = GUEST.index('elif [ "$scenario" = cloud-upload-maintenance ]; then\n    {')
        block = GUEST[start:GUEST.index('\nelif ', start + 1)].split('\n', 1)[1]
        for name, helper in SIDECAR_HELPERS.items():
            for variant in ('valid', 'malformed', 'private-field', 'oversize', 'missing-validator', 'symlink', 'fifo'):
                with self.subTest(name=name, variant=variant), tempfile.TemporaryDirectory() as temporary:
                    home = Path(temporary); output = home / 'alpha-output'; output.mkdir()
                    raw = sidecar_fixtures(home)[name]
                    if variant == 'malformed':
                        raw = b'{"unfinished":'
                    elif variant == 'private-field':
                        value = json.loads(raw); value['private_identifier'] = 'NEVER_EXPORT_PRIVATE'
                        raw = json.dumps(value).encode()
                    elif variant == 'oversize':
                        raw += b' ' * 16385
                    if variant == 'missing-validator':
                        (home / 'source/tests/integration' / helper).unlink()
                    path = output / name
                    if variant == 'symlink':
                        target = home / 'private-target'; target.write_bytes(raw); path.symlink_to(target)
                    elif variant == 'fifo':
                        os.mkfifo(path)
                    else:
                        path.write_bytes(raw)
                    (output / 'private-storage-maintenance-smoke.json').write_text('{}\n')
                    # Original shell export with fixed names and real validators;
                    # no guest, privilege, network or collector process is started.
                    script = '''python3() {
  case "$*" in
    '-B tests/integration/private-storage-maintenance-smoke.py export-names') printf '%s\\n' "$export_name" private-storage-maintenance-smoke.json ;;
    '-B tests/integration/cloud-upload-maintenance-evidence.py export-names-v7') : ;;
    '-I -B tests/integration/storage-fixture-correlation-sampler.py validate-stdin'|'-I -B tests/integration/storage-acquire-diagnostic.py validate-stdin') command python3 "$@" ;;
    *) return 99 ;;
  esac
}
export_name=$1
primary_status=73
''' + block.replace('/home/vpci', shlex.quote(str(home))) + '\nprintf "%s\\n" "$primary_status"\n'
                    result = subprocess.run(['sh', '-eu', '-c', script, 'inert', name],
                        cwd=home / 'source', capture_output=True, text=True, check=True, timeout=5)
                    self.assertEqual(result.stdout, '73\n')
                    with tarfile.open(home / 'alpha-output.tar.gz', 'r:gz') as bundle:
                        self.assertEqual(name in bundle.getnames(), variant == 'valid')
                        if variant == 'valid':
                            self.assertEqual(bundle.extractfile(name).read(), raw)
                        self.assertEqual(bundle.extractfile('private-storage-maintenance-smoke.json').read(), b'{}\n')
                        self.assertFalse(any(b'NEVER_EXPORT_PRIVATE' in bundle.extractfile(item).read()
                            for item in bundle.getmembers()))

    def test_only_named_current_evidence_gets_two_mib_without_partial_export(self):
        module = diagnostics()
        for name, version, kind, size, included in (
                ('cloud-upload-evidence.json', 3, 'cloud-upload-maintenance-evidence', 1050000, True),
                ('cloud-upload-evidence.json', 4, 'cloud-upload-maintenance-evidence', 1050000, True),
                ('cloud-upload-evidence.json', 5, 'cloud-upload-maintenance-evidence', 1050000, True),
                ('cloud-upload-evidence.json', 6, 'cloud-upload-maintenance-evidence', 1050000, True),
                ('cloud-upload-evidence.json', 7, 'cloud-upload-maintenance-evidence', 1050000, True),
                ('cloud-upload-evidence.json', 8, 'cloud-upload-maintenance-evidence', 1050000, False),
                ('cloud-upload-evidence.json', 2, 'cloud-upload-maintenance-evidence', 1050000, False),
                ('cloud-upload-evidence.json', 3, 'wrong', 1050000, False),
                ('cloud-upload-evidence.json', 4, 'wrong', 1050000, False),
                ('cloud-upload-evidence.json', 5, 'wrong', 1050000, False),
                ('cloud-upload-evidence.json', 6, 'wrong', 1050000, False),
                ('cloud-upload-evidence.json', 7, 'wrong', 1050000, False),
                ('cloud-upload-prepare.json', 6, 'cloud-upload-maintenance-evidence', 1050000, False),
                ('cloud-upload-prepare.json', 7, 'cloud-upload-maintenance-evidence', 1050000, False),
                ('cloud-upload-prepare.json', 3, 'cloud-upload-maintenance-evidence', 1050000, False),
                ('cloud-upload-evidence.json', 3, 'cloud-upload-maintenance-evidence', 2097153, False),
                ('cloud-upload-evidence.json', 4, 'cloud-upload-maintenance-evidence', 2097153, False),
                ('cloud-upload-evidence.json', 5, 'cloud-upload-maintenance-evidence', 2097153, False),
                ('cloud-upload-evidence.json', 6, 'cloud-upload-maintenance-evidence', 2097153, False),
                ('cloud-upload-evidence.json', 7, 'cloud-upload-maintenance-evidence', 2097153, False)):
            with tempfile.TemporaryDirectory() as temporary:
                base = Path(temporary); home, opt = base / 'home', base / 'opt'
                root = home / 'alpha-output'; root.mkdir(parents=True)
                raw = json.dumps(dict(schema_version=version, kind=kind, padding='x' * size)).encode()
                (root / name).write_bytes(raw)
                archive = collect(module, home, opt, SCENARIO)
                with tarfile.open(archive, 'r:gz') as bundle:
                    self.assertEqual('published/' + name in bundle.getnames(), included)
                    if included:
                        self.assertEqual(bundle.extractfile('published/' + name).read(), raw)
                    summary = json.load(bundle.extractfile('vm-incomplete.json'))
                    self.assertLessEqual(summary['diagnostics']['captured_bytes'], 8388608)
                    self.assertFalse(summary['success'])

    def test_normal_guest_export_preserves_v6_v7_bytes_and_rejects_wrong_large_records(self):
        start = GUEST.index('elif [ "$scenario" = cloud-upload-maintenance ]; then\n    {')
        block = GUEST[start:GUEST.index('\nelif ', start + 1)].split('\n', 1)[1]
        for name, version, kind, size, included in (
                ('cloud-upload-evidence.json', 6, 'cloud-upload-maintenance-evidence', 1050000, True),
                ('cloud-upload-evidence.json', 7, 'cloud-upload-maintenance-evidence', 1050000, True),
                ('cloud-upload-evidence.json', 8, 'cloud-upload-maintenance-evidence', 1050000, False),
                ('cloud-upload-evidence.json', 6, 'wrong', 1050000, False),
                ('cloud-upload-evidence.json', 7, 'wrong', 1050000, False),
                ('cloud-upload-prepare.json', 6, 'cloud-upload-maintenance-evidence', 1050000, False),
                ('cloud-upload-prepare.json', 7, 'cloud-upload-maintenance-evidence', 1050000, False),
                ('cloud-upload-evidence.json', 6, 'cloud-upload-maintenance-evidence', 2097153, False),
                ('cloud-upload-evidence.json', 7, 'cloud-upload-maintenance-evidence', 2097153, False)):
            with tempfile.TemporaryDirectory() as temporary:
                home = Path(temporary)
                output = home / 'alpha-output'; output.mkdir()
                raw = json.dumps(dict(schema_version=version, kind=kind, padding='x' * size)).encode()
                (output / name).write_bytes(raw)
                (output / 'identity.key').write_text('PRIVATE_CANARY')
                # Run the original guest export block with only its source of
                # allowlisted names replaced; no VM, privileged path or network.
                script = '''python3() {
  case "$2:$3" in
    tests/integration/cloud-upload-maintenance-evidence.py:export-names-v7) printf '%s\\n' "$export_name" ;;
    tests/integration/private-storage-maintenance-smoke.py:export-names) : ;;
    *) return 99 ;;
  esac
}
export_name=$1
''' + block.replace('/home/vpci', shlex.quote(str(home)))
                result = subprocess.run(['sh', '-eu', '-c', script, 'inert', name],
                    capture_output=True, text=True, timeout=5)
                self.assertEqual(result.returncode == 0, included, result.stderr)
                archive = home / 'alpha-output.tar.gz'
                self.assertEqual(archive.exists(), included)
                if included:
                    with tarfile.open(archive, 'r:gz') as bundle:
                        self.assertEqual(bundle.getnames(), [name])
                        self.assertEqual(bundle.extractfile(name).read(), raw)

    def test_outcome_priority_bounds_and_rejected_partial_or_unsafe_files(self):
        module = diagnostics()
        with tempfile.TemporaryDirectory() as temporary:
            base = Path(temporary); home, opt = base / 'home', base / 'opt'
            roots = [home / 'alpha-output', *(opt / ('va.' + str(i) * 32 + '.Abc123') for i in range(4))]
            for i, root in enumerate(roots):
                root.mkdir(parents=True)
                for name in module['CLOUD_UPLOAD_NAMES']:
                    (root / name).write_text(json.dumps({'root': i}))
                (root / 'cloud-upload-provision.json').write_text('{"unfinished":')
                (root / 'cloud-upload-evidence.json').write_text('x' * (1048576 + 1))
                (root / 'cloud-upload-prepare.json').unlink()
                (root / 'cloud-upload-prepare.json').symlink_to(root / 'cloud-upload-finish.json')
                path = root / 'cloud-upload-isolation.json'; path.unlink(); os.mkfifo(path)
            archive = collect(module, home, opt, SCENARIO)
            with tarfile.open(archive, 'r:gz') as bundle:
                names = bundle.getnames()
                summary = json.load(bundle.extractfile('vm-incomplete.json'))
                self.assertLessEqual(len(summary['diagnostics']['files']), 175)
                self.assertLessEqual(summary['diagnostics']['captured_bytes'], 8388608)
                for label in ('published', *(f'work-{i}' for i in range(1, 5))):
                    for name in ('cloud-upload-maintenance-smoke.json', 'cloud-upload-finish.json',
                            'private-storage-maintenance-lifecycle-failure.json'):
                        self.assertIn(f'{label}/{name}', names)
                for suffix in ('cloud-upload-provision.json', 'cloud-upload-evidence.json',
                        'cloud-upload-prepare.json', 'cloud-upload-isolation.json'):
                    self.assertFalse(any(name.endswith(suffix) for name in names))
                self.assertFalse(any(name.endswith('.tail') for name in names))


if __name__ == '__main__':
    unittest.main()
