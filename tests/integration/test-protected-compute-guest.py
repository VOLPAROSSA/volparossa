#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-only
"""Inert guest evidence contracts. Synthetic text fixtures; never Cargo or firmware."""
import copy
import importlib.util
import json
import os
from pathlib import Path
import re
import tempfile
import unittest
from unittest.mock import patch

HERE = Path(__file__).resolve().parent


def load(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    value = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(value)
    return value


G = load('guest_probe', HERE / 'protected-compute-guest.py')
T = load('admission_contracts', HERE / 'test-protected-compute-admission.py')
T.P = G.P


def log():
    return ('running 16 tests\n' + ''.join('test ' + name + ' ... ok\n' for name in G.TESTS)
        + 'test result: ok. 16 passed; 0 failed; 0 ignored; 0 measured; 500 filtered out; finished in 0.1s\n').encode()


def prepare(root, work, packages):
    T.public_trial_fixture(root, work, packages, historical=False, local_policy=True)
    G.P.receipt(work, local_policy=True)


def fake_run(argv, output, seconds):
    assert argv == G.ARGV and seconds == 300
    G.P.write(output, log())
    return T.tool_outcome()


class GuestEvidenceContracts(unittest.TestCase):
    def test_exact_guest_names_are_present_in_source(self):
        raw = (G.P.ROOT / 'crates/volparossa-content/src/provider/compute/guest/tests.rs').read_text()
        names = re.findall(r'#\[test\]\s+fn (\w+)\(', raw)
        self.assertEqual(len(names), 16)
        self.assertEqual({G.PREFIX + name for name in names}, set(G.TESTS))

    def test_exact_success_has_no_hardware_or_private_release_claim(self):
        self.assertEqual(G.verify_tests(log())['passed'], 16)
        for key in ('successful_firmware_quote', 'hardware_attestation', 'full_appraisal',
                'worker_admission', 'private_input_release', 'protected_execution'):
            self.assertIs(G.SCOPE[key], False)

    def test_empty_missing_duplicate_unknown_failed_or_ignored_tests_reject(self):
        good = log()
        variants = [b'', good.replace(G.TESTS[0].encode(), G.TESTS[1].encode()),
            good.replace(G.TESTS[0].encode(), b'unknown'), good.replace(b'... ok', b'... FAILED', 1),
            good.replace(b'... ok', b'... ignored', 1), good.replace(b'running 16', b'running 0'),
            good.replace(b'0 ignored', b'1 ignored'), good + good,
            b'\n'.join(good.split(b'\n')[1:]),
            good.replace(('test ' + G.TESTS[0] + ' ... ok\n').encode(), b'')]
        for raw in variants:
            with self.subTest(raw=raw[:60]), self.assertRaises(ValueError):
                G.verify_tests(raw)

    def test_synthetic_complete_trial_retains_two_separate_proof_scopes(self):
        with T.source_fixture(committed=True, local_policy=True) as (root, work, _, packages):
            prepare(root, work, packages)
            base = G.P.read(work / 'evidence/report.json', G.P.MAX_LOCK)
            with patch.object(G.P, 'run', side_effect=fake_run):
                G.execute(work)
            G.receipt(work)
            result = json.loads((work / 'guest-evidence/report.json').read_text())
            self.assertIs(result['passed'], True)
            self.assertEqual(result['scope'], G.SCOPE)
            self.assertEqual(result['prerequisite'], G.P.digest(base))
            self.assertEqual(set(result['files']), {'tests.log', 'tests.json'})
            self.assertEqual(G.P.read(work / 'evidence/report.json', G.P.MAX_LOCK), base)

    def test_forged_prerequisite_never_starts_cargo(self):
        with T.source_fixture(committed=True, local_policy=True) as (root, work, _, packages):
            prepare(root, work, packages)
            path = work / 'evidence/report.json'
            value = json.loads(path.read_text()); value['scope']['hardware_attestation'] = True
            path.write_text(json.dumps(value))
            with patch.object(G.P, 'run') as run, self.assertRaises(ValueError):
                G.execute(work)
            run.assert_not_called()

    def test_failure_keeps_original_log_and_cannot_produce_success(self):
        with T.source_fixture(committed=True, local_policy=True) as (root, work, _, packages):
            prepare(root, work, packages)
            def failed(argv, output, seconds):
                fake_run(argv, output, seconds)
                return T.tool_outcome(1)
            with patch.object(G.P, 'run', side_effect=failed), self.assertRaises(ValueError):
                G.execute(work)
            with self.assertRaisesRegex(ValueError, 'guest_software_trial_incomplete'):
                G.receipt(work)
            self.assertEqual((work / 'guest-evidence/tests.log').read_bytes(), log())
            self.assertIs(json.loads((work / 'guest-evidence/report.json').read_text())['passed'], False)

    def test_stage_scope_source_hash_command_and_names_cannot_be_relabelled(self):
        with T.source_fixture(committed=True, local_policy=True) as (root, work, _, packages):
            prepare(root, work, packages)
            with patch.object(G.P, 'run', side_effect=fake_run): G.execute(work)
            path = work / 'guest-evidence/tests.json'; original = json.loads(path.read_text())
            for field in ('scope', 'source', 'log', 'prerequisite', 'argv', 'command', 'tests', 'passed', 'extra'):
                changed = copy.deepcopy(original)
                if field == 'scope': changed[field]['hardware_attestation'] = True
                elif field == 'source': changed[field]['commit'] = '0' * 40
                elif field in ('log', 'prerequisite'): changed[field]['sha256'] = '0' * 64
                elif field == 'argv': changed[field].append('--ignored')
                elif field == 'command': changed[field]['leader_joined'] = False
                elif field == 'tests': changed[field]['names'].pop()
                elif field == 'passed': changed[field] = False
                else: changed[field] = True
                path.write_text(json.dumps(changed))
                with self.subTest(field=field), self.assertRaises(ValueError): G.verify_evidence(work)
            path.write_text(json.dumps(original))
            G.verify_evidence(work)

    def test_changed_original_log_is_not_covered_by_pass_flags(self):
        with T.source_fixture(committed=True, local_policy=True) as (root, work, _, packages):
            prepare(root, work, packages)
            with patch.object(G.P, 'run', side_effect=fake_run): G.execute(work)
            (work / 'guest-evidence/tests.log').write_bytes(log() + b'changed\n')
            with self.assertRaises(ValueError): G.verify_evidence(work)

    def test_new_bindings_reject_bool_int_float_aliases(self):
        with T.source_fixture(committed=True, local_policy=True) as (root, work, _, packages):
            prepare(root, work, packages)
            base_path = work / 'evidence/report.json'
            base_raw = base_path.read_bytes()
            base = json.loads(base_raw)
            with patch.object(G.P, 'run', side_effect=fake_run): G.execute(work)
            stage_path = work / 'guest-evidence/tests.json'
            stage_raw = stage_path.read_bytes()
            stage = json.loads(stage_raw)
            variants = (
                (stage_path, stage, ('schema_version',), True),
                (stage_path, stage, ('schema_version',), 1.0),
                (stage_path, stage, ('passed',), 1),
                (stage_path, stage, ('scope', 'hardware_attestation'), 0),
                (stage_path, stage, ('scope', 'software_lifecycle_tests'), 1.0),
                (stage_path, stage, ('tests', 'passed'), 16.0),
                (stage_path, stage, ('tests', 'failed'), False),
                (stage_path, stage, ('log', 'bytes'), float(stage['log']['bytes'])),
                (stage_path, stage, ('prerequisite', 'bytes'), float(stage['prerequisite']['bytes'])),
                (base_path, base, ('schema_version',), 6.0),
                (base_path, base, ('passed',), 1),
                (base_path, base, ('scope', 'hardware_attestation'), 0.0),
                (base_path, base, ('stages', 'tests.json'), 1),
                (base_path, base, ('files', 'tests.log', 'bytes'), float(base['files']['tests.log']['bytes'])),
            )
            for path, original, keys, alias in variants:
                changed = copy.deepcopy(original)
                field = changed
                for key in keys[:-1]: field = field[key]
                self.assertEqual(field[keys[-1]], alias)  # The old Python equality accepted this.
                field[keys[-1]] = alias
                path.write_text(json.dumps(changed))
                reason = 'guest_prerequisite_report' if path == base_path else 'guest_stage_binding'
                with self.subTest(path=path.name, keys=keys, alias=alias), self.assertRaisesRegex(ValueError, reason):
                    G.verify_evidence(work)
                path.write_bytes(base_raw if path == base_path else stage_raw)
            G.verify_evidence(work)

    def test_export_directory_cannot_be_symlink_or_public(self):
        with tempfile.TemporaryDirectory() as tmp:
            work = Path(tmp); other = work / 'other'; other.mkdir(mode=0o700)
            path = work / 'guest-evidence'; path.symlink_to(other, target_is_directory=True)
            with self.assertRaises(ValueError): G.directory(work)
            path.unlink(); path.mkdir(mode=0o700)
            path.chmod(0o755)  # Explicit unsafe fixture, independent of caller umask.
            with self.assertRaises(ValueError): G.directory(work)

    def test_guest_cli_uses_original_hosted_gate_and_fixed_commands(self):
        for phase, branch in ((phase, branch) for phase in ('test', 'receipt')
                for branch in ('feature/protected-compute-guest', 'feature/protected-compute-quote-exchange')):
            with patch.object(G.P, 'hosted') as gate, patch.object(G.P, 'install_signals'), \
                    patch.object(G.P, 'workdir', return_value=Path('/inert')), patch.object(G.P, 'cargo_env'), \
                    patch.dict(os.environ, GITHUB_REF='refs/heads/' + branch), \
                    patch.object(G, 'execute' if phase == 'test' else 'receipt') as action:
                G.main([phase]); gate.assert_called_once(); action.assert_called_once_with(Path('/inert'))
        for args in ([], ['compile'], ['test', 'extra']):
            with patch.object(G.P, 'hosted') as gate, self.assertRaises(ValueError): G.main(args)
            gate.assert_not_called()
        for branch in ('main', 'feature/protected-compute-quote-exchange-other'):
            with patch.object(G.P, 'hosted'), patch.dict(os.environ, GITHUB_REF='refs/heads/' + branch), \
                    self.assertRaisesRegex(ValueError, 'guest_branch_only'):
                G.main(['test'])

    def test_workflow_keeps_guest_exports_and_historical_exports_separate(self):
        raw = (G.P.ROOT / '.github/workflows/protected-compute-admission.yml').read_text()
        expected = re.findall(r'\$\{\{ runner.temp \}\}/volparossa-protected-compute-admission/guest-evidence/(\S+)', raw)
        self.assertEqual(tuple(expected), G.EXPORTS)
        branches = "(github.ref == 'refs/heads/feature/protected-compute-guest' || github.ref == 'refs/heads/feature/protected-compute-quote-exchange')"
        self.assertIn('if: success() && ' + branches, raw)
        self.assertIn('if: always() && ' + branches, raw)
        self.assertIn('protected-compute-guest.py test', raw)
        self.assertIn('protected-compute-guest.py receipt', raw)
        self.assertIn('protected-compute-guest-software-${{ github.sha }}', raw)
        self.assertEqual(G.ARGV, ['cargo', 'test', '--locked', '--offline', '-p',
            'volparossa-content', '--lib', G.PREFIX, '--', '--test-threads=1'])


if __name__ == '__main__':
    unittest.main()
