#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-only
"""Inert quote evidence contracts: synthetic logs, never Cargo or guest firmware."""
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
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


Q = load('quote_probe', HERE / 'protected-compute-quote.py')
A = load('quote_admission_contracts', HERE / 'test-protected-compute-admission.py')
A.P = Q.P


def log(names):
    count = len(names)
    return (f'running {count} tests\n' + ''.join('test ' + name + ' ... ok\n' for name in names)
        + f'test result: ok. {count} passed; 0 failed; 0 ignored; 0 measured; 500 filtered out; finished in 0.1s\n').encode()


def fake_run(argv, output, seconds):
    assert argv in (Q.ARGV, Q.G.ARGV) and seconds == 300
    names = Q.TESTS if argv == Q.ARGV else Q.G.TESTS
    Q.P.write(output, log(names))
    return A.tool_outcome()


def prepare(root, work, packages):
    A.public_trial_fixture(root, work, packages, historical=False, local_policy=True)
    Q.P.receipt(work, local_policy=True)
    with patch.object(Q.P, 'run', side_effect=fake_run):
        Q.G.execute(work)
    Q.G.receipt(work)


class QuoteEvidenceContracts(unittest.TestCase):
    def test_exact_names_match_actual_rust_test_source(self):
        raw = (Q.P.ROOT / 'crates/volparossa-content/src/provider/compute/quote/tests.rs').read_text()
        names = re.findall(r'#\[(?:tokio::)?test(?:\([^\n]*\))?\]\s+(?:async\s+)?fn (\w+)\(', raw)
        self.assertEqual(len(names), 12)
        self.assertEqual({Q.PREFIX + name for name in names}, set(Q.TESTS))

    def test_software_success_never_claims_hardware_route_or_private_task(self):
        self.assertEqual(Q.verify_tests(log(Q.TESTS))['passed'], 12)
        for name in ('successful_firmware_quote', 'hardware_attestation', 'full_appraisal',
                'production_route_execution', 'worker_admission', 'private_input_release', 'protected_execution'):
            self.assertIs(Q.SCOPE[name], False)

    def test_missing_duplicate_unknown_failed_ignored_or_empty_execution_rejects(self):
        good = log(Q.TESTS)
        for raw in (b'', good + good, log(Q.TESTS[:-1]),
                good.replace(Q.TESTS[0].encode(), Q.TESTS[1].encode()),
                good.replace(Q.TESTS[0].encode(), b'unknown'),
                good.replace(b'... ok', b'... FAILED', 1),
                good.replace(b'... ok', b'... ignored', 1),
                good.replace(b'running 12', b'running 0'),
                good.replace(b'0 ignored', b'1 ignored'),
                b'\n'.join(good.split(b'\n')[1:])):
            with self.subTest(raw=raw[:60]), self.assertRaises(ValueError):
                Q.verify_tests(raw)

    def test_synthetic_success_preserves_both_prerequisite_receipts(self):
        with A.source_fixture(committed=True, local_policy=True) as (root, work, _, packages):
            prepare(root, work, packages)
            previous = {name: (work / name).read_bytes() for name in ('evidence/report.json', 'guest-evidence/report.json')}
            with patch.object(Q.P, 'run', side_effect=fake_run):
                Q.execute(work)
            Q.receipt(work)
            result = json.loads((work / 'quote-evidence/report.json').read_bytes())
            self.assertIs(result['passed'], True)
            self.assertEqual(result['scope'], Q.SCOPE)
            self.assertEqual(result['prerequisite'], Q.P.digest(previous['guest-evidence/report.json']))
            self.assertEqual(set(result['files']), {'tests.log', 'tests.json'})
            for name, original in previous.items():
                self.assertEqual((work / name).read_bytes(), original)

    def test_forged_guest_prerequisite_prevents_command_execution(self):
        with A.source_fixture(committed=True, local_policy=True) as (root, work, _, packages):
            prepare(root, work, packages)
            path = work / 'guest-evidence/report.json'
            original = json.loads(path.read_bytes())
            for value in (True, 0):
                changed = copy.deepcopy(original)
                changed['scope']['hardware_attestation'] = value
                path.write_text(json.dumps(changed))
                with patch.object(Q.P, 'run') as run, self.assertRaisesRegex(ValueError, 'quote_prerequisite_report'):
                    Q.execute(work)
                run.assert_not_called()

    def test_original_command_failure_and_missing_execution_cannot_pass(self):
        with A.source_fixture(committed=True, local_policy=True) as (root, work, _, packages):
            prepare(root, work, packages)
            with self.assertRaisesRegex(ValueError, 'quote_software_trial_incomplete'):
                Q.receipt(work)
            self.assertIs(json.loads((work / 'quote-evidence/report.json').read_bytes())['passed'], False)
            (work / 'quote-evidence/report.json').unlink()
            def failed(argv, output, seconds):
                fake_run(argv, output, seconds)
                return A.tool_outcome(1)
            with patch.object(Q.P, 'run', side_effect=failed), self.assertRaises(ValueError):
                Q.execute(work)
            with self.assertRaisesRegex(ValueError, 'quote_software_trial_incomplete'):
                Q.receipt(work)
            self.assertEqual((work / 'quote-evidence/tests.log').read_bytes(), log(Q.TESTS))
            self.assertIs(json.loads((work / 'quote-evidence/report.json').read_bytes())['passed'], False)

    def test_source_scope_hash_command_and_names_cannot_be_relabelled(self):
        with A.source_fixture(committed=True, local_policy=True) as (root, work, _, packages):
            prepare(root, work, packages)
            with patch.object(Q.P, 'run', side_effect=fake_run):
                Q.execute(work)
            path = work / 'quote-evidence/tests.json'
            original = json.loads(path.read_bytes())
            mutations = (
                (('schema_version',), True), (('schema_version',), 1.0),
                (('passed',), 1), (('scope', 'hardware_attestation'), 0),
                (('scope', 'production_route_execution'), True),
                (('source', 'commit'), '0' * 40),
                (('log', 'sha256'), '0' * 64), (('prerequisite', 'sha256'), '0' * 64),
                (('log', 'bytes'), float(original['log']['bytes'])),
                (('argv',), Q.ARGV + ['--ignored']),
                (('command', 'leader_joined'), False),
                (('tests', 'names'), list(Q.TESTS[:-1])),
                (('tests', 'passed'), 12.0), (('extra',), True),
            )
            for keys, value in mutations:
                changed = copy.deepcopy(original)
                target = changed
                for key in keys[:-1]:
                    target = target[key]
                target[keys[-1]] = value
                path.write_text(json.dumps(changed))
                with self.subTest(keys=keys), self.assertRaises(ValueError):
                    Q.verify_evidence(work)
            path.write_text(json.dumps(original))
            Q.verify_evidence(work)
            (work / 'quote-evidence/tests.log').write_bytes(log(Q.TESTS) + b'changed\n')
            with self.assertRaises(ValueError):
                Q.verify_evidence(work)

    def test_evidence_directory_cannot_be_public_or_symlink(self):
        with tempfile.TemporaryDirectory() as tmp:
            work = Path(tmp)
            other = work / 'other'; other.mkdir(mode=0o700)
            target = work / 'quote-evidence'; target.symlink_to(other, target_is_directory=True)
            with self.assertRaises(ValueError): Q.directory(work)
            target.unlink(); target.mkdir(mode=0o700); target.chmod(0o755)
            with self.assertRaises(ValueError): Q.directory(work)

    def test_command_receipt_requires_exact_types_shape_and_cleanup_scope(self):
        with A.source_fixture(committed=True, local_policy=True) as (root, work, _, packages):
            prepare(root, work, packages)
            with patch.object(Q.P, 'run', side_effect=fake_run):
                Q.execute(work)
            path = work / 'quote-evidence/tests.json'
            original = json.loads(path.read_bytes())
            command = original['command']
            changed_commands = [
                dict(command, exit_status=False),
                dict(command, exit_status=0.0),
                dict(command, exit_status=1),
                dict(command, elapsed_ms=-1),
                dict(command, elapsed_ms=False),
                dict(command, elapsed_ms=float(command['elapsed_ms'])),
                dict(command, cleanup_scope='invented-cleanup'),
                dict(command, cleanup_scope=None),
                dict(command, leader_joined=1),
                dict(command, capture_error='command_interrupted'),
                dict(command, extra=True),
                dict(exit_status=0, capture_error=None, leader_joined=True),
                None, [],
            ]
            changed_commands.extend({key: value for key, value in command.items() if key != field}
                for field in command)
            for changed in changed_commands:
                path.write_text(json.dumps(dict(original, command=changed)))
                with self.subTest(command=changed), self.assertRaisesRegex(ValueError, 'quote_command_receipt'):
                    Q.verify_evidence(work)
            path.write_text(json.dumps(original))
            Q.verify_evidence(work)

    def test_fixed_hosted_entrypoint_never_accepts_local_or_other_branch(self):
        for phase in ('test', 'receipt'):
            with patch.object(Q.P, 'hosted') as hosted, patch.object(Q.P, 'install_signals'), \
                    patch.object(Q.P, 'workdir', return_value=Path('/inert')), patch.object(Q.P, 'cargo_env'), \
                    patch.dict(os.environ, GITHUB_REF='refs/heads/feature/protected-compute-quote-exchange'), \
                    patch.object(Q, 'execute' if phase == 'test' else 'receipt') as action:
                Q.main([phase]); hosted.assert_called_once(); action.assert_called_once_with(Path('/inert'))
        for args in ([], ['compile'], ['test', 'extra']):
            with patch.object(Q.P, 'hosted') as hosted, self.assertRaises(ValueError): Q.main(args)
            hosted.assert_not_called()
        for branch in ('main', 'feature/protected-compute-guest', 'feature/protected-compute-quote-exchange-other'):
            with patch.object(Q.P, 'hosted'), patch.dict(os.environ, GITHUB_REF='refs/heads/' + branch), \
                    self.assertRaisesRegex(ValueError, 'quote_branch_only'):
                Q.main(['test'])

    def test_workflow_retains_separate_bounded_software_artifact(self):
        raw = (Q.P.ROOT / '.github/workflows/protected-compute-admission.yml').read_text()
        exports = re.findall(r'\$\{\{ runner.temp \}\}/volparossa-protected-compute-admission/quote-evidence/(\S+)', raw)
        self.assertEqual(tuple(exports), Q.EXPORTS)
        self.assertIn("if: success() && github.ref == 'refs/heads/feature/protected-compute-quote-exchange'", raw)
        self.assertIn("if: always() && github.ref == 'refs/heads/feature/protected-compute-quote-exchange'", raw)
        self.assertIn('protected-compute-quote.py test', raw)
        self.assertIn('protected-compute-quote.py receipt', raw)
        self.assertIn('protected-compute-quote-software-${{ github.sha }}', raw)
        self.assertLess(raw.index('protected-compute-guest.py receipt'), raw.index('protected-compute-quote.py test'))
        self.assertEqual(Q.ARGV, ['cargo', 'test', '--locked', '--offline', '-p',
            'volparossa-content', '--lib', Q.PREFIX, '--', '--test-threads=1'])


if __name__ == '__main__':
    unittest.main()
