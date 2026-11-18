#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-only
"""Inert verifier-contract tests: no Rust, SDK, hardware or network execution."""
import copy
from contextlib import contextmanager
import importlib.util
import io
import json
import os
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest.mock import patch

SOURCE = Path(__file__).with_name('protected-compute-verifier.py')
SPEC = importlib.util.spec_from_file_location('fixture_verifier', SOURCE)
V = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(V)
WORKFLOW = V.ROOT / '.github/workflows/protected-compute-verifier.yml'


def git(source, *args):
    return subprocess.check_output(['git', '-c', 'core.hooksPath=/dev/null', '-c', 'commit.gpgsign=false',
        '-c', 'user.name=Inert fixture', '-c', 'user.email=fixture@example.invalid',
        '-C', str(source), *args], timeout=10).decode().strip()


@contextmanager
def source_fixture():
    """Real Git operations on tiny synthetic text, not upstream/native execution."""
    selected = copy.deepcopy(V.pins())
    with tempfile.TemporaryDirectory() as tmp:
        source = Path(tmp)
        old = b'[[package]]\nname = "num-bigint-dig"\nversion = "0.8.6"\ndependencies = [\n "rand 0.8.5",\n]\n'
        new = old.replace(b' "rand 0.8.5",\n', b' "rand 0.8.8",\n')
        for name in selected['files']:
            path = source / name
            path.parent.mkdir(parents=True, exist_ok=True)
            raw = old if name == 'Cargo.lock' else ('synthetic ' + name + '\n').encode()
            if name == 'LICENSE':
                raw = (V.ROOT / 'third_party/licenses/virtee-sev-8.0.0-Apache-2.0.txt').read_bytes()
            path.write_bytes(raw)
            selected['files'][name] = dict(bytes=len(raw), sha256=V.sha(raw))
        (source / 'other.rs').write_text('synthetic tracked source\n')
        (source / '.gitignore').write_text('ignored-output\n')
        git(source, 'init', '-q')
        git(source, 'add', '--all')
        git(source, 'commit', '-qm', 'inert fixture')
        selected['upstream']['commit'] = git(source, 'rev-parse', 'HEAD')
        selected['upstream']['tree'] = git(source, 'rev-parse', 'HEAD^{tree}')
        selected['lock_correction']['upstream'] = selected['files']['Cargo.lock']
        selected['lock_correction']['effective'] = dict(bytes=len(new), sha256=V.sha(new))
        # Only authority input is substituted. The actual source/HEAD/index/file
        # validators and exact correction run normally against the text fixture.
        with patch.object(V, 'pins', return_value=selected):
            yield source, selected, old, new


def log():
    return ('running 4 tests\n' + ''.join('test ' + name + ' ... ok\n' for name in V.EXPECTED_TESTS)
        + '\ntest result: ok. 4 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.12s\n').encode()


class FixtureContracts(unittest.TestCase):
    def test_original_pinset(self):
        selected = V.pins()
        self.assertEqual(set(selected['files']), V.EXPECTED_FILES)
        license_path = V.ROOT / 'third_party/licenses/virtee-sev-8.0.0-Apache-2.0.txt'
        raw = V.bounded(license_path, 32768)
        self.assertEqual({'bytes': len(raw), 'sha256': V.sha(raw)}, selected['files']['LICENSE'])

    def test_changed_pin_contract_is_rejected(self):
        original = V.pins()
        mutations = []
        for key, value in [('schema_version', True), ('default_features', True),
                ('features', ['sev']), ('test_filter', 'nonexistent'), ('expected_tests', []),
                ('scope', {'private_task_release': True}), ('unknown', 'ignored')]:
            mutated = copy.deepcopy(original)
            mutated[key] = value
            mutations.append(mutated)
        for key in ('commit', 'tree', 'url', 'repository'):
            mutated = copy.deepcopy(original)
            mutated['upstream'][key] = 'wrong'
            mutations.append(mutated)
        for operation in ('missing', 'extra', 'escape', 'malformed'):
            mutated = copy.deepcopy(original)
            if operation == 'missing':
                del mutated['files']['LICENSE']
            elif operation == 'extra':
                mutated['files']['extra'] = mutated['files']['LICENSE']
            elif operation == 'escape':
                mutated['files']['../LICENSE'] = mutated['files'].pop('LICENSE')
            else:
                mutated['files']['LICENSE']['bytes'] = True
            mutations.append(mutated)
        for change in ('missing', 'extra', 'old', 'new', 'effective', 'upstream', 'count', 'old_schema'):
            mutated = copy.deepcopy(original)
            if change == 'missing':
                del mutated['lock_correction']
            elif change == 'extra':
                mutated['lock_correction']['arbitrary_patch'] = True
            elif change in ('old', 'new'):
                mutated['lock_correction'][change + '_dependency'] = 'rand 0.9.0'
            elif change in ('effective', 'upstream'):
                mutated['lock_correction'][change]['sha256'] = 'f' * 64
            elif change == 'count':
                mutated['lock_correction']['occurrences'] = True
            else:
                mutated['schema_version'] = 1
                del mutated['lock_correction']
            mutations.append(mutated)
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / 'pins.json'
            with patch.object(V, 'PINS', path):
                for mutated in mutations:
                    with self.subTest(mutation=mutated):
                        path.write_text(json.dumps(mutated), encoding='utf-8')
                        with self.assertRaises(ValueError):
                            V.pins()

    def test_exact_success_requires_four_executed_tests(self):
        self.assertEqual(V.verify_results(log(), 0)['passed'], 4)

    def test_exit_failure_cannot_become_success(self):
        for status in (1, 101, 124, 137, False):
            with self.subTest(status=status), self.assertRaisesRegex(ValueError, 'cargo_failed'):
                V.verify_results(log(), status)

    def test_missing_duplicate_extra_ignored_or_failed_test(self):
        first = b'test snp::milan_chain ... ok\n'
        for raw in (log().replace(first, b''), log() + first,
                log().replace(first, b'test snp::milan_chain ... ignored\n'),
                log().replace(first, b'test snp::milan_chain ... FAILED\n'),
                log() + b'test unrelated::other ... ok\n',
                log().replace(b'running 4 tests', b'running 0 tests'),
                log().replace(b'4 passed', b'0 passed'), log() + log(),
                b'build succeeded\n', b'\xff', b'x' * (V.MAX_LOG + 1)):
            with self.subTest(raw_prefix=raw[:100]), self.assertRaises((ValueError, UnicodeError)):
                V.verify_results(raw, 0)

    def test_toolchain_receipts_are_version_exact(self):
        rustc = b'rustc 1.85.0 (test fixture)\nrelease: 1.85.0\n'
        cargo = b'cargo 1.85.0 (test fixture)\nrelease: 1.85.0\n'
        self.assertEqual(V.toolchain(rustc, cargo)['rust'], '1.85.0')
        for wrong in (cargo.replace(b'1.85.0', b'1.85.1'), b'cargo 1.85.0\n', b'x' * 32769):
            with self.assertRaises(ValueError):
                V.toolchain(rustc, wrong)

    def test_capture_is_bounded_and_exclusive(self):
        with tempfile.TemporaryDirectory() as tmp, patch.object(V, 'MAX_LOG', 16):
            path = Path(tmp) / 'log'
            V.capture(io.BytesIO(b'x' * 16), path)
            self.assertEqual(path.read_bytes(), b'x' * 16)
            with self.assertRaises(FileExistsError):
                V.capture(io.BytesIO(b'overwrite'), path)
            overflow = Path(tmp) / 'overflow'
            with self.assertRaisesRegex(ValueError, 'test_log_bound'):
                V.capture(io.BytesIO(b'y' * 17), overflow)
            self.assertEqual(overflow.read_bytes(), b'y' * 16)

    def test_bounded_rejects_symlink_and_oversize(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / 'input'
            path.write_bytes(b'1234')
            link = Path(tmp) / 'link'
            link.symlink_to(path)
            with self.assertRaises(ValueError):
                V.bounded(path, 3)
            with self.assertRaises(ValueError):
                V.bounded(link, 4)

    def test_no_local_native_entrypoint(self):
        with patch.dict(os.environ, {}, clear=True):
            with self.assertRaisesRegex(ValueError, 'explicit_disposable_hosted_only'):
                V.main(['source', '/does-not-exist'])

    def test_source_mismatch_precedes_reading_fixtures(self):
        selected = V.pins()
        for observed in (['wrong'], [selected['upstream']['commit'], 'wrong']):
            with tempfile.TemporaryDirectory() as tmp, patch.object(V, 'command', side_effect=observed):
                with self.assertRaisesRegex(ValueError, 'source_(commit|tree|changed)'):
                    V.verify_source(Path(tmp))

    def test_prepare_requires_pristine_then_only_exact_effective_lock(self):
        with source_fixture() as (source, selected, old, new), patch.object(V, 'hosted'):
            V.main(['source', str(source)])
            with self.assertRaisesRegex(ValueError, 'source_changed'):
                V.main(['source-effective', str(source)])
            V.main(['prepare', str(source)])
            self.assertEqual((source / 'Cargo.lock').read_bytes(), new)
            self.assertEqual(V.command_bytes(source, 'show', 'HEAD:Cargo.lock'), old)
            V.main(['source-effective', str(source)])
            self.assertFalse((source / 'report.json').exists())
            for command in ('source', 'prepare'):
                with self.assertRaisesRegex(ValueError, 'source_changed'):
                    V.main([command, str(source)])
            self.assertEqual((source / 'Cargo.lock').read_bytes(), new)

    def test_pre_and_post_patch_reject_other_source_untracked_ignored_or_index_changes(self):
        for effective in (False, True):
            for change in ('tracked', 'untracked', 'ignored', 'staged', 'mode', 'hidden'):
                with self.subTest(effective=effective, change=change), source_fixture() as (source, _, _, _):
                    if effective:
                        V.prepare_source(source)
                    path = source / 'other.rs'
                    if change in ('tracked', 'staged', 'hidden'):
                        path.write_text('changed\n')
                        if change == 'staged':
                            git(source, 'add', '--', 'other.rs')
                        elif change == 'hidden':
                            git(source, 'update-index', '--assume-unchanged', 'other.rs')
                    elif change == 'mode':
                        path.chmod(0o755)
                    else:
                        (source / ('ignored-output' if change == 'ignored' else 'extra')).write_text('extra\n')
                    with self.assertRaisesRegex(ValueError, 'source_(changed|index_flags)'):
                        V.verify_source(source, effective=effective)

    def test_effective_lock_rejects_staging_mode_altered_and_extra_patch(self):
        for change in ('staged', 'mode', 'altered', 'extra', 'reverted'):
            with self.subTest(change=change), source_fixture() as (source, _, old, new):
                V.prepare_source(source)
                path = source / 'Cargo.lock'
                if change == 'staged':
                    git(source, 'add', '--', 'Cargo.lock')
                elif change == 'mode':
                    path.chmod(0o755)
                else:
                    path.write_bytes(new.replace(b'0.8.8', b'0.8.9') if change == 'altered'
                        else new + b'\n' if change == 'extra' else old)
                with self.assertRaises(ValueError):
                    V.verify_source(source, effective=True)

    def test_head_lock_must_match_original_even_if_worktree_matches_effective_pin(self):
        with source_fixture() as (source, selected, old, new):
            (source / 'Cargo.lock').write_bytes(old + b'\n')
            git(source, 'add', '--', 'Cargo.lock')
            git(source, 'commit', '-qm', 'wrong original lock fixture')
            selected['upstream']['commit'] = git(source, 'rev-parse', 'HEAD')
            selected['upstream']['tree'] = git(source, 'rev-parse', 'HEAD^{tree}')
            (source / 'Cargo.lock').write_bytes(new)
            with self.assertRaisesRegex(ValueError, 'lock_digest'):
                V.verify_source(source, effective=True)

    def test_wrong_original_or_wrong_effective_pin_cannot_be_prepared(self):
        with source_fixture() as (source, selected, old, _):
            for raw in (old + b'\n', old.replace(b'0.8.5', b'0.8.9')):
                with self.assertRaisesRegex(ValueError, 'lock_digest'):
                    V.corrected_lock(raw, selected)
            selected['lock_correction']['effective']['sha256'] = 'f' * 64
            with self.assertRaisesRegex(ValueError, 'lock_digest'):
                V.prepare_source(source)
            self.assertEqual((source / 'Cargo.lock').read_bytes(), old)

    def test_receipt_preserves_scope_and_cannot_overwrite(self):
        with tempfile.TemporaryDirectory() as tmp, patch.object(V, 'hosted'), \
                patch.object(V, 'verify_source', return_value=V.pins()), \
                patch.dict(os.environ, {'GITHUB_SHA': 'a' * 40}):
            output = Path(tmp)
            (output / 'tests.log').write_bytes(log())
            for name in ('rustc', 'cargo'):
                (output / (name + '.txt')).write_text(name + ' 1.85.0 (fixture)\nrelease: 1.85.0\n')
            V.main(['receipt', 'inert-source', tmp, '0', '0'])
            result = json.loads((output / 'report.json').read_bytes())
            self.assertEqual(result['schema_version'], 2)
            self.assertEqual(result['source_state'], 'upstream-with-pinned-lock-correction')
            self.assertEqual(result['cargo_lock'], V.LOCK_CORRECTION)
            self.assertNotEqual(result['cargo_lock']['upstream'], result['cargo_lock']['effective'])
            self.assertNotIn('cargo_lock_sha256', result)  # Old ambiguous schema-one field.
            self.assertEqual(result['scope'], V.SCOPE)
            self.assertIs(result['scope']['private_task_release'], False)
            self.assertIs(result['scope']['protected_execution_proven'], False)
            self.assertEqual(result['evidence']['log_sha256'], V.sha(log()))
            with self.assertRaises(FileExistsError):
                V.main(['receipt', 'inert-source', tmp, '0', '0'])
            old = dict(schema_version=1, kind='protected-compute-upstream-fixture-result',
                cargo_lock_sha256=V.LOCK_CORRECTION['upstream']['sha256'], tests=result['tests'])
            legacy = json.dumps(old).encode()
            (output / 'report.json').write_bytes(legacy)
            with self.assertRaises(FileExistsError):
                V.main(['receipt', 'inert-source', tmp, '0', '0'])
            self.assertEqual((output / 'report.json').read_bytes(), legacy)

    def test_unpatched_source_or_preparation_output_cannot_authorize_result(self):
        with source_fixture() as (source, _, _, _), patch.object(V, 'hosted'):
            with tempfile.TemporaryDirectory() as tmp:
                output = Path(tmp)
                (output / 'tests.log').write_bytes(log())
                with self.assertRaisesRegex(ValueError, 'source_changed'):
                    V.main(['receipt', str(source), tmp, '0', '0'])
                V.prepare_source(source)
                (output / 'tests.log').write_bytes(b'source verified and lock prepared\n')
                with self.assertRaisesRegex(ValueError, 'exact_fixture_tests'):
                    V.main(['receipt', str(source), tmp, '0', '0'])
                self.assertFalse((output / 'report.json').exists())

    def test_failed_capture_never_writes_receipt(self):
        with tempfile.TemporaryDirectory() as tmp, patch.object(V, 'hosted'):
            with self.assertRaisesRegex(ValueError, 'capture_failed'):
                V.main(['receipt', 'inert-source', tmp, '0', '1'])
            self.assertFalse((Path(tmp) / 'report.json').exists())

    def test_workflow_keeps_failed_pipeline_exit_evidence(self):
        text = WORKFLOW.read_text()
        step = text.split('      - name: Execute only four public cryptographic fixtures\n', 1)[1]
        step = step.split('      - name:', 1)[0].split('        run: |\n', 1)[1]
        script = '\n'.join(line[10:] for line in step.splitlines())
        # Execute the real workflow shell with inert producer/collector functions.
        # bash -e matches the runner and catches accidentally inherited errexit.
        prefix = '''
timeout() { printf 'inert compiler output\\n'; return "$TEST_CARGO_EXIT"; }
python3() {
  if [[ "$3" == capture ]]; then
    cat >/dev/null
    return "$TEST_CAPTURE_EXIT"
  elif [[ "$3" == receipt ]]; then
    test "$6" = "$TEST_CARGO_EXIT" && test "$7" = "$TEST_CAPTURE_EXIT" || return 98
    test "$6" = 0 && test "$7" = 0
  elif [[ "$3" == source-effective ]]; then
    return 0
  else
    return 99
  fi
}
'''
        for cargo_exit, capture_exit in ((0, 0), (101, 0), (124, 0), (0, 1), (141, 1)):
            with self.subTest(cargo=cargo_exit, capture=capture_exit), tempfile.TemporaryDirectory() as tmp:
                evidence = Path(tmp) / 'build/protected-compute-verifier/evidence'
                evidence.mkdir(parents=True)
                run = subprocess.run(['bash', '--noprofile', '--norc', '-e', '-o', 'pipefail',
                    '-c', prefix + script], cwd=tmp, capture_output=True, timeout=10,
                    env={**os.environ, 'TEST_CARGO_EXIT': str(cargo_exit), 'TEST_CAPTURE_EXIT': str(capture_exit),
                        'VERIFIER_SOURCE': str(Path(tmp) / 'inert-source')})
                self.assertEqual((evidence / 'cargo-exit.txt').read_text().strip(), str(cargo_exit))
                self.assertEqual((evidence / 'capture-exit.txt').read_text().strip(), str(capture_exit))
                self.assertEqual(run.returncode == 0, cargo_exit == capture_exit == 0)

    def test_upstream_is_outside_parent_cargo_workspace(self):
        text = WORKFLOW.read_text()
        binding = '          VERIFIER_SOURCE: ${{ runner.temp }}/volparossa-protected-compute-verifier-source\n'
        names = ('Fetch exact upstream source and verify public fixtures',
            'Fetch locked upstream dependencies without running tests',
            'Execute only four public cryptographic fixtures')

        def assert_step_bindings(value):
            before_steps, steps = value.split('    steps:\n', 1)
            # runner is unavailable in job-level env, even when the YAML parses.
            self.assertNotIn('runner.temp', before_steps)
            self.assertNotIn('VERIFIER_SOURCE', before_steps)
            self.assertEqual(value.count(binding), 3)
            for name in names:
                step = steps.split('      - name: ' + name + '\n', 1)[1].split('      - name:', 1)[0]
                header = step.split('        run: |\n', 1)[0]
                self.assertIn('        env:\n', header)
                self.assertIn(binding, header)

        assert_step_bindings(text)
        old_job_binding = text.replace(binding, '').replace('    steps:\n',
            '    env:\n' + binding[4:] + '    steps:\n', 1)
        for invalid in (old_job_binding, text.replace(binding, '', 1)):
            with self.assertRaises(AssertionError):
                assert_step_bindings(invalid)
        self.assertIn('test ! -e "$VERIFIER_SOURCE"', text)
        self.assertEqual(text.count('--manifest-path "$VERIFIER_SOURCE/Cargo.toml"'), 2)
        self.assertNotIn('build/protected-compute-verifier/source', text)
        self.assertNotIn('workspace.exclude', text)

    def test_workflow_applies_fixed_correction_before_unchanged_locked_commands(self):
        text = WORKFLOW.read_text()
        prefix = 'python3 -B tests/integration/protected-compute-verifier.py '
        pristine = text.index(prefix + 'source "$VERIFIER_SOURCE"')
        prepare = text.index(prefix + 'prepare "$VERIFIER_SOURCE"')
        fetch = text.index('cargo +1.85.0 fetch --locked')
        test = text.index('cargo +1.85.0 test --locked --offline')
        self.assertLess(pristine, prepare)
        self.assertLess(prepare, fetch)
        self.assertEqual(text.count(prefix + 'prepare "$VERIFIER_SOURCE"'), 1)
        self.assertIn(prefix + 'source-effective "$VERIFIER_SOURCE"', text[prepare:fetch])
        self.assertEqual(text[fetch:test].count(prefix + 'source-effective "$VERIFIER_SOURCE"'), 2)
        self.assertNotIn('cargo update', text)
        self.assertNotIn('generate-lockfile', text)

    def test_workflow_is_source_pinned_public_and_bounded(self):
        text = WORKFLOW.read_text()
        for required in ('contents: read', 'runs-on: ubuntu-24.04', 'timeout-minutes: 25',
                'persist-credentials: false', 'CARGO_BUILD_JOBS: \'2\'',
                'cargo +1.85.0 test --locked --offline', '--no-default-features --features snp,crypto_nossl',
                "--test certs 'snp::'", '-- --test-threads=1', 'timeout --kill-after=15s 900s',
                V.pins()['upstream']['commit'], 'cancel-in-progress: false'):
            self.assertIn(required, text)
        for forbidden in ('sudo ', '/dev/sev', 'private-task', 'self-hosted', 'continue-on-error: true'):
            self.assertNotIn(forbidden, text)
        paths = text.split('          path: |\n', 1)[1].splitlines()
        self.assertEqual(len(paths), 6)
        self.assertTrue(all(line.strip().startswith('build/protected-compute-verifier/evidence/') for line in paths))


if __name__ == '__main__':
    unittest.main()
