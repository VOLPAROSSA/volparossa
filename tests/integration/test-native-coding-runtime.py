#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-only
"""Synthetic bundle contracts/wiring only: no download, compiler, runtime or model."""
import hashlib
import importlib.util
import io
import json
import os
from pathlib import Path
import subprocess
import tarfile
import tempfile
import unittest
from unittest.mock import patch

HERE = Path(__file__).resolve().parent
spec = importlib.util.spec_from_file_location('runtime_bundle', HERE / 'native-coding-runtime.py')
runtime = importlib.util.module_from_spec(spec)
spec.loader.exec_module(runtime)
REVISION = 'a' * 40


def sha(data):
    return hashlib.sha256(data).hexdigest()


class BundleTests(unittest.TestCase):
    def setUp(self):
        self.root = tempfile.TemporaryDirectory(prefix='volparossa-native-bundle-contract-')
        self.addCleanup(self.root.cleanup)
        self.path = Path(self.root.name) / 'synthetic.tar.gz'
        self.code = {'LICENSE': b'original synthetic license', 'src/fixture.cjs': b'synthetic fixture'}
        self.files = {f'code/{name}': value for name, value in self.code.items()}
        self.files.update({'runtime/runtime/codex-app-server': b'\x7fELF synthetic never executed',
            'runtime/BUILD_REPORT.json': b'{"synthetic":true}', 'runtime/TOOLCHAIN_REPORT.json': b'synthetic compiler',
            'runtime/prompt.md': b'complete synthetic prompt'})
        self.record = dict(version=1, kind='volparossa-native-coding-runtime-bundle', core_revision=REVISION,
            code_revision=runtime.CODE_REVISION, code_tree=runtime.CODE_TREE, codex_revision=runtime.CODEX_REVISION,
            codex_tree=runtime.CODEX_TREE, toolchain_report_sha256=sha(self.files['runtime/TOOLCHAIN_REPORT.json']),
            binary_sha256=sha(self.files['runtime/runtime/codex-app-server']),
            build_report_sha256=sha(self.files['runtime/BUILD_REPORT.json']), prompt_sha256=sha(self.files['runtime/prompt.md']),
            source_build=True, existing_binary_reused=False, bit_reproducibility_proven=False,
            app_server_executed=False, files={name: dict(bytes=len(data), sha256=sha(data),
                mode=0o555 if name == 'runtime/runtime/codex-app-server' else 0o444) for name, data in self.files.items()})
        for mocked in (patch.object(runtime, 'code_files', return_value={name: sha(data) for name, data in self.code.items()}),
                       patch.object(runtime, 'TOOLCHAIN_SHA', self.record['toolchain_report_sha256']),
                       patch.object(runtime, 'PROMPT_SHA', self.record['prompt_sha256'])):
            mocked.start()
            self.addCleanup(mocked.stop)

    def archive(self, *, extra=None, altered=None, wrong_mode=None):
        with tarfile.open(self.path, 'w:gz') as stream:
            values = dict(self.files)
            values[runtime.MANIFEST] = json.dumps(self.record).encode()
            if altered:
                values.update(altered)
            for name, data in values.items():
                member = tarfile.TarInfo(name)
                member.size = len(data)
                member.mode = 0o555 if name == 'runtime/runtime/codex-app-server' else 0o444
                if wrong_mode == name:
                    member.mode = 0o644
                stream.addfile(member, io.BytesIO(data))
            if extra:
                stream.addfile(extra, io.BytesIO(b'x' * extra.size))

    def test_complete_bundle_checks_all_bytes_and_modes(self):
        self.archive()
        self.assertEqual(runtime.verify(self.path, REVISION), self.record)
        with self.assertRaisesRegex(ValueError, 'authority'):
            runtime.verify(self.path, 'b' * 40)

    def test_tamper_and_writable_files_reject(self):
        for options in ({'altered': {'runtime/runtime/codex-app-server': b'wrong binary'}},
                        {'wrong_mode': 'code/src/fixture.cjs'}):
            self.archive(**options)
            with self.assertRaisesRegex(ValueError, 'bytes or mode'):
                runtime.verify(self.path, REVISION)

    def test_special_entries_duplicates_and_path_escape_reject(self):
        for name, kind in [('runtime/../../escape', tarfile.REGTYPE),
                           ('runtime/newlink', tarfile.SYMTYPE),
                           ('code/src/fixture.cjs', tarfile.REGTYPE)]:
            extra = tarfile.TarInfo(name)
            extra.type = kind
            extra.linkname = '/etc/passwd' if kind == tarfile.SYMTYPE else ''
            self.archive(extra=extra)
            with self.assertRaises(ValueError):
                runtime.verify(self.path, REVISION)

    def test_undeclared_file_and_binary_receipt_rebinding_reject(self):
        extra = tarfile.TarInfo('runtime/undeclared')
        self.archive(extra=extra)
        with self.assertRaisesRegex(ValueError, 'inventory'):
            runtime.verify(self.path, REVISION)
        self.record['binary_sha256'] = '0' * 64
        self.archive()
        with self.assertRaisesRegex(ValueError, 'binding'):
            runtime.verify(self.path, REVISION)

    def test_existing_binary_or_unproven_reproducibility_cannot_be_claimed(self):
        for key in ('existing_binary_reused', 'app_server_executed', 'bit_reproducibility_proven'):
            self.record[key] = True
            self.archive()
            with self.assertRaisesRegex(ValueError, 'authority'):
                runtime.verify(self.path, REVISION)
            self.record[key] = False


class WiringTests(unittest.TestCase):
    def test_ci_bwrap_policy_is_scoped_stacked_and_rejects_host_execution(self):
        policy = (HERE / 'native-coding-bwrap.apparmor').read_text()
        wrapper = (HERE / 'native-coding-apparmor.sh').read_text()
        self.assertIn('profile volparossa_ci_native_bwrap /usr/bin/bwrap', policy)
        self.assertIn('-> volparossa_ci_native_bwrap//&volparossa_ci_native_child,', policy)
        child = policy.split('profile volparossa_ci_native_child ', 1)[1]
        self.assertIn('audit deny capability,', child)
        self.assertIn('allow pix /** -> &volparossa_ci_native_child,', child)
        self.assertNotIn('flags=(unconfined)', policy)
        self.assertNotIn('include if exists <local/', policy)
        self.assertIn(hashlib.sha256(policy.encode()).hexdigest(), wrapper)
        self.assertIn('"$parser" --add --skip-cache', wrapper)
        self.assertIn('"$parser" --remove --skip-cache', wrapper)
        self.assertNotIn('--replace', wrapper)
        self.assertNotIn('sysctl -w', wrapper)
        self.assertIn('int(s["CapEff"], 16) == int(s["CapPrm"], 16) == 0', wrapper)
        self.assertIn('int(s["NoNewPrivs"]) == 1', wrapper)
        self.assertIn('for network in online offline', wrapper)
        self.assertIn('isolation=(--ro-bind "$resolver" "$resolver")', wrapper)
        self.assertIn('if test "$network" = offline; then isolation=(--unshare-net); fi', wrapper)
        self.assertIn('set(Path("/run").rglob("*")) == allowed', wrapper)
        self.assertIn('hashlib.sha256(resolver.read_bytes()).hexdigest() == sys.argv[5]', wrapper)
        self.assertNotIn('--ro-bind /run /run', wrapper)
        self.assertIn("trap 'cleanup' EXIT", wrapper)
        self.assertIn('setsid python3 -B', wrapper)
        self.assertIn('build_status=null', wrapper)
        self.assertIn('"$build_status" "$result"', wrapper)
        self.assertIn('if test "$cleanup_result" != 0; then result=1; fi', wrapper)
        subprocess.run(['bash', '-n', str(HERE / 'native-coding-apparmor.sh')], check=True)
        rejected = subprocess.run(['bash', str(HERE / 'native-coding-apparmor.sh'), REVISION],
                                  env={'PATH': '/usr/bin:/bin', 'GITHUB_ACTIONS': 'false'},
                                  capture_output=True, text=True)
        self.assertNotEqual(rejected.returncode, 0)
        self.assertEqual(rejected.stdout, '')

    def test_failure_diagnostic_reads_only_bounded_public_build_logs(self):
        with tempfile.TemporaryDirectory(prefix='volparossa-build-log-contract-') as temporary:
            root = Path(temporary)
            (root / 'fetch-1.log').write_text('x' * 10000 + '\nsynthetic fetch failure')
            (root / 'private.log').write_text('not a build step')
            (root / 'metadata-2.log').symlink_to(root / 'private.log')
            result = runtime.build_failure_diagnostic(root)
            self.assertFalse(result['model_executed'])
            self.assertFalse(result['private_input_loaded'])
            self.assertEqual(len(result['logs']), 1)
            log = result['logs'][0]
            self.assertEqual(log['name'], 'fetch-1.log')
            self.assertEqual(log['tail_bytes'], 8192)
            self.assertTrue(log['truncated'])
            self.assertTrue(log['text'].endswith('synthetic fetch failure'))
            self.assertNotIn('not a build step', json.dumps(result))

    def test_build_cannot_run_on_development_host(self):
        with patch.dict(os.environ, {'GITHUB_ACTIONS': 'false'}), patch.object(runtime, 'checkout') as checkout:
            with self.assertRaisesRegex(ValueError, 'CI runner'):
                runtime.build(REVISION)
            checkout.assert_not_called()

    def test_exact_code_pin_and_guest_runner_contract(self):
        files = runtime.code_files()
        self.assertEqual(len(files), 10)
        self.assertEqual(files['LICENSE'], runtime.CODE_LICENSE_SHA)
        runner = (HERE / 'run-alpha-topology-vm.sh').read_text()
        self.assertIn('agent-reasoning|agent-private-conversation|agent-native-coding) printf', runner)
        self.assertIn('[ "$scenario" != agent-native-coding ] || driver_time_bound=6000s', runner)
        self.assertIn('native-coding-runtime.py stage --yes', runner)
        self.assertIn('native_runtime_sha256=${6:-none}', runner)
        self.assertIn('"$PACKAGE_SHA256" "$scenario" "$NATIVE_RUNTIME_SHA256"', runner)
        self.assertIn('if scenario in ("agent-private-conversation", "agent-native-coding"):', runner)
        self.assertIn('f"{scenario}-smoke.json"', runner)
        preview = subprocess.run(['sh', str(HERE / 'run-alpha-topology-vm.sh'), '--preview',
                                  '--scenario', 'agent-native-coding'], check=True, capture_output=True, text=True)
        self.assertIn('source-built Codex', preview.stdout)
        self.assertIn('8192 MiB', preview.stdout)

    def test_workflow_is_explicit_source_build_and_closed_exports(self):
        workflow = (HERE.parents[1] / '.github/workflows/alpha-topology.yml').read_text()
        self.assertIn('- agent-native-coding', workflow)
        self.assertIn("inputs.scenario == 'agent-native-coding' && 240", workflow)
        self.assertIn('bash tests/integration/native-coding-apparmor.sh "$GITHUB_SHA"', workflow)
        self.assertIn('python3 apparmor bubblewrap', workflow)
        self.assertIn('coding_args=(--native-runtime "$VOLPAROSSA_NATIVE_RUNTIME")', workflow)
        self.assertIn('agent-native-coding.py report "$report" "$GITHUB_SHA"', workflow)
        upload = workflow.split('- name: Upload bounded native coding fixture evidence', 1)[1].split('- name:', 1)[0]
        self.assertIn('/agent-native-coding-smoke.json', upload)
        self.assertNotIn('native-runtime.tar.gz', upload)
        self.assertNotIn('/opt/', upload)
        self.assertNotIn('*', upload)


if __name__ == '__main__':
    unittest.main()
