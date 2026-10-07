# SPDX-License-Identifier: GPL-3.0-only
"""Tiny inert diagnostic fixtures; no converter, model, source fetch or host service."""
from contextlib import ExitStack, redirect_stderr, redirect_stdout
import hashlib
import io
import json
import os
from pathlib import Path
import signal
import subprocess
import sys
import tempfile
from types import SimpleNamespace
import unittest
from unittest import mock

import convert_llama_cpu as conversion


class ConversionDiagnosticTests(unittest.TestCase):
    def exercise_stage(self, rejected):
        with tempfile.TemporaryDirectory() as directory, ExitStack() as stack:
            base = Path(directory)
            model, build, source = (base / name for name in ('model', 'build', 'source'))
            for path in (model, build, source, build / 'licenses'):
                path.mkdir(mode=0o700)
            for path in (model / 'weights', model / 'LICENSE', build / conversion.native.LIBRARY):
                path.write_bytes(b'inert')
            pinned = [{'path': name, 'bytes': 5, 'sha256': hashlib.sha256(b'inert').hexdigest()}
                      for name in ('weights', 'LICENSE')]
            manifest = dict(version=1, source_commit=conversion.builder.SOURCE, kind=conversion.native.KIND,
                abi_version=1, quantization=False, provisionable=True, sanitizers=False,
                library=dict(path=conversion.native.LIBRARY, **conversion.builder.digest(build / conversion.native.LIBRARY)),
                dynamic_dependencies=['libc.so.6'],
                wrapper_sources={name: conversion.builder.digest(conversion.HERE / 'native-cpu' / name)
                                 for name in ('CMakeLists.txt', 'adapter.h', 'adapter.cpp')})
            (build / 'build.json').write_text(json.dumps(manifest))
            progress, visited = {}, []
            def boundary(stage, result=None):
                self.assertEqual(progress['stage'], stage)
                visited.append(stage)
                if stage == rejected:
                    raise ValueError('CANARY /private/model token')
                return result
            stack.enter_context(mock.patch.object(conversion.provision, 'execution_root',
                side_effect=lambda _args: boundary('guard', (base / 'output', 'inert'))))
            stack.enter_context(mock.patch.object(conversion.builder, 'verify_source',
                side_effect=lambda _path: boundary('source', 'inert-tree')))
            stack.enter_context(mock.patch.object(conversion.provision, 'load_pins', return_value={'files': pinned}))
            versions = {'torch': '2.14.0+cpu', 'transformers': '5.16.1', 'peft': '0.20.0', 'sentencepiece': '0.2.1'}
            stack.enter_context(mock.patch.object(conversion.importlib.metadata, 'version',
                side_effect=lambda name: boundary('runtime', versions[name])))
            original_digest = conversion.builder.digest
            def digest(path):
                if path.parent == model:
                    boundary('model')
                elif path == build / conversion.native.LIBRARY:
                    boundary('build')
                return original_digest(path)
            stack.enter_context(mock.patch.object(conversion.builder, 'digest', side_effect=digest))
            def weights(*_args):
                if progress['stage'] == 'recheck':
                    boundary('recheck')
            stack.enter_context(mock.patch.object(conversion.provision, 'verify_weight_set', side_effect=weights))
            stack.enter_context(mock.patch.object(conversion.shutil, 'disk_usage',
                side_effect=lambda _path: boundary('budget', SimpleNamespace(free=12 * 1024**3))))
            def converter(_command, _log, _environment, _timeout, observed):
                self.assertIs(observed, progress)
                boundary('convert')
                progress['child_exit_status'] = 0
                (base / 'output/model.gguf').write_bytes(b'inert')
            stack.enter_context(mock.patch.object(conversion, 'run_converter', side_effect=converter))
            tokenizer = SimpleNamespace(AutoTokenizer=SimpleNamespace(from_pretrained=
                lambda *_args, **_kwargs: boundary('tokenizer', object())))
            stack.enter_context(mock.patch.dict(sys.modules, {'gguf': SimpleNamespace(GGUFReader=lambda _path: object()),
                                                              'transformers': tokenizer}))
            stack.enter_context(mock.patch.object(conversion, 'verify_conversion',
                side_effect=lambda *_args: boundary('verify', {})))
            original_copy = conversion.shutil.copyfile
            def copyfile(src, dst):
                boundary('bundle')
                return original_copy(src, dst)
            stack.enter_context(mock.patch.object(conversion.shutil, 'copyfile', side_effect=copyfile))
            stack.enter_context(mock.patch.object(conversion.provision, 'native_converter_pins', return_value={'notices': []}))
            stack.enter_context(mock.patch.object(conversion.native, 'validate_manifest',
                side_effect=lambda *_args: boundary('manifest')))
            stack.enter_context(mock.patch.object(conversion, 'private_bundle_modes',
                side_effect=lambda _path: boundary('permissions')))
            args = SimpleNamespace(root=str(base / 'output'), source=source, build=build, model=model,
                                   budget_bytes=10 * 1024**3, timeout_seconds=30)
            try:
                conversion.execute(args, progress)
            except ValueError as error:
                self.assertEqual(str(error), 'CANARY /private/model token')
                return progress, conversion.failure_diagnostic(progress, error), visited
            self.fail('inert stage refusal must not become success')

    def test_actual_pipeline_records_each_failure_stage_without_model_execution(self):
        stages = ['guard', 'source', 'runtime', 'model', 'build', 'budget', 'convert',
                  'tokenizer', 'verify', 'recheck', 'bundle', 'manifest', 'permissions']
        original_path = list(sys.path)
        try:
            for stage in stages:
                with self.subTest(stage=stage):
                    progress, diagnostic, visited = self.exercise_stage(stage)
                    self.assertEqual(progress['stage'], stage)
                    self.assertEqual(visited[-1], stage)
                    self.assertEqual(diagnostic['stage'], stage)
                    self.assertEqual(diagnostic['failure'], 'contract')
                    self.assertNotIn('CANARY', json.dumps(diagnostic))
                    self.assertNotIn('/private', json.dumps(diagnostic))
        finally:
            sys.path[:] = original_path

    def test_child_nonzero_timeout_and_cancellation_retain_bounded_final_status(self):
        signals = (signal.SIGTERM, signal.SIGINT, signal.SIGHUP)
        before = {item: signal.getsignal(item) for item in signals}
        for failure in ('nonzero', 'timeout', 'cancelled'):
            with self.subTest(failure=failure), ExitStack() as stack:
                progress = {'stage': 'convert'}
                child = mock.Mock(pid=os.getpid())
                child.wait.return_value = child.poll.return_value = 7
                expected, status = 'child_failed', 7
                if failure == 'timeout':
                    stack.enter_context(mock.patch.object(conversion.time, 'monotonic', side_effect=[0, 2]))
                    child.poll.side_effect = [None, -15]
                    child.wait.return_value = -15
                    expected, status = 'timeout', -15
                elif failure == 'cancelled':
                    def cancel(**_kwargs):
                        signal.getsignal(signal.SIGTERM)(signal.SIGTERM, None)
                        return 0
                    child.wait.side_effect = cancel
                    child.poll.return_value = 0
                    expected, status = 'cancelled', 0
                stack.enter_context(mock.patch.object(conversion.subprocess, 'Popen', return_value=child))
                with self.assertRaises(Exception) as result:
                    conversion.run_converter(['inert'], io.BytesIO(), {}, 1, progress)
                diagnostic = conversion.failure_diagnostic(progress, result.exception)
                self.assertEqual((diagnostic['failure'], diagnostic['child_exit_status']), (expected, status))
                self.assertEqual({item: signal.getsignal(item) for item in signals}, before)

    def test_main_emits_one_closed_failure_and_keeps_legacy_marker(self):
        argv = ['convert', '--source', '/source', '--build', '/build', '--model', '/model',
                '--root', '/output', '--budget-bytes', '1', '--execute', '--yes', '--disposable-guest']
        def fail(_args, progress):
            progress.update(stage='verify', child_exit_status=0)
            raise ValueError('CANARY /private/model')
        out, err = io.StringIO(), io.StringIO()
        with mock.patch.object(sys, 'argv', argv), mock.patch.object(conversion, 'execute', side_effect=fail), \
                redirect_stdout(out), redirect_stderr(err), self.assertRaises(SystemExit) as stopped:
            conversion.main()
        self.assertEqual(stopped.exception.code, 1)
        self.assertEqual(out.getvalue(), '')
        lines = err.getvalue().splitlines()
        self.assertEqual(len(lines), 2)
        self.assertEqual(lines[1], 'NATIVE_CONVERSION_FAILED')
        self.assertTrue(lines[0].startswith(conversion.DIAGNOSTIC_PREFIX))
        value = json.loads(lines[0][len(conversion.DIAGNOSTIC_PREFIX):])
        self.assertEqual(value, dict(version=1, kind='native-conversion-failure', stage='verify',
                                     failure='contract', child_exit_status=0))
        self.assertNotIn('CANARY', err.getvalue())
        self.assertNotIn('/private', err.getvalue())

    def test_failures_and_unknown_values_never_export_exception_text(self):
        cases = [(FileNotFoundError('CANARY'), 'missing_file'), (PermissionError('CANARY'), 'permission'),
                 (MemoryError('CANARY'), 'memory'), (ImportError('CANARY'), 'import'),
                 (subprocess.CalledProcessError(7, ['CANARY']), 'subprocess'), (OSError('CANARY'), 'os_error'),
                 (KeyError('CANARY'), 'invalid_shape'), (TypeError('CANARY'), 'invalid_shape'),
                 (ValueError('NATIVE_CONVERSION_DISK_BUDGET'), 'disk_budget'),
                 (conversion.provision.ProvisionError('CANARY'), 'contract'), (RuntimeError('CANARY'), 'unknown')]
        for error, expected in cases:
            with self.subTest(expected=expected):
                value = conversion.failure_diagnostic({'stage': ['CANARY'], 'child_exit_status': True}, error)
                self.assertEqual(value['failure'], expected)
                self.assertEqual(value['stage'], 'unknown')
                self.assertIsNone(value['child_exit_status'])
                self.assertNotIn('CANARY', json.dumps(value))
        for status in (-129, 256, True, '0'):
            self.assertIsNone(conversion.child_status(status))


if __name__ == '__main__':
    unittest.main()
