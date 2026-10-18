#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-only
"""Inert builder contracts: mocks/public bytes, no compiler, VM or download."""
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import signal
import subprocess
import sys
import tempfile
import time
import types
import unittest
from unittest import mock

HERE = Path(__file__).resolve().parent
SPEC = importlib.util.spec_from_file_location('resident_build', HERE / 'protected-resident-model-build.py')
M = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(M)


def deadline():
    return time.monotonic_ns() + 60 * 1_000_000_000


def put(path, raw=b'public fixture', mode=0o600):
    missing, parent = [], path.parent
    while not parent.exists():
        missing.append(parent)
        parent = parent.parent
    for parent in reversed(missing):
        parent.mkdir(mode=0o700)
    path.write_bytes(raw)
    path.chmod(mode)
    return path


def lock_value():
    package = dict(version='1.2-3', architecture='amd64', filename='pool/a/a.deb',
                   url='https://deb.debian.org/debian/pool/a/a.deb', bytes=12,
                   sha256='a' * 64, index='trixie', depends='', pre_depends='')
    return dict(version=1, kind='protected-resident-debian-package-lock', architecture='amd64',
        profiles={name: dict(roots=['public-package'], packages=['public-package'])
                  for name in ('build', 'runtime')}, packages={'public-package': package})


def public_elf():
    raw = bytearray(64)
    raw[:7], raw[16:20] = b'\x7fELF\x02\x01\x01', b'\x03\x00\x3e\x00'
    return bytes(raw)  # Structural public bytes only, never executable code.


class SourceTests(unittest.TestCase):
    def test_git_object_known_blob(self):
        self.assertEqual(M.git_object('blob', b'test content\n').hex(),
                         'd670460b4b4aece5915caf5c68d12f560a9fe3e4')

    def fixture(self, root):
        inputs = root / 'input'
        core = inputs / 'core'
        put(core / 'public.py', b'public source\n')
        tree = M.source_tree(core, deadline())
        raw = f'tree {tree}\nauthor Public <public@example.invalid> 0 +0000\n\npublic\n'.encode()
        put(inputs / 'core.commit', raw)
        helper = put(inputs / 'code/scripts/opencode_native_cpu.py', b'# public helper\n')
        return inputs, M.git_object('commit', raw).hex(), hashlib.sha256(helper.read_bytes()).hexdigest()

    def test_exact_commit_tree_and_helper_binding(self):
        with tempfile.TemporaryDirectory() as directory:
            inputs, source, helper = self.fixture(Path(directory))
            with mock.patch.object(M, 'HELPER_SHA256', helper):
                core, path, tree = M.source_binding(inputs, source, deadline())
            self.assertEqual(core, inputs / 'core')
            self.assertEqual(tree, M.source_tree(core, deadline()))
            self.assertEqual(path, inputs / 'code/scripts/opencode_native_cpu.py')

    def test_source_mutation_extra_file_mode_and_wrong_commit_rejected(self):
        for mutation in ('bytes', 'extra', 'mode', 'commit', 'helper'):
            with self.subTest(mutation=mutation), tempfile.TemporaryDirectory() as directory:
                inputs, source, helper = self.fixture(Path(directory))
                if mutation == 'bytes':
                    (inputs / 'core/public.py').write_bytes(b'changed')
                elif mutation == 'extra':
                    put(inputs / 'core/extra')
                elif mutation == 'mode':
                    (inputs / 'core/public.py').chmod(0o700)
                elif mutation == 'commit':
                    source = '0' * 40
                else:
                    helper = '0' * 64
                with mock.patch.object(M, 'HELPER_SHA256', helper), self.assertRaises(ValueError):
                    M.source_binding(inputs, source, deadline())

    def test_source_symlink_is_hashed_not_followed(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / 'link').symlink_to('/never/read/private')
            expected = M.git_object('tree', b'120000 link\0' + M.git_object('blob', b'/never/read/private'))
            self.assertEqual(M.source_tree(root, deadline()), expected.hex())

    def test_source_git_directory_and_group_writable_refused(self):
        for name, mode in (('.git/a', 0o600), ('public', 0o660)):
            with self.subTest(name=name), tempfile.TemporaryDirectory() as directory:
                put(Path(directory) / name, mode=mode)
                with self.assertRaises(ValueError):
                    M.source_tree(Path(directory), deadline())

    def test_read_file_no_follow_hardlink_and_byte_bound(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            original = put(root / 'public', b'1234')
            (root / 'link').symlink_to(original)
            with self.assertRaises(OSError):
                M.read_file(root / 'link', 4, deadline())
            with self.assertRaises(ValueError):
                M.read_file(original, 3, deadline())
            os.link(original, root / 'hardlink')
            with self.assertRaises(ValueError):
                M.read_file(original, 4, deadline())


class PackageTests(unittest.TestCase):
    def test_pinned_repository_lock_schema(self):
        path = HERE / 'protected-resident-model-debian-lock-v1.json'
        raw = path.read_bytes()
        digest = hashlib.sha256(raw).hexdigest()
        # Controller stages private input bytes; do not change checkout modes.
        with tempfile.TemporaryDirectory() as directory:
            staged = put(Path(directory) / 'lock', raw)
            value = M.package_lock(staged, digest, deadline())
        self.assertEqual(len(value['profiles']['build']['packages']), 199)
        self.assertEqual(len(value['profiles']['runtime']['packages']), 65)

    def test_lock_digest_and_closed_package_schema(self):
        for mutation in ('digest', 'version_bool', 'duplicate', 'option_name', 'arch', 'bytes_bool'):
            with self.subTest(mutation=mutation), tempfile.TemporaryDirectory() as directory:
                value = lock_value()
                if mutation == 'version_bool':
                    value['version'] = True
                elif mutation == 'option_name':
                    value['profiles']['build']['packages'] = ['--command']
                elif mutation == 'arch':
                    value['packages']['public-package']['architecture'] = 'arm64'
                elif mutation == 'bytes_bool':
                    value['packages']['public-package']['bytes'] = True
                raw = M.encoded(value)
                if mutation == 'duplicate':
                    raw = raw.replace(b'"version":1', b'"version":1,"version":1')
                path = put(Path(directory) / 'lock', raw)
                digest = '0' * 64 if mutation == 'digest' else hashlib.sha256(raw).hexdigest()
                with self.assertRaises(ValueError):
                    M.package_lock(path, digest, deadline())

    def test_dpkg_query_exact_versions_architecture_status(self):
        with mock.patch.object(M, 'command', return_value=b'public-package\t1.2-3\tamd64\tinstalled\n') as run:
            self.assertEqual(M.verify_packages(lock_value(), deadline()), 1)
        argv = run.call_args.args[0]
        self.assertEqual(argv[0:2], ['/usr/bin/dpkg-query', '--show'])
        self.assertEqual(argv[-1], 'public-package')
        self.assertNotIn('apt-get', ' '.join(argv))

    def test_dpkg_wrong_missing_duplicate_or_unconfigured_denied(self):
        for raw in (b'', b'public-package\t1.2-4\tamd64\tinstalled\n',
                    b'public-package\t1.2-3\tall\tinstalled\n',
                    b'public-package\t1.2-3\tamd64\tunpacked\n',
                    b'public-package\t1.2-3\tamd64\tinstalled\n' * 2):
            with self.subTest(raw=raw), mock.patch.object(M, 'command', return_value=raw), self.assertRaises(ValueError):
                M.verify_packages(lock_value(), deadline())


class DeadlineAndProcessTests(unittest.TestCase):
    def test_one_original_monotonic_epoch_and_phase_caps(self):
        with mock.patch.object(M.time, 'monotonic_ns', return_value=35_000_000_000):
            self.assertEqual(M.remaining(95_000_000_000, 10), 10)
            for value in (True, 34_000_000_000, 8000_000_000_000, float('inf')):
                with self.assertRaises(ValueError):
                    M.remaining(value)

    def test_real_inert_child_stdout_separate_and_group_joined(self):
        # Only public Python fixture execution, never package/compiler/model/VM.
        real_kill, real_wait = os.killpg, subprocess.Popen.wait
        events = []

        def kill(pid, sig):
            events.append(('signal', sig))
            return real_kill(pid, sig)

        def wait(process, *args, **kwargs):
            events.append(('wait', 0))
            return real_wait(process, *args, **kwargs)

        with mock.patch.object(M.os, 'killpg', side_effect=kill), mock.patch.object(M.subprocess.Popen, 'wait', wait):
            raw = M.command([sys.executable, '-c', 'import sys; print("PUBLIC"); print("CANARY", file=sys.stderr)'], deadline())
        self.assertEqual(raw, b'PUBLIC\n')
        self.assertLess(events.index(('signal', signal.SIGKILL)), events.index(('wait', 0)))
        self.assertFalse(any(sig == signal.SIGKILL for kind, sig in events[events.index(('wait', 0)) + 1:]))

    def test_real_inert_child_timeout_and_output_bound(self):
        with self.assertRaisesRegex(ValueError, 'command_timeout'):
            M.command([sys.executable, '-c', 'import time; time.sleep(30)'], deadline(), cap=.1)
        with self.assertRaisesRegex(ValueError, 'command_output_bound'):
            M.command([sys.executable, '-c', 'print("X"*1000)'], deadline(), maximum=10)

    def test_natural_nonzero_exit_closed(self):
        with self.assertRaisesRegex(ValueError, '^command_failed$'):
            M.command([sys.executable, '-c', 'import sys; print("PRIVATE_CANARY", file=sys.stderr); sys.exit(7)'], deadline())

    def test_failed_group_observation_is_unconfirmed(self):
        with mock.patch.object(M, 'group_absent', return_value=False), self.assertRaises(M.CleanupUnconfirmed):
            M.command([sys.executable, '-c', 'pass'], deadline())

    def test_signal_failure_still_reaps_and_reports_unconfirmed(self):
        real_kill, real_wait = os.killpg, subprocess.Popen.wait
        joined = []

        def kill(pid, sig):
            if sig == signal.SIGKILL:
                raise PermissionError('PUBLIC fixture refusal')
            return real_kill(pid, sig)

        def wait(process, *args, **kwargs):
            value = real_wait(process, *args, **kwargs)
            joined.append(value)
            return value

        with mock.patch.object(M.os, 'killpg', side_effect=kill), \
                mock.patch.object(M.subprocess.Popen, 'wait', wait), self.assertRaises(M.CleanupUnconfirmed):
            M.command([sys.executable, '-c', 'pass'], deadline())
        self.assertEqual(joined, [0])

    def test_guest_guard_denies_host_or_root_before_build(self):
        args = types.SimpleNamespace(execute=True, yes=True, disposable_guest=True, deadline_monotonic_ns=deadline())
        with mock.patch.object(M.os, 'getuid', return_value=0), mock.patch.object(M, 'command') as run:
            with self.assertRaisesRegex(ValueError, 'disposable_guest'):
                M.guest_guard(args)
        run.assert_not_called()
        args.yes = False
        with self.assertRaisesRegex(ValueError, 'execution_consent'):
            M.guest_guard(args)

    def test_guest_guard_requires_real_kvm_and_debian13(self):
        args = types.SimpleNamespace(execute=True, yes=True, disposable_guest=True, deadline_monotonic_ns=deadline())
        with mock.patch.object(M.os, 'getuid', return_value=1000), mock.patch.object(M.os, 'geteuid', return_value=1000), \
                mock.patch.object(M.pwd, 'getpwuid', return_value=types.SimpleNamespace(pw_name='vpci')), \
                mock.patch.object(M.socket, 'gethostname', return_value='volparossa-alpha'), \
                mock.patch.object(M.platform, 'machine', return_value='x86_64'), \
                mock.patch.object(M.sys, 'version_info', (3, 13)), \
                mock.patch.object(M, 'read_file', return_value=b'VERSION_ID="13"\n'), \
                mock.patch.object(M, 'command', return_value=b'kvm\n') as run:
            M.guest_guard(args)
            run.return_value = b'qemu\n'
            with self.assertRaises(ValueError):
                M.guest_guard(args)


class BuildAndExportTests(unittest.TestCase):
    def test_export_failure_labels_are_closed_and_never_stringify_exceptions(self):
        class PrivateError(ValueError):
            def __str__(self):
                raise AssertionError('exception stringification forbidden')
        for operation, reasons in M.EXPORT_ERRORS.items():
            for reason in reasons:
                self.assertEqual(M.export_failure(ValueError(reason), operation), reason)
            self.assertEqual(M.export_failure(ValueError('PRIVATE_CANARY'), operation), 'invalid_value')
            self.assertEqual(M.export_failure(PrivateError('PRIVATE_CANARY'), operation), 'invalid_value')
        for error, expected in ((FileNotFoundError(2, 'PRIVATE_CANARY', '/private'), 'missing_file'),
                (FileExistsError('PRIVATE_CANARY'), 'existing_path'),
                (PermissionError('PRIVATE_CANARY'), 'permission_denied'),
                (InterruptedError('PRIVATE_CANARY'), 'interrupted'), (TimeoutError('PRIVATE_CANARY'), 'timeout'),
                (OSError('PRIVATE_CANARY'), 'io_error'), (KeyError('PRIVATE_CANARY'), 'missing_field'),
                (TypeError('PRIVATE_CANARY'), 'invalid_type'),
                (subprocess.CalledProcessError(1, '/private'), 'subprocess_failed'),
                (M.CleanupUnconfirmed('PRIVATE_CANARY'), 'cleanup_unconfirmed')):
            self.assertEqual(M.export_failure(error, 'inventory'), expected)
        self.assertEqual(M.export_failure(ValueError('model_pin'), 'declaration'), 'invalid_value')
        self.assertEqual(M.export_failure(ValueError('model_pin'), []), 'invalid_value')
        self.assertEqual(M.export_failure(ValueError(True), 'metadata'), 'invalid_value')

    def test_export_operation_failure_keeps_original_error_and_stops_before_next_operation(self):
        operations = list(M.EXPORT_ERRORS)[:7]
        for failed in operations:
            with self.subTest(operation=failed), tempfile.TemporaryDirectory() as directory:
                core, binary, native, fixture, output, stager = self.export_fixture(directory)
                events = []
                class Progress(dict):
                    def __setitem__(self, key, value):
                        if key == 'operation':
                            events.append(value)
                        super().__setitem__(key, value)
                progress = Progress(reason=None)
                original = ValueError('PRIVATE_CANARY')
                read, rename = M.read_file, Path.rename
                copy, inventory, write = M.copy_core_binary, M.asset_inventory, M.write_new
                def step(operation, call, *args, **kwargs):
                    if operation == failed:
                        raise original
                    return call(*args, **kwargs)
                with mock.patch.object(M, 'load_module', return_value=stager), \
                        mock.patch.object(M, 'read_file', side_effect=lambda path, *args:
                            step('declaration' if path.name == 'requester.json' else 'fixture_copy', read, path, *args)), \
                        mock.patch.object(Path, 'rename', autospec=True,
                            side_effect=lambda path, target: step('relocate', rename, path, target)), \
                        mock.patch.object(M, 'copy_core_binary', side_effect=lambda *args: step('core_copy', copy, *args)), \
                        mock.patch.object(M, 'asset_inventory', side_effect=lambda *args: step('inventory', inventory, *args)), \
                        mock.patch.object(stager, 'verified_metadata',
                            side_effect=lambda *_: step('metadata', lambda: 'd'*64)), \
                        mock.patch.object(M, 'write_new', side_effect=lambda path, *args:
                            step('write_inventory' if path.name == 'inventory.json' else
                                 'inventory' if path.name == 'public-policy.json' else 'fixture_copy', write, path, *args)), \
                        mock.patch.object(M.subprocess, 'Popen', side_effect=AssertionError('no execution')), \
                        self.assertRaises(ValueError) as caught:
                    M.export_assets(core, binary, native, fixture, output, 'f'*40, deadline(), progress)
                self.assertIs(caught.exception, original)
                self.assertEqual(events, operations[:operations.index(failed)+1])
                self.assertEqual(progress, dict(operation=failed, reason=None))
                self.assertFalse((output / 'inventory.json').exists())

    def test_export_success_reaches_inventory_write_without_claiming_final_rechecks(self):
        with tempfile.TemporaryDirectory() as directory:
            core, binary, native, fixture, output, stager = self.export_fixture(directory)
            progress = dict(operation='declaration', reason=None)
            with mock.patch.object(M, 'load_module', return_value=stager), \
                    mock.patch.object(stager, 'verified_metadata', return_value='d'*64), \
                    mock.patch.object(M.subprocess, 'Popen', side_effect=AssertionError('no execution')):
                result = M.export_assets(core, binary, native, fixture, output, 'f'*40, deadline(), progress)
            self.assertEqual(progress, dict(operation='write_inventory', reason=None))
            self.assertEqual(result['inventory_sha256'], hashlib.sha256((output/'inventory.json').read_bytes()).hexdigest())

    def test_build_exact_core_and_native_commands_without_install_or_inference(self):
        with tempfile.TemporaryDirectory() as directory, mock.patch.object(M, 'command', return_value=b'') as run:
            output, core = Path(directory), Path('/public/core')
            limit = deadline()
            binary, native = M.build_assets(core, output, limit)
        calls = run.call_args_list
        self.assertEqual(len(calls), 6)
        self.assertEqual(calls[0].args[0], ['/usr/bin/cargo', 'build', '--locked', '-p', 'volparossa', '--bin', 'volparossa'])
        self.assertEqual(calls[0].kwargs['cap'], 1200)
        self.assertEqual(calls[0].kwargs['extra_env'], {'CARGO_TARGET_DIR': str(output / 'target'),
            'CARGO_HOME': str(output / 'cargo-home'), 'HOME': str(output / 'home')})
        self.assertIn(M.LLAMA_SOURCE, calls[3].args[0])
        self.assertEqual(calls[-1].kwargs['cap'], 1800)
        self.assertTrue(all(call.args[1] <= limit for call in calls))
        self.assertEqual(binary, output / 'target/debug/volparossa')
        self.assertEqual(native, output / 'native')
        text = str(calls)
        for forbidden in ('apt-get', 'sudo', 'resident-guest', 'private-serve', 'torchrun'):
            self.assertNotIn(forbidden, text)

    def test_provision_original_profile_budget_and_deadline(self):
        contract = types.SimpleNamespace(load_pins=lambda **kw: dict(model_id='Qwen', revision='f'*40, wheels=[1, 2]),
            retained_pin_files=lambda pins: (b'public pins', b'public requirements'), download_total=lambda pins: 42)
        report = dict(success=True, training_performed=False, runtime_autofetch_enabled=False,
            model_id='Qwen', revision='f'*40, model_profile=M.MODEL, download_bytes=42,
            budget_bytes=M.PROVISION_BYTES, installed_wheels=2,
            model_pins_sha256=hashlib.sha256(b'public pins').hexdigest(),
            requirements_sha256=hashlib.sha256(b'public requirements').hexdigest())

        def read(path, *_args):
            return {'provision-report.json': M.encoded(report), 'model-pins.json': b'public pins',
                    'requirements.lock': b'public requirements'}[path.name]

        with mock.patch.object(M, 'command') as run, mock.patch.object(M, 'load_module', return_value=contract), \
                mock.patch.object(M, 'read_file', side_effect=read):
            M.provision(Path('/core'), Path('/output/native'), deadline())
        argv = run.call_args.args[0]
        self.assertEqual(argv[argv.index('--budget-bytes') + 1], '21474836480')
        self.assertEqual(argv[argv.index('--model-profile') + 1], M.MODEL)
        self.assertEqual(argv[0], '/usr/bin/python3.13')
        self.assertIn('--native-cpu-source', argv)
        self.assertIn('--native-cpu-build', argv)
        self.assertLessEqual(int(argv[argv.index('--timeout-seconds') + 1]), 60)

    def export_fixture(self, directory):
        root = Path(directory)
        core, native, output, fixture = root / 'core', root / 'native', root / 'output', root / 'fixture'
        output.mkdir(mode=0o700)
        for name in ('venv/bin/public', 'model/public', 'native-backend/backend.json',
                     'native-backend/build.json', 'native-backend/model.gguf',
                     'native-backend/libvolparossa_llama_cpu.so', 'native-backend/licenses/public.txt',
                     'native-backend/conversion.log'):
            put(native / 'ml' / name)
        binary = put(root / 'volparossa', public_elf(), mode=0o700)
        put(fixture / 'requester.json', M.encoded(dict(requester_key='a'*64, public_input_sha256=['b'*64, 'c'*64])))
        put(fixture / 'server.der')
        put(fixture / 'server-key.der')
        stager = M.load_module(HERE / 'protected-resident-model-workload.py', 'test_stager')
        return core, binary, native, fixture, output, stager

    def test_export_uses_exact_asset_allowlist_and_real_inventory_validator(self):
        with tempfile.TemporaryDirectory() as directory:
            core, binary, native, fixture, output, stager = self.export_fixture(directory)
            with mock.patch.object(M, 'load_module', return_value=stager), \
                    mock.patch.object(stager, 'verified_metadata', return_value='d'*64) as verify:
                result = M.export_assets(core, binary, native, fixture, output, 'f'*40, deadline())
            value = json.loads((output / 'inventory.json').read_bytes())
            policy = json.loads((output / 'assets/public-policy.json').read_bytes())
            self.assertEqual(result['workload_sha256'], policy['workload_sha256'])
            self.assertEqual(result['inventory_sha256'], hashlib.sha256((output / 'inventory.json').read_bytes()).hexdigest())
            self.assertEqual(policy['requester_key'], 'a'*64)
            self.assertNotIn('native-backend/conversion.log', value['entries'])
            self.assertTrue((native / 'ml/native-backend/conversion.log').exists())
            self.assertFalse((native / 'ml/venv').exists())
            verify.assert_called_once()

    def test_export_rejects_private_unknown_duplicate_or_bad_requester_fields(self):
        for raw in (b'{"requester_key":"a","public_input_sha256":[]}',
                    M.encoded(dict(requester_key='a'*64, public_input_sha256=['b'*64]*2, private_seed='CANARY')),
                    b'{"requester_key":"a","requester_key":"a","public_input_sha256":[]}'):
            with self.subTest(raw=raw), tempfile.TemporaryDirectory() as directory:
                core, binary, native, fixture, output, stager = self.export_fixture(directory)
                (fixture / 'requester.json').write_bytes(raw)
                with mock.patch.object(M, 'load_module', return_value=stager), self.assertRaises(ValueError):
                    M.export_assets(core, binary, native, fixture, output, 'f'*40, deadline())
                self.assertFalse((output / 'assets').exists())

    def test_export_refuses_existing_assets(self):
        with tempfile.TemporaryDirectory() as directory:
            core, binary, native, fixture, output, stager = self.export_fixture(directory)
            (output / 'assets').mkdir()
            with mock.patch.object(M, 'load_module', return_value=stager), self.assertRaises(FileExistsError):
                M.export_assets(core, binary, native, fixture, output, 'f'*40, deadline())

    def test_export_passes_full_existing_stager_on_public_small_asset_fixture(self):
        spec = importlib.util.spec_from_file_location('public_workload_fixture',
            HERE / 'test-protected-resident-model-workload.py')
        fixtures = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(fixtures)
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            original = fixtures.Fixture(directory)
            native, output, declaration = root / 'native', root / 'output', root / 'fixture'
            (native / 'ml').mkdir(parents=True, mode=0o700)
            output.mkdir(mode=0o700)
            for name, target in (('runtime', 'venv'), ('model', 'model'), ('native-backend', 'native-backend')):
                (original.assets / name).rename(native / 'ml' / target)
            put(declaration / 'requester.json', M.encoded(dict(requester_key='2'*64,
                public_input_sha256=['3'*64, '4'*64])))
            for name in ('server.der', 'server-key.der'):
                put(declaration / name, (original.assets / name).read_bytes())
            # Only public model bytes replace pinned downloads in this inert
            # fixture. Native schema, wrapper hashes and stager run unchanged.
            fake_pins = types.SimpleNamespace(load_pins=lambda **_kw: original.pins)
            with mock.patch.object(M, 'load_module', return_value=fixtures.M), \
                    mock.patch.object(fixtures.M, 'module', side_effect=lambda name:
                                      fixtures.NATIVE if name == 'llama_cpu' else fake_pins):
                result = M.export_assets(Path('/public/core'), original.assets / 'volparossa', native,
                    declaration, output, fixtures.SOURCE, deadline())
                staged = fixtures.M.stage_workload(output / 'assets', output / 'inventory.json',
                    result['inventory_sha256'], root / 'public-workload.tar', fixtures.SOURCE,
                    time.monotonic() + 30)
            self.assertEqual(staged['workload_sha256'], result['workload_sha256'])
            self.assertTrue((root / 'public-workload.tar').is_file())

    def test_write_new_never_overwrites(self):
        with tempfile.TemporaryDirectory() as directory:
            path = put(Path(directory) / 'existing', b'original')
            with self.assertRaises(FileExistsError):
                M.write_new(path, b'changed')
            self.assertEqual(path.read_bytes(), b'original')

    def test_cargo_hardlink_is_copied_to_exclusive_single_link_bound_elf(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            binary = put(root / 'target/debug/deps/volparossa-hash', public_elf(), mode=0o700)
            alias = root / 'target/debug/volparossa'
            os.link(binary, alias)
            before = M.identity(alias.stat())
            self.assertEqual(alias.stat().st_nlink, 2)
            with self.assertRaisesRegex(ValueError, 'asset_file'):
                M.file_record(alias, deadline())
            output = root / 'exported'
            M.copy_core_binary(alias, output, deadline())
            self.assertEqual(M.identity(alias.stat()), before)
            self.assertEqual(output.stat().st_nlink, 1)
            self.assertNotEqual(output.stat().st_ino, alias.stat().st_ino)
            self.assertEqual(output.read_bytes(), public_elf())
            self.assertEqual(M.file_record(output, deadline())['sha256'], hashlib.sha256(public_elf()).hexdigest())
            with self.assertRaises(FileExistsError):
                M.copy_core_binary(alias, output, deadline())
            (root / 'symlink').symlink_to(alias)
            with self.assertRaises(OSError):
                M.copy_core_binary(root / 'symlink', root / 'denied', deadline())
            with self.assertRaisesRegex(ValueError, 'core_binary_metadata'):
                M.copy_core_binary(put(root / 'short', b'x', mode=0o700), root / 'denied', deadline())


class OrchestrationTests(unittest.TestCase):
    def arguments(self, directory):
        root = Path(directory)
        inputs = root / 'input'
        inputs.mkdir(mode=0o700)
        return types.SimpleNamespace(input=inputs, output=root / 'output', expected_source='f'*40,
            package_lock=root / 'lock', package_lock_sha256='a'*64, deadline_monotonic_ns=deadline())

    def export_observation(self, directory, fail):
        args = self.arguments(directory)
        events, shared = [], {}
        helper = types.SimpleNamespace(SOURCE=M.LLAMA_SOURCE, ORIGIN=M.LLAMA_ORIGIN, MODEL=M.MODEL,
            validate_build=lambda *_: {'build_manifest_sha256': 'a'*64},
            validate_provision=lambda *_: {}, require_output_constraint=lambda *_: None)
        def source(*_):
            events.append('source')
            tree = 'c'*40 if fail == 'source_recheck' and len(events) > 1 else 'b'*40
            return args.input, args.input, tree
        def export(*values):
            events.append('export')
            shared['progress'] = values[-1]
            shared['progress']['operation'] = 'metadata' if fail in ('metadata', 'cleanup') else 'write_inventory'
            if fail == 'metadata':
                raise ValueError('model_pin')
            if fail == 'cleanup':
                raise M.CleanupUnconfirmed('PRIVATE_CANARY')
            return {}
        original_remaining = M.remaining
        def remaining(*values):
            if shared.get('progress', {}).get('operation') == 'final_deadline' and fail == 'final_deadline':
                raise ValueError('build_deadline')
            return original_remaining(*values)
        class InterruptedReturn(dict):
            def __setitem__(self, key, value):
                if key == 'operation' and value == 'source_recheck':
                    raise InterruptedError('PRIVATE_CANARY')
                super().__setitem__(key, value)
        def report_dict(*values, **fields):
            kind = InterruptedReturn if fail == 'returned_interrupt' and fields.keys() == {'operation', 'reason'} else dict
            return kind(*values, **fields)
        with mock.patch.object(M, 'guest_guard'), mock.patch.object(M, 'source_binding', side_effect=source), \
                mock.patch.object(M, 'package_lock', return_value={}), mock.patch.object(M, 'verify_packages', return_value=199), \
                mock.patch.object(M, 'load_module', return_value=helper), \
                mock.patch.object(M, 'build_assets', return_value=(args.output/'binary', args.output/'native')), \
                mock.patch.object(M, 'provision', return_value=({}, {})), \
                mock.patch.object(M, 'export_assets', side_effect=export), \
                mock.patch.object(M, 'remaining', side_effect=remaining), \
                mock.patch.object(M, 'dict', side_effect=report_dict, create=True), \
                mock.patch.object(M.subprocess, 'Popen', side_effect=AssertionError('no execution')):
            result = M.execute(args)
        self.assertEqual(json.loads((args.output/'build-result.json').read_bytes()), result)
        return result, events

    def test_export_failure_and_returned_export_final_checks_remain_distinct(self):
        for failed, reason in (('metadata', 'model_pin'), ('source_recheck', 'source_changed'),
                               ('final_deadline', 'build_deadline')):
            with self.subTest(operation=failed), tempfile.TemporaryDirectory() as directory:
                result, events = self.export_observation(directory, failed)
                self.assertEqual(result['export_diagnostic'], dict(operation=failed, reason=reason))
                self.assertEqual((result['state'], result['phase']), ('failed', 'export'))
                self.assertEqual('export' in result, failed != 'metadata')
                self.assertEqual(events, ['source', 'export'] + ([] if failed == 'metadata' else ['source']))
                self.assertFalse(result['assets_exported'] or result['model_execution'] or result['complete_guest_cleanup'])

    def test_export_completion_has_no_failure_and_requires_final_source_and_deadline(self):
        with tempfile.TemporaryDirectory() as directory:
            result, events = self.export_observation(directory, None)
        self.assertEqual(events, ['source', 'export', 'source'])
        self.assertEqual((result['state'], result['phase']), ('assets_built', 'complete'))
        self.assertNotIn('export_diagnostic', result)
        self.assertTrue(result['assets_exported'])
        self.assertFalse(result['model_execution'] or result['complete_guest_cleanup'])

    def test_interrupt_after_export_return_keeps_returned_metadata_without_next_recheck(self):
        with tempfile.TemporaryDirectory() as directory:
            result, events = self.export_observation(directory, 'returned_interrupt')
        self.assertEqual(events, ['source', 'export'])
        self.assertIn('export', result)
        self.assertEqual((result['state'], result['phase']), ('failed', 'export'))
        self.assertEqual(result['export_diagnostic'], dict(operation='write_inventory', reason='interrupted'))
        self.assertFalse(result['assets_exported'] or result['model_execution'])
        self.assertNotIn('PRIVATE_CANARY', json.dumps(result))

    def test_export_cleanup_failure_still_marks_unjoined_children_without_private_text(self):
        with tempfile.TemporaryDirectory() as directory:
            result, events = self.export_observation(directory, 'cleanup')
        self.assertEqual(events, ['source', 'export'])
        self.assertEqual(result['export_diagnostic'], dict(operation='metadata', reason='cleanup_unconfirmed'))
        self.assertFalse(result['direct_child_groups_joined'])
        self.assertNotIn('PRIVATE_CANARY', json.dumps(result))

    def test_all_ordered_stages_and_source_recheck_without_false_cleanup_or_execution(self):
        with tempfile.TemporaryDirectory() as directory:
            args = self.arguments(directory)
            events = []
            helper = types.SimpleNamespace(SOURCE=M.LLAMA_SOURCE, ORIGIN=M.LLAMA_ORIGIN, MODEL=M.MODEL,
                validate_build=lambda *_: events.append('validate_build') or {'build_manifest_sha256': 'a'*64},
                validate_provision=lambda *_: events.append('validate_provision') or {},
                require_output_constraint=lambda *_: events.append('constraints'))
            with mock.patch.object(M, 'guest_guard', side_effect=lambda *_: events.append('guard')), \
                    mock.patch.object(M, 'source_binding', side_effect=lambda *_: events.append('source') or (args.input, args.input, 'b'*40)), \
                    mock.patch.object(M, 'package_lock', return_value={}), \
                    mock.patch.object(M, 'verify_packages', side_effect=lambda *_: events.append('packages') or 199), \
                    mock.patch.object(M, 'load_module', return_value=helper), \
                    mock.patch.object(M, 'build_assets', side_effect=lambda *_: events.append('build') or (args.output/'binary', args.output/'native')), \
                    mock.patch.object(M, 'provision', side_effect=lambda *_: events.append('provision') or ({}, {})), \
                    mock.patch.object(M, 'export_assets', side_effect=lambda *_: events.append('export') or {}):
                result = M.execute(args)
            self.assertEqual(events, ['guard', 'source', 'packages', 'build', 'validate_build',
                                     'provision', 'validate_provision', 'constraints', 'export', 'source'])
            self.assertEqual(result['state'], 'assets_built')
            self.assertTrue(result['assets_exported'])
            self.assertIsNone(result['descendants_joined'])
            for key in ('model_execution', 'worker_execution', 'private_inputs', 'hardware_attestation',
                        'production_approval', 'complete_guest_cleanup', 'scratch_removed'):
                self.assertIs(result[key], False)
            self.assertEqual(json.loads((args.output/'build-result.json').read_bytes()), result)

    def test_failure_preserves_owned_scratch_and_closed_phase(self):
        for error in (ValueError('PRIVATE_CANARY'), M.CleanupUnconfirmed('PRIVATE_CANARY')):
            with self.subTest(error=type(error)), tempfile.TemporaryDirectory() as directory:
                args = self.arguments(directory)
                with mock.patch.object(M, 'guest_guard'), mock.patch.object(M, 'source_binding', side_effect=error):
                    result = M.execute(args)
                self.assertEqual(result['state'], 'failed')
                self.assertEqual(result['phase'], 'source')
                self.assertFalse(result['assets_exported'])
                self.assertNotIn('PRIVATE_CANARY', json.dumps(result))
                self.assertTrue(args.output.exists())
                self.assertEqual(result['direct_child_groups_joined'], not isinstance(error, M.CleanupUnconfirmed))

    def test_interrupted_final_group_observation_has_closed_unconfirmed_receipt(self):
        with tempfile.TemporaryDirectory() as directory:
            args = self.arguments(directory)
            with mock.patch.object(M, 'guest_guard'), \
                    mock.patch.object(M, 'group_absent', side_effect=InterruptedError('PRIVATE_CANARY')), \
                    mock.patch.object(M, 'source_binding', side_effect=lambda *_:
                                      M.command([sys.executable, '-c', 'pass'], deadline())):
                result = M.execute(args)
            self.assertEqual(result['state'], 'failed')
            self.assertFalse(result['direct_child_groups_joined'])
            self.assertIsNone(result['descendants_joined'])
            self.assertFalse(result['complete_guest_cleanup'])
            self.assertFalse(result['scratch_removed'])
            self.assertNotIn('PRIVATE_CANARY', (args.output / 'build-result.json').read_text())

    def test_existing_output_and_input_ancestor_denied(self):
        with tempfile.TemporaryDirectory() as directory:
            args = self.arguments(directory)
            args.output.mkdir()
            with mock.patch.object(M, 'guest_guard'), self.assertRaises(ValueError):
                M.execute(args)
            args.output = args.input / 'child'
            with mock.patch.object(M, 'guest_guard'), self.assertRaises(ValueError):
                M.execute(args)

    def test_replaced_output_directory_is_not_used_for_failure_receipt(self):
        with tempfile.TemporaryDirectory() as directory:
            args = self.arguments(directory)

            def replace(*_args):
                args.output.rename(args.output.with_name('original-output'))
                args.output.mkdir(mode=0o700)
                raise ValueError('PUBLIC failure')

            with mock.patch.object(M, 'guest_guard'), mock.patch.object(M, 'source_binding', side_effect=replace):
                result = M.execute(args)
            self.assertEqual(result['state'], 'failed')
            self.assertEqual(list(args.output.iterdir()), [])

    def test_main_guard_failure_is_closed_and_restores_handlers(self):
        with mock.patch.object(M, 'execute', side_effect=ValueError('PRIVATE_CANARY')), \
                mock.patch('builtins.print') as print_mock:
            prior = signal.getsignal(signal.SIGTERM)
            code = M.main(['--execute', '--yes', '--disposable-guest', '--input', '/input', '--output', '/output',
                '--expected-source', 'f'*40, '--package-lock', '/lock', '--package-lock-sha256', 'a'*64,
                '--deadline-monotonic-ns', str(deadline())])
        self.assertEqual(code, 1)
        self.assertEqual(signal.getsignal(signal.SIGTERM), prior)
        self.assertNotIn('PRIVATE_CANARY', str(print_mock.call_args))


if __name__ == '__main__':
    unittest.main()
