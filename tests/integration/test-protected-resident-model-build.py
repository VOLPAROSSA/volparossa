#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-only
"""Inert builder contracts: mocks/public bytes, no compiler, VM or download."""
from contextlib import contextmanager, nullcontext
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

    def test_exact_command_environment_omits_legacy_overrides_and_rejects_ambiguous_merge(self):
        env = {'PATH': '/usr/bin:/bin', 'PUBLIC_FIXED': 'yes'}
        raw = M.command([sys.executable, '-c', 'import json,os;print(json.dumps(dict(os.environ)))'],
            deadline(), exact_env=env)
        value = json.loads(raw)
        self.assertEqual(value['PUBLIC_FIXED'], 'yes')
        self.assertNotIn('CARGO_PROFILE_DEV_DEBUG', value)
        self.assertNotIn('CARGO_INCREMENTAL', value)
        with mock.patch.object(M.subprocess, 'Popen') as process:
            with self.assertRaisesRegex(ValueError, '^command_environment$'):
                M.command(['/public/cargo'], deadline(), extra_env={}, exact_env={})
            process.assert_not_called()

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


class CompilerDeadlineTests(unittest.TestCase):
    def test_original_absolute_deadline_restores_alarm_handler_and_timer_on_expiry_or_cancel(self):
        previous = lambda *_: None
        for failure in ('expiry', 'cancel'):
            with self.subTest(failure=failure), \
                    mock.patch.object(M.signal, 'getsignal', return_value=previous), \
                    mock.patch.object(M.signal, 'getitimer', return_value=(0.0, 0.0)), \
                    mock.patch.object(M.signal, 'signal') as handler, \
                    mock.patch.object(M.signal, 'setitimer') as timer:
                end = deadline()
                with self.assertRaises(InterruptedError):
                    with M.compiler_deadline(end):
                        if failure == 'expiry':
                            handler.call_args_list[0].args[1](signal.SIGALRM, None)
                        raise InterruptedError('cancelled')
                self.assertEqual(handler.call_args_list[-1], mock.call(signal.SIGALRM, previous))
                self.assertTrue(all(call.args[0] == signal.SIGALRM for call in handler.call_args_list))
                self.assertGreater(timer.call_args_list[0].args[1], 0)
                self.assertLessEqual(timer.call_args_list[0].args[1], 60)
                self.assertEqual(timer.call_args_list[-2:], [mock.call(signal.ITIMER_REAL, 0),
                    mock.call(signal.ITIMER_REAL, 0.0, 0.0)])

    def test_active_prior_timer_is_rejected_without_stealing_or_renewing_its_budget(self):
        for prior in ((10.0, 0.0), (0.0, 1.0)):
            with self.subTest(prior=prior), mock.patch.object(M.signal, 'getsignal'), \
                    mock.patch.object(M.signal, 'getitimer', return_value=prior), \
                    mock.patch.object(M.signal, 'signal') as handler, \
                    mock.patch.object(M.signal, 'setitimer') as timer:
                with self.assertRaisesRegex(ValueError, '^compiler_timer_busy$'):
                    with M.compiler_deadline(deadline()):
                        self.fail('another timer owner was admitted')
                handler.assert_not_called(); timer.assert_not_called()

    def test_expired_parent_rejects_before_changing_any_signal(self):
        with mock.patch.object(M.signal, 'signal') as handler, \
                mock.patch.object(M.signal, 'setitimer') as timer:
            with self.assertRaisesRegex(ValueError, '^build_deadline$'):
                with M.compiler_deadline(time.monotonic_ns() - 1):
                    self.fail('expired parent was admitted')
            handler.assert_not_called(); timer.assert_not_called()


class CompilerAdapterTests(unittest.TestCase):
    def compiler(self, directory):
        core = Path(directory) / 'core'
        put(core / 'Cargo.lock', b'public current lock')
        put(core / 'scripts/cargo-source-policy.py', b'public reviewed policy')
        pin = put(core / 'scripts/rust189-components.json', b'public reviewed components')
        prefix = Path('/home/vpci/.local/volparossa-rust-1.89.0')
        events = []
        class InstallerCleanupUnconfirmed(RuntimeError):
            pass
        def activate(_mode, *, env, cwd):
            self.assertEqual(cwd, core)
            events.append('activate')
            return dict(env, CARGO_HOME='/home/vpci/.local/volparossa-cargo-public-v1',
                GIT_CONFIG_SYSTEM='/dev/null', GIT_ALLOW_PROTOCOL='https', GIT_ASKPASS='/usr/bin/false')
        policy = dict(activate=mock.Mock(side_effect=activate),
            validate_active=mock.Mock(side_effect=lambda *_: events.append('policy')),
            check_command=mock.Mock(side_effect=lambda *_, **__: events.append('command')))
        compiler = types.SimpleNamespace(PROFILE='rust-1.89.0-20250807', PINS=pin,
            PINS_SHA256=hashlib.sha256(pin.read_bytes()).hexdigest(), MANIFEST_SHA256='a' * 64,
            POLICY=policy, CleanupUnconfirmed=InstallerCleanupUnconfirmed,
            location=mock.Mock(return_value=prefix), pins=mock.Mock(return_value={'reviewed': True}),
            provision=mock.Mock(return_value=prefix),
            verify_payload=mock.Mock(side_effect=lambda *_: events.append('payload')),
            validate_receipt=mock.Mock())
        return core, prefix, compiler, events

    @contextmanager
    def admitted(self, core, prefix, compiler, *, command=None):
        def read(path, _maximum, _deadline):
            if path == prefix / 'receipt.json': return getattr(compiler, 'receipt_payload', b'{"public":"compiler receipt"}\n')
            if path == prefix.parent / 'cargo-source-policy.json': return getattr(compiler, 'scope_payload', b'public source scope')
            return path.read_bytes()
        with mock.patch.object(M.os, 'getuid', return_value=1000), \
                mock.patch.object(M.os, 'geteuid', return_value=1000), \
                mock.patch.object(M.pwd, 'getpwuid', return_value=types.SimpleNamespace(pw_name='vpci', pw_dir='/home/vpci')), \
                mock.patch.object(Path, 'home', return_value=Path('/home/vpci')), \
                mock.patch.object(M, 'compiler_module', return_value=compiler), \
                mock.patch.object(M, 'compiler_deadline', return_value=nullcontext()) as budget, \
                mock.patch.object(M, 'read_file', side_effect=read), \
                mock.patch.object(M, 'command', side_effect=command or (lambda *_a, **_k: b'')) as run:
            yield budget, run

    def test_exact_reviewed_cargo_and_policy_environment_before_and_after_build(self):
        with tempfile.TemporaryDirectory() as directory:
            core, prefix, compiler, events = self.compiler(directory)
            original = dict(os.environ)
            observed_installer = []
            compiler.provision.side_effect = lambda *_: observed_installer.append(dict(os.environ)) or prefix
            with self.admitted(core, prefix, compiler) as (budget, run):
                end = deadline()
                proof = M.build_core(core, Path(directory) / 'target', end)
            budget.assert_called_once_with(end)
            compiler.location.assert_called_once_with('alpha-guest', mock.ANY)
            self.assertEqual(events, ['activate', 'payload', 'policy', 'command', 'payload', 'policy'])
            compiler.validate_receipt.assert_called_once_with({'public': 'compiler receipt'})
            arguments = ['build', '--locked', '-p', 'volparossa', '--bin', 'volparossa']
            compiler.POLICY['check_command'].assert_called_once_with(arguments, cwd=core)
            self.assertEqual(run.call_args.args, ([prefix / 'bin/cargo', *arguments], end))
            self.assertEqual(run.call_args.kwargs['cap'], 1200)
            self.assertEqual(run.call_args.kwargs['cwd'], core)
            env = run.call_args.kwargs['exact_env']
            self.assertNotIn('extra_env', run.call_args.kwargs)
            self.assertEqual(env['HOME'], '/home/vpci')
            self.assertEqual(env['RUSTC'], str(prefix / 'bin/rustc'))
            self.assertEqual(env['RUSTDOC'], str(prefix / 'bin/rustdoc'))
            self.assertEqual(env['PATH'], str(prefix / 'bin') + ':' + M.ENV['PATH'])
            for key in ('CARGO_PROFILE_DEV_DEBUG', 'CARGO_INCREMENTAL'):
                self.assertNotIn(key, env)
            self.assertEqual(observed_installer, [env])
            self.assertEqual(dict(os.environ), original)
            self.assertTrue(proof['payload_verified_before'] and proof['payload_verified_after'])
            self.assertEqual(proof['compiler_receipt_sha256'], hashlib.sha256(b'{"public":"compiler receipt"}\n').hexdigest())

    def test_wrong_account_or_actual_home_denies_before_compiler_location_or_network(self):
        for uid, account, home, declared in ((0, 'vpci', '/home/vpci', '/home/vpci'),
                (1000, 'other', '/home/vpci', '/home/vpci'),
                (1000, 'vpci', '/home/other', '/home/vpci'),
                (1000, 'vpci', '/home/vpci', '/home/other')):
            with self.subTest(uid=uid, account=account, home=home), \
                    mock.patch.object(M.os, 'getuid', return_value=uid), \
                    mock.patch.object(M.os, 'geteuid', return_value=uid), \
                    mock.patch.object(M.pwd, 'getpwuid', return_value=types.SimpleNamespace(pw_name=account, pw_dir=declared)), \
                    mock.patch.object(Path, 'home', return_value=Path(home)), \
                    mock.patch.object(M, 'compiler_module') as module:
                with self.assertRaisesRegex(ValueError, '^compiler_guest_account$'):
                    M.build_core(Path('/public/core'), Path('/public/target'), deadline())
                module.assert_not_called()

    def test_host_and_unsafe_parent_delegate_to_unchanged_guard_before_policy_or_provision(self):
        for reason in ('not a disposable KVM guest', 'unsafe compiler parent'):
            with self.subTest(reason=reason), tempfile.TemporaryDirectory() as directory:
                core, prefix, compiler, _events = self.compiler(directory)
                compiler.location.side_effect = ValueError(reason)
                with self.admitted(core, prefix, compiler) as (_budget, run):
                    with self.assertRaises(ValueError):
                        M.build_core(core, Path(directory) / 'target', deadline())
                compiler.POLICY['activate'].assert_not_called()
                compiler.provision.assert_not_called(); run.assert_not_called()

    def test_policy_denial_precedes_provision_or_compilation(self):
        with tempfile.TemporaryDirectory() as directory:
            core, prefix, compiler, _events = self.compiler(directory)
            compiler.POLICY['activate'].side_effect = ValueError('closed policy denial')
            with self.admitted(core, prefix, compiler) as (_budget, run):
                with self.assertRaises(ValueError):
                    M.build_core(core, Path(directory) / 'target', deadline())
            compiler.provision.assert_not_called(); run.assert_not_called()

    def test_cancelled_provision_restores_environment_and_cleanup_uncertainty_dominates(self):
        for cleanup in (False, True):
            with self.subTest(cleanup=cleanup), tempfile.TemporaryDirectory() as directory:
                core, prefix, compiler, _events = self.compiler(directory)
                original = dict(os.environ)
                error = compiler.CleanupUnconfirmed('PRIVATE_CANARY') if cleanup else InterruptedError('cancelled')
                compiler.provision.side_effect = error
                with self.admitted(core, prefix, compiler) as (_budget, run):
                    with self.assertRaises(M.CleanupUnconfirmed if cleanup else InterruptedError) as caught:
                        M.build_core(core, Path(directory) / 'target', deadline())
                self.assertEqual(dict(os.environ), original)
                if cleanup: self.assertEqual(str(caught.exception), 'compiler_installer_group')
                run.assert_not_called()
                compiler.verify_payload.assert_not_called()

    def test_postbuild_payload_or_active_policy_mutation_prevents_successful_proof(self):
        for kind in ('payload', 'policy', 'receipt', 'scope', 'pins'):
            with self.subTest(kind=kind), tempfile.TemporaryDirectory() as directory:
                core, prefix, compiler, _events = self.compiler(directory)
                if kind == 'payload': compiler.verify_payload.side_effect = [None, ValueError('payload changed')]
                if kind == 'policy': compiler.POLICY['validate_active'].side_effect = [None, ValueError('policy changed')]
                def command(*_args, **_kwargs):
                    if kind == 'pins': compiler.PINS.write_bytes(b'changed reviewed metadata')
                    if kind == 'receipt': compiler.receipt_payload = b'{"public":"changed receipt"}\n'
                    if kind == 'scope': compiler.scope_payload = b'changed source scope'
                    return b''
                with self.admitted(core, prefix, compiler, command=command) as (_budget, run):
                    with self.assertRaises(ValueError):
                        M.build_core(core, Path(directory) / 'target', deadline())
                self.assertEqual(run.call_count, 1)


class BuildAndExportTests(unittest.TestCase):
    def setUp(self):
        # These tests use structural ELF bytes, not a linked GNU ELF. Keep their
        # existing real copy/inventory checks; mock only the new strip command.
        def strip_only(argv, *_args, **_kwargs):
            self.assertEqual(argv[:3], [M.CORE_STRIP, '--strip-debug', '--'])
            self.assertEqual(len(argv), 4)
            return b''
        patch = mock.patch.object(M, 'command', side_effect=strip_only)
        patch.start(); self.addCleanup(patch.stop)

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

    def test_packaging_failure_prevents_fixture_and_inventory_export(self):
        for error in (ValueError('command_failed'), ValueError('core_binary_metadata'),
                      M.CleanupUnconfirmed('command_cleanup')):
            with self.subTest(error=type(error).__name__), tempfile.TemporaryDirectory() as directory:
                core, binary, native, fixture, output, stager = self.export_fixture(directory)
                progress = dict(reason=None)
                with mock.patch.object(M, 'load_module', return_value=stager), \
                        mock.patch.object(M, 'command', side_effect=error), \
                        mock.patch.object(M, 'asset_inventory') as inventory, \
                        mock.patch.object(stager, 'verified_metadata') as metadata, \
                        self.assertRaises(type(error)) as caught:
                    M.export_assets(core, binary, native, fixture, output, 'f'*40, deadline(), progress)
                self.assertIs(caught.exception, error)
                self.assertEqual(progress['operation'], 'core_copy')
                inventory.assert_not_called()
                metadata.assert_not_called()
                self.assertFalse((output / 'inventory.json').exists())
                self.assertFalse((output / 'assets/server.der').exists())
                self.assertFalse((output / 'assets/server-key.der').exists())

    def test_oversized_packaged_output_prevents_inventory_export(self):
        with tempfile.TemporaryDirectory() as directory:
            core, binary, native, fixture, output, stager = self.export_fixture(directory)
            def strip(argv, *_args, **_kwargs):
                with argv[-1].open('r+b') as stream: stream.truncate(M.MAX_BOOT_CORE_BYTES + 1)
                return b''
            progress = dict(reason=None)
            with mock.patch.object(M, 'load_module', return_value=stager), \
                    mock.patch.object(M, 'command', side_effect=strip), \
                    mock.patch.object(M, 'asset_inventory') as inventory, \
                    self.assertRaisesRegex(ValueError, '^core_binary_metadata$'):
                M.export_assets(core, binary, native, fixture, output, 'f'*40, deadline(), progress)
            inventory.assert_not_called()
            self.assertEqual(progress['operation'], 'core_copy')
            self.assertFalse((output / 'inventory.json').exists())
            self.assertFalse((output / 'assets/server.der').exists())

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
        proof = {'synthetic': 'compiler proof validated separately'}
        with tempfile.TemporaryDirectory() as directory, mock.patch.object(M, 'command', return_value=b'') as run, \
                mock.patch.object(M, 'build_core', return_value=proof) as build:
            output, core = Path(directory), Path('/public/core')
            limit = deadline()
            binary, native, compiler = M.build_assets(core, output, limit)
        build.assert_called_once_with(core, output / 'target', limit)
        calls = run.call_args_list
        self.assertEqual(len(calls), 5)
        self.assertIn(M.LLAMA_SOURCE, calls[2].args[0])
        self.assertEqual(calls[-1].kwargs['cap'], 1800)
        self.assertTrue(all(call.args[1] <= limit for call in calls))
        self.assertEqual(binary, output / 'target/debug/volparossa')
        self.assertEqual(native, output / 'native')
        self.assertIs(compiler, proof)
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

    def test_inventory_preflight_rejects_every_invalid_name_before_hash_or_readlink(self):
        stager = M.load_module(HERE / 'protected-resident-model-workload.py', 'test_preflight_stager')
        cases = ((None, 'inventory_path_type'), ('', 'inventory_path_empty'),
            ('z' * 241, 'inventory_path_length'),
            ('runtime/zPRIVATE:CANARY', 'inventory_path_character_or_separator'),
            ('runtime/z/../PRIVATE_CANARY', 'inventory_path_dot_component'))
        for name, reason in cases:
            with self.subTest(reason=reason), mock.patch.object(stager, 'scan',
                    return_value=['runtime/a', name]), mock.patch.object(M, 'file_record') as hashed, \
                    mock.patch.object(M.os, 'readlink') as linked, self.assertRaises(ValueError) as caught:
                M.asset_inventory(Path('/never-opened'), 'f' * 40, stager, deadline())
            self.assertEqual(caught.exception.args, (reason,))
            self.assertEqual(M.export_failure(caught.exception, 'inventory'), reason)
            self.assertEqual(M.export_failure(caught.exception, 'metadata'), 'invalid_value')
            hashed.assert_not_called()
            linked.assert_not_called()
            self.assertNotIn('PRIVATE', reason)

    def test_real_name_scan_finds_late_invalid_entry_before_any_inventory_asset_read(self):
        stager = M.load_module(HERE / 'protected-resident-model-workload.py', 'test_real_preflight_stager')
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            put(root / 'runtime/a', b'public valid file')
            put(root / 'runtime/zPRIVATE:CANARY', b'public invalid pathname fixture')
            (root / 'runtime/b').symlink_to('a')
            with mock.patch.object(M, 'file_record') as hashed, mock.patch.object(M.os, 'readlink') as linked, \
                    self.assertRaisesRegex(ValueError, '^inventory_path_character_or_separator$'):
                M.asset_inventory(root, 'f' * 40, stager, deadline())
            hashed.assert_not_called()
            linked.assert_not_called()

    def test_preflight_preserves_valid_inventory_bytes_and_existing_deadline(self):
        stager = M.load_module(HERE / 'protected-resident-model-workload.py', 'test_valid_preflight_stager')
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            raw = b'public bytes only'
            put(root / 'runtime/a', raw)
            (root / 'runtime/python').symlink_to('/usr/bin/python3.13')
            value = M.asset_inventory(root, 'f' * 40, stager, deadline())
            expected = dict(version=1, kind='protected-resident-public-workload', public_fixture_only=True,
                core_source_commit='f' * 40, entries={
                    'runtime/a': dict(kind='file', bytes=len(raw), sha256=hashlib.sha256(raw).hexdigest(),
                        executable=False),
                    'runtime/python': dict(kind='symlink', target='/usr/bin/python3.13')})
            self.assertEqual(M.encoded(value), M.encoded(expected))
            with mock.patch.object(stager, 'scan', return_value={'runtime/a'}), \
                    mock.patch.object(M, 'file_record') as hashed, \
                    self.assertRaisesRegex(ValueError, '^build_deadline$'):
                M.asset_inventory(root, 'f' * 40, stager, time.monotonic_ns() - 1)
            hashed.assert_not_called()

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
            parenthesized = 'runtime/lib/python3.13/site-packages/setuptools/script (dev).tmpl'
            public_template = b'public inert setuptools pathname fixture\n'
            original.put(parenthesized, public_template)
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
            with fixtures.tarfile.open(root / 'public-workload.tar') as archive:
                self.assertEqual(archive.extractfile('opt/volparossa/' + parenthesized).read(), public_template)

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


class BinaryPackageTests(unittest.TestCase):
    def fixture(self, directory):
        root = Path(directory)
        source = put(root / 'cargo-deps', public_elf() + b'public debug bytes', mode=0o700)
        alias = root / 'cargo-binary'
        os.link(source, alias)
        return source, alias, root / 'exported'

    def test_fixed_tool_original_deadline_independent_copy_and_replaced_inode(self):
        with tempfile.TemporaryDirectory() as directory:
            source, alias, output = self.fixture(directory)
            original, source_identity = source.read_bytes(), M.identity(source.stat())
            limit, copied_inode, copy_streams = deadline(), [], []
            real_fdopen = M.os.fdopen
            def observe_fdopen(*args, **kwargs):
                stream = real_fdopen(*args, **kwargs)
                copy_streams.append(stream)
                return stream
            def strip(argv, end, **kwargs):
                self.assertEqual(argv, ['/usr/bin/x86_64-linux-gnu-strip', '--strip-debug', '--', output])
                self.assertEqual((end, kwargs), (limit, {'cap': 300}))
                self.assertTrue(copy_streams)
                self.assertTrue(all(stream.closed for stream in copy_streams))
                self.assertEqual(output.stat().st_nlink, 1)
                self.assertEqual(output.stat().st_mode & 0o7777, 0o700)
                self.assertNotEqual(output.stat().st_ino, source.stat().st_ino)
                copied_inode.append(output.stat().st_ino)
                # GNU strip may replace its privately owned output inode.
                replacement = put(output.with_name('replacement'), public_elf(), mode=0o700)
                replacement.replace(output)
                return b''
            with mock.patch.object(M.os, 'fdopen', side_effect=observe_fdopen), \
                    mock.patch.object(M, 'command', side_effect=strip) as run:
                M.package_core_binary(alias, output, limit)
            run.assert_called_once()
            self.assertNotEqual(output.stat().st_ino, copied_inode[0])
            self.assertEqual(output.read_bytes(), public_elf())
            self.assertEqual(M.identity(source.stat()), source_identity)
            self.assertEqual(M.identity(alias.stat()), source_identity)
            self.assertEqual(source.read_bytes(), original)
            self.assertEqual(M.file_record(output, limit)['sha256'], hashlib.sha256(public_elf()).hexdigest())

    def test_copy_failure_or_existing_output_never_invokes_tool(self):
        for kind in ('existing', 'symlink', 'bad-input'):
            with self.subTest(kind=kind), tempfile.TemporaryDirectory() as directory:
                source, alias, output = self.fixture(directory)
                if kind == 'existing': put(output, b'original')
                if kind == 'symlink': output.symlink_to(source)
                if kind == 'bad-input': alias = put(Path(directory) / 'invalid', b'bad', mode=0o700)
                with mock.patch.object(M, 'command') as run, self.assertRaises((OSError, ValueError)):
                    M.package_core_binary(alias, output, deadline())
                run.assert_not_called()
                if kind == 'existing': self.assertEqual(output.read_bytes(), b'original')
                self.assertEqual(source.read_bytes(), public_elf() + b'public debug bytes')

    def test_original_tool_failure_and_cleanup_exception_propagate(self):
        for error in (ValueError('command_failed'), ValueError('build_deadline'),
                      M.CleanupUnconfirmed('command_cleanup'), InterruptedError('cancelled')):
            with self.subTest(error=type(error).__name__), tempfile.TemporaryDirectory() as directory:
                source, alias, output = self.fixture(directory)
                original = M.identity(source.stat())
                with mock.patch.object(M, 'command', side_effect=error), self.assertRaises(type(error)) as caught:
                    M.package_core_binary(alias, output, deadline())
                self.assertIs(caught.exception, error)
                self.assertEqual(M.identity(source.stat()), original)

    def test_post_tool_metadata_and_elf_rejections(self):
        for kind in ('oversize', 'short', 'mode', 'hardlink', 'symlink', 'directory', 'magic', 'machine', 'type'):
            with self.subTest(kind=kind), tempfile.TemporaryDirectory() as directory:
                source, alias, output = self.fixture(directory)
                before = M.identity(source.stat())
                def strip(*_args, **_kwargs):
                    if kind == 'oversize':
                        with output.open('r+b') as stream: stream.truncate(M.MAX_BOOT_CORE_BYTES + 1)
                    elif kind == 'short': output.write_bytes(public_elf()[:63])
                    elif kind == 'mode': output.chmod(0o750)
                    elif kind == 'hardlink': os.link(output, output.with_name('extra-link'))
                    elif kind in ('symlink', 'directory'):
                        output.unlink()
                        if kind == 'symlink': output.symlink_to(source)
                        else: output.mkdir(mode=0o700)
                    else:
                        raw = bytearray(public_elf())
                        raw[{'magic': 0, 'machine': 18, 'type': 16}[kind]] = 0
                        output.write_bytes(raw)
                    return b''
                with mock.patch.object(M, 'command', side_effect=strip), self.assertRaises((OSError, ValueError)):
                    M.package_core_binary(alias, output, deadline())
                self.assertEqual(M.identity(source.stat()), before)

    def test_exact_final_size_boundary_is_inclusive(self):
        with tempfile.TemporaryDirectory() as directory:
            _source, alias, output = self.fixture(directory)
            def strip(*_args, **_kwargs):
                output.write_bytes(public_elf() + b'X' * 64)
                return b''
            with mock.patch.object(M, 'MAX_BOOT_CORE_BYTES', 128), \
                    mock.patch.object(M, 'command', side_effect=strip):
                M.package_core_binary(alias, output, deadline())
            self.assertEqual(output.stat().st_size, 128)

    def test_post_tool_owner_rejected(self):
        with tempfile.TemporaryDirectory() as directory:
            source, alias, output = self.fixture(directory)
            def strip(*_args, **_kwargs):
                # Change the observed expected owner only after the original
                # copy's real owner checks, without privileged chown in tests.
                owner_patch.start()
                return b''
            owner_patch = mock.patch.object(M.os, 'getuid', return_value=os.getuid() + 1)
            try:
                with mock.patch.object(M, 'command', side_effect=strip), \
                        self.assertRaisesRegex(ValueError, '^core_binary_metadata$'):
                    M.package_core_binary(alias, output, deadline())
            finally:
                owner_patch.stop()

    def test_deadline_not_renewed_after_tool(self):
        with tempfile.TemporaryDirectory() as directory:
            _source, alias, output = self.fixture(directory)
            limit = deadline()
            def strip(*_args, **_kwargs):
                clock.start()
                return b''
            clock = mock.patch.object(M.time, 'monotonic_ns', return_value=limit + 1)
            try:
                with mock.patch.object(M, 'command', side_effect=strip), \
                        self.assertRaisesRegex(ValueError, '^build_deadline$'):
                    M.package_core_binary(alias, output, limit)
            finally:
                clock.stop()

    def test_post_open_content_and_path_mutation_fail_closed(self):
        for kind in ('growth', 'truncation', 'replacement'):
            with self.subTest(kind=kind), tempfile.TemporaryDirectory() as directory:
                source, alias, output = self.fixture(directory)
                original = M.identity(source.stat())
                real_fdopen = M.os.fdopen
                class MutatingReader:
                    def __init__(self, stream): self.stream, self.changed = stream, False
                    def __enter__(self): return self
                    def __exit__(self, *args): return self.stream.__exit__(*args)
                    def fileno(self): return self.stream.fileno()
                    def read(self, count):
                        raw = self.stream.read(count)
                        if not self.changed:
                            self.changed = True
                            if kind == 'replacement':
                                put(output.with_name('new-inode'), output.read_bytes(), mode=0o700).replace(output)
                            else:
                                with output.open('r+b') as writer:
                                    writer.truncate(output.stat().st_size + 1 if kind == 'growth' else 64)
                        return raw
                def fdopen(fd, mode):
                    stream = real_fdopen(fd, mode)
                    return MutatingReader(stream)
                def strip(*_args, **_kwargs):
                    reader_patch.start()
                    return b''
                reader_patch = mock.patch.object(M.os, 'fdopen', side_effect=fdopen)
                try:
                    with mock.patch.object(M, 'command', side_effect=strip), \
                            self.assertRaisesRegex(ValueError, '^core_binary_changed$'):
                        M.package_core_binary(alias, output, deadline())
                finally:
                    reader_patch.stop()
                self.assertEqual(M.identity(source.stat()), original)


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
                mock.patch.object(M, 'build_assets', return_value=(args.output/'binary', args.output/'native', {})), \
                mock.patch.object(M, 'validate_compiler_proof'), \
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
                    mock.patch.object(M, 'build_assets', side_effect=lambda *_: events.append('build') or (args.output/'binary', args.output/'native', {})), \
                    mock.patch.object(M, 'validate_compiler_proof'), \
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
