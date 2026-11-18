#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-only
"""Inert pidfd/shutdown checks; no QEMU, VM, network or privileged operations."""
import importlib.util
import io
import os
from pathlib import Path
import re
import select
import signal
import subprocess
import sys
import tempfile
import time
import unittest
from unittest import mock

HERE = Path(__file__).resolve().parent
SPEC = importlib.util.spec_from_file_location('qemu_child_lifecycle', HERE / 'qemu-child-lifecycle.py')
M = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(M)
SOURCE = (HERE / 'run-alpha-topology-vm.sh').read_text()


class SyntheticLifecycle(unittest.TestCase):
    def setUp(self):
        for name, value in [('identity', (11, 22)), ('exited', False)]:
            patcher = mock.patch.object(M, name, return_value=value)
            setattr(self, name, patcher.start())
            self.addCleanup(patcher.stop)
        for name, value in [('pidfd_open', 99), ('close', None)]:
            patcher = mock.patch.object(M.os, name, return_value=value)
            setattr(self, name, patcher.start())
            self.addCleanup(patcher.stop)
        patcher = mock.patch.object(M.signal, 'pidfd_send_signal')
        self.send = patcher.start()
        self.addCleanup(patcher.stop)

    def test_graceful_exit_has_no_signal(self):
        self.exited.return_value = True
        self.assertTrue(M.stop(10, 11, 22, graceful=True))
        self.exited.assert_called_once_with(99, 30)
        self.send.assert_not_called()
        self.close.assert_called_once_with(99)

    def test_term_then_exit(self):
        self.exited.side_effect = [False, True]
        self.assertTrue(M.stop(10, 11, 22, graceful=True))
        self.assertEqual(self.exited.call_args_list, [mock.call(99, 30), mock.call(99, 5)])
        self.send.assert_called_once_with(99, signal.SIGTERM)

    def test_kill_then_exit(self):
        self.exited.side_effect = [False, False, True]
        self.assertTrue(M.stop(10, 11, 22, graceful=False))
        self.assertEqual(self.exited.call_args_list, [mock.call(99, 0), mock.call(99, 5), mock.call(99, 5)])
        self.assertEqual(self.send.call_args_list, [mock.call(99, signal.SIGTERM), mock.call(99, signal.SIGKILL)])

    def test_unkillable_is_finite_failure(self):
        self.assertFalse(M.stop(10, 11, 22, graceful=True))
        self.assertEqual(self.exited.call_count, 3)
        self.assertEqual(self.send.call_count, 2)
        self.close.assert_called_once_with(99)

    def test_reused_pid_or_wrong_parent_never_receives_signal(self):
        for value in [(11, 23), (12, 22)]:
            with self.subTest(value=value):
                self.identity.return_value = value
                with self.assertRaises(ValueError):
                    M.stop(10, 11, 22, graceful=False)
                self.pidfd_open.assert_not_called()
                self.send.assert_not_called()

    def test_reuse_between_identity_and_pidfd_is_rejected(self):
        self.identity.side_effect = [(11, 22), (11, 23)]
        with self.assertRaises(ValueError):
            M.stop(10, 11, 22, graceful=False)
        self.send.assert_not_called()
        self.close.assert_called_once_with(99)

    def test_exit_races_are_observed_not_signalled_by_pid(self):
        self.identity.side_effect = FileNotFoundError()
        self.assertTrue(M.stop(10, 11, 22, graceful=False))
        self.send.assert_not_called()
        self.identity.side_effect = [(11, 22), FileNotFoundError()]
        self.exited.return_value = True
        self.assertTrue(M.stop(10, 11, 22, graceful=False))
        self.exited.assert_called_once_with(99, 5)
        self.send.assert_not_called()

    def test_unavailable_observer_does_not_signal(self):
        self.identity.side_effect = PermissionError()
        with self.assertRaises(PermissionError):
            M.stop(10, 11, 22, graceful=True)
        self.send.assert_not_called()
        self.identity.side_effect = None
        self.pidfd_open.side_effect = OSError()
        with self.assertRaises(OSError):
            M.stop(10, 11, 22, graceful=True)
        self.send.assert_not_called()

    def test_birth_rejects_foreign_reused_or_changed_child(self):
        with mock.patch.object(M, 'qemu_command') as command:
            self.assertEqual(M.birth(10, 11), 22)
            command.assert_called_once_with(10)
            self.identity.side_effect = [(11, 22), (11, 23)]
            with self.assertRaises(ValueError):
                M.birth(10, 11)
            self.identity.side_effect = [(12, 22)]
            with self.assertRaises(ValueError):
                M.birth(10, 11)

    def test_birth_waits_for_delayed_exec_without_changing_identity(self):
        with mock.patch.object(M, 'qemu_command', side_effect=[ValueError('command'), None]) as command, \
                mock.patch.object(M.time, 'monotonic', side_effect=[0, .1, .2]), \
                mock.patch.object(M.time, 'sleep') as sleep:
            self.assertEqual(M.birth(10, 11), 22)
            self.assertEqual(command.call_args_list, [mock.call(10), mock.call(10)])
            self.assertEqual(self.identity.call_count, 5)
            sleep.assert_called_once_with(.01)
            self.send.assert_not_called()

    def test_birth_identity_change_during_exec_wait_fails_closed(self):
        self.identity.side_effect = [(11, 22), (11, 22), (11, 22), (11, 23)]
        with mock.patch.object(M, 'qemu_command', side_effect=ValueError('command')) as command, \
                mock.patch.object(M.time, 'monotonic', return_value=0), \
                mock.patch.object(M.time, 'sleep'):
            with self.assertRaises(ValueError):
                M.birth(10, 11)
            command.assert_called_once_with(10)
            self.send.assert_not_called()

    def test_birth_wrong_argv_exhausts_only_original_two_second_bound(self):
        with mock.patch.object(M, 'qemu_command', side_effect=ValueError('command')) as command, \
                mock.patch.object(M.time, 'monotonic', side_effect=[0, .5, 2]), \
                mock.patch.object(M.time, 'sleep') as sleep:
            with self.assertRaises(ValueError):
                M.birth(10, 11)
            self.assertEqual(command.call_count, 2)
            sleep.assert_called_once_with(.01)
            self.send.assert_not_called()

    def test_birth_ready_only_after_deadline_is_not_admitted(self):
        with mock.patch.object(M, 'qemu_command'), \
                mock.patch.object(M.time, 'monotonic', side_effect=[0, 2.01]):
            with self.assertRaises(ValueError):
                M.birth(10, 11)
            self.send.assert_not_called()

    def test_qemu_command_accepts_reviewed_loader_prefix_not_other_sibling(self):
        suffix = b'\0-name\0volparossa-alpha-topology\0-no-user-config\0-nodefaults\0'
        prefixes = (b'/usr/bin/qemu-system-x86_64',
            b'/bin/sh\0/private/bin/qemu-system-x86_64',
            b'/lib/ld-linux-x86-64.so.2\0--library-path\0/private/lib\0/private/usr/bin/qemu-system-x86_64')
        for prefix in prefixes:
            with self.subTest(prefix=prefix), mock.patch.object(M.Path, 'open', return_value=io.BytesIO(prefix + suffix)):
                M.qemu_command(10)
        for raw in (b'python3\0birth\010\011\0', prefixes[0] + suffix.replace(b'alpha-topology', b'other'),
                    prefixes[0] + suffix[:-1], b'x' * 32768 + b'\0'):
            with self.subTest(raw_length=len(raw)), mock.patch.object(M.Path, 'open', return_value=io.BytesIO(raw)):
                with self.assertRaises(ValueError):
                    M.qemu_command(10)


@unittest.skipUnless(hasattr(os, 'pidfd_open') and hasattr(signal, 'pidfd_send_signal'), 'Linux pidfd unavailable')
class HarmlessRealChildren(unittest.TestCase):
    def ready(self, pipe, seconds=2):
        descriptor = pipe.fileno()
        os.set_blocking(descriptor, False)
        poller = select.poll()
        poller.register(descriptor, select.POLLIN | select.POLLHUP)
        deadline, observed = time.monotonic() + seconds, b''
        while len(observed) < 7 and not observed.endswith(b'\n'):
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                break
            if not poller.poll(max(1, int(remaining * 1000))):
                continue
            try:
                data = os.read(descriptor, 7 - len(observed))
            except BlockingIOError:
                continue
            if not data:
                break
            observed += data
        self.assertEqual(observed, b'ready\n', 'child readiness was not confirmed within its bound')

    def child(self, ignore_term=False):
        code = ('import signal,sys; ' +
                ('signal.signal(signal.SIGTERM, signal.SIG_IGN); ' if ignore_term else '') +
                'print("ready", flush=True); sys.stdin.read(1)')
        child = subprocess.Popen([sys.executable, '-B', '-c', code], stdin=subprocess.PIPE,
            stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        def cleanup():
            if child.poll() is None:
                child.kill()
            child.wait(timeout=3)
            for pipe in (child.stdin, child.stdout, child.stderr):
                pipe.close()
        self.addCleanup(cleanup)
        self.ready(child.stdout)
        parent, started = M.identity(child.pid)
        self.assertEqual(parent, os.getpid())
        return child, started

    def test_actual_pidfd_preflight_and_graceful_child(self):
        M.preflight()
        child, started = self.child()
        child.stdin.write(b'x')
        child.stdin.flush()
        self.assertTrue(M.stop(child.pid, os.getpid(), started, graceful=True))
        self.assertEqual(child.wait(timeout=1), 0)

    def test_actual_term_and_already_reaped_child(self):
        child, started = self.child()
        self.assertTrue(M.stop(child.pid, os.getpid(), started, graceful=False))
        self.assertEqual(child.wait(timeout=1), -signal.SIGTERM)
        self.assertTrue(M.stop(child.pid, os.getpid(), started, graceful=False))

    def test_actual_term_ignoring_child_is_killed(self):
        child, started = self.child(ignore_term=True)
        with mock.patch.object(M, 'TERM_SECONDS', .03):
            self.assertTrue(M.stop(child.pid, os.getpid(), started, graceful=False))
        self.assertEqual(child.wait(timeout=1), -signal.SIGKILL)

    def test_wrong_birth_and_parent_leave_actual_child_alive(self):
        child, started = self.child()
        for parent, birth in [(os.getpid() + 1, started), (os.getpid(), started + 1)]:
            with self.subTest(parent=parent, birth=birth), self.assertRaises(ValueError):
                M.stop(child.pid, parent, birth, graceful=False)
            self.assertIsNone(child.poll())

    def test_partial_or_missing_readiness_cannot_hang(self):
        for prefix in (b'', b'rea'):
            read_fd, write_fd = os.pipe()
            try:
                if prefix:
                    os.write(write_fd, prefix)
                with os.fdopen(read_fd, 'rb') as reader, self.assertRaises(AssertionError):
                    self.ready(reader, seconds=.01)
            finally:
                os.close(write_fd)


class ShellShutdownWiring(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory(prefix='volparossa-qemu-lifecycle-')
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        self.scratch = self.root / 'qemu.ABCdef'
        self.scratch.mkdir()
        self.functions = '\n'.join(re.search(r'^' + name + r'\(\) \{\n.*?^\}', SOURCE,
            re.MULTILINE | re.DOTALL).group() for name in ('stop_qemu_child', 'cleanup'))

    def run_script(self, status, confirmed, *, normal=False, started=True):
        script = '\n'.join([
            'set -eu', 'scenario=alpha', 'HERE=/inert', 'RUN_DIRECTORY_PARENT=$1', 'RUN_DIRECTORY_PREFIX=qemu',
            'RUN_DIRECTORY=$1/qemu.ABCdef', 'output_directory=$1', 'FINISHED=no',
            'WEATHER_ANDROID_OWNER_PID=', 'weather_client_version=',
            'QEMU_STARTED=' + ('yes' if started else 'no'), 'QEMU_JOINED=no',
            'QEMU_PID=' + ('123' if started else ''), 'QEMU_BIRTH=456', 'QEMU_STOP_ATTEMPTED=no',
            'timeout() { printf "probe\\n" >>"$output_directory/probes"; return ' + ('0' if confirmed else '1') + '; }',
            'wait() { printf "reap\\n" >>"$output_directory/reaps"; return 7; }',
            self.functions, 'trap cleanup EXIT',
            'GUEST_STATUS=' + str(status),
            ('if ! stop_qemu_child normal; then [ "$GUEST_STATUS" -ne 0 ] || GUEST_STATUS=1; fi' if normal else ':'),
            'exit "$GUEST_STATUS"',
        ])
        return subprocess.run(['sh', '-c', script, 'inert', str(self.root)], capture_output=True, timeout=3)

    def test_normal_join_reaps_once_and_preserves_guest_failure(self):
        result = self.run_script(7, True, normal=True)
        self.assertEqual(result.returncode, 7, result.stderr)
        self.assertEqual((self.root / 'probes').read_text(), 'probe\n')
        self.assertEqual((self.root / 'reaps').read_text(), 'reap\n')
        self.assertFalse(self.scratch.exists())

    def test_unconfirmed_join_retains_scratch_and_never_waits_or_retries(self):
        for status in (0, 7):
            with self.subTest(status=status):
                result = self.run_script(status, False, normal=True)
                self.assertEqual(result.returncode, status or 1, result.stderr)
                self.assertTrue(self.scratch.exists())
                self.assertFalse((self.root / 'reaps').exists())
        self.assertEqual((self.root / 'probes').read_text(), 'probe\nprobe\n')

    def test_abort_trap_preserves_status_and_uses_same_bound(self):
        result = self.run_script(143, True)
        self.assertEqual(result.returncode, 143, result.stderr)
        self.assertEqual((self.root / 'probes').read_text(), 'probe\n')
        self.assertFalse(self.scratch.exists())

    def test_prelaunch_cleanup_never_calls_process_observer(self):
        result = self.run_script(1, False, started=False)
        self.assertEqual(result.returncode, 1, result.stderr)
        self.assertFalse((self.root / 'probes').exists())
        self.assertFalse(self.scratch.exists())

    def test_real_shell_has_no_unconfirmed_qemu_wait_or_numeric_signal(self):
        self.assertEqual(SOURCE.count('wait "$QEMU_PID"'), 1)
        self.assertNotIn('kill -TERM "$QEMU_PID"', SOURCE)
        self.assertNotIn('kill -KILL "$QEMU_PID"', SOURCE)
        self.assertIn('ssh_bounded 15s sudo -n systemctl poweroff', SOURCE)
        self.assertLess(SOURCE.index('qemu-child-lifecycle.py" preflight'), SOURCE.index('\nqemu-system-x86_64 \\\n'))
        self.assertIn('qemu-child-lifecycle.py" birth "$QEMU_PID" "$$"', SOURCE)
        result = subprocess.run(['sh', '-n', str(HERE / 'run-alpha-topology-vm.sh')], capture_output=True, timeout=3)
        self.assertEqual(result.returncode, 0, result.stderr)

    @unittest.skipUnless(hasattr(os, 'pidfd_open') and hasattr(signal, 'pidfd_send_signal'), 'Linux pidfd unavailable')
    def test_real_shell_reaps_its_harmless_child_after_pidfd_confirmation(self):
        # This exercises the actual shell/helper boundary, not QEMU. Obtain the
        # birth token from kernel state directly because the child is deliberately
        # Python, not the source-owned QEMU launch checked by the production CLI.
        function = re.search(r'^stop_qemu_child\(\) \{\n.*?^\}', SOURCE,
            re.MULTILINE | re.DOTALL).group()
        script = '\n'.join([
            'set -eu', 'HERE=$1', 'QEMU_STOP_ATTEMPTED=no',
            'python3 -B -c "import time; time.sleep(3)" &', 'QEMU_PID=$!',
            'QEMU_BIRTH=$(python3 -B -c \'import runpy,sys; print(runpy.run_path(sys.argv[1])["identity"](int(sys.argv[2]))[1])\' "$HERE/qemu-child-lifecycle.py" "$QEMU_PID")',
            function, 'stop_qemu_child abort', 'test -z "$QEMU_PID"',
            'test "$QEMU_STOP_ATTEMPTED" = yes', 'stop_qemu_child abort',
        ])
        result = subprocess.run(['sh', '-c', script, 'inert', str(HERE)], capture_output=True, timeout=5)
        self.assertEqual(result.returncode, 0, result.stderr)


if __name__ == '__main__':
    unittest.main()
