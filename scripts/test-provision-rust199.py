#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-only
"""Inert compiler authority, extraction and execution-location regression tests."""
import copy
import importlib.util
import io
import json
import hashlib
import signal
import shutil
import subprocess
import sys
import time
import os
from pathlib import Path
import tarfile
import tempfile
import unittest
from unittest.mock import patch, MagicMock

SPEC = importlib.util.spec_from_file_location('compiler', Path(__file__).with_name('provision-rust199.py'))
M = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(M)


def receipt():
    return dict(schema_version=1, profile=M.PROFILE, manifest_sha256=M.MANIFEST_SHA256,
                components=M.pins()['components'], observed_versions={
                    'rustc': 'rustc 1.99.1 (58cf8f9c3 2026-10-13)\nrelease: 1.99.1\n',
                    'cargo': 'cargo 1.99.1 (5f94df478 2026-08-27)\nrelease: 1.99.1\n',
                    'rustfmt': 'rustfmt 1.10.0 (fixture)\n',
                    'clippy-driver': 'clippy 0.1.99 (fixture)\n'})


class CompilerTests(unittest.TestCase):
    def test_six_reviewed_components_and_receipt(self):
        M.validate_receipt(receipt())
        self.assertEqual(len(M.pins()['components']), 6)
        self.assertEqual({c['target'] for c in M.pins()['components']},
                         {'x86_64-unknown-linux-gnu', 'i686-unknown-linux-musl'})

    def test_profile_archive_authority_and_observations_fail_closed(self):
        for mutation in ('profile', 'manifest', 'archive', 'missing', 'rustc', 'cargo', 'extra'):
            value = receipt()
            if mutation == 'profile': value['profile'] = 'stable'
            elif mutation == 'manifest': value['manifest_sha256'] = 'a' * 64
            elif mutation == 'archive': value['components'][0]['xz_sha256'] = 'b' * 64
            elif mutation == 'missing': value['components'].pop()
            elif mutation == 'extra': value['caller_expected_hash'] = 'c' * 64
            else: value['observed_versions'][mutation] = 'unreviewed compiler\n'
            with self.subTest(mutation=mutation), self.assertRaises(ValueError):
                M.validate_receipt(value)

    def test_manifest_cargo_version_is_not_assumed_to_be_executable_version(self):
        self.assertTrue(M.pins()['components'][1]['version'].startswith('0.100.0'))
        M.validate_receipt(receipt())

    def test_host_rejected_before_network_or_installation(self):
        with patch.dict(os.environ, {}, clear=True), \
             patch.object(M.urllib.request, 'urlopen', side_effect=AssertionError('network')), \
             patch.object(M.subprocess, 'run', side_effect=AssertionError('execution')), \
             patch.object(M.subprocess, 'check_output', return_value='none\n'):
            with self.assertRaises(ValueError): M.provision('runner')
            with self.assertRaises(ValueError): M.provision('guest')

    def test_archive_mismatch_rejected(self):
        component = M.pins()['components'][0]
        response = io.BytesIO(b'not the reviewed compiler')
        response.geturl = lambda: component['xz_url']
        with tempfile.TemporaryDirectory() as directory, \
             patch.object(M.urllib.request, 'urlopen', return_value=response):
            with self.assertRaisesRegex(ValueError, 'digest'):
                M.download(component, Path(directory) / 'archive')

    def test_unsafe_archive_paths_and_links_rejected(self):
        for name, link in [('../escape', None), ('/escape', None), ('root/link', '/escape')]:
            with self.subTest(name=name), tempfile.TemporaryDirectory() as directory:
                archive = Path(directory) / 'input.tar'
                with tarfile.open(archive, 'w') as output:
                    member = tarfile.TarInfo(name)
                    if link:
                        member.type = tarfile.SYMTYPE
                        member.linkname = link
                    output.addfile(member)
                with self.assertRaises((ValueError, tarfile.TarError)):
                    M.extract(archive, Path(directory) / 'out')

    def test_existing_prefix_is_not_replaced_or_deleted_on_bad_receipt(self):
        with tempfile.TemporaryDirectory() as directory:
            prefix = Path(directory) / M.PREFIX_NAME
            prefix.mkdir(); (prefix / 'receipt.json').write_text('{}')
            with patch.object(M, 'location', return_value=prefix), \
                 patch.object(M, 'download', side_effect=AssertionError('network')):
                with self.assertRaises(ValueError): M.provision('runner')
            self.assertTrue(prefix.is_dir())

    def test_interrupted_installer_keeps_leader_until_descendants_stop(self):
        child = MagicMock(pid=4242)
        with patch.object(M.subprocess, 'Popen', return_value=child), \
             patch.object(M, 'wait_for_leader', side_effect=KeyboardInterrupt()), \
             patch.object(M, 'group_running', side_effect=[True, False, False]), \
             patch.object(M.os, 'killpg') as kill:
            with self.assertRaises(KeyboardInterrupt):
                M.install_component(Path('/inert/source'), Path('/inert/prefix'))
        self.assertEqual([c.args[1] for c in kill.call_args_list], [signal.SIGTERM, signal.SIGKILL])
        child.wait.assert_called_once_with(timeout=5)

    def test_successful_leader_is_not_reaped_before_group_cleanup(self):
        child = subprocess.Popen([sys.executable, '-c', 'pass'], start_new_session=True)
        try:
            result = M.wait_for_leader(child, 5)
            self.assertEqual(result.si_code, os.CLD_EXITED)
            self.assertEqual(result.si_status, 0)
            self.assertIsNone(child.returncode)
            # WNOWAIT kept the actual zombie available and its PID reserved.
            self.assertEqual(os.waitid(os.P_PID, child.pid, os.WEXITED | os.WNOWAIT).si_pid, child.pid)
            M.finish_group(child)
            self.assertEqual(child.returncode, 0)
        finally:
            if child.returncode is None:
                os.killpg(child.pid, signal.SIGKILL); child.wait()

    def test_live_descendant_requires_kill_even_after_leader_exits(self):
        child = MagicMock(pid=4242)
        def group(group):
            child.wait.assert_not_called()  # PID identity remains held.
            return kill.call_count < 2
        with patch.object(M.os, 'killpg') as kill, patch.object(M, 'group_running', side_effect=group):
            M.finish_group(child, grace=0)
        self.assertEqual(kill.call_args_list, [unittest.mock.call(4242, signal.SIGTERM),
                                             unittest.mock.call(4242, signal.SIGKILL)])
        child.wait.assert_called_once()

    def test_uncertain_group_keeps_leader_and_install_files(self):
        child = MagicMock(pid=4242)
        with patch.object(M.os, 'killpg'), patch.object(M, 'group_running', return_value=True):
            with self.assertRaises(M.CleanupUnconfirmed): M.finish_group(child, grace=0)
        child.wait.assert_not_called()
        with tempfile.TemporaryDirectory() as directory:
            prefix = Path(directory) / 'prefix'
            def installer(source, target):
                (target / 'owned-payload').write_bytes(b'retain')
                raise M.CleanupUnconfirmed('inert surviving descendant model')
            with patch.object(M, 'location', return_value=prefix), \
                 patch.object(M, 'download', side_effect=lambda c, p: p.write_bytes(b'archive')), \
                 patch.object(M, 'extract', return_value=Path('/inert')), \
                 patch.object(M, 'install_component', side_effect=installer):
                with self.assertRaises(M.CleanupUnconfirmed): M.provision('guest')
            self.assertEqual((prefix / 'owned-payload').read_bytes(), b'retain')
            self.assertEqual(len(list(Path(directory).glob('rust199-components-*'))), 1)

    def test_real_harmless_term_resistant_descendant_is_stopped(self):
        # This runs only installed Python and a harmless sleep loop, never a
        # compiler/archive installer. Linux subreaper lets this test reap its
        # orphaned grandchild without relying on the host's PID1.
        import ctypes
        libc = ctypes.CDLL(None, use_errno=True)
        old = ctypes.c_int()
        self.assertEqual(libc.prctl(37, ctypes.byref(old), 0, 0, 0), 0)  # GET_CHILD_SUBREAPER
        self.assertEqual(libc.prctl(36, 1, 0, 0, 0), 0)
        child = None
        descendant = None
        try:
            with tempfile.TemporaryDirectory() as directory:
                marker = Path(directory) / 'ready'
                code = ("import os,signal,time; p=os.fork(); "
                        "\nif p == 0:\n signal.signal(signal.SIGTERM,signal.SIG_IGN); "
                        "open(" + repr(str(marker)) + ",'w').write(str(os.getpid())); "
                        "time.sleep(60)\nelse: time.sleep(60)\n")
                child = subprocess.Popen([sys.executable, '-c', code], start_new_session=True)
                deadline = time.monotonic() + 5
                while time.monotonic() < deadline:
                    if marker.exists() and marker.read_text().isdigit():
                        break
                    time.sleep(0.01)
                self.assertTrue(marker.exists())
                descendant = int(marker.read_text())
                with patch.object(M.os, 'killpg', wraps=os.killpg) as kill:
                    M.finish_group(child, grace=0.2)
                self.assertEqual([c.args[1] for c in kill.call_args_list], [signal.SIGTERM, signal.SIGKILL])
                self.assertIsNotNone(child.returncode)
                pid, status = os.waitpid(descendant, 0)
                self.assertEqual(pid, descendant)
                self.assertEqual(os.waitstatus_to_exitcode(status), -signal.SIGKILL)
                descendant = None
        finally:
            if child is not None:
                try: os.killpg(child.pid, signal.SIGKILL)
                except ProcessLookupError: pass
                child.wait()
            if descendant is not None:
                try: os.waitpid(descendant, 0)
                except ChildProcessError: pass
            libc.prctl(36, old.value, 0, 0, 0)

    def test_offline_guest_check_never_installs_missing_compiler(self):
        with tempfile.TemporaryDirectory() as directory, \
             patch.object(M, 'location', return_value=Path(directory) / 'absent'), \
             patch.object(M, 'download', side_effect=AssertionError('network')):
            with self.assertRaisesRegex(ValueError, 'not been provisioned'):
                M.provision('guest-check')


def fixture(prefix):
    """Tiny installer-v3 archives and their copied data, never executable tools."""
    metadata = copy.deepcopy(M.pins())
    archives = prefix / '.component-archives'
    archives.mkdir(parents=True, mode=0o700)
    prefix.chmod(0o700)
    all_files = [
        {'bin/rustc': b'official inert rustc', 'lib/librustc.so': b'runtime'},
        {'bin/cargo': b'official inert cargo'},
        {'lib/rustlib/x86_64-unknown-linux-gnu/lib/libstd.rlib': b'std amd64'},
        {'lib/rustlib/i686-unknown-linux-musl/lib/libstd.rlib': b'std i686'},
        {'bin/clippy-driver': b'official inert clippy'},
        {'bin/rustfmt': b'official inert rustfmt'}]
    names = []
    for index, payload in enumerate(all_files):
        name = 'component-' + str(index); names.append(name)
        manifest = ''.join('file:' + path + '\n' for path in payload).encode()
        files = {'root/components': (name + '\n').encode(),
                 'root/rust-installer-version': b'3\n', 'root/install.sh': b'# inert installer data\n',
                 'root/' + name + '/manifest.in': manifest}
        files.update({'root/' + name + '/' + path: value for path, value in payload.items()})
        archive = archives / f'{index}.tar.xz'
        with tarfile.open(archive, 'w:xz') as output:
            for path, value in files.items():
                member = tarfile.TarInfo(path); member.size = len(value)
                member.mode = 0o755 if '/bin/' in path or path == 'root/install.sh' else 0o644
                output.addfile(member, io.BytesIO(value))
        metadata['components'][index]['xz_sha256'] = hashlib.sha256(archive.read_bytes()).hexdigest()
        for path, value in payload.items():
            destination = prefix / path; destination.parent.mkdir(parents=True, exist_ok=True)
            destination.write_bytes(value); destination.chmod(0o755 if path.startswith('bin/') else 0o644)
        admin = prefix / 'lib/rustlib'; admin.mkdir(parents=True, exist_ok=True)
        (admin / ('manifest-' + name)).write_text(''.join('file:' + str(prefix / path) + '\n' for path in payload))
    (admin / 'components').write_text(''.join(name + '\n' for name in names))
    (admin / 'rust-installer-version').write_bytes(b'3\n')
    (admin / 'uninstall.sh').write_bytes(b'# inert installer data\n'); (admin / 'uninstall.sh').chmod(0o755)
    (admin / 'install.log').write_bytes(b'inert log')
    value = receipt(); value['components'] = metadata['components']
    (prefix / 'receipt.json').write_text(json.dumps(value))
    for path in prefix.rglob('*'):
        path.chmod(0o755 if path.is_dir() or path.stat().st_mode & 0o111 else 0o644)
    return metadata, value


class PayloadTests(unittest.TestCase):
    def test_authenticated_complete_inert_payload_can_be_reused(self):
        with tempfile.TemporaryDirectory() as directory:
            prefix = Path(directory) / 'prefix'; metadata, value = fixture(prefix)
            with patch.object(M, 'location', return_value=prefix), patch.object(M, 'pins', return_value=metadata), \
                 patch.object(M, 'observe', return_value=value['observed_versions']) as observe, \
                 patch.object(M, 'download', side_effect=AssertionError('offline')):
                self.assertEqual(M.provision('guest-check'), prefix)
                observe.assert_called_once()

    def test_spoofed_executable_library_std_or_archive_never_reaches_observe(self):
        for mutation in ('executable', 'library', 'std64', 'std32', 'archive', 'extra',
                         'symlink', 'hardlink', 'directory-link', 'missing', 'executable-log', 'setuid'):
            with self.subTest(mutation=mutation), tempfile.TemporaryDirectory() as directory:
                prefix = Path(directory) / 'prefix'; metadata, _ = fixture(prefix)
                if mutation == 'executable': (prefix / 'bin/rustc').write_bytes(b'#!/bin/sh\necho rustc 1.99.1\n')
                elif mutation == 'library': (prefix / 'lib/librustc.so').write_bytes(b'arbitrary runtime')
                elif mutation.startswith('std'):
                    target = 'x86_64-unknown-linux-gnu' if mutation == 'std64' else 'i686-unknown-linux-musl'
                    (prefix / 'lib/rustlib' / target / 'lib/libstd.rlib').write_bytes(b'arbitrary std')
                elif mutation == 'archive': (prefix / '.component-archives/0.tar.xz').write_bytes(b'changed authority')
                elif mutation == 'extra': (prefix / 'lib/libinjected.so').write_bytes(b'extra loader payload')
                elif mutation == 'symlink':
                    path = prefix / 'bin/rustc'; path.unlink(); path.symlink_to('cargo')
                elif mutation == 'hardlink': os.link(prefix / 'bin/rustc', Path(directory) / 'alias')
                elif mutation == 'directory-link':
                    shutil.move(prefix / 'bin', Path(directory) / 'outside'); (prefix / 'bin').symlink_to(Path(directory) / 'outside')
                elif mutation == 'missing': (prefix / 'bin/rustc').unlink()
                elif mutation == 'setuid': (prefix / 'bin/rustc').chmod(0o4755)
                elif mutation == 'executable-log': (prefix / 'lib/rustlib/install.log').chmod(0o755)
                with patch.object(M, 'location', return_value=prefix), patch.object(M, 'pins', return_value=metadata), \
                     patch.object(M, 'observe', side_effect=AssertionError('unverified execution')) as observe, \
                     patch.object(M, 'download', side_effect=AssertionError('offline')):
                    with self.assertRaises((ValueError, OSError)): M.provision('guest-check')
                    observe.assert_not_called()
                self.assertTrue(prefix.exists())

    def test_original_spoof_without_archives_is_rejected_before_execution(self):
        with tempfile.TemporaryDirectory() as directory:
            prefix = Path(directory); (prefix / 'receipt.json').write_text(json.dumps(receipt()))
            (prefix / 'bin').mkdir(); (prefix / 'bin/rustc').write_bytes(b'version spoof')
            with patch.object(M, 'location', return_value=prefix), \
                 patch.object(M, 'observe', side_effect=AssertionError('execution')) as observe:
                with self.assertRaisesRegex(ValueError, 'archives'): M.provision('guest-check')
                observe.assert_not_called()

    def test_fresh_install_checks_payload_before_observation(self):
        with tempfile.TemporaryDirectory() as directory:
            prefix = Path(directory) / 'prefix'
            calls = []
            def reject(target, metadata):
                calls.append('verify'); raise ValueError('corrupt fresh installation')
            with patch.object(M, 'location', return_value=prefix), \
                 patch.object(M, 'download', side_effect=lambda c, p: p.write_bytes(b'inert')), \
                 patch.object(M, 'extract', return_value=Path('/inert')), \
                 patch.object(M, 'install_component'), patch.object(M, 'verify_payload', side_effect=reject), \
                 patch.object(M, 'observe', side_effect=AssertionError('unverified execution')) as observe:
                with self.assertRaisesRegex(ValueError, 'corrupt fresh'): M.provision('guest')
                observe.assert_not_called()
            self.assertEqual(calls, ['verify'])
            self.assertFalse(prefix.exists())
            self.assertFalse(list(Path(directory).glob('rust199-components-*')))

if __name__ == '__main__': unittest.main()
