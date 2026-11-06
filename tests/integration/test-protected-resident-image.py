#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-only
"""Inert image/boot contract tests: no image tools, downloads, models or VMs."""
import hashlib
from contextlib import nullcontext
import importlib.util
import io
import json
import os
from pathlib import Path
import signal
import stat
import sys
import tarfile
import tempfile
import time
import unittest
from unittest import mock
from types import SimpleNamespace

HERE = Path(__file__).resolve().parent
SPEC = importlib.util.spec_from_file_location('protected_resident_image',
                                              HERE / 'protected-resident-image.py')
M = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(M)


def receipt(outcome='boot_verified'):
    okay = outcome == 'boot_verified'
    return dict(version=1, outcome=outcome, stage='complete' if okay else 'verity_read',
                verity_verified=okay, root_readonly=okay, write_denied=okay,
                entrypoint_invoked=okay, hardware_attestation=False, private_inputs=False,
                model_execution=False, worker_execution=False)


def encoded(value):
    return M.PREFIX + json.dumps(value, sort_keys=True).encode() + b'\n'


def launch_receipt():
    return dict(version=1, scope='execute_process', same_unprivileged_uid=True,
                primary_kvm_group_verified=True, device_group_access_verified=True,
                supplementary_groups_cleared=True, capabilities_cleared=True, no_new_privileges=True)


class InputContracts(unittest.TestCase):
    def test_redirect_allows_only_exact_mirror_resource_and_existing_origins(self):
        path = '/images/cloud/trixie/20260826-2582/debian-13-genericcloud-amd64-20260826-2582.qcow2'
        source = M.urllib.request.Request('https://cloud.debian.org' + path)
        for host in ('saimei.ftp.acc.umu.se', 'saimei.ftp.acc.umu.se:443',
                     'cloud.debian.org', 'deb.debian.org'):
            with self.subTest(host=host):
                target = 'https://' + host + path
                redirect = M.PinnedRedirect().redirect_request(source, None, 302, '', {}, target)
                self.assertEqual(redirect.full_url, target)

    def test_redirect_rejects_changed_path_query_and_fragment(self):
        source = M.urllib.request.Request('https://cloud.debian.org/images/pinned.qcow2')
        for suffix in ('/images/other.qcow2', '/images/pinned.qcow2?changed=1',
                       '/images/pinned.qcow2#fragment', '/images/../pinned.qcow2'):
            with self.subTest(suffix=suffix), self.assertRaisesRegex(ValueError, 'download_redirect'):
                M.PinnedRedirect().redirect_request(source, None, 302, '', {},
                                                    'https://saimei.ftp.acc.umu.se' + suffix)

    def test_redirect_rejects_untrusted_host_transport_credentials_and_port(self):
        source = M.urllib.request.Request('https://cloud.debian.org/images/pinned.qcow2')
        for prefix in ('http://saimei.ftp.acc.umu.se', 'https://unreviewed.ftp.acc.umu.se',
                       'https://saimei.ftp.acc.umu.se.attacker.invalid', 'https://attacker.invalid',
                       'https://user@saimei.ftp.acc.umu.se', 'https://@saimei.ftp.acc.umu.se',
                       'https://user:password@saimei.ftp.acc.umu.se',
                       'https://saimei.ftp.acc.umu.se:444'):
            with self.subTest(prefix=prefix), self.assertRaisesRegex(ValueError, 'download_redirect'):
                M.PinnedRedirect().redirect_request(source, None, 302, '', {},
                                                    prefix + '/images/pinned.qcow2')
        package = M.urllib.request.Request('https://deb.debian.org/images/pinned.qcow2')
        with self.assertRaisesRegex(ValueError, 'download_redirect'):
            M.PinnedRedirect().redirect_request(package, None, 302, '', {},
                'https://saimei.ftp.acc.umu.se/images/pinned.qcow2')

    def test_redirect_does_not_bypass_download_digest_size_or_deadline(self):
        payload = b'public pinned bytes'
        item = dict(url='https://cloud.debian.org/images/pinned.qcow2', bytes=len(payload),
                    sha256=hashlib.sha256(payload).hexdigest())
        def open_public(handler, *_args, **_kwargs):
            source = M.urllib.request.Request(item['url'])
            handler.redirect_request(source, None, 302, '', {},
                'https://saimei.ftp.acc.umu.se/images/pinned.qcow2')
            result = io.BytesIO(payload)
            result.status = 200
            return result
        def opener(handler):
            return SimpleNamespace(open=lambda *args, **kwargs: open_public(handler, *args, **kwargs))
        with tempfile.TemporaryDirectory() as directory, \
                mock.patch.object(M.urllib.request, 'build_opener', side_effect=opener):
            target = Path(directory) / 'good'
            M.fetch(item, target, 'sha256', len(payload), time.monotonic() + 5)
            self.assertEqual(target.read_bytes(), payload)
            for index, (changed, maximum, deadline, reason) in enumerate((
                    ({**item, 'sha256': '0' * 64}, len(payload), time.monotonic() + 5, 'download_digest'),
                    ({**item, 'bytes': len(payload) + 1}, len(payload), time.monotonic() + 5, 'download_digest'),
                    (item, len(payload) - 1, time.monotonic() + 5, 'download_bound'),
                    (item, len(payload), time.monotonic() - 1, 'build_deadline'))):
                with self.subTest(reason=reason), self.assertRaisesRegex(ValueError, reason):
                    M.fetch(changed, Path(directory) / str(index), 'sha256', maximum, deadline)

    def test_existing_debian_manifest_and_three_packages_are_exact(self):
        pins = M.load_pins()
        self.assertEqual(pins['kernel_release'], '6.12.105+deb13-cloud-amd64')
        self.assertEqual(set(pins['packages']), {'cryptsetup-bin', 'libcryptsetup12', 'busybox-static'})
        self.assertEqual(sum(item['bytes'] for item in pins['packages'].values()), 1713000)
        self.assertFalse(pins['independent_production_approval'])
        self.assertTrue(pins['public_test_inputs_only'])

    def test_json_duplicate_keys_and_nonfinite_are_rejected(self):
        for raw in (b'{"version":1,"version":1}', b'{"value":NaN}', b'{"value":Infinity}'):
            with self.subTest(raw=raw), self.assertRaises(ValueError):
                M.exact_json(raw)

    def test_digest_checks_original_bytes_and_refuses_symlink_or_oversize(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'data'
            path.write_bytes(b'public fixture')
            self.assertEqual(M.digest(path), {'bytes': 14,
                'sha256': hashlib.sha256(b'public fixture').hexdigest()})
            link = path.with_name('link')
            link.symlink_to(path)
            with self.assertRaises(OSError):
                M.digest(link)
            with self.assertRaises(ValueError):
                M.digest(path, maximum=13)

    def test_hosted_guard_refuses_local_or_root_execution_before_mkdir(self):
        with tempfile.TemporaryDirectory() as directory:
            target = Path(directory) / 'new'
            for environment, uid in (({}, 1000), ({'GITHUB_ACTIONS': 'true',
                    'RUNNER_ENVIRONMENT': 'github-hosted', 'RUNNER_OS': 'Linux',
                    'RUNNER_TEMP': directory}, 0)):
                with mock.patch.dict(os.environ, environment, clear=True), \
                        mock.patch.object(M.os, 'geteuid', return_value=uid), \
                        self.assertRaises(ValueError):
                    M.hosted_output(target)
            self.assertFalse(target.exists())

    def test_hosted_output_must_be_new_inside_runner_temporary_root(self):
        with tempfile.TemporaryDirectory() as directory:
            environment = {'GITHUB_ACTIONS': 'true', 'RUNNER_ENVIRONMENT': 'github-hosted',
                           'RUNNER_OS': 'Linux', 'RUNNER_TEMP': directory}
            with mock.patch.dict(os.environ, environment, clear=True), \
                    mock.patch.object(M.os, 'geteuid', return_value=1000):
                root = Path(directory)
                for path in (root, root / '..' / 'outside'):
                    with self.assertRaises(ValueError):
                        M.hosted_output(path)
                created = M.hosted_output(root / 'new')
                self.assertEqual(created.stat().st_mode & 0o777, 0o700)
                with self.assertRaises(ValueError):
                    M.hosted_output(created)

    def test_exact_single_root_device_only(self):
        self.assertEqual(M.root_device('/dev/sda1\n'), '/dev/sda1')
        for text in ('', '/dev/sda1\n/dev/sda2\n', '/dev/mapper/arbitrary\n', '/dev/sda1;bad\n'):
            with self.subTest(text=text), self.assertRaises(ValueError):
                M.root_device(text)

    def test_kernel_requires_actual_verity_and_boot_drivers(self):
        names = ('BLK_DEV_INITRD', 'DEVTMPFS', 'EXT4_FS', 'BLK_DEV_DM', 'DM_VERITY',
                 'VIRTIO_PCI', 'VIRTIO_BLK', 'SERIAL_8250', 'SERIAL_8250_CONSOLE')
        good = '\n'.join('CONFIG_' + name + '=y' for name in names)
        M.kernel_config(good)
        for name in names:
            with self.subTest(name=name), self.assertRaises(ValueError):
                M.kernel_config(good.replace('CONFIG_' + name + '=y', '# disabled'))

    def test_source_binding_requires_exact_head_and_clean_source(self):
        revision = 'a' * 40
        with mock.patch.object(M, 'command', side_effect=[(revision + '\n').encode(), b'', b'tree\n']):
            self.assertEqual(M.source_binding(revision), {'revision': revision, 'tree': 'tree'})
        for values in ([b'b' * 40], [(revision + '\n').encode(), b' M source\n']):
            with mock.patch.object(M, 'command', side_effect=values), self.assertRaises(ValueError):
                M.source_binding(revision)

    def test_package_hash_is_checked_before_any_extractor_executes(self):
        pins = M.load_pins()
        with tempfile.TemporaryDirectory() as directory, \
                mock.patch.object(M, 'digest', return_value={'bytes': 1, 'sha256': 'bad'}), \
                mock.patch.object(M, 'command') as run, mock.patch.object(M, 'guestfish') as guest:
            with self.assertRaisesRegex(ValueError, 'package_digest'):
                M.stage_root(Path(directory), {name: Path('/unread/' + name)
                             for name in pins['packages']}, pins)
            run.assert_not_called()
            guest.assert_not_called()


class InspectionContracts(unittest.TestCase):
    def extract(self, directory, *, roots='/dev/sda1', details=('debian', '13', 'ext4', '4096')):
        output = Path(directory)
        pins = M.load_pins()
        handles = []
        def fresh_handle(_image, operations, **kwargs):
            # Inspection cache exists only inside this one invocation.
            inspected, emitted = False, []
            handles.append((operations, kwargs['operation']))
            for operation in operations:
                name = operation[0]
                if name == 'inspect-os':
                    inspected = True
                    emitted.extend((roots if len(handles) == 2 else '/dev/sda1').splitlines())
                elif name.startswith('inspect-get-'):
                    self.assertTrue(inspected, 'fresh handle has no inspection cache')
                    emitted.append(details[0 if name == 'inspect-get-distro' else 1])
                elif name == 'vfs-type':
                    emitted.append(details[2])
                elif name == 'blockdev-getsize64':
                    emitted.append(details[3])
                elif name == 'download' and str(operation[1]).startswith('/boot/config-'):
                    names = ('BLK_DEV_INITRD', 'DEVTMPFS', 'EXT4_FS', 'BLK_DEV_DM', 'DM_VERITY',
                             'VIRTIO_PCI', 'VIRTIO_BLK', 'SERIAL_8250', 'SERIAL_8250_CONSOLE')
                    Path(operation[2]).write_text('\n'.join('CONFIG_' + key + '=y' for key in names))
                elif name == 'readlink':
                    emitted.append('usr/' + operation[1].removeprefix('/'))
                elif name == 'tar-out':
                    with tarfile.open(operation[2], 'w') as archive:
                        modules = tarfile.TarInfo('lib/modules/' + pins['kernel_release'])
                        modules.type = tarfile.DIRTYPE
                        modules.mode = 0o755
                        archive.addfile(modules)
                        public = tarfile.TarInfo('share/public-fixture')
                        public.mode = 0o640
                        public.size = len(b'public fixture')
                        archive.addfile(public, io.BytesIO(b'public fixture'))
            return '\n'.join(emitted) + '\n'
        with mock.patch.object(M, 'digest', return_value={'sha512': pins['debian_image_sha512']}), \
                mock.patch.object(M, 'guestfish', side_effect=fresh_handle):
            tree, size = M.extract_boot(output / 'public.qcow2', output, pins)
        return tree, size, handles

    def test_fresh_root_tree_is_private_before_real_public_archive_extraction(self):
        with tempfile.TemporaryDirectory() as directory:
            self.assertFalse((Path(directory) / 'root-tree').exists())
            tree, size, _handles = self.extract(directory)
            self.assertEqual(size, 4096)
            self.assertEqual(tree.stat().st_mode & 0o777, 0o700)
            self.assertFalse(tree.is_symlink())
            self.assertEqual((tree / 'usr/share/public-fixture').read_bytes(), b'public fixture')
            self.assertEqual((tree / 'usr/share/public-fixture').stat().st_mode & 0o777, 0o640)
            modules = tree / 'usr/lib/modules' / M.load_pins()['kernel_release']
            self.assertEqual(modules.stat().st_mode & 0o777, 0o755)
            for name in ('bin', 'sbin', 'lib', 'lib64'):
                self.assertEqual(os.readlink(tree / name), 'usr/' + name)

    def test_existing_root_tree_file_directory_or_symlink_is_not_reused(self):
        for kind in ('directory', 'file', 'symlink', 'dangling_symlink'):
            with self.subTest(kind=kind), tempfile.TemporaryDirectory() as directory:
                base = Path(directory)
                tree, outside = base / 'root-tree', base / 'outside'
                outside.mkdir()
                (outside / 'canary').write_bytes(b'unchanged')
                if kind == 'directory':
                    tree.mkdir()
                elif kind == 'file':
                    tree.write_bytes(b'unchanged')
                else:
                    tree.symlink_to(outside if kind == 'symlink' else base / 'missing')
                original = tree.lstat()
                with mock.patch.object(M, 'safe_tree', wraps=M.safe_tree) as extractor:
                    with self.assertRaises(FileExistsError):
                        self.extract(directory)
                    extractor.assert_not_called()
                self.assertEqual(tree.lstat(), original)
                self.assertEqual(list(outside.iterdir()), [outside / 'canary'])
                self.assertEqual((outside / 'canary').read_bytes(), b'unchanged')
                if kind == 'directory':
                    self.assertEqual(list(tree.iterdir()), [])
                elif kind == 'file':
                    self.assertEqual(tree.read_bytes(), b'unchanged')
                else:
                    self.assertEqual(os.readlink(tree), str(outside if kind == 'symlink'
                                                           else base / 'missing'))

    def test_metadata_handle_inspects_before_cached_queries_and_binds_same_root(self):
        with tempfile.TemporaryDirectory() as directory:
            tree, size, handles = self.extract(directory)
            self.assertEqual(size, 4096)
            self.assertEqual(tree, Path(directory) / 'root-tree')
            self.assertEqual(handles[1], ([['inspect-os'], ['inspect-get-distro', '/dev/sda1'],
                ['inspect-get-major-version', '/dev/sda1'], ['vfs-type', '/dev/sda1'],
                ['blockdev-getsize64', '/dev/sda1']], 'inspect_details'))
            self.assertEqual([entry[1] for entry in handles], ['inspect_roots', 'inspect_details',
                'extract_boot_files', 'readlink_bin', 'readlink_sbin', 'readlink_lib', 'readlink_lib64'])

    def test_metadata_handle_rejects_different_multiple_or_missing_roots(self):
        for roots in ('/dev/sda2', '/dev/sda1\n/dev/sda2', ''):
            with self.subTest(roots=roots), tempfile.TemporaryDirectory() as directory, \
                    self.assertRaisesRegex(ValueError, 'inspection_root_binding'):
                self.extract(directory, roots=roots)

    def test_metadata_handle_preserves_exact_distribution_filesystem_and_size_guards(self):
        for details in (('ubuntu', '13', 'ext4', '4096'), ('debian', '12', 'ext4', '4096'),
                        ('debian', '13', 'xfs', '4096'), ('debian', '13', 'ext4', '4097'),
                        ('debian', '13', 'ext4', str(M.MAX_ROOT + 4096))):
            with self.subTest(details=details), tempfile.TemporaryDirectory() as directory, \
                    self.assertRaises(ValueError):
                self.extract(directory, details=details)


class ArchiveContracts(unittest.TestCase):
    def archive(self, base, entries):
        path = base / 'fixture.tar'
        with tarfile.open(path, 'w') as output:
            for name, kind, data in entries:
                member = tarfile.TarInfo(name)
                member.type = kind
                if kind == tarfile.REGTYPE:
                    member.size = len(data)
                    output.addfile(member, io.BytesIO(data))
                else:
                    member.linkname = data
                    output.addfile(member)
        return path

    def test_public_regular_files_and_inert_root_absolute_symlinks(self):
        with tempfile.TemporaryDirectory() as directory:
            base = Path(directory)
            archive = self.archive(base, [('usr/bin/tool', tarfile.REGTYPE, b'public'),
                                          ('bin', tarfile.SYMTYPE, '/usr/bin')])
            M.safe_tree(archive, base / 'tree')
            self.assertEqual((base / 'tree/usr/bin/tool').read_bytes(), b'public')
            self.assertEqual(os.readlink(base / 'tree/bin'), '/usr/bin')

    def test_archive_traversal_symlink_parents_and_specials_are_rejected(self):
        fixtures = [[('../escape', tarfile.REGTYPE, b'x')],
                    [('/absolute', tarfile.REGTYPE, b'x')],
                    [('link', tarfile.SYMTYPE, '/tmp'), ('link/canary', tarfile.REGTYPE, b'x')],
                    [('device', tarfile.CHRTYPE, '')]]
        for entries in fixtures:
            with self.subTest(entries=entries), tempfile.TemporaryDirectory() as directory:
                base = Path(directory)
                with self.assertRaises(ValueError):
                    M.safe_tree(self.archive(base, entries), base / 'tree')

    def test_archive_hardlink_becomes_independent_bounded_copy(self):
        with tempfile.TemporaryDirectory() as directory:
            base = Path(directory)
            archive = self.archive(base, [('first', tarfile.REGTYPE, b'public'),
                                          ('second', tarfile.LNKTYPE, 'first')])
            M.safe_tree(archive, base / 'tree')
            self.assertEqual((base / 'tree/second').read_bytes(), b'public')
            self.assertNotEqual((base / 'tree/first').stat().st_ino,
                                (base / 'tree/second').stat().st_ino)


class BootContracts(unittest.TestCase):
    def test_initrd_receipt_binds_bytes_and_public_only_scope(self):
        pins = M.load_pins()
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory)
            for name in ('original-initrd.img', 'initrd.img'):
                (output / name).write_bytes(name.encode())
            value = dict(version=1, kernel_version=pins['kernel_release'], root_hash='a' * 64,
                data_blocks=1, salt=M.SALT, cmdline=M.CMDLINE,
                original_initrd_sha256=M.digest(output / 'original-initrd.img')['sha256'],
                hardware_attestation=False, private_inputs=False, model_execution=False,
                worker_execution=False, closure={'/init': 'a' * 64, '/usr/bin/busybox': 'b' * 64},
                initrd_sha256=M.digest(output / 'initrd.img')['sha256'],
                initrd_bytes=(output / 'initrd.img').stat().st_size)
            self.assertEqual(M.initrd_receipt(json.dumps(value).encode(), output, pins, 'a' * 64, 1), value)
            for delta in ({'model_execution': True}, {'private_note': 'PRIVATE_CANARY'},
                          {'root_hash': 'b' * 64}, {'data_blocks': True},
                          {'initrd_sha256': 'c' * 64}, {'closure': {'/private/canary': 'a' * 64}}):
                with self.subTest(delta=delta), self.assertRaises(ValueError):
                    M.initrd_receipt(json.dumps({**value, **delta}).encode(), output, pins, 'a' * 64, 1)

    def test_boot_has_only_fixed_readonly_disks_and_no_remote_or_debug_access(self):
        argv = M.boot_command(Path('/runner/work'))
        self.assertEqual(argv[argv.index('-append') + 1], M.CMDLINE)
        self.assertEqual(argv[argv.index('-nic') + 1], 'none')
        self.assertEqual(argv[argv.index('-monitor') + 1], 'none')
        disks = [argv[i + 1] for i, word in enumerate(argv) if word == '-drive']
        self.assertEqual(len(disks), 2)
        self.assertTrue(all('readonly=on' in disk and 'format=raw' in disk for disk in disks))
        self.assertFalse(any(word in argv for word in ('-netdev', '-virtfs', '-qmp', '-gdb', '-s')))
        self.assertNotIn('vp.root_hash', M.CMDLINE)
        self.assertEqual(argv[argv.index('-m') + 1], '1024')
        self.assertEqual(argv[argv.index('-smp') + 1], '2')

    def test_qemu_option_injection_is_rejected(self):
        for path in ('/runner/file,readonly=off', '/runner/file\nother'):
            with self.subTest(path=path), self.assertRaises(ValueError):
                M.boot_command(Path(path))

    def test_verity_fixed_parameters_have_no_integrity_bypass(self):
        options = M.verity_options(1024)
        self.assertIn('--no-superblock', options)
        self.assertIn('--salt=' + '0' * 64, options)
        self.assertFalse(any('ignore-' in item or 'check-at-most-once' in item for item in options))
        for blocks in (False, 0, -1, M.MAX_ROOT // 4096 + 1):
            with self.assertRaises(ValueError):
                M.verity_options(blocks)

    def test_success_and_explicit_corruption_are_different_closed_receipts(self):
        for outcome in ('boot_verified', 'integrity_failure'):
            value = receipt(outcome)
            self.assertEqual(M.boot_receipt(b'public kernel log\n' + encoded(value), outcome), value)
        with self.assertRaises(ValueError):
            M.boot_receipt(b'kernel timed out\n', 'integrity_failure')

    def test_private_canary_unknown_fields_duplicates_and_claims_fail_closed(self):
        good = receipt()
        for value in ({**good, 'raw_error': 'PRIVATE_CANARY'}, {**good, 'model_execution': True},
                      {**good, 'hardware_attestation': True}, {**good, 'private_inputs': True},
                      {**good, 'version': True}, {**good, 'write_denied': 1},
                      {**good, 'stage': 'verity_open'}):
            with self.subTest(value=value), self.assertRaises(ValueError):
                M.boot_receipt(encoded(value), 'boot_verified')
        for raw in (encoded(good) * 2, M.PREFIX + b'{"version":1,"version":1}\n',
                    b'x' * (M.MAX_LOG + 1)):
            with self.assertRaises(ValueError):
                M.boot_receipt(raw, 'boot_verified')

    def test_corruption_requires_exact_stage_and_does_not_claim_partial_success(self):
        value = receipt('integrity_failure')
        for key, replacement in (('stage', 'root_mount'), ('verity_verified', True),
                                  ('outcome', 'boot_rejected')):
            with self.assertRaises(ValueError):
                M.boot_receipt(encoded({**value, key: replacement}), 'integrity_failure')

    def test_boot_pair_retains_good_original_and_flips_only_one_data_byte(self):
        with tempfile.TemporaryDirectory() as directory:
            base = Path(directory)
            evidence = base / 'evidence'
            evidence.mkdir()
            original = b'P' * 4096
            (base / 'root.raw').write_bytes(original)
            commands = []
            def invoke(argv, **_):
                commands.append(argv)
                if argv[0] == 'cp':
                    Path(argv[-1]).write_bytes(Path(argv[-2]).read_bytes())
                    return b''
                outcome = 'integrity_failure' if 'corrupted-root.raw' in ' '.join(argv) else 'boot_verified'
                return encoded(receipt(outcome))
            with mock.patch.object(M, 'command', side_effect=invoke):
                M.boot_pair(base, evidence)
            changed = (base / 'corrupted-root.raw').read_bytes()
            self.assertEqual([i for i, pair in enumerate(zip(original, changed)) if pair[0] != pair[1]], [1024])
            self.assertEqual((base / 'root.raw').read_bytes(), original)
            self.assertEqual(len(commands), 3)
            self.assertEqual(set(path.name for path in evidence.iterdir()),
                             {'good-boot.json', 'corrupt-boot.json'})


class OwnedChildContracts(unittest.TestCase):
    def test_bounded_public_python_child_is_joined_before_return(self):
        self.assertEqual(M.command([sys.executable, '-c', 'print("public fixture")']), b'public fixture\n')

    def test_output_overflow_terminates_and_joins_owned_child(self):
        with self.assertRaisesRegex(ValueError, 'command_output_bound'):
            M.command([sys.executable, '-c', 'print("x"*4096)'], maximum=32)

    def test_timeout_terminates_and_joins_without_reusing_pid(self):
        start = time.monotonic()
        with self.assertRaisesRegex(ValueError, 'command_timeout'):
            M.command([sys.executable, '-c', 'import time; time.sleep(10)'], timeout=.1)
        self.assertLess(time.monotonic() - start, 3)

    def test_absolute_budget_rejects_before_spawning(self):
        token = M.DEADLINE.set(time.monotonic() - 1)
        try:
            with mock.patch.object(M.subprocess, 'Popen') as spawn, self.assertRaises(ValueError):
                M.command(['not-executed'])
            spawn.assert_not_called()
        finally:
            M.DEADLINE.reset(token)

    def test_normal_exit_is_not_reaped_before_last_owned_group_signal(self):
        order = []
        wait = M.subprocess.Popen.wait
        kill = M.os.killpg
        def mark_wait(process, *args, **kwargs):
            order.append('wait')
            return wait(process, *args, **kwargs)
        def mark_kill(pid, sig):
            self.assertIn(sig, (signal.SIGKILL, 0))
            order.append('signal' if sig else 'observe')
            return kill(pid, sig)
        with mock.patch.object(M.subprocess.Popen, 'wait', mark_wait), \
                mock.patch.object(M.os, 'killpg', side_effect=mark_kill):
            M.command([sys.executable, '-c', 'pass'])
        self.assertEqual(order, ['signal', 'wait', 'observe'])

    def test_uncertain_group_is_not_treated_as_joined(self):
        with mock.patch.object(M, 'group_absent', return_value=False), \
                self.assertRaisesRegex(M.CleanupUnconfirmed, 'process_group_remaining'):
            M.command([sys.executable, '-c', 'pass'])

    def test_signal_failure_still_attempts_wait_and_closes_pipes_without_cleanup_claim(self):
        calls, processes = [], []
        spawn, kill = M.subprocess.Popen, M.os.killpg
        def remember(*args, **kwargs):
            process = spawn(*args, **kwargs)
            processes.append(process)
            original_wait = process.wait
            def waited(*args, **kwargs):
                calls.append('wait')
                return original_wait(*args, **kwargs)
            process.wait = waited
            return process
        def denied(pid, sig):
            if sig == signal.SIGKILL:
                raise PermissionError('PRIVATE_CANARY')
            return kill(pid, sig)
        with mock.patch.object(M.subprocess, 'Popen', side_effect=remember), \
                mock.patch.object(M.os, 'killpg', side_effect=denied), \
                self.assertRaisesRegex(M.CleanupUnconfirmed, 'process_group_signal_failed'):
            M.command([sys.executable, '-c', 'pass'])
        self.assertEqual(calls, ['wait'])
        self.assertTrue(processes[0].stdout.closed)
        self.assertTrue(processes[0].stderr.closed)

    def test_guestfish_keeps_appliance_in_owned_group_and_disables_network(self):
        with mock.patch.object(M, 'command', return_value=b'') as run, \
                mock.patch.object(M, 'bound_hypervisor', return_value='/public/qemu'):
            M.guestfish(Path('/public/root.raw'), [['inspect-os']], operation='inspect_roots')
        argv = run.call_args.args[0]
        self.assertEqual(argv[argv.index('set-pgroup'):],
            ['set-pgroup', 'false', ':', 'set-network', 'false', ':', 'set-hv', '/public/qemu',
             ':', 'run', ':', 'inspect-os'])
        self.assertEqual(run.call_args.kwargs, {'timeout': 300, 'operation': 'inspect_roots'})
        self.assertEqual(M.ENV['LIBGUESTFS_BACKEND_SETTINGS'], 'force_kvm')


class ApplianceDiagnostics(unittest.TestCase):
    def entries(self, names):
        return nullcontext(iter(SimpleNamespace(name=name) for name in names))

    def test_candidate_census_is_closed_and_never_claims_actual_selection(self):
        canary = 'PRIVATE_KERNEL_CANARY'
        def scan(path):
            return self.entries([canary] if path == Path('/lib/modules') else
                                ['vmlinuz-' + canary, 'config-ignored', 'vmlinuz-../bad',
                                 'vmlinuz-.', 'vmlinuz-..'])
        def readable(path):
            return 'missing' if str(path).startswith('/lib/modules/') and path.name == 'vmlinuz' else 'readable'
        with mock.patch.object(M.os, 'scandir', side_effect=scan), \
                mock.patch.object(M, 'readable_regular', side_effect=readable) as access, \
                mock.patch.object(M, 'kvm_observation', return_value='api_12'):
            value = M.appliance_preflight()
        self.assertEqual(value, dict(version=1, diagnostic_only=True, selected_kernel=False,
            kernel_selection='unobserved', candidates=2, incomplete=False,
            kernel=dict(readable=1, missing=1, denied=0, other=0),
            modules_index=dict(readable=2, missing=0, denied=0, other=0), kvm='api_12'))
        self.assertEqual(access.call_count, 4)
        self.assertNotIn(canary, json.dumps(value))
        self.assertNotIn('/lib/', json.dumps(value))

    def test_candidate_and_directory_scan_caps_mark_incomplete(self):
        for names, candidates, calls in (([f'6.{i}' for i in range(40)], 32, 64),
                                         (['invalid/name'] * 140, 0, 0)):
            with self.subTest(candidates=candidates), \
                    mock.patch.object(M.os, 'scandir', return_value=self.entries(names)) as scan, \
                    mock.patch.object(M, 'readable_regular', return_value='readable') as access, \
                    mock.patch.object(M, 'kvm_observation', return_value='api_12'):
                value = M.appliance_preflight()
            self.assertEqual(value['candidates'], candidates)
            self.assertTrue(value['incomplete'])
            self.assertFalse(value['selected_kernel'])
            self.assertEqual(access.call_count, calls)
            scan.assert_called_once_with(Path('/lib/modules'))

    def test_unavailable_census_is_observation_not_raw_error_or_kernel_selection(self):
        with mock.patch.object(M.os, 'scandir', side_effect=PermissionError('PRIVATE_PATH_CANARY')), \
                mock.patch.object(M, 'kvm_observation', return_value='denied'):
            value = M.appliance_preflight()
        self.assertTrue(value['incomplete'])
        self.assertEqual(value['candidates'], 0)
        self.assertEqual(value['kvm'], 'denied')
        self.assertEqual(value['kernel_selection'], 'unobserved')
        self.assertNotIn('PRIVATE', json.dumps(value))

    def test_file_access_observation_reads_no_contents_and_closes_descriptor(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'kernel'
            path.write_bytes(b'PRIVATE_KERNEL_CONTENT')
            with mock.patch.object(M.os, 'read', side_effect=AssertionError('must not read')):
                self.assertEqual(M.readable_regular(path), 'readable')
                self.assertEqual(M.readable_regular(path.parent), 'other')
                self.assertEqual(M.readable_regular(path.with_name('missing')), 'missing')
        for error, expected in ((PermissionError('PRIVATE'), 'denied'), (OSError('PRIVATE'), 'other')):
            with mock.patch.object(M.os, 'open', side_effect=error):
                self.assertEqual(M.readable_regular('/unread'), expected)
        with mock.patch.object(M.os, 'open', return_value=123), \
                mock.patch.object(M.os, 'fstat', side_effect=OSError('PRIVATE')), \
                mock.patch.object(M.os, 'close') as close:
            self.assertEqual(M.readable_regular('/unread'), 'other')
        close.assert_called_once_with(123)

    def test_kvm_query_is_only_system_api_read_and_always_closes(self):
        for mode, answer, expected in ((M.stat.S_IFCHR, 12, 'api_12'),
                                      (M.stat.S_IFCHR, 11, 'api_mismatch'),
                                      (M.stat.S_IFREG, 12, 'not_character_device')):
            with self.subTest(expected=expected), mock.patch.object(M.os, 'open', return_value=123) as opened, \
                    mock.patch.object(M.os, 'fstat', return_value=SimpleNamespace(st_mode=mode)), \
                    mock.patch.object(M.fcntl, 'ioctl', return_value=answer) as ioctl, \
                    mock.patch.object(M.os, 'close') as close:
                self.assertEqual(M.kvm_observation(), expected)
            opened.assert_called_once_with('/dev/kvm', M.os.O_RDWR | M.os.O_CLOEXEC | M.os.O_NONBLOCK)
            close.assert_called_once_with(123)
            if mode == M.stat.S_IFCHR:
                ioctl.assert_called_once_with(123, 0xAE00, 0)
            else:
                ioctl.assert_not_called()
        for error, expected in ((FileNotFoundError('PRIVATE'), 'missing'),
                                (PermissionError('PRIVATE'), 'denied'), (OSError('PRIVATE'), 'io_error')):
            with mock.patch.object(M.os, 'open', side_effect=error):
                self.assertEqual(M.kvm_observation(), expected)
        with mock.patch.object(M.os, 'open', return_value=123), \
                mock.patch.object(M.os, 'fstat', return_value=SimpleNamespace(st_mode=M.stat.S_IFCHR)), \
                mock.patch.object(M.fcntl, 'ioctl', side_effect=OSError('PRIVATE')), \
                mock.patch.object(M.os, 'close') as close:
            self.assertEqual(M.kvm_observation(), 'io_error')
        close.assert_called_once_with(123)

    def test_preflight_obeys_original_absolute_deadline_before_host_queries(self):
        token = M.DEADLINE.set(time.monotonic() - 1)
        try:
            with mock.patch.object(M, 'kvm_observation') as kvm, \
                    mock.patch.object(M.os, 'scandir') as scan, \
                    self.assertRaisesRegex(ValueError, 'build_deadline'):
                M.appliance_preflight()
            kvm.assert_not_called()
            scan.assert_not_called()
        finally:
            M.DEADLINE.reset(token)

    def test_exact_upstream_stderr_patterns_survive_every_chunk_boundary(self):
        for line, label in M.STDERR_PATTERNS.items():
            with self.subTest(label=label):
                observed = M.GuestfishStderr()
                for byte in line + b'\r\n' + line:
                    observed.feed(bytes([byte]))
                self.assertEqual(observed.finish(), label)
                self.assertEqual(observed.pending, b'')

    def test_unknown_near_match_and_private_stderr_never_become_a_known_class(self):
        line = b'libguestfs: error: force_kvm supplied but kvm not available.'
        for raw in (b'PRIVATE_CANARY/path: Permission denied\n', b'canary ' + line,
                    line + b' PRIVATE_CANARY', line.upper(), b'\xff' + line):
            with self.subTest(raw=raw):
                observed = M.GuestfishStderr()
                observed.feed(raw)
                self.assertEqual(observed.finish(), 'unclassified')
        for bad in ('PRIVATE_CANARY', [], True):
            self.assertIsNone(M.command_failure(M.CommandFailed(1, 'inspect_roots', bad))['stderr_class'])

    def test_fixed_guestfish_argv_prefix_is_supported_without_arbitrary_source_paths(self):
        line = b'libguestfs: error: guestfs_launch failed.'
        for prefix, expected in ((b'*stdin*:0: ', 'appliance_launch_failed'),
                                 (b'*stdin*:1: ', 'unclassified'),
                                 (b'/PRIVATE_PATH:0: ', 'unclassified')):
            observed = M.GuestfishStderr()
            observed.feed(prefix[:4])
            observed.feed(prefix[4:] + line)
            self.assertEqual(observed.finish(), expected)

    def test_long_lines_are_bounded_and_multiple_known_classes_are_ambiguous(self):
        observed = M.GuestfishStderr()
        observed.feed(b'P' * 4097)
        self.assertEqual(observed.pending, b'')
        self.assertTrue(observed.dropping)
        first = b'libguestfs: error: guestfs_launch failed.'
        observed.feed(first + b'\n' + first + b'\n')
        observed.feed(b'libguestfs: error: appliance launch timed out.\n')
        self.assertEqual(observed.finish(), 'ambiguous')

    def test_real_child_classifies_only_stderr_not_stdout_or_unlabelled_commands(self):
        line = b'libguestfs: error: force_kvm supplied but kvm not available.'
        for descriptor, operation, expected in ((1, 'inspect_roots', 'unclassified'),
                                                (2, 'inspect_roots', 'kvm_unavailable'),
                                                (2, None, None)):
            program = f'import os,sys; os.write({descriptor}, {line!r}); sys.exit(7)'
            with self.subTest(descriptor=descriptor, operation=operation), \
                    self.assertRaises(M.CommandFailed) as raised:
                M.command([sys.executable, '-c', program], operation=operation)
            self.assertEqual(raised.exception.stderr_class, expected)
            self.assertEqual(raised.exception.args, ('command_failed',))

    def test_stderr_classifier_does_not_expand_total_output_limit_or_change_success(self):
        line = b'libguestfs: error: guestfs_launch failed.\n'
        program = f'import os; os.write(2, {line!r}); os.write(1, b"public output\\n")'
        result = M.command([sys.executable, '-c', program], operation='inspect_roots')
        self.assertEqual(sorted(result.splitlines()), sorted([line.rstrip(), b'public output']))
        with self.assertRaisesRegex(ValueError, 'command_output_bound') as raised:
            M.command([sys.executable, '-c', program], operation='inspect_roots', maximum=len(line))
        self.assertNotIsInstance(raised.exception, M.CommandFailed)
        self.assertIsNone(M.command_failure(raised.exception))

    def test_preflight_runs_before_download_without_changing_deadline_or_admission(self):
        observed = dict(version=1, diagnostic_only=True, selected_kernel=False,
                        kernel_selection='unobserved', candidates=0, incomplete=True,
                        kernel={}, modules_index={}, kvm='denied')
        order, deadlines = [], []
        original = ValueError('download_digest')
        def sample():
            order.append('observe')
            deadlines.append(M.DEADLINE.get())
            return observed
        def download(*_args):
            order.append('download')
            deadlines.append(M.DEADLINE.get())
            raise original
        def admit(_tools, value):
            order.append('qmp')
            deadlines.append(M.DEADLINE.get())
            value.update(state='passed', present=True, enabled=True)
        with tempfile.TemporaryDirectory() as directory, \
                mock.patch.object(M, 'hosted_output', return_value=Path(directory)), \
                mock.patch.object(M, 'verify_kvm_launch', return_value=launch_receipt()), \
                mock.patch.object(M, 'adopt_appliance', side_effect=lambda *_: dict(
                    deadline=M.DEADLINE.get(), receipt={'version': 1})), \
                mock.patch.object(M, 'source_binding', return_value={'revision': 'a' * 40}), \
                mock.patch.object(M, 'tool_inventory', return_value={}), \
                mock.patch.object(M, 'qmp_preflight', side_effect=admit), \
                mock.patch.object(M, 'appliance_preflight', side_effect=sample), \
                mock.patch.object(M, 'fetch', side_effect=download), \
                self.assertRaises(ValueError) as raised:
            try:
                M.execute(SimpleNamespace(yes=True, work=directory, expected_source='a' * 40))
            finally:
                evidence = Path(directory) / 'evidence'
                value = json.loads((evidence / 'cleanup.json').read_text())
                self.assertEqual(set(path.name for path in evidence.iterdir()), {'cleanup.json'})
                self.assertEqual(value['appliance_preflight'], observed)
                self.assertEqual(value['qmp_kvm_preflight']['state'], 'passed')
                self.assertEqual(value['failure']['reason'], 'download_digest')
                self.assertTrue(value['owned_scratch_removed'])
        self.assertIs(raised.exception, original)
        self.assertEqual(order, ['observe', 'qmp', 'download'])
        self.assertIsNotNone(deadlines[0])
        self.assertEqual(deadlines[0], deadlines[1])
        self.assertEqual(deadlines[1], deadlines[2])


class FailurePreservation(unittest.TestCase):
    def exercise(self, directory, cause):
        args = SimpleNamespace(yes=True, work=directory, expected_source='a' * 40)
        with mock.patch.object(M, 'hosted_output', return_value=Path(directory)), \
                mock.patch.object(M, 'verify_kvm_launch', return_value=launch_receipt()), \
                mock.patch.object(M, 'adopt_appliance', side_effect=lambda *_: dict(
                    deadline=M.DEADLINE.get(), receipt={'version': 1})), \
                mock.patch.object(M, 'source_binding', return_value={'revision': 'a' * 40}), \
                mock.patch.object(M, 'tool_inventory', side_effect=cause):
            return M.execute(args)

    def test_primary_failure_is_closed_and_evidence_survives_scratch_removal(self):
        with tempfile.TemporaryDirectory() as directory:
            original = ValueError('PRIVATE_CANARY arbitrary secret exception')
            with self.assertRaises(ValueError) as raised:
                self.exercise(directory, original)
            self.assertIs(raised.exception, original)
            raw = (Path(directory) / 'evidence/cleanup.json').read_text()
            self.assertNotIn('PRIVATE_CANARY', raw)
            value = json.loads(raw)
            self.assertEqual(value['failure'], {'stage': 'host_tools', 'reason': 'unclassified', 'command': None})
            self.assertTrue(value['owned_scratch_removed'])
            self.assertFalse(value['boot_pair_verified'])

    def test_unconfirmed_join_preserves_owned_scratch_and_original_error(self):
        with tempfile.TemporaryDirectory() as directory:
            original = M.CleanupUnconfirmed('process_group_remaining')
            with self.assertRaises(M.CleanupUnconfirmed) as raised:
                self.exercise(directory, original)
            self.assertIs(raised.exception, original)
            value = json.loads((Path(directory) / 'evidence/cleanup.json').read_text())
            self.assertFalse(value['child_leaders_reaped'])
            self.assertFalse(value['original_process_groups_absent'])
            self.assertFalse(value['owned_scratch_removed'])
            self.assertTrue((Path(directory) / 'payload').is_dir())

    def test_sigterm_cancels_owned_child_and_restores_original_signal_handler(self):
        before = signal.getsignal(signal.SIGTERM)
        def interrupt():
            M.command([sys.executable, '-c',
                'import os,signal,time; os.kill(os.getppid(),signal.SIGTERM); time.sleep(10)'],
                operation='inspect_roots')
        with tempfile.TemporaryDirectory() as directory:
            start = time.monotonic()
            with self.assertRaisesRegex(ValueError, 'cancelled'):
                self.exercise(directory, interrupt)
            self.assertLess(time.monotonic() - start, 3)
            value = json.loads((Path(directory) / 'evidence/cleanup.json').read_text())
            self.assertEqual(value['failure'], {'stage': 'host_tools', 'reason': 'cancelled', 'command': None})
            self.assertTrue(value['original_process_groups_absent'])
            self.assertTrue(value['owned_scratch_removed'])
        self.assertIs(signal.getsignal(signal.SIGTERM), before)

    def test_cleanup_error_never_replaces_original_primary_failure(self):
        with tempfile.TemporaryDirectory() as directory:
            original = ValueError('command_failed')
            with mock.patch.object(M.shutil, 'rmtree', side_effect=PermissionError('PRIVATE_CANARY')), \
                    self.assertRaises(ValueError) as raised:
                self.exercise(directory, original)
            self.assertIs(raised.exception, original)
            value = json.loads((Path(directory) / 'evidence/cleanup.json').read_text())
            self.assertEqual(value['failure']['reason'], 'command_failed')
            self.assertEqual(value['cleanup_error'], 'scratch_removal_failed')
            self.assertFalse(value['owned_scratch_removed'])

    def test_command_failure_has_only_closed_operation_and_bounded_returncode(self):
        for operation in M.GUESTFISH_OPERATIONS:
            for code in (-64, -9, 1, 255):
                failure = M.CommandFailed(code, operation)
                self.assertEqual(M.failure_reason(failure), 'command_failed')
                self.assertEqual(M.command_failure(failure), {'operation': operation, 'returncode': code,
                                                             'stderr_class': None})
        for operation, code in (('PRIVATE_CANARY/path', 1), (None, 1), ('inspect_roots', 0),
                                ('inspect_roots', True), ('inspect_roots', -65),
                                ('inspect_roots', 256), ('inspect_roots', 'PRIVATE_CANARY')):
            self.assertIsNone(M.command_failure(M.CommandFailed(code, operation)))
        fabricated = ValueError('command_failed')
        fabricated.operation, fabricated.returncode = 'inspect_roots', 1
        self.assertIsNone(M.command_failure(fabricated))

    def test_real_public_child_failure_retains_no_output_or_argv(self):
        with self.assertRaises(M.CommandFailed) as raised:
            M.command([sys.executable, '-c',
                'import sys; print("PRIVATE_CANARY"); print("PRIVATE_STDERR", file=sys.stderr); sys.exit(7)'],
                operation='inspect_roots')
        self.assertEqual(raised.exception.args, ('command_failed',))
        value = M.command_failure(raised.exception)
        self.assertEqual(value, {'operation': 'inspect_roots', 'returncode': 7, 'stderr_class': 'unclassified'})
        self.assertNotIn('PRIVATE', json.dumps(value))

    def test_timeout_never_projects_its_cleanup_signal_as_program_returncode(self):
        with self.assertRaisesRegex(ValueError, 'command_timeout') as raised:
            M.command([sys.executable, '-c', 'import time; time.sleep(10)'],
                      timeout=.05, operation='inspect_roots')
        self.assertNotIsInstance(raised.exception, M.CommandFailed)
        self.assertIsNone(M.command_failure(raised.exception))

    def test_typed_failure_context_survives_scratch_cleanup_failure_without_masking_primary(self):
        with tempfile.TemporaryDirectory() as directory:
            original = M.CommandFailed(1, 'inspect_details', 'appliance_launch_failed')
            with mock.patch.object(M.shutil, 'rmtree', side_effect=PermissionError('PRIVATE_CANARY')), \
                    self.assertRaises(M.CommandFailed) as raised:
                self.exercise(directory, original)
            self.assertIs(raised.exception, original)
            raw = (Path(directory) / 'evidence/cleanup.json').read_text()
            self.assertNotIn('PRIVATE', raw)
            value = json.loads(raw)
            self.assertEqual(value['failure'], {'stage': 'host_tools', 'reason': 'command_failed',
                'command': {'operation': 'inspect_details', 'returncode': 1,
                            'stderr_class': 'appliance_launch_failed'}})
            self.assertEqual(value['cleanup_error'], 'scratch_removal_failed')
            self.assertFalse(value['owned_scratch_removed'])


class ApplianceStaging(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        self.stage = self.root / 'stage'
        self.kernel = self.root / 'host-kernel'
        self.modules = self.root / 'modules'
        self.modules.mkdir()
        (self.modules / 'modules.dep').write_bytes(b'kernel/example.ko:\n')
        self.release = '6.8.0-1018-azure'
        self.payload = bytearray(11000)
        self.payload[514:518] = b'HdrS'
        self.payload[518:520] = (0x20f).to_bytes(2, 'little')
        self.payload[526:528] = (0x100).to_bytes(2, 'little')
        self.payload[768:768 + len(self.release)] = self.release.encode()
        self.kernel.write_bytes(self.payload)
        self.args = SimpleNamespace(yes=True, expected_source='a' * 40)
        self.real_inputs, self.real_identity = M.appliance_inputs, M.host_identity
        self.real_stage_path = M.appliance_stage_path
        for patcher in (mock.patch.object(M, 'appliance_stage_path', return_value=self.stage),
                        mock.patch.object(M.os, 'uname', return_value=SimpleNamespace(release=self.release)),
                        mock.patch.object(M, 'appliance_inputs', return_value=(self.kernel, self.modules)),
                        mock.patch.object(M, 'host_identity', side_effect=self.identity),
                        mock.patch.object(M, 'source_binding', return_value={'revision': 'a' * 40})):
            patcher.start()
            self.addCleanup(patcher.stop)

    def identity(self, path, **_kwargs):
        info = path.lstat()
        return [info.st_dev, info.st_ino, info.st_mode, 0, 0, info.st_nlink,
                info.st_size, info.st_mtime_ns, info.st_ctime_ns]

    def copied(self):
        M.prepare_appliance(self.args)
        (self.stage / 'kernel').write_bytes(self.payload)
        (self.stage / 'kernel').chmod(0o600)

    def ready(self):
        self.copied()
        M.finish_appliance(self.args)

    def rewrite(self, name, value):
        (self.stage / name).write_text(json.dumps(value))

    def test_prepare_records_original_budget_and_identity_without_privileged_execution(self):
        with mock.patch.object(M, 'command', side_effect=AssertionError('no privileged reader here')):
            self.assertEqual(M.prepare_appliance(self.args), self.release)
        value = M.read_stage(self.stage / 'prepared.json')
        self.assertEqual(value['source_identity'], self.identity(self.kernel))
        self.assertEqual(value['modules_identity'], self.identity(self.modules))
        self.assertLessEqual(value['started_monotonic_ns'], time.monotonic_ns())
        self.assertEqual(self.stage.stat().st_mode & 0o777, 0o700)
        self.assertFalse((self.stage / 'kernel').exists())
        self.assertIsNone(M.DEADLINE.get())

    def test_release_is_strict_and_fixed_paths_do_not_follow_external_module_alias(self):
        for release in ('../secret', '/tmp/kernel', '', '-option', '6.8\n', '6.8/other', True, '6' * 129):
            with self.subTest(release=release), self.assertRaisesRegex(ValueError, 'appliance_kernel_release'):
                self.real_inputs(release)
        with mock.patch.object(Path, 'resolve', return_value=Path('/usr/lib/modules')):
            self.assertEqual(self.real_inputs(self.release),
                (Path('/boot/vmlinuz-' + self.release), Path('/usr/lib/modules') / self.release))
        with mock.patch.object(Path, 'resolve', return_value=Path('/tmp/PRIVATE_CANARY')), \
                self.assertRaisesRegex(ValueError, 'appliance_host_path'):
            self.real_inputs(self.release)

    def test_root_owned_regular_and_parent_modes_are_mandatory(self):
        def info(mode=M.stat.S_IFREG | 0o600, uid=0, size=11000):
            return SimpleNamespace(st_mode=mode, st_uid=uid, st_gid=0, st_size=size,
                st_dev=1, st_ino=2, st_nlink=1, st_mtime_ns=3, st_ctime_ns=4)
        path = Path('/boot/vmlinuz-' + self.release)
        for changed in (info(uid=1234), info(mode=M.stat.S_IFREG | 0o622),
                        info(mode=M.stat.S_IFLNK | 0o777), info(mode=M.stat.S_IFIFO | 0o600),
                        info(size=0), info(size=M.MAX_APPLIANCE_KERNEL + 1)):
            def metadata(item):
                return changed if item == path else info(mode=M.stat.S_IFDIR | 0o755)
            with self.subTest(mode=changed.st_mode, uid=changed.st_uid, size=changed.st_size), \
                    mock.patch.object(Path, 'resolve', return_value=path), \
                    mock.patch.object(Path, 'lstat', metadata), self.assertRaises(ValueError):
                self.real_identity(path)
        with mock.patch.object(Path, 'resolve', return_value=path), \
                mock.patch.object(Path, 'lstat', return_value=info(mode=M.stat.S_IFDIR | 0o777)), \
                self.assertRaisesRegex(ValueError, 'appliance_host_parent'):
            self.real_identity(path)

    def test_missing_host_pair_stops_before_creating_stage_or_reading_kernel(self):
        self.kernel.unlink()
        with mock.patch.object(M, 'command') as run, self.assertRaises(FileNotFoundError):
            M.prepare_appliance(self.args)
        run.assert_not_called()
        self.assertFalse(self.stage.exists())

    def test_finish_binds_copy_and_preserves_final_debian_pins_and_host_permissions(self):
        before = self.kernel.stat()
        pins = M.PINS.read_bytes()
        self.ready()
        _prepared, value = M.validate_appliance(self.stage, 'a' * 40, ready=True)
        self.assertEqual(value['kernel'], {'bytes': len(self.payload),
            'sha256': hashlib.sha256(self.payload).hexdigest()})
        self.assertEqual(value['kernel_release'], self.release)
        for flag in ('host_permissions_changed', 'pre_pinned_host_kernel', 'appliance_boot_verified'):
            self.assertIs(value[flag], False)
        self.assertEqual(self.kernel.stat().st_mode, before.st_mode)
        self.assertEqual(self.kernel.stat().st_ctime_ns, before.st_ctime_ns)
        self.assertEqual((self.stage / 'kernel').stat().st_mode & 0o777, 0o400)
        self.assertEqual(M.PINS.read_bytes(), pins)
        self.assertNotIn(str(self.root), json.dumps(value))

    def test_changed_source_and_modules_are_rejected_before_adoption(self):
        self.copied()
        prepared = M.read_stage(self.stage / 'prepared.json')
        for path in (self.kernel, self.modules / 'modules.dep'):
            old = path.read_bytes()
            path.write_bytes(old + b'changed')
            with self.subTest(path=path.name), self.assertRaisesRegex(ValueError, 'appliance_source_changed'):
                M.finish_appliance(self.args)
            path.write_bytes(old)
            prepared['source_identity'] = self.identity(self.kernel)
            self.rewrite('prepared.json', prepared)
        self.assertFalse((self.stage / 'ready.json').exists())

    def test_wrong_kernel_release_magic_and_length_are_not_overridden_by_environment(self):
        self.copied()
        for offset, byte in ((514, 0), (768, ord('9'))):
            broken = bytearray(self.payload)
            broken[offset] = byte
            (self.stage / 'kernel').write_bytes(broken)
            with self.subTest(offset=offset), self.assertRaisesRegex(ValueError, 'appliance_kernel_release'):
                M.finish_appliance(self.args)
        (self.stage / 'kernel').write_bytes(self.payload + b'x')
        with self.assertRaisesRegex(ValueError, 'appliance_kernel_bound'):
            M.finish_appliance(self.args)

    def test_copy_cap_is_exact_and_does_not_allow_sparse_oversize(self):
        self.copied()
        with (self.stage / 'kernel').open('wb') as target:
            target.truncate(M.MAX_APPLIANCE_KERNEL + 1)
        with self.assertRaisesRegex(ValueError, 'input_file_shape'):
            M.finish_appliance(self.args)

    def test_prepared_unknown_fields_wrong_source_and_boolean_identity_fail_closed(self):
        self.copied()
        original = M.read_stage(self.stage / 'prepared.json')
        for changed in ({**original, 'private': 'PRIVATE_CANARY'}, {**original, 'source': 'b' * 40},
                        {**original, 'source_identity': [True] * 9}, {**original, 'version': True}):
            self.rewrite('prepared.json', changed)
            with self.subTest(keys=set(changed)), self.assertRaisesRegex(ValueError, 'appliance_stage_binding'):
                M.finish_appliance(self.args)

    def test_stage_files_require_private_regular_single_link_ownership(self):
        self.copied()
        path = self.stage / 'kernel'
        path.chmod(0o644)
        with self.assertRaisesRegex(ValueError, 'appliance_stage_metadata'):
            M.finish_appliance(self.args)
        path.chmod(0o600)
        os.link(path, self.root / 'hardlink')
        with self.assertRaisesRegex(ValueError, 'appliance_stage_metadata'):
            M.finish_appliance(self.args)
        path.unlink()
        path.symlink_to(self.kernel)
        with self.assertRaisesRegex(ValueError, 'appliance_stage_metadata'):
            M.finish_appliance(self.args)

    def test_private_metadata_bound_duplicate_fields_and_replacement_are_rejected(self):
        self.copied()
        path = self.stage / 'prepared.json'
        for content, reason in ((b' ' * 16385, 'appliance_stage_bound'),
                                (b'{"version":1,"version":1}', 'duplicate_json_key')):
            path.write_bytes(content)
            with self.subTest(reason=reason), self.assertRaisesRegex(ValueError, reason):
                M.read_stage(path)
        path.unlink()
        path.symlink_to(self.kernel)
        with self.assertRaisesRegex(ValueError, 'appliance_stage_metadata'):
            M.read_stage(path)

    def test_expired_or_future_stage_budget_is_not_restarted(self):
        self.copied()
        original = M.read_stage(self.stage / 'prepared.json')
        for started in (time.monotonic_ns() - (M.BUILD_SECONDS + 1) * 10 ** 9,
                        time.monotonic_ns() + 60 * 10 ** 9, True):
            self.rewrite('prepared.json', {**original, 'started_monotonic_ns': started})
            with mock.patch.object(M, 'digest') as hashed, self.assertRaisesRegex(ValueError, 'build_deadline'):
                M.finish_appliance(self.args)
            hashed.assert_not_called()
        self.assertIsNone(M.DEADLINE.get())

    def test_adopt_moves_stage_under_existing_cleanup_and_exports_only_three_fixed_variables(self):
        self.ready()
        prepared = M.read_stage(self.stage / 'prepared.json')
        output = self.root / 'payload'
        output.mkdir()
        state = M.adopt_appliance(output, 'a' * 40)
        self.assertFalse(self.stage.exists())
        self.assertEqual(state['deadline'], prepared['started_monotonic_ns'] / 1e9 + 1200)
        token = M.APPLIANCE.set(state)
        try:
            with mock.patch.dict(M.os.environ, {'SUPERMIN_KERNEL': '/PRIVATE_CANARY', 'SECRET': 'canary'}):
                self.assertEqual(M.appliance_environment(), dict(
                    SUPERMIN_KERNEL=str(output / 'appliance/kernel'), SUPERMIN_MODULES=str(self.modules),
                    SUPERMIN_KERNEL_VERSION=self.release))
        finally:
            M.APPLIANCE.reset(token)

    def test_only_guestfish_receives_validated_supermin_not_other_children(self):
        expected = {'SUPERMIN_KERNEL': '/public/staged-kernel', 'SUPERMIN_MODULES': '/public/modules',
                    'SUPERMIN_KERNEL_VERSION': self.release}
        original_popen = M.subprocess.Popen
        seen = []
        def spawn(argv, **kwargs):
            seen.append(kwargs['env'])
            return original_popen([sys.executable, '-c', 'pass'], **kwargs)
        with mock.patch.object(M, 'appliance_environment', return_value=expected) as bound, \
                mock.patch.object(M, 'bound_hypervisor', return_value='/public/qemu'), \
                mock.patch.object(M.subprocess, 'Popen', side_effect=spawn), \
                mock.patch.dict(M.os.environ, {'SUPERMIN_KERNEL': 'PRIVATE_CANARY'}):
            M.command(['guestfish', 'public-fixture'])
            M.command([sys.executable, '-c', 'pass'])
        bound.assert_called_once_with()
        self.assertEqual({key: seen[0][key] for key in expected}, expected)
        self.assertEqual(seen[0]['LIBGUESTFS_HV'], '/public/qemu')
        self.assertNotIn('LIBGUESTFS_HV', seen[1])
        self.assertTrue(set(expected).isdisjoint(seen[1]))
        self.assertNotIn('PRIVATE_CANARY', json.dumps(seen))

    def test_missing_binding_or_changed_staged_bytes_rejects_before_guestfish_spawn(self):
        with mock.patch.object(M.subprocess, 'Popen') as spawned, \
                mock.patch.object(M, 'bound_hypervisor', return_value='/public/qemu'), \
                self.assertRaisesRegex(ValueError, 'appliance_stage_binding'):
            M.command(['guestfish'])
        spawned.assert_not_called()
        self.ready()
        changed = bytearray(self.payload)
        changed[-1] = 1
        (self.stage / 'kernel').chmod(0o600)
        (self.stage / 'kernel').write_bytes(changed)
        (self.stage / 'kernel').chmod(0o400)
        with self.assertRaisesRegex(ValueError, 'appliance_stage_binding'):
            M.validate_appliance(self.stage, 'a' * 40, ready=True)

    def test_cleanup_is_exact_nonrecursive_and_does_not_follow_unknown_entries(self):
        self.ready()
        (self.stage / 'unknown').write_bytes(b'PRIVATE_CANARY')
        with self.assertRaisesRegex(ValueError, 'appliance_stage_binding'):
            M.cleanup_appliance(self.args)
        (self.stage / 'unknown').unlink()
        M.cleanup_appliance(self.args)
        self.assertFalse(self.stage.exists())
        self.assertTrue(self.kernel.exists())
        M.cleanup_appliance(self.args)

    def test_execute_adopts_before_original_failure_and_cleans_stage_without_resetting_budget(self):
        self.ready()
        start = M.read_stage(self.stage / 'prepared.json')['started_monotonic_ns']
        work = self.root / 'work'
        work.mkdir()
        original = ValueError('download_digest')
        def fail(*_args):
            self.assertEqual(M.DEADLINE.get(), start / 1e9 + M.BUILD_SECONDS)
            self.assertFalse(self.stage.exists())
            self.assertIsNotNone(M.APPLIANCE.get())
            raise original
        with mock.patch.object(M, 'hosted_output', return_value=work), \
                mock.patch.object(M, 'verify_kvm_launch', return_value=launch_receipt()), \
                mock.patch.object(M, 'tool_inventory', return_value={}), \
                mock.patch.object(M, 'qmp_preflight'), \
                mock.patch.object(M, 'appliance_preflight', return_value={}), \
                mock.patch.object(M, 'fetch', side_effect=fail), self.assertRaises(ValueError) as raised:
            M.execute(SimpleNamespace(**vars(self.args), work=str(work)))
        self.assertIs(raised.exception, original)
        value = json.loads((work / 'evidence/cleanup.json').read_text())
        self.assertTrue(value['owned_scratch_removed'])
        self.assertEqual(value['appliance_kernel']['selection'], 'explicit_host_kernel')
        self.assertFalse(value['appliance_kernel']['appliance_boot_verified'])
        self.assertIsNone(M.DEADLINE.get())
        self.assertIsNone(M.APPLIANCE.get())

    def test_workflow_privilege_is_only_bounded_read_into_exclusive_user_output(self):
        raw = (M.ROOT / '.github/workflows/protected-resident-image.yml').read_text()
        self.assertIn('sudo -n /usr/bin/timeout --kill-after=2s 15s /usr/bin/dd', raw)
        self.assertIn('iflag=nofollow,count_bytes', raw)
        self.assertIn('count=67108865 bs=1048576 status=none', raw)
        self.assertIn('set -o noclobber', raw)
        self.assertIn('>"$appliance_stage/kernel" 2>/dev/null', raw)
        self.assertNotIn('of=', raw)
        self.assertNotIn('sudo -n guestfish', raw)
        self.assertNotIn('chmod /boot', raw)
        self.assertIn('cleanup-appliance', raw)
        self.assertEqual(M.BUILD_SECONDS, 1200)

    def test_cli_staging_failures_expose_only_closed_action_and_reason(self):
        for action, function in (('prepare-appliance', 'prepare_appliance'),
                                 ('finish-appliance', 'finish_appliance'),
                                 ('cleanup-appliance', 'cleanup_appliance'), ('execute', 'execute')):
            for error, reason in ((ValueError('appliance_stage_binding'), 'appliance_stage_binding'),
                                  (ValueError('PRIVATE_CANARY'), 'unclassified'),
                                  (OSError('PRIVATE_CANARY'), 'io_error'),
                                  (M.subprocess.CalledProcessError(1, ['PRIVATE_CANARY']), 'unclassified')):
                stdout, stderr = io.StringIO(), io.StringIO()
                with self.subTest(action=action, reason=reason), \
                        mock.patch.object(sys, 'argv', ['image', action, '--expected-source', 'a' * 40,
                                                       '--work', '/PRIVATE_CANARY', '--yes']), \
                        mock.patch.object(sys, 'stdout', stdout), mock.patch.object(sys, 'stderr', stderr), \
                        mock.patch.object(M, function, side_effect=error):
                    self.assertEqual(M.main(), 1)
                self.assertEqual(stdout.getvalue(), '')
                self.assertEqual(stderr.getvalue(),
                    'protected_resident_image_failed action=' + action + ' reason=' + reason + '\n')
                self.assertNotIn('PRIVATE_CANARY', stderr.getvalue())

    def test_stage_path_requires_hosted_nonroot_and_numeric_run_id(self):
        environment = dict(GITHUB_ACTIONS='true', RUNNER_ENVIRONMENT='github-hosted',
                           RUNNER_OS='Linux', GITHUB_RUN_ID='123', RUNNER_TEMP=str(self.root))
        with mock.patch.dict(M.os.environ, environment, clear=True), \
                mock.patch.object(M.os, 'geteuid', return_value=1234):
            self.assertEqual(self.real_stage_path(), self.root / 'protected-resident-appliance-123')
            for run in ('', '../private', '1\n', '1' * 21):
                with mock.patch.dict(M.os.environ, {'GITHUB_RUN_ID': run}), \
                        self.assertRaisesRegex(ValueError, 'appliance_stage_path'):
                    self.real_stage_path()
            for changed in ({'GITHUB_ACTIONS': 'false'}, {'RUNNER_ENVIRONMENT': 'self-hosted'}):
                with mock.patch.dict(M.os.environ, changed), self.assertRaisesRegex(ValueError, 'hosted_only'):
                    self.real_stage_path()
            for temporary in ('', '.', 'relative/path'):
                with mock.patch.dict(M.os.environ, {'RUNNER_TEMP': temporary}), \
                        self.assertRaisesRegex(ValueError, 'appliance_stage_path'):
                    self.real_stage_path()
            with mock.patch.object(M.os, 'geteuid', return_value=0), \
                    self.assertRaisesRegex(ValueError, 'hosted_only'):
                self.real_stage_path()


class QmpAdmission(unittest.TestCase):
    def frames(self):
        return [dict(QMP=dict(version=dict(qemu=dict(major=8, minor=2, micro=2),
                                            package='public fixture'), capabilities=['oob'])),
                {'return': {}, 'id': 'capabilities'},
                {'return': {'present': True, 'enabled': True}, 'id': 'kvm'},
                {'return': {}, 'id': 'quit'}]

    def shutdown(self):
        return dict(event='SHUTDOWN', data=dict(guest=False, reason='host-qmp-quit'),
                    timestamp=dict(seconds=123, microseconds=456))

    def raw(self, values=None):
        return b''.join(json.dumps(value).encode() + b'\r\n'
                        for value in (self.frames() if values is None else values))

    def call(self, observed=None, *, output=None, error=None, capture=None):
        observed = M.qmp_observation() if observed is None else observed
        def run(argv, **kwargs):
            source = kwargs['qmp_input']
            info = os.fstat(source.fileno())
            self.assertTrue(stat.S_ISREG(info.st_mode))
            self.assertEqual(stat.S_IMODE(info.st_mode), 0o600)
            self.assertEqual(info.st_nlink, 0)
            self.assertEqual(source.tell(), 0)
            self.assertEqual(source.read(), M.QMP_COMMANDS)
            self.assertEqual(kwargs['timeout'], 15)
            self.assertEqual(kwargs['maximum'], 32768)
            self.assertEqual(kwargs['operation'], M.QMP_OPERATION)
            if capture is not None:
                capture.append((argv, source))
            if error is not None:
                raise error
            return self.raw() if output is None else output
        with mock.patch.object(M, 'bind_hypervisor', return_value='a' * 64), \
                mock.patch.object(M, 'bound_hypervisor', return_value='/usr/bin/qemu-system-x86_64'), \
                mock.patch.object(M, 'command', side_effect=run):
            M.qmp_preflight({}, observed)
        return observed

    def test_exact_greeting_ordered_replies_and_both_documented_quit_endings(self):
        cases = [self.frames(), self.frames() + [self.shutdown()],
                 self.frames()[:3] + [self.shutdown()],
                 self.frames()[:3] + [self.shutdown(), self.frames()[3]]]
        for frames in cases:
            with self.subTest(length=len(frames)):
                self.assertEqual(M.qmp_result(self.raw(frames)), {'present': True, 'enabled': True})

    def test_missing_duplicate_reordered_ids_and_error_response_are_rejected(self):
        frames = self.frames()
        cases = [frames[:3], frames + [frames[3]], [frames[0], frames[2], frames[1], frames[3]],
                 [frames[0], frames[1], {'return': frames[2]['return'], 'id': 'PRIVATE_CANARY'}, frames[3]],
                 [frames[0], frames[1], {'error': {'class': 'GenericError', 'desc': 'PRIVATE_CANARY'},
                                       'id': 'kvm'}, frames[3]]]
        for values in cases:
            with self.subTest(values=values), self.assertRaisesRegex(ValueError, '^qmp_protocol$'):
                M.qmp_result(self.raw(values))

    def test_strict_booleans_closed_result_keys_and_greeting_types(self):
        for result in ({'present': 1, 'enabled': True}, {'present': True, 'enabled': 'true'},
                       {'present': True}, {'present': True, 'enabled': True, 'secret': 'PRIVATE_CANARY'}):
            frames = self.frames()
            frames[2]['return'] = result
            with self.assertRaisesRegex(ValueError, '^qmp_protocol$'):
                M.qmp_result(self.raw(frames))
        for change in ({'version': {}}, {'capabilities': ['PRIVATE_CANARY']},
                       {'extra': 'PRIVATE_CANARY'}, {'capabilities': {}}):
            frames = self.frames()
            frames[0]['QMP'].update(change)
            with self.assertRaisesRegex(ValueError, '^qmp_protocol$'):
                M.qmp_result(self.raw(frames))

    def test_bounds_duplicate_keys_nan_deep_json_and_truncated_output_fail_closed(self):
        raw = self.raw()
        cases = [b'', raw[:-1], b'x' * (M.MAX_QMP + 1),
                 raw.replace(b'"enabled": true', b'"enabled": true, "enabled": false'),
                 raw.replace(b'"enabled": true', b'"enabled": NaN'),
                 b'[' * 2000 + b'0' + b']' * 2000 + b'\n{}\n{}\n{}\n',
                 b'\xff\n{}\n{}\n{}\n', raw + b'PRIVATE_CANARY\n']
        for value in cases:
            with self.assertRaisesRegex(ValueError, '^qmp_protocol$'):
                M.qmp_result(value)

    def test_only_one_fixed_shutdown_after_query_is_accepted(self):
        for change in ({'event': 'STOP'}, {'data': {'guest': True, 'reason': 'host-qmp-quit'}},
                       {'data': {'guest': False, 'reason': 'guest-shutdown'}},
                       {'timestamp': {'seconds': True, 'microseconds': 0}},
                       {'extra': 'PRIVATE_CANARY'}):
            event = self.shutdown()
            event.update(change)
            with self.assertRaisesRegex(ValueError, '^qmp_protocol$'):
                M.qmp_result(self.raw(self.frames()[:3] + [event]))
        for values in ([self.frames()[0], self.shutdown(), *self.frames()[1:3]],
                       [*self.frames()[:3], self.shutdown(), self.shutdown()]):
            with self.assertRaisesRegex(ValueError, '^qmp_protocol$'):
                M.qmp_result(self.raw(values))

    def test_exact_paused_no_disk_no_network_command_and_anonymous_fixed_input(self):
        calls = []
        observed = self.call(capture=calls)
        self.assertEqual(calls[0][0], ['/usr/bin/qemu-system-x86_64', '-no-user-config',
            '-nodefaults', '-S', '-display', 'none', '-nic', 'none', '-serial', 'none',
            '-monitor', 'none', '-machine', 'q35,accel=kvm', '-cpu', 'host', '-m', '128',
            '-smp', '1', '-qmp', 'stdio'])
        self.assertTrue(calls[0][1].closed)
        self.assertEqual([json.loads(line) for line in M.QMP_COMMANDS.splitlines()], [
            {'execute': 'qmp_capabilities', 'id': 'capabilities'},
            {'execute': 'query-kvm', 'id': 'kvm'}, {'execute': 'quit', 'id': 'quit'}])
        self.assertEqual(observed['state'], 'passed')
        self.assertFalse(observed['appliance_boot_verified'])
        self.assertFalse(observed['hardware_attestation'])
        self.assertNotIn('public fixture', json.dumps(observed))

    def test_false_kvm_observations_are_retained_but_never_admit_downloads(self):
        for present, enabled in ((False, False), (True, False), (False, True)):
            frames, observed = self.frames(), M.qmp_observation()
            frames[2]['return'] = dict(present=present, enabled=enabled)
            with self.assertRaisesRegex(ValueError, '^qmp_kvm_unavailable$'):
                self.call(observed, output=self.raw(frames))
            self.assertEqual((observed['present'], observed['enabled']), (present, enabled))
            self.assertEqual(observed['state'], 'failed')

    def test_failure_receipt_survives_exception_without_text_or_fake_returncode(self):
        for error, reason in ((ValueError('command_timeout'), 'command_timeout'),
                              (ValueError('cancelled'), 'cancelled'),
                              (ValueError('PRIVATE_CANARY'), 'unclassified'),
                              (M.CleanupUnconfirmed('process_group_remaining'), 'process_group_remaining')):
            observed, calls = M.qmp_observation(), []
            with self.assertRaises(type(error)) as raised:
                self.call(observed, error=error, capture=calls)
            self.assertIs(raised.exception, error)
            self.assertTrue(calls[0][1].closed)
            self.assertEqual(observed['failure'], reason)
            self.assertIsNone(observed['command'])
            self.assertIsNone(observed['present'])
            self.assertNotIn('PRIVATE_CANARY', json.dumps(observed))
            self.assertNotIn('joined', json.dumps(observed))

    def test_binding_requires_inventory_hash_and_stable_root_owned_file(self):
        with tempfile.TemporaryDirectory() as directory:
            binary = Path(directory) / 'qemu-system-x86_64'
            binary.write_bytes(b'public fixture executable bytes, never run')
            expected = M.digest(binary)['sha256']
            tools = {'observed_tools': {'qemu-system-x86_64': {'binary_sha256': expected}}}
            token = M.HYPERVISOR.set(None)
            try:
                with mock.patch.object(M.shutil, 'which', return_value=str(binary)), \
                        mock.patch.object(M, 'host_identity', return_value=[1, 2]) as identity:
                    self.assertEqual(M.bind_hypervisor(tools), expected)
                    self.assertEqual(M.bound_hypervisor(), str(binary))
                    identity.assert_called_with(binary, maximum=128 * 1024 ** 2)
                    binary.write_bytes(b'changed')
                    with self.assertRaisesRegex(ValueError, '^hypervisor_binding$'):
                        M.bound_hypervisor()
                with mock.patch.object(M.shutil, 'which', return_value=str(binary)), \
                        mock.patch.object(M, 'host_identity', side_effect=ValueError('appliance_host_metadata')), \
                        self.assertRaisesRegex(ValueError, '^appliance_host_metadata$'):
                    M.bind_hypervisor(tools)
            finally:
                M.HYPERVISOR.reset(token)

    def test_identity_change_rejects_even_with_identical_hash(self):
        token = M.HYPERVISOR.set(dict(path=Path('/public/qemu'), identity=[1], sha256='a' * 64))
        try:
            with mock.patch.object(M, 'host_identity', return_value=[2]), \
                    mock.patch.object(M, 'digest') as hashed, \
                    self.assertRaisesRegex(ValueError, '^hypervisor_binding$'):
                M.bound_hypervisor()
            hashed.assert_not_called()
        finally:
            M.HYPERVISOR.reset(token)

    def test_preflight_binding_error_is_retained_before_command_and_never_exports_paths(self):
        observed = M.qmp_observation()
        original = ValueError('PRIVATE_CANARY')
        with mock.patch.object(M, 'bind_hypervisor', side_effect=original), \
                mock.patch.object(M, 'command') as run, self.assertRaises(ValueError) as raised:
            M.qmp_preflight({}, observed)
        run.assert_not_called()
        self.assertIs(raised.exception, original)
        self.assertEqual(observed['state'], 'failed')
        self.assertEqual(observed['failure'], 'unclassified')
        self.assertIsNone(observed['binary_sha256'])
        self.assertNotIn('PRIVATE_CANARY', json.dumps(observed))

    def test_wrong_executable_and_expired_original_deadline_prevent_spawn(self):
        for executable, expired, reason in (('/wrong/qemu', False, 'hypervisor_binding'),
                                             ('/public/qemu', True, 'build_deadline')):
            token = M.DEADLINE.set(time.monotonic() - 1 if expired else None)
            try:
                with tempfile.TemporaryFile(mode='w+b') as source, \
                        mock.patch.object(M, 'bound_hypervisor', return_value='/public/qemu'), \
                        mock.patch.object(M.subprocess, 'Popen') as spawn:
                    source.write(M.QMP_COMMANDS)
                    source.flush()
                    source.seek(0)
                    with self.assertRaisesRegex(ValueError, '^' + reason + '$'):
                        M.command([executable], operation=M.QMP_OPERATION, qmp_input=source, maximum=M.MAX_QMP)
                    spawn.assert_not_called()
            finally:
                M.DEADLINE.reset(token)

    def public_child(self, program, **kwargs):
        # Exercise the actual owned-child runner, substituting only public Python.
        spawn = M.subprocess.Popen
        def start(_argv, **options):
            self.assertEqual(options['env'], M.ENV)
            return spawn([sys.executable, '-c', program], **options)
        with tempfile.TemporaryFile(mode='w+b') as source, \
                mock.patch.object(M, 'bound_hypervisor', return_value='/public/qemu'), \
                mock.patch.object(M.subprocess, 'Popen', side_effect=start):
            source.write(M.QMP_COMMANDS)
            source.flush()
            source.seek(0)
            return M.command(['/public/qemu'], maximum=M.MAX_QMP, operation=M.QMP_OPERATION,
                             qmp_input=source, **kwargs)

    def test_owned_runner_reads_fixed_regular_input_and_keeps_stderr_out_of_json(self):
        program = ('import os,sys; data=sys.stdin.buffer.read(); '
                   f'assert data=={M.QMP_COMMANDS!r}; '
                   f'os.write(1,{self.raw()!r}); os.write(2,b"PRIVATE_CANARY\\n")')
        self.assertEqual(M.qmp_result(self.public_child(program)), {'present': True, 'enabled': True})
        with self.assertRaisesRegex(ValueError, '^command_output_bound$'):
            self.public_child('import os; os.write(2,b"x"*32769)')

    def test_owned_runner_timeout_does_not_report_its_cleanup_sigkill_as_qemu_exit(self):
        with self.assertRaisesRegex(ValueError, '^command_timeout$') as raised:
            self.public_child('import time; time.sleep(10)', timeout=.1)
        self.assertIsNone(M.command_failure(raised.exception))

    def test_owned_runner_natural_failure_has_only_bounded_code_and_closed_context(self):
        with self.assertRaises(M.CommandFailed) as raised:
            self.public_child('import os; os.write(2,b"PRIVATE_CANARY\\n"); raise SystemExit(7)')
        self.assertEqual(M.command_failure(raised.exception),
                         dict(operation='qmp_kvm_preflight', returncode=7, stderr_class='unclassified'))

    def test_qemu_stderr_exact_fixed_patterns_chunking_and_closed_errno_classes(self):
        for line, label in M.QEMU_STDERR_PATTERNS.items():
            parser = M.QemuStderr()
            parser.feed(line[:11])
            parser.feed(line[11:] + b'\r\n')
            self.assertEqual(parser.finish(), label)
            self.assertEqual(M.command_failure(M.CommandFailed(1, M.QMP_OPERATION, label))['stderr_class'], label)
            self.assertIsNone(M.command_failure(M.CommandFailed(1, 'inspect_roots', label))['stderr_class'])
        parser = M.QemuStderr()
        parser.feed(b'Could not access KVM kernel module: Permission denied\n'
                    b'qemu-system-x86_64: failed to initialize kvm: Permission denied\n')
        self.assertEqual(parser.finish(), 'kvm_permission_denied')

    def test_qemu_stderr_unknown_prefix_suffix_overlong_and_ambiguity_do_not_leak(self):
        line = b'qemu-system-x86_64: failed to initialize kvm: Permission denied'
        for raw in (b'PRIVATE_CANARY: ' + line, line + b' PRIVATE_CANARY',
                    b'qemu-system-x86_64: -machine q35,accel=kvm: failed to initialize kvm: Permission denied',
                    b'qemu-system-x86_64: failed to initialize kvm: PRIVATE_CANARY',
                    b'x' * 4097 + line + b'\n',
                    b'libguestfs: error: force_kvm supplied but kvm not available.\n'):
            parser = M.QemuStderr()
            parser.feed(raw)
            self.assertEqual(parser.finish(), 'unclassified')
        parser = M.QemuStderr()
        parser.feed(line + b'\nqemu-system-x86_64: failed to initialize kvm: No such device\n')
        self.assertEqual(parser.finish(), 'ambiguous')

    def test_qemu_failure_class_comes_only_from_stderr_not_stdout(self):
        line = b'qemu-system-x86_64: failed to initialize kvm: Permission denied\n'
        for descriptor, label in ((1, 'unclassified'), (2, 'kvm_permission_denied')):
            with self.assertRaises(M.CommandFailed) as raised:
                self.public_child(f'import os; os.write({descriptor},{line!r}); raise SystemExit(1)')
            self.assertEqual(M.command_failure(raised.exception)['stderr_class'], label)

    def test_fixed_input_rejects_named_file_wrong_bytes_and_incorrect_operation(self):
        with tempfile.TemporaryDirectory() as directory, mock.patch.object(M.subprocess, 'Popen') as spawn:
            path = Path(directory) / 'input'
            path.write_bytes(M.QMP_COMMANDS)
            path.chmod(0o600)
            with path.open('rb') as source, self.assertRaisesRegex(ValueError, '^qmp_input$'):
                M.command(['/public/qemu'], operation=M.QMP_OPERATION, qmp_input=source, maximum=M.MAX_QMP)
            with tempfile.TemporaryFile(mode='w+b') as source:
                source.write(b'PRIVATE_CANARY')
                source.seek(0)
                with self.assertRaisesRegex(ValueError, '^qmp_input$'):
                    M.command(['/public/qemu'], operation=M.QMP_OPERATION, qmp_input=source, maximum=M.MAX_QMP)
                with self.assertRaisesRegex(ValueError, '^qmp_input$'):
                    M.command(['/public/qemu'], qmp_input=source)
            spawn.assert_not_called()

    def test_execute_retains_qmp_failure_before_download_and_quarantines_uncertain_cleanup(self):
        for error in (ValueError('command_timeout'), M.CleanupUnconfirmed('process_group_remaining')):
            with tempfile.TemporaryDirectory() as directory:
                original_deadline = time.monotonic() + 900
                def reject(_tools, observed):
                    self.assertEqual(M.DEADLINE.get(), original_deadline)
                    observed.update(state='failed', failure=M.failure_reason(error))
                    raise error
                with mock.patch.object(M, 'hosted_output', return_value=Path(directory)), \
                        mock.patch.object(M, 'verify_kvm_launch', return_value=launch_receipt()), \
                        mock.patch.object(M, 'adopt_appliance', return_value=dict(
                            deadline=original_deadline, receipt={'version': 1})), \
                        mock.patch.object(M, 'source_binding', return_value={'revision': 'a' * 40}), \
                        mock.patch.object(M, 'tool_inventory', return_value={}), \
                        mock.patch.object(M, 'appliance_preflight', return_value={}), \
                        mock.patch.object(M, 'qmp_preflight', side_effect=reject), \
                        mock.patch.object(M, 'fetch') as download, self.assertRaises(type(error)) as raised:
                    M.execute(SimpleNamespace(yes=True, work=directory, expected_source='a' * 40))
                self.assertIs(raised.exception, error)
                download.assert_not_called()
                value = json.loads((Path(directory) / 'evidence/cleanup.json').read_text())
                safe = not isinstance(error, M.CleanupUnconfirmed)
                self.assertEqual(value['qmp_kvm_preflight']['state'], 'failed')
                self.assertEqual(value['failure']['stage'], 'qmp_kvm_preflight')
                self.assertEqual(value['child_leaders_reaped'], safe)
                self.assertEqual(value['owned_scratch_removed'], safe)
                self.assertFalse(value['boot_pair_verified'])
                self.assertIsNone(M.HYPERVISOR.get())
                self.assertIsNone(M.DEADLINE.get())


class OriginalQmpObservation(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name)
        self.scratch = self.root / 'temporary'
        self.scratch.mkdir(mode=0o700)
        self.binary = Path(sys.executable).resolve(strict=True)
        self.binding = dict(path=self.binary, identity=M.host_identity(self.binary, maximum=128 * 1024 ** 2),
                            sha256=M.digest(self.binary, maximum=128 * 1024 ** 2)['sha256'])
        self.tokens = [(M.SCRATCH, M.SCRATCH.set(self.scratch)),
                       (M.HYPERVISOR, M.HYPERVISOR.set(self.binding)),
                       (M.QMP_CAPTURE, M.QMP_CAPTURE.set(None))]
        with mock.patch.object(M, 'context_snapshot', return_value=dict.fromkeys(M.CONTEXT_KEYS, 'a' * 64)):
            self.value = M.prepare_qmp_capture()
        self.assertIn('wrapper', self.value)

    def tearDown(self):
        for variable, token in reversed(self.tokens):
            variable.reset(token)
        self.temporary.cleanup()

    def config(self):
        return dict(binary=str(self.binary), identity=self.binding['identity'], sha256=self.binding['sha256'],
                    scratch=str(self.scratch), capture=str(self.value['directory']),
                    interpreter=self.value['interpreter'])

    def error_file(self, name='cmderr1.txt', data=b''):
        parent = self.scratch / 'libguestfsABC123'
        parent.mkdir(mode=0o700, exist_ok=True)
        path = parent / name
        path.write_bytes(data)
        path.chmod(0o600)
        return path

    def retain(self, path):
        original_stat, original_link = os.fstat, os.readlink
        with path.open('rb') as source, \
                mock.patch.object(M.os, 'fstat', side_effect=lambda fd:
                    original_stat(source.fileno()) if fd == 2 else original_stat(fd)), \
                mock.patch.object(M.os, 'readlink', side_effect=lambda target, **kwargs:
                    str(path) if str(target) == '/proc/self/fd/2' else original_link(target, **kwargs)):
            M.retain_probe_stderr(self.scratch, self.value['directory'])

    def cache(self, raw=b'{"return":{"present":true,"enabled":false}}\n'):
        directory = self.scratch / ('.guestfs-' + str(os.geteuid()))
        directory.mkdir(mode=0o755, exist_ok=True)
        directory.chmod(0o755)
        name = 'qemu-' + str(self.value['size']) + '-' + str(self.value['mtime']) + '.query-kvm'
        path = directory / name
        path.write_bytes(raw)
        path.chmod(0o600)
        return path

    def observed_pair(self):
        for index in (1, 2):
            path = self.error_file('cmderr' + str(index) + '.txt',
                b'PRIVATE_CANARY unknown text\nqemu-system-x86_64: failed to initialize kvm: Permission denied\n')
            self.retain(path)
            path.unlink()
        self.cache()

    def test_retains_actual_inode_after_original_unlink_without_stream_replacement(self):
        path = self.error_file(data=b'public stderr')
        original = path.stat()
        self.retain(path)
        retained = self.value['directory'] / 'probe-1'
        self.assertEqual((retained.stat().st_dev, retained.stat().st_ino),
                         (original.st_dev, original.st_ino))
        self.assertEqual(path.stat().st_nlink, 2)
        path.unlink()
        self.assertEqual(M.capture_read(retained, M.MAX_QMP), b'public stderr')
        self.assertEqual((self.value['directory'] / 'probe-1.verified').read_bytes(), b'')

    def test_only_two_retained_inodes_and_third_is_not_captured(self):
        for index in (1, 2):
            self.retain(self.error_file('cmderr' + str(index) + '.txt'))
        third = self.error_file('cmderr3.txt')
        with self.assertRaisesRegex(ValueError, '^qmp_capture_bound$'):
            self.retain(third)
        self.assertEqual(third.stat().st_nlink, 1)
        self.assertEqual(len(list(self.value['directory'].iterdir())), 4)

    def test_rejects_wrong_fd_identity_and_nonregular_fd(self):
        path = self.error_file()
        other = self.error_file('cmderr2.txt')
        for info in (other.stat(), path.parent.stat()):
            with self.subTest(mode=info.st_mode), \
                    mock.patch.object(M.os, 'readlink', return_value=str(path)), \
                    mock.patch.object(M.os, 'fstat', return_value=info), \
                    self.assertRaisesRegex(ValueError, '^qmp_capture_binding$'):
                M.retain_probe_stderr(self.scratch, self.value['directory'])
        self.assertEqual(list(self.value['directory'].iterdir()), [])

    def test_rejects_wrong_paths_symlinks_modes_owner_and_existing_links(self):
        path = self.error_file()
        for name in ('other.txt', 'cmderr0.txt', 'cmderr1.txt (deleted)', 'cmderr12345678901.txt'):
            with self.subTest(name=name), mock.patch.object(M.os, 'readlink', return_value=str(path.with_name(name))), \
                    self.assertRaises(ValueError):
                M.retain_probe_stderr(self.scratch, self.value['directory'])
        for mode in (0o644, 0o660, 0o400):
            path.chmod(mode)
            with self.subTest(mode=mode), self.assertRaises(ValueError):
                self.retain(path)
        path.chmod(0o600)
        with mock.patch.object(M.os, 'geteuid', return_value=os.geteuid() + 1), self.assertRaises(ValueError):
            self.retain(path)
        alias = path.with_name('alias')
        os.link(path, alias)
        with self.assertRaises(ValueError):
            self.retain(path)
        alias.unlink()
        path.rename(alias)
        path.symlink_to(alias)
        with self.assertRaises(ValueError):
            self.retain(path)

    def test_rejects_nonprivate_or_replaced_parent_and_capture_directory(self):
        path = self.error_file()
        for directory in (path.parent, self.scratch, self.value['directory']):
            directory.chmod(0o755)
            with self.subTest(directory=directory.name), self.assertRaises(ValueError):
                self.retain(path)
            directory.chmod(0o700)
        directory = self.value['directory']
        directory.rename(self.scratch / 'moved')
        directory.symlink_to(self.scratch / 'moved')
        with self.assertRaises(ValueError):
            self.retain(path)

    def test_post_link_identity_change_never_publishes_verified_marker(self):
        path = self.error_file()
        original_link = os.link
        def replace(source, target, **kwargs):
            original_link(source, target, **kwargs)
            target.unlink()
            target.write_bytes(b'PRIVATE_CANARY')
            target.chmod(0o600)
        with mock.patch.object(M.os, 'link', side_effect=replace), self.assertRaises(ValueError):
            self.retain(path)
        self.assertFalse((self.value['directory'] / 'probe-1.verified').exists())
        self.cache()
        M.project_qmp_capture(self.value, joined=True)
        self.assertEqual(self.value['receipt']['probe_stderr'], [])
        self.assertEqual(self.value['receipt']['state'], 'incomplete')

    def test_nonprobe_passthrough_never_inspects_stderr_and_preserves_arguments_environment(self):
        arguments = ['-display', 'none', '-help']
        before = dict(os.environ)
        with mock.patch.object(M, 'retain_probe_stderr') as retain, \
                mock.patch.object(M.os, 'execv') as execute, mock.patch.object(M.signal, 'signal'):
            M.hypervisor_exec(self.config(), arguments)
        retain.assert_not_called()
        execute.assert_called_once_with(str(self.binary), [str(self.binary), *arguments])
        self.assertEqual(dict(os.environ), before)
        self.assertEqual(arguments, ['-display', 'none', '-help'])

    def test_exact_probe_only_and_capture_failure_preserves_exec(self):
        original = list(M.LIBGUESTFS_QMP_ARGV)
        variants = [original, original + ['-S'], original[:-1],
                    ['-display', 'none', '-machine', 'q35,accel=kvm', '-qmp', 'stdio']]
        for arguments in variants:
            with self.subTest(arguments=arguments), \
                    mock.patch.object(M, 'retain_probe_stderr', side_effect=PermissionError('PRIVATE_CANARY')) as retain, \
                    mock.patch.object(M.os, 'execv') as execute, mock.patch.object(M.signal, 'signal'):
                M.hypervisor_exec(self.config(), arguments)
            self.assertEqual(retain.call_count, int(arguments == original))
            execute.assert_called_once_with(str(self.binary), [str(self.binary), *arguments])
        self.assertEqual((self.value['directory'] / 'incomplete').read_bytes(), b'')

    def test_restores_only_python_changed_signal_dispositions_before_exec(self):
        order = []
        with mock.patch.object(M.signal, 'signal', side_effect=lambda number, value: order.append((number, value))), \
                mock.patch.object(M.os, 'execv', side_effect=lambda *_: order.append('exec')):
            M.hypervisor_exec(self.config(), ['-help'])
        expected = [(getattr(signal, name), signal.SIG_DFL) for name in ('SIGPIPE', 'SIGXFZ', 'SIGXFSZ')
                    if hasattr(signal, name)]
        self.assertEqual(order, [*expected, 'exec'])

    def test_changed_real_binary_binding_rejects_before_any_exec_or_capture(self):
        config = self.config()
        config['sha256'] = '0' * 64
        with mock.patch.object(M.os, 'execv') as execute, \
                mock.patch.object(M, 'retain_probe_stderr') as retain, \
                self.assertRaisesRegex(ValueError, '^hypervisor_binding$'):
            M.hypervisor_exec(config, list(M.LIBGUESTFS_QMP_ARGV))
        execute.assert_not_called()
        retain.assert_not_called()

    def test_generated_script_loads_exact_source_without_bytecode_or_environment_change(self):
        raw = self.value['wrapper'].read_bytes()
        self.assertTrue(raw.startswith(b'#!/usr/bin/python3 -I\n'))
        self.assertIn(b'sys.dont_write_bytecode = True', raw)
        before = dict(os.environ)
        caches = set(HERE.glob('__pycache__/*'))
        with mock.patch.object(sys, 'argv', [str(self.value['wrapper']), '-help']), \
                mock.patch.object(os, 'execv') as execute, mock.patch.object(signal, 'signal'), \
                mock.patch.object(os, '_exit', side_effect=AssertionError('unexpected script rejection')):
            exec(compile(raw, '<fixed-public-trampoline>', 'exec'), {})
        execute.assert_called_once_with(str(self.binary), [str(self.binary), '-help'])
        self.assertEqual(dict(os.environ), before)
        self.assertEqual(set(HERE.glob('__pycache__/*')), caches)

    def test_generated_script_rejects_changed_builder_hash_without_raw_traceback(self):
        raw = self.value['wrapper'].read_bytes()
        source_hash = M.digest(HERE / 'protected-resident-image.py')['sha256'].encode()
        self.assertIn(source_hash, raw)
        raw = raw.replace(source_hash, b'0' * 64)
        with mock.patch.object(os, 'execv') as execute, \
                mock.patch.object(os, '_exit', side_effect=SystemExit(126)), \
                self.assertRaises(SystemExit) as raised:
            exec(compile(raw, '<fixed-public-trampoline>', 'exec'), {})
        self.assertEqual(raised.exception.code, 126)
        execute.assert_not_called()

    def test_guestfish_uses_same_validated_wrapper_and_other_children_do_not(self):
        M.QMP_CAPTURE.set(self.value)
        with mock.patch.object(M, 'command', return_value=b'') as run:
            M.guestfish(Path('/public/root.raw'), [['inspect-os']], operation='inspect_roots')
        argv = run.call_args.args[0]
        self.assertEqual(argv[argv.index('set-hv') + 1], str(self.value['wrapper']))
        original_popen, environments = M.subprocess.Popen, []
        def spawn(_argv, **kwargs):
            environments.append(kwargs['env'])
            return original_popen([sys.executable, '-c', 'pass'], **kwargs)
        with mock.patch.object(M, 'appliance_environment', return_value={}), \
                mock.patch.object(M.subprocess, 'Popen', side_effect=spawn):
            M.command(argv, operation='inspect_roots')
            M.command([sys.executable, '-c', 'pass'])
        self.assertEqual(environments[0]['LIBGUESTFS_HV'], str(self.value['wrapper']))
        self.assertNotIn('LIBGUESTFS_HV', environments[1])

    def test_changed_wrapper_is_not_executed_and_falls_back_to_validated_real_binary(self):
        M.QMP_CAPTURE.set(self.value)
        self.value['wrapper'].chmod(0o700)
        self.value['wrapper'].write_bytes(b'PRIVATE_CANARY')
        self.assertEqual(M.guestfish_hypervisor(), str(self.binary))
        self.assertEqual(self.value['receipt']['state'], 'incomplete')

    def test_changed_interpreter_refuses_trampoline_and_never_executes_unbound_program(self):
        M.QMP_CAPTURE.set(self.value)
        changed = {**self.value['interpreter'], 'sha256': '0' * 64}
        with mock.patch.object(M, 'capture_interpreter', return_value=changed), \
                mock.patch.object(M.os, 'execv') as execute:
            self.assertEqual(M.guestfish_hypervisor(), str(self.binary))
            with self.assertRaisesRegex(ValueError, '^qmp_capture_binding$'):
                M.hypervisor_exec(self.config(), ['-help'])
        execute.assert_not_called()
        self.assertEqual(self.value['receipt']['state'], 'incomplete')

    def test_different_argv_and_handle_creation_hypervisors_reject_before_spawn(self):
        M.QMP_CAPTURE.set(self.value)
        with mock.patch.object(M, 'guestfish_hypervisor',
                               side_effect=[str(self.value['wrapper']), str(self.binary)]), \
                mock.patch.object(M.subprocess, 'Popen') as spawn, \
                self.assertRaisesRegex(ValueError, '^hypervisor_binding$'):
            M.guestfish(Path('/public/root.raw'), [['inspect-os']], operation='inspect_roots')
        spawn.assert_not_called()

    def test_two_original_stderr_classes_and_cache_booleans_remain_uncorrelated(self):
        self.observed_pair()
        M.project_qmp_capture(self.value, joined=True)
        observed = self.value['receipt']
        self.assertEqual(observed['state'], 'observed')
        self.assertEqual(observed['probe_stderr'], [dict(slot=slot, stderr_class='kvm_permission_denied',
            failure_boundary={'open': 'unobserved', 'init': 'eacces'}, pre_exec=M.pre_exec_unavailable())
            for slot in (1, 2)])
        self.assertEqual(observed['query_kvm'], dict(state='observed', present=True, enabled=False))
        self.assertIs(observed['query_correlated'], False)
        self.assertIs(observed['appliance_boot_verified'], False)
        self.assertIs(observed['diagnostic_only'], True)
        public = json.dumps(observed)
        for canary in ('PRIVATE_CANARY', str(self.root), 'cmderr', 'Permission denied'):
            self.assertNotIn(canary, public)

    def test_missing_slot_or_gap_marker_never_implies_query_identity_or_completeness(self):
        path = self.error_file(data=b'unknown')
        self.retain(path)
        path.unlink()
        self.cache()
        M.project_qmp_capture(self.value, joined=True)
        self.assertEqual(self.value['receipt']['state'], 'incomplete')
        self.assertFalse(self.value['receipt']['query_correlated'])
        (self.value['directory'] / 'probe-1').rename(self.value['directory'] / 'probe-2')
        (self.value['directory'] / 'probe-1.verified').rename(self.value['directory'] / 'probe-2.verified')
        M.project_qmp_capture(self.value, joined=True)
        self.assertEqual(self.value['receipt']['probe_stderr'], [dict(slot=2, stderr_class='unclassified',
            failure_boundary={'open': 'unobserved', 'init': 'unobserved'}, pre_exec=M.pre_exec_unavailable())])
        self.assertEqual(self.value['receipt']['state'], 'incomplete')
        self.assertFalse(self.value['receipt']['query_correlated'])

    def test_cache_parser_rejects_malformed_extra_duplicate_and_nonboolean_values(self):
        for raw in (b'', b'PRIVATE_CANARY', b'{"return":{"present":true,"enabled":"false"}}',
                    b'{"return":{"present":1,"enabled":false}}', b'{"return":null}',
                    b'{"return":{"present":true,"enabled":false},"id":"private"}',
                    b'{"return":{"present":true,"enabled":false,"extra":1}}',
                    b'{"return":{"present":true,"enabled":false,"enabled":true}}',
                    b'{"return":{"present":NaN,"enabled":false}}', b' ' * 4097):
            with self.subTest(raw=raw[:40]):
                self.cache(raw)
                M.project_qmp_capture(self.value, joined=True)
                self.assertEqual(self.value['receipt']['query_kvm'],
                                 dict(state='unavailable', present=None, enabled=None))
                self.assertEqual(self.value['receipt']['state'], 'incomplete')

    def test_reprojection_clears_old_cache_and_stderr_on_missing_file_or_expired_budget(self):
        self.observed_pair()
        M.project_qmp_capture(self.value, joined=True)
        self.assertEqual(self.value['receipt']['state'], 'observed')
        self.cache().unlink()
        M.project_qmp_capture(self.value, joined=True)
        self.assertEqual(self.value['receipt']['state'], 'incomplete')
        self.assertEqual(self.value['receipt']['query_kvm'],
                         dict(state='unavailable', present=None, enabled=None))
        self.cache()
        M.project_qmp_capture(self.value, joined=True)
        self.assertEqual(self.value['receipt']['state'], 'observed')
        token = M.DEADLINE.set(time.monotonic() - 1)
        try:
            M.project_qmp_capture(self.value, joined=True)
        finally:
            M.DEADLINE.reset(token)
        self.assertEqual(self.value['receipt']['probe_stderr'], [])
        self.assertEqual(self.value['receipt']['query_kvm'],
                         dict(state='unavailable', present=None, enabled=None))
        self.assertEqual(self.value['receipt']['state'], 'incomplete')

    def test_cache_exact_key_and_owner_regular_nofollow_mode_link_guards(self):
        path = self.cache()
        path.rename(path.with_suffix('.wrong'))
        M.project_qmp_capture(self.value, joined=True)
        self.assertEqual(self.value['receipt']['query_kvm']['state'], 'unavailable')
        path.symlink_to(path.with_suffix('.wrong'))
        M.project_qmp_capture(self.value, joined=True)
        self.assertEqual(self.value['receipt']['query_kvm']['state'], 'unavailable')
        path.unlink()
        path = self.cache()
        for mode in (0o666, 0o660, 0o400):
            path.chmod(mode)
            M.project_qmp_capture(self.value, joined=True)
            self.assertEqual(self.value['receipt']['query_kvm']['state'], 'unavailable')
        path.chmod(0o600)
        os.link(path, path.with_suffix('.alias'))
        M.project_qmp_capture(self.value, joined=True)
        self.assertEqual(self.value['receipt']['query_kvm']['state'], 'unavailable')

    def test_bounded_capture_read_rejects_changed_regular_inode_and_oversize(self):
        path = self.error_file(data=b'public')
        with self.assertRaises(ValueError):
            M.capture_read(path, 5)
        original_stat = M.os.fstat
        calls = 0
        def changed(fd):
            nonlocal calls
            calls += 1
            result = original_stat(fd)
            if calls == 2:
                path.write_bytes(b'changed')
                return original_stat(fd)
            return result
        with mock.patch.object(M.os, 'fstat', side_effect=changed), self.assertRaises(ValueError):
            M.capture_read(path, M.MAX_QMP)

    def test_capture_bounds_unknown_text_and_incomplete_cleanup_never_export_raw_or_claim_join(self):
        path = self.error_file(data=b'PRIVATE_CANARY' * M.MAX_QMP)
        self.retain(path)
        path.unlink()
        self.cache()
        M.project_qmp_capture(self.value, joined=True)
        self.assertEqual(self.value['receipt']['state'], 'incomplete')
        self.assertEqual(self.value['receipt']['probe_stderr'], [])
        with mock.patch.object(M, 'capture_read') as read:
            M.project_qmp_capture(self.value, joined=False)
        read.assert_not_called()
        self.assertNotIn('PRIVATE_CANARY', json.dumps(self.value['receipt']))

    def test_execute_keeps_original_failure_receipt_cleanup_and_deadline_on_capture_fault(self):
        for uncertain in (False, True):
            with tempfile.TemporaryDirectory() as directory:
                original = (M.CleanupUnconfirmed('process_group_remaining') if uncertain
                            else M.CommandFailed(1, 'inspect_roots', 'kvm_unavailable'))
                original_deadline = time.monotonic() + 900
                def admit(_tools, observed):
                    M.HYPERVISOR.set(self.binding)
                    observed.update(state='passed', present=True, enabled=True)
                def fail(*_args):
                    self.assertEqual(M.DEADLINE.get(), original_deadline)
                    value = M.QMP_CAPTURE.get()
                    (value['directory'] / 'probe-1').symlink_to('/PRIVATE_CANARY')
                    raise original
                with mock.patch.object(M, 'hosted_output', return_value=Path(directory)), \
                        mock.patch.object(M, 'verify_kvm_launch', return_value=launch_receipt()), \
                        mock.patch.object(M, 'adopt_appliance', return_value=dict(
                            deadline=original_deadline, receipt={'version': 1})), \
                        mock.patch.object(M, 'source_binding', return_value={'revision': 'a' * 40}), \
                        mock.patch.object(M, 'tool_inventory', return_value={}), \
                        mock.patch.object(M, 'appliance_preflight', return_value={}), \
                        mock.patch.object(M, 'qmp_preflight', side_effect=admit), \
                        mock.patch.object(M, 'fetch'), mock.patch.object(M, 'extract_boot', side_effect=fail), \
                        self.assertRaises(type(original)) as raised:
                    M.execute(SimpleNamespace(yes=True, work=directory, expected_source='a' * 40))
                self.assertIs(raised.exception, original)
                evidence = Path(directory) / 'evidence'
                self.assertEqual([path.name for path in evidence.iterdir()], ['cleanup.json'])
                raw = (evidence / 'cleanup.json').read_text()
                value = json.loads(raw)
                self.assertNotIn('PRIVATE_CANARY', raw)
                self.assertEqual(value['failure']['reason'], 'process_group_remaining' if uncertain else 'command_failed')
                self.assertEqual(value['child_leaders_reaped'], not uncertain)
                self.assertEqual(value['owned_scratch_removed'], not uncertain)
                self.assertEqual(value['original_qmp_observation']['state'], 'incomplete')
                self.assertFalse(value['boot_pair_verified'])


class OriginalProbeContext(unittest.TestCase):
    def setUp(self):
        self.fixture = OriginalQmpObservation()
        self.fixture.setUp()
        self.baseline = dict.fromkeys(M.CONTEXT_KEYS, 'a' * 64)

    def tearDown(self):
        self.fixture.tearDown()

    @staticmethod
    def status():
        return (b'Uid:\t1000\t1000\t1000\t1000\nGid:\t1000\t1000\t1000\t1000\n'
                b'Groups:\t10 20\nCapInh:\t0000000000000000\nCapPrm:\t0000000000000000\n'
                b'CapEff:\t0000000000000000\nCapBnd:\t000001ffffffffff\nCapAmb:\t0000000000000000\n'
                b'NoNewPrivs:\t0\nSeccomp:\t0\nSeccomp_filters:\t0\n')

    def test_exact_error_boundaries_distinguish_eacces_and_eperm_without_raw_text(self):
        for message, expected in ((b'Permission denied', 'eacces'), (b'Operation not permitted', 'eperm')):
            parser = M.QemuFailureBoundary()
            data = (b'Could not access KVM kernel module: ' + message + b'\n'
                    b'qemu-system-x86_64: failed to initialize kvm: ' + message + b'\n')
            for part in (data[:13], data[13:49], data[49:]):
                parser.feed(part)
            self.assertEqual(parser.result(), dict(open=expected, init=expected))

    def test_boundary_unknown_conflict_and_other_do_not_invent_open_failure(self):
        for data, expected in ((b'PRIVATE_CANARY Permission denied\n', 'unobserved'),
                (b'qemu-system-x86_64: failed to initialize kvm: Invalid argument\n', 'other'),
                (b'qemu-system-x86_64: failed to initialize kvm: Permission denied\n'
                 b'qemu-system-x86_64: failed to initialize kvm: Operation not permitted\n', 'ambiguous')):
            parser = M.QemuFailureBoundary()
            parser.feed(data)
            self.assertEqual(parser.result(), dict(open='unobserved', init=expected))
            self.assertNotIn('PRIVATE_CANARY', json.dumps(parser.result()))

    def test_status_projection_is_bounded_hashed_and_partitioned(self):
        original = M.status_context(self.status())
        self.assertEqual(set(original), {'credentials', 'capabilities', 'seccomp'})
        self.assertTrue(all(len(value) == 64 for value in original.values()))
        for before, after, changed in ((b'10 20', b'10 21', 'credentials'),
                (b'CapEff:\t0000000000000000', b'CapEff:\t0000000000000001', 'capabilities'),
                (b'Seccomp:\t0', b'Seccomp:\t2', 'seccomp')):
            current = M.status_context(self.status().replace(before, after))
            self.assertEqual({key for key in current if current[key] != original[key]}, {changed})

    def test_status_rejects_missing_duplicate_unbounded_and_invalid_fields(self):
        for raw in (b'', b'X' * 32769, self.status() + b'Uid: 0 0 0 0\n',
                self.status().replace(b'Seccomp_filters:\t0\n', b''),
                self.status().replace(b'10 20', b' '.join([b'1'] * 257)),
                self.status().replace(b'1000', b'4294967296'),
                self.status().replace(b'Seccomp:\t0', b'Seccomp:\t9'),
                self.status().replace(b'CapEff:\t0000000000000000', b'CapEff: PRIVATE_CANARY')):
            with self.subTest(raw=raw[:20]), self.assertRaises(ValueError):
                M.status_context(raw)

    def test_fixed_proc_read_bounds_nofollow_and_closes_descriptor(self):
        with mock.patch.object(M.os, 'open', return_value=71) as opened, \
                mock.patch.object(M.os, 'fdopen', return_value=io.BytesIO(b'public')) as file, \
                mock.patch.object(M.os, 'fstat', return_value=SimpleNamespace(st_mode=stat.S_IFREG)):
            file.return_value.fileno = lambda: 71
            self.assertEqual(M.context_read('/proc/self/attr/current', 6), b'public')
            self.assertTrue(file.return_value.closed)
        self.assertEqual(opened.call_args.args, ('/proc/self/attr/current',
            os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC | os.O_NONBLOCK))
        with self.assertRaises(ValueError):
            M.context_read('/PRIVATE_CANARY', 10)
        with mock.patch.object(M.os, 'open', return_value=71), \
                mock.patch.object(M.os, 'fdopen', return_value=io.BytesIO(b'x' * 7)) as file, \
                mock.patch.object(M.os, 'fstat', return_value=SimpleNamespace(st_mode=stat.S_IFREG)), \
                self.assertRaises(ValueError):
            file.return_value.fileno = lambda: 71
            M.context_read('/proc/self/attr/current', 6)

    @staticmethod
    def device(inode=5, mode=stat.S_IFCHR | 0o660):
        return SimpleNamespace(st_dev=1, st_ino=inode, st_rdev=42, st_mode=mode,
                               st_uid=0, st_gid=10, st_ctime_ns=100)

    def snapshot(self, acl=b'public ACL', metadata=None):
        def read(path, maximum):
            return self.status() if path.endswith('status') else b'PRIVATE_LSM_CANARY'
        with mock.patch.object(M, 'context_read', side_effect=read), \
                mock.patch.object(M.os, 'lstat', side_effect=metadata or [self.device(), self.device()]), \
                mock.patch.object(M.os, 'getxattr', side_effect=acl if isinstance(acl, Exception) else None,
                                  return_value=acl) as xattr:
            result = M.context_snapshot()
        xattr.assert_called_once_with('/dev/kvm', 'system.posix_acl_access', follow_symlinks=False)
        return result

    def test_snapshot_keeps_only_private_digests_and_distinguishes_absent_acl(self):
        present = self.snapshot()
        absent = self.snapshot(OSError(M.errno.ENODATA, 'PRIVATE_CANARY'))
        self.assertNotEqual(present['device_acl'], absent['device_acl'])
        self.assertTrue(M.valid_context_baseline(present))
        self.assertTrue(M.valid_context_baseline(absent))
        for value in (present, absent):
            self.assertNotIn('PRIVATE', json.dumps(value))
            self.assertTrue(all(item is not None for item in value.values()))

    def test_unreadable_acl_is_unavailable_not_known_absent(self):
        for number in (M.errno.EACCES, M.errno.ENOTSUP):
            value = self.snapshot(OSError(number, 'PRIVATE_CANARY'))
            self.assertIsNone(value['device_acl'])
            self.assertIsNotNone(value['device_metadata'])

    def test_changed_device_or_oversized_acl_cannot_make_positive_identity(self):
        for value in (self.snapshot(metadata=[self.device(), self.device(inode=6)]),
                      self.snapshot(b'x' * 4097)):
            self.assertIsNone(value['device_metadata'])
            self.assertIsNone(value['device_acl'])
        with mock.patch.object(M, 'context_read', side_effect=PermissionError('PRIVATE_CANARY')), \
                mock.patch.object(M.os, 'lstat', return_value=self.device(mode=stat.S_IFLNK)), \
                mock.patch.object(M.os, 'getxattr') as acl:
            self.assertEqual(M.context_snapshot(), dict.fromkeys(M.CONTEXT_KEYS))
        acl.assert_not_called()

    def test_equal_different_missing_are_closed_and_kvm_result_is_only_observation(self):
        current = dict(self.baseline, lsm='b' * 64, device_acl=None)
        with mock.patch.object(M, 'context_snapshot', return_value=current), \
                mock.patch.object(M, 'kvm_observation', return_value='denied') as kvm:
            result = M.pre_exec_observation(self.baseline, time.monotonic() + 5)
        self.assertEqual(result['scope'], 'wrapper_pre_exec')
        self.assertEqual(result['kvm'], 'denied')
        self.assertEqual(result['equality']['credentials'], 'equal')
        self.assertEqual(result['equality']['lsm'], 'different')
        self.assertEqual(result['equality']['device_acl'], 'unavailable')
        kvm.assert_called_once_with()
        self.assertNotIn('a' * 64, json.dumps(result))

    def test_two_missing_components_never_compare_equal(self):
        missing = dict.fromkeys(M.CONTEXT_KEYS)
        with mock.patch.object(M, 'context_snapshot', return_value=missing), \
                mock.patch.object(M, 'kvm_observation', return_value='api_12'):
            result = M.pre_exec_observation(missing, None)
        self.assertEqual(result['equality'], dict.fromkeys(M.CONTEXT_KEYS, 'unavailable'))
        self.assertEqual(result['kvm'], 'api_12')

    def test_malformed_baseline_and_expired_budget_never_run_observation(self):
        for baseline, deadline in (({}, None), ({**self.baseline, 'extra': 'PRIVATE_CANARY'}, None),
                ({**self.baseline, 'lsm': True}, None), ({**self.baseline, 'lsm': 'PRIVATE_CANARY'}, None),
                (self.baseline, time.monotonic() - 1), (self.baseline, True),
                (self.baseline, float('nan')), (self.baseline, float('inf'))):
            with mock.patch.object(M, 'context_snapshot') as snapshot, \
                    mock.patch.object(M, 'kvm_observation') as kvm:
                self.assertEqual(M.pre_exec_observation(baseline, deadline), M.pre_exec_unavailable())
            snapshot.assert_not_called()
            kvm.assert_not_called()

    def test_baseline_is_private_file_not_script_or_exported_configuration_hash(self):
        path = self.fixture.scratch / 'qmp-context-parent'
        self.assertEqual(stat.S_IMODE(path.stat().st_mode), 0o600)
        self.assertEqual(path.stat().st_nlink, 1)
        self.assertEqual(json.loads(path.read_bytes()), self.baseline)
        self.assertNotIn(('a' * 64).encode(), self.fixture.value['wrapper'].read_bytes())
        self.assertNotIn('a' * 64, json.dumps(self.fixture.value['receipt']))

    def test_private_baseline_guards_and_read_failure_do_not_suppress_passthrough(self):
        path = self.fixture.scratch / 'qmp-context-parent'
        for raw in (b'PRIVATE_CANARY', b'{}', b' ' * 2049, b'[' * 1024 + b']' * 1024):
            path.write_bytes(raw)
            self.assertEqual(M.probe_pre_exec(self.fixture.config()), M.pre_exec_unavailable())
        path.unlink()
        path.symlink_to('/PRIVATE_CANARY')
        self.assertEqual(M.probe_pre_exec(self.fixture.config()), M.pre_exec_unavailable())
        error = self.fixture.error_file()
        original_stat, original_link = os.fstat, os.readlink
        with error.open('rb') as source, \
                mock.patch.object(M.os, 'fstat', side_effect=lambda fd:
                    original_stat(source.fileno()) if fd == 2 else original_stat(fd)), \
                mock.patch.object(M.os, 'readlink', side_effect=lambda target, **kwargs:
                    str(error) if str(target) == '/proc/self/fd/2' else original_link(target, **kwargs)), \
                mock.patch.object(M.os, 'execv') as execute, mock.patch.object(M.signal, 'signal'):
            M.hypervisor_exec(self.fixture.config(), list(M.LIBGUESTFS_QMP_ARGV))
        execute.assert_called_once_with(str(self.fixture.binary),
                                       [str(self.fixture.binary), *M.LIBGUESTFS_QMP_ARGV])

    def test_context_sampling_occurs_only_in_two_reserved_existing_probe_slots(self):
        observed = M.pre_exec_unavailable()
        observed['kvm'] = 'api_12'
        for index in (1, 2):
            path = self.fixture.error_file('cmderr' + str(index) + '.txt')
            original_stat, original_link = os.fstat, os.readlink
            with path.open('rb') as source, \
                    mock.patch.object(M.os, 'fstat', side_effect=lambda fd:
                        original_stat(source.fileno()) if fd == 2 else original_stat(fd)), \
                    mock.patch.object(M.os, 'readlink', side_effect=lambda target, **kwargs:
                        str(path) if str(target) == '/proc/self/fd/2' else original_link(target, **kwargs)), \
                    mock.patch.object(M, 'probe_pre_exec', return_value=observed) as sample, \
                    mock.patch.object(M.os, 'execv') as execute, mock.patch.object(M.signal, 'signal'):
                M.hypervisor_exec(self.fixture.config(), list(M.LIBGUESTFS_QMP_ARGV))
            sample.assert_called_once_with(self.fixture.config())
            execute.assert_called_once()
        with mock.patch.object(M, 'probe_pre_exec') as sample:
            with self.assertRaises(ValueError):
                # Both slots occupied: do not even call the optional sampler.
                path = self.fixture.error_file('cmderr3.txt')
                original_stat, original_link = os.fstat, os.readlink
                with path.open('rb') as source, \
                        mock.patch.object(M.os, 'fstat', side_effect=lambda fd:
                            original_stat(source.fileno()) if fd == 2 else original_stat(fd)), \
                        mock.patch.object(M.os, 'readlink', return_value=str(path)):
                    M.retain_probe_stderr(self.fixture.scratch, self.fixture.value['directory'], sample)
        sample.assert_not_called()
        self.fixture.cache()
        M.project_qmp_capture(self.fixture.value, joined=True)
        self.assertEqual([item['pre_exec'] for item in self.fixture.value['receipt']['probe_stderr']],
                         [observed, observed])

    def test_closed_marker_rejects_extra_keys_types_and_canary_fields(self):
        self.fixture.observed_pair()
        marker = self.fixture.value['directory'] / 'probe-1.verified'
        good = M.pre_exec_unavailable()
        for changed in ({**good, 'extra': 'PRIVATE_CANARY'}, {**good, 'version': True},
                {**good, 'scope': 'qemu_after_exec'}, {**good, 'kvm': 'PRIVATE_CANARY'},
                {**good, 'equality': {**good['equality'], 'lsm': True}},
                {**good, 'equality': {**good['equality'], 'unknown': 'equal'}}):
            marker.write_text(json.dumps(changed))
            M.project_qmp_capture(self.fixture.value, joined=True)
            self.assertEqual(self.fixture.value['receipt']['state'], 'incomplete')
            self.assertEqual(self.fixture.value['receipt']['probe_stderr'], [])
            self.assertNotIn('PRIVATE_CANARY', json.dumps(self.fixture.value['receipt']))

    def test_observation_read_failure_never_invents_positive_security_equality(self):
        with mock.patch.object(M, 'context_snapshot', side_effect=PermissionError('PRIVATE_CANARY')), \
                mock.patch.object(M, 'kvm_observation') as kvm:
            self.assertEqual(M.pre_exec_observation(self.baseline, None), M.pre_exec_unavailable())
        kvm.assert_not_called()
        self.fixture.observed_pair()
        M.project_qmp_capture(self.fixture.value, joined=False)
        self.assertEqual(self.fixture.value['receipt']['probe_stderr'], [])


class KvmGroupLaunch(unittest.TestCase):
    @staticmethod
    def status():
        return b''.join(name + b':\t0000000000000000\n' for name in
                        (b'CapInh', b'CapPrm', b'CapEff', b'CapBnd', b'CapAmb')) + b'NoNewPrivs:\t1\n'

    def setUp(self):
        self.uid, self.gid = 1234, 108
        self.device = SimpleNamespace(st_dev=1, st_ino=2, st_rdev=3, st_mode=stat.S_IFCHR | 0o660,
                                      st_uid=0, st_gid=self.gid, st_nlink=1, st_ctime_ns=4)
        for patcher in (mock.patch.object(M.os, 'getresuid', return_value=(self.uid,) * 3),
                        mock.patch.object(M.os, 'getresgid', return_value=(self.gid,) * 3),
                        mock.patch.object(M.os, 'getgroups', return_value=[]),
                        mock.patch.object(M, 'context_read', return_value=self.status()),
                        mock.patch.object(M.grp, 'getgrnam', return_value=SimpleNamespace(
                            gr_name='kvm', gr_gid=self.gid)),
                        mock.patch.object(M.os, 'lstat', return_value=self.device),
                        mock.patch.object(M.os, 'getxattr', side_effect=OSError(M.errno.ENODATA, 'none')),
                        mock.patch.dict(M.os.environ, {'VP_PUBLIC_BOOT_UID': str(self.uid),
                            'VP_PUBLIC_BOOT_KVM_GID': str(self.gid)}, clear=True)):
            patcher.start()
            self.addCleanup(patcher.stop)

    def acl(self, entries=None):
        undefined = 0xffffffff
        entries = entries if entries is not None else [
            (1, 6, undefined), (2, 6, self.uid), (4, 6, undefined),
            (16, 6, undefined), (32, 0, undefined)]
        return M.struct.pack('<I', 2) + b''.join(M.struct.pack('<HHI', *item) for item in entries)

    def test_basic_acl_and_named_kvm_group_are_validated_without_process_or_device_open(self):
        with mock.patch.object(M, 'command') as command, mock.patch.object(M.os, 'open') as opened:
            self.assertEqual(M.kvm_group_ids(), (self.uid, self.gid))
        command.assert_not_called()
        opened.assert_not_called()
        M.grp.getgrnam.assert_called_once_with('kvm')
        M.os.getxattr.assert_called_once_with('/dev/kvm', 'system.posix_acl_access', follow_symlinks=False)

    def test_extended_acl_requires_group_object_and_mask_not_just_mode_bits(self):
        with mock.patch.object(M.os, 'getxattr', return_value=self.acl()):
            self.assertEqual(M.kvm_group_ids(), (self.uid, self.gid))
        for index in (2, 3):
            raw = bytearray(self.acl())
            raw[4 + index * 8 + 2] = 4
            with self.subTest(index=index), mock.patch.object(M.os, 'getxattr', return_value=bytes(raw)), \
                    self.assertRaisesRegex(ValueError, '^kvm_launch_acl$'):
                M.kvm_group_ids()

    def test_denying_named_caller_entry_cannot_be_bypassed_by_group(self):
        raw = bytearray(self.acl())
        raw[14] = 0
        with mock.patch.object(M.os, 'getxattr', return_value=bytes(raw)), \
                self.assertRaisesRegex(ValueError, '^kvm_launch_acl$'):
            M.kvm_group_ids()

    def test_malformed_duplicate_unknown_oversized_and_missing_acl_fields_are_denied(self):
        undefined = 0xffffffff
        cases = [b'', b'PRIVATE_CANARY', b'x' * 4097, self.acl() + b'x',
                 b'\x03' + self.acl()[1:], self.acl() + self.acl()[4:12],
                 self.acl([(1, 6, undefined), (4, 6, undefined), (32, 0, undefined)]),
                 self.acl([(64, 6, undefined)] * 3),
                 self.acl([(1, 6, 1), (4, 6, undefined), (32, 0, undefined)]),
                 self.acl([(1, 8, undefined), (4, 6, undefined), (32, 0, undefined)])]
        for raw in cases:
            with self.subTest(size=len(raw)), mock.patch.object(M.os, 'getxattr', return_value=raw), \
                    self.assertRaisesRegex(ValueError, '^kvm_launch_acl$'):
                M.kvm_group_ids()

    def test_acl_read_errors_are_not_basic_acl_absence(self):
        for code in (M.errno.EACCES, M.errno.EPERM, M.errno.ENOTSUP, M.errno.EIO):
            with mock.patch.object(M.os, 'getxattr', side_effect=OSError(code, 'PRIVATE_CANARY')), \
                    self.assertRaisesRegex(ValueError, '^kvm_launch_acl$'):
                M.kvm_group_ids()

    def test_root_changed_or_saved_privileged_uid_is_rejected(self):
        for value in ((0, 0, 0), (1234, 0, 1234), (1234, 1234, 0), (1234, 1235, 1234)):
            with mock.patch.object(M.os, 'getresuid', return_value=value), \
                    self.assertRaisesRegex(ValueError, '^kvm_launch_identity$'):
                M.kvm_group_ids()

    def test_unknown_wrong_or_root_named_group_is_rejected(self):
        for gid in (0, -1, 2 ** 32 - 1, True, '108'):
            with mock.patch.object(M.grp, 'getgrnam', return_value=SimpleNamespace(gr_name='kvm', gr_gid=gid)), \
                    self.assertRaisesRegex(ValueError, '^kvm_launch_group$'):
                M.kvm_group_ids()
        for group in (SimpleNamespace(gr_name='other', gr_gid=108), KeyError('PRIVATE_CANARY')):
            with mock.patch.object(M.grp, 'getgrnam', side_effect=group if isinstance(group, Exception) else None,
                                   return_value=group), self.assertRaisesRegex(ValueError, '^kvm_launch_group$'):
                M.kvm_group_ids()

    def test_symlink_wrong_owner_gid_mode_and_linkcount_are_rejected(self):
        changes = [dict(st_mode=stat.S_IFLNK | 0o660), dict(st_mode=stat.S_IFREG | 0o660),
                   dict(st_uid=1234), dict(st_gid=109), dict(st_nlink=2),
                   dict(st_mode=stat.S_IFCHR | 0o666), dict(st_mode=stat.S_IFCHR | 0o640)]
        for change in changes:
            with mock.patch.object(M.os, 'lstat', return_value=SimpleNamespace(**(vars(self.device) | change))), \
                    self.assertRaisesRegex(ValueError, '^kvm_launch_device$'):
                M.kvm_group_ids()

    def test_replaced_or_changed_device_during_acl_read_is_rejected(self):
        for change in (dict(st_ino=9), dict(st_ctime_ns=5), dict(st_gid=109), dict(st_rdev=4)):
            with mock.patch.object(M.os, 'lstat', side_effect=[self.device,
                    SimpleNamespace(**(vars(self.device) | change))]), \
                    self.assertRaisesRegex(ValueError, '^kvm_launch_device$'):
                M.kvm_group_ids()

    def test_execute_expected_ids_are_strict_and_actual_all_three_ids_must_match(self):
        for name in ('VP_PUBLIC_BOOT_UID', 'VP_PUBLIC_BOOT_KVM_GID'):
            for value in ('', '0', '01', '-1', '4294967295', '1\n', 'PRIVATE_CANARY'):
                with mock.patch.dict(M.os.environ, {name: value}), \
                        self.assertRaisesRegex(ValueError, '^kvm_launch_identity$'):
                    M.verify_kvm_launch()
        for method in ('getresuid', 'getresgid'):
            for value in ((0, 0, 0), (1234, 1234, 1234), (108, 0, 108), (108, 108, 0)):
                if method == 'getresuid' and value == (1234,) * 3:
                    continue
                with mock.patch.object(M.os, method, return_value=value), \
                        self.assertRaisesRegex(ValueError, '^kvm_launch_identity$'):
                    M.verify_kvm_launch()
        with mock.patch.dict(M.os.environ, {'VP_PUBLIC_BOOT_KVM_GID': '109'}), \
                mock.patch.object(M.os, 'getresgid', return_value=(109,) * 3), \
                self.assertRaisesRegex(ValueError, '^kvm_launch_identity$'):
            M.verify_kvm_launch()

    def test_closed_launch_receipt_has_no_ids_labels_or_claimed_vm_access(self):
        value = M.verify_kvm_launch()
        self.assertEqual(value, launch_receipt())
        for text in ('1234', '108', '/dev/', 'api_12', 'boot_verified'):
            self.assertNotIn(text, json.dumps(value))

    def test_execute_requires_empty_supplementary_groups(self):
        for groups in ([0], [self.gid], [1000, 1001]):
            with mock.patch.object(M.os, 'getgroups', return_value=groups), \
                    self.assertRaisesRegex(ValueError, '^kvm_launch_privileges$'):
                M.verify_kvm_launch()

    def test_execute_requires_every_capability_set_zero_and_no_new_privileges(self):
        for name in (b'CapInh', b'CapPrm', b'CapEff', b'CapBnd', b'CapAmb'):
            raw = self.status().replace(name + b':\t0000000000000000', name + b':\t0000000000000001')
            with mock.patch.object(M, 'context_read', return_value=raw), \
                    self.assertRaisesRegex(ValueError, '^kvm_launch_privileges$'):
                M.verify_kvm_launch()
        with mock.patch.object(M, 'context_read', return_value=self.status().replace(b'NoNewPrivs:\t1', b'NoNewPrivs:\t0')), \
                self.assertRaisesRegex(ValueError, '^kvm_launch_privileges$'):
            M.verify_kvm_launch()

    def test_execute_rejects_missing_duplicate_malformed_and_unreadable_privileges(self):
        for raw in (b'', b'PRIVATE_CANARY', self.status() + b'CapEff:\t0000000000000000\n',
                    self.status().replace(b'CapBnd:\t0000000000000000\n', b''),
                    self.status().replace(b'0000000000000000', b'0'),
                    self.status().replace(b'NoNewPrivs:\t1', b'NoNewPrivs:\ttrue')):
            with mock.patch.object(M, 'context_read', return_value=raw), \
                    self.assertRaisesRegex(ValueError, '^kvm_launch_privileges$'):
                M.verify_kvm_launch()
        with mock.patch.object(M, 'context_read', side_effect=PermissionError('PRIVATE_CANARY')), \
                self.assertRaises(PermissionError):
            M.verify_kvm_launch()
        with mock.patch.object(M, 'context_read', return_value=self.status()) as read:
            self.assertEqual(M.verify_kvm_launch(), launch_receipt())
        read.assert_called_once_with('/proc/self/status', 32768)

    def test_failed_privilege_drop_prevents_work_adoption_and_child_spawn(self):
        args = SimpleNamespace(yes=True, expected_source='a' * 40, work='/PRIVATE_CANARY')
        with mock.patch.object(M.os, 'getgroups', return_value=[0]), \
                mock.patch.object(M, 'hosted_output') as work, mock.patch.object(M, 'adopt_appliance') as adopt, \
                mock.patch.object(M, 'command') as child, self.assertRaisesRegex(ValueError, '^kvm_launch_privileges$'):
            M.execute(args)
        work.assert_not_called()
        adopt.assert_not_called()
        child.assert_not_called()
        self.assertEqual(M.failure_reason(ValueError('kvm_launch_privileges')), 'kvm_launch_privileges')

    def test_preselection_keeps_original_prepared_source_and_absolute_deadline(self):
        args = SimpleNamespace(yes=True, expected_source='a' * 40)
        started, now = 1, [35 * 10 ** 9]
        prepared = dict(source=args.expected_source, started_monotonic_ns=started)
        def select():
            self.assertEqual(M.DEADLINE.get(), started / 1e9 + M.BUILD_SECONDS)
            return self.uid, self.gid
        with mock.patch.object(M, 'appliance_stage_path', return_value=Path('/private-stage')), \
                mock.patch.object(M, 'private_stage_file'), mock.patch.object(M, 'read_stage', return_value=prepared), \
                mock.patch.object(M.time, 'monotonic_ns', side_effect=lambda: now[0]), \
                mock.patch.object(M.time, 'monotonic', side_effect=lambda: now[0] / 1e9), \
                mock.patch.object(M, 'kvm_group_ids', side_effect=select) as selected:
            # A start near boot is valid on a young runner, not already expired.
            self.assertEqual(M.kvm_launch_ids(args), (self.uid, self.gid))
            self.assertIsNone(M.DEADLINE.get())
            for changed in (dict(source='b' * 40, started_monotonic_ns=started),
                            dict(source=args.expected_source, started_monotonic_ns=now[0] + 1),
                            dict(source=args.expected_source, started_monotonic_ns=True)):
                with mock.patch.object(M, 'read_stage', return_value=changed), self.assertRaises(ValueError):
                    M.kvm_launch_ids(args)
            # Advance both clock interfaces past the same original deadline.
            now[0] = started + (M.BUILD_SECONDS + 1) * 10 ** 9
            with self.assertRaisesRegex(ValueError, '^build_deadline$'):
                M.kvm_launch_ids(args)
            self.assertEqual(selected.call_count, 1)
            self.assertIsNone(M.DEADLINE.get())

    def test_execute_rejects_invalid_launch_before_work_adoption_or_child_spawn(self):
        args = SimpleNamespace(yes=True, expected_source='a' * 40, work='/PRIVATE_CANARY')
        with mock.patch.dict(M.os.environ, {'VP_PUBLIC_BOOT_UID': '0'}), \
                mock.patch.object(M, 'hosted_output') as work, mock.patch.object(M, 'adopt_appliance') as adopt, \
                mock.patch.object(M, 'command') as child, self.assertRaisesRegex(ValueError, '^kvm_launch_identity$'):
            M.execute(args)
        work.assert_not_called()
        adopt.assert_not_called()
        child.assert_not_called()

    def test_cli_selection_is_private_numeric_pair_or_closed_failure_only(self):
        for result in ((self.uid, self.gid), ValueError('kvm_launch_acl'), ValueError('PRIVATE_CANARY')):
            stdout, stderr = io.StringIO(), io.StringIO()
            with mock.patch.object(sys, 'argv', ['image', 'kvm-launch-ids', '--expected-source', 'a' * 40, '--yes']), \
                    mock.patch.object(sys, 'stdout', stdout), mock.patch.object(sys, 'stderr', stderr), \
                    mock.patch.object(M, 'kvm_launch_ids', return_value=result,
                                      side_effect=result if isinstance(result, Exception) else None):
                code = M.main()
            if isinstance(result, Exception):
                self.assertEqual(code, 1)
                self.assertEqual(stdout.getvalue(), '')
                self.assertEqual(stderr.getvalue(), 'protected_resident_image_failed action=kvm-launch-ids reason='
                                 + ('kvm_launch_acl' if result.args[0] == 'kvm_launch_acl' else 'unclassified') + '\n')
            else:
                self.assertEqual(code, 0)
                self.assertEqual(stdout.getvalue(), '1234 108\n')
                self.assertEqual(stderr.getvalue(), '')

    def test_workflow_group_launch_is_execute_only_and_does_not_persist_membership(self):
        raw = (M.ROOT / '.github/workflows/protected-resident-image.yml').read_text()
        function = raw.split('          image_tool() {\n', 1)[1].split('          }\n', 1)[0]
        self.assertIn('if test "$1" = execute; then', function)
        self.assertIn('launch=(sudo -n -- /usr/bin/setpriv --reuid="$launch_uid" --regid="$launch_gid"', function)
        self.assertIn('--clear-groups --inh-caps=-all --ambient-caps=-all --bounding-set=-all --no-new-privs --)', function)
        self.assertIn('"${launch[@]}" /usr/bin/env -i', function)
        self.assertIn('VP_PUBLIC_BOOT_UID="${launch_uid:-}" VP_PUBLIC_BOOT_KVM_GID="${launch_gid:-}"', function)
        self.assertLess(raw.index('image_tool finish-appliance'), raw.index('launch_ids="$(image_tool kvm-launch-ids)"'))
        self.assertIn('test "$launch_uid" = "$(id -u)"', raw)
        self.assertIn('sudo -n setfacl --restore=', raw)
        self.assertIn('getfacl -p /dev/kvm | cmp', raw)
        for forbidden in ('usermod', 'gpasswd', 'sudo -n guestfish', 'chmod /dev/kvm', 'udevadm trigger'):
            self.assertNotIn(forbidden, raw)
        self.assertEqual(M.BUILD_SECONDS, 1200)

    def test_original_workflow_execute_argv_uses_fixed_drop_before_env_without_privilege_execution(self):
        raw = (M.ROOT / '.github/workflows/protected-resident-image.yml').read_text()
        function = raw.split('          image_tool() {\n', 1)[1].split('          }\n', 1)[0]
        # A shell function captures sudo's argv and never invokes any binary.
        script = ('set -eu\nsudo() { printf "%s\\0" "$@"; }\n'
                  'launch_uid=1234\nlaunch_gid=108\nimage_tool() {\n' + function +
                  '\n}\nimage_tool execute --work /public-fixture\n')
        environment = dict(GITHUB_REPOSITORY='VOLPAROSSA/volparossa', GITHUB_RUN_ID='123',
            GITHUB_SHA='a' * 40, GITHUB_REF='refs/heads/feature/protected-resident-image',
            RUNNER_TEMP='/public-temp', EXPECTED_SOURCE='a' * 40, PRIVATE_CANARY='never-forward')
        result = M.subprocess.check_output(['/bin/bash', '--noprofile', '--norc', '-c', script],
                                           env=environment, timeout=5)
        self.assertEqual(result.decode().split('\0'), ['-n', '--', '/usr/bin/setpriv',
            '--reuid=1234', '--regid=108', '--clear-groups', '--inh-caps=-all', '--ambient-caps=-all',
            '--bounding-set=-all', '--no-new-privs', '--', '/usr/bin/env', '-i', 'PATH=/usr/bin:/bin',
            'LANG=C.UTF-8', 'PYTHONDONTWRITEBYTECODE=1', 'GITHUB_ACTIONS=true',
            'RUNNER_ENVIRONMENT=github-hosted', 'RUNNER_OS=Linux',
            'GITHUB_REPOSITORY=VOLPAROSSA/volparossa', 'GITHUB_RUN_ID=123', 'GITHUB_SHA=' + 'a' * 40,
            'GITHUB_REF=refs/heads/feature/protected-resident-image', 'RUNNER_TEMP=/public-temp',
            'VP_PUBLIC_BOOT_UID=1234', 'VP_PUBLIC_BOOT_KVM_GID=108',
            'python3', '-B', 'tests/integration/protected-resident-image.py', 'execute',
            '--work', '/public-fixture', '--expected-source', 'a' * 40, '--yes', ''])
        self.assertNotIn(b'PRIVATE_CANARY', result)


if __name__ == '__main__':
    unittest.main()
