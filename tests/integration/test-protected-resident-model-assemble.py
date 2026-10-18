#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-only
"""Inert assembly: small public files, real tar/stager, mocked guestfish only."""
import copy
import hashlib
import os
from pathlib import Path
import stat
import tarfile
import tempfile
import time
import types
import unittest
from unittest import mock

HERE = Path(__file__).resolve().parent


def load(name):
    path = HERE / (name + '.py')
    value = types.ModuleType(name.replace('-', '_'))
    value.__file__ = str(path)
    exec(compile(path.read_bytes(), str(path), 'exec'), value.__dict__)
    return value


M = load('protected-resident-model-assemble')
W = load('test-protected-resident-model-workload')
I = load('test-protected-resident-model-initrd')
SOURCE, TREE = 'a' * 40, 'b' * 40


def deadline():
    return time.monotonic() + 60


def put(path, raw=b'public inert bytes', mode=0o600):
    path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    path.write_bytes(raw)
    path.chmod(mode)
    return path


def row(kind='file', uid=1000, gid=1000, size=1, mode=0o600):
    value = dict.fromkeys(M.STAT_FIELDS, 0)
    value.update(st_dev=1, st_ino=2, st_nlink=1, st_uid=uid, st_gid=gid, st_size=size,
                 st_mode={'file': stat.S_IFREG, 'directory': stat.S_IFDIR, 'symlink': stat.S_IFLNK}[kind] | mode)
    return value


def printed(value):
    return ''.join(f'{key}: {value[key]}\n' for key in M.STAT_FIELDS)


class Fixture:
    def __init__(self, directory):
        self.root = Path(directory)
        self.build = put(self.root / 'build.qcow2')
        self.runtime = put(self.root / 'runtime-root.raw', b'R' * 16384)
        (self.root / 'public').mkdir(mode=0o700)
        self.public = W.Fixture(self.root / 'public')
        elf = bytearray(I.OLD.elf())
        elf[16:18] = b'\x03\x00'
        self.public.put('volparossa', bytes(elf), True)
        self.public.value['core_source_commit'] = SOURCE
        self.public.policy()
        inventory_digest = self.public.inventory()
        native = self.public.value['entries']['native-backend/backend.json']['sha256']
        export = dict(inventory_sha256=inventory_digest,
            workload_sha256=M.STAGER.workload_sha256(self.public.value), native_backend_sha256=native,
            asset_files=len(self.public.value['entries']),
            asset_bytes=sum(item.get('bytes', 0) for item in self.public.value['entries'].values()))
        self.report = dict(version=1, kind='protected-resident-public-model-build', state='assets_built',
            phase='complete', source_commit=SOURCE, source_tree=TREE, code_helper_commit=M.BUILD.CODE_COMMIT,
            code_helper_sha256=M.BUILD.HELPER_SHA256,
            package_lock_sha256=hashlib.sha256((HERE / 'protected-resident-model-debian-lock-v1.json').read_bytes()).hexdigest(),
            assets_exported=True, model_execution=False, worker_execution=False, private_inputs=False,
            hardware_attestation=False, production_approval=False, controller_cgroup_cleanup_required=True,
            direct_child_groups_joined=True, descendants_joined=None, complete_guest_cleanup=False,
            scratch_removed=False, installed_build_packages=199, provision={},
            native_build_manifest_sha256=self.public.value['entries']['native-backend/build.json']['sha256'], export=export)
        self.cleanup = dict(version=1, kind='protected-resident-model-build-cleanup', source_commit=SOURCE,
            source_tree=TREE, guest_uid=1000, guest_gid=1000, qemu_process_joined=True, scope_empty=True,
            guest_build_units_empty=True, guest_root_units_empty=True, runtime_unmounted=True,
            build_image=M.file_digest(self.build, M.MAX_BUILD_IMAGE, deadline()),
            runtime_image=M.file_digest(self.runtime, M.MAX_ROOT, deadline()))
        self.calls, self.mutate_row, self.mutate_download = [], None, None
        self.guest = self.root / 'runtime-guest'
        self.guest.mkdir(mode=0o700)
        self.release = M.STAGER.parse((HERE / 'protected-resident-image-pins-v1.json').read_bytes())['kernel_release']
        for name in I.E.PROFILE['required_guest_executables'] + ['/usr/bin/setpriv']:
            put(self.guest / name.lstrip('/'), I.OLD.elf(), 0o755)
        (self.guest / 'usr/lib/modules' / self.release).mkdir(mode=0o755, parents=True)
        config = '\n'.join('CONFIG_' + name + '=y' for name in ('BLK_DEV_INITRD', 'DEVTMPFS', 'EXT4_FS',
                    'BLK_DEV_DM', 'DM_VERITY', 'VIRTIO_PCI', 'VIRTIO_BLK', 'SERIAL_8250', 'SERIAL_8250_CONSOLE'))
        put(self.guest / ('boot/config-' + self.release), config.encode())
        put(self.guest / ('boot/vmlinuz-' + self.release), b'public kernel, never executed')
        put(self.guest / ('boot/initrd.img-' + self.release), b'public original initrd')

    def header(self, path):
        if path.endswith('/build-result.json'):
            return M.STAGER.encoded(self.report)
        return self.public.inventory_path.read_bytes()

    def metadata(self, path):
        if path.startswith('/boot/'):
            result = row(uid=0, gid=0, size=(self.guest / path.lstrip('/')).stat().st_size)
        elif path == '/home':
            result = row('directory', 0, 0, mode=0o755)
        elif path in ('/home/vpci', M.GUEST_OUTPUT):
            result = row('directory', mode=0o700)
        elif path in (M.GUEST_OUTPUT + '/build-result.json', M.GUEST_OUTPUT + '/inventory.json'):
            result = row(size=len(self.header(path)))
        else:
            name = path[len(M.GUEST_OUTPUT + '/assets'):].lstrip('/')
            item = self.public.value['entries'].get(name)
            result = row('directory', mode=0o700) if item is None else row(item['kind'],
                         size=item.get('bytes', len(item.get('target', ''))),
                         mode=0o777 if item['kind'] == 'symlink' else 0o700 if item['executable'] else 0o600)
        if self.mutate_row:
            self.mutate_row(path, result)
        return result

    def guestfish(self, image, operations, *, readonly=True, image_format='raw', timeout=300, operation=None):
        self.calls.append((image, copy.deepcopy(operations), readonly, image_format, timeout, operation))
        self.assert_operation(operation)
        output = ''
        for op in operations:
            if op[0] == 'inspect-os':
                output += '/dev/sda1\n'
            elif op[0] == 'lstatns':
                output += printed(self.metadata(op[1]))
            elif op[0] == 'download-offset':
                if op[1].startswith('/boot/'):
                    raw = (self.guest / op[1].lstrip('/')).read_bytes()
                elif '/assets/' in op[1]:
                    name = op[1].split('/assets/', 1)[1]
                    raw = (self.public.assets / name).read_bytes()
                else:
                    raw = self.header(op[1])
                if self.mutate_download:
                    raw = self.mutate_download(op[1], raw)
                put(Path(op[2]), raw[int(op[3]):int(op[3]) + int(op[4])], 0o644)
            elif op[0] == 'readlink':
                if '/assets/' in op[1]:
                    output += self.public.value['entries'][op[1].split('/assets/', 1)[1]]['target'] + '\n'
                else:
                    output += 'usr/' + op[1][1:] + '\n'
            elif op[0] == 'vfs-type':
                output += 'ext4\n'
            elif op[0] == 'blockdev-getsize64':
                output += str(M.MAX_ROOT) + '\n'
            elif op[0] == 'tar-in':
                assert not readonly and op[2] == '/'
                # Actual narrow extraction, no tar or image executable is run.
                M.IMAGE.safe_tree(Path(op[1]), self.guest)
            elif op[0] == 'tar-out':
                assert readonly and op[1] == '/usr'
                with tarfile.open(op[2], 'x') as archive:
                    archive.add(self.guest / 'usr', arcname='.')
                Path(op[2]).chmod(0o600)
            elif op[0] == 'download':
                put(Path(op[2]), (self.guest / op[1].lstrip('/')).read_bytes())
            else:
                assert op[0] in ('mount-ro', 'mount', 'sync', 'umount-all'), op
        return output

    @staticmethod
    def assert_operation(value):
        assert value in ('model_export_header', 'model_export_metadata', 'model_export_assets',
                         'model_stage_runtime', 'model_extract_closure')

    def export(self, **kwargs):
        return M.export_assets(self.build, self.root / 'export', self.cleanup, SOURCE, TREE,
                               kwargs.pop('guestfish', self.guestfish), kwargs.pop('deadline', deadline()), **kwargs)

    def assemble(self, exported):
        fake_pins = types.SimpleNamespace(load_pins=lambda **_kwargs: self.public.pins)
        with mock.patch.object(M.STAGER, 'module', side_effect=lambda name: W.NATIVE if name == 'llama_cpu' else fake_pins):
            return M.assemble_runtime(self.runtime, exported, self.root / 'assembled', self.cleanup,
                                      self.guestfish, deadline())


class CleanupTests(unittest.TestCase):
    def test_each_cleanup_proof_is_required_before_guestfish_or_output(self):
        for key in ('qemu_process_joined', 'scope_empty', 'guest_build_units_empty',
                    'guest_root_units_empty', 'runtime_unmounted'):
            for value in (False, 1, None):
                with self.subTest(key=key, value=value), tempfile.TemporaryDirectory() as directory, \
                        mock.patch.object(M, 'MAX_ROOT', 16384):
                    fixture = Fixture(directory)
                    fixture.cleanup[key] = value
                    with self.assertRaises(ValueError):
                        fixture.export()
                    self.assertEqual(fixture.calls, [])
                    self.assertFalse((fixture.root / 'export').exists())

    def test_cleanup_rejects_source_tree_uid_extra_missing_and_bool_version(self):
        for mutation in ('source', 'tree', 'uid', 'gid', 'extra', 'missing', 'version'):
            with self.subTest(mutation=mutation), tempfile.TemporaryDirectory() as directory, \
                    mock.patch.object(M, 'MAX_ROOT', 16384):
                fixture = Fixture(directory)
                if mutation == 'source':
                    fixture.cleanup['source_commit'] = 'c' * 40
                elif mutation == 'tree':
                    fixture.cleanup['source_tree'] = 'c' * 40
                elif mutation in ('uid', 'gid'):
                    fixture.cleanup['guest_' + mutation] = 0
                elif mutation == 'extra':
                    fixture.cleanup['arbitrary'] = True
                elif mutation == 'missing':
                    del fixture.cleanup['runtime_unmounted']
                else:
                    fixture.cleanup['version'] = True
                with self.assertRaises(ValueError):
                    fixture.export()
                self.assertEqual(fixture.calls, [])

    def test_stopped_image_bytes_and_digest_must_match(self):
        for key in ('bytes', 'sha256'):
            with self.subTest(key=key), tempfile.TemporaryDirectory() as directory, mock.patch.object(M, 'MAX_ROOT', 16384):
                fixture = Fixture(directory)
                fixture.cleanup['build_image'][key] = 3 if key == 'bytes' else '0' * 64
                with self.assertRaises(ValueError):
                    fixture.export()
                self.assertEqual(fixture.calls, [])

    def test_existing_output_and_symlink_are_never_overwritten(self):
        for kind in ('directory', 'file', 'symlink'):
            with self.subTest(kind=kind), tempfile.TemporaryDirectory() as directory, mock.patch.object(M, 'MAX_ROOT', 16384):
                fixture = Fixture(directory)
                output = fixture.root / 'export'
                if kind == 'directory':
                    output.mkdir()
                elif kind == 'file':
                    output.write_bytes(b'keep')
                else:
                    output.symlink_to('/not/read')
                with self.assertRaises(FileExistsError):
                    fixture.export()
                self.assertEqual(fixture.calls, [])

    def test_expired_or_nonfinite_deadline_has_no_io_callback(self):
        for value in (True, float('nan'), float('inf'), time.monotonic() - 1):
            with self.subTest(value=value), tempfile.TemporaryDirectory() as directory, mock.patch.object(M, 'MAX_ROOT', 16384):
                fixture = Fixture(directory)
                with self.assertRaises(ValueError):
                    fixture.export(deadline=value)
                self.assertEqual(fixture.calls, [])

    def test_image_symlink_hardlink_or_group_write_rejected_without_callback(self):
        for kind in ('symlink', 'hardlink', 'mode'):
            with self.subTest(kind=kind), tempfile.TemporaryDirectory() as directory, mock.patch.object(M, 'MAX_ROOT', 16384):
                fixture = Fixture(directory)
                if kind == 'symlink':
                    original = fixture.build
                    fixture.build = fixture.root / 'alias.qcow2'
                    fixture.build.symlink_to(original)
                elif kind == 'hardlink':
                    os.link(fixture.build, fixture.root / 'alias.qcow2')
                else:
                    fixture.build.chmod(0o660)
                with self.assertRaises(ValueError):
                    fixture.export()
                self.assertEqual(fixture.calls, [])


class MetadataTests(unittest.TestCase):
    def test_exact_statns_printer_schema_and_signed_range(self):
        value = row()
        self.assertEqual(M.stat_rows(printed(value), 1), [value])
        for raw in (printed(value) + '\n', printed(value).replace('st_uid: 1000', 'st_uid: True'),
                    printed(value).replace('st_uid: 1000', 'st_uid: ' + str(2 ** 63)),
                    printed(value).replace('st_uid: 1000', 'uid: 1000'), printed(value)[:-10]):
            with self.subTest(raw=raw[:50]), self.assertRaises(ValueError):
                M.stat_rows(raw, 1)

    def test_metadata_rejects_owner_type_hardlinks_modes_size_exec(self):
        for key, value in (('st_uid', 0), ('st_gid', 0), ('st_mode', stat.S_IFLNK | 0o777),
                           ('st_nlink', 2), ('st_mode', stat.S_IFREG | 0o666),
                           ('st_mode', stat.S_IFREG | 0o4600), ('st_size', 5)):
            with self.subTest(key=key, value=value):
                item = row()
                item[key] = value
                with self.assertRaises(ValueError):
                    M.guest_metadata(item, 'file', 1000, 1000, size=1, executable=False)
        with self.assertRaises(ValueError):
            M.guest_metadata(row(), 'file', 1000, 1000, size=1, executable=True)

    def test_header_metadata_checked_before_download(self):
        with tempfile.TemporaryDirectory() as directory, mock.patch.object(M, 'MAX_ROOT', 16384):
            fixture = Fixture(directory)
            fixture.mutate_row = lambda path, value: value.update(st_size=M.MAX_RESULT + 1) if path.endswith('build-result.json') else None
            with self.assertRaises(ValueError):
                fixture.export()
            self.assertFalse(any(op[0].startswith('download') for call in fixture.calls for op in call[1]))

    def test_symlink_ancestor_and_wrong_header_owner_refused(self):
        for path, change in (('/home/vpci', dict(st_mode=stat.S_IFLNK | 0o777)),
                             (M.GUEST_OUTPUT + '/inventory.json', dict(st_uid=0))):
            with self.subTest(path=path), tempfile.TemporaryDirectory() as directory, mock.patch.object(M, 'MAX_ROOT', 16384):
                fixture = Fixture(directory)
                fixture.mutate_row = lambda name, value: value.update(change) if name == path else None
                with self.assertRaises(ValueError):
                    fixture.export()
                self.assertFalse(any(op[0].startswith('download') for call in fixture.calls for op in call[1]))

    def test_wrong_asset_parent_or_symlink_metadata_blocks_all_asset_downloads(self):
        for suffix, change in (('/assets/runtime', dict(st_mode=stat.S_IFLNK | 0o777)),
                               ('/assets/runtime/bin/python', dict(st_uid=0)),
                               ('/assets/volparossa', dict(st_size=1))):
            with self.subTest(suffix=suffix), tempfile.TemporaryDirectory() as directory, mock.patch.object(M, 'MAX_ROOT', 16384):
                fixture = Fixture(directory)
                fixture.mutate_row = lambda name, value: value.update(change) if name.endswith(suffix) else None
                with self.assertRaises(ValueError):
                    fixture.export()
                self.assertFalse(any(call[-1] == 'model_export_assets' for call in fixture.calls))


class ExportTests(unittest.TestCase):
    def test_real_files_are_allowlisted_hashed_and_links_reconstructed_without_export_tar(self):
        with tempfile.TemporaryDirectory() as directory, mock.patch.object(M, 'MAX_ROOT', 16384):
            fixture = Fixture(directory)
            result = fixture.export()
            self.assertEqual(M.STAGER.scan(result['assets'], deadline()), fixture.public.value['entries'].keys())
            self.assertEqual(os.readlink(result['assets'] / 'runtime/bin/python3'), '/usr/bin/python3.13')
            self.assertEqual(stat.S_IMODE(result['assets'].stat().st_mode), 0o700)
            for name, item in fixture.public.value['entries'].items():
                if item['kind'] == 'file':
                    self.assertEqual((result['assets'] / name).read_bytes(), (fixture.public.assets / name).read_bytes())
                    self.assertEqual(stat.S_IMODE((result['assets'] / name).stat().st_mode), 0o755 if item['executable'] else 0o644)
            self.assertFalse(list((fixture.root / 'export').glob('*.tar')))
            self.assertEqual(sum(call[-1] == 'model_export_assets' for call in fixture.calls), 1)
            self.assertTrue(all(call[2] and call[3] == 'qcow2' for call in fixture.calls))

    def test_builder_failure_or_false_source_never_exports_assets(self):
        for key, value in (('state', 'failed'), ('phase', 'provision'), ('source_tree', '0' * 40),
                           ('model_execution', True), ('direct_child_groups_joined', False),
                           ('descendants_joined', True), ('version', True), ('installed_build_packages', 1)):
            with self.subTest(key=key), tempfile.TemporaryDirectory() as directory, mock.patch.object(M, 'MAX_ROOT', 16384):
                fixture = Fixture(directory)
                fixture.report[key] = value
                with self.assertRaises(ValueError):
                    fixture.export()
                self.assertFalse(any(call[-1] == 'model_export_assets' for call in fixture.calls))

    def test_inventory_hash_count_and_workload_mismatch_rejected(self):
        for key, value in (('inventory_sha256', '0' * 64), ('asset_files', 1),
                           ('asset_bytes', 1), ('workload_sha256', '0' * 64)):
            with self.subTest(key=key), tempfile.TemporaryDirectory() as directory, mock.patch.object(M, 'MAX_ROOT', 16384):
                fixture = Fixture(directory)
                fixture.report['export'][key] = value
                with self.assertRaises(ValueError):
                    fixture.export()

    def test_asset_corruption_and_short_transfer_fail_closed(self):
        for mutation in (lambda raw: b'x' + raw[1:], lambda raw: raw[:-1]):
            with tempfile.TemporaryDirectory() as directory, mock.patch.object(M, 'MAX_ROOT', 16384):
                fixture = Fixture(directory)
                fixture.mutate_download = lambda path, raw: mutation(raw) if path.endswith('/assets/volparossa') else raw
                with self.assertRaisesRegex(ValueError, 'export_asset_digest'):
                    fixture.export()

    def test_image_changed_during_export_is_not_a_completed_result(self):
        with tempfile.TemporaryDirectory() as directory, mock.patch.object(M, 'MAX_ROOT', 16384):
            fixture = Fixture(directory)
            def callback(*args, **kwargs):
                value = fixture.guestfish(*args, **kwargs)
                if kwargs['operation'] == 'model_export_assets':
                    fixture.build.write_bytes(b'changed image')
                return value
            with self.assertRaisesRegex(ValueError, 'build_image_changed'):
                fixture.export(guestfish=callback)

    def test_callback_failure_and_late_completion_preserve_original_deadline(self):
        with tempfile.TemporaryDirectory() as directory, mock.patch.object(M, 'MAX_ROOT', 16384):
            fixture = Fixture(directory)
            original = RuntimeError('public fixture failure')
            with self.assertRaises(RuntimeError) as caught:
                fixture.export(guestfish=mock.Mock(side_effect=original))
            self.assertIs(caught.exception, original)
        with mock.patch.object(M.time, 'monotonic', side_effect=[10, 12]):
            callback = mock.Mock(return_value='')
            with self.assertRaisesRegex(ValueError, 'assemble_deadline'):
                M.call(callback, Path('/public'), [], 11, 'model_export_assets')
            self.assertEqual(callback.call_args.kwargs['timeout'], 1)

    def test_optional_observation_cannot_mask_interruption(self):
        with tempfile.TemporaryDirectory() as directory, mock.patch.object(M, 'MAX_ROOT', 16384):
            fixture = Fixture(directory)
            original = KeyboardInterrupt()
            with self.assertRaises(KeyboardInterrupt) as caught:
                fixture.export(guestfish=mock.Mock(side_effect=original))
            self.assertIs(caught.exception, original)
            self.assertFalse((fixture.root / 'export/inventory.json').exists())

    def test_inventory_rejects_traversal_and_external_symlink_before_asset_download(self):
        for mutation in ('path', 'symlink'):
            with self.subTest(mutation=mutation), tempfile.TemporaryDirectory() as directory, mock.patch.object(M, 'MAX_ROOT', 16384):
                fixture = Fixture(directory)
                if mutation == 'path':
                    fixture.public.value['entries']['../escape'] = W.record(b'escape')
                else:
                    fixture.public.value['entries']['runtime/bin/python3']['target'] = '/private/host/path'
                fixture.report['export']['inventory_sha256'] = fixture.public.inventory()
                with self.assertRaises(ValueError):
                    fixture.export()
                self.assertFalse(any(call[-1] == 'model_export_assets' for call in fixture.calls))

    def test_metadata_output_bound_and_duplicate_field_rejected(self):
        with mock.patch.object(M, 'MAX_METADATA', 8):
            with self.assertRaisesRegex(ValueError, 'guestfish_output_bound'):
                M.call(mock.Mock(return_value='x' * 9), Path('/public'), [], deadline(), 'model_export_metadata')
        raw = printed(row()).replace('st_gid: 1000', 'st_uid: 1000')
        with self.assertRaisesRegex(ValueError, 'guest_stat_field'):
            M.stat_rows(raw, 1)


class AssemblyTests(unittest.TestCase):
    def test_connected_export_stager_tar_in_and_final_closure_use_real_validators(self):
        with tempfile.TemporaryDirectory() as directory, mock.patch.object(M, 'MAX_ROOT', 16384):
            fixture = Fixture(directory)
            exported = fixture.export()
            result = fixture.assemble(exported)
            self.assertEqual(result['root_tree'].joinpath(M.BOOT.ENTRY.lstrip('/')).read_bytes(), M.BOOT.entrypoint())
            self.assertEqual(result['kernel'].read_bytes(), b'public kernel, never executed')
            self.assertEqual(result['original_initrd'].read_bytes(), b'public original initrd')
            self.assertTrue(result['staging_receipt']['staged'])
            for flag in ('model_execution', 'worker_execution', 'private_inputs', 'hardware_attestation', 'production_approval'):
                self.assertIs(result[flag], False)
            writes = [call for call in fixture.calls if not call[2]]
            self.assertEqual(len(writes), 1)
            self.assertEqual([op[0] for op in writes[0][1]], ['mount', 'tar-in', 'tar-in', 'sync', 'umount-all'])
            self.assertEqual(writes[0][0], fixture.runtime)
            self.assertTrue(all(call[2] for call in fixture.calls if call[-1] == 'model_extract_closure'))
            with tarfile.open(fixture.root / 'assembled/workload.tar') as archive:
                self.assertEqual(archive.getmember('opt/volparossa/runtime').uid, 985)
                self.assertEqual(archive.getmember('opt/volparossa/runtime').mode, 0o700)
                self.assertEqual(archive.getmember('opt/volparossa/runtime/.volparossa-compute.lock').mode, 0o600)
            with tarfile.open(fixture.root / 'assembled/boot-overlay.tar') as archive:
                self.assertTrue(all(member.uid == member.gid == 0 for member in archive))

    def test_runtime_binding_rechecked_before_any_mutation(self):
        with tempfile.TemporaryDirectory() as directory, mock.patch.object(M, 'MAX_ROOT', 16384):
            fixture = Fixture(directory)
            exported = fixture.export()
            fixture.runtime.write_bytes(b'wrong stopped disk')
            before = len(fixture.calls)
            with self.assertRaisesRegex(ValueError, 'runtime_image_binding'):
                fixture.assemble(exported)
            self.assertEqual(len(fixture.calls), before)

    def test_exported_asset_change_rejected_by_real_stager_before_image_write(self):
        with tempfile.TemporaryDirectory() as directory, mock.patch.object(M, 'MAX_ROOT', 16384):
            fixture = Fixture(directory)
            exported = fixture.export()
            (exported['assets'] / 'public-policy.json').write_bytes(b'changed')
            before = len(fixture.calls)
            with self.assertRaises(ValueError):
                fixture.assemble(exported)
            self.assertEqual(len(fixture.calls), before)

    def test_wrong_raw_filesystem_never_gets_tar_in(self):
        with tempfile.TemporaryDirectory() as directory, mock.patch.object(M, 'MAX_ROOT', 16384):
            fixture = Fixture(directory)
            exported = fixture.export()
            original = fixture.guestfish
            def callback(*args, **kwargs):
                value = original(*args, **kwargs)
                return value.replace('ext4', 'xfs') if value.startswith('ext4') else value
            fixture.guestfish = callback
            with self.assertRaisesRegex(ValueError, 'runtime_filesystem'):
                fixture.assemble(exported)
            self.assertFalse(any(not call[2] for call in fixture.calls))

    def test_new_runtime_limit_and_old_boot_limits_remain_distinct(self):
        self.assertEqual(M.MAX_ROOT, 32 * 1024 ** 3)
        self.assertEqual(M.IMAGE.MAX_ROOT, 16 * 1024 ** 3)
        self.assertEqual(M.IMAGE.MAX_TREE, 4 * 1024 ** 3)
        self.assertEqual(M.BOOT.MAX_DATA_BLOCKS * 4096, M.MAX_ROOT)

    def test_joined_build_image_can_be_removed_after_verified_export_before_assembly(self):
        with tempfile.TemporaryDirectory() as directory, mock.patch.object(M, 'MAX_ROOT', 16384):
            fixture = Fixture(directory)
            exported = fixture.export()
            meta = fixture.build.stat()
            self.assertEqual(exported['build_image_identity'], (meta.st_dev, meta.st_ino))
            fixture.build.unlink()  # Only this test's owned tiny public file.
            result = fixture.assemble(exported)
            self.assertTrue(result['staging_receipt']['staged'])
            self.assertFalse(fixture.build.exists())

    def test_runtime_must_be_separate_and_cleanup_still_complete(self):
        for mutation in ('same_image', 'cleanup'):
            with self.subTest(mutation=mutation), tempfile.TemporaryDirectory() as directory, mock.patch.object(M, 'MAX_ROOT', 16384):
                fixture = Fixture(directory)
                exported = fixture.export()
                if mutation == 'same_image':
                    exported['build_image'] = fixture.runtime
                else:
                    fixture.cleanup['runtime_unmounted'] = False
                before = len(fixture.calls)
                with self.assertRaises(ValueError):
                    fixture.assemble(exported)
                self.assertEqual(len(fixture.calls), before)

    def test_boot_metadata_failure_stops_before_boot_download(self):
        with tempfile.TemporaryDirectory() as directory, mock.patch.object(M, 'MAX_ROOT', 16384):
            fixture = Fixture(directory)
            exported = fixture.export()
            fixture.mutate_row = lambda name, item: item.update(st_uid=1000) if name.startswith('/boot/') else None
            with self.assertRaisesRegex(ValueError, 'guest_asset_owner_kind'):
                fixture.assemble(exported)
            self.assertFalse(any(op[0] == 'tar-out' for call in fixture.calls for op in call[1]))

    def test_missing_or_changed_fixed_entrypoint_fails_final_real_validator(self):
        with tempfile.TemporaryDirectory() as directory, mock.patch.object(M, 'MAX_ROOT', 16384):
            fixture = Fixture(directory)
            exported = fixture.export()
            original = fixture.guestfish
            def callback(*args, **kwargs):
                if kwargs['operation'] == 'model_extract_closure':
                    entry = fixture.guest / M.BOOT.ENTRY.lstrip('/')
                    if entry.exists():
                        entry.chmod(0o755)
                        entry.write_bytes(b'changed, never executed')
                        entry.chmod(0o555)
                return original(*args, **kwargs)
            fixture.guestfish = callback
            with self.assertRaisesRegex(ValueError, 'model_entry_identity'):
                fixture.assemble(exported)
            self.assertIsNone(M.IMAGE.DEADLINE.get())


if __name__ == '__main__':
    unittest.main()
