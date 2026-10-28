#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-only
"""Stopped PUBLIC build-guest export and offline runtime-image assembly.

Only repository validators run on the host. No exported executable is loaded.
The controller supplies its joined/empty/unmounted receipt and an owned,
deadline-bound guestfish callback; this helper cannot establish VM ownership.
Images are bound after stop, and assets are downloaded individually through one
command list, not through another full model tar. The one workload tar is the
existing stager's checked guest installation artifact. Sealing, boot, whole
controller cleanup and any actual model result remain separate obligations.
"""
import hashlib
import math
import os
from pathlib import Path, PurePosixPath
import re
import stat
import subprocess
import tarfile
import time
import types

HERE = Path(__file__).resolve().parent
MAX_ROOT = 32 * 1024 ** 3
MAX_BUILD_IMAGE = 128 * 1024 ** 3
MAX_METADATA = 64 * 1024 ** 2
MAX_RESULT = 1024 ** 2
GUEST_OUTPUT = '/home/vpci/resident-output'
SHA = re.compile(r'[0-9a-f]{64}\Z')
SOURCE = re.compile(r'[0-9a-f]{40}\Z')
ASSEMBLY_STEPS = frozenset(('space_reservation', 'cleanup_binding', 'build_receipt',
    'build_identity', 'runtime_image_binding', 'output_directory', 'workload_stage',
    'boot_overlay', 'runtime_filesystem', 'runtime_install', 'boot_metadata',
    'boot_export', 'boot_validate', 'root_extract', 'root_validate',
    'runtime_final_binding', 'kernel_binding', 'receipt_write'))
# Exact source-owned guards only. This is diagnostic vocabulary, never a new
# admission rule. Unlisted nested errors remain unknown rather than raw text.
ASSEMBLY_PREDICATES = frozenset('''
assemble_deadline assemble_file_bound assemble_file_changed assemble_file_metadata
assemble_file_path assemble_output_parent build_cleanup_required build_export_bound
build_export_digest build_export_identity build_export_shape build_guest_owner
build_result_binding build_result_profile build_result_scope cleanup_image_binding
cleanup_source_shape guest_asset_executable guest_asset_mode guest_asset_owner_kind
guest_asset_size_links guest_stat_bound guest_stat_count guest_stat_field
guest_stat_range guestfish_output_bound runtime_boot_bound runtime_boot_size
runtime_filesystem runtime_image_binding runtime_image_size runtime_kernel_modules
runtime_stage_stdout runtime_usr_merge separate_runtime_image staged_workload_binding
asset_digest asset_directory_metadata asset_file_bound asset_file_metadata
asset_inventory_exact asset_path asset_root asset_scope core_executable core_source
duplicate_json_key elf_bound elf_identity executable_scope file_inventory fixture_tls_bound
inventory_bound inventory_changed inventory_digest inventory_entries inventory_entry
inventory_parent_file inventory_scope inventory_total lease_is_generated model_inventory
model_pin native_artifact_binding native_build_binding native_build_digest
native_dependency_binding native_inventory native_manifest_digest native_session_required
native_wrapper_binding nonfinite_json output_path public_policy_binding runtime_config
runtime_python stage_deadline symlink_changed symlink_escape symlink_external symlink_loop
symlink_missing symlink_scope symlink_target inventory_path_type inventory_path_empty
inventory_path_length inventory_path_character_or_separator inventory_path_dot_component
boot_overlay_kind model_boot_directory model_boot_metadata model_boot_root
model_entry_identity model_entry_template model_mountpoint model_write_probe
archive_bound archive_duplicate archive_hardlink archive_overwrite_symlink
archive_parent_symlink archive_path archive_special_file cancelled build_deadline
initrd_path initrd_path_escape initrd_file initrd_file_changed initrd_elf
initrd_elf_machine initrd_elf_headers initrd_elf_segment initrd_elf_dynamic
initrd_elf_interpreter initrd_elf_search_path initrd_elf_dynamic_end initrd_elf_strings
initrd_elf_needed initrd_symlink_loop initrd_parent kernel_feature_BLK_DEV_INITRD kernel_feature_DEVTMPFS
kernel_feature_EXT4_FS kernel_feature_BLK_DEV_DM kernel_feature_DM_VERITY
kernel_feature_VIRTIO_PCI kernel_feature_VIRTIO_BLK kernel_feature_SERIAL_8250
kernel_feature_SERIAL_8250_CONSOLE compiler_proof_scope compiler_proof_profile
compiler_proof_digest compiler_proof_source space_workload_stage runtime_kernel_binding
'''.split())
STAT_FIELDS = ('st_dev', 'st_ino', 'st_mode', 'st_nlink', 'st_uid', 'st_gid',
               'st_rdev', 'st_size', 'st_blksize', 'st_blocks', 'st_atime_sec',
               'st_atime_nsec', 'st_mtime_sec', 'st_mtime_nsec', 'st_ctime_sec',
               'st_ctime_nsec', 'st_spare1', 'st_spare2', 'st_spare3', 'st_spare4',
               'st_spare5', 'st_spare6')


def module(name):
    path = HERE / (name + '.py')
    value = types.ModuleType(name.replace('-', '_'))
    value.__file__ = str(path)
    exec(compile(path.read_bytes(), str(path), 'exec'), value.__dict__)
    return value


STAGER = module('protected-resident-model-workload')
BOOT = module('protected-resident-model-initrd')
IMAGE = module('protected-resident-image')
BUILD = module('protected-resident-model-build')
require = STAGER.require


def assembly_step(observation, step):
    """Optional entered-only marker; it cannot authorize or replace an operation."""
    try:
        if type(observation) is dict and type(step) is str and step in ASSEMBLY_STEPS:
            observation['step'] = step
    except Exception:
        pass


def assembly_failure(observation, error, phase):
    """Project only this controller phase, fixed guards and closed exception classes."""
    if type(phase) is not str or phase != 'runtime_assembly':
        return None
    step = observation.get('step') if type(observation) is dict else None
    if type(step) is not str or step not in ASSEMBLY_STEPS:
        step = 'unavailable'
    predicate = None
    category = {
        ValueError: 'invalid_value', OSError: 'io', FileNotFoundError: 'missing_file',
        FileExistsError: 'existing_path', PermissionError: 'permission_denied',
        InterruptedError: 'interrupted', TimeoutError: 'timeout',
        KeyError: 'missing_field', TypeError: 'invalid_type',
        subprocess.CalledProcessError: 'subprocess_failed',
        subprocess.TimeoutExpired: 'subprocess_timeout',
    }.get(type(error), 'unknown')
    if (type(error) is ValueError and len(error.args) == 1
            and type(error.args[0]) is str and error.args[0] in ASSEMBLY_PREDICATES):
        category, predicate = 'guard', error.args[0]
    return dict(version=1, scope='runtime_assembly', diagnostic_only=True,
        acceptance_evidence=False, causal_attribution=False, step_semantics='entered_only',
        step=step, category=category, predicate=predicate)


def remaining(deadline, cap=1200):
    require(type(deadline) in (int, float) and math.isfinite(deadline), 'assemble_deadline')
    left = deadline - time.monotonic()
    require(left > 0, 'assemble_deadline')
    return min(left, cap)


def identity(meta):
    return STAGER.identity(meta)


def file_digest(path, maximum, deadline):
    remaining(deadline)
    require(path.is_absolute() and path.resolve(strict=True) == path, 'assemble_file_path')
    with os.fdopen(os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK), 'rb') as stream:
        before = os.fstat(stream.fileno())
        require(stat.S_ISREG(before.st_mode) and before.st_uid == os.getuid()
                and before.st_nlink == 1 and not before.st_mode & 0o022
                and 0 <= before.st_size <= maximum, 'assemble_file_metadata')
        digest, count = hashlib.sha256(), 0
        while block := stream.read(1024 ** 2):
            remaining(deadline)
            count += len(block)
            require(count <= maximum, 'assemble_file_bound')
            digest.update(block)
        require(count == before.st_size and identity(before) == identity(os.fstat(stream.fileno())),
                'assemble_file_changed')
    remaining(deadline)
    return dict(bytes=count, sha256=digest.hexdigest())


def image_record(value, maximum):
    require(type(value) is dict and value.keys() == {'bytes', 'sha256'}
            and type(value['bytes']) is int and 0 < value['bytes'] <= maximum
            and type(value['sha256']) is str and SHA.fullmatch(value['sha256']), 'cleanup_image_binding')


def validate_cleanup(receipt, expected_source, expected_tree):
    """Validate controller assertions, not derive them from a guest boolean."""
    flags = {'qemu_process_joined', 'scope_empty', 'guest_build_units_empty',
             'guest_root_units_empty', 'runtime_unmounted'}
    keys = {'version', 'kind', 'source_commit', 'source_tree', 'guest_uid', 'guest_gid',
            'build_image', 'runtime_image', *flags}
    require(type(expected_source) is str and SOURCE.fullmatch(expected_source)
            and type(expected_tree) is str and SOURCE.fullmatch(expected_tree), 'cleanup_source_shape')
    require(type(receipt) is dict and receipt.keys() == keys
            and type(receipt['version']) is int and receipt['version'] == 1
            and receipt['kind'] == 'protected-resident-model-build-cleanup'
            and receipt['source_commit'] == expected_source and receipt['source_tree'] == expected_tree
            and all(receipt[key] is True for key in flags), 'build_cleanup_required')
    for key in ('guest_uid', 'guest_gid'):
        require(type(receipt[key]) is int and 0 < receipt[key] < 2 ** 31, 'build_guest_owner')
    image_record(receipt['build_image'], MAX_BUILD_IMAGE)
    image_record(receipt['runtime_image'], MAX_ROOT)
    require(receipt['runtime_image']['bytes'] == MAX_ROOT, 'runtime_image_size')


def new_directory(path):
    require(path.is_absolute() and path.parent.resolve(strict=True) == path.parent
            and path.parent.is_dir() and path.parent.stat().st_uid == os.getuid()
            and not path.parent.stat().st_mode & 0o022, 'assemble_output_parent')
    path.mkdir(mode=0o700)  # Existing files, directories and dangling links all fail.
    path.chmod(0o700)


def call(guestfish, image, operations, deadline, operation, *, readonly=True, image_format='raw'):
    output = guestfish(image, operations, readonly=readonly, image_format=image_format,
                      timeout=remaining(deadline), operation=operation)
    remaining(deadline)
    require(type(output) is str and len(output.encode()) <=
            (MAX_METADATA if operation == 'model_export_metadata' else MAX_RESULT), 'guestfish_output_bound')
    return output


def stat_rows(raw, count):
    """Exact numeric guestfish statns output; never parse arbitrary shell text.

    libguestfs v1.52 generator/structs.ml defines these 22 FInt64 fields.
    generator/fish.ml uses the generated struct printer, in declaration order.
    """
    require(type(raw) is str and len(raw.encode()) <= MAX_METADATA, 'guest_stat_bound')
    lines = raw.splitlines()
    require(len(lines) == count * len(STAT_FIELDS), 'guest_stat_count')
    rows = []
    for offset in range(count):
        row = {}
        for index, key in enumerate(STAT_FIELDS):
            line = lines[offset * len(STAT_FIELDS) + index]
            prefix = key + ': '
            require(line.startswith(prefix) and re.fullmatch(r'-?[0-9]{1,20}', line[len(prefix):]),
                    'guest_stat_field')
            value = int(line[len(prefix):])
            require(-(2 ** 63) <= value < 2 ** 63, 'guest_stat_range')
            row[key] = value
        rows.append(row)
    return rows


def guest_metadata(row, kind, uid, gid, *, size=None, executable=None):
    mode = row['st_mode']
    predicate = {'directory': stat.S_ISDIR, 'file': stat.S_ISREG, 'symlink': stat.S_ISLNK}[kind]
    require(predicate(mode) and row['st_uid'] == uid and row['st_gid'] == gid
            and row['st_ino'] > 0 and row['st_dev'] >= 0, 'guest_asset_owner_kind')
    if kind != 'symlink':
        require(not mode & 0o7022, 'guest_asset_mode')
    if kind == 'file':
        require(row['st_nlink'] == 1 and row['st_size'] == size, 'guest_asset_size_links')
        if executable is not None:
            require(bool(mode & 0o111) == executable, 'guest_asset_executable')
    if kind == 'symlink':
        require(row['st_nlink'] == 1, 'guest_asset_symlink_links')


def build_result(value, source, tree, *, legacy=False):
    keys = {'version', 'kind', 'state', 'phase', 'source_commit', 'source_tree', 'code_helper_commit',
            'code_helper_sha256', 'package_lock_sha256', 'assets_exported', 'model_execution',
            'worker_execution', 'private_inputs', 'hardware_attestation', 'production_approval',
            'controller_cgroup_cleanup_required', 'direct_child_groups_joined', 'descendants_joined',
            'complete_guest_cleanup', 'scratch_removed', 'installed_build_packages', 'provision',
            'native_build_manifest_sha256', 'export'}
    if not legacy:
        keys.add('compiler')
    require(type(legacy) is bool, 'build_result_profile')
    require(type(value) is dict and value.keys() == keys and type(value['version']) is int
            and value['version'] == (1 if legacy else 2) and value['kind'] == 'protected-resident-public-model-build'
            and value['state'] == 'assets_built' and value['phase'] == 'complete'
            and value['source_commit'] == source and value['source_tree'] == tree
            and value['code_helper_commit'] == BUILD.CODE_COMMIT
            and value['code_helper_sha256'] == BUILD.HELPER_SHA256
            and value['assets_exported'] is True and value['direct_child_groups_joined'] is True
            and value['controller_cgroup_cleanup_required'] is True and value['descendants_joined'] is None
            and all(value[key] is False for key in ('model_execution', 'worker_execution', 'private_inputs',
                    'hardware_attestation', 'production_approval', 'complete_guest_cleanup', 'scratch_removed')),
            'build_result_scope')
    if not legacy:
        BUILD.validate_compiler_proof(value['compiler'], HERE.parents[1])
    lock = hashlib.sha256((HERE / 'protected-resident-model-debian-lock-v1.json').read_bytes()).hexdigest()
    require(value['package_lock_sha256'] == lock and type(value['installed_build_packages']) is int
            and value['installed_build_packages'] == 199 and type(value['provision']) is dict
            and type(value['native_build_manifest_sha256']) is str
            and SHA.fullmatch(value['native_build_manifest_sha256']), 'build_result_binding')
    export = value['export']
    require(type(export) is dict and export.keys() == {'inventory_sha256', 'workload_sha256',
            'native_backend_sha256', 'asset_files', 'asset_bytes'}, 'build_export_shape')
    for key in ('inventory_sha256', 'workload_sha256', 'native_backend_sha256'):
        require(type(export[key]) is str and SHA.fullmatch(export[key]), 'build_export_digest')
    require(type(export['asset_files']) is int and 0 < export['asset_files'] <= STAGER.MAX_ENTRIES
            and type(export['asset_bytes']) is int and 0 < export['asset_bytes'] <= STAGER.MAX_TOTAL,
            'build_export_bound')
    return export


def export_assets(build_image, output, cleanup, expected_source, expected_tree, guestfish, deadline):
    """Export only inventory-bound assets from the stopped qcow2 build image.

    Partial output is private and remains controller-owned on any exception.
    No success result is returned until every digest and the source image have
    been rechecked. Callback operations contain paths, never shell commands.
    """
    validate_cleanup(cleanup, expected_source, expected_tree)
    require(file_digest(build_image, MAX_BUILD_IMAGE, deadline) == cleanup['build_image'], 'build_image_binding')
    new_directory(output)
    device = IMAGE.root_device(call(guestfish, build_image, [['inspect-os']], deadline,
                                   'model_export_header', image_format='qcow2'))
    paths = [GUEST_OUTPUT + '/build-result.json', GUEST_OUTPUT + '/inventory.json']
    ancestors = ['/home', '/home/vpci', GUEST_OUTPUT]
    raw = call(guestfish, build_image, [['mount-ro', device, '/'],
        *[['lstatns', path] for path in ancestors + paths]],
        deadline, 'model_export_header', image_format='qcow2')
    rows = stat_rows(raw, 5)
    guest_metadata(rows[0], 'directory', 0, 0)
    for row in rows[1:3]:
        guest_metadata(row, 'directory', cleanup['guest_uid'], cleanup['guest_gid'])
    rows = rows[3:]
    for name, row, maximum in zip(('build-result.json', 'inventory.json'), rows, (MAX_RESULT, STAGER.MAX_INVENTORY)):
        require(0 < row['st_size'] <= maximum, 'build_header_bound')
        guest_metadata(row, 'file', cleanup['guest_uid'], cleanup['guest_gid'], size=row['st_size'])
    require(not call(guestfish, build_image, [['mount-ro', device, '/'],
        *[['download-offset', path, output / name, '0', str(row['st_size'])]
          for path, name, row in zip(paths, ('build-result.json', 'inventory.json'), rows)]],
        deadline, 'model_export_header', image_format='qcow2').strip(), 'header_export_stdout')
    for name, row, maximum in zip(('build-result.json', 'inventory.json'), rows, (MAX_RESULT, STAGER.MAX_INVENTORY)):
        path = output / name
        require(file_digest(path, maximum, deadline)['bytes'] == row['st_size'], 'build_header_size')
        path.chmod(0o600)
    value = STAGER.parse((output / 'build-result.json').read_bytes())
    export = build_result(value, expected_source, expected_tree)
    inventory = STAGER.inventory(STAGER.read_inventory(output / 'inventory.json', deadline),
                                 export['inventory_sha256'], expected_source)
    entries = inventory['entries']
    require(export['asset_files'] == len(entries) and export['asset_bytes'] ==
            sum(item.get('bytes', 0) for item in entries.values())
            and export['workload_sha256'] == STAGER.workload_sha256(inventory)
            and entries.get('native-backend/build.json', {}).get('sha256') == value['native_build_manifest_sha256']
            and entries.get('native-backend/backend.json', {}).get('sha256') == export['native_backend_sha256'],
            'build_export_binding')
    parents = {''}
    for name in entries:
        parents.update(parent.as_posix() for parent in PurePosixPath(name).parents if parent.as_posix() != '.')
    require(len(parents) + len(entries) <= 2 * STAGER.MAX_ENTRIES, 'guest_asset_count')
    ordered = sorted(parents, key=lambda name: (name.count('/'), name)) + sorted(entries)
    guest_paths = [GUEST_OUTPUT + '/assets' + ('/' + name if name else '') for name in ordered]
    links = [name for name in sorted(entries) if entries[name]['kind'] == 'symlink']
    raw = call(guestfish, build_image, [['mount-ro', device, '/'],
        *[['lstatns', path] for path in guest_paths],
        *[['readlink', GUEST_OUTPUT + '/assets/' + name] for name in links]],
        deadline, 'model_export_metadata', image_format='qcow2')
    lines = raw.splitlines()
    split = len(ordered) * len(STAT_FIELDS)
    rows = stat_rows('\n'.join(lines[:split]), len(ordered))
    require(lines[split:] == [entries[name]['target'] for name in links], 'guest_symlink_target')
    for name, row in zip(ordered, rows):
        item = entries.get(name)
        guest_metadata(row, item['kind'] if item else 'directory', cleanup['guest_uid'], cleanup['guest_gid'],
                       size=item.get('bytes') if item else None,
                       executable=item.get('executable') if item else None)
    assets = output / 'assets'
    assets.mkdir(mode=0o700)
    for name in sorted(parents - {''}, key=lambda name: (name.count('/'), name)):
        (assets / name).mkdir(mode=0o700)
    downloads = [['mount-ro', device, '/']]
    for name, item in sorted(entries.items()):
        if item['kind'] == 'file':
            downloads.append(['download-offset', GUEST_OUTPUT + '/assets/' + name,
                              assets / name, '0', str(item['bytes'])])
    require(not call(guestfish, build_image, downloads, deadline, 'model_export_assets',
                     image_format='qcow2').strip(), 'asset_export_stdout')
    for name, item in sorted(entries.items()):
        if item['kind'] == 'symlink':
            (assets / name).symlink_to(item['target'])
        else:
            require(file_digest(assets / name, STAGER.MAX_FILE, deadline) ==
                    {key: item[key] for key in ('bytes', 'sha256')}, 'export_asset_digest')
            (assets / name).chmod(0o755 if item['executable'] else 0o644)
    require(file_digest(build_image, MAX_BUILD_IMAGE, deadline) == cleanup['build_image'], 'build_image_changed')
    meta = build_image.lstat()
    return dict(build_image=build_image, build_image_identity=(meta.st_dev, meta.st_ino),
                assets=assets, inventory=output / 'inventory.json', build_result=value,
                inventory_sha256=export['inventory_sha256'], workload_sha256=export['workload_sha256'],
                source_commit=expected_source, source_tree=expected_tree)


def boot_overlay(output):
    tree = output / 'boot-overlay'
    tree.mkdir(mode=0o700)
    BOOT.stage_boot_files(tree)
    # Small fixed root-owned overlay only. Never package the asset tree twice.
    archive = output / 'boot-overlay.tar'
    with tarfile.open(archive, 'x', format=tarfile.USTAR_FORMAT) as target:
        for path in sorted(tree.rglob('*')):
            name = path.relative_to(tree).as_posix()
            meta = path.lstat()
            require(stat.S_ISDIR(meta.st_mode) or stat.S_ISREG(meta.st_mode), 'boot_overlay_kind')
            info = STAGER.info(name, stat.S_IMODE(meta.st_mode), 0,
                               kind=tarfile.DIRTYPE if path.is_dir() else tarfile.REGTYPE,
                               size=0 if path.is_dir() else meta.st_size)
            if path.is_dir():
                target.addfile(info)
            else:
                with path.open('rb') as stream:
                    target.addfile(info, stream)
    archive.chmod(0o600)
    return archive


def assemble_runtime(runtime_image, exported, output, cleanup, guestfish, deadline, *, observation=None):
    """Install one checked workload and fixed boot files, then read final closure.

    Runtime is an offline-configured, unmounted whole ext4 filesystem (32 GiB),
    not the build VM's qcow2 and not the old 16 GiB public-boot root. No sealer or
    exported executable is invoked here. Returned Paths are private controller
    inputs, not an artifact allowlist.
    """
    assembly_step(observation, 'cleanup_binding')
    source, tree = exported['source_commit'], exported['source_tree']
    validate_cleanup(cleanup, source, tree)
    assembly_step(observation, 'build_receipt')
    build_result(exported['build_result'], source, tree)
    # The joined build image may already have been removed to reclaim space.
    # Its canonical path and identity were retained only after the final hash.
    assembly_step(observation, 'build_identity')
    build_path, build_id = exported['build_image'], exported['build_image_identity']
    require(type(build_id) is tuple and len(build_id) == 2
            and all(type(item) is int and item >= 0 for item in build_id)
            and isinstance(build_path, Path) and build_path.is_absolute()
            and build_path.resolve(strict=False) == build_path, 'build_export_identity')
    runtime_meta = runtime_image.lstat()
    require(runtime_image.resolve(strict=True) != build_path
            and (runtime_meta.st_dev, runtime_meta.st_ino) != build_id, 'separate_runtime_image')
    assembly_step(observation, 'runtime_image_binding')
    require(file_digest(runtime_image, MAX_ROOT, deadline) == cleanup['runtime_image'], 'runtime_image_binding')
    assembly_step(observation, 'output_directory')
    new_directory(output)
    assembly_step(observation, 'workload_stage')
    staged = STAGER.stage_workload(exported['assets'], exported['inventory'], exported['inventory_sha256'],
                                    output / 'workload.tar', source, deadline)
    require(staged['workload_sha256'] == exported['workload_sha256']
            and staged['native_backend_sha256'] == exported['build_result']['export']['native_backend_sha256'],
            'staged_workload_binding')
    assembly_step(observation, 'boot_overlay')
    overlay = boot_overlay(output)
    assembly_step(observation, 'runtime_filesystem')
    info = call(guestfish, runtime_image, [['vfs-type', '/dev/sda'], ['blockdev-getsize64', '/dev/sda']],
                deadline, 'model_stage_runtime').splitlines()
    require(info == ['ext4', str(MAX_ROOT)], 'runtime_filesystem')
    assembly_step(observation, 'runtime_install')
    require(not call(guestfish, runtime_image, [['mount', '/dev/sda', '/'],
        ['tar-in', output / 'workload.tar', '/'], ['tar-in', overlay, '/'],
        ['sync'], ['umount-all']], deadline, 'model_stage_runtime', readonly=False).strip(), 'runtime_stage_stdout')
    assembly_step(observation, 'boot_metadata')
    pins = STAGER.parse((HERE / 'protected-resident-image-pins-v1.json').read_bytes())
    release = pins['kernel_release']
    boot_paths = [('/boot/vmlinuz-' + release, 'vmlinuz', 64 * 1024 ** 2),
                  ('/boot/config-' + release, 'kernel.config', 1024 ** 2),
                  ('/boot/initrd.img-' + release, 'original-initrd.img', BOOT.BASE.MAX_TOTAL)]
    metadata = stat_rows(call(guestfish, runtime_image, [['mount-ro', '/dev/sda', '/'],
        *[['lstatns', path] for path, _name, _bound in boot_paths]],
        deadline, 'model_extract_closure'), len(boot_paths))
    for (_path, _name, bound), item in zip(boot_paths, metadata):
        require(0 < item['st_size'] <= bound, 'runtime_boot_bound')
        guest_metadata(item, 'file', 0, 0, size=item['st_size'])
    assembly_step(observation, 'boot_export')
    result = call(guestfish, runtime_image, [['mount-ro', '/dev/sda', '/'],
        *[['download-offset', path, output / name, '0', str(item['st_size'])]
          for (path, name, _bound), item in zip(boot_paths, metadata)],
        ['tar-out', '/usr', output / 'usr.tar'],
        *[['readlink', '/' + name] for name in ('bin', 'sbin', 'lib', 'lib64')]],
        deadline, 'model_extract_closure').splitlines()
    require(result == ['usr/bin', 'usr/sbin', 'usr/lib', 'usr/lib64'], 'runtime_usr_merge')
    assembly_step(observation, 'boot_validate')
    boot_inputs = {name: file_digest(output / name, bound, deadline) for _path, name, bound in boot_paths}
    require(all(boot_inputs[name]['bytes'] == item['st_size'] for (_path, name, _bound), item in
                zip(boot_paths, metadata)), 'runtime_boot_size')
    IMAGE.kernel_config((output / 'kernel.config').read_text())
    assembly_step(observation, 'root_extract')
    closure = output / 'root-tree'
    closure.mkdir(mode=0o700)
    # Keep the old extractor's 4 GiB /usr cap intact; model files live in /opt.
    file_digest(output / 'usr.tar', MAX_ROOT + 128 * 1024 ** 2, deadline)
    token = IMAGE.DEADLINE.set(deadline)
    try:
        IMAGE.safe_tree(output / 'usr.tar', closure / 'usr')
    finally:
        IMAGE.DEADLINE.reset(token)
    remaining(deadline)
    assembly_step(observation, 'root_validate')
    for name, target in zip(('bin', 'sbin', 'lib', 'lib64'), result):
        (closure / name).symlink_to(target)
    for name in ('proc', 'sys', 'dev', 'run'):
        (closure / name).mkdir(mode=0o755)
        (closure / name).chmod(0o755)
    BOOT.validate_root(closure)
    require((closure / 'usr/lib/modules' / release).is_dir(), 'runtime_kernel_modules')
    assembly_step(observation, 'runtime_final_binding')
    final = file_digest(runtime_image, MAX_ROOT, deadline)
    return dict(root_tree=closure, kernel=output / 'vmlinuz', kernel_config=output / 'kernel.config',
                original_initrd=output / 'original-initrd.img', kernel_release=release,
                root_bytes=MAX_ROOT, runtime_image=final, staging_receipt=staged, boot_inputs=boot_inputs,
                source_commit=source, source_tree=tree, public_fixture_only=True,
                model_execution=False, worker_execution=False, hardware_attestation=False,
                private_inputs=False, production_approval=False)
