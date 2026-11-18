#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-only
"""Inert hosted workflow contracts; no download, SDK, native process or VM."""
import copy
from contextlib import redirect_stdout
import hashlib
import io
import json
import os
from pathlib import Path
import re
import runpy
import stat
import subprocess
import sys
import tempfile
import textwrap
from types import SimpleNamespace
import unittest
from unittest.mock import patch
import warnings
import zipfile

ROOT = Path(__file__).resolve().parents[2]
SOURCE = (ROOT / '.github/workflows/weather-android-delivery.yml').read_text()
WEATHER = '3b90442a9d5be4db73ccf83cba2028364980c3ca'


def embedded(name):
    start, end = '# BEGIN ' + name, '# END ' + name
    assert SOURCE.count(start) == SOURCE.count(end) == 1
    return textwrap.dedent(SOURCE.split(start, 1)[1].split(end, 1)[0])


def block(name):
    return SOURCE.split('- name: ' + name + '\n', 1)[1].split('      - ', 1)[0]


class AndroidHostedWiring(unittest.TestCase):
    def test_only_explicit_or_exact_workflow_branch_bounded_hosted_execution(self):
        self.assertIn('name: Weather Android protected core delivery\n', SOURCE)
        self.assertEqual(SOURCE.split('on:\n', 1)[1].split('\npermissions:', 1)[0].strip(),
            'workflow_dispatch:\n  push:\n    branches: [feature/weather-android-core]\n    paths:\n'
            '      - .github/workflows/weather-android-delivery.yml')
        for item in ('    runs-on: ubuntu-24.04', '    timeout-minutes: 150', '  cancel-in-progress: false',
                '  contents: read', '  actions: read'):
            self.assertIn(item, SOURCE)
        for forbidden in ('secrets.', 'continue-on-error:', '--retry', 'pull_request:', 'schedule:'):
            self.assertNotIn(forbidden, SOURCE)

    def test_all_actions_and_weather_source_are_exact(self):
        actions = re.findall(r'uses: ([^\s]+)', SOURCE)
        self.assertEqual(len(actions), 3)
        self.assertTrue(all(re.fullmatch(r'actions/(?:checkout|upload-artifact)@[a-f0-9]{40}', item) for item in actions))
        self.assertEqual(SOURCE.count('persist-credentials: false'), 2)
        self.assertIn('  VOLPAROSSA_WEATHER_SOURCE_SHA: ' + WEATHER, SOURCE)
        self.assertIn('          ref: ' + WEATHER, SOURCE)
        self.assertNotIn('ref: main', SOURCE)
        admission = json.loads((ROOT / 'tests/integration/weather-public-android-v6.json').read_text())
        self.assertEqual(admission['scope'], 'disposable-joined-android-core-only')
        self.assertIn('.scope == "disposable-joined-android-core-only"', SOURCE)
        self.assertEqual(admission['sources'], dict(weather=dict(commit=WEATHER)))
        for name in ('weather-android-native.py', 'weather-android-inner-diagnostic.py',
                'weather-android-driver-diagnostic.py'):
            module = runpy.run_path(str(ROOT / 'tests/integration' / name))
            self.assertEqual(module['WEATHER_COMMIT'], WEATHER)
            if name != 'weather-android-native.py':
                self.assertEqual(module['FIRST_DRIVER_WEATHER_COMMIT'], '0a31bf180f1a42b96b0ceaec3715f56496a559a5')
        inner = runpy.run_path(str(ROOT / 'tests/integration/weather-android-inner-diagnostic.py'))
        self.assertEqual(inner['LEGACY_WEATHER_COMMIT'], 'f6ee829961da387d9c0cd71b7163b47baab434fa')
        self.assertEqual(set(admission['artifacts']), {'decoder', 'abi'})
        self.assertEqual(len(admission['files']), 39)
        self.assertIn('(.files | length) == 39', SOURCE)
        self.assertIn('python3 -B tests/integration/test-weather-android-vm-wiring.py', SOURCE)
        self.assertIn('python3 -B tests/integration/test-weather-android-native.py', SOURCE)
        self.assertIn('python3 -B tests/integration/test-weather-android-kvm.py', SOURCE)
        self.assertIn('python3 -B tests/integration/test-weather-android-inner-diagnostic.py', SOURCE)

    def test_nested_checkout_and_vm_output_are_ignored_and_socket_bound_is_checked(self):
        paths = re.findall(r'(?m)^          path: ([.a-zA-Z0-9_/-]+)$', SOURCE)
        self.assertEqual(paths, ['.cache/weather-android-source'])
        ignored = subprocess.run(['git', 'check-ignore', '--no-index', '--stdin'], cwd=ROOT,
            input='\n'.join(paths + ['.cache/weather-android-delivery']) + '\n', text=True, capture_output=True, timeout=5)
        self.assertEqual(ignored.returncode, 0, ignored.stderr)
        self.assertIn('output="$GITHUB_WORKSPACE/.cache/weather-android-delivery"', SOURCE)
        self.assertIn("'weather-client-kvm.ABCDEF/android-api/core-api.sock'", embedded('COMBINED_RESOURCES'))

    def resources(self, root, memory, disk, *, device=True):
        original_text, original_stat = Path.read_text, Path.stat
        def read(path, *args, **kwargs):
            if path == Path('/proc/meminfo'): return f'MemAvailable: {memory // 1024} kB\n'
            return original_text(path, *args, **kwargs)
        def info(path, *args, **kwargs):
            if path == Path('/dev/kvm'): return SimpleNamespace(st_mode=stat.S_IFCHR if device else stat.S_IFREG)
            return original_stat(path, *args, **kwargs)
        with patch.object(sys, 'argv', ['guard', str(root)]), patch.object(Path, 'read_text', read), \
                patch.object(Path, 'stat', info), patch('shutil.disk_usage', return_value=SimpleNamespace(free=disk)):
            exec(compile(embedded('COMBINED_RESOURCES'), 'COMBINED_RESOURCES', 'exec'), {})

    def test_resource_guard_accounts_for_both_guests_and_reserve(self):
        gib = 1024**3
        with tempfile.TemporaryDirectory(prefix='wa-') as temporary:
            root = Path(temporary)
            self.resources(root, 10 * gib, 32 * gib)
            for memory, disk, device in ((10 * gib - 1024, 32 * gib, True), (10 * gib, 32 * gib - 1, True),
                    (10 * gib, 32 * gib, False)):
                with self.subTest(memory=memory, disk=disk, device=device), self.assertRaises(AssertionError):
                    self.resources(root, memory, disk, device=device)
            long = root / ('x' * 90) / 'output'; long.mkdir(parents=True)
            with self.assertRaises(AssertionError): self.resources(long, 10 * gib, 32 * gib)
        self.assertIn('(4 + 4 + 2) * 1024**3', embedded('FINAL_SOURCE_PREFLIGHT'))

    @staticmethod
    def metadata():
        pin = dict(repository='VOLPAROSSA/volparossa-weather', run_id=101, commit='a' * 40,
            id=202, name='admitted-decoder', sha256='b' * 64, bytes=1234)
        run = dict(id=101, run_attempt=1, head_sha='a' * 40, status='completed', conclusion='success')
        artifact = dict(id=202, name=pin['name'], size_in_bytes=1234, digest='sha256:' + 'b' * 64,
            expired=False, workflow_run=dict(id=101, head_sha='a' * 40))
        return pin, run, artifact

    def check_metadata(self, pin, run, artifact):
        with tempfile.TemporaryDirectory(prefix='wa-input-') as temporary:
            root = Path(temporary)
            for name, value in (('record.json', dict(artifacts=dict(decoder=pin))), ('decoder-run.json', run),
                    ('decoder-artifact.json', artifact)):
                (root / name).write_text(json.dumps(value))
            with patch.object(sys, 'argv', ['guard', str(root / 'record.json'), 'decoder', str(root)]):
                exec(compile(embedded('PUBLIC_ARTIFACT_METADATA'), 'PUBLIC_ARTIFACT_METADATA', 'exec'), {})

    def test_actual_metadata_guard_rejects_replaced_or_unfinished_artifacts(self):
        pin, run, artifact = self.metadata(); self.check_metadata(pin, run, artifact)
        for section, key, value in (
                ('run', 'run_attempt', 2), ('run', 'head_sha', 'c' * 40), ('run', 'id', 999),
                ('run', 'status', 'in_progress'), ('run', 'conclusion', 'failure'),
                ('artifact', 'id', 999), ('artifact', 'name', 'latest'), ('artifact', 'size_in_bytes', 1235),
                ('artifact', 'digest', 'sha256:' + 'c' * 64), ('artifact', 'expired', True),
                ('pin', 'repository', 'unknown/repository'), ('pin', 'bytes', 256 * 1024**2 + 1),
                ('pin', 'name', '../outside'), ('pin', 'run_id', True)):
            values = dict(zip(('pin', 'run', 'artifact'), copy.deepcopy((pin, run, artifact))))
            values[section][key] = value
            with self.subTest(section=section, key=key), self.assertRaises(AssertionError): self.check_metadata(**values)
        for key, value in (('id', 999), ('head_sha', 'c' * 40)):
            changed = copy.deepcopy(artifact); changed['workflow_run'][key] = value
            with self.assertRaises(AssertionError): self.check_metadata(pin, run, changed)

    def extract(self, root, members, *, wrong_hash=False):
        archive = root / 'decoder.zip'
        with warnings.catch_warnings():
            warnings.simplefilter('ignore', UserWarning)
            with zipfile.ZipFile(archive, 'w') as stream:
                for name, raw, mode in members:
                    info = zipfile.ZipInfo(name); info.create_system = 3; info.external_attr = mode << 16
                    stream.writestr(info, raw)
        archive.chmod(0o600)
        raw = archive.read_bytes()
        pin = dict(bytes=len(raw), sha256='f' * 64 if wrong_hash else hashlib.sha256(raw).hexdigest())
        record = root / 'record.json'; record.write_text(json.dumps(dict(artifacts=dict(decoder=pin))))
        with patch.object(sys, 'argv', ['extract', str(record), 'decoder', str(root)]):
            exec(compile(embedded('VERIFIED_ARTIFACT_EXTRACTION'), 'VERIFIED_ARTIFACT_EXTRACTION', 'exec'), {})

    def test_artifact_bytes_are_checked_before_safe_private_extraction(self):
        with tempfile.TemporaryDirectory(prefix='wa-zip-') as temporary:
            root = Path(temporary)
            self.extract(root, [('decoder/grib_ls', b'non-executable fixture', stat.S_IFREG | 0o755)])
            target = root / 'decoder/decoder/grib_ls'
            self.assertEqual(target.read_bytes(), b'non-executable fixture')
            self.assertEqual(stat.S_IMODE(target.stat().st_mode), 0o600)
        for members, mismatch in (
                ([('../outside', b'x', stat.S_IFREG | 0o600)], False),
                ([('/absolute', b'x', stat.S_IFREG | 0o600)], False),
                ([('x//y', b'x', stat.S_IFREG | 0o600)], False),
                ([('x\\y', b'x', stat.S_IFREG | 0o600)], False),
                ([('link', b'/etc/passwd', stat.S_IFLNK | 0o777)], False),
                ([('pipe', b'', stat.S_IFIFO | 0o600)], False),
                ([('same', b'1', stat.S_IFREG | 0o600), ('same', b'2', stat.S_IFREG | 0o600)], False),
                ([('okay', b'x', stat.S_IFREG | 0o600)], True)):
            with self.subTest(names=[name for name, _, _ in members], mismatch=mismatch), \
                    tempfile.TemporaryDirectory(prefix='wa-zip-') as temporary:
                root = Path(temporary)
                with self.assertRaises(AssertionError): self.extract(root, members, wrong_hash=mismatch)
                self.assertFalse((root / 'decoder').exists())

    def test_only_two_admitted_artifacts_download_by_exact_id(self):
        section = block('Retrieve only the admitted decoder and ABI artifacts')
        self.assertIn('for kind in decoder abi; do', section)
        self.assertLess(section.index('# END PUBLIC_ARTIFACT_METADATA'), section.index('/artifacts/$artifact_id/zip'))
        self.assertIn('timeout 300s gh api "repos/$repository/actions/artifacts/$artifact_id/zip"', section)
        self.assertNotIn('gh run download', section)
        self.assertNotIn('assets', section)
        self.assertNotIn('proof', section)
        self.assertNotIn('historical', section)

    def test_capture_uses_exact_five_paths_and_cannot_authorize_itself(self):
        section = block('Capture and verify exact v6 inputs without executing them')
        call = re.search(r'weather-client-bundle.py capture-v6\s+(.+?) >', section.replace('\\\n', ' ')).group(1)
        self.assertEqual(re.findall(r'"([^"]+)"', call), ['$weather', '$weather/build/hosted-client-runtime/node',
            '$WEATHER_INPUTS/decoder', '$WEATHER_INPUTS/abi', '$archive'])
        for item in ('verify-runtime "$archive" "$manifest"', 'runtime-version "$archive" "$manifest"',
                '.bundle_version == 6 and .runtime_executed == false', '.native_android_proven == false',
                '.joined_delivery_proven == false'):
            self.assertIn(item, section)
        self.assertNotIn('synthetic_ui_proven == true', SOURCE)
        self.assertNotIn('repository: VOLPAROSSA/volparossa-browser', SOURCE)

    def test_native_prepare_finishes_before_vm_publication_and_does_not_run_fixture(self):
        names = ['Check combined resources before acquiring toolchains',
            'Prepare exact native inputs without executing Android tools',
            'Capture and verify exact v6 inputs without executing them',
            'Grant only this disposable runner temporary KVM access',
            'Prepare offline Android APK before any guest publication',
            'Run actual Android-triggered protected delivery', 'Restore exact original hosted KVM ACL',
            'Require joined Android observations and completed VM cleanup']
        positions = [SOURCE.index('- name: ' + name) for name in names]
        self.assertEqual(positions, sorted(positions))
        section = block('Prepare offline Android APK before any guest publication')
        self.assertIn('prepare_hosted_android_ci.py" --prepare-protected-core', section)
        self.assertIn('weather-android-owner.py preflight --weather-root "$weather"', section)
        self.assertIn('--kvm-output "$WEATHER_OUTPUT"', section)
        self.assertEqual(SOURCE.count('sudo -n setfacl -m'), 1)
        self.assertIn('--weather-commit "$VOLPAROSSA_WEATHER_SOURCE_SHA"', section)
        self.assertNotIn('--run-protected-core', SOURCE)  # The owner controls this, never an independent workflow child.

    def test_kvm_grant_uses_only_guarded_existing_private_primary_group(self):
        section = block('Grant only this disposable runner temporary KVM access')
        self.assertIn('sudo -n setfacl -m "g:$group:rw" /dev/kvm', section)
        self.assertLess(section.index('getfacl --absolute-names'), section.index('# BEGIN KVM_PRIVATE_GROUP'))
        self.assertLess(section.index('# END KVM_PRIVATE_GROUP'), section.index('sudo -n setfacl -m'))
        for forbidden in ('usermod', 'chmod', 'u:$(id -u)', 'udevadm trigger', '/etc/udev', '--retry'):
            self.assertNotIn(forbidden, section)
        output = io.StringIO()
        with patch.object(runpy, 'run_path', return_value=dict(grant_primary_group=lambda: 23456)), redirect_stdout(output):
            exec(compile(embedded('KVM_PRIVATE_GROUP'), 'KVM_PRIVATE_GROUP', 'exec'), {})
        self.assertEqual(output.getvalue(), '23456\n')
        for error in (ValueError('PRIVATE_ID_23456'), OSError('PRIVATE_ACL'), KeyError('PRIVATE_NAME')):
            def fail(): raise error
            with patch.object(runpy, 'run_path', return_value=dict(grant_primary_group=fail)), \
                    self.assertRaises(SystemExit) as raised:
                exec(compile(embedded('KVM_PRIVATE_GROUP'), 'KVM_PRIVATE_GROUP', 'exec'), {})
            self.assertEqual(str(raised.exception), 'KVM scoped group grant unavailable')

    def test_rejected_group_or_preexisting_acl_never_reaches_setfacl(self):
        body = textwrap.dedent(block('Grant only this disposable runner temporary KVM access').split('run: |\n', 1)[1])
        with tempfile.TemporaryDirectory(prefix='wa-grant-') as temporary:
            root = Path(temporary)
            script = '''WEATHER_INPUTS=$1
RUNNER_ENVIRONMENT=github-hosted
getfacl() { printf 'inert original ACL\\n'; }
python3() { return 1; }
sudo() { printf 'unexpected grant\\n' > "$WEATHER_INPUTS/unexpected"; }
''' + body
            result = subprocess.run(['/bin/bash', '-c', script, 'inert-grant', str(root)], capture_output=True, timeout=5)
            self.assertEqual(result.returncode, 1, result.stderr)
            self.assertFalse((root / 'unexpected').exists())
            self.assertEqual((root / 'kvm.acl').read_text(), 'inert original ACL\n')

    def test_pending_kvm_udev_events_settle_bounded_before_restore_even_on_timeout(self):
        cleanup = block('Restore exact original hosted KVM ACL')
        fragment = 'settle_status=0\n' + textwrap.dedent(cleanup.split('settle_status=0\n', 1)[1].split('            python3 -B -', 1)[0])
        self.assertIn('timeout --kill-after=5s 20s sudo -n udevadm settle --timeout=15', fragment)
        self.assertLess(fragment.index('udevadm settle'), fragment.index('sudo -n setfacl --restore='))
        self.assertLess(fragment.index('sudo -n setfacl --restore='), fragment.index('test "$settle_status" -eq 0'))
        for status in (0, 1, 124):
            with self.subTest(status=status), tempfile.TemporaryDirectory(prefix='wa-udev-') as temporary:
                root = Path(temporary); (root / 'kvm.acl').write_text('original inert ACL\n')
                script = '''set -euo pipefail
WEATHER_INPUTS=$1
fixture_status=$2
timeout() { printf 'settle\\n' >> "$WEATHER_INPUTS/trace"; return "$fixture_status"; }
sudo() { printf 'restore\\n' >> "$WEATHER_INPUTS/trace"; }
getfacl() { printf 'original inert ACL\\n'; }
''' + fragment
                result = subprocess.run(['/bin/bash', '-c', script, 'inert-restore', str(root), str(status)],
                    capture_output=True, timeout=5)
                self.assertEqual(result.returncode, 0 if status == 0 else 1, result.stderr)
                self.assertEqual((root / 'trace').read_text().splitlines(), ['settle', 'restore'])
                self.assertEqual((root / 'kvm.acl').read_bytes(), (root / 'kvm-restored.acl').read_bytes())

    def test_vm_owner_keeps_hosted_policy_privileges_without_broad_sudo_wrapper(self):
        section = block('Run actual Android-triggered protected delivery')
        for item in ('--scenario content-provider', '--weather-android-source "$GITHUB_WORKSPACE/.cache/weather-android-source"',
                '--weather-client-bundle "$WEATHER_ARCHIVE"', '--weather-client-manifest-sha256 "$WEATHER_MANIFEST"',
                '--output "$WEATHER_OUTPUT" --expected-commit "$GITHUB_SHA"'):
            self.assertIn(item, section)
        for forbidden in ('setpriv', '--reset-env', '--no-new-privs', 'sudo', 'env -i', '|| true'):
            self.assertNotIn(forbidden, section)
        self.assertLess(section.index('# END FINAL_SOURCE_PREFLIGHT'), section.index('run-alpha-topology-vm.sh'))

    def test_final_source_preflight_rejects_dirty_or_different_checkout(self):
        source = embedded('FINAL_SOURCE_PREFLIGHT')
        for expected, outputs in ((True, [b'a' * 40 + b'\n', b'']), (False, [b'b' * 40 + b'\n']),
                (False, [b'a' * 40 + b'\n', b'?? pending-file\n'])):
            with self.subTest(outputs=outputs), patch.dict(os.environ, GITHUB_SHA='a' * 40), \
                    patch('subprocess.check_output', side_effect=outputs), \
                    patch.object(Path, 'read_text', return_value='MemAvailable: 10485760 kB\n'):
                if expected: exec(compile(source, 'FINAL_SOURCE_PREFLIGHT', 'exec'), {})
                else:
                    with self.assertRaises(AssertionError): exec(compile(source, 'FINAL_SOURCE_PREFLIGHT', 'exec'), {})

    def acl(self, root):
        with patch.object(sys, 'argv', ['acl', str(root)]), patch.dict(os.environ,
                GITHUB_SHA='a' * 40, VOLPAROSSA_WEATHER_SOURCE_SHA=WEATHER, GITHUB_RUN_ID='123', GITHUB_RUN_ATTEMPT='1'):
            exec(compile(embedded('ACL_CLEANUP'), 'ACL_CLEANUP', 'exec'), {})

    def test_acl_cleanup_contains_only_equal_original_and_restored_hashes(self):
        with tempfile.TemporaryDirectory(prefix='wa-acl-') as temporary:
            root = Path(temporary); raw = b'# file: /dev/kvm\nuser::rw-\ngroup::rw-\nother::---\n'
            for name in ('kvm.acl', 'kvm-restored.acl'):
                path = root / name; path.write_bytes(raw); path.chmod(0o600)
            self.acl(root)
            result = json.loads((root / 'kvm-cleanup.json').read_text())
            self.assertEqual(result, dict(schema=6, kind='weather-android-kvm-cleanup',
                identity=dict(core_commit='a' * 40, weather_commit=WEATHER, run_id='123', run_attempt='1'),
                baseline_sha256=hashlib.sha256(raw).hexdigest(), restored_sha256=hashlib.sha256(raw).hexdigest(),
                baseline_bytes=len(raw), restored_bytes=len(raw), original_kvm_acl_restored=True))
            self.assertNotIn('/dev/kvm', json.dumps(result))
            with self.assertRaises(FileExistsError): self.acl(root)

    def test_acl_cleanup_refuses_mismatch_link_bad_mode_or_empty_input(self):
        for failure in ('mismatch', 'symlink', 'hardlink', 'mode', 'empty', 'oversized'):
            with self.subTest(failure=failure), tempfile.TemporaryDirectory(prefix='wa-acl-') as temporary:
                root = Path(temporary); baseline, restored = root / 'kvm.acl', root / 'kvm-restored.acl'
                baseline.write_bytes(b'owned original ACL\n'); restored.write_bytes(b'owned original ACL\n')
                baseline.chmod(0o600); restored.chmod(0o600)
                if failure == 'mismatch': restored.write_bytes(b'different\n')
                elif failure == 'symlink': restored.unlink(); restored.symlink_to(baseline)
                elif failure == 'hardlink': restored.unlink(); restored.hardlink_to(baseline)
                elif failure == 'mode': restored.chmod(0o644)
                elif failure == 'empty': restored.write_bytes(b'')
                elif failure == 'oversized': restored.write_bytes(b'x' * 8193)
                with self.assertRaises((AssertionError, OSError)): self.acl(root)
                self.assertFalse((root / 'kvm-cleanup.json').exists())

    def test_final_acceptance_requires_restoration_and_never_writes_its_own_success_stamp(self):
        cleanup = block('Restore exact original hosted KVM ACL')
        self.assertIn("if: always() && env.WEATHER_INPUTS != ''", cleanup)
        self.assertIn('sudo -n setfacl --restore="$WEATHER_INPUTS/kvm.acl"', cleanup)
        self.assertIn('getfacl --absolute-names /dev/kvm > "$WEATHER_INPUTS/kvm-restored.acl"', cleanup)
        self.assertIn('cmp "$WEATHER_INPUTS/kvm.acl" "$WEATHER_INPUTS/kvm-restored.acl"', cleanup)
        self.assertLess(cleanup.index('cmp '), cleanup.index('# BEGIN ACL_CLEANUP'))
        section = block('Require joined Android observations and completed VM cleanup')
        self.assertIn('content-provider-smoke.py report', section)
        self.assertIn('weather-android-owner.py accept --output "$WEATHER_OUTPUT"', section)
        self.assertIn('--manifest "$WEATHER_MANIFEST" --kvm-cleanup "$WEATHER_INPUTS/kvm-cleanup.json"', section)
        self.assertNotIn('if:', section)  # Default success() requires VM return0 and successful ACL restoration.
        self.assertNotIn('> "$WEATHER_OUTPUT/weather-android-hosted-acceptance.json"', section)

    def test_artifact_upload_is_closed_not_a_directory_or_glob(self):
        section = block('Upload only closed evidence and pinned-input provenance')
        self.assertIn('          include-hidden-files: true\n', section)
        self.assertEqual(SOURCE.count('include-hidden-files:'), 1)
        paths = section.split('          path: |\n', 1)[1].splitlines()
        self.assertEqual([path.strip() for path in paths if path.strip()], [
            '${{ env.WEATHER_OUTPUT }}/weather-android-delivery-evidence.json',
            '${{ env.WEATHER_OUTPUT }}/weather-android-owner-join.json',
            '${{ env.WEATHER_OUTPUT }}/weather-android-owner-failure.json',
            '${{ env.WEATHER_OUTPUT }}/weather-android-kvm-observation.json',
            '${{ env.WEATHER_OUTPUT }}/weather-android-inner-diagnostic.json',
            '${{ env.WEATHER_OUTPUT }}/weather-android-driver-diagnostic.json',
            '${{ env.WEATHER_OUTPUT }}/weather-android-vm-cleanup.json',
            '${{ env.WEATHER_OUTPUT }}/weather-android-hosted-acceptance.json',
            '${{ env.WEATHER_INPUTS }}/kvm-cleanup.json',
            *['${{ env.WEATHER_INPUTS }}/provenance/' + name + '.json' for name in (
                'decoder-run', 'decoder-artifact', 'abi-run', 'abi-artifact', 'capture',
                'verify-runtime', 'runtime-version', 'native-preparation')]])
        for forbidden in ('*', '.log', '.acl', '.zip', '.tar', 'private', 'sdk', 'apk', 'proof/', 'run_directory', 'config'):
            self.assertNotIn(forbidden, '\n'.join(paths).lower())

    def test_inner_diagnostic_is_optional_host_output_not_input_or_acceptance(self):
        parser_test = 'python3 -B tests/integration/test-weather-android-inner-diagnostic.py'
        self.assertIn(parser_test, SOURCE)
        self.assertIn(parser_test, (ROOT / '.github/workflows/quality.yml').read_text())
        output = '${{ env.WEATHER_OUTPUT }}/weather-android-inner-diagnostic.json'
        self.assertEqual(SOURCE.count(output), 1)
        self.assertNotIn('inner-diagnostic', block('Require joined Android observations and completed VM cleanup'))
        for raw in ('emulator-diagnostic.json', 'guest-network-diagnostic.json'):
            self.assertNotIn(raw, block('Upload only closed evidence and pinned-input provenance'))

    def test_early_or_late_driver_projection_is_bounded_local_only_after_cleanup(self):
        name = 'Project closed early or late guest-driver failure observations'
        section = block(name)
        self.assertIn("if: always() && env.WEATHER_OUTPUT != ''", section)
        self.assertIn('timeout --signal=TERM --kill-after=1s 10s python3 -B '
            'tests/integration/weather-android-driver-diagnostic.py export', section)
        self.assertIn('--output "$WEATHER_OUTPUT" --core-commit "$GITHUB_SHA"', section)
        self.assertIn('--weather-commit "$VOLPAROSSA_WEATHER_SOURCE_SHA"', section)
        self.assertLess(SOURCE.index('- name: Restore exact original hosted KVM ACL'), SOURCE.index('- name: ' + name))
        self.assertLess(SOURCE.index('- name: ' + name),
            SOURCE.index('- name: Require joined Android observations and completed VM cleanup'))
        self.assertLess(SOURCE.index('- name: ' + name),
            SOURCE.index('- name: Upload only closed evidence and pinned-input provenance'))
        for forbidden in ('ssh ', 'scp ', 'sudo ', 'curl ', 'continue-on-error', '|| true'):
            self.assertNotIn(forbidden, section)
        parser_test = 'python3 -B tests/integration/test-weather-android-driver-diagnostic.py'
        self.assertIn(parser_test, SOURCE)
        self.assertIn(parser_test, (ROOT / '.github/workflows/quality.yml').read_text())
        output = '${{ env.WEATHER_OUTPUT }}/weather-android-driver-diagnostic.json'
        self.assertEqual(SOURCE.count(output), 1)
        self.assertNotIn('driver-diagnostic', block('Require joined Android observations and completed VM cleanup'))
        for raw in ('vm-incomplete.json', 'guest-phase.txt', 'current-phase', 'content-provider-smoke.json', 'runner.stderr'):
            self.assertNotIn(raw, block('Upload only closed evidence and pinned-input provenance'))

    def test_embedded_python_and_every_run_block_are_syntactically_valid(self):
        for name in ('COMBINED_RESOURCES', 'PUBLIC_ARTIFACT_METADATA', 'VERIFIED_ARTIFACT_EXTRACTION',
                'FINAL_SOURCE_PREFLIGHT', 'ACL_CLEANUP'):
            compile(embedded(name), name, 'exec')
        scripts = re.findall(r'^        run: \|\n((?:(?:^          .*|^)$\n?)*)', SOURCE, re.M)
        self.assertGreaterEqual(len(scripts), 12)
        for index, script in enumerate(scripts):
            with self.subTest(index=index):
                result = subprocess.run(['/bin/bash', '-n'], input=textwrap.dedent(script), text=True,
                    capture_output=True, timeout=5)
                self.assertEqual(result.returncode, 0, result.stderr)


if __name__ == '__main__': unittest.main()
