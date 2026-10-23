#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-only
"""Synthetic inert ZIP/API tests only; these archives are never demo acceptance."""
import hashlib
import copy
import importlib.util
import io
import json
import os
import signal
from pathlib import Path
import stat
import tempfile
import sys
import unittest
from unittest.mock import patch
import zipfile

ROOT = Path(__file__).resolve().parents[2]
spec = importlib.util.spec_from_file_location('demo_review', ROOT / 'scripts/weather-demo-0-review.py')
R = importlib.util.module_from_spec(spec)
spec.loader.exec_module(R)
CORE = 'a' * 40
REVIEW_CORE = 'b' * 40
IDENTITY = dict(core_commit=CORE, weather_commit=R.WEATHER, run_id='123', run_attempt='2')
ENV = dict(GITHUB_ACTIONS='true', RUNNER_ENVIRONMENT='github-hosted', RUNNER_OS='Linux',
           GITHUB_REPOSITORY=R.REPOSITORY, GITHUB_SHA=REVIEW_CORE, GITHUB_RUN_ID='456', GITHUB_RUN_ATTEMPT='1')


def encoded(value):
    return (json.dumps(value, sort_keys=True) + '\n').encode()


def record(raw):
    return dict(bytes=len(raw), sha256=hashlib.sha256(raw).hexdigest())


class Review(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix='inert-demo-review-')
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name).resolve()

    def metadata(self):
        run = dict(id=123, run_attempt=2, head_sha=CORE, status='completed', conclusion='success',
                   repository=dict(full_name=R.REPOSITORY), head_repository=dict(full_name=R.REPOSITORY),
                   run_started_at='2026-10-23T12:00:00Z', updated_at='2026-10-23T13:00:00Z')
        artifact = dict(id=7, name='weather-demo-review-' + CORE, expired=False, size_in_bytes=42,
                        digest='sha256:' + 'c' * 64, workflow_run=dict(id=123, head_sha=CORE),
                        created_at='2026-10-23T12:58:00Z', updated_at='2026-10-23T12:59:00Z')
        listing = dict(total_count=1, artifacts=[artifact])
        return run, artifact, listing

    def fixture(self, *, alter=None, extra=None):
        # Deliberately synthetic bytes; original verifier is mocked, never admitted as real media.
        acceptance = dict(identity=IDENTITY, passed=True, joined_core_acceptance=True,
                          vm_cleanup_pending=False, production_authority=False)
        raw = b'not a video; synthetic unit fixture only'
        video = dict(codec='h264', width=720, height=1280, duration_seconds=3.0, has_audio=False)
        media = dict(identity=IDENTITY, joined_core_acceptance=True, production_authority=False,
                     files={'screen.mp4': record(raw)}, video=video,
                     acceptance_sha256=record(encoded(acceptance))['sha256'])
        files = {name: encoded(acceptance if name == 'weather-android-hosted-acceptance.json'
                               else {'synthetic': 'not runtime evidence'}) for name in R.REPORTS}
        files.update({'demo-media/recording.json': encoded(media), 'demo-media/screen.mp4': raw,
                      'demo-media/screen-001.png': b'synthetic not actual PNG', 'README.md': b'document'})
        presentation = dict(schema=1, kind='weather-demo-unpublished-presentation', identity=IDENTITY,
            actual_app_pixels=True, external_core=True, physical_device=False, production_authority=False,
            publication_authorized=False, includes_installable_binaries=False, visual_review_required=True,
            files={name: record(data) for name, data in files.items()},
            acceptance_sha256=media['acceptance_sha256'], recording_sha256=record(raw)['sha256'],
            # Actual producer video_info() selects these four fields; has_audio
            # belongs to the separate original media verifier's contract.
            original_video={key: video[key] for key in ('codec', 'width', 'height', 'duration_seconds')})
        if alter:
            alter(presentation, files)
        archive_path = self.root / 'review.zip'
        with zipfile.ZipFile(archive_path, 'w', compression=zipfile.ZIP_DEFLATED) as archive:
            for name, data in files.items():
                archive.writestr(R.PREFIX + name, data)
            archive.writestr(R.PREFIX + 'presentation.json', encoded(presentation))
            archive.writestr(R.PREFIX + 'SHA256SUMS', b'not relied upon')
            archive.writestr('weather-demo-sources/core-source.tar.gz', b'not extracted')
            if extra:
                extra(archive)
        return archive_path, presentation, media

    def test_preview_readonly_and_strict_arguments(self):
        with patch.object(R, 'ROOT', self.root), patch.object(R, 'api') as api:
            result = R.prepare('123', '2', CORE, self.root / 'output')
            self.assertFalse(result['executed'])
            self.assertFalse((self.root / 'output').exists())
            api.assert_not_called()
            for run_id, attempt, sha in [('0', '1', CORE), ('123', '-1', CORE),
                                          ('123/zip', '2', CORE), ('123', '2', 'A' * 40)]:
                with self.subTest(values=(run_id, attempt, sha)), self.assertRaises(ValueError):
                    R.prepare(run_id, attempt, sha, self.root / 'output')
            for output in [self.root, self.root.parent / 'outside', self.root / '.git/out',
                           self.root / 'missing/out', Path('relative')]:
                with self.subTest(output=output), self.assertRaises(ValueError):
                    R.prepare('123', '2', CORE, output)

    def test_execute_rejects_local_host_before_network_or_write(self):
        with patch.object(R, 'ROOT', self.root), patch.dict(os.environ, {}, clear=True), \
                patch.object(R, 'api') as api:
            with self.assertRaises(ValueError):
                R.prepare('123', '2', CORE, self.root / 'output', execute=True)
            self.assertFalse((self.root / 'output').exists())
            api.assert_not_called()

    def test_run_and_artifact_exact_latest_attempt(self):
        run, artifact, listing = self.metadata()
        with patch.object(R, 'api', side_effect=[run, run, listing]) as api:
            selected = R.selected_artifact('123', '2', CORE)
            self.assertEqual(selected['id'], 7)
            self.assertEqual([call.args[0] for call in api.call_args_list], [
                'repos/VOLPAROSSA/volparossa/actions/runs/123',
                'repos/VOLPAROSSA/volparossa/actions/runs/123/attempts/2',
                'repos/VOLPAROSSA/volparossa/actions/runs/123/artifacts?per_page=100'])
        for key, value in [('conclusion', 'failure'), ('status', 'in_progress'),
                           ('head_sha', REVIEW_CORE), ('run_attempt', 3)]:
            invalid = {**run, key: value}
            with self.subTest(key=key), patch.object(R, 'api', side_effect=[invalid, run]), \
                    self.assertRaises(ValueError):
                R.selected_artifact('123', '2', CORE)
        invalids = [dict(artifact, expired=True), dict(artifact, digest=None),
                    dict(artifact, size_in_bytes=R.MAX_ZIP + 1),
                    dict(artifact, created_at='2026-10-23T11:59:59Z'),
                    dict(artifact, workflow_run=dict(id=123, head_sha=REVIEW_CORE))]
        for invalid in invalids:
            with patch.object(R, 'api', side_effect=[run, run, dict(total_count=1, artifacts=[invalid])]), \
                    self.assertRaises(ValueError):
                R.selected_artifact('123', '2', CORE)
        with patch.object(R, 'api', side_effect=[run, run, dict(total_count=101, artifacts=[artifact])]), \
                self.assertRaises(ValueError):
            R.selected_artifact('123', '2', CORE)

    def test_download_exact_endpoint_size_and_digest(self):
        payload = b'synthetic ZIP boundary payload'
        artifact = dict(id=7, size_in_bytes=len(payload), digest='sha256:' + record(payload)['sha256'])
        def write(args, **kwargs):
            self.assertEqual(args, ['/usr/bin/gh', 'api', '--method', 'GET',
                'repos/VOLPAROSSA/volparossa/actions/artifacts/7/zip'])
            kwargs['destination'].write_bytes(payload)
        with patch.object(R, 'tool', side_effect=str), patch.object(R, 'command', side_effect=write):
            R.download(artifact, self.root / 'valid.zip')
            with self.assertRaises(ValueError):
                R.download(dict(artifact, digest='sha256:' + '0' * 64), self.root / 'bad.zip')
            with self.assertRaises(ValueError):
                R.download(dict(artifact, size_in_bytes=1), self.root / 'wrong-size.zip')

    def test_subset_extraction_and_original_identity_do_not_fake_environment(self):
        archive, presentation, media = self.fixture()
        destination = self.root / 'evidence'
        def verify(path):
            self.assertEqual(os.environ['GITHUB_SHA'], REVIEW_CORE)
            self.assertEqual(os.environ['GITHUB_RUN_ID'], '456')
            self.assertNotIn('GH_TOKEN', os.environ)
            self.assertEqual(path, destination)
            return media
        with patch.dict(os.environ, {**ENV, 'GH_TOKEN': 'private synthetic token'}, clear=True), \
                patch.object(R.runpy, 'run_path', return_value={'verify': verify}):
            result = R.evidence(archive, destination, IDENTITY)
            self.assertEqual(os.environ['GH_TOKEN'], 'private synthetic token')
        self.assertEqual(result[0], presentation)
        self.assertFalse((destination / 'README.md').exists())
        self.assertFalse((destination / 'core-source.tar.gz').exists())
        self.assertEqual(destination.stat().st_mode & 0o777, 0o700)
        self.assertEqual((destination / 'demo-media/screen.mp4').stat().st_mode & 0o777, 0o600)
        self.assertEqual({p.name for p in (destination / 'demo-media').iterdir()},
                         {'screen.mp4', 'screen-001.png', 'recording.json'})

    def test_hash_mismatch_unselected_member_is_also_rejected(self):
        def alter(_, files):
            files['README.md'] = b'tampered document outside extracted subset'
        archive, _, _ = self.fixture(alter=alter)
        with patch.object(R.runpy, 'run_path') as verifier, self.assertRaisesRegex(ValueError, 'hash mismatch'):
            R.evidence(archive, self.root / 'evidence', IDENTITY)
        verifier.assert_not_called()

    def test_identity_and_original_verifier_failure_stop_render(self):
        archive, _, media = self.fixture()
        with self.assertRaisesRegex(ValueError, 'identity'):
            R.evidence(archive, self.root / 'wrong', dict(IDENTITY, weather_commit='c' * 40))
        def rejected(_):
            raise ValueError('synthetic original validator rejection')
        with patch.object(R.runpy, 'run_path', return_value={'verify': rejected}), \
                self.assertRaisesRegex(ValueError, 'original validator'):
            R.evidence(archive, self.root / 'evidence', IDENTITY)

    def test_zip_rejects_traversal_duplicates_symlinks_and_unknown_roots(self):
        for name in ['../escape', '/absolute', 'weather-demo-presentation/../escape',
                     'weather-demo-presentation//file', 'weather-demo-presentation/./file',
                     'weather-demo-presentation/back\\slash', 'other/file']:
            with self.subTest(name=name), self.assertRaises(ValueError):
                R.canonical_name(name)
        for kind in ['symlink', 'duplicate', 'oversize']:
            path = self.root / (kind + '.zip')
            with zipfile.ZipFile(path, 'w') as archive:
                if kind == 'symlink':
                    info = zipfile.ZipInfo(R.PREFIX + 'link')
                    info.create_system = 3
                    info.external_attr = (stat.S_IFLNK | 0o777) << 16
                    archive.writestr(info, '/tmp/outside')
                else:
                    archive.writestr(R.PREFIX + 'file', b'fixture')
                    if kind == 'duplicate':
                        # The canonical-key collision also covers file-vs-directory duplicates.
                        archive.writestr(R.PREFIX + 'file/', b'')
            with zipfile.ZipFile(path) as archive:
                if kind == 'oversize':
                    archive.infolist()[0].file_size = R.MAX_ZIP + 1
                with self.subTest(kind=kind), self.assertRaises(ValueError):
                    R.zip_entries(archive)

    def test_cleanup_failure_record_retains_both_source_identities(self):
        output = self.root / 'output'
        def failed_download(_, path):
            path.write_bytes(b'partial inert download')
            R.STATE['stage'] = 'artifact-download'
            raise ValueError('private synthetic exception with path and credentials')
        with patch.object(R, 'ROOT', self.root), patch.dict(os.environ, ENV, clear=True), \
                patch.object(R.os, 'getuid', return_value=1000), patch.object(R.os, 'geteuid', return_value=1000), \
                patch.object(R, 'selected_artifact', return_value={}), \
                patch.object(R, 'download', side_effect=failed_download), self.assertRaises(ValueError):
            R.prepare('123', '2', CORE, output, execute=True)
        self.assertEqual([p.name for p in output.iterdir()], ['review-failure.json'])
        failure = json.loads((output / 'review-failure.json').read_text())
        self.assertEqual(failure['identity']['core_commit'], CORE)
        self.assertEqual(failure['review_execution']['core_commit'], REVIEW_CORE)
        self.assertTrue(failure['partial_output_removed'])
        self.assertEqual(failure['stage'], 'artifact-download')
        self.assertFalse(failure['visual_acceptance_claimed'])
        self.assertEqual(failure['category'], 'value')
        self.assertNotIn('private synthetic', (output / 'review-failure.json').read_text())
        self.assertNotIn('reason', failure)

    def test_success_separates_packaging_identity_and_no_runtime_claim(self):
        output = self.root / 'output'
        original_archive, presentation, media = self.fixture()
        def downloaded(_, path):
            path.write_bytes(original_archive.read_bytes())
        def render(_, root, __):
            (root / 'contact-00.png').write_bytes(b'synthetic renderer stub, never real pixels')
            return {'sampled_frames': 1}
        with patch.object(R, 'ROOT', self.root), patch.dict(os.environ, ENV, clear=True), \
                patch.object(R.os, 'getuid', return_value=1000), patch.object(R.os, 'geteuid', return_value=1000), \
                patch.object(R, 'selected_artifact', return_value={'id': 7}), \
                patch.object(R, 'download', side_effect=downloaded), \
                patch.object(R, 'evidence', return_value=(presentation, media, 'c' * 64)), \
                patch.object(R, 'contact_sheets', side_effect=render):
            result = R.prepare('123', '2', CORE, output, execute=True)
        self.assertEqual(result['identity'], IDENTITY)
        self.assertEqual(result['review_execution']['core_commit'], REVIEW_CORE)
        self.assertFalse(result['new_runtime_executed'])
        self.assertNotIn('revised_presentation', result)
        self.assertFalse(result['visual_acceptance_claimed'])
        self.assertFalse((output / 'review.zip').exists())
        self.assertTrue((output / 'review.json').exists())

    def held_fixture(self):
        original = self.root / 'original'
        (original / 'demo-media').mkdir(parents=True)
        raw = b'inert original clip; not runtime media'
        png = (b'\x89PNG\r\n\x1a\n' + b'\0\0\0\rIHDR' +
               (1080).to_bytes(4, 'big') + (1920).to_bytes(4, 'big') + b'synthetic fixture')
        (original / 'demo-media/screen.mp4').write_bytes(raw)
        (original / 'demo-media/screen-003.png').write_bytes(png)
        acceptance = dict(identity=IDENTITY, passed=True,
            observations=dict(products=dict(weather=dict(cold_peer_bytes=12), air_quality=dict(cold_peer_bytes=34))))
        (original / 'weather-android-hosted-acceptance.json').write_bytes(encoded(acceptance))
        media = dict(identity=IDENTITY, acceptance_sha256=record(encoded(acceptance))['sha256'],
            files={'screen.mp4': record(raw), 'screen-003.png': record(png)},
            video=dict(codec='h264', width=720, height=1280, duration_seconds=75.0, has_audio=False))
        output = self.root / 'rendered'
        output.mkdir()
        return original, output, media

    def test_optional_hold_rejects_paths_and_only_accepts_explicit_basename(self):
        with patch.object(R, 'ROOT', self.root), patch.object(R, 'api') as api:
            for name in ['../screen-003.png', '/screen-003.png', 'screen-3.png', 'samples/frame-003.png',
                         'screen-003.png:movie', 'screen-003.png\n']:
                with self.subTest(name=name), self.assertRaises(ValueError):
                    R.prepare('123', '2', CORE, self.root / 'out', hold_image=name)
            preview = R.prepare('123', '2', CORE, self.root / 'out', hold_image='screen-003.png')
            self.assertEqual(preview['held_image_requested'], 'screen-003.png')
            self.assertFalse(preview['executed'])
            api.assert_not_called()

    def test_selected_genuine_image_hash_identity_and_render_contract(self):
        original, output, media = self.held_fixture()
        def lines(identity, products):
            self.assertEqual(identity, IDENTITY)
            self.assertEqual(products['weather']['cold_peer_bytes'], 12)
            return [('completed run', 20, 'ffffff')]
        def render(raw, stage, duration, raw_info, panel, *, hold_image):
            self.assertEqual(raw, original / 'demo-media/screen.mp4')
            self.assertEqual(hold_image, original / 'demo-media/screen-003.png')
            self.assertEqual(raw_info['duration_seconds'], 75.0)
            self.assertEqual(duration, 120)
            self.assertEqual(os.environ['GITHUB_SHA'], REVIEW_CORE)
            (stage / 'weather-demo-0.mp4').write_bytes(b'synthetic renderer output')
            return stage / 'weather-demo-0.mp4', dict(duration_seconds=120)
        package = dict(presentation_lines=lines, render_video=render,
                       captions=lambda *args, **kwargs: ('held captions', 'held transcript'))
        with patch.dict(os.environ, ENV, clear=True), patch.object(R, 'tool', side_effect=str), \
                patch.object(R.runpy, 'run_path', return_value=package):
            result = R.render_held_image(original, output, media, 'screen-003.png')
        self.assertEqual(result['identity'], IDENTITY)
        self.assertEqual(result['held_image'], dict(file='screen-003.png', **media['files']['screen-003.png']))
        self.assertTrue(result['edits']['full_original_clip'])
        self.assertFalse(result['edits']['raw_clip_trimmed'])
        self.assertEqual(result['edits']['held_frame_after_seconds'], 75)
        self.assertTrue(result['visual_review_required'])
        self.assertFalse(result['publication_authorized'])
        self.assertEqual((output / 'transcript.txt').read_text(), 'held transcript')

    def test_fractional_raw_duration_has_a_full_held_second_or_rejects_bound(self):
        original, output, media = self.held_fixture()
        calls = []
        def render(raw, stage, duration, raw_info, panel, *, hold_image):
            calls.append((duration, raw_info['duration_seconds']))
            (stage / 'weather-demo-0.mp4').write_bytes(b'synthetic render output')
            return stage / 'weather-demo-0.mp4', dict(duration_seconds=duration)
        package = dict(presentation_lines=lambda *_: [], render_video=render,
                       captions=lambda *args, **kwargs: ('captions', 'transcript'))
        with patch.object(R, 'tool', side_effect=str), patch.object(R.runpy, 'run_path', return_value=package):
            media['video']['duration_seconds'] = 119.999
            result = R.render_held_image(original, output, media, 'screen-003.png')
            self.assertEqual(calls, [(121, 119.999)])
            self.assertGreaterEqual(result['video']['duration_seconds'] - 119.999, 1)
            self.assertEqual(result['edits']['held_frame_after_seconds'], 119.999)
            self.assertTrue(result['edits']['full_original_clip'])
            media['video']['duration_seconds'] = 179.999
            with self.assertRaisesRegex(ValueError, 'bounded presentation duration'):
                R.render_held_image(original, output, media, 'screen-003.png')
            self.assertEqual(len(calls), 1)

    def test_held_selection_rejects_missing_hash_dimension_or_runtime_binding(self):
        original, output, media = self.held_fixture()
        with patch.object(R.runpy, 'run_path') as renderer:
            with self.assertRaises(ValueError):
                R.render_held_image(original, output, media, 'screen-004.png')
            media['files']['screen-003.png']['sha256'] = '0' * 64
            with self.assertRaisesRegex(ValueError, 'hash mismatch'):
                R.render_held_image(original, output, media, 'screen-003.png')
            image = original / 'demo-media/screen-003.png'
            image.write_bytes(b'wrong dimensions')
            media['files']['screen-003.png'] = record(image.read_bytes())
            with self.assertRaisesRegex(ValueError, 'dimensions'):
                R.render_held_image(original, output, media, 'screen-003.png')
            renderer.assert_not_called()

    def test_held_renderer_rejects_changed_runtime_identity_before_native_work(self):
        original, output, media = self.held_fixture()
        acceptance_path = original / 'weather-android-hosted-acceptance.json'
        acceptance = json.loads(acceptance_path.read_bytes())
        acceptance['identity'] = dict(IDENTITY, core_commit=REVIEW_CORE)
        acceptance_path.write_bytes(encoded(acceptance))
        media['acceptance_sha256'] = record(encoded(acceptance))['sha256']
        with patch.object(R.runpy, 'run_path') as renderer, patch.object(R, 'tool') as tool:
            with self.assertRaisesRegex(ValueError, 'acceptance binding'):
                R.render_held_image(original, output, media, 'screen-003.png')
            renderer.assert_not_called()
            tool.assert_not_called()

    def test_optional_renderer_is_only_called_after_original_acceptance(self):
        output = self.root / 'output'
        original_archive, presentation, media = self.fixture()
        order = []
        def accepted(*_):
            order.append('accepted')
            return presentation, media, 'c' * 64
        def revised(original, stage, selected_media, basename):
            self.assertEqual(order, ['accepted'])
            self.assertEqual(original, output / 'original')
            self.assertEqual(selected_media, media)
            self.assertEqual(basename, 'screen-003.png')
            return dict(identity=IDENTITY, held_image=dict(file=basename), visual_review_required=True)
        with patch.object(R, 'ROOT', self.root), patch.dict(os.environ, ENV, clear=True), \
                patch.object(R.os, 'getuid', return_value=1000), patch.object(R.os, 'geteuid', return_value=1000), \
                patch.object(R, 'selected_artifact', return_value={'id': 7}), \
                patch.object(R, 'download', side_effect=lambda _, path: path.write_bytes(original_archive.read_bytes())), \
                patch.object(R, 'evidence', side_effect=accepted), \
                patch.object(R, 'contact_sheets', return_value={}), \
                patch.object(R, 'render_held_image', side_effect=revised):
            result = R.prepare('123', '2', CORE, output, execute=True, hold_image='screen-003.png')
        self.assertEqual(result['review_execution']['core_commit'], REVIEW_CORE)
        self.assertEqual(result['revised_presentation']['identity']['core_commit'], CORE)
        self.assertFalse(result['visual_acceptance_claimed'])

    def test_sampling_commands_use_only_fixed_tools_and_original_video(self):
        evidence = self.root / 'evidence'
        evidence.mkdir()
        output = self.root / 'render'
        output.mkdir()
        font = self.root / 'font-data'
        font.write_bytes(b'inert font data')
        calls = []
        def render(args, **kwargs):
            calls.append(args)
            if '-start_number' in args and str(args[-1]).endswith('frame-%03d.png'):
                for i in range(3):
                    (output / 'samples' / f'frame-{i:03d}.png').write_bytes(b'synthetic stub PNG')
            else:
                Path(args[-1]).write_bytes(b'synthetic sheet stub')
        with patch.object(R, 'tool', side_effect=str), patch.object(R, 'command', side_effect=render), \
                patch.object(R, 'FONT', font):
            result = R.contact_sheets(evidence, output, dict(video=dict(duration_seconds=3.0)))
        self.assertEqual(result['poster_source'], 'samples/frame-001.png')
        self.assertTrue(all(args[0] == '/usr/bin/ffmpeg' for args in calls))
        self.assertIn(str(evidence / 'demo-media/screen.mp4'), calls[0])
        self.assertIn('file,pipe', calls[0])
        self.assertFalse(result['synthesized_app_pixels'])
        self.assertEqual((output / 'poster.png').read_bytes(), (output / 'samples/frame-001.png').read_bytes())

    def test_child_pipe_limits_timeout_and_failure_diagnostics(self):
        output = R.command([sys.executable, '-c', "print('inert child')"], maximum=100)
        self.assertEqual(output, b'inert child\n')
        with self.assertRaisesRegex(ValueError, 'output limit'):
            R.command([sys.executable, '-c', "print('x' * 1000)"], maximum=100)
        with self.assertRaisesRegex(ValueError, 'timeout'):
            R.command([sys.executable, '-c', 'import time; time.sleep(2)'], seconds=0.01)
        with self.assertRaises(R.ChildFailure) as failure:
            R.command([sys.executable, '-c', "import sys; sys.stderr.write('synthetic stderr'); sys.exit(3)"])
        self.assertEqual(failure.exception.status, 3)
        self.assertFalse(hasattr(failure.exception, 'diagnostics'))
        self.assertNotIn('synthetic stderr', str(failure.exception))

    def test_optional_zero_exit_stderr_rejection_does_not_export_raw_diagnostics(self):
        args = [sys.executable, '-c', "import sys; print('inert output'); sys.stderr.write('synthetic private diagnostic')"]
        self.assertEqual(R.command(args), b'inert output\n')
        with self.assertRaisesRegex(ValueError, 'child emitted error diagnostics') as rejected:
            R.command(args, reject_stderr=True)
        self.assertNotIn('synthetic private diagnostic', str(rejected.exception))

    def test_non_api_children_do_not_receive_github_token(self):
        with patch.dict(os.environ, {'GH_TOKEN': 'private synthetic token'}):
            result = R.command([sys.executable, '-c', "import os; print(os.getenv('GH_TOKEN', 'absent'))"])
        self.assertEqual(result, b'absent\n')

    def test_cli_sigterm_becomes_cleanup_exception_and_restores_handler(self):
        previous = signal.getsignal(signal.SIGTERM)
        def interrupted_prepare(*_):
            os.kill(os.getpid(), signal.SIGTERM)
            self.fail('SIGTERM did not interrupt execution')
        argv = ['--run-id', '123', '--attempt', '2', '--core-revision', CORE,
                '--output', str(self.root / 'interrupted'), '--execute']
        with patch.object(R, 'prepare', side_effect=interrupted_prepare), patch.object(sys, 'stderr', io.StringIO()):
            self.assertEqual(R.main(argv), 1)
        self.assertEqual(signal.getsignal(signal.SIGTERM), previous)

    def quarantine_fixture(self, *, change_raw=None, change_capture=None, corrupt=False):
        png = (b'\x89PNG\r\n\x1a\n' + b'\0\0\0\rIHDR' +
               (1080).to_bytes(4, 'big') + (1920).to_bytes(4, 'big') + b'synthetic PNG fixture')
        video_bytes = b'\0\0\0\x18ftypisom' + b'inert fixture; never decoded'
        report_sha = 'e' * 64
        acceptance = dict(identity=IDENTITY, passed=True, joined_core_acceptance=True,
                          vm_cleanup_pending=False, production_authority=False)
        raw = dict(schema=1, kind='weather-demo-android-recording', started_unix_ms=1000000,
            completed_unix_ms=1069397, elapsed_ms=69397, source='android-screenrecord-and-screencap',
            files={'screen.mp4': record(video_bytes), 'screen-001.png': record(png)},
            screenshots=[dict(file='screen-001.png', started_elapsed_ms=218,
                              completed_elapsed_ms=2578, stage='unclassified')],
            recorder_joined=True, guest_file_removed=True, stage_labels_verified=False, ui_values_verified=False,
            joined_core_acceptance=False, production_authority=False)
        window = dict(schema=1, started_unix_ms=1000166, completed_unix_ms=1067695,
                      installed_report_sha256=report_sha)
        if change_raw:
            change_raw(raw)
        files = {'original-acceptance/' + name: encoded(acceptance if name == 'weather-android-hosted-acceptance.json'
                    else {'synthetic': 'not actual runtime evidence'}) for name in R.REPORTS}
        files.update({'source-capture/rawrecording.json': encoded(raw), 'source-capture/driver-window.json': encoded(window),
                      'source-capture/screen.mp4': video_bytes, 'source-capture/screen-001.png': png})
        capture = dict(schema=1, kind='weather-demo-quarantined-capture', identity=IDENTITY,
            original_acceptance_sha256=record(encoded(acceptance))['sha256'], original_android_report_sha256=report_sha,
            files={name: record(data) for name, data in files.items()},
            capture={key: raw[key] for key in ['started_unix_ms', 'completed_unix_ms', 'elapsed_ms']},
            driver_window={key: window[key] for key in ['started_unix_ms', 'completed_unix_ms']},
            original_core_acceptance_passed=True, media_accepted=False, joined_media_acceptance=False,
            production_authority=False, review_required=True)
        if change_capture:
            change_capture(capture)
        if corrupt:
            files['source-capture/screen.mp4'] += b'changed after manifest'
        path = self.root / 'quarantine.zip'
        with zipfile.ZipFile(path, 'w') as archive:
            archive.writestr('capture.json', encoded(capture))
            for name, data in files.items():
                archive.writestr(name, data)
        # Real unchanged inert helpers validate file hashes, PNG dimensions and wall-clock shape.
        import runpy
        module = runpy.run_path(str(ROOT / 'tests/integration/weather-demo-media.py'))
        module['accepted'] = lambda _: (acceptance, {'original_android_report_sha256': report_sha})
        module['verify'] = lambda _: self.fail('encoded-duration admission must never run for quarantine')
        def profile(_):
            self.assertTrue(all(key not in os.environ for key in ['GH_TOKEN', 'GITHUB_TOKEN', 'GH_ENTERPRISE_TOKEN', 'GITHUB_ENTERPRISE_TOKEN']))
            return dict(codec='h264', width=720, height=1280, duration_seconds=65.579, has_audio=False)
        module['probe_video'] = profile
        return path, capture, module

    def test_quarantine_rechecks_original_core_but_never_admits_failed_duration(self):
        path, capture, module = self.quarantine_fixture()
        with patch.dict(os.environ, {'GH_TOKEN': 'synthetic private token', 'GITHUB_TOKEN': 'synthetic second token'}), \
                patch.object(R.runpy, 'run_path', return_value=module):
            actual, media, _ = R.quarantine_evidence(path, self.root / 'original', IDENTITY)
            self.assertEqual(os.environ['GH_TOKEN'], 'synthetic private token')
            self.assertEqual(os.environ['GITHUB_TOKEN'], 'synthetic second token')
        self.assertEqual(actual, capture)
        self.assertFalse(actual['media_accepted'])
        self.assertFalse(actual['joined_media_acceptance'])
        self.assertTrue(actual['original_core_acceptance_passed'])
        self.assertLess(media['video']['duration_seconds'] * 1000 + 250,
                        capture['driver_window']['completed_unix_ms'] - capture['capture']['started_unix_ms'])
        self.assertEqual({p.name for p in (self.root / 'original').iterdir()},
                         {'capture.json', 'source-capture', 'original-acceptance'})

    def test_quarantine_corrupt_hash_profile_and_window_reject(self):
        cases = [dict(corrupt=True), dict(change_raw=lambda raw: raw.update(joined_core_acceptance=True)),
                 dict(change_raw=lambda raw: raw.update(completed_unix_ms=1000001)),
                 dict(change_capture=lambda capture: capture.update(media_accepted=True)),
                 dict(change_capture=lambda capture: capture.update(identity=dict(IDENTITY, weather_commit='f' * 40)))]
        for index, changes in enumerate(cases):
            path, _, module = self.quarantine_fixture(**changes)
            with self.subTest(index=index), patch.object(R.runpy, 'run_path', return_value=module), self.assertRaises(ValueError):
                R.quarantine_evidence(path, self.root / f'bad-{index}', IDENTITY)

    def test_quarantine_duplicate_manifest_keys_and_native_profile_rejection(self):
        path, _, module = self.quarantine_fixture()
        duplicate = self.root / 'duplicate-quarantine.zip'
        with zipfile.ZipFile(path) as source, zipfile.ZipFile(duplicate, 'w') as target:
            for name in source.namelist():
                raw = source.read(name)
                target.writestr(name, b'{"schema":1,' + raw[1:] if name == 'capture.json' else raw)
        with self.assertRaisesRegex(ValueError, 'duplicate JSON key'):
            R.quarantine_evidence(duplicate, self.root / 'duplicate-output', IDENTITY)
        self.assertFalse((self.root / 'duplicate-output').exists())
        def rejected_profile(_):
            raise ValueError('synthetic invalid encoded stream profile')
        module['probe_video'] = rejected_profile
        with patch.object(R.runpy, 'run_path', return_value=module), self.assertRaisesRegex(ValueError, 'stream profile'):
            R.quarantine_evidence(path, self.root / 'bad-profile', IDENTITY)

    def test_quarantine_accepts_exact_completed_failure_only_in_inspection(self):
        run, artifact, _ = self.metadata()
        run['conclusion'] = 'failure'
        artifact['name'] = 'weather-demo-capture-quarantine-' + CORE
        listing = dict(total_count=1, artifacts=[artifact])
        with patch.object(R, 'api', side_effect=[run, run, listing]):
            selected = R.selected_artifact('123', '2', CORE, quarantine=True)
            self.assertEqual(selected['original_run_conclusion'], 'failure')
            self.assertEqual(selected['name'], artifact['name'])
        with patch.object(R, 'api', side_effect=[run, run]), self.assertRaises(ValueError):
            R.selected_artifact('123', '2', CORE)
        for changes in [dict(status='in_progress'), dict(conclusion='cancelled'), dict(run_attempt=3)]:
            invalid = dict(run, **changes)
            with patch.object(R, 'api', side_effect=[invalid, run]), self.assertRaises(ValueError):
                R.selected_artifact('123', '2', CORE, quarantine=True)

    def test_sampling_bounds_and_quarantine_hold_exclusion(self):
        for start, stop, fps, duration in [(-1, 1, 5, 3), (0, float('nan'), 5, 3), (0, 1, float('inf'), 3),
                (0, 1, 0, 3), (0, 1, 31, 3), (1, 1, 5, 3), (0, 4, 5, 3), (0, 31, 30, 40), (180, None, 5, 180)]:
            with self.subTest(values=(start, stop, fps, duration)), self.assertRaises(ValueError):
                R.sample_window(start, stop, fps, duration)
        self.assertEqual(R.sample_window(0, None, 5, 180), 180)
        self.assertEqual(R.sample_window(0, 180, 30, 180, native=True), 180)
        with patch.object(R, 'ROOT', self.root), patch.object(R, 'api') as api:
            with self.assertRaisesRegex(ValueError, 'cannot render'):
                R.prepare('123', '2', CORE, self.root / 'output', hold_image='screen-003.png', inspect_quarantine=True)
            preview = R.prepare('123', '2', CORE, self.root / 'output', inspect_quarantine=True, native_frames=True)
            self.assertEqual(preview['kind'], 'weather-demo-quarantine-inspection-preview')
            self.assertFalse(preview['media_accepted'])
            self.assertTrue(preview['sampling']['native_frames'])
            self.assertEqual(preview['sampling']['fps'], 5)
            self.assertFalse((self.root / 'output').exists())
            api.assert_not_called()

    def test_clean_source_pts_timeline_discards_side_data_and_never_infers_os_times(self):
        video = self.root / 'source.mp4'
        video.write_bytes(b'synthetic source hash input')
        frames = dict(frames=[dict(pts_time='0.000000', best_effort_timestamp_time='0.000000',
            pkt_duration_time='0.200000', side_data_list=[{'private_unused': 'must never persist'}]),
            dict(pts_time='0.200000', best_effort_timestamp_time='0.200000', pkt_duration_time='0.200000')])
        with patch.object(R, 'tool', side_effect=str), patch.object(R, 'command', return_value=encoded(frames)) as command:
            timeline = R.source_frame_timeline(video, 1.0)
        self.assertEqual([frame['clip_relative_pts_seconds'] for frame in timeline['frames']], [0, 0.2])
        self.assertNotIn('must never persist', json.dumps(timeline))
        self.assertFalse(timeline['os_input_timestamps_inferred'])
        self.assertFalse(timeline['sample_to_source_frame_mapping_verified'])
        self.assertIn('-select_streams', command.call_args.args[0])
        self.assertIn('v:0', command.call_args.args[0])
        self.assertTrue(command.call_args.kwargs['reject_stderr'])
        for invalid in [dict(frames=[dict(pts_time='NaN')]),
                        dict(frames=[dict(pts_time='1.0'), dict(pts_time='0.5')]), dict(frames=[]),
                        dict(frames=[dict(pts_time='0.0', unexpected='private text')])]:
            with patch.object(R, 'tool', side_effect=str), patch.object(R, 'command', return_value=encoded(invalid)), \
                    self.assertRaises(ValueError):
                R.source_frame_timeline(video, 1.0)

    def test_native_and_resampled_inspection_use_bounded_original_video_only(self):
        original = self.root / 'original'
        (original / 'source-capture').mkdir(parents=True)
        font = self.root / 'font.ttf'
        font.write_bytes(b'inert font')
        timeline = dict(frames=[dict(frame_index=i, source_pts_seconds=i / 5,
            clip_relative_pts_seconds=i / 5, pts_time=i / 5) for i in range(4)])
        png = b'\x89PNG\r\n\x1a\n' + b'\0\0\0\rIHDR' + (720).to_bytes(4, 'big') + (1280).to_bytes(4, 'big')
        for native in [False, True]:
            output = self.root / ('native' if native else 'resampled')
            output.mkdir()
            calls = []
            def render(args, **kwargs):
                calls.append(args)
                if str(args[-1]).endswith('frame-%03d.png'):
                    self.assertEqual(kwargs['reject_stderr'], native)
                    count = int(args[args.index('-frames:v') + 1])
                    for index in range(count):
                        (output / 'samples' / f'frame-{index:03d}.png').write_bytes(png)
                else:
                    Path(args[-1]).write_bytes(b'synthetic sheet placeholder')
            with patch.object(R, 'FONT', font), patch.object(R, 'tool', side_effect=str), \
                    patch.object(R, 'source_frame_timeline', return_value=timeline), patch.object(R, 'command', side_effect=render):
                result = R.quarantine_samples(original, output, dict(video=dict(duration_seconds=1)), 0, 1, 5, native=native)
            self.assertEqual(result['sampled_frames'], 4 if native else 5)
            self.assertFalse(result['media_accepted'])
            self.assertFalse(result['os_input_timestamps_inferred'])
            self.assertEqual(result['sample_to_source_frame_mapping_verified'], native)
            self.assertEqual(json.loads((output / 'frame-timeline.json').read_text()), timeline)
            self.assertEqual('-fps_mode' in calls[0], native)
            self.assertEqual('-enc_time_base:v' in calls[0], native)
            graph = calls[0][calls[0].index('-vf') + 1]
            self.assertEqual('drawtext' in graph, not native)
            self.assertEqual('fps=' in graph, not native)
            self.assertIn(str(original / 'source-capture/screen.mp4'), calls[0])
            if native:
                self.assertEqual(calls[0][calls[0].index('-enc_time_base:v') + 1], 'demux')
                self.assertEqual(calls[0][calls[0].index('-fps_mode') + 1], 'passthrough')
                self.assertEqual([row['frame_index'] for row in result['decoded_frames']], [0, 1, 2, 3])
                self.assertNotIn('nominal_sample_seconds', result)
            else:
                self.assertEqual(result['nominal_sample_seconds'], [0, 0.2, 0.4, 0.6, 0.8])

    def test_native_frame_budget_and_decode_count_mismatch_fail_closed(self):
        original = self.root / 'original'
        font = self.root / 'font.ttf'
        font.write_bytes(b'font')
        output = self.root / 'too-many'
        output.mkdir()
        timeline = dict(frames=[dict(frame_index=i, clip_relative_pts_seconds=i / 1000) for i in range(901)])
        with patch.object(R, 'FONT', font), patch.object(R, 'tool', side_effect=str), \
                patch.object(R, 'source_frame_timeline', return_value=timeline), patch.object(R, 'command') as command:
            with self.assertRaisesRegex(ValueError, 'native frame count') as rejected:
                R.quarantine_samples(original, output, dict(video=dict(duration_seconds=1)), 0, 1, 5, native=True)
            self.assertEqual(rejected.exception.sampling_rejection['rule'], 'selection-count')
            self.assertEqual(rejected.exception.sampling_rejection['facts']['expected_frame_count'], 901)
            command.assert_not_called()
        mismatch = self.root / 'mismatch'
        mismatch.mkdir()
        timeline['frames'] = timeline['frames'][:2]
        with patch.object(R, 'FONT', font), patch.object(R, 'tool', side_effect=str), \
                patch.object(R, 'source_frame_timeline', return_value=timeline), patch.object(R, 'command'):
            with self.assertRaises(ValueError) as rejected:
                R.quarantine_samples(original, mismatch, dict(video=dict(duration_seconds=1)), 0, 1, 5, native=True)
            self.assertEqual(rejected.exception.sampling_rejection['rule'], 'frame-inventory')
            self.assertEqual(rejected.exception.sampling_rejection['facts']['expected_frame_count'], 2)
            self.assertEqual(rejected.exception.sampling_rejection['facts']['actual_frame_count'], 0)

    def test_sampling_zero_exit_stderr_still_rejects_with_only_finite_classification(self):
        marker = b'Application provided invalid, non monotonically increasing dts to muxer'
        for raw, classification in ((b'PRIVATE-prefix ' + marker + b' PRIVATE-path/token', 'non-monotonic-dts'),
                (b'PRIVATE unrelated native error', 'other')):
            args = [sys.executable, '-c', 'import sys; sys.stderr.buffer.write(' + repr(raw) + ')']
            with self.assertRaisesRegex(ValueError, 'child emitted error diagnostics') as rejected:
                R.command(args, reject_stderr=True, sampling=True)
            detail = rejected.exception.sampling_rejection
            self.assertEqual(detail['rule'], 'child-stderr')
            self.assertEqual(detail['facts'], dict(native_error_category='stderr', stderr_bytes=len(raw),
                stderr_class=classification, child_status=0))
            self.assertNotIn('PRIVATE', json.dumps(detail))
            self.assertNotIn('PRIVATE', str(rejected.exception))

    def test_sampling_command_failure_preserves_process_status_and_timeout_rejection(self):
        with self.assertRaises(R.ChildFailure) as rejected:
            R.command([sys.executable, '-c', 'raise SystemExit(3)'], sampling=True)
        self.assertEqual(rejected.exception.status, 3)
        self.assertEqual(rejected.exception.sampling_rejection['rule'], 'child-exit')
        self.assertEqual(rejected.exception.sampling_rejection['facts']['native_error_category'], 'process')
        with self.assertRaisesRegex(ValueError, 'timeout') as rejected:
            R.command([sys.executable, '-c', 'import time; time.sleep(2)'], seconds=0.01, sampling=True)
        self.assertEqual(rejected.exception.sampling_rejection['rule'], 'child-timeout')
        self.assertEqual(rejected.exception.sampling_rejection['facts']['native_error_category'], 'timeout')

    def test_sampling_diagnostic_rejects_unknown_rules_facts_unbounded_values_and_raw_text(self):
        for rule, facts in (('PRIVATE-path', {}), ('png-size', {'raw_stderr': 'PRIVATE'}),
                ('png-dimensions', {'width': 'PRIVATE'}), ('png-dimensions', {'height': 2**32}),
                ('native-frame-count', {'actual_frame_count': True}), ('child-stderr', {'stderr_class': 'PRIVATE'})):
            with self.assertRaises(ValueError): R.sampling_rejection(rule, facts)

    def test_sampling_command_guard_classification_is_closed_without_echoing_messages(self):
        for message, rule in (('child timeout', 'child-timeout'), ('generated image budget exceeded', 'child-png-budget'),
                ('child diagnostic limit exceeded', 'child-stderr-limit'), ('child output limit exceeded', 'child-output-limit'),
                ('PRIVATE /path/token', 'child-other')):
            value = R.sampling_command_failure(ValueError(message), b'PRIVATE stderr', None)
            self.assertEqual(value['rule'], rule)
            self.assertEqual(value['facts']['stderr_bytes'], 14)
            self.assertNotIn('PRIVATE', json.dumps(value))

    def test_sampling_png_total_budget_retains_exact_counts_before_cleanup(self):
        original = self.root / 'original'
        font = self.root / 'font.ttf'; font.write_bytes(b'inert font')
        output = self.root / 'budget'; output.mkdir()
        timeline = dict(frames=[dict(frame_index=0, clip_relative_pts_seconds=0)])
        png = b'\x89PNG\r\n\x1a\n' + b'\0\0\0\rIHDR' + (720).to_bytes(4, 'big') + (1280).to_bytes(4, 'big')
        def render(args, **kwargs):
            (output / 'samples' / 'frame-000.png').write_bytes(png)
        with patch.object(R, 'MAX_ZIP', 23), patch.object(R, 'FONT', font), patch.object(R, 'tool', side_effect=str), \
                patch.object(R, 'source_frame_timeline', return_value=timeline), patch.object(R, 'command', side_effect=render):
            with self.assertRaisesRegex(ValueError, 'inventory or budget') as rejected:
                R.quarantine_samples(original, output, dict(video=dict(duration_seconds=1)), 0, 1, 5, native=True)
        detail = rejected.exception.sampling_rejection
        self.assertEqual(detail['rule'], 'png-total-budget')
        self.assertEqual(detail['facts']['expected_frame_count'], 1)
        self.assertEqual(detail['facts']['actual_frame_count'], 1)
        self.assertEqual(detail['facts']['total_png_bytes'], 24)

    def test_sampling_failure_removes_partial_pngs_but_retains_counts_dimensions_and_nonadmission(self):
        output = self.root / 'failed-sampling'
        font = self.root / 'font.ttf'; font.write_bytes(b'inert font')
        timeline = dict(frames=[dict(frame_index=i, clip_relative_pts_seconds=i / 5) for i in range(2)])
        png = b'\x89PNG\r\n\x1a\n' + b'\0\0\0\rIHDR' + (720).to_bytes(4, 'big') + (1).to_bytes(4, 'big')
        def render(args, **kwargs):
            for i in range(2): (output / 'samples' / f'frame-{i:03d}.png').write_bytes(png)
        with patch.object(R, 'ROOT', self.root), patch.object(R, 'hosted'), patch.dict(os.environ, ENV, clear=True), \
                patch.object(R, 'FONT', font), patch.object(R, 'tool', side_effect=str), \
                patch.object(R, 'selected_artifact', return_value={'id': 7, 'original_run_conclusion': 'failure'}), \
                patch.object(R, 'download', side_effect=lambda _, target: target.write_bytes(b'inert archive')), \
                patch.object(R, 'quarantine_evidence', return_value=({}, {'video': {'duration_seconds': 1}}, 'c' * 64)), \
                patch.object(R, 'source_frame_timeline', return_value=timeline), patch.object(R, 'command', side_effect=render):
            with self.assertRaisesRegex(ValueError, 'PNG dimensions'):
                R.prepare('123', '2', CORE, output, execute=True, inspect_quarantine=True, native_frames=True)
        self.assertEqual([path.name for path in output.iterdir()], ['review-failure.json'])
        failure = json.loads((output / 'review-failure.json').read_text())
        detail = failure['sampling_rejection']
        self.assertEqual(detail['rule'], 'png-dimensions')
        self.assertEqual(detail['facts'], dict(width=720, height=1, expected_frame_count=2, actual_frame_count=2,
            total_png_bytes=48, native_error_category='none', stderr_bytes=0, stderr_class='none'))
        self.assertEqual(failure['category'], 'value')
        self.assertTrue(failure['partial_output_removed'])
        for key in ('media_accepted', 'joined_media_acceptance', 'new_runtime_executed', 'production_authority',
                    'visual_acceptance_claimed', 'publication_authorized'):
            self.assertFalse(failure[key])
        self.assertNotIn(str(self.root), json.dumps(failure))

    def test_quarantine_failure_cleanup_retains_nonadmission_and_failed_original(self):
        output = self.root / 'failed-inspection'
        def failed_download(_, target):
            target.write_bytes(b'inert partial download')
            raise ValueError('synthetic boundary failure')
        with patch.object(R, 'ROOT', self.root), patch.object(R, 'hosted'), patch.dict(os.environ, ENV, clear=True), \
                patch.object(R, 'selected_artifact', return_value={'id': 7, 'original_run_conclusion': 'failure'}), \
                patch.object(R, 'download', side_effect=failed_download), self.assertRaises(ValueError):
            R.prepare('123', '2', CORE, output, execute=True, inspect_quarantine=True)
        failure = json.loads((output / 'review-failure.json').read_text())
        self.assertEqual(failure['kind'], 'weather-demo-quarantine-inspection-failure')
        self.assertEqual(failure['original_run_conclusion'], 'failure')
        self.assertEqual([path.name for path in output.iterdir()], ['review-failure.json'])
        self.assertFalse(failure['media_accepted'])
        self.assertFalse(failure['joined_media_acceptance'])
        self.assertFalse(failure['new_runtime_executed'])
        self.assertFalse(failure['production_authority'])
        self.assertTrue(failure['partial_output_removed'])

    def test_quarantine_success_is_only_an_inspection_result_on_a_failed_original_run(self):
        path, capture, module = self.quarantine_fixture()
        output = self.root / 'inspection'
        # Expected metadata is inert data; only quarantine_evidence invokes the token-checking probe stub.
        video = dict(codec='h264', width=720, height=1280, duration_seconds=65.579, has_audio=False)
        media = dict(video=video, files={'screen.mp4': capture['files']['source-capture/screen.mp4']})
        with patch.object(R, 'ROOT', self.root), patch.object(R, 'hosted'), patch.dict(os.environ, ENV, clear=True), \
                patch.object(R, 'selected_artifact', return_value={'id': 7, 'original_run_conclusion': 'failure'}) as selected, \
                patch.object(R, 'download', side_effect=lambda _, target: target.write_bytes(path.read_bytes())), \
                patch.object(R, 'quarantine_evidence', return_value=(capture, media, 'c' * 64)), \
                patch.object(R, 'quarantine_samples', return_value={'native_frames': True}), \
                patch.object(R, 'evidence') as accepted_mode, patch.object(R, 'render_held_image') as held:
            result = R.prepare('123', '2', CORE, output, execute=True, inspect_quarantine=True, native_frames=True)
        self.assertEqual(selected.call_args.kwargs, {'quarantine': True})
        self.assertEqual(result['kind'], 'weather-demo-quarantine-inspection')
        self.assertEqual(result['original_run_conclusion'], 'failure')
        self.assertTrue(result['original_core_acceptance_passed'])
        for key in ['media_accepted', 'joined_media_acceptance', 'encoded_duration_admission_performed',
                    'visual_acceptance_claimed', 'new_runtime_executed', 'publication_authorized']:
            self.assertFalse(result[key])
        self.assertEqual(result['review_execution']['core_commit'], REVIEW_CORE)
        accepted_mode.assert_not_called()
        held.assert_not_called()

    def test_quarantine_success_fixture_tolerates_synthetic_job_token_environment(self):
        with patch.dict(os.environ, {key: 'SYNTHETIC_UNIT_TOKEN' for key in
                ['GH_TOKEN', 'GITHUB_TOKEN', 'GH_ENTERPRISE_TOKEN', 'GITHUB_ENTERPRISE_TOKEN']}):
            self.test_quarantine_success_is_only_an_inspection_result_on_a_failed_original_run()

    def scoped_fixture(self):
        output = self.root / 'scoped-output'
        (output / 'samples').mkdir(parents=True)
        (output / 'original/source-capture').mkdir(parents=True)
        (output / 'original/original-acceptance').mkdir()
        raw_video = b'synthetic unit clip; never native runtime evidence'
        source_hash = record(raw_video)['sha256']
        (output / 'original/source-capture/screen.mp4').write_bytes(raw_video)
        rows = [dict(file=f'samples/frame-{index:03d}.png', frame_index=index,
            source_pts_seconds=index / 10, clip_relative_pts_seconds=index / 10) for index in range(490)]
        timeline = dict(source_video_sha256=source_hash, video_duration_seconds=65.579,
                        frames=[{key: value for key, value in row.items() if key != 'file'} for row in rows])
        (output / 'frame-timeline.json').write_bytes(encoded(timeline))
        for index in R.SCOPED_SCREENSHOTS:
            (output / rows[index]['file']).write_bytes(b'synthetic unit PNG ' + str(index).encode())
        rendered = dict(native_frames=True, sample_to_source_frame_mapping_verified=True,
            sample_start_seconds=0, sample_stop_seconds=65.579, decoded_frames=rows)
        review = dict(schema=1, kind='weather-demo-scoped-visual-review', identity=R.SCOPED_IDENTITY,
            source_video_sha256=source_hash, scope='weather-demo-0-native-timing-v1', hold_frame_index=206,
            witnesses=[dict(claim=claim, frame_index=index, source_pts_seconds=rows[index]['source_pts_seconds'],
                png_sha256=R.digest(output / rows[index]['file'])) for claim, index in R.SCOPED_CLAIMS.items()])
        acceptance = dict(identity=R.SCOPED_IDENTITY, passed=True, observations=dict(products={
            'weather': dict(cold_peer_bytes=123), 'air_quality': dict(cold_peer_bytes=456)}))
        acceptance_path = output / 'original/original-acceptance/weather-android-hosted-acceptance.json'
        acceptance_path.write_bytes(encoded(acceptance))
        capture = dict(original_core_acceptance_passed=True, media_accepted=False, joined_media_acceptance=False,
                       original_acceptance_sha256=R.digest(acceptance_path))
        media = dict(video=dict(codec='h264', width=720, height=1280, duration_seconds=65.579),
                     files={'screen.mp4': record(raw_video)})
        artifact = dict(original_run_conclusion='failure', digest=R.SCOPED_ZIP)
        return output, source_hash, timeline, rendered, review, capture, media, artifact

    def test_scoped_visual_witnesses_bind_claim_index_pts_hash_and_reject_malformed(self):
        output, source_hash, timeline, rendered, review, *_ = self.scoped_fixture()
        with patch.object(R, 'SCOPED_VIDEO', source_hash):
            validated, frames = R.scoped_visual_witnesses(review, output, R.SCOPED_IDENTITY, rendered, timeline)
            self.assertEqual(len(validated), 6)
            self.assertEqual({row['claim'] for row in validated}, set(R.SCOPED_CLAIMS))
            self.assertEqual(frames[206]['source_pts_seconds'], 20.6)
            invalids = []
            for key, value in [('scope', 'unknown'), ('hold_frame_index', 215), ('source_video_sha256', '0' * 64)]:
                changed = copy.deepcopy(review)
                changed[key] = value
                invalids.append(changed)
            changed = copy.deepcopy(review)
            changed['witnesses'] = changed['witnesses'][:-1]
            invalids.append(changed)
            for key, value in [('frame_index', 900), ('source_pts_seconds', float('nan')),
                               ('source_pts_seconds', 0), ('png_sha256', '0' * 64), ('claim', 'unknown')]:
                changed = copy.deepcopy(review)
                changed['witnesses'][0][key] = value
                invalids.append(changed)
            changed = copy.deepcopy(review)
            changed['witnesses'][1] = changed['witnesses'][0]
            invalids.append(changed)
            for invalid in invalids:
                with self.subTest(invalid=invalid.get('scope')), self.assertRaises(ValueError):
                    R.scoped_visual_witnesses(invalid, output, R.SCOPED_IDENTITY, rendered, timeline)

    def test_scoped_visual_review_must_match_committed_document_bytes(self):
        path = self.root / 'visual-review.json'
        raw = encoded({'schema': 1, 'synthetic': True})
        path.write_bytes(raw)
        with patch.object(R, 'ROOT', self.root), patch.object(R, 'tool', side_effect=str), \
                patch.object(R, 'command', return_value=raw) as command:
            self.assertEqual(R.committed_visual_review(path), (raw, json.loads(raw)))
            self.assertIn('HEAD:visual-review.json', command.call_args.args[0])
            self.assertTrue(command.call_args.kwargs['reject_stderr'])
        with patch.object(R, 'ROOT', self.root), patch.object(R, 'tool', side_effect=str), \
                patch.object(R, 'command', return_value=b'{}'), self.assertRaisesRegex(ValueError, 'committed source bytes'):
            R.committed_visual_review(path)

    def test_scoped_flag_requires_whole_native_inspection_fixed_identity_and_review(self):
        common = dict(admit_scoped=True, visual_review=Path('visual-review.json'),
                      inspect_quarantine=True, native_frames=True)
        for change in [dict(inspect_quarantine=False), dict(native_frames=False), dict(sample_start=1),
                       dict(sample_stop=65), dict(hold_image='screen-003.png'), dict(visual_review=None)]:
            with patch.object(R, 'ROOT', self.root), self.assertRaises(ValueError):
                R.prepare('39998753810', '1', R.SCOPED_IDENTITY['core_commit'], self.root / 'output', **(common | change))
        with patch.object(R, 'ROOT', self.root), self.assertRaises(ValueError):
            R.prepare('123', '2', CORE, self.root / 'output', **common)
        with patch.object(R, 'ROOT', self.root), patch.object(R, 'api') as api:
            preview = R.prepare('39998753810', '1', R.SCOPED_IDENTITY['core_commit'], self.root / 'output', **common)
        self.assertFalse(preview['scoped_demo_admitted'])
        self.assertTrue(preview['original_failed_run_preserved'])
        api.assert_not_called()

    def test_scoped_admission_writes_separate_bound_presentation_without_changing_inspection(self):
        output, source_hash, timeline, rendered, review, capture, media, artifact = self.scoped_fixture()
        (output / 'review.json').write_bytes(b'original inspection marker')
        technical = dict(schema=1, kind='weather-demo-native-timing-coherence', technical_coherence_passed=True,
            source_video_sha256=source_hash, media_accepted=False, visual_acceptance_claimed=False,
            publication_authorized=False, production_authority=False)
        def render(raw, stage, duration, raw_info, lines, *, hold_image):
            self.assertEqual(raw, output / 'original/source-capture/screen.mp4')
            self.assertEqual(hold_image, output / 'samples/frame-206.png')
            self.assertEqual(duration, 120)
            (stage / 'weather-demo-0.mp4').write_bytes(b'synthetic final movie')
            return stage / 'weather-demo-0.mp4', dict(duration_seconds=120)
        def preview(args, **kwargs):
            self.assertTrue(kwargs['reject_stderr'])
            if args == ['/usr/bin/ffmpeg', '-version']:
                return b'ffmpeg version 6.1.1-synthetic-test-only\n'
            Path(args[-1]).write_bytes(b'\x89PNG\r\n\x1a\n' + b'\0\0\0\rIHDR' +
                (1920).to_bytes(4, 'big') + (1080).to_bytes(4, 'big'))
        def module(path):
            if str(path).endswith('weather-demo-native-timing.py'):
                return {'validate': lambda video, frames: technical}
            return dict(presentation_lines=lambda *args, **kwargs: [], render_video=render,
                        scoped_captions=lambda *args: ('scoped captions', 'scoped transcript'))
        font = self.root / 'synthetic-font.ttf'
        font.write_bytes(b'synthetic font fixture; never actual render evidence')
        with patch.object(R, 'SCOPED_VIDEO', source_hash), patch.object(R, 'hosted'), \
                patch.object(R, 'committed_visual_review', return_value=(encoded(review), review)), \
                patch.object(R.runpy, 'run_path', side_effect=module), patch.object(R, 'tool', side_effect=str), \
                patch.object(R, 'FONT', font), patch.object(R, 'command', side_effect=preview):
            record = R.admit_scoped_demo(output, R.SCOPED_IDENTITY, capture, media, artifact, rendered,
                                         Path('review.json'), dict(core_commit=REVIEW_CORE))
        self.assertTrue(record['scoped_demo_admitted'])
        checkpoint = json.loads((output / 'native-timing.json').read_text())
        self.assertEqual(checkpoint['technical_report'], technical)
        self.assertEqual(checkpoint['identity'], R.SCOPED_IDENTITY)
        self.assertFalse(checkpoint['scoped_demo_admitted'])
        self.assertFalse(checkpoint['publication_authorized'])
        self.assertEqual(record['native_timing_sha256'], R.digest(output / 'native-timing.json'))
        self.assertEqual(record['original_run_conclusion'], 'failure')
        self.assertFalse(record['original_duration_verify_called'])
        self.assertFalse(record['publication_authorized'])
        self.assertFalse(record['production_authority'])
        self.assertEqual((output / 'review.json').read_bytes(), b'original inspection marker')
        presentation = json.loads((output / 'presentation/presentation.json').read_text())
        self.assertEqual(presentation['pixel_scope'], sorted(R.SCOPED_CLAIMS))
        self.assertEqual(presentation['report_only_scope'], ['second-refresh-completion', 'background-resume-lifecycle-and-mounted-tables'])
        self.assertIn('preview-090.png', presentation['files'])
        self.assertEqual(presentation['hold_frame']['file'], 'screenshots/frame-206.png')
        self.assertIn('30fps CFR', presentation['edits']['presentation_cadence'])
        self.assertEqual(presentation['ffmpeg_version'], 'ffmpeg version 6.1.1-synthetic-test-only')
        self.assertEqual(presentation['font_sha256'], hashlib.sha256(font.read_bytes()).hexdigest())
        self.assertEqual((output / 'presentation/screen.mp4').read_bytes(), b'synthetic unit clip; never native runtime evidence')
        self.assertEqual({p.name for p in (output / 'presentation/screenshots').iterdir()},
                         {f'frame-{index:03d}.png' for index in R.SCOPED_SCREENSHOTS})

    def test_validated_timing_checkpoint_precedes_failed_render(self):
        output, source_hash, timeline, rendered, review, capture, media, artifact = self.scoped_fixture()
        technical = dict(schema=1, kind='weather-demo-native-timing-coherence', technical_coherence_passed=True,
            source_video_sha256=source_hash, media_accepted=False, visual_acceptance_claimed=False,
            publication_authorized=False, production_authority=False)
        def fail_render(*args, **kwargs):
            self.assertTrue((output / 'native-timing.json').exists())
            raise ValueError('Demo presentation rejected')
        def module(path):
            if str(path).endswith('weather-demo-native-timing.py'):
                return {'validate': lambda *_: technical}
            return dict(presentation_lines=lambda *args, **kwargs: [], render_video=fail_render)
        with patch.object(R, 'SCOPED_VIDEO', source_hash), patch.object(R, 'hosted'), \
                patch.object(R, 'committed_visual_review', return_value=(encoded(review), review)), \
                patch.object(R.runpy, 'run_path', side_effect=module), self.assertRaises(ValueError):
            R.admit_scoped_demo(output, R.SCOPED_IDENTITY, capture, media, artifact, rendered,
                                Path('review.json'), dict(core_commit=REVIEW_CORE))
        checkpoint = json.loads((output / 'native-timing.json').read_text())
        self.assertEqual(checkpoint['technical_report'], technical)
        self.assertEqual(checkpoint['original_recording_sha256'], source_hash)
        self.assertFalse(checkpoint['media_accepted'])
        self.assertEqual(R.STATE['stage'], 'scoped-presentation-render')

    def test_presentation_failure_preserves_checkpoint_and_closed_render_facts(self):
        output = self.root / 'inspection'
        capture = dict(original_acceptance_sha256='e' * 64, capture={}, driver_window={})
        media = dict(video={}, files={'screen.mp4': dict(sha256=R.SCOPED_VIDEO)})
        def fail(*args):
            (output / 'native-timing.json').write_bytes(encoded({'synthetic': 'closed checkpoint fixture'}))
            (output / 'presentation').mkdir()
            (output / 'presentation/partial.mp4').write_bytes(b'partial unit fixture')
            R.STATE.update(stage='scoped-presentation-render', presentation_facts=dict(
                raw_duration_ms=65579, requested_duration_ms=120000, held_frame_index=206, secret='drop'))
            error = ValueError('Demo presentation rejected')
            error.render_rejection = dict(phase='output-check', facts=dict(duration_ms=119000,
                requested_duration_ms=120000, width=1920, height=1080, output_bytes=100))
            raise error
        with patch.object(R, 'ROOT', self.root), patch.object(R, 'hosted'), patch.dict(os.environ, ENV, clear=True), \
                patch.object(R, 'selected_artifact', return_value={'original_run_conclusion': 'failure'}), \
                patch.object(R, 'download', side_effect=lambda _, path: path.write_bytes(b'synthetic ZIP')), \
                patch.object(R, 'quarantine_evidence', return_value=(capture, media, 'c' * 64)), \
                patch.object(R, 'quarantine_samples', return_value={}), patch.object(R, 'admit_scoped_demo', side_effect=fail), \
                self.assertRaises(ValueError):
            R.prepare('39998753810', '1', R.SCOPED_IDENTITY['core_commit'], output, execute=True,
                      inspect_quarantine=True, native_frames=True, admit_scoped=True, visual_review=Path('review.json'))
        self.assertTrue((output / 'review.json').exists())
        self.assertTrue((output / 'native-timing.json').exists())
        self.assertFalse((output / 'presentation').exists())
        failure = json.loads((output / 'scoped-admission-failure.json').read_text())
        self.assertEqual(failure['stage'], 'scoped-presentation-render')
        self.assertEqual(failure['presentation_rejection'], 'render-check')
        self.assertEqual(failure['render_rejection']['facts']['duration_ms'], 119000)
        self.assertNotIn('secret', failure['presentation_facts'])
        self.assertEqual(failure['native_timing_sha256'], R.digest(output / 'native-timing.json'))

    def test_scoped_rejection_retains_inspection_and_fixed_native_timing_reason(self):
        output = self.root / 'inspection'
        capture = dict(original_acceptance_sha256='e' * 64, capture={}, driver_window={})
        media = dict(video={}, files={'screen.mp4': dict(sha256=R.SCOPED_VIDEO)})
        timing = R.runpy.run_path(str(ROOT / 'tests/integration/weather-demo-native-timing.py'))
        detail = timing['observation'](dict(streams=[dict(index=1, codec_type='data', codec_tag_string='mett',
            time_base='1/90000', start_pts=0, duration_ts='5902102', nb_frames='1')], packets=[]), dict(frames=[]))
        def fail(*args):
            R.STATE['stage'] = 'scoped-native-timing'
            error = ValueError('native_timing_metadata_relative_disagreement')
            error.native_timing_observation = detail
            raise error
        with patch.object(R, 'ROOT', self.root), patch.object(R, 'hosted'), patch.dict(os.environ, ENV, clear=True), \
                patch.object(R, 'selected_artifact', return_value={'original_run_conclusion': 'failure'}), \
                patch.object(R, 'download', side_effect=lambda _, path: path.write_bytes(b'synthetic ZIP')), \
                patch.object(R, 'quarantine_evidence', return_value=(capture, media, 'c' * 64)), \
                patch.object(R, 'quarantine_samples', return_value={}), patch.object(R, 'admit_scoped_demo', side_effect=fail), \
                patch.object(R.runpy, 'run_path', return_value=timing), \
                self.assertRaises(ValueError):
            R.prepare('39998753810', '1', R.SCOPED_IDENTITY['core_commit'], output, execute=True,
                      inspect_quarantine=True, native_frames=True, admit_scoped=True, visual_review=Path('review.json'))
        self.assertTrue((output / 'review.json').exists())
        failure = json.loads((output / 'scoped-admission-failure.json').read_text())
        self.assertEqual(failure['native_timing_rejection'], 'native_timing_metadata_relative_disagreement')
        self.assertEqual(failure['native_timing_observation']['streams'][0]['duration_ts'], 5902102)
        self.assertFalse(failure['native_timing_observation']['technical_coherence_passed'])
        self.assertTrue(failure['completed_inspection_preserved'])
        self.assertFalse(failure['scoped_demo_admitted'])

    def test_scoped_failure_drops_malformed_timing_attachment(self):
        output = self.root / 'inspection'
        timing = R.runpy.run_path(str(ROOT / 'tests/integration/weather-demo-native-timing.py'))
        capture = dict(original_acceptance_sha256='e' * 64, capture={}, driver_window={})
        media = dict(video={}, files={'screen.mp4': dict(sha256=R.SCOPED_VIDEO)})
        def fail(*args):
            R.STATE['stage'] = 'scoped-native-timing'
            error = ValueError('native_timing_metadata_duration')
            error.native_timing_observation = {'private path': 'secret'}
            raise error
        with patch.object(R, 'ROOT', self.root), patch.object(R, 'hosted'), patch.dict(os.environ, ENV, clear=True), \
                patch.object(R, 'selected_artifact', return_value={'original_run_conclusion': 'failure'}), \
                patch.object(R, 'download', side_effect=lambda _, path: path.write_bytes(b'synthetic ZIP')), \
                patch.object(R, 'quarantine_evidence', return_value=(capture, media, 'c' * 64)), \
                patch.object(R, 'quarantine_samples', return_value={}), patch.object(R, 'admit_scoped_demo', side_effect=fail), \
                patch.object(R.runpy, 'run_path', return_value=timing), self.assertRaises(ValueError):
            R.prepare('39998753810', '1', R.SCOPED_IDENTITY['core_commit'], output, execute=True,
                      inspect_quarantine=True, native_frames=True, admit_scoped=True, visual_review=Path('review.json'))
        raw = (output / 'scoped-admission-failure.json').read_text()
        failure = json.loads(raw)
        self.assertNotIn('native_timing_observation', failure)
        self.assertNotIn('private', raw)
        self.assertNotIn('secret', raw)
        self.assertEqual(failure['native_timing_rejection'], 'native_timing_metadata_duration')
        self.assertTrue(failure['completed_inspection_preserved'])
        self.assertFalse(failure['scoped_demo_admitted'])

    def test_duplicate_json_keys_are_not_silently_accepted(self):
        with self.assertRaises(ValueError):
            R.decode(b'{"a":1,"a":2}')
        with self.assertRaises(ValueError):
            R.decode(b'{"a":NaN}')


if __name__ == '__main__':
    unittest.main()
