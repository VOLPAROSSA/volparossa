#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-only
"""Inert fixtures only: no native media tools, network, app or Core execution."""
import copy
import hashlib
import importlib.util
import json
from pathlib import Path
import stat
import sys
import tempfile
import unittest
from unittest.mock import patch
import zipfile

sys.dont_write_bytecode = True
ROOT = Path(__file__).resolve().parents[2]
spec = importlib.util.spec_from_file_location('weather_short', ROOT / 'scripts/weather-demo-0-short.py')
S = importlib.util.module_from_spec(spec)
spec.loader.exec_module(S)


def encoded(value):
    return (json.dumps(value, sort_keys=True) + '\n').encode()


def binding(raw):
    return dict(bytes=len(raw), sha256=hashlib.sha256(raw).hexdigest())


class ShortPresentation(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix='inert-weather-short-')
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name).resolve()

    def metadata(self):
        run = dict(id=40017379373, run_attempt=1, head_sha=S.SOURCE,
            status='completed', conclusion='success',
            repository=dict(full_name=S.REVIEW['REPOSITORY']),
            head_repository=dict(full_name=S.REVIEW['REPOSITORY']),
            run_started_at='2026-10-23T20:12:12Z', updated_at='2026-10-23T20:14:07Z')
        artifact = dict(S.ARTIFACT, expired=False,
            workflow_run=dict(id=40017379373, head_sha=S.SOURCE),
            created_at='2026-10-23T20:14:00Z', updated_at='2026-10-23T20:14:01Z')
        return run, artifact

    def test_preview_is_inert_and_requires_new_cache_path(self):
        output = self.root / '.cache/short'
        with patch.object(S, 'ROOT', self.root), patch.dict(S.REVIEW, api=lambda _: self.fail('API called')):
            result = S.prepare(output)
            self.assertFalse(result['execute'])
            self.assertFalse(output.exists())
            for path in (Path('relative'), self.root / 'outside', self.root / '.cache/../outside'):
                with self.assertRaises(ValueError):
                    S.prepare(path)
            output.mkdir(parents=True)
            with self.assertRaises(ValueError):
                S.prepare(output)

    def test_execute_rejects_host_before_api_or_creation(self):
        output = self.root / '.cache/short'
        with patch.object(S, 'ROOT', self.root), patch.dict(S.REVIEW,
            hosted=lambda: (_ for _ in ()).throw(ValueError('host rejected')),
            api=lambda _: self.fail('API called')):
            with self.assertRaises(ValueError):
                S.prepare(output, execute=True)
        self.assertFalse(output.exists())

    def test_exact_successful_run_and_artifact_required(self):
        run, artifact = self.metadata()
        with patch.dict(S.REVIEW, api=lambda endpoint: artifact if '/artifacts/' in endpoint else run):
            self.assertEqual(S.selected_artifact()['artifact'], S.ARTIFACT)
        for field, value in (('run_attempt', 2), ('conclusion', 'failure'), ('head_sha', 'a' * 40)):
            changed = dict(run, **{field: value})
            with patch.dict(S.REVIEW, api=lambda endpoint: artifact if '/artifacts/' in endpoint else changed):
                with self.assertRaises(ValueError):
                    S.selected_artifact()
        for field, value in (('id', 1), ('expired', True), ('digest', 'sha256:' + 'a' * 64),
                             ('size_in_bytes', 12), ('created_at', '2026-10-23T20:00:00Z')):
            changed = dict(artifact, **{field: value})
            with patch.dict(S.REVIEW, api=lambda endpoint: changed if '/artifacts/' in endpoint else run):
                with self.assertRaises(ValueError):
                    S.selected_artifact()

    def archive(self, extra=None):
        path = self.root / 'fixture.zip'
        with zipfile.ZipFile(path, 'w') as z:
            z.writestr('presentation/fixture.txt', b'inert')
            if extra:
                extra(z)
        return path

    def test_archive_paths_types_duplicates_and_budgets_rejected(self):
        for name in ('../bad', '/absolute', 'presentation//bad', 'presentation/./bad',
                     'presentation/../bad', 'presentation/\\bad'):
            archive = self.archive(lambda z: z.writestr(name, b'inert'))
            with zipfile.ZipFile(archive) as z, self.assertRaises(ValueError):
                S.archive_members(z)
        def symlink(z):
            info = zipfile.ZipInfo('presentation/link')
            info.external_attr = (stat.S_IFLNK | 0o777) << 16
            z.writestr(info, b'target')
        archive = self.archive(symlink)
        with zipfile.ZipFile(archive) as z, self.assertRaises(ValueError):
            S.archive_members(z)
        archive = self.archive()
        with zipfile.ZipFile(archive) as z, patch.dict(S.REVIEW, MAX_EXPANDED=1), self.assertRaises(ValueError):
            S.archive_members(z)

    def fixture(self, mutate=False):
        trial = self.root / 'trial'
        trial.mkdir()
        original = S.decode((S.TRIAL / 'presentation.json').read_bytes())
        files = {name: ('synthetic-not-media:' + name).encode() for name in original['files']}
        manifest = copy.deepcopy(original)
        manifest['files'] = {name: binding(raw) for name, raw in files.items()}
        raw = encoded(manifest)
        (trial / 'presentation.json').write_bytes(raw)
        for name in ('scoped-admission.json', 'native-timing.json'):
            (trial / name).write_bytes(b'synthetic-inert-record')
        archive = self.root / 'source.zip'
        with zipfile.ZipFile(archive, 'w') as z:
            z.writestr('presentation/presentation.json', raw)
            for name, data in files.items():
                z.writestr('presentation/' + name, data + (b'tampered' if mutate and name == 'screen.mp4' else b''))
            for name in ('scoped-admission.json', 'native-timing.json'):
                z.writestr(name, (trial / name).read_bytes())
            z.writestr('unselected/never-unpacked.bin', b'not selected')
        patches = dict(TRIAL=trial, MANIFEST_SHA=binding(raw)['sha256'],
            ARTIFACT=dict(size_in_bytes=archive.stat().st_size, digest='sha256:' + S.digest(archive)),
            RAW_SHA=binding(files['screen.mp4'])['sha256'],
            TECHNICAL_SHA=binding(files['weather-demo-0.mp4'])['sha256'])
        return archive, manifest, files, patches

    def test_only_fixed_admitted_members_copied_unchanged(self):
        archive, manifest, files, patches = self.fixture()
        output = self.root / 'output'
        output.mkdir()
        with patch.multiple(S, **patches):
            self.assertEqual(S.extract_selected(archive, output), manifest)
        for name, raw in files.items():
            self.assertEqual((output / 'technical-original' / name).read_bytes(), raw)
        self.assertFalse((output / 'unselected').exists())
        self.assertEqual((output / 'technical-original/presentation.json').read_bytes(),
                         (patches['TRIAL'] / 'presentation.json').read_bytes())

    def test_tampered_member_rejected_before_copy(self):
        archive, _, _, patches = self.fixture(mutate=True)
        output = self.root / 'output'
        output.mkdir()
        with patch.multiple(S, **patches), self.assertRaises(ValueError):
            S.extract_selected(archive, output)
        self.assertEqual(list(output.iterdir()), [])

    def test_layout_does_not_trim_scale_or_hold_native_app(self):
        graph = S.overlay_graph(self.root / 'text')
        self.assertIn('setpts=PTS-STARTPTS,fps=30,setsar=1,pad=1280:1440:32:120', graph)
        for forbidden in ('tpad', 'trim=', 'scale=', 'crop=', 'concat=', 'setpts=2', 'setpts=0.5'):
            self.assertNotIn(forbidden, graph)
        text = '\n'.join(p.read_text() for p in (self.root / 'text').iterdir())
        for phrase in ('EXTERNAL Debian Core', 'Acceptance reports', 'animation only', 'ECMWF / NOAA'):
            self.assertIn(phrase, text)
        self.assertIn('Recorded technical demo', text)
        self.assertIn('Core runs outside Android', text)
        self.assertNotIn('Recorded pixels and acceptance reports', text)
        for _, _, title, label, body, note in S.PHASES:
            self.assertTrue(all(len(line) <= 24 for line in (title, label, *body, *note)))
        self.assertLessEqual(120 + 1280, 1416)  # attribution never overlays app pixels

    def test_font_data_identity_uses_pinned_bytes_not_executable_permissions(self):
        font = self.root / 'font.ttf'
        font.write_bytes(b'synthetic inert font data')
        font.chmod(0o666)
        expected = S.digest(font)
        S.check_font(font, expected)
        with self.assertRaises(ValueError):
            S.check_font(font, '0' * 64)
        link = self.root / 'font-link.ttf'
        link.symlink_to(font)
        with self.assertRaises(ValueError):
            S.check_font(link, expected)
        font.write_bytes(b'changed after render')
        with self.assertRaises(ValueError):
            S.check_font(font, expected)

    def test_captions_cover_whole_clip_and_scope_report_evidence(self):
        vtt, transcript = S.captions()
        self.assertTrue(vtt.startswith('WEBVTT\n'))
        self.assertIn('00:01:05.579', vtt)
        self.assertIn('No held ending', transcript)
        self.assertIn('in reports, not pixels', transcript)
        self.assertIn('No settled resume frame', transcript)
        self.assertEqual(S.PHASES[0][0], 0)
        self.assertEqual(S.PHASES[-1][1], S.DURATION)
        self.assertEqual(len(S.PHASES), 7)
        self.assertTrue(all(stop - start >= 2.7 for start, stop, *_ in S.PHASES))
        for left, right in zip(S.PHASES, S.PHASES[1:]):
            self.assertEqual(left[1], right[0])

    def test_caption_line_lengths_reading_speed_and_actual_duration(self):
        duration = 65.566667
        vtt, transcript = S.captions(duration)
        self.assertIn('00:01:05.567', vtt)
        self.assertIn('00:01:05.567', transcript)
        def seconds(timestamp):
            hours, minutes, rest = timestamp.split(':')
            return int(hours) * 3600 + int(minutes) * 60 + float(rest)
        cues = [block.splitlines() for block in vtt.split('\n\n') if ' --> ' in block]
        self.assertEqual(len(cues), 7)
        for interval, *text in cues:
            start, stop = (seconds(t) for t in interval.split(' --> '))
            self.assertLessEqual(len(text), 2)
            self.assertTrue(all(len(line) <= 48 for line in text))
            self.assertLessEqual(len(' '.join(text)) / (stop - start), 20)
            self.assertNotIn('..', ' '.join(text))
        self.assertIn('Descriptive captions for a silent recording', vtt)
        with self.assertRaises(ValueError):
            S.captions(60)


if __name__ == '__main__':
    unittest.main()
