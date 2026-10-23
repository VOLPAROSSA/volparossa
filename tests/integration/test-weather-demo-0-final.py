#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-only
"""Inert editorial-contract checks; no native tools, network, app or Core."""
import importlib.util
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch

sys.dont_write_bytecode = True
ROOT = Path(__file__).resolve().parents[2]
spec = importlib.util.spec_from_file_location('weather_final', ROOT / 'scripts/weather-demo-0-final.py')
F = importlib.util.module_from_spec(spec)
spec.loader.exec_module(F)


class FinalPresentation(unittest.TestCase):
    def test_edit_preserves_normal_speed_and_declared_cut(self):
        self.assertAlmostEqual(F.DURATION, 60.578911)
        for item in F.EDIT_MAP[:3]:
            self.assertEqual(item['speed'], 1)
            self.assertAlmostEqual(item['output_end']-item['output_start'], item['source_end']-item['source_start'])
        self.assertEqual(F.EDIT_MAP[2]['source_start']-F.EDIT_MAP[1]['source_end'], 13)
        self.assertEqual(F.EDIT_MAP[2]['output_start'], 15)
        self.assertEqual(F.EDIT_MAP[0]['kind'], 'replayed-preview')
        self.assertEqual(F.EDIT_MAP[-1]['output_end']-F.EDIT_MAP[-1]['output_start'], 5)
        for source in (28.536533, 29.068, 30.551, 31.266356, 45.391, 45.965578, 58.799733, 65.39):
            self.assertTrue(15 <= source-10 < F.MOVING_DURATION)

    def test_captions_bounds_and_readability(self):
        previous = 0
        for start, end, lines in F.CUES:
            self.assertGreaterEqual(start, previous)
            self.assertLessEqual(end, F.DURATION)
            self.assertGreater(end, start)
            self.assertLessEqual(len(lines), 2)
            self.assertTrue(all(len(line) <= 48 for line in lines))
            self.assertLessEqual(sum(map(len, lines))/(end-start), 20)
            previous = end
        self.assertEqual(previous, F.DURATION)
        vtt, transcript = F.captions()
        self.assertTrue(vtt.startswith('WEBVTT\n'))
        for term in ('13 seconds', 'not a measured latency', '39998753810 failed',
                     '40017379373 passed', 'No visible second-refresh completion', 'Silent'):
            self.assertIn(term, transcript)

    def test_guard_reuse_and_inert_preview(self):
        with tempfile.TemporaryDirectory(prefix='inert-final-') as directory:
            root = Path(directory)
            output = root / '.cache/new-final'
            with patch.object(F, 'ROOT', root), patch.dict(F.REVIEW,
                    hosted=lambda: self.fail('hosted called'), api=lambda _: self.fail('API called')):
                result = F.prepare(output)
                self.assertFalse(result['execute'])
                self.assertFalse(output.exists())
                for path in (Path('relative'), root / 'outside', root / '.cache/../outside'):
                    with self.assertRaises(ValueError):
                        F.prepare(path)
            with patch.object(F, 'ROOT', root), patch.dict(F.REVIEW,
                    hosted=lambda: (_ for _ in ()).throw(ValueError('host rejected')),
                    api=lambda _: self.fail('API called')):
                with self.assertRaises(ValueError):
                    F.prepare(output, execute=True)
            self.assertFalse(output.exists())
            output.mkdir(parents=True)
            with patch.object(F, 'ROOT', root), self.assertRaises(ValueError):
                F.prepare(output)

    def test_source_and_preserved_video_identities(self):
        self.assertEqual(F.SHORT['RAW_SHA'], 'bca54a8f677238f26daff6921bb3af0c661e1b39d0aada5ce3f161fda380d5c8')
        self.assertEqual(F.SHORT['ARTIFACT']['id'], 12529072030)
        self.assertEqual(F.SHORT['TECHNICAL_SHA'], 'e4f72aa6d8236c56ef9d638d5f40563d7865b5411b6d3e7510dd43cee42c4d40')
        self.assertEqual(F.OLD_SHORT_SHA, 'b1a95bbddcdb249759483749756d6c4d3ee6ba8a8cc21204742b40c18d15d725')

    def test_labels_and_app_pane_are_separate(self):
        with tempfile.TemporaryDirectory(prefix='inert-final-layout-') as directory:
            root = Path(directory)
            graph = F.video_graph(root)
            self.assertIn('pad=1280:1440:32:120', graph)
            self.assertNotIn('minterpolate', graph)
            self.assertNotIn('setpts=0.', graph)
            text = '\n'.join(path.read_text() for path in root.rglob('*.txt'))
            for label in ('Recorded preview — excerpt', '— loading abbreviated', 'CUT: 13 seconds omitted',
                          'EXTERNAL Debian Core', 'Core runs externally to Android'):
                self.assertIn(label, text)
            graph = F.thumbnail_graph(root)
            self.assertIn('scale=450:800', graph)
            text = '\n'.join(path.read_text() for path in (root/'thumbnail-text').glob('*.txt'))
            self.assertIn('Conceptual topology', text)
            self.assertIn('Technical demo — external Core', text)

    def test_decode_and_pts_reject_bad_cadence(self):
        import json
        calls = []
        times = [i/30 for i in range(1818)]
        def command(args, **kwargs):
            calls.append((args, kwargs))
            if 'ffprobe' in args[0]:
                return json.dumps({'frames':[{'best_effort_timestamp_time':str(t)} for t in times]}).encode()
            return b''
        with patch.dict(F.REVIEW, command=command):
            result = F.verify_video(Path('/inert/video.mp4'), dict(duration_seconds=60.6))
            self.assertEqual(result['decoded_frames'],1818)
            self.assertTrue(all(options['reject_stderr'] for _, options in calls))
            times[10] += 0.01
            with self.assertRaises(ValueError):
                F.verify_video(Path('/inert/video.mp4'), dict(duration_seconds=60.6))


if __name__ == '__main__':
    unittest.main()
