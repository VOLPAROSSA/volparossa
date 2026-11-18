#!/usr/bin/env python3
"""Inert legacy-export and source-wiring checks; no Rust, model or cache syscall."""
import json
import os
from pathlib import Path
import runpy
import tempfile
import unittest

HERE = Path(__file__).resolve().parent
ROOT = HERE.parent.parent
LEGACY = runpy.run_path(str(HERE / 'agent-private-conversation.py'))
MARKER = b'private_source_weight_cache_diagnostic '


class SourceWeightCacheContract(unittest.TestCase):
    def collect(self, raw, enabled):
        with tempfile.TemporaryDirectory(prefix='source-cache-contract-') as temporary:
            path = Path(temporary) / 'service.log'
            with path.open('xb') as stream:
                stream.write(raw)
            os.chmod(path, 0o600)
            return LEGACY['service_diagnostic'](path, memory_enabled=enabled)

    def test_historical_export_versions_ignore_separate_source_marker_exactly(self):
        event = dict(version=1, phase='task', detail=dict(code='compute_model_memory_headroom',
            io_kind='none', exit_code=None, signal=None, stderr_class=None))
        original = b'private_execution_diagnostic ' + json.dumps(event).encode() + b'\n'
        # Even an unknown future payload cannot contaminate the historical fields.
        extra = MARKER + b'{"version":1,"phase":"source_weights","PRIVATE_CANARY":true}\n'
        for enabled in (False, True):
            with self.subTest(memory_enabled=enabled):
                expected = self.collect(original, enabled)
                self.assertEqual(self.collect(original + extra, enabled), expected)
                self.assertEqual(expected['version'], 2 if enabled else 1)
                self.assertFalse(expected['unrecognized_record'])
                self.assertNotIn('PRIVATE_CANARY', json.dumps(expected))

    def test_observation_target_and_marker_are_separate_from_old_export(self):
        source = (ROOT / 'crates/volparossa/src/compute/native_cpu/source_weight_cache.rs').read_text()
        self.assertIn('volparossa::compute::private_source_weight_cache_diagnostic', source)
        self.assertIn(MARKER.decode() + '{record}', source)
        self.assertNotIn('private_memory_diagnostic ', source)
        self.assertNotIn('private_execution_diagnostic ', source)

    def test_existing_gguf_call_remains_before_new_advice_under_same_lease(self):
        source = (ROOT / 'crates/volparossa/src/compute.rs').read_text()
        order = [source.index(fragment) for fragment in (
            'let _lease = runtime_lease', 'resources::admission(options.model_profile',
            'let source_weight_cache = ', 'let child = sandbox::command(options)',
            'let result = supervise::run(child',
            'cache_hint.after_supervisor(&result, options.model_profile, memory_diagnostic);',
            'source_weight_cache.after_supervisor(&result, memory_diagnostic);')]
        self.assertEqual(order, sorted(order))
        self.assertIn('source_weight_cache.after_supervisor(&result, memory_diagnostic);\n    result\n}', source)


if __name__ == '__main__':
    unittest.main()
