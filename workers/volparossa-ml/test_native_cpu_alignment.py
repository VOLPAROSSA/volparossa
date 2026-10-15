# SPDX-License-Identifier: GPL-3.0-only
"""Inert source/provenance checks. No compiler, model, downloads or native load."""
import copy
import difflib
import hashlib
import json
from pathlib import Path
import stat
import tempfile
import unittest
from unittest import mock

import build_llama_cpu as builder
import llama_cpu as native


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def require(condition, code):
    if not condition:
        raise ValueError(code)


class AlignmentTests(unittest.TestCase):
    def test_patch_contains_only_the_aligned_copy(self):
        raw = (builder.HERE / "native-cpu/q1-aligned-load.patch").read_bytes()
        self.assertEqual(sha(raw), native.CPU_PATCH_SHA)
        lines = raw.decode().splitlines()
        self.assertEqual([line for line in lines if line.startswith('-') and not line.startswith('---')],
            ['-        const uint32_t * GGML_RESTRICT qs32 = (const uint32_t *) x[ib].qs;'])
        self.assertEqual([line for line in lines if line.startswith('+') and not line.startswith('+++')],
            ['+        uint32_t qs32[4];', '+        memcpy(qs32, x[ib].qs, sizeof(qs32));'])

    def test_historical_absence_is_not_patch_evidence(self):
        for version in (2, 3, 4):
            value = dict(version=version)
            native.validate_cpu_provenance(value, require)
            self.assertEqual(value, dict(version=version))
        native.validate_cpu_provenance(dict(version=4, cpu_source_overlay=native.cpu_provenance(),
                                           cpu_compile_source_verified=True), require)

    def test_provenance_is_an_atomic_exact_pair(self):
        good = dict(version=4, cpu_source_overlay=native.cpu_provenance(), cpu_compile_source_verified=True)
        invalid = [dict(version=4, cpu_source_overlay=native.cpu_provenance()),
                   dict(version=4, cpu_compile_source_verified=True)]
        for version in (2, 3, 5, True, '4'):
            invalid.append(dict(good, version=version))
        for verified in (False, 1, None, 'true'):
            invalid.append(dict(good, cpu_compile_source_verified=verified))
        for key in native.cpu_provenance():
            bad = copy.deepcopy(good)
            bad['cpu_source_overlay'][key] = 'unreviewed'
            invalid.append(bad)
            bad = copy.deepcopy(good)
            del bad['cpu_source_overlay'][key]
            invalid.append(bad)
        bad = copy.deepcopy(good)
        bad['cpu_source_overlay']['extra'] = True
        invalid.append(bad)
        for bad in invalid:
            with self.subTest(bad=bad), self.assertRaisesRegex(ValueError, 'NATIVE_CPU_PATCH_BINDING'):
                native.validate_cpu_provenance(bad, require)

    def test_exact_transformation_preserves_the_original_and_rejects_tampering(self):
        before = b'prefix\n        const uint32_t * GGML_RESTRICT qs32 = (const uint32_t *) x[ib].qs;\nsuffix\n'
        after = b'prefix\n        uint32_t qs32[4];\n        memcpy(qs32, x[ib].qs, sizeof(qs32));\nsuffix\n'
        patch = ''.join(difflib.unified_diff(before.decode().splitlines(True), after.decode().splitlines(True),
            fromfile='a/' + native.CPU_ORIGINAL_PATH, tofile='b/' + native.CPU_ORIGINAL_PATH)).encode()
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            source = root / 'source'
            original = source / native.CPU_ORIGINAL_PATH
            original.parent.mkdir(parents=True)
            original.write_bytes(before)
            patch_path = root / 'wrapper/native-cpu/q1-aligned-load.patch'
            patch_path.parent.mkdir(parents=True)
            patch_path.write_bytes(patch)
            with mock.patch.object(builder, 'HERE', root / 'wrapper'), \
                    mock.patch.object(native, 'CPU_ORIGINAL_SHA', sha(before)), \
                    mock.patch.object(native, 'CPU_EFFECTIVE_SHA', sha(after)), \
                    mock.patch.object(native, 'CPU_PATCH_SHA', sha(patch)):
                self.assertEqual(builder.patched_cpu(source), after)
                self.assertEqual(original.read_bytes(), before)
                original.write_bytes(before + b'changed')
                with self.assertRaisesRegex(ValueError, 'NATIVE_CPU_ORIGINAL'):
                    builder.patched_cpu(source)
                original.write_bytes(before)
                patch_path.write_bytes(patch + b'changed')
                with self.assertRaisesRegex(ValueError, 'NATIVE_CPU_PATCH'):
                    builder.patched_cpu(source)
                patch_path.write_bytes(patch)
                with mock.patch.object(native, 'CPU_EFFECTIVE_SHA', '0' * 64), \
                        self.assertRaisesRegex(ValueError, 'NATIVE_CPU_EFFECTIVE'):
                    builder.patched_cpu(source)

    def test_staging_is_fresh_read_only_and_never_replaces_source(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            with mock.patch.object(builder, 'patched_cpu', return_value=b'inert reviewed source'):
                staged = builder.stage_cpu(root / 'original', root)
                self.assertEqual(staged.read_bytes(), b'inert reviewed source')
                self.assertEqual(stat.S_IMODE(staged.stat().st_mode), 0o444)
                self.assertEqual(stat.S_IMODE(staged.parent.stat().st_mode), 0o700)
                with self.assertRaises(FileExistsError):
                    builder.stage_cpu(root / 'original', root)
                self.assertEqual(staged.read_bytes(), b'inert reviewed source')

    def test_compilation_binds_only_the_staged_x86_unit_and_cpu_target(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            source = root / 'original'
            output = root / 'output'
            staged = output / 'cpu-overlay/quants.c'
            staged.parent.mkdir(parents=True)
            staged.write_bytes(b'reviewed CPU source')
            database = output / 'build/compile_commands.json'
            database.parent.mkdir()
            row = dict(directory=str(database.parent), file=str(staged),
                       command='cc -o CMakeFiles/ggml-cpu.dir/cpu-overlay/quants.c.o -c ' + str(staged))
            generic = dict(directory=str(database.parent), file=str(source / 'ggml/src/ggml-cpu/quants.c'),
                           command='cc -o CMakeFiles/ggml-cpu.dir/generic.o -c generic.c')
            with mock.patch.object(native, 'CPU_EFFECTIVE_SHA', sha(staged.read_bytes())):
                database.write_text(json.dumps([row, generic]))
                builder.verify_cpu_compilation(output, source)
                relative = dict(row, command='cc -o CMakeFiles/ggml-cpu.dir/x.o -c ../cpu-overlay/quants.c')
                database.write_text(json.dumps([relative, generic]))
                builder.verify_cpu_compilation(output, source)
                bad_rows = [[], [generic], [row, row],
                    [row, dict(generic, file=str(source / native.CPU_ORIGINAL_PATH))],
                    [dict(row, command='cc -o CMakeFiles/other.dir/quants.c.o -c ignored')],
                    [dict(row, command='cc -c ignored')],
                    [dict(row, command='cc -o CMakeFiles/ggml-cpu.dir/x.o -c ' + str(source / native.CPU_ORIGINAL_PATH))],
                    [dict(row, command='cc -o CMakeFiles/ggml-cpu.dir/x.o -c different.c')],
                    [dict(row, command='cc -o CMakeFiles/ggml-cpu.dir/x.o')],
                    [dict(row, command='cc -o CMakeFiles/ggml-cpu.dir/x.o -c')],
                    [dict(row, command=row['command'] + ' -c ' + str(staged))]]
                for rows in bad_rows:
                    database.write_text(json.dumps(rows))
                    with self.subTest(rows=rows), self.assertRaisesRegex(ValueError, 'NATIVE_'):
                        builder.verify_cpu_compilation(output, source)
                database.write_text(json.dumps([row]))
                staged.write_bytes(b'changed')
                with self.assertRaisesRegex(ValueError, 'NATIVE_COMPILED_CPU'):
                    builder.verify_cpu_compilation(output, source)

    def test_cmake_preserves_other_units_and_uses_original_private_headers(self):
        text = (builder.HERE / 'native-cpu/CMakeLists.txt').read_text()
        self.assertIn('if(source STREQUAL "${VP_LLAMA_SOURCE}/ggml/src/ggml-cpu/arch/x86/quants.c")', text)
        self.assertIn('if(NOT cpu_replacements EQUAL 1)', text)
        self.assertIn('list(APPEND effective_cpu_sources "${source}")', text)
        self.assertIn('target_include_directories(ggml-cpu PRIVATE "${VP_LLAMA_SOURCE}/ggml/src/ggml-cpu/arch/x86")', text)
        self.assertIn('q1-aligned-load.patch', builder.WRAPPER_FILES)


if __name__ == '__main__':
    unittest.main()
