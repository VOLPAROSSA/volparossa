#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-only
"""Hosted-only GNU packaging proof using a public exit(0) toy ELF.

This exercises the actual fixed GNU strip boundary independently of a resident
model/VM trial. It proves neither the original runtime failure's cause nor full
resident runtime acceptance. Only the generated exit(0) toy is executed; no
VOLPAROSSA/model binary is run. Do not include it in local test discovery/runs.
"""
import hashlib
import importlib.util
import os
from pathlib import Path
import platform
import tempfile
import time
import unittest

HERE = Path(__file__).resolve().parent
SPEC = importlib.util.spec_from_file_location('resident_build', HERE / 'protected-resident-model-build.py')
M = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(M)


class HostedGnuBinaryPackageTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        if not (os.environ.get('GITHUB_ACTIONS') == 'true'
                and os.environ.get('RUNNER_ENVIRONMENT') == 'github-hosted'
                and platform.system() == 'Linux' and platform.machine() == 'x86_64'
                and os.getuid() != 0):
            raise RuntimeError('requires explicit unprivileged GitHub-hosted Linux amd64 execution')

    def test_real_debug_elf_becomes_boot_bounded_without_modifying_cargo_hardlinks(self):
        with tempfile.TemporaryDirectory(prefix='resident-gnu-package-') as directory:
            root = Path(directory)
            # Minimal public code plus a deliberately oversized debug section.
            # Only this fixed exit(0) toy is executed, before and after packaging.
            assembly = root / 'public.s'
            assembly.write_text('.text\n.global _start\n_start:\n'
                'mov $60, %rax\nxor %rdi, %rdi\nsyscall\n'
                '.section .debug_str,"MS",@progbits,1\n'
                '.ascii "PUBLIC_RESIDENT_DEBUG_MARKER"\n'
                '.zero 67108864\n.section .note.GNU-stack,"",@progbits\n')
            limit = time.monotonic_ns() + 120 * 1_000_000_000
            obj, source, alias, packaged = (root / name for name in ('public.o', 'cargo-deps', 'cargo-binary', 'exported'))
            M.command(['/usr/bin/x86_64-linux-gnu-as', '--64', '-g', '-o', obj, assembly], limit)
            M.command(['/usr/bin/x86_64-linux-gnu-ld', '-o', source, obj], limit)
            source.chmod(0o700)
            os.link(source, alias)
            before = M.identity(source.stat())
            def digest(path):
                value = hashlib.sha256()
                with path.open('rb') as stream:
                    while block := stream.read(1024 ** 2): value.update(block)
                return value.hexdigest()
            original_hash = digest(source)
            self.assertEqual(M.command([source], limit), b'')
            self.assertGreater(source.stat().st_size, M.MAX_BOOT_CORE_BYTES)
            self.assertLessEqual(source.stat().st_size, 256 * 1024 ** 2)
            M.package_core_binary(alias, packaged, limit)
            self.assertEqual(M.command([packaged], limit), b'')
            self.assertEqual(M.identity(source.stat()), before)
            self.assertEqual(M.identity(alias.stat()), before)
            self.assertEqual(digest(source), original_hash)
            self.assertEqual(packaged.stat().st_nlink, 1)
            self.assertEqual(packaged.stat().st_mode & 0o7777, 0o700)
            self.assertNotEqual(packaged.stat().st_ino, source.stat().st_ino)
            self.assertLessEqual(packaged.stat().st_size, M.MAX_BOOT_CORE_BYTES)
            self.assertNotIn(b'PUBLIC_RESIDENT_DEBUG_MARKER', packaged.read_bytes())
            record = M.file_record(packaged, limit)
            self.assertEqual(record['sha256'], digest(packaged))
            self.assertNotEqual(record['sha256'], original_hash)
            self.assertTrue(record['executable'])


if __name__ == '__main__':
    unittest.main()
