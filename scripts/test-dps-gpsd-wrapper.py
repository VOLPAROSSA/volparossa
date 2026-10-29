#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-only
"""Hosted argument guards only: never sudo, namespaces, network, or product code."""
import os
import json
from pathlib import Path
import runpy
import subprocess
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
RAW = (ROOT / 'scripts/run-isolated-test.sh').read_text()


class WrapperGuards(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        (self.root / 'scripts').mkdir()
        (self.root / 'tests/dps/gpsd').mkdir(parents=True)
        (self.root / 'tests/dps/gpsd/prove.py').write_text('# inert guard fixture\n')
        (self.root / 'target/debug').mkdir(parents=True)
        self.core = self.root / 'target/debug/volparossa'
        self.core.write_text('#!/bin/sh\nexit 99\n')
        self.core.chmod(0o700)
        self.evidence = self.root / 'dps-gpsd-evidence'
        self.evidence.mkdir(mode=0o700)
        self.receipt = self.evidence / 'build-receipt.json'
        self.receipt.write_text('{}\n')
        # End before checking/executing any isolation tool. The entire actual
        # argument parser is preserved; only its terminal action is replaced.
        prefix, tail = RAW.split('for test_tool in ', 1)
        self.assertIn('/usr/bin/unshare', tail)
        self.wrapper = self.root / 'scripts/run-isolated-test.sh'
        self.wrapper.write_text(prefix + "printf 'GUARDS_ACCEPTED\\n'\n")
        self.env = dict(PATH='/usr/bin:/bin', GITHUB_ACTIONS='true',
                        RUNNER_ENVIRONMENT='github-hosted', RUNNER_OS='Linux', RUNNER_ARCH='X64',
                        RUNNER_TEMP=str(self.root), VOLPAROSSA_TEST_ALLOW_SUDO_NETNS='1',
                        GITHUB_SHA='a' * 40, GITHUB_WORKFLOW_SHA='a' * 40)

    def run_guard(self, *args, env=None):
        return subprocess.run(['/bin/sh', str(self.wrapper), *map(str, args)],
                              env=self.env if env is None else env,
                              text=True, capture_output=True, timeout=3)

    def arguments(self):
        return ['--dps-gpsd-command', self.core, self.evidence, self.receipt]

    def rejected(self, args=None, env=None):
        result = self.run_guard(*(self.arguments() if args is None else args), env=env)
        self.assertNotEqual(result.returncode, 0)
        self.assertNotIn('GUARDS_ACCEPTED', result.stdout)
        self.assertIn('isolated-test:', result.stderr)

    def test_exact_arguments_accept_before_any_namespace_tool(self):
        result = self.run_guard(*self.arguments())
        self.assertEqual((result.returncode, result.stdout, result.stderr), (0, 'GUARDS_ACCEPTED\n', ''))

    def test_wrong_actor_platform_optin_and_source_are_rejected(self):
        for name in ('GITHUB_ACTIONS', 'RUNNER_ENVIRONMENT', 'RUNNER_OS', 'RUNNER_ARCH',
                     'VOLPAROSSA_TEST_ALLOW_SUDO_NETNS', 'GITHUB_SHA', 'GITHUB_WORKFLOW_SHA'):
            with self.subTest(name=name):
                env = dict(self.env)
                env[name] = 'unapproved'
                self.rejected(env=env)

    def test_wrong_argument_count_and_binary_are_rejected(self):
        self.rejected(self.arguments()[:-1])
        self.rejected([*self.arguments(), 'extra'])
        args = self.arguments()
        args[1] = '/usr/bin/true'
        self.rejected(args)
        self.core.unlink()
        self.core.symlink_to('/usr/bin/true')
        self.rejected()

    def test_evidence_escape_and_symlink_are_rejected(self):
        for candidate in (self.root / 'other', self.evidence / '../dps-gpsd-evidence'):
            with self.subTest(candidate=str(candidate)):
                args = self.arguments()
                args[2] = candidate
                self.rejected(args)
        self.receipt.unlink()
        self.evidence.rmdir()
        self.evidence.symlink_to(self.root, target_is_directory=True)
        self.rejected()

    def test_receipt_override_and_symlink_are_rejected(self):
        args = self.arguments()
        args[3] = self.evidence / 'other.json'
        self.rejected(args)
        self.receipt.unlink()
        self.receipt.symlink_to(self.core)
        self.rejected()

    def test_marker_cannot_use_ordinary_backend(self):
        self.rejected(['--command', '/usr/bin/python3', 'dps_gpsd',
                       'VOLPAROSSA_DPS_GPSD_PARENT_NETNS', 'loopback'])

    def test_privileged_route_clears_environment_and_preserves_fixed_contract(self):
        branch = RAW.split('if [ "$test_backend" = dps-gpsd ]; then')[-1].split('\nfi\n', 1)[0]
        self.assertIn('/usr/bin/env -i PATH=/usr/bin:/bin LANG=C.UTF-8', branch)
        for name in ('GITHUB_ACTIONS', 'RUNNER_ENVIRONMENT', 'RUNNER_OS', 'RUNNER_ARCH',
                     'RUNNER_TEMP', 'GITHUB_SHA', 'GITHUB_WORKFLOW_SHA'):
            self.assertIn(name + '=', branch)
        self.assertIn('--net --ipc --pid --mount --mount-proc --fork --kill-child=KILL', branch)
        self.assertIn('600s /usr/bin/sudo -n --', branch)
        self.assertNotIn('sudo -E', RAW)

    def test_firewall_equivalence_excludes_only_counter_values(self):
        configuration = runpy.run_path(str(ROOT / 'scripts/dps-gpsd-host-state.py'))['firewall_configuration']
        def encoded(packets, port):
            return json.dumps({'nftables': [{'rule': {'expr': [
                {'counter': {'packets': packets, 'bytes': packets * 100}},
                {'match': {'right': port}}], 'handle': 3}}]}).encode()
        self.assertEqual(configuration(encoded(1, 443)), configuration(encoded(99, 443)))
        self.assertNotEqual(configuration(encoded(1, 443)), configuration(encoded(1, 80)))
        self.assertNotEqual(configuration(encoded(1, 443)), configuration(b'{"nftables":[]}'))


if __name__ == '__main__':
    if (os.environ.get('GITHUB_ACTIONS') != 'true' or
            os.environ.get('RUNNER_ENVIRONMENT') != 'github-hosted'):
        raise SystemExit('Hosted guard tests required; no local execution')
    unittest.main()
