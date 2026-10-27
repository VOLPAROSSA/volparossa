#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-only
"""Inert SSH guest boundary regression against the actual Cargo source policy."""
from pathlib import Path
import re
import runpy
import subprocess
import unittest

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[1]
RUNNER = HERE / 'run-helper-boundary-evidence-vm.sh'
POLICY = ROOT / 'scripts/cargo-source-policy.py'
P = runpy.run_path(str(POLICY))


def guest_script(marker):
    found = re.findall(r"cat >\"\$guest_[a-z]+\" <<'" + marker + r"'\n(.*?)\n" + marker + r'\n',
                       RUNNER.read_text(), re.S)
    if len(found) != 1:
        raise AssertionError((marker, len(found)))
    return found[0]


class GuestSourceEnvironment(unittest.TestCase):
    def test_transport_metadata_alone_reproduces_original_policy_rejection(self):
        # OpenSSH supplies these variables even for RequestTTY=no. Their
        # presence alone reaches the original unchanged environment guard.
        for name in ('SSH_CLIENT', 'SSH_CONNECTION'):
            with self.subTest(name=name), self.assertRaises(P['PolicyError']) as error:
                P['check_environment']({'HOME': '/home/volparossa', name: 'transport-metadata'})
            self.assertEqual(str(error.exception), 'CARGO_PUBLIC_SOURCE_POLICY_V1=environment')

    def run_guest_prefix(self, marker, extra):
        # Execute the exact script prefix, stopping before source/provisioning,
        # network, apt or compiler execution. Only run the actual policy guard.
        prefix = guest_script(marker).split('expected_commit=$1', 1)[0]
        code = '''import os,runpy,sys
policy=runpy.run_path(sys.argv[1])
try:
    policy['check_environment'](os.environ)
except policy['PolicyError']:
    sys.exit(7)
if 'SSH_CLIENT' in os.environ or 'SSH_CONNECTION' in os.environ:
    sys.exit(8)
'''
        env = {'HOME': '/home/volparossa', 'PATH': '/usr/bin:/bin',
               'SSH_CLIENT': '192.0.2.1 12345 22',
               'SSH_CONNECTION': '192.0.2.1 12345 192.0.2.2 22', **extra}
        return subprocess.run(['sh', '-eu', '-c', prefix + '\nexec python3 -B -c "$1" "$2"',
                               'fixture', code, str(POLICY)], env=env, text=True,
                              capture_output=True, timeout=10)

    def test_both_real_guest_prefixes_remove_only_expected_transport_metadata(self):
        for marker in ('GUEST_SETUP', 'GUEST_PROOF'):
            with self.subTest(marker=marker):
                result = self.run_guest_prefix(marker, {})
                self.assertEqual(result.returncode, 0, result.stderr)
                self.assertEqual(result.stdout + result.stderr, '')

    def test_unexpected_ssh_credentials_tty_and_git_indirection_still_rejected(self):
        for marker in ('GUEST_SETUP', 'GUEST_PROOF'):
            for name in ('SSH_AUTH_SOCK', 'SSH_ASKPASS', 'SSH_TTY', 'SSH_UNKNOWN',
                         'GIT_CONFIG_COUNT', 'GIT_CONFIG_KEY_0', 'GIT_SSH_COMMAND'):
                with self.subTest(marker=marker, variable=name):
                    result = self.run_guest_prefix(marker, {name: 'untrusted-fixture-value'})
                    self.assertEqual(result.returncode, 7, result.stderr)
                    self.assertEqual(result.stdout + result.stderr, '')

    def test_cleanup_is_literal_and_precedes_each_first_policy_entry(self):
        for marker, command in (
            ('GUEST_SETUP', 'python3 -B scripts/provision-rust189.py guest\n'),
            ('GUEST_PROOF', 'python3 -B scripts/provision-rust189.py guest-check\n')):
            source = guest_script(marker)
            unsets = re.findall(r'^unset (.*)$', source, re.M)
            self.assertEqual(unsets, ['SSH_CLIENT SSH_CONNECTION'])
            self.assertEqual(source.count(command), 1)
            self.assertLess(source.index('unset SSH_CLIENT SSH_CONNECTION\n'), source.index(command))
            self.assertNotIn('env -i', source)
        ssh = re.search(r'^guest_ssh_raw\(\) \{\n.*?^\}\n', RUNNER.read_text(), re.M | re.S)[0]
        self.assertIn('-o RequestTTY=no', ssh)
        self.assertIn('-o ForwardAgent=no', ssh)
        contract = (HERE / 'test-live-worker-identity-contract.sh').read_text()
        for name in ('test-helper-preflight-diagnostic.py',
                     'test-helper-worker-observation-diagnostic.py',
                     'test-helper-guest-source-environment.py'):
            self.assertEqual(contract.count('python3 -B \"$script_directory/' + name + '\"'), 1)


if __name__ == '__main__':
    unittest.main()
