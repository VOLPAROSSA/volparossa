#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-only
"""Exercise private Image custody boundaries with inert files and a fixed mock guest."""

import hashlib
import json
import os
from pathlib import Path
import re
import subprocess
import tempfile
import unittest

HERE = Path(__file__).resolve().parent
RUNNER = HERE / 'run-alpha-topology-vm.sh'
SOURCE = RUNNER.read_text()
PIN = '0da0c35e9372a828553f376c3eb404a6081e0bb8'
CIPHER = b'private fixture ciphertext\0' * 100
DIGEST = hashlib.sha256(CIPHER).hexdigest()
RECEIPT = json.dumps(dict(version=1, kind='volparossa-immich-snapshot', cipher_file='snapshot.pgp',
    cipher_bytes=len(CIPHER), cipher_sha256=DIGEST, encryption='OpenPGP-AES256',
    source_consistency='operator-asserted-quiesced-copy')).encode()


def function(name):
    return re.search(r'^' + name + r'\(\) \{\n.*?^\}', SOURCE, re.MULTILINE | re.DOTALL).group()


def block(start, end):
    return start + SOURCE.split(start, 1)[1].split(end, 1)[0]


def run(script, env):
    return subprocess.run(['sh', '-eu', '-c', script], env=dict(os.environ, LC_ALL='C', **env),
                          capture_output=True, timeout=5)


class ImagePeerVmHandoff(unittest.TestCase):
    def fixtures(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        base = Path(temporary.name)
        env = dict(HERE=str(HERE), image_handoff=str(base / 'input'), image_stage=str(base / 'stage'),
                   guest=str(base / 'guest'), image_return=str(base / 'return'), RUN_DIRECTORY=str(base),
                   image_revision=PIN, scenario='image-snapshot', output_directory=str(base / 'diagnostics'),
                   image_handoff_sha256=DIGEST, image_handoff_bytes=str(len(CIPHER)), GUEST_STATUS='0',
                   image_receipt_sha256=hashlib.sha256(RECEIPT).hexdigest())
        for key in ('image_handoff', 'image_stage', 'guest', 'image_return', 'output_directory'):
            path = Path(env[key])
            path.mkdir(mode=0o700)
            if key in ('image_handoff', 'image_stage'):
                for name, data in (('receipt.json', RECEIPT), ('snapshot.pgp', CIPHER)):
                    (path / name).write_bytes(data)
                    (path / name).chmod(0o600)
        return env

    def test_separate_private_directories_are_required(self):
        admission = block('if [ -n "$image_handoff$image_return$image_revision" ]; then\n',
                          'if [ -n "$studio_handoff$studio_evidence_sha256" ]; then')
        for mutation in ('valid', 'alias', 'nested', 'symlink', 'nonprivate', 'not_empty', 'wrong_revision', 'wrong_scenario'):
            with self.subTest(mutation=mutation):
                env = self.fixtures()
                target = Path(env['image_return'])
                if mutation == 'alias': env['image_return'] = env['output_directory']
                if mutation == 'nested':
                    nested = Path(env['output_directory']) / 'returned'
                    nested.mkdir(mode=0o700)
                    env['image_return'] = str(nested)
                if mutation == 'symlink':
                    link = target.with_name('linked')
                    link.symlink_to(target)
                    env['image_return'] = str(link)
                if mutation == 'nonprivate': target.chmod(0o755)
                if mutation == 'not_empty': (target / '.hidden').touch()
                if mutation == 'wrong_revision': env['image_revision'] = 'a' * 40
                if mutation == 'wrong_scenario': env['scenario'] = 'content-repair'
                result = run(admission, env)
                self.assertEqual(result.returncode, 0 if mutation == 'valid' else 64, result.stderr)

    def test_verified_guest_transfer_precedes_removal_of_exact_host_sources(self):
        start = 'if [ -n "$image_handoff" ]; then\n    ssh_base mkdir'
        transfer = block(start, 'if [ -n "${studio_handoff:-}" ]; then')
        script = '\n'.join([function('image_input_identity'), function('release_image_source'), '''
image_original_identity=$(image_input_identity "$image_handoff")
image_stage_identity=$(image_input_identity "$image_stage")
scp_to() { cp -- "$1" "$guest/${2##*/}"; }
ssh_bounded() {
    [ "$*" = '30s python3 -I -B - verify /home/vpci/image-peer-handoff' ] || return 1
    case $mutation in
        guest_extra) touch "$guest/extra" ;;
        guest_symlink)
            mv -- "$guest/snapshot.pgp" "$RUN_DIRECTORY/redirected"
            ln -s -- "$RUN_DIRECTORY/redirected" "$guest/snapshot.pgp" ;;
    esac
    python3 -I -B - verify "$guest"
}
ssh_base() {
    case $1 in
        mkdir|chmod) ;;
        sha256sum)
            digest=$(sha256sum <"$guest/${2##*/}" | cut -d ' ' -f1)
            if [ "$mutation" = corrupt_guest ]; then digest=bad; fi
            if [ "${2##*/}" = receipt.json ]; then
                case $mutation in
                    extra) touch "$image_handoff/extra" ;;
                    symlink)
                        mv -- "$image_handoff/snapshot.pgp" "$RUN_DIRECTORY/original"
                        ln -s -- "$RUN_DIRECTORY/original" "$image_handoff/snapshot.pgp" ;;
                    replaced)
                        cp -p -- "$image_handoff/snapshot.pgp" "$image_handoff/replacement"
                        mv -T -- "$image_handoff/replacement" "$image_handoff/snapshot.pgp" ;;
                esac
            fi
            printf '%s  %s\\n' "$digest" "$2" ;;
        *) return 1 ;;
    esac
}
''', transfer])
        for mutation in ('none', 'corrupt_guest', 'guest_extra', 'guest_symlink', 'extra', 'symlink', 'replaced'):
            with self.subTest(mutation=mutation):
                env = self.fixtures()
                result = run(script, dict(env, mutation=mutation))
                self.assertEqual(result.returncode == 0, mutation == 'none', result.stderr)
                self.assertNotIn(CIPHER, result.stdout + result.stderr)
                original = Path(env['image_handoff'])
                self.assertEqual((original / 'receipt.json').read_bytes(), RECEIPT)
                self.assertEqual((original / 'snapshot.pgp').exists(), mutation != 'none')
                if mutation == 'none':
                    self.assertEqual(set(Path(env['image_stage']).iterdir()), {Path(env['image_stage']) / 'receipt.json'})
                elif mutation in ('corrupt_guest', 'guest_extra', 'guest_symlink'):
                    self.assertTrue((Path(env['image_stage']) / 'snapshot.pgp').exists())
                self.assertEqual((Path(env['guest']) / 'snapshot.pgp').read_bytes(), CIPHER)

    def test_only_exact_successful_return_published_outside_diagnostics(self):
        start = 'if [ -n "${image_handoff:-}" ] && [ "$GUEST_STATUS" -eq 0 ]; then\n'
        retrieve = block(start, 'if [ "$weather_client_version" = 6 ]')
        publish = start + SOURCE.rsplit(start, 1)[1].split('FINISHED=yes', 1)[0]
        self.assertLess(SOURCE.rindex('stop_qemu_child normal'), SOURCE.rindex(start))
        self.assertLess(SOURCE.index('release_image_source "$image_handoff"'), SOURCE.index('GUEST_STATUS=$?'))
        self.assertIn('sudo -n rmdir -- "$image_private"', SOURCE)
        for mutation in ('valid', 'wrong_hash', 'guest_failed', 'occupied'):
            with self.subTest(mutation=mutation):
                env = self.fixtures()
                source = Path(env['guest']) / 'snapshot.pgp'
                source.write_bytes(CIPHER if mutation != 'wrong_hash' else bytes(len(CIPHER)))
                returned = Path(env['image_return']) / 'snapshot.pgp'
                if mutation == 'occupied': returned.write_bytes(b'old')
                if mutation == 'guest_failed': env['GUEST_STATUS'] = '1'
                script = '''scp_from_bounded() {
    [ "$1:$2" = '60s:/home/vpci/image-peer-return/snapshot.pgp' ] || return 1
    cp -- "$guest/snapshot.pgp" "$3"
}
''' + retrieve + publish
                result = run(script, env)
                self.assertNotIn(CIPHER, result.stdout + result.stderr)
                self.assertEqual(result.returncode == 0, mutation in ('valid', 'guest_failed'), result.stderr)
                self.assertEqual(list(Path(env['output_directory']).iterdir()), [])
                if mutation == 'valid':
                    self.assertEqual(returned.read_bytes(), CIPHER)
                    self.assertEqual(returned.stat().st_mode & 0o777, 0o600)
                    self.assertEqual(returned.stat().st_nlink, 1)
                elif mutation == 'occupied':
                    self.assertEqual(returned.read_bytes(), b'old')
                else:
                    self.assertFalse(returned.exists())


if __name__ == '__main__':
    unittest.main()
