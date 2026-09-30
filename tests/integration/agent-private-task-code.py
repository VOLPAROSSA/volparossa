#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-only
"""Pinned Node client variant of the existing disposable private-model proof."""

import hashlib
import io
import json
import os
from pathlib import Path, PurePosixPath
import re
import shutil
import signal
import stat
import subprocess
import sys
import tarfile
import tempfile
import time
import urllib.request

HERE = Path(__file__).resolve().parent
ROOT = Path('/home/vpci/private-code')
NAME = 'agent-private-code'
PINS = HERE / 'agent-private-task-code-pins.json'
REVISION = 'd5802a024d665a47b42abdbe809bea2b9ee86bd8'
NODE = 'node-v24.19.0-linux-x64'
SCOPE = ('v1 pinned VOLPAROSSA Code Node PrivateCompute -> real private-serve -> pinned 360M; '
         'one synthetic-code EOS answer, existing core cancel/disconnect and owner/isolation checks, '
         'cleanup observed after client completion; not a Codex app-server, editor, tool-calling, '
         'general coding-quality or confidential remote-compute proof')
NONCLAIMS = dict(codex_agent_proven=False, editor_proven=False, tool_calling_proven=False,
                general_coding_quality_proven=False, confidential_remote_execution_proven=False)
FAILURE_CODES = frozenset(('busy', 'invalid_request', 'handshake_required', 'no_such_task',
    'cancelled', 'execution_failed', 'cleanup_unconfirmed', 'socket_ownership', 'socket_changed',
    'socket_unavailable', 'incompatible_capabilities', 'invalid_response', 'invalid_text',
    'response_bound', 'socket_error', 'disconnected', 'frame_timeout', 'handshake_timeout', 'probe_failed'))


def require(value):
    if not value:
        raise ValueError('private code proof binding failed')


def digest(path):
    with path.open('rb') as stream:
        return hashlib.file_digest(stream, 'sha256').hexdigest()


def load_pins():
    value = json.loads(PINS.read_text())
    require(value['version'] == 1 and value['revision'] == REVISION
            and value['repository'] == 'https://github.com/VOLPAROSSA/volparossa-code'
            and set(value['files']) == {'src/private-compute.cjs', 'LICENSE'})
    runtime = value['runtime']
    require(runtime['version'] == '24.19.0' and runtime['bytes'] == 31633904
            and runtime['url'] == f'https://nodejs.org/dist/v24.19.0/{NODE}.tar.xz'
            and runtime['sha256'] == '14b342e71204f811bde6153be8e04b62aef63c236fef92b55f9c83154b409647'
            and set(runtime['files']) == {'bin/node', 'LICENSE'})
    for record in [*value['files'].values(), *runtime['files'].values()]:
        require(set(record) == {'bytes', 'sha256'} and type(record['bytes']) is int
                and 0 < record['bytes'] <= 160 * 1024**2 and re.fullmatch('[0-9a-f]{64}', record['sha256']))
    return value


def fetch(url, target, record):
    target.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    deadline = time.monotonic() + 180
    with urllib.request.urlopen(url, timeout=30) as response, target.open('xb') as output:
        require(response.geturl() == url)
        total, hashed = 0, hashlib.sha256()
        while block := response.read(min(65536, record['bytes'] + 1 - total)):
            total += len(block)
            require(total <= record['bytes'] and time.monotonic() < deadline)
            hashed.update(block)
            output.write(block)
        require(total == record['bytes'] and hashed.hexdigest() == record['sha256'])
    target.chmod(0o600)


def extract_runtime(archive, destination, expected):
    """Only two verified regular entries; never extract archive paths or links."""
    seen, selected, expanded = set(), set(), 0
    for member in archive:
        name = member.name.rstrip('/') if member.isdir() else member.name
        path = PurePosixPath(name)
        require(name and not path.is_absolute() and '..' not in path.parts
                and str(path) == name and path.parts[0] == NODE and '\\' not in name
                and not any(ord(char) < 32 for char in name) and name not in seen)
        seen.add(name)
        expanded += member.size
        require(len(seen) <= 20000 and 0 <= member.size and expanded <= 512 * 1024**2)
        relative = str(path.relative_to(NODE))
        if relative not in expected:
            continue
        record = expected[relative]
        require(member.isfile() and not member.mode & 0o6000 and member.size == record['bytes'])
        target = destination / relative
        target.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
        hashed = hashlib.sha256()
        with archive.extractfile(member) as source, target.open('xb') as output:
            while block := source.read(65536):
                hashed.update(block)
                output.write(block)
        require(target.stat().st_size == record['bytes'] and hashed.hexdigest() == record['sha256'])
        target.chmod(0o700 if relative == 'bin/node' else 0o600)
        selected.add(relative)
    require(selected == set(expected))


def check_client(value, pins):
    require(type(value) is dict and set(value) == {'version', 'runtime_version', 'network_isolated',
        'private_client_used', 'result_received', 'source_was_synthetic'}
        and value == dict(version=1, runtime_version='v' + pins['runtime']['version'],
            network_isolated=True, private_client_used=True, result_received=True, source_was_synthetic=True))


def check_report(value, revision, core):
    pins = load_pins()
    require(value['report_kind'] == 'volparossa-agent-private-code' and value['proof_version'] == 1
            and value['source_revision'] == revision and value['scope'] == SCOPE and value['success'] is True
            and value['full_b04_claimed'] is False and value['confidential_remote_execution_claimed'] is False
            and value['raw_private_input_exported'] is False and value['raw_worker_report_exported'] is False
            and value['raw_model_answer_exported'] is False and 'answer' not in value
            and value['code_scope'] == NONCLAIMS and value['code_provision'] == pins
            and value['code_inputs_unchanged'] is True
            and value['code_manifest_sha256'] == digest(PINS)
            and value['code_driver_sha256'] == digest(HERE / 'agent-private-task-code.cjs'))
    check_client(value['code_client'], pins)
    answer = value['code_answer']
    require(type(answer) is dict and set(answer) == {'eos', 'canary_present', 'generated_tokens',
            'text_truncated', 'cleanup_confirmed', 'model_answer_correctness_proven'}
            and answer['eos'] is True and answer['canary_present'] is True
            and type(answer['generated_tokens']) is int and 1 <= answer['generated_tokens'] <= 256
            and answer['text_truncated'] is False and answer['cleanup_confirmed'] is True
            and answer['model_answer_correctness_proven'] is False)
    require(value['code_cleanup'] == dict(complete=True, remaining_owned_objects=0,
        guest_code_root_removed=True, observed_process_lifetimes_ended=True,
        process_group_joined=True, fallback_signals_used=False))
    core['check_report_common'](value, 'code_completion')


def check_bundle(path, revision, core):
    value = core['read'](path, 1048576)
    check_report(value, revision, core)
    for field in ('provision', 'isolation', 'snapshot', 'owner_controls', 'result_boundary', 'private_service'):
        require(core['read'](path.parent / f'agent-private-task-{field}.json') == value[field])
    for field in ('provision', 'client', 'answer'):
        require(core['read'](path.parent / f'{NAME}-{field}.json') == value[f'code_{field}'])
    for when in ('before', 'after'):
        require(digest(path.parent / f'host-state-{when}.json') == value['host_state'][f'{when}_sha256'])


class CodeFixture:
    def __init__(self, core):
        self.core, self.process, self.members, self.fallback = core, None, {}, False
        self.pins = load_pins()
        core['TRAIN']['guest_guard']()
        require(not ROOT.exists() and not ROOT.is_symlink())

    def provision(self, output, result):
        ROOT.mkdir(mode=0o700)
        require(shutil.disk_usage(ROOT).free >= 512 * 1024**2)
        result['phase'] = 'private-code-source-fetch'
        for name, record in self.pins['files'].items():
            fetch(f'https://raw.githubusercontent.com/VOLPAROSSA/volparossa-code/{REVISION}/{name}', ROOT / name, record)
        result['phase'] = 'private-code-runtime-fetch'
        archive = ROOT / 'node.tar.xz'
        fetch(self.pins['runtime']['url'], archive, self.pins['runtime'])
        with tarfile.open(archive, 'r:xz') as source:
            extract_runtime(source, ROOT / 'runtime', self.pins['runtime']['files'])
        result.update(code_provision=self.pins, code_manifest_sha256=digest(PINS),
                      code_driver_sha256=digest(HERE / 'agent-private-task-code.cjs'))
        self.core['write'](output / f'{NAME}-provision.json', self.pins)

    def track(self):
        if self.process is not None and self.process.poll() is None:
            for member in self.core['TRAIN']['descendants'](self.process.pid):
                self.members[(member['pid'], member['start_ticks'])] = member
                require(len(self.members) <= 32)

    def verify_inputs(self):
        for base, entries in ((ROOT, self.pins['files']), (ROOT / 'runtime', self.pins['runtime']['files'])):
            for name, record in entries.items():
                target = base / name
                info = target.lstat()
                require(stat.S_ISREG(info.st_mode) and info.st_uid == os.getuid() and info.st_nlink == 1
                        and info.st_size == record['bytes'] and digest(target) == record['sha256'])

    def infer(self, output, socket_path, original, observed, result):
        result['phase'] = 'private-code-submit'
        self.verify_inputs()
        command = ['/usr/bin/bwrap', '--unshare-net', '--die-with-parent', '--ro-bind', '/', '/',
            '--bind', str(ROOT), str(ROOT), '--proc', '/proc', '--dev', '/dev', '--tmpfs', '/tmp',
            '--clearenv', '--setenv', 'PATH', '/usr/bin:/bin', '--setenv', 'LANG', 'C.UTF-8',
            '--chdir', str(ROOT), '--', str(ROOT / 'runtime/bin/node'),
            str(HERE / 'agent-private-task-code.cjs'), str(ROOT), str(socket_path), str(original),
            os.readlink('/proc/self/ns/net')]
        with (ROOT / 'runner.log').open('xb') as log:
            self.process = subprocess.Popen(command, stdout=log, stderr=subprocess.STDOUT, start_new_session=True)
            deadline = time.monotonic() + 15
            while not (ROOT / 'submitted.json').exists():
                self.track()
                require(self.process.poll() is None and time.monotonic() < deadline)
                time.sleep(0.05)
            require(self.core['read'](ROOT / 'submitted.json', 4096) ==
                    dict(version=1, event='client_submit_called'))
            self.core['check_capabilities'](self.core['read'](ROOT / 'capabilities.json', 4096))
            result['isolation'], result['snapshot'] = observed(output, 'inference')
            result['phase'] = 'private-code-model-result'
            deadline = time.monotonic() + 650
            while self.process.poll() is None:
                self.track()
                require(time.monotonic() < deadline)
                time.sleep(0.1)
            require(self.process.returncode == 0)
        require((ROOT / 'runner.log').stat().st_size == 0)
        self.verify_inputs()
        result['code_inputs_unchanged'] = True
        answer = self.core['read'](ROOT / 'answer.json', 65536)
        self.core['check_answer'](answer, result['test_canary'])
        result['code_client'] = self.core['read'](ROOT / 'client.json', 4096)
        check_client(result['code_client'], self.pins)
        result['code_answer'] = dict(eos=True, canary_present=True,
            generated_tokens=answer['output']['generated_tokens'], text_truncated=False,
            cleanup_confirmed=True, model_answer_correctness_proven=False)
        for field in ('client', 'answer'):
            self.core['write'](output / f'{NAME}-{field}.json', result[f'code_{field}'])

    def diagnostic(self):
        value = dict(process_exit_code=None if self.process is None else self.process.poll(), failure_state='absent')
        # Fixed booleans help diagnose a launcher failure without exporting its paths/log.
        try:
            with (ROOT / 'runner.log').open('rb') as stream:
                raw = stream.read(16385)
            value['launcher_log_bounded'] = len(raw) <= 16384
            value['launcher_signals'] = {name: signature in raw for name, signature in (
                ('bwrap_message', b'bwrap:'), ('permission_denied', b'Permission denied'),
                ('operation_denied', b'Operation not permitted'), ('missing_file', b'No such file or directory'),
                ('missing_library', b'error while loading shared libraries'))}
        except OSError:
            value['launcher_log_bounded'] = None
        try:
            failure = self.core['read'](ROOT / 'failure.json', 4096)
            require(type(failure) is dict and set(failure) == {'version', 'phase', 'code'}
                    and failure['version'] == 1 and failure['phase'] in ('guard', 'connect', 'submit', 'result')
                    and failure['code'] in FAILURE_CODES)
            value.update(failure_state='valid', failure=failure)
        except FileNotFoundError:
            pass
        except (OSError, ValueError, TypeError, KeyError):
            value['failure_state'] = 'invalid'
        return value

    def group_absent(self):
        if self.process is None:
            return True
        try:
            os.killpg(self.process.pid, 0)
        except ProcessLookupError:
            return True
        return False

    def cleanup(self):
        self.track()
        alive = self.core['TRAIN']['alive']
        if self.process is not None:
            for sig in (signal.SIGTERM, signal.SIGKILL):
                current = [member for member in self.members.values() if alive(member)]
                if not current:
                    break
                self.fallback = True
                # Only this newly created session, never a reused unrelated PID.
                for member in reversed(current):
                    if alive(member):
                        try:
                            os.kill(member['pid'], sig)
                        except ProcessLookupError:
                            pass
                try:
                    self.process.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    pass
        deadline = time.monotonic() + 2
        while (not self.group_absent() or any(alive(member) for member in self.members.values())) and time.monotonic() < deadline:
            time.sleep(0.05)
        joined = self.group_absent()
        remaining = sum(alive(member) for member in self.members.values()) + int(not joined)
        if remaining == 0 and ROOT.exists():
            info = ROOT.lstat()
            require(stat.S_ISDIR(info.st_mode) and info.st_uid == os.getuid() and stat.S_IMODE(info.st_mode) == 0o700)
            shutil.rmtree(ROOT)
        count = remaining + int(ROOT.exists())
        return dict(complete=count == 0, remaining_owned_objects=count, guest_code_root_removed=not ROOT.exists(),
                    observed_process_lifetimes_ended=remaining == 0, process_group_joined=joined,
                    fallback_signals_used=self.fallback)


def self_test():
    pins = load_pins()
    value = dict(version=1, runtime_version='v24.19.0', network_isolated=True,
        private_client_used=True, result_received=True, source_was_synthetic=True)
    check_client(value, pins)
    for key, replacement in (('network_isolated', False), ('source_was_synthetic', False),
                             ('private_source', 'CANARY-PRIVATE'), ('runtime_version', 'v0.0.0')):
        invalid = dict(value, **{key: replacement})
        try:
            check_client(invalid, pins)
        except ValueError:
            pass
        else:
            raise AssertionError('invalid client proof accepted')
    # Tiny fake archives only test extraction boundaries, never inference/runtime provenance.
    for bad in (None, 'traversal', 'symlink', 'duplicate', 'wrong-hash'):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            raw = io.BytesIO()
            content = b'inert archive fixture'
            expected = {'bin/node': dict(bytes=len(content), sha256=hashlib.sha256(content).hexdigest())}
            if bad == 'wrong-hash':
                expected['bin/node']['sha256'] = '0' * 64
            with tarfile.open(fileobj=raw, mode='w') as archive:
                item = tarfile.TarInfo(f'{NODE}/bin/node' if bad != 'traversal' else f'{NODE}/../outside')
                item.size = len(content)
                if bad == 'symlink':
                    item.type, item.linkname, item.size = tarfile.SYMTYPE, '/outside', 0
                archive.addfile(item, io.BytesIO(content))
                if bad == 'duplicate':
                    archive.addfile(item, io.BytesIO(content))
            raw.seek(0)
            try:
                with tarfile.open(fileobj=raw, mode='r:') as archive:
                    extract_runtime(archive, root / 'out', expected)
            except ValueError:
                require(bad is not None)
            else:
                require(bad is None)
    print('private-code pinned source/runtime and proof/parser controls PASS; no model executed')


if __name__ == '__main__':
    require(sys.argv[1:] == ['self-test'])
    self_test()
