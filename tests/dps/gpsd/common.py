# SPDX-License-Identifier: GPL-3.0-only
"""Bounded utilities for the opt-in, disposable hosted GPSD proof."""
import hashlib
import json
import math
import os
from pathlib import Path
import re
import selectors
import signal
import stat
import subprocess
import time

ROOT = Path(__file__).resolve().parents[3]
PINS = ROOT / 'third_party/gpsd/pins.json'
PINS_SHA256 = '54267541c2952cf8f936563d7b266a3291dbf83080a2efde7be04313e170fdc8'
MAX_LOG = 32 * 1024 * 1024


class CommandFailure(ValueError):
    """An observed nonzero exit, distinct from bounds/observer failures."""


def digest(path, maximum=256 * 1024 * 1024):
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    with os.fdopen(fd, 'rb') as stream:
        before = os.fstat(stream.fileno())
        if not stat.S_ISREG(before.st_mode) or before.st_size > maximum:
            raise ValueError('bounded regular file required')
        value = hashlib.sha256()
        total = 0
        while chunk := stream.read(1024 * 1024):
            total += len(chunk)
            if total > maximum:
                raise ValueError('file exceeded its bound')
            value.update(chunk)
        after = os.fstat(stream.fileno())
        if (before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns,
                before.st_ctime_ns) != (after.st_dev, after.st_ino, after.st_size,
                                      after.st_mtime_ns, after.st_ctime_ns):
            raise ValueError('file changed while hashing')
        return value.hexdigest()


def strict_json(raw):
    def pairs(items):
        result = {}
        for key, value in items:
            if key in result:
                raise ValueError('duplicate JSON key')
            result[key] = value
        return result
    def nonfinite(_):
        raise ValueError('non-finite JSON number')
    def finite_float(raw_number):
        value = float(raw_number)
        if not math.isfinite(value):
            raise ValueError('overflowed JSON number')
        return value
    return json.loads(raw, object_pairs_hook=pairs, parse_constant=nonfinite, parse_float=finite_float)


def pins():
    if digest(PINS, 64 * 1024) != PINS_SHA256:
        raise ValueError('GPSD source authority changed')
    return strict_json(PINS.read_bytes())


def hosted():
    if (os.environ.get('GITHUB_ACTIONS') != 'true' or
            os.environ.get('RUNNER_ENVIRONMENT') != 'github-hosted' or
            os.environ.get('RUNNER_OS') != 'Linux' or
            os.environ.get('RUNNER_ARCH') != 'X64' or os.geteuid() == 0):
        raise ValueError('disposable nonroot hosted Linux amd64 required')


def private_directory(path, *, create=False):
    path = Path(path)
    temporary = Path(os.environ.get('RUNNER_TEMP', '/nonexistent'))
    if (not path.is_absolute() or not temporary.is_absolute() or
            temporary.resolve() != temporary or temporary not in path.parents or
            path.resolve() != path):
        raise ValueError('owned canonical RUNNER_TEMP child required')
    if create:
        path.mkdir(mode=0o700)
    info = path.lstat()
    if (not stat.S_ISDIR(info.st_mode) or info.st_uid != os.geteuid() or
            stat.S_IMODE(info.st_mode) != 0o700):
        raise ValueError('private directory ownership or mode differs')
    return path


def write_json(path, value):
    raw = (json.dumps(value, indent=2, sort_keys=True, allow_nan=False) + '\n').encode()
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    with os.fdopen(fd, 'wb') as stream:
        stream.write(raw)
        stream.flush()
        os.fsync(stream.fileno())


def source_binding(revision):
    if not re.fullmatch('[0-9a-f]{40}', revision):
        raise ValueError('exact reviewed source revision required')
    def git(*args):
        return subprocess.check_output(['/usr/bin/git', '-C', str(ROOT), *args],
                                       timeout=10, text=True).strip()
    if (revision != os.environ.get('GITHUB_SHA') or
            revision != os.environ.get('GITHUB_WORKFLOW_SHA') or git('rev-parse', 'HEAD') != revision or
            git('status', '--porcelain', '--untracked-files=all')):
        raise ValueError('source/workflow/head/clean binding differs')
    return {'commit': revision, 'tree': git('rev-parse', 'HEAD^{tree}'),
            'cargo_lock_sha256': digest(ROOT / 'Cargo.lock'),
            'upstream_lock_sha256': digest(ROOT / 'third_party/upstream.lock.json'),
            'gpsd_pins_sha256': PINS_SHA256}


def terminate(child):
    """Always reap the direct child and remove its remaining process group."""
    for sig, delay in ((signal.SIGTERM, 0.5), (signal.SIGKILL, 1.0)):
        try:
            os.killpg(child.pid, sig)
        except ProcessLookupError:
            pass
        try:
            child.wait(timeout=delay)
        except subprocess.TimeoutExpired:
            continue
        # A parent may exit before its owned descendants. Kill the group too.
        try:
            os.killpg(child.pid, signal.SIGKILL)
        except ProcessLookupError:
            pass
        return child.returncode
    child.wait(timeout=1)
    return child.returncode


def command(argv, *, cwd, env, deadline, log_path, limit=MAX_LOG, observer=None):
    """Capture both pipes concurrently, with a single monotonic time/byte bound."""
    if time.monotonic() >= deadline:
        raise TimeoutError('shared command budget exhausted')
    fd = os.open(log_path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    child = None
    chunks = bytearray()
    with os.fdopen(fd, 'wb') as log, selectors.DefaultSelector() as selector:
        try:
            child = subprocess.Popen(argv, cwd=cwd, env=env, stdin=subprocess.DEVNULL,
                                     stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                     start_new_session=True)
            for pipe in (child.stdout, child.stderr):
                os.set_blocking(pipe.fileno(), False)
                selector.register(pipe, selectors.EVENT_READ)
            while selector.get_map():
                if observer is not None:
                    observer(child)
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    raise TimeoutError('shared command deadline')
                for key, _ in selector.select(min(remaining, 0.1)):
                    chunk = os.read(key.fileobj.fileno(), 64 * 1024)
                    if not chunk:
                        selector.unregister(key.fileobj)
                        continue
                    if len(chunks) + len(chunk) > limit:
                        raise ValueError('command output bound exceeded')
                    chunks.extend(chunk)
                    log.write(chunk)
            result = child.wait(timeout=max(0.001, deadline - time.monotonic()))
            if result != 0:
                raise CommandFailure('command failed; original bounded log retained')
            return bytes(chunks)
        finally:
            if child is not None:
                terminate(child)
                child.stdout.close()
                child.stderr.close()


def clean_environment():
    return {'PATH': '/usr/bin:/bin', 'LANG': 'C.UTF-8', 'LC_ALL': 'C.UTF-8',
            'PYTHONNOUSERSITE': '1', 'PYTHONDONTWRITEBYTECODE': '1'}
