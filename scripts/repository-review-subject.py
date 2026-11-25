#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-only
"""Prepare the complete text of one enrolled public, single-file Git proposal for peer review."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import resource
import stat
import subprocess
import sys
import tempfile
import uuid


def require(ok, message):
    if not ok:
        raise ValueError(message)


def limit_git():
    # Bound object expansion while inspecting a small, explicitly enrolled public pack.
    resource.setrlimit(resource.RLIMIT_AS, (256 * 1024 ** 2,) * 2)
    resource.setrlimit(resource.RLIMIT_FSIZE, (16 * 1024 ** 2,) * 2)
    resource.setrlimit(resource.RLIMIT_CPU, (10, 10))


def git(directory, *args):
    env = {'PATH': '/usr/bin:/bin', 'LC_ALL': 'C', 'GIT_CONFIG_NOSYSTEM': '1', 'GIT_CONFIG_GLOBAL': '/dev/null',
           'GIT_NO_REPLACE_OBJECTS': '1', 'GIT_TERMINAL_PROMPT': '0', 'GIT_NO_LAZY_FETCH': '1'}
    return subprocess.run(['/usr/bin/git', '--literal-pathspecs', '-c', 'core.hooksPath=/dev/null',
        '-c', 'protocol.allow=never', *args], cwd=directory, env=env, stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=15, preexec_fn=limit_git, check=True).stdout


def subject(bundle, bundle_sha256, repository_id, base, candidate, path):
    require(uuid.UUID(repository_id).int and str(uuid.UUID(repository_id)) == repository_id, 'invalid enrolled repository ID')
    require(re.fullmatch('[0-9a-f]{40}', base) and re.fullmatch('[0-9a-f]{40}', candidate) and base != candidate,
            'expected two distinct SHA-1 commit pins')
    require(re.fullmatch(r'[A-Za-z0-9_./-]{1,128}', path) and
            all(p not in ('.', '..', '', '.git') for p in path.split('/')), 'invalid enrolled file path')
    fd = os.open(bundle, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    with os.fdopen(fd, 'rb') as source:
        require(stat.S_ISREG(os.fstat(fd).st_mode), 'public bundle must be a regular file')
        data = source.read(1024 * 1024 + 1)
    require(0 < len(data) <= 1024 * 1024 and hashlib.sha256(data).hexdigest() == bundle_sha256,
            'bundle differs from the enrolled public input')
    with tempfile.TemporaryDirectory(prefix='repository-review-') as temp:
        root = Path(temp)
        copy = root / 'input.bundle'
        copy.write_bytes(data)
        repo = root / 'objects'
        repo.mkdir()
        git(repo, 'init', '--bare', '--quiet', '--template=', '--object-format=sha1', '.')
        git(repo, 'bundle', 'verify', str(copy))
        git(repo, 'bundle', 'unbundle', str(copy))
        for revision in (base, candidate):
            require(git(repo, 'cat-file', '-t', revision) == b'commit\n', 'enrolled revision is not a commit')
        require(git(repo, 'rev-list', '--parents', '-n', '1', candidate).decode().split() == [candidate, base],
                'candidate must have exactly the enrolled base parent')
        git(repo, 'fsck', '--strict', '--no-reflogs', base, candidate)
        delta = git(repo, 'diff-tree', '--no-commit-id', '--raw', '-z', '--no-renames', '-r', base, candidate)
        match = re.fullmatch(rb':100644 100644 ([0-9a-f]{40}) ([0-9a-f]{40}) M\x00([^\x00]+)\x00', delta)
        require(match is not None and match[3] == path.encode(), 'expected one changed regular file at the enrolled path')
        contents = []
        for oid in match.groups()[:2]:
            blob = oid.decode()
            require(int(git(repo, 'cat-file', '-s', blob)) <= 512, 'file exceeds the whole-subject review budget')
            text = git(repo, 'cat-file', 'blob', blob).decode('utf-8')
            require(all(c.isprintable() or c in '\n\r\t' for c in text), 'file contains non-text characters')
            contents.append(text)
        patch = git(repo, 'diff', '--no-ext-diff', '--no-textconv', '--no-color', '--no-renames',
                    '--full-index', '--diff-algorithm=myers', '--no-indent-heuristic', base, candidate, '--', path)
    document = dict(kind='public-git-change-v1', repository=repository_id, base=base, candidate=candidate,
                    path=path, patch_sha256=hashlib.sha256(patch).hexdigest(), before=contents[0], after=contents[1])
    encoded = json.dumps(document, ensure_ascii=True, separators=(',', ':')).encode() + b'\n'
    require(len(encoded) <= 512, 'complete proposal exceeds the native assessment limit')
    return encoded


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--public-bundle', type=Path, required=True)
    for flag in ('bundle-sha256', 'repository-id', 'base', 'candidate', 'path'):
        parser.add_argument('--' + flag, required=True)
    args = parser.parse_args()
    sys.stdout.buffer.write(subject(args.public_bundle, args.bundle_sha256, args.repository_id,
                                   args.base, args.candidate, args.path))


if __name__ == '__main__':
    try:
        main()
    except (ValueError, OSError, subprocess.SubprocessError) as error:
        sys.exit(f'Cannot prepare the enrolled Git proposal ({type(error).__name__}): '
                 + (str(error) if isinstance(error, ValueError) else 'input or Git validation failed'))
