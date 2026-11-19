#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-only
"""Classify a one-commit PR containing one original Storage trial and its status entry."""
import hashlib
import io
import json
import os
import re
import subprocess
import sys
import zipfile

REPO = 'VOLPAROSSA/volparossa'
STATUS = 'docs/IMPLEMENTATION_STATUS.md'
BUNDLE = re.compile(r'docs/development/evidence/storage-maintenance-([1-9][0-9]{0,18})/([^/]+)\Z')
NAMES = {
    'private-storage-maintenance-smoke.json', 'private-storage-maintenance-helper-acquire.json',
    'private-storage-maintenance-route-diagnostic.json', 'private-storage-fixture-correlation.json',
    'private-storage-fragments-finish.json', 'storage-consumer-prepare.json', 'storage-consumer-publish.json',
    'storage-consumer-private-cleanup.json', 'storage-consumer-provider-usage.json',
}
MAX_ZIP = 8 * 1024 * 1024


class FullSuite(Exception):
    """The change or its source could not be positively classified."""


class InvalidReceipt(Exception):
    """An authenticated archive contradicts the proposed receipt."""


def git(*args):
    return subprocess.check_output(['git', '--no-replace-objects', *args], stderr=subprocess.DEVNULL)


def parents(revision):
    header = git('cat-file', 'commit', revision).split(b'\n\n', 1)[0]
    return [line[7:].decode('ascii') for line in header.splitlines() if line.startswith(b'parent ')]


def changes(base, candidate):
    fields = git('diff-tree', '-r', '--no-commit-id', '--raw', '--no-abbrev', '--no-renames',
                 '--no-ext-diff', '--no-textconv', '-z', base, candidate).split(b'\0')
    if len(fields) not in (19, 21) or fields[-1]:
        raise FullSuite
    files, runs = {}, set()
    for meta, name in zip(fields[:-1:2], fields[1::2], strict=True):
        before, after, _old_oid, new_oid, status = meta.decode('ascii').split()
        path = name.decode('utf-8')
        if path == STATUS and (before, after, status) == (':100644', '100644', 'M'):
            continue
        match = BUNDLE.fullmatch(path)
        if not match or (before, after, status) != (':000000', '100644', 'A'):
            raise FullSuite
        runs.add(match[1])
        files[match[2]] = new_oid
    if set(files) != NAMES or len(runs) != 1:
        raise FullSuite
    return runs.pop(), files


def selection(base, head, merge):
    if not all(re.fullmatch('[0-9a-f]{40}', sha) for sha in (base, head, merge)):
        raise FullSuite
    if git('rev-parse', 'HEAD').decode().strip() != merge or parents(merge) != [base, head]:
        raise FullSuite
    authored_base = parents(head)
    if len(authored_base) != 1:
        raise FullSuite
    authored = changes(authored_base[0], head)
    integrated = changes(base, merge)
    if authored != integrated:
        raise FullSuite
    return integrated


def status_entry(base, merge, run_id, revision, digest):
    if int(git('cat-file', '-s', f'{merge}:{STATUS}')) > 1024 * 1024:
        raise FullSuite
    patch = git('diff', '--no-ext-diff', '--no-textconv', '--unified=0', base, merge, '--', STATUS)
    if not patch:
        return
    lines = patch.decode('utf-8').splitlines()
    new = [line[1:] for line in lines if line.startswith('+') and not line.startswith('+++')]
    old = [line[1:] for line in lines if line.startswith('-') and not line.startswith('---')]
    if len(new) > 48 or (old and (len(old) != 1 or not old[0].startswith('| Storage / Image / Cloud |'))):
        raise FullSuite
    entry = '\n'.join(new)
    if not all(text in entry for text in (f'https://github.com/{REPO}/actions/runs/{run_id}',
                                          revision[:8], digest.removeprefix('sha256:'))):
        raise FullSuite


def api(path, limit):
    # gh follows the authenticated artifact redirect. Its stderr may contain a signed URL.
    data = subprocess.check_output(['gh', 'api', f'repos/{REPO}/{path}'],
                                   stderr=subprocess.DEVNULL, timeout=40)
    if len(data) > limit:
        raise FullSuite
    return data


def check_archive(run_id, revision, files, artifact, archive):
    if len(archive) != artifact['size_in_bytes'] or artifact['digest'] != 'sha256:' + hashlib.sha256(archive).hexdigest():
        raise FullSuite
    with zipfile.ZipFile(io.BytesIO(archive)) as original:
        names = original.namelist()
        if len(names) > 4096 or len(set(names)) != len(names):
            raise FullSuite
        for name, oid in files.items():
            if name not in names:
                raise InvalidReceipt
            item = original.getinfo(name)
            if not 0 < item.file_size <= 1024 * 1024:
                raise FullSuite
            data = original.read(item)
            if int(git('cat-file', '-s', oid)) != len(data) or git('cat-file', 'blob', oid) != data:
                raise InvalidReceipt
            receipt = json.loads(data)
            if not isinstance(receipt, dict):
                raise FullSuite
            if name == 'private-storage-maintenance-smoke.json':
                if (receipt.get('report_kind') != 'volparossa-private-storage-maintenance'
                        or receipt.get('source_revision') != revision or type(receipt.get('success')) is not bool):
                    raise FullSuite
    print(f'Validated {len(files)} original Storage receipts from run {run_id} at {revision}.', file=sys.stderr)


def classify(event, merge):
    pr = event['pull_request']
    if (event['repository']['full_name'] != REPO or pr['base']['repo']['full_name'] != REPO
            or pr['base']['ref'] != 'main' or pr['commits'] != 1 or pr['changed_files'] not in (9, 10)):
        raise FullSuite
    run_id, files = selection(pr['base']['sha'], pr['head']['sha'], merge)
    run = json.loads(api(f'actions/runs/{run_id}', 256 * 1024))
    revision = run['head_sha']
    if not (str(run['id']) == run_id and run['repository']['full_name'] == REPO
            and run['head_repository']['full_name'] == REPO and run['path'] == '.github/workflows/alpha-topology.yml'
            and run['event'] == 'workflow_dispatch' and run['status'] == 'completed'
            and run['conclusion'] in ('success', 'failure') and re.fullmatch('[0-9a-f]{40}', revision)):
        raise FullSuite
    response = json.loads(api(f'actions/runs/{run_id}/artifacts?per_page=100', 512 * 1024))
    matches = [a for a in response['artifacts'] if a['name'] == f'alpha-production-helper-topology-{run_id}']
    if response['total_count'] != len(response['artifacts']) or len(matches) != 1:
        raise FullSuite
    artifact = matches[0]
    if (artifact['expired'] or not 0 < artifact['size_in_bytes'] <= MAX_ZIP or type(artifact['id']) is not int
            or not re.fullmatch(r'sha256:[0-9a-f]{64}', artifact['digest'])):
        raise FullSuite
    status_entry(pr['base']['sha'], merge, run_id, revision, artifact['digest'])
    check_archive(run_id, revision, files, artifact, api(f'actions/artifacts/{artifact["id"]}/zip', MAX_ZIP))
    return 'verified'


def main():
    try:
        with open(os.environ['GITHUB_EVENT_PATH'], encoding='utf-8') as source:
            return classify(json.load(source), os.environ['GITHUB_SHA'])
    except InvalidReceipt:
        print('Proposed receipt differs from the original Actions artifact.', file=sys.stderr)
        return 'invalid'
    except (FullSuite, KeyError, OSError, ValueError, TypeError, zipfile.BadZipFile, subprocess.SubprocessError):
        return 'full'


if __name__ == '__main__':
    print(main())
