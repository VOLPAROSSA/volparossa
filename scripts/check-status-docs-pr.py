#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-only
"""Check links and structure in a PR that only edits existing Core status pages."""
from collections import Counter
import functools
import posixpath
import re
import subprocess
import sys
from urllib.parse import unquote, urlsplit

INDEX = 'docs/IMPLEMENTATION_STATUS.md'
PAGES = {INDEX, *(f'docs/status/{topic}.md' for topic in ('applications', 'network', 'storage'))}
INLINE = re.compile(r'\[([^\[\]\n]*)\]\(([^()\s<>]+)\)')
EXPLICIT = re.compile(r'<a id="([\w-]+)"></a>')
MAX_DOC = 1024 * 1024


class FullSuite(Exception):
    """The change or Markdown syntax is outside this narrowly supported route."""


class InvalidDocument(Exception):
    """The supported status document contains a broken link or lost anchor."""


def git(*args):
    return subprocess.check_output(['git', '--no-replace-objects', *args], stderr=subprocess.DEVNULL)


def changed(base, target):
    fields = git('diff-tree', '-r', '--no-commit-id', '--raw', '--no-abbrev', '--no-renames',
                 '--no-ext-diff', '--no-textconv', '-z', base, target).split(b'\0')
    if not 3 <= len(fields) <= 2 * len(PAGES) + 1 or fields[-1]:
        raise FullSuite
    pages = {}
    for metadata, raw_path in zip(fields[:-1:2], fields[1::2], strict=True):
        before, after, old, new, kind = metadata.decode('ascii').split()
        path = raw_path.decode('utf-8')
        if path not in PAGES or (before, after, kind) != (':100644', '100644', 'M'):
            raise FullSuite
        pages[path] = (old, new)
    return pages


@functools.lru_cache(maxsize=128)
def document(oid):
    if int(git('cat-file', '-s', oid)) > MAX_DOC:
        raise FullSuite
    return git('cat-file', 'blob', oid).decode('utf-8')


def anchors(text):
    if '<!--' in text or '-->' in text:
        raise FullSuite
    found = set()
    for heading in re.findall(r'^#{1,6} +(.+?)\s*$', text, re.MULTILINE):
        if '[' in heading or ']' in heading:
            raise FullSuite
        slug = re.sub(r'[^\w -]', '', heading.lower()).replace(' ', '-')
        fragment = slug
        i = 1
        while fragment in found:
            fragment = f'{slug}-{i}'
            i += 1
        found.add(fragment)
    return found | set(EXPLICIT.findall(text))


def verify_page(path, before, after, tree):
    original, updated = document(before), document(after)
    title = re.compile(r'^# +(.+)$', re.MULTILINE)
    previous_title = title.findall(original)
    if len(previous_title) != 1 or title.findall(updated) != previous_title:
        raise InvalidDocument(f'{path}: preserve the status page title')
    previous_ids = Counter(EXPLICIT.findall(original))
    if any(count > max(1, previous_ids[i]) for i, count in Counter(EXPLICIT.findall(updated)).items()):
        raise InvalidDocument(f'{path}: duplicate explicit anchor')
    if not anchors(original) <= anchors(updated):
        raise InvalidDocument(f'{path}: preserve previously addressable sections')
    if path == INDEX:
        def workstreams(text):
            lines = iter(text.splitlines())
            header = next((line for line in lines if line.startswith('| Workstream |')), '')
            rows = []
            for line in lines:
                if not line.startswith('|'):
                    break
                rows.append([cell.strip() for cell in line.split('|')])
            if (not header or len(rows) < 2 or rows[0] != ['', '---', '---', '']
                    or any(len(row) != 4 or not row[1] or not row[2] for row in rows)):
                raise InvalidDocument(f'{path}: invalid workstream table')
            return {row[1] for row in rows[1:]}
        if not workstreams(original) <= workstreams(updated):
            raise FullSuite
    # Check the inline-link notation used by these pages. Other Markdown forms
    # require the ordinary suite and review rather than a partial link check.
    markup = re.sub(r'`[^`\n]+`', '', updated)
    remainder = INLINE.sub('', markup)
    if ('](' in remainder or re.search(r'\]\s*\[|^ {0,3}\[[^\]]+\]:|^ {0,3}(?:```|~~~)', remainder, re.MULTILINE)
            or re.search(r'<[/!?a-zA-Z][^>\n]*>', EXPLICIT.sub('', remainder))):
        raise FullSuite
    for match in INLINE.finditer(markup):
        url = urlsplit(match[2])
        if url.scheme == 'https' and url.hostname:
            continue
        if url.scheme or url.netloc or url.query or '\\' in match[2]:
            raise FullSuite
        name = unquote(url.path)
        if name.startswith('/'):
            raise FullSuite
        name = posixpath.normpath(posixpath.join(posixpath.dirname(path), name)) if name else path
        if name not in tree:
            raise InvalidDocument(f'{path}: missing local target {name}')
        mode, oid = tree[name]
        if mode not in ('100644', '100755', '040000'):
            raise FullSuite
        if url.fragment:
            if mode != '100644' or not name.endswith('.md'):
                raise FullSuite
            if unquote(url.fragment) not in anchors(document(oid)):
                raise InvalidDocument(f'{path}: missing anchor in {name}#{url.fragment}')


def classify(base, head, merge):
    if not all(re.fullmatch(r'[0-9a-f]{40}', sha) for sha in (base, head, merge)):
        raise FullSuite
    if (git('rev-parse', 'HEAD').decode().strip() != merge
            or git('show', '-s', '--format=%P', merge).decode().split() != [base, head]):
        raise FullSuite
    # The workflow selects a single-commit PR. Its parent is available in the
    # depth-three checkout even if protected main advanced since the branch forked.
    parents = git('show', '-s', '--format=%P', head).decode().split()
    if len(parents) != 1:
        raise FullSuite
    authored = changed(parents[0], head)
    integrated = changed(base, merge)
    if authored.keys() != integrated.keys():
        raise FullSuite
    for revision, pages in ((head, authored), (merge, integrated)):
        tree = {}
        for record in git('ls-tree', '-r', '-t', '-z', revision).split(b'\0')[:-1]:
            meta, path = record.split(b'\t', 1)
            mode, _, oid = meta.decode('ascii').split()
            tree[path.decode('utf-8')] = (mode, oid)
        for path, (before, after) in pages.items():
            verify_page(path, before, after, tree)
    print(f'Checked links, anchors and page structure for {len(integrated)} status document(s).', file=sys.stderr)
    return 'status'


def main():
    try:
        return classify(*sys.argv[1:])
    except InvalidDocument as error:
        print(error, file=sys.stderr)
        return 'invalid'
    except (FullSuite, ValueError, TypeError, OSError, subprocess.SubprocessError):
        return 'full'


if __name__ == '__main__':
    print(main())
