#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-only
"""Validate status PR routing with genuine Git objects and the existing required gate."""
import contextlib
import importlib.util
import subprocess
import tempfile
import unittest
from pathlib import Path

HERE = Path(__file__).resolve().parent
spec = importlib.util.spec_from_file_location('status_docs', HERE / 'check-status-docs-pr.py')
check = importlib.util.module_from_spec(spec)
spec.loader.exec_module(check)


def git(*args):
    return subprocess.check_output(['git', *args], stderr=subprocess.DEVNULL, text=True).strip()


class StatusDocs(unittest.TestCase):
    def setUp(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.enterContext(contextlib.chdir(tmp.name))
        git('init', '-q', '-b', 'main')
        git('config', 'user.name', 'Test')
        git('config', 'user.email', 'test@example.invalid')
        self.path = Path('docs/status/network.md')
        self.path.parent.mkdir(parents=True)
        self.path.write_text('# Network trial records\n\n## Network baseline\n')
        self.index = Path(check.INDEX)
        self.index.write_text('# Status\n\n| Workstream | Checkpoint |\n| --- | --- |\n| Network | Ready |\n')
        self.base = self.commit()
        self.source = self.path.read_text()

    def commit(self):
        git('add', '-A')
        git('commit', '-qm', 'fixture')
        return git('rev-parse', 'HEAD')

    def merge(self, head=None):
        head = head or self.commit()
        tree = git('write-tree')
        merge = git('commit-tree', tree, '-p', self.base, '-p', head, '-m', 'merge')
        git('checkout', '--detach', '-q', merge)
        return self.base, head, merge

    def test_existing_page_checks_local_file_and_section(self):
        self.path.write_text(self.source + '[Index](../IMPLEMENTATION_STATUS.md#status)\n')
        self.assertEqual(check.classify(*self.merge()), 'status')

    def test_missing_local_target_or_anchor_is_invalid(self):
        for link in ('missing.md', '../IMPLEMENTATION_STATUS.md#missing'):
            with self.subTest(link=link):
                git('checkout', '-q', self.base)
                self.path.write_text(self.source + f'[Trial]({link})\n')
                with self.assertRaises(check.InvalidDocument):
                    check.classify(*self.merge())

    def test_removing_preexisting_section_breaks_incoming_links(self):
        self.path.write_text('# Network trial records\n\n## Unrelated\n')
        with self.assertRaises(check.InvalidDocument):
            check.classify(*self.merge())

    def test_replacing_an_existing_page_with_a_symlink_is_ineligible(self):
        self.path.unlink()
        self.path.symlink_to('../IMPLEMENTATION_STATUS.md')
        with self.assertRaises(check.FullSuite):
            check.classify(*self.merge())

    def test_altered_workstream_roster_requires_full_suite(self):
        self.index.write_text(self.index.read_text().replace('| Network |', '| Other |'))
        with self.assertRaises(check.FullSuite):
            check.classify(*self.merge())

    def test_new_page_and_other_inputs_cannot_use_document_route(self):
        for path in ('docs/status/storage.md', 'docs/receipt.csv', 'src.rs', '.github/workflows/ci.yml'):
            with self.subTest(path=path):
                git('checkout', '-q', self.base)
                self.path.write_text(self.source + 'Update\n')
                other = Path(path)
                other.parent.mkdir(parents=True, exist_ok=True)
                other.write_text('changed\n')
                with self.assertRaises(check.FullSuite):
                    check.classify(*self.merge())

    def test_code_hidden_by_merge_is_still_ineligible(self):
        Path('build.rs').write_text('fn main() {}')
        self.path.write_text(self.source + 'Update\n')
        head = self.commit()
        git('rm', '-q', 'build.rs')
        with self.assertRaises(check.FullSuite):
            check.classify(*self.merge(head))

    def test_commenting_out_a_heading_falls_back_to_the_full_suite(self):
        self.path.write_text('# Network trial records\n\n<!--\n## Network baseline\n-->\n')
        with self.assertRaises(check.FullSuite):
            check.classify(*self.merge())

    def test_link_in_a_heading_uses_the_full_suite(self):
        self.path.write_text(self.source + '## [Index](../IMPLEMENTATION_STATUS.md)\n')
        with self.assertRaises(check.FullSuite):
            check.classify(*self.merge())

    def test_unknown_markup_falls_back_to_ordinary_suite(self):
        self.path.write_text(self.source + '[trial][source]\n[source]: missing.md\n')
        with self.assertRaises(check.FullSuite):
            check.classify(*self.merge())


if __name__ == '__main__':
    unittest.main()
