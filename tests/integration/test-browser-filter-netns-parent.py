#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-only
"""Inert runtime-parent checks; no namespace, mount, service or VM operations."""
from pathlib import Path
import stat
import subprocess
import tempfile
import unittest

HERE = Path(__file__).resolve().parent
SOURCE = (HERE / "kvm-alpha-topology.sh").read_text()
BEGIN = "# BEGIN browser-filter namespace-parent preflight\n"
END = "# END browser-filter namespace-parent preflight\n"
FRAGMENT = SOURCE.split(BEGIN, 1)[1].split(END, 1)[0]


class BrowserFilterNamespaceParent(unittest.TestCase):
    def run_fragment(self, path, enabled=True, owner="0:0"):
        # Only ownership is represented by an inert stub: the test account need
        # not be root. mkdir, permissions, links and canonical paths are real,
        # under this private temporary fixture, never /run/netns.
        script = ('set -eu\numask 077\nbrowser_filter_bundle=$1\nfixture_owner=$2\n'
                  'fail() { printf "%s\\n" "$1" >&2; exit 69; }\n'
                  'stat() { test "$1" = -Lc; test "$2" = "%u:%g:%a"; '
                  'printf "%s:%s\\n" "$fixture_owner" "$(command stat -Lc "%a" "$3")"; }\n'
                  + FRAGMENT.replace("/run/netns", str(path)))
        return subprocess.run(["/bin/sh", "-c", script, "fixture", "selected" if enabled else "", owner],
                              capture_output=True, timeout=5)

    def test_new_parent_is_searchable_despite_private_umask(self):
        with tempfile.TemporaryDirectory() as temporary:
            parent = Path(temporary).resolve() / "netns"
            result = self.run_fragment(parent)
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertEqual(stat.S_IMODE(parent.stat().st_mode), 0o755)
            self.assertEqual(list(parent.iterdir()), [])

    def test_safe_existing_parent_and_entries_are_unchanged(self):
        for mode in (0o755, 0o711):
            with self.subTest(mode=mode), tempfile.TemporaryDirectory() as temporary:
                parent = Path(temporary).resolve() / "netns"; parent.mkdir(); parent.chmod(mode)
                entry = parent / "pre-existing"; entry.write_bytes(b"untouched fixture")
                before = parent.stat()
                result = self.run_fragment(parent)
                after = parent.stat()
                self.assertEqual(result.returncode, 0, result.stderr)
                self.assertEqual((after.st_dev, after.st_ino, after.st_mode, after.st_mtime_ns),
                                 (before.st_dev, before.st_ino, before.st_mode, before.st_mtime_ns))
                self.assertEqual(entry.read_bytes(), b"untouched fixture")

    def test_private_writable_or_foreign_parent_is_rejected_without_chmod(self):
        for mode, owner in ((0o700, "0:0"), (0o775, "0:0"), (0o777, "0:0"), (0o755, "1000:1000")):
            with self.subTest(mode=mode, owner=owner), tempfile.TemporaryDirectory() as temporary:
                parent = Path(temporary).resolve() / "netns"; parent.mkdir(); parent.chmod(mode)
                before = parent.stat()
                result = self.run_fragment(parent, owner=owner)
                self.assertEqual(result.returncode, 69)
                self.assertIn(b"BROWSER_FILTER_NETNS_PARENT_UNSAFE", result.stderr)
                self.assertEqual(parent.stat().st_mode, before.st_mode)
                self.assertEqual(parent.stat().st_ino, before.st_ino)

    def test_symlink_and_regular_file_are_rejected_without_changes(self):
        for kind in ("symlink", "file"):
            with self.subTest(kind=kind), tempfile.TemporaryDirectory() as temporary:
                root = Path(temporary).resolve(); parent = root / "netns"
                if kind == "symlink":
                    target = root / "target"; target.mkdir(); target.chmod(0o700); parent.symlink_to(target)
                else: parent.write_bytes(b"untouched")
                before = parent.lstat()
                result = self.run_fragment(parent)
                self.assertEqual(result.returncode, 69)
                self.assertEqual(parent.lstat().st_mode, before.st_mode)
                self.assertEqual(parent.lstat().st_ino, before.st_ino)
                if kind == "symlink": self.assertEqual(stat.S_IMODE(target.stat().st_mode), 0o700)
                else: self.assertEqual(parent.read_bytes(), b"untouched")

    def test_without_explicit_browser_bundle_nothing_is_created(self):
        with tempfile.TemporaryDirectory() as temporary:
            parent = Path(temporary).resolve() / "netns"
            result = self.run_fragment(parent, enabled=False)
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertFalse(parent.exists())

    def test_preflight_is_after_disposable_guest_gates_and_before_namespace_creation(self):
        position = SOURCE.index(BEGIN)
        self.assertLess(SOURCE.index('[ "$(id -u)" -eq 0 ]'), position)
        self.assertLess(SOURCE.index('[ "$(systemd-detect-virt)" = kvm ]'), position)
        self.assertLess(position, SOURCE.index('ip netns add "$namespace"'))
        self.assertNotIn("chmod", FRAGMENT)


if __name__ == "__main__":
    unittest.main()
