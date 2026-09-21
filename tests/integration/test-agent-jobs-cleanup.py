#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-only
"""Inert shell cleanup checks: never call the host systemd or modify a real cgroup."""

import os
from pathlib import Path
import subprocess
import tempfile
import unittest


SCRIPT = Path(__file__).with_name("agent-jobs-smoke.sh").resolve()


class BrokerCleanup(unittest.TestCase):
    def test_only_inactive_pidless_empty_owned_units_are_retired(self):
        command = r'''
set -eu
. "$1"
systemctl() {
    case "$*" in
        "show --property=LoadState --value $unit")
            if [ "${stop_attempted:-no}" = yes ]; then
                printf '%s\n' "$after_stop_load"; return "$after_stop_query_status"
            fi
            printf '%s\n' "$load"; return "$query_status" ;;
        "show --property=ActiveState --value $unit") printf '%s\n' "$active" ;;
        "show --property=MainPID --value $unit") printf '%s\n' "$pid" ;;
        "stop $unit") stop_attempted=yes; printf '%s\n' stop; return "$stop_status" ;;
        "reset-failed $unit") return 0 ;;
        *) return 90 ;;
    esac
}
agent_jobs_cgroup_empty() {
    test "$1" = "/sys/fs/cgroup/system.slice/$unit" || return 91
    printf '%s\n' cgroup_checked
    return "$cgroup_status"
}
agent_jobs_stop_unit "$unit"
'''
        defaults = dict(unit="volparossa-alpha-compute@relay4.service", load="loaded",
                        active="inactive", pid="0", query_status="0", stop_status="0", cgroup_status="0",
                        after_stop_load="loaded", after_stop_query_status="0")
        cases = [({}, True, True), ({"load": "not-found"}, True, False),
                 ({"active": "failed"}, True, True),
                 ({"unit": "sshd.service"}, False, False),
                 ({"unit": "volparossa-alpha-compute@relay0.service"}, False, False),
                 ({"load": "error"}, False, False), ({"query_status": "1"}, False, False),
                 ({"stop_status": "1"}, False, True), ({"active": "active"}, False, True),
                 ({"stop_status": "1", "after_stop_load": "not-found"}, True, True),
                 ({"stop_status": "1", "after_stop_load": "not-found", "active": "active"}, False, True),
                 ({"stop_status": "1", "after_stop_load": "not-found", "pid": "123"}, False, True),
                 ({"stop_status": "1", "after_stop_load": "not-found", "cgroup_status": "1"}, False, True),
                 ({"stop_status": "1", "after_stop_load": "not-found", "after_stop_query_status": "1"}, False, True),
                 ({"pid": "123"}, False, True), ({"load": "not-found", "pid": "123"}, False, False),
                 ({"cgroup_status": "1"}, False, True),
                 ({"load": "not-found", "cgroup_status": "1"}, False, False)]
        for changes, success, stopped in cases:
            with self.subTest(changes=changes):
                env = dict(os.environ, **(defaults | changes))
                result = subprocess.run(["sh", "-c", command, "cleanup-test", str(SCRIPT)],
                                        env=env, capture_output=True, text=True, timeout=10)
                self.assertEqual(result.returncode == 0, success, result.stderr)
                self.assertEqual("stop" in result.stdout.splitlines(), stopped)
                if success:
                    self.assertIn("cgroup_checked", result.stdout)

    def test_cgroup_requires_absence_or_no_descendants(self):
        with tempfile.TemporaryDirectory(prefix="volparossa-cgroup-test-") as directory:
            root = Path(directory)
            empty, populated, unknown = (root / name for name in ("empty", "populated", "unknown"))
            for path in (empty, populated, unknown):
                path.mkdir()
            (empty / "cgroup.events").write_text("populated 0\nfrozen 0\n")
            (populated / "cgroup.events").write_text("populated 1\nfrozen 0\n")
            (populated / "cgroup.procs").write_text("")  # A descendant can still be alive.
            (root / "link").symlink_to(empty, target_is_directory=True)
            for path, success in ((root / "absent", True), (empty, True), (populated, False),
                                  (unknown, False), (root / "link", False),
                                  (root / "no-parent" / "unit", False)):
                with self.subTest(path=path.name):
                    result = subprocess.run(["sh", "-c", '. "$1"; agent_jobs_cgroup_empty "$2"',
                                             "cgroup-test", str(SCRIPT), str(path)], timeout=10)
                    self.assertEqual(result.returncode == 0, success)

    def test_collected_cgroup_disappearing_during_read_is_already_clean(self):
        with tempfile.TemporaryDirectory(prefix="volparossa-cgroup-race-test-") as directory:
            group = Path(directory) / "collected"
            group.mkdir()
            (group / "cgroup.events").write_text("populated 0\nfrozen 0\n")
            command = r'''
set -eu
. "$1"
race_group=$2
grep() {
    test "$3" = "$race_group/cgroup.events" || return 91
    # Only this freshly-created temporary fixture, never a real cgroup.
    command rm -- "$race_group/cgroup.events"
    command rmdir -- "$race_group"
    return 2
}
agent_jobs_cgroup_empty "$race_group"
'''
            result = subprocess.run(["sh", "-c", command, "cgroup-race-test", str(SCRIPT), str(group)],
                                    capture_output=True, text=True, timeout=10)
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertFalse(group.exists())


if __name__ == "__main__":
    unittest.main()
