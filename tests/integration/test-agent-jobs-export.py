#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-only
"""Exercise the actual report export with inert files, not a network/model proof."""

import os
from pathlib import Path
import subprocess
import tempfile
import unittest


HERE = Path(__file__).resolve().parent


class ReportExport(unittest.TestCase):
    def test_document_export_retains_raw_discovery_and_skips_private_files(self):
        with tempfile.TemporaryDirectory(prefix="volparossa-report-export-") as directory:
            root = Path(directory)
            work, output = root / "work", root / "output"
            work.mkdir()
            output.mkdir()
            names = [
                "agent-jobs-private-cleanup.json",
                "agent-jobs-result.err",
                "agent-jobs-observer.log",
                "content-custody-fetch-live-selection.json",
                "content-provider-custody-fetch-control.json",
                "content-provider-control-peers.json",
                "content-custody-executor-discovery-live-selection.json",
                "content-custody-executor-discovery-gates.json",
                "content-provider-custody-executor-discovery-control.json",
            ] + [f"content-custody-executor-discovery-privacy-{role}.json"
                 for role in ("client", "relay0", "relay1", "relay2", "exit")]
            expected = {name: (f'{{"synthetic":true,"file":"{name}"}}\n').encode()
                        for name in names}
            for name, data in expected.items():
                (work / name).write_bytes(data)
            (work / "private.key").write_text("not for export")
            (work / "content-custody-executor-discovery-private.key").write_text("not json")
            (work / "content-custody-executor-discovery-link.json").symlink_to(work / "private.key")
            (work / "content-custody-executor-discovery-directory.json").mkdir()
            command = r'''
set -eu
. "$1"
WORK=$2
output_directory=$3
OUTPUT_UID=$4
OUTPUT_GID=$5
agent_public_document=yes
agent_public_document_finalize_report() { test "$1" = 7; }
agent_jobs_finalize_report 7
'''
            subprocess.run(["sh", "-c", command, "export-test", str(HERE / "agent-jobs-smoke.sh"),
                            str(work), str(output), str(os.getuid()), str(os.getgid())],
                           check=True, timeout=15)
            self.assertEqual({path.name for path in output.iterdir()}, set(expected))
            for name, data in expected.items():
                self.assertEqual((output / name).read_bytes(), data)
                self.assertEqual((output / name).stat().st_mode & 0o777, 0o600)

    def test_export_with_no_optional_discovery_files_still_finalizes(self):
        with tempfile.TemporaryDirectory(prefix="volparossa-report-export-") as directory:
            root = Path(directory)
            work, output = root / "work", root / "output"
            work.mkdir()
            output.mkdir()
            command = r'''
set -eu
. "$1"
WORK=$2
output_directory=$3
agent_jobs_follow=yes
agent_jobs_follow_finalize_report() { test "$1" = 0; }
agent_jobs_finalize_report 0
'''
            subprocess.run(["sh", "-c", command, "export-test", str(HERE / "agent-jobs-smoke.sh"),
                            str(work), str(output)], check=True, timeout=15)
            self.assertEqual(list(output.iterdir()), [])


if __name__ == "__main__":
    unittest.main()
