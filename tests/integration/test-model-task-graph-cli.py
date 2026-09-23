#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-only
"""Real compiled argument/preview checks only; no source, model or network execution."""

import json
from pathlib import Path
import subprocess
import sys
import tempfile


QUESTION = "Which route meets the stated privacy constraints, why, and what further evidence is needed before comparing performance?"
# Public RFC8032 test-vector identities only; no signer or account is acquired.
KEYS = (
    "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a",
    "3d4017c3e843895a92b70aa74d1b7ebc9c982ccf2ec4968cc0cd55f12af4660c",
    "fc51cd8e6218a1a38da47ed00230f0580816ed13ba3303ac5deb911548908025",
)


def require(condition, reason):
    if not condition:
        raise AssertionError(reason)


def invoke(binary, root, flags, success):
    result = subprocess.run(
        [str(binary), "--control-socket", str(root / "absent-control.sock"),
         "compute", "peer", "document", *flags],
        capture_output=True, text=True, timeout=15, check=False,
    )
    require((result.returncode == 0) == success,
            f"unexpected compiled CLI status {result.returncode} for {flags!r}: {result.stderr[:2048]}")
    require(not list(root.iterdir()), "inert preview created source, workflow or control state")
    return result


def main():
    require(len(sys.argv) == 2, "usage: test-model-task-graph-cli.py ABSOLUTE_BINARY")
    binary = Path(sys.argv[1])
    require(binary.is_absolute() and binary.is_file(), "compiled CLI binary required")
    with tempfile.TemporaryDirectory(prefix="volparossa-graph-cli-") as temporary:
        root = Path(temporary)
        help_text = invoke(binary, root, ["--help"], True).stdout
        require("--plan-structure" in help_text and "dependent" in help_text,
                "dependent graph option missing from compiled command")
        flags = ["--directory", str(root / "graph"), "--input", str(root / "absent-source.txt"),
                 "--public-content", "--public-question", QUESTION,
                 "--license", "GPL-3.0-only", "--runtime-root", str(root / "absent-runtime"),
                 "--model-root", str(root / "absent-model"), "--identity", str(root / "absent-identity"),
                 "--passphrase-file", str(root / "absent-passphrase"), "--publisher-key", KEYS[2],
                 "--provider-key", KEYS[0], "--provider-key", KEYS[1],
                 "--model-profile", "smollm2-360m-v1", "--max-seconds", "600"]
        base = json.loads(invoke(binary, root, [*flags, "--plan-task-graph"], True).stdout)
        require(base["operation"] == "compute_document_plan" and base["execute"] is False
                and base["plan_task_graph"] is True and base["plan_structure"] is None,
                "unspecified graph silently acquired a dependency requirement")
        requested = json.loads(invoke(binary, root,
            [*flags, "--plan-task-graph", "--plan-structure", "dependent"], True).stdout)
        require(requested == dict(base, plan_structure="dependent_analysis_v1")
                and requested["maximum_seconds_per_worker"] == 600
                and requested["tokenizer_execution"] is requested["network_execution"] is False,
                "dependency selection changed resource/execution scope")
        legacy = json.loads(invoke(binary, root, [*flags, "--plan-tasks"], True).stdout)
        require(legacy["plan_tasks"] is True and legacy["plan_task_graph"] is False
                and legacy["plan_structure"] is None, "legacy question planner changed")
        for extra in (["--plan-structure", "dependent"],
                      ["--plan-tasks", "--plan-structure", "dependent"],
                      ["--plan-task-graph", "--plan-structure", "unknown"],
                      ["--plan-task-graph", "--plan-structure", "dependent", "--task-plan", str(root / "absent-plan.json")]):
            invoke(binary, root, [*flags, *extra], False)
        invoke(binary, root, ["--directory", str(root / "graph"), "--resume",
                              "--plan-structure", "dependent"], False)
    print("PASS: compiled dependent graph selection, historical default and inert previews")
    print("NOT PROVEN: model decomposition, peer execution, parent consumption or answer quality")


if __name__ == "__main__":
    main()
