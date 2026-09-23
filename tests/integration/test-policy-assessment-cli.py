#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-only
"""Exercise the compiled public-policy CLI without any model or network execution.

This proves argument wiring and inert previews only. Real model assessments, peer
transport, cross-review and policy quality require their own disposable proof.
"""

import json
from pathlib import Path
import subprocess
import sys
import tempfile


# Public RFC8032 test-vector keys; no account or production identity is used.
KEYS = (
    "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a",
    "3d4017c3e843895a92b70aa74d1b7ebc9c982ccf2ec4968cc0cd55f12af4660c",
    "fc51cd8e6218a1a38da47ed00230f0580816ed13ba3303ac5deb911548908025",
)


def require(condition, reason):
    if not condition:
        raise AssertionError(reason)


def run(binary, root, flags, success, command="policy-assess"):
    completed = subprocess.run(
        [str(binary), "--control-socket", str(root / "absent-control.sock"),
         "compute", "peer", command, *flags],
        capture_output=True, text=True, timeout=15, check=False,
    )
    require((completed.returncode == 0) == success,
            f"unexpected CLI exit {completed.returncode}: {completed.stderr[:2048]}")
    require(not list(root.iterdir()), "inert CLI invocation created local state")
    return completed


def main():
    require(len(sys.argv) == 2, "usage: test-policy-assessment-cli.py ABSOLUTE_BINARY")
    binary = Path(sys.argv[1])
    require(binary.is_absolute() and binary.is_file(), "compiled CLI binary required")
    with tempfile.TemporaryDirectory(prefix="volparossa-policy-cli-") as name:
        root = Path(name)
        output = str(root / "new-assessment")
        help_text = run(binary, root, ["--help"], True).stdout
        for option in ("--source-publisher-key", "--source-manifest-id", "--provider-key",
                       "--resume", "--execute", "--portable-receipts"):
            require(option in help_text, f"missing real CLI option {option}")
        flags = [
            "--output", output,
            "--source-publisher-key", KEYS[0], "--source-name", "public-principles-probe",
            "--source-manifest-id", "42" * 32, "--cache", str(root / "absent-cache"),
            "--publisher-key", KEYS[2], "--identity", str(root / "absent-identity"),
            "--passphrase-file", str(root / "absent-passphrase"),
            "--provider-key", KEYS[0], "--provider-key", KEYS[1], "--license", "CC0-1.0",
        ]
        preview = json.loads(run(binary, root, flags, True).stdout)
        require(preview["operation"] == "compute_peer_policy_assessment"
                and preview["execute"] is False
                and preview["network_policy_activation"] is False
                and preview["assessment_peers"] == 2
                and preview["planned_jobs"] == 4
                and preview["dataset_version"] == 4 and preview["structured_output"] is True
                and preview["model_profile"] == "smollm2-360m-v1"
                and preview["generation_limit_tokens"] == 512, "wrong public assessment preview scope")
        resumed = json.loads(run(binary, root, ["--output", output, "--resume"], True).stdout)
        require(resumed["execute"] is False and resumed["network_policy_activation"] is False,
                "resume preview acquired execution authority")
        require(resumed["dataset_version"] is None and resumed["structured_output"] is None
                and resumed["generation_limit_tokens"] is None,
                "resume preview guessed the version of an unread historical enrollment")
        portable = json.loads(run(binary, root, [*flags, "--portable-receipts"], True).stdout)
        require(portable["portable_receipts"] is True, "portable opt-in missing")
        pack = json.loads(run(binary, root, ["--assessment", output, "--output", str(root / "pack"),
            "--requester-key", KEYS[2]], True, "policy-pack").stdout)
        require(pack["execute"] is False and pack["automatic_publication"] is False,
                "pack preview published or accessed absent workflow")
        fetch_flags = ["--publisher-key", KEYS[2], "--name", "selected-assessment",
            "--manifest-id", "43" * 32, "--cache", str(root / "fetch-cache"),
            "--output", str(root / "fetch"), "--requester-key", KEYS[2],
            "--source-publisher-key", KEYS[0], "--source-manifest-id", "42" * 32,
            "--provider-key", KEYS[0], "--provider-key", KEYS[1]]
        fetched = json.loads(run(binary, root, fetch_flags, True, "policy-fetch").stdout)
        require(fetched["execute"] is False and fetched["model_execution"] is False
                and fetched["network_policy_activation"] is False, "fetch preview acquired authority")
        run(binary, root, [*fetch_flags, "--allow-network-policy-activation"], False, "policy-fetch")
        run(binary, root, [*flags, "--allow-network-policy-activation"], False)
        run(binary, root, ["--output", output, "--resume", "--execute"], False)
    print("PASS: compiled policy-assess/pack/fetch CLI, inert previews and absent-state rejection")
    print("NOT PROVEN: real models, peer execution, cross-review or policy correctness")


if __name__ == "__main__":
    main()
