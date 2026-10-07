#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-only
"""Strict offline gate for the real isolated Comet/ABCI TEST fixture's receipts.

No process/network execution. This validates observations from the fixture, not
a light-client certificate, Byzantine proof, real payment or independent nodes.
"""

import argparse
import importlib.util
import json
from pathlib import Path
import re
import sys

SPEC = importlib.util.spec_from_file_location("transaction_abci_fixture", Path(__file__).with_name("transaction-abci-smoke.py"))
FIXTURE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(FIXTURE)
HASH = re.compile(r"[0-9a-fA-F]{64}")
PARENT_FIELDS = {"addresses", "routes4", "routes6", "rules4", "rules6", "firewall", "namespaces", "dns", "sysctls"}


def require(condition):
    if not condition:
        raise ValueError("transaction_abci_evidence_rejected")


def digest(value):
    return isinstance(value, str) and HASH.fullmatch(value) is not None


def natural(value, minimum=0):
    return type(value) is int and value >= minimum


def convergence(value):
    require(isinstance(value, dict) and natural(value.get("height"), 2)
            and digest(value.get("block_hash")) and digest(value.get("header_app_hash")))


def partition(value, members):
    require(isinstance(value, dict) and value.get("all_processes_alive") is True)
    require(isinstance(value.get("heights"), list) and len(value["heights"]) == members
            and all(natural(height, 2) for height in value["heights"]))
    require(natural(value.get("samples"), 8)
            and type(value.get("observation_seconds")) in (int, float)
            and 8 <= value["observation_seconds"] <= FIXTURE.TRIAL_SECONDS)
    require(isinstance(value.get("drop_packets"), list) and len(value["drop_packets"]) == 2
            and all(natural(count, 1) for count in value["drop_packets"]))


def validate(build, inner, outer, *, revision, driver_exit, guest_exit, phase):
    require(isinstance(revision, str) and re.fullmatch(r"[0-9a-f]{40}", revision) is not None)
    require(driver_exit == "0" and guest_exit == "0" and phase == "complete")
    require(isinstance(build, dict) and build.get("schema") == 1
            and build.get("source_commit") == revision and build.get("comet_source") == FIXTURE.COMET_COMMIT
            and build.get("compiler") == FIXTURE.GO_VERSION
            and build.get("compiler_archive_sha256") == FIXTURE.GO_SHA256
            and build.get("compiler_license_sha256") == FIXTURE.GO_LICENSE_SHA256
            and build.get("source_built_engine") is True and build.get("compiler_auto_upgrade") is False)
    require(all(digest(build.get(field)) for field in ("comet_sha256", "adapter_sha256", "go_mod_sha256", "go_sum_sha256")))
    require(isinstance(inner, dict) and FIXTURE.inner_complete(inner))
    require(inner.get("scope") == FIXTURE.plan()["does_not_prove"])
    children = inner.get("children_before_cleanup")
    require(isinstance(children, list) and len(children) == 8)
    require(all(isinstance(child, dict) and child.get("exit_status") is None for child in children))
    require({(child.get("node"), child.get("kind")) for child in children}
            == {(node, kind) for node in range(4) for kind in ("app", "comet")})
    checks = inner["checkpoints"]
    setup = checks["setup"]
    require(setup.get("validators") == 4 and setup.get("independent_stores") == 4
            and setup.get("private_sockets") == 4 and digest(setup.get("genesis_sha256")))
    for name in ("startup", "signed_conflict", "commit", "rejoin_3_1", "rejoin_2_2", "crash_replay"):
        convergence(checks[name])
    require(checks["startup"]["height"] < checks["signed_conflict"]["height"] < checks["commit"]["height"])
    conflict = checks["signed_conflict"]
    require(isinstance(conflict.get("result_codes"), list) and all(type(code) is int for code in conflict["result_codes"])
            and sorted(conflict["result_codes"]) == [0, 7] and conflict.get("conserved_units") == 100)
    require(checks["commit"].get("debited_units") == 70 and checks["commit"].get("credited_units") == 70
            and checks["commit"].get("conserved_units") == 100)
    three_one, two_two = checks["partition_3_1"], checks["partition_2_2"]
    partition(three_one, 1)
    partition(two_two, 4)
    for field in ("majority_heights_before", "majority_heights_after"):
        require(isinstance(three_one.get(field), list) and len(three_one[field]) == 3
                and all(natural(height, 2) for height in three_one[field]))
    require(three_one.get("majority_progress_blocks_at_least") == 3
            and min(three_one["majority_heights_after"]) >= max(three_one["majority_heights_before"]) + 3)
    require(three_one["heights"][0] >= checks["commit"]["height"])
    require(checks["rejoin_3_1"]["height"] > max(three_one["majority_heights_after"]))
    require(min(two_two["heights"]) >= checks["rejoin_3_1"]["height"])
    require(checks["rejoin_2_2"]["height"] >= max(two_two["heights"]) + 2)
    crash = checks["crash_replay"]
    require(crash.get("crashed_node") == 3 and crash.get("post_commit_restart") is True
            and crash.get("unchanged_balances") is True and crash.get("unchanged_receipts") is True
            and crash.get("second_abci_execution_proven") is True
            and natural(crash.get("height_before_restart"), checks["rejoin_2_2"]["height"])
            and crash["height"] >= crash["height_before_restart"] + 4)
    require(natural(crash.get("retry_start_height"), crash["height_before_restart"] + 2))
    heights = crash.get("retry_committed_heights")
    require(isinstance(heights, list) and len(heights) == 2
            and all(natural(height, crash["retry_start_height"] + 1) for height in heights)
            and crash["height"] > max(heights))
    require(crash.get("retry_result_codes") == [0, 0])
    sequences = crash.get("original_receipt_sequences")
    require(isinstance(sequences, list) and len(sequences) == 2
            and all(natural(sequence, 1) for sequence in sequences) and sequences[1] > sequences[0])
    require(isinstance(outer, dict) and outer.get("schema") == 1 and outer.get("source_commit") == revision
            and outer.get("comet_source") == FIXTURE.COMET_COMMIT and outer.get("acceptance") is True
            and outer.get("parent_unchanged") is True and outer.get("owned_namespaces_removed") is True
            and outer.get("private_keys_removed") is True and outer.get("failure") is None
            and outer.get("scope") == FIXTURE.plan()["does_not_prove"])
    before, after = outer.get("parent_before"), outer.get("parent_after")
    require(isinstance(before, dict) and isinstance(after, dict) and set(before) == PARENT_FIELDS
            and before == after and all(digest(value) for value in before.values()))


def read_file(path, maximum=32768):
    require(path.is_file() and not path.is_symlink())
    with path.open("rb") as stream:
        data = stream.read(maximum + 1)
    require(len(data) <= maximum)
    return data


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", required=True, type=Path)
    parser.add_argument("--expected-commit", required=True)
    parser.add_argument("--driver-exit-code", required=True)
    args = parser.parse_args()
    build, inner, outer = [json.loads(read_file(args.output / name)) for name in (
        "transaction-abci-build.json", "transaction-abci-inner.json", "transaction-abci-acceptance.json")]
    validate(build, inner, outer, revision=args.expected_commit, driver_exit=args.driver_exit_code,
             guest_exit=read_file(args.output / "guest-exit-status", 16).decode().strip(),
             phase=read_file(args.output / "guest-phase", 64).decode().strip())
    print("Isolated four-validator TEST evidence accepted; no Byzantine, overlay or real-settlement claim.")


if __name__ == "__main__":
    try:
        main()
    except (OSError, ValueError, TypeError, KeyError, AttributeError):
        print("transaction_abci_evidence_rejected", file=sys.stderr)
        raise SystemExit(1)
