#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-only
"""One source-bound OpenCode/public-core task; reuse the real peer observer.

No VM launch, download, model response or peer result is provided here. The Code
driver declares its synthetic PRIVATE planner; only public execution is observed.
"""
import hashlib
import json
import os
from pathlib import Path
import pwd
import re
import runpy
import shutil
import stat
import subprocess
import sys
import time

HERE = Path(__file__).resolve().parent
BROWSER = runpy.run_path(str(HERE / "agent-cooperative-browser.py"))
JOBS = BROWSER["JOBS"]
read, write, require = JOBS["read"], JOBS["write"], JOBS["require"]
NAME = "agent-cooperative-code"
CODE_REVISION = "b3a4cfe79158d24e1dd61dcb56d37123f9d3d55c"
OPENCODE_REVISION = "aec0b9a6d8898f68f923aaf08b7306d931fd9d76"
CODE_FILES = tuple("src/" + name for name in (
    "private-compute.cjs", "private-conversation.cjs", "responses-provider.cjs",
    "chat-completions-provider.cjs", "opencode-config.cjs", "opencode-client.cjs",
    "opencode-task.cjs", "opencode-bridge.cjs", "opencode-runtime.cjs",
    "cooperative-tool-client.cjs", "cooperative-tool-server.cjs", "cooperative-delegation.cjs",
    "opencode-cooperative-tool.js")) + (
    "scripts/opencode_session.py", "scripts/opencode_session.cjs", "scripts/smoke_opencode_cooperation.cjs",
    "third_party/opencode.json", "third_party/opencode-LICENSE.txt",
    "patches/opencode-no-runtime-installs.patch", "LICENSE", "THIRD_PARTY_LICENSES.md")
BUNDLE_FILES = tuple("code/" + name for name in CODE_FILES) + (
    "runtime/opencode", "runtime/build-report.json", "runtime/node", "runtime/node-LICENSE")
EXPORT_NAMES = tuple(f"{NAME}-{suffix}.json" for suffix in (
    "smoke", "evidence", "provision", "input", "driver", "observation", "result", "cleanup", "diagnostic")) + (
    "a01-expected-peers.json", "agent-jobs-layout.json", "agent-jobs-provision.json", "agent-jobs-private-cleanup.json",
    "content-custody-fetch-live-selection.json", "content-custody-fetch-gates.json",
    "content-provider-custody-fetch-control.json",
    *(f"content-custody-fetch-privacy-{role}.json" for role in JOBS["CUSTODY"]["ROLES"]))
FALSE_SCOPE = ("private_peer_execution_proven", "native_model_planning_proven", "coding_quality_proven",
               "live_peer_cancellation_proven", "answer_correctness_proven", "full_alpha_acceptance_claimed")


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def digest(path):
    with path.open("rb") as stream:
        return hashlib.file_digest(stream, "sha256").hexdigest()


def hex64(value):
    return isinstance(value, str) and re.fullmatch(r"[0-9a-f]{64}", value) is not None


def paths(work):
    return work / "agent-jobs-user/code", work / "state-client/compute-source/public-code"


def bundle_manifest(value):
    require(set(value) == {"version", "kind", "code_revision", "opencode_revision", "opencode_binary_sha256", "node_version", "files"}
            and value["version"] == 1 and value["kind"] == "opencode-cooperative-inputs"
            and value["code_revision"] == CODE_REVISION and value["opencode_revision"] == OPENCODE_REVISION
            and value["node_version"] == "24.19.0" and hex64(value["opencode_binary_sha256"])
            and set(value["files"]) == set(BUNDLE_FILES),
            "exact reviewed Code bundle required")
    total = 0
    for name, entry in value["files"].items():
        maximum = 160 * 1048576 if name in ("runtime/opencode", "runtime/node") else 1048576
        mode = 0o700 if name in ("runtime/opencode", "runtime/node") else 0o600
        require(set(entry) == {"bytes", "sha256", "mode"} and type(entry["bytes"]) is int
                and 0 < entry["bytes"] <= maximum and entry["mode"] == mode and hex64(entry["sha256"]),
                "invalid bundle inventory")
        total += entry["bytes"]
    require(total <= 340 * 1048576, "bundle too large")
    require(value["opencode_binary_sha256"] == value["files"]["runtime/opencode"]["sha256"], "binary pin differs")


def checked_file(path, uid, maximum):
    info = path.lstat()
    owners = {0, uid, pwd.getpwnam("vpci").pw_uid}
    require(path.is_absolute() and path.resolve(strict=True) == path and stat.S_ISREG(info.st_mode)
            and info.st_nlink == 1 and info.st_uid in owners and not info.st_mode & 0o6022
            and 0 < info.st_size <= maximum, "unsafe staged file")
    return info


def provision(work, bundle, expected):
    JOBS["guest_work"](work)
    require(hex64(expected) and bundle.is_absolute() and bundle.resolve(strict=True) == bundle,
            "explicit canonical bundle and hash required")
    account = pwd.getpwnam("volparossa")
    checked_file(bundle / "INPUTS.json", account.pw_uid, 65536)
    require(digest(bundle / "INPUTS.json") == expected, "bundle manifest changed")
    selected = read(bundle / "INPUTS.json", 65536)
    bundle_manifest(selected)
    for name, record in selected["files"].items():
        info = checked_file(bundle / name, account.pw_uid, record["bytes"])
        require(info.st_size == record["bytes"] and digest(bundle / name) == record["sha256"], "bundle file changed")
    build = read(bundle / "runtime/build-report.json", 65536)
    pin = read(bundle / "code/third_party/opencode.json", 65536)
    node = read(HERE / "agent-private-conversation-pins.json")["runtime"]
    require(build["source_build"] is True and build["source_commit"] == OPENCODE_REVISION
            and pin["commit"] == OPENCODE_REVISION and build["runtime_version"] == "1.18.34"
            and pin["tag"] == "v1.18.34" and build["lock_sha256"] == pin["bun_lock_sha256"]
            and pin["local_patch"] == "patches/opencode-no-runtime-installs.patch"
            and build["patch_sha256"] == digest(bundle / "code" / pin["local_patch"])
            and build["binary_sha256"] == selected["files"]["runtime/opencode"]["sha256"]
            and build["license_sha256"] == pin["license_sha256"] == digest(bundle / "code/third_party/opencode-LICENSE.txt")
            and node["version"] == "24.19.0"
            and selected["files"]["runtime/node"]["sha256"] == node["files"]["bin/node"]["sha256"]
            and selected["files"]["runtime/node"]["bytes"] == node["files"]["bin/node"]["bytes"]
            and selected["files"]["runtime/node-LICENSE"]["sha256"] == node["files"]["LICENSE"]["sha256"],
            "source build or pinned Node provenance differs")
    root, _ = paths(work)
    require(not root.exists() and not root.is_symlink(), "new Code fixture required")
    root.mkdir(mode=0o700)
    os.chown(root, account.pw_uid, account.pw_gid)
    for name, record in selected["files"].items():
        target = root / name
        for directory in reversed(target.parent.relative_to(root).parents):
            (root / directory).mkdir(mode=0o700, exist_ok=True)
        target.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
        with (bundle / name).open("rb") as source, target.open("xb") as output:
            shutil.copyfileobj(source, output, 65536)
        require(digest(target) == record["sha256"], "copy changed")
        target.chmod(record["mode"])
        os.chown(target, account.pw_uid, account.pw_gid)
        for directory in [target.parent, *target.parent.parents]:
            if directory == root:
                break
            os.chown(directory, account.pw_uid, account.pw_gid)
            directory.chmod(0o700)
    (root / "projects").mkdir(mode=0o700)
    os.chown(root / "projects", account.pw_uid, account.pw_gid)
    original = (work / "bin/agent-jobs-README.md").read_bytes()
    require(3840 <= len(original) <= 1048576, "bounded public README missing")
    context = original[:3840].decode("utf-8", errors="ignore")
    snapshot = dict(question=BROWSER["QUESTION"], context=context, license="GPL-3.0-only",
                    public_content=True, rights_confirmed=True)
    write(root / "input.json", snapshot)
    os.chown(root / "input.json", account.pw_uid, account.pw_gid)
    write(work / f"{NAME}-input.json", dict(context_bytes=len(context.encode()), context_sha256=sha(context.encode()),
        question_sha256=sha(snapshot["question"].encode()), snapshot_sha256=digest(root / "input.json"),
        readme_sha256=sha(original), license="GPL-3.0-only", explicit_public_source=True))
    write(work / f"{NAME}-provision.json", dict(version=1, bundle_manifest_sha256=expected, manifest=selected,
        source_build=True, opencode_revision=OPENCODE_REVISION, runtime_version="1.18.34", node_version=node["version"]))


def account_home(work, cleanup=False):
    marker = work / f"{NAME}-home.json"
    if cleanup and not marker.exists() and not marker.is_symlink():
        return
    JOBS["guest_work"](work)
    account = pwd.getpwnam("volparossa")
    home = Path("/var/lib/volparossa")
    require(account.pw_dir == str(home), "unexpected service account home")
    if cleanup:
        if marker.exists() or marker.is_symlink():
            BROWSER["cleanup_account_home"](home, read(marker))
    else:
        require(not marker.exists() and not marker.is_symlink(), "home marker already exists")
        ownership = BROWSER["prepare_account_home"](home, account.pw_uid, account.pw_gid)
        try:
            write(marker, ownership)
        except OSError:
            BROWSER["cleanup_account_home"](home, ownership)
            raise


def unique_document(state, manifest_id):
    require(hex64(manifest_id), "invalid result manifest")
    matches = []
    for root in BROWSER["task_roots"](state):
        manifest = root / "document/source.manifest"
        if manifest.exists():
            info = manifest.lstat()
            require(stat.S_ISREG(info.st_mode) and not manifest.is_symlink() and 0 < info.st_size <= 65536,
                    "invalid retained manifest")
            if digest(manifest) == manifest_id:
                matches.append(root / "document")
    require(len(matches) == 1, "no unique retained source manifest")
    return matches[0]


DRIVER_FIELDS = set("version kind passed phase failure synthetic_private_planner actual_private_model_inference synthetic_public_core externally_supplied_public_endpoint public_results_injected private_peer_execution_proven native_model_planning_proven coding_quality_proven independent_peer_execution_proven peer_worker_receipts_and_datapath_owned_by_parent source_binding_to_core_manifest_owned_by_parent vm_cleanup_owned_by_parent source_commit binary_sha256 build_report_sha256 node_sha256 snapshot_sha256 submitted_snapshot_sha256 question_sha256 context_sha256 license original_public_result actual_native_turn_completed original_tool_result_roundtrip refused_actions public_submissions public_completed runtime_cleanup_confirmed public_owner_cleanup_confirmed planner_cleanup_confirmed project_removed elapsed_ms".split())
RESULT_FIELDS = set("tool_call_id core_task_id original_tool_result_sha256 original_core_result_sha256 output_sha256 output_bytes source_manifest_id provider_keys selected_provider_keys answer_complete answer_status execution_complete joining package_count total_parts synthesis_levels core_reported_remote_cleanup_confirmed complete_with_two_execution_providers".split())


def driver(value, successful=False):
    require(set(value) == DRIVER_FIELDS and value["version"] == 1
            and value["kind"] == "opencode-external-public-core-cooperation"
            and value["phase"] in ("prepare", "runtime-start", "native-cooperative-task", "observed-public-result", "complete")
            and value["failure"] in (None, "public_answer_incomplete", "fewer_than_two_execution_providers",
                "cancelled_or_deadline", "task_or_runtime_failed", "cleanup_unconfirmed", "incomplete_integration_evidence")
            and value["source_commit"] == OPENCODE_REVISION and value["license"] == "GPL-3.0-only", "driver scope differs")
    for key, item in value.items():
        if key.endswith("sha256"):
            require(hex64(item), "invalid driver digest")
    for key in ("refused_actions", "public_submissions", "public_completed", "elapsed_ms"):
        require(type(value[key]) is int and 0 <= value[key] <= 10_000_000, "driver count differs")
    true = ("synthetic_private_planner", "externally_supplied_public_endpoint", "peer_worker_receipts_and_datapath_owned_by_parent",
            "source_binding_to_core_manifest_owned_by_parent", "vm_cleanup_owned_by_parent")
    false = ("actual_private_model_inference", "synthetic_public_core", "public_results_injected", "private_peer_execution_proven",
             "native_model_planning_proven", "coding_quality_proven", "independent_peer_execution_proven")
    require(all(value[key] is True for key in true) and all(value[key] is False for key in false), "driver claims overstated")
    for key in ("passed", "actual_native_turn_completed", "original_tool_result_roundtrip", "runtime_cleanup_confirmed",
                "public_owner_cleanup_confirmed", "planner_cleanup_confirmed", "project_removed"):
        require(type(value[key]) is bool, "invalid driver state")
    result = value["original_public_result"]
    if result is not None:
        require(set(result) == RESULT_FIELDS and result["tool_call_id"] == "external-public-cooperation-1"
                and re.fullmatch(r"[0-9a-f]{32}", result["core_task_id"]), "tool/request identity differs")
        for key in ("original_tool_result_sha256", "original_core_result_sha256", "output_sha256", "source_manifest_id"):
            require(hex64(result[key]), "invalid original result digest")
        for key in ("provider_keys", "selected_provider_keys"):
            require(type(result[key]) is list and len(result[key]) <= 4 and all(hex64(x) for x in result[key])
                    and len(set(result[key])) == len(result[key]), "invalid providers")
        require(len(result["selected_provider_keys"]) >= 2
                and set(result["provider_keys"]) <= set(result["selected_provider_keys"]), "provider enrollment differs")
        for key in ("output_bytes", "package_count", "total_parts", "synthesis_levels"):
            require(type(result[key]) is int and 0 <= result[key] <= 65536, "invalid result count")
        for key in ("answer_complete", "execution_complete", "complete_with_two_execution_providers",
                    "core_reported_remote_cleanup_confirmed"):
            require(type(result[key]) is bool, "invalid result state")
        require(result["answer_status"] == ("complete" if result["answer_complete"] else "incomplete")
                and result["joining"] in ("single_source_answer", "hierarchical_peer_synthesis",
                    "hierarchical_peer_synthesis_incomplete", "awaiting_fragments_before_peer_synthesis",
                    "incomplete_fragment_answers", "ordered_source_ranges_not_neural_synthesis"), "result scope differs")
    if successful:
        require(value["passed"] is True and value["phase"] == "complete" and value["failure"] is None
                and all(value[key] is True for key in ("actual_native_turn_completed", "original_tool_result_roundtrip",
                    "runtime_cleanup_confirmed", "public_owner_cleanup_confirmed", "planner_cleanup_confirmed", "project_removed"))
                and value["public_submissions"] == value["public_completed"] == 1 and value["refused_actions"] == 0
                and result is not None and result["answer_complete"] is True and result["execution_complete"] is True
                and result["core_reported_remote_cleanup_confirmed"] is True
                and result["complete_with_two_execution_providers"] is True and len(result["provider_keys"]) >= 2,
                "native cooperation incomplete")
    return value


def join_result(shown, original, snapshot):
    require(all(shown[key] == original[key] for key in (
        "source_manifest_id", "output_sha256", "package_count", "total_parts", "synthesis_levels"))
        and sorted(shown["provider_keys"]) == original["provider_keys"]
        and shown["joining"] == "hierarchical_peer_synthesis"
        and original["source_sha256"] == sha(snapshot["context"].encode())
        and original["context_bytes"] == len(snapshot["context"].encode())
        and original["answer_complete"] is True and original["execution_complete"] is True
        and original["exact_native_receipts_verified"] is True, "native result binding differs")


def observe(work, pid):
    JOBS["guest_work"](work)
    root, state = paths(work)
    owner = JOBS["identity"](pid)
    layout = read(work / "agent-jobs-layout.json")
    brokers = {node: JOBS["identity"](JOBS["broker_pid"](node)) for node in layout["provider_nodes"]}
    observed, tasks = {}, []
    deadline = time.monotonic() + 2460
    phase = "worker_scan"
    try:
        while JOBS["alive"](owner) and time.monotonic() < deadline:
            tasks = BROWSER["task_roots"](state)
            require(len(tasks) <= 1, "more than one public task admitted")
            for task in tasks:
                BROWSER["scan_workers"](work, task / "document", layout, brokers, observed)
            time.sleep(0.05)
        require(not JOBS["alive"](owner), "Code driver exceeded bound")
        phase = "retained_result"
        shown = driver(read(root / "report.json", 131072), successful=True)
        require(len(BROWSER["task_roots"](state)) == 1, "exactly one retained public task required")
        document = unique_document(state, shown["original_public_result"]["source_manifest_id"])
        original = BROWSER["retained_result"](document, read(root / "input.json"), layout, observed)
        join_result(shown["original_public_result"], original, read(root / "input.json"))
        require(not any(JOBS["alive"](member) for entry in observed.values() for member in entry["owned_processes"]),
                "observed public workers remain alive")
        write(work / f"{NAME}-result.json", original)
        write(work / f"{NAME}-observation.json", dict(version=1, unique_manifest_join=True,
            wire_id_is_not_directory_id=True, observed_workers_ended=True,
            real_fragment_peers=sorted({entry["node"] for entry in observed.values() if entry["level"] is None}),
            observed_synthesis_levels=sorted({entry["level"] for entry in observed.values() if entry["level"] is not None}),
            completed_workers=list(observed.values()), live_cancellation_observed=False))
    except (OSError, ValueError, KeyError, TypeError, subprocess.SubprocessError):
        try:
            write(work / f"{NAME}-observer-status.private", dict(version=1, phase=phase,
                failure="observer_incomplete", observed_workers=min(len(observed), 128), task_count=min(len(tasks), 2)))
        except OSError:
            pass  # Retain the execution failure, not a diagnostic-write exception.
        raise


def closed_observer(path):
    try:
        info = path.lstat()
        require(stat.S_ISREG(info.st_mode) and stat.S_IMODE(info.st_mode) == 0o600
                and info.st_size <= 4096, "invalid observer diagnostic")
        value = read(path, 4096)
        require(set(value) == {"version", "phase", "failure", "observed_workers", "task_count"}
                and type(value["version"]) is int and value["version"] == 1
                and value["phase"] in ("worker_scan", "retained_result") and value["failure"] == "observer_incomplete"
                and type(value["observed_workers"]) is int and 0 <= value["observed_workers"] <= 128
                and type(value["task_count"]) is int and 0 <= value["task_count"] <= 2,
                "invalid observer diagnostic fields")
        return dict(state="valid", status=value)
    except FileNotFoundError:
        return dict(state="absent")
    except (OSError, ValueError, KeyError, TypeError):
        return dict(state="invalid")


def capture(work, application_status, observer_status):
    JOBS["guest_work"](work)
    root, state = paths(work)
    require(0 <= application_status <= 255 and 0 <= observer_status <= 255, "invalid exit status")
    status = "absent"
    try:
        value = driver(read(root / "report.json", 131072))
        write(work / f"{NAME}-driver.json", value)
        status = "valid"
    except FileNotFoundError:
        pass
    except (OSError, ValueError, KeyError, TypeError):
        status = "invalid"
    write(work / f"{NAME}-diagnostic.json", dict(version=1, driver_exit_status=application_status,
        observer_exit_status=observer_status, driver_report=status,
        observer=closed_observer(work / f"{NAME}-observer-status.private"),
        coordinator=BROWSER["coordinator_diagnostic"](state)))


def check_evidence(value, revision):
    require(value["source_revision"] == revision and value["success"] is True
            and all(value[key] is False for key in FALSE_SCOPE), "evidence scope differs")
    provision = value["provision"]
    bundle_manifest(provision["manifest"])
    shown = driver(value["driver"], successful=True)
    selected = provision["manifest"]["files"]
    require(shown["binary_sha256"] == selected["runtime/opencode"]["sha256"]
            and shown["build_report_sha256"] == selected["runtime/build-report.json"]["sha256"]
            and shown["node_sha256"] == selected["runtime/node"]["sha256"], "runtime provenance differs")
    original, observed, input_ = value["result"], value["observation"], value["input"]
    require(shown["snapshot_sha256"] == input_["snapshot_sha256"]
            and shown["context_sha256"] == original["source_sha256"] == input_["context_sha256"]
            and shown["question_sha256"] == input_["question_sha256"]
            and original["context_bytes"] == input_["context_bytes"] <= 4096
            and input_["explicit_public_source"] is True and input_["license"] == "GPL-3.0-only"
            and all(shown["original_public_result"][key] == original[key] for key in (
                "source_manifest_id", "output_sha256", "package_count", "total_parts", "synthesis_levels"))
            and sorted(shown["original_public_result"]["provider_keys"]) == original["provider_keys"]
            and original["exact_native_receipts_verified"] is True and original["answer_complete"] is True
            and original["execution_complete"] is True and original["semantic_completeness_proven"] is False,
            "source/answer join differs")
    require(observed["unique_manifest_join"] is True and observed["wire_id_is_not_directory_id"] is True
            and observed["observed_workers_ended"] is True and observed["live_cancellation_observed"] is False
            and observed["real_fragment_peers"] == sorted(value["layout"]["provider_nodes"])
            and len(observed["observed_synthesis_levels"]) == original["synthesis_levels"] >= 2
            and observed["completed_workers"] and len(original["provider_keys"]) == 2,
            "real worker proof incomplete")
    for entry in observed["completed_workers"]:
        require(entry["isolated_live_worker"] is True and entry["base_model_sha256"] == JOBS["TRAIN"]["WEIGHT_HASH"]
                and entry["provider_key"] in original["provider_keys"] and hex64(entry["dataset_sha256"]),
                "worker provenance differs")
    require(value["private_cleanup"] == dict(observed_compute_processes_ended=True, model_runtime_removed=True,
            private_job_roots_removed=True, publisher_key_removed=True)
            and value["cleanup"] == dict(public_service_stopped=True, peer_brokers_stopped=True,
                code_root_removed=True, public_receipts_removed=True, socket_removed=True), "cleanup incomplete")
    JOBS["CUSTODY"]["validate_path"](value["path"], value["peers"], value["layout"], "fetch", payload_minimum=1)
    for node in value["layout"]["provider_nodes"]:
        application = value["path"]["privacy"]["exit"]["provider_application"][node]
        require(application["request_packets"] > 0 and application["response_payload_bytes"] > 0,
                "executor protected exchange absent")
    require(value["path"]["gates"]["exit_mptcp_tls_completed"] >= 6, "protected completions absent")


def evidence(work, revision):
    JOBS["guest_work"](work)
    root, state = paths(work)
    require(not root.exists() and not state.exists() and not (state.parent / "public.sock").exists(), "owned state remains")
    layout = read(work / "agent-jobs-layout.json")
    for unit in ("volparossa-alpha-public-code.service", "volparossa-alpha-cooperative-code.service",
                 *(f"volparossa-alpha-compute@{node}.service" for node in layout["provider_nodes"])):
        status = subprocess.check_output(["systemctl", "show", "--property=ActiveState", "--value", unit], text=True).strip()
        require(status in ("inactive", "failed"), "owned unit remains active")
    cleanup = dict(public_service_stopped=True, peer_brokers_stopped=True, code_root_removed=True,
                   public_receipts_removed=True, socket_removed=True)
    write(work / f"{NAME}-cleanup.json", cleanup)
    value = {name: read(work / f"{NAME}-{name}.json", 1048576)
             for name in ("provision", "input", "driver", "observation", "result", "cleanup")}
    value.update(source_revision=revision, success=True, **dict.fromkeys(FALSE_SCOPE, False),
        private_cleanup=read(work / "agent-jobs-private-cleanup.json"), peers=read(work / "a01-expected-peers.json"), layout=layout,
        path=dict(selected_route=read(work / "content-custody-fetch-live-selection.json"),
            privacy={role: read(work / f"content-custody-fetch-privacy-{role}.json") for role in JOBS["CUSTODY"]["ROLES"]},
            control_privacy=read(work / "content-provider-custody-fetch-control.json"), gates=read(work / "content-custody-fetch-gates.json")))
    check_evidence(value, revision)
    write(work / f"{NAME}-evidence.json", value)


def finalize(work, revision, status, complete, remaining, phase, blocker):
    path = work / f"{NAME}-evidence.json"
    value = read(path, 1048576) if path.is_file() else None
    if value is not None:
        check_evidence(value, revision)
    host_path = work / "a15-evidence.json"
    host = read(host_path) if host_path.is_file() else {}
    write(work / f"{NAME}-smoke.json", dict(report_kind="volparossa-cooperative-code", schema_version=1,
        source_revision=revision, runner_exit_status=status, phase=phase,
        observed_blocker=None if blocker == "NONE" else blocker, evidence=value, host_state=host,
        cleanup=dict(complete=complete, remaining_owned_objects=remaining),
        success=status == 0 and complete and remaining == 0 and host.get("unchanged") is True and value is not None))


def check_report(value, revision):
    require(re.fullmatch(r"[0-9a-f]{40}", revision) and value["source_revision"] == revision
            and value["report_kind"] == "volparossa-cooperative-code" and value["schema_version"] == 1
            and value["success"] is True and value["runner_exit_status"] == 0
            and value["phase"] == "agent-cooperative-code-complete" and value["observed_blocker"] is None
            and value["cleanup"] == dict(complete=True, remaining_owned_objects=0)
            and value["host_state"]["unchanged"] is True
            and value["host_state"]["before_sha256"] == value["host_state"]["after_sha256"],
            "exact-source host/cleanup proof missing")
    check_evidence(value["evidence"], revision)


def main(args):
    if args == ["export-names"]:
        print("\n".join(EXPORT_NAMES))
    elif len(args) == 4 and args[0] == "provision":
        provision(Path(args[1]), Path(args[2]), args[3])
    elif len(args) == 2 and args[0] in ("account-home-prepare", "account-home-cleanup"):
        account_home(Path(args[1]), cleanup=args[0] == "account-home-cleanup")
    elif len(args) == 3 and args[0] == "observe":
        observe(Path(args[1]), int(args[2]))
    elif len(args) == 4 and args[0] == "capture":
        capture(Path(args[1]), int(args[2]), int(args[3]))
    elif len(args) == 3 and args[0] == "evidence":
        evidence(Path(args[1]), args[2])
    elif len(args) == 8 and args[0] == "finalize":
        finalize(Path(args[1]), args[2], int(args[3]), args[4] == "true", int(args[5]), args[6], args[7])
    elif len(args) == 3 and args[0] == "report":
        check_report(read(Path(args[1]), 1048576), args[2])
    else:
        raise ValueError("unknown cooperative Code fixture command")


if __name__ == "__main__":
    try:
        main(sys.argv[1:])
    except (KeyError, TypeError, ValueError, OSError, subprocess.SubprocessError):
        print("cooperative Code proof failed; private diagnostics withheld", file=sys.stderr)
        sys.exit(1)
