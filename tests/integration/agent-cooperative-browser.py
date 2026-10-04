#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-only
"""Source-bound Gecko/public-service/real-peer proof; no private offload or answer-quality claim."""
import hashlib
import json
import os
from pathlib import Path
import pwd
import re
import runpy
import stat
import subprocess
import sys
import time
import urllib.request

HERE = Path(__file__).resolve().parent
JOBS = runpy.run_path(str(HERE / "agent-jobs-smoke.py"))
DOCUMENT = runpy.run_path(str(HERE / "agent-public-document-smoke.py"))
read, write, require = JOBS["read"], JOBS["write"], JOBS["require"]
PINS = HERE / "agent-cooperative-browser-pins.json"
QUESTION = DOCUMENT["QUESTION"]
NAME = "agent-cooperative-browser"
TRIAL = None  # Omitted selector preserves the original fixed-135M proof contract.
FILES = (
    "scripts/smoke_cooperative_compute.py", "scripts/smoke_compute_model.py", "scripts/smoke_privacy.py",
    "scripts/stage_firefox.py", "integration/VolparossaCooperativeCompute.sys.mjs",
    "integration/VolparossaCooperativePanel.sys.mjs", "defaults/privacy.json",
)
EXPORT_NAMES = tuple(f"{NAME}-{suffix}.json" for suffix in (
    "smoke", "evidence", "provision", "panel", "observation", "result", "cleanup", "input", "diagnostic",
    "route-diagnostic")) + (
    "a01-expected-peers.json", "agent-jobs-layout.json", "agent-jobs-provision.json", "agent-jobs-private-cleanup.json",
    "content-custody-fetch-live-selection.json", "content-custody-fetch-gates.json",
    "content-provider-custody-fetch-control.json",
    *(f"content-custody-fetch-privacy-{role}.json" for role in JOBS["CUSTODY"]["ROLES"]),
)
FALSE_SCOPE = ("private_offload_proven", "answer_correctness_proven", "global_peer_erasure_claimed",
               "full_firefox_build_proven", "full_alpha_acceptance_claimed")
STATUS_PHASES = frozenset(("wrapper-launch", "namespace-validation", "browser-start", "marionette-connect",
    "sidebar", "prefill", "awaiting-consent", "first-task", "result-received", "result-verified",
    "cancel-task", "cancel-admitted", "cancel-authorized", "cancelled", "panel-cleanup",
    "result-validation", "browser-stop", "complete"))
STATUS_ERRORS = frozenset(("CHECK_FAILED", "OS_ERROR", "SUBPROCESS_FAILED", "INTERRUPTED", "SCRIPT_FAILED",
    "busy", "invalid_request", "handshake_required", "no_such_task", "execution_failed",
    "cleanup_unconfirmed", "unavailable", "not_configured", "invalid_response", "invalid_question",
    "invalid_context", "public_consent_required", "invalid_license", "deadline_exceeded", "storage_bound"))
OBSERVER_PHASES = frozenset(("setup", "owner_binding", "broker_binding", "awaiting_consent",
    "consent_precheck", "consent_authorization", "task_scan", "worker_scan", "result_join",
    "result_authorization", "cancel_worker_scan", "cancel_authorization", "completion_check",
    "worker_cleanup_check", "observation_write", "complete"))
OBSERVER_ERRORS = frozenset(("invariant_or_unknown", "io_not_found", "io_permission", "io_other",
    "json_syntax", "subprocess", "interrupted"))
OBSERVER_INVARIANT_REASONS = {
    "unexpected public task state": "task_identity",
    "unexpected browser task admission": "task_count",
    "original task directory changed": "task_order",
    "invalid retained job identity": "job_identity",
    "unexpected task executor": "provider_binding",
    "observed worker did not receive exact public fragment/derived input": "fragment_binding",
    "unbounded observed worker set": "workers_bound",
    "actual broker not running": "broker_not_running",
    "broker changed during observation": "broker_identity",
    "unexpected broker executable": "broker_executable",
    "broker outside its actual node namespace": "broker_network",
    "actual worker mounts not isolated": "worker_mounts",
    "expected one actual node-owned job input": "dataset_count",
    "worker input is not exact node-local file": "input_inode",
    "worker shares node or guest network namespace": "worker_namespace",
    "worker has external network": "worker_network",
    "worker exposes host authority": "worker_authority",
    "broker mount exposes other node state": "other_node_visibility",
    "broker is not the unprivileged node owner": "broker_owner",
    "runtime lock is aliased": "worker_runtime_lock",
    "observed worker does not hold its runtime lease": "worker_runtime_lease",
    "observed worker ownership differs": "worker_ownership",
    "observed task workers still alive": "worker_cleanup",
    "synthesis published different frontier rows": "synthesis_dataset_binding",
}
EXECUTION_PHASES = frozenset(('input', 'validation', 'directory', 'source_selection', 'provider_selection',
    'source_retention', 'tokenization', 'publication', 'enrollment_save', 'peer_execution', 'refinement', 'synthesis',
    'collection_join', 'result_save', 'complete', 'compaction'))
EXECUTION_ERRORS = frozenset(('none', 'io_not_found', 'io_permission', 'io_other', 'json_syntax',
    'json_data', 'json_eof', 'json_io', 'reaped_worker', 'peer_rpc', 'invariant_or_unknown'))
RECEIPT_PHASES = frozenset(('scan_tree', 'read_handle', 'decode_handle', 'duplicate_handle',
    'read_receipt', 'decode_receipt', 'handle_lookup', 'binding', 'status_validation', 'missing_terminal', 'complete'))
RPC_PHASES = frozenset(('capabilities', 'eligibility', 'submit', 'poll', 'cancel'))
RPC_ERRORS = frozenset(('invalid', 'busy', 'missing', 'expired', 'model_mismatch', 'worker_failed',
                       'result_mismatch', 'unavailable'))
RPC_EVENT_CODES = frozenset(("COMPUTE_RPC_LOCAL_REQUEST_FAILED", "COMPUTE_RPC_LOCAL_REPLY_FAILED",
    "COMPUTE_RPC_ROUTE_SETUP_FAILED", "COMPUTE_RPC_DISCOVERY_FAILED", "COMPUTE_RPC_OFFER_BINDING_FAILED",
    "COMPUTE_RPC_ROUTE_BINDING_FAILED", "COMPUTE_RPC_ROUTE_FLOW_FAILED", "COMPUTE_RPC_PROVIDER_TLS_FAILED",
    "COMPUTE_RPC_CHALLENGE_FAILED", "COMPUTE_RPC_PREEXPORT_CHECK_FAILED", "COMPUTE_RPC_SIGNED_EXCHANGE_FAILED",
    "COMPUTE_RPC_REPLY_BINDING_FAILED", "COMPUTE_RPC_PROVIDER_CLOSE_FAILED", "COMPUTE_RPC_ROUTE_CLOSE_FAILED",
    "COMPUTE_RPC_FINAL_POLICY_FAILED"))
PRESELECTION_REASON_CODES = (
    "PRESELECTION_SAMPLE_NO_EXIT", "PRESELECTION_SAMPLE_INSUFFICIENT_RELAYS",
    "PRESELECTION_SAMPLE_INVALID_POLICY", "PRESELECTION_SAMPLE_INVALID_SNAPSHOT",
    "PRESELECTION_SAMPLE_ENTROPY",
)
# Preserve fixed discovery rejection reasons, not arbitrary event names or raw errors.
# These are event counts, not distinct failed exchanges; one exchange may emit several.
DISCOVERY_FAILURE_EVENT_CODES = frozenset((
    "CONTENT_DISCOVERY_CONTROL_CONNECTION_LOST", "CONTENT_DISCOVERY_RESPONSE_AUTHORITY_REJECTED",
    "CONTENT_DISCOVERY_RESPONSE_TARGETS_UNAVAILABLE", "CONTENT_DISCOVERY_RESPONSE_OFFER_REJECTED",
    "CONTENT_DISCOVERY_RESPONSE_REJECTED", "CONTENT_DISCOVERY_DIAL_FAILED",
    "CONTENT_DISCOVERY_RPC_TIMED_OUT", "CONTENT_DISCOVERY_CONNECTION_CLOSED",
    "CONTENT_DISCOVERY_PROTOCOL_UNSUPPORTED", "CONTENT_DISCOVERY_RPC_IO_FAILED",
    "CONTENT_DISCOVERY_RELAY_NONCE_INVALID", "CONTENT_DISCOVERY_RELAY_SERVICE_UNAVAILABLE",
    "CONTENT_DISCOVERY_RELAY_AUTHORITY_UNAVAILABLE", "CONTENT_DISCOVERY_RELAY_SELF_REJECTED",
    "CONTENT_DISCOVERY_RELAY_CONNECTION_INVALID", "CONTENT_DISCOVERY_RELAY_QUEUE_FULL",
    "CONTENT_DISCOVERY_RELAY_REPLAY_FULL", "CONTENT_DISCOVERY_RELAY_REPLAY_REJECTED",
    "CONTENT_DISCOVERY_RELAY_QUERY_REJECTED", "CONTENT_DISCOVERY_LIMIT_INVALID",
    "CONTENT_DISCOVERY_CALLER_CLOSED", "CONTENT_DISCOVERY_CLIENT_ROLE_REJECTED",
    "CONTENT_DISCOVERY_CLIENT_QUEUE_FULL", "CONTENT_DISCOVERY_CONTROL_MISSING",
    "CONTENT_DISCOVERY_CONTROL_SELF_REJECTED", "CONTENT_DISCOVERY_CONTROL_EXPIRED",
    "CONTENT_DISCOVERY_CONTROL_LIFETIME_SHORT", "CONTENT_DISCOVERY_CONNECTION_REGISTRY_POISONED",
    "CONTENT_DISCOVERY_CONNECTION_ABSENT", "CONTENT_DISCOVERY_CONNECTION_NO_DIRECT",
    "CONTENT_DISCOVERY_REQUEST_REJECTED", "CONTENT_DISCOVERY_LOCAL_DEADLINE",
    "CONTENT_EXACT_ADDRESS_UNAVAILABLE"))
# Lifecycle observations are separate: registration/withdrawal need not be a failure.
PROVIDER_LIFECYCLE_EVENT_CODES = frozenset(("CONTENT_PROVIDER_REGISTERED",
    "CONTENT_PROVIDER_WITHDRAWN", "CONTENT_PROVIDER_REGISTRATION_EXPIRED",
    "CONTENT_PROVIDER_REGISTRATION_RETRY_PENDING", "CONTENT_PROVIDER_REGISTRATION_RECOVERED",
    "CONTENT_PROVIDER_REGISTRATION_FAILED"))
ANSWER_JOININGS = frozenset(("ordered_source_ranges_not_neural_synthesis", "single_source_answer",
    "hierarchical_peer_synthesis", "hierarchical_peer_synthesis_incomplete",
    "incomplete_fragment_answers", "awaiting_fragments_before_peer_synthesis"))
SYNTHESIS_REASONS = frozenset(("worker_output_was_wire_truncated", "worker_produced_empty_answer",
    "legacy_generation_end_unknown", "worker_output_hit_token_limit", "cancelled", "peer_work_pending",
    "invocation_round_budget",
    "reduction_did_not_shrink_no_inputs_discarded", "hierarchy_budget_no_inputs_discarded"))
REFINEMENT_REASONS = frozenset(("complete", "unsupported_or_over_limit", "children_incomplete", "cancelled",
    "source_expired", "round_budget_exhausted", "split_budget_exhausted", "split_level_exhausted",
    "source_cannot_split", "unsupported_child"))
ANSWER_STATUSES = ("eos", "json_boundary", "token_limit", "wire_truncated", "empty",
                   "legacy_unknown", "invalid_or_unknown")


def select_trial(value):
    global TRIAL
    require(value == "discovered-360m" and TRIAL is None, "unknown or repeated cooperative trial")
    TRIAL = value


def trial_fields():
    return {} if TRIAL is None else dict(trial_contract="discovered-360m",
        scenario="agent-cooperative-browser-discovered", model_profile="smollm2-360m-v1",
        provider_selection="protected_provider_eligibility_discovery")


def check_trial(value):
    fields = ("trial_contract", "scenario", "model_profile", "provider_selection")
    require({key: value[key] for key in fields if key in value} == trial_fields(),
            "cooperative trial provenance differs")


def selected_model():
    return JOBS["TRAIN"]["inference_profile"]("smollm2-360m-v1" if TRIAL else "smollm2-135m-v1")


def expected_inventory(peers):
    names = ("client", "bootstrap1", "bootstrap2", *(f"relay{i}" for i in range(6)), "exit", "exit2")
    require(set(peers) == set(names) and all(isinstance(peers[name], str)
            and re.fullmatch(r"[1-9A-HJ-NP-Za-km-z]{32,128}", peers[name]) for name in names)
            and len(set(peers.values())) == len(names), "invalid expected fixture identities")
    return {peers[name]: "0b010" if name.startswith("relay") else "0b100"
            for name in names if name.startswith("relay") or name.startswith("exit")}


def inventory_ready(raw, expected):
    observed = parse_inventory(raw)
    return observed is not None and all(observed.get(peer) == role for peer, role in expected.items())


def parse_inventory(raw):
    # Same six relay/two exit advertisements as A01, read from the real agent's
    # authenticated inventory. This is NOT current capability or route readiness.
    if not isinstance(raw, bytes) or len(raw) > 1048576:
        return None
    try:
        lines = raw.decode("ascii").splitlines()
    except UnicodeError:
        return None
    if len(lines) > 4096:
        return None
    observed = {}
    for line in lines:
        match = re.fullmatch(r"([1-9A-HJ-NP-Za-km-z]{32,128})\troles=(0b[01]{3})\treachability=([0-3])", line)
        if match is None or match[1] in observed:
            return None
        observed[match[1]] = match[2]
    return observed


INVENTORY_ROLES = tuple(f"relay{i}" for i in range(6)) + ("exit", "exit2")
INVENTORY_OUTCOMES = ("none", "timeout", "nonzero", "invalid_reply", "partial", "complete", "os_error")


def closed_inventory(value):
    fields = {"version", "scope", "deadline_seconds", "attempts", "query_timeouts", "query_nonzero",
              "invalid_replies", "last_query_outcome", "last_valid_presence", "ready"}
    if (not isinstance(value, dict) or value.keys() != fields or value["version"] != 1
            or value["scope"] != "last_valid_inventory_not_route_readiness"
            or value["deadline_seconds"] != 60 or type(value["ready"]) is not bool
            or value["last_query_outcome"] not in INVENTORY_OUTCOMES
            or any(type(value[key]) is not int or not 0 <= value[key] <= 601
                   for key in ("attempts", "query_timeouts", "query_nonzero", "invalid_replies"))):
        return None
    presence = value["last_valid_presence"]
    if presence is not None and (not isinstance(presence, dict) or set(presence) != set(INVENTORY_ROLES)
                                or any(type(present) is not bool for present in presence.values())):
        return None
    return value


def await_inventory(work):
    JOBS["guest_work"](work)
    require(TRIAL == "discovered-360m", "inventory wait is only for the discovered fixture")
    peers = read(work / "a01-expected-peers.json", 8192)
    expected = expected_inventory(peers)
    command = [str(work / "bin/volparossa"), "--control-socket",
               str(work / "runtime-client/control/agent.sock"), "peers"]
    deadline = time.monotonic() + 60
    record = dict(version=1, scope="last_valid_inventory_not_route_readiness", deadline_seconds=60,
        attempts=0, query_timeouts=0, query_nonzero=0, invalid_replies=0,
        last_query_outcome="none", last_valid_presence=None, ready=False)
    while (remaining := deadline - time.monotonic()) > 0:
        record["attempts"] += 1
        try:
            # The CLI validates a <=256 KiB RPC frame, <=4096 entries and
            # <=128-byte IDs before printing; stdout is bounded below 1 MiB.
            result = subprocess.run(command, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
                                    check=False, timeout=min(2, remaining))
            observed = parse_inventory(result.stdout) if result.returncode == 0 else None
            if result.returncode != 0:
                record["query_nonzero"] += 1
                record["last_query_outcome"] = "nonzero"
            elif observed is None:
                record["invalid_replies"] += 1
                record["last_query_outcome"] = "invalid_reply"
            else:
                record["last_valid_presence"] = {name: observed.get(peers[name]) == expected[peers[name]]
                                                 for name in INVENTORY_ROLES}
                record["last_query_outcome"] = "complete" if all(record["last_valid_presence"].values()) else "partial"
            if time.monotonic() < deadline and result.returncode == 0 and inventory_ready(result.stdout, expected):
                record["ready"] = True
                write(work / f"{NAME}-inventory.private", record)
                return
        except subprocess.TimeoutExpired:
            record["query_timeouts"] += 1
            record["last_query_outcome"] = "timeout"
        except OSError:
            record["last_query_outcome"] = "os_error"
            write(work / f"{NAME}-inventory.private", record)
            raise
        remaining = deadline - time.monotonic()
        if remaining > 0:
            time.sleep(min(0.1, remaining))
    write(work / f"{NAME}-inventory.private", record)
    raise ValueError("expected advertisement inventory did not arrive within its deadline")


def source_excerpt(original):
    """Literal public README prefix: legacy 3840B, explicit discovered trial 4096B."""
    limit = 4096 if TRIAL else 3840
    require(limit <= len(original) <= 1048576, "bounded public README missing")
    context = original[:limit].decode("utf-8", errors="ignore")
    require(original.startswith(context.encode()), "public README excerpt is not a literal UTF-8 prefix")
    return context


def check_discovered_provision(value):
    model = selected_model()["model"]
    pin_root = HERE / "ml" if (HERE / "ml").is_dir() else HERE.parent.parent / "workers/volparossa-ml"
    selected = read(pin_root / "model-pins.json")
    selected.update(read(pin_root / "model-pins-360m.json"))
    weights = next(item for item in selected["files"] if item["path"] == "model.safetensors")
    require(model["model_id"] == selected["model_id"] and model["model_revision"] == selected["revision"]
            and model["base_weights"] == {key: weights[key] for key in ("bytes", "sha256")}
            and value["success"] is True and value["installed_wheels"] == len(selected["wheels"]) == 38
            and value["model_profile"] == "smollm2-360m-v1" and value["model_id"] == model["model_id"]
            and value["revision"] == model["model_revision"]
            and value["download_bytes"] == sum(item["bytes"] for item in selected["files"] + selected["wheels"]) == 977655758
            and value["model_pins_sha256"] == sha((json.dumps(selected, indent=2) + "\n").encode())
            and value["requirements_sha256"] == sha((pin_root / "requirements.lock").read_bytes())
            and value["budget_bytes"] == 3 * 1024**3 and value["runtime_autofetch_enabled"] is False
            and value["training_performed"] is False, "discovered trial model provision differs")


def check_trial_plan(plan, source):
    if TRIAL is None:
        return DOCUMENT["check_plan"](plan, source)
    profile = selected_model()
    model, limit = profile["model"], profile["prompt_tokens"]
    require(plan["version"] == 1 and plan["source_bytes"] == len(source) and plan["source_sha256"] == sha(source)
            and plan["question_sha256"] == sha(QUESTION.encode()) and plan["model_id"] == model["model_id"]
            and plan["model_revision"] == model["model_revision"] and plan["tokenizer_sha256"] == DOCUMENT["TOKENIZER"]
            and plan["prompt_limit"] == limit and plan.get("synthesis", False) is False
            and 2 <= len(plan["parts"]) <= 128, "discovered trial needs an exact multipart selected-model plan")
    end = 0
    for part in plan["parts"]:
        require(type(part["start"]) is int and type(part["end"]) is int and part["start"] == end
                and 0 < part["end"] - part["start"] <= 4096 and part["end"] <= len(source)
                and type(part["prompt_tokens"]) is int and 1 <= part["prompt_tokens"] <= limit,
                "discovered tokenizer omitted bytes or exceeded selected profile")
        source[part["start"]:part["end"]].decode("utf-8")
        end = part["end"]
    require(end == len(source), "discovered tokenizer omitted original source tail")


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def digest(path):
    with path.open("rb") as source:
        return hashlib.file_digest(source, "sha256").hexdigest()


def paths(work):
    return (work / "agent-jobs-user/browser", work / "state-client/compute-source/public-browser")


def prepare_account_home(path, uid, gid):
    """Create only an absent account home; never chmod or adopt an existing path."""
    require(path.is_absolute() and path.parent.resolve() == path.parent and uid > 0 and gid > 0,
            "invalid fixture account home")
    created = False
    try:
        info = path.lstat()
    except FileNotFoundError:
        path.mkdir(mode=0o700)
        info = path.lstat()
        try:
            if (info.st_uid, info.st_gid) != (uid, gid):
                os.chown(path, uid, gid, follow_symlinks=False)
        except OSError:
            if (path.lstat().st_dev, path.lstat().st_ino) == (info.st_dev, info.st_ino):
                path.rmdir()
            raise
        created = True
        info = path.lstat()
    require(stat.S_ISDIR(info.st_mode) and stat.S_IMODE(info.st_mode) == 0o700
            and (info.st_uid, info.st_gid) == (uid, gid), "account home ownership/mode differs")
    return dict(version=1, created=created, device=info.st_dev, inode=info.st_ino, uid=uid, gid=gid)


def cleanup_account_home(path, marker):
    require(set(marker) == {"version", "created", "device", "inode", "uid", "gid"}
            and marker["version"] == 1 and type(marker["created"]) is bool
            and all(type(marker[key]) is int and marker[key] >= 0 for key in ("device", "inode", "uid", "gid")),
            "invalid fixture home ownership marker")
    if not marker["created"]:
        return
    try:
        info = path.lstat()
    except FileNotFoundError:
        return
    require(stat.S_ISDIR(info.st_mode) and stat.S_IMODE(info.st_mode) == 0o700
            and (info.st_dev, info.st_ino, info.st_uid, info.st_gid)
                == tuple(marker[key] for key in ("device", "inode", "uid", "gid")),
            "fixture-created account home changed")
    path.rmdir()  # Empty only: never recursively remove browser or pre-existing data.


def account_home(work, cleanup=False):
    require(work.parent == Path("/opt") and work.name.startswith("va.") and work.resolve() == work,
            "invalid disposable fixture root")
    marker = work / f"{NAME}-home.json"
    if cleanup and not marker.exists() and not marker.is_symlink():
        return
    require(os.geteuid() == 0 and JOBS["TRAIN"]["socket"].gethostname() == "volparossa-alpha"
            and subprocess.check_output(["systemd-detect-virt"], text=True, timeout=5).strip() == "kvm",
            "account home fixture is disposable-guest-only")
    account = pwd.getpwnam("volparossa")
    home = Path("/var/lib/volparossa")
    require(account.pw_dir == str(home), "unexpected service account home")
    if cleanup:
        cleanup_account_home(home, read(marker))
    else:
        require(not marker.exists() and not marker.is_symlink(), "home ownership marker already exists")
        ownership = prepare_account_home(home, account.pw_uid, account.pw_gid)
        try:
            write(marker, ownership)
        except OSError:
            cleanup_account_home(home, ownership)
            raise


def pins():
    value = read(PINS)
    require(value["version"] == 1 and value["repository"] == "https://github.com/VOLPAROSSA/volparossa-browser"
            and re.fullmatch(r"[0-9a-f]{40}", value["revision"]) and value["revision"] != "0" * 40
            and set(value["files"]) == set(FILES), "exact reviewed browser source pin required")
    for record in value["files"].values():
        require(set(record) == {"bytes", "sha256"} and type(record["bytes"]) is int
                and 0 < record["bytes"] <= 131072 and re.fullmatch(r"[0-9a-f]{64}", record["sha256"]),
                "browser source manifest malformed")
    require(value["runtime"] == read(HERE / "agent-private-task-browser-pins.json")["runtime"],
            "browser runtime changed without an explicit reviewed pin")
    return value


def fetch(url, path, record):
    path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    with urllib.request.urlopen(url, timeout=60) as response, path.open("xb") as output:
        require(response.geturl() == url, "unexpected pinned source redirect")
        total, hashed = 0, hashlib.sha256()
        while data := response.read(min(65536, record["bytes"] + 1 - total)):
            total += len(data)
            require(total <= record["bytes"], "pinned download exceeds expected size")
            hashed.update(data); output.write(data)
    require(total == record["bytes"] and hashed.hexdigest() == record["sha256"], "download provenance differs")


def provision(work):
    require(os.getuid() != 0 and work.parent == Path("/opt") and work.name.startswith("va.")
            and JOBS["TRAIN"]["socket"].gethostname() == "volparossa-alpha"
            and subprocess.check_output(["systemd-detect-virt"], text=True).strip() == "kvm",
            "browser provisioning is disposable-guest-only")
    root, _ = paths(work)
    require(not root.exists() and not root.is_symlink(), "browser fixture must be new")
    root.mkdir(mode=0o700)
    selected = pins()
    for name, record in selected["files"].items():
        fetch(f"https://raw.githubusercontent.com/VOLPAROSSA/volparossa-browser/{selected['revision']}/{name}",
              root / name, record)
    fetch(selected["runtime"]["url"], root / "firefox-esr.deb", selected["runtime"])
    subprocess.run(["dpkg-deb", "--extract", str(root / "firefox-esr.deb"), str(root / "package")],
                   check=True, timeout=60, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    subprocess.run([sys.executable, "-B", str(root / "scripts/stage_firefox.py"),
        "--firefox", str(root / "package/usr/lib/firefox-esr/firefox-esr"),
        "--output", str(root / "build/firefox-esr"), "--without-extensions",
        "--expected-version", selected["runtime"]["version"],
        "--expected-source-stamp", selected["runtime"]["source_stamp"]],
        check=True, timeout=90, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    require(all(digest(root / "build/firefox-esr" / name) == expected
                for name, expected in selected["runtime"]["files"].items()), "staged ESR runtime changed")
    original = (work / "bin/agent-jobs-README.md").read_bytes()
    context = source_excerpt(original)
    write(root / "input.json", dict(question=QUESTION, context=context, license="GPL-3.0-only"))
    write(root / "provision.json", selected)
    if TRIAL:
        check_discovered_provision(read(work / "agent-jobs-user/provision/provision-report.json"))
    print(json.dumps(dict(context_bytes=len(context.encode()), context_sha256=sha(context.encode()),
                         readme_sha256=sha(original), explicit_public_source=True, license="GPL-3.0-only",
                         **trial_fields())))


def marker(path, event):
    value = read(path, 16384)
    require(value["version"] == 1 and value["event"] == event, "browser synchronization marker differs")
    return value


def closed_status(path):
    try:
        info = path.lstat()
        require(stat.S_ISREG(info.st_mode) and info.st_size <= 4096, "invalid status file")
        value = read(path, 4096)
        require(type(value) is dict and set(value) == {"version", "phase", "failure"}
                and type(value["version"]) is int and value["version"] == 1
                and value["phase"] in STATUS_PHASES
                and (value["failure"] is None or value["failure"] in STATUS_ERRORS), "invalid status fields")
        return dict(state="valid", status=value)
    except FileNotFoundError:
        return dict(state="absent")
    except (OSError, ValueError, KeyError, TypeError):
        return dict(state="invalid")


def check_execution_diagnostic(value):
    require(type(value) is dict and type(value.get('version')) is int and value['version'] in (1, 2),
            'invalid closed coordinator version')
    extra = {'execution_complete', 'answer_complete', 'reconciliation'} if value['version'] == 2 else set()
    require(set(value) == {'version', 'phase', 'execution_ok', 'error_class',
        'rpc', 'local_cleanup_confirmed', 'receipts', 'cleanup_confirmed'} | extra
        and value['phase'] in EXECUTION_PHASES and value['error_class'] in EXECUTION_ERRORS
        and all(type(value[name]) is bool for name in ('execution_ok', 'local_cleanup_confirmed', 'cleanup_confirmed')),
        'invalid closed coordinator diagnostic')
    receipt = value['receipts']
    require(type(receipt) is dict and set(receipt) == {'phase', 'handles', 'receipts', 'terminal', 'error', 'confirmed'}
        and receipt['phase'] in RECEIPT_PHASES and receipt['error'] in EXECUTION_ERRORS
        and type(receipt['confirmed']) is bool
        and all(type(receipt[name]) is int and 0 <= receipt[name] <= 16384 for name in ('handles', 'receipts', 'terminal'))
        and receipt['terminal'] <= receipt['handles']
        and value['cleanup_confirmed'] == (value['local_cleanup_confirmed'] and receipt['confirmed']),
        'invalid closed receipt diagnostic')
    def check_rpc(rpc, error):
        if rpc is None:
            return
        require(type(rpc) is dict and rpc.get('category') in
            ('exchange_unconfirmed', 'broker_rejected', 'receipt_validation')
            and rpc.get('phase') in RPC_PHASES, 'invalid closed RPC diagnostic')
        expected = {'category', 'phase'}
        if rpc['category'] == 'broker_rejected':
            expected.add('code')
            require(rpc.get('code') in RPC_ERRORS, 'invalid closed broker code')
        require(set(rpc) == expected and error == 'peer_rpc', 'invalid closed RPC fields')
    check_rpc(value['rpc'], value['error_class'])
    if value['version'] == 2:
        require(all(value[name] is None or type(value[name]) is bool for name in ('execution_complete', 'answer_complete'))
                and (value['answer_complete'] is not True or value['execution_complete'] is True),
                'invalid document completion facts')
        recovery = value['reconciliation']
        require(type(recovery) is dict and set(recovery) == {'attempted', 'terminal_persisted', 'deadline_reached', 'error', 'rpc'}
                and all(type(recovery[name]) is int and 0 <= recovery[name] <= 16384
                        for name in ('attempted', 'terminal_persisted'))
                and recovery['terminal_persisted'] <= recovery['attempted']
                and type(recovery['deadline_reached']) is bool and recovery['error'] in EXECUTION_ERRORS,
                'invalid reconciliation observations')
        check_rpc(recovery['rpc'], recovery['error'])
    return value


def closed_execution(path):
    try:
        info = path.lstat()
        require(stat.S_ISREG(info.st_mode) and info.st_nlink == 1 and info.st_size <= 8192
                and stat.S_IMODE(info.st_mode) == 0o600 and info.st_uid == path.parent.stat().st_uid,
                'invalid coordinator diagnostic file')
        return dict(state='valid', status=check_execution_diagnostic(read(path, 8192)))
    except FileNotFoundError:
        return dict(state='absent')
    except (OSError, ValueError, KeyError, TypeError):
        return dict(state='invalid')


def answer_status_counts(rows):
    """Closed observations only; neither generation validation nor task-success authority."""
    if rows is None:
        return dict(state="absent")
    if type(rows) is not list or len(rows) > 16384:
        return dict(state="invalid")
    counts = dict.fromkeys(ANSWER_STATUSES, 0)
    for row in rows:
        status = "invalid_or_unknown"
        if type(row) is dict:
            generation = row.get("generation")
            if "generation" not in row:
                status = "legacy_unknown"
            elif (type(generation) is dict and generation.get("stop_reason") in
                    ("eos", "json_boundary", "token_limit") and type(row.get("text")) is str
                    and type(row.get("text_truncated")) is bool):
                # Same presentation precedence as peer/batch/output.rs; text is never exported.
                status = ("wire_truncated" if row["text_truncated"] else
                          "empty" if not row["text"].strip() else generation["stop_reason"])
            if "answer_status" in row and row["answer_status"] != status:
                status = "invalid_or_unknown"
        counts[status] += 1
    return dict(state="incomplete" if counts["invalid_or_unknown"] else "valid",
                observed=len(rows), counts=counts)


def closed_refinement(value):
    """Observe retained metadata, never infer child endings from parent flags.

    Source/receipt authority is validated separately by the acceptance checker.
    Historical v1 reports did not retain child generation: that stays absent.
    """
    if value is None:
        return dict(state="absent")
    try:
        require(type(value) is dict and type(value.get("version")) is int and value["version"] in (1, 2),
                "invalid refinement diagnostic version")
        parents, descendants = value.get("parents"), value.get("descendants", [])
        require(type(parents) is list and type(descendants) is list and len(parents) + len(descendants) <= 16
                and (value["version"] != 1 or not descendants), "invalid refinement diagnostic nodes")
        status, incomplete = dict(version=value["version"]), False
        for key in ("enabled", "complete"):
            status[key] = value.get(key) if type(value.get(key)) is bool else None
            incomplete |= status[key] is None
        reason = value.get("reason")
        status["reason"] = reason if type(reason) is str and reason in REFINEMENT_REASONS else None
        incomplete |= status["reason"] is None
        levels = value.get("split_levels")
        status["split_levels"] = levels if type(levels) is int and 1 <= levels <= 4 else None
        incomplete |= status["split_levels"] is None
        if value["version"] == 2:
            require("descendants" in value, "missing descendant diagnostics")
            stops = value.get("stop_reasons")
            known_stops = (type(stops) is list and len(stops) <= len(REFINEMENT_REASONS)
                           and all(type(reason) is str and reason in REFINEMENT_REASONS for reason in stops))
            status["stop_reasons"] = stops if known_stops else None
            incomplete |= not known_stops
        counts = dict.fromkeys(("eos", "json_boundary", "token_limit", "absent", "invalid_or_unknown"), 0)
        completions = dict(complete=0, incomplete=0, unknown=0)
        nodes = []
        for number, parent in enumerate(parents + descendants, 1):
            require(type(parent) is dict and type(parent.get("children")) is list
                    and len(parent["children"]) <= 2, "invalid refinement diagnostic children")
            level = parent.get("level", 1 if number <= len(parents) else None)
            node = dict(ordinal=number, level=level if type(level) is int and 1 <= level <= 4 else None,
                        complete=parent.get("complete") if type(parent.get("complete")) is bool else None, children=[])
            incomplete |= node["level"] is None or node["complete"] is None
            for index, child in enumerate(parent["children"], 1):
                require(type(child) is dict, "invalid refinement diagnostic child")
                projected = dict(ordinal=index)
                for key in ("complete", "answer_complete"):
                    projected[key] = child.get(key) if type(child.get(key)) is bool else None
                    incomplete |= projected[key] is None
                if "text_truncated" in child:
                    projected["text_truncated"] = child["text_truncated"] if type(child["text_truncated"]) is bool else None
                completions["unknown" if projected["answer_complete"] is None else
                            "complete" if projected["answer_complete"] else "incomplete"] += 1
                generation = child.get("generation")
                if generation is None:
                    projected["generation"], ending = dict(state="absent"), "absent"
                elif (type(generation) is dict and type(generation.get("version")) is int
                      and generation["version"] == 1 and type(generation.get("stop_reason")) is str
                      and generation["stop_reason"] in ("eos", "json_boundary", "token_limit")):
                    ending = generation["stop_reason"]
                    projected["generation"] = dict(state="valid", stop_reason=ending)
                else:
                    projected["generation"], ending = dict(state="invalid"), "invalid_or_unknown"
                counts[ending] += 1
                incomplete |= ending in ("absent", "invalid_or_unknown")
                node["children"].append(projected)
            nodes.append(node)
        status.update(nodes=nodes, children_observed=sum(counts.values()), child_answer_complete=completions,
                      child_generation_counts=counts, effective_answers=answer_status_counts(value.get("answers")))
        incomplete |= status["effective_answers"]["state"] != "valid"
        return dict(state="incomplete" if incomplete else "valid", status=status)
    except (ValueError, KeyError, TypeError):
        return dict(state="invalid")


def closed_answer_diagnostic(task):
    """Project the original retained report, not the compact IPC answer or guessed failure text.

    `valid` means the diagnostic could be projected, never that the answer is complete.
    No receipt revalidation, new inference or recursive journal search occurs here.
    """
    try:
        document = task / "document"
        directory = document.lstat()
        require(stat.S_ISDIR(directory.st_mode) and stat.S_IMODE(directory.st_mode) == 0o700
                and directory.st_uid == task.stat().st_uid, "invalid retained document directory")
        path = document / "result.json"
        info = path.lstat()
        require(stat.S_ISREG(info.st_mode) and info.st_nlink == 1 and info.st_size <= 8 * 1048576
                and stat.S_IMODE(info.st_mode) == 0o600 and info.st_uid == directory.st_uid,
                "invalid retained document result")
        value = read(path, 8 * 1048576)
        require(type(value) is dict and type(value.get("version")) is int and value["version"] in (1, 2)
                and value.get("operation") == "compute_public_document", "invalid document result kind")
        incomplete = False
        status = dict(version=1)
        for name in ("complete", "execution_complete", "answer_complete", "interrupted"):
            status[name] = value.get(name) if type(value.get(name)) is bool else None
            incomplete |= status[name] is None
        joining = value.get("joining")
        status["joining"] = joining if type(joining) is str and joining in ANSWER_JOININGS else None
        incomplete |= status["joining"] is None
        status["leaf_answers"] = answer_status_counts(value.get("answers"))
        incomplete |= status["leaf_answers"]["state"] != "valid"
        status["refinement"] = closed_refinement(value.get("refinement"))
        incomplete |= status["refinement"]["state"] not in ("valid", "absent")
        synthesis = value.get("synthesis")
        status["synthesis"] = dict(state="absent")
        if "synthesis" in value:
            require(type(synthesis) is dict, "invalid retained synthesis")
            reason = synthesis.get("reason")
            known_reason = reason is None or (type(reason) is str and reason in SYNTHESIS_REASONS)
            levels = synthesis.get("levels")
            require(type(levels) is list and len(levels) <= 16, "invalid retained synthesis levels")
            projected, seen = [], set()
            for level in levels:
                require(type(level) is dict and type(level.get("level")) is int
                        and 1 <= level["level"] <= 16 and level["level"] not in seen,
                        "invalid retained synthesis level")
                seen.add(level["level"])
                counts = answer_status_counts(level.get("answers"))
                incomplete |= counts["state"] != "valid"
                projected.append(dict(level=level["level"], answers=counts))
            status["synthesis"] = dict(state="valid" if known_reason else "incomplete",
                reason=reason if known_reason else None, levels=projected)
            incomplete |= not known_reason
        return dict(state="incomplete" if incomplete else "valid", status=status)
    except FileNotFoundError:
        return dict(state="absent")
    except (OSError, ValueError, KeyError, TypeError):
        return dict(state="invalid")


def coordinator_diagnostic(state):
    try:
        tasks = task_roots(state)
        return dict(state='valid', tasks=[dict(ordinal=index + 1, answer_diagnostic=closed_answer_diagnostic(task),
            **closed_execution(task / 'execution-diagnostic.json')) for index, task in enumerate(tasks)])
    except FileNotFoundError:
        return dict(state='absent')
    except (OSError, ValueError, KeyError, TypeError):
        return dict(state='invalid')


def closed_observer(path):
    try:
        info = path.lstat()
        require(stat.S_ISREG(info.st_mode) and info.st_nlink == 1 and info.st_size <= 4096
                and stat.S_IMODE(info.st_mode) == 0o600 and info.st_uid == path.parent.stat().st_uid,
                "invalid observer diagnostic file")
        value = read(path, 4096)
        require(type(value) is dict and set(value) == {"version", "phase", "failure", "invariant_reason", "task_count",
            "observed_workers", "cancel_workers", "counts_saturated", "driver_alive"}
            and type(value["version"]) is int and value["version"] == 1
            and value["phase"] in OBSERVER_PHASES
            and (value["failure"] is None or value["failure"] in OBSERVER_ERRORS)
            and (value["invariant_reason"] is None or
                 (value["failure"] == "invariant_or_unknown"
                  and value["invariant_reason"] in OBSERVER_INVARIANT_REASONS.values()))
            and all(type(value[name]) is int and 0 <= value[name] <= maximum
                    for name, maximum in (("task_count", 2), ("observed_workers", 128), ("cancel_workers", 128)))
            and type(value["counts_saturated"]) is bool
            and (value["driver_alive"] is None or type(value["driver_alive"]) is bool),
            "invalid closed observer diagnostic")
        return dict(state="valid", status=value)
    except FileNotFoundError:
        return dict(state="absent")
    except (OSError, ValueError, KeyError, TypeError):
        return dict(state="invalid")


def observer_error(error):
    # Never export exception text: invariant messages can contain private paths/data.
    if isinstance(error, KeyboardInterrupt):
        return "interrupted"
    if isinstance(error, FileNotFoundError):
        return "io_not_found"
    if isinstance(error, PermissionError):
        return "io_permission"
    if isinstance(error, OSError):
        return "io_other"
    if isinstance(error, json.JSONDecodeError):
        return "json_syntax"
    if isinstance(error, subprocess.SubprocessError):
        return "subprocess"
    return "invariant_or_unknown"


def observer_invariant_reason(error):
    # Exact known literals select fixed codes; never copy or interpolate raw errors.
    return OBSERVER_INVARIANT_REASONS.get(str(error)) if type(error) is ValueError else None


def closed_rpc_events(path, baseline, query_code):
    require(type(baseline) is int and baseline > 0 and type(query_code) is int and 0 <= query_code <= 255,
            "invalid RPC event observation arguments")
    if query_code != 0:
        return dict(state="query_failed")
    try:
        info = path.lstat()
        require(stat.S_ISREG(info.st_mode) and info.st_nlink == 1 and info.st_size <= 262144
                and stat.S_IMODE(info.st_mode) == 0o600 and info.st_uid == os.geteuid(), "invalid private RPC event file")
        records = []
        counts = dict.fromkeys(sorted(RPC_EVENT_CODES), 0)
        discovery_counts = dict.fromkeys(sorted(DISCOVERY_FAILURE_EVENT_CODES), 0)
        provider_counts = dict.fromkeys(sorted(PROVIDER_LIFECYCLE_EVENT_CODES), 0)
        for line in path.read_text(encoding="ascii").splitlines():
            match = re.fullmatch(r"([0-9]{1,20})\tlevel=([0-9])\tevent=([A-Z0-9_]{1,96})\tsession=[0-9a-f]{0,64}\tpath=(?:-|[0-9]{1,10})", line)
            require(match is not None, "invalid bounded RPC event record")
            timestamp = int(match[1])
            require(timestamp > 0 and (not records or timestamp >= records[-1]), "RPC event clock regressed")
            records.append(timestamp)
            if timestamp > baseline:
                for group in (counts, discovery_counts, provider_counts):
                    if match[3] in group:
                        group[match[3]] += 1
        require(len(records) <= 1000, "RPC event ring exceeded")
        return dict(state="valid", baseline_unix_ms=baseline, limit=1000, records=len(records),
            window_covers_baseline=bool(records) and records[0] <= baseline,
            matching_failures=sum(counts.values()), counts=counts,
            discovery_failure_events=sum(discovery_counts.values()), discovery_counts=discovery_counts,
            provider_lifecycle_counts=provider_counts)
    except FileNotFoundError:
        return dict(state="absent")
    except (OSError, ValueError, UnicodeError):
        return dict(state="invalid")


def closed_preselection_events(path):
    # Metadata from the existing cleanup capture, not attribution to the final
    # Connect attempt or proof that the retained ring covers the whole run.
    value = dict(version=1, state="unknown", observed_reason="unknown", uncertainty="absent",
        scope="retained_client_log_ring_not_last_attempt_proof", limit=400,
        records=None, counts=None, unrecognized_reason_records=None)
    try:
        info = path.lstat()
        require(stat.S_ISREG(info.st_mode) and info.st_nlink == 1 and info.st_size <= 131072
                and stat.S_IMODE(info.st_mode) == 0o600 and info.st_uid == os.geteuid(),
                "invalid private preselection event file")
        lines = path.read_text(encoding="ascii").splitlines()
        require(len(lines) <= 400, "preselection event ring exceeded")
        counts = dict.fromkeys(PRESELECTION_REASON_CODES, 0)
        unrecognized, previous = 0, 0
        for line in lines:
            match = re.fullmatch(r"([0-9]{1,20})\tlevel=([0-9])\tevent=([A-Z0-9_]{1,96})\tsession=[0-9a-f]{0,64}\tpath=(?:-|[0-9]{1,10})", line)
            require(match is not None, "invalid bounded preselection event record")
            timestamp = int(match[1])
            require(timestamp > 0 and timestamp >= previous, "preselection event clock regressed")
            previous = timestamp
            if match[3] in counts:
                counts[match[3]] += 1
            elif match[3].startswith("PRESELECTION_SAMPLE_"):
                unrecognized += 1
        value.update(records=len(lines), counts=counts, unrecognized_reason_records=unrecognized)
        observed = [code for code, count in counts.items() if count]
        if len(lines) == 400:
            value["uncertainty"] = "ring_at_capacity"
        elif unrecognized:
            value["uncertainty"] = "unrecognized"
        elif len(observed) > 1:
            value["uncertainty"] = "ambiguous"
        elif not observed:
            value["uncertainty"] = "no_signal"
        else:
            value.update(state="known", observed_reason=observed[0], uncertainty=None)
    except FileNotFoundError:
        pass
    except (OSError, ValueError, UnicodeError):
        value["uncertainty"] = "invalid"
    return value


def diagnostic(work, browser_code, observer_code, baseline, rpc_query_code):
    JOBS["guest_work"](work)
    require(0 <= browser_code <= 255 and 0 <= observer_code <= 255, "invalid process exit status")
    root, state = paths(work)
    write(work / f"{NAME}-diagnostic.json", dict(version=3, browser_exit_status=browser_code,
        observer_exit_status=observer_code, browser=closed_status(root / "build/cooperative-proof/browser-status.json"),
        observer=closed_observer(work / f"{NAME}-observer-status.private"),
        coordinator=coordinator_diagnostic(state),
        rpc_events=closed_rpc_events(work / f"{NAME}-rpc-events.private", baseline, rpc_query_code)))


def authorize(path, event):
    require(not path.exists() and not path.is_symlink(), "consent marker already exists")
    write(path, dict(version=1, event=event))
    os.chown(path, path.parent.stat().st_uid, path.parent.stat().st_gid)


def task_roots(state):
    roots = []
    for path in state.iterdir():
        if path.name.startswith("task-"):
            info = path.lstat()
            require(re.fullmatch(r"task-[0-9a-f]{32}", path.name) and stat.S_ISDIR(info.st_mode)
                    and stat.S_IMODE(info.st_mode) == 0o700 and info.st_uid != 0, "unexpected public task state")
            roots.append(path)
    require(len(roots) <= 2, "unexpected browser task admission")
    return sorted(roots, key=lambda item: item.stat().st_ctime_ns)


def scan_workers(work, document, layout, brokers, observed):
    for path in sorted(document.glob("**/attempt-????/job-?.json")):
        handle = read(path, 16384)
        binding = handle["binding"]
        key = binding["job_id"]
        if key in observed:
            continue
        require(re.fullmatch(r"[0-9a-f]{32}", key), "invalid retained job identity")
        node = next((n for n in layout["provider_nodes"] if layout["provider_keys"][n] == handle["provider_key"]), None)
        require(node is not None, "unexpected task executor")
        current = JOBS["worker_snapshot"](work, node, brokers[node], binding["dataset_sha256"])
        if current and JOBS["alive"](current["worker"]):
            relative = path.relative_to(document).as_posix()
            match = re.match(r"synthesis/level-([0-9]{2})-group-[0-9]{4}/", relative)
            data = json.loads(current["dataset_json"])
            require(data["version"] == (3 if match else 2)
                    and binding["dataset_sha256"] == current["dataset_file"]["sha256"]
                    and handle["capabilities"]["public_inference_only"] is True,
                    "observed worker did not receive exact public fragment/derived input")
            observed[key] = dict(node=node, level=int(match[1]) if match else None,
                handle_path=relative, provider_key=handle["provider_key"], dataset_sha256=binding["dataset_sha256"],
                broker=current["broker"], worker=current["worker"], owned_processes=current["owned_processes"],
                isolated_live_worker=True, base_model_sha256=handle["capabilities"]["model"]["base_weights"]["sha256"])
    require(len(observed) <= 128, "unbounded observed worker set")


def task_processes(entry):
    # descendants() deliberately includes its root. The validated broker is a
    # persistent service, stopped by the later fixture cleanup, not by a task.
    # Retain every other observed process, including sandbox parents/tokenizers;
    # never remove a live process merely because the model worker has ended.
    broker, worker, family = entry["broker"], entry["worker"], entry["owned_processes"]
    require(isinstance(family, list) and 2 <= len(family) <= 32
            and all(isinstance(member, dict) and set(member) == {"pid", "start_ticks"}
                    and type(member["pid"]) is int and member["pid"] > 0
                    and type(member["start_ticks"]) is int and member["start_ticks"] >= 0 for member in family)
            and len({member["pid"] for member in family}) == len(family)
            and family.count(broker) == 1 and worker != broker and worker in family,
            "observed worker ownership differs")
    return [member for member in family if member != broker]


def check_task_workers_ended(entries):
    require(not any(JOBS["alive"](member) for entry in entries for member in task_processes(entry)),
            "observed task workers still alive")


def exact_bytes(path, maximum=1048576):
    JOBS["file_hash"](path, maximum)
    return path.read_bytes()


def encoded(value):
    return json.dumps(value, ensure_ascii=False, separators=(",", ":"), allow_nan=False).encode()


def checked_receipt_input(path, receipt, document, enrollment):
    """Bind actual worker input to its retained signed source, not result flags."""
    handle, binding = receipt["handle"], receipt["handle"]["binding"]
    package, work = path.parents[1], path.parents[2]
    raw = exact_bytes(package / "dataset.json")
    manifest = exact_bytes(package / "manifest.bin", 65536)
    data = json.loads(raw)
    fields = JOBS["CUSTODY"]["fields"]
    body = fields(fields(manifest, 65536)[1], 65536)
    metadata = fields(body[8], 65536)
    require(enrollment["selected_at_unix_seconds"] <= body[3] < enrollment["expires_at_unix_seconds"],
            "worker publication escaped original lifetime")
    authority = dict(enrollment, selected_at_unix_seconds=body[3])
    manifest_id = DOCUMENT["manifest"](manifest, raw, authority, metadata[1].decode(), metadata[3].decode())
    source = exact_bytes(document / "source.manifest", 65536)
    require(manifest_id == binding["dataset_manifest_id"]
            and data["visibility"] == "public" and data["license"] == enrollment["license"]
            and data["source_manifest_hex"] == source.hex()
            and enrollment["selected_at_unix_seconds"] < binding["expires_unix_seconds"] <= enrollment["expires_at_unix_seconds"]
            and binding["task"] == dict(kind="answer_public_question_v1", question=enrollment["public_question"])
            and handle["capabilities"]["public_inference_only"] is True,
            "worker signed source/task/lifetime differs")
    require(metadata[3].decode() == (DOCUMENT["PROFILE"] if data["version"] == 2 else DOCUMENT["SYNTHESIS"]["PROFILE"]),
            "worker publication content type differs")
    selected = binding["row_indices"]
    require(selected and len(selected) == len(set(selected))
            and all(type(index) is int and 0 <= index < len(data["inference"]) for index in selected),
            "worker selected invalid input rows")
    derived = dict(data, inference=[data["inference"][index] for index in selected])
    require(sha(encoded(derived)) == binding["dataset_sha256"], "worker input lost exact signed rows")
    workflow = read(work / "workflow.json")
    require(workflow["provider_keys"] == enrollment["provider_keys"]
            and workflow.get("model_fingerprint") == enrollment["model_fingerprint"],
            "worker changed the frozen executor cohort")
    handles = [read(item, 16384) for item in sorted(path.parent.glob("job-?.json"))]
    require(sum(saved == handle for saved in handles) == 1
            and path.name == f"receipt-{binding['job_id']}.json", "receipt has no exact retained job")
    return data


def checked_answer(answer, reports, complete=True):
    record = reports[answer["job_id"]]
    handle, status, report = record["handle"], record["status"], record["report"]
    index = answer["output_index"]
    require(type(index) is int and 0 <= index < len(report["outputs"]), "answer output identity missing")
    output = report["outputs"][index]
    require(output["sample_index"] == index and answer["provider_key"] == handle["provider_key"]
            and answer["report_sha256"] == status["report_sha256"]
            and answer["package_manifest_id"] == handle["binding"]["dataset_manifest_id"]
            and answer["model_fingerprint"] == handle["binding"]["model_fingerprint"]
            and all(answer[key] == output[key] for key in ("text", "generated_tokens", "generation", "text_truncated")),
            "answer differs from its immutable native receipt")
    JOBS["TRAIN"]["check_generation"](output, require_eos=complete, model_profile=selected_model()["name"])
    require(output["text_truncated"] is False and output["text"].strip(), "incomplete answer cannot enter frontier")
    return record


def source_answer(answer, reports, source, complete=True):
    record = checked_answer(answer, reports, complete)
    data, binding = record["data"], record["handle"]["binding"]
    row_index = binding["row_indices"][answer["output_index"]]
    start, end = answer["source_start"], answer["source_end"]
    require(type(start) is int and type(end) is int and 0 <= start < end <= len(source)
            and data["version"] == 2 and data["inference"][row_index] == dict(
                question=QUESTION, context=source[start:end].decode(), start=start, end=end),
            "answer is not the exact original signed source range")
    return record


def answer_bytes(answer):
    # Rust synthesis::Answer/Generation field order is part of this retained commitment.
    fields = ("text", "provider_key", "job_id", "report_sha256", "package_manifest_id", "model_fingerprint",
              "output_index", "source_start", "source_end", "generated_tokens", "text_truncated", "generation")
    value = {key: answer[key] for key in fields}
    value["generation"] = {key: answer["generation"][key] for key in
                           ("version", "stop_reason", "max_new_tokens", "model_profile")}
    return encoded(value)


def checked_refinement_children(document, source, enrollment, parent, original, frontier, reports,
                                address=(), descendants=None, visited=None, child_jobs=None, repaired_jobs=None):
    descendants = {} if descendants is None else descendants
    visited = set() if visited is None else visited
    child_jobs = set() if child_jobs is None else child_jobs
    repaired_jobs = set() if repaired_jobs is None else repaired_jobs
    root = document / f"refinement/leaf-{parent['part_index']:04}"
    for bit in address:
        root = root / f"child-{bit}" / "refinement"
    require(parent["parent_job_id"] == original["job_id"]
            and parent["parent_report_sha256"] == original["report_sha256"]
            and parent["parent_source_start"] == original["source_start"]
            and parent["parent_source_end"] == original["source_end"]
            and len(parent["children"]) == 2 and original["generation"]["stop_reason"] == "token_limit",
            "refinement did not retain exact failed parent")
    intent_bytes = exact_bytes(root / "intent.json")
    intent = json.loads(intent_bytes)
    expected = dict(version=1, part_index=parent["part_index"], parent_sha256=sha(answer_bytes(original)),
        parent_report_sha256=original["report_sha256"], parent_job_id=original["job_id"],
        parent_source_start=original["source_start"], parent_source_end=original["source_end"],
        source_manifest_id=enrollment["source_manifest_id"], source_sha256=sha(source), source_bytes=len(source),
        model_profile=selected_model()["name"], model_fingerprint=original["model_fingerprint"],
        publisher_key=enrollment["publisher_key"], provider_keys=enrollment["provider_keys"],
        selected_at_unix_seconds=enrollment["selected_at_unix_seconds"],
        expires_at_unix_seconds=enrollment["expires_at_unix_seconds"], license=enrollment["license"],
        question_sha256=sha(QUESTION.encode()), children=[dict(start=child["start"], end=child["end"],
            source_sha256=sha(source[child["start"]:child["end"]])) for child in parent["children"]])
    require(intent == expected and sha(intent_bytes) == parent["intent_sha256"],
            "refinement intent changed original authority or receipt")
    previous_end, answers = original["source_start"], []
    for index, child in enumerate(parent["children"]):
        start, end = child["start"], child["end"]
        require(type(start) is int and type(end) is int and start == previous_end < end <= original["source_end"]
                and child["complete"] is True and type(child["answer_complete"]) is bool,
                "refinement children omitted, overlapped or remain incomplete")
        child_root = root / f"child-{index}"
        text = source[start:end].decode()
        require(text.strip(), "refinement child source is empty")
        planner_bytes = exact_bytes(child_root / "planner-input.json")
        require(json.loads(planner_bytes) == dict(version=1, model_profile=selected_model()["name"],
            visibility="public", license=enrollment["license"], document=text, question=QUESTION),
            "refinement tokenizer received another source")
        plan = read(child_root / "document-plan.json")
        profile = selected_model()
        require(plan["version"] == 1 and plan["source_bytes"] == end - start
                and plan["source_sha256"] == sha(text.encode()) and plan["question_sha256"] == sha(QUESTION.encode())
                and plan["model_id"] == profile["model"]["model_id"]
                and plan["model_revision"] == profile["model"]["model_revision"]
                and plan["tokenizer_sha256"] == DOCUMENT["TOKENIZER"] and plan["prompt_limit"] == 1024
                and plan.get("synthesis", False) is False and len(plan["parts"]) == 1
                and plan["parts"][0]["start"] == 0 and plan["parts"][0]["end"] == end - start
                and 0 < plan["parts"][0]["prompt_tokens"] <= 1024, "refinement lacks an exact measured child plan")
        planner = read(child_root / "tokenizer-report.json")
        artifacts = [path for path in child_root.glob("tokenizer*/document-plan.json")
                     if read(path) == plan and planner["artifacts"] == [dict(relative_path="document-plan.json",
                         bytes=path.stat().st_size, sha256=sha(exact_bytes(path)))]]
        require(planner["mode"] == "plan_document" and planner["status"] == "ok" and planner["device"] == "cpu"
                and planner["model_weights_loaded"] is False and planner["updates_completed"] == 0
                and planner["dataset"]["sha256"] == sha(planner_bytes) and len(artifacts) == 1,
                "refinement tokenizer has no actual retained artifact")
        DOCUMENT["check_supervisor"](planner)
        raw = exact_bytes(child_root / "dataset.json")
        signed = exact_bytes(child_root / "dataset.manifest", 65536)
        manifest_id = DOCUMENT["manifest"](signed, raw, enrollment,
            f"refined-leaf-{parent['part_index']:04}-child-{index}", DOCUMENT["PROFILE"])
        require(manifest_id == child["package_manifest_id"], "refinement child manifest changed")
        matches = [(job, record) for job, record in reports.items()
                   if record["handle"]["binding"]["dataset_manifest_id"] == manifest_id
                   and record["path"].is_relative_to(child_root / "work")]
        require(len(matches) == 1, "refinement child has no unique terminal receipt")
        job, record = matches[0]
        output = record["report"]["outputs"][0]
        answer = {key: output[key] for key in ("text", "generated_tokens", "text_truncated", "generation")}
        answer.update(provider_key=record["handle"]["provider_key"], job_id=job,
            report_sha256=record["status"]["report_sha256"], package_manifest_id=manifest_id,
            model_fingerprint=record["handle"]["binding"]["model_fingerprint"],
            output_index=0, source_start=start, source_end=end)
        source_answer(answer, reports, source, complete=False)
        require(answer["source_start"] == start and answer["source_end"] == end and answer["output_index"] == 0
                and record["path"].is_relative_to(child_root / "work")
                and record["data"] == json.loads(raw) and len(record["data"]["inference"]) == 1
                and exact_bytes(child_root / "work/package-0000/dataset.json") == raw
                and exact_bytes(child_root / "work/package-0000/manifest.bin", 65536) == signed,
                "refinement answer is not the exact child execution")
        eos = output["generation"]["stop_reason"] == "eos"
        require(child["answer_complete"] is eos, "token-limited answer or child ending was relabelled")
        for field in ("generation", "generated_tokens", "text_truncated"):
            if field in child:
                require(child[field] == output[field], "refinement child metadata changed its receipt")
        require(job not in child_jobs, "refinement reused a child receipt")
        child_jobs.add(job)
        key = (parent["part_index"], address + (index,))
        if eos:
            found = [saved for saved in frontier if saved["package_manifest_id"] == manifest_id]
            require(found == [answer], "refinement child has no unique effective answer")
            answers.append(answer)
        else:
            # A terminal token-limit receipt is retained, never promoted to EOS.
            # Only its own source/receipt-bound descendant may replace it.
            require(output["generation"]["stop_reason"] == "token_limit" and key in descendants
                    and key not in visited, "token-limited answer lacks verified descendant repair")
            visited.add(key)
            repaired_jobs.add(job)
            answers.extend(checked_refinement_children(document, source, enrollment, descendants[key], answer,
                frontier, reports, key[1], descendants, visited, child_jobs, repaired_jobs))
        previous_end = end
    require(parent["complete"] is all(child["answer_complete"] for child in parent["children"]),
            "parent ending was relabelled from descendant results")
    require(previous_end == original["source_end"], "refinement lost original source tail")
    return answers


def check_synthesis_frontier(document, enrollment, result, reports, frontier):
    """Verify that the REAL synthesis inputs use the checked effective frontier."""
    synthesis = DOCUMENT["SYNTHESIS"]
    for number, level in enumerate(result["synthesis"]["levels"], 1):
        require(level["level"] == number and level["complete"] is True
                and level["parents"] == len(frontier) and len(frontier) > 1
                and len(level["groups"]) == (len(frontier) + 63) // 64,
                "synthesis omitted the effective frontier")
        expected_packages = {}
        for group_index, group in enumerate(level["groups"]):
            root = document / f"synthesis/level-{number:02}-group-{group_index:04}"
            parents = frontier[group_index * 64:group_index * 64 + 64]
            require(read(root / "parents.json") == parents,
                    "synthesis consumed failed or changed parents")
            group_record = read(root / "group.json")
            require(group_record["parents_sha256"] == sha(exact_bytes(root / "parents.json"))
                    and group_record["source_manifest_id"] == enrollment["source_manifest_id"]
                    and group_record["parent_offset"] == group_index * 64 and group_record["level"] == number,
                    "synthesis frontier commitment differs")
            plan = read(root / "document-plan.json")
            combined, rows = synthesis["expected_rows"](parents, plan["parts"], QUESTION, group_index * 64)
            require(group["parts"] == len(rows) and group["input_sha256"] == sha(combined),
                    "synthesis frontier input accounting differs")
            previous_end = 0
            for part in plan["parts"]:
                require(part["start"] == previous_end < part["end"] <= len(combined),
                        "synthesis input coverage differs")
                previous_end = part["end"]
            require(previous_end == len(combined), "synthesis omitted frontier bytes")
            for index in range((len(rows) + 3) // 4):
                package = root / f"package-{index:04}"
                data = read(package / "dataset.json")
                require(data == dict(version=3, visibility="public", license=enrollment["license"],
                    source_manifest_hex=exact_bytes(document / "source.manifest", 65536).hex(), level=number,
                    claim_scope=synthesis["CLAIM"], model_profile=selected_model()["name"],
                    inference=rows[index * 4:index * 4 + 4]),
                    "synthesis published different frontier rows")
                expected_packages[sha(exact_bytes(package / "dataset.manifest", 65536))] = data
        seen = set()
        for answer in level["answers"]:
            record = checked_answer(answer, reports)
            manifest_id = answer["package_manifest_id"]
            require(record["data"] == expected_packages[manifest_id], "synthesis receipt used another frontier")
            row = record["handle"]["binding"]["row_indices"][answer["output_index"]]
            require((manifest_id, row) not in seen, "synthesis duplicated a frontier result")
            seen.add((manifest_id, row))
            inputs = record["data"]["inference"][row]["inputs"]
            require(answer["source_start"] == min(item["source_start"] for item in inputs)
                    and answer["source_end"] == max(item["source_end"] for item in inputs),
                    "synthesis output changed original source coverage")
        require(seen == {(key, row) for key, data in expected_packages.items()
                         for row in range(len(data["inference"]))}, "synthesis lacks a frontier result")
        frontier = level["answers"]
    require(len(frontier) == 1 and result["synthesized_answer"] == frontier[0],
            "final answer is not the verified frontier reduction")


def checked_frontier(document, source, enrollment, plan, result, reports):
    require(enrollment.get("refine_incomplete") is True, "source refinement was not owner-enrolled")
    originals = []
    require(len(result["answers"]) == len(plan["parts"]), "original leaf answers disappeared")
    require(len(enrollment["packages"]) == (len(plan["parts"]) + 3) // 4, "original package enrollment changed")
    for index, (original, part) in enumerate(zip(result["answers"], plan["parts"])):
        record = reports[original["job_id"]]
        package = enrollment["packages"][index // 4]
        require(original["source_part"] == index and original["start"] == part["start"]
                and original["end"] == part["end"]
                and original["context_sha256"] == sha(source[part["start"]:part["end"]])
                and record["path"].relative_to(document).parts[0] == f"package-{index // 4:04}"
                and package["manifest_id"] == original["package_manifest_id"]
                and package["dataset_sha256"] == sha(exact_bytes(document / f"package-{index // 4:04}/dataset.json"))
                and package["first_part"] == index // 4 * 4 and package["rows"] == min(4, len(plan["parts"]) - index // 4 * 4),
                "original leaf identity or range changed")
        output = record["report"]["outputs"][0]
        answer = {key: original[key] for key in ("text", "provider_key", "job_id", "report_sha256",
                  "package_manifest_id", "generated_tokens", "text_truncated", "generation")}
        answer.update(model_fingerprint=record["handle"]["binding"]["model_fingerprint"], output_index=0,
                      source_start=part["start"], source_end=part["end"])
        source_answer(answer, reports, source, complete=False)
        eos = output["generation"]["stop_reason"] == "eos"
        require(original["answer_complete"] is eos and original["answer_status"] == output["generation"]["stop_reason"],
                "original incomplete answer was relabelled complete")
        originals.append(answer)
    limited = {index for index, answer in enumerate(originals) if answer["generation"]["stop_reason"] == "token_limit"}
    refinement = result.get("refinement")
    child_jobs, repaired_jobs, descendants, visited = set(), set(), {}, set()
    split_count, deepest = len(limited), 1
    if limited:
        levels = enrollment.get("refinement_levels", 1)
        require(type(levels) is int and 1 <= levels <= 4, "invalid enrolled refinement depth")
        require(type(refinement) is dict and type(refinement["version"]) is int
                and refinement["version"] == (1 if levels == 1 else 2) and refinement["enabled"] is True
                and refinement["complete"] is True and refinement["reason"] == "complete"
                and refinement["maximum_refined_leaves"] == 16 and refinement["split_levels"] == levels
                and 1 <= len(limited) <= 16 and refinement["eligible_leaves"] == refinement["refined_leaves"] == len(limited)
                and refinement["original_parts"] == len(originals), "complete bounded refinement missing")
        parents = refinement["parents"]
        require(len(parents) == len(limited) and {parent["part_index"] for parent in parents} == limited,
                "refinement omitted or duplicated an original failed leaf")
        if levels > 1:
            nested = refinement["descendants"]
            require(type(nested) is list and len(parents) + len(nested) <= 16,
                    "refinement exceeded shared split budget")
            for parent in parents + nested:
                address = parent["address"]
                require(type(parent["part_index"]) is int and parent["part_index"] in limited
                        and type(address) is list and len(address) < levels
                        and all(type(bit) is int and bit in (0, 1) for bit in address)
                        and type(parent["level"]) is int and parent["level"] == len(address) + 1,
                        "refinement descendant address or level differs")
            require(all(parent["address"] == [] for parent in parents), "original refinement root moved")
            for child in nested:
                key = (child["part_index"], tuple(child["address"]))
                require(key[1] and key not in descendants, "duplicate or root descendant")
                descendants[key] = child
            split_count = len(parents) + len(nested)
            deepest = max(parent["level"] for parent in parents + nested)
            require(refinement["maximum_child_jobs"] == 32 and refinement["retained_splits"] == split_count
                    and refinement["remaining_splits"] == 16 - split_count and refinement["deepest_level"] == deepest
                    and refinement["unresolved_leaves"] == 0
                    and refinement["source_admission_expires_unix_seconds"] == enrollment["expires_at_unix_seconds"],
                    "refinement shared accounting or original expiry differs")
        replacements = {}
        for parent in parents:
            index, original = parent["part_index"], originals[parent["part_index"]]
            replacements[index] = checked_refinement_children(document, source, enrollment, parent,
                original, refinement["answers"], reports, (), descendants, visited, child_jobs, repaired_jobs)
        require(visited == set(descendants), "unreachable or unnecessary descendant claimed")
        frontier = [child for index, original in enumerate(originals) for child in replacements.get(index, [original])]
        require(refinement["answers"] == frontier, "reported refinement is not the exact effective frontier")
    else:
        require(refinement is None, "refinement claimed without a failed original leaf")
        frontier = originals
    previous_end = 0
    for answer in frontier:
        source_answer(answer, reports, source)
        require(answer["source_start"] == previous_end, "effective frontier overlaps or omits original bytes")
        previous_end = answer["source_end"]
    require(previous_end == len(source), "effective frontier omitted original tail")
    incomplete_jobs = {key for key, record in reports.items()
                       if any(output["generation"]["stop_reason"] != "eos" for output in record["report"]["outputs"])}
    require(incomplete_jobs == {originals[index]["job_id"] for index in limited} | repaired_jobs,
            "an incomplete child or synthesis output was accepted")
    used = {answer["job_id"] for answer in originals + frontier} | child_jobs
    used.update(answer["job_id"] for level in result["synthesis"]["levels"] for answer in level["answers"])
    require(used == set(reports), "a native receipt lies outside the original/refinement/synthesis frontier")
    check_synthesis_frontier(document, enrollment, result, reports, frontier)
    summary = dict(version=1, enabled=True, applied=bool(limited), original_parts=len(originals),
        refined_leaves=len(limited), effective_parts=len(frontier), original_token_limited_outputs=len(limited),
        exact_frontier_verified=True)
    if refinement is not None and refinement["version"] == 2:
        summary.update(version=2, retained_splits=split_count, deepest_level=deepest,
                       intermediate_token_limited_outputs=len(repaired_jobs))
    return summary


def retained_result(document, fixture, layout, observed):
    source = (document / "source.txt").read_bytes()
    require(source == fixture["context"].encode(), "public coordinator source changed")
    enrollment, plan, result = (read(document / name, 8 * 1048576)
        for name in ("document.json", "document-plan.json", "result.json"))
    check_trial_plan(plan, source)
    selected = [layout["provider_keys"][node] for node in layout["provider_nodes"]]
    if TRIAL:
        require(len(enrollment["provider_keys"]) == len(selected) == 2
                and set(enrollment["provider_keys"]) == set(selected)
                and enrollment["model_fingerprint"] == selected_model()["fingerprint"]
                and enrollment.get("replace_peers", False) is False,
                "discovered enrollment changed the selected cohort")
        selected = enrollment["provider_keys"]
    require(enrollment["provider_keys"] == selected and enrollment["synthesize"] is True
            and result["joining"] == "hierarchical_peer_synthesis"
            and result["execution_complete"] is True and result["complete"] is True
            and result["semantic_completeness_proven"] is False
            and result["source_sha256"] == sha(source) and result["license"] == fixture["license"]
            and result["public_question"] == fixture["question"], "real hierarchical result absent")
    source_id = DOCUMENT["manifest"]((document / "source.manifest").read_bytes(), source,
                                    enrollment, "document-source", "text/plain")
    require(source_id == result["source_manifest_id"], "source manifest not retained")
    levels = result["synthesis"]["levels"]
    require((1 if TRIAL else 2) <= len(levels) <= 16 and all(level["complete"] is True for level in levels)
            and {entry["level"] for entry in observed.values() if entry["level"] is not None}
                == {level["level"] for level in levels}, "actual worker missing at a reduction level")
    require({entry["node"] for entry in observed.values() if entry["level"] is None}
            == set(layout["provider_nodes"]), "both real fragment peers were not observed")
    ids, provider_keys, reports = set(), set(), {}
    for path in sorted(document.glob("**/attempt-????/receipt-*.json")):
        receipt = read(path, 1048576)
        handle, status = receipt["handle"], receipt["status"]
        binding = handle["binding"]
        require(status["state"] == "complete" and status["binding"] == binding
                and status["report_sha256"] == sha(status["report_json"].encode())
                and binding["job_id"] not in ids and handle["provider_key"] in selected,
                "exact terminal peer receipt missing")
        report = json.loads(status["report_json"])
        require(report["mode"] == "infer" and report["status"] == "ok" and report["device"] == "cpu"
                and report["dataset"]["version"] in (2, 3)
                and report["dataset"]["sha256"] == binding["dataset_sha256"]
                and report["dataset"]["source_manifest_sha256"] == source_id
                and report["model"]["files"]["model.safetensors"]["sha256"] == selected_model()["model"]["base_weights"]["sha256"],
                "real pinned worker report changed")
        if TRIAL:
            profile = selected_model()
            require(handle["capabilities"]["model"] == profile["model"]
                    and handle["capabilities"]["max_rows"] == 1
                    and handle["capabilities"]["max_job_seconds"] == 600
                    and binding["model_fingerprint"] == handle["capabilities"]["model_fingerprint"] == profile["fingerprint"]
                    and report["model"]["id"] == profile["model"]["model_id"]
                    and report["model"]["revision"] == profile["model"]["model_revision"]
                    and report["model"]["files"]["model.safetensors"] == profile["model"]["base_weights"]
                    and report["supervisor"]["rss_limit_bytes"] == 3 * 1024**3
                    and report["threads"] == 2 and len(report["outputs"]) == 1,
                    "discovered worker profile/resource binding differs")
            for output in report["outputs"]:
                # Historical token-limit receipts stay unchanged; only an independently
                # checked refinement may replace them in the effective frontier below.
                JOBS["TRAIN"]["check_generation"](output, model_profile=profile["name"])
                require(output["text_truncated"] is False and output["text"].strip()
                        and len(json.dumps(output["text"], ensure_ascii=True).encode()) <= profile["wire_bytes"],
                        "discovered worker answer incomplete")
        DOCUMENT["check_supervisor"](report)
        ids.add(binding["job_id"]); provider_keys.add(handle["provider_key"])
        reports[binding["job_id"]] = dict(provider_key=handle["provider_key"], report_sha256=status["report_sha256"],
            texts=[item["text"] for item in report["outputs"]], handle=handle, status=status, report=report,
            path=path, data=checked_receipt_input(path, receipt, document, enrollment) if TRIAL else None)
    require(set(observed) <= ids and provider_keys == set(selected), "observed worker lacks terminal report")
    refinement = checked_frontier(document, source, enrollment, plan, result, reports) if TRIAL else None
    final = result["synthesized_answer"]
    require(final["job_id"] in reports and final["provider_key"] == reports[final["job_id"]]["provider_key"]
            and final["text"] in reports[final["job_id"]]["texts"], "display answer is not a real final peer output")
    return dict(source_sha256=sha(source), source_manifest_id=source_id, context_bytes=len(source),
        total_parts=result["total_parts"], package_count=len(result["packages"]), synthesis_levels=len(levels),
        provider_keys=sorted(provider_keys), jobs=len(ids), output_sha256=sha(final["text"].encode()),
        execution_complete=True, answer_complete=result["answer_complete"],
        semantic_completeness_proven=False, exact_native_receipts_verified=True,
        **(dict(selected_provider_keys=selected, model_fingerprint=selected_model()["fingerprint"],
                refinement=refinement, **trial_fields()) if TRIAL else {}))


def observe(work, pid):
    JOBS["guest_work"](work)
    progress = dict(version=1, phase="setup", failure=None, invariant_reason=None, task_count=0,
                    observed_workers=0, cancel_workers=0, counts_saturated=False, driver_alive=None)
    tracked = dict(owner=None, tasks=[], observed={}, cancelled={})
    try:
        observe_inner(work, pid, progress, tracked)
    except (Exception, KeyboardInterrupt) as error:
        progress["failure"] = observer_error(error)
        progress["invariant_reason"] = observer_invariant_reason(error)
        raise
    finally:
        if tracked["owner"] is not None:
            try:
                progress["driver_alive"] = JOBS["alive"](tracked["owner"])
            except Exception:
                progress["driver_alive"] = None
        for name, key, bound in (("task_count", "tasks", 2), ("observed_workers", "observed", 128),
                                 ("cancel_workers", "cancelled", 128)):
            count = len(tracked[key])
            progress[name] = min(count, bound)
            progress["counts_saturated"] |= count > bound
        try:
            # Written before observe exits and the shell can interrupt its driver.
            # This is diagnostic only; never replace the original failure or proof.
            write(work / f"{NAME}-observer-status.private", progress)
        except Exception:
            pass


def observe_inner(work, pid, progress, tracked):
    root, state = paths(work)
    output = root / "build/cooperative-proof"
    progress["phase"] = "owner_binding"
    owner = JOBS["identity"](pid)
    tracked["owner"] = owner
    layout = read(work / "agent-jobs-layout.json")
    progress["phase"] = "broker_binding"
    brokers = {node: JOBS["identity"](JOBS["broker_pid"](node)) for node in layout["provider_nodes"]}
    deadline = time.monotonic() + 2400
    consent = False
    observed, cancelled = tracked["observed"], tracked["cancelled"]
    first = None
    result = None
    while JOBS["alive"](owner) and time.monotonic() < deadline:
        progress["phase"] = "awaiting_consent"
        if not consent and (output / "pre-consent.json").exists():
            progress["phase"] = "consent_precheck"
            marker(output / "pre-consent.json", "prefill_without_dispatch")
            require(not task_roots(state)
                    and all(JOBS["worker_snapshot"](work, node, broker) is None for node, broker in brokers.items()),
                    "task executed before explicit public consent")
            progress["phase"] = "consent_authorization"
            authorize(output / "authorize.json", "allow_explicit_public_submit")
            consent = True
        progress["phase"] = "task_scan"
        tasks = task_roots(state)
        tracked["tasks"] = tasks
        if tasks:
            require(consent, "task was admitted before consent")
            if first is None:
                first = tasks[0]
            require(tasks[0] == first, "original task directory changed")
            progress["phase"] = "worker_scan"
            scan_workers(work, first / "document", layout, brokers, observed)
        if first and result is None and (output / "result-received.json").exists():
            progress["phase"] = "result_join"
            marker(output / "result-received.json", "public_result_received")
            result = retained_result(first / "document", read(root / "input.json"), layout, observed)
            write(work / f"{NAME}-result.json", result)
            progress["phase"] = "result_authorization"
            authorize(output / "result-verified.json", "public_result_verified")
        if len(tasks) == 2:
            progress["phase"] = "cancel_worker_scan"
            require(result is not None, "second task preceded retained first result")
            scan_workers(work, tasks[1] / "document", layout, brokers, cancelled)
            if cancelled and not (output / "cancel-authorize.json").exists():
                progress["phase"] = "cancel_authorization"
                marker(output / "cancel-admitted.json", "public_cancel_target_admitted")
                authorize(output / "cancel-authorize.json", "allow_scoped_public_cancel")
        time.sleep(0.05)
    progress["phase"] = "completion_check"
    require(not JOBS["alive"](owner) and consent and result is not None and cancelled,
            "browser did not complete both real public tasks within fixture bound")
    progress["phase"] = "worker_cleanup_check"
    check_task_workers_ended([*observed.values(), *cancelled.values()])
    progress["phase"] = "observation_write"
    write(work / f"{NAME}-observation.json", dict(no_dispatch_before_consent=True,
        real_fragment_peers=sorted({entry["node"] for entry in observed.values() if entry["level"] is None}),
        observed_synthesis_levels=sorted({entry["level"] for entry in observed.values() if entry["level"] is not None}),
        completed_workers=list(observed.values()), cancelled_workers=list(cancelled.values()),
        cancel_target_had_live_peer_worker=True, observed_workers_ended=True))
    progress["phase"] = "complete"


def check_panel(panel, result, revision):
    require(panel["version"] == 1 and panel["kind"] == "real-gecko-cooperative-public-peers"
            and panel["passed"] is True and panel["core_revision"] == revision
            and panel["temporary_browser_data_removed"] is True, "actual Gecko panel proof incomplete")
    observed = panel["observed"]
    require(all(observed[name] is True for name in (
        "prefill_no_dispatch", "explicit_consent", "text_only", "scoped_cancel_confirmed")),
        "public consent/cancel UI boundary missing")
    require(observed["first_task_id"] != observed["cancel_task_id"], "cancel targeted the completed original task")
    displayed = observed["first_result"]
    require(all(displayed[name] == result[name] for name in (
        "source_manifest_id", "package_count", "total_parts", "synthesis_levels", "output_sha256"))
        and sorted(displayed["provider_keys"]) == result["provider_keys"]
        and displayed["execution_complete"] is True and displayed["joining"] == "hierarchical_peer_synthesis",
        "browser output does not join the exact native peer result")
    if TRIAL:
        require(displayed["selected_provider_keys"] == result["selected_provider_keys"],
                "browser changed the discovered enrollment")


def collect(work, revision):
    JOBS["guest_work"](work)
    panel = read(work / f"{NAME}-panel.json", 131072)
    result = read(work / f"{NAME}-result.json")
    check_panel(panel, result, revision)
    observed = read(work / f"{NAME}-observation.json", 1048576)
    require(observed["observed_workers_ended"] is True, "cooperative workers retained")


def check_evidence(value, revision, source_pins=None):
    check_trial(value)
    check_trial(value["input"])
    check_trial(value["result"])
    if TRIAL:
        check_discovered_provision(value["model_provision"])
        expected = [value["layout"]["provider_keys"][node] for node in value["layout"]["provider_nodes"]]
        require(len(value["result"]["selected_provider_keys"]) == len(expected) == 2
                and set(value["result"]["selected_provider_keys"]) == set(expected)
                and set(value["result"]["provider_keys"]) == set(expected)
                and value["result"]["model_fingerprint"] == selected_model()["fingerprint"],
                "discovered evidence selection differs")
        refinement = value["result"]["refinement"]
        extra = {"retained_splits", "deepest_level", "intermediate_token_limited_outputs"} if refinement.get("version") == 2 else set()
        require(set(refinement) == {"version", "enabled", "applied", "original_parts", "refined_leaves",
                    "effective_parts", "original_token_limited_outputs", "exact_frontier_verified"} | extra
                and type(refinement["version"]) is int and refinement["version"] in (1, 2) and refinement["enabled"] is True
                and refinement["exact_frontier_verified"] is True
                and type(refinement["refined_leaves"]) is int and 0 <= refinement["refined_leaves"] <= 16
                and refinement["applied"] is (refinement["refined_leaves"] > 0)
                and refinement["original_parts"] == value["result"]["total_parts"]
                and refinement["effective_parts"] == refinement["original_parts"] + refinement.get("retained_splits", refinement["refined_leaves"])
                and refinement["original_token_limited_outputs"] == refinement["refined_leaves"],
                "discovered refinement evidence differs")
        if extra:
            require(type(refinement["retained_splits"]) is int
                    and 1 <= refinement["refined_leaves"] <= refinement["retained_splits"] <= 16
                    and type(refinement["deepest_level"]) is int and 1 <= refinement["deepest_level"] <= 4
                    and type(refinement["intermediate_token_limited_outputs"]) is int
                    and refinement["intermediate_token_limited_outputs"] == refinement["retained_splits"] - refinement["refined_leaves"],
                    "multi-level refinement evidence accounting differs")
    require(value["source_revision"] == revision and value["success"] is True
            and all(value[field] is False for field in FALSE_SCOPE), "cooperative proof scope overstated")
    selected = pins() if source_pins is None else source_pins
    require(value["provision"] == selected, "browser source/runtime provenance changed")
    panel = value["panel"]
    require(panel["browser_source_sha256"] == {name: record["sha256"] for name, record in selected["files"].items()}
            and panel["runtime_version"] == selected["runtime"]["version"]
            and panel["runtime_source_stamp"] == selected["runtime"]["source_stamp"]
            and panel["runtime_sha256"] == selected["runtime"]["files"]
            and panel["interfaces"] == ["lo"] and panel["host_read_only"] is True
            and panel["same_owner_socket_mode"] == 0o600,
            "actual browser source/runtime/isolation observation differs")
    result, observation = value["result"], value["observation"]
    check_panel(value["panel"], result, revision)
    require(result["exact_native_receipts_verified"] is True and result["execution_complete"] is True
            and result["answer_complete"] is True and result["semantic_completeness_proven"] is False
            and (1 if TRIAL else 2) <= result["synthesis_levels"] <= 16
            and result["total_parts"] >= (2 if TRIAL else 5)
            and result["package_count"] >= (1 if TRIAL else 2) and result["jobs"] >= (3 if TRIAL else 4)
            and len(result["provider_keys"]) == len(set(result["provider_keys"])) == 2
            and result["source_sha256"] == value["input"]["context_sha256"]
            and result["context_bytes"] == value["input"]["context_bytes"] <= 4096
            and value["input"]["explicit_public_source"] is True and value["input"]["license"] == "GPL-3.0-only",
            "real public document/synthesis receipt missing")
    require(observation["no_dispatch_before_consent"] is True
            and observation["cancel_target_had_live_peer_worker"] is True
            and observation["observed_workers_ended"] is True
            and observation["real_fragment_peers"] == sorted(value["layout"]["provider_nodes"])
            and len(observation["observed_synthesis_levels"]) == result["synthesis_levels"]
            and observation["cancelled_workers"] and observation["completed_workers"],
            "actual multi-peer/cancellation observation missing")
    for entry in observation["completed_workers"] + observation["cancelled_workers"]:
        require(entry["isolated_live_worker"] is True
                and entry["base_model_sha256"] == selected_model()["model"]["base_weights"]["sha256"]
                and entry["provider_key"] in result["provider_keys"]
                and re.fullmatch(r"[0-9a-f]{64}", entry["dataset_sha256"]), "observed worker provenance changed")
    require(value["private_cleanup"] == dict(observed_compute_processes_ended=True, model_runtime_removed=True,
            private_job_roots_removed=True, publisher_key_removed=True), "private owned state remains")
    require(value["cleanup"] == dict(public_service_stopped=True, peer_brokers_stopped=True,
            browser_root_removed=True, public_receipts_removed=True, socket_removed=True), "app/service state remains")
    JOBS["CUSTODY"]["validate_path"](value["path"], value["peers"], value["layout"], "fetch", payload_minimum=1)
    for node in value["layout"]["provider_nodes"]:
        application = value["path"]["privacy"]["exit"]["provider_application"][node]
        require(application["request_packets"] > 0 and application["response_payload_bytes"] > 0,
                "one selected executor did not exchange real protected traffic")
    require(value["path"]["gates"]["exit_mptcp_tls_completed"] >= 6, "protected task completions missing")


def evidence(work, revision):
    JOBS["guest_work"](work)
    root, state = paths(work)
    require(not root.exists() and not state.exists()
            and not (work / "state-client/compute-source/public.sock").exists(), "owner state was not cleaned")
    units = ["volparossa-alpha-public-browser.service", "volparossa-alpha-cooperative-browser.service"]
    layout = read(work / "agent-jobs-layout.json")
    units += [f"volparossa-alpha-compute@{node}.service" for node in layout["provider_nodes"]]
    for unit in units:
        status = subprocess.check_output(["systemctl", "show", "--property=ActiveState", "--value", unit], text=True).strip()
        require(status in ("inactive", "failed"), "owned service still active")
    cleanup = dict(public_service_stopped=True, peer_brokers_stopped=True, browser_root_removed=True,
                   public_receipts_removed=True, socket_removed=True)
    write(work / f"{NAME}-cleanup.json", cleanup)
    value = {name: read(work / f"{NAME}-{name}.json", 1048576)
             for name in ("provision", "panel", "observation", "result", "input", "cleanup")}
    value.update(source_revision=revision, success=True, **dict.fromkeys(FALSE_SCOPE, False),
        private_cleanup=read(work / "agent-jobs-private-cleanup.json"),
        peers=read(work / "a01-expected-peers.json"), layout=layout,
        path=dict(selected_route=read(work / "content-custody-fetch-live-selection.json"),
            privacy={role: read(work / f"content-custody-fetch-privacy-{role}.json") for role in JOBS["CUSTODY"]["ROLES"]},
            control_privacy=read(work / "content-provider-custody-fetch-control.json"),
            gates=read(work / "content-custody-fetch-gates.json")))
    value.update(trial_fields())
    if TRIAL:
        value["model_provision"] = read(work / "agent-jobs-provision.json")
    check_evidence(value, revision)
    write(work / f"{NAME}-evidence.json", value)


def finalize(work, revision, status, complete, remaining, phase, blocker):
    path = work / f"{NAME}-evidence.json"
    value = read(path, 1048576) if path.is_file() else None
    host_path = work / "a15-evidence.json"
    host = read(host_path) if host_path.is_file() else {}
    inventory_path = work / f"{NAME}-inventory.private"
    inventory = closed_inventory(read(inventory_path, 4096)) if TRIAL and inventory_path.is_file() else None
    write(work / f"{NAME}-smoke.json", dict(report_kind="volparossa-cooperative-browser", schema_version=1,
        source_revision=revision, runner_exit_status=status, phase=phase,
        observed_blocker=None if blocker == "NONE" else blocker, evidence=value, host_state=host,
        preselection_diagnostic=closed_preselection_events(work / "logs-client.txt"),
        cleanup=dict(complete=complete, remaining_owned_objects=remaining),
        success=status == 0 and complete and remaining == 0 and host.get("unchanged") is True and value is not None,
        **({"inventory_diagnostic": inventory} if TRIAL else {}), **trial_fields()))


def check_report(value, revision):
    check_trial(value)
    require(re.fullmatch(r"[0-9a-f]{40}", revision) and value["source_revision"] == revision
            and value["report_kind"] == "volparossa-cooperative-browser" and value["schema_version"] == 1
            and value["success"] is True and value["runner_exit_status"] == 0
            and value["phase"] == "agent-cooperative-browser-complete" and value["observed_blocker"] is None
            and value["cleanup"] == dict(complete=True, remaining_owned_objects=0)
            and value["host_state"]["unchanged"] is True
            and value["host_state"]["before_sha256"] == value["host_state"]["after_sha256"],
            "exact-source host/cleanup proof missing")
    check_evidence(value["evidence"], revision)


def main(args):
    if args[:1] == ["--trial"]:
        require(len(args) >= 3, "cooperative trial command missing")
        select_trial(args[1])
        args = args[2:]
    if len(args) == 2 and args[0] in ("account-home-prepare", "account-home-cleanup"):
        account_home(Path(args[1]), cleanup=args[0] == "account-home-cleanup")
        return
    if args == ["export-names"]:
        print("\n".join(EXPORT_NAMES))
    elif len(args) == 2 and args[0] == "await-inventory":
        await_inventory(Path(args[1]))
    elif len(args) == 2 and args[0] == "provision":
        provision(Path(args[1]))
    elif len(args) == 3 and args[0] == "observe":
        observe(Path(args[1]), int(args[2]))
    elif len(args) == 6 and args[0] == "diagnostic":
        diagnostic(Path(args[1]), int(args[2]), int(args[3]), int(args[4]), int(args[5]))
    elif len(args) == 3 and args[0] == "collect":
        collect(Path(args[1]), args[2])
    elif len(args) == 3 and args[0] == "evidence":
        evidence(Path(args[1]), args[2])
    elif len(args) == 8 and args[0] == "finalize":
        finalize(Path(args[1]), args[2], int(args[3]), args[4] == "true", int(args[5]), args[6], args[7])
    elif len(args) == 3 and args[0] == "report":
        check_report(read(Path(args[1]), 1048576), args[2])
    else:
        raise ValueError("unknown cooperative browser fixture command")


if __name__ == "__main__":
    try:
        main(sys.argv[1:])
    except (KeyError, TypeError, ValueError, OSError, subprocess.SubprocessError):
        print("cooperative browser proof failed; private diagnostics withheld", file=sys.stderr)
        sys.exit(1)
