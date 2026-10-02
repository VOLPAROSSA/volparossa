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
FILES = (
    "scripts/smoke_cooperative_compute.py", "scripts/smoke_compute_model.py", "scripts/smoke_privacy.py",
    "scripts/stage_firefox.py", "integration/VolparossaCooperativeCompute.sys.mjs",
    "integration/VolparossaCooperativePanel.sys.mjs", "defaults/privacy.json",
)
EXPORT_NAMES = tuple(f"{NAME}-{suffix}.json" for suffix in (
    "smoke", "evidence", "provision", "panel", "observation", "result", "cleanup", "input", "diagnostic")) + (
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
}
EXECUTION_PHASES = frozenset(('input', 'validation', 'directory', 'source_selection', 'provider_selection',
    'source_retention', 'tokenization', 'publication', 'enrollment_save', 'peer_execution', 'synthesis',
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
ANSWER_JOININGS = frozenset(("ordered_source_ranges_not_neural_synthesis", "single_source_answer",
    "hierarchical_peer_synthesis", "hierarchical_peer_synthesis_incomplete",
    "incomplete_fragment_answers", "awaiting_fragments_before_peer_synthesis"))
SYNTHESIS_REASONS = frozenset(("worker_output_was_wire_truncated", "worker_produced_empty_answer",
    "legacy_generation_end_unknown", "worker_output_hit_token_limit", "cancelled", "peer_work_pending",
    "invocation_round_budget",
    "reduction_did_not_shrink_no_inputs_discarded", "hierarchy_budget_no_inputs_discarded"))
ANSWER_STATUSES = ("eos", "json_boundary", "token_limit", "wire_truncated", "empty",
                   "legacy_unknown", "invalid_or_unknown")


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
    require(3840 <= len(original) <= 1048576, "bounded public README missing")
    context = original[:3840].decode("utf-8", errors="ignore")
    write(root / "input.json", dict(question=QUESTION, context=context, license="GPL-3.0-only"))
    write(root / "provision.json", selected)
    print(json.dumps(dict(context_bytes=len(context.encode()), context_sha256=sha(context.encode()),
                         readme_sha256=sha(original), explicit_public_source=True, license="GPL-3.0-only")))


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
        for line in path.read_text(encoding="ascii").splitlines():
            match = re.fullmatch(r"([0-9]{1,20})\tlevel=([0-9])\tevent=([A-Z0-9_]{1,96})\tsession=[0-9a-f]{0,64}\tpath=(?:-|[0-9]{1,10})", line)
            require(match is not None, "invalid bounded RPC event record")
            timestamp = int(match[1])
            require(timestamp > 0 and (not records or timestamp >= records[-1]), "RPC event clock regressed")
            records.append(timestamp)
            if timestamp > baseline and match[3] in counts:
                counts[match[3]] += 1
        require(len(records) <= 1000, "RPC event ring exceeded")
        return dict(state="valid", baseline_unix_ms=baseline, limit=1000, records=len(records),
            window_covers_baseline=bool(records) and records[0] <= baseline,
            matching_failures=sum(counts.values()), counts=counts)
    except FileNotFoundError:
        return dict(state="absent")
    except (OSError, ValueError, UnicodeError):
        return dict(state="invalid")


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
                worker=current["worker"], owned_processes=current["owned_processes"],
                isolated_live_worker=True, base_model_sha256=handle["capabilities"]["model"]["base_weights"]["sha256"])
    require(len(observed) <= 128, "unbounded observed worker set")


def retained_result(document, fixture, layout, observed):
    source = (document / "source.txt").read_bytes()
    require(source == fixture["context"].encode(), "public coordinator source changed")
    enrollment, plan, result = (read(document / name, 8 * 1048576)
        for name in ("document.json", "document-plan.json", "result.json"))
    DOCUMENT["check_plan"](plan, source)
    selected = [layout["provider_keys"][node] for node in layout["provider_nodes"]]
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
    require(2 <= len(levels) <= 16 and all(level["complete"] is True for level in levels)
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
                and report["model"]["files"]["model.safetensors"]["sha256"] == JOBS["TRAIN"]["WEIGHT_HASH"],
                "real pinned worker report changed")
        DOCUMENT["check_supervisor"](report)
        ids.add(binding["job_id"]); provider_keys.add(handle["provider_key"])
        reports[binding["job_id"]] = dict(provider_key=handle["provider_key"], report_sha256=status["report_sha256"],
                                        texts=[item["text"] for item in report["outputs"]])
    require(set(observed) <= ids and provider_keys == set(selected), "observed worker lacks terminal report")
    final = result["synthesized_answer"]
    require(final["job_id"] in reports and final["provider_key"] == reports[final["job_id"]]["provider_key"]
            and final["text"] in reports[final["job_id"]]["texts"], "display answer is not a real final peer output")
    return dict(source_sha256=sha(source), source_manifest_id=source_id, context_bytes=len(source),
        total_parts=result["total_parts"], package_count=len(result["packages"]), synthesis_levels=len(levels),
        provider_keys=sorted(provider_keys), jobs=len(ids), output_sha256=sha(final["text"].encode()),
        execution_complete=True, answer_complete=result["answer_complete"],
        semantic_completeness_proven=False, exact_native_receipts_verified=True)


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
    require(not any(JOBS["alive"](member) for entry in [*observed.values(), *cancelled.values()]
                    for member in entry["owned_processes"]), "observed task workers still alive")
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


def collect(work, revision):
    JOBS["guest_work"](work)
    panel = read(work / f"{NAME}-panel.json", 131072)
    result = read(work / f"{NAME}-result.json")
    check_panel(panel, result, revision)
    observed = read(work / f"{NAME}-observation.json", 1048576)
    require(observed["observed_workers_ended"] is True, "cooperative workers retained")


def check_evidence(value, revision, source_pins=None):
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
            and 2 <= result["synthesis_levels"] <= 16
            and result["total_parts"] >= 5 and result["package_count"] >= 2 and result["jobs"] >= 4
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
        require(entry["isolated_live_worker"] is True and entry["base_model_sha256"] == JOBS["TRAIN"]["WEIGHT_HASH"]
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
    check_evidence(value, revision)
    write(work / f"{NAME}-evidence.json", value)


def finalize(work, revision, status, complete, remaining, phase, blocker):
    path = work / f"{NAME}-evidence.json"
    value = read(path, 1048576) if path.is_file() else None
    host_path = work / "a15-evidence.json"
    host = read(host_path) if host_path.is_file() else {}
    write(work / f"{NAME}-smoke.json", dict(report_kind="volparossa-cooperative-browser", schema_version=1,
        source_revision=revision, runner_exit_status=status, phase=phase,
        observed_blocker=None if blocker == "NONE" else blocker, evidence=value, host_state=host,
        cleanup=dict(complete=complete, remaining_owned_objects=remaining),
        success=status == 0 and complete and remaining == 0 and host.get("unchanged") is True and value is not None))


def check_report(value, revision):
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
    if len(args) == 2 and args[0] in ("account-home-prepare", "account-home-cleanup"):
        account_home(Path(args[1]), cleanup=args[0] == "account-home-cleanup")
        return
    if args == ["export-names"]:
        print("\n".join(EXPORT_NAMES))
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
