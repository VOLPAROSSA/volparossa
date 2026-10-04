#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-only
"""Actual fragmented-storage CLI over protected routes; never whole-archive replica proof."""
import base64
import hashlib
import json
import os
from pathlib import Path
import re
import runpy
import signal
import stat
import subprocess
import sys
import tempfile
import time

BASE = runpy.run_path(str(Path(__file__).with_name("private-storage-replicas-smoke.py")))
NET = BASE["NET"]
read, require, ROLES = BASE["read"], BASE["require"], BASE["ROLES"]
private_root, private_file, create = BASE["private_root"], BASE["private_file"], BASE["create"]
invoke, unlock = BASE["invoke"], BASE["unlock"]
CHUNK = 262144
FIXTURE = bytes(range(256)) * (3 * CHUNK // 256) + b"VOLPAROSSA synthetic opaque fragment transport fixture".ljust(73, b".")
BYTES, SHA = len(FIXTURE), hashlib.sha256(FIXTURE).hexdigest()
LENGTHS = (CHUNK, CHUNK, CHUNK, 73)
PROVIDER_BYTES, PROVIDER_LEASES = (2 * CHUNK + 73, 2 * CHUNK + 73, 2 * CHUNK), (3, 3, 2)
NODES = ("relay4", "relay5", "relay3")
PHASES = dict(upload=56, restore=16, finish=16)
SCOPE_FALSE = (*BASE["SCOPE_FALSE"], "automatic_placement", "automatic_contribution_resize", "erasure_coding")
SUMMARY_NAMES = ("smoke", "evidence", "prepare", *PHASES, "withdrawal", "isolation", "layout",
                 "uploaded_usage", "restored_usage", "deleted_usage", "private_cleanup")
EXPORT_NAMES = ("a01-expected-peers.json", *(f"private-storage-fragments-{name}.json" for name in SUMMARY_NAMES),
    *(name for phase in PHASES for name in (
        f"private-storage-fragments-{phase}-live-selection.json",
        f"private-storage-fragments-{phase}-gates.json",
        f"content-provider-adaptive-private-storage-fragments-{phase}-control.json",
        *(f"private-storage-fragments-{phase}-privacy-{role}.json" for role in ROLES))))
FILES = {"identity.key", "passphrase", "grant-a.bin", "grant-b.bin", "grant-c.bin",
         "input.bin", "restore-1.bin", "restore-2.bin", "identities.sha256"}
RESTORE_STAGE = "not_started"
RESTORE_NUMBER = 0
RESTORE_CLI = None
RESTORE_COPY_OUTCOMES = frozenset(("explicitly_deleted", "unavailable_or_grant_invalid",
    "unknown_reservation", "restored_and_retained", "unavailable_or_restore_unverified"))
RESTORE_FAILURES = {
    "private replica CLI operation failed": "cli_exit",
    "replica diagnostics exceeded fixture bound": "cli_output_bound",
    "fragment result has wrong identity/scope": "report_identity_scope",
    "wrong fragment/provider counts": "report_counts",
    "fragment range differs": "fragment_range",
    "fragment copy placement or charge differs": "copy_placement_or_charge",
    "copy lost its committed bytes or finite lease": "copy_receipt",
    "confirmed copy count differs": "confirmed_copy_count",
    "physical accounting differs": "physical_accounting",
    "per-state charge differs": "state_accounting",
    "provider physical charge differs": "provider_accounting",
    "full reconstruction not verified": "reconstruction_receipt",
    "fragment was not obtained from its actual surviving provider": "survivor_receipt",
    "fixture file must be unlinked, owned and 0600": "output_metadata",
    "full reconstructed archive differs from removed source": "output_length_or_hash",
    "signed root or retained owner/provider/grant/archive/lease changed": "retained_identity",
    "existing output overwritten": "existing_output_changed",
    "temporary ciphertext staging remains": "staging_remains",
}


def configure_payload_geometry(ciphertext_bytes):
    """Reuse physical-path checks for a real application's four-fragment archive.

    This changes only fixture geometry, never an encryption/success claim.
    The Image checker supplies its independently measured OpenPGP byte length.
    """
    global BYTES, LENGTHS, PROVIDER_BYTES
    require(type(ciphertext_bytes) is int and 3 * CHUNK < ciphertext_bytes <= 4 * CHUNK,
            "application ciphertext must occupy four bounded fragments")
    BYTES = ciphertext_bytes
    LENGTHS = (CHUNK, CHUNK, CHUNK, BYTES - 3 * CHUNK)
    PROVIDER_BYTES = (2 * CHUNK + LENGTHS[-1], 2 * CHUNK + LENGTHS[-1], 2 * CHUNK)


def restore_failure(error):
    # A closed structural record replaces an empty failed-phase artifact. Never
    # export arbitrary exception text, commands, paths, receipts or private stderr.
    code = RESTORE_FAILURES.get(str(error), "unclassified")
    if isinstance(error, subprocess.TimeoutExpired):
        code = "cli_timeout"
    elif isinstance(error, KeyError):
        code = "report_field_missing"
    elif isinstance(error, OSError):
        code = "local_io"
    return dict(version=1, kind="private-storage-fragments-restore-failure", success=False,
        restore_number=RESTORE_NUMBER, stage=RESTORE_STAGE, code=code, cli=RESTORE_CLI)


def restore_cli_receipt(stdout):
    # The CLI emits an honest incomplete report before returning exit status 1.
    # Retain only bounded structural facts, not its provider keys or full report.
    try:
        require(len(stdout) <= 16384, "bounded restore receipt")
        value = json.loads(stdout)
        require(type(value) is dict and value.get("operation") == "private_storage_fragments_restore",
                "restore receipt operation")
        fields = ("operation_complete", "restored", "whole_archive_sha256_verified")
        require(all(value.get(key) is None or type(value[key]) is bool for key in fields), "restore receipt flags")
        unavailable = value.get("unavailable_fragment")
        require(unavailable is None or type(unavailable) is int and 0 <= unavailable < 4,
                "restore receipt fragment")
        outcomes = value.get("fragment_outcomes")
        require(type(outcomes) is list and len(outcomes) <= 4, "restore receipt outcomes")
        sanitized = []
        for index, outcome in enumerate(outcomes):
            require(type(outcome) is dict and type(outcome.get("index")) is int and outcome["index"] == index
                and type(outcome.get("restored")) is bool and type(outcome.get("copy_outcomes")) is list
                and len(outcome["copy_outcomes"]) <= 2
                and all(type(code) is str and code in RESTORE_COPY_OUTCOMES for code in outcome["copy_outcomes"]),
                "restore receipt outcome")
            sanitized.append(dict(index=index, restored=outcome["restored"], copy_outcomes=outcome["copy_outcomes"]))
        return dict(report="structural", **{key: value.get(key) for key in fields},
            unavailable_fragment=unavailable, completed_fragments=sum(item["restored"] for item in sanitized),
            fragment_outcomes=sanitized)
    except (TypeError, ValueError, KeyError, UnicodeError):
        return dict(report="unavailable_or_invalid")


def restore_invoke(binary, socket, args, expected=0, deadline=700):
    global RESTORE_CLI
    RESTORE_CLI = dict(exit_code=None, timed_out=False, stdout_bytes=None, stderr_bytes=None,
                       receipt=None)
    process = subprocess.Popen([binary, "--control-socket", socket, *map(str, args)],
                               stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    try:
        stdout, stderr = process.communicate(timeout=deadline)
        RESTORE_CLI.update(stdout_bytes=len(stdout), stderr_bytes=len(stderr),
                           receipt=restore_cli_receipt(stdout))
        require(process.returncode == expected, "private replica CLI operation failed")
        require(len(stdout) <= 16384 and len(stderr) <= 16384, "replica diagnostics exceeded fixture bound")
        if expected:
            require(not stdout, "failed no-clobber operation emitted a success response")
            return None
        return json.loads(stdout)
    except subprocess.TimeoutExpired:
        RESTORE_CLI["timed_out"] = True
        raise
    finally:
        if process.poll() is None:
            process.terminate()
            try:
                process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait(timeout=5)
        RESTORE_CLI["exit_code"] = process.returncode


def parse_flow_window(raw):
    require(type(raw) is bytes and len(raw) <= 262144, "invalid bounded Exit log")
    records = []
    for line in raw.decode("ascii").splitlines():
        match = re.fullmatch(r"([0-9]+)\tlevel=([0-9]+)\tevent=([A-Z0-9_]+)\tsession=[0-9a-f]*\tpath=(?:-|[0-9]+)", line)
        require(match is not None, "unexpected Exit log record")
        timestamp = int(match[1])
        require(timestamp > 0 and (not records or timestamp >= records[-1][0]),
                "Exit log clock regressed")
        # Retain full bounded records privately: timestamp/event deduplication
        # would discard repeated events in the same millisecond.
        records.append((timestamp, match[3], line))
    require(0 < len(records) <= 1000, "invalid Exit log window length")
    return records


def flow_gates(path, baseline):
    # Only code-only counters/timestamps leave the VM; this private snapshot is
    # not an export. Never infer cumulative totals from a truncated log window.
    require(type(baseline) is int and baseline > 0, "invalid event baseline")
    info = path.lstat()
    require(stat.S_ISREG(info.st_mode) and info.st_size <= 262144, "invalid bounded Exit log")
    records = parse_flow_window(path.read_bytes())
    return dict(event_baseline_unix_ms=baseline, exit_log_limit=1000, exit_log_records=len(records),
        exit_log_oldest_unix_ms=records[0][0], exit_log_newest_unix_ms=records[-1][0],
        exit_log_window_covers_baseline=records[0][0] <= baseline,
        exit_mptcp_tls_completed=sum(timestamp > baseline and event == "MPTCP_EXIT_FLOW_COMPLETED"
                                     for timestamp, event, _ in records),
        exit_mptcp_tls_failed=sum(timestamp > baseline and event == "MPTCP_EXIT_FLOW_FAILED"
                                 for timestamp, event, _ in records))


class FlowObservation:
    """Bounded fixture-only reconstruction of overlapping chronological rings.

    There is no sequence/cursor API. Match an entire shared suffix starting at a
    timestamp group whose beginning is present in BOTH snapshots. Reject a lost
    or ambiguous overlap instead of guessing which identical events are new.
    """
    def __init__(self, baseline):
        require(type(baseline) is int and baseline > 0, "invalid event baseline")
        self.baseline, self.previous = baseline, []
        self.snapshots = self.total = self.completed = self.failed = 0
        self.first_oldest = self.first_newest = 0

    def observe(self, raw):
        current = parse_flow_window(raw)
        require(self.snapshots < 10000, "Exit observation budget exhausted")
        if not self.previous:
            require(current[0][0] <= self.baseline, "Exit initial window truncated")
            added = current
        elif len(current) < 1000:
            # A non-full ring has not evicted anything. Shrinking/restarting or
            # mutating its prefix is not valid continuity evidence.
            require(current[:len(self.previous)] == self.previous, "Exit overlap missing")
            added = current[len(self.previous):]
        else:
            require(current[-1][0] >= self.previous[-1][0], "Exit log clock regressed")
            boundary = max(current[0][0], self.previous[0][0])
            prior = [row for row in self.previous if row[0] > boundary]
            require(prior, "Exit overlap missing")
            shared = [row for row in current if row[0] >= prior[0][0]]
            require(shared[:len(prior)] == prior, "Exit overlap missing")
            added = shared[len(prior):]
        if not self.previous:
            self.first_oldest, self.first_newest = current[0][0], current[-1][0]
        self.total += len(added)
        self.completed += sum(t > self.baseline and e == "MPTCP_EXIT_FLOW_COMPLETED" for t, e, _ in added)
        self.failed += sum(t > self.baseline and e == "MPTCP_EXIT_FLOW_FAILED" for t, e, _ in added)
        self.previous, self.snapshots = current, self.snapshots + 1

    def report(self, failure, command_status, joined):
        return dict(event_baseline_unix_ms=self.baseline, exit_log_limit=1000,
            exit_log_records=len(self.previous),
            exit_log_oldest_unix_ms=self.previous[0][0] if self.previous else 0,
            exit_log_newest_unix_ms=self.previous[-1][0] if self.previous else 0,
            exit_log_window_covers_baseline=bool(self.previous and self.previous[0][0] <= self.baseline),
            exit_mptcp_tls_completed=self.completed, exit_mptcp_tls_failed=self.failed,
            observation=dict(version=1, mode="incremental-overlap", snapshots=self.snapshots,
                observed_records=self.total, first_oldest_unix_ms=self.first_oldest,
                first_newest_unix_ms=self.first_newest, continuity_verified=failure is None,
                command_exit_status=command_status, command_joined=joined, failure=failure))


FLOW_FAILURES = {
    "Exit initial window truncated": "initial_window_truncated",
    "Exit overlap missing": "overlap_missing",
    "Exit log clock regressed": "clock_regressed",
    "Exit observation budget exhausted": "observation_budget",
    "Exit log query failed": "query_failed",
    "Exit protected completions missing": "completions_missing",
    "private fragments fixture interrupted": "interrupted",
}


def observe_flows(binary, socket, baseline, output, minimum, command):
    """Observe the unchanged timeout/setpriv command; export only closed counts.

    First snapshot precedes command start. Every later snapshot must overlap;
    final draining retains the existing fifty 100-ms polls. No raw ring or
    command output is added to the export allowlist.
    """
    require(command and type(minimum) is int and minimum > 0, "invalid observed command")
    observation, process, status, failure = FlowObservation(baseline), None, None, None

    def snapshot():
        # The fixed CLI already bounds its reply. Bound the observer's read too,
        # do not hold unbounded PIPE output or retain an on-disk diagnostic file.
        with tempfile.TemporaryFile() as stdout:
            reply = subprocess.run([binary, "--control-socket", socket, "logs", "--limit", "1000"],
                stdout=stdout, stderr=subprocess.DEVNULL, timeout=2, check=False)
            require(reply.returncode == 0, "Exit log query failed")
            stdout.seek(0)
            observation.observe(stdout.read(262145))

    try:
        snapshot()
        process = subprocess.Popen(command, start_new_session=True)
        while process.poll() is None:
            time.sleep(0.25)
            snapshot()
        status = process.returncode
        snapshot()
        if status == 0:
            for _ in range(50):
                if observation.completed >= minimum:
                    break
                time.sleep(0.1)
                snapshot()
            require(observation.completed >= minimum, "Exit protected completions missing")
    except (ValueError, OSError, subprocess.SubprocessError) as error:
        failure = ("query_timeout" if isinstance(error, subprocess.TimeoutExpired) else
                   FLOW_FAILURES.get(str(error), "invalid_observation"))
    finally:
        if process is not None:
            if process.poll() is None:
                try:
                    os.killpg(process.pid, signal.SIGTERM)
                except ProcessLookupError:
                    pass  # command may finish between poll and signal
                try:
                    process.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    try:
                        os.killpg(process.pid, signal.SIGKILL)
                    except ProcessLookupError:
                        pass
                    process.wait(timeout=5)
            status = process.returncode
        output.write_text(json.dumps(observation.report(failure, status, process is not None
            and process.returncode is not None), sort_keys=True) + "\n")
    return 0 if failure is None and status == 0 else 1


def validate_flow_gates(gates, minimum):
    require(gates["event_baseline_unix_ms"] > 0 and gates["exit_log_limit"] == 1000
            and 0 < gates["exit_log_records"] <= 1000
            and 0 < gates["exit_log_oldest_unix_ms"] <= gates["exit_log_newest_unix_ms"]
            and gates["event_baseline_unix_ms"] < gates["exit_log_newest_unix_ms"]
            and gates["exit_mptcp_tls_completed"] >= minimum, "protected completion count incomplete")
    if "observation" not in gates:
        require(gates["exit_log_window_covers_baseline"] is True
                and gates["exit_log_oldest_unix_ms"] <= gates["event_baseline_unix_ms"],
                "protected completion count incomplete")
        return
    value = gates["observation"]
    require(value["version"] == 1 and value["mode"] == "incremental-overlap"
            and type(value["snapshots"]) is int and 2 <= value["snapshots"] <= 10000
            and type(value["observed_records"]) is int
            and gates["exit_log_records"] <= value["observed_records"] <= 1000 * value["snapshots"]
            and 0 < value["first_oldest_unix_ms"] <= gates["event_baseline_unix_ms"]
            and value["first_oldest_unix_ms"] <= value["first_newest_unix_ms"] <= gates["exit_log_newest_unix_ms"]
            and gates["exit_log_window_covers_baseline"] is
                (gates["exit_log_oldest_unix_ms"] <= gates["event_baseline_unix_ms"])
            and value["continuity_verified"] is True and value["failure"] is None
            and type(value["command_exit_status"]) is int and value["command_exit_status"] == 0
            and value["command_joined"] is True, "incremental Exit observation incomplete")


def existing(root):
    return ["--state", root / "fragment-set", *unlock(root)]


def prepare(root, binary, client, provider_a, provider_b, provider_c, key_a, key_b, key_c):
    keys = (key_a, key_b, key_c)
    require(not list(root.iterdir()) and len(set(keys)) == 3, "new owner directory and distinct providers required")
    create(root / "input.bin", FIXTURE)
    create(root / "passphrase", base64.b64encode(os.urandom(48)) + b"\n")
    invoke(binary, client, ["init", *unlock(root)], raw=True)
    owner = invoke(binary, client, ["content", "recipient-key", *unlock(root)])["identity_public_key_hex"]
    require(re.fullmatch(r"[0-9a-f]{64}", owner) and owner not in keys, "owner must be distinct")
    for index, (label, control, key) in enumerate(zip("abc", (provider_a, provider_b, provider_c), keys)):
        value = invoke(binary, control, ["storage", "peer", "grant", "--provider-key", key,
            "--owner-key", owner, "--max-payload-bytes", PROVIDER_BYTES[index], "--max-leases", PROVIDER_LEASES[index],
            "--max-retention-seconds", 7200, "--lifetime-seconds", 7200, "--output", root / f"grant-{label}.bin"])
        require(value["grant_written"] is True and value["max_payload_bytes"] == PROVIDER_BYTES[index]
            and value["max_leases"] == PROVIDER_LEASES[index] and value["reserved_bytes"] == 0
            and value["network_contribution_credit"] is False, "exact subset-only provider grant missing")
    return dict(synthetic_opaque_bytes=True, ciphertext_bytes=BYTES, fragment_lengths=list(LENGTHS),
        providers=3, copies_per_fragment=2, grant_payload_bytes=list(PROVIDER_BYTES),
        grant_max_leases=list(PROVIDER_LEASES), owner_distinct_from_all_providers=True, owner_secrets_exported=False)


def identity_digest(root):
    state = root / "fragment-set"
    manifest = state / "fragments.json"
    require(private_file(manifest).st_size <= 1048576, "signed manifest exceeds bound")
    digest = hashlib.sha256(manifest.read_bytes())
    for fragment in range(4):
        for copy in range(2):
            path = state / f"fragment-{fragment:04}/copy-{copy}/archive.json"
            require(private_file(path).st_size <= 16384, "journal exceeds bound")
            value = json.loads(path.read_text())
            require(value["lease"] is not None, "copy lease is not acknowledged")
            digest.update(json.dumps({key: value[key] for key in ("provider_key", "owner_key", "grant_hex",
                "archive_id", "ciphertext_bytes", "sha256", "lease")}, sort_keys=True).encode())
    return digest.digest()


def check_identity(root):
    private_file(root / "identities.sha256")
    require(identity_digest(root) == (root / "identities.sha256").read_bytes(),
            "signed root or retained owner/provider/grant/archive/lease changed")


def validate_cli(value, operation, keys, phase):
    require(value["operation"] == "private_storage_fragments_" + operation
        and value["logical_ciphertext_bytes"] == BYTES and value["fragment_count"] == 4
        and value["copies_per_fragment"] == 2 and value["distinct_provider_identities"] == 3
        and value.get("operation_complete", True) is True
        and value["read_consumes_archive"] is False and value["owner_signature_verified"] is True
        and value["expired_copies_remain_charged"] is True
        and all(value[field] is False for field in ("metadata_overhead_measured", "current_remote_availability_proven",
            "independent_failure_domains_proven", "network_contribution_credit", "automatic_repair",
            "automatic_handoff", "erasure_coding")), "fragment result has wrong identity/scope")
    require(len(value["fragments"]) == 4 and len(value["providers"]) == 3, "wrong fragment/provider counts")
    totals = dict(reserved=0, committed=0, uncertain=0)
    provider_charge, confirmed_fragments, redundant = [0, 0, 0], 0, True
    for index, (entry, size) in enumerate(zip(value["fragments"], LENGTHS)):
        require(entry["index"] == index and entry["offset"] == sum(LENGTHS[:index])
                and entry["ciphertext_bytes"] == size and len(entry["copies"]) == 2, "fragment range differs")
        confirmed = 0
        for copy, receipt in enumerate(entry["copies"]):
            provider = (index + copy) % 3
            charge = ("unattempted" if phase == "created" else "deleted" if phase == "deleted"
                      else "uncertain" if phase == "restore" and provider == 0 and index in (0, 3) else "committed")
            require(receipt["provider_key"] == keys[provider] and receipt["charge"] == charge, "fragment copy placement or charge differs")
            retained = charge not in ("unattempted", "deleted")
            require(receipt["last_confirmed_stored_bytes"] == (size if retained else 0)
                and (receipt["last_confirmed_expiry"] > int(time.time()) if retained else receipt["last_confirmed_expiry"] == 0)
                and receipt["last_confirmed_state"] == ("Committed" if retained else "Deleted" if charge == "deleted" else None),
                "copy lost its committed bytes or finite lease")
            if retained:
                totals[charge] += size
                provider_charge[provider] += size
                confirmed += int(charge == "committed")
        require(entry["confirmed_unexpired_copies"] == confirmed, "confirmed copy count differs")
        confirmed_fragments += int(confirmed > 0)
        redundant &= confirmed == 2
    require(value["fragments_with_confirmed_unexpired_copy"] == confirmed_fragments
        and value["fully_redundant_from_retained_receipts"] is redundant
        and value["physical_payload_charge_upper_bound"] == sum(totals.values()), "physical accounting differs")
    for category, expected in totals.items():
        require(value[category + "_payload_bytes"] == expected, "per-state charge differs")
    require(value["providers"] == [dict(provider_key=key, physical_payload_charge_upper_bound=charge)
        for key, charge in zip(keys, provider_charge)], "provider physical charge differs")


def staged_files_absent(root):
    require(not any(path.name.startswith(".fragment-transfer-") for path in (root / "fragment-set").iterdir()),
            "temporary ciphertext staging remains")


def upload(root, binary, client, keys):
    command = ["storage", "fragments", "create", *existing(root), "--input", root / "input.bin",
        "--sha256", SHA, "--already-encrypted", "--copies", 2, "--fragment-bytes", CHUNK, "--lifetime-seconds", 1800]
    for label, key in zip("abc", keys):
        command.extend(["--provider-key", key, "--grant", root / f"grant-{label}.bin"])
    validate_cli(invoke(binary, client, command), "create", keys, "created")
    deposit = ["storage", "fragments", "deposit", *existing(root), "--input", root / "input.bin", "--already-encrypted"]
    validate_cli(invoke(binary, client, deposit, deadline=900), "deposit", keys, "committed")
    create(root / "identities.sha256", identity_digest(root))
    for operation, arguments in (("progress", ["storage", "fragments", "progress", *existing(root)]),
            ("deposit", deposit), ("renew", ["storage", "fragments", "renew", *existing(root), "--lifetime-seconds", 3600])):
        validate_cli(invoke(binary, client, arguments, deadline=900), operation, keys, "committed")
        check_identity(root)
    validate_cli(invoke(binary, client, ["storage", "fragments", "status", "--state", root / "fragment-set"]),
        "status", keys, "committed")
    staged_files_absent(root)
    private_file(root / "input.bin")
    (root / "input.bin").unlink()
    return dict(fragment_count=4, copies_per_fragment=2, committed_fragment_copies=8,
        logical_ciphertext_bytes=BYTES, physical_payload_charge=2 * BYTES, owner_signature_verified=True,
        fresh_process_progress=True, committed_retry_same_identities=True, renewal_confirmed_by_progress=True,
        source_removed_before_restore=True, staging_removed=True)


def validate_restore_result(value, keys):
    global RESTORE_STAGE
    RESTORE_STAGE = "validate_accounting"
    validate_cli(value, "restore", keys, "restore")
    RESTORE_STAGE = "validate_survivor_receipts"
    selected = (1, 1, 2, 1)
    require(value["restored"] is True and value["whole_archive_sha256_verified"] is True
        and len(value["fragment_outcomes"]) == 4, "full reconstruction not verified")
    for index, outcome in enumerate(value["fragment_outcomes"]):
        expected = (["unavailable_or_restore_unverified", "restored_and_retained"]
                    if index in (0, 3) else ["restored_and_retained"])
        require(outcome == dict(index=index, restored=True, provider_key=keys[selected[index]], copy_outcomes=expected),
                "fragment was not obtained from its actual surviving provider")


def restore(root, binary, client, keys):
    global RESTORE_STAGE, RESTORE_NUMBER
    RESTORE_STAGE = "source_absent"
    require(not (root / "input.bin").exists(), "original source remains")
    selected = (1, 1, 2, 1)
    for number in (1, 2):
        RESTORE_NUMBER = number
        path = root / f"restore-{number}.bin"
        RESTORE_STAGE = "cli_restore"
        value = restore_invoke(binary, client, ["storage", "fragments", "restore", *existing(root), "--output", path])
        validate_restore_result(value, keys)
        RESTORE_STAGE = "validate_output"
        require(private_file(path).st_size == BYTES and hashlib.sha256(path.read_bytes()).hexdigest() == SHA,
                "full reconstructed archive differs from removed source")
        RESTORE_STAGE = "validate_retained_identity"
        check_identity(root)
    RESTORE_STAGE = "cli_existing_output"
    restore_invoke(binary, client, ["storage", "fragments", "restore", *existing(root), "--output", root / "restore-1.bin"], expected=1, deadline=180)
    RESTORE_STAGE = "validate_existing_output"
    require(hashlib.sha256((root / "restore-1.bin").read_bytes()).hexdigest() == SHA, "existing output overwritten")
    RESTORE_STAGE = "validate_staging_removed"
    staged_files_absent(root)
    return dict(restores=2, source_absent=True, fragment_provider_indexes=list(selected),
        failed_first_provider_attempts=4, whole_archive_sha256_verified=True, reads_nonconsuming=True,
        existing_output_preserved=True, retained_identity_unchanged=True, staging_removed=True,
        physical_payload_charge=2 * BYTES, uncertain_payload_charge=CHUNK + 73)


def finish(root, binary, client, keys):
    validate_cli(invoke(binary, client, ["storage", "fragments", "progress", *existing(root)], deadline=900),
        "progress", keys, "committed")
    for _ in range(2):
        validate_cli(invoke(binary, client, ["storage", "fragments", "delete", *existing(root)], deadline=900),
            "delete", keys, "deleted")
        check_identity(root)
    staged_files_absent(root)
    return dict(reopened_copies_confirmed=True, all_eight_copies_deleted=True,
        delete_retry_idempotent=True, original_identities_retained=True, final_payload_charge=0, staging_removed=True)


def read_usage(path):
    require(not path.is_symlink() and path.is_file() and path.stat().st_size <= 2048, "bounded usage evidence missing")
    values = json.loads(path.read_text())
    require(isinstance(values, list) and len(values) == 3, "three actual provider stores required")
    for value in values:
        require(isinstance(value, dict) and set(value) == {"reserved_bytes", "committed_bytes", "leases"}
            and all(type(count) is int and 0 <= count < 2**64 for count in value.values()), "invalid usage counter")
    return values


def cleanup(path):
    root = private_root(path, missing=True)
    files, directories = [], []
    if root.exists():
        def visit(directory, depth):
            require(depth <= 4, "unexpected private directory depth")
            entries = list(directory.iterdir())
            require(len(entries) <= 24, "private cleanup entry bound exceeded")
            for child in entries:
                info = child.lstat()
                if stat.S_ISDIR(info.st_mode):
                    allowed = ((depth == 0 and (child.name == "fragment-set" or re.fullmatch(r"\.fragments-[A-Za-z0-9]+", child.name)))
                        or (depth == 1 and (re.fullmatch(r"fragment-000[0-3]", child.name)
                            or re.fullmatch(r"\.(?:replicas|fragment-transfer)-[A-Za-z0-9]+", child.name)))
                        or (depth == 2 and child.name in ("copy-0", "copy-1")))
                    require(allowed and stat.S_IMODE(info.st_mode) == 0o700 and info.st_uid == os.geteuid(),
                            "unexpected private cleanup directory")
                    visit(child, depth + 1)
                    directories.append(child)
                else:
                    allowed = ((depth == 0 and child.name in FILES) or (depth == 1 and child.name == "fragments.json")
                        or (depth == 2 and child.name in ("replicas.json", "restored-fragment"))
                        or (depth == 3 and child.name == "archive.json") or re.fullmatch(r"\.tmp[A-Za-z0-9]+", child.name))
                    require(allowed, "unexpected private cleanup file")
                    private_file(child)
                    files.append(child)
        visit(root, 0)
        require(len(files) <= 64 and len(directories) <= 24, "private cleanup bound exceeded")
        for entry in files:
            entry.unlink()
        for entry in directories:
            entry.rmdir()
        root.rmdir()
    return dict(owner_identity_removed=True, passphrase_removed=True, grants_removed=True,
        fragment_metadata_removed=True, input_and_outputs_removed=True, fragment_staging_removed=True, user_directory_removed=True)


def validate_network(phase, peers, layout, name):
    selected, privacy = phase["selected_route"], phase["privacy"]
    paths, slots, nodes = selected["paths"], selected["benchmark_slots"], layout["provider_nodes"]
    require(nodes == list(NODES) and len({peers[node] for node in nodes}) == 3
            and layout["control_relay_peer_id"] in {peers[node] for node in ROLES[1:4]},
            "three providers or ordinary control relay changed")
    require(selected["transport"] == "mptcp" and selected["route_context_id"] == layout["route_context_id"]
            and len(paths) == len(slots) == 2 and len({p["relay_peer_id"] for p in paths}) == 2
            and {p["exit_peer_id"] for p in paths} == {peers["exit"]}
            and all(p["route_context_id"] == selected["route_context_id"] for p in paths)
            and [p["relay_peer_id"] for p in paths] == [s["relay_peer_id"] for s in slots],
            "protected MPTCP route changed")
    forbidden = {peers["client"], peers["exit"], layout["control_relay_peer_id"]} | {p["relay_peer_id"] for p in paths}
    require(all(peers[node] not in forbidden for node in nodes), "provider overlaps a protected route role")
    relays = [slot["relay_node"] for slot in slots]
    require(len(set(relays)) == 2 and all(r in ROLES[1:4] for r in relays)
            and all(peers[s["relay_node"]] == s["relay_peer_id"] for s in slots)
            and set(privacy) == set(ROLES), "physical role capture mismatch")
    for role, capture in privacy.items():
        require(capture["capture_role"] == role and capture["content_provider_mode"] is True
                and capture["unexpected_outer_packets"] == capture["unexpected_provider_application_packets"] == 0
                and capture["expected_link_down_notifications"] == 0
                and set(capture["provider_application"]) == set(NODES), "unexpected application egress")
        NET["validate_drained"](capture, allow_empty=role in ROLES[1:4] and role not in relays)
        if role != "exit":
            require(all(n == 0 for values in capture["provider_application"].values() for n in values.values()),
                    "provider storage bypassed Exit")
    require(privacy["client"]["direct_client_exit_packets"] == privacy["client"]["internet_destination_outer_packets"] == 0
            and privacy["exit"]["direct_client_exit_packets"] == privacy["exit"]["client_public_packets"] == 0
            and privacy["exit"]["outbound_client_discovery_attempt_packets"] == 0
            and all(privacy[r]["internet_destination_outer_packets"] == 0 for r in ROLES[1:4]), "privacy boundary violated")
    for relay in relays:
        require(privacy[relay]["client_leg_wireguard_data_datagrams"] > 16
                and privacy[relay]["exit_leg_wireguard_data_datagrams"] > 16, "real two-leg traffic missing")
    active = NODES[1:] if name == "restore" else NODES
    app = privacy["exit"]["provider_application"]
    for node in NODES:
        if node in active:
            require(app[node]["request_packets"] > 0 and app[node]["response_packets"] > 0,
                    "active provider did not exchange real protected traffic")
        else:
            require(app[node]["response_payload_bytes"] == 0, "stopped or untouched provider returned payload")
    if name == "restore":
        for node, minimum in ((NODES[1], 2 * (2 * CHUNK + LENGTHS[-1])), (NODES[2], 2 * CHUNK)):
            require(app[node]["response_payload_bytes"] >= minimum, "actual survivor fragment payload absent")
    control = phase["control_privacy"]
    control_node = next(node for node in ROLES[1:4] if peers[node] == layout["control_relay_peer_id"])
    pairs = {f"ac{i}": [NET["PUBLIC_IPS"][control_node], NET["PUBLIC_IPS"][node]]
             for i, node in enumerate(("relay3", "relay4", "relay5"))}
    require(control["capture_role"] == "content-control" and control["content_provider_mode"] is True
            and control["content_control_pairs"] == pairs and set(control["interfaces"]) == set(pairs)
            and set(control["content_control_packets"]) == set(pairs)
            and control["unexpected_provider_control_packets"] == control["unexpected_provider_application_packets"] == 0
            and set(control["provider_application"]) == set(NODES)
            and all(n == 0 for values in control["provider_application"].values() for n in values.values()),
            "control links carried forbidden application or unknown traffic")
    # Provider control may reuse cached authenticated discovery; an empty but
    # fully drained dedicated capture is valid, never unexpected control traffic.
    NET["validate_drained"](control, allow_empty=True)
    validate_flow_gates(phase["gates"], PHASES[name])


def validate_evidence(value):
    require(value["success"] is True and all(value[field] is False for field in SCOPE_FALSE), "scope overstated")
    require(value["prepare"] == dict(synthetic_opaque_bytes=True, ciphertext_bytes=BYTES, fragment_lengths=list(LENGTHS),
        providers=3, copies_per_fragment=2, grant_payload_bytes=list(PROVIDER_BYTES),
        grant_max_leases=list(PROVIDER_LEASES), owner_distinct_from_all_providers=True, owner_secrets_exported=False),
        "exact subset-only provider grants missing")
    require(value["upload"] == dict(fragment_count=4, copies_per_fragment=2, committed_fragment_copies=8,
        logical_ciphertext_bytes=BYTES, physical_payload_charge=2 * BYTES, owner_signature_verified=True,
        fresh_process_progress=True, committed_retry_same_identities=True, renewal_confirmed_by_progress=True,
        source_removed_before_restore=True, staging_removed=True), "fragment deposit or original-source removal missing")
    require(value["restore"] == dict(restores=2, source_absent=True, fragment_provider_indexes=[1, 1, 2, 1],
        failed_first_provider_attempts=4, whole_archive_sha256_verified=True, reads_nonconsuming=True,
        existing_output_preserved=True, retained_identity_unchanged=True, staging_removed=True,
        physical_payload_charge=2 * BYTES, uncertain_payload_charge=CHUNK + 73), "two surviving-fragment reconstructions missing")
    require(value["finish"] == dict(reopened_copies_confirmed=True, all_eight_copies_deleted=True,
        delete_retry_idempotent=True, original_identities_retained=True, final_payload_charge=0, staging_removed=True),
        "explicit eight-copy deletion missing")
    require(value["withdrawal"] == dict(first_provider_stopped_before_restore=True, first_store_retained=True,
        other_two_providers_serving=True, same_three_stores_reopened=True, all_usage_snapshots_with_services_stopped=True,
        all_three_store_inodes_preserved=True, agent_restart_claimed=False), "provider withdrawal/reopen missing")
    retained = [dict(reserved_bytes=0, committed_bytes=size, leases=count)
                for size, count in zip(PROVIDER_BYTES, PROVIDER_LEASES)]
    require(value["uploaded_usage"] == value["restored_usage"] == retained
        and all(usage["committed_bytes"] < BYTES for usage in retained)
        and value["deleted_usage"] == [dict(reserved_bytes=0, committed_bytes=0, leases=0)] * 3,
        "physical stores do not hold exact nonconsumed subsets or final zero usage")
    require(value["private_cleanup"] == dict(owner_identity_removed=True, passphrase_removed=True, grants_removed=True,
        fragment_metadata_removed=True, input_and_outputs_removed=True, fragment_staging_removed=True, user_directory_removed=True),
        "private owner metadata/key cleanup incomplete")
    isolation = value["isolation"]
    require(isolation["user_uid"] > 0 and isolation["user_uid"] != isolation["agent_uid"]
        and isolation["control_gid"] != isolation["agent_gid"]
        and all(isolation[field] is True for field in ("agent_cannot_read_user_state", "client_cannot_read_any_provider_store",
            "agent_mount_positive_control", "all_provider_keys_match_independent_fixture_peers", "three_provider_namespaces_distinct")),
        "owner/provider isolation missing")
    require(set(value["network"]) == set(PHASES), "fragment network phase missing")
    for name, phase in value["network"].items():
        validate_network(phase, value["expected_peers"], value["layout"], name)


def build_evidence(work):
    value = {name: read(work / f"private-storage-fragments-{name}.json") for name in SUMMARY_NAMES
        if name not in ("smoke", "evidence", "uploaded_usage", "restored_usage", "deleted_usage")}
    for name in ("uploaded_usage", "restored_usage", "deleted_usage"):
        value[name] = read_usage(work / f"private-storage-fragments-{name}.json")
    value.update(success=True, expected_peers=read(work / "a01-expected-peers.json"), **dict.fromkeys(SCOPE_FALSE, False))
    value["network"] = {name: dict(selected_route=read(work / f"private-storage-fragments-{name}-live-selection.json"),
        privacy={role: read(work / f"private-storage-fragments-{name}-privacy-{role}.json") for role in ROLES},
        control_privacy=read(work / f"content-provider-adaptive-private-storage-fragments-{name}-control.json"),
        gates=read(work / f"private-storage-fragments-{name}-gates.json")) for name in PHASES}
    validate_evidence(value)
    return value


def validate_report(report, revision):
    require(re.fullmatch(r"[0-9a-f]{40}", revision) and report["source_revision"] == revision
        and report["schema_version"] == 1 and report["report_kind"] == "volparossa-private-storage-fragments"
        and report["success"] is True and report["runner_exit_status"] == 0
        and report["phase"] == "private-storage-fragments-complete" and report["observed_blocker"] is None
        and report["cleanup"]["complete"] is True and report["cleanup"]["remaining_owned_objects"] == 0
        and report["host_state"]["unchanged"] is True, "source-bound host/guest cleanup incomplete")
    validate_evidence(report["storage"])


def main(arguments):
    command = arguments[0]
    if command == "export-names" and len(arguments) == 1:
        print("\n".join(EXPORT_NAMES)); return
    if command == "flow-gates" and len(arguments) == 3:
        result = flow_gates(Path(arguments[1]), int(arguments[2]))
    elif command == "observe-flows" and len(arguments) > 8 and arguments[6] == "--":
        sys.exit(observe_flows(arguments[1], arguments[2], int(arguments[3]),
            Path(arguments[4]), int(arguments[5]), arguments[7:]))
    elif command == "validate-flow-gates" and len(arguments) == 3:
        validate_flow_gates(read(Path(arguments[1])), int(arguments[2]))
        return
    elif command == "prepare" and len(arguments) == 10:
        result = prepare(private_root(arguments[1]), *arguments[2:])
    elif command in PHASES and len(arguments) == 7:
        result = {"upload": upload, "restore": restore, "finish": finish}[command](
            private_root(arguments[1]), arguments[2], arguments[3], arguments[4:])
    elif command == "cleanup" and len(arguments) == 2:
        result = cleanup(arguments[1])
    elif command == "evidence" and len(arguments) == 3:
        result = build_evidence(Path(arguments[1]))
        Path(arguments[2]).write_text(json.dumps(result, sort_keys=True) + "\n")
    elif command == "report" and len(arguments) == 3:
        validate_report(read(Path(arguments[1])), arguments[2])
        result = dict(success=True, report_kind="volparossa-private-storage-fragments")
    else:
        raise ValueError("unknown fragmented-storage fixture command")
    print(json.dumps(result, sort_keys=True))


if __name__ == "__main__":
    def interrupted(_signal, _frame):
        raise ValueError("private fragments fixture interrupted")
    for signum in (signal.SIGTERM, signal.SIGINT):
        signal.signal(signum, interrupted)
    try:
        main(sys.argv[1:])
    except (KeyError, TypeError, ValueError, OSError, StopIteration, subprocess.SubprocessError) as error:
        if len(sys.argv) > 1 and sys.argv[1] == "restore":
            print(json.dumps(restore_failure(error), sort_keys=True))
        print("private fragments fixture failed; private diagnostics not exported", file=sys.stderr)
        sys.exit(1)
