#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-only
"""Real Signal native export/import over real protected replica storage; private state stays local."""
import base64
import hashlib
import json
import os
from pathlib import Path
import re
import resource
import runpy
import shutil
import signal
import socket
import stat
import subprocess
import sys
import time

REPLICAS = runpy.run_path(str(Path(__file__).with_name("private-storage-replicas-smoke.py")))
read, require, ROLES = REPLICAS["read"], REPLICAS["require"], REPLICAS["ROLES"]
create, private_file, invoke, unlock = (REPLICAS[name] for name in ("create", "private_file", "invoke", "unlock"))
CHAT = "c897667d76bea8140f0bc5f373404e43cbd54552"
SIGNAL = "ef3872cb0249ec939d8aff857568a0e87a6b5075"
CAPACITY = 67108864
RUNTIME = Path("/home/vpci/signal-backup-runtime")
TITLE = "backups exports and imports a VOLPAROSSA replicated encrypted backup"
STAGE = "dispatch"
NATIVE_EXIT = None
NATIVE_DIAGNOSTIC = None
SANDBOX_PHASES = frozenset(("entry", "identity", "capabilities", "control-group", "control-socket", "xvfb-exec"))
REPORTER_PHASES = frozenset(("reporter-initialized", "run-start", "hook-start", "hook-end", "test-start",
                            "test-end", "test-pass", "test-fail", "hook-fail", "unknown-fail", "pending", "run-end"))
NATIVE_ERROR_CODES = frozenset(("EACCES", "EPERM", "ENOENT", "EROFS", "ENOSPC", "ENOMEM", "ECONNREFUSED",
    "ETIMEDOUT", "ERR_MODULE_NOT_FOUND", "MODULE_NOT_FOUND", "ERR_DLOPEN_FAILED", "ERR_REQUIRE_ESM",
    "ERR_UNKNOWN_FILE_EXTENSION", "ERR_ASSERTION", "ERR_MOCHA_TIMEOUT", "OTHER"))
STARTUP_CAUSES = frozenset(("crashpad_database", "chromium_namespace", "chromium_setuid_sandbox",
    "chromium_display", "native_library", "cpu_instruction", "user_data_directory", "debugger_connect",
    "chromium_process_launch", "resource_limit"))
STARTUP_SIGNALS = frozenset(("SIGABRT", "SIGBUS", "SIGFPE", "SIGILL", "SIGKILL", "SIGSEGV", "SIGSYS",
                           "SIGTERM", "SIGTRAP", "SIGXCPU", "SIGXFSZ", "OTHER"))
FALSE_SCOPE = ("server_free_messaging_proven", "independent_failure_domains_proven",
               "network_contribution_credit", "electron_sandbox_claimed", "full_alpha_acceptance_claimed")
EXPORT_NAMES = ("a01-expected-peers.json",) + tuple(f"signal-backup-{name}.json" for name in
    ("smoke", "evidence", "prepare", "native", "finish", "deleted_usage", "private_cleanup", "isolation",
     "layout", "guard", "native-live-selection", "native-gates")) + (
    "content-provider-signal-backup-native-control.json",
    *(f"signal-backup-native-privacy-{role}.json" for role in ROLES))


def owner_root(path, missing=False):
    root = Path(path)
    require(root.is_absolute() and root.name == "signal-backup-user" and root.parent.name == "client-fixtures",
            "invalid private Signal fixture root")
    require(root.parent.resolve() == root.parent, "symlink fixture parent")
    if missing and not root.exists() and not root.is_symlink():
        return root
    info = root.lstat()
    require(stat.S_ISDIR(info.st_mode) and stat.S_IMODE(info.st_mode) == 0o700
            and info.st_uid == os.geteuid(), "Signal owner root must be owned and 0700")
    return root


def prepare(root, binary, client, provider_a, provider_b, key_a, key_b):
    require(not list(root.iterdir()) and key_a != key_b, "new private owner and distinct providers required")
    create(root / "passphrase", base64.b64encode(os.urandom(48)) + b"\n")
    invoke(binary, client, ["init", *unlock(root)], raw=True)
    owner = invoke(binary, client, ["content", "recipient-key", *unlock(root)])["identity_public_key_hex"]
    require(re.fullmatch(r"[0-9a-f]{64}", owner) and owner not in (key_a, key_b), "distinct owner required")
    providers = []
    for label, control, key in (("a", provider_a, key_a), ("b", provider_b, key_b)):
        grant = root / f"grant-{label}.bin"
        result = invoke(binary, control, ["storage", "peer", "grant", "--provider-key", key,
            "--owner-key", owner, "--max-payload-bytes", CAPACITY, "--max-leases", 1,
            "--max-retention-seconds", 7200, "--lifetime-seconds", 7200, "--output", grant])
        require(result["grant_written"] is True and result["max_payload_bytes"] == CAPACITY
                and result["max_leases"] == 1 and result["reserved_bytes"] == 0,
                "bounded real provider grant missing")
        providers.append(dict(key=key, grant=str(grant)))
    config = dict(executable=binary, controlSocket=client, identity=str(root / "identity.key"),
                  passphraseFile=str(root / "passphrase"), providers=providers, lifetimeSeconds=1800)
    create(root / "config.json", json.dumps(config).encode())
    for name in ("backup", "tmp", "config", "cache", "data", "runtime"):
        (root / name).mkdir(mode=0o700)
    return dict(providers=2, grant_max_leases_each=1, grant_payload_bytes_each=CAPACITY,
                owner_distinct_from_both_providers=True, owner_secrets_exported=False)


def validate_mocha(value):
    require(value == dict(version=1, tests=1, passes=1, failures=0, pending=0, exact_test=True),
            "exact native Signal backup test did not pass")


def validate_provision(value):
    require(value["version"] == 1 and value["kind"] == "signal-backup-runtime-provision"
            and value["chat_revision"] == CHAT and value["signal_revision"] == SIGNAL
            and value["candidate"] == "build/signal-backup-candidate"
            and value["node"] == "build/node-v24.19.0-linux-x64-with-npm/bin/node"
            and value["electron_version"] == "44.1.0" and value["success"] is True and value["phase"] == "complete"
            and value["preparatory_compilation_succeeded"] is True
            and value["native_artifacts_materialized"] is True
            and re.fullmatch(r"[0-9a-f]{64}", value["compile_receipt_sha256"]), "pinned Signal runtime unavailable")


def digest(path):
    with path.open("rb") as source:
        return hashlib.file_digest(source, "sha256").hexdigest()


def closed_error(error):
    kind = next((name for name, cls in (("os_error", OSError), ("timeout", subprocess.TimeoutExpired),
        ("subprocess_error", subprocess.SubprocessError), ("check_failed", ValueError),
        ("invalid_shape", (KeyError, TypeError, StopIteration))) if isinstance(error, cls)), "other")
    number = getattr(error, "errno", None)
    return dict(kind=kind, errno=number if type(number) is int and 0 < number < 4096 else None)


def sandbox_status(root, phase, error=None):
    require(phase in SANDBOX_PHASES, "invalid sandbox diagnostic phase")
    temporary, target = root / "sandbox-status.json.tmp", root / "sandbox-status.json"
    create(temporary, json.dumps(dict(version=1, phase=phase,
        error=None if error is None else closed_error(error))).encode())
    if target.exists() or target.is_symlink():
        private_file(target)
    temporary.replace(target)


def closed_status(path, reporter=False):
    result = dict(available=False, valid=False, value=None)
    try:
        private_file(path)
        require(path.stat().st_size <= 4096, "native diagnostic bound")
        result["available"] = True
        value = read(path)
        if reporter:
            require(set(value) == {"version", "phase", "tests", "passes", "failures", "pending", "exact_test", "last_failure"}
                and value["version"] == 1 and value["phase"] in REPORTER_PHASES
                and type(value["exact_test"]) is bool
                and all(type(value[key]) is int and 0 <= value[key] <= 10000 for key in ("tests", "passes", "failures", "pending")),
                "native reporter diagnostic shape")
            failure = value["last_failure"]
            require(failure is None or isinstance(failure, dict) and set(failure) == {"kind", "code", "errno"}
                and failure["kind"] in ("test", "hook", "unknown") and failure["code"] in NATIVE_ERROR_CODES
                and (failure["errno"] is None or type(failure["errno"]) is int and 0 < abs(failure["errno"]) < 4096),
                "native reporter failure shape")
        else:
            require(set(value) == {"version", "phase", "error"} and value["version"] == 1
                and value["phase"] in SANDBOX_PHASES, "native sandbox diagnostic shape")
            error = value["error"]
            require(error is None or isinstance(error, dict) and set(error) == {"kind", "errno"}
                and error["kind"] in ("os_error", "timeout", "subprocess_error", "check_failed", "invalid_shape", "other")
                and (error["errno"] is None or type(error["errno"]) is int and 0 < error["errno"] < 4096),
                "native sandbox failure shape")
        result.update(valid=True, value=value)
    except (ValueError, OSError, KeyError, TypeError):
        pass
    return result


def log_classification(path):
    result = dict(available=False, truncated=False, signals={})
    try:
        private_file(path)
        with path.open("rb") as source:
            size = os.fstat(source.fileno()).st_size
            source.seek(max(0, size - 16384))
            raw = source.read(16384).lower()
        patterns = {
            "permission_denied": (b"permission denied", b"eacces", b"eperm"),
            "missing_path": (b"enoent", b"no such file or directory"),
            "readonly_filesystem": (b"read-only file system", b"erofs"),
            "bwrap_failure": (b"bwrap: ",),
            "xvfb_failure": (b"xvfb-run: error:", b"fatal server error:"),
            "display_unavailable": (b"cannot open display", b"missing x server", b"unable to open x display"),
            "module_missing": (b"err_module_not_found", b"module_not_found", b"cannot find module"),
            "typescript_loader": (b"err_unknown_file_extension", b"err_require_esm", b"transformerror"),
            "native_module_load": (b"err_dlopen_failed", b"no native build was found", b"invalid elf"),
            "shared_library_missing": (b"error while loading shared libraries",),
            "electron_launch": (b"electron.launch", b"failed to launch", b"app failed to start after"),
            "signal_bootstrap_retry": (b"failed to start the app, attempt",),
            "signal_fatal_test": (b"app had fatal test errors",),
            "assertion": (b"assertionerror", b"err_assertion"),
            "timeout": (b"timeouterror", b"timeout of", b"timed out", b"err_mocha_timeout"),
            "test_selection": (b"no test files found", b"no tests found", b"pending test forbidden"),
            "resource_failure": (b"out of memory", b"cannot allocate memory", b"no space left", b"file size limit exceeded"),
        }
        result.update(available=True, truncated=size > 16384,
            signals={name: any(pattern in raw for pattern in options) for name, options in patterns.items()})
    except (ValueError, OSError):
        pass
    return result


def native_diagnostic(root, joined):
    return dict(version=1, process_group_joined=joined, sandbox=closed_status(root / "sandbox-status.json"),
        reporter=closed_status(root / "native-status.json", reporter=True),
        bootstrap=bootstrap_diagnostic(root / "startup-status.json"),
        stdout=log_classification(root / "native.stdout"), stderr=log_classification(root / "native.stderr"),
        private_logs_exported=False)


def bootstrap_diagnostic(path):
    """Closed native-startup observation, never a raw exception or process command line."""
    result = dict(available=False, valid=False, value=None)
    try:
        private_file(path)
        require(path.stat().st_size <= 4096, "bootstrap diagnostic bound")
        result["available"] = True
        value = read(path)
        require(set(value) == {"version", "phase", "attempt", "exception", "process", "failure_class",
                              "causes", "cause_unknown", "message_truncated"}
            and value["version"] == 1 and value["phase"] == "bootstrap-startup-failed"
            and type(value["attempt"]) is int and 1 <= value["attempt"] <= 4,
            "bootstrap diagnostic shape")
        error, process, causes = value["exception"], value["process"], value["causes"]
        require(set(error) == {"name", "code", "errno"}
            and error["name"] in ("Error", "TypeError", "RangeError", "TimeoutError", "SystemError", "OTHER")
            and error["code"] in NATIVE_ERROR_CODES | {"ECONNRESET", "EADDRINUSE", "EADDRNOTAVAIL"}
            and (error["errno"] is None or type(error["errno"]) is int and 0 < abs(error["errno"]) < 4096),
            "bootstrap exception shape")
        process_flags = {"launcher_started", "spawn_failure_observed", "launcher_exit_observed",
                         "node_endpoint_observed", "chromium_endpoint_observed"}
        require(set(process) == process_flags | {"launcher_exit_code", "launcher_exit_signal", "electron_exit_signal"}
            and all(type(process[key]) is bool for key in process_flags)
            and (process["launcher_exit_code"] is None or type(process["launcher_exit_code"]) is int
                 and abs(process["launcher_exit_code"]) <= 255)
            and all(process[key] is None or process[key] in STARTUP_SIGNALS
                    for key in ("launcher_exit_signal", "electron_exit_signal")), "bootstrap process shape")
        require(value["failure_class"] in ("electron_signal", "launcher_exit", "debugger_connect_timeout",
                "chromium_endpoint_timeout", "node_endpoint_timeout", "spawn_error", "unknown")
            and set(causes) == STARTUP_CAUSES and all(type(flag) is bool for flag in causes.values())
            and type(value["cause_unknown"]) is bool and value["cause_unknown"] == (not any(causes.values()))
            and type(value["message_truncated"]) is bool, "bootstrap cause shape")
        result.update(valid=True, value=value)
    except (ValueError, OSError, KeyError, TypeError):
        pass
    return result


def native_command(candidate, node, reporter):
    return ["xvfb-run", "--auto-servernum", "--server-args=-screen 0 1280x1024x24 -nolisten tcp",
        str(node), "node_modules/mocha/bin/mocha.js", "--require", str(reporter.with_name("signal-backup-startup.cjs")),
        "--require", "ts/test-mock/setup-ci.node.ts",
        "--grep", "^" + TITLE + "$", "--forbid-pending", "--fail-zero", "--reporter", str(reporter),
        "ts/test-mock/backups/backups_test.node.ts"]


def isolated_command(root, candidate, node, reporter):
    # No host HOME override; Electron user data and all writable state are separately scoped.
    return ["bwrap", "--die-with-parent", "--unshare-user", "--unshare-pid", "--unshare-ipc",
        "--cap-drop", "ALL", "--ro-bind", "/", "/", "--bind", str(root), str(root),
        "--proc", "/proc", "--dev", "/dev", "--tmpfs", "/tmp", "--chdir", str(candidate),
        "/usr/bin/python3", "-B", str(Path(__file__)), "sandbox", str(root), str(candidate), str(node),
        str(reporter), os.readlink("/proc/self/ns/net")]


def sandbox_exec(root, candidate, node, reporter, client_namespace):
    """Positive socket proof after user/mount/PID isolation, without weakening its permissions."""
    phase = "entry"
    try:
        sandbox_status(root, phase)
        phase = "identity"; sandbox_status(root, phase)
        require(os.geteuid() != 0 and os.readlink("/proc/self/ns/net") == client_namespace,
                "sandbox lost the unprivileged Client namespace")
        phase = "capabilities"; sandbox_status(root, phase)
        status = dict(line.split(":", 1) for line in Path("/proc/self/status").read_text().splitlines())
        require(all(int(status[field], 16) == 0 for field in ("CapInh", "CapPrm", "CapEff", "CapBnd", "CapAmb"))
                and int(status["NoNewPrivs"]) == 1, "sandbox acquired capabilities")
        phase = "control-group"; sandbox_status(root, phase)
        control_path = read(root / "config.json")["controlSocket"]
        # User namespace GID rendering may be overflowgid, but actual Unix access must survive.
        require(Path(control_path).stat().st_gid in os.getgroups(), "sandbox control group unavailable")
        phase = "control-socket"; sandbox_status(root, phase)
        with socket.socket(socket.AF_UNIX) as control:
            control.settimeout(2); control.connect(control_path)
        create(root / "sandbox.json", json.dumps(dict(client_namespace_retained=True,
            capless_nonroot=True, control_socket_access_verified=True)).encode())
        phase = "xvfb-exec"; sandbox_status(root, phase)
        os.execvpe("xvfb-run", native_command(candidate, node, reporter), os.environ)
    except (OSError, ValueError, KeyError, TypeError) as error:
        try:
            sandbox_status(root, phase, error)
        except (OSError, ValueError):
            pass
        raise


def join_group(process):
    def alive():
        try:
            os.killpg(process.pid, 0)
            return True
        except ProcessLookupError:
            return False
    for signum in (signal.SIGTERM, signal.SIGKILL):
        try:
            os.killpg(process.pid, signum)
        except ProcessLookupError:
            pass
        try:
            process.wait(timeout=1)
        except subprocess.TimeoutExpired:
            pass
        deadline = time.monotonic() + 1
        while alive() and time.monotonic() < deadline:
            time.sleep(0.05)
        if not alive() and process.poll() is not None:
            return
    raise ValueError("native process group not joined")


def run_native(root):
    global STAGE, NATIVE_EXIT, NATIVE_DIAGNOSTIC
    STAGE = "runtime-validation"
    provision = read(Path(__file__).with_name("signal-backup-runtime.json"))
    validate_provision(provision)
    candidate, node = RUNTIME / provision["candidate"], RUNTIME / provision["node"]
    require(candidate.is_dir() and node.is_file() and os.geteuid() != 0, "unprivileged native app required")
    require(digest(node) == provision["node_sha256"] and len(provision["runtime_sha256"]) == 7
            and all(not Path(name).is_absolute() and ".." not in Path(name).parts
                and digest(candidate / name) == sha for name, sha in provision["runtime_sha256"].items()),
            "staged native/runtime bytes changed")
    status = dict(line.split(":", 1) for line in Path("/proc/self/status").read_text().splitlines())
    require(all(int(status[field], 16) == 0 for field in ("CapInh", "CapPrm", "CapEff", "CapBnd", "CapAmb"))
            and int(status["NoNewPrivs"]) == 1, "capless native app boundary absent")
    config = read(root / "config.json")
    control_gid = Path(config["controlSocket"]).stat().st_gid
    require(set(os.getgroups()) == {control_gid}, "native app control group missing")
    with socket.socket(socket.AF_UNIX) as control:
        control.settimeout(2); control.connect(config["controlSocket"])
    STAGE = "application-network-guard"
    # Positive loopback controls, plus an actual forbidden direct provider connection.
    for family, address in ((socket.AF_INET, "127.0.0.1"), (socket.AF_INET6, "::1")):
        with socket.socket(family) as listener, socket.socket(family) as client:
            listener.bind((address, 0)); listener.listen(1); client.settimeout(2)
            client.connect(listener.getsockname())
            connection, _ = listener.accept(); connection.close()
    with socket.socket() as direct:
        direct.settimeout(2)
        try:
            direct.connect(("49.165.5.1", 18080))
        except OSError:
            pass
        else:
            raise ValueError("native app escaped direct-network guard")
    environment = {name: os.environ[name] for name in ("HOME", "USER", "LOGNAME") if name in os.environ}
    environment.update(NODE_ENV="production", CI="1", TMPDIR=str(root / "tmp"), LANG="C.UTF-8", LC_ALL="C.UTF-8",
        XDG_CONFIG_HOME=str(root / "config"), XDG_CACHE_HOME=str(root / "cache"),
        XDG_DATA_HOME=str(root / "data"), XDG_RUNTIME_DIR=str(root / "runtime"),
        VOLPAROSSA_BACKUP_CONFIG=str(root / "config.json"), VOLPAROSSA_BACKUP_WORK=str(root / "backup"),
        VOLPAROSSA_BACKUP_RESULT=str(root / "result.json"), PLAYWRIGHT_SKIP_BROWSER_DOWNLOAD="1",
        VOLPAROSSA_BACKUP_STATUS=str(root / "native-status.json"),
        VOLPAROSSA_BACKUP_STARTUP=str(root / "startup-status.json"),
        PATH=f"{node.parent}:{candidate / 'node_modules/.bin'}:/usr/bin:/bin")
    command = isolated_command(root, candidate, node, Path(__file__).with_name("signal-backup-reporter.cjs"))
    resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
    resource.setrlimit(resource.RLIMIT_FSIZE, (128 * 1024 * 1024, 128 * 1024 * 1024))
    STAGE = "sandbox-launch"
    with (root / "native.stdout").open("xb") as stdout, (root / "native.stderr").open("xb") as stderr:
        os.chmod(root / "native.stdout", 0o600); os.chmod(root / "native.stderr", 0o600)
        process = subprocess.Popen(command, cwd=root, env=environment, stdout=stdout, stderr=stderr,
                                   start_new_session=True)
        try:
            STAGE = "native-regression"
            NATIVE_EXIT = process.wait(timeout=2700)
            require(NATIVE_EXIT == 0, "native test failed; private diagnostics withheld")
        finally:
            joined = False
            try:
                join_group(process)
                joined = True
            finally:
                NATIVE_DIAGNOSTIC = native_diagnostic(root, joined)
    STAGE = "native-receipt"
    require(read(root / "sandbox.json") == dict(client_namespace_retained=True,
        capless_nonroot=True, control_socket_access_verified=True), "inside sandbox positive proof missing")
    private_file(root / "result.json")
    validate_mocha(read(root / "result.json"))
    require(not (root / "backup/archive.signal").exists()
            and not (root / "backup/restored/download.signal").exists(), "local archive was retained")
    return dict(chat_revision=CHAT, signal_revision=SIGNAL, native_test=read(root / "result.json"),
                compiled_runtime_sha256=provision["runtime_sha256"], node_sha256=provision["node_sha256"],
                compile_receipt_sha256=provision["compile_receipt_sha256"],
                native_encrypted_export_import=True, original_ciphertext_removed=True,
                upstream_messages_attachments_screenshots_verified=True,
                registration_and_relink_mock_server_required=True, application_egress_loopback_only=True,
                loopback_ipv4_ipv6_verified=True, capless_app=True, control_group_socket_verified=True,
                native_process_group_joined=True, private_logs_exported=False)


def validate_receipt(value, operation, keys, size, charges):
    require(value["operation"] == "private_storage_replicas_" + operation
            and type(size) is int and 0 < size <= CAPACITY and value["logical_ciphertext_bytes"] == size
            and value["distinct_provider_identities"] == 2
            and [entry["provider_key"] for entry in value["copies"]] == keys
            and [entry["charge"] for entry in value["copies"]] == charges
            and value["read_consumes_archive"] is False and value["operation_complete"] is True
            and value["physical_payload_charge_upper_bound"] == charges.count("committed") * size
            and value["committed_payload_bytes"] == charges.count("committed") * size
            and value["reserved_payload_bytes"] == value["uncertain_payload_bytes"] == 0,
            "retained replica receipt missing or inconsistent")


def finish(root, binary, client):
    private_file(root / "backup/recovery.json")
    descriptor = read(root / "backup/recovery.json")
    size = descriptor["ciphertextBytes"]
    keys = [entry["key"] for entry in read(root / "config.json")["providers"]]
    arguments = ["--state", root / "backup/replicas", *unlock(root)]
    validate_receipt(invoke(binary, client, ["storage", "replicas", "progress", *arguments]),
                     "progress", keys, size, ["committed", "committed"])
    for index, key in enumerate(keys):
        validate_receipt(invoke(binary, client, ["storage", "replicas", "delete", *arguments,
                                                "--provider-key", key]),
                         "delete", keys, size, ["deleted"] * (index + 1) + ["committed"] * (1 - index))
    return dict(logical_ciphertext_bytes=size, retained_copies_after_native_import=2,
                physical_payload_charge_before_delete=2 * size, reads_nonconsuming=True,
                both_remote_copies_deleted=True, final_payload_charge=0)


def cleanup(path):
    root = owner_root(path, missing=True)
    if root.exists():
        # Root must be the validated exact private fixture child; rmtree does not follow symlinks.
        require(shutil.rmtree.avoids_symlink_attacks, "safe private cleanup unavailable")
        shutil.rmtree(root)
    return dict(owner_identity_removed=True, recovery_keys_removed=True, grants_removed=True,
                profiles_logs_plaintext_removed=True, user_directory_removed=True)


def validate_evidence(value):
    require(value["success"] is True and all(value[field] is False for field in FALSE_SCOPE), "scope overstated")
    native = value["native"]
    validate_mocha(native["native_test"])
    require(native["chat_revision"] == CHAT and native["signal_revision"] == SIGNAL
            and len(native["compiled_runtime_sha256"]) == 7
            and all(re.fullmatch(r"[0-9a-f]{64}", sha) for sha in native["compiled_runtime_sha256"].values())
            and all(re.fullmatch(r"[0-9a-f]{64}", native[name]) for name in ("node_sha256", "compile_receipt_sha256"))
            and all(native[field] is True for field in ("native_encrypted_export_import", "original_ciphertext_removed",
                "upstream_messages_attachments_screenshots_verified", "registration_and_relink_mock_server_required",
                "application_egress_loopback_only", "loopback_ipv4_ipv6_verified", "capless_app",
                "control_group_socket_verified", "native_process_group_joined"))
            and native["private_logs_exported"] is False, "native Signal proof missing")
    prepared = value["prepare"]
    require(prepared == dict(providers=2, grant_max_leases_each=1, grant_payload_bytes_each=CAPACITY,
            owner_distinct_from_both_providers=True, owner_secrets_exported=False), "real owner/grants absent")
    finish = value["finish"]
    size = finish["logical_ciphertext_bytes"]
    require(type(size) is int and 0 < size <= CAPACITY and finish == dict(logical_ciphertext_bytes=size,
            retained_copies_after_native_import=2, physical_payload_charge_before_delete=2 * size,
            reads_nonconsuming=True, both_remote_copies_deleted=True, final_payload_charge=0), "storage receipt absent")
    require(value["deleted_usage"] == [dict(reserved_bytes=0, committed_bytes=0, leases=0)] * 2,
            "provider capacity retained")
    require(value["private_cleanup"] == dict(owner_identity_removed=True, recovery_keys_removed=True,
            grants_removed=True, profiles_logs_plaintext_removed=True, user_directory_removed=True), "private cleanup missing")
    isolation = value["isolation"]
    require(isolation["user_uid"] > 0 and isolation["user_uid"] != isolation["agent_uid"]
            and isolation["control_gid"] != isolation["agent_gid"]
            and all(isolation[field] is True for field in ("agent_cannot_read_user_state",
                "client_cannot_read_either_provider_store", "agent_mount_positive_control",
                "both_provider_keys_match_independent_fixture_peers", "provider_namespaces_distinct")), "isolation absent")
    require(value["guard"]["app_uid"] == isolation["user_uid"] and value["guard"]["blocked_packets"] > 0
            and value["guard"]["loopback_ipv4_ipv6_only"] is True, "application network guard not observed")
    REPLICAS["validate_network"](value["network"], value["expected_peers"], value["layout"], "native", minimum_flows=6)


def evidence(work):
    value = {name: read(work / f"signal-backup-{name}.json") for name in
             ("prepare", "native", "finish", "private_cleanup", "isolation", "layout", "guard")}
    value.update(success=True, expected_peers=read(work / "a01-expected-peers.json"), **dict.fromkeys(FALSE_SCOPE, False))
    value["deleted_usage"] = REPLICAS["read_deleted_usage"](work / "signal-backup-deleted_usage.json")
    value["network"] = dict(selected_route=read(work / "signal-backup-native-live-selection.json"),
        privacy={role: read(work / f"signal-backup-native-privacy-{role}.json") for role in ROLES},
        control_privacy=read(work / "content-provider-signal-backup-native-control.json"),
        gates=read(work / "signal-backup-native-gates.json"))
    validate_evidence(value)
    return value


def validate_report(value, revision):
    require(re.fullmatch(r"[0-9a-f]{40}", revision) and value["source_revision"] == revision
            and value["schema_version"] == 1 and value["report_kind"] == "volparossa-signal-backup"
            and value["success"] is True and value["runner_exit_status"] == 0
            and value["phase"] == "signal-backup-complete" and value["observed_blocker"] is None
            and value["cleanup"]["complete"] is True and value["cleanup"]["remaining_owned_objects"] == 0
            and value["host_state"]["unchanged"] is True, "source/host/cleanup proof missing")
    validate_evidence(value["backup"])


def main(args):
    command = args[0]
    if command == "export-names" and len(args) == 1:
        print("\n".join(EXPORT_NAMES)); return
    if command == "prepare" and len(args) == 8:
        result = prepare(owner_root(args[1]), *args[2:])
    elif command == "native" and len(args) == 2:
        result = run_native(owner_root(args[1]))
    elif command == "sandbox" and len(args) == 6:
        sandbox_exec(owner_root(args[1]), Path(args[2]), Path(args[3]), Path(args[4]), args[5])
    elif command == "finish" and len(args) == 4:
        result = finish(owner_root(args[1]), *args[2:])
    elif command == "cleanup" and len(args) == 2:
        result = cleanup(args[1])
    elif command == "evidence" and len(args) == 3:
        result = evidence(Path(args[1])); Path(args[2]).write_text(json.dumps(result, sort_keys=True) + "\n")
    elif command == "report" and len(args) == 3:
        validate_report(read(Path(args[1])), args[2]); result = dict(success=True, report_kind="volparossa-signal-backup")
    else:
        raise ValueError("unknown native Signal fixture command")
    print(json.dumps(result, sort_keys=True))


if __name__ == "__main__":
    def interrupted(_signal, _frame):
        raise ValueError("native Signal fixture interrupted")
    for signum in (signal.SIGTERM, signal.SIGINT):
        signal.signal(signum, interrupted)
    try:
        main(sys.argv[1:])
    except (KeyError, TypeError, ValueError, OSError, StopIteration, subprocess.SubprocessError) as error:
        print(json.dumps(dict(success=False, failure_stage=STAGE, native_exit_status=NATIVE_EXIT,
            error=closed_error(error), native_diagnostic=NATIVE_DIAGNOSTIC)))
        print("native Signal fixture failed; private diagnostics withheld", file=sys.stderr)
        sys.exit(1)
