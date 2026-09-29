#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-only
"""Guest-only pinned browser half of the combined private-service proof."""

import copy
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import signal
import stat
import subprocess
import sys
import tempfile
import time
import urllib.request

HERE = Path(__file__).resolve().parent
PINS = HERE / "agent-private-task-browser-pins.json"
NAME = "agent-private-browser"
ROOT = Path("/home/vpci/private-browser")
FILES = (
    "scripts/smoke_compute_model.py", "scripts/smoke_privacy.py", "scripts/stage_firefox.py",
    "integration/VolparossaCompute.sys.mjs", "integration/VolparossaComputePanel.sys.mjs",
    "defaults/privacy.json",
)
SCOPE = ("v1 combined pinned ESR sidebar -> actual private-serve -> pinned 360M local worker; "
         "one synthetic EOS answer after real IPC cancel/disconnect, exact model/input isolation, "
         "decoded-result cleanup before panel render and complete owned teardown; "
         "not a Firefox 157 build, native provider selector, general answer quality, remote private execution or completed B04")
PANEL_SCOPE = dict(firefox157_build_proven=False, native_provider_selector_proven=False,
    standalone_model_authenticity_proven=False, general_answer_quality_proven=False,
    public_peer_execution_proven=False, private_prompt_exported=False, raw_model_answer_exported=False)
STATUS_PHASES = frozenset((
    "wrapper-launch", "namespace-validation", "browser-start", "marionette-connect",
    "marionette-session", "script-start", "module-import", "sidebar-initialize",
    "sidebar-show", "sidebar-document", "panel-create", "broker-connect",
    "capabilities-received", "submit-admitted", "result-received", "result-cleanup-verified",
    "panel-render-check", "panel-cleanup", "script-complete", "result-validation",
    "browser-stop", "private-log-check", "report-write", "complete",
))
STATUS_ERRORS = frozenset((
    "FIREFOX_EXITED_EARLY", "MARIONETTE_CONNECT_TIMEOUT",
    "CHECK_FAILED", "OS_ERROR", "SUBPROCESS_FAILED", "RUNTIME_FAILED", "INTERRUPTED",
    "SCRIPT_FAILED", "UNCLASSIFIED", "BROKER_BUSY", "BROKER_INVALID_REQUEST",
    "BROKER_HANDSHAKE_REQUIRED", "BROKER_NO_SUCH_TASK", "BROKER_CANCELLED",
    "BROKER_EXECUTION_FAILED", "BROKER_CLEANUP_UNCONFIRMED", "MODULE_UNAVAILABLE",
    "MODULE_NOT_CONFIGURED", "MODULE_INVALID_RESPONSE", "MODULE_INVALID_QUESTION",
    "MODULE_INVALID_CONTEXT", "MODULE_CLEANUP_UNCONFIRMED",
))


def require(condition, message="private browser proof binding failed"):
    if not condition:
        raise ValueError(message)


def digest(path):
    with path.open("rb") as stream:
        return hashlib.file_digest(stream, "sha256").hexdigest()


def check_browser_status(value):
    require(type(value) is dict and set(value) == {"version", "phase", "failure"}
            and type(value["version"]) is int and value["version"] == 1
            and value["phase"] in STATUS_PHASES
            and (value["failure"] is None or value["failure"] in STATUS_ERRORS))
    return value


def check_browser_startup(value):
    require(type(value) is dict and set(value) == {
        "version", "outcome", "firefox_exit_code", "elapsed_ms", "connection_deadline_elapsed",
        "log_readable", "log_truncated", "log_signals",
    } and type(value["version"]) is int and value["version"] == 1
        and value["outcome"] in ("not_started", "exited", "timeout", "connected", "connection_error")
        and (value["firefox_exit_code"] is None or type(value["firefox_exit_code"]) is int
             and -128 <= value["firefox_exit_code"] <= 255)
        and type(value["elapsed_ms"]) is int and 0 <= value["elapsed_ms"] <= 710000
        and all(type(value[name]) is bool for name in (
            "connection_deadline_elapsed", "log_readable", "log_truncated"))
        and type(value["log_signals"]) is dict and set(value["log_signals"]) == {
            "library_load_message", "profile_message", "sandbox_message", "permission_message", "out_of_memory_message",
        } and all(type(flag) is bool for flag in value["log_signals"].values()))
    if value["outcome"] == "exited":
        require(value["firefox_exit_code"] is not None)
    if value["outcome"] in ("timeout", "not_started"):
        require(value["firefox_exit_code"] is None)
    if value["outcome"] == "timeout":
        require(value["connection_deadline_elapsed"] is True)
    return value


def browser_diagnostic(report_root, process, deadline):
    code = process.poll() if process is not None else None
    result = dict(process_state="not_started" if process is None else "running" if code is None else "exited",
        exit_code=code, deadline_elapsed=time.monotonic() >= deadline, status_state="absent")
    path = report_root / "browser-status.json"
    try:
        info = path.lstat()
        require(stat.S_ISREG(info.st_mode) and info.st_uid == os.getuid()
                and stat.S_IMODE(info.st_mode) == 0o600 and info.st_size <= 4096)
        with path.open("rb") as source:
            data = source.read(4097)
        require(len(data) <= 4096)
        result["status"] = check_browser_status(json.loads(data))
        result["status_state"] = "valid"
    except FileNotFoundError:
        pass
    except (OSError, ValueError, KeyError, TypeError):
        # Never export malformed status fields, raw logs, exception messages or paths.
        result["status_state"] = "invalid"
    startup_path = report_root / "browser-startup.json"
    try:
        info = startup_path.lstat()
        require(stat.S_ISREG(info.st_mode) and info.st_uid == os.getuid()
                and stat.S_IMODE(info.st_mode) == 0o600 and info.st_size <= 4096)
        with startup_path.open("rb") as source:
            data = source.read(4097)
        require(len(data) <= 4096)
        result["runtime_startup"] = check_browser_startup(json.loads(data))
        result["runtime_startup_state"] = "valid"
    except FileNotFoundError:
        pass
    except (OSError, ValueError, KeyError, TypeError):
        result["runtime_startup_state"] = "invalid"
    return result


def load_pins():
    value = json.loads(PINS.read_text())
    require(value["version"] == 1 and value["repository"] == "https://github.com/VOLPAROSSA/volparossa-browser"
            and re.fullmatch(r"[0-9a-f]{40}", value["revision"])
            and set(value["files"]) == set(FILES))
    for record in value["files"].values():
        require(set(record) == {"bytes", "sha256"} and type(record["bytes"]) is int
                and 0 < record["bytes"] <= 131072 and re.fullmatch(r"[0-9a-f]{64}", record["sha256"]))
    require(sum(record["bytes"] for record in value["files"].values()) <= 1024**2)
    runtime = value["runtime"]
    require(runtime["version"] == "140.16.0" and runtime["source_stamp"] == "d864999404b3032f682d74ccc60d1ce38c9ce609"
            and runtime["bytes"] == 71994716
            and runtime["sha256"] == "e32aeabcab2e74fe112332fad10f7d9630e14cd6f4564a596a71073018d24508"
            and runtime["url"] == "https://security.debian.org/debian-security/pool/updates/main/f/firefox-esr/"
                "firefox-esr_140.16.0esr-1~deb13u1_amd64.deb"
            and set(runtime["files"]) == {"firefox-esr", "libxul.so", "omni.ja", "browser/omni.ja"}
            and all(re.fullmatch(r"[0-9a-f]{64}", item) for item in runtime["files"].values()))
    return value


def fetch(url, path, record):
    # Exact URL, length and hash; no unbounded archive extraction or host downloads.
    path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    with urllib.request.urlopen(url, timeout=60) as response, path.open("xb") as output:
        require(response.geturl() == url)
        total, hashed = 0, hashlib.sha256()
        while block := response.read(min(65536, record["bytes"] + 1 - total)):
            total += len(block)
            require(total <= record["bytes"])
            hashed.update(block)
            output.write(block)
        require(total == record["bytes"] and hashed.hexdigest() == record["sha256"])


def check_panel(value, revision, canary, isolation_sha256):
    pins = load_pins()
    require(type(value) is dict and set(value) == {
        "passed", "kind", "version", "scope", "core_revision", "synthetic_canary", "observed",
        "core_observer_sha256", "runtime_version", "runtime_source_stamp", "runtime_sha256",
        "host_read_only", "interfaces", "same_owner_socket_mode", "browser_source_sha256",
        "private_prompt_absent_from_browser_log", "temporary_browser_data_removed",
    })
    require(value["passed"] is True and value["kind"] == "real-gecko-panel-existing-private-core-service"
            and value["version"] == 1 and value["scope"] == PANEL_SCOPE
            and value["core_revision"] == revision and value["synthetic_canary"] == canary
            and re.fullmatch(r"CANARY[0-9]{8}", canary)
            and value["core_observer_sha256"] == isolation_sha256
            and value["runtime_version"] == pins["runtime"]["version"]
            and value["runtime_source_stamp"] == pins["runtime"]["source_stamp"]
            and value["runtime_sha256"] == pins["runtime"]["files"]
            and value["browser_source_sha256"] == {name: pins["files"][name]["sha256"] for name in FILES}
            and value["host_read_only"] is True and value["interfaces"] == ["lo"]
            and value["same_owner_socket_mode"] == 0o600
            and value["private_prompt_absent_from_browser_log"] is True
            and value["temporary_browser_data_removed"] is True)
    observed = value["observed"]
    require(set(observed) == {"capabilities", "admitted", "answer", "boundary", "panel", "removed"}
            and observed["admitted"] == 1 and observed["removed"] is True
            and observed["capabilities"] == dict(visibility="private_local", local_only=True,
                model_profile="smollm2-360m-v1", network_access=False, public_cache=False,
                training=False, cloud_fallback=False)
            and observed["boundary"] == dict(point="decoded_result_before_panel_render",
                ephemeral_children=0, observed_worker_lifetimes_ended=True)
            and observed["panel"] == dict(actual_sidebar_document=True, connected=True,
                canary_rendered=True, text_only=True, eos_status_visible=True))
    answer = observed["answer"]
    require(set(answer) == {"answer_status", "complete", "canary_present", "generated_tokens"}
            and answer["answer_status"] == "eos" and answer["complete"] is True
            and answer["canary_present"] is True and type(answer["generated_tokens"]) is int
            and 1 <= answer["generated_tokens"] <= 256)


def check_report(value, revision, core):
    pins = load_pins()
    require(value["report_kind"] == "volparossa-agent-private-browser" and value["proof_version"] == 1
            and value["source_revision"] == revision and value["scope"] == SCOPE and value["success"] is True
            and value["browser_revision"] == pins["revision"] and value["browser_manifest_sha256"] == digest(PINS)
            and value["browser_provision"] == pins
            and value["full_b04_claimed"] is False and value["confidential_remote_execution_claimed"] is False
            and value["raw_private_input_exported"] is False and value["raw_worker_report_exported"] is False
            and value["raw_model_answer_exported"] is False
            and "answer" not in value)
    core["check_report_common"](value, "browser_completion")
    isolation_hash = hashlib.sha256((json.dumps(value["isolation"], indent=2, allow_nan=False) + "\n").encode()).hexdigest()
    # The saved observer uses TRAIN.write's canonical serialization; bind its actual file too in check_bundle.
    check_panel(value["browser_panel"], revision, value["test_canary"], isolation_hash)
    require(value["browser_cleanup"] == dict(complete=True, remaining_owned_objects=0,
        guest_browser_root_removed=True, observed_process_lifetimes_ended=True, fallback_signals_used=False))


def check_bundle(path, revision, core):
    value = core["read"](path, 1048576)
    check_report(value, revision, core)
    for field in ("provision", "isolation", "snapshot", "owner_controls", "result_boundary", "private_service"):
        require(core["read"](path.parent / f"agent-private-task-{field}.json") == value[field])
    for field in ("panel", "provision"):
        require(core["read"](path.parent / f"{NAME}-{field}.json") == value[f"browser_{field}"])
    require(digest(path.parent / "agent-private-task-isolation.json") == value["browser_panel"]["core_observer_sha256"])
    for when in ("before", "after"):
        require(digest(path.parent / f"host-state-{when}.json") == value["host_state"][f"{when}_sha256"])


class BrowserFixture:
    def __init__(self, core):
        self.core, self.process, self.members, self.fallback = core, None, {}, False
        self.pins = load_pins()
        core["TRAIN"]["guest_guard"]()
        require(not ROOT.exists() and not ROOT.is_symlink())

    def provision(self, output, result):
        ROOT.mkdir(mode=0o700)
        require(shutil.disk_usage(ROOT).free >= 1024**3)
        revision = self.pins["revision"]
        result["phase"] = "private-browser-source-fetch"
        for name, record in self.pins["files"].items():
            fetch(f"https://raw.githubusercontent.com/VOLPAROSSA/volparossa-browser/{revision}/{name}", ROOT / name, record)
        package = ROOT / "firefox-esr.deb"
        result["phase"] = "private-browser-runtime-fetch"
        fetch(self.pins["runtime"]["url"], package, self.pins["runtime"])
        result["phase"] = "private-browser-runtime-extract"
        subprocess.run(["dpkg-deb", "--extract", str(package), str(ROOT / "package")], check=True,
                       stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=60)
        result["phase"] = "private-browser-runtime-stage"
        subprocess.run([sys.executable, "-B", str(ROOT / "scripts/stage_firefox.py"),
            "--firefox", str(ROOT / "package/usr/lib/firefox-esr/firefox-esr"),
            "--output", str(ROOT / "build/firefox-esr"), "--without-extensions",
            "--expected-version", self.pins["runtime"]["version"],
            "--expected-source-stamp", self.pins["runtime"]["source_stamp"]],
            check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=90)
        for name, expected in self.pins["runtime"]["files"].items():
            require(digest(ROOT / "build/firefox-esr" / name) == expected)
        result.update(browser_revision=revision, browser_manifest_sha256=digest(PINS), browser_provision=self.pins)
        self.core["write"](output / f"{NAME}-provision.json", self.pins)

    def track(self):
        if self.process is not None and self.process.poll() is None:
            for member in self.core["TRAIN"]["descendants"](self.process.pid):
                self.members[(member["pid"], member["start_ticks"])] = member
                require(len(self.members) <= 64)

    def infer(self, output, revision, socket_path, work_parent, service, canary, observed, result):
        self.deadline = time.monotonic() + 55
        try:
            self._infer(output, revision, socket_path, work_parent, service, canary, observed, result)
        finally:
            # Captured in the existing main report before cleanup removes the private root.
            # This diagnoses browser exit/timeout/module/broker errors; it is not success proof.
            result["browser_diagnostics"] = browser_diagnostic(ROOT / "build/model-proof", self.process, self.deadline)

    def _infer(self, output, revision, socket_path, work_parent, service, canary, observed, result):
        report_root = ROOT / "build/model-proof"
        result["phase"] = "private-browser-admission"
        with (ROOT / "runner.log").open("xb") as diagnostics:
            self.process = subprocess.Popen([sys.executable, "-B", str(ROOT / "scripts/smoke_compute_model.py"),
                "--stage", str(ROOT / "build/firefox-esr"), "--output", str(report_root),
                "--socket", str(socket_path), "--work-parent", str(work_parent),
                "--observer-file", str(output / "agent-private-task-isolation.json"),
                "--service-pid", str(service.pid), "--core-revision", revision, "--canary", canary],
                stdout=diagnostics, stderr=subprocess.STDOUT)
            deadline = time.monotonic() + 55
            self.deadline = deadline
            marker = report_root / "admitted.json"
            while not marker.is_file():
                self.track()
                require(self.process.poll() is None and time.monotonic() < deadline)
                time.sleep(0.1)
            require(self.core["read"](marker, 4096) == dict(version=1, event="real_core_job_admitted"))
            result["isolation"], result["snapshot"] = observed(output, "inference")
            result["phase"] = "private-browser-inference-and-render"
            deadline = time.monotonic() + 650
            self.deadline = deadline
            while self.process.poll() is None:
                self.track()
                require(time.monotonic() < deadline)
                time.sleep(0.1)
            require(self.process.returncode == 0)
        result["phase"] = "private-browser-result-binding"
        panel = self.core["read"](report_root / "report.json", 65536)
        check_panel(panel, revision, canary, digest(output / "agent-private-task-isolation.json"))
        result["browser_panel"] = panel
        self.core["write"](output / f"{NAME}-panel.json", panel)

    def cleanup(self):
        self.track()
        alive = self.core["TRAIN"]["alive"]
        # Firefox's main process has waited for its children; allow already-exiting
        # descendants to be reaped before deciding emergency signals were necessary.
        deadline = time.monotonic() + 2
        while self.process is not None and self.process.poll() is not None \
                and any(alive(member) for member in self.members.values()) and time.monotonic() < deadline:
            time.sleep(0.05)
        for sig in (signal.SIGINT, signal.SIGTERM, signal.SIGKILL):
            current = [member for member in self.members.values() if alive(member)]
            if not current:
                break
            self.fallback = True
            for member in reversed(current):
                if alive(member):
                    try:
                        os.kill(member["pid"], sig)
                    except ProcessLookupError:
                        pass
            if self.process is not None:
                try:
                    self.process.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    pass
            deadline = time.monotonic() + 5
            while any(alive(member) for member in current) and time.monotonic() < deadline:
                time.sleep(0.05)
        remaining = sum(alive(member) for member in self.members.values())
        if remaining == 0 and ROOT.exists():
            info = ROOT.lstat()
            require(stat.S_ISDIR(info.st_mode) and info.st_uid == os.getuid() and stat.S_IMODE(info.st_mode) == 0o700)
            shutil.rmtree(ROOT)
        count = remaining + int(ROOT.exists())
        return dict(complete=count == 0, remaining_owned_objects=count, guest_browser_root_removed=not ROOT.exists(),
                    observed_process_lifetimes_ended=remaining == 0, fallback_signals_used=self.fallback)


def self_test():
    pins = load_pins()
    require(len(pins["files"]) == 6)
    # Source-independent framing/privacy checks never count as a live Gecko/model result.
    for unsafe in ("", "main", "0" * 39, "g" * 40):
        require(re.fullmatch(r"[0-9a-f]{40}", unsafe) is None)
    revision, canary, observation = "a" * 40, "CANARY12345678", "b" * 64
    value = dict(passed=True, kind="real-gecko-panel-existing-private-core-service", version=1,
        scope=PANEL_SCOPE, core_revision=revision, synthetic_canary=canary,
        core_observer_sha256=observation, runtime_version=pins["runtime"]["version"],
        runtime_source_stamp=pins["runtime"]["source_stamp"], runtime_sha256=pins["runtime"]["files"],
        browser_source_sha256={name: pins["files"][name]["sha256"] for name in FILES},
        host_read_only=True, interfaces=["lo"], same_owner_socket_mode=0o600,
        private_prompt_absent_from_browser_log=True, temporary_browser_data_removed=True,
        observed=dict(admitted=1, removed=True, capabilities=dict(visibility="private_local", local_only=True,
            model_profile="smollm2-360m-v1", network_access=False, public_cache=False, training=False, cloud_fallback=False),
            answer=dict(answer_status="eos", complete=True, canary_present=True, generated_tokens=8),
            boundary=dict(point="decoded_result_before_panel_render", ephemeral_children=0, observed_worker_lifetimes_ended=True),
            panel=dict(actual_sidebar_document=True, connected=True, canary_rendered=True, text_only=True, eos_status_visible=True)))
    check_panel(value, revision, canary, observation)
    for path, replacement in (
        (("core_revision",), "c" * 40), (("core_observer_sha256",), "c" * 64),
        (("runtime_sha256", "libxul.so"), "c" * 64),
        (("browser_source_sha256", FILES[0]), "c" * 64),
        (("host_read_only",), False), (("interfaces",), ["lo", "eth0"]),
        (("raw_answer",), "PRIVATE-not-for-export"),
        (("scope", "firefox157_build_proven"), True),
        (("observed", "boundary", "point"), "first_result_frame_byte"),
        (("observed", "boundary", "ephemeral_children"), 1),
        (("observed", "answer", "generated_tokens"), 257),
        (("observed", "answer", "canary_present"), False),
        (("observed", "panel", "actual_sidebar_document"), False),
        (("observed", "capabilities", "cloud_fallback"), True),
    ):
        wrong = copy.deepcopy(value)
        target = wrong
        for key in path[:-1]:
            target = target[key]
        target[path[-1]] = replacement
        try:
            check_panel(wrong, revision, canary, observation)
        except ValueError:
            pass
        else:
            raise ValueError("unbound/private browser evidence accepted")
    with tempfile.TemporaryDirectory(prefix="private-browser-status-") as temporary:
        root = Path(temporary)
        class Process:
            def __init__(self, code):
                self.code = code
            def poll(self):
                return self.code
        result = browser_diagnostic(root, Process(None), time.monotonic() + 60)
        require(result == dict(process_state="running", exit_code=None, deadline_elapsed=False, status_state="absent"))
        status_path = root / "browser-status.json"
        status_path.write_text(json.dumps(dict(version=1, phase="broker-connect", failure="MODULE_UNAVAILABLE")))
        status_path.chmod(0o600)
        result = browser_diagnostic(root, Process(1), time.monotonic() + 60)
        require(result == dict(process_state="exited", exit_code=1, deadline_elapsed=False,
            status_state="valid", status=dict(version=1, phase="broker-connect", failure="MODULE_UNAVAILABLE")))
        require(browser_diagnostic(root, Process(None), time.monotonic() - 1)["deadline_elapsed"] is True)
        for bad in (
            dict(version=1, phase="broker-connect", failure="PRIVATE-not-for-export"),
            dict(version=1, phase="private input", failure=None),
            dict(version=1, phase="broker-connect", failure=None, answer="private answer"),
            dict(version=True, phase="broker-connect", failure=None),
        ):
            status_path.write_text(json.dumps(bad))
            result = browser_diagnostic(root, Process(1), time.monotonic() + 60)
            require(result["status_state"] == "invalid" and "status" not in result)
        status_path.write_bytes(b"x" * 4097)
        require(browser_diagnostic(root, None, time.monotonic() + 60)["status_state"] == "invalid")
        startup = dict(version=1, outcome="exited", firefox_exit_code=-4, elapsed_ms=1234,
            connection_deadline_elapsed=False, log_readable=True, log_truncated=False,
            log_signals=dict(library_load_message=False, profile_message=False, sandbox_message=False,
                permission_message=False, out_of_memory_message=False))
        startup_path = root / "browser-startup.json"
        startup_path.write_text(json.dumps(startup))
        startup_path.chmod(0o600)
        result = browser_diagnostic(root, Process(1), time.monotonic() + 60)
        require(result["runtime_startup_state"] == "valid" and result["runtime_startup"] == startup)
        for field, replacement in (("outcome", "private text"), ("firefox_exit_code", True),
                                   ("elapsed_ms", -1), ("raw_log", "private question"),
                                   ("log_signals", dict(library_load_message="private path"))):
            wrong = dict(startup)
            wrong[field] = replacement
            startup_path.write_text(json.dumps(wrong))
            result = browser_diagnostic(root, Process(1), time.monotonic() + 60)
            require(result["runtime_startup_state"] == "invalid" and "runtime_startup" not in result)
    print("private-browser exact source/runtime, result boundary, 14 rejection controls and fixed private-free diagnostics PASS; no browser/model executed")


if __name__ == "__main__":
    require(sys.argv[1:] == ["self-test"])
    self_test()
