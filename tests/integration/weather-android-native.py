#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-only
"""Invoke the unchanged pinned Weather main and retain only typed failure data.

Runtime output still belongs to the owner's bounded, private pipes. This
launcher appends one final marked record, never a traceback or exception text.
It does not change native guards, resource budgets, cleanup or acceptance.
"""
import hashlib
import json
import os
from pathlib import Path
import re
import runpy
import stat
import subprocess
import sys

HERE = Path(__file__).resolve().parent
CORE = HERE.parents[1]
K = runpy.run_path(str(HERE / "weather-android-kvm.py"))
E = runpy.run_path(str(HERE / "weather-android-evidence.py"))
WEATHER_COMMIT = "3b90442a9d5be4db73ccf83cba2028364980c3ca"
ENTRYPOINT_SHA256 = "fdf07c912236ecc7f08bb2c63af97e2a2a799409d58b8a2736f172123ae5c490"
PREFIX = "VOLPAROSSA_ANDROID_NATIVE_DIAGNOSTIC "
CATEGORIES = frozenset(("interrupted", "value", "key", "type", "timeout", "process", "os", "system_exit", "unknown"))
# Reviewed literal errors in f6's Android entrypoint and its pinned hosted
# helpers. Do not derive an allowlist from runtime text or accept code-shaped
# strings: unknown messages, filenames and exception details stay private.
CODES = frozenset("""
UNKNOWN NATIVE_LAUNCHER_ARGUMENTS NATIVE_LAUNCHER_IDENTITY NATIVE_LAUNCHER_SOURCE
NATIVE_LAUNCHER_PATH NATIVE_LAUNCHER_RUNTIME
HOSTED_PROFILE DISPOSABLE_HOSTED_ONLY EXACT_SOURCE CORE_CHECKOUT_SCOPE
CORE_RUN_IDENTITY UBUNTU_24_REQUIRED SOURCE_HEAD POLICY_CHANGED
OWNED_INPUT_REQUIRED KVM_REQUIRED_NO_TCG HOST_MEMORY_RESERVE
CORE_PREPARATION_IDENTITY CORE_PREPARATION_COMPLETION CORE_PREPARATION_CLEANUP
PREPARED_APK_CHANGED PREPARED_NATIVE_SOURCE_CHANGED PREPARED_RUNTIME_CHANGED
PREPARED_SDK_CHANGED PREPARED_ANDROID_CHANGED PREPARED_DEPENDENCIES_CHANGED
PREPARED_DISTRO_TOOL_CHANGED PREPARED_RECEIPT_CHANGED PREPARED_RECEIPT_SET
PREPARED_MOUNT_CHANGED PREPARED_APP_CHANGED_DURING_TRIAL
CORE_SOCKET_PATH CORE_SOCKET_PARENT CORE_SOCKET_ONLY CORE_SOCKET_CHANGED
CORE_SOCKET_READ_ONLY_MOUNT HOSTED_ANDROID_CORE_INTERRUPTED LIVE_EMULATOR_CLEANUP
LIVE_INSTALLED_APP_PROOF LIVE_INSTALLED_APP_SCOPE LIVE_INSTALLED_APP_COMPLETION
LIVE_INSTALLED_APP_CHECKS LIVE_INSTALLED_PRODUCT_PAIR LIVE_INSTALLED_PRODUCT_BINDING
LIVE_FORECAST_PAIR LIVE_FORECAST_BINDING LIVE_RESPONSE_BINDING
CLEANUP_UNCONFIRMED GRADLE_USER_HOME_PRIVATE GRADLE_USER_PROPERTIES_PRIVATE
GRADLE_USER_PROPERTIES_CHANGED NATIVE_SANDBOX_MODE SOCKET_EMULATOR_ONLY
NATIVE_SOURCE_CHANGED NATIVE_SOURCE_COUNT NATIVE_SOURCE_NAME NATIVE_SOURCE_BINDING_CHANGED
JAVA_17_REQUIRED JAVA_TOOL JAVA_TOOL_BOUND JAVA_TOOL_CHANGED JAVA_TOOL_PATH
AWK_TOOL AWK_TOOL_BOUND AWK_TOOL_CHANGED AWK_TOOL_PATH
DEPENDENCY_METADATA_CHANGED GRADLE_METADATA_HASHES GRADLE_METADATA_XML
PREFLIGHT PREFLIGHT_SCOPE OFFLINE_SANDBOX_ONLY INSIDE_SCOPE
EMULATOR_INTERRUPTED EMULATOR_DEADLINE EMULATOR_BOOT_FAILED
EMULATOR_CLEANUP_UNCONFIRMED EMULATOR_COMMAND_DEADLINE EMULATOR_COMMAND_OUTPUT
NO_ARBITRARY_COMMAND PRIVATE_CLEANUP_PATH NATIVE_OWNED_SPAWN_INTERRUPTED
ORDINARY_RUNNER_REQUIRED EXPLICIT_DISPOSABLE_CI_REQUIRED CI_SOURCE_REQUIRED
CI_SOURCE_CHANGED UBUNTU_24_CI_REQUIRED POLICY_PROVENANCE_CHANGED
PACKAGED_BWRAP_REQUIRED BWRAP_PRIVILEGES_CHANGED PARSER_REQUIRED
PACKAGE_VERIFICATION_FAILED EXISTING_POLICY_CONFLICT EXPECTED_USERNS_RESTRICTION_REQUIRED
STAGING_PATH_EXISTS STAGED_POLICY_CHANGED PROFILE_INVENTORY_INVALID
SANDBOX_PREFLIGHT_FAILED CI_INTERRUPTED CI_POLICY_CLEANUP_FAILED
UNSAFE_OR_OVERSIZED_INPUT INPUT_BOUND UNSAFE_FILE PRIVATE_DIRECTORY_REQUIRED
DUPLICATE_JSON_KEY CHILD_FAILED CHILD_MEMORY_BOUND CHILD_PROCESS_BOUND CHILD_STATUS_BOUND
OUTPUT_BOUND LOG_BOUND PHASE_DEADLINE WHOLE_BUILD_DEADLINE CLEANUP_UNPROVEN
CANCELLED_DURING_OWNED_SPAWN POLICY_PROVENANCE PREFLIGHT_FAILED
SDK_FILES SDK_TOOL_MOUNT_NOT_EMPTY SDK_TOOL_PARENT SDK_TOOL_STATE_BOUND
SDK_TOOL_STATE_OWNER SDK_TOOL_STATE_PATH SDK_TOOL_STATE_ROOT SDK_TOOL_STATE_TYPE
RUNTIME_PATH RUNTIME_RECORD RUNTIME_ROOT_TYPE RUNTIME_SIZE_BOUND RUNTIME_TREE_BOUND
RUNTIME_TREE_TYPE RUNTIME_BYTES_CHANGED RUNTIME_INVENTORY_BOUND
RUNTIME_EXTRA_OR_MISSING_FILES RUNTIME_PROVENANCE_CHANGED
CANONICAL_WHICH_REQUIRED UNSAFE_WHICH OWNED_SOURCE_REQUIRED SOURCE_COMMIT_CHANGED
SYSTEM_TOOLS_CHANGED FLUTTER_COMMIT_CHANGED FLUTTER_EXECUTABLE_CHANGED
""".split())


def require(condition, code):
    if not condition:
        raise ValueError(code)


def validate_diagnostic(value):
    require(type(value) is dict and set(value) == {"schema", "kind", "outcome", "category", "code",
        "joined_core_acceptance"}, "NATIVE_LAUNCHER_RUNTIME")
    require(type(value["schema"]) is int and value["schema"] == 6
        and value["kind"] == "weather-android-native-diagnostic" and value["outcome"] == "failed"
        and type(value["category"]) is str and value["category"] in CATEGORIES
        and type(value["code"]) is str and value["code"] in CODES
        and value["joined_core_acceptance"] is False, "NATIVE_LAUNCHER_RUNTIME")
    return value


def diagnostic(error, interrupted=None):
    category = ("interrupted" if isinstance(error, KeyboardInterrupt)
        or isinstance(interrupted, type) and isinstance(error, interrupted) else
        "timeout" if isinstance(error, subprocess.TimeoutExpired) else
        "process" if isinstance(error, subprocess.SubprocessError) else
        "os" if isinstance(error, OSError) else
        "key" if isinstance(error, KeyError) else
        "type" if isinstance(error, TypeError) else
        "value" if isinstance(error, ValueError) else
        "system_exit" if isinstance(error, SystemExit) else "unknown")
    # Only ValueError and the pinned interrupt type carry reviewed literal
    # codes. Never stringify CalledProcessError, OSError, SystemExit or keys.
    code = "UNKNOWN"
    if category in ("value", "interrupted") and len(error.args) == 1:
        literal = error.args[0]
        if type(literal) is str and len(literal) <= 96 and literal in CODES:
            code = literal
    return validate_diagnostic(dict(schema=6, kind="weather-android-native-diagnostic", outcome="failed",
        category=category, code=code, joined_core_acceptance=False))


def owned(path, *, directory=False):
    path = Path(path)
    require(path.is_absolute() and path.resolve(strict=True) == path, "NATIVE_LAUNCHER_PATH")
    info = path.lstat()
    require((stat.S_ISDIR if directory else stat.S_ISREG)(info.st_mode)
        and info.st_uid == os.getuid() and not info.st_mode & 0o022
        and (directory or info.st_nlink == 1), "NATIVE_LAUNCHER_PATH")
    return path


def verified_script(weather, core_commit, weather_commit, socket):
    expected = dict(GITHUB_ACTIONS="true", RUNNER_OS="Linux", RUNNER_ENVIRONMENT="github-hosted",
        GITHUB_REPOSITORY="VOLPAROSSA/volparossa", GITHUB_WORKFLOW="Weather Android protected core delivery",
        GITHUB_WORKSPACE=str(CORE), GITHUB_SHA=core_commit, VOLPAROSSA_WEATHER_SOURCE_SHA=weather_commit)
    require(os.getuid() == os.geteuid() != 0 and re.fullmatch("[0-9a-f]{40}", core_commit)
        and weather_commit == WEATHER_COMMIT and all(os.environ.get(k) == v for k, v in expected.items())
        and all(re.fullmatch("[1-9][0-9]{0,19}", os.environ.get(k, ""))
            for k in ("GITHUB_RUN_ID", "GITHUB_RUN_ATTEMPT")), "NATIVE_LAUNCHER_IDENTITY")
    weather = owned(weather, directory=True)
    require(weather != CORE and weather.is_relative_to(CORE), "NATIVE_LAUNCHER_PATH")
    require(Path(socket).is_absolute() and len(os.fsencode(socket)) < 104
        and not re.search(r"[\x00-\x1f\x7f]", socket), "NATIVE_LAUNCHER_PATH")
    environment = dict(PATH="/usr/bin:/bin", LANG="C.UTF-8", LC_ALL="C.UTF-8",
        GIT_CONFIG_NOSYSTEM="1", GIT_CONFIG_GLOBAL="/dev/null", GIT_OPTIONAL_LOCKS="0", GIT_TERMINAL_PROMPT="0")
    for root, commit in ((CORE, core_commit), (weather, weather_commit)):
        base = ["/usr/bin/git", "--no-optional-locks", "-c", "core.hooksPath=/dev/null", "-c",
            "core.fsmonitor=false", "-C", str(root)]
        head = subprocess.run([*base, "rev-parse", "HEAD"], stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, env=environment, timeout=10, check=True)
        require(head.stdout == (commit + "\n").encode(), "NATIVE_LAUNCHER_SOURCE")
        subprocess.run([*base, "-c", "diff.autoRefreshIndex=false", "diff", "--no-ext-diff", "--quiet", "HEAD", "--"],
            stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
            env=environment, timeout=15, check=True)
    script = owned(weather / "scripts/prepare_hosted_android_ci.py")
    require(script.stat().st_size <= 256 * 1024, "NATIVE_LAUNCHER_SOURCE")
    with script.open("rb") as stream:
        raw = stream.read(256 * 1024 + 1)
    require(len(raw) <= 256 * 1024 and hashlib.sha256(raw).hexdigest() == ENTRYPOINT_SHA256,
        "NATIVE_LAUNCHER_SOURCE")
    return script


def load_kvm_baseline(socket, selected_identity):
    # The only readable baseline belongs to this owner's canonical run tree.
    # Failure remains diagnostic: original Weather admission still decides.
    path = Path(socket)
    try:
        require(path.name == "core-api.sock" and path.parent.name == "android-api"
            and path.is_absolute() and path.parent.parent.is_relative_to(CORE)
            and re.fullmatch(r"weather-client-kvm\.[A-Za-z0-9]{6}", path.parent.parent.name),
            "NATIVE_LAUNCHER_PATH")
        target = path.parent.parent / "android-owner/kvm-baseline.json"
        value = E["decode"](E["private_bytes"](target, 16384, os.getuid(), 0o600), 16384)
        return K["baseline"](value, selected_identity), "available"
    except FileNotFoundError: return None, "absent"
    except (OSError, ValueError, TypeError, KeyError, RecursionError): return None, "rejected"


def main(arguments):
    previous, interrupted = sys.argv, None
    observation, before, initial, selected_identity = None, None, None, None
    baseline_state = "absent"
    try:
        require(len(arguments) == 8 and arguments[::2] == ["--weather-root", "--core-commit",
            "--weather-commit", "--upstream-socket"], "NATIVE_LAUNCHER_ARGUMENTS")
        weather, core_commit, weather_commit, socket = arguments[1::2]
        script = verified_script(weather, core_commit, weather_commit, socket)
        runtime = runpy.run_path(str(script), run_name="__volparossa_android_native__")
        interrupted = runtime["H"].Interrupted
        selected_identity = dict(core_commit=core_commit, weather_commit=weather_commit,
            run_id=os.environ["GITHUB_RUN_ID"], run_attempt=os.environ["GITHUB_RUN_ATTEMPT"])
        # This baseline is private owner state, never an exported artifact. A
        # missing/rejected diagnostic baseline does not replace Weather guards.
        try:
            initial, baseline_state = load_kvm_baseline(socket, selected_identity)
            before = K["snapshot"]()
            observation = K["native_record"](selected_identity, before, initial, baseline_state)
        except (OSError, ValueError, TypeError, KeyError, RecursionError, NotImplementedError):
            # Diagnostic failure is explicitly absent in the owner's receipt;
            # it must not become a replacement for the original native guard.
            observation = None
        sys.argv = [str(script), "--run-protected-core", "--upstream-socket", socket]
        # Invoke the original entrypoint, including every guard. Its generic
        # __main__ catch is the only bypassed layer; its internal finally and
        # cleanup still run before our exception handler sees any failure.
        runtime["main"]()
        if observation is not None:
            print("\n" + K["PREFIX"] + json.dumps(observation, sort_keys=True, separators=(",", ":")), flush=True)
        return 0
    except BaseException as error:
        value = diagnostic(error, interrupted)
        # Probe again only for the exact original KVM guard. Never replace the
        # original failure with an observation/serialization failure.
        if observation is not None:
            if value["category"] == "value" and value["code"] == "KVM_REQUIRED_NO_TCG":
                try:
                    observation = K["native_record"](selected_identity, before, initial,
                        baseline_state, K["snapshot"]())
                except (OSError, ValueError, TypeError, KeyError, RecursionError): pass
            print("\n" + K["PREFIX"] + json.dumps(observation, sort_keys=True, separators=(",", ":")), flush=True)
        # Prefix and final line are parsed strictly by the owner. Existing
        # native output is not republished as evidence; its old pipe cap stays.
        print(("" if observation is not None else "\n") + PREFIX
            + json.dumps(value, sort_keys=True, separators=(",", ":")), flush=True)
        return 1
    finally:
        sys.argv = previous


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
