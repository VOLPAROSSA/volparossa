#!/bin/sh
# SPDX-License-Identifier: GPL-3.0-only
# Deterministic unprivileged contract tests for the identity-bound QEMU supervisor.
set -eu

export LC_ALL=C
PATH=/usr/sbin:/usr/bin:/sbin:/bin
export PATH
umask 077

script_directory=$(CDPATH='' cd -- "$(dirname -- "$0")" && pwd)
supervisor=$script_directory/qemu-pidfd-supervisor.py
temporary_directory=$(mktemp -d /tmp/volparossa-qemu-supervisor.XXXXXX)
case $temporary_directory in
    /tmp/volparossa-qemu-supervisor.??????) ;;
    *)
        printf 'unsafe supervisor test directory: %s\n' "$temporary_directory" >&2
        exit 1
        ;;
esac

supervisor_processes=
parent_release=
supervisor_stdin_fixture=$temporary_directory/host-standard-input
printf '%s\n' 'must-not-reach-supervised-command' >"$supervisor_stdin_fixture"
chmod 0600 "$supervisor_stdin_fixture"
atomic_empty_file() {
    target=$1
    temporary=$target.tmp.$$
    (umask 077; : >"$temporary")
    chmod 600 "$temporary"
    mv -f -- "$temporary" "$target"
}
cleanup() {
    if [ -n "$parent_release" ] && [ ! -e "$parent_release" ]; then
        atomic_empty_file "$parent_release" || true
    fi
    for control_directory in "$temporary_directory"/control-*; do
        if [ -d "$control_directory" ] && [ ! -L "$control_directory" ]; then
            if [ ! -e "$control_directory/stop" ]; then
                atomic_empty_file "$control_directory/stop" || true
            fi
            if [ ! -e "$control_directory/ack" ]; then
                atomic_empty_file "$control_directory/ack" || true
            fi
        fi
    done
    for supervisor_process in $supervisor_processes; do
        wait "$supervisor_process" 2>/dev/null || true
    done
    rm -rf --one-file-system -- "$temporary_directory"
}
trap cleanup EXIT
trap 'exit 129' HUP
trap 'exit 130' INT
trap 'exit 143' TERM

if [ "$(id -u)" -eq 0 ]; then
    printf '%s\n' 'BLOCKED: pidfd supervisor tests must remain unprivileged' >&2
    exit 77
fi
if [ ! -f "$supervisor" ] || [ -L "$supervisor" ] || [ ! -x "$supervisor" ]; then
    printf '%s\n' 'the pidfd supervisor is missing, linked, or not executable' >&2
    exit 1
fi
PYTHONPYCACHEPREFIX=$temporary_directory/pycache
export PYTHONPYCACHEPREFIX
python3 -m py_compile "$supervisor"
python3 - <<'PY'
import os
import signal

if not hasattr(os, "pidfd_open") or not hasattr(signal, "pidfd_send_signal"):
    raise SystemExit("Python pidfd support is unavailable")
PY

new_control_directory() {
    name=$1
    control_directory=$temporary_directory/control-$name
    mkdir -m 700 "$control_directory"
    printf '%s\n' "$control_directory"
}

wait_for_file() {
    file=$1
    attempts=0
    while [ "$attempts" -lt 400 ]; do
        if [ -f "$file" ] && [ ! -L "$file" ]; then
            return 0
        fi
        attempts=$((attempts + 1))
        sleep 0.01
    done
    printf 'timed out waiting for protocol file: %s\n' "$file" >&2
    return 1
}

assert_private_regular_file() {
    file=$1
    if [ ! -f "$file" ] || [ -L "$file" ]; then
        printf 'protocol output is not a regular file: %s\n' "$file" >&2
        exit 1
    fi
    mode=$(stat -c '%a' "$file")
    links=$(stat -c '%h' "$file")
    if [ "$mode" != 600 ] || [ "$links" -ne 1 ]; then
        printf 'protocol output has unsafe metadata: %s\n' "$file" >&2
        exit 1
    fi
}

assert_json_equals() {
    file=$1
    expected=$2
    python3 - "$file" "$expected" <<'PY'
import json
import pathlib
import sys

path = pathlib.Path(sys.argv[1])
expected = json.loads(sys.argv[2])
raw = path.read_bytes()
parsed = json.loads(raw)
canonical = (json.dumps(parsed, ensure_ascii=True, separators=(",", ":"), sort_keys=True) + "\n").encode("ascii")
if parsed != expected or raw != canonical:
    raise SystemExit(f"non-canonical or unexpected protocol JSON: {path}")
PY
}

assert_no_atomic_temporary_files() {
    control_directory=$1
    if find "$control_directory" -mindepth 1 -maxdepth 1 -name '.*.tmp' -print -quit |
        grep -q .; then
        printf 'an atomic-write temporary file leaked in %s\n' "$control_directory" >&2
        exit 1
    fi
}

start_supervisor() {
    control_directory=$1
    stdout_file=$2
    stderr_file=$3
    shift 3
    "$supervisor" \
        --grace-seconds 0.05 \
        --term-seconds 0.15 \
        --kill-seconds 0.50 \
        --ack-timeout-seconds 2 \
        "$control_directory" -- "$@" \
        <"$supervisor_stdin_fixture" >"$stdout_file" 2>"$stderr_file" &
    started_process=$!
    supervisor_processes="$supervisor_processes $started_process"
}

wait_for_supervisor() {
    process=$1
    expected=$2
    set +e
    wait "$process"
    actual=$?
    set -e
    if [ "$actual" -ne "$expected" ]; then
        printf 'expected supervisor exit %s, got %s\n' "$expected" "$actual" >&2
        exit 1
    fi
}

ready_json='{"protocol":"volparossa-qemu-pidfd-supervisor-v1","state":"ready"}'

# A naturally exiting child is reaped, reported canonically, and held for ack.
normal_control=$(new_control_directory normal)
VOLPAROSSA_SUPERVISOR_TEST_SECRET=must-not-reach-child
export VOLPAROSSA_SUPERVISOR_TEST_SECRET
exec 9>"$temporary_directory/inherited-descriptor"
start_supervisor "$normal_control" \
    "$temporary_directory/normal.stdout" "$temporary_directory/normal.stderr" \
    python3 -c \
    'import os, stat, sys; metadata = os.fstat(0); bad = "VOLPAROSSA_SUPERVISOR_TEST_SECRET" in os.environ or os.path.exists("/proc/self/fd/9") or not stat.S_ISCHR(metadata.st_mode) or os.major(metadata.st_rdev) != 1 or os.minor(metadata.st_rdev) != 3 or os.read(0, 1) != b""; sys.exit(99 if bad else 7)'
normal_supervisor=$started_process
unset VOLPAROSSA_SUPERVISOR_TEST_SECRET
exec 9>&-
wait_for_file "$normal_control/ready"
wait_for_file "$normal_control/status"
assert_private_regular_file "$normal_control/ready"
assert_private_regular_file "$normal_control/status"
assert_json_equals "$normal_control/ready" "$ready_json"
assert_json_equals "$normal_control/status" \
    '{"exit_code":7,"exit_signal":null,"protocol":"volparossa-qemu-pidfd-supervisor-v1","state":"exited","termination":"none","trigger":"child-exit"}'
assert_no_atomic_temporary_files "$normal_control"
if [ ! -r "/proc/$normal_supervisor/stat" ]; then
    printf '%s\n' 'supervisor exited before the parent acknowledgement' >&2
    exit 1
fi
if [ -s "$temporary_directory/normal.stdout" ] ||
    [ -s "$temporary_directory/normal.stderr" ]; then
    printf '%s\n' 'successful normal lifecycle emitted output' >&2
    exit 1
fi
atomic_empty_file "$normal_control/ack"
wait_for_supervisor "$normal_supervisor" 0
assert_private_regular_file "$normal_control/ack"
assert_json_equals "$normal_control/status" \
    '{"exit_code":7,"exit_signal":null,"protocol":"volparossa-qemu-pidfd-supervisor-v1","state":"exited","termination":"none","trigger":"child-exit"}'

# An atomic stop request reaches the exact child through pidfd SIGTERM.
term_control=$(new_control_directory term)
term_child_ready=$temporary_directory/term-child-ready
start_supervisor "$term_control" \
    "$temporary_directory/term.stdout" "$temporary_directory/term.stderr" \
    python3 -c \
    'import pathlib, sys, time; pathlib.Path(sys.argv[1]).touch(mode=0o600); time.sleep(30)' \
    "$term_child_ready"
term_supervisor=$started_process
wait_for_file "$term_control/ready"
wait_for_file "$term_child_ready"
atomic_empty_file "$term_control/stop"
wait_for_file "$term_control/status"
assert_json_equals "$term_control/status" \
    '{"exit_code":null,"exit_signal":15,"protocol":"volparossa-qemu-pidfd-supervisor-v1","state":"exited","termination":"term","trigger":"stop-requested"}'
assert_private_regular_file "$term_control/stop"
atomic_empty_file "$term_control/ack"
wait_for_supervisor "$term_supervisor" 0
if [ -s "$temporary_directory/term.stdout" ] ||
    [ -s "$temporary_directory/term.stderr" ]; then
    printf '%s\n' 'successful TERM lifecycle emitted output' >&2
    exit 1
fi

# A child that has installed SIG_IGN for TERM is killed through its pidfd.
kill_control=$(new_control_directory kill)
kill_child_ready=$temporary_directory/kill-child-ready
start_supervisor "$kill_control" \
    "$temporary_directory/kill.stdout" "$temporary_directory/kill.stderr" \
    python3 -c \
    'import pathlib, signal, sys, time; signal.signal(signal.SIGTERM, signal.SIG_IGN); pathlib.Path(sys.argv[1]).touch(mode=0o600); time.sleep(30)' \
    "$kill_child_ready"
kill_supervisor=$started_process
wait_for_file "$kill_control/ready"
wait_for_file "$kill_child_ready"
atomic_empty_file "$kill_control/stop"
wait_for_file "$kill_control/status"
assert_json_equals "$kill_control/status" \
    '{"exit_code":null,"exit_signal":9,"protocol":"volparossa-qemu-pidfd-supervisor-v1","state":"exited","termination":"kill","trigger":"stop-requested"}'
atomic_empty_file "$kill_control/ack"
wait_for_supervisor "$kill_supervisor" 0
if [ -s "$temporary_directory/kill.stdout" ] ||
    [ -s "$temporary_directory/kill.stderr" ]; then
    printf '%s\n' 'successful KILL lifecycle emitted output' >&2
    exit 1
fi

# PR_SET_PDEATHSIG turns loss of the direct parent into the same bounded cleanup.
parent_control=$(new_control_directory parent-death)
parent_child_ready=$temporary_directory/parent-death-child-ready
parent_release=$temporary_directory/parent-death-release
python3 -c '
import ctypes
import os
import pathlib
import signal
import sys
import time

supervisor, control, child_ready, release, stdout_file, stderr_file = sys.argv[1:]
libc = ctypes.CDLL(None, use_errno=True)
if libc.prctl(36, 1, 0, 0, 0) != 0:  # PR_SET_CHILD_SUBREAPER
    raise SystemExit("could not become a child subreaper")
owner = os.fork()
if owner == 0:
    supervised = os.fork()
    if supervised == 0:
        stdout = os.open(stdout_file, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        stderr = os.open(stderr_file, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        os.dup2(os.open(os.devnull, os.O_RDONLY), 0)
        os.dup2(stdout, 1)
        os.dup2(stderr, 2)
        os.closerange(3, 1024)
        os.execv(
            supervisor,
            [
                supervisor,
                "--grace-seconds", "0.05",
                "--term-seconds", "0.15",
                "--kill-seconds", "0.50",
                "--ack-timeout-seconds", "2",
                control,
                "--",
                "python3",
                "-c",
                "import pathlib, signal, sys, time; signal.signal(signal.SIGTERM, signal.SIG_IGN); pathlib.Path(sys.argv[1]).touch(mode=0o600); time.sleep(30)",
                child_ready,
            ],
        )
    while not pathlib.Path(release).is_file():
        time.sleep(0.01)
    os._exit(0)
_, owner_status = os.waitpid(owner, 0)
if not os.WIFEXITED(owner_status) or os.WEXITSTATUS(owner_status) != 0:
    raise SystemExit("owner fixture failed")
supervised, supervisor_status = os.waitpid(-1, 0)
if supervised <= 0 or not os.WIFEXITED(supervisor_status) or os.WEXITSTATUS(supervisor_status) != 0:
    raise SystemExit("supervisor fixture failed")
' "$supervisor" "$parent_control" "$parent_child_ready" "$parent_release" \
    "$temporary_directory/parent-death.stdout" "$temporary_directory/parent-death.stderr" &
parent_harness=$!
supervisor_processes="$supervisor_processes $parent_harness"
wait_for_file "$parent_control/ready"
wait_for_file "$parent_child_ready"
atomic_empty_file "$parent_release"
wait_for_file "$parent_control/status"
assert_json_equals "$parent_control/status" \
    '{"exit_code":null,"exit_signal":9,"protocol":"volparossa-qemu-pidfd-supervisor-v1","state":"exited","termination":"kill","trigger":"parent-death"}'
atomic_empty_file "$parent_control/ack"
wait_for_supervisor "$parent_harness" 0
if [ -s "$temporary_directory/parent-death.stdout" ] ||
    [ -s "$temporary_directory/parent-death.stderr" ]; then
    printf '%s\n' 'successful parent-death lifecycle emitted output' >&2
    exit 1
fi

# Invalid arguments and unsafe control directories fail before launching COMMAND.
usage_control=$(new_control_directory usage)
set +e
"$supervisor" "$usage_control" -- \
    >"$temporary_directory/usage.stdout" 2>"$temporary_directory/usage.stderr"
usage_status=$?
set -e
if [ "$usage_status" -ne 64 ] || [ -e "$usage_control/ready" ]; then
    printf '%s\n' 'missing COMMAND did not fail closed with EX_USAGE' >&2
    exit 1
fi

unsafe_control=$temporary_directory/control-unsafe
mkdir -m 755 "$unsafe_control"
unsafe_marker=$temporary_directory/unsafe-command-ran
set +e
"$supervisor" "$unsafe_control" -- /usr/bin/touch "$unsafe_marker" \
    >"$temporary_directory/unsafe.stdout" 2>"$temporary_directory/unsafe.stderr"
unsafe_status=$?
set -e
if [ "$unsafe_status" -eq 0 ] || [ -e "$unsafe_marker" ]; then
    printf '%s\n' 'unsafe control-directory mode did not fail before COMMAND' >&2
    exit 1
fi

stale_control=$(new_control_directory stale)
atomic_empty_file "$stale_control/stop"
stale_marker=$temporary_directory/stale-command-ran
set +e
"$supervisor" "$stale_control" -- /usr/bin/touch "$stale_marker" \
    >"$temporary_directory/stale.stdout" 2>"$temporary_directory/stale.stderr"
stale_status=$?
set -e
if [ "$stale_status" -eq 0 ] || [ -e "$stale_marker" ] || [ -e "$stale_control/ready" ]; then
    printf '%s\n' 'stale control protocol did not fail before COMMAND' >&2
    exit 1
fi

real_control=$(new_control_directory real)
linked_control=$temporary_directory/control-linked
ln -s "$real_control" "$linked_control"
linked_marker=$temporary_directory/linked-command-ran
set +e
"$supervisor" "$linked_control" -- /usr/bin/touch "$linked_marker" \
    >"$temporary_directory/linked.stdout" 2>"$temporary_directory/linked.stderr"
linked_status=$?
set -e
if [ "$linked_status" -eq 0 ] || [ -e "$linked_marker" ]; then
    printf '%s\n' 'linked control directory did not fail before COMMAND' >&2
    exit 1
fi

pidfd_failure_control=$(new_control_directory pidfd-failure)
pidfd_failure_marker=$temporary_directory/pidfd-failure-command-ran
python3 - "$supervisor" "$pidfd_failure_control" "$pidfd_failure_marker" <<'PY'
import errno
import importlib.util
import json
import os
import pathlib
import sys
import threading
import time

supervisor_path, control_directory, marker = sys.argv[1:]
module_name = "volparossa_qemu_pidfd_supervisor_failure_test"
spec = importlib.util.spec_from_file_location(module_name, supervisor_path)
if spec is None or spec.loader is None:
    raise SystemExit("could not load supervisor module")
module = importlib.util.module_from_spec(spec)
sys.modules[module_name] = module
spec.loader.exec_module(module)
captured_processes = []
real_pidfd_open = module.os.pidfd_open
real_pidfd_send_signal = module.signal.pidfd_send_signal
base_control = pathlib.Path(control_directory)
expected_failure = {
    "error": "supervisor-failure",
    "protocol": "volparossa-qemu-pidfd-supervisor-v1",
    "state": "failed",
}


def fresh_configuration(name):
    control = base_control if name == "missing-open" else pathlib.Path(f"{base_control}-{name}")
    if control != base_control:
        control.mkdir(mode=0o700)
    return module.Configuration(
        control_directory=str(control),
        command=("/usr/bin/touch", marker),
        grace_seconds=0.05,
        term_seconds=0.05,
        kill_seconds=0.50,
        ack_timeout_seconds=1.0,
    )


def run_expected_failure(configuration):
    control = pathlib.Path(configuration.control_directory)
    acknowledgement_errors = []

    def acknowledge():
        status = control / "status"
        for _ in range(200):
            if status.is_file() and not status.is_symlink():
                try:
                    raw = status.read_bytes()
                    expected_raw = (
                        json.dumps(
                            expected_failure,
                            ensure_ascii=True,
                            separators=(",", ":"),
                            sort_keys=True,
                        )
                        + "\n"
                    ).encode("ascii")
                    if raw != expected_raw:
                        raise RuntimeError("failure status is not exact canonical JSON")
                    descriptor = os.open(
                        control / "ack",
                        os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_CLOEXEC,
                        0o600,
                    )
                    os.close(descriptor)
                except BaseException as error:
                    acknowledgement_errors.append(error)
                return
            time.sleep(0.01)
        acknowledgement_errors.append(RuntimeError("failure status was not published"))

    acknowledgement = threading.Thread(target=acknowledge)
    acknowledgement.start()
    try:
        module.supervise(configuration)
    except module.SupervisorError:
        pass
    else:
        raise SystemExit("injected supervisor failure was accepted")
    acknowledgement.join(timeout=3.0)
    if acknowledgement.is_alive() or acknowledgement_errors:
        raise SystemExit(f"failure acknowledgement failed: {acknowledgement_errors}")
    if (control / "ready").exists():
        raise SystemExit("pre-ready failure published ready")
    for name in ("status", "ack"):
        metadata = (control / name).stat()
        if not pathlib.Path(control / name).is_file() or metadata.st_mode & 0o777 != 0o600 or metadata.st_nlink != 1:
            raise SystemExit(f"unsafe failure protocol metadata: {name}")

for missing_api in ("pidfd_open", "pidfd_send_signal"):
    configuration = fresh_configuration(
        "missing-open" if missing_api == "pidfd_open" else "missing-send"
    )
    if missing_api == "pidfd_open":
        module.os.pidfd_open = None
    else:
        module.signal.pidfd_send_signal = None
    try:
        run_expected_failure(configuration)
    finally:
        module.os.pidfd_open = real_pidfd_open
        module.signal.pidfd_send_signal = real_pidfd_send_signal
    if pathlib.Path(marker).exists():
        raise SystemExit(f"COMMAND ran without {missing_api}")

def fail_pidfd_open(process_id, _flags):
    captured_processes.append(process_id)
    raise OSError(errno.EMFILE, "injected pidfd_open failure")

module.os.pidfd_open = fail_pidfd_open
configuration = fresh_configuration("open-error")
try:
    run_expected_failure(configuration)
finally:
    module.os.pidfd_open = real_pidfd_open
if pathlib.Path(marker).exists() or len(captured_processes) != 1:
    raise SystemExit("COMMAND ran or pidfd_open was not attempted exactly once")
try:
    os.waitpid(captured_processes[0], os.WNOHANG)
except ChildProcessError:
    pass
else:
    raise SystemExit("unbound fork child was not reaped")
PY
if [ -e "$pidfd_failure_marker" ] || [ -e "$pidfd_failure_control/ready" ] \
    || [ ! -e "$pidfd_failure_control/status" ] \
    || [ ! -e "$pidfd_failure_control/ack" ]; then
    printf '%s\n' 'pidfd_open failure did not fail before COMMAND release' >&2
    exit 1
fi

set +e
"$supervisor" --grace-seconds nan "$usage_control" -- /bin/true \
    >"$temporary_directory/nan.stdout" 2>"$temporary_directory/nan.stderr"
nan_status=$?
set -e
if [ "$nan_status" -ne 64 ]; then
    printf '%s\n' 'non-finite lifecycle timeout did not fail with EX_USAGE' >&2
    exit 1
fi
set +e
"$supervisor" --kill-seconds 0 "$usage_control" -- /bin/true \
    >"$temporary_directory/zero-kill.stdout" 2>"$temporary_directory/zero-kill.stderr"
zero_kill_status=$?
set -e
if [ "$zero_kill_status" -ne 64 ]; then
    printf '%s\n' 'zero KILL reap timeout did not fail with EX_USAGE' >&2
    exit 1
fi

printf '%s\n' \
    'PASS: pidfd supervisor normal, TERM, KILL, parent-death, pre-ready failure, isolated stdin/environment/FDs, atomic status, and ack lifecycles are exact.'
