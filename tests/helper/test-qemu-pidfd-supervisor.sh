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

wait_for_status_after_stderr() {
    control_directory=$1
    attempts=0
    while [ "$attempts" -lt 400 ]; do
        if [ -e "$control_directory/status" ] \
            && { [ ! -f "$control_directory/stderr" ] \
                || [ -L "$control_directory/stderr" ]; }; then
            printf '%s\n' 'status became visible before finalized stderr' >&2
            return 1
        fi
        if [ -f "$control_directory/status" ] \
            && [ ! -L "$control_directory/status" ]; then
            return 0
        fi
        attempts=$((attempts + 1))
        sleep 0.01
    done
    printf 'timed out waiting for supervisor status: %s\n' "$control_directory" >&2
    return 1
}

wait_for_qmp_status_after_outputs() {
    control_directory=$1
    attempts=0
    while [ "$attempts" -lt 400 ]; do
        if [ -e "$control_directory/status" ] \
            && { [ ! -f "$control_directory/qmp" ] \
                || [ -L "$control_directory/qmp" ] \
                || [ ! -f "$control_directory/stderr" ] \
                || [ -L "$control_directory/stderr" ]; }; then
            printf '%s\n' 'status became visible before finalized QMP and stderr' >&2
            return 1
        fi
        if [ -f "$control_directory/status" ] \
            && [ ! -L "$control_directory/status" ]; then
            return 0
        fi
        attempts=$((attempts + 1))
        sleep 0.01
    done
    printf 'timed out waiting for QMP supervisor status: %s\n' \
        "$control_directory" >&2
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

start_qmp_supervisor() {
    control_directory=$1
    stdout_file=$2
    stderr_file=$3
    shift 3
    "$supervisor" \
        --grace-seconds 0.05 \
        --term-seconds 0.15 \
        --kill-seconds 0.50 \
        --ack-timeout-seconds 2 \
        --qmp-stdio \
        --qmp-timeout-seconds 0.75 \
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

ready_json='{"protocol":"volparossa-qemu-pidfd-supervisor-v3","state":"ready"}'

# QMP stdio is private to the supervisor. It negotiates capabilities, sends
# only cont, publishes ready after that reply, and retains only allowlisted
# canonical events before status.
qmp_control=$(new_control_directory qmp)
start_qmp_supervisor "$qmp_control" \
    "$temporary_directory/qmp.stdout" "$temporary_directory/qmp.stderr" \
    python3 -c '
import json
import select
import sys


def emit(value):
    encoded = json.dumps(value, ensure_ascii=True, separators=(",", ":"))
    sys.stdout.buffer.write(encoded.encode("ascii") + b"\r\n")
    sys.stdout.buffer.flush()


secret = "-----BEGIN PRIVATE KEY-----"
emit({
    "QMP": {
        "capabilities": [],
        "future": secret,
        "version": {
            "future": secret,
            "package": "fake-qemu",
            "qemu": {"future": secret, "major": 8, "micro": 8, "minor": 2},
        },
    },
    "future": secret,
})
if sys.stdin.buffer.readline() != b"{\"execute\":\"qmp_capabilities\",\"id\":\"volparossa-capabilities\"}\r\n":
    raise SystemExit(91)
emit({"future": secret, "id": "volparossa-capabilities", "return": {"future": secret}})
if sys.stdin.buffer.readline() != b"{\"execute\":\"cont\",\"id\":\"volparossa-cont\"}\r\n":
    raise SystemExit(92)
emit({"future": secret, "id": "volparossa-cont", "return": {"future": secret}})
timestamp = {"future": secret, "microseconds": 2, "seconds": 1}
emit({"data": {"future": secret}, "event": "STOP", "future": secret, "timestamp": timestamp})
emit({"data": {"future": secret, "guest": True, "reason": "guest-reset"}, "event": "RESET", "future": secret, "timestamp": timestamp})
emit({"data": {"future": secret, "guest": False, "reason": "attacker-controlled-token"}, "event": "SHUTDOWN", "future": secret, "timestamp": timestamp})
emit({"data": {"action": "pause", "future": secret, "info": {"raw": secret}}, "event": "GUEST_PANICKED", "future": secret, "timestamp": timestamp})
emit({"data": {"raw": "never retained"}, "event": "UNRELATED", "timestamp": timestamp})
if select.select([sys.stdin.buffer], [], [], 0.15)[0]:
    raise SystemExit(93)
'
qmp_supervisor=$started_process
wait_for_file "$qmp_control/ready"
wait_for_qmp_status_after_outputs "$qmp_control"
for qmp_output in ready qmp stderr status; do
    assert_private_regular_file "$qmp_control/$qmp_output"
done
assert_json_equals "$qmp_control/ready" "$ready_json"
assert_json_equals "$qmp_control/qmp" \
    '{"events":[{"event":"STOP"},{"event":"RESET","guest":true,"reason":"guest-reset"},{"event":"SHUTDOWN","guest":false,"reason":"unavailable"},{"action":"pause","event":"GUEST_PANICKED"}],"protocol":"volparossa-qemu-pidfd-supervisor-v3","state":"final","truncated":false}'
test ! -s "$qmp_control/stderr"
if grep -aF 'PRIVATE KEY' "$qmp_control/qmp" >/dev/null; then
    printf '%s\n' 'raw QMP panic information reached the event record' >&2
    exit 1
fi
assert_json_equals "$qmp_control/status" \
    '{"exit_code":0,"exit_signal":null,"protocol":"volparossa-qemu-pidfd-supervisor-v3","state":"exited","termination":"none","trigger":"child-exit"}'
assert_no_atomic_temporary_files "$qmp_control"
if [ -s "$temporary_directory/qmp.stdout" ] \
    || [ -s "$temporary_directory/qmp.stderr" ]; then
    printf '%s\n' 'successful QMP lifecycle emitted supervisor output' >&2
    exit 1
fi
atomic_empty_file "$qmp_control/ack"
wait_for_supervisor "$qmp_supervisor" 0

# Closing QMP immediately before process exit is not mistaken for a live QMP
# disconnect, even under repeated scheduler races.
qmp_stress_iteration=1
while [ "$qmp_stress_iteration" -le 100 ]; do
    qmp_stress_control=$(new_control_directory "qmp-stress-$qmp_stress_iteration")
    start_qmp_supervisor "$qmp_stress_control" \
        "$temporary_directory/qmp-stress-$qmp_stress_iteration.stdout" \
        "$temporary_directory/qmp-stress-$qmp_stress_iteration.stderr" \
        python3 -c '
import json
import os
import sys
import time


def emit(value):
    sys.stdout.buffer.write(json.dumps(value, separators=(",", ":")).encode("ascii") + b"\r\n")
    sys.stdout.buffer.flush()


emit({"QMP": {"capabilities": [], "version": {"package": "stress", "qemu": {"major": 8, "micro": 8, "minor": 2}}}})
if not sys.stdin.buffer.readline():
    raise SystemExit(71)
emit({"id": "volparossa-capabilities", "return": {}})
if not sys.stdin.buffer.readline():
    raise SystemExit(72)
emit({"id": "volparossa-cont", "return": {}})
ready = os.path.join(sys.argv[1], "ready")
for _ in range(500):
    if os.path.isfile(ready) and not os.path.islink(ready):
        raise SystemExit(0)
    time.sleep(0.001)
raise SystemExit(73)
' "$qmp_stress_control"
    qmp_stress_supervisor=$started_process
    wait_for_qmp_status_after_outputs "$qmp_stress_control"
    assert_json_equals "$qmp_stress_control/qmp" \
        '{"events":[],"protocol":"volparossa-qemu-pidfd-supervisor-v3","state":"final","truncated":false}'
    assert_json_equals "$qmp_stress_control/status" \
        '{"exit_code":0,"exit_signal":null,"protocol":"volparossa-qemu-pidfd-supervisor-v3","state":"exited","termination":"none","trigger":"child-exit"}'
    atomic_empty_file "$qmp_stress_control/ack"
    wait_for_supervisor "$qmp_stress_supervisor" 0
    qmp_stress_iteration=$((qmp_stress_iteration + 1))
done

# Malformed, out-of-order and overflowing fake QMP peers fail closed. Raw QMP
# bytes are never published, and event overflow cannot yield partial evidence.
for qmp_failure_mode in \
    unsolicited-null duplicate-key nonfinite deep-json lf-only early-event \
    child-before-greeting oversized overflow total-stream eof-live
do
    qmp_failure_control=$(new_control_directory "qmp-$qmp_failure_mode")
    start_qmp_supervisor "$qmp_failure_control" \
        "$temporary_directory/qmp-$qmp_failure_mode.stdout" \
        "$temporary_directory/qmp-$qmp_failure_mode.stderr" \
        python3 -c '
import json
import os
import sys
import time

mode = sys.argv[1]


def raw(value):
    sys.stdout.buffer.write(value)
    sys.stdout.buffer.flush()


def emit(value):
    raw(json.dumps(value, ensure_ascii=True, separators=(",", ":")).encode("ascii") + b"\r\n")


greeting = {"QMP": {"capabilities": [], "version": {"package": "fake", "qemu": {"major": 8, "micro": 8, "minor": 2}}}}
timestamp = {"microseconds": 0, "seconds": 1}
if mode == "unsolicited-null":
    emit({"id": None, "return": {}})
elif mode == "duplicate-key":
    raw(b"{\"QMP\":{},\"QMP\":{}}\r\n")
elif mode == "nonfinite":
    raw(b"{\"QMP\":{\"capabilities\":[],\"version\":{\"package\":\"fake\",\"qemu\":{\"major\":NaN,\"micro\":8,\"minor\":2}}}}\r\n")
elif mode == "deep-json":
    raw(b"[" * 2000 + b"0" + b"]" * 2000 + b"\r\n")
elif mode == "lf-only":
    raw(json.dumps(greeting, separators=(",", ":")).encode("ascii") + b"\n")
elif mode == "early-event":
    emit({"data": {"guest": True, "reason": "guest-reset"}, "event": "RESET", "timestamp": timestamp})
elif mode == "child-before-greeting":
    raise SystemExit(0)
elif mode == "oversized":
    raw(b"X" * 65537)
elif mode in ("overflow", "total-stream", "eof-live"):
    emit(greeting)
    if not sys.stdin.buffer.readline():
        raise SystemExit(81)
    emit({"id": "volparossa-capabilities", "return": {}})
    if not sys.stdin.buffer.readline():
        raise SystemExit(82)
    emit({"id": "volparossa-cont", "return": {}})
    if mode == "overflow":
        for _ in range(65):
            emit({"event": "STOP", "timestamp": timestamp})
    elif mode == "total-stream":
        try:
            for _ in range(9000):
                emit({"data": {"ignored": "X" * 960}, "event": "UNRELATED", "timestamp": timestamp})
        except BrokenPipeError:
            pass
    else:
        os.close(1)
else:
    raise SystemExit(83)
time.sleep(30)
' "$qmp_failure_mode"
    qmp_failure_supervisor=$started_process
    wait_for_qmp_status_after_outputs "$qmp_failure_control"
    assert_private_regular_file "$qmp_failure_control/qmp"
    assert_private_regular_file "$qmp_failure_control/stderr"
    assert_private_regular_file "$qmp_failure_control/status"
    python3 - "$qmp_failure_control/qmp" "$qmp_failure_mode" <<'PY'
import json
import pathlib
import sys

path = pathlib.Path(sys.argv[1])
mode = sys.argv[2]
raw = path.read_bytes()
record = json.loads(raw)
canonical = (json.dumps(record, ensure_ascii=True, separators=(",", ":"), sort_keys=True) + "\n").encode("ascii")
if raw != canonical or record.get("protocol") != "volparossa-qemu-pidfd-supervisor-v3" or record.get("state") != "failed":
    raise SystemExit(f"invalid failed QMP record for {mode}")
if mode == "overflow":
    if record.get("truncated") is not True or len(record.get("events", [])) != 64:
        raise SystemExit("QMP event overflow was not explicit and fail-closed")
elif record != {
    "events": [],
    "protocol": "volparossa-qemu-pidfd-supervisor-v3",
    "state": "failed",
    "truncated": False,
}:
    raise SystemExit(f"unexpected pre-handshake QMP evidence for {mode}")
PY
    assert_json_equals "$qmp_failure_control/status" \
        '{"error":"supervisor-failure","protocol":"volparossa-qemu-pidfd-supervisor-v3","state":"failed"}'
    atomic_empty_file "$qmp_failure_control/ack"
    wait_for_supervisor "$qmp_failure_supervisor" 69
done

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
wait_for_status_after_stderr "$normal_control"
assert_private_regular_file "$normal_control/ready"
assert_private_regular_file "$normal_control/stderr"
assert_private_regular_file "$normal_control/status"
test ! -s "$normal_control/stderr"
assert_json_equals "$normal_control/ready" "$ready_json"
assert_json_equals "$normal_control/status" \
    '{"exit_code":7,"exit_signal":null,"protocol":"volparossa-qemu-pidfd-supervisor-v3","state":"exited","termination":"none","trigger":"child-exit"}'
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
    '{"exit_code":7,"exit_signal":null,"protocol":"volparossa-qemu-pidfd-supervisor-v3","state":"exited","termination":"none","trigger":"child-exit"}'

# A noisy child cannot block the supervisor. Its true rolling stderr tail is
# finalized and published before status without imposing a file limit on it.
tail_control=$(new_control_directory tail)
start_supervisor "$tail_control" \
    "$temporary_directory/tail.stdout" "$temporary_directory/tail.stderr" \
    python3 -c \
    'import sys; sys.stderr.buffer.write(b"A" * 524288 + b"B" * 1048576); sys.stderr.buffer.flush(); sys.exit(23)'
tail_supervisor=$started_process
wait_for_status_after_stderr "$tail_control"
assert_private_regular_file "$tail_control/stderr"
assert_private_regular_file "$tail_control/status"
test "$(stat -c '%s' "$tail_control/stderr")" -eq 917504
python3 - "$tail_control/stderr" <<'PY'
import pathlib
import sys

captured = pathlib.Path(sys.argv[1]).read_bytes()
if captured != b"B" * 917_504:
    raise SystemExit("supervisor did not retain the exact bounded stderr tail")
PY
assert_json_equals "$tail_control/status" \
    '{"exit_code":23,"exit_signal":null,"protocol":"volparossa-qemu-pidfd-supervisor-v3","state":"exited","termination":"none","trigger":"child-exit"}'
atomic_empty_file "$tail_control/ack"
wait_for_supervisor "$tail_supervisor" 0

# A private-key marker is detected across the entire stream even when the
# rolling tail would discard it, and no part of that stream is published.
redacted_control=$(new_control_directory redacted)
start_supervisor "$redacted_control" \
    "$temporary_directory/redacted.stdout" "$temporary_directory/redacted.stderr" \
    python3 -c '
import os
import sys
import time

for part in (b"-----BE", b"GIN OPENSSH PRIVATE", b" KEY-----\n"):
    os.write(2, part)
    time.sleep(0.05)
sys.stderr.buffer.write(b"Z" * 1048576)
sys.stderr.buffer.flush()
sys.exit(24)
'
redacted_supervisor=$started_process
wait_for_status_after_stderr "$redacted_control"
assert_private_regular_file "$redacted_control/stderr"
test "$(cat "$redacted_control/stderr")" = \
    '[stderr suppressed: private-key marker detected]'
assert_json_equals "$redacted_control/status" \
    '{"exit_code":24,"exit_signal":null,"protocol":"volparossa-qemu-pidfd-supervisor-v3","state":"exited","termination":"none","trigger":"child-exit"}'
atomic_empty_file "$redacted_control/ack"
wait_for_supervisor "$redacted_supervisor" 0

# An inherited writer cannot make final stderr draining unbounded after the
# identity-bound child exits. The lifecycle fails closed instead.
inherited_writer_control=$(new_control_directory inherited-writer)
start_supervisor "$inherited_writer_control" \
    "$temporary_directory/inherited-writer.stdout" \
    "$temporary_directory/inherited-writer.stderr" \
    python3 -c '
import os

if os.fork() != 0:
    os._exit(25)
while True:
    try:
        os.write(2, b"W" * 65536)
    except BrokenPipeError:
        os._exit(0)
'
inherited_writer_supervisor=$started_process
wait_for_status_after_stderr "$inherited_writer_control"
assert_private_regular_file "$inherited_writer_control/stderr"
assert_json_equals "$inherited_writer_control/status" \
    '{"error":"supervisor-failure","protocol":"volparossa-qemu-pidfd-supervisor-v3","state":"failed"}'
atomic_empty_file "$inherited_writer_control/ack"
wait_for_supervisor "$inherited_writer_supervisor" 69

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
assert_private_regular_file "$term_control/stderr"
test ! -s "$term_control/stderr"
assert_json_equals "$term_control/status" \
    '{"exit_code":null,"exit_signal":15,"protocol":"volparossa-qemu-pidfd-supervisor-v3","state":"exited","termination":"term","trigger":"stop-requested"}'
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
assert_private_regular_file "$kill_control/stderr"
test ! -s "$kill_control/stderr"
assert_json_equals "$kill_control/status" \
    '{"exit_code":null,"exit_signal":9,"protocol":"volparossa-qemu-pidfd-supervisor-v3","state":"exited","termination":"kill","trigger":"stop-requested"}'
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
assert_private_regular_file "$parent_control/stderr"
test ! -s "$parent_control/stderr"
assert_json_equals "$parent_control/status" \
    '{"exit_code":null,"exit_signal":9,"protocol":"volparossa-qemu-pidfd-supervisor-v3","state":"exited","termination":"kill","trigger":"parent-death"}'
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

stale_stderr_control=$(new_control_directory stale-stderr)
atomic_empty_file "$stale_stderr_control/stderr"
stale_stderr_marker=$temporary_directory/stale-stderr-command-ran
set +e
"$supervisor" "$stale_stderr_control" -- /usr/bin/touch "$stale_stderr_marker" \
    >"$temporary_directory/stale-stderr.stdout" \
    2>"$temporary_directory/stale-stderr.stderr"
stale_stderr_status=$?
set -e
if [ "$stale_stderr_status" -eq 0 ] || [ -e "$stale_stderr_marker" ] \
    || [ -e "$stale_stderr_control/ready" ]; then
    printf '%s\n' 'stale stderr protocol did not fail before COMMAND' >&2
    exit 1
fi

stale_qmp_control=$(new_control_directory stale-qmp)
atomic_empty_file "$stale_qmp_control/qmp"
stale_qmp_marker=$temporary_directory/stale-qmp-command-ran
set +e
"$supervisor" --qmp-stdio "$stale_qmp_control" -- /usr/bin/touch "$stale_qmp_marker" \
    >"$temporary_directory/stale-qmp.stdout" \
    2>"$temporary_directory/stale-qmp.stderr"
stale_qmp_status=$?
set -e
if [ "$stale_qmp_status" -eq 0 ] || [ -e "$stale_qmp_marker" ] \
    || [ -e "$stale_qmp_control/ready" ]; then
    printf '%s\n' 'stale QMP protocol did not fail before COMMAND' >&2
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
    "protocol": "volparossa-qemu-pidfd-supervisor-v3",
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
        qmp_stdio=False,
        qmp_timeout_seconds=1.0,
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
    if (control / "stderr").read_bytes() != b"":
        raise SystemExit("pre-ready failure stderr is not exact and empty")
    for name in ("stderr", "status", "ack"):
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
    'PASS: pidfd supervisor lifecycle, bounded stderr tail/redaction, pre-ready failure, isolation, atomic status, and acknowledgement are exact.'
