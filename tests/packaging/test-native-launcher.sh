#!/bin/sh
# SPDX-License-Identifier: GPL-3.0-only
# Exercise role selection and worker shutdown without installing software or opening the network.
set -eu
export LC_ALL=C
repository=$(CDPATH='' cd -- "$(dirname -- "$0")/../.." && pwd -P)
temporary=$(mktemp -d /tmp/volparossa-native-launch.XXXXXX)
case $temporary in /tmp/volparossa-native-launch.??????) ;; *) exit 69 ;; esac
launcher_pid=
cleanup() {
    status=$?
    trap - EXIT HUP INT TERM
    [ -z "$launcher_pid" ] || kill -TERM "$launcher_pid" 2>/dev/null || :
    [ -z "$launcher_pid" ] || wait "$launcher_pid" 2>/dev/null || :
    rm -rf --one-file-system -- "$temporary"
    exit "$status"
}
trap cleanup EXIT
trap 'exit 129' HUP
trap 'exit 130' INT
trap 'exit 143' TERM

# Substitute only the fixed native executable in an isolated copy. The shipped launcher does
# not accept an environment-variable executable override.
# shellcheck disable=SC2016
sed 's|^binary=/usr/libexec/volparossa/volparossa-mpquic$|binary=$TEST_NATIVE_BINARY|' \
    "$repository/packaging/volparossa-mpquic-launch" >"$temporary/launcher"
cat >"$temporary/native-fixture" <<'FIXTURE'
#!/bin/sh
set -eu
[ "$#" -eq 4 ] && [ "$1" = --mode ] && [ "$3" = --socket ]
mode=$2
socket=$4
printf '%s\n' "$socket" >"$TEST_DIRECTORY/socket-$mode"
trap 'printf "%s\n" stopped >"$TEST_DIRECTORY/stopped-$mode"' EXIT
trap 'exit 0' HUP INT TERM
printf '%s\n' "$$" >"$TEST_DIRECTORY/pid-$mode"
while [ ! -f "$TEST_DIRECTORY/stop-$mode" ]; do sleep 0.1; done
exit 7
FIXTURE
chmod 0755 "$temporary/native-fixture"
export TEST_NATIVE_BINARY="$temporary/native-fixture"
export VOLPAROSSA_CONFIG="$temporary/config.yaml"
export VOLPAROSSA_MPQUIC_SOCKET="$temporary/native.sock"

await_file() {
    attempt=0
    while [ ! -f "$1" ]; do
        attempt=$((attempt + 1))
        [ "$attempt" -lt 100 ] || { printf 'timed out waiting for %s\n' "$1" >&2; exit 1; }
        sleep 0.1
    done
}

for failed_role in client exit; do
    TEST_DIRECTORY=$temporary/combined-$failed_role
    export TEST_DIRECTORY
    mkdir "$TEST_DIRECTORY"
    printf 'roles:\n  client: true\n  relay: true\n  exit: true\n' >"$VOLPAROSSA_CONFIG"
    sh "$temporary/launcher" >"$TEST_DIRECTORY/output" 2>&1 &
    launcher_pid=$!
    await_file "$TEST_DIRECTORY/pid-client"
    await_file "$TEST_DIRECTORY/pid-exit"
    [ "$(cat "$TEST_DIRECTORY/socket-client")" = "$VOLPAROSSA_MPQUIC_SOCKET" ]
    [ "$(cat "$TEST_DIRECTORY/socket-exit")" = "$VOLPAROSSA_MPQUIC_SOCKET.exit" ]
    [ "$(cat "$TEST_DIRECTORY/pid-client")" != "$(cat "$TEST_DIRECTORY/pid-exit")" ]
    touch "$TEST_DIRECTORY/stop-$failed_role"
    await_file "$TEST_DIRECTORY/stopped-client"
    await_file "$TEST_DIRECTORY/stopped-exit"
    status=0
    wait "$launcher_pid" || status=$?
    launcher_pid=
    [ "$status" -eq 1 ]
done

TEST_DIRECTORY=$temporary/shutdown
export TEST_DIRECTORY
mkdir "$TEST_DIRECTORY"
sh "$temporary/launcher" >"$TEST_DIRECTORY/output" 2>&1 &
launcher_pid=$!
await_file "$TEST_DIRECTORY/pid-client"
await_file "$TEST_DIRECTORY/pid-exit"
kill -TERM "$launcher_pid"
await_file "$TEST_DIRECTORY/stopped-client"
await_file "$TEST_DIRECTORY/stopped-exit"
wait "$launcher_pid"
launcher_pid=

for only_role in client exit; do
    TEST_DIRECTORY=$temporary/only-$only_role
    export TEST_DIRECTORY
    mkdir "$TEST_DIRECTORY"
    client=false; exit_role=false
    if [ "$only_role" = client ]; then client=true; else exit_role=true; fi
    printf 'roles:\n  client: %s\n  relay: false\n  exit: %s\n' \
        "$client" "$exit_role" >"$VOLPAROSSA_CONFIG"
    sh "$temporary/launcher" >"$TEST_DIRECTORY/output" 2>&1 &
    launcher_pid=$!
    await_file "$TEST_DIRECTORY/pid-$only_role"
    [ "$(cat "$TEST_DIRECTORY/socket-$only_role")" = "$VOLPAROSSA_MPQUIC_SOCKET" ]
    kill -TERM "$launcher_pid"
    wait "$launcher_pid"
    launcher_pid=
done

TEST_DIRECTORY=$temporary/dormant
export TEST_DIRECTORY
mkdir "$TEST_DIRECTORY"
printf 'roles:\n  client: false\n  relay: false\n  exit: false\n' >"$VOLPAROSSA_CONFIG"
sh "$temporary/launcher" >"$TEST_DIRECTORY/output" 2>&1
[ ! -f "$TEST_DIRECTORY/pid-client" ] && [ ! -f "$TEST_DIRECTORY/pid-exit" ]
printf '%s\n' 'PASS: combined native roles use distinct workers and sockets; failures and shutdown stop both.'
