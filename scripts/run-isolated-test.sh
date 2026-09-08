#!/bin/sh
# Run one exact test without ever opening its sockets in the caller's network namespace.
# Kernel PID-namespace teardown reaps descendants; no named namespace or host state is created.
set -eu

fail() {
    printf 'isolated-test: %s\n' "$1" >&2
    exit 1
}

[ "$#" -eq 4 ] || fail 'expected TEST_EXECUTABLE TEST_NAME PARENT_NETNS_MARKER none|loopback'
test_executable=$1
test_name=$2
test_marker=$3
test_network=$4
case "$test_executable" in /*) ;; *) fail 'test executable must be absolute' ;; esac
if [ ! -f "$test_executable" ] || [ ! -x "$test_executable" ]; then fail 'test executable is unavailable'; fi
case "$test_name" in ''|*[!a-zA-Z0-9_:]*) fail 'invalid exact test name' ;; esac
case "$test_marker" in
    VOLPAROSSA_HANDOFF_TEST_PARENT_NETNS|VOLPAROSSA_DNS_COLLECTOR_PARENT_NETNS|VOLPAROSSA_DNS_CACHE_PARENT_NETNS) ;;
    *) fail 'unsupported namespace marker' ;;
esac
case "$test_network" in none|loopback) ;; *) fail 'unsupported disposable network setup' ;; esac
for test_tool in /usr/bin/unshare /usr/bin/setpriv /usr/bin/readlink /usr/bin/id /usr/bin/env /usr/bin/timeout /bin/sh; do
    [ -x "$test_tool" ] || fail "required tool is unavailable: $test_tool"
done
if [ "$test_network" = loopback ]; then
    if [ ! -x /usr/bin/ip ] && [ ! -x /usr/sbin/ip ]; then fail 'iproute2 is required for disposable loopback setup'; fi
fi
test_parent=$(/usr/bin/readlink /proc/self/ns/net)
test_uid=$(/usr/bin/id -u)
test_gid=$(/usr/bin/id -g)

# Literal script is interpreted only after setpriv removed privileges.
# shellcheck disable=SC2016
test_verify='
set -efu
target_uid=$1
target_gid=$2
parent_net=$3
marker=$4
executable=$5
exact_test=$6
expected_groups=$7
[ "$(/usr/bin/readlink /proc/self/ns/net)" != "$parent_net" ] || exit 121
ids=0
groups=0
caps=0
nnp=0
while IFS= read -r status_line; do
    case "$status_line" in
        Uid:*) set -- $status_line
            [ "$2" = "$target_uid" ] && [ "$3" = "$target_uid" ] && [ "$4" = "$target_uid" ] && [ "$5" = "$target_uid" ] || exit 122
            ids=$((ids + 1)) ;;
        Gid:*) set -- $status_line
            [ "$2" = "$target_gid" ] && [ "$3" = "$target_gid" ] && [ "$4" = "$target_gid" ] && [ "$5" = "$target_gid" ] || exit 123
            ids=$((ids + 1)) ;;
        Groups:*) set -- $status_line; shift; [ "$*" = "$expected_groups" ] || exit 124; groups=1 ;;
        CapInh:*|CapPrm:*|CapEff:*|CapBnd:*|CapAmb:*) set -- $status_line
            [ "$2" = 0000000000000000 ] || exit 125; caps=$((caps + 1)) ;;
        NoNewPrivs:*) set -- $status_line; nnp=$2 ;;
    esac
done < /proc/self/status
[ "$ids" = 2 ] && [ "$groups" = 1 ] && [ "$caps" = 5 ] && [ "$nnp" = 1 ] || exit 126
exec /usr/bin/env "$marker=$parent_net" "$executable" --exact "$exact_test" --nocapture
'

# Only this fixed trampoline runs before privilege removal in the opt-in sudo path.
# The following verification script and test executable run only after setpriv.
# shellcheck disable=SC2016
test_trampoline='
set -eu
target_uid=$1
target_gid=$2
parent_net=$3
marker=$4
network=$5
executable=$6
exact_test=$7
verify=$8
group_mode=$9
[ "$(/usr/bin/readlink /proc/self/ns/net)" != "$parent_net" ] || exit 120
if [ "$network" = loopback ]; then
    if [ -x /usr/bin/ip ]; then /usr/bin/ip link set dev lo up
    else /usr/sbin/ip link set dev lo up; fi
fi
expected_groups=
case "$group_mode" in
    keep)
        # Unprivileged gid_map requires setgroups=deny. Preserve only the exact
        # existing mapped groups; clearing them is forbidden by that kernel gate.
        group_option=--keep-groups
        while IFS= read -r status_line; do
            case "$status_line" in Groups:*) set -- $status_line; shift; expected_groups="$*" ;; esac
        done < /proc/self/status ;;
    clear) group_option=--clear-groups ;;
    *) exit 127 ;;
esac
exec /usr/bin/setpriv --reuid="$target_uid" --regid="$target_gid" "$group_option" \
    --inh-caps=-all --ambient-caps=-all --bounding-set=-all --no-new-privs -- \
    /bin/sh -c "$verify" isolated-test-dropped "$target_uid" "$target_gid" "$parent_net" \
    "$marker" "$executable" "$exact_test" "$expected_groups"
'

printf 'isolated-test: new disposable user/network/PID namespaces; loopback=%s; preserve kernel-restricted mapped groups, clear capabilities; exact test %s\n' \
    "$test_network" "$test_name"
# Probe only namespace creation, never the actual test: a test failure cannot cause a rerun.
if /usr/bin/timeout --kill-after=1s 5s /usr/bin/unshare --user --map-root-user --net --pid --fork --kill-child=KILL -- /usr/bin/true; then
    exec /usr/bin/timeout --kill-after=5s 120s /usr/bin/unshare --user --map-root-user --net --pid --fork --kill-child=KILL -- \
        /bin/sh -c "$test_trampoline" isolated-test 0 0 "$test_parent" "$test_marker" \
        "$test_network" "$test_executable" "$test_name" "$test_verify" keep
fi

[ "${VOLPAROSSA_TEST_ALLOW_SUDO_NETNS:-0}" = 1 ] ||
    fail 'unprivileged namespace creation denied; privileged fallback is not explicitly enabled'
[ "$test_uid" -ne 0 ] || fail 'privileged fallback requires an original non-root test user'
[ -x /usr/bin/sudo ] || fail 'explicit privileged fallback requires sudo'
printf 'isolated-test: explicit sudo fallback creates only disposable network/PID namespaces; loopback=%s; drop to UID=%s GID=%s before test\n' \
    "$test_network" "$test_uid" "$test_gid"
exec /usr/bin/timeout --kill-after=5s 120s /usr/bin/sudo -n -- /usr/bin/unshare --net --pid --fork --kill-child=KILL -- \
    /bin/sh -c "$test_trampoline" isolated-test "$test_uid" "$test_gid" "$test_parent" \
    "$test_marker" "$test_network" "$test_executable" "$test_name" "$test_verify" clear
