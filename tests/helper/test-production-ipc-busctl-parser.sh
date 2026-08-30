#!/bin/sh
# SPDX-License-Identifier: GPL-3.0-only
# Exercise the production hook's typed busctl parsers without contacting PID 1.
set -eu

export LC_ALL=C

repository_root=$(CDPATH='' cd -- "$(dirname -- "$0")/../.." && pwd)
hook=$repository_root/tests/helper/lib/production-ipc-unit-hook.sh

for command_name in awk cat chmod grep jq mktemp sed; do
    command -v "$command_name" >/dev/null 2>&1 || {
        printf 'required parser-fixture tool is unavailable: %s\n' \
            "$command_name" >&2
        exit 127
    }
done

temporary_directory=$(mktemp -d /tmp/volparossa-busctl-parser-test.XXXXXX)
case $temporary_directory in
    /tmp/volparossa-busctl-parser-test.??????) ;;
    *)
        printf 'unsafe parser-fixture directory: %s\n' \
            "$temporary_directory" >&2
        exit 1
        ;;
esac
cleanup() {
    /bin/rm -r -- "$temporary_directory"
}
trap cleanup EXIT
trap 'exit 130' HUP INT TERM

parser_functions=$temporary_directory/parser-functions.sh
for function_name in \
    number_is_safe \
    main_pid_property_is_safe \
    unit_name_is_safe \
    invocation_id_is_safe \
    unit_object_path \
    unit_invocation_id \
    unit_u32_property \
    unit_main_pid
do
    sed -n "/^$function_name() {\$/,/^}\$/p" "$hook" \
        >>"$parser_functions"
done

[ "$(grep -c '^[_a-z][a-z0-9_]*() {$' "$parser_functions")" -eq 8 ] || {
    printf '%s\n' 'the production bus parser functions cannot be isolated exactly' >&2
    exit 1
}
[ "$(grep -Fc '/usr/bin/busctl' "$parser_functions")" -eq 3 ] || {
    printf '%s\n' 'the production bus parser does not contain three fixed busctl calls' >&2
    exit 1
}

fake_busctl=$temporary_directory/busctl
object_fixture=$temporary_directory/object.json
property_fixture=$temporary_directory/property.json
call_log=$temporary_directory/calls

# The variable is deliberately retained for expansion by the sourced parser.
# shellcheck disable=SC2016
sed 's|/usr/bin/busctl|"$fake_busctl"|g' "$parser_functions" \
    >"$temporary_directory/parser-functions-under-test.sh"
sh -n "$temporary_directory/parser-functions-under-test.sh"

# The fake accepts only the exact busctl argv emitted by the production parser.
# It never contacts a bus and writes only below this test's private directory.
cat >"$fake_busctl" <<'EOF'
#!/bin/sh
set -eu

[ "$1" = '--address=unix:path=/run/dbus/system_bus_socket' ] || exit 91
[ "$2" = '--json=short' ] || exit 92

case ${3:-} in
    call)
        [ "$#" -eq 9 ] || exit 93
        [ "$4" = org.freedesktop.systemd1 ] || exit 94
        [ "$5" = /org/freedesktop/systemd1 ] || exit 95
        [ "$6" = org.freedesktop.systemd1.Manager ] || exit 96
        [ "$7" = GetUnit ] || exit 97
        [ "$8" = s ] || exit 98
        [ "$9" = "$VOLPAROSSA_BUSCTL_FIXTURE_UNIT" ] || exit 99
        printf '%s\n' object >>"$VOLPAROSSA_BUSCTL_FIXTURE_CALL_LOG"
        [ "$VOLPAROSSA_BUSCTL_FIXTURE_OBJECT_STATUS" -eq 0 ] \
            || exit "$VOLPAROSSA_BUSCTL_FIXTURE_OBJECT_STATUS"
        cat "$VOLPAROSSA_BUSCTL_FIXTURE_OBJECT"
        ;;
    get-property)
        [ "$#" -eq 7 ] || exit 100
        [ "$4" = org.freedesktop.systemd1 ] || exit 101
        [ "$5" = "$VOLPAROSSA_BUSCTL_FIXTURE_OBJECT_PATH" ] || exit 102
        case "$6:$7" in
            org.freedesktop.systemd1.Unit:InvocationID|\
            org.freedesktop.systemd1.Service:ControlPID|\
            org.freedesktop.systemd1.Service:MainPID|\
            org.freedesktop.systemd1.Service:NFileDescriptorStore)
                ;;
            *) exit 103 ;;
        esac
        printf '%s\n' property >>"$VOLPAROSSA_BUSCTL_FIXTURE_CALL_LOG"
        [ "$VOLPAROSSA_BUSCTL_FIXTURE_PROPERTY_STATUS" -eq 0 ] \
            || exit "$VOLPAROSSA_BUSCTL_FIXTURE_PROPERTY_STATUS"
        cat "$VOLPAROSSA_BUSCTL_FIXTURE_PROPERTY"
        ;;
    *) exit 104 ;;
esac
EOF
chmod 0700 "$fake_busctl"

VOLPAROSSA_BUSCTL_FIXTURE_UNIT=volparossa-helper-live-proof-Ab12Z9.service
VOLPAROSSA_BUSCTL_FIXTURE_OBJECT_PATH=/org/freedesktop/systemd1/unit/volparossa_2dhelper_2dlive_2dproof_2dAb12Z9_2eservice
VOLPAROSSA_BUSCTL_FIXTURE_OBJECT=$object_fixture
VOLPAROSSA_BUSCTL_FIXTURE_PROPERTY=$property_fixture
VOLPAROSSA_BUSCTL_FIXTURE_CALL_LOG=$call_log
VOLPAROSSA_BUSCTL_FIXTURE_OBJECT_STATUS=0
VOLPAROSSA_BUSCTL_FIXTURE_PROPERTY_STATUS=0
export \
    VOLPAROSSA_BUSCTL_FIXTURE_UNIT \
    VOLPAROSSA_BUSCTL_FIXTURE_OBJECT_PATH \
    VOLPAROSSA_BUSCTL_FIXTURE_OBJECT \
    VOLPAROSSA_BUSCTL_FIXTURE_PROPERTY \
    VOLPAROSSA_BUSCTL_FIXTURE_CALL_LOG \
    VOLPAROSSA_BUSCTL_FIXTURE_OBJECT_STATUS \
    VOLPAROSSA_BUSCTL_FIXTURE_PROPERTY_STATUS

# Symbols consumed only by the dynamically sourced production functions.
# shellcheck disable=SC2034
system_bus_address=unix:path=/run/dbus/system_bus_socket
# shellcheck disable=SC1091
. "$temporary_directory/parser-functions-under-test.sh"

set_object_fixture() {
    [ "$#" -eq 1 ] || return 1
    printf '%s\n' "$1" >"$object_fixture"
}

set_property_fixture() {
    [ "$#" -eq 1 ] || return 1
    printf '%s\n' "$1" >"$property_fixture"
}

expect_success() {
    [ "$#" -ge 3 ] || return 1
    expected_output=$1
    fixture_description=$2
    shift 2
    observed_output=$("$@") || {
        printf 'valid bus fixture was rejected: %s\n' "$fixture_description" >&2
        exit 1
    }
    [ "$observed_output" = "$expected_output" ] || {
        printf 'bus fixture produced unexpected output: %s\n' \
            "$fixture_description" >&2
        exit 1
    }
}

expect_failure() {
    [ "$#" -ge 2 ] || return 1
    fixture_description=$1
    shift
    if "$@" >"$temporary_directory/rejected.stdout" \
        2>"$temporary_directory/rejected.stderr"; then
        printf 'adversarial bus fixture was accepted: %s\n' \
            "$fixture_description" >&2
        exit 1
    fi
}

valid_object=$(printf '{"type":"o","data":["%s"]}' \
    "$VOLPAROSSA_BUSCTL_FIXTURE_OBJECT_PATH")
set_object_fixture "$valid_object"
expect_success "$VOLPAROSSA_BUSCTL_FIXTURE_OBJECT_PATH" \
    'exact GetUnit object path' \
    unit_object_path "$VOLPAROSSA_BUSCTL_FIXTURE_UNIT"

# Object response shape and exact escaped unit lineage.
for adversarial_object in \
    '{"type":"o","data":["/org/freedesktop/systemd1/unit/wrong_2eservice"]}' \
    '{"type":"o","data":["/org/freedesktop/systemd1/unit/volparossa_2dhelper_2dlive_2dproof_2dAb12Z9_2eservice"],"extra":0}' \
    '{"type":"o"}' \
    '{"type":"s","data":["/org/freedesktop/systemd1/unit/volparossa_2dhelper_2dlive_2dproof_2dAb12Z9_2eservice"]}' \
    '{"type":"o","data":"/org/freedesktop/systemd1/unit/volparossa_2dhelper_2dlive_2dproof_2dAb12Z9_2eservice"}' \
    '{"type":"o","data":[]}' \
    '{"type":"o","data":["/org/freedesktop/systemd1/unit/volparossa_2dhelper_2dlive_2dproof_2dAb12Z9_2eservice","/second"]}'
do
    set_object_fixture "$adversarial_object"
    expect_failure 'invalid GetUnit response' \
        unit_object_path "$VOLPAROSSA_BUSCTL_FIXTURE_UNIT"
done
printf '%s\n%s\n' "$valid_object" '{}' >"$object_fixture"
expect_failure 'valid GetUnit response followed by a second JSON document' \
    unit_object_path "$VOLPAROSSA_BUSCTL_FIXTURE_UNIT"
printf '%s\n%s\n' '{}' "$valid_object" >"$object_fixture"
expect_failure 'valid GetUnit response preceded by a second JSON document' \
    unit_object_path "$VOLPAROSSA_BUSCTL_FIXTURE_UNIT"
set_object_fixture "$valid_object"
expect_failure 'unsafe unit name' unit_object_path wrong.service

VOLPAROSSA_BUSCTL_FIXTURE_OBJECT_STATUS=17
expect_failure 'nonzero GetUnit busctl status' \
    unit_object_path "$VOLPAROSSA_BUSCTL_FIXTURE_UNIT"
VOLPAROSSA_BUSCTL_FIXTURE_OBJECT_STATUS=0

valid_invocation=0102030405060708090a0b0c0d0e0f10
set_property_fixture \
    '{"type":"ay","data":[1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16]}'
expect_success "$valid_invocation" 'sixteen InvocationID octets' \
    unit_invocation_id "$VOLPAROSSA_BUSCTL_FIXTURE_UNIT"

for adversarial_invocation in \
    '{"type":"ay","data":[1,2,3,4,5,6,7,8,9,10,11,12,13,14,15]}' \
    '{"type":"ay","data":[1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16,17]}' \
    '{"type":"as","data":[1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16]}' \
    '{"type":"ay","data":[1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,"16"]}' \
    '{"type":"ay","data":[1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16.5]}' \
    '{"type":"ay","data":[1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,-1]}' \
    '{"type":"ay","data":[1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,256]}' \
    '{"type":"ay","data":[0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0]}' \
    '{"type":"ay","data":[1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16],"extra":0}' \
    '{"data":[1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16]}'
do
    set_property_fixture "$adversarial_invocation"
    expect_failure 'invalid InvocationID response' \
        unit_invocation_id "$VOLPAROSSA_BUSCTL_FIXTURE_UNIT"
done
printf '%s\n%s\n' \
    '{"type":"ay","data":[1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16]}' \
    '{}' >"$property_fixture"
expect_failure 'valid InvocationID followed by a second JSON document' \
    unit_invocation_id "$VOLPAROSSA_BUSCTL_FIXTURE_UNIT"
printf '%s\n%s\n' \
    '{}' \
    '{"type":"ay","data":[1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16]}' \
    >"$property_fixture"
expect_failure 'valid InvocationID preceded by a second JSON document' \
    unit_invocation_id "$VOLPAROSSA_BUSCTL_FIXTURE_UNIT"

VOLPAROSSA_BUSCTL_FIXTURE_PROPERTY_STATUS=23
expect_failure 'nonzero InvocationID busctl status' \
    unit_invocation_id "$VOLPAROSSA_BUSCTL_FIXTURE_UNIT"
VOLPAROSSA_BUSCTL_FIXTURE_PROPERTY_STATUS=0

for valid_u32 in 0 1 9 10 4294967295; do
    set_property_fixture "{\"type\":\"u\",\"data\":$valid_u32}"
    expect_success "$valid_u32" "valid u32 $valid_u32" \
        unit_u32_property "$VOLPAROSSA_BUSCTL_FIXTURE_UNIT" \
        org.freedesktop.systemd1.Service NFileDescriptorStore
done

for adversarial_u32 in \
    '{"type":"u","data":-1}' \
    '{"type":"u","data":1.5}' \
    '{"type":"u","data":4294967296}' \
    '{"type":"t","data":1}' \
    '{"type":"u","data":"1"}' \
    '{"type":"u","data":[1]}' \
    '{"type":"u","data":1,"extra":0}' \
    '{"data":1}'
do
    set_property_fixture "$adversarial_u32"
    expect_failure 'invalid u32 property response' \
        unit_u32_property "$VOLPAROSSA_BUSCTL_FIXTURE_UNIT" \
        org.freedesktop.systemd1.Service NFileDescriptorStore
done
printf '%s\n%s\n' '{"type":"u","data":1}' '{}' >"$property_fixture"
expect_failure 'valid u32 followed by a second JSON document' \
    unit_u32_property "$VOLPAROSSA_BUSCTL_FIXTURE_UNIT" \
    org.freedesktop.systemd1.Service NFileDescriptorStore
printf '%s\n%s\n' '{}' '{"type":"u","data":1}' >"$property_fixture"
expect_failure 'valid u32 preceded by a second JSON document' \
    unit_u32_property "$VOLPAROSSA_BUSCTL_FIXTURE_UNIT" \
    org.freedesktop.systemd1.Service NFileDescriptorStore

set_property_fixture '{"type":"u","data":0}'
expect_success 0 'manager-unbound zero MainPID' \
    unit_main_pid "$VOLPAROSSA_BUSCTL_FIXTURE_UNIT"
expect_success 0 'manager-unbound zero ControlPID' \
    unit_u32_property "$VOLPAROSSA_BUSCTL_FIXTURE_UNIT" \
        org.freedesktop.systemd1.Service ControlPID
set_property_fixture '{"type":"u","data":1}'
expect_success 1 'one MainPID' unit_main_pid "$VOLPAROSSA_BUSCTL_FIXTURE_UNIT"
expect_success 1 'one ControlPID' \
    unit_u32_property "$VOLPAROSSA_BUSCTL_FIXTURE_UNIT" \
        org.freedesktop.systemd1.Service ControlPID
set_property_fixture '{"type":"u","data":4294967294}'
expect_success 4294967294 'maximum safe MainPID' \
    unit_main_pid "$VOLPAROSSA_BUSCTL_FIXTURE_UNIT"
set_property_fixture '{"type":"u","data":4294967295}'
expect_failure 'reserved maximum u32 MainPID' \
    unit_main_pid "$VOLPAROSSA_BUSCTL_FIXTURE_UNIT"

set_property_fixture '{"type":"u","data":0}'
expect_success 0 'zero ControlPID' \
    unit_u32_property "$VOLPAROSSA_BUSCTL_FIXTURE_UNIT" \
    org.freedesktop.systemd1.Service ControlPID

set_property_fixture '{"type":"u","data":1}'
expect_failure 'wrong property interface' \
    unit_u32_property "$VOLPAROSSA_BUSCTL_FIXTURE_UNIT" \
    org.freedesktop.systemd1.Unit MainPID
expect_failure 'non-allowlisted property' \
    unit_u32_property "$VOLPAROSSA_BUSCTL_FIXTURE_UNIT" \
    org.freedesktop.systemd1.Service TasksCurrent

VOLPAROSSA_BUSCTL_FIXTURE_PROPERTY_STATUS=29
expect_failure 'nonzero u32 busctl status' \
    unit_u32_property "$VOLPAROSSA_BUSCTL_FIXTURE_UNIT" \
    org.freedesktop.systemd1.Service NFileDescriptorStore

printf '%s\n' 'production IPC typed bus parser fixtures: pass'
