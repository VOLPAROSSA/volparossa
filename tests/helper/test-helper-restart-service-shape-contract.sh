#!/bin/sh
# shellcheck disable=SC1003,SC2016
# SPDX-License-Identifier: GPL-3.0-only
# Cross-layer contract for the production-exact MayOwn restart service shape.
set -eu
export LC_ALL=C
PATH=/usr/sbin:/usr/bin:/sbin:/bin
export PATH
umask 077

here=$(CDPATH='' cd -- "$(dirname -- "$0")" && pwd)
repository=$(CDPATH='' cd -- "$here/../.." && pwd)
gate=$here/require-live-worker-identity-proof.sh
hook=$here/lib/production-ipc-unit-hook.sh
fdstore=$repository/crates/volparossa-helper/src/systemd_fdstore.rs
custody=$repository/crates/volparossa-helper/src/systemd_custody.rs
tmp=$(mktemp -d /tmp/volparossa-restart-shape-contract.XXXXXX)
case $tmp in /tmp/volparossa-restart-shape-contract.??????) ;; *) exit 1 ;; esac
trap 'rm -rf --one-file-system -- "$tmp"' EXIT
trap 'exit 129' HUP
trap 'exit 130' INT
trap 'exit 143' TERM

for input in "$gate" "$hook" "$fdstore" "$custody"; do
    [ -f "$input" ] && [ ! -L "$input" ] || exit 1
done
sh -n "$gate"
sh -n "$hook"

may_own_launch=$tmp/may-own-launch
sed -n '/^    driver_phase=may-own-launch$/,/^    may_own_run_status=\$?$/p' \
    "$gate" >"$may_own_launch"

launch_contract_is_exact() {
    [ "$#" -eq 1 ] || return 1
    [ "$(grep -Fc -- '--service-type=simple \' "$1")" -eq 1 ] \
        && [ "$(grep -Fc -- '--property=RestartSec=3s \' "$1")" -eq 1 ] \
        && [ "$(grep -Fc -- '--property=Restart=on-failure \' "$1")" -eq 1 ] \
        && [ "$(grep -Fc -- "--property='RestartPreventExitStatus=70 71' \\" "$1")" -eq 1 ] \
        && [ "$(grep -Fc -- '--service-type=exec' "$1")" -eq 0 ] \
        && [ "$(grep -Fc -- 'RestartSec=10s' "$1")" -eq 0 ] \
        && [ "$(grep -Fc -- 'ExecStartPost=' "$1")" -eq 0 ]
}

launch_contract_is_exact "$may_own_launch" || exit 1
for mutation in type restart post; do
    mutated=$tmp/launch-$mutation
    case $mutation in
        type) sed 's/--service-type=simple/--service-type=exec/' \
            "$may_own_launch" >"$mutated" ;;
        restart) sed 's/--property=RestartSec=3s/--property=RestartSec=10s/' \
            "$may_own_launch" >"$mutated" ;;
        post) cp "$may_own_launch" "$mutated" \
            && printf '%s\n' '--property=ExecStartPost=/bin/false' >>"$mutated" ;;
    esac
    if launch_contract_is_exact "$mutated"; then
        printf 'service-shape contract accepted %s mutation\n' "$mutation" >&2
        exit 1
    fi
done

# The driver re-observes PID 1's shape while each external observer is alive.
# It accepts documented repeated reads of the same MainPID in cgroup.procs,
# never another process, and requires an empty ExecStartPost command list.
shape_contract=$tmp/shape-function
sed -n '/^may_own_service_shape_is_exact() {$/,/^}$/p' \
    "$gate" >"$shape_contract"
if ! awk '
    /--property=Type --value/ { type = NR; type_count++ }
    /--property=RestartUSec --value/ { restart = NR; restart_count++ }
    /--property=ControlPID --value/ { control = NR; control_count++ }
    /--property=MainPID --value/ { main = NR; main_count++ }
    /--property=ExecStartPost --value/ { post = NR; post_count++ }
    /cgroup\.procs/ { procs = NR; procs_count++ }
    /\$0 != expected_pid/ { exact_pid = NR; exact_pid_count++ }
    END {
        valid = type_count == 1 && restart_count == 1 && control_count == 1
        valid = valid && main_count == 1 && post_count == 1 && procs_count == 1
        valid = valid && exact_pid_count == 1
        valid = valid && type < restart && restart < control && control < main
        valid = valid && main < post && post < procs && procs < exact_pid
        if (!valid) exit 1
    }
' "$shape_contract"; then
    printf '%s\n' 'driver service-shape observation is incomplete' >&2
    exit 1
fi
grep -F '[ "$(systemctl show --property=Type --value "$unit_name")" = simple ]' \
    "$shape_contract" >/dev/null
grep -F '[ "$(systemctl show --property=RestartUSec --value "$unit_name")" = 3s ]' \
    "$shape_contract" >/dev/null
grep -F '[ "$(systemctl show --property=ControlPID --value "$unit_name")" = 0 ]' \
    "$shape_contract" >/dev/null
[ "$(grep -Fc 'may_own_service_shape_is_exact "$may_own_pid_' "$gate")" -eq 3 ]

# Frozen successors are first followed through both exec transitions. GDB then
# holds the helper at its final exec until the outside-cgroup observer has
# entered the final private namespaces and the driver has accepted the shape.
for sequence in second third; do
    sequence_contract=$tmp/$sequence-sequence
    case $sequence in
        second)
            sed -n '/^    driver_phase=may-own-second-crash$/,/^    driver_phase=may-own-recovery$/p' \
                "$gate" >"$sequence_contract"
            sequence_pid=two
            ;;
        third)
            sed -n '/^    driver_phase=may-own-recovery$/,/^    driver_phase=may-own-retirement$/p' \
                "$gate" >"$sequence_contract"
            sequence_pid=three
            ;;
    esac
    grep -F "shell while [ ! -f \$may_own_${sequence}_driver_release ]; do /usr/bin/sleep 0.05; done" \
        "$sequence_contract" >/dev/null
    if ! awk -v expected_pid="$sequence_pid" '
        /while ! vp_capture_file_is_safe "\$may_own_.*_helper_exec_ready"/ {
            helper_wait = NR; helper_wait_count++
        }
        $0 ~ "start_may_own_driver_observer " expected_pid " " {
            observer = NR; observer_count++
        }
        $0 ~ "may_own_service_shape_is_exact \"\\$may_own_pid_" expected_pid "\"" {
            shape = NR; shape_count++
        }
        /vp_capture_run "\$may_own_.*_driver_release"/ {
            release = NR; release_count++
        }
        /^    wait "\$may_own_debugger_pid"/ { debugger_wait = NR; debugger_wait_count++ }
        END {
            valid = helper_wait_count == 1 && observer_count == 1
            valid = valid && shape_count == 1 && release_count == 1
            valid = valid && debugger_wait_count == 1
            valid = valid && helper_wait < observer && observer < shape
            valid = valid && shape < release && release < debugger_wait
            if (!valid) exit 1
        }
    ' "$sequence_contract"; then
        printf '%s successor observer handshake is not affine\n' "$sequence" >&2
        exit 1
    fi
done

# Each forced crash has a two-sided GDB/driver handshake. The stopped inferior
# publishes kill-ready, GDB waits, and the driver verifies the production shape
# plus a fully frozen cgroup before releasing the one pending GDB kill. This
# prevents the three-second production restart from racing the successor fence.
freeze_contract=$tmp/freeze-function
sed -n '/^freeze_may_own_cgroup_before_forced_crash() {$/,/^}$/p' \
    "$gate" >"$freeze_contract"
if ! awk '
    /may_own_service_shape_is_exact/ { shape = NR; shape_count++ }
    /1 >"\$may_own_cgroup\/cgroup\.freeze"/ { request = NR; request_count++ }
    /may_own_cgroup_frozen=yes/ { tracked = NR; tracked_count++ }
    /cat "\$may_own_cgroup\/cgroup\.freeze"/ { readback = NR; readback_count++ }
    /may_own_cgroup_is_fully_frozen/ { complete = NR; complete_count++ }
    /capture_process_starttime "\$may_own_debugger_pid"/ { debugger = NR; debugger_count++ }
    END {
        valid = shape_count == 1 && request_count == 1 && tracked_count == 1
        valid = valid && readback_count == 1 && complete_count == 1
        valid = valid && debugger_count == 1
        valid = valid && shape < request && request < tracked
        valid = valid && tracked < readback && readback < complete
        valid = valid && complete < debugger
        if (!valid) exit 1
    }
' "$freeze_contract"; then
    printf '%s\n' 'MayOwn cgroup freeze contract is incomplete' >&2
    exit 1
fi
frozen_event_contract=$tmp/frozen-event-function
sed -n '/^may_own_cgroup_is_fully_frozen() {$/,/^}$/p' \
    "$gate" >"$frozen_event_contract"
grep -F 'may_own_frozen_events=$may_own_frozen_cgroup/cgroup.events' \
    "$frozen_event_contract" >/dev/null
grep -F '$1 == "frozen" {' "$frozen_event_contract" >/dev/null
grep -F 'if (seen || NF != 2 || $2 != "1") exit 1' \
    "$frozen_event_contract" >/dev/null

for sequence in first second; do
    crash_contract=$tmp/$sequence-crash
    case $sequence in
        first)
            sed -n '/^    driver_phase=may-own-first-crash$/,/^    driver_phase=may-own-second-crash$/p' \
                "$gate" >"$crash_contract"
            sequence_pid=one
            ;;
        second)
            sed -n '/^    driver_phase=may-own-second-crash$/,/^    driver_phase=may-own-recovery$/p' \
                "$gate" >"$crash_contract"
            sequence_pid=two
            ;;
    esac
    if ! awk -v sequence="$sequence" -v expected_pid="$sequence_pid" '
        $0 ~ "shell printf .*MAY_OWN_" toupper(sequence) "_KILL_READY" {
            gdb_ready = NR; gdb_ready_count++
        }
        $0 ~ "shell while .*may_own_" sequence "_freeze_release" {
            gdb_hold = NR; gdb_hold_count++
        }
        /^[[:space:]]*\047kill\047/ { inferior_kill = NR; inferior_kill_count++ }
        /^[[:space:]]*\047quit 0\047/ { clean_quit = NR; clean_quit_count++ }
        $0 ~ "while ! vp_capture_file_is_safe .*may_own_" sequence "_kill_ready" {
            ready_wait = NR; ready_wait_count++
        }
        $0 ~ "freeze_may_own_cgroup_before_forced_crash .*may_own_pid_" expected_pid {
            freeze = NR; freeze_count++
        }
        $0 ~ "vp_capture_run .*may_own_" sequence "_freeze_release" {
            release = NR; release_count++
        }
        /^    wait "\$may_own_debugger_pid"/ { debugger_wait = NR; debugger_wait_count++ }
        END {
            valid = gdb_ready_count == 1 && gdb_hold_count == 1
            valid = valid && inferior_kill_count == 1 && ready_wait_count == 1
            valid = valid && clean_quit_count == 1
            valid = valid && freeze_count == 1 && release_count == 1
            valid = valid && debugger_wait_count == 1
            valid = valid && gdb_ready < gdb_hold && gdb_hold < inferior_kill
            valid = valid && inferior_kill < clean_quit && clean_quit < ready_wait
            valid = valid && ready_wait < freeze
            valid = valid && freeze < release && release < debugger_wait
            if (!valid) exit 1
        }
    ' "$crash_contract"; then
        printf '%s crash does not freeze before its GDB kill\n' "$sequence" >&2
        exit 1
    fi
done

# The polling observer enters the service mount and network namespaces. Its
# cgroup stays outside the service, is credential- and NNP-bound, and the hook
# independently requires ControlPID zero plus cgroup.procs containing only MainPID.
driver_start=$tmp/driver-start
sed -n '/^start_may_own_driver_observer() {$/,/^}$/p' "$gate" >"$driver_start"
grep -F '/usr/bin/nsenter --mount="/proc/$may_own_driver_main_pid/ns/mnt" \' \
    "$driver_start" >/dev/null
grep -F -- '--net="/proc/$may_own_driver_main_pid/ns/net" -- \' \
    "$driver_start" >/dev/null
grep -F '/usr/bin/setpriv --no-new-privs --reuid=0 \' "$driver_start" >/dev/null
grep -F '/run/volparossa-helper-production-ipc-hook may-own-driver-start \' \
    "$driver_start" >/dev/null
grep -F 'may_own_initial_namespaces_are_ready "$may_own_pid_one" \' \
    "$gate" >/dev/null
driver_entry=$tmp/driver-entry
sed -n '/^may_own_driver_entry_contract_is_exact() {$/,/^}$/p' \
    "$hook" >"$driver_entry"
grep -F '"/system.slice/$hook_driver_unit"|"/system.slice/$hook_driver_unit/"*)' \
    "$driver_entry" >/dev/null
grep -F 'org.freedesktop.systemd1.Service ControlPID)" = 0 ]' \
    "$driver_entry" >/dev/null
grep -F 'stat -Lc '\''%d:%i'\'' "/proc/$hook_driver_main_pid/ns/net"' \
    "$driver_entry" >/dev/null
grep -F 'stat -Lc '\''%d:%i'\'' /proc/1/ns/mnt' "$driver_start" >/dev/null
grep -F 'stat -Lc '\''%d:%i'\'' /proc/1/ns/net' "$driver_start" >/dev/null
grep -F 'hook_driver_service_procs=$hook_driver_service_cgroup/cgroup.procs' \
    "$driver_entry" >/dev/null
grep -F 'NR > 32 || $0 != expected_pid { invalid = 1 }' \
    "$driver_entry" >/dev/null
[ "$(grep -Fc 'may-own-driver-start)' "$hook")" -eq 1 ]
[ "$(grep -Fc 'may-own-start)' "$hook")" -eq 0 ]

# The runner settings are not an approximation: join them to the production
# Rust predicates and the production cgroup parser that gate restart custody.
[ "$(grep -Fc 'const RESTART_REAPER_RESTART_MICROSECONDS: u64 = 3_000_000;' \
    "$fdstore")" -eq 1 ]
fdstore_shape=$tmp/fdstore-shape
sed -n '/impl ServiceCgroupIsolationSnapshot {/,/^fn exact_bounded_property/p' \
    "$fdstore" >"$fdstore_shape"
grep -F 'if raw.control_pid != 0 {' "$fdstore_shape" >/dev/null
grep -F '!exact_bounded_property(&raw.service_type, "simple")' \
    "$fdstore_shape" >/dev/null
grep -F 'raw.restart_microseconds != RESTART_REAPER_RESTART_MICROSECONDS' \
    "$fdstore_shape" >/dev/null
custody_shape=$tmp/custody-shape
sed -n '/^fn parse_cgroup_procs(/,/^fn parse_canonical_decimal_u64/p' \
    "$custody" >"$custody_shape"
grep -F 'if value != current_main_pid {' "$custody_shape" >/dev/null
grep -F 'if members.len() != 1 || !members.contains(&current_main_pid) {' \
    "$custody_shape" >/dev/null

printf '%s\n' \
    'PASS: MayOwn restart runner exactly matches production Type/simple, 3s restart, and single-MainPID service shape.'
