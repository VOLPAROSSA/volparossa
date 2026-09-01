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
# Pre-exec and recovery phases require only MainPID; the stopped active-custody
# phase requires MainPID plus one separately affine worker. Both modes retain
# the same empty ExecStartPost and exact manager contract.
shape_contract=$tmp/shape-function
sed -n '/^may_own_service_shape_is_exact() {$/,/^}$/p' \
    "$gate" >"$shape_contract"
if ! awk '
    /--property=Type --value/ { type = NR; type_count++ }
    /--property=RestartUSec --value/ { restart = NR; restart_count++ }
    /--property=ControlPID --value/ { control = NR; control_count++ }
    /--property=MainPID --value/ { main = NR; main_count++ }
    /unit_current_invocation_id/ { invocation = NR; invocation_count++ }
    /--property=NRestarts --value/ { restarts = NR; restarts_count++ }
    /--property=NFileDescriptorStore --value/ { fdstore = NR; fdstore_count++ }
    /--property=ControlGroup \\/ { cgroup = NR; cgroup_count++ }
    /--property=ControlGroupId/ { cgroup_id = NR; cgroup_id_count++ }
    /--property=ExecStartPost --value/ { post = NR; post_count++ }
    /cgroup\.procs/ { procs = NR; procs_count++ }
    /may_own_shape_membership=\$5/ { membership = NR; membership_count++ }
    /^        main-only\)$/ { main_mode = NR; main_mode_count++ }
    /^        active-custody\)$/ { active_mode = NR; active_mode_count++ }
    /may_own_cgroup_members_are_exact/ { main_members = NR; main_members_count++ }
    /may_own_active_custody_worker_is_exact/ {
        active_members = NR; active_members_count++
    }
    END {
        valid = type_count == 1 && restart_count == 1 && control_count == 1
        valid = valid && main_count == 1 && invocation_count == 1
        valid = valid && restarts_count == 1 && fdstore_count == 1
        valid = valid && cgroup_count == 1 && cgroup_id_count == 1
        valid = valid && post_count == 1 && procs_count == 1
        valid = valid && membership_count == 1
        valid = valid && main_mode_count == 2 && active_mode_count == 2
        valid = valid && main_members_count == 1 && active_members_count == 1
        valid = valid && type < restart && restart < control && control < main
        valid = valid && membership < type
        valid = valid && main < post && post < procs
        valid = valid && procs < main_members && main_members < active_members
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
for exact_shape_field in \
    'unit_current_invocation_id' \
    'NRestarts --value' \
    'NFileDescriptorStore --value' \
    'FileDescriptorStoreMax --value' \
    'FileDescriptorStorePreserve --value' \
    'may_own_shape_control_group=$(systemctl show --property=ControlGroup' \
    'ControlGroupId' \
    'cgroup.type' \
    'nr_descendants' \
    'nr_dying_descendants'
do
    grep -F "$exact_shape_field" "$shape_contract" >/dev/null
done
[ "$(grep -Fc 'may_own_service_shape_is_exact "$may_own_pid_' "$gate")" -eq 3 ]

# The active phase accepts exactly the affine two-member set. A third PID,
# replacement worker, duplicate or collapsed MainPID/worker identity is a hard
# failure; order in cgroup.procs is immaterial.
active_members_contract=$tmp/active-members-function
sed -n '/^may_own_active_cgroup_members_are_exact() {$/,/^}$/p' \
    "$gate" >"$active_members_contract"
active_members_source_is_exact() {
    [ "$#" -eq 1 ] || return 1
    [ "$(grep -Fc 'NR > 32 || NF != 1' "$1")" -eq 1 ] \
        && [ "$(grep -Fc '$1 != expected_main && $1 != expected_worker' "$1")" -eq 1 ] \
        && [ "$(grep -Fc 'seen[$1]++' "$1")" -eq 1 ] \
        && [ "$(grep -Fc 'invalid || NR != 2 || seen[expected_main] != 1' "$1")" -eq 1 ] \
        && [ "$(grep -Fc 'seen[expected_worker] != 1' "$1")" -eq 1 ]
}
active_members_source_is_exact "$active_members_contract" || exit 1
sh -n "$active_members_contract"
# shellcheck disable=SC1090
. "$active_members_contract"
active_members_exact=$tmp/active-members.exact
active_members_reversed=$tmp/active-members.reversed
active_members_third=$tmp/active-members.third
active_members_unaffine=$tmp/active-members.unaffine
active_members_duplicate=$tmp/active-members.duplicate
printf '%s\n' 101 202 >"$active_members_exact"
printf '%s\n' 202 101 >"$active_members_reversed"
printf '%s\n' 101 202 303 >"$active_members_third"
printf '%s\n' 101 303 >"$active_members_unaffine"
printf '%s\n' 101 202 202 >"$active_members_duplicate"
may_own_active_cgroup_members_are_exact "$active_members_exact" 101 202
may_own_active_cgroup_members_are_exact "$active_members_reversed" 101 202
for active_members_mutant in \
    "$active_members_third" "$active_members_unaffine" \
    "$active_members_duplicate"
do
    if may_own_active_cgroup_members_are_exact \
        "$active_members_mutant" 101 202; then
        printf 'active custody accepted member mutant: %s\n' \
            "${active_members_mutant##*/}" >&2
        exit 1
    fi
done
if may_own_active_cgroup_members_are_exact "$active_members_exact" 101 101; then
    printf '%s\n' 'active custody accepted collapsed MainPID/worker identity' >&2
    exit 1
fi
active_members_count_mutant=$tmp/active-members-count-mutant
sed 's/invalid || NR != 2/invalid || NR < 2/' \
    "$active_members_contract" >"$active_members_count_mutant"
active_members_worker_mutant=$tmp/active-members-worker-mutant
sed 's/seen\[expected_worker\] != 1/seen[expected_worker] < 1/' \
    "$active_members_contract" >"$active_members_worker_mutant"
for active_members_source_mutant in \
    "$active_members_count_mutant" "$active_members_worker_mutant"
do
    sh -n "$active_members_source_mutant"
    if active_members_source_is_exact "$active_members_source_mutant"; then
        printf 'active member source contract accepted mutant: %s\n' \
            "${active_members_source_mutant##*/}" >&2
        exit 1
    fi
done

# The active worker is held at GDB's publication breakpoint while both the
# hook-side and outer predicates run. Linux reports that ptrace boundary as
# lowercase `t`; runnable, sleeping, uninterruptible, job-control-stopped, or
# uppercase tracing variants are not phase-equivalent. Its birth token is
# parsed with a separate tracing-stop parser, never by widening the generic
# R/S/D process parser.
active_starttime_contract=$tmp/active-starttime-function
sed -n '/^tracing_stop_process_starttime_from_stat() {$/,/^}$/p' \
    "$gate" >"$active_starttime_contract"
active_starttime_source_is_exact() {
    [ "$#" -eq 1 ] || return 1
    [ "$(grep -Fc 'value[1] != "t"' "$1")" -eq 1 ] \
        && [ "$(grep -Fc '/^(R|S|D)$/' "$1")" -eq 0 ] \
        && [ "$(grep -Fc 'starttime = value[20]' "$1")" -eq 1 ]
}
active_starttime_source_is_exact "$active_starttime_contract" || exit 1
sh -n "$active_starttime_contract"
# shellcheck disable=SC1090
. "$active_starttime_contract"
write_active_stat_fixture() {
    [ "$#" -eq 2 ] || return 1
    active_stat_fixture=$1
    active_stat_state=$2
    {
        printf '202 (contract fixture) %s' "$active_stat_state"
        active_stat_field=2
        while [ "$active_stat_field" -le 19 ]; do
            printf ' 0'
            active_stat_field=$((active_stat_field + 1))
        done
        printf ' 777\n'
    } >"$active_stat_fixture"
}

pre_boundary_starttime_contract=$tmp/pre-boundary-starttime-function
sed -n '/^pre_boundary_process_starttime_from_stat() {$/,/^}$/p' \
    "$gate" >"$pre_boundary_starttime_contract"
pre_boundary_starttime_source_is_exact() {
    [ "$#" -eq 1 ] || return 1
    [ "$(grep -Fc 'value[1] !~ /^(R|S|D|t)$/' "$1")" -eq 1 ] \
        && [ "$(grep -Fc '|T)' "$1")" -eq 0 ] \
        && [ "$(grep -Fc 'starttime = value[20]' "$1")" -eq 1 ]
}
pre_boundary_starttime_source_is_exact \
    "$pre_boundary_starttime_contract" || exit 1
sh -n "$pre_boundary_starttime_contract"
# shellcheck disable=SC1090
. "$pre_boundary_starttime_contract"
for pre_boundary_starttime_state in R S D t; do
    pre_boundary_starttime_fixture=$tmp/pre-boundary-starttime.$pre_boundary_starttime_state
    write_active_stat_fixture \
        "$pre_boundary_starttime_fixture" "$pre_boundary_starttime_state"
    [ "$(pre_boundary_process_starttime_from_stat \
        "$(cat "$pre_boundary_starttime_fixture")" 202)" = 777 ]
done
for pre_boundary_starttime_state in T X; do
    pre_boundary_starttime_mutant=$tmp/pre-boundary-starttime.$pre_boundary_starttime_state
    write_active_stat_fixture \
        "$pre_boundary_starttime_mutant" "$pre_boundary_starttime_state"
    if pre_boundary_process_starttime_from_stat \
        "$(cat "$pre_boundary_starttime_mutant")" 202 >/dev/null 2>&1; then
        printf 'pre-boundary custody accepted unsafe state: %s\n' \
            "$pre_boundary_starttime_state" >&2
        exit 1
    fi
done
pre_boundary_starttime_state_mutant=$tmp/pre-boundary-starttime-state-mutant
sed 's/|t)\$/|t|T)$/' \
    "$pre_boundary_starttime_contract" \
    >"$pre_boundary_starttime_state_mutant"
sh -n "$pre_boundary_starttime_state_mutant"
if pre_boundary_starttime_source_is_exact \
    "$pre_boundary_starttime_state_mutant"; then
    printf '%s\n' 'pre-boundary starttime source accepted state mutant' >&2
    exit 1
fi

active_starttime_exact=$tmp/active-starttime.t
write_active_stat_fixture "$active_starttime_exact" t
[ "$(tracing_stop_process_starttime_from_stat \
    "$(cat "$active_starttime_exact")" 202)" = 777 ]
for active_starttime_state in R S D T; do
    active_starttime_mutant=$tmp/active-starttime.$active_starttime_state
    write_active_stat_fixture \
        "$active_starttime_mutant" "$active_starttime_state"
    if tracing_stop_process_starttime_from_stat \
        "$(cat "$active_starttime_mutant")" 202 >/dev/null 2>&1; then
        printf 'active custody accepted non-tracing starttime state: %s\n' \
            "$active_starttime_state" >&2
        exit 1
    fi
done
active_starttime_state_mutant=$tmp/active-starttime-state-mutant
sed 's/value\[1\] != "t"/value[1] != "R"/' \
    "$active_starttime_contract" >"$active_starttime_state_mutant"
sh -n "$active_starttime_state_mutant"
if active_starttime_source_is_exact "$active_starttime_state_mutant"; then
    printf '%s\n' 'active starttime source accepted state mutant' >&2
    exit 1
fi

active_status_contract=$tmp/active-status-function
sed -n '/^may_own_worker_status_record_is_exact() {$/,/^}$/p' \
    "$gate" >"$active_status_contract"
active_status_source_is_exact() {
    [ "$#" -eq 1 ] || return 1
    [ "$(grep -Fc '$2 != "t"' "$1")" -eq 1 ] \
        && [ "$(grep -Fc '$2 !~ /^(R|S|D)$/' "$1")" -eq 0 ] \
        && [ "$(grep -Fc 'states != 1' "$1")" -eq 1 ] \
        && [ "$(grep -Fc 'threads != 1' "$1")" -eq 1 ]
}
active_status_source_is_exact "$active_status_contract" || exit 1
sh -n "$active_status_contract"
# shellcheck disable=SC1090
. "$active_status_contract"
write_active_status_fixture() {
    [ "$#" -eq 2 ] || return 1
    active_status_fixture=$1
    active_status_state=$2
    printf '%s\n' \
        "State: $active_status_state (contract fixture)" \
        'Pid: 202' \
        'PPid: 101' \
        'NSpid: 202' \
        'Threads: 1' >"$active_status_fixture"
}
active_status_exact=$tmp/active-status.t
write_active_status_fixture "$active_status_exact" t
may_own_worker_status_record_is_exact "$active_status_exact" 202 101
for active_status_state in R S D T; do
    active_status_mutant=$tmp/active-status.$active_status_state
    write_active_status_fixture "$active_status_mutant" "$active_status_state"
    if may_own_worker_status_record_is_exact \
        "$active_status_mutant" 202 101; then
        printf 'active custody accepted non-tracing-stop state: %s\n' \
            "$active_status_state" >&2
        exit 1
    fi
done
active_status_state_mutant=$tmp/active-status-state-mutant
sed 's/$2 != "t"/$2 != "R"/' \
    "$active_status_contract" >"$active_status_state_mutant"
sh -n "$active_status_state_mutant"
if active_status_source_is_exact "$active_status_state_mutant"; then
    printf '%s\n' 'active status source contract accepted state mutant' >&2
    exit 1
fi

active_worker_contract=$tmp/active-worker-function
sed -n '/^may_own_active_custody_worker_is_exact() {$/,/^}$/p' \
    "$gate" >"$active_worker_contract"
for active_worker_predicate in \
    'may_own_active_custody_boundary_is_exact' \
    'may_own_direct_helper_child "$may_own_active_main_pid"' \
    'capture_tracing_stop_process_starttime' \
    'may_own_worker_status_is_exact' \
    'may_own_worker_cgroup_is_exact' \
    'may_own_active_cgroup_members_are_exact'
do
    grep -F "$active_worker_predicate" "$active_worker_contract" >/dev/null
done
[ "$(grep -Fc 'may_own_direct_helper_child "$may_own_active_main_pid"' \
    "$active_worker_contract")" -eq 2 ]
[ "$(grep -Fc 'capture_tracing_stop_process_starttime' \
    "$active_worker_contract")" -eq 2 ]
[ "$(grep -Fc 'may_own_active_cgroup_members_are_exact' \
    "$active_worker_contract")" -eq 2 ]

# FIFO-gated successors are manager/cgroup-bound while the fixed launcher is
# still MainPID. GDB and the outside-cgroup pre-exec observer arm before release;
# the helper then remains stopped until the functional observer accepts shape.
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
        /may_own_preexec_barrier_is_exact/ { barrier = NR; barrier_count++ }
        /start_may_own_preexec_observer/ { preobserver = NR; preobserver_count++ }
        /release_may_own_preexec_barrier/ { fifo_release = NR; fifo_release_count++ }
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
            valid = barrier_count == 1 && preobserver_count == 1
            valid = valid && fifo_release_count == 1
            valid = valid && helper_wait_count == 1 && observer_count == 1
            valid = valid && shape_count == 1 && release_count == 1
            valid = valid && debugger_wait_count == 1
            valid = valid && barrier < preobserver && preobserver < fifo_release
            valid = valid && fifo_release < helper_wait
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
# proves the exact crash frame. The driver thaws/removes that old crash cgroup
# before waiting for the independently FIFO-gated successor.
freeze_contract=$tmp/freeze-function
sed -n '/^freeze_may_own_cgroup_before_forced_crash() {$/,/^}$/p' \
    "$gate" >"$freeze_contract"
if ! awk '
    /may_own_service_shape_is_exact/ {
        if (!shape_first) shape_first = NR
        shape_last = NR
        shape_count++
    }
    /^        main-only\)$/ { main_mode = NR; main_mode_count++ }
    /^        active-custody\)$/ { active_mode = NR; active_mode_count++ }
    /1 >"\$may_own_cgroup\/cgroup\.freeze"/ { request = NR; request_count++ }
    /may_own_cgroup_frozen=yes/ { tracked = NR; tracked_count++ }
    /cat "\$may_own_cgroup\/cgroup\.freeze"/ { readback = NR; readback_count++ }
    /may_own_cgroup_is_fully_frozen/ { complete = NR; complete_count++ }
    /capture_process_starttime "\$may_own_debugger_pid"/ { debugger = NR; debugger_count++ }
    END {
        valid = shape_count == 2 && request_count == 1 && tracked_count == 1
        valid = valid && main_mode_count == 1 && active_mode_count == 1
        valid = valid && readback_count == 1 && complete_count == 1
        valid = valid && debugger_count == 1
        valid = valid && main_mode < shape_first && shape_first < active_mode
        valid = valid && active_mode < shape_last && shape_last < request
        valid = valid && request < tracked
        valid = valid && tracked < readback && readback < complete
        valid = valid && complete < debugger
        if (!valid) exit 1
    }
' "$freeze_contract"; then
    printf '%s\n' 'MayOwn cgroup freeze contract is incomplete' >&2
    exit 1
fi
grep -F '2 main-only || return 1' "$freeze_contract" >/dev/null
grep -F '2 active-custody "$3" "$4" "$5" "$6" || return 1' \
    "$freeze_contract" >/dev/null
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

thaw_contract=$tmp/thaw-function
sed -n '/^thaw_may_own_crash_boundary_before_restart() {$/,/^}$/p' \
    "$gate" >"$thaw_contract"
grep -F '[ "$(systemctl show --property=MainPID --value "$unit_name")" = 0 ]' \
    "$thaw_contract" >/dev/null
grep -F '0 >"$may_own_cgroup/cgroup.freeze"' "$thaw_contract" >/dev/null
grep -F 'may_own_cgroup_frozen=no' "$thaw_contract" >/dev/null
if sed -n '/^    driver_phase=may-own-second-crash$/,/^    driver_phase=may-own-retirement$/p' \
    "$gate" | grep -F '0 >"$may_own_cgroup/cgroup.freeze"' >/dev/null; then
    printf '%s\n' 'MayOwn successor release still depends on cgroup.freeze' >&2
    exit 1
fi

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
driver_entry_members=$tmp/driver-entry-members
sed -n '/^may_own_driver_cgroup_members_are_exact() {$/,/^}$/p' \
    "$hook" >"$driver_entry_members"
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
    "$driver_entry_members" >/dev/null
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
    'PASS: MayOwn restart runner exactly matches production Type/simple, 3s restart, and phase-affine service shape.'
