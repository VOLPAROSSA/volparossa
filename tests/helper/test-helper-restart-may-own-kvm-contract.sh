#!/bin/sh
# shellcheck disable=SC1003,SC2016
# SPDX-License-Identifier: GPL-3.0-only
# Static fail-closed contract for the singleton MayOwnCustody Relay KVM proof.
set -eu
export LC_ALL=C
PATH=/usr/sbin:/usr/bin:/sbin:/bin
export PATH
umask 077

here=$(CDPATH='' cd -- "$(dirname -- "$0")" && pwd)
repository=$(CDPATH='' cd -- "$here/../.." && pwd)
gate=$here/require-live-worker-identity-proof.sh
hook=$here/lib/production-ipc-unit-hook.sh
observer=$here/lib/restart-may-own-relay-observer.sh
schema=$here/helper-restart-may-own-custody-relay-evidence-v1.schema.json
fixture=$here/fixtures/helper-restart-may-own-custody-relay-evidence-v1.pass.json
validator=$here/validate-helper-restart-may-own-custody-relay-evidence-v1.sh
environment_schema=$here/helper-restart-may-own-custody-relay-vm-environment-v1.schema.json
environment_fixture=$here/fixtures/helper-restart-may-own-custody-relay-vm-environment-v1.pass.json
environment_validator=$here/validate-helper-restart-may-own-custody-relay-vm-environment-v1.sh
runner=$here/run-helper-boundary-evidence-vm.sh
workflow=$repository/.github/workflows/helper-boundary-evidence.yml
tmp=$(mktemp -d /tmp/volparossa-may-own-restart-contract.XXXXXX)
case $tmp in /tmp/volparossa-may-own-restart-contract.??????) ;; *) exit 1 ;; esac
trap 'rm -rf --one-file-system -- "$tmp"' EXIT
trap 'exit 129' HUP
trap 'exit 130' INT
trap 'exit 143' TERM

for executable in \
    "$gate" "$hook" "$observer" "$validator" "$environment_validator" "$runner"
do
    [ -f "$executable" ] && [ -x "$executable" ] && [ ! -L "$executable" ] \
        || exit 1
    sh -n "$executable"
done
for json_input in "$schema" "$fixture" "$environment_schema" "$environment_fixture"; do
    [ -f "$json_input" ] && [ ! -L "$json_input" ] || exit 1
    jq -e -s 'length == 1' "$json_input" >/dev/null
done
"$validator" "$fixture"
"$environment_validator" "$environment_fixture" "$fixture" \
    1111111111111111111111111111111111111111 \
    aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa

# Reject representative widening, missing observations, collapsed lineage and
# non-canonical additions even when the JSON remains syntactically valid.
mutation_count=0
reject_mutation() {
    mutation_count=$((mutation_count + 1))
    mutation=$tmp/mutation.$mutation_count.json
    jq -S -c "$1" "$fixture" >"$mutation"
    if "$validator" "$mutation" >/dev/null 2>&1; then
        printf 'MayOwn validator accepted forbidden mutation %s\n' \
            "$mutation_count" >&2
        exit 1
    fi
}
reject_mutation '.scope.general_restart_recovery = true'
reject_mutation '.scope.cleanup_owned = true'
reject_mutation '.scope.usable_datapath = true'
reject_mutation '.restart.initial.target_role = "Client"'
reject_mutation '.restart.initial.manager_fdstore_count = 0'
reject_mutation '.restart.crashes = [.restart.crashes[0]]'
reject_mutation '.restart.crashes[0].exec_main_code = "killed"'
reject_mutation '.restart.crashes[1].exec_main_code = "killed"'
reject_mutation '.restart.recovered.new_socket_published_before_settlement = true'
reject_mutation '.invocation_ids[2] = .invocation_ids[1]'
reject_mutation '.checks[0].result = "SKIP"'
reject_mutation '.unexpected = true'
reject_mutation '.restart.crashes[1].boundary_observed_at = "2026-08-30T11:59:59Z"'

environment_mutation=$tmp/environment-mutation.json
jq -S -c '.report_sha256 = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"' \
    "$environment_fixture" >"$environment_mutation"
if "$environment_validator" "$environment_mutation" "$fixture" \
    1111111111111111111111111111111111111111 \
    aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa \
    >/dev/null 2>&1; then
    printf '%s\n' 'MayOwn environment validator accepted an unlinked report hash' >&2
    exit 1
fi

# The report is intentionally narrow: this proves one Relay MayOwnCustody
# singleton and two crashes, not cleanup-owned, a general restart proof, a
# package, a usable datapath, or A01--A15 acceptance.
jq -e '
  .report_kind == "volparossa-helper-restart-may-own-custody-relay-evidence"
  and .restart.initial.target_count == 1
  and .restart.initial.target_role == "Relay"
  and .restart.initial.target_phase == "MayOwnCustody"
  and .restart.initial.target_disposition == "ExactPresent"
  and (.restart.crashes | length == 2)
' "$fixture" >/dev/null
jq -e '
  .scope == {
    acceptance_a01_a15: false,
    cleanup_owned: false,
    forced_helper_crash_count: 2,
    general_restart_recovery: false,
    helper_boundary_only: true,
    installed_package: false,
    may_own_custody_exact_present_singleton_relay: true,
    usable_datapath: false
  }
  and (.checks | length == 25)
' "$fixture" >/dev/null

# Accept only closed executable source modes, hash before and after, then stage
# one root-owned mode-0500 image.
source_contract=$tmp/source-contract
sed -n '/may_own_observer_initial_snapshot=/,/MayOwn Relay observer has unsafe workspace metadata/p' \
    "$gate" >"$source_contract"
for accepted_mode in 700 750 755; do
    [ "$(grep -Fc \
        "\"\$may_own_observer_initial_snapshot\" $accepted_mode \"\$proof_file_max_bytes\"" \
        "$source_contract")" -eq 1 ]
done
[ "$(grep -Fc 'source_snapshot_is_exact' "$source_contract")" -eq 3 ]
staging_contract=$tmp/staging-contract
sed -n '/may_own_observer_before=/,/MayOwn Relay observer changed while copied/p' \
    "$gate" >"$staging_contract"
grep -F 'install -o root -g root -m 0500 "$may_own_observer_source" \' \
    "$staging_contract" >/dev/null
grep -F '"$temporary_stage/may-own-observer"' "$staging_contract" >/dev/null
grep -F 'staged_may_own_observer_digest' "$staging_contract" >/dev/null

# GDB runs the fixed observer as UID 0 with exactly the validated agent GID as
# real/effective and complete supplementary groups.
if ! awk '
    $0 == "observer_gid=$3" { gid = NR; gid_count++ }
    $0 == "case $observer_gid in" { validation = NR; validation_count++ }
    /\$\{#observer_gid\}.*-gt 10/ { length_bound = NR; length_count++ }
    /\$observer_gid.*-gt 4294967294/ { value_bound = NR; value_count++ }
    $0 == "exec /usr/bin/setpriv \\" { adapter = NR; adapter_count++ }
    $0 == "    --reuid=0 \\" { reuid = NR; reuid_count++ }
    $0 == "    --regid=\"$observer_gid\" \\" { regid = NR; regid_count++ }
    $0 == "    --groups=\"$observer_gid\" \\" { groups = NR; groups_count++ }
    $0 == "    -- /run/volparossa-helper-production-ipc-hook may-own-observe \"$@\"" {
        hook_line = NR; hook_count++
    }
    /^exec \/run\/volparossa-helper-production-ipc-hook/ { direct_hook++ }
    END {
        valid = gid_count == 1 && validation_count == 1
        valid = valid && length_count == 1 && value_count == 1
        valid = valid && adapter_count == 1 && reuid_count == 1
        valid = valid && regid_count == 1 && groups_count == 1 && hook_count == 1
        valid = valid && direct_hook == 0 && gid < validation
        valid = valid && validation < length_bound && length_bound < value_bound
        valid = valid && value_bound < adapter && adapter < reuid
        valid = valid && reuid < regid && regid < groups && groups < hook_line
        if (!valid) exit 1
    }
' "$observer"; then
    printf '%s\n' 'MayOwn observer identity adapter is not exact' >&2
    exit 1
fi
[ "$(grep -Fc 'armed|first-publication|after-first-crash|second-confirm|after-second-crash|third-removal)' \
    "$observer")" -eq 1 ]
for invalid_gid in '' 0 061000 not-a-gid 4294967295 99999999999; do
    set +e
    "$observer" armed volparossa-helper-live-proof-ABC123.service \
        "$invalid_gid" 1 >/dev/null 2>&1
    observer_status=$?
    set -e
    [ "$observer_status" -eq 64 ] || exit 1
done

# Exactly three debugger targets must each resolve to one Rust text symbol.
symbol_contract=$tmp/symbol-contract
sed -n '/may_own_symbol_counts=$(nm -C/,/MayOwn debugger symbols are not exact and unique/p' \
    "$gate" >"$symbol_contract"
for symbol in \
    volparossa_helper::worker_v3::DurableCustodyPublicationTerminalGuard::retain_published \
    volparossa_helper::ownership_journal::actor::DurableOwnershipStartup::confirm_single_restart_cleanup \
    volparossa_helper::systemd_fdstore::remove_restart_custody
do
    [ "$(grep -Fc "$symbol" "$symbol_contract")" -eq 1 ]
done
[ "$(grep -Fc 'if ($2 ~ /^[Tt]$/)' "$symbol_contract")" -eq 3 ]
grep -F "[ \"\$may_own_symbol_counts\" = '1:1:1:1:1:1' ] \\" \
    "$symbol_contract" >/dev/null

# Invocation one installs a pending publication breakpoint and exec catch while
# the fixed launcher is still blocked. After release it stops at the third
# publication (Client, Exit, then Relay) and uses GDB's bounded inferior kill.
if ! awk '
    /^    driver_phase=may-own-first-crash$/ { in_block = 1; start = NR }
    in_block && /break volparossa_helper::worker_v3::DurableCustodyPublicationTerminalGuard::retain_published/ {
        breakpoint = NR; breakpoint_count++
    }
    in_block && /ignore 1 2/ { ignore = NR; ignore_count++ }
    in_block && /set breakpoint pending on/ { pending = NR; pending_count++ }
    in_block && /tcatch exec/ { catch_exec = NR; catch_count++ }
    in_block && /may-own-observer first-publication/ { publication = NR; publication_count++ }
    in_block && /while \[ ! -f \$may_own_first_driver_release \]/ {
        driver_release = NR; driver_release_count++
    }
    in_block && /^[[:space:]]*\047kill\047/ { inferior_kill = NR; inferior_kill_count++ }
    in_block && /signal SIGKILL/ { invalid_signal++ }
    in_block && /may-own-observer armed/ { armed = NR; armed_count++ }
    in_block && /^    chmod 0600 "\$may_own_debugger_one_commands"/ {
        finish = NR; in_block = 0
    }
    END {
        valid = start > 0 && breakpoint_count == 1 && ignore_count == 1
        valid = valid && pending_count == 1 && catch_count == 1
        valid = valid && publication_count == 1 && driver_release_count == 1
        valid = valid && inferior_kill_count == 1
        valid = valid && invalid_signal == 0
        valid = valid && armed_count == 1 && finish > 0
        valid = valid && start < breakpoint && breakpoint < ignore
        valid = valid && pending < breakpoint && breakpoint < ignore
        valid = valid && ignore < armed && armed < publication
        valid = valid && publication < driver_release
        valid = valid && driver_release < inferior_kill
        valid = valid && inferior_kill < catch_exec && catch_exec < finish
        if (!valid) exit 1
    }
' "$gate"; then
    printf '%s\n' 'MayOwn first forced-crash debugger sequence is not exact' >&2
    exit 1
fi
grep -F -- '--net=/proc/$may_own_pid_one/ns/net -- /run/volparossa-helper-may-own-observer first-publication' \
    "$gate" >/dev/null
grep -F 'first-publication $unit_name $agent_gid $may_own_pid_one $worker_uid $worker_gid' \
    "$gate" >/dev/null

# At that exact publication breakpoint the staged observer joins the helper's
# mount and network namespaces, binds the unique direct worker to parent-owned
# process/pidfd/netns descriptors, revalidates those descriptors against the
# manager FD store and Relay journal, then publishes the bounded identity used
# by the outer active-cgroup predicate.
may_own_active_observer_contract=$tmp/may-own-active-observer-contract.sh
sed -n '/^may_own_observe_active_worker_custody() {$/,/^}$/p' \
    "$hook" >"$may_own_active_observer_contract"
may_own_active_observer_contract_is_exact() {
    [ "$#" -eq 1 ] || return 1
    may_own_active_observer_source=$1
    [ "$(grep -Fc 'direct_helper_child' \
        "$may_own_active_observer_source")" -eq 2 ] \
        && [ "$(grep -Fc 'capture_parent_worker_custody' \
            "$may_own_active_observer_source")" -eq 2 ] \
        && [ "$(grep -Fc 'capture_fdstore_descriptor_identity' \
            "$may_own_active_observer_source")" -eq 2 ] \
        && [ "$(grep -Fc 'unit_fdstore_exact_active_custody' \
            "$may_own_active_observer_source")" -eq 1 ] \
        && [ "$(grep -Fc 'traced_worker_identity_from_process_fd' \
            "$may_own_active_observer_source")" -eq 1 ] \
        && [ "$(grep -Fc '$(worker_identity_from_process_fd' \
            "$may_own_active_observer_source")" -eq 0 ] \
        && [ "$(grep -Fc 'may_own_active_cgroup_is_exact' \
            "$may_own_active_observer_source")" -eq 2 ] \
        && [ "$(grep -Fc '"$hook_may_own_active_custody" = \' \
            "$may_own_active_observer_source")" -eq 1 ] \
        && [ "$(grep -Fc '"$hook_may_own_expected_custody" ]' \
            "$may_own_active_observer_source")" -eq 1 ]
}
may_own_active_observer_contract_is_exact \
    "$may_own_active_observer_contract" || {
        printf '%s\n' 'MayOwn active worker observer is not descriptor-affine' >&2
        exit 1
    }
for may_own_active_observer_mutation in descriptor cgroup worker; do
    may_own_active_observer_mutant=$tmp/may-own-active-observer-$may_own_active_observer_mutation-mutant.sh
    case $may_own_active_observer_mutation in
        descriptor)
            sed '0,/unit_fdstore_exact_active_custody/s//true/' \
                "$may_own_active_observer_contract" \
                >"$may_own_active_observer_mutant"
            ;;
        cgroup)
            sed '0,/may_own_active_cgroup_is_exact/s//true/' \
                "$may_own_active_observer_contract" \
                >"$may_own_active_observer_mutant"
            ;;
        worker)
            sed '0,/traced_worker_identity_from_process_fd/s//worker_identity_from_process_fd/' \
                "$may_own_active_observer_contract" \
                >"$may_own_active_observer_mutant"
            ;;
    esac
    sh -n "$may_own_active_observer_mutant"
    if may_own_active_observer_contract_is_exact \
        "$may_own_active_observer_mutant"; then
        printf 'MayOwn active observer accepted mutant: %s\n' \
            "$may_own_active_observer_mutation" >&2
        exit 1
    fi
done

may_own_traced_identity_contract=$tmp/may-own-traced-identity-contract.sh
sed -n '/^traced_worker_identity_from_process_fd() {$/,/^}$/p' \
    "$hook" >"$may_own_traced_identity_contract"
may_own_traced_identity_contract_is_exact() {
    [ "$#" -eq 1 ] || return 1
    [ "$(grep -Fc 'capture_process_starttime_from_fd' "$1")" -eq 2 ] \
        && [ "$(grep -Fc 'worker_status_from_process_fd_is_exact' "$1")" -eq 2 ] \
        && [ "$(grep -Fc '"$hook_worker_parent_filters" tracing-stop' "$1")" -eq 2 ]
}
may_own_traced_identity_contract_is_exact \
    "$may_own_traced_identity_contract" || {
        printf '%s\n' 'MayOwn traced worker identity is not stably pinned' >&2
        exit 1
    }
may_own_traced_identity_mutant=$tmp/may-own-traced-identity-mutant.sh
sed '0,/"$hook_worker_parent_filters" tracing-stop/s//"$hook_worker_parent_filters" running/' \
    "$may_own_traced_identity_contract" >"$may_own_traced_identity_mutant"
sh -n "$may_own_traced_identity_mutant"
if may_own_traced_identity_contract_is_exact \
    "$may_own_traced_identity_mutant"; then
    printf '%s\n' 'MayOwn traced identity accepted running-state mutant' >&2
    exit 1
fi

may_own_worker_status_contract=$tmp/may-own-worker-status-contract.sh
sed -n '/^worker_status_from_process_fd_is_exact() {$/,/^}$/p' \
    "$hook" >"$may_own_worker_status_contract"
[ "$(grep -Fc 'expected_state_mode == "tracing-stop" && $2 != "t"' \
    "$may_own_worker_status_contract")" -eq 1 ]
[ "$(grep -Fc 'expected_state_mode == "running"' \
    "$may_own_worker_status_contract")" -eq 1 ]
[ "$(grep -Fc 'running|tracing-stop)' \
    "$may_own_worker_status_contract")" -eq 1 ]

may_own_observe_contract=$tmp/may-own-observe-contract.sh
sed -n '/^may_own_observe_hook() {$/,/^}$/p' "$hook" \
    >"$may_own_observe_contract"
if ! awk '
    /first-publication\)$/ {
        if (!first_mode) first_mode = NR
        first_mode_count++
    }
    /\[ "\$#" -eq 6 \]/ { arity = NR; arity_count++ }
    /"\$probe" prove-restart-may-own-relay \\$/ {
        journal = NR; journal_count++
    }
    /may_own_observe_active_worker_custody/ { active = NR; active_count++ }
    /hook_may_own_record=\$\(printf .*%s/ {
        if (!record) record = NR
        record_count++
    }
    /"\$hook_may_own_active_worker_pid"/ { worker = NR; worker_count++ }
    /"\$hook_may_own_active_worker_starttime"/ { birth = NR; birth_count++ }
    /"\$hook_may_own_active_process_identity"/ { process = NR; process_count++ }
    /"\$hook_may_own_active_pidfd_descriptor"/ { pidfd = NR; pidfd_count++ }
    /"\$hook_may_own_active_namespace_descriptor"/ { netns = NR; netns_count++ }
    /"\$hook_may_own_active_cgroup_identity"/ { cgroup = NR; cgroup_count++ }
    END {
        valid = first_mode_count == 2 && arity_count == 1
        valid = valid && journal_count == 1 && active_count == 1
        valid = valid && record_count == 3 && worker_count == 1
        valid = valid && birth_count == 1 && process_count == 1
        valid = valid && pidfd_count == 1 && netns_count == 1
        valid = valid && cgroup_count == 1
        valid = valid && first_mode < arity && arity < journal
        valid = valid && journal < active && active < record
        valid = valid && record < worker && worker < birth
        valid = valid && birth < process && process < pidfd
        valid = valid && pidfd < netns && netns < cgroup
        if (!valid) exit 1
    }
' "$may_own_observe_contract"; then
    printf '%s\n' 'MayOwn first boundary omits affine active-custody identity' >&2
    exit 1
fi

# Invocation two begins in the same launcher, installs one pending helper
# breakpoint plus one exec catch, observes the reaper journal confirmation
# boundary, then uses the second bounded inferior kill.
if ! awk '
    /^    may_own_tracer_ready=/ { in_block = 1; start = NR }
    in_block && /set breakpoint pending on/ { pending = NR; pending_count++ }
    in_block && /tcatch exec/ { catches++; c1 = NR }
    in_block && /'\''continue'\''/ { continues++; if (continues == 1) k1 = NR; if (continues == 2) k2 = NR }
    in_block && /break volparossa_helper::ownership_journal::actor::DurableOwnershipStartup::confirm_single_restart_cleanup/ {
        breakpoint = NR; breakpoint_count++
    }
    in_block && /may-own-observer second-confirm/ { observer_line = NR; observer_count++ }
    in_block && /^[[:space:]]*\047kill\047/ { inferior_kill = NR; inferior_kill_count++ }
    in_block && /signal SIGKILL/ { invalid_signal++ }
    in_block && /^    chmod 0600 "\$may_own_debugger_two_commands"/ {
        finish = NR; in_block = 0
    }
    END {
        valid = start > 0 && pending_count == 1 && catches == 1 && continues == 2
        valid = valid && breakpoint_count == 1 && observer_count == 1
        valid = valid && inferior_kill_count == 1 && invalid_signal == 0 && finish > 0
        valid = valid && start < pending && pending < breakpoint
        valid = valid && breakpoint < observer_line && observer_line < inferior_kill
        valid = valid && inferior_kill < c1 && c1 < k1 && k1 < k2 && k2 < finish
        if (!valid) exit 1
    }
' "$gate"; then
    printf '%s\n' 'MayOwn second forced-crash debugger sequence is not exact' >&2
    exit 1
fi

# Invocation three begins in the fixed launcher, installs one pending helper
# breakpoint plus one exec catch, observes exact restart custody removal, and
# detaches so startup can settle and publish.
if ! awk '
    /^    may_own_third_tracer_ready=/ { in_block = 1; start = NR }
    in_block && /set breakpoint pending on/ { pending = NR; pending_count++ }
    in_block && /tcatch exec/ { catches++; c1 = NR }
    in_block && /'\''continue'\''/ { continues++; if (continues == 1) k1 = NR; if (continues == 2) k2 = NR }
    in_block && /break volparossa_helper::systemd_fdstore::remove_restart_custody/ {
        breakpoint = NR; breakpoint_count++
    }
    in_block && /may-own-observer third-removal/ { observer_line = NR; observer_count++ }
    in_block && /'\''detach'\''/ { detach = NR; detach_count++ }
    in_block && /'\''quit'\''/ { quit = NR; quit_count++ }
    in_block && /^    chmod 0600 "\$may_own_debugger_three_commands"/ {
        finish = NR; in_block = 0
    }
    END {
        valid = start > 0 && pending_count == 1 && catches == 1 && continues == 2
        valid = valid && breakpoint_count == 1 && observer_count == 1
        valid = valid && detach_count == 1 && quit_count == 1 && finish > 0
        valid = valid && start < pending && pending < breakpoint
        valid = valid && breakpoint < observer_line
        valid = valid && observer_line < detach && detach < quit
        valid = valid && quit < c1 && c1 < k1 && k1 < k2 && k2 < finish
        if (!valid) exit 1
    }
' "$gate"; then
    printf '%s\n' 'MayOwn recovery debugger sequence is not exact' >&2
    exit 1
fi

# Three distinct service invocations are adopted one at a time; restart counters
# are observed as exactly 0, 1, and 2 at their respective fences.
grep -F 'recover_successful_may_own_manager_binding() {' "$gate" >/dev/null
grep -F 'adopt_launched_tentative_unit || return 1' "$gate" >/dev/null
grep -F '"$temporary_stage/systemd-run-may-own.stdout")" = 0 ] \' \
    "$gate" >/dev/null
grep -F 'elif recover_successful_may_own_manager_binding; then' "$gate" >/dev/null
grep -F "adopt_tentative_unit || failed 'MayOwn second invocation could not be adopted'" \
    "$gate" >/dev/null
grep -F "adopt_tentative_unit || failed 'MayOwn third invocation could not be adopted'" \
    "$gate" >/dev/null
lineage_contract=$tmp/lineage-contract
sed -n '/driver_phase=may-own-first-crash/,/MayOwn third invocation lineage is invalid/p' \
    "$gate" >"$lineage_contract"
grep -F 'if [ "$(systemctl show --property=NRestarts --value "$unit_name")" != 0 ] \' \
    "$lineage_contract" >/dev/null
[ "$(grep -Fc '[ "$(systemctl show --property=NRestarts --value "$unit_name")" != 1 ]' \
    "$lineage_contract")" -eq 2 ]
grep -F '|| [ "$(systemctl show --property=NRestarts --value "$unit_name")" != 2 ]; then' \
    "$lineage_contract" >/dev/null
grep -F '|| [ "$may_own_invocation_two" = "$may_own_invocation_one" ] \' \
    "$lineage_contract" >/dev/null
grep -F '|| [ "$may_own_invocation_three" = "$may_own_invocation_one" ] \' \
    "$lineage_contract" >/dev/null
grep -F '|| [ "$may_own_invocation_three" = "$may_own_invocation_two" ] \' \
    "$lineage_contract" >/dev/null

# All three invocations use the same fixed no-argument launcher as MainPID and
# are released only from an invocation/PID-bound FIFO after exact manager,
# cgroup, debugger and external-observer readiness. The cgroup freezer must be
# zero at this gate.
grep -F -- '--property=Environment=VOLPAROSSA_HELPER_PREEXEC_MODE=may-own \' \
    "$gate" >/dev/null
grep -F '/run/volparossa-helper-restart-launcher \' "$gate" >/dev/null
[ "$(grep -Fc 'may_own_preexec_barrier_is_exact "$may_own_pid_' "$gate")" -eq 3 ]
[ "$(grep -Fc 'start_may_own_preexec_observer ' "$gate")" -eq 3 ]
[ "$(grep -Fc 'release_may_own_preexec_barrier "$may_own_pid_' "$gate")" -eq 3 ]
[ "$(grep -Fc 'release_may_own_preexec_observer ' "$gate")" -eq 3 ]
preexec_release_contract=$tmp/preexec-release-contract
sed -n '/^release_may_own_preexec_barrier() {$/,/^}$/p' \
    "$gate" >"$preexec_release_contract"
if ! awk '
    /timeout --preserve-status --signal=TERM --kill-after=1s 5s/ {
        timeout_line = NR; timeout_count++
    }
    $0 == "        /bin/sh -c \047printf \"%s\\n\" G >\"$1\"\047 sh \\" {
        writer = NR; writer_count++
    }
    $0 == "        \"$may_own_preexec_release_fifo\" \\" {
        fifo = NR; fifo_count++
    }
    /printf %s G/ { unterminated_writer++ }
    END {
        valid = timeout_count == 1 && writer_count == 1 && fifo_count == 1
        valid = valid && unterminated_writer == 0
        valid = valid && timeout_line < writer && writer < fifo
        if (!valid) exit 1
    }
' "$preexec_release_contract"; then
    printf '%s\n' 'MayOwn pre-exec release is not newline-exact and bounded' >&2
    exit 1
fi
preexec_contract=$tmp/preexec-contract
sed -n '/^may_own_preexec_barrier_is_exact() {$/,/^}$/p' \
    "$gate" >"$preexec_contract"
may_own_preexec_wait_contract_is_exact() {
    [ "$#" -eq 1 ] || return 1
    may_own_preexec_source=$1
    awk '
        /may_own_barrier_starttime=\$\(capture_process_starttime/ {
            starttime[++starttime_count] = NR
        }
        /while ! vp_capture_file_is_safe "\$may_own_barrier_record"; do/ {
            wait_loop = NR; wait_loop_count++
        }
        /if \[ -e "\$may_own_barrier_record" \]/ {
            unsafe_exists = NR; unsafe_exists_count++
        }
        /\|\| \[ -L "\$may_own_barrier_record" \]; then/ {
            unsafe_symlink = NR; unsafe_symlink_count++
        }
        /^            vp_capture_file_is_safe "\$may_own_barrier_record" \|\| return 1$/ {
            publication_recheck = NR; publication_recheck_count++
        }
        /^            break$/ { publication_break = NR; publication_break_count++ }
        /^        fi$/ { publication_fi = NR; publication_fi_count++ }
        /systemctl show --property=MainPID --value "\$unit_name"/ {
            main_pid[++main_pid_count] = NR
        }
        /unit_current_invocation_id 2>\/dev\/null \|\| true/ {
            invocation[++invocation_count] = NR
        }
        /capture_process_starttime "\$may_own_barrier_main_pid"/ {
            process_starttime[++process_starttime_count] = NR
        }
        /unit_description_matches_marker \|\| return 1/ {
            marker[++marker_count] = NR
        }
        index($0, "may_own_barrier_wait=$((may_own_barrier_wait + 1))") {
            increment[++increment_count] = NR
        }
        /\[ "\$may_own_barrier_wait" -lt 600 \] \|\| return 1/ {
            bound[++bound_count] = NR
        }
        /^        sleep 0\.05$/ { sleep_line[++sleep_count] = NR }
        /^    done$/ { loop_done[++loop_done_count] = NR }
        /may_own_service_shape_is_exact "\$may_own_barrier_main_pid"/ {
            shape = NR; shape_count++
        }
        /^    do$/ { shape_do = NR; shape_do_count++ }
        /"\$may_own_preexec_barrier_failure_stage" = shape-cgroup-members/ {
            shape_guard = NR; shape_guard_count++
        }
        /may_own_preexec_barrier_failure_stage=shape-cgroup-members/ {
            shape_stage = NR; shape_stage_count++
        }
        /stat -Lc '\''%s'\'' "\$may_own_barrier_record"/ {
            size = NR; size_count++
        }
        /cmp -s "\$may_own_barrier_expected" "\$may_own_barrier_record"/ {
            content = NR; content_count++
        }
        /may_own_preexec_barrier_failure_stage=launcher-executable/ {
            executable_stage = NR; executable_stage_count++
        }
        /may_own_barrier_executable=\$\(stat -Lc '\''%d:%i'\''/ {
            executable_capture = NR; executable_capture_count++
        }
        /"\/proc\/\$may_own_barrier_main_pid\/exe"\)/ {
            executable_path = NR; executable_path_count++
        }
        /may_own_barrier_interpreter=\$\(stat -Lc '\''%d:%i'\'' \/bin\/sh\)/ {
            interpreter = NR; interpreter_count++
        }
        /"\$may_own_barrier_executable" = "\$may_own_barrier_interpreter"/ {
            interpreter_match = NR; interpreter_match_count++
        }
        /may_own_preexec_barrier_failure_stage=launcher-script-fd/ {
            launcher_fd_stage = NR; launcher_fd_stage_count++
        }
        /may_own_barrier_launcher_fd=\$\(stat -Lc/ {
            launcher_fd_capture = NR; launcher_fd_capture_count++
        }
        /"\/proc\/\$may_own_barrier_main_pid\/fd\/9"/ {
            launcher_fd_path = NR; launcher_fd_path_count++
        }
        /may_own_barrier_launcher_stage=\$\(stat -Lc/ {
            launcher_stage_capture = NR; launcher_stage_capture_count++
        }
        /"\$temporary_stage\/restart-launcher" 2>\/dev\/null\)/ {
            launcher_stage_path = NR; launcher_stage_path_count++
        }
        /"\$may_own_barrier_launcher_fd" = "\$may_own_barrier_launcher_stage"/ {
            launcher_fd_match = NR; launcher_fd_match_count++
        }
        /may_own_preexec_barrier_failure_stage=launcher-script-flags/ {
            launcher_flags_stage = NR; launcher_flags_stage_count++
        }
        /"\/proc\/\$may_own_barrier_main_pid\/fdinfo\/9"/ {
            launcher_fdinfo = NR; launcher_fdinfo_count++
        }
        /\[ "\$\(\(may_own_barrier_launcher_flags & 3\)\)" -eq 0 \]/ {
            launcher_read_only = NR; launcher_read_only_count++
        }
        /cgroup\.freeze"\)" = 0 \]/ { freezer = NR; freezer_count++ }
        END {
            valid = wait_loop_count == 1 && unsafe_exists_count == 1
            valid = valid && unsafe_symlink_count == 1
            valid = valid && publication_recheck_count == 1
            valid = valid && publication_break_count == 1
            valid = valid && publication_fi_count == 1
            valid = valid && main_pid_count == 3 && invocation_count == 3
            valid = valid && starttime_count == 1
            valid = valid && process_starttime_count == 3 && marker_count == 3
            valid = valid && increment_count == 2 && bound_count == 2
            valid = valid && sleep_count == 2 && loop_done_count == 2
            valid = valid && shape_count == 1 && size_count == 1
            valid = valid && shape_do_count == 1 && shape_guard_count == 1
            valid = valid && shape_stage_count == 1
            valid = valid && content_count == 1
            valid = valid && executable_stage_count == 1
            valid = valid && executable_capture_count == 1
            valid = valid && executable_path_count == 1
            valid = valid && interpreter_count == 1
            valid = valid && interpreter_match_count == 1
            valid = valid && launcher_fd_stage_count == 1
            valid = valid && launcher_fd_capture_count == 1
            valid = valid && launcher_fd_path_count == 1
            valid = valid && launcher_stage_capture_count == 1
            valid = valid && launcher_stage_path_count == 1
            valid = valid && launcher_fd_match_count == 1
            valid = valid && launcher_flags_stage_count == 1
            valid = valid && launcher_fdinfo_count == 1
            valid = valid && launcher_read_only_count == 1
            valid = valid && freezer_count == 1
            valid = valid && starttime[1] < wait_loop
            valid = valid && wait_loop < unsafe_exists
            valid = valid && unsafe_exists < unsafe_symlink
            valid = valid && unsafe_symlink < publication_recheck
            valid = valid && publication_recheck < publication_break
            valid = valid && publication_break < publication_fi
            valid = valid && publication_fi < main_pid[1]
            valid = valid && main_pid[1] < invocation[1]
            valid = valid && invocation[1] < process_starttime[1]
            valid = valid && process_starttime[1] < marker[1]
            valid = valid && marker[1] < increment[1]
            valid = valid && increment[1] < bound[1]
            valid = valid && bound[1] < sleep_line[1]
            valid = valid && sleep_line[1] < loop_done[1]
            valid = valid && loop_done[1] < main_pid[2]
            valid = valid && main_pid[2] < invocation[2]
            valid = valid && invocation[2] < process_starttime[2]
            valid = valid && process_starttime[2] < marker[2]
            valid = valid && marker[2] < shape && shape < shape_do
            valid = valid && shape_do < shape_guard
            valid = valid && shape_guard < main_pid[3]
            valid = valid && main_pid[3] < invocation[3]
            valid = valid && invocation[3] < process_starttime[3]
            valid = valid && process_starttime[3] < marker[3]
            valid = valid && marker[3] < increment[2]
            valid = valid && increment[2] < shape_stage
            valid = valid && shape_stage < bound[2]
            valid = valid && bound[2] < sleep_line[2]
            valid = valid && sleep_line[2] < loop_done[2]
            valid = valid && loop_done[2] < size
            valid = valid && size < content && content < executable_stage
            valid = valid && executable_stage < executable_capture
            valid = valid && executable_capture < executable_path
            valid = valid && executable_path < interpreter
            valid = valid && interpreter < interpreter_match
            valid = valid && interpreter_match < launcher_fd_stage
            valid = valid && launcher_fd_stage < launcher_fd_capture
            valid = valid && launcher_fd_capture < launcher_fd_path
            valid = valid && launcher_fd_path < launcher_stage_capture
            valid = valid && launcher_stage_capture < launcher_stage_path
            valid = valid && launcher_stage_path < launcher_fd_match
            valid = valid && launcher_fd_match < launcher_flags_stage
            valid = valid && launcher_flags_stage < launcher_fdinfo
            valid = valid && launcher_fdinfo < launcher_read_only
            valid = valid && launcher_read_only < freezer
            if (!valid) exit 1
        }
    ' "$may_own_preexec_source"
}
if ! may_own_preexec_wait_contract_is_exact "$preexec_contract"; then
    printf '%s\n' 'MayOwn pre-exec publication wait is not exact' >&2
    exit 1
fi
for preexec_field in \
    'may_own_service_shape_is_exact "$may_own_barrier_main_pid" \' \
    'VOLPAROSSA_HELPER_MAY_OWN_PRE_EXEC_BARRIER_V1=ready' \
    'cmp -s "$may_own_barrier_expected" "$may_own_barrier_record"' \
    'may_own_barrier_interpreter=$(stat -Lc '\''%d:%i'\'' /bin/sh)' \
    '"/proc/$may_own_barrier_main_pid/fd/9"' \
    '"/proc/$may_own_barrier_main_pid/fdinfo/9"' \
    'may_own_barrier_launcher_flags & 3' \
    'cgroup.freeze")" = 0 ]'
do
    grep -F "$preexec_field" "$preexec_contract" >/dev/null
done

preexec_single_shot_mutant=$tmp/preexec-single-shot-mutant
sed \
    -e 's/while ! vp_capture_file_is_safe "$may_own_barrier_record"; do/if ! vp_capture_file_is_safe "$may_own_barrier_record"; then/' \
    -e '0,/^    done$/s//    fi/' \
    "$preexec_contract" >"$preexec_single_shot_mutant"
preexec_main_pid_mutant=$tmp/preexec-main-pid-mutant
sed '0,/--property=MainPID/s//--property=MainPID_REMOVED/' \
    "$preexec_contract" >"$preexec_main_pid_mutant"
preexec_publication_recheck_mutant=$tmp/preexec-publication-recheck-mutant
sed '/^            vp_capture_file_is_safe /s/vp_capture_file_is_safe/false/' \
    "$preexec_contract" >"$preexec_publication_recheck_mutant"
preexec_invocation_mutant=$tmp/preexec-invocation-mutant
sed '0,/unit_current_invocation_id/s//unit_current_invocation_id_removed/' \
    "$preexec_contract" >"$preexec_invocation_mutant"
preexec_starttime_mutant=$tmp/preexec-starttime-mutant
sed '0,/capture_process_starttime/s//capture_removed_process_starttime/' \
    "$preexec_contract" >"$preexec_starttime_mutant"
preexec_bound_mutant=$tmp/preexec-bound-mutant
sed 's/-lt 600/-lt 6000/' "$preexec_contract" >"$preexec_bound_mutant"
preexec_shape_guard_mutant=$tmp/preexec-shape-guard-mutant
sed 's/= shape-cgroup-members ]/= shape-cgroup-stat ]/' \
    "$preexec_contract" >"$preexec_shape_guard_mutant"
preexec_interpreter_mutant=$tmp/preexec-interpreter-mutant
sed 's@stat -Lc '\''%d:%i'\'' /bin/sh@stat -Lc '\''%d:%i'\'' /bin/false@' \
    "$preexec_contract" >"$preexec_interpreter_mutant"
preexec_launcher_fd_mutant=$tmp/preexec-launcher-fd-mutant
sed 's@/fd/9@/fd/8@g; s@/fdinfo/9@/fdinfo/8@g' \
    "$preexec_contract" >"$preexec_launcher_fd_mutant"
preexec_launcher_flags_mutant=$tmp/preexec-launcher-flags-mutant
sed 's/& 3/\& 0/' "$preexec_contract" >"$preexec_launcher_flags_mutant"
preexec_shape_order_mutant=$tmp/preexec-shape-order-mutant
awk '
    { source[NR] = $0 }
    /while ! vp_capture_file_is_safe "\$may_own_barrier_record"; do/ {
        wait_loop = NR
    }
    /may_own_service_shape_is_exact "\$may_own_barrier_main_pid"/ {
        shape_start = NR
        shape_end = NR + 3
    }
    END {
        if (!wait_loop || !shape_start) exit 1
        for (line = 1; line <= NR; line++) {
            if (line == wait_loop) {
                for (shape_line = shape_start; shape_line <= shape_end; shape_line++) {
                    print source[shape_line]
                }
            }
            if (line < shape_start || line > shape_end) print source[line]
        }
    }
' "$preexec_contract" >"$preexec_shape_order_mutant"
for preexec_mutant in \
    "$preexec_single_shot_mutant" "$preexec_publication_recheck_mutant" \
    "$preexec_main_pid_mutant" \
    "$preexec_invocation_mutant" "$preexec_starttime_mutant" \
    "$preexec_bound_mutant" "$preexec_shape_guard_mutant" \
    "$preexec_interpreter_mutant" "$preexec_launcher_fd_mutant" \
    "$preexec_launcher_flags_mutant" \
    "$preexec_shape_order_mutant"
do
    sh -n "$preexec_mutant"
    if may_own_preexec_wait_contract_is_exact "$preexec_mutant"; then
        printf 'MayOwn pre-exec wait accepted forbidden mutant: %s\n' \
            "${preexec_mutant##*/}" >&2
        exit 1
    fi
done

preexec_diagnostic_functions=$tmp/preexec-diagnostic-functions
{
    sed -n '/^may_own_preexec_barrier_failure_stage_is_safe() {$/,/^}$/p' \
        "$gate"
    sed -n '/^report_may_own_preexec_barrier_failure_stage() {$/,/^}$/p' \
        "$gate"
} >"$preexec_diagnostic_functions"
sh -n "$preexec_diagnostic_functions"
# shellcheck disable=SC1090
. "$preexec_diagnostic_functions"
preexec_diagnostic_stdout=$tmp/preexec-diagnostic.stdout
preexec_diagnostic_stderr=$tmp/preexec-diagnostic.stderr
preexec_diagnostic_categories='arguments starttime publication-unsafe publication-timeout lineage-mainpid lineage-invocation lineage-starttime lineage-marker shape-mainpid-argument shape-invocation-argument shape-count-arguments shape-membership-mode shape-type shape-restart-usec shape-control-pid shape-main-pid shape-invocation shape-restarts shape-fdstore-count shape-fdstore-max shape-fdstore-preserve shape-exec-start-post shape-control-group shape-control-group-id shape-cgroup-path shape-cgroup-procs shape-active-boundary shape-worker-child shape-worker-starttime shape-worker-parent shape-worker-cgroup shape-cgroup-members shape-worker-stability shape-cgroup-type shape-cgroup-stat record-size expectation-create expectation-write record-content launcher-executable launcher-script-fd launcher-script-flags freezer'
for preexec_diagnostic_category in $preexec_diagnostic_categories; do
    may_own_preexec_barrier_failure_stage_is_safe \
        "$preexec_diagnostic_category" || exit 1
    # The sourced reporter consumes this reviewed global directly.
    # shellcheck disable=SC2034
    may_own_preexec_barrier_failure_stage=$preexec_diagnostic_category
    report_may_own_preexec_barrier_failure_stage \
        >"$preexec_diagnostic_stdout" 2>"$preexec_diagnostic_stderr"
    [ ! -s "$preexec_diagnostic_stdout" ]
    [ "$(cat "$preexec_diagnostic_stderr")" = \
        "VOLPAROSSA_HELPER_LIVE_MAY_OWN_PREEXEC_BARRIER_DIAGNOSTIC_V1=$preexec_diagnostic_category" ]
    grep -F "may_own_preexec_barrier_failure_stage=$preexec_diagnostic_category" \
        "$gate" >/dev/null
done
for unsafe_preexec_diagnostic_category in \
    '' private-detail shape-private /tmp/value 'shape-type value'
do
    if may_own_preexec_barrier_failure_stage_is_safe \
        "$unsafe_preexec_diagnostic_category"; then
        printf 'MayOwn pre-exec diagnostic accepted unsafe category: %s\n' \
            "$unsafe_preexec_diagnostic_category" >&2
        exit 1
    fi
done
[ "$(grep -Fc 'report_may_own_preexec_barrier_failure_stage \' "$gate")" -eq 6 ]
preexec_assigned_categories=$tmp/preexec-assigned-categories
sed -n 's/^[[:space:]]*may_own_preexec_barrier_failure_stage=\([a-z][a-z0-9-]*\)$/\1/p' \
    "$gate" >"$preexec_assigned_categories"
while IFS= read -r assigned_preexec_diagnostic_category; do
    may_own_preexec_barrier_failure_stage_is_safe \
        "$assigned_preexec_diagnostic_category" || exit 1
done <"$preexec_assigned_categories"

may_own_driver_start_reporter_contract=$tmp/may-own-driver-start-reporter-contract.sh
sed -n '/^report_may_own_driver_start_failure_stage() {$/,/^}$/p' \
    "$gate" >"$may_own_driver_start_reporter_contract"
may_own_driver_start_reporter=$tmp/may-own-driver-start-reporter.sh
{
    sed -n '/^production_start_failure_stage_is_safe() {$/,/^}$/p' "$gate"
    sed -n '/^may_own_driver_entry_failure_stage_is_safe() {$/,/^}$/p' "$gate"
    sed -n '/^report_may_own_driver_start_failure_stage() {$/,/^}$/p' "$gate"
} >"$may_own_driver_start_reporter"
sh -n "$may_own_driver_start_reporter"
may_own_driver_start_reporter_contract_is_exact() {
    [ "$#" -eq 1 ] || return 1
    awk '
        /vp_capture_file_is_safe "\$may_own_driver_start_failure_file"/ {
            start_safe_file = NR; start_safe_file_count++
        }
        /may_own_driver_start_failure_file\.next/ {
            start_next_path[++start_next_path_count] = NR
        }
        /may_own_driver_start_failure_size" -le 128 \]/ {
            start_size_bound = NR; start_size_bound_count++
        }
        /may_own_driver_start_failure_prefix=VOLPAROSSA_HELPER_V3_IPC_START_FAILURE_STAGE_V1=/ {
            start_prefix = NR; start_prefix_count++
        }
        /production_start_failure_stage_is_safe/ {
            start_allowlist = NR; start_allowlist_count++
        }
        /\| cmp -s - "\$may_own_driver_start_failure_file"/ {
            start_exact = NR; start_exact_count++
        }
        /may_own_driver_entry_failure_file\.next/ {
            entry_next_path[++entry_next_path_count] = NR
        }
        /\[ "\$may_own_driver_start_failure_stage" = preflight-runtime \]/ {
            entry_scope = NR; entry_scope_count++
        }
        /vp_capture_file_is_safe "\$may_own_driver_entry_failure_file"/ {
            entry_safe_file = NR; entry_safe_file_count++
        }
        /may_own_driver_entry_failure_size" -le 128 \]/ {
            entry_size_bound = NR; entry_size_bound_count++
        }
        /may_own_driver_entry_failure_prefix=VOLPAROSSA_HELPER_V3_MAY_OWN_DRIVER_ENTRY_FAILURE_V1=/ {
            entry_prefix = NR; entry_prefix_count++
        }
        /may_own_driver_entry_failure_stage_is_safe/ {
            entry_allowlist = NR; entry_allowlist_count++
        }
        /\| cmp -s - "\$may_own_driver_entry_failure_file"/ {
            entry_exact = NR; entry_exact_count++
        }
        /VOLPAROSSA_HELPER_LIVE_MAY_OWN_DRIVER_START_FAILURE_V1=%s/ {
            start_output = NR; start_output_count++
        }
        /VOLPAROSSA_HELPER_LIVE_MAY_OWN_DRIVER_ENTRY_FAILURE_V1=%s/ {
            entry_output = NR; entry_output_count++
        }
        END {
            valid = start_safe_file_count == 1 && start_next_path_count == 2
            valid = valid && start_size_bound_count == 1
            valid = valid && start_prefix_count == 1
            valid = valid && start_allowlist_count == 1
            valid = valid && start_exact_count == 1
            valid = valid && entry_next_path_count == 2
            valid = valid && entry_scope_count == 1
            valid = valid && entry_safe_file_count == 1
            valid = valid && entry_size_bound_count == 1
            valid = valid && entry_prefix_count == 1
            valid = valid && entry_allowlist_count == 1
            valid = valid && entry_exact_count == 1
            valid = valid && start_output_count == 1
            valid = valid && entry_output_count == 1
            valid = valid && start_safe_file < start_next_path[1]
            valid = valid && start_next_path[1] <= start_next_path[2]
            valid = valid && start_next_path[2] < start_size_bound
            valid = valid && start_size_bound < start_prefix
            valid = valid && start_prefix < start_allowlist
            valid = valid && start_allowlist < start_exact
            valid = valid && start_exact < entry_next_path[1]
            valid = valid && entry_next_path[1] <= entry_next_path[2]
            valid = valid && entry_next_path[2] < entry_scope
            valid = valid && entry_scope < entry_safe_file
            valid = valid && entry_safe_file < entry_size_bound
            valid = valid && entry_size_bound < entry_prefix
            valid = valid && entry_prefix < entry_allowlist
            valid = valid && entry_allowlist < entry_exact
            valid = valid && entry_exact < start_output
            valid = valid && start_output < entry_output
            if (!valid) exit 1
        }
    ' "$1"
}
may_own_driver_start_reporter_contract_is_exact \
    "$may_own_driver_start_reporter_contract" || exit 1
if ! awk '
    /report_may_own_driver_start_failure_stage \|\| :/ {
        diagnostic[++diagnostic_count] = NR
    }
    /failed '\''MayOwn first driver-side observer exited before identity proof'\''/ {
        identity_failure = NR; identity_failure_count++
    }
    /failed '\''MayOwn first driver-side observer exited before active custody'\''/ {
        service_failure = NR; service_failure_count++
    }
    END {
        valid = diagnostic_count == 2 && identity_failure_count == 1
        valid = valid && service_failure_count == 1
        valid = valid && diagnostic[1] < identity_failure
        valid = valid && identity_failure < diagnostic[2]
        valid = valid && diagnostic[2] < service_failure
        if (!valid) exit 1
    }
' "$gate"; then
    printf '%s\n' 'MayOwn observer death is not diagnosed before fail-closed exit' >&2
    exit 1
fi
may_own_driver_start_reporter_allowlist_mutant=$tmp/may-own-driver-reporter-allowlist-mutant
sed 's/production_start_failure_stage_is_safe/true/' \
    "$may_own_driver_start_reporter_contract" \
    >"$may_own_driver_start_reporter_allowlist_mutant"
may_own_driver_entry_reporter_allowlist_mutant=$tmp/may-own-driver-entry-reporter-allowlist-mutant
sed 's/may_own_driver_entry_failure_stage_is_safe/true/' \
    "$may_own_driver_start_reporter_contract" \
    >"$may_own_driver_entry_reporter_allowlist_mutant"
may_own_driver_entry_reporter_scope_mutant=$tmp/may-own-driver-entry-reporter-scope-mutant
sed 's/= preflight-runtime ]/= identity-publication ]/' \
    "$may_own_driver_start_reporter_contract" \
    >"$may_own_driver_entry_reporter_scope_mutant"
may_own_driver_start_reporter_exact_mutant=$tmp/may-own-driver-reporter-exact-mutant
sed 's/cmp -s -/cmp -n 0 -/' "$may_own_driver_start_reporter_contract" \
    >"$may_own_driver_start_reporter_exact_mutant"
may_own_driver_start_reporter_size_mutant=$tmp/may-own-driver-reporter-size-mutant
sed 's/-le 128/-le 1280/' "$may_own_driver_start_reporter_contract" \
    >"$may_own_driver_start_reporter_size_mutant"
may_own_driver_start_reporter_next_mutant=$tmp/may-own-driver-reporter-next-mutant
sed 's/start_failure_file\.next/start_failure_file.pending/g' \
    "$may_own_driver_start_reporter_contract" \
    >"$may_own_driver_start_reporter_next_mutant"
for may_own_driver_start_reporter_mutant in \
    "$may_own_driver_start_reporter_allowlist_mutant" \
    "$may_own_driver_entry_reporter_allowlist_mutant" \
    "$may_own_driver_entry_reporter_scope_mutant" \
    "$may_own_driver_start_reporter_exact_mutant" \
    "$may_own_driver_start_reporter_size_mutant" \
    "$may_own_driver_start_reporter_next_mutant"
do
    sh -n "$may_own_driver_start_reporter_mutant"
    if may_own_driver_start_reporter_contract_is_exact \
        "$may_own_driver_start_reporter_mutant"; then
        printf 'MayOwn driver-stage reporter accepted mutant: %s\n' \
            "${may_own_driver_start_reporter_mutant##*/}" >&2
        exit 1
    fi
done

vp_capture_file_is_safe() {
    [ "$#" -eq 1 ] || return 1
    [ -f "$1" ] && [ ! -L "$1" ] || return 1
    [ "$(stat -Lc '%u:%g:%a:%h' "$1" 2>/dev/null || true)" = \
        "$(id -u):$(id -g):600:1" ]
}
# shellcheck disable=SC1090
. "$may_own_driver_start_reporter"
may_own_driver_start_stage_root=$tmp/may-own-driver-start-stage
mkdir -m 0700 "$may_own_driver_start_stage_root"
mkdir -m 0700 "$may_own_driver_start_stage_root/may-own-output"
temporary_stage=$may_own_driver_start_stage_root
may_own_driver_start_stage_file=$temporary_stage/may-own-output/start.failure
may_own_driver_start_reporter_stdout=$tmp/may-own-driver-start-reporter.stdout
may_own_driver_start_reporter_stderr=$tmp/may-own-driver-start-reporter.stderr
printf '%s\n' \
    'VOLPAROSSA_HELPER_V3_IPC_START_FAILURE_STAGE_V1=identity-publication' \
    >"$may_own_driver_start_stage_file"
chmod 0600 "$may_own_driver_start_stage_file"
report_may_own_driver_start_failure_stage \
    >"$may_own_driver_start_reporter_stdout" \
    2>"$may_own_driver_start_reporter_stderr"
[ ! -s "$may_own_driver_start_reporter_stdout" ]
[ "$(cat "$may_own_driver_start_reporter_stderr")" = \
    'VOLPAROSSA_HELPER_LIVE_MAY_OWN_DRIVER_START_FAILURE_V1=identity-publication' ]
may_own_driver_entry_stage_file=$temporary_stage/may-own-output/may-own.driver-entry.failure
printf '%s\n' \
    'VOLPAROSSA_HELPER_V3_IPC_START_FAILURE_STAGE_V1=preflight-runtime' \
    >"$may_own_driver_start_stage_file"
printf '%s\n' \
    'VOLPAROSSA_HELPER_V3_MAY_OWN_DRIVER_ENTRY_FAILURE_V1=service-cgroup-members' \
    >"$may_own_driver_entry_stage_file"
chmod 0600 "$may_own_driver_entry_stage_file"
report_may_own_driver_start_failure_stage \
    >"$may_own_driver_start_reporter_stdout" \
    2>"$may_own_driver_start_reporter_stderr"
[ ! -s "$may_own_driver_start_reporter_stdout" ]
[ "$(cat "$may_own_driver_start_reporter_stderr")" = \
    "$(printf '%s\n%s' \
        'VOLPAROSSA_HELPER_LIVE_MAY_OWN_DRIVER_START_FAILURE_V1=preflight-runtime' \
        'VOLPAROSSA_HELPER_LIVE_MAY_OWN_DRIVER_ENTRY_FAILURE_V1=service-cgroup-members')" ]
for rejected_may_own_driver_entry_stage in private-detail unknown-stage; do
    printf 'VOLPAROSSA_HELPER_V3_MAY_OWN_DRIVER_ENTRY_FAILURE_V1=%s\n' \
        "$rejected_may_own_driver_entry_stage" \
        >"$may_own_driver_entry_stage_file"
    if report_may_own_driver_start_failure_stage \
        >"$may_own_driver_start_reporter_stdout" \
        2>"$may_own_driver_start_reporter_stderr"; then
        printf 'MayOwn reporter accepted unsafe entry stage: %s\n' \
            "$rejected_may_own_driver_entry_stage" >&2
        exit 1
    fi
    [ ! -s "$may_own_driver_start_reporter_stdout" ]
    [ ! -s "$may_own_driver_start_reporter_stderr" ]
done
printf '%s\n%s\n' \
    'VOLPAROSSA_HELPER_V3_MAY_OWN_DRIVER_ENTRY_FAILURE_V1=proc-records' \
    'VOLPAROSSA_HELPER_V3_MAY_OWN_DRIVER_ENTRY_FAILURE_V1=service-cgroup-members' \
    >"$may_own_driver_entry_stage_file"
if report_may_own_driver_start_failure_stage \
    >"$may_own_driver_start_reporter_stdout" \
    2>"$may_own_driver_start_reporter_stderr"; then
    printf '%s\n' 'MayOwn reporter accepted multiple entry stages' >&2
    exit 1
fi
chmod 0644 "$may_own_driver_entry_stage_file"
if report_may_own_driver_start_failure_stage \
    >"$may_own_driver_start_reporter_stdout" \
    2>"$may_own_driver_start_reporter_stderr"; then
    printf '%s\n' 'MayOwn reporter accepted unsafe entry metadata' >&2
    exit 1
fi
chmod 0600 "$may_own_driver_entry_stage_file"
printf '%s\n' \
    'VOLPAROSSA_HELPER_V3_MAY_OWN_DRIVER_ENTRY_FAILURE_V1=service-cgroup-members' \
    >"$may_own_driver_entry_stage_file"
: >"$may_own_driver_entry_stage_file.next"
chmod 0600 "$may_own_driver_entry_stage_file.next"
if report_may_own_driver_start_failure_stage \
    >"$may_own_driver_start_reporter_stdout" \
    2>"$may_own_driver_start_reporter_stderr"; then
    printf '%s\n' 'MayOwn reporter accepted a pending entry stage' >&2
    exit 1
fi
rm -f -- "$may_own_driver_entry_stage_file.next"
printf '%s\n' \
    'VOLPAROSSA_HELPER_V3_IPC_START_FAILURE_STAGE_V1=identity-publication' \
    >"$may_own_driver_start_stage_file"
if report_may_own_driver_start_failure_stage \
    >"$may_own_driver_start_reporter_stdout" \
    2>"$may_own_driver_start_reporter_stderr"; then
    printf '%s\n' 'MayOwn reporter accepted an out-of-scope entry stage' >&2
    exit 1
fi
rm -f -- "$may_own_driver_entry_stage_file"
for rejected_may_own_driver_start_stage in private-detail unknown-stage; do
    printf 'VOLPAROSSA_HELPER_V3_IPC_START_FAILURE_STAGE_V1=%s\n' \
        "$rejected_may_own_driver_start_stage" \
        >"$may_own_driver_start_stage_file"
    if report_may_own_driver_start_failure_stage \
        >"$may_own_driver_start_reporter_stdout" \
        2>"$may_own_driver_start_reporter_stderr"; then
        printf 'MayOwn reporter accepted unsafe stage: %s\n' \
            "$rejected_may_own_driver_start_stage" >&2
        exit 1
    fi
    [ ! -s "$may_own_driver_start_reporter_stdout" ]
    [ ! -s "$may_own_driver_start_reporter_stderr" ]
done
printf '%s\n%s\n' \
    'VOLPAROSSA_HELPER_V3_IPC_START_FAILURE_STAGE_V1=identity-socket' \
    'VOLPAROSSA_HELPER_V3_IPC_START_FAILURE_STAGE_V1=identity-publication' \
    >"$may_own_driver_start_stage_file"
if report_may_own_driver_start_failure_stage \
    >"$may_own_driver_start_reporter_stdout" \
    2>"$may_own_driver_start_reporter_stderr"; then
    printf '%s\n' 'MayOwn reporter accepted multiple stages' >&2
    exit 1
fi
chmod 0644 "$may_own_driver_start_stage_file"
if report_may_own_driver_start_failure_stage \
    >"$may_own_driver_start_reporter_stdout" \
    2>"$may_own_driver_start_reporter_stderr"; then
    printf '%s\n' 'MayOwn reporter accepted unsafe metadata' >&2
    exit 1
fi
chmod 0600 "$may_own_driver_start_stage_file"
rm -f -- "$may_own_driver_start_stage_file"
if report_may_own_driver_start_failure_stage \
    >"$may_own_driver_start_reporter_stdout" \
    2>"$may_own_driver_start_reporter_stderr"; then
    printf '%s\n' 'MayOwn reporter accepted a missing stage' >&2
    exit 1
fi

may_own_driver_entry_contract=$tmp/may-own-driver-entry-contract.sh
sed -n '/^may_own_driver_entry_contract_is_exact() {$/,/^}$/p' \
    "$hook" >"$may_own_driver_entry_contract"
sh -n "$may_own_driver_entry_contract"
may_own_driver_entry_categories='arguments unit-name gid main-pid service-cgroup-argument observer-pid proc-records process-credentials observer-cgroup-record observer-cgroup-length observer-cgroup-boundary manager-main-pid network-namespace control-pid service-cgroup-root service-cgroup-filesystem service-cgroup-type service-cgroup-stat service-cgroup-procs service-cgroup-members service-cgroup-stability'
may_own_driver_entry_mapping_is_exact() {
    [ "$#" -eq 1 ] || return 1
    awk '
        /^    may_own_driver_entry_failure_stage=[a-z]/ {
            stage[++stage_count] = $0
            stage_line[stage_count] = NR
        }
        /^    may_own_driver_entry_failure_stage=$/ {
            clear = NR; clear_count++
        }
        /\[ "\$#" -eq 4 \] \|\| return 1/ { predicate[1] = NR; count[1]++ }
        /unit_name_is_safe "\$hook_driver_unit" \|\| return 1/ { predicate[2] = NR; count[2]++ }
        /number_is_safe "\$hook_driver_gid" \|\| return 1/ { predicate[3] = NR; count[3]++ }
        /number_is_safe "\$hook_driver_main_pid" \|\| return 1/ { predicate[4] = NR; count[4]++ }
        /kernel_object_identity_is_safe/ && !predicate[5] { predicate[5] = NR; count[5]++ }
        /\[ "\$\$" != "\$hook_driver_main_pid" \] \|\| return 1/ { predicate[6] = NR; count[6]++ }
        /\[ -f "\$hook_driver_status" \]/ { predicate[7] = NR; count[7]++ }
        /\/usr\/bin\/awk -v expected_gid="\$hook_driver_gid"/ { predicate[8] = NR; count[8]++ }
        /hook_driver_cgroup=\$\(\/usr\/bin\/awk/ { predicate[9] = NR; count[9]++ }
        /\$\{#hook_driver_cgroup\}" -le 4096/ { predicate[10] = NR; count[10]++ }
        /^    case \$hook_driver_cgroup in$/ { predicate[11] = NR; count[11]++ }
        /unit_main_pid "\$hook_driver_unit"/ && !predicate[12] { predicate[12] = NR; count[12]++ }
        /hook_driver_network_identity=\$\(stat -Lc/ { predicate[13] = NR; count[13]++ }
        /org\.freedesktop\.systemd1\.Service ControlPID/ && !predicate[14] { predicate[14] = NR; count[14]++ }
        /\[ -d "\$hook_driver_service_cgroup" \]/ { predicate[15] = NR; count[15]++ }
        /stat -f -Lc '\''%T'\'' "\$hook_driver_service_cgroup"/ && !predicate[16] { predicate[16] = NR; count[16]++ }
        /hook_driver_service_cgroup_type=\$hook_driver_service_cgroup\/cgroup\.type/ { predicate[17] = NR; count[17]++ }
        /may_own_driver_cgroup_stat_is_exact/ && !predicate[18] { predicate[18] = NR; count[18]++ }
        /\[ -f "\$hook_driver_service_procs" \]/ { predicate[19] = NR; count[19]++ }
        /may_own_driver_cgroup_members_are_exact/ && !predicate[20] { predicate[20] = NR; count[20]++ }
        /hook_driver_service_cgroup_identity_after=\$\(stat -Lc/ { predicate[21] = NR; count[21]++ }
        END {
            expected[1] = "arguments"
            expected[2] = "unit-name"
            expected[3] = "gid"
            expected[4] = "main-pid"
            expected[5] = "service-cgroup-argument"
            expected[6] = "observer-pid"
            expected[7] = "proc-records"
            expected[8] = "process-credentials"
            expected[9] = "observer-cgroup-record"
            expected[10] = "observer-cgroup-length"
            expected[11] = "observer-cgroup-boundary"
            expected[12] = "manager-main-pid"
            expected[13] = "network-namespace"
            expected[14] = "control-pid"
            expected[15] = "service-cgroup-root"
            expected[16] = "service-cgroup-filesystem"
            expected[17] = "service-cgroup-type"
            expected[18] = "service-cgroup-stat"
            expected[19] = "service-cgroup-procs"
            expected[20] = "service-cgroup-members"
            expected[21] = "service-cgroup-stability"
            valid = stage_count == 21 && clear_count == 1
            for (i = 1; i <= 21; i++) {
                valid = valid && stage[i] == "    may_own_driver_entry_failure_stage=" expected[i]
                valid = valid && count[i] == 1
                valid = valid && stage_line[i] < predicate[i]
                if (i < 21) valid = valid && predicate[i] < stage_line[i + 1]
            }
            valid = valid && predicate[21] < clear
            if (!valid) exit 1
        }
    ' "$1"
}
may_own_driver_entry_mapping_is_exact "$may_own_driver_entry_contract" \
    || {
        printf '%s\n' 'MayOwn driver-entry diagnostic mapping is not exact' >&2
        exit 1
    }

may_own_cgroup_members_contract_is_exact() {
    [ "$#" -eq 1 ] || return 1
    [ "$(grep -Fc '[ -f "' "$1")" -eq 1 ] || return 1
    [ "$(grep -Fc '[ ! -L "' "$1")" -eq 1 ] || return 1
    [ "$(grep -Fc 'NR > 32 || $0 != expected_pid { invalid = 1 }' \
        "$1")" -eq 1 ] || return 1
    [ "$(grep -Fc \
        'END { if (invalid || NR < 1) exit 1 }' "$1")" -eq 1 ] \
        || return 1
}
may_own_cgroup_stat_contract_is_exact() {
    [ "$#" -eq 1 ] || return 1
    [ "$(grep -Fc '[ -f "' "$1")" -eq 1 ] || return 1
    [ "$(grep -Fc '[ ! -L "' "$1")" -eq 1 ] || return 1
    [ "$(grep -Fc 'NR > 256 { invalid = 1 }' "$1")" -eq 1 ] \
        || return 1
    [ "$(grep -Fc '$1 == "nr_descendants" {' "$1")" -eq 1 ] \
        || return 1
    [ "$(grep -Fc \
        'if (seen_descendants || NF != 2 || $2 != 0) invalid = 1' \
        "$1")" -eq 1 ] || return 1
    [ "$(grep -Fc 'seen_descendants = 1' "$1")" -eq 1 ] || return 1
    [ "$(grep -Fc '$1 == "nr_dying_descendants" {' "$1")" -eq 1 ] \
        || return 1
    [ "$(grep -Fc \
        'if (seen_dying || NF != 2 || $2 != 0) invalid = 1' \
        "$1")" -eq 1 ] || return 1
    [ "$(grep -Fc 'seen_dying = 1' "$1")" -eq 1 ] || return 1
    [ "$(grep -Fc \
        'if (invalid || !seen_descendants || !seen_dying) exit 1' \
        "$1")" -eq 1 ] || return 1
}
may_own_driver_members_contract=$tmp/may-own-driver-members-contract.sh
may_own_driver_stat_contract=$tmp/may-own-driver-stat-contract.sh
may_own_host_members_contract=$tmp/may-own-host-members-contract.sh
may_own_host_stat_contract=$tmp/may-own-host-stat-contract.sh
sed -n '/^may_own_driver_cgroup_members_are_exact() {$/,/^}$/p' \
    "$hook" >"$may_own_driver_members_contract"
sed -n '/^may_own_driver_cgroup_stat_is_exact() {$/,/^}$/p' \
    "$hook" >"$may_own_driver_stat_contract"
sed -n '/^may_own_cgroup_members_are_exact() {$/,/^}$/p' \
    "$gate" >"$may_own_host_members_contract"
sed -n '/^may_own_cgroup_stat_is_exact() {$/,/^}$/p' \
    "$gate" >"$may_own_host_stat_contract"
for may_own_members_contract in \
    "$may_own_driver_members_contract" "$may_own_host_members_contract"
do
    sh -n "$may_own_members_contract"
    may_own_cgroup_members_contract_is_exact "$may_own_members_contract" \
        || exit 1
done
for may_own_stat_contract in \
    "$may_own_driver_stat_contract" "$may_own_host_stat_contract"
do
    sh -n "$may_own_stat_contract"
    may_own_cgroup_stat_contract_is_exact "$may_own_stat_contract" || exit 1
done
may_own_members_predicate_mutant=$tmp/may-own-members-predicate-mutant.sh
sed 's/\$0 != expected_pid/\$0 == expected_pid/' \
    "$may_own_driver_members_contract" >"$may_own_members_predicate_mutant"
if may_own_cgroup_members_contract_is_exact \
    "$may_own_members_predicate_mutant"; then
    printf '%s\n' 'MayOwn cgroup members contract accepted predicate mutant' >&2
    exit 1
fi
may_own_stat_zero_mutant=$tmp/may-own-stat-zero-mutant.sh
sed '0,/\$2 != 0/s//\$2 != 1/' "$may_own_driver_stat_contract" \
    >"$may_own_stat_zero_mutant"
if may_own_cgroup_stat_contract_is_exact "$may_own_stat_zero_mutant"; then
    printf '%s\n' 'MayOwn cgroup stat contract accepted zero mutant' >&2
    exit 1
fi

may_own_private_cgroup_contract_is_exact() {
    [ "$#" -eq 1 ] || return 1
    may_own_private_cgroup_source=$1
    [ "$(grep -Fxc \
        '    hook_driver_service_cgroup=/sys/fs/cgroup' \
        "$may_own_private_cgroup_source")" -eq 1 ] || return 1
    [ "$(grep -Fc '/sys/fs/cgroup/system.slice' \
        "$may_own_private_cgroup_source")" -eq 0 ] || return 1
    [ "$(grep -Fc '/proc/1/root' "$may_own_private_cgroup_source")" -eq 0 ] \
        || return 1
    [ "$(grep -Fc \
        'hook_driver_service_cgroup_identity_before=$(stat -Lc' \
        "$may_own_private_cgroup_source")" -eq 1 ] || return 1
    [ "$(grep -Fc \
        'hook_driver_service_cgroup_identity_after=$(stat -Lc' \
        "$may_own_private_cgroup_source")" -eq 1 ] || return 1
    [ "$(grep -Fc '"$hook_driver_expected_cgroup_identity"' \
        "$may_own_private_cgroup_source")" -eq 3 ] || return 1
    [ "$(grep -Fc \
        'stat -f -Lc '\''%T'\'' "$hook_driver_service_cgroup"' \
        "$may_own_private_cgroup_source")" -eq 2 ] || return 1
    [ "$(grep -Fc '= cgroup2fs ]' \
        "$may_own_private_cgroup_source")" -eq 2 ] || return 1
    [ "$(grep -Fc \
        'hook_driver_service_cgroup_type=$hook_driver_service_cgroup/cgroup.type' \
        "$may_own_private_cgroup_source")" -eq 1 ] || return 1
    [ "$(grep -Fc 'cat "$hook_driver_service_cgroup_type"' \
        "$may_own_private_cgroup_source")" -eq 2 ] || return 1
    [ "$(grep -Fc '= domain ]' \
        "$may_own_private_cgroup_source")" -eq 2 ] || return 1
    [ "$(grep -Fc 'may_own_driver_cgroup_stat_is_exact' \
        "$may_own_private_cgroup_source")" -eq 2 ] || return 1
    [ "$(grep -Fc 'may_own_driver_cgroup_members_are_exact' \
        "$may_own_private_cgroup_source")" -eq 2 ] || return 1
    [ "$(grep -Fc \
        'hook_driver_service_procs_identity_before=$(stat -Lc' \
        "$may_own_private_cgroup_source")" -eq 1 ] || return 1
    [ "$(grep -Fc \
        'hook_driver_service_procs_identity_after=$(stat -Lc' \
        "$may_own_private_cgroup_source")" -eq 1 ] || return 1
    [ "$(grep -Fc 'unit_main_pid "$hook_driver_unit"' \
        "$may_own_private_cgroup_source")" -eq 2 ] || return 1
    [ "$(grep -Fc 'org.freedesktop.systemd1.Service ControlPID' \
        "$may_own_private_cgroup_source")" -eq 2 ] || return 1
}
may_own_private_cgroup_contract_is_exact "$may_own_driver_entry_contract" \
    || {
        printf '%s\n' 'MayOwn private cgroup root proof is not exact' >&2
        exit 1
    }
may_own_private_cgroup_root_mutant=$tmp/may-own-private-cgroup-root-mutant
sed 's@hook_driver_service_cgroup=/sys/fs/cgroup$@hook_driver_service_cgroup=/sys/fs/cgroup/system.slice/$hook_driver_unit@' \
    "$may_own_driver_entry_contract" >"$may_own_private_cgroup_root_mutant"
may_own_private_cgroup_member_mutant=$tmp/may-own-private-cgroup-member-mutant
sed '0,/may_own_driver_cgroup_members_are_exact/s//true/' \
    "$may_own_driver_entry_contract" >"$may_own_private_cgroup_member_mutant"
may_own_private_cgroup_filesystem_mutant=$tmp/may-own-private-cgroup-filesystem-mutant
sed '0,/cgroup2fs/s//tmpfs/' "$may_own_driver_entry_contract" \
    >"$may_own_private_cgroup_filesystem_mutant"
for may_own_private_cgroup_mutant in \
    "$may_own_private_cgroup_root_mutant" \
    "$may_own_private_cgroup_member_mutant" \
    "$may_own_private_cgroup_filesystem_mutant"
do
    sh -n "$may_own_private_cgroup_mutant"
    if may_own_private_cgroup_contract_is_exact \
        "$may_own_private_cgroup_mutant"; then
        printf 'MayOwn private cgroup contract accepted mutant: %s\n' \
            "${may_own_private_cgroup_mutant##*/}" >&2
        exit 1
    fi
done

may_own_host_cgroup_contract=$tmp/may-own-host-cgroup-contract.sh
sed -n '/^may_own_host_service_cgroup_identity() {$/,/^}$/p' \
    "$gate" >"$may_own_host_cgroup_contract"
may_own_host_cgroup_contract_is_exact() {
    [ "$#" -eq 1 ] || return 1
    may_own_host_cgroup_source=$1
    [ "$(grep -Fc \
        'may_own_host_cgroup_path=/sys/fs/cgroup/system.slice/$unit_name' \
        "$may_own_host_cgroup_source")" -eq 1 ] || return 1
    [ "$(grep -Fc '/proc/1/root' "$may_own_host_cgroup_source")" -eq 0 ] \
        || return 1
    [ "$(grep -Fc 'systemctl show --property=ControlGroup' \
        "$may_own_host_cgroup_source")" -eq 2 ] || return 1
    [ "$(grep -Fc \
        'may_own_host_cgroup_identity_before=$(stat -Lc' \
        "$may_own_host_cgroup_source")" -eq 1 ] || return 1
    [ "$(grep -Fc \
        'may_own_host_cgroup_identity_after=$(stat -Lc' \
        "$may_own_host_cgroup_source")" -eq 1 ] || return 1
    [ "$(grep -Fc 'stat -f -Lc '\''%T'\''' \
        "$may_own_host_cgroup_source")" -eq 1 ] || return 1
    [ "$(grep -Fc '/cgroup.type' \
        "$may_own_host_cgroup_source")" -eq 3 ] || return 1
    [ "$(grep -Fc '= domain ]' \
        "$may_own_host_cgroup_source")" -eq 1 ] || return 1
    [ "$(grep -Fc 'may_own_cgroup_stat_is_exact' \
        "$may_own_host_cgroup_source")" -eq 1 ] || return 1
    [ "$(grep -Fc 'may_own_cgroup_members_are_exact' \
        "$may_own_host_cgroup_source")" -eq 2 ] || return 1
    [ "$(grep -Fc '[ -f "$may_own_host_cgroup_procs" ]' \
        "$may_own_host_cgroup_source")" -eq 1 ] || return 1
    [ "$(grep -Fc '[ ! -L "$may_own_host_cgroup_procs" ]' \
        "$may_own_host_cgroup_source")" -eq 1 ] || return 1
    [ "$(grep -Fc \
        'may_own_host_cgroup_procs_identity_before=$(stat -Lc' \
        "$may_own_host_cgroup_source")" -eq 1 ] || return 1
    [ "$(grep -Fc \
        'may_own_host_cgroup_procs_identity_after=$(stat -Lc' \
        "$may_own_host_cgroup_source")" -eq 1 ] || return 1
    [ "$(grep -Fc 'systemctl show --property=MainPID' \
        "$may_own_host_cgroup_source")" -eq 1 ] || return 1
    [ "$(grep -Fc 'systemctl show --property=ControlPID' \
        "$may_own_host_cgroup_source")" -eq 1 ] || return 1
    [ "$(grep -Fc 'unit_current_invocation_id' \
        "$may_own_host_cgroup_source")" -eq 1 ] || return 1
    tail -n 2 "$may_own_host_cgroup_source" \
        | grep -F 'printf '\''%s\n'\'' "$may_own_host_cgroup_identity_after"' \
        >/dev/null || return 1
}
may_own_host_cgroup_contract_is_exact "$may_own_host_cgroup_contract" \
    || {
        printf '%s\n' 'MayOwn outer host cgroup proof is not exact' >&2
        exit 1
    }
may_own_host_cgroup_member_mutant=$tmp/may-own-host-cgroup-member-mutant
sed '0,/may_own_cgroup_members_are_exact/s//true/' \
    "$may_own_host_cgroup_contract" >"$may_own_host_cgroup_member_mutant"
may_own_host_cgroup_path_mutant=$tmp/may-own-host-cgroup-path-mutant
sed 's@/sys/fs/cgroup/system.slice@/proc/1/root/sys/fs/cgroup/system.slice@' \
    "$may_own_host_cgroup_contract" >"$may_own_host_cgroup_path_mutant"
for may_own_host_cgroup_mutant in \
    "$may_own_host_cgroup_member_mutant" "$may_own_host_cgroup_path_mutant"
do
    sh -n "$may_own_host_cgroup_mutant"
    if may_own_host_cgroup_contract_is_exact \
        "$may_own_host_cgroup_mutant"; then
        printf 'MayOwn host cgroup contract accepted mutant: %s\n' \
            "${may_own_host_cgroup_mutant##*/}" >&2
        exit 1
    fi
done

may_own_driver_launch_contract=$tmp/may-own-driver-launch-contract.sh
sed -n '/^start_may_own_driver_observer() {$/,/^}$/p' \
    "$gate" >"$may_own_driver_launch_contract"
if ! awk '
    /may_own_driver_cgroup_identity=\$\(may_own_host_service_cgroup_identity/ {
        capture = NR; capture_count++
    }
    /may_own_kernel_object_identity_is_safe/ {
        validation = NR; validation_count++
    }
    /\/usr\/bin\/nsenter --mount=/ { nsenter_line = NR; nsenter_count++ }
    /--net=.* -- \\/ { net = NR; net_count++ }
    /\/run\/volparossa-helper-production-ipc-hook may-own-driver-start/ {
        hook_line = NR; hook_count++
    }
    /"\$may_own_driver_cgroup_identity" \\/ {
        handoff = NR; handoff_count++
    }
    /--cgroup/ { forbidden_cgroup_namespace++ }
    /\/proc\/1\/root/ { forbidden_host_root++ }
    END {
        valid = capture_count == 1 && validation_count == 1
        valid = valid && nsenter_count == 1 && net_count == 1
        valid = valid && hook_count == 1 && handoff_count == 1
        valid = valid && forbidden_cgroup_namespace == 0
        valid = valid && forbidden_host_root == 0
        valid = valid && capture < validation && validation < nsenter_line
        valid = valid && nsenter_line < net && net < hook_line
        valid = valid && hook_line < handoff
        if (!valid) exit 1
    }
' "$may_own_driver_launch_contract"; then
    printf '%s\n' 'MayOwn driver cgroup identity handoff is not exact' >&2
    exit 1
fi
if ! awk '
    /start_may_own_driver_observer one/ { outer_before = NR; before_count++ }
    /while ! vp_capture_file_is_safe .*may-own-output\/unit.identity/ {
        identity_wait = NR; wait_count++
    }
    /may_own_service_shape_is_exact "\$may_own_pid_one"/ {
        outer_after = NR; after_count++
    }
    END {
        valid = before_count == 1 && wait_count == 1 && after_count == 1
        valid = valid && outer_before < identity_wait
        valid = valid && identity_wait < outer_after
        if (!valid) exit 1
    }
' "$gate"; then
    printf '%s\n' 'MayOwn cgroup proof is not bracketed around first identity' >&2
    exit 1
fi

may_own_first_active_wait=$tmp/may-own-first-active-wait.sh
sed -n '/^    may_own_first_boundary=\$temporary_stage/,/^    vp_capture_run "\$may_own_first_driver_release"/p' \
    "$gate" | sed '$d' >"$may_own_first_active_wait"
sh -n "$may_own_first_active_wait"
may_own_first_active_wait_is_exact() {
    [ "$#" -eq 1 ] || return 1
    may_own_first_active_source=$1
    [ "$(grep -Fc \
        'may_own_preexec_barrier_failure_stage=shape-active-boundary' \
        "$may_own_first_active_source")" -eq 1 ] || return 1
    [ "$(grep -Fc \
        'while ! vp_capture_file_is_safe "$may_own_first_boundary"; do' \
        "$may_own_first_active_source")" -eq 1 ] || return 1
    [ "$(grep -Fc '[ -e "$may_own_first_boundary" ]' \
        "$may_own_first_active_source")" -eq 1 ] || return 1
    [ "$(grep -Fc '[ -L "$may_own_first_boundary" ]; then' \
        "$may_own_first_active_source")" -eq 1 ] || return 1
    [ "$(grep -Fc 'report_may_own_preexec_barrier_failure_stage' \
        "$may_own_first_active_source")" -eq 3 ] || return 1
    [ "$(grep -Fc 'capture_process_starttime "$may_own_driver_observer_pid"' \
        "$may_own_first_active_source")" -eq 1 ] || return 1
    [ "$(grep -Fc '"$may_own_driver_observer_starttime"' \
        "$may_own_first_active_source")" -eq 1 ] || return 1
    [ "$(grep -Fc 'capture_process_starttime "$may_own_debugger_pid"' \
        "$may_own_first_active_source")" -eq 1 ] || return 1
    [ "$(grep -Fc '"$may_own_debugger_starttime"' \
        "$may_own_first_active_source")" -eq 1 ] || return 1
    [ "$(grep -Fc 'unit_current_invocation_id' \
        "$may_own_first_active_source")" -eq 1 ] || return 1
    [ "$(grep -Fc 'capture_process_starttime "$may_own_pid_one"' \
        "$may_own_first_active_source")" -eq 1 ] || return 1
    [ "$(grep -Fc '"$may_own_wait" -ge 600' \
        "$may_own_first_active_source")" -eq 1 ] || return 1
    [ "$(grep -Fc \
        'may_own_worker_one=$(sed -n '\''8p'\'' "$may_own_first_boundary")' \
        "$may_own_first_active_source")" -eq 1 ] || return 1
    [ "$(grep -Fc \
        'may_own_worker_one_starttime=$(sed -n '\''9p'\'' "$may_own_first_boundary")' \
        "$may_own_first_active_source")" -eq 1 ] || return 1
    [ "$(grep -Fc '0 2 active-custody \' \
        "$may_own_first_active_source")" -eq 1 ] || return 1
    [ "$(grep -Fc '"$may_own_driver_cgroup_identity" "$may_own_first_boundary"; then' \
        "$may_own_first_active_source")" -eq 1 ] || return 1
    awk '
        /may_own_wait=\$\(\(may_own_wait \+ 1\)\)/ {
            increment = NR
            increment_count++
        }
        /"\$may_own_wait" -ge 600/ {
            bound = NR
            bound_count++
        }
        /may_own_worker_one=\$\(sed -n/ {
            worker = NR
            worker_count++
        }
        /may_own_service_shape_is_exact "\$may_own_pid_one"/ {
            shape = NR
            shape_count++
        }
        /^[[:space:]]*sleep 0\.05$/ {
            sleep_line = NR
            sleep_count++
        }
        END {
            valid = increment_count == 1 && bound_count == 1
            valid = valid && worker_count == 1 && shape_count == 1
            valid = valid && sleep_count == 1
            valid = valid && increment < bound && bound < sleep_line
            valid = valid && sleep_line < worker && worker < shape
            if (!valid) exit 1
        }
    ' "$may_own_first_active_source" || return 1
}
may_own_first_active_wait_is_exact "$may_own_first_active_wait" \
    || {
        printf '%s\n' 'MayOwn first active-custody wait is not exact' >&2
        exit 1
    }
may_own_first_active_stage_mutant=$tmp/may-own-first-active-stage-mutant.sh
sed 's/=shape-active-boundary/=shape-cgroup-members/' \
    "$may_own_first_active_wait" >"$may_own_first_active_stage_mutant"
may_own_first_active_mode_mutant=$tmp/may-own-first-active-mode-mutant.sh
sed 's/0 2 active-custody/0 2 main-only/' \
    "$may_own_first_active_wait" >"$may_own_first_active_mode_mutant"
may_own_first_active_worker_mutant=$tmp/may-own-first-active-worker-mutant.sh
sed "s/sed -n '8p'/sed -n '10p'/" \
    "$may_own_first_active_wait" >"$may_own_first_active_worker_mutant"
may_own_first_active_observer_identity_mutant=$tmp/may-own-first-active-observer-identity-mutant.sh
sed 's/"$may_own_driver_observer_starttime"/"$may_own_debugger_starttime"/' \
    "$may_own_first_active_wait" >"$may_own_first_active_observer_identity_mutant"
may_own_first_active_debugger_identity_mutant=$tmp/may-own-first-active-debugger-identity-mutant.sh
sed 's/"$may_own_debugger_starttime"/"$may_own_driver_observer_starttime"/' \
    "$may_own_first_active_wait" >"$may_own_first_active_debugger_identity_mutant"
for may_own_first_active_mutant in \
    "$may_own_first_active_stage_mutant" \
    "$may_own_first_active_mode_mutant" \
    "$may_own_first_active_worker_mutant" \
    "$may_own_first_active_observer_identity_mutant" \
    "$may_own_first_active_debugger_identity_mutant"
do
    sh -n "$may_own_first_active_mutant"
    if may_own_first_active_wait_is_exact "$may_own_first_active_mutant"; then
        printf 'MayOwn first active wait accepted mutant: %s\n' \
            "${may_own_first_active_mutant##*/}" >&2
        exit 1
    fi
done

may_own_driver_entry_stage_functions=$tmp/may-own-driver-entry-stage-functions.sh
sed -n '/^may_own_driver_entry_failure_stage_is_safe() {$/,/^}$/p' \
    "$hook" >"$may_own_driver_entry_stage_functions"
sh -n "$may_own_driver_entry_stage_functions"
# shellcheck disable=SC1090
. "$may_own_driver_entry_stage_functions"
for may_own_driver_entry_category in $may_own_driver_entry_categories; do
    may_own_driver_entry_failure_stage_is_safe \
        "$may_own_driver_entry_category" || exit 1
done
for unsafe_may_own_driver_entry_category in \
    '' private-detail /tmp/value 'service-cgroup-members value'
do
    if may_own_driver_entry_failure_stage_is_safe \
        "$unsafe_may_own_driver_entry_category"; then
        printf 'MayOwn driver-entry allowlist accepted unsafe category: %s\n' \
            "$unsafe_may_own_driver_entry_category" >&2
        exit 1
    fi
done

may_own_driver_entry_mutation_index=0
for may_own_driver_entry_category in $may_own_driver_entry_categories; do
    may_own_driver_entry_mutation_index=$((may_own_driver_entry_mutation_index + 1))
    may_own_driver_entry_mutant=$tmp/may-own-driver-entry-mutant.$may_own_driver_entry_mutation_index
    sed "s/may_own_driver_entry_failure_stage=$may_own_driver_entry_category$/may_own_driver_entry_failure_stage=private-detail/" \
        "$may_own_driver_entry_contract" >"$may_own_driver_entry_mutant"
    sh -n "$may_own_driver_entry_mutant"
    if may_own_driver_entry_mapping_is_exact "$may_own_driver_entry_mutant"; then
        printf 'MayOwn driver-entry mapping accepted mutant: %s\n' \
            "$may_own_driver_entry_category" >&2
        exit 1
    fi
done
may_own_driver_entry_predicate_mutant=$tmp/may-own-driver-entry-predicate-mutant
sed 's/unit_main_pid "\$hook_driver_unit"/unit_removed_main_pid "\$hook_driver_unit"/' \
    "$may_own_driver_entry_contract" >"$may_own_driver_entry_predicate_mutant"
if may_own_driver_entry_mapping_is_exact \
    "$may_own_driver_entry_predicate_mutant"; then
    printf '%s\n' 'MayOwn driver-entry mapping accepted a missing predicate' >&2
    exit 1
fi
may_own_driver_entry_clear_mutant=$tmp/may-own-driver-entry-clear-mutant
sed 's/^    may_own_driver_entry_failure_stage=$/    :/' \
    "$may_own_driver_entry_contract" >"$may_own_driver_entry_clear_mutant"
if may_own_driver_entry_mapping_is_exact "$may_own_driver_entry_clear_mutant"; then
    printf '%s\n' 'MayOwn driver-entry mapping accepted a retained success stage' >&2
    exit 1
fi

may_own_driver_entry_publisher_contract=$tmp/may-own-driver-entry-publisher-contract.sh
sed -n '/^publish_may_own_driver_entry_failure() {$/,/^}$/p' \
    "$hook" >"$may_own_driver_entry_publisher_contract"
may_own_driver_entry_publisher_contract_is_exact() {
    [ "$#" -eq 1 ] || return 1
    awk '
        /\[ "\$may_own_driver_observer_mode" = yes \] \|\| return 1/ { observer = NR; observer_count++ }
        /\[ "\$start_failure_armed" = yes \] \|\| return 1/ { armed = NR; armed_count++ }
        /\[ "\$start_failure_stage" = preflight-runtime \] \|\| return 1/ { scope = NR; scope_count++ }
        /may_own_driver_entry_failure_stage_is_safe/ { allowlist = NR; allowlist_count++ }
        /write_private_file "\$may_own_driver_entry_failure_record"/ { writer = NR; writer_count++ }
        /VOLPAROSSA_HELPER_V3_MAY_OWN_DRIVER_ENTRY_FAILURE_V1=\$may_own_driver_entry_failure_stage/ { payload = NR; payload_count++ }
        END {
            valid = observer_count == 1 && armed_count == 1
            valid = valid && scope_count == 1 && allowlist_count == 1
            valid = valid && writer_count == 1 && payload_count == 1
            valid = valid && observer < armed && armed < scope
            valid = valid && scope < allowlist && allowlist < writer
            valid = valid && writer < payload
            if (!valid) exit 1
        }
    ' "$1"
}
may_own_driver_entry_publisher_contract_is_exact \
    "$may_own_driver_entry_publisher_contract" || exit 1
may_own_driver_entry_publisher_scope_mutant=$tmp/may-own-driver-entry-publisher-scope-mutant
sed 's/= preflight-runtime ]/= identity-publication ]/' \
    "$may_own_driver_entry_publisher_contract" \
    >"$may_own_driver_entry_publisher_scope_mutant"
may_own_driver_entry_publisher_allowlist_mutant=$tmp/may-own-driver-entry-publisher-allowlist-mutant
sed 's/may_own_driver_entry_failure_stage_is_safe/true/' \
    "$may_own_driver_entry_publisher_contract" \
    >"$may_own_driver_entry_publisher_allowlist_mutant"
may_own_driver_entry_publisher_writer_mutant=$tmp/may-own-driver-entry-publisher-writer-mutant
sed 's/write_private_file/printf/' "$may_own_driver_entry_publisher_contract" \
    >"$may_own_driver_entry_publisher_writer_mutant"
for may_own_driver_entry_publisher_mutant in \
    "$may_own_driver_entry_publisher_scope_mutant" \
    "$may_own_driver_entry_publisher_allowlist_mutant" \
    "$may_own_driver_entry_publisher_writer_mutant"
do
    sh -n "$may_own_driver_entry_publisher_mutant"
    if may_own_driver_entry_publisher_contract_is_exact \
        "$may_own_driver_entry_publisher_mutant"; then
        printf 'MayOwn driver-entry publisher accepted mutant: %s\n' \
            "${may_own_driver_entry_publisher_mutant##*/}" >&2
        exit 1
    fi
done

may_own_driver_entry_publisher=$tmp/may-own-driver-entry-publisher.sh
{
    cat "$may_own_driver_entry_stage_functions"
    cat "$may_own_driver_entry_publisher_contract"
} >"$may_own_driver_entry_publisher"
write_private_file() {
    [ "$#" -eq 2 ] || return 1
    published_may_own_driver_entry_path=$1
    published_may_own_driver_entry_payload=$2
}
# shellcheck disable=SC1090
. "$may_own_driver_entry_publisher"
# shellcheck disable=SC2034
may_own_driver_observer_mode=yes
# shellcheck disable=SC2034
start_failure_armed=yes
start_failure_stage=preflight-runtime
may_own_driver_entry_failure_stage=service-cgroup-members
may_own_driver_entry_failure_record=$tmp/may-own.driver-entry.failure
published_may_own_driver_entry_path=
published_may_own_driver_entry_payload=
publish_may_own_driver_entry_failure
[ "$published_may_own_driver_entry_path" = \
    "$may_own_driver_entry_failure_record" ]
[ "$published_may_own_driver_entry_payload" = \
    'VOLPAROSSA_HELPER_V3_MAY_OWN_DRIVER_ENTRY_FAILURE_V1=service-cgroup-members' ]
for rejected_may_own_driver_entry_category in '' private-detail unknown-stage; do
    may_own_driver_entry_failure_stage=$rejected_may_own_driver_entry_category
    if publish_may_own_driver_entry_failure; then
        printf 'MayOwn driver-entry publisher accepted unsafe stage: %s\n' \
            "$rejected_may_own_driver_entry_category" >&2
        exit 1
    fi
done
# shellcheck disable=SC2034
may_own_driver_entry_failure_stage=service-cgroup-members
# shellcheck disable=SC2034
start_failure_stage=identity-publication
if publish_may_own_driver_entry_failure; then
    printf '%s\n' 'MayOwn driver-entry publisher accepted an unsafe scope' >&2
    exit 1
fi

if ! awk '
    /if ! may_own_driver_entry_contract_is_exact/ { contract = NR; contract_count++ }
    /publish_may_own_driver_entry_failure \|\| :/ { publish = NR; publish_count++ }
    /fail '\''MayOwn driver observer boundary is not exact'\''/ { failure = NR; failure_count++ }
    END {
        valid = contract_count == 1 && publish_count == 1 && failure_count == 1
        valid = valid && contract < publish && publish < failure
        if (!valid) exit 1
    }
' "$hook"; then
    printf '%s\n' 'MayOwn driver-entry failure is not safely published before exit' >&2
    exit 1
fi

may_own_start_hook_contract=$tmp/may-own-start-hook-contract.sh
sed -n '/^may_own_start_hook() {$/,/^}$/p' \
    "$hook" >"$may_own_start_hook_contract"
sh -n "$may_own_start_hook_contract"
may_own_launcher_mode_contract_is_exact() {
    [ "$#" -eq 1 ] || return 1
    awk '
        /if \[ ! -e "\$may_own_first_boundary_record" \]/ {
            first = NR; first_count++
        }
        /^        restart_launcher_identity_mode=yes$/ {
            launcher = NR; launcher_count++
        }
        /^        restart_exact_present_mode=yes$/ {
            restart_flow_count++
        }
        /^        may_own_relay_mode=yes$/ { relay = NR; relay_count++ }
        /^        start_hook "\$1" "\$2" "\$3" "\$4" "\$5" "\$6"$/ {
            start = NR; start_count++
        }
        END {
            valid = first_count == 1 && launcher_count == 1
            valid = valid && restart_flow_count == 0
            valid = valid && relay_count == 1 && start_count == 1
            valid = valid && first < launcher && launcher < relay && relay < start
            if (!valid) exit 1
        }
    ' "$1"
}
may_own_launcher_mode_contract_is_exact "$may_own_start_hook_contract" \
    || {
        printf '%s\n' 'MayOwn first launch is not bound to the restart launcher' >&2
        exit 1
    }
may_own_launcher_mode_mutant=$tmp/may-own-launcher-mode-mutant.sh
sed '/^        restart_launcher_identity_mode=yes$/d' \
    "$may_own_start_hook_contract" >"$may_own_launcher_mode_mutant"
sh -n "$may_own_launcher_mode_mutant"
if may_own_launcher_mode_contract_is_exact "$may_own_launcher_mode_mutant"; then
    printf '%s\n' 'MayOwn launcher-mode contract accepted a missing binding' >&2
    exit 1
fi

# The debugger publishes its armed record only after the third durable-custody publication. The
# Client, Exit and Relay functional cycles must therefore start without waiting on that future
# record; otherwise the observer and debugger form a circular handshake before Relay custody.
start_hook_contract=$tmp/start-hook-contract.sh
sed -n '/^start_hook() {$/,/^}$/p' "$hook" >"$start_hook_contract"
may_own_functional_cycle_order_is_exact() {
    [ "$#" -eq 1 ] || return 1
    awk '
        /run_probe bind-after bind-runtime/ {
            bind_after = NR
            bind_after_count++
        }
        /^    case \$may_own_relay_mode in$/ {
            mode = NR
            mode_count++
        }
        /^        yes\|no\) ;;$/ {
            accepted = NR
            accepted_count++
        }
        /\*\) fail '\''MayOwn mode is invalid'\'' ;;$/ {
            rejected = NR
            rejected_count++
        }
        /may_own_debugger_armed_record/ { armed_record_count++ }
        /^    advance_start_failure_stage functional-underlay/ {
            functional_stage = NR
            functional_stage_count++
        }
        /^    run_functional_client_lease_probe/ {
            functional_probe = NR
            functional_probe_count++
        }
        END {
            valid = bind_after_count == 1 && mode_count == 1
            valid = valid && accepted_count == 1 && rejected_count == 1
            valid = valid && armed_record_count == 0
            valid = valid && functional_stage_count == 1
            valid = valid && functional_probe_count == 1
            valid = valid && bind_after < mode && mode < accepted
            valid = valid && accepted < rejected && rejected < functional_stage
            valid = valid && functional_stage < functional_probe
            if (!valid) exit 1
        }
    ' "$1"
}
may_own_functional_cycle_order_is_exact "$start_hook_contract" || {
    printf '%s\n' 'MayOwn functional cycles are not free of a future debugger-marker wait' >&2
    exit 1
}
start_hook_armed_wait_mutant=$tmp/start-hook-armed-wait-mutant.sh
sed 's/^    advance_start_failure_stage functional-underlay/    test -f "$may_own_debugger_armed_record"\
&/' "$start_hook_contract" >"$start_hook_armed_wait_mutant"
sh -n "$start_hook_armed_wait_mutant"
if may_own_functional_cycle_order_is_exact "$start_hook_armed_wait_mutant"; then
    printf '%s\n' 'MayOwn functional-cycle contract accepted a future-marker wait' >&2
    exit 1
fi

observer_preexec_contract=$tmp/observer-preexec-contract
sed -n '/^[[:space:]]*pre-exec-one|pre-exec-two|pre-exec-three)/,/^[[:space:]]*;;$/p' \
    "$observer" >"$observer_preexec_contract"
grep -F 'VOLPAROSSA_HELPER_MAY_OWN_PRE_EXEC_OBSERVER_V1=ready' \
    "$observer_preexec_contract" >/dev/null
grep -F 'while [ ! -f "$release_record" ]; do' \
    "$observer_preexec_contract" >/dev/null

# systemctl v257 renders ExecMainCode numerically. Both SIGKILL fences require
# Linux CLD_KILLED == 2; symbolic "killed", deletion, or either one-sided
# mutation must be rejected by this source contract.
may_own_exec_code_contract_is_exact() {
    [ "$#" -eq 1 ] || return 1
    may_own_exec_code_source=$1
    [ "$(grep -Fc 'ExecMainCode --value "$unit_name")" != 2 ]' \
        "$may_own_exec_code_source")" -eq 2 ] \
        && [ "$(grep -Fc 'ExecMainCode --value "$unit_name")" != killed ]' \
            "$may_own_exec_code_source")" -eq 0 ]
}
may_own_exec_code_contract_is_exact "$gate" || exit 1
for mutated_fence in 1 2; do
    exec_code_mutant=$tmp/exec-code-$mutated_fence
    awk -v target="$mutated_fence" '
        {
            if (index($0, "ExecMainCode --value \"$unit_name\")\" != 2 ]")) {
                seen++
                if (seen == target) sub(/!= 2 \]/, "!= killed ]")
            }
            print
        }
    ' "$gate" >"$exec_code_mutant"
    if may_own_exec_code_contract_is_exact "$exec_code_mutant"; then
        printf 'MayOwn ExecMainCode contract accepted fence %s mutation\n' \
            "$mutated_fence" >&2
        exit 1
    fi
done

# Freezing is used only at the two non-empty crash frames. Each old cgroup is
# thawed (or already removed) while MainPID and NRestarts still describe the
# failed invocation, before the driver begins waiting for the successor. No
# successor-side thaw may act as its start gate.
first_thaw=$(grep -n 'thaw_may_own_crash_boundary_before_restart 0' "$gate" \
    | cut -d: -f1)
second_phase=$(grep -n 'driver_phase=may-own-second-crash' "$gate" | cut -d: -f1)
second_thaw=$(grep -n 'thaw_may_own_crash_boundary_before_restart 1' "$gate" \
    | cut -d: -f1)
third_phase=$(grep -n 'driver_phase=may-own-recovery' "$gate" | cut -d: -f1)
[ "$first_thaw" -lt "$second_phase" ] && [ "$second_thaw" -lt "$third_phase" ]
successor_segment=$tmp/successor-segment
sed -n '/^    driver_phase=may-own-second-crash$/,/^    driver_phase=may-own-retirement$/p' \
    "$gate" >"$successor_segment"
if grep -F '0 >"$may_own_cgroup/cgroup.freeze"' "$successor_segment" >/dev/null; then
    printf '%s\n' 'MayOwn successor still uses the freezer as its release gate' >&2
    exit 1
fi

# Every boundary derives one canonical custody name from two stable manager
# snapshots, preserves count 2 through the crashes, then proves stable empty
# FDStore and a RecoveredMayOwn settled journal before accepting a new socket.
grep -F 'hook_may_own_custody=$(unit_fdstore_single_custody "$hook_may_own_unit")' \
    "$hook" >/dev/null
grep -F '[ "$hook_fdstore_count_before:$hook_fdstore_count_after" = 2:2 ] \' \
    "$hook" >/dev/null
for mode in \
    prove-restart-may-own-relay \
    prove-restart-may-own-relay-cleanup-confirmed \
    prove-restart-may-own-relay-settled
do
    grep -F '"$probe" '"$mode" "$hook" >/dev/null
done
grep -F "fail 'MayOwn successor published a socket before the second crash'" \
    "$hook" >/dev/null
grep -F 'while ! private_file_is_safe "$may_own_third_boundary_record"; do' \
    "$hook" >/dev/null
grep -F 'may_own_socket_is_absent_or_initial \' "$hook" >/dev/null
grep -F "fail 'MayOwn socket changed before restart settlement'" "$hook" >/dev/null
grep -F "fail 'MayOwn third invocation published a socket before removal'" \
    "$hook" >/dev/null
grep -F 'unit_fdstore_is_empty "$hook_may_own_unit" \' "$hook" >/dev/null
grep -F "'VOLPAROSSA_HELPER_V3_RESTART_MAY_OWN_RELAY_SETTLED_V1=pass'" \
    "$hook" >/dev/null

# EXIT cleanup is starttime- and exact-cgroup-bound. Successful retirement also
# proves lock release, socket/.next absence, not-found collection and final journal.
cleanup_contract=$tmp/cleanup-contract
sed -n '/^cleanup() {$/,/restart_successor_debugger_pid/p' "$gate" \
    >"$cleanup_contract"
for cleanup_pattern in \
    'capture_process_starttime "$may_own_preexec_observer_pid"' \
    'kill "$may_own_preexec_observer_pid"' \
    'wait "$may_own_preexec_observer_pid"' \
    '"$may_own_preexec_observer_record_pid" 2>/dev/null || true)' \
    'kill "$may_own_preexec_observer_record_pid"' \
    'capture_process_starttime "$may_own_driver_observer_pid"' \
    'kill "$may_own_driver_observer_pid"' \
    'wait "$may_own_driver_observer_pid"' \
    'capture_process_starttime "$may_own_debugger_pid"' \
    'kill "$may_own_debugger_pid"' \
    'wait "$may_own_debugger_pid"' \
    'capture_process_starttime "$may_own_mount_keeper_pid"' \
    'kill "$may_own_mount_keeper_pid"' \
    'wait "$may_own_mount_keeper_pid"' \
    '[ "$may_own_cgroup" = "/sys/fs/cgroup/system.slice/$unit_name" ] \' \
    '0 >"$may_own_cgroup/cgroup.freeze"'
do
    grep -F "$cleanup_pattern" "$cleanup_contract" >/dev/null
done
grep -F "/usr/bin/flock -n 9 || failed 'MayOwn journal lock remained held'" \
    "$gate" >/dev/null
grep -F "failed 'MayOwn runtime did not retire cleanly'" "$gate" >/dev/null
grep -F '[ "$may_own_retired_load_state" = not-found ] \' "$gate" >/dev/null
grep -F 'prove-restart-may-own-relay-settled "$may_own_pid_three" \' \
    "$gate" >/dev/null

# The guest consumes three canonical JSONL values. Only retained-main installs
# this report/hash/environment; branch smoke mode proves its output is empty.
grep -F 'test "$(wc -l </home/volparossa/helper-proof-reports.jsonl)" -eq 3' \
    "$runner" >/dev/null
grep -F "sed -n '3p' /home/volparossa/helper-proof-reports.jsonl \\" \
    "$runner" >/dev/null
grep -F '>/home/volparossa/helper-restart-may-own-custody-relay-evidence-v1.json' \
    "$runner" >/dev/null
retention_contract=$tmp/retention-contract
sed -n '/if \[ "$proof_mode" = retained-main \]; then/,/non-retained helper-boundary PR smoke completed/p' \
    "$runner" >"$retention_contract"
for retained_name in \
    helper-restart-may-own-custody-relay-evidence-v1.json \
    helper-restart-may-own-custody-relay-evidence-v1.json.sha256 \
    helper-restart-may-own-custody-relay-vm-environment-v1.json
do
    grep -F '"$output_directory/'"$retained_name"'"' \
        "$retention_contract" >/dev/null
done
grep -F 'find "$output_directory" -mindepth 1 -maxdepth 1 -print -quit' \
    "$retention_contract" >/dev/null
grep -F "failed 'the non-retained PR smoke output directory is not empty'" \
    "$retention_contract" >/dev/null

# GitHub uploads the slice only after a successful retained-main proof, host
# validator/hash/environment recheck, and unchanged KVM ACL.
grep -F 'tests/helper/validate-helper-restart-may-own-custody-relay-evidence-v1.sh \' \
    "$workflow" >/dev/null
grep -F 'tests/helper/validate-helper-restart-may-own-custody-relay-vm-environment-v1.sh \' \
    "$workflow" >/dev/null
workflow_artifact=$tmp/workflow-artifact
sed -n '/name: Upload bounded singleton MayOwn Relay restart evidence/,/retention-days: 90/p' \
    "$workflow" >"$workflow_artifact"
grep -F 'id: may_own_restart_pass_artifact_upload' "$workflow_artifact" >/dev/null
grep -F "steps.source_selection.outputs.proof_mode == 'retained-main'" \
    "$workflow_artifact" >/dev/null
grep -F "steps.vm_proof.outputs.exit_code == '0'" "$workflow_artifact" >/dev/null
grep -F "steps.host_validation.outcome == 'success'" "$workflow_artifact" >/dev/null
grep -F "steps.verify_kvm_state.outcome == 'success'" "$workflow_artifact" >/dev/null
grep -F 'uses: actions/upload-artifact@043fb46d1a93c77aae656e7c1c64a875d1fc6a0a # v7.0.1' \
    "$workflow_artifact" >/dev/null
for retained_name in \
    helper-restart-may-own-custody-relay-evidence-v1.json \
    helper-restart-may-own-custody-relay-evidence-v1.json.sha256 \
    helper-restart-may-own-custody-relay-vm-environment-v1.json
do
    grep -F "\${{ runner.temp }}/helper-boundary-retained/$retained_name" \
        "$workflow_artifact" >/dev/null
done
grep -F 'MAY_OWN_RESTART_PASS_ARTIFACT_UPLOAD_OUTCOME:' "$workflow" >/dev/null
grep -F 'test "$MAY_OWN_RESTART_PASS_ARTIFACT_UPLOAD_OUTCOME" = success' \
    "$workflow" >/dev/null

printf '%s\n' \
    'PASS: singleton MayOwnCustody Relay restart KVM contract is bounded, lineage-safe, and claim-exact.'
