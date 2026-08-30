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

# Invocation one stops at the third publication (Client, Exit, then Relay), records
# the observation and uses GDB's bounded inferior kill at the live publication frame.
if ! awk '
    /^    driver_phase=may-own-first-crash$/ { in_block = 1; start = NR }
    in_block && /break volparossa_helper::worker_v3::DurableCustodyPublicationTerminalGuard::retain_published/ {
        breakpoint = NR; breakpoint_count++
    }
    in_block && /ignore 1 2/ { ignore = NR; ignore_count++ }
    in_block && /may-own-observer first-publication/ { publication = NR; publication_count++ }
    in_block && /^[[:space:]]*\047kill\047/ { inferior_kill = NR; inferior_kill_count++ }
    in_block && /signal SIGKILL/ { invalid_signal++ }
    in_block && /may-own-observer armed/ { armed = NR; armed_count++ }
    in_block && /^    chmod 0600 "\$may_own_debugger_one_commands"/ {
        finish = NR; in_block = 0
    }
    END {
        valid = start > 0 && breakpoint_count == 1 && ignore_count == 1
        valid = valid && publication_count == 1 && inferior_kill_count == 1
        valid = valid && invalid_signal == 0
        valid = valid && armed_count == 1 && finish > 0
        valid = valid && start < breakpoint && breakpoint < ignore
        valid = valid && ignore < publication && publication < inferior_kill
        valid = valid && inferior_kill < armed && armed < finish
        if (!valid) exit 1
    }
' "$gate"; then
    printf '%s\n' 'MayOwn first forced-crash debugger sequence is not exact' >&2
    exit 1
fi

# Invocation two follows two executor exec transitions, observes the reaper
# journal confirmation boundary, then uses the second bounded inferior kill.
if ! awk '
    /^    may_own_tracer_ready=/ { in_block = 1; start = NR }
    in_block && /tcatch exec/ { catches++; if (catches == 1) c1 = NR; if (catches == 2) c2 = NR }
    in_block && /'\''continue'\''/ { continues++; if (continues == 1) k1 = NR; if (continues == 2) k2 = NR; if (continues == 3) k3 = NR }
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
        valid = start > 0 && catches == 2 && continues == 3
        valid = valid && breakpoint_count == 1 && observer_count == 1
        valid = valid && inferior_kill_count == 1 && invalid_signal == 0 && finish > 0
        valid = valid && start < c1 && c1 < k1 && k1 < c2 && c2 < k2
        valid = valid && k2 < breakpoint && breakpoint < observer_line
        valid = valid && observer_line < inferior_kill && inferior_kill < k3 && k3 < finish
        if (!valid) exit 1
    }
' "$gate"; then
    printf '%s\n' 'MayOwn second forced-crash debugger sequence is not exact' >&2
    exit 1
fi

# Invocation three follows two executor exec transitions, observes exact restart
# custody removal, and detaches so startup can settle and publish.
if ! awk '
    /^    may_own_third_tracer_ready=/ { in_block = 1; start = NR }
    in_block && /tcatch exec/ { catches++; if (catches == 1) c1 = NR; if (catches == 2) c2 = NR }
    in_block && /'\''continue'\''/ { continues++; if (continues == 1) k1 = NR; if (continues == 2) k2 = NR; if (continues == 3) k3 = NR }
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
        valid = start > 0 && catches == 2 && continues == 3
        valid = valid && breakpoint_count == 1 && observer_count == 1
        valid = valid && detach_count == 1 && quit_count == 1 && finish > 0
        valid = valid && start < c1 && c1 < k1 && k1 < c2 && c2 < k2
        valid = valid && k2 < breakpoint && breakpoint < observer_line
        valid = valid && observer_line < detach && detach < quit
        valid = valid && quit < k3 && k3 < finish
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
