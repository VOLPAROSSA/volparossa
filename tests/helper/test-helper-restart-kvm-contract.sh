#!/bin/sh
# SPDX-License-Identifier: GPL-3.0-only
# Static fail-closed contract for the singleton ExactPresent forced-restart VM proof.
# The contract deliberately matches literal shell source containing quotes,
# dollars and trailing backslashes; those strings must not be expanded here.
# shellcheck disable=SC1003,SC2016,SC2317
set -eu
export LC_ALL=C
PATH=/usr/sbin:/usr/bin:/sbin:/bin
export PATH
umask 077

here=$(CDPATH='' cd -- "$(dirname -- "$0")" && pwd)
repository=$(CDPATH='' cd -- "$here/../.." && pwd)
gate=$here/require-live-worker-identity-proof.sh
hook=$here/lib/production-ipc-unit-hook.sh
observer=$here/lib/restart-exact-present-observer.sh
launcher=$here/lib/restart-exact-present-launcher.sh
schema=$here/helper-restart-exact-present-evidence-v1.schema.json
fixture=$here/fixtures/helper-restart-exact-present-evidence-v1.pass.json
validator=$here/validate-helper-restart-exact-present-evidence-v1.sh
workflow=$repository/.github/workflows/helper-boundary-evidence.yml
functional_probe=$repository/crates/volparossa-helper/examples/volparossa-helper-production-ipc-probe.rs
functional_backend=$repository/crates/volparossa-helper/src/worker_v3/functional_backend.rs
tmp=$(mktemp -d /tmp/volparossa-restart-kvm-contract.XXXXXX)
case $tmp in /tmp/volparossa-restart-kvm-contract.??????) ;; *) exit 1 ;; esac
trap 'rm -rf --one-file-system -- "$tmp"' EXIT
trap 'exit 129' HUP
trap 'exit 130' INT
trap 'exit 143' TERM

for executable in "$gate" "$hook" "$observer" "$launcher" "$validator"; do
    [ -f "$executable" ] && [ -x "$executable" ] && [ ! -L "$executable" ] || exit 1
    sh -n "$executable"
done
jq -e . "$schema" >/dev/null
"$validator" "$fixture"

# The VM driver clones tracked source under umask 077, while a developer checkout
# normally exposes mode 0755. Both are private, executable source inputs; require
# the root proof to accept only the same closed 0700/0750/0755 set as its adjacent
# production hook before copying either input to a root:root mode-0500 stage.
observer_source_mode_contract=$tmp/observer-source-mode-contract
sed -n '/restart_observer_initial_snapshot=/,/restart observer has unsafe workspace metadata/p' \
    "$gate" >"$observer_source_mode_contract"
for accepted_mode in 700 750 755; do
    test "$(grep -Fc \
        "\"\$restart_observer_initial_snapshot\" $accepted_mode \"\$proof_file_max_bytes\"" \
        "$observer_source_mode_contract")" -eq 1
done
test "$(grep -Fc 'source_snapshot_is_exact' "$observer_source_mode_contract")" -eq 3
launcher_source_mode_contract=$tmp/launcher-source-mode-contract
sed -n '/restart_launcher_initial_snapshot=/,/restart launcher has unsafe workspace metadata/p' \
    "$gate" >"$launcher_source_mode_contract"
for accepted_mode in 700 750 755; do
    test "$(grep -Fc \
        "\"\$restart_launcher_initial_snapshot\" $accepted_mode \"\$proof_file_max_bytes\"" \
        "$launcher_source_mode_contract")" -eq 1
done
test "$(grep -Fc 'source_snapshot_is_exact' "$launcher_source_mode_contract")" -eq 3

# The checked-in launcher is one fixed no-argument test seam. Restart mode keeps
# its original crash-selected successor barrier. MayOwn mode instead holds every
# invocation behind one invocation/PID-bound FIFO barrier before the same PID
# execs the helper.
if ! awk '
    /^\[ "\$#" -eq 0 \] \|\| exit 64$/ { argc = NR; argc_count++ }
    /^case \$\{VOLPAROSSA_HELPER_PREEXEC_MODE:-restart\} in$/ { mode = NR; mode_count++ }
    /^[[:space:]]*may-own\)$/ { may_own = NR; may_own_count++ }
    /may-own\.pre-exec\.\$may_own_invocation_id$/ { may_ready = NR; may_ready_count++ }
    /VOLPAROSSA_HELPER_MAY_OWN_PRE_EXEC_BARRIER_V1=ready/ {
        may_record = NR; may_record_count++
    }
    /dd if="\$may_own_release_fifo" of="\$may_own_release_capture"/ {
        may_read = NR; may_read_count++
    }
    /^[[:space:]]*restart\)$/ { restart = NR; restart_count++ }
    /if \[ ! -e "\$crash_record" \] && \[ ! -L "\$crash_record" \]; then/ {
        absent = NR; absent_count++
    }
    /^[[:space:]]*exec "\$production_helper"$/ {
        execs++
        if (execs == 1) first_exec = NR
        if (execs == 2) successor_exec = NR
    }
    /^[[:space:]]*invocation_id=\$\{INVOCATION_ID:-\}$/ { invocation = NR; invocation_count++ }
    /VOLPAROSSA_HELPER_RESTART_SUCCESSOR_BARRIER_V1=ready/ {
        ready = NR; ready_count++
    }
    /stat -Lc .*"\$release_fifo"/ { fifo = NR; fifo_count++ }
    /^[[:space:]]*mv -T "\$ready_next" "\$ready_record"$/ { publish = NR; publish_count++ }
    /^[[:space:]]*dd if="\$release_fifo" of="\$release_capture" iflag=fullblock/ {
        read = NR; read_count++
    }
    /bs=2 count=1 status=none/ { bound = NR; bound_count++ }
    /regular file:0:0:600:1:1/ { exact = NR; exact_count++ }
    /^[[:space:]]*\[ "\$\(cat "\$release_capture"\)" = G \] \|\| exit 65$/ {
        gate = NR; gate_count++
    }
    END {
        valid = argc_count == 1 && mode_count == 1 && may_own_count == 1
        valid = valid && may_ready_count == 1 && may_record_count == 1
        valid = valid && may_read_count == 1 && restart_count == 1
        valid = valid && absent_count == 1 && execs == 2
        valid = valid && invocation_count == 1 && ready_count == 1
        valid = valid && fifo_count == 1
        valid = valid && publish_count == 1 && read_count == 1
        valid = valid && bound_count == 2
        valid = valid && exact_count == 2 && gate_count == 1
        valid = valid && argc < mode && mode < may_own
        valid = valid && may_own < may_ready && may_ready < may_record
        valid = valid && may_record < may_read && may_read < restart
        valid = valid && restart < absent && absent < first_exec
        valid = valid && first_exec < invocation && invocation < fifo
        valid = valid && fifo < ready && ready < publish && publish < read
        valid = valid && read < bound && bound < exact
        valid = valid && exact < gate && gate < successor_exec
        if (!valid) exit 1
    }
' "$launcher"; then
    printf '%s\n' 'restart launcher is not the exact restart and MayOwn affine barrier' >&2
    exit 1
fi

# The outer proof compares a byte-exact, newline-terminated barrier record;
# shell command substitution must not canonicalise trailing empty lines.
barrier_expected=$tmp/restart-successor-barrier.expected
barrier_candidate=$tmp/restart-successor-barrier.candidate
printf '%s\n%s\n%s\n' \
    'VOLPAROSSA_HELPER_RESTART_SUCCESSOR_BARRIER_V1=ready' \
    '11111111111111111111111111111111' '1234' >"$barrier_expected"
cp "$barrier_expected" "$barrier_candidate"
cmp -s "$barrier_expected" "$barrier_candidate"
printf '%s\n%s\n%s' \
    'VOLPAROSSA_HELPER_RESTART_SUCCESSOR_BARRIER_V1=ready' \
    '11111111111111111111111111111111' '1234' >"$barrier_candidate"
if cmp -s "$barrier_expected" "$barrier_candidate"; then
    printf '%s\n' 'restart barrier accepted a missing terminal newline' >&2
    exit 1
fi
printf '%s\n%s\n%s\n\n' \
    'VOLPAROSSA_HELPER_RESTART_SUCCESSOR_BARRIER_V1=ready' \
    '11111111111111111111111111111111' '1234' >"$barrier_candidate"
if cmp -s "$barrier_expected" "$barrier_candidate"; then
    printf '%s\n' 'restart barrier accepted an additional terminal newline' >&2
    exit 1
fi
barrier_contract=$tmp/restart-successor-barrier-contract
sed -n '/restart_expected_barrier=\$temporary_stage/,/restart successor pre-exec barrier is not manager-bound/p' \
    "$gate" >"$barrier_contract"
grep -F 'install -o root -g root -m 0600 /dev/null "$restart_expected_barrier" \' \
    "$barrier_contract" >/dev/null
grep -F 'cmp -s "$restart_expected_barrier" \' "$barrier_contract" >/dev/null
if grep -F '$(cat "$restart_successor_barrier")' "$barrier_contract" >/dev/null; then
    printf '%s\n' 'restart successor barrier still uses newline-normalising substitution' >&2
    exit 1
fi

# The launcher is an observed proof artifact: schema, validator, report writer,
# source/staged digests, and final staged metadata must all remain wired.
test "$(grep -Fc '"restart_launcher_sha256"' "$schema")" -eq 2
test "$(jq -r '.observed_artifact_hashes.restart_launcher_sha256 | length' \
    "$fixture")" -eq 64
grep -F '"restart_launcher_sha256"' "$validator" >/dev/null
test "$(grep -Fc 'staged_restart_launcher_digest' "$gate")" -ge 5
grep -F -- '--arg launcher_digest "$staged_restart_launcher_digest" \' \
    "$gate" >/dev/null
grep -F 'restart_launcher_sha256: $launcher_digest,' "$gate" >/dev/null
grep -Fx "    || [ \"\$staged_restart_launcher_final\" != 'regular file:0:0:500:1' ] \\" \
    "$gate" >/dev/null
command_preflight=$tmp/command-preflight
sed -n '/^for command_name in \\/,/^do$/p' "$gate" >"$command_preflight"
grep -Eq '(^|[[:space:]])dd([[:space:]]|$)' "$command_preflight"

# PID 1 is configured with the fixed launcher for restart evidence while the
# running process image remains the real helper. Both identities are fenced:
# ordinary production keeps its direct entrypoint, restart mode requires the
# launcher, and both typed systemd records receive that exact expectation.
launch_entrypoint_contract=$tmp/restart-launch-entrypoint-contract
sed -n '/^capture_systemd_launch_contract() {$/,/^}$/p' \
    "$hook" >"$launch_entrypoint_contract"
grep -Fx '        no) hook_launch_entrypoint=$production_helper ;;' \
    "$launch_entrypoint_contract" >/dev/null
grep -Fx '        yes) hook_launch_entrypoint=$restart_launcher ;;' \
    "$launch_entrypoint_contract" >/dev/null
test "$(grep -Fc '"$hook_launch_entrypoint") || return 1' \
    "$launch_entrypoint_contract")" -eq 2
grep -F 'capture_launch_image_identity "$production_helper"' "$hook" >/dev/null

# The pre-kill authorization is a single fixed private record published
# before the functional release byte. Exercise its exact producer state and
# reject payload, pending-path, hardlink and symlink substitution.
restart_release_authorized_functions=$tmp/restart-release-authorized-functions.sh
{
    sed -n '/^publish_restart_initial_release_authorized() {$/,/^}$/p' "$hook"
    sed -n '/^restart_initial_release_authorized_record_is_exact() {$/,/^}$/p' "$hook"
} >"$restart_release_authorized_functions"
[ "$(grep -c '^[_a-z].*() {$' "$restart_release_authorized_functions")" -eq 2 ]
# shellcheck disable=SC1090,SC2317
. "$restart_release_authorized_functions"
restart_initial_release_authorized_record=$tmp/restart-initial-release.authorized
private_file_is_safe() {
    [ -f "$1" ] && [ ! -L "$1" ] \
        && [ "$(command stat -Lc '%a:%h' "$1")" = 600:1 ]
}
write_private_file() {
    [ "$#" -eq 2 ] || return 1
    [ ! -e "$1" ] && [ ! -L "$1" ] \
        && [ ! -e "$1.next" ] && [ ! -L "$1.next" ] || return 1
    printf '%s\n' "$2" >"$1.next" || return 1
    chmod 0600 "$1.next" || return 1
    mv -- "$1.next" "$1"
}
reset_release_authorized_model() {
    rm -f -- "$restart_initial_release_authorized_record" \
        "$restart_initial_release_authorized_record.next"
    restart_exact_present_mode=yes
    start_failure_stage=functional-client-release
    start_failure_armed=yes
    start_failure_published=no
    start_failure_exit_publication=no
    restart_initial_handshake_armed=yes
    restart_initial_handshake_failure_stage=preflight
}
reset_release_authorized_model
publish_restart_initial_release_authorized
restart_initial_release_authorized_record_is_exact \
    "$restart_initial_release_authorized_record"
printf '%s\n' \
    'VOLPAROSSA_HELPER_V3_RESTART_INITIAL_RELEASE_AUTHORIZED_V1=pass' \
    | cmp -s - "$restart_initial_release_authorized_record"
[ "$(command stat -Lc '%a:%h' \
    "$restart_initial_release_authorized_record")" = 600:1 ]
for release_authorized_precondition in \
    mode stage armed published fallback handshake handshake-stage
do
    reset_release_authorized_model
    # These assignments are consumed by the dynamically sourced producer.
    # shellcheck disable=SC2034
    case $release_authorized_precondition in
        mode) restart_exact_present_mode=no ;;
        stage) start_failure_stage=functional-relay-cleanup ;;
        armed) start_failure_armed=no ;;
        published) start_failure_published=yes ;;
        fallback) start_failure_exit_publication=yes ;;
        handshake) restart_initial_handshake_armed=no ;;
        handshake-stage) restart_initial_handshake_failure_stage=publication ;;
    esac
    if publish_restart_initial_release_authorized; then
        printf 'restart release authorization accepted invalid precondition: %s\n' \
            "$release_authorized_precondition" >&2
        exit 1
    fi
    [ ! -e "$restart_initial_release_authorized_record" ] \
        && [ ! -L "$restart_initial_release_authorized_record" ]
    [ ! -e "$restart_initial_release_authorized_record.next" ] \
        && [ ! -L "$restart_initial_release_authorized_record.next" ]
done
for release_authorized_payload_mutation in \
    mutated suffix extra-newline missing-newline
do
    reset_release_authorized_model
    case $release_authorized_payload_mutation in
        mutated)
            printf '%s\n' mutated >"$restart_initial_release_authorized_record"
            ;;
        suffix)
            printf '%s\n%s\n' \
                'VOLPAROSSA_HELPER_V3_RESTART_INITIAL_RELEASE_AUTHORIZED_V1=pass' \
                junk >"$restart_initial_release_authorized_record"
            ;;
        extra-newline)
            printf '%s\n\n' \
                'VOLPAROSSA_HELPER_V3_RESTART_INITIAL_RELEASE_AUTHORIZED_V1=pass' \
                >"$restart_initial_release_authorized_record"
            ;;
        missing-newline)
            printf %s \
                'VOLPAROSSA_HELPER_V3_RESTART_INITIAL_RELEASE_AUTHORIZED_V1=pass' \
                >"$restart_initial_release_authorized_record"
            ;;
    esac
    chmod 0600 "$restart_initial_release_authorized_record"
    if restart_initial_release_authorized_record_is_exact \
        "$restart_initial_release_authorized_record"; then
        printf 'restart release authorization accepted payload mutation: %s\n' \
            "$release_authorized_payload_mutation" >&2
        exit 1
    fi
done
reset_release_authorized_model
publish_restart_initial_release_authorized
printf '%s\n' pending >"$restart_initial_release_authorized_record.next"
chmod 0600 "$restart_initial_release_authorized_record.next"
if restart_initial_release_authorized_record_is_exact \
    "$restart_initial_release_authorized_record"; then
    printf '%s\n' 'restart release authorization accepted a pending sibling' >&2
    exit 1
fi
reset_release_authorized_model
publish_restart_initial_release_authorized
ln -s "$tmp/restart-release-authorized-missing-pending-target" \
    "$restart_initial_release_authorized_record.next"
if restart_initial_release_authorized_record_is_exact \
    "$restart_initial_release_authorized_record"; then
    printf '%s\n' 'restart release authorization accepted a pending symlink' >&2
    exit 1
fi
reset_release_authorized_model
printf '%s\n' \
    'VOLPAROSSA_HELPER_V3_RESTART_INITIAL_RELEASE_AUTHORIZED_V1=pass' \
    >"$tmp/restart-release-authorized-symlink-target"
chmod 0600 "$tmp/restart-release-authorized-symlink-target"
ln -s "$tmp/restart-release-authorized-symlink-target" \
    "$restart_initial_release_authorized_record"
if restart_initial_release_authorized_record_is_exact \
    "$restart_initial_release_authorized_record"; then
    printf '%s\n' 'restart release authorization accepted a symlink' >&2
    exit 1
fi
reset_release_authorized_model
printf '%s\n' \
    'VOLPAROSSA_HELPER_V3_RESTART_INITIAL_RELEASE_AUTHORIZED_V1=pass' \
    >"$tmp/restart-release-authorized-hardlink-target"
chmod 0600 "$tmp/restart-release-authorized-hardlink-target"
ln "$tmp/restart-release-authorized-hardlink-target" \
    "$restart_initial_release_authorized_record"
if restart_initial_release_authorized_record_is_exact \
    "$restart_initial_release_authorized_record"; then
    printf '%s\n' 'restart release authorization accepted a hardlink' >&2
    exit 1
fi
reset_release_authorized_model
unset -f private_file_is_safe write_private_file \
    publish_restart_initial_release_authorized \
    restart_initial_release_authorized_record_is_exact \
    reset_release_authorized_model

# The initial start hook rejects every regular or symlinked authorization path,
# including a dangling pending symlink. Deleting any predicate must fail.
restart_release_authorized_start_guard=$tmp/restart-release-authorized-start-guard
sed -n '/^    if \[ -e "\$restart_initial_release_authorized_record" \] \\/,/^    fi$/p' \
    "$hook" >"$restart_release_authorized_start_guard"
restart_release_authorized_start_guard_is_exact() {
    [ "$#" -eq 1 ] || return 1
    [ "$(wc -l <"$1")" -eq 6 ] || return 1
    [ "$(grep -Fc '[ -e "$restart_initial_release_authorized_record" ]' "$1")" -eq 1 ] \
        || return 1
    [ "$(grep -Fc '[ -L "$restart_initial_release_authorized_record" ]' "$1")" -eq 1 ] \
        || return 1
    [ "$(grep -Fc '[ -e "$restart_initial_release_authorized_record.next" ]' "$1")" -eq 1 ] \
        || return 1
    [ "$(grep -Fc '[ -L "$restart_initial_release_authorized_record.next" ]' "$1")" -eq 1 ] \
        || return 1
    [ "$(grep -Fc "fail 'restart initial release authorization path is unsafe'" "$1")" -eq 1 ]
}
restart_release_authorized_start_guard_is_exact \
    "$restart_release_authorized_start_guard"
for release_authorized_guard_mutation in \
    '[ -e "$restart_initial_release_authorized_record" ]' \
    '[ -L "$restart_initial_release_authorized_record" ]' \
    '[ -e "$restart_initial_release_authorized_record.next" ]' \
    '[ -L "$restart_initial_release_authorized_record.next" ]' \
    "fail 'restart initial release authorization path is unsafe'"
do
    awk -v dropped="$release_authorized_guard_mutation" \
        'index($0, dropped) == 0 { print }' \
        "$restart_release_authorized_start_guard" \
        >"$restart_release_authorized_start_guard.mutated"
    if restart_release_authorized_start_guard_is_exact \
        "$restart_release_authorized_start_guard.mutated"; then
        printf 'restart release authorization start guard survived mutation: %s\n' \
            "$release_authorized_guard_mutation" >&2
        exit 1
    fi
done
unset -f restart_release_authorized_start_guard_is_exact

# The exact restart hook authorizes release before writing it, never waits for
# the impossible settled Destroy response, and retains both pins through the
# pre-kill boundary, PID 1 transition, exact probe abort and failure ACK.
restart_pin_hold_contract=$tmp/restart-pin-hold-contract
sed -n '/^    advance_start_failure_stage functional-client-release/,/^    hook_functional_client_settled_output=/p' \
    "$hook" >"$restart_pin_hold_contract"
if ! awk '
    /^    advance_start_failure_stage functional-client-release/ {
        stage = NR; stage_count++
    }
    /^    if \[ "\$restart_exact_present_mode" = yes \]; then$/ {
        mode_count++
        if (mode_count == 1) arm_mode = NR
        else if (mode_count == 2) crash_mode = NR
    }
    /^        start_failure_exit_publication=no$/ {
        trap_off = NR; trap_off_count++
    }
    /^        restart_initial_handshake_armed=yes$/ {
        handshake = NR; handshake_count++
    }
    /^        set_restart_initial_handshake_failure_stage preflight \|\| return 1$/ {
        preflight = NR; preflight_count++
    }
    /^        publish_restart_initial_release_authorized \|\| return 1$/ {
        authorize = NR; authorize_count++
    }
    /printf .%s. "\$functional_release_byte" >&6/ {
        release = NR; release_count++
    }
    /^        hook_restart_pin_wait=0$/ { crash_wait = NR; crash_wait_count++ }
    /^        while ! private_file_is_safe "\$restart_crash_record"; do$/ {
        crash_loop = NR; crash_loop_count++
    }
    /"\$hook_restart_pin_wait" -lt 400/ {
        crash_bound = NR; crash_bound_count++
    }
    /^        worker_process_fd_is_retired 8 \|\| return 1$/ {
        retired = NR; retired_count++
    }
    /worker_wireguard_is_absent 7 "\$hook_functional_peer_address"/ {
        wireguard = NR; wireguard_count++
    }
    /^        hook_restart_termination_wait=0$/ {
        main_wait = NR; main_wait_count++
    }
    /hook_restart_termination_main=\$\(unit_main_pid/ {
        main = NR; main_count++
    }
    /^            if \[ "\$hook_restart_termination_main" = 0 \]; then$/ {
        main_zero = NR; main_zero_count++
    }
    /^                observe_functional_probe_failure \\$/ {
        reap = NR; reap_count++
    }
    /^                probe_output_is_exact \\$/ {
        ready_only = NR; ready_only_count++
    }
    /FUNCTIONAL_CLIENT_LEASE_FAILURE_V1=destroy,protocol/ {
        abort = NR; abort_count++
    }
    /^                publish_and_wait_for_restart_initial_failure_ack \\$/ {
        ack = NR; ack_count++; in_ack = 1
    }
    in_ack && /"\$hook_functional_worker_namespace" \|\| return 1$/ {
        ack_bound = NR; ack_bound_count++; in_ack = 0; await_failure = 1
    }
    await_failure && /^                return 1$/ {
        deliberate_failure = NR; deliberate_failure_count++; await_failure = 0
    }
    /^    hook_functional_client_settled_output=/ {
        normal_settled = NR; normal_settled_count++
    }
    /advance_start_failure_stage functional-client-cleanup/ { premature_cleanup++ }
    /^    command exec [78]>&-/ { early_close++ }
    /"\$hook_functional_process_identity" \] \|\| return 1/ {
        process_fence_count++
    }
    /"\$hook_functional_worker_namespace" \] \|\| return 1/ {
        namespace_fence_count++
    }
    END {
        valid = stage_count == 1 && mode_count == 2
        valid = valid && trap_off_count == 1 && handshake_count == 1
        valid = valid && preflight_count == 1 && authorize_count == 1
        valid = valid && release_count == 1 && crash_wait_count == 1
        valid = valid && crash_loop_count == 1 && crash_bound_count == 1
        valid = valid && retired_count == 1 && wireguard_count == 1
        valid = valid && main_wait_count == 1 && main_count == 1
        valid = valid && main_zero_count == 1 && reap_count == 1
        valid = valid && ready_only_count == 1 && abort_count == 1
        valid = valid && ack_count == 1 && ack_bound_count == 1
        valid = valid && deliberate_failure_count == 1
        valid = valid && normal_settled_count == 1
        valid = valid && process_fence_count >= 3
        valid = valid && namespace_fence_count >= 3
        valid = valid && premature_cleanup == 0 && early_close == 0
        valid = valid && stage < arm_mode && arm_mode < trap_off
        valid = valid && trap_off < handshake && handshake < preflight
        valid = valid && preflight < authorize && authorize < release
        valid = valid && release < crash_mode && crash_mode < crash_wait
        valid = valid && crash_wait < crash_loop && crash_loop < crash_bound
        valid = valid && crash_bound < retired && retired < wireguard
        valid = valid && wireguard < main_wait && main_wait < main
        valid = valid && main < main_zero && main_zero < reap
        valid = valid && reap < ready_only && ready_only < abort
        valid = valid && abort < ack && ack < ack_bound
        valid = valid && ack_bound < deliberate_failure
        valid = valid && deliberate_failure < normal_settled
        if (!valid) exit 1
    }
' "$restart_pin_hold_contract"; then
    printf '%s\n' 'restart hook release/kill handshake is not causally exact' >&2
    exit 1
fi

# Bind the shell handshake to the real probe/backend order that made a
# post-Destroy settled barrier impossible: release precedes Destroy, while
# ClientSettled follows the response; CleanupConfirmed precedes manager removal.
if ! awk '
    /FunctionalPhase::Release,/ && !release { release = NR; release_count++ }
    /phase\.set\(FunctionalPhase::Commit\);/ && !commit {
        commit = NR; commit_count++
    }
    /phase\.set\(FunctionalPhase::Destroy\);/ && !destroy {
        destroy = NR; destroy_count++
    }
    /destroy_functional_cycle\(&mut stream, &first_plan, &first\.prepared\)/ {
        destroy_call = NR; destroy_call_count++
    }
    /phase\.set\(FunctionalPhase::ClientSettled\);/ {
        settled = NR; settled_count++
    }
    /publish_fixed_record\(FUNCTIONAL_CLIENT_SETTLED_RECORD\)/ {
        settled_publish = NR; settled_publish_count++
    }
    END {
        valid = release_count == 1 && commit_count == 1 && destroy_count == 1
        valid = valid && destroy_call_count == 1 && settled_count == 1
        valid = valid && settled_publish_count == 1
        valid = valid && release < commit && commit < destroy
        valid = valid && destroy < destroy_call && destroy_call < settled
        valid = valid && settled < settled_publish
        if (!valid) exit 1
    }
' "$functional_probe"; then
    printf '%s\n' 'functional probe release/Destroy/settled order changed' >&2
    exit 1
fi
functional_removal_contract=$tmp/functional-removal-contract
sed -n '/DurableJournalSettlement::CleanupConfirmed(cleanup) => {/,/DurableJournalSettlement::ManagerRemovalProven/p' \
    "$functional_backend" >"$functional_removal_contract"
if ! awk '
    /DurableJournalSettlement::CleanupConfirmed\(cleanup\) =>/ {
        cleanup = NR; cleanup_count++
    }
    /remove_current_process_custody\(/ { removal = NR; removal_count++ }
    END {
        valid = cleanup_count == 1 && removal_count == 1
        valid = valid && cleanup < removal
        if (!valid) exit 1
    }
' "$functional_removal_contract"; then
    printf '%s\n' 'CleanupConfirmed no longer precedes current-process removal' >&2
    exit 1
fi

# A deleted procfs process-directory descriptor cannot be reopened through a
# second process, but its holder-visible symlink and inode remain observable.
# Require the observer to bind the holder to systemd ControlPID, inspect that
# exact descriptor twice in place, and duplicate only the live namespace pin.
held_retirement_functions=$tmp/held-retirement-functions.sh
{
    sed -n '/^number_is_safe() {$/,/^}$/p' "$hook"
    sed -n '/^fd_number_is_safe() {$/,/^}$/p' "$hook"
    sed -n '/^kernel_object_number_is_safe() {$/,/^}$/p' "$hook"
    sed -n '/^kernel_object_identity_is_safe() {$/,/^}$/p' "$hook"
    sed -n '/^held_worker_process_fd_is_retired() {$/,/^}$/p' "$hook"
} >"$held_retirement_functions"
if ! awk '
    /^held_worker_process_fd_is_retired\(\) \{$/ { start = NR; start_count++ }
    /^    \[ "\$#" -eq 4 \] \|\| return 1$/ { argc = NR; argc_count++ }
    /^    hook_worker_held_path=\/proc\/\$hook_worker_holder_pid\/fd\/\$hook_worker_process_fd$/ {
        path = NR; path_count++
    }
    /^    hook_worker_deleted_target=\/proc\/\$hook_worker_pid\\ \\\(deleted\\\)$/ {
        target = NR; target_count++
    }
    /readlink "\$hook_worker_held_path"/ { readlink_count++; if (!readlink_one) readlink_one = NR; else readlink_two = NR }
    /stat -Lc .*\$hook_worker_held_path/ { stat_count++; if (!stat_one) stat_one = NR; else stat_two = NR }
    /^    if cat "\$hook_worker_held_path\/stat"/ { retired_stat = NR; retired_stat_count++ }
    /^    if cat "\$hook_worker_held_path\/status"/ { retired_status = NR; retired_status_count++ }
    /^    \[ ! -e "\/proc\/\$hook_worker_pid" \] \\$/ { absent = NR; absent_count++ }
    /command exec|^    exec / { unsafe_exec++ }
    END {
        valid = start_count == 1 && argc_count == 1
        valid = valid && path_count == 1 && target_count == 1
        valid = valid && readlink_count == 2 && stat_count == 2
        valid = valid && retired_stat_count == 1 && retired_status_count == 1
        valid = valid && absent_count == 1 && unsafe_exec == 0
        valid = valid && start < argc && argc < path && path < target
        valid = valid && target < readlink_one && readlink_one < stat_one
        valid = valid && stat_one < retired_stat && retired_stat < retired_status
        valid = valid && retired_status < absent && absent < readlink_two
        valid = valid && readlink_two < stat_two
        if (!valid) exit 1
    }
' "$held_retirement_functions"; then
    printf '%s\n' 'held retired-process descriptor observation is not exact' >&2
    exit 1
fi
/bin/bash -s -- "$held_retirement_functions" <<'HELD_RETIREMENT_TEST'
    # Exercise the actual cross-process procfs rule without touching network or
    # host configuration. The observer subshell closes its inherited fd first.
    set -eu
    . "$1"
    sleep 30 &
    held_retirement_worker=$!
    trap 'kill "$held_retirement_worker" 2>/dev/null || :; wait "$held_retirement_worker" 2>/dev/null || :' EXIT
    command exec 8<"/proc/$held_retirement_worker"
    held_retirement_holder=$$
    held_retirement_identity=$(stat -Lc '%d:%i' /proc/self/fd/8)
    if (
        command exec 8>&-
        held_worker_process_fd_is_retired \
            "$held_retirement_holder" 8 "$held_retirement_worker" \
            "$held_retirement_identity"
    ); then
        printf '%s\n' 'held process descriptor appeared retired while live' >&2
        exit 1
    fi
    kill "$held_retirement_worker"
    wait "$held_retirement_worker" 2>/dev/null || :
    (
        command exec 8>&-
        held_worker_process_fd_is_retired \
            "$held_retirement_holder" 8 "$held_retirement_worker" \
            "$held_retirement_identity"
    )
    if (
        command exec 8>&-
        held_worker_process_fd_is_retired \
            "$held_retirement_holder" 8 "$held_retirement_worker" 1:1
    ); then
        printf '%s\n' 'held process descriptor accepted a substituted identity' >&2
        exit 1
    fi
    command exec 8>&-
    if held_worker_process_fd_is_retired \
        "$held_retirement_holder" 8 "$held_retirement_worker" \
        "$held_retirement_identity"; then
        printf '%s\n' 'held process descriptor accepted a closed holder fd' >&2
        exit 1
    fi
    trap - EXIT
HELD_RETIREMENT_TEST
restart_observer_pin_contract=$tmp/restart-observer-pin-contract
sed -n '/^                cleanup-confirmed)$/,/write_private_file "\$restart_crash_record"/p' \
    "$hook" >"$restart_observer_pin_contract"
if ! awk '
    /Service ControlPID/ {
        control_count++
        if (control_count == 1) initial_control = NR
        else if (control_count == 2) middle_control = NR
        else if (control_count == 3) final_control = NR
    }
    /command exec 7<"\/proc\/\$hook_restart_hook_pid\/fd\/7"/ {
        namespace = NR; namespace_count++
    }
    /stat -Lc '\''%d:%i'\'' \/proc\/self\/fd\/7/ {
        namespace_identity_count++
        if (namespace_identity_count == 1) initial_namespace_identity = NR
        else if (namespace_identity_count == 2) middle_namespace_identity = NR
        else if (namespace_identity_count == 3) final_namespace_identity = NR
    }
    /held_worker_process_fd_is_retired \\$/ {
        process_count++
        if (process_count == 1) initial_process = NR
        else if (process_count == 2) middle_process = NR
        else if (process_count == 3) final_process = NR
    }
    /worker_wireguard_is_absent 7/ {
        wireguard_count++
        if (wireguard_count == 1) initial_wireguard = NR
        else if (wireguard_count == 2) middle_wireguard = NR
        else if (wireguard_count == 3) final_wireguard = NR
    }
    /unit_main_pid "\$hook_restart_unit"/ {
        main_count++
        if (main_count == 1) middle_main = NR
        else if (main_count == 2) final_main = NR
    }
    /unit_invocation_id "\$hook_restart_unit"/ {
        invocation_count++
        if (invocation_count == 1) initial_invocation = NR
        else if (invocation_count == 2) middle_invocation = NR
        else if (invocation_count == 3) final_invocation = NR
    }
    /^                    restart_initial_release_authorized_record_is_exact \\$/ {
        authorization_count++
        if (authorization_count == 1) authorization = NR
        else if (authorization_count == 2) authorization_revalidate = NR
    }
    /^                    hook_restart_release_authorized_identity=\$\(stat -Lc \\$/ {
        authorization_identity = NR; authorization_identity_count++
    }
    /^                    rm -- "\$restart_initial_release_authorized_record" \\$/ {
        authorization_consume = NR; authorization_consume_count++
    }
    /restart initial release authorization survived consumption/ {
        authorization_absence = NR; authorization_absence_count++
    }
    /^                    command exec 7>&-$/ {
        close_namespace = NR; close_namespace_count++
    }
    /write_private_file "\$restart_crash_record"/ { publish = NR; publish_count++ }
    /command exec 8<"\/proc\/\$hook_restart_hook_pid\/fd\/8"/ { process_reopen++ }
    /hook_restart_cleanup_ready_wait|sleep 0\.05/ { delayed_wait++ }
    END {
        valid = control_count == 3 && namespace_count == 1
        valid = valid && namespace_identity_count == 3
        valid = valid && process_count == 3 && wireguard_count == 3
        valid = valid && main_count == 2 && invocation_count == 3
        valid = valid && authorization_count == 2
        valid = valid && authorization_identity_count == 1
        valid = valid && authorization_consume_count == 1
        valid = valid && authorization_absence_count == 1
        valid = valid && close_namespace_count == 1 && publish_count == 1
        valid = valid && process_reopen == 0 && delayed_wait == 0
        valid = valid && initial_control < namespace
        valid = valid && namespace < initial_namespace_identity
        valid = valid && initial_namespace_identity < initial_process
        valid = valid && initial_process < initial_wireguard
        valid = valid && initial_wireguard < authorization
        valid = valid && authorization < middle_main
        valid = valid && middle_main < middle_invocation
        valid = valid && middle_invocation < middle_control
        valid = valid && middle_control < middle_namespace_identity
        valid = valid && middle_namespace_identity < middle_process
        valid = valid && middle_process < middle_wireguard
        valid = valid && middle_wireguard < authorization_identity
        valid = valid && authorization_identity < authorization_revalidate
        valid = valid && authorization_revalidate < authorization_consume
        valid = valid && authorization_consume < authorization_absence
        valid = valid && authorization_absence < final_main
        valid = valid && final_main < final_invocation
        valid = valid && final_invocation < final_control
        valid = valid && final_control < final_namespace_identity
        valid = valid && final_namespace_identity < final_process
        valid = valid && final_process < final_wireguard
        valid = valid && final_wireguard < close_namespace
        valid = valid && close_namespace < publish
        if (!valid) exit 1
    }
' "$restart_observer_pin_contract"; then
    printf '%s\n' 'restart observer does not consume authorization and re-fence affinely' >&2
    exit 1
fi

# GDB starts this adapter as root:root. A direct hook exec would therefore make
# the production probe reject the observation. Require one exact transition
# that retains real/effective UID 0, sets real/effective GID and the complete
# supplementary group vector to the validated agent GID, then execs the hook.
if ! awk '
    $0 == "observer_gid=$3" { gid = NR; gid_count++ }
    $0 == "case $observer_gid in" { validation = NR; validation_count++ }
    /\$\{#observer_gid\}.*-gt 10/ { length_bound = NR; length_count++ }
    /\$observer_gid.*-gt 4294967294/ { value_bound = NR; value_count++ }
    $0 == "exec /usr/bin/setpriv \\" { adapter = NR; adapter_count++ }
    $0 == "    --reuid=0 \\" { reuid = NR; reuid_count++ }
    $0 == "    --regid=\"$observer_gid\" \\" { regid = NR; regid_count++ }
    $0 == "    --groups=\"$observer_gid\" \\" { groups = NR; groups_count++ }
    $0 == "    -- /run/volparossa-helper-production-ipc-hook restart-observe \"$@\"" {
        hook = NR; hook_count++
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
        valid = valid && reuid < regid && regid < groups && groups < hook
        if (!valid) exit 1
    }
' "$observer"; then
    printf '%s\n' 'restart observer does not install the exact root-to-agent-GID adapter' >&2
    exit 1
fi
for invalid_gid in '' 0 061000 not-a-gid 4294967295 99999999999; do
    if "$observer" armed volparossa-helper-live-proof-ABC123.service \
        "$invalid_gid" 1 >/dev/null 2>&1; then
        printf 'restart observer accepted invalid agent GID: %s\n' "$invalid_gid" >&2
        exit 1
    else
        observer_status=$?
    fi
    [ "$observer_status" -eq 64 ] \
        || { printf 'restart observer returned %s for invalid agent GID\n' \
            "$observer_status" >&2; exit 1; }
done

# A running service has one positive MainPID, while systemd exposes exact zero
# after the killed invocation is manager-unbound. The restart observer needs
# both states, but still rejects every non-canonical or out-of-range value.
main_pid_property_contract=$tmp/main-pid-property-contract
sed -n '/^main_pid_property_is_safe() {$/,/^}$/p' \
    "$hook" >"$main_pid_property_contract"
[ "$(grep -Fc 'main_pid_property_is_safe() {' \
    "$main_pid_property_contract")" -eq 1 ]
# shellcheck source=/dev/null
. "$main_pid_property_contract"
for accepted_main_pid in 0 1 4294967294; do
    main_pid_property_is_safe "$accepted_main_pid"
done
for rejected_main_pid in '' 00 01 -1 not-a-pid 4294967295 99999999999; do
    if main_pid_property_is_safe "$rejected_main_pid"; then
        printf 'MainPID property validator accepted invalid value: %s\n' \
            "$rejected_main_pid" >&2
        exit 1
    fi
done
unit_main_pid_contract=$tmp/unit-main-pid-contract
sed -n '/^unit_main_pid() {$/,/^}$/p' "$hook" >"$unit_main_pid_contract"
[ "$(grep -Fc 'main_pid_property_is_safe "$hook_main_pid" || return 1' \
    "$unit_main_pid_contract")" -eq 1 ]
[ "$(grep -Fc 'number_is_safe "$hook_main_pid"' \
    "$unit_main_pid_contract")" -eq 0 ]
after_crash_observer_contract=$tmp/after-crash-observer-contract
sed -n '/^[[:space:]]*after-crash)$/,/^[[:space:]]*recovery-boundary)$/p' \
    "$hook" >"$after_crash_observer_contract"
[ "$(grep -Fc \
    '                        org.freedesktop.systemd1.Service NRestarts)" = 0 ] \' \
    "$after_crash_observer_contract")" -eq 1 ]
[ "$(grep -Fc \
    "                        || fail 'restart began before the after-crash fence'" \
    "$after_crash_observer_contract")" -eq 1 ]

# The cleanup observer needs all three results produced by the exact fdstore
# inventory in its own shell. Command substitution would run the function in a
# dash subshell, discard those affine global assignments, and let `set -u`
# terminate the observer before it can publish the forced-crash record.
restart_fdstore_observer_contract=$tmp/restart-fdstore-observer-contract
sed -n \
    '/^            custody_fd_name_is_safe "\$hook_restart_custody" \\/,/^                || fail '\''restart exact descriptor custody changed'\''$/p' \
    "$hook" >"$restart_fdstore_observer_contract"
printf '%s\n' \
    '            custody_fd_name_is_safe "$hook_restart_custody" \' \
    "                || fail 'restart custody name is invalid'" \
    '            unit_fdstore_exact_active_custody \' \
    '                "$hook_restart_unit" "$hook_restart_pidfd_descriptor" \' \
    '                "$hook_restart_namespace_descriptor" >/dev/null \' \
    "                || fail 'restart exact descriptor custody is unavailable'" \
    '            hook_restart_observed_custody=$hook_fdstore_custody_name' \
    '            hook_restart_manager_before_removal=$hook_fdstore_count_before' \
    '            hook_restart_manager_after_removal=$hook_fdstore_count_after' \
    '            if [ "$hook_restart_manager_before_removal" != 2 ] \' \
    '                || [ "$hook_restart_manager_after_removal" != 2 ]; then' \
    "                fail 'restart descriptor count changed during observation'" \
    '            fi' \
    '            [ "$hook_restart_observed_custody" = "$hook_restart_custody" ] \' \
    "                || fail 'restart exact descriptor custody changed'" \
    | cmp -s - "$restart_fdstore_observer_contract"
if grep -F '$(unit_fdstore_exact_active_custody' \
    "$restart_fdstore_observer_contract" >/dev/null; then
    printf '%s\n' 'restart observer discards exact fdstore outputs in a subshell' >&2
    exit 1
fi
restart_fdstore_direct_semantics() (
    set -eu
    unit_fdstore_exact_active_custody() {
        hook_fdstore_custody_name=exact-custody
        hook_fdstore_count_before=2
        hook_fdstore_count_after=2
        printf '%s\n' "$hook_fdstore_custody_name"
    }
    unit_fdstore_exact_active_custody >/dev/null
    hook_restart_observed_custody=$hook_fdstore_custody_name
    hook_restart_manager_before_removal=$hook_fdstore_count_before
    hook_restart_manager_after_removal=$hook_fdstore_count_after
    [ "$hook_restart_observed_custody" = exact-custody ] \
        && [ "$hook_restart_manager_before_removal" = 2 ] \
        && [ "$hook_restart_manager_after_removal" = 2 ]
)
restart_fdstore_subshell_mutant() (
    set -eu
    unit_fdstore_exact_active_custody() {
        hook_fdstore_custody_name=exact-custody
        hook_fdstore_count_before=2
        hook_fdstore_count_after=2
        printf '%s\n' "$hook_fdstore_custody_name"
    }
    hook_restart_observed_custody=$(unit_fdstore_exact_active_custody)
    hook_restart_manager_before_removal=$hook_fdstore_count_before
)
restart_fdstore_direct_semantics
set +e
restart_fdstore_subshell_mutant >/dev/null 2>&1
restart_fdstore_subshell_status=$?
set -e
[ "$restart_fdstore_subshell_status" -eq 2 ]
if ! awk '
    /^            unit_fdstore_exact_active_custody \\$/ {
        call = NR; call_count++
    }
    /^            hook_restart_observed_custody=\$hook_fdstore_custody_name$/ {
        custody = NR; custody_count++
    }
    /^            hook_restart_manager_before_removal=\$hook_fdstore_count_before$/ {
        before = NR; before_count++
    }
    /^            hook_restart_manager_after_removal=\$hook_fdstore_count_after$/ {
        after = NR; after_count++
    }
    /restart exact descriptor custody changed/ { comparison = NR; comparison_count++ }
    /write_private_file "\$restart_crash_record" "\$hook_restart_crash"/ {
        publication = NR; publication_count++
    }
    END {
        valid = call_count == 1 && custody_count == 1
        valid = valid && before_count == 1 && after_count == 1
        valid = valid && comparison_count == 1 && publication_count == 1
        valid = valid && call < custody && custody < before && before < after
        valid = valid && after < comparison && comparison < publication
        if (!valid) exit 1
    }
' "$hook"; then
    printf '%s\n' 'restart observer does not retain fdstore outputs through crash publication' >&2
    exit 1
fi

# Only a fixed classification of the private debugger stderr may leave the VM.
# Exercise the production classifier with the exact failure now fenced by the
# generic crash-record category, plus an unrecognised private-detail mutant.
restart_crash_classifier=$tmp/restart-crash-classifier.sh
sed -n '/^report_restart_crash_record_diagnostic() {$/,/^}$/p' \
    "$gate" >"$restart_crash_classifier"
[ "$(grep -c '^report_restart_crash_record_diagnostic() {$' \
    "$restart_crash_classifier")" -eq 1 ]
vp_capture_file_is_safe() {
    [ "$#" -eq 1 ] || return 1
    [ -f "$1" ] && [ ! -L "$1" ]
}
# shellcheck disable=SC1090
. "$restart_crash_classifier"
restart_crash_absent=$tmp/restart.crash.absent
restart_crash_debugger_stderr=$tmp/restart-debugger.stderr
restart_crash_classifier_output=$tmp/restart-crash-classifier.output
printf '%s\n' \
    'production IPC unit hook failed: restart exact descriptor custody is unavailable' \
    >"$restart_crash_debugger_stderr"
report_restart_crash_record_diagnostic \
    "$restart_crash_absent" "$restart_crash_debugger_stderr" \
    2>"$restart_crash_classifier_output"
if ! printf '%s\n' \
    'VOLPAROSSA_HELPER_LIVE_RESTART_CRASH_RECORD_DIAGNOSTIC_V1=record-absent,observer-fdstore-read' \
    | cmp -s - "$restart_crash_classifier_output"; then
    printf '%s\n' 'restart crash classifier did not map fdstore read failure' >&2
    sed -n '1p' "$restart_crash_classifier_output" >&2
    exit 1
fi
printf '%s\n' \
    'production IPC unit hook failed: precrash hook ControlPID changed' \
    >"$restart_crash_debugger_stderr"
report_restart_crash_record_diagnostic \
    "$restart_crash_absent" "$restart_crash_debugger_stderr" \
    2>"$restart_crash_classifier_output"
printf '%s\n' \
    'VOLPAROSSA_HELPER_LIVE_RESTART_CRASH_RECORD_DIAGNOSTIC_V1=record-absent,observer-control-binding' \
    | cmp -s - "$restart_crash_classifier_output"
printf '%s\n' 'private runtime address 192.0.2.55' \
    >"$restart_crash_debugger_stderr"
report_restart_crash_record_diagnostic \
    "$restart_crash_absent" "$restart_crash_debugger_stderr" \
    2>"$restart_crash_classifier_output"
printf '%s\n' \
    'VOLPAROSSA_HELPER_LIVE_RESTART_CRASH_RECORD_DIAGNOSTIC_V1=record-absent,observer-stderr-other' \
    | cmp -s - "$restart_crash_classifier_output"
if grep -F '192.0.2.55' "$restart_crash_classifier_output" >/dev/null; then
    printf '%s\n' 'restart crash classifier exposed private debugger detail' >&2
    exit 1
fi

# Successor diagnostics consume only the exact ordered private GDB markers and
# one literal hook failure. Malformed order, duplicates and private details
# collapse to fixed categories and never leave this classifier.
restart_successor_classifier=$tmp/restart-successor-debugger-classifier.sh
{
    sed -n '/^restart_successor_debugger_failure_category_is_safe() {$/,/^}$/p' \
        "$gate"
    sed -n '/^restart_successor_debugger_failure_category() {$/,/^}$/p' \
        "$gate"
} >"$restart_successor_classifier"
[ "$(grep -c '^restart_successor_debugger_failure_category.*() {$' \
    "$restart_successor_classifier")" -eq 2 ]
vp_capture_file_is_safe() {
    [ "$#" -eq 1 ] || return 1
    [ -f "$1" ] && [ ! -L "$1" ]
}
# shellcheck disable=SC1090
. "$restart_successor_classifier"
restart_successor_stdout=$tmp/restart-successor.stdout
restart_successor_stderr=$tmp/restart-successor.stderr
restart_successor_exec=VOLPAROSSA_HELPER_RESTART_SUCCESSOR_GDB_V1=exec-caught
restart_successor_breakpoint=VOLPAROSSA_HELPER_RESTART_SUCCESSOR_GDB_V1=breakpoint-installed
restart_successor_hit=VOLPAROSSA_HELPER_RESTART_SUCCESSOR_GDB_V1=breakpoint-hit
restart_successor_ok=VOLPAROSSA_HELPER_RESTART_SUCCESSOR_GDB_V1=observer-ok
restart_successor_failed=VOLPAROSSA_HELPER_RESTART_SUCCESSOR_GDB_V1=observer-failed
expect_restart_successor_category() {
    [ "$#" -eq 2 ]
    restart_successor_expected=$1
    restart_successor_status=$2
    restart_successor_actual=$(restart_successor_debugger_failure_category \
        "$restart_successor_status" "$restart_successor_stdout" \
        "$restart_successor_stderr")
    [ "$restart_successor_actual" = "$restart_successor_expected" ]
}
: >"$restart_successor_stdout"
: >"$restart_successor_stderr"
expect_restart_successor_category exec-not-caught 1
printf '%s\n' "$restart_successor_exec" >"$restart_successor_stdout"
expect_restart_successor_category breakpoint-not-installed 1
printf '%s\n%s\n' "$restart_successor_exec" \
    "$restart_successor_breakpoint" >"$restart_successor_stdout"
expect_restart_successor_category breakpoint-not-reached 1
printf '%s\n%s\n%s\n' "$restart_successor_exec" \
    "$restart_successor_breakpoint" "$restart_successor_hit" \
    >"$restart_successor_stdout"
expect_restart_successor_category observer-timeout 143
expect_restart_successor_category observer-other 1
printf '%s\n%s\n%s\n%s\n' "$restart_successor_exec" \
    "$restart_successor_breakpoint" "$restart_successor_hit" \
    "$restart_successor_ok" >"$restart_successor_stdout"
expect_restart_successor_category post-observer 1
printf '%s\n%s\n%s\n%s\n' "$restart_successor_exec" \
    "$restart_successor_breakpoint" "$restart_successor_hit" \
    "$restart_successor_failed" >"$restart_successor_stdout"
while IFS='|' read -r restart_successor_hook_failure \
    restart_successor_expected_category; do
    printf '%s\n' "$restart_successor_hook_failure" \
        >"$restart_successor_stderr"
    expect_restart_successor_category \
        "$restart_successor_expected_category" 1
done <<'EOF'
production IPC unit hook failed: restart MainPID is not manager-bound|observer-manager-binding
production IPC unit hook failed: restart precrash identity is unavailable|observer-precrash-record
production IPC unit hook failed: restart initial invocation is invalid|observer-precrash-record
production IPC unit hook failed: restart exact descriptor custody is unavailable|observer-fdstore-read
production IPC unit hook failed: restart descriptor count changed during observation|observer-fdstore-count
production IPC unit hook failed: restart exact descriptor custody changed|observer-fdstore-name
production IPC unit hook failed: restart CleanupConfirmed journal is unavailable|observer-journal-read
production IPC unit hook failed: restart CleanupConfirmed journal proof is invalid|observer-journal-value
production IPC unit hook failed: restart successor invocation is unavailable|observer-invocation-read
production IPC unit hook failed: restart successor reused the invocation|observer-invocation-reuse
production IPC unit hook failed: restart successor reused the MainPID|observer-mainpid-reuse
production IPC unit hook failed: restart count is not exactly one|observer-restart-count
production IPC unit hook failed: a new socket appeared before settlement|observer-socket-change
production IPC unit hook failed: restart boundary time is unavailable|observer-time
production IPC unit hook failed: restart successor starttime is unavailable|observer-starttime
production IPC unit hook failed: restart boundary record is unavailable|observer-record-build
production IPC unit hook failed: restart boundary record could not be published|observer-record-publication
EOF
printf '%s\n' \
    'production IPC unit hook failed: private runtime address 192.0.2.55' \
    >"$restart_successor_stderr"
expect_restart_successor_category observer-other 1
printf '%s\n%s\n' \
    'production IPC unit hook failed: restart count is not exactly one' \
    'production IPC unit hook failed: restart successor reused the MainPID' \
    >"$restart_successor_stderr"
expect_restart_successor_category observer-other 1
printf '%s\n%s\n%s\n%s\n%s\n' "$restart_successor_exec" \
    "$restart_successor_breakpoint" "$restart_successor_hit" \
    "$restart_successor_failed" "$restart_successor_exec" \
    >"$restart_successor_stdout"
expect_restart_successor_category marker-invalid 1
if restart_successor_debugger_failure_category 0 \
    "$restart_successor_stdout" "$restart_successor_stderr" \
    >"$restart_crash_classifier_output" 2>&1; then
    printf '%s\n' 'successor classifier accepted zero debugger status' >&2
    exit 1
fi
if grep -F '192.0.2.55' "$restart_crash_classifier_output" >/dev/null; then
    printf '%s\n' 'successor classifier exposed private debugger detail' >&2
    exit 1
fi

# The binary symbol fence accepts Debian debug builds where private Rust text
# symbols are local `t`, while still rejecting aliases or duplicate matches.
symbol_contract=$tmp/symbol-contract
sed -n '/restart_symbol_counts=$(nm -C/,/restart debugger symbols are not exact and unique/p' \
    "$gate" >"$symbol_contract"
[ "$(grep -Fc 'volparossa_helper::systemd_fdstore::remove_current_process_custody' \
    "$symbol_contract")" -eq 1 ]
[ "$(grep -Fc 'volparossa_helper::systemd_fdstore::remove_restart_custody' \
    "$symbol_contract")" -eq 1 ]
[ "$(grep -Fc 'if ($2 ~ /^[Tt]$/)' "$symbol_contract")" -eq 2 ]
grep -Fx "    [ \"\$restart_symbol_counts\" = '1:1:1:1' ] \\" \
    "$symbol_contract" >/dev/null

# The initial debugger kills only at the real current-process removal boundary
# and only after the observer returned normally with status zero. Every other
# observer outcome detaches the still-live inferior and makes the proof fail.
if ! awk '
    /^[[:space:]]*\047break volparossa_helper::systemd_fdstore::remove_current_process_custody\047/ {
        in_block = 1; breakpoint = NR; breakpoint_count++
    }
    in_block && /restart-observer cleanup-confirmed/ { observer = NR; observer_count++ }
    in_block && /^[[:space:]]*\047if !\$_isvoid\(\$_shell_exitcode\) && \$_shell_exitcode == 0\047/ {
        status_guard_count++
        if (status_guard_count == 1) cleanup_status_guard = NR
        else if (status_guard_count == 2) armed_status_guard = NR
    }
    in_block && /^[[:space:]]*\047kill\047/ {
        inferior_kill = NR; inferior_kill_count++
    }
    in_block && /^[[:space:]]*\047quit 0\047/ {
        clean_quit = NR; clean_quit_count++
    }
    in_block && /^[[:space:]]*\047else\047/ {
        failure_else_count++
        if (failure_else_count == 1) cleanup_failure_else = NR
        else if (failure_else_count == 2) armed_failure_else = NR
    }
    in_block && /^[[:space:]]*\047detach\047/ {
        failure_detach_count++
        if (failure_detach_count == 1) cleanup_failure_detach = NR
        else if (failure_detach_count == 2) armed_failure_detach = NR
    }
    in_block && /^[[:space:]]*\047quit 1\047/ {
        failure_quit_count++
        if (failure_quit_count == 1) cleanup_failure_quit = NR
        else if (failure_quit_count == 2) armed_failure_quit = NR
    }
    in_block && /^[[:space:]]*\047end\047/ {
        block_end_count++
        if (block_end_count == 1) cleanup_status_end = NR
        else if (block_end_count == 2) command_end = NR
        else if (block_end_count == 3) armed_status_end = NR
    }
    in_block && /signal SIGKILL/ { invalid_signal++ }
    in_block && /restart-observer armed/ { armed = NR; armed_count++ }
    in_block && /^[[:space:]]*\047continue\047/ {
        armed_continue = NR; armed_continue_count++
    }
    in_block && /initial restart debugger commands could not be written/ {
        end = NR; in_block = 0
    }
    END {
        valid = invalid_signal == 0 && breakpoint_count == 1 && observer_count == 1
        valid = valid && status_guard_count == 2
        valid = valid && inferior_kill_count == 1 && clean_quit_count == 1
        valid = valid && failure_else_count == 2 && failure_detach_count == 2
        valid = valid && failure_quit_count == 2 && block_end_count == 3
        valid = valid && armed_continue_count == 1
        valid = valid && armed_count == 1 && breakpoint < observer
        valid = valid && observer < cleanup_status_guard
        valid = valid && cleanup_status_guard < inferior_kill
        valid = valid && inferior_kill < clean_quit
        valid = valid && clean_quit < cleanup_failure_else
        valid = valid && cleanup_failure_else < cleanup_failure_detach
        valid = valid && cleanup_failure_detach < cleanup_failure_quit
        valid = valid && cleanup_failure_quit < cleanup_status_end
        valid = valid && cleanup_status_end < command_end
        valid = valid && command_end < armed
        valid = valid && armed < armed_status_guard
        valid = valid && armed_status_guard < armed_continue
        valid = valid && armed_continue < armed_failure_else
        valid = valid && armed_failure_else < armed_failure_detach
        valid = valid && armed_failure_detach < armed_failure_quit
        valid = valid && armed_failure_quit < armed_status_end
        valid = valid && armed_status_end < end
        if (!valid) exit 1
    }
' "$gate"; then
    printf '%s\n' 'initial forced-crash debugger boundary is not exact' >&2
    exit 1
fi

# The successor launcher has already published its invocation/PID-bound barrier.
# Attach there, stop at its one exec into the real helper, and install the exact
# restart-removal breakpoint before the final continue.
if ! awk '
    /^    restart_successor_tracer_ready=/ { in_block = 1; start = NR }
    in_block && /tcatch exec/ {
        catches++
        if (catches == 1) catch_one = NR
    }
    in_block && /^[[:space:]]*\047continue\047/ {
        continues++
        if (continues == 1) continue_one = NR
        if (continues == 2) continue_two = NR
    }
    in_block && /break volparossa_helper::systemd_fdstore::remove_restart_custody/ {
        breakpoint = NR; breakpoint_count++
    }
    in_block && /VOLPAROSSA_HELPER_RESTART_SUCCESSOR_GDB_V1=exec-caught/ {
        exec_marker = NR; exec_marker_count++
    }
    in_block && /VOLPAROSSA_HELPER_RESTART_SUCCESSOR_GDB_V1=breakpoint-installed/ {
        breakpoint_marker = NR; breakpoint_marker_count++
    }
    in_block && /VOLPAROSSA_HELPER_RESTART_SUCCESSOR_GDB_V1=breakpoint-hit/ {
        hit_marker = NR; hit_marker_count++
    }
    in_block && /VOLPAROSSA_HELPER_RESTART_SUCCESSOR_GDB_V1=observer-ok/ {
        observer_ok = NR; observer_ok_count++
    }
    in_block && /VOLPAROSSA_HELPER_RESTART_SUCCESSOR_GDB_V1=observer-failed/ {
        observer_failed = NR; observer_failed_count++
    }
    in_block && /restart-observer recovery-boundary/ { observer = NR; observer_count++ }
    in_block && /\047if !\$_isvoid\(\$_shell_exitcode\) && \$_shell_exitcode == 0\047/ {
        status_guard = NR; status_guard_count++
    }
    in_block && /^[[:space:]]*\047detach\047/ {
        detach_count++
        if (detach_count == 1) success_detach = NR
        if (detach_count == 2) failure_detach = NR
    }
    in_block && /^[[:space:]]*\047quit 0\047/ { clean_quit = NR; clean_quit_count++ }
    in_block && /^[[:space:]]*\047else\047/ { failure_else = NR; failure_else_count++ }
    in_block && /^[[:space:]]*\047quit 1\047/ { failure_quit = NR; failure_quit_count++ }
    in_block && /^[[:space:]]*\047end\047/ {
        end_count++
        if (end_count == 1) status_end = NR
        if (end_count == 2) command_end = NR
    }
    in_block && /^    chmod 0600 "\$restart_debugger_successor_commands"/ {
        chmod_line = NR; in_block = 0
    }
    END {
        valid = start > 0 && catches == 1 && continues == 2
        valid = valid && breakpoint_count == 1 && observer_count == 1
        valid = valid && exec_marker_count == 1 && breakpoint_marker_count == 1
        valid = valid && hit_marker_count == 1 && observer_ok_count == 1
        valid = valid && observer_failed_count == 1
        valid = valid && status_guard_count == 1 && detach_count == 2
        valid = valid && clean_quit_count == 1 && failure_else_count == 1
        valid = valid && failure_quit_count == 1 && end_count == 2
        valid = valid && chmod_line > 0
        valid = valid && start < catch_one && catch_one < continue_one
        valid = valid && continue_one < exec_marker && exec_marker < breakpoint
        valid = valid && breakpoint < breakpoint_marker
        valid = valid && breakpoint_marker < hit_marker && hit_marker < observer
        valid = valid && observer < status_guard && status_guard < observer_ok
        valid = valid && observer_ok < success_detach
        valid = valid && success_detach < clean_quit && clean_quit < failure_else
        valid = valid && failure_else < observer_failed
        valid = valid && observer_failed < failure_detach && failure_detach < failure_quit
        valid = valid && failure_quit < status_end && status_end < command_end
        valid = valid && command_end < continue_two
        valid = valid && continue_two < chmod_line
        if (!valid) exit 1
    }
' "$gate"; then
    printf '%s\n' 'successor debugger does not stop and arm the exact startup boundary' >&2
    exit 1
fi

# Successor ExecStartPost may begin as soon as Type=exec accepts the launcher.
# It must wait on the same exact MainPID/invocation until GDB publishes the
# recovery boundary. Its 90-second budget strictly contains the 45-second
# debugger verdict; it may neither race ahead nor accept a substituted file.
if ! awk '
    /^restart_start_hook\(\) \{$/ { in_hook = 1; start = NR }
    in_hook && /^    hook_restart_wait_pid=\$\(unit_main_pid/ {
        pid = NR; pid_count++
    }
    in_hook && /^    hook_restart_wait_invocation=\$\(unit_invocation_id/ {
        invocation = NR; invocation_count++
    }
    in_hook && /^    while ! private_file_is_safe "\$restart_recovery_boundary_record"; do$/ {
        wait = NR; wait_count++
    }
    in_hook && /restart recovery boundary is unsafe/ {
        unsafe_count++
        if (unsafe_count == 1) unsafe = NR
        if (unsafe_count == 2) final_unsafe = NR
    }
    in_hook && /restart successor MainPID changed before recovery/ {
        pid_fence = NR; pid_fence_count++
    }
    in_hook && /restart successor invocation changed before recovery/ {
        invocation_fence = NR; invocation_fence_count++
    }
    in_hook && /"\$hook_restart_wait" -ge 1800/ { bound = NR; bound_count++ }
    in_hook && /if private_file_is_safe "\$restart_recovery_boundary_record"/ {
        recovery_recheck_count++
        if (recovery_recheck_count == 1) ordinary_recheck = NR
        if (recovery_recheck_count == 2) final_recheck = NR
        if (recovery_recheck_count == 3) final_present_recheck = NR
    }
    in_hook && wait && /^[[:space:]]+break$/ {
        recovery_break_count++
        if (recovery_break_count == 1) ordinary_break = NR
        if (recovery_break_count == 2) final_break = NR
        if (recovery_break_count == 3) final_present_break = NR
    }
    in_hook && /restart recovery boundary is unavailable/ {
        unavailable = NR; unavailable_count++
    }
    in_hook && /^    hook_restart_current_pid=\$\(unit_main_pid/ {
        current = NR; current_count++
    }
    in_hook && /^}$/ { end = NR; in_hook = 0 }
    END {
        valid = start > 0 && pid_count == 1 && invocation_count == 1
        valid = valid && wait_count == 1 && unsafe_count == 2
        valid = valid && pid_fence_count == 1 && invocation_fence_count == 1
        valid = valid && bound_count == 1 && recovery_recheck_count == 3
        valid = valid && recovery_break_count == 3
        valid = valid && unavailable_count == 1 && current_count == 1 && end > 0
        valid = valid && start < pid && pid < invocation && invocation < wait
        valid = valid && wait < ordinary_recheck && ordinary_recheck < ordinary_break
        valid = valid && ordinary_break < unsafe
        valid = valid && unsafe < pid_fence
        valid = valid && pid_fence < invocation_fence
        valid = valid && invocation_fence < bound && bound < final_recheck
        valid = valid && final_recheck < final_break
        valid = valid && final_break < final_present_recheck
        valid = valid && final_present_recheck < final_present_break
        valid = valid && final_present_break < final_unsafe
        valid = valid && final_unsafe < unavailable
        valid = valid && unavailable < current && current < end
        if (!valid) exit 1
    }
' "$hook"; then
    printf '%s\n' 'successor start hook does not wait behind exact recovery ownership' >&2
    exit 1
fi

# The recovery observer runs as a synchronous GDB breakpoint command. Its
# process-identity read must accept exactly Linux's lowercase ptrace-stop state,
# without weakening the active-process starttime parser used elsewhere.
[ "$(grep -Fc 'capture_traced_process_starttime() {' "$hook")" -eq 1 ]
[ "$(grep -Fc 'hook_starttime_state=active' "$hook")" -eq 1 ]
[ "$(grep -Fc '[ "$3" = traced ] || return 1' "$hook")" -eq 1 ]
[ "$(grep -Fc 'expected_state == "traced" && value[1] == "t"' "$hook")" -eq 1 ]
[ "$(grep -Fc 'hook_restart_new_starttime=$(capture_traced_process_starttime \' \
    "$hook")" -eq 1 ]
if ! awk '
    /^restart_start_hook\(\) \{$/ { in_hook = 1; start = NR }
    in_hook && /hook_restart_boundary_starttime=\$\(restart_record_line/ {
        boundary = NR; boundary_count++
    }
    in_hook && /"\$restart_recovery_boundary_record" 4\)/ {
        boundary_line = NR; boundary_line_count++
    }
    in_hook && /"process-starttime-v1=\$hook_restart_boundary_starttime"/ {
        old_compare = NR; old_compare_count++
    }
    in_hook && /^    wait_for_restart_fdstore_settlement \\/ {
        settlement = NR; settlement_count++
    }
    in_hook && /hook_restart_resumed_starttime=\$\(capture_process_starttime/ {
        active = NR; active_count++
    }
    in_hook && /"\$hook_restart_resumed_starttime" = "\$hook_restart_boundary_starttime"/ {
        exact = NR; exact_count++
    }
    in_hook && /^}$/ { end = NR; in_hook = 0 }
    END {
        valid = start > 0 && boundary_count == 1 && boundary_line_count == 1
        valid = valid && old_compare_count == 1 && settlement_count == 1
        valid = valid && active_count == 1 && exact_count == 1 && end > 0
        valid = valid && start < boundary && boundary < boundary_line
        valid = valid && boundary_line < old_compare && old_compare < settlement
        valid = valid && settlement < active && active < exact && exact < end
        if (!valid) exit 1
    }
' "$hook"; then
    printf '%s\n' \
        'restart starttime proof is not synchronized across GDB detach' >&2
    exit 1
fi

# The first and successor ExecStartPost attempts share one root-only pathname.
# Consume the intentional release-stage probe/start failure tuple before the
# successor, then reserve both absent paths for its closed stage graph.
initial_failure_contract=$tmp/restart-initial-start-failure-contract
sed -n '/^consume_expected_restart_initial_start_failure() {$/,/^}$/p' \
    "$gate" >"$initial_failure_contract"
[ "$(grep -c '^consume_expected_restart_initial_start_failure() {$' \
    "$initial_failure_contract")" -eq 1 ]
grep -F \
    'VOLPAROSSA_HELPER_V3_IPC_START_FAILURE_STAGE_V1=functional-client-release' \
    "$initial_failure_contract" >/dev/null
grep -F \
    'VOLPAROSSA_HELPER_V3_FUNCTIONAL_CLIENT_LEASE_FAILURE_V1=destroy,protocol' \
    "$initial_failure_contract" >/dev/null
grep -F \
    'VOLPAROSSA_HELPER_V3_FUNCTIONAL_CLIENT_LEASE_V1=ready' \
    "$initial_failure_contract" >/dev/null
[ "$(grep -Fc 'systemctl show --property=MainPID --value "$unit_name"' \
    "$initial_failure_contract")" -eq 2 ]
[ "$(grep -Fc 'systemctl show --property=NRestarts --value "$unit_name"' \
    "$initial_failure_contract")" -eq 2 ]
[ "$(grep -Fc 'systemctl show --property=ControlPID --value "$unit_name"' \
    "$initial_failure_contract")" -eq 2 ]
[ "$(grep -Fc 'unit_current_invocation_id 2>/dev/null || true' \
    "$initial_failure_contract")" -eq 2 ]
[ "$(grep -Fc 'unit_description_matches_marker' \
    "$initial_failure_contract")" -eq 2 ]
grep -F 'restart_initial_start_failure_wait" -lt 150' \
    "$initial_failure_contract" >/dev/null
grep -F 'restart_initial_terminal_wait" -lt 300' \
    "$initial_failure_contract" >/dev/null
grep -F 'rm -- "$restart_initial_start_failure_file"' \
    "$initial_failure_contract" >/dev/null
if ! awk '
    /functional-client-release/ { exact = NR; exact_count++ }
    /restart_initial_functional_failure_identity=\$\(stat/ {
        functional_identity = NR; functional_identity_count++
    }
    /rm -- "\$restart_initial_functional_failure_file"/ {
        functional_removal = NR; functional_removal_count++
    }
    /\[ ! -e "\$restart_initial_functional_failure_file" \]/ {
        functional_absence = NR; functional_absence_count++
    }
    /restart_initial_start_failure_identity=\$\(stat/ {
        identity = NR; identity_count++
    }
    /rm -- "\$restart_initial_start_failure_file"/ {
        removal = NR; removal_count++
    }
    /restart_initial_terminal_record_is_exact/ {
        terminal_exact = NR; terminal_exact_count++
    }
    /rm -- "\$restart_initial_terminal_file"/ {
        terminal_removal = NR; terminal_removal_count++
    }
    removal && /(systemctl show|unit_current_invocation_id|unit_description_matches_marker)/ {
        manager_read_after_ack++
    }
    /\[ ! -e "\$restart_initial_start_failure_file" \]/ {
        if (!absence) absence = NR
        absence_count++
    }
    END {
        valid = exact_count == 1 && functional_identity_count == 1
        valid = valid && functional_removal_count == 1
        valid = valid && functional_absence_count == 1
        valid = valid && identity_count == 1
        valid = valid && removal_count == 1 && absence_count >= 1
        valid = valid && terminal_exact_count == 1 && terminal_removal_count == 0
        valid = valid && manager_read_after_ack == 0
        valid = valid && exact < functional_identity
        valid = valid && functional_identity < functional_removal
        valid = valid && functional_removal < functional_absence
        valid = valid && functional_absence < identity
        valid = valid && identity < removal && removal < absence
        valid = valid && removal < terminal_exact
        if (!valid) exit 1
    }
' "$initial_failure_contract"; then
    printf '%s\n' 'initial restart start-failure consumption is not affine' >&2
    exit 1
fi

initial_release_contract=$tmp/restart-initial-terminal-release-contract
sed -n '/^release_expected_restart_initial_terminal() {$/,/^}$/p' \
    "$gate" >"$initial_release_contract"
[ "$(grep -c '^release_expected_restart_initial_terminal() {$' \
    "$initial_release_contract")" -eq 1 ]
grep -F '[ "$restart_initial_after_crash_observed" = yes ]' \
    "$initial_release_contract" >/dev/null
grep -F 'restart_initial_hook_quiescence_wait" -lt 300' \
    "$initial_release_contract" >/dev/null
if ! awk '
    /restart_initial_after_crash_observed" = yes/ { observed = NR; observed_count++ }
    /rm -- "\$restart_initial_release_terminal_file"/ {
        unlink = NR; unlink_count++
    }
    /while \[ "\$\(capture_process_starttime "\$restart_initial_hook_pid"/ {
        quiescence = NR; quiescence_count++
    }
    unlink && /(systemctl show|unit_current_invocation_id|unit_description_matches_marker)/ {
        stale_manager_read++
    }
    /restart_initial_after_crash_observed=no/ { complete = NR; complete_count++ }
    END {
        valid = observed_count == 1 && unlink_count == 1
        valid = valid && quiescence_count == 1 && complete_count == 1
        valid = valid && stale_manager_read == 0
        valid = valid && observed < unlink && unlink < quiescence
        valid = valid && quiescence < complete
        if (!valid) exit 1
    }
' "$initial_release_contract"; then
    printf '%s\n' 'initial terminal release is not causally hook-quiescent' >&2
    exit 1
fi
if ! awk '
    /\/run\/volparossa-helper-restart-observer after-crash/ {
        observer = NR; observer_count++
    }
    /^    restart_initial_after_crash_observed=yes$/ {
        observed = NR; observed_count++
    }
    /^    if ! release_expected_restart_initial_terminal \\/ {
        release = NR; release_count++
    }
    /^    driver_phase=restart-observation$/ { successor = NR; successor_count++ }
    END {
        valid = observer_count == 1 && observed_count == 1
        valid = valid && release_count == 1 && successor_count == 1
        valid = valid && observer < observed && observed < release
        valid = valid && release < successor
        if (!valid) exit 1
    }
' "$gate"; then
    printf '%s\n' 'after-crash observation does not precede terminal release' >&2
    exit 1
fi
if ! awk '
    /^start_failure_exit\(\) \{$/ { in_exit = 1 }
    in_exit && /remove_functional_(relay_pair_fixtures|exit_relay_fixture|relay_fixture)/ {
        if (!cleanup) cleanup = NR
        cleanup_count++
    }
    in_exit && /publish_and_wait_for_restart_initial_terminal_ack/ {
        terminal = NR; terminal_count++
    }
    in_exit && /^}$/ { in_exit = 0 }
    END {
        valid = cleanup_count >= 3 && terminal_count == 1
        valid = valid && cleanup < terminal
        if (!valid) exit 1
    }
' "$hook"; then
    printf '%s\n' 'EXIT cleanup does not causally precede terminal publication' >&2
    exit 1
fi

# Execute the production consumer against closed mutation models. The success
# model publishes terminal success only after the root unlink and makes every
# manager/marker read fail once that unlink has happened, proving the driver
# cannot accept the input ACK as terminal or re-read stale systemd lineage.
restart_initial_driver_functions=$tmp/restart-initial-driver-functions.sh
{
    sed -n '/^restart_initial_driver_failure_stage_is_safe() {$/,/^}$/p' "$gate"
    sed -n '/^set_restart_initial_driver_failure_stage() {$/,/^}$/p' "$gate"
    sed -n '/^restart_initial_hook_failure_stage_is_safe() {$/,/^}$/p' "$gate"
    sed -n '/^read_restart_initial_hook_failure_stage() {$/,/^}$/p' "$gate"
    sed -n '/^inspect_restart_initial_hook_failure_record() {$/,/^}$/p' "$gate"
    sed -n '/^restart_initial_terminal_record_is_exact() {$/,/^}$/p' "$gate"
    sed -n '/^inspect_restart_initial_terminal_record() {$/,/^}$/p' "$gate"
    sed -n '/^consume_expected_restart_initial_start_failure() {$/,/^}$/p' "$gate"
    sed -n '/^release_expected_restart_initial_terminal() {$/,/^}$/p' "$gate"
} >"$restart_initial_driver_functions"
[ "$(grep -c '^[_a-z].*() {$' "$restart_initial_driver_functions")" -eq 9 ]
# shellcheck disable=SC1090,SC2317
. "$restart_initial_driver_functions"
temporary_stage=$tmp/restart-driver-stage
mkdir -p "$temporary_stage/restart-output"
restart_driver_start=$temporary_stage/restart-output/start.failure
restart_driver_functional=$temporary_stage/restart-output/functional-client-lease.failure
restart_driver_functional_stdout=$temporary_stage/restart-output/functional-client-lease.stdout
restart_driver_functional_stderr=$temporary_stage/restart-output/functional-client-lease.stderr
restart_driver_hook=$temporary_stage/restart-output/restart.initial-start.failure-stage
restart_driver_terminal=$temporary_stage/restart-output/restart.initial-start.terminal
restart_driver_stat_count=$tmp/restart-driver-stat-count
# Consumed dynamically by the sourced production consumer.
# shellcheck disable=SC2034
unit_name=volparossa-helper-live-proof-a1b2c3.service
restart_initial_invocation_id=11111111111111111111111111111111
restart_driver_main_pid=0
restart_driver_restarts=0
restart_driver_invocation=$restart_initial_invocation_id
restart_driver_marker=yes
restart_driver_sleep_action=terminal
restart_driver_remove_action=normal
restart_driver_functional_remove_action=normal
restart_driver_stat_mutation=
restart_driver_ack_seen=no
restart_driver_release_allowed=no
restart_driver_control_pid=777
restart_driver_hook_starttime=888
restart_driver_terminal_released=no
restart_driver_terminal_remove_action=normal
restart_driver_quiescence_action=success
vp_capture_file_is_safe() {
    [ "$#" -eq 1 ] || return 1
    [ -f "$1" ] && [ ! -L "$1" ] \
        && [ "$(command stat -Lc '%a:%h' "$1")" = 600:1 ]
}
systemctl() {
    [ "$1" = show ] || return 1
    if [ "$restart_driver_ack_seen" = yes ] \
        && [ "$restart_driver_release_allowed" != yes ]; then
        return 1
    fi
    case $2 in
        --property=MainPID) printf '%s\n' "$restart_driver_main_pid" ;;
        --property=NRestarts) printf '%s\n' "$restart_driver_restarts" ;;
        --property=ControlPID) printf '%s\n' "$restart_driver_control_pid" ;;
        *) return 1 ;;
    esac
}
unit_current_invocation_id() {
    if [ "$restart_driver_ack_seen" = yes ] \
        && [ "$restart_driver_release_allowed" != yes ]; then
        return 1
    fi
    printf '%s\n' "$restart_driver_invocation"
}
unit_description_matches_marker() {
    { [ "$restart_driver_ack_seen" = no ] \
        || [ "$restart_driver_release_allowed" = yes ]; } \
        && [ "$restart_driver_marker" = yes ]
}
stat() {
    if [ "$#" -eq 3 ] && [ "$1" = -Lc ] \
        && [ "$2" = '%d:%i:%f:%u:%g:%a:%h:%s' ] \
        && [ "$3" = "$restart_driver_stat_mutation" ]; then
        restart_driver_stat_calls=$(cat "$restart_driver_stat_count") || return 1
        restart_driver_stat_calls=$((restart_driver_stat_calls + 1))
        printf '%s\n' "$restart_driver_stat_calls" >"$restart_driver_stat_count"
        if [ "$restart_driver_stat_calls" -eq 2 ]; then
            printf '%s\n' '1:2:3:0:0:600:1:64'
            return 0
        fi
    fi
    command stat "$@"
}
rm() {
    if [ "$#" -eq 2 ] && [ "$1" = -- ] \
        && [ "$2" = "$restart_driver_functional" ]; then
        case $restart_driver_functional_remove_action in
            fail) return 1 ;;
            retain) return 0 ;;
        esac
    fi
    if [ "$#" -eq 2 ] && [ "$1" = -- ] \
        && [ "$2" = "$restart_driver_start" ]; then
        case $restart_driver_remove_action in
            fail) return 1 ;;
            retain)
                restart_driver_ack_seen=yes
                return 0
                ;;
        esac
        restart_driver_ack_seen=yes
    fi
    if [ "$#" -eq 2 ] && [ "$1" = -- ] \
        && [ "$2" = "$restart_driver_terminal" ]; then
        case $restart_driver_terminal_remove_action in
            fail) return 1 ;;
            retain)
                restart_driver_terminal_released=yes
                return 0
                ;;
        esac
        restart_driver_terminal_released=yes
    fi
    command rm "$@"
}
capture_process_starttime() {
    [ "$#" -eq 1 ] && [ "$1" = 777 ] || return 1
    if [ "$restart_driver_terminal_released" = no ]; then
        printf '%s\n' "$restart_driver_hook_starttime"
        return 0
    fi
    case $restart_driver_quiescence_action in
        success) return 1 ;;
        timeout) printf '%s\n' "$restart_driver_hook_starttime" ;;
        post-failure)
            if [ ! -e "$restart_driver_hook" ]; then
                printf '%s\n' \
                    'VOLPAROSSA_HELPER_V3_RESTART_INITIAL_HANDSHAKE_FAILURE_V1=terminal-post-pins' \
                    >"$restart_driver_hook"
                chmod 0600 "$restart_driver_hook"
            fi
            return 1
            ;;
        *) return 1 ;;
    esac
}
restart_driver_write_start() {
    printf '%s\n' \
        'VOLPAROSSA_HELPER_V3_IPC_START_FAILURE_STAGE_V1=functional-client-release' \
        >"$restart_driver_start"
    chmod 0600 "$restart_driver_start"
}
restart_driver_write_functional() {
    printf '%s\n' \
        'VOLPAROSSA_HELPER_V3_FUNCTIONAL_CLIENT_LEASE_V1=ready' \
        >"$restart_driver_functional_stdout"
    printf '%s\n' \
        'VOLPAROSSA_HELPER_V3_FUNCTIONAL_CLIENT_LEASE_FAILURE_V1=destroy,protocol' \
        >"$restart_driver_functional_stderr"
    command cp "$restart_driver_functional_stderr" "$restart_driver_functional"
    chmod 0600 "$restart_driver_functional_stdout" \
        "$restart_driver_functional_stderr" "$restart_driver_functional"
}
restart_driver_write_terminal() {
    printf '%s\n' \
        'VOLPAROSSA_HELPER_V3_RESTART_INITIAL_HANDSHAKE_TERMINAL_V1=success' \
        >"$restart_driver_terminal"
    chmod 0600 "$restart_driver_terminal"
}
restart_driver_write_hook_failure() {
    printf '%s\n' \
        'VOLPAROSSA_HELPER_V3_RESTART_INITIAL_HANDSHAKE_FAILURE_V1=post-pins' \
        >"$restart_driver_hook"
    chmod 0600 "$restart_driver_hook"
}
sleep() {
    [ "$1" = 0.05 ] || return 1
    if [ ! -e "$restart_driver_start" ]; then
        case $restart_driver_sleep_action in
            terminal)
                restart_driver_write_terminal
                restart_driver_sleep_action=none
                ;;
            hook)
                restart_driver_write_hook_failure
                restart_driver_sleep_action=none
                ;;
            none) ;;
            *) return 1 ;;
        esac
    fi
}
restart_driver_reset() {
    command rm -f -- "$restart_driver_start" "$restart_driver_start.next" \
        "$restart_driver_functional" "$restart_driver_functional.next" \
        "$restart_driver_functional_stdout" "$restart_driver_functional_stderr" \
        "$restart_driver_hook" "$restart_driver_hook.next" \
        "$restart_driver_terminal" "$restart_driver_terminal.next" \
        "$restart_driver_stat_count"
    printf '%s\n' 0 >"$restart_driver_stat_count"
    restart_driver_main_pid=0
    restart_driver_restarts=0
    restart_driver_invocation=$restart_initial_invocation_id
    restart_driver_marker=yes
    restart_driver_sleep_action=terminal
    restart_driver_remove_action=normal
    restart_driver_functional_remove_action=normal
    restart_driver_stat_mutation=
    restart_driver_ack_seen=no
    restart_driver_write_start
    restart_driver_write_functional
    restart_driver_release_allowed=no
    restart_driver_control_pid=777
    restart_driver_hook_starttime=888
    restart_driver_terminal_released=no
    restart_driver_terminal_remove_action=normal
    restart_driver_quiescence_action=success
    restart_initial_after_crash_observed=no
    # Consumed dynamically by the sourced production release function.
    # shellcheck disable=SC2034
    restart_initial_hook_pid=777
    # shellcheck disable=SC2034
    restart_initial_hook_starttime=$restart_driver_hook_starttime
}
restart_driver_reset
consume_expected_restart_initial_start_failure "$restart_driver_start"
[ -z "$restart_initial_driver_failure_stage" ]
[ ! -e "$restart_driver_start" ] && [ ! -e "$restart_driver_functional" ]
[ -e "$restart_driver_terminal" ]
[ ! -e "$restart_driver_hook" ]
restart_driver_release_allowed=yes
restart_initial_after_crash_observed=yes
release_expected_restart_initial_terminal \
    "$restart_driver_terminal" "$restart_driver_hook"
[ -z "$restart_initial_driver_failure_stage" ]
[ ! -e "$restart_driver_terminal" ] && [ ! -e "$restart_driver_hook" ]
[ "$restart_initial_after_crash_observed" = no ]
for restart_driver_mutation in \
    main-pid restart-count control-pid invocation marker start-payload stable-inode \
    unlink absence
do
    restart_driver_reset
    case $restart_driver_mutation in
        main-pid) restart_driver_main_pid=1 ;;
        restart-count) restart_driver_restarts=1 ;;
        control-pid) restart_driver_control_pid=778 ;;
        invocation) restart_driver_invocation=22222222222222222222222222222222 ;;
        marker) restart_driver_marker=no ;;
        start-payload) printf '%s\n' mutated >"$restart_driver_start" ;;
        stable-inode) restart_driver_stat_mutation=$restart_driver_start ;;
        unlink) restart_driver_remove_action=fail ;;
        absence) restart_driver_remove_action=retain ;;
    esac
    if consume_expected_restart_initial_start_failure "$restart_driver_start"; then
        printf 'restart initial driver accepted mutation: %s\n' \
            "$restart_driver_mutation" >&2
        exit 1
    fi
    [ "$restart_initial_driver_failure_stage" = "$restart_driver_mutation" ]
done
for restart_driver_functional_mutation in \
    functional-missing functional-payload functional-stdout functional-stderr \
    functional-next functional-stable-inode functional-unlink functional-absence
do
    restart_driver_reset
    case $restart_driver_functional_mutation in
        functional-missing)
            command rm -- "$restart_driver_functional"
            ;;
        functional-payload)
            printf '%s\n' mutated >"$restart_driver_functional"
            ;;
        functional-stdout)
            printf '%s\n%s\n' \
                'VOLPAROSSA_HELPER_V3_FUNCTIONAL_CLIENT_LEASE_V1=ready' \
                'VOLPAROSSA_HELPER_V3_FUNCTIONAL_CLIENT_SETTLED_V1=pass' \
                >"$restart_driver_functional_stdout"
            ;;
        functional-stderr)
            printf '%s\n' mutated >"$restart_driver_functional_stderr"
            ;;
        functional-next)
            printf '%s\n' collision >"$restart_driver_functional.next"
            chmod 0600 "$restart_driver_functional.next"
            ;;
        functional-stable-inode)
            restart_driver_stat_mutation=$restart_driver_functional
            ;;
        functional-unlink)
            restart_driver_functional_remove_action=fail
            ;;
        functional-absence)
            restart_driver_functional_remove_action=retain
            ;;
    esac
    if consume_expected_restart_initial_start_failure "$restart_driver_start"; then
        printf 'restart initial driver accepted functional mutation: %s\n' \
            "$restart_driver_functional_mutation" >&2
        exit 1
    fi
    case $restart_driver_functional_mutation in
        functional-missing|functional-payload|functional-stdout|\
        functional-stderr|functional-next)
            restart_driver_functional_expected_stage=start-payload
            ;;
        functional-stable-inode|functional-unlink|functional-absence)
            restart_driver_functional_expected_stage=stable-inode
            ;;
    esac
    [ "$restart_initial_driver_failure_stage" = \
        "$restart_driver_functional_expected_stage" ]
done
restart_driver_reset
command rm -- "$restart_driver_start"
restart_driver_sleep_action=none
if consume_expected_restart_initial_start_failure "$restart_driver_start"; then
    printf '%s\n' 'restart initial driver accepted missing publication' >&2
    exit 1
fi
[ "$restart_initial_driver_failure_stage" = appearance ]
restart_driver_reset
command rm -- "$restart_driver_start"
ln -s missing "$restart_driver_start"
if consume_expected_restart_initial_start_failure "$restart_driver_start"; then
    printf '%s\n' 'restart initial driver accepted unsafe pending path' >&2
    exit 1
fi
[ "$restart_initial_driver_failure_stage" = unsafe-pending-path ]
command rm -- "$restart_driver_start"
restart_driver_reset
restart_driver_sleep_action=hook
if consume_expected_restart_initial_start_failure "$restart_driver_start"; then
    printf '%s\n' 'restart initial driver accepted post-ACK hook failure' >&2
    exit 1
fi
# Assigned dynamically by the sourced production hook-record reader.
# shellcheck disable=SC2154
[ "$restart_initial_hook_failure_stage" = post-pins ]

# Terminal success cannot be released before the independent after-crash
# observer, and release cannot succeed until the exact old hook has quiesced.
restart_driver_reset
consume_expected_restart_initial_start_failure "$restart_driver_start"
restart_driver_release_allowed=yes
if release_expected_restart_initial_terminal \
    "$restart_driver_terminal" "$restart_driver_hook"; then
    printf '%s\n' 'restart terminal released before after-crash observation' >&2
    exit 1
fi
[ "$restart_initial_driver_failure_stage" = hook-identity ]
[ -e "$restart_driver_terminal" ]
restart_initial_after_crash_observed=yes
for restart_driver_invalid_starttime in \
    process-starttime-v1=888 0 0888 88x 123456789012345678901
do
    restart_driver_hook_starttime=$restart_driver_invalid_starttime
    # Consumed dynamically by the sourced production release function.
    # shellcheck disable=SC2034
    restart_initial_hook_starttime=$restart_driver_hook_starttime
    if release_expected_restart_initial_terminal \
        "$restart_driver_terminal" "$restart_driver_hook"; then
        printf 'restart terminal release accepted invalid hook starttime: %s\n' \
            "$restart_driver_invalid_starttime" >&2
        exit 1
    fi
    [ "$restart_initial_driver_failure_stage" = hook-identity ]
done

restart_driver_reset
consume_expected_restart_initial_start_failure "$restart_driver_start"
restart_driver_release_allowed=yes
restart_initial_after_crash_observed=yes
restart_driver_control_pid=778
if release_expected_restart_initial_terminal \
    "$restart_driver_terminal" "$restart_driver_hook"; then
    printf '%s\n' 'restart terminal release accepted changed ControlPID' >&2
    exit 1
fi
[ "$restart_initial_driver_failure_stage" = control-pid ]

restart_driver_reset
consume_expected_restart_initial_start_failure "$restart_driver_start"
restart_driver_release_allowed=yes
restart_initial_after_crash_observed=yes
printf '%s\n' mutated >"$restart_driver_terminal"
if release_expected_restart_initial_terminal \
    "$restart_driver_terminal" "$restart_driver_hook"; then
    printf '%s\n' 'restart terminal release accepted a mutated terminal payload' >&2
    exit 1
fi
[ "$restart_initial_driver_failure_stage" = terminal-payload ]

restart_driver_reset
consume_expected_restart_initial_start_failure "$restart_driver_start"
restart_driver_release_allowed=yes
restart_initial_after_crash_observed=yes
printf '%s\n' mutated >"$restart_driver_hook"
if release_expected_restart_initial_terminal \
    "$restart_driver_terminal" "$restart_driver_hook"; then
    printf '%s\n' 'restart terminal release accepted a mutated hook payload' >&2
    exit 1
fi
[ "$restart_initial_driver_failure_stage" = hook-payload ]

restart_driver_reset
consume_expected_restart_initial_start_failure "$restart_driver_start"
restart_driver_release_allowed=yes
restart_initial_after_crash_observed=yes
restart_driver_quiescence_action=post-failure
if release_expected_restart_initial_terminal \
    "$restart_driver_terminal" "$restart_driver_hook"; then
    printf '%s\n' 'restart terminal release accepted late hook failure' >&2
    exit 1
fi
[ "$restart_initial_driver_failure_stage" = hook-quiescence ]
[ "$restart_initial_hook_failure_stage" = terminal-post-pins ]
[ ! -e "$restart_driver_terminal" ]

restart_driver_reset
consume_expected_restart_initial_start_failure "$restart_driver_start"
restart_driver_release_allowed=yes
restart_initial_after_crash_observed=yes
restart_driver_quiescence_action=timeout
if release_expected_restart_initial_terminal \
    "$restart_driver_terminal" "$restart_driver_hook"; then
    printf '%s\n' 'restart terminal release accepted a live old hook timeout' >&2
    exit 1
fi
[ "$restart_initial_driver_failure_stage" = hook-quiescence ]
[ -e "$restart_driver_terminal" ] || [ "$restart_driver_terminal_released" = yes ]

unset -f vp_capture_file_is_safe systemctl unit_current_invocation_id \
    unit_description_matches_marker stat rm sleep capture_process_starttime

# The still-live first ExecStartPost publishes the fixed cleanup failure itself
# and treats the driver's unlink as an acknowledgement. Model success, unlink
# during validation, timeout, payload/.next mutation, lineage loss, and any
# premature NRestarts transition without systemd or network privileges.
restart_initial_ack_function=$tmp/restart-initial-failure-ack-function.sh
restart_initial_stage_functions=$tmp/restart-initial-failure-stage-functions.sh
{
    sed -n '/^restart_initial_handshake_failure_stage_is_safe() {$/,/^}$/p' \
        "$hook"
    sed -n '/^set_restart_initial_handshake_failure_stage() {$/,/^}$/p' \
        "$hook"
} >"$restart_initial_stage_functions"
sed -n '/^publish_and_wait_for_restart_initial_failure_ack() {$/,/^}$/p' \
    "$hook" >"$restart_initial_ack_function"
[ "$(grep -c '^[_a-z].*() {$' "$restart_initial_stage_functions")" -eq 2 ]
[ "$(grep -c '^publish_and_wait_for_restart_initial_failure_ack() {$' \
    "$restart_initial_ack_function")" -eq 1 ]
grep -F 'hook_restart_failure_wait" -ge 600' \
    "$restart_initial_ack_function" >/dev/null
[ "$(grep -Fc 'org.freedesktop.systemd1.Service NRestarts' \
    "$restart_initial_ack_function")" -eq 3 ]
[ "$(grep -Fc 'org.freedesktop.systemd1.Service ControlPID' \
    "$restart_initial_ack_function")" -eq 3 ]
[ "$(grep -Fc 'unit_invocation_id "$hook_restart_failure_unit"' \
    "$restart_initial_ack_function")" -eq 3 ]
# shellcheck disable=SC1090,SC2317
. "$restart_initial_stage_functions"
# shellcheck disable=SC1090,SC2317
. "$restart_initial_ack_function"
restart_ack_sleep_count=$tmp/restart-ack-sleep-count
restart_ack_safe_count=$tmp/restart-ack-safe-count
start_failure_record=$tmp/restart-initial.start.failure
restart_initial_handshake_failure_record=$tmp/restart-initial.handshake.failure
restart_initial_handshake_terminal_record=$tmp/restart-initial.handshake.terminal
restart_initial_release_authorized_record=$tmp/restart-initial.release-authorized
functional_failure_record=$tmp/restart-initial.functional.failure
restart_ack_main_pid=0
restart_ack_restarts=0
restart_ack_control_pid=$$
restart_ack_invocation=11111111111111111111111111111111
restart_ack_action=ack
restart_ack_action_after=2
restart_ack_safe_unlink=no
restart_ack_pin_mutated=no
restart_ack_publication_status=0
unit_name_is_safe() { [ "$1" = volparossa-helper-live-proof-a1b2c3.service ]; }
invocation_id_is_safe() {
    [ "$1" = 11111111111111111111111111111111 ]
}
kernel_object_identity_is_safe() { [ "$1" = 10:20 ] || [ "$1" = 30:40 ]; }
unit_main_pid() { printf '%s\n' "$restart_ack_main_pid"; }
unit_u32_property() {
    [ "$#" -eq 3 ] || return 1
    case $3 in
        NRestarts) printf '%s\n' "$restart_ack_restarts" ;;
        ControlPID) printf '%s\n' "$restart_ack_control_pid" ;;
        *) return 1 ;;
    esac
}
unit_invocation_id() { printf '%s\n' "$restart_ack_invocation"; }
stat() {
    [ "$#" -eq 3 ] || return 1
    restart_ack_path=$3
    case $restart_ack_path in
        /proc/self/fd/8)
            if [ "$restart_ack_pin_mutated" = yes ]; then
                printf '%s\n' 50:60
            else
                printf '%s\n' 10:20
            fi
            ;;
        /proc/self/fd/7) printf '%s\n' 30:40 ;;
        *) command stat "$@" ;;
    esac
}
private_file_is_safe() {
    restart_ack_safe_calls=$(cat "$restart_ack_safe_count") || return 1
    printf '%s\n' $((restart_ack_safe_calls + 1)) >"$restart_ack_safe_count"
    if [ "$restart_ack_safe_unlink" = yes ]; then
        rm -f -- "$1"
        restart_ack_safe_unlink=no
        return 1
    fi
    [ -f "$1" ] && [ ! -L "$1" ] \
        && [ "$(command stat -Lc '%a:%h' "$1")" = 600:1 ]
}
publish_start_failure() {
    [ "$start_failure_armed" = yes ] \
        && [ "$start_failure_published" = no ] || return 1
    [ "$restart_ack_publication_status" -eq 0 ] || return 1
    printf '%s\n' \
        'VOLPAROSSA_HELPER_V3_IPC_START_FAILURE_STAGE_V1=functional-client-release' \
        >"$start_failure_record" || return 1
    chmod 0600 "$start_failure_record" || return 1
    start_failure_published=yes
}
publish_restart_initial_handshake_terminal() {
    [ "$restart_initial_handshake_armed" = yes ] || return 1
    printf '%s\n' \
        'VOLPAROSSA_HELPER_V3_RESTART_INITIAL_HANDSHAKE_TERMINAL_V1=success' \
        >"$restart_initial_handshake_terminal_record" || return 1
    chmod 0600 "$restart_initial_handshake_terminal_record"
}
sleep() {
    restart_ack_sleeps=$(cat "$restart_ack_sleep_count") || return 1
    restart_ack_sleeps=$((restart_ack_sleeps + 1))
    printf '%s\n' "$restart_ack_sleeps" >"$restart_ack_sleep_count"
    [ "$restart_ack_sleeps" -eq "$restart_ack_action_after" ] || return 0
    case $restart_ack_action in
        ack) rm -f -- "$start_failure_record" ;;
        content) printf '%s\n' mutated >"$start_failure_record" ;;
        next) printf '%s\n' collision >"$start_failure_record.next" ;;
        invocation) restart_ack_invocation=22222222222222222222222222222222 ;;
        restart) restart_ack_restarts=1 ;;
        control) restart_ack_control_pid=0 ;;
        pin) restart_ack_pin_mutated=yes ;;
        post-lineage)
            rm -f -- "$start_failure_record"
            restart_ack_main_pid=1
            ;;
        post-pins)
            rm -f -- "$start_failure_record"
            restart_ack_pin_mutated=yes
            ;;
        none) ;;
        *) return 1 ;;
    esac
}
restart_reset_ack_model() {
    rm -f -- "$start_failure_record" "$start_failure_record.next" \
        "$restart_initial_handshake_failure_record" \
        "$restart_initial_handshake_failure_record.next" \
        "$restart_initial_handshake_terminal_record" \
        "$restart_initial_handshake_terminal_record.next" \
        "$restart_initial_release_authorized_record" \
        "$restart_initial_release_authorized_record.next" \
        "$functional_failure_record" "$functional_failure_record.next"
    printf '%s\n' 0 >"$restart_ack_sleep_count"
    printf '%s\n' 0 >"$restart_ack_safe_count"
    restart_ack_main_pid=0
    restart_ack_restarts=0
    restart_ack_control_pid=$$
    restart_ack_invocation=11111111111111111111111111111111
    restart_ack_action=ack
    restart_ack_action_after=2
    restart_ack_safe_unlink=no
    restart_ack_pin_mutated=no
    restart_ack_publication_status=0
    start_failure_stage=functional-client-release
    start_failure_armed=yes
    start_failure_published=no
    restart_initial_handshake_armed=yes
    restart_initial_handshake_failure_stage=preflight
    restart_initial_handshake_terminal_ready=no
}
for restart_initial_stage in \
    preflight publication ack-path ack-payload ack-lineage ack-pins \
    ack-timeout post-lineage post-pins cleanup terminal-publication \
    terminal-ack-path terminal-ack-payload terminal-ack-lineage \
    terminal-ack-pins terminal-ack-timeout terminal-post-lineage \
    terminal-post-pins
do
    restart_initial_handshake_failure_stage_is_safe "$restart_initial_stage"
done
if restart_initial_handshake_failure_stage_is_safe private-runtime-detail \
    || restart_initial_handshake_failure_stage_is_safe '';
then
    printf '%s\n' 'initial handshake stage allowlist accepted private detail' >&2
    exit 1
fi
restart_reset_ack_model
publish_and_wait_for_restart_initial_failure_ack \
    volparossa-helper-live-proof-a1b2c3.service \
    11111111111111111111111111111111 10:20 30:40
[ "$start_failure_published" = yes ]
[ "$restart_initial_handshake_armed" = yes ]
[ "$restart_initial_handshake_failure_stage" = cleanup ]
[ "$restart_initial_handshake_terminal_ready" = yes ]
[ ! -e "$restart_initial_handshake_failure_record" ] \
    && [ ! -L "$restart_initial_handshake_failure_record" ]
[ ! -e "$restart_initial_handshake_terminal_record" ] \
    && [ ! -L "$restart_initial_handshake_terminal_record" ]
[ "$(cat "$restart_ack_sleep_count")" -eq 2 ]
[ ! -e "$start_failure_record" ] && [ ! -L "$start_failure_record" ]
restart_reset_ack_model
restart_ack_safe_unlink=yes
publish_and_wait_for_restart_initial_failure_ack \
    volparossa-helper-live-proof-a1b2c3.service \
    11111111111111111111111111111111 10:20 30:40
[ "$start_failure_published" = yes ]
[ "$restart_initial_handshake_armed" = yes ]
[ "$restart_initial_handshake_failure_stage" = cleanup ]
[ "$restart_initial_handshake_terminal_ready" = yes ]
[ ! -e "$restart_initial_handshake_failure_record" ] \
    && [ ! -L "$restart_initial_handshake_failure_record" ]
[ ! -e "$restart_initial_handshake_terminal_record" ] \
    && [ ! -L "$restart_initial_handshake_terminal_record" ]
[ ! -e "$start_failure_record" ] && [ ! -L "$start_failure_record" ]
for restart_ack_mutation in \
    content next invocation restart control pin post-lineage post-pins
do
    restart_reset_ack_model
    restart_ack_action=$restart_ack_mutation
    restart_ack_action_after=1
    if publish_and_wait_for_restart_initial_failure_ack \
        volparossa-helper-live-proof-a1b2c3.service \
        11111111111111111111111111111111 10:20 30:40; then
        printf 'initial failure ACK accepted mutation: %s\n' \
            "$restart_ack_mutation" >&2
        exit 1
    fi
    case $restart_ack_mutation in
        content)
            restart_ack_expected_stage=ack-payload
            restart_ack_expected_path=present
            ;;
        next)
            restart_ack_expected_stage=ack-path
            restart_ack_expected_path=present
            ;;
        invocation|restart|control)
            restart_ack_expected_stage=ack-lineage
            restart_ack_expected_path=present
            ;;
        pin)
            restart_ack_expected_stage=ack-pins
            restart_ack_expected_path=present
            ;;
        post-lineage)
            restart_ack_expected_stage=post-lineage
            restart_ack_expected_path=absent
            ;;
        post-pins)
            restart_ack_expected_stage=post-pins
            restart_ack_expected_path=absent
            ;;
    esac
    [ "$restart_initial_handshake_failure_stage" = \
        "$restart_ack_expected_stage" ]
    case $restart_ack_expected_path in
        present) [ -e "$start_failure_record" ] || [ -L "$start_failure_record" ] ;;
        absent) [ ! -e "$start_failure_record" ] && [ ! -L "$start_failure_record" ] ;;
    esac
done
restart_reset_ack_model
restart_ack_main_pid=1
if publish_and_wait_for_restart_initial_failure_ack \
    volparossa-helper-live-proof-a1b2c3.service \
    11111111111111111111111111111111 10:20 30:40; then
    printf '%s\n' 'initial failure ACK accepted a preflight lineage mutation' >&2
    exit 1
fi
[ "$restart_initial_handshake_failure_stage" = preflight ]
restart_reset_ack_model
restart_ack_publication_status=1
if publish_and_wait_for_restart_initial_failure_ack \
    volparossa-helper-live-proof-a1b2c3.service \
    11111111111111111111111111111111 10:20 30:40; then
    printf '%s\n' 'initial failure ACK accepted publication failure' >&2
    exit 1
fi
[ "$restart_initial_handshake_failure_stage" = publication ]
restart_reset_ack_model
restart_ack_action=none
restart_ack_action_after=601
if publish_and_wait_for_restart_initial_failure_ack \
    volparossa-helper-live-proof-a1b2c3.service \
    11111111111111111111111111111111 10:20 30:40; then
    printf '%s\n' 'initial failure ACK accepted an unacknowledged timeout' >&2
    exit 1
fi
[ "$(cat "$restart_ack_sleep_count")" -eq 599 ]
[ -e "$start_failure_record" ] && [ ! -L "$start_failure_record" ]
[ "$restart_initial_handshake_failure_stage" = ack-timeout ]

# Terminal success belongs to the EXIT cleanup path and remains manager-bound
# until the root driver releases it. Model exact ACK, unlink during validation,
# dual-record/path/payload/lineage/pin mutations, post-ACK failures and timeout.
restart_initial_terminal_ack_function=$tmp/restart-initial-terminal-ack-function.sh
sed -n '/^publish_and_wait_for_restart_initial_terminal_ack() {$/,/^}$/p' \
    "$hook" >"$restart_initial_terminal_ack_function"
[ "$(grep -c '^publish_and_wait_for_restart_initial_terminal_ack() {$' \
    "$restart_initial_terminal_ack_function")" -eq 1 ]
[ "$(grep -Fc 'org.freedesktop.systemd1.Service ControlPID' \
    "$restart_initial_terminal_ack_function")" -eq 2 ]
# shellcheck disable=SC1090,SC2317
. "$restart_initial_terminal_ack_function"
restart_terminal_action=ack
restart_terminal_action_after=2
restart_terminal_sleep_count=$tmp/restart-terminal-sleep-count
sleep() {
    restart_terminal_sleeps=$(cat "$restart_terminal_sleep_count") || return 1
    restart_terminal_sleeps=$((restart_terminal_sleeps + 1))
    printf '%s\n' "$restart_terminal_sleeps" >"$restart_terminal_sleep_count"
    [ "$restart_terminal_sleeps" -eq "$restart_terminal_action_after" ] || return 0
    case $restart_terminal_action in
        ack) rm -f -- "$restart_initial_handshake_terminal_record" ;;
        content) printf '%s\n' mutated >"$restart_initial_handshake_terminal_record" ;;
        next) printf '%s\n' collision >"$restart_initial_handshake_terminal_record.next" ;;
        dual)
            printf '%s\n' \
                'VOLPAROSSA_HELPER_V3_RESTART_INITIAL_HANDSHAKE_FAILURE_V1=terminal-ack-path' \
                >"$restart_initial_handshake_failure_record"
            chmod 0600 "$restart_initial_handshake_failure_record"
            ;;
        invocation) restart_ack_invocation=22222222222222222222222222222222 ;;
        restart) restart_ack_restarts=1 ;;
        control) restart_ack_control_pid=0 ;;
        pin) restart_ack_pin_mutated=yes ;;
        post-lineage)
            rm -f -- "$restart_initial_handshake_terminal_record"
            restart_ack_main_pid=1
            ;;
        post-pins)
            rm -f -- "$restart_initial_handshake_terminal_record"
            restart_ack_pin_mutated=yes
            ;;
        none) ;;
        *) return 1 ;;
    esac
}
restart_reset_terminal_model() {
    rm -f -- "$start_failure_record" "$start_failure_record.next" \
        "$restart_initial_handshake_failure_record" \
        "$restart_initial_handshake_failure_record.next" \
        "$restart_initial_handshake_terminal_record" \
        "$restart_initial_handshake_terminal_record.next" \
        "$restart_initial_release_authorized_record" \
        "$restart_initial_release_authorized_record.next" \
        "$functional_failure_record" "$functional_failure_record.next"
    printf '%s\n' 0 >"$restart_terminal_sleep_count"
    printf '%s\n' 0 >"$restart_ack_safe_count"
    restart_ack_main_pid=0
    restart_ack_restarts=0
    restart_ack_control_pid=$$
    restart_ack_invocation=11111111111111111111111111111111
    restart_ack_pin_mutated=no
    restart_ack_safe_unlink=no
    restart_terminal_action=ack
    restart_terminal_action_after=2
    restart_initial_handshake_armed=yes
    restart_initial_handshake_failure_stage=terminal-publication
    restart_initial_handshake_terminal_ready=yes
}
restart_reset_terminal_model
publish_and_wait_for_restart_initial_terminal_ack
[ "$restart_initial_handshake_armed" = no ]
[ "$restart_initial_handshake_terminal_ready" = no ]
[ -z "$restart_initial_handshake_failure_stage" ]
[ ! -e "$restart_initial_handshake_terminal_record" ]
[ "$(cat "$restart_terminal_sleep_count")" -eq 2 ]
restart_reset_terminal_model
restart_ack_safe_unlink=yes
publish_and_wait_for_restart_initial_terminal_ack
[ "$restart_initial_handshake_armed" = no ]
[ ! -e "$restart_initial_handshake_terminal_record" ]
for restart_terminal_mutation in \
    content next dual invocation restart control pin post-lineage post-pins
do
    restart_reset_terminal_model
    restart_terminal_action=$restart_terminal_mutation
    restart_terminal_action_after=1
    if publish_and_wait_for_restart_initial_terminal_ack; then
        printf 'initial terminal ACK accepted mutation: %s\n' \
            "$restart_terminal_mutation" >&2
        exit 1
    fi
    case $restart_terminal_mutation in
        content) restart_terminal_expected_stage=terminal-ack-payload ;;
        next|dual) restart_terminal_expected_stage=terminal-ack-path ;;
        invocation|restart|control)
            restart_terminal_expected_stage=terminal-ack-lineage
            ;;
        pin) restart_terminal_expected_stage=terminal-ack-pins ;;
        post-lineage) restart_terminal_expected_stage=terminal-post-lineage ;;
        post-pins) restart_terminal_expected_stage=terminal-post-pins ;;
    esac
    [ "$restart_initial_handshake_failure_stage" = \
        "$restart_terminal_expected_stage" ]
done
for restart_terminal_residue in \
    authorization-record authorization-pending \
    authorization-record-symlink authorization-pending-symlink \
    functional-record functional-pending \
    functional-record-symlink functional-pending-symlink
do
    restart_reset_terminal_model
    case $restart_terminal_residue in
        authorization-record)
            printf '%s\n' \
                'VOLPAROSSA_HELPER_V3_RESTART_INITIAL_RELEASE_AUTHORIZED_V1=pass' \
                >"$restart_initial_release_authorized_record"
            chmod 0600 "$restart_initial_release_authorized_record"
            ;;
        authorization-pending)
            printf '%s\n' pending >"$restart_initial_release_authorized_record.next"
            chmod 0600 "$restart_initial_release_authorized_record.next"
            ;;
        authorization-record-symlink)
            ln -s "$tmp/restart-terminal-missing-record-target" \
                "$restart_initial_release_authorized_record"
            ;;
        authorization-pending-symlink)
            ln -s "$tmp/restart-terminal-missing-pending-target" \
                "$restart_initial_release_authorized_record.next"
            ;;
        functional-record)
            printf '%s\n' \
                'VOLPAROSSA_HELPER_V3_FUNCTIONAL_CLIENT_LEASE_FAILURE_V1=destroy,protocol' \
                >"$functional_failure_record"
            chmod 0600 "$functional_failure_record"
            ;;
        functional-pending)
            printf '%s\n' pending >"$functional_failure_record.next"
            chmod 0600 "$functional_failure_record.next"
            ;;
        functional-record-symlink)
            ln -s "$tmp/restart-terminal-missing-functional-target" \
                "$functional_failure_record"
            ;;
        functional-pending-symlink)
            ln -s "$tmp/restart-terminal-missing-functional-pending-target" \
                "$functional_failure_record.next"
            ;;
    esac
    if publish_and_wait_for_restart_initial_terminal_ack; then
        printf 'initial terminal ACK accepted restart residue: %s\n' \
            "$restart_terminal_residue" >&2
        exit 1
    fi
    [ "$restart_initial_handshake_failure_stage" = terminal-post-pins ]
done
restart_reset_terminal_model
restart_terminal_action=none
restart_terminal_action_after=601
if publish_and_wait_for_restart_initial_terminal_ack; then
    printf '%s\n' 'initial terminal ACK accepted an unacknowledged timeout' >&2
    exit 1
fi
[ "$(cat "$restart_terminal_sleep_count")" -eq 599 ]
[ "$restart_initial_handshake_failure_stage" = terminal-ack-timeout ]
[ -e "$restart_initial_handshake_terminal_record" ]

# Once the synchronous path owns publication, EXIT cleanup may clean fixtures
# but must never create a second failure record, including on prepublish error.
restart_exit_function=$tmp/restart-start-failure-exit-function.sh
sed -n '/^start_failure_exit() {$/,/^}$/p' "$hook" >"$restart_exit_function"
# shellcheck disable=SC1090
. "$restart_exit_function"
restart_exit_republish_marker=$tmp/restart-exit-republish.marker
set +e
(
    set +e
    # Consumed by the sourced EXIT handler.
    # shellcheck disable=SC2034
    functional_fixture_shape=single
    # shellcheck disable=SC2034
    functional_relay_state=absent
    # shellcheck disable=SC2034
    functional_exit_relay_state=absent
    start_failure_armed=yes
    start_failure_published=no
    # shellcheck disable=SC2034
    start_failure_exit_publication=no
    # shellcheck disable=SC2034
    restart_initial_handshake_armed=no
    remove_functional_relay_fixture() { return 0; }
    remove_functional_exit_relay_fixture() { return 0; }
    publish_start_failure() { : >"$restart_exit_republish_marker"; }
    false
    start_failure_exit
)
restart_exit_status=$?
set -e
[ "$restart_exit_status" -eq 1 ]
[ ! -e "$restart_exit_republish_marker" ] \
    && [ ! -L "$restart_exit_republish_marker" ]
restart_exit_handshake_record=$tmp/restart-exit-handshake.failure
set +e
(
    set +e
    # Consumed by the sourced EXIT handler.
    # shellcheck disable=SC2034
    functional_fixture_shape=single
    # shellcheck disable=SC2034
    functional_relay_state=absent
    # shellcheck disable=SC2034
    functional_exit_relay_state=absent
    start_failure_armed=yes
    start_failure_published=no
    # shellcheck disable=SC2034
    start_failure_exit_publication=no
    restart_initial_handshake_armed=yes
    restart_initial_handshake_failure_stage=ack-payload
    restart_initial_handshake_terminal_ready=no
    remove_functional_relay_fixture() { return 0; }
    remove_functional_exit_relay_fixture() { return 0; }
    publish_start_failure() { : >"$restart_exit_republish_marker"; }
    publish_restart_initial_handshake_failure() {
        [ ! -e "$restart_exit_handshake_record" ] \
            && [ ! -L "$restart_exit_handshake_record" ] || return 1
        printf '%s\n' \
            'VOLPAROSSA_HELPER_V3_RESTART_INITIAL_HANDSHAKE_FAILURE_V1=ack-payload' \
            >"$restart_exit_handshake_record"
    }
    false
    start_failure_exit
)
restart_exit_status=$?
set -e
[ "$restart_exit_status" -eq 1 ]
printf '%s\n' \
    'VOLPAROSSA_HELPER_V3_RESTART_INITIAL_HANDSHAKE_FAILURE_V1=ack-payload' \
    | cmp -s - "$restart_exit_handshake_record"
[ ! -e "$restart_exit_republish_marker" ] \
    && [ ! -L "$restart_exit_republish_marker" ]

restart_exit_order=$tmp/restart-exit-order
restart_exit_failure_marker=$tmp/restart-exit-failure.marker
set +e
(
    set +e
    # Consumed by the sourced EXIT handler.
    # shellcheck disable=SC2034
    functional_fixture_shape=single
    # shellcheck disable=SC2034
    functional_relay_state=present
    # shellcheck disable=SC2034
    functional_exit_relay_state=absent
    start_failure_armed=yes
    start_failure_published=yes
    # shellcheck disable=SC2034
    start_failure_exit_publication=no
    restart_initial_handshake_armed=yes
    restart_initial_handshake_failure_stage=cleanup
    restart_initial_handshake_terminal_ready=yes
    remove_functional_relay_fixture() {
        printf '%s\n' cleanup >>"$restart_exit_order"
    }
    remove_functional_exit_relay_fixture() { return 0; }
    publish_and_wait_for_restart_initial_terminal_ack() {
        [ "$(cat "$restart_exit_order")" = cleanup ] || return 1
        printf '%s\n' terminal >>"$restart_exit_order"
        restart_initial_handshake_armed=no
        restart_initial_handshake_terminal_ready=no
    }
    publish_restart_initial_handshake_failure() {
        : >"$restart_exit_failure_marker"
    }
    false
    start_failure_exit
)
restart_exit_status=$?
set -e
[ "$restart_exit_status" -eq 1 ]
printf '%s\n' cleanup terminal | cmp -s - "$restart_exit_order"
[ ! -e "$restart_exit_failure_marker" ]

rm -f -- "$restart_exit_order" "$restart_exit_failure_marker"
set +e
(
    set +e
    # Consumed by the sourced EXIT handler.
    # shellcheck disable=SC2034
    functional_fixture_shape=single
    # shellcheck disable=SC2034
    functional_relay_state=present
    # shellcheck disable=SC2034
    functional_exit_relay_state=absent
    start_failure_armed=yes
    start_failure_published=yes
    # shellcheck disable=SC2034
    start_failure_exit_publication=no
    restart_initial_handshake_armed=yes
    restart_initial_handshake_failure_stage=cleanup
    restart_initial_handshake_terminal_ready=yes
    remove_functional_relay_fixture() {
        printf '%s\n' cleanup-failed >>"$restart_exit_order"
        return 1
    }
    remove_functional_exit_relay_fixture() { return 0; }
    publish_and_wait_for_restart_initial_terminal_ack() {
        printf '%s\n' terminal >>"$restart_exit_order"
    }
    publish_restart_initial_handshake_failure() {
        printf '%s\n' "$restart_initial_handshake_failure_stage" \
            >"$restart_exit_failure_marker"
    }
    false
    start_failure_exit
)
restart_exit_status=$?
set -e
[ "$restart_exit_status" -eq 1 ]
[ "$(cat "$restart_exit_order")" = cleanup-failed ]
[ "$(cat "$restart_exit_failure_marker")" = cleanup ]

restart_stage_functions=$tmp/restart-start-stage-functions.sh
{
    sed -n '/^restart_start_failure_stage_is_safe() {$/,/^}$/p' "$hook"
    sed -n '/^advance_restart_start_failure_stage() {$/,/^}$/p' "$hook"
} >"$restart_stage_functions"
[ "$(grep -c '^[_a-z].*() {$' "$restart_stage_functions")" -eq 2 ]
sh -n "$restart_stage_functions"
# shellcheck disable=SC1090
. "$restart_stage_functions"
restart_expected_stages=$tmp/restart-expected-start-stages
printf '%s\n' \
    restart-recovery-wait \
    restart-lineage \
    restart-descriptor-settlement \
    restart-journal-settlement \
    restart-socket-validation \
    restart-publication >"$restart_expected_stages"
while IFS= read -r restart_expected_stage; do
    restart_start_failure_stage_is_safe "$restart_expected_stage"
done <"$restart_expected_stages"
if restart_start_failure_stage_is_safe functional-client-release \
    || restart_start_failure_stage_is_safe functional-client-cleanup \
    || restart_start_failure_stage_is_safe restart-private-detail; then
    printf '%s\n' 'successor start stage allowlist accepted another graph' >&2
    exit 1
fi
start_failure_stage=preflight-runtime
while IFS= read -r restart_expected_stage; do
    advance_restart_start_failure_stage "$restart_expected_stage"
done <"$restart_expected_stages"
[ "$start_failure_stage" = restart-publication ]
start_failure_stage=preflight-runtime
if advance_restart_start_failure_stage restart-lineage; then
    printf '%s\n' 'successor stage graph accepted a skipped recovery fence' >&2
    exit 1
fi
start_failure_stage=restart-descriptor-settlement
if advance_restart_start_failure_stage restart-lineage \
    || advance_restart_start_failure_stage restart-private-detail; then
    printf '%s\n' 'successor stage graph accepted a reverse or unbounded edge' >&2
    exit 1
fi
grep -F 'restart_start_failure_stage_is_safe "$start_failure_stage"' \
    "$hook" >/dev/null
for restart_expected_stage in \
    restart-recovery-wait \
    restart-lineage \
    restart-descriptor-settlement \
    restart-journal-settlement \
    restart-socket-validation \
    restart-publication
do
    [ "$(grep -Fc \
        "advance_restart_start_failure_stage $restart_expected_stage" \
        "$hook")" -eq 1 ]
done
[ "$(grep -Fc 'wait_for_restart_fdstore_settlement \' "$hook")" -eq 1 ]

# The recovery observer runs while GDB is stopped at the removal-function
# entry. Model only the exact manager transition 2 -> 0 and require stable
# empty observation bracketed by the same PID and InvocationID.
restart_settlement_function=$tmp/restart-fdstore-settlement-function.sh
sed -n '/^wait_for_restart_fdstore_settlement() {$/,/^}$/p' \
    "$hook" >"$restart_settlement_function"
[ "$(grep -c '^wait_for_restart_fdstore_settlement() {$' \
    "$restart_settlement_function")" -eq 1 ]
[ "$(grep -Fc 'unit_main_pid "$hook_restart_settlement_unit"' \
    "$restart_settlement_function")" -eq 2 ]
[ "$(grep -Fc 'unit_invocation_id "$hook_restart_settlement_unit"' \
    "$restart_settlement_function")" -eq 2 ]
grep -F '2) ;;' "$restart_settlement_function" >/dev/null
grep -F '0)' "$restart_settlement_function" >/dev/null
grep -F '*) return 1 ;;' "$restart_settlement_function" >/dev/null
grep -F 'hook_restart_settlement_wait" -lt 900' \
    "$restart_settlement_function" >/dev/null
# shellcheck disable=SC1090,SC2317
. "$restart_settlement_function"
restart_settlement_sequence=$tmp/restart-settlement-sequence
restart_settlement_index=$tmp/restart-settlement-index
restart_settlement_empty_calls=$tmp/restart-settlement-empty-calls
restart_settlement_pid=4242
restart_settlement_invocation=11111111111111111111111111111111
restart_settlement_post_pid=
restart_settlement_post_invocation=
restart_settlement_empty_status=0
unit_name_is_safe() { [ "$1" = volparossa-helper-live-proof-a1b2c3.service ]; }
number_is_safe() { [ "$1" = 4242 ]; }
invocation_id_is_safe() {
    [ "${#1}" -eq 32 ] && [ "$1" != 00000000000000000000000000000000 ]
}
unit_main_pid() {
    if [ "$(cat "$restart_settlement_empty_calls")" -gt 0 ] \
        && [ -n "$restart_settlement_post_pid" ]; then
        printf '%s\n' "$restart_settlement_post_pid"
    else
        printf '%s\n' "$restart_settlement_pid"
    fi
}
unit_invocation_id() {
    if [ "$(cat "$restart_settlement_empty_calls")" -gt 0 ] \
        && [ -n "$restart_settlement_post_invocation" ]; then
        printf '%s\n' "$restart_settlement_post_invocation"
    else
        printf '%s\n' "$restart_settlement_invocation"
    fi
}
unit_u32_property() {
    restart_model_index=$(cat "$restart_settlement_index") || return 1
    restart_model_value=$(sed -n "${restart_model_index}p" \
        "$restart_settlement_sequence") || return 1
    [ -n "$restart_model_value" ] || return 1
    printf '%s\n' $((restart_model_index + 1)) >"$restart_settlement_index"
    printf '%s\n' "$restart_model_value"
}
unit_fdstore_is_empty() {
    restart_model_empty_calls=$(cat "$restart_settlement_empty_calls") || return 1
    printf '%s\n' $((restart_model_empty_calls + 1)) \
        >"$restart_settlement_empty_calls"
    hook_fdstore_count_before=0
    hook_fdstore_count_after=0
    [ "$restart_settlement_empty_status" -eq 0 ]
}
sleep() { :; }
restart_reset_settlement_model() {
    printf '%s\n' 1 >"$restart_settlement_index"
    printf '%s\n' 0 >"$restart_settlement_empty_calls"
    restart_settlement_post_pid=
    restart_settlement_post_invocation=
}
printf '%s\n' 2 2 0 >"$restart_settlement_sequence"
restart_reset_settlement_model
wait_for_restart_fdstore_settlement \
    volparossa-helper-live-proof-a1b2c3.service 4242 \
    11111111111111111111111111111111
[ "$(cat "$restart_settlement_index")" -eq 4 ]
[ "$(cat "$restart_settlement_empty_calls")" -eq 1 ]
[ "$hook_fdstore_count_before:$hook_fdstore_count_after" = 0:0 ]
printf '%s\n' 1 >"$restart_settlement_sequence"
restart_reset_settlement_model
if wait_for_restart_fdstore_settlement \
    volparossa-helper-live-proof-a1b2c3.service 4242 \
    11111111111111111111111111111111; then
    printf '%s\n' 'restart settlement accepted a manager count other than 2 -> 0' >&2
    exit 1
fi
printf '%s\n' 0 >"$restart_settlement_sequence"
restart_reset_settlement_model
restart_settlement_empty_status=1
if wait_for_restart_fdstore_settlement \
    volparossa-helper-live-proof-a1b2c3.service 4242 \
    11111111111111111111111111111111; then
    printf '%s\n' 'restart settlement accepted an invalid stable-empty dump' >&2
    exit 1
fi
restart_settlement_empty_status=0
restart_settlement_post_pid=4243
restart_reset_settlement_model
restart_settlement_post_pid=4243
if wait_for_restart_fdstore_settlement \
    volparossa-helper-live-proof-a1b2c3.service 4242 \
    11111111111111111111111111111111; then
    printf '%s\n' 'restart settlement accepted a post-empty MainPID change' >&2
    exit 1
fi
restart_reset_settlement_model
restart_settlement_post_invocation=22222222222222222222222222222222
if wait_for_restart_fdstore_settlement \
    volparossa-helper-live-proof-a1b2c3.service 4242 \
    11111111111111111111111111111111; then
    printf '%s\n' 'restart settlement accepted a post-empty InvocationID change' >&2
    exit 1
fi
awk 'BEGIN { for (i = 1; i <= 900; i++) print 2 }' \
    >"$restart_settlement_sequence"
restart_reset_settlement_model
if wait_for_restart_fdstore_settlement \
    volparossa-helper-live-proof-a1b2c3.service 4242 \
    11111111111111111111111111111111; then
    printf '%s\n' 'restart settlement accepted a nonterminating two-FD state' >&2
    exit 1
fi
[ "$(cat "$restart_settlement_index")" -eq 901 ]
[ "$(cat "$restart_settlement_empty_calls")" -eq 0 ]

# Empty fdstore precedes both journal continuation and socket bind. Exercise a
# later journal and still-later socket, plus authenticated bind readiness,
# inode reuse, unsafe/disappearing sockets, final bracket changes, and timeout.
restart_readiness_function=$tmp/restart-readiness-function.sh
{
    sed -n '/^run_restart_bind_probe() {$/,/^}$/p' "$hook"
    sed -n '/^restart_uptime_seconds() {$/,/^}$/p' "$hook"
    sed -n '/^restart_monotonic_seconds() {$/,/^}$/p' "$hook"
    sed -n '/^wait_for_restart_readiness() {$/,/^}$/p' "$hook"
    sed -n '/^restart_readiness_failure_stage_is_safe() {$/,/^}$/p' "$hook"
} >"$restart_readiness_function"
[ "$(grep -c '^[_a-z].*() {$' "$restart_readiness_function")" -eq 5 ]
[ "$(grep -c '^wait_for_restart_readiness() {$' \
    "$restart_readiness_function")" -eq 1 ]
[ "$(grep -Fc 'unit_main_pid "$hook_restart_ready_unit"' \
    "$restart_readiness_function")" -eq 2 ]
[ "$(grep -Fc 'unit_invocation_id "$hook_restart_ready_unit"' \
    "$restart_readiness_function")" -eq 2 ]
[ "$(grep -Fc 'capture_socket_identity' "$restart_readiness_function")" -eq 2 ]
[ "$(grep -Fc 'capture_journal_state' "$restart_readiness_function")" -eq 2 ]
grep -F 'hook_restart_ready_deadline=$((hook_restart_ready_started + 40))' \
    "$restart_readiness_function" >/dev/null
grep -F 'hook_restart_ready_wait" -lt 900' \
    "$restart_readiness_function" >/dev/null
grep -F '</proc/uptime' "$restart_readiness_function" >/dev/null
test "$(grep -Fc \
    'const PROBE_TIMEOUT: Duration = Duration::from_secs(5);' \
    "$functional_probe")" -eq 1
grep -F -- '--groups="$hook_restart_bind_groups"' \
    "$restart_readiness_function" >/dev/null
grep -F '"$probe" bind-runtime "$hook_restart_bind_pid"' \
    "$restart_readiness_function" >/dev/null
grep -F '"$hook_restart_bind_gid" 2>/dev/null' \
    "$restart_readiness_function" >/dev/null
# shellcheck disable=SC1090,SC2317
. "$restart_readiness_function"
[ "$(restart_uptime_seconds 0.00)" = 0 ]
[ "$(restart_uptime_seconds 9.12)" = 9 ]
[ "$(restart_uptime_seconds 10.34)" = 10 ]
for restart_invalid_uptime in \
    '' .12 01.23 1.2 1.234 1..23 1x.23 4294967255.00
do
    if restart_uptime_seconds "$restart_invalid_uptime" >/dev/null 2>&1; then
        printf 'restart uptime parser accepted malformed value: %s\n' \
            "$restart_invalid_uptime" >&2
        exit 1
    fi
done
restart_readiness_sequence=$tmp/restart-readiness-sequence
restart_readiness_index=$tmp/restart-readiness-index
restart_readiness_sleep_count=$tmp/restart-readiness-sleep-count
restart_readiness_socket_calls=$tmp/restart-readiness-socket-calls
restart_readiness_bind_sequence=$tmp/restart-readiness-bind-sequence
restart_readiness_bind_index=$tmp/restart-readiness-bind-index
restart_readiness_clock_sequence=$tmp/restart-readiness-clock-sequence
restart_readiness_clock_index=$tmp/restart-readiness-clock-index
restart_readiness_journal_state_sequence=$tmp/restart-readiness-journal-state-sequence
restart_readiness_journal_state_index=$tmp/restart-readiness-journal-state-index
restart_readiness_socket_disappear_once=$tmp/restart-readiness-disappear-once
export restart_readiness_sequence restart_readiness_index
probe=$tmp/restart-readiness-probe
printf '%s\n' \
    '#!/bin/sh' \
    'set -eu' \
    '[ "$#" -eq 3 ] || exit 64' \
    '[ "$1:$2:$3" = prove-restart-settled:4242:77 ] || exit 65' \
    'probe_index=$(cat "$restart_readiness_index")' \
    'probe_value=$(sed -n "${probe_index}p" "$restart_readiness_sequence")' \
    '[ -n "$probe_value" ] || exit 66' \
    'printf "%s\n" $((probe_index + 1)) >"$restart_readiness_index"' \
    'case $probe_value in' \
    '  unavailable) exit 1 ;;' \
    '  pass) printf "%s\n" VOLPAROSSA_HELPER_V3_RESTART_EXACT_PRESENT_SETTLED_V1=pass ;;' \
    '  wrong) printf "%s\n" VOLPAROSSA_HELPER_V3_RESTART_EXACT_PRESENT_SETTLED_V1=wrong ;;' \
    '  *) exit 67 ;;' \
    'esac' >"$probe"
chmod 0700 "$probe"
helper_socket=$tmp/restart-helper.sock
journal_next=$tmp/restart-helper.ownership-v3.next
restart_readiness_pid=4242
restart_readiness_invocation=11111111111111111111111111111111
restart_readiness_post_pid=
restart_readiness_post_invocation=
restart_readiness_socket_status=0
restart_readiness_socket_identity=new-socket
restart_readiness_socket_identity_after_sleep=
restart_readiness_post_socket_identity=
restart_readiness_socket_after_sleep=2
unit_name_is_safe() { [ "$1" = volparossa-helper-live-proof-a1b2c3.service ]; }
number_is_safe() {
    [ "$1" = 4242 ] || [ "$1" = 76 ] || [ "$1" = 77 ] || [ "$1" = 88 ]
}
invocation_id_is_safe() {
    [ "${#1}" -eq 32 ] && [ "$1" != 00000000000000000000000000000000 ]
}
unit_main_pid() {
    if [ "$(cat "$restart_readiness_socket_calls")" -gt 0 ] \
        && [ -n "$restart_readiness_post_pid" ]; then
        printf '%s\n' "$restart_readiness_post_pid"
    else
        printf '%s\n' "$restart_readiness_pid"
    fi
}
unit_invocation_id() {
    if [ "$(cat "$restart_readiness_socket_calls")" -gt 0 ] \
        && [ -n "$restart_readiness_post_invocation" ]; then
        printf '%s\n' "$restart_readiness_post_invocation"
    else
        printf '%s\n' "$restart_readiness_invocation"
    fi
}
capture_socket_identity() {
    restart_readiness_calls=$(cat "$restart_readiness_socket_calls") || return 1
    printf '%s\n' $((restart_readiness_calls + 1)) \
        >"$restart_readiness_socket_calls"
    if [ -e "$restart_readiness_socket_disappear_once" ]; then
        rm -f -- "$restart_readiness_socket_disappear_once"
        rm -f -- "$helper_socket"
        return 1
    fi
    [ "$restart_readiness_socket_status" -eq 0 ] || return 1
    if [ "$restart_readiness_calls" -gt 0 ] \
        && [ -n "$restart_readiness_post_socket_identity" ]; then
        printf '%s\n' "$restart_readiness_post_socket_identity"
    else
        printf '%s\n' "$restart_readiness_socket_identity"
    fi
}
run_restart_bind_probe() {
    [ "$#" -eq 4 ]
    [ "$1:$2:$3:$4" = 4242:76:77:88 ]
    restart_bind_index=$(cat "$restart_readiness_bind_index") || return 1
    restart_bind_value=$(sed -n "${restart_bind_index}p" \
        "$restart_readiness_bind_sequence") || return 1
    [ -n "$restart_bind_value" ] || return 1
    printf '%s\n' $((restart_bind_index + 1)) \
        >"$restart_readiness_bind_index"
    case $restart_bind_value in
        unavailable) return 1 ;;
        pass) printf '%s\n' VOLPAROSSA_HELPER_V3_IPC_BIND_RUNTIME_V1=pass ;;
        wrong) printf '%s\n' VOLPAROSSA_HELPER_V3_IPC_BIND_RUNTIME_V1=wrong ;;
        *) return 1 ;;
    esac
}
restart_monotonic_seconds() {
    restart_clock_index=$(cat "$restart_readiness_clock_index") || return 1
    restart_clock_value=$(sed -n "${restart_clock_index}p" \
        "$restart_readiness_clock_sequence") || return 1
    if [ -n "$restart_clock_value" ]; then
        printf '%s\n' $((restart_clock_index + 1)) \
            >"$restart_readiness_clock_index"
    else
        restart_clock_value=$restart_readiness_clock_default
    fi
    case $restart_clock_value in
        unavailable) return 1 ;;
        *) printf '%s\n' "$restart_clock_value" ;;
    esac
}
capture_journal_state() {
    [ "$#" -eq 1 ] && [ "$1" = 77 ]
    restart_state_index=$(cat "$restart_readiness_journal_state_index") \
        || return 1
    restart_state_value=$(sed -n "${restart_state_index}p" \
        "$restart_readiness_journal_state_sequence") || return 1
    if [ -n "$restart_state_value" ]; then
        printf '%s\n' $((restart_state_index + 1)) \
            >"$restart_readiness_journal_state_index"
    else
        restart_state_value=stable
    fi
    case $restart_state_value in
        stable) printf '%s\n%s\n%s\n' PRESENT stable-metadata stable-checksum ;;
        changed) printf '%s\n%s\n%s\n' PRESENT changed-metadata changed-checksum ;;
        unavailable) return 1 ;;
        *) return 1 ;;
    esac
}
sleep() {
    restart_readiness_sleeps=$(cat "$restart_readiness_sleep_count") || return 1
    restart_readiness_sleeps=$((restart_readiness_sleeps + 1))
    printf '%s\n' "$restart_readiness_sleeps" >"$restart_readiness_sleep_count"
    if [ "$restart_readiness_sleeps" -eq \
        "$restart_readiness_socket_after_sleep" ]; then
        : >"$helper_socket"
        if [ -n "$restart_readiness_socket_identity_after_sleep" ]; then
            restart_readiness_socket_identity=$restart_readiness_socket_identity_after_sleep
        fi
    fi
}
restart_reset_readiness_model() {
    rm -f -- "$helper_socket" "$journal_next" \
        "$restart_readiness_socket_disappear_once"
    printf '%s\n' 1 >"$restart_readiness_index"
    printf '%s\n' 0 >"$restart_readiness_sleep_count"
    printf '%s\n' 0 >"$restart_readiness_socket_calls"
    printf '%s\n' 1 >"$restart_readiness_bind_index"
    printf '%s\n' 1 >"$restart_readiness_clock_index"
    printf '%s\n' 1 >"$restart_readiness_journal_state_index"
    restart_readiness_pid=4242
    restart_readiness_invocation=11111111111111111111111111111111
    restart_readiness_post_pid=
    restart_readiness_post_invocation=
    restart_readiness_socket_status=0
    restart_readiness_socket_identity=new-socket
    restart_readiness_socket_identity_after_sleep=
    restart_readiness_post_socket_identity=
    restart_readiness_socket_after_sleep=2
    restart_readiness_clock_default=1
    start_failure_stage=restart-journal-settlement
}
: >"$restart_readiness_clock_sequence"
: >"$restart_readiness_journal_state_sequence"
printf '%s\n' unavailable pass pass >"$restart_readiness_sequence"
printf '%s\n' pass >"$restart_readiness_bind_sequence"
restart_reset_readiness_model
hook_restart_readiness_failure_stage=
hook_restart_ready_journal_state=
wait_for_restart_readiness \
    volparossa-helper-live-proof-a1b2c3.service 4242 \
    11111111111111111111111111111111 76 77 88
[ "$start_failure_stage" = restart-socket-validation ]
[ "$(cat "$restart_readiness_index")" -eq 4 ]
[ "$(cat "$restart_readiness_sleep_count")" -eq 2 ]
[ "$(cat "$restart_readiness_socket_calls")" -eq 2 ]
[ "$hook_restart_ready_journal_state" = \
    "$(printf '%s\n%s\n%s' PRESENT stable-metadata stable-checksum)" ]
printf '%s\n' wrong >"$restart_readiness_sequence"
restart_reset_readiness_model
if wait_for_restart_readiness \
    volparossa-helper-live-proof-a1b2c3.service 4242 \
    11111111111111111111111111111111 76 77 88; then
    printf '%s\n' 'restart readiness accepted a wrong successful journal proof' >&2
    exit 1
fi
[ "$hook_restart_readiness_failure_stage" = initial-journal-value ]
printf '%s\n' pass >"$restart_readiness_sequence"
restart_reset_readiness_model
: >"$helper_socket"
restart_readiness_socket_status=1
if wait_for_restart_readiness \
    volparossa-helper-live-proof-a1b2c3.service 4242 \
    11111111111111111111111111111111 76 77 88; then
    printf '%s\n' 'restart readiness accepted an unsafe published socket' >&2
    exit 1
fi
[ "$hook_restart_readiness_failure_stage" = socket-capture ]
restart_reset_readiness_model
: >"$helper_socket"
restart_readiness_socket_identity=old-socket
printf '%s\n' pass pass >"$restart_readiness_sequence"
wait_for_restart_readiness \
    volparossa-helper-live-proof-a1b2c3.service 4242 \
    11111111111111111111111111111111 76 77 88
[ "$(cat "$restart_readiness_socket_calls")" -eq 2 ]
[ "$(cat "$restart_readiness_sleep_count")" -eq 0 ]
printf '%s\n' pass pass >"$restart_readiness_sequence"
printf '%s\n' unavailable pass >"$restart_readiness_bind_sequence"
restart_reset_readiness_model
: >"$helper_socket"
wait_for_restart_readiness \
    volparossa-helper-live-proof-a1b2c3.service 4242 \
    11111111111111111111111111111111 76 77 88
[ "$(cat "$restart_readiness_bind_index")" -eq 3 ]
[ "$(cat "$restart_readiness_sleep_count")" -eq 1 ]
printf '%s\n' pass pass >"$restart_readiness_sequence"
printf '%s\n' wrong >"$restart_readiness_bind_sequence"
restart_reset_readiness_model
: >"$helper_socket"
if wait_for_restart_readiness \
    volparossa-helper-live-proof-a1b2c3.service 4242 \
    11111111111111111111111111111111 76 77 88; then
    printf '%s\n' 'restart readiness accepted a wrong bind response' >&2
    exit 1
fi
[ "$hook_restart_readiness_failure_stage" = bind-runtime-value ]
printf '%s\n' pass unavailable >"$restart_readiness_sequence"
printf '%s\n' pass >"$restart_readiness_bind_sequence"
restart_reset_readiness_model
: >"$helper_socket"
if wait_for_restart_readiness \
    volparossa-helper-live-proof-a1b2c3.service 4242 \
    11111111111111111111111111111111 76 77 88; then
    printf '%s\n' 'restart readiness accepted an unreadable final journal' >&2
    exit 1
fi
[ "$hook_restart_readiness_failure_stage" = final-journal-read ]
printf '%s\n' pass wrong >"$restart_readiness_sequence"
restart_reset_readiness_model
: >"$helper_socket"
if wait_for_restart_readiness \
    volparossa-helper-live-proof-a1b2c3.service 4242 \
    11111111111111111111111111111111 76 77 88; then
    printf '%s\n' 'restart readiness accepted a wrong final journal proof' >&2
    exit 1
fi
[ "$hook_restart_readiness_failure_stage" = final-journal-value ]
printf '%s\n' pass pass >"$restart_readiness_sequence"
printf '%s\n' unavailable >"$restart_readiness_journal_state_sequence"
restart_reset_readiness_model
: >"$helper_socket"
if wait_for_restart_readiness \
    volparossa-helper-live-proof-a1b2c3.service 4242 \
    11111111111111111111111111111111 76 77 88; then
    printf '%s\n' 'restart readiness accepted an unreadable initial journal state' >&2
    exit 1
fi
[ "$hook_restart_readiness_failure_stage" = journal-state-before ]
printf '%s\n' stable unavailable >"$restart_readiness_journal_state_sequence"
restart_reset_readiness_model
: >"$helper_socket"
if wait_for_restart_readiness \
    volparossa-helper-live-proof-a1b2c3.service 4242 \
    11111111111111111111111111111111 76 77 88; then
    printf '%s\n' 'restart readiness accepted an unreadable final journal state' >&2
    exit 1
fi
[ "$hook_restart_readiness_failure_stage" = journal-state-after ]
printf '%s\n' stable changed >"$restart_readiness_journal_state_sequence"
restart_reset_readiness_model
: >"$helper_socket"
if wait_for_restart_readiness \
    volparossa-helper-live-proof-a1b2c3.service 4242 \
    11111111111111111111111111111111 76 77 88; then
    printf '%s\n' 'restart readiness accepted changed journal bytes' >&2
    exit 1
fi
[ "$hook_restart_readiness_failure_stage" = journal-state-change ]
: >"$restart_readiness_journal_state_sequence"
printf '%s\n' pass pass >"$restart_readiness_sequence"
restart_reset_readiness_model
: >"$helper_socket"
: >"$journal_next"
if wait_for_restart_readiness \
    volparossa-helper-live-proof-a1b2c3.service 4242 \
    11111111111111111111111111111111 76 77 88; then
    printf '%s\n' 'restart readiness accepted a pending final journal' >&2
    exit 1
fi
[ "$hook_restart_readiness_failure_stage" = journal-next ]
printf '%s\n' pass pass >"$restart_readiness_sequence"
printf '%s\n' pass >"$restart_readiness_bind_sequence"
restart_reset_readiness_model
: >"$helper_socket"
: >"$restart_readiness_socket_disappear_once"
restart_readiness_socket_after_sleep=1
wait_for_restart_readiness \
    volparossa-helper-live-proof-a1b2c3.service 4242 \
    11111111111111111111111111111111 76 77 88
[ "$(cat "$restart_readiness_sleep_count")" -eq 1 ]
printf '%s\n' pass pass >"$restart_readiness_sequence"
restart_reset_readiness_model
: >"$helper_socket"
restart_readiness_post_pid=4243
if wait_for_restart_readiness \
    volparossa-helper-live-proof-a1b2c3.service 4242 \
    11111111111111111111111111111111 76 77 88; then
    printf '%s\n' 'restart readiness accepted a post-socket MainPID change' >&2
    exit 1
fi
[ "$hook_restart_readiness_failure_stage" = final-lineage-pid ]
printf '%s\n' pass pass >"$restart_readiness_sequence"
restart_reset_readiness_model
: >"$helper_socket"
restart_readiness_post_socket_identity=substituted-socket
if wait_for_restart_readiness \
    volparossa-helper-live-proof-a1b2c3.service 4242 \
    11111111111111111111111111111111 76 77 88; then
    printf '%s\n' 'restart readiness accepted a rebound successor socket' >&2
    exit 1
fi
[ "$hook_restart_readiness_failure_stage" = socket-stability ]
printf '%s\n' pass pass >"$restart_readiness_sequence"
restart_reset_readiness_model
: >"$helper_socket"
restart_readiness_post_invocation=22222222222222222222222222222222
if wait_for_restart_readiness \
    volparossa-helper-live-proof-a1b2c3.service 4242 \
    11111111111111111111111111111111 76 77 88; then
    printf '%s\n' 'restart readiness accepted a post-socket InvocationID change' >&2
    exit 1
fi
[ "$hook_restart_readiness_failure_stage" = final-lineage-invocation ]
awk 'BEGIN { for (i = 1; i <= 900; i++) print "unavailable" }' \
    >"$restart_readiness_sequence"
restart_reset_readiness_model
restart_readiness_socket_after_sleep=901
if wait_for_restart_readiness \
    volparossa-helper-live-proof-a1b2c3.service 4242 \
    11111111111111111111111111111111 76 77 88; then
    printf '%s\n' 'restart readiness accepted an unavailable journal forever' >&2
    exit 1
fi
[ "$(cat "$restart_readiness_index")" -eq 901 ]
[ "$(cat "$restart_readiness_sleep_count")" -eq 899 ]
[ "$(cat "$restart_readiness_socket_calls")" -eq 0 ]
[ "$hook_restart_readiness_failure_stage" = timeout ]

printf '%s\n' pass pass >"$restart_readiness_sequence"
printf '%s\n' \
    unavailable unavailable unavailable unavailable unavailable \
    unavailable unavailable unavailable unavailable unavailable pass \
    >"$restart_readiness_bind_sequence"
: >"$restart_readiness_clock_sequence"
restart_reset_readiness_model
: >"$helper_socket"
wait_for_restart_readiness \
    volparossa-helper-live-proof-a1b2c3.service 4242 \
    11111111111111111111111111111111 76 77 88
[ "$(cat "$restart_readiness_bind_index")" -eq 12 ]
[ "$(cat "$restart_readiness_sleep_count")" -eq 10 ]

printf '%s\n' unavailable >"$restart_readiness_clock_sequence"
restart_reset_readiness_model
if wait_for_restart_readiness \
    volparossa-helper-live-proof-a1b2c3.service 4242 \
    11111111111111111111111111111111 76 77 88; then
    printf '%s\n' 'restart readiness accepted an unreadable monotonic clock' >&2
    exit 1
fi
[ "$hook_restart_readiness_failure_stage" = clock-read ]
printf '%s\n' 10 9 >"$restart_readiness_clock_sequence"
restart_reset_readiness_model
if wait_for_restart_readiness \
    volparossa-helper-live-proof-a1b2c3.service 4242 \
    11111111111111111111111111111111 76 77 88; then
    printf '%s\n' 'restart readiness accepted a backwards monotonic clock' >&2
    exit 1
fi
[ "$hook_restart_readiness_failure_stage" = clock-backwards ]
printf '%s\n' 10 50 >"$restart_readiness_clock_sequence"
restart_reset_readiness_model
if wait_for_restart_readiness \
    volparossa-helper-live-proof-a1b2c3.service 4242 \
    11111111111111111111111111111111 76 77 88; then
    printf '%s\n' 'restart readiness exceeded its monotonic deadline' >&2
    exit 1
fi
[ "$hook_restart_readiness_failure_stage" = timeout ]
printf '%s\n' pass >"$restart_readiness_sequence"
printf '%s\n' pass >"$restart_readiness_bind_sequence"
printf '%s\n' 10 10 50 >"$restart_readiness_clock_sequence"
restart_reset_readiness_model
: >"$helper_socket"
if wait_for_restart_readiness \
    volparossa-helper-live-proof-a1b2c3.service 4242 \
    11111111111111111111111111111111 76 77 88; then
    printf '%s\n' 'restart readiness began a bind probe at its deadline' >&2
    exit 1
fi
[ "$(cat "$restart_readiness_bind_index")" -eq 1 ]
[ "$hook_restart_readiness_failure_stage" = timeout ]
printf '%s\n' \
    unavailable unavailable unavailable unavailable \
    unavailable unavailable unavailable unavailable pass \
    >"$restart_readiness_bind_sequence"
printf '%s\n' \
    10 10 10 15 15 20 20 25 25 30 30 35 35 40 40 45 45 50 \
    >"$restart_readiness_clock_sequence"
restart_reset_readiness_model
: >"$helper_socket"
if wait_for_restart_readiness \
    volparossa-helper-live-proof-a1b2c3.service 4242 \
    11111111111111111111111111111111 76 77 88; then
    printf '%s\n' 'restart readiness started a ninth slow bind probe' >&2
    exit 1
fi
[ "$(cat "$restart_readiness_bind_index")" -eq 9 ]
[ "$hook_restart_readiness_failure_stage" = timeout ]
: >"$restart_readiness_clock_sequence"

# The post-retirement proof must capture the exact host bind-source journal,
# never the helper's hard-coded namespace-local /run path. Exercise the capture
# primitives causally: exact path and regular-file shape, metadata, digest, and
# stat-before/hash/stat-after stability are all fail-closed.
restart_journal_capture_functions=$tmp/restart-journal-capture-functions.sh
{
    sed -n '/^restart_journal_metadata_is_exact() {$/,/^}$/p' "$gate"
    sed -n '/^restart_journal_digest_is_exact() {$/,/^}$/p' "$gate"
    sed -n '/^capture_restart_journal_state() {$/,/^}$/p' "$gate"
    sed -n '/^capture_restart_journal_state_record() {$/,/^}$/p' "$gate"
} >"$restart_journal_capture_functions"
[ "$(grep -c '^[_a-z].*() {$' "$restart_journal_capture_functions")" -eq 4 ]
# shellcheck disable=SC1090
. "$restart_journal_capture_functions"
temporary_stage=$tmp/restart-final-journal-stage
mkdir -p "$temporary_stage/production-runtime" "$temporary_stage/restart-output"
restart_capture_path=$temporary_stage/production-runtime/helper.ownership-v3
restart_capture_record=$temporary_stage/restart-output/restart.journal.settled.state
: >"$restart_capture_path"
chmod 0600 "$restart_capture_path"
restart_capture_log=$tmp/restart-journal-capture.log
restart_capture_stat_index=$tmp/restart-journal-capture-stat.index
restart_capture_metadata='41:123:8180:0:77:600:1:64:2026-09-01 04:59:14.833008566 +0200:2026-09-01 04:59:14.833008566 +0200'
restart_capture_metadata_after=$restart_capture_metadata
restart_capture_digest=aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa
restart_capture_digest_status=0
restart_capture_stat_before_status=0
restart_capture_stat_after_status=0
restart_reset_journal_capture_model() {
    : >"$restart_capture_log"
    printf '%s\n' 0 >"$restart_capture_stat_index"
    restart_capture_metadata_after=$restart_capture_metadata
    restart_capture_digest=aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa
    restart_capture_digest_status=0
    restart_capture_stat_before_status=0
    restart_capture_stat_after_status=0
}
stat() {
    if [ "$#" -eq 3 ] && [ "$1" = -c ] \
        && [ "$2" = '%d:%i:%f:%u:%g:%a:%h:%s:%y:%z' ] \
        && [ "$3" = "$restart_capture_path" ]; then
        restart_capture_stat_call=$(cat "$restart_capture_stat_index") || return 1
        case $restart_capture_stat_call in
            0)
                printf '%s\n' stat-before >>"$restart_capture_log"
                printf '%s\n' 1 >"$restart_capture_stat_index"
                [ "$restart_capture_stat_before_status" -eq 0 ] || return 1
                printf '%s\n' "$restart_capture_metadata"
                ;;
            1)
                printf '%s\n' stat-after >>"$restart_capture_log"
                printf '%s\n' 2 >"$restart_capture_stat_index"
                [ "$restart_capture_stat_after_status" -eq 0 ] || return 1
                printf '%s\n' "$restart_capture_metadata_after"
                ;;
            *) return 1 ;;
        esac
    else
        command stat "$@"
    fi
}
vp_capture_sha256_file() {
    [ "$#" -eq 1 ] && [ "$1" = "$restart_capture_path" ] || return 1
    printf '%s\n' hash >>"$restart_capture_log"
    [ "$restart_capture_digest_status" -eq 0 ] || return 1
    printf '%s\n' "$restart_capture_digest"
}
vp_capture_file_is_safe() {
    [ "$#" -eq 1 ] && [ -f "$1" ] && [ ! -L "$1" ] \
        && [ "$(command stat -Lc '%a:%h' "$1")" = 600:1 ]
}
restart_reset_journal_capture_model
restart_captured_state=$(capture_restart_journal_state \
    "$restart_capture_path" 77)
[ "$restart_captured_state" = \
    "$(printf 'PRESENT\n%s\n%s' "$restart_capture_metadata" \
        "$restart_capture_digest")" ]
printf '%s\n' stat-before hash stat-after \
    | cmp -s - "$restart_capture_log"
if capture_restart_journal_state "$restart_capture_path.invalid" 77 \
    >/dev/null 2>&1; then
    printf '%s\n' 'restart journal capture accepted a noncanonical path' >&2
    exit 1
fi
mv "$restart_capture_path" "$restart_capture_path.real"
ln -s "$restart_capture_path.real" "$restart_capture_path"
if capture_restart_journal_state "$restart_capture_path" 77 \
    >/dev/null 2>&1; then
    printf '%s\n' 'restart journal capture accepted a symlink' >&2
    exit 1
fi
rm -f -- "$restart_capture_path"
mv "$restart_capture_path.real" "$restart_capture_path"
restart_reset_journal_capture_model
restart_capture_metadata='41:123:8180:0:77:640:1:64:2026-09-01 04:59:14.833008566 +0200:2026-09-01 04:59:14.833008566 +0200'
restart_capture_metadata_after=$restart_capture_metadata
if capture_restart_journal_state "$restart_capture_path" 77 \
    >/dev/null 2>&1; then
    printf '%s\n' 'restart journal capture accepted unsafe metadata' >&2
    exit 1
fi
restart_capture_metadata='41:123:8180:0:77:600:1:64:2026-09-01 04:59:14.833008566 +0200:2026-09-01 04:59:14.833008566 +0200'
restart_reset_journal_capture_model
restart_capture_digest=AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
if capture_restart_journal_state "$restart_capture_path" 77 \
    >/dev/null 2>&1; then
    printf '%s\n' 'restart journal capture accepted a noncanonical digest' >&2
    exit 1
fi
restart_reset_journal_capture_model
restart_capture_digest_status=1
if capture_restart_journal_state "$restart_capture_path" 77 \
    >/dev/null 2>&1; then
    printf '%s\n' 'restart journal capture accepted a failed digest read' >&2
    exit 1
fi
restart_reset_journal_capture_model
restart_capture_metadata_after='41:124:8180:0:77:600:1:64:2026-09-01 04:59:14.833008566 +0200:2026-09-01 04:59:14.833008566 +0200'
if capture_restart_journal_state "$restart_capture_path" 77 \
    >/dev/null 2>&1; then
    printf '%s\n' 'restart journal capture accepted stat drift' >&2
    exit 1
fi
restart_reset_journal_capture_model
restart_capture_stat_after_status=1
if capture_restart_journal_state "$restart_capture_path" 77 \
    >/dev/null 2>&1; then
    printf '%s\n' 'restart journal capture accepted an unavailable final stat' >&2
    exit 1
fi

# The retained in-unit state is a bounded root-private canonical three-line
# record. Extra lines, unsafe metadata, malformed hashes, pending paths, or an
# oversized payload are not permitted to become the expected final state.
restart_capture_metadata='41:123:8180:0:77:600:1:64:2026-09-01 04:59:14.833008566 +0200:2026-09-01 04:59:14.833008566 +0200'
restart_capture_digest=aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa
printf 'PRESENT\n%s\n%s\n' \
    "$restart_capture_metadata" "$restart_capture_digest" \
    >"$restart_capture_record"
chmod 0600 "$restart_capture_record"
[ "$(capture_restart_journal_state_record \
    "$restart_capture_record" 77)" = \
    "$(printf 'PRESENT\n%s\n%s' "$restart_capture_metadata" \
        "$restart_capture_digest")" ]
mv "$restart_capture_record" "$restart_capture_record.real"
ln -s "$restart_capture_record.real" "$restart_capture_record"
if capture_restart_journal_state_record "$restart_capture_record" 77 \
    >/dev/null 2>&1; then
    printf '%s\n' 'restart state record accepted a symlink' >&2
    exit 1
fi
rm -f -- "$restart_capture_record"
mv "$restart_capture_record.real" "$restart_capture_record"
printf 'PRESENT\n%s\n%s\nextra\n' \
    "$restart_capture_metadata" "$restart_capture_digest" \
    >"$restart_capture_record"
if capture_restart_journal_state_record "$restart_capture_record" 77 \
    >/dev/null 2>&1; then
    printf '%s\n' 'restart state record accepted a fourth line' >&2
    exit 1
fi
printf 'PRESENT\n%s\n%s\n' \
    '41:123:8180:0:77:640:1:64:2026-09-01 04:59:14.833008566 +0200:2026-09-01 04:59:14.833008566 +0200' \
    "$restart_capture_digest" >"$restart_capture_record"
if capture_restart_journal_state_record "$restart_capture_record" 77 \
    >/dev/null 2>&1; then
    printf '%s\n' 'restart state record accepted unsafe metadata' >&2
    exit 1
fi
printf 'PRESENT\n%s\n%s\n' "$restart_capture_metadata" \
    AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA \
    >"$restart_capture_record"
if capture_restart_journal_state_record "$restart_capture_record" 77 \
    >/dev/null 2>&1; then
    printf '%s\n' 'restart state record accepted a noncanonical digest' >&2
    exit 1
fi
printf 'PRESENT\n%s\n%s\n' \
    "$restart_capture_metadata" "$restart_capture_digest" \
    >"$restart_capture_record"
: >"$restart_capture_record.next"
if capture_restart_journal_state_record "$restart_capture_record" 77 \
    >/dev/null 2>&1; then
    printf '%s\n' 'restart state record accepted a pending path' >&2
    exit 1
fi
rm -f -- "$restart_capture_record.next"
/usr/bin/awk 'BEGIN { for (i = 0; i < 513; i++) printf "x" }' \
    >"$restart_capture_record"
if capture_restart_journal_state_record "$restart_capture_record" 77 \
    >/dev/null 2>&1; then
    printf '%s\n' 'restart state record accepted an oversized payload' >&2
    exit 1
fi
stat() { command stat "$@"; }

# The namespace-local predicate is run only by the in-unit hook. Once PID 1
# has retired the successor, the root driver holds the pre-pinned lock inode
# across an exact host bind-source capture, all absence checks, the state cmp,
# a final path re-pin, and a final unit-not-found observation.
restart_final_bracket=$tmp/restart-final-bracket.sh
sed -n '/^    driver_phase=restart-retirement$/,/^    restart_evidence_validated=true$/p' \
    "$gate" >"$restart_final_bracket"
if grep -F '"$temporary_stage/production-ipc-probe" prove-restart-settled' \
    "$restart_final_bracket" >/dev/null; then
    printf '%s\n' 'post-retirement proof still probes namespace-local /run' >&2
    exit 1
fi
if ! awk '
    /restart_retired_load_state=\$\(unit_load_state\)/ {
        initial_collection = NR; initial_collection_count++
    }
    /restart_expected_journal_state=\$\(capture_restart_journal_state_record/ {
        expected_state = NR; expected_state_count++
    }
    /restart_lock_path_before=\$\(stat -c/ {
        path_before = NR; path_before_count++
    }
    /^    \[ "\$restart_lock_path_before" = "\$expected_production_lock_identity" \] \\/ {
        path_before_pin = NR; path_before_pin_count++
    }
    /^    if command exec 9<"\$restart_lock_path"; then$/ {
        open_fd = NR; open_fd_count++
    }
    /restart_lock_fd_identity=\$\(stat -Lc/ {
        fd_identity = NR; fd_identity_count++
    }
    /^        \[ "\$restart_lock_fd_identity" = "\$expected_production_lock_identity" \] \\/ {
        fd_pin = NR; fd_pin_count++
    }
    /\/usr\/bin\/flock -n 9/ { flock = NR; flock_count++ }
    /restart_lock_path_after_flock=\$\(stat -c/ {
        path_after_flock = NR; path_after_flock_count++
    }
    /"\$restart_lock_path_after_flock" = \\/ {
        path_after_flock_pin = NR; path_after_flock_pin_count++
    }
    /if \[ -e "\$temporary_stage\/production-runtime\/helper.sock" \] \\/ {
        absence_count++
        if (absence_count == 1) absence_before = NR
        if (absence_count == 2) absence_after = NR
    }
    /restart_final_journal_state=\$\(capture_restart_journal_state/ {
        capture = NR; capture_count++
    }
    /^        \[ "\$restart_final_journal_state" = \\/ {
        state_cmp = NR; state_cmp_count++
    }
    /\| cmp -s - "\$restart_journal_state_record" \\/ {
        record_cmp = NR; record_cmp_count++
    }
    /restart_lock_path_final=\$\(stat -c/ {
        final_path = NR; final_path_count++
    }
    /^        \[ "\$restart_lock_path_final" = "\$expected_production_lock_identity" \] \\/ {
        final_path_pin = NR; final_path_pin_count++
    }
    /restart_final_load_state=\$\(unit_load_state\)/ {
        final_collection = NR; final_collection_count++
    }
    /^        command exec 9>&- \\/ { close_fd = NR; close_fd_count++ }
    /^    restart_evidence_validated=true$/ { validated = NR; validated_count++ }
    END {
        valid = initial_collection_count == 1 && expected_state_count == 1
        valid = valid && path_before_count == 1 && path_before_pin_count == 1
        valid = valid && open_fd_count == 1 && fd_identity_count == 1
        valid = valid && fd_pin_count == 1 && flock_count == 1
        valid = valid && path_after_flock_count == 1
        valid = valid && path_after_flock_pin_count == 1
        valid = valid && absence_count == 2 && capture_count == 1
        valid = valid && state_cmp_count == 1 && record_cmp_count == 1
        valid = valid && final_path_count == 1 && final_path_pin_count == 1
        valid = valid && final_collection_count == 1 && close_fd_count == 1
        valid = valid && validated_count == 1
        valid = valid && initial_collection < expected_state
        valid = valid && expected_state < path_before
        valid = valid && path_before < path_before_pin
        valid = valid && path_before_pin < open_fd && open_fd < fd_identity
        valid = valid && fd_identity < fd_pin && fd_pin < flock
        valid = valid && flock < path_after_flock
        valid = valid && path_after_flock < path_after_flock_pin
        valid = valid && path_after_flock_pin < absence_before
        valid = valid && absence_before < capture && capture < absence_after
        valid = valid && absence_after < state_cmp && state_cmp < record_cmp
        valid = valid && record_cmp < final_path && final_path < final_path_pin
        valid = valid && final_path_pin < final_collection
        valid = valid && final_collection < close_fd && close_fd < validated
        if (!valid) exit 1
    }
' "$restart_final_bracket"; then
    printf '%s\n' 'restart final journal and lock proof is not one exact bracket' >&2
    exit 1
fi

restart_in_unit_state_bracket=$tmp/restart-in-unit-state-bracket.sh
sed -n '/^wait_for_restart_readiness() {$/,/^}$/p' \
    "$hook" >"$restart_in_unit_state_bracket"
if ! awk '
    /hook_restart_ready_journal_state_before=\$\(capture_journal_state/ {
        before = NR; before_count++
    }
    /hook_restart_ready_final_journal=\$\(/ { predicate = NR; predicate_count++ }
    /hook_restart_ready_journal_state=\$\(capture_journal_state/ {
        after = NR; after_count++
    }
    /"\$hook_restart_ready_journal_state_before" \] \|\| return 1/ {
        equal = NR; equal_count++
    }
    /\[ ! -e "\$journal_next" \] && \[ ! -L "\$journal_next" \]/ {
        no_next = NR; no_next_count++
    }
    /"\$hook_restart_ready_socket" \] \|\| return 1/ {
        socket = NR; socket_count++
    }
    /hook_restart_readiness_failure_stage=final-lineage-pid/ {
        final_pid = NR; final_pid_count++
    }
    /hook_restart_readiness_failure_stage=final-lineage-invocation/ {
        final_invocation = NR; final_invocation_count++
    }
    END {
        valid = before_count == 1 && predicate_count == 1 && after_count == 1
        valid = valid && equal_count == 1 && no_next_count == 1
        valid = valid && socket_count == 1 && final_pid_count == 1
        valid = valid && final_invocation_count == 1
        valid = valid && before < predicate && predicate < after
        valid = valid && after < equal && equal < no_next
        valid = valid && no_next < socket && socket < final_pid
        valid = valid && final_pid < final_invocation
        if (!valid) exit 1
    }
' "$restart_in_unit_state_bracket"; then
    printf '%s\n' 'in-unit restart journal state is not exactly bracketed' >&2
    exit 1
fi
restart_state_publication=$tmp/restart-state-publication.sh
sed -n '/^restart_start_hook() {$/,/^}$/p' "$hook" \
    >"$restart_state_publication"
if ! awk '
    /if ! wait_for_restart_readiness \\/ { readiness = NR; readiness_count++ }
    /advance_restart_start_failure_stage restart-publication/ {
        publication = NR; publication_count++
    }
    /write_private_file "\$restart_journal_settled_state_record" \\/ {
        state = NR; state_count++
    }
    /write_private_file "\$restart_resumed_record" "\$hook_restart_resumed" \\/ {
        resumed = NR; resumed_count++
    }
    END {
        valid = readiness_count == 1 && publication_count == 1
        valid = valid && state_count == 1 && resumed_count == 1
        valid = valid && readiness < publication && publication < state
        valid = valid && state < resumed
        if (!valid) exit 1
    }
' "$restart_state_publication"; then
    printf '%s\n' 'restart journal state is not published before resumed lineage' >&2
    exit 1
fi

for restart_readiness_stage in \
    preflight clock-read clock-backwards lineage-pid lineage-invocation socket-capture \
    initial-journal-value stage-transition bind-runtime-read \
    bind-runtime-value final-journal-read final-journal-value journal-next \
    journal-state-before journal-state-after journal-state-change \
    socket-stability final-lineage-pid final-lineage-invocation timeout
do
    restart_readiness_failure_stage_is_safe "$restart_readiness_stage"
done
if restart_readiness_failure_stage_is_safe private-runtime-detail; then
    printf '%s\n' 'restart readiness allowlist accepted private detail' >&2
    exit 1
fi

# The inner proof consumes fixed private records; the VM runner receives only
# these allowlisted categories and never the record payload.
restart_failure_classifier=$tmp/restart-successor-start-failure-classifier.sh
{
    sed -n '/^restart_successor_start_failure_category() {$/,/^}$/p' "$gate"
    sed -n '/^restart_readiness_failure_stage_is_safe() {$/,/^}$/p' "$gate"
    sed -n '/^report_restart_readiness_failure_diagnostic() {$/,/^}$/p' "$gate"
} >"$restart_failure_classifier"
[ "$(grep -c '^[_a-z].*() {$' "$restart_failure_classifier")" -eq 3 ]
# shellcheck disable=SC1090
. "$restart_failure_classifier"
vp_capture_file_is_safe() {
    [ -f "$1" ] && [ ! -L "$1" ] \
        && [ "$(stat -Lc '%a:%h' "$1")" = 600:1 ]
}
restart_failure_record=$tmp/restart-start.failure
while IFS='|' read -r restart_failure_stage restart_failure_category; do
    printf 'VOLPAROSSA_HELPER_V3_IPC_START_FAILURE_STAGE_V1=%s\n' \
        "$restart_failure_stage" >"$restart_failure_record"
    chmod 0600 "$restart_failure_record"
    [ "$(restart_successor_start_failure_category \
        "$restart_failure_record")" = "$restart_failure_category" ]
done <<'EOF'
preflight-runtime|preflight
restart-recovery-wait|recovery-wait
restart-lineage|lineage
restart-descriptor-settlement|descriptor-settlement
restart-journal-settlement|journal-settlement
restart-socket-validation|socket-validation
restart-publication|publication
EOF
restart_readiness_failure_record=$tmp/restart-readiness.failure
restart_readiness_public_record=$tmp/restart-readiness.public
for restart_readiness_stage in \
    preflight clock-read clock-backwards lineage-pid lineage-invocation \
    socket-capture \
    initial-journal-value stage-transition bind-runtime-read \
    bind-runtime-value final-journal-read final-journal-value journal-next \
    journal-state-before journal-state-after journal-state-change \
    socket-stability final-lineage-pid final-lineage-invocation timeout
do
    printf 'VOLPAROSSA_HELPER_V3_RESTART_READINESS_FAILURE_V1=%s\n' \
        "$restart_readiness_stage" >"$restart_readiness_failure_record"
    chmod 0600 "$restart_readiness_failure_record"
    report_restart_readiness_failure_diagnostic \
        "$restart_readiness_failure_record" \
        2>"$restart_readiness_public_record"
    [ "$(cat "$restart_readiness_public_record")" = \
        "VOLPAROSSA_HELPER_LIVE_RESTART_READINESS_DIAGNOSTIC_V1=$restart_readiness_stage" ]
done
printf '%s\n' \
    'VOLPAROSSA_HELPER_V3_RESTART_READINESS_FAILURE_V1=private-runtime-detail' \
    >"$restart_readiness_failure_record"
chmod 0600 "$restart_readiness_failure_record"
if report_restart_readiness_failure_diagnostic \
    "$restart_readiness_failure_record" >/dev/null 2>&1; then
    printf '%s\n' 'restart readiness reporter exposed private detail' >&2
    exit 1
fi
printf '%s\n' \
    'VOLPAROSSA_HELPER_V3_IPC_START_FAILURE_STAGE_V1=functional-client-release' \
    >"$restart_failure_record"
if restart_successor_start_failure_category "$restart_failure_record" \
    >/dev/null 2>&1; then
    printf '%s\n' 'successor classifier accepted the initial failure stage' >&2
    exit 1
fi
printf '%s' \
    'VOLPAROSSA_HELPER_V3_IPC_START_FAILURE_STAGE_V1=restart-lineage' \
    >"$restart_failure_record"
if restart_successor_start_failure_category "$restart_failure_record" \
    >/dev/null 2>&1; then
    printf '%s\n' 'successor classifier accepted a non-canonical record' >&2
    exit 1
fi
printf '%s\n' pending >"$restart_failure_record.next"
chmod 0600 "$restart_failure_record.next"
if restart_successor_start_failure_category "$restart_failure_record" \
    >/dev/null 2>&1; then
    printf '%s\n' 'successor classifier accepted a colliding temporary record' >&2
    exit 1
fi
rm -f -- "$restart_failure_record.next"

# The failed ExactPresent empty-cgroup freezer assumption is completely absent.
# A later MayOwn proof may freeze its separately named, non-empty, shape-checked
# service cgroup; it is not part of this ExactPresent handshake. The fixed FIFO
# release happens only after private GDB readiness and before waiting for the
# exact debugger child to complete.
if grep -E '(^|[^[:alnum:]_])restart_cgroup([^[:alnum:]_]|$)|restart cgroup' \
    "$gate" >/dev/null; then
    printf '%s\n' 'restart proof still depends on an empty unit cgroup freezer' >&2
    exit 1
fi
if ! awk '
    /^    vp_capture_file_is_safe "\$restart_successor_tracer_ready"/ {
        ready = NR; ready_count++
    }
    $0 == "        /bin/sh -c \047printf %s G >\"$1\"\047 sh \\" {
        release = NR; release_count++
    }
    /restart_successor_release_fifo/ { fifo_lines++; if (release > 0) fifo = NR }
    /^    wait "\$restart_successor_debugger_pid"$/ {
        waited = NR; waited_count++
    }
    END {
        valid = ready_count == 1 && release_count == 1 && waited_count == 1
        valid = valid && fifo_lines >= 6 && ready < release
        valid = valid && release <= fifo && fifo < waited
        if (!valid) exit 1
    }
' "$gate"; then
    printf '%s\n' 'successor FIFO release is not debugger-ready and bounded' >&2
    exit 1
fi

# Capture the debugger verdict, validate both private bounded logs, and expose
# only one allowlisted classifier slug before considering the boundary record.
if ! awk '
    /^    wait "\$restart_successor_debugger_pid"$/ {
        waited = NR; waited_count++
    }
    /^    restart_successor_debugger_status=\$\?$/ {
        status = NR; status_count++
    }
    /^    restart_successor_debugger_pid=$/ { clear_pid = NR; clear_pid_count++ }
    waited && /^    for restart_debugger_log in \\/ { logs = NR; logs_count++ }
    logs && /successor debugger log is unsafe/ { safe = NR; safe_count++ }
    logs && /successor debugger log exceeds 1 MiB/ { size = NR; size_count++ }
    /^    if \[ "\$restart_successor_debugger_status" -ne 0 \]; then$/ {
        failure = NR; failure_count++
    }
    failure && /^            restart_successor_debugger_failure_category \\/ {
        classifier = NR; classifier_count++
    }
    failure && /^        restart_successor_debugger_failure_category_is_safe \\/ {
        allowlist = NR; allowlist_count++
    }
    failure && /failed "successor recovery-boundary debugger failed:/ {
        bounded_failure = NR; bounded_failure_count++
    }
    /^    restart_successor_boundary=/ { boundary = NR; boundary_count++ }
    END {
        valid = waited_count == 1 && status_count == 1 && clear_pid_count == 1
        valid = valid && logs_count == 1 && safe_count == 1 && size_count == 1
        valid = valid && failure_count == 1 && classifier_count == 1
        valid = valid && allowlist_count == 1 && bounded_failure_count == 1
        valid = valid && boundary_count == 1
        valid = valid && waited < status && status < clear_pid
        valid = valid && clear_pid < logs && logs < safe && safe < size
        valid = valid && size < failure && failure < classifier
        valid = valid && classifier < allowlist && allowlist < bounded_failure
        valid = valid && bounded_failure < boundary
        if (!valid) exit 1
    }
' "$gate"; then
    printf '%s\n' 'successor debugger diagnostics are not private and bounded' >&2
    exit 1
fi

# A zero debugger status is not sufficient: GDB may observe an ordinary
# inferior exit before the breakpoint. Require the exact private boundary
# payload, bound to the adopted successor, before dropping the mount keeper.
if ! awk '
    /^    wait "\$restart_successor_debugger_pid"$/ {
        waited = NR; waited_count++
    }
    /^    restart_successor_boundary=/ {
        boundary = NR; boundary_count++; in_boundary = 1
    }
    in_boundary && /^    if ! vp_capture_file_is_safe "\$restart_successor_boundary"/ {
        safe = NR; safe_count++
    }
    in_boundary && /\|\| \[ -e "\$restart_successor_boundary\.next" \]/ {
        next_exists = NR; next_exists_count++
    }
    in_boundary && /\|\| \[ -L "\$restart_successor_boundary\.next" \]/ {
        next_symlink = NR; next_symlink_count++
    }
    in_boundary && /stat -Lc \047%s\047.*-gt 512/ {
        size_bound = NR; size_bound_count++
    }
    in_boundary && /wc -l <"\$restart_successor_boundary".*-ne 6/ {
        line_count = NR; line_count_count++
    }
    in_boundary && /restart_successor_boundary_time=\$\(sed -n \0471p\047/ {
        timestamp = NR; timestamp_count++
    }
    in_boundary && /^[[:space:]]*\[0-9\]\[0-9\]\[0-9\]\[0-9\]-\[0-9\]\[0-9\]-\[0-9\]\[0-9\]T\[0-9\]\[0-9\]:\[0-9\]\[0-9\]:\[0-9\]\[0-9\]Z\) ;;$/ {
        timestamp_shape = NR; timestamp_shape_count++
    }
    in_boundary && /restart_successor_boundary_time_canonical=\$\(date -u -d/ {
        timestamp_canonical = NR; timestamp_canonical_count++
    }
    in_boundary && /\047\+%Y-%m-%dT%H:%M:%SZ\047/ {
        timestamp_format = NR; timestamp_format_count++
    }
    in_boundary && /\[ "\$restart_successor_boundary_time_canonical" != \\/ {
        timestamp_compare = NR; timestamp_compare_count++
    }
    in_boundary && timestamp_compare && NR == timestamp_compare + 1 \
        && /"\$restart_successor_boundary_time" \] \\/ {
        timestamp_target = NR; timestamp_target_count++
    }
    in_boundary && /sed -n \0472p\047.* != \\/ {
        invocation = NR; invocation_count++
    }
    in_boundary && invocation && NR == invocation + 1 \
        && /"\$restart_successor_invocation_id" \] \\/ {
        invocation_target = NR; invocation_target_count++
    }
    in_boundary && /sed -n \0473p\047.* != \\/ { pid = NR; pid_count++ }
    in_boundary && pid && NR == pid + 1 \
        && /"\$restart_successor_pid" \] \\/ {
        pid_target = NR; pid_target_count++
    }
    in_boundary && /sed -n \0474p\047.* != \\/ {
        starttime = NR; starttime_count++
    }
    in_boundary && starttime && NR == starttime + 1 \
        && /"\$restart_successor_starttime" \] \\/ {
        starttime_target = NR; starttime_target_count++
    }
    in_boundary && /sed -n \0475p\047.* != \\/ { removal = NR; removal_count++ }
    in_boundary && removal && NR == removal + 1 \
        && /startup-removal-call-v1=systemd_fdstore::remove_restart_custody/ {
        removal_target = NR; removal_target_count++
    }
    in_boundary && /sed -n \0476p\047.* != \\/ { fdstore = NR; fdstore_count++ }
    in_boundary && fdstore && NR == fdstore + 1 \
        && /manager-fdstore-before-removal-v1=2/ {
        fdstore_target = NR; fdstore_target_count++
    }
    in_boundary && /successor recovery boundary is not exact/ {
        failure_count++
        if (failure_count == 1) first_failure = NR
        failure = NR
    }
    in_boundary && /^    kill "\$restart_mount_keeper_pid"/ {
        keeper = NR; keeper_count++; in_boundary = 0
    }
    END {
        valid = waited_count == 1 && boundary_count == 1 && safe_count == 1
        valid = valid && next_exists_count == 1 && next_symlink_count == 1
        valid = valid && size_bound_count == 1 && line_count_count == 1
        valid = valid && timestamp_count == 1 && timestamp_shape_count == 1
        valid = valid && timestamp_canonical_count == 1
        valid = valid && timestamp_format_count == 1
        valid = valid && timestamp_compare_count == 1 && timestamp_target_count == 1
        valid = valid && invocation_count == 1 && pid_count == 1
        valid = valid && starttime_count == 1 && removal_count == 1
        valid = valid && fdstore_count == 1
        valid = valid && invocation_target_count == 1 && pid_target_count == 1
        valid = valid && starttime_target_count == 1
        valid = valid && removal_target_count == 1 && fdstore_target_count == 1
        valid = valid && failure_count == 5 && keeper_count == 1
        valid = valid && waited < boundary && boundary < safe
        valid = valid && safe < next_exists && next_exists < next_symlink
        valid = valid && next_symlink < size_bound && size_bound < line_count
        valid = valid && line_count < first_failure
        valid = valid && first_failure < timestamp && timestamp < timestamp_shape
        valid = valid && timestamp_shape < timestamp_canonical
        valid = valid && timestamp_canonical < timestamp_format
        valid = valid && timestamp_format < timestamp_compare
        valid = valid && timestamp_compare < timestamp_target
        valid = valid && timestamp_target < invocation && invocation < invocation_target
        valid = valid && invocation_target < pid && pid < pid_target
        valid = valid && pid_target < starttime && starttime < starttime_target
        valid = valid && starttime_target < removal && removal < removal_target
        valid = valid && removal_target < fdstore && fdstore < fdstore_target
        valid = valid && fdstore_target < failure
        valid = valid && failure < keeper
        if (!valid) exit 1
    }
' "$gate"; then
    printf '%s\n' 'successor debugger success is not bound to its exact recovery record' >&2
    exit 1
fi

# Crash state is read before the delayed restart can begin. Old authority is
# cleared only after the failed invocation and marker are re-fenced. The exact
# crash outcome and bounded logs precede the closed GDB-status decision. The
# successor launcher barrier is manager-bound before adoption and GDB release.
debugger_status_case=$tmp/debugger-status-case
sed -n '/^    case \$restart_initial_debugger_status in$/,/^    esac$/p' \
    "$gate" >"$debugger_status_case"
printf '%s\n' \
    '    case $restart_initial_debugger_status in' \
    '        0) ;;' \
    "        *) failed 'initial forced-crash debugger did not complete' ;;" \
    '    esac' | cmp -s - "$debugger_status_case"
initial_debugger_log_loop=$tmp/initial-debugger-log-loop
awk '
    /forced-crash boundary record is unavailable/ { after_crash_record = 1 }
    after_crash_record && /^    for restart_debugger_log in \\$/ { capture = 1 }
    capture { print }
    capture && /^    done$/ { exit }
' "$gate" >"$initial_debugger_log_loop"
printf '%s\n' \
    '    for restart_debugger_log in \' \
    '        "$restart_debugger_initial_stdout" "$restart_debugger_initial_stderr"; do' \
    '        vp_capture_file_is_safe "$restart_debugger_log" \' \
    "            || failed 'initial debugger log is unsafe'" \
    "        [ \"\$(stat -Lc '%s' \"\$restart_debugger_log\")\" -le 1048576 ] \\" \
    "            || failed 'initial debugger log exceeds 1 MiB'" \
    '    done' | cmp -s - "$initial_debugger_log_loop"
if ! awk '
    /^[[:space:]]*restart_initial_debugger_status=/ {
        debugger_assignment_count++
    }
    /restart_initial_debugger_status=\$\?/ {
        debugger_done = NR; debugger_done_count++
    }
    /post-crash forced-helper MainPID is not zero/ { crash_main = NR; crash_main_count++ }
    /post-crash forced-helper restart count is not zero/ {
        crash_count = NR; crash_count_count++
    }
    /post-crash forced-helper result is not signal/ { crash_result = NR; crash_result_count++ }
    /post-crash forced-helper code is not CLD_KILLED/ { crash_code = NR; crash_code_count++ }
    /post-crash forced-helper status is not SIGKILL/ { crash_status = NR; crash_status_count++ }
    /post-crash failed invocation lost its exact ownership fence/ { old_fence = NR }
    old_fence && /^    unit_may_own=yes unit_owned=no unit_invocation_id=$/ {
        tentative_transition = NR; tentative_transition_count++
    }
    /^        report_restart_crash_record_diagnostic \\$/ {
        crash_diagnostic = NR; crash_diagnostic_count++
    }
    /forced-crash boundary record is unavailable/ { crash_record = NR }
    crash_record && !debugger_status && /^    for restart_debugger_log in \\$/ {
        debugger_logs = NR; debugger_logs_count++; in_debugger_logs = 1
    }
    in_debugger_logs && /^    done$/ {
        debugger_logs_done = NR; debugger_logs_done_count++; in_debugger_logs = 0
    }
    /^[[:space:]]*case \$restart_initial_debugger_status in$/ {
        debugger_status = NR; debugger_status_count++
    }
    /^[[:space:]]*0\) ;;$/ { clean_status = NR; clean_status_count++ }
    /initial forced-crash debugger did not complete/ {
        debugger_failure = NR; debugger_failure_count++
    }
    /restart-observer after-crash/ { after_crash = NR; after_crash_count++ }
    /^    restart_successor_barrier=/ { barrier = NR; barrier_count++ }
    /restart successor pre-exec barrier is not manager-bound/ {
        barrier_bound = NR; barrier_bound_count++
    }
    /restart successor starttime is unavailable/ { successor_starttime = NR }
    /restart successor count is not exactly one/ { successor_count = NR }
    /restart successor lost the ownership marker/ { successor_marker = NR }
    /^    adopt_tentative_unit \\/ { adoption = NR; adoption_count++ }
    /^    restart_successor_invocation_id=\$unit_invocation_id$/ { invocation = NR }
    /restart successor lineage changed after adoption/ { refence = NR }
    /^    restart_successor_tracer_ready=/ { tracer = NR }
    END {
        valid = debugger_assignment_count == 1 && debugger_done_count == 1
        valid = valid && crash_main_count == 1 && crash_count_count == 1
        valid = valid && crash_result_count == 1 && crash_code_count == 1
        valid = valid && crash_status_count == 1
        valid = valid && debugger_done < crash_main
        valid = valid && crash_main < crash_count && crash_count < crash_result
        valid = valid && crash_result < crash_code && crash_code < crash_status
        valid = valid && crash_status < old_fence
        valid = valid && old_fence < tentative_transition
        valid = valid && tentative_transition_count == 1
        valid = valid && tentative_transition < crash_diagnostic
        valid = valid && crash_diagnostic_count == 1
        valid = valid && crash_diagnostic < crash_record
        valid = valid && crash_record < debugger_logs && debugger_logs_count == 1
        valid = valid && debugger_logs < debugger_logs_done
        valid = valid && debugger_logs_done_count == 1
        valid = valid && debugger_logs_done < debugger_status
        valid = valid && debugger_status_count == 1 && clean_status_count == 1
        valid = valid && debugger_status < clean_status
        valid = valid && clean_status < debugger_failure
        valid = valid && debugger_failure_count == 1
        valid = valid && debugger_failure < after_crash
        valid = valid && barrier_count == 1 && barrier_bound_count == 1
        valid = valid && after_crash_count == 1 && after_crash < barrier
        valid = valid && barrier < barrier_bound && barrier_bound < successor_starttime
        valid = valid && successor_starttime < successor_count
        valid = valid && successor_count < successor_marker
        valid = valid && successor_marker < adoption && adoption_count == 1
        valid = valid && adoption < invocation && invocation < refence && refence < tracer
        if (!valid) exit 1
    }
' "$gate"; then
    printf '%s\n' 'post-crash and successor barrier ownership are not fail-closed' >&2
    exit 1
fi

[ "$(grep -Fc 'timeout --preserve-status --signal=TERM --kill-after=5s' "$gate")" -eq 7 ]
[ "$(grep -Fc 'prlimit --core=0:0 --fsize=1048576:1048576 --' "$gate")" -eq 7 ]
grep -F '30s \' "$gate" >/dev/null
grep -F '45s \' "$gate" >/dev/null
[ "$(grep -Fc '"$restart_wait" -lt 2400' "$gate")" -eq 1 ]
[ "$(grep -Fc "exceeds 1 MiB'" "$gate")" -eq 2 ]

# EXIT handling is lineage-safe: exact debugger and namespace-keeper identities
# are killed and waited before normal exact-unit retirement.
if ! awk '
    /^cleanup\(\) \{$/ { in_cleanup = 1; next }
    in_cleanup && /kill "\$restart_successor_debugger_pid"/ { debugger_kill = NR }
    in_cleanup && /wait "\$restart_successor_debugger_pid"/ { debugger_wait = NR }
    in_cleanup && /kill "\$restart_mount_keeper_pid"/ { keeper_kill = NR }
    in_cleanup && /wait "\$restart_mount_keeper_pid"/ { keeper_wait = NR }
    in_cleanup && /^    retirement_complete=no$/ { retirement_begin = NR }
    in_cleanup && /^    if retire_unit; then$/ { retirement = NR }
    in_cleanup && /^        retirement_complete=yes$/ { retirement_commit = NR }
    in_cleanup && /^    if \[ "\$retirement_complete" = yes \]; then$/ {
        stage_guard = NR
    }
    in_cleanup && /^        if ! remove_temporary_stage; then$/ {
        stage_removal = NR
    }
    in_cleanup && /^}$/ { in_cleanup = 0 }
    END {
        valid = debugger_kill > 0 && debugger_kill < debugger_wait
        valid = valid && debugger_wait < keeper_kill && keeper_kill < keeper_wait
        valid = valid && keeper_wait < retirement_begin && retirement_begin < retirement
        valid = valid && retirement < retirement_commit
        valid = valid && retirement_commit < stage_guard
        valid = valid && stage_guard < stage_removal
        if (!valid) exit 1
    }
' "$gate"; then
    printf '%s\n' 'restart EXIT cleanup is not ordered and exactly bounded' >&2
    exit 1
fi

# Reported manager counts are values returned by the two read-only manager
# observations, not literals asserted by the report generator.
grep -F 'hook_restart_manager_before_removal=$hook_fdstore_count_before' "$hook" >/dev/null
grep -F '"manager-fdstore-before-removal-v1=$hook_restart_manager_before_removal"' \
    "$hook" >/dev/null
grep -F 'hook_restart_manager_after_removal=$hook_fdstore_count_after' "$hook" >/dev/null
grep -F '"manager-fdstore-after-removal-v1=$hook_restart_manager_after_removal"' \
    "$hook" >/dev/null
grep -F 'restart_manager_before=${restart_manager_before_record#manager-fdstore-before-removal-v1=}' \
    "$gate" >/dev/null
grep -F 'restart_manager_after=${restart_manager_after_record#manager-fdstore-after-removal-v1=}' \
    "$gate" >/dev/null

# Restart evidence validation must create two independent private captures.
# Passing both names to one install invocation treats the first as another
# source and exits before the validator can run.
# shellcheck disable=SC2016
if grep -F '"$restart_validator_stdout" "$restart_validator_stderr"' \
    "$gate" >/dev/null \
    || [ "$(grep -Fc 'install -o root -g root -m 0600 /dev/null "$restart_validator_stdout"' "$gate")" -ne 1 ] \
    || [ "$(grep -Fc 'install -o root -g root -m 0600 /dev/null "$restart_validator_stderr"' "$gate")" -ne 1 ] \
    || [ "$(grep -Fc 'final_checkpoint=restart-report-validation' "$gate")" -ne 1 ] \
    || [ "$(grep -Fc 'vp_capture_file_is_safe "$restart_report_path"' "$gate")" -ne 1 ] \
    || [ "$(grep -Fc 'vp_capture_file_is_safe "$restart_validator_stdout"' "$gate")" -ne 1 ] \
    || [ "$(grep -Fc 'vp_capture_file_is_safe "$restart_validator_stderr"' "$gate")" -ne 1 ]; then
    printf '%s\n' \
        'restart evidence validation does not use two exact private captures' >&2
    exit 1
fi

for forbidden_claim in \
    fdstore_remove_notifications \
    fdstore_remove_ancillary_descriptors \
    fresh_empty_snapshot_count \
    fresh_empty_snapshots_equal \
    manager_empty_observation_count \
    manager_empty_observations_equal \
    fdstore_idle_observation
do
    if grep -F "$forbidden_claim" "$schema" "$fixture" "$validator" >/dev/null; then
        printf 'restart report retains an unobserved claim: %s\n' "$forbidden_claim" >&2
        exit 1
    fi
done
jq -e '
  .scope.restart_recovery == false
  and .scope.cleanup_confirmed_mixed_restart == false
  and .scope.may_own_recovery == false
  and .scope.cleanup_owned == false
  and .scope.cleanup_confirmed_exact_present_singleton == true
  and (.checks | length == 20)
' "$fixture" >/dev/null
grep -F 'helper-restart-exact-present-evidence-v1.json' "$workflow" >/dev/null
grep -F 'helper-restart-vm-environment-v1.json' "$workflow" >/dev/null
grep -F 'retention-days: 90' "$workflow" >/dev/null

printf '%s\n' \
    'PASS: singleton ExactPresent forced-crash KVM contract is bounded, lineage-safe, and claim-exact.'
