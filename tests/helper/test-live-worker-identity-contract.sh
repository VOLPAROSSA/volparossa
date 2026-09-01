#!/bin/sh
# SPDX-License-Identifier: GPL-3.0-only
# Unprivileged argument, preview, and static safety contract for the live helper gate.
set -eu

export LC_ALL=C
PATH=/usr/sbin:/usr/bin:/sbin:/bin
export PATH
umask 077

script_directory=$(CDPATH='' cd -- "$(dirname -- "$0")" && pwd)
repository_directory=$(CDPATH='' cd -- "$script_directory/../.." && pwd)
gate=$repository_directory/tests/helper/require-live-worker-identity-proof.sh
capture_library=$repository_directory/tests/helper/lib/live-worker-proof-capture.sh
ipc_hook=$repository_directory/tests/helper/lib/production-ipc-unit-hook.sh
evidence_validator=$repository_directory/tests/helper/validate-helper-boundary-evidence-v1.sh
evidence_schema=$repository_directory/tests/helper/helper-boundary-evidence-v1.schema.json
worker_source=$repository_directory/crates/volparossa-helper/src/worker_v3.rs
worker_sandbox_source=$repository_directory/crates/volparossa-helper/src/worker_sandbox.rs
temporary_directory=$(mktemp -d /tmp/volparossa-helper-proof-contract.XXXXXX)
resolver_authority_outside=
resolver_runtime_directory=
case $temporary_directory in
    /tmp/volparossa-helper-proof-contract.??????) ;;
    *)
        printf 'unsafe helper proof contract directory: %s\n' "$temporary_directory" >&2
        exit 1
        ;;
esac
cleanup() {
    if [ -n "$resolver_authority_outside" ]; then
        case $resolver_authority_outside in
            /tmp/volparossa-resolver-authority-outside.??????)
                rm -f -- "$resolver_authority_outside"
                ;;
            *)
                printf 'unsafe resolver authority cleanup path: %s\n' \
                    "$resolver_authority_outside" >&2
                ;;
        esac
    fi
    if [ -n "$resolver_runtime_directory" ]; then
        case $resolver_runtime_directory in
            /tmp/volparossa-resolver-runtime.??????)
                rm -rf --one-file-system -- "$resolver_runtime_directory"
                ;;
            *)
                printf 'unsafe resolver runtime cleanup path: %s\n' \
                    "$resolver_runtime_directory" >&2
                ;;
        esac
    fi
    rm -rf --one-file-system -- "$temporary_directory"
}
trap cleanup EXIT
trap 'exit 129' HUP
trap 'exit 130' INT
trap 'exit 143' TERM

if [ "$(id -u)" -eq 0 ]; then
    printf '%s\n' 'BLOCKED: helper proof contract test must remain unprivileged' >&2
    exit 77
fi
if [ ! -f "$gate" ] || [ ! -x "$gate" ] || [ -L "$gate" ]; then
    printf '%s\n' 'live helper proof gate is not one executable regular file' >&2
    exit 1
fi
if [ ! -f "$capture_library" ] || [ -L "$capture_library" ]; then
    printf '%s\n' 'live helper proof capture library is not one regular file' >&2
    exit 1
fi
if [ ! -f "$ipc_hook" ] || [ ! -x "$ipc_hook" ] || [ -L "$ipc_hook" ]; then
    printf '%s\n' 'production IPC unit hook is not one executable regular file' >&2
    exit 1
fi
if [ ! -f "$evidence_validator" ] || [ ! -x "$evidence_validator" ] \
    || [ -L "$evidence_validator" ]; then
    printf '%s\n' 'helper-boundary evidence validator is not one executable regular file' >&2
    exit 1
fi
if [ ! -f "$evidence_schema" ] || [ ! -r "$evidence_schema" ] \
    || [ -L "$evidence_schema" ]; then
    printf '%s\n' 'helper-boundary evidence schema is not one readable regular file' >&2
    exit 1
fi
for worker_contract_source in "$worker_source" "$worker_sandbox_source"; do
    if [ ! -f "$worker_contract_source" ] || [ -L "$worker_contract_source" ]; then
        printf 'worker contract source is unsafe: %s\n' "$worker_contract_source" >&2
        exit 1
    fi
done
sh -n "$gate"
sh -n "$capture_library"
sh -n "$ipc_hook"
sh -n "$evidence_validator"
jq -e . "$evidence_schema" >/dev/null

VP_CAPTURE_OWNER_UID=$(id -u)
VP_CAPTURE_OWNER_GID=$(id -g)
export VP_CAPTURE_OWNER_UID VP_CAPTURE_OWNER_GID
# shellcheck source=tests/helper/lib/live-worker-proof-capture.sh
. "$capture_library"

counter=0
last_stdout=
last_stderr=
expect_status() {
    expected=$1
    shift
    counter=$((counter + 1))
    last_stdout=$temporary_directory/stdout.$counter
    last_stderr=$temporary_directory/stderr.$counter
    set +e
    "$@" >"$last_stdout" 2>"$last_stderr"
    observed=$?
    set -e
    if [ "$observed" -ne "$expected" ]; then
        printf 'expected exit %s, got %s: %s\n' "$expected" "$observed" "$*" >&2
        sed -n '1,80p' "$last_stderr" >&2
        exit 1
    fi
}

# Unexpected shell exits may disclose only fixed, coarse progress markers from
# the real EXIT cleanup. Exercise the exact helpers and the status-preserving trap.
driver_phase_functions=$temporary_directory/driver-phase-functions.sh
{
    sed -n '/^driver_phase_is_safe() {$/,/^}$/p' "$gate"
    sed -n '/^report_unexpected_driver_phase() {$/,/^}$/p' "$gate"
    sed -n '/^final_checkpoint_is_safe() {$/,/^}$/p' "$gate"
    sed -n '/^report_unexpected_final_checkpoint() {$/,/^}$/p' "$gate"
} >"$driver_phase_functions"
if [ "$(grep -c '^driver_phase_is_safe() {$' "$driver_phase_functions")" -ne 1 ] \
    || [ "$(grep -c '^report_unexpected_driver_phase() {$' \
        "$driver_phase_functions")" -ne 1 ] \
    || [ "$(grep -c '^final_checkpoint_is_safe() {$' \
        "$driver_phase_functions")" -ne 1 ] \
    || [ "$(grep -c '^report_unexpected_final_checkpoint() {$' \
        "$driver_phase_functions")" -ne 1 ]; then
    printf '%s\n' 'the unexpected progress helpers are not uniquely extractable' >&2
    exit 1
fi
sh -n "$driver_phase_functions"
# shellcheck disable=SC1090
. "$driver_phase_functions"

expected_driver_phases=$temporary_directory/expected-driver-phases
printf '%s\n' \
    staging \
    worker-launch \
    worker-terminal-observation \
    worker-retirement \
    production-launch \
    production-observation \
    production-retirement \
    restart-launch \
    restart-observation \
    restart-retirement \
    final-verification >"$expected_driver_phases"
while IFS= read -r expected_driver_phase; do
    driver_phase_is_safe "$expected_driver_phase" || {
        printf 'driver phase is not allowlisted: %s\n' "$expected_driver_phase" >&2
        exit 1
    }
    expect_status 0 report_unexpected_driver_phase "$expected_driver_phase"
    if [ -s "$last_stdout" ] \
        || [ "$(cat "$last_stderr")" \
            != "VOLPAROSSA_HELPER_LIVE_DRIVER_PHASE_V1=$expected_driver_phase" ] \
        || [ "$(wc -l <"$last_stderr")" -ne 1 ]; then
        printf 'driver phase did not emit one fixed record: %s\n' \
            "$expected_driver_phase" >&2
        exit 1
    fi
done <"$expected_driver_phases"
expect_status 1 report_unexpected_driver_phase
test ! -s "$last_stdout" && test ! -s "$last_stderr"
expect_status 1 report_unexpected_driver_phase 'production-observation/private-record'
test ! -s "$last_stdout" && test ! -s "$last_stderr"

expected_final_checkpoints=$temporary_directory/expected-final-checkpoints
printf '%s\n' \
    host-state \
    structured-reporting \
    cleanup-summary \
    lifecycle-summary \
    artifact-integrity \
    source-integrity \
    report-times \
    report-generation \
    report-validation \
    restart-report-validation \
    publication-fence \
    stage-retirement >"$expected_final_checkpoints"
while IFS= read -r expected_final_checkpoint; do
    final_checkpoint_is_safe "$expected_final_checkpoint" || {
        printf 'final checkpoint is not allowlisted: %s\n' \
            "$expected_final_checkpoint" >&2
        exit 1
    }
    expect_status 0 report_unexpected_final_checkpoint "$expected_final_checkpoint"
    if [ -s "$last_stdout" ] \
        || [ "$(cat "$last_stderr")" \
            != "VOLPAROSSA_HELPER_LIVE_FINAL_CHECKPOINT_V1=$expected_final_checkpoint" ] \
        || [ "$(wc -l <"$last_stderr")" -ne 1 ]; then
        printf 'final checkpoint did not emit one fixed record: %s\n' \
            "$expected_final_checkpoint" >&2
        exit 1
    fi
done <"$expected_final_checkpoints"
expect_status 1 report_unexpected_final_checkpoint
test ! -s "$last_stdout" && test ! -s "$last_stderr"
expect_status 1 report_unexpected_final_checkpoint 'report-validation/private-record'
test ! -s "$last_stdout" && test ! -s "$last_stderr"

gate_cleanup_function=$temporary_directory/gate-cleanup-function.sh
sed -n '/^cleanup() {$/,/^}$/p' "$gate" >"$gate_cleanup_function"
# This is a literal gate-source contract; expansion here would defeat it.
# shellcheck disable=SC2016
if [ "$(grep -c '^cleanup() {$' "$gate_cleanup_function")" -ne 1 ] \
    || [ "$(grep -Fc 'report_unexpected_driver_phase "${driver_phase:-}" || :' \
        "$gate_cleanup_function")" -ne 1 ]; then
    printf '%s\n' 'the status-preserving driver-phase cleanup is not unique' >&2
    exit 1
fi
sh -n "$gate_cleanup_function"
exercise_gate_cleanup() (
    phase=$1
    checkpoint=$2
    structured=$3
    requested_status=$4
    retire_status=$5
    removal_status=$6
    # Invoked indirectly by the extracted EXIT cleanup.
    # shellcheck disable=SC2317
    retire_unit() { return "$retire_status"; }
    # shellcheck disable=SC2317
    remove_temporary_stage() {
        if [ "$removal_status" -eq 9 ]; then
            printf '%s\n' 'unsafe-stage-removal-after-ambiguous-retirement' >&2
            return 0
        fi
        return "$removal_status"
    }
    cleanup_error=no
    structured_failure_reported=$structured
    if [ "$phase" = missing ]; then
        unset driver_phase
    else
        driver_phase=$phase
    fi
    if [ "$checkpoint" = missing ]; then
        unset final_checkpoint
    else
        final_checkpoint=$checkpoint
    fi
    : "$cleanup_error" "$structured_failure_reported" \
        "${driver_phase:-}" "${final_checkpoint:-}"
    # shellcheck disable=SC1090
    . "$gate_cleanup_function"
    trap cleanup EXIT
    exit "$requested_status"
)
expect_status 2 exercise_gate_cleanup worker-terminal-observation missing no 2 0 0
test ! -s "$last_stdout"
test "$(cat "$last_stderr")" \
    = 'VOLPAROSSA_HELPER_LIVE_DRIVER_PHASE_V1=worker-terminal-observation'
expect_status 2 exercise_gate_cleanup missing missing no 2 0 0
test ! -s "$last_stdout" && test ! -s "$last_stderr"
expect_status 2 exercise_gate_cleanup invalid-phase missing no 2 0 0
test ! -s "$last_stdout" && test ! -s "$last_stderr"
expect_status 2 exercise_gate_cleanup production-launch report-validation yes 2 0 0
test ! -s "$last_stdout" && test ! -s "$last_stderr"
expect_status 1 exercise_gate_cleanup worker-retirement missing no 0 1 9
test ! -s "$last_stdout"
test "$(cat "$last_stderr")" \
    = 'VOLPAROSSA_HELPER_LIVE_DRIVER_PHASE_V1=worker-retirement'
expect_status 2 exercise_gate_cleanup production-retirement missing no 2 1 1
test ! -s "$last_stdout"
test "$(cat "$last_stderr")" \
    = 'VOLPAROSSA_HELPER_LIVE_DRIVER_PHASE_V1=production-retirement'
expect_status 2 exercise_gate_cleanup final-verification report-validation no 2 0 0
test ! -s "$last_stdout"
test "$(cat "$last_stderr")" = \
    'VOLPAROSSA_HELPER_LIVE_DRIVER_PHASE_V1=final-verification
VOLPAROSSA_HELPER_LIVE_FINAL_CHECKPOINT_V1=report-validation'
expect_status 2 exercise_gate_cleanup final-verification invalid-checkpoint no 2 0 0
test ! -s "$last_stdout"
test "$(cat "$last_stderr")" \
    = 'VOLPAROSSA_HELPER_LIVE_DRIVER_PHASE_V1=final-verification'

if ! awk '
    /^driver_phase=staging$/ { staging++; staging_line = NR }
    /^driver_phase=worker-launch$/ { worker_launch++; worker_launch_line = NR }
    /^driver_phase=worker-terminal-observation$/ {
        worker_terminal++; worker_terminal_line = NR
    }
    /^driver_phase=worker-retirement$/ { worker_retirement++; worker_retirement_line = NR }
    /^    driver_phase=production-launch$/ {
        production_launch++; production_launch_line = NR
    }
    /^    driver_phase=production-observation$/ {
        production_observation++; production_observation_line = NR
    }
    /^    driver_phase=production-retirement$/ {
        production_retirement++; production_retirement_line = NR
    }
    /^driver_phase=final-verification$/ { final_verification++; final_verification_line = NR }
    /^final_checkpoint=structured-reporting$/ {
        structured_checkpoint++; structured_checkpoint_line = NR
    }
    END {
        valid = staging == 1 && worker_launch == 1 && worker_terminal == 1
        valid = valid && worker_retirement == 1 && production_launch == 1
        valid = valid && production_observation == 1 && production_retirement == 1
        valid = valid && final_verification == 1 && structured_checkpoint == 1
        valid = valid && staging_line < worker_launch_line
        valid = valid && worker_launch_line < worker_terminal_line
        valid = valid && worker_terminal_line < worker_retirement_line
        valid = valid && worker_retirement_line < production_launch_line
        valid = valid && production_launch_line < production_observation_line
        valid = valid && production_observation_line < production_retirement_line
        valid = valid && production_retirement_line < final_verification_line
        valid = valid && final_verification_line < structured_checkpoint_line
        if (!valid) exit 1
    }
' "$gate"; then
    printf '%s\n' 'the coarse driver phases are not unique and monotonic' >&2
    exit 1
fi

# Retained VM evidence may expose only one fixed, privacy-safe predicate group.
# Exercise the exact gate helpers and pin both the allowlist and first-failure rule.
proof_failure_functions=$temporary_directory/proof-failure-functions.sh
{
    sed -n '/^proof_failure_reason_is_safe() {$/,/^}$/p' "$gate"
    sed -n '/^record_proof_failure() {$/,/^}$/p' "$gate"
    sed -n '/^worker_confinement_failure_is_safe() {$/,/^}$/p' "$gate"
    sed -n '/^record_worker_confinement_failure() {$/,/^}$/p' "$gate"
    sed -n '/^record_helper_live_proof_failure_stage() {$/,/^}$/p' "$gate"
    sed -n '/^classify_worker_live_proof_terminal() {$/,/^}$/p' "$gate"
    sed -n '/^record_worker_launch_failure() {$/,/^}$/p' "$gate"
    sed -n '/^report_worker_launch_diagnostic() {$/,/^}$/p' "$gate"
    sed -n '/^report_worker_confinement_diagnostic() {$/,/^}$/p' "$gate"
    sed -n '/^production_start_failure_stage_is_safe() {$/,/^}$/p' "$gate"
    sed -n '/^production_functional_probe_failure_value_is_safe() {$/,/^}$/p' "$gate"
    sed -n '/^report_production_launch_diagnostic() {$/,/^}$/p' "$gate"
    sed -n '/^report_proof_failure() {$/,/^}$/p' "$gate"
} >"$proof_failure_functions"
if [ "$(grep -c '^proof_failure_reason_is_safe() {$' "$proof_failure_functions")" -ne 1 ] \
    || [ "$(grep -c '^record_proof_failure() {$' "$proof_failure_functions")" -ne 1 ] \
    || [ "$(grep -c '^worker_confinement_failure_is_safe() {$' \
        "$proof_failure_functions")" -ne 1 ] \
    || [ "$(grep -c '^record_worker_confinement_failure() {$' \
        "$proof_failure_functions")" -ne 1 ] \
    || [ "$(grep -c '^record_helper_live_proof_failure_stage() {$' \
        "$proof_failure_functions")" -ne 1 ] \
    || [ "$(grep -c '^classify_worker_live_proof_terminal() {$' \
        "$proof_failure_functions")" -ne 1 ] \
    || [ "$(grep -c '^record_worker_launch_failure() {$' \
        "$proof_failure_functions")" -ne 1 ] \
    || [ "$(grep -c '^report_worker_launch_diagnostic() {$' \
        "$proof_failure_functions")" -ne 1 ] \
    || [ "$(grep -c '^report_worker_confinement_diagnostic() {$' \
        "$proof_failure_functions")" -ne 1 ] \
    || [ "$(grep -c '^production_start_failure_stage_is_safe() {$' \
        "$proof_failure_functions")" -ne 1 ] \
    || [ "$(grep -c '^production_functional_probe_failure_value_is_safe() {$' \
        "$proof_failure_functions")" -ne 1 ] \
    || [ "$(grep -c '^report_production_launch_diagnostic() {$' \
        "$proof_failure_functions")" -ne 1 ] \
    || [ "$(grep -c '^report_proof_failure() {$' "$proof_failure_functions")" -ne 1 ]; then
    printf '%s\n' 'the privacy-safe proof failure helpers are not uniquely extractable' >&2
    exit 1
fi
sh -n "$proof_failure_functions"

expected_proof_failure_reasons=$temporary_directory/expected-proof-failure-reasons
printf '%s\n' \
    worker-launch-status \
    worker-launch-envelope \
    worker-manager-binding \
    worker-helper-parent-contract \
    worker-helper-runtime-preparation \
    worker-helper-worker-spawn \
    worker-helper-publication \
    worker-helper-retirement-cleanup \
    worker-terminal-state \
    worker-unit-contract \
    worker-proof-records \
    worker-confinement \
    worker-retirement \
    production-launch-status \
    production-launch-envelope \
    production-manager-binding \
    production-running-state \
    production-unit-contract \
    production-confinement \
    production-process-identity \
    production-socket-identity \
    production-start-records \
    production-runtime-layout \
    production-process-stability \
    production-retirement \
    production-lock-release \
    production-stop-records \
    | sort -u >"$expected_proof_failure_reasons"

observed_proof_failure_allowlist=$temporary_directory/observed-proof-failure-allowlist
sed -n '/^proof_failure_reason_is_safe() {$/,/^}$/p' "$gate" \
    | sed -nE 's/^[[:space:]]*([a-z][a-z-]*)(\|\\|\))[[:space:]]*$/\1/p' \
    | sort -u >"$observed_proof_failure_allowlist"
observed_proof_failure_calls=$temporary_directory/observed-proof-failure-calls
sed -n "s/.*record_proof_failure '\([a-z][a-z-]*\)'.*/\1/p" "$gate" \
    | sort -u >"$observed_proof_failure_calls"
if ! cmp -s "$expected_proof_failure_reasons" "$observed_proof_failure_allowlist" \
    || ! cmp -s "$expected_proof_failure_reasons" "$observed_proof_failure_calls"; then
    printf '%s\n' 'the recorded proof failures do not equal the fixed reason allowlist' >&2
    exit 1
fi
all_proof_failure_calls=$(grep -Ec 'record_proof_failure[[:space:]]' "$gate")
literal_proof_failure_calls=$(grep -Ec \
    "record_proof_failure '[a-z][a-z-]*'" "$gate")
if [ "$all_proof_failure_calls" -ne "$literal_proof_failure_calls" ]; then
    printf '%s\n' 'proof failure state can bypass the literal first-failure recorder' >&2
    exit 1
fi
if ! awk '
    /^record_proof_failure\(\) \{$/ { in_recorder = 1; next }
    in_recorder && /^}$/ { in_recorder = 0; next }
    /^[[:space:]]*unset[[:space:]]+production_ok[[:space:]]*$/ {
        production_unset++
        production_unset_line = NR
        next
    }
    /(^|[^[:alnum:]_])(proof_ok|production_ok|proof_failure_reason)[[:space:]]*=/ {
        assignment = $0
        sub(/^[[:space:]]*/, "", assignment)
        if (in_recorder) {
            if (assignment == "proof_ok=no") proof_no++
            else if (assignment == "production_ok=no") production_no++
            else if (assignment == "proof_failure_reason=$1") reason_record++
            else invalid++
        } else {
            if (assignment == "proof_ok=yes") {
                proof_yes++
                proof_yes_line = NR
            } else if (assignment == "production_ok=yes") {
                production_yes++
                production_yes_line = NR
            } else if (assignment == "proof_failure_reason=") {
                reason_initial++
                reason_initial_line = NR
            } else invalid++
        }
    }
    END {
        valid = invalid == 0 && proof_no == 1 && production_no == 1
        valid = valid && reason_record == 1 && proof_yes == 1
        valid = valid && production_yes == 1 && reason_initial == 1
        valid = valid && production_unset == 1
        valid = valid && production_unset_line < reason_initial_line
        valid = valid && reason_initial_line < proof_yes_line
        valid = valid && proof_yes_line < production_yes_line
        if (!valid) exit 1
    }
' "$gate"; then
    printf '%s\n' 'proof failure state has a direct or non-canonical assignment' >&2
    exit 1
fi
if ! awk '
    /^[[:space:]]*production_ok=yes$/ { production_boundary = NR }
    /record_proof_failure .*worker-/ {
        worker_calls++
        if (production_boundary > 0) invalid++
    }
    /record_proof_failure .*production-/ {
        production_calls++
        if (production_boundary == 0) invalid++
    }
    END {
        if (invalid > 0 || worker_calls == 0 || production_calls == 0) exit 1
    }
' "$gate"; then
    printf '%s\n' 'worker or production failure labels escaped their exact phase' >&2
    exit 1
fi
# These are literal gate-source contracts; expansion here would defeat them.
# shellcheck disable=SC2016
if [ "$(grep -Fc 'report_proof_failure "$proof_failure_reason"' "$gate")" -ne 1 ] \
    || [ "$(grep -Ec '^[[:space:]]+report_worker_launch_diagnostic([[:space:]]|$)' \
        "$gate")" -ne 1 ] \
    || [ "$(grep -Fc "printf 'live worker-identity proof failed: predicate rejected: %s\\n' \"\$1\" >&2" \
        "$proof_failure_functions")" -ne 1 ]; then
    printf '%s\n' 'the final proof failure does not use the revalidating reporter once' >&2
    exit 1
fi

failed() {
    printf 'diagnostic failure: %s\n' "$1" >&2
    exit 1
}
# shellcheck source=/dev/null
. "$proof_failure_functions"
while IFS= read -r proof_failure_reason_under_test; do
    proof_failure_reason_is_safe "$proof_failure_reason_under_test" || {
        printf 'allowlisted proof failure was rejected: %s\n' \
            "$proof_failure_reason_under_test" >&2
        exit 1
    }
done <"$expected_proof_failure_reasons"

# A retired worker's numeric PID and nsfs inode may be reused after the final
# live pin closes. Cross-generation numeric inequalities are therefore not
# identity proofs; every active generation is bound through current custody.
# shellcheck disable=SC2016
for forbidden_stale_identity_comparison in \
    '[ "$hook_functional_exit_worker_pid" != "$hook_functional_worker_pid" ]' \
    '[ "$hook_functional_pair_worker_pid" != "$hook_functional_worker_pid" ]' \
    '[ "$hook_functional_pair_worker_pid" != "$hook_functional_exit_worker_pid" ]' \
    '[ "$hook_functional_exit_worker_namespace" !=' \
    '[ "$hook_functional_pair_worker_namespace" !='
do
    if grep -F "$forbidden_stale_identity_comparison" "$ipc_hook" >/dev/null; then
        printf 'production hook treats a reusable numeric identity as authority: %s\n' \
            "$forbidden_stale_identity_comparison" >&2
        exit 1
    fi
done

expected_production_start_stages=$temporary_directory/expected-production-start-stages
printf '%s\n' \
    preflight-runtime \
    identity-socket \
    identity-lock \
    identity-manager \
    identity-launch \
    identity-birth \
    identity-process \
    identity-stability \
    identity-publication \
    active-lock \
    protocol-bind-before \
    protocol-frame-bounds \
    protocol-wire-shapes \
    protocol-wrong-uid \
    protocol-wrong-gid \
    protocol-root-peer \
    protocol-bind-after \
    functional-underlay \
    functional-underlay-parent-contract \
    functional-underlay-pristine-namespace \
    functional-underlay-pristine-link \
    functional-underlay-pristine-ipv-four \
    functional-underlay-pristine-ipv-six \
    functional-underlay-absent \
    functional-underlay-link \
    functional-underlay-address \
    functional-underlay-route \
    functional-underlay-ifindex \
    functional-underlay-readback-link \
    functional-underlay-readback-address \
    functional-underlay-readback-route \
    functional-probe-ready \
    functional-probe-fixture \
    functional-probe-launch \
    functional-probe-wait \
    functional-probe-identity \
    functional-probe-socket \
    functional-probe-fdstore \
    functional-worker-observation \
    functional-relay-fixture \
    functional-relay-traffic \
    functional-relay-cleanup \
    functional-client-release \
    functional-client-cleanup \
    functional-exit-ready \
    functional-exit-worker-observation \
    functional-exit-relay-fixture \
    functional-exit-relay-traffic \
    functional-exit-relay-cleanup \
    functional-exit-release \
    functional-exit-cleanup \
    functional-exit-cleanup-retirement \
    functional-exit-cleanup-process-pin \
    functional-exit-cleanup-wireguard-absence \
    functional-exit-cleanup-namespace-pin \
    functional-exit-cleanup-process-close \
    functional-exit-cleanup-namespace-close \
    functional-exit-cleanup-fdstore-absence \
    functional-exit-cleanup-parent-custody \
    functional-exit-cleanup-parent-custody-pidfd \
    functional-exit-cleanup-parent-custody-procfd \
    functional-exit-cleanup-parent-custody-foreign-netns-exit-worker-one \
    functional-exit-cleanup-parent-custody-foreign-netns-exit-worker-two \
    functional-exit-cleanup-parent-custody-foreign-netns-exit-worker-three-plus \
    functional-exit-cleanup-parent-custody-foreign-netns-other \
    functional-exit-cleanup-parent-custody-fd-scan \
    functional-exit-cleanup-parent-custody-clear \
    functional-relay-pair-ready \
    functional-relay-pair-worker-observation \
    functional-relay-pair-fixtures \
    functional-relay-pair-traffic \
    functional-relay-pair-cleanup \
    functional-probe-finish \
    functional-cleanup \
    publication >"$expected_production_start_stages"
while IFS= read -r expected_production_start_stage; do
    production_start_failure_stage_is_safe "$expected_production_start_stage" || {
        printf 'production start stage is not allowlisted: %s\n' \
            "$expected_production_start_stage" >&2
        exit 1
    }
done <"$expected_production_start_stages"
if production_start_failure_stage_is_safe 'functional-private-value'; then
    printf '%s\n' 'an unbounded production start stage was accepted' >&2
    exit 1
fi

expected_functional_failure_phases=$temporary_directory/expected-functional-failure-phases
printf '%s\n' \
    plan \
    connect \
    bind \
    prepare \
    activate \
    shutdown \
    ready \
    release \
    reconnect \
    commit \
    destroy \
    second-cycle-plan \
    second-cycle-bind \
    second-cycle-prepare \
    second-cycle-activate \
    reuse \
    second-cycle-shutdown \
    second-cycle-ready \
    second-cycle-release \
    second-cycle-reconnect \
    second-cycle-commit \
    second-cycle-destroy \
    relay-pair-plan \
    relay-pair-bind \
    relay-pair-prepare \
    relay-pair-activate \
    relay-pair-reuse \
    relay-pair-shutdown \
    relay-pair-ready \
    relay-pair-release \
    relay-pair-reconnect \
    relay-pair-commit \
    relay-pair-destroy \
    final-shutdown >"$expected_functional_failure_phases"
expected_functional_failure_classes=$temporary_directory/expected-functional-failure-classes
printf '%s\n' \
    random \
    protocol \
    io \
    timeout \
    untrusted \
    correlation \
    unexpected-response >"$expected_functional_failure_classes"
while IFS= read -r functional_failure_phase; do
    while IFS= read -r functional_failure_class; do
        production_functional_probe_failure_value_is_safe \
            "$functional_failure_phase,$functional_failure_class" || {
            printf 'gate rejected functional failure value: %s,%s\n' \
                "$functional_failure_phase" "$functional_failure_class" >&2
            exit 1
        }
    done <"$expected_functional_failure_classes"
done <"$expected_functional_failure_phases"
for invalid_functional_failure_value in \
    '' private,io prepare,private prepare,io,extra prepare/io; do
    if production_functional_probe_failure_value_is_safe \
        "$invalid_functional_failure_value"; then
        printf 'gate accepted functional failure mutant: %s\n' \
            "$invalid_functional_failure_value" >&2
        exit 1
    fi
done

exercise_production_launch_diagnostic() (
    [ "$#" -eq 2 ] || exit 98
    production_diagnostic_name=$1
    production_diagnostic_stage=$2
    temporary_stage=$temporary_directory/production-launch-$production_diagnostic_name
    mkdir -m 0700 "$temporary_stage" "$temporary_stage/production-output"
    printf 'VOLPAROSSA_HELPER_V3_IPC_START_FAILURE_STAGE_V1=%s\n' \
        "$production_diagnostic_stage" \
        >"$temporary_stage/production-output/start.failure"
    chmod 0600 "$temporary_stage/production-output/start.failure"
    proof_failure_reason=production-launch-status
    report_production_launch_diagnostic
)
expect_status 0 exercise_production_launch_diagnostic exact functional-worker-observation
test ! -s "$last_stdout"
test "$(cat "$last_stderr")" = \
    'VOLPAROSSA_HELPER_LIVE_PRODUCTION_LAUNCH_DIAGNOSTIC_V1=functional-worker-observation'
production_launch_privacy_sentinel='private-production-launch-value'
expect_status 1 exercise_production_launch_diagnostic invalid \
    "$production_launch_privacy_sentinel"
test ! -s "$last_stdout" && test ! -s "$last_stderr"

exercise_production_functional_probe_diagnostic() (
    [ "$#" -eq 3 ] || exit 98
    production_diagnostic_name=$1
    production_diagnostic_stage=$2
    production_functional_payload=$3
    temporary_stage=$temporary_directory/production-functional-$production_diagnostic_name
    mkdir -m 0700 "$temporary_stage" "$temporary_stage/production-output"
    printf 'VOLPAROSSA_HELPER_V3_IPC_START_FAILURE_STAGE_V1=%s\n' \
        "$production_diagnostic_stage" \
        >"$temporary_stage/production-output/start.failure"
    printf 'VOLPAROSSA_HELPER_V3_FUNCTIONAL_CLIENT_LEASE_FAILURE_V1=%s\n' \
        "$production_functional_payload" \
        >"$temporary_stage/production-output/functional-client-lease.failure"
    chmod 0600 \
        "$temporary_stage/production-output/start.failure" \
        "$temporary_stage/production-output/functional-client-lease.failure"
    proof_failure_reason=production-launch-status
    report_production_launch_diagnostic
)
expect_status 0 exercise_production_functional_probe_diagnostic \
    exact functional-probe-wait prepare,unexpected-response
test ! -s "$last_stdout"
printf '%s\n%s\n' \
    'VOLPAROSSA_HELPER_LIVE_PRODUCTION_LAUNCH_DIAGNOSTIC_V1=functional-probe-wait' \
    'VOLPAROSSA_HELPER_LIVE_FUNCTIONAL_CLIENT_LEASE_DIAGNOSTIC_V1=prepare,unexpected-response' \
    >"$temporary_directory/expected-functional-production-diagnostic"
cmp -s "$temporary_directory/expected-functional-production-diagnostic" "$last_stderr"
expect_status 0 exercise_production_functional_probe_diagnostic \
    exit-ready functional-client-release second-cycle-ready,timeout
test ! -s "$last_stdout"
printf '%s\n%s\n' \
    'VOLPAROSSA_HELPER_LIVE_PRODUCTION_LAUNCH_DIAGNOSTIC_V1=functional-client-release' \
    'VOLPAROSSA_HELPER_LIVE_FUNCTIONAL_CLIENT_LEASE_DIAGNOSTIC_V1=second-cycle-ready,timeout' \
    >"$temporary_directory/expected-functional-exit-ready-diagnostic"
cmp -s "$temporary_directory/expected-functional-exit-ready-diagnostic" "$last_stderr"
expect_status 0 exercise_production_functional_probe_diagnostic \
    pair-ready functional-exit-release relay-pair-ready,timeout
test ! -s "$last_stdout"
printf '%s\n%s\n' \
    'VOLPAROSSA_HELPER_LIVE_PRODUCTION_LAUNCH_DIAGNOSTIC_V1=functional-exit-release' \
    'VOLPAROSSA_HELPER_LIVE_FUNCTIONAL_CLIENT_LEASE_DIAGNOSTIC_V1=relay-pair-ready,timeout' \
    >"$temporary_directory/expected-functional-pair-ready-diagnostic"
cmp -s "$temporary_directory/expected-functional-pair-ready-diagnostic" "$last_stderr"
expect_status 0 exercise_production_functional_probe_diagnostic \
    pair-commit functional-probe-finish relay-pair-commit,correlation
test ! -s "$last_stdout"
while read -r production_functional_mutant_name production_functional_mutant; do
    expect_status 1 exercise_production_functional_probe_diagnostic \
        "$production_functional_mutant_name" functional-probe-wait \
        "$production_functional_mutant"
    test ! -s "$last_stdout" && test ! -s "$last_stderr"
done <<'EOF'
private-phase private-phase,io
private-class prepare,private-class
extra-field prepare,io,extra
wrong-separator prepare/io
EOF
expect_status 1 exercise_production_functional_probe_diagnostic \
    wrong-stage functional-probe-identity prepare,io
test ! -s "$last_stdout" && test ! -s "$last_stderr"

reject_production_functional_probe_capture() (
    [ "$#" -eq 2 ] || exit 98
    production_functional_shape_name=$1
    production_functional_shape=$2
    temporary_stage=$temporary_directory/production-functional-shape-$production_functional_shape_name
    mkdir -m 0700 "$temporary_stage" "$temporary_stage/production-output"
    printf '%s\n' \
        'VOLPAROSSA_HELPER_V3_IPC_START_FAILURE_STAGE_V1=functional-probe-wait' \
        >"$temporary_stage/production-output/start.failure"
    chmod 0600 "$temporary_stage/production-output/start.failure"
    production_functional_file=$temporary_stage/production-output/functional-client-lease.failure
    case $production_functional_shape in
        duplicate)
            printf '%s\n%s\n' \
                'VOLPAROSSA_HELPER_V3_FUNCTIONAL_CLIENT_LEASE_FAILURE_V1=prepare,io' \
                'VOLPAROSSA_HELPER_V3_FUNCTIONAL_CLIENT_LEASE_FAILURE_V1=connect,io' \
                >"$production_functional_file"
            ;;
        truncated)
            printf '%s' \
                'VOLPAROSSA_HELPER_V3_FUNCTIONAL_CLIENT_LEASE_FAILURE_V1=prepare,io' \
                >"$production_functional_file"
            ;;
        oversized)
            awk 'BEGIN { for (i = 0; i < 129; i++) printf "x"; printf "\n" }' \
                >"$production_functional_file"
            ;;
        symlink)
            printf '%s\n' \
                'VOLPAROSSA_HELPER_V3_FUNCTIONAL_CLIENT_LEASE_FAILURE_V1=prepare,io' \
                >"$production_functional_file.target"
            chmod 0600 "$production_functional_file.target"
            ln -s "$production_functional_file.target" "$production_functional_file"
            ;;
        next)
            printf '%s\n' \
                'VOLPAROSSA_HELPER_V3_FUNCTIONAL_CLIENT_LEASE_FAILURE_V1=prepare,io' \
                >"$production_functional_file"
            : >"$production_functional_file.next"
            chmod 0600 "$production_functional_file.next"
            ;;
        *) exit 97 ;;
    esac
    if [ "$production_functional_shape" != symlink ]; then
        chmod 0600 "$production_functional_file"
    fi
    proof_failure_reason=production-launch-status
    if report_production_launch_diagnostic; then
        exit 96
    fi
)
for production_functional_shape in duplicate truncated oversized symlink next; do
    expect_status 0 reject_production_functional_probe_capture \
        "$production_functional_shape" "$production_functional_shape"
    test ! -s "$last_stdout" && test ! -s "$last_stderr"
done

exercise_production_launch_diagnostic_missing() (
    temporary_stage=$temporary_directory/production-launch-missing
    mkdir -m 0700 "$temporary_stage" "$temporary_stage/production-output"
    proof_failure_reason=production-launch-status
    report_production_launch_diagnostic
)
expect_status 1 exercise_production_launch_diagnostic_missing
test ! -s "$last_stdout" && test ! -s "$last_stderr"

exercise_production_launch_diagnostic_wrong_reason() (
    temporary_stage=$temporary_directory/production-launch-wrong-reason
    mkdir -m 0700 "$temporary_stage" "$temporary_stage/production-output"
    printf '%s\n' \
        'VOLPAROSSA_HELPER_V3_IPC_START_FAILURE_STAGE_V1=publication' \
        >"$temporary_stage/production-output/start.failure"
    chmod 0600 "$temporary_stage/production-output/start.failure"
    proof_failure_reason=production-running-state
    report_production_launch_diagnostic
)
expect_status 1 exercise_production_launch_diagnostic_wrong_reason
test ! -s "$last_stdout" && test ! -s "$last_stderr"

reject_production_launch_capture() (
    [ "$#" -eq 3 ] || exit 98
    production_rejection_name=$1
    production_rejection_shape=$2
    production_rejection_mode=$3
    temporary_stage=$temporary_directory/production-launch-reject-$production_rejection_name
    mkdir -m 0700 "$temporary_stage" "$temporary_stage/production-output"
    case $production_rejection_shape in
        duplicate)
            printf '%s\n%s\n' \
                'VOLPAROSSA_HELPER_V3_IPC_START_FAILURE_STAGE_V1=identity-process' \
                'VOLPAROSSA_HELPER_V3_IPC_START_FAILURE_STAGE_V1=publication' \
                >"$temporary_stage/production-output/start.failure"
            ;;
        truncated)
            printf '%s' \
                'VOLPAROSSA_HELPER_V3_IPC_START_FAILURE_STAGE_V1=identity-process' \
                >"$temporary_stage/production-output/start.failure"
            ;;
        with-pass)
            printf '%s\n' \
                'VOLPAROSSA_HELPER_V3_IPC_START_FAILURE_STAGE_V1=identity-process' \
                >"$temporary_stage/production-output/start.failure"
            : >"$temporary_stage/production-output/start.pass"
            chmod 0600 "$temporary_stage/production-output/start.pass"
            ;;
        exact)
            printf '%s\n' \
                'VOLPAROSSA_HELPER_V3_IPC_START_FAILURE_STAGE_V1=identity-process' \
                >"$temporary_stage/production-output/start.failure"
            ;;
        *) exit 97 ;;
    esac
    chmod "$production_rejection_mode" \
        "$temporary_stage/production-output/start.failure"
    proof_failure_reason=production-launch-status
    if report_production_launch_diagnostic; then
        exit 96
    fi
)
while read -r production_rejection_name production_rejection_shape \
    production_rejection_mode; do
    expect_status 0 reject_production_launch_capture \
        "$production_rejection_name" "$production_rejection_shape" \
        "$production_rejection_mode"
    test ! -s "$last_stdout" && test ! -s "$last_stderr"
done <<'EOF'
duplicate duplicate 0600
truncated truncated 0600
unsafe-mode exact 0644
mixed-pass with-pass 0600
EOF

# Run the exact production identity fragment with its artifact missing. Every
# downstream operand must stay defined and the fixed predicate must survive.
production_identity_fragment=$temporary_directory/production-identity-fragment.sh
awk '
    /^    identity_invocation=$/ { capture = 1 }
    /^    production_socket_identity_file=/ { capture = 0 }
    capture {
        line = $0
        sub(/^    /, "", line)
        print line
    }
' "$gate" >"$production_identity_fragment"
if [ "$(grep -c '^identity_launch=$' "$production_identity_fragment")" -ne 1 ] \
    || [ "$(grep -c '^production_identity=' "$production_identity_fragment")" -ne 1 ]; then
    printf '%s\n' 'the production identity fallback is not uniquely executable' >&2
    exit 1
fi
sh -n "$production_identity_fragment"
exercise_missing_production_identity() (
    set -u
    temporary_stage=$temporary_directory/missing-production-identity
    agent_gid=61000
    : "$agent_gid"
    proof_failure_reason=
    # Invoked by the exact extracted observation fragment.
    # shellcheck disable=SC2317
    vp_capture_file_is_safe() { return 1; }
    # shellcheck disable=SC2317
    record_proof_failure() {
        [ -z "$proof_failure_reason" ] && proof_failure_reason=$1
    }
    # shellcheck disable=SC1090
    . "$production_identity_fragment"
    [ "$proof_failure_reason" = production-process-identity ] \
        && [ -z "$identity_invocation" ] \
        && [ -z "$identity_main_pid" ] \
        && [ -z "$identity_launch" ] \
        && [ -z "$identity_launch_image" ] \
        && [ -z "$identity_starttime" ] \
        && [ -z "$identity_starttime_value" ] \
        && [ -z "$identity_process_contract" ] \
        && [ -z "$identity_extra" ] \
        && [ -z "$identity_seccomp_filters" ]
)
expect_status 0 exercise_missing_production_identity
test ! -s "$last_stdout" && test ! -s "$last_stderr"

# A failed redirection on POSIX special builtin `exec` used to terminate dash
# with status 2. The exact `command exec` form must remain an ordinary failure.
# These are literal gate-source contracts; expansion here would defeat them.
# shellcheck disable=SC2016
grep -Fx '    if command exec 9<>"$production_lock_path"; then' "$gate" >/dev/null
# shellcheck disable=SC2016
if grep -F 'if exec 9<>"$production_lock_path"; then' "$gate" >/dev/null; then
    printf '%s\n' 'the production lock probe restored fatal special-builtin semantics' >&2
    exit 1
fi
exercise_missing_production_lock() (
    set -eu
    production_lock_path=$temporary_directory/absent-directory/lock
    if command exec 9<>"$production_lock_path"; then
        exit 91
    else
        lock_open_status=$?
    fi
    [ "$lock_open_status" -eq 2 ]
)
expect_status 0 exercise_missing_production_lock
test ! -s "$last_stdout"
grep -F 'cannot create' "$last_stderr" >/dev/null

exercise_worker_launch_diagnostic() (
    [ "$#" -eq 3 ] || exit 98
    diagnostic_name=$1
    diagnostic_stage_payload=$2
    diagnostic_exec_status=$3
    temporary_stage=$temporary_directory/worker-launch-diagnostic-$diagnostic_name
    mkdir -m 0700 "$temporary_stage"
    printf '%s\n' 'fixed systemd client failure' >"$temporary_stage/systemd-run.stderr"
    printf '%s\n' "$diagnostic_stage_payload" >"$temporary_stage/proof.stderr"
    chmod 0600 "$temporary_stage/systemd-run.stderr" "$temporary_stage/proof.stderr"
    proof_failure_reason=worker-launch-status
    run_status=1
    worker_launch_captures_ok=yes
    worker_launch_json_ok=no
    worker_manager_binding_ok=no
    active_state=failed
    sub_state=failed
    result=exit-code
    exec_code=1
    exec_status=$diagnostic_exec_status
    report_worker_launch_diagnostic
)
expect_status 0 exercise_worker_launch_diagnostic valid \
    'VOLPAROSSA_HELPER_LIVE_PROOF_FAILURE_STAGE_V1=publication' 203
test ! -s "$last_stdout"
grep -Fx \
    'VOLPAROSSA_HELPER_LIVE_WORKER_LAUNCH_DIAGNOSTIC_V1=run-nonzero,captures-yes,json-no,manager-no,client-stderr-nonempty,terminal-failed-exit-status-203,stage-publication' \
    "$last_stderr" >/dev/null

worker_launch_privacy_sentinel='private-worker-launch-value'
expect_status 0 exercise_worker_launch_diagnostic other \
    "$worker_launch_privacy_sentinel" 999
test ! -s "$last_stdout"
grep -Fx \
    'VOLPAROSSA_HELPER_LIVE_WORKER_LAUNCH_DIAGNOSTIC_V1=run-nonzero,captures-yes,json-no,manager-no,client-stderr-nonempty,terminal-other,stage-other' \
    "$last_stderr" >/dev/null
if grep -F "$worker_launch_privacy_sentinel" "$last_stdout" "$last_stderr" >/dev/null; then
    printf '%s\n' 'worker launch diagnostic exposed a non-allowlisted payload' >&2
    exit 1
fi

if proof_failure_reason_is_safe 'worker-launch-status/private-record'; then
    printf '%s\n' 'an unbounded proof failure reason was accepted' >&2
    exit 1
fi

exercise_helper_failure_stage_mapping() (
    [ "$#" -eq 2 ] || exit 98
    stage_capture=$temporary_directory/helper-stage-$1.capture
    printf 'VOLPAROSSA_HELPER_LIVE_PROOF_FAILURE_STAGE_V1=%s\n' "$1" \
        >"$stage_capture"
    chmod 0600 "$stage_capture"
    proof_failure_reason=
    proof_ok=yes
    unset production_ok
    record_helper_live_proof_failure_stage "$stage_capture" || exit 97
    [ "$proof_failure_reason" = "$2" ] \
        && [ "$proof_ok" = no ] \
        && [ "${production_ok+x}" != x ]
)
while read -r helper_stage helper_stage_reason; do
    expect_status 0 exercise_helper_failure_stage_mapping \
        "$helper_stage" "$helper_stage_reason"
    if [ -s "$last_stdout" ] || [ -s "$last_stderr" ]; then
        printf 'helper failure stage mapping emitted diagnostics: %s\n' \
            "$helper_stage" >&2
        exit 1
    fi
done <<'EOF'
parent-contract worker-helper-parent-contract
runtime-preparation worker-helper-runtime-preparation
worker-spawn worker-helper-worker-spawn
publication worker-helper-publication
retirement-cleanup worker-helper-retirement-cleanup
EOF

reject_helper_failure_stage_capture() (
    [ "$#" -eq 1 ] || exit 98
    proof_failure_reason=
    proof_ok=yes
    unset production_ok
    if record_helper_live_proof_failure_stage "$1"; then
        exit 97
    fi
    [ -z "$proof_failure_reason" ] \
        && [ "$proof_ok" = yes ] \
        && [ "${production_ok+x}" != x ]
)
helper_stage_privacy_sentinel='private/helper/stage/value'
helper_stage_unknown=$temporary_directory/helper-stage-unknown.capture
printf '%s\n' \
    'VOLPAROSSA_HELPER_LIVE_PROOF_FAILURE_STAGE_V1=unknown' \
    >"$helper_stage_unknown"
helper_stage_extra=$temporary_directory/helper-stage-extra.capture
printf '%s\n' \
    'VOLPAROSSA_HELPER_LIVE_PROOF_FAILURE_STAGE_V1=publication' \
    "$helper_stage_privacy_sentinel" >"$helper_stage_extra"
helper_stage_truncated=$temporary_directory/helper-stage-truncated.capture
printf '%s' \
    'VOLPAROSSA_HELPER_LIVE_PROOF_FAILURE_STAGE_V1=worker-spawn' \
    >"$helper_stage_truncated"
helper_stage_multiple=$temporary_directory/helper-stage-multiple.capture
printf '%s\n' \
    'VOLPAROSSA_HELPER_LIVE_PROOF_FAILURE_STAGE_V1=parent-contract' \
    'VOLPAROSSA_HELPER_LIVE_PROOF_FAILURE_STAGE_V1=retirement-cleanup' \
    >"$helper_stage_multiple"
helper_stage_embedded=$temporary_directory/helper-stage-embedded.capture
printf 'VOLPAROSSA_HELPER_LIVE_PROOF_FAILURE_STAGE_V1=%s\n' \
    "$helper_stage_privacy_sentinel" >"$helper_stage_embedded"
helper_stage_unsafe=$temporary_directory/helper-stage-unsafe.capture
printf '%s\n' \
    'VOLPAROSSA_HELPER_LIVE_PROOF_FAILURE_STAGE_V1=publication' \
    >"$helper_stage_unsafe"
chmod 0600 \
    "$helper_stage_unknown" \
    "$helper_stage_extra" \
    "$helper_stage_truncated" \
    "$helper_stage_multiple" \
    "$helper_stage_embedded"
chmod 0644 "$helper_stage_unsafe"
for rejected_stage_capture in \
    "$helper_stage_unknown" \
    "$helper_stage_extra" \
    "$helper_stage_truncated" \
    "$helper_stage_multiple" \
    "$helper_stage_embedded" \
    "$helper_stage_unsafe"
do
    expect_status 0 reject_helper_failure_stage_capture "$rejected_stage_capture"
    if [ -s "$last_stdout" ] || [ -s "$last_stderr" ] \
        || grep -F "$helper_stage_privacy_sentinel" \
            "$last_stdout" "$last_stderr" >/dev/null; then
        printf '%s\n' 'a rejected helper stage escaped privacy-safe diagnostics' >&2
        exit 1
    fi
done
expect_status 1 record_helper_live_proof_failure_stage
if [ -s "$last_stdout" ] || [ -s "$last_stderr" ]; then
    printf '%s\n' 'invalid helper stage mapper arity emitted diagnostics' >&2
    exit 1
fi
expect_status 1 record_helper_live_proof_failure_stage \
    "$helper_stage_unknown" "$helper_stage_extra"
if [ -s "$last_stdout" ] || [ -s "$last_stderr" ]; then
    printf '%s\n' 'invalid helper stage mapper arity emitted diagnostics' >&2
    exit 1
fi

# ShellCheck cannot resolve the extracted classifier's reads of these fixture globals.
# shellcheck disable=SC2034
exercise_worker_terminal_decision() (
    [ "$#" -eq 10 ] || exit 98
    decision_name=$1
    worker_manager_binding_ok=$2
    decision_current=$3
    decision_capture=$4
    decision_tuple=$5
    run_status=$6
    worker_launch_captures_ok=$7
    worker_launch_json_ok=$8
    worker_launch_stderr_empty=$9
    expected_decision=${10}
    decision_stage=$temporary_directory/terminal-decision-$decision_name.capture
    case $decision_capture in
        exact)
            printf '%s\n' \
                'VOLPAROSSA_HELPER_LIVE_PROOF_FAILURE_STAGE_V1=publication' \
                >"$decision_stage"
            chmod 0600 "$decision_stage"
            ;;
        empty)
            : >"$decision_stage"
            chmod 0600 "$decision_stage"
            ;;
        unknown)
            printf '%s\n' \
                'VOLPAROSSA_HELPER_LIVE_PROOF_FAILURE_STAGE_V1=unknown' \
                >"$decision_stage"
            chmod 0600 "$decision_stage"
            ;;
        truncated)
            printf '%s' \
                'VOLPAROSSA_HELPER_LIVE_PROOF_FAILURE_STAGE_V1=publication' \
                >"$decision_stage"
            chmod 0600 "$decision_stage"
            ;;
        unsafe)
            printf '%s\n' \
                'VOLPAROSSA_HELPER_LIVE_PROOF_FAILURE_STAGE_V1=publication' \
                >"$decision_stage"
            chmod 0644 "$decision_stage"
            ;;
        extra)
            printf '%s\n' \
                'VOLPAROSSA_HELPER_LIVE_PROOF_FAILURE_STAGE_V1=publication' \
                'private-stage-payload' >"$decision_stage"
            chmod 0600 "$decision_stage"
            ;;
        multiple)
            printf '%s\n' \
                'VOLPAROSSA_HELPER_LIVE_PROOF_FAILURE_STAGE_V1=publication' \
                'VOLPAROSSA_HELPER_LIVE_PROOF_FAILURE_STAGE_V1=worker-spawn' \
                >"$decision_stage"
            chmod 0600 "$decision_stage"
            ;;
        *) exit 97 ;;
    esac
    case $decision_tuple in
        failure)
            active_state=failed
            sub_state=failed
            result=exit-code
            exec_code=1
            exec_status=1
            ;;
        mismatched)
            active_state=failed
            sub_state=failed
            result=exit-code
            exec_code=1
            exec_status=2
            ;;
        success)
            active_state=active
            sub_state=exited
            result=success
            exec_code=1
            exec_status=0
            ;;
        timeout)
            active_state=failed
            sub_state=failed
            result=timeout
            exec_code=2
            exec_status=15
            ;;
        signal)
            active_state=failed
            sub_state=failed
            result=signal
            exec_code=2
            exec_status=15
            ;;
        core)
            active_state=failed
            sub_state=failed
            result=core-dump
            exec_code=3
            exec_status=6
            ;;
        *) exit 96 ;;
    esac
    # Invoked indirectly by the extracted terminal classifier.
    # shellcheck disable=SC2317
    unit_invocation_is_current() {
        [ "$decision_current" = yes ]
    }
    # Invoked indirectly by the extracted terminal classifier. Manager-marker
    # drift is exercised separately by the failed-launch recovery matrix.
    # shellcheck disable=SC2317
    unit_description_matches_marker() {
        return 0
    }
    proof_failure_reason=
    proof_ok=yes
    unset production_ok
    classify_worker_live_proof_terminal "$decision_stage" || exit 95
    if [ "$expected_decision" = none ]; then
        [ -z "$proof_failure_reason" ] && [ "$proof_ok" = yes ] \
            && [ "${production_ok+x}" != x ]
    else
        [ "$proof_failure_reason" = "$expected_decision" ] \
            && [ "$proof_ok" = no ] \
            && [ "${production_ok+x}" != x ]
    fi
)
while read -r decision_name decision_binding decision_current decision_capture \
    decision_tuple decision_run decision_captures decision_json decision_stderr \
    decision_expected
do
    expect_status 0 exercise_worker_terminal_decision \
        "$decision_name" "$decision_binding" "$decision_current" \
        "$decision_capture" "$decision_tuple" "$decision_run" \
        "$decision_captures" "$decision_json" "$decision_stderr" \
        "$decision_expected"
    if [ -s "$last_stdout" ] || [ -s "$last_stderr" ]; then
        printf 'worker terminal decision emitted diagnostics: %s\n' \
            "$decision_name" >&2
        exit 1
    fi
done <<'EOF'
stage-wins yes yes exact failure 1 yes yes yes worker-helper-publication
stage-wins-after-exec yes yes exact failure 0 yes yes yes worker-helper-publication
current-mismatch yes no exact failure 1 yes yes yes worker-launch-status
binding-missing no yes exact failure 0 yes yes yes worker-manager-binding
unknown-stage yes yes unknown failure 1 yes yes yes worker-launch-status
truncated-stage yes yes truncated failure 1 yes yes yes worker-launch-status
unsafe-stage yes yes unsafe failure 1 yes yes yes worker-launch-status
unknown-stage-after-exec yes yes unknown failure 0 yes yes yes worker-terminal-state
truncated-stage-after-exec yes yes truncated failure 0 yes yes yes worker-terminal-state
unsafe-stage-after-exec yes yes unsafe failure 0 yes yes yes worker-terminal-state
extra-stage-after-exec yes yes extra failure 0 yes yes yes worker-terminal-state
multiple-stage-after-exec yes yes multiple failure 0 yes yes yes worker-terminal-state
timeout-is-generic yes yes exact timeout 0 yes yes yes worker-terminal-state
signal-is-generic yes yes exact signal 0 yes yes yes worker-terminal-state
core-is-generic yes yes exact core 0 yes yes yes worker-terminal-state
terminal-mismatch yes yes exact mismatched 0 yes yes yes worker-terminal-state
stage-before-envelope yes yes exact failure 0 yes yes no worker-helper-publication
capture-envelope no yes empty failure 0 no no no worker-launch-envelope
json-envelope no yes empty failure 0 yes no yes worker-launch-envelope
clean-success yes yes empty success 0 yes yes yes none
nonzero-success yes yes empty success 1 yes yes yes worker-launch-status
EOF

# Exercise the failed-Type=exec binding recovery through the production helper
# bodies while replacing only read-only systemctl observations. No host unit is
# created or mutated by this contract test.
worker_binding_recovery_functions=$temporary_directory/worker-binding-recovery-functions.sh
for recovery_function in \
    unit_name_is_safe \
    unit_invocation_id_is_safe \
    unit_ownership_marker_is_safe \
    unit_description_matches_marker \
    unit_current_invocation_id \
    unit_invocation_is_current \
    forget_unit_ownership \
    unit_load_state \
    unit_active_state \
    adopt_tentative_unit \
    adopt_launched_tentative_unit \
    recover_failed_worker_manager_binding \
    recover_successful_restart_manager_binding
do
    sed -n "/^$recovery_function() {$/,/^}$/p" "$gate" \
        >>"$worker_binding_recovery_functions"
done
for recovery_function in \
    unit_name_is_safe \
    unit_invocation_id_is_safe \
    unit_ownership_marker_is_safe \
    unit_description_matches_marker \
    unit_current_invocation_id \
    unit_invocation_is_current \
    forget_unit_ownership \
    unit_load_state \
    unit_active_state \
    adopt_tentative_unit \
    adopt_launched_tentative_unit \
    recover_failed_worker_manager_binding \
    recover_successful_restart_manager_binding
do
    if [ "$(grep -c "^$recovery_function() {$" \
        "$worker_binding_recovery_functions")" -ne 1 ]; then
        printf 'worker binding recovery helper is not uniquely extractable: %s\n' \
            "$recovery_function" >&2
        exit 1
    fi
done
sh -n "$worker_binding_recovery_functions"
# shellcheck source=/dev/null
. "$worker_binding_recovery_functions"

# A launched no-block unit is still cleanup-owned while PID 1 temporarily
# reports not-found. The retain form must therefore leave the complete affine
# tuple byte-for-byte intact; the ordinary retirement form may forget it.
exercise_tentative_not_found_disposition() (
    [ "$#" -eq 1 ] || exit 98
    not_found_disposition=$1
    unit_name=volparossa-helper-live-proof-ABC123.service
    unit_owned=no
    unit_may_own=yes
    unit_invocation_id=
    unit_ownership_marker=volparossa-helper-live-proof-owner-v1-0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef
    expected_name=$unit_name
    expected_marker=$unit_ownership_marker
    interrupted=no
    read -r exercise_pid _ </proc/self/stat
    # Invoked through the extracted production adopter.
    # shellcheck disable=SC2317
    unit_load_state() {
        if [ "$not_found_disposition" = interrupted-retain ]; then
            kill -TERM "$exercise_pid"
        fi
        printf '%s\n' not-found
    }
    if [ "$not_found_disposition" = interrupted-retain ]; then
        trap '[ "$unit_name" = "$expected_name" ] \
            && [ "$unit_owned" = no ] && [ "$unit_may_own" = yes ] \
            && [ -z "$unit_invocation_id" ] \
            && [ "$unit_ownership_marker" = "$expected_marker" ] \
            || exit 89; interrupted=yes' TERM
    fi
    case $not_found_disposition in
        retain|interrupted-retain)
            adopt_tentative_unit retain || exit 97
            [ "$unit_name" = "$expected_name" ] \
                && [ "$unit_owned" = no ] && [ "$unit_may_own" = yes ] \
                && [ -z "$unit_invocation_id" ] \
                && [ "$unit_ownership_marker" = "$expected_marker" ] \
                || exit 96
            ;;
        forget)
            adopt_tentative_unit || exit 97
            [ -z "$unit_name" ] && [ "$unit_owned" = no ] \
                && [ "$unit_may_own" = no ] \
                && [ -z "$unit_invocation_id" ] \
                && [ -z "$unit_ownership_marker" ] || exit 96
            ;;
        invalid)
            if adopt_tentative_unit invalid; then
                exit 95
            fi
            [ "$unit_name" = "$expected_name" ] \
                && [ "$unit_owned" = no ] && [ "$unit_may_own" = yes ] \
                && [ -z "$unit_invocation_id" ] \
                && [ "$unit_ownership_marker" = "$expected_marker" ] \
                || exit 94
            ;;
        *) exit 93 ;;
    esac
    if [ "$not_found_disposition" = interrupted-retain ]; then
        [ "$interrupted" = yes ] || exit 92
    else
        [ "$interrupted" = no ] || exit 92
    fi
)
for not_found_disposition in retain interrupted-retain forget invalid; do
    expect_status 0 exercise_tentative_not_found_disposition \
        "$not_found_disposition"
    if [ -s "$last_stdout" ] || [ -s "$last_stderr" ]; then
        printf 'tentative not-found disposition emitted diagnostics: %s\n' \
            "$not_found_disposition" >&2
        exit 1
    fi
done

# ShellCheck cannot resolve the extracted recovery and classifier reads of
# these fixture globals or the indirect calls to the systemctl fixture.
# shellcheck disable=SC2034
exercise_failed_worker_binding_recovery() (
    [ "$#" -eq 6 ] || exit 98
    recovery_name=$1
    recovery_stdout=$2
    recovery_manager=$3
    recovery_tuple=$4
    expected_recovery_decision=$5
    expected_manager_binding=$6
    temporary_stage=$temporary_directory/worker-binding-$recovery_name
    mkdir -m 0700 "$temporary_stage"
    case $recovery_stdout in
        empty)
            : >"$temporary_stage/systemd-run.stdout"
            ;;
        nonempty)
            printf '\n' >"$temporary_stage/systemd-run.stdout"
            ;;
        malformed)
            printf '%s\n' '{"unit":' >"$temporary_stage/systemd-run.stdout"
            ;;
        *) exit 97 ;;
    esac
    chmod 0600 "$temporary_stage/systemd-run.stdout"
    decision_stage=$temporary_stage/proof.stderr
    printf '%s\n' \
        'VOLPAROSSA_HELPER_LIVE_PROOF_FAILURE_STAGE_V1=publication' \
        >"$decision_stage"
    chmod 0600 "$decision_stage"

    unit_name=volparossa-helper-live-proof-A1b2C3.service
    unit_ownership_marker=volparossa-helper-live-proof-owner-v1-0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef
    exact_invocation_id=0123456789abcdef0123456789abcdef
    systemctl_call_log=$temporary_stage/systemctl.calls
    # Invoked indirectly by the extracted tentative-adoption helpers.
    # shellcheck disable=SC2317
    systemctl() {
        printf '%s\n' "$2" >>"$systemctl_call_log"
        [ "$1" = show ] || return 1
        case $2 in
            --property=LoadState)
                case $recovery_manager in
                    adoption-failure) return 1 ;;
                    not-found) printf '%s\n' not-found ;;
                    *) printf '%s\n' loaded ;;
                esac
                ;;
            --property=Description)
                observed_id_reads=$(grep -Fc -- '--property=InvocationID' \
                    "$systemctl_call_log" 2>/dev/null || true)
                if [ "$recovery_manager" = bad-marker ] \
                    || { [ "$recovery_manager" = marker-drift-after-id ] \
                        && [ "$observed_id_reads" -ge 2 ]; }; then
                    printf '%s\n' \
                        volparossa-helper-live-proof-owner-v1-ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff
                else
                    printf '%s\n' "$unit_ownership_marker"
                fi
                ;;
            --property=InvocationID)
                if [ "$recovery_manager" = bad-id ]; then
                    printf '%s\n' 00000000000000000000000000000000
                else
                    printf '%s\n' "$exact_invocation_id"
                fi
                ;;
            --property=ActiveState)
                if [ "$recovery_manager" = bad-id ]; then
                    printf '%s\n' unknown
                else
                    printf '%s\n' failed
                fi
                ;;
            *) return 1 ;;
        esac
    }

    run_status=1
    worker_launch_captures_ok=yes
    worker_launch_json_ok=no
    worker_manager_binding_ok=no
    worker_launch_stderr_empty=no
    unit_owned=no
    unit_may_own=yes
    unit_invocation_id=
    case $recovery_tuple in
        failure)
            active_state=failed
            sub_state=failed
            result=exit-code
            exec_code=1
            exec_status=1
            ;;
        success)
            active_state=active
            sub_state=exited
            result=success
            exec_code=1
            exec_status=0
            ;;
        *) exit 96 ;;
    esac

    proof_failure_reason=
    proof_ok=yes
    unset production_ok
    recover_failed_worker_manager_binding || true
    if [ "$worker_manager_binding_ok" != yes ]; then
        record_worker_launch_failure
    fi
    classify_worker_live_proof_terminal "$decision_stage" || exit 95
    [ "$worker_manager_binding_ok" = "$expected_manager_binding" ] \
        && [ "$proof_failure_reason" = "$expected_recovery_decision" ] \
        && [ "$proof_ok" = no ] \
        && [ "${production_ok+x}" != x ] || exit 94
    if [ "$recovery_stdout" != empty ]; then
        [ ! -s "$systemctl_call_log" ] || exit 93
    fi
)
while read -r recovery_name recovery_stdout recovery_manager recovery_tuple \
    recovery_expected recovery_binding
do
    expect_status 0 exercise_failed_worker_binding_recovery \
        "$recovery_name" "$recovery_stdout" "$recovery_manager" \
        "$recovery_tuple" "$recovery_expected" "$recovery_binding"
    if [ -s "$last_stdout" ] || [ -s "$last_stderr" ]; then
        printf 'worker binding recovery emitted diagnostics: %s\n' \
            "$recovery_name" >&2
        exit 1
    fi
done <<'EOF'
adopted-stage empty exact failure worker-helper-publication yes
nonempty-stdout nonempty exact failure worker-launch-status no
malformed-stdout malformed exact failure worker-launch-status no
bad-marker empty bad-marker failure worker-launch-status no
bad-id empty bad-id failure worker-launch-status no
marker-drift-after-id empty marker-drift-after-id failure worker-launch-status no
adoption-failure empty adoption-failure failure worker-launch-status no
not-found-success-return empty not-found failure worker-launch-status no
nonzero-success empty exact success worker-launch-status yes
EOF

# A successful no-block systemd request may produce an exactly empty CLI
# envelope. In that one case, bind through PID1's exact marker and invocation;
# every nonempty/malformed envelope must fail before tentative adoption.
# ShellCheck cannot resolve the fixture globals consumed by the extracted
# manager-binding helper.
# shellcheck disable=SC2034
exercise_successful_restart_binding_recovery() (
    [ "$#" -eq 4 ] || exit 98
    restart_recovery_scenario=$1
    expected_restart_recovery_status=$2
    expected_restart_adoptions=$3
    expected_restart_disposition=$4
    temporary_stage=$temporary_directory/restart-binding-$restart_recovery_scenario
    mkdir -m 0700 "$temporary_stage"
    : >"$temporary_stage/systemd-run-restart.stdout"
    : >"$temporary_stage/systemd-run-restart.stderr"
    chmod 0600 "$temporary_stage/systemd-run-restart.stdout" \
        "$temporary_stage/systemd-run-restart.stderr"

    restart_run_status=0
    restart_launch_captures_ok=yes
    restart_launch_json_ok=no
    restart_launch_stderr=empty
    restart_launch_fresh=no
    restart_launch_stdout=empty
    restart_initial_invocation_id=
    unit_name=volparossa-helper-live-proof-ABC123.service
    unit_owned=no
    unit_may_own=yes
    unit_invocation_id=
    unit_ownership_marker=volparossa-helper-live-proof-owner-v1-0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef
    production_invocation_id=ffffffffffffffffffffffffffffffff
    restart_exact_invocation_id=0123456789abcdef0123456789abcdef
    restart_adoptions=0
    restart_capture_safe=yes
    restart_adoption_shape=exact
    restart_current=yes
    restart_marker=yes
    restart_interrupt=none
    restart_interrupt_observed=no
    read -r restart_exercise_pid _ </proc/self/stat

    case $restart_recovery_scenario in
        exact-empty) ;;
        delayed-exact) restart_adoption_shape=not-found-once ;;
        never-found) restart_adoption_shape=not-found ;;
        wrong-marker) restart_marker=no ;;
        wrong-marker-interrupt)
            restart_marker=no
            restart_interrupt=marker
            ;;
        unsafe-id) restart_adoption_shape=unsafe-id ;;
        same-production)
            production_invocation_id=$restart_exact_invocation_id
            ;;
        current-mismatch) restart_current=no ;;
        current-mismatch-interrupt)
            restart_current=no
            restart_interrupt=current
            ;;
        nonzero-status) restart_run_status=1 ;;
        unsafe-capture) restart_capture_safe=no ;;
        nonempty-stderr)
            printf '\n' >"$temporary_stage/systemd-run-restart.stderr"
            restart_launch_stderr=nonempty
            ;;
        json-claimed) restart_launch_json_ok=yes ;;
        fresh-claimed) restart_launch_fresh=yes ;;
        dirty-owned)
            unit_owned=yes
            unit_invocation_id=$restart_exact_invocation_id
            ;;
        dirty-may-own) unit_may_own=no ;;
        whitespace-stdout)
            printf ' \n' >"$temporary_stage/systemd-run-restart.stdout"
            restart_launch_stdout=nonempty
            ;;
        unit-only-stdout)
            printf '%s\n' \
                '{"unit":"volparossa-helper-live-proof-ABC123.service"}' \
                >"$temporary_stage/systemd-run-restart.stdout"
            restart_launch_stdout=unit-only
            ;;
        forged-unit-only-stdout)
            printf '%s\n' \
                '{"unit":"other.service"}' \
                >"$temporary_stage/systemd-run-restart.stdout"
            restart_launch_stdout=unit-only
            ;;
        malformed-stdout)
            printf '%s\n' '{"unit":' \
                >"$temporary_stage/systemd-run-restart.stdout"
            restart_launch_stdout=nonempty
            ;;
        wrong-unit-stdout)
            printf '%s\n' \
                '{"invocation_id":"0123456789abcdef0123456789abcdef","unit":"other.service"}' \
                >"$temporary_stage/systemd-run-restart.stdout"
            restart_launch_stdout=nonempty
            ;;
        valid-json-stdout)
            printf '%s\n' \
                '{"invocation_id":"0123456789abcdef0123456789abcdef","unit":"volparossa-helper-live-proof-ABC123.service"}' \
                >"$temporary_stage/systemd-run-restart.stdout"
            restart_launch_stdout=nonempty
            ;;
        *) exit 97 ;;
    esac

    # Invoked indirectly by the extracted manager-binding recovery helper.
    # shellcheck disable=SC2317
    vp_capture_file_is_safe() {
        [ "$restart_capture_safe" = yes ] \
            && [ -f "$1" ] && [ ! -L "$1" ]
    }
    # shellcheck disable=SC2317
    adopt_tentative_unit() {
        [ "$#" -eq 1 ] && [ "$1" = retain ] || return 1
        restart_adoptions=$((restart_adoptions + 1))
        case $restart_adoption_shape in
            exact)
                unit_owned=yes
                unit_may_own=no
                unit_invocation_id=$restart_exact_invocation_id
                ;;
            not-found-once)
                if [ "$restart_adoptions" -ne 1 ]; then
                    unit_owned=yes
                    unit_may_own=no
                    unit_invocation_id=$restart_exact_invocation_id
                fi
                ;;
            not-found) ;;
            unsafe-id)
                unit_owned=yes
                unit_may_own=no
                unit_invocation_id=unsafe
                ;;
            *) return 1 ;;
        esac
    }
    # shellcheck disable=SC2317
    unit_invocation_is_current() {
        if [ "$restart_interrupt" = current ] \
            && [ "$restart_interrupt_observed" = no ]; then
            kill -TERM "$restart_exercise_pid"
        fi
        [ "$restart_current" = yes ] \
            && [ "$unit_invocation_id" = "$restart_exact_invocation_id" ]
    }
    # shellcheck disable=SC2317
    unit_description_matches_marker() {
        if [ "$restart_interrupt" = marker ] \
            && [ "$restart_interrupt_observed" = no ]; then
            kill -TERM "$restart_exercise_pid"
        fi
        [ "$restart_marker" = yes ]
    }
    # Invoked by the bounded launched-unit appearance loop.
    # shellcheck disable=SC2317
    sleep() {
        [ "$#" -eq 1 ] && [ "$1" = 0.05 ]
    }
    if [ "$restart_interrupt" != none ]; then
        trap '[ "$unit_owned" = yes ] && [ "$unit_may_own" = no ] \
            && [ "$unit_invocation_id" = "$restart_exact_invocation_id" ] \
            || exit 89; restart_interrupt_observed=yes' TERM
    fi

    if recover_successful_restart_manager_binding; then
        observed_restart_recovery_status=0
    else
        observed_restart_recovery_status=$?
    fi
    [ "$observed_restart_recovery_status" -eq \
        "$expected_restart_recovery_status" ] || exit 96
    [ "$restart_adoptions" -eq "$expected_restart_adoptions" ] || exit 95
    if [ "$restart_recovery_scenario" = fresh-claimed ]; then
        [ "$restart_launch_fresh" = yes ] || exit 94
    else
        [ "$restart_launch_fresh" = no ] || exit 94
    fi
    if [ "$expected_restart_recovery_status" -eq 0 ]; then
        [ "$restart_initial_invocation_id" = \
            "$restart_exact_invocation_id" ] \
            && [ "$unit_owned" = yes ] && [ "$unit_may_own" = no ] \
            || exit 93
    elif [ "$expected_restart_adoptions" -eq 0 ]; then
        [ -z "$restart_initial_invocation_id" ] || exit 92
    fi
    if [ "$restart_interrupt" = none ]; then
        [ "$restart_interrupt_observed" = no ] || exit 89
    else
        [ "$restart_interrupt_observed" = yes ] || exit 89
    fi
    case $expected_restart_disposition in
        owned)
            [ "$unit_owned" = yes ] && [ "$unit_may_own" = no ] \
                && [ "$unit_invocation_id" = "$restart_exact_invocation_id" ] \
                || exit 91
            ;;
        tentative)
            [ "$unit_owned" = no ] && [ "$unit_may_own" = yes ] \
                && [ -z "$unit_invocation_id" ] \
                && [ "$unit_name" = \
                    volparossa-helper-live-proof-ABC123.service ] \
                || exit 91
            ;;
        forgotten)
            [ "$unit_owned" = no ] && [ "$unit_may_own" = no ] \
                && [ -z "$unit_invocation_id" ] && [ -z "$unit_name" ] \
                || exit 91
            ;;
        unowned)
            [ "$unit_owned" = no ] && [ "$unit_may_own" = no ] \
                && [ -z "$unit_invocation_id" ] \
                && [ "$unit_name" = \
                    volparossa-helper-live-proof-ABC123.service ] \
                || exit 91
            ;;
        dirty)
            [ "$unit_owned" = yes ] && [ "$unit_may_own" = yes ] \
                && [ "$unit_invocation_id" = "$restart_exact_invocation_id" ] \
                && [ "$unit_name" = \
                    volparossa-helper-live-proof-ABC123.service ] \
                || exit 91
            ;;
        *) exit 90 ;;
    esac
)
while read -r restart_recovery_name restart_recovery_status restart_recovery_adoptions \
    restart_recovery_disposition
do
    expect_status 0 exercise_successful_restart_binding_recovery \
        "$restart_recovery_name" "$restart_recovery_status" \
        "$restart_recovery_adoptions" "$restart_recovery_disposition"
    if [ -s "$last_stdout" ] || [ -s "$last_stderr" ]; then
        printf 'successful restart binding recovery emitted diagnostics: %s\n' \
            "$restart_recovery_name" >&2
        exit 1
    fi
done <<'EOF'
exact-empty 0 1 owned
unit-only-stdout 0 1 owned
forged-unit-only-stdout 1 0 tentative
delayed-exact 0 2 owned
never-found 1 1000 tentative
wrong-marker 1 1 tentative
wrong-marker-interrupt 1 1 tentative
unsafe-id 1 1 tentative
same-production 1 1 tentative
current-mismatch 1 1 tentative
current-mismatch-interrupt 1 1 tentative
nonzero-status 1 0 tentative
unsafe-capture 1 0 tentative
nonempty-stderr 1 0 tentative
json-claimed 1 0 tentative
fresh-claimed 1 0 tentative
dirty-owned 1 0 dirty
dirty-may-own 1 0 unowned
whitespace-stdout 1 0 tentative
malformed-stdout 1 0 tentative
wrong-unit-stdout 1 0 tentative
valid-json-stdout 1 0 tentative
EOF

# Exercise retirement through exact manager snapshots. The fixture accepts
# only one five-property `systemctl show` call per observation, so collection
# can be represented as a complete not-found state instead of occurring
# between independent property reads. No host unit is created or mutated.
retirement_state_machine_functions=$temporary_directory/retirement-state-machine-functions.sh
for retirement_function in retire_failure_stage_is_safe \
    observe_unit_retirement_snapshot retire_unit; do
    sed -n "/^$retirement_function() {$/,/^}$/p" "$gate" \
        >>"$retirement_state_machine_functions"
done
for retirement_function in retire_failure_stage_is_safe \
    observe_unit_retirement_snapshot retire_unit; do
    if [ "$(grep -c "^$retirement_function() {$" \
        "$retirement_state_machine_functions")" -ne 1 ]; then
        printf 'retirement state-machine helper is not uniquely extractable: %s\n' \
            "$retirement_function" >&2
        exit 1
    fi
done
sh -n "$retirement_state_machine_functions"
# shellcheck source=/dev/null
. "$retirement_state_machine_functions"

for retirement_failure_stage in adoption identity initial-snapshot stop-request \
    stop-wait reset-failed reset-wait fdstore-clean post-clean final-reset \
    collection; do
    retire_failure_stage_is_safe "$retirement_failure_stage"
done
for retirement_failure_stage in '' private-runtime-detail snapshot stop reset; do
    if retire_failure_stage_is_safe "$retirement_failure_stage"; then
        printf 'retirement substage allowlist accepted: %s\n' \
            "$retirement_failure_stage" >&2
        exit 1
    fi
done

if ! awk '
    /^retire_unit\(\) \{$/ { in_retire = 1; start = NR }
    in_retire && /^    retire_failure_stage=adoption$/ { adoption = NR; adoption_count++ }
    in_retire && /^    retire_failure_stage=identity$/ { identity = NR; identity_count++ }
    in_retire && /^    retire_failure_stage=initial-snapshot$/ {
        initial_snapshot = NR; initial_snapshot_count++
    }
    in_retire && /^    retire_failure_stage=stop-request$/ {
        stop_request = NR; stop_request_count++
    }
    in_retire && /^    retire_failure_stage=stop-wait$/ {
        stop_wait = NR; stop_wait_count++
    }
    in_retire && /^        retire_failure_stage=reset-failed$/ {
        reset_failed = NR; reset_failed_count++
    }
    in_retire && /^        retire_failure_stage=reset-wait$/ {
        reset_wait = NR; reset_wait_count++
    }
    in_retire && /^    retire_failure_stage=fdstore-clean$/ {
        fdstore_clean = NR; fdstore_clean_count++
    }
    in_retire && /^    retire_failure_stage=post-clean$/ {
        post_clean = NR; post_clean_count++
    }
    in_retire && /^    retire_failure_stage=final-reset$/ {
        final_reset = NR; final_reset_count++
    }
    in_retire && /^    retire_failure_stage=collection$/ {
        collection = NR; collection_count++
    }
    in_retire && /^}$/ { end = NR; in_retire = 0 }
    END {
        valid = start > 0 && adoption_count == 1 && identity_count == 1
        valid = valid && initial_snapshot_count == 1 && stop_request_count == 1
        valid = valid && stop_wait_count == 1 && reset_failed_count == 1
        valid = valid && reset_wait_count == 1 && fdstore_clean_count == 1
        valid = valid && post_clean_count == 1 && final_reset_count == 1
        valid = valid && collection_count == 1 && end > 0
        valid = valid && start < adoption && adoption < identity
        valid = valid && identity < initial_snapshot
        valid = valid && initial_snapshot < stop_request && stop_request < stop_wait
        valid = valid && stop_wait < reset_failed && reset_failed < reset_wait
        valid = valid && reset_wait < fdstore_clean && fdstore_clean < post_clean
        valid = valid && post_clean < final_reset && final_reset < collection
        valid = valid && collection < end
        if (!valid) exit 1
    }
' "$gate"; then
    printf '%s\n' 'retirement substages do not cover the exact state machine' >&2
    exit 1
fi

# ShellCheck cannot resolve the fixture globals consumed by the extracted
# retirement function or the dynamically dispatched systemctl/sleep mocks.
# shellcheck disable=SC2034
exercise_retirement_sequence() (
    [ "$#" -eq 6 ] || exit 98
    retirement_scenario=$1
    expected_retirement_status=$2
    expected_retirement_disposition=$3
    expected_retirement_actions=$4
    expected_retirement_shows=$5
    expected_retirement_failure_stage=$6
    retirement_stage=$temporary_directory/retirement-$retirement_scenario
    mkdir -m 0700 "$retirement_stage"
    retirement_sequence=$retirement_stage/snapshots
    retirement_actions=$retirement_stage/actions
    retirement_show_count=$retirement_stage/show-count
    : >"$retirement_actions"
    printf '%s\n' 0 >"$retirement_show_count"
    retirement_default_snapshot=

    case $retirement_scenario in
        collected-after-stop)
            printf '%s\n' \
                'loaded current active absent 0' \
                'not-found absent inactive absent 0' \
                >"$retirement_sequence"
            ;;
        tentative-successor-collected-after-stop)
            printf '%s\n' \
                'loaded current active absent 0' \
                'not-found absent inactive absent 0' \
                >"$retirement_sequence"
            ;;
        tentative-never-found)
            : >"$retirement_sequence"
            ;;
        settled-then-collected)
            printf '%s\n' \
                'loaded current active absent 0' \
                'loaded current deactivating present 0' \
                'loaded current inactive absent 0' \
                'loaded current inactive absent 0' \
                'not-found absent inactive absent 0' \
                >"$retirement_sequence"
            ;;
        failed-then-collected)
            printf '%s\n' \
                'loaded current active absent 0' \
                'loaded current failed absent 0' \
                'loaded current inactive absent 0' \
                'loaded current inactive absent 0' \
                'not-found absent inactive absent 0' \
                >"$retirement_sequence"
            ;;
        collected-after-clean)
            printf '%s\n' \
                'loaded current active absent 0' \
                'loaded current inactive absent 0' \
                'not-found absent inactive absent 0' \
                >"$retirement_sequence"
            ;;
        stop-failed-collected)
            printf '%s\n' \
                'loaded current active absent 0' \
                'not-found absent inactive absent 0' \
                >"$retirement_sequence"
            ;;
        substituted-after-stop)
            printf '%s\n' \
                'loaded current active absent 0' \
                'loaded other inactive absent 0' \
                >"$retirement_sequence"
            ;;
        malformed-snapshot)
            printf '%s\n' 'malformed absent inactive absent 0' \
                >"$retirement_sequence"
            ;;
        never-collected)
            printf '%s\n' \
                'loaded current active absent 0' \
                'loaded current inactive absent 0' \
                'loaded current inactive absent 0' \
                >"$retirement_sequence"
            retirement_default_snapshot='loaded current inactive absent 0'
            ;;
        *) exit 97 ;;
    esac
    chmod 0600 "$retirement_sequence" "$retirement_actions" \
        "$retirement_show_count"

    unit_name=volparossa-helper-live-proof-A1b2C3.service
    unit_owned=yes
    unit_may_own=no
    unit_invocation_id=0123456789abcdef0123456789abcdef
    unit_ownership_marker=volparossa-helper-live-proof-owner-v1-0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef
    retirement_other_invocation=ffffffffffffffffffffffffffffffff
    expected_show_call="show --no-pager --property=LoadState --property=InvocationID --property=ActiveState --property=Job --property=NFileDescriptorStore $unit_name"
    if [ "$retirement_scenario" = tentative-successor-collected-after-stop ] \
        || [ "$retirement_scenario" = tentative-never-found ]; then
        unit_owned=no
        unit_may_own=yes
        unit_invocation_id=
    fi

    # Invoked indirectly by the extracted retirement function.
    # shellcheck disable=SC2317
    systemctl() {
        [ "$#" -ge 1 ] || return 1
        retirement_operation=$1
        case $retirement_operation in
            show)
                if [ "$*" = "show --property=LoadState --value $unit_name" ]; then
                    if [ "$retirement_scenario" = tentative-never-found ]; then
                        printf '%s\n' not-found
                    else
                        printf '%s\n' loaded
                    fi
                    return 0
                fi
                if [ "$*" = "show --property=Description --value $unit_name" ]; then
                    printf '%s\n' "$unit_ownership_marker"
                    return 0
                fi
                if [ "$*" = "show --property=InvocationID --value $unit_name" ]; then
                    printf '%s\n' 0123456789abcdef0123456789abcdef
                    return 0
                fi
                [ "$*" = "$expected_show_call" ] || return 1
                observed_show_count=$(cat "$retirement_show_count") || return 1
                observed_show_count=$((observed_show_count + 1))
                printf '%s\n' "$observed_show_count" \
                    >"$retirement_show_count" || return 1
                retirement_snapshot=$(sed -n "${observed_show_count}p" \
                    "$retirement_sequence") || return 1
                if [ -z "$retirement_snapshot" ]; then
                    retirement_snapshot=$retirement_default_snapshot
                fi
                [ -n "$retirement_snapshot" ] || return 1
                # The fixture syntax is exactly five space-delimited canonical
                # atoms; intentional splitting is the parser under test here.
                # shellcheck disable=SC2086
                set -- $retirement_snapshot
                [ "$#" -eq 5 ] || return 1
                snapshot_load=$1
                snapshot_invocation=$2
                snapshot_active=$3
                snapshot_job=$4
                snapshot_fdstore=$5
                if [ "$snapshot_load" = malformed ]; then
                    printf '%s\n' \
                        "NFileDescriptorStore=$snapshot_fdstore" \
                        "ActiveState=$snapshot_active" \
                        'InvocationID=' \
                        'LoadState=not-found'
                    return 0
                fi
                case $snapshot_invocation in
                    current) snapshot_invocation=$unit_invocation_id ;;
                    other) snapshot_invocation=$retirement_other_invocation ;;
                    absent) snapshot_invocation= ;;
                    *) return 1 ;;
                esac
                case $snapshot_job in
                    absent) snapshot_job= ;;
                    present) snapshot_job='7 /org/freedesktop/systemd1/job/7' ;;
                    *) return 1 ;;
                esac
                # Deliberately use a different order than the requested
                # properties; the strict parser is key-based, not positional.
                printf '%s\n' \
                    "NFileDescriptorStore=$snapshot_fdstore" \
                    "Job=$snapshot_job" \
                    "ActiveState=$snapshot_active" \
                    "InvocationID=$snapshot_invocation" \
                    "LoadState=$snapshot_load"
                ;;
            stop)
                [ "$*" = "stop --no-block $unit_name" ] || return 1
                printf '%s\n' stop >>"$retirement_actions" || return 1
                [ "$retirement_scenario" != stop-failed-collected ]
                ;;
            clean)
                [ "$*" = "clean --what=fdstore $unit_name" ] || return 1
                printf '%s\n' clean >>"$retirement_actions"
                ;;
            reset-failed)
                [ "$*" = "reset-failed $unit_name" ] || return 1
                printf '%s\n' reset >>"$retirement_actions"
                ;;
            *) return 1 ;;
        esac
    }
    # Invoked indirectly by the extracted bounded polling loops.
    # shellcheck disable=SC2317
    sleep() {
        [ "$#" -eq 1 ] && [ "$1" = 0.05 ]
    }

    retire_failure_stage=
    if retire_unit; then
        observed_retirement_status=0
    else
        observed_retirement_status=$?
    fi
    [ "$observed_retirement_status" -eq "$expected_retirement_status" ] \
        || exit 96
    if [ "$expected_retirement_failure_stage" != - ]; then
        [ "$retire_failure_stage" = "$expected_retirement_failure_stage" ] \
            || exit 96
    fi
    case $expected_retirement_disposition in
        forgotten)
            [ -z "$unit_name" ] && [ "$unit_owned" = no ] \
                && [ "$unit_may_own" = no ] && [ -z "$unit_invocation_id" ] \
                || exit 95
            ;;
        retained)
            [ "$unit_name" = volparossa-helper-live-proof-A1b2C3.service ] \
                && [ "$unit_owned" = yes ] && [ "$unit_may_own" = no ] \
                && [ "$unit_invocation_id" \
                    = 0123456789abcdef0123456789abcdef ] || exit 95
            ;;
        tentative)
            [ "$unit_name" = volparossa-helper-live-proof-A1b2C3.service ] \
                && [ "$unit_owned" = no ] && [ "$unit_may_own" = yes ] \
                && [ -z "$unit_invocation_id" ] \
                && [ -n "$unit_ownership_marker" ] || exit 95
            ;;
        *) exit 94 ;;
    esac
    observed_retirement_actions=$(paste -sd, "$retirement_actions") \
        || exit 93
    observed_retirement_shows=$(cat "$retirement_show_count") || exit 93
    if [ "$expected_retirement_actions" = - ]; then
        expected_retirement_actions=
    fi
    [ "$observed_retirement_actions" = "$expected_retirement_actions" ] \
        && [ "$observed_retirement_shows" -eq "$expected_retirement_shows" ] \
        || exit 92
)
while read -r retirement_name retirement_status retirement_disposition \
    retirement_actions_expected retirement_shows_expected \
    retirement_failure_stage_expected
do
    expect_status 0 exercise_retirement_sequence \
        "$retirement_name" "$retirement_status" "$retirement_disposition" \
        "$retirement_actions_expected" "$retirement_shows_expected" \
        "$retirement_failure_stage_expected"
    if [ -s "$last_stdout" ] || [ -s "$last_stderr" ]; then
        printf 'retirement sequence emitted diagnostics: %s\n' \
            "$retirement_name" >&2
        exit 1
    fi
done <<'EOF'
collected-after-stop 0 forgotten stop 2 -
tentative-successor-collected-after-stop 0 forgotten stop 2 -
tentative-never-found 1 tentative - 0 adoption
settled-then-collected 0 forgotten stop,clean,reset 5 -
failed-then-collected 0 forgotten stop,reset,clean,reset 5 -
collected-after-clean 0 forgotten stop,clean 3 -
stop-failed-collected 0 forgotten stop 2 -
substituted-after-stop 1 retained stop 2 stop-wait
malformed-snapshot 1 retained - 1 initial-snapshot
never-collected 1 retained stop,clean,reset 1203 collection
EOF

# A real TERM/HUP/INT path exits through cleanup. If PID 1 still reports a
# status-0 transient launch as not-found for the full bounded window, cleanup
# must fail while preserving the stage; deleting it could strand a unit that
# appears after the driver has lost its bound files.
interrupted_cleanup_stage_marker=$temporary_directory/interrupted-cleanup-stage-removed
exercise_interrupted_launched_cleanup() (
    [ "$#" -eq 1 ] || exit 98
    interrupted_signal=$1
    unit_name=volparossa-helper-live-proof-A1b2C3.service
    unit_owned=no
    unit_may_own=yes
    unit_invocation_id=
    unit_ownership_marker=volparossa-helper-live-proof-owner-v1-0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef
    cleanup_error=no
    structured_failure_reported=yes
    # Read indirectly by the extracted production cleanup function.
    # shellcheck disable=SC2034
    restart_successor_debugger_pid='' \
        restart_successor_debugger_starttime='' restart_mount_keeper_pid='' \
        restart_mount_keeper_starttime='' temporary_stage_identity=fixture
    temporary_stage=$temporary_directory/interrupted-cleanup-stage
    # Invoked by the real launched-unit adoption loop.
    # shellcheck disable=SC2317
    unit_load_state() { printf '%s\n' not-found; }
    # shellcheck disable=SC2317
    sleep() { [ "$#" -eq 1 ] && [ "$1" = 0.05 ]; }
    # Invoked only if cleanup violates the retained-stage contract.
    # shellcheck disable=SC2317
    remove_temporary_stage() {
        : >"$interrupted_cleanup_stage_marker"
    }
    # shellcheck disable=SC1090
    . "$gate_cleanup_function"
    trap cleanup EXIT
    trap 'exit 129' HUP
    trap 'exit 130' INT
    trap 'exit 143' TERM
    read -r interrupted_cleanup_pid _ </proc/self/stat
    kill -s "$interrupted_signal" "$interrupted_cleanup_pid"
    exit 97
)
while read -r interrupted_signal interrupted_status; do
    rm -f -- "$interrupted_cleanup_stage_marker"
    expect_status "$interrupted_status" exercise_interrupted_launched_cleanup \
        "$interrupted_signal"
    if [ -e "$interrupted_cleanup_stage_marker" ] \
        || [ -L "$interrupted_cleanup_stage_marker" ]; then
        printf 'ambiguous interrupted launch removed its stage: %s\n' \
            "$interrupted_signal" >&2
        exit 1
    fi
    if [ -s "$last_stdout" ] || [ -s "$last_stderr" ]; then
        printf 'ambiguous interrupted launch emitted diagnostics: %s\n' \
            "$interrupted_signal" >&2
        exit 1
    fi
done <<'EOF'
HUP 129
INT 130
TERM 143
EOF

# The production identity must be fully retired before the restart proof may
# derive or publish a second transient unit name. Exercise the real transition
# helper and prove every dirty affine precondition fails without changing any
# of the guarded fields.
restart_identity_function=$temporary_directory/restart-identity-function.sh
sed -n '/^prepare_restart_unit_identity() {$/,/^}$/p' "$gate" \
    >"$restart_identity_function"
if [ "$(grep -c '^prepare_restart_unit_identity() {$' \
    "$restart_identity_function")" -ne 1 ]; then
    printf '%s\n' 'the restart identity transition is not uniquely extractable' >&2
    exit 1
fi
sh -n "$restart_identity_function"
# shellcheck source=/dev/null
. "$restart_identity_function"

# ShellCheck cannot resolve the fixture globals consumed by the extracted
# restart identity transition.
# shellcheck disable=SC2034
exercise_restart_identity_transition() (
    [ "$#" -eq 3 ] || exit 98
    restart_identity_scenario=$1
    expected_transition_status=$2
    expected_restart_name=$3

    stage_suffix=ABC123
    production_unit_name=volparossa-helper-live-proof-ABC123.service
    production_retirement_confirmed=yes
    unit_name=
    unit_owned=no
    unit_may_own=no
    unit_invocation_id=
    unit_ownership_marker=

    case $restart_identity_scenario in
        success-a) ;;
        success-other)
            stage_suffix=zBC123
            production_unit_name=volparossa-helper-live-proof-zBC123.service
            ;;
        unconfirmed) production_retirement_confirmed=no ;;
        dirty-name) unit_name=$production_unit_name ;;
        dirty-owned) unit_owned=yes ;;
        dirty-may-own) unit_may_own=yes ;;
        dirty-invocation)
            unit_invocation_id=0123456789abcdef0123456789abcdef
            ;;
        dirty-marker)
            unit_ownership_marker=volparossa-helper-live-proof-owner-v1-0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef
            ;;
        invalid-stage) stage_suffix=ABC12- ;;
        invalid-production)
            production_unit_name=volparossa-helper-live-proof-ABC12-.service
            ;;
        *) exit 97 ;;
    esac

    transition_before=$(printf '%s|%s|%s|%s|%s|%s' \
        "$production_retirement_confirmed" "$unit_name" "$unit_owned" \
        "$unit_may_own" "$unit_invocation_id" "$unit_ownership_marker") \
        || exit 96
    if prepare_restart_unit_identity; then
        observed_transition_status=0
    else
        observed_transition_status=$?
    fi
    transition_after=$(printf '%s|%s|%s|%s|%s|%s' \
        "$production_retirement_confirmed" "$unit_name" "$unit_owned" \
        "$unit_may_own" "$unit_invocation_id" "$unit_ownership_marker") \
        || exit 96

    [ "$observed_transition_status" -eq "$expected_transition_status" ] \
        || exit 95
    if [ "$expected_transition_status" -eq 0 ]; then
        [ "$unit_name" = "$expected_restart_name" ] \
            && [ "$production_retirement_confirmed" = yes ] \
            && [ "$unit_owned" = no ] && [ "$unit_may_own" = no ] \
            && [ -z "$unit_invocation_id" ] \
            && [ -z "$unit_ownership_marker" ] \
            || exit 94
    else
        [ "$transition_after" = "$transition_before" ] || exit 93
    fi
)
while read -r restart_identity_name expected_restart_identity_status \
    expected_restart_identity_unit
do
    expect_status 0 exercise_restart_identity_transition \
        "$restart_identity_name" "$expected_restart_identity_status" \
        "$expected_restart_identity_unit"
    if [ -s "$last_stdout" ] || [ -s "$last_stderr" ]; then
        printf 'restart identity transition emitted diagnostics: %s\n' \
            "$restart_identity_name" >&2
        exit 1
    fi
done <<'EOF'
success-a 0 volparossa-helper-live-proof-BBC123.service
success-other 0 volparossa-helper-live-proof-ABC123.service
unconfirmed 1 -
dirty-name 1 -
dirty-owned 1 -
dirty-may-own 1 -
dirty-invocation 1 -
dirty-marker 1 -
invalid-stage 1 -
invalid-production 1 -
EOF

# Exercise the exact capability normalizer with Debian's awk implementation.
# The production regression here was caused by using awk's built-in `index`
# function name as a loop variable, which mawk rejects while parsing.
capability_normalizer=$temporary_directory/capability-normalizer.sh
sed -n '/^normalize_capabilities() {$/,/^}$/p' "$gate" \
    >"$capability_normalizer"
if [ "$(grep -c '^normalize_capabilities() {$' "$capability_normalizer")" -ne 1 ]; then
    printf '%s\n' 'the capability normalizer is not uniquely extractable' >&2
    exit 1
fi
if grep -Eq 'for[[:space:]]*\([[:space:]]*index[[:space:]]*=' \
    "$capability_normalizer"; then
    printf '%s\n' 'the capability normalizer reused awk index as a loop variable' >&2
    exit 1
fi
sh -n "$capability_normalizer"
# shellcheck source=/dev/null
. "$capability_normalizer"
capabilities='CAP_KILL CAP_NET_ADMIN CAP_NET_RAW CAP_SETGID CAP_SETPCAP CAP_SETUID CAP_SYS_ADMIN'
capability_raw=$temporary_directory/capabilities.raw
capability_normalized=$temporary_directory/capabilities.normalized
printf '%s\n' \
    'cap_sys_admin cap_setuid CAP_SETPCAP cap_setgid' \
    'cap_net_raw CAP_NET_ADMIN cap_kill' >"$capability_raw"
chmod 0600 "$capability_raw"
expect_status 0 normalize_capabilities "$capability_raw" "$capability_normalized"
if [ -s "$last_stdout" ] || [ -s "$last_stderr" ] \
    || [ "$(cat "$capability_normalized")" != "$capabilities" ]; then
    printf '%s\n' 'the Debian-compatible capability normalization is not exact' >&2
    exit 1
fi
normalize_capabilities_with_mawk() (
    # Invoked indirectly by the extracted capability normalizer.
    # shellcheck disable=SC2317
    awk() {
        command mawk "$@"
    }
    normalize_capabilities "$@"
)
if command -v mawk >/dev/null 2>&1; then
    capability_mawk_normalized=$temporary_directory/capabilities.mawk.normalized
    expect_status 0 normalize_capabilities_with_mawk \
        "$capability_raw" "$capability_mawk_normalized"
    if [ -s "$last_stdout" ] || [ -s "$last_stderr" ] \
        || [ "$(cat "$capability_mawk_normalized")" != "$capabilities" ]; then
        printf '%s\n' 'explicit mawk capability normalization is not exact' >&2
        exit 1
    fi
fi

for confinement_reason in bounding ambient private-network control-group; do
    confinement_application_count=3
    if [ "$confinement_reason" = control-group ]; then
        confinement_application_count=6
    fi
    if ! worker_confinement_failure_is_safe "$confinement_reason" \
        || [ "$(grep -Fc "record_worker_confinement_failure '$confinement_reason'" \
            "$gate")" -ne "$confinement_application_count" ]; then
        printf 'worker confinement reason is not closed and fully applied: %s\n' \
            "$confinement_reason" >&2
        exit 1
    fi
done
if worker_confinement_failure_is_safe '' \
    || worker_confinement_failure_is_safe 'control-group/private-record'; then
    printf '%s\n' 'the worker confinement subcategory allowlist is not closed' >&2
    exit 1
fi

report_worker_confinement_first_failure() (
    proof_failure_reason=
    proof_ok=yes
    unset production_ok
    worker_confinement_failure=
    record_worker_confinement_failure 'ambient'
    record_worker_confinement_failure 'control-group'
    if [ "$proof_ok" != no ] || [ "${production_ok+x}" = x ] \
        || [ "$proof_failure_reason" != worker-confinement ] \
        || [ "$worker_confinement_failure" != ambient ]; then
        exit 99
    fi
    report_worker_confinement_diagnostic
)
expect_status 0 report_worker_confinement_first_failure
if [ -s "$last_stdout" ] \
    || ! grep -Fx \
        'VOLPAROSSA_HELPER_LIVE_WORKER_CONFINEMENT_DIAGNOSTIC_V1=ambient' \
        "$last_stderr" >/dev/null \
    || [ "$(wc -l <"$last_stderr")" -ne 1 ]; then
    printf '%s\n' 'the worker confinement diagnostic did not retain its first fixed reason' >&2
    exit 1
fi

reject_late_worker_confinement_diagnostic() (
    proof_failure_reason=
    proof_ok=yes
    unset production_ok
    worker_confinement_failure=
    record_proof_failure 'worker-unit-contract'
    record_worker_confinement_failure 'bounding'
    report_worker_confinement_diagnostic
)
expect_status 1 reject_late_worker_confinement_diagnostic
if [ -s "$last_stdout" ] || [ -s "$last_stderr" ]; then
    printf '%s\n' 'a later worker confinement predicate escaped first-failure precedence' >&2
    exit 1
fi

report_worker_first_failure() (
    proof_failure_reason=
    proof_ok=yes
    unset production_ok
    record_proof_failure 'worker-launch-status'
    record_proof_failure 'worker-proof-records'
    if [ "$proof_ok" != no ] || [ "${production_ok+x}" = x ] \
        || [ "$proof_failure_reason" != worker-launch-status ]; then
        exit 99
    fi
    report_proof_failure "$proof_failure_reason"
)
expect_status 1 report_worker_first_failure
if [ -s "$last_stdout" ] \
    || ! grep -Fx 'live worker-identity proof failed: predicate rejected: worker-launch-status' \
        "$last_stderr" >/dev/null \
    || [ "$(wc -l <"$last_stderr")" -ne 1 ]; then
    printf '%s\n' 'the worker diagnostic did not retain only its first fixed reason' >&2
    exit 1
fi

report_allowlisted_unrecorded_failure() (
    proof_failure_reason=
    proof_ok=yes
    unset production_ok
    report_proof_failure 'worker-unit-contract'
)
expect_status 1 report_allowlisted_unrecorded_failure
if [ -s "$last_stdout" ] \
    || ! grep -Fx \
        'diagnostic failure: internal proof failure reason was not recorded' \
        "$last_stderr" >/dev/null \
    || grep -F 'worker-unit-contract' "$last_stderr" >/dev/null \
    || [ "$(wc -l <"$last_stderr")" -ne 1 ]; then
    printf '%s\n' 'the reporter accepted an allowlisted but unrecorded reason' >&2
    exit 1
fi

report_mismatched_first_failure() (
    proof_failure_reason=
    proof_ok=yes
    unset production_ok
    record_proof_failure 'worker-launch-status'
    report_proof_failure 'worker-proof-records'
)
expect_status 1 report_mismatched_first_failure
if [ -s "$last_stdout" ] \
    || ! grep -Fx \
        'diagnostic failure: internal proof failure reason was not recorded' \
        "$last_stderr" >/dev/null \
    || grep -E 'worker-(launch-status|proof-records)' "$last_stderr" >/dev/null \
    || [ "$(wc -l <"$last_stderr")" -ne 1 ]; then
    printf '%s\n' 'the reporter accepted a reason other than the recorded first failure' >&2
    exit 1
fi

report_unfailed_status() (
    proof_failure_reason=
    proof_ok=yes
    unset production_ok
    record_proof_failure 'worker-launch-status'
    proof_ok=yes
    report_proof_failure "$proof_failure_reason"
)
expect_status 1 report_unfailed_status
if [ -s "$last_stdout" ] \
    || ! grep -Fx \
        'diagnostic failure: internal proof failure reason was not recorded' \
        "$last_stderr" >/dev/null \
    || grep -F 'worker-launch-status' "$last_stderr" >/dev/null \
    || [ "$(wc -l <"$last_stderr")" -ne 1 ]; then
    printf '%s\n' 'the reporter accepted a recorded reason without failed proof state' >&2
    exit 1
fi

report_production_first_failure() (
    proof_failure_reason=
    proof_ok=yes
    production_ok=yes
    record_proof_failure 'production-running-state'
    record_proof_failure 'production-stop-records'
    if [ "$proof_ok" != no ] || [ "$production_ok" != no ] \
        || [ "$proof_failure_reason" != production-running-state ]; then
        exit 99
    fi
    report_proof_failure "$proof_failure_reason"
)
expect_status 1 report_production_first_failure
if [ -s "$last_stdout" ] \
    || ! grep -Fx 'live worker-identity proof failed: predicate rejected: production-running-state' \
        "$last_stderr" >/dev/null \
    || [ "$(wc -l <"$last_stderr")" -ne 1 ]; then
    printf '%s\n' 'the production diagnostic did not retain only its first fixed reason' >&2
    exit 1
fi

report_unsafe_failure() (
    report_proof_failure 'worker-launch-status/private-record'
)
expect_status 1 report_unsafe_failure
if [ -s "$last_stdout" ] \
    || ! grep -Fx \
        'diagnostic failure: internal proof failure reason was not recorded' \
        "$last_stderr" >/dev/null \
    || grep -F 'private-record' "$last_stderr" >/dev/null \
    || [ "$(wc -l <"$last_stderr")" -ne 1 ]; then
    printf '%s\n' 'the proof failure reporter reflected an untrusted reason' >&2
    exit 1
fi

record_unsafe_failure() (
    proof_failure_reason=
    proof_ok=yes
    production_ok=yes
    record_proof_failure 'production-running-state/private-record'
)
expect_status 1 record_unsafe_failure
if [ -s "$last_stdout" ] \
    || ! grep -Fx 'diagnostic failure: internal proof failure reason is invalid' \
        "$last_stderr" >/dev/null \
    || grep -F 'private-record' "$last_stderr" >/dev/null \
    || [ "$(wc -l <"$last_stderr")" -ne 1 ]; then
    printf '%s\n' 'the proof failure recorder reflected an untrusted reason' >&2
    exit 1
fi

# Capture safety is a metadata contract, not a non-empty-content contract.
# Successful commands and validators legitimately produce zero-byte streams.
empty_capture=$temporary_directory/empty.capture
vp_capture_run "$empty_capture" :
if ! vp_capture_file_is_safe "$empty_capture" \
    || [ -s "$empty_capture" ] \
    || [ "$(stat -Lc '%f:%u:%g:%a:%h' "$empty_capture")" != \
        "8180:$VP_CAPTURE_OWNER_UID:$VP_CAPTURE_OWNER_GID:600:1" ]; then
    printf '%s\n' 'a successful empty private capture was rejected' >&2
    exit 1
fi
empty_normalized=$temporary_directory/empty.normalized
vp_capture_normalize "$empty_capture" "$empty_normalized" cat
if ! vp_capture_file_is_safe "$empty_normalized" || [ -s "$empty_normalized" ]; then
    printf '%s\n' 'a successful empty normalized capture was rejected' >&2
    exit 1
fi

chmod 0640 "$empty_capture"
if vp_capture_file_is_safe "$empty_capture"; then
    printf '%s\n' 'an empty capture with the wrong mode was accepted' >&2
    exit 1
fi
chmod 0600 "$empty_capture"
capture_owner_uid=$VP_CAPTURE_OWNER_UID
VP_CAPTURE_OWNER_UID=0
if vp_capture_file_is_safe "$empty_capture"; then
    VP_CAPTURE_OWNER_UID=$capture_owner_uid
    printf '%s\n' 'an empty capture with the wrong expected owner was accepted' >&2
    exit 1
fi
VP_CAPTURE_OWNER_UID=$capture_owner_uid
empty_capture_symlink=$temporary_directory/empty.capture.link
ln -s "$empty_capture" "$empty_capture_symlink"
if vp_capture_file_is_safe "$empty_capture_symlink"; then
    printf '%s\n' 'an empty capture symlink was accepted' >&2
    exit 1
fi
empty_capture_hardlink=$temporary_directory/empty.capture.hardlink
ln "$empty_capture" "$empty_capture_hardlink"
if vp_capture_file_is_safe "$empty_capture" \
    || vp_capture_file_is_safe "$empty_capture_hardlink"; then
    printf '%s\n' 'a multiply linked empty capture was accepted' >&2
    exit 1
fi
rm -f -- "$empty_capture_hardlink"
vp_capture_file_is_safe "$empty_capture"

# The production ownership lock is intentionally empty. Model its exact
# numeric path/FD identity, active contention, and release without root.
empty_lock=$temporary_directory/empty-ownership.lock
: >"$empty_lock"
chmod 0600 "$empty_lock"
empty_lock_identity=$(stat -c '%d:%i:%f:%u:%g:%a:%h' "$empty_lock")
case $empty_lock_identity in
    *":8180:$VP_CAPTURE_OWNER_UID:$VP_CAPTURE_OWNER_GID:600:1") ;;
    *)
        printf '%s\n' 'the empty ownership-lock metadata is not canonical' >&2
        exit 1
        ;;
esac
exec 9<>"$empty_lock"
empty_lock_fd_identity=$(stat -Lc '%d:%i:%f:%u:%g:%a:%h' /proc/self/fd/9)
if [ "$empty_lock_fd_identity" != "$empty_lock_identity" ] \
    || ! /usr/bin/flock -n -x 9; then
    printf '%s\n' 'the empty ownership-lock path/FD identity was not retained' >&2
    exit 1
fi
if (
    exec 8<>"$empty_lock"
    /usr/bin/flock -n -x 8
); then
    printf '%s\n' 'the empty ownership lock did not prove active contention' >&2
    exit 1
fi
exec 9>&-
exec 9<>"$empty_lock"
/usr/bin/flock -n -x 9
exec 9>&-

# Pin the root-only production hook and outer gate to the same size-independent
# lock identity. The dynamic model above exercises the tuple without root.
private_file_contract=$(sed -n '/^private_file_is_safe() {$/,/^}$/p' "$ipc_hook")
capture_lock_contract=$(sed -n '/^capture_lock_identity() {$/,/^}$/p' "$ipc_hook")
if [ "$(printf '%s\n' "$private_file_contract" \
        | grep -Fc "stat -Lc '%f:%u:%g:%a:%h'")" -ne 1 ] \
    || [ "$(printf '%s\n' "$private_file_contract" \
        | grep -Fc "'8180:0:0:600:1'")" -ne 1 ] \
    || [ "$(printf '%s\n' "$capture_lock_contract" \
        | grep -Fc "stat -c '%d:%i:%f:%u:%g:%a:%h'")" -ne 1 ] \
    || [ "$(printf '%s\n' "$capture_lock_contract" \
        | grep -Fc "\":8180:0:\$hook_lock_gid:600:1\"")" -ne 1 ]; then
    printf '%s\n' 'the production hook has a size-dependent private-file contract' >&2
    exit 1
fi
# These are literal gate-source contracts; expansion here would defeat them.
# shellcheck disable=SC2016
for numeric_lock_contract in \
    "stat -c '%f:%u:%g:%a:%h'" \
    '"8180:0:$agent_gid:600:1"' \
    "stat -c '%d:%i:%f:%u:%g:%a:%h'" \
    "stat -Lc '%d:%i:%f:%u:%g:%a:%h'"
do
    grep -F -- "$numeric_lock_contract" "$gate" >/dev/null || {
        printf 'missing size-independent outer lock contract: %s\n' \
            "$numeric_lock_contract" >&2
        exit 1
    }
done

injected_successful_producer() {
    printf '%s\n' 'identical partial capture'
}

injected_failing_producer() {
    printf '%s\n' 'identical partial capture'
    return 19
}

injected_failing_parser() {
    cat
    return 23
}

producer_failure_gate() {
    producer_raw=$temporary_directory/producer-failure.raw
    producer_digest=$temporary_directory/producer-failure.digest
    vp_capture_run "$producer_raw" injected_failing_producer || return 77
    vp_capture_publish_digest "$producer_raw" "$producer_digest" || return 77
}

parser_failure_gate() {
    parser_raw=$temporary_directory/parser-failure.raw
    parser_normalized=$temporary_directory/parser-failure.normalized
    parser_digest=$temporary_directory/parser-failure.digest
    vp_capture_run "$parser_raw" injected_successful_producer || return 77
    vp_capture_normalize "$parser_raw" "$parser_normalized" injected_failing_parser || return 77
    vp_capture_publish_digest "$parser_normalized" "$parser_digest" || return 77
}

stream_producer_failure_gate() {
    stream_fifo=$temporary_directory/stream-producer-failure.fifo
    stream_digest=$temporary_directory/stream-producer-failure.digest
    vp_capture_stream_sha256 "$stream_fifo" "$stream_digest" injected_failing_producer \
        || return 77
}

stream_hasher_failure_gate() {
    (
        sha256sum() {
            cat >/dev/null
            return 29
        }
        stream_fifo=$temporary_directory/stream-hasher-failure.fifo
        stream_digest=$temporary_directory/stream-hasher-failure.digest
        vp_capture_stream_sha256 "$stream_fifo" "$stream_digest" \
            injected_successful_producer || exit 77
    )
}

# Exercise the gate's real network-state normalizers. In particular, keep each
# flags sort scoped to its flags array rather than the enclosing object.
network_state_producers=$temporary_directory/network-state-producers.sh
{
    sed -n '/^quiet_jq() {$/,/^}$/p' "$gate"
    sed -n '/^link_state_producer() {$/,/^}$/p' "$gate"
    sed -n '/^address_state_producer() {$/,/^}$/p' "$gate"
    sed -n '/^route_state_producer() {$/,/^}$/p' "$gate"
    sed -n '/^rule_state_producer() {$/,/^}$/p' "$gate"
    sed -n '/^nexthop_state_producer() {$/,/^}$/p' "$gate"
    sed -n '/^qdisc_state_producer() {$/,/^}$/p' "$gate"
    sed -n '/^nftables_state_producer() {$/,/^}$/p' "$gate"
} >"$network_state_producers"
if [ "$(grep -c '^quiet_jq() {$' "$network_state_producers")" -ne 1 ] \
    || [ "$(grep -c '^link_state_producer() {$' "$network_state_producers")" -ne 1 ] \
    || [ "$(grep -c '^address_state_producer() {$' "$network_state_producers")" -ne 1 ] \
    || [ "$(grep -c '^route_state_producer() {$' "$network_state_producers")" -ne 1 ] \
    || [ "$(grep -c '^rule_state_producer() {$' "$network_state_producers")" -ne 1 ] \
    || [ "$(grep -c '^nexthop_state_producer() {$' "$network_state_producers")" -ne 1 ] \
    || [ "$(grep -c '^qdisc_state_producer() {$' "$network_state_producers")" -ne 1 ] \
    || [ "$(grep -c '^nftables_state_producer() {$' "$network_state_producers")" -ne 1 ]; then
    printf '%s\n' 'the network-state normalizers cannot be isolated' >&2
    exit 1
fi
sh -n "$network_state_producers"
if [ "$(grep -Ec '^[[:space:]]*jq([[:space:]]|$)' \
        "$network_state_producers")" -ne 1 ] \
    || ! grep -Fx '    jq "$@" 2>/dev/null' "$network_state_producers" >/dev/null; then
    printf '%s\n' 'network-state producers contain a bare jq bypass outside quiet_jq' >&2
    exit 1
fi
if sed -n '/^capture_host_state() {$/,/^}$/p' "$gate" \
    | grep -Eq '^[[:space:]]*jq([[:space:]]|$)'; then
    printf '%s\n' 'host capture contains a bare jq bypass' >&2
    exit 1
fi
# The function path is generated from the reviewed gate above.
# shellcheck disable=SC1090
. "$network_state_producers"

if ! awk '
    BEGIN {
        required["link_state_producer"] = 1
        required["address_state_producer"] = 1
        required["route_state_producer"] = 1
        required["rule_state_producer"] = 1
        required["nexthop_state_producer"] = 1
        required["qdisc_state_producer"] = 1
        required["nftables_state_producer"] = 1
    }
    /^[a-z_]+_state_producer\(\) \{$/ {
        producer = $1
        sub(/\(\)$/, "", producer)
        next
    }
    producer != "" && /quiet_jq / { quiet[producer]++ }
    producer != "" && /^}$/ { producer = "" }
    END {
        for (producer in required) if (quiet[producer] != 1) exit 1
    }
' "$network_state_producers"; then
    printf '%s\n' 'a network-state producer is not bound to exactly one quiet jq call' >&2
    exit 1
fi

if ! awk '
    BEGIN {
        expected["links"] = "link_state_producer"
        expected["addresses"] = "address_state_producer"
        expected["routes"] = "route_state_producer"
        expected["rules"] = "rule_state_producer"
        expected["nexthops"] = "nexthop_state_producer"
        expected["qdiscs"] = "qdisc_state_producer"
        expected["nftables-a"] = "nftables_state_producer"
        expected["nftables-b"] = "nftables_state_producer"
        label["links"] = "host link normalization failed"
        label["addresses"] = "host address normalization failed"
        label["routes"] = "host route normalization failed"
        label["rules"] = "host rule normalization failed"
        label["nexthops"] = "host nexthop normalization failed"
        label["qdiscs"] = "host qdisc normalization failed"
        label["nftables-a"] = "host nftables first normalization failed"
        label["nftables-b"] = "host nftables second normalization failed"
    }
    $0 == "capture_host_state() {" { in_capture = 1; next }
    in_capture && $0 == "}" { in_capture = 0; next }
    in_capture {
        started = 0
        for (site in expected) {
            target = "$capture_directory/" site ".normalized"
            if (index($0, target) > 0 \
                && index($0, "vp_capture_publish_digest") == 0 \
                && seen[site] == 0) {
                if (active != "") exit 1
                active = site
                command = $0
                started = 1
                break
            }
        }
        if (active != "" && !started) command = command "\n" $0
        if (active != "" && index($0, label[active]) > 0) {
            if (index(command, expected[active]) == 0) exit 1
            seen[active]++
            active = ""
            command = ""
        }
    }
    END {
        if (active != "" || in_capture) exit 1
        for (site in expected) if (seen[site] != 1) exit 1
    }
' "$gate"; then
    printf '%s\n' 'host capture does not use every exact quiet network-state producer' >&2
    exit 1
fi

link_valid=$temporary_directory/link-valid.raw
link_normalized=$temporary_directory/link-valid.normalized
link_expected=$temporary_directory/link-valid.expected
printf '%s\n' \
    '[{"ifindex":2,"ifname":"wg0","flags":["RUNNING","POINTOPOINT"],"altnames":["zeta","alpha"],"operstate":"UP"},{"ifindex":3,"ifname":"wg1"}]' \
    >"$link_valid"
printf '%s\n' \
    '[{"altnames":["alpha","zeta"],"flags":["POINTOPOINT"],"ifindex":2,"ifname":"wg0"},{"flags":[],"ifindex":3,"ifname":"wg1"}]' \
    >"$link_expected"
vp_capture_normalize "$link_valid" "$link_normalized" link_state_producer
if ! cmp -s "$link_expected" "$link_normalized"; then
    printf '%s\n' 'link records did not normalize deterministically' >&2
    exit 1
fi

address_valid=$temporary_directory/address-valid.raw
address_normalized=$temporary_directory/address-valid.normalized
address_expected=$temporary_directory/address-valid.expected
printf '%s\n' '[{"ifindex":2,"ifname":"wg0"}]' >"$address_valid"
printf '%s\n' '[{"addr_info":[],"ifindex":2,"ifname":"wg0"}]' >"$address_expected"
vp_capture_normalize "$address_valid" "$address_normalized" address_state_producer
if ! cmp -s "$address_expected" "$address_normalized"; then
    printf '%s\n' 'address records did not normalize deterministically' >&2
    exit 1
fi

qdisc_valid=$temporary_directory/qdisc-valid.raw
qdisc_normalized=$temporary_directory/qdisc-valid.normalized
qdisc_expected=$temporary_directory/qdisc-valid.expected
printf '%s\n' '[{"kind":"fq_codel","dev":"wg0","packets":7}]' >"$qdisc_valid"
printf '%s\n' '[{"dev":"wg0","kind":"fq_codel"}]' >"$qdisc_expected"
vp_capture_normalize "$qdisc_valid" "$qdisc_normalized" qdisc_state_producer
if ! cmp -s "$qdisc_expected" "$qdisc_normalized"; then
    printf '%s\n' 'qdisc records did not normalize deterministically' >&2
    exit 1
fi

nftables_valid=$temporary_directory/nftables-valid.raw
nftables_normalized=$temporary_directory/nftables-valid.normalized
nftables_expected=$temporary_directory/nftables-valid.expected
printf '%s\n' '{"nftables":[]}' >"$nftables_valid"
printf '%s\n' '{"nftables":[]}' >"$nftables_expected"
vp_capture_normalize "$nftables_valid" "$nftables_normalized" nftables_state_producer
if ! cmp -s "$nftables_expected" "$nftables_normalized"; then
    printf '%s\n' 'nftables records did not normalize deterministically' >&2
    exit 1
fi

routes_empty=$temporary_directory/routes-empty.raw
routes_first=$temporary_directory/routes-first.raw
routes_first_v6=$temporary_directory/routes-first-v6.raw
routes_second=$temporary_directory/routes-second.raw
routes_second_v6=$temporary_directory/routes-second-v6.raw
routes_first_normalized=$temporary_directory/routes-first.normalized
routes_second_normalized=$temporary_directory/routes-second.normalized
routes_expected=$temporary_directory/routes.expected
printf '%s\n' '[]' >"$routes_empty"
printf '%s\n' \
    '[{"table":"main","dst":"default","protocol":"static","dev":"wg-alpha","flags":["pervasive","offload","onlink","dead"],"expires":3}]' \
    >"$routes_first"
printf '%s\n' \
    '[{"table":"main","dst":"default","protocol":"static","dev":"wg-alpha","flags":["pervasive","offload","onlink","dead"],"expires":3}]' \
    >"$routes_first_v6"
printf '%s\n' \
    '[{"flags":["dead","onlink","offload","pervasive"],"dev":"wg-alpha","protocol":"static","dst":"default","table":"main","expires":9}]' \
    >"$routes_second"
printf '%s\n' \
    '[{"flags":["dead","onlink","offload","pervasive"],"dev":"wg-alpha","protocol":"static","dst":"default","table":"main","expires":9}]' \
    >"$routes_second_v6"
printf '%s\n' \
    '[{"dev":"wg-alpha","dst":"default","family":"inet","flags":["onlink","pervasive"],"protocol":"static","table":"main"},{"dev":"wg-alpha","dst":"default","family":"inet6","flags":["onlink","pervasive"],"protocol":"static","table":"main"}]' \
    >"$routes_expected"
vp_capture_run "$routes_first_normalized" route_state_producer \
    "$routes_first" "$routes_first_v6"
vp_capture_run "$routes_second_normalized" route_state_producer \
    "$routes_second" "$routes_second_v6"
if ! cmp -s "$routes_expected" "$routes_first_normalized" \
    || ! cmp -s "$routes_first_normalized" "$routes_second_normalized"; then
    printf '%s\n' 'route flags did not normalize deterministically' >&2
    exit 1
fi
route_without_flags=$temporary_directory/route-without-flags.raw
route_without_flags_normalized=$temporary_directory/route-without-flags.normalized
route_without_flags_expected=$temporary_directory/route-without-flags.expected
printf '%s\n' \
    '[{"family":"inet","table":"main","dst":"198.51.100.0/24","dev":"wg-no-flags"}]' \
    >"$route_without_flags"
printf '%s\n' \
    '[{"dev":"wg-no-flags","dst":"198.51.100.0/24","family":"inet","table":"main"}]' \
    >"$route_without_flags_expected"
vp_capture_run "$route_without_flags_normalized" route_state_producer \
    "$route_without_flags" "$routes_empty"
if ! cmp -s "$route_without_flags_expected" "$route_without_flags_normalized"; then
    printf '%s\n' 'a route with absent flags was not accepted canonically' >&2
    exit 1
fi

rules_v4=$temporary_directory/rules-v4.raw
rules_v6=$temporary_directory/rules-v6.raw
rules_normalized=$temporary_directory/rules.normalized
rules_expected=$temporary_directory/rules.expected
printf '%s\n' \
    '[{"family":"inet","priority":200,"table":"main"},{"table":"main","priority":100}]' \
    >"$rules_v4"
printf '%s\n' \
    '[{"table":"main","priority":100}]' \
    >"$rules_v6"
printf '%s\n' \
    '[{"family":"inet","priority":100,"table":"main"},{"family":"inet","priority":200,"table":"main"},{"family":"inet6","priority":100,"table":"main"}]' \
    >"$rules_expected"
vp_capture_run "$rules_normalized" rule_state_producer "$rules_v4" "$rules_v6"
if ! cmp -s "$rules_expected" "$rules_normalized"; then
    printf '%s\n' 'rule records did not normalize deterministically' >&2
    exit 1
fi

nexthops_first=$temporary_directory/nexthops-first.raw
nexthops_second=$temporary_directory/nexthops-second.raw
nexthops_first_normalized=$temporary_directory/nexthops-first.normalized
nexthops_second_normalized=$temporary_directory/nexthops-second.normalized
nexthops_expected=$temporary_directory/nexthops.expected
printf '%s\n' \
    '[{"id":7,"dev":"wg-beta","via":{"family":"inet6","addr":"2001:db8::1"},"flags":["pervasive","trap","onlink","offload"],"used":4},{"id":8,"dev":"wg-no-flags"}]' \
    >"$nexthops_first"
printf '%s\n' \
    '[{"dev":"wg-no-flags","id":8},{"used":8,"flags":["offload","onlink","trap","pervasive"],"via":{"addr":"2001:db8::1","family":"inet6"},"dev":"wg-beta","id":7}]' \
    >"$nexthops_second"
printf '%s\n' \
    '[{"dev":"wg-beta","flags":["onlink","pervasive"],"id":7,"via":{"addr":"2001:db8::1","family":"inet6"}},{"dev":"wg-no-flags","id":8}]' \
    >"$nexthops_expected"
vp_capture_normalize "$nexthops_first" "$nexthops_first_normalized" \
    nexthop_state_producer
vp_capture_normalize "$nexthops_second" "$nexthops_second_normalized" \
    nexthop_state_producer
if ! cmp -s "$nexthops_expected" "$nexthops_first_normalized" \
    || ! cmp -s "$nexthops_first_normalized" "$nexthops_second_normalized"; then
    printf '%s\n' 'nexthop flags did not normalize deterministically' >&2
    exit 1
fi

two_family_shape_failure_gate() {
    [ "$#" -eq 4 ] || return 78
    network_failure_producer=$1
    network_failure_family=$2
    network_failure_label=$3
    network_failure_input=$4
    network_failure_output=$temporary_directory/$network_failure_producer-$network_failure_family-$network_failure_label.normalized
    case $network_failure_family in
        v4)
            vp_capture_run "$network_failure_output" "$network_failure_producer" \
                "$network_failure_input" "$routes_empty" || return 77
            ;;
        v6)
            vp_capture_run "$network_failure_output" "$network_failure_producer" \
                "$routes_empty" "$network_failure_input" || return 77
            ;;
        *) return 78 ;;
    esac
}

nexthop_shape_failure_gate() {
    [ "$#" -eq 2 ] || return 78
    nexthop_failure_label=$1
    nexthop_failure_input=$2
    nexthop_shape_output=$temporary_directory/nexthop-$nexthop_failure_label.normalized
    vp_capture_normalize "$nexthop_failure_input" "$nexthop_shape_output" \
        nexthop_state_producer || return 77
}

single_state_shape_failure_gate() {
    [ "$#" -eq 3 ] || return 78
    single_failure_producer=$1
    single_failure_label=$2
    single_failure_input=$3
    single_failure_output=$temporary_directory/$single_failure_producer-$single_failure_label.normalized
    vp_capture_normalize "$single_failure_input" "$single_failure_output" \
        "$single_failure_producer" || return 77
}

quiet_jq_sort_failure_gate() {
    quiet_sort_output=$temporary_directory/quiet-jq-sort.normalized
    vp_capture_normalize "$network_object" "$quiet_sort_output" \
        quiet_jq -c 'sort' || return 77
}

network_null=$temporary_directory/network-null.raw
network_object=$temporary_directory/network-object.raw
network_extra=$temporary_directory/network-extra.raw
network_nonobject=$temporary_directory/network-nonobject.raw
network_privacy_sentinel=volparossa-private-route-sentinel.invalid
printf '%s\n' 'null' >"$network_null"
printf '%s\n' \
    '{"family":"inet","dst":"volparossa-private-route-sentinel.invalid","flags":["onlink"]}' \
    >"$network_object"
printf '%s\n%s\n' '[]' '[]' >"$network_extra"
printf '%s\n' '[null]' >"$network_nonobject"
expect_status 77 quiet_jq_sort_failure_gate
if [ -s "$last_stdout" ] || [ -s "$last_stderr" ] \
    || grep -F "$network_privacy_sentinel" \
        "$last_stdout" "$last_stderr" >/dev/null; then
    printf '%s\n' 'quiet jq exposed data-dependent sort diagnostics' >&2
    exit 1
fi
if [ -e "$temporary_directory/quiet-jq-sort.normalized" ]; then
    printf '%s\n' 'failed quiet jq sort left partial normalized state' >&2
    exit 1
fi
for single_failure_producer in \
    link_state_producer address_state_producer qdisc_state_producer nftables_state_producer
do
    for single_failure_label in null object extra nonobject; do
        case $single_failure_label in
            null) single_failure_input=$network_null ;;
            object) single_failure_input=$network_object ;;
            extra) single_failure_input=$network_extra ;;
            nonobject) single_failure_input=$network_nonobject ;;
        esac
        expect_status 77 single_state_shape_failure_gate \
            "$single_failure_producer" "$single_failure_label" "$single_failure_input"
        if [ -s "$last_stdout" ] || [ -s "$last_stderr" ] \
            || grep -F "$network_privacy_sentinel" \
                "$last_stdout" "$last_stderr" >/dev/null; then
            printf 'invalid %s %s input escaped parser diagnostics\n' \
                "$single_failure_producer" "$single_failure_label" >&2
            exit 1
        fi
        single_failure_output=$temporary_directory/$single_failure_producer-$single_failure_label.normalized
        if [ -e "$single_failure_output" ]; then
            printf 'invalid %s %s input left normalized capture state\n' \
                "$single_failure_producer" "$single_failure_label" >&2
            exit 1
        fi
    done
done
for network_failure_producer in route_state_producer rule_state_producer; do
    for network_failure_family in v4 v6; do
        for network_failure_label in null object extra nonobject; do
            case $network_failure_label in
                null) network_failure_input=$network_null ;;
                object) network_failure_input=$network_object ;;
                extra) network_failure_input=$network_extra ;;
                nonobject) network_failure_input=$network_nonobject ;;
            esac
            expect_status 77 two_family_shape_failure_gate \
                "$network_failure_producer" "$network_failure_family" \
                "$network_failure_label" "$network_failure_input"
            if [ -s "$last_stdout" ] || [ -s "$last_stderr" ] \
                || grep -F "$network_privacy_sentinel" \
                    "$last_stdout" "$last_stderr" >/dev/null; then
                printf 'invalid %s %s %s input escaped parser diagnostics\n' \
                    "$network_failure_producer" "$network_failure_family" \
                    "$network_failure_label" >&2
                exit 1
            fi
            network_failure_output=$temporary_directory/$network_failure_producer-$network_failure_family-$network_failure_label.normalized
            if [ -e "$network_failure_output" ]; then
                printf 'invalid %s %s %s input left normalized capture state\n' \
                    "$network_failure_producer" "$network_failure_family" \
                    "$network_failure_label" >&2
                exit 1
            fi
        done
    done
done
family_null=$temporary_directory/family-null.raw
family_nonstring=$temporary_directory/family-nonstring.raw
family_conflict_v4=$temporary_directory/family-conflict-v4.raw
family_conflict_v6=$temporary_directory/family-conflict-v6.raw
printf '%s\n' '[{"family":null}]' >"$family_null"
printf '%s\n' '[{"family":7}]' >"$family_nonstring"
printf '%s\n' '[{"family":"inet6"}]' >"$family_conflict_v4"
printf '%s\n' '[{"family":"inet"}]' >"$family_conflict_v6"
for network_failure_producer in route_state_producer rule_state_producer; do
    for network_failure_family in v4 v6; do
        for family_failure_label in null nonstring conflict; do
            case $family_failure_label in
                null) family_failure_input=$family_null ;;
                nonstring) family_failure_input=$family_nonstring ;;
                conflict)
                    if [ "$network_failure_family" = v4 ]; then
                        family_failure_input=$family_conflict_v4
                    else
                        family_failure_input=$family_conflict_v6
                    fi
                    ;;
            esac
            network_failure_label=family-$family_failure_label
            expect_status 77 two_family_shape_failure_gate \
                "$network_failure_producer" "$network_failure_family" \
                "$network_failure_label" "$family_failure_input"
            if [ -s "$last_stdout" ] || [ -s "$last_stderr" ]; then
                printf 'invalid %s %s family %s escaped parser diagnostics\n' \
                    "$network_failure_producer" "$network_failure_family" \
                    "$family_failure_label" >&2
                exit 1
            fi
            network_failure_output=$temporary_directory/$network_failure_producer-$network_failure_family-$network_failure_label.normalized
            if [ -e "$network_failure_output" ]; then
                printf 'invalid %s %s family %s left normalized capture state\n' \
                    "$network_failure_producer" "$network_failure_family" \
                    "$family_failure_label" >&2
                exit 1
            fi
        done
    done
done

flags_null=$temporary_directory/flags-null.raw
flags_scalar=$temporary_directory/flags-scalar.raw
flags_nonstring=$temporary_directory/flags-nonstring.raw
printf '%s\n' '[{"flags":null}]' >"$flags_null"
printf '%s\n' '[{"flags":"onlink"}]' >"$flags_scalar"
printf '%s\n' '[{"flags":["onlink",7]}]' >"$flags_nonstring"
for flags_failure_label in null scalar nonstring; do
    case $flags_failure_label in
        null) flags_failure_input=$flags_null ;;
        scalar) flags_failure_input=$flags_scalar ;;
        nonstring) flags_failure_input=$flags_nonstring ;;
    esac
    single_failure_label=flags-$flags_failure_label
    expect_status 77 single_state_shape_failure_gate \
        link_state_producer "$single_failure_label" "$flags_failure_input"
    if [ -s "$last_stdout" ] || [ -s "$last_stderr" ]; then
        printf 'invalid link flags %s escaped parser diagnostics\n' \
            "$flags_failure_label" >&2
        exit 1
    fi
    if [ -e "$temporary_directory/link_state_producer-$single_failure_label.normalized" ]; then
        printf 'invalid link flags %s left normalized capture state\n' \
            "$flags_failure_label" >&2
        exit 1
    fi
done

altnames_null=$temporary_directory/altnames-null.raw
altnames_scalar=$temporary_directory/altnames-scalar.raw
altnames_nonstring=$temporary_directory/altnames-nonstring.raw
printf '%s\n' '[{"altnames":null}]' >"$altnames_null"
printf '%s\n' '[{"altnames":"wg-alt"}]' >"$altnames_scalar"
printf '%s\n' '[{"altnames":["wg-alt",7]}]' >"$altnames_nonstring"
for altnames_failure_label in null scalar nonstring; do
    case $altnames_failure_label in
        null) altnames_failure_input=$altnames_null ;;
        scalar) altnames_failure_input=$altnames_scalar ;;
        nonstring) altnames_failure_input=$altnames_nonstring ;;
    esac
    single_failure_label=altnames-$altnames_failure_label
    expect_status 77 single_state_shape_failure_gate \
        link_state_producer "$single_failure_label" "$altnames_failure_input"
    if [ -s "$last_stdout" ] || [ -s "$last_stderr" ]; then
        printf 'invalid link altnames %s escaped parser diagnostics\n' \
            "$altnames_failure_label" >&2
        exit 1
    fi
    if [ -e "$temporary_directory/link_state_producer-$single_failure_label.normalized" ]; then
        printf 'invalid link altnames %s left normalized capture state\n' \
            "$altnames_failure_label" >&2
        exit 1
    fi
done

addr_info_null=$temporary_directory/addr-info-null.raw
addr_info_scalar=$temporary_directory/addr-info-scalar.raw
addr_info_nonobject=$temporary_directory/addr-info-nonobject.raw
printf '%s\n' '[{"addr_info":null}]' >"$addr_info_null"
printf '%s\n' '[{"addr_info":"address"}]' >"$addr_info_scalar"
printf '%s\n' '[{"addr_info":[null]}]' >"$addr_info_nonobject"
for addr_info_failure_label in null scalar nonobject; do
    case $addr_info_failure_label in
        null) addr_info_failure_input=$addr_info_null ;;
        scalar) addr_info_failure_input=$addr_info_scalar ;;
        nonobject) addr_info_failure_input=$addr_info_nonobject ;;
    esac
    single_failure_label=addr-info-$addr_info_failure_label
    expect_status 77 single_state_shape_failure_gate \
        address_state_producer "$single_failure_label" "$addr_info_failure_input"
    if [ -s "$last_stdout" ] || [ -s "$last_stderr" ]; then
        printf 'invalid addr_info %s escaped parser diagnostics\n' \
            "$addr_info_failure_label" >&2
        exit 1
    fi
    if [ -e "$temporary_directory/address_state_producer-$single_failure_label.normalized" ]; then
        printf 'invalid addr_info %s left normalized capture state\n' \
            "$addr_info_failure_label" >&2
        exit 1
    fi
done

nftables_null=$temporary_directory/nftables-null.raw
nftables_scalar=$temporary_directory/nftables-scalar.raw
nftables_nonobject=$temporary_directory/nftables-nonobject.raw
printf '%s\n' '{"nftables":null}' >"$nftables_null"
printf '%s\n' '{"nftables":"rules"}' >"$nftables_scalar"
printf '%s\n' '{"nftables":[null]}' >"$nftables_nonobject"
for nftables_failure_label in null scalar nonobject; do
    case $nftables_failure_label in
        null) nftables_failure_input=$nftables_null ;;
        scalar) nftables_failure_input=$nftables_scalar ;;
        nonobject) nftables_failure_input=$nftables_nonobject ;;
    esac
    single_failure_label=nftables-$nftables_failure_label
    expect_status 77 single_state_shape_failure_gate \
        nftables_state_producer "$single_failure_label" "$nftables_failure_input"
    if [ -s "$last_stdout" ] || [ -s "$last_stderr" ]; then
        printf 'invalid nftables %s escaped parser diagnostics\n' \
            "$nftables_failure_label" >&2
        exit 1
    fi
    if [ -e "$temporary_directory/nftables_state_producer-$single_failure_label.normalized" ]; then
        printf 'invalid nftables %s left normalized capture state\n' \
            "$nftables_failure_label" >&2
        exit 1
    fi
done
for network_failure_family in v4 v6; do
    for flags_failure_label in null scalar nonstring; do
        case $flags_failure_label in
            null) flags_failure_input=$flags_null ;;
            scalar) flags_failure_input=$flags_scalar ;;
            nonstring) flags_failure_input=$flags_nonstring ;;
        esac
        network_failure_label=flags-$flags_failure_label
        expect_status 77 two_family_shape_failure_gate \
            route_state_producer "$network_failure_family" \
            "$network_failure_label" "$flags_failure_input"
        if [ -s "$last_stdout" ] || [ -s "$last_stderr" ]; then
            printf 'invalid route %s flags %s escaped parser diagnostics\n' \
                "$network_failure_family" "$flags_failure_label" >&2
            exit 1
        fi
        network_failure_output=$temporary_directory/route_state_producer-$network_failure_family-$network_failure_label.normalized
        if [ -e "$network_failure_output" ]; then
            printf 'invalid route %s flags %s left normalized capture state\n' \
                "$network_failure_family" "$flags_failure_label" >&2
            exit 1
        fi
    done
done
for nexthop_failure_label in null object extra nonobject; do
    case $nexthop_failure_label in
        null) nexthop_failure_input=$network_null ;;
        object) nexthop_failure_input=$network_object ;;
        extra) nexthop_failure_input=$network_extra ;;
        nonobject) nexthop_failure_input=$network_nonobject ;;
    esac
    expect_status 77 nexthop_shape_failure_gate \
        "$nexthop_failure_label" "$nexthop_failure_input"
    if [ -s "$last_stdout" ] || [ -s "$last_stderr" ] \
        || grep -F "$network_privacy_sentinel" \
            "$last_stdout" "$last_stderr" >/dev/null; then
        printf 'invalid nexthop %s input escaped parser diagnostics\n' \
            "$nexthop_failure_label" >&2
        exit 1
    fi
    if [ -e "$temporary_directory/nexthop-$nexthop_failure_label.normalized" ]; then
        printf 'invalid nexthop %s input left normalized capture state\n' \
            "$nexthop_failure_label" >&2
        exit 1
    fi
done
for flags_failure_label in null scalar nonstring; do
    case $flags_failure_label in
        null) flags_failure_input=$flags_null ;;
        scalar) flags_failure_input=$flags_scalar ;;
        nonstring) flags_failure_input=$flags_nonstring ;;
    esac
    nexthop_failure_label=flags-$flags_failure_label
    expect_status 77 nexthop_shape_failure_gate \
        "$nexthop_failure_label" "$flags_failure_input"
    if [ -s "$last_stdout" ] || [ -s "$last_stderr" ]; then
        printf 'invalid nexthop flags %s escaped parser diagnostics\n' \
            "$flags_failure_label" >&2
        exit 1
    fi
    if [ -e "$temporary_directory/nexthop-$nexthop_failure_label.normalized" ]; then
        printf 'invalid nexthop flags %s left normalized capture state\n' \
            "$flags_failure_label" >&2
        exit 1
    fi
done
if link_state_producer unexpected >/dev/null 2>&1 \
    || address_state_producer unexpected >/dev/null 2>&1 \
    || route_state_producer "$routes_first" >/dev/null 2>&1 \
    || rule_state_producer "$rules_v4" >/dev/null 2>&1 \
    || nexthop_state_producer unexpected >/dev/null 2>&1 \
    || qdisc_state_producer unexpected >/dev/null 2>&1 \
    || nftables_state_producer unexpected >/dev/null 2>&1; then
    printf '%s\n' 'network-state normalizer accepted an invalid arity' >&2
    exit 1
fi

# Exercise the gate's real legacy-xtables inventory, producer, normalizer,
# join, and stable-capture functions.  Every executable below is a private
# fixture; this test never invokes a host firewall frontend.
legacy_firewall_functions=$temporary_directory/legacy-firewall-functions.sh
{
    sed -n '/^legacy_firewall_inventory_producer() {$/,/^}$/p' "$gate"
    sed -n '/^legacy_firewall_save_producer() {$/,/^}$/p' "$gate"
    sed -n '/^legacy_firewall_save_normalizer() {$/,/^}$/p' "$gate"
    sed -n '/^legacy_firewall_join_producer() {$/,/^}$/p' "$gate"
    sed -n '/^capture_stable_legacy_firewall_state() ($/,/^)$/p' "$gate"
} >"$legacy_firewall_functions"
for legacy_function in \
    legacy_firewall_inventory_producer \
    legacy_firewall_save_producer \
    legacy_firewall_save_normalizer \
    legacy_firewall_join_producer
do
    if [ "$(grep -c "^$legacy_function() {$" "$legacy_firewall_functions")" -ne 1 ]; then
        printf 'legacy firewall function cannot be isolated: %s\n' \
            "$legacy_function" >&2
        exit 1
    fi
done
if [ "$(grep -c '^capture_stable_legacy_firewall_state() ($' \
        "$legacy_firewall_functions")" -ne 1 ]; then
    printf '%s\n' 'stable legacy firewall capture cannot be isolated' >&2
    exit 1
fi
sh -n "$legacy_firewall_functions"

# Keep the production authority and observation order pinned independently of
# the fixture-driven tests below.  In particular, Debian's mutable generic
# alternatives must never enter this gate: iptables-nft is already represented
# by the nft JSON bookends.
legacy_host_capture_function=$temporary_directory/legacy-host-capture-function.sh
sed -n '/^capture_host_state() {$/,/^}$/p' "$gate" \
    >"$legacy_host_capture_function"
# These are literal gate-source fragments; the trailing backslashes and
# dollar-prefixed names must not be interpreted by this test shell.
# shellcheck disable=SC1003,SC2016
if [ "$(grep -c '^capture_host_state() {$' \
        "$legacy_host_capture_function")" -ne 1 ] \
    || grep -Eq '(^|[[:space:]])(iptables-save|ip6tables-save)([[:space:]\\]|$)' \
        "$legacy_host_capture_function" \
    || [ "$(grep -Fc \
        'capture_stable_legacy_firewall_state ipv4 /proc/self/net/ip_tables_names \' \
        "$legacy_host_capture_function")" -ne 1 ] \
    || [ "$(grep -Fc '0 0 440 /usr/sbin/iptables-legacy-save \' \
        "$legacy_host_capture_function")" -ne 1 ] \
    || [ "$(grep -Fc \
        'capture_stable_legacy_firewall_state ipv6 /proc/self/net/ip6_tables_names \' \
        "$legacy_host_capture_function")" -ne 1 ] \
    || [ "$(grep -Fc '0 0 440 /usr/sbin/ip6tables-legacy-save \' \
        "$legacy_host_capture_function")" -ne 1 ]; then
    printf '%s\n' 'legacy firewall production authority is not exact' >&2
    exit 1
fi
# These are also literal extracted-function fragments.
# shellcheck disable=SC1003,SC2016
if [ "$(grep -Fc \
        'vp_capture_run "$legacy_inventory_a" legacy_firewall_inventory_producer \' \
        "$legacy_firewall_functions")" -ne 1 ] \
    || [ "$(grep -Fc \
        'vp_capture_run "$legacy_inventory_b" legacy_firewall_inventory_producer \' \
        "$legacy_firewall_functions")" -ne 1 ] \
    || [ "$(grep -Fc \
        'vp_capture_run "$legacy_raw_a" legacy_firewall_save_producer \' \
        "$legacy_firewall_functions")" -ne 1 ] \
    || [ "$(grep -Fc \
        'vp_capture_run "$legacy_raw_b" legacy_firewall_save_producer \' \
        "$legacy_firewall_functions")" -ne 1 ] \
    || [ "$(grep -Fc \
        'if "$legacy_save_tool" -M /bin/false 2>/dev/null; then' \
        "$legacy_firewall_functions")" -ne 1 ] \
    || [ "$(grep -Fc 'legacy_save_target_digest_before=$(vp_capture_sha256_file \' \
        "$legacy_firewall_functions")" -ne 1 ] \
    || [ "$(grep -Fc 'legacy_save_target_digest_after=$(vp_capture_sha256_file \' \
        "$legacy_firewall_functions")" -ne 1 ]; then
    printf '%s\n' 'legacy firewall bookends or exact producer command changed' >&2
    exit 1
fi
if ! awk '
    /nftables-a\.raw" nft --json list ruleset/ {
        if (++nft_a != 1) exit 1
        nft_a_line = NR
        nft_a_stderr_pending = 1
        next
    }
    nft_a_stderr_pending {
        if ($0 != "        2>/dev/null " "\\") exit 1
        nft_a_stderr++
        nft_a_stderr_pending = 0
        next
    }
    /capture_stable_legacy_firewall_state ipv4 \/proc\/self\/net\/ip_tables_names/ {
        if (++legacy_v4 != 1) exit 1
        legacy_v4_line = NR
    }
    /capture_stable_legacy_firewall_state ipv6 \/proc\/self\/net\/ip6_tables_names/ {
        if (++legacy_v6 != 1) exit 1
        legacy_v6_line = NR
    }
    /nftables-b\.raw" nft --json list ruleset/ {
        if (++nft_b != 1) exit 1
        nft_b_line = NR
        nft_b_stderr_pending = 1
        next
    }
    nft_b_stderr_pending {
        if ($0 != "        2>/dev/null " "\\") exit 1
        nft_b_stderr++
        nft_b_stderr_pending = 0
        next
    }
    /cmp -s "\$capture_directory\/nftables-a\.normalized"/ {
        if (++nft_cmp != 1) exit 1
        nft_cmp_line = NR
    }
    /vp_capture_publish_digest "\$capture_directory\/nftables-a\.normalized"/ {
        if (++publish_nft != 1) exit 1
        publish_nft_line = NR
    }
    /vp_capture_publish_digest "\$capture_directory\/legacy-ipv4\.stable"/ {
        if (++publish_v4 != 1) exit 1
        publish_v4_line = NR
    }
    /vp_capture_publish_digest "\$capture_directory\/legacy-ipv6\.stable"/ {
        if (++publish_v6 != 1) exit 1
        publish_v6_line = NR
    }
    END {
        if (nft_a != 1 || nft_a_stderr != 1 || nft_a_stderr_pending ||
            legacy_v4 != 1 || legacy_v6 != 1 || nft_b != 1 ||
            nft_b_stderr != 1 || nft_b_stderr_pending ||
            nft_cmp != 1 || publish_nft != 1 || publish_v4 != 1 ||
            publish_v6 != 1 ||
            !(nft_a_line < legacy_v4_line &&
                legacy_v4_line < legacy_v6_line &&
                legacy_v6_line < nft_b_line &&
                nft_b_line < nft_cmp_line &&
                nft_cmp_line < publish_nft_line &&
                publish_nft_line < publish_v4_line &&
                publish_v4_line < publish_v6_line)) exit 1
    }
' "$legacy_host_capture_function"; then
    printf '%s\n' 'legacy firewall state is not enclosed by unpublished nft bookends' >&2
    exit 1
fi
# The function path is generated from the reviewed gate above.
# shellcheck disable=SC1090
. "$legacy_firewall_functions"

legacy_fixture_uid=$(id -u)
legacy_fixture_gid=$(id -g)
legacy_fixture_mode=600
legacy_absent_inventory=$temporary_directory/legacy-absent.inventory
legacy_empty_inventory=$temporary_directory/legacy-empty.inventory
legacy_present_inventory=$temporary_directory/legacy-present.inventory
: >"$legacy_empty_inventory"
printf '%s\n' filter >"$legacy_present_inventory"
chmod 0600 "$legacy_empty_inventory" "$legacy_present_inventory"

legacy_inventory_absent_capture=$temporary_directory/legacy-inventory-absent.capture
legacy_inventory_empty_capture=$temporary_directory/legacy-inventory-empty.capture
legacy_inventory_present_capture=$temporary_directory/legacy-inventory-present.capture
vp_capture_run "$legacy_inventory_absent_capture" legacy_firewall_inventory_producer \
    "$legacy_absent_inventory" "$legacy_fixture_uid" "$legacy_fixture_gid" \
    "$legacy_fixture_mode"
vp_capture_run "$legacy_inventory_empty_capture" legacy_firewall_inventory_producer \
    "$legacy_empty_inventory" "$legacy_fixture_uid" "$legacy_fixture_gid" \
    "$legacy_fixture_mode"
vp_capture_run "$legacy_inventory_present_capture" legacy_firewall_inventory_producer \
    "$legacy_present_inventory" "$legacy_fixture_uid" "$legacy_fixture_gid" \
    "$legacy_fixture_mode"
if [ "$(cat "$legacy_inventory_absent_capture")" != PROC_ABSENT ] \
    || [ "$(cat "$legacy_inventory_empty_capture")" != NO_TABLES ] \
    || [ "$(sed -n '1p' "$legacy_inventory_present_capture")" != PRESENT ] \
    || [ "$(sed -n '2p' "$legacy_inventory_present_capture")" != filter ] \
    || [ -n "$(sed -n '3p' "$legacy_inventory_present_capture")" ] \
    || cmp -s "$legacy_inventory_absent_capture" "$legacy_inventory_empty_capture" \
    || cmp -s "$legacy_inventory_empty_capture" "$legacy_inventory_present_capture"; then
    printf '%s\n' 'legacy proc absent, empty, and present states are not canonical and distinct' >&2
    exit 1
fi

legacy_inventory_failure_gate() {
    [ "$#" -eq 2 ] || return 78
    legacy_inventory_failure_label=$1
    legacy_inventory_failure_input=$2
    legacy_inventory_failure_output=$temporary_directory/legacy-inventory-$legacy_inventory_failure_label.capture
    vp_capture_run "$legacy_inventory_failure_output" \
        legacy_firewall_inventory_producer "$legacy_inventory_failure_input" \
        "$legacy_fixture_uid" "$legacy_fixture_gid" "$legacy_fixture_mode" \
        || return 77
}

legacy_inventory_duplicate=$temporary_directory/legacy-inventory-duplicate.raw
legacy_inventory_blank=$temporary_directory/legacy-inventory-blank.raw
legacy_inventory_invalid=$temporary_directory/legacy-inventory-invalid.raw
legacy_inventory_long=$temporary_directory/legacy-inventory-long.raw
legacy_inventory_many=$temporary_directory/legacy-inventory-many.raw
legacy_inventory_no_lf=$temporary_directory/legacy-inventory-no-lf.raw
legacy_inventory_wrong_mode=$temporary_directory/legacy-inventory-wrong-mode.raw
legacy_inventory_symlink=$temporary_directory/legacy-inventory-symlink.raw
printf '%s\n%s\n' filter filter >"$legacy_inventory_duplicate"
printf '\n' >"$legacy_inventory_blank"
printf '%s\n' 'filter table' >"$legacy_inventory_invalid"
printf '%s\n' 12345678901234567890123456789012 >"$legacy_inventory_long"
awk 'BEGIN { for (i = 1; i <= 65; i++) print "table" i }' >"$legacy_inventory_many"
printf '%s' filter >"$legacy_inventory_no_lf"
printf '%s\n' filter >"$legacy_inventory_wrong_mode"
chmod 0644 "$legacy_inventory_wrong_mode"
ln -s -- "$legacy_present_inventory" "$legacy_inventory_symlink"
for legacy_inventory_failure_label in \
    duplicate blank invalid long many no-lf wrong-mode symlink
do
    case $legacy_inventory_failure_label in
        duplicate) legacy_inventory_failure_input=$legacy_inventory_duplicate ;;
        blank) legacy_inventory_failure_input=$legacy_inventory_blank ;;
        invalid) legacy_inventory_failure_input=$legacy_inventory_invalid ;;
        long) legacy_inventory_failure_input=$legacy_inventory_long ;;
        many) legacy_inventory_failure_input=$legacy_inventory_many ;;
        no-lf) legacy_inventory_failure_input=$legacy_inventory_no_lf ;;
        wrong-mode) legacy_inventory_failure_input=$legacy_inventory_wrong_mode ;;
        symlink) legacy_inventory_failure_input=$legacy_inventory_symlink ;;
    esac
    expect_status 77 legacy_inventory_failure_gate \
        "$legacy_inventory_failure_label" "$legacy_inventory_failure_input"
    legacy_inventory_failure_output=$temporary_directory/legacy-inventory-$legacy_inventory_failure_label.capture
    if [ -s "$last_stdout" ] || [ -s "$last_stderr" ] \
        || [ -e "$legacy_inventory_failure_output" ] \
        || [ -L "$legacy_inventory_failure_output" ]; then
        printf 'invalid legacy inventory escaped diagnostics or partial state: %s\n' \
            "$legacy_inventory_failure_label" >&2
        exit 1
    fi
done

legacy_fake_tool=$temporary_directory/legacy-firewall-save-fixture
# The single quotes intentionally defer fixture variables to the generated
# executable rather than expanding them in this contract-test process.
# shellcheck disable=SC2016
printf '%s\n' \
    '#!/bin/sh' \
    'set -eu' \
    '[ "$#" -eq 2 ] && [ "$1" = -M ] && [ "$2" = /bin/false ] || exit 91' \
    'if [ -n "${VP_LEGACY_FIXTURE_LOG:-}" ]; then' \
    '    printf "%s|%s\n" "$1" "$2" >>"$VP_LEGACY_FIXTURE_LOG"' \
    'fi' \
    'fixture_count=0' \
    'if [ -n "${VP_LEGACY_FIXTURE_COUNT:-}" ] && [ -f "$VP_LEGACY_FIXTURE_COUNT" ]; then' \
    '    fixture_count=$(cat "$VP_LEGACY_FIXTURE_COUNT")' \
    'fi' \
    'fixture_count=$((fixture_count + 1))' \
    'if [ -n "${VP_LEGACY_FIXTURE_COUNT:-}" ]; then' \
    '    printf "%s\n" "$fixture_count" >"$VP_LEGACY_FIXTURE_COUNT"' \
    'fi' \
    'case ${VP_LEGACY_FIXTURE_MODE:-stable-v4} in' \
    '    must-not-run)' \
    '        printf "%s\n" legacy-tool-was-invoked >&2' \
    '        exit 92' \
    '        ;;' \
    '    fail)' \
    '        printf "%s\n" volparossa-private-firewall-stdout.invalid' \
    '        printf "%s\n" volparossa-private-firewall-stderr.invalid >&2' \
    '        exit 19' \
    '        ;;' \
    '    malformed)' \
    '        printf "%s\n" volparossa-private-firewall-parser.invalid' \
    '        ;;' \
    '    inventory-drift)' \
    '        if [ "$fixture_count" -eq 1 ]; then' \
    '            printf "%s\n" nat >"$VP_LEGACY_FIXTURE_INVENTORY"' \
    '        fi' \
    '        printf "%s\n" "# Generated by iptables-save v1.8.11 on Thu Aug 28 00:00:0${fixture_count} 2026"' \
    '        printf "%s\n" "*filter" ":INPUT ACCEPT [$fixture_count:$fixture_count]" "COMMIT"' \
    '        printf "%s\n" "# Completed on Thu Aug 28 00:00:0${fixture_count} 2026"' \
    '        ;;' \
    '    save-drift)' \
    '        printf "%s\n" "# Generated by iptables-save v1.8.11 on Thu Aug 28 00:00:0${fixture_count} 2026"' \
    '        printf "%s\n" "*filter" ":INPUT ACCEPT [$fixture_count:$fixture_count]"' \
    '        if [ "$fixture_count" -eq 1 ]; then' \
    '            printf "%s\n" "-A INPUT -j ACCEPT"' \
    '        else' \
    '            printf "%s\n" "-A INPUT -j DROP"' \
    '        fi' \
    '        printf "%s\n" "COMMIT"' \
    '        printf "%s\n" "# Completed on Thu Aug 28 00:00:0${fixture_count} 2026"' \
    '        ;;' \
    '    stable-v4)' \
    '        printf "%s\n" "# Generated by iptables-save v1.8.11 on Thu Aug 28 00:00:0${fixture_count} 2026"' \
    '        printf "%s\n" "*filter" ":INPUT ACCEPT [$fixture_count:$fixture_count]"' \
    '        printf "%s\n" "-A INPUT -m comment --comment \"semantic [1:2]\" -j ACCEPT"' \
    '        printf "%s\n" "COMMIT"' \
    '        printf "%s\n" "# Completed on Thu Aug 28 00:00:0${fixture_count} 2026"' \
    '        ;;' \
    '    stable-v6)' \
    '        printf "%s\n" "# Generated by ip6tables-save v1.8.11 on Thu Aug 28 00:00:0${fixture_count} 2026"' \
    '        printf "%s\n" "*filter" ":INPUT ACCEPT [$fixture_count:$fixture_count]" "COMMIT"' \
    '        printf "%s\n" "# Completed on Thu Aug 28 00:00:0${fixture_count} 2026"' \
    '        ;;' \
    '    *) exit 93 ;;' \
    'esac' \
    >"$legacy_fake_tool"
chmod 0700 "$legacy_fake_tool"

legacy_raw_first=$temporary_directory/legacy-raw-first.capture
legacy_raw_second=$temporary_directory/legacy-raw-second.capture
legacy_normalized_first=$temporary_directory/legacy-normalized-first.capture
legacy_normalized_second=$temporary_directory/legacy-normalized-second.capture
legacy_fixture_count=$temporary_directory/legacy-normalizer.count
legacy_fixture_log=$temporary_directory/legacy-normalizer.log
VP_LEGACY_FIXTURE_MODE=stable-v4
VP_LEGACY_FIXTURE_COUNT=$legacy_fixture_count
VP_LEGACY_FIXTURE_LOG=$legacy_fixture_log
export VP_LEGACY_FIXTURE_MODE VP_LEGACY_FIXTURE_COUNT VP_LEGACY_FIXTURE_LOG
vp_capture_run "$legacy_raw_first" legacy_firewall_save_producer "$legacy_fake_tool"
vp_capture_run "$legacy_raw_second" legacy_firewall_save_producer "$legacy_fake_tool"
vp_capture_normalize "$legacy_raw_first" "$legacy_normalized_first" \
    legacy_firewall_save_normalizer ipv4
vp_capture_normalize "$legacy_raw_second" "$legacy_normalized_second" \
    legacy_firewall_save_normalizer ipv4
if ! cmp -s "$legacy_normalized_first" "$legacy_normalized_second" \
    || ! grep -Fx ':INPUT ACCEPT [COUNTERS]' "$legacy_normalized_first" >/dev/null \
    || ! grep -Fx -- \
        '-A INPUT -m comment --comment "semantic [1:2]" -j ACCEPT' \
        "$legacy_normalized_first" >/dev/null \
    || [ "$(grep -Fc -- '-M|/bin/false' "$legacy_fixture_log")" -ne 2 ]; then
    printf '%s\n' 'legacy timestamp/counter normalization changed rule semantics or tool arguments' >&2
    exit 1
fi

legacy_normalizer_failure_gate() {
    [ "$#" -eq 3 ] || return 78
    legacy_normalizer_failure_label=$1
    legacy_normalizer_failure_family=$2
    legacy_normalizer_failure_input=$3
    legacy_normalizer_failure_output=$temporary_directory/legacy-normalizer-$legacy_normalizer_failure_label.capture
    vp_capture_normalize "$legacy_normalizer_failure_input" \
        "$legacy_normalizer_failure_output" legacy_firewall_save_normalizer \
        "$legacy_normalizer_failure_family" || return 77
}

legacy_bad_timestamp=$temporary_directory/legacy-bad-timestamp.raw
legacy_wrong_family=$temporary_directory/legacy-wrong-family.raw
legacy_bad_counter=$temporary_directory/legacy-bad-counter.raw
legacy_extra_comment=$temporary_directory/legacy-extra-comment.raw
printf '%s\n' \
    '# Generated by iptables-save v1.8.11 on volparossa-private-firewall-timestamp.invalid' \
    '*filter' ':INPUT ACCEPT [0:0]' 'COMMIT' \
    '# Completed on Thu Aug 28 00:00:00 2026' >"$legacy_bad_timestamp"
printf '%s\n' \
    '# Generated by iptables-save v1.8.11 on Thu Aug 28 00:00:00 2026' \
    '*filter' ':INPUT ACCEPT [0:0]' 'COMMIT' \
    '# Completed on Thu Aug 28 00:00:00 2026' >"$legacy_wrong_family"
printf '%s\n' \
    '# Generated by iptables-save v1.8.11 on Thu Aug 28 00:00:00 2026' \
    '*filter' ':INPUT ACCEPT [not:a-counter]' 'COMMIT' \
    '# Completed on Thu Aug 28 00:00:00 2026' >"$legacy_bad_counter"
printf '%s\n' \
    '# Generated by iptables-save v1.8.11 on Thu Aug 28 00:00:00 2026' \
    '*filter' '# volparossa-private-firewall-comment.invalid' 'COMMIT' \
    '# Completed on Thu Aug 28 00:00:00 2026' >"$legacy_extra_comment"
for legacy_normalizer_failure_label in bad-timestamp wrong-family bad-counter extra-comment; do
    case $legacy_normalizer_failure_label in
        bad-timestamp)
            legacy_normalizer_failure_family=ipv4
            legacy_normalizer_failure_input=$legacy_bad_timestamp
            ;;
        wrong-family)
            legacy_normalizer_failure_family=ipv6
            legacy_normalizer_failure_input=$legacy_wrong_family
            ;;
        bad-counter)
            legacy_normalizer_failure_family=ipv4
            legacy_normalizer_failure_input=$legacy_bad_counter
            ;;
        extra-comment)
            legacy_normalizer_failure_family=ipv4
            legacy_normalizer_failure_input=$legacy_extra_comment
            ;;
    esac
    expect_status 77 legacy_normalizer_failure_gate \
        "$legacy_normalizer_failure_label" "$legacy_normalizer_failure_family" \
        "$legacy_normalizer_failure_input"
    legacy_normalizer_failure_output=$temporary_directory/legacy-normalizer-$legacy_normalizer_failure_label.capture
    if [ -s "$last_stdout" ] || [ -s "$last_stderr" ] \
        || [ -e "$legacy_normalizer_failure_output" ]; then
        printf 'invalid legacy save escaped diagnostics or normalized output: %s\n' \
            "$legacy_normalizer_failure_label" >&2
        exit 1
    fi
done
if legacy_firewall_save_normalizer unexpected </dev/null >/dev/null 2>&1 \
    || legacy_firewall_save_producer relative/path >/dev/null 2>&1; then
    printf '%s\n' 'legacy save producer or normalizer accepted an invalid authority' >&2
    exit 1
fi

# Prove the join is an exact set comparison, not a count or concatenation
# shortcut.  Deliberately reverse the two valid table stanzas in the happy
# path, then reject missing, extra, and duplicate table identities without
# retaining producer output or leaking the private fixture marker.
legacy_join_inventory=$temporary_directory/legacy-join.inventory
legacy_join_raw=$temporary_directory/legacy-join.raw
legacy_join_normalized=$temporary_directory/legacy-join.normalized
legacy_join_output=$temporary_directory/legacy-join.output
legacy_join_expected=$temporary_directory/legacy-join.expected
printf '%s\n' PRESENT filter nat >"$legacy_join_inventory"
printf '%s\n' \
    '# Generated by iptables-save v1.8.11 on Thu Aug 28 00:00:00 2026' \
    '*nat' ':PREROUTING ACCEPT [1:2]' 'COMMIT' \
    '# Completed on Thu Aug 28 00:00:00 2026' \
    '# Generated by iptables-save v1.8.11 on Thu Aug 28 00:00:01 2026' \
    '*filter' ':INPUT ACCEPT [3:4]' 'COMMIT' \
    '# Completed on Thu Aug 28 00:00:01 2026' >"$legacy_join_raw"
vp_capture_normalize "$legacy_join_raw" "$legacy_join_normalized" \
    legacy_firewall_save_normalizer ipv4
vp_capture_run "$legacy_join_output" legacy_firewall_join_producer \
    "$legacy_join_inventory" "$legacy_join_normalized"
{
    printf '%s\n' PRESENT filter nat
    cat "$legacy_join_normalized"
} >"$legacy_join_expected"
if ! cmp -s "$legacy_join_expected" "$legacy_join_output"; then
    printf '%s\n' 'legacy multi-table exact-set join rejected canonical reordered tables' >&2
    exit 1
fi

legacy_join_failure_gate() {
    [ "$#" -eq 2 ] || return 78
    legacy_join_failure_label=$1
    legacy_join_failure_dump=$2
    legacy_join_failure_output=$temporary_directory/legacy-join-$legacy_join_failure_label.output
    vp_capture_run "$legacy_join_failure_output" legacy_firewall_join_producer \
        "$legacy_join_inventory" "$legacy_join_failure_dump" || return 77
}

legacy_join_missing=$temporary_directory/legacy-join-missing.normalized
legacy_join_extra=$temporary_directory/legacy-join-extra.normalized
legacy_join_duplicate=$temporary_directory/legacy-join-duplicate.normalized
printf '%s\n' '*filter' ':INPUT ACCEPT [COUNTERS]' 'COMMIT' \
    >"$legacy_join_missing"
printf '%s\n' \
    '*filter' ':INPUT ACCEPT [COUNTERS]' 'COMMIT' \
    '*nat' ':PREROUTING ACCEPT [COUNTERS]' 'COMMIT' \
    '*volparossa_private' ':PRIVATE ACCEPT [COUNTERS]' 'COMMIT' \
    >"$legacy_join_extra"
printf '%s\n' \
    '*filter' ':INPUT ACCEPT [COUNTERS]' 'COMMIT' \
    '*filter' ':OUTPUT ACCEPT [COUNTERS]' 'COMMIT' \
    '*nat' ':PREROUTING ACCEPT [COUNTERS]' 'COMMIT' \
    >"$legacy_join_duplicate"
for legacy_join_failure_label in missing extra duplicate; do
    case $legacy_join_failure_label in
        missing) legacy_join_failure_dump=$legacy_join_missing ;;
        extra) legacy_join_failure_dump=$legacy_join_extra ;;
        duplicate) legacy_join_failure_dump=$legacy_join_duplicate ;;
    esac
    expect_status 77 legacy_join_failure_gate "$legacy_join_failure_label" \
        "$legacy_join_failure_dump"
    legacy_join_failure_output=$temporary_directory/legacy-join-$legacy_join_failure_label.output
    if [ -s "$last_stdout" ] || [ -s "$last_stderr" ] \
        || grep -F 'volparossa_private' "$last_stdout" "$last_stderr" >/dev/null \
        || [ -e "$legacy_join_failure_output" ] \
        || [ -L "$legacy_join_failure_output" ]; then
        printf 'inexact legacy table set leaked diagnostics or partial output: %s\n' \
            "$legacy_join_failure_label" >&2
        exit 1
    fi
done

# A successful executable which changes only its own bytes during invocation
# must be rejected by the target-digest bookends.  Its metadata and command
# shape remain valid, so this is a behavioral check of digest timing rather
# than another authority predicate.
legacy_mutating_tool=$temporary_directory/legacy-firewall-save-mutating-fixture
legacy_mutating_marker=$temporary_directory/legacy-firewall-save-mutating.marker
legacy_mutating_output=$temporary_directory/legacy-firewall-save-mutating.output
# The single quotes intentionally defer fixture variables to the executable.
# shellcheck disable=SC2016
printf '%s\n' \
    '#!/bin/sh' \
    'set -eu' \
    '[ "$#" -eq 2 ] && [ "$1" = -M ] && [ "$2" = /bin/false ] || exit 91' \
    'printf "%s\n" "# self-mutation" >>"$0"' \
    'printf "%s\n" completed >"$VP_LEGACY_MUTATING_MARKER"' \
    'printf "%s\n" "# Generated by iptables-save v1.8.11 on Thu Aug 28 00:00:00 2026"' \
    'printf "%s\n" "*filter" ":INPUT ACCEPT [0:0]" "COMMIT"' \
    'printf "%s\n" "# Completed on Thu Aug 28 00:00:00 2026"' \
    >"$legacy_mutating_tool"
chmod 0700 "$legacy_mutating_tool"
VP_LEGACY_MUTATING_MARKER=$legacy_mutating_marker
export VP_LEGACY_MUTATING_MARKER
legacy_mutating_digest_before=$(vp_capture_sha256_file "$legacy_mutating_tool")

legacy_mutating_failure_gate() {
    vp_capture_run "$legacy_mutating_output" legacy_firewall_save_producer \
        "$legacy_mutating_tool" || return 77
}

expect_status 77 legacy_mutating_failure_gate
legacy_mutating_digest_after=$(vp_capture_sha256_file "$legacy_mutating_tool")
if [ "$legacy_mutating_digest_before" = "$legacy_mutating_digest_after" ] \
    || [ "$(cat "$legacy_mutating_marker")" != completed ] \
    || [ -s "$last_stdout" ] || [ -s "$last_stderr" ] \
    || [ -e "$legacy_mutating_output" ] || [ -L "$legacy_mutating_output" ]; then
    printf '%s\n' 'legacy executable digest drift was not rejected cleanly' >&2
    exit 1
fi

assert_legacy_capture_cleaned() {
    [ "$#" -eq 2 ] || return 1
    legacy_cleanup_prefix=$1
    legacy_cleanup_output=$2
    for legacy_cleanup_path in \
        "$legacy_cleanup_prefix.inventory-a" "$legacy_cleanup_prefix.inventory-b" \
        "$legacy_cleanup_prefix.raw-a" "$legacy_cleanup_prefix.raw-b" \
        "$legacy_cleanup_prefix.normalized-a" "$legacy_cleanup_prefix.normalized-b" \
        "$legacy_cleanup_output"
    do
        [ ! -e "$legacy_cleanup_path" ] && [ ! -L "$legacy_cleanup_path" ] \
            || return 1
    done
}

legacy_stable_failure_gate() {
    [ "$#" -eq 3 ] || return 78
    legacy_stable_failure_label=$1
    legacy_stable_failure_inventory=$2
    legacy_stable_failure_mode=$3
    legacy_stable_failure_prefix=$temporary_directory/legacy-stable-$legacy_stable_failure_label
    legacy_stable_failure_output=$temporary_directory/legacy-stable-$legacy_stable_failure_label.output
    legacy_stable_failure_count=$temporary_directory/legacy-stable-$legacy_stable_failure_label.count
    legacy_stable_failure_log=$temporary_directory/legacy-stable-$legacy_stable_failure_label.log
    VP_LEGACY_FIXTURE_MODE=$legacy_stable_failure_mode
    VP_LEGACY_FIXTURE_COUNT=$legacy_stable_failure_count
    VP_LEGACY_FIXTURE_LOG=$legacy_stable_failure_log
    VP_LEGACY_FIXTURE_INVENTORY=$legacy_stable_failure_inventory
    export VP_LEGACY_FIXTURE_MODE VP_LEGACY_FIXTURE_COUNT \
        VP_LEGACY_FIXTURE_LOG VP_LEGACY_FIXTURE_INVENTORY
    capture_stable_legacy_firewall_state ipv4 \
        "$legacy_stable_failure_inventory" "$legacy_fixture_uid" \
        "$legacy_fixture_gid" "$legacy_fixture_mode" "$legacy_fake_tool" \
        "$legacy_stable_failure_prefix" "$legacy_stable_failure_output" \
        || return 77
}

legacy_absent_prefix=$temporary_directory/legacy-stable-absent
legacy_absent_output=$temporary_directory/legacy-stable-absent.output
legacy_absent_count=$temporary_directory/legacy-stable-absent.count
legacy_absent_log=$temporary_directory/legacy-stable-absent.log
VP_LEGACY_FIXTURE_MODE=must-not-run
VP_LEGACY_FIXTURE_COUNT=$legacy_absent_count
VP_LEGACY_FIXTURE_LOG=$legacy_absent_log
export VP_LEGACY_FIXTURE_MODE VP_LEGACY_FIXTURE_COUNT VP_LEGACY_FIXTURE_LOG
capture_stable_legacy_firewall_state ipv4 "$legacy_absent_inventory" \
    "$legacy_fixture_uid" "$legacy_fixture_gid" "$legacy_fixture_mode" \
    "$legacy_fake_tool" "$legacy_absent_prefix" "$legacy_absent_output"
if [ "$(cat "$legacy_absent_output")" != PROC_ABSENT ] \
    || [ -e "$legacy_absent_count" ] || [ -e "$legacy_absent_log" ]; then
    printf '%s\n' 'proc-absent legacy state invoked a firewall frontend or joined incorrectly' >&2
    exit 1
fi

legacy_empty_prefix=$temporary_directory/legacy-stable-empty
legacy_empty_output=$temporary_directory/legacy-stable-empty.output
legacy_empty_count=$temporary_directory/legacy-stable-empty.count
legacy_empty_log=$temporary_directory/legacy-stable-empty.log
VP_LEGACY_FIXTURE_MODE=must-not-run
VP_LEGACY_FIXTURE_COUNT=$legacy_empty_count
VP_LEGACY_FIXTURE_LOG=$legacy_empty_log
export VP_LEGACY_FIXTURE_MODE VP_LEGACY_FIXTURE_COUNT VP_LEGACY_FIXTURE_LOG
capture_stable_legacy_firewall_state ipv4 "$legacy_empty_inventory" \
    "$legacy_fixture_uid" "$legacy_fixture_gid" "$legacy_fixture_mode" \
    "$legacy_fake_tool" "$legacy_empty_prefix" "$legacy_empty_output"
if [ "$(cat "$legacy_empty_output")" != NO_TABLES ] \
    || [ -e "$legacy_empty_count" ] || [ -e "$legacy_empty_log" ]; then
    printf '%s\n' 'empty legacy inventory invoked a firewall frontend or joined incorrectly' >&2
    exit 1
fi

legacy_present_prefix=$temporary_directory/legacy-stable-present
legacy_present_output=$temporary_directory/legacy-stable-present.output
legacy_present_count=$temporary_directory/legacy-stable-present.count
legacy_present_log=$temporary_directory/legacy-stable-present.log
VP_LEGACY_FIXTURE_MODE=stable-v4
VP_LEGACY_FIXTURE_COUNT=$legacy_present_count
VP_LEGACY_FIXTURE_LOG=$legacy_present_log
export VP_LEGACY_FIXTURE_MODE VP_LEGACY_FIXTURE_COUNT VP_LEGACY_FIXTURE_LOG
capture_stable_legacy_firewall_state ipv4 "$legacy_present_inventory" \
    "$legacy_fixture_uid" "$legacy_fixture_gid" "$legacy_fixture_mode" \
    "$legacy_fake_tool" "$legacy_present_prefix" "$legacy_present_output"
if [ "$(cat "$legacy_present_count")" -ne 2 ] \
    || [ "$(grep -Fc -- '-M|/bin/false' "$legacy_present_log")" -ne 2 ] \
    || [ "$(sed -n '1p' "$legacy_present_output")" != PRESENT ] \
    || [ "$(sed -n '2p' "$legacy_present_output")" != filter ] \
    || ! grep -Fx ':INPUT ACCEPT [COUNTERS]' "$legacy_present_output" >/dev/null \
    || ! grep -Fx -- \
        '-A INPUT -m comment --comment "semantic [1:2]" -j ACCEPT' \
        "$legacy_present_output" >/dev/null; then
    printf '%s\n' 'present legacy state did not require two stable exact-tool dumps' >&2
    exit 1
fi
for legacy_present_intermediate in \
    "$legacy_present_prefix.inventory-a" "$legacy_present_prefix.inventory-b" \
    "$legacy_present_prefix.raw-a" "$legacy_present_prefix.raw-b" \
    "$legacy_present_prefix.normalized-a" "$legacy_present_prefix.normalized-b"
do
    if [ -e "$legacy_present_intermediate" ] || [ -L "$legacy_present_intermediate" ]; then
        printf '%s\n' 'successful legacy capture retained a private intermediate' >&2
        exit 1
    fi
done

legacy_failure_inventory=$temporary_directory/legacy-failure.inventory
for legacy_stable_failure_label in producer parser inventory-drift save-drift; do
    printf '%s\n' filter >"$legacy_failure_inventory"
    chmod 0600 "$legacy_failure_inventory"
    case $legacy_stable_failure_label in
        producer) legacy_stable_failure_mode=fail ;;
        parser) legacy_stable_failure_mode=malformed ;;
        inventory-drift) legacy_stable_failure_mode=inventory-drift ;;
        save-drift) legacy_stable_failure_mode=save-drift ;;
    esac
    expect_status 77 legacy_stable_failure_gate "$legacy_stable_failure_label" \
        "$legacy_failure_inventory" "$legacy_stable_failure_mode"
    legacy_stable_failure_prefix=$temporary_directory/legacy-stable-$legacy_stable_failure_label
    legacy_stable_failure_output=$temporary_directory/legacy-stable-$legacy_stable_failure_label.output
    if [ -s "$last_stdout" ] || [ -s "$last_stderr" ] \
        || grep -F 'volparossa-private-firewall-' \
            "$last_stdout" "$last_stderr" >/dev/null \
        || ! assert_legacy_capture_cleaned "$legacy_stable_failure_prefix" \
            "$legacy_stable_failure_output"; then
        printf 'failed legacy capture leaked diagnostics or partial state: %s\n' \
            "$legacy_stable_failure_label" >&2
        exit 1
    fi
done

# A stable-field nftables difference must remain visible to the caller's
# mandatory A/B comparison; only counters and documented telemetry normalize.
legacy_nft_first=$temporary_directory/legacy-nft-first.raw
legacy_nft_second=$temporary_directory/legacy-nft-second.raw
legacy_nft_first_normalized=$temporary_directory/legacy-nft-first.normalized
legacy_nft_second_normalized=$temporary_directory/legacy-nft-second.normalized
printf '%s\n' \
    '{"nftables":[{"table":{"family":"inet","name":"before"}}]}' \
    >"$legacy_nft_first"
printf '%s\n' \
    '{"nftables":[{"table":{"family":"inet","name":"after"}}]}' \
    >"$legacy_nft_second"
vp_capture_normalize "$legacy_nft_first" "$legacy_nft_first_normalized" \
    nftables_state_producer
vp_capture_normalize "$legacy_nft_second" "$legacy_nft_second_normalized" \
    nftables_state_producer
if cmp -s "$legacy_nft_first_normalized" "$legacy_nft_second_normalized"; then
    printf '%s\n' 'stable nftables drift disappeared during normalization' >&2
    exit 1
fi

# Exercise the gate's real snapshot parser rather than a test-side copy. These
# fixtures cover both accepted size boundaries and every metadata field that
# grants authority to stage a workspace-owned executable as root.
source_snapshot_function=$temporary_directory/source-snapshot-function.sh
sed -n '/^source_snapshot_is_exact() {$/,/^}$/p' "$gate" \
    >"$source_snapshot_function"
if [ "$(grep -c '^source_snapshot_is_exact() {$' "$source_snapshot_function")" -ne 1 ]; then
    printf '%s\n' 'the bounded source-snapshot predicate cannot be isolated' >&2
    exit 1
fi
sh -n "$source_snapshot_function"
repository_owner_uid=$(id -u)
repository_owner_gid=$(id -g)
staged_executable_max_bytes=134217728
# The function path is generated from the reviewed gate above.
# shellcheck disable=SC1090
. "$source_snapshot_function"

require_snapshot_acceptance() {
    snapshot_description=$1
    snapshot_value=$2
    if ! source_snapshot_is_exact \
        "$snapshot_value" 755 "$staged_executable_max_bytes"; then
        printf 'valid source snapshot was rejected: %s\n' "$snapshot_description" >&2
        exit 1
    fi
}

require_snapshot_rejection() {
    snapshot_description=$1
    snapshot_value=$2
    if source_snapshot_is_exact \
        "$snapshot_value" 755 "$staged_executable_max_bytes"; then
        printf 'adversarial source snapshot was accepted: %s\n' \
            "$snapshot_description" >&2
        exit 1
    fi
}

snapshot_prefix="regular file:11:12:$repository_owner_uid:$repository_owner_gid:755:1"
snapshot_suffix='13:14'
require_snapshot_acceptance size-one \
    "$snapshot_prefix:1:$snapshot_suffix"
require_snapshot_acceptance size-exactly-128-mib \
    "$snapshot_prefix:134217728:$snapshot_suffix"
require_snapshot_rejection size-zero \
    "$snapshot_prefix:0:$snapshot_suffix"
require_snapshot_rejection size-over-128-mib \
    "$snapshot_prefix:134217729:$snapshot_suffix"
require_snapshot_rejection wrong-type \
    "directory:11:12:$repository_owner_uid:$repository_owner_gid:755:1:1:$snapshot_suffix"
require_snapshot_rejection wrong-uid \
    "regular file:11:12:$((repository_owner_uid + 1)):$repository_owner_gid:755:1:1:$snapshot_suffix"
require_snapshot_rejection wrong-gid \
    "regular file:11:12:$repository_owner_uid:$((repository_owner_gid + 1)):755:1:1:$snapshot_suffix"
require_snapshot_rejection wrong-mode \
    "regular file:11:12:$repository_owner_uid:$repository_owner_gid:700:1:1:$snapshot_suffix"
require_snapshot_rejection extra-hardlink \
    "regular file:11:12:$repository_owner_uid:$repository_owner_gid:755:2:1:$snapshot_suffix"
require_snapshot_rejection malformed-missing-field \
    "$snapshot_prefix:1:13"
require_snapshot_rejection malformed-extra-field \
    "$snapshot_prefix:1:$snapshot_suffix:15"
require_snapshot_rejection malformed-size \
    "$snapshot_prefix:not-a-size:$snapshot_suffix"
require_snapshot_rejection noncanonical-size \
    "$snapshot_prefix:01:$snapshot_suffix"

# `dash` preserves the parent's `$$` inside `( ... )`. Build a new /bin/sh
# process around the gate's real limiter so this hard-limit test cannot lower
# the contract runner's own RLIMIT_FSIZE.
proof_limit_runner=$temporary_directory/proof-limit-runner.sh
{
    # Variables in these literal lines expand only in the generated child.
    # shellcheck disable=SC2016
    printf '%s\n' \
        '#!/bin/sh' \
        'set -eu' \
        'export LC_ALL=C' \
        'PATH=/usr/sbin:/usr/bin:/sbin:/bin' \
        'export PATH' \
        'umask 077' \
        'proof_file_max_bytes=1048576'
    sed -n '/^install_proof_file_limit() {$/,/^}$/p' "$gate"
    # Variables in these literal lines expand only in the generated child.
    # shellcheck disable=SC2016
    printf '%s\n' \
        '[ "$#" -eq 1 ] || exit 64' \
        'boundary_file=$1' \
        '[ ! -e "$boundary_file" ] && [ ! -L "$boundary_file" ] || exit 1' \
        'if install_proof_file_limit; then exit 1; fi' \
        'if install_proof_file_limit 1048575; then exit 1; fi' \
        'if install_proof_file_limit "$proof_file_max_bytes" extra; then exit 1; fi' \
        'install_proof_file_limit "$proof_file_max_bytes"' \
        'observed_limit=$(prlimit --pid "$$" --fsize --raw --noheadings --output SOFT,HARD | awk '\''NF == 2 { print $1 ":" $2 }'\'')' \
        '[ "$observed_limit" = "$proof_file_max_bytes:$proof_file_max_bytes" ]' \
        'dd if=/dev/zero of="$boundary_file" bs="$proof_file_max_bytes" count=1 status=none' \
        '[ "$(stat -Lc '\''%s'\'' "$boundary_file")" -eq "$proof_file_max_bytes" ]' \
        'set +e' \
        'dd if=/dev/zero of="$boundary_file" bs=1 count=1 oflag=append conv=notrunc status=none 2>/dev/null' \
        'extra_status=$?' \
        'set -e' \
        '[ "$extra_status" -ne 0 ]' \
        '[ "$(stat -Lc '\''%s'\'' "$boundary_file")" -eq "$proof_file_max_bytes" ]'
} >"$proof_limit_runner"
if [ "$(grep -c '^install_proof_file_limit() {$' "$proof_limit_runner")" -ne 1 ]; then
    printf '%s\n' 'the proof file-size limiter cannot be isolated' >&2
    exit 1
fi
chmod 0700 "$proof_limit_runner"
sh -n "$proof_limit_runner"
parent_fsize_before=$(
    prlimit --pid "$$" --fsize --raw --noheadings --output SOFT,HARD \
        | awk 'NF == 2 { print $1 ":" $2 }'
)
case $parent_fsize_before in
    ''|*:|:*|*:*:*)
        printf '%s\n' 'the parent file-size limit is not observable' >&2
        exit 1
        ;;
esac
proof_limit_boundary=$temporary_directory/proof-limit-boundary
expect_status 0 /bin/sh "$proof_limit_runner" "$proof_limit_boundary"
parent_fsize_after=$(
    prlimit --pid "$$" --fsize --raw --noheadings --output SOFT,HARD \
        | awk 'NF == 2 { print $1 ":" $2 }'
)
if [ "$parent_fsize_before" != "$parent_fsize_after" ]; then
    printf '%s\n' 'the child limiter changed the contract runner file-size limit' >&2
    exit 1
fi
if [ "$(stat -Lc '%F:%u:%a:%h:%s' "$proof_limit_boundary")" \
    != "regular file:$(id -u):600:1:1048576" ]; then
    printf '%s\n' 'the proof-limit boundary write did not fail closed at exactly 1 MiB' >&2
    exit 1
fi

resolver_fixture=$temporary_directory/resolver-fixture
mkdir -m 0700 "$resolver_fixture"
resolver_runtime_directory=$(mktemp -d /tmp/volparossa-resolver-runtime.XXXXXX)
case $resolver_runtime_directory in
    /tmp/volparossa-resolver-runtime.??????) ;;
    *)
        printf 'unsafe resolver runtime fixture path: %s\n' \
            "$resolver_runtime_directory" >&2
        exit 1
        ;;
esac
chmod 0755 "$resolver_runtime_directory"
resolver_allowed_roots="$temporary_directory $resolver_runtime_directory"
resolver_runtime_uid=$(id -u)
resolver_runtime_gid=$(id -g)
resolver_other_capture_uid=0
if [ "$resolver_runtime_gid" -eq 0 ]; then
    resolver_other_capture_gid=1
else
    resolver_other_capture_gid=0
fi
if [ "$resolver_runtime_uid" -eq 1 ]; then
    resolver_wrong_runtime_uid=2
else
    resolver_wrong_runtime_uid=1
fi
if [ "$resolver_runtime_gid" -eq 1 ]; then
    resolver_wrong_runtime_gid=2
else
    resolver_wrong_runtime_gid=1
fi

resolver_regular=$resolver_fixture/regular.conf
printf '%s\n' 'nameserver 192.0.2.53' >"$resolver_regular"
chmod 0600 "$resolver_regular"
resolver_regular_snapshot=$temporary_directory/resolver-regular.snapshot
vp_capture_resolver_snapshot "$resolver_regular" "$resolver_regular_snapshot" \
    "$resolver_fixture" "$resolver_runtime_directory" \
    "$resolver_runtime_uid" "$resolver_runtime_gid"
vp_capture_file_is_safe "$resolver_regular_snapshot"
grep -Fx REGULAR "$resolver_regular_snapshot" >/dev/null
grep -Fx "$resolver_regular" "$resolver_regular_snapshot" >/dev/null

resolver_symlink_target=$resolver_fixture/symlink-target.conf
printf '%s\n' 'nameserver 2001:db8::53' >"$resolver_symlink_target"
chmod 0600 "$resolver_symlink_target"
resolver_symlink=$resolver_fixture/resolv.conf
ln -s symlink-target.conf "$resolver_symlink"
resolver_symlink_snapshot=$temporary_directory/resolver-symlink.snapshot
vp_capture_resolver_snapshot "$resolver_symlink" "$resolver_symlink_snapshot" \
    "$resolver_fixture" "$resolver_runtime_directory" \
    "$resolver_runtime_uid" "$resolver_runtime_gid"
vp_capture_file_is_safe "$resolver_symlink_snapshot"
grep -Fx symlink-target.conf "$resolver_symlink_snapshot" >/dev/null
grep -Fx "$resolver_symlink_target" "$resolver_symlink_snapshot" >/dev/null

# Model Debian's managed /etc/resolv.conf -> .../stub-resolv.conf authority split.
resolver_managed_stub=$resolver_runtime_directory/stub-resolv.conf
printf '%s\n' 'nameserver 127.0.0.53' >"$resolver_managed_stub"
chmod 0644 "$resolver_managed_stub"
resolver_managed_link=$resolver_fixture/managed-resolv.conf
ln -s "$resolver_managed_stub" "$resolver_managed_link"
resolver_managed_snapshot=$temporary_directory/resolver-managed.snapshot
vp_capture_resolver_snapshot "$resolver_managed_link" "$resolver_managed_snapshot" \
    "$resolver_allowed_roots" "$resolver_runtime_directory" \
    "$resolver_runtime_uid" "$resolver_runtime_gid"
vp_capture_file_is_safe "$resolver_managed_snapshot"
grep -Fx "$resolver_managed_stub" "$resolver_managed_snapshot" >/dev/null
resolver_managed_runtime_link=$resolver_runtime_directory/managed-resolv.conf
ln -s stub-resolv.conf "$resolver_managed_runtime_link"

resolver_managed_observation_gate() {
    (
        VP_CAPTURE_OWNER_UID=$resolver_other_capture_uid
        VP_CAPTURE_OWNER_GID=$resolver_other_capture_gid
        export VP_CAPTURE_OWNER_UID VP_CAPTURE_OWNER_GID
        vp_capture_resolver_observation "$resolver_managed_runtime_link" \
            "$resolver_allowed_roots" "$resolver_runtime_directory" \
            "$resolver_runtime_uid" "$resolver_runtime_gid" >/dev/null || exit 77
    )
}
expect_status 0 resolver_managed_observation_gate

resolver_managed_uplink=$resolver_runtime_directory/resolv.conf
printf '%s\n' 'nameserver 192.0.2.60' >"$resolver_managed_uplink"
chmod 0644 "$resolver_managed_uplink"
resolver_managed_uplink_snapshot=$temporary_directory/resolver-managed-uplink.snapshot
vp_capture_resolver_snapshot "$resolver_managed_uplink" \
    "$resolver_managed_uplink_snapshot" "$resolver_allowed_roots" \
    "$resolver_runtime_directory" "$resolver_runtime_uid" "$resolver_runtime_gid"
vp_capture_file_is_safe "$resolver_managed_uplink_snapshot"
grep -Fx "$resolver_managed_uplink" "$resolver_managed_uplink_snapshot" >/dev/null

resolver_unsafe_object_parent=$resolver_fixture/unsafe-object-parent
mkdir -m 0777 "$resolver_unsafe_object_parent"
resolver_unsafe_object=$resolver_unsafe_object_parent/resolv.conf
ln -s "$resolver_managed_stub" "$resolver_unsafe_object"
resolver_unsafe_object_snapshot=$temporary_directory/resolver-unsafe-object.snapshot
if vp_capture_resolver_snapshot "$resolver_unsafe_object" \
    "$resolver_unsafe_object_snapshot" "$resolver_allowed_roots" \
    "$resolver_runtime_directory" "$resolver_runtime_uid" "$resolver_runtime_gid"; then
    printf '%s\n' 'resolver symlink below a writable object parent was accepted' >&2
    exit 1
fi
if [ -e "$resolver_unsafe_object_snapshot" ]; then
    printf '%s\n' 'unsafe resolver object parent left a partial snapshot' >&2
    exit 1
fi

# The service UID/GID grants authority only below the one explicit runtime directory.
resolver_authority_outside=$(mktemp /tmp/volparossa-resolver-authority-outside.XXXXXX)
case $resolver_authority_outside in
    /tmp/volparossa-resolver-authority-outside.??????) ;;
    *)
        printf 'unsafe resolver authority fixture path: %s\n' \
            "$resolver_authority_outside" >&2
        exit 1
        ;;
esac
printf '%s\n' 'nameserver 192.0.2.56' >"$resolver_authority_outside"
chmod 0600 "$resolver_authority_outside"
resolver_outside_authority_gate() {
    (
        VP_CAPTURE_OWNER_UID=$resolver_other_capture_uid
        VP_CAPTURE_OWNER_GID=$resolver_other_capture_gid
        export VP_CAPTURE_OWNER_UID VP_CAPTURE_OWNER_GID
        vp_capture_resolver_observation "$resolver_authority_outside" /tmp \
            "$resolver_runtime_directory" "$resolver_runtime_uid" \
            "$resolver_runtime_gid" >/dev/null || exit 77
    )
}
expect_status 77 resolver_outside_authority_gate
rm -f -- "$resolver_authority_outside"
resolver_authority_outside=

resolver_wrong_uid_snapshot=$temporary_directory/resolver-wrong-uid.snapshot
if vp_capture_resolver_snapshot "$resolver_managed_link" \
    "$resolver_wrong_uid_snapshot" "$resolver_allowed_roots" \
    "$resolver_runtime_directory" "$resolver_wrong_runtime_uid" \
    "$resolver_runtime_gid"; then
    printf '%s\n' 'managed resolver target with the wrong authority UID was accepted' >&2
    exit 1
fi
if [ -e "$resolver_wrong_uid_snapshot" ]; then
    printf '%s\n' 'wrong resolver authority UID left a partial snapshot' >&2
    exit 1
fi

resolver_wrong_gid_snapshot=$temporary_directory/resolver-wrong-gid.snapshot
if vp_capture_resolver_snapshot "$resolver_managed_link" \
    "$resolver_wrong_gid_snapshot" "$resolver_allowed_roots" \
    "$resolver_runtime_directory" "$resolver_runtime_uid" \
    "$resolver_wrong_runtime_gid"; then
    printf '%s\n' 'managed resolver target with the wrong authority GID was accepted' >&2
    exit 1
fi
if [ -e "$resolver_wrong_gid_snapshot" ]; then
    printf '%s\n' 'wrong resolver authority GID left a partial snapshot' >&2
    exit 1
fi

resolver_writable_target_runtime=$resolver_fixture/writable-target-runtime
mkdir -m 0755 "$resolver_writable_target_runtime"
resolver_unsafe_target=$resolver_writable_target_runtime/stub-resolv.conf
printf '%s\n' 'nameserver 198.51.100.53' >"$resolver_unsafe_target"
chmod 0666 "$resolver_unsafe_target"
resolver_unsafe_snapshot=$temporary_directory/resolver-unsafe.snapshot
if vp_capture_resolver_snapshot "$resolver_unsafe_target" "$resolver_unsafe_snapshot" \
    "$temporary_directory" "$resolver_writable_target_runtime" \
    "$resolver_runtime_uid" "$resolver_runtime_gid"; then
    printf '%s\n' 'writable resolver target was accepted' >&2
    exit 1
fi
if [ -e "$resolver_unsafe_snapshot" ]; then
    printf '%s\n' 'rejected resolver target left a partial snapshot' >&2
    exit 1
fi

resolver_writable_runtime=$resolver_fixture/writable-runtime
mkdir -m 0777 "$resolver_writable_runtime"
resolver_writable_runtime_target=$resolver_writable_runtime/stub-resolv.conf
printf '%s\n' 'nameserver 192.0.2.57' >"$resolver_writable_runtime_target"
chmod 0644 "$resolver_writable_runtime_target"
resolver_writable_runtime_snapshot=$temporary_directory/resolver-writable-runtime.snapshot
if vp_capture_resolver_snapshot "$resolver_writable_runtime_target" \
    "$resolver_writable_runtime_snapshot" "$temporary_directory" \
    "$resolver_writable_runtime" "$resolver_runtime_uid" "$resolver_runtime_gid"; then
    printf '%s\n' 'writable resolver runtime directory was accepted' >&2
    exit 1
fi
if [ -e "$resolver_writable_runtime_snapshot" ]; then
    printf '%s\n' 'writable resolver runtime directory left a partial snapshot' >&2
    exit 1
fi

resolver_hardlinked_runtime=$resolver_fixture/hardlinked-runtime
mkdir -m 0755 "$resolver_hardlinked_runtime"
resolver_hardlinked_target=$resolver_hardlinked_runtime/stub-resolv.conf
printf '%s\n' 'nameserver 192.0.2.58' >"$resolver_hardlinked_target"
chmod 0644 "$resolver_hardlinked_target"
ln "$resolver_hardlinked_target" "$resolver_fixture/hardlinked-resolv.peer"
resolver_hardlinked_snapshot=$temporary_directory/resolver-hardlinked.snapshot
if vp_capture_resolver_snapshot "$resolver_hardlinked_target" \
    "$resolver_hardlinked_snapshot" "$temporary_directory" \
    "$resolver_hardlinked_runtime" "$resolver_runtime_uid" "$resolver_runtime_gid"; then
    printf '%s\n' 'hard-linked resolver target was accepted' >&2
    exit 1
fi
if [ -e "$resolver_hardlinked_snapshot" ]; then
    printf '%s\n' 'hard-linked resolver target left a partial snapshot' >&2
    exit 1
fi

resolver_oversize_runtime=$resolver_fixture/oversize-runtime
mkdir -m 0755 "$resolver_oversize_runtime"
resolver_oversize_target=$resolver_oversize_runtime/stub-resolv.conf
dd if=/dev/zero of="$resolver_oversize_target" bs=65537 count=1 2>/dev/null
chmod 0644 "$resolver_oversize_target"
resolver_oversize_snapshot=$temporary_directory/resolver-oversize.snapshot
if vp_capture_resolver_snapshot "$resolver_oversize_target" \
    "$resolver_oversize_snapshot" "$temporary_directory" \
    "$resolver_oversize_runtime" "$resolver_runtime_uid" "$resolver_runtime_gid"; then
    printf '%s\n' 'resolver target larger than 64 KiB was accepted' >&2
    exit 1
fi
if [ -e "$resolver_oversize_snapshot" ]; then
    printf '%s\n' 'oversized resolver target left a partial snapshot' >&2
    exit 1
fi

resolver_runtime_symlink_target=$resolver_fixture/runtime-symlink-target
mkdir -m 0755 "$resolver_runtime_symlink_target"
printf '%s\n' 'nameserver 192.0.2.59' \
    >"$resolver_runtime_symlink_target/stub-resolv.conf"
chmod 0644 "$resolver_runtime_symlink_target/stub-resolv.conf"
resolver_runtime_symlink=$resolver_fixture/runtime-symlink
ln -s runtime-symlink-target "$resolver_runtime_symlink"
resolver_runtime_symlink_snapshot=$temporary_directory/resolver-runtime-symlink.snapshot
if vp_capture_resolver_snapshot "$resolver_runtime_symlink/stub-resolv.conf" \
    "$resolver_runtime_symlink_snapshot" "$temporary_directory" \
    "$resolver_runtime_symlink" "$resolver_runtime_uid" "$resolver_runtime_gid"; then
    printf '%s\n' 'symlinked resolver runtime directory was accepted' >&2
    exit 1
fi
if [ -e "$resolver_runtime_symlink_snapshot" ]; then
    printf '%s\n' 'symlinked resolver runtime directory left a partial snapshot' >&2
    exit 1
fi

resolver_outside=$temporary_directory/resolver-outside.conf
printf '%s\n' 'nameserver 203.0.113.53' >"$resolver_outside"
chmod 0600 "$resolver_outside"
resolver_outside_link=$resolver_fixture/outside.conf
ln -s "$resolver_outside" "$resolver_outside_link"
resolver_outside_snapshot=$temporary_directory/resolver-outside.snapshot
if vp_capture_resolver_snapshot "$resolver_outside_link" "$resolver_outside_snapshot" \
    "$resolver_fixture" "$resolver_runtime_directory" \
    "$resolver_runtime_uid" "$resolver_runtime_gid"; then
    printf '%s\n' 'resolver target outside the allowed root was accepted' >&2
    exit 1
fi
if [ -e "$resolver_outside_snapshot" ]; then
    printf '%s\n' 'rejected outside resolver target left a partial snapshot' >&2
    exit 1
fi

resolver_unsafe_parent=$resolver_fixture/unsafe-parent
mkdir -m 0777 "$resolver_unsafe_parent"
resolver_unsafe_parent_target=$resolver_unsafe_parent/resolv.conf
printf '%s\n' 'nameserver 192.0.2.54' >"$resolver_unsafe_parent_target"
chmod 0600 "$resolver_unsafe_parent_target"
resolver_unsafe_parent_snapshot=$temporary_directory/resolver-unsafe-parent.snapshot
if vp_capture_resolver_snapshot "$resolver_unsafe_parent_target" \
    "$resolver_unsafe_parent_snapshot" "$resolver_fixture" \
    "$resolver_runtime_directory" "$resolver_runtime_uid" "$resolver_runtime_gid"; then
    printf '%s\n' 'resolver target below an unsafe parent was accepted' >&2
    exit 1
fi
if [ -e "$resolver_unsafe_parent_snapshot" ]; then
    printf '%s\n' 'unsafe-parent rejection left a partial resolver snapshot' >&2
    exit 1
fi

resolver_drift_target=$resolver_fixture/drift.conf
printf '%s\n' 'nameserver 192.0.2.55' >"$resolver_drift_target"
chmod 0600 "$resolver_drift_target"
resolver_drift_snapshot=$temporary_directory/resolver-drift.snapshot
resolver_drift_gate() {
    (
        # ShellCheck cannot see the indirect call through the sourced capture helper.
        # shellcheck disable=SC2317
        vp_capture_sha256_file() {
            drift_checksum_line=$(command sha256sum "$1") || return 1
            drift_checksum=$(vp_capture_checksum_from_line "$drift_checksum_line") || return 1
            printf '%s\n' '# injected drift' >>"$1" || return 1
            printf '%s\n' "$drift_checksum"
        }
        vp_capture_resolver_snapshot "$resolver_drift_target" "$resolver_drift_snapshot" \
            "$resolver_fixture" "$resolver_runtime_directory" \
            "$resolver_runtime_uid" "$resolver_runtime_gid" || exit 77
    )
}

expect_status 77 producer_failure_gate
if [ -e "$temporary_directory/producer-failure.raw" ] \
    || [ -e "$temporary_directory/producer-failure.digest" ]; then
    printf '%s\n' 'failed producer left hashable or published capture state' >&2
    exit 1
fi
expect_status 77 parser_failure_gate
if [ -e "$temporary_directory/parser-failure.normalized" ] \
    || [ -e "$temporary_directory/parser-failure.digest" ]; then
    printf '%s\n' 'failed parser left hashable or published normalized state' >&2
    exit 1
fi
expect_status 77 stream_producer_failure_gate
if [ -e "$temporary_directory/stream-producer-failure.fifo" ] \
    || [ -e "$temporary_directory/stream-producer-failure.digest" ] \
    || [ -e "$temporary_directory/stream-producer-failure.digest.consumer" ]; then
    printf '%s\n' 'failed secret producer left a FIFO, digest, or consumer record' >&2
    exit 1
fi
expect_status 77 stream_hasher_failure_gate
if [ -e "$temporary_directory/stream-hasher-failure.fifo" ] \
    || [ -e "$temporary_directory/stream-hasher-failure.digest" ] \
    || [ -e "$temporary_directory/stream-hasher-failure.digest.consumer" ]; then
    printf '%s\n' 'failed secret hasher left a FIFO, digest, or consumer record' >&2
    exit 1
fi
expect_status 77 resolver_drift_gate
if [ -e "$resolver_drift_snapshot" ]; then
    printf '%s\n' 'resolver drift left a partial snapshot' >&2
    exit 1
fi

expect_status 0 "$gate"
default_preview=$last_stdout
if [ -s "$last_stderr" ]; then
    printf '%s\n' 'default preview wrote standard error' >&2
    exit 1
fi
expected_preview=$temporary_directory/expected-preview
printf '%s\n' \
    'VOLPAROSSA live worker-identity proof plan:' \
    '  require a disposable Debian 13 amd64 VM, root, and the exact systemd v257 manager;' \
    '  bookend one unchanged clean Git revision and exact helper, probe, hook,' \
    '    restart observer/launcher, and debugger artifact hashes;' \
    '  copy the already-built real helper into one validated root-only temporary stage;' \
    '  create synthetic, collision-free agent/worker/group records only inside that stage;' \
    '  bind account files plus the system bus socket read-only in four sequential transient services;' \
    '  let PID 1 resolve only host-present root/root unit credentials before those binds;' \
    '  use exact /usr/bin/setpriv to install the staged primary and singleton agent GID;' \
    '  bind the canonical systemd notify socket read-only inside both private /run trees;' \
    '  pin its D-Bus system address to that verified socket inside the private /run;' \
    '  run with PrivateNetwork=yes, a private temporary /run, and no host account changes;' \
    '  require the host /run/volparossa path absent before and after every private unit run;' \
    '  set NotifyAccess=main, FileDescriptorStoreMax=128, and' \
    '    FileDescriptorStorePreserve=yes on that transient service;' \
    '  start its fixed credential trampoline as blocking Type=exec, then require helper exec;' \
    '  retain diagnostic success with RemainAfterExit=yes and failures with CollectMode=inactive;' \
    '  forbid ignore-failure, aggressive collection, and asynchronous or waiting client modes;' \
    '  grant exactly CAP_KILL, CAP_NET_ADMIN, CAP_NET_RAW, CAP_SETGID, CAP_SETPCAP,' \
    '    CAP_SETUID, and CAP_SYS_ADMIN to the helper parent;' \
    '  bound both large build-artifact staging copies at 128 MiB, then cap' \
    '    the proof process and every transient-unit file write at 1 MiB;' \
    '  cap the diagnostic worker runtime at 45 seconds;' \
    '  cap the production runtime at three minutes;' \
    '  cap the two-crash MayOwn service runtime at six minutes;' \
    '  discard production runtime stdout and stderr through exact systemd null streams;' \
    '  require its kernel supplementary-group vector to contain only the staged agent GID;' \
    '  invoke only --internal-worker-v3-live-proof and require its exact two success records;' \
    '  after main exit require exactly two descriptors in the systemd descriptor store;' \
    '  bind normal retirement to the exact JSON InvocationID returned for that run;' \
    '  recover tentative ownership only from its exact marker and current nonzero manager ID;' \
    '  stop, clean only its fdstore, and collect that exact first invocation;' \
    '  only after the unit is not-found, reuse its random name with a new exact marker and ID;' \
    '  run the argumentless production helper and fixed IPC probe inside the confined unit;' \
    '  use one fixed no-argument launcher and FIFO barriers to hold the ExactPresent successor' \
    '    plus all three MayOwn invocations before same-MainPID helper exec;' \
    '  release each MayOwn launcher only after exact PID, new InvocationID, NRestarts,' \
    '    ControlPID, ControlGroup/ControlGroupId, fdstore, cgroup shape, GDB exec-catch,' \
    '    pending breakpoint, and an outside-cgroup namespace observer are ready;' \
    '  use GDB inferior kill plus quit 0 for exactly three SIGKILL crash boundaries;' \
    '  freeze only each non-empty, exact single-MainPID MayOwn cgroup at its two crash frames,' \
    '    then thaw or observe removal before PID 1 may launch the FIFO-gated successor;' \
    '  require stable Bind identity, bounded malformed-frame and wire-shape rejection,' \
    '    exact peer PID/UID/GID rejection, stable socket inode/token metadata, and zero fdstore;' \
    '  create one fixed dummy underlay only inside the production PrivateNetwork namespace;' \
    '  hold sequential singleton Client and Exit leases, then one simultaneous Relay pair at fixed FIFO READY barriers;' \
    '  externally prove every child PID, executable, identity, distinct netns, and live WireGuard;' \
    '  drive bounded ICMPv6 over both pair legs ::1/::2 and ::3/::4, then require exact Commit;' \
    '  require byte-identical Commit retries, exact fixture cleanup, Destroy, and worker retirement;' \
    '  preserve one MainPID and InvocationID throughout those checks, then require clean' \
    '    SIGTERM, an unchanged journal, one held-then-unlocked lock inode, and removed socket;' \
    '  retire each exact unit, stop all observers/keepers/debuggers, thaw any crash freezer,' \
    '    collect the units, and remove the validated temporary stage;' \
    '  compare privacy-safe before/after host account, resolver, mount, firewall, WireGuard,' \
    '    and network digests;' \
    '  validate exactly three bounded canonical evidence-v1 reports before publishing only those JSON values.' \
    'This stages the helper identity and production IPC boundary. It creates no host account,' \
    'host link, route, firewall rule, WireGuard device, DNS change, sysctl change, or production VPN datapath.' \
    'One dummy underlay and ephemeral Client, Exit, and simultaneous Relay-pair WireGuard leases exist only in private namespaces.' \
    'It is not package-install, general restart recovery, CleanupOwned, production datapath, or A01-A15 evidence.' \
    'PREVIEW ONLY: no file, account, service, or network state was changed.' \
    >"$expected_preview"
if ! cmp -s "$expected_preview" "$default_preview"; then
    printf '%s\n' 'default preview does not match the exact reviewed plan' >&2
    exit 1
fi

expect_status 0 "$gate" --preview
if ! cmp -s "$default_preview" "$last_stdout" || [ -s "$last_stderr" ]; then
    printf '%s\n' 'explicit and default previews are not byte-identical' >&2
    exit 1
fi

expect_status 0 "$gate" --help
grep -F 'usage: tests/helper/require-live-worker-identity-proof.sh' "$last_stdout" >/dev/null
expect_status 64 "$gate" --execute
grep -Fx 'Execution requires --yes after reviewing the exact plan.' "$last_stderr" >/dev/null
if [ -s "$last_stdout" ]; then
    printf '%s\n' 'unapproved execute request wrote non-JSON standard output' >&2
    exit 1
fi
expect_status 64 "$gate" --preview --yes
expect_status 64 "$gate" --preview --execute
expect_status 64 "$gate" --execute --execute
expect_status 64 "$gate" --execute --yes --yes
expect_status 64 "$gate" --unknown

find /var/tmp -maxdepth 1 -name 'volparossa-helper-live-proof.*' -printf '%f\n' \
    | sort >"$temporary_directory/stages.before"
expect_status 77 "$gate" --execute --yes
if [ -s "$last_stdout" ]; then
    printf '%s\n' 'blocked execute request wrote non-JSON standard output' >&2
    exit 1
fi
grep -Fx 'VOLPAROSSA live worker-identity proof plan:' "$last_stderr" >/dev/null
if grep -F 'PREVIEW ONLY:' "$last_stderr" >/dev/null; then
    printf '%s\n' 'approved execution printed a preview-only claim' >&2
    exit 1
fi
grep -Fx 'BLOCKED: execution requires root inside the disposable VM' "$last_stderr" >/dev/null
find /var/tmp -maxdepth 1 -name 'volparossa-helper-live-proof.*' -printf '%f\n' \
    | sort >"$temporary_directory/stages.after"
if ! cmp -s "$temporary_directory/stages.before" "$temporary_directory/stages.after"; then
    printf '%s\n' 'unprivileged refusal created a temporary proof stage' >&2
    exit 1
fi

if ! awk '
    /^if \[ "\$approval" != yes \]; then$/ { approval_guard = NR }
    /^print_plan >&2$/ { execute_plan = NR }
    /^if \[ "\$\(id -u\)" -ne 0 \]; then$/ { root_preflight = NR }
    END {
        if (!(approval_guard < execute_plan && execute_plan < root_preflight)) exit 1
    }
' "$gate"; then
    printf '%s\n' 'execute plan is not ordered between approval and preflight' >&2
    exit 1
fi

if ! awk '
    /^[[:space:]]*systemd-run \\$/ {
        run_count++
        if (run_count == 1) first_run = NR
        if (run_count == 2) second_run = NR
        if (run_count == 3) third_run = NR
        if (run_count == 4) fourth_run = NR
    }
    /^worker_unit_name=\$unit_name$/ { first_identity_saved = NR }
    /^        unit_name=\$worker_unit_name$/ { name_reused = NR }
    /if \[ "\$reuse_load_state" != not-found \]/ { not_found_required = NR }
    /VOLPAROSSA helper production IPC transient ownership marker v1/ {
        production_marker = NR
    }
    /VOLPAROSSA helper singleton ExactPresent restart marker v1/ {
        restart_marker = NR
    }
    /VOLPAROSSA helper singleton MayOwn Relay restart marker v1/ {
        may_own_marker = NR
    }
    /^    production_retirement_confirmed=no$/ {
        production_retirement_init = NR
    }
    /^    production_unit_name=\$unit_name$/ { production_name_saved = NR }
    second_run > 0 && /^    if ! retire_unit; then$/ \
        && production_retirement == 0 { production_retirement = NR }
    /failed '\''production unit retirement did not settle'\''/ {
        production_retirement_failed = NR
    }
    /failed '\''production unit retirement retained affine ownership state'\''/ {
        production_affine_failed = NR
    }
    /^    unit_name=\$production_unit_name$/ { production_name_restored = NR }
    /^    production_retired_load_state=/ { production_not_found_observation = NR }
    /! retired_runtime_is_absent "\$production_unit_name"/ {
        production_runtime_fence = NR
    }
    /failed '\''production unit retirement fence did not settle'\''/ {
        production_fence_failed = NR
    }
    production_fence_failed > 0 && production_ownership_forgotten == 0 \
        && /^    forget_unit_ownership$/ {
        production_ownership_forgotten = NR
    }
    /^    production_retirement_confirmed=yes$/ {
        production_retirement_confirmed = NR
    }
    /^    prepare_restart_unit_identity \\$/ {
        restart_identity_prepared = NR
    }
    /^    \[ "\$restart_initial_load_state" = not-found \]/ {
        restart_not_found_required = NR
    }
    END {
        valid = run_count == 4 && first_run < first_identity_saved
        valid = valid && first_identity_saved < name_reused
        valid = valid && name_reused < not_found_required
        valid = valid && not_found_required < production_marker
        valid = valid && production_marker < second_run
        valid = valid && second_run < production_retirement_init
        valid = valid && production_retirement_init < production_name_saved
        valid = valid && production_name_saved < production_retirement
        valid = valid && production_retirement < production_retirement_failed
        valid = valid && production_retirement_failed < production_affine_failed
        valid = valid && production_affine_failed < production_name_restored
        valid = valid && production_name_restored < production_not_found_observation
        valid = valid && production_not_found_observation < production_runtime_fence
        valid = valid && production_runtime_fence < production_fence_failed
        valid = valid && production_fence_failed < production_ownership_forgotten
        valid = valid && production_ownership_forgotten < production_retirement_confirmed
        valid = valid && production_retirement_confirmed < restart_identity_prepared
        valid = valid && restart_identity_prepared < restart_not_found_required
        valid = valid && restart_not_found_required < restart_marker
        valid = valid && restart_marker < third_run
        valid = valid && third_run < may_own_marker && may_own_marker < fourth_run
        if (!valid) exit 1
    }
' "$gate"; then
    printf '%s\n' 'production IPC phase does not follow collected not-found worker proof' >&2
    exit 1
fi

if ! awk '
    /^classify_worker_live_proof_terminal\(\) \{$/ {
        classifier_definition = NR
        in_classifier = 1
        next
    }
    in_classifier && /^}$/ { in_classifier = 0; next }
    in_classifier && /^    if \[ "\$worker_manager_binding_ok" = yes \] \\$/ {
        helper_guard = NR
    }
    in_classifier && /&& unit_description_matches_marker \\$/ {
        current_marker = NR
    }
    in_classifier && /&& unit_invocation_is_current \\$/ { current_invocation = NR }
    in_classifier && /= failed:failed:exit-code:1:1 \]; then/ {
        exact_failure_tuple = NR
    }
    in_classifier && /record_helper_live_proof_failure_stage "\$1"/ {
        helper_stage_mapping = NR
    }
    in_classifier && /^    record_worker_launch_failure$/ {
        generic_launch_fallback = NR
    }
    in_classifier && /^    if \[ "\$active_state" != active \]/ {
        success_terminal_gate = NR
    }
    in_classifier && /record_proof_failure '\''worker-terminal-state'\''/ {
        generic_terminal = NR
    }
    !in_classifier && /^    record_worker_launch_failure$/ {
        early_launch_fallback = NR
    }
    !in_classifier && /^    recover_failed_worker_manager_binding \|\| true$/ {
        failed_binding_recovery = NR
    }
    /capture_unit_property ExecMainCode "\$temporary_stage\/unit-exec-code"/ {
        exec_code_capture = NR
    }
    /classify_worker_live_proof_terminal "\$temporary_stage\/proof.stderr"/ {
        classifier_call = NR
    }
    /^    record_proof_failure '\''worker-proof-records'\''$/ {
        generic_proof_records = NR
    }
    END {
        valid = classifier_definition > 0 && helper_guard > 0 && current_marker > 0
        valid = valid && current_invocation > 0
        valid = valid && exact_failure_tuple > 0 && helper_stage_mapping > 0
        valid = valid && generic_launch_fallback > 0 && success_terminal_gate > 0
        valid = valid && generic_terminal > 0 && early_launch_fallback > 0
        valid = valid && failed_binding_recovery > 0
        valid = valid && exec_code_capture > 0 && classifier_call > 0
        valid = valid && generic_proof_records > 0
        valid = valid && classifier_definition < helper_guard
        valid = valid && helper_guard < current_invocation
        valid = valid && current_invocation < current_marker
        valid = valid && current_marker < exact_failure_tuple
        valid = valid && exact_failure_tuple < helper_stage_mapping
        valid = valid && helper_stage_mapping < generic_launch_fallback
        valid = valid && generic_launch_fallback < success_terminal_gate
        valid = valid && success_terminal_gate < generic_terminal
        valid = valid && failed_binding_recovery < early_launch_fallback
        valid = valid && early_launch_fallback < exec_code_capture
        valid = valid && exec_code_capture < classifier_call
        valid = valid && classifier_call < generic_proof_records
        if (!valid) exit 1
    }
' "$gate"; then
    printf '%s\n' \
        'helper failure stages are not bound before generic terminal diagnostics' >&2
    exit 1
fi

if ! awk '
    /^recover_failed_worker_manager_binding\(\) \{$/ {
        in_recovery = 1
        definition = NR
        next
    }
    in_recovery && /^}$/ { in_recovery = 0; next }
    in_recovery && /\[ "\$run_status" -ne 0 \] \|\| return 1/ { failed_status = NR }
    in_recovery && /\[ "\$worker_launch_captures_ok" = yes \] \|\| return 1/ {
        safe_captures = NR
    }
    in_recovery && /vp_capture_file_is_safe "\$temporary_stage\/systemd-run.stdout"/ {
        stdout_metadata = NR
    }
    in_recovery && /\[ ! -s "\$temporary_stage\/systemd-run.stdout" \] \|\| return 1/ {
        empty_stdout = NR
    }
    in_recovery && /\[ "\$worker_launch_json_ok" = no \] \|\| return 1/ {
        missing_json = NR
    }
    in_recovery && /\[ "\$worker_manager_binding_ok" = no \] \|\| return 1/ {
        missing_binding = NR
    }
    in_recovery && /\[ "\$unit_owned" = no \] \|\| return 1/ { pre_owned = NR }
    in_recovery && /\[ "\$unit_may_own" = yes \] \|\| return 1/ { pre_may = NR }
    in_recovery && /adopt_tentative_unit \|\| return 1/ { adoption = NR }
    in_recovery && /\[ "\$unit_owned" = yes \] \|\| return 1/ { post_owned = NR }
    in_recovery && /\[ "\$unit_may_own" = no \] \|\| return 1/ { post_may = NR }
    in_recovery && /^    unit_description_matches_marker \|\| return 1$/ {
        post_marker = NR
    }
    in_recovery && /^    unit_invocation_is_current \|\| return 1$/ {
        post_current = NR
    }
    in_recovery && /^    worker_manager_binding_ok=yes$/ { binding_commit = NR }
    END {
        valid = definition > 0 && definition < failed_status
        valid = valid && failed_status < safe_captures
        valid = valid && safe_captures < stdout_metadata
        valid = valid && stdout_metadata < empty_stdout
        valid = valid && empty_stdout < missing_json
        valid = valid && missing_json < missing_binding
        valid = valid && missing_binding < pre_owned && pre_owned < pre_may
        valid = valid && pre_may < adoption && adoption < post_owned
        valid = valid && post_owned < post_may && post_may < post_current
        valid = valid && post_current < post_marker && post_marker < binding_commit
        if (!valid) exit 1
    }
' "$gate"; then
    printf '%s\n' \
        'failed worker binding recovery is not exact and fail closed' >&2
    exit 1
fi

if ! awk '
    /^adopt_tentative_unit\(\) \{$/ { in_adopt = 1; next }
    in_adopt && /^\}$/ { in_adopt = 0 }
    in_adopt && /adopted_invocation_id=\$\(unit_current_invocation_id/ { id_read = NR }
    in_adopt && id_read > 0 && /unit_description_matches_marker \|\| return 1/ {
        marker_after_id = NR
    }
    in_adopt && /unit_owned=yes/ { ownership_commit = NR }
    END {
        if (!(id_read > 0 && id_read < marker_after_id && marker_after_id < ownership_commit)) {
            exit 1
        }
    }
' "$gate"; then
    printf '%s\n' 'tentative unit adoption does not recheck its marker after the ID read' >&2
    exit 1
fi

# These are literal source contracts; expansion here would defeat the check.
# shellcheck disable=SC2016
for required_contract in \
    'awk base64 busctl cat chmod chown' \
    'nsenter paste ping prlimit readlink rm sed setpriv' \
    'busctl_path=/usr/bin/busctl' \
    '[ "$(command -v busctl)" != "$busctl_path" ]' \
    "blocked 'the fixed root-owned systemd bus client is unavailable'" \
    'setpriv_path=/usr/bin/setpriv' \
    '[ "$(command -v setpriv)" != "$setpriv_path" ]' \
    "!= 'regular file:0:0:755:1' ]; then" \
    "blocked 'the fixed root-owned setpriv credential trampoline is unavailable'" \
    'staged_executable_max_bytes=134217728' \
    'proof_file_max_bytes=1048576' \
    'source_snapshot_is_exact() {' \
    'install_proof_file_limit() {' \
    'source_snapshot_is_exact "$source_before" 755 "$staged_executable_max_bytes"' \
    'source_snapshot_is_exact "$ipc_probe_before" 755 "$staged_executable_max_bytes"' \
    'source_snapshot_is_exact "$ipc_hook_before" 700 "$proof_file_max_bytes"' \
    'source_snapshot_is_exact "$ipc_hook_before" 750 "$proof_file_max_bytes"' \
    'source_snapshot_is_exact "$ipc_hook_before" 755 "$proof_file_max_bytes"' \
    '[ "$source_before" != "$helper_initial_snapshot" ]' \
    '[ "$ipc_probe_before" != "$ipc_probe_initial_snapshot" ]' \
    '[ "$ipc_hook_before" = "$ipc_hook_initial_snapshot" ]' \
    'prlimit --fsize="$staged_executable_max_bytes:$staged_executable_max_bytes" --' \
    'install_proof_file_limit "$proof_file_max_bytes"' \
    'prlimit --pid "$$" --fsize="$1:$1"' \
    'prlimit --pid "$$" --fsize --raw --noheadings --output SOFT,HARD' \
    '--property=PrivateNetwork=yes' \
    '--property=PrivateMounts=yes' \
    '--property=NoNewPrivileges=yes' \
    '--property=RestrictSUIDSGID=no' \
    '--property=LimitCORE=0' \
    '--property=LimitFSIZE=1048576' \
    '--property=NotifyAccess=main' \
    '--property=FileDescriptorStoreMax=128' \
    '--property=FileDescriptorStorePreserve=yes' \
    '--property=User=0' \
    '--property=Group=0' \
    '--property=SupplementaryGroups=' \
    '--property=CollectMode=inactive' \
    '--property=RuntimeMaxSec=45s' \
    '--property=TimeoutStartSec=45s' \
    '--property=TimeoutStartSec=90s' \
    '--property=TimeoutStopSec=45s' \
    '--service-type=exec' \
    '--property=Restart=no' \
    '--property=RuntimeMaxSec=180s' \
    '--property=StandardOutput=null' \
    '--property=StandardError=null' \
    '--property=KillSignal=SIGTERM' \
    '--json=short' \
    '--description="$unit_ownership_marker"' \
    '--property="CapabilityBoundingSet=$capabilities"' \
    '--property="AmbientCapabilities=$capabilities"' \
    'helper_bind="$temporary_stage/volparossa-helper:/run/volparossa-helper-live-proof:norbind"' \
    'production_helper_bind="$temporary_stage/volparossa-helper:/run/volparossa-helper-production:norbind"' \
    '/usr/bin/setpriv --regid="$agent_gid" --groups="$agent_gid" -- /run/volparossa-helper-live-proof --internal-worker-v3-live-proof' \
    '/usr/bin/setpriv --regid="$agent_gid" --groups="$agent_gid" -- /run/volparossa-helper-production' \
    '--property="BindReadOnlyPaths=$helper_bind $account_binds $system_bus_bind $notify_socket_bind"' \
    '--property="BindReadOnlyPaths=$production_helper_bind $production_probe_bind $production_hook_bind $production_host_network_identity_bind $account_binds $system_bus_bind $notify_socket_bind"' \
    '--property="BindPaths=$production_runtime_bind $production_output_bind"' \
    "--property='ExecSearchPath=/usr/sbin /usr/bin /sbin /bin'" \
    '--property="ExecStartPost=/usr/bin/setpriv --regid=$agent_gid --groups=$agent_gid -- /run/volparossa-helper-production-ipc-hook start $unit_name $agent_uid $agent_gid $operator_gid $worker_uid $worker_gid"' \
    '--property="ExecStopPost=/usr/bin/setpriv --regid=$agent_gid --groups=$agent_gid -- /run/volparossa-helper-production-ipc-hook stop $unit_name $agent_gid"' \
    'install -d -o root -g root -m 2700 "$temporary_stage/production-output"' \
    'production_host_network_identity_file=$temporary_stage/production-host-network.identity' \
    'production_driver_network_identity=$(stat -Lc' \
    '/proc/self/ns/net)' \
    'production_host_network_identity=$(stat -Lc' \
    '/proc/1/ns/net)' \
    '[ "$production_driver_network_identity" = "$production_host_network_identity" ]' \
    'production_host_network_identity_bind="$production_host_network_identity_file:/run/volparossa-helper-production-host-network.identity:norbind"' \
    'vp_capture_run "$production_host_network_identity_file"' \
    'vp_capture_file_is_safe "$production_host_network_identity_file"' \
    '--property=Environment=DBUS_SYSTEM_BUS_ADDRESS=unix:path=/run/dbus/system_bus_socket' \
    'system_bus_socket=/run/dbus/system_bus_socket' \
    'notify_socket=/run/systemd/notify' \
    'notify_socket_bind="$notify_socket:$notify_socket:norbind"' \
    "blocked 'the canonical root-owned systemd notify socket is unavailable'" \
    'host_runtime_directory=/run/volparossa' \
    "blocked 'the disposable host /run/volparossa path must initially be absent'" \
    'state_records='"'"'production_runtime_path accounts namespaces mounts resolver sysctls links addresses routes rules nexthops qdiscs nftables wireguard legacy_ipv4_firewall legacy_ipv6_firewall'"'"'' \
    "failed 'the host /run/volparossa path is not absent at a state fence'" \
    'systemctl show --property=Version --value' \
    "blocked 'execution requires exact systemd v257'" \
    'capture_unit_property Environment "$temporary_stage/unit-environment"' \
    'capture_unit_property ExecSearchPath "$temporary_stage/unit-exec-search-path"' \
    'capture_unit_property CollectMode "$temporary_stage/unit-collect-mode"' \
    'capture_unit_property Type "$temporary_stage/unit-type"' \
    'capture_unit_property RemainAfterExit "$temporary_stage/unit-remain-after-exit"' \
    'capture_unit_property RuntimeMaxUSec "$temporary_stage/unit-runtime-max"' \
    'capture_unit_property ExecMainCode "$temporary_stage/unit-exec-code"' \
    'capture_unit_property ExecSearchPath' \
    '"$temporary_stage/production-exec-search-path"' \
    'capture_unit_property CollectMode' \
    '"$temporary_stage/production-collect-mode"' \
    'capture_unit_property Type "$temporary_stage/production-type"' \
    'capture_unit_property RemainAfterExit' \
    '"$temporary_stage/production-remain-after-exit"' \
    '[ "$observed_exec_search_path" != '"'"'/usr/sbin /usr/bin /sbin /bin'"'"' ]' \
    '[ "$observed_collect_mode" != inactive ]' \
    '[ "$observed_unit_type" != exec ]' \
    '[ "$observed_remain_after_exit" != yes ]' \
    '[ "$observed_runtime_max" != 45s ]' \
    '!= '"'"'/usr/sbin /usr/bin /sbin /bin'"'"' ]' \
    '[ "$production_collect_mode" != inactive ]' \
    '[ "$production_unit_type" != exec ]' \
    '[ "$production_remain_after_exit" != no ]' \
    '!= DBUS_SYSTEM_BUS_ADDRESS=unix:path=/run/dbus/system_bus_socket ]' \
    'parsed_invocation_id=$(jq -ers --arg expected_unit "$unit_name"' \
    'and (.[0] | keys) == ["invocation_id", "unit"]' \
    'unit_invocation_id=$parsed_invocation_id' \
    'unit_owned=yes' \
    'unit_may_own=yes' \
    'unit_may_own=no' \
    'VOLPAROSSA helper live proof transient ownership marker v1' \
    'VOLPAROSSA helper production IPC transient ownership marker v1' \
    'unit_description_matches_marker' \
    'adopt_tentative_unit' \
    '[ "$adopt_attempt" -lt 1000 ]' \
    'unit_invocation_is_current || return 1' \
    'if ! unit_invocation_is_current; then' \
    'forget_unit_ownership' \
    'capture_unit_property Description "$temporary_stage/unit-description"' \
    '[ "$observed_description" != "$unit_ownership_marker" ]' \
    'capture_unit_property NFileDescriptorStore "$temporary_stage/unit-fdstore-count"' \
    'capture_unit_property ControlGroup "$temporary_stage/unit-control-group"' \
    'capture_unit_property Slice "$temporary_stage/unit-slice"' \
    'capture_unit_property Slice "$temporary_stage/production-slice"' \
    'capture_unit_property ControlGroup "$temporary_stage/production-control-group"' \
    'capture_unit_property RuntimeMaxUSec' \
    'capture_unit_property LimitFSIZE "$temporary_stage/production-limit-fsize"' \
    'capture_unit_property LimitFSIZESoft' \
    'capture_unit_property StandardOutput' \
    'capture_unit_property StandardError' \
    '[ "$observed_fdstore_count" != 2 ]' \
    '[ "$production_fdstore_count" != 0 ]' \
    '[ "$production_runtime_max" != 3min ]' \
    '[ "$production_limit_fsize" != 1048576 ]' \
    '[ "$production_limit_fsize_soft" != 1048576 ]' \
    '[ "$production_standard_output" != null ]' \
    '[ "$production_standard_error" != null ]' \
    'identity_launch=$(sed -n '"'"'3p'"'"' "$production_identity")' \
    'identity_launch_image=$(sed -n '"'"'4p'"'"' "$production_identity")' \
    'identity_starttime=$(sed -n '"'"'5p'"'"' "$production_identity")' \
    'identity_process_contract=$(sed -n '"'"'6p'"'"' "$production_identity")' \
    'identity_extra=$(sed -n '"'"'7p'"'"' "$production_identity")' \
    'systemd_launch_record_is_safe "$identity_launch"' \
    'launch_image_record_is_safe' \
    'identity_starttime_prefix=process-starttime-v1=' \
    'expected_process_contract_prefix="process-status-v1=uid:0:0:0:0;gid:$agent_gid:$agent_gid:$agent_gid:$agent_gid;groups:$agent_gid;nnp:1;seccomp:2;caps:00000000002031e0;filters:"' \
    'identity_seccomp_filters=${identity_process_contract#"$expected_process_contract_prefix"}' \
    '[ "${#identity_seccomp_filters}" -gt 10 ]' \
    '[ "$identity_seccomp_filters" -gt 1024 ]' \
    'production_socket_identity_file=$temporary_stage/production-output/socket.identity' \
    'production_lock_identity_file=$temporary_stage/production-output/lock.identity' \
    'production_lock_fd_identity=$(stat -Lc' \
    '/usr/bin/flock -n 9' \
    'systemctl stop --no-block "$unit_name"' \
    'observe_unit_retirement_snapshot' \
    'systemctl show --no-pager' \
    '--property=Job' \
    '[ "$retire_invocation_id" = "$unit_invocation_id" ] || return 1' \
    'systemctl clean --what=fdstore "$unit_name"' \
    '[ "$retire_fdstore_count" -eq 0 ]' \
    '[ "$retire_load_state" = not-found ]' \
    '[ "$retire_attempt" -lt 1200 ]' \
    '[ "$poll_attempt" -ge 2000 ]' \
    'retired_runtime_is_absent' \
    'retired_cgroup_path=/sys/fs/cgroup$retired_control_group' \
    '[ "$retired_attempt" -lt 1200 ]' \
    'retired_starttime_path=/proc/$retired_starttime_pid/stat' \
    '"$retired_process_starttime"' \
    '[ "$poll_attempt" -ge 1000 ]' \
    'systemctl reset-failed "$unit_name"' \
    '--internal-worker-v3-live-proof' \
    'worker_manager_binding_ok=yes' \
    'VOLPAROSSA_HELPER_LIVE_PROOF_FAILURE_STAGE_V1=parent-contract' \
    'VOLPAROSSA_HELPER_LIVE_PROOF_FAILURE_STAGE_V1=runtime-preparation' \
    'VOLPAROSSA_HELPER_LIVE_PROOF_FAILURE_STAGE_V1=worker-spawn' \
    'VOLPAROSSA_HELPER_LIVE_PROOF_FAILURE_STAGE_V1=publication' \
    'VOLPAROSSA_HELPER_LIVE_PROOF_FAILURE_STAGE_V1=retirement-cleanup' \
    'VOLPAROSSA_HELPER_LIVE_WORKER_PROOF_V1=pass' \
    'VOLPAROSSA_HELPER_LIVE_SYSTEMD_FDSTORE_PROOF_V1=pass' \
    '|| [ -s "$temporary_stage/proof.stderr" ]; then' \
    'VOLPAROSSA_HELPER_V3_IPC_BIND_BEFORE_V1=pass' \
    'VOLPAROSSA_HELPER_V3_IPC_FRAME_BOUNDS_V1=pass' \
    'VOLPAROSSA_HELPER_V3_IPC_WIRE_SHAPES_V1=pass' \
    'VOLPAROSSA_HELPER_V3_IPC_WRONG_UID_V1=pass' \
    'VOLPAROSSA_HELPER_V3_IPC_WRONG_GID_V1=pass' \
    'VOLPAROSSA_HELPER_V3_IPC_ROOT_PEER_V1=pass' \
    'VOLPAROSSA_HELPER_V3_IPC_BIND_AFTER_V1=pass' \
    'VOLPAROSSA_HELPER_V3_IPC_CLEAN_SHUTDOWN_V1=pass' \
    'evidence_validator=$script_directory/validate-helper-boundary-evidence-v1.sh' \
    'status --porcelain=v1 --untracked-files=normal' \
    "blocked 'the source worktree must be clean before live evidence execution'" \
    "failed 'the exact clean source revision changed during live execution'" \
    'jq -n -S -c' \
    'install -o root -g root -m 0600 /dev/null "$validator_stdout"' \
    'install -o root -g root -m 0600 /dev/null "$validator_stderr"' \
    '"$evidence_validator" "$report_path" >"$validator_stdout" 2>"$validator_stderr"' \
    'vp_capture_file_is_safe "$restart_report_path"' \
    'install -o root -g root -m 0600 /dev/null "$restart_validator_stdout"' \
    'install -o root -g root -m 0600 /dev/null "$restart_validator_stderr"' \
    'vp_capture_file_is_safe "$restart_validator_stdout"' \
    'vp_capture_file_is_safe "$restart_validator_stderr"' \
    '"$restart_evidence_validator" "$restart_report_path"' \
    '[ "$validator_status" -ne 0 ]' \
    '[ -s "$validator_stdout" ]' \
    '[ -s "$validator_stderr" ]' \
    'validated_report=$(cat "$report_path")' \
    "failed 'the exact clean source revision changed before report publication'" \
    'if ! remove_temporary_stage; then' \
    'printf '\''%s\n'\'' "$validated_report"'
do
    grep -F -- "$required_contract" "$gate" >/dev/null || {
        printf 'missing live helper proof contract: %s\n' "$required_contract" >&2
        exit 1
    }
done
# These are literal gate-source contracts; expansion here would defeat the assertions.
# shellcheck disable=SC2016
if grep -F '"$validator_stdout" "$validator_stderr"' "$gate" >/dev/null \
    || [ "$(grep -Fc 'install -o root -g root -m 0600 /dev/null "$validator_stdout"' "$gate")" -ne 1 ] \
    || [ "$(grep -Fc 'install -o root -g root -m 0600 /dev/null "$validator_stderr"' "$gate")" -ne 1 ]; then
    printf '%s\n' 'private validator captures are not created as two exact files' >&2
    exit 1
fi
# These are literal gate-source contracts; expansion here would defeat them.
# shellcheck disable=SC2016
if grep -F '"$restart_validator_stdout" "$restart_validator_stderr"' \
    "$gate" >/dev/null \
    || [ "$(grep -Fc 'install -o root -g root -m 0600 /dev/null "$restart_validator_stdout"' "$gate")" -ne 1 ] \
    || [ "$(grep -Fc 'install -o root -g root -m 0600 /dev/null "$restart_validator_stderr"' "$gate")" -ne 1 ]; then
    printf '%s\n' \
        'private restart-validator captures are not created as two exact files' >&2
    exit 1
fi
if ! awk '
    /^[[:space:]]*resolver_runtime_uid=\$\(/ { runtime_uid_derived = NR }
    /^[[:space:]]*resolver_runtime_gid=\$\(/ { runtime_gid_derived = NR }
    {
        logical_line = $0
        logical_continues = logical_line ~ /\\[[:space:]]*$/
        sub(/[[:space:]]*\\[[:space:]]*$/, " ", logical_line)
        logical_statement = logical_statement " " logical_line
        if (logical_continues) next
        if (logical_statement ~ /vp_capture_resolver_snapshot \/etc\/resolv[.]conf/) {
            resolver_calls++
            if (index(logical_statement, "\"$resolver_object_capture\"") > 0 \
                && index(logical_statement, "/etc /run") > 0 \
                && index(logical_statement, \
                    "/run/systemd/resolve \"$resolver_runtime_uid\" \"$resolver_runtime_gid\"") \
                    > 0) {
                explicit_authority_call = NR
            }
        }
        logical_statement = ""
    }
    END {
        valid = resolver_calls == 1 && runtime_uid_derived > 0 && runtime_gid_derived > 0
        valid = valid && explicit_authority_call > runtime_uid_derived
        valid = valid && explicit_authority_call > runtime_gid_derived
        if (!valid) exit 1
    }
' "$gate"; then
    printf '%s\n' \
        'live resolver capture lacks one literal runtime authority and derived UID/GID pair' >&2
    exit 1
fi
if ! awk '
    /if \[ "\$proof_ok" != yes \]; then/ { proof_gate = NR }
    /final_source_commit=\$\(git / { source_revalidation = NR }
    /^jq -n -S -c \\/ && report_generation == 0 { report_generation = NR }
    /^"\$evidence_validator" "\$report_path" >/ { report_validation = NR }
    /^validator_status=\$\?$/ { validator_status = NR }
    /if ! vp_capture_file_is_safe "\$validator_stdout"/ { validator_gate = NR }
    /validated_report=\$\(cat "\$report_path"\)/ { retained_report = NR }
    /restart_report_path=\$temporary_stage\/helper-restart-exact-present-evidence-v1[.]json/ {
        restart_generation = NR
    }
    /^"\$restart_evidence_validator" "\$restart_report_path" \\/ {
        restart_validation = NR
    }
    /validated_restart_report=\$\(cat "\$restart_report_path"\)/ {
        retained_restart_report = NR
    }
    /publication_source_commit=\$\(git / { publication_fence = NR }
    /if ! remove_temporary_stage; then/ { stage_removal = NR }
    /^printf '\''%s\\n'\'' "\$validated_report"$/ { publication = NR }
    /^printf '\''%s\\n'\'' "\$validated_restart_report"$/ {
        restart_publication = NR
    }
    END {
        valid = proof_gate > 0 && source_revalidation > 0 && report_generation > 0
        valid = valid && report_validation > 0 && validator_status > 0
        valid = valid && validator_gate > 0 && retained_report > 0
        valid = valid && restart_generation > retained_report
        valid = valid && restart_validation > restart_generation
        valid = valid && retained_restart_report > restart_validation
        valid = valid && publication_fence > 0 && stage_removal > 0 && publication > 0
        valid = valid && restart_publication > publication
        valid = valid && proof_gate < source_revalidation
        valid = valid && source_revalidation < report_generation
        valid = valid && report_generation < report_validation
        valid = valid && report_validation < validator_status
        valid = valid && validator_status < validator_gate
        valid = valid && validator_gate < retained_report
        valid = valid && retained_restart_report < publication_fence
        valid = valid && publication_fence < stage_removal
        valid = valid && stage_removal < publication
        if (!valid) exit 1
    }
' "$gate"; then
    printf '%s\n' 'validated report publication is not ordered after proof and stage removal' >&2
    exit 1
fi
if [ "$(grep -Fc -- '--property=LimitFSIZE=1048576' "$gate")" -ne 4 ]; then
    printf '%s\n' 'all four transient helper invocations do not have the exact file-size limit' >&2
    exit 1
fi
if ! awk '
    /^[[:space:]]*systemd-run \\$/ {
        if (in_run) invalid++
        run_count++
        in_run = 1
        next
    }
    in_run {
        argument_line = $0
        sub(/^[[:space:]]*/, "", argument_line)
        short_option_line = argument_line
        gsub(/[\047\"]/, "", short_option_line)
        if (short_option_line ~ /(^|[[:space:]])-[^-[:space:]]/) invalid++
        if (argument_line ~ /^--/) {
            option_copy = argument_line
            sub(/=.*/, "", option_copy)
            if (gsub(/--/, "", option_copy) != 1) invalid++
            if (argument_line !~ /^--json=/ \
                && argument_line !~ /^--unit=/ \
                && argument_line !~ /^--slice=/ \
                && argument_line !~ /^--description=/ \
                && argument_line !~ /^--service-type=/ \
                && argument_line !~ /^--no-block([[:space:]]|\\|$)/ \
                && argument_line !~ /^--remain-after-exit([[:space:]]|\\|$)/ \
                && argument_line !~ /^--property=/) invalid++
        } else if (argument_line !~ /^\/usr\/bin\/setpriv([[:space:]]|$)/ \
            && argument_line !~ /^>/ \
            && argument_line !~ /^2>/) invalid++
        if (index($0, "--ignore-failure") > 0 \
            || index($0, "--collect") > 0 \
            || index($0, "--wait") > 0 \
            || index($0, "--pipe") > 0 \
            || index($0, "--pty") > 0 \
            || index($0, "--scope") > 0 \
            || index($0, "--shell") > 0) invalid++

        if (index($0, "--no-block") > 0) no_block_assignments[run_count]++
        if ($0 ~ /^[[:space:]]*--no-block \\$/) exact_no_block[run_count]++

        if (index($0, "--service-type=") > 0) type_assignments[run_count]++
        if ($0 ~ /^[[:space:]]*--service-type=exec \\$/) {
            exact_exec_types[run_count]++
        }
        if ($0 ~ /^[[:space:]]*--service-type=simple \\$/) {
            exact_simple_types[run_count]++
        }
        if (index($0, "Type=") > 0 \
            && index($0, "--service-type=") == 0) invalid++

        if (index($0, "CollectMode=") > 0) collect_assignments[run_count]++
        if ($0 ~ /^[[:space:]]*--property=CollectMode=inactive \\$/) {
            exact_collect_modes[run_count]++
        }

        if (index($0, "--slice=") > 0) slice_assignments[run_count]++
        if ($0 ~ /^[[:space:]]*--slice=system\.slice \\$/) {
            exact_worker_slice[run_count]++
        }

        if (index($0, "--remain-after-exit") > 0 \
            || index($0, "RemainAfterExit=") > 0) remain_assignments[run_count]++
        if ($0 ~ /^[[:space:]]*--remain-after-exit \\$/) exact_remain[run_count]++

        if (index($0, "RuntimeMaxSec=") > 0) runtime_assignments[run_count]++
        if ($0 ~ /^[[:space:]]*--property=RuntimeMaxSec=45s \\$/) {
            exact_worker_runtime[run_count]++
        }
        if ($0 ~ /^[[:space:]]*--property=RuntimeMaxSec=180s \\$/) {
            exact_production_runtime[run_count]++
        }
        if ($0 ~ /^[[:space:]]*--property=RuntimeMaxSec=240s \\$/) {
            exact_restart_runtime[run_count]++
        }
        if ($0 ~ /^[[:space:]]*--property=RuntimeMaxSec=360s \\$/) {
            exact_may_own_runtime[run_count]++
        }

        if ($0 !~ /\\[[:space:]]*$/) {
            in_run = 0
            run_end_count++
        }
    }
    END {
        valid = !in_run && invalid == 0 && run_count == 4 && run_end_count == 4
        for (run = 1; run <= 4; run++) {
            valid = valid && type_assignments[run] == 1
            valid = valid && collect_assignments[run] == 1
            valid = valid && exact_collect_modes[run] == 1
            valid = valid && runtime_assignments[run] == 1
        }
        valid = valid && exact_exec_types[1] == 1 && exact_simple_types[1] == 0
        valid = valid && exact_exec_types[2] == 1 && exact_simple_types[2] == 0
        valid = valid && exact_exec_types[3] == 1 && exact_simple_types[3] == 0
        valid = valid && exact_exec_types[4] == 0 && exact_simple_types[4] == 1
        valid = valid && remain_assignments[1] == 1 && exact_remain[1] == 1
        valid = valid && remain_assignments[2] == 0 && exact_remain[2] == 0
        valid = valid && remain_assignments[3] == 0 && exact_remain[3] == 0
        valid = valid && remain_assignments[4] == 0 && exact_remain[4] == 0
        valid = valid && slice_assignments[1] == 1 && exact_worker_slice[1] == 1
        valid = valid && slice_assignments[2] == 1 && exact_worker_slice[2] == 1
        valid = valid && slice_assignments[3] == 1 && exact_worker_slice[3] == 1
        valid = valid && slice_assignments[4] == 1 && exact_worker_slice[4] == 1
        valid = valid && no_block_assignments[1] == 0 && exact_no_block[1] == 0
        valid = valid && no_block_assignments[2] == 0 && exact_no_block[2] == 0
        valid = valid && no_block_assignments[3] == 1 && exact_no_block[3] == 1
        valid = valid && no_block_assignments[4] == 1 && exact_no_block[4] == 1
        valid = valid && exact_worker_runtime[1] == 1
        valid = valid && exact_worker_runtime[2] == 0
        valid = valid && exact_worker_runtime[3] == 0
        valid = valid && exact_worker_runtime[4] == 0
        valid = valid && exact_production_runtime[1] == 0
        valid = valid && exact_production_runtime[2] == 1
        valid = valid && exact_production_runtime[3] == 0
        valid = valid && exact_production_runtime[4] == 0
        valid = valid && exact_restart_runtime[1] == 0
        valid = valid && exact_restart_runtime[2] == 0
        valid = valid && exact_restart_runtime[3] == 1
        valid = valid && exact_restart_runtime[4] == 0
        valid = valid && exact_may_own_runtime[1] == 0
        valid = valid && exact_may_own_runtime[2] == 0
        valid = valid && exact_may_own_runtime[3] == 0
        valid = valid && exact_may_own_runtime[4] == 1
        if (!valid) exit 1
    }
' "$gate"; then
    printf '%s\n' \
        'transient systemd-run argument blocks are not exact, blocking, and fail-observable' >&2
    exit 1
fi
# These are literal gate-source contracts; expansion here would defeat the checks.
# shellcheck disable=SC2016
if [ "$(grep -Fc -- '--property=RuntimeMaxSec=45s' "$gate")" -ne 1 ] \
    || [ "$(grep -Fc -- \
        'capture_unit_property RuntimeMaxUSec "$temporary_stage/unit-runtime-max"' \
        "$gate")" -ne 1 ] \
    || [ "$(grep -Fc -- '[ "$observed_runtime_max" != 45s ]' "$gate")" -ne 1 ]; then
    printf '%s\n' 'the diagnostic worker runtime is not bounded and read back exactly' >&2
    exit 1
fi
# This is a literal gate-source contract, not a test-shell expansion.
# shellcheck disable=SC2016
if [ "$(grep -Fc -- \
    'prlimit --fsize="$staged_executable_max_bytes:$staged_executable_max_bytes" --' \
    "$gate")" -ne 2 ]; then
    printf '%s\n' 'both large staging copies do not have the exact 128 MiB limit' >&2
    exit 1
fi
# This is a literal gate-source regular expression.
# shellcheck disable=SC1003,SC2016
if [ "$(grep -Ec '^install_proof_file_limit "\$proof_file_max_bytes" \\' \
    "$gate")" -ne 1 ]; then
    printf '%s\n' 'the proof process does not install its exact 1 MiB limit once' >&2
    exit 1
fi
if [ "$(grep -Ec '^[[:space:]]*prlimit --pid "\$\$" --fsize=' "$gate")" -ne 1 ]; then
    printf '%s\n' 'the proof source changes its own file-size limit more than once' >&2
    exit 1
fi
if ! awk '
    /failed '\''the bounded helper staging copy failed'\''/ { helper_copy = NR }
    /failed '\''the real helper changed while copied or the staged image is unsafe'\''/ {
        helper_fence = NR
    }
    /failed '\''the bounded production IPC probe staging copy failed'\''/ {
        probe_copy = NR
    }
    /failed '\''the production IPC probe changed while copied or its staged image is unsafe'\''/ {
        probe_fence = NR
    }
    /^install_proof_file_limit "\$proof_file_max_bytes" \\/ { proof_limit = NR }
    /^ipc_hook_before=/ { hook_copy = NR }
    /'\''root:x:0:0:root:\/root:\/bin\/sh'\''/ { account_write = NR }
    /^capture_host_state "\$temporary_stage\/before"$/ { host_capture = NR }
    /^[[:space:]]*systemd-run \\/ && first_unit == 0 { first_unit = NR }
    END {
        valid = helper_copy > 0 && helper_fence > 0 && probe_copy > 0
        valid = valid && probe_fence > 0 && proof_limit > 0 && hook_copy > 0
        valid = valid && account_write > 0 && host_capture > 0 && first_unit > 0
        valid = valid && helper_copy < helper_fence && helper_fence < probe_copy
        valid = valid && probe_copy < probe_fence && probe_fence < proof_limit
        valid = valid && proof_limit < hook_copy && hook_copy < account_write
        valid = valid && account_write < host_capture && host_capture < first_unit
        if (!valid) exit 1
    }
' "$gate"; then
    printf '%s\n' 'the two-tier staging and proof-file limits are ordered incorrectly' >&2
    exit 1
fi
for exact_cgroup_property in \
    '--property=ProtectControlGroupsEx=strict' \
    '--property=Delegate=no' \
    '--property=PrivatePIDs=no' \
    "--property='SystemCallFilter=@system-service @network-io seccomp'" \
    "--property='SystemCallFilter=~@mount'"
do
    if [ "$(grep -Fc -- "$exact_cgroup_property" "$gate")" -ne 4 ]; then
        printf 'all four transient helper invocations lack exact cgroup isolation: %s\n' \
            "$exact_cgroup_property" >&2
        exit 1
    fi
done
transient_slice_contract_is_exact() {
    [ "$#" -eq 1 ] || return 1
    worker_slice_source=$1
    [ -f "$worker_slice_source" ] && [ ! -L "$worker_slice_source" ] || return 1
    awk '
        /^[[:space:]]+--slice=system\.slice \\$/ {
            slice_assignment++
            if (slice_assignment == 1) worker_slice_assignment_line = NR
            if (slice_assignment == 2) production_slice_assignment_line = NR
            if (slice_assignment == 3) restart_slice_assignment_line = NR
            if (slice_assignment == 4) may_own_slice_assignment_line = NR
        }
        /^if capture_unit_property ActiveState "\$temporary_stage\/unit-active-state"; then$/ {
            terminal_read++
            terminal_read_line = NR
        }
        /^if capture_unit_property ControlGroup "\$temporary_stage\/unit-control-group"; then$/ {
            terminal_control_group_read++
            terminal_control_group_read_line = NR
        }
        /^if capture_unit_property Slice "\$temporary_stage\/unit-slice"; then$/ {
            worker_slice_read++
            worker_slice_read_line = NR
        }
        /^if \[ -n "\$observed_terminal_control_group" \]; then$/ {
            terminal_control_group_empty++
            terminal_control_group_empty_line = NR
        }
        /^if \[ "\$observed_slice" != system\.slice \]; then$/ {
            worker_slice_requirement++
            worker_slice_requirement_line = NR
        }
        /^worker_control_group=\/system\.slice\/\$unit_name$/ {
            cgroup_derivation++
            cgroup_derivation_line = NR
        }
        /^    if capture_unit_property Slice "\$temporary_stage\/production-slice"; then$/ {
            production_slice_read++
            production_slice_read_line = NR
        }
        /\|\| \[ "\$production_slice" != system\.slice \] \\$/ {
            production_slice_requirement++
            production_slice_requirement_line = NR
        }
        /capture_unit_property ControlGroup "\$temporary_stage\/production-control-group"/ {
            production_control_group_read++
            production_control_group_read_line = NR
        }
        /^if ! retire_unit; then$/ {
            retirement++
            retirement_line = NR
        }
        END {
            valid = slice_assignment == 4 && terminal_read == 1
            valid = valid && worker_slice_read == 1 && worker_slice_requirement == 1
            valid = valid && terminal_control_group_read == 1
            valid = valid && terminal_control_group_empty == 1 && cgroup_derivation == 1
            valid = valid && production_slice_read == 1
            valid = valid && production_slice_requirement == 1
            valid = valid && production_control_group_read == 1 && retirement == 1
            valid = valid && worker_slice_assignment_line < terminal_read_line
            valid = valid && terminal_read_line < terminal_control_group_read_line
            valid = valid && terminal_control_group_read_line < worker_slice_read_line
            valid = valid && worker_slice_read_line < terminal_control_group_empty_line
            valid = valid && terminal_control_group_empty_line < worker_slice_requirement_line
            valid = valid && worker_slice_requirement_line < cgroup_derivation_line
            valid = valid && cgroup_derivation_line < retirement_line
            valid = valid && retirement_line < production_slice_assignment_line
            valid = valid && production_slice_assignment_line < production_slice_read_line
            valid = valid && production_slice_read_line < production_slice_requirement_line
            valid = valid && production_slice_requirement_line < production_control_group_read_line
            valid = valid && production_control_group_read_line < restart_slice_assignment_line
            valid = valid && restart_slice_assignment_line < may_own_slice_assignment_line
            if (!valid) exit 1
        }
    ' "$worker_slice_source"
}
if ! transient_slice_contract_is_exact "$gate"; then
    printf '%s\n' \
        'the transient slice, terminal cgroup and derived retirement contracts are not exact' >&2
    exit 1
fi
# These mutations must retain literal gate variables; the contract, not this
# test shell, expands them.
# shellcheck disable=SC2016
for worker_slice_mutation in \
    assignment terminal-control-read terminal-empty readback requirement derivation \
    production-readback production-requirement
do
    worker_slice_mutant=$temporary_directory/worker-slice-$worker_slice_mutation.sh
    case $worker_slice_mutation in
        assignment)
            sed '0,/--slice=system\.slice/s//--slice=user.slice/' \
                "$gate" >"$worker_slice_mutant"
            ;;
        terminal-control-read)
            sed '0,/capture_unit_property ControlGroup "\$temporary_stage\/unit-control-group"/s//capture_unit_property Slice "$temporary_stage\/unit-control-group"/' \
                "$gate" >"$worker_slice_mutant"
            ;;
        terminal-empty)
            sed '0,/\[ -n "\$observed_terminal_control_group" \]/s//[ -z "$observed_terminal_control_group" ]/' \
                "$gate" >"$worker_slice_mutant"
            ;;
        readback)
            sed '0,/capture_unit_property Slice "\$temporary_stage\/unit-slice"/s//capture_unit_property ControlGroup "$temporary_stage\/unit-slice"/' \
                "$gate" >"$worker_slice_mutant"
            ;;
        requirement)
            sed '0,/"\$observed_slice" != system\.slice/s//"$observed_slice" != user.slice/' \
                "$gate" >"$worker_slice_mutant"
            ;;
        derivation)
            sed '0,/worker_control_group=\/system\.slice\/\$unit_name/s//worker_control_group=\/user.slice\/$unit_name/' \
                "$gate" >"$worker_slice_mutant"
            ;;
        production-readback)
            sed '0,/capture_unit_property Slice "\$temporary_stage\/production-slice"/s//capture_unit_property ControlGroup "$temporary_stage\/production-slice"/' \
                "$gate" >"$worker_slice_mutant"
            ;;
        production-requirement)
            sed '0,/"\$production_slice" != system\.slice/s//"$production_slice" != user.slice/' \
                "$gate" >"$worker_slice_mutant"
            ;;
        *) exit 1 ;;
    esac
    chmod 0600 "$worker_slice_mutant"
    if transient_slice_contract_is_exact "$worker_slice_mutant"; then
        printf 'worker slice contract accepted mutation: %s\n' \
            "$worker_slice_mutation" >&2
        exit 1
    fi
done
if [ "$(grep -Fc -- '--property=RestrictSUIDSGID=no' "$gate")" -ne 4 ] \
    || grep -F -- '--property=RestrictSUIDSGID=yes' "$gate" >/dev/null \
    || [ "$(grep -Fc -- \
        "capture_unit_property RestrictSUIDSGID \\" "$gate")" -ne 2 ] \
    || [ "$(grep -Fc -- 'restrict_suid_sgid" != no ]' "$gate")" -ne 2 ]; then
    printf '%s\n' \
        'all transient helpers must disable the v257 openat2-incompatible restriction' >&2
    exit 1
fi
if grep -F -- 'ProtectControlGroups=' "$gate" >/dev/null; then
    printf '%s\n' 'a transient helper still assigns the boolean-only legacy cgroup property' >&2
    exit 1
fi
if [ "$(grep -Fc -- "--property='ExecSearchPath=/usr/sbin /usr/bin /sbin /bin'" "$gate")" -ne 4 ]; then
    printf '%s\n' 'all four transient helper invocations lack the exact fixed executable search path' >&2
    exit 1
fi
# These are literal gate-source contracts; expansion here would defeat the checks.
# shellcheck disable=SC1003,SC2016
if [ "$(grep -Fc 'notify_socket=/run/systemd/notify' "$gate")" -ne 1 ] \
    || [ "$(grep -Fc 'if [ ! -S "$notify_socket" ] || [ -L "$notify_socket" ] \' \
        "$gate")" -ne 1 ] \
    || [ "$(grep -Fc "stat -Lc '%F:%u:%g:%a:%h' \"\$notify_socket\" 2>/dev/null || true" \
        "$gate")" -ne 1 ] \
    || [ "$(grep -Fc "!= 'socket:0:0:777:1' ]; then" "$gate")" -ne 1 ] \
    || [ "$(grep -Fc 'notify_socket_bind="$notify_socket:$notify_socket:norbind"' \
        "$gate")" -ne 1 ] \
    || [ "$(grep -Fc '$notify_socket_bind' "$gate")" -ne 4 ]; then
    printf '%s\n' 'the exact canonical systemd notify-socket preflight and four binds are not pinned' >&2
    exit 1
fi
# These are literal source assignments; expansion here would defeat the check.
# shellcheck disable=SC2016
for exact_private_binding in \
    'helper_bind="$temporary_stage/volparossa-helper:/run/volparossa-helper-live-proof:norbind"' \
    'production_helper_bind="$temporary_stage/volparossa-helper:/run/volparossa-helper-production:norbind"'
do
    if [ "$(grep -Fc -- "$exact_private_binding" "$gate")" -ne 1 ]; then
        printf '%s\n' 'a transient helper private bind is absent or duplicated' >&2
        exit 1
    fi
done
# These are literal gate-source contracts; expansion here would defeat the checks.
# shellcheck disable=SC1003,SC2016
if [ "$(grep -Fc \
    '/usr/bin/setpriv --regid="$agent_gid" --groups="$agent_gid" -- /run/volparossa-helper-live-proof --internal-worker-v3-live-proof \' \
    "$gate")" -ne 1 ] \
    || [ "$(grep -Fc \
        '/usr/bin/setpriv --regid="$agent_gid" --groups="$agent_gid" -- /run/volparossa-helper-production \' \
        "$gate")" -ne 1 ] \
    || [ "$(grep -Fc \
        '/usr/bin/setpriv --regid="$agent_gid" --groups="$agent_gid" -- /run/volparossa-helper-restart-launcher \' \
        "$gate")" -ne 2 ]; then
    printf '%s\n' 'transient helper credential trampolines are not exact' >&2
    exit 1
fi
# PID 1 must never resolve the deliberately host-absent staged GID. The exact
# trampoline is the sole authority that may install it after the private account
# binds exist, while the helper parent contract proves the resulting identity.
unit_credential_source_contract_is_exact() {
    [ "$#" -eq 1 ] || return 1
    credential_contract_source=$1
    [ -f "$credential_contract_source" ] \
        && [ ! -L "$credential_contract_source" ] || return 1
    awk '
        /^[[:space:]]+--property=User=/ {
            user++
            if ($0 ~ /^[[:space:]]+--property=User=0 \\$/) exact_user++
        }
        /^[[:space:]]+--property=Group=/ {
            group++
            if ($0 ~ /^[[:space:]]+--property=Group=0 \\$/) exact_group++
        }
        /^[[:space:]]+--property=SupplementaryGroups=/ {
            supplementary++
            if ($0 ~ /^[[:space:]]+--property=SupplementaryGroups= \\$/) {
                exact_supplementary++
            }
        }
        END {
            valid = user == 4 && exact_user == 4
            valid = valid && group == 4 && exact_group == 4
            valid = valid && supplementary == 4 && exact_supplementary == 4
            if (!valid) exit 1
        }
    ' "$credential_contract_source"
}
# This is a literal gate-source contract; expansion would defeat the check.
# shellcheck disable=SC2016
if ! unit_credential_source_contract_is_exact "$gate" \
    || grep -F -- '--property=Group="$agent_gid"' "$gate" >/dev/null; then
    printf '%s\n' 'transient units do not use exact host-resolvable root/root credentials' >&2
    exit 1
fi
for credential_mutation in user-suffix group-suffix supplementary-value
do
    credential_mutant=$temporary_directory/credential-$credential_mutation.sh
    case $credential_mutation in
        user-suffix)
            sed '0,/--property=User=0/s//--property=User=00/' \
                "$gate" >"$credential_mutant"
            ;;
        group-suffix)
            sed '0,/--property=Group=0/s//--property=Group=00/' \
                "$gate" >"$credential_mutant"
            ;;
        supplementary-value)
            sed '0,/--property=SupplementaryGroups=/s//--property=SupplementaryGroups=0/' \
                "$gate" >"$credential_mutant"
            ;;
        *) exit 1 ;;
    esac
    chmod 0600 "$credential_mutant"
    if unit_credential_source_contract_is_exact "$credential_mutant"; then
        printf 'transient credential contract accepted mutation: %s\n' \
            "$credential_mutation" >&2
        exit 1
    fi
done
# These are literal gate-source contracts; expansion here would defeat the checks.
# shellcheck disable=SC2016
if [ "$(grep -Fc 'setpriv_path=/usr/bin/setpriv' "$gate")" -ne 1 ] \
    || [ "$(grep -Fc '[ "$(command -v setpriv)" != "$setpriv_path" ]' "$gate")" -ne 1 ] \
    || [ "$(grep -Fc "stat -Lc '%F:%u:%g:%a:%h' \"\$setpriv_path\" 2>/dev/null || true" \
        "$gate")" -ne 1 ] \
    || [ "$(grep -Fc "!= 'regular file:0:0:755:1' ]; then" "$gate")" -ne 3 ] \
    || [ "$(grep -Fc \
        "blocked 'the fixed root-owned setpriv credential trampoline is unavailable'" \
        "$gate")" -ne 1 ]; then
    printf '%s\n' 'the fixed root-owned setpriv credential trampoline is not pinned' >&2
    exit 1
fi
# This is a literal gate-source contract; expansion would defeat the check.
# shellcheck disable=SC2016
if [ "$(grep -Fc 'busctl_path=/usr/bin/busctl' "$gate")" -ne 1 ] \
    || [ "$(grep -Fc '[ "$(command -v busctl)" != "$busctl_path" ]' "$gate")" -ne 1 ] \
    || [ "$(grep -Fc "stat -Lc '%F:%u:%g:%a:%h' \"\$busctl_path\" 2>/dev/null || true" \
        "$gate")" -ne 1 ] \
    || [ "$(grep -Fc \
        "blocked 'the fixed root-owned systemd bus client is unavailable'" \
        "$gate")" -ne 1 ]; then
    printf '%s\n' 'the fixed root-owned systemd bus client is not pinned' >&2
    exit 1
fi
for cgroup_assignment_contract in \
    'ProtectControlGroupsEx=:4' \
    'Delegate=:4' \
    'PrivatePIDs=:4' \
    'SystemCallFilter=:8'
do
    assignment_key=${cgroup_assignment_contract%:*}
    expected_count=${cgroup_assignment_contract##*:}
    observed_count=$(grep -Fc -- "$assignment_key" "$gate")
    if [ "$observed_count" -ne "$expected_count" ]; then
        printf 'transient helper profiles contain extra cgroup assignments: %s expected %s, got %s\n' \
            "$assignment_key" "$expected_count" "$observed_count" >&2
        exit 1
    fi
done

# The production hook is root inside a private /run. Query typed properties
# through the explicit policy-mediated system bus and never widen the sandbox
# with systemd's privileged private manager socket.
# These are literal hook-source contracts; expansion would defeat the checks.
# shellcheck disable=SC2016
if [ "$(grep -xc 'system_bus_address=unix:path=/run/dbus/system_bus_socket' \
        "$ipc_hook")" -ne 1 ] \
    || [ "$(grep -Fc '/usr/bin/busctl' "$ipc_hook")" -ne 8 ] \
    || [ "$(grep -Fc -- '--address="$system_bus_address"' "$ipc_hook")" -ne 8 ] \
    || [ "$(grep -Fc 'GetUnit s "$1" 2>/dev/null)' "$ipc_hook")" -ne 1 ] \
    || [ "$(grep -Fc 'DumpFileDescriptorStore 2>/dev/null)' \
        "$ipc_hook")" -ne 3 ] \
    || grep -F -- 'SYSTEMCTL_FORCE_BUS' "$ipc_hook" >/dev/null \
    || grep -F -- 'systemctl ' "$ipc_hook" >/dev/null \
    || grep -F -- '/run/systemd/private' "$gate" >/dev/null \
    || grep -F -- '/run/systemd/private' "$ipc_hook" >/dev/null; then
    printf '%s\n' \
        'production hook does not use the exact policy-mediated systemd bus' >&2
    exit 1
fi
# These patterns are also literal hook-source contracts; shell expansion would weaken the check.
# shellcheck disable=SC2016
if [ "$(grep -Fc 'capture_fdstore_descriptor_identity' "$ipc_hook")" -ne 9 ] \
    || [ "$(grep -Fc 'unit_fdstore_exact_active_custody' "$ipc_hook")" -ne 6 ] \
    || [ "$(grep -Fc 'unit_fdstore_prior_custody_is_absent' "$ipc_hook")" -ne 4 ] \
    || [ "$(grep -Fc 'fdstore_dump_exact_custody_name' "$ipc_hook")" -ne 2 ] \
    || [ "$(grep -Fc 'prove-settled-journal' "$ipc_hook")" -ne 2 ] \
    || [ "$(grep -Fc \
        'hook_descriptor_status_flags=$((hook_descriptor_status_flags & ~524288 & ~32768))' \
        "$ipc_hook")" -ne 1 ]; then
    printf '%s\n' \
        'production hook does not bind all active, restart and settled custody cycles exactly' >&2
    exit 1
fi

# Debian 13 systemd v257 exposes the service launch command through two
# differently typed ten-field tuples. Exercise the exact parser against both
# shapes and representative substitutions before trusting the source contract.
hook_launch_parser_functions=$temporary_directory/hook-launch-parser-functions.sh
{
    sed -n '/^systemd_exec_record_from_json() {$/,/^}$/p' "$ipc_hook"
    sed -n '/^process_starttime_from_stat() {$/,/^}$/p' "$ipc_hook"
    sed -n '/^capture_process_starttime() {$/,/^}$/p' "$ipc_hook"
    sed -n '/^capture_traced_process_starttime() {$/,/^}$/p' "$ipc_hook"
} >"$hook_launch_parser_functions"
if [ "$(grep -c '^systemd_exec_record_from_json() {$' \
        "$hook_launch_parser_functions")" -ne 1 ] \
    || [ "$(grep -c '^process_starttime_from_stat() {$' \
        "$hook_launch_parser_functions")" -ne 1 ] \
    || [ "$(grep -c '^capture_process_starttime() {$' \
        "$hook_launch_parser_functions")" -ne 1 ] \
    || [ "$(grep -c '^capture_traced_process_starttime() {$' \
        "$hook_launch_parser_functions")" -ne 1 ]; then
    printf '%s\n' 'production launch parsers are not uniquely extractable' >&2
    exit 1
fi
sh -n "$hook_launch_parser_functions"
# shellcheck disable=SC2034,SC2317
exercise_hook_launch_parsers() (
    number_is_safe() {
        [ "$#" -eq 1 ] || return 1
        case $1 in
            ''|0|0*|*[!0-9]*) return 1 ;;
            *) [ "${#1}" -le 10 ] && [ "$1" -le 4294967294 ] ;;
        esac
    }
    production_helper=/run/volparossa-helper-production
    restart_launcher=/run/volparossa-helper-restart-launcher
    # shellcheck disable=SC1090
    . "$hook_launch_parser_functions"
    basic='{"type":"a(sasbttttuii)","data":[["/usr/bin/setpriv",["/usr/bin/setpriv","--regid=61000","--groups=61000","--","/run/volparossa-helper-production"],false,123456789,234567890,0,0,4242,0,0]]}'
    extended='{"type":"a(sasasttttuii)","data":[["/usr/bin/setpriv",["/usr/bin/setpriv","--regid=61000","--groups=61000","--","/run/volparossa-helper-production"],[],123456789,234567890,0,0,4242,0,0]]}'
    expected='systemd-launch-v1=pid:4242;gid:61000;start-realtime:123456789;start-monotonic:234567890'
    [ "$(systemd_exec_record_from_json \
        "$basic" basic 4242 61000 'a(sasbttttuii)' \
        "$production_helper")" = "$expected" ]
    [ "$(systemd_exec_record_from_json \
        "$extended" extended 4242 61000 'a(sasasttttuii)' \
        "$production_helper")" = "$expected" ]
    restart_basic=$(printf '%s' "$basic" \
        | sed 's#/run/volparossa-helper-production#/run/volparossa-helper-restart-launcher#')
    [ "$(systemd_exec_record_from_json \
        "$restart_basic" basic 4242 61000 'a(sasbttttuii)' \
        "$restart_launcher")" = "$expected" ]
    if systemd_exec_record_from_json \
        "$basic" basic 4242 61000 'a(sasbttttuii)' \
        "$restart_launcher" >/dev/null 2>&1 \
        || systemd_exec_record_from_json \
            "$restart_basic" basic 4242 61000 'a(sasbttttuii)' \
            "$production_helper" >/dev/null 2>&1 \
        || systemd_exec_record_from_json \
            "$basic" basic 4242 61000 'a(sasbttttuii)' \
            /usr/bin/env >/dev/null 2>&1; then
        printf '%s\n' 'production launch parser accepted a substituted entrypoint' >&2
        exit 1
    fi
    for mutation in wrong-path wrong-argument wrong-gid wrong-pid wrong-type \
        wrong-flag nonzero-stop nonzero-status duplicate-document
    do
        case $mutation in
            wrong-path) candidate=$(printf '%s' "$basic" | sed 's#/usr/bin/setpriv#/usr/bin/env#') ;;
            wrong-argument) candidate=$(printf '%s' "$basic" | sed 's/"--",/"--bad",/') ;;
            wrong-gid) candidate=$(printf '%s' "$basic" | sed 's/--groups=61000/--groups=61001/') ;;
            wrong-pid) candidate=$(printf '%s' "$basic" | sed 's/,4242,0,0/,4243,0,0/') ;;
            wrong-type) candidate=$(printf '%s' "$basic" | sed 's/a(sasbttttuii)/a(sasasttttuii)/') ;;
            wrong-flag) candidate=$(printf '%s' "$basic" | sed 's/],false,/],true,/' ) ;;
            nonzero-stop) candidate=$(printf '%s' "$basic" | sed 's/,234567890,0,0,/,234567890,1,0,/') ;;
            nonzero-status) candidate=$(printf '%s' "$basic" | sed 's/,4242,0,0]]/,4242,0,1]]/') ;;
            duplicate-document) candidate=$(printf '%s\n%s' "$basic" "$basic") ;;
            *) exit 99 ;;
        esac
        if systemd_exec_record_from_json \
            "$candidate" basic 4242 61000 'a(sasbttttuii)' \
            "$production_helper" >/dev/null 2>&1; then
            printf 'production launch parser accepted mutation: %s\n' "$mutation" >&2
            exit 1
        fi
    done

    valid_stat=$(awk 'BEGIN {
        printf "4242 (worker ) name) S"
        for (field = 4; field <= 21; field++) printf " %d", field
        printf " 98765"
        for (field = 23; field <= 52; field++) printf " 0"
    }')
    [ "$(process_starttime_from_stat "$valid_stat" 4242)" = 98765 ]
    embedded_close_stat=$(printf '%s' "$valid_stat" | sed 's/worker ) name/worker ) name ) tail/')
    [ "$(process_starttime_from_stat "$embedded_close_stat" 4242)" = 98765 ]
    traced_stat=$(printf '%s' "$valid_stat" | sed 's/) S /) t /')
    [ "$(process_starttime_from_stat "$traced_stat" 4242 traced)" = 98765 ]
    if process_starttime_from_stat "$traced_stat" 4242 >/dev/null 2>&1 \
        || process_starttime_from_stat "$valid_stat" 4242 traced \
            >/dev/null 2>&1 \
        || process_starttime_from_stat "$traced_stat" 4242 active \
            >/dev/null 2>&1 \
        || process_starttime_from_stat \
            "$(printf '%s' "$valid_stat" | sed 's/) S /) T /')" \
            4242 traced >/dev/null 2>&1; then
        printf '%s\n' \
            'process starttime parser did not isolate the exact ptrace stop' >&2
        exit 1
    fi
    for invalid_stat in \
        "$(printf '%s' "$valid_stat" | sed 's/^4242 /4243 /')" \
        "$(printf '%s' "$valid_stat" | sed 's/) S /) Z /')" \
        "$(printf '%s' "$valid_stat" | sed 's/) S /) S  /')" \
        "$(printf '%s' "$valid_stat" | sed 's/ 98765 / 0 /')" \
        "$(printf '%s' "$valid_stat" | sed 's/ 98765 / 123456789012345678901 /')" \
        "$(printf '%s\n%s' "$valid_stat" "$valid_stat")"
    do
        if process_starttime_from_stat "$invalid_stat" 4242 >/dev/null 2>&1; then
            printf '%s\n' 'process starttime parser accepted a malformed stat record' >&2
            exit 1
        fi
    done
    current_starttime=$(capture_process_starttime "$$")
    case $current_starttime in
        ''|0|0*|*[!0-9]*) exit 1 ;;
    esac
    if capture_traced_process_starttime "$$" >/dev/null 2>&1; then
        printf '%s\n' 'traced starttime capture accepted an active process' >&2
        exit 1
    fi

)
exercise_hook_launch_parsers || {
    printf '%s\n' 'production launch parser behavior is not exact' >&2
    exit 1
}

# Parent descriptors are kernel indexes, so canonical FD zero is valid even
# though the PID/UID/GID validator deliberately rejects zero. Exercise that
# boundary and the pidfd record parser independently of a live privileged run.
hook_custody_parser_functions=$temporary_directory/hook-custody-parser-functions.sh
{
    sed -n '/^number_is_safe() {$/,/^}$/p' "$ipc_hook"
    sed -n '/^fd_number_is_safe() {$/,/^}$/p' "$ipc_hook"
    sed -n '/^pidfd_record_from_fdinfo() {$/,/^}$/p' "$ipc_hook"
    sed -n '/^capture_fdstore_descriptor_identity() {$/,/^}$/p' "$ipc_hook"
    sed -n '/^fdstore_dump_exact_custody_name() {$/,/^}$/p' "$ipc_hook"
} >"$hook_custody_parser_functions"
if [ "$(grep -c '^number_is_safe() {$' "$hook_custody_parser_functions")" -ne 1 ] \
    || [ "$(grep -c '^fd_number_is_safe() {$' \
        "$hook_custody_parser_functions")" -ne 1 ] \
    || [ "$(grep -c '^pidfd_record_from_fdinfo() {$' \
        "$hook_custody_parser_functions")" -ne 1 ] \
    || [ "$(grep -c '^capture_fdstore_descriptor_identity() {$' \
        "$hook_custody_parser_functions")" -ne 1 ] \
    || [ "$(grep -c '^fdstore_dump_exact_custody_name() {$' \
        "$hook_custody_parser_functions")" -ne 1 ]; then
    printf '%s\n' 'worker custody parsers are not uniquely extractable' >&2
    exit 1
fi
sh -n "$hook_custody_parser_functions"
# shellcheck disable=SC1090,SC2317
exercise_hook_custody_parsers() (
    . "$hook_custody_parser_functions"
    for valid_fd in 0 1 4294967294; do
        fd_number_is_safe "$valid_fd"
    done
    for invalid_fd in '' 00 01 -1 1x 4294967295 99999999999; do
        if fd_number_is_safe "$invalid_fd"; then
            exit 1
        fi
    done
    if number_is_safe 0; then
        exit 1
    fi

    valid_pidfd_info=$(printf '%s\n' \
        'pos: 0' \
        'flags: 02000002' \
        'mnt_id: 5' \
        'ino: 123' \
        'Pid: 4242' \
        'NSpid: 4242')
    [ "$(pidfd_record_from_fdinfo "$valid_pidfd_info" 0 4242)" = \
        'pidfd-v1=fd:0;pid:4242' ]
    for invalid_pidfd_info in \
        "$(printf '%s\n' "$valid_pidfd_info" 'Pid: 4242')" \
        "$(printf '%s\n' "$valid_pidfd_info" 'NSpid: 4242')" \
        "$(printf '%s\n' "$valid_pidfd_info" | sed 's/Pid: 4242/Pid: 4243/')" \
        "$(printf '%s\n' "$valid_pidfd_info" | sed 's/NSpid: 4242/NSpid: 1 4242/')" \
        "$(printf '%s\n' "$valid_pidfd_info" | sed '/^Pid:/d')" \
        "$(printf '%s\n' "$valid_pidfd_info" | sed '/^NSpid:/d')"
    do
        if pidfd_record_from_fdinfo \
            "$invalid_pidfd_info" 0 4242 >/dev/null 2>&1; then
            printf '%s\n' 'pidfd parser accepted a malformed identity record' >&2
            exit 1
        fi
    done
    if pidfd_record_from_fdinfo "$valid_pidfd_info" 00 4242 \
        >/dev/null 2>&1 \
        || pidfd_record_from_fdinfo "$valid_pidfd_info" 4294967295 4242 \
            >/dev/null 2>&1; then
        exit 1
    fi

    command exec 7</dev/null
    readonly_identity=$(capture_fdstore_descriptor_identity "/proc/$$/fd/7")
    command exec 8<>/dev/null
    readwrite_identity=$(capture_fdstore_descriptor_identity "/proc/$$/fd/8")
    [ "${readonly_identity%:*}" = "${readwrite_identity%:*}" ]
    [ "${readonly_identity##*:}" = 0 ]
    [ "${readwrite_identity##*:}" = 2 ]
    [ "$(printf '%s\n' "$readonly_identity" \
        | awk -F: 'NF == 7 { print NF }')" = 7 ]
    if capture_fdstore_descriptor_identity /dev/null >/dev/null 2>&1 \
        || capture_fdstore_descriptor_identity /proc/self/fd/7 >/dev/null 2>&1; then
        exit 1
    fi
    command exec 8>&-
    command exec 7>&-

    custody_name=volparossa-custody-v1-aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa
    pidfd_identity=33261:0:5:100:0:0:2
    namespace_identity=33060:0:4:200:0:0:0
    fdstore_dump=$(printf \
        '{"type":"a(suuutuusu)","data":[[["%s",33261,0,5,100,0,0,"anon_inode:[pidfd]",32770],["%s",33060,0,4,200,0,0,"net:[200]",32768]]]}' \
        "$custody_name" "$custody_name")
    [ "$(fdstore_dump_exact_custody_name \
        "$fdstore_dump" "$pidfd_identity" "$namespace_identity")" = \
        "$custody_name" ]
    for fdstore_mutation in \
        '.data[0][0][8] = 32771' \
        '.data[0][1][0] = "volparossa-custody-v1-bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"' \
        '.data[0] |= .[0:1]' \
        '.data[0] += [.data[0][0]]' \
        '.data += [.data[0]]'
    do
        mutated_fdstore_dump=$(printf '%s' "$fdstore_dump" \
            | jq -c "$fdstore_mutation")
        if fdstore_dump_exact_custody_name \
            "$mutated_fdstore_dump" "$pidfd_identity" "$namespace_identity" \
            >/dev/null 2>&1; then
            exit 1
        fi
    done
    if fdstore_dump_exact_custody_name \
        "$(printf '%s\n%s' "$fdstore_dump" "$fdstore_dump")" \
        "$pidfd_identity" "$namespace_identity" >/dev/null 2>&1; then
        exit 1
    fi
)
exercise_hook_custody_parsers || {
    printf '%s\n' 'worker custody parser behavior is not exact' >&2
    exit 1
}
# These are literal hook variable names. PID and identity numbers remain on the
# positive-number validator, while every descriptor index uses the FD domain.
# shellcheck disable=SC2016
for exact_fd_variable in \
    hook_worker_process_fd hook_pidfd_number hook_custody_fd hook_namespace_fd
do
    if grep -E "^[[:space:]]*number_is_safe \"\\\$$exact_fd_variable\"" \
        "$ipc_hook" >/dev/null \
        || ! grep -E "^[[:space:]]*fd_number_is_safe \"\\\$$exact_fd_variable\"" \
            "$ipc_hook" >/dev/null; then
        printf 'descriptor does not use the canonical FD validator: %s\n' \
            "$exact_fd_variable" >&2
        exit 1
    fi
done

# A producer-side `exit` inside a POSIX pipeline is masked by the final sort.
# Both procfs inventories must finish in a checked command substitution before
# any separately checked normalization or ordering command consumes them.
producer_pipeline_is_absent() {
    [ "$#" -eq 1 ] || return 1
    if grep -E '^[[:space:]]*done([[:space:]]|\\)*\|' "$1" >/dev/null; then
        return 1
    fi
}
for inventory_function in direct_helper_child capture_parent_worker_custody; do
    inventory_body=$temporary_directory/$inventory_function.body
    inventory_mutant=$temporary_directory/$inventory_function.pipeline-mutant
    sed -n "/^$inventory_function() {\$/,/^}\$/p" "$ipc_hook" >"$inventory_body"
    [ "$(grep -c "^$inventory_function() {\$" "$inventory_body")" -eq 1 ] || {
        printf 'procfs inventory is not uniquely extractable: %s\n' \
            "$inventory_function" >&2
        exit 1
    }
    producer_pipeline_is_absent "$inventory_body" || {
        printf 'procfs inventory masks producer failure: %s\n' \
            "$inventory_function" >&2
        exit 1
    }
    sed '0,/^        done$/s//        done | sort -n/' \
        "$inventory_body" >"$inventory_mutant"
    if producer_pipeline_is_absent "$inventory_mutant"; then
        printf 'procfs inventory pipeline mutant was accepted: %s\n' \
            "$inventory_function" >&2
        exit 1
    fi
done

# iproute2 may omit a route field that was already constrained on the command
# line. Keep the underlay readback as three checked producer captures followed
# by separate jq validation, and query the complete main-table default set so
# the output still carries the device that the proof compares.
# The preceding pristine-network inventory uses the same producer/consumer
# boundary: a partial `ip` result must never become trusted through POSIX
# pipeline status masking.
# These patterns deliberately name literal hook variables.
# shellcheck disable=SC2016
private_network_source_is_exact() {
    [ "$#" -eq 1 ] || return 1
    [ "$(grep -Fxc \
        '    hook_private_links=$(' "$1")" -eq 1 ] || return 1
    [ "$(grep -Fxc \
        '        /usr/sbin/ip -details -json link show 2>/dev/null' \
        "$1")" -eq 1 ] || return 1
    [ "$(grep -Fxc '    ) || return 1' "$1")" -eq 1 ] || return 1
    [ "$(grep -Fc -- \
        '--argjson observed "$hook_private_links"' "$1")" -eq 1 ] \
        || return 1
}
private_network_body=$temporary_directory/private-network.body
private_network_mutant=$temporary_directory/private-network.pipeline-mutant
sed -n '/^private_network_is_pristine() {$/,/^}$/p' \
    "$ipc_hook" >"$private_network_body"
private_network_source_is_exact "$private_network_body" || {
    printf '%s\n' 'private-network inventory masks producer failure' >&2
    exit 1
}
sed '0,/ip -details -json link show/s/$/ | \/usr\/bin\/jq -e ./' \
    "$private_network_body" >"$private_network_mutant"
if private_network_source_is_exact "$private_network_mutant"; then
    printf '%s\n' 'private-network inventory accepted a producer-pipeline mutant' >&2
    exit 1
fi

# These patterns deliberately name literal hook variables.
# shellcheck disable=SC2016
functional_underlay_source_is_exact() {
    [ "$#" -eq 1 ] || return 1
    [ "$(grep -c '^[[:space:]]*hook_underlay_.*_json=\$(' "$1")" -eq 3 ] \
        || return 1
    [ "$(grep -c '^[[:space:]]*) || return 1$' "$1")" -eq 3 ] \
        || return 1
    for hook_underlay_exact_line in \
        '        /usr/sbin/ip -details -json link show dev "$functional_underlay" 2>/dev/null' \
        '        /usr/sbin/ip -4 -json address show dev "$functional_underlay" 2>/dev/null' \
        '        /usr/sbin/ip -4 -json route show table main default 2>/dev/null'
    do
        [ "$(grep -Fxc -- "$hook_underlay_exact_line" "$1")" -eq 1 ] \
            || return 1
    done
    for hook_underlay_exact_consumer in \
        '--argjson observed "$hook_underlay_link_json"' \
        '--argjson observed "$hook_underlay_address_json"' \
        '--argjson observed "$hook_underlay_route_json"'
    do
        [ "$(grep -Fc -- "$hook_underlay_exact_consumer" "$1")" -eq 1 ] \
            || return 1
    done
    ! grep -F 'route show default dev "$functional_underlay"' "$1" >/dev/null
}
functional_underlay_body=$temporary_directory/functional-underlay.body
functional_underlay_mutant=$temporary_directory/functional-underlay.mutant
sed -n '/^functional_underlay_is_exact() {$/,/^}$/p' \
    "$ipc_hook" >"$functional_underlay_body"
functional_underlay_source_is_exact "$functional_underlay_body" || {
    printf '%s\n' 'functional underlay readback is not fail-closed and field-complete' >&2
    exit 1
}
# This recreates the Debian 13/iproute2 failure where `dev` disappears from
# JSON because it was consumed as a route-show filter.
# shellcheck disable=SC2016
sed '0,/route show table main default/s//route show default dev "$functional_underlay"/' \
    "$functional_underlay_body" >"$functional_underlay_mutant"
if functional_underlay_source_is_exact "$functional_underlay_mutant"; then
    printf '%s\n' 'functional underlay accepted the iproute2 field-omission mutant' >&2
    exit 1
fi
sed '0,/) || return 1/s//) || :/' \
    "$functional_underlay_body" >"$functional_underlay_mutant"
if functional_underlay_source_is_exact "$functional_underlay_mutant"; then
    printf '%s\n' 'functional underlay accepted an unchecked producer mutant' >&2
    exit 1
fi
# A checked command substitution still masks an `ip` failure when the producer
# is silently changed back into a POSIX pipeline whose final command succeeds.
sed '0,/ip -details -json link show dev/s/$/ | \/usr\/bin\/jq -e ./' \
    "$functional_underlay_body" >"$functional_underlay_mutant"
if functional_underlay_source_is_exact "$functional_underlay_mutant"; then
    printf '%s\n' 'functional underlay accepted a producer-pipeline mutant' >&2
    exit 1
fi
if ! awk '
    /^direct_helper_child\(\) \{$/ { direct = 1; next }
    /^helper_has_no_children\(\) \{$/ { direct = 0 }
    direct && /hook_children_raw=\$\(/ { raw = NR }
    direct && /^        done$/ { direct_done = NR }
    direct && /^    \) \|\| return 1$/ {
        direct_close_count++
        if (direct_close_count == 1) raw_close = NR
        if (direct_close_count == 2) lines_close = NR
        if (direct_close_count == 3) nonempty_close = NR
        if (direct_close_count == 4) sorted_close = NR
    }
    direct && /hook_children_lines=\$\(tr / { lines = NR }
    direct && /hook_children_nonempty=\$\(sed / { nonempty = NR }
    direct && /hook_children=\$\(sort -u / { sorted = NR }
    /^capture_parent_worker_custody\(\) \{$/ { custody = 1; next }
    /^worker_wireguard_interface\(\) \{$/ { custody = 0 }
    custody && /hook_custody_fd_unsorted=\$\(/ { fd_raw = NR }
    custody && /^        done$/ { fd_done = NR }
    custody && /^    \) \|\| return 1$/ {
        fd_close_count++
        if (fd_close_count == 1) fd_raw_close = NR
        if (fd_close_count == 2) fd_sorted_close = NR
    }
    custody && /hook_custody_fd_numbers=\$\(sort -n / { fd_sorted = NR }
    END {
        direct_ok = direct_close_count == 4 && raw < direct_done
        direct_ok = direct_ok && direct_done < raw_close && raw_close < lines
        direct_ok = direct_ok && lines < lines_close && lines_close < nonempty
        direct_ok = direct_ok && nonempty < nonempty_close
        direct_ok = direct_ok && nonempty_close < sorted && sorted < sorted_close
        custody_ok = fd_close_count == 2 && fd_raw < fd_done
        custody_ok = custody_ok && fd_done < fd_raw_close
        custody_ok = custody_ok && fd_raw_close < fd_sorted
        custody_ok = custody_ok && fd_sorted < fd_sorted_close
        if (!(direct_ok && custody_ok)) exit 1
    }
' "$ipc_hook"; then
    printf '%s\n' 'procfs inventories are not fail-closed before normalization' >&2
    exit 1
fi

gate_launch_identity_functions=$temporary_directory/gate-launch-identity-functions.sh
{
    sed -n '/^systemd_launch_record_is_safe() {$/,/^}$/p' "$gate"
    sed -n '/^launch_image_record_is_safe() {$/,/^}$/p' "$gate"
    sed -n '/^process_starttime_from_stat() {$/,/^}$/p' "$gate"
    sed -n '/^capture_process_starttime() {$/,/^}$/p' "$gate"
    sed -n '/^retired_runtime_is_absent() {$/,/^}$/p' "$gate"
} >"$gate_launch_identity_functions"
if [ "$(grep -c '^systemd_launch_record_is_safe() {$' \
        "$gate_launch_identity_functions")" -ne 1 ] \
    || [ "$(grep -c '^launch_image_record_is_safe() {$' \
        "$gate_launch_identity_functions")" -ne 1 ] \
    || [ "$(grep -c '^retired_runtime_is_absent() {$' \
        "$gate_launch_identity_functions")" -ne 1 ]; then
    printf '%s\n' 'gate launch identity helpers are not uniquely extractable' >&2
    exit 1
fi
sh -n "$gate_launch_identity_functions"
# shellcheck disable=SC1090,SC2317
exercise_gate_launch_identity() (
    . "$gate_launch_identity_functions"
    launch='systemd-launch-v1=pid:4242;gid:61000;start-realtime:123456789;start-monotonic:234567890'
    digest=aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa
    image="launch-image-v1=device:17;inode:23;size:81726341;sha256:$digest"
    systemd_launch_record_is_safe "$launch" 4242 61000
    launch_image_record_is_safe "$image" "$digest"
    if systemd_launch_record_is_safe "$launch" 4243 61000 \
        || systemd_launch_record_is_safe \
            "${launch};start-monotonic:1" 4242 61000 \
        || launch_image_record_is_safe \
            "launch-image-v1=device:17;inode:23;size:134217729;sha256:$digest" \
            "$digest" \
        || launch_image_record_is_safe "$image" \
            bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb; then
        exit 1
    fi

    current_starttime=$(capture_process_starttime "$$")
    synthetic_unit=volparossa-helper-live-proof-TST123.service
    synthetic_group=/system.slice/$synthetic_unit
    [ ! -e "/sys/fs/cgroup$synthetic_group" ]
    retired_runtime_is_absent "$synthetic_unit" "$synthetic_group" \
        "$$" "${current_starttime}9"
    # An existing PID with the same birth token must remain present and fail
    # the bounded retirement predicate. Remove wall-clock delay in this
    # contract process while preserving all 1,200 exact observations.
    sleep() { :; }
    ! retired_runtime_is_absent "$synthetic_unit" "$synthetic_group" \
        "$$" "$current_starttime"
)
exercise_gate_launch_identity || {
    printf '%s\n' 'gate launch identity or PID-reuse behavior is not fail closed' >&2
    exit 1
}

# Cross-credential procfs magic-link and argument reads require ptrace-like
# authority. The evidence path must neither depend on those reads nor widen
# the transient sandbox to make them possible.
# shellcheck disable=SC2016
if grep -F '/proc/$hook_identity_pid/exe' "$ipc_hook" >/dev/null \
    || grep -F '/proc/$hook_identity_pid/cmdline' "$ipc_hook" >/dev/null \
    || grep -F '/proc/$hook_worker_pid/exe' "$ipc_hook" >/dev/null \
    || grep -F '/proc/$hook_worker_pid/cmdline' "$ipc_hook" >/dev/null \
    || grep -F '/proc/$hook_functional_worker_pid/ns/net' "$ipc_hook" >/dev/null \
    || grep -F 'CAP_SYS_PTRACE' "$gate" "$ipc_hook" >/dev/null \
    || grep -F '/run/systemd/private' "$gate" "$ipc_hook" >/dev/null; then
    printf '%s\n' 'production launch evidence widened or retained ptrace-gated reads' >&2
    exit 1
fi
if ! awk '
    /^worker_identity_from_process_fd\(\) \{$/ { in_identity = 1; next }
    /^worker_wireguard_interface\(\) \{$/ { in_identity = 0 }
    in_identity && /capture_process_starttime_from_fd/ {
        starttime_count++
        if (starttime_count == 1) start_before = NR
        if (starttime_count == 2) start_after = NR
    }
    in_identity && /worker_status_from_process_fd_is_exact/ {
        status_count++
        if (status_count == 1) status_before = NR
        if (status_count == 2) status_after = NR
    }
    END {
        valid = starttime_count == 2 && status_count == 2
        valid = valid && start_before < status_before
        valid = valid && status_before < start_after && start_after < status_after
        if (!valid) exit 1
    }
' "$ipc_hook"; then
    printf '%s\n' 'worker external identity is not stably bracketed' >&2
    exit 1
fi

# Failed production start hooks publish only one private fixed stage. Exercise
# the exact allowlist and transition graph, then pin the failure trap and all
# fallible descriptor redirections to ordinary `command exec` semantics.
hook_start_stage_functions=$temporary_directory/hook-start-stage-functions.sh
{
    sed -n '/^start_failure_stage_is_safe() {$/,/^}$/p' "$ipc_hook"
    sed -n '/^advance_start_failure_stage() {$/,/^}$/p' "$ipc_hook"
} >"$hook_start_stage_functions"
test "$(grep -c '^start_failure_stage_is_safe() {$' \
    "$hook_start_stage_functions")" -eq 1
test "$(grep -c '^advance_start_failure_stage() {$' \
    "$hook_start_stage_functions")" -eq 1
sh -n "$hook_start_stage_functions"
# shellcheck disable=SC1090
. "$hook_start_stage_functions"
observed_hook_start_stages=$temporary_directory/observed-hook-start-stages
sed -n '/^start_failure_stage_is_safe() {$/,/^}$/p' "$ipc_hook" \
    | sed -nE 's/^[[:space:]]*([a-z][a-z-]*)(\|\\|\))[[:space:]]*$/\1/p' \
    >"$observed_hook_start_stages"
cmp -s "$expected_production_start_stages" "$observed_hook_start_stages" || {
    printf '%s\n' 'production hook start failure stages differ from the fixed allowlist' >&2
    exit 1
}
start_failure_stage=
hook_stage_index=0
expected_production_monotone_start_stages=$temporary_directory/expected-production-monotone-start-stages
grep -Ev '^functional-exit-cleanup-parent-custody-(pidfd|procfd|foreign-netns-exit-worker-one|foreign-netns-exit-worker-two|foreign-netns-exit-worker-three-plus|foreign-netns-other|fd-scan|clear)$' \
    "$expected_production_start_stages" \
    >"$expected_production_monotone_start_stages"
while IFS= read -r hook_start_stage; do
    hook_stage_index=$((hook_stage_index + 1))
    if [ "$hook_stage_index" -eq 1 ]; then
        [ "$hook_start_stage" = preflight-runtime ] || exit 1
        start_failure_stage=$hook_start_stage
    else
        advance_start_failure_stage "$hook_start_stage" || {
            printf 'production hook rejected monotone start stage: %s\n' \
                "$hook_start_stage" >&2
            exit 1
        }
    fi
done <"$expected_production_monotone_start_stages"
[ "$start_failure_stage" = publication ] || {
    printf '%s\n' 'production hook start stage did not reach publication' >&2
    exit 1
}
for hook_custody_failure_stage in \
    pidfd procfd foreign-netns-exit-worker-one \
    foreign-netns-exit-worker-two foreign-netns-exit-worker-three-plus \
    foreign-netns-other fd-scan clear; do
    start_failure_stage=functional-exit-cleanup-parent-custody
    advance_start_failure_stage \
        "functional-exit-cleanup-parent-custody-$hook_custody_failure_stage" \
        || {
            printf 'production hook rejected custody diagnostic stage: %s\n' \
                "$hook_custody_failure_stage" >&2
            exit 1
        }
    [ "$start_failure_stage" = \
        "functional-exit-cleanup-parent-custody-$hook_custody_failure_stage" ] \
        || exit 1
    if advance_start_failure_stage functional-relay-pair-ready; then
        printf 'production hook advanced past custody diagnostic stage: %s\n' \
            "$hook_custody_failure_stage" >&2
        exit 1
    fi
done
if advance_start_failure_stage identity-socket \
    || { start_failure_stage=preflight-runtime; advance_start_failure_stage active-lock; }; then
    printf '%s\n' 'production hook start stage accepted a skipped or regressed transition' >&2
    exit 1
fi

# The initial capture must run in the hook shell so its fixed stages survive;
# ordinary reobservations retain their stdout surface and never move the stage.
hook_identity_capture_function=$temporary_directory/hook-identity-capture-function.sh
sed -n '/^capture_running_identity() {$/,/^}$/p' "$ipc_hook" \
    >"$hook_identity_capture_function"
test "$(grep -c '^capture_running_identity() {$' \
    "$hook_identity_capture_function")" -eq 1
sh -n "$hook_identity_capture_function"
# These functions and assignments satisfy symbols in the dynamically sourced
# capture function, which static ShellCheck analysis cannot follow.
# shellcheck disable=SC2034,SC2154,SC2317
exercise_hook_identity_capture_modes() (
    # shellcheck disable=SC1090
    . "$hook_start_stage_functions"
    # shellcheck disable=SC1090
    . "$hook_identity_capture_function"
    number_is_safe() { return 0; }
    unit_invocation_id() { printf '%s\n' 11111111111111111111111111111111; }
    unit_main_pid() { printf '%s\n' 4242; }
    capture_systemd_launch_contract() {
        printf '%s\n' \
            'systemd-launch-v1=pid:4242;gid:7;start-realtime:123;start-monotonic:456'
    }
    capture_launch_image_identity() {
        printf '%s\n' \
            'launch-image-v1=device:1;inode:2;size:3;sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa'
    }
    launch_image_matches_identity() {
        [ "$2" = \
            'launch-image-v1=device:1;inode:2;size:3;sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa' ]
    }
    capture_process_starttime() { printf '%s\n' 789; }
    capture_helper_process_contract() { printf '%s\n' process-contract-v1; }
    production_helper=/run/exact-helper
    expected_launch_image='launch-image-v1=device:1;inode:2;size:3;sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa'
    expected_identity=$(printf '%s\n%s\n%s\n%s\n%s\n%s' \
        11111111111111111111111111111111 \
        4242 \
        'systemd-launch-v1=pid:4242;gid:7;start-realtime:123;start-monotonic:456' \
        "$expected_launch_image" \
        process-starttime-v1=789 \
        process-contract-v1)

    start_failure_stage=identity-lock
    capture_running_identity exact.service 7 initial \
        >"$temporary_directory/initial-identity.stdout"
    [ ! -s "$temporary_directory/initial-identity.stdout" ]
    [ "$start_failure_stage" = identity-stability ]
    [ "$hook_captured_running_identity" = "$expected_identity" ]

    start_failure_stage=active-lock
    observed_identity=$(capture_running_identity \
        exact.service 7 "$expected_launch_image")
    [ "$start_failure_stage" = active-lock ]
    [ "$observed_identity" = "$expected_identity" ]
    ! capture_running_identity exact.service 7 substituted
)
exercise_hook_identity_capture_modes || {
    printf '%s\n' 'production hook identity capture modes are not affine to start stages' >&2
    exit 1
}
# These are literal hook-source contracts; expansion would defeat the checks.
# shellcheck disable=SC2016
for fixed_start_failure_contract in \
    'start_failure_record=$proof_directory/start.failure' \
    "write_private_file \"\$start_failure_record\" \\" \
    'VOLPAROSSA_HELPER_V3_IPC_START_FAILURE_STAGE_V1=$start_failure_stage' \
    'trap start_failure_exit EXIT' \
    'capture_running_identity "$hook_unit" "$agent_gid" initial' \
    'hook_identity=$hook_captured_running_identity' \
    'start_failure_armed=no' \
    'trap - EXIT'
do
    grep -F -- "$fixed_start_failure_contract" "$ipc_hook" >/dev/null || {
        printf 'production hook start failure contract is missing: %s\n' \
            "$fixed_start_failure_contract" >&2
        exit 1
    }
done
if grep -E '^[[:space:]]*(if ![[:space:]]+)?exec[[:space:]]+[0-9]+[<>]' \
    "$ipc_hook" >/dev/null \
    || [ "$(grep -Ec '^[[:space:]]*(if ![[:space:]]+)?command exec [0-9]+[<>]' \
        "$ipc_hook")" -ne 23 ] \
    || [ "$(grep -Fc "        command exec /usr/bin/setpriv \\" \
        "$ipc_hook")" -ne 1 ]; then
    printf '%s\n' 'production hook FD redirections can retain fatal special-builtin semantics' >&2
    exit 1
fi
hook_start_exit_functions=$temporary_directory/hook-start-exit-functions.sh
{
    sed -n '/^start_failure_stage_is_safe() {$/,/^}$/p' "$ipc_hook"
    sed -n '/^publish_start_failure() {$/,/^}$/p' "$ipc_hook"
    sed -n '/^start_failure_exit() {$/,/^}$/p' "$ipc_hook"
} >"$hook_start_exit_functions"
test "$(grep -c '^[_a-z].*() {$' "$hook_start_exit_functions")" -eq 3
sh -n "$hook_start_exit_functions"
forced_fd_script=$temporary_directory/forced-hook-fd-failure.sh
{
    printf '%s\n' '#!/bin/sh' 'set -eu'
    printf '. %s\n' "$hook_start_exit_functions"
    cat <<'EOF'
write_private_file() {
    [ "$#" -eq 2 ] || return 1
    forced_destination=$1
    forced_payload=$2
    (
        umask 077
        set -C
        printf '%s\n' "$forced_payload" >"$forced_destination"
    ) 2>/dev/null || return 1
    [ "$(stat -Lc '%F:%h:%u:%a' "$forced_destination")" = \
        "regular file:1:$(id -u):600" ]
}
start_failure_record=$1
start_failure_stage=functional-probe-ready
start_failure_armed=yes
start_failure_published=no
functional_fixture_shape=single
functional_relay_state=marked
functional_exit_relay_state=absent
functional_cleanup_observed=$3
remove_functional_exit_relay_fixture() {
    [ "$functional_exit_relay_state" = absent ]
}
remove_functional_relay_fixture() {
    [ "$functional_relay_state" = marked ] || return 1
    printf '%s\n' cleanup >"$functional_cleanup_observed" || return 1
    functional_relay_state=absent
}
trap start_failure_exit EXIT
force_fd_failure() {
    command exec 8<>"$1" || return 1
}
force_fd_failure "$2"
EOF
} >"$forced_fd_script"
chmod 0700 "$forced_fd_script"
forced_fd_record=$temporary_directory/forced-hook-fd.start.failure
forced_fd_cleanup=$temporary_directory/forced-hook-fd.cleanup
set +e
dash "$forced_fd_script" "$forced_fd_record" \
    "$temporary_directory/absent-directory/fd" "$forced_fd_cleanup" \
    >"$temporary_directory/forced-hook-fd.stdout" \
    2>"$temporary_directory/forced-hook-fd.stderr"
forced_fd_status=$?
set -e
if [ "$forced_fd_status" -ne 1 ] \
    || [ -s "$temporary_directory/forced-hook-fd.stdout" ] \
    || [ "$(stat -Lc '%F:%h:%u:%a' "$forced_fd_record" 2>/dev/null || true)" \
        != "regular file:1:$(id -u):600" ] \
    || [ "$(cat "$forced_fd_cleanup" 2>/dev/null || true)" != cleanup ] \
    || ! printf '%s\n' \
        'VOLPAROSSA_HELPER_V3_IPC_START_FAILURE_STAGE_V1=functional-probe-ready' \
        | cmp -s - "$forced_fd_record"; then
    printf '%s\n' 'forced hook FD failure did not return status 1 with one fixed stage' >&2
    exit 1
fi

# Exercise the relay fixture state machine without network privileges. Every
# mutator is replaced with a stateful model so command-edge failures prove both
# fail-closed identity handling and exact, repeatable cleanup.
hook_relay_lifecycle_functions=$temporary_directory/hook-relay-lifecycle-functions.sh
{
    sed -n '/^forget_functional_relay_fixture() {$/,/^}$/p' "$ipc_hook"
    sed -n '/^create_functional_relay_fixture() {$/,/^}$/p' "$ipc_hook"
    sed -n '/^remove_functional_relay_fixture() {$/,/^}$/p' "$ipc_hook"
} >"$hook_relay_lifecycle_functions"
test "$(grep -c '^[_a-z].*() {$' "$hook_relay_lifecycle_functions")" -eq 3
sh -n "$hook_relay_lifecycle_functions"
# The sourced production functions resolve these deliberately modelled
# dependencies at execution time.
# shellcheck disable=SC2034,SC2317
exercise_functional_relay_lifecycle_edges() (
    # shellcheck disable=SC1090
    . "$hook_relay_lifecycle_functions"

    functional_relay=vprl0
    functional_relay_alias=volparossa-proof-relay-v1
    functional_relay_public_key=MdSras7slhE3kXA3k25gcW+sVzr+lNnahKgCBEjfwRI=
    functional_relay_listen_port=10000
    functional_underlay_address=192.31.195.254
    functional_peer_keepalive=25
    mock_client_public_key=l8OxC01sEzp46l3MHPZCHT+Brjex9ijOFMpvzncw8zM=
    mock_client_listen_port=10001
    mock_client_address=fd76:6f6c:7061:0000:0000:0001:0001:0001
    mock_relay_address=fd76:6f6c:7061:0000:0000:0001:0001:0002

    number_is_safe() {
        [ "$#" -eq 1 ] || return 1
        case $1 in
            ''|0|0*|*[!0-9]*) return 1 ;;
            *) [ "${#1}" -le 10 ] && [ "$1" -le 4294967294 ] ;;
        esac
    }
    mock_record() {
        if [ -n "$mock_events" ]; then
            mock_events=$mock_events,$1
        else
            mock_events=$1
        fi
    }
    mock_drop_link() {
        mock_link_present=no
        mock_alias_present=no
        mock_wireguard_configured=no
        mock_address_present=no
        mock_link_up=no
        mock_route_present=no
    }
    mock_reset() {
        mock_failure=$1
        mock_events=
        mock_link_present=no
        mock_alias_present=no
        mock_wireguard_configured=no
        mock_address_present=no
        mock_link_up=no
        mock_route_present=no
        mock_ifindex=41
        mock_kind=wireguard
        mock_delete_count=0
        functional_relay_state=absent
        functional_relay_ifindex=
        functional_relay_client_address=
        hook_captured_relay_ifindex=
    }
    functional_relay_link_is_absent() {
        mock_record absent
        [ "$mock_link_present" = no ]
    }
    functional_relay_route_is_absent() {
        mock_record route-absent
        [ "$mock_route_present" = no ]
    }
    functional_relay_identity_is_exact() {
        mock_record identity
        [ "$#" -eq 1 ] \
            && [ "$mock_link_present" = yes ] \
            && [ "$mock_kind" = wireguard ] \
            && [ "$mock_ifindex" = "$1" ]
    }
    functional_relay_link_is_exact() {
        mock_record exact
        [ "$#" -eq 1 ] \
            && [ "$mock_link_present" = yes ] \
            && [ "$mock_kind" = wireguard ] \
            && [ "$mock_ifindex" = "$1" ] \
            && [ "$mock_alias_present" = yes ]
    }
    add_functional_relay_link() {
        mock_record add
        [ "$mock_failure" != add ] || return 1
        mock_link_present=yes
    }
    capture_functional_relay_ifindex() {
        mock_record capture
        [ "$mock_failure" != capture ] || return 1
        [ "$mock_link_present" = yes ] || return 1
        hook_captured_relay_ifindex=$mock_ifindex
    }
    mark_functional_relay_link() {
        mock_record alias
        [ "$mock_failure" != alias ] || return 1
        mock_alias_present=yes
    }
    configure_functional_relay_wireguard() {
        mock_record wg
        [ "$#" -eq 3 ] || return 1
        [ "$mock_failure" != wg ] || return 1
        mock_wireguard_configured=yes
    }
    add_functional_relay_address() {
        mock_record address
        [ "$#" -eq 1 ] || return 1
        [ "$mock_failure" != address ] || return 1
        mock_address_present=yes
    }
    raise_functional_relay_link() {
        mock_record up
        [ "$mock_failure" != up ] || return 1
        mock_link_up=yes
    }
    add_functional_relay_route() {
        mock_record route
        [ "$#" -eq 1 ] || return 1
        [ "$mock_failure" != route ] || return 1
        mock_route_present=yes
    }
    functional_relay_fixture_is_exact() {
        mock_record fixture
        [ "$#" -eq 5 ] \
            && [ "$mock_link_present" = yes ] \
            && [ "$mock_alias_present" = yes ] \
            && [ "$mock_wireguard_configured" = yes ] \
            && [ "$mock_address_present" = yes ] \
            && [ "$mock_link_up" = yes ] \
            && [ "$mock_route_present" = yes ] \
            && [ "$mock_ifindex" = "$1" ]
    }
    delete_functional_relay_link() {
        mock_record delete
        mock_delete_count=$((mock_delete_count + 1))
        if [ "$mock_failure" = delete-before ]; then
            return 1
        fi
        if [ "$mock_failure" = delete-route-retained ]; then
            mock_link_present=no
            mock_alias_present=no
            mock_wireguard_configured=no
            mock_address_present=no
            mock_link_up=no
            return 0
        fi
        mock_drop_link
        [ "$mock_failure" != delete-after ]
    }
    mock_fixture_is_pristine() {
        [ "$functional_relay_state" = absent ] \
            && [ -z "$functional_relay_ifindex" ] \
            && [ -z "$functional_relay_client_address" ] \
            && [ -z "$hook_captured_relay_ifindex" ] \
            && [ "$mock_link_present" = no ] \
            && [ "$mock_alias_present" = no ] \
            && [ "$mock_wireguard_configured" = no ] \
            && [ "$mock_address_present" = no ] \
            && [ "$mock_link_up" = no ] \
            && [ "$mock_route_present" = no ]
    }
    mock_create_fixture() {
        create_functional_relay_fixture \
            "$mock_client_public_key" \
            "$mock_client_listen_port" \
            "$mock_client_address" \
            "$mock_relay_address"
    }

    mock_reset none
    mock_create_fixture || return 1
    [ "$functional_relay_state" = marked ] \
        && [ "$functional_relay_ifindex" = 41 ] || return 1
    case $mock_events in
        absent,add,capture,identity,alias,exact,wg,address,up,route,fixture) ;;
        *) return 1 ;;
    esac
    remove_functional_relay_fixture || return 1
    [ "$mock_delete_count" -eq 1 ] && mock_fixture_is_pristine || return 1
    remove_functional_relay_fixture || return 1
    [ "$mock_delete_count" -eq 1 ] || return 1

    while IFS=: read -r mock_edge mock_expected_state mock_expected_deletes; do
        mock_reset "$mock_edge"
        if mock_create_fixture; then
            return 1
        fi
        [ "$functional_relay_state" = "$mock_expected_state" ] || return 1
        remove_functional_relay_fixture || return 1
        [ "$mock_delete_count" -eq "$mock_expected_deletes" ] \
            && mock_fixture_is_pristine || return 1
        remove_functional_relay_fixture || return 1
        [ "$mock_delete_count" -eq "$mock_expected_deletes" ] || return 1
    done <<'EOF'
add:adding:0
alias:created:1
wg:marked:1
address:marked:1
route:marked:1
EOF

    # A link created without a captured ifindex is never deleted by name.
    mock_reset capture
    ! mock_create_fixture || return 1
    [ "$functional_relay_state" = adding ] || return 1
    ! remove_functional_relay_fixture || return 1
    [ "$mock_delete_count" -eq 0 ] \
        && [ "$mock_link_present" = yes ] || return 1
    mock_drop_link
    remove_functional_relay_fixture || return 1
    mock_fixture_is_pristine || return 1

    # A same-name object with a substituted ifindex is rejected, not deleted.
    mock_reset wg
    ! mock_create_fixture || return 1
    [ "$functional_relay_state" = marked ] || return 1
    mock_failure=none
    mock_ifindex=42
    ! remove_functional_relay_fixture || return 1
    [ "$mock_delete_count" -eq 0 ] \
        && [ "$mock_link_present" = yes ] \
        && [ "$functional_relay_state" = marked ] || return 1
    mock_drop_link
    remove_functional_relay_fixture || return 1
    mock_fixture_is_pristine || return 1

    # Once delete is observed, a failed pristine-route proof resumes at
    # `deleted` and never targets the interface name a second time.
    mock_reset none
    mock_create_fixture || return 1
    mock_failure=delete-route-retained
    ! remove_functional_relay_fixture || return 1
    [ "$functional_relay_state" = deleted ] \
        && [ "$mock_delete_count" -eq 1 ] \
        && [ "$mock_link_present" = no ] \
        && [ "$mock_route_present" = yes ] || return 1
    mock_failure=none
    mock_route_present=no
    remove_functional_relay_fixture || return 1
    [ "$mock_delete_count" -eq 1 ] && mock_fixture_is_pristine || return 1

    # A mutator that reports failure after the link disappeared is also
    # reconciled from observed absence without a second delete.
    mock_reset none
    mock_create_fixture || return 1
    mock_failure=delete-after
    remove_functional_relay_fixture || return 1
    [ "$mock_delete_count" -eq 1 ] && mock_fixture_is_pristine || return 1
)
exercise_functional_relay_lifecycle_edges || {
    printf '%s\n' \
        'production relay fixture failure edges do not clean up exactly and idempotently' >&2
    exit 1
}

hook_exit_relay_lifecycle_functions=$temporary_directory/hook-exit-relay-lifecycle-functions.sh
{
    sed -n '/^forget_functional_exit_relay_fixture() {$/,/^}$/p' "$ipc_hook"
    sed -n '/^create_functional_exit_relay_fixture() {$/,/^}$/p' "$ipc_hook"
    sed -n '/^remove_functional_exit_relay_fixture() {$/,/^}$/p' "$ipc_hook"
} >"$hook_exit_relay_lifecycle_functions"
test "$(grep -c '^[_a-z].*() {$' "$hook_exit_relay_lifecycle_functions")" -eq 3
sh -n "$hook_exit_relay_lifecycle_functions"
# shellcheck disable=SC2034,SC2317
exercise_functional_exit_relay_lifecycle_edges() (
    # shellcheck disable=SC1090
    . "$hook_exit_relay_lifecycle_functions"

    functional_exit_relay=vpre0
    functional_exit_relay_alias=volparossa-proof-relay-exit-v1
    functional_exit_relay_public_key=c7LYt2qptTZgAyvI9di+46OuTjs6f9Sa3oH3NHo0qmg=
    functional_exit_relay_listen_port=10001
    functional_underlay_address=192.31.195.254
    functional_peer_keepalive=25
    mock_exit_public_key=l8OxC01sEzp46l3MHPZCHT+Brjex9ijOFMpvzncw8zM=
    mock_exit_listen_port=10002
    mock_exit_address=fd76:6f6c:7061:0000:0000:0001:0001:0004
    mock_relay_exit_address=fd76:6f6c:7061:0000:0000:0001:0001:0003

    number_is_safe() {
        [ "$#" -eq 1 ] || return 1
        case $1 in
            ''|0|0*|*[!0-9]*) return 1 ;;
            *) [ "${#1}" -le 10 ] && [ "$1" -le 4294967294 ] ;;
        esac
    }
    exit_mock_drop_link() {
        exit_mock_link=no
        exit_mock_alias=no
        exit_mock_wg=no
        exit_mock_address=no
        exit_mock_up=no
        exit_mock_route=no
    }
    exit_mock_reset() {
        exit_mock_failure=$1
        exit_mock_link=no
        exit_mock_alias=no
        exit_mock_wg=no
        exit_mock_address=no
        exit_mock_up=no
        exit_mock_route=no
        exit_mock_ifindex=51
        exit_mock_delete_count=0
        functional_exit_relay_state=absent
        functional_exit_relay_ifindex=
        functional_exit_relay_exit_address=
        hook_captured_exit_relay_ifindex=
    }
    functional_exit_relay_link_is_absent() {
        [ "$exit_mock_link" = no ]
    }
    functional_exit_relay_route_is_absent() {
        [ "$exit_mock_route" = no ]
    }
    functional_exit_relay_identity_is_exact() {
        [ "$#" -eq 1 ] && [ "$exit_mock_link" = yes ] \
            && [ "$exit_mock_ifindex" = "$1" ]
    }
    functional_exit_relay_link_is_exact() {
        functional_exit_relay_identity_is_exact "$1" \
            && [ "$exit_mock_alias" = yes ]
    }
    add_functional_exit_relay_link() {
        [ "$exit_mock_failure" != add ] || return 1
        exit_mock_link=yes
    }
    capture_functional_exit_relay_ifindex() {
        [ "$exit_mock_failure" != capture ] || return 1
        [ "$exit_mock_link" = yes ] || return 1
        hook_captured_exit_relay_ifindex=$exit_mock_ifindex
    }
    mark_functional_exit_relay_link() {
        [ "$exit_mock_failure" != alias ] || return 1
        exit_mock_alias=yes
    }
    configure_functional_exit_relay_wireguard() {
        [ "$#" -eq 3 ] || return 1
        [ "$exit_mock_failure" != wg ] || return 1
        exit_mock_wg=yes
    }
    add_functional_exit_relay_address() {
        [ "$#" -eq 1 ] || return 1
        [ "$exit_mock_failure" != address ] || return 1
        exit_mock_address=yes
    }
    raise_functional_exit_relay_link() {
        [ "$exit_mock_failure" != up ] || return 1
        exit_mock_up=yes
    }
    add_functional_exit_relay_route() {
        [ "$#" -eq 1 ] || return 1
        [ "$exit_mock_failure" != route ] || return 1
        exit_mock_route=yes
    }
    functional_exit_relay_fixture_is_exact() {
        [ "$#" -eq 5 ] && [ "$exit_mock_link" = yes ] \
            && [ "$exit_mock_alias" = yes ] && [ "$exit_mock_wg" = yes ] \
            && [ "$exit_mock_address" = yes ] && [ "$exit_mock_up" = yes ] \
            && [ "$exit_mock_route" = yes ] && [ "$exit_mock_ifindex" = "$1" ]
    }
    delete_functional_exit_relay_link() {
        exit_mock_delete_count=$((exit_mock_delete_count + 1))
        [ "$exit_mock_failure" != delete-before ] || return 1
        if [ "$exit_mock_failure" = delete-route-retained ]; then
            exit_mock_link=no
            exit_mock_alias=no
            exit_mock_wg=no
            exit_mock_address=no
            exit_mock_up=no
            return 0
        fi
        exit_mock_drop_link
        [ "$exit_mock_failure" != delete-after ]
    }
    exit_mock_pristine() {
        [ "$functional_exit_relay_state" = absent ] \
            && [ -z "$functional_exit_relay_ifindex" ] \
            && [ -z "$functional_exit_relay_exit_address" ] \
            && [ -z "$hook_captured_exit_relay_ifindex" ] \
            && [ "$exit_mock_link" = no ] && [ "$exit_mock_route" = no ]
    }
    exit_mock_create() {
        create_functional_exit_relay_fixture \
            "$mock_exit_public_key" "$mock_exit_listen_port" \
            "$mock_exit_address" "$mock_relay_exit_address"
    }

    exit_mock_reset none
    exit_mock_create || return 1
    [ "$functional_exit_relay_state" = marked ] \
        && [ "$functional_exit_relay_ifindex" = 51 ] || return 1
    remove_functional_exit_relay_fixture || return 1
    [ "$exit_mock_delete_count" -eq 1 ] && exit_mock_pristine || return 1
    remove_functional_exit_relay_fixture || return 1
    [ "$exit_mock_delete_count" -eq 1 ] || return 1

    while IFS=: read -r exit_mock_edge exit_expected_state exit_expected_deletes; do
        exit_mock_reset "$exit_mock_edge"
        ! exit_mock_create || return 1
        [ "$functional_exit_relay_state" = "$exit_expected_state" ] || return 1
        remove_functional_exit_relay_fixture || return 1
        [ "$exit_mock_delete_count" -eq "$exit_expected_deletes" ] \
            && exit_mock_pristine || return 1
    done <<'EOF'
add:adding:0
alias:created:1
wg:marked:1
address:marked:1
up:marked:1
route:marked:1
EOF

    exit_mock_reset capture
    ! exit_mock_create || return 1
    ! remove_functional_exit_relay_fixture || return 1
    [ "$exit_mock_delete_count" -eq 0 ] && [ "$exit_mock_link" = yes ] || return 1
    exit_mock_drop_link
    remove_functional_exit_relay_fixture || return 1
    exit_mock_pristine || return 1

    exit_mock_reset wg
    ! exit_mock_create || return 1
    exit_mock_failure=none
    exit_mock_ifindex=52
    ! remove_functional_exit_relay_fixture || return 1
    [ "$exit_mock_delete_count" -eq 0 ] \
        && [ "$functional_exit_relay_state" = marked ] || return 1
    exit_mock_drop_link
    remove_functional_exit_relay_fixture || return 1
    exit_mock_pristine || return 1

    exit_mock_reset none
    exit_mock_create || return 1
    exit_mock_failure=delete-route-retained
    ! remove_functional_exit_relay_fixture || return 1
    [ "$functional_exit_relay_state" = deleted ] \
        && [ "$exit_mock_delete_count" -eq 1 ] \
        && [ "$exit_mock_route" = yes ] || return 1
    exit_mock_failure=none
    exit_mock_route=no
    remove_functional_exit_relay_fixture || return 1
    [ "$exit_mock_delete_count" -eq 1 ] && exit_mock_pristine

    exit_mock_reset none
    exit_mock_create || return 1
    exit_mock_failure=delete-after
    remove_functional_exit_relay_fixture || return 1
    [ "$exit_mock_delete_count" -eq 1 ] && exit_mock_pristine
)
exercise_functional_exit_relay_lifecycle_edges || {
    printf '%s\n' \
        'production Exit relay fixture failure edges do not clean up exactly and idempotently' >&2
    exit 1
}

# The paired wrapper must treat its anonymous NEWNET keepers and moved links as
# one transaction. Any build failure rolls both legs back, while teardown must
# prove/remove/reap RelayExit before it can target RelayClient.
hook_relay_pair_lifecycle_functions=$temporary_directory/hook-relay-pair-lifecycle-functions.sh
{
    sed -n '/^create_functional_relay_pair_fixtures() {$/,/^}$/p' "$ipc_hook"
    sed -n '/^remove_functional_relay_pair_fixtures() {$/,/^}$/p' "$ipc_hook"
} >"$hook_relay_pair_lifecycle_functions"
test "$(grep -c '^[_a-z].*() {$' "$hook_relay_pair_lifecycle_functions")" -eq 2
sh -n "$hook_relay_pair_lifecycle_functions"
# shellcheck disable=SC2034,SC2317
exercise_functional_relay_pair_lifecycle_edges() (
    # shellcheck disable=SC1090
    . "$hook_relay_pair_lifecycle_functions"

    pair_reset() {
        pair_failure=$1
        pair_events=
        pair_client_present=no
        pair_exit_present=no
        functional_fixture_shape=single
        functional_relay_state=absent
        functional_exit_relay_state=absent
        functional_pair_client_keeper_state=absent
        functional_pair_exit_keeper_state=absent
        functional_pair_client_link_state=absent
        functional_pair_exit_link_state=absent
        functional_pair_client_keeper_pid=
        functional_pair_exit_keeper_pid=
        functional_relay_public_key=\
MdSras7slhE3kXA3k25gcW+sVzr+lNnahKgCBEjfwRI=
        functional_exit_relay_public_key=\
c7LYt2qptTZgAyvI9di+46OuTjs6f9Sa3oH3NHo0qmg=
    }
    pair_event() {
        if [ -n "$pair_events" ]; then
            pair_events=$pair_events,$1
        else
            pair_events=$1
        fi
    }
    number_is_safe() {
        [ "$#" -eq 1 ] && [ -n "$1" ]
    }
    functional_relay_link_is_absent() {
        [ "$pair_client_present" = no ]
    }
    functional_exit_relay_link_is_absent() {
        [ "$pair_exit_present" = no ]
    }
    build_functional_relay_pair_fixtures() {
        pair_event pair-build
        functional_fixture_shape=pair
        functional_relay_state=marked
        functional_exit_relay_state=marked
        functional_pair_client_keeper_state=ready
        functional_pair_exit_keeper_state=ready
        functional_pair_client_link_state=moved
        functional_pair_exit_link_state=moved
        functional_pair_client_keeper_pid=41
        functional_pair_exit_keeper_pid=42
        pair_client_present=yes
        pair_exit_present=yes
        [ "$pair_failure" != pair-build ]
    }
    remove_functional_relay_pair_exit_fixture() {
        pair_event exit-remove
        [ "$pair_failure" != exit-remove ] || return 1
        pair_exit_present=no
        functional_exit_relay_state=absent
        functional_pair_exit_keeper_state=absent
        functional_pair_exit_link_state=absent
        functional_pair_exit_keeper_pid=
    }
    remove_functional_relay_pair_client_fixture() {
        pair_event client-remove
        [ "$pair_failure" != client-remove ] || return 1
        pair_client_present=no
        functional_relay_state=absent
        functional_pair_client_keeper_state=absent
        functional_pair_client_link_state=absent
        functional_pair_client_keeper_pid=
    }
    functional_relay_pair_fixtures_are_absent() {
        pair_event pair-absent
        [ "$pair_failure" != pair-absent ] \
            && [ "$pair_client_present" = no ] \
            && [ "$pair_exit_present" = no ] \
            && [ "$functional_relay_state" = absent ] \
            && [ "$functional_exit_relay_state" = absent ] \
            && [ "$functional_pair_client_keeper_state" = absent ] \
            && [ "$functional_pair_exit_keeper_state" = absent ]
    }
    pair_create() {
        create_functional_relay_pair_fixtures \
            AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA= 10002 \
            fd00:0000:0000:0000:0000:0000:0000:0002 \
            fd00:0000:0000:0000:0000:0000:0000:0001 \
            BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB= 10003 \
            fd00:0000:0000:0000:0000:0000:0000:0003 \
            fd00:0000:0000:0000:0000:0000:0000:0004
    }

    pair_reset none
    pair_create || return 1
    [ "$pair_events" = pair-build ] \
        && [ "$pair_client_present" = yes ] \
        && [ "$pair_exit_present" = yes ] \
        && [ "$functional_fixture_shape" = pair ] || return 1
    pair_events=
    remove_functional_relay_pair_fixtures || return 1
    [ "$pair_events" = exit-remove,client-remove,pair-absent ] \
        && [ "$pair_client_present" = no ] \
        && [ "$pair_exit_present" = no ] \
        && [ "$functional_fixture_shape" = single ] || return 1

    pair_reset pair-build
    ! pair_create || return 1
    [ "$pair_events" = pair-build,exit-remove,client-remove,pair-absent ] \
        && [ "$pair_client_present" = no ] \
        && [ "$pair_exit_present" = no ] \
        && [ "$functional_fixture_shape" = single ] || return 1

    pair_reset none
    pair_create || return 1
    pair_events=
    pair_failure=exit-remove
    ! remove_functional_relay_pair_fixtures || return 1
    [ "$pair_events" = exit-remove ] \
        && [ "$pair_client_present" = yes ] \
        && [ "$pair_exit_present" = yes ] \
        && [ "$functional_fixture_shape" = pair ] || return 1
    pair_failure=none
    pair_events=
    remove_functional_relay_pair_fixtures || return 1
    [ "$pair_events" = exit-remove,client-remove,pair-absent ] \
        && [ "$pair_client_present" = no ] \
        && [ "$pair_exit_present" = no ] \
        && [ "$functional_fixture_shape" = single ] || return 1
    pair_events=
    remove_functional_relay_pair_fixtures || return 1
    [ "$pair_events" = exit-remove,client-remove,pair-absent ] \
        && [ "$pair_client_present" = no ] \
        && [ "$pair_exit_present" = no ] \
        && [ "$functional_fixture_shape" = single ]
)
exercise_functional_relay_pair_lifecycle_edges || {
    printf '%s\n' \
        'production Relay-pair fixture is not atomic across failure and exact reverse cleanup' >&2
    exit 1
}

if ! awk '
    /^launch_functional_peer_keeper\(\) \{$/ { in_launch = 1; next }
    /^retire_functional_peer_keeper\(\) \{$/ { in_launch = 0; in_retire = 1; next }
    /^functional_pair_parent_wireguard_is_exact\(\) \{$/ { in_retire = 0 }
    in_launch && /\/usr\/bin\/unshare --net -- \/usr\/bin\/sleep 3600/ {
        anonymous_newnet = NR
    }
    in_launch && /functional_direct_child_is_exact/ { launch_child = NR }
    in_retire && /functional_peer_keeper_is_exact/ { retire_identity = NR }
    in_retire && /kill -TERM "\$hook_peer_pid"/ { retire_signal = NR }
    in_retire && /wait "\$hook_peer_pid"/ { retire_wait = NR }
    in_retire && /! -e "\/proc\/\$hook_peer_pid"/ { retire_absent = NR }
    /^build_functional_relay_pair_fixtures\(\) \{$/ { in_build = 1; next }
    /^create_functional_relay_pair_fixtures\(\) \{$/ { in_build = 0 }
    in_build && /if launch_functional_peer_keeper/ {
        launches++
        if (launches == 1) client_keeper = NR
        if (launches == 2) exit_keeper = NR
    }
    in_build && /functional_pair_client_namespace_identity" !=/ {
        distinct_namespaces = NR
    }
    in_build && /^    configure_functional_relay_pair_wireguard/ {
        client_wg_config = NR
    }
    in_build && /^    configure_functional_exit_relay_pair_wireguard/ {
        exit_wg_config = NR
    }
    in_build && /ip link set dev "\$functional_relay"/ { client_move = NR }
    in_build && /ip link set dev "\$functional_exit_relay"/ { exit_move = NR }
    in_build && /^    configure_functional_pair_peer_namespace/ {
        namespace_configs++
        if (namespace_configs == 1) client_namespace_config = NR
        if (namespace_configs == 2) exit_namespace_config = NR
    }
    in_build && /functional_relay_pair_fixtures_are_exact/ { exact = NR }
    END {
        launch = anonymous_newnet < launch_child
        retire = retire_identity < retire_signal && retire_signal < retire_wait
        retire = retire && retire_wait < retire_absent
        build = launches == 2 && namespace_configs == 2
        build = build && client_keeper < exit_keeper
        build = build && exit_keeper < distinct_namespaces
        build = build && distinct_namespaces < client_wg_config
        build = build && client_wg_config < exit_wg_config
        build = build && exit_wg_config < client_move
        build = build && client_move < client_namespace_config
        build = build && client_namespace_config < exit_move
        build = build && exit_move < exit_namespace_config
        build = build && exit_namespace_config < exact
        if (!(launch && retire && build)) exit 1
    }
' "$ipc_hook"; then
    printf '%s\n' \
        'Relay-pair peers are not anonymous NEWNET keepers with configure-before-move and exact reap' >&2
    exit 1
fi

# The real EXIT trap must preserve the paired wrapper's reverse-atomic edge:
# failure to prove/remove RelayExit may not target RelayClient. Singleton cleanup
# remains role-specific outside a paired fixture lifecycle.
hook_start_failure_exit_function=$temporary_directory/hook-start-failure-exit-function.sh
sed -n '/^start_failure_exit() {$/,/^}$/p' "$ipc_hook" \
    >"$hook_start_failure_exit_function"
test "$(grep -c '^start_failure_exit() {$' "$hook_start_failure_exit_function")" -eq 1
sh -n "$hook_start_failure_exit_function"
# shellcheck disable=SC2034,SC2317
exercise_start_failure_exit_edges() (
    # shellcheck disable=SC1090
    . "$hook_start_failure_exit_function"

    trap_event() {
        printf '%s\n' "$1" >>"$trap_event_file"
    }
    remove_functional_relay_pair_fixtures() {
        trap_event pair-remove
        [ "$trap_failure" != pair-remove ] || return 1
        functional_exit_relay_state=absent
        functional_relay_state=absent
        functional_fixture_shape=single
    }
    remove_functional_exit_relay_fixture() {
        trap_event exit-remove
        [ "$trap_failure" != exit-remove ] || return 1
        functional_exit_relay_state=absent
    }
    remove_functional_relay_fixture() {
        trap_event client-remove
        [ "$trap_failure" != client-remove ] || return 1
        functional_relay_state=absent
    }

    run_trap_case() (
        trap_event_file=$1
        functional_fixture_shape=$2
        functional_exit_relay_state=$3
        functional_relay_state=$4
        trap_failure=$5
        start_failure_armed=no
        start_failure_published=no
        : >"$trap_event_file"
        trap start_failure_exit EXIT
        exit 7
    )

    trap_pair_failure=$temporary_directory/trap-pair-failure.events
    expect_status 1 run_trap_case \
        "$trap_pair_failure" pair marked marked pair-remove
    [ "$(cat "$trap_pair_failure")" = pair-remove ] || return 1

    trap_pair_success=$temporary_directory/trap-pair-success.events
    expect_status 7 run_trap_case \
        "$trap_pair_success" pair marked marked none
    [ "$(cat "$trap_pair_success")" = pair-remove ] || return 1

    trap_exit_singleton=$temporary_directory/trap-exit-singleton.events
    expect_status 7 run_trap_case \
        "$trap_exit_singleton" single marked absent none
    [ "$(cat "$trap_exit_singleton")" = exit-remove ] || return 1

    trap_client_singleton=$temporary_directory/trap-client-singleton.events
    expect_status 7 run_trap_case \
        "$trap_client_singleton" single absent marked none
    [ "$(cat "$trap_client_singleton")" = client-remove ]
)
exercise_start_failure_exit_edges || {
    printf '%s\n' \
        'production EXIT trap breaks Relay-pair reverse atomicity or singleton cleanup' >&2
    exit 1
}

# The hook may retain a failed functional child only after observing its exact
# exit status with wait and validating one bounded, fully enumerated record.
hook_functional_failure_functions=$temporary_directory/hook-functional-failure-functions.sh
{
    sed -n '/^functional_probe_failure_value_is_safe() {$/,/^}$/p' "$ipc_hook"
    sed -n '/^functional_probe_failure_record_is_exact() {$/,/^}$/p' "$ipc_hook"
    sed -n '/^publish_functional_probe_failure() {$/,/^}$/p' "$ipc_hook"
    sed -n '/^observe_functional_probe_failure() {$/,/^}$/p' "$ipc_hook"
} >"$hook_functional_failure_functions"
test "$(grep -c '^[_a-z].*() {$' "$hook_functional_failure_functions")" -eq 4
sh -n "$hook_functional_failure_functions"
# shellcheck disable=SC1090
. "$hook_functional_failure_functions"
while IFS= read -r functional_failure_phase; do
    while IFS= read -r functional_failure_class; do
        functional_probe_failure_value_is_safe \
            "$functional_failure_phase,$functional_failure_class" || {
            printf 'hook rejected functional failure value: %s,%s\n' \
                "$functional_failure_phase" "$functional_failure_class" >&2
            exit 1
        }
    done <"$expected_functional_failure_classes"
done <"$expected_functional_failure_phases"
for invalid_functional_failure_value in \
    '' private,io prepare,private prepare,io,extra prepare/io; do
    if functional_probe_failure_value_is_safe "$invalid_functional_failure_value"; then
        printf 'hook accepted functional failure mutant: %s\n' \
            "$invalid_functional_failure_value" >&2
        exit 1
    fi
done
exercise_hook_functional_failure() (
    [ "$#" -eq 3 ] || exit 98
    hook_failure_name=$1
    hook_failure_value=$2
    hook_failure_status=$3
    hook_failure_directory=$temporary_directory/hook-functional-failure-$hook_failure_name
    mkdir -m 0700 "$hook_failure_directory"
    hook_failure_source=$hook_failure_directory/probe.stderr
    functional_failure_record=$hook_failure_directory/probe.failure
    functional_failure_prefix=VOLPAROSSA_HELPER_V3_FUNCTIONAL_CLIENT_LEASE_FAILURE_V1=
    printf '%s%s\n' "$functional_failure_prefix" "$hook_failure_value" \
        >"$hook_failure_source"
    chmod 0600 "$hook_failure_source"
    # Invoked indirectly by the extracted production hook helpers.
    # shellcheck disable=SC2317
    private_file_is_safe() {
        [ "$#" -eq 1 ] || return 1
        [ -f "$1" ] && [ ! -L "$1" ] \
            && [ "$(stat -Lc '%f:%u:%g:%a:%h' "$1" 2>/dev/null || true)" = \
                "8180:$(id -u):$(id -g):600:1" ]
    }
    # Invoked indirectly by the extracted production hook helpers.
    # shellcheck disable=SC2317
    write_private_file() {
        [ "$#" -eq 2 ] || return 1
        printf '%s\n' "$2" >"$1.next" || return 1
        chmod 0600 "$1.next" || return 1
        private_file_is_safe "$1.next" || return 1
        mv -- "$1.next" "$1" || return 1
        private_file_is_safe "$1"
    }
    # shellcheck disable=SC1090
    . "$hook_functional_failure_functions"
    publish_functional_probe_failure "$hook_failure_status" "$hook_failure_source"
    functional_probe_failure_record_is_exact "$functional_failure_record"
)
expect_status 0 exercise_hook_functional_failure \
    exact second-cycle-prepare,correlation 1
test ! -s "$last_stdout" && test ! -s "$last_stderr"
while read -r hook_failure_name hook_failure_value hook_failure_status; do
    expect_status 1 exercise_hook_functional_failure \
        "$hook_failure_name" "$hook_failure_value" "$hook_failure_status"
    test ! -s "$last_stdout" && test ! -s "$last_stderr"
done <<'EOF'
bad-phase private,io 1
bad-class prepare,private 1
extra-field prepare,io,extra 1
wrong-status prepare,io 2
success-status prepare,io 0
EOF

exercise_hook_functional_failure_wait() (
    hook_failure_directory=$temporary_directory/hook-functional-failure-wait
    mkdir -m 0700 "$hook_failure_directory"
    hook_failure_source=$hook_failure_directory/probe.stderr
    functional_failure_record=$hook_failure_directory/probe.failure
    functional_failure_prefix=VOLPAROSSA_HELPER_V3_FUNCTIONAL_CLIENT_LEASE_FAILURE_V1=
    printf '%s\n' \
        'VOLPAROSSA_HELPER_V3_FUNCTIONAL_CLIENT_LEASE_FAILURE_V1=connect,io' \
        >"$hook_failure_source"
    chmod 0600 "$hook_failure_source"
    # Invoked indirectly by the extracted production hook helpers.
    # shellcheck disable=SC2317
    private_file_is_safe() {
        [ "$#" -eq 1 ] || return 1
        [ -f "$1" ] && [ ! -L "$1" ] \
            && [ "$(stat -Lc '%f:%u:%g:%a:%h' "$1" 2>/dev/null || true)" = \
                "8180:$(id -u):$(id -g):600:1" ]
    }
    # Invoked indirectly by the extracted production hook helpers.
    # shellcheck disable=SC2317
    write_private_file() {
        printf '%s\n' "$2" >"$1.next" || return 1
        chmod 0600 "$1.next" || return 1
        mv -- "$1.next" "$1"
    }
    # Invoked indirectly by the extracted production hook helpers.
    # shellcheck disable=SC2317
    number_is_safe() {
        case $1 in ''|0|*[!0-9]*) return 1 ;; *) return 0 ;; esac
    }
    # shellcheck disable=SC1090
    . "$hook_functional_failure_functions"
    (exit 1) &
    hook_failure_pid=$!
    observe_functional_probe_failure "$hook_failure_pid" "$hook_failure_source"
    functional_probe_failure_record_is_exact "$functional_failure_record"
)
expect_status 0 exercise_hook_functional_failure_wait
test ! -s "$last_stdout" && test ! -s "$last_stderr"
# These are literal hook-source contracts; expansion would defeat the checks.
# shellcheck disable=SC2016
if [ "$(grep -Fc 'wait "$hook_functional_failure_pid"' "$ipc_hook")" -ne 1 ] \
    || [ "$(grep -Fc 'wait "$hook_functional_failure_pid"; then' "$ipc_hook")" -ne 1 ] \
    || [ "$(grep -Fc 'observe_functional_probe_failure' "$ipc_hook")" -ne 7 ]; then
    printf '%s\n' 'functional probe failures are not observed through exact child waits' >&2
    exit 1
fi
if [ "$(grep -Fc -- 'capture_unit_property CollectMode' "$gate")" -ne 2 ] \
    || [ "$(grep -Fc -- 'collect_mode" != inactive' "$gate")" -ne 2 ]; then
    printf '%s\n' \
        'both transient units do not read back exact nonaggressive collection' >&2
    exit 1
fi
if [ "$(grep -Fc -- 'capture_unit_property Type' "$gate")" -ne 2 ] \
    || [ "$(grep -Fc -- 'unit_type" != exec' "$gate")" -ne 2 ] \
    || [ "$(grep -Fc -- 'capture_unit_property RemainAfterExit' "$gate")" -ne 2 ] \
    || [ "$(grep -Fc -- 'remain_after_exit" !=' "$gate")" -ne 2 ]; then
    printf '%s\n' \
        'both transient units do not read back exact type and exit retention' >&2
    exit 1
fi
if [ "$(grep -Fc -- '--property=RuntimeMaxSec=180s' "$gate")" -ne 1 ]; then
    printf '%s\n' 'production IPC invocation does not have one exact runtime limit' >&2
    exit 1
fi
if [ "$(grep -Fc -- '--property=StandardOutput=null' "$gate")" -ne 3 ] \
    || [ "$(grep -Fc -- '--property=StandardError=null' "$gate")" -ne 3 ]; then
    printf '%s\n' 'production IPC and both restart invocations do not have exact null output streams' >&2
    exit 1
fi
# These are literal source paths; expansion here would defeat the check.
# shellcheck disable=SC2016
if grep -F -- '"$temporary_stage/production.stdout"' "$gate" >/dev/null \
    || grep -F -- '"$temporary_stage/production.stderr"' "$gate" >/dev/null; then
    printf '%s\n' 'production IPC proof still stages runtime output files' >&2
    exit 1
fi

# These are literal hook contracts; expansion here would defeat the check.
# shellcheck disable=SC2016
for required_hook_contract in \
    'runtime_directory=/run/volparossa' \
    'host_network_identity_record=/run/volparossa-helper-production-host-network.identity' \
    'helper_socket=$runtime_directory/helper.sock' \
    'cleanup_token=$runtime_directory/helper.cleanup-token' \
    'probe=/run/volparossa-helper-production-ipc-probe' \
    'production_helper=/run/volparossa-helper-production' \
    'restart_launcher=/run/volparossa-helper-restart-launcher' \
    'helper_bootstrap_capability_mask=00000000002031e0' \
    "'directory:0:0:2700'" \
    'systemd_exec_record_from_json() {' \
    "basic:'a(sasbttttuii)'|extended:'a(sasasttttuii)'" \
    '--arg expected_path /usr/bin/setpriv' \
    '--arg expected_regid "--regid=$hook_exec_gid"' \
    '--arg expected_groups "--groups=$hook_exec_gid"' \
    '--arg expected_entrypoint "$hook_exec_expected_entrypoint"' \
    'capture_systemd_launch_contract() {' \
    'yes) hook_launch_entrypoint=$restart_launcher ;;' \
    'org.freedesktop.systemd1.Service' \
    'ExecStart 2>/dev/null)' \
    'ExecStartEx 2>/dev/null)' \
    'capture_launch_image_metadata() {' \
    "stat -Lc '%d:%i:%F:%u:%g:%a:%h:%s'" \
    'capture_launch_image_identity() {' \
    'hook_image_digest=$(checksum_file "$1")' \
    'launch_image_matches_identity() {' \
    'process_starttime_from_stat() {' \
    'hook_starttime_path=/proc/$hook_starttime_pid/stat' \
    'process-starttime-v1=$hook_process_starttime' \
    'capture_helper_process_contract() {' \
    'hook_contract_status=/proc/$hook_contract_pid/status' \
    '$1 == "Uid:" {' \
    '$1 == "Gid:" {' \
    '$1 == "Groups:" {' \
    '$1 == "NoNewPrivs:" {' \
    '$1 == "Seccomp:" {' \
    '$1 == "Seccomp_filters:" {' \
    '$1 == "CapInh:" {' \
    '$1 == "CapPrm:" {' \
    '$1 == "CapEff:" {' \
    '$1 == "CapBnd:" {' \
    '$1 == "CapAmb:" {' \
    'process-status-v1=uid:0:0:0:0;gid:%s:%s:%s:%s;groups:%s;nnp:1;seccomp:2;caps:%s;filters:%s' \
    'hook_process_contract=$(capture_helper_process_contract' \
    '"$hook_identity_pid" "$hook_identity_gid")' \
    '"$hook_probe_unit" "$hook_probe_identity" "$hook_expected_agent_gid"' \
    'capture_socket_identity' \
    'socket_identity_is_unchanged' \
    'capture_lock_identity' \
    'write_private_file "$proof_directory/socket.identity" "$hook_socket_identity"' \
    'write_private_file "$proof_directory/lock.identity" "$hook_lock_identity"' \
    'exec 8<>"$journal_lock"' \
    'hook_active_lock_fd_identity=$(stat -Lc' \
    '/usr/bin/flock -n -x -E 42 8' \
    '[ "$hook_active_flock_status" -eq 42 ]' \
    'running_identity_is_unchanged "$hook_unit"' \
    '"$proof_directory/unit.identity" "$agent_gid"' \
    'exec 8>&-' \
    '/usr/bin/setpriv' \
    '--clear-groups' \
    '--groups="$hook_probe_groups"' \
    '--inh-caps=-all' \
    '--ambient-caps=-all' \
    '--bounding-set=-all' \
    '--no-new-privs' \
    '"$hook_expected_main_pid" "$hook_expected_agent_gid"' \
    '[ "$hook_probe_status" -eq 0 ] || return 1' \
    'run_probe bind-before bind-runtime "$agent_uid" "$agent_gid" "$operator_gid"' \
    'run_probe frame-bounds reject-frame-bounds "$agent_uid" "$agent_gid" "$operator_gid"' \
    'run_probe wire-shapes reject-wire-shapes "$agent_uid" "$agent_gid" "$operator_gid"' \
    'run_probe wrong-uid expect-unauthorised-peer "$worker_uid" "$agent_gid" clear' \
    'run_probe wrong-gid expect-unauthorised-peer "$agent_uid" "$operator_gid" "$agent_gid"' \
    'run_probe root-peer expect-unauthorised-peer 0 "$agent_gid" clear' \
    'run_probe bind-after bind-runtime "$agent_uid" "$agent_gid" "$operator_gid"' \
    'functional_underlay_address=192.31.195.254' \
    'functional_underlay_gateway=192.31.195.1' \
    'functional_underlay_alias=volparossa-proof-underlay-v1' \
    'functional_relay=vprl0' \
    'functional_relay_alias=volparossa-proof-relay-v1' \
    'functional_relay_listen_port=10000' \
    'functional_relay_public_key=MdSras7slhE3kXA3k25gcW+sVzr+lNnahKgCBEjfwRI=' \
    'functional_exit_relay=vpre0' \
    'functional_exit_relay_alias=volparossa-proof-relay-exit-v1' \
    'functional_exit_relay_listen_port=10001' \
    'functional_exit_relay_public_key=c7LYt2qptTZgAyvI9di+46OuTjs6f9Sa3oH3NHo0qmg=' \
    'functional_relay_state=absent' \
    'functional_relay_state=adding' \
    'capture_functional_relay_ifindex || return 1' \
    'functional_relay_ifindex=$hook_captured_relay_ifindex' \
    'functional_relay_state=created' \
    'functional_relay_state=marked' \
    'functional_relay_state=deleted' \
    'emit_functional_relay_private_key() {' \
    'emit_functional_exit_relay_private_key() {' \
    '/usr/bin/base64 -w 0' \
    'functional_ready_record=VOLPAROSSA_HELPER_V3_FUNCTIONAL_CLIENT_LEASE_V1=ready' \
    'functional_activated_kernel_record=VOLPAROSSA_HELPER_V3_FUNCTIONAL_CLIENT_LEASE_ACTIVATED_KERNEL_V1=pass' \
    'functional_committed_kernel_record=VOLPAROSSA_HELPER_V3_FUNCTIONAL_CLIENT_LEASE_COMMITTED_KERNEL_V1=pass' \
    'functional_pass_record=VOLPAROSSA_HELPER_V3_FUNCTIONAL_CLIENT_LEASE_V1=pass' \
    'functional_cleanup_record=VOLPAROSSA_HELPER_V3_FUNCTIONAL_CLIENT_LEASE_EXTERNAL_CLEANUP_V1=pass' \
    'functional_exit_ready_record=VOLPAROSSA_HELPER_V3_FUNCTIONAL_EXIT_LEASE_V1=ready' \
    'functional_exit_activated_kernel_record=VOLPAROSSA_HELPER_V3_FUNCTIONAL_EXIT_LEASE_ACTIVATED_KERNEL_V1=pass' \
    'functional_exit_committed_kernel_record=VOLPAROSSA_HELPER_V3_FUNCTIONAL_EXIT_LEASE_COMMITTED_KERNEL_V1=pass' \
    'functional_exit_pass_record=VOLPAROSSA_HELPER_V3_FUNCTIONAL_EXIT_LEASE_V1=pass' \
    'functional_exit_cleanup_record=VOLPAROSSA_HELPER_V3_FUNCTIONAL_EXIT_LEASE_EXTERNAL_CLEANUP_V1=pass' \
    'functional_relay_pair_ready_record=VOLPAROSSA_HELPER_V3_FUNCTIONAL_RELAY_PAIR_LEASE_V1=ready' \
    'functional_relay_pair_activated_kernel_record=VOLPAROSSA_HELPER_V3_FUNCTIONAL_RELAY_PAIR_LEASE_ACTIVATED_KERNEL_V1=pass' \
    'functional_relay_pair_committed_kernel_record=VOLPAROSSA_HELPER_V3_FUNCTIONAL_RELAY_PAIR_LEASE_COMMITTED_KERNEL_V1=pass' \
    'functional_relay_pair_pass_record=VOLPAROSSA_HELPER_V3_FUNCTIONAL_RELAY_PAIR_LEASE_V1=pass' \
    'functional_relay_pair_cleanup_record=VOLPAROSSA_HELPER_V3_FUNCTIONAL_RELAY_PAIR_LEASE_EXTERNAL_CLEANUP_V1=pass' \
    'functional_fixture_shape=single' \
    'functional_peer_public_key=$functional_relay_public_key' \
    'functional_peer_endpoint=$functional_underlay_address:$functional_relay_listen_port' \
    'functional_peer_keepalive=25' \
    'functional_release_byte=G' \
    '/usr/sbin/ip link add name "$functional_underlay" type dummy' \
    '/usr/sbin/ip address add "$functional_underlay_address/24"' \
    '/usr/sbin/ip route add default via "$functional_underlay_gateway"' \
    'mkfifo -m 0600 "$hook_functional_fifo"' \
    "'fifo:0:0:600:1'" \
    'command exec 6<>"$hook_functional_fifo"' \
    '"$probe" functional-client-lease' \
    '<"$hook_functional_fifo"' \
    'probe_output_is_exact' \
    '"$hook_functional_stdout" "$functional_ready_record"' \
    '[ "$hook_functional_wait_attempt" -lt 300 ] || return 1' \
    'hook_functional_worker_pid=$(direct_helper_child "$hook_functional_main_pid")' \
    'hook_entry_contract_is_exact() {' \
    'capture_helper_process_contract "$$" "$hook_entry_gid"' \
    'hook_entry_contract_is_exact "$agent_gid"' \
    'hook_entry_contract_is_exact "$hook_expected_agent_gid"' \
    'process_contract_filter_count() {' \
    'fd_number_is_safe() {' \
    'worker_status_from_process_fd_is_exact() {' \
    'capture_traced_process_starttime_from_fd() {' \
    'traced_worker_identity_from_process_fd() {' \
    'worker_identity_from_process_fd() {' \
    'capture_process_starttime_from_fd() {' \
    'hook_worker_expected_filters=$((hook_worker_parent_filters + 1))' \
    'if (NF != 2 || $2 != expected_pid) invalid = 1' \
    'if (NF != 2 || $2 != expected_filters) invalid = 1' \
    'if (NF != 2 || $2 != "0000000000001000") invalid = 1' \
    'pidfd_record_from_fdinfo() {' \
    'capture_parent_pidfd_record() {' \
    'hook_custody_pidfd_identity=$hook_custody_observed_identity' \
    'capture_parent_worker_custody() {' \
    "'anon_inode:[pidfd]'" \
    'capture_parent_process_fd_identity' \
    'capture_parent_namespace_fd_identity' \
    '"$hook_functional_parent_namespace" != "$hook_functional_worker_namespace"' \
    'command exec 7<"$hook_functional_parent_namespace_path"' \
    'command exec 8<"$hook_functional_parent_process_path"' \
    'worker_identity_from_process_fd' \
    '/usr/bin/nsenter --net="/proc/self/fd/$hook_namespace_fd" --' \
    '/usr/bin/wg show interfaces' \
    'derive_client_peer_address() {' \
    'derive_client_local_address() {' \
    'derive_exit_peer_address() {' \
    'derive_exit_local_address() {' \
    'worker_relay_pair_interfaces() {' \
    'derive_relay_pair_address() {' \
    'worker_relay_pair_address() {' \
    'wireguard_counter_line_is_exact() {' \
    'wireguard_snapshot_from_lines() {' \
    'wireguard_snapshot_has_growth() {' \
    'activated_route_destination() {' \
    '/usr/bin/cat /proc/net/if_inet6' \
    '/usr/sbin/ip -6 -json route show table main' \
    '/usr/bin/wg show "$hook_interface" allowed-ips' \
    '/usr/bin/wg show "$hook_interface" latest-handshakes' \
    '/usr/bin/wg show "$hook_interface" transfer' \
    'worker_wireguard_interface 7' \
    'worker_client_peer_address' \
    'worker_client_local_address' \
    'worker_activated_wireguard_is_exact' \
    'create_functional_relay_fixture' \
    'functional_relay_fixture_is_exact' \
    '/usr/bin/ping -6 -n -I "$functional_relay"' \
    'remove_functional_relay_fixture' \
    'create_functional_exit_relay_fixture' \
    'functional_exit_relay_fixture_is_exact' \
    '/usr/bin/ping -6 -n -I "$functional_exit_relay"' \
    'remove_functional_exit_relay_fixture' \
    '/usr/bin/unshare --net -- /usr/bin/sleep 3600' \
    'functional_peer_keeper_is_exact() {' \
    'functional_pair_client_namespace_identity' \
    'functional_pair_exit_namespace_identity' \
    'configure_functional_relay_pair_wireguard' \
    'configure_functional_exit_relay_pair_wireguard' \
    'netns "$functional_pair_client_keeper_pid"' \
    'netns "$functional_pair_exit_keeper_pid"' \
    'create_functional_relay_pair_fixtures' \
    'functional_relay_pair_fixtures_are_exact' \
    'remove_functional_relay_pair_fixtures' \
    'functional_relay_pair_fixtures_are_absent' \
    'printf '"'"'%s'"'"' "$functional_release_byte" >&6' \
    'wait "$hook_functional_probe_pid"' \
    'functional_probe_output_is_exact "$hook_functional_stdout"' \
    'helper_has_no_children "$hook_functional_main_pid"' \
    'worker_process_fd_is_retired 8' \
    'helper_holds_no_worker_custody() {' \
    'wait_for_helper_no_worker_custody() {' \
    'wait_for_helper_no_worker_custody "$hook_functional_main_pid"' \
    'worker_wireguard_is_absent 7 "$hook_functional_peer_address"' \
    'command exec 8>&-' \
    'command exec 7>&-' \
    'private_network_is_pristine' \
    'private_file_is_safe "$host_network_identity_record"' \
    'hook_host_namespace=$(cat "$host_network_identity_record")' \
    'kernel_object_identity_is_safe "$hook_host_namespace"' \
    '"$hook_private_namespace" != "$hook_host_namespace"' \
    '[ "$(cat "$host_network_identity_record")" = "$hook_host_namespace" ]' \
    '/usr/sbin/ip -json route show default' \
    '/usr/sbin/ip -6 -json route show default' \
    'unit_fdstore_is_empty' \
    'capture_fdstore_descriptor_identity() {' \
    'fdstore_dump_exact_custody_name() {' \
    'hook_descriptor_status_flags=$((hook_descriptor_status_flags & ~524288 & ~32768))' \
    'unit_fdstore_exact_active_custody() {' \
    'unit_fdstore_prior_custody_is_absent() {' \
    'remove_functional_underlay "$hook_functional_ifindex"' \
    'run_functional_client_lease_probe' \
    'VOLPAROSSA_HELPER_V3_IPC_BIND_RUNTIME_V1=pass' \
    'VOLPAROSSA_HELPER_V3_IPC_FRAME_BOUNDS_V1=pass' \
    'VOLPAROSSA_HELPER_V3_IPC_WIRE_SHAPES_V1=pass' \
    'VOLPAROSSA_HELPER_V3_IPC_UNAUTHORISED_PEER_V1=pass' \
    'VOLPAROSSA_HELPER_V3_IPC_BIND_BEFORE_V1=pass' \
    'VOLPAROSSA_HELPER_V3_IPC_WRONG_UID_V1=pass' \
    'VOLPAROSSA_HELPER_V3_IPC_WRONG_GID_V1=pass' \
    'VOLPAROSSA_HELPER_V3_IPC_ROOT_PEER_V1=pass' \
    'VOLPAROSSA_HELPER_V3_IPC_BIND_AFTER_V1=pass' \
    'VOLPAROSSA_HELPER_V3_FUNCTIONAL_CLIENT_LEASE_V1=ready' \
    'VOLPAROSSA_HELPER_V3_FUNCTIONAL_CLIENT_LEASE_SETTLED_V1=pass' \
    'VOLPAROSSA_HELPER_V3_FUNCTIONAL_CLIENT_LEASE_ACTIVATED_KERNEL_V1=pass' \
    'VOLPAROSSA_HELPER_V3_FUNCTIONAL_CLIENT_LEASE_COMMITTED_KERNEL_V1=pass' \
    'VOLPAROSSA_HELPER_V3_FUNCTIONAL_CLIENT_LEASE_V1=pass' \
    'VOLPAROSSA_HELPER_V3_FUNCTIONAL_CLIENT_LEASE_EXTERNAL_CLEANUP_V1=pass' \
    'VOLPAROSSA_HELPER_V3_FUNCTIONAL_EXIT_LEASE_V1=ready' \
    'VOLPAROSSA_HELPER_V3_FUNCTIONAL_EXIT_LEASE_ACTIVATED_KERNEL_V1=pass' \
    'VOLPAROSSA_HELPER_V3_FUNCTIONAL_EXIT_LEASE_COMMITTED_KERNEL_V1=pass' \
    'VOLPAROSSA_HELPER_V3_FUNCTIONAL_EXIT_LEASE_V1=pass' \
    'VOLPAROSSA_HELPER_V3_FUNCTIONAL_EXIT_LEASE_EXTERNAL_CLEANUP_V1=pass' \
    'VOLPAROSSA_HELPER_V3_FUNCTIONAL_RELAY_PAIR_LEASE_V1=ready' \
    'VOLPAROSSA_HELPER_V3_FUNCTIONAL_RELAY_PAIR_LEASE_ACTIVATED_KERNEL_V1=pass' \
    'VOLPAROSSA_HELPER_V3_FUNCTIONAL_RELAY_PAIR_LEASE_COMMITTED_KERNEL_V1=pass' \
    'VOLPAROSSA_HELPER_V3_FUNCTIONAL_RELAY_PAIR_LEASE_V1=pass' \
    'VOLPAROSSA_HELPER_V3_FUNCTIONAL_RELAY_PAIR_LEASE_EXTERNAL_CLEANUP_V1=pass' \
    'VOLPAROSSA_HELPER_V3_FUNCTIONAL_JOURNAL_SETTLED_V1=pass' \
    'VOLPAROSSA_HELPER_V3_FUNCTIONAL_FDSTORE_CYCLES_V1=pass' \
    'prove-settled-journal' \
    '[ "${SERVICE_RESULT:-}" = success ]' \
    '[ "${EXIT_CODE:-}" = exited ]' \
    '[ "${EXIT_STATUS:-}" = 0 ]' \
    '[ "$#" -eq 2 ] || fail '"'"'stop hook argument count is invalid'"'"'' \
    'hook_expected_agent_gid=$2' \
    'capture_journal_state' \
    "stat -c '%d:%i:%f:%u:%g:%a:%h:%s:%y:%z'" \
    'hook_expected_lock_identity=$(cat "$proof_directory/lock.identity")' \
    'command exec 9<>"$journal_lock"' \
    'hook_lock_fd_identity=$(stat -Lc' \
    '/usr/bin/flock -n 9' \
    'unit_u32_property' \
    'NFileDescriptorStore' \
    '[ "$hook_fdstore_count" = 0 ]' \
    'VOLPAROSSA_HELPER_V3_IPC_CLEAN_SHUTDOWN_V1=pass'
do
    grep -F -- "$required_hook_contract" "$ipc_hook" >/dev/null || {
        printf 'missing production IPC hook contract: %s\n' "$required_hook_contract" >&2
        exit 1
    }
done
if grep -F '/proc/1/ns/net' "$ipc_hook" >/dev/null; then
    printf '%s\n' \
        'production hook regained ptrace-gated PID 1 namespace inspection' >&2
    exit 1
fi
for worker_launch_anchor in \
    'crate::worker_sandbox::WorkerKernelPins::pin_process(child)' \
    'ExpectedUnixCredentials::new(child_pid, worker_identity.uid(), worker_identity.gid())' \
    'parent_handshake(&process, observation, challenge, binding)' \
    'prctl::set_dumpable(false)' \
    'send_credential_record(&channel, &accepted.sandbox_ready().encode())'
do
    grep -F -- "$worker_launch_anchor" "$worker_source" >/dev/null || {
        printf 'worker launch anchor is missing: %s\n' "$worker_launch_anchor" >&2
        exit 1
    }
done
for worker_kernel_anchor in \
    'pidfd_open(Pid::from_child(child), PidfdFlags::empty())' \
    'process_directory = open(' \
    'pin_network_namespace_before_identity_drop('
do
    grep -F -- "$worker_kernel_anchor" "$worker_sandbox_source" >/dev/null || {
        printf 'worker kernel anchor is missing: %s\n' "$worker_kernel_anchor" >&2
        exit 1
    }
done

activated_parser_functions=$temporary_directory/activated-parser-functions.sh
for activated_parser_function in \
    derive_client_peer_address \
    derive_client_local_address \
    derive_exit_peer_address \
    derive_exit_local_address \
    derive_relay_pair_address \
    wireguard_counter_line_is_exact \
    wireguard_snapshot_from_lines \
    wireguard_snapshot_has_growth \
    activated_route_destination
do
    sed -n "/^$activated_parser_function() {$/,/^}$/p" "$ipc_hook" \
        >>"$activated_parser_functions"
    if [ "$(grep -c "^$activated_parser_function() {$" \
        "$activated_parser_functions")" -ne 1 ]; then
        printf 'activated kernel parser is not uniquely extractable: %s\n' \
            "$activated_parser_function" >&2
        exit 1
    fi
done
sh -n "$activated_parser_functions"
# shellcheck source=/dev/null
. "$activated_parser_functions"

functional_peer_key=MdSras7slhE3kXA3k25gcW+sVzr+lNnahKgCBEjfwRI=
functional_interface=vpc1proof
valid_client_address='fd766f6c70611234567800019abc0001 02 80 00 80 vpc1proof'
link_local_address='fe80000000000000123456fffe789abc 02 40 20 80 vpc1proof'
expected_peer_address=fd76:6f6c:7061:1234:5678:0001:9abc:0002
observed_peer_address=$(printf '%s\n%s\n' \
    "$valid_client_address" "$link_local_address" \
    | derive_client_peer_address "$functional_interface") \
    || {
        printf '%s\n' 'valid Client topology address was rejected' >&2
        exit 1
    }
if [ "$observed_peer_address" != "$expected_peer_address" ]; then
    printf '%s\n' 'Client peer address was not derived as exact topology host ::2' >&2
    exit 1
fi
expected_local_address=fd76:6f6c:7061:1234:5678:0001:9abc:0001
observed_local_address=$(printf '%s\n%s\n' \
    "$valid_client_address" "$link_local_address" \
    | derive_client_local_address "$functional_interface") || {
        printf '%s\n' 'valid Client local topology address was rejected' >&2
        exit 1
    }
if [ "$observed_local_address" != "$expected_local_address" ]; then
    printf '%s\n' 'Client local address parser changed the exact topology host ::1' >&2
    exit 1
fi
for invalid_client_address in \
    'fd776f6c70611234567800019abc0001 02 80 00 80 vpc1proof' \
    'fd766f6c70611234567800029abc0001 02 80 00 80 vpc1proof' \
    'fd766f6c70611234567800019abc0002 02 80 00 80 vpc1proof' \
    'fd766f6c70611234567800019abc0001 02 70 00 80 vpc1proof' \
    'fd766f6c70611234567800019abc0001 02 80 20 80 vpc1proof' \
    'fd766f6c70611234567800019abc0001 02 80 00 80 other'
do
    if printf '%s\n' "$invalid_client_address" \
        | derive_client_peer_address "$functional_interface" >/dev/null 2>&1 \
        || printf '%s\n' "$invalid_client_address" \
            | derive_client_local_address "$functional_interface" >/dev/null 2>&1; then
        printf 'invalid Client topology address was accepted: %s\n' \
            "$invalid_client_address" >&2
        exit 1
    fi
done
if printf '%s\n%s\n' "$valid_client_address" "$valid_client_address" \
    | derive_client_peer_address "$functional_interface" >/dev/null 2>&1 \
    || printf '%s\n%s\n' "$valid_client_address" "$valid_client_address" \
        | derive_client_local_address "$functional_interface" >/dev/null 2>&1; then
    printf '%s\n' 'duplicate Client topology addresses were accepted' >&2
    exit 1
fi

valid_exit_address='fd766f6c70611234567800019abc0004 02 80 00 80 vpc1proof'
expected_exit_peer_address=fd76:6f6c:7061:1234:5678:0001:9abc:0003
observed_exit_peer_address=$(printf '%s\n%s\n' \
    "$valid_exit_address" "$link_local_address" \
    | derive_exit_peer_address "$functional_interface") || {
        printf '%s\n' 'valid Exit topology address was rejected' >&2
        exit 1
    }
[ "$observed_exit_peer_address" = "$expected_exit_peer_address" ] || {
    printf '%s\n' 'Exit peer address was not derived as exact topology host ::3' >&2
    exit 1
}
expected_exit_local_address=fd76:6f6c:7061:1234:5678:0001:9abc:0004
observed_exit_local_address=$(printf '%s\n%s\n' \
    "$valid_exit_address" "$link_local_address" \
    | derive_exit_local_address "$functional_interface") || {
        printf '%s\n' 'valid Exit local topology address was rejected' >&2
        exit 1
    }
[ "$observed_exit_local_address" = "$expected_exit_local_address" ] || {
    printf '%s\n' 'Exit local address parser changed the exact topology host ::4' >&2
    exit 1
}
for invalid_exit_address in \
    'fd776f6c70611234567800019abc0004 02 80 00 80 vpc1proof' \
    'fd766f6c70611234567800029abc0004 02 80 00 80 vpc1proof' \
    'fd766f6c70611234567800019abc0003 02 80 00 80 vpc1proof' \
    'fd766f6c70611234567800019abc0004 02 70 00 80 vpc1proof' \
    'fd766f6c70611234567800019abc0004 02 80 20 80 vpc1proof' \
    'fd766f6c70611234567800019abc0004 02 80 00 80 other'
do
    if printf '%s\n' "$invalid_exit_address" \
        | derive_exit_peer_address "$functional_interface" >/dev/null 2>&1 \
        || printf '%s\n' "$invalid_exit_address" \
            | derive_exit_local_address "$functional_interface" >/dev/null 2>&1; then
        printf 'invalid Exit topology address was accepted: %s\n' \
            "$invalid_exit_address" >&2
        exit 1
    fi
done
if printf '%s\n%s\n' "$valid_exit_address" "$valid_exit_address" \
    | derive_exit_peer_address "$functional_interface" >/dev/null 2>&1 \
    || printf '%s\n%s\n' "$valid_exit_address" "$valid_exit_address" \
        | derive_exit_local_address "$functional_interface" >/dev/null 2>&1 \
    || printf '%s\n' "$valid_client_address" \
        | derive_exit_local_address "$functional_interface" >/dev/null 2>&1 \
    || printf '%s\n' "$valid_exit_address" \
        | derive_client_local_address "$functional_interface" >/dev/null 2>&1; then
    printf '%s\n' 'duplicate or cross-role topology addresses were accepted' >&2
    exit 1
fi

relay_client_interface=vpr1deadbeef
relay_exit_interface=vps1deadbeef
valid_relay_client_address='fd766f6c70611234567800019abc0002 02 80 00 80 vpr1deadbeef'
valid_relay_exit_address='fd766f6c70611234567800019abc0003 03 80 00 80 vps1deadbeef'
relay_pair_client_peer=$(printf '%s\n' "$valid_relay_client_address" \
    | derive_relay_pair_address "$relay_client_interface" 0002 0001) || exit 1
relay_pair_client_local=$(printf '%s\n' "$valid_relay_client_address" \
    | derive_relay_pair_address "$relay_client_interface" 0002 0002) || exit 1
relay_pair_exit_local=$(printf '%s\n' "$valid_relay_exit_address" \
    | derive_relay_pair_address "$relay_exit_interface" 0003 0003) || exit 1
relay_pair_exit_peer=$(printf '%s\n' "$valid_relay_exit_address" \
    | derive_relay_pair_address "$relay_exit_interface" 0003 0004) || exit 1
if [ "$relay_pair_client_peer" != \
        fd76:6f6c:7061:1234:5678:0001:9abc:0001 ] \
    || [ "$relay_pair_client_local" != \
        fd76:6f6c:7061:1234:5678:0001:9abc:0002 ] \
    || [ "$relay_pair_exit_local" != \
        fd76:6f6c:7061:1234:5678:0001:9abc:0003 ] \
    || [ "$relay_pair_exit_peer" != \
        fd76:6f6c:7061:1234:5678:0001:9abc:0004 ]; then
    printf '%s\n' 'Relay-pair parser did not preserve exact ::1/::2/::3/::4 roles' >&2
    exit 1
fi
if printf '%s\n' "$valid_relay_client_address" \
        | derive_relay_pair_address "$relay_client_interface" 0002 0004 \
            >/dev/null 2>&1 \
    || printf '%s\n' "$valid_relay_exit_address" \
        | derive_relay_pair_address "$relay_exit_interface" 0003 0001 \
            >/dev/null 2>&1 \
    || printf '%s\n' "$valid_relay_client_address" \
        | derive_relay_pair_address "$relay_exit_interface" 0002 0001 \
            >/dev/null 2>&1 \
    || printf '%s\n%s\n' \
        "$valid_relay_client_address" "$valid_relay_client_address" \
        | derive_relay_pair_address "$relay_client_interface" 0002 0001 \
            >/dev/null 2>&1 \
    || printf '%s\n' \
        'fd766f6c70611234567800029abc0002 02 80 00 80 vpr1deadbeef' \
        | derive_relay_pair_address "$relay_client_interface" 0002 0001 \
            >/dev/null 2>&1; then
    printf '%s\n' \
        'Relay-pair parser accepted a role, interface, duplicate, or path substitution' >&2
    exit 1
fi

valid_handshake_line=$(printf '%s\t%s' "$functional_peer_key" 123)
valid_transfer_line=$(printf '%s\t%s\t%s' "$functional_peer_key" 11 21)
valid_snapshot=$(wireguard_snapshot_from_lines \
    "$valid_handshake_line" "$valid_transfer_line" "$functional_peer_key") || {
        printf '%s\n' 'valid WireGuard proof snapshot was rejected' >&2
        exit 1
    }
expected_snapshot=$(printf '123\t11\t21')
[ "$valid_snapshot" = "$expected_snapshot" ] || {
    printf '%s\n' 'WireGuard proof snapshot changed canonical counters' >&2
    exit 1
}
baseline_snapshot=$(printf '0\t10\t20')
wireguard_snapshot_has_growth "$baseline_snapshot" "$valid_snapshot" || {
    printf '%s\n' 'strict bidirectional WireGuard growth was rejected' >&2
    exit 1
}
for rejected_snapshot in \
    "$(printf '0\t11\t21')" \
    "$(printf '123\t10\t21')" \
    "$(printf '123\t11\t20')" \
    "$(printf '123\t9\t22')" \
    "$(printf '123\t12\t19')" \
    "$(printf '123\t18446744073709551616\t22')"
do
    if wireguard_snapshot_has_growth \
        "$baseline_snapshot" "$rejected_snapshot"; then
        printf 'invalid WireGuard proof growth was accepted: %s\n' \
            "$rejected_snapshot" >&2
        exit 1
    fi
done
wrong_snapshot_key=$(printf '%s\t1' \
    AAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAg=)
extra_snapshot_transfer=$(printf '%s\t11\t21\n%s\t12\t22' \
    "$functional_peer_key" "$functional_peer_key")
if wireguard_snapshot_from_lines \
    "$wrong_snapshot_key" "$valid_transfer_line" "$functional_peer_key" \
    >/dev/null 2>&1 \
    || wireguard_snapshot_from_lines \
        "$valid_handshake_line" "$extra_snapshot_transfer" \
        "$functional_peer_key" >/dev/null 2>&1; then
    printf '%s\n' 'substituted or extra WireGuard snapshot record was accepted' >&2
    exit 1
fi

for valid_counter in 0 1 18446744073709551615
do
    valid_counter_line=$(printf '%s\t%s' "$functional_peer_key" "$valid_counter")
    wireguard_counter_line_is_exact \
        "$valid_counter_line" "$functional_peer_key" 2 || {
            printf 'canonical WireGuard counter was rejected: %s\n' \
                "$valid_counter" >&2
            exit 1
        }
done
valid_transfer_line=$(printf '%s\t%s\t%s' \
    "$functional_peer_key" 0 18446744073709551615)
wireguard_counter_line_is_exact \
    "$valid_transfer_line" "$functional_peer_key" 3 || {
        printf '%s\n' 'canonical WireGuard rx/tx counters were rejected' >&2
        exit 1
    }
for invalid_counter in 00 01 -1 +1 18446744073709551616 999999999999999999999
do
    invalid_counter_line=$(printf '%s\t%s' \
        "$functional_peer_key" "$invalid_counter")
    if wireguard_counter_line_is_exact \
        "$invalid_counter_line" "$functional_peer_key" 2; then
        printf 'non-canonical WireGuard counter was accepted: %s\n' \
            "$invalid_counter" >&2
        exit 1
    fi
done
wrong_key_counter=$(printf '%s\t%s' \
    AAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAg= 0)
extra_counter=$(printf '%s\t%s\t%s' "$functional_peer_key" 0 0)
duplicate_counter=$(printf '%s\t0\n%s\t0' \
    "$functional_peer_key" "$functional_peer_key")
if wireguard_counter_line_is_exact \
    "$wrong_key_counter" "$functional_peer_key" 2 \
    || wireguard_counter_line_is_exact \
        "$extra_counter" "$functional_peer_key" 2 \
    || wireguard_counter_line_is_exact \
        "$duplicate_counter" "$functional_peer_key" 2; then
    printf '%s\n' 'substituted or non-singleton WireGuard counter record was accepted' >&2
    exit 1
fi

valid_route='[{"dst":"fd76:6f6c:7061:1234:5678:1:9abc:2","dev":"vpc1proof","protocol":"static","metric":1024,"flags":[],"pref":"medium"}]'
observed_route=$(printf '%s\n' "$valid_route" \
    | activated_route_destination "$functional_interface") || {
        printf '%s\n' 'exact activated main-table route was rejected' >&2
        exit 1
    }
if [ "$observed_route" != 'fd76:6f6c:7061:1234:5678:1:9abc:2' ]; then
    printf '%s\n' 'activated route parser changed the exact peer destination' >&2
    exit 1
fi
for route_mutation in \
    '.[0].dst = "default"' \
    '.[0].dev = "other"' \
    '.[0].protocol = "kernel"' \
    '.[0].metric = 1023' \
    '.[0].flags = ["onlink"]' \
    '.[0].pref = "high"' \
    '.[0].gateway = "fd00::1"' \
    '.[0].nexthops = [{"dev":"vpc1proof"}]' \
    '.[0].prefsrc = "fd00::1"' \
    '.[0].src = "fd00::/64"'
do
    mutated_route=$(printf '%s\n' "$valid_route" \
        | /usr/bin/jq -c "$route_mutation") || exit 1
    if printf '%s\n' "$mutated_route" \
        | activated_route_destination "$functional_interface" >/dev/null 2>&1; then
        printf 'substituted activated route was accepted: %s\n' \
            "$route_mutation" >&2
        exit 1
    fi
done
two_routes=$(printf '%s\n%s\n' "$valid_route" "$valid_route" \
    | /usr/bin/jq -s 'add') || exit 1
if printf '%s\n' '[]' \
    | activated_route_destination "$functional_interface" >/dev/null 2>&1 \
    || printf '%s\n' "$two_routes" \
        | activated_route_destination "$functional_interface" >/dev/null 2>&1; then
    printf '%s\n' 'absent or non-singleton activated route was accepted' >&2
    exit 1
fi
if [ "$(grep -Fc \
    'VOLPAROSSA_HELPER_V3_FUNCTIONAL_CLIENT_LEASE_ACTIVATED_KERNEL_V1=pass' \
    "$gate")" -ne 1 ]; then
    printf '%s\n' 'KVM harness does not require one activated-kernel record' >&2
    exit 1
fi
if [ "$(grep -Fc \
    'VOLPAROSSA_HELPER_V3_FUNCTIONAL_CLIENT_LEASE_COMMITTED_KERNEL_V1=pass' \
    "$gate")" -ne 1 ]; then
    printf '%s\n' 'KVM harness does not require one committed-kernel record' >&2
    exit 1
fi
for required_role_kernel_record in \
    'VOLPAROSSA_HELPER_V3_FUNCTIONAL_EXIT_LEASE_ACTIVATED_KERNEL_V1=pass' \
    'VOLPAROSSA_HELPER_V3_FUNCTIONAL_EXIT_LEASE_COMMITTED_KERNEL_V1=pass' \
    'VOLPAROSSA_HELPER_V3_FUNCTIONAL_RELAY_PAIR_LEASE_ACTIVATED_KERNEL_V1=pass' \
    'VOLPAROSSA_HELPER_V3_FUNCTIONAL_RELAY_PAIR_LEASE_COMMITTED_KERNEL_V1=pass'
do
    if [ "$(grep -Fc "$required_role_kernel_record" "$gate")" -ne 1 ]; then
        printf 'KVM harness does not require one role kernel record: %s\n' \
            "$required_role_kernel_record" >&2
        exit 1
    fi
done

hook_process_contract_source_is_exact() {
    [ "$#" -eq 1 ] || return 1
    hook_contract_source=$1
    [ -f "$hook_contract_source" ] && [ ! -L "$hook_contract_source" ] || return 1
    awk '
        $0 == "helper_bootstrap_capability_mask=00000000002031e0" { mask++ }
        /^capture_helper_process_contract\(\) \{$/ { in_contract = 1; next }
        /^capture_running_identity\(\) \{$/ {
            in_contract = 0
            in_identity = 1
            next
        }
        /^running_identity_is_unchanged\(\) \{$/ {
            in_identity = 0
            in_recheck = 1
            next
        }
        /^probe_output_is_exact\(\) \{$/ { in_recheck = 0 }
        in_contract && /\$1 == "Pid:"/ { pid_field++ }
        in_contract && /\$1 == "Uid:"/ { uid_field++ }
        in_contract && /\$1 == "Gid:"/ { gid_field++ }
        in_contract && /\$1 == "Groups:"/ { groups_field++ }
        in_contract && /\$1 == "NoNewPrivs:"/ { nnp_field++ }
        in_contract && /\$1 == "Seccomp:"/ { seccomp_field++ }
        in_contract && /\$1 == "Seccomp_filters:"/ { filters_field++ }
        in_contract && /\$1 == "CapInh:"/ { inherited_field++ }
        in_contract && /\$1 == "CapPrm:"/ { permitted_field++ }
        in_contract && /\$1 == "CapEff:"/ { effective_field++ }
        in_contract && /\$1 == "CapBnd:"/ { bounding_field++ }
        in_contract && /\$1 == "CapAmb:"/ { ambient_field++ }
        in_contract && /NF != 5 \|\| \$2 != 0 \|\| \$3 != 0/ { uid_exact++ }
        in_contract && /NF != 5 \|\| \$2 != expected_gid/ { gid_exact++ }
        in_contract && /NF != 2 \|\| \$2 != expected_gid/ { groups_exact++ }
        in_contract && /NF != 2 \|\| \$2 != 1/ { nnp_exact++ }
        in_contract && /NF != 2 \|\| \$2 != 2/ { seccomp_exact++ }
        in_contract && /filters !~ \/\^\[1-9\]\[0-9\]\*\$\// { filters_canonical++ }
        in_contract && /length\(filters\) > 10 \|\| filters > 1024/ { filters_bounded++ }
        in_contract && /NF != 2 \|\| \$2 != expected_caps/ { exact_capsets++ }
        in_contract && /process-status-v1=uid:0:0:0:0;gid:%s:%s:%s:%s;/ {
            canonical_record++
        }
        in_contract && /valid = valid && groups_count == 1 && nnp_count == 1/ {
            group_counts++
        }
        in_contract && /valid = valid && ambient_count == 1/ { exact_counts++ }
        in_identity && /hook_process_contract=\$\(capture_helper_process_contract/ {
            process_capture = NR
        }
        in_identity && /unit_invocation_id "\$hook_identity_unit"/ {
            invocation_observations++
            if (invocation_observations == 2) invocation_after = NR
        }
        in_identity && /unit_main_pid "\$hook_identity_unit"/ {
            pid_observations++
            if (pid_observations == 2) pid_after = NR
        }
        in_identity && /capture_systemd_launch_contract/ {
            launch_observations++
            launch_before = NR
        }
        in_identity && /capture_process_starttime/ {
            starttime_observations++
            if (starttime_observations == 1) starttime_before = NR
            if (starttime_observations == 2) starttime_after = NR
        }
        in_identity && /capture_launch_image_identity/ { image_capture = NR }
        in_identity && /launch_image_matches_identity/ {
            image_observations++
            if (image_observations == 1) image_before = NR
            if (image_observations == 2) image_after = NR
        }
        in_recheck && /hook_observed_identity=\$\(capture_running_identity/ {
            recheck_capture = NR
        }
        in_recheck && /"\$hook_identity_unit" "\$hook_identity_gid"/ {
            recheck_gid = NR
        }
        END {
            valid = mask == 1 && pid_field == 1 && uid_field == 1 && gid_field == 1
            valid = valid && groups_field == 1 && nnp_field == 1
            valid = valid && seccomp_field == 1 && filters_field == 1
            valid = valid && inherited_field == 1 && permitted_field == 1
            valid = valid && effective_field == 1 && bounding_field == 1
            valid = valid && ambient_field == 1 && exact_capsets == 5
            valid = valid && uid_exact == 1 && gid_exact == 1 && groups_exact == 1
            valid = valid && nnp_exact == 1 && seccomp_exact == 1
            valid = valid && filters_canonical == 1 && filters_bounded == 1
            valid = valid && canonical_record == 1 && group_counts == 1
            valid = valid && exact_counts == 1
            valid = valid && launch_observations == 1 && starttime_observations == 2
            valid = valid && image_observations == 2
            valid = valid && launch_before < image_capture
            valid = valid && image_capture < image_before
            valid = valid && image_before < starttime_before
            valid = valid && starttime_before < process_capture
            valid = valid && process_capture < starttime_after
            valid = valid && starttime_after < image_after
            valid = valid && image_after < pid_after
            valid = valid && pid_after < invocation_after
            valid = valid && recheck_capture < recheck_gid
            if (!valid) exit 1
        }
    ' "$hook_contract_source"
}
if ! hook_process_contract_source_is_exact "$ipc_hook"; then
    printf '%s\n' 'production helper process-status contract is incomplete or unordered' >&2
    exit 1
fi
for hook_contract_mutation in capability-mask group-count ambient-field \
    starttime-recheck launch-image-recheck
do
    hook_contract_mutant=$temporary_directory/hook-$hook_contract_mutation.sh
    case $hook_contract_mutation in
        capability-mask)
            sed '0,/00000000002031e0/s//0000000000000000/' \
                "$ipc_hook" >"$hook_contract_mutant"
            ;;
        group-count)
            sed '0,/groups_count == 1/s//groups_count == 0/' \
                "$ipc_hook" >"$hook_contract_mutant"
            ;;
        ambient-field)
            sed '0,/CapAmb:/s//CapXYZ:/' "$ipc_hook" >"$hook_contract_mutant"
            ;;
        starttime-recheck)
            # shellcheck disable=SC2016
            sed '0,/\[ "$(capture_process_starttime/s/capture_process_starttime/unchecked_process_starttime/' \
                "$ipc_hook" >"$hook_contract_mutant"
            ;;
        launch-image-recheck)
            # shellcheck disable=SC2016
            sed '0,/launch_image_matches_identity "\$production_helper" "\$hook_launch_image"/s/launch_image_matches_identity/unchecked_launch_image/' \
                "$ipc_hook" >"$hook_contract_mutant"
            ;;
        *) exit 1 ;;
    esac
    chmod 0600 "$hook_contract_mutant"
    if hook_process_contract_source_is_exact "$hook_contract_mutant"; then
        printf 'production helper process-status contract accepted mutation: %s\n' \
            "$hook_contract_mutation" >&2
        exit 1
    fi
done
if ! awk '
    /^start_hook\(\) \{$/ { in_start = 1; next }
    /^stop_hook\(\) \{$/ { in_start = 0 }
    in_start && /hook_lock_identity=\$\(capture_lock_identity/ { captured = NR }
    in_start && /exec 8<>"\$journal_lock"/ { opened = NR }
    in_start && /hook_active_lock_fd_identity=\$\(stat -Lc/ { fd_identity = NR }
    in_start && /"\$hook_active_lock_fd_identity" = "\$hook_lock_identity"/ {
        fd_compared = NR
    }
    in_start && /hook_active_lock_path_before=\$\(capture_lock_identity/ {
        path_before = NR
    }
    in_start && /"\$hook_active_lock_path_before" = "\$hook_lock_identity"/ {
        path_before_compared = NR
    }
    in_start && /\/usr\/bin\/flock -n -x -E 42 8/ { flocked = NR }
    in_start && /"\$hook_active_flock_status" -eq 42/ { contended = NR }
    in_start && /running_identity_is_unchanged "\$hook_unit"/ {
        identity_count++
        if (identity_count == 1) identity_after_contention = NR
        if (identity_count == 2) identity_after_close = NR
    }
    in_start && /hook_active_lock_path_after=\$\(capture_lock_identity/ {
        path_after = NR
    }
    in_start && /"\$hook_active_lock_path_after" = "\$hook_lock_identity"/ {
        path_after_compared = NR
    }
    in_start && /exec 8>&-/ { closed = NR }
    in_start && /hook_active_lock_path_after_close=\$\(capture_lock_identity/ {
        path_after_close = NR
    }
    in_start && /"\$hook_active_lock_path_after_close" = "\$hook_lock_identity"/ {
        path_after_close_compared = NR
    }
    in_start && /write_private_file "\$proof_directory\/lock.identity"/ { published = NR }
    END {
        valid = captured < opened && opened < fd_identity && fd_identity < fd_compared
        valid = valid && fd_compared < path_before && path_before < path_before_compared
        valid = valid && path_before_compared < flocked && flocked < contended
        valid = valid && identity_count == 2
        valid = valid && contended < identity_after_contention
        valid = valid && identity_after_contention < path_after
        valid = valid && path_after < path_after_compared && path_after_compared < closed
        valid = valid && closed < path_after_close
        valid = valid && path_after_close < path_after_close_compared
        valid = valid && path_after_close_compared < identity_after_close
        valid = valid && identity_after_close < published
        if (!valid) exit 1
    }
' "$ipc_hook"; then
    printf '%s\n' 'start hook does not prove exact active lock contention in fail-closed order' >&2
    exit 1
fi
if ! awk '
    /^run_probe\(\) \{$/ { in_probe = 1; next }
    in_probe && /socket_identity_is_unchanged/ {
        socket_count++
        if (socket_count == 1) socket_before = NR
        if (socket_count == 2) socket_after = NR
    }
    in_probe && /running_identity_is_unchanged/ {
        identity_count++
        if (identity_count == 1) identity_before = NR
        if (identity_count == 2) identity_after = NR
    }
    in_probe && /"\$probe" "\$hook_probe_mode"/ {
        probe_count++
        if (probe_count == 1) first_probe = NR
        if (probe_count == 2) second_probe = NR
    }
    in_probe && /"\$hook_probe_status" -eq 0/ { status_gate = NR }
    /^functional_underlay_is_exact\(\) \{$/ { in_probe = 0 }
    END {
        valid = socket_count == 2 && identity_count == 2 && probe_count == 2
        valid = valid && identity_before < socket_before && socket_before < first_probe
        valid = valid && second_probe < identity_after && identity_after < socket_after
        valid = valid && socket_after < status_gate
        if (!valid) exit 1
    }
' "$ipc_hook"; then
    printf '%s\n' 'unit and socket identity are not fenced around every probe branch' >&2
    exit 1
fi
if ! awk '
    /hook_expected_lock_identity=\$\(cat/ { expected = NR }
    /exec 9<>"\$journal_lock"/ { opened = NR }
    /hook_lock_fd_identity=\$\(stat -Lc/ { fd_identity = NR }
    /"\$hook_lock_fd_identity" = "\$hook_expected_lock_identity"/ { compared = NR }
    /\/usr\/bin\/flock -n 9/ { flocked = NR }
    /exec 9>&-/ { closed = NR }
    END {
        valid = expected < opened && opened < fd_identity
        valid = valid && fd_identity < compared
        valid = valid && compared < flocked && flocked < closed
        if (!valid) exit 1
    }
' "$ipc_hook"; then
    printf '%s\n' 'stop hook does not flock the exact start lock FD in fail-closed order' >&2
    exit 1
fi
if ! awk '
    /run_probe bind-before bind-runtime/ { bind_before = NR }
    /run_probe frame-bounds reject-frame-bounds/ { frame = NR }
    /run_probe wire-shapes reject-wire-shapes/ { wire = NR }
    /run_probe wrong-uid expect-unauthorised-peer/ { wrong_uid = NR }
    /run_probe wrong-gid expect-unauthorised-peer/ { wrong_gid = NR }
    /run_probe root-peer expect-unauthorised-peer/ { root_peer = NR }
    /run_probe bind-after bind-runtime/ { bind_after = NR }
    /^    run_functional_client_lease_probe/ { functional = NR }
    /'"'"'VOLPAROSSA_HELPER_V3_IPC_BIND_BEFORE_V1=pass'"'"'/ { marker_bind_before = NR }
    /'"'"'VOLPAROSSA_HELPER_V3_IPC_FRAME_BOUNDS_V1=pass'"'"'/ { marker_frame = NR }
    /'"'"'VOLPAROSSA_HELPER_V3_IPC_WIRE_SHAPES_V1=pass'"'"'/ { marker_wire = NR }
    /'"'"'VOLPAROSSA_HELPER_V3_IPC_WRONG_UID_V1=pass'"'"'/ { marker_wrong_uid = NR }
    /'"'"'VOLPAROSSA_HELPER_V3_IPC_WRONG_GID_V1=pass'"'"'/ { marker_wrong_gid = NR }
    /'"'"'VOLPAROSSA_HELPER_V3_IPC_ROOT_PEER_V1=pass'"'"'/ { marker_root_peer = NR }
    /'"'"'VOLPAROSSA_HELPER_V3_IPC_BIND_AFTER_V1=pass'"'"'/ { marker_bind_after = NR }
    /"\$functional_ready_record"/ { marker_functional_ready = NR }
    /"\$functional_activated_kernel_record"/ { marker_functional_activated = NR }
    /"\$functional_committed_kernel_record"/ { marker_functional_committed = NR }
    /"\$functional_pass_record"/ { marker_functional_pass = NR }
    /"\$functional_cleanup_record"/ { marker_functional_cleanup = NR }
    /"\$functional_exit_ready_record"/ { marker_exit_ready = NR }
    /"\$functional_exit_activated_kernel_record"/ { marker_exit_activated = NR }
    /"\$functional_exit_committed_kernel_record"/ { marker_exit_committed = NR }
    /"\$functional_exit_pass_record"/ { marker_exit_pass = NR }
    /"\$functional_exit_cleanup_record"/ { marker_exit_cleanup = NR }
    /"\$functional_relay_pair_ready_record"/ { marker_pair_ready = NR }
    /"\$functional_relay_pair_activated_kernel_record"/ {
        marker_pair_activated = NR
    }
    /"\$functional_relay_pair_committed_kernel_record"/ {
        marker_pair_committed = NR
    }
    /"\$functional_relay_pair_pass_record"/ { marker_pair_pass = NR }
    /"\$functional_relay_pair_cleanup_record"/ { marker_pair_cleanup = NR }
    END {
        probes = bind_before < frame && frame < wire && wire < wrong_uid
        probes = probes && wrong_uid < wrong_gid && wrong_gid < root_peer
        probes = probes && root_peer < bind_after && bind_after < functional
        markers = bind_after < marker_bind_before && marker_bind_before < marker_frame
        markers = markers && marker_frame < marker_wire && marker_wire < marker_wrong_uid
        markers = markers && marker_wrong_uid < marker_wrong_gid
        markers = markers && marker_wrong_gid < marker_root_peer
        markers = markers && marker_root_peer < marker_bind_after
        markers = markers && marker_bind_after < marker_functional_ready
        markers = markers && marker_functional_ready < marker_functional_activated
        markers = markers && marker_functional_activated < marker_functional_committed
        markers = markers && marker_functional_committed < marker_functional_pass
        markers = markers && marker_functional_pass < marker_functional_cleanup
        markers = markers && marker_functional_cleanup < marker_exit_ready
        markers = markers && marker_exit_ready < marker_exit_activated
        markers = markers && marker_exit_activated < marker_exit_committed
        markers = markers && marker_exit_committed < marker_exit_pass
        markers = markers && marker_exit_pass < marker_exit_cleanup
        markers = markers && marker_exit_cleanup < marker_pair_ready
        markers = markers && marker_pair_ready < marker_pair_activated
        markers = markers && marker_pair_activated < marker_pair_committed
        markers = markers && marker_pair_committed < marker_pair_pass
        markers = markers && marker_pair_pass < marker_pair_cleanup
        if (!(probes && markers)) exit 1
    }
' "$ipc_hook"; then
    printf '%s\n' 'production IPC probes or hook-owned records are not in exact order' >&2
    exit 1
fi

no_custody_wait_contract=$temporary_directory/no-custody-wait-contract.sh
sed -n '/^wait_for_helper_no_worker_custody() {$/,/^}$/p' \
    "$ipc_hook" >"$no_custody_wait_contract"
# These are literal hook-source contracts; expansion here would defeat them.
# shellcheck disable=SC2016
no_custody_wait_source_is_exact() {
    [ "$#" -eq 1 ] || return 1
    [ "$(grep -Fc 'helper_holds_no_worker_custody' "$1")" -eq 1 ] \
        && [ "$(grep -Fc 'hook_custody_wait_attempt=0' "$1")" -eq 1 ] \
        && [ "$(grep -Fc \
            'hook_custody_wait_attempt=$((hook_custody_wait_attempt + 1))' \
            "$1")" -eq 1 ] \
        && [ "$(grep -Ec \
            '^[[:space:]]*\[ "\$hook_custody_wait_attempt" -lt 100 \] \|\| return 1$' \
            "$1")" -eq 1 ] \
        && [ "$(grep -Fc 'sleep 0.05' "$1")" -eq 1 ] \
        && [ "$(grep -Fc '|| true' "$1")" -eq 0 ]
}
no_custody_wait_source_is_exact "$no_custody_wait_contract" || {
    printf '%s\n' 'worker-custody retirement wait is not exact and bounded' >&2
    exit 1
}
sh -n "$no_custody_wait_contract"
# shellcheck disable=SC1090,SC2030,SC2317
exercise_no_custody_wait_contract() (
    . "$no_custody_wait_contract"
    number_is_safe() { [ "$#" -eq 1 ] && [ "$1" = 4242 ]; }
    sleep() { [ "$#" -eq 1 ] && [ "$1" = 0.05 ]; }
    custody_observations=0
    helper_holds_no_worker_custody() {
        custody_observations=$((custody_observations + 1))
        if [ "$custody_observations" -eq 3 ]; then
            hook_custody_failure_stage=none
            return 0
        fi
        hook_custody_failure_stage=pidfd
        return 1
    }
    wait_for_helper_no_worker_custody 4242
    [ "$custody_observations" -eq 3 ]
    [ "$hook_custody_failure_stage" = none ]
    custody_observations=0
    helper_holds_no_worker_custody() {
        custody_observations=$((custody_observations + 1))
        hook_custody_failure_stage=procfd
        return 1
    }
    if wait_for_helper_no_worker_custody 4242; then
        exit 1
    fi
    [ "$custody_observations" -eq 100 ]
    [ "$hook_custody_failure_stage" = procfd ]
)
exercise_no_custody_wait_contract || {
    printf '%s\n' 'worker-custody retirement wait does not converge or fail closed' >&2
    exit 1
}
no_custody_wait_bound_mutant=$temporary_directory/no-custody-wait-bound-mutant.sh
sed 's/-lt 100/-lt 1000/' \
    "$no_custody_wait_contract" >"$no_custody_wait_bound_mutant"
no_custody_wait_predicate_mutant=$temporary_directory/no-custody-wait-predicate-mutant.sh
sed 's/helper_holds_no_worker_custody/true/' \
    "$no_custody_wait_contract" >"$no_custody_wait_predicate_mutant"
for no_custody_wait_mutant in \
    "$no_custody_wait_bound_mutant" "$no_custody_wait_predicate_mutant"
do
    sh -n "$no_custody_wait_mutant"
    if no_custody_wait_source_is_exact "$no_custody_wait_mutant"; then
        printf 'worker-custody retirement wait accepted mutant: %s\n' \
            "${no_custody_wait_mutant##*/}" >&2
        exit 1
    fi
done

no_custody_predicate_contract=$temporary_directory/no-custody-predicate-contract.sh
sed -n '/^helper_holds_no_worker_custody() {$/,/^}$/p' \
    "$ipc_hook" >"$no_custody_predicate_contract"
# These are literal hook-source contracts; expansion here would defeat them.
# shellcheck disable=SC2016
no_custody_predicate_source_is_exact() {
    [ "$#" -eq 1 ] || return 1
    [ "$(grep -Fc 'hook_custody_failure_stage=fd-scan' "$1")" -eq 1 ] \
        && [ "$(grep -Fc 'hook_custody_failure_stage=pidfd' "$1")" -eq 1 ] \
        && [ "$(grep -Fc 'hook_custody_failure_stage=procfd' "$1")" -eq 1 ] \
        && [ "$(grep -Fc 'hook_custody_failure_stage=foreign-netns' \
            "$1")" -eq 1 ] \
        && [ "$(grep -Fc 'hook_custody_failure_stage=none' "$1")" -eq 1 ] \
        && [ "$(grep -Fc "'anon_inode:[pidfd]'" "$1")" -eq 1 ] \
        && [ "$(grep -Fc '/proc/[1-9][0-9]*)' "$1")" -eq 1 ] \
        && [ "$(grep -Fc 'net:\[[1-9][0-9]*\])' "$1")" -eq 1 ] \
        && [ "$(grep -Ec '(^|[[:space:]])(echo|logger|printf)([[:space:]]|$)' \
            "$1")" -eq 0 ]
}
no_custody_predicate_source_is_exact "$no_custody_predicate_contract" || {
    printf '%s\n' 'worker-custody predicate diagnostics are not fixed and value-free' >&2
    exit 1
}
sh -n "$no_custody_predicate_contract"
no_custody_predicate_target_mutant=$temporary_directory/no-custody-predicate-target-mutant.sh
sed "s/'anon_inode:\[pidfd\]'/'anon_inode:[worker-pidfd]'/" \
    "$no_custody_predicate_contract" >"$no_custody_predicate_target_mutant"
no_custody_predicate_stage_mutant=$temporary_directory/no-custody-predicate-stage-mutant.sh
sed 's/hook_custody_failure_stage=foreign-netns/hook_custody_failure_stage=none/' \
    "$no_custody_predicate_contract" >"$no_custody_predicate_stage_mutant"
for no_custody_predicate_mutant in \
    "$no_custody_predicate_target_mutant" "$no_custody_predicate_stage_mutant"
do
    sh -n "$no_custody_predicate_mutant"
    if no_custody_predicate_source_is_exact "$no_custody_predicate_mutant"; then
        printf 'worker-custody predicate accepted diagnostic mutant: %s\n' \
            "${no_custody_predicate_mutant##*/}" >&2
        exit 1
    fi
done

parent_custody_diagnostic_contract=$temporary_directory/parent-custody-diagnostic-contract.sh
sed -n '/^count_parent_namespace_identity_fds() {$/,/^}$/p' \
    "$ipc_hook" >"$parent_custody_diagnostic_contract"
sed -n '/^refine_parent_custody_failure_stage() {$/,/^}$/p' \
    "$ipc_hook" >>"$parent_custody_diagnostic_contract"
sed -n '/^advance_parent_custody_failure_diagnostic() {$/,/^}$/p' \
    "$ipc_hook" >>"$parent_custody_diagnostic_contract"
# These are literal hook-source contracts; expansion here would defeat them.
# shellcheck disable=SC2016
parent_custody_diagnostic_source_is_exact() {
    [ "$#" -eq 1 ] || return 1
    [ "$(grep -Fc \
        'functional-exit-cleanup-parent-custody ] || return 1' \
        "$1")" -eq 1 ] \
        && [ "$(grep -Fc \
            '[ "$hook_custody_current_parent_pid" = ' "$1")" -eq 1 ] \
        && [ "$(grep -Fc \
            '"$hook_custody_expected_parent_pid" ]; then' "$1")" -eq 1 ] \
        && [ "$(grep -Fc 'helper_holds_no_worker_custody' "$1")" -eq 1 ] \
        && [ "$(grep -Fc 'hook_custody_failure_stage=clear' "$1")" -eq 1 ] \
        && [ "$(grep -Fc \
            'kernel_object_identity_is_safe "$hook_custody_observed_identity"' \
            "$1")" -eq 1 ] \
        && [ "$(grep -Fc \
            '"${hook_functional_exit_worker_namespace:-}"' "$1")" -eq 1 ] \
        && [ "$(grep -Fc \
            '[ "$hook_custody_observed_identity" = ' "$1")" -eq 1 ] \
        && [ "$(grep -Fc \
            '"$hook_functional_exit_worker_namespace" ]; then' "$1")" -eq 1 ] \
        && [ "$(grep -Fc \
            'count_parent_namespace_identity_fds' "$1")" -eq 2 ] \
        && [ "$(grep -Fc \
            'hook_custody_failure_stage=foreign-netns-exit-worker-one' \
            "$1")" -eq 1 ] \
        && [ "$(grep -Fc \
            'hook_custody_failure_stage=foreign-netns-exit-worker-two' \
            "$1")" -eq 1 ] \
        && [ "$(grep -Fc \
            'hook_custody_failure_stage=foreign-netns-exit-worker-three-plus' \
            "$1")" -eq 1 ] \
        && [ "$(grep -Fc \
            'hook_custody_failure_stage=foreign-netns-other' "$1")" -eq 1 ] \
        && [ "$(grep -Fc \
            '"$hook_custody_expected_parent_pid" || return 1' "$1")" -eq 1 ] \
        && [ "$(grep -Fc \
            'foreign-netns-exit-worker-two|foreign-netns-exit-worker-three-plus' \
            "$1")" -eq 1 ] \
        && [ "$(grep -Fc \
            'foreign-netns-other|fd-scan|clear) ;;' "$1")" -eq 1 ] \
        && [ "$(grep -Fc \
            '"functional-exit-cleanup-parent-custody-$hook_custody_failure_stage"' \
            "$1")" -eq 1 ] \
        && [ "$(grep -Fc '|| true' "$1")" -eq 0 ] \
        && [ "$(grep -Ec '(^|[[:space:]])(echo|logger|printf)([[:space:]]|$)' \
            "$1")" -eq 0 ]
}
parent_custody_diagnostic_source_is_exact \
    "$parent_custody_diagnostic_contract" || {
        printf '%s\n' \
            'parent-custody failure diagnostic is not bound and value-free' >&2
        exit 1
    }
sh -n "$parent_custody_diagnostic_contract"
parent_custody_binding_mutant=$temporary_directory/parent-custody-binding-mutant.sh
# This is a literal hook-source mutation; expansion here would defeat it.
# shellcheck disable=SC2016
sed 's/"$hook_custody_current_parent_pid" =/"$hook_custody_current_parent_pid" !=/' \
    "$parent_custody_diagnostic_contract" >"$parent_custody_binding_mutant"
parent_custody_predicate_mutant=$temporary_directory/parent-custody-predicate-mutant.sh
sed 's/helper_holds_no_worker_custody/true/' \
    "$parent_custody_diagnostic_contract" >"$parent_custody_predicate_mutant"
parent_custody_identity_mutant=$temporary_directory/parent-custody-identity-mutant.sh
# This is a literal hook-source mutation; expansion here would defeat it.
# shellcheck disable=SC2016
sed 's/"$hook_custody_observed_identity" =/"$hook_custody_observed_identity" !=/' \
    "$parent_custody_diagnostic_contract" >"$parent_custody_identity_mutant"
parent_custody_count_mutant=$temporary_directory/parent-custody-count-mutant.sh
sed 's/2) hook_custody_failure_stage=foreign-netns-exit-worker-two/2) hook_custody_failure_stage=foreign-netns-exit-worker-one/' \
    "$parent_custody_diagnostic_contract" >"$parent_custody_count_mutant"
parent_custody_category_mutant=$temporary_directory/parent-custody-category-mutant.sh
sed 's/foreign-netns-other|fd-scan/foreign-netns-other|private-value|fd-scan/' \
    "$parent_custody_diagnostic_contract" >"$parent_custody_category_mutant"
parent_custody_stage_mutant=$temporary_directory/parent-custody-stage-mutant.sh
# This is a literal hook-source mutation; expansion here would defeat it.
# shellcheck disable=SC2016
sed 's/parent-custody-\$hook_custody_failure_stage/parent-custody-fd-scan/' \
    "$parent_custody_diagnostic_contract" >"$parent_custody_stage_mutant"
for parent_custody_diagnostic_mutant in \
    "$parent_custody_binding_mutant" "$parent_custody_predicate_mutant" \
    "$parent_custody_identity_mutant" "$parent_custody_count_mutant" \
    "$parent_custody_category_mutant" \
    "$parent_custody_stage_mutant"
do
    sh -n "$parent_custody_diagnostic_mutant"
    if parent_custody_diagnostic_source_is_exact \
        "$parent_custody_diagnostic_mutant"; then
        printf 'parent-custody diagnostic accepted mutant: %s\n' \
            "${parent_custody_diagnostic_mutant##*/}" >&2
        exit 1
    fi
done

parent_custody_runtime_contract=$temporary_directory/parent-custody-runtime-contract.sh
for parent_custody_runtime_function in \
    number_is_safe fd_number_is_safe kernel_object_number_is_safe \
    kernel_object_identity_is_safe namespace_number_from_target \
    capture_parent_namespace_fd_identity helper_holds_no_worker_custody \
    wait_for_helper_no_worker_custody count_parent_namespace_identity_fds \
    refine_parent_custody_failure_stage \
    advance_start_failure_stage \
    advance_parent_custody_failure_diagnostic
do
    sed -n \
        "/^$parent_custody_runtime_function() {\$/,/^}\$/p" \
        "$ipc_hook" >>"$parent_custody_runtime_contract"
done
sh -n "$parent_custody_runtime_contract"
# This subshell uses the hook's real functions and a real process-held /proc
# descriptor. No predicate, wait, sleep, stage advance, or PID binding is stubbed.
# shellcheck disable=SC1090,SC2031
exercise_parent_custody_runtime_contract() (
    . "$parent_custody_runtime_contract"
    hook_custody_runtime_namespace=$(stat -Lc '%d:%i' \
        /proc/self/ns/net 2>/dev/null)
    kernel_object_identity_is_safe "$hook_custody_runtime_namespace"
    command exec 7</proc/self/ns/net
    command exec 8</proc/self/ns/net
    hook_custody_failure_stage=foreign-netns
    # The extracted hook function reads these globals at runtime.
    # shellcheck disable=SC2034
    hook_custody_observed_identity=$hook_custody_runtime_namespace
    # shellcheck disable=SC2034
    hook_functional_exit_worker_namespace=$hook_custody_runtime_namespace
    refine_parent_custody_failure_stage "$$"
    [ "$hook_custody_failure_stage" = foreign-netns-exit-worker-two ]
    command exec 8>&-
    command exec 7>&-
    hook_custody_failure_stage=foreign-netns
    # shellcheck disable=SC2034
    hook_custody_observed_identity=1:3
    refine_parent_custody_failure_stage "$$"
    [ "$hook_custody_failure_stage" = foreign-netns-other ]
    custody_runtime_child=
    cleanup_custody_runtime_child() {
        if [ -n "$custody_runtime_child" ]; then
            kill "$custody_runtime_child" 2>/dev/null || :
            wait "$custody_runtime_child" 2>/dev/null || :
        fi
    }
    trap cleanup_custody_runtime_child EXIT HUP INT TERM
    /bin/sh -c 'exec 9</proc/self/status; sleep 15' \
        </dev/null >/dev/null 2>&1 &
    custody_runtime_child=$!
    number_is_safe "$custody_runtime_child"
    custody_runtime_ready_attempt=0
    while [ "$(readlink "/proc/$custody_runtime_child/fd/9" \
        2>/dev/null || true)" != "/proc/$custody_runtime_child/status" ]; do
        custody_runtime_ready_attempt=$((custody_runtime_ready_attempt + 1))
        [ "$custody_runtime_ready_attempt" -lt 100 ] || exit 1
        sleep 0.01
    done
    start_failure_stage=functional-exit-cleanup-parent-custody
    if wait_for_helper_no_worker_custody "$custody_runtime_child"; then
        exit 1
    fi
    [ "$hook_custody_failure_stage" = procfd ]
    advance_parent_custody_failure_diagnostic \
        "$custody_runtime_child" "$custody_runtime_child"
    [ "$start_failure_stage" = \
        functional-exit-cleanup-parent-custody-procfd ]
    start_failure_stage=identity-socket
    if advance_parent_custody_failure_diagnostic \
        "$custody_runtime_child" "$custody_runtime_child"; then
        exit 1
    fi
    start_failure_stage=functional-exit-cleanup-parent-custody
    advance_parent_custody_failure_diagnostic "$custody_runtime_child" 1
    [ "$start_failure_stage" = \
        functional-exit-cleanup-parent-custody-fd-scan ]
    cleanup_custody_runtime_child
    custody_runtime_child=
    trap - EXIT HUP INT TERM
)
exercise_parent_custody_runtime_contract || {
    printf '%s\n' \
        'real worker-custody wait did not propagate to the bound failure stage' >&2
    exit 1
}

start_failure_exit_contract=$temporary_directory/start-failure-exit-contract.sh
sed -n '/^start_failure_exit() {$/,/^}$/p' "$ipc_hook" \
    >"$start_failure_exit_contract"
if ! awk '
    /functional-exit-cleanup-parent-custody ]; then/ {
        custody_guard = NR
    }
    /hook_functional_current_main_pid=.*unit_main_pid/ { main_binding = NR }
    /advance_parent_custody_failure_diagnostic/ { custody_diagnostic = NR }
    /restart_initial_cleanup_succeeded=yes/ { cleanup = NR }
    /publish_start_failure/ { publication = NR }
    END {
        valid = custody_guard && main_binding && custody_diagnostic
        valid = valid && cleanup && publication
        valid = valid && custody_guard < main_binding
        valid = valid && main_binding < custody_diagnostic
        valid = valid && custody_diagnostic < cleanup
        valid = valid && cleanup < publication
        if (!valid) exit 1
    }
' "$start_failure_exit_contract"; then
    printf '%s\n' \
        'parent-custody trap diagnostic is not before cleanup and publication' >&2
    exit 1
fi

if ! awk '
    /^run_functional_client_lease_probe\(\) \{$/ { in_functional = 1; next }
    /^restart_record_line\(\) \{$/ { in_functional = 0 }
    in_functional && /private_network_is_pristine/ {
        pristine_count++
        if (pristine_count == 1) pristine_before = NR
        if (pristine_count == 2) pristine_after = NR
    }
    in_functional && /\/usr\/sbin\/ip link add name "\$functional_underlay"/ {
        underlay = NR
    }
    in_functional && /mkfifo -m 0600/ { fifo = NR }
    in_functional && /exec 6<>"\$hook_functional_fifo"/ { fifo_open = NR }
    in_functional && /"\$probe" functional-client-lease/ { probe = NR }
    in_functional && /while ! probe_output_is_exact/ {
        ready_wait_count++
        if (ready_wait_count == 1) client_ready = NR
        if (ready_wait_count == 2) client_settled_wait = NR
        if (ready_wait_count == 3) exit_ready_wait = NR
        if (ready_wait_count == 4) exit_settled_wait = NR
        if (ready_wait_count == 5) pair_ready_wait = NR
    }
    in_functional && /hook_functional_worker_pid=\$\(direct_helper_child/ {
        client_child = NR
    }
    in_functional && /hook_functional_exit_worker_pid=\$\(direct_helper_child/ {
        exit_child = NR
    }
    in_functional && /hook_functional_pair_worker_pid=\$\(direct_helper_child/ {
        pair_child = NR
    }
    in_functional && /capture_parent_worker_custody/ { custody_count++ }
    in_functional && /command exec 7<"\$hook_functional_parent_namespace_path"/ {
        client_namespace_pin = NR
    }
    in_functional && /command exec 8<"\$hook_functional_parent_process_path"/ {
        client_process_pin = NR
    }
    in_functional && /command exec 7<"\$hook_functional_exit_parent_namespace_path"/ {
        exit_namespace_pin = NR
    }
    in_functional && /command exec 8<"\$hook_functional_exit_parent_process_path"/ {
        exit_process_pin = NR
    }
    in_functional && /command exec 7<"\$hook_functional_pair_parent_namespace_path"/ {
        pair_namespace_pin = NR
    }
    in_functional && /command exec 8<"\$hook_functional_pair_parent_process_path"/ {
        pair_process_pin = NR
    }
    in_functional && /worker_identity_from_process_fd/ { identity_count++ }
    in_functional && /worker_activated_wireguard_is_exact/ { activated_count++ }
    in_functional && /hook_functional_baseline=\$\(worker_wireguard_snapshot/ {
        client_baseline = NR
    }
    in_functional && /hook_functional_exit_baseline=\$\(worker_wireguard_snapshot/ {
        exit_baseline = NR
    }
    in_functional && /^    create_functional_relay_fixture/ { client_relay_create = NR }
    in_functional && /\/usr\/bin\/ping -6 -n -I "\$functional_relay"/ {
        relay_ping_count++
        if (relay_ping_count == 1) client_traffic = NR
        if (relay_ping_count == 2) {
            pair_client_traffic = NR
            expect_pair_destination = 1
        }
    }
    in_functional && expect_pair_destination \
        && /"\$hook_functional_pair_exit_peer_address"/ {
        pair_cross_destination = NR
        expect_pair_destination = 0
    }
    in_functional \
        && /--net="\/proc\/\$functional_pair_client_keeper_pid\/ns\/net"/ {
        pair_peer_nsenter = NR
    }
    in_functional && /^    remove_functional_relay_fixture/ { client_relay_remove = NR }
    in_functional && /^    create_functional_exit_relay_fixture/ { exit_relay_create = NR }
    in_functional && /\/usr\/bin\/ping -6 -n -I "\$functional_exit_relay"/ {
        exit_relay_ping_count++
        if (exit_relay_ping_count == 1) exit_traffic = NR
    }
    in_functional && /^    remove_functional_exit_relay_fixture/ { exit_relay_remove = NR }
    in_functional && /wireguard_snapshot_has_growth/ { growth_count++ }
    in_functional && /advance_start_failure_stage functional-client-release/ {
        client_release_stage = NR
    }
    in_functional && /advance_start_failure_stage functional-client-cleanup/ {
        client_cleanup_stage = NR
    }
    in_functional && /publish_restart_initial_release_authorized/ {
        exact_release_authorized = NR
    }
    in_functional && /hook_restart_termination_main=\$\(unit_main_pid/ {
        exact_main_wait = NR
    }
    in_functional && exact_main_wait > 0 && exact_ack == 0 \
        && /observe_functional_probe_failure/ {
        exact_failure_observe = NR
    }
    in_functional && exact_failure_observe > 0 && exact_ack == 0 \
        && /probe_output_is_exact/ {
        exact_ready_only = NR
    }
    in_functional && /publish_and_wait_for_restart_initial_failure_ack/ {
        exact_ack = NR
    }
    in_functional && exact_ack > 0 && /^                return 1$/ {
        exact_return = NR
    }
    in_functional && /advance_start_failure_stage functional-exit-ready/ {
        exit_ready_stage = NR
    }
    in_functional && /advance_start_failure_stage functional-exit-worker-observation/ {
        exit_worker_stage = NR
    }
    in_functional && /advance_start_failure_stage functional-exit-relay-fixture/ {
        exit_fixture_stage = NR
    }
    in_functional && /advance_start_failure_stage functional-exit-relay-cleanup/ {
        exit_fixture_cleanup_stage = NR
    }
    in_functional && /hook_functional_exit_retained=\$\(worker_wireguard_snapshot/ {
        exit_retained = NR
    }
    in_functional && /advance_start_failure_stage functional-exit-release/ {
        exit_release_stage = NR
    }
    in_functional \
        && /advance_start_failure_stage functional-exit-cleanup \|\|/ {
        exit_cleanup_stage = NR
    }
    in_functional \
        && /advance_start_failure_stage functional-exit-cleanup-retirement/ {
        exit_cleanup_retirement_stage = NR
    }
    in_functional \
        && /advance_start_failure_stage functional-exit-cleanup-process-pin/ {
        exit_cleanup_process_pin_stage = NR
    }
    in_functional \
        && /advance_start_failure_stage functional-exit-cleanup-wireguard-absence/ {
        exit_cleanup_wireguard_stage = NR
    }
    in_functional \
        && /advance_start_failure_stage functional-exit-cleanup-namespace-pin/ {
        exit_cleanup_namespace_pin_stage = NR
    }
    in_functional \
        && /advance_start_failure_stage functional-exit-cleanup-process-close/ {
        exit_cleanup_process_close_stage = NR
    }
    in_functional \
        && /advance_start_failure_stage functional-exit-cleanup-namespace-close/ {
        exit_cleanup_namespace_close_stage = NR
    }
    in_functional \
        && /advance_start_failure_stage functional-exit-cleanup-fdstore-absence/ {
        exit_cleanup_fdstore_stage = NR
    }
    in_functional \
        && /advance_start_failure_stage functional-exit-cleanup-parent-custody/ {
        exit_cleanup_parent_stage = NR
    }
    in_functional && /advance_start_failure_stage functional-relay-pair-ready/ {
        pair_ready_stage = NR
    }
    in_functional \
        && /advance_start_failure_stage functional-relay-pair-worker-observation/ {
        pair_worker_stage = NR
    }
    in_functional \
        && /advance_start_failure_stage functional-relay-pair-fixtures/ {
        pair_fixture_stage = NR
    }
    in_functional && /^    create_functional_relay_pair_fixtures/ {
        pair_fixtures_create = NR
    }
    in_functional && /advance_start_failure_stage functional-relay-pair-traffic/ {
        pair_traffic_stage = NR
    }
    in_functional && /advance_start_failure_stage functional-relay-pair-cleanup/ {
        pair_fixture_cleanup_stage = NR
    }
    in_functional && /^    remove_functional_relay_pair_fixtures/ {
        pair_fixtures_remove = NR
    }
    in_functional && /^    functional_relay_pair_fixtures_are_absent/ {
        pair_fixtures_absent = NR
    }
    in_functional && /advance_start_failure_stage functional-probe-finish/ {
        finish_stage = NR
    }
    in_functional && /advance_start_failure_stage functional-cleanup/ {
        cleanup_stage = NR
    }
    in_functional && /rm -f -- "\$hook_functional_fifo"/ { fifo_unlink = NR }
    in_functional && /functional_release_byte.*>&6/ {
        release_count++
        if (release_count == 1) client_release = NR
        if (release_count == 2) client_settlement_release = NR
        if (release_count == 3) exit_release = NR
        if (release_count == 4) exit_settlement_release = NR
        if (release_count == 5) pair_release = NR
    }
    in_functional && /exec 6>&-/ { release_close = NR }
    in_functional && /wait "\$hook_functional_probe_pid"/ { waited = NR }
    in_functional && /functional_probe_output_is_exact/ { final_output = NR }
    in_functional && /helper_has_no_children/ { no_children = NR }
    in_functional && /worker_process_fd_is_retired 8/ {
        retired_count++
        if (retired_count == 1) exact_client_retired = NR
        if (retired_count == 2) client_retired = NR
        if (retired_count == 3) exit_retired = NR
        if (retired_count == 4) pair_retired = NR
    }
    in_functional && /wait_for_helper_no_worker_custody/ {
        custody_wait_count++
        if (custody_wait_count == 1) client_custody_absent = NR
        if (custody_wait_count == 2) exit_custody_absent = NR
        if (custody_wait_count == 3) pair_custody_absent = NR
    }
    in_functional && /worker_wireguard_is_absent/ {
        wireguard_absent_count++
        if (wireguard_absent_count == 1) exact_client_wireguard_absent = NR
        if (wireguard_absent_count == 2) client_wireguard_absent = NR
        if (wireguard_absent_count == 3) exit_wireguard_absent = NR
        if (wireguard_absent_count == 4) pair_client_wireguard_absent = NR
        if (wireguard_absent_count == 5) pair_exit_wireguard_absent = NR
    }
    in_functional && /command exec 8>&-/ { process_release_count++ }
    in_functional && /command exec 7>&-/ { namespace_release_count++ }
    in_functional && /remove_functional_underlay/ { underlay_remove = NR }
    END {
        valid = pristine_count == 2 && ready_wait_count == 5
        valid = valid && relay_ping_count == 2 && exit_relay_ping_count == 1
        valid = valid && custody_count == 9 && identity_count == 6
        valid = valid && activated_count == 10 && growth_count == 12
        valid = valid && release_count == 5 && retired_count == 4
        valid = valid && wireguard_absent_count == 5
        valid = valid && process_release_count == 3 && namespace_release_count == 3
        valid = valid && custody_wait_count == 3
        valid = valid && pristine_before < underlay && underlay < fifo
        valid = valid && fifo < fifo_open && fifo_open < probe && probe < client_ready
        valid = valid && client_ready < client_child
        valid = valid && client_child < client_namespace_pin
        valid = valid && client_namespace_pin < client_process_pin
        valid = valid && client_process_pin < client_baseline
        valid = valid && client_baseline < client_relay_create
        valid = valid && client_relay_create < client_traffic
        valid = valid && client_traffic < client_relay_remove
        valid = valid && client_relay_remove < client_release_stage
        valid = valid && client_release_stage < exact_release_authorized
        valid = valid && exact_release_authorized < client_release
        valid = valid && client_release < exact_client_retired
        valid = valid && exact_client_retired < exact_client_wireguard_absent
        valid = valid && exact_client_wireguard_absent < exact_main_wait
        valid = valid && exact_main_wait < exact_failure_observe
        valid = valid && exact_failure_observe < exact_ready_only
        valid = valid && exact_ready_only < exact_ack && exact_ack < exact_return
        valid = valid && exact_return < client_settled_wait
        valid = valid && client_settled_wait < client_cleanup_stage
        valid = valid && client_cleanup_stage < client_retired
        valid = valid && client_retired < client_wireguard_absent
        valid = valid && client_wireguard_absent < client_custody_absent
        valid = valid && client_custody_absent < client_settlement_release
        valid = valid && client_settlement_release < exit_ready_wait
        valid = valid && exit_ready_wait < exit_ready_stage
        valid = valid && exit_ready_stage < exit_worker_stage
        valid = valid && exit_worker_stage < exit_child
        valid = valid && exit_child < exit_namespace_pin
        valid = valid && exit_namespace_pin < exit_process_pin
        valid = valid && exit_process_pin < exit_baseline
        valid = valid && exit_baseline < exit_fixture_stage
        valid = valid && exit_fixture_stage < exit_relay_create
        valid = valid && exit_relay_create < exit_traffic
        valid = valid && exit_traffic < exit_fixture_cleanup_stage
        valid = valid && exit_fixture_cleanup_stage < exit_relay_remove
        valid = valid && exit_relay_remove < exit_retained
        valid = valid && exit_retained < exit_release_stage
        valid = valid && exit_release_stage < exit_release
        valid = valid && exit_release < exit_settled_wait
        valid = valid && exit_settled_wait < exit_cleanup_stage
        valid = valid && exit_cleanup_stage < exit_cleanup_retirement_stage
        valid = valid && exit_cleanup_retirement_stage < exit_retired
        valid = valid && exit_retired < exit_cleanup_process_pin_stage
        valid = valid && exit_cleanup_process_pin_stage < exit_cleanup_wireguard_stage
        valid = valid && exit_cleanup_wireguard_stage < exit_wireguard_absent
        valid = valid && exit_wireguard_absent < exit_cleanup_namespace_pin_stage
        valid = valid && exit_cleanup_namespace_pin_stage < exit_cleanup_process_close_stage
        valid = valid && exit_cleanup_process_close_stage < exit_cleanup_namespace_close_stage
        valid = valid && exit_cleanup_namespace_close_stage < exit_cleanup_fdstore_stage
        valid = valid && exit_cleanup_fdstore_stage < exit_cleanup_parent_stage
        valid = valid && exit_cleanup_parent_stage < exit_custody_absent
        valid = valid && exit_custody_absent < exit_settlement_release
        valid = valid && exit_settlement_release < pair_ready_wait
        valid = valid && pair_ready_wait < pair_ready_stage
        valid = valid && pair_ready_stage < pair_worker_stage
        valid = valid && pair_worker_stage < pair_child
        valid = valid && pair_child < pair_namespace_pin
        valid = valid && pair_namespace_pin < pair_process_pin
        valid = valid && pair_process_pin < pair_fixture_stage
        valid = valid && pair_fixture_stage < pair_fixtures_create
        valid = valid && pair_fixtures_create < pair_traffic_stage
        valid = valid && pair_traffic_stage < pair_peer_nsenter
        valid = valid && pair_peer_nsenter < pair_client_traffic
        valid = valid && pair_client_traffic < pair_cross_destination
        valid = valid && pair_cross_destination < pair_fixture_cleanup_stage
        valid = valid && pair_fixture_cleanup_stage < pair_fixtures_remove
        valid = valid && pair_fixtures_remove < pair_fixtures_absent
        valid = valid && pair_fixtures_absent < finish_stage
        valid = valid && finish_stage < fifo_unlink && fifo_unlink < pair_release
        valid = valid && pair_release < release_close && release_close < waited
        valid = valid && waited < final_output && final_output < cleanup_stage
        valid = valid && cleanup_stage < no_children && no_children < pair_retired
        valid = valid && pair_retired < pair_custody_absent
        valid = valid && pair_custody_absent < pair_client_wireguard_absent
        valid = valid && pair_client_wireguard_absent < pair_exit_wireguard_absent
        valid = valid && pair_exit_wireguard_absent < underlay_remove
        valid = valid && underlay_remove < pristine_after
        if (!valid) exit 1
    }
' "$ipc_hook"; then
    printf '%s\n' \
        'functional lease READY, live observation, release, and cleanup are not fail-closed' >&2
    exit 1
fi
if ! awk '
    /VOLPAROSSA_HELPER_LIVE_WORKER_PROOF_V1=pass/ && worker_record == 0 {
        worker_record = NR
    }
    /VOLPAROSSA_HELPER_LIVE_SYSTEMD_FDSTORE_PROOF_V1=pass/ && fdstore_record == 0 {
        fdstore_record = NR
    }
    END {
        if (!(worker_record > 0 && worker_record < fdstore_record)) exit 1
    }
' "$gate"; then
    printf '%s\n' 'live helper proof records are absent or not in exact order' >&2
    exit 1
fi
# The descriptor-store target is a literal source contract, not this test's variable.
# shellcheck disable=SC2016
if [ "$(grep -Fc 'systemctl clean --what=fdstore "$unit_name"' "$gate")" -ne 1 ]; then
    printf '%s\n' 'live helper proof gate does not clean exactly one fdstore target' >&2
    exit 1
fi
if grep -E 'systemctl[[:space:]]+(kill|clean[[:space:]]+--what=(all|cache|configuration|logs|runtime|state))' \
    "$gate" "$ipc_hook" >/dev/null; then
    printf '%s\n' 'live helper proof gate has an over-broad or forced unit retirement path' >&2
    exit 1
fi
grep -F \
    "capabilities='CAP_KILL CAP_NET_ADMIN CAP_NET_RAW CAP_SETGID CAP_SETPCAP CAP_SETUID CAP_SYS_ADMIN'" \
    "$gate" >/dev/null

if grep -E '(^|[^[:alnum:]_-])(useradd|groupadd|adduser|addgroup|systemd-sysusers)([^[:alnum:]_-]|$)' \
    "$gate" "$ipc_hook" >/dev/null; then
    printf '%s\n' 'live helper proof gate contains a host account mutator' >&2
    exit 1
fi
if grep -E '(^|[;&|[:space:]])sysctl[[:space:]]+-w([;&|[:space:]]|$)' \
    "$gate" "$ipc_hook" >/dev/null \
    || grep -E '(^|[;&|[:space:]])wg[[:space:]]+([^#]*[[:space:]])?set([[:space:]]|$)' \
        "$gate" >/dev/null \
    || grep -E '(^|[;&|[:space:]])ip[[:space:]]+([^#]*[[:space:]])?(add|delete|replace|set)([[:space:]]|$)' \
        "$gate" >/dev/null \
    || grep -E '(^|[;&|[:space:]])nft[[:space:]]+([^#]*[[:space:]])?(add|delete|flush)([[:space:]]|$)' \
        "$gate" "$ipc_hook" >/dev/null; then
    printf '%s\n' 'live helper proof gate contains a host network mutator' >&2
    exit 1
fi
hook_ip_mutator_count=$(grep -Ec \
    '^[[:space:]]*/usr/sbin/ip[[:space:]]+(-6[[:space:]]+)?(link|address|route)[[:space:]]+(add|delete|set)([[:space:]]|$)' \
    "$ipc_hook")
hook_wg_mutator_count=$(grep -Ec \
    '^[[:space:]]*(\|[[:space:]]+)?/usr/bin/wg[[:space:]]+set([[:space:]]|$)' \
    "$ipc_hook")
# These are literal hook contracts; expansion here would defeat the check.
# shellcheck disable=SC2016
if [ "$hook_ip_mutator_count" -ne 27 ] \
    || [ "$hook_wg_mutator_count" -ne 4 ] \
    || [ "$(grep -Fc '/usr/sbin/ip link add name "$functional_underlay" type dummy' \
        "$ipc_hook")" -ne 1 ] \
    || [ "$(grep -Fc '/usr/sbin/ip link set dev "$functional_underlay" alias' \
        "$ipc_hook")" -ne 1 ] \
    || [ "$(grep -Fc '/usr/sbin/ip link set dev "$functional_underlay" up' \
        "$ipc_hook")" -ne 1 ] \
    || [ "$(grep -Fc '/usr/sbin/ip address add "$functional_underlay_address/24"' \
        "$ipc_hook")" -ne 1 ] \
    || [ "$(grep -Fc '/usr/sbin/ip route add default via "$functional_underlay_gateway"' \
        "$ipc_hook")" -ne 1 ] \
    || [ "$(grep -Fc '/usr/sbin/ip link delete dev "$functional_underlay"' \
        "$ipc_hook")" -ne 1 ] \
    || [ "$(grep -Fc '/usr/sbin/ip link add name "$functional_relay" type wireguard' \
        "$ipc_hook")" -ne 1 ] \
    || [ "$(grep -Fc '/usr/sbin/ip link set dev "$functional_relay" alias' \
        "$ipc_hook")" -ne 1 ] \
    || [ "$(grep -Fc '/usr/bin/wg set "$functional_relay"' \
        "$ipc_hook")" -ne 2 ] \
    || [ "$(grep -Fc 'private-key /dev/stdin' "$ipc_hook")" -ne 4 ] \
    || [ "$(grep -Fc '/usr/sbin/ip -6 address add "$hook_relay_local_address/128"' \
        "$ipc_hook")" -ne 1 ] \
    || [ "$(grep -Fc '/usr/sbin/ip link set dev "$functional_relay" up' \
        "$ipc_hook")" -ne 1 ] \
    || [ "$(grep -Fc '/usr/sbin/ip -6 route add "$hook_client_local_address/128"' \
        "$ipc_hook")" -ne 1 ] \
    || [ "$(grep -Fc '/usr/sbin/ip link delete dev "$functional_relay"' \
        "$ipc_hook")" -ne 2 ] \
    || [ "$(grep -Fc '/usr/sbin/ip link add name "$functional_exit_relay" type wireguard' \
        "$ipc_hook")" -ne 1 ] \
    || [ "$(grep -Fc '/usr/sbin/ip link set dev "$functional_exit_relay" alias' \
        "$ipc_hook")" -ne 1 ] \
    || [ "$(grep -Fc '/usr/bin/wg set "$functional_exit_relay"' \
        "$ipc_hook")" -ne 2 ] \
    || [ "$(grep -Fc '/usr/sbin/ip -6 address add "$hook_exit_relay_local_address/128"' \
        "$ipc_hook")" -ne 1 ] \
    || [ "$(grep -Fc '/usr/sbin/ip link set dev "$functional_exit_relay" up' \
        "$ipc_hook")" -ne 1 ] \
    || [ "$(grep -Fc '/usr/sbin/ip -6 route add "$hook_exit_local_address/128"' \
        "$ipc_hook")" -ne 1 ] \
    || [ "$(grep -Fc '/usr/sbin/ip link delete dev "$functional_exit_relay"' \
        "$ipc_hook")" -ne 2 ] \
    || grep -F '/usr/bin/wg show all dump' "$ipc_hook" >/dev/null; then
    printf '%s\n' \
        'production hook network mutation is not the exact private fixture lifecycle' >&2
    exit 1
fi
if grep -Ei 'capabilit(y|ies)[_-]?state|state[_-]?capabilit(y|ies)' "$ipc_hook" >/dev/null; then
    printf '%s\n' 'functional lease proof contains a capability state file' >&2
    exit 1
fi

printf '%s\n' \
    'PASS: live helper identity/fdstore and production IPC plus sequential Client/Exit and cross-leg Relay forwarding, bidirectional nft/WireGuard growth, Commit retry, exact peer reap, retirement, root refusal, confinement, and no-host-mutation contracts are exact.'
