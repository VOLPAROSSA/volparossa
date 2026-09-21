#!/bin/sh
# SPDX-License-Identifier: GPL-3.0-only
# A real third executor joins one followed workflow, only in the disposable guest.
# shellcheck disable=SC2154,SC2034

agent_jobs_peer_recovery_cli() {
    recovery_cli_pid=$(systemctl show --property=MainPID --value volparossa-alpha-agent@client.service)
    case $recovery_cli_pid in ''|0|*[!0-9]*) return 1 ;; esac
    # Two independent 600-second leases, bounded initial/replacement discovery,
    # and deterministic fixture cutover. Original worker/source TTLs do not change.
    timeout --signal=INT --kill-after=15s 1800s nsenter --target "$recovery_cli_pid" --mount --net \
        setpriv --reuid="$AGENT_UID" --regid="$AGENT_GID" --clear-groups \
        --inh-caps=-all --ambient-caps=-all --bounding-set=-all --no-new-privs \
        -- "$binary_directory/volparossa" --control-socket "$WORK/runtime-client/control/agent.sock" "$@"
}

agent_jobs_peer_recovery_filter() {
    printf '%s\n' 'Disposable Client namespace: block direct QUIC discovery to R3/R4/R5; keep R0/R1/R2 eligible control contacts. Three provider control links will carry authenticated discovery through the selected relay.'
    ip netns exec "$CLIENT" nft -f - <<'RULES'
table inet vpa_peer_recovery {
    chain input {
        type filter hook input priority -30; policy accept;
        iifname { "cr3", "cr4", "cr5" } udp sport 41000 drop
        iifname { "cr3", "cr4", "cr5" } udp dport 41000 drop
    }
    chain output {
        type filter hook output priority -30; policy accept;
        oifname { "cr3", "cr4", "cr5" } udp sport 41000 drop
        oifname { "cr3", "cr4", "cr5" } udp dport 41000 drop
    }
}
RULES
}

agent_jobs_peer_recovery_phase_start() {
    recovery_phase=$1
    capture_product_logs
    provider_baseline_ms=$(client_log_baseline_ms) || fail PEER_RECOVERY_BASELINE_MISSING
    start_privacy_observers "content-custody-peer-$recovery_phase-privacy" || fail PEER_RECOVERY_CAPTURE_FAILED
    content_provider_adaptive_start_control_observer "content-provider-adaptive-peer-$recovery_phase-control" \
        || fail PEER_RECOVERY_CONTROL_CAPTURE_FAILED
}

agent_jobs_peer_recovery_phase_finish() {
    benchmark_capture_paths "agent-jobs-peer-recovery-$recovery_phase-live" mptcp || fail PEER_RECOVERY_ROUTE_MISSING
    stop_privacy_observers || fail PEER_RECOVERY_CAPTURE_NOT_DRAINED
    content_provider_stop_control_observer || fail PEER_RECOVERY_CONTROL_NOT_DRAINED
}

agent_jobs_peer_recovery_run() {
    recovery_script=$source_directory/tests/integration/agent-jobs-peer-recovery-smoke.py
    PHASE=agent-jobs-peer-recovery-enrollment
    setpriv --reuid="$AGENT_UID" --regid="$AGENT_GID" --clear-groups \
        --inh-caps=-all --ambient-caps=-all --bounding-set=-all --no-new-privs \
        -- python3 -B "$WORK/bin/agent-jobs-follow-smoke.py" prepare "$jobs_source" "$jobs_publisher" \
        || fail PEER_RECOVERY_PLAN_FAILED
    setpriv --reuid="$AGENT_UID" --regid="$AGENT_GID" --clear-groups \
        --inh-caps=-all --ambient-caps=-all --bounding-set=-all --no-new-privs \
        -- "$binary_directory/volparossa" content recipient-key --identity "$WORK/state-relay3/identity.key" \
        --passphrase-file "$WORK/credential-relay3/identity-passphrase" \
        >"$WORK/agent-jobs-relay3-public.json" || fail PEER_RECOVERY_NEW_KEY_FAILED
    agent_jobs_peer_recovery_phase_start initial
    # A single unchanged owner command discovers the initial two peers and later
    # a new third peer. No provider list or resume command is supplied after launch.
    agent_jobs_peer_recovery_cli compute peer workflow --batch-barrier --plan "$jobs_source/follow-plan.json" \
        --discover-peers --replace-peers --directory "$jobs_source/follow" \
        --follow --follow-poll-seconds 30 --max-batches 1 --max-seconds 600 --execute \
        >"$WORK/agent-jobs-peer-recovery-output.jsonl" 2>"$WORK/agent-jobs-peer-recovery-result.err" &
    jobs_batch_pid=$!
    PHASE=agent-jobs-peer-recovery-worker-loss
    python3 -B "$recovery_script" pause-after-loss "$WORK" "$jobs_batch_pid" \
        >"$WORK/agent-jobs-peer-recovery-observer.log" 2>"$WORK/agent-jobs-peer-recovery-observer.err" \
        || fail PEER_RECOVERY_ORIGINAL_RECEIPTS_MISSING
    agent_jobs_peer_recovery_phase_finish
    PHASE=agent-jobs-peer-recovery-new-executor
    printf '%s\n' 'Disposable guest: same owner is pidfd-paused after terminal original receipts; stop R4/R5 compute brokers, start real R3 with its original identity, then resume the same owner. This pause is fixture orchestration, not product behavior.'
    for recovery_node in relay4 relay5; do
        systemctl stop "volparossa-alpha-compute@$recovery_node.service" || fail PEER_RECOVERY_OLD_BROKER_STOP_FAILED
    done
    agent_jobs_broker relay3 || fail PEER_RECOVERY_NEW_BROKER_FAILED
    python3 -B "$recovery_script" cutover "$WORK" || fail PEER_RECOVERY_CUTOVER_INVALID
    agent_jobs_peer_recovery_phase_start replacement
    python3 -B "$recovery_script" continue-owner "$WORK" || fail PEER_RECOVERY_OWNER_RESUME_FAILED
    python3 -B "$recovery_script" observe-replacement "$WORK" \
        >>"$WORK/agent-jobs-peer-recovery-observer.log" 2>>"$WORK/agent-jobs-peer-recovery-observer.err" \
        || fail PEER_RECOVERY_NEW_WORKER_NOT_OBSERVED
    wait "$jobs_batch_pid" || fail PEER_RECOVERY_EXECUTION_INCOMPLETE
    jobs_batch_pid=
    python3 -B "$recovery_script" capture "$WORK" || fail PEER_RECOVERY_RETAINED_FILES_INVALID
    agent_jobs_peer_recovery_phase_finish
    benchmark_disconnect_route agent-jobs || fail PEER_RECOVERY_ROUTE_CLEANUP_FAILED
    agent_jobs_cleanup || fail PEER_RECOVERY_PRIVATE_CLEANUP_FAILED
    python3 -B "$recovery_script" evidence "$WORK" "$expected_commit" || fail PEER_RECOVERY_EVIDENCE_INVALID
    OBSERVED_BLOCKER=NONE
    PHASE=agent-jobs-peer-recovery-complete
}

agent_jobs_peer_recovery_finalize_report() {
    for recovery_log in "$WORK"/agent-jobs-peer-recovery-* "$WORK"/content-custody-peer-*-privacy-*.json \
        "$WORK"/content-provider-adaptive-peer-*-control.json "$WORK"/content-provider-adaptive-control-*.json; do
        [ ! -f "$recovery_log" ] || [ -L "$recovery_log" ] || \
            install -o "$OUTPUT_UID" -g "$OUTPUT_GID" -m 0600 "$recovery_log" "$output_directory/$(basename -- "$recovery_log")"
    done
    python3 -B "$source_directory/tests/integration/agent-jobs-peer-recovery-smoke.py" finalize "$WORK" "$expected_commit" \
        "$1" "$CLEANUP_COMPLETE" "$REMAINING_OWNED_OBJECTS" "$PHASE" "$OBSERVED_BLOCKER" || return 1
    install -o "$OUTPUT_UID" -g "$OUTPUT_GID" -m 0600 "$WORK/agent-jobs-peer-recovery-smoke.json" "$output_directory/agent-jobs-peer-recovery-smoke.json"
    python3 -B "$source_directory/tests/integration/agent-jobs-peer-recovery-smoke.py" report "$WORK/agent-jobs-peer-recovery-smoke.json" "$expected_commit"
}
