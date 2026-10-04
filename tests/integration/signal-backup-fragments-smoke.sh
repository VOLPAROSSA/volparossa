#!/bin/sh
# SPDX-License-Identifier: GPL-3.0-only
# Explicit disposable native Signal variant; the historical replica trial is unchanged.
# shellcheck disable=SC2154,SC2034

signal_backup_fragments_private() {
    timeout --signal=TERM --kill-after=10s 2800s setpriv \
        --reuid="$WORKER_UID" --regid="$WORKER_GID" --groups="$custody_control_gid" \
        --inh-caps=-all --ambient-caps=-all --bounding-set=-all --no-new-privs \
        -- python3 -B "$WORK/bin/signal-backup-fragments-smoke.py" "$@"
}

signal_backup_fragments_run() {
    storage_fixture_driver=signal-backup-fragments-smoke.py
    storage_owner_directory=$WORK/client-fixtures/signal-backup-user
    private_storage_fragments_setup
    for signal_summary in prepare layout isolation; do
        cp -- "$WORK/private-storage-fragments-$signal_summary.json" \
            "$WORK/signal-backup-fragments-$signal_summary.json" || fail SIGNAL_FRAGMENTS_SETUP_FAILED
    done
    if [ ! -d /home/vpci ] || [ -L /home/vpci ]; then fail SIGNAL_BACKUP_RUNTIME_PARENT_INVALID; fi
    SIGNAL_BACKUP_PARENT_MODE=$(stat -Lc '%a' /home/vpci)
    chmod o+x /home/vpci || fail SIGNAL_BACKUP_RUNTIME_TRAVERSAL_FAILED
    install -o root -g root -m 0444 /home/vpci/signal-backup-runtime/provision.json "$WORK/bin/signal-backup-runtime.json"
    if ip netns exec "$CLIENT" nft list table inet vpa_signal_backup >/dev/null 2>&1; then
        fail SIGNAL_BACKUP_GUARD_ALREADY_EXISTS
    fi
    ip netns exec "$CLIENT" nft -f - <<EOF
table inet vpa_signal_backup {
    chain output {
        type filter hook output priority -150; policy accept;
        meta skuid $WORKER_UID ip daddr != 127.0.0.1 counter reject
        meta skuid $WORKER_UID ip6 daddr != ::1 counter reject
    }
}
EOF
    PHASE=signal-backup-fragments-native-export
    private_storage_fragments_phase_start upload
    ip netns exec "$CLIENT" timeout --signal=TERM --kill-after=10s 2800s setpriv \
        --reuid="$WORKER_UID" --regid="$WORKER_GID" --groups="$custody_control_gid" \
        --inh-caps=-all --ambient-caps=-all --bounding-set=-all --no-new-privs \
        -- python3 -B "$WORK/bin/signal-backup-fragments-smoke.py" native "$storage_user" \
        >"$WORK/signal-backup-fragments-native.json" &
    DOWNLOAD_CLIENT_PID=$!
    # No unbounded spin and no provider withdrawal racing an unfinished deposit.
    # The native test permits only 120 seconds after its exact ready marker.
    signal_wait=0
    while [ ! -f "$storage_user/backup/withdrawal-ready.json" ]; do
        kill -0 "$DOWNLOAD_CLIENT_PID" 2>/dev/null || fail SIGNAL_FRAGMENTS_NATIVE_EXITED_BEFORE_EXPORT
        [ "$signal_wait" -lt 2400 ] || fail SIGNAL_FRAGMENTS_NATIVE_EXPORT_TIMEOUT
        sleep 1
        signal_wait=$((signal_wait + 1))
    done
    signal_backup_fragments_private uploaded "$storage_user" "$binary_directory/volparossa" \
        "$WORK/runtime-client/control/agent.sock" >"$WORK/signal-backup-fragments-uploaded.json" \
        || fail SIGNAL_FRAGMENTS_NATIVE_DEPOSIT_INVALID
    private_storage_fragments_phase_finish 32
    private_storage_fragments_usage uploaded_usage
    cp -- "$WORK/private-storage-fragments-uploaded_usage.json" "$WORK/signal-backup-fragments-uploaded_usage.json"
    private_storage_fragments_reopen relay5 relay3
    content_custody_cli relay4 content status | jq -e '.serving == false' >/dev/null \
        || fail SIGNAL_FRAGMENTS_FIRST_PROVIDER_STILL_SERVING
    for storage_node in relay5 relay3; do
        content_custody_cli "$storage_node" content status | jq -e '.serving == true' >/dev/null \
            || fail SIGNAL_FRAGMENTS_SURVIVOR_NOT_SERVING
    done
    PHASE=signal-backup-fragments-native-import
    private_storage_fragments_phase_start restore
    signal_backup_fragments_private confirm-withdrawal "$storage_user" >/dev/null \
        || fail SIGNAL_FRAGMENTS_WITHDRAWAL_CONFIRMATION_FAILED
    if wait "$DOWNLOAD_CLIENT_PID"; then DOWNLOAD_CLIENT_PID=; else DOWNLOAD_CLIENT_PID=; fail SIGNAL_FRAGMENTS_NATIVE_TEST_FAILED; fi
    # A second real core reconstruction after native import proves reading did not
    # consume the archive. Its retained receipts name the actual surviving peers.
    signal_backup_fragments_private restore "$storage_user" "$binary_directory/volparossa" \
        "$WORK/runtime-client/control/agent.sock" >"$WORK/signal-backup-fragments-restore.json" \
        || fail SIGNAL_FRAGMENTS_REPEAT_RESTORE_FAILED
    private_storage_fragments_phase_finish 16
    private_storage_fragments_usage restored_usage
    cp -- "$WORK/private-storage-fragments-restored_usage.json" "$WORK/signal-backup-fragments-restored_usage.json"
    private_storage_fragments_reopen relay4 relay5 relay3
    jq -n '{first_provider_stopped_before_confirmation:true,native_ready_provider_matches_first:true,
        first_store_retained:true,other_two_providers_serving:true,same_three_stores_reopened:true,
        all_usage_snapshots_with_services_stopped:true,all_three_store_inodes_preserved:true}' \
        >"$WORK/signal-backup-fragments-withdrawal.json"
    PHASE=signal-backup-fragments-retire
    private_storage_fragments_phase_start finish
    signal_backup_fragments_private finish "$storage_user" "$binary_directory/volparossa" \
        "$WORK/runtime-client/control/agent.sock" >"$WORK/signal-backup-fragments-finish.json" \
        || fail SIGNAL_FRAGMENTS_RETIREMENT_FAILED
    private_storage_fragments_phase_finish 16
    private_storage_fragments_usage deleted_usage
    cp -- "$WORK/private-storage-fragments-deleted_usage.json" "$WORK/signal-backup-fragments-deleted_usage.json"
    ip netns exec "$CLIENT" nft -j list table inet vpa_signal_backup | jq --argjson uid "$WORKER_UID" \
        '{app_uid:$uid,loopback_ipv4_ipv6_only:true,blocked_packets:([.nftables[]?.rule.expr[]?.counter.packets // empty] | add // 0)}' \
        >"$WORK/signal-backup-fragments-guard.json"
    benchmark_disconnect_route private-storage-fragments || fail SIGNAL_FRAGMENTS_ROUTE_CLEANUP_FAILED
    signal_backup_cleanup || fail SIGNAL_BACKUP_PRIVATE_CLEANUP_FAILED
    python3 -B "$source_directory/tests/integration/signal-backup-fragments-smoke.py" evidence "$WORK" \
        "$WORK/signal-backup-fragments-evidence.json" >/dev/null || fail SIGNAL_FRAGMENTS_EVIDENCE_INVALID
    OBSERVED_BLOCKER=NONE
    PHASE=signal-backup-fragments-complete
}

signal_backup_fragments_finalize_report() {
    storage_status=$1
    optional_json_evidence "$WORK/signal-backup-fragments-evidence.json" >"$WORK/signal-report-evidence.part"
    optional_json_evidence "$WORK/a15-evidence.json" >"$WORK/signal-report-host.part"
    jq -cn --arg revision "$expected_commit" --arg run "$RUN_ID" --arg phase "$PHASE" --arg blocker "$OBSERVED_BLOCKER" \
        --argjson status "$storage_status" --slurpfile evidence "$WORK/signal-report-evidence.part" \
        --slurpfile host "$WORK/signal-report-host.part" --argjson complete "$CLEANUP_COMPLETE" \
        --argjson remaining "$REMAINING_OWNED_OBJECTS" '
      {schema_version:1,report_kind:"volparossa-signal-backup-fragments",source_revision:$revision,run_id:$run,
       phase:$phase,runner_exit_status:$status,backup:$evidence[0],
       success:($status == 0 and $evidence[0].success == true and $complete and $remaining == 0 and $host[0].unchanged == true),
       observed_blocker:(if $blocker == "NONE" then null else $blocker end),
       cleanup:{complete:$complete,remaining_owned_objects:$remaining},host_state:($host[0] | del(.acceptance_id)),
       scope:"native Signal encrypted export/import and repeated actual fragment restore after first provider loss; three providers, eight charged fragment copies; no server-free messaging or independent hardware/contribution proof"}' \
        >"$WORK/signal-backup-fragments-smoke.json" || return 1
    storage_exports=$(python3 -B "$source_directory/tests/integration/signal-backup-fragments-smoke.py" export-names) || return 1
    for storage_name in $storage_exports; do
        storage_artifact=$WORK/$storage_name
        if [ -f "$storage_artifact" ] && [ ! -L "$storage_artifact" ]; then
            [ "$(wc -c <"$storage_artifact")" -le 1048576 ] || return 1
            install -o "$OUTPUT_UID" -g "$OUTPUT_GID" -m 0600 "$storage_artifact" "$output_directory/$storage_name"
        fi
    done
    python3 -B "$source_directory/tests/integration/signal-backup-fragments-smoke.py" report \
        "$WORK/signal-backup-fragments-smoke.json" "$expected_commit"
}
