#!/bin/sh
# SPDX-License-Identifier: GPL-3.0-only
# Sourced only by the guarded disposable reciprocal KVM topology.
# shellcheck disable=SC2154,SC2034

reciprocity_private_dns_start() {
    PRIVATE_DNS_UPLINK_PID=
    PRIVATE_DNS_RUN_PID=
    for private_dns_file in reciprocity-private-dns.py reciprocity-private-dns-capture.py \
        reciprocity-private-dns-uplink.py dns-cache-smoke.py dns-cache-fixture.py \
        dns-cache-capture.py content-replication-capture.py reciprocity-smoke.py; do
        install -o root -g root -m 0555 "$source_directory/tests/integration/$private_dns_file" \
            "$WORK/bin/$private_dns_file"
    done
    printf 'Private DNS fixture: create only %s TAPs in %s, %s, %s, %s; use bounded owned slirp processes, disable its DNS/host-loopback, preserve explicit peer routes and restore the original disposable defaults. No host network change.\n' \
        dnsup0 "$CLIENT" "$R0" "$R2" "$EXIT_NODE"
    python3 -B "$WORK/bin/reciprocity-private-dns-uplink.py" "$WORK" "$CLIENT" "$R0" "$R2" "$EXIT_NODE" \
        >"$WORK/reciprocity-private-dns-uplinks.log" 2>&1 &
    PRIVATE_DNS_UPLINK_PID=$!
    private_dns_attempt=0
    while [ ! -s "$WORK/reciprocity-private-dns-uplinks-ready.json" ]; do
        kill -0 "$PRIVATE_DNS_UPLINK_PID" 2>/dev/null || fail PRIVATE_DNS_UPLINK_ENDED
        [ "$private_dns_attempt" -lt 250 ] || fail PRIVATE_DNS_UPLINK_TIMEOUT
        private_dns_attempt=$((private_dns_attempt + 1)); sleep 0.1
    done
}

reciprocity_private_dns_config() {
    case $node in client|relay0|relay2|exit)
        printf 'dns_cache:\n  enabled: true\n  upstream: null\n  fallback:\n    mode: unbound_private\n'
        ;;
    esac
}

reciprocity_private_dns_run() {
    PHASE=reciprocity-private-dns
    kill -0 "$PRIVATE_DNS_UPLINK_PID" 2>/dev/null || fail PRIVATE_DNS_UPLINK_ENDED
    python3 -B "$WORK/bin/reciprocity-private-dns.py" run "$WORK" "$binary_directory/volparossa" \
        "$WORKER_UID" "$WORKER_GID" "$CLIENT" "$R0" "$R2" "$EXIT_NODE" \
        >"$WORK/reciprocity-private-dns-run.log" 2>&1 &
    PRIVATE_DNS_RUN_PID=$!
    private_dns_status=0
    wait "$PRIVATE_DNS_RUN_PID" || private_dns_status=$?
    PRIVATE_DNS_RUN_PID=
    [ "$private_dns_status" -eq 0 ] || fail PRIVATE_DNS_RECIPROCAL_PROOF_FAILED
    # Python verified each actual post-DNS echo before setting the existing stop
    # barrier, then observed shared DNS-association idle cleanup outside that window.
}

reciprocity_private_dns_stop() {
    private_dns_clean=yes
    for private_dns_pid in ${PRIVATE_DNS_RUN_PID:-} ${PRIVATE_DNS_UPLINK_PID:-}; do
        kill -TERM "$private_dns_pid" 2>/dev/null || true
        private_dns_attempt=0
        while kill -0 "$private_dns_pid" 2>/dev/null && [ "$private_dns_attempt" -lt 450 ]; do
            private_dns_attempt=$((private_dns_attempt + 1)); sleep 0.1
        done
        if kill -0 "$private_dns_pid" 2>/dev/null; then
            kill -KILL "$private_dns_pid" 2>/dev/null || true
            private_dns_clean=no
        fi
        wait "$private_dns_pid" || private_dns_clean=no
    done
    PRIVATE_DNS_RUN_PID=
    PRIVATE_DNS_UPLINK_PID=
    [ "$private_dns_clean" = yes ]
}

reciprocity_private_dns_finalize_report() {
    private_dns_status=$1
    private_dns_evidence='{"success":false}'
    private_dns_uplinks='{"complete":false}'
    [ ! -s "$WORK/reciprocity-private-dns-evidence.json" ] \
        || private_dns_evidence=$(cat "$WORK/reciprocity-private-dns-evidence.json")
    [ ! -s "$WORK/reciprocity-private-dns-uplinks-cleanup.json" ] \
        || private_dns_uplinks=$(cat "$WORK/reciprocity-private-dns-uplinks-cleanup.json")
    jq -cn --arg revision "$expected_commit" --arg run_id "$RUN_ID" --arg phase "$PHASE" \
        --arg blocker "$OBSERVED_BLOCKER" --argjson status "$private_dns_status" \
        --argjson evidence "$private_dns_evidence" --argjson uplinks "$private_dns_uplinks" \
        --slurpfile reciprocal "$WORK/reciprocity-smoke.json" \
        '{version:1,report_kind:"volparossa-reciprocity-private-dns",source_revision:$revision,
          run_id:$run_id,phase:$phase,observed_blocker:(if $blocker == "" then null else $blocker end),
          success:($status == 0 and $evidence.success and $uplinks.complete and $reciprocal[0].success),
          scope:"four unchanged all-role agents and concurrent native UDP flows; protected one-relay application DNS, private native recursion and independently validated local reuse; not all DNS cases or default-private rollout",
          evidence:$evidence,uplinks_cleanup:$uplinks,reciprocity:$reciprocal[0],
          cleanup:$reciprocal[0].cleanup,host_state:$reciprocal[0].host_state}' \
        >"$WORK/reciprocity-private-dns-smoke.json"
    for private_dns_artifact in "$WORK"/reciprocity-private-dns-*.json "$WORK"/reciprocity-private-dns-*.log "$WORK"/reciprocity-private-dns-*.err; do
        [ -f "$private_dns_artifact" ] && [ ! -L "$private_dns_artifact" ] || continue
        install -o "$OUTPUT_UID" -g "$OUTPUT_GID" -m 0600 "$private_dns_artifact" \
            "$output_directory/$(basename -- "$private_dns_artifact")"
    done
    python3 -B "$WORK/bin/reciprocity-private-dns.py" check "$WORK/reciprocity-private-dns-smoke.json" "$expected_commit"
}
