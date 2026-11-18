#!/bin/sh
# SPDX-License-Identifier: GPL-3.0-only
# Profile 6 guest lifecycle only. Sourcing performs no I/O. The enclosing
# admitted KVM run supplies all paths, identities and the publication deadline.
# shellcheck disable=SC2154,SC2034

WEATHER_ANDROID_API_PID=
WEATHER_ANDROID_API_IDENTITY=
WEATHER_ANDROID_API_JOINED=no
WEATHER_ANDROID_API_STATUS=
WEATHER_ANDROID_PRIVACY_STARTED=no
WEATHER_ANDROID_CONTROL_STARTED=no
WEATHER_ANDROID_CONTROLLER_ATTEMPTED=no
WEATHER_ANDROID_CONTROLLER_IDENTITY=
WEATHER_ANDROID_PREPARED_SHA=
WEATHER_ANDROID_CONTROLLER=/usr/local/libexec/volparossa-weather-android-control.py

weather_android_process_identity() {
    # Start time prevents signalling a recycled PID after the shell reaps an
    # exited child. No caller-supplied process is admitted to this lifecycle.
    case $WEATHER_ANDROID_API_PID in ''|*[!0-9]*) return 2 ;; esac
    [ -d "/proc/$WEATHER_ANDROID_API_PID" ] || return 1
    if ! IFS= read -r weather_android_proc_line <"/proc/$WEATHER_ANDROID_API_PID/stat" 2>/dev/null; then
        [ -d "/proc/$WEATHER_ANDROID_API_PID" ] || return 1
        return 2
    fi
    weather_android_proc_fields=${weather_android_proc_line##*) }
    # Everything after the final comm delimiter is a fixed kernel field, not
    # shell input. Keep this cheap while waiting; do not spawn a polling worker.
    # shellcheck disable=SC2086
    set -- $weather_android_proc_fields
    [ "$#" -ge 20 ] || return 2
    case $1 in Z|X) return 1 ;; esac
    shift 19
    case $1 in ''|*[!0-9]*) return 2 ;; esac
    printf '%s\n' "$1"
}

weather_android_api_alive() {
    [ -n "$WEATHER_ANDROID_API_PID" ] && [ -n "$WEATHER_ANDROID_API_IDENTITY" ] || return 2
    weather_android_current_identity=$(weather_android_process_identity) || return $?
    [ "$weather_android_current_identity" = "$WEATHER_ANDROID_API_IDENTITY" ]
}

weather_android_join_api() {
    # wait has no portable deadline. Call it only after observing termination
    # or PID replacement, never after an inconclusive /proc read or missing
    # initial identity. An unconfirmed join remains a failure for VM teardown.
    if weather_android_api_alive; then return 1; else weather_android_probe_status=$?; fi
    [ "$weather_android_probe_status" -eq 1 ] || return 1
    WEATHER_ANDROID_API_STATUS=0
    wait "$WEATHER_ANDROID_API_PID" || WEATHER_ANDROID_API_STATUS=$?
    WEATHER_ANDROID_API_JOINED=yes
}

weather_android_stop_observers() {
    weather_android_observer_status=0
    if [ "$WEATHER_ANDROID_PRIVACY_STARTED" = yes ]; then
        stop_privacy_observers || weather_android_observer_status=1
        WEATHER_ANDROID_PRIVACY_STARTED=no
    fi
    if [ "$WEATHER_ANDROID_CONTROL_STARTED" = yes ]; then
        content_provider_stop_control_observer || weather_android_observer_status=1
        WEATHER_ANDROID_CONTROL_STARTED=no
    fi
    return "$weather_android_observer_status"
}

weather_android_stop_api() {
    [ -n "$WEATHER_ANDROID_API_PID" ] && [ "$WEATHER_ANDROID_API_JOINED" = no ] || return 0
    weather_android_stop_status=0
    if weather_android_api_alive; then
        kill -TERM "$WEATHER_ANDROID_API_PID" || weather_android_stop_status=1
        weather_android_stop_attempt=0
        while weather_android_api_alive && [ "$weather_android_stop_attempt" -lt 200 ]; do
            sleep 0.1
            weather_android_stop_attempt=$((weather_android_stop_attempt + 1))
        done
        if weather_android_api_alive; then
            # A forced owner kill cannot establish descendant cleanup. The VM
            # teardown is still mandatory; never call this successful delivery.
            kill -KILL "$WEATHER_ANDROID_API_PID" || true
            weather_android_stop_status=1
            weather_android_stop_attempt=0
            while weather_android_api_alive && [ "$weather_android_stop_attempt" -lt 50 ]; do
                sleep 0.1
                weather_android_stop_attempt=$((weather_android_stop_attempt + 1))
            done
        fi
    fi
    weather_android_join_api || return 1
    [ "$WEATHER_ANDROID_API_STATUS" -eq 0 ] || weather_android_stop_status=1
    return "$weather_android_stop_status"
}

weather_android_controller_cleanup() {
    weather_android_controller_status=0
    if [ "$WEATHER_ANDROID_CONTROLLER_ATTEMPTED" = yes ]; then
        python3 -B "$WORK/bin/weather-android-control.py" remove "$WORK" "$WEATHER_ANDROID_PREPARED_SHA" \
            >"$WORK/weather-android-delivery-controller-cleanup.json" || weather_android_controller_status=1
    fi
    if [ -n "$WEATHER_ANDROID_CONTROLLER_IDENTITY" ]; then
        if [ -L "$WEATHER_ANDROID_CONTROLLER" ] || [ ! -f "$WEATHER_ANDROID_CONTROLLER" ] \
            || [ "$(stat -Lc '%d:%i:%u:%g:%a' "$WEATHER_ANDROID_CONTROLLER")" != "$WEATHER_ANDROID_CONTROLLER_IDENTITY" ]; then
            weather_android_controller_status=1
        else
            rm -- "$WEATHER_ANDROID_CONTROLLER" || weather_android_controller_status=1
            WEATHER_ANDROID_CONTROLLER_IDENTITY=
        fi
    fi
    return "$weather_android_controller_status"
}

weather_android_evidence_failure() {
    # Only this exact verifier's finite statuses name a rejected check group.
    # No stderr parsing, dynamic blocker suffix or success fallback is allowed.
    case $1 in
        20) fail WEATHER_ANDROID_EVIDENCE_BOUNDARY_INVALID ;;
        21) fail WEATHER_ANDROID_EVIDENCE_SOURCE_INVALID ;;
        22) fail WEATHER_ANDROID_EVIDENCE_PREPARED_INVALID ;;
        23) fail WEATHER_ANDROID_EVIDENCE_SELECTION_INVALID ;;
        24) fail WEATHER_ANDROID_EVIDENCE_CONFIGURATION_INVALID ;;
        25) fail WEATHER_ANDROID_EVIDENCE_API_LIFECYCLE_INVALID ;;
        26) fail WEATHER_ANDROID_EVIDENCE_API_PRIVATE_CLEANUP_INVALID ;;
        27) fail WEATHER_ANDROID_EVIDENCE_RECEIPT_CUSTODY_INVALID ;;
        28) fail WEATHER_ANDROID_EVIDENCE_RECEIPT_SHAPE_INVALID ;;
        29) fail WEATHER_ANDROID_EVIDENCE_RECEIPT_TIMING_INVALID ;;
        30) fail WEATHER_ANDROID_EVIDENCE_RECEIPT_PUBLICATION_INVALID ;;
        31) fail WEATHER_ANDROID_EVIDENCE_RECEIPT_COUNTERS_INVALID ;;
        32) fail WEATHER_ANDROID_EVIDENCE_ACQUISITION_INVALID ;;
        33) fail WEATHER_ANDROID_EVIDENCE_TOPOLOGY_INPUTS_INVALID ;;
        34) fail WEATHER_ANDROID_EVIDENCE_CACHE_CUSTODY_INVALID ;;
        35) fail WEATHER_ANDROID_EVIDENCE_PUBLICATION_FILES_INVALID ;;
        36) fail WEATHER_ANDROID_EVIDENCE_PACKET_CONTROL_ROUTE_INVALID ;;
        37) fail WEATHER_ANDROID_EVIDENCE_PUBLISHER_CLEANUP_INVALID ;;
        38) fail WEATHER_ANDROID_EVIDENCE_SOURCE_SNAPSHOT_INVALID ;;
        39) fail WEATHER_ANDROID_EVIDENCE_EXPORT_SHAPE_INVALID ;;
        124) fail WEATHER_ANDROID_EVIDENCE_TIMEOUT ;;
        125) fail WEATHER_ANDROID_EVIDENCE_INTERRUPTED ;;
        129|1[3-8][0-9]|19[0-2])
            fail WEATHER_ANDROID_EVIDENCE_SIGNAL ;;
        *) fail WEATHER_ANDROID_EVIDENCE_INVALID ;;
    esac
}

# Overrides the historical browser trap only for explicit profile 6. Private
# proof stays in the disposable guest for the evidence join, never public logs.
weather_client_delivery_cleanup() {
    weather_android_cleanup_status=0
    weather_android_stop_api || weather_android_cleanup_status=1
    weather_android_stop_observers || weather_android_cleanup_status=1
    weather_android_controller_cleanup || weather_android_cleanup_status=1
    if [ -f "$WORK/bin/weather-products-delivery.py" ] && [ -n "${site_control_gid:-}" ]; then
        weather_products_private publisher-cleanup "$WORK/client-fixtures/weather-publisher" \
            >"$WORK/weather-products-delivery-publisher-cleanup.json" || weather_android_cleanup_status=1
    fi
    # No browser home was created. Do not run the browser's user-cleanup on an
    # Android proof directory, or erase failure evidence before export.
    return "$weather_android_cleanup_status"
}

weather_client_delivery_copy_artifacts() {
    [ -f "$WORK/bin/weather-android-evidence.py" ] || return 1
    python3 -B "$WORK/bin/weather-android-evidence.py" copy-artifacts "$WORK" \
        "$output_directory" "$OUTPUT_UID" "$OUTPUT_GID" >/dev/null
}

weather_android_delivery_run() {
    [ "$weather_profile_version" = 6 ] && [ "$WORKER_UID" = 985 ] \
        && [ "$(id -u)" -eq 0 ] && [ "$(systemd-detect-virt)" = kvm ] || fail WEATHER_ANDROID_BOUNDARY_INVALID
    [ ! -e "$weather_publisher" ] && [ ! -L "$weather_publisher" ] || fail WEATHER_ANDROID_ORIGINALS_REMAIN
    PHASE=weather-android-delivery-prepare
    weather_android_cache=$WORK/weather-android-cache
    # This exact empty parent must predate the client's strict mount sandbox.
    # Do not recreate it here: a replacement would not be the writable bind.
    [ "${WEATHER_AGENT_PROFILE_VERSION:-}" = 6 ] && [ -n "${WEATHER_ANDROID_CACHE_IDENTITY:-}" ] \
        && [ -d "$weather_android_cache" ] && [ ! -L "$weather_android_cache" ] \
        && [ "$(stat -Lc '%d:%i:%u:%g:%a' "$weather_android_cache")" = "$WEATHER_ANDROID_CACHE_IDENTITY" ] \
        && [ "$(stat -Lc '%u:%g:%a' "$weather_android_cache")" = "$AGENT_UID:$site_control_gid:710" ] \
        || fail WEATHER_ANDROID_CACHE_PARENT_CHANGED
    weather_command_limit=$(weather_products_remaining 40) || fail WEATHER_PRODUCTS_DEADLINE
    timeout --signal=TERM --kill-after=20s "${weather_command_limit}s" ip netns exec "$CLIENT" setpriv \
        --reuid="$WORKER_UID" --regid="$site_control_gid" --clear-groups \
        --inh-caps=-all --ambient-caps=-all --bounding-set=-all --no-new-privs \
        -- python3 -B "$WORK/bin/weather-android-delivery.py" prepare "$WORK" "$weather_client_manifest_sha256" \
        "$site_parent_ns" "$site_client_ns" "$site_control_gid" \
        >"$WORK/weather-android-delivery-prepared.json" || fail WEATHER_ANDROID_PREPARE_FAILED
    WEATHER_ANDROID_PREPARED_SHA=$(sha256sum "$WORK/weather-android-delivery-prepared.json" | awk '{print $1}')
    install -o "$WORKER_UID" -g "$site_control_gid" -m 0400 "$WORK/weather-android-delivery-prepared.json" \
        "$weather_viewer/prepared.json" || fail WEATHER_ANDROID_PREPARED_RETENTION_FAILED
    [ ! -e "$WEATHER_ANDROID_CONTROLLER" ] && [ ! -L "$WEATHER_ANDROID_CONTROLLER" ] \
        || fail WEATHER_ANDROID_CONTROLLER_EXISTS
    [ -d /usr/local/libexec ] && [ ! -L /usr/local/libexec ] \
        && [ "$(stat -Lc '%u:%g:%a' /usr/local/libexec)" = 0:0:755 ] || fail WEATHER_ANDROID_CONTROLLER_DIRECTORY_UNSAFE
    install -o root -g root -m 0555 "$WORK/bin/weather-android-control.py" "$WEATHER_ANDROID_CONTROLLER" \
        || fail WEATHER_ANDROID_CONTROLLER_STAGE_FAILED
    WEATHER_ANDROID_CONTROLLER_IDENTITY=$(stat -Lc '%d:%i:%u:%g:%a' "$WEATHER_ANDROID_CONTROLLER")
    weather_android_seconds=$(weather_products_remaining 840) || fail WEATHER_PRODUCTS_DEADLINE
    [ "$weather_android_seconds" -ge 600 ] || fail WEATHER_ANDROID_TRIAL_BUDGET_INSUFFICIENT
    # One common window, not the independent v1-v5 product capture claim.
    WEATHER_ANDROID_PRIVACY_STARTED=yes
    start_privacy_observers weather-android-delivery-privacy || fail WEATHER_ANDROID_CAPTURE_UNAVAILABLE
    WEATHER_ANDROID_CONTROL_STARTED=yes
    content_provider_start_control_observer weather-android-delivery-control || fail WEATHER_ANDROID_CONTROL_UNAVAILABLE
    PHASE=weather-android-delivery-api
    ip netns exec "$CLIENT" setpriv --reuid="$WORKER_UID" --regid="$site_control_gid" --clear-groups \
        --inh-caps=-all --ambient-caps=-all --bounding-set=-all --no-new-privs \
        -- python3 -B "$WORK/bin/weather-android-api.py" serve "$WORK" "$weather_client_manifest_sha256" \
        "$WEATHER_ANDROID_PREPARED_SHA" "$site_parent_ns" "$site_client_ns" "$site_control_gid" "$WEATHER_PRODUCTS_DEADLINE" \
        >"$WORK/weather-android-delivery-api.jsonl" 2>"$WORK/weather-android-delivery-api.err" &
    WEATHER_ANDROID_API_PID=$!
    WEATHER_ANDROID_API_IDENTITY=$(weather_android_process_identity) || fail WEATHER_ANDROID_API_START_FAILED
    weather_android_ready_until=$(($(date +%s) + 20))
    while :; do
        weather_android_api_alive || fail WEATHER_ANDROID_API_EXITED
        [ "$(date +%s)" -lt "$weather_android_ready_until" ] || fail WEATHER_ANDROID_API_READY_TIMEOUT
        if [ -s "$WORK/weather-android-delivery-api.jsonl" ] \
            && IFS= read -r weather_android_ready_line <"$WORK/weather-android-delivery-api.jsonl"; then
            break
        fi
        sleep 0.1
    done
    weather_android_seconds=$(weather_products_remaining 840) || fail WEATHER_PRODUCTS_DEADLINE
    [ "$weather_android_seconds" -ge 600 ] || fail WEATHER_ANDROID_TRIAL_BUDGET_INSUFFICIENT
    WEATHER_ANDROID_CONTROLLER_ATTEMPTED=yes
    python3 -B "$WORK/bin/weather-android-control.py" publish "$WORK" "$weather_client_manifest_sha256" \
        "$weather_core_sha256" "$WEATHER_ANDROID_PREPARED_SHA" "$site_control_gid" "$WEATHER_PRODUCTS_DEADLINE" \
        >"$WORK/weather-android-delivery-ready.json" || fail WEATHER_ANDROID_READY_REJECTED
    PHASE=weather-android-delivery-installed-app
    # The host runs the prepared Android APK through the fixed API-only tunnel.
    # It requests finalization only after joining Android and the held-open
    # tunnel. API expiry/abort is not a successful finalize marker.
    weather_android_join_until=$((WEATHER_PRODUCTS_DEADLINE + 20))
    while weather_android_api_alive; do
        [ "$(date +%s)" -lt "$weather_android_join_until" ] || fail WEATHER_ANDROID_API_JOIN_TIMEOUT
        sleep 0.1
    done
    weather_android_join_api || fail WEATHER_ANDROID_API_JOIN_UNCONFIRMED
    [ "$WEATHER_ANDROID_API_STATUS" -eq 0 ] || fail WEATHER_ANDROID_API_FAILED
    PHASE=weather-android-delivery-verify
    benchmark_capture_paths weather-android-delivery mptcp || fail WEATHER_ANDROID_PATHS_UNAVAILABLE
    weather_android_stop_observers || fail WEATHER_ANDROID_CAPTURE_INCOMPLETE
    weather_client_verify_tree >"$WORK/weather-products-delivery-tree-after.json" || fail WEATHER_PRODUCTS_SOURCE_CHANGED
    # This fail-closed gate is intentionally required even while the new guest
    # verifier is being wired. Lifecycle success alone is not network evidence.
    if python3 -B "$WORK/bin/weather-android-evidence.py" guest "$WORK" "$weather_client_manifest_sha256" \
        "$weather_core_sha256" "$WEATHER_ANDROID_PREPARED_SHA" \
        >"$WORK/weather-android-delivery-evidence.json"; then
        :
    else
        weather_android_evidence_failure "$?"
    fi
    weather_android_controller_cleanup || fail WEATHER_ANDROID_CONTROLLER_CLEANUP_FAILED
    PHASE=weather-android-delivery-complete
}
