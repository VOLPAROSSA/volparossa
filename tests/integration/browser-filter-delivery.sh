#!/bin/sh
# SPDX-License-Identifier: GPL-3.0-only
# Explicit optional continuation of the ORIGINAL protected cold filter fetch.
# All new paths are below the disposable topology's exact WORK directory.
# shellcheck disable=SC2154,SC2034

browser_filter_private() {
    setpriv --reuid="$WORKER_UID" --regid="$site_control_gid" --clear-groups \
        --inh-caps=-all --ambient-caps=-all --bounding-set=-all --no-new-privs \
        -- python3 -B "$WORK/bin/browser-filter-delivery.py" "$@"
}

browser_filter_delivery_cleanup() {
    [ -f "$WORK/bin/browser-filter-delivery.py" ] || return 0
    browser_filter_private cleanup "$WORK/client-fixtures/browser-filter-delivery" \
        >"$WORK/browser-filter-delivery-input-cleanup.json"
    # The driver removes its profiles and owned broker; the enclosing topology
    # owns final removal of the staged source/runtime/report tree under WORK.
}

browser_filter_delivery_copy_artifacts() {
    # Exact bounded JSON only, including partial failure receipts. Never export
    # the Browser log, archive, temporary authority, profile or source tree.
    [ -f "$WORK/bin/browser-filter-delivery.py" ] || return 0
    python3 -B "$WORK/bin/browser-filter-delivery.py" copy-artifacts "$WORK" \
        "$output_directory" "$OUTPUT_UID" "$OUTPUT_GID" >/dev/null
}

browser_filter_delivery_run() {
    if [ -z "${browser_filter_bundle:-}" ] || [ -z "${browser_filter_manifest_sha256:-}" ]; then
        fail BROWSER_FILTER_INPUTS_MISSING
    fi
    PHASE=browser-filter-delivery-prepare
    printf '%s\n' 'Browser filter trial: stage verified inputs only under the disposable WORK; reuse the actual private agent cache; run capless in the Client namespace; remove only the fixture grant/profile.'
    browser_filter_directory=$WORK/client-fixtures/browser-filter-source
    browser_filter_input=$WORK/client-fixtures/browser-filter-delivery
    for browser_filter_new in "$browser_filter_directory" "$browser_filter_input"; do
        if [ -e "$browser_filter_new" ] || [ -L "$browser_filter_new" ]; then fail BROWSER_FILTER_PATH_EXISTS; fi
    done
    install -o root -g root -m 0555 "$source_directory/tests/integration/browser-filter-delivery.py" \
        "$WORK/bin/browser-filter-delivery.py" || fail BROWSER_FILTER_DRIVER_UNAVAILABLE
    install -o root -g root -m 0555 "$source_directory/tests/integration/browser-filter-bundle.py" \
        "$WORK/bin/browser-filter-bundle.py" || fail BROWSER_FILTER_BUNDLE_DRIVER_UNAVAILABLE
    install -o root -g root -m 0600 "$browser_filter_bundle" "$WORK/browser-filter-inputs.tar" \
        || fail BROWSER_FILTER_ARCHIVE_COPY_FAILED
    python3 -B "$WORK/bin/browser-filter-bundle.py" unpack \
        "$WORK/browser-filter-inputs.tar" "$browser_filter_directory" "$browser_filter_manifest_sha256" \
        >"$WORK/browser-filter-delivery-unpack.json" || fail BROWSER_FILTER_UNPACK_FAILED
    # Unpack has already rejected symlinks, hardlinks, unknown paths and modes.
    # This is the fresh, validated input tree only, never existing agent state.
    chown -R "$WORKER_UID:$site_control_gid" "$browser_filter_directory" || fail BROWSER_FILTER_OWNER_FAILED
    install -d -o "$WORKER_UID" -g "$site_control_gid" -m 0700 "$browser_filter_input" "$browser_filter_input/home"
    install -o "$WORKER_UID" -g "$site_control_gid" -m 0400 "$WORK/content-provider-filter-input.json" \
        "$browser_filter_input/selection.json" || fail BROWSER_FILTER_SELECTION_UNAVAILABLE
    browser_filter_expiry=$(jq -er '.expires_unix_seconds | select(type == "number" and . > 0 and . == floor)' \
        "$WORK/content-provider-filter-publish.json") || fail BROWSER_FILTER_EXPIRY_INVALID
    browser_filter_private prepare "$browser_filter_input" "$browser_filter_expiry" \
        >"$WORK/browser-filter-delivery-prepared.json" || fail BROWSER_FILTER_AUTHORITY_FAILED
    browser_filter_broker_sha256=$(sha256sum "$binary_directory/volparossa" | awk '{print $1}')
    python3 -B "$WORK/bin/browser-filter-delivery.py" cache-state "$filter_cache" "$AGENT_UID" "$AGENT_GID" \
        >"$WORK/browser-filter-delivery-cache-before.json" || fail BROWSER_FILTER_CACHE_INVALID
    setpriv --reuid="$WORKER_UID" --regid="$site_control_gid" --clear-groups \
        --inh-caps=-all --ambient-caps=-all --bounding-set=-all --no-new-privs \
        -- python3 -B "$WORK/bin/browser-filter-bundle.py" verify-tree \
        "$browser_filter_directory" "$browser_filter_manifest_sha256" \
        >"$WORK/browser-filter-delivery-tree-before.json" || fail BROWSER_FILTER_SOURCE_CHANGED
    PHASE=browser-filter-delivery-native
    browser_filter_status=0
    timeout --signal=TERM --kill-after=10s 500s ip netns exec "$CLIENT" setpriv \
        --reuid="$WORKER_UID" --regid="$site_control_gid" --clear-groups \
        --inh-caps=-all --ambient-caps=-all --bounding-set=-all --no-new-privs \
        -- env HOME="$browser_filter_input/home" python3 -B "$WORK/bin/browser-filter-delivery.py" launch \
        "$browser_filter_directory" "$browser_filter_input" "$binary_directory/volparossa" \
        "$browser_filter_broker_sha256" "$WORK/runtime-client/control/agent.sock" "$filter_cache" \
        "$site_parent_ns" "$site_client_ns" "$WORKER_UID" "$site_control_gid" \
        >"$WORK/browser-filter-delivery-launch.json" 2>"$WORK/browser-filter-delivery.err" \
        || browser_filter_status=$?
    PHASE=browser-filter-delivery-verify
    python3 -B "$WORK/bin/browser-filter-delivery.py" retain "$WORK" \
        >"$WORK/browser-filter-delivery-retained.json" || fail BROWSER_FILTER_RECEIPT_RETENTION_FAILED
    browser_filter_delivery_cleanup || fail BROWSER_FILTER_INPUT_CLEANUP_FAILED
    [ "$browser_filter_status" -eq 0 ] || fail BROWSER_FILTER_NATIVE_FAILED
    setpriv --reuid="$WORKER_UID" --regid="$site_control_gid" --clear-groups \
        --inh-caps=-all --ambient-caps=-all --bounding-set=-all --no-new-privs \
        -- python3 -B "$WORK/bin/browser-filter-bundle.py" verify-tree \
        "$browser_filter_directory" "$browser_filter_manifest_sha256" \
        >"$WORK/browser-filter-delivery-tree-after.json" || fail BROWSER_FILTER_SOURCE_CHANGED
    python3 -B "$WORK/bin/browser-filter-delivery.py" cache-state "$filter_cache" "$AGENT_UID" "$AGENT_GID" \
        >"$WORK/browser-filter-delivery-cache-after.json" || fail BROWSER_FILTER_CACHE_INVALID
    if setpriv --reuid="$WORKER_UID" --regid="$site_control_gid" --clear-groups \
        --inh-caps=-all --ambient-caps=-all --bounding-set=-all --no-new-privs \
        -- test -r "$filter_cache"; then fail BROWSER_FILTER_AGENT_CACHE_EXPOSED; fi
    python3 -B "$WORK/bin/browser-filter-delivery.py" evidence "$WORK" "$browser_filter_manifest_sha256" \
        "$browser_filter_broker_sha256" "$WORKER_UID" "$WORKER_GID" "$site_control_gid" \
        >"$WORK/browser-filter-delivery-evidence.json" || fail BROWSER_FILTER_EVIDENCE_INVALID
}
