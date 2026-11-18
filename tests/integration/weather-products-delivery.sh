#!/bin/sh
# SPDX-License-Identifier: GPL-3.0-only
# Two independently published public products; each admitted client keeps its
# own cold-fetch and evidence contract. Profile 6 never enters the browser loop.
# Sourced after the enclosing runner verifies the selected input archive.
# Reuses the v1 guest/home/CLI utilities; sourcing this file performs no I/O.
# shellcheck disable=SC2154,SC2034

WEATHER_PRODUCTS_DEADLINE=

weather_products_remaining() {
    weather_requested_seconds=$1
    if [ -z "$WEATHER_PRODUCTS_DEADLINE" ]; then
        printf '%s\n' "$weather_requested_seconds"
        return 0
    fi
    weather_seconds_left=$((WEATHER_PRODUCTS_DEADLINE - $(date +%s)))
    [ "$weather_seconds_left" -gt 0 ] || return 1
    if [ "$weather_seconds_left" -lt "$weather_requested_seconds" ]; then
        printf '%s\n' "$weather_seconds_left"
    else
        printf '%s\n' "$weather_requested_seconds"
    fi
}

weather_products_private() {
    setpriv --reuid="$WORKER_UID" --regid="$site_control_gid" --clear-groups \
        --inh-caps=-all --ambient-caps=-all --bounding-set=-all --no-new-privs \
        -- python3 -B "$WORK/bin/weather-products-delivery.py" "$@"
}

weather_products_cli() {
    weather_socket_node=$1
    shift
    weather_command_limit=$(weather_products_remaining 120) || return 1
    timeout --signal=TERM --kill-after=5s "${weather_command_limit}s" setpriv \
        --reuid="$WORKER_UID" --regid="$site_control_gid" --clear-groups \
        --inh-caps=-all --ambient-caps=-all --bounding-set=-all --no-new-privs \
        -- "$binary_directory/volparossa" \
        --control-socket "$WORK/runtime-$weather_socket_node/control/agent.sock" "$@"
}

weather_products_select() {
    case $1 in
        weather)
            weather_product=weather
            weather_product_path=weather
            weather_product_file=forecast.json
            weather_product_manifest=manifest.bin
            weather_product_receipt=publish-receipt.json
            weather_product_source_cache=source-cache
            weather_product_name=disposable-public-community-weather
            weather_publications=4 ;;
        air_quality)
            weather_product=air_quality
            weather_product_path=air-quality
            weather_product_file=air-quality.json
            weather_product_manifest=air-quality-manifest.bin
            weather_product_receipt=air-quality-publish-receipt.json
            weather_product_source_cache=air-quality-source-cache
            weather_product_name=disposable-public-community-air-quality
            weather_publications=5 ;;
        *) return 1 ;;
    esac
    weather_product_prefix=weather-products-delivery-$weather_product_path
    weather_product_cache=$WORK/state-client/$weather_product_path-cache
}

# These replace the v1 trap/export entrypoints only after verified v2 dispatch.
weather_client_delivery_cleanup() {
    weather_cleanup_status=0
    if [ -f "$WORK/bin/weather-products-delivery.py" ] && [ -n "${site_control_gid:-}" ]; then
        if [ ! -e "$WORK/weather-products-delivery-original-report.json" ] \
            && [ ! -L "$WORK/weather-products-delivery-original-report.json" ]; then
            if [ -e "$WORK/client-fixtures/weather-viewer/browser-output/report.json" ] \
                || [ -L "$WORK/client-fixtures/weather-viewer/browser-output/report.json" ]; then
                python3 -B "$WORK/bin/weather-products-delivery.py" retain "$WORK" \
                    >"$WORK/weather-products-delivery-retained.json" || weather_cleanup_status=1
            fi
        fi
        weather_products_private publisher-cleanup "$WORK/client-fixtures/weather-publisher" \
            >"$WORK/weather-products-delivery-publisher-cleanup.json" || weather_cleanup_status=1
        weather_products_private user-cleanup "$WORK/client-fixtures/weather-viewer" \
            >"$WORK/weather-products-delivery-input-cleanup.json" || weather_cleanup_status=1
    fi
    weather_client_home_cleanup || weather_cleanup_status=1
    return "$weather_cleanup_status"
}

weather_client_delivery_copy_artifacts() {
    [ -f "$WORK/bin/weather-products-delivery.py" ] || return 0
    weather_export_action=copy-artifacts
    if [ -e "$WORK/weather-products-delivery-acquisition-failure.json" ] \
        || [ -L "$WORK/weather-products-delivery-acquisition-failure.json" ]; then
        weather_export_action=copy-failure-artifacts
    fi
    # The trusted helper validates the marker. An unsafe failure marker must not
    # fall back to the independent, atomic success-evidence exporter.
    python3 -B "$WORK/bin/weather-products-delivery.py" "$weather_export_action" "$WORK" \
        "$output_directory" "$OUTPUT_UID" "$OUTPUT_GID" >/dev/null
}

weather_products_delivery_run() {
    [ -n "$weather_client_bundle" ] && [ -n "$weather_client_manifest_sha256" ] \
        || fail WEATHER_PRODUCTS_INPUTS_MISSING
    # Selected by complete immutable-archive validation in the enclosing
    # dispatcher. Never accept a caller-supplied driver path or fallback UI.
    case ${weather_profile_version:-} in
        2|4) weather_products_driver=integrations/drizzli/smoke_core_browser.py ;;
        3|5) weather_products_driver=integrations/overmorrow/smoke_core_browser.py ;;
        6)
            # Sourcing only defines ownership/cleanup. The API starts after both
            # publications and removal of their original publisher files.
            . "$source_directory/tests/integration/weather-android-delivery.sh"
            weather_products_driver= ;;
        *) fail WEATHER_CLIENT_PROFILE_INVALID ;;
    esac
    PHASE=weather-products-delivery-prepare
    if [ "$weather_profile_version" = 6 ]; then
        printf '%s\n' 'Weather Android trial: acquire and publish the two real public products, remove publisher originals, then use a common capture window for Android-triggered cold fetch and two refreshes. No prewarm, no extra fetch on resume, no host network or user-data changes.'
    else
        printf '%s\n' 'Weather two-product trial: acquire public ECMWF precipitation/weather and NOAA particulate fields in the disposable guest; publish separately to two existing peers, remove both originals and publisher identity, cold-fetch each product with independent captures, then check both products and refresh in the exact bundled isolated client. No host network or user-data changes.'
    fi
    [ "$WORKER_UID" = 985 ] && [ "$site_control_gid" != "$AGENT_GID" ] \
        || fail WEATHER_PRODUCTS_USER_INVALID
    weather_client_directory=$WORK/client-fixtures/weather-client-source
    weather_publisher=$WORK/client-fixtures/weather-publisher
    weather_viewer=$WORK/client-fixtures/weather-viewer
    for weather_new in "$weather_client_directory" "$weather_publisher" "$weather_viewer" \
        "$WORK/state-client/weather-cache" "$WORK/state-client/air-quality-cache" \
        "$WORK/state-$provider_node_a/weather-cache" "$WORK/state-$provider_node_b/weather-cache" \
        "$WORK/state-$provider_node_a/air-quality-cache" "$WORK/state-$provider_node_b/air-quality-cache"; do
        if [ -e "$weather_new" ] || [ -L "$weather_new" ]; then fail WEATHER_PRODUCTS_PATH_EXISTS; fi
    done
    for weather_script in weather-products-delivery.py weather-source-observer.mjs weather-client-delivery.py weather-client-bundle.py \
        browser-filter-bundle.py content-provider-https-smoke.py content-network-smoke.py weather-public-drizzli-v4.json; do
        install -o root -g root -m 0555 "$source_directory/tests/integration/$weather_script" \
            "$WORK/bin/$weather_script" || fail WEATHER_PRODUCTS_DRIVER_UNAVAILABLE
    done
    # This reviewed record does not exist until the public Overmorrow trial is
    # admitted. Missing v5 authority must not disable the older profiles.
    if [ "$weather_profile_version" = 5 ]; then
        install -o root -g root -m 0555 "$source_directory/tests/integration/weather-public-overmorrow-v5.json" \
            "$WORK/bin/weather-public-overmorrow-v5.json" || fail WEATHER_PRODUCTS_DRIVER_UNAVAILABLE
    fi
    if [ "$weather_profile_version" = 6 ]; then
        for weather_android_script in weather-public-android-v6.json weather-android-delivery.py \
            weather-android-api.py weather-android-control.py weather-android-evidence.py; do
            install -o root -g root -m 0555 "$source_directory/tests/integration/$weather_android_script" \
                "$WORK/bin/$weather_android_script" || fail WEATHER_PRODUCTS_DRIVER_UNAVAILABLE
        done
    fi
    install -o root -g root -m 0600 "$weather_client_bundle" "$WORK/weather-client-inputs.tar" \
        || fail WEATHER_PRODUCTS_ARCHIVE_COPY_FAILED
    python3 -B "$WORK/bin/weather-client-bundle.py" unpack "$WORK/weather-client-inputs.tar" \
        "$weather_client_directory" "$weather_client_manifest_sha256" \
        >"$WORK/weather-products-delivery-unpack.json" || fail WEATHER_PRODUCTS_UNPACK_FAILED
    install -o root -g root -m 0400 "$weather_client_directory/INPUTS.json" \
        "$WORK/weather-products-delivery-manifest.json" || fail WEATHER_PRODUCTS_MANIFEST_RETENTION_FAILED
    chown -R "$WORKER_UID:$site_control_gid" "$weather_client_directory" || fail WEATHER_PRODUCTS_OWNER_FAILED
    install -d -o "$WORKER_UID" -g "$site_control_gid" -m 0700 "$weather_publisher" "$weather_viewer" \
        || fail WEATHER_PRODUCTS_PRIVATE_DIRECTORY_FAILED
    weather_client_verify_tree >"$WORK/weather-products-delivery-tree-before.json" || fail WEATHER_PRODUCTS_SOURCE_CHANGED
    if [ "$weather_profile_version" != 6 ]; then
        weather_client_home_prepare || fail WEATHER_PRODUCTS_HOME_UNSAFE
    fi
    weather_core_sha256=$(sha256sum "$binary_directory/volparossa" | awk '{print $1}')
    weather_products_private init "$weather_publisher" >"$WORK/weather-products-delivery-assets.json" \
        || fail WEATHER_PRODUCTS_INPUT_FAILED
    PHASE=weather-products-delivery-acquire
    # Both bounded source acquisitions precede publication; they cannot consume
    # the publication's lifetime. No origin retry is delegated to the browser.
    # The helper owns separately-sessioned decoder children. Allow its bounded
    # TERM/KILL/reap cleanup (at most 20s) to finish before the outer hard kill.
    weather_acquisition_status=0
    timeout --signal=TERM --kill-after=30s 740s setpriv \
        --reuid="$WORKER_UID" --regid="$site_control_gid" --clear-groups \
        --inh-caps=-all --ambient-caps=-all --bounding-set=-all --no-new-privs \
        -- python3 -B "$WORK/bin/weather-products-delivery.py" acquire \
        "$weather_client_directory" "$weather_client_manifest_sha256" "$weather_publisher" \
        "$site_parent_ns" "$site_client_ns" "$site_control_gid" \
        >"$WORK/weather-products-delivery-acquisition.json" 2>"$WORK/weather-products-delivery-acquisition.err" \
        || weather_acquisition_status=$?
    if [ "$weather_acquisition_status" -ne 0 ]; then
        if [ -e "$WORK/weather-products-delivery-acquisition-failure.json" ] \
            || [ -L "$WORK/weather-products-delivery-acquisition-failure.json" ]; then
            fail WEATHER_PRODUCTS_ACQUISITION_DIAGNOSTIC_FAILED
        fi
        python3 -B "$WORK/bin/weather-products-delivery.py" retain-acquisition-failure \
            "$WORK" "$weather_acquisition_status" \
            >"$WORK/weather-products-delivery-acquisition-failure.json" \
            || fail WEATHER_PRODUCTS_ACQUISITION_DIAGNOSTIC_FAILED
        fail WEATHER_PRODUCTS_ACQUISITION_FAILED
    fi
    # Budget all later commands together, not 900 seconds per operation. Each
    # immutable publication still independently enforces its original expiry.
    WEATHER_PRODUCTS_DEADLINE=$(($(date +%s) + 840))
    PHASE=weather-products-delivery-publish
    weather_products_cli "$provider_node_a" init --identity "$weather_publisher/identity.key" \
        --passphrase-file "$weather_publisher/passphrase" >"$WORK/weather-products-delivery-init.log" \
        2>"$WORK/weather-products-delivery-init.err" || fail WEATHER_PRODUCTS_IDENTITY_FAILED
    weather_key=
    for weather_kind in weather air_quality; do
        weather_products_select "$weather_kind" || fail WEATHER_PRODUCTS_KIND_INVALID
        weather_products_cli "$provider_node_a" content publish --input "$weather_publisher/$weather_product_file" \
            --name "$weather_product_name" --revision 1 --content-type application/json \
            --lifetime-seconds 900 --identity "$weather_publisher/identity.key" \
            --passphrase-file "$weather_publisher/passphrase" --cache "$weather_publisher/$weather_product_source_cache" \
            --manifest "$weather_publisher/$weather_product_manifest" >"$WORK/$weather_product_prefix-publish.json" \
            2>"$WORK/$weather_product_prefix-publish.err" || fail WEATHER_PRODUCTS_PUBLISH_FAILED
        weather_published_key=$(jq -er '.publisher_key_hex | select(test("^[0-9a-f]{64}$"))' \
            "$WORK/$weather_product_prefix-publish.json") || fail WEATHER_PRODUCTS_PUBLISHER_INVALID
        if [ "$weather_published_key" = "$provider_publisher" ] || [ "$weather_published_key" = "$site_key" ] \
            || [ "$weather_published_key" = "$filter_key" ]; then fail WEATHER_PRODUCTS_PUBLISHER_REUSED; fi
        if [ -n "$weather_key" ] && [ "$weather_key" != "$weather_published_key" ]; then fail WEATHER_PRODUCTS_PUBLISHER_CHANGED; fi
        weather_key=$weather_published_key
        install -o "$WORKER_UID" -g "$site_control_gid" -m 0400 "$WORK/$weather_product_prefix-publish.json" \
            "$weather_publisher/$weather_product_receipt" || fail WEATHER_PRODUCTS_PUBLISH_RECEIPT_UNAVAILABLE
        for weather_node in "$provider_node_a" "$provider_node_b"; do
            case $weather_node in
                relay4) weather_address=49.165.5.1; weather_hostname=provider-a.volparossa.test ;;
                relay5) weather_address=50.166.6.1; weather_hostname=provider-b.volparossa.test ;;
                relay3) weather_address=48.164.4.1; weather_hostname=provider-c.volparossa.test ;;
                *) fail WEATHER_PRODUCTS_PROVIDER_INVALID ;;
            esac
            weather_products_cli "$weather_node" content import --public-content \
                --manifest "$weather_publisher/$weather_product_manifest" --publisher-key "$weather_key" \
                --cache "$weather_publisher/$weather_product_source_cache" --agent-cache "$WORK/state-$weather_node/$weather_product_path-cache" \
                >"$WORK/$weather_product_prefix-$weather_node-import.json" \
                2>"$WORK/$weather_product_prefix-$weather_node-import.err" || fail WEATHER_PRODUCTS_IMPORT_FAILED
            weather_products_cli "$weather_node" content serve --name-lookup \
                --manifest "$weather_publisher/$weather_product_manifest" --publisher-key "$weather_key" \
                --cache "$WORK/state-$weather_node/$weather_product_path-cache" --bind "$weather_address:18080" \
                --advertised-hostname "$weather_hostname" >"$WORK/$weather_product_prefix-$weather_node-serve.json" \
                2>"$WORK/$weather_product_prefix-$weather_node-serve.err" || fail WEATHER_PRODUCTS_SERVE_FAILED
            jq -e --argjson publications "$weather_publications" \
                '.serving == true and .publications == $publications and .replication_enabled == false' \
                "$WORK/$weather_product_prefix-$weather_node-serve.json" >/dev/null || fail WEATHER_PRODUCTS_NOT_READY
            if [ -L "$WORK/state-$weather_node/$weather_product_path-cache" ] \
                || [ "$(stat -Lc '%a:%u:%g' "$WORK/state-$weather_node/$weather_product_path-cache")" != "700:$AGENT_UID:$AGENT_GID" ]; then
                fail WEATHER_PRODUCTS_PROVIDER_CACHE_CHANGED
            fi
            if nsenter --target "$provider_client_pid" --mount \
                setpriv --reuid="$AGENT_UID" --regid="$AGENT_GID" --clear-groups \
                --inh-caps=-all --ambient-caps=-all --bounding-set=-all --no-new-privs \
                -- test -r "$WORK/state-$weather_node/$weather_product_path-cache"; then fail WEATHER_PRODUCTS_LOCAL_SHORTCUT; fi
            if setpriv --reuid="$WORKER_UID" --regid="$site_control_gid" --clear-groups \
                --inh-caps=-all --ambient-caps=-all --bounding-set=-all --no-new-privs \
                -- test -r "$WORK/state-$weather_node/$weather_product_path-cache"; then fail WEATHER_PRODUCTS_AGENT_CACHE_EXPOSED; fi
        done
    done
    weather_products_private select "$weather_publisher" "$weather_viewer" \
        >"$WORK/weather-products-delivery-input.json" || fail WEATHER_PRODUCTS_SELECTION_FAILED
    nsenter --target "$provider_client_pid" --mount \
        setpriv --reuid="$AGENT_UID" --regid="$AGENT_GID" --clear-groups \
        --inh-caps=-all --ambient-caps=-all --bounding-set=-all --no-new-privs \
        -- test -r "$WORK/state-client/identity.key" || fail WEATHER_PRODUCTS_ISOLATION_PROBE_FAILED
    if nsenter --target "$provider_client_pid" --mount \
        setpriv --reuid="$AGENT_UID" --regid="$AGENT_GID" --clear-groups \
        --inh-caps=-all --ambient-caps=-all --bounding-set=-all --no-new-privs \
        -- test -r "$weather_viewer"; then fail WEATHER_PRODUCTS_USER_STATE_EXPOSED; fi
    weather_products_private publisher-cleanup "$weather_publisher" \
        >"$WORK/weather-products-delivery-publisher-cleanup.json" || fail WEATHER_PRODUCTS_PUBLISHER_CLEANUP_FAILED
    [ ! -e "$weather_publisher" ] && [ ! -L "$weather_publisher" ] || fail WEATHER_PRODUCTS_PUBLISHER_FILES_REMAIN
    if [ "$weather_profile_version" = 6 ]; then
        # The installed Android application's first real GET must create the
        # client cache and fetch its bytes. No cold CLI, browser preparation or
        # prefetched forecast may run on this branch.
        weather_android_delivery_run
        return
    fi
    for weather_kind in weather air_quality; do
        weather_products_select "$weather_kind" || fail WEATHER_PRODUCTS_KIND_INVALID
        PHASE=weather-products-delivery-cold-$weather_product_path
        start_privacy_observers "$weather_product_prefix-privacy" || fail WEATHER_PRODUCTS_CAPTURE_UNAVAILABLE
        content_provider_start_control_observer "$weather_product_prefix-control" || fail WEATHER_PRODUCTS_CONTROL_UNAVAILABLE
        weather_command_limit=$(weather_products_remaining 200) || fail WEATHER_PRODUCTS_DEADLINE
        timeout --signal=TERM --kill-after=30s "${weather_command_limit}s" ip netns exec "$CLIENT" setpriv \
            --reuid="$WORKER_UID" --regid="$site_control_gid" --clear-groups \
            --inh-caps=-all --ambient-caps=-all --bounding-set=-all --no-new-privs \
            -- python3 -B "$WORK/bin/weather-products-delivery.py" cold "$weather_product" \
            "$binary_directory/volparossa" "$WORK/runtime-client/control/agent.sock" "$weather_product_cache" "$weather_viewer" \
            "$site_parent_ns" "$site_client_ns" "$site_control_gid" \
            >"$WORK/$weather_product_prefix-cold-consumer.json" 2>"$WORK/$weather_product_prefix-cold.err" \
            || fail WEATHER_PRODUCTS_COLD_FAILED
        benchmark_capture_paths "$weather_product_prefix" mptcp || fail WEATHER_PRODUCTS_PATHS_UNAVAILABLE
        stop_privacy_observers || fail WEATHER_PRODUCTS_CAPTURE_INCOMPLETE
        content_provider_stop_control_observer || fail WEATHER_PRODUCTS_CONTROL_INCOMPLETE
        python3 -B "$WORK/bin/weather-products-delivery.py" cache-state "$weather_product" \
            "$weather_product_cache" "$AGENT_UID" "$AGENT_GID" >"$WORK/$weather_product_prefix-cache-before.json" \
            || fail WEATHER_PRODUCTS_CACHE_INVALID
    done
    PHASE=weather-products-delivery-cold-verify
    python3 -B "$WORK/bin/weather-products-delivery.py" cache-summary "$WORK" before \
        >"$WORK/weather-products-delivery-cache-before.json" || fail WEATHER_PRODUCTS_CACHE_INVALID
    python3 -B "$WORK/bin/weather-products-delivery.py" cold-evidence "$WORK" "$weather_client_manifest_sha256" \
        "$weather_core_sha256" >"$WORK/weather-products-delivery-cold-evidence.json" || fail WEATHER_PRODUCTS_COLD_EVIDENCE_INVALID
    python3 -B "$WORK/bin/weather-products-delivery.py" copy-cold-evidence "$WORK" \
        "$output_directory" "$OUTPUT_UID" "$OUTPUT_GID" >/dev/null || fail WEATHER_PRODUCTS_COLD_RETENTION_FAILED
    weather_command_limit=$(weather_products_remaining 40) || fail WEATHER_PRODUCTS_DEADLINE
    timeout --signal=TERM --kill-after=30s "${weather_command_limit}s" setpriv \
        --reuid="$WORKER_UID" --regid="$site_control_gid" --clear-groups \
        --inh-caps=-all --ambient-caps=-all --bounding-set=-all --no-new-privs \
        -- python3 -B "$WORK/bin/weather-products-delivery.py" prepare "$weather_client_directory" "$weather_viewer" \
        "$binary_directory/volparossa" "$WORK/runtime-client/control/agent.sock" "$WORK/state-client/weather-cache" \
        "$WORK/state-client/air-quality-cache" "$weather_profile_version" \
        >"$WORK/weather-products-delivery-prepared.json" || fail WEATHER_PRODUCTS_EXPECTED_FAILED
    PHASE=weather-products-delivery-browser
    weather_browser_status=0
    # Historical drivers keep their original CLI; only the new, explicit
    # Overmorrow profile accepts this fixed version selector.
    set --
    if [ "$weather_profile_version" = 5 ]; then set -- --bundle-version 5; fi
    weather_command_limit=$(weather_products_remaining 270) || fail WEATHER_PRODUCTS_DEADLINE
    timeout --signal=TERM --kill-after=30s "${weather_command_limit}s" ip netns exec "$CLIENT" setpriv \
        --reuid="$WORKER_UID" --regid="$site_control_gid" --clear-groups \
        --inh-caps=-all --ambient-caps=-all --bounding-set=-all --no-new-privs \
        -- env -i PATH=/usr/bin:/bin LANG=C.UTF-8 LC_ALL=C.UTF-8 PYTHONDONTWRITEBYTECODE=1 \
        python3 -B "$weather_client_directory/volparossa-weather/$weather_products_driver" \
        --execute --bundle-root "$weather_client_directory" --bundle-manifest-sha256 "$weather_client_manifest_sha256" \
        --config "$weather_viewer/config.json" --expected "$weather_viewer/expected.json" \
        --output "$weather_viewer/browser-output" --parent-netns "$site_parent_ns" --client-netns "$site_client_ns" \
        --control-gid "$site_control_gid" "$@" >"$WORK/weather-products-delivery-launch.json" \
        2>"$WORK/weather-products-delivery-browser.err" || weather_browser_status=$?
    PHASE=weather-products-delivery-verify
    python3 -B "$WORK/bin/weather-products-delivery.py" retain "$WORK" \
        >"$WORK/weather-products-delivery-retained.json" || fail WEATHER_PRODUCTS_RECEIPT_RETENTION_FAILED
    weather_client_delivery_cleanup || fail WEATHER_PRODUCTS_INPUT_CLEANUP_FAILED
    [ "$weather_browser_status" -eq 0 ] || fail WEATHER_PRODUCTS_BROWSER_FAILED
    weather_client_verify_tree >"$WORK/weather-products-delivery-tree-after.json" || fail WEATHER_PRODUCTS_SOURCE_CHANGED
    for weather_kind in weather air_quality; do
        weather_products_select "$weather_kind" || fail WEATHER_PRODUCTS_KIND_INVALID
        python3 -B "$WORK/bin/weather-products-delivery.py" cache-state "$weather_product" \
            "$weather_product_cache" "$AGENT_UID" "$AGENT_GID" >"$WORK/$weather_product_prefix-cache-after.json" \
            || fail WEATHER_PRODUCTS_CACHE_INVALID
        if setpriv --reuid="$WORKER_UID" --regid="$site_control_gid" --clear-groups \
            --inh-caps=-all --ambient-caps=-all --bounding-set=-all --no-new-privs \
            -- test -r "$weather_product_cache"; then fail WEATHER_PRODUCTS_AGENT_CACHE_EXPOSED; fi
    done
    python3 -B "$WORK/bin/weather-products-delivery.py" cache-summary "$WORK" after \
        >"$WORK/weather-products-delivery-cache-after.json" || fail WEATHER_PRODUCTS_CACHE_INVALID
    python3 -B "$WORK/bin/weather-products-delivery.py" evidence "$WORK" "$weather_client_manifest_sha256" \
        "$weather_core_sha256" >"$WORK/weather-products-delivery-evidence.json" || fail WEATHER_PRODUCTS_EVIDENCE_INVALID
    PHASE=weather-products-delivery-complete
}
