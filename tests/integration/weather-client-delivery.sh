#!/bin/sh
# SPDX-License-Identifier: GPL-3.0-only
# Explicit optional joined acquisition -> protected cold fetch -> native Weather UI.
# Sourced only by the disposable KVM topology; no host browser or network setup.
# shellcheck disable=SC2154,SC2034

# Ownership is established by this invocation, never inherited from a caller.
WEATHER_CLIENT_HOME_CREATED=no
WEATHER_CLIENT_HOME_IDENTITY=
WEATHER_AGENT_PROFILE_VERSION=
WEATHER_ANDROID_CACHE_IDENTITY=

weather_client_private() {
    setpriv --reuid="$WORKER_UID" --regid="$site_control_gid" --clear-groups \
        --inh-caps=-all --ambient-caps=-all --bounding-set=-all --no-new-privs \
        -- python3 -B "$WORK/bin/weather-client-delivery.py" "$@"
}

weather_client_cli() {
    weather_socket_node=$1
    shift
    timeout --signal=TERM --kill-after=5s 120s setpriv \
        --reuid="$WORKER_UID" --regid="$site_control_gid" --clear-groups \
        --inh-caps=-all --ambient-caps=-all --bounding-set=-all --no-new-privs \
        -- "$binary_directory/volparossa" \
        --control-socket "$WORK/runtime-$weather_socket_node/control/agent.sock" "$@"
}

weather_client_home_prepare() {
    # The browser maps its isolated home to the account's real passwd home.
    # Never replace HOME, change an existing home, or create this on the host.
    [ "$(id -u)" -eq 0 ] && [ "$(systemd-detect-virt)" = kvm ] \
        && [ "$(sed -n '1p' /proc/1/comm)" = systemd ] || return 1
    [ "$WORKER_UID" = 985 ] \
        && [ "$(getent passwd 985 | cut -d: -f6)" = /nonexistent ] || return 1
    [ ! -L /nonexistent ] || return 1
    if [ ! -e /nonexistent ]; then
        mkdir -m 0755 -- /nonexistent || return 1
        WEATHER_CLIENT_HOME_CREATED=yes
        WEATHER_CLIENT_HOME_IDENTITY=$(stat -Lc '%d:%i' /nonexistent) || return 1
    fi
    [ -d /nonexistent ] && [ "$(readlink -e -- /nonexistent)" = /nonexistent ] \
        && [ "$(stat -Lc '%u:%g:%a' /nonexistent)" = 0:0:755 ] || return 1
    weather_home_entry=$(find /nonexistent -mindepth 1 -maxdepth 1 -print -quit) || return 1
    [ -z "$weather_home_entry" ]
}

weather_client_home_cleanup() {
    [ "${WEATHER_CLIENT_HOME_CREATED:-no}" = yes ] || return 0
    [ "$(id -u)" -eq 0 ] && [ "$(systemd-detect-virt)" = kvm ] || return 1
    [ -n "${WEATHER_CLIENT_HOME_IDENTITY:-}" ] && [ ! -L /nonexistent ] \
        && [ -d /nonexistent ] && [ "$(readlink -e -- /nonexistent)" = /nonexistent ] \
        && [ "$(stat -Lc '%u:%g:%a' /nonexistent)" = 0:0:755 ] \
        && [ "$(stat -Lc '%d:%i' /nonexistent)" = "$WEATHER_CLIENT_HOME_IDENTITY" ] || return 1
    # rmdir refuses a nonempty/replaced directory; never recursively remove it.
    rmdir -- /nonexistent || return 1
    WEATHER_CLIENT_HOME_CREATED=no
    WEATHER_CLIENT_HOME_IDENTITY=
}

weather_client_delivery_cleanup() {
    weather_cleanup_status=0
    if [ -f "$WORK/bin/weather-client-delivery.py" ] && [ -n "${site_control_gid:-}" ]; then
        # An interruption may enter the topology trap before the normal retain
        # step. Preserve only the strictly validated closed report, never logs.
        if [ ! -e "$WORK/weather-client-delivery-original-report.json" ] \
            && [ ! -L "$WORK/weather-client-delivery-original-report.json" ]; then
            if [ -e "$WORK/client-fixtures/weather-viewer/browser-output/report.json" ] \
                || [ -L "$WORK/client-fixtures/weather-viewer/browser-output/report.json" ]; then
                python3 -B "$WORK/bin/weather-client-delivery.py" retain "$WORK" \
                    >"$WORK/weather-client-delivery-retained.json" || weather_cleanup_status=1
            fi
        fi
        weather_client_private publisher-cleanup "$WORK/client-fixtures/weather-publisher" \
            >"$WORK/weather-client-delivery-publisher-cleanup.json" || weather_cleanup_status=1
        weather_client_private user-cleanup "$WORK/client-fixtures/weather-viewer" \
            >"$WORK/weather-client-delivery-input-cleanup.json" || weather_cleanup_status=1
    fi
    # Independent attempts: a failed user cleanup must not skip the owned home.
    weather_client_home_cleanup || weather_cleanup_status=1
    return "$weather_cleanup_status"
}

weather_client_delivery_copy_artifacts() {
    [ -f "$WORK/bin/weather-client-delivery.py" ] || return 0
    python3 -B "$WORK/bin/weather-client-delivery.py" copy-artifacts "$WORK" \
        "$output_directory" "$OUTPUT_UID" "$OUTPUT_GID" >/dev/null
}

weather_client_verify_tree() {
    setpriv --reuid="$WORKER_UID" --regid="$site_control_gid" --clear-groups \
        --inh-caps=-all --ambient-caps=-all --bounding-set=-all --no-new-privs \
        -- python3 -B "$WORK/bin/weather-client-bundle.py" verify-tree \
        "$weather_client_directory" "$weather_client_manifest_sha256"
}

weather_client_runtime_profile() {
    # Match the topology preflight: the guest input may still belong to vpci.
    # Root readability is not parser ownership; do not relax its owner check or
    # retry a failed unprivileged validation with broader authority.
    weather_profile_uid=$(stat -Lc '%u' "$weather_client_bundle") || return 1
    if [ "$weather_profile_uid" -eq 0 ]; then
        python3 -B "$source_directory/tests/integration/weather-client-bundle.py" \
            runtime-version "$weather_client_bundle" "$weather_client_manifest_sha256"
    elif weather_profile_vpci_uid=$(id -u vpci) \
        && [ "$weather_profile_uid" -eq "$weather_profile_vpci_uid" ]; then
        runuser -u vpci -- python3 -B "$source_directory/tests/integration/weather-client-bundle.py" \
            runtime-version "$weather_client_bundle" "$weather_client_manifest_sha256"
    else
        return 1
    fi
}

weather_client_agent_cache_prepare() {
    # Agent mount permissions are fixed at service start, before publication and
    # the later app dispatcher. Select from the fully checked archive, not from
    # an inherited profile variable. Empty staging is not a product prefetch.
    weather_agent_profile=$(weather_client_runtime_profile) || return 1
    WEATHER_AGENT_PROFILE_VERSION=$(printf '%s\n' "$weather_agent_profile" | \
        jq -er '.bundle_version | select(type == "number" and (. == 1 or . == 2 or . == 3 or . == 4 or . == 5 or . == 6))') \
        || return 1
    [ "$WEATHER_AGENT_PROFILE_VERSION" = 6 ] || return 0
    [ "$(id -u)" -eq 0 ] && [ "$(systemd-detect-virt)" = kvm ] \
        && [ "$WORKER_UID" = 985 ] && [ "$AGENT_UID" != "$WORKER_UID" ] || return 1
    weather_agent_control_gid=$(getent group volparossa-users | cut -d: -f3) || return 1
    case $weather_agent_control_gid in ''|*[!0-9]*) return 1 ;; esac
    [ "$weather_agent_control_gid" -gt 0 ] && [ "$weather_agent_control_gid" -le 65535 ] \
        && [ "$weather_agent_control_gid" != "$AGENT_GID" ] || return 1
    weather_agent_cache=$WORK/weather-android-cache
    [ ! -e "$weather_agent_cache" ] && [ ! -L "$weather_agent_cache" ] || return 1
    install -d -o "$AGENT_UID" -g "$weather_agent_control_gid" -m 0710 "$weather_agent_cache" || return 1
    WEATHER_ANDROID_CACHE_IDENTITY=$(stat -Lc '%d:%i:%u:%g:%a' "$weather_agent_cache") || return 1
    [ "$(stat -Lc '%u:%g:%a' "$weather_agent_cache")" = "$AGENT_UID:$weather_agent_control_gid:710" ]
}

weather_client_delivery_run() {
    PHASE=weather-client-delivery-profile
    if [ -z "${weather_client_bundle:-}" ] || [ -z "${weather_client_manifest_sha256:-}" ]; then
        fail WEATHER_CLIENT_INPUTS_MISSING
    fi
    # Select only after the complete immutable archive has been validated. The
    # legacy profile must keep its original driver and evidence contract.
    weather_profile=$(weather_client_runtime_profile) || fail WEATHER_CLIENT_PROFILE_INVALID
    weather_profile_version=$(printf '%s\n' "$weather_profile" | \
        jq -er '.bundle_version | select(type == "number" and (. == 1 or . == 2 or . == 3 or . == 4 or . == 5 or . == 6))') \
        || fail WEATHER_CLIENT_PROFILE_INVALID
    case $weather_profile_version in
        1) ;;
        2|3|4|5|6)
            . "$source_directory/tests/integration/weather-products-delivery.sh"
            weather_products_delivery_run
            return ;;
        *) fail WEATHER_CLIENT_PROFILE_INVALID ;;
    esac
    PHASE=weather-client-delivery-prepare
    printf '%s\n' 'Weather trial: stage verified inputs under disposable WORK; acquire one explicit public ECMWF forecast in the guest parent namespace; publish to two existing peers; cold-fetch through the protected Client route, then render and refresh the same bytes in an isolated browser. Create the empty root-owned /nonexistent only if absent in this KVM guest; remove only that owned empty directory. No HOME override or private cache permission change.'
    if [ "$WORKER_UID" != 985 ] || [ "$site_control_gid" = "$AGENT_GID" ]; then
        fail WEATHER_CLIENT_USER_INVALID
    fi
    weather_client_directory=$WORK/client-fixtures/weather-client-source
    weather_publisher=$WORK/client-fixtures/weather-publisher
    weather_viewer=$WORK/client-fixtures/weather-viewer
    weather_cache=$WORK/state-client/weather-cache
    for weather_new in "$weather_client_directory" "$weather_publisher" "$weather_viewer" "$weather_cache" \
        "$WORK/state-$provider_node_a/weather-cache" "$WORK/state-$provider_node_b/weather-cache"; do
        if [ -e "$weather_new" ] || [ -L "$weather_new" ]; then fail WEATHER_CLIENT_PATH_EXISTS; fi
    done
    for weather_script in weather-client-delivery.py weather-client-bundle.py browser-filter-bundle.py \
        content-provider-https-smoke.py content-network-smoke.py; do
        install -o root -g root -m 0555 "$source_directory/tests/integration/$weather_script" \
            "$WORK/bin/$weather_script" || fail WEATHER_CLIENT_DRIVER_UNAVAILABLE
    done
    install -o root -g root -m 0600 "$weather_client_bundle" "$WORK/weather-client-inputs.tar" \
        || fail WEATHER_CLIENT_ARCHIVE_COPY_FAILED
    python3 -B "$WORK/bin/weather-client-bundle.py" unpack "$WORK/weather-client-inputs.tar" \
        "$weather_client_directory" "$weather_client_manifest_sha256" \
        >"$WORK/weather-client-delivery-unpack.json" || fail WEATHER_CLIENT_UNPACK_FAILED
    # Preserve proof metadata under root ownership before handing this validated
    # new source tree to the worker. No existing user/agent state is chowned.
    install -o root -g root -m 0400 "$weather_client_directory/INPUTS.json" \
        "$WORK/weather-client-delivery-manifest.json" || fail WEATHER_CLIENT_MANIFEST_RETENTION_FAILED
    chown -R "$WORKER_UID:$site_control_gid" "$weather_client_directory" || fail WEATHER_CLIENT_OWNER_FAILED
    install -d -o "$WORKER_UID" -g "$site_control_gid" -m 0700 "$weather_publisher" "$weather_viewer" \
        || fail WEATHER_CLIENT_PRIVATE_DIRECTORY_FAILED
    weather_client_verify_tree >"$WORK/weather-client-delivery-tree-before.json" \
        || fail WEATHER_CLIENT_SOURCE_CHANGED
    weather_client_home_prepare || fail WEATHER_CLIENT_HOME_UNSAFE
    weather_core_sha256=$(sha256sum "$binary_directory/volparossa" | awk '{print $1}')
    weather_client_private init "$weather_publisher" >"$WORK/weather-client-delivery-assets.json" \
        || fail WEATHER_CLIENT_INPUT_FAILED
    PHASE=weather-client-delivery-acquire
    timeout --signal=TERM --kill-after=10s 400s setpriv \
        --reuid="$WORKER_UID" --regid="$site_control_gid" --clear-groups \
        --inh-caps=-all --ambient-caps=-all --bounding-set=-all --no-new-privs \
        -- python3 -B "$WORK/bin/weather-client-delivery.py" acquire \
        "$weather_client_directory" "$weather_client_manifest_sha256" "$weather_publisher" \
        "$site_parent_ns" "$site_client_ns" "$site_control_gid" \
        >"$WORK/weather-client-delivery-acquisition.json" 2>"$WORK/weather-client-delivery-acquisition.err" \
        || fail WEATHER_CLIENT_ACQUISITION_FAILED
    PHASE=weather-client-delivery-publish
    weather_client_cli "$provider_node_a" init --identity "$weather_publisher/identity.key" \
        --passphrase-file "$weather_publisher/passphrase" >"$WORK/weather-client-delivery-init.log" \
        2>"$WORK/weather-client-delivery-init.err" || fail WEATHER_CLIENT_IDENTITY_FAILED
    weather_client_cli "$provider_node_a" content publish --input "$weather_publisher/forecast.json" \
        --name disposable-public-community-weather --revision 1 --content-type application/json \
        --lifetime-seconds 900 --identity "$weather_publisher/identity.key" \
        --passphrase-file "$weather_publisher/passphrase" --cache "$weather_publisher/source-cache" \
        --manifest "$weather_publisher/manifest.bin" >"$WORK/weather-client-delivery-publish.json" \
        2>"$WORK/weather-client-delivery-publish.err" || fail WEATHER_CLIENT_PUBLISH_FAILED
    weather_key=$(jq -er '.publisher_key_hex | select(test("^[0-9a-f]{64}$"))' \
        "$WORK/weather-client-delivery-publish.json") || fail WEATHER_CLIENT_PUBLISHER_INVALID
    if [ "$weather_key" = "$provider_publisher" ] || [ "$weather_key" = "$site_key" ] \
        || [ "$weather_key" = "$filter_key" ]; then fail WEATHER_CLIENT_PUBLISHER_REUSED; fi
    install -o "$WORKER_UID" -g "$site_control_gid" -m 0400 "$WORK/weather-client-delivery-publish.json" \
        "$weather_publisher/publish-receipt.json" || fail WEATHER_CLIENT_PUBLISH_RECEIPT_UNAVAILABLE
    weather_client_private select "$weather_publisher" "$weather_publisher/publish-receipt.json" "$weather_viewer" \
        >"$WORK/weather-client-delivery-input.json" || fail WEATHER_CLIENT_SELECTION_FAILED
    PHASE=weather-client-delivery-register
    for weather_node in "$provider_node_a" "$provider_node_b"; do
        case $weather_node in
            relay4) weather_address=49.165.5.1; weather_hostname=provider-a.volparossa.test ;;
            relay5) weather_address=50.166.6.1; weather_hostname=provider-b.volparossa.test ;;
            relay3) weather_address=48.164.4.1; weather_hostname=provider-c.volparossa.test ;;
            *) fail WEATHER_CLIENT_PROVIDER_INVALID ;;
        esac
        weather_client_cli "$weather_node" content import --public-content \
            --manifest "$weather_publisher/manifest.bin" --publisher-key "$weather_key" \
            --cache "$weather_publisher/source-cache" --agent-cache "$WORK/state-$weather_node/weather-cache" \
            >"$WORK/weather-client-delivery-$weather_node-import.json" \
            2>"$WORK/weather-client-delivery-$weather_node-import.err" || fail WEATHER_CLIENT_IMPORT_FAILED
        weather_client_cli "$weather_node" content serve --name-lookup \
            --manifest "$weather_publisher/manifest.bin" --publisher-key "$weather_key" \
            --cache "$WORK/state-$weather_node/weather-cache" --bind "$weather_address:18080" \
            --advertised-hostname "$weather_hostname" >"$WORK/weather-client-delivery-$weather_node-serve.json" \
            2>"$WORK/weather-client-delivery-$weather_node-serve.err" || fail WEATHER_CLIENT_SERVE_FAILED
        jq -e '.serving == true and .publications == 4 and .replication_enabled == false' \
            "$WORK/weather-client-delivery-$weather_node-serve.json" >/dev/null || fail WEATHER_CLIENT_NOT_READY
        if [ -L "$WORK/state-$weather_node/weather-cache" ] \
            || [ "$(stat -Lc '%a:%u:%g' "$WORK/state-$weather_node/weather-cache")" != "700:$AGENT_UID:$AGENT_GID" ]; then
            fail WEATHER_CLIENT_PROVIDER_CACHE_CHANGED
        fi
        if nsenter --target "$provider_client_pid" --mount \
            setpriv --reuid="$AGENT_UID" --regid="$AGENT_GID" --clear-groups \
            --inh-caps=-all --ambient-caps=-all --bounding-set=-all --no-new-privs \
            -- test -r "$WORK/state-$weather_node/weather-cache"; then fail WEATHER_CLIENT_LOCAL_SHORTCUT; fi
        if setpriv --reuid="$WORKER_UID" --regid="$site_control_gid" --clear-groups \
            --inh-caps=-all --ambient-caps=-all --bounding-set=-all --no-new-privs \
            -- test -r "$WORK/state-$weather_node/weather-cache"; then fail WEATHER_CLIENT_AGENT_CACHE_EXPOSED; fi
    done
    nsenter --target "$provider_client_pid" --mount \
        setpriv --reuid="$AGENT_UID" --regid="$AGENT_GID" --clear-groups \
        --inh-caps=-all --ambient-caps=-all --bounding-set=-all --no-new-privs \
        -- test -r "$WORK/state-client/identity.key" || fail WEATHER_CLIENT_ISOLATION_PROBE_FAILED
    if nsenter --target "$provider_client_pid" --mount \
        setpriv --reuid="$AGENT_UID" --regid="$AGENT_GID" --clear-groups \
        --inh-caps=-all --ambient-caps=-all --bounding-set=-all --no-new-privs \
        -- test -r "$weather_viewer"; then fail WEATHER_CLIENT_USER_STATE_EXPOSED; fi
    # All publisher commands exited. Remove the identity, original forecast,
    # manifest and source chunks before an independent Client resolves the name.
    weather_client_private publisher-cleanup "$weather_publisher" \
        >"$WORK/weather-client-delivery-publisher-cleanup.json" || fail WEATHER_CLIENT_PUBLISHER_CLEANUP_FAILED
    if [ -e "$weather_publisher" ] || [ -L "$weather_publisher" ]; then
        fail WEATHER_CLIENT_PUBLISHER_FILES_REMAIN
    fi
    PHASE=weather-client-delivery-cold
    start_privacy_observers weather-client-delivery-privacy || fail WEATHER_CLIENT_CAPTURE_UNAVAILABLE
    content_provider_start_control_observer weather-client-delivery-control || fail WEATHER_CLIENT_CONTROL_UNAVAILABLE
    timeout --signal=TERM --kill-after=10s 200s ip netns exec "$CLIENT" setpriv \
        --reuid="$WORKER_UID" --regid="$site_control_gid" --clear-groups \
        --inh-caps=-all --ambient-caps=-all --bounding-set=-all --no-new-privs \
        -- python3 -B "$WORK/bin/weather-client-delivery.py" cold "$binary_directory/volparossa" \
        "$WORK/runtime-client/control/agent.sock" "$weather_cache" "$weather_viewer" \
        "$site_parent_ns" "$site_client_ns" "$site_control_gid" \
        >"$WORK/weather-client-delivery-cold-consumer.json" 2>"$WORK/weather-client-delivery-cold.err" \
        || fail WEATHER_CLIENT_COLD_FAILED
    benchmark_capture_paths weather-client-delivery mptcp || fail WEATHER_CLIENT_PATHS_UNAVAILABLE
    stop_privacy_observers || fail WEATHER_CLIENT_CAPTURE_INCOMPLETE
    content_provider_stop_control_observer || fail WEATHER_CLIENT_CONTROL_INCOMPLETE
    python3 -B "$WORK/bin/weather-client-delivery.py" cache-state "$weather_cache" "$AGENT_UID" "$AGENT_GID" \
        >"$WORK/weather-client-delivery-cache-before.json" || fail WEATHER_CLIENT_CACHE_INVALID
    # Preserve the fully validated cold transport separately before any browser
    # preparation or execution. Later UI failure must not erase this evidence,
    # and this record explicitly makes no UI or end-to-end success claim.
    PHASE=weather-client-delivery-cold-verify
    python3 -B "$WORK/bin/weather-client-delivery.py" cold-evidence "$WORK" "$weather_client_manifest_sha256" \
        "$weather_core_sha256" >"$WORK/weather-client-delivery-cold-evidence.json" \
        || fail WEATHER_CLIENT_COLD_EVIDENCE_INVALID
    python3 -B "$WORK/bin/weather-client-delivery.py" copy-cold-evidence "$WORK" \
        "$output_directory" "$OUTPUT_UID" "$OUTPUT_GID" >/dev/null \
        || fail WEATHER_CLIENT_COLD_RETENTION_FAILED
    weather_client_private prepare "$weather_client_directory" "$weather_viewer" \
        "$binary_directory/volparossa" "$WORK/runtime-client/control/agent.sock" "$weather_cache" \
        >"$WORK/weather-client-delivery-prepared.json" || fail WEATHER_CLIENT_EXPECTED_FAILED
    PHASE=weather-client-delivery-browser
    weather_browser_status=0
    timeout --signal=TERM --kill-after=10s 270s ip netns exec "$CLIENT" setpriv \
        --reuid="$WORKER_UID" --regid="$site_control_gid" --clear-groups \
        --inh-caps=-all --ambient-caps=-all --bounding-set=-all --no-new-privs \
        -- env -i PATH=/usr/bin:/bin LANG=C.UTF-8 LC_ALL=C.UTF-8 PYTHONDONTWRITEBYTECODE=1 \
        python3 -B "$weather_client_directory/volparossa-weather/integrations/drizzli/smoke_core_browser.py" \
        --execute --bundle-root "$weather_client_directory" --bundle-manifest-sha256 "$weather_client_manifest_sha256" \
        --config "$weather_viewer/config.json" --expected "$weather_viewer/expected.json" \
        --output "$weather_viewer/browser-output" --parent-netns "$site_parent_ns" --client-netns "$site_client_ns" \
        --control-gid "$site_control_gid" >"$WORK/weather-client-delivery-launch.json" \
        2>"$WORK/weather-client-delivery-browser.err" || weather_browser_status=$?
    PHASE=weather-client-delivery-verify
    python3 -B "$WORK/bin/weather-client-delivery.py" retain "$WORK" \
        >"$WORK/weather-client-delivery-retained.json" || fail WEATHER_CLIENT_RECEIPT_RETENTION_FAILED
    weather_client_delivery_cleanup || fail WEATHER_CLIENT_INPUT_CLEANUP_FAILED
    [ "$weather_browser_status" -eq 0 ] || fail WEATHER_CLIENT_BROWSER_FAILED
    weather_client_verify_tree >"$WORK/weather-client-delivery-tree-after.json" \
        || fail WEATHER_CLIENT_SOURCE_CHANGED
    python3 -B "$WORK/bin/weather-client-delivery.py" cache-state "$weather_cache" "$AGENT_UID" "$AGENT_GID" \
        >"$WORK/weather-client-delivery-cache-after.json" || fail WEATHER_CLIENT_CACHE_INVALID
    if setpriv --reuid="$WORKER_UID" --regid="$site_control_gid" --clear-groups \
        --inh-caps=-all --ambient-caps=-all --bounding-set=-all --no-new-privs \
        -- test -r "$weather_cache"; then fail WEATHER_CLIENT_AGENT_CACHE_EXPOSED; fi
    python3 -B "$WORK/bin/weather-client-delivery.py" evidence "$WORK" "$weather_client_manifest_sha256" \
        "$weather_core_sha256" >"$WORK/weather-client-delivery-evidence.json" || fail WEATHER_CLIENT_EVIDENCE_INVALID
    PHASE=weather-client-delivery-complete
}
