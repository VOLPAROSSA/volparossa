#!/bin/sh
# SPDX-License-Identifier: GPL-3.0-only
# Stage one real helper worker-identity proof inside a disposable systemd service.
set -eu

export LC_ALL=C
PATH=/usr/sbin:/usr/bin:/sbin:/bin
export PATH
umask 077

mode=preview
approval=no
seen_mode=no
seen_approval=no

usage() {
    printf '%s\n' \
        'usage: tests/helper/require-live-worker-identity-proof.sh [--preview|--execute] [--yes]' \
        '' \
        'Preview is the non-writing default. Execution requires --execute --yes as root' \
        'inside a disposable Debian 13 amd64 virtual machine running systemd.'
}

print_plan() {
    printf '%s\n' \
        'VOLPAROSSA live worker-identity proof plan:' \
        '  require a disposable Debian 13 amd64 VM, root, and the system systemd manager;' \
        '  copy the already-built real helper into one validated root-only temporary stage;' \
        '  create synthetic, collision-free agent/worker/group records only inside that stage;' \
        '  bind passwd, group, shadow, and nsswitch read-only inside one transient service;' \
        '  run with PrivateNetwork=yes, a private temporary /run, and no host account changes;' \
        '  grant exactly CAP_KILL, CAP_NET_ADMIN, CAP_NET_RAW, CAP_SETGID, CAP_SETPCAP,' \
        '    CAP_SETUID, and CAP_SYS_ADMIN to the helper parent;' \
        '  require its kernel supplementary-group vector to contain only the staged agent GID;' \
        '  invoke only --internal-worker-v3-live-proof and require its exact success record;' \
        '  stop and collect the transient unit, remove the stage, and compare privacy-safe' \
        '    before/after host account, resolver, mount, firewall, WireGuard, and network digests.' \
        'This stages only the helper identity component. It creates no host account, link,' \
        'route, firewall rule, WireGuard device, DNS change, sysctl change, or VPN datapath.'
}

while [ "$#" -gt 0 ]; do
    case $1 in
        --preview)
            [ "$seen_mode" = no ] || { usage >&2; exit 64; }
            mode=preview
            seen_mode=yes
            ;;
        --execute)
            [ "$seen_mode" = no ] || { usage >&2; exit 64; }
            mode=execute
            seen_mode=yes
            ;;
        --yes)
            [ "$seen_approval" = no ] || { usage >&2; exit 64; }
            approval=yes
            seen_approval=yes
            ;;
        -h|--help)
            usage
            exit 0
            ;;
        *)
            usage >&2
            exit 64
            ;;
    esac
    shift
done

if [ "$mode" = preview ]; then
    if [ "$approval" = yes ]; then
        printf '%s\n' '--yes is valid only with --execute' >&2
        exit 64
    fi
    print_plan
    printf '%s\n' 'PREVIEW ONLY: no file, account, service, or network state was changed.'
    exit 0
fi

if [ "$approval" != yes ]; then
    print_plan >&2
    printf '%s\n' 'Execution requires --yes after reviewing the exact plan.' >&2
    exit 64
fi

print_plan

blocked() {
    printf 'BLOCKED: %s\n' "$1" >&2
    exit 77
}

failed() {
    printf 'live worker-identity proof failed: %s\n' "$1" >&2
    exit 1
}

if [ "$(id -u)" -ne 0 ]; then
    blocked 'execution requires root inside the disposable VM'
fi
if [ ! -r /etc/os-release ]; then
    blocked 'operating-system identity is unavailable'
fi
os_id=$(sed -n 's/^ID=//p' /etc/os-release)
os_version_id=$(sed -n 's/^VERSION_ID=//p' /etc/os-release)
if [ "$os_id" != debian ] \
    || { [ "$os_version_id" != 13 ] && [ "$os_version_id" != '"13"' ]; }; then
    blocked 'execution requires Debian 13'
fi
if ! command -v dpkg >/dev/null 2>&1 \
    || [ "$(dpkg --print-architecture)" != amd64 ] \
    || [ "$(uname -m)" != x86_64 ]; then
    blocked 'execution requires Debian 13 amd64 on x86_64'
fi
if [ ! -d /run/systemd/system ] || [ ! -r /proc/1/comm ] \
    || [ "$(sed -n '1p' /proc/1/comm)" != systemd ]; then
    blocked 'PID 1 is not the system systemd manager'
fi
if systemd-detect-virt --container --quiet; then
    blocked 'containers cannot provide the required disposable-host evidence'
fi
if ! systemd-detect-virt --vm --quiet; then
    blocked 'execution is restricted to a recognised disposable virtual machine'
fi

for command_name in \
    awk chmod chown cmp cp dpkg find getent id install ip jq mkfifo mktemp nft paste readlink rm sed \
    sha256sum sort stat systemctl systemd-detect-virt systemd-run tc tr uname
do
    if ! command -v "$command_name" >/dev/null 2>&1; then
        blocked "required Debian tool is unavailable: $command_name"
    fi
done
manager_state=$(systemctl is-system-running 2>/dev/null || true)
case $manager_state in
    running|degraded) ;;
    *) blocked 'the system systemd manager is not operational' ;;
esac

script_directory=$(CDPATH='' cd -- "$(dirname -- "$0")" && pwd)
repository_directory=$(CDPATH='' cd -- "$script_directory/../.." && pwd)
VP_CAPTURE_OWNER_UID=0
VP_CAPTURE_OWNER_GID=0
export VP_CAPTURE_OWNER_UID VP_CAPTURE_OWNER_GID
# shellcheck source=tests/helper/lib/live-worker-proof-capture.sh
. "$script_directory/lib/live-worker-proof-capture.sh"
helper_source=$repository_directory/target/debug/volparossa-helper
if [ ! -f "$helper_source" ] || [ ! -x "$helper_source" ] || [ -L "$helper_source" ]; then
    blocked 'build target/debug/volparossa-helper as an unprivileged workspace user first'
fi
if [ "$(stat -Lc '%F:%h' "$helper_source")" != 'regular file:1' ]; then
    blocked 'the helper source must be one executable regular file with one hard link'
fi

if [ "$(stat -c '%F:%u:%g:%a' /var/tmp)" != 'directory:0:0:1777' ]; then
    blocked '/var/tmp is not the canonical root-owned sticky staging parent'
fi

temporary_stage=
temporary_stage_identity=
unit_name=
cleanup_error=no

unit_load_state() {
    systemctl show --property=LoadState --value "$unit_name" 2>/dev/null || printf '%s\n' unknown
}

retire_unit() {
    [ -n "$unit_name" ] || return 0
    if [ "$(unit_load_state)" != not-found ]; then
        if ! systemctl stop "$unit_name" >/dev/null 2>&1; then
            systemctl kill --kill-who=all --signal=SIGKILL "$unit_name" >/dev/null 2>&1 || true
            systemctl stop "$unit_name" >/dev/null 2>&1 || return 1
        fi
        systemctl reset-failed "$unit_name" >/dev/null 2>&1 || true
    fi
    attempt=0
    while [ "$(unit_load_state)" != not-found ]; do
        attempt=$((attempt + 1))
        [ "$attempt" -le 100 ] || return 1
        sleep 0.05
    done
}

cleanup() {
    saved_status=$?
    trap - EXIT HUP INT TERM
    if ! retire_unit; then
        cleanup_error=yes
    fi
    if [ -n "$temporary_stage" ]; then
        case $temporary_stage in
            /var/tmp/volparossa-helper-live-proof.??????)
                observed_identity=$(stat -Lc '%d:%i:%F:%u:%g:%a' "$temporary_stage" 2>/dev/null || true)
                if [ "$observed_identity" = "$temporary_stage_identity" ]; then
                    rm -rf --one-file-system -- "$temporary_stage" || cleanup_error=yes
                elif [ -e "$temporary_stage" ]; then
                    printf 'Refusing to remove replaced proof stage: %s\n' "$temporary_stage" >&2
                    cleanup_error=yes
                fi
                ;;
            *)
                printf 'Refusing to remove unsafe proof stage: %s\n' "$temporary_stage" >&2
                cleanup_error=yes
                ;;
        esac
    fi
    if [ "$cleanup_error" = yes ] && [ "$saved_status" -eq 0 ]; then
        saved_status=1
    fi
    exit "$saved_status"
}
trap cleanup EXIT
trap 'exit 129' HUP
trap 'exit 130' INT
trap 'exit 143' TERM

temporary_stage=$(mktemp -d /var/tmp/volparossa-helper-live-proof.XXXXXX)
case $temporary_stage in
    /var/tmp/volparossa-helper-live-proof.??????) ;;
    *) failed 'mktemp returned an unsafe staging path' ;;
esac
temporary_stage_identity=$(stat -Lc '%d:%i:%F:%u:%g:%a' "$temporary_stage")
case $temporary_stage_identity in
    *:directory:0:0:700) ;;
    *) failed 'temporary stage ownership or mode is unsafe' ;;
esac
stage_suffix=${temporary_stage##*.}
case $stage_suffix in
    ''|*[!A-Za-z0-9]*) failed 'temporary stage suffix is non-canonical' ;;
esac
unit_name=volparossa-helper-live-proof-$stage_suffix.service
if [ "$(unit_load_state)" != not-found ]; then
    failed 'random transient unit name is already loaded'
fi

entry_is_absent() {
    database=$1
    key=$2
    set +e
    getent "$database" "$key" >/dev/null 2>&1
    status=$?
    set -e
    [ "$status" -eq 2 ]
}

base_id=61000
ids_found=no
while [ "$base_id" -le 64990 ]; do
    agent_uid=$base_id
    agent_gid=$base_id
    operator_gid=$((base_id + 1))
    worker_uid=$((base_id + 2))
    worker_gid=$((base_id + 2))
    shadow_gid=$((base_id + 3))
    if entry_is_absent passwd "$agent_uid" \
        && entry_is_absent passwd "$worker_uid" \
        && entry_is_absent group "$agent_gid" \
        && entry_is_absent group "$operator_gid" \
        && entry_is_absent group "$worker_gid" \
        && entry_is_absent group "$shadow_gid"; then
        ids_found=yes
        break
    fi
    base_id=$((base_id + 4))
done
if [ "$ids_found" != yes ]; then
    blocked 'no collision-free synthetic service identity range is available'
fi

source_before=$(stat -Lc '%d:%i:%u:%g:%a:%h:%s:%Y:%Z' "$helper_source")
source_digest_before=$(vp_capture_sha256_file "$helper_source") \
    || failed 'the helper source could not be hashed'
install -o root -g root -m 0500 "$helper_source" "$temporary_stage/volparossa-helper"
source_after=$(stat -Lc '%d:%i:%u:%g:%a:%h:%s:%Y:%Z' "$helper_source")
source_digest_after=$(vp_capture_sha256_file "$helper_source") \
    || failed 'the helper source could not be re-hashed'
staged_digest=$(vp_capture_sha256_file "$temporary_stage/volparossa-helper") \
    || failed 'the staged helper could not be hashed'
if [ "$source_before" != "$source_after" ] \
    || [ "$source_digest_before" != "$source_digest_after" ] \
    || [ "$source_digest_before" != "$staged_digest" ] \
    || [ "$(stat -Lc '%F:%u:%g:%a:%h' "$temporary_stage/volparossa-helper")" \
        != 'regular file:0:0:500:1' ]; then
    failed 'the real helper changed while copied or the staged image is unsafe'
fi

printf '%s\n' \
    'root:x:0:0:root:/root:/bin/sh' \
    "volparossa:x:$agent_uid:$agent_gid:VOLPAROSSA staged agent:/var/lib/volparossa:/usr/sbin/nologin" \
    "volparossa-worker:x:$worker_uid:$worker_gid:VOLPAROSSA staged worker:/nonexistent:/usr/sbin/nologin" \
    >"$temporary_stage/passwd"
printf '%s\n' \
    'root:x:0:' \
    "volparossa:x:$agent_gid:" \
    "volparossa-users:x:$operator_gid:volparossa" \
    "volparossa-worker:x:$worker_gid:" \
    "shadow:x:$shadow_gid:" \
    >"$temporary_stage/group"
printf '%s\n' \
    'root:!:0:0:99999:7:::' \
    'volparossa:!:0:0:99999:7:::' \
    'volparossa-worker:!:0:0:99999:7::1:' \
    >"$temporary_stage/shadow"
printf '%s\n' \
    'passwd: files' \
    'group: files' \
    'shadow: files' \
    'initgroups: files' \
    >"$temporary_stage/nsswitch.conf"
chown root:root "$temporary_stage/passwd" "$temporary_stage/group" \
    "$temporary_stage/nsswitch.conf"
chmod 0644 "$temporary_stage/passwd" "$temporary_stage/group" \
    "$temporary_stage/nsswitch.conf"
chown "root:$shadow_gid" "$temporary_stage/shadow"
chmod 0640 "$temporary_stage/shadow"
for staged_file in passwd group nsswitch.conf; do
    if [ "$(stat -Lc '%F:%u:%g:%a:%h' "$temporary_stage/$staged_file")" \
        != 'regular file:0:0:644:1' ]; then
        failed "unsafe staged account file: $staged_file"
    fi
done
if [ "$(stat -Lc '%F:%u:%g:%a:%h' "$temporary_stage/shadow")" \
    != "regular file:0:$shadow_gid:640:1" ]; then
    failed 'unsafe staged shadow file'
fi
install -o root -g root -m 0600 /dev/null "$temporary_stage/proof.stdout"
install -o root -g root -m 0600 /dev/null "$temporary_stage/proof.stderr"

state_records='accounts namespaces mounts resolver sysctls links addresses routes rules nexthops qdiscs nftables wireguard legacy_ipv4_firewall legacy_ipv6_firewall'

publish_optional_digest_record() {
    [ "$#" -eq 2 ] || failed 'invalid optional state publication request'
    optional_capture=$1
    optional_record=$2
    optional_digest=$(vp_capture_sha256 "$optional_capture") \
        || failed 'an optional host-state capture could not be hashed'
    vp_capture_run "$optional_record" printf '%s\n%s\n' PRESENT "$optional_digest" \
        || failed 'an optional host-state digest could not be published'
}

publish_streamed_digest_record() {
    [ "$#" -eq 2 ] || failed 'invalid streamed state publication request'
    streamed_digest_capture=$1
    streamed_digest_record=$2
    vp_capture_file_is_safe "$streamed_digest_capture" \
        || failed 'a streamed host-state digest is not a validated private file'
    streamed_digest_line=$(cat "$streamed_digest_capture") \
        || failed 'a streamed host-state digest could not be read'
    streamed_digest=$(vp_capture_checksum_from_line "$streamed_digest_line") \
        || failed 'a streamed host-state digest is malformed'
    vp_capture_run "$streamed_digest_record" printf '%s\n%s\n' PRESENT "$streamed_digest" \
        || failed 'a streamed host-state digest could not be published'
}

publish_absent_record() {
    [ "$#" -eq 1 ] || failed 'invalid absent state publication request'
    vp_capture_run "$1" printf '%s\n' ABSENT \
        || failed 'an absent host-state marker could not be published'
}

capture_host_state() {
    destination=$1
    install -d -o root -g root -m 0700 "$destination"
    capture_directory=$destination/captures
    install -d -o root -g root -m 0700 "$capture_directory"

    accounts_capture=$capture_directory/accounts.validated
    : >"$accounts_capture"
    chmod 0600 "$accounts_capture"
    for account_file in /etc/passwd /etc/group /etc/shadow /etc/gshadow /etc/nsswitch.conf; do
        if [ ! -f "$account_file" ] || [ -L "$account_file" ]; then
            failed "host account database is unsafe: $account_file"
        fi
        account_before=$(stat -Lc '%F:%d:%i:%u:%g:%a:%h:%s:%Y:%Z' "$account_file") \
            || failed 'host account metadata could not be captured'
        account_digest=$(vp_capture_sha256_file "$account_file") \
            || failed 'host account content could not be hashed'
        account_after=$(stat -Lc '%F:%d:%i:%u:%g:%a:%h:%s:%Y:%Z' "$account_file") \
            || failed 'host account metadata could not be re-captured'
        [ "$account_before" = "$account_after" ] \
            || failed 'host account database changed during one capture'
        printf '%s\n%s\n%s\n' "$account_file" "$account_before" "$account_digest" \
            >>"$accounts_capture" || failed 'host account capture could not be written'
    done
    vp_capture_file_is_safe "$accounts_capture" \
        || failed 'host account capture is not a validated private file'
    vp_capture_publish_digest "$accounts_capture" "$destination/accounts" \
        || failed 'host account capture could not be published'

    namespaces_capture=$capture_directory/namespaces.validated
    : >"$namespaces_capture"
    chmod 0600 "$namespaces_capture"
    for namespace in user net mnt pid pid_for_children; do
        namespace_identity=$(stat -Lc '%d:%i' "/proc/self/ns/$namespace") \
            || failed 'host namespace identity could not be captured'
        printf '%s\n%s\n' "$namespace" "$namespace_identity" >>"$namespaces_capture" \
            || failed 'host namespace capture could not be written'
    done
    vp_capture_file_is_safe "$namespaces_capture" \
        || failed 'host namespace capture is not a validated private file'
    vp_capture_publish_digest "$namespaces_capture" "$destination/namespaces" \
        || failed 'host namespace capture could not be published'

    vp_capture_run "$capture_directory/mounts.raw" cat /proc/self/mountinfo \
        || failed 'host mount producer failed'
    vp_capture_publish_digest "$capture_directory/mounts.raw" "$destination/mounts" \
        || failed 'host mount capture could not be published'

    resolver_capture=$capture_directory/resolver.validated
    vp_capture_resolver_snapshot /etc/resolv.conf "$resolver_capture" '/etc /run' \
        || failed 'resolver object or resolved target could not be captured safely'
    vp_capture_publish_digest "$resolver_capture" "$destination/resolver" \
        || failed 'resolver capture could not be published'

    sysctls_capture=$capture_directory/sysctls.validated
    : >"$sysctls_capture"
    chmod 0600 "$sysctls_capture"
    for sysctl_path in \
        /proc/sys/net/ipv4/ip_forward \
        /proc/sys/net/ipv6/conf/all/forwarding \
        /proc/sys/net/ipv6/conf/default/forwarding
    do
        sysctl_value=$(cat "$sysctl_path") || failed 'host forwarding state could not be read'
        case $sysctl_value in 0|1) ;; *) failed 'host forwarding state is non-canonical' ;; esac
        printf '%s=%s\n' "$sysctl_path" "$sysctl_value" >>"$sysctls_capture" \
            || failed 'host forwarding capture could not be written'
    done
    vp_capture_file_is_safe "$sysctls_capture" \
        || failed 'host forwarding capture is not a validated private file'
    vp_capture_publish_digest "$sysctls_capture" "$destination/sysctls" \
        || failed 'host forwarding capture could not be published'

    vp_capture_run "$capture_directory/links.raw" ip -json link show \
        || failed 'host link producer failed'
    vp_capture_normalize "$capture_directory/links.raw" "$capture_directory/links.normalized" \
        jq -S -c '
        map(del(.operstate,.link_netnsid,.promiscuity,.allmulti,.stats,.stats64)
            | .flags=((.flags // []) | map(select(. != "LOWER_UP" and . != "RUNNING"
                and . != "DORMANT" and . != "NO-CARRIER")) | sort)
            | if has("altnames") then .altnames |= sort else . end)
        | sort_by(.ifindex,.ifname)
    ' || failed 'host link normalization failed'
    vp_capture_publish_digest "$capture_directory/links.normalized" "$destination/links" \
        || failed 'host link capture could not be published'

    vp_capture_run "$capture_directory/addresses.raw" ip -json address show \
        || failed 'host address producer failed'
    vp_capture_normalize "$capture_directory/addresses.raw" \
        "$capture_directory/addresses.normalized" jq -S -c '
        map({ifindex,ifname,addr_info:((.addr_info // [])
            | map(del(.valid_life_time,.preferred_life_time,.valid_lft,.preferred_lft,
                .tstamp,.cstamp,.tentative,.dadfailed,.deprecated,.optimistic))
            | sort_by(.family,.local,(.peer // ""),.prefixlen,.scope,(.label // "")))})
        | sort_by(.ifindex,.ifname)
    ' || failed 'host address normalization failed'
    vp_capture_publish_digest "$capture_directory/addresses.normalized" "$destination/addresses" \
        || failed 'host address capture could not be published'

    vp_capture_run "$capture_directory/routes-v4.raw" ip -json -4 route show table all \
        || failed 'host IPv4 route producer failed'
    vp_capture_run "$capture_directory/routes-v6.raw" ip -json -6 route show table all \
        || failed 'host IPv6 route producer failed'
    vp_capture_run "$capture_directory/routes.normalized" jq -S -c -s '
        add | walk(if type == "object" then
            del(.expires,.used,.age,.lastuse,.users,.cache,.statistics)
            | if ((.flags? // null)|type) == "array" then
                .flags |= map(select(. != "linkdown" and . != "dead" and . != "offload"
                    and . != "trap" and . != "unresolved")) | sort
              else . end
          else . end)
        | sort_by((.family // ""),(.table // ""|tostring),(.dst // ""),(.src // ""),
            (.metric // 0),(.protocol // ""),(.dev // ""),(.gateway // ""))
    ' "$capture_directory/routes-v4.raw" "$capture_directory/routes-v6.raw" \
        || failed 'host route normalization failed'
    vp_capture_publish_digest "$capture_directory/routes.normalized" "$destination/routes" \
        || failed 'host route capture could not be published'

    vp_capture_run "$capture_directory/rules-v4.raw" ip -json -4 rule show \
        || failed 'host IPv4 rule producer failed'
    vp_capture_run "$capture_directory/rules-v6.raw" ip -json -6 rule show \
        || failed 'host IPv6 rule producer failed'
    vp_capture_run "$capture_directory/rules.normalized" jq -S -c -s '
        add | sort_by(.family,.priority,(.table // ""|tostring),
            (.src // ""),(.dst // ""))
    ' "$capture_directory/rules-v4.raw" "$capture_directory/rules-v6.raw" \
        || failed 'host rule normalization failed'
    vp_capture_publish_digest "$capture_directory/rules.normalized" "$destination/rules" \
        || failed 'host rule capture could not be published'

    vp_capture_run "$capture_directory/nexthops.raw" ip -json nexthop show \
        || failed 'host nexthop producer failed'
    vp_capture_normalize "$capture_directory/nexthops.raw" \
        "$capture_directory/nexthops.normalized" jq -S -c '
        walk(if type == "object" then del(.used,.age,.lastuse,.statistics)
            | if ((.flags? // null)|type) == "array" then
                .flags |= map(select(. != "offload" and . != "trap")) | sort
              else . end else . end)
        | sort_by(.id,(.dev // ""),(.via // ""|tostring))
    ' || failed 'host nexthop normalization failed'
    vp_capture_publish_digest "$capture_directory/nexthops.normalized" "$destination/nexthops" \
        || failed 'host nexthop capture could not be published'

    vp_capture_run "$capture_directory/qdiscs.raw" tc -json qdisc show \
        || failed 'host qdisc producer failed'
    vp_capture_normalize "$capture_directory/qdiscs.raw" \
        "$capture_directory/qdiscs.normalized" jq -S -c '
        walk(if type == "object" then
            del(.refcnt,.bytes,.packets,.drops,.overlimits,.requeues,.backlog,.qlen,
                .direct_packets_stat,.xstats) else . end)
        | sort_by(.dev,(.parent // ""),(.handle // ""),.kind)
    ' || failed 'host qdisc normalization failed'
    vp_capture_publish_digest "$capture_directory/qdiscs.normalized" "$destination/qdiscs" \
        || failed 'host qdisc capture could not be published'

    vp_capture_run "$capture_directory/nftables.raw" nft --json list ruleset \
        || failed 'host nftables producer failed'
    vp_capture_normalize "$capture_directory/nftables.raw" \
        "$capture_directory/nftables.normalized" jq -S -c '
        walk(if type == "object" then
            if has("counter") then .counter |= del(.packets,.bytes) else . end
            | del(.expires,.last,.used) else . end)
    ' || failed 'host nftables normalization failed'
    vp_capture_publish_digest "$capture_directory/nftables.normalized" "$destination/nftables" \
        || failed 'host nftables capture could not be published'

    # `wg dump` contains private key material. A validated 0600 FIFO streams it
    # directly to a separately checked SHA-256 consumer; raw bytes never enter
    # a regular file, shell variable, published record, or log.
    if command -v wg >/dev/null 2>&1; then
        vp_capture_stream_sha256 "$capture_directory/wireguard.fifo" \
            "$capture_directory/wireguard.digest" wg show all dump \
            || failed 'host WireGuard producer failed'
        publish_streamed_digest_record "$capture_directory/wireguard.digest" \
            "$destination/wireguard"
    else
        publish_absent_record "$destination/wireguard"
    fi

    if command -v iptables-save >/dev/null 2>&1; then
        vp_capture_run "$capture_directory/iptables.raw" iptables-save \
            || failed 'host legacy IPv4 firewall producer failed'
        vp_capture_normalize "$capture_directory/iptables.raw" \
            "$capture_directory/iptables.normalized" \
            sed -E 's/\[[0-9]+:[0-9]+\]/[COUNTERS]/g' \
            || failed 'host legacy IPv4 firewall normalization failed'
        publish_optional_digest_record "$capture_directory/iptables.normalized" \
            "$destination/legacy_ipv4_firewall"
    else
        publish_absent_record "$destination/legacy_ipv4_firewall"
    fi
    if command -v ip6tables-save >/dev/null 2>&1; then
        vp_capture_run "$capture_directory/ip6tables.raw" ip6tables-save \
            || failed 'host legacy IPv6 firewall producer failed'
        vp_capture_normalize "$capture_directory/ip6tables.raw" \
            "$capture_directory/ip6tables.normalized" \
            sed -E 's/\[[0-9]+:[0-9]+\]/[COUNTERS]/g' \
            || failed 'host legacy IPv6 firewall normalization failed'
        publish_optional_digest_record "$capture_directory/ip6tables.normalized" \
            "$destination/legacy_ipv6_firewall"
    else
        publish_absent_record "$destination/legacy_ipv6_firewall"
    fi
}

state_digest() {
    directory=$1
    aggregate=$directory/state.aggregate
    : >"$aggregate"
    chmod 0600 "$aggregate"
    for record in $state_records; do
        vp_capture_file_is_safe "$directory/$record" \
            || failed "host-state digest record is unsafe: $record"
        printf '%s\n' "$record" >>"$aggregate" \
            || failed 'host-state aggregate could not be written'
        cat "$directory/$record" >>"$aggregate" \
            || failed 'host-state digest record could not be aggregated'
    done
    vp_capture_file_is_safe "$aggregate" \
        || failed 'host-state aggregate is not a validated private file'
    vp_capture_sha256 "$aggregate" || failed 'host-state aggregate could not be hashed'
}

capture_host_state "$temporary_stage/before"
before_digest=$(state_digest "$temporary_stage/before")

capabilities='CAP_KILL CAP_NET_ADMIN CAP_NET_RAW CAP_SETGID CAP_SETPCAP CAP_SETUID CAP_SYS_ADMIN'
account_binds="$temporary_stage/passwd:/etc/passwd:norbind $temporary_stage/group:/etc/group:norbind $temporary_stage/shadow:/etc/shadow:norbind $temporary_stage/nsswitch.conf:/etc/nsswitch.conf:norbind"
helper_bind="$temporary_stage/volparossa-helper:/run/volparossa-helper-live-proof:norbind"

set +e
systemd-run \
    --quiet \
    --collect \
    --unit="$unit_name" \
    --service-type=oneshot \
    --remain-after-exit \
    --property=User=0 \
    --property=Group="$agent_gid" \
    --property=SupplementaryGroups= \
    --property=UMask=0077 \
    --property=LimitCORE=0 \
    --property=NoNewPrivileges=yes \
    --property="CapabilityBoundingSet=$capabilities" \
    --property="AmbientCapabilities=$capabilities" \
    --property=PrivateNetwork=yes \
    --property=PrivateMounts=yes \
    --property=PrivateTmp=yes \
    --property=PrivateDevices=no \
    --property=DevicePolicy=closed \
    --property='DeviceAllow=/dev/net/tun rw' \
    --property=ProtectSystem=strict \
    --property=ProtectHome=yes \
    --property=ProtectControlGroups=yes \
    --property=ProtectKernelModules=yes \
    --property=ProtectKernelLogs=yes \
    --property=ProtectClock=yes \
    --property=ProtectHostname=yes \
    --property=LockPersonality=yes \
    --property=MemoryDenyWriteExecute=yes \
    --property=RestrictRealtime=yes \
    --property=RestrictSUIDSGID=yes \
    --property=RestrictNamespaces=net \
    --property=SystemCallArchitectures=native \
    --property='SystemCallFilter=@system-service @network-io @mount seccomp' \
    --property=SystemCallErrorNumber=EPERM \
    --property='RestrictAddressFamilies=AF_UNIX AF_INET AF_INET6 AF_NETLINK' \
    --property='TemporaryFileSystem=/run:rw,nodev,nosuid,noexec,mode=0755,size=16M' \
    --property="BindReadOnlyPaths=$helper_bind $account_binds" \
    --property=KillMode=control-group \
    --property=SendSIGKILL=yes \
    --property=TimeoutStartSec=30s \
    --property=TimeoutStopSec=10s \
    --property=RuntimeMaxSec=30s \
    --property=TasksMax=16 \
    --property=SetLoginEnvironment=no \
    --property="StandardOutput=file:$temporary_stage/proof.stdout" \
    --property="StandardError=file:$temporary_stage/proof.stderr" \
    /run/volparossa-helper-live-proof --internal-worker-v3-live-proof \
    >"$temporary_stage/systemd-run.stdout" 2>"$temporary_stage/systemd-run.stderr"
run_status=$?
set -e

proof_ok=yes
if [ "$run_status" -ne 0 ]; then
    proof_ok=no
fi
poll_attempt=0
while :; do
    active_state=$(systemctl show --property=ActiveState --value "$unit_name" 2>/dev/null || true)
    sub_state=$(systemctl show --property=SubState --value "$unit_name" 2>/dev/null || true)
    if [ "$active_state:$sub_state" = active:exited ]; then
        break
    fi
    case $active_state in
        failed|inactive) break ;;
    esac
    poll_attempt=$((poll_attempt + 1))
    if [ "$poll_attempt" -ge 600 ]; then
        proof_ok=no
        break
    fi
    sleep 0.05
done
capture_unit_property() {
    [ "$#" -eq 2 ] || return 1
    vp_capture_run "$2" systemctl show --property="$1" --value "$unit_name"
}
if capture_unit_property ActiveState "$temporary_stage/unit-active-state"; then
    active_state=$(cat "$temporary_stage/unit-active-state") || proof_ok=no
else
    active_state=
    proof_ok=no
fi
if capture_unit_property SubState "$temporary_stage/unit-sub-state"; then
    sub_state=$(cat "$temporary_stage/unit-sub-state") || proof_ok=no
else
    sub_state=
    proof_ok=no
fi
if capture_unit_property Result "$temporary_stage/unit-result"; then
    result=$(cat "$temporary_stage/unit-result") || proof_ok=no
else
    result=
    proof_ok=no
fi
if capture_unit_property ExecMainStatus "$temporary_stage/unit-exec-status"; then
    exec_status=$(cat "$temporary_stage/unit-exec-status") || proof_ok=no
else
    exec_status=
    proof_ok=no
fi
if [ "$active_state" != active ] || [ "$sub_state" != exited ] \
    || [ "$result" != success ] || [ "$exec_status" != 0 ]; then
    proof_ok=no
fi
printf '%s\n' 'VOLPAROSSA_HELPER_LIVE_WORKER_PROOF_V1=pass' \
    >"$temporary_stage/expected.stdout"
if ! cmp -s "$temporary_stage/expected.stdout" "$temporary_stage/proof.stdout" \
    || [ -s "$temporary_stage/proof.stderr" ]; then
    proof_ok=no
fi

normalize_capabilities() {
    [ "$#" -eq 2 ] || return 1
    # The dollar expressions below belong to awk, not the shell.
    # shellcheck disable=SC2016
    vp_capture_normalize "$1" "$2" awk -v expected="$capabilities" '
        BEGIN {
            expected_count = split(expected, ordered, " ")
            for (index = 1; index <= expected_count; index++) {
                allowed[ordered[index]] = 1
            }
        }
        {
            for (field = 1; field <= NF; field++) {
                capability = toupper($field)
                if (!(capability in allowed) || seen[capability]++) exit 1
                observed_count++
            }
        }
        END {
            if (observed_count != expected_count) exit 1
            print expected
        }
    '
}
if capture_unit_property CapabilityBoundingSet "$temporary_stage/unit-bounding.raw" \
    && normalize_capabilities "$temporary_stage/unit-bounding.raw" \
        "$temporary_stage/unit-bounding.normalized"; then
    observed_bounding=$(cat "$temporary_stage/unit-bounding.normalized") || proof_ok=no
else
    observed_bounding=
    proof_ok=no
fi
if capture_unit_property AmbientCapabilities "$temporary_stage/unit-ambient.raw" \
    && normalize_capabilities "$temporary_stage/unit-ambient.raw" \
        "$temporary_stage/unit-ambient.normalized"; then
    observed_ambient=$(cat "$temporary_stage/unit-ambient.normalized") || proof_ok=no
else
    observed_ambient=
    proof_ok=no
fi
if capture_unit_property PrivateNetwork "$temporary_stage/unit-private-network"; then
    observed_private_network=$(cat "$temporary_stage/unit-private-network") || proof_ok=no
else
    observed_private_network=
    proof_ok=no
fi
if [ "$observed_bounding" != "$capabilities" ] \
    || [ "$observed_ambient" != "$capabilities" ] \
    || [ "$observed_private_network" != yes ]; then
    proof_ok=no
fi

if ! retire_unit; then
    cleanup_error=yes
    proof_ok=no
fi
capture_host_state "$temporary_stage/after"
after_digest=$(state_digest "$temporary_stage/after")
changed_records=
for record in $state_records; do
    if ! cmp -s "$temporary_stage/before/$record" "$temporary_stage/after/$record"; then
        changed_records="$changed_records $record"
    fi
done
if [ -n "$changed_records" ] || [ "$before_digest" != "$after_digest" ]; then
    printf 'Host state changed in:%s\n' "$changed_records" >&2
    failed 'privacy-safe before/after host-state digests differ'
fi
if [ "$proof_ok" != yes ]; then
    failed 'the staged helper did not produce the exact live identity/reap proof'
fi

printf '%s\n' \
    'PASS: staged helper worker identity, confinement, confirmed reap, and pin release were proved.' \
    "HOST_STATE_BEFORE_SHA256=$before_digest" \
    "HOST_STATE_AFTER_SHA256=$after_digest" \
    'SCOPE=STAGED_HELPER_COMPONENT_ONLY' \
    'No host account or network configuration was changed; this is not a VPN datapath or A01-A15 acceptance result.'
