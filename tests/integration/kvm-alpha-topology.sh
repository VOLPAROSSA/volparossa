#!/bin/sh
# SPDX-License-Identifier: GPL-3.0-only
# Run the five-node development-alpha topology with one real production helper per agent.
# This script is intentionally restricted to a disposable Debian 13 KVM guest.
# shellcheck disable=SC2317
set -eu

export LC_ALL=C
PATH=/usr/sbin:/usr/bin:/sbin:/bin
export PATH
umask 077

mode=preview
approval=no
source_directory=
binary_directory=
output_directory=
expected_commit=

usage() {
    printf '%s\n' \
        'usage: tests/integration/kvm-alpha-topology.sh --preview' \
        '       tests/integration/kvm-alpha-topology.sh --execute --yes' \
        '         --source DIRECTORY --bin DIRECTORY --output DIRECTORY' \
        '         --expected-commit SHA'
}

print_plan() {
    printf '%s\n' \
        'VOLPAROSSA production-helper alpha topology plan:' \
        '  require one disposable Debian 13 amd64 KVM guest with systemd v257 as PID 1;' \
        '  create Client, Relay 1, Relay 2, Exit and destination network namespaces;' \
        '  create only Client-Relay, Relay-Exit and Exit-destination underlay links;' \
        '  launch four distinct transient production-helper service instances;' \
        '  bind each helper and agent privately to its node-owned /run/volparossa;' \
        '  prove GetUnitByPID, MainPID, cgroup, network namespace and FD-store binding;' \
        '  launch four real agents and a destination TCP/UDP endpoint;' \
        '  request Connect, retain bounded logs, then stop units and remove namespaces.'
}

while [ "$#" -gt 0 ]; do
    case $1 in
        --preview)
            mode=preview
            ;;
        --execute)
            mode=execute
            ;;
        --yes)
            approval=yes
            ;;
        --source)
            [ "$#" -ge 2 ] || { usage >&2; exit 64; }
            source_directory=$2
            shift
            ;;
        --bin)
            [ "$#" -ge 2 ] || { usage >&2; exit 64; }
            binary_directory=$2
            shift
            ;;
        --output)
            [ "$#" -ge 2 ] || { usage >&2; exit 64; }
            output_directory=$2
            shift
            ;;
        --expected-commit)
            [ "$#" -ge 2 ] || { usage >&2; exit 64; }
            expected_commit=$2
            shift
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
    if [ "$approval" != no ] \
        || [ -n "$source_directory$binary_directory$output_directory$expected_commit" ]; then
        usage >&2
        exit 64
    fi
    print_plan
    printf '%s\n' 'PREVIEW ONLY: no VM, service, namespace, route or file was changed.'
    exit 0
fi

if [ "$approval" != yes ] || [ -z "$source_directory" ] \
    || [ -z "$binary_directory" ] || [ -z "$output_directory" ] \
    || [ -z "$expected_commit" ]; then
    usage >&2
    exit 64
fi

case $source_directory:$binary_directory:$output_directory in
    /*:/*:/*) ;;
    *) printf '%s\n' 'source, binary and output paths must be absolute' >&2; exit 64 ;;
esac
case $expected_commit in
    ''|*[!0-9a-f]*) printf '%s\n' 'expected commit is not canonical' >&2; exit 64 ;;
esac
case ${#expected_commit} in 40|64) ;; *) exit 64 ;; esac

[ "$(id -u)" -eq 0 ] || { printf '%s\n' 'execution requires root inside KVM' >&2; exit 77; }
[ "$(sed -n '1{s/\..*$//;p;}' /etc/debian_version)" = 13 ] \
    || { printf '%s\n' 'execution requires Debian 13' >&2; exit 77; }
[ "$(uname -m)" = x86_64 ] || { printf '%s\n' 'execution requires amd64' >&2; exit 77; }
[ "$(sed -n '1p' /proc/1/comm)" = systemd ] \
    || { printf '%s\n' 'PID 1 must be systemd' >&2; exit 77; }
[ "$(systemctl show --property=Version --value | sed 's/[^0-9].*$//')" = 257 ] \
    || { printf '%s\n' 'execution requires systemd v257' >&2; exit 77; }
[ "$(systemd-detect-virt)" = kvm ] \
    || { printf '%s\n' 'execution requires a KVM guest' >&2; exit 77; }

for command_name in awk busctl cat chmod chown cut date grep install ip jq kill \
    mkdir mktemp python3 readlink runuser sed setpriv sha256sum sleep stat systemctl \
    systemd-run systemd-sysusers tail tr; do
    command -v "$command_name" >/dev/null 2>&1 \
        || { printf 'required guest tool unavailable: %s\n' "$command_name" >&2; exit 69; }
done
for executable in volparossa volparossa-agent volparossa-helper; do
    [ -x "$binary_directory/$executable" ] \
        || { printf 'required product executable unavailable: %s\n' "$executable" >&2; exit 69; }
done
[ -x "$binary_directory/examples/acceptance-policy-fixture" ] \
    || { printf '%s\n' 'acceptance policy fixture unavailable' >&2; exit 69; }
[ -f "$source_directory/packaging/systemd/volparossa.sysusers" ] \
    || { printf '%s\n' 'production service identity declaration unavailable' >&2; exit 69; }
if [ ! -d "$output_directory" ] || [ -L "$output_directory" ]; then
    printf '%s\n' 'output directory is unsafe' >&2
    exit 64
fi

OUTPUT_UID=$(stat -Lc '%u' "$output_directory")
OUTPUT_GID=$(stat -Lc '%g' "$output_directory")
case $OUTPUT_UID:$OUTPUT_GID in :|:*|*:|*[!0-9:]*) exit 64 ;; esac

RUN_ID=$(tr -d -- - </proc/sys/kernel/random/uuid)
case $RUN_ID in ''|*[!0-9a-f]*) exit 69 ;; esac
[ "${#RUN_ID}" -eq 32 ] || exit 69
PREFIX=va-$(printf '%.8s' "$RUN_ID")
CLIENT=$PREFIX-c
R1=$PREFIX-r1
R2=$PREFIX-r2
EXIT_NODE=$PREFIX-x
DEST=$PREFIX-d
WORK=$(mktemp -d "/var/tmp/volparossa-alpha-topology.$RUN_ID.XXXXXX")
case $WORK in /var/tmp/volparossa-alpha-topology.*) ;; *) exit 69 ;; esac
chmod 0700 "$WORK"

PHASE=identity-setup
TOPOLOGY_READY=false
HELPERS_READY=false
AGENTS_READY=false
DESTINATION_READY=false
CONNECT_REQUESTED=false
CONNECT_SUCCEEDED=false
CONNECT_STATUS=-1
OBSERVED_BLOCKER=NOT_REACHED
CLEANUP_COMPLETE=false
HELPER_UNITS=
AGENT_UNITS=
DESTINATION_PID=
FINALIZED=no

copy_artifacts() {
    for artifact in \
        connect-client.out connect-client.err \
        logs-client.txt logs-relay1.txt logs-relay2.txt logs-exit.txt \
        status-client.txt status-relay1.txt status-relay2.txt status-exit.txt \
        roles-client.txt roles-relay1.txt roles-relay2.txt roles-exit.txt \
        helper-client.log helper-relay1.log helper-relay2.log helper-exit.log \
        agent-client.log agent-relay1.log agent-relay2.log agent-exit.log \
        destination.log helper-units.json; do
        if [ -f "$WORK/$artifact" ] && [ ! -L "$WORK/$artifact" ]; then
            install -o "$OUTPUT_UID" -g "$OUTPUT_GID" -m 0600 \
                "$WORK/$artifact" "$output_directory/$artifact"
        fi
    done
}

unit_load_state() {
    systemctl show --property=LoadState --value "$1" 2>/dev/null || true
}

retire_unit() {
    retire_name=$1
    case $retire_name in
        volparossa-alpha-helper@*.service|volparossa-alpha-agent@*.service) ;;
        *) return 1 ;;
    esac
    [ "$(unit_load_state "$retire_name")" = loaded ] || return 0
    systemctl stop "$retire_name" >/dev/null 2>&1 || true
    retire_attempt=0
    while [ "$retire_attempt" -lt 100 ]; do
        retire_active=$(systemctl show --property=ActiveState --value \
            "$retire_name" 2>/dev/null || true)
        case $retire_active in inactive|failed|'') break ;; esac
        sleep 0.1
        retire_attempt=$((retire_attempt + 1))
    done
    systemctl clean --what=fdstore "$retire_name" >/dev/null 2>&1 || true
    systemctl reset-failed "$retire_name" >/dev/null 2>&1 || true
    return 0
}

write_report() {
    report_status=$1
    helper_records='[]'
    if [ -f "$WORK/helper-units.json" ]; then
        helper_records=$(cat "$WORK/helper-units.json" 2>/dev/null || printf '[]')
    fi
    jq -S -c -n \
        --arg commit "$expected_commit" \
        --arg run_id "$RUN_ID" \
        --arg phase "$PHASE" \
        --arg blocker "$OBSERVED_BLOCKER" \
        --argjson topology "$TOPOLOGY_READY" \
        --argjson helpers "$HELPERS_READY" \
        --argjson agents "$AGENTS_READY" \
        --argjson destination "$DESTINATION_READY" \
        --argjson requested "$CONNECT_REQUESTED" \
        --argjson connected "$CONNECT_SUCCEEDED" \
        --argjson connect_status "$CONNECT_STATUS" \
        --argjson cleanup "$CLEANUP_COMPLETE" \
        --argjson exit_status "$report_status" \
        --argjson helper_records "$helper_records" \
        '{schema_version:1,report_kind:"volparossa-alpha-kvm-topology",
          source_revision:$commit,run_id:$run_id,last_phase:$phase,
          topology:{ready:$topology,direct_client_exit_adjacency:false,
            roles:["client","relay1","relay2","exit","destination"]},
          production_helpers:{ready:$helpers,instances:$helper_records},
          agents_ready:$agents,destination_ready:$destination,
          client_connect:{requested:$requested,succeeded:$connected,
            exit_status:$connect_status,observed_blocker:$blocker},
          cleanup:{complete:$cleanup},runner_exit_status:$exit_status}' \
        >"$output_directory/report.json"
    chown "$OUTPUT_UID:$OUTPUT_GID" "$output_directory/report.json"
    chmod 0600 "$output_directory/report.json"
}

cleanup() {
    original_status=$?
    [ "$FINALIZED" = no ] || exit "$original_status"
    FINALIZED=yes
    trap - EXIT HUP INT TERM

    if [ -n "$DESTINATION_PID" ]; then
        kill -TERM "$DESTINATION_PID" 2>/dev/null || true
        wait "$DESTINATION_PID" 2>/dev/null || true
    fi
    for cleanup_unit in $AGENT_UNITS; do retire_unit "$cleanup_unit" || true; done
    for cleanup_unit in $HELPER_UNITS; do retire_unit "$cleanup_unit" || true; done
    for cleanup_ns in "$DEST" "$EXIT_NODE" "$R2" "$R1" "$CLIENT"; do
        ip netns del "$cleanup_ns" 2>/dev/null || true
    done

    remaining_namespaces=$(ip netns list | awk -v prefix="$PREFIX-" \
        '$1 ~ ("^" prefix) { count++ } END { print count + 0 }')
    remaining_units=0
    for cleanup_unit in $AGENT_UNITS $HELPER_UNITS; do
        [ "$(unit_load_state "$cleanup_unit")" = not-found ] \
            || remaining_units=$((remaining_units + 1))
    done
    if [ "$remaining_namespaces" -eq 0 ] && [ "$remaining_units" -eq 0 ]; then
        CLEANUP_COMPLETE=true
    else
        CLEANUP_COMPLETE=false
        original_status=1
    fi
    copy_artifacts
    write_report "$original_status"
    exit "$original_status"
}
trap cleanup EXIT
trap 'exit 129' HUP
trap 'exit 130' INT
trap 'exit 143' TERM

fail() {
    OBSERVED_BLOCKER=$1
    printf 'alpha KVM topology failed in %s: %s\n' "$PHASE" "$1" >&2
    exit 1
}

# This creates only the package-declared identities inside the disposable VM.
systemd-sysusers "$source_directory/packaging/systemd/volparossa.sysusers"
AGENT_UID=$(id -u volparossa)
AGENT_GID=$(id -g volparossa)
WORKER_UID=$(id -u volparossa-worker)
WORKER_GID=$(id -g volparossa-worker)
case $AGENT_UID:$AGENT_GID:$WORKER_UID:$WORKER_GID in
    :*|*::*|*:|*[!0-9:]*) fail IDENTITY_INVALID ;;
esac
if [ "$AGENT_UID" -eq 0 ] || [ "$AGENT_GID" -eq 0 ] \
    || [ "$WORKER_UID" -eq 0 ] || [ "$WORKER_GID" -eq 0 ] \
    || [ "$AGENT_UID" -eq "$WORKER_UID" ]; then
    fail IDENTITY_INVALID
fi
chown "root:$AGENT_GID" "$WORK"
chmod 0750 "$WORK"
install -d -o root -g "$AGENT_GID" -m 0755 "$WORK/bin"
for staged_executable in volparossa volparossa-agent volparossa-helper; do
    install -o root -g "$AGENT_GID" -m 0555 \
        "$binary_directory/$staged_executable" "$WORK/bin/$staged_executable"
done
install -d -o root -g "$AGENT_GID" -m 0755 "$WORK/bin/examples"
install -o root -g "$AGENT_GID" -m 0555 \
    "$binary_directory/examples/acceptance-policy-fixture" \
    "$WORK/bin/examples/acceptance-policy-fixture"
binary_directory=$WORK/bin

PHASE=network-topology
for namespace in "$CLIENT" "$R1" "$R2" "$EXIT_NODE" "$DEST"; do
    [ -z "$(ip netns list | awk -v name="$namespace" '$1 == name { print $1 }')" ] \
        || fail NAMESPACE_COLLISION
    ip netns add "$namespace"
    ip -n "$namespace" link set lo up
done

link_nodes() {
    left_ns=$1; left_name=$2; left_address=$3
    right_ns=$4; right_name=$5; right_address=$6
    left_temp=t${left_name}a
    right_temp=t${right_name}b
    ip link add "$left_temp" type veth peer name "$right_temp"
    ip link set "$left_temp" netns "$left_ns"
    ip link set "$right_temp" netns "$right_ns"
    ip -n "$left_ns" link set "$left_temp" name "$left_name"
    ip -n "$right_ns" link set "$right_temp" name "$right_name"
    ip -n "$left_ns" address add "$left_address" dev "$left_name"
    ip -n "$right_ns" address add "$right_address" dev "$right_name"
    ip -n "$left_ns" link set "$left_name" up
    ip -n "$right_ns" link set "$right_name" up
}

link_nodes "$CLIENT" cr1 10.241.11.1/30 "$R1" r1c 10.241.11.2/30
link_nodes "$CLIENT" cr2 10.241.12.1/30 "$R2" r2c 10.241.12.2/30
link_nodes "$R1" r1x 10.241.21.1/30 "$EXIT_NODE" xr1 10.241.21.2/30
link_nodes "$R2" r2x 10.241.22.1/30 "$EXIT_NODE" xr2 10.241.22.2/30
link_nodes "$EXIT_NODE" xd 10.241.31.1/30 "$DEST" dx 10.241.31.2/30
ip -n "$CLIENT" address add 43.159.1.1/32 dev lo
ip -n "$R1" address add 44.160.1.1/32 dev lo
ip -n "$R2" address add 45.161.2.1/32 dev lo
ip -n "$EXIT_NODE" address add 46.162.3.1/32 dev lo
ip -n "$CLIENT" route add 44.160.1.1/32 via 10.241.11.2 dev cr1 src 43.159.1.1
ip -n "$CLIENT" route add 45.161.2.1/32 via 10.241.12.2 dev cr2 src 43.159.1.1
ip -n "$R1" route add 43.159.1.1/32 via 10.241.11.1 dev r1c src 44.160.1.1
ip -n "$R1" route add 46.162.3.1/32 via 10.241.21.2 dev r1x src 44.160.1.1
ip -n "$R2" route add 43.159.1.1/32 via 10.241.12.1 dev r2c src 45.161.2.1
ip -n "$R2" route add 46.162.3.1/32 via 10.241.22.2 dev r2x src 45.161.2.1
ip -n "$EXIT_NODE" route add 44.160.1.1/32 via 10.241.21.1 dev xr1 src 46.162.3.1
ip -n "$EXIT_NODE" route add 45.161.2.1/32 via 10.241.22.1 dev xr2 src 46.162.3.1
for forbidden in 10.241.21.2 10.241.22.2 10.241.31.2; do
    if ip -n "$CLIENT" route get "$forbidden" >/dev/null 2>&1; then
        fail DIRECT_CLIENT_EXIT_REACHABLE
    fi
done
TOPOLOGY_READY=true

PHASE=configuration
for node in client relay1 relay2 exit; do
    install -d -o root -g "$AGENT_GID" -m 0750 "$WORK/runtime-$node"
    install -d -o "$AGENT_UID" -g "$AGENT_GID" -m 0750 \
        "$WORK/runtime-$node/control"
    install -d -o "$AGENT_UID" -g "$AGENT_GID" -m 0700 \
        "$WORK/runtime-$node/native" "$WORK/state-$node" "$WORK/credential-$node"
    printf '%s\n' 'disposable alpha topology identity passphrase' \
        >"$WORK/credential-$node/identity-passphrase"
    chown "$AGENT_UID:$AGENT_GID" "$WORK/credential-$node/identity-passphrase"
    chmod 0600 "$WORK/credential-$node/identity-passphrase"
    runuser -u volparossa -- "$binary_directory/volparossa" init \
        --identity "$WORK/state-$node/identity.key" \
        --passphrase-file "$WORK/credential-$node/identity-passphrase" \
        >"$WORK/init-$node.log"
done
CLIENT_PEER=$(sed -n 's/^peer ID: //p' "$WORK/init-client.log")
R1_PEER=$(sed -n 's/^peer ID: //p' "$WORK/init-relay1.log")
R2_PEER=$(sed -n 's/^peer ID: //p' "$WORK/init-relay2.log")
EXIT_PEER=$(sed -n 's/^peer ID: //p' "$WORK/init-exit.log")
for peer in "$CLIENT_PEER" "$R1_PEER" "$R2_PEER" "$EXIT_PEER"; do
    [ -n "$peer" ] || fail IDENTITY_INITIALISATION_FAILED
done

"$binary_directory/examples/acceptance-policy-fixture" "$WORK"
chown "$AGENT_UID:$AGENT_GID" "$WORK/development-policy.manifest" \
    "$WORK/policy-maintainers.json"

write_config() {
    node=$1; operator=$2; relay_role=$3; exit_role=$4; listen_ip=$5
    bootstrap_one=$6; bootstrap_two=$7
    relay_capacity=0; exit_capacity=0; advertised_asn=0; advertised_prefix=null
    [ "$relay_role" = false ] || relay_capacity=32
    [ "$exit_role" = false ] || exit_capacity=32
    case $node in
        relay1) advertised_asn=64512; advertised_prefix=44.160.1.0/24 ;;
        relay2) advertised_asn=64513; advertised_prefix=45.161.2.0/24 ;;
        exit) advertised_asn=64514; advertised_prefix=46.162.3.0/24 ;;
    esac
    {
        printf 'runtime_mode: development\nnetwork:\n  name: VOLPAROSSA-alpha-%s\n' "$RUN_ID"
        printf '  protocol_version: 4\n  advertisement_ttl_seconds: 300\n'
        [ "$operator" = null ] && printf '  operator_id: null\n' \
            || printf '  operator_id: %s\n' "$operator"
        printf '  advertised_region: acceptance\n  advertised_country_code: ZZ\n'
        printf '  advertised_asn: %s\n' "$advertised_asn"
        [ "$advertised_prefix" = null ] && printf '  advertised_ipv4_prefix: null\n' \
            || printf '  advertised_ipv4_prefix: %s\n' "$advertised_prefix"
        printf '  advertised_ipv6_prefix: null\n  listen_addresses:\n'
        printf '    - /ip4/%s/udp/41000/quic-v1\n  bootstrap_peers:\n' "$listen_ip"
        [ "$bootstrap_one" = none ] \
            || printf '    - %s\n' "$bootstrap_one"
        [ "$bootstrap_two" = none ] \
            || printf '    - %s\n' "$bootstrap_two"
        printf 'roles:\n  client: true\n  relay: %s\n  exit: %s\n' "$relay_role" "$exit_role"
        printf 'capacity:\n  relay_upload_limit_mbps: %s\n' "$relay_capacity"
        printf '  relay_download_limit_mbps: %s\n' "$relay_capacity"
        printf '  exit_upload_limit_mbps: %s\n' "$exit_capacity"
        printf '  exit_download_limit_mbps: %s\n' "$exit_capacity"
        printf '  maximum_relay_sessions: %s\n' "$relay_capacity"
        printf '  maximum_exit_sessions: %s\n' "$exit_capacity"
        printf 'policy:\n  fail_closed: true\n'
        printf '  manifest_path: "%s/development-policy.manifest"\n' "$WORK"
        printf '  minimum_signatures: 3\n  reject_ech: true\n'
        printf '  reject_unverifiable_sni: true\nprivacy:\n  metrics_enabled: false\n'
        printf '  persist_domain_logs: false\n  persist_destination_ips: false\n'
    } >"$WORK/config-$node.yaml"
    chown "$AGENT_UID:$AGENT_GID" "$WORK/config-$node.yaml"
    chmod 0600 "$WORK/config-$node.yaml"
}

write_config client null false false 43.159.1.1 \
    "/ip4/44.160.1.1/udp/41000/quic-v1/p2p/$R1_PEER" \
    "/ip4/45.161.2.1/udp/41000/quic-v1/p2p/$R2_PEER"
write_config relay1 acceptance-relay-one true false 44.160.1.1 none none
write_config relay2 acceptance-relay-two true false 45.161.2.1 none none
write_config exit acceptance-exit false true 46.162.3.1 \
    "/ip4/44.160.1.1/udp/41000/quic-v1/p2p/$R1_PEER" \
    "/ip4/45.161.2.1/udp/41000/quic-v1/p2p/$R2_PEER"

PHASE=helper-launch
CAPABILITIES='CAP_KILL CAP_NET_ADMIN CAP_NET_RAW CAP_SETGID CAP_SETPCAP CAP_SETUID CAP_SYS_ADMIN'

launch_helper() {
    node=$1; namespace=$2
    helper_unit=volparossa-alpha-helper@$node.service
    helper_log=$WORK/helper-$node.log
    : >"$helper_log"
    chmod 0600 "$helper_log"
    [ "$(unit_load_state "$helper_unit")" = not-found ] \
        || fail HELPER_UNIT_COLLISION
    HELPER_UNITS="$HELPER_UNITS $helper_unit"
    systemd-run --no-block --unit="$helper_unit" --slice=system.slice \
        --description="VOLPAROSSA disposable alpha helper $node" \
        --service-type=exec \
        --property=CollectMode=inactive-or-failed \
        --property=Restart=no \
        --property=NotifyAccess=main \
        --property=FileDescriptorStoreMax=128 \
        --property=FileDescriptorStorePreserve=yes \
        --property=User=root \
        --property=Group=root \
        --property=SupplementaryGroups= \
        --property=UMask=0077 \
        --property=LimitCORE=0 \
        --property=LimitFSIZE=16777216 \
        --property=NoNewPrivileges=yes \
        --property="CapabilityBoundingSet=$CAPABILITIES" \
        --property="AmbientCapabilities=$CAPABILITIES" \
        --property="NetworkNamespacePath=/run/netns/$namespace" \
        --property=PrivateMounts=yes \
        --property=PrivateTmp=yes \
        --property=PrivateDevices=no \
        --property=DevicePolicy=closed \
        --property='DeviceAllow=/dev/net/tun rw' \
        --property=ProtectSystem=strict \
        --property=ProtectHome=yes \
        --property=ProtectControlGroupsEx=strict \
        --property=Delegate=no \
        --property=PrivatePIDs=no \
        --property=ProtectKernelModules=yes \
        --property=ProtectKernelTunables=no \
        --property=ProtectKernelLogs=yes \
        --property=ProtectClock=yes \
        --property=ProtectHostname=yes \
        --property=LockPersonality=yes \
        --property=MemoryDenyWriteExecute=yes \
        --property=RestrictRealtime=yes \
        --property=RestrictSUIDSGID=no \
        --property=RestrictNamespaces=net \
        --property=SystemCallArchitectures=native \
        --property='SystemCallFilter=@system-service @network-io seccomp' \
        --property='SystemCallFilter=~@mount' \
        --property=SystemCallErrorNumber=EPERM \
        --property='RestrictAddressFamilies=AF_UNIX AF_INET AF_INET6 AF_NETLINK' \
        --property="BindPaths=$WORK/runtime-$node:/run/volparossa" \
        --property='ReadWritePaths=/run/volparossa -/run/netns' \
        --property='ExecSearchPath=/usr/sbin /usr/bin /sbin /bin' \
        --property=Environment=DBUS_SYSTEM_BUS_ADDRESS=unix:path=/run/dbus/system_bus_socket \
        --property=KillMode=control-group \
        --property=SendSIGKILL=yes \
        --property=TimeoutStartSec=45s \
        --property=TimeoutStopSec=45s \
        --property=TasksMax=64 \
        --property=SetLoginEnvironment=no \
        --property="StandardOutput=append:$helper_log" \
        --property="StandardError=append:$helper_log" \
        /usr/bin/setpriv --regid="$AGENT_GID" --groups="$AGENT_GID" -- \
        "$binary_directory/volparossa-helper" >/dev/null
}

launch_helper client "$CLIENT"
launch_helper relay1 "$R1"
launch_helper relay2 "$R2"
launch_helper exit "$EXIT_NODE"

PHASE=helper-verification
verify_helper() {
    node=$1; namespace=$2
    helper_unit=volparossa-alpha-helper@$node.service
    attempt=0
    while [ "$attempt" -lt 300 ]; do
        helper_state=$(systemctl show --property=ActiveState --value "$helper_unit" 2>/dev/null || true)
        helper_substate=$(systemctl show --property=SubState --value "$helper_unit" 2>/dev/null || true)
        [ "$helper_state:$helper_substate" = active:running ] \
            && [ -S "$WORK/runtime-$node/helper.sock" ] && break
        case $helper_state in failed|inactive) break ;; esac
        sleep 0.1
        attempt=$((attempt + 1))
    done
    [ "$helper_state:$helper_substate" = active:running ] \
        || fail "HELPER_SERVICE_UNAVAILABLE_$node"
    [ -S "$WORK/runtime-$node/helper.sock" ] \
        || fail "HELPER_SOCKET_UNAVAILABLE_$node"
    helper_pid=$(systemctl show --property=MainPID --value "$helper_unit")
    case $helper_pid in ''|0|*[!0-9]*) fail "HELPER_MAINPID_INVALID_$node" ;; esac
    by_name=$(busctl call org.freedesktop.systemd1 /org/freedesktop/systemd1 \
        org.freedesktop.systemd1.Manager GetUnit s "$helper_unit")
    by_pid=$(busctl call org.freedesktop.systemd1 /org/freedesktop/systemd1 \
        org.freedesktop.systemd1.Manager GetUnitByPID u "$helper_pid")
    [ "$by_name" = "$by_pid" ] || fail "HELPER_GETUNITBYPID_MISMATCH_$node"
    process_net=$(stat -Lc '%d:%i' "/proc/$helper_pid/ns/net")
    expected_net=$(stat -Lc '%d:%i' "/run/netns/$namespace")
    [ "$process_net" = "$expected_net" ] \
        || fail "HELPER_NETWORK_NAMESPACE_MISMATCH_$node"
    helper_properties=$(systemctl show "$helper_unit" \
        --property=ActiveState --property=SubState --property=MainPID \
        --property=NotifyAccess --property=FileDescriptorStoreMax \
        --property=FileDescriptorStorePreserve --property=NFileDescriptorStore \
        --property=ControlGroup --property=User --property=Group)
    printf '%s\n' "$helper_properties" >"$WORK/helper-unit-$node.txt"
    printf '%s\n' "$helper_properties" | grep -Fx 'NotifyAccess=main' >/dev/null \
        || fail "HELPER_NOTIFY_CONTRACT_$node"
    printf '%s\n' "$helper_properties" | grep -Fx 'FileDescriptorStoreMax=128' >/dev/null \
        || fail "HELPER_FDSTORE_MAX_CONTRACT_$node"
    printf '%s\n' "$helper_properties" | grep -Fx 'FileDescriptorStorePreserve=yes' >/dev/null \
        || fail "HELPER_FDSTORE_PRESERVE_CONTRACT_$node"
    control_group=$(printf '%s\n' "$helper_properties" | sed -n 's/^ControlGroup=//p')
    [ "$control_group" = "/system.slice/$helper_unit" ] \
        || fail "HELPER_CGROUP_CONTRACT_$node"
    socket_meta=$(stat -Lc '%F:%u:%g:%a' "$WORK/runtime-$node/helper.sock")
    [ "$socket_meta" = "socket:0:$AGENT_GID:660" ] \
        || fail "HELPER_SOCKET_METADATA_$node"
    jq -S -c -n --arg node "$node" --arg unit "$helper_unit" \
        --argjson pid "$helper_pid" --arg cgroup "$control_group" \
        --arg namespace "$namespace" --arg namespace_identity "$process_net" \
        --arg get_unit_by_pid "$by_pid" \
        '{node:$node,unit:$unit,main_pid:$pid,cgroup:$cgroup,
          network_namespace:$namespace,network_namespace_identity:$namespace_identity,
          get_unit_by_pid:$get_unit_by_pid,notify_access:"main",
          file_descriptor_store_max:128,file_descriptor_store_preserve:"yes",
          helper_socket_verified:true}' >"$WORK/helper-record-$node.json"
}

verify_helper client "$CLIENT"
verify_helper relay1 "$R1"
verify_helper relay2 "$R2"
verify_helper exit "$EXIT_NODE"
jq -S -c -s . "$WORK"/helper-record-*.json >"$WORK/helper-units.json"
HELPERS_READY=true

PHASE=agent-launch
launch_agent() {
    node=$1; namespace=$2
    agent_unit=volparossa-alpha-agent@$node.service
    agent_log=$WORK/agent-$node.log
    : >"$agent_log"
    chown "$AGENT_UID:$AGENT_GID" "$agent_log"
    chmod 0600 "$agent_log"
    [ "$(unit_load_state "$agent_unit")" = not-found ] || fail AGENT_UNIT_COLLISION
    AGENT_UNITS="$AGENT_UNITS $agent_unit"
    systemd-run --no-block --unit="$agent_unit" --slice=system.slice \
        --description="VOLPAROSSA disposable alpha agent $node" \
        --service-type=exec \
        --property=CollectMode=inactive-or-failed \
        --property=Restart=no \
        --property=User=volparossa \
        --property=Group=volparossa \
        --property=SupplementaryGroups=volparossa-users \
        --property=UMask=0077 \
        --property=NoNewPrivileges=yes \
        --property=CapabilityBoundingSet= \
        --property=AmbientCapabilities= \
        --property="NetworkNamespacePath=/run/netns/$namespace" \
        --property=PrivateMounts=yes \
        --property=PrivateTmp=yes \
        --property=PrivateDevices=yes \
        --property=ProtectSystem=strict \
        --property=ProtectHome=yes \
        --property=ProtectControlGroups=yes \
        --property=ProtectKernelModules=yes \
        --property=ProtectKernelTunables=yes \
        --property=ProtectKernelLogs=yes \
        --property=ProtectClock=yes \
        --property=ProtectHostname=yes \
        --property=LockPersonality=yes \
        --property=MemoryDenyWriteExecute=yes \
        --property=RestrictRealtime=yes \
        --property=RestrictSUIDSGID=yes \
        --property=RestrictNamespaces=yes \
        --property=SystemCallArchitectures=native \
        --property='SystemCallFilter=@system-service @network-io' \
        --property=SystemCallErrorNumber=EPERM \
        --property='RestrictAddressFamilies=AF_UNIX AF_INET AF_INET6 AF_NETLINK' \
        --property="BindPaths=$WORK/runtime-$node:/run/volparossa" \
        --property="ReadWritePaths=$WORK/state-$node" \
        --property="Environment=VOLPAROSSA_CONFIG=$WORK/config-$node.yaml" \
        --property="Environment=VOLPAROSSA_STATE_DIRECTORY=$WORK/state-$node" \
        --property=Environment=VOLPAROSSA_CONTROL_SOCKET=/run/volparossa/control/agent.sock \
        --property=Environment=VOLPAROSSA_HELPER_SOCKET=/run/volparossa/helper.sock \
        --property=Environment=VOLPAROSSA_MPQUIC_SOCKET=/run/volparossa/native/mpquic.sock \
        --property="Environment=CREDENTIALS_DIRECTORY=$WORK/credential-$node" \
        --property=Environment=RUST_LOG=volparossa_agent=info \
        --property=KillMode=control-group \
        --property=SendSIGKILL=yes \
        --property=TimeoutStartSec=30s \
        --property=TimeoutStopSec=30s \
        --property=SetLoginEnvironment=no \
        --property="StandardOutput=append:$agent_log" \
        --property="StandardError=append:$agent_log" \
        "$binary_directory/volparossa-agent" >/dev/null
}

launch_agent client "$CLIENT"
launch_agent relay1 "$R1"
launch_agent relay2 "$R2"
launch_agent exit "$EXIT_NODE"

install -d -o "$AGENT_UID" -g "$AGENT_GID" -m 0700 "$WORK/destination"
cat >"$WORK/bin/destination.py" <<'PYTHON'
import signal
import socket
import sys
import time

tcp = socket.socket()
tcp.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
tcp.bind(("10.241.31.2", 18080))
tcp.listen(4)
udp = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
udp.bind(("10.241.31.2", 18081))
open(sys.argv[1], "x", encoding="ascii").write(
    "tcp=10.241.31.2:18080\nudp=10.241.31.2:18081\n"
)
signal.signal(signal.SIGTERM, lambda *_: sys.exit(0))
time.sleep(600)
PYTHON
chown "root:$AGENT_GID" "$WORK/bin/destination.py"
chmod 0550 "$WORK/bin/destination.py"
ip netns exec "$DEST" setpriv --reuid="$AGENT_UID" --regid="$AGENT_GID" \
    --clear-groups --inh-caps=-all --ambient-caps=-all --bounding-set=-all \
    --no-new-privs -- \
    python3 "$WORK/bin/destination.py" "$WORK/destination/ready" \
    >"$WORK/destination.log" 2>&1 &
DESTINATION_PID=$!

PHASE=agent-readiness
attempt=0
while [ "$attempt" -lt 300 ]; do
    agents_running=yes
    for node in client relay1 relay2 exit; do
        agent_unit=volparossa-alpha-agent@$node.service
        [ "$(systemctl show --property=ActiveState --value "$agent_unit" 2>/dev/null || true)" = active ] \
            || agents_running=no
        [ -S "$WORK/runtime-$node/control/agent.sock" ] || agents_running=no
    done
    [ -f "$WORK/destination/ready" ] || agents_running=no
    [ "$agents_running" = yes ] && break
    sleep 0.1
    attempt=$((attempt + 1))
done
[ "$agents_running" = yes ] || fail AGENT_OR_DESTINATION_NOT_READY
AGENTS_READY=true
DESTINATION_READY=true

for node in client relay1 relay2 exit; do
    "$binary_directory/volparossa" \
        --control-socket "$WORK/runtime-$node/control/agent.sock" status \
        >"$WORK/status-$node.txt"
    "$binary_directory/volparossa" \
        --control-socket "$WORK/runtime-$node/control/agent.sock" role show \
        >"$WORK/roles-$node.txt"
done
grep -Fx 'client: true' "$WORK/roles-client.txt" >/dev/null || fail CLIENT_ROLE_INVALID
grep -Fx 'relay: true' "$WORK/roles-relay1.txt" >/dev/null || fail RELAY1_ROLE_INVALID
grep -Fx 'relay: true' "$WORK/roles-relay2.txt" >/dev/null || fail RELAY2_ROLE_INVALID
grep -Fx 'exit: true' "$WORK/roles-exit.txt" >/dev/null || fail EXIT_ROLE_INVALID

PHASE=discovery
attempt=0
while [ "$attempt" -lt 300 ]; do
    control_ready=yes
    for node in client relay1 relay2 exit; do
        if ! "$binary_directory/volparossa" \
            --control-socket "$WORK/runtime-$node/control/agent.sock" status \
            >"$WORK/status-$node.txt"; then
            control_ready=no
            continue
        fi
        active_peers=$(awk '/^active peers: / { print $3 }' "$WORK/status-$node.txt")
        [ -n "$active_peers" ] && [ "$active_peers" -ge 2 ] || control_ready=no
    done
    [ "$control_ready" = yes ] && break
    sleep 0.1
    attempt=$((attempt + 1))
done
[ "$control_ready" = yes ] || fail DISCOVERY_NOT_READY

PHASE=client-connect
CONNECT_REQUESTED=true
set +e
"$binary_directory/volparossa" \
    --control-socket "$WORK/runtime-client/control/agent.sock" connect \
    >"$WORK/connect-client.out" 2>"$WORK/connect-client.err"
CONNECT_STATUS=$?
set -e

for node in client relay1 relay2 exit; do
    "$binary_directory/volparossa" \
        --control-socket "$WORK/runtime-$node/control/agent.sock" logs --limit 400 \
        >"$WORK/logs-$node.txt" || true
done

if [ "$CONNECT_STATUS" -eq 0 ]; then
    CONNECT_SUCCEEDED=true
    OBSERVED_BLOCKER=NONE
    PHASE=connect-complete
    exit 0
fi

OBSERVED_BLOCKER=$(grep -Eo 'event=[A-Z0-9_]*(UNAVAILABLE|FAILED|DENIED|REJECTED)[A-Z0-9_]*' \
    "$WORK/logs-client.txt" 2>/dev/null | tail -n 1 | sed 's/^event=//' || true)
[ -n "$OBSERVED_BLOCKER" ] || OBSERVED_BLOCKER=CONNECT_EXIT_NONZERO
PHASE=connect-blocked
exit 77
