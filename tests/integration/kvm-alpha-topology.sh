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
mpquic_binary=
output_directory=
expected_commit=

usage() {
    printf '%s\n' \
        'usage: tests/integration/kvm-alpha-topology.sh --preview' \
        '       tests/integration/kvm-alpha-topology.sh --execute --yes' \
        '         --source DIRECTORY --bin DIRECTORY --output DIRECTORY' \
        '         --mpquic PATH --expected-commit SHA'
}

print_plan() {
    printf '%s\n' \
        'VOLPAROSSA production-helper alpha topology plan:' \
        '  require one disposable Debian 13 amd64 KVM guest with systemd v257 as PID 1;' \
        '  create Client, Relay 1, Relay 2, Exit and destination network namespaces;' \
        '  give each product node one disposable public underlay and fail-closed default;' \
        '  create only Client-Relay, Relay-Exit and Exit-destination underlay links;' \
        '  launch four distinct transient production-helper service instances;' \
        '  launch real pinned mqvpn/xquic processes for the Client and Exit;' \
        '  bind each helper and agent privately to its node-owned /run/volparossa;' \
        '  prove GetUnitByPID, MainPID, cgroup, network namespace and FD-store binding;' \
        '  launch four real agents and exact-policy TCP/UDP echo applications;' \
        '  prove transparent TCP over Relay-only MPTCP/TLS and signed OPEN_TCP;' \
        '  request UDP Connect, then send one non-trusted application datagram through ingress;' \
        '  prove exact replies, selected Relays and zero direct Client-Exit packets;' \
        '  retain bounded evidence, then stop units and remove namespaces.'
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
        --mpquic)
            [ "$#" -ge 2 ] || { usage >&2; exit 64; }
            mpquic_binary=$2
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
        || [ -n "$source_directory$binary_directory$mpquic_binary$output_directory$expected_commit" ]; then
        usage >&2
        exit 64
    fi
    print_plan
    printf '%s\n' 'PREVIEW ONLY: no VM, service, namespace, route or file was changed.'
    exit 0
fi

if [ "$approval" != yes ] || [ -z "$source_directory" ] \
    || [ -z "$binary_directory" ] || [ -z "$mpquic_binary" ] \
    || [ -z "$output_directory" ] \
    || [ -z "$expected_commit" ]; then
    usage >&2
    exit 64
fi

case $source_directory:$binary_directory:$mpquic_binary:$output_directory in
    /*:/*:/*:/*) ;;
    *) printf '%s\n' 'source, binary, MPQUIC and output paths must be absolute' >&2; exit 64 ;;
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
if [ ! -f "$mpquic_binary" ] || [ ! -x "$mpquic_binary" ] \
    || [ -L "$mpquic_binary" ]; then
    printf '%s\n' 'pinned native MPQUIC executable unavailable' >&2
    exit 69
fi
MPQUIC_SIZE=$(stat -Lc '%s' "$mpquic_binary")
case $MPQUIC_SIZE in ''|0|*[!0-9]*) exit 69 ;; esac
[ "$MPQUIC_SIZE" -le 67108864 ] \
    || { printf '%s\n' 'pinned native MPQUIC executable is oversized' >&2; exit 69; }
[ "$("$mpquic_binary" --api-version)" = 6 ] \
    || { printf '%s\n' 'pinned native MPQUIC API mismatch' >&2; exit 69; }
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
A02_DESTINATION_IP=47.163.4.2
A02_EXIT_SOURCE=47.163.4.1
# PrivateTmp is part of both production service sandboxes and Debian mounts its
# runtime tmpfs non-executable. Keep this disposable-VM stage on the executable
# root filesystem so both transient units see and can execute the exact build.
WORK=$(mktemp -d "/opt/volparossa-alpha-topology.$RUN_ID.XXXXXX")
case $WORK in /opt/volparossa-alpha-topology.*) ;; *) exit 69 ;; esac
chmod 0700 "$WORK"

PHASE=identity-setup
TOPOLOGY_READY=false
HELPERS_READY=false
MPQUIC_READY=false
AGENTS_READY=false
DESTINATION_READY=false
CONNECT_REQUESTED=false
CONNECT_SUCCEEDED=false
CONNECT_STATUS=-1
A02_REQUESTED=false
A02_SUCCEEDED=false
A02_STATUS=-1
A05_REQUESTED=false
A05_SUCCEEDED=false
A05_STATUS=-1
OBSERVED_BLOCKER=NOT_REACHED
CLEANUP_COMPLETE=false
CLIENT_EXIT_ROUTE_ABSENT=false
REMAINING_NAMESPACES=-1
REMAINING_UNITS=-1
HELPER_UNITS=
MPQUIC_UNITS=
AGENT_UNITS=
DESTINATION_PID=
CLIENT_OBSERVER_PID=
EXIT_OBSERVER_PID=
FINALIZED=no

copy_artifacts() {
    for artifact in \
        connect-client.out connect-client.err \
        logs-client.txt logs-relay1.txt logs-relay2.txt logs-exit.txt \
        status-client.txt status-relay1.txt status-relay2.txt status-exit.txt \
        roles-client.txt roles-relay1.txt roles-relay2.txt roles-exit.txt \
        helper-client.log helper-relay1.log helper-relay2.log helper-exit.log \
        mpquic-client.log mpquic-exit.log mpquic-units.json \
        agent-client.log agent-relay1.log agent-relay2.log agent-exit.log \
        destination.log destination-tcp-evidence.json destination-udp-evidence.json \
        helper-units.json a02-client.json a02-client.err a02-client-fallback-route.txt \
        a02-client-capture.json a02-client-capture.log a02-client-capture.err \
        a02-exit-capture.json a02-exit-capture.log a02-exit-capture.err \
        a02-evidence.json \
        a05-client.json a05-client.err a05-client-fallback-route.txt \
        a05-client-capture.json a05-client-capture.log a05-client-capture.err \
        a05-exit-capture.json a05-exit-capture.log a05-exit-capture.err \
        a05-evidence.json; do
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
        volparossa-alpha-helper@*.service|volparossa-alpha-mpquic@*.service|volparossa-alpha-agent@*.service) ;;
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
    a02_evidence=null
    if [ -f "$WORK/a02-evidence.json" ]; then
        a02_evidence=$(cat "$WORK/a02-evidence.json" 2>/dev/null || printf 'null')
    fi
    mpquic_records='[]'
    if [ -f "$WORK/mpquic-units.json" ]; then
        mpquic_records=$(cat "$WORK/mpquic-units.json" 2>/dev/null || printf '[]')
    fi
    a05_evidence=null
    if [ -f "$WORK/a05-evidence.json" ]; then
        a05_evidence=$(cat "$WORK/a05-evidence.json" 2>/dev/null || printf 'null')
    fi
    jq -S -c -n \
        --arg commit "$expected_commit" \
        --arg run_id "$RUN_ID" \
        --arg phase "$PHASE" \
        --arg blocker "$OBSERVED_BLOCKER" \
        --argjson topology "$TOPOLOGY_READY" \
        --argjson client_exit_route_absent "$CLIENT_EXIT_ROUTE_ABSENT" \
        --argjson helpers "$HELPERS_READY" \
        --argjson mpquic "$MPQUIC_READY" \
        --argjson agents "$AGENTS_READY" \
        --argjson destination "$DESTINATION_READY" \
        --argjson requested "$CONNECT_REQUESTED" \
        --argjson connected "$CONNECT_SUCCEEDED" \
        --argjson connect_status "$CONNECT_STATUS" \
        --argjson a02_requested "$A02_REQUESTED" \
        --argjson a02_succeeded "$A02_SUCCEEDED" \
        --argjson a02_status "$A02_STATUS" \
        --argjson a05_requested "$A05_REQUESTED" \
        --argjson a05_succeeded "$A05_SUCCEEDED" \
        --argjson a05_status "$A05_STATUS" \
        --argjson cleanup "$CLEANUP_COMPLETE" \
        --argjson remaining_namespaces "$REMAINING_NAMESPACES" \
        --argjson remaining_units "$REMAINING_UNITS" \
        --argjson exit_status "$report_status" \
        --argjson helper_records "$helper_records" \
        --argjson a02_evidence "$a02_evidence" \
        --argjson mpquic_records "$mpquic_records" \
        --argjson a05_evidence "$a05_evidence" \
        '{schema_version:1,report_kind:"volparossa-alpha-kvm-topology",
          source_revision:$commit,run_id:$run_id,last_phase:$phase,
          topology:{ready:$topology,direct_client_exit_adjacency:false,
            client_exit_route_absent:$client_exit_route_absent,
            roles:["client","relay1","relay2","exit","destination"]},
          production_helpers:{ready:$helpers,instances:$helper_records},
          native_mpquic:{ready:$mpquic,api_version:6,instances:$mpquic_records},
          agents_ready:$agents,destination_ready:$destination,
          client_connect:{requested:$requested,succeeded:$connected,
            exit_status:$connect_status,observed_blocker:$blocker},
          a02_transparent_tcp:{requested:$a02_requested,succeeded:$a02_succeeded,
            exit_status:$a02_status,evidence:$a02_evidence},
          a05_udp_echo:{requested:$a05_requested,succeeded:$a05_succeeded,
            exit_status:$a05_status,evidence:$a05_evidence},
          cleanup:{complete:$cleanup,remaining_namespaces:$remaining_namespaces,
            remaining_units:$remaining_units},runner_exit_status:$exit_status}' \
        >"$output_directory/report.json"
    chown "$OUTPUT_UID:$OUTPUT_GID" "$output_directory/report.json"
    chmod 0600 "$output_directory/report.json"
}

cleanup() {
    original_status=$?
    [ "$FINALIZED" = no ] || exit "$original_status"
    FINALIZED=yes
    trap - EXIT HUP INT TERM

    for observer_pid in "$CLIENT_OBSERVER_PID" "$EXIT_OBSERVER_PID"; do
        [ -z "$observer_pid" ] || kill -TERM "$observer_pid" 2>/dev/null || true
    done
    for observer_pid in "$CLIENT_OBSERVER_PID" "$EXIT_OBSERVER_PID"; do
        [ -z "$observer_pid" ] || wait "$observer_pid" 2>/dev/null || true
    done
    if [ -n "$DESTINATION_PID" ]; then
        kill -TERM "$DESTINATION_PID" 2>/dev/null || true
        destination_stop_attempt=0
        while kill -0 "$DESTINATION_PID" 2>/dev/null \
            && [ "$destination_stop_attempt" -lt 50 ]; do
            sleep 0.1
            destination_stop_attempt=$((destination_stop_attempt + 1))
        done
        if kill -0 "$DESTINATION_PID" 2>/dev/null; then
            kill -KILL "$DESTINATION_PID" 2>/dev/null || true
        fi
        wait "$DESTINATION_PID" 2>/dev/null || true
    fi
    for cleanup_unit in $AGENT_UNITS; do retire_unit "$cleanup_unit" || true; done
    for cleanup_unit in $MPQUIC_UNITS; do retire_unit "$cleanup_unit" || true; done
    for cleanup_unit in $HELPER_UNITS; do retire_unit "$cleanup_unit" || true; done
    for cleanup_ns in "$DEST" "$EXIT_NODE" "$R2" "$R1" "$CLIENT"; do
        ip netns del "$cleanup_ns" 2>/dev/null || true
    done

    REMAINING_NAMESPACES=$(ip netns list | awk -v prefix="$PREFIX-" \
        '$1 ~ ("^" prefix) { count++ } END { print count + 0 }')
    REMAINING_UNITS=0
    for cleanup_unit in $AGENT_UNITS $MPQUIC_UNITS $HELPER_UNITS; do
        [ "$(unit_load_state "$cleanup_unit")" = not-found ] \
            || REMAINING_UNITS=$((REMAINING_UNITS + 1))
    done
    if [ "$REMAINING_NAMESPACES" -eq 0 ] && [ "$REMAINING_UNITS" -eq 0 ]; then
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
install -o root -g "$AGENT_GID" -m 0555 \
    "$mpquic_binary" "$WORK/bin/volparossa-mpquic"
install -d -o root -g "$AGENT_GID" -m 0755 "$WORK/bin/examples"
install -o root -g "$AGENT_GID" -m 0555 \
    "$binary_directory/examples/acceptance-policy-fixture" \
    "$WORK/bin/examples/acceptance-policy-fixture"
binary_directory=$WORK/bin
mpquic_binary=$WORK/bin/volparossa-mpquic

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

add_public_underlay() {
    underlay_ns=$1
    underlay_address=$2
    ip -n "$underlay_ns" link add underlay type dummy
    ip -n "$underlay_ns" address add "$underlay_address/32" dev underlay
    ip -n "$underlay_ns" link set underlay up
    # The helper deliberately selects only a non-loopback directly assigned public
    # address whose interface owns the sole main-table universe-scope default.
    # Explicit peer routes below still carry all topology packets; this disposable
    # default has no peer and therefore cannot create a hidden Client -> Exit path.
    ip -n "$underlay_ns" route add default dev underlay scope global
}

link_nodes "$CLIENT" cr1 10.241.11.1/30 "$R1" r1c 10.241.11.2/30
link_nodes "$CLIENT" cr2 10.241.12.1/30 "$R2" r2c 10.241.12.2/30
link_nodes "$R1" r1x 10.241.21.1/30 "$EXIT_NODE" xr1 10.241.21.2/30
link_nodes "$R2" r2x 10.241.22.1/30 "$EXIT_NODE" xr2 10.241.22.2/30
link_nodes "$EXIT_NODE" xd 10.241.31.1/30 "$DEST" dx 10.241.31.2/30
ip -n "$EXIT_NODE" address add 47.163.4.1/30 dev xd
ip -n "$DEST" address add 47.163.4.2/30 dev dx
add_public_underlay "$CLIENT" 43.159.1.1
add_public_underlay "$R1" 44.160.1.1
add_public_underlay "$R2" 45.161.2.1
add_public_underlay "$EXIT_NODE" 46.162.3.1
ip -n "$CLIENT" route add 44.160.1.1/32 via 10.241.11.2 dev cr1 src 43.159.1.1
ip -n "$CLIENT" route add 45.161.2.1/32 via 10.241.12.2 dev cr2 src 43.159.1.1
ip -n "$R1" route add 43.159.1.1/32 via 10.241.11.1 dev r1c src 44.160.1.1
ip -n "$R1" route add 46.162.3.1/32 via 10.241.21.2 dev r1x src 44.160.1.1
ip -n "$R2" route add 43.159.1.1/32 via 10.241.12.1 dev r2c src 45.161.2.1
ip -n "$R2" route add 46.162.3.1/32 via 10.241.22.2 dev r2x src 45.161.2.1
ip -n "$EXIT_NODE" route add 44.160.1.1/32 via 10.241.21.1 dev xr1 src 46.162.3.1
ip -n "$EXIT_NODE" route add 45.161.2.1/32 via 10.241.22.1 dev xr2 src 46.162.3.1
for forbidden in 10.241.21.2 10.241.22.2 10.241.31.1 10.241.31.2 46.162.3.1 \
    47.163.4.1; do
    ip -n "$CLIENT" route add unreachable "$forbidden/32"
    if ip -n "$CLIENT" route get "$forbidden" >/dev/null 2>&1; then
        fail DIRECT_CLIENT_EXIT_REACHABLE
    fi
done
CLIENT_EXIT_ROUTE_ABSENT=true
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
    client_role=false; relay_capacity=0; exit_capacity=0; advertised_asn=0; advertised_prefix=null
    [ "$node" != client ] || client_role=true
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
        printf 'roles:\n  client: %s\n  relay: %s\n  exit: %s\n' \
            "$client_role" "$relay_role" "$exit_role"
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

PHASE=mpquic-launch
launch_mpquic() {
    node=$1; namespace=$2; native_mode=$3
    mpquic_unit=volparossa-alpha-mpquic@$node.service
    mpquic_log=$WORK/mpquic-$node.log
    : >"$mpquic_log"
    chown "$AGENT_UID:$AGENT_GID" "$mpquic_log"
    chmod 0600 "$mpquic_log"
    [ "$(unit_load_state "$mpquic_unit")" = not-found ] \
        || fail MPQUIC_UNIT_COLLISION
    MPQUIC_UNITS="$MPQUIC_UNITS $mpquic_unit"
    systemd-run --no-block --unit="$mpquic_unit" --slice=system.slice \
        --description="VOLPAROSSA disposable native MPQUIC $node" \
        --service-type=exec \
        --property=CollectMode=inactive-or-failed \
        --property=Restart=no \
        --property=User=volparossa \
        --property=Group=volparossa \
        --property=SupplementaryGroups= \
        --property=UMask=0077 \
        --property=LimitCORE=0 \
        --property=LimitFSIZE=16777216 \
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
        --property='RestrictAddressFamilies=AF_UNIX AF_INET AF_INET6' \
        --property="BindPaths=$WORK/runtime-$node:/run/volparossa" \
        --property='ReadWritePaths=/run/volparossa/native' \
        --property=KillMode=control-group \
        --property=SendSIGKILL=yes \
        --property=TimeoutStartSec=30s \
        --property=TimeoutStopSec=30s \
        --property=TasksMax=128 \
        --property=SetLoginEnvironment=no \
        --property="StandardOutput=append:$mpquic_log" \
        --property="StandardError=append:$mpquic_log" \
        "$mpquic_binary" --mode "$native_mode" \
        --socket /run/volparossa/native/mpquic.sock >/dev/null
}

verify_mpquic() {
    node=$1; namespace=$2; native_mode=$3
    mpquic_unit=volparossa-alpha-mpquic@$node.service
    attempt=0
    while [ "$attempt" -lt 300 ]; do
        mpquic_state=$(systemctl show --property=ActiveState --value \
            "$mpquic_unit" 2>/dev/null || true)
        mpquic_substate=$(systemctl show --property=SubState --value \
            "$mpquic_unit" 2>/dev/null || true)
        [ "$mpquic_state:$mpquic_substate" = active:running ] \
            && [ -S "$WORK/runtime-$node/native/mpquic.sock" ] && break
        case $mpquic_state in failed|inactive) break ;; esac
        sleep 0.1
        attempt=$((attempt + 1))
    done
    [ "$mpquic_state:$mpquic_substate" = active:running ] \
        || fail "MPQUIC_SERVICE_UNAVAILABLE_$node"
    [ -S "$WORK/runtime-$node/native/mpquic.sock" ] \
        || fail "MPQUIC_SOCKET_UNAVAILABLE_$node"
    mpquic_pid=$(systemctl show --property=MainPID --value "$mpquic_unit")
    case $mpquic_pid in ''|0|*[!0-9]*) fail "MPQUIC_MAINPID_INVALID_$node" ;; esac
    process_net=$(stat -Lc '%d:%i' "/proc/$mpquic_pid/ns/net")
    expected_net=$(stat -Lc '%d:%i' "/run/netns/$namespace")
    [ "$process_net" = "$expected_net" ] \
        || fail "MPQUIC_NETWORK_NAMESPACE_MISMATCH_$node"
    [ "$(readlink -f -- "/proc/$mpquic_pid/exe")" = "$mpquic_binary" ] \
        || fail "MPQUIC_EXECUTABLE_MISMATCH_$node"
    socket_meta=$(stat -Lc '%F:%u:%g:%a' \
        "$WORK/runtime-$node/native/mpquic.sock")
    [ "$socket_meta" = "socket:$AGENT_UID:$AGENT_GID:600" ] \
        || fail "MPQUIC_SOCKET_METADATA_$node"
    jq -S -c -n --arg node "$node" --arg unit "$mpquic_unit" \
        --arg mode "$native_mode" --arg namespace "$namespace" \
        --arg namespace_identity "$process_net" --argjson pid "$mpquic_pid" \
        '{node:$node,unit:$unit,mode:$mode,main_pid:$pid,
          network_namespace:$namespace,network_namespace_identity:$namespace_identity,
          api_version:6,socket_verified:true}' >"$WORK/mpquic-record-$node.json"
}

launch_mpquic client "$CLIENT" client
launch_mpquic exit "$EXIT_NODE" exit
verify_mpquic client "$CLIENT" client
verify_mpquic exit "$EXIT_NODE" exit
jq -S -c -s . "$WORK"/mpquic-record-*.json >"$WORK/mpquic-units.json"
MPQUIC_READY=true

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
cat >"$WORK/bin/a05-observer.py" <<'PYTHON'
import json
import select
import signal
import socket
import struct
import sys
import time

role, output_path, ready_path, *interfaces = sys.argv[1:]
if role not in {"client", "exit"} or not interfaces:
    raise SystemExit("invalid bounded observer arguments")

counters = (
    {
        "relay1_wireguard_data_datagrams": 0,
        "relay2_wireguard_data_datagrams": 0,
        "direct_client_exit_packets": 0,
    }
    if role == "client"
    else {
        "relay1_wireguard_data_datagrams": 0,
        "relay2_wireguard_data_datagrams": 0,
        "destination_request_datagrams": 0,
        "destination_response_datagrams": 0,
    }
)
sockets = {}
for interface in interfaces:
    capture = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(0x0800))
    capture.bind((interface, 0))
    capture.setblocking(False)
    sockets[capture] = interface

open(ready_path, "x", encoding="ascii").write("ready\n")
running = True
truncated = False
observed_frames = 0


def stop(*_unused):
    global running
    running = False


signal.signal(signal.SIGTERM, stop)
signal.signal(signal.SIGINT, stop)
deadline = time.monotonic() + 25
while running and time.monotonic() < deadline:
    readable, _, _ = select.select(list(sockets), [], [], 0.2)
    for capture in readable:
        while True:
            try:
                frame = capture.recv(65535)
            except BlockingIOError:
                break
            observed_frames += 1
            if observed_frames > 4096:
                truncated = True
                running = False
                break
            if len(frame) < 34 or struct.unpack("!H", frame[12:14])[0] != 0x0800:
                continue
            offset = 14
            header_length = (frame[offset] & 0x0F) * 4
            if header_length < 20 or len(frame) < offset + header_length:
                continue
            protocol = frame[offset + 9]
            source = socket.inet_ntoa(frame[offset + 12 : offset + 16])
            destination = socket.inet_ntoa(frame[offset + 16 : offset + 20])
            source_port = destination_port = 0
            if protocol == socket.IPPROTO_UDP and len(frame) >= offset + header_length + 4:
                source_port, destination_port = struct.unpack(
                    "!HH", frame[offset + header_length : offset + header_length + 4]
                )
            interface = sockets[capture]
            transport_offset = offset + header_length
            udp_length = 0
            wireguard_message_type = 0
            if protocol == socket.IPPROTO_UDP and len(frame) >= transport_offset + 12:
                udp_length = struct.unpack(
                    "!H", frame[transport_offset + 4 : transport_offset + 6]
                )[0]
                wireguard_message_type = struct.unpack(
                    "<I", frame[transport_offset + 8 : transport_offset + 12]
                )[0]
            # WireGuard type 4 is encrypted transport data. Requiring a UDP length above 40
            # excludes its zero-length keepalive form, so these counters do not mistake a
            # handshake for traffic on an active MPTCP path.
            is_wireguard_data = wireguard_message_type == 4 and udp_length > 40
            if role == "client":
                if source == "43.159.1.1" and destination in {
                    "10.241.21.2",
                    "10.241.22.2",
                    "10.241.31.1",
                    "10.241.31.2",
                    "46.162.3.1",
                }:
                    counters["direct_client_exit_packets"] += 1
                if protocol == socket.IPPROTO_UDP and is_wireguard_data:
                    if interface == "cr1" and source == "43.159.1.1" and destination == "44.160.1.1":
                        counters["relay1_wireguard_data_datagrams"] += 1
                    if interface == "cr2" and source == "43.159.1.1" and destination == "45.161.2.1":
                        counters["relay2_wireguard_data_datagrams"] += 1
            else:
                if protocol == socket.IPPROTO_UDP and is_wireguard_data:
                    if interface == "xr1" and source == "44.160.1.1" and destination == "46.162.3.1":
                        counters["relay1_wireguard_data_datagrams"] += 1
                    if interface == "xr2" and source == "45.161.2.1" and destination == "46.162.3.1":
                        counters["relay2_wireguard_data_datagrams"] += 1
                if interface == "xd" and protocol == socket.IPPROTO_UDP:
                    if destination == "10.241.31.2" and destination_port == 18081:
                        counters["destination_request_datagrams"] += 1
                    if source == "10.241.31.2" and source_port == 18081:
                        counters["destination_response_datagrams"] += 1

for capture in sockets:
    capture.close()
with open(output_path, "x", encoding="ascii") as output:
    json.dump(
        {
            "schema_version": 1,
            "capture_role": role,
            "interfaces": interfaces,
            "observed_frames": observed_frames,
            "truncated": truncated,
            **counters,
        },
        output,
        sort_keys=True,
        separators=(",", ":"),
    )
    output.write("\n")
PYTHON
cat >"$WORK/bin/a02-observer.py" <<'PYTHON'
import json
import select
import signal
import socket
import struct
import sys
import time

role, output_path, ready_path, *interfaces = sys.argv[1:]
if role not in {"client", "exit"} or not interfaces:
    raise SystemExit("invalid bounded A02 observer arguments")

counters = (
    {
        "relay1_wireguard_data_datagrams": 0,
        "relay2_wireguard_data_datagrams": 0,
        "direct_client_exit_packets": 0,
    }
    if role == "client"
    else {
        "relay1_wireguard_data_datagrams": 0,
        "relay2_wireguard_data_datagrams": 0,
        "destination_request_segments": 0,
        "destination_response_segments": 0,
    }
)
sockets = {}
for interface in interfaces:
    capture = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(0x0800))
    capture.bind((interface, 0))
    capture.setblocking(False)
    sockets[capture] = interface

open(ready_path, "x", encoding="ascii").write("ready\n")
running = True
truncated = False
observed_frames = 0


def stop(*_unused):
    global running
    running = False


signal.signal(signal.SIGTERM, stop)
signal.signal(signal.SIGINT, stop)
deadline = time.monotonic() + 180
while running and time.monotonic() < deadline:
    readable, _, _ = select.select(list(sockets), [], [], 0.2)
    for capture in readable:
        while True:
            try:
                frame = capture.recv(65535)
            except BlockingIOError:
                break
            observed_frames += 1
            if observed_frames > 131072:
                truncated = True
                running = False
                break
            if len(frame) < 34 or struct.unpack("!H", frame[12:14])[0] != 0x0800:
                continue
            offset = 14
            header_length = (frame[offset] & 0x0F) * 4
            if header_length < 20 or len(frame) < offset + header_length:
                continue
            protocol = frame[offset + 9]
            source = socket.inet_ntoa(frame[offset + 12 : offset + 16])
            destination = socket.inet_ntoa(frame[offset + 16 : offset + 20])
            source_port = destination_port = 0
            if protocol in {socket.IPPROTO_TCP, socket.IPPROTO_UDP} \
                    and len(frame) >= offset + header_length + 4:
                source_port, destination_port = struct.unpack(
                    "!HH", frame[offset + header_length : offset + header_length + 4]
                )
            interface = sockets[capture]
            transport_offset = offset + header_length
            udp_length = 0
            wireguard_message_type = 0
            if protocol == socket.IPPROTO_UDP and len(frame) >= transport_offset + 12:
                udp_length = struct.unpack(
                    "!H", frame[transport_offset + 4 : transport_offset + 6]
                )[0]
                wireguard_message_type = struct.unpack(
                    "<I", frame[transport_offset + 8 : transport_offset + 12]
                )[0]
            is_wireguard_data = wireguard_message_type == 4 and udp_length > 40
            if role == "client":
                if source == "43.159.1.1" and destination in {
                    "10.241.21.2",
                    "10.241.22.2",
                    "10.241.31.1",
                    "10.241.31.2",
                    "46.162.3.1",
                    "47.163.4.1",
                    "47.163.4.2",
                }:
                    counters["direct_client_exit_packets"] += 1
                if protocol == socket.IPPROTO_UDP and is_wireguard_data:
                    if interface == "cr1" and source == "43.159.1.1" \
                            and destination == "44.160.1.1":
                        counters["relay1_wireguard_data_datagrams"] += 1
                    if interface == "cr2" and source == "43.159.1.1" \
                            and destination == "45.161.2.1":
                        counters["relay2_wireguard_data_datagrams"] += 1
            else:
                if protocol == socket.IPPROTO_UDP and is_wireguard_data:
                    if interface == "xr1" and source == "44.160.1.1" \
                            and destination == "46.162.3.1":
                        counters["relay1_wireguard_data_datagrams"] += 1
                    if interface == "xr2" and source == "45.161.2.1" \
                            and destination == "46.162.3.1":
                        counters["relay2_wireguard_data_datagrams"] += 1
                if interface == "xd" and protocol == socket.IPPROTO_TCP:
                    if destination == "47.163.4.2" and destination_port == 18080:
                        counters["destination_request_segments"] += 1
                    if source == "47.163.4.2" and source_port == 18080:
                        counters["destination_response_segments"] += 1

for capture in sockets:
    capture.close()
with open(output_path, "x", encoding="ascii") as output:
    json.dump(
        {
            "schema_version": 1,
            "capture_role": role,
            "interfaces": interfaces,
            "observed_frames": observed_frames,
            "truncated": truncated,
            **counters,
        },
        output,
        sort_keys=True,
        separators=(",", ":"),
    )
    output.write("\n")
PYTHON
cat >"$WORK/bin/destination.py" <<'PYTHON'
import hashlib
import json
import os
import select
import signal
import socket
import sys

udp = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
udp.bind(("10.241.31.2", 18081))
udp.setblocking(False)
tcp = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
tcp.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
tcp.bind(("47.163.4.2", 18080))
tcp.listen(8)
tcp.setblocking(False)
run_id = bytes.fromhex(sys.argv[4])
tcp_prefix = b"volparossa-a02:" + run_id
tcp_payload_bytes = 4 * 1024 * 1024
open(sys.argv[1], "x", encoding="ascii").write(
    "tcp=47.163.4.2:18080\nudp=10.241.31.2:18081\n"
)
running = True


def stop(*_unused):
    global running
    running = False


signal.signal(signal.SIGTERM, stop)
while running:
    readable, _, _ = select.select([udp, tcp], [], [], 0.5)
    if not readable:
        continue
    if udp in readable:
        payload, source = udp.recvfrom(2048)
        if payload and len(payload) <= 1350:
            sent = udp.sendto(payload, source)
            if sent != len(payload):
                raise SystemExit("short UDP echo")
            evidence = {
                "schema_version": 1,
                "listen": {"ip": "10.241.31.2", "port": 18081},
                "source": {"ip": source[0], "port": source[1]},
                "bytes": len(payload),
                "sha256": hashlib.sha256(payload).hexdigest(),
            }
            if not os.path.exists(sys.argv[2]):
                with open(sys.argv[2], "x", encoding="ascii") as output:
                    json.dump(evidence, output, sort_keys=True, separators=(",", ":"))
                    output.write("\n")
                    output.flush()
                    os.fsync(output.fileno())
            print(json.dumps(evidence, sort_keys=True, separators=(",", ":")), flush=True)
    if tcp in readable:
        connection, source = tcp.accept()
        try:
            connection.settimeout(90)
            received = bytearray()
            while len(received) < tcp_payload_bytes:
                chunk = connection.recv(tcp_payload_bytes - len(received))
                if not chunk:
                    break
                received.extend(chunk)
            if len(received) != tcp_payload_bytes or not received.startswith(tcp_prefix):
                continue
            attempt_offset = len(tcp_prefix)
            attempt = int.from_bytes(received[attempt_offset : attempt_offset + 4], "big")
            if attempt >= 30:
                continue
            seed = tcp_prefix + attempt.to_bytes(4, "big")
            expected_tcp = (seed * ((tcp_payload_bytes + len(seed) - 1) // len(seed)))[
                :tcp_payload_bytes
            ]
            if bytes(received) != expected_tcp:
                continue
            connection.sendall(expected_tcp)
            connection.shutdown(socket.SHUT_WR)
            evidence = {
                "schema_version": 1,
                "listen": {"ip": "47.163.4.2", "port": 18080},
                "source": {"ip": source[0], "port": source[1]},
                "attempt": attempt,
                "bytes": len(received),
                "sha256": hashlib.sha256(received).hexdigest(),
            }
            evidence_path = os.path.join(sys.argv[3], f"tcp-evidence-{attempt}.json")
            if not os.path.exists(evidence_path):
                with open(evidence_path, "x", encoding="ascii") as output:
                    json.dump(evidence, output, sort_keys=True, separators=(",", ":"))
                    output.write("\n")
                    output.flush()
                    os.fsync(output.fileno())
            print(json.dumps(evidence, sort_keys=True, separators=(",", ":")), flush=True)
        finally:
            connection.close()
PYTHON
chown root:root "$WORK/bin/a02-observer.py" "$WORK/bin/a05-observer.py"
chmod 0500 "$WORK/bin/a02-observer.py" "$WORK/bin/a05-observer.py"
chown "root:$AGENT_GID" "$WORK/bin/destination.py"
chmod 0550 "$WORK/bin/destination.py"
ip netns exec "$DEST" setpriv --reuid="$AGENT_UID" --regid="$AGENT_GID" \
    --clear-groups --inh-caps=-all --ambient-caps=-all --bounding-set=-all \
    --no-new-privs -- \
    python3 "$WORK/bin/destination.py" "$WORK/destination/ready" \
    "$WORK/destination/udp-evidence.json" "$WORK/destination" "$RUN_ID" \
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
grep -Fx 'client: false' "$WORK/roles-relay1.txt" >/dev/null || fail RELAY1_CLIENT_ROLE_INVALID
grep -Fx 'client: false' "$WORK/roles-relay2.txt" >/dev/null || fail RELAY2_CLIENT_ROLE_INVALID
grep -Fx 'client: false' "$WORK/roles-exit.txt" >/dev/null || fail EXIT_CLIENT_ROLE_INVALID
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

capture_product_logs() {
    for log_node in client relay1 relay2 exit; do
        "$binary_directory/volparossa" \
            --control-socket "$WORK/runtime-$log_node/control/agent.sock" logs --limit 400 \
            >"$WORK/logs-$log_node.txt" || true
    done
}

wait_observer() {
    observer_pid=$1
    observer_ready=$2
    observer_attempt=0
    while [ "$observer_attempt" -lt 50 ]; do
        [ ! -f "$observer_ready" ] || return 0
        kill -0 "$observer_pid" 2>/dev/null || return 1
        sleep 0.1
        observer_attempt=$((observer_attempt + 1))
    done
    return 1
}

stop_observers() {
    a05_observer_stop_status=0
    for observer_pid in "$CLIENT_OBSERVER_PID" "$EXIT_OBSERVER_PID"; do
        [ -z "$observer_pid" ] || kill -TERM "$observer_pid" 2>/dev/null || true
    done
    if [ -n "$CLIENT_OBSERVER_PID" ] && ! wait "$CLIENT_OBSERVER_PID"; then
        a05_observer_stop_status=1
    fi
    if [ -n "$EXIT_OBSERVER_PID" ] && ! wait "$EXIT_OBSERVER_PID"; then
        a05_observer_stop_status=1
    fi
    CLIENT_OBSERVER_PID=
    EXIT_OBSERVER_PID=
    return "$a05_observer_stop_status"
}

PHASE=a02-capture
A02_REQUESTED=true
A02_FALLBACK_ROUTE=$(ip -n "$CLIENT" -o route get "$A02_DESTINATION_IP" | sed -n '1p')
printf '%s\n' "$A02_FALLBACK_ROUTE" >"$WORK/a02-client-fallback-route.txt"
printf '%s\n' "$A02_FALLBACK_ROUTE" | grep -Eq '(^| )dev underlay( |$)' \
    || fail A02_FALLBACK_ROUTE_INVALID
if printf '%s\n' "$A02_FALLBACK_ROUTE" | grep -Eq '(^| )dev (cr1|cr2)( |$)'; then
    fail DIRECT_CLIENT_EXIT_REACHABLE
fi

PHASE=a02-transparent-tcp-echo
: >"$WORK/a02-client.err"
attempt=0
while [ "$attempt" -lt 30 ]; do
    attempt_label=$(printf '%02d' "$attempt")
    client_capture="$WORK/a02-client-capture-$attempt_label.json"
    client_capture_ready="$WORK/a02-client-capture-$attempt_label.ready"
    exit_capture="$WORK/a02-exit-capture-$attempt_label.json"
    exit_capture_ready="$WORK/a02-exit-capture-$attempt_label.ready"
    destination_evidence="$WORK/destination/tcp-evidence-$attempt.json"

    ip netns exec "$CLIENT" python3 "$WORK/bin/a02-observer.py" \
        client "$client_capture" "$client_capture_ready" \
        cr1 cr2 underlay >"$WORK/a02-client-capture.log" \
        2>"$WORK/a02-client-capture.err" &
    CLIENT_OBSERVER_PID=$!
    ip netns exec "$EXIT_NODE" python3 "$WORK/bin/a02-observer.py" \
        exit "$exit_capture" "$exit_capture_ready" \
        xr1 xr2 xd >"$WORK/a02-exit-capture.log" \
        2>"$WORK/a02-exit-capture.err" &
    EXIT_OBSERVER_PID=$!
    wait_observer "$CLIENT_OBSERVER_PID" "$client_capture_ready" \
        || fail A02_CLIENT_CAPTURE_UNAVAILABLE
    wait_observer "$EXIT_OBSERVER_PID" "$exit_capture_ready" \
        || fail A02_EXIT_CAPTURE_UNAVAILABLE

    set +e
    ip netns exec "$CLIENT" setpriv --reuid="$WORKER_UID" --regid="$WORKER_GID" \
        --clear-groups --inh-caps=-all --ambient-caps=-all --bounding-set=-all \
        --no-new-privs -- python3 - "$RUN_ID" "$attempt" >"$WORK/a02-client.json" \
        2>>"$WORK/a02-client.err" <<'PYTHON'
import hashlib
import json
import socket
import sys

attempt = int(sys.argv[2])
seed = b"volparossa-a02:" + bytes.fromhex(sys.argv[1]) + attempt.to_bytes(4, "big")
payload_bytes = 4 * 1024 * 1024
payload = (seed * ((payload_bytes + len(seed) - 1) // len(seed)))[:payload_bytes]
destination = ("47.163.4.2", 18080)
with socket.create_connection(destination, timeout=60) as application:
    application.settimeout(90)
    application.sendall(payload)
    application.shutdown(socket.SHUT_WR)
    response = bytearray()
    while len(response) <= len(payload):
        chunk = application.recv(min(4096, len(payload) + 1 - len(response)))
        if not chunk:
            break
        response.extend(chunk)
    local = application.getsockname()
if bytes(response) != payload:
    raise SystemExit("application received a substituted TCP response")
json.dump(
    {
        "schema_version": 1,
        "attempt": attempt,
        "application": {"ip": local[0], "port": local[1]},
        "destination": {"ip": destination[0], "port": destination[1]},
        "response_source": {"ip": destination[0], "port": destination[1]},
        "sent_bytes": len(payload),
        "response_bytes": len(response),
        "sent_sha256": hashlib.sha256(payload).hexdigest(),
        "response_sha256": hashlib.sha256(response).hexdigest(),
    },
    sys.stdout,
    sort_keys=True,
    separators=(",", ":"),
)
sys.stdout.write("\n")
PYTHON
    A02_STATUS=$?
    set -e
    evidence_attempt=0
    while [ "$A02_STATUS" -eq 0 ] && [ "$evidence_attempt" -lt 100 ] \
        && [ ! -s "$destination_evidence" ]; do
        sleep 0.1
        evidence_attempt=$((evidence_attempt + 1))
    done
    if ! stop_observers; then
        A02_STATUS=1
    fi
    for evidence_file in "$WORK/a02-client.json" "$destination_evidence" \
        "$client_capture" "$exit_capture"; do
        if [ "$A02_STATUS" -eq 0 ] \
            && { [ ! -s "$evidence_file" ] \
                || ! jq -e . "$evidence_file" >/dev/null 2>&1; }; then
            A02_STATUS=1
        fi
    done
    if [ "$A02_STATUS" -eq 0 ]; then
        install -o root -g root -m 0600 \
            "$destination_evidence" "$WORK/destination-tcp-evidence.json"
        install -o root -g root -m 0600 \
            "$client_capture" "$WORK/a02-client-capture.json"
        install -o root -g root -m 0600 \
            "$exit_capture" "$WORK/a02-exit-capture.json"
        break
    fi
    sleep 1
    attempt=$((attempt + 1))
done

log_attempt=0
while [ "$A02_STATUS" -eq 0 ] && [ "$log_attempt" -lt 300 ]; do
    capture_product_logs
    grep -F 'event=INGRESS_TCP_STREAM_COMPLETED' "$WORK/logs-client.txt" >/dev/null \
        && grep -F 'event=MPTCP_SESSION_RELAY_COMPLETED' "$WORK/logs-relay1.txt" >/dev/null \
        && grep -F 'event=MPTCP_SESSION_RELAY_COMPLETED' "$WORK/logs-relay2.txt" >/dev/null \
        && grep -F 'event=MPTCP_EXIT_FLOW_COMPLETED' "$WORK/logs-exit.txt" >/dev/null \
        && break
    sleep 0.1
    log_attempt=$((log_attempt + 1))
done
capture_product_logs

for evidence_file in a02-client.json destination-tcp-evidence.json \
    a02-client-capture.json a02-exit-capture.json; do
    if [ ! -s "$WORK/$evidence_file" ] \
        || ! jq -e . "$WORK/$evidence_file" >/dev/null 2>&1; then
        A02_STATUS=1
    fi
done

if [ "$A02_STATUS" -eq 0 ]; then
    CLIENT_INGRESS_EVENT=false
    RELAY1_MPTCP_EVENT=false
    RELAY2_MPTCP_EVENT=false
    EXIT_MPTCP_EVENT=false
    grep -F 'event=INGRESS_TCP_STREAM_COMPLETED' "$WORK/logs-client.txt" >/dev/null \
        && CLIENT_INGRESS_EVENT=true
    grep -F 'event=MPTCP_SESSION_RELAY_COMPLETED' "$WORK/logs-relay1.txt" >/dev/null \
        && RELAY1_MPTCP_EVENT=true
    grep -F 'event=MPTCP_SESSION_RELAY_COMPLETED' "$WORK/logs-relay2.txt" >/dev/null \
        && RELAY2_MPTCP_EVENT=true
    grep -F 'event=MPTCP_EXIT_FLOW_COMPLETED' "$WORK/logs-exit.txt" >/dev/null \
        && EXIT_MPTCP_EVENT=true
    jq -S -c -n \
        --slurpfile application "$WORK/a02-client.json" \
        --slurpfile destination "$WORK/destination-tcp-evidence.json" \
        --slurpfile client_capture "$WORK/a02-client-capture.json" \
        --slurpfile exit_capture "$WORK/a02-exit-capture.json" \
        --arg fallback_route "$A02_FALLBACK_ROUTE" \
        --arg exit_source "$A02_EXIT_SOURCE" \
        --argjson route_absent "$CLIENT_EXIT_ROUTE_ABSENT" \
        --argjson ingress_event "$CLIENT_INGRESS_EVENT" \
        --argjson relay1_event "$RELAY1_MPTCP_EVENT" \
        --argjson relay2_event "$RELAY2_MPTCP_EVENT" \
        --argjson exit_event "$EXIT_MPTCP_EVENT" \
        '($application[0]) as $app
        | ($destination[0]) as $destination
        | ($client_capture[0]) as $client
        | ($exit_capture[0]) as $exit
        | (($app.destination == {ip:"47.163.4.2",port:18080})
            and ($app.attempt == $destination.attempt)
            and ($app.response_source == $app.destination)
            and ($app.sent_bytes == $app.response_bytes)
            and ($app.sent_sha256 == $app.response_sha256)
            and ($app.sent_bytes == $destination.bytes)
            and ($app.sent_sha256 == $destination.sha256)
            and ($destination.listen == $app.destination)
            and ($destination.source.ip == $exit_source)
            and $route_absent
            and ($client.relay1_wireguard_data_datagrams > 0)
            and ($client.relay2_wireguard_data_datagrams > 0)
            and ($exit.relay1_wireguard_data_datagrams > 0)
            and ($exit.relay2_wireguard_data_datagrams > 0)
            and ($client.direct_client_exit_packets == 0)
            and ($client.truncated == false)
            and ($exit.truncated == false)
            and ($exit.destination_request_segments > 0)
            and ($exit.destination_response_segments > 0)
            and $ingress_event and $relay1_event and $relay2_event and $exit_event) as $success
        | {schema_version:1,acceptance_id:"A02",success:$success,
           transport:"IPPROTO_MPTCP over two Relay WireGuard paths, TLS 1.3",
           application:$app,destination_echo:$destination,
           path_evidence:{client_capture:$client,exit_capture:$exit,
             relay_only_path_count:2,relay1_session_completed:$relay1_event,
             relay2_session_completed:$relay2_event},
           protected_flow:{helper_tproxy_ingress_completed:$ingress_event,
             kernel_mptcp_negotiation_gate_passed:$exit_event,
             tls_1_3_gate_passed:$exit_event,signed_open_tcp_gate_passed:$exit_event,
             ordinary_tcp_fallback_allowed:false},
           no_direct_client_exit:{topology_adjacency:false,route_absent:$route_absent,
             fallback_route:$fallback_route,
             observed_packets:$client.direct_client_exit_packets}}' \
        >"$WORK/a02-evidence.json"
    jq -e '.success == true' "$WORK/a02-evidence.json" >/dev/null 2>&1 \
        || A02_STATUS=1
fi

if [ "$A02_STATUS" -ne 0 ]; then
    OBSERVED_BLOCKER=$(grep -Eo 'event=INGRESS_TCP_[A-Z0-9_]+' \
        "$WORK/logs-client.txt" 2>/dev/null | tail -n 1 | sed 's/^event=//' || true)
    [ -n "$OBSERVED_BLOCKER" ] || OBSERVED_BLOCKER=A02_TRANSPARENT_TCP_UNAVAILABLE
    PHASE=a02-blocked
    exit 77
fi

A02_SUCCEEDED=true
OBSERVED_BLOCKER=NONE
PHASE=a02-complete

PHASE=client-connect
CONNECT_REQUESTED=true
attempt=0
while [ "$attempt" -lt 30 ]; do
    set +e
    "$binary_directory/volparossa" \
        --control-socket "$WORK/runtime-client/control/agent.sock" connect \
        >"$WORK/connect-client.out" 2>"$WORK/connect-client.err"
    CONNECT_STATUS=$?
    set -e
    [ "$CONNECT_STATUS" -ne 0 ] || break
    grep -F 'PRESELECTION_UNAVAILABLE' "$WORK/connect-client.err" >/dev/null \
        || break
    sleep 1
    attempt=$((attempt + 1))
done
capture_product_logs

if [ "$CONNECT_STATUS" -ne 0 ]; then
    OBSERVED_BLOCKER=$(grep -Eo 'event=[A-Z0-9_]*(UNAVAILABLE|FAILED|DENIED|REJECTED)[A-Z0-9_]*' \
        "$WORK/logs-client.txt" 2>/dev/null | tail -n 1 | sed 's/^event=//' || true)
    [ -n "$OBSERVED_BLOCKER" ] || OBSERVED_BLOCKER=CONNECT_EXIT_NONZERO
    PHASE=connect-blocked
    exit 77
fi
CONNECT_SUCCEEDED=true
OBSERVED_BLOCKER=NONE

PHASE=a05-capture
A05_REQUESTED=true
# Local-output netfilter needs an initial route lookup before the production route-chain can steer
# the datagram. The only fallback is the peerless dummy underlay, never a Relay or Exit link; the
# passive observer below treats any packet that leaks onto it as a direct-path failure.
ip -n "$CLIENT" route del unreachable 10.241.31.2/32
A05_FALLBACK_ROUTE=$(ip -n "$CLIENT" -o route get 10.241.31.2 | sed -n '1p')
printf '%s\n' "$A05_FALLBACK_ROUTE" >"$WORK/a05-client-fallback-route.txt"
printf '%s\n' "$A05_FALLBACK_ROUTE" | grep -Eq '(^| )dev underlay( |$)' \
    || fail A05_FALLBACK_ROUTE_INVALID
if printf '%s\n' "$A05_FALLBACK_ROUTE" | grep -Eq '(^| )dev (cr1|cr2)( |$)'; then
    fail DIRECT_CLIENT_EXIT_REACHABLE
fi

ip netns exec "$CLIENT" python3 "$WORK/bin/a05-observer.py" \
    client "$WORK/a05-client-capture.json" "$WORK/a05-client-capture.ready" \
    cr1 cr2 underlay >"$WORK/a05-client-capture.log" \
    2>"$WORK/a05-client-capture.err" &
CLIENT_OBSERVER_PID=$!
ip netns exec "$EXIT_NODE" python3 "$WORK/bin/a05-observer.py" \
    exit "$WORK/a05-exit-capture.json" "$WORK/a05-exit-capture.ready" \
    xr1 xr2 xd >"$WORK/a05-exit-capture.log" \
    2>"$WORK/a05-exit-capture.err" &
EXIT_OBSERVER_PID=$!
wait_observer "$CLIENT_OBSERVER_PID" "$WORK/a05-client-capture.ready" \
    || fail A05_CLIENT_CAPTURE_UNAVAILABLE
wait_observer "$EXIT_OBSERVER_PID" "$WORK/a05-exit-capture.ready" \
    || fail A05_EXIT_CAPTURE_UNAVAILABLE

PHASE=a05-udp-echo
set +e
ip netns exec "$CLIENT" setpriv --reuid="$WORKER_UID" --regid="$WORKER_GID" \
    --clear-groups --inh-caps=-all --ambient-caps=-all --bounding-set=-all \
    --no-new-privs -- python3 - "$RUN_ID" >"$WORK/a05-client.json" \
    2>"$WORK/a05-client.err" <<'PYTHON'
import hashlib
import json
import socket
import sys

payload = b"volparossa-a05:" + bytes.fromhex(sys.argv[1])
destination = ("10.241.31.2", 18081)
application = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
application.bind(("43.159.1.1", 0))
application.settimeout(20)
sent = application.sendto(payload, destination)
if sent != len(payload):
    raise SystemExit("short application UDP send")
response, source = application.recvfrom(2048)
if source != destination or response != payload:
    raise SystemExit("application received a substituted UDP response")
local = application.getsockname()
json.dump(
    {
        "schema_version": 1,
        "application": {"ip": local[0], "port": local[1]},
        "destination": {"ip": destination[0], "port": destination[1]},
        "response_source": {"ip": source[0], "port": source[1]},
        "sent_bytes": len(payload),
        "response_bytes": len(response),
        "sent_sha256": hashlib.sha256(payload).hexdigest(),
        "response_sha256": hashlib.sha256(response).hexdigest(),
    },
    sys.stdout,
    sort_keys=True,
    separators=(",", ":"),
)
sys.stdout.write("\n")
PYTHON
A05_STATUS=$?
set -e
sleep 1
if ! stop_observers; then
    A05_STATUS=1
fi
if [ -f "$WORK/destination/udp-evidence.json" ] \
    && [ ! -L "$WORK/destination/udp-evidence.json" ]; then
    install -o root -g root -m 0600 \
        "$WORK/destination/udp-evidence.json" \
        "$WORK/destination-udp-evidence.json"
fi
capture_product_logs

for evidence_file in a05-client.json destination-udp-evidence.json \
    a05-client-capture.json a05-exit-capture.json; do
    if [ ! -s "$WORK/$evidence_file" ] \
        || ! jq -e . "$WORK/$evidence_file" >/dev/null 2>&1; then
        A05_STATUS=1
    fi
done

if [ "$A05_STATUS" -eq 0 ]; then
    jq -S -c -n \
        --slurpfile application "$WORK/a05-client.json" \
        --slurpfile destination "$WORK/destination-udp-evidence.json" \
        --slurpfile client_capture "$WORK/a05-client-capture.json" \
        --slurpfile exit_capture "$WORK/a05-exit-capture.json" \
        --arg fallback_route "$A05_FALLBACK_ROUTE" \
        '($application[0]) as $app
        | ($destination[0]) as $destination
        | ($client_capture[0]) as $client
        | ($exit_capture[0]) as $exit
        | (if $client.relay1_wireguard_data_datagrams > 0
              and $client.relay2_wireguard_data_datagrams == 0
              and $exit.relay1_wireguard_data_datagrams > 0
              and $exit.relay2_wireguard_data_datagrams == 0 then "relay1"
           elif $client.relay2_wireguard_data_datagrams > 0
              and $client.relay1_wireguard_data_datagrams == 0
              and $exit.relay2_wireguard_data_datagrams > 0
              and $exit.relay1_wireguard_data_datagrams == 0 then "relay2"
           else "ambiguous" end) as $selected
        | (($app.destination == {ip:"10.241.31.2",port:18081})
            and ($app.response_source == $app.destination)
            and ($app.sent_bytes == $app.response_bytes)
            and ($app.sent_sha256 == $app.response_sha256)
            and ($app.sent_bytes == $destination.bytes)
            and ($app.sent_sha256 == $destination.sha256)
            and ($destination.listen == $app.destination)
            and ($selected != "ambiguous")
            and ($client.direct_client_exit_packets == 0)
            and ($client.truncated == false)
            and ($exit.truncated == false)
            and ($exit.destination_request_datagrams > 0)
            and ($exit.destination_response_datagrams > 0)) as $success
        | {schema_version:1,acceptance_id:"A05",success:$success,
           transport:"single-path QUIC MASQUE UDP",
           application:$app,destination_echo:$destination,selected_relay:$selected,
           path_evidence:{client_capture:$client,exit_capture:$exit},
           no_direct_client_exit:{topology_adjacency:false,
             fallback_route:$fallback_route,
             observed_packets:$client.direct_client_exit_packets}}' \
        >"$WORK/a05-evidence.json"
    jq -e '.success == true' "$WORK/a05-evidence.json" >/dev/null 2>&1 \
        || A05_STATUS=1
fi

if [ "$A05_STATUS" -ne 0 ]; then
    OBSERVED_BLOCKER=$(grep -Eo 'event=INGRESS_UDP_[A-Z0-9_]+' \
        "$WORK/logs-client.txt" 2>/dev/null | tail -n 1 | sed 's/^event=//' || true)
    [ -n "$OBSERVED_BLOCKER" ] || OBSERVED_BLOCKER=A05_UDP_ECHO_UNAVAILABLE
    PHASE=a05-blocked
    exit 77
fi

A05_SUCCEEDED=true
OBSERVED_BLOCKER=NONE
PHASE=a05-complete
exit 0
