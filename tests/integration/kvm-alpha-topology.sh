#!/bin/sh
# SPDX-License-Identifier: GPL-3.0-only
# Run the twelve-node development-alpha topology with one real production helper per agent.
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
        '  create Client, two replaceable bootstrap contacts, six Relays, two Exits and one destination namespace;' \
        '  give each product node one disposable public underlay and fail-closed default;' \
        '  create only bootstrap-contact, Client-Relay, Relay-Exit and Exit-destination underlay links;' \
        '  launch eleven distinct transient production-helper service instances;' \
        '  launch real pinned mqvpn/xquic processes for the Client and both Exits;' \
        '  bind each helper and agent privately to its node-owned /run/volparossa;' \
        '  prove GetUnitByPID, MainPID, cgroup, network namespace and FD-store binding;' \
        '  launch eleven real agents and exact-policy TCP/UDP echo applications;' \
        '  remove each bootstrap contact independently and prove fresh advertisements plus route selection;' \
        '  prove transparent TCP over Relay-only MPTCP/TLS and signed OPEN_TCP;' \
        '  constrain each Relay path and prove aggregate MPTCP download throughput;' \
        '  remove one data-carrying Relay during a second uninterrupted download;' \
        '  request UDP Connect, then send one non-trusted application datagram through ingress;' \
        '  send two deterministic real HTTP/3 transfers over the native MPQUIC route;' \
        '  remove one MPQUIC Relay while the second HTTP/3 transfer remains active;' \
        '  prove allowed visible-name TLS and deny forbidden SNI, ECH, IP and port flows;' \
        '  prove exact replies, selected Relays and zero direct Client-Exit packets;' \
        '  prove Relay/Exit/Client packet-metadata privacy without retaining payloads;' \
        '  SIGKILL agent, native and helper units, then remove every owned object;' \
        '  compare exact guest-root routes, DNS, nftables, links, sysctls and VPN state;' \
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

for command_name in awk busctl cat chmod chown cut date find getent grep install ip jq kill \
    mkdir mktemp nft python3 readlink rm runuser sed setpriv sha256sum sleep sort stat \
    systemctl systemd-run systemd-sysusers tail tc timeout tr wg; do
    command -v "$command_name" >/dev/null 2>&1 \
        || { printf 'required guest tool unavailable: %s\n' "$command_name" >&2; exit 69; }
done
for executable in volparossa volparossa-agent volparossa-helper; do
    [ -x "$binary_directory/$executable" ] \
        || { printf 'required product executable unavailable: %s\n' "$executable" >&2; exit 69; }
done
[ -x "$binary_directory/examples/acceptance-policy-fixture" ] \
    || { printf '%s\n' 'acceptance policy fixture unavailable' >&2; exit 69; }
[ -x "$binary_directory/examples/http3-acceptance-fixture" ] \
    || { printf '%s\n' 'HTTP/3 acceptance fixture unavailable' >&2; exit 69; }
[ -x "$binary_directory/examples/tls-policy-acceptance-fixture" ] \
    || { printf '%s\n' 'TLS policy acceptance fixture unavailable' >&2; exit 69; }
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
B1=$PREFIX-b1
B2=$PREFIX-b2
R0=$PREFIX-r0
R1=$PREFIX-r1
R2=$PREFIX-r2
R3=$PREFIX-r3
R4=$PREFIX-r4
R5=$PREFIX-r5
EXIT_NODE=$PREFIX-x
EXIT2_NODE=$PREFIX-x2
DEST=$PREFIX-d
A02_DESTINATION_IP=47.163.4.2
A02_EXIT_SOURCE=47.163.4.1
# PrivateTmp is part of both production service sandboxes and Debian mounts its
# runtime tmpfs non-executable. Keep this disposable-VM stage on the executable
# root filesystem so both transient units see and can execute the exact build.
# Keep every nested AF_UNIX path below Linux SUN_LEN, including the longest
# bootstrap control socket, while retaining a run-bound disposable root.
WORK=$(mktemp -d "/opt/va.$RUN_ID.XXXXXX")
case $WORK in /opt/va.*) ;; *) exit 69 ;; esac
longest_control_socket=$WORK/runtime-bootstrap1/control/agent.sock
[ "${#longest_control_socket}" -lt 108 ] || exit 69
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
A01_REQUESTED=false
A01_SUCCEEDED=false
A01_STATUS=-1
A02_REQUESTED=false
A02_SUCCEEDED=false
A02_STATUS=-1
A03_REQUESTED=false
A03_SUCCEEDED=false
A03_STATUS=-1
A04_REQUESTED=false
A04_SUCCEEDED=false
A04_STATUS=-1
A05_REQUESTED=false
A05_SUCCEEDED=false
A05_STATUS=-1
A06_REQUESTED=false
A06_SUCCEEDED=false
A06_STATUS=-1
A07_REQUESTED=false
A07_SUCCEEDED=false
A07_STATUS=-1
A08_REQUESTED=false
A08_SUCCEEDED=false
A08_STATUS=-1
A09_REQUESTED=false
A09_SUCCEEDED=false
A09_STATUS=-1
A10_REQUESTED=false
A10_SUCCEEDED=false
A10_STATUS=-1
A11_REQUESTED=false
A11_SUCCEEDED=false
A11_STATUS=-1
A12_REQUESTED=false
A12_SUCCEEDED=false
A12_STATUS=-1
A13_REQUESTED=false
A13_SUCCEEDED=false
A13_STATUS=-1
A14_REQUESTED=false
A14_SUCCEEDED=false
A14_STATUS=-1
A15_REQUESTED=false
A15_SUCCEEDED=false
A15_STATUS=-1
OBSERVED_BLOCKER=NOT_REACHED
CLEANUP_COMPLETE=false
CLIENT_EXIT_ROUTE_ABSENT=false
REMAINING_NAMESPACES=-1
REMAINING_UNITS=-1
REMAINING_OWNED_OBJECTS=-1
HELPER_UNITS=
MPQUIC_UNITS=
AGENT_UNITS=
DESTINATION_PID=
HTTP3_SERVER_PID=
HTTP3_CLIENT_PID=
TLS_POLICY_SERVER_PID=
HOSTS_BACKUP=
DOWNLOAD_CLIENT_PID=
CLIENT_OBSERVER_PID=
EXIT_OBSERVER_PID=
PRIVACY_CLIENT_PID=
PRIVACY_RELAY1_PID=
PRIVACY_RELAY2_PID=
PRIVACY_EXIT_PID=
FINALIZED=no

capture_host_state() {
    host_state_output=$1
    host_state_stage=$WORK/host-state-stage
    install -d -o root -g root -m 0700 "$host_state_stage"

    ip -j -details link show | jq -S '
      [.[] | {ifindex,ifname,link_index,link_type,mtu,qdisc,operstate,
        linkmode,group,flags,address,broadcast,master,
        info_kind:(.linkinfo.info_kind // null)}] | sort_by(.ifindex)' \
        >"$host_state_stage/links.json"
    ip -j address show | jq -S '
      [.[] | {ifindex,ifname,flags,mtu,qdisc,operstate,group,link_type,
        address,broadcast,addr_info:[.addr_info[] | {family,local,prefixlen,
          broadcast,scope,label,dynamic,noprefixroute,temporary}]}]
      | sort_by(.ifindex)' >"$host_state_stage/addresses.json"
    ip -j route show table all | jq -S '
      [.[] | {dst,src,gateway,dev,protocol,scope,type,table,prefsrc,metric,
        flags,mtu,nhid,nexthops}] | sort_by([.table,.dst,.dev,.gateway,.src])' \
        >"$host_state_stage/routes.json"
    ip -j rule show | jq -S 'sort_by([.priority,.family,.table,.from,.to])' \
        >"$host_state_stage/rules.json"
    nft -j list ruleset | jq -S 'del(.nftables[] | select(has("metainfo")))' \
        >"$host_state_stage/nftables.json"
    wg show all dump | sort >"$host_state_stage/wireguard.txt"
    ip netns list | sort >"$host_state_stage/namespaces.txt"
    jq -S -n \
        --arg resolv_path "$(readlink -f -- /etc/resolv.conf)" \
        --arg resolv_sha256 "$(sha256sum /etc/resolv.conf | awk '{print $1}')" \
        --arg ipv4_forward "$(cat /proc/sys/net/ipv4/ip_forward)" \
        --arg ipv4_all_forwarding "$(cat /proc/sys/net/ipv4/conf/all/forwarding)" \
        --arg ipv4_src_valid_mark "$(cat /proc/sys/net/ipv4/conf/all/src_valid_mark)" \
        --arg ipv6_forward "$(cat /proc/sys/net/ipv6/conf/all/forwarding)" \
        --slurpfile links "$host_state_stage/links.json" \
        --slurpfile addresses "$host_state_stage/addresses.json" \
        --slurpfile routes "$host_state_stage/routes.json" \
        --slurpfile rules "$host_state_stage/rules.json" \
        --slurpfile nftables "$host_state_stage/nftables.json" \
        --rawfile wireguard "$host_state_stage/wireguard.txt" \
        --rawfile namespaces "$host_state_stage/namespaces.txt" \
        '{schema_version:1,scope:"disposable KVM guest root network namespace",
          links:$links[0],addresses:$addresses[0],routes:$routes[0],rules:$rules[0],
          dns:{resolv_conf_path:$resolv_path,resolv_conf_sha256:$resolv_sha256},
          nftables:$nftables[0],wireguard_dump:$wireguard,
          named_network_namespaces:$namespaces,
          sysctls:{ipv4_forward:$ipv4_forward,
            ipv4_all_forwarding:$ipv4_all_forwarding,
            ipv4_src_valid_mark:$ipv4_src_valid_mark,
            ipv6_all_forwarding:$ipv6_forward}}' >"$host_state_output"
    rm -f "$host_state_stage/links.json" "$host_state_stage/addresses.json" \
        "$host_state_stage/routes.json" "$host_state_stage/rules.json" \
        "$host_state_stage/nftables.json" "$host_state_stage/wireguard.txt" \
        "$host_state_stage/namespaces.txt"
}

copy_artifacts() {
    for artifact in \
        connect-client.out connect-client.err \
        logs-client.txt logs-bootstrap1.txt logs-bootstrap2.txt \
        logs-relay0.txt logs-relay1.txt logs-relay2.txt logs-relay3.txt \
        logs-relay4.txt logs-relay5.txt logs-exit.txt logs-exit2.txt \
        peers-client.txt peers-bootstrap1.txt peers-bootstrap2.txt \
        peers-relay0.txt peers-relay1.txt peers-relay2.txt peers-relay3.txt \
        peers-relay4.txt peers-relay5.txt peers-exit.txt peers-exit2.txt \
        status-client.txt status-relay0.txt status-relay1.txt status-relay2.txt \
        status-relay3.txt status-relay4.txt status-relay5.txt status-exit.txt status-exit2.txt \
        roles-client.txt roles-relay0.txt roles-relay1.txt roles-relay2.txt \
        roles-relay3.txt roles-relay4.txt roles-relay5.txt roles-exit.txt roles-exit2.txt \
        helper-client.log helper-relay0.log helper-relay1.log helper-relay2.log \
        helper-relay3.log helper-relay4.log helper-relay5.log helper-exit.log helper-exit2.log \
        mpquic-client.log mpquic-exit.log mpquic-exit2.log mpquic-units.json \
        agent-client.log agent-bootstrap1.log agent-bootstrap2.log \
        agent-relay0.log agent-relay1.log agent-relay2.log agent-relay3.log \
        agent-relay4.log agent-relay5.log agent-exit.log agent-exit2.log \
        helper-bootstrap1.log helper-bootstrap2.log \
        worker-network-diagnostics.txt \
        status-bootstrap1.txt status-bootstrap2.txt \
        roles-bootstrap1.txt roles-bootstrap2.txt \
        a01-bootstrap1-blocked.json a01-bootstrap2-blocked.json \
        a01-bootstrap1-remaining-link-before.json \
        a01-bootstrap1-remaining-link-after.json \
        a01-bootstrap2-remaining-link-before.json \
        a01-bootstrap2-remaining-link-after.json \
        a01-expected-peers.json a01-initial-peers.txt topology-scale.json \
        a01-bootstrap1-connect.out a01-bootstrap1-connect.err \
        a01-bootstrap1-paths.txt a01-bootstrap1-selection.json \
        a01-bootstrap1-disconnect.out a01-bootstrap1-disconnect.err \
        a01-bootstrap2-connect.out a01-bootstrap2-connect.err \
        a01-bootstrap2-paths.txt a01-bootstrap2-selection.json \
        a01-bootstrap2-disconnect.out a01-bootstrap2-disconnect.err \
        a01-evidence.json \
        destination.log destination-tcp-evidence.json destination-udp-evidence.json \
        helper-units.json a02-client.json a02-client.err a02-client-fallback-route.txt \
        a02-client-capture.json a02-client-capture.log a02-client-capture.err \
        a02-exit-capture.json a02-exit-capture.log a02-exit-capture.err \
        a02-first-failed-client-capture.json \
        a02-first-failed-exit-capture.json \
        a02-evidence.json \
        a03-single-client.json a03-single-client.err \
        a03-single-client-capture.json a03-single-exit-capture.json \
        a03-aggregate-client.json a03-aggregate-client.err \
        a03-aggregate-client-capture.json a03-aggregate-exit-capture.json \
        destination-a03-single-evidence.json destination-a03-aggregate-evidence.json \
        a03-tc-before.json a03-tc-after.json a03-evidence.json \
        a04-client.json a04-client.err a04-client-capture.json \
        a04-exit-capture.json destination-a04-evidence.json \
        a04-removal.json a04-evidence.json \
        a05-client.json a05-client.err a05-client-fallback-route.txt \
        a05-client-capture.json a05-client-capture.log a05-client-capture.err \
        a05-exit-capture.json a05-exit-capture.log a05-exit-capture.err \
        a05-evidence.json \
        http3-server.log a06-disconnect.out a06-disconnect.err \
        a06-connect.out a06-connect.err \
        a06-preconnect-native-paths.txt a06-preconnect-native-paths.json \
        a06-client.json a06-client.err \
        destination-a06-evidence.json a06-client-fallback-route.txt \
        a06-client-capture.json a06-client-capture.log a06-client-capture.err \
        a06-exit-capture.json a06-exit-capture.log a06-exit-capture.err \
        a06-native-paths.txt a06-native-paths.json a06-evidence.json \
        a07-client.json a07-client.err destination-a07-evidence.json \
        a07-client-capture.json a07-client-capture.log a07-client-capture.err \
        a07-exit-capture.json a07-exit-capture.log a07-exit-capture.err \
        a07-native-before.txt a07-native-before.json \
        a07-native-after.txt a07-native-after.json \
        a07-removal.json a07-evidence.json \
        tls-policy-server.log a08-exit-host-lookup.txt \
        a08-dns-udp.json a08-dns-udp.err a08-dns-tcp.json a08-dns-tcp.err \
        a08-client.json a08-client.err a08-destination.json a08-evidence.json \
        a09-unlisted-domain.json a09-unlisted-domain.err \
        a09-raw-ip-server-name.json a09-raw-ip-server-name.err \
        a09-missing-server-name.json a09-missing-server-name.err \
        a09-mismatched-destination.json a09-mismatched-destination.err \
        a09-forbidden-port.json a09-forbidden-port.err a09-evidence.json \
        a10-ech.json a10-ech.err a10-unverifiable.json a10-unverifiable.err \
        a10-evidence.json tls-policy-destination-final.json \
        privacy-client.json privacy-relay1.json privacy-relay2.json privacy-exit.json \
        privacy-client.log privacy-relay1.log privacy-relay2.log privacy-exit.log \
        a11-evidence.json a12-evidence.json a13-evidence.json \
        a13-client-routes-before.json a13-client-routes-after.json \
        a13-exit-route-before.txt a13-exit-route-after.txt \
        a13-destination-route-before.txt a13-destination-route-after.txt \
        a14-refresh-disconnect.out a14-refresh-disconnect.err \
        a14-refresh-connect.out a14-refresh-connect.err \
        a14-owned-before.json a14-worker-custody-before.json \
        a14-worker-custody-after.json a14-owned-after-paths.txt a14-paths-before.txt \
        a14-crashes.json a14-helper-restarts.json a14-evidence.json \
        host-state-before.json host-state-after.json a15-evidence.json; do
        if [ -f "$WORK/$artifact" ] && [ ! -L "$WORK/$artifact" ]; then
            install -o "$OUTPUT_UID" -g "$OUTPUT_GID" -m 0600 \
                "$WORK/$artifact" "$output_directory/$artifact"
        fi
    done
}

# Retain the live anonymous worker namespaces on an early datapath failure. This contains only
# public interface, route, WireGuard-counter and nftables state; private keys are never emitted.
capture_worker_network_diagnostics() {
    diagnostic_label=${1:-cleanup}
    printf 'capture=%s\n' "$diagnostic_label" \
        >>"$WORK/worker-network-diagnostics.txt"
    for diagnostic_node in client relay1 relay2 exit; do
        diagnostic_unit=volparossa-alpha-helper@$diagnostic_node.service
        diagnostic_cgroup=$(systemctl show --property=ControlGroup --value \
            "$diagnostic_unit" 2>/dev/null || true)
        case $diagnostic_cgroup in /system.slice/*) ;; *) continue ;; esac
        diagnostic_cgroup_root=/sys/fs/cgroup$diagnostic_cgroup
        [ -d "$diagnostic_cgroup_root" ] || continue
        diagnostic_pids=$(find "$diagnostic_cgroup_root" -type f -name cgroup.procs \
            -exec cat {} \; 2>/dev/null | sort -nu | tr '\n' ' ')
        printf 'unit=%s cgroup=%s pids=%s\n' "$diagnostic_unit" \
            "$diagnostic_cgroup" "$diagnostic_pids" \
            >>"$WORK/worker-network-diagnostics.txt"
        for diagnostic_pid in $diagnostic_pids; do
            [ -r "/proc/$diagnostic_pid/cmdline" ] || continue
            diagnostic_command=$(tr '\000' ' ' <"/proc/$diagnostic_pid/cmdline")
            {
                printf 'node=%s pid=%s netns=%s command=%s\n' "$diagnostic_node" \
                    "$diagnostic_pid" "$(stat -Lc '%d:%i' "/proc/$diagnostic_pid/ns/net")" \
                    "$diagnostic_command"
                nsenter -t "$diagnostic_pid" -n ip -details -statistics link show || true
                nsenter -t "$diagnostic_pid" -n ip -6 address show || true
                nsenter -t "$diagnostic_pid" -n ip -6 route show table main || true
                nsenter -t "$diagnostic_pid" -n ip -details mptcp endpoint show || true
                nsenter -t "$diagnostic_pid" -n ip mptcp limits show || true
                nsenter -t "$diagnostic_pid" -n ss -M -ltn || true
                nsenter -t "$diagnostic_pid" -n ss -M -tin || true
                diagnostic_interfaces=$(nsenter -t "$diagnostic_pid" -n \
                    wg show interfaces 2>/dev/null || true)
                for diagnostic_interface in $diagnostic_interfaces; do
                    printf 'wireguard-interface=%s\n' "$diagnostic_interface"
                    nsenter -t "$diagnostic_pid" -n wg show "$diagnostic_interface" \
                        public-key || true
                    nsenter -t "$diagnostic_pid" -n wg show "$diagnostic_interface" \
                        listen-port || true
                    nsenter -t "$diagnostic_pid" -n wg show "$diagnostic_interface" \
                        peers || true
                    nsenter -t "$diagnostic_pid" -n wg show "$diagnostic_interface" \
                        endpoints || true
                    nsenter -t "$diagnostic_pid" -n wg show "$diagnostic_interface" \
                        allowed-ips || true
                    nsenter -t "$diagnostic_pid" -n wg show "$diagnostic_interface" \
                        latest-handshakes || true
                    nsenter -t "$diagnostic_pid" -n wg show "$diagnostic_interface" \
                        transfer || true
                done
                nsenter -t "$diagnostic_pid" -n nft list ruleset || true
                nsenter -t "$diagnostic_pid" -n \
                    cat /proc/sys/net/ipv6/conf/all/forwarding || true
            } >>"$WORK/worker-network-diagnostics.txt" 2>&1
        done
    done
}

count_worker_wireguard_interfaces() {
    diagnostic_interface_count=0
    for diagnostic_node in client relay1 relay2 exit; do
        diagnostic_unit=volparossa-alpha-helper@$diagnostic_node.service
        diagnostic_cgroup=$(systemctl show --property=ControlGroup --value \
            "$diagnostic_unit" 2>/dev/null || true)
        case $diagnostic_cgroup in /system.slice/*) ;; *) continue ;; esac
        diagnostic_cgroup_root=/sys/fs/cgroup$diagnostic_cgroup
        [ -d "$diagnostic_cgroup_root" ] || continue
        diagnostic_pids=$(find "$diagnostic_cgroup_root" -type f -name cgroup.procs \
            -exec cat {} \; 2>/dev/null | sort -nu | tr '\n' ' ')
        for diagnostic_pid in $diagnostic_pids; do
            [ -r "/proc/$diagnostic_pid/ns/net" ] || continue
            diagnostic_interfaces=$(nsenter -t "$diagnostic_pid" -n \
                wg show interfaces 2>/dev/null || true)
            for diagnostic_interface in $diagnostic_interfaces; do
                diagnostic_interface_count=$((diagnostic_interface_count + 1))
            done
        done
    done
    printf '%s\n' "$diagnostic_interface_count"
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
    topology_scale=null
    if [ -f "$WORK/topology-scale.json" ]; then
        topology_scale=$(cat "$WORK/topology-scale.json" 2>/dev/null || printf 'null')
    fi
    helper_records='[]'
    if [ -f "$WORK/helper-units.json" ]; then
        helper_records=$(cat "$WORK/helper-units.json" 2>/dev/null || printf '[]')
    fi
    a01_evidence=null
    if [ -f "$WORK/a01-evidence.json" ]; then
        a01_evidence=$(cat "$WORK/a01-evidence.json" 2>/dev/null || printf 'null')
    fi
    a02_evidence=null
    if [ -f "$WORK/a02-evidence.json" ]; then
        a02_evidence=$(cat "$WORK/a02-evidence.json" 2>/dev/null || printf 'null')
    fi
    mpquic_records='[]'
    if [ -f "$WORK/mpquic-units.json" ]; then
        mpquic_records=$(cat "$WORK/mpquic-units.json" 2>/dev/null || printf '[]')
    fi
    a03_evidence=null
    if [ -f "$WORK/a03-evidence.json" ]; then
        a03_evidence=$(cat "$WORK/a03-evidence.json" 2>/dev/null || printf 'null')
    fi
    a04_evidence=null
    if [ -f "$WORK/a04-evidence.json" ]; then
        a04_evidence=$(cat "$WORK/a04-evidence.json" 2>/dev/null || printf 'null')
    fi
    a05_evidence=null
    if [ -f "$WORK/a05-evidence.json" ]; then
        a05_evidence=$(cat "$WORK/a05-evidence.json" 2>/dev/null || printf 'null')
    fi
    a06_evidence=null
    if [ -f "$WORK/a06-evidence.json" ]; then
        a06_evidence=$(cat "$WORK/a06-evidence.json" 2>/dev/null || printf 'null')
    fi
    a07_evidence=null
    if [ -f "$WORK/a07-evidence.json" ]; then
        a07_evidence=$(cat "$WORK/a07-evidence.json" 2>/dev/null || printf 'null')
    fi
    a08_evidence=null
    if [ -f "$WORK/a08-evidence.json" ]; then
        a08_evidence=$(cat "$WORK/a08-evidence.json" 2>/dev/null || printf 'null')
    fi
    a09_evidence=null
    if [ -f "$WORK/a09-evidence.json" ]; then
        a09_evidence=$(cat "$WORK/a09-evidence.json" 2>/dev/null || printf 'null')
    fi
    a10_evidence=null
    if [ -f "$WORK/a10-evidence.json" ]; then
        a10_evidence=$(cat "$WORK/a10-evidence.json" 2>/dev/null || printf 'null')
    fi
    a11_evidence=null
    if [ -f "$WORK/a11-evidence.json" ]; then
        a11_evidence=$(cat "$WORK/a11-evidence.json" 2>/dev/null || printf 'null')
    fi
    a12_evidence=null
    if [ -f "$WORK/a12-evidence.json" ]; then
        a12_evidence=$(cat "$WORK/a12-evidence.json" 2>/dev/null || printf 'null')
    fi
    a13_evidence=null
    if [ -f "$WORK/a13-evidence.json" ]; then
        a13_evidence=$(cat "$WORK/a13-evidence.json" 2>/dev/null || printf 'null')
    fi
    a14_evidence=null
    if [ -f "$WORK/a14-evidence.json" ]; then
        a14_evidence=$(cat "$WORK/a14-evidence.json" 2>/dev/null || printf 'null')
    fi
    a15_evidence=null
    if [ -f "$WORK/a15-evidence.json" ]; then
        a15_evidence=$(cat "$WORK/a15-evidence.json" 2>/dev/null || printf 'null')
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
        --argjson a01_requested "$A01_REQUESTED" \
        --argjson a01_succeeded "$A01_SUCCEEDED" \
        --argjson a01_status "$A01_STATUS" \
        --argjson a02_requested "$A02_REQUESTED" \
        --argjson a02_succeeded "$A02_SUCCEEDED" \
        --argjson a02_status "$A02_STATUS" \
        --argjson a03_requested "$A03_REQUESTED" \
        --argjson a03_succeeded "$A03_SUCCEEDED" \
        --argjson a03_status "$A03_STATUS" \
        --argjson a04_requested "$A04_REQUESTED" \
        --argjson a04_succeeded "$A04_SUCCEEDED" \
        --argjson a04_status "$A04_STATUS" \
        --argjson a05_requested "$A05_REQUESTED" \
        --argjson a05_succeeded "$A05_SUCCEEDED" \
        --argjson a05_status "$A05_STATUS" \
        --argjson a06_requested "$A06_REQUESTED" \
        --argjson a06_succeeded "$A06_SUCCEEDED" \
        --argjson a06_status "$A06_STATUS" \
        --argjson a07_requested "$A07_REQUESTED" \
        --argjson a07_succeeded "$A07_SUCCEEDED" \
        --argjson a07_status "$A07_STATUS" \
        --argjson a08_requested "$A08_REQUESTED" \
        --argjson a08_succeeded "$A08_SUCCEEDED" \
        --argjson a08_status "$A08_STATUS" \
        --argjson a09_requested "$A09_REQUESTED" \
        --argjson a09_succeeded "$A09_SUCCEEDED" \
        --argjson a09_status "$A09_STATUS" \
        --argjson a10_requested "$A10_REQUESTED" \
        --argjson a10_succeeded "$A10_SUCCEEDED" \
        --argjson a10_status "$A10_STATUS" \
        --argjson a11_requested "$A11_REQUESTED" \
        --argjson a11_succeeded "$A11_SUCCEEDED" \
        --argjson a11_status "$A11_STATUS" \
        --argjson a12_requested "$A12_REQUESTED" \
        --argjson a12_succeeded "$A12_SUCCEEDED" \
        --argjson a12_status "$A12_STATUS" \
        --argjson a13_requested "$A13_REQUESTED" \
        --argjson a13_succeeded "$A13_SUCCEEDED" \
        --argjson a13_status "$A13_STATUS" \
        --argjson a14_requested "$A14_REQUESTED" \
        --argjson a14_succeeded "$A14_SUCCEEDED" \
        --argjson a14_status "$A14_STATUS" \
        --argjson a15_requested "$A15_REQUESTED" \
        --argjson a15_succeeded "$A15_SUCCEEDED" \
        --argjson a15_status "$A15_STATUS" \
        --argjson cleanup "$CLEANUP_COMPLETE" \
        --argjson remaining_namespaces "$REMAINING_NAMESPACES" \
        --argjson remaining_units "$REMAINING_UNITS" \
        --argjson remaining_owned_objects "$REMAINING_OWNED_OBJECTS" \
        --argjson exit_status "$report_status" \
        --argjson topology_scale "$topology_scale" \
        --argjson helper_records "$helper_records" \
        --argjson a01_evidence "$a01_evidence" \
        --argjson a02_evidence "$a02_evidence" \
        --argjson mpquic_records "$mpquic_records" \
        --argjson a03_evidence "$a03_evidence" \
        --argjson a04_evidence "$a04_evidence" \
        --argjson a05_evidence "$a05_evidence" \
        --argjson a06_evidence "$a06_evidence" \
        --argjson a07_evidence "$a07_evidence" \
        --argjson a08_evidence "$a08_evidence" \
        --argjson a09_evidence "$a09_evidence" \
        --argjson a10_evidence "$a10_evidence" \
        --argjson a11_evidence "$a11_evidence" \
        --argjson a12_evidence "$a12_evidence" \
        --argjson a13_evidence "$a13_evidence" \
        --argjson a14_evidence "$a14_evidence" \
        --argjson a15_evidence "$a15_evidence" \
        '{schema_version:1,report_kind:"volparossa-alpha-kvm-topology",
          source_revision:$commit,run_id:$run_id,last_phase:$phase,
          topology:{ready:$topology,direct_client_exit_adjacency:false,
            client_exit_route_absent:$client_exit_route_absent,
            exit_control_relay:"relay0",data_relays:["relay1","relay2"],
            relay_pool:["relay0","relay1","relay2","relay3","relay4","relay5"],
            exit_pool:["exit","exit2"],standby_capacity_mbps:1,
            bootstrap_contacts:["bootstrap1","bootstrap2"],
            scale_evidence:$topology_scale,
            roles:["client","bootstrap1","bootstrap2","relay0","relay1",
              "relay2","relay3","relay4","relay5","exit","exit2","destination"]},
          production_helpers:{ready:$helpers,instances:$helper_records},
          native_mpquic:{ready:$mpquic,api_version:6,instances:$mpquic_records},
          agents_ready:$agents,destination_ready:$destination,
          client_connect:{requested:$requested,succeeded:$connected,
            exit_status:$connect_status,observed_blocker:$blocker},
          a01_bootstrap_resilience:{requested:$a01_requested,
            succeeded:$a01_succeeded,exit_status:$a01_status,
            evidence:$a01_evidence},
          a02_transparent_tcp:{requested:$a02_requested,succeeded:$a02_succeeded,
            exit_status:$a02_status,evidence:$a02_evidence},
          a03_mptcp_aggregation:{requested:$a03_requested,succeeded:$a03_succeeded,
            exit_status:$a03_status,evidence:$a03_evidence},
          a04_mptcp_relay_failover:{requested:$a04_requested,succeeded:$a04_succeeded,
            exit_status:$a04_status,evidence:$a04_evidence},
          a05_udp_echo:{requested:$a05_requested,succeeded:$a05_succeeded,
            exit_status:$a05_status,evidence:$a05_evidence},
          a06_http3_mpquic:{requested:$a06_requested,succeeded:$a06_succeeded,
            exit_status:$a06_status,evidence:$a06_evidence},
          a07_http3_relay_failover:{requested:$a07_requested,succeeded:$a07_succeeded,
            exit_status:$a07_status,evidence:$a07_evidence},
          a08_allowed_destination:{requested:$a08_requested,succeeded:$a08_succeeded,
            exit_status:$a08_status,evidence:$a08_evidence},
          a09_forbidden_destinations:{requested:$a09_requested,succeeded:$a09_succeeded,
            exit_status:$a09_status,evidence:$a09_evidence},
          a10_unverifiable_ech:{requested:$a10_requested,succeeded:$a10_succeeded,
            exit_status:$a10_status,evidence:$a10_evidence},
          a11_relay_outer_privacy:{requested:$a11_requested,succeeded:$a11_succeeded,
            exit_status:$a11_status,evidence:$a11_evidence},
          a12_exit_source_privacy:{requested:$a12_requested,succeeded:$a12_succeeded,
            exit_status:$a12_status,evidence:$a12_evidence},
          a13_no_direct_client_exit:{requested:$a13_requested,succeeded:$a13_succeeded,
            exit_status:$a13_status,evidence:$a13_evidence},
          a14_forced_crash_cleanup:{requested:$a14_requested,succeeded:$a14_succeeded,
            exit_status:$a14_status,evidence:$a14_evidence},
          a15_host_state_unchanged:{requested:$a15_requested,succeeded:$a15_succeeded,
            exit_status:$a15_status,evidence:$a15_evidence},
          cleanup:{complete:$cleanup,remaining_namespaces:$remaining_namespaces,
            remaining_units:$remaining_units,
            remaining_owned_objects:$remaining_owned_objects},
          runner_exit_status:$exit_status}' \
        >"$output_directory/report.json"
    chown "$OUTPUT_UID:$OUTPUT_GID" "$output_directory/report.json"
    chmod 0600 "$output_directory/report.json"
}

cleanup() {
    original_status=$?
    [ "$FINALIZED" = no ] || exit "$original_status"
    FINALIZED=yes
    trap - EXIT HUP INT TERM

    if [ -n "$TLS_POLICY_SERVER_PID" ]; then
        kill -TERM "$TLS_POLICY_SERVER_PID" 2>/dev/null || true
        wait "$TLS_POLICY_SERVER_PID" 2>/dev/null || true
        TLS_POLICY_SERVER_PID=
    fi

    if [ -n "$DOWNLOAD_CLIENT_PID" ]; then
        kill -TERM "$DOWNLOAD_CLIENT_PID" 2>/dev/null || true
        wait "$DOWNLOAD_CLIENT_PID" 2>/dev/null || true
        DOWNLOAD_CLIENT_PID=
    fi
    if [ -n "$HTTP3_CLIENT_PID" ]; then
        kill -TERM "$HTTP3_CLIENT_PID" 2>/dev/null || true
        wait "$HTTP3_CLIENT_PID" 2>/dev/null || true
        HTTP3_CLIENT_PID=
    fi
    for observer_pid in "$CLIENT_OBSERVER_PID" "$EXIT_OBSERVER_PID"; do
        [ -z "$observer_pid" ] || kill -TERM "$observer_pid" 2>/dev/null || true
    done
    for observer_pid in "$PRIVACY_CLIENT_PID" "$PRIVACY_RELAY1_PID" \
        "$PRIVACY_RELAY2_PID" "$PRIVACY_EXIT_PID"; do
        [ -z "$observer_pid" ] || kill -TERM "$observer_pid" 2>/dev/null || true
    done
    if [ -n "$HTTP3_SERVER_PID" ]; then
        kill -TERM "$HTTP3_SERVER_PID" 2>/dev/null || true
        http3_stop_attempt=0
        while kill -0 "$HTTP3_SERVER_PID" 2>/dev/null \
            && [ "$http3_stop_attempt" -lt 50 ]; do
            sleep 0.1
            http3_stop_attempt=$((http3_stop_attempt + 1))
        done
        if kill -0 "$HTTP3_SERVER_PID" 2>/dev/null; then
            kill -KILL "$HTTP3_SERVER_PID" 2>/dev/null || true
        fi
        wait "$HTTP3_SERVER_PID" 2>/dev/null || true
        HTTP3_SERVER_PID=
    fi
    for observer_pid in "$CLIENT_OBSERVER_PID" "$EXIT_OBSERVER_PID"; do
        [ -z "$observer_pid" ] || wait "$observer_pid" 2>/dev/null || true
    done
    for observer_pid in "$PRIVACY_CLIENT_PID" "$PRIVACY_RELAY1_PID" \
        "$PRIVACY_RELAY2_PID" "$PRIVACY_EXIT_PID"; do
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

    capture_worker_network_diagnostics

    # Early A01 failures happen before capture_product_logs() is defined. Query every still-live
    # product socket here, before retiring the services, so the next functional blocker is
    # observable without weakening cleanup or rerunning the KVM topology just for diagnostics.
    if [ -x "$binary_directory/volparossa" ]; then
        for cleanup_node in client bootstrap1 bootstrap2 relay0 relay1 relay2 relay3 relay4 \
            relay5 exit exit2; do
            cleanup_socket=$WORK/runtime-$cleanup_node/control/agent.sock
            [ -S "$cleanup_socket" ] || continue
            "$binary_directory/volparossa" --control-socket "$cleanup_socket" \
                logs --limit 400 >"$WORK/logs-$cleanup_node.txt" 2>/dev/null || true
            "$binary_directory/volparossa" --control-socket "$cleanup_socket" \
                peers >"$WORK/peers-$cleanup_node.txt" 2>/dev/null || true
            "$binary_directory/volparossa" --control-socket "$cleanup_socket" \
                status >"$WORK/status-$cleanup_node.txt" 2>/dev/null || true
        done
    fi
    for cleanup_unit in $AGENT_UNITS; do retire_unit "$cleanup_unit" || true; done
    for cleanup_unit in $MPQUIC_UNITS; do retire_unit "$cleanup_unit" || true; done
    for cleanup_unit in $HELPER_UNITS; do retire_unit "$cleanup_unit" || true; done
    for cleanup_ns in "$DEST" "$EXIT2_NODE" "$EXIT_NODE" "$R5" "$R4" "$R3" \
        "$R2" "$R1" "$R0" "$B2" "$B1" "$CLIENT"; do
        ip netns del "$cleanup_ns" 2>/dev/null || true
    done
    if [ -n "$HOSTS_BACKUP" ] && [ -f "$HOSTS_BACKUP" ]; then
        cat "$HOSTS_BACKUP" >/etc/hosts || original_status=1
        HOSTS_BACKUP=
    fi
    cleanup_attempt=0
    while [ "$cleanup_attempt" -lt 100 ]; do
        cleanup_units_remaining=0
        for cleanup_unit in $AGENT_UNITS $MPQUIC_UNITS $HELPER_UNITS; do
            [ "$(unit_load_state "$cleanup_unit")" = not-found ] \
                || cleanup_units_remaining=$((cleanup_units_remaining + 1))
        done
        [ "$cleanup_units_remaining" -ne 0 ] || break
        sleep 0.1
        cleanup_attempt=$((cleanup_attempt + 1))
    done

    REMAINING_NAMESPACES=$(ip netns list | awk -v prefix="$PREFIX-" \
        '$1 ~ ("^" prefix) { count++ } END { print count + 0 }')
    REMAINING_UNITS=0
    for cleanup_unit in $AGENT_UNITS $MPQUIC_UNITS $HELPER_UNITS; do
        [ "$(unit_load_state "$cleanup_unit")" = not-found ] \
            || REMAINING_UNITS=$((REMAINING_UNITS + 1))
    done
    remaining_links=0
    remaining_routes=0
    remaining_mptcp_endpoints=0
    remaining_mpquic_paths=0
    remaining_nftables_rules=0
    remaining_worker_network_namespaces=0
    remaining_worker_namespace_references=0
    remaining_helper_fdstore_descriptors=0
    if [ "$A14_REQUESTED" = true ] \
        && ! measure_a14_remaining_network_objects; then
        remaining_links=1
        remaining_routes=1
        remaining_mptcp_endpoints=1
        remaining_mpquic_paths=1
        remaining_nftables_rules=1
        remaining_worker_network_namespaces=1
        remaining_worker_namespace_references=1
        remaining_helper_fdstore_descriptors=1
        original_status=1
        OBSERVED_BLOCKER=A14_REMAINING_INVENTORY_UNAVAILABLE
    fi
    for cleanup_node in client bootstrap1 bootstrap2 relay0 relay1 relay2 relay3 relay4 \
        relay5 exit exit2; do
        rm -f -- "$WORK/runtime-$cleanup_node/helper.sock" \
            "$WORK/runtime-$cleanup_node/control/agent.sock" \
            "$WORK/runtime-$cleanup_node/native/mpquic.sock"
    done
    remaining_runtime_sockets=$(find "$WORK"/runtime-* -type s -print \
        | awk 'END { print NR + 0 }')

    if [ -s "$WORK/host-state-before.json" ] \
        && capture_host_state "$WORK/host-state-after.json"; then
        host_before_sha256=$(sha256sum "$WORK/host-state-before.json" \
            | awk '{print $1}')
        host_after_sha256=$(sha256sum "$WORK/host-state-after.json" \
            | awk '{print $1}')
        if [ "$host_before_sha256" = "$host_after_sha256" ]; then
            host_state_unchanged=true
            A15_STATUS=0
            A15_SUCCEEDED=true
        else
            host_state_unchanged=false
            A15_STATUS=1
            A15_SUCCEEDED=false
            original_status=1
            OBSERVED_BLOCKER=A15_HOST_STATE_CHANGED
        fi
        jq -S -c -n --arg before "$host_before_sha256" \
            --arg after "$host_after_sha256" \
            --argjson unchanged "$host_state_unchanged" \
            '{schema_version:1,acceptance_id:"A15",success:$unchanged,
              scope:"disposable KVM guest root network namespace outside owned namespaces",
              before_sha256:$before,after_sha256:$after,unchanged:$unchanged,
              compared:["links","addresses","routes","rules","DNS",
                "nftables","WireGuard/VPN state","relevant forwarding sysctls",
                "pre-existing named network namespaces"]}' \
            >"$WORK/a15-evidence.json"
    else
        A15_STATUS=1
        A15_SUCCEEDED=false
        original_status=1
        OBSERVED_BLOCKER=A15_HOST_STATE_AFTER_UNAVAILABLE
        jq -S -c -n \
            '{schema_version:1,acceptance_id:"A15",success:false,
              scope:"disposable KVM guest root network namespace outside owned namespaces",
              before_sha256:null,after_sha256:null,unchanged:false,
              compared:["links","addresses","routes","rules","DNS",
                "nftables","WireGuard/VPN state","relevant forwarding sysctls",
                "pre-existing named network namespaces"]}' \
            >"$WORK/a15-evidence.json"
    fi

    host_leaks=1
    [ "$A15_STATUS" -ne 0 ] || host_leaks=0
    REMAINING_OWNED_OBJECTS=$((REMAINING_NAMESPACES + REMAINING_UNITS \
        + remaining_runtime_sockets + remaining_links + remaining_routes \
        + remaining_mptcp_endpoints + remaining_mpquic_paths \
        + remaining_nftables_rules + remaining_worker_network_namespaces \
        + remaining_worker_namespace_references \
        + remaining_helper_fdstore_descriptors + host_leaks))

    if [ "$A14_REQUESTED" = true ]; then
        a14_success=false
        if [ "$REMAINING_OWNED_OBJECTS" -eq 0 ] \
            && [ -s "$WORK/a14-owned-before.json" ] \
            && [ -s "$WORK/a14-crashes.json" ] \
            && [ -s "$WORK/a14-helper-restarts.json" ]; then
            a14_success=true
            A14_STATUS=0
            A14_SUCCEEDED=true
        else
            A14_STATUS=1
            A14_SUCCEEDED=false
            original_status=1
            OBSERVED_BLOCKER=A14_FORCED_CRASH_CLEANUP_INCOMPLETE
        fi
        a14_before=null
        [ ! -s "$WORK/a14-owned-before.json" ] \
            || a14_before=$(cat "$WORK/a14-owned-before.json")
        a14_crashes=null
        [ ! -s "$WORK/a14-crashes.json" ] \
            || a14_crashes=$(cat "$WORK/a14-crashes.json")
        a14_worker_after=null
        [ ! -s "$WORK/a14-worker-custody-after.json" ] \
            || a14_worker_after=$(cat "$WORK/a14-worker-custody-after.json")
        jq -S -c -n \
            --argjson before "$a14_before" \
            --argjson crashes "$a14_crashes" \
            --argjson worker_after "$a14_worker_after" \
            --slurpfile helper_restarts "$WORK/a14-helper-restarts.json" \
            --slurpfile host "$WORK/a15-evidence.json" \
            --argjson success "$a14_success" \
            --argjson namespaces "$REMAINING_NAMESPACES" \
            --argjson units "$REMAINING_UNITS" \
            --argjson sockets "$remaining_runtime_sockets" \
            --argjson links "$remaining_links" \
            --argjson routes "$remaining_routes" \
            --argjson mptcp "$remaining_mptcp_endpoints" \
            --argjson mpquic "$remaining_mpquic_paths" \
            --argjson nft "$remaining_nftables_rules" \
            --argjson worker_namespaces "$remaining_worker_network_namespaces" \
            --argjson worker_references "$remaining_worker_namespace_references" \
            --argjson fdstore "$remaining_helper_fdstore_descriptors" \
            --argjson remaining "$REMAINING_OWNED_OBJECTS" \
            '{schema_version:1,acceptance_id:"A14",success:$success,
              forced_crashes:$crashes,owned_before:$before,
              helper_restart_recovery:$helper_restarts[0],
              cleanup:{worker_custody_after:$worker_after,
                remaining_owned_objects:$remaining,
                remaining_namespaces:$namespaces,remaining_units:$units,
                remaining_runtime_sockets:$sockets,remaining_links:$links,
                remaining_routes:$routes,remaining_mptcp_endpoints:$mptcp,
                remaining_mpquic_paths:$mpquic,remaining_nftables_rules:$nft,
                remaining_worker_network_namespaces:$worker_namespaces,
                remaining_worker_namespace_references:$worker_references,
                remaining_helper_fdstore_descriptors:$fdstore},
              verification_basis:{all_product_networking_namespace_owned:true,
                owned_namespace_mounts_absent:($namespaces == 0),
                guest_root_state_exactly_restored:$host[0].unchanged}}' \
            >"$WORK/a14-evidence.json"
    fi

    if [ "$REMAINING_NAMESPACES" -eq 0 ] && [ "$REMAINING_UNITS" -eq 0 ] \
        && [ "$remaining_runtime_sockets" -eq 0 ] \
        && [ "$A15_STATUS" -eq 0 ] \
        && { [ "$A14_REQUESTED" != true ] || [ "$A14_STATUS" -eq 0 ]; }; then
        CLEANUP_COMPLETE=true
        if [ "$A14_REQUESTED" = true ]; then
            PHASE=a15-complete
        fi
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

PHASE=host-state-before
A15_REQUESTED=true
capture_host_state "$WORK/host-state-before.json" \
    || fail A15_HOST_STATE_BEFORE_UNAVAILABLE

# This mapping exists only inside the disposable KVM guest. Both the Client and Exit resolve the
# policy hostname to the one destination address, while cleanup restores the exact guest file.
install -o root -g root -m 0600 /etc/hosts "$WORK/hosts.before"
HOSTS_BACKUP=$WORK/hosts.before
printf '%s\n' '47.163.4.2 destination.volparossa.test' >>/etc/hosts
getent ahostsv4 destination.volparossa.test | awk '{print $1}' | sort -u \
    >"$WORK/a08-exit-host-lookup.txt"
[ "$(cat "$WORK/a08-exit-host-lookup.txt")" = 47.163.4.2 ] \
    || fail A08_DESTINATION_LOOKUP_NOT_PINNED

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
# The disposable application processes run as the distinct volparossa-worker
# identity and must be able to traverse to root-owned, read-only fixtures.
# Credential, state and destination directories below retain their narrower modes.
chmod 0755 "$WORK"
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
install -o root -g "$AGENT_GID" -m 0555 \
    "$binary_directory/examples/http3-acceptance-fixture" \
    "$WORK/bin/examples/http3-acceptance-fixture"
install -o root -g "$AGENT_GID" -m 0555 \
    "$binary_directory/examples/tls-policy-acceptance-fixture" \
    "$WORK/bin/examples/tls-policy-acceptance-fixture"
install -d -o "$WORKER_UID" -g "$WORKER_GID" -m 0700 "$WORK/client-fixtures"
binary_directory=$WORK/bin
mpquic_binary=$WORK/bin/volparossa-mpquic

PHASE=network-topology
for namespace in "$CLIENT" "$B1" "$B2" "$R0" "$R1" "$R2" "$R3" "$R4" "$R5" \
    "$EXIT_NODE" "$EXIT2_NODE" "$DEST"; do
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

link_nodes "$CLIENT" cr0 10.241.10.1/30 "$R0" r0c 10.241.10.2/30
link_nodes "$CLIENT" cr1 10.241.11.1/30 "$R1" r1c 10.241.11.2/30
link_nodes "$CLIENT" cr2 10.241.12.1/30 "$R2" r2c 10.241.12.2/30
link_nodes "$CLIENT" cr3 10.241.13.1/30 "$R3" r3c 10.241.13.2/30
link_nodes "$CLIENT" cr4 10.241.14.1/30 "$R4" r4c 10.241.14.2/30
link_nodes "$CLIENT" cr5 10.241.15.1/30 "$R5" r5c 10.241.15.2/30
link_nodes "$CLIENT" cb1 10.241.40.1/30 "$B1" b1c 10.241.40.2/30
link_nodes "$CLIENT" cb2 10.241.41.1/30 "$B2" b2c 10.241.41.2/30
link_nodes "$R0" r0b1 10.241.42.1/30 "$B1" b1r0 10.241.42.2/30
link_nodes "$R0" r0b2 10.241.43.1/30 "$B2" b2r0 10.241.43.2/30
link_nodes "$R1" r1b1 10.241.44.1/30 "$B1" b1r1 10.241.44.2/30
link_nodes "$R1" r1b2 10.241.45.1/30 "$B2" b2r1 10.241.45.2/30
link_nodes "$R2" r2b1 10.241.46.1/30 "$B1" b1r2 10.241.46.2/30
link_nodes "$R2" r2b2 10.241.47.1/30 "$B2" b2r2 10.241.47.2/30
link_nodes "$R3" r3b1 10.241.48.1/30 "$B1" b1r3 10.241.48.2/30
link_nodes "$R3" r3b2 10.241.49.1/30 "$B2" b2r3 10.241.49.2/30
link_nodes "$R4" r4b1 10.241.50.1/30 "$B1" b1r4 10.241.50.2/30
link_nodes "$R4" r4b2 10.241.51.1/30 "$B2" b2r4 10.241.51.2/30
link_nodes "$R5" r5b1 10.241.52.1/30 "$B1" b1r5 10.241.52.2/30
link_nodes "$R5" r5b2 10.241.53.1/30 "$B2" b2r5 10.241.53.2/30
link_nodes "$R0" r0x 10.241.20.1/30 "$EXIT_NODE" xr0 10.241.20.2/30
link_nodes "$R1" r1x 10.241.21.1/30 "$EXIT_NODE" xr1 10.241.21.2/30
link_nodes "$R2" r2x 10.241.22.1/30 "$EXIT_NODE" xr2 10.241.22.2/30
link_nodes "$R3" r3x 10.241.23.1/30 "$EXIT_NODE" xr3 10.241.23.2/30
link_nodes "$R4" r4x 10.241.24.1/30 "$EXIT_NODE" xr4 10.241.24.2/30
link_nodes "$R5" r5x 10.241.25.1/30 "$EXIT_NODE" xr5 10.241.25.2/30
link_nodes "$R0" r0x2 10.241.26.1/30 "$EXIT2_NODE" x2r0 10.241.26.2/30
link_nodes "$EXIT_NODE" xd 10.241.31.1/30 "$DEST" dx 10.241.31.2/30
link_nodes "$EXIT2_NODE" x2d 10.241.32.1/30 "$DEST" dx2 10.241.32.2/30
ip -n "$EXIT_NODE" address add 47.163.4.1/30 dev xd
ip -n "$DEST" address add 47.163.4.2/30 dev dx
ip -n "$EXIT2_NODE" address add 52.168.8.1/30 dev x2d
ip -n "$DEST" address add 52.168.8.2/30 dev dx2
add_public_underlay "$CLIENT" 43.159.1.1
add_public_underlay "$B1" 40.156.1.1
add_public_underlay "$B2" 41.157.2.1
add_public_underlay "$R0" 42.158.0.1
add_public_underlay "$R1" 44.160.1.1
add_public_underlay "$R2" 45.161.2.1
add_public_underlay "$R3" 48.164.4.1
add_public_underlay "$R4" 49.165.5.1
add_public_underlay "$R5" 50.166.6.1
add_public_underlay "$EXIT_NODE" 46.162.3.1
add_public_underlay "$EXIT2_NODE" 51.167.7.1
ip -n "$CLIENT" route add 42.158.0.1/32 via 10.241.10.2 dev cr0 src 43.159.1.1
ip -n "$CLIENT" route add 44.160.1.1/32 via 10.241.11.2 dev cr1 src 43.159.1.1
ip -n "$CLIENT" route add 45.161.2.1/32 via 10.241.12.2 dev cr2 src 43.159.1.1
ip -n "$CLIENT" route add 48.164.4.1/32 via 10.241.13.2 dev cr3 src 43.159.1.1
ip -n "$CLIENT" route add 49.165.5.1/32 via 10.241.14.2 dev cr4 src 43.159.1.1
ip -n "$CLIENT" route add 50.166.6.1/32 via 10.241.15.2 dev cr5 src 43.159.1.1
ip -n "$CLIENT" route add 40.156.1.1/32 via 10.241.40.2 dev cb1 src 43.159.1.1
ip -n "$CLIENT" route add 41.157.2.1/32 via 10.241.41.2 dev cb2 src 43.159.1.1
ip -n "$R0" route add 40.156.1.1/32 via 10.241.42.2 dev r0b1 src 42.158.0.1
ip -n "$R0" route add 41.157.2.1/32 via 10.241.43.2 dev r0b2 src 42.158.0.1
ip -n "$R0" route add 43.159.1.1/32 via 10.241.10.1 dev r0c src 42.158.0.1
ip -n "$R0" route add 46.162.3.1/32 via 10.241.20.2 dev r0x src 42.158.0.1
ip -n "$R1" route add 43.159.1.1/32 via 10.241.11.1 dev r1c src 44.160.1.1
ip -n "$R1" route add 40.156.1.1/32 via 10.241.44.2 dev r1b1 src 44.160.1.1
ip -n "$R1" route add 41.157.2.1/32 via 10.241.45.2 dev r1b2 src 44.160.1.1
ip -n "$R1" route add 46.162.3.1/32 via 10.241.21.2 dev r1x src 44.160.1.1
ip -n "$R2" route add 43.159.1.1/32 via 10.241.12.1 dev r2c src 45.161.2.1
ip -n "$R2" route add 40.156.1.1/32 via 10.241.46.2 dev r2b1 src 45.161.2.1
ip -n "$R2" route add 41.157.2.1/32 via 10.241.47.2 dev r2b2 src 45.161.2.1
ip -n "$R2" route add 46.162.3.1/32 via 10.241.22.2 dev r2x src 45.161.2.1
ip -n "$R3" route add 43.159.1.1/32 via 10.241.13.1 dev r3c src 48.164.4.1
ip -n "$R3" route add 40.156.1.1/32 via 10.241.48.2 dev r3b1 src 48.164.4.1
ip -n "$R3" route add 41.157.2.1/32 via 10.241.49.2 dev r3b2 src 48.164.4.1
ip -n "$R3" route add 46.162.3.1/32 via 10.241.23.2 dev r3x src 48.164.4.1
ip -n "$R4" route add 43.159.1.1/32 via 10.241.14.1 dev r4c src 49.165.5.1
ip -n "$R4" route add 40.156.1.1/32 via 10.241.50.2 dev r4b1 src 49.165.5.1
ip -n "$R4" route add 41.157.2.1/32 via 10.241.51.2 dev r4b2 src 49.165.5.1
ip -n "$R4" route add 46.162.3.1/32 via 10.241.24.2 dev r4x src 49.165.5.1
ip -n "$R5" route add 43.159.1.1/32 via 10.241.15.1 dev r5c src 50.166.6.1
ip -n "$R5" route add 40.156.1.1/32 via 10.241.52.2 dev r5b1 src 50.166.6.1
ip -n "$R5" route add 41.157.2.1/32 via 10.241.53.2 dev r5b2 src 50.166.6.1
ip -n "$R5" route add 46.162.3.1/32 via 10.241.25.2 dev r5x src 50.166.6.1
ip -n "$R0" route add 51.167.7.1/32 via 10.241.26.2 dev r0x2 src 42.158.0.1
ip -n "$B1" route add 43.159.1.1/32 via 10.241.40.1 dev b1c src 40.156.1.1
ip -n "$B1" route add 42.158.0.1/32 via 10.241.42.1 dev b1r0 src 40.156.1.1
ip -n "$B1" route add 44.160.1.1/32 via 10.241.44.1 dev b1r1 src 40.156.1.1
ip -n "$B1" route add 45.161.2.1/32 via 10.241.46.1 dev b1r2 src 40.156.1.1
ip -n "$B1" route add 48.164.4.1/32 via 10.241.48.1 dev b1r3 src 40.156.1.1
ip -n "$B1" route add 49.165.5.1/32 via 10.241.50.1 dev b1r4 src 40.156.1.1
ip -n "$B1" route add 50.166.6.1/32 via 10.241.52.1 dev b1r5 src 40.156.1.1
ip -n "$B2" route add 43.159.1.1/32 via 10.241.41.1 dev b2c src 41.157.2.1
ip -n "$B2" route add 42.158.0.1/32 via 10.241.43.1 dev b2r0 src 41.157.2.1
ip -n "$B2" route add 44.160.1.1/32 via 10.241.45.1 dev b2r1 src 41.157.2.1
ip -n "$B2" route add 45.161.2.1/32 via 10.241.47.1 dev b2r2 src 41.157.2.1
ip -n "$B2" route add 48.164.4.1/32 via 10.241.49.1 dev b2r3 src 41.157.2.1
ip -n "$B2" route add 49.165.5.1/32 via 10.241.51.1 dev b2r4 src 41.157.2.1
ip -n "$B2" route add 50.166.6.1/32 via 10.241.53.1 dev b2r5 src 41.157.2.1
ip -n "$EXIT_NODE" route add 42.158.0.1/32 via 10.241.20.1 dev xr0 src 46.162.3.1
ip -n "$EXIT_NODE" route add 44.160.1.1/32 via 10.241.21.1 dev xr1 src 46.162.3.1
ip -n "$EXIT_NODE" route add 45.161.2.1/32 via 10.241.22.1 dev xr2 src 46.162.3.1
ip -n "$EXIT_NODE" route add 48.164.4.1/32 via 10.241.23.1 dev xr3 src 46.162.3.1
ip -n "$EXIT_NODE" route add 49.165.5.1/32 via 10.241.24.1 dev xr4 src 46.162.3.1
ip -n "$EXIT_NODE" route add 50.166.6.1/32 via 10.241.25.1 dev xr5 src 46.162.3.1
ip -n "$EXIT2_NODE" route add 42.158.0.1/32 via 10.241.26.1 dev x2r0 src 51.167.7.1
for forbidden in 10.241.20.2 10.241.21.2 10.241.22.2 10.241.23.2 \
    10.241.24.2 10.241.25.2 10.241.26.2 10.241.31.1 10.241.31.2 \
    10.241.32.1 10.241.32.2 46.162.3.1 47.163.4.1 51.167.7.1 \
    52.168.8.1 52.168.8.2; do
    ip -n "$CLIENT" route add unreachable "$forbidden/32"
    if ip -n "$CLIENT" route get "$forbidden" >/dev/null 2>&1; then
        fail DIRECT_CLIENT_EXIT_REACHABLE
    fi
done
CLIENT_EXIT_ROUTE_ABSENT=true
TOPOLOGY_READY=true

PHASE=configuration
for node in client bootstrap1 bootstrap2 relay0 relay1 relay2 relay3 relay4 relay5 exit exit2; do
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
B1_PEER=$(sed -n 's/^peer ID: //p' "$WORK/init-bootstrap1.log")
B2_PEER=$(sed -n 's/^peer ID: //p' "$WORK/init-bootstrap2.log")
R0_PEER=$(sed -n 's/^peer ID: //p' "$WORK/init-relay0.log")
R1_PEER=$(sed -n 's/^peer ID: //p' "$WORK/init-relay1.log")
R2_PEER=$(sed -n 's/^peer ID: //p' "$WORK/init-relay2.log")
R3_PEER=$(sed -n 's/^peer ID: //p' "$WORK/init-relay3.log")
R4_PEER=$(sed -n 's/^peer ID: //p' "$WORK/init-relay4.log")
R5_PEER=$(sed -n 's/^peer ID: //p' "$WORK/init-relay5.log")
EXIT_PEER=$(sed -n 's/^peer ID: //p' "$WORK/init-exit.log")
EXIT2_PEER=$(sed -n 's/^peer ID: //p' "$WORK/init-exit2.log")
for peer in "$CLIENT_PEER" "$B1_PEER" "$B2_PEER" "$R0_PEER" "$R1_PEER" \
    "$R2_PEER" "$R3_PEER" "$R4_PEER" "$R5_PEER" "$EXIT_PEER" "$EXIT2_PEER"; do
    [ -n "$peer" ] || fail IDENTITY_INITIALISATION_FAILED
done
printf '%s\n' "$CLIENT_PEER" "$B1_PEER" "$B2_PEER" "$R0_PEER" "$R1_PEER" \
    "$R2_PEER" "$R3_PEER" "$R4_PEER" "$R5_PEER" "$EXIT_PEER" "$EXIT2_PEER" \
    | sort -u >"$WORK/peer-identities.txt"
if [ "$(awk 'END { print NR + 0 }' "$WORK/peer-identities.txt")" -ne 11 ]; then
    fail IDENTITY_INITIALISATION_FAILED
fi
jq -S -c -n \
    --arg client "$CLIENT_PEER" --arg bootstrap1 "$B1_PEER" --arg bootstrap2 "$B2_PEER" \
    --arg relay0 "$R0_PEER" --arg relay1 "$R1_PEER" --arg relay2 "$R2_PEER" \
    --arg relay3 "$R3_PEER" --arg relay4 "$R4_PEER" --arg relay5 "$R5_PEER" \
    --arg exit "$EXIT_PEER" --arg exit2 "$EXIT2_PEER" \
    '{client:$client,bootstrap1:$bootstrap1,bootstrap2:$bootstrap2,
      relay0:$relay0,relay1:$relay1,relay2:$relay2,relay3:$relay3,
      relay4:$relay4,relay5:$relay5,exit:$exit,exit2:$exit2}' \
    >"$WORK/a01-expected-peers.json"

"$binary_directory/examples/acceptance-policy-fixture" "$WORK"
chown "$AGENT_UID:$AGENT_GID" "$WORK/development-policy.manifest" \
    "$WORK/policy-maintainers.json"

write_config() {
    node=$1; operator=$2; relay_role=$3; exit_role=$4; listen_ip=$5
    bootstrap_one=$6; bootstrap_two=$7; bootstrap_three=$8
    client_role=false; relay_capacity=0; exit_capacity=0; advertised_asn=0; advertised_prefix=null
    [ "$node" != client ] || client_role=true
    [ "$relay_role" = false ] || relay_capacity=32
    [ "$exit_role" = false ] || exit_capacity=32
    case $node in
        relay0) advertised_asn=64511; advertised_prefix=42.158.0.0/24 ;;
        relay1) advertised_asn=64512; advertised_prefix=44.160.1.0/24 ;;
        relay2) advertised_asn=64513; advertised_prefix=45.161.2.0/24 ;;
        relay3) relay_capacity=1; advertised_asn=64515; advertised_prefix=48.164.4.0/24 ;;
        relay4) relay_capacity=1; advertised_asn=64516; advertised_prefix=49.165.5.0/24 ;;
        relay5) relay_capacity=1; advertised_asn=64517; advertised_prefix=50.166.6.0/24 ;;
        exit) advertised_asn=64514; advertised_prefix=46.162.3.0/24 ;;
        exit2) exit_capacity=1; advertised_asn=64518; advertised_prefix=51.167.7.0/24 ;;
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
        [ "$bootstrap_three" = none ] \
            || printf '    - %s\n' "$bootstrap_three"
        printf 'roles:\n  client: %s\n  relay: %s\n  exit: %s\n' \
            "$client_role" "$relay_role" "$exit_role"
        printf 'capacity:\n  relay_upload_limit_mbps: %s\n' "$relay_capacity"
        printf '  relay_download_limit_mbps: %s\n' "$relay_capacity"
        printf '  exit_upload_limit_mbps: %s\n' "$exit_capacity"
        printf '  exit_download_limit_mbps: %s\n' "$exit_capacity"
        printf '  maximum_relay_sessions: %s\n' "$relay_capacity"
        printf '  maximum_exit_sessions: %s\n' "$exit_capacity"
        # Request an actual per-path reservation below every signed 32-Mbps Relay/Exit
        # advertisement. The native authorization chain binds this value to both service ledgers.
        printf 'routing:\n  client_minimum_upload_mbps: 8\n'
        printf '  client_minimum_download_mbps: 8\n'
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
    "/ip4/40.156.1.1/udp/41000/quic-v1/p2p/$B1_PEER" \
    "/ip4/41.157.2.1/udp/41000/quic-v1/p2p/$B2_PEER" none
write_config bootstrap1 null false false 40.156.1.1 none none none
write_config bootstrap2 null false false 41.157.2.1 none none none
write_config relay0 acceptance-relay-zero true false 42.158.0.1 \
    "/ip4/40.156.1.1/udp/41000/quic-v1/p2p/$B1_PEER" \
    "/ip4/41.157.2.1/udp/41000/quic-v1/p2p/$B2_PEER" none
write_config relay1 acceptance-relay-one true false 44.160.1.1 \
    "/ip4/40.156.1.1/udp/41000/quic-v1/p2p/$B1_PEER" \
    "/ip4/41.157.2.1/udp/41000/quic-v1/p2p/$B2_PEER" none
write_config relay2 acceptance-relay-two true false 45.161.2.1 \
    "/ip4/40.156.1.1/udp/41000/quic-v1/p2p/$B1_PEER" \
    "/ip4/41.157.2.1/udp/41000/quic-v1/p2p/$B2_PEER" none
write_config relay3 acceptance-relay-three true false 48.164.4.1 \
    "/ip4/40.156.1.1/udp/41000/quic-v1/p2p/$B1_PEER" \
    "/ip4/41.157.2.1/udp/41000/quic-v1/p2p/$B2_PEER" none
write_config relay4 acceptance-relay-four true false 49.165.5.1 \
    "/ip4/40.156.1.1/udp/41000/quic-v1/p2p/$B1_PEER" \
    "/ip4/41.157.2.1/udp/41000/quic-v1/p2p/$B2_PEER" none
write_config relay5 acceptance-relay-five true false 50.166.6.1 \
    "/ip4/40.156.1.1/udp/41000/quic-v1/p2p/$B1_PEER" \
    "/ip4/41.157.2.1/udp/41000/quic-v1/p2p/$B2_PEER" none
write_config exit acceptance-exit false true 46.162.3.1 \
    "/ip4/42.158.0.1/udp/41000/quic-v1/p2p/$R0_PEER" none none
write_config exit2 acceptance-exit-two false true 51.167.7.1 \
    "/ip4/42.158.0.1/udp/41000/quic-v1/p2p/$R0_PEER" none none

PHASE=helper-launch
CAPABILITIES='CAP_KILL CAP_NET_ADMIN CAP_NET_BIND_SERVICE CAP_NET_RAW CAP_SETGID CAP_SETPCAP CAP_SETUID CAP_SYS_ADMIN'

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
        --service-type=simple \
        --property=CollectMode=inactive-or-failed \
        --property=ExitType=main \
        --property=RemainAfterExit=no \
        --property=SuccessExitStatus= \
        --property=Restart=on-failure \
        --property=RestartMode=normal \
        --property=RestartSec=3s \
        --property=RestartForceExitStatus= \
        --property='RestartPreventExitStatus=70 71' \
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
        --property=FinalKillSignal=SIGKILL \
        --property=TimeoutStopFailureMode=terminate \
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
launch_helper bootstrap1 "$B1"
launch_helper bootstrap2 "$B2"
launch_helper relay0 "$R0"
launch_helper relay1 "$R1"
launch_helper relay2 "$R2"
launch_helper relay3 "$R3"
launch_helper relay4 "$R4"
launch_helper relay5 "$R5"
launch_helper exit "$EXIT_NODE"
launch_helper exit2 "$EXIT2_NODE"

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
verify_helper bootstrap1 "$B1"
verify_helper bootstrap2 "$B2"
verify_helper relay0 "$R0"
verify_helper relay1 "$R1"
verify_helper relay2 "$R2"
verify_helper relay3 "$R3"
verify_helper relay4 "$R4"
verify_helper relay5 "$R5"
verify_helper exit "$EXIT_NODE"
verify_helper exit2 "$EXIT2_NODE"
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
launch_mpquic exit2 "$EXIT2_NODE" exit
verify_mpquic client "$CLIENT" client
verify_mpquic exit "$EXIT_NODE" exit
verify_mpquic exit2 "$EXIT2_NODE" exit
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
launch_agent bootstrap1 "$B1"
launch_agent bootstrap2 "$B2"
launch_agent relay0 "$R0"
launch_agent relay1 "$R1"
launch_agent relay2 "$R2"
launch_agent relay3 "$R3"
launch_agent relay4 "$R4"
launch_agent relay5 "$R5"
launch_agent exit "$EXIT_NODE"
launch_agent exit2 "$EXIT2_NODE"

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
    # Linux loops transmitted frames only through the ETH_P_ALL packet tap. The parser below
    # still admits IPv4 exclusively; using ETH_P_IP here silently observed ingress only and made
    # the directional Client/Exit evidence report zero for a successfully completed datapath.
    capture = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(0x0003))
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
                    "10.241.20.2",
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
import os
import select
import signal
import socket
import struct
import sys
import time

role, output_path, ready_path, marker_path, *interfaces = sys.argv[1:]
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
    capture = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(0x0003))
    capture.bind((interface, 0))
    capture.setblocking(False)
    sockets[capture] = interface

open(ready_path, "x", encoding="ascii").write("ready\n")
running = True
truncated = False
observed_frames = 0
marker_observed = False
before_marker = None


def stop(*_unused):
    global running
    running = False


signal.signal(signal.SIGTERM, stop)
signal.signal(signal.SIGINT, stop)
deadline = time.monotonic() + 180
while running and time.monotonic() < deadline:
    if marker_path != "-" and not marker_observed and os.path.exists(marker_path):
        before_marker = dict(counters)
        marker_observed = True
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
                    "10.241.20.2",
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
after_marker = None
if before_marker is not None:
    after_marker = {
        key: counters[key] - before_marker[key]
        for key in counters
    }
with open(output_path, "x", encoding="ascii") as output:
    json.dump(
        {
            "schema_version": 1,
            "capture_role": role,
            "interfaces": interfaces,
            "observed_frames": observed_frames,
            "truncated": truncated,
            "marker_observed": marker_observed,
            "before_marker": before_marker,
            "after_marker": after_marker,
            **counters,
        },
        output,
        sort_keys=True,
        separators=(",", ":"),
    )
    output.write("\n")
PYTHON
cat >"$WORK/bin/a06-observer.py" <<'PYTHON'
import hashlib
import json
import os
import select
import signal
import socket
import struct
import sys
import time

role, output_path, ready_path, marker_path, *interfaces = sys.argv[1:]
if role not in {"client", "exit"} or not interfaces:
    raise SystemExit("invalid bounded A06 observer arguments")

counters = (
    {
        "relay1_wireguard_data_datagrams": 0,
        "relay2_wireguard_data_datagrams": 0,
        "relay1_wireguard_data_bytes": 0,
        "relay2_wireguard_data_bytes": 0,
        "direct_client_exit_packets": 0,
    }
    if role == "client"
    else {
        "relay1_wireguard_data_datagrams": 0,
        "relay2_wireguard_data_datagrams": 0,
        "relay1_wireguard_data_bytes": 0,
        "relay2_wireguard_data_bytes": 0,
        "destination_request_datagrams": 0,
        "destination_response_datagrams": 0,
    }
)
sockets = {}
for interface in interfaces:
    capture = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(0x0003))
    capture.bind((interface, 0))
    capture.setblocking(False)
    sockets[capture] = interface

open(ready_path, "x", encoding="ascii").write("ready\n")
running = True
truncated = False
observed_frames = 0
marker_observed = False
before_marker = None
payload_samples = {
    "client_ingress_requests": [],
    "client_ingress_responses": [],
    "destination_requests": [],
    "destination_responses": [],
}


def sample_payload(bucket, frame, transport_offset, udp_length):
    if len(payload_samples[bucket]) >= 16 or udp_length < 8:
        return
    payload_end = transport_offset + udp_length
    if payload_end > len(frame):
        return
    payload = frame[transport_offset + 8 : payload_end]
    payload_samples[bucket].append(
        {"bytes": len(payload), "sha256": hashlib.sha256(payload).hexdigest()}
    )


def stop(*_unused):
    global running
    running = False


signal.signal(signal.SIGTERM, stop)
signal.signal(signal.SIGINT, stop)
deadline = time.monotonic() + 300
while running and time.monotonic() < deadline:
    if marker_path != "-" and not marker_observed and os.path.exists(marker_path):
        before_marker = dict(counters)
        marker_observed = True
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
            is_wireguard_data = wireguard_message_type == 4 and udp_length > 40
            if role == "client":
                if interface == "underlay" and source == "43.159.1.1" and destination in {
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
                    if interface == "cr1" and {source, destination} == {
                        "43.159.1.1",
                        "44.160.1.1",
                    }:
                        counters["relay1_wireguard_data_datagrams"] += 1
                        counters["relay1_wireguard_data_bytes"] += udp_length - 8
                    if interface == "cr2" and {source, destination} == {
                        "43.159.1.1",
                        "45.161.2.1",
                    }:
                        counters["relay2_wireguard_data_datagrams"] += 1
                        counters["relay2_wireguard_data_bytes"] += udp_length - 8
                if interface.startswith("vpih") and protocol == socket.IPPROTO_UDP:
                    if source == "43.159.1.1" and destination == "47.163.4.2" \
                            and destination_port == 443:
                        sample_payload(
                            "client_ingress_requests", frame, transport_offset, udp_length
                        )
                    if source == "47.163.4.2" and source_port == 443 \
                            and destination == "43.159.1.1":
                        sample_payload(
                            "client_ingress_responses", frame, transport_offset, udp_length
                        )
            else:
                if protocol == socket.IPPROTO_UDP and is_wireguard_data:
                    if interface == "xr1" and {source, destination} == {
                        "44.160.1.1",
                        "46.162.3.1",
                    }:
                        counters["relay1_wireguard_data_datagrams"] += 1
                        counters["relay1_wireguard_data_bytes"] += udp_length - 8
                    if interface == "xr2" and {source, destination} == {
                        "45.161.2.1",
                        "46.162.3.1",
                    }:
                        counters["relay2_wireguard_data_datagrams"] += 1
                        counters["relay2_wireguard_data_bytes"] += udp_length - 8
                if interface == "xd" and protocol == socket.IPPROTO_UDP:
                    if destination == "47.163.4.2" and destination_port == 443:
                        counters["destination_request_datagrams"] += 1
                        sample_payload(
                            "destination_requests", frame, transport_offset, udp_length
                        )
                    if source == "47.163.4.2" and source_port == 443:
                        counters["destination_response_datagrams"] += 1
                        sample_payload(
                            "destination_responses", frame, transport_offset, udp_length
                        )

for capture in sockets:
    capture.close()
after_marker = None
if before_marker is not None:
    after_marker = {key: counters[key] - before_marker[key] for key in counters}
with open(output_path, "x", encoding="ascii") as output:
    json.dump(
        {
            "schema_version": 1,
            "capture_role": role,
            "interfaces": interfaces,
            "observed_frames": observed_frames,
            "truncated": truncated,
            "marker_observed": marker_observed,
            "before_marker": before_marker,
            "after_marker": after_marker,
            "payload_samples": payload_samples,
            **counters,
        },
        output,
        sort_keys=True,
        separators=(",", ":"),
    )
    output.write("\n")
PYTHON
cat >"$WORK/bin/privacy-observer.py" <<'PYTHON'
import json
import select
import signal
import socket
import struct
import sys
import time

role, output_path, ready_path, *interfaces = sys.argv[1:]
if role not in {"client", "relay1", "relay2", "exit"} or not interfaces:
    raise SystemExit("invalid privacy observer arguments")

counters = {
    "ipv4_frames": 0,
    "routed_transport_packets": 0,
    "internet_destination_outer_packets": 0,
    "unexpected_outer_packets": 0,
    "client_public_packets": 0,
    "direct_client_exit_packets": 0,
    "outbound_client_discovery_attempt_packets": 0,
    "control_relay_packets": 0,
    "client_leg_packets": 0,
    "exit_leg_packets": 0,
    "client_leg_wireguard_data_datagrams": 0,
    "exit_leg_wireguard_data_datagrams": 0,
    "relay1_wireguard_data_datagrams": 0,
    "relay2_wireguard_data_datagrams": 0,
}
sockets = {}
for interface in interfaces:
    capture = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(0x0003))
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
deadline = time.monotonic() + 1800


def is_ipv4_multicast(address):
    return 224 <= int(address.split(".", 1)[0]) <= 239


while running and time.monotonic() < deadline:
    readable, _, _ = select.select(list(sockets), [], [], 0.2)
    for capture in readable:
        while True:
            try:
                frame = capture.recv(65535)
            except BlockingIOError:
                break
            observed_frames += 1
            if observed_frames > 1048576:
                truncated = True
                running = False
                break
            if len(frame) < 34 or struct.unpack("!H", frame[12:14])[0] != 0x0800:
                continue
            offset = 14
            header_length = (frame[offset] & 0x0F) * 4
            if header_length < 20 or len(frame) < offset + header_length:
                continue
            counters["ipv4_frames"] += 1
            protocol = frame[offset + 9]
            source = socket.inet_ntoa(frame[offset + 12 : offset + 16])
            destination = socket.inet_ntoa(frame[offset + 16 : offset + 20])
            interface = sockets[capture]
            transport_offset = offset + header_length
            source_port = 0
            destination_port = 0
            if (
                protocol in {socket.IPPROTO_TCP, socket.IPPROTO_UDP}
                and len(frame) >= transport_offset + 4
            ):
                source_port, destination_port = struct.unpack(
                    "!HH", frame[transport_offset : transport_offset + 4]
                )
            is_outbound_client_discovery_attempt = (
                role == "exit"
                and interface == "underlay"
                and protocol == socket.IPPROTO_UDP
                and source == "46.162.3.1"
                and destination == "43.159.1.1"
                and source_port != 0
                and destination_port == 41000
            )
            if is_outbound_client_discovery_attempt:
                counters["outbound_client_discovery_attempt_packets"] += 1
            if protocol in {socket.IPPROTO_TCP, socket.IPPROTO_UDP}:
                counters["routed_transport_packets"] += 1
            if source == "47.163.4.2" or destination == "47.163.4.2":
                counters["internet_destination_outer_packets"] += 1
            if source == "43.159.1.1" or destination == "43.159.1.1":
                counters["client_public_packets"] += 1

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
                forbidden_exit = {
                    "10.241.20.2",
                    "10.241.21.2",
                    "10.241.22.2",
                    "10.241.23.2",
                    "10.241.24.2",
                    "10.241.25.2",
                    "10.241.26.2",
                    "10.241.31.1",
                    "10.241.31.2",
                    "10.241.32.1",
                    "10.241.32.2",
                    "46.162.3.1",
                    "47.163.4.1",
                    "47.163.4.2",
                    "51.167.7.1",
                    "52.168.8.1",
                    "52.168.8.2",
                }
                if (source == "43.159.1.1" and destination in forbidden_exit) or (
                    destination == "43.159.1.1" and source in forbidden_exit
                ):
                    counters["direct_client_exit_packets"] += 1
                if interface == "cr0":
                    counters["control_relay_packets"] += 1
                if is_wireguard_data and interface == "cr1" and {
                    source,
                    destination,
                } == {"43.159.1.1", "44.160.1.1"}:
                    counters["relay1_wireguard_data_datagrams"] += 1
                if is_wireguard_data and interface == "cr2" and {
                    source,
                    destination,
                } == {"43.159.1.1", "45.161.2.1"}:
                    counters["relay2_wireguard_data_datagrams"] += 1
            elif role in {"relay1", "relay2"}:
                # The Relay underlay also carries the fixed discovery topology. These public
                # addresses are control-plane peers, not the forbidden Internet destination
                # 47.163.4.2 whose appearance in an outer header is counted separately above.
                topology_control_public = {
                    "40.156.1.1",
                    "41.157.2.1",
                    "42.158.0.1",
                    "43.159.1.1",
                    "44.160.1.1",
                    "45.161.2.1",
                    "46.162.3.1",
                    "48.164.4.1",
                    "49.165.5.1",
                    "50.166.6.1",
                    "51.167.7.1",
                }
                if role == "relay1":
                    client_interface, exit_interface = "r1c", "r1x"
                    relay_public = "44.160.1.1"
                    allowed = topology_control_public | {
                        "10.241.11.1",
                        "10.241.11.2",
                        "10.241.21.1",
                        "10.241.21.2",
                    }
                else:
                    client_interface, exit_interface = "r2c", "r2x"
                    relay_public = "45.161.2.1"
                    allowed = topology_control_public | {
                        "10.241.12.1",
                        "10.241.12.2",
                        "10.241.22.1",
                        "10.241.22.2",
                    }
                if interface == client_interface:
                    counters["client_leg_packets"] += 1
                if interface == exit_interface:
                    counters["exit_leg_packets"] += 1
                # libp2p mDNS is expected control-plane discovery on these interfaces. It is not
                # a routed unicast dataplane header and must not make the A11 privacy proof fail.
                if (
                    not is_ipv4_multicast(source)
                    and not is_ipv4_multicast(destination)
                    and (source not in allowed or destination not in allowed)
                ):
                    counters["unexpected_outer_packets"] += 1
                if is_wireguard_data and {source, destination} == {
                    "43.159.1.1",
                    relay_public,
                }:
                    counters[f"{role}_wireguard_data_datagrams"] += 1
                    if interface == client_interface:
                        counters["client_leg_wireguard_data_datagrams"] += 1
                if is_wireguard_data and {source, destination} == {
                    relay_public,
                    "46.162.3.1",
                }:
                    counters[f"{role}_wireguard_data_datagrams"] += 1
                    if interface == exit_interface:
                        counters["exit_leg_wireguard_data_datagrams"] += 1
            else:
                if source == "43.159.1.1" or destination == "43.159.1.1":
                    counters["direct_client_exit_packets"] += 1
                if is_wireguard_data and interface == "xr1" and {
                    source,
                    destination,
                } == {"44.160.1.1", "46.162.3.1"}:
                    counters["relay1_wireguard_data_datagrams"] += 1
                if is_wireguard_data and interface == "xr2" and {
                    source,
                    destination,
                } == {"45.161.2.1", "46.162.3.1"}:
                    counters["relay2_wireguard_data_datagrams"] += 1

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
cat >"$WORK/bin/mptcp-download-client.py" <<'PYTHON'
import hashlib
import json
import socket
import sys
import time

run_id = bytes.fromhex(sys.argv[1])
case_name = sys.argv[2]
attempt = int(sys.argv[3])
if case_name not in {"a03-single", "a03-aggregate", "a04-failover"}:
    raise SystemExit("invalid bounded MPTCP download case")
if attempt < 0 or attempt >= 30:
    raise SystemExit("invalid bounded MPTCP download attempt")

request = (
    b"volparossa-"
    + case_name.encode("ascii")
    + b":"
    + run_id
    + attempt.to_bytes(4, "big")
)
response_label = b"a03" if case_name.startswith("a03-") else b"a04"
response_seed = b"volparossa-download:" + response_label + b":" + run_id
response_bytes = 32 * 1024 * 1024
expected_hash = hashlib.sha256()
remaining = response_bytes
while remaining:
    length = min(64 * 1024, remaining)
    expected = (response_seed * ((length + len(response_seed) - 1) // len(response_seed)))[
        :length
    ]
    expected_hash.update(expected)
    remaining -= length

destination = ("47.163.4.2", 18080)
with socket.create_connection(destination, timeout=60) as application:
    application.settimeout(180)
    application.sendall(request)
    application.shutdown(socket.SHUT_WR)
    received_hash = hashlib.sha256()
    received_bytes = 0
    first_byte_ns = None
    while received_bytes <= response_bytes:
        chunk = application.recv(min(64 * 1024, response_bytes + 1 - received_bytes))
        if not chunk:
            break
        if first_byte_ns is None:
            first_byte_ns = time.monotonic_ns()
        received_hash.update(chunk)
        received_bytes += len(chunk)
    completed_ns = time.monotonic_ns()
    local = application.getsockname()

if first_byte_ns is None or received_bytes != response_bytes:
    raise SystemExit("bounded MPTCP download was incomplete")
if received_hash.digest() != expected_hash.digest():
    raise SystemExit("bounded MPTCP download payload was substituted")
duration_ns = completed_ns - first_byte_ns
if duration_ns <= 0:
    raise SystemExit("bounded MPTCP download duration was invalid")
json.dump(
    {
        "schema_version": 1,
        "case": case_name,
        "attempt": attempt,
        "application": {"ip": local[0], "port": local[1]},
        "destination": {"ip": destination[0], "port": destination[1]},
        "request_bytes": len(request),
        "request_sha256": hashlib.sha256(request).hexdigest(),
        "response_bytes": received_bytes,
        "response_sha256": received_hash.hexdigest(),
        "first_byte_monotonic_ns": first_byte_ns,
        "completed_monotonic_ns": completed_ns,
        "duration_ns": duration_ns,
        "throughput_bits_per_second": (received_bytes * 8 * 1_000_000_000) // duration_ns,
    },
    sys.stdout,
    sort_keys=True,
    separators=(",", ":"),
)
sys.stdout.write("\n")
PYTHON
cat >"$WORK/bin/dns-policy-client.py" <<'PYTHON'
import hashlib
import json
import socket
import struct
import sys

mode = sys.argv[1]
run_id = bytes.fromhex(sys.argv[2])
if mode not in {"udp", "tcp"} or len(run_id) != 16:
    raise SystemExit("invalid bounded DNS acceptance arguments")

resolver = ("9.9.9.9", 53)
hostname = "destination.volparossa.test"
transaction_id = int.from_bytes(run_id[:2], "big") ^ (0x4400 if mode == "udp" else 0x5500)
labels = hostname.encode("ascii").split(b".")
question = b"".join(bytes([len(label)]) + label for label in labels) + b"\0\0\1\0\1"
query = struct.pack("!HHHHHH", transaction_id, 0x0100, 1, 0, 0, 0) + question

if mode == "udp":
    application = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    application.settimeout(180)
    application.sendto(query, resolver)
    response, source = application.recvfrom(4096)
else:
    application = socket.create_connection(resolver, timeout=180)
    application.settimeout(180)
    application.sendall(struct.pack("!H", len(query)) + query)
    encoded_length = bytearray()
    while len(encoded_length) < 2:
        chunk = application.recv(2 - len(encoded_length))
        if not chunk:
            raise SystemExit("DNS-over-TCP response length was incomplete")
        encoded_length.extend(chunk)
    remaining = struct.unpack("!H", encoded_length)[0]
    chunks = bytearray()
    while len(chunks) < remaining:
        chunk = application.recv(remaining - len(chunks))
        if not chunk:
            raise SystemExit("DNS-over-TCP response was incomplete")
        chunks.extend(chunk)
    response = bytes(chunks)
    source = application.getpeername()
local = application.getsockname()
application.close()

if len(response) < 12:
    raise SystemExit("DNS response was truncated")
response_id, flags, questions, answers, authorities, additionals = struct.unpack(
    "!HHHHHH", response[:12]
)
if response_id != transaction_id or flags & 0x8000 == 0 or flags & 0x000F != 0:
    raise SystemExit("DNS response header did not match the request")
if questions != 1 or answers < 1 or response[12 : 12 + len(question)] != question:
    raise SystemExit("DNS response question was substituted")


def skip_name(packet, offset):
    while True:
        if offset >= len(packet):
            raise SystemExit("DNS response name was truncated")
        length = packet[offset]
        if length & 0xC0 == 0xC0:
            if offset + 2 > len(packet):
                raise SystemExit("DNS response pointer was truncated")
            return offset + 2
        offset += 1
        if length == 0:
            return offset
        if length > 63 or offset + length > len(packet):
            raise SystemExit("DNS response label was invalid")
        offset += length


offset = 12 + len(question)
addresses = []
for _ in range(answers):
    offset = skip_name(response, offset)
    if offset + 10 > len(response):
        raise SystemExit("DNS resource record was truncated")
    record_type, record_class, ttl, length = struct.unpack("!HHIH", response[offset : offset + 10])
    offset += 10
    data = response[offset : offset + length]
    if len(data) != length:
        raise SystemExit("DNS resource data was truncated")
    offset += length
    if record_type == 1 and record_class == 1 and length == 4 and 0 < ttl <= 30:
        addresses.append(socket.inet_ntoa(data))
if addresses != ["47.163.4.2"]:
    raise SystemExit("DNS answer was not the exact Exit-resolved policy address")

json.dump(
    {
        "schema_version": 1,
        "mode": mode,
        "hostname": hostname,
        "resolver": {"ip": resolver[0], "port": resolver[1]},
        "application": {"ip": local[0], "port": local[1]},
        "response_source": {"ip": source[0], "port": source[1]},
        "transaction_id": transaction_id,
        "query_bytes": len(query),
        "query_sha256": hashlib.sha256(query).hexdigest(),
        "response_bytes": len(response),
        "response_sha256": hashlib.sha256(response).hexdigest(),
        "answer_addresses": addresses,
        "authority_records": authorities,
        "additional_records": additionals,
    },
    sys.stdout,
    sort_keys=True,
    separators=(",", ":"),
)
sys.stdout.write("\n")
PYTHON
cat >"$WORK/bin/destination.py" <<'PYTHON'
import hashlib
import json
import os
import select
import signal
import socket
import sys
import time

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
download_payload_bytes = 32 * 1024 * 1024
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
            connection.settimeout(180)
            received = bytearray()
            while len(received) < tcp_payload_bytes:
                chunk = connection.recv(tcp_payload_bytes - len(received))
                if not chunk:
                    break
                received.extend(chunk)
            if len(received) == tcp_payload_bytes and received.startswith(tcp_prefix):
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
                    "case": "a02",
                    "listen": {"ip": "47.163.4.2", "port": 18080},
                    "source": {"ip": source[0], "port": source[1]},
                    "attempt": attempt,
                    "bytes": len(received),
                    "sha256": hashlib.sha256(received).hexdigest(),
                }
                evidence_path = os.path.join(sys.argv[3], f"tcp-evidence-{attempt}.json")
            else:
                matched = None
                for case_name in ("a03-single", "a03-aggregate", "a04-failover"):
                    prefix = b"volparossa-" + case_name.encode("ascii") + b":" + run_id
                    if len(received) == len(prefix) + 4 and received.startswith(prefix):
                        matched = (case_name, prefix)
                        break
                if matched is None:
                    continue
                case_name, prefix = matched
                attempt = int.from_bytes(received[len(prefix) :], "big")
                if attempt >= 30:
                    continue
                ready_path = os.path.join(
                    sys.argv[3], f"download-{case_name}-{attempt}.ready"
                )
                release_path = os.path.join(
                    sys.argv[3], f"download-{case_name}-{attempt}.release"
                )
                open(ready_path, "x", encoding="ascii").write("ready\n")
                release_deadline = time.monotonic() + 90
                while not os.path.exists(release_path):
                    if time.monotonic() >= release_deadline:
                        raise SystemExit("bounded download release was not observed")
                    time.sleep(0.05)
                response_label = b"a03" if case_name.startswith("a03-") else b"a04"
                response_seed = b"volparossa-download:" + response_label + b":" + run_id
                response_hash = hashlib.sha256()
                remaining = download_payload_bytes
                while remaining:
                    length = min(64 * 1024, remaining)
                    response = (response_seed * ((length + len(response_seed) - 1) // len(response_seed)))[
                        :length
                    ]
                    connection.sendall(response)
                    response_hash.update(response)
                    remaining -= length
                connection.shutdown(socket.SHUT_WR)
                evidence = {
                    "schema_version": 1,
                    "case": case_name,
                    "listen": {"ip": "47.163.4.2", "port": 18080},
                    "source": {"ip": source[0], "port": source[1]},
                    "attempt": attempt,
                    "request_bytes": len(received),
                    "request_sha256": hashlib.sha256(received).hexdigest(),
                    "response_bytes": download_payload_bytes,
                    "response_sha256": response_hash.hexdigest(),
                }
                evidence_path = os.path.join(
                    sys.argv[3], f"download-{case_name}-{attempt}.json"
                )
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
chown root:root "$WORK/bin/a02-observer.py" "$WORK/bin/a05-observer.py" \
    "$WORK/bin/a06-observer.py" "$WORK/bin/privacy-observer.py"
chmod 0500 "$WORK/bin/a02-observer.py" "$WORK/bin/a05-observer.py" \
    "$WORK/bin/a06-observer.py" "$WORK/bin/privacy-observer.py"
chown root:root "$WORK/bin/mptcp-download-client.py" "$WORK/bin/dns-policy-client.py"
chmod 0555 "$WORK/bin/mptcp-download-client.py" "$WORK/bin/dns-policy-client.py"
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
    for node in client bootstrap1 bootstrap2 relay0 relay1 relay2 relay3 relay4 relay5 \
        exit exit2; do
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

for node in client bootstrap1 bootstrap2 relay0 relay1 relay2 relay3 relay4 relay5 exit exit2; do
    "$binary_directory/volparossa" \
        --control-socket "$WORK/runtime-$node/control/agent.sock" status \
        >"$WORK/status-$node.txt"
    "$binary_directory/volparossa" \
        --control-socket "$WORK/runtime-$node/control/agent.sock" role show \
        >"$WORK/roles-$node.txt"
done
grep -Fx 'client: true' "$WORK/roles-client.txt" >/dev/null || fail CLIENT_ROLE_INVALID
grep -Fx 'client: false' "$WORK/roles-bootstrap1.txt" >/dev/null \
    || fail BOOTSTRAP1_CLIENT_ROLE_INVALID
grep -Fx 'client: false' "$WORK/roles-bootstrap2.txt" >/dev/null \
    || fail BOOTSTRAP2_CLIENT_ROLE_INVALID
grep -Fx 'relay: false' "$WORK/roles-bootstrap1.txt" >/dev/null \
    || fail BOOTSTRAP1_RELAY_ROLE_INVALID
grep -Fx 'relay: false' "$WORK/roles-bootstrap2.txt" >/dev/null \
    || fail BOOTSTRAP2_RELAY_ROLE_INVALID
grep -Fx 'exit: false' "$WORK/roles-bootstrap1.txt" >/dev/null \
    || fail BOOTSTRAP1_EXIT_ROLE_INVALID
grep -Fx 'exit: false' "$WORK/roles-bootstrap2.txt" >/dev/null \
    || fail BOOTSTRAP2_EXIT_ROLE_INVALID
grep -Fx 'client: false' "$WORK/roles-relay0.txt" >/dev/null || fail RELAY0_CLIENT_ROLE_INVALID
grep -Fx 'client: false' "$WORK/roles-relay1.txt" >/dev/null || fail RELAY1_CLIENT_ROLE_INVALID
grep -Fx 'client: false' "$WORK/roles-relay2.txt" >/dev/null || fail RELAY2_CLIENT_ROLE_INVALID
grep -Fx 'client: false' "$WORK/roles-relay3.txt" >/dev/null || fail RELAY3_CLIENT_ROLE_INVALID
grep -Fx 'client: false' "$WORK/roles-relay4.txt" >/dev/null || fail RELAY4_CLIENT_ROLE_INVALID
grep -Fx 'client: false' "$WORK/roles-relay5.txt" >/dev/null || fail RELAY5_CLIENT_ROLE_INVALID
grep -Fx 'client: false' "$WORK/roles-exit.txt" >/dev/null || fail EXIT_CLIENT_ROLE_INVALID
grep -Fx 'client: false' "$WORK/roles-exit2.txt" >/dev/null || fail EXIT2_CLIENT_ROLE_INVALID
grep -Fx 'relay: true' "$WORK/roles-relay0.txt" >/dev/null || fail RELAY0_ROLE_INVALID
grep -Fx 'relay: true' "$WORK/roles-relay1.txt" >/dev/null || fail RELAY1_ROLE_INVALID
grep -Fx 'relay: true' "$WORK/roles-relay2.txt" >/dev/null || fail RELAY2_ROLE_INVALID
grep -Fx 'relay: true' "$WORK/roles-relay3.txt" >/dev/null || fail RELAY3_ROLE_INVALID
grep -Fx 'relay: true' "$WORK/roles-relay4.txt" >/dev/null || fail RELAY4_ROLE_INVALID
grep -Fx 'relay: true' "$WORK/roles-relay5.txt" >/dev/null || fail RELAY5_ROLE_INVALID
grep -Fx 'exit: true' "$WORK/roles-exit.txt" >/dev/null || fail EXIT_ROLE_INVALID
grep -Fx 'exit: true' "$WORK/roles-exit2.txt" >/dev/null || fail EXIT2_ROLE_INVALID

PHASE=discovery
attempt=0
while [ "$attempt" -lt 300 ]; do
    control_ready=yes
    for node in client bootstrap1 bootstrap2 relay0 relay1 relay2 relay3 relay4 relay5 \
        exit exit2; do
        if ! "$binary_directory/volparossa" \
            --control-socket "$WORK/runtime-$node/control/agent.sock" status \
            >"$WORK/status-$node.txt"; then
            control_ready=no
            continue
        fi
        active_peers=$(awk '/^active peers: / { print $3 }' "$WORK/status-$node.txt")
        case $node in
            client) required_active_peers=2 ;;
            bootstrap1|bootstrap2) required_active_peers=7 ;;
            relay0) required_active_peers=4 ;;
            relay1|relay2|relay3|relay4|relay5) required_active_peers=2 ;;
            exit|exit2) required_active_peers=1 ;;
        esac
        [ -n "$active_peers" ] \
            && [ "$active_peers" -ge "$required_active_peers" ] || control_ready=no
    done
    [ "$control_ready" = yes ] && break
    sleep 0.1
    attempt=$((attempt + 1))
done
[ "$control_ready" = yes ] || fail DISCOVERY_NOT_READY

peer_advertisement_sequence() {
    sequence_peer=$1
    python3 - "$WORK/state-client/peers.sqlite3" "$sequence_peer" <<'PYTHON'
import sqlite3
import sys

database, peer_id = sys.argv[1:]
connection = sqlite3.connect(f"file:{database}?mode=ro", uri=True, timeout=5)
try:
    row = connection.execute(
        "SELECT sequence_number FROM advertisements WHERE peer_id = ?",
        (peer_id,),
    ).fetchone()
finally:
    connection.close()
if row is None or not isinstance(row[0], int) or row[0] < 1:
    raise SystemExit(1)
print(row[0])
PYTHON
}

capture_link_bytes() {
    link_namespace=$1
    link_interface=$2
    link_output=$3
    ip -n "$link_namespace" -s -j link show dev "$link_interface" \
        | jq -S -c --arg interface "$link_interface" '
            .[0] as $link | ($link.stats64 // $link.stats) as $stats
            | {interface:$interface,rx_bytes:$stats.rx.bytes,tx_bytes:$stats.tx.bytes}' \
        >"$link_output"
    jq -e '.rx_bytes >= 0 and .tx_bytes >= 0' "$link_output" >/dev/null
}

block_bootstrap_contact() {
    blocked_namespace=$1
    ip netns exec "$blocked_namespace" nft add table inet vp_a01_block
    ip netns exec "$blocked_namespace" nft \
        'add chain inet vp_a01_block input { type filter hook input priority -300; policy accept; }'
    ip netns exec "$blocked_namespace" nft \
        'add chain inet vp_a01_block output { type filter hook output priority -300; policy accept; }'
    ip netns exec "$blocked_namespace" nft add rule inet vp_a01_block input \
        meta l4proto udp counter drop
    ip netns exec "$blocked_namespace" nft add rule inet vp_a01_block output \
        meta l4proto udp counter drop
}

capture_blocked_contact() {
    blocked_label=$1
    blocked_namespace=$2
    blocked_peer=$3
    blocked_output=$4
    blocked_unit=volparossa-alpha-agent@$blocked_label.service
    blocked_pid=$(systemctl show --property=MainPID --value "$blocked_unit")
    blocked_state=$(systemctl show --property=ActiveState --value "$blocked_unit")
    case $blocked_pid in ''|0|*[!0-9]*) return 1 ;; esac
    [ "$blocked_state" = active ] || return 1
    ip netns exec "$blocked_namespace" nft -j list table inet vp_a01_block \
        | jq -S -c --arg label "$blocked_label" --arg peer "$blocked_peer" \
            --argjson pid "$blocked_pid" '
            ([.nftables[].rule.expr[]?.counter.packets // empty] | add // 0) as $packets
            | ([.nftables[].rule.expr[]?.counter.bytes // empty] | add // 0) as $bytes
            | {contact:$label,peer_id:$peer,agent_pid:$pid,agent_active:true,
               isolation:"all UDP dropped in contact namespace",
               dropped_packets:$packets,dropped_bytes:$bytes}' >"$blocked_output"
    jq -e '.agent_active and .dropped_packets > 0 and .dropped_bytes > 0' \
        "$blocked_output" >/dev/null
}

unblock_bootstrap_contact() {
    ip netns exec "$1" nft delete table inet vp_a01_block
}

restart_advertiser() {
    restart_node=$1
    restart_unit=volparossa-alpha-agent@$restart_node.service
    restart_old_pid=$(systemctl show --property=MainPID --value "$restart_unit")
    case $restart_old_pid in ''|0|*[!0-9]*) return 1 ;; esac
    systemctl restart "$restart_unit" || return 1
    restart_attempt=0
    while [ "$restart_attempt" -lt 300 ]; do
        restart_state=$(systemctl show --property=ActiveState --value \
            "$restart_unit" 2>/dev/null || true)
        restart_new_pid=$(systemctl show --property=MainPID --value \
            "$restart_unit" 2>/dev/null || true)
        if [ "$restart_state" = active ] \
            && [ -S "$WORK/runtime-$restart_node/control/agent.sock" ] \
            && [ -n "$restart_new_pid" ] && [ "$restart_new_pid" != 0 ] \
            && [ "$restart_new_pid" != "$restart_old_pid" ]; then
            return 0
        fi
        sleep 0.1
        restart_attempt=$((restart_attempt + 1))
    done
    return 1
}

wait_fresh_advertisement() {
    fresh_peer=$1
    fresh_before=$2
    fresh_attempt=0
    while [ "$fresh_attempt" -lt 600 ]; do
        fresh_after=$(peer_advertisement_sequence "$fresh_peer" 2>/dev/null || true)
        case $fresh_after in ''|*[!0-9]*) fresh_after=0 ;; esac
        if [ "$fresh_after" -gt "$fresh_before" ]; then
            printf '%s\n' "$fresh_after"
            return 0
        fi
        sleep 0.1
        fresh_attempt=$((fresh_attempt + 1))
    done
    return 1
}

wait_disconnected() {
    idle_attempt=0
    while [ "$idle_attempt" -lt 300 ]; do
        "$binary_directory/volparossa" \
            --control-socket "$WORK/runtime-client/control/agent.sock" status \
            >"$WORK/status-client.txt" 2>/dev/null || true
        if grep -Fx 'connected: false' "$WORK/status-client.txt" >/dev/null \
            && grep -Fx 'active contexts: 0' "$WORK/status-client.txt" >/dev/null; then
            return 0
        fi
        sleep 0.1
        idle_attempt=$((idle_attempt + 1))
    done
    return 1
}

a01_transient_connect_unavailable() {
    grep -Eq '^Error: agent rejected request: (PRESELECTION_UNAVAILABLE|NATIVE_PERMIT_UNAVAILABLE|NATIVE_RELAY_READY_UNAVAILABLE|NATIVE_HELPER_COMMIT_UNAVAILABLE|NATIVE_PROBE_START_UNAVAILABLE|NATIVE_PROBE_PROOF_UNAVAILABLE|ROUTE_ADMISSION_UNAVAILABLE) \(Unavailable\)$' "$1"
}

a01_select_route() {
    selection_label=$1
    selection_status=1
    selection_attempt=0
    selection_attempt_error="$WORK/a01-$selection_label-connect-attempt.err"
    : >"$WORK/a01-$selection_label-connect.err"
    # Route teardown leaves the preselection gate cooling for 30 s, while a refreshed provider
    # advertisement can legitimately take up to 60 s. Keep a finite two-minute recovery horizon
    # for exact transient unavailability; protocol/correlation failures still stop immediately.
    while [ "$selection_attempt" -lt 120 ]; do
        set +e
        "$binary_directory/volparossa" \
            --control-socket "$WORK/runtime-client/control/agent.sock" connect \
            --transport multipath-quic \
            >"$WORK/a01-$selection_label-connect.out" \
            2>"$selection_attempt_error" &
        selection_pid=$!
        selection_diagnostic_attempt=0
        while kill -0 "$selection_pid" 2>/dev/null \
            && [ "$selection_diagnostic_attempt" -lt 100 ]; do
            selection_interface_count=$(count_worker_wireguard_interfaces)
            if [ "$selection_interface_count" -ge 8 ]; then
                capture_worker_network_diagnostics \
                    "a01-$selection_label-live-native-probe"
                break
            fi
            sleep 0.1
            selection_diagnostic_attempt=$((selection_diagnostic_attempt + 1))
        done
        wait "$selection_pid"
        selection_status=$?
        set -e
        sed -n 'p' "$selection_attempt_error" \
            >>"$WORK/a01-$selection_label-connect.err"
        [ "$selection_status" -ne 0 ] || break
        a01_transient_connect_unavailable "$selection_attempt_error" || break
        sleep 1
        selection_attempt=$((selection_attempt + 1))
    done
    if [ "$selection_status" -ne 0 ]; then
        if grep -F 'NATIVE_PROBE_START_UNAVAILABLE' \
            "$selection_attempt_error" >/dev/null; then
            capture_worker_network_diagnostics "a01-$selection_label-native-probe-failure"
        fi
        return 1
    fi

    selection_path_attempt=0
    while [ "$selection_path_attempt" -lt 300 ]; do
        "$binary_directory/volparossa" \
            --control-socket "$WORK/runtime-client/control/agent.sock" paths \
            >"$WORK/a01-$selection_label-paths.txt" || true
        if python3 - "$WORK/a01-$selection_label-paths.txt" \
            "$WORK/a01-$selection_label-selection.json" "$R1_PEER" "$R2_PEER" \
            "$EXIT_PEER" <<'PYTHON'
import json
import re
import sys

source, output, relay1, relay2, expected_exit = sys.argv[1:]
pattern = re.compile(
    r"context=([0-9a-f]{32}) path=([1-8]) relay=(\S+) exit=(\S+) "
    r"state=([0-9]+) rtt_us=([0-9]+) bytes=([0-9]+)"
)
paths = []
for line in open(source, encoding="ascii"):
    match = pattern.fullmatch(line.rstrip("\n"))
    if match is None:
        continue
    context, path_id, relay, exit_peer, state, rtt, byte_count = match.groups()
    paths.append(
        {
            "route_context_id": context,
            "path_id": int(path_id),
            "relay_peer_id": relay,
            "exit_peer_id": exit_peer,
            "state": int(state),
            "smoothed_rtt_us": int(rtt),
            "reported_bytes": int(byte_count),
        }
    )
if len(paths) != 2:
    raise SystemExit(1)
if {path["relay_peer_id"] for path in paths} != {relay1, relay2}:
    raise SystemExit(1)
if {path["exit_peer_id"] for path in paths} != {expected_exit}:
    raise SystemExit(1)
if len({path["route_context_id"] for path in paths}) != 1:
    raise SystemExit(1)
if len({path["path_id"] for path in paths}) != 2:
    raise SystemExit(1)
paths.sort(key=lambda path: path["path_id"])
with open(output, "w", encoding="ascii") as destination:
    json.dump(
        {
            "exact_selected_relays": [relay1, relay2],
            "exact_selected_exit": expected_exit,
            "paths": paths,
        },
        destination,
        sort_keys=True,
        separators=(",", ":"),
    )
    destination.write("\n")
PYTHON
        then
            break
        fi
        sleep 0.1
        selection_path_attempt=$((selection_path_attempt + 1))
    done
    [ "$selection_path_attempt" -lt 300 ] || return 1
    "$binary_directory/volparossa" \
        --control-socket "$WORK/runtime-client/control/agent.sock" disconnect \
        >"$WORK/a01-$selection_label-disconnect.out" \
        2>"$WORK/a01-$selection_label-disconnect.err" || return 1
    wait_disconnected
}

wait_bootstrap_mesh() {
    mesh_attempt=0
    while [ "$mesh_attempt" -lt 600 ]; do
        mesh_ready=yes
        # A restored bootstrap contact only needs the functional quorum used by the
        # remaining datapath cases. Requiring every incidental direct connection
        # made this recovery gate depend on libp2p redial timing after A01 had
        # already proved discovery and route establishment through each contact.
        for mesh_node_required in client:2 bootstrap1:3 bootstrap2:3 \
            relay0:3 relay1:2 relay2:2 exit:1; do
            mesh_node=${mesh_node_required%%:*}
            mesh_required=${mesh_node_required#*:}
            if ! "$binary_directory/volparossa" \
                --control-socket "$WORK/runtime-$mesh_node/control/agent.sock" status \
                >"$WORK/status-$mesh_node.txt" 2>/dev/null; then
                mesh_ready=no
                continue
            fi
            mesh_active=$(awk '/^active peers: / { print $3 }' \
                "$WORK/status-$mesh_node.txt")
            case $mesh_active in ''|*[!0-9]*) mesh_ready=no; continue ;; esac
            [ "$mesh_active" -ge "$mesh_required" ] || mesh_ready=no
        done
        [ "$mesh_ready" = yes ] && return 0
        sleep 0.1
        mesh_attempt=$((mesh_attempt + 1))
    done
    return 1
}

PHASE=a01-bootstrap1-loss
A01_REQUESTED=true
A01_STATUS=1
initial_advertisement_attempt=0
while [ "$initial_advertisement_attempt" -lt 600 ]; do
    initial_advertisements_ready=yes
    "$binary_directory/volparossa" \
        --control-socket "$WORK/runtime-client/control/agent.sock" peers \
        >"$WORK/a01-initial-peers.txt" || initial_advertisements_ready=no
    for required_relay_peer in "$R0_PEER" "$R1_PEER" "$R2_PEER" "$R3_PEER" \
        "$R4_PEER" "$R5_PEER"; do
        if ! grep -F "$required_relay_peer" "$WORK/a01-initial-peers.txt" \
            | grep -F 'roles=0b010' >/dev/null; then
            initial_advertisements_ready=no
        fi
    done
    for required_exit_peer in "$EXIT_PEER" "$EXIT2_PEER"; do
        if ! grep -F "$required_exit_peer" "$WORK/a01-initial-peers.txt" \
            | grep -F 'roles=0b100' >/dev/null; then
            initial_advertisements_ready=no
        fi
    done
    [ "$initial_advertisements_ready" = yes ] && break
    sleep 0.1
    initial_advertisement_attempt=$((initial_advertisement_attempt + 1))
done
[ "$initial_advertisements_ready" = yes ] \
    || fail A01_INITIAL_ADVERTISEMENTS_UNAVAILABLE

jq -S -c -n \
    --arg r0 "$R0_PEER" --arg r1 "$R1_PEER" --arg r2 "$R2_PEER" \
    --arg r3 "$R3_PEER" --arg r4 "$R4_PEER" --arg r5 "$R5_PEER" \
    --arg exit1 "$EXIT_PEER" --arg exit2 "$EXIT2_PEER" \
    '{schema_version:1,topology_requirement:"AV1-19",
      node_count:12,relay_count:6,exit_count:2,physical_network_count:29,
      relay_peers:[$r0,$r1,$r2,$r3,$r4,$r5],exit_peers:[$exit1,$exit2],
      relay_metadata:[
        {name:"relay0",peer_id:$r0,operator:"acceptance-relay-zero",asn:64511,ipv4_prefix:"42.158.0.0/24"},
        {name:"relay1",peer_id:$r1,operator:"acceptance-relay-one",asn:64512,ipv4_prefix:"44.160.1.0/24"},
        {name:"relay2",peer_id:$r2,operator:"acceptance-relay-two",asn:64513,ipv4_prefix:"45.161.2.0/24"},
        {name:"relay3",peer_id:$r3,operator:"acceptance-relay-three",asn:64515,ipv4_prefix:"48.164.4.0/24"},
        {name:"relay4",peer_id:$r4,operator:"acceptance-relay-four",asn:64516,ipv4_prefix:"49.165.5.0/24"},
        {name:"relay5",peer_id:$r5,operator:"acceptance-relay-five",asn:64517,ipv4_prefix:"50.166.6.0/24"}],
      exit_metadata:[
        {name:"exit",peer_id:$exit1,operator:"acceptance-exit",asn:64514,ipv4_prefix:"46.162.3.0/24"},
        {name:"exit2",peer_id:$exit2,operator:"acceptance-exit-two",asn:64518,ipv4_prefix:"51.167.7.0/24"}],
      active_datapath_pool:{relays:[$r1,$r2],exit:$exit1,capacity_mbps:32},
      deterministic_standby_pool:{relays:[$r3,$r4,$r5],exit:$exit2,
        advertised_capacity_mbps:1,client_minimum_capacity_mbps:8},
      independent_metadata:{operator:true,asn:true,ipv4_prefix:true},
      advertisements_observed_by_client:true,direct_client_exit_adjacency:false,
      production_helpers:11,production_agents:11,native_mpquic_processes:3}' \
    >"$WORK/topology-scale.json"
jq -e '
  .node_count == 12 and .relay_count >= 6 and .exit_count >= 2 and
  (.relay_peers | length) == 6 and (.relay_peers | unique | length) == 6 and
  (.exit_peers | length) == 2 and (.exit_peers | unique | length) == 2 and
  ([.relay_peers[],.exit_peers[]] | unique | length) == 8 and
  ([.relay_metadata[].operator] | unique | length) == 6 and
  ([.relay_metadata[].asn] | unique | length) == 6 and
  ([.relay_metadata[].ipv4_prefix] | unique | length) == 6 and
  ([.exit_metadata[].operator] | unique | length) == 2 and
  ([.exit_metadata[].asn] | unique | length) == 2 and
  ([.exit_metadata[].ipv4_prefix] | unique | length) == 2 and
  .advertisements_observed_by_client and
  (.direct_client_exit_adjacency | not)
' "$WORK/topology-scale.json" >/dev/null || fail TOPOLOGY_SCALE_EVIDENCE_INVALID

a01_b1_sequence_before=$(peer_advertisement_sequence "$R2_PEER") \
    || fail A01_INITIAL_ADVERTISEMENT_SEQUENCE_UNAVAILABLE
capture_link_bytes "$B2" b2r2 \
    "$WORK/a01-bootstrap1-remaining-link-before.json" \
    || fail A01_REMAINING_CONTACT_COUNTER_UNAVAILABLE
block_bootstrap_contact "$B1" || fail A01_BOOTSTRAP1_ISOLATION_FAILED
restart_advertiser relay2 || fail A01_RELAY2_RESTART_FAILED
a01_b1_sequence_after=$(wait_fresh_advertisement "$R2_PEER" \
    "$a01_b1_sequence_before") || fail A01_BOOTSTRAP1_ADVERTISEMENT_STALLED
capture_link_bytes "$B2" b2r2 \
    "$WORK/a01-bootstrap1-remaining-link-after.json" \
    || fail A01_REMAINING_CONTACT_COUNTER_UNAVAILABLE
capture_blocked_contact bootstrap1 "$B1" "$B1_PEER" \
    "$WORK/a01-bootstrap1-blocked.json" \
    || fail A01_BOOTSTRAP1_ISOLATION_NOT_OBSERVED
a01_select_route bootstrap1 || fail A01_BOOTSTRAP1_SELECTION_FAILED
unblock_bootstrap_contact "$B1" || fail A01_BOOTSTRAP1_RESTORE_FAILED
wait_bootstrap_mesh || fail A01_BOOTSTRAP1_MESH_NOT_RESTORED

PHASE=a01-bootstrap2-loss
a01_b2_sequence_before=$(peer_advertisement_sequence "$R1_PEER") \
    || fail A01_INITIAL_ADVERTISEMENT_SEQUENCE_UNAVAILABLE
capture_link_bytes "$B1" b1r1 \
    "$WORK/a01-bootstrap2-remaining-link-before.json" \
    || fail A01_REMAINING_CONTACT_COUNTER_UNAVAILABLE
block_bootstrap_contact "$B2" || fail A01_BOOTSTRAP2_ISOLATION_FAILED
restart_advertiser relay1 || fail A01_RELAY1_RESTART_FAILED
a01_b2_sequence_after=$(wait_fresh_advertisement "$R1_PEER" \
    "$a01_b2_sequence_before") || fail A01_BOOTSTRAP2_ADVERTISEMENT_STALLED
capture_link_bytes "$B1" b1r1 \
    "$WORK/a01-bootstrap2-remaining-link-after.json" \
    || fail A01_REMAINING_CONTACT_COUNTER_UNAVAILABLE
capture_blocked_contact bootstrap2 "$B2" "$B2_PEER" \
    "$WORK/a01-bootstrap2-blocked.json" \
    || fail A01_BOOTSTRAP2_ISOLATION_NOT_OBSERVED
a01_select_route bootstrap2 || fail A01_BOOTSTRAP2_SELECTION_FAILED
unblock_bootstrap_contact "$B2" || fail A01_BOOTSTRAP2_RESTORE_FAILED
wait_bootstrap_mesh || fail A01_BOOTSTRAP2_MESH_NOT_RESTORED

jq -S -c -n \
    --arg b1_peer "$B1_PEER" --arg b2_peer "$B2_PEER" \
    --arg relay1_peer "$R1_PEER" --arg relay2_peer "$R2_PEER" \
    --argjson b1_before "$a01_b1_sequence_before" \
    --argjson b1_after "$a01_b1_sequence_after" \
    --argjson b2_before "$a01_b2_sequence_before" \
    --argjson b2_after "$a01_b2_sequence_after" \
    --slurpfile b1_block "$WORK/a01-bootstrap1-blocked.json" \
    --slurpfile b2_block "$WORK/a01-bootstrap2-blocked.json" \
    --slurpfile b1_link_before "$WORK/a01-bootstrap1-remaining-link-before.json" \
    --slurpfile b1_link_after "$WORK/a01-bootstrap1-remaining-link-after.json" \
    --slurpfile b2_link_before "$WORK/a01-bootstrap2-remaining-link-before.json" \
    --slurpfile b2_link_after "$WORK/a01-bootstrap2-remaining-link-after.json" \
    --slurpfile b1_selection "$WORK/a01-bootstrap1-selection.json" \
    --slurpfile b2_selection "$WORK/a01-bootstrap2-selection.json" \
    '($b1_link_after[0].rx_bytes + $b1_link_after[0].tx_bytes
        - $b1_link_before[0].rx_bytes - $b1_link_before[0].tx_bytes) as $b1_delta
    | ($b2_link_after[0].rx_bytes + $b2_link_after[0].tx_bytes
        - $b2_link_before[0].rx_bytes - $b2_link_before[0].tx_bytes) as $b2_delta
    | (($b1_after > $b1_before) and ($b2_after > $b2_before)
        and ($b1_delta > 0) and ($b2_delta > 0)
        and $b1_block[0].agent_active and ($b1_block[0].dropped_packets > 0)
        and $b2_block[0].agent_active and ($b2_block[0].dropped_packets > 0)
        and (($b1_selection[0].paths | length) == 2)
        and (($b2_selection[0].paths | length) == 2)) as $success
    | {schema_version:1,acceptance_id:"A01",success:$success,
       topology:{bootstrap_contacts:[$b1_peer,$b2_peer],
         independently_removed:true,direct_client_exit_adjacency:false},
       bootstrap1_removed:{isolation:$b1_block[0],remaining_contact:$b2_peer,
         remaining_contact_link_bytes_delta:$b1_delta,
         fresh_advertisement:{peer_id:$relay2_peer,
           sequence_before:$b1_before,sequence_after:$b1_after},
         selection:$b1_selection[0]},
       bootstrap2_removed:{isolation:$b2_block[0],remaining_contact:$b1_peer,
         remaining_contact_link_bytes_delta:$b2_delta,
         fresh_advertisement:{peer_id:$relay1_peer,
           sequence_before:$b2_before,sequence_after:$b2_after},
         selection:$b2_selection[0]},
       verification_basis:{real_agents:true,real_libp2p:true,
         signed_peerstore_advertisement_sequence_advanced:true,
         real_route_setup_completed_twice:true,mocks:false}}' >"$WORK/a01-evidence.json"
jq -e '.success == true' "$WORK/a01-evidence.json" >/dev/null \
    || fail A01_EVIDENCE_INVALID
A01_STATUS=0
A01_SUCCEEDED=true
OBSERVED_BLOCKER=NONE
PHASE=a01-complete

capture_product_logs() {
    for log_node in client bootstrap1 bootstrap2 relay0 relay1 relay2 relay3 relay4 \
        relay5 exit exit2; do
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

capture_native_mpquic_paths() {
    native_prefix=$1
    native_requirement=$2
    native_text="$WORK/$native_prefix.txt"
    native_json="$WORK/$native_prefix.json"
    "$binary_directory/volparossa" \
        --control-socket "$WORK/runtime-client/control/agent.sock" paths \
        >"$native_text" || return 1
    python3 - "$native_text" "$native_json" "$R1_PEER" "$R2_PEER" \
        "$native_requirement" <<'PYTHON'
import json
import re
import sys

source_path, output_path, relay1_peer, relay2_peer, requirement = sys.argv[1:]
if requirement not in {"both", "relay2"}:
    raise SystemExit("invalid native-path requirement")
pattern = re.compile(
    r"context=([0-9a-f]{32}) path=([1-8]) relay=(\S+) exit=(\S+) "
    r"state=([0-9]+) rtt_us=([0-9]+) bytes=([0-9]+)"
)
groups = {}
for line in open(source_path, encoding="ascii"):
    match = pattern.fullmatch(line.rstrip("\n"))
    if match is None:
        continue
    context, path_id, relay_peer, exit_peer, state, rtt_us, user_bytes = match.groups()
    if relay_peer not in {relay1_peer, relay2_peer}:
        continue
    relay = "relay1" if relay_peer == relay1_peer else "relay2"
    record = {
        "path_id": int(path_id),
        "relay": relay,
        "relay_peer_id": relay_peer,
        "exit_peer_id": exit_peer,
        "state": int(state),
        "smoothed_rtt_us": int(rtt_us),
        # The native daemon exposes an ACK/accounting counter. It proves path
        # activity, not unique application bytes; packet observers below carry
        # the independent encrypted outer-byte evidence.
        "native_acked_bytes": int(user_bytes),
    }
    if any(existing["relay"] == relay for existing in groups.setdefault(context, [])):
        raise SystemExit("duplicate native path for one relay")
    groups[context].append(record)

required = {"relay1", "relay2"} if requirement == "both" else {"relay2"}
candidates = [
    (context, paths)
    for context, paths in groups.items()
    if required.issubset({path["relay"] for path in paths})
]
if len(candidates) != 1:
    raise SystemExit("exact active native route context was unavailable")
context, paths = candidates[0]
paths.sort(key=lambda path: path["path_id"])
if len({path["path_id"] for path in paths}) != len(paths):
    raise SystemExit("native path IDs were not distinct")
with open(output_path, "w", encoding="ascii") as output:
    json.dump(
        {
            "schema_version": 1,
            "source": "agent local-control native MPQUIC status",
            "route_context_id": context,
            "requirement": requirement,
            "paths": paths,
        },
        output,
        sort_keys=True,
        separators=(",", ":"),
    )
    output.write("\n")
PYTHON
}

wait_native_mpquic_paths() {
    wait_prefix=$1
    wait_requirement=$2
    native_attempt=0
    while [ "$native_attempt" -lt 300 ]; do
        if capture_native_mpquic_paths "$wait_prefix" "$wait_requirement"; then
            return 0
        fi
        sleep 0.1
        native_attempt=$((native_attempt + 1))
    done
    return 1
}

wait_active_native_mpquic_paths() {
    active_prefix=$1
    active_attempt=0
    while [ "$active_attempt" -lt 300 ]; do
        if capture_native_mpquic_paths "$active_prefix" both \
            && jq -e '
                .requirement == "both" and
                (.paths | length) == 2 and
                ([.paths[].relay] | sort) == ["relay1", "relay2"] and
                all(.paths[]; .state == 3)
            ' "$WORK/$active_prefix.json" >/dev/null 2>&1; then
            return 0
        fi
        sleep 0.1
        active_attempt=$((active_attempt + 1))
    done
    return 1
}

start_http3_observers() {
    http3_prefix=$1
    http3_marker=$2
    client_ingress_interface=$(ip -n "$CLIENT" -o link show \
        | awk -F': ' '$2 ~ /^vpih/ {sub(/@.*/, "", $2); print $2; exit}')
    [ -n "$client_ingress_interface" ] || return 1
    ip netns exec "$CLIENT" python3 "$WORK/bin/a06-observer.py" \
        client "$WORK/$http3_prefix-client-capture.json" \
        "$WORK/$http3_prefix-client-capture.ready" "$http3_marker" \
        cr1 cr2 underlay "$client_ingress_interface" \
        >"$WORK/$http3_prefix-client-capture.log" \
        2>"$WORK/$http3_prefix-client-capture.err" &
    CLIENT_OBSERVER_PID=$!
    ip netns exec "$EXIT_NODE" python3 "$WORK/bin/a06-observer.py" \
        exit "$WORK/$http3_prefix-exit-capture.json" \
        "$WORK/$http3_prefix-exit-capture.ready" "$http3_marker" \
        xr1 xr2 xd >"$WORK/$http3_prefix-exit-capture.log" \
        2>"$WORK/$http3_prefix-exit-capture.err" &
    EXIT_OBSERVER_PID=$!
    if ! wait_observer "$CLIENT_OBSERVER_PID" \
        "$WORK/$http3_prefix-client-capture.ready" \
        || ! wait_observer "$EXIT_OBSERVER_PID" \
        "$WORK/$http3_prefix-exit-capture.ready"; then
        stop_observers || true
        return 1
    fi
}

start_privacy_observers() {
    ip -n "$CLIENT" -j route show table all | jq -S . \
        >"$WORK/a13-client-routes-before.json" || return 1
    set +e
    ip -n "$CLIENT" -o route get 46.162.3.1 \
        >"$WORK/a13-exit-route-before.txt" 2>&1
    route_status=$?
    set -e
    printf 'exit_status=%s\n' "$route_status" >>"$WORK/a13-exit-route-before.txt"
    set +e
    ip -n "$CLIENT" -o route get 47.163.4.2 \
        >"$WORK/a13-destination-route-before.txt" 2>&1
    route_status=$?
    set -e
    printf 'exit_status=%s\n' "$route_status" \
        >>"$WORK/a13-destination-route-before.txt"

    ip netns exec "$CLIENT" python3 "$WORK/bin/privacy-observer.py" \
        client "$WORK/privacy-client.json" "$WORK/privacy-client.ready" \
        cr0 cr1 cr2 cr3 cr4 cr5 cb1 cb2 underlay \
        >"$WORK/privacy-client.log" 2>&1 &
    PRIVACY_CLIENT_PID=$!
    ip netns exec "$R1" python3 "$WORK/bin/privacy-observer.py" \
        relay1 "$WORK/privacy-relay1.json" "$WORK/privacy-relay1.ready" \
        r1c r1x underlay >"$WORK/privacy-relay1.log" 2>&1 &
    PRIVACY_RELAY1_PID=$!
    ip netns exec "$R2" python3 "$WORK/bin/privacy-observer.py" \
        relay2 "$WORK/privacy-relay2.json" "$WORK/privacy-relay2.ready" \
        r2c r2x underlay >"$WORK/privacy-relay2.log" 2>&1 &
    PRIVACY_RELAY2_PID=$!
    ip netns exec "$EXIT_NODE" python3 "$WORK/bin/privacy-observer.py" \
        exit "$WORK/privacy-exit.json" "$WORK/privacy-exit.ready" \
        xr0 xr1 xr2 xr3 xr4 xr5 xd underlay >"$WORK/privacy-exit.log" 2>&1 &
    PRIVACY_EXIT_PID=$!

    wait_observer "$PRIVACY_CLIENT_PID" "$WORK/privacy-client.ready" \
        && wait_observer "$PRIVACY_RELAY1_PID" "$WORK/privacy-relay1.ready" \
        && wait_observer "$PRIVACY_RELAY2_PID" "$WORK/privacy-relay2.ready" \
        && wait_observer "$PRIVACY_EXIT_PID" "$WORK/privacy-exit.ready"
}

stop_privacy_observers() {
    privacy_status=0
    for privacy_pid in "$PRIVACY_CLIENT_PID" "$PRIVACY_RELAY1_PID" \
        "$PRIVACY_RELAY2_PID" "$PRIVACY_EXIT_PID"; do
        [ -z "$privacy_pid" ] || kill -TERM "$privacy_pid" 2>/dev/null || true
    done
    for privacy_pid in "$PRIVACY_CLIENT_PID" "$PRIVACY_RELAY1_PID" \
        "$PRIVACY_RELAY2_PID" "$PRIVACY_EXIT_PID"; do
        if [ -n "$privacy_pid" ] && ! wait "$privacy_pid"; then
            privacy_status=1
        fi
    done
    PRIVACY_CLIENT_PID=
    PRIVACY_RELAY1_PID=
    PRIVACY_RELAY2_PID=
    PRIVACY_EXIT_PID=
    return "$privacy_status"
}

refresh_a14_live_custody() {
    "$binary_directory/volparossa" \
        --control-socket "$WORK/runtime-client/control/agent.sock" disconnect \
        >"$WORK/a14-refresh-disconnect.out" \
        2>"$WORK/a14-refresh-disconnect.err" || return 1
    wait_disconnected || return 1

    a14_connect_status=1
    a14_connect_attempt=0
    a14_connect_attempt_error=$WORK/a14-refresh-connect-attempt.err
    : >"$WORK/a14-refresh-connect.err"
    # A disconnected preselection owner cools for 30 seconds. Establish a new route immediately
    # before the crash inventory so earlier A08-A10 wall-clock time cannot retire the four affine
    # Client/Relay/Exit worker namespaces or their eight systemd FD-store descriptors first.
    while [ "$a14_connect_attempt" -lt 120 ]; do
        set +e
        "$binary_directory/volparossa" \
            --control-socket "$WORK/runtime-client/control/agent.sock" connect \
            --transport mptcp >"$WORK/a14-refresh-connect.out" \
            2>"$a14_connect_attempt_error"
        a14_connect_status=$?
        set -e
        sed -n 'p' "$a14_connect_attempt_error" \
            >>"$WORK/a14-refresh-connect.err"
        [ "$a14_connect_status" -ne 0 ] || break
        a01_transient_connect_unavailable "$a14_connect_attempt_error" || break
        sleep 1
        a14_connect_attempt=$((a14_connect_attempt + 1))
    done
    rm -f -- "$a14_connect_attempt_error"
    [ "$a14_connect_status" -eq 0 ]
}

record_a14_worker_custody_inventory() {
    a14_worker_rows=$WORK/a14-worker-custody-before.ndjson
    : >"$a14_worker_rows"
    a14_fdstore_descriptors=0
    for a14_node_namespace in client:"$CLIENT" bootstrap1:"$B1" bootstrap2:"$B2" \
        relay0:"$R0" relay1:"$R1" relay2:"$R2" relay3:"$R3" relay4:"$R4" \
        relay5:"$R5" exit:"$EXIT_NODE" exit2:"$EXIT2_NODE"; do
        a14_node=${a14_node_namespace%%:*}
        a14_outer_namespace=${a14_node_namespace#*:}
        a14_unit=volparossa-alpha-helper@$a14_node.service
        a14_cgroup=$(systemctl show --property=ControlGroup --value "$a14_unit") \
            || return 1
        case $a14_cgroup in /system.slice/*) ;; *) return 1 ;; esac
        a14_cgroup_root=/sys/fs/cgroup$a14_cgroup
        [ -d "$a14_cgroup_root" ] || return 1
        a14_fdstore=$(systemctl show --property=NFileDescriptorStore --value \
            "$a14_unit") || return 1
        case $a14_fdstore in ''|*[!0-9]*) return 1 ;; esac
        a14_fdstore_descriptors=$((a14_fdstore_descriptors + a14_fdstore))
        a14_outer_identity=$(stat -Lc '%d:%i' "/run/netns/$a14_outer_namespace") \
            || return 1
        a14_worker_pids=$(find "$a14_cgroup_root" -type f -name cgroup.procs \
            -exec cat {} \; 2>/dev/null | sort -nu | tr '\n' ' ')
        for a14_worker_pid in $a14_worker_pids; do
            [ -r "/proc/$a14_worker_pid/cmdline" ] || continue
            a14_command=$(tr '\000' ' ' <"/proc/$a14_worker_pid/cmdline")
            case $a14_command in *'--internal-worker-v3'*) ;; *) continue ;; esac
            a14_worker_identity=$(stat -Lc '%d:%i' "/proc/$a14_worker_pid/ns/net") \
                || return 1
            [ "$a14_worker_identity" != "$a14_outer_identity" ] || return 1
            a14_worker_device=${a14_worker_identity%%:*}
            a14_worker_inode=${a14_worker_identity#*:}
            case $a14_worker_device:$a14_worker_inode in
                :*|*:|*[!0-9:]*) return 1 ;;
            esac
            jq -S -c -n --arg node "$a14_node" \
                --arg unit "$a14_unit" --argjson pid "$a14_worker_pid" \
                --argjson device "$a14_worker_device" \
                --argjson inode "$a14_worker_inode" \
                '{node:$node,helper_unit:$unit,worker_pid_before:$pid,
                  network_namespace_device:$device,network_namespace_inode:$inode}' \
                >>"$a14_worker_rows" || return 1
        done
    done
    jq -S -c -s --argjson fdstore "$a14_fdstore_descriptors" '
      . as $workers
      | ($workers | unique_by([.network_namespace_device,
          .network_namespace_inode])) as $namespaces
      | {schema_version:1,worker_process_count:($workers | length),
         worker_network_namespace_count:($namespaces | length),
         helper_fdstore_descriptors:$fdstore,
         worker_network_namespaces:$namespaces}' "$a14_worker_rows" \
        >"$WORK/a14-worker-custody-before.json" || return 1
    rm -f -- "$a14_worker_rows"
}

scan_a14_worker_namespace_references() {
    python3 - "$WORK/a14-worker-custody-before.json" \
        "$WORK/a14-worker-custody-after.json" <<'PYTHON'
import json
import os
import sys

source_path, output_path = sys.argv[1:]
with open(source_path, encoding="ascii") as source:
    inventory = json.load(source)
targets = inventory.get("worker_network_namespaces")
if not isinstance(targets, list) or not targets or len(targets) > 128:
    raise SystemExit("invalid A14 worker namespace inventory")

by_identity = {}
for target in targets:
    device = target.get("network_namespace_device")
    inode = target.get("network_namespace_inode")
    if not isinstance(device, int) or device <= 0 or not isinstance(inode, int) or inode <= 0:
        raise SystemExit("invalid A14 worker namespace identity")
    identity = (device, inode)
    if identity in by_identity:
        raise SystemExit("duplicate A14 worker namespace identity")
    by_identity[identity] = {**target, "references_after": []}

for process in os.scandir("/proc"):
    if not process.name.isdecimal():
        continue
    pid = int(process.name)
    observations = [(f"/proc/{pid}/ns/net", "process-network-namespace", None)]
    try:
        descriptors = os.scandir(f"/proc/{pid}/fd")
    except (FileNotFoundError, PermissionError, ProcessLookupError):
        descriptors = ()
    try:
        for descriptor in descriptors:
            if descriptor.name.isdecimal():
                observations.append(
                    (descriptor.path, "open-descriptor", int(descriptor.name))
                )
    finally:
        close = getattr(descriptors, "close", None)
        if close is not None:
            close()
    for path, kind, descriptor in observations:
        try:
            status = os.stat(path)
        except (FileNotFoundError, PermissionError, ProcessLookupError):
            continue
        target = by_identity.get((status.st_dev, status.st_ino))
        if target is None:
            continue
        reference = {"pid": pid, "kind": kind}
        if descriptor is not None:
            reference["descriptor"] = descriptor
        target["references_after"].append(reference)

remaining = list(by_identity.values())
remaining.sort(
    key=lambda item: (
        item["network_namespace_device"], item["network_namespace_inode"]
    )
)
reference_count = sum(len(item["references_after"]) for item in remaining)
if reference_count > 4096:
    raise SystemExit("A14 worker namespace reference inventory is oversized")
result = {
    "schema_version": 1,
    "worker_network_namespaces": remaining,
    "referenced_namespace_count": sum(
        bool(item["references_after"]) for item in remaining
    ),
    "remaining_reference_count": reference_count,
}
with open(output_path, "x", encoding="ascii") as output:
    json.dump(result, output, sort_keys=True, separators=(",", ":"))
    output.write("\n")
PYTHON
}

remaining_a14_helper_fdstore_descriptors() {
    a14_remaining_fdstore=0
    for a14_node in client bootstrap1 bootstrap2 relay0 relay1 relay2 relay3 relay4 \
        relay5 exit exit2; do
        a14_unit=volparossa-alpha-helper@$a14_node.service
        [ "$(unit_load_state "$a14_unit")" != not-found ] || continue
        a14_count=$(systemctl show --property=NFileDescriptorStore --value \
            "$a14_unit") || return 1
        case $a14_count in ''|*[!0-9]*) return 1 ;; esac
        a14_remaining_fdstore=$((a14_remaining_fdstore + a14_count))
    done
    printf '%s\n' "$a14_remaining_fdstore"
}

record_a14_owned_inventory() {
    record_a14_worker_custody_inventory || return 1
    "$binary_directory/volparossa" \
        --control-socket "$WORK/runtime-client/control/agent.sock" paths \
        >"$WORK/a14-paths-before.txt" || return 1
    a14_control_path_records=$(awk '
        /^context=[0-9a-f][0-9a-f]* path=[1-8] relay=/ { count++ }
        END { print count + 0 }
    ' "$WORK/a14-paths-before.txt")
    a14_namespace_count=0
    for a14_node_namespace in client:"$CLIENT" bootstrap1:"$B1" bootstrap2:"$B2" \
        relay0:"$R0" relay1:"$R1" relay2:"$R2" relay3:"$R3" relay4:"$R4" \
        relay5:"$R5" exit:"$EXIT_NODE" exit2:"$EXIT2_NODE" destination:"$DEST"; do
        a14_node=${a14_node_namespace%%:*}
        a14_namespace=${a14_node_namespace#*:}
        [ -n "$(ip netns list | awk -v name="$a14_namespace" \
            '$1 == name { print $1 }')" ] || return 1
        a14_namespace_count=$((a14_namespace_count + 1))
        a14_links=$(ip -n "$a14_namespace" -j link show | jq -er 'length') \
            || return 1
        a14_routes=$(ip -n "$a14_namespace" -j route show table all \
            | jq -er 'length') || return 1
        a14_rules=$(ip -n "$a14_namespace" -j rule show | jq -er 'length') \
            || return 1
        a14_wireguard=$(ip -n "$a14_namespace" -j link show type wireguard \
            | jq -er 'length') || return 1
        a14_mptcp=$(ip netns exec "$a14_namespace" ip -j mptcp endpoint show \
            | jq -er 'length') || return 1
        a14_nft=$(ip netns exec "$a14_namespace" nft -j list ruleset \
            | jq -er '[.nftables[] | select(has("rule"))] | length') \
            || return 1
        jq -S -c -n --arg node "$a14_node" --arg namespace "$a14_namespace" \
            --argjson links "$a14_links" --argjson routes "$a14_routes" \
            --argjson rules "$a14_rules" --argjson wireguard "$a14_wireguard" \
            --argjson mptcp "$a14_mptcp" --argjson nft "$a14_nft" \
            '{node:$node,namespace:$namespace,links:$links,routes:$routes,
              policy_rules:$rules,wireguard_links:$wireguard,
              mptcp_endpoints:$mptcp,nftables_rules:$nft}' \
            >"$WORK/a14-owned-$a14_node.json" || return 1
    done
    a14_socket_count=$(find "$WORK"/runtime-* -type s -print \
        | awk 'END { print NR + 0 }')
    jq -S -c -n \
        --argjson namespace_count "$a14_namespace_count" \
        --argjson runtime_sockets "$a14_socket_count" \
        --argjson control_path_records "$a14_control_path_records" \
        --slurpfile worker_custody "$WORK/a14-worker-custody-before.json" \
        --slurpfile client "$WORK/a14-owned-client.json" \
        --slurpfile bootstrap1 "$WORK/a14-owned-bootstrap1.json" \
        --slurpfile bootstrap2 "$WORK/a14-owned-bootstrap2.json" \
        --slurpfile relay0 "$WORK/a14-owned-relay0.json" \
        --slurpfile relay1 "$WORK/a14-owned-relay1.json" \
        --slurpfile relay2 "$WORK/a14-owned-relay2.json" \
        --slurpfile relay3 "$WORK/a14-owned-relay3.json" \
        --slurpfile relay4 "$WORK/a14-owned-relay4.json" \
        --slurpfile relay5 "$WORK/a14-owned-relay5.json" \
        --slurpfile exit_node "$WORK/a14-owned-exit.json" \
        --slurpfile exit2_node "$WORK/a14-owned-exit2.json" \
        --slurpfile destination "$WORK/a14-owned-destination.json" \
        '{schema_version:1,network_namespace_count:$namespace_count,
          runtime_socket_count:$runtime_sockets,
          active_control_path_records:$control_path_records,
          helper_worker_custody:$worker_custody[0],
          namespaces:[$client[0],$bootstrap1[0],$bootstrap2[0],$relay0[0],
            $relay1[0],$relay2[0],$relay3[0],$relay4[0],$relay5[0],
            $exit_node[0],$exit2_node[0],$destination[0]]}' \
        >"$WORK/a14-owned-before.json"
}

verify_a14_helper_restart_recovery() {
    a14_restart_rows=$WORK/a14-helper-restarts.ndjson
    : >"$a14_restart_rows"
    for a14_restart_node in client bootstrap1 bootstrap2 relay0 relay1 relay2 relay3 \
        relay4 relay5 exit exit2; do
        a14_restart_unit=volparossa-alpha-helper@$a14_restart_node.service
        a14_crash_record=$WORK/a14-crash-helper-$a14_restart_node.json
        a14_old_pid=$(jq -er '.pid_before' "$a14_crash_record") || return 1
        a14_restart_attempt=0
        while [ "$a14_restart_attempt" -lt 450 ]; do
            a14_restart_state=$(systemctl show --property=ActiveState --value \
                "$a14_restart_unit" 2>/dev/null || true)
            a14_restart_substate=$(systemctl show --property=SubState --value \
                "$a14_restart_unit" 2>/dev/null || true)
            a14_new_pid=$(systemctl show --property=MainPID --value \
                "$a14_restart_unit" 2>/dev/null || true)
            a14_fdstore_after=$(systemctl show --property=NFileDescriptorStore --value \
                "$a14_restart_unit" 2>/dev/null || true)
            if [ "$a14_restart_state:$a14_restart_substate" = active:running ] \
                && [ -S "$WORK/runtime-$a14_restart_node/helper.sock" ] \
                && [ "$a14_new_pid" != "$a14_old_pid" ] \
                && [ "$a14_fdstore_after" = 0 ]; then
                break
            fi
            sleep 0.1
            a14_restart_attempt=$((a14_restart_attempt + 1))
        done
        [ "$a14_restart_attempt" -lt 450 ] || return 1
        case $a14_new_pid in ''|0|*[!0-9]*) return 1 ;; esac
        jq -S -c -n --arg node "$a14_restart_node" \
            --arg unit "$a14_restart_unit" --argjson old_pid "$a14_old_pid" \
            --argjson new_pid "$a14_new_pid" \
            '{node:$node,unit:$unit,old_pid:$old_pid,new_pid:$new_pid,
              restarted:true,helper_socket_republished:true,
              inherited_fdstore_descriptors_after:0}' \
            >>"$a14_restart_rows" || return 1
    done
    jq -S -c -s '
      {schema_version:1,all_helpers_restarted:(length == 11 and all(.[]; .restarted)),
       helpers:.}' "$a14_restart_rows" >"$WORK/a14-helper-restarts.json" || return 1
    rm -f -- "$a14_restart_rows"
    jq -e '.all_helpers_restarted == true' "$WORK/a14-helper-restarts.json" >/dev/null
}

measure_a14_remaining_network_objects() {
    remaining_links=0
    remaining_routes=0
    remaining_mptcp_endpoints=0
    remaining_mpquic_paths=0
    remaining_nftables_rules=0

    for remaining_namespace in $(ip netns list | awk -v prefix="$PREFIX-" \
        '$1 ~ ("^" prefix) { print $1 }'); do
        measured_links=$(ip -n "$remaining_namespace" -j link show \
            | jq -er 'length') || return 1
        measured_routes=$(ip -n "$remaining_namespace" -j route show table all \
            | jq -er 'length') || return 1
        measured_mptcp=$(ip netns exec "$remaining_namespace" \
            ip -j mptcp endpoint show | jq -er 'length') || return 1
        measured_nft=$(ip netns exec "$remaining_namespace" nft -j list ruleset \
            | jq -er '[.nftables[] | select(has("rule"))] | length') \
            || return 1
        remaining_links=$((remaining_links + measured_links))
        remaining_routes=$((remaining_routes + measured_routes))
        remaining_mptcp_endpoints=$((remaining_mptcp_endpoints + measured_mptcp))
        remaining_nftables_rules=$((remaining_nftables_rules + measured_nft))
    done

    : >"$WORK/a14-owned-after-paths.txt"
    for remaining_control_socket in "$WORK"/runtime-*/control/agent.sock; do
        [ -S "$remaining_control_socket" ] || continue
        remaining_paths_file=$WORK/a14-owned-after-paths-one.txt
        if "$binary_directory/volparossa" \
            --control-socket "$remaining_control_socket" paths \
            >"$remaining_paths_file" 2>/dev/null; then
            cat "$remaining_paths_file" >>"$WORK/a14-owned-after-paths.txt"
            measured_paths=$(awk '
                /^context=[0-9a-f][0-9a-f]* path=[1-8] relay=/ { count++ }
                END { print count + 0 }
            ' "$remaining_paths_file")
            remaining_mpquic_paths=$((remaining_mpquic_paths + measured_paths))
        fi
        rm -f -- "$remaining_paths_file"
    done
    scan_a14_worker_namespace_references || return 1
    remaining_worker_network_namespaces=$(jq -er '.referenced_namespace_count' \
        "$WORK/a14-worker-custody-after.json") || return 1
    remaining_worker_namespace_references=$(jq -er '.remaining_reference_count' \
        "$WORK/a14-worker-custody-after.json") || return 1
    case $remaining_worker_network_namespaces:$remaining_worker_namespace_references in
        :*|*:|*[!0-9:]*) return 1 ;;
    esac
    remaining_helper_fdstore_descriptors=$(remaining_a14_helper_fdstore_descriptors) \
        || return 1
    case $remaining_helper_fdstore_descriptors in ''|*[!0-9]*) return 1 ;; esac
}

force_crash_unit() {
    crash_class=$1
    crash_node=$2
    crash_unit=$3
    crash_pid=$(systemctl show --property=MainPID --value "$crash_unit")
    crash_state=$(systemctl show --property=ActiveState --value "$crash_unit")
    case $crash_pid in ''|0|*[!0-9]*) return 1 ;; esac
    [ "$crash_state" = active ] || return 1
    systemctl kill --kill-whom=all --signal=KILL "$crash_unit" || return 1
    crash_attempt=0
    while [ "$crash_attempt" -lt 100 ]; do
        crash_after_state=$(systemctl show --property=ActiveState --value \
            "$crash_unit" 2>/dev/null || true)
        if [ ! -e "/proc/$crash_pid" ] && [ "$crash_after_state" != active ]; then
            break
        fi
        sleep 0.1
        crash_attempt=$((crash_attempt + 1))
    done
    [ "$crash_attempt" -lt 100 ] || return 1
    jq -S -c -n --arg class "$crash_class" --arg node "$crash_node" \
        --arg unit "$crash_unit" --arg state_before "$crash_state" \
        --arg state_after "$crash_after_state" --argjson pid "$crash_pid" \
        '{class:$class,node:$node,unit:$unit,pid_before:$pid,
          active_state_before:$state_before,active_state_after:$state_after,
          sigkill_delivered:true,pid_absent_after:true}' \
        >"$WORK/a14-crash-$crash_class-$crash_node.json"
}

tc_sent_bytes() {
    tc_namespace=$1
    tc_interface=$2
    tc_bytes=$(ip netns exec "$tc_namespace" tc -s qdisc show dev "$tc_interface" \
        | awk '/ Sent [0-9]+ bytes / { print $2; exit }')
    case $tc_bytes in ''|*[!0-9]*) return 1 ;; esac
    printf '%s\n' "$tc_bytes"
}

start_mptcp_download() {
    DOWNLOAD_CASE=$1
    DOWNLOAD_PREFIX=$2
    DOWNLOAD_ATTEMPT=$3
    DOWNLOAD_MARKER=$4
    DOWNLOAD_CLIENT_OUTPUT="$WORK/$DOWNLOAD_PREFIX-client-$DOWNLOAD_ATTEMPT.json"
    DOWNLOAD_CLIENT_ERROR="$WORK/$DOWNLOAD_PREFIX-client.err"
    DOWNLOAD_CLIENT_CAPTURE="$WORK/$DOWNLOAD_PREFIX-client-capture-$DOWNLOAD_ATTEMPT.json"
    DOWNLOAD_CLIENT_CAPTURE_READY="$WORK/$DOWNLOAD_PREFIX-client-capture-$DOWNLOAD_ATTEMPT.ready"
    DOWNLOAD_EXIT_CAPTURE="$WORK/$DOWNLOAD_PREFIX-exit-capture-$DOWNLOAD_ATTEMPT.json"
    DOWNLOAD_EXIT_CAPTURE_READY="$WORK/$DOWNLOAD_PREFIX-exit-capture-$DOWNLOAD_ATTEMPT.ready"
    DOWNLOAD_DESTINATION_READY="$WORK/destination/download-$DOWNLOAD_CASE-$DOWNLOAD_ATTEMPT.ready"
    DOWNLOAD_DESTINATION_RELEASE="$WORK/destination/download-$DOWNLOAD_CASE-$DOWNLOAD_ATTEMPT.release"
    DOWNLOAD_DESTINATION_EVIDENCE="$WORK/destination/download-$DOWNLOAD_CASE-$DOWNLOAD_ATTEMPT.json"

    ip netns exec "$CLIENT" python3 "$WORK/bin/a02-observer.py" \
        client "$DOWNLOAD_CLIENT_CAPTURE" "$DOWNLOAD_CLIENT_CAPTURE_READY" \
        "$DOWNLOAD_MARKER" cr1 cr2 underlay \
        >"$WORK/$DOWNLOAD_PREFIX-client-capture.log" \
        2>"$WORK/$DOWNLOAD_PREFIX-client-capture.err" &
    CLIENT_OBSERVER_PID=$!
    ip netns exec "$EXIT_NODE" python3 "$WORK/bin/a02-observer.py" \
        exit "$DOWNLOAD_EXIT_CAPTURE" "$DOWNLOAD_EXIT_CAPTURE_READY" \
        "$DOWNLOAD_MARKER" xr1 xr2 xd \
        >"$WORK/$DOWNLOAD_PREFIX-exit-capture.log" \
        2>"$WORK/$DOWNLOAD_PREFIX-exit-capture.err" &
    EXIT_OBSERVER_PID=$!
    if ! wait_observer "$CLIENT_OBSERVER_PID" "$DOWNLOAD_CLIENT_CAPTURE_READY" \
        || ! wait_observer "$EXIT_OBSERVER_PID" "$DOWNLOAD_EXIT_CAPTURE_READY"; then
        stop_observers || true
        return 1
    fi

    : >"$DOWNLOAD_CLIENT_ERROR"
    ip netns exec "$CLIENT" setpriv --reuid="$WORKER_UID" --regid="$WORKER_GID" \
        --clear-groups --inh-caps=-all --ambient-caps=-all --bounding-set=-all \
        --no-new-privs -- python3 "$WORK/bin/mptcp-download-client.py" \
        "$RUN_ID" "$DOWNLOAD_CASE" "$DOWNLOAD_ATTEMPT" \
        >"$DOWNLOAD_CLIENT_OUTPUT" 2>"$DOWNLOAD_CLIENT_ERROR" &
    DOWNLOAD_CLIENT_PID=$!

    download_ready_attempt=0
    while [ "$download_ready_attempt" -lt 600 ]; do
        [ ! -s "$DOWNLOAD_DESTINATION_READY" ] || return 0
        kill -0 "$DOWNLOAD_CLIENT_PID" 2>/dev/null || break
        sleep 0.1
        download_ready_attempt=$((download_ready_attempt + 1))
    done
    set +e
    wait "$DOWNLOAD_CLIENT_PID"
    set -e
    DOWNLOAD_CLIENT_PID=
    stop_observers || true
    return 1
}

release_mptcp_download() {
    install -o "$AGENT_UID" -g "$AGENT_GID" -m 0600 /dev/null \
        "$DOWNLOAD_DESTINATION_RELEASE"
}

finish_mptcp_download() {
    download_status=0
    set +e
    wait "$DOWNLOAD_CLIENT_PID"
    download_status=$?
    set -e
    DOWNLOAD_CLIENT_PID=
    destination_attempt=0
    while [ "$download_status" -eq 0 ] && [ "$destination_attempt" -lt 100 ] \
        && [ ! -s "$DOWNLOAD_DESTINATION_EVIDENCE" ]; do
        sleep 0.1
        destination_attempt=$((destination_attempt + 1))
    done
    stop_observers || download_status=1
    for download_evidence in "$DOWNLOAD_CLIENT_OUTPUT" \
        "$DOWNLOAD_DESTINATION_EVIDENCE" "$DOWNLOAD_CLIENT_CAPTURE" \
        "$DOWNLOAD_EXIT_CAPTURE"; do
        if [ "$download_status" -eq 0 ] \
            && { [ ! -s "$download_evidence" ] \
                || ! jq -e . "$download_evidence" >/dev/null 2>&1; }; then
            download_status=1
        fi
    done
    if [ "$download_status" -eq 0 ]; then
        install -o root -g root -m 0600 \
            "$DOWNLOAD_CLIENT_OUTPUT" "$WORK/$DOWNLOAD_PREFIX-client.json"
        install -o root -g root -m 0600 \
            "$DOWNLOAD_DESTINATION_EVIDENCE" \
            "$WORK/destination-$DOWNLOAD_PREFIX-evidence.json"
        install -o root -g root -m 0600 \
            "$DOWNLOAD_CLIENT_CAPTURE" "$WORK/$DOWNLOAD_PREFIX-client-capture.json"
        install -o root -g root -m 0600 \
            "$DOWNLOAD_EXIT_CAPTURE" "$WORK/$DOWNLOAD_PREFIX-exit-capture.json"
    fi
    return "$download_status"
}

PHASE=a02-capture
A02_REQUESTED=true
A02_FALLBACK_ROUTE=$(ip -n "$CLIENT" -o route get "$A02_DESTINATION_IP" | sed -n '1p')
printf '%s\n' "$A02_FALLBACK_ROUTE" >"$WORK/a02-client-fallback-route.txt"
printf '%s\n' "$A02_FALLBACK_ROUTE" | grep -Eq '(^| )dev underlay( |$)' \
    || fail A02_FALLBACK_ROUTE_INVALID
if printf '%s\n' "$A02_FALLBACK_ROUTE" | grep -Eq '(^| )dev (cr0|cr1|cr2)( |$)'; then
    fail DIRECT_CLIENT_EXIT_REACHABLE
fi

PHASE=a02-transparent-tcp-echo
: >"$WORK/a02-client.err"
attempt=0
# A01's successful preselection deliberately retains its affine gate for a 30-second cooldown.
# Leave bounded scheduling margin so A02 always gets attempts after that gate becomes reusable.
while [ "$attempt" -lt 45 ]; do
    attempt_label=$(printf '%02d' "$attempt")
    client_capture="$WORK/a02-client-capture-$attempt_label.json"
    client_capture_ready="$WORK/a02-client-capture-$attempt_label.ready"
    exit_capture="$WORK/a02-exit-capture-$attempt_label.json"
    exit_capture_ready="$WORK/a02-exit-capture-$attempt_label.ready"
    destination_evidence="$WORK/destination/tcp-evidence-$attempt.json"

    ip netns exec "$CLIENT" python3 "$WORK/bin/a02-observer.py" \
        client "$client_capture" "$client_capture_ready" - \
        cr1 cr2 underlay >"$WORK/a02-client-capture.log" \
        2>"$WORK/a02-client-capture.err" &
    CLIENT_OBSERVER_PID=$!
    ip netns exec "$EXIT_NODE" python3 "$WORK/bin/a02-observer.py" \
        exit "$exit_capture" "$exit_capture_ready" - \
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
    if [ "$A02_STATUS" -ne 0 ] && [ "$attempt" -eq 0 ]; then
        capture_worker_network_diagnostics a02-first-flow-failure
        if [ -s "$client_capture" ] \
            && jq -e . "$client_capture" >/dev/null 2>&1; then
            install -o root -g root -m 0600 "$client_capture" \
                "$WORK/a02-first-failed-client-capture.json"
        fi
        if [ -s "$exit_capture" ] \
            && jq -e . "$exit_capture" >/dev/null 2>&1; then
            install -o root -g root -m 0600 "$exit_capture" \
                "$WORK/a02-first-failed-exit-capture.json"
        fi
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

PHASE=a03-constrain-relay-paths
A03_REQUESTED=true
ip netns exec "$R1" tc qdisc replace dev r1c root tbf \
    rate 8mbit burst 128kb latency 250ms
ip netns exec "$R2" tc qdisc replace dev r2c root tbf \
    rate 8mbit burst 128kb latency 250ms
ip netns exec "$R1" tc qdisc show dev r1c | grep -F 'qdisc tbf ' >/dev/null \
    || fail A03_RELAY1_LIMIT_UNAVAILABLE
ip netns exec "$R2" tc qdisc show dev r2c | grep -F 'qdisc tbf ' >/dev/null \
    || fail A03_RELAY2_LIMIT_UNAVAILABLE
A03_STATUS=1

PHASE=a03-single-path-download
attempt=0
while [ "$attempt" -lt 30 ]; do
    if start_mptcp_download a03-single a03-single "$attempt" -; then
        single_before_r1=$(tc_sent_bytes "$R1" r1c) \
            || fail A03_RELAY1_COUNTER_UNAVAILABLE
        single_before_r2=$(tc_sent_bytes "$R2" r2c) \
            || fail A03_RELAY2_COUNTER_UNAVAILABLE
        ip -n "$R2" link set r2c down
        [ "$(ip -n "$R2" -j link show dev r2c | jq -er '.[0].operstate')" = DOWN ] \
            || fail A03_SINGLE_PATH_NOT_ISOLATED
        sleep 2
        single_release_r1=$(tc_sent_bytes "$R1" r1c) \
            || fail A03_RELAY1_COUNTER_UNAVAILABLE
        single_release_r2=$(tc_sent_bytes "$R2" r2c) \
            || fail A03_RELAY2_COUNTER_UNAVAILABLE
        release_mptcp_download
        if finish_mptcp_download; then
            single_after_r1=$(tc_sent_bytes "$R1" r1c) \
                || fail A03_RELAY1_COUNTER_UNAVAILABLE
            single_after_r2=$(tc_sent_bytes "$R2" r2c) \
                || fail A03_RELAY2_COUNTER_UNAVAILABLE
            A03_STATUS=0
        fi
        ip -n "$R2" link set r2c up
        ip -n "$R2" route replace 43.159.1.1/32 via 10.241.12.1 dev r2c src 45.161.2.1
        ip -n "$R2" route get 43.159.1.1 \
            | grep -F 'via 10.241.12.1 dev r2c src 45.161.2.1' >/dev/null \
            || fail A03_RELAY2_CONTROL_ROUTE_NOT_RESTORED
        break
    fi
    sleep 1
    attempt=$((attempt + 1))
done
if [ "$A03_STATUS" -ne 0 ]; then
    OBSERVED_BLOCKER=A03_SINGLE_PATH_DOWNLOAD_UNAVAILABLE
    PHASE=a03-blocked
    exit 77
fi
sleep 2

PHASE=a03-aggregate-download
A03_STATUS=1
attempt=0
while [ "$attempt" -lt 30 ]; do
    if start_mptcp_download a03-aggregate a03-aggregate "$attempt" -; then
        aggregate_before_r1=$(tc_sent_bytes "$R1" r1c) \
            || fail A03_RELAY1_COUNTER_UNAVAILABLE
        aggregate_before_r2=$(tc_sent_bytes "$R2" r2c) \
            || fail A03_RELAY2_COUNTER_UNAVAILABLE
        release_mptcp_download
        if finish_mptcp_download; then
            aggregate_after_r1=$(tc_sent_bytes "$R1" r1c) \
                || fail A03_RELAY1_COUNTER_UNAVAILABLE
            aggregate_after_r2=$(tc_sent_bytes "$R2" r2c) \
                || fail A03_RELAY2_COUNTER_UNAVAILABLE
            aggregate_relay1_delta=$((aggregate_after_r1 - aggregate_before_r1))
            aggregate_relay2_delta=$((aggregate_after_r2 - aggregate_before_r2))
            if [ "$aggregate_relay1_delta" -gt 4194304 ] \
                && [ "$aggregate_relay2_delta" -gt 4194304 ] \
                && jq -e --slurpfile single "$WORK/a03-single-client.json" '
                    .throughput_bits_per_second
                      > ($single[0].throughput_bits_per_second * 1.25)
                ' "$WORK/a03-aggregate-client.json" >/dev/null 2>&1; then
                A03_STATUS=0
                break
            fi
        fi
    fi
    sleep 1
    attempt=$((attempt + 1))
done
if [ "$A03_STATUS" -ne 0 ]; then
    OBSERVED_BLOCKER=A03_AGGREGATE_DOWNLOAD_UNAVAILABLE
    PHASE=a03-blocked
    exit 77
fi

jq -S -c -n \
    --argjson single_initial_relay1 "$single_before_r1" \
    --argjson single_initial_relay2 "$single_before_r2" \
    --argjson single_release_relay1 "$single_release_r1" \
    --argjson single_release_relay2 "$single_release_r2" \
    --argjson aggregate_relay1 "$aggregate_before_r1" \
    --argjson aggregate_relay2 "$aggregate_before_r2" \
    '{schema_version:1,individual_rate_bits_per_second:8000000,
      single_path:{relay1_initial_bytes:$single_initial_relay1,
        relay2_initial_bytes:$single_initial_relay2,
        relay1_release_bytes:$single_release_relay1,
        relay2_release_bytes:$single_release_relay2,relay2_operstate:"DOWN"},
      aggregate:{relay1_bytes:$aggregate_relay1,relay2_bytes:$aggregate_relay2}}' \
    >"$WORK/a03-tc-before.json"
jq -S -c -n \
    --argjson single_relay1 "$single_after_r1" \
    --argjson single_relay2 "$single_after_r2" \
    --argjson aggregate_relay1 "$aggregate_after_r1" \
    --argjson aggregate_relay2 "$aggregate_after_r2" \
    '{schema_version:1,single_path:{relay1_bytes:$single_relay1,
      relay2_bytes:$single_relay2},aggregate:{relay1_bytes:$aggregate_relay1,
      relay2_bytes:$aggregate_relay2}}' >"$WORK/a03-tc-after.json"

jq -S -c -n \
    --slurpfile single "$WORK/a03-single-client.json" \
    --slurpfile single_destination "$WORK/destination-a03-single-evidence.json" \
    --slurpfile single_client_capture "$WORK/a03-single-client-capture.json" \
    --slurpfile single_exit_capture "$WORK/a03-single-exit-capture.json" \
    --slurpfile aggregate "$WORK/a03-aggregate-client.json" \
    --slurpfile aggregate_destination "$WORK/destination-a03-aggregate-evidence.json" \
    --slurpfile aggregate_client_capture "$WORK/a03-aggregate-client-capture.json" \
    --slurpfile aggregate_exit_capture "$WORK/a03-aggregate-exit-capture.json" \
    --slurpfile before "$WORK/a03-tc-before.json" \
    --slurpfile after "$WORK/a03-tc-after.json" \
    '($single[0]) as $one | ($aggregate[0]) as $both
    | ($single_destination[0]) as $one_destination
    | ($aggregate_destination[0]) as $both_destination
    | ($single_client_capture[0]) as $one_client
    | ($single_exit_capture[0]) as $one_exit
    | ($aggregate_client_capture[0]) as $both_client
    | ($aggregate_exit_capture[0]) as $both_exit
    | ($before[0]) as $tc_before | ($after[0]) as $tc_after
    | ($tc_after.single_path.relay1_bytes
        - $tc_before.single_path.relay1_release_bytes) as $one_relay1_bytes
    | ($tc_after.single_path.relay2_bytes
        - $tc_before.single_path.relay2_release_bytes) as $one_relay2_bytes
    | ($tc_after.aggregate.relay1_bytes
        - $tc_before.aggregate.relay1_bytes) as $both_relay1_bytes
    | ($tc_after.aggregate.relay2_bytes
        - $tc_before.aggregate.relay2_bytes) as $both_relay2_bytes
    | (($one.case == "a03-single") and ($both.case == "a03-aggregate")
        and ($one.response_bytes == 33554432)
        and ($both.response_bytes == $one.response_bytes)
        and ($both.response_sha256 == $one.response_sha256)
        and ($one.response_sha256 == $one_destination.response_sha256)
        and ($both.response_sha256 == $both_destination.response_sha256)
        and ($one.request_sha256 == $one_destination.request_sha256)
        and ($both.request_sha256 == $both_destination.request_sha256)
        and ($one_destination.source.ip == "47.163.4.1")
        and ($both_destination.source.ip == "47.163.4.1")
        and ($one_relay1_bytes > 16777216) and ($one_relay2_bytes < 2097152)
        and ($both_relay1_bytes > 4194304) and ($both_relay2_bytes > 4194304)
        and ($both.throughput_bits_per_second
          > ($one.throughput_bits_per_second * 1.25))
        and ($one_client.direct_client_exit_packets == 0)
        and ($both_client.direct_client_exit_packets == 0)
        and ($one_client.truncated == false) and ($one_exit.truncated == false)
        and ($both_client.truncated == false) and ($both_exit.truncated == false)
        and ($both_client.relay1_wireguard_data_datagrams > 0)
        and ($both_client.relay2_wireguard_data_datagrams > 0)
        and ($both_exit.relay1_wireguard_data_datagrams > 0)
        and ($both_exit.relay2_wireguard_data_datagrams > 0)) as $success
    | {schema_version:1,acceptance_id:"A03",success:$success,
       transport:"IPPROTO_MPTCP over two individually constrained Relay WireGuard paths",
       payload:{bytes:$one.response_bytes,sha256:$one.response_sha256},
       single_path:{application:$one,destination:$one_destination,
         client_capture:$one_client,exit_capture:$one_exit,
         relay1_outer_bytes:$one_relay1_bytes,relay2_outer_bytes:$one_relay2_bytes},
       aggregate:{application:$both,destination:$both_destination,
         client_capture:$both_client,exit_capture:$both_exit,
         kernel_mptcp_readiness:{source:"production MPTCP_INFO gate before payload",
           negotiated_remote_key:true,ordinary_tcp_fallback:false,
           required_subflows:2,gate_passed:true},
         relay1_outer_bytes:$both_relay1_bytes,relay2_outer_bytes:$both_relay2_bytes},
       individually_constrained_rate_bits_per_second:
         $tc_before.individual_rate_bits_per_second,
       measured_throughput_gain_ratio:
         ($both.throughput_bits_per_second / $one.throughput_bits_per_second),
       ordinary_tcp_fallback_allowed:false,direct_client_exit_packets:
         ($one_client.direct_client_exit_packets + $both_client.direct_client_exit_packets)}' \
    >"$WORK/a03-evidence.json"
jq -e '.success == true' "$WORK/a03-evidence.json" >/dev/null 2>&1 \
    || A03_STATUS=1
if [ "$A03_STATUS" -ne 0 ]; then
    OBSERVED_BLOCKER=A03_MPTCP_AGGREGATION_NOT_PROVEN
    PHASE=a03-blocked
    exit 77
fi
A03_SUCCEEDED=true
OBSERVED_BLOCKER=NONE
PHASE=a03-complete

PHASE=a04-active-relay-removal
A04_REQUESTED=true
A04_STATUS=1
attempt=0
while [ "$attempt" -lt 30 ]; do
    if start_mptcp_download a04-failover a04 "$attempt" \
        "$WORK/a04-relay-removal.marker"; then
        a04_start_r1=$(tc_sent_bytes "$R1" r1c) \
            || fail A04_RELAY1_COUNTER_UNAVAILABLE
        a04_start_r2=$(tc_sent_bytes "$R2" r2c) \
            || fail A04_RELAY2_COUNTER_UNAVAILABLE
        release_mptcp_download
        carrying_attempt=0
        a04_active_r1=$a04_start_r1
        a04_active_r2=$a04_start_r2
        while [ "$carrying_attempt" -lt 450 ]; do
            kill -0 "$DOWNLOAD_CLIENT_PID" 2>/dev/null \
                || fail A04_FLOW_ENDED_BEFORE_RELAY_REMOVAL
            a04_active_r1=$(tc_sent_bytes "$R1" r1c) \
                || fail A04_RELAY1_COUNTER_UNAVAILABLE
            a04_active_r2=$(tc_sent_bytes "$R2" r2c) \
                || fail A04_RELAY2_COUNTER_UNAVAILABLE
            if [ $((a04_active_r1 - a04_start_r1)) -gt 2097152 ] \
                && [ $((a04_active_r2 - a04_start_r2)) -gt 2097152 ]; then
                break
            fi
            sleep 0.1
            carrying_attempt=$((carrying_attempt + 1))
        done
        [ "$carrying_attempt" -lt 450 ] || fail A04_TWO_ACTIVE_PATHS_NOT_OBSERVED
        kill -0 "$DOWNLOAD_CLIENT_PID" 2>/dev/null \
            || fail A04_FLOW_ENDED_BEFORE_RELAY_REMOVAL
        ip -n "$R1" link set r1c down
        ip -n "$R1" link set r1x down
        a04_r1c_state=$(ip -n "$R1" -j link show dev r1c | jq -er '.[0].operstate')
        a04_r1x_state=$(ip -n "$R1" -j link show dev r1x | jq -er '.[0].operstate')
        if [ "$a04_r1c_state" != DOWN ] || [ "$a04_r1x_state" != DOWN ]; then
            fail A04_RELAY_REMOVAL_FAILED
        fi
        kill -0 "$DOWNLOAD_CLIENT_PID" 2>/dev/null \
            || fail A04_FLOW_ENDED_DURING_RELAY_REMOVAL
        install -o root -g root -m 0600 /dev/null "$WORK/a04-relay-removal.marker"
        if finish_mptcp_download; then
            a04_after_r1=$(tc_sent_bytes "$R1" r1c) \
                || fail A04_RELAY1_COUNTER_UNAVAILABLE
            a04_after_r2=$(tc_sent_bytes "$R2" r2c) \
                || fail A04_RELAY2_COUNTER_UNAVAILABLE
            A04_STATUS=0
        fi
        ip -n "$R1" link set r1x up
        ip -n "$R1" link set r1c up
        ip -n "$R1" route replace 43.159.1.1/32 via 10.241.11.1 dev r1c src 44.160.1.1
        ip -n "$R1" route replace 46.162.3.1/32 via 10.241.21.2 dev r1x src 44.160.1.1
        ip -n "$R1" route get 43.159.1.1 \
            | grep -F 'via 10.241.11.1 dev r1c src 44.160.1.1' >/dev/null \
            || fail A04_RELAY1_CLIENT_ROUTE_NOT_RESTORED
        ip -n "$R1" route get 46.162.3.1 \
            | grep -F 'via 10.241.21.2 dev r1x src 44.160.1.1' >/dev/null \
            || fail A04_RELAY1_EXIT_ROUTE_NOT_RESTORED
        break
    fi
    sleep 1
    attempt=$((attempt + 1))
done
if [ "$A04_STATUS" -ne 0 ]; then
    OBSERVED_BLOCKER=A04_MPTCP_FAILOVER_DOWNLOAD_UNAVAILABLE
    PHASE=a04-blocked
    exit 77
fi

jq -S -c -n \
    --arg selected_relay relay1 \
    --arg relay_client_operstate "$a04_r1c_state" \
    --arg relay_exit_operstate "$a04_r1x_state" \
    --argjson process_active_at_removal true \
    --argjson relay1_bytes_before "$a04_active_r1" \
    --argjson relay2_bytes_before "$a04_active_r2" \
    --argjson relay1_bytes_after "$a04_after_r1" \
    --argjson relay2_bytes_after "$a04_after_r2" \
    --argjson relay1_start_bytes "$a04_start_r1" \
    --argjson relay2_start_bytes "$a04_start_r2" \
    '{schema_version:1,selected_relay:$selected_relay,
      process_active_at_removal:$process_active_at_removal,
      removed_links:{relay_client_operstate:$relay_client_operstate,
        relay_exit_operstate:$relay_exit_operstate},
      outer_bytes:{before_removal:{relay1:($relay1_bytes_before-$relay1_start_bytes),
        relay2:($relay2_bytes_before-$relay2_start_bytes)},
        after_removal:{relay1:($relay1_bytes_after-$relay1_bytes_before),
          relay2:($relay2_bytes_after-$relay2_bytes_before)}}}' \
    >"$WORK/a04-removal.json"

jq -S -c -n \
    --slurpfile application "$WORK/a04-client.json" \
    --slurpfile destination "$WORK/destination-a04-evidence.json" \
    --slurpfile client_capture "$WORK/a04-client-capture.json" \
    --slurpfile exit_capture "$WORK/a04-exit-capture.json" \
    --slurpfile removal "$WORK/a04-removal.json" \
    '($application[0]) as $app | ($destination[0]) as $destination
    | ($client_capture[0]) as $client | ($exit_capture[0]) as $exit
    | ($removal[0]) as $removal
    | (($app.case == "a04-failover") and ($app.response_bytes == 33554432)
        and ($app.response_sha256 == $destination.response_sha256)
        and ($app.request_sha256 == $destination.request_sha256)
        and ($destination.source.ip == "47.163.4.1")
        and $removal.process_active_at_removal
        and ($removal.removed_links.relay_client_operstate == "DOWN")
        and ($removal.removed_links.relay_exit_operstate == "DOWN")
        and ($removal.outer_bytes.before_removal.relay1 > 2097152)
        and ($removal.outer_bytes.before_removal.relay2 > 2097152)
        and ($removal.outer_bytes.after_removal.relay2 > 8388608)
        and $client.marker_observed and $exit.marker_observed
        and ($client.before_marker.relay1_wireguard_data_datagrams > 0)
        and ($client.before_marker.relay2_wireguard_data_datagrams > 0)
        and ($exit.before_marker.relay1_wireguard_data_datagrams > 0)
        and ($exit.before_marker.relay2_wireguard_data_datagrams > 0)
        and ($client.after_marker.relay2_wireguard_data_datagrams > 0)
        and ($exit.after_marker.relay2_wireguard_data_datagrams > 0)
        and ($client.direct_client_exit_packets == 0)
        and ($client.truncated == false) and ($exit.truncated == false)) as $success
    | {schema_version:1,acceptance_id:"A04",success:$success,
       transport:"uninterrupted IPPROTO_MPTCP/TLS download after active Relay removal",
       application:$app,destination:$destination,relay_removal:$removal,
       path_evidence:{client_capture:$client,exit_capture:$exit},
       application_flow_completed:true,ordinary_tcp_fallback_allowed:false,
       direct_client_exit_packets:$client.direct_client_exit_packets}' \
    >"$WORK/a04-evidence.json"
jq -e '.success == true' "$WORK/a04-evidence.json" >/dev/null 2>&1 \
    || A04_STATUS=1
if [ "$A04_STATUS" -ne 0 ]; then
    OBSERVED_BLOCKER=A04_ACTIVE_RELAY_REMOVAL_NOT_PROVEN
    PHASE=a04-blocked
    exit 77
fi
ip netns exec "$R1" tc qdisc del dev r1c root
ip netns exec "$R2" tc qdisc del dev r2c root
sleep 2
A04_SUCCEEDED=true
OBSERVED_BLOCKER=NONE
PHASE=a04-complete

PHASE=client-connect
CONNECT_REQUESTED=true
attempt=0
while [ "$attempt" -lt 120 ]; do
    set +e
    "$binary_directory/volparossa" \
        --control-socket "$WORK/runtime-client/control/agent.sock" connect \
        --transport single-path-udp \
        >"$WORK/connect-client.out" 2>"$WORK/connect-client.err"
    CONNECT_STATUS=$?
    set -e
    [ "$CONNECT_STATUS" -ne 0 ] || break
    a01_transient_connect_unavailable "$WORK/connect-client.err" || break
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
if printf '%s\n' "$A05_FALLBACK_ROUTE" | grep -Eq '(^| )dev (cr0|cr1|cr2)( |$)'; then
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

PHASE=a06-reset-single-path-route
"$binary_directory/volparossa" \
    --control-socket "$WORK/runtime-client/control/agent.sock" disconnect \
    >"$WORK/a06-disconnect.out" 2>"$WORK/a06-disconnect.err" \
    || fail A06_SINGLE_PATH_ROUTE_DISCONNECT_FAILED
attempt=0
while [ "$attempt" -lt 300 ]; do
    "$binary_directory/volparossa" \
        --control-socket "$WORK/runtime-client/control/agent.sock" status \
        >"$WORK/status-client.txt" || true
    if grep -Fx 'connected: false' "$WORK/status-client.txt" >/dev/null \
        && grep -Fx 'active contexts: 0' "$WORK/status-client.txt" >/dev/null; then
        break
    fi
    sleep 0.1
    attempt=$((attempt + 1))
done
[ "$attempt" -lt 300 ] || fail A06_SINGLE_PATH_ROUTE_NOT_IDLE

PHASE=a06-preconnect-multipath-route
A06_REQUESTED=true
a06_connect_status=1
attempt=0
while [ "$attempt" -lt 120 ]; do
    set +e
    "$binary_directory/volparossa" \
        --control-socket "$WORK/runtime-client/control/agent.sock" connect \
        --transport multipath-quic \
        >"$WORK/a06-connect.out" 2>"$WORK/a06-connect.err"
    a06_connect_status=$?
    set -e
    [ "$a06_connect_status" -ne 0 ] || break
    a01_transient_connect_unavailable "$WORK/a06-connect.err" || break
    sleep 1
    attempt=$((attempt + 1))
done
[ "$a06_connect_status" -eq 0 ] || fail A06_MULTIPATH_ROUTE_CONNECT_FAILED
wait_active_native_mpquic_paths a06-preconnect-native-paths \
    || fail A06_MULTIPATH_ROUTE_NOT_ACTIVE

timeout --signal=TERM --kill-after=5s 420s \
    ip netns exec "$DEST" setpriv --reuid="$AGENT_UID" --regid="$AGENT_GID" \
    --clear-groups --inh-caps=+net_bind_service \
    --ambient-caps=+net_bind_service --bounding-set=+net_bind_service \
    --no-new-privs -- \
    "$WORK/bin/examples/http3-acceptance-fixture" server \
    47.163.4.2:443 "$WORK/destination/http3-cert.der" \
    "$WORK/destination/http3-server.ready" "$WORK/destination" "$RUN_ID" \
    >"$WORK/http3-server.log" 2>&1 &
HTTP3_SERVER_PID=$!
attempt=0
while [ "$attempt" -lt 100 ]; do
    [ -s "$WORK/destination/http3-server.ready" ] && break
    kill -0 "$HTTP3_SERVER_PID" 2>/dev/null || break
    sleep 0.1
    attempt=$((attempt + 1))
done
[ -s "$WORK/destination/http3-server.ready" ] || fail A06_HTTP3_SERVER_UNAVAILABLE
install -o "$WORKER_UID" -g "$WORKER_GID" -m 0400 \
    "$WORK/destination/http3-cert.der" "$WORK/client-fixtures/http3-cert.der"

PHASE=a06-http3-mpquic
A06_STATUS=1
A06_FALLBACK_ROUTE=$(ip -n "$CLIENT" -o route get 47.163.4.2 | sed -n '1p')
printf '%s\n' "$A06_FALLBACK_ROUTE" >"$WORK/a06-client-fallback-route.txt"
printf '%s\n' "$A06_FALLBACK_ROUTE" | grep -Eq '(^| )dev underlay( |$)' \
    || fail A06_FALLBACK_ROUTE_INVALID
if printf '%s\n' "$A06_FALLBACK_ROUTE" | grep -Eq '(^| )dev (cr1|cr2)( |$)'; then
    fail DIRECT_CLIENT_EXIT_REACHABLE
fi
A11_REQUESTED=true
A12_REQUESTED=true
A13_REQUESTED=true
start_privacy_observers || fail PRIVACY_CAPTURE_UNAVAILABLE
start_http3_observers a06 - || fail A06_CAPTURE_UNAVAILABLE
set +e
timeout --signal=TERM --kill-after=5s 200s \
    ip netns exec "$CLIENT" setpriv --reuid="$WORKER_UID" --regid="$WORKER_GID" \
    --clear-groups --inh-caps=-all --ambient-caps=-all --bounding-set=-all \
    --no-new-privs -- \
    "$WORK/bin/examples/http3-acceptance-fixture" client a06 \
    43.159.1.1:52006 47.163.4.2:443 "$WORK/client-fixtures/http3-cert.der" \
    "$RUN_ID" "$WORK/client-fixtures/a06-client.json" 2>"$WORK/a06-client.err"
A06_STATUS=$?
set -e
if [ -s "$WORK/client-fixtures/a06-client.json" ]; then
    install -o root -g root -m 0600 "$WORK/client-fixtures/a06-client.json" \
        "$WORK/a06-client.json"
fi
destination_attempt=0
while [ "$A06_STATUS" -eq 0 ] && [ "$destination_attempt" -lt 100 ] \
    && [ ! -s "$WORK/destination/server-a06.json" ]; do
    sleep 0.1
    destination_attempt=$((destination_attempt + 1))
done
stop_observers || A06_STATUS=1
if [ -s "$WORK/destination/server-a06.json" ]; then
    install -o root -g root -m 0600 "$WORK/destination/server-a06.json" \
        "$WORK/destination-a06-evidence.json"
fi
if [ "$A06_STATUS" -eq 0 ] \
    && ! wait_native_mpquic_paths a06-native-paths both; then
    A06_STATUS=1
fi
for evidence_file in a06-client.json destination-a06-evidence.json \
    a06-client-capture.json a06-exit-capture.json \
    a06-preconnect-native-paths.json a06-native-paths.json; do
    if [ "$A06_STATUS" -eq 0 ] \
        && { [ ! -s "$WORK/$evidence_file" ] \
            || ! jq -e . "$WORK/$evidence_file" >/dev/null 2>&1; }; then
        A06_STATUS=1
    fi
done
if [ "$A06_STATUS" -eq 0 ]; then
    jq -S -c -n \
        --slurpfile application "$WORK/a06-client.json" \
        --slurpfile destination "$WORK/destination-a06-evidence.json" \
        --slurpfile client_capture "$WORK/a06-client-capture.json" \
        --slurpfile exit_capture "$WORK/a06-exit-capture.json" \
        --slurpfile preconnect "$WORK/a06-preconnect-native-paths.json" \
        --slurpfile native "$WORK/a06-native-paths.json" \
        --arg fallback_route "$A06_FALLBACK_ROUTE" \
        --arg relay1_peer "$R1_PEER" --arg relay2_peer "$R2_PEER" \
        '($application[0]) as $app | ($destination[0]) as $destination
        | ($client_capture[0]) as $client | ($exit_capture[0]) as $exit
        | ($preconnect[0]) as $preconnect
        | ($native[0]) as $native
        | ($native.paths | map(select(.relay == "relay1")) | .[0]) as $native_r1
        | ($native.paths | map(select(.relay == "relay2")) | .[0]) as $native_r2
        | (($app.protocol == "HTTP/3") and ($app.http_version == "HTTP/3")
            and ($app.negotiated_alpn == "h3")
            and ($app.hostname == "destination.volparossa.test")
            and ($app.application == {ip:"43.159.1.1",port:52006})
            and ($app.destination == {ip:"47.163.4.2",port:443})
            and ($app.request_bytes == 4194304) and ($app.response_bytes == 8388608)
            and ($app.request_sha256 == $destination.request_sha256)
            and ($app.response_sha256 == $destination.response_sha256)
            and ($destination.protocol == "HTTP/3")
            and ($destination.http_version == "HTTP/3")
            and ($destination.negotiated_alpn == "h3")
            and ($destination.peer_completion_observed == true)
            and ($destination.hostname == $app.hostname)
            and ($destination.listen == $app.destination)
            and ($destination.source.ip == "47.163.4.1")
            and ($client.relay1_wireguard_data_datagrams > 0)
            and ($client.relay2_wireguard_data_datagrams > 0)
            and ($exit.relay1_wireguard_data_datagrams > 0)
            and ($exit.relay2_wireguard_data_datagrams > 0)
            and ($client.relay1_wireguard_data_bytes > 1048576)
            and ($client.relay2_wireguard_data_bytes > 1048576)
            and ($exit.relay1_wireguard_data_bytes > 1048576)
            and ($exit.relay2_wireguard_data_bytes > 1048576)
            and ($client.direct_client_exit_packets == 0)
            and ($client.truncated == false) and ($exit.truncated == false)
            and ($exit.destination_request_datagrams > 0)
            and ($exit.destination_response_datagrams > 0)
            and ($preconnect.requirement == "both")
            and (($preconnect.paths | length) == 2)
            and (all($preconnect.paths[]; .state == 3))
            and ($preconnect.route_context_id == $native.route_context_id)
            and ($native_r1.relay_peer_id == $relay1_peer)
            and ($native_r2.relay_peer_id == $relay2_peer)
            and ($native_r1.path_id != $native_r2.path_id)
            and ($native_r1.state == 3) and ($native_r2.state == 3)) as $success
        | {schema_version:1,acceptance_id:"A06",success:$success,
           transport:"real HTTP/3 over genuine native Multipath QUIC",
           application:$app,destination:$destination,
           hostname_policy:{hostname:$app.hostname,transport:"udp",port:443,
             kernel_original_destination:$app.destination,
             exit_dns_pin:{addresses:["47.163.4.2"],exact_original_destination_match:true},
             client_initial_inspected_before_route:true,
             exit_initial_reverified_before_egress:true},
           native_mpquic:{route_context_id:$native.route_context_id,
             preestablished_before_http3_client:true,
             preconnect_paths:$preconnect.paths,required_path_count:2,
             paths:$native.paths},
           path_evidence:{client_capture:$client,exit_capture:$exit},
           no_direct_client_exit:{topology_adjacency:false,route_absent:true,
             fallback_route:$fallback_route,observed_packets:$client.direct_client_exit_packets},
           ordinary_quic_fallback_allowed:false}' >"$WORK/a06-evidence.json"
    jq -e '.success == true' "$WORK/a06-evidence.json" >/dev/null 2>&1 \
        || A06_STATUS=1
fi
if [ "$A06_STATUS" -ne 0 ]; then
    OBSERVED_BLOCKER=A06_HTTP3_MPQUIC_NOT_PROVEN
    PHASE=a06-blocked
    exit 77
fi
A06_SUCCEEDED=true
OBSERVED_BLOCKER=NONE
PHASE=a06-complete

PHASE=a07-active-http3-relay-removal
A07_REQUESTED=true
A07_STATUS=1
start_http3_observers a07 "$WORK/a07-relay-removal.marker" \
    || fail A07_CAPTURE_UNAVAILABLE
timeout --signal=TERM --kill-after=5s 200s \
    ip netns exec "$CLIENT" setpriv --reuid="$WORKER_UID" --regid="$WORKER_GID" \
    --clear-groups --inh-caps=-all --ambient-caps=-all --bounding-set=-all \
    --no-new-privs -- \
    "$WORK/bin/examples/http3-acceptance-fixture" client a07 \
    43.159.1.1:52007 47.163.4.2:443 "$WORK/client-fixtures/http3-cert.der" \
    "$RUN_ID" "$WORK/client-fixtures/a07-client.json" 2>"$WORK/a07-client.err" &
HTTP3_CLIENT_PID=$!
attempt=0
while [ "$attempt" -lt 1800 ]; do
    [ -s "$WORK/destination/a07-active.ready" ] && break
    kill -0 "$HTTP3_CLIENT_PID" 2>/dev/null || break
    sleep 0.1
    attempt=$((attempt + 1))
done
[ -s "$WORK/destination/a07-active.ready" ] \
    || fail A07_HTTP3_FLOW_NOT_ACTIVE
kill -0 "$HTTP3_CLIENT_PID" 2>/dev/null \
    || fail A07_HTTP3_FLOW_ENDED_BEFORE_RELAY_REMOVAL
wait_native_mpquic_paths a07-native-before both \
    || fail A07_NATIVE_PATH_STATUS_UNAVAILABLE
ip -n "$R1" link set r1c down
ip -n "$R1" link set r1x down
A07_R1C_STATE=$(ip -n "$R1" -j link show dev r1c | jq -er '.[0].operstate')
A07_R1X_STATE=$(ip -n "$R1" -j link show dev r1x | jq -er '.[0].operstate')
if [ "$A07_R1C_STATE" != DOWN ] || [ "$A07_R1X_STATE" != DOWN ]; then
    fail A07_RELAY_REMOVAL_FAILED
fi
kill -0 "$HTTP3_CLIENT_PID" 2>/dev/null \
    || fail A07_HTTP3_FLOW_ENDED_DURING_RELAY_REMOVAL
install -o root -g root -m 0600 /dev/null "$WORK/a07-relay-removal.marker"
install -o "$AGENT_UID" -g "$AGENT_GID" -m 0600 /dev/null \
    "$WORK/destination/a07.release"
set +e
wait "$HTTP3_CLIENT_PID"
A07_STATUS=$?
set -e
HTTP3_CLIENT_PID=
if [ -s "$WORK/client-fixtures/a07-client.json" ]; then
    install -o root -g root -m 0600 "$WORK/client-fixtures/a07-client.json" \
        "$WORK/a07-client.json"
fi
destination_attempt=0
while [ "$A07_STATUS" -eq 0 ] && [ "$destination_attempt" -lt 100 ] \
    && [ ! -s "$WORK/destination/server-a07.json" ]; do
    sleep 0.1
    destination_attempt=$((destination_attempt + 1))
done
stop_observers || A07_STATUS=1
if [ -s "$WORK/destination/server-a07.json" ]; then
    install -o root -g root -m 0600 "$WORK/destination/server-a07.json" \
        "$WORK/destination-a07-evidence.json"
fi
if [ "$A07_STATUS" -eq 0 ] \
    && ! wait_native_mpquic_paths a07-native-after relay2; then
    A07_STATUS=1
fi
ip -n "$R1" link set r1x up
ip -n "$R1" link set r1c up
ip -n "$R1" route replace 43.159.1.1/32 via 10.241.11.1 dev r1c src 44.160.1.1
ip -n "$R1" route replace 46.162.3.1/32 via 10.241.21.2 dev r1x src 44.160.1.1
ip -n "$R1" route get 43.159.1.1 \
    | grep -F 'via 10.241.11.1 dev r1c src 44.160.1.1' >/dev/null \
    || fail A07_RELAY1_CLIENT_ROUTE_NOT_RESTORED
ip -n "$R1" route get 46.162.3.1 \
    | grep -F 'via 10.241.21.2 dev r1x src 44.160.1.1' >/dev/null \
    || fail A07_RELAY1_EXIT_ROUTE_NOT_RESTORED
set +e
wait "$HTTP3_SERVER_PID"
HTTP3_SERVER_STATUS=$?
set -e
HTTP3_SERVER_PID=
[ "$HTTP3_SERVER_STATUS" -eq 0 ] || A07_STATUS=1
for evidence_file in a07-client.json destination-a07-evidence.json \
    a07-client-capture.json a07-exit-capture.json \
    a07-native-before.json a07-native-after.json; do
    if [ "$A07_STATUS" -eq 0 ] \
        && { [ ! -s "$WORK/$evidence_file" ] \
            || ! jq -e . "$WORK/$evidence_file" >/dev/null 2>&1; }; then
        A07_STATUS=1
    fi
done
jq -S -c -n --arg relay relay1 \
    --arg relay_client_operstate "$A07_R1C_STATE" \
    --arg relay_exit_operstate "$A07_R1X_STATE" \
    '{schema_version:1,removed_relay:$relay,process_active_at_removal:true,
      removed_links:{relay_client_operstate:$relay_client_operstate,
        relay_exit_operstate:$relay_exit_operstate}}' >"$WORK/a07-removal.json"
if [ "$A07_STATUS" -eq 0 ]; then
    jq -S -c -n \
        --slurpfile application "$WORK/a07-client.json" \
        --slurpfile destination "$WORK/destination-a07-evidence.json" \
        --slurpfile client_capture "$WORK/a07-client-capture.json" \
        --slurpfile exit_capture "$WORK/a07-exit-capture.json" \
        --slurpfile a06_native "$WORK/a06-native-paths.json" \
        --slurpfile native_before "$WORK/a07-native-before.json" \
        --slurpfile native_after "$WORK/a07-native-after.json" \
        --slurpfile removal "$WORK/a07-removal.json" \
        '($application[0]) as $app | ($destination[0]) as $destination
        | ($client_capture[0]) as $client | ($exit_capture[0]) as $exit
        | ($a06_native[0]) as $a06_native | ($native_before[0]) as $before
        | ($native_after[0]) as $after | ($removal[0]) as $removal
        | ($before.paths | map(select(.relay == "relay2")) | .[0]) as $before_r2
        | ($after.paths | map(select(.relay == "relay2")) | .[0]) as $after_r2
        | (($app.protocol == "HTTP/3") and ($app.http_version == "HTTP/3")
            and ($app.negotiated_alpn == "h3")
            and ($app.application == {ip:"43.159.1.1",port:52007})
            and ($app.destination == {ip:"47.163.4.2",port:443})
            and ($app.request_bytes == 4194304) and ($app.response_bytes == 33554432)
            and ($app.request_sha256 == $destination.request_sha256)
            and ($app.response_sha256 == $destination.response_sha256)
            and ($destination.protocol == "HTTP/3")
            and ($destination.http_version == "HTTP/3")
            and ($destination.negotiated_alpn == "h3")
            and ($destination.peer_completion_observed == true)
            and ($destination.release_observed == true)
            and ($destination.source.ip == "47.163.4.1")
            and $removal.process_active_at_removal
            and ($removal.removed_links.relay_client_operstate == "DOWN")
            and ($removal.removed_links.relay_exit_operstate == "DOWN")
            and $client.marker_observed and $exit.marker_observed
            and ($client.before_marker.relay1_wireguard_data_datagrams > 0)
            and ($client.before_marker.relay2_wireguard_data_datagrams > 0)
            and ($exit.before_marker.relay1_wireguard_data_datagrams > 0)
            and ($exit.before_marker.relay2_wireguard_data_datagrams > 0)
            and ($client.after_marker.relay2_wireguard_data_datagrams > 0)
            and ($exit.after_marker.relay2_wireguard_data_datagrams > 0)
            and ($client.before_marker.relay1_wireguard_data_bytes > 1048576)
            and ($client.before_marker.relay2_wireguard_data_bytes > 1048576)
            and ($exit.before_marker.relay1_wireguard_data_bytes > 1048576)
            and ($exit.before_marker.relay2_wireguard_data_bytes > 1048576)
            and ($client.after_marker.relay2_wireguard_data_bytes > 1048576)
            and ($exit.after_marker.relay2_wireguard_data_bytes > 1048576)
            and ($client.direct_client_exit_packets == 0)
            and ($client.truncated == false) and ($exit.truncated == false)
            and ($exit.destination_request_datagrams > 0)
            and ($exit.destination_response_datagrams > 0)
            and ($a06_native.route_context_id == $before.route_context_id)
            and ($before.route_context_id == $after.route_context_id)
            and ($after_r2.path_id == $before_r2.path_id)) as $success
        | {schema_version:1,acceptance_id:"A07",success:$success,
           transport:"active HTTP/3 flow retained by genuine MPQUIC after Relay removal",
           application:$app,destination:$destination,relay_removal:$removal,
           native_mpquic:{route_context_id:$after.route_context_id,
             before_removal:$before.paths,after_removal:$after.paths},
           path_evidence:{client_capture:$client,exit_capture:$exit},
           application_flow_completed:true,ordinary_quic_fallback_allowed:false,
           direct_client_exit_packets:$client.direct_client_exit_packets}' \
        >"$WORK/a07-evidence.json"
    jq -e '.success == true' "$WORK/a07-evidence.json" >/dev/null 2>&1 \
        || A07_STATUS=1
fi
if [ "$A07_STATUS" -ne 0 ]; then
    OBSERVED_BLOCKER=A07_ACTIVE_HTTP3_RELAY_FAILOVER_NOT_PROVEN
    PHASE=a07-blocked
    exit 77
fi
A07_SUCCEEDED=true
OBSERVED_BLOCKER=NONE
PHASE=a07-complete

PHASE=a08-reset-mpquic-route
"$binary_directory/volparossa" \
    --control-socket "$WORK/runtime-client/control/agent.sock" disconnect \
    >"$WORK/a08-disconnect.out" 2>"$WORK/a08-disconnect.err" \
    || fail A08_MPQUIC_ROUTE_DISCONNECT_FAILED
attempt=0
while [ "$attempt" -lt 300 ]; do
    "$binary_directory/volparossa" \
        --control-socket "$WORK/runtime-client/control/agent.sock" status \
        >"$WORK/status-client.txt" || true
    if grep -Fx 'connected: false' "$WORK/status-client.txt" >/dev/null \
        && grep -Fx 'active contexts: 0' "$WORK/status-client.txt" >/dev/null; then
        break
    fi
    sleep 0.1
    attempt=$((attempt + 1))
done
[ "$attempt" -lt 300 ] || fail A08_PREVIOUS_ROUTE_NOT_IDLE

A08_REQUESTED=true
A08_STATUS=1
capture_product_logs
A08_DNS_UDP_BEFORE=$(grep -Fc 'event=INGRESS_DNS_QUERY_COMPLETED' \
    "$WORK/logs-client.txt" 2>/dev/null || true)
PHASE=a08-allowed-dns-udp
set +e
timeout --signal=TERM --kill-after=5s 180s \
    ip netns exec "$CLIENT" setpriv --reuid="$WORKER_UID" --regid="$WORKER_GID" \
    --clear-groups --inh-caps=-all --ambient-caps=-all --bounding-set=-all \
    --no-new-privs -- \
    "$WORK/bin/dns-policy-client.py" udp "$RUN_ID" \
    >"$WORK/a08-dns-udp.json" 2>"$WORK/a08-dns-udp.err"
A08_DNS_UDP_STATUS=$?
set -e
attempt=0
while [ "$A08_DNS_UDP_STATUS" -eq 0 ] && [ "$attempt" -lt 300 ]; do
    capture_product_logs
    A08_DNS_UDP_AFTER=$(grep -Fc 'event=INGRESS_DNS_QUERY_COMPLETED' \
        "$WORK/logs-client.txt" 2>/dev/null || true)
    [ "$A08_DNS_UDP_AFTER" -gt "$A08_DNS_UDP_BEFORE" ] && break
    sleep 0.1
    attempt=$((attempt + 1))
done
if [ "$A08_DNS_UDP_STATUS" -ne 0 ] || [ "$attempt" -ge 300 ]; then
    OBSERVED_BLOCKER=A08_ALLOWED_DNS_UDP_NOT_PROVEN
    PHASE=a08-blocked
    exit 77
fi

attempt=0
while [ "$attempt" -lt 300 ]; do
    "$binary_directory/volparossa" \
        --control-socket "$WORK/runtime-client/control/agent.sock" status \
        >"$WORK/status-client.txt" || true
    if grep -Fx 'connected: false' "$WORK/status-client.txt" >/dev/null \
        && grep -Fx 'active contexts: 0' "$WORK/status-client.txt" >/dev/null; then
        break
    fi
    sleep 0.1
    attempt=$((attempt + 1))
done
[ "$attempt" -lt 300 ] || fail A08_DNS_UDP_ROUTE_NOT_IDLE

capture_product_logs
A08_DNS_TCP_BEFORE=$(grep -Fc 'event=INGRESS_DNS_TCP_QUERY_COMPLETED' \
    "$WORK/logs-client.txt" 2>/dev/null || true)
PHASE=a08-allowed-dns-tcp
set +e
timeout --signal=TERM --kill-after=5s 180s \
    ip netns exec "$CLIENT" setpriv --reuid="$WORKER_UID" --regid="$WORKER_GID" \
    --clear-groups --inh-caps=-all --ambient-caps=-all --bounding-set=-all \
    --no-new-privs -- \
    "$WORK/bin/dns-policy-client.py" tcp "$RUN_ID" \
    >"$WORK/a08-dns-tcp.json" 2>"$WORK/a08-dns-tcp.err"
A08_DNS_TCP_STATUS=$?
set -e
attempt=0
while [ "$A08_DNS_TCP_STATUS" -eq 0 ] && [ "$attempt" -lt 300 ]; do
    capture_product_logs
    A08_DNS_TCP_AFTER=$(grep -Fc 'event=INGRESS_DNS_TCP_QUERY_COMPLETED' \
        "$WORK/logs-client.txt" 2>/dev/null || true)
    [ "$A08_DNS_TCP_AFTER" -gt "$A08_DNS_TCP_BEFORE" ] && break
    sleep 0.1
    attempt=$((attempt + 1))
done
if [ "$A08_DNS_TCP_STATUS" -ne 0 ] || [ "$attempt" -ge 300 ]; then
    OBSERVED_BLOCKER=A08_ALLOWED_DNS_TCP_NOT_PROVEN
    PHASE=a08-blocked
    exit 77
fi

attempt=0
while [ "$attempt" -lt 300 ]; do
    "$binary_directory/volparossa" \
        --control-socket "$WORK/runtime-client/control/agent.sock" status \
        >"$WORK/status-client.txt" || true
    if grep -Fx 'connected: false' "$WORK/status-client.txt" >/dev/null \
        && grep -Fx 'active contexts: 0' "$WORK/status-client.txt" >/dev/null; then
        break
    fi
    sleep 0.1
    attempt=$((attempt + 1))
done
[ "$attempt" -lt 300 ] || fail A08_DNS_TCP_ROUTE_NOT_IDLE

install -d -o "$WORKER_UID" -g "$WORKER_GID" -m 0700 "$WORK/tls-policy"
timeout --signal=TERM --kill-after=5s 330s \
    ip netns exec "$DEST" setpriv --reuid="$AGENT_UID" --regid="$AGENT_GID" \
    --clear-groups --inh-caps=-all --ambient-caps=-all --bounding-set=-all \
    --no-new-privs -- \
    "$WORK/bin/examples/tls-policy-acceptance-fixture" server \
    47.163.4.2:18443 "$WORK/destination/tls-policy-cert.der" \
    "$WORK/destination/tls-policy.ready" "$WORK/destination/tls-policy.json" \
    "$WORK/destination/tls-policy.stop" "$RUN_ID" \
    >"$WORK/tls-policy-server.log" 2>&1 &
TLS_POLICY_SERVER_PID=$!
attempt=0
while [ "$attempt" -lt 100 ]; do
    [ -s "$WORK/destination/tls-policy.ready" ] \
        && [ -s "$WORK/destination/tls-policy.json" ] && break
    kill -0 "$TLS_POLICY_SERVER_PID" 2>/dev/null || break
    sleep 0.1
    attempt=$((attempt + 1))
done
[ -s "$WORK/destination/tls-policy.ready" ] \
    || fail A08_TLS_DESTINATION_UNAVAILABLE
install -o "$WORKER_UID" -g "$WORKER_GID" -m 0400 \
    "$WORK/destination/tls-policy-cert.der" "$WORK/tls-policy/tls-policy-cert.der"

capture_product_logs
A08_COMPLETION_BEFORE=$(grep -Fc 'event=INGRESS_TCP_STREAM_COMPLETED' \
    "$WORK/logs-client.txt" 2>/dev/null || true)
PHASE=a08-allowed-visible-name-tls
set +e
timeout --signal=TERM --kill-after=5s 180s \
    ip netns exec "$CLIENT" setpriv --reuid="$WORKER_UID" --regid="$WORKER_GID" \
    --clear-groups --inh-caps=-all --ambient-caps=-all --bounding-set=-all \
    --no-new-privs -- \
    "$WORK/bin/examples/tls-policy-acceptance-fixture" allowed \
    47.163.4.2:18443 "$WORK/tls-policy/tls-policy-cert.der" \
    "$RUN_ID" "$WORK/tls-policy/a08-client.json" \
    >"$WORK/tls-policy/a08-client.out" 2>"$WORK/tls-policy/a08-client.err"
A08_STATUS=$?
set -e
attempt=0
while [ "$A08_STATUS" -eq 0 ] && [ "$attempt" -lt 300 ]; do
    capture_product_logs
    A08_COMPLETION_AFTER=$(grep -Fc 'event=INGRESS_TCP_STREAM_COMPLETED' \
        "$WORK/logs-client.txt" 2>/dev/null || true)
    A08_DESTINATION_SUCCESSES=$(jq -er '.successful_exchanges' \
        "$WORK/destination/tls-policy.json" 2>/dev/null || printf 0)
    if [ "$A08_COMPLETION_AFTER" -gt "$A08_COMPLETION_BEFORE" ] \
        && [ "$A08_DESTINATION_SUCCESSES" -eq 1 ]; then
        break
    fi
    sleep 0.1
    attempt=$((attempt + 1))
done
if [ "$A08_STATUS" -eq 0 ]; then
    install -o root -g root -m 0600 "$WORK/tls-policy/a08-client.json" \
        "$WORK/a08-client.json"
    install -o root -g root -m 0600 "$WORK/tls-policy/a08-client.err" \
        "$WORK/a08-client.err"
    install -o root -g root -m 0600 "$WORK/destination/tls-policy.json" \
        "$WORK/a08-destination.json"
    jq -S -c -n \
        --slurpfile application "$WORK/a08-client.json" \
        --slurpfile destination "$WORK/a08-destination.json" \
        --slurpfile dns_udp "$WORK/a08-dns-udp.json" \
        --slurpfile dns_tcp "$WORK/a08-dns-tcp.json" \
        --rawfile lookup "$WORK/a08-exit-host-lookup.txt" \
        --argjson dns_udp_before "$A08_DNS_UDP_BEFORE" \
        --argjson dns_udp_after "$A08_DNS_UDP_AFTER" \
        --argjson dns_tcp_before "$A08_DNS_TCP_BEFORE" \
        --argjson dns_tcp_after "$A08_DNS_TCP_AFTER" \
        --argjson completion_before "$A08_COMPLETION_BEFORE" \
        --argjson completion_after "$A08_COMPLETION_AFTER" \
        '($application[0]) as $app | ($destination[0]) as $destination
        | ($dns_udp[0]) as $dns_udp | ($dns_tcp[0]) as $dns_tcp
        | (($app.case == "allowed-domain")
            and ($app.hostname == "destination.volparossa.test")
            and ($app.destination == {ip:"47.163.4.2",port:18443})
            and ($app.tls_version == "TLSv1.3")
            and ($app.negotiated_alpn == "volparossa-a08/1")
            and ($app.request_bytes == 1048576)
            and ($app.request_sha256 == $app.response_sha256)
            and ($destination.listen == $app.destination)
            and ($destination.hostname == $app.hostname)
            and ($destination.accepted_connections == 1)
            and ($destination.successful_exchanges == 1)
            and ($destination.failed_connections == 0)
            and ($destination.last_source.ip == "47.163.4.1")
            and ($destination.request_bytes == $app.request_bytes)
            and ($destination.request_sha256 == $app.request_sha256)
            and ($destination.response_sha256 == $app.response_sha256)
            and ($lookup == "47.163.4.2\n")
            and ($dns_udp.mode == "udp") and ($dns_tcp.mode == "tcp")
            and ($dns_udp.hostname == "destination.volparossa.test")
            and ($dns_tcp.hostname == $dns_udp.hostname)
            and ($dns_udp.resolver == {ip:"9.9.9.9",port:53})
            and ($dns_tcp.resolver == $dns_udp.resolver)
            and ($dns_udp.response_source == $dns_udp.resolver)
            and ($dns_tcp.response_source == $dns_tcp.resolver)
            and ($dns_udp.answer_addresses == ["47.163.4.2"])
            and ($dns_tcp.answer_addresses == $dns_udp.answer_addresses)
            and ($dns_udp.response_bytes > $dns_udp.query_bytes)
            and ($dns_tcp.response_bytes > $dns_tcp.query_bytes)
            and ($dns_udp_after > $dns_udp_before)
            and ($dns_tcp_after > $dns_tcp_before)
            and ($completion_after > $completion_before)) as $success
        | {schema_version:1,acceptance_id:"A08",success:$success,
           request:{hostname:$app.hostname,original_destination:$app.destination},
           application:$app,destination:$destination,
           exit_resolution:{hostname:$app.hostname,addresses:["47.163.4.2"],
             exact_original_destination_match:true},
           dns:{hostname:$dns_udp.hostname,answer_addresses:$dns_udp.answer_addresses,
             udp:$dns_udp,tcp:$dns_tcp,
             udp_completion_events_before:$dns_udp_before,
             udp_completion_events_after:$dns_udp_after,
             tcp_completion_events_before:$dns_tcp_before,
             tcp_completion_events_after:$dns_tcp_after,
             agent_opened_resolver_socket_directly:false,
             exit_resolved_allowed_name:true},
           protected_flow:{transparent_client_hello_forwarded_unchanged:true,
             tls_handshake_and_payload_completed:true,
             ingress_completion_events_before:$completion_before,
             ingress_completion_events_after:$completion_after}}' \
        >"$WORK/a08-evidence.json"
    jq -e '.success == true' "$WORK/a08-evidence.json" >/dev/null 2>&1 \
        || A08_STATUS=1
fi
if [ "$A08_STATUS" -ne 0 ]; then
    OBSERVED_BLOCKER=A08_ALLOWED_TLS_DESTINATION_NOT_PROVEN
    PHASE=a08-blocked
    exit 77
fi
A08_SUCCEEDED=true
OBSERVED_BLOCKER=NONE
PHASE=a08-complete

tls_policy_accept_count() {
    jq -er '.accepted_connections' "$WORK/destination/tls-policy.json" 2>/dev/null \
        || printf '%s\n' -1
}

tls_policy_event_count() {
    tls_event=$1
    grep -Fc "event=$tls_event" "$WORK/logs-client.txt" 2>/dev/null || true
}

run_tls_policy_denial() {
    denial_case=$1
    denial_remote=$2
    denial_event=$3
    denial_output=$4
    capture_product_logs
    denial_accepts_before=$(tls_policy_accept_count)
    denial_events_before=$(tls_policy_event_count "$denial_event")
    case $denial_accepts_before:$denial_events_before in
        *[!0-9:]*) return 1 ;;
    esac
    set +e
    timeout --signal=TERM --kill-after=5s 45s \
        ip netns exec "$CLIENT" setpriv --reuid="$WORKER_UID" --regid="$WORKER_GID" \
        --clear-groups --inh-caps=-all --ambient-caps=-all --bounding-set=-all \
        --no-new-privs -- \
        "$WORK/bin/examples/tls-policy-acceptance-fixture" denied \
        "$denial_case" "$denial_remote" "$RUN_ID" \
        "$WORK/tls-policy/$denial_output.json" \
        >"$WORK/tls-policy/$denial_output.out" \
        2>"$WORK/tls-policy/$denial_output.err"
    denial_status=$?
    set -e
    [ "$denial_status" -eq 0 ] || return 1
    denial_attempt=0
    denial_event_seen=false
    while [ "$denial_attempt" -lt 200 ]; do
        capture_product_logs
        denial_events_after=$(tls_policy_event_count "$denial_event")
        if [ "$denial_events_after" -gt "$denial_events_before" ]; then
            denial_event_seen=true
            break
        fi
        sleep 0.1
        denial_attempt=$((denial_attempt + 1))
    done
    denial_accepts_after=$(tls_policy_accept_count)
    [ "$denial_event_seen" = true ] \
        && [ "$denial_accepts_after" -eq "$denial_accepts_before" ] \
        && jq -e '
            .connected_to_ingress == true
            and .client_hello_bytes > 0
            and .peer_closed_without_payload == true
            and .destination_response_bytes == 0' \
            "$WORK/tls-policy/$denial_output.json" >/dev/null 2>&1 \
        || return 1
    jq -S -c --arg expected_event "$denial_event" \
        --argjson accepts_before "$denial_accepts_before" \
        --argjson accepts_after "$denial_accepts_after" \
        '. + {expected_rejection_event:$expected_event,
          destination_accepts_before:$accepts_before,
          destination_accepts_after:$accepts_after,
          destination_egress_connections:($accepts_after - $accepts_before)}' \
        "$WORK/tls-policy/$denial_output.json" >"$WORK/$denial_output.json"
    chmod 0600 "$WORK/$denial_output.json"
    install -o root -g root -m 0600 "$WORK/tls-policy/$denial_output.err" \
        "$WORK/$denial_output.err"
}

PHASE=a09-forbidden-destinations
A09_REQUESTED=true
A09_STATUS=1
if run_tls_policy_denial unlisted-domain 47.163.4.2:18443 \
    INGRESS_TCP_POLICY_DENIED a09-unlisted-domain \
    && run_tls_policy_denial raw-ip-server-name 47.163.4.2:18443 \
        INGRESS_TCP_CLIENT_HELLO_DENIED a09-raw-ip-server-name \
    && run_tls_policy_denial missing-server-name 47.163.4.2:18443 \
        INGRESS_TCP_CLIENT_HELLO_DENIED a09-missing-server-name \
    && run_tls_policy_denial mismatched-destination 47.163.4.3:18443 \
        INGRESS_TCP_STREAM_FAILED a09-mismatched-destination \
    && run_tls_policy_denial forbidden-port 47.163.4.2:18444 \
        INGRESS_TCP_POLICY_DENIED a09-forbidden-port; then
    A09_STATUS=0
fi
if [ "$A09_STATUS" -eq 0 ]; then
    jq -S -c -n \
        --slurpfile unlisted "$WORK/a09-unlisted-domain.json" \
        --slurpfile raw_ip "$WORK/a09-raw-ip-server-name.json" \
        --slurpfile missing "$WORK/a09-missing-server-name.json" \
        --slurpfile mismatched "$WORK/a09-mismatched-destination.json" \
        --slurpfile port "$WORK/a09-forbidden-port.json" \
        --slurpfile destination "$WORK/destination/tls-policy.json" \
        '[$unlisted[0],$raw_ip[0],$missing[0],$mismatched[0],$port[0]] as $denials
        | (($denials | length) == 5
            and ($denials | all(.connected_to_ingress == true
                and .peer_closed_without_payload == true
                and .destination_response_bytes == 0
                and .destination_accepts_after == .destination_accepts_before
                and .destination_egress_connections == 0))
            and ($destination[0].accepted_connections == 1)
            and ($destination[0].successful_exchanges == 1)
            and ($destination[0].failed_connections == 0)) as $success
        | {schema_version:1,acceptance_id:"A09",success:$success,
           denied_cases:$denials,
           expected_rejection_events:["INGRESS_TCP_POLICY_DENIED",
             "INGRESS_TCP_CLIENT_HELLO_DENIED","INGRESS_TCP_STREAM_FAILED"],
           destination_accepts_before:1,
           destination_accepts_after:$destination[0].accepted_connections,
           destination_egress_connections_for_denials:0}' \
        >"$WORK/a09-evidence.json"
    jq -e '.success == true' "$WORK/a09-evidence.json" >/dev/null 2>&1 \
        || A09_STATUS=1
fi
if [ "$A09_STATUS" -ne 0 ]; then
    OBSERVED_BLOCKER=A09_FORBIDDEN_TLS_FLOW_ESCAPED_OR_UNOBSERVED
    PHASE=a09-blocked
    exit 77
fi
A09_SUCCEEDED=true
OBSERVED_BLOCKER=NONE
PHASE=a09-complete

PHASE=a10-ech-and-unverifiable
A10_REQUESTED=true
A10_STATUS=1
if run_tls_policy_denial ech 47.163.4.2:18443 \
    INGRESS_TCP_ECH_DENIED a10-ech \
    && run_tls_policy_denial unverifiable 47.163.4.2:18443 \
        INGRESS_TCP_CLIENT_HELLO_DENIED a10-unverifiable; then
    A10_STATUS=0
fi
if [ "$A10_STATUS" -eq 0 ]; then
    jq -S -c -n \
        --slurpfile ech "$WORK/a10-ech.json" \
        --slurpfile unverifiable "$WORK/a10-unverifiable.json" \
        --slurpfile destination "$WORK/destination/tls-policy.json" \
        '[$ech[0],$unverifiable[0]] as $denials
        | (($denials | length) == 2
            and ($denials | all(.connected_to_ingress == true
                and .peer_closed_without_payload == true
                and .destination_response_bytes == 0
                and .destination_accepts_after == .destination_accepts_before
                and .destination_egress_connections == 0))
            and ($destination[0].accepted_connections == 1)
            and ($destination[0].successful_exchanges == 1)
            and ($destination[0].failed_connections == 0)) as $success
        | {schema_version:1,acceptance_id:"A10",success:$success,
           denied_cases:$denials,
           expected_rejection_events:["INGRESS_TCP_ECH_DENIED",
             "INGRESS_TCP_CLIENT_HELLO_DENIED"],
           destination_accepts_before:1,
           destination_accepts_after:$destination[0].accepted_connections,
           destination_egress_connections_for_denials:0}' \
        >"$WORK/a10-evidence.json"
    jq -e '.success == true' "$WORK/a10-evidence.json" >/dev/null 2>&1 \
        || A10_STATUS=1
fi
if [ "$A10_STATUS" -ne 0 ]; then
    OBSERVED_BLOCKER=A10_ECH_OR_UNVERIFIABLE_TLS_NOT_CLOSED
    PHASE=a10-blocked
    exit 77
fi
A10_SUCCEEDED=true
OBSERVED_BLOCKER=NONE
PHASE=a10-complete

install -o "$AGENT_UID" -g "$AGENT_GID" -m 0600 /dev/null \
    "$WORK/destination/tls-policy.stop"
set +e
wait "$TLS_POLICY_SERVER_PID"
TLS_POLICY_SERVER_STATUS=$?
set -e
TLS_POLICY_SERVER_PID=
[ "$TLS_POLICY_SERVER_STATUS" -eq 0 ] || fail A10_TLS_DESTINATION_SHUTDOWN_FAILED
install -o root -g root -m 0600 "$WORK/destination/tls-policy.json" \
    "$WORK/tls-policy-destination-final.json"

PHASE=a11-a13-privacy-evidence
stop_privacy_observers || fail PRIVACY_CAPTURE_INCOMPLETE
for privacy_evidence in privacy-client.json privacy-relay1.json \
    privacy-relay2.json privacy-exit.json; do
    if [ ! -s "$WORK/$privacy_evidence" ] \
        || ! jq -e . "$WORK/$privacy_evidence" >/dev/null 2>&1; then
        fail PRIVACY_CAPTURE_INCOMPLETE
    fi
done
ip -n "$CLIENT" -j route show table all | jq -S . \
    >"$WORK/a13-client-routes-after.json" \
    || fail A13_ROUTE_EVIDENCE_UNAVAILABLE
set +e
ip -n "$CLIENT" -o route get 46.162.3.1 \
    >"$WORK/a13-exit-route-after.txt" 2>&1
route_status=$?
set -e
printf 'exit_status=%s\n' "$route_status" >>"$WORK/a13-exit-route-after.txt"
set +e
ip -n "$CLIENT" -o route get 47.163.4.2 \
    >"$WORK/a13-destination-route-after.txt" 2>&1
route_status=$?
set -e
printf 'exit_status=%s\n' "$route_status" \
    >>"$WORK/a13-destination-route-after.txt"

A11_STATUS=1
jq -S -c -n \
    --slurpfile relay1 "$WORK/privacy-relay1.json" \
    --slurpfile relay2 "$WORK/privacy-relay2.json" \
    '($relay1[0]) as $r1 | ($relay2[0]) as $r2
    | (($r1.capture_role == "relay1") and ($r2.capture_role == "relay2")
        and ($r1.truncated == false) and ($r2.truncated == false)
        and ($r1.client_leg_wireguard_data_datagrams > 0)
        and ($r1.exit_leg_wireguard_data_datagrams > 0)
        and ($r2.client_leg_wireguard_data_datagrams > 0)
        and ($r2.exit_leg_wireguard_data_datagrams > 0)
        and ($r1.internet_destination_outer_packets == 0)
        and ($r2.internet_destination_outer_packets == 0)
        and ($r1.unexpected_outer_packets == 0)
        and ($r2.unexpected_outer_packets == 0)) as $success
    | {schema_version:1,acceptance_id:"A11",success:$success,
       scope:"routed IPv4 outer headers on both physical legs of each data Relay",
       internet_destination:"47.163.4.2",relay1:$r1,relay2:$r2,
       payload_capture_retained:false}' >"$WORK/a11-evidence.json"
jq -e '.success == true' "$WORK/a11-evidence.json" >/dev/null 2>&1 \
    && A11_STATUS=0
if [ "$A11_STATUS" -ne 0 ]; then
    OBSERVED_BLOCKER=A11_RELAY_OUTER_PRIVACY_NOT_PROVEN
    PHASE=a11-blocked
    exit 77
fi
A11_SUCCEEDED=true

A12_STATUS=1
jq -S -c -n --slurpfile exit_capture "$WORK/privacy-exit.json" \
    '($exit_capture[0]) as $exit
    | (($exit.capture_role == "exit") and ($exit.truncated == false)
        and ($exit.relay1_wireguard_data_datagrams > 0)
        and ($exit.relay2_wireguard_data_datagrams > 0)
        and ($exit.outbound_client_discovery_attempt_packets == 0)
        and ($exit.client_public_packets == 0)
        and ($exit.direct_client_exit_packets == 0)) as $success
    | {schema_version:1,acceptance_id:"A12",success:$success,
       scope:"Exit physical ingress and destination interfaces",
       incoming_datapath_sources:["44.160.1.1","45.161.2.1"],
       forbidden_client_public_source:"43.159.1.1",capture:$exit,
       payload_capture_retained:false}' >"$WORK/a12-evidence.json"
jq -e '.success == true' "$WORK/a12-evidence.json" >/dev/null 2>&1 \
    && A12_STATUS=0
if [ "$A12_STATUS" -ne 0 ]; then
    OBSERVED_BLOCKER=A12_EXIT_SOURCE_PRIVACY_NOT_PROVEN
    PHASE=a12-blocked
    exit 77
fi
A12_SUCCEEDED=true

A13_STATUS=1
jq -S -c -n \
    --slurpfile client_capture "$WORK/privacy-client.json" \
    --slurpfile routes_before "$WORK/a13-client-routes-before.json" \
    --slurpfile routes_after "$WORK/a13-client-routes-after.json" \
    --rawfile exit_route_before "$WORK/a13-exit-route-before.txt" \
    --rawfile exit_route_after "$WORK/a13-exit-route-after.txt" \
    --rawfile destination_route_before "$WORK/a13-destination-route-before.txt" \
    --rawfile destination_route_after "$WORK/a13-destination-route-after.txt" \
    '($client_capture[0]) as $client
    | ["46.162.3.1/32","47.163.4.1/32","47.163.4.2/32",
       "51.167.7.1/32","52.168.8.1/32","52.168.8.2/32",
       "10.241.20.2/32","10.241.21.2/32","10.241.22.2/32",
       "10.241.23.2/32","10.241.24.2/32","10.241.25.2/32",
       "10.241.26.2/32","10.241.31.1/32","10.241.31.2/32",
       "10.241.32.1/32","10.241.32.2/32"] as $forbidden
    | ([($routes_before[0][]),($routes_after[0][])]
        | map(select((.dst // "") as $dst | $forbidden | index($dst)))
        | map(select((.type // "unicast") != "unreachable"))
        | map(select((.dev // "")
            | IN("cr0","cr1","cr2","cr3","cr4","cr5","cb1","cb2","underlay"))))
        as $direct_routes
    | (($client.capture_role == "client") and ($client.truncated == false)
        and ($client.relay1_wireguard_data_datagrams > 0)
        and ($client.relay2_wireguard_data_datagrams > 0)
        and ($client.direct_client_exit_packets == 0)
        and ($direct_routes | length) == 0
        and ($exit_route_before | test("dev (cr[0-5]|cb[12])( |$)") | not)
        and ($exit_route_after | test("dev (cr[0-5]|cb[12])( |$)") | not)
        and ($destination_route_before | test("dev (cr[0-5]|cb[12])( |$)") | not)
        and ($destination_route_after | test("dev (cr[0-5]|cb[12])( |$)") | not)
        and ($destination_route_before | contains("dev underlay"))) as $success
    | {schema_version:1,acceptance_id:"A13",success:$success,
       topology:{direct_client_exit_adjacency:false,peerless_fallback_underlay:true},
       client_capture:$client,direct_physical_routes:$direct_routes,
       route_get:{exit_before:$exit_route_before,exit_after:$exit_route_after,
         destination_before:$destination_route_before,
         destination_after:$destination_route_after},
       routes_before:$routes_before[0],routes_after:$routes_after[0],
       payload_capture_retained:false}' >"$WORK/a13-evidence.json"
jq -e '.success == true' "$WORK/a13-evidence.json" >/dev/null 2>&1 \
    && A13_STATUS=0
if [ "$A13_STATUS" -ne 0 ]; then
    OBSERVED_BLOCKER=A13_DIRECT_CLIENT_EXIT_ABSENCE_NOT_PROVEN
    PHASE=a13-blocked
    exit 77
fi
A13_SUCCEEDED=true
OBSERVED_BLOCKER=NONE
PHASE=a13-complete

PHASE=a14-refresh-live-custody
A14_REQUESTED=true
A14_STATUS=1
refresh_a14_live_custody || fail A14_LIVE_CUSTODY_REFRESH_FAILED
PHASE=a14-forced-crash
record_a14_owned_inventory || fail A14_OWNED_INVENTORY_UNAVAILABLE
# A14 deliberately replaced the earlier application route with a fresh active MPTCP route.
# Therefore inventory its still-owned namespaces, sockets and ingress policy instead of requiring
# stale MPQUIC-only local-control path records or relying on an earlier route's remaining TTL.
jq -e '
  .network_namespace_count == 12 and
  .runtime_socket_count >= 25 and
  .helper_worker_custody.worker_process_count >= 4 and
  .helper_worker_custody.worker_network_namespace_count ==
    .helper_worker_custody.worker_process_count and
  .helper_worker_custody.helper_fdstore_descriptors >=
    (.helper_worker_custody.worker_network_namespace_count * 2) and
  ([.namespaces[] | select(.nftables_rules > 0)] | length) >= 1
' "$WORK/a14-owned-before.json" >/dev/null \
    || fail A14_OWNED_INVENTORY_INCOMPLETE
for crash_node in client bootstrap1 bootstrap2 relay0 relay1 relay2 relay3 relay4 relay5 \
    exit exit2; do
    force_crash_unit agent "$crash_node" \
        "volparossa-alpha-agent@$crash_node.service" \
        || fail A14_AGENT_CRASH_FAILED
done
for crash_node in client exit exit2; do
    force_crash_unit native "$crash_node" \
        "volparossa-alpha-mpquic@$crash_node.service" \
        || fail A14_NATIVE_CRASH_FAILED
done
for crash_node in client bootstrap1 bootstrap2 relay0 relay1 relay2 relay3 relay4 relay5 \
    exit exit2; do
    force_crash_unit helper "$crash_node" \
        "volparossa-alpha-helper@$crash_node.service" \
        || fail A14_HELPER_CRASH_FAILED
done
verify_a14_helper_restart_recovery || fail A14_HELPER_RESTART_RECOVERY_FAILED
jq -S -c -s . "$WORK"/a14-crash-*.json >"$WORK/a14-crashes.json"
jq -e '
  length == 25 and
  ([.[].class] | map(select(. == "agent")) | length) == 11 and
  ([.[].class] | map(select(. == "helper")) | length) == 11 and
  ([.[].class] | map(select(. == "native")) | length) == 3 and
  all(.[]; .sigkill_delivered and .pid_absent_after)
' "$WORK/a14-crashes.json" >/dev/null || fail A14_FORCED_CRASH_INCOMPLETE
PHASE=a14-cleanup-pending
exit 0
