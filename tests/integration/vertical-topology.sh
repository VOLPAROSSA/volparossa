#!/bin/sh
# SPDX-License-Identifier: GPL-3.0-only
# Fixed internal worker for the disposable five-role acceptance topology.
set -eu
umask 077

[ "$#" -eq 6 ] && [ "$1" = --internal ] || exit 64
RUN_ID=$2
WORK=$3
BIN=$4
HOST_NET=$5
HOST_MNT=$6
case $RUN_ID in *[!0123456789abcdef]*|'') exit 64;; esac
[ "${#RUN_ID}" -eq 32 ] || exit 64
case $WORK:$BIN in /*:/*) ;; *) exit 64;; esac
[ -d "$WORK/evidence" ] && [ ! -L "$WORK" ] || exit 64
[ -x "$BIN/volparossa" ] && [ -x "$BIN/volparossa-agent" ] \
    && [ -x "$BIN/examples/acceptance-policy-fixture" ] || exit 69
[ "$(readlink /proc/self/ns/net)" != "$HOST_NET" ] || exit 70
[ "$(readlink /proc/self/ns/mnt)" != "$HOST_MNT" ] || exit 70
[ "$$" -eq 1 ] || exit 70

PREFIX=vp-$(printf '%.12s' "$RUN_ID")
CLIENT=$PREFIX-c
R1=$PREFIX-r1
R2=$PREFIX-r2
EXIT=$PREFIX-x
DEST=$PREFIX-d
PIDS=
CLEANED=no

cleanup() {
    [ "$CLEANED" = no ] || return 0
    for pid in $PIDS; do kill -TERM "$pid" 2>/dev/null || true; done
    attempt=0
    while [ "$attempt" -lt 50 ]; do
        live=no
        for pid in $PIDS; do kill -0 "$pid" 2>/dev/null && live=yes || true; done
        [ "$live" = no ] && break
        sleep 0.1
        attempt=$((attempt + 1))
    done
    for pid in $PIDS; do
        kill -0 "$pid" 2>/dev/null && kill -KILL "$pid" 2>/dev/null || true
        wait "$pid" 2>/dev/null || true
    done
    for ns in $DEST $EXIT $R2 $R1 $CLIENT; do ip netns del "$ns" 2>/dev/null || true; done
    remaining=$(ip netns list | awk -v p="$PREFIX-" '$1 ~ ("^" p) {n++} END {print n+0}')
    jq -n --arg id "$RUN_ID" --argjson remaining "$remaining" '{
      schema_version:1,run_id:$id,attempted:true,complete:($remaining == 0),
      remaining_owned_objects:$remaining,
      teardown_order:["destination","exit","relay2","relay1","client"],
      containment:"anonymous user, mount, PID, and network namespaces"
    }' >"$WORK/evidence/cleanup.json"
    CLEANED=yes
}
trap cleanup EXIT HUP INT TERM

mount --make-rprivate /
mount -t tmpfs -o mode=0755,nosuid,nodev tmpfs /run
mount -t tmpfs -o mode=0700,nosuid,nodev tmpfs /tmp
/bin/mkdir -p /run/netns
for ns in $CLIENT $R1 $R2 $EXIT $DEST; do ip netns add "$ns"; ip -n "$ns" link set lo up; done

link() {
    lns=$1; lname=$2; laddr=$3; rns=$4; rname=$5; raddr=$6
    la=t${lname}a; rb=t${rname}b
    ip link add "$la" type veth peer name "$rb"
    ip link set "$la" netns "$lns"; ip link set "$rb" netns "$rns"
    ip -n "$lns" link set "$la" name "$lname"; ip -n "$rns" link set "$rb" name "$rname"
    ip -n "$lns" address add "$laddr" dev "$lname"; ip -n "$rns" address add "$raddr" dev "$rname"
    ip -n "$lns" link set "$lname" up; ip -n "$rns" link set "$rname" up
}
link "$CLIENT" cr1 10.241.11.1/30 "$R1" r1c 10.241.11.2/30
link "$CLIENT" cr2 10.241.12.1/30 "$R2" r2c 10.241.12.2/30
link "$R1" r1x 10.241.21.1/30 "$EXIT" xr1 10.241.21.2/30
link "$R2" r2x 10.241.22.1/30 "$EXIT" xr2 10.241.22.2/30
link "$EXIT" xd 10.241.31.1/30 "$DEST" dx 10.241.31.2/30
for address in 10.241.21.2 10.241.22.2 10.241.31.2; do
    ip -n "$CLIENT" route get "$address" >/dev/null 2>&1 && exit 71 || true
done

CRED=$WORK/credential
CONTROL=/tmp/$PREFIX
/bin/mkdir -p "$CRED"
/bin/mkdir -p "$CONTROL"
printf '%s\n' 'disposable acceptance identity passphrase' >"$CRED/identity-passphrase"
chmod 0600 "$CRED/identity-passphrase"
init() {
    node=$1; state=$WORK/state-$node
    /bin/mkdir -p "$state" "$WORK/control-$node"; chmod 0700 "$state" "$WORK/control-$node"
    "$BIN/volparossa" init --identity "$state/identity.key" \
        --passphrase-file "$CRED/identity-passphrase" >"$WORK/init-$node.log"
    sed -n 's/^peer ID: //p' "$WORK/init-$node.log"
}
CLIENT_PEER=$(init client); R1_PEER=$(init relay1); R2_PEER=$(init relay2); EXIT_PEER=$(init exit)
for peer in "$CLIENT_PEER" "$R1_PEER" "$R2_PEER" "$EXIT_PEER"; do [ -n "$peer" ] || exit 72; done

config() {
    node=$1; operator=$2; relay=$3; exit_role=$4; ip1=$5; ip2=$6; boot1=$7; boot2=$8
    relay_cap=0; exit_cap=0; manifest="\"$WORK/development-policy.manifest\""
    advertised_asn=0; advertised_prefix=null
    [ "$relay" = false ] || relay_cap=32
    if [ "$exit_role" = true ]; then exit_cap=32; fi
    if [ "$relay" = true ] || [ "$exit_role" = true ]; then
        case $node in relay1) advertised_asn=64512;; relay2) advertised_asn=64513;; exit) advertised_asn=64514;; *) exit 64;; esac
        advertised_prefix=$(printf '%s\n' "$ip1" | awk -F. '{print $1 "." $2 "." $3 ".0/24"}')
    fi
    {
      printf 'runtime_mode: development\nnetwork:\n  name: VOLPAROSSA-acceptance-%s\n  protocol_version: 4\n' "$RUN_ID"
      [ "$operator" = null ] && printf '  operator_id: null\n' || printf '  operator_id: %s\n' "$operator"
      printf '  advertised_region: acceptance\n  advertised_country_code: ZZ\n'
      printf '  advertised_asn: %s\n' "$advertised_asn"
      [ "$advertised_prefix" = null ] && printf '  advertised_ipv4_prefix: null\n' || printf '  advertised_ipv4_prefix: %s\n' "$advertised_prefix"
      printf '  advertised_ipv6_prefix: null\n'
      printf '  listen_addresses:\n    - /ip4/%s/udp/41000/quic-v1\n' "$ip1"
      [ "$ip2" = none ] || printf '    - /ip4/%s/udp/41000/quic-v1\n' "$ip2"
      printf '  bootstrap_peers:\n'
      [ "$boot1" = none ] || printf '    - %s\n' "$boot1"
      [ "$boot2" = none ] || printf '    - %s\n' "$boot2"
      printf 'roles:\n  client: true\n  relay: %s\n  exit: %s\n' "$relay" "$exit_role"
      printf 'capacity:\n  relay_upload_limit_mbps: %s\n  relay_download_limit_mbps: %s\n' "$relay_cap" "$relay_cap"
      printf '  exit_upload_limit_mbps: %s\n  exit_download_limit_mbps: %s\n' "$exit_cap" "$exit_cap"
      printf '  maximum_relay_sessions: %s\n  maximum_exit_sessions: %s\n' "$relay_cap" "$exit_cap"
      printf 'policy:\n  fail_closed: true\n  manifest_path: %s\n  minimum_signatures: 3\n' "$manifest"
      printf '  reject_ech: true\n  reject_unverifiable_sni: true\nprivacy:\n  metrics_enabled: false\n'
      printf '  persist_domain_logs: false\n  persist_destination_ips: false\n'
    } >"$WORK/config-$node.yaml"
    chmod 0600 "$WORK/config-$node.yaml"
}
"$BIN/examples/acceptance-policy-fixture" "$WORK"
config client null false false 10.241.11.1 10.241.12.1 \
  /ip4/10.241.11.2/udp/41000/quic-v1/p2p/$R1_PEER \
  /ip4/10.241.12.2/udp/41000/quic-v1/p2p/$R2_PEER
config relay1 acceptance-relay-one true false 10.241.11.2 10.241.21.1 none none
config relay2 acceptance-relay-two true false 10.241.12.2 10.241.22.1 none none
config exit acceptance-exit false true 10.241.21.2 10.241.22.2 \
  /ip4/10.241.21.1/udp/41000/quic-v1/p2p/$R1_PEER \
  /ip4/10.241.22.1/udp/41000/quic-v1/p2p/$R2_PEER

agent() {
    ns=$1; node=$2
    ip netns exec "$ns" setpriv --no-new-privs --bounding-set=-all --inh-caps=-all --ambient-caps=-all \
      env VOLPAROSSA_CONFIG="$WORK/config-$node.yaml" VOLPAROSSA_STATE_DIRECTORY="$WORK/state-$node" \
      VOLPAROSSA_CONTROL_SOCKET="$CONTROL/$node-agent.sock" \
      VOLPAROSSA_HELPER_SOCKET="$CONTROL/$node-helper.sock" \
      VOLPAROSSA_MPQUIC_SOCKET="$CONTROL/$node-mpquic.sock" CREDENTIALS_DIRECTORY="$CRED" \
      RUST_LOG=volparossa_agent=info "$BIN/volparossa-agent" >"$WORK/agent-$node.log" 2>&1 &
    pid=$!; PIDS="$PIDS $pid"; eval "PID_$node=$pid"
}
agent "$CLIENT" client; agent "$R1" relay1; agent "$R2" relay2; agent "$EXIT" exit

printf '%s\n' \
 'import signal,socket,sys,time' \
 't=socket.socket();t.setsockopt(socket.SOL_SOCKET,socket.SO_REUSEADDR,1);t.bind(("10.241.31.2",18080));t.listen(4)' \
 'u=socket.socket(socket.AF_INET,socket.SOCK_DGRAM);u.bind(("10.241.31.2",18081))' \
 'open(sys.argv[1],"x").write("tcp=10.241.31.2:18080\\nudp=10.241.31.2:18081\\n")' \
 'signal.signal(signal.SIGTERM,lambda *_:sys.exit(0))' \
 'time.sleep(3600)' >"$WORK/destination.py"
ip netns exec "$DEST" setpriv --no-new-privs --bounding-set=-all --inh-caps=-all --ambient-caps=-all \
  python3 "$WORK/destination.py" "$WORK/destination.ready" >"$WORK/destination.log" 2>&1 &
PIDS="$PIDS $!"

attempt=0; ready=no
while [ "$attempt" -lt 100 ]; do
    ready=yes
    for node in client relay1 relay2 exit; do
        eval "pid=\$PID_$node"
        kill -0 "$pid" 2>/dev/null || ready=no
        [ -S "$CONTROL/$node-agent.sock" ] || ready=no
    done
    [ -f "$WORK/destination.ready" ] || ready=no
    [ "$ready" = yes ] && break
    sleep 0.1; attempt=$((attempt + 1))
done
[ "$ready" = yes ] || exit 73
for node in client relay1 relay2 exit; do
    "$BIN/volparossa" --control-socket "$CONTROL/$node-agent.sock" status >"$WORK/status-$node.json"
    "$BIN/volparossa" --control-socket "$CONTROL/$node-agent.sock" role show \
        >"$WORK/roles-$node.txt"
done
grep -Fx 'client: true' "$WORK/roles-client.txt" >/dev/null
grep -Fx 'relay: false' "$WORK/roles-client.txt" >/dev/null
grep -Fx 'exit: false' "$WORK/roles-client.txt" >/dev/null
for node in relay1 relay2; do
    grep -Fx 'relay: true' "$WORK/roles-$node.txt" >/dev/null
    grep -Fx 'exit: false' "$WORK/roles-$node.txt" >/dev/null
done
grep -Fx 'relay: false' "$WORK/roles-exit.txt" >/dev/null
grep -Fx 'exit: true' "$WORK/roles-exit.txt" >/dev/null

attempt=0; control_ready=no
while [ "$attempt" -lt 200 ]; do
    control_ready=yes
    for node in client relay1 relay2 exit; do
        "$BIN/volparossa" --control-socket "$CONTROL/$node-agent.sock" status \
            >"$WORK/status-$node.txt" || control_ready=no
        peers=$(awk '/^active peers: / {print $3}' "$WORK/status-$node.txt")
        [ -n "$peers" ] && [ "$peers" -ge 2 ] || control_ready=no
    done
    [ "$control_ready" = yes ] && break
    sleep 0.1; attempt=$((attempt + 1))
done
[ "$control_ready" = yes ] || exit 73

set +e
"$BIN/volparossa" --control-socket "$CONTROL/client-agent.sock" connect \
    >"$WORK/connect-client.txt" 2>"$WORK/connect-client.err"
connect_status=$?
set -e
[ "$connect_status" -ne 0 ] || exit 74
"$BIN/volparossa" --control-socket "$CONTROL/client-agent.sock" logs --limit 20 \
    >"$WORK/logs-client.txt"
grep -F 'event=CONNECT_DATAPLANE_UNAVAILABLE' "$WORK/logs-client.txt" >/dev/null || exit 74

jq -n --arg id "$RUN_ID" --arg c "$CLIENT" --arg r1 "$R1" --arg r2 "$R2" \
 --arg x "$EXIT" --arg d "$DEST" --arg cp "$CLIENT_PEER" --arg p1 "$R1_PEER" \
 --arg p2 "$R2_PEER" --arg xp "$EXIT_PEER" '{
  schema_version:1,run_id:$id,
  isolation:{user:true,mount:true,pid:true,network:true,host_network_mutated:false},topology_ready:true,
  nodes:[{name:"client",namespace:$c,role:"client",peer_id:$cp,agent_started:true},
    {name:"relay1",namespace:$r1,role:"relay",peer_id:$p1,agent_started:true},
    {name:"relay2",namespace:$r2,role:"relay",peer_id:$p2,agent_started:true},
    {name:"exit",namespace:$x,role:"exit",peer_id:$xp,agent_started:true},
    {name:"destination",namespace:$d,role:"destination",tcp:"10.241.31.2:18080",udp:"10.241.31.2:18081",endpoints_started:true}],
  links:["client-relay1","client-relay2","relay1-exit","relay2-exit","exit-destination"],
  direct_client_exit_adjacency:false,
  client_connect:{requested:true,diagnostic_code:"DATAPLANE_UNAVAILABLE",route_created:false},
  first_product_blocker:{code:"PRODUCT_DATAPLANE_UNAVAILABLE",message:"The real client control API reached its production fail-closed DATAPLANE_UNAVAILABLE response; no route context was created."}
 }' >"$WORK/evidence/topology.json"

cleanup
trap - EXIT HUP INT TERM
jq -e '.complete and .remaining_owned_objects == 0' "$WORK/evidence/cleanup.json" >/dev/null
exit 77
