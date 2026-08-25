#!/bin/sh
# Require the fixed ICMPv4 echo plus rollback proof on an unprivileged Debian 13 host.
set -eu

export LC_ALL=C
PATH=/usr/bin:/bin
export PATH
umask 077

usage() {
    printf '%s\n' 'usage: tests/netns/require-fixed-icmp-echo-proof.sh' >&2
}

fail() {
    printf '%s\n' "fixed ICMP echo proof gate failed: $1" >&2
    exit 1
}

if [ "$#" -ne 0 ]; then
    usage
    exit 64
fi

repository_root=$(CDPATH='' cd -- "$(dirname -- "$0")/../.." && pwd)
runner_source=$repository_root/target/fixed-icmp-echo-proof/x86_64-unknown-linux-gnu/debug/volparossa-netns-runner
if [ ! -f "$runner_source" ] || [ ! -x "$runner_source" ] || [ -L "$runner_source" ]; then
    fail 'fixed workspace runner must be one executable regular file, not a symlink'
fi

if [ ! -r /etc/os-release ]; then
    fail 'operating-system identity is unavailable'
fi
os_id=$(sed -n 's/^ID=//p' /etc/os-release)
os_version_id=$(sed -n 's/^VERSION_ID=//p' /etc/os-release)
if [ "$os_id" != debian ] || { [ "$os_version_id" != 13 ] && [ "$os_version_id" != '"13"' ]; }; then
    fail 'host is not Debian 13'
fi
if ! command -v dpkg >/dev/null 2>&1 || [ "$(dpkg --print-architecture)" != amd64 ]; then
    fail 'host architecture is not Debian amd64'
fi
if [ "$(id -u)" -eq 0 ]; then
    fail 'gate must run as an unprivileged user'
fi
if ! command -v systemd-detect-virt >/dev/null 2>&1; then
    fail 'systemd-detect-virt is required to identify the acceptance host'
fi
for required_tool in /usr/bin/ip /usr/bin/jq /usr/bin/readlink /usr/bin/stat /usr/sbin/tc; do
    if [ ! -x "$required_tool" ]; then
        fail "required read-only fingerprint tool is unavailable: $required_tool"
    fi
done
virt_status=0
virt_kind=$(systemd-detect-virt 2>/dev/null) || virt_status=$?
case "$virt_status:$virt_kind" in
    0:*)
        if systemd-detect-virt --container --quiet; then
            fail 'container execution cannot provide Debian-host kernel evidence'
        fi
        if ! systemd-detect-virt --vm --quiet; then
            fail 'virtualisation type is neither a recognised VM nor bare metal'
        fi
        proof_scope=vm
        ;;
    1:none) proof_scope=additional-bare-metal-local ;;
    *) fail 'virtualisation identity is unavailable or non-canonical' ;;
esac

if ! awk '
    BEGIN { count = 0 }
    $1 == "CapInh:" || $1 == "CapPrm:" || $1 == "CapEff:" || $1 == "CapAmb:" {
        count++
        if ($2 != "0000000000000000") exit 1
    }
    END { if (count != 4) exit 1 }
' /proc/self/status; then
    fail 'inherited, permitted, effective, or ambient capabilities are nonzero'
fi
if ! awk '$1 == "NoNewPrivs:" { count++; if ($2 != "1") exit 1 }
    END { if (count != 1) exit 1 }' /proc/self/status; then
    fail 'no-new-privileges is not enforced'
fi

for quota in \
    /proc/sys/user/max_user_namespaces \
    /proc/sys/user/max_mnt_namespaces \
    /proc/sys/user/max_net_namespaces \
    /proc/sys/user/max_pid_namespaces
do
    if [ ! -r "$quota" ]; then
        fail 'required namespace quota is unreadable'
    fi
    quota_value=$(sed -n '1p' "$quota")
    case $quota_value in
        ''|*[!0-9]*) fail 'required namespace quota is not canonical decimal' ;;
    esac
    if [ "$quota_value" -eq 0 ]; then
        fail 'required namespace quota is zero'
    fi
done

proof_tmp=$(mktemp -d /tmp/volparossa-fixed-icmp-echo-proof.XXXXXX)
cleanup() {
    rm -rf -- "$proof_tmp"
}
trap cleanup EXIT
trap 'exit 129' HUP
trap 'exit 130' INT
trap 'exit 143' TERM

runner=$proof_tmp/volparossa-netns-runner
cp -- "$runner_source" "$runner"
chmod 0500 "$runner"
runner_identity=$(stat -Lc '%u:%a:%h' "$runner")
if [ "$runner_identity" != "$(id -u):500:1" ]; then
    fail 'private runner copy has unexpected ownership, mode, or link count'
fi

capture_host_state() {
    destination=$1
    : >"$destination/namespaces"
    for namespace in user net mnt pid pid_for_children; do
        stat -Lc '%d:%i' "/proc/self/ns/$namespace" >>"$destination/namespaces"
    done
    cp /proc/self/mountinfo "$destination/mountinfo"
    cp /proc/sys/net/ipv4/ip_forward "$destination/ipv4-forwarding"
    cp /proc/sys/net/ipv6/conf/all/forwarding "$destination/ipv6-forwarding-all"
    cp /proc/sys/net/ipv6/conf/default/forwarding "$destination/ipv6-forwarding-default"

    # Preserve configured link flags such as UP while filtering carrier-driven
    # flags, operstate and namespace-ID telemetry.  The ordinary link view does
    # not expose statistics or bridge countdown timers.  Qdisc configuration is
    # fingerprinted independently below.
    /usr/bin/ip -json link show | /usr/bin/jq -S -c '
        map(
            del(.operstate, .link_netnsid, .promiscuity, .allmulti, .stats, .stats64)
            | .flags = ((.flags // [])
                | map(select(
                    . != "LOWER_UP"
                    and . != "RUNNING"
                    and . != "DORMANT"
                    and . != "NO-CARRIER"
                ))
                | sort)
            | if has("altnames") then .altnames |= sort else . end
        )
        | sort_by(.ifindex, .ifname)
    ' >"$destination/links"

    # Address identity and configuration remain exact, but DAD state and
    # countdown lifetimes are ordinary volatile telemetry and are removed.
    /usr/bin/ip -json address show | /usr/bin/jq -S -c '
        map({
            ifindex,
            ifname,
            addr_info: ((.addr_info // [])
                | map(del(
                    .valid_life_time,
                    .preferred_life_time,
                    .valid_lft,
                    .preferred_lft,
                    .tstamp,
                    .cstamp,
                    .tentative,
                    .dadfailed,
                    .deprecated,
                    .optimistic
                ))
                | sort_by(
                    .family,
                    .local,
                    (.peer // ""),
                    .prefixlen,
                    .scope,
                    (.label // "")
                ))
        })
        | sort_by(.ifindex, .ifname)
    ' >"$destination/addresses"

    # Route expiry/cache/use data is volatile.  Configured route flags remain,
    # while kernel-offload/link-health presentation flags are excluded.
    route_filter='
        def stable_route_flags:
            map(select(
                . != "linkdown"
                and . != "dead"
                and . != "offload"
                and . != "trap"
                and . != "unresolved"
            )) | sort;
        walk(
            if type == "object" then
                del(
                    .expires,
                    .used,
                    .age,
                    .lastuse,
                    .users,
                    .cache,
                    .statistics
                )
                | if ((.flags? // null) | type) == "array" then
                    .flags |= stable_route_flags
                  else . end
            else . end
        )
        | sort_by(
            (.table // "" | tostring),
            (.dst // ""),
            (.src // ""),
            (.metric // 0),
            (.protocol // ""),
            (.dev // ""),
            (.gateway // "")
        )
    '
    /usr/bin/ip -json -4 route show table all | /usr/bin/jq -S -c "$route_filter" \
        >"$destination/ipv4-routes"
    /usr/bin/ip -json -6 route show table all | /usr/bin/jq -S -c "$route_filter" \
        >"$destination/ipv6-routes"

    /usr/bin/ip -json -4 rule show | /usr/bin/jq -S -c '
        sort_by(.priority, (.table // "" | tostring), (.src // ""), (.dst // ""))
    ' >"$destination/ipv4-rules"
    /usr/bin/ip -json -6 rule show | /usr/bin/jq -S -c '
        sort_by(.priority, (.table // "" | tostring), (.src // ""), (.dst // ""))
    ' >"$destination/ipv6-rules"
    /usr/bin/ip -json nexthop show | /usr/bin/jq -S -c '
        walk(
            if type == "object" then
                del(.used, .age, .lastuse, .statistics)
                | if ((.flags? // null) | type) == "array" then
                    .flags |= map(select(. != "offload" and . != "trap")) | sort
                  else . end
            else . end
        )
        | sort_by(.id, (.dev // ""), (.via // "" | tostring))
    ' >"$destination/nexthops"

    # Do not request tc statistics.  Refcounts and queue/backlog counters are
    # telemetry; the qdisc kind, handles, parent and options are configuration.
    /usr/sbin/tc -json qdisc show | /usr/bin/jq -S -c '
        walk(
            if type == "object" then
                del(
                    .refcnt,
                    .bytes,
                    .packets,
                    .drops,
                    .overlimits,
                    .requeues,
                    .backlog,
                    .qlen,
                    .direct_packets_stat,
                    .xstats
                )
            else . end
        )
        | sort_by(.dev, (.parent // ""), (.handle // ""), .kind)
    ' >"$destination/qdiscs"

    capture_resolver_state "$destination"
}

capture_resolver_state() {
    destination=$1
    if [ ! -r /etc/resolv.conf ]; then
        fail 'resolver configuration is unavailable or unreadable'
    fi

    resolver_object_before=$(/usr/bin/stat -c '%F:%d:%i:%u:%g:%a:%h' /etc/resolv.conf)
    resolver_target_before=$(/usr/bin/stat -Lc '%F:%d:%i:%u:%g:%a:%h' /etc/resolv.conf)
    if [ -L /etc/resolv.conf ]; then
        /usr/bin/readlink -- /etc/resolv.conf >"$destination/resolver-link-target"
    else
        : >"$destination/resolver-link-target"
    fi
    cp -L /etc/resolv.conf "$destination/resolver-content"
    resolver_object_after=$(/usr/bin/stat -c '%F:%d:%i:%u:%g:%a:%h' /etc/resolv.conf)
    resolver_target_after=$(/usr/bin/stat -Lc '%F:%d:%i:%u:%g:%a:%h' /etc/resolv.conf)
    if [ "$resolver_object_before" != "$resolver_object_after" ] \
        || [ "$resolver_target_before" != "$resolver_target_after" ]; then
        fail 'resolver object changed during one fingerprint capture'
    fi
    printf '%s\n' "$resolver_object_before" >"$destination/resolver-object-identity"
    printf '%s\n' "$resolver_target_before" >"$destination/resolver-target-identity"
}

mkdir "$proof_tmp/before" "$proof_tmp/after"
capture_host_state "$proof_tmp/before"

set +e
/usr/bin/env -i "$runner" --run >"$proof_tmp/stdout" 2>"$proof_tmp/stderr"
runner_status=$?
set -e

capture_host_state "$proof_tmp/after"

if [ "$runner_status" -ne 77 ]; then
    fail 'runner did not return the exact blocked status 77'
fi
if [ -s "$proof_tmp/stdout" ]; then
    fail 'runner wrote unexpected standard output'
fi
printf '%s\n' \
    'BLOCKED: one pinned BOOTSTRAP_READY and canonical GO authorized the fixed descriptor-relative private run. PID 1 proved the exact disposable parent/A/B baselines, two run-bound nsfs pins, two fixed veth pairs and four /30 addresses; installed the topology-bound generation-2 parent FORWARD policy before link activation; conditionally enabled only the disposable parent ip_forward record; activated all four ends; installed the two exact static endpoint /32 routes; and installed four exact affine NUD_PERMANENT neighbours with zero probes and zero proxy neighbours. Only structurally valid volatile NDA_CACHEINFO telemetry was excluded from neighbour equality. With those neighbours armed, PID 1 consumed zero-counter policy authority, opened one nonblocking close-on-exec raw ICMPv4 socket inside endpoint A, bound it to eth0 and 10.241.1.2, connected it to 10.241.2.2, and issued exactly one sendmsg with no retry for one 40-byte echo request. The request used the first two canonical run-ID ASCII bytes as its big-endian identifier, sequence 1, and the full 32-byte canonical ASCII run ID as payload. Before the absolute deadline, endpoint A received one exact 60-byte IPv4 echo reply; source, destination, receive interface and IP_PKTINFO, IPv4 and ICMP checksums, identifier, sequence, and full payload all matched. The socket closed before two identical complete generation-bracketed observations proved the request-accept, reply-accept, and terminal-drop counters at exactly packets/bytes 1/60, 1/60, and 0/0. Fresh semantic RTNL observations proved every one of the four veth ends at exactly one RX and one TX packet and 74 RX and TX bytes, with all other parsed link statistics zero, while routes, addresses, qdiscs, four permanent neighbours, zero probes, and zero proxy-neighbour records remained exact. PID 1 removed the neighbours in reverse endpoint B/A then parent B/A order, proved the exact routed state restored without changing the post-echo link telemetry, and re-proved the exact 1/60, 1/60, 0/0 policy-counter profile. It then converted the policy to counter-agnostic cleanup authority, deleted veth B then A, restored the exact original parent ip_forward record, proved pristine parent/endpoints under generation 2, deleted only the observed table handle, proved semantic-empty generation 3, retired lower owners, reversed nsfs/filesystem state, emitted the rollback checkpoint, and completed exact TERM/EOF/reap. The outer host ip_forward record remained byte-identical. This proves one fixed run-bound ICMPv4 echo request/reply exchange, its exact two-accept/zero-drop counter profile, matching four-veth link telemetry, and bounded configuration teardown. It does not prove packet absence, packet-capture privacy, a general VPN datapath, an ownership manifest, network-topology readiness, TOPOLOGY_READY, forced-crash cleanup, A14, A15, or acceptance evidence.' \
    >"$proof_tmp/expected-stderr"
if ! cmp -s "$proof_tmp/expected-stderr" "$proof_tmp/stderr"; then
        fail 'runner did not report the exact fixed ICMP echo and teardown outcome'
fi
for record in \
    namespaces \
    mountinfo \
    links \
    addresses \
    ipv4-routes \
    ipv6-routes \
    ipv4-rules \
    ipv6-rules \
    nexthops \
    qdiscs \
    ipv4-forwarding \
    ipv6-forwarding-all \
    ipv6-forwarding-default \
    resolver-object-identity \
    resolver-target-identity \
    resolver-link-target \
    resolver-content
do
    if ! cmp -s "$proof_tmp/before/$record" "$proof_tmp/after/$record"; then
        fail "outer canonical host configuration changed: $record"
    fi
done

# This unprivileged gate deliberately does not escalate merely to inspect the
# host firewall.  Host nftables/legacy-firewall state and VPN-private peer/key
# state are not authoritatively readable here.  The visible link/configuration
# fingerprint is useful fixed-ICMP rollback evidence, but it is not A14 or A15 acceptance.

case $proof_scope in
    vm)
        printf '%s\n' 'Debian 13 VM fixed ICMP echo plus rollback gate passed (one exact run-bound request/reply; policy counters 1/60,1/60,0/0; outer configuration fingerprint unchanged; no packet-absence, TOPOLOGY_READY, A14/A15 or acceptance claim)'
        ;;
    additional-bare-metal-local)
        printf '%s\n' 'additional bare-metal local fixed ICMP echo plus rollback gate passed (one exact run-bound request/reply; policy counters 1/60,1/60,0/0; outer configuration fingerprint unchanged; no packet-absence, TOPOLOGY_READY, A14/A15 or acceptance claim)'
        ;;
    *) fail 'fixed ICMP echo proof scope was not classified' ;;
esac
