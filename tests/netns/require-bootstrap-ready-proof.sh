#!/bin/sh
# Require the two-veth rollback proof on an unprivileged Debian 13 host.
set -eu

export LC_ALL=C
PATH=/usr/bin:/bin
export PATH
umask 077

usage() {
    printf '%s\n' 'usage: tests/netns/require-bootstrap-ready-proof.sh' >&2
}

fail() {
    printf '%s\n' "veth rollback proof gate failed: $1" >&2
    exit 1
}

if [ "$#" -ne 0 ]; then
    usage
    exit 64
fi

repository_root=$(CDPATH='' cd -- "$(dirname -- "$0")/../.." && pwd)
runner_source=$repository_root/target/veth-rollback-proof/x86_64-unknown-linux-gnu/debug/volparossa-netns-runner
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

proof_tmp=$(mktemp -d /tmp/volparossa-veth-rollback-proof.XXXXXX)
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
    'BLOCKED: one pinned BOOTSTRAP_READY and canonical GO authorized descriptor-relative private-run roots, two live run-bound nsfs pins, and two fixed down-veth pairs, each created atomically with its eth0 peer born directly in the exact retained endpoint namespace. PID 1 proved the exact parent and A/B network deltas, deleted veth B then A, proved parent and both endpoints pristine again, unmounted nsfs B then A, restored the hidden slots, and reversed every private-run creation. It emitted one rollback-complete checkpoint, and the outer independently re-proved empty private mounts before fixed pidfd-to-PID1-signalfd TERM, post-GO cleanup-required EOF, and exact reap. No configured address, route, forwarding change, nftables mutation, packet, probe, ownership manifest, network-topology readiness, TOPOLOGY_READY, A14, A15, or acceptance evidence was produced.' \
    >"$proof_tmp/expected-stderr"
if ! cmp -s "$proof_tmp/expected-stderr" "$proof_tmp/stderr"; then
    fail 'runner did not report the veth rollback outcome'
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
# fingerprint is useful rollback evidence, but it is not A14 or A15 acceptance.

case $proof_scope in
    vm)
        printf '%s\n' 'Debian 13 VM veth rollback configuration-fingerprint gate passed (not A14/A15)'
        ;;
    additional-bare-metal-local)
        printf '%s\n' 'additional bare-metal local veth rollback configuration-fingerprint gate passed (not A14/A15)'
        ;;
    *) fail 'veth rollback proof scope was not classified' ;;
esac
