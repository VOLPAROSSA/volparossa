#!/bin/sh
# SPDX-License-Identifier: GPL-3.0-only
# Real MeshOwner backend association proof, strictly inside the disposable KVM guest.
# shellcheck disable=SC2317
set -eu
export LC_ALL=C
PATH=/usr/sbin:/usr/bin:/sbin:/bin
export PATH
umask 077
mode=preview
approval=no
test_binary=
output=
revision=
plan() {
    printf '%s\n' \
        'VOLPAROSSA disposable KVM Wi-Fi mesh backend plan:' \
        '  require Debian 13 KVM guest volparossa-alpha and no existing wireless radio;' \
        '  load only guest mac80211_hwsim with two simulated radios;' \
        '  create two temporary namespaces and move one simulated radio into each;' \
        '  execute actual MeshOwner create/join/ESTAB and bidirectional UDP/hash/counter proof;' \
        '  prove explicit idempotent deletion and socket-loss automatic deletion;' \
        '  remove exact namespaces/module and compare original guest routes/DNS/firewall/links.' \
        'No development-host radio action, physical Wi-Fi, SAE, throughput or full overlay claim.'
}
while [ "$#" -gt 0 ]; do
    case $1 in
        --preview) mode=preview ;;
        --execute) mode=execute ;;
        --yes) approval=yes ;;
        --test-binary) [ "$#" -ge 2 ] || exit 64; test_binary=$2; shift ;;
        --output) [ "$#" -ge 2 ] || exit 64; output=$2; shift ;;
        --expected-commit) [ "$#" -ge 2 ] || exit 64; revision=$2; shift ;;
        *) exit 64 ;;
    esac
    shift
done
if [ "$mode" = preview ]; then
    [ "$approval" = no ] && [ -z "$test_binary$output$revision" ] || exit 64
    plan
    printf '%s\n' 'PREVIEW ONLY: no radio, module, namespace, file or network state was changed.'
    exit 0
fi
[ "$approval" = yes ] && [ -n "$test_binary" ] && [ -n "$output" ] && [ -n "$revision" ] || exit 64
case $test_binary in /home/vpci/target/debug/deps/volparossa_helper-*) ;; *) exit 64 ;; esac
[ -f "$test_binary" ] && [ -x "$test_binary" ] && [ ! -L "$test_binary" ] || exit 64
[ "$output" = /home/vpci/alpha-output ] && [ -d "$output" ] && [ ! -L "$output" ] || exit 64
case $revision in ''|*[!0-9a-f]*) exit 64 ;; esac
[ "${#revision}" -eq 40 ] || [ "${#revision}" -eq 64 ] || exit 64
[ "$(id -u)" -eq 0 ] && [ "$(hostname)" = volparossa-alpha ] || exit 77
[ "$(systemd-detect-virt)" = kvm ] || exit 77
[ "$(uname -r)" = 6.12.107+deb13-amd64 ] || exit 77
# shellcheck source=/dev/null
[ "$(. /etc/os-release; printf '%s:%s' "$ID" "$VERSION_ID")" = debian:13 ] || exit 77
[ ! -d /sys/module/mac80211_hwsim ] || exit 77
[ -z "$(find /sys/class/ieee80211 -mindepth 1 -maxdepth 1 -print 2>/dev/null)" ] || exit 77
[ ! -e /run/volparossa-wifi-mesh-kvm ] || exit 77
for tool in ip iw jq modprobe nft python3 sha256sum timeout; do command -v "$tool" >/dev/null; done
plan
HERE=$(CDPATH='' cd -- "$(dirname -- "$0")" && pwd -P)
work=$(mktemp -d /run/volparossa-mesh-smoke.XXXXXX)
case $work in /run/volparossa-mesh-smoke.??????) ;; *) exit 69 ;; esac
ns_a=vmsha-$$
ns_b=vmshb-$$
pid_a=
pid_b=
pid_crash=
module_owned=no
ns_a_owned=no
ns_b_owned=no
normal_success=no
socket_loss=no
snapshot() {
    ip -j address show >"$work/addresses" || return 1
    jq -S 'map(.addr_info |= map(del(.valid_life_time,.preferred_life_time))) | sort_by(.ifindex)' "$work/addresses" || return 1
    for family in -4 -6; do
        ip -j "$family" route show table all >"$work/routes" || return 1
        jq -S '[.[] | {dst,src,gateway,dev,protocol,scope,type,table,prefsrc,metric,flags,mtu,nhid,nexthops}] | sort_by(tostring)' "$work/routes" || return 1
        ip -j "$family" rule show >"$work/rules" || return 1
        jq -S 'sort_by(tostring)' "$work/rules" || return 1
    done
    nft --stateless -j list ruleset >"$work/nft" || return 1
    jq -S 'del(.nftables[] | select(has("metainfo")))' "$work/nft" || return 1
    sha256sum /etc/resolv.conf || return 1
    readlink -f /etc/resolv.conf || return 1
    ip netns list || return 1
    for knob in /proc/sys/net/ipv4/ip_forward /proc/sys/net/ipv4/conf/all/forwarding \
        /proc/sys/net/ipv4/conf/all/src_valid_mark /proc/sys/net/ipv6/conf/all/forwarding; do
        cat "$knob" || return 1
    done
}
namespace_snapshot() {
    ip -n "$1" -j address show >"$work/ns-addresses" || return 1
    jq -S . "$work/ns-addresses" || return 1
    for family in -4 -6; do
        ip -n "$1" -j "$family" route show table all >"$work/ns-routes" || return 1
        jq -S 'sort_by(tostring)' "$work/ns-routes" || return 1
    done
}
snapshot >"$work/host-before"
cleanup() {
    status=$?
    trap - EXIT HUP INT TERM
    set +e
    for child in "$pid_a" "$pid_b" "$pid_crash"; do
        if [ -n "$child" ] && kill -0 "$child" 2>/dev/null; then
            kill -KILL "$child" 2>/dev/null
            wait "$child" 2>/dev/null
        fi
    done
    [ "$ns_a_owned" = no ] || ip netns delete "$ns_a"
    [ "$ns_b_owned" = no ] || ip netns delete "$ns_b"
    if [ "$module_owned" = yes ]; then
        attempt=0
        while [ -d /sys/module/mac80211_hwsim ] && [ "$attempt" -lt 50 ]; do
            modprobe -r mac80211_hwsim && break
            sleep 0.1
            attempt=$((attempt + 1))
        done
    fi
    rm -f /run/volparossa-wifi-mesh-kvm
    snapshot_ok=no
    snapshot >"$work/host-after" && snapshot_ok=yes
    unchanged=no
    [ "$snapshot_ok" = yes ] && cmp -s "$work/host-before" "$work/host-after" && unchanged=yes
    remaining=0
    [ ! -e "/run/netns/$ns_a" ] || remaining=$((remaining + 1))
    [ ! -e "/run/netns/$ns_b" ] || remaining=$((remaining + 1))
    [ ! -d /sys/module/mac80211_hwsim ] || remaining=$((remaining + 1))
    radios=$(find /sys/class/ieee80211 -mindepth 1 -maxdepth 1 -print 2>/dev/null | wc -l)
    remaining=$((remaining + radios))
    python3 "$HERE/wifi-mesh-report.py" "$output" "$revision" "$status" \
        "$normal_success" "$socket_loss" "$unchanged" "$remaining"
    report_status=$?
    rm -rf --one-file-system -- "$work"
    [ "$status" -eq 0 ] && [ "$report_status" -eq 0 ] || exit 1
    exit 0
}
trap cleanup EXIT
trap 'exit 129' HUP
trap 'exit 130' INT
trap 'exit 143' TERM
printf '%s\n' hwsim-only >/run/volparossa-wifi-mesh-kvm
module_owned=yes
modprobe mac80211_hwsim radios=2
set -- /sys/class/ieee80211/phy*
[ "$#" -eq 2 ]
phy_a=${1##*/}
phy_b=${2##*/}
for phy in "$phy_a" "$phy_b"; do
    [ "$(basename "$(readlink -f "/sys/class/ieee80211/$phy/device/subsystem")")" = mac80211_hwsim ]
done
ip netns add "$ns_a"
ns_a_owned=yes
ip netns add "$ns_b"
ns_b_owned=yes
# Radios were created in the same hwsim netgroup before moving: frames cross these netns.
iw phy "$phy_a" set netns name "$ns_a"
iw phy "$phy_b" set netns name "$ns_b"
parent_a=$(ip netns exec "$ns_a" iw dev | awk '$1 == "Interface" { print $2 }')
parent_b=$(ip netns exec "$ns_b" iw dev | awk '$1 == "Interface" { print $2 }')
case $parent_a:$parent_b in wlan[0-9]*:wlan[0-9]*) ;; *) exit 1 ;; esac
ip -n "$ns_a" link set dev "$parent_a" down
ip -n "$ns_b" link set dev "$parent_b" down
ip -n "$ns_a" link set dev lo up
ip -n "$ns_b" link set dev lo up
namespace_snapshot "$ns_a" >"$work/a-before"
namespace_snapshot "$ns_b" >"$work/b-before"
test_name=kernel::wifi_mesh::tests::hwsim::disposable_hwsim_mesh_owner
ip netns exec "$ns_a" env VOLPAROSSA_WIFI_MESH_KVM=1 VOLPAROSSA_WIFI_MESH_ROLE=a \
    VOLPAROSSA_WIFI_MESH_PARENT="$parent_a" "$test_binary" --ignored --exact "$test_name" \
    --nocapture >"$output/mesh-a.log" 2>&1 &
pid_a=$!
ip netns exec "$ns_b" env VOLPAROSSA_WIFI_MESH_KVM=1 VOLPAROSSA_WIFI_MESH_ROLE=b \
    VOLPAROSSA_WIFI_MESH_PARENT="$parent_b" "$test_binary" --ignored --exact "$test_name" \
    --nocapture >"$output/mesh-b.log" 2>&1 &
pid_b=$!
wait "$pid_a"
pid_a=
wait "$pid_b"
pid_b=
namespace_snapshot "$ns_a" >"$work/a-after"
namespace_snapshot "$ns_b" >"$work/b-after"
cmp "$work/a-before" "$work/a-after"
cmp "$work/b-before" "$work/b-after"
normal_success=yes
ip netns exec "$ns_a" env VOLPAROSSA_WIFI_MESH_KVM=1 VOLPAROSSA_WIFI_MESH_ROLE=crash \
    VOLPAROSSA_WIFI_MESH_PARENT="$parent_a" "$test_binary" --ignored --exact "$test_name" \
    --nocapture >"$output/mesh-crash.log" 2>&1 &
pid_crash=$!
attempt=0
while ! grep -q '^MESH_CRASH_READY ' "$output/mesh-crash.log"; do
    kill -0 "$pid_crash" 2>/dev/null || exit 1
    [ "$attempt" -lt 100 ] || exit 1
    sleep 0.1
    attempt=$((attempt + 1))
done
[ "$(readlink -f "/proc/$pid_crash/exe")" = "$test_binary" ]
kill -KILL "$pid_crash"
wait "$pid_crash" 2>/dev/null || true
pid_crash=
attempt=0
while ip -n "$ns_a" link show dev vw5353535353535 >/dev/null 2>&1; do
    [ "$attempt" -lt 100 ] || exit 1
    sleep 0.1
    attempt=$((attempt + 1))
done
namespace_snapshot "$ns_a" >"$work/a-crash-after"
cmp "$work/a-before" "$work/a-crash-after"
socket_loss=yes
exit 0
