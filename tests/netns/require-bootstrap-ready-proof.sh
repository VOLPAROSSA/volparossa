#!/bin/sh
# Require the complete pinned BOOTSTRAP_READY proof on an unprivileged Debian 13 host.
set -eu

export LC_ALL=C
PATH=/usr/bin:/bin
export PATH
umask 077

usage() {
    printf '%s\n' 'usage: tests/netns/require-bootstrap-ready-proof.sh' >&2
}

fail() {
    printf '%s\n' "BOOTSTRAP_READY proof gate failed: $1" >&2
    exit 1
}

if [ "$#" -ne 0 ]; then
    usage
    exit 64
fi

repository_root=$(CDPATH='' cd -- "$(dirname -- "$0")/../.." && pwd)
runner_source=$repository_root/target/bootstrap-ready-proof/x86_64-unknown-linux-gnu/debug/volparossa-netns-runner
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

proof_tmp=$(mktemp -d /tmp/volparossa-bootstrap-ready-proof.XXXXXX)
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
    cp /proc/net/route "$destination/ipv4-routes"
    cp /proc/net/ipv6_route "$destination/ipv6-routes"
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
    'BLOCKED: the exact new-netns RTNL baseline and one pinned BOOTSTRAP_READY were verified before the fixed pidfd-to-PID1-signalfd TERM, pre-GO EOF, and exact reap; no GO, network-topology mutation, or A14 evidence was produced.' \
    >"$proof_tmp/expected-stderr"
if ! cmp -s "$proof_tmp/expected-stderr" "$proof_tmp/stderr"; then
    fail 'runner did not report the complete pinned BOOTSTRAP_READY proof outcome'
fi
for record in namespaces mountinfo ipv4-routes ipv6-routes; do
    if ! cmp -s "$proof_tmp/before/$record" "$proof_tmp/after/$record"; then
        fail 'outer host namespace, mount, or route state changed'
    fi
done

case $proof_scope in
    vm)
        printf '%s\n' 'Debian 13 VM pinned BOOTSTRAP_READY proof gate passed'
        ;;
    additional-bare-metal-local)
        printf '%s\n' 'additional bare-metal local pinned BOOTSTRAP_READY proof gate passed'
        ;;
    *) fail 'BOOTSTRAP_READY proof scope was not classified' ;;
esac
