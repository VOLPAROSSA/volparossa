#!/bin/sh
# SPDX-License-Identifier: GPL-3.0-only
# Install, start, diagnose, upgrade and remove one package only inside a disposable Debian 13 KVM.
set -eu

export LC_ALL=C
PATH=/usr/sbin:/usr/bin:/sbin:/bin
export PATH
umask 077

mode=preview
approval=no
package_path=
output_directory=

usage() {
    printf '%s\n' \
        'usage: tests/packaging/debian13-package-lifecycle.sh --preview' \
        '       tests/packaging/debian13-package-lifecycle.sh --execute --yes' \
        '         --package ABSOLUTE_PATH --output ABSOLUTE_EMPTY_DIRECTORY'
}

print_plan() {
    printf '%s\n' \
        'VOLPAROSSA disposable Debian package lifecycle plan:' \
        '  require Debian 13 amd64, PID 1 systemd and exact KVM virtualization;' \
        '  require a clean VM with no installed VOLPAROSSA package or state;' \
        '  derive an older-version candidate from the exact supplied package;' \
        '  install it without enabling services and verify package ownership/modes;' \
        '  provision one throwaway identity, local threshold policy and credential;' \
        '  run doctor, start all shipped services and query the live agent;' \
        '  upgrade to the exact supplied package and require active processes to restart;' \
        '  remove the package while active and require services/binaries/units absent;' \
        '  require encrypted identity/config preservation and unchanged VM networking.'
}

while [ "$#" -gt 0 ]; do
    case $1 in
        --preview) mode=preview ;;
        --execute) mode=execute ;;
        --yes) approval=yes ;;
        --package)
            [ "$#" -ge 2 ] || { usage >&2; exit 64; }
            package_path=$2
            shift
            ;;
        --output)
            [ "$#" -ge 2 ] || { usage >&2; exit 64; }
            output_directory=$2
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
    if [ "$approval" != no ] || [ -n "$package_path$output_directory" ]; then
        usage >&2
        exit 64
    fi
    print_plan
    printf '%s\n' 'PREVIEW ONLY: no package, service, account, file or network state was changed.'
    exit 0
fi

if [ "$approval" != yes ] || [ -z "$package_path" ] || [ -z "$output_directory" ]; then
    usage >&2
    exit 64
fi
case $package_path:$output_directory in /*:/*) ;; *) exit 64 ;; esac
[ "$(id -u)" -eq 0 ] || { printf '%s\n' 'execute requires guest root' >&2; exit 77; }

for command_name in apt-get awk cmp dpkg dpkg-deb dpkg-query find getent grep id \
    install ip jq mktemp nft readlink rm runuser sed sha256sum stat systemctl \
    systemd-creds systemd-detect-virt uname; do
    command -v "$command_name" >/dev/null 2>&1 \
        || { printf 'required guest command unavailable: %s\n' "$command_name" >&2; exit 69; }
done

os_id=$(sed -n 's/^ID=//p' /etc/os-release)
os_version=$(sed -n 's/^VERSION_ID="\{0,1\}\([^"[:space:]]*\)"\{0,1\}$/\1/p' \
    /etc/os-release)
test "$os_id:$os_version" = debian:13
test "$(dpkg --print-architecture)" = amd64
test "$(uname -m)" = x86_64
test "$(sed -n '1p' /proc/1/comm)" = systemd
test "$(systemd-detect-virt)" = kvm

[ "$(readlink -f -- "$package_path")" = "$package_path" ] || exit 64
[ -f "$package_path" ] && [ ! -L "$package_path" ] || exit 64
[ -d "$output_directory" ] && [ ! -L "$output_directory" ] || exit 64
[ -z "$(find "$output_directory" -mindepth 1 -maxdepth 1 -print -quit)" ] || exit 64
[ "$(dpkg-deb -f "$package_path" Package)" = volparossa ] || exit 64
[ "$(dpkg-deb -f "$package_path" Architecture)" = amd64 ] || exit 64
package_version=$(dpkg-deb -f "$package_path" Version)
case $package_version in ''|*[!0-9A-Za-z.+:~_-]*) exit 64 ;; esac
if dpkg-query -W -f='${Status}\n' volparossa 2>/dev/null | grep -Fx \
    'install ok installed' >/dev/null; then
    printf '%s\n' 'execute requires a clean VM without an installed volparossa package' >&2
    exit 77
fi
for path in /etc/volparossa /var/lib/volparossa /run/volparossa; do
    if [ -e "$path" ] || [ -L "$path" ]; then
        printf 'execute requires absent initial path: %s\n' "$path" >&2
        exit 77
    fi
done

run_directory=$(mktemp -d /tmp/volparossa-package-lifecycle.XXXXXX)
case $run_directory in /tmp/volparossa-package-lifecycle.??????) ;; *) exit 69 ;; esac
finished=no
cleanup() {
    status=$?
    trap - EXIT HUP INT TERM
    if [ "$finished" != yes ]; then
        systemctl stop volparossa-agent.service volparossa-mpquic.service \
            volparossa-helper.service >/dev/null 2>&1 || true
        env DEBIAN_FRONTEND=noninteractive dpkg --remove volparossa >/dev/null 2>&1 || true
        rm -f -- /var/lib/volparossa/.lifecycle-identity-passphrase \
            /etc/credstore.encrypted/identity-passphrase 2>/dev/null || true
        rm -rf --one-file-system -- /var/lib/volparossa/lifecycle-policy 2>/dev/null || true
    fi
    rm -rf --one-file-system -- "$run_directory"
    exit "$status"
}
trap cleanup EXIT
trap 'exit 129' HUP
trap 'exit 130' INT
trap 'exit 143' TERM

snapshot_network() {
    destination=$1
    {
        printf 'resolv_conf=%s\n' "$(sha256sum /etc/resolv.conf | awk '{ print $1 }')"
        printf 'ipv4_forward=%s\n' "$(sed -n '1p' /proc/sys/net/ipv4/ip_forward)"
        printf 'ipv6_forward=%s\n' "$(sed -n '1p' /proc/sys/net/ipv6/conf/all/forwarding)"
        printf '%s\n' 'links='
        ip -j link show | jq -S 'sort_by(.ifindex)'
        printf '%s\n' 'addresses='
        ip -j address show | jq -S \
            'walk(if type == "object" then del(.valid_life_time,.preferred_life_time) else . end) | sort_by(.ifindex)'
        printf '%s\n' 'routes='
        ip -j route show table all | jq -S \
            'walk(if type == "object" then del(.expires,.used) else . end) | sort_by([.table,.dst,.dev,.gateway])'
        printf '%s\n' 'rules='
        ip -j rule show | jq -S 'sort_by([.priority,.table])'
        printf '%s\n' 'nftables='
        nft -j list ruleset | jq -S .
    } >"$destination"
}

network_before=$run_directory/network.before
network_after=$run_directory/network.after
snapshot_network "$network_before"
package_sha256=$(sha256sum "$package_path" | awk '{ print $1 }')

# Exercise a real dpkg upgrade rather than treating a fresh installation as sufficient.
old_root=$run_directory/old-root
old_package=$run_directory/volparossa-old.deb
dpkg-deb --raw-extract "$package_path" "$old_root"
old_version=${package_version}~volparossa.lifecycle1
dpkg --compare-versions "$old_version" lt "$package_version"
awk -v version="$old_version" '
    BEGIN { replaced = 0 }
    /^Version: / {
        if (replaced != 0) exit 65
        print "Version: " version
        replaced = 1
        next
    }
    { print }
    END { if (replaced != 1) exit 65 }
' "$old_root/DEBIAN/control" >"$run_directory/control"
install -m 0644 "$run_directory/control" "$old_root/DEBIAN/control"
dpkg-deb --root-owner-group --build "$old_root" "$old_package" >/dev/null

env DEBIAN_FRONTEND=noninteractive apt-get install --yes --no-install-recommends \
    "$old_package" >/dev/null
test "$(dpkg-query -W -f='${Version}' volparossa)" = "$old_version"
for unit in volparossa-helper.service volparossa-mpquic.service volparossa-agent.service; do
    test "$(systemctl is-enabled "$unit" 2>/dev/null || true)" = disabled
    if systemctl is-active --quiet "$unit"; then exit 1; fi
done
test "$(stat -Lc '%U:%G:%a' /var/lib/volparossa)" = volparossa:volparossa:700
test "$(stat -Lc '%U:%G:%a' /etc/volparossa)" = root:volparossa:750
test "$(stat -Lc '%U:%G:%a' /etc/volparossa/config.yaml)" = root:volparossa:640
test "$(stat -Lc '%U:%G:%a' /run/volparossa/control)" = volparossa:volparossa-users:750
test "$(getent passwd volparossa | awk -F: '{ print $6 ":" $7 }')" \
    = /var/lib/volparossa:/usr/sbin/nologin
test "$(getent passwd volparossa-worker | awk -F: '{ print $6 ":" $7 }')" \
    = /nonexistent:/usr/sbin/nologin
test "$(id -Gn volparossa)" = 'volparossa volparossa-users'
test "$(id -Gn volparossa-worker)" = volparossa-worker

passphrase_file=/var/lib/volparossa/.lifecycle-identity-passphrase
install -o volparossa -g volparossa -m 0600 /dev/null "$passphrase_file"
printf '%s\n' 'disposable-alpha-passphrase-2026' >"$passphrase_file"
runuser -u volparossa -- /usr/bin/volparossa init \
    --passphrase-file "$passphrase_file" >/dev/null
test "$(stat -Lc '%U:%G:%a' /var/lib/volparossa/identity.key)" \
    = volparossa:volparossa:600
identity_before=$(sha256sum /var/lib/volparossa/identity.key | awk '{ print $1 }')

policy_directory=/var/lib/volparossa/lifecycle-policy
runuser -u volparossa -- /usr/bin/volparossa policy bootstrap-local \
    --output-directory "$policy_directory" \
    --allow-domain destination.volparossa.test=tcp:443,udp:443 \
    --lifetime-hours 24 >/dev/null
install -o root -g volparossa -m 0640 "$policy_directory/policy.manifest" \
    /etc/volparossa/policy.manifest
install -o root -g volparossa -m 0640 "$policy_directory/policy-maintainers.json" \
    /etc/volparossa/policy-maintainers.json
rm -rf --one-file-system -- "$policy_directory"
sed 's|^  manifest_path: ""$|  manifest_path: "/etc/volparossa/policy.manifest"|' \
    /etc/volparossa/config.yaml >"$run_directory/config.yaml"
test "$(grep -c '^  manifest_path: "/etc/volparossa/policy.manifest"$' \
    "$run_directory/config.yaml")" -eq 1
install -o root -g volparossa -m 0640 "$run_directory/config.yaml" \
    /etc/volparossa/config.yaml
runuser -u volparossa -- /usr/bin/volparossa config validate >/dev/null

install -d -o root -g root -m 0700 /etc/credstore.encrypted
systemd-creds encrypt --name=identity-passphrase "$passphrase_file" \
    /etc/credstore.encrypted/identity-passphrase >/dev/null
chmod 0600 /etc/credstore.encrypted/identity-passphrase
rm -f -- "$passphrase_file"

/usr/bin/volparossa doctor --json >"$output_directory/doctor-before-upgrade.json"
jq -e 'all(.checks[]; .status != "fail")' \
    "$output_directory/doctor-before-upgrade.json" >/dev/null
/usr/bin/volparossa start

wait_active() {
    service=$1
    attempt=0
    while [ "$attempt" -lt 100 ]; do
        if systemctl is-active --quiet "$service"; then return 0; fi
        sleep 0.1
        attempt=$((attempt + 1))
    done
    systemctl status --no-pager "$service" >&2 || true
    return 1
}

services='volparossa-helper.service volparossa-mpquic.service volparossa-agent.service'
for unit in $services; do wait_active "$unit"; done
/usr/bin/volparossa status >/dev/null

before_pids=
for unit in $services; do
    pid=$(systemctl show --property=MainPID --value "$unit")
    case $pid in ''|0|*[!0-9]*) exit 1 ;; esac
    before_pids="$before_pids $unit:$pid"
done

env DEBIAN_FRONTEND=noninteractive apt-get install --yes --no-install-recommends \
    "$package_path" >/dev/null
test "$(dpkg-query -W -f='${Version}' volparossa)" = "$package_version"
for unit in $services; do
    wait_active "$unit"
    old_pid=$(printf '%s\n' "$before_pids" | awk -v unit="$unit" '
        { for (i = 1; i <= NF; i++) if ($i ~ ("^" unit ":")) { sub("^[^:]*:", "", $i); print $i } }
    ')
    new_pid=$(systemctl show --property=MainPID --value "$unit")
    case $new_pid in ''|0|*[!0-9]*) exit 1 ;; esac
    test "$new_pid" != "$old_pid"
done
test "$(sha256sum /var/lib/volparossa/identity.key | awk '{ print $1 }')" \
    = "$identity_before"
/usr/bin/volparossa status >/dev/null
/usr/bin/volparossa doctor --json >"$output_directory/doctor-after-upgrade.json"
jq -e 'all(.checks[]; .status != "fail")' \
    "$output_directory/doctor-after-upgrade.json" >/dev/null

# Removal itself must stop active services; do not pre-stop them here.
env DEBIAN_FRONTEND=noninteractive apt-get remove --yes volparossa >/dev/null
test "$(dpkg-query -W -f='${db:Status-Abbrev}' volparossa)" = rc
for unit in $services; do
    if systemctl is-active --quiet "$unit"; then exit 1; fi
    test "$(systemctl is-enabled "$unit" 2>/dev/null || true)" = not-found
done
for path in /usr/bin/volparossa /usr/bin/volparossa-agent \
    /usr/libexec/volparossa/volparossa-helper \
    /usr/libexec/volparossa/volparossa-mpquic \
    /usr/lib/systemd/system/volparossa-helper.service \
    /usr/lib/systemd/system/volparossa-mpquic.service \
    /usr/lib/systemd/system/volparossa-agent.service; do
    [ ! -e "$path" ] && [ ! -L "$path" ]
done
test "$(sha256sum /var/lib/volparossa/identity.key | awk '{ print $1 }')" \
    = "$identity_before"
test -f /etc/volparossa/config.yaml

snapshot_network "$network_after"
cmp -s "$network_before" "$network_after"

jq -n \
    --arg package_sha256 "$package_sha256" \
    --arg package_version "$package_version" \
    '{
        schema_version: 1,
        environment: {debian_version: "13", architecture: "amd64", virtualization: "kvm"},
        package: {version: $package_version, sha256: $package_sha256},
        fresh_install: {services_enabled: false, filesystem_contract: true},
        doctor_before_upgrade: true,
        service_start: {helper: true, native_mpquic: true, agent: true, live_status: true},
        upgrade: {maintainer_path_exercised: true, active_processes_restarted: true, identity_preserved: true},
        doctor_after_upgrade: true,
        uninstall: {active_services_stopped: true, package_files_absent: true, identity_preserved: true, config_preserved: true},
        network_state_unchanged: true,
        overall: "PASS"
    }' >"$output_directory/package-lifecycle.json"

rm -f -- /etc/credstore.encrypted/identity-passphrase
finished=yes
printf 'PASS: Debian 13 package lifecycle evidence: %s\n' \
    "$output_directory/package-lifecycle.json"
