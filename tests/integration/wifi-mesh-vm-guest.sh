#!/bin/sh
# SPDX-License-Identifier: GPL-3.0-only
# Called only by the existing pinned-image disposable KVM driver as its unprivileged guest user.
set -eu
export LC_ALL=C
umask 077

revision=$1
case $revision in ''|*[!0-9a-f]*) exit 64 ;; esac
[ "${#revision}" -eq 40 ] || [ "${#revision}" -eq 64 ] || exit 64
[ "$(id -un)" = vpci ]
[ "$(hostname)" = volparossa-alpha ]
[ "$(systemd-detect-virt)" = kvm ]
# shellcheck source=/dev/null
[ "$(. /etc/os-release; printf '%s:%s' "$ID" "$VERSION_ID")" = debian:13 ]
[ "$(pwd -P)" = /home/vpci/source ]

kernel=6.12.107+deb13-amd64
package=linux-image-6.12.107+deb13-amd64
version=6.12.107-1
sha256=7794643cf4560de2a7e3b069e8ca8511ad2a568d652ea285f0fe051f79bc9e99
if [ "$(uname -r)" != "$kernel" ]; then
    printf '%s\n' 'Disposable guest only: install exact signed Debian generic kernel for hwsim; reboot once.'
    test ! -e /home/vpci/wifi-mesh-kernel-prepared
    sudo -n env DEBIAN_FRONTEND=noninteractive apt-get update
    kernel_work=$(mktemp -d /home/vpci/wifi-mesh-kernel.XXXXXX)
    cd "$kernel_work"
    apt-get download "$package=$version"
    set -- "$kernel_work"/*.deb
    [ "$#" -eq 1 ] && [ -f "$1" ] && [ ! -L "$1" ]
    printf '%s  %s\n' "$sha256" "$1" | sha256sum --check --strict -
    [ "$(dpkg-deb -f "$1" Package)" = "$package" ]
    [ "$(dpkg-deb -f "$1" Version)" = "$version" ]
    sudo -n env DEBIAN_FRONTEND=noninteractive apt-get install --yes --no-install-recommends "$1"
    test -f "/boot/vmlinuz-$kernel"
    grep -Fx 'CONFIG_MAC80211_HWSIM=m' "/boot/config-$kernel"
    grep -Fx 'CONFIG_MAC80211_MESH=y' "/boot/config-$kernel"
    # Select the exact installed entry for the single next boot, not an arbitrary newer kernel.
    sudo -n grub-reboot "Advanced options for Debian GNU/Linux>Debian GNU/Linux, with Linux $kernel"
    printf '%s\n' "$kernel" >/home/vpci/wifi-mesh-kernel-prepared
    exit 194
fi

sudo -n env DEBIAN_FRONTEND=noninteractive apt-get update
sudo -n env DEBIAN_FRONTEND=noninteractive apt-get install --yes --no-install-recommends \
    build-essential ca-certificates cargo cmake git iproute2 iw jq kmod nftables pkg-config python3 rustc
CARGO_TARGET_DIR=/home/vpci/target cargo test --locked -p volparossa-helper --lib \
    --no-run --message-format=json >/home/vpci/wifi-mesh-build.jsonl 2>/home/vpci/wifi-mesh-build.stderr || {
        tail -c 131072 /home/vpci/wifi-mesh-build.stderr >&2
        exit 1
    }
test_binary=$(jq -sr '[.[] | select(.reason == "compiler-artifact" and .target.name == "volparossa_helper" and .profile.test == true) | .executable | select(. != null)] | unique | if length == 1 then .[0] else error("one exact helper test binary required") end' /home/vpci/wifi-mesh-build.jsonl)
mkdir /home/vpci/alpha-output
set +e
# Redirects intentionally belong to the unprivileged guest user that created alpha-output.
# shellcheck disable=SC2024
sudo -n -- sh ./tests/integration/wifi-mesh-smoke.sh --execute --yes \
    --test-binary "$test_binary" --output /home/vpci/alpha-output --expected-commit "$revision" \
    >/home/vpci/alpha-output/runner.stdout 2>/home/vpci/alpha-output/runner.stderr
status=$?
set -e
printf '%s\n' "$status" >/home/vpci/alpha-output/guest-exit-status
sudo -n chown -R vpci:vpci /home/vpci/alpha-output
find /home/vpci/alpha-output -type d -exec chmod 0700 {} +
find /home/vpci/alpha-output -type f -exec chmod 0600 {} +
tar -C /home/vpci/alpha-output -czf /home/vpci/alpha-output.tar.gz .
exit "$status"
