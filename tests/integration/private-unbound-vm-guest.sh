#!/bin/sh
# SPDX-License-Identifier: GPL-3.0-only
# Extra dns-cache preflight, not normal-route or reciprocal deployment proof.
set -eu
printf '%s\n' \
    'Private DNS preflight: disposable Debian 13 KVM only.' \
    'Installs the two exact SHA-checked libunbound 1.26.1 guest packages and root anchors.' \
    'Builds/installs the fixed native worker; never starts a DNS listener.' \
    'Queries only iana.org, neverssl.com and dnssec-failed.org using genuine recursion.' \
    'Temporarily mounts an OS-positive hosts sentinel in a PRIVATE guest mount namespace.' \
    'Stops only the probe-owned native child through pidfd to verify timeout/cancel reaping.' \
    'No developer-host networking changes; no Client route or reciprocal privacy claim.'
[ "${1:---preview}" = --execute ] || exit 0
[ "$#" -eq 2 ] || exit 64
[ "$(id -u)" -ne 0 ] || exit 77
[ "$(hostname)" = volparossa-alpha ] && [ "$(systemd-detect-virt)" = kvm ] || exit 77
# shellcheck source=/dev/null
[ "$(. /etc/os-release; printf '%s:%s' "$ID" "$VERSION_ID")" = debian:13 ] || exit 77
[ "$(dpkg --print-architecture)" = amd64 ] || exit 77
root=$(CDPATH='' cd -- "$(dirname -- "$0")/../.." && pwd -P)
[ "$root" = /home/vpci/source ] || exit 77
revision=$2
case $revision in *[!0-9a-f]*|'') exit 65 ;; esac
[ "${#revision}" -eq 40 ] || exit 65
mkdir -p "$root/build/private-dns-guest-packages"
cd "$root/build/private-dns-guest-packages"
apt-get download libunbound8=1.26.1-0+deb13u1 libunbound-dev=1.26.1-0+deb13u1
printf '%s\n' \
    '2331c4c305f68aab91dbe16245bd76c0e0edc532353b3ce52accad71d24dfbb3  libunbound8_1.26.1-0+deb13u1_amd64.deb' \
    'e909714ea6d39833cf42e8e48f3dbe68a42147d8853850e7848769d7fd5a3d12  libunbound-dev_1.26.1-0+deb13u1_amd64.deb' \
    | sha256sum --check --strict -
sudo -n env DEBIAN_FRONTEND=noninteractive apt-get install --yes --no-install-recommends \
    ./libunbound8_1.26.1-0+deb13u1_amd64.deb ./libunbound-dev_1.26.1-0+deb13u1_amd64.deb dns-root-data
cd "$root"
cmake -S native/volparossa-dns-worker -B native/volparossa-dns-worker/build \
    -DCMAKE_BUILD_TYPE=Release -DCMAKE_SKIP_RPATH=ON
cmake --build native/volparossa-dns-worker/build --parallel 2
sudo -n install -d /usr/libexec
sudo -n install -m 0755 native/volparossa-dns-worker/build/volparossa-dns-worker /usr/libexec/volparossa-dns-worker
parent_mntns=$(readlink /proc/self/ns/mnt)
sudo -n env VOLPAROSSA_PRIVATE_DNS_PARENT_MNTNS="$parent_mntns" \
    unshare --mount --propagation private -- \
    python3 -B tests/integration/private-unbound-proof.py execute \
    /home/vpci/target/debug/examples/private-unbound-proof /home/vpci/private-unbound-proof.json "$revision"
