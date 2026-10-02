#!/bin/sh
# SPDX-License-Identifier: GPL-3.0-only
# Debian-13-only worker dependency. Never install packages or start services.
set -eu
usage() {
    printf '%s\n' \
        'usage: packaging/build-private-dns-worker-deb.sh [--preview|--build]' \
        'Builds only the source-built private DNS worker companion for Debian 13 amd64.' \
        'Requires provisioned CMake, C compiler, pkg-config, libunbound-dev >= 1.26.1 and dns-root-data.' \
        'Writes native/volparossa-dns-worker/build/, dist/, and one disposable staging directory.' \
        'Does not install dependencies, activate participation, start a resolver or change networking.'
}
mode=${1:---preview}
[ "$#" -le 1 ] || { usage >&2; exit 64; }
case $mode in --preview) usage; exit 0 ;; --build) usage ;; *) usage >&2; exit 64 ;; esac
[ "$(id -u)" -ne 0 ] || { printf '%s\n' 'Refusing a root package build.' >&2; exit 77; }
# shellcheck source=/dev/null
[ "$(. /etc/os-release; printf '%s:%s' "$ID" "$VERSION_ID")" = debian:13 ] || exit 77
[ "$(dpkg --print-architecture)" = amd64 ] || exit 77
for tool in cmake cc pkg-config dpkg-deb sha256sum install mktemp find touch sed head; do
    command -v "$tool" >/dev/null 2>&1 || { printf 'Missing build tool: %s\n' "$tool" >&2; exit 69; }
done
pkg-config --atleast-version=1.26.1 libunbound || {
    printf '%s\n' 'Provision libunbound-dev >= 1.26.1 explicitly; no dependency is installed by this builder.' >&2
    exit 77
}
[ -r /usr/share/dns/root.key ] && [ -r /usr/share/dns/root.hints ] || exit 77
root=$(CDPATH='' cd -- "$(dirname -- "$0")/.." && pwd -P)
version=$(sed -n 's/^version = "\([^"]*\)"/\1/p' "$root/Cargo.toml" | head -n 1)
case $version in ''|*[!0-9.]*) exit 65 ;; esac
epoch=${SOURCE_DATE_EPOCH:-0}
case $epoch in ''|*[!0-9]*) exit 65 ;; esac
export LC_ALL=C TZ=UTC SOURCE_DATE_EPOCH="$epoch"
package=$root/dist/volparossa-private-dns-worker_${version}_amd64.deb
[ ! -e "$package" ] && [ ! -L "$package" ] || exit 73
cmake -S "$root/native/volparossa-dns-worker" -B "$root/native/volparossa-dns-worker/build" \
    -UUNBOUND_INCLUDE_DIR -UUNBOUND_LIBRARY -DCMAKE_BUILD_TYPE=Release -DCMAKE_SKIP_RPATH=ON
cmake --build "$root/native/volparossa-dns-worker/build" --parallel 2
staging=$(mktemp -d -t volparossa-private-dns.XXXXXX)
case $staging in /tmp/volparossa-private-dns.*|/var/tmp/volparossa-private-dns.*) ;; *) exit 1 ;; esac
cleanup() { rm -rf -- "$staging"; }
trap cleanup EXIT
trap 'exit 130' HUP INT TERM
install -d "$staging/DEBIAN" "$staging/usr/libexec" "$staging/usr/share/doc/volparossa-private-dns-worker"
install -m 0755 "$root/native/volparossa-dns-worker/build/volparossa-dns-worker" "$staging/usr/libexec/volparossa-dns-worker"
install -m 0644 "$root/LICENSE" "$staging/usr/share/doc/volparossa-private-dns-worker/copyright"
install -m 0644 "$root/THIRD_PARTY_LICENSES.md" "$root/docs/network/UNBOUND_FALLBACK.md" \
    "$staging/usr/share/doc/volparossa-private-dns-worker/"
printf '%s\n' \
    'Package: volparossa-private-dns-worker' "Version: $version" 'Architecture: amd64' \
    'Section: net' 'Priority: optional' 'Maintainer: VOLPAROSSA contributors' \
    'Depends: libunbound8 (>= 1.26.1), dns-root-data' \
    'Description: private libunbound worker for VOLPAROSSA' \
    ' Typed inherited-pipe resolver; no listening DNS service or automatic activation.' >"$staging/DEBIAN/control"
find "$staging" -exec touch -h -d "@$epoch" {} +
install -d "$root/dist"
dpkg-deb --root-owner-group --build --uniform-compression -Zxz "$staging" "$package"
sha256sum "$package"
