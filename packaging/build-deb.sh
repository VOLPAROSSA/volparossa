#!/bin/sh
# SPDX-License-Identifier: GPL-3.0-only
# Build a deterministic candidate binary package without installing or changing host networking.
set -eu
umask 022

mode=preview
usage() {
    printf '%s\n' \
        'usage: packaging/build-deb.sh [--preview|--build]' \
        '' \
        'Preview is the non-writing default. --build performs the explicit non-root build.'
}

case "$#" in
    0) ;;
    1)
        case "$1" in
            --preview) mode=preview ;;
            --build) mode=build ;;
            -h|--help) usage; exit 0 ;;
            *) usage >&2; exit 64 ;;
        esac
        ;;
    *) usage >&2; exit 64 ;;
esac

export LC_ALL=C
export TZ=UTC

script_directory=$(CDPATH='' cd -- "$(dirname -- "$0")" && pwd)
repository_directory=$(CDPATH='' cd -- "$script_directory/.." && pwd)
native_launcher=$script_directory/volparossa-mpquic-launch

for command_name in awk cargo dpkg-deb du find head install jq md5sum mktemp rm sed sha256sum sort touch xargs; do
    if ! command -v "$command_name" >/dev/null 2>&1; then
        printf 'Required packaging command is missing: %s\n' "$command_name" >&2
        exit 1
    fi
done

version=$(sed -n 's/^version = "\([^"]*\)"/\1/p' "$repository_directory/Cargo.toml" | head -n 1)
if [ -z "$version" ]; then
    printf '%s\n' 'Cannot determine workspace version from Cargo.toml.' >&2
    exit 1
fi

architecture=amd64
if command -v dpkg >/dev/null 2>&1 && [ "$(dpkg --print-architecture)" != "$architecture" ]; then
    printf '%s\n' 'This package target is Debian amd64; cross-packaging is not supported by this script.' >&2
    exit 1
fi

source_date_epoch=${SOURCE_DATE_EPOCH:-}
if [ -z "$source_date_epoch" ] && command -v git >/dev/null 2>&1; then
    source_date_epoch=$(git -C "$repository_directory" log -1 --format=%ct 2>/dev/null || true)
fi
source_date_epoch=${source_date_epoch:-0}
case "$source_date_epoch" in
    ''|*[!0-9]*) printf '%s\n' 'SOURCE_DATE_EPOCH must be a non-negative integer.' >&2; exit 1 ;;
esac
export SOURCE_DATE_EPOCH="$source_date_epoch"

printf '%s\n' \
    "VOLPAROSSA Debian package plan for version $version on $architecture." \
    "SOURCE_DATE_EPOCH=$SOURCE_DATE_EPOCH" \
    '  cargo build --locked --release --workspace --all-features' \
    '  native/volparossa-mpquic/scripts/build-upstream.sh' \
    '  stage fixed binaries, configuration, units, notices, and resolved Cargo licenses' \
    "  dpkg-deb -> dist/volparossa_${version}_${architecture}.deb" \
    'Writes, when --build is explicit: the Cargo target directory, native build output, dist/, and one validated temporary directory.' \
    'Never installs a package or service and never changes networking.'
if [ -x "$native_launcher" ]; then
    printf '%s\n' 'Native launcher prerequisite: READY.'
else
    printf '%s\n' 'BLOCKER: packaging/volparossa-mpquic-launch is absent; --build will refuse before compiling.'
    printf '%s\n' \
        'The launcher must orchestrate separate role service identities and control sockets' \
        'with the agent. It remains blocked until trusted helper origin for' \
        'request-bound route UDP FDs and exit' \
        'listener and in-memory TLS identity are wired end to end.' \
        'API-v6 session secrets arrive over the control socket, never through' \
        'launcher argv, environment, or files.'
fi

if [ "$mode" = preview ]; then
    printf '%s\n' 'PREVIEW ONLY: no build or package output was written.'
    exit 0
fi
if [ ! -x "$native_launcher" ]; then
    printf 'BLOCKED: reviewed native launcher is absent: %s\n' "$native_launcher" >&2
    printf '%s\n' 'No build or package output was written.' >&2
    exit 77
fi
if [ "$(id -u)" -eq 0 ]; then
    printf '%s\n' 'Refusing to build the candidate package as root; use an ordinary workspace user.' >&2
    exit 77
fi

cd "$repository_directory"
cargo_target_directory=$(cargo metadata --locked --offline --no-deps --format-version 1 | \
    jq -er '.target_directory | select(type == "string" and startswith("/"))')
if [ -z "$cargo_target_directory" ]; then
    printf '%s\n' 'Cargo did not report one absolute target directory.' >&2
    exit 1
fi
release_directory=$cargo_target_directory/release
cargo build --locked --release --workspace --all-features

for binary_name in volparossa volparossa-agent volparossa-helper; do
    if [ ! -x "$release_directory/$binary_name" ]; then
        printf 'Required release binary is missing: %s/%s\n' \
            "$release_directory" "$binary_name" >&2
        exit 1
    fi
done
"$repository_directory/native/volparossa-mpquic/scripts/build-upstream.sh"
native_binary=$repository_directory/native/volparossa-mpquic/build/volparossa-mpquic
if [ ! -x "$native_binary" ]; then
    printf 'Required native executable is missing: %s\n' "$native_binary" >&2
    exit 1
fi

staging_parent=$(mktemp -d -t volparossa-deb.XXXXXX)
case "$staging_parent" in
    /tmp/volparossa-deb.*|/var/tmp/volparossa-deb.*) ;;
    *) printf 'Unexpected temporary path: %s\n' "$staging_parent" >&2; exit 1 ;;
esac
cleanup_staging() {
    rm -rf -- "$staging_parent"
}
trap cleanup_staging EXIT
trap 'exit 130' HUP INT TERM

package_root=$staging_parent/root
install -d \
    "$package_root/DEBIAN" \
    "$package_root/etc/volparossa" \
    "$package_root/usr/bin" \
    "$package_root/usr/libexec/volparossa" \
    "$package_root/usr/lib/systemd/system" \
    "$package_root/usr/lib/sysusers.d" \
    "$package_root/usr/lib/tmpfiles.d" \
    "$package_root/usr/share/doc/volparossa" \
    "$package_root/usr/share/doc/volparossa/native-licenses"

install -m 0755 "$release_directory/volparossa" "$package_root/usr/bin/volparossa"
install -m 0755 "$release_directory/volparossa-agent" "$package_root/usr/bin/volparossa-agent"
install -m 0755 "$release_directory/volparossa-helper" \
    "$package_root/usr/libexec/volparossa/volparossa-helper"
install -m 0755 "$native_binary" "$package_root/usr/libexec/volparossa/volparossa-mpquic"
install -m 0755 "$native_launcher" "$package_root/usr/libexec/volparossa/volparossa-mpquic-launch"
install -m 0640 config/examples/default.yaml "$package_root/etc/volparossa/config.yaml"

for unit_name in volparossa-helper.service volparossa-mpquic.service volparossa-agent.service; do
    install -m 0644 "$script_directory/systemd/$unit_name" \
        "$package_root/usr/lib/systemd/system/$unit_name"
done
install -m 0644 "$script_directory/systemd/volparossa.sysusers" \
    "$package_root/usr/lib/sysusers.d/volparossa.conf"
install -m 0644 "$script_directory/systemd/volparossa.tmpfiles" \
    "$package_root/usr/lib/tmpfiles.d/volparossa.conf"

for document_name in README.md LICENSE THIRD_PARTY_LICENSES.md SECURITY.md; do
    install -m 0644 "$repository_directory/$document_name" \
        "$package_root/usr/share/doc/volparossa/$document_name"
done
install -m 0644 docs/OPERATIONS.md "$package_root/usr/share/doc/volparossa/OPERATIONS.md"
install -m 0644 docs/PRIVACY.md "$package_root/usr/share/doc/volparossa/PRIVACY.md"
install -m 0644 "$script_directory/debian/copyright" \
    "$package_root/usr/share/doc/volparossa/copyright"

for native_notice in "$repository_directory"/third_party/licenses/*.txt; do
    if [ ! -f "$native_notice" ]; then
        printf '%s\n' 'Locked native license inventory is absent.' >&2
        exit 1
    fi
    install -m 0644 "$native_notice" \
        "$package_root/usr/share/doc/volparossa/native-licenses/${native_notice##*/}"
done


metadata_file=$staging_parent/cargo-metadata.json
release_packages=$staging_parent/release-packages.txt
cargo tree --locked --offline --workspace --all-features \
    --target x86_64-unknown-linux-gnu --prefix none --format '{p}' \
    | sed -E 's/ \([^)]*\)$//' | LC_ALL=C sort -u > "$release_packages"
cargo metadata --locked --offline --filter-platform x86_64-unknown-linux-gnu \
    --format-version 1 \
    | jq --rawfile release_packages "$release_packages" '
        .packages |= map(. as $package
            | select(($release_packages | split("\n"))
                | index($package.name + " v" + $package.version)))
      ' > "$metadata_file"
"$script_directory/collect-cargo-licenses.sh" "$metadata_file" \
    "$package_root/usr/share/doc/volparossa/cargo-licenses"
installed_size=$(du -sk "$package_root/etc" "$package_root/usr" | \
    awk '{ total += $1 } END { print total }')
case "$installed_size" in
    ''|*[!0-9]*) printf '%s\n' 'Cannot determine installed package size.' >&2; exit 1 ;;
esac
sed -e "s/@VERSION@/$version/g" \
    -e "s/@ARCHITECTURE@/$architecture/g" \
    -e "s/@INSTALLED_SIZE@/$installed_size/g" \
    "$script_directory/debian/control.binary.in" > "$package_root/DEBIAN/control"
install -m 0644 "$script_directory/debian/conffiles" "$package_root/DEBIAN/conffiles"
for maintainer_script in postinst prerm postrm; do
    install -m 0755 "$script_directory/debian/$maintainer_script" \
        "$package_root/DEBIAN/$maintainer_script"
done
(cd "$package_root" && \
    find etc usr -type f -print0 | LC_ALL=C sort -z | \
    xargs -0 -r md5sum) >"$package_root/DEBIAN/md5sums"

find "$package_root" -print -exec touch -h -d "@$SOURCE_DATE_EPOCH" {} +

install -d "$repository_directory/dist"
package_path=$repository_directory/dist/volparossa_${version}_${architecture}.deb
if [ -e "$package_path" ]; then
    printf 'Refusing to overwrite existing package: %s\n' "$package_path" >&2
    printf '%s\n' 'Move the existing candidate aside before a new reproducibility build.' >&2
    exit 73
fi
dpkg-deb --root-owner-group --build --uniform-compression -Zxz "$package_root" "$package_path"
sha256sum "$package_path"
printf 'Candidate package created: %s\n' "$package_path"
