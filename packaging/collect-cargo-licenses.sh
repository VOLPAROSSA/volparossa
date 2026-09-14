#!/bin/sh
# SPDX-License-Identifier: GPL-3.0-only
# Copy the exact resolved crates' top-level license/notice files into a binary package staging tree.
set -eu

export LC_ALL=C

repository_root=$(CDPATH='' cd -- "$(dirname -- "$0")/.." && pwd)

if [ "$#" -ne 2 ]; then
    printf '%s\n' 'Usage: packaging/collect-cargo-licenses.sh METADATA.json DESTINATION' >&2
    exit 2
fi

metadata_file=$1
destination=$2

if ! command -v jq >/dev/null 2>&1; then
    printf '%s\n' 'jq is required to collect locked dependency licenses.' >&2
    exit 1
fi
if [ ! -r "$metadata_file" ]; then
    printf '%s\n' 'Cargo metadata file is unreadable.' >&2
    exit 1
fi

"$repository_root/scripts/check-rust-dependencies.sh" --verify-vendor-only

install -d "$destination"
summary=$destination/DEPENDENCIES.tsv
printf 'name\tversion\tlicense-expression\tsource\n' > "$summary"
package_list=$destination/.packages.tsv

jq -er '
    .workspace_members as $workspace_members
    | .packages[]
    | . as $package
    | select(($workspace_members | index($package.id)) == null)
    | [.name, .version, (.license // "NOASSERTION"), (.license_file // "-"),
       .manifest_path, (.source // "path")]
    | @tsv
' "$metadata_file" | LC_ALL=C sort > "$package_list"
if [ ! -s "$package_list" ]; then
    printf '%s\n' 'Cargo metadata contained no resolved third-party packages.' >&2
    exit 1
fi
while IFS="	" read -r crate_name crate_version license_expression license_file manifest_path source; do
    case "$crate_name:$crate_version" in
        *[!A-Za-z0-9_.:+-]*)
            printf 'Unsafe Cargo package identifier: %s %s\n' "$crate_name" "$crate_version" >&2
            exit 1
            ;;
    esac

    source_label=$source
    case "$source" in
        registry+https://github.com/rust-lang/crates.io-index*) ;;
        path)
            case "$manifest_path" in
                "$repository_root/third_party/rust/vendor/hickory-proto-0.25.2/Cargo.toml")
                    source_label='vendored-crates.io+hickory-proto-0.25.2-security-backport'
                    ;;
                "$repository_root/third_party/rust/vendor/time-0.3.41/Cargo.toml")
                    source_label='vendored-crates.io+time-0.3.41-security-backport'
                    ;;
                "$repository_root/third_party/rust/vendor/libp2p-yamux-0.47.0/Cargo.toml")
                    source_label='vendored-crates.io+libp2p-yamux-0.47.0-single-backend'
                    ;;
                *)
                    printf 'Unapproved non-workspace Cargo path dependency: %s\n' "$manifest_path" >&2
                    exit 1
                    ;;
            esac
            ;;
        *) printf 'Unapproved Cargo source in package metadata: %s\n' "$source" >&2; exit 1 ;;
    esac

    crate_directory=$(dirname -- "$manifest_path")
    crate_destination=$destination/$crate_name-$crate_version
    install -d "$crate_destination"
    copied=0

    if [ "$license_file" != - ]; then
        case "$license_file" in
            /*) resolved_license=$license_file ;;
            *) resolved_license=$crate_directory/$license_file ;;
        esac
        if [ -f "$resolved_license" ]; then
            install -m 0644 "$resolved_license" "$crate_destination/$(basename -- "$resolved_license")"
            copied=1
        fi
    fi

    for pattern in LICENSE LICENSE-* LICENSE.* COPYING COPYING-* COPYING.* NOTICE NOTICE-* NOTICE.*; do
        for notice_path in "$crate_directory"/$pattern; do
            [ -f "$notice_path" ] || continue
            notice_name=$(basename -- "$notice_path")
            install -m 0644 "$notice_path" "$crate_destination/$notice_name"
            copied=1
        done
    done

    if [ "$copied" -ne 1 ] &&
        [ "$crate_name" = yamux ] &&
        [ "$crate_version" = 0.13.10 ] &&
        [ "$license_expression" = 'Apache-2.0 OR MIT' ] &&
        [ "$source" = 'registry+https://github.com/rust-lang/crates.io-index' ]
    then
        vcs_info=$crate_directory/.cargo_vcs_info.json
        jq -e \
            '.git.sha1 == "38e9944f8fbb723a3a4df575cfb15109efcb2d24" and
             .path_in_vcs == "yamux"' \
            "$vcs_info" >/dev/null 2>&1 || {
                printf '%s\n' 'yamux 0.13.10 has unexpected or missing VCS provenance.' >&2
                exit 1
            }
        install -m 0644 \
            "$repository_root/third_party/rust/licenses/yamux-0.13.10/LICENSE-APACHE" \
            "$crate_destination/LICENSE-APACHE"
        install -m 0644 \
            "$repository_root/third_party/rust/licenses/yamux-0.13.10/LICENSE-MIT" \
            "$crate_destination/LICENSE-MIT"
        copied=1
        source_label='crates.io+yamux-0.13.10;licenses=official-tag-70db05dc63e8368bd0559a5ec0dba6e5fc2bdd41'
    fi

    if [ "$copied" -ne 1 ]; then
        fallback_table=$repository_root/third_party/rust/licenses/registry-fallbacks.tsv
        fallback=$(awk -F '\t' -v name="$crate_name" -v version="$crate_version" \
            -v license="$license_expression" '
            $1 == name && $2 == version && $3 == license { print; found++ }
            END { if (found != 1) exit 1 }
        ' "$fallback_table") || fallback=
        if [ -n "$fallback" ]; then
            fallback_sha=$(printf '%s\n' "$fallback" | cut -f 4)
            fallback_directory=$(printf '%s\n' "$fallback" | cut -f 5)
            vcs_info=$crate_directory/.cargo_vcs_info.json
            jq -e --arg sha "$fallback_sha" '.git.sha1 == $sha' "$vcs_info" \
                >/dev/null 2>&1 || {
                printf '%s %s has unexpected or missing VCS provenance.\n' \
                    "$crate_name" "$crate_version" >&2
                exit 1
            }
            if [ "$fallback_directory" != - ]; then
                fallback_root=$repository_root/third_party/rust/licenses/registry-fallback/$fallback_directory
                [ -d "$fallback_root" ] || {
                    printf 'Reviewed license fallback is absent: %s %s\n' \
                        "$crate_name" "$crate_version" >&2
                    exit 1
                }
                if [ ! -f "$fallback_root/SHA256SUMS" ] \
                    || ! (cd "$fallback_root" && sha256sum -c SHA256SUMS >/dev/null); then
                    printf 'Reviewed license fallback hash failed: %s %s\n' \
                        "$crate_name" "$crate_version" >&2
                    exit 1
                fi
                fallback_copied=0
                for fallback_path in "$fallback_root"/*; do
                    [ -f "$fallback_path" ] || continue
                    [ "${fallback_path##*/}" != SHA256SUMS ] || continue
                    install -m 0644 "$fallback_path" \
                        "$crate_destination/$(basename -- "$fallback_path")"
                    fallback_copied=1
                done
                [ "$fallback_copied" -eq 1 ] || {
                    printf 'Reviewed license fallback is empty: %s %s\n' \
                        "$crate_name" "$crate_version" >&2
                    exit 1
                }
            fi
            copied=1
            source_label="crates.io+vcs-license-$fallback_sha"
        fi
    fi

    if [ "$copied" -ne 1 ]; then
        printf 'Resolved crate has no distributable top-level license/notice file: %s %s (%s)\n' \
            "$crate_name" "$crate_version" "$license_expression" >&2
        exit 1
    fi
    printf '%s\t%s\t%s\t%s\n' "$crate_name" "$crate_version" "$license_expression" "$source_label" \
        >> "$summary"
done < "$package_list"
rm -f -- "$package_list"
