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

    if [ "$copied" -ne 1 ]; then
        printf 'Resolved crate has no distributable top-level license/notice file: %s %s (%s)\n' \
            "$crate_name" "$crate_version" "$license_expression" >&2
        exit 1
    fi
    printf '%s\t%s\t%s\t%s\n' "$crate_name" "$crate_version" "$license_expression" "$source_label" \
        >> "$summary"
done < "$package_list"
rm -f -- "$package_list"
