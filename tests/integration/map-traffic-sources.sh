#!/bin/sh
# SPDX-License-Identifier: GPL-3.0-only
# Bind only the four public Map files this guest executes or reads.
set -eu
umask 077
revision=f965604d365f87612caa6686e50b3705313a0ddc
root=$2
case $1 in download) [ "$(id -u)" != 0 ]; mkdir -m 0700 -- "$root" ;; verify) ;; *) exit 64 ;; esac
while read -r digest path; do
    file=$root/${path##*/}
    if [ "$1" = download ]; then
        curl --fail --silent --show-error --proto '=https' --max-filesize 65536 --max-time 40 \
            "https://raw.githubusercontent.com/VOLPAROSSA/volparossa-map/$revision/$path" -o "$file"
    fi
    [ -f "$file" ] && [ ! -L "$file" ] && [ "$(stat -c %h "$file")" = 1 ]
    printf '%s  %s\n' "$digest" "$file" | sha256sum --check --status --strict -
done <<'INPUTS'
c5155399c55d6bd6df545b80fa8a5ac5322aaaa29110ce225cfedd30c246e43b src/core_traffic.py
c720bd8afaa74293891d9896fc74f0e5f65fb34ff07dd6bd024a49870b5b6ce1 src/traffic_snapshot.py
ca5c9182e581f424121ae38480bf97c660c3a0dacd800163433f9f2eaf946eab tests/peer-traffic/trial.py
15ed165796e598bdf617f8f12d648091d3ea74b9f8821ccef38194941e08696a tests/peer-traffic/synthetic-dataset.json
INPUTS
printf '%s\n' "$revision"
