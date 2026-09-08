#!/bin/sh
# SPDX-License-Identifier: GPL-3.0-only
# Explicit installed-Firefox smoke; no browser/dependency installation or host network writes.
set -eu

[ "$#" -eq 2 ] || { echo 'usage: site-browser-smoke.sh ABSOLUTE_TEST_BINARY NEW_PRIVATE_EVIDENCE_DIRECTORY' >&2; exit 2; }
site_binary=$(realpath -e -- "$1")
site_evidence=$(realpath -e -- "$2")
[ -f "$site_binary" ] && [ -x "$site_binary" ] || exit 2
[ -d "$site_evidence" ] && [ ! -L "$2" ] || exit 2
[ "$(stat -c %u -- "$site_evidence")" = "$(id -u)" ] || exit 2
[ "$(stat -c %a -- "$site_evidence")" = 700 ] || exit 2
[ -z "$(find "$site_evidence" -mindepth 1 -maxdepth 1 -print -quit)" ] || exit 2
site_parent_netns=$(/usr/bin/readlink /proc/self/ns/net)
printf '%s\n' 'Browser smoke: disposable user/net/PID/IPC namespaces; only their loopback is enabled.'
printf '%s\n' 'Host mounts read-only; private /run and /tmp; only the named evidence directory is writable.'
printf 'Evidence directory: %s\n' "$site_evidence"
printf '%s\n' 'All capabilities are dropped before the real CLI/browser test; namespace destruction reaps children.'

# Setup runs in an anonymous namespace, under a nonzero mapped UID so Firefox can create
# its own child sandbox without the kernel's parent-UID-zero mapping restriction. The
# nested read-only mount sandbox drops all capabilities before the test starts.
# shellcheck disable=SC2016
exec /usr/bin/timeout --kill-after=5s 90s /usr/bin/unshare \
    --user --map-user=987 --map-group=987 --keep-caps --net --pid --fork --kill-child=KILL \
    -- /bin/sh -c '/usr/bin/ip link set dev lo up && exec /usr/bin/setpriv --inh-caps=-all --ambient-caps=-all --bounding-set=-all --no-new-privs -- "$@"' isolated-site-setup \
    /usr/bin/bwrap --unshare-user --uid 987 --gid 987 --unshare-pid --unshare-ipc \
    --die-with-parent --new-session --ro-bind / / --dev /dev --proc /proc \
    --tmpfs /run --tmpfs /tmp --bind "$site_evidence" /tmp/vp \
    --cap-drop ALL \
    --setenv TMPDIR /tmp/vp \
    --setenv VOLPAROSSA_HANDOFF_TEST_PARENT_NETNS "$site_parent_netns" \
    --setenv VOLPAROSSA_SITE_BROWSER_ARTIFACT /tmp/vp/site.png \
    --unsetenv DBUS_SESSION_BUS_ADDRESS --unsetenv XAUTHORITY \
    --unsetenv DISPLAY --unsetenv WAYLAND_DISPLAY \
    -- /usr/bin/setpriv --no-new-privs -- "$site_binary" \
    --exact site::site_cli_delivers_signed_html_assets_ranges_and_cleans_up --nocapture
