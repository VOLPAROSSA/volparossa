#!/bin/sh
# SPDX-License-Identifier: GPL-3.0-only
# Non-mutating contract checks for package lifecycle entry points and maintainer scripts.
set -eu

export LC_ALL=C
repository=$(CDPATH='' cd -- "$(dirname -- "$0")/../.." && pwd -P)
lifecycle=$repository/tests/packaging/debian13-package-lifecycle.sh
temporary=$(mktemp -d /tmp/volparossa-package-contract.XXXXXX)
case $temporary in /tmp/volparossa-package-contract.??????) ;; *) exit 69 ;; esac
cleanup() {
    status=$?
    trap - EXIT HUP INT TERM
    rm -rf --one-file-system -- "$temporary"
    exit "$status"
}
trap cleanup EXIT
trap 'exit 129' HUP
trap 'exit 130' INT
trap 'exit 143' TERM

"$lifecycle" --preview >"$temporary/preview"
grep -F 'PREVIEW ONLY: no package, service, account, file or network state was changed.' \
    "$temporary/preview" >/dev/null
grep -F 'agent_control_socket=/run/volparossa/control/agent.sock' "$lifecycle" >/dev/null
[ "$(grep -Fc 'wait_agent_control_socket' "$lifecycle")" -eq 3 ]
[ "$(grep -Fc -- "--control-socket \"\$agent_control_socket\" status" "$lifecycle")" -eq 1 ]
grep -F '/usr/bin/timeout --signal=KILL 0.2s' "$lifecycle" >/dev/null
grep -F 'volparossa-agent control socket did not become ready' "$lifecycle" >/dev/null

mkdir "$temporary/bin"
log=$temporary/commands
for command in systemd-sysusers systemd-tmpfiles systemctl chown chmod; do
    shim=$temporary/bin/$command
    # shellcheck disable=SC2016
    printf '%s\n' '#!/bin/sh' 'printf "%s %s\\n" "${0##*/}" "$*" >>"$COMMAND_LOG"' \
        'exit 0' >"$shim"
    chmod 0755 "$shim"
done
export COMMAND_LOG="$log"
PATH=$temporary/bin:/usr/bin:/bin
export PATH

: >"$log"
"$repository/packaging/debian/postinst" configure
grep -Fx 'systemd-sysusers /usr/lib/sysusers.d/volparossa.conf' "$log" >/dev/null
grep -Fx 'systemd-tmpfiles --create /usr/lib/tmpfiles.d/volparossa.conf' "$log" >/dev/null
grep -Fx 'systemctl daemon-reload' "$log" >/dev/null
if grep -F 'try-restart' "$log" >/dev/null; then
    printf '%s\n' 'fresh installation unexpectedly restarted a service' >&2
    exit 1
fi

: >"$log"
"$repository/packaging/debian/postinst" configure 0.0.1
grep -Fx 'systemctl try-restart volparossa-helper.service volparossa-mpquic.service volparossa-agent.service' \
    "$log" >/dev/null

: >"$log"
"$repository/packaging/debian/prerm" upgrade 0.1.0
test ! -s "$log"

: >"$log"
"$repository/packaging/debian/prerm" remove
grep -Fx 'systemctl stop volparossa-agent.service volparossa-mpquic.service volparossa-helper.service' \
    "$log" >/dev/null
grep -Fx 'systemctl disable volparossa-agent.service volparossa-mpquic.service volparossa-helper.service' \
    "$log" >/dev/null

printf '%s\n' 'PASS: package lifecycle preview is non-mutating and maintainer actions are bounded.'
