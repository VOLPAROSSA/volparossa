#!/usr/bin/env bash
# SPDX-License-Identifier: GPL-3.0-only
# Temporary policy for this explicit disposable Ubuntu CI source build only.
set -euo pipefail
test "${GITHUB_ACTIONS:-}" = true
test "${RUNNER_OS:-}" = Linux
test "${VOLPAROSSA_ALPHA_SCENARIO:-}" = agent-native-coding
test "$(id -u)" -ne 0
test "$#" -eq 1
[[ "$1" =~ ^[0-9a-f]{40}$ ]]
# shellcheck source=/dev/null
. /etc/os-release
test "$ID" = ubuntu && test "$VERSION_ID" = 24.04
here=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)
profile="$here/native-coding-bwrap.apparmor"
staged=/run/volparossa-native-coding.apparmor
parser=/usr/sbin/apparmor_parser
test -x "$parser"
test ! -e "$staged" && test ! -L "$staged"
test "$(dpkg-query -S /usr/bin/bwrap)" = 'bubblewrap: /usr/bin/bwrap'
test -z "$(dpkg --verify bubblewrap)"
python3 -I - <<'PY'
import os, stat
from pathlib import Path
p = Path('/usr/bin/bwrap')
s = p.lstat()
assert p.resolve() == p and stat.S_ISREG(s.st_mode) and s.st_uid == 0
assert s.st_mode & 0o6022 == 0 and s.st_mode & 0o111
assert 'security.capability' not in os.listxattr(p)
PY
dpkg-query -W -f='${Package} ${Version}\n' apparmor bubblewrap
inventory=$(sudo -n cat /sys/kernel/security/apparmor/profiles)
if grep -Eq 'bwrap|volparossa_ci_native' <<<"$inventory"; then
  printf '%s\n' 'Existing bwrap policy found; refusing to replace or override it.' >&2
  exit 1
fi
restriction=$(< /proc/sys/kernel/apparmor_restrict_unprivileged_userns)
test "$restriction" = 1
test "$(sha256sum "$profile" | cut -d ' ' -f 1)" = 3f3fefdfc6fe46e882af9b803ddcddd6691083e434b26f5fb244ceddf05b6794
printf '%s\n' 'CI only: add two exact bwrap/child AppArmor profiles, run unprivileged source build, then remove only those profiles. No sysctl, setuid, developer-host or builder changes.'
owned=0
attempted=0
build_pid=
build_status=null
probe=
# Called indirectly by the EXIT trap, including the explicit final exit below.
# shellcheck disable=SC2317
cleanup() {
  result=$?
  cleanup_result=0
  trap - EXIT INT TERM
  if test -n "$build_pid"; then
    kill -TERM -- "-$build_pid" 2>/dev/null || true
    for _ in {1..20}; do
      kill -0 "$build_pid" 2>/dev/null || break
      sleep 0.25
    done
    kill -KILL -- "-$build_pid" 2>/dev/null || true
    wait "$build_pid" 2>/dev/null || true
  fi
  if test "$attempted" = 1; then
    sudo -n "$parser" --remove --skip-cache "$staged" || cleanup_result=1
    remaining=$(sudo -n cat /sys/kernel/security/apparmor/profiles) || cleanup_result=1
    if grep -q volparossa_ci_native <<<"${remaining:-}"; then cleanup_result=1; fi
  fi
  if test "$owned" = 1; then sudo -n rm -- "$staged" || cleanup_result=1; fi
  if test -n "$probe"; then rmdir -- "$probe/source" "$probe" || cleanup_result=1; fi
  test "$(< /proc/sys/kernel/apparmor_restrict_unprivileged_userns)" = "$restriction" || cleanup_result=1
  printf '{"ci_bwrap_cleanup_complete":%s,"source_build_exit_status":%s,"wrapper_exit_status":%s}\n' \
    "$([ "$cleanup_result" = 0 ] && printf true || printf false)" "$build_status" "$result"
  if test "$cleanup_result" != 0; then result=1; fi
  exit "$result"
}
trap 'cleanup' EXIT
trap 'exit 130' INT
trap 'exit 143' TERM
sudo -n install -o root -g root -m 0600 -- "$profile" "$staged"
owned=1
# Add, never replace: pre-existing profile definitions are not ours to modify.
attempted=1
sudo -n "$parser" --add --skip-cache "$staged"
probe=$(mktemp -d "${RUNNER_TEMP:?}/volparossa-bwrap.XXXXXXXX")
mkdir -m 0700 "$probe/source"
for network in online offline; do
  isolation=()
  if test "$network" = offline; then isolation=(--unshare-net); fi
  # Same mount/namespace layout as the unchanged pinned build_codex_runtime.py.
  timeout 20s env -i PATH=/usr/bin:/bin LANG=C.UTF-8 /usr/bin/bwrap \
    --die-with-parent --ro-bind / / --tmpfs /home --tmpfs /root --tmpfs /run --tmpfs /tmp \
    --bind "$probe" "$probe" --ro-bind "$probe/source" "$probe/source" \
    --proc /proc --dev /dev --chdir "$probe/source" "${isolation[@]}" -- \
    /usr/bin/python3 -I -c '
import errno, json, os
from pathlib import Path
import sys
s = dict(line.split(":", 1) for line in Path("/proc/self/status").read_text().splitlines() if ":" in line)
assert os.getuid() == int(sys.argv[1]) != 0
assert int(s["CapEff"], 16) == int(s["CapPrm"], 16) == 0
assert int(s["NoNewPrivs"]) == 1
assert "volparossa_ci_native_child" in Path("/proc/self/attr/current").read_text()
assert not list(Path("/root").iterdir()) and not list(Path("/run").iterdir())
try:
    os.open("forbidden-write", os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
except OSError as error:
    assert error.errno == errno.EROFS
else:
    raise AssertionError("source mount unexpectedly writable")
if sys.argv[2] == "offline":
    assert os.readlink("/proc/self/ns/net") != sys.argv[3]
print(json.dumps({"ci_bwrap_preflight": True, "mode": sys.argv[2], "capabilities": 0, "no_new_privs": True}))
' "$(id -u)" "$network" "$(readlink /proc/self/ns/net)"
done
setsid python3 -B "$here/native-coding-runtime.py" build --yes --expected-commit "$1" &
build_pid=$!
if wait "$build_pid"; then build_status=0; else build_status=$?; fi
build_pid=
exit "$build_status"
