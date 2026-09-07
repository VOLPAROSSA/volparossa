#!/bin/sh
# SPDX-License-Identifier: GPL-3.0-only
# Boot the pinned Debian 13 image and run the production-helper alpha topology inside KVM.
# shellcheck disable=SC2317
set -eu

export LC_ALL=C
PATH=/usr/sbin:/usr/bin:/sbin:/bin
export PATH
umask 077

mode=preview
approval=no
image_path=
mpquic_path=
package_path=
output_directory=
expected_commit=
scenario=alpha

usage() {
    printf '%s\n' \
        'usage: tests/integration/run-alpha-topology-vm.sh --preview' \
        '       tests/integration/run-alpha-topology-vm.sh --execute --yes' \
        '         --image PATH --mpquic PATH --package PATH --output DIRECTORY' \
        '         --expected-commit SHA [--scenario alpha|datapath|reciprocity|local-link|mixed-link|sharing|download-sharing|wifi-mesh|wifi-link|uplink-link|crash-recovery|content|content-message|content-https|content-provider|content-replication]' \
        '       --package is required only for alpha; --mpquic is unnecessary for wifi-mesh.'
}

print_plan() {
    printf '%s\n' \
        'VOLPAROSSA disposable alpha topology VM plan:' \
        '  verify the reviewed Debian 13 amd64 image by its pinned SHA-512;' \
        '  archive only the exact clean checked-out Git revision;' \
        '  verify/copy pinned mqvpn/xquic when the selected scenario uses it;' \
        '  boot one temporary KVM-only qcow2 overlay with QEMU user networking;' \
        '  install Debian build/runtime packages and build only required test binaries;' \
        '  run the selected production-helper proof as guest root;' \
        '  retrieve bounded non-secret logs and its machine-readable result;' \
        '  power off and discard the overlay, keys, seed and source archive.' \
        'No TAP, bridge, host route, firewall, DNS, sysctl or VPN state is changed.'
    if [ "$scenario" = content-replication ]; then
        printf '%s\n' \
            'Content-replication scenario: Relay4 also consumes P and opportunistically retains unrelated Q;' \
            '  exact two protected relay paths, real physical-interface accounting, fresh private cache;' \
            '  stop the original provider, then Client retrieves Q from Relay4 with independent publisher trust;' \
            '  complete role-specific captures and cleanup; no full C03/C04, browser or speed claim.'
    elif [ "$scenario" = content-provider ]; then
        printf '%s\n' \
            'Content-provider scenario: two of Relay3/4/5 serve disjoint caches, excluding the current control relay;' \
            '  two disposable UDP41000-only broker-provider links with exact route and drained capture evidence;' \
            '  actual generic DHT/control-relay discovery and protected MPTCP reconstruction after publisher removal;' \
            '  exact policy-only DNS destinations, isolated Client files, both provider PeerIds and complete privacy/cleanup;' \
            '  cooperative-origin HTTPS same-object complete/missing-ranges cases; no general NAT/browser HTTPS/full-C02 claim.'
    elif [ "$scenario" = content-https ]; then
        printf '%s\n' \
            'Content-https scenario: genuine application TLS origin metadata, partial peer chunks and origin fallback;' \
            '  all nine streams traverse existing MPTCP/TLS/WireGuard; fixture-only app trust, no interception CA;' \
            '  exact captures/cleanup, no browser, peer-discovery, speed or full-C08 claim.'
    elif [ "$scenario" = content-message ]; then
        printf '%s\n' \
            'Content-message scenario: temporary application-owned 0600 recipient key, ciphertext-only replicas;' \
            '  two real protected fetches, intended-recipient decryption and wrong-recipient rejection;' \
            '  remove temporary key/plaintext and verify unchanged guest; no mailbox/product-key/C07 claim.'
    elif [ "$scenario" = content ]; then
        printf '%s\n' \
            'Content scenario: two disjoint replica processes, publisher removed before retrieval;' \
            '  native signed chunks through the existing protected MPTCP route and exact authorized destination;' \
            '  separate content-network-smoke.json; no HTTPS, node-diversity or full-alpha claim.'
    elif [ "$scenario" = alpha ]; then
        printf '%s\n' \
            'Alpha scenario: verify/copy the exact candidate Debian package and prove' \
            '  install, doctor, start, upgrade and removal inside the guest first.'
    elif [ "$scenario" = crash-recovery ]; then
        printf '%s\n' \
            'Crash-recovery scenario: real held MPTCP application, exact A14 forced crashes and helper restart;' \
            '  A15 unchanged host state and zero owned references; A01-A13 and packaging are not executed.'
    elif [ "$scenario" = wifi-link ]; then
        printf '%s\n' \
            'Wi-Fi link scenario: exact generic guest kernel and two simulated radios; agent-created mesh;' \
            '  mDNS bootstrap, protected consume/GIVE plus retained Ethernet; no physical radio or capacity claim.'
    elif [ "$scenario" = wifi-mesh ]; then
        printf '%s\n' \
            'Wi-Fi mesh scenario: install one exact hash-verified official generic guest kernel and reboot once;' \
            '  real MeshOwner hwsim association, UDP/counters and cleanup, not physical Wi-Fi or full overlay proof.'
    elif [ "$scenario" = mixed-link ]; then
        printf '%s\n' \
            'Mixed-link scenario: real HTTP/3 over genuine two-path MPQUIC through LAN/public Relays;' \
            '  compare bounded WAN-only and LAN+WAN HTTP/3 throughput with exact paths, hashes and cleanup;' \
            '  no physical-radio, arbitrary-link speed or packaging claim.'
    elif [ "$scenario" = download-sharing ]; then
        printf '%s\n' \
            'Download-sharing scenario: exact Relay receive counters plus authenticated adjacent sender budgets;' \
            '  real protected download, same-link owner contention, recovery, privacy and cleanup;' \
            '  separate download-sharing-smoke.json; no upload-sharing or full-alpha evidence substitution.'
    elif [ "$scenario" = sharing ]; then
        printf '%s\n' \
            'Sharing scenario: genuine Exit contribution and owner upload on one shared veth;' \
            '  actual contention, recovery and exact cleanup; no download/radio or packaging claim.'
    elif [ "$scenario" = uplink-link ]; then
        printf '%s\n' \
            'Uplink-link scenario: same-daemon independent egress loss and restoration, actual fallback UDP;' \
            '  exact new contexts, local contribution, packet/privacy and cleanup proof; no packaging claim.'
    elif [ "$scenario" = local-link ]; then
        printf '%s\n' \
            'Local-link scenario: offline RFC1918 consumer, two LAN Relay contacts and WAN Exit;' \
            '  concurrent real consumption and LAN relay contribution, not radio or aggregate capacity; packaging is skipped.'
    elif [ "$scenario" = reciprocity ]; then
        printf '%s\n' \
            'Reciprocity scenario: simultaneous client/relay/exit datapaths;' \
            '  package/release checks are skipped, not reported as passed.'
    else
        printf '%s\n' \
            'Datapath scenario: run the full A01-A15 functional topology;' \
            '  package/release checks are skipped, not reported as passed.'
    fi
}

while [ "$#" -gt 0 ]; do
    case $1 in
        --preview) mode=preview ;;
        --execute) mode=execute ;;
        --yes) approval=yes ;;
        --scenario)
            [ "$#" -ge 2 ] || { usage >&2; exit 64; }
            scenario=$2
            case $scenario in alpha|datapath|reciprocity|local-link|mixed-link|sharing|download-sharing|wifi-mesh|wifi-link|uplink-link|crash-recovery|content|content-message|content-https|content-provider|content-replication) ;; *) usage >&2; exit 64 ;; esac
            shift
            ;;
        --image)
            [ "$#" -ge 2 ] || { usage >&2; exit 64; }
            image_path=$2
            shift
            ;;
        --mpquic)
            [ "$#" -ge 2 ] || { usage >&2; exit 64; }
            mpquic_path=$2
            shift
            ;;
        --package)
            [ "$#" -ge 2 ] || { usage >&2; exit 64; }
            package_path=$2
            shift
            ;;
        --output)
            [ "$#" -ge 2 ] || { usage >&2; exit 64; }
            output_directory=$2
            shift
            ;;
        --expected-commit)
            [ "$#" -ge 2 ] || { usage >&2; exit 64; }
            expected_commit=$2
            shift
            ;;
        -h|--help)
            usage
            exit 0
            ;;
        *)
            usage >&2
            exit 64
            ;;
    esac
    shift
done

if [ "$mode" = preview ]; then
    if [ "$approval" != no ] \
        || [ -n "$image_path$mpquic_path$package_path$output_directory$expected_commit" ]; then
        usage >&2
        exit 64
    fi
    print_plan
    printf '%s\n' 'PREVIEW ONLY: no image, VM, key, file, service or network state was changed.'
    exit 0
fi

if [ "$approval" != yes ] || [ -z "$image_path" ] \
    || [ -z "$output_directory" ] || [ -z "$expected_commit" ]; then
    usage >&2
    exit 64
fi
case $image_path:$output_directory in
    /*:/*) ;;
    *) exit 64 ;;
esac
if [ "$scenario" = alpha ] && [ -z "$package_path" ]; then usage >&2; exit 64; fi
if [ "$scenario" != wifi-mesh ] && [ -z "$mpquic_path" ]; then usage >&2; exit 64; fi
case $mpquic_path in ''|/*) ;; *) exit 64 ;; esac
case $package_path in ''|/*) ;; *) exit 64 ;; esac
case $expected_commit in ''|*[!0-9a-f]*) exit 64 ;; esac
case ${#expected_commit} in 40|64) ;; *) exit 64 ;; esac
[ "$(id -u)" -ne 0 ] || { printf '%s\n' 'VM runner must remain unprivileged' >&2; exit 77; }

for command_name in awk cat chmod cloud-localds cmp cut dpkg-deb find git grep gzip install \
    jq kill mktemp qemu-img qemu-system-x86_64 readlink rm scp sed sha256sum \
    sha512sum sleep ssh ssh-keygen ss stat tail tar timeout; do
    command -v "$command_name" >/dev/null 2>&1 \
        || { printf 'required host tool unavailable: %s\n' "$command_name" >&2; exit 77; }
done
if [ ! -r /dev/kvm ] || [ ! -w /dev/kvm ]; then
    printf '%s\n' 'usable KVM is unavailable' >&2
    exit 77
fi
qemu-system-x86_64 -accel help | grep -Fx kvm >/dev/null \
    || { printf '%s\n' 'QEMU has no KVM accelerator' >&2; exit 77; }

HERE=$(CDPATH='' cd -- "$(dirname -- "$0")" && pwd -P)
REPOSITORY=$(CDPATH='' cd -- "$HERE/../.." && pwd -P)
MANIFEST=$REPOSITORY/tests/helper/debian13-amd64-image-v1.json
IMAGE_FILENAME=debian-13-genericcloud-amd64-20260826-2582.qcow2
IMAGE_SHA512=184761b0dad0f9ace02f9298050ca96ce3caa39a461a47706d47ff9698b59933918b91b40177fbd4d392f6446af8b4d18ecb94caca988169b19641606bf34003
MANIFEST_SHA256=c535c54e44f724aa05278fe2bfa7bf607ecd285b83f35e136f16b99d1b99392a

[ "$(git -C "$REPOSITORY" rev-parse --show-toplevel)" = "$REPOSITORY" ] || exit 64
[ "$(git -C "$REPOSITORY" rev-parse 'HEAD^{commit}')" = "$expected_commit" ] || exit 64
[ -z "$(GIT_OPTIONAL_LOCKS=0 git -C "$REPOSITORY" status --porcelain=v1 \
    --untracked-files=normal --ignore-submodules=none)" ] \
    || { printf '%s\n' 'source worktree must be clean' >&2; exit 64; }
if git -C "$REPOSITORY" ls-files --stage \
    | awk '$1 == "160000" { found=1 } END { exit !found }'; then
    printf '%s\n' 'submodules are outside the VM source contract' >&2
    exit 64
fi
[ -f "$MANIFEST" ] && [ ! -L "$MANIFEST" ] || exit 64
printf '%s  %s\n' "$MANIFEST_SHA256" "$MANIFEST" | sha256sum --check --strict -
jq -e --arg filename "$IMAGE_FILENAME" --arg sha512 "$IMAGE_SHA512" \
    '.filename == $filename and .sha512 == $sha512 and .debian_version == "13"
      and .architecture == "amd64" and .systemd_version == 257
      and .format == "qcow2"' "$MANIFEST" >/dev/null || exit 64
[ "$(readlink -f -- "$image_path")" = "$image_path" ] || exit 64
[ "${image_path##*/}" = "$IMAGE_FILENAME" ] || exit 64
[ -f "$image_path" ] && [ ! -L "$image_path" ] || exit 64
printf '%s  %s\n' "$IMAGE_SHA512" "$image_path" | sha512sum --check --strict -
MPQUIC_SHA256=none
if [ -n "$mpquic_path" ]; then
[ "$(readlink -f -- "$mpquic_path")" = "$mpquic_path" ] || exit 64
[ -f "$mpquic_path" ] && [ -x "$mpquic_path" ] && [ ! -L "$mpquic_path" ] || exit 64
MPQUIC_SIZE=$(stat -Lc '%s' "$mpquic_path")
case $MPQUIC_SIZE in ''|0|*[!0-9]*) exit 64 ;; esac
[ "$MPQUIC_SIZE" -le 67108864 ] || exit 64
[ "$("$mpquic_path" --api-version)" = 6 ] || exit 64
MPQUIC_SHA256=$(sha256sum "$mpquic_path" | awk '{ print $1 }')
fi
PACKAGE_SHA256=none
if [ -n "$package_path" ]; then
[ "$(readlink -f -- "$package_path")" = "$package_path" ] || exit 64
[ -f "$package_path" ] && [ ! -L "$package_path" ] || exit 64
[ "$(dpkg-deb -f "$package_path" Package)" = volparossa ] || exit 64
[ "$(dpkg-deb -f "$package_path" Architecture)" = amd64 ] || exit 64
PACKAGE_SIZE=$(stat -Lc '%s' "$package_path")
case $PACKAGE_SIZE in ''|0|*[!0-9]*) exit 64 ;; esac
[ "$PACKAGE_SIZE" -le 536870912 ] || exit 64
PACKAGE_SHA256=$(sha256sum "$package_path" | awk '{ print $1 }')
fi
[ -d "$output_directory" ] && [ ! -L "$output_directory" ] || exit 64
[ -z "$(find "$output_directory" -mindepth 1 -maxdepth 1 -print -quit)" ] || exit 64

if ss -H -ltn 2>/dev/null | awk '$4 ~ /:22223$/ { found=1 } END { exit !found }'; then
    printf '%s\n' 'loopback TCP port 22223 is already occupied' >&2
    exit 77
fi

RUN_DIRECTORY=$(mktemp -d /tmp/volparossa-alpha-kvm.XXXXXX)
case $RUN_DIRECTORY in /tmp/volparossa-alpha-kvm.??????) ;; *) exit 69 ;; esac
chmod 0700 "$RUN_DIRECTORY"
QEMU_PID=
FINISHED=no

cleanup() {
    status=$?
    trap - EXIT HUP INT TERM
    if [ -n "$QEMU_PID" ] && kill -0 "$QEMU_PID" 2>/dev/null; then
        kill -TERM "$QEMU_PID" 2>/dev/null || true
        wait_attempt=0
        while kill -0 "$QEMU_PID" 2>/dev/null && [ "$wait_attempt" -lt 50 ]; do
            sleep 0.1
            wait_attempt=$((wait_attempt + 1))
        done
        if kill -0 "$QEMU_PID" 2>/dev/null; then
            kill -KILL "$QEMU_PID" 2>/dev/null || true
        fi
        wait "$QEMU_PID" 2>/dev/null || true
    fi
    if [ "$FINISHED" = no ] && [ -f "$RUN_DIRECTORY/console.log" ]; then
        install -m 0600 "$RUN_DIRECTORY/console.log" "$output_directory/vm-console.log" \
            2>/dev/null || true
    fi
    rm -rf --one-file-system -- "$RUN_DIRECTORY"
    exit "$status"
}
trap cleanup EXIT
trap 'exit 129' HUP
trap 'exit 130' INT
trap 'exit 143' TERM

SOURCE_ARCHIVE=$RUN_DIRECTORY/source.tar.gz
git -C "$REPOSITORY" archive --format=tar --prefix=source/ "$expected_commit" \
    | gzip -9 >"$SOURCE_ARCHIVE"
[ "$(stat -Lc '%s' "$SOURCE_ARCHIVE")" -gt 0 ] || exit 69
[ "$(stat -Lc '%s' "$SOURCE_ARCHIVE")" -le 536870912 ] || exit 69
SOURCE_SHA256=$(sha256sum "$SOURCE_ARCHIVE" | awk '{ print $1 }')

OVERLAY=$RUN_DIRECTORY/overlay.qcow2
SEED=$RUN_DIRECTORY/seed.img
SSH_KEY=$RUN_DIRECTORY/guest-key
HOST_KEY=$RUN_DIRECTORY/host-key
KNOWN_HOSTS=$RUN_DIRECTORY/known-hosts
USER_DATA=$RUN_DIRECTORY/user-data
META_DATA=$RUN_DIRECTORY/meta-data
GUEST_DRIVER=$RUN_DIRECTORY/guest-driver.sh
GUEST_DIAGNOSTICS=$RUN_DIRECTORY/guest-diagnostics.py
CONSOLE=$RUN_DIRECTORY/console.log

qemu-img create -q -f qcow2 -F qcow2 -b "$image_path" "$OVERLAY" 16G
ssh-keygen -q -t ed25519 -N '' -C volparossa-alpha-kvm-user -f "$SSH_KEY"
ssh-keygen -q -t ed25519 -N '' -C volparossa-alpha-kvm-host -f "$HOST_KEY"
GUEST_PUBLIC_KEY=$(cat "$SSH_KEY.pub")
GUEST_HOST_PUBLIC_KEY=$(cat "$HOST_KEY.pub")
printf '[127.0.0.1]:22223 %s\n' "$GUEST_HOST_PUBLIC_KEY" >"$KNOWN_HOSTS"
chmod 0600 "$KNOWN_HOSTS"

{
    printf '%s\n' '#cloud-config' \
        'users:' \
        '  - name: vpci' \
        '    gecos: VOLPAROSSA alpha KVM runner' \
        '    groups: [sudo]' \
        '    sudo: "ALL=(ALL) NOPASSWD:ALL"' \
        '    shell: /bin/bash' \
        '    lock_passwd: true' \
        '    ssh_authorized_keys:'
    printf '      - %s\n' "$GUEST_PUBLIC_KEY"
    printf '%s\n' \
        'ssh_pwauth: false' \
        'disable_root: true' \
        'ssh_deletekeys: true' \
        'ssh_keys:' \
        '  ed25519_private: |'
    sed 's/^/    /' "$HOST_KEY"
    printf '  ed25519_public: %s\n' "$GUEST_HOST_PUBLIC_KEY"
    printf '%s\n' \
        'growpart:' \
        '  mode: auto' \
        '  devices: [/]' \
        'resize_rootfs: true'
} >"$USER_DATA"
printf 'instance-id: volparossa-alpha-%s\nlocal-hostname: volparossa-alpha\n' \
    "$(printf '%.12s' "$expected_commit")" >"$META_DATA"
cloud-localds "$SEED" "$USER_DATA" "$META_DATA"

cat >"$GUEST_DIAGNOSTICS" <<'GUEST_DIAGNOSTICS_PYTHON'
#!/usr/bin/env python3
"""Bounded, incomplete evidence only; never clean up or mutate guest networking."""
import json
import os
from pathlib import Path
import pwd
import re
import socket
import stat
import subprocess
import sys
import tarfile
import tempfile

FILE_LIMIT = 131072
TOTAL_LIMIT = 8388608
FILE_COUNT_LIMIT = 64
NODES = ("client", "bootstrap1", "bootstrap2", "relay0", "relay1", "relay2",
         "relay3", "relay4", "relay5", "exit", "exit2")
SAFE_NAMES = {"runner.stdout", "runner.stderr", "guest-exit-status", "current-phase",
              "worker-network-diagnostics.txt", "host-state-before.json", "host-state-after.json",
              "report.json", "local-link-smoke.json", "wifi-link-smoke.json",
              "reciprocity-smoke.json", "mixed-link-smoke.json", "sharing-smoke.json", "download-sharing-smoke.json",
              "uplink-link-smoke.json", "crash-recovery.json", "content-network-smoke.json", "content-message-smoke.json", "content-https-smoke.json", "content-provider-smoke.json", "content-replication-smoke.json",
              "a14-evidence.json", "a15-evidence.json"}
SAFE_NAMES.update(f"{kind}-{node}.{extension}" for node in NODES
                  for kind, extension in (("agent", "log"), ("helper", "log"),
                                           ("logs", "txt"), ("status", "txt"),
                                           ("peers", "txt"), ("roles", "txt")))


def read_tail(path, limit=FILE_LIMIT):
    try:
        fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
        with os.fdopen(fd, "rb") as stream:
            info = os.fstat(stream.fileno())
            if not stat.S_ISREG(info.st_mode):
                return None
            stream.seek(max(0, info.st_size - limit))
            return stream.read(limit), info.st_size
    except OSError:
        return None


def phase_at(path):
    observed = read_tail(path, 65)
    if observed is None or observed[1] > 65:
        return None
    value = observed[0].strip().decode("ascii", errors="replace")
    return value if re.fullmatch(r"[a-z0-9-]{1,64}", value) else None


def helper_processes(cgroups, proc):
    processes = []
    for node in NODES:
        unit = f"volparossa-alpha-helper@{node}.service"
        members = read_tail(cgroups / unit / "cgroup.procs", 8192)
        if members is None:
            continue
        for raw_pid in members[0].split()[:64]:
            if not raw_pid.isdigit() or len(raw_pid) > 10 or len(processes) >= 128:
                continue
            pid = raw_pid.decode("ascii")
            directory = proc / pid
            identity = read_tail(directory / "cgroup", 8192)
            if identity is None or f"0::/system.slice/{unit}".encode() not in identity[0].splitlines():
                continue
            record = {"node": node, "pid": int(pid)}
            for field in ("stat", "wchan", "syscall"):
                observed = read_tail(directory / field, 1024)
                record[field] = None if observed is None else observed[0].decode("ascii", errors="replace").strip()
            try:
                namespace = os.readlink(directory / "ns/net")
                record["netns"] = namespace if re.fullmatch(r"net:\[[0-9]+\]", namespace) else None
            except OSError:
                record["netns"] = None
            processes.append(record)
    return processes


def collect(home, opt, revision, scenario, guest_status,
            cgroups=Path("/sys/fs/cgroup/system.slice"), proc=Path("/proc")):
    target = Path(tempfile.mkdtemp(prefix="alpha-incomplete.", dir=home))
    entries = []
    seen_sources = set()
    total = 0
    candidates = [(home / name, f"driver/{name}") for name in
                  ("guest-phase.txt", "cargo-build.log", "egress-netns-test.log",
                   "package-lifecycle.stdout", "package-lifecycle.stderr")]
    roots = [(home / "alpha-output", "published")]
    for path in sorted(opt.glob("va.*"))[:32]:
        if not path.is_symlink() and path.is_dir() and re.fullmatch(r"va\.[0-9a-f]{32}\.[A-Za-z0-9]{6}", path.name):
            roots.append((path, f"work-{len(roots)}"))
            if len(roots) == 5:
                break
    for root, label in roots:
        if root.is_symlink() or not root.is_dir():
            continue
        for name in sorted(SAFE_NAMES):
            candidates.append((root / name, f"{label}/{name}"))
        candidates.extend((path, f"{label}/{path.name}") for path in sorted(root.glob("wifi-link-*"))[:64]
                          if re.fullmatch(r"wifi-link-[a-z0-9-]+\.(json|txt|log)", path.name))
        candidates.extend((path, f"{label}/{path.name}") for path in sorted(root.glob("download-sharing-*"))[:64]
                          if re.fullmatch(r"download-sharing-[a-z0-9-]+\.(json|txt|log)", path.name))
        candidates.extend((path, f"{label}/{path.name}") for path in sorted(root.glob("content-*"))[:48]
                          if re.fullmatch(r"content-[a-z0-9-]+\.(json|txt|log|err|out)", path.name))
    for path, relative in candidates:
        if len(entries) >= FILE_COUNT_LIMIT or total >= TOTAL_LIMIT:
            break
        if path in seen_sources:
            continue
        seen_sources.add(path)
        observed = read_tail(path, min(FILE_LIMIT, TOTAL_LIMIT - total))
        if observed is None:
            continue
        data, original_size = observed
        # Retain only the explicitly allowlisted non-secret fixture outputs, never keys/configs.
        if re.search(br"-----BEGIN [A-Z0-9 ]*PRIVATE KEY-----", data):
            continue
        if original_size > len(data):
            relative += ".tail"
        destination = target / relative
        destination.parent.mkdir(parents=True, exist_ok=True)
        with destination.open("xb") as stream:
            stream.write(data)
        entries.append({"file": relative, "original_bytes": original_size,
                        "captured_bytes": len(data), "truncated": original_size > len(data)})
        total += len(data)
    summary = {"schema_version": 1, "report_kind": "volparossa-incomplete-vm-diagnostics",
               "source_revision": revision, "scenario": scenario, "success": False,
               "guest_exit_status": guest_status,
               "observed_blocker": "GUEST_EXECUTION_TIMEOUT" if guest_status in (124, 137)
                                   else "GUEST_OUTPUT_UNAVAILABLE",
               "driver_phase": phase_at(home / "guest-phase.txt"),
               "topology_phase": phase_at(home / "alpha-output/current-phase"),
               "cleanup": {"complete": False, "verified": False},
               "host_state": {"unchanged": None, "verified": False},
               "helper_processes": helper_processes(cgroups, proc),
               "diagnostics": {"available": True, "partial": True,
                               "captured_bytes": total, "files": entries}}
    (target / "vm-incomplete.json").write_text(json.dumps(summary, sort_keys=True) + "\n")
    archive = target / "snapshot.tar.gz"
    with tarfile.open(archive, "w:gz") as bundle:
        for entry in entries:
            bundle.add(target / entry["file"], arcname=entry["file"], recursive=False)
        bundle.add(target / "vm-incomplete.json", arcname="vm-incomplete.json", recursive=False)
    return archive


if __name__ == "__main__":
    if len(sys.argv) != 4 or not re.fullmatch(r"[0-9a-f]{40}|[0-9a-f]{64}", sys.argv[1]):
        raise SystemExit(64)
    if sys.argv[2] not in ("alpha", "datapath", "reciprocity", "local-link", "mixed-link",
                           "sharing", "download-sharing", "wifi-mesh", "wifi-link", "uplink-link", "crash-recovery", "content", "content-message", "content-https", "content-provider", "content-replication"):
        raise SystemExit(64)
    status_code = int(sys.argv[3])
    if not 0 <= status_code <= 255 or socket.gethostname() != "volparossa-alpha" or os.geteuid() != 0:
        raise SystemExit(77)
    virtual = subprocess.run(["systemd-detect-virt"], capture_output=True, timeout=2, check=False)
    if virtual.stdout.strip() != b"kvm" or virtual.returncode != 0:
        raise SystemExit(77)
    result = collect(Path("/home/vpci"), Path("/opt"), sys.argv[1], sys.argv[2], status_code)
    account = pwd.getpwnam("vpci")
    os.chown(result, account.pw_uid, account.pw_gid)
    os.chmod(result, 0o600)
    os.replace(result, "/home/vpci/alpha-incomplete-output.tar.gz")
    print("bounded incomplete guest diagnostics exported; cleanup remains unverified")
GUEST_DIAGNOSTICS_PYTHON
chmod 0700 "$GUEST_DIAGNOSTICS"

cat >"$GUEST_DRIVER" <<'GUEST_DRIVER_SCRIPT'
#!/bin/sh
set -eu
export LC_ALL=C
umask 077
expected_commit=$1
source_sha256=$2
mpquic_sha256=$3
package_sha256=$4
scenario=$5
case $scenario in alpha|datapath|reciprocity|local-link|mixed-link|sharing|download-sharing|wifi-mesh|wifi-link|uplink-link|crash-recovery|content|content-message|content-https|content-provider|content-replication) ;; *) exit 64 ;; esac
cd /home/vpci
guest_phase() { printf '%s\n' "$1" >/home/vpci/guest-phase.txt; }
guest_phase verify-source
printf '%s  source.tar.gz\n' "$source_sha256" | sha256sum --check --strict -
if [ "$scenario" = wifi-mesh ]; then
    guest_phase wifi-mesh-backend
    test "$(hostname)" = volparossa-alpha
    test "$(systemd-detect-virt)" = kvm
    tar -xzf source.tar.gz
    cd source
    exec sh tests/integration/wifi-mesh-vm-guest.sh "$expected_commit"
fi
if [ "$scenario" = wifi-link ]; then
    guest_phase wifi-kernel
    tar -xzf source.tar.gz
    (cd source && sh tests/integration/wifi-mesh-vm-guest.sh "$expected_commit" kernel-only)
fi
printf '%s  volparossa-mpquic\n' "$mpquic_sha256" | sha256sum --check --strict -
[ "$(stat -Lc '%s' volparossa-mpquic)" -le 67108864 ]
if [ "$scenario" = alpha ]; then
    printf '%s  volparossa.deb\n' "$package_sha256" | sha256sum --check --strict -
    [ "$(stat -Lc '%s' volparossa.deb)" -le 536870912 ]
fi
chmod 0555 volparossa-mpquic
guest_phase packages
sudo -n env DEBIAN_FRONTEND=noninteractive apt-get update
sudo -n env DEBIAN_FRONTEND=noninteractive apt-get install \
    --yes --no-install-recommends \
    build-essential ca-certificates cargo cmake dbus git iproute2 iputils-ping jq \
    nftables pkg-config python3 rustc sudo util-linux wireguard-tools
[ "$(./volparossa-mpquic --api-version)" = 6 ]
test "$(. /etc/os-release; printf '%s:%s' "$ID" "$VERSION_ID")" = debian:13
test "$(dpkg --print-architecture)" = amd64
test "$(uname -m)" = x86_64
test "$(sed -n '1p' /proc/1/comm)" = systemd
test "$(systemctl show --property=Version --value | sed 's/[^0-9].*$//')" = 257
test "$(systemd-detect-virt)" = kvm
tar -xzf source.tar.gz
cd source
test -x tests/integration/kvm-alpha-topology.sh
test -x tests/packaging/debian13-package-lifecycle.sh
guest_phase build
CARGO_TARGET_DIR=/home/vpci/target cargo build --locked \
    -p volparossa --bin volparossa \
    -p volparossa-agent --bin volparossa-agent \
    -p volparossa-helper-entry --bin volparossa-helper \
    -p volparossa-policy --example acceptance-policy-fixture \
    -p volparossa-test-support --example http3-acceptance-fixture \
    -p volparossa-test-support --example tls-policy-acceptance-fixture \
    >/home/vpci/cargo-build.log 2>&1 || {
        tail -c 131072 /home/vpci/cargo-build.log >&2
        exit 1
    }
if [ "$scenario" = content ] || [ "$scenario" = content-message ] || [ "$scenario" = content-provider ] \
    || [ "$scenario" = content-replication ]; then
    CARGO_TARGET_DIR=/home/vpci/target cargo build --locked \
        -p volparossa-content --example content-acceptance-fixture \
        >>/home/vpci/cargo-build.log 2>&1 || {
            tail -c 131072 /home/vpci/cargo-build.log >&2
            exit 1
        }
fi
if [ "$scenario" = content-https ] || [ "$scenario" = content-provider ]; then
    CARGO_TARGET_DIR=/home/vpci/target cargo build --locked \
        -p volparossa-content --example https-content-acceptance-fixture \
        >>/home/vpci/cargo-build.log 2>&1 || {
            tail -c 131072 /home/vpci/cargo-build.log >&2
            exit 1
        }
fi
if [ "$scenario" = uplink-link ]; then
    guest_phase egress-netns-test
    if ! VOLPAROSSA_REQUIRE_EGRESS_NETNS_PROOF=1 CARGO_TARGET_DIR=/home/vpci/target \
        cargo test --locked -p volparossa-linux-uapi --lib \
        egress::tests::egress_disposable_link_loss_return_and_capless_first_bind \
        -- --exact --nocapture --test-threads=1 >/home/vpci/egress-netns-test.log 2>&1; then
        tail -c 131072 /home/vpci/egress-netns-test.log >&2
        exit 1
    fi
    tail -c 131072 /home/vpci/egress-netns-test.log
fi
mkdir /home/vpci/alpha-output

# The package lifecycle requires a pristine VM, including an absent
# /run/volparossa. Exercise it before the topology's transient units can create
# that bind-mount target; successful package removal leaves no active services
# or installed binaries that could affect the later datapath evidence.
package_status=0
if [ "$scenario" = alpha ]; then
guest_phase package-lifecycle
mkdir /home/vpci/alpha-output/package
package_stdout=/home/vpci/package-lifecycle.stdout
package_stderr=/home/vpci/package-lifecycle.stderr
set +e
sudo -n -- ./tests/packaging/debian13-package-lifecycle.sh \
    --execute --yes \
    --package /home/vpci/volparossa.deb \
    --output /home/vpci/alpha-output/package \
    >"$package_stdout" 2>"$package_stderr"
package_status=$?
set -e
mv -- "$package_stdout" /home/vpci/alpha-output/package/runner.stdout
mv -- "$package_stderr" /home/vpci/alpha-output/package/runner.stderr
printf '%s\n' "$package_status" >/home/vpci/alpha-output/package/guest-exit-status
fi

topology_scenario=alpha
case $scenario in reciprocity|local-link|mixed-link|sharing|download-sharing|wifi-link|uplink-link|crash-recovery|content|content-message|content-https|content-provider|content-replication) topology_scenario=$scenario ;; esac
guest_phase topology
set +e
sudo -n -- ./tests/integration/kvm-alpha-topology.sh \
    --execute --yes \
    --source /home/vpci/source \
    --bin /home/vpci/target/debug \
    --mpquic /home/vpci/volparossa-mpquic \
    --scenario "$topology_scenario" \
    --output /home/vpci/alpha-output \
    --expected-commit "$expected_commit" \
    >/home/vpci/alpha-output/runner.stdout \
    2>/home/vpci/alpha-output/runner.stderr
topology_status=$?
set -e
guest_phase archive
printf '%s\n' "$topology_status" >/home/vpci/alpha-output/guest-exit-status
sudo -n chown -R vpci:vpci /home/vpci/alpha-output
find /home/vpci/alpha-output -type d -exec chmod 0700 {} +
find /home/vpci/alpha-output -type f -exec chmod 0600 {} +
tar -C /home/vpci/alpha-output -czf /home/vpci/alpha-output.tar.gz .
guest_phase driver-finished
if [ "$package_status" -ne 0 ]; then exit "$package_status"; fi
exit "$topology_status"
GUEST_DRIVER_SCRIPT
chmod 0700 "$GUEST_DRIVER"

set -- -no-reboot
case $scenario in wifi-mesh|wifi-link) set -- ;; esac
qemu-system-x86_64 \
    -name volparossa-alpha-topology \
    -no-user-config -nodefaults \
    -machine q35,accel=kvm -cpu host -smp 4 -m 4096 \
    -device VGA,id=video0,bus=pcie.0,addr=0x1 \
    -drive "if=virtio,format=qcow2,file=$OVERLAY" \
    -drive "if=virtio,format=raw,readonly=on,file=$SEED" \
    -device virtio-rng-pci \
    -device virtio-net-pci,netdev=net0 \
    -netdev user,id=net0,hostfwd=tcp:127.0.0.1:22223-:22 \
    -display none -monitor none -serial "file:$CONSOLE" "$@" \
    -sandbox on,obsolete=deny,elevateprivileges=deny,spawn=deny,resourcecontrol=deny \
    </dev/null >/dev/null 2>&1 &
QEMU_PID=$!

ssh_bounded() {
    ssh_time_bound=$1
    shift
    timeout --signal=TERM --kill-after=10s "$ssh_time_bound" ssh \
        -F /dev/null -i "$SSH_KEY" -p 22223 \
        -o BatchMode=yes -o ConnectTimeout=5 \
        -o ClearAllForwardings=yes -o ControlMaster=no -o ControlPath=none \
        -o ForwardAgent=no -o GlobalKnownHostsFile=/dev/null \
        -o HostKeyAlgorithms=ssh-ed25519 -o IdentitiesOnly=yes \
        -o IdentityAgent=none -o KbdInteractiveAuthentication=no \
        -o PasswordAuthentication=no -o ProxyCommand=none -o ProxyJump=none \
        -o RequestTTY=no -o StrictHostKeyChecking=yes -o Tunnel=no \
        -o UserKnownHostsFile="$KNOWN_HOSTS" vpci@127.0.0.1 "$@"
}

ssh_base() { ssh_bounded 2400s "$@"; }

scp_to() {
    timeout --signal=TERM --kill-after=10s 600s scp \
        -F /dev/null -i "$SSH_KEY" -P 22223 \
        -o BatchMode=yes -o ConnectTimeout=5 \
        -o ClearAllForwardings=yes -o ControlMaster=no -o ForwardAgent=no \
        -o GlobalKnownHostsFile=/dev/null -o HostKeyAlgorithms=ssh-ed25519 \
        -o IdentitiesOnly=yes -o IdentityAgent=none \
        -o KbdInteractiveAuthentication=no -o PasswordAuthentication=no \
        -o ProxyCommand=none -o ProxyJump=none -o RequestTTY=no \
        -o StrictHostKeyChecking=yes -o Tunnel=no \
        -o UserKnownHostsFile="$KNOWN_HOSTS" "$1" "vpci@127.0.0.1:$2"
}

scp_from_bounded() {
    scp_time_bound=$1
    shift
    timeout --signal=TERM --kill-after=10s "$scp_time_bound" scp \
        -F /dev/null -i "$SSH_KEY" -P 22223 \
        -o BatchMode=yes -o ConnectTimeout=5 \
        -o ClearAllForwardings=yes -o ControlMaster=no -o ForwardAgent=no \
        -o GlobalKnownHostsFile=/dev/null -o HostKeyAlgorithms=ssh-ed25519 \
        -o IdentitiesOnly=yes -o IdentityAgent=none \
        -o KbdInteractiveAuthentication=no -o PasswordAuthentication=no \
        -o ProxyCommand=none -o ProxyJump=none -o RequestTTY=no \
        -o StrictHostKeyChecking=yes -o Tunnel=no \
        -o UserKnownHostsFile="$KNOWN_HOSTS" "vpci@127.0.0.1:$1" "$2"
}

scp_from() { scp_from_bounded 600s "$@"; }

retrieve_incomplete_output() {
    # This record remains even when the guest is unreachable. It is never a success report.
    jq -cn --arg revision "$expected_commit" --arg scenario "$scenario" \
        --argjson status "$GUEST_STATUS" \
        '{schema_version:1,report_kind:"volparossa-incomplete-vm-diagnostics",
          source_revision:$revision,scenario:$scenario,success:false,guest_exit_status:$status,
          observed_blocker:(if $status==124 or $status==137 then "GUEST_EXECUTION_TIMEOUT"
                            else "GUEST_OUTPUT_UNAVAILABLE" end),
          driver_phase:null,topology_phase:null,cleanup:{complete:false,verified:false},
          host_state:{unchanged:null,verified:false},diagnostics:{available:false,partial:true}}' \
        >"$output_directory/vm-incomplete.json"
    if ssh_bounded 30s sudo -n python3 /home/vpci/guest-diagnostics.py \
        "$expected_commit" "$scenario" "$GUEST_STATUS" \
        >"$output_directory/vm-diagnostics.log" 2>"$output_directory/vm-diagnostics.stderr" \
        && scp_from_bounded 30s /home/vpci/alpha-incomplete-output.tar.gz \
            "$RUN_DIRECTORY/alpha-incomplete-output.tar.gz"; then
        [ "$(stat -Lc '%s' "$RUN_DIRECTORY/alpha-incomplete-output.tar.gz")" -le 9437184 ] \
            || return 1
        tar -C "$output_directory" -xzf "$RUN_DIRECTORY/alpha-incomplete-output.tar.gz"
    fi
}

ssh_attempt=0
while [ "$ssh_attempt" -lt 240 ]; do
    kill -0 "$QEMU_PID" 2>/dev/null || { tail -c 131072 "$CONSOLE" >&2; exit 1; }
    if ssh_base true >/dev/null 2>&1; then break; fi
    sleep 1
    ssh_attempt=$((ssh_attempt + 1))
done
[ "$ssh_attempt" -lt 240 ] || { tail -c 131072 "$CONSOLE" >&2; exit 1; }
ssh_base sudo -n cloud-init status --wait >/dev/null
scp_to "$SOURCE_ARCHIVE" /home/vpci/source.tar.gz
if [ -n "$mpquic_path" ]; then scp_to "$mpquic_path" /home/vpci/volparossa-mpquic; fi
if [ -n "$package_path" ]; then scp_to "$package_path" /home/vpci/volparossa.deb; fi
scp_to "$GUEST_DRIVER" /home/vpci/guest-driver.sh
scp_to "$GUEST_DIAGNOSTICS" /home/vpci/guest-diagnostics.py
ssh_base chmod 0700 /home/vpci/guest-driver.sh

set +e
ssh_base /home/vpci/guest-driver.sh "$expected_commit" "$SOURCE_SHA256" \
    "$MPQUIC_SHA256" "$PACKAGE_SHA256" "$scenario"
GUEST_STATUS=$?
set -e
if { [ "$scenario" = wifi-mesh ] || [ "$scenario" = wifi-link ]; } && [ "$GUEST_STATUS" -eq 194 ]; then
    # Only the Wi-Fi guest stage may request this one exact-kernel reboot.
    old_boot=$(ssh_base cat /proc/sys/kernel/random/boot_id)
    ssh_base sudo -n systemctl reboot >/dev/null 2>&1 || true
    reboot_attempt=0
    while [ "$reboot_attempt" -lt 120 ]; do
        kill -0 "$QEMU_PID" 2>/dev/null || exit 1
        new_boot=$(ssh_base cat /proc/sys/kernel/random/boot_id 2>/dev/null) || new_boot=
        if [ -n "$new_boot" ] && [ "$new_boot" != "$old_boot" ]; then break; fi
        sleep 1
        reboot_attempt=$((reboot_attempt + 1))
    done
    [ "$reboot_attempt" -lt 120 ] || exit 1
    [ "$(ssh_base uname -r)" = 6.12.107+deb13-amd64 ] || exit 1
    set +e
    ssh_base /home/vpci/guest-driver.sh "$expected_commit" "$SOURCE_SHA256" \
        "$MPQUIC_SHA256" "$PACKAGE_SHA256" "$scenario"
    GUEST_STATUS=$?
    set -e
fi
retrieval_bound=600s
[ "$GUEST_STATUS" -eq 0 ] || retrieval_bound=30s
if ! scp_from_bounded "$retrieval_bound" /home/vpci/alpha-output.tar.gz "$RUN_DIRECTORY/alpha-output.tar.gz"; then
    retrieve_incomplete_output || true
    tail -c 131072 "$CONSOLE" >&2
    [ "$GUEST_STATUS" -ne 0 ] || GUEST_STATUS=1
    exit "$GUEST_STATUS"
fi
tar -C "$output_directory" -xzf "$RUN_DIRECTORY/alpha-output.tar.gz"
if grep -aERq -- '-----BEGIN ([A-Z0-9 ]+ )?PRIVATE KEY-----' "$output_directory"; then
    printf '%s\n' 'refusing topology output containing private-key material' >&2
    exit 1
fi
install -m 0600 "$CONSOLE" "$output_directory/vm-console.log"
ssh_base sudo -n systemctl poweroff >/dev/null 2>&1 || true
wait "$QEMU_PID" || true
QEMU_PID=
printf '%s  %s\n' "$IMAGE_SHA512" "$image_path" | sha512sum --check --strict -
FINISHED=yes
exit "$GUEST_STATUS"
