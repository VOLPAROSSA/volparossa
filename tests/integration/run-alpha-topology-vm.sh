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

usage() {
    printf '%s\n' \
        'usage: tests/integration/run-alpha-topology-vm.sh --preview' \
        '       tests/integration/run-alpha-topology-vm.sh --execute --yes' \
        '         --image PATH --mpquic PATH --package PATH --output DIRECTORY' \
        '         --expected-commit SHA'
}

print_plan() {
    printf '%s\n' \
        'VOLPAROSSA disposable alpha topology VM plan:' \
        '  verify the reviewed Debian 13 amd64 image by its pinned SHA-512;' \
        '  archive only the exact clean checked-out Git revision;' \
        '  verify and copy the locally built pinned mqvpn/xquic daemon;' \
        '  verify and copy the exact candidate Debian package;' \
        '  boot one temporary KVM-only qcow2 overlay with QEMU user networking;' \
        '  prove package install, doctor, start, upgrade and removal in the guest;' \
        '  install Debian build/runtime packages and build only required test binaries;' \
        '  run the twelve-node production-helper topology as guest root;' \
        '  retrieve bounded non-secret logs and its machine-readable result;' \
        '  power off and discard the overlay, keys, seed and source archive.' \
        'No TAP, bridge, host route, firewall, DNS, sysctl or VPN state is changed.'
}

while [ "$#" -gt 0 ]; do
    case $1 in
        --preview) mode=preview ;;
        --execute) mode=execute ;;
        --yes) approval=yes ;;
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

if [ "$approval" != yes ] || [ -z "$image_path" ] || [ -z "$mpquic_path" ] \
    || [ -z "$package_path" ] \
    || [ -z "$output_directory" ] || [ -z "$expected_commit" ]; then
    usage >&2
    exit 64
fi
case $image_path:$mpquic_path:$package_path:$output_directory in
    /*:/*:/*:/*) ;;
    *) exit 64 ;;
esac
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
[ "$(readlink -f -- "$mpquic_path")" = "$mpquic_path" ] || exit 64
[ -f "$mpquic_path" ] && [ -x "$mpquic_path" ] && [ ! -L "$mpquic_path" ] || exit 64
MPQUIC_SIZE=$(stat -Lc '%s' "$mpquic_path")
case $MPQUIC_SIZE in ''|0|*[!0-9]*) exit 64 ;; esac
[ "$MPQUIC_SIZE" -le 67108864 ] || exit 64
[ "$("$mpquic_path" --api-version)" = 6 ] || exit 64
MPQUIC_SHA256=$(sha256sum "$mpquic_path" | awk '{ print $1 }')
[ "$(readlink -f -- "$package_path")" = "$package_path" ] || exit 64
[ -f "$package_path" ] && [ ! -L "$package_path" ] || exit 64
[ "$(dpkg-deb -f "$package_path" Package)" = volparossa ] || exit 64
[ "$(dpkg-deb -f "$package_path" Architecture)" = amd64 ] || exit 64
PACKAGE_SIZE=$(stat -Lc '%s' "$package_path")
case $PACKAGE_SIZE in ''|0|*[!0-9]*) exit 64 ;; esac
[ "$PACKAGE_SIZE" -le 536870912 ] || exit 64
PACKAGE_SHA256=$(sha256sum "$package_path" | awk '{ print $1 }')
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

cat >"$GUEST_DRIVER" <<'GUEST_DRIVER_SCRIPT'
#!/bin/sh
set -eu
export LC_ALL=C
umask 077
expected_commit=$1
source_sha256=$2
mpquic_sha256=$3
package_sha256=$4
cd /home/vpci
printf '%s  source.tar.gz\n' "$source_sha256" | sha256sum --check --strict -
printf '%s  volparossa-mpquic\n' "$mpquic_sha256" | sha256sum --check --strict -
printf '%s  volparossa.deb\n' "$package_sha256" | sha256sum --check --strict -
[ "$(stat -Lc '%s' volparossa-mpquic)" -le 67108864 ]
[ "$(stat -Lc '%s' volparossa.deb)" -le 536870912 ]
chmod 0555 volparossa-mpquic
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
mkdir /home/vpci/alpha-output
set +e
sudo -n -- ./tests/integration/kvm-alpha-topology.sh \
    --execute --yes \
    --source /home/vpci/source \
    --bin /home/vpci/target/debug \
    --mpquic /home/vpci/volparossa-mpquic \
    --output /home/vpci/alpha-output \
    --expected-commit "$expected_commit" \
    >/home/vpci/alpha-output/runner.stdout \
    2>/home/vpci/alpha-output/runner.stderr
topology_status=$?
set -e
printf '%s\n' "$topology_status" >/home/vpci/alpha-output/guest-exit-status

# The topology runner has completed its own scoped cleanup before returning.
# Exercise the installed package only afterwards so package systemd services
# cannot affect datapath evidence or its host-state comparison.
mkdir /home/vpci/alpha-output/package
set +e
sudo -n -- ./tests/packaging/debian13-package-lifecycle.sh \
    --execute --yes \
    --package /home/vpci/volparossa.deb \
    --output /home/vpci/alpha-output/package \
    >/home/vpci/alpha-output/package/runner.stdout \
    2>/home/vpci/alpha-output/package/runner.stderr
package_status=$?
set -e
printf '%s\n' "$package_status" >/home/vpci/alpha-output/package/guest-exit-status
sudo -n chown -R vpci:vpci /home/vpci/alpha-output
find /home/vpci/alpha-output -type d -exec chmod 0700 {} +
find /home/vpci/alpha-output -type f -exec chmod 0600 {} +
tar -C /home/vpci/alpha-output -czf /home/vpci/alpha-output.tar.gz .
if [ "$package_status" -ne 0 ]; then exit "$package_status"; fi
exit "$topology_status"
GUEST_DRIVER_SCRIPT
chmod 0700 "$GUEST_DRIVER"

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
    -display none -monitor none -serial "file:$CONSOLE" -no-reboot \
    -sandbox on,obsolete=deny,elevateprivileges=deny,spawn=deny,resourcecontrol=deny \
    </dev/null >/dev/null 2>&1 &
QEMU_PID=$!

ssh_base() {
    timeout --signal=TERM --kill-after=10s 2400s ssh \
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

scp_from() {
    timeout --signal=TERM --kill-after=10s 600s scp \
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
scp_to "$mpquic_path" /home/vpci/volparossa-mpquic
scp_to "$package_path" /home/vpci/volparossa.deb
scp_to "$GUEST_DRIVER" /home/vpci/guest-driver.sh
ssh_base chmod 0700 /home/vpci/guest-driver.sh

set +e
ssh_base /home/vpci/guest-driver.sh "$expected_commit" "$SOURCE_SHA256" \
    "$MPQUIC_SHA256" "$PACKAGE_SHA256"
GUEST_STATUS=$?
set -e
if ! scp_from /home/vpci/alpha-output.tar.gz "$RUN_DIRECTORY/alpha-output.tar.gz"; then
    tail -c 131072 "$CONSOLE" >&2
    exit 1
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
