# SPDX-License-Identifier: GPL-3.0-only
# Sourced by the hosted application fixtures after their runner and source checks.
prepare_application_topology() {
    local kvm_gid runtime manifest image
    sudo env DEBIAN_FRONTEND=noninteractive apt-get install --yes --no-install-recommends \
        build-essential cmake git libevent-dev pkg-config qemu-system-x86 qemu-utils cloud-image-utils openssh-client curl jq util-linux
    test -c /dev/kvm
    test "$(stat -Lc '%u' /dev/kvm)" = 0
    kvm_gid=$(stat -Lc '%g' /dev/kvm)
    [[ "$kvm_gid" =~ ^[1-9][0-9]*$ ]]
    test "$(getent group "$kvm_gid" | cut -d: -f1)" = kvm
    qemu-system-x86_64 -accel help | grep -Fx kvm

    native/volparossa-mpquic/scripts/fetch-upstream.sh --yes
    VMP_BUILD_JOBS=2 VMP_RUN_TESTS=no native/volparossa-mpquic/scripts/build-upstream.sh
    runtime="$(pwd -P)/native/volparossa-mpquic/build/volparossa-mpquic"
    test -x "$runtime"
    test "$("$runtime" --api-version)" = 7
    test "$(stat -Lc '%s' "$runtime")" -le 67108864

    manifest=tests/helper/debian13-amd64-image-v1.json
    printf '%s  %s\n' c535c54e44f724aa05278fe2bfa7bf607ecd285b83f35e136f16b99d1b99392a "$manifest" | sha256sum --check --strict -
    image="$RUNNER_TEMP/$(jq -er .filename "$manifest")"
    test ! -e "$image"
    test ! -L "$image"
    curl --fail --show-error --silent --location --connect-timeout 30 --max-time 1200 --max-filesize 2147483648 \
        --max-redirs 3 --proto '=https' --proto-redir '=https' --output "$image" "$(jq -er .url "$manifest")"
    printf '%s  %s\n' "$(jq -er .sha512 "$manifest")" "$image" | sha512sum --check --strict -
}
