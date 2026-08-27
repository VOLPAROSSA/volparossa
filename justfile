set dotenv-load := false
set positional-arguments := true
set shell := ["sh", "-eu", "-c"]

default:
    @just --list

setup:
    ./scripts/bootstrap-debian13-dev.sh

native-build:
    ./native/volparossa-mpquic/scripts/build-upstream.sh

native-sanitize:
    ./native/volparossa-mpquic/scripts/test-sanitized-upstream.sh

build: native-build
    cargo build --locked --workspace --all-features

build-release: native-build
    cargo build --locked --workspace --all-features --release

fmt:
    cargo fmt --all --check

fmt-fix:
    cargo fmt --all

lint:
    ./scripts/check-shell.sh
    cargo clippy --locked --workspace --all-targets --all-features -- -D warnings
    ./scripts/check-rust-dependencies.sh

test:
    cargo test --locked --workspace --all-features

test-unit:
    cargo test --locked --workspace --all-features --lib

test-integration:
    ./packaging/test-collect-cargo-licenses.sh
    ./tests/netns/test-lifecycle-contract.sh
    ./tests/integration/test-harness.sh
    ./tests/integration/run.sh --preview --suite all

test-package-licenses:
    ./packaging/test-collect-cargo-licenses.sh

test-netns:
    ./tests/netns/run-topology.sh --preview --only all

test-netns-fixed-icmp-echo-proof:
    cargo build --locked --target x86_64-unknown-linux-gnu \
        --target-dir target/fixed-icmp-echo-proof -p volparossa-netns-runner
    /usr/bin/setpriv --no-new-privs --inh-caps=-all --ambient-caps=-all \
        ./tests/netns/require-fixed-icmp-echo-proof.sh

test-helper-live-worker-identity-contract:
    ./tests/helper/test-live-worker-identity-contract.sh

test-helper-boundary-evidence:
    ./tests/helper/test-helper-boundary-evidence-v1.sh

test-helper-live-worker-identity-preview:
    ./tests/helper/require-live-worker-identity-proof.sh --preview

build-helper-live-worker-identity-proof:
    cargo build --locked -p volparossa-helper-entry
    cargo build --locked -p volparossa-helper \
        --example volparossa-helper-production-ipc-probe
    install -m 0755 target/debug/volparossa-helper \
        target/debug/volparossa-helper.detached
    mv -f target/debug/volparossa-helper.detached target/debug/volparossa-helper
    install -m 0755 target/debug/examples/volparossa-helper-production-ipc-probe \
        target/debug/examples/volparossa-helper-production-ipc-probe.detached
    mv -f target/debug/examples/volparossa-helper-production-ipc-probe.detached \
        target/debug/examples/volparossa-helper-production-ipc-probe

# Run build-helper-live-worker-identity-proof as the workspace user first;
# execute this recipe itself as root only inside a disposable Debian 13 amd64 VM.
test-helper-live-worker-identity-proof:
    ./tests/helper/require-live-worker-identity-proof.sh --execute --yes

# Backwards-compatible names for the now-stronger fixed ICMP echo plus rollback proof.
test-netns-permanent-neighbour-proof: test-netns-fixed-icmp-echo-proof
test-netns-counted-forward-policy-proof: test-netns-fixed-icmp-echo-proof
test-netns-ipv4-forwarding-runtime-proof: test-netns-fixed-icmp-echo-proof
test-netns-forward-policy-teardown-proof: test-netns-fixed-icmp-echo-proof
test-netns-endpoint-route-teardown-proof: test-netns-fixed-icmp-echo-proof
test-netns-link-activation-teardown-proof: test-netns-fixed-icmp-echo-proof
test-netns-ipv4-address-rollback-proof: test-netns-fixed-icmp-echo-proof
test-netns-veth-rollback-proof: test-netns-fixed-icmp-echo-proof
test-netns-live-nsfs-proof: test-netns-fixed-icmp-echo-proof
test-netns-authorized-private-run-proof: test-netns-fixed-icmp-echo-proof
test-netns-bootstrap-ready-proof: test-netns-fixed-icmp-echo-proof

test-mptcp:
    ./tests/netns/run-topology.sh --preview --only mptcp

test-mpquic:
    ./tests/netns/run-topology.sh --preview --only mpquic

fuzz:
    ./scripts/run-fuzz.sh

benchmark:
    ./tests/netns/run-benchmarks.sh --preview

package-deb:
    ./packaging/build-deb.sh --preview

package-deb-build:
    ./packaging/build-deb.sh --build

doctor:
    cargo run --locked -p volparossa -- doctor

demo:
    cargo run --locked -p volparossa -- demo

clean:
    cargo clean

cleanup-network:
    ./scripts/cleanup-network.sh
