# Debian 13 operations

This guide targets Debian 13 (Trixie) amd64 with systemd, nftables, kernel WireGuard, and kernel
MPTCP. It is not a release announcement. Do not enable services or route sensitive traffic until
the relevant checks in [IMPLEMENTATION_STATUS.md](IMPLEMENTATION_STATUS.md) are complete.

## Read-only prerequisites

Run the checker as an ordinary user:

```sh
./scripts/check-system.sh
```

It reads OS, architecture, kernel feature/configuration, command/library availability, time status,
and potentially conflicting VOLPAROSSA-reserved route/rule ranges. It does not load modules, write
sysctls, create sockets/interfaces/namespaces, query external hosts, or alter networking.

For development, first preview exact Debian package candidates, then opt in:

```sh
./scripts/bootstrap-debian13-dev.sh --print-only
./scripts/bootstrap-debian13-dev.sh
```

The script does not run `apt update` or install optional mptcpd by default. It uses only Debian apt
packages and asks before `apt-get install`. Review the complete command shown.

## Build and package

```sh
cargo build --locked --workspace --all-features
cargo fmt --all --check
cargo clippy --workspace --all-targets --all-features -- -D warnings
cargo test --workspace --all-features
./scripts/check-rust-dependencies.sh
./packaging/test-collect-cargo-licenses.sh
./packaging/build-deb.sh --build
```

The dependency gate is offline and requires `cargo-audit >= 0.22.1` plus an
existing local RustSec advisory checkout. It reconstructs and verifies the two
Debian-Rust-compatible source backports plus the reviewed single-backend Yamux
override before applying the documented scanner exemptions; see
`third_party/rust/README.md`.

`just package-deb` and `./packaging/build-deb.sh` are non-writing previews. Building requires the
explicit `./packaging/build-deb.sh --build` form and refuses to run as root or overwrite an existing
candidate. In the current tree, build mode exits 77 before compilation because the reviewed native
launcher is absent; preview mode names this blocker explicitly.

The candidate package build uses `Cargo.lock`, a caller-supplied or repository source timestamp,
root-owned archive metadata, deterministic file ordering from `dpkg-deb`, and a clean temporary
staging directory. It must fail if any required runtime binary is absent. Reproducibility is proven
only by comparing two clean Debian 13 builds, not by these flags alone.

Inspect before installation:

```sh
dpkg-deb --info dist/volparossa_0.1.0_amd64.deb
dpkg-deb --contents dist/volparossa_0.1.0_amd64.deb
sudo apt install ./dist/volparossa_0.1.0_amd64.deb
```

Package installation creates the locked `volparossa` system account, `/var/lib/volparossa` mode
0700, `/etc/volparossa` mode 0750, a root/service-only `/run/volparossa`, a separate
agent-owned `/run/volparossa/control` mode 0750 that members of `volparossa-users` may traverse,
and a service-only native socket directory. Human control users can connect to the group-writable
agent socket but cannot replace it or access/unlink the helper socket. Installation does not
enable agent/helper services. journald is the default; no file log or logrotate configuration is
enabled.

## First initialization

As the service identity through the final supported CLI flow, initialize one permanent identity and
verify file ownership/mode without printing its content:

```sh
volparossa init
volparossa config validate
volparossa policy verify /etc/volparossa/policy.manifest
volparossa doctor
```

Provision the already initialized identity's passphrase as an encrypted systemd credential. The
passphrase is read interactively and is not placed in the command line, shell history, unit, or
environment:

```sh
sudo install -d -m 0700 /etc/credstore.encrypted
systemd-ask-password "VOLPAROSSA identity passphrase:" \
  | sudo systemd-creds encrypt --name=identity-passphrase - \
      /etc/credstore.encrypted/identity-passphrase
sudo chmod 0600 /etc/credstore.encrypted/identity-passphrase
```

`volparossa-agent.service` imports only the named `identity-passphrase` credential. systemd exposes
the decrypted bytes in its protected per-service credential directory; the agent opens that one
fixed regular file with `O_NOFOLLOW`, enforces owner-only mode and a strict length bound, and
zeroizes the temporary bytes. Missing or unsafe credentials make startup fail closed. Protect the
encrypted credential and identity file together when backing up or rotating the permanent
identity. This provisioning flow still requires a Debian 13 systemd integration test before a
package is declared releasable.

The packaged example keeps client on, relay and exit off, the kill switch on, direct-exit debug off,
plain-TCP fallback off, required MPQUIC paths at two or more, and policy fail-closed. An empty policy
path means connections fail closed; it is not an allow-all policy.

Privacy-v4 is a hard-incompatible migration: set `network.protocol_version: 4`. Signed peer
control and `/volparossa/advertisement/4` accept exactly v4; v1, v2, v3, zero, and future values are
rejected without negotiation or fallback. The retired direct exit/relay/confirmation v2 protocol
IDs are never registered. This does not retire the independently versioned threshold policy
manifest v2 or libp2p Circuit Relay v2, which remains control-plane connectivity only.

The default client-only configuration may leave `network.operator_id: null`. Enabling relay or exit
instead requires an explicit operator ID of 1..=128 ASCII letters, digits, `-`, `_`, `.`, or
`:`; `unknown` is not synthesized. Unknown configuration fields remain rejected.

Relay and exit advertisement/provider publication currently stays fail closed even after the role
is configured, because no helper-backed live service preparation/admission handle is connected yet.
The agent never substitutes a static or placeholder WireGuard key, listen port, probe, or activation
receipt.

The intended client chooses a directly verified control relay before any exit. Direct
`/volparossa/advertisement/4` retrieval may establish relay/control-relay provenance only. A
combined-role node may be an exit only from exclusively forwarded provenance:
direct-then-forwarded is rejected, while forwarded-then-direct withdraws and quarantines exit
capability for the advertisement lifetime. Exit advertisement lookup and every exit hold, permit,
finalize, and confirmation RPC must traverse `/volparossa/exit-forward/4` and
`/volparossa/exit-forward-upstream/4`. Selected datapath relays are contacted directly only on
`/volparossa/datapath-relay/4`. Within one route the exit differs by node ID and Peer ID from the
control relay and every datapath relay; the control relay needs its own probe and grant before it
can also carry a datapath.

## Services and sockets

Candidate units are installed as:

- `volparossa-helper.service`: root, only the bounded networking capabilities/address families and
  `/run/volparossa`; creates a root-owned `helper.sock` with group `volparossa` and mode 0660. Its
  main process is the only accepted systemd notifier, and PID 1 accepts at most 128 preserved
  descriptors for at most 64 future pidfd/network-namespace custody pairs. Production currently seals,
  duplicates and structurally validates inherited activation groups before Tokio, then refuses
  startup because typed journal-bound adoption and the restart reaper are not installed; no
  FD-store publication path is enabled yet. A future publisher must use `FDPOLL=0`, a manager
  barrier and a complete post-barrier store-inventory attestation before arming;
- `volparossa-agent.service`: user/group `volparossa`, no capabilities, persistent state/config,
  control-plane network access, the helper socket, and an agent-owned mode-0660 socket under a
  non-group-writable `/run/volparossa/control`; the unit loads only the named encrypted identity
  credential;
- `volparossa-mpquic.service`: candidate unprivileged isolation only. It is not runnable yet.
  API v6 preflights one client or exit role/process lifetime, targets that instance thereafter, and
  correlates every response to the exact canonical request. It accepts exact 43-character
  base64url client auth and TLS names only in bounded, signed-scope route-session messages; the
  native commitment check proves bearer equality, not generator entropy or binary attestation.
  `AddPath` consumes exactly one request-bound UDP descriptor and native never creates or binds a
  path socket, but the agent does not yet call this API and production helper acquisition does not
  provide independently authenticated descriptor provenance. The package also has only one
  same-UID native unit/socket; separate client/exit service identities and role sockets remain
  required before an untrusted agent can use this as an authenticated boundary.
  `StartExitSession` carries bounded, unparsed in-memory TLS candidate material and consumes exactly
  one caller-supplied, pre-bound IPv6 UDP descriptor whose current tuple and flags are checked by
  Rust and native. Those descriptor checks do not prove assigned-address or network-namespace
  state. Native converts the supplied wall expiry to a BOOTTIME deadline and keeps a bounded,
  process-local reservation/finalize ledger with no live eviction; it rejects pair replay and
  one-ID scope collisions, but does not independently verify the reservation signature or general
  nonce freshness, and restart clears the ledger. The dormant exit runtime consumes a valid pair,
  closes the descriptor, and fails closed because no reviewed exit backend exists. This blocks
  service enablement and package release;
  the unit must not be treated as operational.

Review `systemd-analyze verify`, `systemd-analyze security`, and functional tests in an installed
Debian 13 package root. Do not enable the service set while the native launch contract above is
unresolved:

```sh
systemd-analyze verify volparossa-helper.service volparossa-agent.service volparossa-mpquic.service
systemd-analyze security volparossa-helper.service volparossa-agent.service volparossa-mpquic.service
```

Hardening is not a substitute for helper input validation. If a needed syscall/capability is found,
document the failing operation and narrowly adjust the unit; do not disable the sandbox wholesale.

## Normal CLI lifecycle

The required CLI surface is:

```text
volparossa init                 volparossa doctor
volparossa start                volparossa stop
volparossa status               volparossa connect
volparossa disconnect           volparossa peers
volparossa paths                volparossa sessions
volparossa policy status        volparossa policy verify <file>
volparossa role show            volparossa role enable|disable relay
volparossa role enable|disable exit
volparossa config validate      volparossa logs
volparossa cleanup              volparossa demo
```

`role enable exit` must require explicit valid policy and non-zero configured exit capacity;
installation never enables it. Relay enablement similarly requires explicit capacity, and either
service role requires the explicit `network.operator_id` described above. `status`,
`paths`, and `sessions` distinguish configured, validated, active, and real data-carrying paths and
separate user bytes from tunnel bytes. Output never contains private keys.

At present, a production `connect` cannot complete: real two-leg probe production, helper
`Prepare`, complete agent orchestration, and client ingress all return or remain
`Unavailable`/blocked. Operators must not interpret successful configuration, v4 peer-codec tests, or
service role state as an active route.

## Crash and cleanup

The target behavior is Destroy-first. From successful helper `Prepare`, a cancellation-safe
supervisor retains the exact opaque cleanup authority. On rejection, expiry, cancellation, received
backend `Unavailable`, disconnect, or crash, helper Destroy must succeed or prove absence before
the client releases coordinator state, endpoint leases, or remote reservation authority. An
ambiguous or failed Destroy keeps the authority quarantined for retry. Expiry blocks new flows but
does not authorize forgetting host state.

The current helper v3 does not yet provide complete crash recovery or restart cleanup.
Before rotating its cleanup token or touching its socket, it rejects every object at the retired
`/run/volparossa/helper.ownership-v1` path and starts the canonical v3 journal actor. That actor may
durably settle a never-dispatched `Intent`. It may also retire a complete set of already durable
`CleanupConfirmed` records only when inherited custody is empty and a revalidated fresh manager
barrier plus two stable snapshots prove the complete descriptor store remains exactly empty. A
`MayOwnCustody` or `MayOwnPrepare` remains byte-identical and blocks startup because production has
no worker/kernel absence-proving recovery executor. Never remove a journal object
merely to bypass this interlock: stop and inspect until a supported reaper exists.

The boot-scoped v3 module has a canonical, bounded, secret-free codec/CAS store with
file-sync/rename/directory-sync ordering and failpoint tests. Production owns its startup/shutdown
actor but exposes no complete absence-proving recovery backend, restart reaper, or cross-runtime
tag-28 proof. Journal absence is not cleanup evidence; the narrow manager proof applies only after
durable `CleanupConfirmed`. The current `doctor`
also has no helper-v3 crash-ownership readiness check, so other passing checks do not make cleanup
ready.

A future explicit cleanup must preview generated namespaces, interfaces, route tables, marks, and
nftables objects without secrets and ask before a root action. Re-running it must be safe.

The acceptance topology has no standalone cleanup mode: a later supervisor may delete only an
exact object recorded by its current run and only after the current namespace mount still matches
the recorded device and inode. A name or prefix match is never ownership proof. Its inner worker is
fixed repository code reached through inherited IPC and cannot be replaced with an environment or
command-line supplied program.

Do not manually run broad `ip netns delete`, nftables flush, route flush, or interface wildcard
commands. If verified cleanup is unavailable, stop and inspect with read-only commands rather than
risk unrelated host state.

## Uninstall and data removal

First use the product's scoped cleanup while the package/helper still exists, then remove services:

```sh
volparossa disconnect
volparossa cleanup
sudo systemctl disable --now volparossa-agent.service volparossa-mpquic.service volparossa-helper.service
sudo apt remove volparossa
```

Package removal preserves `/var/lib/volparossa` because it contains the encrypted permanent identity
and local peer history. Back up the encrypted identity if desired. Only after verifying there is no
needed identity and no owned network state should an operator explicitly remove `/var/lib/volparossa`
and `/etc/volparossa`; this is irreversible. Package maintainer scripts must not flush host routing or
firewall state.

## Diagnostics and privacy

Prefer `volparossa doctor`, stable structured codes, aggregate metrics, and `journalctl -u` output.

### Local metrics

When `privacy.metrics_enabled` is true, the agent serves Prometheus text at
`http://127.0.0.1:<privacy.metrics_port>/metrics` (default port `9767`). The address is hard-coded
to IPv4 loopback; only the non-zero port is configurable. The endpoint has bounded request size,
concurrency, and time-outs, and exports no labels, peer IDs, route IDs, hostnames, destination
addresses, URLs, or payload data. Disable it with `privacy.metrics_enabled: false`; no listener is
created in that mode.

Never publish an identity file, passphrase, WireGuard key, full hostname, destination IP, DNS history,
payload, or unredacted packet capture. The system checker emits no secrets. There is no external
telemetry or update channel.
