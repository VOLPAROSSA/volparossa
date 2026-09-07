# Debian 13 operations

This guide targets Debian 13 (Trixie) amd64 with systemd, nftables, kernel WireGuard, and kernel
MPTCP. It is not a release announcement. Do not enable services or route sensitive traffic until
the relevant checks in [IMPLEMENTATION_STATUS.md](IMPLEMENTATION_STATUS.md) are complete.

The original v1 datapaths and A01--A15 passed together on the unchanged `482e33d0` build in
[the retained Debian 13 KVM run](https://github.com/VOLPAROSSA/volparossa/actions/runs/34047766913).
That functional checkpoint does not certify an arbitrary host installation, every later extension,
or release readiness. Consult the current status and each feature's scoped evidence separately.

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

The dependency gate is offline and requires `cargo-deny >= 0.18.6`,
`cargo-audit >= 0.22.1`, and an existing local RustSec advisory checkout. It
reconstructs and verifies the two
Debian-Rust-compatible source backports plus the reviewed single-backend Yamux
override before applying the documented scanner exemptions; see
`third_party/rust/README.md`.

`just package-deb` and `./packaging/build-deb.sh` are non-writing previews. Building requires the
explicit `./packaging/build-deb.sh --build` form and refuses to run as root or overwrite an existing
candidate. A combined client/exit node runs two immutable-role native workers under one service;
its Client socket is `VOLPAROSSA_MPQUIC_SOCKET`, and its Exit socket appends `.exit` to that path.

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
fixed regular file with `O_NOFOLLOW`, accepts either owner-only mode or systemd's exact
root-owned `0440` named-user ACL projection, enforces a strict length bound, and zeroizes the
temporary bytes. Missing or unsafe credentials make startup fail closed. Protect the
encrypted credential and identity file together when backing up or rotating the permanent
identity. This provisioning flow still requires a Debian 13 systemd integration test before a
package is declared releasable.

The packaged example keeps all roles off, the kill switch on, direct-exit debug off,
plain-TCP fallback off, required MPQUIC paths at two or more, and policy fail-closed. An empty policy
path means connections fail closed; it is not an allow-all policy.

Production client participation always requires `roles.relay` and positive relay capacity. With
`network.uplink: independent_internet` (the default), consumers must also explicitly enable
`roles.exit`, with positive exit capacity and a valid policy. With `network.uplink: local_only`,
consumers configure client + relay and must keep exit disabled in production and development:
Internet access obtained through the overlay must never be offered back as an independent exit.
The uplink setting is an operator declaration of available capability, not runtime connectivity
proof, an uptime measurement, or automatic outage detection. Offline consumption and simultaneous
relay contribution have separate disposable Ethernet and simulated-radio proofs; see
[local-link scope](LOCAL_LINK_NETWORK.md). Configuration validation alone is still not datapath
evidence, and simulated radios do not establish compatibility or performance on physical Wi-Fi.

Installing or initializing the package does not consent to Internet egress. Configure those
responsibilities in `/etc/volparossa/config.yaml`, run `volparossa config validate`, then start the services or
restart them after changing an existing configuration. Role-isolated development fixtures are
not a client-only production participation option.

Privacy-v4 is a hard-incompatible migration: set `network.protocol_version: 4`. Signed peer
control and `/volparossa/advertisement/4` accept exactly v4; v1, v2, v3, zero, and future values are
rejected without negotiation or fallback. The retired direct exit/relay/confirmation v2 protocol
IDs are never registered. This does not retire the independently versioned threshold policy
manifest v2 or libp2p Circuit Relay v2, which remains control-plane connectivity only.

The default dormant configuration may leave `network.operator_id: null`. Enabling relay or exit
instead requires an explicit operator ID of 1..=128 ASCII letters, digits, `-`, `_`, `.`, or
`:`. An independent-Internet service node also needs a non-zero `advertised_asn` and at least one
canonical `advertised_ipv4_prefix` (`/24`) or `advertised_ipv6_prefix` (`/48`). Local-only nodes may
leave ASN at zero and prefixes unset; do not fabricate public origin information. Any supplied
prefix must still be canonical. Region and two-letter country claims are explicit untrusted
diversity hints. Unknown configuration fields remain rejected.

Relay and exit runtimes publish those short-lived signed service claims and provider indexes while
capacity and policy remain active. Publication does not claim helper preparation, Fresh evidence or
route usability. The agent never substitutes a static or placeholder WireGuard key, listen port,
probe, or activation receipt.

The client chooses a directly verified control relay before any exit. Direct
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
  descriptors for at most 64 pidfd/network-namespace custody pairs. Production seals, duplicates
  and structurally validates inherited activation groups before Tokio. Durable Prepare publication
  uses `FDPOLL=0`, a manager barrier and complete post-barrier store-inventory attestation before
  arming. Startup correlates the durable journal with inherited custody and settles supported
  exact recovery states before socket bind. Ambiguous or unsupported custody still fails closed;
  do not remove journal entries or stored descriptors to force startup;
- `volparossa-agent.service`: user/group `volparossa`, no capabilities, persistent state/config,
  control-plane network access, the helper socket, and an agent-owned mode-0660 socket under a
  non-group-writable `/run/volparossa/control`; the unit loads only the named encrypted identity
  credential;
- `volparossa-mpquic.service`: unprivileged Client and Exit role workers, not a release-security claim.
  API v6 preflights one client or exit role/process lifetime, targets that instance thereafter, and
  correlates every response to the exact canonical request. It accepts exact 43-character
  base64url client auth and TLS names only in bounded, signed-scope route-session messages; the
  native commitment check proves bearer equality, not generator entropy or binary attestation.
  `AddPath` consumes exactly one request-bound UDP descriptor and native never creates or binds a
  path socket. The agent passes helper-prepared descriptors through the role-specific native
  socket. Combined roles have
  separate native workers and sockets under one same-UID service; separate service identities
  remain required before an untrusted agent can use this as an authenticated boundary.
  `StartExitSession` carries bounded, unparsed in-memory TLS candidate material and consumes exactly
  one caller-supplied, pre-bound IPv6 UDP descriptor whose current tuple and flags are checked by
  Rust and native. Those descriptor checks do not prove assigned-address or network-namespace
  state. Native converts the supplied wall expiry to a BOOTTIME deadline and keeps a bounded,
  process-local reservation/finalize ledger with no live eviction; it rejects pair replay and
  one-ID scope collisions, but does not independently verify the reservation signature or general
  nonce freshness, and restart clears the ledger. The Exit backend now runs the pinned mqvpn/xquic
  server, accepts authorized path listeners and exchanges protected datagrams with the agent's
  policy-controlled egress. The original v1 KVM checkpoint exercised this real backend; it is no
  longer a dormant descriptor-closing stub. This does not independently certify the installed
  service's security boundary or make the package release-ready.

Review `systemd-analyze verify`, `systemd-analyze security`, and functional tests in an installed
Debian 13 package root before operational deployment; passing the disposable topology does not
replace those checks on the actual installation:

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
volparossa role enable|disable client|exit
volparossa config validate      volparossa logs
volparossa cleanup              volparossa demo
volparossa content publish      volparossa content assemble
volparossa content recipient-key
volparossa content publish-message    volparossa content open-message
```

Role commands validate the proposed change but effective changes require editing configuration
and restarting the service: the current agent returns `ROLE_RESTART_REQUIRED`, without silently
changing its active protocols or persisted roles. `role enable client` alone on a dormant
production node returns `ROLE_PREREQUISITES`; it never silently enables relay or exit service.
Exit enablement requires an independent uplink, explicit valid policy, and nonzero configured
capacity. Relay enablement requires explicit capacity, and both service roles require the operator
identity described above.
`status`,
`paths`, and `sessions` distinguish configured, validated, active, and real data-carrying paths and
separate user bytes from tunnel bytes. Output never contains private keys.

With valid participation, policy, discovery and helper configuration, `connect` can complete the
signed reservation, helper preparation/activation, native transport and ingress chain. Select the
intended transport explicitly:

```sh
volparossa connect --transport mptcp
volparossa connect --transport single-path-udp
volparossa connect --transport multipath-quic
```

These are alternative route requests, not instructions to run all three simultaneously. The default
is `single-path-udp`; MPTCP and required Multipath QUIC do not silently fall back to ordinary TCP or
single-path QUIC. The original v1 checkpoint exercised the real client--relay--exit datapaths.
Unavailable peers, policy, capacity or required paths still cause explicit failure. Do not interpret
a Permit, valid configuration, signed advertisement or role state alone as a usable route.

## Offline content commands

`content publish` and `content assemble` work locally without starting services, opening network
listeners or contacting peers. Run them as the existing identity/cache owner in caller-chosen local
directories. Publishing unlocks the existing encrypted Ed25519 identity; it neither generates a new
permanent identity nor exports a private key. These commands authenticate native publisher content,
not an HTTPS origin, a latest-version name lookup or network distribution.

For an explicit regular input file, choose a new cache directory and new manifest path:

```sh
volparossa content publish \
  --identity /path/to/existing/identity.key \
  --input ./notes.pdf --cache ./content-cache --manifest ./notes.v1.pb \
  --name notes --revision 1 --content-type application/pdf
```

The command prompts for the existing passphrase without echo. Alternatively, `--passphrase-file`
may name an already provisioned strict `0600` regular file; never put the secret itself in arguments
or environment variables. Omitting `--identity` uses the normal node identity path. Successful JSON
output includes the publisher's public key, byte/chunk count and expiry, with
`network_publication: false`.

Defaults are a 24-hour signed lifetime (`--lifetime-seconds`, maximum 31 days), a 256-MiB payload
quota per cache (`--quota-bytes`), 4096 indexed chunks (`--max-entries`, maximum 65536), and a 64-MiB
free-space floor (`--min-free-bytes`). Each object is limited to 256 MiB, in chunks of at most
256 KiB. Cache hits do not renew a manifest's validity. A failed publish may leave owned,
quota-accounted chunks, but never a successful final manifest for an incomplete operation.

For another publication in that same cache, explicitly add `--reuse-cache` and choose a new manifest
path and revision. Reuse accepts only a verified owned `ChunkStore`; it never adopts an arbitrary
directory. Applying its byte/entry quotas may evict older **owned** chunks. Without this flag,
an existing cache directory is rejected. Existing manifest files are never overwritten.

To reconstruct, obtain the publisher's 64-character hexadecimal public key through an independently
trusted channel. Replace `TRUSTED_PUBLISHER_PUBLIC_KEY_HEX` below; do not trust a key merely because
the supplied manifest or a provider contains it:

```sh
volparossa content assemble \
  --manifest ./notes.v1.pb --publisher-key TRUSTED_PUBLISHER_PUBLIC_KEY_HEX \
  --cache ./content-cache --output ./restored-notes.pdf
```

Repeat `--cache` for up to 16 explicitly owned local caches when chunks are split between them.
The same quota options apply when opening each cache; an oversized existing cache is rejected,
not silently evicted to fit. The command verifies the exact manifest, publisher, expiry and chunk
hashes, and exposes a new `0600` output atomically only after complete reconstruction. Wrong keys,
expired manifests, absent/corrupt chunks and an existing output are errors. No peer discovery or
network retrieval occurs; successful output explicitly reports `network_retrieval: false`.

### Recipient-encrypted message commands

These commands use the existing encrypted node identity; they do not create a separate plaintext
recipient key file, start networking, or capture application messages. First, the recipient runs:

```sh
volparossa content recipient-key --identity /path/to/recipient/identity.key
```

Share `recipient_public_key_hex` with the sender through an independently authenticated channel.
This X25519 encryption key is **not** the Ed25519 signing key. The JSON also identifies the node's
public signing key, but does not itself authenticate that association for a remote party.
The sender encrypts an explicit regular file of at most 4 MiB before caching any bytes:

```sh
volparossa content publish-message \
  --identity /path/to/sender/identity.key \
  --recipient-key TRUSTED_RECIPIENT_PUBLIC_KEY_HEX \
  --input ./message.txt --cache ./encrypted-message-cache --manifest ./message.pb
```

The signed manifest uses a random opaque name and contains no subject or recipient identifier.
Sender identity, ciphertext length and expiry remain public. The existing lifetime/cache limits
and explicit `--reuse-cache` option apply. Publishing is local: use the existing `content serve`
command with this manifest/cache and the sender's signing key to make ciphertext available.
Recipients must receive the exact manifest and authenticate the sender key independently; there
is no mailbox or automatic name/key lookup. `content fetch` can retrieve the ciphertext through
the existing protected route into a new owned cache/output. That fetched output is still encrypted.
Once the needed chunks are present in owned caches, the recipient opens the message:

```sh
volparossa content open-message \
  --identity /path/to/recipient/identity.key \
  --manifest ./message.pb --sender-key TRUSTED_SENDER_PUBLIC_KEY_HEX \
  --cache ./retrieved-ciphertext-cache --output ./received-message.txt
```

Repeat `--cache` for partial stores. The command checks the sender, validity, every chunk and the
encrypted envelope before writing plaintext to a new `0600` output. It never emits plaintext on
stdout or writes it back to the shared cache. Existing outputs are never overwritten. All three
commands support the same strict `--passphrase-file` option as `content publish`.

The recipient key is reproducible from the existing encrypted identity using a versioned,
domain-separated RFC 9180 derivation. Changing its passphrase preserves the key; **rotating or
losing the identity loses access to old messages unless the old encrypted identity is retained**.
Use `--identity` to select such a retained copy explicitly. One identity has one recipient key,
not one per local profile. Identity compromise also compromises these messages; there is no
ratchet, forward secrecy, delivery acknowledgement, guaranteed retention or email interoperability.

### Explicit protected content service and retrieval

The development runtime now also has `content serve`, `content fetch`, `content status` and `content stop`.
Compilation and focused tests pass; the independent-node network acceptance run is pending.
Use a disposable topology while this integration is under development. These commands talk to
the already running unprivileged agent (`--control-socket` can select its socket); they neither
unlock another private key nor install/change the host network.

A provider needs an existing cache created by the **agent account**, an independently trusted
publisher key, and an explicitly chosen reachable bind address/DNS name. That hostname and TCP
port must already be allowed by the threshold-signed Exit policy; an offer does not create an
allowlist entry. Do not copy/chown an owned cache as a provisioning shortcut. Use caller-chosen
paths accessible inside the agent's service sandbox. For example, after provisioning those
prerequisites, substitute the actual addresses and paths:

```sh
volparossa content serve \
  --manifest /agent-accessible/notes.v1.pb --publisher-key TRUSTED_PUBLISHER_PUBLIC_KEY_HEX \
  --cache /agent-owned/replica-cache --bind PROVIDER_BIND_IP:18080 \
  --advertised-hostname provider.example

volparossa content fetch \
  --manifest ./notes.v1.pb --publisher-key TRUSTED_PUBLISHER_PUBLIC_KEY_HEX \
  --cache /agent-owned/new-retrieval-cache --output /agent-owned/restored-notes.pdf

volparossa content status
volparossa content stop
```

Serve announces a five-minute node-signed generic service offer and refreshes it while active.
Repeat it with the same endpoint for up to 64 explicit manifests; a cache may hold only some
chunks. Fetch asks an authenticated control Relay for at most 16 provider hints, validates their
signatures and opens policy-authorized MPTCP/TLS streams through the normal Relay/Exit route.
It does not connect directly to provider endpoints or use ordinary TCP as a fallback. The
selected route's Exit and Relays are excluded as content suppliers in this initial runtime.

Fetch requires a **new** cache by default and always a **new** output path; it verifies every chunk
and the whole object before publishing output. To resume an interrupted `content fetch` or
`content fetch-https`, repeat the same command with `--reuse-cache`, the original agent-owned cache
path and an output path that does not exist. Only missing chunks are requested; already verified
chunks are reopened with the original ownership/index checks, not copied, chowned or adopted from
an arbitrary directory. Reuse does not overwrite output or authorize a publisher: native fetch
reverifies the supplied manifest/key, and HTTPS fetch authenticates fresh same-origin metadata
before using any cached chunks. The original signed/HTTP expiry is never extended by cache reuse.
Normal quota enforcement still applies and can evict unrelated older cached chunks.
Missing data causes failure, retaining any verified owned cache data;
this native command does not yet compose the separate HTTPS-origin fallback API. Its explicit
JSON receipt includes reconstructed bytes/chunks and the unique supplying `provider_peer_ids`;
those identifiers are not written to a background browsing log.
Status inspects only retained local state, including `control_relay_peer_id`; it opens no
network connection or route. Fetch's receipt binds that same control identity. Stop withdraws the offer and
closes the listener but retains the owned cache files. Registration is in memory, not durable
publication retention. Without the explicit replica configuration below, these commands start
no background copying. They never capture browsing, resolve latest publication names or promise
faster retrieval.

For the first development-only redistribution integration, add `--replica-cache /agent-owned/new-extras`
to `content serve`. The directory must be new, private to the agent and different from the
existing publication cache. Optional limits are `--replica-quota-bytes` (default 64 MiB, at most
256 MiB), `--replica-max-entries` (default 256), `--replica-max-bytes` (64 bytes through 1 MiB,
default 1 MiB of protocol traffic) and `--replica-max-chunks` (1--4, default 4). Repeated Serve
registrations use the same replica configuration; changing it requires stopping the service.

The job starts only after a successful native/HTTPS content fetch has actually received verified
chunks from a provider. Both `sharing` and `download_sharing` must be explicitly configured and
enabled, with meaningful link capacities and the real carrying interfaces. Unknown/down/overlay
interfaces or a busy preflight sample cause uptake to pause; no host configuration is changed by
the sampling itself. The receiver uses protocol v3: after each received chunk the provider must
wait for a new one-chunk credit. A fresh sample of the configured links precedes that credit;
a busy or unavailable sample sends stop and retains verified partial chunks for re-serving.
Credit, stop and finish framing share the original protocol budget/deadline. There is no silent
fallback to the unsolicited v2 exchange. New foreground content operations cancel background
uptake. One already credited chunk can still overlap new demand; unmeasured links, per-flow
owner accounting and radio contention are not covered. This is not the full C04 fairness proof.

`content status` reports `replication_enabled` separately from actual retained `replica_chunks`,
`replica_bytes` and registered `replica_publications`; an enabled job is not evidence of useful
replication. Busy cache access returns Busy rather than a fabricated count. Stop cancels the job
and withdraws the service, retaining owned cache files. Replica registration is not yet durable
across restart; this is not a reliable offline hosting/retention service. Use disposable topology
probes while the independent-node C02/C03 proofs remain incomplete.

## Crash and cleanup

Route teardown is Destroy-first. From successful helper `Prepare`, a cancellation-safe supervisor
retains the exact opaque cleanup authority. Rejection, expiry, cancellation, disconnect and failure
must settle helper-owned state before coordinator resources or remote reservation authority are
released. Ambiguous or failed destruction keeps the route quarantined; expiry is not permission to
forget network state.

The helper's boot-scoped v3 ownership journal and systemd descriptor custody are live. Startup
revalidates the journal and complete inherited inventory before serving requests; supported recovery
uses the authenticated restart reaper and exact namespace/descriptor ownership rather than names
or prefixes. Durable cleanup confirmation and descriptor-store settlement precede reuse.
Unsupported or inconsistent recovery states still refuse startup. Never delete a journal, remove
custody descriptors or rotate a cleanup token merely to bypass that refusal.

Crash recovery is no longer an untested placeholder: the retained A14/A15 evidence on
[`482e33d0`](https://github.com/VOLPAROSSA/volparossa/actions/runs/34047766913)
includes 25 forced crashes, helper restart recovery, zero remaining owned objects, namespace
references and descriptors, and unchanged guest state. This is evidence for the exercised Debian 13
topology and build, not every possible disk corruption, boot transition or installed-package
recovery scenario. `doctor` prerequisites and a missing journal are not independent cleanup proof.

Keep the service fail-stop contract intact. Helper exit status 70 marks a terminal startup
fail-stop; status 71 marks diagnostic live-proof setup ambiguity. The packaged unit excludes both
from automatic restart. Inspect the journal and service logs rather than repeatedly restarting or
loosening systemd's cgroup retirement settings to hide the failure.

Use the normal scoped cleanup lifecycle while the helper is still installed:

```sh
volparossa cleanup
volparossa cleanup --execute
```

The first command previews the service/resource scope. The explicit execution requests agent
Disconnect, stops the VOLPAROSSA service set and triggers helper shutdown cleanup. It is not a
generic repair tool for an unrecognized journal or unrelated host resources. Check the resulting
status and cleanup evidence before declaring resources absent.

Acceptance networking remains confined to disposable namespaces. A later supervisor may delete
only an exact object recorded by its current run, after checking its namespace device/inode;
a name or prefix alone is not ownership proof. Do not manually run broad `ip netns delete`,
nftables flush, route flush or interface wildcard commands. When exact cleanup cannot be verified,
stop and inspect read-only instead of risking unrelated host state.

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
