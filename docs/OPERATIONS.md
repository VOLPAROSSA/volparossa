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
0700, `/etc/volparossa` mode 0750, `/run/volparossa` root/service mode 0750, a separate
agent-owned `/run/volparossa/control` mode 0750 that members of `volparossa-users` may traverse,
and a service-only native socket directory. Human control users can connect to the group-writable
agent socket but cannot replace it or access/unlink the helper socket. Installation does not
enable agent/helper services. journald is the default; no file log or logrotate configuration is
enabled. A search-only access ACL on `/run/volparossa` lets `volparossa-users` reach the
control subdirectory without listing the parent or inheriting access to helper/native files.
This uses Debian 13's [tmpfiles access-ACL support](https://manpages.debian.org/trixie/systemd/tmpfiles.d.5.en.html).

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

## Shared positive DNS cache

UDP and TCP DNS ingress share a dedicated, bounded protected association, separate from the
main data/content route. Normal DNS ingress prepares it on demand. To inspect readiness explicitly:

```sh
volparossa connect --transport protected-dns
volparossa paths
```

This selects a real Client--Relay--Exit route; `Reachable` with zero bytes/RTT is readiness,
not a successful DNS response. Each DNS association is retired after its response. A subsequent
query may select a new route. `disconnect`, shutdown and policy/client disablement retire both
client-route owners; retiring one DNS context does not remove the main route's path projection.

The agent can reuse independently validated positive DNSSEC A/AAAA answers at the Exit. It keeps
proofs only in bounded RAM; disabling/restarting it does not leave a DNS-history database. Existing
destination policy, protected DNS ingress and exact destination pinning still apply.

The default configuration is:

```yaml
dns_cache:
  enabled: true
  upstream: null
```

This enables no network role and selects no public DNS provider. To collect shareable proofs,
set `upstream` to an existing recursive resolver that you already trust and that accepts DNS over
TCP on port 53. For example, `127.0.0.53:53` is appropriate only if such a listener actually exists
in the agent's network namespace; VOLPAROSSA does not install or reconfigure it. Restart the agent
after an explicit configuration change. A null endpoint retains peer-proof reuse and the existing
OS-resolution fallback; `enabled: false` retains the old resolver path without cache exchange.

Peer signatures authenticate the transport peer, not the DNS answer. Every usable peer proof must
validate against the built-in DNSSEC root anchors. Unsigned, missing or unsupported evidence falls
back to existing resolution and is not shared as validated data. Cache peers never perform an
upstream lookup on another peer's cache miss. Names are not published in the DHT or product logs;
the authenticated cache peer serving a question necessarily sees that question. Involved route
relays are excluded from those requests. CNAME and negative-answer sharing remain outside this
initial positive-answer implementation. See the source-bound
[implementation status](IMPLEMENTATION_STATUS.md); the complete two-Exit network proof is pending.

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

### Moving an explicit public publication to or from the service

The agent runs as a different account and must not open your private cache directory directly.
Use its protected local control socket to copy one complete, explicitly selected native object:

```sh
volparossa content import --public-content \
  --manifest ./notes.v1.pb --publisher-key TRUSTED_PUBLISHER_PUBLIC_KEY_HEX \
  --cache ./content-cache --agent-cache /var/lib/volparossa/new-notes-cache
```

The agent-owned destination must be new and its parent already agent-writable. You can then
explicitly `content serve` that cache with the same manifest/key and an authorized endpoint.
Import itself does not start serving. Conversely, after `content fetch` has completed into an
agent-owned native cache, copy it to your account and use normal offline reconstruction:

```sh
volparossa content export --public-content \
  --manifest ./notes.v1.pb --publisher-key TRUSTED_PUBLISHER_PUBLIC_KEY_HEX \
  --agent-cache /var/lib/volparossa/fetched-notes-cache --cache ./received-notes-cache
volparossa content assemble \
  --manifest ./notes.v1.pb --publisher-key TRUSTED_PUBLISHER_PUBLIC_KEY_HEX \
  --cache ./received-notes-cache --output ./received-notes.pdf
```

Both directions require `--public-content` for ordinary native content; the default only accepts
recipient-encrypted messages. All chunks and the whole object hash are verified, including empty
objects, within the existing 256-MiB object bound. New destination caches remain `0700` and are
never adopted or overwritten. Failed transfers may retain verified partial chunks, not a success
receipt. No key, ownership or permission change occurs. `public_content: true` means you explicitly
selected an ordinary native object; it does not mean a peer may automatically publish browsing data.
Native signatures are not HTTPS origin authentication. This command does not export an authenticated
HTTPS descriptor or make arbitrary cached HTTPS responses shareable.

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
and explicit `--reuse-cache` option apply. Publishing is local. The packaged service runs as
`volparossa`, not your user account, so first copy ciphertext through its protected local socket:

```sh
volparossa content import --manifest ./message.pb --publisher-key TRUSTED_SENDER_PUBLIC_KEY_HEX \
  --cache ./encrypted-message-cache --agent-cache /var/lib/volparossa/new-message-cache
```

The agent cache must be a new path with an existing agent-writable parent. Use `content serve`
with that agent-owned cache, the same manifest and sender key, and a policy-authorized endpoint
to make ciphertext available. Import itself starts no network service and transfers no keys.
For this explicit-object workflow, recipients must receive the exact manifest and authenticate
the sender key independently. The separate mailbox workflow below removes the per-message
manifest handoff, not the need to authenticate contacts. `content fetch` can retrieve the ciphertext through
the existing protected route into a new agent-owned cache/output. That fetched output is still
encrypted. Export its ciphertext to a new cache owned by the receiving user:

```sh
volparossa content export --manifest ./message.pb --publisher-key TRUSTED_SENDER_PUBLIC_KEY_HEX \
  --agent-cache /var/lib/volparossa/fetched-message-cache --cache ./retrieved-ciphertext-cache
```

Import/export accept complete recipient-encrypted messages by default (at most 4 MiB of
plaintext plus the bounded encrypted envelope), not partial caches. Ordinary native public
objects require the separate explicit `--public-content` flag described above; that flag never
bypasses envelope validation for the exact private-message content type.
They preserve each account's `0700` cache ownership and do not change permissions. No destination
cache is reused or overwritten. A failed transfer may leave verified encrypted chunks in its
new destination; it never reports them as a complete message. This is local ciphertext copying,
not recipient authentication, decryption, a network transfer or a delivery acknowledgement.
Once the needed chunks are present in user-owned caches, the recipient opens the message:

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

### Known-contact mailboxes

`content mailbox` adds a private inbox to the existing protected content service. It is an
explicit development feature: use disposable test nodes until its normal-network scenario has
passed. There is no automatic contact lookup, SMTP delivery, background boot activation or
promise of permanent availability. Existing encrypted identities remain in the calling user's
account; providers and the agent receive neither passphrases nor recipient decryption keys.

First select **two independently authenticated provider Ed25519 keys** and a known sender's
Ed25519 key. Distinct keys alone do not prove independent operators or failure domains.
Each provider explicitly starts its mailbox service using its normal agent socket:

```sh
volparossa content mailbox serve --bind 0.0.0.0:7443 \
  --advertised-hostname mailbox.example.net --cache /var/lib/volparossa/mailbox-cache
```

The hostname/port must already be authorized by the common signed Exit policy. The cache parent
must be agent-writable. Use a new cache initially; after `content stop` or restart, add
`--reuse-cache` to reopen only that same owned store. A mailbox can attach to an already running
public content service only at its exact existing bind and advertised endpoint. Otherwise stop
that service first. `content stop` stops both services while retaining their owned cache files.

The recipient creates an invitation using an existing encrypted identity and registers it:

```sh
volparossa content mailbox invite --identity /path/to/recipient/identity.key \
  --sender-key TRUSTED_SENDER_PUBLIC_KEY_HEX \
  --provider-key TRUSTED_PROVIDER_A_KEY_HEX --provider-key TRUSTED_PROVIDER_B_KEY_HEX \
  --invitation ./invitation.pb
volparossa content mailbox enroll --identity /path/to/recipient/identity.key \
  --invitation ./invitation.pb
```

Give the invitation privately to that sender, who must independently authenticate the recipient's
Ed25519 key. The invitation binds the recipient encryption key, sender, exact providers, an opaque
inbox ID, original expiry and limits. It is not a registration receipt. Enrollment succeeds only
after two actual signed provider confirmations; registration does not reserve future disk space.
Defaults are seven days, 64 MiB and 64 messages per invitation; acknowledged-message records count
against the message limit until their original expiry. Limits cannot be silently renewed.

The sender encrypts and deposits an explicit file, at most 4 MiB:

```sh
volparossa content mailbox send --identity /path/to/sender/identity.key \
  --invitation ./invitation.pb --owner-key TRUSTED_RECIPIENT_SIGNING_KEY_HEX \
  --input ./message.txt --cache ./outgoing-ciphertext --manifest ./outgoing-message.pb
```

Success requires two signed storage confirmations after durable writes. Keep the original local
manifest/cache until that succeeds. If a connection fails after one provider stored the message,
repeat with `--resume` and the same invitation/cache/manifest, omitting `--input`. That retries the
same message rather than producing a duplicate. Storage receipts attest to the operation then;
they cannot prove future reachability or force a dishonest provider to keep bytes.

The recipient needs only its identity and original invitation, **not a message ID or manifest**:

```sh
volparossa content mailbox receive --identity /path/to/recipient/identity.key \
  --invitation ./invitation.pb --output-dir ./new-inbox
```

The command asks both enrolled providers for signed private inbox metadata and accepts at least
one valid list; `listed_providers` and `degraded` expose a missing provider rather than claiming
the complete network inbox was checked. It verifies sender and original expiry, tries the other
provider if retrieval fails, and decrypts locally. It creates a new `0700` directory
and `0600` files named only by opaque message IDs; existing outputs are never overwritten.
Only after a complete verified file is durably written does it acknowledge that exact message
at both providers. An interrupted or partially acknowledged receive preserves already written
files and reports the incomplete operation; it does not claim two confirmations. Provider
tombstones prevent an acknowledged message from returning through a sender retry.
An exact `send --resume` after acknowledgement reports `already_acknowledged_providers`, not
renewed storage; `retained_providers` counts only actual still-retained copies.

Provider storage is bounded to 16 invitations and a shared configurable payload quota of at most
256 MiB, also respecting the configured free-space reserve. It refuses excess deposits rather
than evicting unexpired accepted mail to admit another sender. Expiry removes retained messages;
acknowledgement can free their ciphertext earlier. There is no automatic replica repair, global
fairness/Sybil guarantee or remote secure-deletion guarantee. Providers see pseudonymous contact
keys, opaque IDs, length, expiry and operation timing; do not infer metadata anonymity or forward
secrecy from encryption. Private inbox names and message IDs are not published into Kademlia or
the public-name service. All identity commands support the existing strict `--passphrase-file`.

The additive disposable-VM acceptance scenario is `content-mailbox`; inspect it without changing
network state with `tests/integration/run-alpha-topology-vm.sh --preview --scenario content-mailbox`.
It exercises separate storage agents and distinct sender/recipient applications using one Client
agent, not two independently located client nodes. A local checker pass is not a passing VM run.

### Explicit protected content service and retrieval

The development runtime now also has `content serve`, `content fetch`, `content status` and `content stop`.
Compilation and focused tests pass. The
[exact `10f63244` independent-node run](https://github.com/VOLPAROSSA/volparossa/actions/runs/34178615941)
also passes native and cooperative HTTPS retrieval, plus normal user publication/import,
service serving, independent retrieval and user export/assembly. This is a scoped command-path
result, not complete C02, generic browser integration or guaranteed availability.
Use a disposable topology while this integration is under development. These commands talk to
the already running unprivileged agent (`--control-socket` can select its socket); they neither
unlock another private key nor install/change the host network.

A provider needs an existing cache created by the **agent account**, an independently trusted
publisher key, and an explicitly chosen reachable bind address/DNS name. That hostname and TCP
port must already be allowed by the threshold-signed Exit policy; an offer does not create an
allowlist entry. Do not copy/chown an owned cache as a provisioning shortcut. Use caller-chosen
cache/output paths accessible inside the agent's service sandbox. The CLI reads and verifies
`--manifest` itself, so that file must be readable by the calling user. After provisioning those
prerequisites, substitute the actual addresses and paths:

```sh
volparossa content serve \
  --manifest ./notes.v1.pb --publisher-key TRUSTED_PUBLISHER_PUBLIC_KEY_HEX \
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
closes the listener but retains the owned cache files. Primary publications must be explicitly
registered again; this is not automatic publication retention. Without the replica configuration below, these commands start
no background copying. They never capture browsing or promise faster retrieval.

#### Retrieving a native publication by publisher and name

Public native publications can also be retrieved without distributing a manifest file first.
The provider must explicitly enable name lookup when starting its service:

```sh
volparossa content serve --name-lookup \
  --manifest ./notes.v1.pb --publisher-key TRUSTED_PUBLISHER_PUBLIC_KEY_HEX \
  --cache /agent-owned/replica-cache --bind PROVIDER_BIND_IP:18080 \
  --advertised-hostname provider.example

volparossa content fetch-name \
  --publisher-key TRUSTED_PUBLISHER_PUBLIC_KEY_HEX --name notes --min-revision 1 \
  --cache /agent-owned/new-named-cache --local-output ./notes.pdf
```

Use the exact name originally supplied to `publish`, including case and UTF-8 bytes.
The publisher key must be authenticated independently; providers never supply that trust.
`--name-lookup` is a service-wide choice, unchanged across additional registrations; stop and
restart to change it. It does not enable background replication or expose private-message names.
Existing hash-only serving remains the default.

The agent asks at most 16 existing providers over its protected route, verifies their original
signed manifests, and retrieves the highest valid **observed** revision. Names are not put in
the DHT. This is not a globally newest-version guarantee. Every newly signed publication must
use a higher revision: two different signed envelopes at the same publisher/name/revision are
a conflict, even when the underlying bytes are identical.
The explicit agent-owned cache retains up to 64 revision floors separately from chunk eviction
and manifest expiry. Use `--reuse-cache` to retain these observations across downloads; a new or
deliberately deleted cache starts a new observation scope. A higher observation is saved before
chunk retrieval, so missing new chunks do not silently trigger an older-version fallback.
The caller receives a verified `0600` file through the same local socket; no user-output path
is sent to the agent. An offline publisher is usable only while reachable replicas retain valid
metadata and all required chunks. This is not yet general website hosting or a message mailbox.

For cooperative HTTPS origins, `content fetch-https` first obtains fresh authenticated
same-origin metadata, uses matching peer chunks and fills missing ranges from that origin.
To receive the result in the calling user's account instead of creating an agent-owned output:

```sh
volparossa content fetch-https \
  --url https://downloads.example/asset.bin \
  --metadata-path /.well-known/volparossa/content/asset \
  --cache /agent-owned/new-https-cache --local-output ./asset.bin
```

Use exactly one of `--local-output` (caller-owned) and the existing `--output` (agent-owned).
The cache still belongs to the agent. Local delivery uses the same authorized control connection;
the user path is never passed to the agent. The CLI verifies the complete object and correlated
final receipt, then atomically publishes a new `0600` file without overwriting anything. It does
not create a second cache, change ownership, or save a reusable HTTPS authority document.
`--reuse-cache` still requires fresh origin authorization; an offline origin is not bypassed.
The origin must support the documented anonymous binary-content descriptor and satisfy the
normal signed Exit policy. Debian's normal public CA bundle is used unless an explicit public
`--ca-file` is supplied for this operation. This is not interception or generic browser caching.
The CLI/process, origin-library and different-UID network checks pass, as recorded in
[implementation status](IMPLEMENTATION_STATUS.md).

Both HTTPS download commands accept `--source-strategy auto|peers-first|origin-only`:

- `auto` (default) prefers the origin when recent comparable completion-cost measurements are
  absent. Otherwise it refreshes at most two recently useful peers and attempts them only within
  a lookup-plus-transfer budget projected to beat the origin. Network changes can still make a
  prediction wrong; this is not a guarantee of higher speed.
- `peers-first` explicitly explores/preferentially uses peers, then obtains missing ranges from
  the origin in descriptor mode, or one full GET in digest mode. It is useful for provider
  tests but may be slower than origin retrieval.
- `origin-only` skips provider lookup/body retrieval and gets missing bytes from the origin.
  Descriptor mode reuses verified local chunks with `--reuse-cache`; digest mode performs a
  full GET because the HEAD digest supplies no authenticated chunk index.

All modes retain fresh same-origin authorization, the normal protected route and signed Exit
policy. No mode publishes private HTTPS content, accepts a peer as an origin authority or races
duplicate full-object downloads. Recent cost hints are RAM-only and short-lived, with no URL or
object catalogue; native/explicit peer transfers supply useful-peer observations. A node with no
such observations conservatively uses the origin, rather than inventing a speed estimate.

### HTTPS origin-digest downloads

For an origin that returns a supported SHA-256 `Repr-Digest` in its own resource HEAD response,
use `--origin-digest` **instead of** `--metadata-path`:

```sh
volparossa content fetch-https \
  --url https://downloads.example/asset.bin --origin-digest \
  --source-strategy peers-first \
  --cache /agent-owned/new-digest-cache --local-output ./asset.bin
```

This example explicitly explores peers; omit `--source-strategy` for measured `auto` selection,
which prefers origin when useful comparable costs are unavailable. `browser-download` accepts
the same mode in place of its metadata path, without either output option.

The consumer authenticates the exact resource using its own TLS 1.3 HEAD exchange through the
normal protected route. The supported profile is status 200, identity encoding,
`application/octet-stream`, explicit public freshness and one canonical SHA-256 representation
digest; cookies, credentials, variants, redirects and content-location indirection are rejected.
`Content-Digest` on HEAD is not accepted as the resource digest. No custom VOLPAROSSA descriptor
is needed, but an origin without supported `Repr-Digest` is currently unavailable in this mode;
there is no silent trust downgrade or generic ordinary-download fallback for such origins.

Protected providers are queried by whole-object hash and length, not URL. Their original signed
manifest is only a bounded transport index, never origin authority. The agent verifies the
complete representation before local delivery, browser readiness or automatic contribution.
An incomplete peer attempt ends before one full origin GET; its received bytes are still
reported. This mode does not request partial origin ranges. Existing descriptor-mode partial
retrieval remains available. With `--reuse-cache`, matching local chunks can help after a valid
peer index is found, but an offline origin still cannot authorize a new download.

Local/browser JSON reports `authentication_scope: "origin-repr-digest"` and the original
`transport_manifest_id`; descriptor mode reports `cooperative-origin`. These labels distinguish
authorization from transport signatures. The original HTTP expiry is never renewed by caching.
Targeted local origin-TLS, provider, CLI and harness checks pass; the integrated network proof
is pending. No general website support or speed gain is claimed.

### Automatic public-content contribution

This integration removes the manual initial `content serve --manifest` step for received
public objects. It is still awaiting its dedicated source-stop/restart network proof.
On an explicitly participating relay, configure a policy-authorized endpoint and private cache:

```yaml
content_contribution:
  enabled: true
  bind_address: "0.0.0.0:18080"
  advertised_hostname: cache.example
  cache: /var/lib/volparossa/public-contribution
  quota_bytes: 67108864
  max_entries: 256
  min_free_bytes: 268435456
  max_bytes: 1048576
  max_chunks: 4
```

This block requires the existing `sharing` and `download_sharing` settings, with explicit local
interfaces and usable capacities; it does not configure those interfaces, enable roles or
grant new Exit policy permissions. The hostname and TCP port must already be permitted by the
active signed policy. The directory must be new or the same exclusively owned contribution
cache; arbitrary existing directories are not adopted. The listener starts empty, and only
valid retained publications are offered after startup or admission.

Enabling this setting is explicit consent to retain and serve successfully verified public
native/named objects and supported anonymous cooperative-HTTPS or origin-digest content. Private messages and
mailbox storage are excluded; ordinary encrypted browsing, cookies, login sessions and
`private`/`no-store` responses are not opted in. Every later HTTPS consumer still obtains fresh
origin authorization. Storage peers do not become publishers or origin authorities.

One quota covers both received content and incidental extra chunks. Admission never evicts live
content to make room; insufficient space skips optional work. A bounded in-memory queue expires
after at most five minutes, and each idle batch copies at most four chunks / one MiB. Foreground
downloads and configured owner traffic take precedence. Cache persistence is not a retention
promise, global fairness measurement or guarantee that other clients can always retrieve an
entire object. `content status` reports the same service and replica counters as manual serving;
`content stop` stops the current service, and the explicit configuration takes effect again at
the next agent start.

### One-shot browser download

For the same supported cooperative HTTPS origin, let the browser choose where to save the
already verified result:

```sh
volparossa content browser-download \
  --url https://downloads.example/asset.bin \
  --metadata-path /.well-known/volparossa/content/asset \
  --cache /agent-owned/new-browser-cache
```

For the supported [origin-digest profile](#https-origin-digest-downloads), replace the
`--metadata-path` argument with `--origin-digest`; the remaining browser behavior is identical.

Keep the command running. After protected retrieval and verification, its first JSON line contains
`download_url`; paste that temporary URL directly into the browser's address bar. It binds only
`127.0.0.1` on an automatically chosen port, accepts one authorized GET and sends a binary attachment.
There is no `--output`, `--local-output` or `--bind` option, proxy endpoint or resumable browser Range
request. The unguessable URL is a temporary access secret: do not publish or share it.
The link and transfer deadline are the earlier of five minutes or the original authenticated
authority's expiry. The CLI removes its private temporary spool on completion or interruption;
the browser's saved download remains under the user's control. A final JSON receipt reports
delivery and spool cleanup.

The normal agent-owned cache, optional `--reuse-cache`, limits and explicit public `--ca-file`
retain the same meaning as `fetch-https`. Fresh origin authentication still precedes peer reuse;
no certificate is installed, verification bypassed or origin authority persisted. The localhost
attachment gains none of the source website's browser permissions, cookies or login state.
This is an explicit download integration, not general website rendering or transparent HTTPS
caching. Measured benefit and the complete C08 checkpoint remain unproved.

### Native static websites

Pack an explicitly selected directory with an `index.html`, then publish the bundle with the
existing encrypted identity and ordinary native-content commands:

```sh
volparossa content site pack --directory ./public --output ./site.vps
volparossa content publish \
  --identity /path/to/existing/identity.key \
  --input ./site.vps --cache ./site-cache --manifest ./site.v1.pb \
  --name my-site --revision 1 --content-type application/vnd.volparossa.site.v1
```

Packing is offline and does not publish anything. It selects at most 256 regular files within
the native 256-MiB object limit, excludes dotfiles/directories, rejects symlinks and requires
unambiguous UTF-8 paths. Keep secrets outside this explicitly public directory. The new private
bundle is never written over an existing file. HTML, CSS, JavaScript, images, fonts and media are
indexed into one signed publication; no files are extracted while viewing.

Import and serve that public publication using the [existing account handoff](#moving-an-explicit-public-publication-to-or-from-the-service)
and `content serve --name-lookup`. Each consumer obtains the trusted publisher key and exact name,
not the publisher's private key or a browser localhost URL:

```sh
volparossa content site open \
  --publisher-key TRUSTED_PUBLISHER_PUBLIC_KEY_HEX --name my-site --min-revision 1 \
  --cache /agent-owned/new-site-cache
```

Keep the command running and paste `site_url` from its first JSON line into the browser. It first
retrieves and verifies the entire named publication through the existing protected chunk path,
then serves only those immutable assets on a random `*.localhost` name and loopback-only port.
Root-relative links, directory `index.html`, UTF-8 paths, GET/HEAD and single byte ranges work;
bounded query strings are ignored for immutable lookup, not interpreted as server operations.
`--reuse-cache` and `--min-revision` retain the normal named-cache semantics.

The local viewer expires at the earlier of the original signed expiry or its own
`--lifetime-seconds` (default one hour, maximum one day). SIGINT/TERM closes the listener and
in-flight responses and removes the private spool. No certificate is installed and the page
does not inherit an external website's origin, login or cookies. Its browser sandbox supports
scripts and local assets but excludes persistent origin storage, service workers, forms,
embedded frames and external network requests. This is a static publication, not a dynamic
server/database, transparent HTTPS cache or a promise of permanent replica availability.
The publisher may be offline only while reachable replicas retain valid metadata and every
required chunk. See [source-scoped verification](IMPLEMENTATION_STATUS.md).

### Opportunistic replica cache

For the first development-only redistribution integration, add `--replica-cache /agent-owned/new-extras`
to `content serve`. By default the directory must be new, private to the agent and different from
the existing publication cache. To restart this service with an existing owned replica store,
repeat the primary publication's Serve command with the same `--replica-cache` and limits, adding
`--reuse-replica-cache`. This restores unexpired original replica manifests and verified chunks
before opening the listener; it does not infer registrations from loose files, extend expiry or
activate anything on boot. Missing metadata means zero restored publications; foreign, corrupt,
busy or incomplete stores fail without adoption or automatic deletion. Primary registrations
take precedence, and excess valid metadata remains stored when the 64-publication registry is full.
Optional limits are `--replica-quota-bytes` (default 64 MiB, at most
256 MiB), `--replica-max-entries` (default 256), `--replica-max-bytes` (64 bytes through 1 MiB,
default 1 MiB of protocol traffic) and `--replica-max-chunks` (1--4, default 4). Repeated Serve
registrations use the same replica configuration; changing it requires stopping the service.

The job starts only after a successful native/HTTPS content fetch has actually received verified
chunks from a provider. Both `sharing` and `download_sharing` must be explicitly configured and
enabled, with meaningful link capacities and the real carrying interfaces. Unknown/down/overlay
interfaces or a busy preflight sample cause uptake to pause; no host configuration is changed by
the sampling itself. The receiver uses protocol v3: after each received chunk the provider must
wait for a new one-chunk credit. A fresh sample of the configured links precedes that credit;
a busy sample withholds credit and waits for quiet within the same original deadline, then
resumes that exchange without renewing its budget. Unavailable accounting never authorizes
credit; cancellation or deadline expiry ends the job without extending authority.
Credit, stop and finish framing share the original protocol budget/deadline. There is no silent
fallback to the unsolicited v2 exchange. New foreground content operations cancel background
uptake. One already credited chunk can still overlap new demand; unmeasured links, per-flow
owner accounting and radio contention are not covered. This is not the full C04 fairness proof.

`content status` reports `replication_enabled` separately from actual retained `replica_chunks`,
`replica_bytes` and registered `replica_publications`; an enabled job is not evidence of useful
replication. Busy cache access returns Busy rather than a fabricated count. Stop cancels the job
and withdraws the service, retaining owned cache files and the cache-bound registration journal.
Explicit reuse restores the journal, not the old service, contacts or route authority. Expired
records are not offered again; maintenance before new uptake reclaims only expired, unshared
journaled chunks, preserving live/foreground references and refusing mailbox stores. It does not
repair lost replicas.
It remains a development service, not reliable offline hosting or guaranteed owner-priority sharing.

## Crash and cleanup

Route teardown is Destroy-first. From successful helper `Prepare`, a cancellation-safe supervisor
retains the exact opaque cleanup authority. Rejection, expiry, cancellation, disconnect and failure
must settle helper-owned state before coordinator resources or remote reservation authority are
released. Ambiguous or failed destruction keeps the route quarantined; expiry is not permission to
forget network state.

The new remote-retirement integration retains the original session authority and exact selected
control/data relays before a request can create a remote route. Local Destroy precedes parallel
remote requests; coordinator resources are released only after independently verified Relay and
Exit confirmations. A slow peer does not prevent attempts to retire other selected peers.
Role disable or policy replacement does not authorize new traffic, but does not by itself block
destruction of an exactly retained old context.
Normal daemon shutdown stops new operations first and keeps discovery available during the
bounded retirement attempt. It reports `ShutdownCleanup` if route destruction remains unconfirmed;
stopping discovery afterwards does not turn failed cleanup into success.

Current development limitation: remote retirement scopes, including completed ones, are retained
in memory under a hard 1,024-context bound per role. New scope admission fails when that bound is
full. They cannot safely be evicted merely because the original route expired: another selected
relay may still need its Exit confirmation. Capacity reclamation and restart recovery of these
remote scopes remain separate unfinished work; neither missing memory state nor restarting an
agent is treated as proof that remote network resources were removed.

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
