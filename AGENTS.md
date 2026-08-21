# VOLPAROSSA repository instructions

These instructions apply to the entire repository and must remain in force in future sessions.

## Mission and truthfulness

- Build VOLPAROSSA v1 as an open-source, decentralised VPN overlay for Debian 13 amd64.
- The normal data path is always `client -> exactly one voluntary relay -> exit -> destination`; every parallel path uses a different relay between the same client and exit.
- Never describe ordinary TCP or single-path QUIC as MPTCP or Multipath QUIC. A feature is complete only when tests prove that its real datapath and required number of paths carry data.
- Keep `docs/IMPLEMENTATION_STATUS.md` current. Checked items must be supported by passing tests or explicit evidence; incomplete work stays unchecked.
- Do not leave essential mocks, stubs, `TODO`s, or `unimplemented!()` calls in production datapaths.

## Non-negotiable privacy and policy invariants

- Normal clients must never connect directly to an exit dataplane. A conspicuous development-only direct-exit debug option may exist, must default to false, and must not be used by normal tests or production configuration.
- Relays learn the client address and selected exit, but not the Internet destination. Exits learn destinations and incoming relays, but not the client's public address. Destinations see only the exit address.
- Client-to-exit payloads remain end-to-end encrypted even though a relay terminates two distinct WireGuard links.
- Relays may forward only explicitly authorised, short-lived route IDs between the two relevant WireGuard interfaces. They must never provide Internet NAT/egress for relayed sessions or access to the relay host.
- Only an explicitly enabled exit may provide egress. Exit mode defaults to disabled. Nodes may independently enable client, relay, and exit roles.
- All exits fail closed against the same threshold-signed whitelist manifest. No open proxy, implicit raw-IP egress, arbitrary DNS, destination changes, or unsafe port fallback is allowed.
- Product configuration rejects development policy keys. Never add production private keys, accounts, analytics, telemetry, hidden update channels, or automatic code downloads.
- Do not persist URLs, DNS history, payloads, full browsing hostnames, destination IP history, private keys, or a durable node-to-browsing association by default.

## Required v1 datapaths

- TCP: transparent proxy framing over TLS 1.3 over a Linux `IPPROTO_MPTCP` connection whose subflows are bound to selected WireGuard relay paths; no silent ordinary-TCP fallback.
- General UDP: datagrams over a protected single-path QUIC MASQUE CONNECT-IP/CONNECT-UDP association through exactly one relay; destination tuple is pinned.
- Browser QUIC/HTTP/3: original QUIC datagrams inside MASQUE CONNECT-IP over genuine Multipath QUIC with at least two active WireGuard relay paths. Default is fail closed when multipath is required and unavailable.
- Do not add v1 cover traffic, cells, artificial delay, batching, packet duplication, FEC, erasure coding, adaptive path equalisation, payments, tokens, blockchain, automatic exit enablement, or a GUI. Keep scheduler interfaces extensible for later policies.

## Architecture and implementation choices

- Target Debian 13 Trixie amd64, systemd, nftables, iproute2/netlink, kernel WireGuard, and kernel MPTCP.
- Write new control-plane, configuration, policy, selection, orchestration, and service code in stable Rust using Tokio, `tracing`, `serde`, SQLite, and a canonical wire encoding (prefer Protocol Buffers with `prost` unless documented otherwise).
- Use rust-libp2p QUIC plus Identify, Ping, Kademlia with a VOLPAROSSA-specific protocol, mDNS, AutoNAT, DCUtR, Circuit Relay v2 for control-plane connectivity, and request-response protocols. Bootstrap peers are replaceable contacts, never authorities.
- Use Kademlia provider records as capability indexes; fetch signed, short-lived advertisements directly from provider peers. Never publish a central all-node catalogue.
- Use `mp0rta/mqvpn`/xquic only after checking current upstream code, license, draft compatibility, and tests. Pin an exact commit, record provenance/license/patches, and do not use unchecked prebuilt binaries. Isolate native MPQUIC behind a versioned process API where practical.
- Use GPL-3.0-only for original code and preserve every third-party license and notice unchanged.
- Use one permanent Ed25519 identity, libp2p Peer ID derived from it, encrypted local key storage at mode `0600`, ephemeral session identities, and ephemeral WireGuard keys per route context/path. Do not invent cryptographic primitives.
- Every signed control message includes version, sender, timestamp, expiry, nonce, type, payload hash, and signature. Reject invalid versions, signatures, expiry, replay, lengths, and resource use.
- Select exit first, then relays; score full `client -> relay -> exit` paths. Enforce operator, IPv4 /24, IPv6 /48, ASN, and network-origin diversity plus an exploration pool.
- The reusable `MptcpPathManagerBackend` must have a kernel backend; add an mptcpd backend only if a reproducible Debian 13 limitation requires it. Kernel MPTCP retains scheduling, congestion control, retransmission, and reassembly.
- The MPQUIC scheduler uses estimated delivery time based on RTT, queue, delivery rate, congestion, and loss; it respects congestion state and performs no duplication/FEC.

## Privilege and host-safety boundaries

- Keep `volparossa-agent` unprivileged. `volparossa-helper` is the smallest possible privileged service and accepts only a strict, typed allowlist of network operations over a protected root-owned Unix socket. It must never accept commands, arbitrary paths, or free-form privileged input.
- Apply restrictive systemd sandboxing and the minimum capabilities/address families/syscalls needed by each executable.
- Product networking uses netlink/UAPI, not parsed `wg`, `ip`, or `nft` CLI output. Diagnostic and test scripts may use those tools.
- Never alter the development host's active DNS, routes, firewall, VPN, sysctls, or network configuration. Network tests run only in disposable Linux network namespaces using veth devices and temporary nftables rules.
- Any script requiring root must print its exact intended changes, request confirmation where appropriate, trap interruption, and implement idempotent full cleanup. Verify original host routes, DNS, and firewall remain unchanged.
- Do not install or permanently modify anything outside this workspace without explicit user approval. Never use `curl | sh`, untagged containers, unpinned Git dependencies, or silently downloaded binaries.
- Do not commit or push unless the user explicitly requests it.

## Quality workflow

- After every meaningful change run the narrowest relevant formatter, static analysis, and tests; regularly run the full required suite:
  - `cargo fmt --check`
  - `cargo clippy --workspace --all-targets --all-features -- -D warnings`
  - `cargo test --workspace --all-features`
  - `cargo deny check`
- Provide unit/property tests for canonical encoding, signatures/replay/TTL, advertisements, policy, routing contexts, scoring/diversity/capacity, reservations, framing, versions, cleanup, and configuration.
- Fuzz all externally controlled parsers named in the master specification. Bound message sizes, allocations, peers, sessions, buffers, and time. Use secure randomness and constant-time secret comparisons.
- The privileged integration topology must be disposable and must test real libp2p discovery, reservations, WireGuard links, MPTCP subflows, MPQUIC paths, TCP/UDP/HTTP3, policy denials, failover, privacy packet captures, crash cleanup, and no host damage. Emit a machine-readable acceptance report.
- Native code must be covered by upstream tests plus sanitizers and Valgrind or AddressSanitizer.
- Prefer official specifications and primary upstream documentation. Record external source commit, origin, license, and local patches in `THIRD_PARTY_LICENSES.md`.

## Safe operating defaults

- Default roles: client on, relay off, exit off. Default kill switch and policy fail-closed are on.
- Default multipath settings: four active, at least two, at most eight, two warm backups, 20 ms maximum RTT spread; a new active path should add roughly 10% unique throughput or meaningful failover value.
- Route contexts are scoped by local profile, registrable domain/origin, transport, and policy version; never move an established flow to a new exit. Expiry affects new flows, and LRU cleanup removes all associated interfaces, routes, MPTCP/MPQUIC paths, and firewall state.
- Treat DHT records, advertisements, peers, parsers, and the unprivileged agent as untrusted. Fail closed on ambiguity.
- Be candid in documentation: this low-latency design cannot guarantee protection from a global observer correlating both ends, and local anti-Sybil measures mitigate rather than eliminate Sybil attacks.
