# Threat model

## Scope and security goals

VOLPAROSSA v1 aims to separate a client's public address and permanent identity from the Internet
destination and exit. The client first chooses one control relay; every exit advertisement and exit
RPC uses that relay on both forwarding hops. Every datapath then places exactly one independently
selected relay between client and exit. The design also aims to prevent volunteer relays from
becoming egress proxies, prevent exits from reaching destinations outside a threshold-signed
whitelist, keep control messages authenticated and short-lived, and confine privileged network
mutations to scoped, reversible helper operations.

This is a low-latency overlay. It does **not** guarantee protection against a global observer that
can correlate timing and volume at both ends. It does not defend against local root, endpoint
compromise, browser fingerprinting, application identifiers, or content voluntarily disclosed to a
destination.

## Assets and boundaries

Assets include the permanent Ed25519 identity, passphrase-encrypted identity file, ephemeral session
and WireGuard keys, signed policy, route reservations, helper cleanup token, destination decisions,
and the absence of forbidden host network changes. Trust boundaries are peer-to-peer protocols,
DHT/provider data, agent/helper and agent/native sockets, configuration and policy files, SQLite,
the kernel networking API, and systemd service boundaries.

## Adversaries and mitigations

### Malicious control relay

The selected control relay sees the client's authenticated control connection, the chosen exit,
operation types, timing, and volume. It may drop, delay, replay, reorder, or substitute forwarding
bytes. End-to-end signed v3 envelopes, exact full-byte comparison, bound node/Peer IDs, absolute
deadlines, and detail-free failures prevent it from minting a positive exit response. It performs
no internal retry and forwards no permanent client Peer ID or public address upstream. It still
learns that one client selected one exit and can correlate that fact with an exit if they collude.

A directly fetched advertisement never mints exit capability. A combined-role node is not globally
forbidden, but this client process accepts it as an exit only from exclusively forwarded
provenance. Direct-then-forwarded is rejected; forwarded-then-direct withdraws and quarantines exit
capability for the advertisement lifetime. Within one route, the exit must differ by node ID and
Peer ID from the control relay and every datapath relay. A control relay can become one datapath
relay only through its own permit, real two-leg probe, selection, authorization, and grant.

### Malicious datapath relay

A datapath relay sees the client endpoint, chosen exit, timing, volume, and its own ephemeral
overlay state.
It may drop, delay, reorder, throttle, replay, or lie about capacity. Separate client-relay and
relay-exit WireGuard links plus client-exit TLS/QUIC keep payload confidential from the relay. The
relay nftables fence permits only one signed, expiring route prefix between its two derived
interfaces and denies host input and Internet NAT/egress. Local performance observations,
reservations, rate limits, hysteresis, and replacement limit disruption; they do not make a relay
honest.

### Malicious exit

An exit sees destinations, incoming control/datapath relays, an ephemeral client-session ID, timing,
volume, DNS answers, and application traffic not otherwise end-to-end encrypted by the application.
It must not receive a direct client connection, the client's public address, permanent node ID, or
Peer ID. All exit advertisements, holds, permits, finalizations, and confirmations arrive through
the one bound control relay. Threshold policy verification, exact advertised policy hashes,
exit-side DNS/SNI/QUIC checks, destination pinning, and fail-closed raw-IP handling constrain egress.
A malicious exit can still log allowed traffic, serve malicious DNS answers, tamper with plaintext
application traffic, or deny service. Application TLS remains essential.

### Relay/exit collusion and traffic correlation

A colluding control or datapath relay and exit can combine their observations and correlate a client
with destinations. Exclusive forwarded provenance and same-route identity separation prevent the
simplest single-node linkage, but they do not prove independent operators or stop collusion.
Multiple relays improve path diversity and failure tolerance, not anonymity against collusion.
Timing, packet sizes, bursts, throughput changes, and deliberate watermarking remain correlation
signals because v1 deliberately has no cover traffic, cells, padding schedule, batching, or
artificial delay.

### Global timing observer

An observer of both client-relay and exit-destination sides can correlate low-latency flows. The
architecture makes no guarantee against this adversary. MPTCP and MPQUIC can create additional
observable path structure. Documentation and UI must never imply otherwise.

### Sybil attack

An attacker can create many Ed25519 identities and advertisements. Local limits by IPv4 /24, IPv6
/48, ASN, operator, identity age, uptime, advertisement rate, and network origin; bounded proof-of-
work fields; exploration; and observed performance raise cost and reduce route concentration. They
cannot cryptographically prove that operators are independent, so Sybil attacks are mitigated, not
eliminated.

### DHT poisoning and eclipse

Provider records are untrusted capability hints. Relay/control-relay advertisements are fetched
directly from their authenticated providers and verified for signature, sender binding, version,
expiry, sequence, consistency, and resource bounds. Exit provider IDs are never directly dialed for
advertisement retrieval; the selected control relay fetches exit advertisements over the two-hop v3
protocols. Direct provenance cannot mint exit capability. Multiple independent bootstrap methods,
remembered peers, mDNS, peerlinks, routing diversity, and no central all-node catalogue reduce
single-source dependence. An eclipse can still suppress or bias available candidates; clients fail
closed when diversity or policy requirements cannot be met.

### False capacity and quality advertisements

Claims only support cheap preselection. Usable capacity is conservatively bounded by advertised free
capacity, local p25 observations, operator limits, and already reserved capacity. Reservations
consume capacity immediately. Clients retain local delivery/failure histories and a bounded
exploration pool. Attackers may still waste setup time or perform selective service.

### Replay, downgrade, and resource exhaustion

Signed peer-control messages require exactly version 3 and commit to sender/public key, creation and
expiry, 256-bit nonce, type, and payload hash. Canonical encoding, strict field validation, maximum
lifetimes, bounded replay caches, frame limits, timeouts, count limits, and fail-closed cache
exhaustion address replay and parser abuse. Peer-control and advertisement versions 1 and 2 and all
future versions are rejected without negotiation or fallback. The threshold policy manifest's own
version 2 and libp2p Circuit Relay v2 are independent protocols and are not downgrade paths. Peers
can still consume bounded CPU, memory, sockets, bandwidth, and log volume, so per-peer/session/rate
limits are required.

### Whitelist bypass

Potential bypasses include wildcard mistakes, Unicode/IDNA confusion, raw IPs, alternate ports,
redirects, DNS rebinding, stale policy, mismatched policy hashes, fragmented TLS/QUIC handshakes,
and protocol confusion. Rules normalize domains to canonical ASCII, match complete labels, authorize
exact transport/port pairs, and never let domain rules imply raw-IP access. The exit resolves and
pins approved answers and checks the visible TLS SNI or verifiable QUIC identity. Redirects create a
new policy decision. Missing or ambiguous evidence fails closed.

### ECH and shared CDN addresses

Encrypted ClientHello can hide the destination needed for v1 exit-side enforcement. ECH therefore
fails closed when policy cannot be verified; no fallback to IP-only authorization is allowed. A
shared CDN IP does not authorize every hostname at that IP: hostname, exact rule, port, resolution,
and visible handshake identity must agree. This limits compatibility with ECH-only services and is
an intentional security tradeoff.

### NAT and hole punching

NAT can expose endpoint metadata, make mappings unstable, or let an attacker race coordinated UDP
hole punching. Endpoint candidates and reservations are authenticated and bounded; reachability must
be proven before activation and keepalive is limited. libp2p Circuit Relay v2 is control-plane
connectivity only; it is legitimate alongside privacy-v3 but never an implicit WireGuard dataplane
fallback. Paths that cannot establish an authorized direct dataplane are rejected. The production
two-leg probe producer does not exist yet, so the current runtime fails closed before this claim.

### Local root compromise

Root can inspect memory, steal identity and session keys, change binaries or policy, alter routes and
firewall state, observe all destinations, and impersonate the node. Encrypted-at-rest identity,
0600 permissions, privilege separation, systemd hardening, ephemeral keys, and redacted persistence
help against accidents and lesser local users, not a hostile root.

### Denial of service

Peers may flood discovery, advertisements, reservations, handshakes, QUIC datagrams, path changes,
or expensive policy inputs. Fixed frame and field bounds, rate/count/capacity limits, short TTLs,
timeouts, bounded queues, passive metrics, conservative probes, and stable error codes limit cost.
Relays/exits can simply refuse service, and network attackers can block UDP or MPTCP. Availability is
best effort; failure must remain private and fail closed.

## Validation evidence

The required namespace acceptance suite includes policy denials, malicious/missing paths, relay and
exit packet captures, crash cleanup, and byte-for-byte unchanged host state. In particular, A12 must
prove from an exit-namespace packet capture that the exit sees incoming relays rather than the
client's public address, and A13 must combine client capture and routing evidence to prove no direct
client-exit control or dataplane path exists. The probe producer, helper backend, agent route
orchestration, and client ingress remain blocked. Until those tests pass and are checked in
[IMPLEMENTATION_STATUS.md](IMPLEMENTATION_STATUS.md), the mitigations above are design requirements
rather than release claims.
