# VOLPAROSSA repository instructions

These instructions apply to this repository with Codex, OpenCode and other coding
agents. The user's latest scoped instructions take precedence over older records.

## Scope and reading

- Build the complete DICN development alpha in `docs/development/GOAL.md`, including
  its DPS and Studio/hosting additions. A milestone never reduces agreed scope.
- Start with the task and `docs/IMPLEMENTATION_STATUS.md`. For a full project
  resumption, read GOAL; for bounded work, read the affected requirements and topic
  sections. Use `docs/README.md` as the index and the application's own guidance.
  Do not load historical ledgers, source snapshots or unrelated specifications by default.
- `docs/development/CODEX_WORKFLOW.md` defines the shared development workflow;
  despite its filename it is client-independent. `PURSUING_GOAL.md` is an optional
  continuation prompt; `GOAL_VERIFICATION.md` documents preservation checks when
  requirements or their source records change. None needs ritual rereading per task.

## Autonomous execution and coordination

- Choose models, reasoning effort, agents/subagents, skills, tools, context and
  parallelism dynamically for the task's complexity, uncertainty, risk and cost,
  using capabilities actually available in the current client. Reassess as needed.
  There are no required model names, vendors, fixed role assignments or project
  concurrency quotas. This replaces all earlier development model-routing rules.
- Delegate independent bounded work when it helps. Give each assignment the goal,
  source revision, owned paths/worktree, relevant contracts and expected evidence.
  Avoid duplicate exploration and concurrent writers to the same files. The
  coordinating agent integrates results; use independent review where correctness,
  privacy or consequential integration warrants it. Agents may not approve their
  own work or gain publication/release authority through delegation.
- Choose implementation details, priorities, checks and scoped commit/push timing
  autonomously. Preserve unrelated changes, unfinished work and branch protections.
  Ask only for consequential authority outside the agreed scope: private disclosure,
  real funds, host changes, permission expansion or bypassing release controls.
- Keep project requirements, implementation evidence and development-tool choices
  distinct. Client settings may constrain model switching; report actual limitations
  rather than claiming a prompt changed configuration or enabled automatic routing.

## Network and privacy invariants

- Target Debian 13 amd64 with systemd, nftables, netlink/iproute2, kernel WireGuard
  and kernel MPTCP; additional platforms remain in scope where feasible.
- Normal Internet traffic is `client -> exactly one relay -> exit -> destination`.
  Parallel paths use different relays between the same client and exit. Direct
  client-to-exit dataplanes are forbidden except a conspicuous development-only
  debug option, default false, excluded from normal tests and production config.
- Relays know client and exit, never the Internet destination; exits know destination
  and relay, never the client's public address; destinations see the exit address.
  Client-to-exit payloads remain end-to-end encrypted across the two WireGuard links.
- Relays forward only authorized short-lived route IDs between the relevant
  WireGuard interfaces: no relay-host access or Internet NAT/egress for sessions.
- Participation is reciprocal and capability-based. Production consumers contribute
  nonzero relay capacity and, with independent Internet access, exit service.
  Local-only nodes contribute local links/relay service and never enable exit,
  invent an ASN/public origin prefix or derive Internet egress from the overlay.
  Service-only participation is allowed; client-only consumption is rejected.
- `network.uplink` is an operator declaration (`independent_internet` by default,
  or `local_only`), not reachability/outage proof. Configuration alone cannot prove
  offline/private-endpoint routing. All nodes use the same software; no privileged
  central server class.
- Installation activates no roles. Client, relay and exit default off; participation
  requires explicit acceptance of available-capability responsibilities. Only an
  enabled authorized exit with independent Internet provides egress. Role-isolated
  disposable fixtures are tests, not production participation modes.
- Core kill switch and policy fail-closed default on. The Browser's separately
  scoped kill switch defaults off as specified in GOAL; it cannot weaken other apps.
- Exits fail closed against the same threshold-signed whitelist: no open proxy,
  implicit raw-IP egress, arbitrary DNS, destination mutation or unsafe port fallback.
  Product configuration rejects development policy keys.
- No production private keys/accounts, telemetry, analytics or hidden update channels.
  Required automatic client updates accept only independently authorized releases
  authenticated against pre-established trust; peers/model output are not execution
  authority and installation cannot expand permissions or alter the development host.
- Do not persist URLs, DNS/browsing/destination-IP history, payloads, private keys or
  durable node-to-browsing associations by default. Treat peers, DHT data, parsers,
  advertisements and the unprivileged agent as untrusted; fail closed on ambiguity.

## Required datapaths and architecture

- TCP: transparent proxy framing over TLS 1.3 over Linux `IPPROTO_MPTCP`, with
  subflows bound to selected WireGuard relay paths; no ordinary-TCP fallback.
- General UDP: protected single-path QUIC MASQUE CONNECT-IP/CONNECT-UDP through
  exactly one relay, with a pinned destination tuple.
- Browser QUIC/HTTP3: original QUIC datagrams inside MASQUE CONNECT-IP over genuine
  Multipath QUIC with at least two active WireGuard relay paths; fail closed when
  required multipath is unavailable. Prove data on the required paths.
- No cover traffic, cells, artificial delay, batching, duplication, FEC/erasure coding
  or adaptive path equalisation in v1 network datapaths. Scheduler interfaces stay
  extensible. Storage may separately evaluate erasure coding with uniform redundancy,
  compatibility and recoverability preserved.
- New control/configuration/policy/orchestration/service code uses stable Rust,
  Tokio, tracing, serde, SQLite and canonical wire encoding (prefer prost protobuf).
  Use rust-libp2p QUIC, Identify, Ping, VOLPAROSSA Kademlia, mDNS, AutoNAT, DCUtR,
  Circuit Relay v2 and request-response. Bootstrap contacts are replaceable, not
  authorities. DHT provider records index capabilities; fetch signed short-lived
  advertisements directly, without a central all-node catalogue.
- Before using mqvpn/xquic, inspect current upstream source, license, draft and tests;
  pin the commit, record origin/notices/patches and build from source. Prefer a
  versioned process boundary for native MPQUIC. Original code is GPL-3.0-only;
  retain third-party licenses/notices unchanged in `THIRD_PARTY_LICENSES.md`.
- Use a permanent Ed25519 identity and derived libp2p Peer ID, encrypted local keys
  at mode 0600, ephemeral session identities and per-route/path WireGuard keys.
  Never invent cryptography. Signed control messages include version, sender,
  timestamp, expiry, nonce, type, payload hash and signature; reject bad signatures,
  versions, expiry, replay, lengths and excessive resource use.
- Select exit before relays and score complete paths; enforce operator, IPv4 /24,
  IPv6 /48, ASN and network-origin diversity with exploration. The reusable
  `MptcpPathManagerBackend` needs a kernel backend; mptcpd requires a reproducible
  Debian 13 limitation. Kernel MPTCP owns scheduling/congestion/retransmission/reassembly.
  MPQUIC uses estimated delivery time from RTT, queue, rate, congestion and loss,
  respecting congestion without duplication/FEC.
- Defaults: four active paths, minimum two, maximum eight, two warm backups,
  maximum 20 ms RTT spread. New active paths add roughly 10% unique throughput
  or meaningful failover value. Scope route contexts by profile, registrable
  domain/origin, transport and policy version; never move established flows to a
  new exit. Expiry affects new flows; LRU cleanup removes all associated resources.
- Keep reusable Cache, Storage, Compute and Transaction layers alongside applications.
  No payments/tokens/blockchain as overlay participation conditions, automatic exit
  activation or core-daemon GUI. Implement the reusable Bank Transaction-layer;
  isolated fictitious-asset tests are authorized. Distinguish ownership, payment
  authority, accounting and settlement; simulations prove neither real-money
  settlement/legal ownership nor guaranteed recovery of externally transferred funds.

## Host safety and verification

- `volparossa-agent` stays unprivileged; the minimal privileged helper accepts only
  typed allowlisted network operations over a protected root-owned Unix socket,
  never commands, arbitrary paths or free-form privileged input. Apply restrictive
  systemd sandboxing and minimum capabilities, address families and syscalls.
  Product networking uses netlink/UAPI; diagnostic/test scripts may use CLI tools.
- Never change development-host DNS, routes, firewall, VPN, sysctls or active network
  configuration. Network trials use disposable namespaces/veth/nftables with full
  cleanup. Root scripts state exact changes, confirm where appropriate, trap
  interruption and clean up idempotently; verify host routes/DNS/firewall unchanged.
  Use approved disposable hosted runners for builds, native/model/VM/SDK/Gradle and
  installation trials; local inspection and inert documentation checks are allowed.
- Do not install or permanently modify anything outside the workspace without
  approval. No curl-pipe-shell, untagged containers, unpinned Git dependencies or
  silently downloaded binaries. Preserve dirty worktrees and unique evidence;
  recover or retire checkouts through the shared workflow.
- Integrate useful executable slices. Run the smallest relevant formatter/compile
  check and functional smoke; broaden checks for affected boundaries and integration.
  Reuse exact-source results; do not rerun completed trials because a conversation
  ended. Full quality commands and acceptance requirements are in
  `docs/development/TESTING.md`, not mandatory steps for every small edit.
- Test canonical encoding, signatures/replay/TTL, advertisements, policy, scoring,
  diversity/capacity, reservations, framing, versions, cleanup and configuration.
  Bound external input/resources; fuzz the specified parsers; use secure randomness
  and constant-time secret comparisons. Native code needs upstream tests and
  sanitizers plus Valgrind or AddressSanitizer as appropriate.
- Disposable network acceptance must prove real discovery, reservations, WireGuard,
  MPTCP/MPQUIC paths, TCP/UDP/HTTP3, denials, failover, privacy captures, crash cleanup
  and no host damage, with a machine-readable report. Mocks, interfaces, simulations,
  disabled tests and single-path substitutes do not prove required runtime behavior.
  No essential stubs, TODOs or unimplemented production datapaths.
- Keep current status concise: changed source, result, evidence link and remaining
  dependency. Preserve original failed reports separately. Claims require evidence;
  checks do not imply product completion. Local anti-Sybil measures mitigate rather
  than eliminate attacks; this design cannot guarantee protection from a global
  observer correlating both ends.
