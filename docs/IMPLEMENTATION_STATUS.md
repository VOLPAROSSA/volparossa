# VOLPAROSSA v1 implementation status

This is the repository's source of truth for implementation progress. A checked item means the repository contains the implementation and its stated verification has passed. Architecture documents, interfaces, disabled tests, mocks, simulations, and single-path fallbacks do **not** satisfy dataplane requirements.

Last updated: 2026-08-26

## Fixed alpha v1 scorecard

This scorecard measures progress toward a **working alpha**, separately from
the detailed implementation checklist below. Within alpha v1, the rows, names,
IDs, criteria, weights, 100-point threshold, and A01--A15 definitions are frozen
as of 2026-08-26; only State and supporting evidence may change. The normative
baseline is repository commit `14d7f2b02a70dd626b5f6b7ba06348ac3dd48b9c`
with `AGENTS.md` SHA-256
`4c766b1f81c428f5862557c1c4d3c1cc0fbdd308f7944c2dd92e9d6a64dbee75`.
A fully tested,
explicitly named foundation, core, or boundary may earn only its own points
before it has a production caller. Partial work, mocks, and dormant code earn
no downstream production or dataplane points. An earned milestone can lose
points only when a regression invalidates its evidence, not because the work is
later estimated with a different ruler. Any future scope change must publish a
visibly versioned replacement table instead of silently changing this one.
The short milestone labels incorporate all corresponding normative-baseline
privacy, policy, host-safety, cryptographic, path-count, no-fallback, and
evidence requirements; their omission from a short label never relaxes an
invariant.

| ID | Milestone | Points | State | Evidence |
| --- | --- | ---: | --- | --- |
| AV1-01 | GPL source/licensing, pinned native provenance and separate RustSec audit gates | 3 | Earned | [Repository baseline](#repository-and-engineering-baseline), [testing](#testing-and-fuzzing) |
| AV1-02 | Validated configuration/default roles and encrypted permanent node identity | 3 | Earned | [Configuration](#configuration-and-roles), [identity](#identity-and-signed-protocol) |
| AV1-03 | Threshold-signed whitelist manifest and fail-closed matching core | 3 | Earned | [Policy](#policy-and-whitelist-enforcement) |
| AV1-04 | Native API-v6 process, framing, descriptor, replay and client-assignment boundary | 2 | Earned | [Native boundary](#genuine-multipath-quic--masque), [testing](#testing-and-fuzzing) |
| AV1-05 | Canonical signed control envelopes, replay/TTL and compromise recovery | 3 | Open | — |
| AV1-06 | Live libp2p discovery, capability indexes and replaceable bootstrap | 5 | Open | — |
| AV1-07 | Exit-first path selection, measurements, capacity and diversity | 5 | Open | — |
| AV1-08 | Production FreshEvidence, reservations and exact-set join | 5 | Open | — |
| AV1-09 | Production helper identity, authenticated IPC and operation allowlist | 6 | Open | — |
| AV1-10 | Durable helper ownership journal, restart reaper and crash settlement | 5 | Open | — |
| AV1-11 | Ephemeral-key two-leg WireGuard paths, relay fence/no relay egress or host access, exit-only egress | 9 | Open | — |
| AV1-12 | Route orchestration, descriptor handoff, expiry and complete cleanup | 5 | Open | — |
| AV1-13 | Transparent ingress, kill switch, DNS routing and loop prevention | 6 | Open | — |
| AV1-14 | Live exit resolution/SNI/QUIC/general-UDP whitelist enforcement | 6 | Open | — |
| AV1-15 | Single-path QUIC MASQUE UDP through exactly one relay | 6 | Open | — |
| AV1-16 | Transparent TLS 1.3 framing over real multi-subflow kernel MPTCP, without ordinary-TCP fallback | 9 | Open | — |
| AV1-17 | Browser QUIC over genuine MPQUIC/MASQUE on at least two data-carrying distinct-relay paths, fail closed/failover | 10 | Open | — |
| AV1-18 | Debian 13 doctor, hardened services, privacy-safe logs/retention, reproducible package and operations | 3 | Open | — |
| AV1-19 | Disposable full-topology runner and machine-readable evidence | 3 | Open | — |
| AV1-20 | One unchanged clean build passes all required quality gates and A01--A15, including privacy and host safety | 3 | Open | — |

Current fixed alpha score: **11/100 (11%)**. Alpha requires **100/100** and the
single clean-build A01--A15 run; the score is not a release claim.

## Repository and engineering baseline

- [x] Workspace is a Git repository.
- [x] Durable repository rules are recorded in `AGENTS.md`.
- [x] The Rust workspace and required crate layout compile on stable Rust after the
  hard-incompatible privacy-v4 discovery and route-setup migration.
- [x] GPL-3.0-only licensing, including the standalone fuzz package and new
  local mqvpn patch files, and compatible third-party notices are complete.
- [ ] Workspace formatting, strict Clippy, and tests pass after the privacy-v4 migration; the
  required all-in-one dependency-deny gate remains blocked as documented below, so the combined
  gate stays unchecked.
- [ ] The Debian-compatible Cargo-deny 0.18.3 cannot parse current CVSS 4.0 advisory metadata
  for an all-in-one `cargo deny check`; the separate pinned Cargo-audit 0.22.1 gate reports zero
  unremediated vulnerabilities.
- [x] `justfile` exposes every required build, test, fuzz, benchmark, doctor, demo, package,
  and cleanup entrypoint; privileged integration and package execution still report `BLOCKED`
  until their real drivers exist.
- [ ] No essential production datapath contains a mock, stub, `TODO`, or `unimplemented!()`.
- [ ] Clean Debian 13 amd64 build is reproduced.

## Configuration and roles

- [x] The shipped `config/examples/default.yaml` is parsed and validated in a regression test and
  is exactly equal to the fully validated `Config::default()` snapshot.
- [x] Client defaults enabled; relay and exit default disabled.
- [x] Unsafe combinations, invalid bounds, and unknown safety-sensitive fields fail closed.
- [ ] `routing.direct_exit_debug` defaults off and production rejects it; explicit development
  configuration accepts it, but no debug datapath or prominent runtime warning is implemented.
- [ ] A private atomic role store initializes startup roles. Privacy-v4 protocol directions are
  immutable after process start; runtime changes return restart-required without mutation or
  persistence. No controlled apply/restart workflow or live service-readiness proof exists.
- [ ] Route-context TTL, flow pinning, maximum contexts, and LRU cleanup exist as tested cache
  primitives, but no production session caller inserts, binds, expires, or retires route contexts.

## Processes and privilege separation

- [ ] `volparossa` CLI implements every command in the master specification.
- [ ] Unprivileged `volparossa-agent` owns control-plane, selection, sessions, and local metrics.
- [ ] Minimal `volparossa-helper` owns only allowlisted privileged network operations; v3
  has a bounded typed external state machine plus a disconnected child bootstrap that applies and
  independently verifies NEWNET, pre-barrier NNP plus a fixed descendant-and-namespace-transition
  denying seccomp filter, a parent-pinned pre-drop namespace, exact descriptors and one task, an
  exact dedicated non-root UID/GID with empty supplementary groups, exact capability reduction,
  restored parent-death signal,
  credential-bound staged proof-to-Accepted-to-Ready, a second parent-side descriptor audit after
  proof, and leader pin retention. The parent attests
  filter mode plus exactly one filter beyond its pre-spawn thread baseline; exact BPF content is
  structurally bound by the current executable's fixed UAPI rather than claimed from `/proc`.
  `clone`, `clone3`, `fork`, `vfork`, `setns` and `unshare` monotonically return `EPERM` before the
  namespace-pin barrier, including post-Ready and across exec. After the parent has independently
  observed the final sandbox and sent Accepted, the child disables and reads back `PR_SET_DUMPABLE`
  before Ready or any operational request; the fixed service and transient live-proof driver also
  set `LimitCORE=0`. It has no production caller and
  production deliberately returns
  `Unavailable`. The package declares a locked, group-isolated `volparossa-worker`, pins its numeric
  identity at startup, and first binds unique local passwd/group names and numeric IDs to exact
  name- and number-based NSS results. Only the canonical `files` or `files systemd` order is
  accepted for passwd/group/shadow and optional initgroups; service group sets must exactly match
  the local package contract. It excludes both service identities from the live `shadow` group and validates
  unique agent and worker shadow entries from one zeroizing snapshot: both passwords begin with
  `!`, the worker account expiry is exactly `1`, and root-owned metadata is not writable by either
  service identity, with group read limited to the resolved
  `shadow` group. The bounded zeroizing read cannot reallocate hashes. This is still not complete isolation or
  context cleanup: disposable Debian 13 live-root proof of the identity transition, parent-signal
  and runtime-path denials, pre-filter process-tree state and unchanged host state is outstanding;
  retirement also owns only the exact leader. A preview-first root driver now stages the real
  component in a transient `PrivateNetwork` systemd unit with synthetic read-only account overlays,
  a private `/run`, the exact seven-capability parent set, exact singleton staged-agent
  supplementary-group attestation (so inherited host-root groups fail closed), confirmed leader
  reap and privacy-safe before/after host-state digests. It has not yet run in the required
  disposable Debian 13 VM,
  validates neither a staged package nor the production server lifecycle, and closes no checkbox.
- [ ] Agent-helper protocol is versioned, typed, length-bounded, protected by socket ownership/mode
  plus exact peer credentials, and accepts no shell/free-text/filesystem-path operations; v3 parser
  tests reject v1/v2/future versions, unknown/noncanonical input and retired v2 operations, while
  live root integration remains outstanding.
- [ ] Dormant helper tags 35/28 register one exact runtime-global Prepare intent and reconcile only
  an expired same-runtime lineage. HelperClient uses one authenticated stream and one absolute
  five-second budget for each Bind-plus-operation sequence; post-Prepare-write failures transfer
  exact authority to the owned route-ticket supervisor. Tag 35 now requires the context role and a
  canonical, role-complete closed lease plan projected from the same canonically ordered Prepare;
  the engine rejects any plan substitution before that Prepare's Pending/backend dispatch, and the dormant journal
  has an exact fallible conversion to its existing `ClosedPlan`. The crate-private Prepare method has no other
  production call site; polling it standalone in future code would not be cancellation-safe. Runtime
  mismatch and missing evidence quarantine, target-only cleanup never removes
  Activated/Committed state, and exact retries re-evaluate a capped 1024-entry runtime-lifetime
  `Absent` ledger. There is no tombstone ACK; tag 28 retries exact Pending/Owned cleanup, while tag 29
  is an independent process-wide operation outside per-route reconciliation. Production Prepare
  remains `Unavailable`, and no production manager calls this path. A dormant boot-scoped,
  secret-free canonical/CAS ownership store and a read-only startup interlock have temp-directory
  tests. Its insert, prepare-arm, never-dispatched retirement, and confirmed-recovery transitions
  are exact-current-revision retry-safe after lost replies; persisted typed `Absent` origins prevent
  cross-operation acknowledgement and repeated recovery execution. Intervening transitions and
  conflicting identity, plan, expiry, generation, anchor, or reconciliation state fail closed
  without journal mutation. A private dormant single-writer actor owns the store and recovery
  executor on one named thread, opens and retains one verified parent-directory descriptor, and
  trips a process-global one-shot start latch before lock creation. The latch remains set after
  startup failure or clean shutdown. The private startup sweep resolves every observed uncertain
  record before reporting ready, and admission is bounded to four operations plus shutdown.
  Every non-test actor entry point now requires one absolute hard deadline carried through
  admission, queueing, actor execution, reply and thread settlement. Startup rechecks it before
  filesystem/latch work and each pending record, commands recheck it after dequeue, and recovery
  receives the exact same value. Recovery checks it before the executor and after the exact proof,
  immediately before journal mutation, so a late executor return cannot publish `Absent`. Expired
  unstarted work is mutation-free; every late completion permanently fences admission as ambiguous,
  and shutdown cannot hide settlement ambiguity behind a weaker deadline result.
  Definite pre-rename I/O failures permit a retry only after the retained parent, exact exclusive
  lock, absent temporary entry, and durable snapshot are all re-proved; otherwise the actor is
  permanently ambiguous. Reply and thread-settlement waits are bounded, but an actor thread stuck
  inside the non-cancellable recovery executor can only be detached while retaining the journal
  lock; the process latch remains set. Clean shutdown proves the durable boundary and additionally
  requires every record to be durably `Absent`; it refuses rather than retires or recovers an
  outstanding record. The codec and actor remain private and pre-production; no production
  writer/recovery wiring, server-wired restart reaper, supported on-disk migration, cross-runtime
  tag-28 proof, or live root proof exists.
- [ ] `HelperEngine` now keeps one armed affine owner across asynchronous PLAN/CALL/COMMIT or exact
  rollback. Stable Prepare lineage is separate from rotating operation generations; every backend
  and runtime call binds exact phase/action/request/digest plus one monotonic absolute deadline.
  Adversarial fake-backend tests cover factory/poll panic, caller cancellation, missing-binding
  recovery without stale-owner substitution, overflow, completion/deadline substitution,
  `CleanupIncomplete` quarantine, shutdown correlation, and wrong/late Acquire descriptor closure
  before exact Destroy. The disconnected `WorkerCoordinator` now carries one absolute deadline from
  pre-PLAN admission through request, response, optional Acquire FD, liveness and COMMIT; expiry
  before PLAN leaves no state, late completion cannot commit, and a late installed FD is closed.
  This is a success/COMMIT acceptance boundary rather than a wall-clock return guarantee because
  exact-owner cleanup and scheduling may deliver the fail-closed result later.
  A successful credentialed Acquire adopts its private raw-FD owner only after exact
  PID/UID/GID, credential/FD count, ancillary, binding and deadline validation. The audited safe
  boundary uses `F_DUPFD_CLOEXEC` with minimum 3, immediately owns and verifies the duplicate's
  `FD_CLOEXEC`, consumes and closes the original, and closes the adopted `OwnedFd` if the final
  deadline check fails.
  Its separate launcher carries one absolute spawn/handshake budget, polls spawn-lock acquisition
  against that deadline, pre-arms retirement ownership before the blocking `Command::spawn`
  operation and installs any returned child into that owner before further fallible work; only the
  spawn operation itself remains non-interruptible.
  A private dormant lifecycle seam now reserves a coordinator-local generation, retains a
  non-expiring `LifecycleOwned` shutdown fence, authenticates a passive worker under that same
  deadline, and registers it in `Starting` without dispatching any child operation. Every
  post-reservation uncertain outcome returns a non-`Clone` exact-placement owner; registration
  failure keeps its reservation visible until detached reap, and `ReapedPendingPurge` retries only
  idempotent six-index registry cleanup without signalling the process twice. If a successful
  terminal supervisor `DestroyContext` has already confirmed reap and removed that exact generation
  from all six registry locations, a separately retained affine `Registered` owner proves complete
  absence under the registry lock and settles idempotently to `ConfirmedWorkerGenerationAbsent`
  without a second signal or wait. Partial registry residue or deadline expiry fails closed with
  that owner retained for exact retry. Commit, settlement, detach and purge recheck the deadline
  immediately before mutation. Its recovery source retains
  and revalidates the exact pidfd, proc directory, boot-ID source, PID/start ticks, executable,
  cgroup namespace/root/service directory and typed network namespace. Bootstrap binds the child
  executable to the parent image and its unified cgroup to the parent service cgroup. After the
  fixed seccomp filter denies re-exec and later namespace transitions, the parent revalidates the
  protected procfs links before identity drop; post-drop it requires exact `EACCES` on both and
  seals only retained descriptors plus freshly read start-time and cgroup evidence, without
  `CAP_SYS_PTRACE`. Recovery performs full proof I/O outside the registry lock, constructs all eight
  durable Prepare-anchor fields, and then revalidates exact process identity, `Starting`, TTL and
  liveness under the same hard deadline. Ambiguous spawn remains permanently fail-closed.
  Dropped/unwound lifecycle ownership is not yet recoverable. Concurrent terminal retirement may
  transiently retain a `Registered` owner while record or detached process ownership remains; after
  confirmed reap and complete six-index purge, that same owner settles without a second signal or
  wait. Neither production journal/reaper wiring nor a cancellation-safe production settlement
  guard exists. No datapath or acceptance checkbox closes.
  Shutdown uses attempt-correlated `Pending`/`Retryable`/`Confirmed`/terminal-`Unresolved` states:
  an expired new attempt returns `Retryable` without changing state, orderly timeout retains exact
  workers and handles for a later upgrade, and a waiter accepts only completion published strictly
  before its own deadline, while runtime/task cancellation fails closed and cannot upgrade.
  Terminal unresolved settlement atomically drains captured owners and immediately escalates any
  later owner instead of leaving it stranded.
  Successful internal Prepare, Activate, Probe and MPTCP endpoint responses must preserve exact
  request order and identity; engine Prepare proof also rejects duplicate public keys or public
  endpoints before affine handles can be paired. A worker `CleanupIncomplete` result now
  quarantines and detaches that exact generation instead of caching an apparently stable failure.
  The inactive kernel layer preflights a complete batch as fresh, DOWN, exact-name/alias/kind
  WireGuard links before key/address mutation, and has exact-owned delete plus absence proof. The
  alias is not yet bound to durable journal ownership, so these primitives remain disconnected.
  Production still installs only the `Unavailable` backend. This lifecycle settlement remains
  private and dormant: there is no production journal writer or restart reaper, no production worker
  or host-network mutation, and no datapath evidence. Production adapter wiring, durable
  journal/reaper integration, and the separate Add/Remove MPTCP endpoint seam remain required; this
  status and every datapath or acceptance checkbox remain open.
- [ ] Root-owned Unix socket permissions and peer credential checks are enforced.
- [ ] systemd services use minimum capabilities and restrictive sandboxing; the shipped helper unit
  and doctor contract now require exactly the reviewed seven-capability bootstrap set
  (`CAP_KILL`, `CAP_NET_ADMIN`, `CAP_NET_RAW`, `CAP_SETGID`, `CAP_SETPCAP`, `CAP_SETUID`,
  `CAP_SYS_ADMIN`) and
  reject `CAP_SYS_PTRACE`; they also require `LimitCORE=0`, while the child independently disables
  process dumpability after parent attestation and before Ready. The component-only transient driver
  exists, but staged-package and
  disposable Debian 13 live-root execution remain outstanding, and the final worker proof permits
  only `CAP_NET_ADMIN`.
- [ ] Helper crash/termination cleanup is idempotent and complete; fake-backend reaper/quarantine
  tests prove bounded timeout retry and process-fatal signal/wait errors without false reap evidence,
  but live namespace/kernel cleanup proof does not.
- [ ] Namespace-local MPTCP/QUIC sockets use typed tag-27 `AcquireTransportSocket` and exactly-one CLOEXEC `SCM_RIGHTS` framing; canonical binding, retry, correlation, close-on-reject and consuming credentialed-FD-to-`OwnedFd` adoption tests pass, including audited minimum-3 `F_DUPFD_CLOEXEC`, CLOEXEC readback and original closure. Internal protocol v2 consumes and drops the worker source before an exact credentialed release record, while missing/wrong/late release closes the adopted FD. The disconnected coordinator duplicates the already attested worker namespace pin affinely before this Acquire request's tombstone/in-flight mutation, retains it across concurrent retirement without probing a process under the registry lock, and the consuming parent validator independently verifies both the complete socket shape and exact `SIOCGSKNS` nsfs device/inode identity before registry COMMIT. Post-PLAN mismatch, validation failure or expiry closes the descriptor and quarantines the generation. Production still returns `Unavailable` before network work; committed child Acquire dispatch, datapath adoption and live route proof remain.
- [ ] Native MPQUIC API v6 preflights an exact role/process lifetime, targets every later operation to that instance, requires nonce plus canonical-request digest response correlation, and consumes exactly one operation-bound UDP descriptor for `AddPath` or `StartExitSession` and zero otherwise. Start requests bind reservation/finalize IDs derived from the signed scope, bearer commitment, certificate digest, and both process instances; Rust and C share exact request/descriptor hash vectors and independently reject bearer/commitment mismatch. Native samples BOOTTIME before REALTIME, maintains a monotone wall floor, converts accepted wall expiry once to a BOOTTIME deadline, and fails closed on clock failure, regression, or overflow. A fixed 128-record process-local ledger has no live eviction, rejects exact pair replay and half-key scope reuse, permits only byte-identical live client retries, and tombstones stop, expiry, and valid exit attempts before the dormant backend boundary. Rust and two independent C boundaries enforce server `10.76.0.1/32`, client `10.76.0.2/32` through `10.76.0.254/32`, optional client `fd76:6f6c:7062::2/112` through `fd76:6f6c:7062::fe/112`, and MTU 1280--1420. The native client deep-copies one assignment, permits only an identical active duplicate, exposes it only after `ESTABLISHED`, enforces outbound source and reverse-destination ownership, and wipes it on fatal transport failure. Focused tests cover these clock/replay/capacity and assignment-state rules, exact current-path projection with retired closed records only, typed terminal reverse-queue overflow, distinct framed exit nonces, stale-instance without hidden retry, response/assignment shape, socket tuple/flag checks, binding and ownership behavior, digest-failure FD cleanup, stream fragmentation with exactly-one ancillary transfer, incomplete/late/extra descriptors, timeout cleanup, and the dormant exit runtime closing its listener before `exit_listener_orchestration_unavailable`. The clean full-graph API-v6 ASan+UBSan gate passes. Peer-control v4 retains separate zeroizing, non-cloneable one-shot client/exit authorizations. Isolated native foundations now model one bounded, externally serialized exit session and validate the leaf identity in a bounded PEM certificate chain against its private key, a non-wildcard DNS hostname under case-insensitive X.509 DNS semantics, trusted interval, canonical complete-leaf DER digest, and DER SPKI digest. They have no runtime caller and do not perform trust-chain validation. Native still does not verify the signed bundle, cache general request nonces, or retain ledger state across restart; production also lacks a preverified affine handoff through the agent, separate role service identities/sockets, exact helper-derived millisecond-to-trusted-interval conversion, a fixed independent Rust/C DER-SPKI vector, parser fuzzing, server-side pool allocation/uniqueness/lifetime binding plus exact-namespace assigned-address proof, disposable-topology evidence, trusted helper provenance, and the actual exit backend, so route setup and the launcher remain blocked.
- [ ] Pre-route client ingress uses typed tags 31–34, exactly eight kind/family identities, one-shot agent acquisition, cross-unique handles/receipts, canonical exactly-one-FD binding, error-preserving RAII capabilities and retryable destroy; pure/socketpair tests pass, but production deliberately returns `Unavailable` before state/network until the namespace listener, privileged transfer cache, atomic TPROXY/DNS/kill-switch transaction, rollback and live proof exist.

## Identity and signed protocol

- [x] `volparossa init` creates an Ed25519 identity and derived libp2p Peer ID.
- [x] Private identity is encrypted at rest and created with mode `0600`.
- [ ] Session identities and WireGuard keys are ephemeral per route/path context.
- [ ] Canonical signed envelopes include version, sender, timestamp, expiry, nonce, message type, payload hash, and signature.
- [ ] Invalid signatures, unsupported versions, expired messages, replayed nonces, excessive lengths, and malformed encodings are rejected.
- [ ] Key rotation rules and compromise recovery are documented and implemented.

## Decentralised discovery

- [ ] rust-libp2p QUIC transport is integrated with Identify and Ping.
- [ ] VOLPAROSSA-specific Kademlia protocol and capability provider records are integrated.
- [ ] mDNS, AutoNAT, DCUtR/hole punching, and Circuit Relay v2 control-plane support are integrated.
- [ ] Versioned `/advertisement/4` fetches relay advertisements directly, while exit advertisements
  use only `/exit-forward/4` plus `/exit-forward-upstream/4`; the discovery crate proves the
  three-hop shape. The live single-owner agent actor now serializes policy application and
  cross-ledger revocation before reply, and linearizes freshness, current policy/authority, replay,
  and peerstore mutation in one synchronous advertisement commit before successful completion is
  cached or replied. A crate-private command can now produce a sorted, unique, at-most-200
  in-process snapshot only after production signature revalidation and exact persisted
  fingerprint/actor capability/policy joins. Expired, conflicted, self, pending-direct, unpaired,
  direct-only exit, and multiply-control-paired exit records fail closed. The snapshot has no
  production caller, serialization, or dispatch authority. Control-v4 tags 17 and 18 now define a
  protocol precursor with no production/network caller for an actor-signed direct observation
  transcript or an exit-signed receipt nested in a control-signed public-prefix claim. The
  dedicated verifiers are transactional and return opaque affine transcripts. A separate dormant
  A1a owner now validates
  an endpoint-free reduced snapshot and local conservative ceiling, internally mints a 16-byte
  batch ID plus two to nine unique 32-byte request/challenged-relay-or-exit challenges (the control
  shares the exit challenge), and retains one forwarded response plus one to eight direct-relay
  responses as three to ten opaque signed-envelope proofs. It allows only one
  JIT pending request, uses fixed 5-second request/30-second attempt/30-second cooldown windows,
  120-second challenge and batch tombstones (36+4), and a 40-entry replay cache without redraw,
  retry, or live eviction. On pre-entropy rejection `PreselectionBeginFailure` retains the original
  gate without cooldown; after admission only a valid non-decreasing terminal clock returns a
  cooling gate, while invalid/backward/overflowing time loses it fail closed. Its opaque
  `BoundPreselectionTranscriptBatch` records no authenticated
  connection/socket, send/arrival event, direct prefix, RTT, reachability, Fresh validity, capacity
  authority, reservation, route-session, or dispatch authority. The completed affine A1a owner
  retains the original non-cloned candidate snapshot as a sibling, never inside that endpoint-free
  transcript batch, so a later exact-set owner need not reconstruct the candidate union. Any
  advertised control endpoints in that existing actor-private snapshot never enter the transcript
  batch or opaque transport proof. Discovery now composes two role-gated v4 request-response wire
  behaviours over unchanged exact A0 canonical bytes: Client outbound/Relay inbound for direct
  Relay receipts or forwarded Exit attestations,
  and Relay outbound/Exit inbound for forwarded Exit requests and Exit receipts. Requests and
  receipts are bounded to 4096 bytes, forwarded attestations to 8192 bytes; both behaviours use an
  exact five-second timeout, 64 streams, distinct event/request-ID domains, no legacy aliases and
  no retry. Their opaque wrappers and codecs enforce only state-free canonical/version/hop
  type/role/payload/envelope shape on read and write. A dormant service seam derives the target and
  family from an exact client-hop request, admits one active dispatch, captures a connection witness
  immediately before send, and can cancel it or bind a typed response event after internally
  stamping arrival. Binding rechecks the exact service, request ID, peer, event-local connection,
  half-open deadline, uniqueness, generation and native prefix; the affine bound result exposes no
  field or decomposition. Explicit cancellation consumes the exact originating token. Drop, a
  non-response event, unavailable pre-correlation wall time, or a service/ID/peer mismatch leaves
  the only slot occupied fail closed. Exact correlation consumes it before later time or provenance
  checks. There is still no production root or lifecycle owner, producer, signer,
  application handler, sampler, runtime/agent caller, upstream sender, responder/forwarder,
  cryptographic verification/replay, A1a exact-set join, or conversion into fresh local evidence.
  A future A1c boundary must consume and exact-set join these real request/connection proofs before
  phase-A evidence. A first dormant private A1c precursor now passively tracks authenticated libp2p
  establish/address-change/close lineage under the existing 384-global/four-per-peer ceilings.
  It counts unusable siblings for uniqueness, accepts prefixes only from exact direct public-IP
  TCP or QUIC-v1 remote shapes, retains only the opaque normalized token plus the same native three
  or six prefix bytes (no full IP/multiaddress), generation-invalidates every address change, and
  permanently poisons and clears on ambiguous lineage or overflow. Its affine
  witness/binding rechecks the exact Peer ID, `ConnectionId`, non-zero generation and native /24 or
  /48. It has no generic registry/address/prefix accessor; only the purpose-specific client seam
  may consume its affine witness. There is still no A1a join or Fresh-evidence mint. The
  fake-only 1-200-record evidence boundary and prospective planner remain separate;
  no checkbox is closed. Production still publishes no usable relay/exit capability, route
  finalization still fails closed with `ProbeEvidenceUnavailable`, and no production evidence
  producer, production transaction caller/orchestration or disposable live-network proof exists.
- [ ] Bootstrap from peerstore, mDNS, multiple independent built-ins, peerlinks, and signed bootstrap files works.
- [ ] No bootstrap node or DHT record becomes a unique authority or central node catalogue.
- [ ] `volparossa://peer/...` peerlinks round-trip and validate.

## Advertisements, peerstore, and reputation

- [ ] Signed advertisement schema contains the required bounded fields, but production currently
  signs only client advertisements and withdraws provider state whenever relay or exit is enabled;
  no usable service capability is published.
- [x] Advertisement TTL, monotonic sequence, signature, consistency, v4 protocol, active-policy,
  current-authority, and replay checks fail closed at one synchronous commit boundary.
- [ ] SQLite has bounded schema/APIs for advertisements, endpoints, reachability, path measurements,
  delivery history, uptime, failures, policy hash, and last success; the agent discovery actor
  produces advertisement/endpoint writes, but no production measurement, failure, or
  session-success producers exist.
- [x] Peerstore does not persist browsing domains or destination history.
- [ ] A tested conservative capacity primitive takes the minimum of advertised free, fresh local
  p25 when present, and a conservative preselection capacity ceiling. Snapshot projection
  deliberately omits stored endpoint/RTT/capacity history; the fake batch accepts scope-bound
  p25/count, one normalized public /24 or /48, exact advertisement payload hashes and that ceiling
  only from test observations and preserves sparsely measured peers as bounded exploration. The
  prefix, hashes and ceiling grant no provenance, reservation or dispatch authority. Explicit
  validity is bounded by freshness, policy, advertisement and actor capability expiry. The bridge has no
  runtime caller or observation producer, so the intended actor path remains at zero usable route
  candidates instead of substituting control-plane or stored evidence.
- [ ] A bounded 70/20/10 exploration primitive and a peer-only prospective relay selector are
  tested. The latter canonically handles at most 200 candidates, returns at most eight, and applies
  strict control/exit/slate diversity without synthetic complete-path metrics. Its dormant
  prefix-native path and the source-compatible legacy full-origin adapters use one shared
  filter/scoring/band/RNG/diversity core. No production route-selection caller lets new peers
  participate yet.
- [ ] The reputation model is local and has no universal score, but production observation
  producers and the route-selection consumer are not connected.

## Policy and whitelist enforcement

- [x] Canonical manifest supports version, validity, domains/patterns, protocols/ports, explicit IPs, maintainer keys, and signatures.
- [x] Threshold verification defaults to three-of-five production maintainer signatures.
- [x] Development keys are clearly marked and rejected in production mode.
- [ ] Live policy refresh is serialized through the discovery actor and revokes mismatched
  capability and forwarding authority before reply; selection rejects mismatched exits, but
  decentralised distribution and usable relay/exit policy-hash publication are not wired.
- [x] Domain pattern matching is label-safe and raw IP fails closed unless exact-listed.
- [ ] Exit-side resolution pins approved addresses to a flow/session and defends against rebinding.
- [ ] TCP allowlist enforces hostname, port, and TLS ClientHello SNI; missing SNI, mismatch, and ECH fail closed.
- [ ] QUIC Initial parsing enforces approved hostname/SNI on UDP/443; missing verification and ECH fail closed.
- [ ] General UDP pins an approved domain/protocol/port tuple with short idle timeout.
- [ ] DNS travels through the exit; arbitrary external resolvers and physical-interface leaks are blocked.
- [ ] Rejection logs use reason codes without durable full hostnames.

## Candidate, exit, and relay selection

- [ ] Candidate pool targets approximately 200 usable peers and applies every hard filter. The
  actor now has an exact 200-entry snapshot bound, but its production usable-candidate count
  deliberately remains zero.
- [ ] Weighted candidate selection uses the specified 30/20/15/15/10/10 inputs and 70/20/10 exploration tiers.
- [ ] Exit selection occurs before relay selection and uses the specified weighted factors. A
  dormant fake-only planner now consumes an exact snapshot-bound observation batch and selects one
  exactly forwarded exit before constructing a prospective relay slate. Its conservative
  preselection capacity ceiling and normalized prefix are only test scalars and establish no offer,
  hold, reservation, admission, provenance or dispatch authority. Exact advertisement payload hashes
  bind the projected advertisement, direct/forwarded capabilities, Fresh/authenticated/verified
  records and later capability re-resolution. A1a and Fresh remain disconnected; no production
  producer or caller supplies this evidence.
- [ ] Relay selection measures and scores the complete client-relay-exit path. The second dormant
  scalar preflight stage can require complete evidence bound to the selected exit and exact relay
  snapshot, but it remains a test-only boundary and is not called or trusted by the new phase-A
  plan. The plan contains no complete-path scalars. The separate private/dormant route transaction
  now moves one session, hold and the original non-Clone-bound probe objects through an internal
  measured continuation with the same IDs and absolute deadline. Its canonical post-probe selector
  ignores pre-probe active/warm hints: any eligible measured path may satisfy the minimum, while
  additional active paths still require unique-throughput gain or failover value. A dormant
  phase-C1 boundary can consume the phase-A plan once, preserve actor-specific evidence windows,
  assign stable prospective path IDs, carry one bounded Tokio deadline and mint one route-authority
  pair plus one `ReservationSession` only after all validation. Dormant C2a/C2b prerequisites make
  the phase-B request a flat ordered list of
  explicit prospective path IDs and remove pre-probe active/warm roles; final policy counts remain
  independent, so a UDP `1/1/1` policy may probe several prospects. The bridge consumes each full
  `Candidate` into a private actor-bound proof before request construction. That proof retains exact
  batch/actor/key/sequence/payload-hash/policy/expiry/static-scope/forwarded-exit binding, an
  observed prefix and
  an opaque value-only selection projection, but no full advertisement, advertised endpoint or raw
  observed-origin IP. Request, path and proof values are non-cloneable, non-debuggable and
  non-serializable. Post-probe scoring revalidates their exact time/scope binding and uses the same
  canonical selector core as the source-compatible legacy API; successful selection consumes all
  proofs and forwards only proof-free selected actor bindings, while error retains the original
  transaction for rollback. The private unmeasured wrapper moves one caller-supplied deadline into
  the measured continuation, and the transaction no longer exposes its old resolve-and-generate
  constructor or a product session-remint call. The dormant C2c adapter now consumes the C1
  continuation under one manager task/watch, recomputes its exact actor/evidence ceilings, builds
  the sanitized request in stable path-ID order, and performs one bounded borrowed re-resolution
  through the same owned combined resolver/transport value; the adapter accepts no second handle
  between these phases. It post-checks wall time, cancellation,
  deadline, proofs and resolved capabilities—including exact advertisement payload hashes—before
  moving the original session, IDs, limits and
  unchanged deadline into `UnmeasuredRouteSetup`. Pending cancel, call timeout or handle drop ends
  before reservation dispatch with no helper/journal cleanup. Real measurement production,
  production probe verification/handling, production orchestration and a production caller remain
  absent, so the checkbox remains open.
- [ ] Path capacity is the minimum of both legs, relay free capacity, and exit reservation.
- [ ] Operator, IPv4 /24, IPv6 /48, ASN, and visible-access diversity constraints are enforced.
- [ ] Defaults select four active, at least two, at most eight, plus two warm backup paths with RTT-spread/hysteresis rules.
- [ ] A new path is activated only for meaningful unique throughput (about 10%) or failover value.
- [ ] The dormant prospective selector enforces node/Peer ID, operator, ASN and one normalized
  public IPv4 /24 or IPv6 /48 against control, exit and the slate. The fake evidence, plan and actor
  proof retain no full host IP; the legacy candidate-origin field is `None`. This limits one selected
  slot per observed cluster but does not eliminate pre-sampling Sybil identity multiplicity. The
  broader production anti-Sybil layers, age/rate policy, authenticated ConnectionId/send-arrival
  evidence and live observation producers remain incomplete. There are still zero usable production
  candidates, and this item remains open.

## Reservations and path lifecycle

- [ ] Hard-incompatible reservation/control v4 uses a fresh session key/ID and signed, bounded
  capacity-hold -> probe-permit/evidence -> exact relay-set finalize -> relay-grant -> exact
  confirmation-receipt phases; v4 wire/package types remove permanent client Peer-ID fields and
  reject v1/v2/v3/future envelopes without fallback. The hold separately binds a final path-count
  upper bound and a prospective permit limit with `1 <= maximum_paths <= probe_permit_limit <= 8`;
  protocol, coordinator, exit, relay, fixture, and agent route tests cover missing-field rejection
  and a non-contiguous 2/5/8 final subset. The migrated route coordinator remains private/dormant
  and has no production caller. Its private phase-B split returns the original transaction on a
  measurement error, rejects cancellation/deadline expiry before retirement/Prepare, and builds one
  finalize frame only after Prepare while retaining the same session/IDs/deadline. The route-level
  probe associated type is no longer Clone-bound, but public reservation `Verified*` values are not
  claimed to be affine and `VerifiedRelayProbe` remains cloneable for API compatibility. C2a/C2b
  admit only explicit ordered prospective IDs `1..N` (1-8 and at least the policy minimum), retain
  affine actor-bound proofs until successful post-probe selection and carry one bounded
  caller-supplied deadline from the private unmeasured wrapper through phase B; work already expired
  when wrapper execution begins fails before its first protocol, transport, retirement or helper
  event. Exact probe-ID membership is checked before capacity filtering, and later trusted time is
  checked against every proof before selection completes or helper Prepare. The private C2c seam
  now consumes the C1 pre-probe continuation into the existing transaction with the same freshly
  minted session/ID pair, stable path IDs, limits and absolute deadline after bounded actor
  re-resolution. Dropping C1 before the handoff still needs no rollback; cancelling, timing out or
  dropping a pending resolver also occurs before reservation dispatch and makes no helper or
  journal cleanup claim. No production caller invokes this seam. A separate dormant owner-first
  prerequisite can retain one already-running route handle or one established route. Its occupied
  slot returns a second handle intact but is not admission control and does not prevent that second
  task from already having dispatched. Consuming settlement keeps success established, reopens the
  slot only after `NotRequired`/`Destroyed` failure cleanup, and leaves `Quarantined` terminal.
  Consuming drain cancels and waits for pending work, immediately retires a racing late success, or
  tears down an established route; dropping the owner/future delegates to the existing handle and
  retirement RAII. It does not own/start/shut down the manager, and a future production lifecycle
  must drain it before manager shutdown. It has no production caller, so admission-before-spawn,
  production lifecycle integration and end-to-end route ownership remain incomplete.
- [ ] Every exit-facing v4 scope binds the chosen control-relay node/Peer ID, exit node/Peer ID and
  boot incarnation, policy, capacity, session key/ID, hold/finalize IDs and expiries; final bundle and
  confirmation hashes bind exact canonical frames and ordered authorizations. Finalization also
  signs only a domain-separated commitment to the affine 43-byte route bearer plus the MASQUE
  context and client-native process instance. The final exit grant signs the exact echo together
  with certificate/SPKI hashes, canonical TLS name, and exit-native instance. Client release is
  gated by the exact full confirmation-receipt path set; exit TLS ownership is separately
  zeroizing, absent from response caches, confirmation-gated, and one-shot. Release, purge, and expiry wipe pending
  ownership, and scope mismatch does not consume a legitimate retry. The discovery crate
  exposes no client-to-exit RPC; the migrated route coordinator resolves actor-minted capabilities
  and dispatches every exit phase only through the selected control relay. The coordinator remains
  private/test-only and has no live network or packet-capture proof. Its production bridge has no
  production native API-v6 preflight caller and therefore rejects before signing a hold or dispatching any
  reservation/helper operation; certificate/key consistency and native backend adoption remain
  incomplete.
- [ ] Exit/relay services reserve and roll back capacity through bounded idempotent state machines.
  Prospective permits cause no additional ledger debit; successful subset finalization clears
  unused permits and their response cache while retaining only the exact finalize retry response,
  and every finalize error leaves the held permits fail-atomically intact. Production finalize
  deliberately returns `ProbeEvidenceUnavailable` until helper-proven endpoints/readiness and an
  exit-participating disposable probe producer exist; only an explicit test-only evidence verifier
  reaches the subsequent helper phases in tests.
- [ ] The v3 lease API exposes only opaque handles and public endpoint material and has no private-key
  input/output. Production obtains no WireGuard lease because `HelperEngine::new` returns
  `Unavailable` before endpoint publication or helper-owned kernel key/port/underlay proof.
- [ ] Typed/pure/fake helper boundaries prove exact public handles, cardinality, TTL, idempotency,
  state transitions, and handshake/RX/TX proof policy. Agent route tests exercise
  prepare/activate/commit/destroy and destroy-first retirement through fake backends, but the
  coordinator has no production caller and no live worker/kernel tunnel exists.
- [ ] Service ledgers reduce internal available capacity immediately, but production publishes no
  relay/exit advertisement, so advertised free-capacity updates are not wired.
- [ ] Ledger/service tests prove that explicit expiry purging restores capacity, and the agent
  discovery runtime contains a periodic purge path; no live capacity-restoration or advertised
  free-capacity propagation proof exists.
- [ ] Path state machine implements cold, reachable, warm, active, backup, degraded, and dead.
- [ ] Passive metrics, bounded probes, hysteresis, replacement, and per-direction observations are implemented.

## WireGuard, NAT traversal, and routing

- [ ] Each path creates two separate ephemeral kernel WireGuard links: client-relay and relay-exit.
- [ ] Each path has unique route ID, path ID, keys, ULA prefix, endpoint addresses, routes, authorisation TTL, and limits.
- [ ] Product code configures WireGuard and networking through netlink/UAPI, not parsed CLI output.
- [ ] Relay nftables permits only the authorised prefixes/protocol/interfaces/time and denies host access and Internet egress.
- [ ] Dataplane traversal attempts IPv6, public IPv4, coordinated UDP endpoint punching, bounded keepalive, then rejects unsuitable paths.
- [ ] libp2p circuit relay is never an implicit WireGuard dataplane fallback.
- [ ] TPROXY namespace intercepts TCP, UDP, and DNS, recovers original destinations, excludes tunnels/control traffic, and prevents loops; typed socket and fail-closed TCP/UDP original-destination UAPI foundations have pure/socketpair tests, but no namespace/nftables transaction or live interception exists.
- [ ] Kill switch prevents physical-interface leaks while preserving explicit control/tunnel reachability.

## TCP over real MPTCP

- [ ] Transparent TCP interception feeds a streaming local proxy.
- [ ] Versioned `OPEN_TCP` framing is signed, bounded, and validated at the exit.
- [ ] Client-to-exit proxy framing is protected by TLS 1.3 while preserving the application's own byte stream/TLS.
- [ ] Proxy sockets explicitly use `IPPROTO_MPTCP`; ordinary TCP fallback is impossible by default.
- [ ] `MptcpPathManagerBackend` and Debian 13 kernel path-manager backend create only selected path subflows.
- [ ] Exit validates policy, resolves/pins the destination, validates visible TLS SNI, connects, and streams without message-sized buffering.
- [ ] At least two MPTCP subflows carry real data over different relay paths.
- [ ] Bidirectional scheduling works, aggregation exceeds a single constrained path where topology permits, and relay failure preserves the application flow.

## General UDP through one relay

- [ ] Transparent UDP interception/classification and original destination recovery work; exact family-matching original-destination ancillary parsing fails closed in pure/socketpair tests, but the live transparent UDP listener and routed datapath are not connected.
- [ ] Signed flow authorisation binds a single approved destination tuple.
- [ ] QUIC DATAGRAM over MASQUE CONNECT-IP/CONNECT-UDP traverses exactly one WireGuard relay path.
- [ ] Datagram semantics, destination immutability, idle timeout, and explicit DNS policy are enforced.
- [ ] Path failure may create a new association but never leaks or silently connects directly to the exit.

## Genuine Multipath QUIC / MASQUE

- [x] Current `mp0rta/mqvpn`/xquic upstream is inspected, license/draft compatibility recorded, tests run, and an exact commit pinned.
- [x] Native integration layer is isolated behind a versioned, bounded Unix-socket API (or justified safe FFI).
- [ ] MASQUE CONNECT-IP and QUIC DATAGRAM carry original browser QUIC/IP packets.
- [ ] At least two simultaneously active outer QUIC paths bind to distinct selected WireGuard interfaces/addresses and carry real data.
- [ ] Paths can be added/removed dynamically; failover preserves the inner QUIC flow where protocol permits.
- [ ] Per-path RTT, loss, congestion window, delivery rate, queued bytes, and bytes-in-flight are reported.
- [ ] Swappable scheduler predicts delivery time from RTT, queue/rate, congestion, and loss and honours congestion control.
- [ ] No duplication, FEC, or false multipath reporting exists.
- [ ] UDP/443 classification recognises valid QUIC Initial packets and policy-verifiable SNI.
- [ ] Required-multipath mode defaults to at least two paths and fails closed without an unsafe downgrade.
- [x] Native upstream and the current API-v6 sanitizer gates pass: the pinned
  graph passed 35/35 upstream and 9/9 wrapper tests under ASan+UBSan with
  bounded SIGINT/SIGTERM lifecycle smokes; the earlier recorded release
  Valgrind gate also passed.

## Logging, metrics, and operations

- [ ] Structured logs contain ephemeral session/path/error/version/aggregate fields and redact prohibited metadata/secrets.
- [ ] A local-only, label-free metrics endpoint and bounded metric registry exist, but production
  does not yet produce the required throughput, RTT, loss, session, MPTCP, or MPQUIC observations.
- [x] No external telemetry is present.
- [ ] `doctor` checks every specified kernel, tool, capability, network, route, policy, library, and clock prerequisite.
- [ ] Cleanup command is safe, scoped, previewed, and idempotent.
- [ ] Demo exercises the real local topology or clearly reports unmet prerequisites.

## Testing and fuzzing

- [ ] Unit/property tests cover canonical encoding, signatures, replay, TTL, advertisements, whitelist, route contexts, scores, diversity, capacity, reservations, framing, versions, cleanup, and configuration.
- [ ] Fuzz targets cover advertisements, policy, control messages, TCP open, UDP authorisation, QUIC classification, TLS ClientHello, and QUIC Initial parsing.
- [ ] One command builds the full disposable namespace topology in the master specification using
  veth, nftables, and `tc netem`; the unprivileged lifecycle frame/state, fixed two-endpoint spec,
  run-name, ownership-manifest, confirmation, and refusal contracts pass. A separate test-only
  runner now provisions the random run ID and original namespace identities over a dedicated
  inherited unnamed seqpacket channel while retaining separate bootstrap-control and lifecycle
  channels. It kernel- and executable-authenticates its fixed parent/child pair, rejects duplicate
  or timed-out provisioning, re-executes only its fixed image with a descriptor fence, and directly
  creates anonymous user, mount, network, and pending child PID namespaces. Before mapping, the
  outer holds a pidfd, anchored proc directory, exact user/mount/network/current-PID namespace FDs,
  an empty child-set proof, and the kernel-defined uninstantiated `pid_for_children` proof. It then
  installs and independently reads back one UID/GID mapping extent. The launcher emits its mapping
  verification but cannot spawn until the outer repeats its anchored readback and returns one
  affine `MAPPINGS_PINNED` proceed record. It subsequently creates exactly one fixed
  self-reexecuted PID 1 and upgrades the full namespace proof. PID 1
  checks its PID/PPID, mappings, credentials, namespaces, environment, cwd, task count, and
  parent-death signal; the outer independently proves its executable/selector, PID nesting,
  mappings, namespaces, empty descendant set, and sole launcher-child relation. Only after the
  outer returns its run- and PID-bound pin does PID 1 make the inherited mount tree recursively
  private and use the descriptor-based Linux mount API to attach a fixed 16 MiB, 4096-inode,
  mode-0700 tmpfs at `/run` plus a new procfs at `/proc`, both with `nosuid,nodev,noexec`.
  PID 1 retains fixed root, `/run`, and `/proc` descriptors and repeatedly binds their visible
  mount IDs to bounded mountinfo, requires no propagation relationships, and proves the exact
  PID/task set `{1}` with no child. The outer independently repeats the mount-ID, filesystem,
  capacity, ownership, PID-namespace, PID/PPID/task, and empty-child proof while PID 1 remains
  pinned. Before any child process or fallback-reaper thread exists, the outer requires exact
  default inherited HUP/INT/TERM actions, a waitable default CHLD action, and an empty inherited
  signal mask. It then blocks HUP/INT/TERM/CHLD and owns the nonblocking close-on-exec `signalfd`.
  PID 1 inherits that
  exact mask, installs fixed HUP/INT/TERM emergency handlers, and verifies them directly through
  the audited Linux-UAPI layer. The outer independently requires exact live proc masks
  (`SigBlk=0000000000014003`, `SigCgt=0000000000004443`, and no managed ignored or pending bit)
  through its retained pidfd and proc anchor. The caught mask is `0x4003` managed handlers plus
  the repository-pinned Rust 1.85.0 runtime's `0x0440` SIGBUS/SIGSEGV baseline on Debian 13 amd64,
  not a Linux ABI constant. After mount verification, PID 1 directly proves the enumerated
  read-only pre-`GO` network-readiness baseline and constructs one canonical `BOOTSTRAP_READY`
  bound to the run and its measured network, mount, and PID namespace identities. The RTNL part
  pins the down-loopback configuration, including its mutable GSO/GRO limits, and proves empty
  address, route, ordinary/proxy-neighbour, nexthop, and unexpected-qdisc object sets plus the
  exact default IPv4/IPv6 rules. Each complete observation also reads the fixed namespace-local
  `/proc/sys/net/ipv4/ip_forward` record through the retained private-proc descriptor, accepts
  only canonical `0\n` or `1\n`, and requires its procfs object identity and value to remain
  stable within that observation and to match the value authorized for the current lifecycle
  phase. A bounded read-only `NETLINK_NETFILTER` exchange requires generation 1 immediately
  before and after complete table, chain, rule, set, object, and flowtable dumps, all of which must
  be empty. This readiness proof does not claim that IPv4 forwarding is disabled and makes no
  forwarding-setting request before `GO`. These observations do not claim that every netconf or
  firewall/netfilter facility is empty. Qdisc enumeration and disposable live `ingress`/`clsact`
  rejection tests prevent such a hook from hiding behind link qdisc name `noop`; traffic-control
  classes, filters, and chains are
  not separately enumerated because this slice admits no non-baseline qdisc on which they could
  attach. Other netconf, address-label,
  neighbour-parameter, conntrack, ipset,
  NFQUEUE/NFLOG, legacy-xtables, and independent-hook state remains outside this proof. The fixed
  GET requests may cause ordinary kernel module loading but create no firewall object. A strict
  production raw-`NFNETLINK` writer and observer implement the exact lifecycle policy: one
  run-derived `inet vpl_<run_id>` table, one priority-0 `filter` base chain named `forward` with a
  drop policy, and exactly three ordered rules. The first matches only the endpoint-A-to-B IPv4
  ICMP echo-request tuple and places one inline counter immediately before `accept`; the second
  matches only its exact B-to-A echo reply and likewise places one inline counter immediately
  before `accept`; the third is unconditional and places one inline counter immediately before
  `drop`. Before packet authority is consumed, every fresh complete active-policy observation
  accepts the three typed counters only when each is exactly `packets=0` and `bytes=0`. The
  one-way fixed-ICMP counter phase cannot regain zero-counter authority. After the sole raw socket
  closes, success requires two identical complete generation-bracketed observations with
  request/reply/drop packets/bytes exactly `1/60`, `1/60`, and `0/0`; subsequent teardown retains
  only counter-agnostic deletion authority. The nftables writer's sole mutation surface is one
  bounded generation-pinned atomic install and later handle-only table deletion, with strict capped ACK binding and fresh
  complete-ruleset reconciliation after every possibly sent request. Disposable namespace tests
  exercise that production writer and prove an empty generation-1 baseline, the complete exact policy at
  generation 2, and a semantically empty ruleset at generation 3 after removal. The live fixture
  also proves its inherited canonical forwarding value byte-identical; extra or altered policy
  objects, counter values, expression order, ACKs, handles, and generation lineages fail closed.
  An isolated observation cannot prove counter stability or packet absence because nftables
  generation IDs do not bind counter updates. The integrated proof instead joins one affine send
  authority to one exact reply, two matching post-close counter observations, and exact four-veth
  link telemetry. A separate fixed, descriptor-pinned
  proc writer can establish canonical `1\n` only in PID 1's disposable parent network namespace
  and later restore the exact retained original `0\n` or `1\n` record. It requests one bounded
  two-byte write only when the target differs; an already-enabled or already-restored record is a
  freshly verified no-op. Possibly written requests retain reconciliation authority. After a
  possibly written enable, only an exact enabled readback may advance; even a return to the
  original record is indeterminate and aborts fail closed because a transient write cannot be
  excluded. Production sends only the fixed run-bound ICMPv4 request described below. It does not
  claim packet absence, packet-capture privacy, a general VPN datapath, topology readiness,
  `TOPOLOGY_READY`, A14, A15, or acceptance evidence.
  The outer accepts that actual lifecycle frame
  only after matching all three identities to its retained
  PID-1 namespace pins and repeating the live mount and signal proofs. Only then does the outer
  send one canonical `GO`. PID 1 consumes the resulting affine `MutationAuthorization` and
  immediately revalidates the complete pristine network baseline before its first write. Using
  only retained directory descriptors, the production `AuthorizedPrivateRun` transition creates
  exactly `/run/netns` and `/run/volparossa-netns-runner/<run_id>` at mode 0700 plus the two
  run-derived empty namespace slots at mode 0000. It proves the exact entry set and each retained
  object identity. One fixed PID-1 task then consumes that state into `AuthorizedNamespacePins`,
  creates two distinct network namespaces A and B, and restores its exact parent network namespace
  after each excursion. It clones each namespace into a detached nsfs mount through the audited
  `open_tree` UAPI and attaches that mount to its exact run-derived slot with `move_mount`. The
  runtime proves both published pins are `CLONE_NEWNET`, have the expected owning user namespace,
  are distinct from each other and the parent, expose the expected object and mount identities,
  and are joinable through their visible read-only pins. The bounded mountinfo proof requires the
  original baseline records unchanged plus exactly those two known mount-ID/path/nsfs/no-propagation
  additions beneath the private `/run` mount; it does not independently validate every possible
  nsfs root or option field. While visiting A and B through the visible pins, PID 1 runs the same
  complete pristine-network proof used at the lifecycle barriers and restores the exact parent
  after every visit. It then uses fixed, bounded RTNETLINK directly: exactly two `RTM_NEWLINK`
  requests with `NLM_F_REQUEST|NLM_F_ACK|NLM_F_CREATE|NLM_F_EXCL`. Each request derives its parent
  name from the authorized run ID, fixes MTU 1500, TXQLEN 1000, and one TX/RX queue on both sides,
  and creates peer `eth0` directly in the exact retained target via `IFLA_NET_NS_FD`; no
  create-then-move fallback exists. The affine `AuthorizedVethPairs` state retains the target nsfs
  identities and exact observed indices. Independent parent/A/B snapshots prove the down-veth
  profiles, peer and namespace lineage, unique locally administered MACs, exact zero fresh-link
  statistics/ifmap, unchanged non-link and qdisc state, IPv4-forwarding record, and empty nftables
  baseline. PID 1 then borrows that pair owner into one affine `AuthorizedIpv4Addresses`
  sub-transaction. It sends exactly four `RTM_NEWADDR` requests with
  `NLM_F_REQUEST|NLM_F_ACK|NLM_F_CREATE|NLM_F_EXCL`, deriving every address, `/30` prefix,
  interface label/index, namespace identity, scope, permanent lifetime, and rollback target from
  retained authority: parent A `10.241.1.1/30`, endpoint A `10.241.1.2/30`, parent B
  `10.241.2.1/30`, and endpoint B `10.241.2.2/30`. All four veth ends initially remain down.
  Independent parent/A/B snapshots admit exactly those four address records and the four
  kernel-created local-table `/32` routes coupled to them, while requiring every other route and
  RTNL object, qdisc observation, IPv4-forwarding record, and nftables baseline to remain
  unchanged. PID 1 then sends four separate bounded `RTM_NEWLINK` requests that change only the
  IPv6 address-generation mode to `none`, with an ACK, exact readback, and a distinct four-end
  proof barrier before any link-up request. Canonical retained run, pair, namespace, and parent
  ifindex lineage then supplies the only accepted policy expectation. PID 1 atomically installs and
  freshly proves the exact generation-2 policy described above before any link-up request. With
  that drop policy active and all four ends still down at IPv6 address-generation mode `none`, PID 1
  uses the retained private-proc descriptor to establish canonical `1\n` in the fixed parent
  `ip_forward` record. An original `0\n` causes exactly one bounded two-byte write; an original
  `1\n` is freshly re-read and adopted without a write. It next
  sends four separate link-up requests and
  requires an exact converged parent/A/B observation: every end is carrier-up with `noqueue`, no
  IPv6 address exists, and the admitted route additions are exactly four IPv4 local `/32`, four
  connected `/30`, four high-broadcast `/32`, and four local-table IPv6 `ff00::/8` multicast
  routes. The bounded read-only observer retains those exact requirements while tolerating only
  temporary stable kernel snapshots during route convergence inside the same two-second absolute
  deadline. Those routes remain kernel side effects of the fixed addresses and activated links.
  After fresh exact active-state reproof, PID 1 installs exactly two endpoint routes through bounded
  raw `RTM_NEWROUTE` requests: endpoint A `10.241.2.2/32 via 10.241.1.1 dev eth0` and endpoint B
  `10.241.1.2/32 via 10.241.2.1 dev eth0`. Each request uses
  `NLM_F_REQUEST|NLM_F_ACK|NLM_F_CREATE|NLM_F_EXCL` and an exact `AF_INET` `/32`, main-table,
  `RTPROT_STATIC`, universe-scope, unicast, flags-zero route header with attributes exactly
  `RTA_TABLE=254`, `RTA_DST`, `RTA_GATEWAY`, and `RTA_OIF`. The plan derives its namespace,
  destination, gateway, interface index, and both-pair lineage from retained authority. A fresh
  dump proves the parent equal to its active baseline and each endpoint equal except for its one
  authorized route; a non-exact sibling or any extra object fails closed. Route authority remains
  deletion-bound after a possibly sent request, including lost or ambiguous ACK/readback. PID 1
  next installs exactly four affine IPv4 neighbours through bounded raw `RTM_NEWNEIGH` requests,
  each with `NLM_F_REQUEST|NLM_F_ACK|NLM_F_CREATE|NLM_F_EXCL`, `AF_INET`, `NUD_PERMANENT`,
  unicast type, flags zero, and exactly `NDA_DST`, `NDA_LLADDR`, and
  `NDA_PROTOCOL=RTPROT_STATIC`. Their canonical install order is
  parent A, parent B, endpoint A, endpoint B. The two parent records map each fixed endpoint address
  to its endpoint MAC; the two endpoint records map each fixed parent gateway to its parent MAC.
  Every address, MAC, interface index, namespace identity, and route relationship is derived from
  retained affine authority rather than caller input. Strict semantic parent/A/B snapshots require
  exactly those four records, `NDA_PROBES=0`, zero proxy-neighbour records, and no other
  configuration delta. They validate the exact `NDA_CACHEINFO` structure but exclude only its
  volatile telemetry values from equality; unknown, duplicate, malformed, non-permanent, or
  conflicting neighbour records fail closed. The generation-2 policy is freshly re-proved with all
  three counters still exactly zero around installation. With those neighbours armed, PID 1
  consumes zero-counter authority and opens one nonblocking close-on-exec raw ICMPv4 socket in
  endpoint A, bound to `eth0` and `10.241.1.2`, connected to `10.241.2.2`, and enabled for
  `IP_PKTINFO`. It issues exactly one `sendmsg`, with no retry, for one 40-byte echo request. The
  identifier is the first two canonical run-ID ASCII bytes interpreted big-endian, the sequence is
  one, and the payload is the full 32-byte canonical ASCII run ID. Before the absolute deadline,
  one bounded receive must return an exact 60-byte IPv4 reply with matching source, destination,
  receive interface, `IP_PKTINFO`, IPv4 and ICMP checksums, identifier, sequence, and full payload.
  After socket close, two identical complete generation-bracketed observations prove the
  request-accept, reply-accept, and terminal-drop counters at exactly `packets/bytes=1/60`, `1/60`,
  and `0/0`. Fresh semantic parent/A/B RTNL observations prove every veth end at exactly one RX and
  one TX packet and 74 RX and TX bytes, with every other parsed 32- and 64-bit statistic zero,
  while routes, addresses, qdiscs, all four permanent neighbours, zero probes, and zero proxy
  neighbours remain exact. PID 1 then sends explicit bounded `RTM_DELNEIGH` requests in reverse
  endpoint B, endpoint A, parent B, parent A order, reconciles every possibly sent request to exact
  absence, proves the pre-neighbour routed state restored without changing the post-echo link
  telemetry, and re-proves the exact `1/60`, `1/60`, `0/0` counter profile. It never relies on link
  deletion to remove a neighbour. No `RTM_DELROUTE` request or encoder exists. PID 1 then consumes
  the joined reply/counter/telemetry proof, converts policy ownership to counter-agnostic cleanup
  authority, and directly deletes veth B followed by A as the sole route-removal mechanism. It does
  not attempt to restore link-down or
  EUI-64 state and does not run ordinary per-address rollback after the first possibly-sent link
  mutation. Both route owners, all four address owners, and both pair owners remain armed. After
  deleting both pairs, PID 1
  restores the exact retained original `ip_forward` record while the structural generation-2
  policy remains under counter-agnostic cleanup authority: an original `0\n` causes one bounded
  two-byte restore write, while an original `1\n`
  requires no write. The retained parent and endpoint baselines then prove all three namespaces
  byte-exactly equal to the enumerated network baselines for that restored phase while the exact
  generation-2 policy structure remains active. PID 1 then deletes only the freshly
  observed table handle in one generation-pinned atomic transaction, proves a semantically empty
  generation 3, and binds the final RTNL/proc and endpoint reproofs to that result. Only after those
  final proofs does one prevalidated infallible retirement barrier disarm the route, address, and
  pair owners. The restoration claim covers only the fixed `ip_forward` record: Linux may reset
  related per-device IPv4 configuration when forwarding changes, those additional devconf values
  are not exhaustively enumerated here, and their complete removal relies on destruction of the
  disposable parent network namespace after its last reference closes; this slice does not
  separately observe that destruction. PID 1 then ensures every detached-clone and transient
  visible-pin
  descriptor is closed before ordinarily unmounting nsfs B and then A with `UMOUNT_NOFOLLOW`,
  proves the hidden empty slots and exact original mountinfo baseline are restored, and removes
  every owned mount and link plus every transaction-retained descriptor reference. Namespace
  destruction after the last reference closes is governed by the kernel's reference-counting
  semantics and is not claimed as a separately observed event. The transition then rolls back slot
  B, slot A, the per-run directory, the workspace root, and the netns root, with the required
  directory `fsync` barriers. PID 1 returns to the `PristineRun` state, revalidates the pinned
  network baseline and private mounts, and emits the internal, canonical
  `MUTATION_ROLLBACK_COMPLETE` record through the launcher. The outer
  accepts and run/PID-binds that checkpoint, then independently proves that the private `/run` is
  empty again before sending exact TERM through the PID-1 pidfd. PID 1 consumes the real `signalfd`
  record and returns an affine run/PID/signal observation through the launcher. Lifecycle EOF is
  necessarily
  post-`GO` and is classified as `CleanupRequired`, after which PID 1 is exactly reaped.
  If the outer PID-1 pin is unavailable after spawn, one run-bound pre-mount abort record
  retires PID 1 without issuing a mount instruction. Only `EPERM` or `EACCES` from a fixed
  mount-UAPI operation may produce the exclusive
  `BlockedAtPrivateMountSetup` policy result; all malformed state, unsupported APIs, invalid
  options, resource failures, and failed evidence remain hard errors. The positive
  `BlockedAfterFixedIcmpEchoTeardown` route proves that complete read-only network baseline,
  one real pinned `BOOTSTRAP_READY`, the canonical `GO`, affine authorization consumption, the
  descriptor-relative root/slot transaction, two live pristine nsfs pins, two fixed down-veth
  pairs each created through one atomic `RTM_NEWLINK` request, their exact parent/A/B delta proof,
  the four fixed `/30` IPv4 addresses and exactly four kernel-created local-table `/32` routes while
  all ends remain down, the separate all-addrgen-NONE barrier, atomic exact generation-2 parent
  FORWARD policy installation, exact carrier-up activation of all four ends with `noqueue` and the
  complete kernel-created route set, both exact static endpoint routes and their exact parent/A/B
  observation, exactly four semantically proved permanent neighbours with zero probes and zero
  proxy-neighbour records, one no-retry 40-byte raw ICMPv4 request from endpoint A, one exact
  60-byte reply bound to the full canonical run ID, two identical post-close policy-counter
  observations at request/reply/drop `1/60`, `1/60`, `0/0`, and exact one-RX/one-TX plus 74-byte
  RX/TX telemetry on every veth end. It further proves canonical reverse neighbour removal back to
  the exact routed state without changing that telemetry, a final exact counter-profile reproof,
  conversion to counter-agnostic policy cleanup authority, direct veth B/A deletion, complete pristine reverse
  proof under generation 2 after exact restoration of the original parent `ip_forward` record,
  handle-only policy deletion, semantic-empty generation 3, final
  parent/endpoint reproof before route/address/pair owner retirement, the
  internal rollback checkpoint,
  the post-rollback empty-`/run` proof, the TERM/EOF/signal chain, and exact PID-1 exit/reap. The only
  transient topology is the two otherwise-pristine network namespace objects, their kernel-default
  loopback/rules, their nsfs mounts, two fixed veth pairs, four fixed IPv4 addresses, four active
  link ends, four `noqueue` qdiscs, fourteen associated IPv4 routes, four IPv6 multicast routes,
  four affine `NUD_PERMANENT` IPv4 neighbours, and the one transient exact `inet`
  policy table/chain/three-rule counted set. The parent namespace's fixed
  `ip_forward` record is conditionally changed from `0\n` to `1\n` and restored to `0\n`; an
  inherited `1\n` takes the no-write path throughout. The outer host record remains byte-identical.
  This slice proves one fixed run-bound ICMPv4 echo exchange and its joined reply/counter/link
  evidence. It makes no packet-absence, packet-capture-privacy, general VPN datapath,
  network-topology-readiness, `TOPOLOGY_READY`, forced-crash-cleanup, A14, A15, or acceptance claim.
  Repeated portable tests prove exact
  outer-launcher reaping, unchanged outer namespace/mount observations, and an unchanged canonical
  outer fingerprint of stable link fields,
  addresses without expiring lifetimes, IPv4/IPv6 routes and policy rules, nexthops, qdiscs without
  counters, IPv4 `ip_forward`, IPv6 `all/default` forwarding, and `/etc/resolv.conf` object/target
  identity plus content. They
  exclude volatile neighbour/carrier telemetry and do not claim an authoritative comparison of host
  nftables/legacy-firewall state, resolver-daemon caches, or VPN-private peer/key state. This remains
  rollback evidence rather than A14, A15, or acceptance evidence.
  Normal reaping retains both pidfd and exact `Child` ownership; every forced `SIGKILL` after
  admission targets that pidfd.
  Pidfd acquisition is mandatory; its failure closes the private channels, attempts `SIGKILL`
  against the still-owned unreaped child, and synchronously waits/reaps it before returning the
  pidfd error. The public `--run` entry requires one task, and a non-default `SIGCHLD` handler or
  `SA_NOCLDWAIT` is rejected before any spawn. The rare process-local fallback-reaper path is not
  post-exit cleanup or A14 evidence. Required parent, namespace, mapping, mount-policy, and outer
  PID-1 proofs fail closed when kernel policy hides them. Generic CI may therefore prove only
  fail-closed behaviour. Pre-isolation parent-proof or namespace-policy denial uses a bounded
  control/lifecycle half-close handshake that keeps the launcher alive until the outer
  acknowledges EOF, preventing an early-`SIGCHLD` race; only the outer containment deadline bounds
  that wait. Complete live evidence for this slice requires the explicit
  `BlockedAfterFixedIcmpEchoTeardown` outcome. At supervised IPC boundaries, managed outer
  HUP/INT/TERM prioritizes bounded exact-launcher containment; the live gate does not yet prove
  external-signal handling across every reap/report phase, general descendant reaping, forced
  parent-death/crash-chain cleanup, or A14. The production ownership and namespace modules and their
  affine `PristineRun`/`AuthorizedPrivateRun`/`AuthorizedNamespacePins`/`AuthorizedVethPairs` and
  borrowed `AuthorizedIpv4Addresses`, `AuthorizedIpv4AddrgenNone`,
  `AuthorizedActivatedTopology`, `AuthorizedEndpointRoutes`, `AuthorizedPermanentNeighbours`, and
  `AuthorizedDeletedTopology`
  typestates plus the affine initial/active/retired nftables authorities, the enabled/restored/
  indeterminate IPv4-forwarding authorities, and
  `PolicyBoundPrivateMounts` are active in the runtime path for the
  descriptor-relative private-root, empty-slot,
  two-pin, two-veth, four-address, counted forward-policy, conditional parent-forwarding enable/restore,
  link-activation, endpoint-route, permanent-neighbour, fixed-ICMP echo, deletion-only link teardown,
  and exact policy-retirement
  transaction described above. A provisional
  containment guard is installed immediately after each exclusive creation. Within this fixed
  runner's one-PID-1-task and trusted-launcher scope, an inotify witness rejects delete, move, or
  recreate activity during the non-atomic `mkdirat`-to-open handoff. A retained descriptor plus
  that exact handoff observation permits only a scoped cleanup attempt; the guard performs an
  immediate second descriptor/path/parent/shape revalidation before any unlink. If the new
  directory cannot be pinned unambiguously, it is not unlinked by name and the
  run fails closed until its disposable mount namespace is torn down. Only fully pinned and
  journalled entries can reach the rollback-complete checkpoint. This is not an identity-conditioned
  kernel unlink primitive and does not defend against a hostile mapped-same-UID process that
  already holds a writable descriptor into the private mount. A production helper must establish
  root-owned exclusive mutation authority before reusing this transaction. A private
  `cfg(test)`-only Rust model still covers the separate canonical ownership manifest
  reader/classifier and atomic tempfile publication machine. It verifies exclusive
  pending creation, exact bounded readback, file/directory sync, no-replace rename, immediate
  pinning, failpoints, and reverse identity-scoped unlink of its own synthetic regular-file
  fixtures. Manifest publication remains test-only: production does not create or publish an
  ownership manifest. The runtime does construct and fully reverse two transient live nsfs pins,
  two fixed veth pairs, four fixed IPv4 addresses, four active link ends, two explicit endpoint
  routes, four explicitly removed permanent neighbours, the exact kernel-created qdisc and route
  side effects, one fixed run-bound ICMPv4 exchange with exact reply/counter/link evidence, and the
  transient generation-2 nftables policy's affine zero-to-`1/60,1/60,0/0`-to-cleanup transition
  described above, but proves direct link deletion, handle-only policy
  retirement, and
  ordinary unmount only within its fixed one-PID-1-task and
  trusted-launcher scope.
  Cleanup uses the retained parent directory through a descriptor-rooted
  `/proc/thread-self/fd/<fd>/<leaf>` path, with an identity verification before ordinary unmount;
  the intervening path lookup means this is not a race-free unmount proof against an excluded
  hostile mapped-same-UID actor. A production helper must provide root-owned exclusive mutation
  authority before reusing it. The link-activation, exact endpoint-route, exact permanent-neighbour,
  exact nftables-policy,
  fixed ICMP socket path, and fixed parent-namespace `ip_forward` writer are fixed and bounded; no
  general sysctl, general nftables, ownership-manifest, packet/probe, or general route/neighbour
  mutation API exists. The only route objects
  admitted in this slice are the exact kernel-created local,
  connected, high-broadcast, and IPv6 multicast routes coupled to the fixed address and activation
  transaction plus the two exact static `/32` endpoint routes described above. The only ordinary
  neighbour objects admitted are the four exact affine `NUD_PERMANENT` IPv4 records described
  above; proxy neighbours remain forbidden. The slice
  still has no general
  root-filesystem or supplementary-group isolation,
  `TOPOLOGY_READY`, `STOP`, `FINISHED`, configured dataplane-topology mutation, crash-cleanup evidence,
  acceptance report, or A01-A15 result. In particular, the deletion-only fixed-link teardown is
  not forced-crash cleanup or A14, A15, or acceptance evidence. `BOOTSTRAP_READY` remains
  readiness evidence; `GO` authorizes only this bounded private-root, two-pin, two-veth,
  four-address, counted forward-policy, conditional forwarding enable/restore, link-activation,
  endpoint-route, permanent-neighbour, fixed-ICMP, and policy-teardown transaction,
  and `MUTATION_ROLLBACK_COMPLETE` is an
  internal containment checkpoint rather than cleanup or acceptance evidence.
- [ ] Integration run performs real discovery, advertisement, selection, reservation, WireGuard, MPTCP, MPQUIC, TCP, UDP, and HTTP/3 operations.
- [ ] Machine-readable acceptance report is emitted.

### Required acceptance tests

- [ ] A01 discovery survives loss of either bootstrap peer.
- [ ] A02 TCP download proves at least two data-carrying MPTCP subflows.
- [ ] A03 constrained MPTCP paths aggregate bandwidth beyond one path.
- [ ] A04 removing a relay does not terminate an active MPTCP download.
- [ ] A05 UDP echo uses exactly one relay and no direct client-exit datapath.
- [ ] A06 HTTP/3 through MASQUE proves at least two data-carrying MPQUIC paths.
- [ ] A07 removing one MPQUIC relay avoids unnecessary inner-QUIC interruption.
- [ ] A08 allowed test domain succeeds.
- [ ] A09 domain, raw-IP, SNI, and forbidden-port policy denials succeed.
- [ ] A10 unverifiable ECH fails closed.
- [ ] A11 relay capture reveals no Internet destination in the routed outer layer.
- [ ] A12 exit capture sees relay peers rather than the client's public address.
- [ ] A13 client capture proves there is no direct client-exit dataplane route.
- [ ] A14 forced crash plus cleanup removes all temporary network state.
- [ ] A15 original host routes, DNS, firewall, links, sysctls, and VPN state remain unchanged.

## Performance and packaging

- [ ] Benchmarks cover one/four relays, TCP/MPTCP, QUIC/MPQUIC, RTT spread, loss, jitter, capacity, CPU, memory, context switches, WireGuard overhead, setup, discovery, and failover.
- [ ] Reports distinguish net user data from physical tunnel data.
- [ ] The Debian 13 bootstrap script previews packages, asks permission, and performs no direct
  route/DNS/firewall/VPN mutation; package-maintainer service side effects are not independently
  constrained or audited.
- [x] System-check script is read-only.
- [ ] Reproducible `.deb`, hardened systemd units, tmpfiles, users/groups, optional logrotate, uninstall, and cleanup instructions are provided.

## Documentation

- [ ] README accurately covers purpose/non-goals, architecture, install, demo, roles, warnings, limitations, and threat-model link.
- [ ] Architecture document contains discovery, reservation, WireGuard, MPTCP, UDP, MPQUIC, cleanup, and policy diagrams.
- [ ] Protocol document specifies every wire message, limits, canonical form, signatures, and versioning.
- [ ] Threat model covers every required adversary/attack and clearly states global-observer limitations.
- [ ] Discovery, routing, MPTCP, MPQUIC, whitelist, operations, testing, and privacy documents match implemented behaviour.

## Definition of done

- [ ] Every master-specification completion criterion is evidenced above; all checks and linters pass; packaging and the complete real-network acceptance suite pass on clean Debian 13.
