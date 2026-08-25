# VOLPAROSSA v1 protocol reference

This reference describes the currently implemented wire types and their fail-closed boundaries.
The peer control envelope is hard-incompatible version 3. Envelope versions 1, 2, zero, and every
future version are rejected without fallback. The historical v2 schema is retained only for tag
archaeology and refusal tests; it is not registered or negotiated.

The checked-in [control-v3 schema](../proto/volparossa/control/v3/control.proto) covers
`SignedEnvelope` and all eighteen signed `ControlPayload` messages. The separate checked-in
[discovery-v3 schema](../proto/volparossa/discovery/v3/discovery.proto) mirrors the hand-written
advertisement, exit-forwarding, and datapath-relay request-response wrappers. Descriptor and fuzz
gates verify tag/enum parity; the two forwarding-hop Rust marker types remain distinct even though
their canonical wire bytes are deliberately identical.

## Common encoding, framing, and active identifiers

Control messages and peer RPC wrappers use canonical Protocol Buffers. A value is decoded,
validated, and re-encoded; the bytes must match exactly. Alternate encodings, unknown fields,
wrong discriminators, and ambiguous response shapes are rejected. The signed control stream frame
is a 4-byte unsigned big-endian length followed by exactly one canonical envelope.

| Channel | Active version or protocol ID | Bound and authentication |
|---|---|---|
| Signed peer control | 3 | 256 KiB envelope; 192 KiB inner payload; Ed25519 |
| Direct relay/control-relay advertisement retrieval | `/volparossa/advertisement/3` | canonical protobuf; authenticated provider peer plus peer-bound signed advertisement |
| Client-to-control-relay exit forwarding | `/volparossa/exit-forward/3` | 512 KiB canonical protobuf; authenticated control relay |
| Control-relay-to-exit forwarding | `/volparossa/exit-forward-upstream/3` | 512 KiB canonical protobuf; authenticated exit and relay peers |
| Client-to-selected datapath relay | `/volparossa/datapath-relay/3` | 512 KiB canonical protobuf; authenticated selected relay |
| CLI to agent | 1 | 256 KiB; Unix socket ownership and peer credentials |
| Agent to helper | 3 | 128 KiB; root-owned Unix socket, peer credentials, typed allowlist |
| Agent to native MPQUIC | 4 | 1 MiB; protected local Unix socket and typed allowlist |

The retired direct reservation identifiers
`/volparossa/reservation/exit/2`, `/volparossa/reservation/relay/2`, and
`/volparossa/reservation/exit-confirmation/2` are refusal-test constants only. Normal exit
operations use exactly one selected control relay on both forwarding hops. A generic hop-local
`Rejected` or `Unavailable` status is never an end-to-end positive grant. A received canonical
`Unavailable` is definitive for that setup and is not a retry trigger; only a local transport
outcome with no response evidence may become `AmbiguousAfterDispatch` for a bounded exact-byte
retry.

## Signed control envelope

`SignedEnvelope` commits:

1. `protocol_version = 3`;
2. the 32-byte sender node ID and 32-byte Ed25519 public key;
3. creation and expiry timestamps;
4. a fresh 32-byte nonce;
5. the exact message discriminator;
6. canonical payload bytes and their SHA-256 digest;
7. a 64-byte Ed25519 signature.

The signature input uses `volparossa/control-envelope/v3\0`. Verification checks version before
signature use, sender/key binding, canonical encoding, payload hash, type, signature, lifetime,
payload-specific scope, and replay. The default envelope ceiling is 15 minutes with at most 60
seconds of future clock skew. Reservation phase messages impose the shorter bounds described below.
Replay caches retain `(sender_id, nonce)` until expiry and do not evict a live entry to admit a new
one.

## Identity and privacy bindings

Each route attempt uses a fresh Ed25519 session key. Its `client_session_id` is derived from that
key. No v3 hold, capability, permit, probe result, final grant, relay request, relay authorization,
relay reservation, confirmation, or receipt contains the client's permanent node ID or libp2p Peer
ID. Retired client-Peer-ID tags remain reserved and raw occurrences are non-canonical.

Exit-facing phase envelopes bind the exact selected exit node ID and authenticated exit Peer ID,
plus the exact forwarding control-relay node ID and Peer ID. Relay-path artifacts also bind the
selected relay node ID and Peer ID. A fresh non-zero CSPRNG `exit_boot_id` is created for every
exit process start and is never operator configuration or persistent state. Restarting an exit
invalidates every earlier capability, hold, permit, finalization, grant, and confirmation scope.

## Signed message types

The v3 discriminators are fixed:

| ID | Signed payload | Purpose |
|---:|---|---|
| 1 | `NodeAdvertisement` | short-lived, peer-bound discovery metadata |
| 2 | `ExitReservation` | finalized exit grant for an exact ordered relay set |
| 3 | `RelayAuthorization` | exit-signed authorization for one exact relay path |
| 4 | `RelayReservation` | relay-signed grant containing the nested exit authorization |
| 5 | `OpenTcp` | exact policy-bound TCP flow authorization |
| 6 | `UdpFlowAuthorization` | immutable policy-bound UDP destination tuple |
| 7 | `ExitCapacityHoldRequest` | request capacity before revealing any relay |
| 8 | `RelayReservationRequest` | submit one final exit authorization to its relay |
| 9 | `ExitReservationConfirmation` | return one verified relay grant to the exit |
| 10 | `ClientSessionCapability` | exit-signed bounded session proof of possession |
| 11 | `ExitCapacityHold` | exit-signed short capacity hold without relay selection |
| 12 | `RelayProbePermitRequest` | request one bounded exact-relay probe permit |
| 13 | `RelayProbePermit` | exit-signed exact probe scope |
| 14 | `RelayProbeResult` | relay-signed structured two-leg observations |
| 15 | `ExitReservationFinalizeRequest` | submit the exact ordered relay set and probe artifacts |
| 16 | `ExitConfirmationReceipt` | exit-signed positive acknowledgement of exact confirmation bytes |
| 17 | `PreselectionObservationReceipt` | actor-signed response to one exact unsigned preselection challenge |
| 18 | `ForwardedPreselectionAttestation` | control-signed public-prefix claim around one exact exit receipt |

`NodeAdvertisement` contains roles, transport/family flags, bounded capacity counters, coarse
network/operator hints, quality claims, policy version/hash, and lifetime. It contains no reusable
or route-specific WireGuard endpoint. Advertised capacity, control reachability, uptime, and
quality remain untrusted preselection metadata. They are not reservation capacity or datapath
evidence and cannot by themselves create a production route candidate.

### Dormant preselection-observation precursor

Tags 17 and 18 are protocol-only primitives for a future phase-A observation producer. A
`PreselectionObservationRequest` is unsigned, version 3, at most 4096 bytes, and live for at most
five seconds. A future caller MUST CSPRNG-generate a fresh unique 32-byte challenge for every
observation request, challenged subject (a direct relay or forwarded exit), and attempt, and MUST
never reuse it across requests, subjects, or attempts. This module checks only the challenge's
exact 32-byte, non-zero shape and has no producer, signer, uniqueness registry, handler, RPC, rate
limiter, or network dispatcher. Dormant A1a is its only product-code static consumer, and that
consumer has no production root, orchestrator, transport caller, or network path.

A direct relay signs one `PreselectionObservationReceipt`. For a forwarded exit, the exit signs
that same receipt and the exact prospective forwarding control named in the request signs a
`ForwardedPreselectionAttestation` around the exact nested receipt bytes. The control intentionally
echoes the exit-subject challenge while using its own envelope nonce and time window; there is no
second control challenge. The wrapper carries only a control-attested public IPv4 /24 or IPv6 /48
claim, never a host address, endpoint, or port. A future handler MUST derive that claim from the
exact authenticated upstream connection. A valid control signature does not prove that a malicious
control relay reported the origin truthfully.

A signed actor-receipt envelope is at most 4096 bytes. A forwarded wrapper is at most 8192 bytes
and its exact nested signed receipt is independently at most 4096 bytes. Each actor binding fixes
node ID, Peer ID, public key, advertisement sequence and expiry, advertisement payload hash, and
capability expiry; the request and both signed layers repeat the exact role, transport, address
family, and policy version/hash/expiry scope.

Every actor binding carries `advertisement_payload_hash`. A future producer MUST copy the exact
32-byte `SignedEnvelope.payload_hash` from the same freshly cryptographically verified canonical
`NodeAdvertisement`; A0 validates only its non-zero shape and exact transcript echo, not that
advertisement provenance. The dormant agent-side A1a owner copies this value only from the exact
freshly revalidated stored signed advertisement used to construct its hidden subject set. A
conforming direct Relay request/receipt binds
`capability_expires_at_ms` to exactly the minimum of actor-advertisement and policy expiry. A
forwarded control uses the same minimum, while the exit binding uses exactly the minimum of exit
advertisement expiry, policy expiry, and control capability expiry. A standalone Exit receipt
accepts only a ceiling no later than its own actor/policy minimum; the dedicated composite verifier
enforces the forwarded exact minimum. A1a separately retains any stricter local discovery
authority expiry, caps the JIT request by both values, and never presents that local ceiling as the
actor's canonical wire capability.

Requests and actor envelopes use their own validity clocks. The request must satisfy
`created_at_ms <= local_now_ms < expires_at_ms`; each signed envelope is independently checked by
`TimePolicy` and has at most a 60-second signed lifetime. No ordering between control and exit
timestamps is inferred across their clocks. A later producer must record local arrival wall time
and monotonic RTT itself. Its aggregate validity ceiling must be the minimum of the local-arrival
freshness ceiling, the future supervisor's unchanged absolute observation-attempt deadline, every
applicable signed receipt/attestation validity window, actor advertisement/capability expiries,
and the policy expiry. Remote `observed_at_ms` is not local reachability, RTT, or freshness
evidence.

Direct verification cryptographically verifies and replay-inserts the receipt before decoding and
checking the expected request. A later request liveness or exact-binding failure rolls back only
that newly inserted receipt entry.

Forwarded verification first checks the outer envelope hash, Ed25519 signature, and time. Its
payload validation then performs bounded, signature-free nested canonical/type/digest/binding
checks before the outer replay insertion. The verifier next checks the exact expected request,
then performs nested cryptographic verification and replay insertion. An inner verification
failure removes only the newly inserted outer entry. A precommitted inner entry is never removed,
and successful composite verification commits both entries. A later cross-binding invariant
failure always attempts inner cleanup before outer cleanup and reports an invariant error only
after both attempts.

The exact request digest is SHA-256 over ASCII
`volparossa/preselection-observation-request/v3`, one NUL byte, the unsigned 32-bit big-endian
canonical-request length, and the exact canonical unsigned request bytes. The exact receipt digest
uses ASCII `volparossa/preselection-observation-receipt/v3`, one NUL byte, the unsigned 32-bit
big-endian nested-envelope length, and the exact canonical signed receipt-envelope bytes.

Only `verify_direct_preselection_transcript` and
`verify_forwarded_preselection_transcript` return the deliberately opaque affine transcript
bundles. Generic `verify_control_message::<ForwardedPreselectionAttestation>` verifies only the
outer control envelope and structural nested binding; it does not verify or replay-commit the
nested exit signature. Likewise, a standalone verified Exit receipt is not a forwarded composite
transcript. The opaque values have no `Clone`, `Debug`, Serde, getter, or decomposition surface.
Neither is local origin, reachability, RTT, capacity, admission, reservation, route-session, or
dispatch authority. The wire messages contain no capacity value; future phase A must independently
supply its conservative local preselection ceiling. Dormant A1a accepts that value only as
caller-supplied local input; a future production phase-A owner must derive it independently.

The agent now has a separate dormant A1a consumer around this protocol boundary. Its
discovery-private `pub(super)` affine `PreselectionAttemptGate` validates one endpoint-free reduced
snapshot and a caller-supplied non-zero conservative local bandwidth ceiling before entropy. It
then uses `OsRng` internally to mint one non-zero 16-byte process-local batch ID and between two and nine
unique non-zero 32-byte challenges, one per request and challenged direct relay or forwarded exit;
the control wrapper shares the exit challenge. A test-only fallible deterministic minter exists;
no product API accepts an RNG or challenge. The attempt contains exactly one forwarded-exit
request plus one to eight distinct prospective direct-relay requests. The forwarded response
retains one exit receipt and one control wrapper, so two to nine requests retain three to ten
signed envelopes while only one request is pending at a time.

An admitted attempt lasts at most 30 seconds and prepares each JIT request for at most five
seconds. Each JIT-prepared challenge is tombstoned until 120 seconds after that preparation;
the same batch-ID tombstone is extended to that horizon at every JIT preparation. Fixed capacities
are 36 challenge tombstones, four batch tombstones, and 40 replay entries. Available capacity for
the whole request set is checked before entropy and then held by exclusive affine ownership; there
is no redraw, retry, live-entry eviction, reservation, or ledger claim. On pre-entropy validation
or capacity rejection, `PreselectionBeginFailure` retains the original gate without cooldown.
After admission, a terminal transition with valid non-decreasing wall and monotonic clocks returns
the gate only after a 30-second cooldown; an invalid, backward, or overflowing terminal time loses
it fail closed.

A1a immediately feeds raw bounded response bytes into the dedicated A0 verifier and exact
canonical-request consumer. Once A0 commits replay state, a later owner-side failure does not roll
the transcript back or permit reminting within that gate lineage. The final
`BoundPreselectionTranscriptBatch` retains only
the endpoint-free subject/scope binding, opaque bound transcript tokens, process-local dispatch
correlation, and attempt ceilings. It has no getter or decomposition surface and contains no local
socket, connection ID, send/arrival event, prefix-derived direct origin, RTT, reachability,
`FreshPeerEvidence`, route-session, reservation, or dispatch authority. There is still no
production owner, request-response handler, transport caller, or network producer; A1a therefore
does not alter production discovery behavior.

Discovery now composes a dormant A1c wire shell without changing A0 or adding a protobuf wrapper.
`/volparossa/preselection-observation/3` carries an exact canonical Relay or forwarded
Exit request (at most 4096 bytes) from Client to Relay and returns either the exact Relay signed
receipt (at most 4096 bytes) or exact control-signed forwarded Exit attestation (at most 8192
bytes). `/volparossa/preselection-observation-upstream/3` carries only the same forwarded Exit
request from Relay to Exit and returns only the exact Exit signed receipt (both at most 4096
bytes). Each libp2p substream is one EOF-delimited canonical protobuf value with no additional
length prefix. The protocols are separate behaviours and event/request-ID domains, use an exact
five-second transport timeout and 64 streams per behaviour, register no v1/v2 aliases, and perform
no retry.

The opaque hop wrappers admit bytes only after state-free canonical, version, hop type/role,
payload-local, and typed envelope-binding validation; codec writes repeat those checks. This is
not cryptographic verification, replay acceptance, signature/origin authority, or usable evidence.
Discovery has one dormant client-hop transport seam: it derives the peer and family from the exact
request, admits one active dispatch, takes a connection-generation witness immediately before send,
and binds only a typed matching response event under the fixed/request/attempt deadline minimum.
The bind stamps arrival time internally and rechecks the exact service instance, request ID, peer,
event-local `ConnectionId`, current unique connection generation and native prefix. The affine
result exposes none of those fields. Explicit cancellation consumes the originating token. Dropping
it, a non-response event, unavailable pre-correlation wall time, or a cross-service, wrong-ID or
wrong-peer event keeps the only slot occupied fail closed. Exact correlation consumes the slot
before later time or provenance checks.
There is no runtime/agent caller, upstream sender, responder,
signer, handler, forwarder, A0 verification/replay consumer, A1a exact-set join, or Fresh-evidence
conversion. A later owner must consume the unchanged response bytes and opaque proof together
before any observation can become usable.

Tags removed during the hard migration are permanently reserved: hold-request tags 5 and 10,
relay-request tag 2, exit-grant tag 5, relay-authorization tags 7 and 13, relay-reservation tags 7
and 15, confirmation tag 7, finalized-path tag 5, and advertisement tag 7. The corresponding old
names (`client_peer_id`, `relay_paths`, `overlay_prefixes`, and `wireguard`) are reserved in
the v3 schema.

## Reservation state machine

1. **Hold.** The client signs `ExitCapacityHoldRequest` with its fresh session key. It binds the
   selected exit, control relay, policy, transports, final path-count upper bound, independent
   prospective probe-permit limit, rates, and final reservation expiry, but contains no relay
   list. All three hold artifacts enforce
   `1 <= maximum_paths <= probe_permit_limit <= 8`. A missing pre-change v3 field decodes to zero
   and is rejected. The exit verifies all scope, reserves capacity once, and only commits after it
   has signed both `ClientSessionCapability` and `ExitCapacityHold`.
2. **Probe permit.** For each prospective relay, the session signs a short
   `RelayProbePermitRequest`. The exit checks the exact capability, hold, boot incarnation,
   control relay, relay identity, transport, family, path uniqueness, and hold state before signing
   `RelayProbePermit`. It issues at most `probe_permit_limit` disposable permits, and every
   `path_id` is in `1..=probe_permit_limit`. Permit issuance does not consume another capacity slot
   or rate allocation.
3. **Probe result.** `RelayProbeResult` binds the exact signed permit and requires both
   client-to-relay and relay-to-exit `ProbeLegEvidence`: controlled-window start/end, measured
   timestamp, directional capacity, RTT, and non-zero transmitted/received byte counts. Typed
   absence is invalid.
4. **Finalize.** The client submits a strictly ordered selected subset containing
   `1..=maximum_paths` `FinalizedRelayPath` values. Relay node IDs, Relay Peer IDs, path IDs, and
   client WireGuard public keys are unique. Selected path IDs need not be contiguous (for example
   2, 5, and 8), but remain bounded by `probe_permit_limit`. The exit verifies all signatures and
   scope, then external probe evidence, then endpoint leases and signatures. It commits only after
   every path and every signature succeeds. The final `ExitReservation.maximum_paths` is the exact
   selected count; downstream TCP, UDP, bundle, and confirmation cardinality checks remain exact.
5. **Relay grant.** Each selected relay verifies the client-session request, capability, final exit
   grant, and nested exit authorization. It leases distinct client-facing and exit-facing
   WireGuard endpoints, signs `RelayReservation`, and commits capacity only after signing.
6. **Confirmation.** The client verifies the outer relay signature, nested exit signature, all
   route/session/boot/peer/capacity/policy fields, and the relay-to-client endpoint before signing
   `ExitReservationConfirmation`. The exit accepts only the exact finalized path and returns an
   `ExitConfirmationReceipt`. A path is not usable at the exit before this signed positive
   receipt exists.

Hold, permit, probe, finalize, relay-request, confirmation, and receipt windows are at most 30
seconds. Capabilities, final exit grants, relay authorizations, and relay reservations are at most 15
minutes. Exact successful request bytes are cached with the authenticated forwarding peer binding.
An exact retry before expiry returns the same signed bytes. Successful finalization clears every
unused/disposable permit and its cached permit response, while retaining the one exact finalize
response needed for byte-identical retry. A non-identical retry for the same committed path fails.
Every finalize error before endpoint preparation leaves the hold and issued permits unchanged and
rolls cryptographic, replay, and reservation state back atomically. Helper-backed endpoint-lease
retirement is not yet production-wired: provider paths remain `Unavailable` until a linearly owned
`DestroyContext` supervisor guarantees cleanup on every failure, release, expiry, and shutdown.

An ambiguous forwarding outcome permits only an exact-byte retry of the same operation and
identifier. A detail-free rejection is definitive failure; it never substitutes for a signed
positive response.

## Hash and receipt binding

`finalized_bundle_hash` is SHA-256 over
`volparossa/finalized-reservation-bundle/v3\0`, followed by the canonical signed
`ExitReservation` and each canonical signed `RelayAuthorization` in strictly increasing path
order. Every member is prefixed by its unsigned 32-bit big-endian byte length.

`confirmation_envelope_hash` is SHA-256 over
`volparossa/exit-confirmation-envelope/v3\0`, one unsigned 32-bit big-endian length, and the
exact canonical client-signed confirmation envelope. The receipt additionally binds reservation,
context, session, capability, hold, finalize ID, path, control-relay node/Peer ID, exit node/Peer
ID, exit boot incarnation, creation, expiry, and nonce. A receipt for byte-different confirmation
data does not acknowledge the client's frame.

## Production probe and dataplane boundary

The permit/result messages are protocol primitives, not a production evidence producer. They do
not yet carry helper-proven client and exit WireGuard endpoints, nor a relay-ready,
exit-activate/start, exit-participating countersigned receipt handshake. Consequently a real
client-to-relay-to-exit controlled probe cannot yet be produced.

Production `finalize_reservation_with` therefore uses a verifier whose only result is
`ProbeEvidenceUnavailable`. This happens after complete signature and scope verification but
before exit endpoint allocation, signing, or commit. The short hold remains valid for a later exact
attempt with real evidence and capacity is not reserved twice. Tests use an explicit verifier that
matches exact expected permit/result bytes after normal cryptographic and scope verification;
there is no accept-all production or test provider.

The `/volparossa/datapath-relay/3` ExecuteProbe wrapper is framing only and does not change this
boundary. Likewise, signed route binding is not helper/kernel tunnel evidence and does not mark the
capacity ledger tunnel-established. Real helper-owned endpoint preparation, readiness,
activation, handshake/counter proof, route supervision, and cleanup remain required before a
production datapath can be claimed.

Unprivileged endpoint leases contain only helper-returned public endpoints and opaque non-secret
handles. `VerifiedRelayProbe` projects immutable typed leg metrics, transport/family, and the
exact already-verified signed result bytes. `VerifiedRelayGrant` projects only the already
verified relay-to-client WireGuard endpoint. Neither projection re-decodes untrusted raw fields,
and nested-signature substitution fails without producing a projected value.


## CLI-to-agent local protocol

`ControlRequest` contains version 1, a 16-byte random request ID, and exactly one operation:
`Status`, `Connect`, `Disconnect`, `Peers`, `Paths`, `Sessions`, `PolicyStatus`, `SetRole`, `Roles`,
or `Logs(maximum_records)` (1–1000). Relay and exit configuration persists independently and
client remains the safe default. Privacy-v3 protocol directions are immutable after process start;
a real runtime role change fails closed as restart-required rather than silently changing live
request-response exposure.

`ControlResponse` echoes version/request ID, provides `Ok`, `InvalidRequest`, `InvalidState`,
`Policy`, `Helper`, or `Unavailable`, a diagnostic code no longer than 96 bytes, and a matching typed
payload. Payloads expose bounded peer/path/session summaries, aggregate user and tunnel bytes,
policy version/hash/expiry/signature count, role state, or privacy-safe in-memory log records. Lists
are capped at 4096 entries. They contain no destination hostname/IP or private key.

## Agent-to-helper protocol

`HelperRequest` accepts exactly version 3, a non-zero 16-byte request ID, and one of fourteen active
allowlisted operations at tags 20–23, 25–29, and 31–35. Versions 1, 2, zero, and future versions are
rejected before dispatch.

| Operation | Typed effect |
|---|---|
| `PrepareLeaseBatch` | prepare the exact role/cardinality set for paths 1–8 and return only opaque non-secret handles plus helper-owned public evidence |
| `ActivateLeaseBatch` | bind every prepared lease to one exact public peer key/endpoint; derive local overlay and privileged state |
| `CommitLeaseBatch` | succeed only after a recent correlated WireGuard handshake and strict RX/TX counter growth for every lease |
| `DestroyContext` | idempotently remove one context and all contained state |
| `AddMptcpEndpoint` | request one derived committed-path MPTCP endpoint; currently returns `Unavailable` in production |
| `RemoveMptcpEndpoint` | remove one exact owned MPTCP endpoint; currently returns `Unavailable` in production |
| `AcquireTransportSocket` | tag 27: bind one committed context/path/role to connected MPTCP, listening MPTCP, or unconnected QUIC UDP metadata and transfer one separately correlated CLOEXEC descriptor; production currently returns `Unavailable` before network work |
| `ReconcileExpiredPrepare` | tag 28: after setup expiry, re-evaluate one exact same-runtime ambiguous Prepare lineage and succeed only after its exact generation is proven absent |
| `CleanupOwned` | remove only resources matching a random 32-byte process-start ownership token |
| `PrepareClientIngress` | tag 31: request a pre-route client runtime with exactly four closed socket kinds crossed with IPv4/IPv6; production returns `Unavailable` before state or network work |
| `AcquireIngressSocket` | tag 32: bind one exact prepared identity to a unique receipt and exactly one separately correlated CLOEXEC descriptor; production returns `Unavailable` |
| `ActivateClientIngress` | tag 33: require the complete eight-identity, cross-unique receipt set before activation; production returns `Unavailable` |
| `DestroyClientIngress` | tag 34: idempotently destroy one exact client-runtime authority; production returns `Unavailable` |
| `BindHelperRuntime` | tag 35: return the non-secret per-process runtime ID and optionally register one exact, non-network Prepare intent in that runtime |

Historical operation tags 10 (`CreateContext`), 11 (`ConfigureWireguard`), 12
(`InstallRelayFence`), 14 (`SetLinkState`), and 24 (`InstallInterception`) are permanently reserved
and are not among the fourteen active operations. Their protobuf variants and message types are
absent from the active schema and must not be reused. Any raw occurrence is rejected as unknown and
non-canonical before dispatch.

The active v3 agent API has no private-key field and cannot select an interface name, local overlay
address, allowed prefix, listen port, nftables expression, sysctl, command, filesystem path, or free-form
diagnostic.
Responses echo the request identity, return a stable result, a bounded diagnostic code, the BLAKE3
digest of the canonical request, and an operation-specific success value. Failure responses cannot
contain a success value.

For route preparation, the agent constructs the complete canonical `PrepareLeaseBatch` request,
request ID, digest, and frame before contacting the helper. It then sends
`BindHelperRuntime(Some(PrepareIntent))` and, only after a correlated `HelperRuntime` success, the
prebuilt Prepare on the same `SO_PEERCRED`-validated Unix stream. One absolute five-second client
deadline covers connect, credential validation, both writes, and both responses; it is never reset
between frames. Intent registration is runtime-global helper state, not a server-enforced binding to
that connection. Same-stream use is the HelperClient invariant that prevents a pathname/socket swap
between registration and dispatch.

A Bind failure is definitive for privileged/network mutation because it can leave only an inert
in-memory intent. Immediately before the first Prepare-frame write future is polled, the client arms
the exact reconciliation authority. Every error from that point onward is ambiguous and carries the
helper runtime ID, route-context ID, original Prepare request ID and digest, and both expiries. This
state survives cancellation of the inner deadline future. Cancellation safety for the complete call
comes from the owned route-ticket supervisor, which continues settling the call after its waiter is
cancelled. The crate-private HelperClient Prepare method has no other production call site; if future
code polls it standalone, that future does not provide the supervisor's cancellation guarantee.

After the half-open setup window ends (`now >= setup_expires_at_unix`), reconciliation first sends
`BindHelperRuntime(None)` and verifies the retained runtime ID before sending tag 28 on the same
stream and under one new absolute five-second deadline. A runtime change sends no tag 28 and keeps
the route retirement quarantined. Tag 28 accepts and echoes the complete authority exactly, targets
only its server-owned record and generation, and never treats a missing record as proof. It may turn
an expired, never-dispatched intent into `Absent`, retry cleanup for an exact Pending generation, or
destroy an exact still-Prepared/Quarantined owned generation. Activated or Committed state cannot be
removed through this operation.

Route-context setup and hard-expiry windows are half-open: admission and commit require
`now < expiry`; equality is expired, and cleanup/reconciliation becomes eligible at
`now >= expiry`. An operation that already linearized before a boundary may still return its exact
cached response; that is not fresh admission and makes no new backend call. An exact tag-28 retry is
the intentional exception to the normal response-cache rule: it re-evaluates the retained lineage
and current target state rather than replaying a generic cached success. An `Absent` proof remains in
a runtime-lifetime in-memory ledger capped at 1024 records because there is no authenticated receipt
ACK; capacity exhaustion rejects new intents instead of evicting proof. Tag 28 itself retries exact
Pending/Owned cleanup. Tag 29 `CleanupOwned` is an independent process-wide cleanup operation, not
part of per-route reconciliation or an ACK, and does not release an `Absent` tombstone.

`TransportSocketReady` and `IngressSocketReady` start a second, bounded ancillary phase. The server
sends exactly one FD plus a 32-byte domain-separated BLAKE3 binding in one `SCM_RIGHTS` message; the
binding commits version, request ID, operation digest, canonical response and descriptor kind. The
agent first validates protobuf correlation, then accepts exactly one `MSG_CMSG_CLOEXEC` FD.
Missing, extra, mismatched or truncated handoffs fail closed and every rejected installed descriptor
is RAII-closed. Ingress additionally binds runtime, ingress/socket/receipt handles, kind, family and
wildcard local tuple. All ingress/socket/receipt handles are non-zero, fixed-width and
cross-category unique. The agent locally permits only one acquisition attempt per prepared identity;
activation failure returns the prepared cleanup authority and all eight descriptors, and destroy
borrows authority so ambiguous failure remains retryable.

The independent internal worker protocol v2 reserves exact tag 17 for the corresponding
route-context/path/role/kind/tuple request. Its tested private `SOCK_SEQPACKET` building block uses
canonical records, a separately bound zero-or-one-FD completion record, fixed deadlines and
close-on-reject semantics. On success the consuming worker send API drops its source descriptor and
then sends a distinct domain-separated, credentialed and descriptor-free release record. A received
FD remains in a private affine raw owner until exact peer PID/UID/GID, credential and descriptor
counts, ancillary shape, request/response binding and the shared deadline all validate. Consuming
adoption then uses the audited Linux-UAPI
`F_DUPFD_CLOEXEC` operation with minimum 3, immediately owns the duplicate, reads back
`FD_CLOEXEC`, and closes the original when the duplication call returns. The parent returns the
adopted owner only after the exact release record arrives within the same absolute deadline. Any
adoption or release-barrier failure closes every local owner. A consuming parent validator also
re-queries the closed socket shape; the fixed `SIOCGSKNS` UAPI safely returns a typed namespace FD,
but comparison against the retained worker namespace pin is not connected yet. Closed worker-side
factories create and revalidate connected MPTCP, listening MPTCP and unconnected UDP sockets,
including genuine `MPTCP_INFO` negotiation evidence for a connected stream. These components are
not wired into a production worker process, so their socketpair/fake-kernel tests do not prove a
namespace socket or datapath.

The production lease backend currently fails closed: `PrepareLeaseBatch` returns
`Unavailable/PREPARE_FAILED` and creates no context because the read-only rtnetlink
`DirectAssigned` collector and the v3 parent/worker kernel transaction are not connected yet. It
does not return a placeholder endpoint or claim a tunnel. `AcquireTransportSocket` likewise returns
`Unavailable/TRANSPORT_SOCKET_UNAVAILABLE` before context lookup or any network action until the
worker lifecycle owns committed lease state and invokes the factory. The exact proof contract,
namespace transport blocker and remaining live-kernel work are recorded in
[Privileged helper protocol v3](HELPER_V3.md).

Tags 35 and 28 therefore provide only dormant same-process ambiguity containment. No production
route-manager caller reaches this transaction. A boot-scoped, secret-free canonical/CAS ownership
store exists as a temp-directory-tested dormant primitive, and production startup refuses any of
its exact main/lock/next objects before touching the token or socket. No production writer,
recovery backend, restart reaper, or cross-runtime receipt uses that store. A helper restart changes
the runtime ID, so retained agent authority remains quarantined rather than being misreported as
absent; an absent journal is not cleanup evidence.

All four client-ingress operations return `Unavailable/CLIENT_INGRESS_UNAVAILABLE` before clock,
cache, state, backend or network access. The Linux UAPI has pure/socketpair-tested socket
revalidation plus fail-closed TCP/UDP original-destination parsing, but no production namespace,
listener, TPROXY/DNS/kill-switch nftables transaction, privileged per-identity transfer cache,
rollback, or live datapath is connected.

## Agent-to-native MPQUIC API

`NativeRequest` contains canonical API version 4, a 16-byte nonce, and one operation. Versions 1,
2, 3, and every future version are rejected before dispatch. One control-socket contact carries
exactly one request, with one total deadline and a required client write-half close before dispatch:

- `StartSession`: 16-byte context, 32-byte exit SPKI SHA-256 pin, minimum paths, non-zero MASQUE
  context ID, explicit multipath/single-path mode, bounded per-route credential, exact TLS server
  name, and an expiry no more than fifteen minutes ahead;
- `StartExitSession`: the exact context, per-route credential, expiry, minimum paths, MASQUE context
  ID, and explicit transport mode for one explicitly enabled exit route;
- `AddPath`: context/path ID, exact IPv6 local/remote overlay addresses, local/remote UDP ports, and
  a 32-byte relay-reservation hash. The address pair must use `fd76:6f6c:7061::/48`, embed the path
  ID in segment six, share one `/112`, and use fixed client host `1` and exit host `4`;
- `RemovePath`, `GetStatus`, and `StopSession`: exact context and, where relevant, path;
- `SendDatagram`: context, MASQUE context ID, and one already-authorized bounded IPv4/IPv6
  datagram;
- `ReceiveDatagram`: exact context and MASQUE context ID for one bounded reverse poll.

Before the framed protobuf, every contact sends one fixed 32-byte binding record through
`recvmsg`. `AddPath` binds exactly one `SCM_RIGHTS` UDP descriptor to the canonical request with
SHA-256 over the NUL-terminated `VOLPAROSSA-MPQUIC-ADD-PATH-FD-V4` domain, the four-byte
big-endian canonical payload length, and the payload. All other operations require an all-zero
binding and zero descriptors. Missing, extra, truncated, late, wrongly bound, or otherwise
unexpected ancillary data is rejected and every received descriptor is closed. Rust validates the
socket before transfer; native repeats its type, UDP protocol, bound local tuple, unconnected state,
nonblocking/close-on-exec flags, overlay shape, exact exit peer, and session-consistent nonzero
network-namespace cookie before mqvpn adopts it. Native never opens or binds a path socket and does
not use an agent-supplied interface. The hash and same-session cookie prove correlation and
namespace consistency, not privileged-helper origin; production path adoption remains blocked
until helper provenance is independently authenticated.

`NativeResponse` echoes version/nonce and returns `Ok`, `Version`, `InvalidRequest`, `NotFound`,
`Unauthorised`, `Transport`, `InsufficientPaths`, `NoDatagram`, or `QueueOverflow`, plus a bounded
code, an optional exactly correlated reverse datagram, and no more than eight path records. Each
record reports path ID, smoothed RTT, loss, delivered unique bytes, congestion window, bytes in
flight, delivery rate, and a flag that becomes true only after validation and real payload carriage.
These fields are necessary to prevent a native process from falsely reporting mere path
configuration as multipath operation.

## Policy manifest encoding

Policy manifests retain schema version 1 and accept a minimum VOLPAROSSA policy protocol version
up to 2. Their maximum signed size is 512 KiB (448 KiB body). Limits include 32
maintainers/signatures, 4096 destination rules, 64 permissions per
destination, and 16384 total permissions. A canonical body commits to monotonic version, validity,
maintainer set/environment, exact and wildcard domains, exact IP rules, and exact TCP/UDP ports.
Production defaults require three unique valid signatures from five trusted production maintainers;
development maintainers are rejected in production mode. See [WHITELIST.md](WHITELIST.md).

## Versioning rules

Unknown enum values, versions, required fields, or oneof operations are rejected. New optional
protobuf fields may be added only when old implementations can safely ignore them without changing
authorization; because canonical re-encoding is enforced, deployments must explicitly coordinate
such changes. Any change to a signature domain, security meaning, path invariant, or required field
uses a new protocol identifier/version. There is no silent downgrade to plain TCP, direct exit, or
single-path QUIC.
