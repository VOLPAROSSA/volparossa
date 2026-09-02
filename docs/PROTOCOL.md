# VOLPAROSSA v1 protocol reference

This reference describes the currently implemented wire types and their fail-closed boundaries.
The peer control envelope is hard-incompatible version 4. Envelope versions 1, 2, 3, zero, and
every future version are rejected without fallback. Historical schemas are retained only for tag
archaeology and refusal tests; they are not registered or negotiated.

The checked-in [control-v4 schema](../proto/volparossa/control/v4/control.proto) covers
`SignedEnvelope` and all twenty-five signed `ControlPayload` messages. The separate checked-in
[discovery-v4 schema](../proto/volparossa/discovery/v4/discovery.proto) mirrors the hand-written
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
| Signed peer control | 4 | 256 KiB envelope; 192 KiB inner payload; Ed25519 |
| Direct relay/control-relay advertisement retrieval | `/volparossa/advertisement/4` | canonical protobuf; authenticated provider peer plus peer-bound signed advertisement |
| Client-to-control-relay exit forwarding | `/volparossa/exit-forward/4` | 512 KiB canonical protobuf; authenticated control relay |
| Control-relay-to-exit forwarding | `/volparossa/exit-forward-upstream/4` | 512 KiB canonical protobuf; authenticated exit and relay peers |
| Client-to-selected datapath relay | `/volparossa/datapath-relay/4` | 512 KiB canonical protobuf; authenticated selected relay |
| CLI to agent | 1 | 256 KiB; Unix socket ownership and peer credentials |
| Agent to helper | 3 | 128 KiB; root-owned Unix socket, peer credentials, typed allowlist |
| Agent to native MPQUIC | 6 | 1 MiB; same-UID Unix socket, typed allowlist, process-instance and request correlation; separate production role identities remain required |

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

1. `protocol_version = 4`;
2. the 32-byte sender node ID and 32-byte Ed25519 public key;
3. creation and expiry timestamps;
4. a fresh 32-byte nonce;
5. the exact message discriminator;
6. canonical payload bytes and their SHA-256 digest;
7. a 64-byte Ed25519 signature.

The signature input uses `volparossa/control-envelope/v4\0`. Verification checks version before
signature use, sender/key binding, canonical encoding, payload hash, type, signature, lifetime,
payload-specific scope, and replay. The default envelope ceiling is 15 minutes with at most 60
seconds of future clock skew. Reservation phase messages impose the shorter bounds described below.
Replay caches retain `(sender_id, nonce)` until expiry and do not evict a live entry to admit a new
one.

## Identity and privacy bindings

Each route attempt uses a fresh Ed25519 session key. Its `client_session_id` is derived from that
key. No v4 hold, capability, permit, probe result, final grant, relay request, relay authorization,
relay reservation, confirmation, or receipt contains the client's permanent node ID or libp2p Peer
ID. Retired client-Peer-ID tags remain reserved and raw occurrences are non-canonical.

Exit-facing phase envelopes bind the exact selected exit node ID and authenticated exit Peer ID,
plus the exact forwarding control-relay node ID and Peer ID. Relay-path artifacts also bind the
selected relay node ID and Peer ID. A fresh non-zero CSPRNG `exit_boot_id` is created for every
exit process start and is never operator configuration or persistent state. Restarting an exit
invalidates every earlier capability, hold, permit, finalization, grant, and confirmation scope.

## Signed message types

The v4 discriminators are fixed:

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
| 19 | `NativeProbePermitRequest` | endpoint-free request for one exact native candidate path |
| 20 | `NativeProbePermit` | exit-signed endpoint-free permit for that exact path |
| 21 | `NativeProbeExitReady` | Exit-to-data-Relay readiness containing only the Relay-Exit and Exit endpoints |
| 22 | `NativeProbeRelayReady` | data-Relay-to-client readiness containing only the Relay-Client endpoint |
| 23 | `NativeProbeStart` | client-to-data-Relay start containing only the Client endpoint |
| 24 | `NativeProbeExitResult` | endpoint-free Exit result bound to the exact challenge and local lease |
| 25 | `NativeProbeRelayResult` | endpoint-free data-Relay result wrapping the exact Exit result and local proofs |

`NodeAdvertisement` contains roles, transport/family flags, bounded capacity counters, coarse
network/operator hints, quality claims, policy version/hash, and lifetime. It contains no reusable
or route-specific WireGuard endpoint. Advertised capacity, control reachability, uptime, and
quality remain untrusted preselection metadata. They are not reservation capacity or datapath
evidence and cannot by themselves create a production route candidate.

### Preselection-observation control messages

Tags 17 and 18 are partial phase-A control-transcript primitives. A
`PreselectionObservationRequest` is unsigned, version 4, at most 4096 bytes, and live for at most
five seconds. The production discovery attempt owner CSPRNG-generates a fresh unique 32-byte
challenge for every observation request, challenged subject (a direct relay or forwarded exit), and attempt, and MUST
never reuse it across requests, subjects, or attempts. The protocol module checks only the
challenge's exact 32-byte, non-zero shape. Actor-owned A1a is the only product-code consumer that
verifies a complete client-side transcript; the same owner joins it to the exact service-bound
transport proof. Discovery separately owns the role-gated
Relay/Exit responders and Relay forwarding wrapper described below; this message type itself
provides no client request producer or challenge-uniqueness authority.

A direct relay signs one `PreselectionObservationReceipt`. For a forwarded exit, the exit signs
that same receipt and the exact prospective forwarding control named in the request signs a
`ForwardedPreselectionAttestation` around the exact nested receipt bytes. The control intentionally
echoes the exit-subject challenge while using its own envelope nonce and time window; there is no
second control challenge. The wrapper carries only a control-attested public IPv4 /24 or IPv6 /48
claim, never a host address, endpoint, or port. The production Relay handler derives that claim
from the exact authenticated upstream connection. A valid control signature does not prove that a malicious
control relay reported the origin truthfully.

A signed actor-receipt envelope is at most 4096 bytes. A forwarded wrapper is at most 8192 bytes
and its exact nested signed receipt is independently at most 4096 bytes. Each actor binding fixes
node ID, Peer ID, public key, advertisement sequence and expiry, advertisement payload hash, and
capability expiry; the request and both signed layers repeat the exact role, transport, address
family, and policy version/hash/expiry scope.

Every actor binding carries `advertisement_payload_hash`. The client-side discovery owner copies
the exact 32-byte `SignedEnvelope.payload_hash` from the same freshly cryptographically verified canonical
`NodeAdvertisement`; A0 validates only its non-zero shape and exact transcript echo, not that
advertisement provenance. The actor-owned A1a attempt copies this value only from the exact
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
timestamps is inferred across their clocks. The service-bound A1c transport proof records local
arrival wall time and monotonic RTT, and the actor-owned join combines it only with its exact
request transcript. The aggregate validity ceiling is the minimum of the local-arrival
freshness ceiling, the supervisor's unchanged absolute observation-attempt deadline, every
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
`volparossa/preselection-observation-request/v4`, one NUL byte, the unsigned 32-bit big-endian
canonical-request length, and the exact canonical unsigned request bytes. The exact receipt digest
uses ASCII `volparossa/preselection-observation-receipt/v4`, one NUL byte, the unsigned 32-bit
big-endian nested-envelope length, and the exact canonical signed receipt-envelope bytes.

Only `verify_direct_preselection_transcript` and
`verify_forwarded_preselection_transcript` return the deliberately opaque affine transcript
bundles. Generic `verify_control_message::<ForwardedPreselectionAttestation>` verifies only the
outer control envelope and structural nested binding; it does not verify or replay-commit the
nested exit signature. Likewise, a standalone verified Exit receipt is not a forwarded composite
transcript. The opaque values have no `Clone`, `Debug`, Serde, getter, or decomposition surface.
Neither is local origin, reachability, RTT, capacity, admission, reservation, route-session, or
dispatch authority. The wire messages contain no capacity value; actor-owned A1a independently
accepts a conservative local preselection ceiling as typed caller input. A downstream route
orchestrator must derive that ceiling independently; no such production caller exists yet.

Before A1a, a separate discovery-private affine sampler can now narrow the exact actor-built
candidate snapshot to one forwarded Exit, its exact control Relay, and one to eight other Relay
prospects. It rechecks the complete advertisement/capability/policy/identity and forwarding shape,
filters by requested role, transport, address family, advertised capacity and free slots, then uses
an internal fallible CSPRNG with weighted 70/20/10 high, diverse-middle and exploration bands. Exit
selection is randomized across all eligible forwarded pairs; it is never an implicit first sorted
Exit. The result keeps the Exit forwarded and the control at direct index zero, so the sampler
cannot create a normal client-to-Exit hop. Sampling failure returns the exact original snapshot
affinely.

The sampler applies strict operator-ID, ASN and requested-family advertised-prefix-hint diversity
across the Exit, control and Relay slate. Those signed canonical public `/24` or `/48` hints are not
authenticated network origins and do not satisfy A1c. The later exact-set transport join may mint
only direct connection-derived or control-attested prefixes into private Fresh evidence. The
existing FreshEvidence/selection hard filter must re-enforce actual origin diversity before route
planning. The production discovery actor invokes this native-dataplane-agnostic sampler before its
affine request dispatch; the sampler chooses no endpoint and grants no dispatch authority itself.

The production discovery actor owns the A1a consumer around this protocol boundary. Its
discovery-private `pub(super)` affine `PreselectionAttemptGate` validates one endpoint-free reduced
snapshot and a caller-supplied non-zero conservative local bandwidth ceiling before entropy. It
then uses `OsRng` internally to mint one non-zero 16-byte process-local batch ID and between two
and nine unique non-zero 32-byte challenges, one per request and challenged direct relay or forwarded exit;
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
`FreshPeerEvidence`, route-session, reservation, or dispatch authority. The client-side attempt
owner is production code. The local `Connect` route gate now invokes its crate-private handle from
an explicit validated client route profile; this control step alone still grants no route.

The completed A1a owner advances through one actor-owned affine A1c join. It accepts exactly one
`BoundClientPreselectionTransport` in canonical request order for each retained transcript and
purpose-consumes both opaque proof types only after rechecking the exact count, unique request
hash, actor/role/forwarded-control shape, transport, native family, wall-clock attempt window and
independent monotonic attempt window. Any mismatch consumes the unusable proof set and returns only
the cooldown owner. A successful join retains the original snapshot and produces one bounded
endpoint-free proof record per request; it adds no constructor, clone, serialization or reusable
dispatch authority.

The route-selection child is the sole production mint for those joined facts and constructs its
existing private `FreshEvidenceBatch` directly. Direct Relay evidence uses the matching
client-Relay prefix and round trip. Forwarded evidence uses the client's control-Relay prefix plus
the exact control-signed upstream Exit prefix; its RTT is the complete
client-control-Exit-control-client transaction, not a direct client-Exit measurement. The mint
records one reachability sample, no measured p25, a configured non-authoritative capacity ceiling,
zero proximity and egress-quality scores, and `network_address_usable = false`. Its
`locally_blocked = false` means only that no local blocklist hit was supplied, not that policy was
proved. The existing hard filter therefore rejects the batch until a separate native-path sampler
adds dataplane evidence. The actor calls this join/mint and returns only opaque
`PreparedPreselectionEvidence`. A crate-private native-preselection child now consumes that value
from the production `Connect` gate while the five-second receipts are still live. It mints an
independent bounded owner and dispatches the first endpoint-free native Permit request only through
the selected control Relay; neither the Prepared handoff nor this Permit stage grants admission,
reservation, route, usability or datapath authority.

### Native-preselection contract and server-side Permit provider

Tags 19 through 25 define an endpoint-separated native-probe transcript and affine verification
states. The private client owner consumes the exact Prepared handoff before its signed five-second
receipt window closes, discards the control-plane reachability observations and mints a distinct
attempt bounded to at most five minutes by policy and actor expiry. This does not extend or reinterpret
the original receipt lifetime. One candidate set contains the control Relay plus one to eight other
data Relays, for two to nine preselection candidates total; later route selection still admits at
most eight paths.

The Permit request and Permit are endpoint-free and bind the exact attempt, candidate set, path
ordinal, data Relay, Exit, transport, native family, policy and expiry. Exit readiness is visible
only to the selected data Relay and contains the Relay-Exit and Exit endpoints. Client-visible Relay
readiness contains only the Relay-Client endpoint. Start exposes the Client endpoint only to that
data Relay. Both result messages are endpoint-free. Consequently the client/control side never
receives Relay-Exit or Exit-underlay endpoint bytes, and the Exit never receives the Client's helper
endpoint or prepared-lease commitment.

Every endpoint binding and lease proof uses `route_context_id == scope.probe_id`; the same route
context spans the four helper-local leases. Relay-Client and Relay-Exit must have one Relay helper
runtime, while Client, Relay and Exit runtimes are distinct. The data-Relay affine transition sees
all four bindings and rejects every cross-role collision in helper runtime where nodes must differ,
WireGuard public key, exact `(underlay IP, listen port)` socket tuple, or 32-byte prepared-lease
commitment. It alone consumes verified Exit readiness plus both local prepared bindings to sign
Relay readiness, then consumes the verified Start, verified Exit result, both Relay lease proofs and
forwarding proof exactly once to sign the Relay result. Phase order is established by exact hashes
and affine states, never by ordering wall clocks owned by different nodes; each signed message still
enforces its own bounded lifetime, expiry ceiling and the normal clock-skew policy. Replay failures
and cross-binding substitutions roll back only the newly admitted entries and fail closed.

The client-side native attempt now has one production Permit dispatcher; ExitReady and ExitResult
remain callerless contract/test foundations. The Exit composes one production server-side Permit
handler on the existing forwarded control protocol. Relay and Exit runtimes install their exact
signed local service advertisement and bounded provider indexes from explicit configuration and
current capacity. This opens the handler's local-advertisement gate, but the advertisement remains
an untrusted claim and not usable datapath evidence. A separate discovery transport integration
proves connection-bound response handoff; no test yet completes the whole handler exchange end to
end. The handler accepts
only the exact signed native Permit request received from an authenticated control Relay, rechecks
the current full Relay capability and exact locally served Exit advertisement, and consumes a
purpose-specific token for that exact libp2p `ConnectionId` when handing the response back.
Multiple or Circuit-Relay control connections are valid; this is authenticated control-channel
provenance, not native-prefix or datapath evidence. The Exit API stores the response before handoff
in a bounded no-live-eviction ledger together with its affine Permit owner. An exact retry by the
same authenticated control actor returns the byte-identical signed Permit without signing or
consuming replay again; request or actor substitution fails closed.

Only Permit has that production-composed caller, and it cannot currently issue in a normal runtime.
The module-private, non-Clone Exit readiness/result owner
still uses raw test-seam data-Relay identities. Its typed projection from the `Copy`
`ExitEndpointLease` proves neither helper-resource custody nor same-connection helper-runtime
provenance or cleanup authority, and the private helper/datapath observation has no constructor.
There is no production Ready/Result caller, helper lifecycle/cleanup owner, challenge delivery,
live WireGuard probe, measured readiness/capacity, terminal
helper-evidence producer, usability promotion or route admission. Permit, ExitReady and ExitResult
each cap their own lifetime at the lower of the parent expiry and local production time plus 30
seconds. Private phase owners retain the process-unique Exit boot incarnation and reject
cross-restart consumption. In particular, Permit production cannot set
`network_address_usable = true`; the existing hard filter continues to reject its output.

Discovery composes A1c wire protocols without changing A0 or adding a protobuf wrapper.
`/volparossa/preselection-observation/4` carries an exact canonical Relay or forwarded
Exit request (at most 4096 bytes) from Client to Relay and returns either the exact Relay signed
receipt (at most 4096 bytes) or exact control-signed forwarded Exit attestation (at most 8192
bytes). `/volparossa/preselection-observation-upstream/4` carries only the same forwarded Exit
request from Relay to Exit and returns only the exact Exit signed receipt (both at most 4096
bytes). Each libp2p substream is one EOF-delimited canonical protobuf value with no additional
length prefix. The protocols are separate behaviours and event/request-ID domains, use an exact
five-second transport timeout and 64 streams per behaviour, register no v1/v2/v3 aliases, and perform
no retry.

The opaque hop wrappers admit bytes only after state-free canonical, version, hop type/role,
payload-local, and typed envelope-binding validation; codec writes repeat those checks. This is
not cryptographic verification, replay acceptance, signature/origin authority, or usable evidence.
Discovery has independent client-hop and relay-to-exit transport seams. Each derives its
target and family from the exact request, admits one active same-hop dispatch, takes a
connection-generation witness immediately before send, and binds only a typed matching response
arrival sealed by the originating service's private swarm pump under the fixed/request/caller
deadline minimum. The upstream seam additionally requires the
forwarding control identity to be local and never targets it instead of the exit. The private
swarm pump stamps monotonic and wall arrival time while sealing the opaque arrival; binding then
rechecks that both the dispatch and arrival belong to the exact service instance, and that the
private request ID, peer, event-local `ConnectionId`, current unique connection generation and
native prefix match. Context-bound entrypoints
can carry a non-cloned attempt/snapshot or downstream-channel owner through only that exact bind or
cancellation. A client transaction offered to a foreign service is returned unchanged for its
originating service. Once the originating service recognizes the exact active client transaction,
every sealed response is terminal: the slot is released before service-instance, peer, request-ID,
time or provenance validation, and failure recovers the exact unchanged caller context without the
consumed dispatch. Dropping an active token or an unavailable arrival clock still leaves the slot
occupied. The upstream hop also retains its slot for a foreign service, peer or request ID; only
exact upstream correlation consumes it before later time or provenance checks.

Dispatches, transactions, arrivals and the unconsumed bound tokens expose no ID-equality oracle,
constructor, generic ID/hash/time/prefix getter or decomposition. Their purpose-specific terminal
consumers destroy the authority-bearing token and expose only an endpoint-free normalized public
IPv4 `/24` or IPv6 `/48`, sealed local wall-observation time and monotonic round trip for the client
transport; only a normalized prefix for the Relay-signed upstream wrapper; only the signed validity
ceiling for a direct transcript; or the earlier joint signed ceiling and control-signed normalized
prefix for a forwarded transcript. These projections contain no request, actor identity, signature,
nonce, full endpoint, connection or reusable dispatch/evidence authority. The production
discovery owner consumes them through the exact join, but native usability remains false and no
route-readiness claim follows. A still-current inbound client-hop request is withheld unless it
targets the local relay/control and its authenticated remote differs from both local peer and actor;
requester-anonymous A0 has no client identity to bind. Upstream instead requires the authenticated
relay to equal `forwarded_control` and the actor to equal the local exit. These predicates and the
raw response channels remain behind a private pump. The ordinary public event pump closes inbound
requests on both hops, drops stale/unowned responses, and replaces responses for the exact active
dispatch with service-sealed opaque arrivals;
the role-gated responder pump does the same while owning direct Relay and upstream Exit requests
internally. No public pump yields a raw
preselection request or response message, and no public API accepts a raw response event or
response channel or sends either response type. Real independent client-hop and upstream
request-response behaviours deliberately reproduce the same behaviour-local outbound ID and prove
that their responses, even when sealed by a sibling service, cannot bind the originating dispatch.

Discovery also exposes one production-compiled role-gated Relay/Exit response poll transaction. It
takes each typed inbound request directly from the same service's swarm, so its behaviour-local request
ID, response channel and `ConnectionId` cannot be transplanted across service instances. That exact
`ConnectionId`, authenticated peer and requested native family rebind to a unique current private
connection witness; it cryptographically re-verifies the exact currently served local Relay or
Exit advertisement; requires nonzero ASN, matching local identity,
advertised transport/family support and exact active policy; tombstones the exact request hash for
120 seconds under fixed 1024-global/16-per-peer limits; and signs the bound receipt with a fresh
fallibly generated CSPRNG nonce. It retains the affine connection proof through the exact libp2p
response-channel handoff. For the upstream hop, the `forwarded_control` public key and Peer ID must
also derive the exact authenticated Relay and the challenged actor must be the exact local Exit.
Replay, stale authority, ambiguity, capacity or signing failures emit no response. Real two-swarm
tests prove that each originating direct and upstream channel carries only its exact role-signed
receipt. Companion transport regressions prove that neither public pump exposes an inbound channel
and that a sibling service cannot answer a privately captured originating channel. Each receipt
includes no prefix, endpoint, RTT, capacity, reachability, admission,
reservation, route-session or evidence authority. The production discovery actor now polls this
private seam only with an immutable Relay or Exit role, an exact active threshold-verified policy snapshot
and the same actor-owned permanent identity. A policy command cancels the outstanding poll before
the actor applies the replacement. Successful response production additionally requires an exact
currently served role advertisement. Production intentionally advertises no usable Relay/Exit
capability before dataplane readiness is proved, so this lifecycle caller remains fail closed and
does not make the responder, a transport, or a route ready.

For a forwarded Exit request, the same private poll is now the sole affine control-Relay owner. It
retains the original canonical request, authenticated client peer, event-local `ConnectionId`,
behaviour-local inbound request ID and response channel while dispatching the unchanged request over
the separately authenticated upstream behaviour. Only the exact upstream peer/request ID and
still-current unique connection generation may consume that owner. The returned Exit receipt is
cryptographically verified and admitted into a fixed 1024-entry no-live-eviction replay cache,
then rebound to the exact request hash, challenge, Exit actor, scope and Exit signing identity. A
cross-binding failure rolls back only its newly inserted replay entry. The opaque upstream
connection proof has one purpose-specific consuming projection into an endpoint-free public IPv4
`/24` or IPv6 `/48`; there is no generic prefix/address getter.

The Relay performs a read-only unique Exit-provenance preflight before shared replay admission.
The subsequent tombstone is tentative until the synchronous no-failure send boundary: every
pre-send dispatch failure consumes its exact non-cloneable token and rolls back only that new
record, while a successful dispatch commits it.

Before signing, the owner re-verifies the current Relay advertisement, permanent Identity and exact
active policy. It caps the wrapper by the request, nested receipt, both actors' advertisement and
capability expiries, and policy expiry, and uses a fresh fallible CSPRNG nonce. The canonical
`ForwardedPreselectionAttestation` is sent only through the retained original client channel.
Timeout, downstream cancellation, exact upstream failure, policy/Identity drift, replay,
provenance, signature or channel failure drops the owner and clears its one upstream slot without a
response. A hermetic three-swarm MemoryTransport test verifies both signatures and replay
protection, checks live connected-peer state contains the Relay but not the Exit, and exercises
wrong-peer, wrong-request, wrong-connection, upstream-failure, downstream-failure, policy-drift,
deadline and responder-disable cleanup. Its `/24` derives from explicitly injected public endpoint
lineage; it is not an external-network measurement. This is still control-plane transcript
production only: it makes no Fresh, readiness, capacity, reservation, route or datapath claim.

A production discovery owner now drives the snapshot, native-agnostic sampler, exact affine
request/bind lineage, A1a/A1c join and opaque Prepared handoff. The private client child can consume
that handoff only through a test seam. A separate module-private, non-Clone Exit owner can retain
one Permit in a bounded idempotency ledger. Its sole production-composed caller binds the request
and response channel to the exact authenticated control-Relay connection and current control/Exit
advertisement and policy identities, but the current product has no local Exit-advertisement source
that can satisfy the gate. ExitReady and ExitResult remain test-only; their
data-Relay arguments still have no production connection-owned source. The typed
`ExitEndpointLease` projection is not helper-resource custody or cleanup authority, and the result
requires a private helper/datapath observation type with no constructor. Production client Permit
dispatch, real same-helper custody/lifecycle and challenge providers, live dataplane evidence,
measured readiness/capacity, usability promotion, route admission and reservation are still absent.
The fixed alpha score remains
**11/100 (11%)**.

Tags removed during the hard migration are permanently reserved: hold-request tags 5 and 10,
relay-request tag 2, exit-grant tag 5, relay-authorization tags 7 and 13, relay-reservation tags 7
and 15, confirmation tag 7, finalized-path tag 5, and advertisement tag 7. The corresponding old
names (`client_peer_id`, `relay_paths`, `overlay_prefixes`, and `wireguard`) are reserved in
the v4 schema.

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

### Signed native-route identity and affine secret ownership

Protocol v4 adds one native-route scope to finalization without exposing the route bearer to a
relay. The client CSPRNG-generates exactly 32 bearer bytes, encodes them as one canonical 43-byte
unpadded base64url value, and signs only
`SHA-256("VOLPAROSSA-NATIVE-ROUTE-AUTH-COMMITMENT-V4\0" || exact_bearer_bytes)` in the finalize
request. That request also binds the non-zero MASQUE context and the exact 32-byte client-native
process instance. The raw bearer never enters a peer-control protobuf, signed envelope, response
cache, or `Debug` output.

The exit signs a nested `NativeRouteIdentity` into the final `ExitReservation`. It exactly echoes
the commitment, MASQUE context, and client-native instance and additionally binds the certificate
SHA-256, SPKI SHA-256, canonical TLS server name, and exit-native process instance. The certificate
digest is SHA-256 over the leaf X.509 certificate's complete DER encoding; the SPKI digest is
SHA-256 over that same leaf's DER-encoded `SubjectPublicKeyInfo`. Neither digest hashes PEM text,
base64 spelling, surrounding whitespace, or any additional chain certificate. The client
retains the zeroizing bearer affinely across a corrected exact retry, accepts only that exact signed
identity echo, and releases a non-cloneable client authorization exactly once and only after every
path in the finalized bundle has an exact confirmation receipt.

The exit keeps certificate and private-key PEM in a separate non-cloneable zeroizing owner; cached
finalization replies clone only public signed bytes. Exact full-path confirmation gates a separate
one-shot exit authorization. Scope mismatch does not consume the owner, while success, release,
expiry, and purge remove it. This layer validates bounds, canonical public fields, PEM framing, and
exact ownership scope. It does **not** yet prove certificate/private-key cryptographic consistency,
activate a listener, start an mqvpn backend, or hand the verified signed authorization affinely to
native. The separate API-v6 runtime converts the caller-supplied wall expiry once to a
`CLOCK_BOOTTIME` deadline, but no production caller performs that preflight or carries the
preverified authorization affinely into the dormant route. The production identity provider and
separate role service identities remain unavailable, so both sides still fail closed.

## Hash and receipt binding

`finalized_bundle_hash` is SHA-256 over
`volparossa/finalized-reservation-bundle/v4\0`, followed by the canonical signed
`ExitReservation` and each canonical signed `RelayAuthorization` in strictly increasing path
order. Every member is prefixed by its unsigned 32-bit big-endian byte length.

`confirmation_envelope_hash` is SHA-256 over
`volparossa/exit-confirmation-envelope/v4\0`, one unsigned 32-bit big-endian length, and the
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

The `/volparossa/datapath-relay/4` `ExecuteProbe` wrapper is framing only and does not change this
boundary. The same v4 wrapper now also gives native preselection two exact operations:
`NativeProbeReady` carries only a client-signed endpoint-free request plus its Exit-signed Permit and
accepts only `NativeProbeRelayReady`; `NativeProbeStart` carries only the client-signed Start and
accepts only `NativeProbeRelayResult`. Both target the selected data Relay identity and retain
separate 16-byte correlation IDs. These wrappers are still not helper/kernel tunnel evidence and do
not mark the capacity ledger tunnel-established. The strict helper additionally refuses Client
activation until a standard nested Exit/Relay-signed `RelayReservation` binds the helper-prepared
Client key, selected Relay endpoint, exact route context and hard expiry. Neither native wrapper
currently obtains that post-Prepare authority. Real helper-owned endpoint preparation, readiness,
activation, handshake/counter proof, route supervision, and cleanup remain required before a
production datapath can be claimed.

The helper's retained singleton evidence proves two sequential lifecycles, not one simultaneous
route. Its Client cycle carries bounded ICMPv6 over a client-to-relay WireGuard leg; its later Exit
cycle starts a fresh worker and namespace and carries bounded ICMPv6 over a separate relay-to-exit
WireGuard leg. Each fixture is removed exactly before its `CommitLeaseBatch`, so Commit proves the
retained recent role-specific handshake and strict-counter result, not a currently live peer.
Retained exact-main run 33301595311 additionally proves one simultaneous ordered `RelayClient` +
`RelayExit` endpoint-pair lifecycle, but predates cross-leg forwarding. Non-retained branch smoke
[run 33306523739](https://github.com/VOLPAROSSA/volparossa/actions/runs/33306523739) at
`8d9cc533edfc1e9add273c03a9ce3fa164c3353d` proves bounded ICMPv6 through both live WireGuard legs,
both nftables forwarding counters, all four peer counter views, Commit retry, teardown and the
unchanged-host-state fence. Exact-main
[run 33309109220](https://github.com/VOLPAROSSA/volparossa/actions/runs/33309109220) at
`1f3cee798787ed4673a3ba28d88931947800ca22` reproduced that proof and retained artifact
[9731470248](https://github.com/VOLPAROSSA/volparossa/actions/runs/33309109220/artifacts/9731470248).
It remains a self-contained single-path helper fixture: there is no
production Client/Relay/Exit route manager, `RelayProbeResult`, trusted selection/policy authority,
transport or ingress. These scoped helper facts therefore do not change the production two-leg
`ProbeEvidenceUnavailable` boundary.

Unprivileged endpoint leases contain only helper-returned public endpoints and opaque non-secret
handles. `VerifiedRelayProbe` projects immutable typed leg metrics, transport/family, and the
exact already-verified signed result bytes. `VerifiedRelayGrant` projects only the already
verified relay-to-client WireGuard endpoint. Neither projection re-decodes untrusted raw fields,
and nested-signature substitution fails without producing a projected value.


## CLI-to-agent local protocol

`ControlRequest` contains version 1, a 16-byte random request ID, and exactly one operation:
`Status`, `Connect`, `Disconnect`, `Peers`, `Paths`, `Sessions`, `PolicyStatus`, `SetRole`, `Roles`,
or `Logs(maximum_records)` (1–1000). Relay and exit configuration persists independently and
client remains the safe default. Privacy-v4 protocol directions are immutable after process start;
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
| `ActivateLeaseBatch` | bind every prepared lease to one exact public peer key/endpoint and one bounded signed relay reservation; the production backend accepts one to eight ordered Client/Exit path leases or the exact ordered Relay pair, verifies all applicable signed authority and, for Relay, activates the exact helper-internal two-direction forwarding fence |
| `CommitLeaseBatch` | succeed only after a recent correlated WireGuard handshake and strict RX/TX counter growth for every lease; Relay additionally requires growth of both exact forwarding counters and commits only when every proof passes |
| `DestroyContext` | idempotently remove one context and all contained state; Relay first restores policy-drop and proves the active fence absent |
| `AddMptcpEndpoint` | add one kernel endpoint derived inside the worker namespace from an exact live committed Client MPTCP lease; arbitrary addresses/interfaces and Exit/Relay leases are rejected |
| `RemoveMptcpEndpoint` | remove one exact worker-owned Client MPTCP endpoint; missing, stale, wrong-generation or non-Client ownership fails closed |
| `AcquireTransportSocket` | tag 27: bind one exact path in a committed context to connected MPTCP, listening MPTCP, or unconnected QUIC UDP metadata and transfer one separately correlated CLOEXEC descriptor; production accepts unconnected QUIC UDP for an exact committed Client/Exit lease, genuine connected MPTCP only for Client, and a genuine MPTCP listener only for Exit, while Relay remains unavailable |
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
The tag-8 `signed_relay_reservation` bytes in each activation lease are preserved exactly by the
canonical wire and committed by the request digest. For Relay, tag 9 on `RelayClient` preserves the
exact canonical client-session-signed `RelayReservationRequest`; `RelayExit` must carry no tag-9
bytes and both leases must carry byte-identical tag-8 bytes. Generic decoding retains
empty-compatible fields, but the production functional Client/Exit-singleton-or-Relay-pair backend
requires the applicable bytes. Relay activation canonically verifies five signed envelopes as one
rollback-capable replay transaction: the outer client `RelayReservationRequest`, its embedded
`ClientSessionCapability` and `ExitReservation`, the relay `RelayReservation`, and its nested
`RelayAuthorization`. It checks every signer, TTL and full capability/exit/authorization scope,
including the capability, reservation, route, client session/key, exit/control-relay identities,
policy, transport, rate, path/permit and creation/expiry bindings. The relay-signed tag-30 SHA-256
commitment must equal the exact tag-9 signed-request bytes. Client/Exit singleton activation still
verifies the applicable relay and nested authorization envelopes. For Client, the helper-generated
key must equal the signed client key and the
privileged peer derives exclusively from `relay_client_wireguard_endpoint`. For Exit, the
helper-prepared key, `DirectAssigned` public underlay IP and kernel-selected listen port must equal
the nested exit-signed `exit_wireguard_endpoint`; `same_relay_grant` also requires its outer
relay-signed copy to be exactly equal, and the privileged peer derives exclusively from the
relay-signed `relay_exit_wireguard_endpoint`. For Relay, the prepared relay-client and relay-exit
local tuples must equal their two relay-signed endpoints; the client-facing peer comes only from the
client-signed request and the exit-facing peer only from the nested exit-signed endpoint. The client
key is also matched to its relay-signed copy, all local/peer keys and socket tuples are distinct,
and the request/grant session, route, path, expiry and rate scope is exact. The untrusted activation
tuples are correlation copies and must equal those role-specific signed values. Each item and
aggregate remain capped by the 128 KiB helper frame ceiling. The five-record transaction
cryptographically binds the complete Relay request and response authority, but the self-contained
authority universe is not an independent
discovery/connection trust anchor and does not yet carry a separately trusted helper-side
selected-operator or policy authority; replay memory also does not survive helper restart.
Responses echo the request identity, return a stable result, a bounded diagnostic code, the BLAKE3
digest of the canonical request, and an operation-specific success value. Failure responses cannot
contain a success value.

For route preparation, the agent constructs the complete canonical `PrepareLeaseBatch` request,
request ID, digest, and frame before contacting the helper. It then sends
`BindHelperRuntime(Some(PrepareIntent))` and, only after a correlated `HelperRuntime` success, the
prebuilt Prepare on the same `SO_PEERCRED`-validated Unix stream. The intent contains the exact
context role and a required, strictly ordered, role-complete `(path_id, WireGuard role)` recovery
plan in addition to the request identity, digest and expiries. The Prepare lease set follows the
same canonical order, so a permutation cannot acquire a second encoding or be silently normalised
at the future journal boundary. One absolute five-second client
deadline covers connect, credential validation, both writes, and both responses; it is never reset
between frames. Intent registration is runtime-global helper state, not a server-enforced binding to
that connection. Same-stream use is the HelperClient invariant that prevents a pathname/socket swap
between registration and dispatch.

A successful Prepare is retained by the agent as one affine runtime-bound lifecycle owner rather
than returned as freely cloneable phase authority. On every new Unix stream used for Activate,
Commit or exact retirement Destroy, the agent first sends `BindHelperRuntime(None)`, requires the
same retained 32-byte runtime ID, and only then sends the canonical phase request on that stream.
Runtime change sends no phase request. The bounded route supervisor retains this owner while a
phase call settles and transfers it to its existing retirement/retry worker on failure, timeout or
cancellation. This does not add Ready/Result, restart adoption or a usable route datapath.

This pre-alpha protocol-v3 refinement is deployed lockstep with the packaged agent and helper. It
does not provide a mixed-version rolling-upgrade path: an old agent omits required tag 6, a new agent
sends a field an old helper cannot canonically accept, and formerly accepted permuted lease sets are
now invalid. Every mixed combination therefore fails closed before Prepare dispatch.

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

Route-context setup and hard-expiry windows are half-open on both the original Unix/realtime and
frozen process-local BOOTTIME deadlines: equality on either is expired for helper admission,
post-backend commit and reaping. The agent cannot observe the helper-local BOOTTIME deadline and
initiates tag-28 reconciliation only at `now >= setup_expires_at_unix`. An operation that already
linearized before a boundary may still return its exact
cached response; that is not fresh admission and makes no new backend call. An exact tag-28 retry is
the intentional exception to the normal response-cache rule: it re-evaluates the retained lineage
and current target state rather than replaying a generic cached success. An `Absent` proof remains in
a runtime-lifetime in-memory ledger capped at 1024 records because there is no authenticated receipt
ACK; capacity exhaustion rejects new intents instead of evicting proof. Tag 28 itself retries exact
Pending/Owned cleanup. Tag 29 `CleanupOwned` is an independent process-wide cleanup operation, not
part of per-route reconciliation or an ACK, and does not release an `Absent` tombstone.

The external wire continues to carry Unix expiries only. At the first accepted Bind/Prepare intent,
the helper freezes matching process-local `CLOCK_BOOTTIME` setup and hard deadlines and carries them
affinely through engine, backend and worker ownership. Prepare, Activate, Commit, descriptor
acquisition and their post-backend commits require both their Unix and frozen BOOTTIME windows to
remain open; the reaper retires on either boundary. Retries never refresh either deadline. The live
Relay fence combines its realtime cutoff with a kernel-jiffies timeout derived conservatively from
the frozen hard deadline. This fails closed across ordinary suspend or ordinary realtime rollback.
Only an already-compromised host root able to both suspend the host and roll `CLOCK_REALTIME` back
sufficiently can leave a short post-resume race until serialized cleanup; containment against such
host-root compromise is not claimed. The KVM proof did not exercise suspend/resume or realtime
mutation.

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

The independent internal worker protocol v4 reserves exact tag 17 for the corresponding
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
re-queries the closed socket shape. The coordinator additionally duplicates the
already attested worker namespace pin affinely before recording this request's tombstone or
in-flight transition, retains it across concurrent retirement without probing the worker process
under the registry lock, and before registry COMMIT compares the typed namespace FD returned by
fixed `SIOCGSKNS` against that pin by exact nsfs device/inode identity. Expired cache and tombstone
housekeeping may precede pinning but carries no socket or namespace authority. Post-PLAN mismatch,
validation failure or expiry closes the descriptor and quarantines the generation. Closed worker-side
factories create and revalidate connected MPTCP, listening MPTCP and unconnected UDP sockets,
including genuine `MPTCP_INFO` negotiation evidence for a connected stream. The production
functional-alpha path uses the coordinator for one Client/Exit singleton or one exact Relay
endpoint pair's Initialise, Prepare, signed-authority-bound Activate, correlated Probe/Commit and
Destroy operations, and for one committed Client/Exit singleton's helper-internal unconnected QUIC
UDP socket. MPTCP and Relay socket acquisition, a production route-manager caller and every usable
datapath remain disconnected.

Internal worker protocol v4 makes the canonical, role-complete `PrepareLeases` plan mandatory in
`InitialiseContext`. Its route context and exact ordered resources are validated before
`NamespaceKernel` access and before the parent may create or move a birth link. The child retains
that staged set while its namespace remains pinned. If no lease lifecycle was adopted,
`DestroyContext` deletes those exact resources in reverse canonical order, proves every resource
absent inside the child namespace, and only then retires the restricted Relay baseline. Missing or
substituted staged state is invalid and partial absence proof remains `CleanupIncomplete`; a
context-level `NotFound` counts as cleanup evidence only before every parent birth flag remained
false. If the correlated `Initialise` response misses the parent's deadline after durable dispatch,
the child preserves the cleanup executor instead of retrying a possibly queued response. The
cleanup-only parent retains the exact canonical `Initialise` request; its later Destroy, under a new
caller deadline, may consume at most one exact credentialed, digest-bound, descriptor-free late
response before the Destroy response. Duplicate, foreign or cross-context responses fail closed.
A lost Destroy response remains ambiguous and is never promoted to cleanup proof.

The production functional-alpha backend connects the bounded rtnetlink `DirectAssigned` collector
and the v4 parent/worker kernel transaction for exactly one live context containing either one
matching-role Client/Exit WireGuard lease or the ordered `RelayClient` + `RelayExit` pair. A
successful `PrepareLeaseBatch` reports only the child's correlated
kernel-proven public key/listen port plus the selected direct-underlay address; it is not evidence of an activated
tunnel. A server-owned expiry driver schedules cancellation-safe exact cleanup once per second
without waiting for another agent request, serializes it behind earlier operations, retries
quarantined lineages, and is joined before backend shutdown. Client `ActivateLeaseBatch` installs
and reads back only the verified relay-client peer. Exit first binds its complete helper-prepared
local tuple to the dual-signed exit endpoint and then installs and reads back only the verified
relay-exit peer. Relay binds both prepared local tuples to the relay grant, installs only the
client-request peer and nested exit-signed peer on their respective leases, and rolls back the
complete pair on any partial failure. Every lease installs its helper-derived `/128` route and
retains that readback as the activation counter baseline. Relay activation also replaces the
policy-drop baseline with two exact ifindex- and `/128`-bound cross-leg accept rules guarded by one
singleton timeout set and realtime cutoff, followed by terminal drop. `CommitLeaseBatch` sends one
correlated internal Probe/Commit, requires every handshake to be no older than activation, strict
RX/TX growth for every lease and, for Relay, growth of both exact forwarding-rule counters. It
independently revalidates the complete proof, transitions only the exact singleton or pair to
Committed and caches the successful receipt for an identical retry. Destroy restores policy-drop
before removing the interfaces and proves the fence absent. For an exact committed Client/Exit
singleton, each successfully committed valid `AcquireTransportSocket` request creates one bound
unconnected QUIC UDP socket in that worker namespace, consumes the credentialed source-release
record, and independently validates socket shape and exact namespace. After backend descriptor
validation and engine COMMIT—but before outer response/FD delivery can be known—the helper binds the
request ID/digest in a bounded, descriptorless same-helper-runtime context-generation ledger rather
than the evictable response cache. Identical replay returns `TRANSPORT_SOCKET_ALREADY_ACQUIRED` before a
backend call even after generic cache expiry/eviction or ambiguous outer delivery; digest
substitution conflicts.
This is same-request-ID/digest replay refusal, not a per-context/path/role one-shot receipt; a fresh
request ID can reach the backend again. Confirmed Destroy purges the generation's ledger, while
ledger saturation can reject only new Acquire and cannot block Destroy. The worker registry
separately reserves its final tombstone slot for terminal
Destroy before admitting nonterminal operations. MPTCP, Relay
transport handoff and every production route-manager, transport or ingress caller remain absent;
this is still an isolated helper-internal single-path seam. The exact proof contract and remaining
live-kernel work are recorded in [Privileged helper protocol v3](HELPER_V3.md).

The disposable production-IPC producer exercises that implemented subset sequentially. Its first
cycle runs Client Bind/Prepare/Activate, including an identical cached Activate retry, then pauses at
a fixed READY barrier so the root hook can observe the exact child identity, separate namespace,
relay-client peer and derived `/128` route. In the transient production unit's `PrivateNetwork`, a
temporary relay-side peer on UDP port 10000 carries bounded ICMPv6 over the client-to-relay leg and
proves recent handshake plus strict RX/TX growth before exact removal, Commit with byte-identical
retry and Destroy. Exact-main run 33294974441 at
`77b60aed3c39ba0c80d3e2dac2b9817fd6d7be2f` retained that Client-only proof.

The second cycle starts an Exit singleton in a different child PID and network namespace.
It verifies the dual-signed local exit tuple and relay-signed relay-exit peer at a separate READY
barrier. A distinct `vpre0` peer with a second deterministic key and UDP port 10001 carries bounded
ICMPv6 over a real, separate relay-to-exit WireGuard leg and proves recent handshake plus strict
bidirectional growth before exact alias/ifindex/WireGuard-kind-bound cleanup, Exit Commit with
byte-identical retry and Destroy. This proves sequential capacity reuse, not a simultaneous two-leg
route, Relay context or forwarding. Successful cleanup leaves the private namespace with exactly
loopback and no default route before retirement. The self-contained fixture identities prove no
trusted selection/policy authority, transport descriptor, ingress, usable VPN/datapath or crash
recovery. Exact-main [run
33296892632](https://github.com/VOLPAROSSA/volparossa/actions/runs/33296892632) at
`1ca51fe0d2a2be855adb182e85c229d1d12bc017` retained this Exit proof as artifact
[9727739271](https://github.com/VOLPAROSSA/volparossa/actions/runs/33296892632/artifacts/9727739271).
Retained exact-main run 33301595311 at
`0095b113e450a0ab29da853fafa53b2b130f05fc` separately proves the simultaneous Relay endpoint pair
before forwarding was implemented. Non-retained branch smoke [run
33306523739](https://github.com/VOLPAROSSA/volparossa/actions/runs/33306523739) at
`8d9cc533edfc1e9add273c03a9ce3fa164c3353d` proves the current exact cross-leg Relay fence, bounded
traffic, correlated WireGuard and nftables counter growth, Commit retry, teardown and unchanged host
state, but that non-main run publishes no artifact. Exact-main run 33309109220 at
`1f3cee798787ed4673a3ba28d88931947800ca22` reproduced the proof and retained the 39,915-byte artifact
`helper-boundary-evidence-1f3cee798787ed4673a3ba28d88931947800ca22` (artifact 9731470248, expiry
`2026-11-28T11:30:49Z`). Its streamed report is overall `PASS` from the exact clean source SHA on
Debian 13 amd64 (`x86_64`) with systemd 257; all 16 checks pass and the before/after host-state
SHA-256 is identically
`2209ca5e63388fe23b8bf54c072cd2be5aa289e7e68293841150bce93ff59698`. Its explicit scope remains
`helper_boundary_only=true`, `datapath=false`, `restart_recovery=false`,
`acceptance_a01_a15=false`, `cleanup_owned=false`, and `installed_package=false`; it is not live
product-route or A01--A15 evidence. The fixed alpha score remains **11/100 (11%)**.

The current exact-head report contract has 18 checks and is not proved by that historical 16-check
artifact. It requires an initially empty production FD store, exact active Client/Exit/Relay custody
counts `[2, 2, 2]` joined to each cycle's pidfd and network-namespace identities including normalized
status flags, and settled counts `[0, 0, 0]`. The journal must finish as exactly three stable
`Absent(RecoveredMayOwn)` tombstones with no recovery or reconciliation evidence: Client path 1
`[Client]`, Relay path 1 ordered `[RelayClient, RelayExit]`, and Exit path 1 `[Exit]`. Two canonical
reads must agree byte-for-byte and `.next` must remain absent. Exact-main
[run 33318629099](https://github.com/VOLPAROSSA/volparossa/actions/runs/33318629099) at
`63e405119ca1266499fef145fbeff7348cef5562` proved all 18 checks on privileged Debian 13 KVM and
retained
[artifact 9734273695](https://github.com/VOLPAROSSA/volparossa/actions/runs/33318629099/artifacts/9734273695).
Its scope is only `helper_boundary_only=true`; acceptance A01--A15, datapath, cleanup ownership,
installed-package and restart-recovery evidence remain explicitly false.

Tags 35 and 28 still provide only same-process ambiguity containment to the agent. The
functional-alpha request path reconstructs the original canonical Prepare intent from tag 35's
immutable lineage plus the correlated batch, commits it before worker reservation, and carries its
affine owner through systemd custody, durable `MayOwnPrepare`, dispatch, and clean same-runtime
settlement. No production route-manager caller reaches this transaction. Production starts one boot-scoped,
secret-free canonical/CAS ownership actor before publishing its cleanup token or socket, and joins
it after expiry-driver and engine cleanup. Startup may durably settle never-dispatched `Intent` and
one bounded restart state: a full set of already durable `CleanupConfirmed` targets. Each
exact-present pair is removed once in canonical name order and must produce a stable complete
predecessor-minus-pair successor; already-absent members are skipped. Journal revalidation plus a
fresh final manager barrier and two stable exact-empty snapshots precede one-shot full-set evidence
for `CleanupConfirmed -> Absent`. Restart removal errors erase retry authority and stop that
process. The deliberately refusing cleanup executor leaves every inherited `MayOwnCustody` or
`MayOwnPrepare` byte-identical and blocks
the internal socket-publication boundary. No inherited-custody recovery backend, restart reaper, or
cross-runtime receipt exists yet. A helper restart changes the runtime ID, so retained agent
authority remains quarantined rather than being misreported as absent; an absent journal is not
cleanup evidence.

An ordinary failure before descriptor-store publication is retained as an unpublished Handoff
terminal under a fresh serial, exact context and optional durable ownership selector. A later exact
functional Destroy may retrieve only that terminal. Definitive no-worker outcomes retire their
exact Intent directly; worker-bearing outcomes first require exact generation reap and complete
registry purge. Deadline or actor failure restores the same selector and affine proof for a fresh
attempt, while selector mismatch takes nothing and genuinely ambiguous admission remains retained.
`PublicationStart`, publication/post-attestation, `SupervisorDropped`, and `DispatchOpen` terminals
are outside this settlement path and remain fail-closed.

All four client-ingress operations return `Unavailable/CLIENT_INGRESS_UNAVAILABLE` before clock,
cache, state, backend or network access. The Linux UAPI has pure/socketpair-tested socket
revalidation plus fail-closed TCP/UDP original-destination parsing, but no production namespace,
listener, TPROXY/DNS/kill-switch nftables transaction, privileged per-identity transfer cache,
rollback, or live datapath is connected.

## Agent-to-native MPQUIC API

`NativeRequest` contains canonical API version 6, a nonzero 16-byte nonce, a target native-process
instance, and one operation. Versions 1 through 5 and every future version are rejected before
dispatch. One control-socket contact carries exactly one request, with one total deadline and a
required client write-half close before dispatch. `Preflight` is the sole operation with an empty
target: it names the expected client or exit role and returns the native process's fresh, nonzero
32-byte per-start instance. Every later request targets that exact instance and fails with
`StaleInstance` after a restart; the Rust client never hides this by automatically preflighting or
retrying retained route authority. This is process-lifetime correlation over the current same-UID
local channel, not binary attestation or authentication against an explicitly untrusted agent.
Production packaging must still provide separate role sockets and service identities before this
channel can carry trusted route authority.

The route operations are:

- `StartSession`: 16-byte context, 32-byte exit SPKI SHA-256 pin, minimum paths, non-zero MASQUE
  context ID, explicit multipath/single-path mode, an exact 43-character base64url per-route
  credential, exact TLS server name, and an expiry no more than fifteen minutes ahead. It also
  carries the signed reservation/finalize IDs, bearer commitment, certificate digest, and exact
  client/exit native instances. The client instance must equal the request target. The native check
  establishes credential encoding syntax and commitment equality, not generator entropy;
- `StartExitSession`: the exact context, 43-character base64url credential, expiry, one-path
  `SinglePathGeneralUdp` shape, MASQUE context ID, nonzero exit-SPKI pin, TLS server name, path ID,
  exact exit-listener and expected-client IPv6 overlay tuples, nonzero reservation hash, and
  in-memory certificate-chain/private-key PEM bounded to 64 KiB/16 KiB. It carries the same signed
  reservation/finalize, commitment, certificate and process-instance scope as `StartSession`; the
  exit instance must equal the request target. No pathname is accepted;
- `AddPath`: context/path ID, exact IPv6 local/remote overlay addresses, local/remote UDP ports, and
  a 32-byte relay-reservation hash. The address pair must use `fd76:6f6c:7061::/48`, embed the path
  ID in segment six, share one `/112`, and use fixed client host `1` and exit host `4`;
- `RemovePath`, `GetStatus`, and `StopSession`: exact context and, where relevant, path;
- `SendDatagram`: context, MASQUE context ID, and one already-authorized bounded IPv4/IPv6
  datagram;
- `ReceiveDatagram`: exact context and MASQUE context ID for one bounded reverse poll.

The canonical API-v6 `StartExitSession` field tags are deliberately append-only relative to its
old six-field shape:

| Tag | Field |
|---:|---|
| 1 | `route_context_id` |
| 2 | `auth_secret` |
| 3 | `expires_at_ms` |
| 4 | `minimum_paths` |
| 5 | `masque_context_id` |
| 6 | `transport_mode` |
| 7 | `exit_spki_sha256` |
| 8 | `tls_server_name` |
| 9 | `path_id` |
| 10 | `listener_ip` |
| 11 | `listener_port` |
| 12 | `expected_client_ip` |
| 13 | `expected_client_port` |
| 14 | `reservation_hash` |
| 15 | `tls_certificate_pem` |
| 16 | `tls_private_key_pem` |
| 17 | `reservation_id` |
| 18 | `finalize_id` |
| 19 | `auth_commitment` |
| 20 | `certificate_sha256` |
| 21 | `client_native_instance_id` |
| 22 | `exit_native_instance_id` |

Before the framed protobuf, every contact sends one fixed 32-byte binding as a stream prefix.
Because `SOCK_STREAM` may split it across reads, native assembles the complete prefix; any
descriptor must accompany its first received byte and later ancillary data is forbidden.
`AddPath` and `StartExitSession` each bind exactly one `SCM_RIGHTS` UDP descriptor to the
canonical request with SHA-256 over a separate NUL-terminated API-v6 domain
(`VOLPAROSSA-MPQUIC-ADD-PATH-FD-V6` or `VOLPAROSSA-MPQUIC-START-EXIT-FD-V6`), the four-byte
big-endian canonical payload length, and the payload. All other operations require an all-zero
binding and zero descriptors. Missing, extra, incomplete, late, cross-domain, wrongly bound, or
otherwise unexpected ancillary data is rejected and every received descriptor is closed.

For `AddPath`, Rust validates the socket before transfer and the active native client backend
repeats its UDP/tuple/overlay checks before mqvpn adoption. For `StartExitSession`, Rust requires an
unconnected nonblocking close-on-exec IPv6-only UDP socket, exact pre-bound listener tuple, and
disabled address/port reuse; the dormant C runtime independently repeats those current socket and
tuple checks. Neither check proves that the overlay address was assigned by the helper or that the
socket belongs to the attested route namespace. The native runtime consumes and closes that descriptor on every path,
then returns `exit_listener_orchestration_unavailable`; it never binds a host listener, reads a
secret pathname, or falls back. Both descriptor hashes prove request correlation. Only the active
`AddPath` client backend checks a same-session namespace cookie; `StartExitSession` has no namespace
cookie or helper-origin proof.
Production adoption remains blocked until helper provenance and the reviewed exit backend exist.
API v6 is intentionally incompatible with v5 and has no negotiation or downgrade. A consumed
descriptor is never reused after success, rejection, timeout, or I/O failure; any caller-level
retry requires a newly acquired listener, a fresh control connection and nonce, and a still-valid
authorization. A structurally valid `StartExitSession` whose bearer matches its supplied
commitment consumes its reservation/finalize pair before returning
`exit_listener_orchestration_unavailable`; that pair cannot be retried in the same process.

The API-v6 exit boundary validates DNS syntax for the supplied TLS name, nonzero length for the
SPKI pin, and only nonempty/NUL-free size bounds for the purported certificate/private-key PEM
bytes. A separate, callerless native foundation strictly parses a bounded certificate chain and
private key, treats the first certificate as the leaf, and verifies leaf-key consistency, an exact
non-wildcard DNS hostname match under case-insensitive X.509 DNS semantics, a caller-supplied
trusted interval, canonical complete-leaf DER SHA-256, and leaf-SPKI DER SHA-256. Additional chain
certificates must be canonical DER and parse completely but are not trust-path validated.
The runtime does not call this verifier. Production integration remains blocked on an affine expiry
handoff with overflow-safe floor-now/ceil-expiry conversion from signed Unix milliseconds, an
independent fixed Rust/C DER-SPKI vector, parser fuzzing, and TLS trust/usage enforcement. No
current session or datapath success claim depends on this isolated identity check.
The bearer commitment, signed IDs, certificate digest, process instances and SPKI bytes are now
carried together, but native does not itself verify the exit's signed final reservation bundle.
After shape and bearer-commitment validation, native uses a fixed 128-record, no-live-eviction
process-local ledger keyed by `(reservation_id, finalize_id)`: exact reuse is a replay, reuse of
only one ID is a scope collision, an exact live client retry is allowed only while its original
session remains active, and stop, expiry, or a valid exit start leaves a tombstone until the
authorization deadline. Request nonces remain response-correlation values, not a general replay
cache. The ledger is erased by process restart and purged at the deadline, so this is not
independent cryptographic or durable replay verification; a production caller must verify the
signed scope, bind both native instances, and hand it off affinely.

For admission, native samples `CLOCK_BOOTTIME` before `CLOCK_REALTIME`, maintains a monotone
effective wall-clock floor, and converts the accepted remaining wall lifetime once to a
`CLOCK_BOOTTIME` deadline. Live-session checks thereafter read only `CLOCK_BOOTTIME`; wall-clock
rollback cannot extend or revive an authorization, while a forward jump can only shorten it.
Clock read failure, BOOTTIME regression, and arithmetic overflow fail closed.

`NativeResponse` echoes version/nonce, requires the responding role/instance, and carries SHA-256
over `"VOLPAROSSA-MPQUIC-REQUEST-V6\0"`, the four-byte big-endian canonical payload length, and the
exact canonical unframed request. It returns `Ok`, `Version`, `InvalidRequest`, `NotFound`,
`Unauthorised`, `Transport`, `InsufficientPaths`, `NoDatagram`, or `QueueOverflow`, plus a bounded
code, an optional exactly correlated reverse datagram, and no more than eight path records.
`StaleInstance` is a separate typed result. Only a successful `StartSession` may carry a bounded
IPv4/optional-IPv6 tunnel assignment; every other operation rejects one. The current mqvpn backend
deep-copies exactly one assignment while `TUNNEL_READY`, accepts only a byte-identical duplicate
after activation, and publishes it only after mqvpn synchronously reaches `ESTABLISHED`. Rust, the
C protocol boundary, and the backend state independently require server `10.76.0.1/32`, client
`10.76.0.2/32` through `10.76.0.254/32`, MTU 1280..1420, and either no IPv6 address or
`fd76:6f6c:7062::2/112` through `fd76:6f6c:7062::fe/112`. The backend rejects outbound packets
whose source is not the retained client address and reverse packets whose destination is not that
address, and wipes retained state on fatal transport failure. This does not prove that a production
exit allocated the address uniquely for the route lifetime, that the helper assigned it in the
exact namespace, or that a real packet traversed it. Each path wire record reserves fields for path
ID, smoothed RTT, loss, unique delivered payload bytes, congestion window, bytes in flight,
delivery rate, and validation/real-carriage state. The runtime now publishes an exact current path
set only when the pinned backend supplies every required metric and a valid normalized path state.
It uses ACKed transport bytes only for the real-carriage boolean and keeps unique delivered payload
bytes at zero, because transport framing and retransmissions make the former unsuitable for the
latter. These fields are necessary to prevent a native process from falsely reporting mere path
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
