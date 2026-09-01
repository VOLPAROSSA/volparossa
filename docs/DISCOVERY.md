# Decentralised discovery

VOLPAROSSA uses rust-libp2p for its control plane. Discovery is not a source of trust: it produces
candidates that remain subject to signed-message, policy, diversity, capacity, reachability, and
local-observation checks.

## Protocol composition

The current discovery crate composes:

- QUIC and TCP+Noise+Yamux transports;
- Identify and Ping;
- a private Kademlia protocol, `/volparossa/kad/1`;
- mDNS for local bootstrap;
- AutoNAT and DCUtR for reachability and direct control-plane upgrades;
- Circuit Relay v2 client/server for control-plane connectivity only;
- canonical protobuf request-response on `/volparossa/advertisement/4` for direct retrieval of
  relay/control-relay advertisements only;
- canonical protobuf request-response on `/volparossa/exit-forward/4` for the client-to-control-
  relay hop and `/volparossa/exit-forward-upstream/4` for the control-relay-to-exit hop;
- canonical protobuf request-response on `/volparossa/datapath-relay/4` for direct operations with
  one prospective or selected datapath relay;
- canonical-byte request-response on `/volparossa/preselection-observation/4` for the
  client-to-control/direct-relay hop and `/volparossa/preselection-observation-upstream/4` for the
  control-relay-to-exit hop; both behaviours have independent bounded one-at-a-time affine
  context/dispatch/bind/cancel seams; public event pumps expose no inbound response channel, the
  direct Relay and upstream Exit have one role-gated service-owned signer/responder pump, and the
  same private pump now owns one affine forwarded client request through the exact upstream Exit
  response and control Relay-signed prefix wrapper. The client-side outbound attempt owner remains
  absent;
- refusal-test constants, but no registered behaviour or fallback, for advertisement v1/v2/v3 and the
  retired direct reservation v2 identifiers; and
- a process-local MemoryTransport used by hermetic swarm integration tests, not as a network or
  dataplane route.

Kademlia record/provider TTL is five minutes and provider publication is shorter than that. Exact
values are resource bounds, not trust guarantees.

## Capability indexes

Nodes announce only recognized capability keys such as relay, exit, MPTCP, MPQUIC, bounded region,
and exact policy hash. Provider records contain provider identity/reachability, not a full node
catalogue or browsing metadata. The client first queries relay capability, directly fetches a
peer-bound v4 advertisement, and chooses a control relay. It then queries exit capability and asks
that relay to fetch each candidate exit advertisement over the two-hop forwarding protocols. The
client never dials an exit provider to retrieve its advertisement.

A directly fetched advertisement can mint only relay/control-relay provenance; its exit role is
unusable. A combined-role node is allowed to advertise, but this client process can mint its exit
capability only from exclusively forwarded provenance. Direct-then-forwarded is rejected;
forwarded-then-direct withdraws and quarantines that exit capability for the advertisement
lifetime. Within one route, the exit differs by node ID and Peer ID from the control relay and every
datapath relay. The same control relay may later serve as one datapath relay only after its own
permit, real two-leg probe, selection, authorization, and direct relay grant.

There is no global score, authority node, mandatory bootstrap, or central policy service. Policy
trust comes from configured maintainer keys and threshold signatures, not DHT popularity.

## Bootstrap sources

Target v1 accepts remembered peerstore addresses, mDNS, several replaceable independent built-in
contacts, user-imported `volparossa://peer/...` peerlinks, and a signed bootstrap file. Peerlinks
bind a libp2p multiaddress's `/p2p` component to the expected Peer ID. Once the DHT table is useful,
all bootstrap contacts may disappear without changing protocol authority.

Built-in contacts must be individually removable and distributed across independent operators and
networks. A signed bootstrap file authenticates its contents but still grants no policy or catalogue
authority. Acceptance test A01 disables each bootstrap in turn.

## Inbound validation and limits

Peers and DHT records are adversarial. The direct-advertisement v4 codec limits a request to 64 bytes
and the canonical protobuf response frame to 512 KiB; the contained signed envelope is separately
limited to 256 KiB. The behaviour permits at most 64 combined inbound and outbound streams.
Process-local bookkeeping admits at most 16 distinct outstanding provider queries and 256
outstanding advertisement requests; exact duplicates reuse the existing operation. Ingestion
requires equality among the advertisement's derived node ID, envelope sender, payload node and Peer
IDs, and authenticated provider Peer ID before committing replay or peerstore state.

Each exit-forwarding hop and each datapath-relay frame is canonical protobuf capped at 512 KiB, with
any signed control envelope still capped at 256 KiB. Role-aware protocol support prevents a client
from accepting upstream exit requests, an exit from accepting client-hop requests, or a client from
registering the retired direct-exit protocols. Both forwarding wrappers bind the forward ID,
absolute deadline, selected control-relay node/Peer ID, selected exit node/Peer ID, operation, and
exact canonical request bytes. The control relay authenticates both hops, compares the complete
request, performs no internal retry, and never adds a client Peer ID or address upstream.

All exit advertisements and exit operations - hold, probe permit, finalize, and confirmation - use
the same selected control relay on both hops. Positive responses are signed by the exit and checked
end to end. A generic hop response carries only `Granted`, `Rejected`, or `Unavailable`;
`Rejected` is definitive and neither failure status is a positive grant. A genuinely ambiguous
forwarding outcome permits only an exact-byte retry with the same operation, forwarding ID, peers,
absolute deadline, and still-live signed scope. A deliberately received fail-closed
`Unavailable` from the probe, helper, or agent is terminal for that setup and cannot be relabelled
as transport ambiguity or evidence of work.

The reservation order is hold, per-candidate permit, real controlled two-leg probe, final datapath-
relay selection, helper `Prepare`, exit finalization, direct selected-relay grants, exit confirmation
receipt for every path, then helper `Activate` and `Commit`. The direct relay protocol authenticates
the selected relay and exact signed session request. No v4 reservation artifact exposes the
client's permanent node ID or Peer ID to the exit. Expiry removes capacity and cached success
responses; setup and teardown retain local Destroy authority until the helper proves cleanup.

Circuit Relay v2 is never a WireGuard or Internet dataplane fallback. A peer that cannot establish
an authorized direct UDP/WireGuard path may still be reachable for discovery, but is unsuitable for
that dataplane path. Its name is independent of the hard-incompatible VOLPAROSSA privacy-v4 control
protocol.

Advertisements contain only non-secret, static selection metadata. They never publish per-route or
per-path WireGuard public keys or listen ports, and a capability is not evidence of kernel state,
reachability, admission, or probe success. Relay and exit provider publication therefore remains
fail closed until the corresponding local helper-backed preparation and service admission are
actually available. The default client-only configuration publishes neither a fake operator nor a
useless service provider record.

## Current evidence boundary

The crate contains the v4 codecs, role-aware behaviours, capability namespace, peerlink validation,
and process-local swarm tests. One three-peer test proves an exit advertisement request cannot be
sent directly to the exit and that the byte-identical request/response crosses exactly one control
relay. Another proves the `ExecuteProbe` frame is valid while its production handler returns
`Unavailable` without exposing a fake probe event. Unit tests cover canonical encoding, exact
bounds, role direction, identity contradictions, response shapes, and refusal of advertisement
v1/v2/v3 and retired direct-reservation v2 identifiers.

The unprivileged discovery actor also has a dormant, crate-private route-candidate snapshot
command. It captures one lower-bound timestamp, purges expired actor entries, copies the exact
active policy metadata, and loads at most 200 records. Before projection it re-verifies each
persisted canonical signed envelope in production code and joins its exact fingerprint, node and
Peer IDs, sequence, signed millisecond timestamps, actor capability, and policy
version/hash/expiry. Output is explicitly sorted and identity-unique. Stored-only, expired,
conflicted, self, pending-direct, unpaired, and direct-only exit records are excluded. An exit with
more than one otherwise valid control-relay pair is currently excluded in full: choosing one
without a selected-control measurement primitive would hide ambiguity, so this is a deliberate
fail-closed availability limitation.

The snapshot contains no raw signed envelope, stored endpoint, stored RTT/capacity history, wire
serialization, or RPC authority. It projects only the verified advertisement body, exact signed
times, limited historical reputation/fault state, and actor-minted in-process capability binding.
Each projection also retains the opaque exact `SignedEnvelope.payload_hash`; a forwarded exit
retains distinct control-relay and exit hashes. The full fingerprint record, signature and raw
envelope stay inside discovery. The hash is only an equality binding, not reservation, session or
dispatch authority: route execution still has to re-resolve and exactly compare current actor
capabilities later.

The protocol crate contains the A0 preselection-observation transcript primitives. Discovery now
has production-compiled role-gated Relay/Exit responders and an affine Relay-to-Exit forwarding
wrapper; the client-side outbound attempt owner remains absent. A direct relay can sign one exact
short-lived challenge response. For a forwarded exit,
the exit signs the response and the exact prospective forwarding control named in the unsigned
request countersigns the exact nested bytes plus a public IPv4 /24 or IPv6 /48 prefix claim. The
control intentionally echoes the exit-subject challenge with its own signed-envelope nonce and
time window; it is not separately challenged. The claim contains no host address, endpoint, port,
capacity, reservation, or dispatch authority, and a control signature is not proof that a
malicious control reported origin truthfully. The production Relay handler derives the prefix from
the exact authenticated upstream connection before signing it. Prefix validation maps the fixed
three- or six-byte wire
field directly into the shared normalized prefix type and checks its public range; it never
constructs a representative host IP. That normalized value alone proves neither provenance nor
origin truth.

A0 still has no production client-side outbound attempt owner. A separate dormant affine sampler
can narrow the actor-built snapshot, and a dormant affine join can consume the completed A1a owner
together with one exact service-bound client transport per request, purpose-consume both proof
kinds, and mint the route-selection child's existing private `FreshEvidenceBatch`. No actor calls
either boundary, and the conservative batch deliberately leaves native dataplane-address usability
false, so it cannot yet produce a selectable `CandidateEvidence` or route. Discovery composes
request-response behaviours around the unchanged exact A0 bytes. Its client sending seam can
dispatch one request, bind an opaque matching response arrival sealed and timestamped by the
originating service's private pump to a current unique connection proof, or cancel that exact
dispatch; the affine Relay forwarding wrapper owns upstream sending separately.

Discovery now also contains a role-gated Relay/Exit response poll seam called by the agent event
loop while an exact active policy is present. The poll owner obtains a typed inbound request
directly from the same service's swarm;
the raw behaviour-local request IDs, `ConnectionId` and response channel never cross its public
caller boundary and therefore cannot be transplanted between service instances. The ordinary
public event pump closes both client-hop and upstream inbound preselection channels without
yielding them. It seals responses for the exact active outbound dispatch into opaque
instance-bound arrival values before returning them and drops stale/unowned responses. The
responder pump consumes both role-appropriate inbound hops internally and applies the same response
sealing. No public pump yields a raw preselection request or response message. Each responder synchronously
requires the exact event `ConnectionId` to rebind a unique current authenticated peer/family
witness. It then cryptographically re-verifies the exact currently served local Relay or Exit
advertisement and its Peer/node/public-key identity, requires nonzero ASN, advertised
transport/family support and the
exact supplied active policy version/hash/expiry, and signs an exact request-bound receipt through
the same permanent Ed25519 key. The envelope and payload commit version, sender, timestamp, expiry,
fresh fallible CSPRNG nonce, type, payload hash, request hash, challenge, actor and scope. A fixed
120-second no-rollback request-hash tombstone is inserted before signing; 1024 global and 16 per
authenticated peer are the hard bounds. Duplicate requests, exhausted bounds, stale or substituted
authority, ambiguous lineage and signing failure return no response. The affine connection proof
is retained until the exact response-channel handoff and exposes no getter. An upstream request
additionally requires `forwarded_control`'s public key and Peer ID to be the exact authenticated
Relay, while its challenged actor must be the exact local Exit.

These responders record no origin claim, RTT, capacity, reachability, reservation, route or Fresh
authority. The production discovery actor polls its private responder only while an immutable
Relay or Exit role and an exact active threshold-verified policy snapshot are present. It
uses the same actor-owned permanent identity, and a policy command cancels the poll before applying
the replacement. A response still requires an exact currently served role advertisement;
production deliberately publishes no usable Relay/Exit capability before dataplane readiness is
proved, so no successful production response or readiness claim follows from this lifecycle
connection yet. The control-signed prefix wrapper is now implemented, while the outbound attempt
owner and the A0 response-verification/A1a exact-set join owner remain absent. Dormant A1a
remains only a static consumer of verifier/consume functions. The opaque transcripts, transport
proof and wire wrappers are not yet local freshness, capacity, or route authority.

The agent now contains a dormant A1a ownership prerequisite. Snapshot construction privately mints
an endpoint-free, non-derived subject set from the exact freshly revalidated stored signed
advertisements; legacy snapshot construction remains available when that hidden binding cannot be
minted, while A1a begin rejects the unavailable marker. The subject set retains exact node and
Peer identities, public key, required role/control-exit shape, advertisement sequence/expiry and
`SignedEnvelope.payload_hash`, policy version/hash/expiry, canonical actor-capability expiry, and a
separate local discovery-authority ceiling. It contains no endpoint, origin, history, stored RTT,
per-peer capacity, operator, or ASN projection.

A separate discovery-private affine sampler now consumes that actor-built candidate snapshot and
revalidates its exact advertisement, capability, policy, identity, role, transport, family and
forwarded-control bindings before choosing anything. It chooses one eligible forwarded Exit and
that Exit's exact control Relay first, then between one and eight other Relay prospects. The
product entry point owns `OsRng`; weighted choices use bounded 70/20/10 high, diverse-middle and
exploration bands, so multiple eligible Exits and Relays are sampled rather than silently taking
the first canonical record. The reduced snapshot keeps the control at direct index zero, one
forwarded Exit paired to it, and the remaining Relays in sampled order; no direct Exit candidate is
created. Invalid shape, entropy failure, missing Exit/control, or inadequate diversity fails
closed while returning the exact original snapshot affinely in the boxed failure.

Preselection diversity is strict across the chosen control, Exit and every other Relay for signed
operator ID, non-zero ASN and a canonical public advertised IPv4 `/24` or IPv6 `/48` hint in the
requested family. The hints are inexpensive signed claims, not authenticated network origins;
they provide no Fresh, route, reservation or reachability authority. The later exact-set transport
join must replace each hint with the direct connection-derived or control-attested native prefix
and re-enforce actual network-origin diversity before minting `FreshEvidenceBatch`. The sampler is
still dormant: it has no production attempt actor, network dispatch or Fresh-evidence caller.

Each discovery-private `pub(super)` affine `PreselectionAttemptGate` lineage admits at most one
attempt at a time. It validates a batch-wide non-zero conservative local bandwidth ceiling and an
exact one-forwarded plus one-to-eight-other-relay slate before internally minting a non-zero
16-byte batch ID and two
to nine unique non-zero 32-byte challenges with `OsRng`, one per request and challenged direct
relay or forwarded exit; the control wrapper shares the exit challenge. A single request is
prepared at a time; the forwarded response contributes both its exit receipt and control wrapper,
yielding three to
ten retained signed envelopes. The attempt/request/cooldown limits are 30/5/30 seconds. Challenge
and batch-ID tombstones are retained for 120 seconds from each JIT preparation, with fixed 36+4
capacities and a 40-entry owned replay cache; no redraw, retry, or live eviction is allowed.
On pre-entropy validation or capacity rejection, `PreselectionBeginFailure` retains the original
gate without cooldown. An admitted attempt returns a cooling gate only for a valid non-decreasing
terminal wall/monotonic pair; invalid, backward, or
overflowing terminal time loses it fail closed.

A1a gives each raw bounded response directly to the dedicated A0 verifier, then consumes the
verified transcript against the exact canonical request bytes. Its final
`BoundPreselectionTranscriptBatch` is opaque, non-cloneable, endpoint-free, and retains only
sanitized subject/request bindings, process-local dispatch ID/request hash, opaque transcript
tokens and attempt ceilings. It deliberately records no authenticated connection, local send or
arrival event, socket origin, RTT, reachability, usable address, or Fresh-evidence validity. It
has no production client root, transport-join owner, or conversion into phase-A evidence,
and creates no `RouteSessionAuthority` or `ReservationSession`. The production request-response
responders and forwarding wrapper do not consume this A1a value. The completed
affine A1a owner retains the original, non-cloned `RouteCandidateSnapshot` beside—not inside—the
endpoint-free transcript batch. This preserves the exact candidate-union allocation for a later
owner without exposing a getter or reconstructing candidate state. That sibling is the existing
actor-private selection snapshot and can contain advertised control endpoints; those never enter
the transcript batch or the opaque transport proof.

A later A1c transport-provenance owner must exact-set join that batch to the authenticated Peer ID,
libp2p `ConnectionId`, local request ID and request hash, and local monotonic send/arrival events.
For a direct relay, both RTT and the normalized public IPv4 /24 or IPv6 /48 must come from that same
authenticated remote socket. For a forwarded exit, the control-attested upstream /24 or /48 stays
native; it must never be widened into a fabricated full representative IP. An
`observed_endpoints[PeerId]` mutable cache, advertised endpoint, stored Ping/history, the control's
own origin, or a direct client-to-exit connection are forbidden substitutes. Only A1c may impose
the local-arrival freshness ceiling and aggregate it with the unchanged absolute attempt deadline,
every applicable signed receipt/attestation window, actor advertisement/capability expiries, and
policy expiry before minting a verified observation.

The first A1c provenance component is composed as a private passive libp2p behaviour. It observes
the authenticated `ConnectionEstablished`, `AddressChange` and `ConnectionClosed` event lineage,
bounds the registry by the existing 384-global/four-per-peer connection ceilings, and permanently
poisons and clears the registry on overflow or inconsistent event lineage. Every connection,
including one whose remote address is unusable, counts toward per-peer uniqueness. A usable native
prefix is accepted only from an exact direct public-IP TCP or QUIC-v1 remote multiaddress, with an
optional terminal `/p2p` component matching the authenticated peer; DNS, memory, circuit-relayed,
private/special, zero-port and extra-component addresses are rejected. Records retain only the
Peer ID, `ConnectionId`, non-zero generation, opaque normalized /24-or-/48 token and the same native
three or six prefix bytes, never a full IP or multiaddress. An address change increments the
generation even inside the same prefix. The private
affine witness can be minted only for exactly one total connection to that peer in the requested
native family, and binding consumes it while rechecking peer, connection, generation and prefix.
There is deliberately no generic `DiscoveryService` registry, address, prefix, witness, or bound-
observation accessor. The only consumers are the purpose-specific client and upstream transaction
seams described below; there is still no A1a join or Fresh-evidence mint, so the rest of A1c
remains required.

A second A1c wire component consists of two strictly separate libp2p request-response
behaviours and event variants. The client-facing protocol is outbound for Client and inbound for
Relay roles; it carries an A0-valid Relay or forwarded Exit request of at most 4096 bytes and
returns either a Relay-role signed receipt of at most 4096 bytes or a control-signed forwarded Exit
attestation of at most 8192 bytes. The upstream protocol is outbound for Relay and inbound for Exit
roles; it accepts only the same canonical forwarded Exit request and returns only an Exit-role
signed receipt, each at most 4096 bytes. Both behaviours have an exact five-second transport
timeout, 64 concurrent streams each, no legacy protocol aliases, and no retry. A shorter unchanged
A0/A1a absolute request expiry remains authoritative.

The codecs revalidate canonical encoding, v4 and hop-specific type/role shape, payload-local
invariants, and typed payload-to-envelope fields on both read and write. They neither verify a
signature nor mutate replay state, sign a response, or claim origin/reachability. The two event
variants retain separate libp2p request-ID domains and independent one-at-a-time active slots. The
client hop derives the direct relay or forwarding control plus native family from the exact
canonical request; the upstream hop requires the request's forwarding control to be local and
derives only the exit plus family. Each requires one unique current direct connection, mints a
generation-bound witness immediately before its synchronous libp2p send, binds only a typed
same-hop response arrival minted by the same service instance, and applies the minimum of its fixed timeout, unchanged A0 expiry, and
caller deadline. Context-bound variants retain an arbitrary non-cloned caller owner—intended for
the original candidate-snapshot attempt on the client and the original downstream channel/request
owner at a control relay. A client transaction presented to a foreign service is retained
unchanged so its originating service can still bind or cancel it. Once that originating service
recognizes its exact active client transaction, every sealed response is terminal: it releases the
slot before checking the arrival's service instance, peer, request ID, time or connection
provenance, and a failed bind returns the exact unchanged caller context without reusable dispatch
authority. The upstream context is still returned only by its exact bind or cancellation. This
prevents a later owner from accidentally pairing a sibling response and snapshot without exposing
the context during flight.

Merely dropping an active dispatch, transaction or arrival, or failing to obtain an arrival clock,
leaves its slot occupied fail closed. On the upstream hop a foreign service, wrong peer or wrong ID
also leaves the slot occupied; exact upstream correlation consumes it before subsequent time or
connection-provenance checks. The private pump stamps local monotonic and wall time at observation;
binding rechecks the exact service instance, private request ID, authenticated peer, event-local
`ConnectionId`, deadline, uniqueness, generation and native prefix. The bound authority tokens
themselves expose no address, peer, connection, ID/hash/time getter, equality oracle, clone or
decomposition. Purpose-specific terminal consumers destroy those tokens and expose only the facts
needed by a future private freshness owner: the client transport yields an endpoint-free normalized
public IPv4 `/24` or IPv6 `/48`, its sealed local wall-observation time and monotonic round trip; the
upstream connection may yield only the normalized prefix for the Relay-signed wrapper; and verified
direct or forwarded transcripts yield only their signed validity ceiling, or the earlier joint
signed ceiling plus the control-signed normalized prefix. None exposes a request, identity,
signature, nonce, full endpoint, connection, dispatch capability or other reusable authority. No
production outbound client attempt actor/owner yet exact-set joins these projections and
the retained A1a set into a `FreshEvidenceBatch`, so they establish neither Fresh evidence nor route
readiness. The swarm pump drops a
still-current client-hop request unless it targets the local relay/control and its authenticated
remote sender differs from both that local peer and the challenged actor. A0 deliberately contains
no client identity, so this is not a claim that the sender is request-bound. Upstream, the pump
instead requires `forwarded_control` to equal the authenticated relay and the actor to equal the
local exit. Those predicates exist only inside the private raw transport pump. There is no public
raw-event bind, preselection response-channel or response-sending API; transport-only unit proofs
use the private raw pump, while public real-swarm proofs bind both sealed response types.
Independent client-hop and upstream request-response behaviours intentionally collide with the
originating behaviour-local outbound ID, yet their real responses cannot bind when sealed by
another service. The service-owned Exit responder now consumes an admitted upstream request
without exposing its channel.

A separate production-compiled role-gated poll owns each raw inbound direct-Relay or upstream-Exit
event and its response channel inside the originating `DiscoveryService`. It binds the authenticated peer,
event-local `ConnectionId` and requested native family to one unique current private connection
lineage and retains that opaque affine proof through response handoff. It re-verifies the exact
currently served signed role advertisement and local Peer/node/key identity, requires non-zero ASN,
advertised transport/family support and the exact active policy version/hash/expiry, and signs the
request hash, challenge, actor, scope, local observation time and bounded validity with the same
permanent identity. The v4 envelope also binds sender, time, expiry, a fresh fallibly generated
CSPRNG nonce, message type, payload hash and Ed25519 signature. Exact request hashes enter a
120-second no-rollback tombstone before signing, bounded to 1024 globally and 16 per authenticated
peer. Replay, resource exhaustion, signer failure, stale authority and ambiguous lineage fail
closed without a response. A real two-swarm test proves that the originating channel carries the
exact signed receipt. Separate real transport regressions prove that the ordinary public pump never
yields an inbound channel and a sibling service cannot answer a channel captured by the
originating service's private test pump. A second real two-swarm proof sends an upstream request
from an authenticated Relay and verifies the exact Exit-signed receipt on only its originating
channel. The Exit responder itself mints no control-Relay prefix wrapper.

For a forwarded Exit request, the same private production pump retains the original canonical
request, authenticated client peer, event-local connection, inbound request ID and response channel
as one affine owner. It first requires a read-only unique authenticated Exit-provenance preflight,
then tentatively reserves shared replay capacity and synchronously dispatches the unchanged
request. Every pre-send dispatch failure consumes an exact non-cloneable token to roll back only
that newly inserted tombstone; successful send commits it. Only the
exact upstream peer/request and still-current connection generation can return. The owner verifies
and fixed-cache replay-admits the Exit signature and exact request binding, purpose-consumes the
opaque upstream proof into only a public `/24` or `/48`, rechecks the current Relay
advertisement/Identity/policy, applies every expiry ceiling, signs a fresh-nonce
`ForwardedPreselectionAttestation`, and responds only on the retained client channel. Policy-off,
policy/Identity drift, deadline, exact upstream/downstream failure and the generic event pump all
cancel the owner and free its one upstream slot. Requests without unique Exit provenance fail
before consuming a tombstone.

A hermetic three-swarm MemoryTransport test verifies the nested signatures/replay and checks live
connected-peer state includes the Relay but not the Exit. It also exercises wrong peer/request/
connection and all lifecycle cleanup paths above. The test `/24` is derived from explicitly
injected public endpoint lineage and is not external-network evidence. Neither receipt nor wrapper
claims origin, RTT, capacity, Fresh evidence, reservation, route, admission, readiness, or datapath
authority. The production agent supplies the policy and permanent signer, but there is still no
client-side outbound attempt owner. The dormant sampler, exact-set join and private Fresh-evidence
mint described below therefore have no runtime caller.

A separate dormant A1b selector hardening does not consume A1a transcripts. It makes the fake-only
Fresh/plan path prefix-native while treating the normalized prefix as untrusted data rather than
provenance: the path retains no full host IP, sets the legacy candidate-origin field to `None`, and
uses one opaque /24 or /48 value in the shared hard-filter, exit, prospective-relay and complete-path
kernels. Legacy full-origin selector entry points remain source-compatible boundary adapters. A1b
does not consume the separate snapshot sampler and adds no handler, transport evidence, production
caller or usable production candidate. The A1a/A1c bridge now consumes the exact opaque transport
and transcript proofs, but deliberately cannot prove native dataplane usability. Its private Fresh
batch is still subject to the existing observed-origin diversity hard filter before route planning.

A dormant phase-A boundary consumes one non-cloneable `FreshEvidenceBatch` before it builds a
`ProspectiveRoutePlan`. In addition to test fixtures, its private production mint now requires the
exact retained A1a candidate set and one purpose-consumed A1c transport plus cryptographic
transcript for every request. It rejects count, order, request hash, actor, forwarded-control,
transport, family, wall-window and monotonic-window substitution before minting. The batch has a non-zero opaque ID, contains exactly the 1-200
direct-relay plus forwarded-exit identities in the actor snapshot (no missing or unrelated record),
and binds every observation to role, node/Peer ID, capability public key, advertisement
sequence/expiry/payload hash, transport, address family, policy version/hash/expiry, observation
time, explicit `valid_until`, one normalized public IPv4 /24 or IPv6 /48, and a conservative
preselection capacity ceiling. A relay observation has the Relay role and no forwarded-control
field. An exit observation has the Exit role and carries the exact forwarded control tuple,
including its advertisement hash plus key and advertisement/capability expiries. A direct record's
RTT is its exact client-Relay request round trip. The forwarded record's RTT spans the complete
client-control-Exit-control-client request round trip and is copied conservatively to its control
and Exit evidence; it is never represented as a direct client-Exit measurement. The configured
ceiling and endpoint-free prefixes are only local selector input: they establish no measured
capacity, offer, hold, reservation, admission or dispatch authority. Trusted time must satisfy
`observed_at <= now < valid_until`; the observation is at most 60 seconds old and `valid_until`
cannot exceed freshness, policy, advertisement or capability expiry.

The proof mint records one successful reachability sample, no measured p25, neutral zero proximity
and egress-quality scores, and no native dataplane-address proof. `locally_blocked = false` means
only that this proof input supplied no local blocklist hit; it is not affirmative policy evidence.
Consequently the existing hard filter rejects every such batch until a separate native-path
sampler supplies the missing dataplane evidence. The bridge grants no discovery dispatch,
reservation or route authority and has no production caller.

Phase A still selects the exclusively forwarded exit first. It then uses only hard-filtered local
peer evidence and the existing randomized 70/20/10 score bands to choose a seed-dependent
prospective relay slate of at most eight in randomized sampling order. Canonical candidate ordering
makes a fixed seed independent of snapshot input order; exploration remains possible, and no
complete-path RTT, capacity, throughput-gain or failover value is invented. Control, exit and slate
entries must be distinct by node ID, Peer ID, operator, ASN and one normalized public IPv4 /24 or
IPv6 /48. These constraints permit at most one
selected slot from any such observed cluster; they mitigate but do not eliminate Sybil attacks or
the pre-sampling multiplicity advantage of many identities in one cluster.

The private plan is neither cloneable nor serializable and has no `Debug` representation. It binds
the batch ID, trusted selection time, exact forwarded control/exit identities, immutable route
scope/policy, 1-8 prospective relay identities, bounded selection-only peer evidence/diversity and the
earliest evidence expiry. Each control, exit and relay binding now retains its own explicit evidence
validity; plan construction and consumption independently recompute the aggregate as their exact
minimum. The retained diversity material contains operator and ASN plus only the normalized /24 or
/48, not a full host IP, together with local capacity/quality/history needed for later hard filtering;
it retains no full observed host IP,
dialable multiaddress or port, signed envelope, hostname, destination, application or flow history.
The legacy `CandidateEvidence.observed_network_origin` field is explicitly `None` on this path.
Legacy public selector entry points remain source-compatible adapters, while legacy and new
prefix-native entry points share the same private filter, scoring, banding, RNG and diversity
kernels. C1 must consume the plan before its earliest expiry; future dispatch must consume the C1
continuation and re-resolve every actor capability before any RPC.

The dormant phase-C1 boundary now consumes that plan by value into one private pre-probe
continuation. Before either mint, it checks the retained non-zero batch identity, selection time,
policy, node-to-key binding, non-zero advertisement sequences, global node/Peer/key uniqueness,
per-actor evidence and capability windows, capacity, reachability, exact normalized prefix and hard
diversity invariants. It assigns stable path IDs `1..N`, validates replay/setup/hard limits and
helper second-floor boundaries, and projects one Tokio deadline from a monotonic sample bounded by
the remaining wall-clock setup/evidence window. Only then does it mint non-zero, distinct
reservation/context IDs and exactly one in-memory `ReservationSession`. The continuation has no
clone, copy, debug, serialization, getter or decomposition API. It still retains the observed
prefix, but no observed host IP, as short-lived local diversity evidence.

There is no dispatch while C1 constructs this value. Dropping it before handing it to C2c remains
pre-dispatch cancellation by abandonment: it drops the ephemeral in-memory reservation session and
zeroizes the separate route-authority ID arrays, but it neither proves full session-memory
zeroization nor performs a rollback or journal mutation.

A dormant, crate-private C2c handoff can now consume that continuation under one manager-owned task
and cancellation watch. Before resolving actors it rechecks cancellation, the carried Tokio
deadline and wall/evidence windows, recomputes the exact actor hard/evidence ceilings, and consumes
the carried route authority plus ordered proofs into the endpoint-free `RouteSetupRequest`. One
bounded borrowed resolve then obtains the exact current control, exit and relay capabilities from
the same owned combined resolver/transport value; the adapter accepts no second handle between
these phases. The resolver future owns neither the route IDs nor the
reservation session. After resolution, C2c rejects a backwards or expired wall clock, cancellation,
deadline expiry, stale proofs, changed actor capability—including its exact advertisement payload
hash—or changed retained selection-time control/exit bindings. Only then does it move the original
`ReservationSession`, stable path IDs,
limits and unchanged absolute deadline into the existing private `UnmeasuredRouteSetup`; it neither
remints nor renumbers them. Dropping or cancelling a pending resolver drops that future and
requires no helper, network-state or journal cleanup because reservation dispatch has not begun.

The older scalar complete-path second stage remains only as a clearly dormant test boundary; the
new plan neither calls nor trusts it. C2c supplies the private ownership and actor-resolution link
to the existing phase-B transaction, but there is still no production fresh-evidence producer,
real probe verifier/handler, production orchestration or production caller. Consequently the real
resolver/transport path is not invoked by phase A in production. C2c adds no new wire, provider or
helper implementation, so it causes no production network/host mutation, and the reported usable
route-candidate count deliberately remains zero.

These are wire and control-service foundations only. They do not prove the production agent route
state machine, a real two-leg probe producer, helper-backed endpoints, client ingress, Internet
bootstrap failover, NAT traversal, enabled relay/exit serving, or any WireGuard/MPTCP/MPQUIC
dataplane. Those items remain governed by
[IMPLEMENTATION_STATUS.md](IMPLEMENTATION_STATUS.md).
