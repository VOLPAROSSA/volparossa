# Route contexts, WireGuard, and privileged routing

A route context is scoped by local profile, registrable domain/origin, transport class, and policy
version. Existing flows never migrate to a new exit. Context expiry affects admission of new flows;
LRU eviction drains and removes all associated interfaces, routes, MPTCP/MPQUIC paths, and firewall
state.

## Path invariant

Every active or backup path is `client -> exactly one datapath relay -> selected exit`. Parallel
paths use different relays and the same exit. One control relay is selected before the exit and is
bound to every exit-facing v4 operation for that route attempt. It differs from the exit by node ID
and Peer ID. It may also become one datapath relay only through its own permit, real probe,
selection, authorization, and grant.

A path owns a random route-context ID, path ID 1-8, short-lived reservation proof, fresh
client-session identity, two separate WireGuard links/four endpoint keys, a unique ULA `/112`,
exact endpoints, rates, expiry, and state. No exit-facing artifact carries the client's permanent
node ID or Peer ID. The normal client control plane and dataplane never have a direct connection or
route to an exit endpoint. A conspicuous development-only direct-exit flag exists in configuration,
defaults false, and is rejected in production.

## Control-plane and setup transaction

The required order is:

1. Directly fetch and verify a relay-capable `/volparossa/advertisement/4`, then choose its node as
   the control relay. Direct provenance can never mint exit capability.
2. Ask that control relay to fetch candidate exit advertisements over
   `/volparossa/exit-forward/4` and `/volparossa/exit-forward-upstream/4`. A combined-role node is
   usable as an exit only from exclusively forwarded provenance: direct-then-forwarded is rejected,
   while forwarded-then-direct withdraws and quarantines exit capability for the advertisement
   lifetime. Select an exit distinct by node ID and Peer ID from the control relay and every
   prospective datapath relay.
3. Create a fresh Ed25519 session key and request an exit capacity hold through the control relay.
   The hold declares path count, policy, transport, rates, and lifetime but reveals no relay list.
4. Obtain an exit-signed permit for every prospective relay through the same control relay, execute
   a real controlled client-relay-exit probe on `/volparossa/datapath-relay/4`, verify both-leg
   evidence, and only then select final datapath relays.
5. Build the exact helper `Prepare` request, register its intent with tag-35
   `BindHelperRuntime`, then send that prebuilt Prepare on the same authenticated helper stream.
6. Finalize the strictly ordered relay set through the control relay; verify the exit grant and
   every exact relay authorization.
7. Request each selected relay grant directly over `/volparossa/datapath-relay/4` and verify its
   nested exit authorization and helper-bound endpoints.
8. Send each exact relay grant to the exit through the control relay and require an exit-signed
   confirmation receipt bound to the exact confirmation bytes.
9. Only after all receipts exist, call helper `Activate` and then `Commit`.
10. Transfer grants, receipts, helper handles, and cleanup authority to the established route until
    Destroy-first teardown completes.

All calls share one absolute setup deadline. The only retryable reservation outcome is genuinely
ambiguous after dispatch: resend the exact bytes with the same operation ID, peers, and original
deadline while every signed scope remains live. A received `Rejected` or fail-closed backend
`Unavailable` ends that setup. Cancellation is not a retry reason, and peer-control v1/v2/v3 is never negotiated
or used as fallback.

The local Bind-plus-Prepare subsequence has one absolute five-second HelperClient budget inside the
outer setup deadline. The canonical Prepare frame, request ID, and digest exist before Bind. Tag 35
registers its exact intent in helper-runtime-global memory; it does not create a server-enforced
connection session. The client nevertheless requires Bind and Prepare on one `SO_PEERCRED`-validated
Unix stream. A failure before the first Prepare-frame write is definitive for network mutation;
every error after the first Prepare write is polled is ambiguous and carries the complete same-runtime
reconciliation authority.

The crate now has a dormant in-process boundary for the beginning of steps 1-4. A bounded command
asks the single-owner discovery actor for an immutable candidate snapshot. The actor purges expiry,
captures exact policy lineage, re-verifies persisted signatures/fingerprints, and joins only exact
remote direct-relay and forwarded-exit capabilities. It returns neither serialized messages nor
dispatch authority. Stored reachability, RTT, and advertised capacity do not become fresh route
evidence. Each projected advertisement and direct capability retain the same opaque exact
`SignedEnvelope.payload_hash`; a forwarded capability retains separate control-relay and exit
hashes. Those hashes are equality bindings, not authority, and the UI-facing usable-candidate count
stays zero.

The dormant fake-only phase-A planner now consumes one non-cloneable observation batch that exactly
matches the snapshot's direct-relay and forwarded-exit capability union. Every record is bound to a
non-zero batch ID, role, full actor identity/key/sequence/expiry/payload hash, transport, family,
policy lineage, observation time, explicit validity, one normalized public IPv4 /24 or IPv6 /48,
and a conservative preselection capacity ceiling; an exit also carries the exact forwarded control
tuple including its advertisement hash, while a relay carries none. The ceiling and prefix are
test-only local selection inputs and convey no offer, hold, reservation, admission, provenance or
dispatch authority. The trusted clock must remain inside every freshness and
policy/advertisement/capability lifetime. The planner applies the complete relay policy, selects
the forwarded exit first, then
chooses 1-8 prospective relays using the selector's real peer-only 70/20/10 bands. It does not
fabricate or accept complete-path scalars.

Control, exit and prospective relays are hard-diverse by node, Peer ID, operator, ASN and one
normalized public IPv4 /24 or IPv6 /48. The prefix-native plan and actor proof retain no full
observed host IP. Legacy full-origin selector APIs normalize at their boundary and then use the
same filter, scoring, banding, RNG and diversity kernels; no second selection algorithm exists.
Canonical ordering makes a fixed random seed independent of input order, while different seeds may
choose different valid slates and exploration is retained.
Hard diversity limits any observed cluster to one slate slot but does not eliminate Sybil identity
multiplicity before sampling. An exit with multiple otherwise valid control-relay pairs is still
excluded entirely until an actor-owned selected-control primitive exists.

The resulting private plan is non-cloneable, non-serializable and not debug-printable. It retains
only exact actor identity and advertisement-payload-hash bindings, route scope/policy, short-lived
peer capacity/quality/history, prefix-native operator/ASN and /24-or-/48 diversity, each actor's
explicit evidence-validity window, and their exact minimum. It retains no full observed host IP,
dialable endpoint/port, envelope, hostname, destination, application/flow history, route-session ID
or dispatch authority. Its legacy `CandidateEvidence.observed_network_origin` field is `None`. C1
consumes the plan before expiry; future dispatch must consume the C1 continuation and re-resolve
actor capabilities before any RPC.

The dormant phase-C1 consume boundary now moves this plan into one private pre-probe continuation.
It structurally checks the retained control, exit and relay node-to-key bindings, non-zero
advertisement sequences and payload hashes, global node/Peer/key uniqueness, actor and evidence
expiries, capacity/reachability/prefix/diversity, route policy, replay bound, setup/hard wall windows and
helper second-floor limits. It allocates stable prospective path IDs `1..N` and one Tokio deadline,
projected from a monotonic sample conservatively taken before the trusted wall sample and bounded by
the minimum of setup timeout and the remaining setup/evidence window. Only after every check and
path allocation does it mint a non-zero distinct reservation/context pair and exactly one in-memory
`ReservationSession`. A mint failure returns no continuation. It does not re-authenticate an
advertisement or re-resolve actor capability.

The pre-probe continuation has no clone, copy, debug, serialization, getter or decomposition API.
Dropping it is pre-dispatch cancellation by abandonment: there is no RPC, task, helper frame,
external state, rollback or journal write. This proves no full memory wipe for the reservation
session; only the separate route-authority ID arrays have an explicit zeroizing drop.

The previous scalar complete-path phase remains a dormant test boundary only and is not called or
trusted by the new plan. The existing private, dormant `RouteSetupTransaction` now has an internal
phase-B ownership split: `measure_owned` moves its exact session, hold and original verified probe
objects into a non-cloneable measured continuation, and `finish_owned` consumes that continuation
with the same reservation/context IDs and original absolute deadline. A measurement error returns
the original transaction for one rollback. Cancellation or deadline expiry at the handoff is
checked before a retirement slot or helper `Prepare`; finalization is signed once, after `Prepare`,
and ambiguous retries reuse that exact frame.

The dormant phase-B request prerequisite is flat, role-hint-free and affine. Each prospective entry
retains its explicit path ID plus one private actor-bound proof. The legacy bridge consumes the full
`Candidate` before request construction and the proof cross-binds the evidence batch, exact relay
node/Peer/key/advertisement sequence, actor and policy expiries, static selection scope, exact
advertisement payload hash, forwarded control/exit identities and only an observed `/24` or `/48`
prefix. The request and its
path/proof values have no `Clone`, `Debug` or serialization surface and retain no advertised control
endpoint, raw observed-origin IP, hostname, destination or full advertisement. The constructor
accepts only caller order `1..N`, never sorts or renumbers it, and requires 1-8 entries and at least
the policy minimum. Probe-slate size is independent of the final policy target: a UDP policy with
final counts `1/1/1` may probe several prospective paths and still finalize one.
`RouteSetupRequest` carries no per-path roles; phase B assigns final roles only after verified
probes.

One private, non-derived `UnmeasuredRouteSetup` owns the assembled transaction and its absolute
Tokio deadline. The legacy phase-B manager entry accepts only this wrapper; the separate dormant
C2c entry accepts `PreProbeContinuation` and produces the wrapper within its single task. Measurement
consumes the wrapper deadline without a replacement and passes the same value into
`MeasuredRouteSetup`. The sole assembly function takes the protocol and deadline together, rejects
a deadline beyond the setup-timeout budget, and permits an already-expired value only so the first
live check can fail before any protocol, transport, retirement or helper event. The old
resolving/generating transaction constructor and its product `ReservationSession` remint path are
removed.

Post-probe selection no longer treats the pre-probe active/warm labels as measurement authority.
Immediately before scoring, every proof is revalidated at the later trusted time against its exact
static scope, evidence batch and actor/policy windows. Complete-path measurements borrow the opaque,
value-only projection and enter the same private canonical selector core used by the legacy API;
there is no synthetic `Candidate`, advertisement or signature bit. Any eligible measured path may
satisfy the minimum. Paths beyond that minimum still require the canonical unique-throughput-gain
or meaningful-failover rule; warm backups are then taken only from the remaining bounded set.
Unknown or duplicate probe IDs fail before capacity filtering. On successful selection the request
proofs are consumed once and only proof-free selected relay bindings continue; a measurement error
returns the original transaction and all proofs for one rollback. The route-level protocol no
longer requires its probe type to implement `Clone`, and the private measured handoff has no
`Clone`, `Debug` or serialization implementation. This is an internal ownership property, not an
end-to-end affine claim about public reservation `Verified*` types; the public
`VerifiedRelayProbe` remains cloneable for API compatibility.

A dormant C2c adapter now consumes the C1 continuation inside one private manager task and watch.
It first rechecks cancellation, the carried Tokio deadline and trusted wall/evidence windows, then
recomputes the exact policy/advertisement/capability and per-actor evidence ceilings. It consumes
the existing authority and ordered actor-bound proofs into the endpoint-free `RouteSetupRequest`
without restoring role hints, sorting or renumbering paths. Request construction precedes one
bounded borrowed `RouteSetupAuthorities::resolve`; the same owned combined resolver/transport value
then moves into the later reservation phase, and the adapter accepts no second handle between
these phases. The resolve future borrows the request and owns neither the route authority nor the
reservation session.

After resolve, C2c rejects cancellation, deadline expiry, a backwards or expired wall clock, stale
proofs and any changed control/exit/relay capability, including its exact advertisement payload
hash. It then moves the same `ReservationSession`,
route/context IDs, limits, stable path IDs and absolute deadline into `UnmeasuredRouteSetup`, whose
existing phase-B flow carries them through measurement and finish without a remint or reset. A
pending resolve cancelled by the watch, a call timeout or dropping its handle drops the resolver
future before reservation dispatch and needs no rollback, helper cleanup or ownership-journal
entry. The dormant bridge now builds a `Candidate` whose legacy observed-origin field is `None` and
pairs it with the opaque normalized prefix before consuming both into a bounded projection. No full
host IP is reconstructed or retained; the existing local quality/history and advertised control
endpoint remain outside the projection and request.

This is still dormant infrastructure, not a production route. The private C2c entry has no
production caller, and the fake-only phase-A evidence has no production producer. A real evidence
producer, production probe verifier/handler and production-owned orchestration remain absent; tests
are the only callers. C1 construction itself still performs no RPC, helper call, provider update,
host/network mutation or ownership-journal write. C2c adds no new wire, provider or helper
implementation and has no production caller/orchestration, so it causes no production dispatch or
mutation. These fake-only prefix boundaries remain disconnected from A1a transport evidence.

A separate dormant lifecycle prerequisite now provides one private, affine route-attempt ownership
slot. It can retain either one already-running `RouteSetupHandle` or one `EstablishedRoute`; it
does not start a manager, spawn a task, mint authority, admit work before spawn or prevent a second
task from already having dispatched. An occupied slot returns the supplied second handle intact.
Pending settlement consumes the owner and yields an established owner on success. A settled
failure reported with cleanup `NotRequired` or `Destroyed` returns a vacant owner for explicit
reuse, whereas `Quarantined` remains terminal and rejects another adoption.

Settlement and drain both consume the owner, so cancelling either future cannot expose a reusable
vacant value. Pending drain cancels and waits; a completion race is immediately torn down instead
of published as established. Established drain tears down explicitly. Dropping a pending owner
delegates cancellation to the retained handle, while dropping an established owner passively
publishes its existing retirement ownership. The owner neither owns nor shuts down the route
manager: a future production lifecycle must drain it before manager shutdown. Tests are the only
callers and exercise first/last probe cancellation, late success, future drop, quarantine retry,
destroy-before-release ordering and shutdown fencing. Production admission, lifecycle ownership
and orchestration remain absent.

## Addressing and keys

The WireGuard crate derives a deterministic ULA prefix and four `/128` endpoint addresses from the
route-context/path IDs, and validates secret-free local endpoint capabilities. It does **not**
generate or expose private keys. The helper-v3 worker contract requires each ephemeral WireGuard
private key to be generated and retained only inside the route namespace worker; the unprivileged
agent receives an opaque lease handle plus the kernel-proven public key and public UDP endpoint.
Interface names are derived, bounded to Linux's 15-character limit, and never accepted from the
agent. The production worker/kernel backend is still unavailable, so these contracts are not yet
evidence that a live tunnel exists. Keys must never be persisted and are destroyed with the worker
context.

## Privileged helper boundary

The helper accepts only the operations documented in [PROTOCOL.md](PROTOCOL.md). It must validate
Unix peer credentials, protocol version, fixed identifier/key/address sizes, enum values, numerical
ranges, ownership token, and lifecycle transition before invoking netlink or WireGuard UAPI.

Product code does not parse `ip`, `wg`, or `nft` command output. These tools are diagnostic/test aids
only. The helper must create network namespaces, addresses, policy routes, TPROXY and DNS
interception, kill-switch rules, WireGuard interfaces, and relay fences through kernel APIs.

## Relay fence

For one signed path, forwarding is permitted only between the derived client-facing and exit-facing
WireGuard interfaces, for the exact overlay prefix, within the reservation lifetime and rate limits.
Rules deny traffic to relay host addresses, unrelated overlay prefixes, other contexts, physical
interfaces, and NAT/Internet egress. Default input/forward behavior for that context is deny.

## Client interception and leak prevention

The target client namespace transparently intercepts TCP, UDP, and DNS, recovers the original
destination, excludes control-plane and tunnel packets to avoid loops, and marks traffic into a
reserved policy-routing table. The kill switch defaults on and allows only explicit control-plane
reachability and authenticated tunnel setup on physical interfaces. No protected DNS or user flow
may fall back to the host route when the overlay fails.

## Lifecycle and cleanup

Setup is transactional. The owned route-ticket supervisor starts before the helper call and remains
responsible after its external waiter is cancelled. As soon as `Prepare` succeeds, it owns exact
`DestroyContext` authority; after an ambiguous Prepare write it instead owns the exact helper runtime,
context, original request ID/digest, and both expiries. This is the cancellation-safety boundary: a
crate-private HelperClient Prepare method has no other production call site, and polling it standalone
in future code would not be independently cancellation-safe. On rejection, expiry, cancellation,
received backend `Unavailable`, or kernel failure, the helper must Destroy or prove
absence of every owned local object before the coordinator releases endpoint leases or reservation
state. A failed or ambiguous cleanup keeps authority quarantined for retry; it is never discarded
because a remote grant expired.

At the half-open setup boundary (`now >= setup expiry`), retirement reconnects, sends read-only
`BindHelperRuntime(None)`, and compares the retained per-process runtime ID before tag 28. Runtime
mismatch sends no reconciliation request and remains quarantined. A matching tag 28 targets only the
exact server-owned lineage/generation, re-evaluates every retry rather than replaying a generic cache
entry, and releases remote state only after the complete authority is echoed and absence is proven.
Missing evidence, Activated/Committed state, unrelated state, or incomplete cleanup never counts as
absence. Exact `Absent` tombstones remain in a 1024-entry runtime-lifetime ledger because no ACK
protocol exists. Tag 28 itself retries exact Pending/Owned cleanup; tag 29 is an independent
process-wide cleanup operation, neither part of route reconciliation nor an ACK.

Cleanup is idempotent and scoped by context/runtime ownership. It removes MP paths before
interfaces, rules/routes before namespaces, temporary keys and sockets, and finally the ownership
record. It must tolerate missing objects and retry partial kernel failures without touching objects
outside its namespace/name/ID ranges. Context expiry prevents new flow admission but never removes
the supervisor's cleanup duty.

Explicit cleanup must show a secret-safe preview. Root-requiring test scripts must print exact
namespace/interface/table operations, ask before execution where appropriate, trap signals, and
compare host routes, DNS, and firewall before/after. No development command may experiment on the
active host network.

## Current evidence boundary

The v4 wire types, service state machines, forwarding codecs, helper plan/call/commit supervisor, and
authorization binding have unprivileged tests. They are not proof of a live route. The production
two-leg probe producer does not exist. The actor-linearized candidate snapshot and staged preflight
described above are dormant and report no production-usable candidates. Helper `Prepare`
deliberately returns `Unavailable`, and the production manager does not call the helper-backed
transaction. A dormant boot-scoped,
secret-free canonical/CAS ownership store exists and any exact main/lock/next object blocks helper
startup before token/socket mutation, but no production writer, recovery backend, restart reaper,
or cross-runtime tag-28 proof uses it. Tag 35 now carries the exact canonical closed Prepare plan
needed by that store, but the conversion is dormant and performs no journal write; journal absence
is not cleanup proof. Client ingress is also
blocked. Consequently
no production path can reach finalize, `Activate`, or `Commit`, and kernel configuration,
Destroy-first cleanup, A12/A13 privacy, MPTCP, and MPQUIC remain unproved. See
[IMPLEMENTATION_STATUS.md](IMPLEMENTATION_STATUS.md).
