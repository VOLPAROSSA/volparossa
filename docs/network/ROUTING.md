# Route contexts, WireGuard, and privileged routing

A route is a temporary, authorized way to carry application traffic through the network.
The client chooses an exit and reaches it through a relay, never directly. Several such
paths can work in parallel, with a different relay on each path.

A **route context** keeps related flows and their permissions together. A **path** is one
`client -> relay -> exit` connection within that context. Its **two legs** are two separate
WireGuard links; they do not mean two parallel paths. The payload remains protected
between client and exit even though the relay terminates the WireGuard links.

A route context is scoped by local profile, registrable domain/origin, transport class, and policy
version. Existing flows never migrate to a new exit. Context expiry affects admission of new flows;
LRU eviction drains and removes all associated interfaces, routes, MPTCP/MPQUIC paths, and firewall
state.

## Route setup at a glance

- **Discover and choose:** obtain verified candidates without directly contacting the exit.
- **Reserve and measure:** obtain permission for candidate paths, probe both legs and select
  the paths that meet the policy.
- **Prepare and authorize:** the privileged helper prepares local resources; the exit and
  selected relays supply matching grants and confirmations.
- **Activate and carry traffic:** only the fully authorized route may carry application data.
- **Retire and clean up:** cancellation, expiry and failure retain an owner until the helper
  has confirmed removal of the resources.

The **control relay** carries exit-facing setup messages. The **datapath relay** carries
traffic on a selected path. One node may perform both roles only after separately meeting
the requirements for each. The detailed transaction below makes those checks explicit.

## Current evidence boundary

The [source-bound v1 checkpoint](../IMPLEMENTATION_STATUS.md#current-live-integration-checkpoint)
records the unchanged `482e33d0` build passing A01--A15, including the real routing chain,
privacy captures and crash cleanup. This is scoped functional evidence, not a release
security audit or completion of every later extension.

Earlier helper-only and dormant-planner stages are archived below; their old score
and missing-caller claims do not describe the accepted later route. Current progress
and remaining failures belong in [IMPLEMENTATION_STATUS.md](../IMPLEMENTATION_STATUS.md).

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
9. Only after all receipts exist, call helper `Activate` and then `Commit`; each fresh phase stream
   must first bind and verify the exact helper runtime retained by the affine Prepare owner.
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

Earlier staged implementation notes are retained in the
[development archive](../archive/network-architecture-notes-20261026.txt); they do not add a second route-setup procedure.

## Addressing and keys

The WireGuard crate derives a deterministic ULA prefix and four `/128` endpoint addresses from the
route-context/path IDs, and validates secret-free local endpoint capabilities. It does **not**
generate or expose private keys. The helper-v3 worker contract requires each ephemeral WireGuard
private key to be generated and retained only inside the route namespace worker; the unprivileged
agent receives an opaque lease handle plus the kernel-proven public key and public UDP endpoint.
Interface names are derived, bounded to Linux's 15-character limit, and never accepted from the
agent.

Earlier staged implementation notes are retained in the
[development archive](../archive/network-architecture-notes-20261026.txt); they do not add a second route-setup procedure.

## Privileged helper boundary

The helper accepts only the operations documented in [PROTOCOL.md](../architecture/PROTOCOL.md). It must validate
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
The early single-path helper proof implemented this fence with two direction rules bound to
the derived interface indices and `/128` peers, one singleton kernel-timeout lease, one realtime
cutoff and a terminal drop. That helper-only milestone did not by itself prove a complete route;
its original receipts are retained in the historical records below.

## Client interception and leak prevention

The target client namespace transparently intercepts TCP, UDP, and DNS, recovers the original
destination, excludes control-plane and tunnel packets to avoid loops, and marks traffic into a
reserved policy-routing table. The kill switch defaults on and allows only explicit control-plane
reachability and authenticated tunnel setup on physical interfaces. No protected DNS or user flow
may fall back to the host route when the overlay fails.

## Lifecycle and cleanup

Cleanup is part of owning a route, not an optional step after a successful request.
A caller disappearing does not cancel the service's responsibility for the resources it
created. If removal cannot be confirmed, the state stays quarantined rather than being
reported as safely released.

The following technical contract explains how that ownership survives cancellation,
ambiguous replies and expiry.

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

Before any parent-side birth-link mutation, internal worker protocol v4 requires `Initialise` to
accept the same canonical role-complete Prepare plan and stage its exact child-namespace cleanup
set. If Prepare never adopts a moved birth link, Destroy must delete and prove that staged set absent
inside the still-pinned child namespace; `NotFound` is cleanup evidence only for a genuinely
pre-birth lineage. A response-lost durable `Initialise` moves to a cleanup-only phase without
killing the authenticated child. The next exact Destroy has a separate deadline and may reconcile
at most one fully correlated late `Initialise` response; it never replays `Initialise`, accepts no
foreign or duplicate record, and does not treat a lost Destroy response as cleanup evidence.

At the half-open setup boundary (`now >= setup expiry`), retirement reconnects, sends read-only
`BindHelperRuntime(None)`, and compares the retained per-process runtime ID before tag 28. Runtime
mismatch sends no reconciliation request and remains quarantined. A matching tag 28 targets only the
exact server-owned lineage/generation, re-evaluates every retry rather than replaying a generic cache
entry, and releases remote state only after the complete authority is echoed and absence is proven.
Missing evidence, Activated/Committed state, unrelated state, or incomplete cleanup never counts as
absence. Exact `Absent` tombstones remain in a 1024-entry runtime-lifetime ledger because no ACK
protocol exists. Tag 28 itself retries exact Pending/Owned cleanup; tag 29 is an independent
process-wide cleanup operation, neither part of route reconciliation nor an ACK.

An unpublished Handoff failure is stored under a fresh serial, exact context and optional durable
ownership selector. A later exact functional Destroy can take only that terminal. A definitive
no-worker outcome retires its Intent directly; a worker-bearing outcome first requires exact
generation reap and complete registry purge. Deadline or actor failure restores the same affine
proof and selector, mismatch takes nothing, and ambiguous admission remains retained. This path
cannot publish custody, open dispatch, send a child request or mutate network resources.

External requests carry Unix expiries. On the first accepted Bind/Prepare intent the helper freezes
matching process-local `CLOCK_BOOTTIME` setup and hard deadlines and carries them through the exact
engine/backend/worker lineage. Admission and post-backend commit require both clocks to remain within
their half-open windows, retries never refresh either deadline, and the reaper retires on either
boundary. The Relay fence combines the signed realtime cutoff with a conservative kernel-jiffies
timeout derived from the frozen hard deadline. Ordinary suspend and ordinary realtime rollback
therefore fail closed. Only an already-compromised host root able to both suspend the host and roll
`CLOCK_REALTIME` back sufficiently can leave a short post-resume race until serialized cleanup;
containment against such host-root compromise is outside this boundary. The KVM proof did not
exercise suspend/resume or realtime mutation.

Cleanup is idempotent and scoped by context/runtime ownership. It removes MP paths before
interfaces, rules/routes before namespaces, temporary keys and sockets, and finally the ownership
record. It must tolerate missing objects and retry partial kernel failures without touching objects
outside its namespace/name/ID ranges. Context expiry prevents new flow admission but never removes
the supervisor's cleanup duty.

Explicit cleanup must show a secret-safe preview. Root-requiring test scripts must print exact
namespace/interface/table operations, ask before execution where appropriate, trap signals, and
compare host routes, DNS, and firewall before/after. No development command may experiment on the
active host network.

## Historical helper-boundary evidence

Earlier staged implementation notes are retained in the
[development archive](../archive/network-architecture-notes-20261026.txt); they do not add a second route-setup procedure.
