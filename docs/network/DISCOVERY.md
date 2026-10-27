# Decentralised discovery

Discovery answers **“which peers might be useful?”**, not **“which peers may be trusted?”**.
It finds possible relay and exit services; signed advertisements, policy checks and real
path measurements decide whether a candidate can become part of a route. No participant
needs a central catalogue of every node.

## How a node finds a usable path

1. **Find contacts.** Remembered peers, local discovery and replaceable bootstrap contacts
   provide entry points. A contact is an introduction, not an authority.
2. **Find a relay.** The distributed index points to peers advertising relay capability.
   The client retrieves a signed advertisement and chooses a control relay.
3. **Find an exit without contacting it directly.** The control relay obtains candidate
   exit advertisements on the client's behalf. Their signatures are checked end to end.
4. **Check the candidates.** Advertisements must be current and policy-compatible; peers
   must meet identity and network-diversity requirements. Advertising capacity is not
   proof that a usable tunnel exists.
5. **Hand over to route setup.** Reservations, controlled probes and helper-owned network
   preparation establish the actual path. Discovery alone does not authorize traffic;
   see [route setup](ROUTING.md#control-plane-and-setup-transaction).

An **advertisement** is a signed, short-lived description of a peer's services. A
**capability index** is a lookup hint for finding those advertisements. A **control relay**
forwards setup messages toward an exit; a **datapath relay** carries the protected traffic.
These roles are related, but one does not automatically grant the other.

## Current evidence boundary

The [source-bound v1 checkpoint](../IMPLEMENTATION_STATUS.md#current-live-integration-checkpoint)
records all A01--A15 passing on the unchanged `482e33d0` build. That includes the real
probe/helper/agent/ingress chain; it is not a claim that every later extension or current
deployment has passed the same acceptance sequence.

The protocol and privacy rules below explain the design. The
[historical development record](#historical-discovery-development) preserves earlier
control-plane and preselection milestones, including their then-missing production
callers. Its words “now”, “dormant” and “remain absent” describe those stages, not today's
overall implementation status. For current work and unresolved integration, use
[IMPLEMENTATION_STATUS.md](../IMPLEMENTATION_STATUS.md).

## Protocol composition

The control plane uses rust-libp2p. The discovery crate composes:

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
  response and control Relay-signed prefix wrapper. The discovery actor separately owns the
  client-side snapshot, native-agnostic sampling, sequential request/bind, exact transport join,
  and opaque prepared-evidence handoff;
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
actually available. Installation leaves all participation roles off. A consuming node must
contribute according to its available capabilities; client-only consumption is not a production
mode. An inactive node does not publish invented service capacity.

## Historical discovery development

Earlier control-plane, preselection and native-handoff stages are preserved in the
[source-bound development archive](../archive/network-architecture-notes-20261026.txt). They are not a second discovery
procedure or current completion claim. The active contract above and
[current status](../IMPLEMENTATION_STATUS.md) govern new work.
