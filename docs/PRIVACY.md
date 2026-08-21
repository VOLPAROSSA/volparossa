# Privacy design

VOLPAROSSA minimizes retained metadata; it does not promise anonymity against traffic correlation.
The required path separation changes which network participant directly sees which endpoint, while
low-latency timing and volume remain observable.

## Intended visibility

| Party | Sees | Does not need to see |
|---|---|---|
| Control relay | client's control connection/Peer ID, selected exit, operation class, bytes/timing | destination, payload, or a client identity forwarded to the exit |
| Datapath relay | client public endpoint, selected exit, ephemeral route/path, bytes/timing | Internet hostname or destination IP in the routed outer layer |
| Exit | control/datapath relay endpoints, ephemeral client-session ID, approved destination/DNS/SNI, bytes/timing | client public endpoint, permanent client node ID, or client Peer ID |
| Destination | exit public endpoint and normal application-layer disclosures | client and relay endpoints |
| Bootstrap/DHT peers | control-plane Peer ID, capability keys, reachable control addresses | browsing destinations or a global browsing catalogue |
| Local operator/root | potentially all local process and kernel state | no technical protection against hostile root is claimed |

The client chooses and authenticates a control relay before looking up an exit. Exit advertisements
and all exit RPCs cross `/volparossa/exit-forward/3` and
`/volparossa/exit-forward-upstream/3`; the client never creates a direct exit control connection.
A directly retrieved v3 advertisement can establish relay/control-relay provenance only. A
combined-role node may be an exit only when this client process learned its advertisement
exclusively through forwarding. Direct-then-forwarded provenance is rejected; forwarded-then-direct
provenance withdraws and quarantines exit capability for the advertisement lifetime, because the
direct connection created a client association.

The exit must be distinct by node ID and Peer ID from the control relay and every datapath relay in
that route. Each datapath uses one relay. The control relay may additionally be one datapath relay
only after its own permit, real probe, selection, and grant. Multiple paths expose the client's
endpoint to multiple selected relays, which is a reliability/throughput tradeoff. A relay and exit
may correlate observations if they collude. A global observer can correlate both ends.

## Data allowed at rest

The node's permanent identity is encrypted and its file mode is exactly `0600`. It signs the
node's own advertisements and anchors its libp2p Peer ID; it is not placed in client-session
reservation artifacts. The local peerstore may retain public Peer IDs, signed advertisements,
endpoints, reachability, aggregate path measurements, delivery history, uptime/failures, policy
hash, and last-success timestamps. Configuration stores operator choices and role/capacity limits.
Policy manifests store public allowlist and maintainer material.

By default VOLPAROSSA must not persist:

- URLs, DNS query history, payloads, full browsing hostnames, or destination-IP history;
- private session or WireGuard keys;
- a durable association between a permanent node identity and browsing activity;
- external analytics identifiers, account information, email addresses, or phone numbers.

Each route attempt generates a fresh Ed25519 session key and derived `client_session_id`. The exit
can verify that session's signed scope without receiving the client's permanent node ID, Peer ID, or
public address. Ephemeral route-context, flow, session, path, capability, hold, permit, grant, and
receipt state expires with its bounded context. Crash recovery may retain only the minimum opaque
ownership authority needed to safely destroy VOLPAROSSA-created network state; it must not convert
that authority into browsing history.

## Logs

The default is structured journald output, not files and not remote telemetry. Logs use stable reason
codes and may include ephemeral session/path IDs, protocol version, aggregate counters, and coarse
latency/failure data. They must redact private keys, passphrases, raw packet content, full hostnames,
URLs, DNS messages, destination addresses, policy secrets, signatures that enable unwanted linkage,
and upstream error strings containing these values.

File logging is not enabled by the packaged defaults; consequently no logrotate policy is installed.
An operator who explicitly adds file logging owns its retention, permissions, encryption, and
rotation policy and should keep retention short.

## Metrics

Metrics are local-only and distinguish net user bytes from physical tunnel bytes. Permitted metrics
are bounded aggregates such as peer counts, route contexts, reservation utilization, active and
data-carrying path counts, RTT/loss/rate buckets, setup/failover durations, policy version/hash, and
structured rejection counts. Labels must not contain hostnames, destination IPs, URLs, permanent
client-to-flow identifiers, or payload-derived values. There is no external telemetry endpoint.

## DNS and policy metadata

DNS for protected flows travels through the selected exit. The exit temporarily holds approved
answers to pin a flow and defend against rebinding. These records expire with the authorization and
are not browsing history. The client and exit necessarily handle a hostname long enough to select a
policy rule; durable storage is not necessary. Arbitrary external resolvers and physical-interface
DNS leaks must be blocked by the client namespace kill switch.

## Evidence boundary

The privacy separation is not established by signatures or diagrams. Acceptance A12 requires an
exit-namespace packet capture proving that only incoming relays are visible, and A13 requires
client-side packet capture plus route evidence proving that no direct client-exit control or
dataplane path exists. Those captures have not run. The real probe producer, helper backend, agent
route orchestration, and client ingress are also blocked, so no sensitive traffic should rely on
these properties yet.

## Operator guidance

Do not use real browsing data during development. Keep test domains and addresses reserved for the
namespace topology. Before sharing diagnostics, remove private multiaddresses, public IPs, peer IDs
when linkability matters, identity files, policy signatures, packet payloads, hostnames, and
destination addresses. Deleting `/var/lib/volparossa` destroys identity and peer history and is
irreversible; package removal intentionally preserves it unless the operator explicitly removes it.
