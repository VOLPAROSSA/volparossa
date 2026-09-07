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
and all exit RPCs cross `/volparossa/exit-forward/4` and
`/volparossa/exit-forward-upstream/4`; the client never creates a direct exit control connection.
A directly retrieved v4 advertisement can establish relay/control-relay provenance only. A
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

Default VPN/control-plane storage must not persist:

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

## Planned content storage and sharing

The requested [content layer](CONTENT_NETWORK_PROPOSAL.md) adds a separate bounded storage
purpose; it does not turn ordinary routed traffic or logs into a browsing archive. Public
publication/shared-cache bytes can be visible to their holders. Chunk identifiers, queries,
replica placement and timing can reveal known content or interests even without a plaintext URL;
hashed URLs are not private discovery keys. Do not publish a durable user-to-content association.

Private messages must be encrypted for their recipient before replication, with separate
authorization, quotas and expiry. Ciphertext still exposes size, timing and availability, and
replication does not guarantee anonymity, delivery or deletion of every remote copy. Public
shareability requires its own evidence: missing cookies are insufficient, and encryption does
not authorize retaining a `no-store` response. Shared DNS objects retain validation and remaining
TTL, never query history or another user's private DNS view.

The current native-message library encrypts before storage and keeps recipient keys and returned
plaintext in zeroizing memory. Public manifest metadata still exposes sender, opaque name, size
and lifetime. It does not provide forward secrecy after recipient-key compromise, key discovery,
mailbox metadata privacy or delivery guarantees. Only an explicit disposable acceptance fixture
writes a temporary recipient key and known test plaintext; those files are private, excluded
from artifacts and explicitly cleaned up. This does not enable default browsing/message capture.

HTTPS adapters must preserve origin authentication, browser isolation, credentials and cache
semantics without an interception CA or TLS bypass. An optional HTTPS witness would introduce
explicit additional trust, not an automatic public/default service. These are design boundaries;
the scoped protected-route content proof is not automatic distributed discovery or a browser runtime.

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
dataplane path exists. Those captures and the real probe/helper/agent/ingress chain passed as part
of A01--A15 on unchanged `482e33d0`: the retained native/MPTCP capture windows were complete, with
zero socket drops, and cleanup left no owned objects and unchanged guest state. See the exact
run and artifact in [IMPLEMENTATION_STATUS.md](IMPLEMENTATION_STATUS.md). This establishes that
topology's result, not a guarantee against correlation or proof for later sharing/content changes.
Sensitive traffic should not rely on development builds as a release-security assurance.

## Operator guidance

Do not use real browsing data during development. Keep test domains and addresses reserved for the
namespace topology. Before sharing diagnostics, remove private multiaddresses, public IPs, peer IDs
when linkability matters, identity files, policy signatures, packet payloads, hostnames, and
destination addresses. Deleting `/var/lib/volparossa` destroys identity and peer history and is
irreversible; package removal intentionally preserves it unless the operator explicitly removes it.
