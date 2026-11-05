# MASQUE over genuine Multipath QUIC

Browser QUIC/HTTP/3 requires genuine Multipath QUIC. Multiple independent single-path QUIC
connections, connection migration, configured-but-idle paths, packet duplication, or simulated
telemetry do not satisfy this requirement.

## Required stack

The target native component is built from audited, exact revisions of `mp0rta/mqvpn` and its xquic
and other submodules. It carries original browser IP/QUIC datagrams with MASQUE CONNECT-IP and QUIC
DATAGRAM over one outer Multipath QUIC connection to the selected exit. At least two validated outer
paths bind to different selected WireGuard interface indexes/addresses, traverse different relays,
terminate at the same exit, and carry unique payload bytes.

Exact recursive upstream revisions and local patch hashes are pinned in
`third_party/upstream.lock.json`; verified source exports and build trees remain ignored rather than
vendored into Git. Provenance, licenses, patches, sanitizer evidence, and unresolved findings are
tracked in `THIRD_PARTY_LICENSES.md`. The API in `volparossa-quic` remains a process boundary, not
proof of a production transport datapath.

## Process API and containment

The active process API is version 7, canonical protobuf bounded to 1 MiB. It
preflights an exact immutable Client or Exit role and fresh process instance, then
correlates each typed request and any adopted descriptor by nonce, instance and
canonical-request digest. Older executables fail preflight without downgrade.

The [protocol reference](../architecture/PROTOCOL.md#agent-to-native-mpquic-api)
specifies allowed operations, field tags and descriptor domains; the
[native contract](../../native/volparossa-mpquic/README.md) specifies adoption,
TLS identity, replay, deadline, tunnel-assignment and backend behavior. Start fixes
SPKI/certificate digests, TLS name, MASQUE/route context, signed reservation/finalize
scope, bearer commitment, both native instances, path proofs, destination policy
and minimum-path count. Exact helper/namespace provenance and authority must precede
adoption; generic wire values or a same-UID socket are not independent attestation.
There is no free-form interface, path, command, configuration or mutable destination.

The integrated baseline has real Client and Exit transport execution, not a
client-only dormant-exit facade. Its source-bound A01–A15 result is indexed in
[implementation status](../IMPLEMENTATION_STATUS.md#current-live-integration-checkpoint).
This does not prove a release build, another composition, unique inner-byte accounting,
or every newer path-growth requirement. Original API6 limitations remain in the
[development archive](../archive/network-architecture-notes-20261026.txt).

## Scheduling

The swappable scheduler estimates delivery time per direction from smoothed RTT, queued bytes,
delivery rate, congestion window, bytes in flight, loss, and congestion/path state. It does not send
on blocked or unvalidated paths and chooses one eligible path for each datagram. Kernel/xquic
congestion control remains authoritative. v1 has no duplication, retransmission outside QUIC, FEC,
erasure coding, artificial equalization, or adaptive delay.

The production mqvpn client and exit configurations select the dedicated patched xquic
`volparossa_edt` callback only for Multipath QUIC. It uses current xquic RTT, bytes in flight,
bandwidth estimate, congestion window/headroom, sendability, and recent loss. The single-path
general-UDP mode remains on MinRTT and is not a fallback for required multipath.

Path-set validation requires 2–8 paths, distinct path IDs, relays, and interface indexes, the same
exit, and the configured maximum RTT spread. A path's `data_carrying` status becomes true only after
unique payload delivery, not after handshake alone.

## Classification and fail-closed behavior

UDP/443 is treated as candidate browser QUIC only after strict QUIC long-header/Initial parsing and
policy-verifiable hostname evidence. Parsing a public Initial header alone does not decrypt TLS or
prove SNI. Missing verification, ECH that hides required policy information, malformed/fragmented
input beyond bounds, a policy mismatch, or fewer than the required data-carrying paths fails closed.
Production defaults forbid degraded single-path fallback.

General UDP is a separate single-path MASQUE flow and must never be reported in MPQUIC metrics.

## Upstream intake gate

Before integration, record exact full commits and recursive submodule revisions; copy license and
NOTICE files; map the implemented Multipath QUIC draft to current peer interoperability; review
MASQUE CONNECT-IP/QUIC DATAGRAM behavior; build from source with warnings enabled; run upstream and
VOLPAROSSA interoperability tests; and run ASan/UBSan plus Valgrind. Local patches require a purpose,
upstream reference, and rebase procedure.

## Required evidence

Acceptance checks A06–A07 require a real browser/HTTP3 transfer whose native and independent packet
counters prove at least two relay paths carried unique bytes. Removing one relay must preserve the
inner QUIC flow where the protocol permits, without a direct route or single-path downgrade. CPU,
memory, bytes-in-flight, loss, failover time, and net-versus-tunnel bytes must be reported. Each implementation claim must bind that
evidence to its exact source; an older passing source does not qualify another build.
