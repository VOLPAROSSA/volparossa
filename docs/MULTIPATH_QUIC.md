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

The version-6, 1 MiB bounded Protocol Buffers API first preflights an exact client or exit process
role and a fresh instance per process start. Later operations target that instance and are
correlated by nonce plus an exact canonical-request digest. They are limited to starting/stopping a
client or exit context, adopting one request-bound UDP descriptor for a fixed path or exit listener,
adding/removing a fixed overlay path, sending/polling an already-authorized inner IP datagram, and
retrieving bounded status. There is no free-form interface name, pathname, command, configuration
text, or arbitrary destination. The current same-UID socket provides channel correlation, not
binary attestation or authentication against a compromised agent; separate client/exit service
identities and role sockets remain required.

The exit SPKI/certificate hashes, TLS name, MASQUE context, route context, signed reservation and
finalize IDs, bearer commitment, both native instances, path/reservation proof, destination policy,
and minimum-path count are fixed before native activation. Rust validates response identity,
request correlation, and bounded tunnel-assignment shape. No production caller or backend
assignment exists yet, and helper provenance, product-pool addresses, namespace ownership,
independent signed-bundle replay verification plus affine handoff, certificate/key consistency,
and byte-counter evidence remain fail-closed requirements. Native's process-local pair ledger and
BOOTTIME deadline do not replace that missing production authority.

## Scheduling

The swappable scheduler estimates delivery time per direction from smoothed RTT, queued bytes,
delivery rate, congestion window, bytes in flight, loss, and congestion/path state. It does not send
on blocked or unvalidated paths and chooses one eligible path for each datagram. Kernel/xquic
congestion control remains authoritative. v1 has no duplication, retransmission outside QUIC, FEC,
erasure coding, artificial equalization, or adaptive delay.

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
memory, bytes-in-flight, loss, failover time, and net-versus-tunnel bytes must be reported. Until that
evidence exists, MPQUIC is incomplete.
