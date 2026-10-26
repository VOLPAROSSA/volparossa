# VOLPAROSSA native MPQUIC boundary

This directory contains a bounded process boundary around exact, locally
patched mqvpn/xquic source. The build produces a real `volparossa-mpquic`
executable and links the pinned libraries from source. Native API version 7
provides bounded request-driven bidirectional datagrams, per-route
credentials and TLS server names, an independent local association identifier,
explicit multipath and single-path modes, descriptor-only path adoption, and a
fail-closed descriptor-bound exit-listener contract. It retains the v6 binding of
every operational request to a native-generated process incarnation,
correlates responses to the exact canonical request digest, carries the
fields derived from the exit-signed route scope without verifying that
signature itself. The client adapter retains a strictly validated
tunnel assignment, exposes it only after `ESTABLISHED`, and enforces packet
address ownership. API v7 adds an explicit per-path acknowledged-transport byte counter;
v6 binaries fail preflight rather than silently presenting an unavailable metric as zero.
This boundary's metrics alone do not prove an end-to-end VOLPAROSSA datapath.
Current source-bound network evidence is recorded in
[`IMPLEMENTATION_STATUS.md`](../../docs/IMPLEMENTATION_STATUS.md); unique inner-payload
delivery is not inferred from acknowledged transport counters.

## What is implemented and tested

- An allocation-free, strict decoder for native API version 7 requests and a
  bounded request/response encoder compatible with the `volparossa-quic`
  messages. Versions 1 through 6 and unknown versions are rejected. Canonical field
  order and minimal varints are required.
- A fixed 32-byte descriptor-binding record followed by a four-byte big-endian
  frame boundary capped at 1 MiB before allocation. Each control-socket contact
  carries exactly one request and must half-close its write side before dispatch.
- Exact field-length, operation, path-count, address, local/remote port,
  reservation-hash, nonzero nonce, nonzero 62-bit association identifier,
  transport-mode, and complete inner IPv4/IPv6 datagram validation. `AddPath`
  itself accepts only the fixed IPv6 VOLPAROSSA overlay prefix, its path ID in
  address segment six, one shared `/112`, client host `1`, and exit host `4`.
- Rejection of unknown fields, duplicate fields, malformed varints,
  unsupported versions, ambiguous operations, zero-length frames, and
  excessive requests.
- A regular pathname `AF_UNIX`/`SOCK_STREAM` endpoint. Every parent directory
  is traversed without following symlinks; the immediate parent must be owned
  by the effective user and mode `0700`. The socket must remain owned by that
  user, mode `0600`, and single-linked. Cleanup unlinks only the exact
  device/inode created by this process.
- Per-connection `SO_PEERCRED` checks, a total monotonic timeout starting at
  the first binding byte, and bounded engine pumping while idle or blocked.
  Every read crosses an audited `recvmsg` boundary; truncated payload/control,
  unexpected ancillary data, trailing bytes, incomplete frames, missing EOF,
  and a second request all fail closed. Tests force both `MSG_TRUNC` and
  `MSG_CTRUNC` through that production receive path and verify that any
  installed descriptor is closed.
- `StartSession` carries an exact 43-character base64url credential, an exact DNS TLS
  server name of at most 253 bytes, and an absolute expiry no more than fifteen
  minutes ahead. They are deep-copied into only that route session, compared
  without secret-length timing shortcuts, and wiped on retirement. The daemon
  accepts no static product credential or TLS name through argv, environment,
  or a pathname. This boundary check proves credential syntax and length, not
  generator entropy. Native recomputes the existing domain-separated v4
  SHA-256 bearer commitment and compares it in constant time to the signed
  request field; an arbitrary bearer/commitment pairing is rejected.
- Before publishing its socket, each process obtains a nonzero 32-byte
  incarnation from Linux `getrandom()`. `Preflight` returns that incarnation
  and the explicit client/exit role. Every later request targets it exactly,
  every response repeats it, and stale process authority receives the typed
  `StaleInstance` result. This is channel-bound process-incarnation identity,
  not executable measurement, binary attestation, or authentication against an
  untrusted same-UID agent.
- Every decodable response carries SHA-256 over
  `VOLPAROSSA-MPQUIC-REQUEST-V7\0`, the four-byte canonical request length,
  and the exact unframed request. Nonces, request hashes, role, and incarnation
  therefore form one response-correlation contract.
- A bounded runtime of 32 sessions and eight paths per session. `StartSession`
  is idempotent only for byte-identical requests, remains pending until the
  tunnel and requested active-path count are real, and otherwise reports
  insufficient paths.
- Authorization admission samples `CLOCK_BOOTTIME` before `CLOCK_REALTIME`,
  advances a monotone effective wall-clock floor, and converts the accepted
  remaining lifetime once to a BOOTTIME deadline. Runtime checks thereafter
  use only BOOTTIME; clock failure, regression, and overflow fail closed. A
  fixed 128-record process-local ledger with no live eviction rejects exact
  reservation/finalize pair replay and one-ID scope collisions. Exact client
  retries are allowed only while their byte-identical session remains live;
  stop, expiry, and valid exit attempts leave tombstones until the deadline.
  This ledger neither verifies signed scope nor caches general request nonces,
  and it is erased on process restart.
- Explicit `MultipathQuic` and `SinglePathGeneralUdp` modes. Multipath requires
  at least two active paths; single-path permits exactly one. Shape mismatches
  are rejected without downgrade.
- A nonzero association identifier carried on every send/receive request and
  validated against the active session at the mqvpn adapter boundary. This is
  local association correlation: RFC 9484 IP Datagram wire encoding still
  uses its standards-required zero Context ID.
- Request-driven `ReceiveDatagram` polling; there is no asynchronous native
  push channel. The mqvpn callback copies complete inner datagrams into a
  fixed per-session FIFO capped at eight packets, 256 KiB total, and 65,535
  bytes per packet. Overflow deterministically wipes the queue and becomes a
  sticky `QueueOverflow` result rather than silently dropping or reordering
  data. Consumed and retired entries are wiped.
- Real mqvpn client session and path lifecycle using only the one UDP descriptor
  consumed by `AddPath`; native code never opens or binds a path socket and does
  not trust an agent-supplied interface. Rust validates UDP type/protocol,
  bound local tuple, unconnected state, nonblocking mode, close-on-exec, and
  overlay shape before transfer. Native repeats the socket, tuple, and overlay
  checks, connects the exact exit tuple, and requires one nonzero namespace
  cookie consistently across a session. A matching cookie proves only session
  namespace consistency, not that the helper created the descriptor.
- `AddPath` and `StartExitSession` each transfer exactly one descriptor only
  with a 32-byte SHA-256 binding over their separate API-v7 domains,
  `VOLPAROSSA-MPQUIC-ADD-PATH-FD-V7` and
  `VOLPAROSSA-MPQUIC-START-EXIT-FD-V7`, plus canonical request length and
  canonical request. Every other operation requires the all-zero binding and
  zero descriptors. The fixed binding prefix may be fragmented by `SOCK_STREAM`
  and is assembled safely; missing, extra, incomplete, truncated, late,
  cross-domain, or wrongly bound descriptors are rejected and closed on every
  path.
- `StartExitSession` supports both explicit transport modes and carries its
  nonzero SPKI pin, DNS TLS name, exact exit-listener/expected-client overlay tuples,
  reservation hash and bounded in-memory certificate/private-key PEM (64 KiB/16 KiB).
  Rust and C validate a pre-bound, unconnected, nonblocking, close-on-exec, IPv6-only
  UDP descriptor without address/port reuse. The real exit backend adopts the exact
  listener; failures close owned descriptors without host binding or secret-path
  fallback. Repeated listeners must match the live session's immutable parameters;
  collisions, stale/replayed authority and path-capacity overflow fail closed.
- Focused upstream patches enforce the caller-supplied leaf-SPKI SHA-256 pin
  on every handshake, pass explicit local/remote tuples to xquic, expose real
  RTT, congestion-window, bytes-in-flight, loss, rate, and ACKed-transport
  counters with validity flags, preserve the server session ID on every
  client-originated inner packet, and add a bounded in-memory server PEM
  identity API. Linux server startup imports that identity through sealed
  anonymous memfds, closes them immediately after synchronous xquic engine
  initialization, and wipes copied identity and credential material on
  replacement, retirement, initialization, and destruction.
- Parser, server, runtime, and socket-lifecycle unit tests, an optional
  libFuzzer harness, strict compiler warnings, ASan/UBSan build options, and
  Valgrind-compatible test binaries.

There is no mock production dispatcher and no ordinary-QUIC fallback.
`SendDatagram` and request-driven reverse polling cross the real mqvpn adapter
for an active client session. `GetStatus` returns the exact current client path
set only when every path has a valid native state and complete RTT, loss,
congestion-window, in-flight, estimated-rate, and ACKed-transport metrics.
`data_carrying` means that xquic has ACKed transport bytes on that path;
`acked_transport_bytes` (native path tag 9) exposes that actual cumulative counter. Health
and warm-path probes use its fresh deltas, rejecting regressions for an unchanged path.
`delivered_bytes` remains zero because that counter is not unique inner
payload delivery. The ACK counter includes QUIC framing and possible retransmissions;
complete application hashes and independent path captures remain separate acceptance gates.

## Tunnel assignment

Rust and C accept only server IPv4 `10.76.0.1/32` and client IPv4
`10.76.0.2` through `10.76.0.254`, each with prefix `/32`. MTU is 1280–1420.
Optional client IPv6 is `fd76:6f6c:7062::2` through `fd76:6f6c:7062::fe`,
with prefix `/112`; absent IPv6 requires prefix zero (and zero address storage
in the C representation). The adapter exposes the assignment only after
`ESTABLISHED`, rejects mutation for the session, and binds outbound inner source
and reverse inner destination to the assigned address. Assignment shape is not
independent route/helper authority.

## Executable contract

The daemon has an explicit role and a narrow argument surface:

~~~text
volparossa-mpquic --api-version
volparossa-mpquic --mode client --socket ABSOLUTE_PATH
volparossa-mpquic --mode exit --socket ABSOLUTE_PATH
~~~

`--api-version` is a side-effect-free offline probe: it writes exactly `7\n`
and opens no socket or runtime. The control socket path must satisfy the
ownership and mode checks above. Authentication and the TLS server name arrive
only in bounded API-v7 route-session messages. Client and exit roles are
separate process modes; a node enabling both needs two separately
orchestrated instances and control sockets.

Exit mode accepts role-specific `StartExitSession` requests and descriptor-bound
listeners through the real mqvpn server backend. Request admission, process-local
replay, session matching, listener adoption and cleanup are in
[`runtime.c`](src/runtime.c); server configuration, namespace-cookie checks and
packet callbacks are in [`mqvpn_backend.c`](src/mqvpn_backend.c). The
[authority boundary](#authority-and-acceptance) remains separate from those checks.

## Locked upstream source

`third_party/upstream.lock.json` pins full commits and Git trees:

| Component | Exact commit | Upstream license |
|---|---|---|
| mqvpn 0.15.1 | `607c0df921e2c23bae8bea21cb3c6f2acb2db275` | Apache-2.0 plus NOTICE |
| xquic | `6957ccf9b9fcb9ab62c43672638876abe47162dc` | Apache-2.0 |
| lwIP | `821af1994c4dbaf1e2cba9a7c2207303b3e5327b` | BSD-3-Clause |
| BoringSSL | `fd490c05de684d4cf135388023acf9aabb4e54f1` | Apache-2.0 for linked `libcrypto`/`libssl`; BSD-3-Clause only for unlinked Go TLS test support |
| Wintun userspace header | bundled by the locked mqvpn tree; file hashes are in the lock | GPL-2.0 OR MIT; mqvpn selects MIT |

The pinned BoringSSL `LICENSE` SHA-256 remains
`827c8d8fc207c2392794eef9e00fe246f9f61fdcc132556c275be3dd8c3cd97f`.
Ancestor commit `33d1049b1f730d2725bb09b2256fd5fe4c46b17e` changed the project license
to Apache-2.0. The trailing BSD-3-Clause notice covers Go TLS test support
that is not included in linked `libcrypto` or `libssl`. This records
provenance and is not legal advice.

The two reviewed source patches are also content-addressed:

| Target | Patch | SHA-256 |
|---|---|---|
| mqvpn | `patches/volparossa-mqvpn.patch` | `4ce314d8eb539dc362359f7fb901b6a76c827126b3c7091ee9b04528f556dd34` |
| xquic | `patches/volparossa-xquic.patch` | `52b1a30297fb4793067f00b6695dcdfdfba25d684ae45fdda37dc61bed6f13f9` |

Path loss exported to the API7 runtime is the saturating 64-bit count of actual xquic
loss declarations, including unreliable DATAGRAMs. It is not the older retransmission
counter, which can remain zero when those datagrams are dropped without repair.
`volparossa_xquic_detected_loss` tests the actual detector and exported connection stats;
ACKed transport bytes remain distinct from unique application bytes. This correction
alone does not prove successful live adaptive path growth.

Fetch source explicitly, then verify and build it:

~~~sh
native/volparossa-mpquic/scripts/fetch-upstream.sh --yes
native/volparossa-mpquic/scripts/verify-upstream.sh
native/volparossa-mpquic/scripts/build-upstream.sh
~~~

The fetcher writes only under ignored `third_party/src/`. The verifier checks
each commit, tree, origin, tag, parent gitlink, tracked-worktree cleanliness,
verbatim license/NOTICE copy, local patch hash, and the exact Wintun header,
license, and README hashes. The builder exports every locked tree with
`git archive` into an ignored staging directory, verifies and applies both
patches there, and performs no network access. The locked repositories remain
immutable.

Wintun is an upstream Windows-only source header under mqvpn. It is never
compiled or linked by the Debian target. No Wintun DLL is bundled, downloaded,
or loaded at runtime.

The host build requires CMake, Make, C/C++ compilers, `pkg-config`,
`libevent-dev`, and the other repository build dependencies. It runs the
patched upstream tests followed by the nine bounded native tests and writes
the executable to:

~~~text
native/volparossa-mpquic/build/volparossa-mpquic
~~~

The CMake install target places a mode-`0755`, byte-identical copy at
`libexec/volparossa/volparossa-mpquic` below the selected prefix. mqvpn,
xquic, lwIP, and BoringSSL are linked statically. The Debian runtime
`DT_NEEDED` set is limited to `libm.so.6`, `libstdc++.so.6`,
`libgcc_s.so.1`, and `libc.so.6`. Packaging must use this native artifact
instead of looking under Cargo's `target/release/`.

Passing these unit tests is necessary, but it does not prove the VOLPAROSSA
datapath.

## Local boundary build

Run build and sanitizer commands only in the approved disposable build environment;
they are not permission to install tooling or change the development host.

~~~sh
cmake -S native/volparossa-mpquic -B /tmp/volparossa-mpquic-build \
  -DCMAKE_BUILD_TYPE=Debug -DBUILD_TESTING=ON
cmake --build /tmp/volparossa-mpquic-build
ctest --test-dir /tmp/volparossa-mpquic-build --output-on-failure
~~~

## Full pinned-graph sanitizer build

Run the reproducible, network-free ASan+UBSan build with:

~~~sh
just native-sanitize
~~~

The recipe starts with `verify-upstream.sh`, then creates the same
`git archive` exports and applies the same content-addressed patches as the
release builder. It compiles and links BoringSSL, xquic, mqvpn/lwIP, the
VOLPAROSSA wrapper, and the daemon with exactly
`-fsanitize=address,undefined -fno-omit-frame-pointer`. All output stays in
the ignored, separate
`native/volparossa-mpquic/build/sanitized-upstream/` tree.

The recipe audits every C/C++ compile command and executable/shared-library
link command, checks sanitizer references in each production archive, runs
the mqvpn/lwIP suite with exactly 35 tests and the wrapper suite with exactly
9 tests, and performs sanitized daemon lifecycle smoke tests for both SIGINT
and SIGTERM. Each shutdown is bounded by a five-second watchdog and must exit
zero and remove the exact Unix socket it created.
`ASAN_OPTIONS` and `UBSAN_OPTIONS` halt on the first finding; leak detection
is enabled. It performs no downloads and does not change host networking.

BoringSSL and xquic are exercised through their sanitized production
archives, the mqvpn integration suite, and the sanitized daemon. This recipe
does not claim the separate BoringSSL Go suite or xquic CUnit suite, and it
does not constitute namespace dataplane acceptance.

The libFuzzer target additionally requires Clang and
`-DVMP_BUILD_FUZZER=ON`.

<a id="resolved-seams-and-mandatory-write-stop-gates"></a>

## Upstream integration contracts

The locked mqvpn/xquic revisions genuinely implement RFC 9484 CONNECT-IP,
QUIC DATAGRAM, and draft-ietf-quic-multipath-21 path creation. The local
patches close ten concrete integration seams:

1. A caller-supplied leaf-SPKI SHA-256 pin is mandatory and checked on every
   handshake. Chain-validation hard failures remain hard failures; only the
   explicitly permitted self-signed/unknown-issuer case is eligible for the
   pin override.
2. Every path creation carries the exact local and peer socket tuple into
   xquic instead of silently inheriting a connection-wide peer address.
3. mqvpn exposes real path measurements and labels ACKed transport bytes
   honestly.
4. Server delivery of a client-originated inner packet includes the same
   stable session ID used by connect and disconnect callbacks; legacy
   server-generated packets remain on the uncorrelated callback.
5. Replaced and retired auth keys, TLS names, user slots, client/server
   handles, and temporary SPKI buffers are explicitly wiped.
6. The server-only mqvpn config accepts bounded in-memory PEM identity. Linux
   snapshots it into sealed anonymous memfds solely for synchronous xquic
   engine initialization, closes the descriptors immediately afterwards, and
   wipes both copied PEM buffers. No caller-supplied certificate or private-key
   pathname is required.
7. Server `multipath=false` is honoured without an implicit enable override.
8. Every app-accepted, pre-H3 server QUIC connection consumes one bounded
   `MaxClients` slot before mqvpn's per-connection context allocation and H3
   authentication, and releases it exactly once across refusal, failure,
   close, and destroy paths. xquic has already allocated its transport/TLS
   connection state when this application callback runs.
   The upstream patch deliberately does not hard-code VOLPAROSSA's product
   `MaxClients=1` policy; applying that value remains a wrapper/runtime
   configuration non-goal for this upstream hardening patch.
9. A dedicated server socket API pins one canonical caller-supplied UDP peer.
   Off-peer ingress is rejected before xquic; egress tuple mismatches fail and
   every send uses only the retained peer. The legacy unpinned API remains an
   upstream compatibility surface and is not sufficient for VOLPAROSSA.
10. Each H3 connection has one monotonic, lifetime-affine CONNECT-IP claim.
    Concurrent and sequential duplicates receive 409 and cannot parse owner
    capsules or inject through another stream's Datagram quarter-stream ID.
    Request close, H3 close, refusal, and defensive destroy share idempotent
    session-table, address, callback, and admission cleanup.

## Authority and acceptance

The current runtime has client and exit backends. `dispatch_start_exit` validates
role, descriptor, route shape, credential commitment, admission time and process-local
pair replay before creating the real transport and adopting its listener. The mqvpn
exit backend configures the fixed IPv4/IPv6 pools, one client, route identity/auth,
explicit transport mode and scheduler. It checks listener tuples and nonzero consistent
`SO_NETNS_COOKIE`; it opens no replacement host listener.

These implementation boundaries do not collapse the following distinct claims:

- A same-UID socket, request digest and process incarnation correlate a contact;
  they are not binary attestation or independent proof of helper-origin authority.
  Socket shape and namespace consistency alone do not prove the helper created it.
- Native's bounded, process-local pair ledger is not independent signature verification
  of the complete reservation bundle and does not survive process restart. Production
  admission belongs to the signed route/helper orchestration contract in
  [the helper specification](../../docs/architecture/HELPER_V3.md).
- `acked_transport_bytes` and `data_carrying` describe transport activity, not unique
  inner payload. Inner hashes, independent path counters and privacy/cleanup captures
  remain necessary for the requested source and mode.
- The original unchanged `482e33d0` topology passes A01–A15, as recorded in
  [implementation status](../../docs/IMPLEMENTATION_STATUS.md#network-baseline-and-remaining-proof).
  That result does not qualify an arbitrary newer build, arbitrary NAT/radio topology
  or later adaptive-growth feature. Review the exact source and acceptance scenario.

The superseded API-v6 foundation and blocker narrative is retained in the
[historical excerpt](../../docs/archive/implementation-notes-20261026.txt).
It must not be read as a claim that the current exit backend is dormant.

## Policy boundary

The native process accepts complete inner IP datagrams only within an admitted
route session. It is not the whitelist authority and must not infer
authorization from packet shape. The Rust policy/traffic layer must validate
the flow, including QUIC Initial/TLS ClientHello SNI and ECH rules where
required, before forwarding; the exit must independently enforce the same
signed manifest and pinned destination tuple. The native parser's packet
checks are defence in depth, not a policy decision.
