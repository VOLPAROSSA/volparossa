# VOLPAROSSA native MPQUIC boundary

This directory contains a bounded process boundary around exact, locally
patched mqvpn/xquic source. The build produces a real `volparossa-mpquic`
executable and links the pinned libraries from source. Native API version 5
provides bounded request-driven bidirectional datagrams, per-route
credentials and TLS server names, an independent local association identifier,
explicit multipath and single-path modes, descriptor-only path adoption, and a
fail-closed descriptor-bound single-path exit-listener contract.
It is still not a proven VOLPAROSSA dataplane: the exit lifecycle, exact scheduler, honest
unique-payload metric, trusted helper origin for path descriptors, and
disposable namespace acceptance remain incomplete and fail closed where
applicable.

## What is implemented and tested

- An allocation-free, strict decoder for native API version 5 requests and a
  bounded request/response encoder compatible with the `volparossa-quic`
  messages. Versions 1 through 4 and unknown versions are rejected. Canonical field
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
  generator entropy.
- A bounded runtime of 32 sessions and eight paths per session. `StartSession`
  is idempotent only for byte-identical requests, remains pending until the
  tunnel and requested active-path count are real, and otherwise reports
  insufficient paths.
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
  with a 32-byte SHA-256 binding over their separate API-v5 domains,
  `VOLPAROSSA-MPQUIC-ADD-PATH-FD-V5` and
  `VOLPAROSSA-MPQUIC-START-EXIT-FD-V5`, plus canonical request length and
  canonical request. Every other operation requires the all-zero binding and
  zero descriptors. The fixed binding prefix may be fragmented by `SOCK_STREAM`
  and is assembled safely; missing, extra, incomplete, truncated, late,
  cross-domain, or wrongly bound descriptors are rejected and closed on every
  path.
- `StartExitSession` is restricted to one `SinglePathGeneralUdp` route and
  carries its nonzero SPKI pin, DNS TLS name, exact exit-listener/expected-client
  overlay tuples, reservation hash, and bounded unparsed in-memory certificate/private-
  key candidate PEM (64 KiB/16 KiB). Rust requires the transferred descriptor to be a
  pre-bound, unconnected, nonblocking, close-on-exec, IPv6-only UDP socket
  without address/port reuse, and the dormant C runtime repeats those current
  socket and tuple checks. Neither proves helper origin, assigned-address state,
  or network namespace. The dormant native runtime closes it on every
  path and returns `exit_listener_orchestration_unavailable`; no host bind,
  pathname secret, or fallback exists.
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
for an active client session. `GetStatus` still fails closed rather than
relabeling ACKed QUIC transport bytes as uniquely delivered payload.

## Executable contract

The daemon has an explicit role and a narrow argument surface:

~~~text
volparossa-mpquic --api-version
volparossa-mpquic --mode client --socket ABSOLUTE_PATH
volparossa-mpquic --mode exit --socket ABSOLUTE_PATH
~~~

`--api-version` is a side-effect-free offline probe: it writes exactly `5\n`
and opens no socket or runtime. The control socket path must satisfy the
ownership and mode checks above. Authentication and the TLS server name arrive
only in bounded API-v5 route-session messages. Client and exit roles are
separate process modes; a node enabling both eventually needs two separately
orchestrated instances and control sockets.

Exit mode accepts only its role-specific `StartExitSession` shape, validates
its credential syntax, bounded identity metadata, exact overlay route and short authorization window,
and consumes exactly one inherited listener descriptor, but still returns
`exit_listener_orchestration_unavailable`. The native boundary has no reviewed
exit backend factory. It closes the supplied listener and never substitutes a
host-local listener, secret pathname, or fallback.
The dormant boundary does not yet parse the certificate, prove that its key
matches, or bind the leaf certificate to the supplied DNS name and SPKI pin;
those checks are mandatory before the future backend may report success.

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
| mqvpn | `patches/volparossa-mqvpn.patch` | `dfeffe71a9db187a700a078f0f9f427a57f7eb69bfae2ba1b974a556bd22719d` |
| xquic | `patches/volparossa-xquic.patch` | `acdb5af1a3ba452cfd49b46c80e99e49774db43e1130d032808d4e538772353b` |

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
patched upstream tests followed by the five bounded native tests and writes
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
the mqvpn/lwIP suite with exactly 33 tests and the wrapper suite with exactly
5 tests, and performs sanitized daemon lifecycle smoke tests for both SIGINT
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

## Resolved seams and mandatory WRITE-STOP gates

The locked mqvpn/xquic revisions genuinely implement RFC 9484 CONNECT-IP,
QUIC DATAGRAM, and draft-ietf-quic-multipath-21 path creation. The local
patches close six concrete integration seams:

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

API version 5 retains the bounded reverse/session contracts and adds a strict
single-path exit-listener handoff while preserving the earlier six
process-boundary seams:

1. Reverse datagrams use bounded, request-driven polling with deterministic
   overflow and explicit memory wiping; the native process never pushes an
   unsolicited frame.
2. A nonzero local association identifier is carried and validated through
   the mqvpn adapter boundary independently of route ID and request nonce.
   This identifier does not alter the RFC 9484 zero wire Context ID for IP
   Datagrams.
3. Multipath QUIC requires at least two paths while general UDP single-path
   requires exactly one; either mismatch fails without fallback.
4. Exact-length base64url client auth, TLS server name, and an
   at-most-fifteen-minute expiry are bound to one `StartSession`; no
   process-global product credential remains.
5. Versions 1 through 4, unknown versions, non-minimal varints, reordered fields,
   duplicate fields, and unknown fields fail closed.
6. `AddPath` consumes exactly one correlated UDP descriptor and native never
   opens or binds its own path socket. The descriptor and metadata are checked
   independently by Rust and C.
7. `StartExitSession` consumes exactly one separately domain-bound, listener-shaped
   descriptor, carries its exact overlay peer metadata and bounded unparsed TLS
   candidate material, and closes the descriptor before the intentionally dormant backend returns
   unavailable. Every remaining operation carries no descriptor.

The following gates remain hard blockers:

1. **No trusted helper-origin proof for path or listener descriptors.** SCM_RIGHTS,
   request hashes, strict private overlay shapes, and current socket checks prevent
   several substitutions, but an untrusted agent can still create a conforming
   socket. Only client `AddPath` checks a same-session namespace cookie; StartExit
   lacks exact namespace and assigned-address proof. Production adoption remains
   blocked until an affine helper-to-native capability binds each descriptor to
   the attested helper acquisition.
2. **No unique payload-delivery metric.** xquic's counter includes QUIC
   transport overhead and retransmission. It cannot satisfy
   `NativePathStatus.delivered_bytes`, which promises uniquely delivered
   payload. `GetStatus` returns `unique_delivery_metric_unsupported`.
3. **No operational exit lifecycle.** The patched mqvpn server can report a
   session-correlated inbound packet and can initialize xquic from bounded
   in-memory TLS candidate material without a caller-supplied secret pathname.
   The native backend remains client-only, and the helper/agent does not yet provide the
   end-to-end listener provenance/handoff to a reviewed exit factory. API v5
   accepts and closes the descriptor and carries the TLS material in memory,
   but does not yet bind it cryptographically to the certificate key, DNS name,
   SPKI pin, signed reservation scope, or a replay decision. Valid
   `StartExitSession` requests still return
   `exit_listener_orchestration_unavailable`; no launcher is shipped.
4. **No replay authority or monotonic authorization deadline.** Native request
   nonces correlate one response but have no replay tombstone. The active client
   runtime compares expiry to `CLOCK_REALTIME`, so a backward clock adjustment
   can extend an accepted session. Production must consume verified signed scope
   affinely and convert its remaining lifetime once to a monotonic deadline.
5. **No exact VOLPAROSSA EDT scheduler.** mqvpn's WLB is congestion-aware but
   is not the required replaceable delivery-time formula. FEC, XOR, and
   reinjection remain disabled; that does not make WLB an EDT implementation.
6. **No real reverse-dataplane acceptance.** Unit tests prove queue/poll
   framing, correlation, overflow, and wiping, but no disposable topology has
   yet proved an exit-originated inner datagram reaches the Rust client.
7. **No end-to-end dynamic path removal or failover evidence.** The pinned
   upstream exposes these operations, but the VOLPAROSSA lifecycle has not
   exercised them across real relay paths.
8. **No full acceptance evidence.** No disposable namespace test yet proves
   at least two data-carrying paths via distinct relays, bidirectional
   CONNECT-IP, loss-aware scheduling, failover, disabled duplication/FEC,
   privacy packet captures, and unchanged host routes, firewall, and DNS.

The implementation-status dataplane items remain unchecked until these gates
and the real namespace acceptance suite are complete. Focused API-v5 boundary
tests and the full API-v5 sanitizer run alone must not be reported as A06/A07
or full dataplane acceptance.

## Policy boundary

The native process may eventually accept only an already-authorised complete
inner IP datagram. It is not the whitelist authority and must not infer
authorization from packet shape. The Rust policy/traffic layer must validate
the flow, including QUIC Initial/TLS ClientHello SNI and ECH rules where
required, before forwarding; the exit must independently enforce the same
signed manifest and pinned destination tuple. The native parser's packet
checks are defence in depth, not a policy decision.
