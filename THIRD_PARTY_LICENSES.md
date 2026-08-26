# Third-party software and notices

Original VOLPAROSSA source in this repository is licensed under GPL-3.0-only. Dependencies and
vendored components retain their own licenses. This file is a provenance record, not a substitute
for the license text shipped by each upstream project.

## Native MPQUIC audit state

The native MPQUIC input was audited through 2026-08-14. Every upstream
repository, submodule revision, Git tree, origin, license copy, bundled Wintun
file, and local patch is content addressed in
`third_party/upstream.lock.json`. Source retrieval is an explicit `--yes`
operation; verification and builds perform no network access and refuse
unchecked prebuilt binaries. Upstream checkouts under `third_party/src/` and
generated outputs under `native/volparossa-mpquic/build/` are ignored build
inputs, not committed source or release artifacts.

### Locked native source

| Component | Canonical origin | Exact commit and tree | Tag | Upstream license |
|---|---|---|---|---|
| mqvpn | `https://github.com/mp0rta/mqvpn.git` | commit `607c0df921e2c23bae8bea21cb3c6f2acb2db275`; tree `d6c5ff654c5b7be4754bcb8ad2720b112a2b1e56` | `v0.15.1` | Apache-2.0 plus NOTICE |
| xquic | `https://github.com/mp0rta/xquic.git` | commit `6957ccf9b9fcb9ab62c43672638876abe47162dc`; tree `1999a0a944a1c93b46f7b41b9ff4dccb9302966b` | `mqvpn-v0.15.1` | Apache-2.0 |
| lwIP fork | `https://github.com/mp0rta/heiher-lwip.git` | commit `821af1994c4dbaf1e2cba9a7c2207303b3e5327b`; tree `995119cb3b9074644ed8af3d8c2553fe4f3781aa` | none | BSD-3-Clause |
| BoringSSL | `https://github.com/google/boringssl.git` | commit `fd490c05de684d4cf135388023acf9aabb4e54f1`; tree `0420b7c79fdb88ccf2d7cb21bb934da6a0bc4092` | `0.20260730.0` | Apache-2.0 for linked `libcrypto`/`libssl`; BSD-3-Clause only for unlinked Go TLS test support |
| Wintun userspace header | `https://www.wintun.net/` | bundled by locked mqvpn; exact `wintun.h`, `LICENSE`, and `README.md` SHA-256 values are in the lock | bundled with `v0.15.1` | GPL-2.0 OR MIT; mqvpn selects MIT |

The mqvpn parent gitlinks pin xquic and lwIP; the xquic parent gitlink pins
BoringSSL. Verbatim license and NOTICE copies are retained in
`third_party/licenses/` and their SHA-256 values are locked. The Wintun input
is exactly `third_party/src/mqvpn/third_party/wintun/{wintun.h,LICENSE,README.md}`.
The verifier checks all three files and the byte-identical
`third_party/licenses/wintun-MIT.txt` copy; the Wintun license SHA-256 is
`55743868302006ccaa536bcb96903e185999c6a9cb51ff5bf4b41b96bb30fd07`.
The notice is Copyright WireGuard LLC 2018–2021. This header is Windows-only
and is never compiled or linked on Debian; no Wintun DLL is bundled,
downloaded, or loaded at runtime. The verifier also checks full commits,
trees, origins, tags, parent gitlinks, and tracked-tree cleanliness before a
build can start.

The pinned BoringSSL `LICENSE` has SHA-256
`827c8d8fc207c2392794eef9e00fe246f9f61fdcc132556c275be3dd8c3cd97f`
and starts with Apache-2.0. Ancestor commit
`33d1049b1f730d2725bb09b2256fd5fe4c46b17e` switched the project license
to Apache-2.0. Its trailing BSD-3-Clause notice applies only to Go TLS test
support that the license itself says is not included in compiled
`libcrypto` or `libssl`. This is a source-provenance scope statement, not
legal advice.

### Reviewed local patches

| Target | Patch and SHA-256 | Purpose and security effect |
|---|---|---|
| mqvpn | `patches/volparossa-mqvpn.patch`; `91885f49781c5fc38f9d1822c2b98ffec135fc939c769b678acccd7de48fa887` | Requires a caller-supplied leaf-SPKI SHA-256 pin, propagates explicit path tuples and honest counters, accepts bounded in-memory server PEM identity through sealed anonymous Linux memfds, wipes copied secrets, honours `multipath=false`, bounds pre-H3 mqvpn admission, pins one exact UDP peer, and enforces one lifetime-affine CONNECT-IP claim with idempotent request/connection teardown and duplicate body/Datagram isolation. |
| xquic | `patches/volparossa-xquic.patch`; `acdb5af1a3ba452cfd49b46c80e99e49774db43e1130d032808d4e538772353b` | Invokes the requested certificate callback for every handshake, creates paths with explicit local and remote tuples, labels ACKed transport bytes without claiming unique payload delivery, avoids zero-length null-pointer copies during initial ALPN, empty session-ticket setup, and bodiless stream FIN handling, and returns overflow-checked, `XQC_ALIGNMENT`-aligned large pool allocations. |

The mqvpn patch adds `src/spki_pin.c`, `src/spki_pin.h`,
`src/server_hardening.c`, `src/server_hardening.h`,
`tests/test_spki_pin.c`, `tests/test_server_hardening.c`, and
`tests/test_server_adversarial.c` as GPL-3.0-only files. Its changes to
existing Apache-2.0 upstream files preserve their upstream license and
notices.

No local patch is applied to lwIP or BoringSSL. The builder checks both patch
hashes, runs `git apply --check`, and applies them only to fresh
`git archive` exports. The locked source checkouts remain unchanged.

### Protocol baseline and source evidence

| Protocol | Audited upstream capability |
|---|---|
| RFC 9484 | mqvpn implements MASQUE CONNECT-IP |
| RFC 9297 | mqvpn carries HTTP Datagrams and their context handling |
| RFC 9221 | xquic supplies QUIC DATAGRAM transport |
| RFC 9114 | mqvpn/xquic supply the HTTP/3 association |
| draft-ietf-quic-multipath-21 | the pinned xquic fork implements dynamic multipath path creation and removal |

Source inspection also found genuine multipath APIs, dynamic path add/remove,
and switches that keep FEC, XOR, and duplication disabled. These are upstream
capabilities only. They do not prove that the required VOLPAROSSA
client-to-distinct-relay-to-exit datapath carries traffic.

### Verification evidence

The following checks passed against the exact lock and patches on Debian 13
amd64 on 2026-08-05:

- `verify-upstream.sh` accepted all commits, trees, origins, tags, gitlinks,
  clean worktrees, notice copies, and patch hashes.
- A clean source build compiled BoringSSL, xquic, patched mqvpn, and the native
  daemon. The patched mqvpn upstream suite passed 33 of 33 tests, including the
  added SPKI-pin test.
- The strict native parser, server, runtime, and Unix-socket suites passed 4 of
  4 tests with warnings treated as errors.
- An isolated Debug build compiled the daemon and all four tests with
  AddressSanitizer, LeakSanitizer, and UndefinedBehaviorSanitizer. All 4 of 4
  tests passed with leak detection and halt-on-error enabled.
- The sanitized daemon completed an exit-mode inherited-credential smoke test:
  its parent directory was mode `0700`, its socket was mode `0600`, and
  exact device/inode cleanup removed the socket on SIGINT.
- Valgrind 3.24 reported zero errors and zero live heap bytes/blocks for each
  of the four release test executables.
- The resulting amd64 PIE executable was
  `native/volparossa-mpquic/build/volparossa-mpquic`, SHA-256
  `2386040e4190f7f548c6cc1e86018d866325233d106c796c5cd5138f2ddbf75d`,
  with mqvpn, xquic, lwIP, and BoringSSL linked statically. Its exact
  `DT_NEEDED` entries were `libm.so.6`, `libstdc++.so.6`,
  `libgcc_s.so.1`, and `libc.so.6`.
- The CMake install contract placed a byte-identical mode-`0755` executable
  at `libexec/volparossa/volparossa-mpquic` under a temporary prefix.

The API-v2 change set separately passed the following checks on Debian 13
amd64 on 2026-08-06:

- `cargo fmt --package volparossa-quic -- --check`,
  `cargo clippy -p volparossa-quic --all-targets --all-features -- -D warnings`,
  and all 19 `volparossa-quic` tests.
- Warnings-as-errors builds of both the standalone native boundary and the
  daemon linked to the real pinned mqvpn/xquic source; each passed all 4 native
  CTest executables.
- An AddressSanitizer/UndefinedBehaviorSanitizer daemon build linked to the
  pinned native source; all 4 CTest executables passed.
- `verify-upstream.sh` accepted the exact Wintun header, README, MIT license
  copy, all other locked source and patch inputs, and the JSON lock parsed
  successfully.

The full pinned graph was rerun from fresh `git archive` exports on Debian 13
amd64 on 2026-08-13 with no network access:

- `verify-upstream.sh` accepted the exact commits, trees, tags, gitlinks,
  origins, licenses, notices, bundled files, and patch SHA-256 values.
- BoringSSL, xquic, mqvpn/lwIP, the VOLPAROSSA wrapper, and the daemon were all
  compiled and linked with AddressSanitizer and UndefinedBehaviorSanitizer,
  frame pointers, and no sanitizer suppressions. The verifier found ASan and
  UBSan references in every production archive and the final daemon.
- All 33 mqvpn/lwIP tests and all 4 VOLPAROSSA wrapper tests passed with leak
  detection and halt-on-error enabled.
- The real daemon process handled both SIGINT and SIGTERM within the bounded
  five-second shutdown gate, exited zero, and removed its mode-`0600` Unix
  socket. Both sanitizer logs were empty.

The superseded incompatible API-v3 boundary and final mqvpn
session-correlation, bounded TLS-identity ingestion, and zeroization patch were
previously verified on Debian 13 amd64 on 2026-08-14:

- `verify-upstream.sh` accepted the final mqvpn patch SHA-256
  `dfeffe71a9db187a700a078f0f9f427a57f7eb69bfae2ba1b974a556bd22719d`
  and every other locked source, license, notice, bundled file, and patch.
- A clean release build passed all 33 mqvpn/lwIP tests and all 4 bounded
  wrapper tests. The real mqvpn loopback used the bounded in-memory PEM API and
  completed its handshake after the sealed memfds had already been closed. It
  also correlated the client-originated inner packet with the connect/disconnect
  session ID; focused API tests covered bounds, interior NULs, transactional
  rejection, legacy replacement wiping, and malformed identity rejection.
- One clean, offline ASan+UBSan graph instrumented 350 BoringSSL, 156 xquic,
  145 mqvpn/lwIP, and 10 wrapper C/C++ compile commands, plus their production
  links. All 33 upstream and all 4 wrapper tests passed with leak detection,
  halt-on-error, abort-on-error, and no sanitizer suppressions.
- The sanitized daemon side-effect-free `--api-version` probe wrote exactly
  `3\n`; its SIGINT and SIGTERM lifecycle checks exited zero and removed the
  exact mode-`0600` control socket.
- Valgrind 3.24 reported zero errors, zero definitely/indirectly/possibly lost
  bytes, and only the three standard descriptors open for focused release API
  and server-loopback tests. The remaining 760 reachable bytes are three
  BoringSSL thread-local caches rather than lost allocations.
- `volparossa-quic` passed formatting, Clippy with warnings denied, and all 22
  superseded API-v3 unit tests.

That historical run does not claim the separate BoringSSL Go suite, the xquic
CUnit suite, or disposable-network-namespace dataplane acceptance.

The incompatible native API-v4 descriptor-adoption boundary was then verified
on Debian 13 amd64 on 2026-08-14:

- `verify-upstream.sh` again accepted the locked commits, trees, tags,
  gitlinks, origins, licenses, bundled files, and the unchanged mqvpn and xquic
  patch SHA-256 values.
- A pinned release build passed all 33 mqvpn/lwIP tests and all 5 bounded
  wrapper tests. The real daemon's side-effect-free `--api-version` probe
  wrote exactly `4\n`.
- Focused boundary tests covered exact-one-FD `AddPath`, zero-FD non-AddPath
  requests, missing/two/three/late descriptors, descriptor-bearing frame
  payloads, wrong SHA-256 bindings, `MSG_TRUNC`, `MSG_CTRUNC`, trailing and
  incomplete frames, total-deadline timeout, EOF, peer credentials, strict
  private-overlay tuples, socket revalidation, and descriptor ownership on every reject path.
- `volparossa-quic` passed formatting, Clippy with warnings denied, and all
  26 API-v4 unit tests, including consuming `OwnedFd` on local validation,
  transfer, native rejection, and timeout paths.
- A final clean, offline ASan+UBSan graph instrumented 350 BoringSSL, 156
  xquic, 145 mqvpn/lwIP, and 12 wrapper C/C++ compile commands; its audited
  production/test link counts were 1, 1, 32, and 6 respectively. All 33
  upstream and all 5 wrapper tests passed with leak detection and
  halt/abort-on-error enabled. The API probe and bounded SIGINT/SIGTERM daemon
  lifecycle checks also passed with no sanitizer finding.

This API-v4 run does not prove privileged-helper origin for a descriptor,
the separate BoringSSL Go suite, the xquic CUnit suite, or disposable-
network-namespace dataplane acceptance.

The native API-v5 exit-listener boundary was verified on Debian 13 amd64 on
2026-08-26:

- `verify-upstream.sh` accepted the exact locked commits, trees, tags,
  gitlinks, origins, licenses, bundled files, and patch SHA-256 values before
  the build started.
- A clean, offline full-graph build instrumented BoringSSL, xquic, mqvpn/lwIP,
  the VOLPAROSSA wrapper, and the final daemon with AddressSanitizer and
  UndefinedBehaviorSanitizer. All 33 mqvpn/lwIP tests and all 5 wrapper tests
  passed with leak detection and halt/abort-on-error enabled.
- The sanitized daemon's side-effect-free API-version probe wrote exactly
  `5\n`. Bounded SIGINT and SIGTERM lifecycle checks exited zero, removed the
  exact mode-`0600` control sockets they created, and produced no sanitizer
  finding.
- Focused API-v5 boundary tests cover independent Rust/C listener socket
  checks, operation-specific descriptor binding, fragmented stream assembly,
  rejection of missing, late, extra, or truncated ancillary data, timeout
  cleanup, and fail-closed dormant exit dispatch.

This API-v5 run does not prove trusted-helper descriptor provenance,
assigned-address or network-namespace state, cryptographic consistency of the
candidate TLS identity, the separate BoringSSL Go suite, the xquic CUnit
suite, or disposable-network-namespace dataplane acceptance.

The incompatible native API-v6 process-instance and request-correlation
boundary was verified on Debian 13 amd64 on 2026-08-26:

- `verify-upstream.sh` again accepted every locked commit, tree, tag, gitlink,
  origin, license, bundled file, and local patch SHA-256 before compilation.
- A newly replaced, offline full-graph build instrumented BoringSSL, xquic,
  mqvpn/lwIP, the VOLPAROSSA wrapper, and the final daemon with AddressSanitizer
  and UndefinedBehaviorSanitizer. All 33 mqvpn/lwIP and all 7 wrapper tests
  passed with leak detection and halt/abort-on-error enabled.
- The sanitized daemon's side-effect-free version probe wrote exactly `6\n`;
  bounded SIGINT and SIGTERM lifecycle checks exited zero, removed their exact
  mode-`0600` sockets, and produced no sanitizer finding.
- Focused Rust/C tests share canonical request and descriptor-binding goldens
  and cover role preflight, target/instance substitution, exact response
  digest, stale-instance without automatic retry, signed Start scope, bearer
  commitment recomputation, tunnel-assignment shape, descriptor ownership, and
  fail-closed dormant exit dispatch. Native tests additionally cover
  BOOTTIME/REALTIME admission, rollback/forward-jump/overflow behavior,
  bounded no-eviction reservation/finalize replay tombstones, same-pair exit
  consumption through the framed server boundary, and FD cleanup when request
  digest generation fails. Rust and C independently enforce the exact
  VOLPAROSSA tunnel pools and MTU; focused native tests additionally cover
  immutable retention, duplicate/conflict handling, secure wiping, minimum
  IP version/length shape plus MTU, client source/reverse-destination
  ownership, exact current-path projection with only retired CLOSED records,
  and typed terminal reverse-queue overflow.

This API-v6 run does not prove separate role service identity, trusted-helper
descriptor provenance, server-side product-pool allocation, uniqueness and
route-lifetime binding, assigned-address namespace state,
independent signed-bundle verification or durable/general-nonce replay
authority, cryptographic consistency of the candidate TLS identity, the
separate BoringSSL Go suite, the xquic CUnit suite, or disposable
network-namespace dataplane acceptance. The proven replay ledger is
process-local and the accepted wall lifetime is converted once to a
`CLOCK_BOOTTIME` deadline; neither claim supplies the missing production
verifier and affine handoff.

The current mqvpn connection/session hardening patch was then reverified from
fresh locked-tree exports on Debian 13 amd64 on 2026-08-26:

- `verify-upstream.sh` accepted every locked commit, tree, tag, gitlink,
  origin, license, bundled file, and the mqvpn patch SHA-256
  `91885f49781c5fc38f9d1822c2b98ffec135fc939c769b678acccd7de48fa887`;
  `git apply --check` also accepted the patch directly against mqvpn commit
  `607c0df921e2c23bae8bea21cb3c6f2acb2db275`.
- The ordinary patched mqvpn/lwIP suite passed all 35 tests. Its raw QUIC/H3
  adversarial test covers concurrent and sequential duplicate CONNECT-IP
  requests, rejected-stream ADDRESS_REQUEST bodies and Datagram IDs,
  owner-only close, request-close and connection-close teardown, mixed server
  destroy, pre-H3 `MaxClients` N/N+1 refusal plus capacity reuse, and
  app-admitted unsupported-ALPN cleanup plus capacity reuse through
  `cb_refuse`. Mutation checks proved both the owner-QSID and `cb_refuse`
  assertions fail when their respective production checks are removed.
- A fresh offline ASan+UBSan graph instrumented 350 BoringSSL, 156 xquic, 150
  mqvpn/lwIP, and 20 wrapper C/C++ compile commands; audited link counts were
  1, 1, 34, and 10. All 35 mqvpn/lwIP and all 9 wrapper tests passed with leak
  detection and halt/abort-on-error enabled.
- The sanitized daemon's side-effect-free API-v6 probe and bounded SIGINT and
  SIGTERM lifecycle checks passed and removed their exact mode-`0600` sockets.

This run proves the bounded upstream connection/session lifecycle and native
unit boundaries only. It does not hard-code VOLPAROSSA's separate
`MaxClients=1` product policy and does not prove helper provenance, a usable
exit lifecycle, the separate BoringSSL Go or xquic CUnit suites, or disposable
network-namespace dataplane acceptance.

This evidence proves reproducible source intake, compilation, and bounded
native behavior. It is not namespace dataplane acceptance.

### Mandatory unresolved findings

Native API version 6 preflights an exact client or exit role and a fresh instance
per process start, then target-binds each later operation and correlates every
response to its canonical request digest. It carries signed reservation/finalize
IDs, bearer commitment, certificate digest, and both native instances together
with route-scoped auth, TLS name, and short expiry. Native recomputes the bearer
commitment for both Start roles. Multipath-at-least-two remains distinct from
single-path general UDP, no mode silently downgrades, and no unsolicited frame
is sent. Native converts an accepted wall expiry once to BOOTTIME and keeps a
fixed 128-record, no-live-eviction process-local ledger that rejects exact
reservation/finalize replay and one-ID scope collisions; it does not verify the
signed bundle or retain replay state across restart. `AddPath` consumes one
request-bound UDP descriptor, enforces the fixed private IPv6 overlay, and
never creates or binds a path socket.
`StartExitSession` consumes one separately domain-bound listener-shaped
descriptor, carries exact overlay peer metadata and bounded unparsed TLS
candidate material, then closes the descriptor and fails closed while the exit
backend remains dormant. Versions 1 through 5 and future versions fail closed.
The process instance does not change the RFC 9484 zero Context ID for IP
Datagrams. The current same-UID socket and both SCM_RIGHTS bindings prove local
correlation only, not binary attestation, authentication against an untrusted
agent, or privileged-helper origin. The active client `AddPath` backend also
checks one same-session namespace cookie; `StartExitSession` has no namespace
or assigned-address provenance. The client backend now retains one exact
product-pool assignment, exposes it only after `ESTABLISHED`, rejects mutation,
and enforces inner source/reverse-destination ownership. No test yet proves
that a production exit configured that pool or that the helper installed it in
the same namespace.

The following required contracts and evidence remain unresolved:

1. separate client/exit service identities and role sockets, followed by
   production agent preflight and affine handoff into signed route setup;
2. trusted helper-origin, exact namespace, server-side product-pool allocation,
   uniqueness/lifetime binding and assigned-address proof for each client path
   and exit-listener descriptor;
3. a unique delivered-payload counter rather than ACKed transport bytes;
4. an operational exit backend with helper-to-native listener provenance,
   independent signed-reservation verification, preverified affine replay
   handoff, and cryptographic certificate/key/name/SPKI consistency over the
   in-message TLS material;
5. the exact replaceable VOLPAROSSA estimated-delivery-time scheduler;
6. disposable-topology proof that an exit-originated inner datagram traverses
   the native queue/poll boundary and reaches the Rust client;
7. end-to-end dynamic path removal and failover across real relay paths; and
8. disposable namespace evidence for at least two distinct data-carrying relay
   paths, bidirectional CONNECT-IP, loss-aware scheduling, privacy captures,
   disabled duplication/FEC, and unchanged host routes, firewall, and DNS.

The implementation fails closed at unsupported seams. No native MPQUIC
dataplane status item, including A06 or A07, may be checked until the
applicable runtime gates and the real namespace acceptance suite are complete.

## Rust dependency audit

Rust dependencies are resolved by `Cargo.lock`. A complete
distributable notice inventory is declared only after the release lock passes:

```sh
./scripts/check-rust-dependencies.sh
./packaging/test-collect-cargo-licenses.sh
```

`deny.toml` rejects unknown registries, unknown Git sources, wildcard
versions, yanked crates, and licenses outside its explicit allowlist. That
automated result and the license files embedded in resolved crates are
authoritative for a packaged release. Candidate packaging records each
package, version, license, and source and copies every crate's top-level
license/NOTICE files; it fails on an unapproved source or missing notice.

### Debian 13 compatible Rust security overrides

Three crates.io packages are overridden with verified project-local source.
The Hickory and time fixed releases require Rust 1.88, while the future
single-backend libp2p-yamux release also raises its MSRV above Debian 13's
Rust 1.85:

| Component | Exact source and upstream revision | License | Local security patch |
|---|---|---|---|
| hickory-proto 0.25.2 | crates.io SHA-256 `f8a6fe56c0038198998a6f217ca4e7ef3a5e51f46163bd6dd60b5c71ca6c6502`; git `527c9f470a418cf6b92da902ea0aaa5749963d59` | Apache-2.0 OR MIT; original license files preserved | `third_party/rust/patches/hickory-proto-0.25.2-rustsec.patch`, SHA-256 `bd1d5df1a13574d5c8b546e1a53dfde04d524353a646c8235786d7724215828a`; bounds compression candidates, rejects cross-zone NSEC3 proofs, and adds a non-default regression-only adapter |
| time 0.3.41 | crates.io SHA-256 `8a7619e19bc266e0f9c5e6686659d394bc57973859340060a69221e57dbc0c40`; git `cc35dcfcde917bb833c114e2b4c00292a374c4ba` | Apache-2.0 OR MIT; original license files preserved | `third_party/rust/patches/time-0.3.41-rustsec.patch`, SHA-256 `bc4ad8b199c3284c59b1aa259d5ec907d43f7cb898083a8d5ab99a71cc7a5c8a`; bounds RFC 2822 comment recursion |
| libp2p-yamux 0.47.0 | crates.io SHA-256 `f15df094914eb4af272acf9adaa9e287baa269943f32ea348ba29cfb9bfc60d8`; git `9736aacf814eb7b9df0372c5f9adcffba8a4b212` | MIT; exact upstream repository license retained | `third_party/rust/patches/libp2p-yamux-0.47.0-single-backend.patch`, SHA-256 `1a845f6cfaa57c993b54f654dc8e9294a450de8c46be323618481a7cc750740d`; removes the retired 0.12 backend, pins fixed yamux 0.13.10, and preserves read-after-close policy |

The complete sources, patch review notes, resulting tree hashes, test
contract, and removal condition are in `third_party/rust/README.md`.
`scripts/check-rust-dependencies.sh` reconstructs all three trees from the exact
archives, applies the locked patches, byte-compares the result, verifies
unchanged licenses and the feature graph, runs cargo-deny
license/ban/source checks, and performs a no-fetch cargo-audit scan against a
local RustSec checkout. It prints that checkout's exact commit.

The GPL-3.0-only harness under `third_party/rust/backport-regressions` has a
rustc-1.85-resolved lockfile (SHA-256
`08e7bcd46d2e3f7411e8f4e855c70027f627be6061f63ab459c43f41a687c5cc`)
and executes all five dependency-security regressions offline. Its Hickory feature calls the same
private NSEC3 validator through a doc-hidden adapter; that feature is absent
from and forbidden in the production dependency graph. Its bounded Yamux raw
frame test proves an oversized first-stream body fails closed without an
unwind; its public-wrapper test preserves `set_max_num_streams` and
`read_after_close(false)` semantics.

RustSec scanners still identify the unchanged semantic versions as affected.
`RUSTSEC-2026-0009`, `RUSTSEC-2026-0118`, and
`RUSTSEC-2026-0119` are narrowly exempted only after reconstruction
establishes the local fixes. These are locally remediated advisory-version
matches, not accepted vulnerable upstream artifacts. The production feature
graph also keeps both Hickory DNSSEC features disabled; the NSEC3 fix is
nevertheless present and tested.

The dependency gate requires a CVSS 4.0-capable `cargo-audit >= 0.22.1`.
Debian cargo-deny 0.18.3 remains authoritative for licenses, bans, and sources
but cannot parse the current CVSS 4.0 advisory database.

Candidate packaging excludes workspace members and admits path dependencies
only at the three exact verified vendor paths above.
`yamux 0.13.10` omits license files from its crate archive, so exact
Apache-2.0 and MIT files from official release tag
`70db05dc63e8368bd0559a5ec0dba6e5fc2bdd41` are retained under
`third_party/rust/licenses/yamux-0.13.10/`. The collector fallback requires the
exact registry package identity, license expression, and embedded VCS
revision. `packaging/test-collect-cargo-licenses.sh` proves every vendored and
fallback license is collected and an arbitrary non-workspace path dependency
is rejected.

## Notable Rust source dependencies

| Component family | Purpose | Upstream license expression to verify in release audit |
|---|---|---|
| Tokio, tracing, futures | async runtime and structured diagnostics | MIT |
| serde, serde_json, serde_yaml, prost | configuration and wire encoding | MIT or Apache-2.0/MIT |
| rust-libp2p and Quinn | decentralised control plane and QUIC | MIT |
| rustls, ring, ed25519-dalek, x25519-dalek, Argon2 | transport, identity, and key protection | mixed permissive licenses; inspect every resolved crate |
| rusqlite and SQLite bundle | bounded local peer/session state | MIT for wrapper; SQLite is public domain |
| rtnetlink, netlink-sys, wireguard-uapi, nix, libc | Linux networking and OS boundary | mixed permissive licenses; inspect every resolved crate |

This table is descriptive rather than a claim that every transitive Rust
dependency has already been approved. Never replace the native provenance
record with an unverified version tag or a downloaded executable.
