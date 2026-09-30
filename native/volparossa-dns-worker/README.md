# Private libunbound worker

This GPL-3.0-only executable is a small, synchronous C ABI shim for Debian's
libunbound. Rust owns policy checks, concurrency, framing validation, deadlines
and exact child termination/reaping. No Rust unsafe-code exception is added.

It has no listening socket, command-line options, environment configuration or
private pathname input. The agent starts the fixed packaged path
`/usr/libexec/volparossa-dns-worker` with private stdin/stdout pipes, null stderr
and an empty environment. The worker retains the agent UID and creates only
ordinary recursive-resolver sockets; no additional UID/firewall exemption exists.
It closes every inherited FD above stderr, refuses core dumps and limits address
space to 128 MiB, FDs to 64 and CPU time to five seconds. Rust permits at most two
workers and reserves the last 500 ms of the existing resolution deadline for
cleanup. Cancellation is observed by a separately owned supervisor; an
unconfirmed reap quarantines the backend and retains the child/concurrency slot.

The process uses the real `ub_resolve` validator/iterator, Debian's read-only
`/usr/share/dns/root.key` and `root.hints`, checking enabled, QNAME minimisation,
ordinary TTLs, and no query logs or disk cache. It never reads `resolv.conf`,
`hosts`, or a daemon configuration. One child retains one native resolver context
for the original address lookup and up to 31 related DNSSEC evidence lookups.
There is **no persistent libunbound cache** between resolution operations. The
original raw answer seeds the independent Rust verifier; it requests only
DNSKEY/DS records for that name or its ancestors, including the root DNSKEY.
Only a successfully verified chain can enter the existing policy-scoped shared
proof cache. A native `secure` verdict alone remains local provenance.

## Version-2 pipe protocol

The only local canonical-encoding exception is this fixed-width private FFI
protocol; it avoids adding a Protocol Buffers runtime to the small native shim.
It is not a peer protocol and cannot grant policy, configuration or privilege.
Every integer uses big-endian encoding. Unknown versions, unrelated questions,
incorrect sequence/nonce/name/type and trailing bytes are rejected. The first
request is A or AAAA; later requests may only obtain the related evidence above.
At most 32 sequential exchanges share one session nonce and the original deadline.
Closing stdin ends the session; Rust requires stdout EOF and confirmed child reaping.

| Byte range | Request | Reply |
|---|---|---|
| 0–7 | `VPDNS002` | `VPDNS002` |
| 8–9 | IN RR type: A/AAAA initially, then DS/DNSKEY | status byte, then native secure boolean |
| 10–11 | canonical ASCII name length, 1–253 | address count, 0–16 |
| 12–15 | sequence, starting at zero | remaining TTL in seconds |
| 16–31 | opaque 16-byte request nonce | exact request nonce |
| 32–35 | name begins at byte 32 | exact request sequence |
| 36–39 | — | raw DNS packet length, at most 4,096 |
| 40–41 | — | exact requested RR type |
| 42–43 | — | exact question-name length |
| 44 onward | — | echoed name, address RDATA, then raw packet |

Status values are `0=positive`, `1=unavailable`, `2=NXDOMAIN`, `3=NODATA`,
`4=DNSSEC bogus`. Every nonpositive response is exactly 44 bytes plus the echoed
question name, with secure/count/TTL/raw length zero. Maximum request/reply sizes
are 285/4,649 bytes. The root name is encoded as `.`; other names have no trailing
dot. No raw native error, filesystem path or remote parser text is emitted. Public
unicast/address-family checks stay in Rust. Unbound's TTL already includes the
minimum CNAME/address lifetime; Rust conservatively starts that lifetime before
the query so pipe/cleanup time can never extend it. Evidence collection strips
unneeded authority/additional sections and AD, retains all answer RRsets/signatures,
and validates against the built-in root anchors. Unsupported CNAME, wildcard or
unsigned evidence is not promoted to shared proof. Optional proof collection can
leave a usable native fallback answer, but malformed pipe data, bogus responses
or unconfirmed cleanup still fail closed. A proof-collection timeout can return
that already obtained answer only after confirmed child reaping.

## Build without installing or starting a resolver

Build dependencies: C11 compiler, CMake 3.25+, pkg-config, `libunbound-dev` >= 1.26.1.
Runtime dependencies: Debian `libunbound8` and `dns-root-data`; no `unbound`
daemon package is necessary. The separate optional Debian-13-only companion
`volparossa-private-dns-worker` builds it from this source; the existing core
package build/dependencies remain unchanged. Neither package activates roles or
changes DNS. Explicit private configuration fails agent startup with
`DNS_PRIVATE_WORKER_UNAVAILABLE` if its fixed worker or root-anchor files are absent
or unsafe. This installation check does not prove recursive connectivity.

```sh
cmake -S native/volparossa-dns-worker -B native/volparossa-dns-worker/build
cmake --build native/volparossa-dns-worker/build --parallel 2
# Optional companion .deb, only in a provisioned Debian 13 build environment:
sh packaging/build-private-dns-worker-deb.sh --preview
sh packaging/build-private-dns-worker-deb.sh --build
```

For the approved workspace-only ABI check, pass `UNBOUND_INCLUDE_DIR` and
`UNBOUND_LIBRARY` to CMake, pointing at `build/native-unbound-deps/root/usr/include`
and `build/native-unbound-deps/root/usr/lib/x86_64-linux-gnu/libunbound.so`.
No package installation, unchecked fetch or host DNS query is part of that build.
The exact reviewed source/package provenance is in
[`THIRD_PARTY_LICENSES.md`](../../THIRD_PARTY_LICENSES.md).

Compilation, pure protocol tests and owned inert-process lifecycle tests are not
proof of real recursive DNS, DNSSEC rejection or reciprocal Client+Exit privacy.
That proof still needs a disposable network/VM execution with packet captures,
no publicly reachable resolver, exact child cleanup and unchanged host state.
