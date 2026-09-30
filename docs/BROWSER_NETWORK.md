# Scoped browser TCP gateway

Status: executable development candidate; a live Firefox-to-overlay proof is still pending.
This is not the complete browser network integration or a browser-wide kill switch.

## One daemon, independent application connections

An explicitly authorized application can obtain its own short-lived TCP gateway from the
running agent. The administrative control socket issues an exact-host, port, partition and
application-UID grant. A separate `.apps` Unix socket redeems the one-use capability after
checking the connecting kernel UID. It accepts no administrative commands. UID plus capability
delegates authority; it does not identify a particular browser executable or sandbox.

Each attachment gets its own loopback CONNECT listener, proxy secret and route controller.
It uses the existing real `connect_tcp -> open_content_stream -> proxy_application` chain:
kernel MPTCP, protected relay paths and Exit policy checks. There is no direct destination
socket, ordinary-TCP transport substitute, or automatic Internet fallback in this adapter.
The browser retains end-to-origin TLS certificate verification inside the tunnel.

Closing the application connection, reaching its expiry or losing policy authorization closes
that attachment's streams and retires its route. Other attachments and the daemon's main/DNS
route owners are separate. Unconfirmed retirement keeps the owner and its admission slot for
daemon cleanup; it is not reported as completed or forgotten. Closing a browser does not stop
the shared daemon.

## Explicit development grant

An operator with access to the administrative socket can use:

```sh
volparossa browser grant --app-uid 1000 --hostname example.com --port 443 \
  --partition 0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef \
  --lifetime-seconds 60 --output /absolute/private/new-browser-grant.json
```

Use the application's actual UID and an opaque application-owned partition identifier.
The current policy must already authorize the exact hostname/port and client participation
must already be enabled; this command changes neither. The output must be a new, explicitly
chosen file, written at mode `0600`. It contains a secret one-use capability: deliver it
privately to the intended app and remove it when no longer needed. No default credential
file, secret stdout output or browsing-history record is created.

The local administrative protocol remains version 2, with request tag 42 and response tag 32.
The separate application bootstrap is local-only version 1: a four-byte big-endian length
and strict UTF-8 JSON, at most 4096 bytes. The request contains `version`, `capability` and
`partition`. The response pins the original scope and expiry and supplies an ephemeral
`127.0.0.1` proxy port plus its `Proxy-Authorization` value. Keep that Unix connection alive
for the attachment's lifetime; unexpected input or EOF closes it. This is not a peer protocol.

The explicit resource bounds are eight outstanding/active attachments, eight streams each,
and at most 300 seconds per grant/attachment. The original route, policy and helper deadlines
remain authoritative. These are development gateway resource bounds, not a claim of completed
adaptive network-wide path admission.

## Failure and verification boundaries

Only CONNECT for the exact canonical hostname and port, with the attachment's proxy secret,
is accepted. The secret is consumed locally, not forwarded to the destination. Route setup,
policy denial, invalid authentication and ambiguous failure never authorize a direct retry.
CONNECT 200 acknowledges a tunnel, not successful Exit-origin connection or origin TLS.

Three CLI checks, one local-protocol check and five agent checks pass. They cover exact scope,
private capability-file creation, one-use/UID/expiry admission, strict CONNECT/bootstrap parsing
and independent controller shutdown. The controller test does not prove two simultaneously
carrying MPTCP routes. The live disposable Firefox/HTTPS proof is a separate remaining step.

The [Firefox adapter](https://github.com/VOLPAROSSA/volparossa-browser/pull/4) is pinned to
`2ed43df06d110685edb830ccc48fc38cdb4b0e9b` for the `browser-network` VM scenario.
Its existing isolated ESR 140.16 smoke proves real Gecko Unix IPC and three TLS 1.3
responses against a **synthetic** gateway, including independent detach and absence of
proxy credentials at the origin. That result is not a real overlay proof.

The combined fixture instead uses the actual core, two explicit CLI grants and a temporary
HTTPS origin CA. Each 32-MiB response must pass its browser-side hash and show two genuine
carrying MPTCP subflows through distinct WireGuard relays. It completes A's response, opens
B, then retires A's attachment while B remains active; this does not claim simultaneous
payload transfer by both apps. Original kernel socket/worker identities, helper namespace
ownership, captures, independent retirement and unchanged host state are checked separately.
Only sanitized metadata is exported; grants, profiles and temporary test keys are removed.
The fixture's browser-UID loopback guard contains background traffic in the disposable
namespace; it is explicitly not the product's browser-wide kill switch. No compute model
is downloaded or executed for this network-only scenario.

The [first combined run](https://github.com/VOLPAROSSA/volparossa/actions/runs/36625896567)
on `b4b2d62b03046dff9d83e1b8ba1e11bbed92accc` **failed** before HTTPS at
`BROWSER_NETWORK_APP_BOUNDARY_INVALID`; it does not prove browser overlay traffic. Its
15 original artifacts retain complete cleanup and matching before/after host-state hashes
`578e552dc0fa4c9fabed4a26eaa7c7a0d3462e6b5a6fee18b5b7cf587b71cc4b`
(artifact ZIP SHA-256 `a24aa758425b05386ba1f184b653a4a4c9c8565adff03f89c8c4c24a99e5ec5c`).
The fixture requested fully numeric `nft -n -j` output but expected the symbolic `ipv6`
value. It now requires Linux `NFPROTO_IPV6 = 10`, as emitted by nftables' numeric JSON
serialization, with the same exact UID, loopback address, drop verdicts and chain.
This corrects a deterministic checker mismatch; the old run did not retain enough boundary
diagnostics to exclude an additional launch failure. Eight pure fixture checks pass,
including rejection of weakened guards and closed failure-stage diagnostics; the corrected
live combined proof remains pending. No firewall or product isolation was relaxed.

The [second combined run](https://github.com/VOLPAROSSA/volparossa/actions/runs/36714093009)
on `fd2d7eb2ed11a6b17415faec747115904800d348` passes that actual application boundary,
but fails at `BROWSER_NETWORK_HTTPS_REQUEST_UNAVAILABLE`. It retains 16 original artifacts
(ZIP SHA-256 `cf7f30b8aaafd17e60792ec307849b4a32658feb0ffd789f57904393fea04c59`),
complete cleanup and unchanged host-state hash
`05a36403bd56c0a962b92113ff73661f4002c583e3803c7ce5face4b2ea8cf07`.
No browser report or WireGuard payload was observed; pre-browser driver failures were not
recorded sufficiently to identify their cause. A new closed driver-status export retains
the last wrapper/namespace/Firefox/attachment stage, canonical error/errno and boolean
stderr classifications. It exports no raw stderr, browser logs, grants or private paths.
Nine pure fixture checks pass, including rejection of unexpected diagnostic fields.
The diagnostic revision changes its driver/tests/documentation, not the network module
or pinned ESR package.

The [third combined run](https://github.com/VOLPAROSSA/volparossa/actions/runs/36716815095)
on `e53034f64ae3faf6c8a09999ead19bbe27767822` still **fails** before HTTPS. Its new
closed diagnostic identifies `wrapper-launch` / `SUBPROCESS_FAILED`, child exit 1 and a
permission-denied signal; the child never records runtime validation. All 17 original
artifacts are retained (ZIP SHA-256
`3178ac704a14d72ac51f3fa4e91d7a79d640d63aaf88494dcb5f37521efe210e`), with complete
cleanup and matching host-state hash
`8b201fe6a22c03c9c59b6d94f9de21719c81b4402c8b8daea33229180ae37445`.
The fixture inherited the provisioning user's private source-checkout working directory
after dropping to the application UID. The candidate driver now explicitly enters its
own fresh `0700` work directory both before and inside bubblewrap. This removes that
inaccessible-directory dependency without widening source permissions or network access;
it is not yet a demonstrated live fix. Closed stderr classification now distinguishes
working-directory from bind/mount failures without exporting private paths. Eight browser
driver checks and nine core fixture checks pass. Actual browser payloads remain unproven
until the next combined run passes.

The [fourth combined run](https://github.com/VOLPAROSSA/volparossa/actions/runs/36719104806)
on `9bb16c996a2bb05adaa27704daca8578e21fc54a` also **fails** before HTTPS with browser driver
`a82e6c6313a4dc56cebaac4fcdff5cd3d12895d4`: the owned working directory did not resolve
the observed launch failure. The closed status is still `wrapper-launch` /
`SUBPROCESS_FAILED`, child exit 1, permission denied, without a child-validation phase.
Working-directory, mount and namespace classifications are false; they do not identify
the failing operation, because source/destination lookup, remount and exec messages were
not classified. No raw stderr is retained or exported, so this evidence cannot establish
an exact failing path or syscall. All 17 originals remain failed (ZIP SHA-256
`1ab9e6e8c17fdcd1a8fc2140771eeb93877c18793dea8a706afeec7627f9bc6a`), with complete private
cleanup and unchanged host-state hash
`904fa278236acb21131d1881e4bcc148e9c82e44a0de2f65a0c9e56455ed72d3`.
The next diagnostic retains only fixed bwrap operation flags, never their path/argv suffixes;
the sandbox, application permissions, pinned browser and core datapath are unchanged.
This is diagnostic coverage, not a claimed launch or browser-payload fix.

The [fifth combined run](https://github.com/VOLPAROSSA/volparossa/actions/runs/36722045933)
on `ff98dc8c26a0e94840bfe20eb46a7f1682f634a4` **fails** at the same wrapper boundary.
It now identifies bwrap directory creation as the failing operation; source lookup,
readonly remount, identity mapping and exec classifications are false. The original
diagnostic did not retain the destination, so a permission change is not justified by
this result. All 17 originals remain retained (ZIP SHA-256
`373524974dd2bb20c04553179c6240965f98c2af16d06d87f1caa2b31436b5b1`).
Private cleanup passes; both host snapshots hash to
`58a90792fd99dbcca21bc6cf50e9aacd6db110f708f678abfee56f1b237b5ca3`.
The next diagnostic classifies only exact fixture-owned destinations and fixed bwrap
setup directories, retaining an unknown category rather than exporting paths. Eleven
focused checks pass. No sandbox permission, browser pin or product datapath changed;
actual browser-to-overlay payload transfer remains unproven.

The [sixth combined run](https://github.com/VOLPAROSSA/volparossa/actions/runs/36726326554)
on `4808fe06113915709d61b070c022288cb1e53331` **fails** before child validation or HTTPS.
Its closed diagnostic identifies `browser_work` as the sole directory-creation target,
with permission denied. All 17 original artifacts are retained (ZIP SHA-256
`68f134e5df9061ab7ce2146a72c3fbac7a00890c2be270b969d1d5801f8e2e20`).
Private cleanup passes, and both host snapshots hash to
`d8101820722bbbbdddb5afe8866ff8ec5e6aab0e3729d68818576a8a4a3da438`.
A bounded local bubblewrap-only probe, using UID 985 with zero effective capabilities
and no-new-privileges, reproduces destination-parent creation denial with an unmapped,
search-only parent. An anonymous child-only parent shell removes that dependency.
The candidate driver therefore rebinds only the pinned runtime read-only beneath that
shell, remounts the shell read-only, and retains the original private writable work bind.
Other provisioning-home entries are hidden, not copied or made readable. Existing parent,
runtime and grant permissions, application UID, network namespace and capability checks
are unchanged. Nine focused browser tests pass. This is a sandbox-launch candidate;
the next actual combined run must still prove Gecko HTTPS and protected MPTCP payloads.

The [seventh combined run](https://github.com/VOLPAROSSA/volparossa/actions/runs/36732926403)
on `cd3e630d243739e1d3188074907af0e8d5e03f81` gets past sandbox setup and launches actual
ESR 140.16, but **fails at `attach-a` / `unavailable` before Ready**. It observes no
WireGuard/provider payload. All 18 originals remain retained (ZIP SHA-256
`b468959bab11bdedb2020696fa6f1ffb6a74beec21b609045339d13d18d0b2d0`). Browser/profile and
private-file cleanup pass, topology cleanup leaves zero objects, and both host snapshots
hash to `f4e38c146026adcbb328fd871ef32615655af76a690b1460888f549b3927b4f5`.

The next diagnostic distinguishes fixed socket/stream/bootstrap stages, peer EOF and
timeout with an optional numeric `nsresult`; it exports no exception text or credentials.
A non-consuming in-sandbox preflight verifies the actual Unix socket/parent ownership,
mode, access and peer UID without sending any bytes or claiming a capability. Eleven
browser checks, twelve core evidence checks and a fresh real-ESR/synthetic-gateway smoke
pass, including all three TLS responses and cleanup. The exact core bootstrap cause
and actual browser-to-MPTCP payload remain unproven; no production routing or permission
change is inferred from the previous generic error.

Ordinary browsing integration, opportunistic fallback with the user-requested default-off
browser kill switch, HTTP/3, WebRTC, background traffic and crash-persistent browser-wide
enforcement remain unfinished. Existing shared-core security defaults are unchanged. Shared
HTTPS caching is also a separate integration; a CONNECT tunnel cannot make encrypted content
automatically public or safely shareable.
