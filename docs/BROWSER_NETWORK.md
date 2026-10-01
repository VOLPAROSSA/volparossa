# Scoped browser TCP gateway

Status: the scoped Firefox-to-overlay TCP component has passed its live proof.
This is not the complete browser network integration or a browser-wide kill switch.

## Verified component milestone

The exact [run 36776940049](https://github.com/VOLPAROSSA/volparossa/actions/runs/36776940049)
on core `b8a1dd6e52978c40ced4c92c006f8301a587c659`, with browser adapter
`198e288183b06d8a4ff584210ade449f124bc737`, passes. The 30 original artifacts were
downloaded and revalidated against that source, including the original kernel samples
and capture reports (artifact ZIP SHA-256
`86174637ad5bdc62cbd2b785effed63325e5b4e4a10041212cd46806000b8a19`).

Actual ESR 140.16 Gecko receives two separate 32-MiB HTTPS responses with complete
length/hash verification and end-to-origin TLS 1.3. Each transfer has two carrying
kernel MPTCP subflows bound to distinct WireGuard relays; each Client subflow receives
more than 5 MiB between its original samples. The origin observes only the Exit and
no proxy credentials. Closing attachment A retires its independent Client/Exit route
while B remains active. Wrong-scope requests, packet-capture privacy boundaries,
private-file cleanup and zero remaining owned topology objects are checked. The
before/after guest-root host-state SHA-256 is unchanged:
`b30f6805035ff4ce776c836dbe80a14d95a4883a25fa427f606b0f227821d396`.

This proves two explicit scoped Gecko channels, not ordinary tab navigation over the
overlay, simultaneous A/B payload transfer, live direct fallback, HTTP/3, a complete
browser kill switch or a Firefox 157 source build. The disposable profile disables
ECH-GREASE to match the existing Exit inspection boundary; product-scoped native ECH
compatibility remains separate work. Earlier failed trials below remain historical
failures; their pending-proof descriptions are superseded only for this component.

## Native ordinary-tab integration: actual trials remain failed

The separate native candidate uses the locally compiled Firefox 157.0.1 source
`47c5f402c8d3a5369f1fb1b6cd61b0bb92725af1` and browser adapter
`c3311ebedcc02dc45ff9c9822cee62f091609f86`. Its original native build receipt and
binaries are unchanged; a separately recorded product-JavaScript resource overlay
fixes DOM-owner lookup. It does not substitute ESR compatibility modules or disable
ECH-GREASE globally. The actual disposable core VM trials below have **not** yet
proved ordinary tab traffic through WireGuard/MPTCP.

- Local `build/browser-native-vm-02`, core `683e0ede8e0061f9efaf521006af4f61f300d0ba`,
  failed before attachments/origin connections. Its original browser report SHA-256 is
  `8ed5cf164e8ac6d7553781533e7142504043359d4423caa1631ceb9d2fd2e4dd`.
  The original diagnostic does not establish a Firefox crash. A subsequent source
  check proved that pinned Marionette returns `GetWindowHandles` as a direct array,
  while the driver incorrectly indexed a `value` field; that harness bug was fixed.
- Local `build/browser-native-vm-03`, core `b3f31a98dab04538124aa4e464a18c52b26a10f2`,
  confirms Firefox startup and an actual Marionette session. It failed because two
  initial tabs were present while the driver required exactly one. Firefox was still
  running before cleanup; it was then terminated by the driver's own SIGTERM.
  No attachment or origin connection had started. Original browser report SHA-256:
  `05f24c95d9088b442c11e5a283231d69a2c3eafda297bed36147e3cab5205192`.
  The corrected candidate accepts a nonempty initial set bounded to 128 handles;
  it still requires exactly two **new** tab handles and both real body hashes.

Both original failures are retained. Private/profile cleanup and guest A15 pass;
before/after guest-state hashes are respectively
`fb3e9a997cb35de534b2394cebe5c82d4db945f8bfa0f5891c03720788ed09ef` and
`13cd2d65376c4f841df6b19da3b030bca6b47a3ea2cd0153b78e8efd10c13192`.
Both temporary VMs were removed and host DNS/route hashes stayed unchanged.
Native ordinary-tab/core payload, HTTP/3, a browser-wide kill switch and raw
ECH ClientHello wire evidence remain unproved by these trials.

Local `build/browser-native-vm-04` on
`76e9edbfe33c91c66d399209302102d32f96d00f` passes those startup/initial-tab
steps and enters attachment A. The actual core reports route preparation followed
by `PreselectionUnavailable`, before any origin connection. This is not a Firefox
startup failure, and does not establish a specific policy, candidate, address-family
or connection-lineage cause: the existing mapping collapses several discovery
errors, separately from `NoEligiblePaths`. The candidate now records only that
closed inner enum through the existing opt-in, bounded gateway diagnostic; no
retry, timer, policy or network authority changes. The original browser receipt
SHA-256 is `6d2000d87b03792ce9657ecd3d3fa8347480db42f13842234488fa542f9405f6`.
A15/private/profile cleanup passes; guest-state hash
`5c78a1aa3fe989c5e031e05593e551c05aac0885fe893f9adeed2983b8bfb93b`
matches before/after, the VM is removed and host DNS/routes remain unchanged.

Local `build/browser-native-vm-05` on
`923d61a571cde9bbd95deddefd01c9312f27614c` observes transient `Unavailable`
and then `Busy` preselection results, but **both attachments eventually become
ready** using the existing retry behavior. This does not prove the diagnostic
change fixed preselection. The ordinary first tab's CONNECT is accepted and the
origin verifies one GET after TLS completion. The original kernel baseline has
two genuine MPTCP subflows on distinct WireGuard relay paths. The trial then
fails at `request-a` / `BROWSER_NETWORK_PAYLOAD_UNAVAILABLE`: no progress sample,
full body hash, second response or independent detach proof was completed.
The candidate retains fixed navigation failure stages, numeric statuses, byte
counts and state booleans to distinguish the four currently collapsed callback
failures; it changes no browser module, native binary, route or timeout.
Original browser/driver receipt SHA-256 values are
`188c6f6d4bb80d7db52f2f8facbd3f2d6ea2854eee89f8d8597d955ceb1344c6` and
`064787125056906a3d7a314e7d077f55c13a383ceb724fed9925594f33a6dee1`.
A15/private/profile cleanup passes with matching guest-state hash
`bf53a77017aa24b464027065df7dfeb17c069a0a1b03a84634b62e5bacf65cb4`;
the VM is removed and host DNS/routes remain unchanged. All earlier failures
remain retained; no native ECH wire or complete browser-payload claim is made.

Local `build/browser-native-vm-06` on
`f1596e3b6eebea8c2d90460835cf5fa830d89af3`, with driver bundle05
`90cf1655f9c084bd5b7b135f4fd64ec017c481115117a395ad8e4fb51cfc9191`,
starts Firefox normally but fails attachment A after 34 `Unavailable` preselection
results and terminal `PreselectionUnavailable`. No origin connection or navigation
callback occurs. Original browser/driver receipt hashes are
`8296515dffb591973b5518e94b568ac13cb7ac7e1653644a7dec327d2b982ede` and
`e9219f612f9a0a5be257baf0a87f00c7235bf5a538e8fff19fd3f26b86d48e5c`.
A15/private/profile cleanup passes, guest-state hash
`28e3787d6cedcb54f171950bd186a098222f3bab448a90e41cbef79c38e3ae8c`
is unchanged, and the VM/scratch are removed with unchanged host DNS/routes.

The candidate now exports only existing actor ring codes/counts and aggregate
status before private cleanup, not raw logs or a route-readiness assertion.
Independently, its native origin now generates printable ASCII for its `text/plain`
ordinary-tab response: the old random binary bytes could trigger the pinned
Firefox misconfigured-text sniffer (`nsHttpChannel::ShouldSniffMisconfiguredType`
and `nsUnknownDecoder::SniffBinary`). This is a fixture correction, **not a proven
cause or fix of trials05/06**. Historical ESR binary content is unchanged; native
responses still require exactly 32 MiB, independently recomputed full hashes and
the same two carrying-path/cleanup proofs. No browser preference, product code,
native binary, route deadline or retry has changed.

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

The attachment prepares its own route **before** publishing the listener and `Ready`.
Cold signed discovery and native route admission therefore run in the authenticated
control handshake, not inside the browser's already-started CONNECT/TLS wait. Preparation
is bounded to 90 seconds or the original grant deadline, whichever comes first. EOF,
unexpected bootstrap input, daemon shutdown or expiry cancels the waiter and enters the
existing owner-retained route cleanup. Policy is checked again before `Ready`.
`Ready` means route admission succeeded; it does not certify an origin TLS exchange or
payload. The browser's companion bootstrap wait is at most 95 seconds, also capped by
the original expiry; its five-second Unix-connect and native TLS timeouts are unchanged.

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

The app bootstrap now distinguishes a genuine lack of eligible paths from ambiguous
failure. Only a valid candidate snapshot missing an eligible exit or enough diverse
relays produces `NoEligiblePaths`; policy/store errors, invalidated snapshots,
timeouts and transport failures do not. Existing discovery retries remain bounded.
After exact route retirement succeeds and the original grant/current identical policy
are revalidated, the core may return a scoped terminal frame:
`version`, `status`, `reason`, `hostname`, `port`, `partition`, `expires_at_ms`,
`direct_until_ms`. `unavailable/no_eligible_paths` permits an explicitly killswitch-off
browser to consider a **new** direct request for at most five seconds, never beyond the
original monotonic grant or policy expiry. Every other returned failure is
`denied/blocked` with `direct_until_ms: 0`; invalid bootstrap credentials still close.
EOF is never fallback authority, and no direct decision is issued after Ready.
The core itself never connects directly to the origin or weakens exit policy.

Fourteen gateway checks and the actual discovery diversity-rejection check pass;
these prove the typed boundary, not ordinary-browser dispatch or live fallback.

Three CLI checks, one local-protocol check and five agent checks pass. They cover exact scope,
private capability-file creation, one-use/UID/expiry admission, strict CONNECT/bootstrap parsing
and independent controller shutdown. The controller test does not prove two simultaneously
carrying MPTCP routes. The live disposable Firefox/HTTPS proof is a separate remaining step.

The [Firefox adapter](https://github.com/VOLPAROSSA/volparossa-browser/pull/4) is pinned to
`198e288183b06d8a4ff584210ade449f124bc737` in the next `browser-network` VM candidate.
Its existing isolated ESR 140.16 smoke proves real Gecko Unix IPC and three TLS 1.3
responses against a **synthetic** gateway, including independent detach and absence of
proxy credentials at the origin. That result is not a real overlay proof.

The new privileged per-tab controller also passes an actual ordinary Gecko
`browser.loadURI` navigation through the synthetic gateway, preserving native channel
listeners and container/private boundaries. This remains distinct from the two explicit
channels in the pending real-core trial, and does not prove a browser-wide kill switch.
Pinned ESR sends ECH-GREASE by default, whereas core inspection rejects every ECH
extension before origin connection. The disposable core proof profile now disables only
that GREASE experiment; real ECH, TLS and certificate validation are not relaxed at the
exit. Product-scoped ECH compatibility remains open because the available scripted
channel interface does not expose `DONT_TRY_ECH`. The fixture's first origin accept
budget is 270 seconds to cover both 90-second route preparations plus browser startup;
TLS handshake itself is capped at 30 seconds. Closed exit/origin diagnostics identify
later failures without private requests or inner error text. Seventeen fixture checks
and the Rust closed-error classification check pass; a fresh actual transfer is required.

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

The [eighth combined run](https://github.com/VOLPAROSSA/volparossa/actions/runs/36738800599)
on `be2c6cd6baf70da6ec8c8550e88072f2117b4109` **fails** at the new socket preflight:
`socket-path / OS_ERROR / ENOENT`. All 17 originals are retained (ZIP SHA-256
`23394cdd6ed6b19abb070c49459941073932e5b2950496cfbfd6ac7aceecfdfb`). Private cleanup
passes, topology cleanup leaves zero objects, and both host snapshots hash to
`dd39e154bd1e2ea640e8cdb8ba7b41a609865394950276d57c670cd75f9c0e6b`.
Source inspection confirms a fixture mount-publication mismatch: the agent binds its
runtime at `/run/volparossa` and correctly advertises that app socket, while the browser
sees the external fixture path. The candidate maps only the exact client control directory
read-only at the unchanged advertised path inside the browser's private `/run`; neither
the rest of the runtime nor agent state is published there. Parent/socket inode, mode and
ownership equality, read-only access and the original grant are mandatory proof fields.
Production Rust, peer UID checks, application credentials and egress restrictions are
unchanged. Twelve pure browser checks, one actual unprivileged namespace/socket check
and thirteen core evidence checks pass; actual browser/MPTCP transfer is still pending.

The [ninth combined run](https://github.com/VOLPAROSSA/volparossa/actions/runs/36743469202)
on `4d60478acbe50873c4b1f167c05b2bc0106314f0` passes the original-inode mount mapping,
socket access, both real grant attachments and the wrong-scope denial. Actual Gecko then
**fails at `request-a / SCRIPT_FAILED`**, before observed WireGuard payload. All 18
original artifacts remain failed (ZIP SHA-256
`d10f84b04860eafbb0a1bd973007b4683983bfef772ce52a6ebba7ffd4dd115a`). Browser/profile and
private-file cleanup pass; topology cleanup leaves zero objects and both host snapshots
hash to `0777714e9b0d08e611e73ecefb892cf591a2245a6a8112b73d696e54bc862873`.

A local replay against the synthetic gateway now also passes at the fixture's destination
port 18443: three real TLS responses, exact CONNECT authority/header shape and native
Gecko proxy-response status 200, with complete cleanup. This rules out that port alone;
it is not evidence of a working overlay route. The next combined candidate preserves
fixed request stages, numeric native/CONNECT/HTTP statuses and a body-present flag.
Only the disposable client's gateway tracing target is enabled at debug level. Export
reads at most the final 64 KiB and retains at most 64 allowlisted CONNECT, policy, route
or flow stage/error records—no raw logs, addresses, URLs, headers, capabilities or payloads.
Thirteen pure browser checks and fifteen core checks pass. These are diagnostic changes;
the route failure is not yet identified or fixed, and real browser/MPTCP payload proof
remains pending. Existing policy, isolation, lifetime and no-direct-fallback rules remain.

The [tenth combined run](https://github.com/VOLPAROSSA/volparossa/actions/runs/36766377022)
on `3f89c5ab5a43bfa1df19cca55b81ec2bdc1ea839` again **fails at the first request**, now
with closed native code `NS_ERROR_NET_TIMEOUT` (`0x804b000e`), CONNECT status 0 and no
response body. The gateway records `connect_header/received` and `accepted`, but never
route-ready, stream acquisition or forwarding. Both original attachments and namespace
socket bindings pass. The run does not establish browser payload on either required path.
All 18 originals are retained (ZIP SHA-256
`9c9c48f175ee69e6682fe98ebfecf3f2e9f37938f0bed5c77e1a89f81667bee9`), with complete
browser/profile/private/topology cleanup and unchanged host-state hash
`ef974fc320c395a70e895e0b7f9332b1afb2fc843f4d4429931d3462a847a780`.

Source inspection identifies a definite ordering bug: core published `Ready` before cold
route admission, then performed that admission inside HTTP CONNECT. In the exact ESR
release's [HTTP connection implementation](https://github.com/mozilla-firefox/firefox/blob/FIREFOX_140_16_0esr_RELEASE/netwerk/protocol/http/nsHttpConnection.cpp)
and [TLS handshaker](https://github.com/mozilla-firefox/firefox/blob/FIREFOX_140_16_0esr_RELEASE/netwerk/protocol/http/TlsHandshaker.cpp),
TLS setup precedes tunnel establishment and incomplete negotiation is subject to the native
handshake timeout. The staged runtime's default is 30 seconds. This explains a possible
timeout boundary; the historical closed events contain no elapsed times, so they do not
prove that this exact timer caused the failed run or that no additional route failure exists.

The candidate fixes the ordering as described above and retains only closed preparation
stage/error enums in the existing diagnostic export. The fixture keeps two serial independent
attachments; its first-request orchestration wait covers both preparations, without extending
the 300-second grants or altering Firefox network/TLS preferences. Fifteen pure core fixture
checks and shell syntax pass. Four focused Rust preparation checks are added for central
execution; neither they nor the browser's simulated-transport checks are live overlay proof.
The corrected real Firefox/MPTCP trial remains required.

Ordinary browsing integration, opportunistic fallback with the user-requested default-off
browser kill switch, HTTP/3, WebRTC, background traffic and crash-persistent browser-wide
enforcement remain unfinished. Existing shared-core security defaults are unchanged. Shared
HTTPS caching is also a separate integration; a CONNECT tunnel cannot make encrypted content
automatically public or safely shareable.
