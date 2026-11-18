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
compatibility remains separate work. Earlier trials remain historical failures in the linked archive; their pending-proof
descriptions are superseded only for this component.

## Native ordinary-tab integration: actual trials remain failed

The separate native candidate uses the locally compiled Firefox 157.0.1 source
`47c5f402c8d3a5369f1fb1b6cd61b0bb92725af1` and browser adapter
`c3311ebedcc02dc45ff9c9822cee62f091609f86`. Its original native build receipt and
binaries are unchanged; a separately recorded product-JavaScript resource overlay
fixes DOM-owner lookup. It does not substitute ESR compatibility modules or disable
ECH-GREASE globally. The actual disposable core VM trials below have **not** yet
completed the ordinary-tab WireGuard/MPTCP integration proof.

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

Local `build/browser-native-vm-07` on
`10479854ee8cef1fd82e004aa0058d8699d1a15f`, with unchanged bundle05,
reaches two ready attachments and receives **16,777,216 bytes** in the actual
first tab. It still fails: `stream-stop` reports `NS_ERROR_NET_PARTIAL_TRANSFER`
(`0x804b004c`), and the topology reports `BROWSER_NETWORK_TWO_CARRYING_PATHS_MISSING`.
The original baseline revalidates two real MPTCP subflows on relay1/relay2; its
monotonic sampling interval is 639.074547001–639.209327516 seconds. The final
progress receipt instead says `native_owner_not_verified` with no candidates.
There is no valid same-lifetime progress delta, complete 32-MiB hash, second
response or independent detach proof. Original browser, driver and baseline hashes:

- `5fc698c83eed0739115c68be30e45853876f3cd5d935d32169609689c91e0a82`
- `bce9aae06dc9bb5f13dea49ead6c36ced14a8f1b13061ec63a34c50a70fcd0c5`
- `009ea687717655f296fe966ffa5b84289e26a8c790de814a0540045a3eeb13db`

The gateway records two accepted CONNECTs during the first request. A source-level
observer defect is reproduced by a focused test: it rejected any worker containing
more than one MPTCP connection, even when the original transfer remained present.
The candidate now pins progress to the original worker incarnation and exact meta
cookie/token/tuple, retaining full bounded kernel dumps and every original subflow
lifetime, path and byte-delta check. Unrelated connections cannot supply progress.
It also retains the first failed observation with a closed stage and monotonic
timestamps instead of overwriting it with later empty-socket observations.

The origin's `request_rejected` is recorded at `wait-continue`, after its first
16 MiB, not while parsing the HTTP request. That fixture gate is released only
after successful path sampling; its unchanged timeout is 60 seconds. The original
first failed sample was overwritten, and origin/gateway events have no retained
timestamps, so the exact ordering of observer and transport failure is **not
recoverable**. The concurrent-connection defect is not yet proved to be this
trial's cause or a live fix. A15/private/profile cleanup passes with unchanged
guest-state hash `0fec7e486a2ec776598501c8ca26bdb2fa2349e62dee6914dc00592368460890`;
VM/scratch removal and unchanged host DNS/routes are verified. All earlier failed
receipts remain intact; no native ECH wire or complete browser claim is made.

Local `build/browser-native-vm-08` on
`ca37a68a48a352b3e2edf62a24a10cf7aca84cd0`, still using unchanged bundle05,
fails earlier at attachment A with `PreselectionUnavailable`. Its untruncated
client event window identifies **34 `PRESELECTION_SAMPLE_INVALID_SNAPSHOT`**
events. The origin accepts no connection; no baseline or progress sample exists,
so this run does not exercise the exact-flow observer correction. The category
does not identify which snapshot predicate failed. Relay provider-unavailable
events are also present, but do not establish the client's precise failure cause.
Original browser, driver and readiness hashes:

- `022a7d5556ff34532f107243a1459b344d1854f6c0bba5d8691b7b79202b2b97`
- `e9219f612f9a0a5be257baf0a87f00c7235bf5a538e8fff19fd3f26b86d48e5c`
- `4d15f7aadc89a6a169dd9ecf452600c037b2321f4fc6f48b08903c9c2b59d709`

A15/private/browser cleanup passes with unchanged guest-state hash
`0c45d14704680dd97bae8e12fffa70df500a5ad127c4d23b5325f12949cb36f0`.
VM/scratch removal and unchanged host DNS/routes are verified; trials02–07
remain intact. The next diagnostic candidate reports one of eight closed
snapshot-clause categories through the existing bounded in-memory event ring;
it retains every existing rejection, wire format, timer and privacy boundary.
Six focused Rust tests pass, including an actor-local sequence that rejects a
provider index without a signed Exit, then admits preselection after real
signature-verified forwarded ingestion on the same connected control. This
does not reproduce provider-network delivery or identify trial08's missing
clause. The 22 browser fixture checks and nine native-driver checks also pass.
This remains diagnosis, not a product fix or a successful browser datapath claim.

Local `build/browser-native-vm-09` on
`f8dda1e3e5dddac2b208b795f99afe4472c8d861` also **fails**, ending at
`attach-b` / `SCRIPT_FAILED`. Firefox startup and Marionette succeed, but the
origin accepts no connection. The untruncated client event ring records 19
`PRESELECTION_SNAPSHOT_RELAY_COUNT`, 11 `PRESELECTION_SNAPSHOT_NO_FORWARDED_EXIT`
and five `PRESELECTION_SAMPLE_NO_EXIT` events. The separate gateway ring includes
one later Ready. These bounded aggregate windows are not a per-attachment
timeline and do not identify the final JavaScript exception or establish its cause.
Original browser, driver and readiness receipt SHA-256 values are:

- `c2b340ca2a0bca70e5bad640d8c527bb9dab12e181111aad06bfc15610ef09c1`
- `b165ef53c84e6248060426cf085209da0b41c18ad54a8560fafec982cdf70e24`
- `dd2c2466d516df9b61e6495a66846eaa05b5a2638a772e93e3eec2f34f076e69`

Its `native_bundle_sha256` is the verified **manifest** digest
`15b7cbc3a63002229ae50a4459de3d7df4259cbc4764f982213c8273cfeb7b12`;
the unchanged bundle05 **archive** digest remains
`90cf1655f9c084bd5b7b135f4fd64ec017c481115117a395ad8e4fb51cfc9191`.
These identify different objects, not different Firefox builds. Browser/profile
and private cleanup pass, zero owned topology objects remain, and the before/after
guest-root network snapshot digest is
`5e3d25d06e35825e490910ef2d585ab7ccfc1aee8b7cb26c17f576bf7fcd4567`.
That A15 receipt concerns the disposable guest root outside owned namespaces;
it is not a broader assertion about every part of the development host.

The main integration preserves this native driver, bundle provenance and all
payload/cleanup gates, while retaining main's request-scoped route snapshot and
eligible relay/Exit-control selection. The scoped-selection changes were absent
from the original trial's source. They do not invent missing advertisements, and
the integration alone does not prove a fix for this or any earlier failed trial.
Native ordinary-tab payload, full hashes, two carrying paths per route and
independent detach still require a new exact-source disposable proof.

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
channels in the recorded real-core trial, and does not prove a browser-wide kill switch.
Pinned ESR sends ECH-GREASE by default, whereas core inspection rejects every ECH
extension before origin connection. The disposable core proof profile now disables only
that GREASE experiment; real ECH, TLS and certificate validation are not relaxed at the
exit. Product-scoped ECH compatibility remains open because the available scripted
channel interface does not expose `DONT_TRY_ECH`. The fixture's first origin accept
budget is 270 seconds to cover both 90-second route preparations plus browser startup;
TLS handshake itself is capped at 30 seconds. Closed exit/origin diagnostics identify
later failures without private requests or inner error text. Fixture and closed-error classification checks are supporting evidence; the
source-bound actual transfer result is recorded above.

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

## Earlier trial history

The [original combined-run record](../archive/implementation-notes-20261026.txt)
retains all ten failed attempts, source fixes, artifact digests and host-state
observations. Those failures are not rewritten by the later passing component
milestone above. Diagnostic-only/source checks never established browser payload
by themselves. The route-before-Ready contract is active; the earlier account of
that ordering fix is historical, not a remaining implementation task.

Ordinary browsing integration, opportunistic fallback with the user-requested default-off
browser kill switch, HTTP/3, WebRTC, background traffic and crash-persistent browser-wide
enforcement remain unfinished. Existing shared-core security defaults are unchanged. Shared
HTTPS caching is also a separate integration; a CONNECT tunnel cannot make encrypted content
automatically public or safely shareable.
