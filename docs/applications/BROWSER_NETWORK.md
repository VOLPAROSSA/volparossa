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
