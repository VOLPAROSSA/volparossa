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

Ordinary browsing integration, opportunistic fallback with the user-requested default-off
browser kill switch, HTTP/3, WebRTC, background traffic and crash-persistent browser-wide
enforcement remain unfinished. Existing shared-core security defaults are unchanged. Shared
HTTPS caching is also a separate integration; a CONNECT tunnel cannot make encrypted content
automatically public or safely shareable.
