# Public filter broker protocol

`volparossa content filter-serve` exposes one independently owner-authorized public
filter snapshot over an explicitly started local Unix socket. It reuses signed
named-content retrieval and the `filter-snapshot` verifier. It does not configure
Firefox, select a publisher, approve rules, publish content, enable participation
or supply a browser startup or resume barrier.

## Operator configuration

The command requires `--authority`, `--cache`, `--work-parent` and `--socket`.
Without `--execute` it validates local inputs and prints a preview, without opening
the socket or contacting the agent. The agent's cache must already exist; every retrieval
uses `reuse_cache=true` and preserves the existing revision/conflict floors.
Cache misses use the existing protected agent path, with no direct-origin fallback.
The broker neither creates a replacement cache nor searches for a newer publication.

The authority file is an explicit operator grant, not evidence of independent
governance approval. Its complete schema is:

```json
{"version":1,"enabled":true,"public_content":true,"authorize_filter_publisher":true,"publisher_key":"<64 hex digits>","name":"<exact public name>","manifest_id":"<64 nonzero hex digits>","not_after_unix_seconds":1791400000}
```

Unknown and duplicate fields are rejected. Names contain 1–128 ASCII bytes without
control characters. The publisher/name/manifest must be independently selected;
provider advertisements, model suggestions and delivery receipts are not authority.
The original file bytes are pinned for the process lifetime. Deletion, changed
bytes, unsafe permissions or replacement with a symlink terminally revoke this
instance. Restoration does not revive it; a deliberate restart re-reads the grant.
Such checks do not detect an owner changing and restoring a file between checks.

Authority files are owned regular files, mode 0600, one link and at most 4096
bytes, below owned mode-0700 directories. Work directories are also owned, mode
0700 and canonical without symlink components. The broker checks only the cache
path's absolute normalized syntax; the system agent can own that cache under a
different account. Only the existing agent `ChunkStore::open` checks cache
ownership, safe paths, index integrity and revision floors. Preview does not
inspect the cache, and the broker never opens, chmods or mutates it directly.
Socket creation never overwrites an entry; cleanup removes only the inode this
instance created.

The broker is unprivileged. Its mode-0600 socket admits only the same effective
UID through kernel peer credentials, with at most four live connections. This is
account-level trust, **not browser-extension identity**. A consumer must use an
independently configured trusted socket location and expected publication; it
must not learn trusted selectors from the server. The agent control endpoint is
operator-configured and must retain its trusted local deployment permissions.
The broker does not forward its control API to clients.

## Framing and requests

Each frame is a four-byte unsigned big-endian byte length followed by UTF-8 JSON.
This same-owner local protocol deliberately uses JSON for a narrow browser
consumer, like the existing private service; it is not the peer/control wire
encoding or a signed message format. Requests are at most 512 bytes; responses
are at most 2097152 bytes. An idle or partial request has a five-second deadline,
and writing a response has a three-second deadline. A connection handles at most
32 requests, sequentially. Only one retrieval can run at once, with a 55-second
broker deadline around the existing downloader. Timeout drops the local transfer
and temporary download, rechecks local authority, then returns `unavailable`
(or the observed authority error). It does not leave the broker awaiting the
downloader's longer internal limit.

```json
{"version":1,"id":"00000000000000000000000000000001","operation":{"type":"capabilities"}}
```

`operation.type` is exactly `capabilities`, `status` or `fetch`; the operation has
no other fields. IDs are exactly 32 lowercase hexadecimal characters and cannot
repeat within a connection. Successful capabilities negotiation is required
before status/fetch. Requests cannot contain a path, URL, publisher, manifest,
page context, browsing history or a control operation.

Responses use compact `serde_json::to_vec(Value)` JSON: ASCII strings, integers
within JavaScript's safe integer range, booleans and null; no floating point.
Consumers may require the compact parse/stringify round trip to reject duplicate
keys and alternate encodings. Object field order has no semantic meaning.

## Closed responses

Every response contains `version:1`, the exact request `id`, and `event`.
No other fields beyond the corresponding list below are permitted.

- `capabilities`: `protocol:"volparossa-filter"`, `same_uid_only:true`,
  `public_content_only:true`, `fixed_publication:true`, `browser_activation:false`,
  `max_request_bytes:512`, `max_response_bytes:2097152`, `max_requests:32`,
  `max_connections:4`, `publisher_key`, `name`, `manifest_id`,
  `authority_expires_unix_seconds`.
- `status`: `state` is `unavailable` with `snapshot:null` until retrieval, or
  `ready` with the snapshot metadata below. Status never initiates retrieval.
- `snapshot`: `snapshot` metadata, `filters` containing the exact original ASCII
  text, and `manifest_hex` containing the complete original signed envelope in
  lowercase hex. No provider receipt or local path is exposed.
- `error`: only `code`, one of `invalid_request`, `handshake_required`,
  `duplicate_request`, `busy`, `unavailable`, `revoked`, `expired`, `clock_error`
  or `invalid_snapshot`. Malformed frames receive `id:null` and the connection
  closes. Failures never format raw parser, filesystem, agent or content errors.

Snapshot metadata has exactly these fields:

```text
generation  publisher_key  name  revision  sha256  bytes  rules
grammar  verified_at_unix_seconds  expires_unix_seconds
authorization_expires_unix_seconds
```

`generation` is the exact manifest ID, not a fresh per-fetch identifier. `grammar`
is `ubo-domain-block-v1`: at most 1 MiB, 4096 domain-block rules and 8192 lines;
only lowercase `||domain.example^`, blank lines and an optional first-line
`[Adblock Plus 2.0]` header. No includes, directives, exceptions, comments,
scriptlets or rule options are admitted. Bytes are not rewritten.

The original verification timestamp and signed expiry do not change on in-memory
reuse. Effective authorization ends at the earlier of signed expiry and the
operator grant's `not_after_unix_seconds`. Publisher key, signature, exact name,
manifest ID, whole-object hash, length and grammar are checked by the shared
verifier, including before and after response serialization. Local grant checks
also surround awaited retrieval and response writes. Revocation/expiry observed
during writing aborts further writes. Bytes already written cannot be retracted;
the consumer must still check expiry after receiving a complete frame.

## Expiry and consumer responsibility

The broker projects authority onto Linux `CLOCK_BOOTTIME`, which includes
suspend, sampling before `CLOCK_REALTIME`. Clock regression, observed expiry or
revocation is terminal for that instance. This clock floor is process-local;
the signed expiry also retains the earlier process-start projection, so time
spent suspended during retrieval cannot restart the object's validity budget.
Operator clock trust and cross-restart clock policy remain deployment concerns.
The original content-cache revision floor remains durable and is not reset.

A response is data, not a continuing lease to apply filtering rules. The receiver
must reject incomplete frames, bind metadata to its independently selected
authority, verify expiry after receiving the complete frame and enforce expiry
during use. Already delivered bytes cannot be remotely withdrawn. This broker
does not remove rules loaded into uBO or prove a Firefox startup/resume barrier.
Those controls and production publisher governance remain unfinished.

SIGINT/SIGTERM stop admission, cancel owned connection tasks, remove transient
local download files and unlink the owned socket. Agent-owned verified cache
chunks may remain under the existing protected downloader's bounds. No host
network configuration or browser profile is modified.
