# Distributed content, publishing and offline delivery

Status: user idea received 2026-09-07; architecture proposal with working persistent native
storage, protected-route public/encrypted transfer and cooperative-origin/representation-digest
HTTPS consumers.
**Multi-peer retrieval, bounded owner-contention integration and native static-site publishing
have source-bound passing checkpoints; browser benefit and generic existing-site reuse remain
incomplete.** Global replica repair/fairness and unsupported-site HTTPS integration are still
requested work; the bounded checkpoints do not remove them from the functional scope.
This is additional functional scope, not evidence that the VPN/local-link alpha is finished.
Continue from the scoped downlink/mixed-link passes into the application/content runtime.

## Requested result

Every capable participant contributes bounded local storage as well as its agreed network
roles. Reusable content is split into verifiable chunks, fetched from several useful peers,
retained and redistributed. Ordinary exchanges may carry a small additional selection of
chunks to improve availability and diversity, but only within genuinely spare resources.
Missing, expired or slower-to-fetch parts can come from the original source instead. The
same substrate should support shared DNS records, publishing a user's own website/content,
and delivering encrypted messages while the sender is offline.

## Common substrate

- Content-addressed chunks and a versioned authenticated manifest bind ordering, total length,
  chunk hashes, content type, publisher authority and expiry. Hashes establish byte integrity;
  they do not by themselves establish an Internet origin or legitimate publisher.
- Bounded distributed provider discovery indexes available chunks, not a central catalogue
  of users or their browsing. Availability advertisements expire and are verified by actual
  bounded retrieval. A hash of a known URL is not a browsing-privacy mechanism.
- Retrieval selects sources using measured latency, delivery progress, congestion and costs.
  It must not wait indefinitely for cache discovery before trying an authorized origin.
  Missing ranges may be fetched from the origin only with matching representation/version
  validation; stale and current chunks must not be combined into one object.
- Opportunistic replication is separate application-level content replication, not transport
  packet duplication, cover traffic or FEC. It has a bounded hop/expiry/replica target and
  favors useful scarce chunks and diverse holders rather than uncontrolled gossip of every
  object. Self-declared popularity or free space is not trusted as proof.
- Explicit disk quotas, a free-space floor, bounded memory/CPU/IO and separate foreground,
  retrieval-serving and background-replication budgets protect the owner. Background copying
  pauses under owner demand, uncertainty or congestion; scarce paid/mobile bandwidth, battery
  and shared radio airtime also matter. Spare disk is not permission to fill the whole SSD.
- Content-protocol authorization and privacy must be designed explicitly. A direct peer
  download must not silently bypass the existing route/privacy boundaries or Internet egress
  policy. Serving an overlay object is not advertising an independent Internet Exit uplink.

## Different objects need different rules

### Existing web content

Generic TLS traffic is session-encrypted. An overlay cannot turn arbitrary recorded HTTPS
packets into reusable cross-client HTTP responses. Existing-web integration therefore needs
an application/browser boundary or publisher cooperation; installing an interception CA,
breaking TLS, bypassing login/DRM or extracting application secrets is not part of this design.

Shareable HTTP responses must preserve cache semantics, including no-store/private,
authorization, freshness, Vary, validators and range identity. Neither another peer's claim
nor its signature proves that bytes came from the claimed web origin. The design needs an
authentic origin/publisher binding before peer content can stand in for that origin.
Personalized/private responses must not become public shared objects. Generic automatic
YouTube caching is not promised by the existence of a chunk store.

### Native public publishing and websites

Publishers explicitly publish signed, versioned objects. A stable name resolves to an
authenticated current manifest; updates and stale versions have defined lifetimes.
Static site assets can remain available while the original machine is offline only if all
needed chunks still have reachable replicas. Dynamic application execution is a separate
capability; caching HTML does not provide an offline database, login service or checkout.

The additional explicit cache-only consumer mode preserves the original publisher-signed
envelope after a completed named download. An existing owned cache can then reopen a native
publication/site without route setup or peer discovery, while retaining its original expiry
and durable revision/conflict floor. Missing newer content cannot silently revive an older
version. This is local availability, separate from external replica retention or global
latest-version claims. Its [no-route integrated proof on `4e6cc308`](https://github.com/VOLPAROSSA/volparossa/actions/runs/34214732165)
passes with identical cached bytes, no peer/origin delivery and full cleanup.

Best-effort cache eviction alone cannot provide durable publishing. Retention commitments,
replica receipts, repair and an honest availability status are needed. No permanent-availability
or deletion-of-all-remote-copies guarantee is implied.

### Private messages and optional mail interoperability

Encrypt for the intended recipient before chunking/replication. Storage peers must not need
plaintext or recipient decryption keys. A recipient's authenticated mailbox/discovery scheme,
anti-spam quotas, retention/expiry and delivery acknowledgement are distinct from public caching.
Offline delivery requires sufficient reachable replicas before the sender disconnects.
Network-native messaging does not automatically interoperate with existing email; SMTP/DNS
delivery or gateways for ordinary email are separate integration work.

### DNS

Share validated DNS RRsets with their original authentication and remaining TTL, never query
history. DNSSEC material can be independently validated; unsigned data from an arbitrary peer
must not become trusted merely because the peer signed it. Use the established trusted
resolution path where independent validation is unavailable. Replication must not renew TTL
or signature lifetime, mix private/split-horizon views, override policy or redirect arbitrary
destinations. A DNS record is a typed object with DNS-specific validation, not generic web data.

The first integrated implementation now connects one RAM-only `ExitResolver` to protected DNS,
TCP hostname resolution and UDP/browser-QUIC destination pinning. Positive A/AAAA proofs are
checked independently with the pinned Hickory DNSSEC verifier and built-in root anchors. A
generic provider capability locates caches; DNS names never enter provider records. Queries and
replies use the existing signed control envelope over an exact authenticated direct connection,
excluding the local node and every retained control/data relay for the original route. A cache
miss never makes the serving peer perform a recursive lookup. Each receiving Exit still applies
its own policy and independently validates the proof before using it. Capability publication now
requires at least one actual unexpired RAM proof for the active policy, not merely a configured
resolver or enabled role. Cold Clients therefore publish no empty cache offer. Local withdrawal
does not recall already propagated or in-flight DHT hints; cache misses still never recurse.

`dns_cache.enabled` defaults to true but activates no roles or new listener. Optional
`dns_cache.upstream` selects an operator-specified existing recursive TCP/53 endpoint for proof
collection; its default is null, with no built-in DNS provider or host DNS reconfiguration.
Invalid, absent, unsigned or unsupported proofs retain the existing OS-resolution fallback,
whose answers are not advertised as DNSSEC evidence. CNAME chains and negative-answer sharing
are not implemented by this positive-only slice. Cache entries are policy-partitioned and
bounded by received TTLs, signature expiry and local monotone first-seen deadlines; forwarding
cannot extend the local expiry. DNSSEC cannot prove when an unknown peer first received a
record, so this is not an absolute network-wide TTL-replay guarantee.

The combined runtime compiles and the focused core verifies a real cryptographic test chain
and TCP collector in a disposable namespace. That test's private anchor exists only under
`cfg(test)`; it does not prove the current public chain or network-wide C05. A separate fixture
probe now passes genuine public A and AAAA validation against the unchanged built-in production
anchors, followed by local cache reuse, in the
[exact `0fa80d65` run](https://github.com/VOLPAROSSA/volparossa/actions/runs/34182008684).
The ordinary two-Exit peer-hit/fallback network checkpoint remains open.

## First delivered foundation (2026-09-07)

[`volparossa-content`](../crates/volparossa-content/README.md) now has real, bounded local
SHA-256 chunk stores, canonical Ed25519-signed native manifests and verified reconstruction.
The caller supplies an independently trusted publisher key; the verified result retains that
publisher identity. Byte/entry quotas, a free-space check and LRU eviction bound each fresh
private cache. Reconstruction can publish an output file atomically without overwriting it.

Fourteen focused tests and strict crate Clippy pass. Owned caches now reopen after process exit;
their UID/directory-bound marker, exclusive lock and bounded persisted index prevent arbitrary
directory adoption. Corrupt/incomplete mutations are refused without a recovery sweep.

The normal CLI now exposes explicit offline publication and reconstruction: `content publish`
uses the existing encrypted node identity, and `content assemble` requires an independently
trusted publisher key and explicit local cache paths. Both have real separate-invocation
roundtrip evidence. By default they do not announce a provider, distribute chunks or resolve a public name.
See the [operational commands](OPERATIONS.md#offline-content-commands).

Explicit `content publish --contribute` now adds complete publication through an already
configured contribution service: the authorized local stream carries bytes from the user's
private cache, and success requires the original full object in the actual configured cache,
durable ownership and live registration. No hand-written `serve` step or filesystem ownership
change is needed; `site pack` bundles use the same command. The
[publish/restart/independent-consumer proof on `ac782769`](https://github.com/VOLPAROSSA/volparossa/actions/runs/34221501655)
passes with all 2,097,628 site bytes and the original manifest/expiry. This is one complete
local copy, not the outstanding external retention, replica repair or global availability promise.

The integrated runtime provides explicit `content serve` / `content fetch` / `content stop`.
A provider signs only a short-lived generic service location. A consumer asks its current
authenticated control Relay to find services, verifies their node-key signatures, then fetches
the exact independently trusted manifest over existing policy-authorized MPTCP/TLS routes.
The DHT and control lookup carry no object IDs, URLs or publication-key catalogue. At most
16 offers and 64 explicitly registered publications are supported. Compilation and focused
provider/discovery/control/CLI tests pass. The first independent-provider KVM attempt on
`aa634ce1` failed before retrieval. The later `fdcb64d3` run now completes live discovery with
two verified offers. With application TLS, `a20efb71` then reconstructs the complete object
through native and HTTPS commands, including partial origin ranges. Its final evidence gate
uses the wrong fixture Exit interface address; corrected raw-record validation passes, but the
original scenario still failed before its final explicit service-stop steps. Cleanup completed
with unchanged host state. The `472b6e7a` rerun again completes both two-provider downloads,
but a subsequent lookup yields no usable peer offer and HTTPS falls back to the complete origin
body. The same repeated-lookup defect blocks the new C03 sequence after its first real download.
The subsequent native-role/content-offer ownership and unchanged-policy refresh fixes preserve
valid provider offers without renewing their deadlines. The fresh `e592b610` provider scenario
now passes native and both HTTPS cases, including exact partial ranges, physical captures and
cleanup. That scoped explicit-object proof does not establish general NAT reachability or a
complete C02 claim. Automatic placement, retention and name lookup are not supplied by it,
and C06 remains open. The newer
[normal-user run on `10f63244`](https://github.com/VOLPAROSSA/volparossa/actions/runs/34178615941)
also passes publication/import, service serving, independent protected retrieval and user
export/assembly of the exact signed object across separate accounts. This does not supply
stable-name discovery, retention repair or general website hosting. The new explicit
`fetch-name` slice adds publisher-local name retrieval over those same protected provider
streams: original signed envelopes, highest observed revision, durable cache-bound conflict/
rollback floors, and caller-owned output without a prior manifest file. Public serving must
opt in; names stay out of DHT records and private-message metadata stays excluded. The
[separate live name phase on `d2f886c8`](https://github.com/VOLPAROSSA/volparossa/actions/runs/34186359414)
passes retrieval of nine chunks / 2,097,275 bytes from two providers without the Client's
manifest copy, into a separate user's private file. Both actual relay paths, account isolation
and cleanup pass. Source-specific evidence is recorded in
[implementation status](IMPLEMENTATION_STATUS.md); no globally newest-version, retention or
general website-hosting claim is implied.
The newer normal HTTPS command is described below; [implementation status](IMPLEMENTATION_STATUS.md)
retains the source-specific network and Quality results.

The runtime uses a real provider application-TLS layer inside the protected path. The
existing libp2p TLS identity proof pins the endpoint to its verified signed offer; exact SNI and
content ALPN are required. A new temporary consumer identity is used per TLS session, not the
permanent Client key. This provider authentication does not replace the separately trusted
publisher or origin descriptor. The normal flow also performs bounded TLS shutdown instead
of dropping a successful session as an aborted transport.

The new stream API pulls only missing chunks from each provider, authenticating bytes before
storage and bounding requests, bytes and exchange/session time. A real separate-process proof
in a disposable loopback namespace reconstructs 2,097,275 bytes / nine chunks after the publisher
directory/key are removed: the first replica supplies five chunks / 1,048,699 bytes; the consumer
restarts and the second supplies only the remaining four / 1,048,576 bytes. The reconstructed
SHA-256 is `add0724d8dbe68407d544c24714128732a29c4880cff30d283b1ada9362e3767`.

The dedicated [`content` KVM scenario on `f0a906ca`](https://github.com/VOLPAROSSA/volparossa/actions/runs/34146922945)
passes through the existing real MPTCP/TLS ingress, two WireGuard legs and exact policy-authorized
destination. Both providers observe the Exit address; ten complete, zero-drop boundary privacy
captures and cleanup with unchanged guest state pass. This completes C01. Two replica processes
on the same destination do not establish
distributed provider discovery, independent provider nodes, durable offline availability,
HTTPS authenticity or speed gain. No browsing capture is enabled. [Testing instructions](TESTING.md#native-content-storage-foundation)
and crate documentation record these limits. Only existing workspace dependencies are reused.

### Recipient-encrypted native messages

The next implemented library slice uses the existing RFC 9180 HPKE profile
(X25519/HKDF-SHA256/ChaCha20-Poly1305), plus the native sender-signed manifest. The sender must
already trust the recipient's encryption key; the recipient must already trust the sender's
signing key. Neither association comes from the storage peer. Up to 4 MiB of plaintext is
encrypted before chunking; associated data binds sender, opaque name, type, revision, lifetime
and envelope length. Caches contain only ciphertext. The library keeps recipient keys in memory
and returns verified plaintext in zeroizing memory; it does not implement a key store.

The normal CLI now supplies `content recipient-key`, `content publish-message` and
`content open-message`. Its versioned recipient profile uses the pinned HPKE implementation's
[RFC 9180 section 7.1.3 DeriveKeyPair](https://www.rfc-editor.org/rfc/rfc9180.html#section-7.1.3)
with input `"volparossa/message-recipient/v1\0" || Ed25519 secret seed`. This is a
domain-separated derivation, not raw Ed25519-to-X25519 conversion. Only the existing encrypted
identity is stored; no additional plaintext private-key file is provisioned. Passphrase changes
preserve the recipient key, identity rotation replaces it, and compromise of the identity also
compromises messages addressed to that key. One node identity means one recipient key across
local profiles, not profile isolation. Public keys still need independent authentication.
The local CLI smoke reconstructs from two partial ciphertext stores across identity reloads,
rejects a wrong recipient/sender and overwrites, and preserves a 0600 plaintext output. This
does not upgrade the older test-only-key network evidence into a normal-CLI network proof.
The network harness now provisions its disposable encrypted identities through normal `init`,
exports only `recipient-key`, and uses `open-message` on the retrieved cache. Its six local
checker/cleanup/process tests pass, including real CLI compatibility with the existing fixture
publisher. The [fresh network run on `4c4c8954`](https://github.com/VOLPAROSSA/volparossa/actions/runs/34170523962)
now passes with normal recipient CLI decryption of the retrieved ciphertext, exact bytes,
wrong-recipient/no-clobber checks, ten complete zero-drop captures and unchanged-host cleanup.
In that `4c4c8954` run the sender remains a fixture; neither automatic key discovery nor a
mailbox is introduced. The additive `f0936007` harness now composes normal private
publish/import/serve/fetch/export/open, with the new sender's key and input removed before
remote retrieval. Its local checks pass; its
[exact VM run](https://github.com/VOLPAROSSA/volparossa/actions/runs/34182554210) reaches successful
transfer and recipient opening but fails the final privacy check: an empty DNS-cache provider
advertisement causes three outgoing Exit-to-Client discovery attempts. The availability correction
passes targeted checks but needs a fresh network run; the original run stays failed, not a
completed normal-sender or full C07 network claim.

Five focused tests, strict crate Clippy and an isolated separate-process transfer/decryption
proof pass. The [`content-message` protected-route KVM scenario](https://github.com/VOLPAROSSA/volparossa/actions/runs/34149009080)
also passes on `b1082645`, including actual recipient decryption, ten complete zero-drop boundary
captures and unchanged guest state. Its disposable
test-only recipient key and cleartext output have explicit ownership checks and cleanup; they
are not an example of production private-key persistence. Public sender identity, length and
lifetime remain visible. Key discovery, a mailbox, anti-spam/acknowledgements, retention, forward
secrecy after key compromise and email interoperability are not supplied by this slice. C07
therefore stays open rather than counting the configured fixture as a complete messaging service.

The next executable slice adds known-contact mailboxes rather than requiring a manifest to be
handed to the recipient for every message. Normal `content mailbox invite/enroll/send/receive/serve`
commands bind one sender and recipient to two explicitly trusted providers. A private durable
index supports bounded listing, original expiry, quota refusal and acknowledgement tombstones;
the original encrypted messages survive provider-store reopen. Fresh provider offers are found
through the Client's existing control Relay, with no public mailbox/contact index or direct
Client-provider discovery. Two local wire tests prove authenticated deposit, reopening, private
listing, retrieval/decryption and acknowledgement; three disk-store tests and a four-node real
libp2p exact-lookup test also pass. These are scoped local results, not yet the normal protected
network mailbox proof. C07 remains unchecked. Automatic contact discovery, retention repair,
forward secrecy and ordinary email interoperability are still separate work.

### Cooperative-origin HTTPS retrieval

The first HTTPS route is implemented in `origin_https`: every consumer performs its own real
TLS 1.3 hostname/CA verification before obtaining a canonical origin descriptor. A separate
in-memory `OriginAuthorizedManifest` binds the exact resource and HTTP validity; ordinary native
manifests do not acquire implicit HTTPS authority. The current explicit profile is anonymous
GET, status 200, identity encoding, `application/octet-stream`, public/max-age, canonical HTTP
Date and no cookies, credentials, variants, redirects or nonzero Age. Unsupported responses
are rejected by this adapter, not silently declared shareable; a general application fallback
for unsupported sites still needs integration.

Seven real-TLS tests and a disposable separate-process demonstration pass. A 777-byte origin
descriptor authorizes 2,097,275 payload bytes reconstructed from two partial caches, with no
origin body transfer. Missing chunks invoke one full origin download checked against the same
manifest; changed bytes, wrong CA/name, stale metadata and partial publication are rejected.
No new authority is imported from peers or persisted by the consumer. The
[`content-https` KVM scenario on `2de8209f`](https://github.com/VOLPAROSSA/volparossa/actions/runs/34150683819)
passes the same full-body-fallback sequence over protected routes, with ten complete zero-drop
boundary captures and unchanged guest state.

The next implemented version adds exact missing-chunk Range fallback. Eleven real-TLS tests
and a separate-process disposable-loopback proof pass: five cached chunks supply 1,048,699 bytes,
then four 206 responses supply only the missing 1,048,576 bytes. Each range binds the original
offset, length, total and authenticated chunk hash; wrong/stale/changed responses are rejected.
An origin that ignores Range can still supply a fully verified 200 response, with its full cost
reported. Original authorization never renews. The
[Range protected-route proof on `6cf2394b`](https://github.com/VOLPAROSSA/volparossa/actions/runs/34151753705)
passes with the exact four missing ranges, nine protected flows, ten complete zero-drop boundary
captures, zero remaining owned objects and unchanged guest state; exact-source Quality also passes.
This requires publisher support and proves neither faster total retrieval nor
browser/generic-web/TLSNotary integration.

The normal `volparossa content fetch-https` command now composes these operations in the agent:
`--url` supplies the exact canonical HTTPS resource, `--metadata-path` its canonical same-origin
descriptor path, and `--cache` / `--output` name new agent-owned destinations. Unlike native
`content fetch`, it accepts no independent publisher-key argument: its own authenticated origin
descriptor supplies that authority. Origin and provider application streams use the existing
policy-authorized protected MPTCP path; the consumer never takes a direct provider shortcut.
Peer discovery failure can fall back to the authenticated origin without claiming a peer success.
Missing chunks use exact ranges; a fully verified 200 response may satisfy an ignored Range,
with its full transfer cost exposed in the receipt.

Content-service registration is owned by the explicit listener, not by native Relay/Exit
advertisement readiness. A reproduced coupling bug withdrew cache offers during native
advertisement withdrawal; the corrected actor preserves the independent offer without renewing
its deadline. Explicit service stop, policy replacement, shutdown and original offer/policy expiry
still invalidate it. The local regression passes; a complete multi-node rerun remains necessary.

Both normal fetch commands also accept explicit `--reuse-cache` for an existing owned store.
Resumption skips verified chunks, never adopts an unrelated directory, overwrites an output,
or substitutes cached metadata for fresh HTTPS-origin authorization. Real native partial-transfer
and interrupted-TLS-body tests pass; the latter requests only the remaining Range after reopen
and keeps the original authenticated expiry. Per-session verified byte counts survive failures
and eviction, so old cache hits are not reported as new network delivery.

Default trust comes from Debian's system certificate bundle. Optional `--ca-file` is a bounded
explicit public PEM input used only for this operation, not an installed interception CA or a
certificate/hostname-verification bypass. CLI/agent/control tests and strict Clippy pass locally;
the normal command's exact protected-route KVM proof now passes on `e592b610`, with two
independent providers and four exact fallback ranges. This is not complete C02/C08 or automatic capture
of arbitrary browser HTTPS, personalized response sharing, or generic unsupported-site adapter.

The explicit one-shot `content browser-download` adapter now has local process tests and an
executable protected-network harness (`d82a64f`), whose checker passes locally. A same-overlay
origin-only reference fixture (`49a0253`) uses the existing origin verifier and an ordinary Client
socket; the integrated comparison harness records actual monotone durations and reports the
result even when the origin is faster. The complete sequence now passes on `fed8ab33`, including
native static-site publication/retrieval after publisher-application exit. Its peer-assisted
HTTPS download is slower than the origin reference, so C08 stays open. The ordinary HTTPS CLI
now has `--source-strategy auto|peers-first|origin-only`: auto prefers origin in the absence of
recent comparable costs, otherwise bounds fresh known-peer lookup and transfer together. Local
verified chunks remain reusable under fresh origin authority. Explicit peers-first exploration
is not a latency guarantee; source selection does not make unsupported HTTPS sites shareable.
The new strategy requires its own integrated measurement.

### Own-origin representation digests without a custom descriptor

The additional explicit `--origin-digest` application mode implements the origin-metadata option
without a VOLPAROSSA-specific descriptor endpoint. Every consumer obtains a SHA-256
`Repr-Digest` and exact representation length from its own hostname/CA-verified TLS 1.3 HEAD
exchange. This follows the representation/content distinction in
[RFC 9530, Appendix B.2](https://www.rfc-editor.org/rfc/rfc9530.html#appendix-B.2): HEAD
`Content-Digest` is not substituted for the resource's representation digest.
The first profile deliberately supports anonymous public identity-encoded binary objects and
one canonical SHA-256 entry, not arbitrary responses or every valid digest-field combination.

A bounded protected-provider query returns an original signed chunk index matching the whole
hash and length. The signature establishes only index consistency, not origin provenance.
All ordered bytes must pass whole-object verification before Ready, atomic output or automatic
public contribution. The live HTTP/monotonic deadline remains separate from the native index;
neither a replica journal nor a peer key becomes reusable HTTPS authority. Normal publication
retains the original signed index without enabling name lookup or extra replication implicitly.
The provider lookup publishes no per-object catalogue in the DHT.

The normal agent, local-control, fetch CLI and browser-download adapter compose this mode with
the existing measured source choice and two-provider transfer. If peers cannot provide the
whole verified representation, their workers end before one full protected origin GET. Unlike
the cooperative descriptor, a whole digest cannot authorize individual guessed ranges; this
first mode therefore does not combine partial origin ranges. An absent/unsupported digest
currently returns unavailable, not arbitrary peer trust. Unsupported-site/witness integration
remains separate work, with any extra trust requiring the user's explicit choice.

Real local origin-TLS and provider-stream tests, CLI-process checks, strict scoped Clippy and
the additive harness checks pass. The
[protected-network run on `f3abee8e`](https://github.com/VOLPAROSSA/volparossa/actions/runs/34212634858)
now verifies cold HEAD+origin GET, then cold HEAD+two-provider delivery with zero origin body,
the exact original transport index, same output hash, physical captures and cleanup. The
peer-assisted operation takes 9.230 seconds versus 2.577 seconds for origin-only: all 2,097,275
origin payload bytes are avoided on the peer hit, but there is no latency benefit. C08 remains
open; explicit peers-first is not evidence of successful measured automatic peer selection.

The next implementation removes two concrete limitations without changing the provider wire:
known peers are refreshed before waiting for a new full DHT round, and independently signed
compatible transport indexes stay paired with their actual providers. Their complete ordered
chunk lists, whole digest, length and public type must agree; the final own-origin hash check
still authorizes output. One writer distributes missing chunks across at most two workers at
a time, each selecting its provider's original index. Native/named exact-index behavior and
private-content exclusion remain unchanged. Real local complementary-provider tests and
targeted agent checks pass. The [new network proof on `3357169e`](https://github.com/VOLPAROSSA/volparossa/actions/runs/34218261300)
also passes with both independent indexes, complete reconstruction and zero origin body.
Recent lookup replies arrive in 42/64 ms; the entire peers-first operation takes 4.915 seconds
versus 2.544 seconds origin-only. Eliminating the earlier DHT wait does not yet make this
fixture faster than its origin or complete C08.

The next automatic-selection implementation also accounts for the separately measured digest
index flows. Two lookups overlap under the original deadline; successful complete delivery may
attach their short-lived cost to the exact useful provider hints without creating new hints or
renewing validity. Automatic admission requires this measurement and rechecks remaining payload
cost after the actual index round. The fixed 4-Mbps origin-uplink comparison on `2769761c`
completes a genuine automatic two-provider hit: 4.092 seconds versus 6.308 seconds origin-only
for complete commands, with zero origin body. Its workflow fails at two checker-shape/accounting
errors; the retained HTTPS raw evidence passes after those narrow corrections. Later phases
were not reached, so this is not a full workflow pass. The single bounded benefit does not
replace the earlier fast-origin trials or complete C08.

### Bounded post-download redistribution

The first C03 implementation adds a separate versioned exchange over the existing protected
content stream. An explicitly shareable publication retains its original signed manifest,
expiry and chunk hashes. A storage-only replica checks signature self-consistency and bytes;
it does **not** establish a trusted publisher, web origin or recipient. A later consumer still
supplies independent native authority or obtains its own origin-authenticated HTTPS descriptor.

The earlier foreground implementation used at most two concurrent provider streams.
A production-protocol test over backpressured streams proves overlapping progress,
exclusive in-flight chunk ownership and bounded reassignment after missing/failed chunks;
reconnection does not reset the original deadline or request budget. Focused tests and strict
Clippy pass. The [exact `b22a9153` VM](https://github.com/VOLPAROSSA/volparossa/actions/runs/34193391288)
also proves 933,365,936 ns of overlapping provider bulk-payload windows using kernel arrival
timestamps, with exact reconstruction and complete captures/cleanup. This is not measured speedup.
The later `b0e7c36` correction retains verified partial progress after a failed parallel stream;
three duplex variants and strict agent Clippy pass locally, without extending that older VM result.

The user's 2026-09-08 adaptive-connection revision is now being applied first to cache workers.
Native/named retrieval has a dynamically sized coordinator and starts only assigned candidates,
with one shared resource lease per actual protected stream. Beyond its initial pair, extra
missing-content coverage or a measured aggregate-throughput probe can justify another worker;
redistributing a fixed bottleneck among peers is not itself a throughput gain. Unhelpful probes
stop further growth; memory/descriptor scarcity and system pressure drain surplus streams after
their current chunk. Original authority, exclusive chunk ownership and the deadline stay intact.
The core has no replacement two/eight-worker ceiling, but the current discovery message remains
bounded to sixteen candidates and the HTTPS source planner still selects pairs. This does not
yet generalize control peers, Wi-Fi neighbors or backend path capacity, nor prove owner fairness
or three-provider protected-network operation. Those scopes remain separate work.

An explicitly configured agent replica cache can pick up other chunks from a recently used
provider after a successful foreground download. No new provider discovery or route is created
for this job. One job is allowed at a time, with at most four chunks and 1 MiB of content-protocol
bytes in both directions, including selector, request, metadata and frame overhead. TLS,
WireGuard and lower-layer overhead are additional, not counted as useful content. Four full
256-KiB chunks therefore do not fit that wire budget. The separate private cache has its own
byte/entry/free-space limits and never evicts existing chunks to admit optional work. Original
expiry is not renewed; copying increments a locally bounded hop count, not a proof against
malicious hop rewriting. Exact interests remain inside the protected stream, not in the DHT.

Admission requires fresh read-only traffic samples on the explicitly configured sharing links.
The agent now uses a distinct v3 exchange with one receiver credit per chunk, never a silent
v2 fallback. While the provider waits for its next credit, the receiver takes another fresh
sample; a busy sample withholds credit until quiet, resuming the same exchange only within its
original deadline and reserved budget. Unavailable accounting fails closed; cancellation or
deadline expiry ends the session without renewing authority. Credits, stop
and finish remain inside the original protocol-byte limit and deadline. Waiting holds neither
the provider's registry mutex nor an open provider cache. The older v1/v2 protocols remain
available to existing explicit callers, without inheriting this new pacing claim.
A new foreground content download or service stop cancels the job. A conservative full-budget
cooldown bounds its configured average rate; the 30-second overall limit also closes slow jobs.
One already credited chunk may overlap new owner demand. These configured-interface samples
are not all-link/per-flow accounting, radio fairness or a no-slowdown/speedup guarantee. The job
does not subtract its own estimated bytes from counters; samples run at quiet credit boundaries,
where residual packets may conservatively postpone the next credit rather than renew any budget.
This bounded pause/resume is not an integrated contention or completed C04 proof.
The new `910a3ac` harness requires real owner UDP traffic during three-chunk Q uptake, allows one
already credited chunk, then requires provider-payload silence and resume on the same connection.
Its local seed/capture/evidence checks pass; the actual contention VM and C04 remain pending.
Original replica manifests, hop counts and retained chunk IDs now persist in a private,
cache-ID-bound, atomically replaced journal (at most 64 records / 8 MiB). Subsequent uptake merges
with previous valid records; partial replicas retain their original expiry. Explicit
`content serve --reuse-replica-cache` validates the original signature, cache ownership and live
chunks before registering them. Missing metadata grants no authority; foreign/corrupt records
are refused. Before another uptake attempt, bounded maintenance now reclaims only expired
journaled chunks without live replica or explicit foreground references. It preserves unknown
files, refuses mailbox-owned stores and uses measured remaining capacity; it neither renews
expiry nor evicts live content. Two core tests and one runtime filter pass, including real uptake
after a full cache releases an expired unshared chunk. These advance an explicit library clock,
not wall-clock or VM time. Quota still pauses uptake when no eligible capacity can be reclaimed.
No boot service, retention repair or storage-peer publisher authority is introduced; full C04
and an expiry-maintenance network sequence remain unproved.

Five focused duplex tests pass, including actual uptake followed by re-serving, quota without
eviction, exclusions/duplicates, original expiry/hops, malformed data and a hard deadline.
Existing v1 provider tests still pass. Three new persistence probes cover actual credit-uptake,
merge, original expiry and re-serving after publisher removal and store reopen; two agent
tests cover explicit restoration, missing journals and full/duplicate registration handling.
Strict content/agent/CLI/local-control Clippy passes. The `e592b610` network run completes v3 Q
uptake and an independent Client's Q retrieval after the original provider stops, but its final
capture gate remains failed because remote route owners survive the replicator's disconnect.
The next fixture also stops and explicitly reopens the replica service from its journal before
that final retrieval. Its [live run on `603cec9d`](https://github.com/VOLPAROSSA/volparossa/actions/runs/34178099281)
passes uptake, provider removal, journal reopen and independent Q retrieval with complete
physical captures and unchanged-host cleanup. Retention repair and global contribution/fairness
remain absent; that older run covers C03's bounded-diversity criterion. The newer owner-contention
run below covers C04's local bounded-contribution criterion, not those wider missing functions.

### Automatic contribution from actual downloads

The explicit `content_contribution` integration now joins verified foreground reception to the
same bounded cache/provider/journal rather than requiring a seed manifest and manual initial
Serve. It starts an empty or restored service after Discovery starts, queues successful public
native/named and freshly origin-authorized cooperative/digest HTTPS objects, and copies small batches
without live-content eviction. The existing extra-chunk exchange and local copy share a single
background owner. Name lookup retains the original independently trusted publisher authority;
no URL, private-message payload or reusable HTTPS authority enters this automatic public queue.
The [source-offline/agent-restart/independent-retrieval run on `f76ac97a`](https://github.com/VOLPAROSSA/volparossa/actions/runs/34211580709)
passes: an empty automatic service admits a completed normal P download, retains its original
journal across a real agent PID change after source shutdown, then serves all 524,609 bytes to
an independent Client. Twenty complete zero-drop captures and unchanged-state cleanup pass.
This does not introduce global placement fairness, retention repair or generic HTTPS capture.

The preceding measured-source selection now has a
[passing exact-source run on `8830a57a`](https://github.com/VOLPAROSSA/volparossa/actions/runs/34205965849):
auto chose origin before peer payload, taking 2.684 seconds versus 2.554 seconds for explicit
origin-only on the same cold object/protected route. This is live origin-preferred behavior,
not a speedup or evidence for successful automatic peer selection. C08 remains open.

## Integrated functional checkpoints

- [x] C01: bounded real chunk storage, authenticated manifests and corrupt/missing-part rejection;
  protected-route transfer verified on `f0a906ca` (source-scoped evidence above).
- [x] C02: real multi-peer discovery/fetch/reassembly and appropriate partial origin fallback ([`d2f886c8` network proof](https://github.com/VOLPAROSSA/volparossa/actions/runs/34186359414)).
- [x] C03: bounded opportunistic redistribution improving reachable chunk diversity ([`603cec9d` extra-Q uptake and subsequent replica retrieval](https://github.com/VOLPAROSSA/volparossa/actions/runs/34178099281)).
- [x] C04: local owner-priority network/storage behavior and bounded contribution under contention
  ([`fed8ab33` real owner-load pause/resume, replica reopen and Q retrieval](https://github.com/VOLPAROSSA/volparossa/actions/runs/34203089267),
  together with bounded quotas/min-free-space and foreground cancellation). This does not claim
  global fairness, general disk-I/O QoS or an unconditional no-slowdown guarantee.
- [x] C05: independent DNS validation, correct expiry and no peer-induced policy bypass ([`b172d11f` protected upstream/peer/local/fallback proof](https://github.com/VOLPAROSSA/volparossa/actions/runs/34192821990)).
- [x] C06: signed public publication remains retrievable after its publisher goes offline ([`603cec9d` original-node-stop/replica-reopen proof](https://github.com/VOLPAROSSA/volparossa/actions/runs/34178099281)).
- [x] C07: an intended recipient retrieves and decrypts a replicated message after sender exit ([`b172d11f` sender-app-exit/route-disconnect/inbox proof](https://github.com/VOLPAROSSA/volparossa/actions/runs/34192823996)).
- [ ] C08: agreed existing-web application integration and measured benefit over origin retrieval.

Start with the common chunk/manifest/provider substrate and a real publish/retrieve/offline
example, then reuse it for redistribution, DNS and messages. This is implementation ordering,
not removal of the requested existing-web integration or other checkpoints.

## HTTPS integration decision: separate retrieval from origin authentication

The user asked on 2026-09-07 to find/build a safe and fast way to share existing HTTPS
content too. The proposed implementation uses an explicit application integration with
three authentication routes into the same chunk store. It does not decrypt another user's
TLS records or replace the browser's certificate authority. The first cooperative-origin
route is implemented above; browser integration and the other existing-web proof routes are
still design work, not delivered compatibility.

| Route | Authentication before using peer bytes | Intended use |
| --- | --- | --- |
| Origin metadata | The consumer obtains a cryptographic representation digest or chunk manifest over its own authenticated origin HTTPS connection. | Small origin validation transfer, large peer payload transfer, where the origin actually supplies suitable metadata. |
| Publisher signature | Verify a manifest/exchange against a key independently authenticated for that origin, including identity, representation and validity. | Publisher-supported resources and native VOLPAROSSA publications; reusable without contacting the publisher for each copy while valid. |
| Witnessed HTTPS | Verify a reusable TLSNotary attestation against an explicitly trusted witness that participated in the original fetch. | Experimental public-resource compatibility where a publisher supplies no reusable proof; additional trust and performance costs remain visible. |

A peer-supplied digest, certificate, key or signature is not an origin trust anchor. An ETag
is an opaque validator, not a guaranteed cryptographic content hash. HEAD or range sampling
does not prove the bytes of a complete object. The first route works only when authenticated
metadata binds the exact expected representation; otherwise it falls back, not guesses.
If only a whole-object digest exists, verify the complete object before exposing its bytes;
independently usable streaming chunks require an authenticated chunk-hash manifest.

Existing integrity metadata can sometimes supply the first route without a new publisher
service: for example, an SRI hash in an authentically obtained page binds the exact script or
stylesheet it authorizes. It does not authenticate arbitrary response headers, grant a new
origin or override cache/CORS rules. Do not reinterpret opaque hashed-looking filenames as
SRI, or claim that this covers arbitrary video pages.

The proof binds the HTTPS origin and resource, request variant, response status, security
and representation metadata, encoded-byte identity, total length and freshness authority.
Content-Type, encoding, redirects, CSP/CORS and credential rules must survive reconstruction.
Expiry is the earliest applicable HTTP/proof/publisher validity boundary. Replication does
not restart Age, freshness, signature expiry or authorization. Origin fallback retrieves
only the same authorized version; an origin change requires a new manifest/version.

### Fast path and fallback

1. The local application identifies eligible public reusable content. Public shareability
   is not inferred merely from absent cookies. Private/no-store, authenticated or ambiguous
   personalized content is not admitted to the public pool; encryption is not permission to
   persist a no-store response.
2. Fetch/validate small origin metadata or a reusable proof and discover candidate holders
   within a bounded foreground budget. Local verified chunks are reused immediately when
   their object authority is still valid.
3. Request disjoint authenticated chunks from useful peers, verify before delivery, and
   assemble the exact representation. Missing/corrupt/stale pieces select another authorized
   source or the origin; unverified bytes never become a successful cache hit.
4. Estimate end-to-end completion including discovery, proof validation, disk access and
   transfer. Prefer the origin when it is faster, the resource is small, or evidence is
   unavailable. Any bounded source race must cancel losers and account for its wasted bytes;
   it is not permission for continuous duplicate downloads.
5. Share retained chunks and small scarce extras only through the common owner-priority
   storage/network budgets. Proof creation and replication must not stall owner traffic.

Measure cold origin retrieval, first proof creation, warm proof verification and warm peer
retrieval separately. Proof-generation cost can be amortized over subsequent eligible hits,
but no universal speedup or origin-load reduction is promised before measured results.

### Browser/application boundary

Start with a native content consumer and publisher-origin fixture. Then connect a supported
browser/application adapter to the same verifier/store rather than duplicating its trust logic.
Firefox exposes a response-body filter; it supplies access to bytes, not origin evidence.
Ordinary Chromium extension request rules do not supply an equivalent body-replacement API.
Chromium's explicit debugger/CDP interception can support a restricted experiment but brings
strong permissions and target-lifecycle constraints; it is not a universal invisible solution.

A publisher-installed service worker can serve verified resources inside its own origin/scope;
a VOLPAROSSA worker cannot take over unrelated HTTPS sites. The Cache API does not enforce HTTP
expiry automatically. Signed Exchanges provide another publisher-supported path but require
appropriate signing certificates and browser support. A localhost page or isolated web app
must not silently acquire another website's origin, cookies or script privileges.

### Existing websites without publisher changes: bounded TLSNotary experiment

The researched TLSNotary release is `v0.1.0-alpha.15`, commit
`47aee45b53e06648c1b2ad3689b367b8c923fdec` (MIT OR Apache-2.0). It has an attestation crate and
reusable presentation examples. It is **not vendored, integrated, or an approved default trust
service** here; importing it requires the normal pinned-source/license/dependency workflow.

The witness must be online during the fetch; a previous ordinary HTTPS recording cannot be
notarized retroactively. Later consumers trust that witness not to collude with the uploader.
An arbitrary peer majority, self-selected verification key or the term "zero knowledge" does
not remove this assumption. No central compulsory witness service is proposed. Locally chosen
trust anchors could allow independent operators, but node identity alone does not confer trust.
Until explicitly configured, this route remains disabled and ordinary origin retrieval works.

The current implementation supports TLS 1.2, not a general TLS 1.3/HTTP3 proof path. There is
no silent downgrade of normal traffic or the required overlay datapaths. MPC and faster Proxy
mode also have different assumptions: Proxy additionally requires an uncompromised
verifier-to-origin network path. Treating an untrusted overlay exit as satisfying that
assumption would be an unsupported security claim.

The upstream full-response reveal optimization avoids per-byte ZK response proving when the
entire response direction is disclosed. Its published 1--51 KB test measured roughly 14.5 s
for MPC and 1.6 s for Proxy. That is not evidence of constant-time large-video processing.
The first experiment should use an anonymous public resource, complete authenticated HTTP
semantics and separate creation/reuse measurements. It must not publish request secrets or
make public discovery a user's URL/history index. Without a suitable proof or configured
witness, use the origin. This keeps unsupported sites working without pretending all HTTPS
resources, authenticated streaming services or DRM media are publicly reusable.

## Primary references

- [TLS 1.3, RFC 8446](https://www.rfc-editor.org/rfc/rfc8446.html)
- [HTTP caching, RFC 9111](https://www.rfc-editor.org/rfc/rfc9111.html)
- [Digest fields and their authentication limits, RFC 9530](https://www.rfc-editor.org/rfc/rfc9530.html)
- [HTTP Message Signatures, RFC 9421](https://www.rfc-editor.org/rfc/rfc9421.html)
- [W3C Subresource Integrity](https://www.w3.org/TR/sri/)
- [Firefox response-body filtering](https://developer.mozilla.org/en-US/docs/Mozilla/Add-ons/WebExtensions/API/webRequest/filterResponseData)
- [Chromium declarative request rules](https://developer.chrome.com/docs/extensions/reference/api/declarativeNetRequest)
- [Chromium debugger API](https://developer.chrome.com/docs/extensions/reference/api/debugger)
- [CDP Fetch interception](https://chromedevtools.github.io/devtools-protocol/tot/Fetch/)
- [Service-worker registration and scope](https://developer.mozilla.org/en-US/docs/Web/API/ServiceWorkerContainer/register)
- [Cache API semantics](https://developer.mozilla.org/en-US/docs/Web/API/Cache)
- [Signed Exchange loading and validation](https://wicg.github.io/webpackage/loading.html)
- [TLSNotary alpha.15 source release](https://github.com/tlsnotary/tlsn/releases/tag/v0.1.0-alpha.15)
- [TLSNotary reusable attestation verification example](https://raw.githubusercontent.com/tlsnotary/tlsn/v0.1.0-alpha.15/crates/examples/attestation/verify.rs)
- [TLSNotary public verifiability and witness trust](https://tlsnotary.org/blog/2026/06/17/public-verifiability/)
- [TLSNotary full-reveal measurements](https://tlsnotary.org/blog/2026/05/19/fast-reveal/)
- [TLSNotary supported TLS versions](https://tlsnotary.org/docs/faq/)
- [TLSNotary Proxy mode assumptions](https://tlsnotary.org/docs/protocol/proxy-mode/)
- [DNSSEC overview, RFC 4033](https://www.rfc-editor.org/rfc/rfc4033.html)
- [DNSSEC protocol validation, RFC 4035](https://www.rfc-editor.org/rfc/rfc4035.html)
