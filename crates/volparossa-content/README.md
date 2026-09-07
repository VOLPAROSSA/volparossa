# Native content storage and stream transfer

This crate implements real local disk caching and reconstruction for **explicit native
publications**. C01's bounded-storage/authenticated-transfer checkpoint has passed a real
protected-route test; this is not C02/C06 completion, a browser cache, an HTTPS-origin verifier,
or an automatic distributed retrieval service.

- SHA-256-addressed chunks, each at most 256 KiB; at most 1,024 chunks / 256 MiB per object.
- Canonical protobuf manifest, at most 64 KiB. Ed25519 authenticates version, publisher,
  creation/expiry, fresh random nonce, message type and payload hash. The payload binds
  native name/revision/content type, ordered chunk hashes/lengths and whole-object SHA-256.
- Verification requires the caller's **previously established publisher public key**.
  A key chosen by a serving peer is not trusted. A native publisher signature is not
  proof of an HTTPS origin or DNS authority. Manifest reuse does not extend its lifetime;
  latest-name resolution and revision anti-rollback remain separate work.
- Fresh, private mode-0700 cache directories only: no adoption or deletion of unrelated
  caller files. Explicit payload-byte/entry quotas, a configurable free-space floor and
  LRU eviction. Zero-byte chunks are rejected; tiny chunks count toward the entry quota.
  Caches reopen using their private UID/directory-bound marker and bounded checksummed index,
  under an exclusive lock. Renaming is supported; copying/chowning a cache is not adoption.
  Interrupted mutations are refused, not silently recovered or swept. Data remains on drop.
- Chunk-sized streaming input/reconstruction, integrity checks before each chunk is emitted,
  and an atomic output-file helper that never publishes a partial object or overwrites a
  pre-existing destination. Generic `Write` callers must honor the result after a failure.
- Canonical, bounded chunk request/response frames over a caller-supplied `AsyncRead/AsyncWrite`
  stream. Peers serve only chunks of an approved native publication; consumers verify every
  response against their independently authenticated manifest. Cache hits skip requests, misses
  remain explicit, and byte/request/deadline limits include unsuccessful requests. This library
  does not dial directly around the overlay or implement provider discovery.

Run the actual temporary-disk example:

```sh
cargo run -p volparossa-content --example offline_publication
cargo test -p volparossa-content
```

The example publishes three chunks, copies alternating chunks into two separate disk stores,
deletes the publisher's directory and drops its signing key, then reconstructs the exact
object using the pre-established public key and surviving stores. All example directories
are temporary and cleaned up. This proves local storage/reassembly, **not offline network
availability**. Fourteen focused tests cover manifests, disk storage/reopening and stream
transfer, including corrupt bytes, oversized frames and silent peers.

The separate `content-acceptance-fixture` executable seeds nine disjoint chunks across two
replicas, removes its publisher store/key, then serves and fetches in separate processes.
A disposable-loopback run reconstructs 2,097,275 bytes across two consumer invocations; the
second reopens its cache and requests only the four missing chunks. The `content` KVM scenario
connects these ordinary application sockets through the existing transparent MPTCP/TLS ingress
and two WireGuard legs to the exact policy-authorized destination. That test passed on `f0a906ca`;
two processes on that one destination do not prove independent provider nodes or discovery.
Do not run the fixture's sockets outside a disposable network namespace/VM.

`private_message` encrypts native messages before storing their chunks, using the existing
RFC 9180 HPKE dependency/profile plus the sender-signed native manifest. Callers must already
authenticate recipient encryption and sender signing keys. Messages are bounded to 4 MiB;
opening verifies all ciphertext before returning plaintext in zeroizing memory. The library
does not persist recipient keys or plaintext. Five focused message tests and a separate-process
disposable-loopback proof pass; the `content-message` protected-route VM test remains pending.
That fixture alone creates an explicit temporary recipient key and plaintext output, excluded
from artifacts and removed afterward. This is not a mailbox/key-discovery service, forward
secrecy after recipient-key compromise, anonymous metadata or complete C07.

No network discovery, automatic route selection for content, origin fallback, automatic
replication, owner-priority I/O scheduling, durable retention, web policy or DNS behavior is
installed or enabled. Publisher input and output-path selection remain caller-authorized;
this crate does not authorize sharing captured/private/no-store traffic.
