# Native content storage foundation

This crate implements real local disk caching and reconstruction for **explicit native
publications**. It is not a completed content-network checkpoint (C01, C02 or C06), a
browser cache, an HTTPS-origin verifier, or a network retrieval implementation.

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
  Cache handles leave their data on drop; reopening/index recovery is not implemented yet.
- Chunk-sized streaming input/reconstruction, integrity checks before each chunk is emitted,
  and an atomic output-file helper that never publishes a partial object or overwrites a
  pre-existing destination. Generic `Write` callers must honor the result after a failure.

Run the actual temporary-disk example:

```sh
cargo run -p volparossa-content --example offline_publication
cargo test -p volparossa-content
```

The example publishes three chunks, copies alternating chunks into two separate disk stores,
deletes the publisher's directory and drops its signing key, then reconstructs the exact
object using the pre-established public key and surviving stores. All example directories
are temporary and cleaned up. This proves local storage/reassembly, **not offline network
availability**. No network discovery, provider transport, origin fallback, automatic
replication, owner-priority I/O scheduling, durable retention, web policy or DNS behavior is
installed or enabled. Publisher input and output-path selection remain caller-authorized;
this crate does not authorize sharing captured/private/no-store traffic.
