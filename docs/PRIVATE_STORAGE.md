# Private cooperative storage

Development scope: reusable core storage for encrypted application backups, including
the separately developed [Signal client](https://github.com/VOLPAROSSA/volparossa-chat).
This is **not** the public cache, a training-data source or the message-delivery mailbox.

## Separate lifecycles

Message delivery can acknowledge and consume an inbox item. A backup restore must not
consume its storage lease. Backup retention, renewal, expiry and owner deletion are
separate operations with separate authorization. They may share protected network
connections, but a message ACK must never delete a backup or free its reservation.

The application encrypts before handing data to the core. Signal retains its identities,
session state and backup recovery keys. Storage providers receive opaque ciphertext,
not a readable conversation database. A hash detects corruption; it is not encryption,
proof of ownership or permission to publish private data. Backup consent never authorizes
public-cache publication or compute training.

## Reciprocal contribution

The user-selected rule is:

`required usable local contribution >= actual remote storage used, counting every copy`

One GB retained at one remote provider requires at least one GB contributed locally.
Two full copies of that GB require about two GB plus counted overhead. Replica repairs
and in-flight reservations must be accounted for without charging a retry twice or
pretending that a promised copy already exists. Logical archive length, reserved bytes,
retained ciphertext bytes, replication and any charged metadata must remain distinct.

A configured disk allowance is not proof that a participant provides reachable storage,
that replicas exist, or that the same allowance has not been promised to several peers.
Receipt-backed distributed accounting and usable-capacity checks remain to be implemented.
No payments, tokens or blockchain are introduced.

## First executable slice: local provider storage

`volparossa storage local` operates an explicit, owner-only store. It does not contact
peers, advertise capacity, enforce network-wide reciprocity or export Signal backups.

- `init --store /absolute/new-directory --capacity-bytes N` establishes a separate
  non-evicting store and persisted payload limit. `--min-free-bytes N` preserves a
  separate filesystem headroom floor.
- `deposit --store ... --input /absolute/archive --sha256 HEX --already-encrypted`
  reserves the entire declared ciphertext length durably, then streams bounded chunks.
  Exact length and SHA-256 must match before the lease becomes committed. The flag is
  an explicit owner acknowledgement, **not** a cryptographic test or an encryption step.
- `status --store ...` distinguishes pending reservations and committed ciphertext.
  These are local payload bytes per stored copy; SQLite/filesystem overhead is not
  represented as verified remote usage and is protected separately by free-space checks.
- `restore --store ... --lease HEX --output /absolute/new-file` verifies reconstruction
  and publishes a new mode-0600 output only after success. Existing output is not replaced;
  restoring twice does not consume the lease.
- `renew --store ... --lease HEX --lifetime-seconds N` changes the local retention deadline,
  not ciphertext or its digest. This owner-only command is not a remote renewal capability.
- `delete --store ... --lease HEX` explicitly removes this local copy/reservation. This is
  permanent local removal, not proof of secure erasure by an untrusted remote provider.

Interrupted or invalid deposits retain their charged reservation until explicit deletion
or a supported retry. A failed deposit reports its local lease ID for cleanup but does not
report a completed archive. Expired bytes also remain charged until explicit deletion;
expiry blocks ordinary restore without silently reclaiming another user's retained data.

Keep source archives and independently recoverable keys until a real restore is verified.
The local trial uses synthetic opaque bytes and does not demonstrate Signal-format validity,
multi-node availability, replication, recovery after loss of all credentials, or working
cloud backup. A provider's restore must eventually be guarded by an authenticated, private
lease capability; a local lease identifier alone is not a remote authentication scheme.

## Next end-to-end slice

Current local evidence: five library lifecycle tests and four real CLI-process tests pass.
An explicitly invoked 1 GiB synthetic-blob test writes the actual SQLite store on the
workspace SSD, closes/reopens it, verifies the complete restored length/hash and deletes
the lease. It passed on 2026-09-29; the large test is deliberately not part of every CI run.
Reproduce with `cargo test -p volparossa-content --test private_storage private_storage_one_gib -- --ignored`,
using a disposable, sufficiently sized disk-backed `TMPDIR`. This is not a Signal archive
or a network replication test.

Connect this separate store to authenticated protected provider transport and versioned
application IPC. Bind private leases, owner authorization, finite renewal and original
object identity; count physical copies using verified custody receipts. Demonstrate real
remote deposit, provider restart, source-offline restore and quota refusal before adding
repair across independently failing providers.

The Signal bridge must export a completed upstream encrypted snapshot, including its
referenced encrypted attachments and private metadata, then reconstruct and validate that
snapshot through Signal's importer. Merely restoring an opaque file is not Signal restore.
The same core interface should serve other applications without reimplementing storage.
