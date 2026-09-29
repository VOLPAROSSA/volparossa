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

### Adaptive contribution and safe handoff

The intended controller follows **actual remote physical usage**, including every recovery
copy and any charged overhead. If that usage falls from 2 GB to 1 GB, the local contribution
target also falls from 2 GB to 1 GB. A reduction in logical backup size alone is not enough:
remote copies, reservations and deletion acknowledgements must first be reconciled.

The target is not the same as currently occupied or immediately releasable local space.
Accounting must show the target, committed custody, charged pending reservations and
pending release separately. Reducing a target must never delete another participant's
live fragments. Occupied space can be released only after those fragments have been
migrated to verified, independently placed replacement holders and their handoff has
been acknowledged. Identity, integrity and usable replacement custody must be checked;
a signed receipt or capacity pledge alone does not prove actual available storage or
future availability.

Placement and repair should account for availability and independent failure risks,
maintain the required recoverability and repair missing copies. Temporary repair and
migration copies consume real capacity too: count that overhead explicitly, use bounded
headroom, and never present an in-progress transfer as freed space. If suitable replacement
capacity is unavailable, retain existing custody and expose a **pending drain** instead of
claiming the lower target has already been achieved.

This availability-aware placement, repair, handoff and automatic contribution controller
is a requirement for the next networked work, **not implemented by the current local store
or authenticated stream library**. No replication factor or coding scheme is prescribed here.

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

## Current authorized, resumable library slice

The core now also has provider-issued bounded grants, owner-signed challenge-bound
operations and durable provider/owner/archive/lease bindings around the real SQLite store.
Reserve, chunk append, progress, finalize, range read, renewal and deletion are separate
operations. Fresh connection challenges reject cross-connection replay; exact upload
retries do not charge another copy, and durable deletion tombstones prevent resurrection.
Every reserved copy remains fully charged while partial or expired and until deletion.

The framed wire library operates on an **already protected stream supplied by its caller**.
It neither discovers peers nor establishes the production protected transport itself.
Provider identity must be trusted independently; signed receipts bind the exact request
but remain provider statements, not proof of network-wide contribution or future custody.
There is still no real-peer storage path, versioned core application IPC or Signal
encryption/export/import integration demonstrated by this milestone.

Current focused evidence: 13 authentication, durable-provider and framed-stream tests
pass (four protocol, five real SQLite provider and four framed-stream tests), alongside
eight ordinary resumable-storage tests. The stream tests exercise real signed metadata
and SQLite custody over in-process framed streams; they are not a multi-node network test.
The earlier five local lifecycle and four CLI-process tests cover the separate local commands.

The manual 1 GiB resumable test passed on 2026-09-29 in **93.04 seconds**: it writes half
the synthetic archive to the actual SQLite store, closes/reopens it, resumes the remaining
chunks, finalizes, reopens again and restores twice in bounded ranges, checking the full
length and SHA-256 both times. Restore leaves the committed copy intact. The large test
is deliberately excluded from ordinary CI runs. Reproduce with
`cargo test -p volparossa-content --test private_storage_resumable resumable_one_gib -- --ignored`,
using a disposable, sufficiently sized disk-backed `TMPDIR`. This is neither a Signal
archive nor evidence of remote replication or automatic contribution adjustment.

## Next end-to-end slice

Connect the authenticated store/stream library to actual protected peer transport and
versioned application IPC. Demonstrate real remote deposit, interrupted-upload resume,
provider restart, source-offline restore and quota refusal. Keep provider statements
distinct from measured custody and usable capacity when reconciling physical usage.
Then add availability-aware redundant placement and repair, with the adaptive contribution
and acknowledged drain/handoff controller above. Demonstrate both a growing target and a
2 GB-to-1 GB target reduction without losing other participants' live data, including the
pending-drain case when replacement capacity is insufficient.

The Signal bridge must export a completed upstream encrypted snapshot, including its
referenced encrypted attachments and private metadata, then reconstruct and validate that
snapshot through Signal's importer. Merely restoring an opaque file is not Signal restore.
The same core interface should serve other applications without reimplementing storage.
