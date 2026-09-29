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
is a requirement for the next networked work, **not implemented by the current local store,
authenticated stream library or peer-command candidate**. Reopening a provider with
`--reuse-store` preserves its original capacity and free-space floor; it is not a resize
operation. No replication factor or coding scheme is prescribed here.

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
That local/library milestone does not demonstrate a real-peer storage path, application
integration or Signal encryption/export/import. The next candidate below supplies agent
attachment and peer commands, without treating their implementation as live overlay proof.

Local/library baseline evidence: 13 authentication, durable-provider and framed-stream tests
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

## Peer-command candidate: protected agent attachment

The explicit disposable `private-storage-peer` scenario now exercises the seven commands:
three-chunk opaque fixture upload, committed retry, provider-store close/reopen, source removal,
two complete non-consuming restores, renewal and idempotent deletion. It requires actual
protected Exit flow completions, privacy capture checks and full host-state-preserving cleanup.
The [live VM run on `434ed112`](https://github.com/VOLPAROSSA/volparossa/actions/runs/36589770066)
**passes**: 524,326 synthetic opaque bytes travel in three chunks to a distinct provider,
with 16 completed Exit MPTCP/TLS operations. Reopening the same store preserves the committed
copy; both restores verify the full length/hash after the original source is removed.
Renewal, idempotent deletion, zero remaining leases/charged bytes, privacy capture checks,
complete teardown and unchanged host state pass. This scenario does not substitute for
interrupted-upload proof, a Signal archive,
encryption implementation, independent replicas or distributed contribution accounting.

`volparossa storage peer` adds seven commands: **serve, grant, deposit, progress, restore,
renew and delete**. Unlike `storage local`, these use the running agent's versioned local
control interface. The provider attaches the durable store to its explicit content-service
endpoint; the consumer asks the agent for the independently pinned provider through the
normal protected route. There is no direct TCP/HTTP fallback or alternate unprotected
connection if that route is unavailable. The source-exact run above proves the bounded
single-provider path in a disposable multi-node topology, not independent-device availability
or a complete replicated backup service.

The current socket is an administrative interface, not a completed least-authority API for
arbitrary applications. Owner signing authority stays in the CLI: the agent receives a
provider-signed grant, a fresh provider challenge and the exact owner-signed operation,
never the owner's signing key or passphrase. A successful command requires both the
request-bound provider receipt and the final correlated response on the same agent
connection. Grant issuance authorizes limits; it does not reserve disk or establish a
replica. See [shared-core and application lifetimes](APPLICATION_LIFECYCLE.md) for the
remaining enrollment, per-application authority and lifecycle work.

### Explicit usage

The examples are templates: replace the uppercase key/hash placeholders with independently
verified 64-hex values and use actual absolute paths. They assume an already configured,
authorized running agent and a provider hostname admitted by the signed Exit policy. They
do not install services, enable participation, add policy entries or change host networking.
Use the global `--control-socket /absolute/agent.sock` option if the configured socket is
not the default. Provider and consumer commands run against their respective agents.
The provider needs an enabled relay role, current policy and an approved TCP hostname/port;
it need not also have an active consumer session. The consumer asks the route manager for
the normal protected TCP route, so a separate prior `connect` command is not required.
Grant issuance additionally requires the private store's listener to be attached and live.

On the provider, attach a **new** store with a 4 GiB payload quota and 256 MiB free-space
floor. After a service restart, use the second form to reopen the same owned store; do not
supply either limit with `--reuse-store`.

```sh
volparossa storage peer serve --bind 0.0.0.0:8443 \
  --advertised-hostname storage.example --store /absolute/provider-store \
  --capacity-bytes 4294967296 --min-free-bytes 268435456

volparossa storage peer serve --bind 0.0.0.0:8443 \
  --advertised-hostname storage.example --store /absolute/provider-store --reuse-store
```

Issue one owner's grant, capped at a single 1 GiB copy. The provider public key must be
known independently, not adopted from this command's response. The new grant file is
written at mode `0600`; transfer it privately to the named owner and keep that permission.
Rights `127` permits all seven current storage operations, not future unknown operations.

```sh
volparossa storage peer grant --provider-key PROVIDER_PUBLIC_KEY_HEX \
  --owner-key OWNER_PUBLIC_KEY_HEX --max-payload-bytes 1073741824 --max-leases 1 \
  --rights 127 --max-retention-seconds 1209600 --lifetime-seconds 2678400 \
  --output /absolute/new-owner.grant
```

On the owner device, deposit an application-encrypted archive. `--identity` names the
existing encrypted owner identity authorized by that grant. Omit `--passphrase-file` to
use the no-echo prompt; a supplied passphrase file must already have strict `0600` permissions.
The input's regular-file length and supplied full SHA-256 are checked by streaming before
the first reservation. The complete payload is reserved, then transferred in 256 KiB chunks.

```sh
volparossa storage peer deposit --provider-key PROVIDER_PUBLIC_KEY_HEX \
  --grant /absolute/owner.grant --input /absolute/encrypted-archive \
  --sha256 ARCHIVE_SHA256_HEX --already-encrypted --state /absolute/archive-state \
  --lifetime-seconds 604800 --identity /absolute/owner.identity
```

The **new** state directory is owned and locked at mode `0700`; its bounded journal is
`0600`. Before any Reserve request, it durably records the original provider grant, owner,
random archive ID, ciphertext length/hash and requested deadline. The returned lease and
observed progress are then saved atomically. No plaintext, recovery key, owner signing key
or source pathname is stored in that journal. Keep the journal and owner credentials
privately recoverable: no public backup catalogue or lost-credential recovery is provided.

After interruption, repeat the exact deposit command with **`--resume`**, the same input,
hash, grant and state directory. A known lease is reconciled with signed Progress before
upload resumes. If the first reservation reply was lost, retrying Reserve uses the same
retained archive ID, not a new charged copy. Failures preserve the journal and any provider
reservation. Resume does not silently extend the lease or its original grant.

Once the lease is known, inspect it, restore to a new file, extend its retention explicitly
or delete that one provider copy:

```sh
volparossa storage peer progress --provider-key PROVIDER_PUBLIC_KEY_HEX \
  --state /absolute/archive-state --identity /absolute/owner.identity

volparossa storage peer restore --provider-key PROVIDER_PUBLIC_KEY_HEX \
  --state /absolute/archive-state --identity /absolute/owner.identity \
  --output /absolute/new-restored-ciphertext

volparossa storage peer renew --provider-key PROVIDER_PUBLIC_KEY_HEX \
  --state /absolute/archive-state --identity /absolute/owner.identity --lifetime-seconds 1209600

volparossa storage peer delete --provider-key PROVIDER_PUBLIC_KEY_HEX \
  --state /absolute/archive-state --identity /absolute/owner.identity
```

The renewal interval must fit the provider's retention permission and remaining grant
lifetime. This example grants up to fourteen days per retention request, deposits for
seven days and explicitly renews to fourteen days from that operation's time. It must also
extend the existing deadline; a shorter or out-of-grant request is refused. A new grant
is not interchangeable with an existing lease's original grant.

Progress, renew and delete never create an unknown reservation: if its first reply was
lost, use explicit `deposit --resume` to reconcile it first. Restore reads ranges of at most
16 MiB into a temporary `0600` file, checks the full original length/hash, then exposes the
new output without overwriting anything. It neither acknowledges nor consumes the archive;
repeat it with another new output path to restore again. Delete is permanent removal of
this copy and releases its charge, not proof that an untrusted provider securely erased it.

The agent owns the live store lock; do not concurrently open it with `storage local`.
The listener is part of the shared content service, not an application-owned daemon.
The existing `volparossa content stop` stops that **shared** service, not just one
application's storage attachment; do not treat it as a per-app disconnect operation.
These commands do not yet provide per-application service shutdown, automatic repair,
contribution-driven resize or pending-drain execution.

Focused CLI-unit checks passed for explicit arguments, private journal locking/reopen and
provider/owner binding, unknown-lease refusal and no-overwrite/symlink rules. The local
Unix-IPC fixture uses the actual signed stream protocol and SQLite provider: it loses a
Reserve terminal reply, retries the same archive, uploads two chunks with Progress,
finalizes, reads twice, renews and deletes idempotently. Three agent attachment/grant checks
and two local-control protocol checks also passed. This is not a multi-node overlay run
or a full application process/Signal integration proof; no independent-replica claim
follows from it.

## Next end-to-end proof

Exercise the candidate's real protected peer attachment and versioned agent IPC in a
disposable multi-node topology. Demonstrate remote deposit, interrupted-upload resume,
provider restart, source-offline restore and quota refusal, with privacy and complete
cleanup evidence. Finish least-authority application enrollment rather than treating the
administrative socket as that API. Keep provider statements distinct from measured custody
and usable capacity when reconciling physical usage.
Then add availability-aware redundant placement and repair, with the adaptive contribution
and acknowledged drain/handoff controller above. Demonstrate both a growing target and a
2 GB-to-1 GB target reduction without losing other participants' live data, including the
pending-drain case when replacement capacity is insufficient.

The Signal bridge must export a completed upstream encrypted snapshot, including its
referenced encrypted attachments and private metadata, then reconstruct and validate that
snapshot through Signal's importer. Merely restoring an opaque file is not Signal restore.
The same core interface should serve other applications without reimplementing storage.
