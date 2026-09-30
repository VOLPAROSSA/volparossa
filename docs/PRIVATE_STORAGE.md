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

Availability-aware placement, repair and the automatic contribution controller remain
requirements, **not completed by the current storage primitives**. Explicit owner-coordinated
handoff and the local admission-target control below are building blocks, not automatic
migration or verified network-wide reciprocity. Reopening a provider with `--reuse-store`
preserves its original capacity/free-space floor and its current admission target; it does
not choose a new target. No replication factor or coding scheme is prescribed here.

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
- `target --store ... --target-bytes N` changes only the durable admission target described
  below. It never removes a lease or changes the store's original hard payload quota.
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

## Local admission target and pending drain

The explicit owner can now lower the target **below retained custody** without invalidating
existing leases. This is local payload admission control, not an automatic computation of
the contribution owed for remote physical storage. Five new real-store/provider checks,
the real-process local CLI check, the framed Unix-IPC/service check and two local protocol
checks pass. Strict all-target/all-feature Clippy for content, local control, agent and CLI
also passes. No new live-network contribution-resize proof is claimed here.

For an offline owned store:

```sh
volparossa storage local target --store /absolute/private-store --target-bytes 1073741824
volparossa storage local status --store /absolute/private-store
```

The store must not already be held open by the provider service; its exclusive ownership
lock is not bypassed. For a running provider, use its existing administrative control socket
and independently pin the **local** provider key:

```sh
volparossa --control-socket /absolute/control/agent.sock storage peer admission \
  --provider-key LOCAL_PROVIDER_KEY_HEX --target-bytes 1073741824
volparossa --control-socket /absolute/control/agent.sock storage peer admission \
  --provider-key LOCAL_PROVIDER_KEY_HEX
```

Despite the `peer` command group, these two operations affect only the already attached
local provider. They open no remote route, accept no caller-selected store path, and reject
a different provider key. Omitting `--target-bytes` reads status. The active store's existing
bounded disk worker performs the mutation; no listener or participation role is enabled.

Status separates `capacity_bytes` (original hard quota), `target_bytes`, pending reservations,
committed payload, `retained_payload_bytes`, `pending_drain_bytes` and
`available_for_new_reservations_bytes`. For example, 2 GiB retained with a 1 GiB target reports
1 GiB pending drain and zero new-admission allowance. The existing 2 GiB is still retained,
not claimed as released. New reservations that do not fit are rejected, not queued; existing
reserved uploads, exact idempotent retries, valid restores and renewals keep their authority.
Partial and expired undeleted copies remain fully counted. Reads do not consume custody.

Zero closes new admission; increasing the target cannot exceed the original hard quota.
Neither change alters lease identities, ownership, retention, ciphertext or the filesystem
free-space floor. Lowering the target never deletes another owner's archive. Only a separate
authorized deletion, including the existing owner-coordinated verified handoff, can reduce
retained obligations; without that, pending drain remains pending.

Store schema version 2 persists the target. Opening an exclusively owned version-1 store
atomically migrates its schema/version, initializing the target to its original hard quota.
Older executables reject version 2 rather than silently ignoring a lowered target. Reopening
with current code preserves the target, and a target below usage is not store corruption.

These counters exclude measured SQLite/filesystem/migration overhead. Admission allowance
is **not free disk space**, available replacement custody, automatic migration or verified
1:1 contribution. Status explicitly reports these limitations; the automatic remote-usage
reconciler and safe distributed drain orchestration remain unfinished.

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

## Replica-set candidate: explicit copies and restore failover

`volparossa storage replicas` adds **create, deposit, status, progress, restore, renew and
delete** around the same authenticated peer transfers. It does not invent another transport,
discover provider trust or manage placement automatically. Select two to eight distinct,
independently trusted provider identities and obtain an owner-bound grant from each. This
is a bounded capacity of the current command, not a network-wide replication limit. Different
keys do not prove different operators, devices or failure domains.

Prepare a **new** owner-local set; pair each repeated provider key with its corresponding
grant in the same order. The regular input must already be encrypted and match the full hash.
Creation performs no remote reservation. The existing provider setup, policy-authorized
agent routes and owner-unlock requirements above still apply.

```sh
volparossa storage replicas create --state /absolute/replica-set \
  --input /absolute/encrypted-archive --sha256 ARCHIVE_SHA256_HEX --already-encrypted \
  --provider-key PROVIDER_A_KEY_HEX --grant /absolute/provider-a.grant \
  --provider-key PROVIDER_B_KEY_HEX --grant /absolute/provider-b.grant \
  --lifetime-seconds 604800 --identity /absolute/owner.identity

volparossa storage replicas deposit --state /absolute/replica-set \
  --input /absolute/encrypted-archive --already-encrypted --identity /absolute/owner.identity

volparossa storage replicas status --state /absolute/replica-set
volparossa storage replicas progress --state /absolute/replica-set --identity /absolute/owner.identity
volparossa storage replicas restore --state /absolute/replica-set \
  --output /absolute/new-restored-ciphertext --identity /absolute/owner.identity
volparossa storage replicas renew --state /absolute/replica-set \
  --lifetime-seconds 1209600 --identity /absolute/owner.identity
volparossa storage replicas delete --state /absolute/replica-set \
  --provider-key PROVIDER_A_KEY_HEX --identity /absolute/owner.identity
```

The locked `0700` set retains a bounded, atomically saved `0600` manifest and the original
per-provider journals. Each copy stays bound to its provider, grant, owner, archive ID and
complete ciphertext identity. Repeat **the same `replicas deposit` command** after interruption:
it resumes the retained copies without a `--resume` flag or allocating replacement identities.
A failed copy never rolls back another copy or deletes the source. Partial operations print
`operation_complete: false` and exit nonzero; successful copies remain available.

Restore tries the retained providers sequentially. Only a full length/hash-verified result
is published to a new `0600` output; failed or incomplete data is not exposed. Restore never
consumes a lease. Explicit delete targets **only the named provider**, and a confirmed deleted
copy is not silently uploaded again. This operator-selected deletion is not automatic repair
or a safe distributed capacity-drain controller.

Local status needs no identity unlock. It distinguishes logical ciphertext length from
reserved, committed and uncertain **full-copy payload charges**, including expired copies.
Before each exchange, durable uncertainty prevents a lost confirmation from making a copy
disappear from accounting. An unknown initial reservation requires `replicas deposit` with
the retained input to reconcile the same archive before lease-only progress/delete can work.
Lost deletion confirmation remains charged until a successful explicit retry. Renewal alone
does not prove commitment, so it is followed by authenticated Progress. Reported charges are
conservative local accounting of provider statements, not measured metadata overhead, proven
future custody or usable reciprocal contribution.

All **three focused replica tests pass** (7.36 seconds), including a local Unix/framed-stream
lifecycle with two real SQLite providers, lost confirmations, provider/owner-state reopen,
restore failover and preservation of the surviving copy. This
fixture is not an actual two-provider protected-overlay run, independent-device availability
proof or Signal snapshot validation.

The disposable **`private-storage-replicas`** scenario now has a
[passing real run](https://github.com/VOLPAROSSA/volparossa/actions/runs/36602808623) on exact
source `bff536e2e2fe781be89d573ec264afa2ddacc3f0`. Its original 110-file artifact passes the
exact-source report checker. Independently rebuilding the evidence from all retained phase
files produces exactly the exported aggregate and the report's storage evidence. The ZIP
SHA-256 is `3bc47fb9d80e8406cb773e47e733b3d8f76d5aecba8887016c6bacce43d73d46`.

Two actual stores in distinct disposable namespaces, with independently pinned identities,
each commit 524,326 synthetic opaque bytes in three chunks. The owner accounts for
**1,048,652 physical payload bytes**, not just the one-copy logical length. After removing
the original input, the fixture stops the first provider's content service. Two separate
restores fail over to the second provider, verify the full original length/SHA-256 and leave
its copy intact; no-clobber and the unavailable copy's continued charge are checked too.
Reopening the same first store retains the original identities. Explicitly deleting its copy
leaves the second copy available for a third verified restore. Retried deletion is idempotent;
deleting the final copy leaves both providers with zero leases and charged payload bytes.

The upload, failover and final phases each retain their own drained, zero-drop physical and
control-path captures, with respectively **18 / 4 / 6** completed Exit MPTCP/TLS operations
on the same protected route. The unavailable provider sends zero response payload during
failover; the survivor sends enough for both complete restores. The checker also verifies
the two relay paths, absence of direct Client-to-Exit/provider bypasses and separation from
the selected control relay. The Client cannot read either provider store locally. Private
credentials, grants, journals and input/output files are removed; topology cleanup leaves
zero owned objects, and the guest-parent network snapshots are byte-identical.

This is **explicit two-store service failover**, not independent physical failure domains,
whole-agent restart, interrupted network-upload resume, archive encryption or Signal snapshot
validation. It does not prove automatic placement/repair, measured metadata overhead, safe
contribution-driven drain or network-wide storage credit. The original single-provider proof
is unchanged. Replica-only fixture bounds allow 420 seconds per failover restore and 900
seconds per private phase; core exchanges retain their original 120-second limits without
automatic operation retries.

The [first run](https://github.com/VOLPAROSSA/volparossa/actions/runs/36600197974) on `ba38a6a5`
reaches the final evidence step after the actual two-copy upload, source removal, first-service
withdrawal, repeated survivor restores, same-store reopen and explicit deletion lifecycle.
Its aggregate metadata reports 1,048,652 charged payload bytes initially and zero finally;
private and topology cleanup finish with unchanged host state. The overall result is still
**FAILED**: the builder attempts to read a two-element usage array using an object-only reader.
The first exporter also omits the separate phase route/capture/completion files, so the original
bundle cannot independently establish all protected-path/privacy gates. The original 85 files
remain unchanged and failed; the later passing run above supplies fresh evidence rather than
relabeling this earlier result.

## Next end-to-end proof

### Owner-coordinated replacement candidate

`storage replicas replace` performs one explicit, resumable **A/B → B/C** handoff, using
the existing owner-signed operations and protected agent transport. It is not provider
discovery, unattended repair or permission to move somebody else's archive. The owner
must be online with the original identity, privately retained set and independently trusted
replacement grant. The new grant must permit Reserve, Append, Progress, Finalize and ReadRange,
and its retention must cover at least the original A lease.

```sh
volparossa storage replicas replace --state /absolute/replica-set \
  --from-provider-key PROVIDER_A_KEY_HEX --provider-key PROVIDER_C_KEY_HEX \
  --grant /absolute/provider-c.grant --lifetime-seconds 604800 \
  --identity /absolute/owner.identity
```

No original source file is required. The command fully restores and hashes a surviving
copy other than A/C into owner-private temporary ciphertext storage. It uploads/resumes C
under a durable replacement archive identity, then retrieves **all of C's bytes again**
and checks the original length/SHA-256. A committed receipt alone is insufficient. The
survivor's committed state is reconfirmed before the owner signs Delete for **only A**.
Neither reads nor failed attempts consume B or delete A. This proves current retrievability
when completed, not different physical failure domains or future availability.

Repeat the same command after interruption. Every incomplete retry rechecks the replacement
before source deletion, even if an earlier process reached the deletion phase. A missing
replacement response, quota refusal, unavailable survivor or unconfirmed A deletion remains
`pending_handoff` with `operation_complete: false`; uncertain copies stay fully charged.
Temporary migration therefore counts up to three full payload copies. Only A's authenticated
deletion confirmation lowers that bound back to B/C's two copies. Lost acknowledgements reuse
the exact retained archive/lease and idempotent deletion tombstone, not another reservation.

The additive version-two manifest retains the handoff and all original provider journals.
The existing eight-record limit includes deleted provider history; a full set cannot silently
discard an old identity to make room. The command uses bounded RAM but requires temporary
local disk room for one complete encrypted archive and removes its staging directory on normal
completion/failure. This handoff does not resize a provider, change the contribution target,
or add owner-offline migration authority. Its protected-overlay result is recorded below.
The targeted three-real-store framed-transport test passes, covering lost Reserve,
replacement-read and Delete confirmations, reopen/retry and repeated non-consuming
replacement restores. All four focused replica tests pass together in 11.27 seconds;
these local checks are separate from the protected-overlay proof below.

The real [three-provider handoff run on `721b56f9`](https://github.com/VOLPAROSSA/volparossa/actions/runs/36616700648)
passes its exact-source checker against all 139 original artifact files. Its original source
file is absent before migration. Stopped A leaves three actual copies charged; after the
same-store retry, C is fully verified before A's confirmed deletion reduces the charge to
two copies. B and C each restore the full archive twice while the other service is unavailable.
Six protected MPTCP/TLS route/privacy phases and full cleanup pass; guest host-state bytes
are unchanged (SHA-256 `8e1d848f7788cb4092c5d7215ef7079cc2214346edf45f70d696d65cad0965e1`).
The immutable artifact ZIP SHA-256 is
`6d6d274c2fd526930147c929cb27a96caad05b98726ed73e27ed1146e14ac131`.
This proves explicit owner-coordinated handoff, not automatic resizing/repair, independent
hardware failure domains, archive encryption or Signal backup restore.

Extend the passing two-provider proof to interrupted network upload, whole-agent restart,
source-device-offline recovery and network quota refusal, with privacy and complete cleanup
evidence. The current proof removes the original file and withdraws one provider service;
it does not take independent hardware or the owner's device offline. Finish least-authority
application enrollment rather than treating the administrative socket as that API. Keep
provider statements distinct from measured custody and usable capacity when reconciling
physical usage.
Then add availability-aware redundant placement and repair, with the adaptive contribution
and acknowledged drain/handoff controller above. Demonstrate both a growing target and a
2 GB-to-1 GB target reduction without losing other participants' live data, including the
pending-drain case when replacement capacity is insufficient.

### Native Signal backup round trip

The [exact native Signal trial](https://github.com/VOLPAROSSA/volparossa/actions/runs/36742201942)
on core `90dbea789b57efcbc6cab941e54dfb6a5240511e` and chat
`c897667d76bea8140f0bc5f373404e43cbd54552` passes. Signal exports and encrypts its real snapshot
and referenced attachments; after the original ciphertext is removed, the connector restores
through the real protected core and Signal's importer verifies messages, attachment hashes
and screenshots. The 198,352-byte archive occupies two independently identified provider
stores (396,704 charged payload bytes). Import consumes neither copy; explicit deletion then
returns both stores to zero charged bytes and leases. Twelve protected MPTCP/TLS exchanges,
two selected relay paths carrying data, privacy captures and full private/host cleanup pass.

This is one actual native regression in a disposable guest, not merely opaque-file testing.
Its local upstream mock server still handles registration/relink, its Electron test launcher
does not establish Chromium sandboxing, and the provider namespaces are not independent
hardware failure domains. Production account recovery UX, least-authority app enrollment,
automatic repair/contribution accounting and decentralized Signal messages/calls remain open.
The [implementation status](IMPLEMENTATION_STATUS.md) retains the exact artifact hashes and
earlier failed trials. Other applications can use the same core storage interface without
reimplementing custody or acquiring Signal's private recovery keys.
