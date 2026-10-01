# Private cooperative storage

Development scope: reusable core storage for encrypted application backups, including
the separately developed [Signal client](https://github.com/VOLPAROSSA/volparossa-chat).
This is **not** the public cache, a training-data source or the message-delivery mailbox.

## One core-owned redundancy policy

Every **new logical storage archive** uses the same core-owned target: two independently
pinned copies of each encrypted fragment, or two complete copies for the legacy replica
format. Applications do not choose a redundancy tier. More providers can spread fragments
more widely; that does not change the copy target. `ARCHIVE_COPY_TARGET` is the shared core
constant. The hidden legacy `--copies 2` argument is only a compatibility assertion;
other values are rejected before creating state or contacting peers.

Previously created higher-copy archives remain fully readable, renewable and deletable.
Their original target and all retained physical charges remain visible; no migration,
silent pruning or relabeling to two copies occurs. Replacement may temporarily retain more
than two copies and must continue counting every uncertain or retained copy until deletion
is confirmed. Single-provider lease commands are underlying custody primitives, not a
different application backup tier or proof of archive redundancy. This fixed creation
policy is not automatic repair, independent-device availability or adaptive capacity drain.

## Separate lifecycles

### Explicit owner-private background maintenance

`storage fragments maintenance` enrolls one existing owner archive for finite,
core-coordinated maintenance. It is a separate unlocked owner process, not another
network node: the shared daemon receives only a public owner key, opaque enrollment
ID and bounded resource request. Owner keys, archive paths, grants and the signed
enrollment stay in its private workspace. The existing operator control socket is
still an administrative boundary, not a completed per-application capability API.

```sh
volparossa storage fragments maintenance enroll \
  --enrollment /absolute/private-maintenance --state /absolute/private-fragments \
  --from-provider-key PROVIDER_A_KEY_HEX \
  --provider-key PROVIDER_D_KEY_HEX --grant /absolute/provider-d.grant \
  --authorization-seconds 604800 --lifetime-seconds 86400 \
  --renew-before-seconds 43200 --maximum-charged-bytes 4294967296 \
  --identity /absolute/owner.identity
volparossa storage fragments maintenance serve \
  --enrollment /absolute/private-maintenance --identity /absolute/owner.identity
volparossa storage fragments maintenance status --enrollment /absolute/private-maintenance
```

To allow automatic repair of **any explicitly selected source provider**, repeat
`--from-provider-key` when enrolling. For example, append
`--from-provider-key PROVIDER_B_KEY_HEX --from-provider-key PROVIDER_C_KEY_HEX`
to authorize A/B/C, and supply the individually signed candidate grants using paired
`--provider-key` / `--grant` arguments. A future replacement provider may also be
authorized as a source, but only when its candidate grant is explicitly supplied.
Neither a discovered peer nor an unrelated pending handoff widens this authority.

One source retains the exact version-one enrollment signature format and fixed-source
behavior. Multiple sources create a version-two owner-signed enrollment; existing
enrollments are not silently migrated. This mode chooses the exact observed uncertain
fragment copy, so a healthy earlier copy belonging to the same provider is not replaced.
Copying resumes first with its retained identity; verified retirement remains charged
and does not cause a second replacement for the same pending fragment. A retry may
perform another real readback, but that is not another placement or freed source space.
The source set contains at most eight explicit identities, matching the bounded
candidate set; identities do not establish independent physical failure domains.
Four targeted maintenance tests pass, including a real signed SQLite-provider trial
where B, rather than the former fixed A source, disappears. It repairs B's exact
observed fragments, resumes the same replacement identity after a lost confirmation
and reopening owner/provider state, restores the removed source twice from C/D while A/B are offline,
and releases B's retained charges only after B returns and confirms deletion. The
rotating renewal/repair engine is exercised locally; this is not an additional
running-daemon/protected-overlay proof of version-two enrollment.

The worker has no independent maintenance timer. The existing core maintenance tick
may issue one live, owner/UID-bound turn when its foreground and shared resource
conditions permit. Both existing upload/download sharing budgets must be explicitly
configured. Each actual signed request is checked before its requested ciphertext
bytes plus framing allowance consume the turn budget and shared quiet-link cooldown.
Background reads use 256 KiB credits; ordinary foreground range reads are unchanged.
Only one storage exchange can occupy the turn's RAM/descriptor reservation at a time.
Foreground activity, owner disconnect, daemon shutdown, exhausted bytes or the one-hour
turn ceiling revoke work; enrollment expiry also stops the owner process. A finite
`--maximum-turns` is available for supervised trials. Quiet sampling and conservative
limits are not a guarantee that a transfer can never affect interactive throughput.

Each turn rotates through **one fragment** for lease reconciliation or renewal and
attempts at most **one replacement** from the explicitly signed candidate grants.
The durable checkpoint preserves this scan position across restart; the original
signed reconstruction manifest and custody journals remain the only placement,
lease and charge authority. Copying intents resume without a second replacement;
verified pending retirement does not prevent repairing another fragment. A complete
survivor and replacement readback still precede source deletion. An unavailable or
unconfirmed original remains fully charged, including after process restart.

The byte ceiling defaults to 128 MiB per turn, including metadata allowance. Enrollment
rejects fragments whose successful replacement would already exceed that ceiling;
explicit foreground repair remains available. Busy links, short remaining grants,
insufficient capacity or insufficient uninterrupted time can leave work pending.
`owner_locked`, `grant_refresh_required`, `charge_limit`, `retry_pending` and revoked
turns are visible states, not completion. Provider grants are never silently extended.
This is one explicit owner enrollment, not automatic archive discovery, device-offline
authority, contribution resizing, an autonomous grant issuer or a guaranteed SLA.

The targeted local maintenance checks pass: real signed SQLite provider operations
preserve a longer existing lease, genuinely renew a shorter one, repair A's fragments
one per pass while A is offline, retain charges across restart, restore the removed
source twice from C/D and finally confirm A's deletion when it returns. Separate core
tests cover owner/UID/token binding, shared leases, byte exhaustion, refusal of an
ineligible loopback link and foreground/EOF revocation. The wire tests separately
prove real signed transfer admission and refusal before provider mutation. Strict
CLI/agent Clippy and formatting pass. A combined running-daemon/protected-overlay
maintenance trial remains required; earlier fragment and Image proofs do not prove
this new worker, and the local checks do not establish positive live-link admission.

The new disposable `private-storage-maintenance` scenario is wired but **not yet
passing**. It reuses the three protected fragment providers and explicitly enables
both sharing budgets on the client's existing guest `cr0` veth; there is no loopback
exception or host network change. Its proposed passing receipt requires actual
core-issued renewal, cursor retention after owner-process EOF, revocation by a separate
foreground journal, and one verified replacement per turn while A is stopped.
The B/C replica set must then support two source-free archive reconstructions, with
all unavailable A copies still charged until A returns and confirms deletion. Cleanup covers all eleven
retained copy records, the separate foreground lease and private owner/enrollment state.
Five pure receipt/cleanup tests and four dispatch/export tests pass; these check the
fixture contract, not the missing live-daemon/protected-overlay result. No reciprocal
credit, capacity resizing, physical failure diversity or owner-device-offline claim is
made by this scenario.

Its first [VM attempt on `53cccdde`](https://github.com/VOLPAROSSA/volparossa/actions/runs/36927623039)
failed at `agent-readiness` with `AGENT_OR_DESTINATION_NOT_READY`, **before any
maintenance operation** (`maintenance: null`). The generated client YAML contained
duplicate `sharing` and `download_sharing` sections: the new scenario emitter and the
existing custody emitter both wrote them. The correction consolidates these settings
in the existing custody function; a targeted test executes the full client emitter
and checks it with the actual Rust configuration parser, including duplicate rejection.
The original failed run remains failed. Its cleanup completed with zero owned objects,
and both host-state snapshots have SHA-256
`9ad34bb217725c3860b1b4ef57bb127a6ad1e0f29f7c2aad632fd05808834ac8`.
The original seven-file artifact ZIP has SHA-256
`7734d310d1c079fc1e86c77c62b6ad9ded11a81b841e1a7a3609e730ba78b141`.

Message delivery can acknowledge and consume an inbox item. A backup restore must not
consume its storage lease. Backup retention, renewal, expiry and owner deletion are
separate operations with separate authorization. They may share protected network
connections, but a message ACK must never delete a backup or free its reservation.

The application encrypts before handing data to the core. Signal retains its identities,
session state and backup recovery keys. Storage providers receive opaque ciphertext,
not a readable conversation database. A hash detects corruption; it is not encryption,
proof of ownership or permission to publish private data. Backup consent never authorizes
public-cache publication or compute training.

### Fragment placement versus transfer chunks

The required end state distributes different encrypted chunks across storage participants,
with redundant copies of each chunk and a private authenticated reconstruction manifest.
The owner restores by gathering and verifying the required chunks; no single provider
needs a complete archive. Contribution accounting counts every actual retained chunk copy
and charged overhead, regardless of how many holders share them.

`storage replicas` deposits the **same complete encrypted archive at each selected
provider**. The separate `storage fragments` path now distributes different encrypted
fragments: its real protected-overlay trial
[36773683946](https://github.com/VOLPAROSSA/volparossa/actions/runs/36773683946)
restores the removed synthetic archive twice after provider A stops, using B/C's subsets,
then deletes all eight copies with exact zero final usage. No provider holds the whole
archive in this trial. Automatic placement, independent replica repair and recovery of
the private reconstruction metadata remain unfinished. Complete-copy proofs are still
not interchangeable with distributed-fragment evidence.

The `image-snapshot` scenario is a verified cross-repository slice: it uses pinned
VOLPAROSSA Image code to encrypt a synthetic quiesced database/assets snapshot with GPG,
passes only that ciphertext through the actual Image Node storage CLI, and requires two
independently hash-verified plaintext restorations after provider A stops. The owner keeps
the recovery key private. In [trial 36901573120](https://github.com/VOLPAROSSA/volparossa/actions/runs/36901573120),
the actual guest report confirms those operations and complete cleanup, but the overall
workflow fails its runner-side report check because runtime-generated synthetic gzip
headers differ between Python versions. Fixed synthetic bytes preserve the exact guest
identity and remove that cross-version dependency. The subsequent complete
[run 36905847039](https://github.com/VOLPAROSSA/volparossa/actions/runs/36905847039)
passes on core `cf4de524ce885af95d0f75fcb53d80254486c27f`: real GPG, actual Node/core
fragment storage, A offline, two B/C decryptions, all-copy deletion, zero owned
objects and unchanged host state. Its original report passes exact-revision replay.
This trial uses pinned Image `e177afeb`, not a newer adapter, and does not establish a
running Immich database, mobile synchronization or general serverless Immich availability.

The `cloud-private-file` scenario has **passed its one-file protected-peer trial**.
It reuses the
same protected topology with Cloud `541cc826fe14ce69cf89a82ecb600ad14dd534c6`:
an actual authenticated synthetic DAV endpoint feeds the pinned Cloud importer,
which encrypts the file and source metadata locally. The endpoint is stopped and
joined before create/deposit, its credentials are removed, and the local encrypted
file is removed before two provider-loss restores. The actual Cloud CLI must fetch
through core fragment storage and complete authenticated GPG/manifest verification
before new plaintext directories appear. Owner keys never go to peers or exported
reports. Retained physical charges, explicit lease deletion, private cleanup and
unchanged host state passed in [run36909989038](https://github.com/VOLPAROSSA/volparossa/actions/runs/36909989038)
on core `41e404a40312f039827f761dea7b90be48d0c21f`; the original exact-source
report also passed replay. This source-bound result does not establish a newer
Cloud read service or an actual OpenCloud server/web UI.

The subsequent catalog/SDK integration uses Cloud
`a67b91fbed42ecd23ba215eb21ef54397fc9f06a`: an encrypted immutable owner selection,
private restoration through the core and authenticated loopback DAV listing and
reads. Its real GPG/OpenCloud SDK local integration test passes with an explicitly
injected storage adapter. The new protected-peer client proof now independently
passes in [run36916040042](https://github.com/VOLPAROSSA/volparossa/actions/runs/36916040042)
on core `5d9d347fc52e4cc13498ed3b6790d1f00de370c3`. The original source and local
ciphertext are absent and provider A is offline before direct recovery, catalog
creation and actual SDK full/range reads reconstruct from B/C. All 32 required
MPTCP/TLS exchanges complete; authentication/ETag denial, private cleanup, retained
physical charges and final zero leases pass. Exact-source replay of the 44
original artifacts reproduces the aggregate; ZIP SHA-256
`f59a2c2baf693b5087c0827c0971589da23bf15610f96c885db6f2bbe0abdaef`.
Range requests still reconstruct and verify the complete encrypted file before
selecting plaintext bytes. This is not the full web UI. Accounts, shared permissions,
writes, peer-distributed catalogs and second-device recovery are not completed.
Preview with
`sh tests/integration/run-alpha-topology-vm.sh --preview --scenario cloud-private-file`;
execution belongs only in the explicitly approved disposable KVM workflow.

## Reciprocal contribution

The user-selected rule is:

`required usable local contribution >= actual remote storage used, counting every copy`

One GB retained at one remote provider requires at least one GB contributed locally.
Two full copies of that GB require about two GB plus counted overhead: the first one-GB
copy and one additional one-GB recovery copy, not three GB. The matching local contribution
is usable space for other participants, not the owner's own retained original archive.
Keeping that original consumes separate local disk space. Replica repairs
and in-flight reservations must be accounted for without charging a retry twice or
pretending that a promised copy already exists. Logical archive length, reserved bytes,
retained ciphertext bytes, replication and any charged metadata must remain distinct.

A configured disk allowance is not proof that a participant provides reachable storage,
that replicas exist, or that the same allowance has not been promised to several peers.
Receipt-backed distributed accounting and usable-capacity checks remain to be implemented.
No payments, tokens or blockchain are introduced.

## Storage immune system and private-content limits

The storage layer is subject to the same principle-led content policy as the network,
cache and compute layers. Privacy is not permission to store prohibited material,
including child sexual abuse material (CSAM). Preventing that use and protecting providers
from abuse are requirements; **the current storage commands do not implement a private
content-classification or distributed abuse-review mechanism**.

The intended design separates three responsibilities:

1. **Source-side admission:** an authorized application can check eligible input before it
   encrypts it, without sharing private files with compute peers. The core currently accepts
   already-encrypted archives and cannot perform that inspection. A hostile uploader can
   modify or bypass local checks. An application assertion, signature or `--already-encrypted`
   flag must never be described as proof that the content was checked or is permitted.
2. **Custody and resource admission:** authenticate owners and operations, enforce grants,
   byte/lease limits and retention, and reconcile real usage and usable contribution.
   Existing signed grants and local quotas address bounded custody; they are not a content
   verdict or completed distributed anti-abuse/accounting system.
3. **Scoped abuse response:** privacy-minimizing reports, evidence provenance, mutual review,
   conflicting-evidence handling, and reviewable restrictions, quarantine or removal.
   Decisions must identify an authorized subject and scope, bind to the correct object/lease
   and revision, and resist replay and fabricated reports. An accusation alone must not
   delete a backup. Unknown ciphertext is not by itself evidence of prohibited content, and
   the public-cache policy gate is not authority to classify or delete private backups.
   A quarantined object must not be automatically redistributed by repair.
   Reversals must be supported where possible; actual deletion is not reversible and must
   not be presented as such. None of this establishes erasure by a malicious remote holder.

Review must not publish plaintext, private filenames, plaintext content fingerprints,
recovery keys or browsing associations. It must not redistribute suspected illegal files
as peer evidence or training data. Use synthetic, lawful fixtures for development. Content
integrity, origin authentication and proof of retained bytes are distinct from a judgment
about what the bytes mean. Ciphertext hashes cannot classify the plaintext; ordinary remote
AI inference would disclose that plaintext to its worker and is not an acceptable shortcut.

The unresolved requirement is an admission and response design that meaningfully resists
malicious uploaders while preserving the agreed privacy boundary. Opaque ciphertext plus
client self-attestation cannot establish the absence of illegal content. Do not claim that
the immune system is complete, all stored content is lawful, or encrypted custody removes
legal risk. No decryption escrow, blanket client-file scanning, or specific confidential-
hardware scheme is selected or authorized by this design note.

See [principle-led governance](DECENTRALIZED_AGENTS.md#principles-guide-rules-not-the-other-way-around)
and the [four-layer overview](../README.md#storage-layer-private-cloud-storage).

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

### Queued investigation: storage erasure coding

Investigate erasure coding for private storage as an explicit extension beyond the
original replication-only v1 scope. Compare it with fragment replication under
intermittent peers and correlated failures: physical storage charge, parallel-read
latency, repair bandwidth, owner-device CPU/memory cost and recovery availability.
This is a queued design investigation, not an implemented format or a promised
reduction in storage contribution. Select parameters against those tradeoffs;
preserve encryption, authenticated reconstruction, actual-byte reciprocity and
safe migration of existing replicas. Repair must not expose plaintext to storage
peers. This does not authorize transport-layer FEC or change existing archives.

First finish the current fragment/provider-loss recovery path. Automatic placement,
repair and safe capacity drain remain required alongside this investigation, not
features that coding alone replaces.

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
discover provider trust or manage placement automatically. Select exactly two distinct,
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

## Fragment placement candidate: redundant pieces, not whole archives per provider

`storage fragments create/deposit/status/progress/restore/renew/delete` composes the
existing authenticated replica lifecycle over **distinct ranges of an already-encrypted
archive**. Select three to eight independently trusted provider/grant pairs; the core gives
every fragment exactly two copies. Deterministic rotating placement spreads those copies
while each provider retains only a subset of the archive. It adds no
new transport, erasure coding, encryption scheme or automatically inferred provider trust.

```sh
volparossa storage fragments create --state /absolute/fragment-set \
  --input /absolute/encrypted-archive --sha256 ARCHIVE_SHA256_HEX --already-encrypted \
  --provider-key PROVIDER_A_KEY_HEX --grant /absolute/provider-a.grant \
  --provider-key PROVIDER_B_KEY_HEX --grant /absolute/provider-b.grant \
  --provider-key PROVIDER_C_KEY_HEX --grant /absolute/provider-c.grant \
  --fragment-bytes 16777216 --lifetime-seconds 604800 \
  --identity /absolute/owner.identity
volparossa storage fragments deposit --state /absolute/fragment-set \
  --input /absolute/encrypted-archive --already-encrypted --identity /absolute/owner.identity
volparossa storage fragments status --state /absolute/fragment-set
volparossa storage fragments progress --state /absolute/fragment-set --identity /absolute/owner.identity
volparossa storage fragments restore --state /absolute/fragment-set \
  --output /absolute/new-restored-ciphertext --identity /absolute/owner.identity
volparossa storage fragments renew --state /absolute/fragment-set \
  --lifetime-seconds 1209600 --identity /absolute/owner.identity
volparossa storage fragments delete --state /absolute/fragment-set --identity /absolute/owner.identity
```

Creation is local only. The owner signs an immutable reconstruction manifest binding the
original ciphertext length/hash, every contiguous fragment range/hash, exact provider keys,
grant digests and original per-copy archive IDs. Existing private journals retain each
subsequently issued lease and receipt; opening them verifies their immutable fields against
the signed root. Keep the complete owner-only state directory independently with recovery
material: neither peers nor the public cache receive this reconstruction manifest or keys.
Fragmentation does not itself encrypt a plaintext input; `--already-encrypted` is an explicit
caller contract, not cryptographic detection.

There are at most 256 fragments, each at most 1 GiB. The default 16 MiB upper fragment size
supports archives up to 4 GiB; larger archives need an explicitly larger fragment size,
within the existing 64 GiB archive bound. Small archives split further to ensure at least
one fragment per selected provider and must contain at least that many bytes. Aggregate
planned bytes and lease counts must fit every original grant before any state or network
allocation. Temporary staging contains at most one fragment alongside a restoring output.

Repeat the same deposit command to resume the original reservations after interruption.
Reserved, committed, uncertain and expired copies remain conservatively charged at their
**actual fragment lengths**, including every retained replica. Missing confirmations do not
release those charges. Unknown initial reservations require deposit retry with the original
input before lease-only reconciliation. Restore independently tries each fragment's surviving
copies and publishes a new `0600` file only after both fragment and complete-archive checks;
repeated reads consume nothing. Delete targets **all** owned fragment copies, unlike the
single-provider replica delete command. Failed deletion remains charged and retryable.

All three focused tests pass, including three real SQLite providers over local signed framed
streams: lost Reserve acknowledgement, durable same-identity resume, subset-only custody,
source removal, two non-consuming restores with one provider unavailable, refusal when both
holders of a fragment are unavailable, renewal and interrupted deletion/retry to zero leases.
Tampering with the signed root or consistently rewriting both unsigned nested archive-ID
records is rejected. This is **local transfer/lifecycle evidence**, not a new protected-overlay
or independent-device proof. The explicit fragment-copy replacement primitive below extends
this lifecycle; automatic repair/drain, measured metadata overhead and network-wide
reciprocal contribution credit remain unfinished.

### Explicit fragment-copy replacement

`storage fragments replace` repairs or moves **one copy of one fragment**, not a complete
backup. It reuses the existing replica transfer, readback, deletion and accounting path:

```sh
volparossa storage fragments replace --state /absolute/fragment-set \
  --fragment-index 0 --from-provider-key OLD_PROVIDER_KEY_HEX \
  --provider-key NEW_PROVIDER_KEY_HEX --grant /absolute/replacement.grant \
  --lifetime-seconds 604800 --identity /absolute/owner.identity
```

The owner supplies a new independently trusted provider for that fragment. The same provider
may already hold other fragments, but cannot be another current or historical holder of the
selected fragment. A surviving copy is required; this command cannot recreate missing bytes
when every copy has disappeared. The owner stays online and signs the operations. It is a
repair **primitive**, not an automatic placement or maintenance service.

Before changing the child replica set, the owner durably signs a placement extension bound
to the exact original reconstruction root, fragment, retiring copy, new provider, grant,
archive identity and initial expiry. The immutable `fragments.json` stays unchanged. Keep
`placement-authorizations.json` with the rest of the private recovery state. Reopening
authenticates the parent extension before recovering any child journal; an interrupted
installation resumes the exact allocated identity, never a fresh reservation.

The source is restored from a surviving provider, uploaded to the replacement, then read
back completely and hash-verified. Only after verification and survivor reconciliation may
the original copy be deleted. Retention must still cover the original obligation at deletion
time. A lost delete confirmation leaves retirement pending and the original fully charged.
Repeat the exact command to retry. Progress, non-consuming restore, renewal and all-copy
deletion remain available; renewal keeps the old obligation while copying and excludes it
only after verified replacement advances to pending deletion. Historical copies are never
silently forgotten. The existing bound of eight retained copy identities per fragment also
limits repeated replacements; journal compaction is not implemented.

The existing copy journals remain the **only charge ledger**. During replacement the charge
may exceed `logical_ciphertext_bytes * copies_per_fragment`; all reserved, committed,
uncertain and expired copies count at their actual fragment length until confirmed deletion.
Only archives with a placement extension emit the additive `report_version: 2`, with
`desired_copies_per_fragment`, `placement_authorizations`, `retained_copy_records`,
`pending_retirements` and `replacement_overhead_included`. Desired redundancy is not the
length of a historical `fragments[].copies` array. Providers include newly authorized
identities; each provider's charge still sums its retained records. Unmodified archives
retain their old manifest and report shape.

**Consumer boundary:** the pinned Image v1 adapter currently rejects this extended history
and temporary overhead. Before Image initiates replacement, its report parser must accept
the explicit v2 shape, keep the original desired copy count, validate up to eight historical
records per fragment and sum actual per-copy/per-provider charges rather than cap them at
the original target. Until that coordinated update, Image should use unreplaced archives;
this core change does not claim repaired-archive Image compatibility.

Targeted local tests use real signed storage services and SQLite stores: parent/child crash
windows, rejected unsigned recovery, lost reservation/readback/deletion confirmations,
same-identity restart, survivor reconstruction without the local source, renewal during
pending retirement and all-copy deletion. These are not new overlay or independent-device
availability proofs, automatic repair, safe provider-capacity drain or network-wide credit.

### Bounded owner-driven archive drain

`storage fragments drain` applies the same verified replacement lifecycle across one
archive, without manually selecting a destination for each fragment:

```sh
volparossa storage fragments drain --state /absolute/fragment-set \
  --from-provider-key RETIRING_PROVIDER_KEY_HEX \
  --provider-key CANDIDATE_A_KEY_HEX --grant /absolute/candidate-a.grant \
  --provider-key CANDIDATE_B_KEY_HEX --grant /absolute/candidate-b.grant \
  --max-fragments 16 --lifetime-seconds 604800 --identity /absolute/owner.identity
```

The owner explicitly supplies 1–8 independently trusted candidate grants. For each new
placement, the controller chooses the eligible provider with the lowest **this-archive
retained charge**, using the provider key as a stable tie-break. It excludes current and
historical holders of that fragment, insufficient rights/retention, exhausted history,
and candidate quotas too small for the archive's retained allocations plus the new copy.
Original unattempted allocations reserve planning room too. This local estimate is not a
global capacity or uptime claim: the real provider still enforces its actual storage and
grant quota, including other archives.

Before creating **any** new placement, a pass resumes earlier signed handoffs using their
exact retained provider, grant, archive identity and expiry—even when that provider is
not in the new candidate list. A failed upload, readback, survivor check or deletion stops
the pass visibly. The existing charge ledger retains all uncertain copies; no replacement
is redirected to another provider and no source is retired before verified replacement.
Expired pending authority remains incomplete rather than silently acquiring new authority.

The default bound is 16 handoff attempts per invocation (maximum 256), including resumed
intents. A partial pass returns nonzero with `operation_complete: false`, a closed
`drain_stage`, per-fragment outcomes and `remaining_provider_fragments`. Repeat the command
to continue after restart. Completion concerns **only this owner's archive**: it neither
changes the uniform two-copy target nor frees unrelated users' leases. The original signed
manifest is unchanged. The v2 consumer boundary above still applies.

This is an owner-online, explicit bounded pass, not background repair, automatic discovery,
network-wide contribution resizing or a promise that an offline provider's uncertain
charge can be removed. Local signed-service tests exercise lost replies, restart, exact
retry identity, a bounded partial pass, least-charged placement, restore without the local
source and final zero-lease cleanup; they are not a new protected-overlay proof.

### Bounded owner-driven repair pass

`storage fragments repair` uses the same explicit owner authority, candidate grants,
least-charged selection and real replacement/readback operations as `drain`, but separates
repair progress from an unreachable source's outstanding deletion:

```sh
volparossa storage fragments repair --state /absolute/fragment-set \
  --from-provider-key UNAVAILABLE_PROVIDER_KEY_HEX \
  --provider-key CANDIDATE_KEY_HEX --grant /absolute/candidate.grant \
  --max-fragments 16 --lifetime-seconds 604800 --identity /absolute/owner.identity
```

Copying intents resume first with their exact signed provider, archive identity, grant and
expiry, including when that provider is absent from the fresh candidate list. New repairs
come next; already pending retirements come last so repeated small passes can repair the
other fragments while the original provider remains offline. Every fragment is attempted
at most once per pass and the same total 1–256 attempt bound applies. A fragment with a
pending handoff never receives another replacement intent.

An incomplete handoff permits continuation **only** when that invocation verified the
survivor and fully read back the exact replacement, with only `source_delete_unconfirmed`
remaining. A failed upload, readback or survivor check still stops the pass. A persisted
`DeletePending` phase is not counted as new verification; a retirement retry performs the
existing real handoff checks again before it can delete anything. The original provider's
uncertain bytes remain fully charged even when the replacement is usable.

The JSON report distinguishes `freshly_verified_replacements` and per-fragment
`replacement_verified_this_pass` from `pending_retirements` and
`remaining_provider_fragments` (the original copies not yet confirmed deleted).
`repair_stage: retirement_pending` and nonzero exit status remain visible until all source
copies are confirmed deleted. `pass_limit`, `pending_handoff`, `pending_grant_unavailable`
and `no_eligible_candidate` also remain incomplete. `repair_pending` means another pass is
needed after a fragment's earlier handoff for a different source provider was completed;
the pass does not schedule two handoffs for that fragment. Repeating the command after provider
or owner restart retains the same identities and charges. `drain` keeps its stricter
stop-on-unconfirmed-deletion behavior.

This is a bounded owner-online controller, not background availability detection, automatic
contribution resizing, a new redundancy policy or proof of independent device availability.
The original signed reconstruction root and the existing v2 consumer boundary are unchanged.
Its functional probe uses actual signed local provider services and SQLite stores, not a
new protected-overlay run.

### Disposable protected-fragment proof

The `private-storage-fragments` scenario is separate from the older whole-archive
`private-storage-replicas` and replacement `private-storage-handoff` proofs. Preview it with:

```sh
sh tests/integration/run-alpha-topology-vm.sh --preview --scenario private-storage-fragments
```

The executable fixture places four distinct ranges (three 256-KiB fragments and 73 bytes)
with two copies each on three explicitly pinned providers. Exact per-provider grants and
usage snapshots require 524,361 / 524,361 / 524,288 retained bytes and 3 / 3 / 2 leases,
respectively, not a whole archive on each provider. With the original source removed and
the first provider stopped, two complete restores must combine fragments from the other
two stores. Unavailable copies remain charged; repeated reads must leave all three stores'
usage unchanged. Reopening the same stores precedes deletion of all eight copies and
confirmation of zero retained leases/payload. All store inspection happens after stopping
the corresponding service, never by bypassing its live lock.

The fixture retains two-path MPTCP, exactly one relay on each path, TLS, control/data-plane
privacy captures and disposable-host cleanup gates. Only a closed list of sanitized reports
is exported, never private owner keys, grants, journals or raw ciphertext. Twelve focused
receipt/export/wiring tests pass. Exact trial `36744395110` verifies the full upload phase
and subset accounting, then fails during survivor restore; returned B/C traffic
alone is not proof of complete reconstruction. Its private cleanup and host-state checks
pass. The genuine local three-store lifecycle passes the actual fixture's restore validator.
A closed failure record now distinguishes CLI, accounting, survivor-receipt, output,
identity and cleanup stages, preserving only fixed incomplete-report categories/counters
before rejecting a nonzero CLI exit, without exporting raw private diagnostics. See
[implementation status](IMPLEMENTATION_STATUS.md) for the original failure evidence.

The subsequent exact [trial 36773683946](https://github.com/VOLPAROSSA/volparossa/actions/runs/36773683946)
at `64c4f18cadb839ad6024c21166d6154e6665733f` **passes the complete protected-fragment
lifecycle**, including the unchanged 56/16/16 protected-flow thresholds, two complete
survivor reconstructions, non-consuming accounting, reopening all original stores and
idempotent all-copy deletion to zero leases/payload. Both WireGuard relay paths, all
privacy captures, private artifact removal and unchanged disposable guest-host state
pass. This is a three-provider namespace proof, not independent-device availability,
automatic repair, contribution resizing or network-wide reciprocal credit.
The public synthetic opaque fixture proves no archive encryption or native Signal integration.

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

The Signal bridge must export a completed upstream encrypted snapshot, including its
referenced encrypted attachments and private metadata, then reconstruct and validate that
snapshot through Signal's importer. Merely restoring an opaque file is not Signal restore.
The same core interface should serve other applications without reimplementing storage.
