# Storage trial records

For the current checkpoints and open work, see the [implementation status](../IMPLEMENTATION_STATUS.md).

## Storage consumer and provider evidence

The Image-only trial on Core `46f5c2c98f49eeda1816517530961f2d8090657c` and Image
`ce16debc9277bdf80fa76c373746e3d502fc96fb` recovered a live Immich 3.2.4 album from three
Storage providers. The owner removed the source project and ciphertext, withdrew one provider,
and restored the 51,283-byte OpenPGP snapshot twice. A fresh PostgreSQL database and Immich
server returned the original 8,516-byte photo to the authenticated owner. Anonymous access was
denied. All eight fragment copies were deleted and final usage was zero at every provider.
The independently vaulted key stayed with the owner. [Run 44411540175](https://github.com/VOLPAROSSA/volparossa/actions/runs/44411540175) · [Immich receipt](../development/evidence/immich-peer-44411540175/immich-restore-result.json) · [Core receipt](../development/evidence/immich-peer-44411540175/image-topology-receipt.json)

The two retained JSON files are the original artifact contents. The ZIP SHA-256 is
`f467c00dfa0aa8036e52106d85961c67dc530ba53c39ce4b8e7d71a619036478`. To repeat the joined
trial on a selected Core ref containing the scenario, use
`gh workflow run alpha-topology.yml --ref <core-ref> -f scenario=image-immich -f image_revision=ce16debc9277bdf80fa76c373746e3d502fc96fb`.
The separate multi-application maintenance scenario is tracked below.

- **Integrated provider fixes:** PR327 merges close-before-log source
  `a41030a51471` as `157908ad1e4a`. Scoped run 39832609493 proves actual TLS
  session release under held event-log locks; ordinary Quality/CodeQL pass.
  PR331 merges provider event-drain source `c111114b65a5` as `2a15a7f114e6`;
  scoped run 39851344008 passes two queue units, five candidate cases, three
  negative controls, strict Clippy and host comparison. These controlled fixes
  do not establish the cause of earlier consumer stalls.
- **Consumer failure:** run 39837551972 on `a41030a51471` fails Cloud deposit
  (`CONTENT_UNAVAILABLE` at distinct TLS/route stages). Run 39855345985 on
  `7c569dd08a71` reaches `cloud_catalog_create/catalog_materialization_failed`;
  the API collapses peer restore, verification/decryption and local I/O, so the
  substage is unknown. Provider usage remains 6/6/4 leases and
  1,198,718/1,198,718/799,148 committed bytes with zero reservations. Local and
  coordinator cleanup pass; remote deletion and aggregate consumer cleanup do
  not. Image/Cloud fixture pins remain unchanged.
- **Integrated diagnostics:** PR334 merges as `a68b805a4a00` with passing Quality
  39857954009 and CodeQL 39857949804. Catalog restore diagnostic PR336, source
  `300766d9e822`, merges as `146cfe898e15`; Quality 39863841700, all CodeQL
  analyses and 66 Node tests pass. These source results do not prove catalog
  restoration. Failure snapshots are bounded/sequential, not per-request cause
  evidence; empty saturated rings do not prove absence of failures.
- **October failure and follow-up:** Alpha 39864473079 fails
  `private-storage-maintenance-core-restart`, specifically
  `baseline_custody/reconcile_progress/pending_handoff` with
  `replacement_retention_insufficient`. The retention guard correctly prevents
  deletion; a pending fragment can require its next renewal rotation. Consumer
  work is not reached. Reviewed PR339 at `145c49e35ac8`, tree `a0bc4b2eec1d`,
  preserves authority/custody behavior and drives the calculated ordinary turns.
  Its 93 inert smoke/44 wiring tests and real writer-to-bounded-reader controls
  pass. Recorded ordinary Quality 39871649767 and CodeQL 39871645927 pass;
  Quality tests merge `d78c02be1003`, tree `b6a107651409` (main `18b96ff3` plus
  source `145c49e3`), with 4,250 passed/0 failed/18 ignored top-level tests,
  334 focused Storage Python cases and 66 Node tests. Actual Alpha
  [39871646877](https://github.com/VOLPAROSSA/volparossa/actions/runs/39871646877)
  is now verified completed/failed at that source; its failed job step is
  `Require actual owner-private storage maintenance`. This metadata does not
  establish the underlying failure substage, rotation convergence, catalog
  restoration or independent remote cleanup.

PR371 restored bounded ordinary renewal rotation and validated failure
diagnostics. On PR279 at `2a8b4fdff5eec755cbad14998d2411f54c066cbe`, Quality
passed the Storage contracts, build and integration tests, and their shared gate.
Its test merge `1485ae3c` has the same tree as that source. CodeQL also passed.
[Quality](https://github.com/VOLPAROSSA/volparossa/actions/runs/42147777520) · [CodeQL](https://github.com/VOLPAROSSA/volparossa/actions/runs/42147771678) · [Earlier Storage runs, pins and artifact digests](https://github.com/VOLPAROSSA/volparossa/blob/2a8b4fdff5eec755cbad14998d2411f54c066cbe/docs/IMPLEMENTATION_STATUS.md#storage-consumer-and-provider-evidence)

The 18 November trial at that same source failed during Image publish. Core
maintenance reached cursor 9, restored twice and deleted all eleven copies.
Three independent provider readings then showed zero reserved bytes, committed
bytes and leases. Image later received `CONTENT_UNAVAILABLE` on fragment 2,
copy 0, during APPEND. Opening the stream reached `flow_acquire` and recorded
three rounds. The first failed with `helper_kernel` and the last with
`helper_cleanup_incomplete`, both at `helper_acquire`. Cloud did not start.
[Run 44301340772](https://github.com/VOLPAROSSA/volparossa/actions/runs/44301340772)

A separate phase-wide observer recorded `mptcp_connect_poll_timed_out` first
and `acquire_coordinator_unavailable` last across three attempts. The record
has no application, fragment, copy or provider identity. The helper log separately
reported a bind failure (errno 98) and two poll timeouts. The cause of the
Image request failure remains open.

The guest host-state comparison passed, and local fixture cleanup left
zero owned objects. Consumer providers A, B and C still held 3, 3 and 2 leases
respectively. Their committed bytes were 599,359, 599,359 and 199,787. C also
held 199,787 reserved bytes. Remote consumer deletion and owner reconciliation
remain open. The retained ZIP has SHA-256
`5b4303e602b2ec8b6541cdc93b64421ae010b4b64c12f7858d8bf7bab77ea95b`.
[Trial artifact](https://github.com/VOLPAROSSA/volparossa/actions/runs/44301340772/artifacts/14428484479)

Two further hosted trials restored the Core archive and deleted all eleven copies.
Each recorded zero leases and bytes at the three Core providers. On `8ae10f21`,
Image FINALIZE waited 90–120 seconds for the challenge length on fragment 2.
On `43e9027e`, Image RESERVE on that fragment hit the TLS deadline for copy 0
and helper cleanup was unconfirmed during stream acquisition for copy 1.
The helper independently recorded `lease_expired` during the publish phase.
The same route had already served the preceding Core phases for over 561 seconds.
The log cannot link that expiry to a particular copy. Cloud did not start.
Consumer providers retained eight leases in the first trial and six in the second.
[First trial](https://github.com/VOLPAROSSA/volparossa/actions/runs/44313217738) · [Second trial](https://github.com/VOLPAROSSA/volparossa/actions/runs/44315089745)

The second source bounded the worker connect poll by the five-second cap and
the original request deadline, reserving 250 ms to return the result. It also
reduced the failed-consumer sampler to one final snapshot. The inert incomplete-flow
fixture used eight control queries, down from 104, and preserved the original error.
The next revision also caps a connected client MPTCP acquisition at the registered
worker lease expiry before dispatch. The caller's earlier deadline takes precedence.
The remaining acceptance check is Image and Cloud publication, restoration after
provider withdrawal, deletion and independent zero usage through route turnover.

On `ff268f3e`, the trial stopped earlier. The foreground `storage peer progress`
command exited while the maintenance turn was marked `working`. The receipt
contained no cause for that exit. The fixture now requests a diagnostic from
that same call and can retain its exit status, typed operation stage, error
category and bounded agent code. A failure outside a known stage is recorded
as `unknown`. Image and Cloud were not reached in this run.
[Foreground trial](https://github.com/VOLPAROSSA/volparossa/actions/runs/44332080434)

On `49955656`, foreground progress succeeded. Core restored twice and deleted
all eleven copies. Each Core provider reported zero leases and bytes. Consumer
publication then stopped at `cloud_catalog_create/catalog_materialization_failed`.
The catalog's single Storage restore returned verified and complete. Consumer
providers A, B and C retained 6, 6 and 4 leases.
[Catalog trial](https://github.com/VOLPAROSSA/volparossa/actions/runs/44341178239)

Without a user runtime directory, the Cloud catalog's private GnuPG socket
would use a 105-byte path. The pinned helper allows up to 103 bytes. The
fixture now uses a 102-byte catalog socket path and checks it before consumer
publication. The trial did not record which runtime directory GnuPG selected.

The next [catalog trial](https://github.com/VOLPAROSSA/volparossa/actions/runs/44348799240)
at `5186411b` failed during Cloud catalog creation. Its bound restore returned
`retained_operation_incomplete` with both Core operation completion and restore
verification false. Providers A/B/C retained 6/6/4 leases with zero reserved
bytes. Guest cleanup and host comparison passed. The
[artifact](https://github.com/VOLPAROSSA/volparossa/actions/runs/44348799240/artifacts/14452602822)
has SHA-256 `d0a3e132d6cfc0402e63db407b01cc36e7310e0e3cd7d2896712b3e5ddfb8abf`.
The copy and transport cause of this restore failure are unknown.

Foreground restore now shares one retry per copy across its Progress preflight
and verified range reads when the agent reports a provider TLS handshake deadline
before READY. The retry keeps the existing exchange deadline, offset and grant.
Background turns and ordinary successful flow counts are preserved.

At `edf778da`, [Quality](https://github.com/VOLPAROSSA/volparossa/actions/runs/44367731858)
passed, including the live framed restore lifecycle. The
[KVM trial](https://github.com/VOLPAROSSA/volparossa/actions/runs/44367739602)
completed Image and Cloud publication, including Cloud catalog creation and the
56-flow publication gate. Both applications committed eight copies and
1,598,292 bytes each. The run then failed at `exercise/image_repair/private_file`.
Independent readings found 6/6/5 provider leases with zero reserved bytes.
Scoped local cleanup and the guest host-state comparison passed. The
[artifact](https://github.com/VOLPAROSSA/volparossa/actions/runs/44367739602/artifacts/14459484719)
has SHA-256 `ab571e82f420c93df74883d07268a6140aa673ece20f2d6777a70af9d17421f3`.
The report does not record the inode or attribute that tripped the private-file check.

A deterministic fixture regression reproduces the same error when the replica
writer renames a new manifest after the observer opens the old one and before its
first stat. The observer now discards an otherwise valid private inode with zero
links so its existing bounded poll can reopen the current path. Multiple links,
wrong ownership or mode, and invalid file size remain fatal.

The [assembled trial](https://github.com/VOLPAROSSA/volparossa/actions/runs/44375959400)
at `c6a810a8` passed the 56-flow publication gate and both applications committed
eight copies each. Exercise stopped at `image_repair/application_failed`.
The three stores held 6/7/6 leases and zero reserved bytes. Local cleanup
and the guest configuration comparison passed. All-copy deletion on this
maintenance run remains unverified. The
[artifact](https://github.com/VOLPAROSSA/volparossa/actions/runs/44375959400/artifacts/14463864552)
has SHA-256 `e54fbdd7eac7d52beeead56af4a644e935038ec8bedfeec72b541acd605a466e`.

The Image fixture now observes repaired membership before the foreground
restore, which supplies the verified post-read accounting. This removes an
extra status command that would pause and restart the active owner before the
actual read. Owner startup, repair observation, restore, decryption and final
join report separate stages. A closed exercise error survives subsequent owner
teardown. The earlier generic error does not identify which call failed.

[Run 44385364109](https://github.com/VOLPAROSSA/volparossa/actions/runs/44385364109)
at `8e156da3` stopped in the source-contract step before VM preparation.
The Image wiring test's isolated shell selector lacked the empty default for
the newly integrated optional Studio evidence digest. The complete guest driver
already initialized it. The test now supplies the same empty default.

The next [maintenance run](https://github.com/VOLPAROSSA/volparossa/actions/runs/44387064217)
passed preflight and ran on `ac51c47a`. Three Cloud deposit reservations
failed before a protected stream was available. The corresponding requests
for fragment/copy (1,0), (1,1) and (2,0) each recorded eight flow acquisition
attempts with `helper_kernel` at both ends of the summary. A separate phase
sample observed a socket bind error and a poll timeout. Its records cannot be
assigned to a particular copy. Providers A/B/C still held 6/5/2 leases with
zero reserved bytes. Local cleanup and the guest network-state comparison
passed. The run ended before the Image repair and all-copy deletion stages.
[Retained archive](https://github.com/VOLPAROSSA/volparossa/actions/runs/44387064217/artifacts/14470925130)
SHA-256 `8b37f49942e02d42f8be595c78f3b9fffd896066ecdc1b68da17a7b13c70d543`.

The opt-in fixture on `b037a998` distinguishes an authenticated client MPTCP
bind rejection (`EADDRINUSE`) from a connect poll timeout. The ordinary
application still sees the same kernel failure category. The first hosted
attempt on this revision passed its source checks, then stopped before VM
startup because the runner's APT index offered no QEMU package. It produced
no guest report. In the separate workspace quality run, strict Clippy flagged
a narrowing cast in the 256 MiB site-layout test. Revision `53027324` uses
a checked conversion for the block length.
[Initial runner setup failure](https://github.com/VOLPAROSSA/volparossa/actions/runs/44397819655/attempts/1)
· [Original workspace check](https://github.com/VOLPAROSSA/volparossa/actions/runs/44397448406)

[Attempt 2](https://github.com/VOLPAROSSA/volparossa/actions/runs/44397819655/attempts/2)
installed the packages and ran the twelve-node KVM trial on `b037a998`.
Cloud again stopped before READY on the same three deposit reservations.
Both copies of fragment 1 recorded eight connection attempts. Copy 0 of
fragment 2 recorded seven, ending with `helper_other_rejection`. The source
maps that final category to an unconfirmed acquisition and ends the retry
loop. The app recorded no deadline for these requests. The fixture retained
a poll timeout for one exchange. The separate helper
log also recorded a bind rejection. The available records do not establish
which copy experienced either event or the causes of the intermediate attempts.
Providers A/B/C retained 6/5/2 leases with zero reserved bytes each. Local
cleanup and the guest network-state comparison passed. The combined trial
did not reach repair, cold restore or all-copy deletion.
[Retained second-attempt archive](https://github.com/VOLPAROSSA/volparossa/actions/runs/44397819655/artifacts/14475421816)
has SHA-256 `47a1dbe1618480fb88f7e065a3769b70011cccf906e21b098c2177265a825a53`.

The [next twelve-node run](https://github.com/VOLPAROSSA/volparossa/actions/runs/44409967365)
on `ed1764f6` stopped during Image deposit. The original request for
fragment 2, copy 0 hit a provider TLS handshake deadline before the agent
reported READY for Append. The reservations for (2,1) and (3,0) each
recorded eight flow acquisition attempts, with kernel errors on the first
and last attempts. Reservation (3,1) returned `CONTENT_POLICY`. The
helper recorded a bind rejection without a binding to a particular copy.
The three stores had 1/2/2 leases, 199,787/399,574/199,787 committed bytes,
and 0/0/199,787 reserved bytes. The guest removed its local fixture and
owned processes and its host-state files matched. This run did not reach
Cloud publication, repair, cold restoration or acknowledged remote deletion.
[Original evidence archive](https://github.com/VOLPAROSSA/volparossa/actions/runs/44409967365/artifacts/14480386650)
SHA-256 `a5895c3e122b8559b9703b1bb0b3b9482c90152668cd5b4e850938ae7541a1e4`.

The foreground deposit now allows one new TLS handshake per copy after a
correlated timeout before READY, within the original exchange deadline.
The framed owner/provider test reopened its original journal after losing the
first Reserve confirmation. It retained the first acknowledged chunk, rejected
a subsequent authentication failure, completed the original lease and read the
exact bytes back. Deletion returned provider use to zero. The test used the
real SQLite provider and a controlled local IPC transport. It passed in the
default-branch change's workspace suite (4,459 passed, zero failed, 21 ignored).
[Core integration](https://github.com/VOLPAROSSA/volparossa/pull/386)
· [Quality and test log](https://github.com/VOLPAROSSA/volparossa/actions/runs/44418876629)

The next twelve-node trial on `462581e2` prepared Image and Cloud. Image
publication stopped at fragment 2, copy 0. The owner had yet to send a signed
Reserve. The agent spent 90–120 seconds awaiting the response frame length for
the provider challenge and exhausted its operation deadline. The error report
does not establish how many length bytes arrived. Separate fixture records
observed a provider TLS timeout without identifying the affected copy.
The Image adapter closed. The later owner deletion returned an incomplete
result. Independent reads found zero leases, reserved bytes and committed
bytes at all three providers. Local cleanup removed 40 files and 20 directories,
and the host snapshots matched. Cloud publication and combined repair were
not reached. The 82,243-byte Actions ZIP has SHA-256
`12cfd2f78bce34895487d6fb9e116eef7f33adc4c86b8e3f6891928ec8838b56`.
[Hosted run](https://github.com/VOLPAROSSA/volparossa/actions/runs/44419915713)
· [Original failure, usage and cleanup reports](../development/evidence/storage-maintenance-44419915713)

The twelve-node trial on `9335306b` completed the separate Core lifecycle and
deleted all eleven Core copies. The consumer phase prepared two encrypted inputs
of 799,146 bytes each and passed Image enrollment. Cloud stopped during deposit.
Its fragment 0 FINALIZE (copy 0) and RESERVE (copy 1) each made eight attempts
to acquire a protected stream before READY. Both reported `helper_kernel` on
the first and last attempt. A separate RESERVE on fragment 1, copy 0 returned
`CONTENT_POLICY`. The helper logged one MPTCP poll timeout. The phase observer also recorded a
generic transport-unavailable response. Neither observation identified a fragment or copy.

During failure cleanup, the owner confirmed deletion for both Image and Cloud.
Before the private journals were removed, all three providers independently
reported zero leases, reserved bytes and committed bytes. The disposable guest
removed its fixture state and both host snapshots matched byte for byte.
Cloud publication stopped before joint repair, cold restore and the final
acceptance checks. The 82,290-byte ZIP has SHA-256
`a3870f4a6ab880537cb1e8752f3d64c569579f71e5cdb7415378ce1f2c0590e8`.
[Original run](https://github.com/VOLPAROSSA/volparossa/actions/runs/44430761553) · [Original application, route and cleanup receipts](../development/evidence/storage-maintenance-44430761553)

On `b856970b`, the twelve-node trial deleted all eleven standalone Core copies
and prepared both 799,146-byte encrypted application inputs. The Cloud CLI
reported one failure during deposit. Its reserve for fragment 1, copy 1
returned `CONTENT_POLICY` while waiting for agent READY. The protected
stream acquisition log projection was empty. The incomplete fixture sample
included a provider C selector-read error and had no fragment or copy binding.
Both owners confirmed deletion. All three providers independently reported
zero leases, reserved bytes and committed bytes. The host snapshots matched.
Combined repair and cold restoration remain open. The original 81,804-byte
Actions ZIP has SHA-256
`38468903864d1f287f161674cfcc4fd1901a92bacef266cc940bd6e39eca8b14`.
[Hosted run](https://github.com/VOLPAROSSA/volparossa/actions/runs/44440163724) · [Original application, sample and cleanup receipts](../development/evidence/storage-maintenance-44440163724)

In the following twelve-node run at `e5d06b21e87409139d78317dc7deeae6b372b51b`,
Image stopped during publication. FINALIZE on fragment 2, copy 0 reached the
initial READY boundary with a TLS handshake deadline. RESERVE on fragment 2,
copy 1 and fragment 3, copy 0 each reported eight helper-kernel acquisition
rounds. Fragment 3, copy 1 reported three rounds, from helper-kernel to another
helper rejection. All four foreground failures carried `CONTENT_UNAVAILABLE`.
The separate incomplete sampler observed a two-sided TLS timeout at provider C.
Its samples carry no fragment or copy identity. Image confirmed owner deletion.
Cloud had no archive. All three independent provider measurements showed zero
leases, reserved bytes and committed bytes. Local cleanup completed and the
guest's outside-namespace network snapshots matched. Joint maintenance and
cold restoration remained pending. The preceding run reached Cloud before it
stopped. The 82,262-byte archive (artifact `14496173050`) has SHA-256
`95205102709774ce80e5a7df56fc85121e399b3aa4a2d00744ae8fc5c72a50dd`.
[Hosted run](https://github.com/VOLPAROSSA/volparossa/actions/runs/44447515035) · [Original application, samples and cleanup receipts](../development/evidence/storage-maintenance-44447515035)

The next twelve-node trial on `cf93b5a2` completed the independent eleven-copy
Core lifecycle. Image then reported one failed deposit operation, with zero
omitted failures. Its owner submitted FINALIZE for fragment 2, copy 1. The
agent reached the operation deadline while reading the provider receipt.
The helper recorded zero acquire samples. Provider event sampling reported one
request I/O failure before identifying an operation, with no fragment binding.
The provider's state at the time of that timeout remains unknown.
Image subsequently confirmed owner deletion, Cloud had no archive, and the
three provider stores each showed zero leases and zero reserved and committed
bytes. Guest host-state digests matched. The combined repair and cold
restoration still need a completed joint run.
[Original archive, SHA-256 `0f4afc3c…19c0f23`](https://github.com/VOLPAROSSA/volparossa/actions/runs/44455715673/artifacts/14499901605) · [Original application and cleanup reports](../development/evidence/storage-maintenance-44455715673)

The separate upload-continuation VM on the same Core revision also stopped
during shared Image publication. Its only failed operation was APPEND for
fragment 3, copy 1. The agent returned `CONTENT_UNAVAILABLE` during control
selection, before READY. The owner confirmed Image deletion. Cloud had no
archive, and the upload continuation did not start. The independent Core test
deleted all eleven copies with zero payload charge. The guest removed its
owned fixtures and its before/after network digests matched. This run has no
consumer provider-usage snapshot for the failed Image deposit.
[Original 81,532-byte archive, SHA-256 `8e6123b1…ce80bc75`](https://github.com/VOLPAROSSA/volparossa/actions/runs/44514676250/artifacts/14527619866) · [Original reports](../development/evidence/storage-maintenance-44514676250)

On `bb48e128` the shared publication reached Cloud. Its only failed operation
was RESERVE for fragment 3, copy 0. The agent returned `CONTENT_UNAVAILABLE`
during stream opening with local route state as its reason. The provider had
received no signed reservation on this connection. A separate helper sample
recorded a bind error (errno 98) without a matching request identity. Both
owners confirmed deletion. Providers A, B and C independently reported zero
leases, reserved bytes and committed bytes. The eleven-copy Core lifecycle and
guest cleanup completed. The guest's before/after host-state digests matched.
[Original 81,981-byte archive, SHA-256 `cfb1313c…8bb5e46`](https://github.com/VOLPAROSSA/volparossa/actions/runs/44516433050/artifacts/14529597943) · [Original reports](../development/evidence/storage-maintenance-44516433050)

The shared trial on `200d58c5` published Image using `21988efc` and reached
Cloud using `08be9711`. Cloud FINALIZE for fragment 1, copy 1 was its sole
reported failure. The agent returned `CONTENT_UNAVAILABLE` during control
selection, before READY. Both owners confirmed deletion. The independent Core
lifecycle deleted all eleven copies, and its three providers reported zero
leases, reserved bytes and committed bytes. An independent usage reading
for the failed application deposits is absent. The guest removed its owned
objects and its before/after network digests matched. Shared repair, cold
restore and the separate finite upload lifecycle remain open.
[Original 81,883-byte archive, SHA-256 `c90eb64a…c01ae792`](https://github.com/VOLPAROSSA/volparossa/actions/runs/44537092652/artifacts/14539650755) · [Original reports](../development/evidence/storage-maintenance-44537092652)

The twelve-node trial on `3dedd5f0` stopped at Image publication. The owner
sent RESERVE for fragment 2, copy 1. Its one reported failure was an I/O error
while waiting for the receipt. The agent recorded an operation timeout reading
the remote receipt. Image deletion was unconfirmed and Cloud had no archive.
Provider A retained one lease with 199,787 reserved bytes. Providers B and C
reported zero leases and bytes. The usage receipt identifies the provider but
does not identify the fragment. The separate Core lifecycle deleted all eleven
copies and its three providers reported zero usage. Local cleanup completed
and the guest network snapshots matched. Shared repair and cold restore still
require a completed trial.
[Original 95,189-byte archive, SHA-256 `bec95299…e3b7ac0`](https://github.com/VOLPAROSSA/volparossa/actions/runs/44568672976/artifacts/14557796765) · [Original reports](../development/evidence/storage-maintenance-44568672976)

## Automatic upload integration candidate

Upload profiles 1–6 retain their application pins and finite authorization
ceilings. Before upload profile 6 can run, shared consumer profile 10 must pass
the full Image and Cloud lifecycle with verified cleanup and zero usage on all
providers. The run also requires TLS-close diagnostic 9. Consumer profile 10
pins Image `f51b8ace` and Cloud `5f143725`. Upload profile 6 pins Image
`1e812ec6` and Cloud `35598609`. Each phase checks its own source and preceding
receipt. Quality covers the reusable upload checks and two isolated TLS-close
contracts. Both upload export paths validate the two diagnostic sidecars.
[PR279](https://github.com/VOLPAROSSA/volparossa/pull/279) · [Original candidate](https://github.com/VOLPAROSSA/volparossa/blob/dd1fd4dff55413ade4cfb26ffcb7bf5a9ad26c01/docs/IMPLEMENTATION_STATUS.md)

The joined trial must demonstrate authenticated upload, automatic enrollment
under finite authority, provider withdrawal, repair, two cold restorations
across restart, deletion and cleanup. That trial remains pending.
