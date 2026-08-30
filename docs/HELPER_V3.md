# Privileged helper protocol v3

This document records the implemented external helper boundary and the exact point at which the
live Linux implementation currently stops. It is not evidence that a VOLPAROSSA datapath works.

## External boundary

The agent/helper protocol accepts exactly version 3. Version 1, version 2, zero, and future versions
are rejected during canonical decoding, before engine dispatch. Frames are bounded to 128 KiB and
use a four-byte big-endian length. The root-owned socket, peer-credential, cleanup-token,
request-ID, request-digest, response-correlation, and zeroization checks remain in force.

The v3 route-context lifecycle is:

1. `PrepareLeaseBatch` describes a route context, its client/relay/exit role, one to eight paths,
   bounded MPTCP limits, a setup expiry, and a hard expiry.
2. `ActivateLeaseBatch` presents only the exact public key and public UDP endpoint of every peer,
   correlated by opaque helper-issued context and lease handles. Relay rate limits are bounded.
3. `CommitLeaseBatch` presents the same opaque handles and identities. Success is permitted only
   after a correlated kernel probe proves a recent handshake and strict growth of both RX and TX
   counters relative to the activation baseline.
4. `AcquireTransportSocket` requests one descriptor for an exact committed context, lease path,
   endpoint role, closed transport kind and concrete address tuple. The descriptor is transferred
   separately and is not representable in protobuf.
5. `DestroyContext` removes one exact owned context. Repeated destruction is successful and reports
   whether a context existed. Cleanup ambiguity quarantines the context rather than claiming success.

Before step 1, the HelperClient constructs the exact canonical Prepare frame, request ID, and digest.
It sends tag-35 `BindHelperRuntime(Some(PrepareIntent))`, validates the non-secret per-process runtime
ID, and sends that prebuilt Prepare on the same `SO_PEERCRED`-validated Unix stream. The intent also
contains a required closed recovery plan: the exact context role and strictly ordered,
role-complete `(path_id, WireGuard role)` identities projected from that same Prepare. Prepare itself
requires the same canonical identity order. The helper stores the complete binding in runtime-global
state and requires an exact plan match before that target can enter `Pending` or invoke its Prepare
backend call; unrelated global expiry housekeeping may run before target admission. A server-owned
driver also invokes that cleanup every second, with missed ticks skipped, so cleanup does not depend
on another agent request. The server does not bind the intent to that connection. Same-stream use is
therefore a client-side socket-swap
defence, not a server-side session authorization rule.

Role cardinality is exact for every path: client has one client endpoint, relay has one client-facing
and one exit-facing endpoint, and exit has one exit endpoint. Path identifiers are 1 through 8.
Setup expiry is at most 30 seconds and hard expiry at most 15 minutes. Both intervals are half-open:
admission and commit require `now < expiry`, while equality is expired and permits reaping or exact
reconciliation. The engine limits contexts and its idempotency cache; a normal exact request retry
returns the cached response, while request-ID reuse with different bytes is rejected. Tag 28 is the
documented exception: each exact retry re-evaluates its retained lineage and target state instead of
replaying a generic response-cache entry. An operation already linearized before a boundary may still
return an exact cached response; this is not fresh admission and performs no new backend call. Routing
configuration can permit a 30-60 minute context, but that is not authority for the helper: production
must cap the requested hard expiry to the signed reservation grant, currently at most 15 minutes. No
signed lease-renewal operation exists yet.

The active v3 agent API has no private-key input or output and no caller-selected interface name,
local overlay address, allowed prefix, listen port, filesystem path, sysctl, command, or nftables expression.
Historical operation tags 10 (`CreateContext`), 11 (`ConfigureWireguard`), 12
(`InstallRelayFence`), 14 (`SetLinkState`), and 24 (`InstallInterception`) are permanently reserved.
Their protobuf variants and message types are absent from the active source and must never be
reused. A raw occurrence of any retired tag is rejected as unknown/non-canonical before dispatch;
version 1, version 2, future versions, unknown operations, and non-canonical encodings likewise fail
closed. Regression tests cover every retired tag, including the former secret-bearing tag 11.

## Prepare evidence and current functional-alpha boundary

A successful `PrepareLeaseBatch` response is required to contain:

- opaque, non-secret context and lease handles;
- a helper-generated, non-zero ephemeral WireGuard public key;
- a public UDP endpoint whose address has `DirectAssigned` evidence from read-only rtnetlink state;
- a non-zero UDP port obtained from an exact acknowledged WireGuard `SET` followed by a bounded,
  correlated WireGuard `GET` that also matches the expected public key.

The internal v3 worker protocol, underlay evidence policy, secret-free link derivation, exact
WireGuard `SET` encoders, and bounded `GET` proof parser have pure tests. The authenticated child
now executes `Prepare` and `Destroy` for exactly one lease: it reconstructs the canonical interface
and `/128` from the bound context/path/role and one bounded ownership alias, generates and retains
the ephemeral X25519 private key in worker-owned secret containers that zeroize on drop, and
returns only the public key and port from the correlated kernel proof. Failed Prepare deletes the
exact resource and returns a normal kernel failure only after proving absence; otherwise it retains
the resource/key state and returns `CleanupIncomplete` for a later exact Destroy. Destroy without
an adopted lease returns `NotFound`, never false kernel-absence evidence. Successful internal
Prepare, Activate, Probe and MPTCP endpoint responses are bound to the request's exact identity
order; the external engine
also rejects duplicate public keys and public endpoints before pairing affine handles.
Each credentialed worker request carries one canonical envelope with the parent's fixed absolute
Linux `CLOCK_MONOTONIC` expiry. The child projects a no-later local deadline and reuses it for the
operation and response, so transport delay cannot create a fresh five-second mutation budget. The
affine `MayOwnPrepare` owner can canonically project its ordered durable resources into internal-v3
lease descriptors; call sites supply none of the path, role, `/128`, expiry or ownership alias.
`NamespaceKernel` contains v3 prepare, peer-activation, and probe primitives plus a complete-batch
preflight that requires exact name, current ownership alias,
WireGuard kind and fresh DOWN/key-zero/port-zero/fwmark-zero/peerless state before mutation. Its
exact-owned delete re-proves absence. A validated journal record now deterministically projects a
non-`Clone` resource for each exact link. Its public `ownership-v1` alias commits the immutable
ownership-record fields, closed plan, and per-link identity without exposing raw ownership
coordinates; lifecycle phase and reconciliation evidence do not change it. Every owner-sensitive
kernel entry point consumes that typed resource and rejects any non-exact marker.
The underlay parser independently accepts only the exact helper grammar and interface binding,
rejecting malformed, legacy, or mismatched helper aliases. The marker is evidence, not current
journal-phase or cleanup authority. The child transaction is not connected to the production
durable-journal path; transaction-wide crash/restart rollback is still absent. The production
server now selects a crate-private functional-alpha backend for exactly one Client context with
exactly one `WireguardRole::Client` lease. It obtains a consistent read-only direct-underlay
snapshot before mutation, opens a process-owned worker coordinator, initializes the authenticated
child, exclusively creates the helper-derived WireGuard birth link at one deterministic high
ifindex in the parent, proves its provisional DOWN name/kind identity, sets the exact ownership
alias by that index, re-proves the full marked identity, and requires the move to preserve the same
index in the pinned child `NEWNET` before dispatching Prepare. The single outer deadline reserves
separate reconciliation and cleanup tails; same-runtime owner state retains the exact index after
every fully sent mutation. Only the
child's correlated kernel proof supplies the
public key and UDP port; the response combines that proof with the selected direct-underlay IP.
Destroy sends the exact child operation and succeeds only after worker termination, reap and
registry purge. The backend permits no second live context. Activate, Probe, transport acquisition,
routing, peer configuration and every datapath remain explicitly `Unavailable`; shutdown succeeds
only with empty backend state and confirmed coordinator cleanup. The periodic driver uses an owned,
cancellation-safe engine supervisor with nonzero domain-separated exact-lineage correlation; it
retries cleanup-pending Quarantined contexts and orphan Pending preparations, and unexpected driver
exit stops the server. Shutdown first stops and joins this driver, then cleans the engine, then joins
the durable actor. The driver schedules a sweep once per second with missed ticks skipped; a sweep
begins only after every earlier request in the serialized operation gate has settled. Once begun,
its kernel-absence attempt remains bounded by the backend hard deadline. The public
`HelperEngine::new` constructor remains fully fail-closed and does not select this backend. No
crash/restart recovery or durable journal/systemd custody is claimed, and no placeholder or
agent-supplied endpoint is used.

## Ownership journal startup boundary

The v1/v2 context worker, its internal command-line entry point, and its live journal cleanup
executor have been removed. Any filesystem object at the retired
`/run/volparossa/helper.ownership-v1` path still stops production startup before runtime-state
mutation and requires explicit operator inspection. After fixed account and runtime-directory
validation, production opens the v3 store through one canonical, exclusively locked actor. The
actor must finish its startup sweep and complete-boundary recheck before cleanup-token publication,
stale-socket removal, or listener bind. Orderly shutdown cleans the engine first, then fences and
joins the quiescent actor before releasing the socket path.

The v3 module contains a boot-scoped, secret-free, canonical and length-bounded codec/CAS store for
exact `Intent`, `MayOwnCustody`, `MayOwnPrepare`, `CleanupConfirmed`, and `Absent` ownership records.
Its fixed lock, atomic file-fsync/rename/directory-fsync transaction, typed recovery anchor,
role-ordered pidfd/network-namespace identity binding, and two distinct non-cryptographic
exact-record-echo proof interfaces have temp-directory tests. The first interface may advance a
custody-bound `MayOwnCustody` or `MayOwnPrepare` record to `CleanupConfirmed` only after a trusted
executor has proved worker teardown and exact kernel cleanup. The second may advance only that
durable `CleanupConfirmed` record to `Absent(RecoveredMayOwn)` after a separate executor has proved
exact stable manager absence. There is no direct `MayOwnPrepare -> Absent` transition. A private
single-writer actor owns the store and both executor interfaces on one named thread. It retains one
verified parent-directory descriptor and acquires a process-global one-shot store latch before
opening the lock. Its generic settlement path processes every custody-bearing phase before retiring
even one `Intent`, rechecks the complete durable boundary, and only then reports ready. The
production lock-held startup join still refuses every non-empty custody target set before this path,
and its installed executor refuses both proofs. Its non-blocking admission accepts at most four
operations while reserving channel capacity for shutdown; opaque non-`Clone` keys expose neither
the journal revision nor raw ownership coordinates. Each validated wire intent locally receives a
fresh random 256-bit `OwnershipId` inside a non-`Clone` registration owner. Registration consumes
that owner into one durable key. Custody marking consumes the key into a `MayOwnCustody` token only
after atomically persisting the complete recovery anchor and exact role-ordered descriptor
identities. Arming consumes only that token, preserves the custody evidence byte-for-byte, and
returns a `MayOwnPrepare` token exposing only the context and borrowed owner-bound resource
metadata. Every error returns the exact affine owner which still exists, so the typed API neither
duplicates authority nor discards it on an error path.

Validated records and private settlement targets now deterministically rederive the same non-`Clone`
per-link resources. Focused tests fix the public alias grammar and cover every immutable field
class, mutable-field exclusion, redacted debug output, canonical codec/reopen stability, a lost
insert reply, and recovery projection. This dormant projection exposes no production issuance API
and does not authorize a kernel operation.

Production exposes only a start/shutdown wrapper around the actor; registration, custody marking,
arming and raw settlement authority remain inaccessible to the server and engine. Its production
executor always refuses both trusted cleanup and manager-absence proof requests, so
`MayOwnCustody`, `MayOwnPrepare`, and `CleanupConfirmed` remain byte-identical and block startup.
Only a never-dispatched `Intent` may be durably settled to `Absent` before the internal actor-ready
and socket-publication boundary. There is no production request-path issuance/arming writer,
restart-stable namespace custody, worker-death and kernel-cleanup executor, manager-absence
executor, restart reaper, supported on-disk migration, or live-root proof. Every non-test actor
entry point requires one caller-supplied absolute hard deadline. That same value is carried through
admission, the queued command, actor-thread execution, reply handling and thread settlement. Each
settlement operation additionally receives its exact supplied deadline and rechecks it before
invoking its trusted executor and after the exact proof, immediately before its one journal
mutation. Startup rechecks its deadline before the first filesystem or latch
operation and before each pending record; ordinary commands recheck it immediately after dequeue.
Work which expires before its first mutation returns `DeadlineElapsed` without touching journal
bytes. Non-settlement journal I/O which already began must settle, while either settlement executor
may return late but can no longer publish its next phase; every late or unobservable completion
permanently fences admission as ambiguous. Shutdown gives settlement ambiguity precedence over a weaker queued
deadline result. Only `Drop` retains a private emergency deadline; relative-deadline convenience
wrappers are test-only. If the actor thread is stuck inside a non-cancellable settlement executor,
its join handle is detached after the bounded settlement wait; that thread may retain the journal
lock, while the process-global latch remains set until process exit. A clean shutdown now requires
both an intact durable boundary and every record already durably `Absent`; it never retires or
settles an outstanding record and returns `RecoveryNotConfirmed` for a known `Intent`,
`MayOwnCustody`, `MayOwnPrepare`, or `CleanupConfirmed`. Reopening requires a fresh process. These
limitations must be resolved at the production service boundary before the actor can become the request-path
issuance/arming writer. The required tag-35 closed plan has a fallible exact conversion into the
store's existing `ClosedPlan`; this removes the wire/schema mismatch but performs no journal I/O and
grants no mutation authority. A missing journal is therefore not proof that stale kernel state is
absent, and the startup wrapper cannot issue a cross-runtime tag-28 receipt. The current `doctor`
has no helper-v3 crash-ownership readiness check, so its other successful checks must not be
interpreted as evidence of live recovery or cleanup.

The store's insert, custody mark, custody-bound prepare arm, never-dispatched retirement, cleanup
confirmation, and manager-absence confirmation transitions are independently
exact-current-revision retry-safe after a lost reply. A retry
succeeds only when the complete durable post-state of that same operation still exists; an
intervening transition, changed intent, generation, recovery anchor, descriptor identity, or
reconciliation binding fails closed without another write. `MayOwnCustody -> MayOwnPrepare`
accepts only the exact already-persisted custody evidence and copies it byte-for-byte.
`CleanupConfirmed` preserves the exact custody evidence and has no absent origin. An exact retry of
that first transition does not rerun cleanup, while the distinct manager-absence proof is still
required before `Absent(RecoveredMayOwn)` may be written. `Absent` records persist whether they came
from a never-dispatched intent or from completed two-step settlement, so one operation can never
acknowledge the other's tombstone and an exact retry never reruns its executor. Mutation authority
remains private and pre-production: the server owns only the start/shutdown wrapper, version 3 has no supported on-disk
migration contract yet, and production decodes a v3 object only behind the canonical lock and
refuses Ready while any custody-bearing record cannot complete both settlement proofs.

After a definite pre-rename I/O failure, another mutation is admitted only if a read-only health
check re-proves the retained parent object, exact lock entry and exclusive lock, absence of the
temporary entry, and byte-exact durable snapshot. Any uncertainty poisons the actor permanently.

### Production fail-closed inherited-custody capture and classification

Before constructing tracing, Tokio or the helper socket, the separate executable-entry crate makes
the only explicit unsafe startup assertion in the helper process. The one-shot Linux-UAPI boundary
consumes its latch before inspecting systemd's complete
`LISTEN_PID`/`LISTEN_FDS`/`LISTEN_FDNAMES` tuple, requires the exact current PID and a positive count
of at most 128, reserves all owner storage, and preflights the complete contiguous range beginning
at fd 3 with `CLOEXEC` readback. It then removes all three activation variables and takes each
original raw descriptor slot directly into affine `OwnedFd` ownership. It does not duplicate the
range. PID 1 may still retain its independent descriptor-store copies referring to the same open
file descriptions. The owner-forming loop performs no syscall or fallible allocation after its
first owner exists. Exact absence produces an opaque empty token, so safe helper code cannot bypass
the one-shot boundary with an ordinary `None`. The shipped entry treats every takeover failure as
terminal for that process; internal worker, nft frontend and live-proof invocations never call it.

The safe helper library consumes that unforgeable token, requires a positive even count for a
present set, and parses every advertised name directly into the fixed lowercase opaque
`CustodyFdName` buffer before grouping owners.

Each same-name pair is then classified without trusting descriptor order. A pidfd is accepted only
when `fstatfs(2)` returns Debian 13's `PID_FS_MAGIC`; a network namespace is accepted only when
`NS_GET_NSTYPE` returns `CLONE_NEWNET`. Exactly one of each is retained in canonical role order,
both retained owners are re-sealed `CLOEXEC`, and their full
mode/device/inode/rdev/open-flag identities are retained for descriptor-store attestation. Object
overlap is rejected within and across all bounded names using the stable mode/device/inode/rdev
fields, so mutable `O_NONBLOCK` drift cannot hide an alias. Arbitrary files, other namespace kinds,
duplicate roles, incomplete groups and identity reuse fail closed. Type classification deliberately
accepts an exited pidfd: capture proves object type, not worker liveness or cleanup.

Production now opens the ownership actor in a record-transition-free, lock-holding preflight which
keeps the exact journal parent, exclusive lock and decoded snapshot alive. Creating the fixed lock
entry is expected, but no main-journal transition or `Intent` sweep occurs. It projects at most 64
canonical custody-bound `MayOwnCustody`/`MayOwnPrepare`/`CleanupConfirmed` targets, each containing
its durable phase, derived opaque name, complete recovery anchor and role-ordered descriptor
binding. Legacy `MayOwnPrepare`, name collision and cross-record kernel-object reuse fail closed.
While that lock remains held, one non-mutating systemd barrier precedes two uncached, identical
complete bounded D-Bus inventory identity projections of the exact current service object. Exact
`MainPID`, `NotifyAccess=main`,
128-entry capacity and `FileDescriptorStorePreserve=yes` remain mandatory. The complete manager
and inherited maps must be equal, with no extra name, partial pair or cross-name alias. Local
descriptor bindings are measured before the barrier and after both projections. The journal's
retained parent, lock entry, held lock, absence of its temporary entry and byte-exact durable
snapshot are then revalidated, followed by a final local binding measurement, all under one
absolute deadline.

A custody-bound `MayOwnPrepare` target classifies only when the exact pair is present in both maps.
A custody-bound `MayOwnCustody` target may classify either `ExactPresent` or
`ExactNoStoredCustody`; the latter means only that its name and both journal identities are absent
from both complete observed maps. A `CleanupConfirmed` target is likewise `ExactPresent` when the
pair remains stored, but manager absence receives the distinct
`CleanupConfirmedNoStoredCustody` disposition. Neither no-store disposition proves old-worker
death, kernel cleanup, or authority for a journal transition. In particular,
`ExactNoStoredCustody` cannot substitute for either settlement proof, while the cleanup-confirmed
disposition is still only read-only startup classification rather than the actor's separate affine
manager-absence proof. Every partial, one-sided, wrong-name, wrong-binding or unstable case remains
unresolved.

A refusal-only observation seam can consume the complete affine classification and wait for exact
inherited process-pidfd exit. Before its first wait, every pending `MayOwnCustody` or
`MayOwnPrepare` target must be `ExactPresent`; an absent pending target fails the whole set without
minting evidence. `CleanupConfirmed` targets are skipped because their earlier durable cleanup
transition does not require a second, weaker death observation. Every pending pidfd is waited under
one copied absolute deadline. Linux `POLLIN` is mandatory, `POLLIN|POLLHUP` is accepted for a reaped
task, and bare `POLLHUP`, `POLLERR`, `POLLNVAL` or any other bit fails closed. The exact descriptor
binding is freshly remeasured before and after every wait, including the network-namespace
device/inode slice of the anchor, followed by one final remeasurement of the complete pending set
before evidence can be constructed. Process/thread-group semantics rely on the private causal
publication path having created every worker pidfd with `PidfdFlags::empty()`; `PID_FS_MAGIC` proves
only pidfs object type and cannot reveal after restart whether `PIDFD_THREAD` was requested. The
remaining complete anchor fields are correlated only by the previously lock-held journal
projection; they cannot safely be reconstructed from an already-terminal pidfd and are not freshly
journal-revalidated by this observer. Success or failure retains the complete classification,
manager snapshot, pidfds and namespace owners affinely, with no raw descriptor or PID exposure.

This seam proves only that the exact inherited worker thread group exited. It does not prove
descendant exit, cgroup emptiness, network-namespace destruction, kernel cleanup, descriptor-store
removal, journal settlement, adoption or readiness to publish the helper socket. The retained
namespace descriptor intentionally keeps that namespace alive. The seam is synchronous and has no
separate cancellation surface: expiry returns the entire classification unresolved. The
production non-empty restart-refusal path now invokes it while retaining and revalidating the exact
startup journal guard and holding the process-wide worker-spawn admission guard. It still consumes
no cleanup or settlement authority and never permits socket publication.

A second private sampler borrows that first seam's successful opaque exit-set capability
through every await. Cancelling its future therefore leaves the PR68 pidfd/namespace/custody owners
with the caller, although partial manager/cgroup sampling state inside the cancelled future is
discarded. Only a separate synchronous join consumes the exit capability. Every returned join
outcome retains that capability and all complete sampling owners returned by the async layer. The
synchronous production entry now drives that borrow non-cancellably and joins it before releasing
the journal or spawn-admission guard. It resolves no new unit by PID. The original D-Bus unique-name
owner, typed unit object path and `MainPID` scope are retained, so a manager restart or owner change
fails closed. Both fresh uncached inventory pairs must retain that exact scope and exactly match
freshly remeasured inherited descriptor bindings. One absolute deadline covers both manager and
isolation bookends, cgroup capture, every bounded read, synchronous join, and final journal
revalidation. Attempts are also bound to the exact pending count, classified targets, fresh
manager/durable descriptor maps and unit invocation, so one exit set cannot consume another set's
samples.

The sampler requires the strict cgroup-namespace view `0::/`, pins the fixed cgroup2 root with
read-only `open()`, resolves and pins the service directory beneath it through
`openat2(BENEATH|NO_XDEV|NO_MAGICLINKS|NO_SYMLINKS)`, and pins both the PID and cgroup namespace.
Both the root and service descriptors must report a read-only mount. The service's kernfs file
handle is obtained through one fixed audited `name_to_handle_at(AT_EMPTY_PATH)` wrapper; its
nonzero `FILEID_KERNFS` value must exactly equal systemd's `ControlGroupId` and is never confused
with `st_ino`. Every complete revalidation reopens the fixed process records,
resolves the path beneath the retained root, remeasures directory and namespace identities, counts
the pending target set back to the earlier nonzero pidfd-observation count, and remeasures each
present custody binding. Only pending non-`CleanupConfirmed` targets must match the current pinned
service-cgroup inode; cleanup-confirmed targets remain structurally and manager validated without
claiming current membership. Two initial samples, one sample after the second manager observation,
and one fresh synchronous-join sample must have identical canonical projections. `cgroup.type` must
be exactly `domain`; the bounded canonical
`cgroup.stat` parser permits additional unique numeric kernel fields but requires exactly one zero
`nr_descendants` and `nr_dying_descendants`; and canonicalised `cgroup.procs` membership must be the
singleton current `MainPID`. Repeated lines containing that same PID are accepted because Linux
documents duplicate PID observations during iteration, while zero, noncanonical, overflowed, or
different PIDs fail closed.

Each isolation bookend additionally requires one stable nonzero 16-byte `InvocationID`, current
`MainPID`, zero `ControlPID`, a canonical non-root `ControlGroup`, nonzero matching
`ControlGroupId`, `Delegate=false`, empty delegate controllers/subgroup,
`ProtectControlGroups=true`, `ProtectControlGroupsEx=strict`, `PrivatePIDs=no`,
`KillMode=control-group`, and `SendSIGKILL=true`. The packaged unit enforces those values and removes
the broad `@mount` syscall group both from its positive allowlist and through an explicit
`SystemCallFilter=~@mount` subtraction while preserving the network-namespace syscalls required by
the typed worker bootstrap.

The result is still only bounded read-only quiescence sample/correlation evidence. `cgroup.type`,
`cgroup.stat`, and `cgroup.procs` are separate, non-atomic reads. The process-wide spawn guard closes
the helper's own admission path, but it does not serialize PID 1 or another privileged migration;
alternating external placement can still make every projection pass even though set-wide absence
never existed. It therefore proves neither continuous absence,
instantaneous old-process absence, nor absence when sampling or join returns. It is unusable as
cleanup authority. It exposes no PID, path, descriptor, signal, cgroup write, cleanup, journal,
manager-removal, adoption, or server authority. The process-wide admission guard excludes only new
workers created through this helper; it does not constrain PID 1 or another privileged actor. The
configured and observed strict mount does not prove that no writable cgroup descriptor was
inherited before startup. This slice therefore proves no network-namespace destruction,
kernel-resource cleanup, manager removal or journal transition. It keeps the helper in the same
non-empty refusal state, leaves AV1-10 Open, and leaves the fixed alpha score at 11/100 (11%).

This is still a refusal boundary, not production recovery. Any non-empty journal target set blocks
startup after read-only classification and drops its exact source-slot owners without publishing a
cleanup token or helper socket. The takeover creates no additional process-local source alias;
dropping the refused set closes every captured source slot while PID 1 retains any manager copies.
This classification invokes no descriptor-store removal, journal transition, worker adoption,
reaper or cleanup. Those proofs remain mandatory before the refusal may be replaced by settlement
and socket publication; the separate dormant removal adapter below does not change this startup
authority boundary.

### Production-dormant systemd descriptor-store mutation boundary

The helper contains a private adapter for the systemd v257 descriptor-store protocol. Its two
private non-test callers are the live-proof selector and the dormant supervisor publisher; neither
is connected to `ProductionServer`, `HelperEngine` or a request path. It
validates one fixed-shape opaque custody name, borrows exactly two already-owned descriptors,
snapshots their kernel identities and sends them together in one `SCM_RIGHTS` datagram containing
only the required `FDSTORE=1`, `FDNAME=` and `FDPOLL=0` assignments. It then sends `BARRIER=1`
separately with exactly one pipe descriptor and carries one absolute monotonic deadline through
every send, barrier wait and inventory read. The publication path never sends `READY=1` or
`FDSTOREREMOVE=1`.
Before the first send it rejects an existing exact name and any partial or complete reuse of either
role identity elsewhere in the bounded descriptor-store inventory, including reuse under a
different name.

A successful notify send is not an acknowledgement that either descriptor was stored, and a
successful barrier proves only that systemd processed earlier notifications. The adapter therefore
accepts custody only after uncached D-Bus reads show stable pre/post `NFileDescriptorStore` counts
and `DumpFileDescriptorStore()` supplies the exact complete, bounded descriptor multiset, including
matching name, mode, device, inode, device-node and open-flag identity. Every failure after the
publication datagram may have been accepted is classified as manager-may-own and carries one
opaque monotone in-process attempt identity into the retained supervisor terminal. The single
process-global manager-mutation gate binds that attempt before `sendmsg(2)` to the exact typed unit
object path, `MainPID`, parsed notify endpoint, fixed custody name and role-ordered local descriptor
identities. Publication and removal have distinct attempt-ID types but draw from one monotone
counter. A later caller cannot obtain a new attempt identity merely by encountering the existing
poison. Callers must retain their original affine descriptor owners; there is deliberately no
automatic removal on an ambiguous path.

A separate dormant, observation-only reconciler can inspect only that exact poisoned in-process
attempt. While borrowing both affine owners and holding the shared manager-mutation gate, it
reopens the stored unit object directly, sends one non-mutating `BARRIER=1`, takes two complete
bounded uncached D-Bus inventory identity projections, requires those projections and service
properties to be identical, and remeasures the local role binding before accepting a result. It
reports `ExactPresent` only for exactly two target name entries whose complete stat/status-flag
identity multiset matches the retained pair; any same-kernel-object alias under another name fails
closed even when flags differ. It reports `ExactAbsent` only when the target name and both kernel
objects are absent everywhere. Partial, wrong, unstable, expired or otherwise ambiguous
observations are `Unresolved`. Present and absent
use private evidence types distinct from publication attestation, so they cannot arm a worker,
adopt or remove custody, advance the journal, open dispatch, clear the permanent poison, or
authorize publication retry. This is correlated inventory evidence, not proof of shared
open-file-description identity. A `SupervisorDropped` terminal produced before a normal
manager-may-own failure returns has no exported attempt identity and deliberately remains
not reconcilable in this slice.

A separate private dormant adapter can send exactly one name-scoped descriptor-store removal. It
accepts an already stable complete startup inventory, the exact custody name and binding, and
borrows both affine local owners. Before its mutation boundary it validates the complete baseline,
takes a fresh uncached preflight snapshot which must equal that baseline, remeasures the local
binding, creates the separate barrier pipe, and rechecks the absolute deadline. It then poisons the
same manager-mutation gate immediately before sending exactly
`FDSTOREREMOVE=1\nFDNAME=<fixed-name>` with zero `SCM_RIGHTS` or other ancillary descriptors. A
separate `BARRIER=1` notification carries exactly one pipe descriptor. After the barrier, two fresh
uncached complete inventory snapshots must be equal, the service contract and local binding must
remain exact, and the result must be precisely the original baseline minus the named two-descriptor
pair with every unrelated entry unchanged. Only that result yields exact removal evidence.

Every error from immediately before the removal `sendmsg(2)` onward is
`ManagerMayHaveRemoved`; the retained opaque attempt stays poisoned and the adapter never retries
blindly. Its observation-only reconciler uses the same exact attempt, a new barrier, two equal
uncached complete snapshots, and local-binding remeasurement. Exact baseline-minus-pair may settle
the shared gate, while exact unchanged-baseline evidence still authorizes no retry and leaves the
gate poisoned; every other outcome remains unresolved. Publication, removal and their reconciler
observations now hold that one gate from the fresh baseline/preflight read through terminal
attestation. An ambiguous attempt of either kind blocks both mutation kinds, and a reconciler with
the wrong typed attempt kind or exact target binding fails before barrier or inventory I/O.
Publication reconciliation never clears poison; only exact-removed evidence for the same removal
attempt reopens a gate poisoned by that removal. The removal adapter and reconciler have no
production caller, do not prove worker death or kernel cleanup, and cannot by themselves advance
the ownership journal.

Only the durably confirmed `MayOwnCustody` token can derive an opaque, domain-separated fixed
custody name from its exact journal epoch, context, ownership ID and generation without exposing
those coordinates. A private dormant worker typestate first obtains the descriptor identities
through the same measurement path used by descriptor-store publication, persists them with the
complete worker anchor, and only then creates publication authority. A private dormant
activation-fenced supervisor can synchronously take that complete affine owner before any publisher
poll, reserve bounded terminal storage, and register its capacity permit and blocking-task handle
before activation. It performs at most one descriptor-store publication attempt, never retries, and
stores every resulting affine terminal before sending a non-authoritative completion notice.
`BeforeSend` and `ManagerMayOwn` are both unresolved and never authorize retry. Dropping the waiter
cannot cancel the owner-bearing work; an activated blocking publication survives outer-runtime
shutdown, while a queued abort stores the unpublished owner without polling the publisher. A
separately cloneable arm-only journal handle authorizes only the exact
`MayOwnCustody -> MayOwnPrepare` transition; `ProductionOwnershipRuntime` remains the sole owner of
actor startup, shutdown and thread settlement.

This is not production composition. The supervisor entry point and production publisher remain
private and unreachable from the server, engine and request path. Terminal storage has no
production consumer for the in-process observer; cross-process/restart-stable reconciliation,
adoption and authority-ordered manager removal are not connected, inherited descriptors are still
refused rather than adopted, and no restart reaper exists. In particular, no production worker-death
proof or exact namespace/kernel cleanup backend can satisfy the first settlement transition, and
the dormant removal evidence is not wired into the second. The executable live-proof path has not yet
produced recorded evidence inside the required disposable Debian 13 transient service. This
therefore leaves AV1-10 Open, keeps the fixed alpha score at 11/100 (11%), and closes no production,
crash-cleanup, datapath or acceptance milestone.

The unprivileged side may retain only a v3 `PreparedLeaseBatch`: its opaque non-secret context
handle and `PreparedLease` values containing an opaque lease handle, path, role, helper-generated
public key, kernel-proven public UDP endpoint, and `DirectAssigned` evidence. Later operations may
echo those handles and signed public peer tuples. A WireGuard private key, raw private-key bytes, or
an endpoint secret must never cross into routing, agent, reservation, discovery, or any other
unprivileged state.

The target worker transaction is intentionally stricter than the old worker:

- create an anonymous child network namespace;
- generate the private key inside that worker and retain it only in local `Zeroizing` memory;
- create/configure the device without peers, set the link up, then request `listen_port = 0`;
- require exact netlink acknowledgements and an exact correlated `GET`;
- publish only the derived public key and proven address/port;
- roll back exactly, or quarantine the complete context when absence cannot be proven.

Activation must derive all local overlay addresses, allowed prefixes, interface names, routes, and
fences from the route context, role, and path. It accepts only public peer material. Commit must
repeat a correlated WireGuard `GET` for every lease and must not install interception, advertise a
tunnel, or make a ledger/capacity claim without handshake and bidirectional counter proof.

## Anonymous namespace transport boundary

Route contexts use anonymous child network namespaces, while the current TCP and QUIC transports
open sockets in the host network namespace. Consequently, even a successfully committed child
interface would not be usable by those host-created sockets. v3 makes no datapath-active claim.

Internal protocol tag 17 now represents only an exact route-context/path/role/kind/local/remote
transport request and its exact echo. It is independent from the external protobuf schema. A private
blocking `AF_UNIX SOCK_SEQPACKET` socketpair has bounded read/write deadlines and canonical
request/response records. `SO_PASSCRED` is enabled on both receivers before either endpoint is
exposed. Every received record must contain exactly one kernel-selected `SCM_CREDENTIALS` value
matching the expected PID, UID and GID; missing, duplicate, wrong or truncated credentials and all
unexpected ancillary data fail closed. Internal protocol v3 follows an Acquire response with a
domain-separated 32-byte completion record. Success requires exactly one `MSG_CMSG_CLOEXEC`
descriptor in that record, transfers ownership into the consuming send API, drops the worker's
source owner, and then emits a distinct credentialed, descriptor-free source-release binding as a
third record. An error requires exactly no descriptor and no release record. The parent adopts the
installed descriptor immediately but does not return it before that exact release record arrives
under the same deadline. Every reject path closes it. This marker proves ordering in the audited
single-threaded worker implementation; it is not proof that a compromised process did not create an
untracked duplicate. Creator-time `SO_PEERCRED` is never used as proof of the later executed child
PID.

### Authenticated worker-v3 lifecycle foundation

The separate fixed `--internal-worker-v3` child entry has a tested parent launcher. The production
server's narrow functional-alpha backend now uses that launcher for one Client lease; the public
`HelperEngine::new` constructor still returns `Unavailable` before spawn or network work. The
launcher reopens the exact running Linux image through `/proc/self/exe`, creates a
private credential-enabled Unix seqpacket socketpair and generates a 256-bit OS-CSPRNG challenge. It
maps only the child endpoint to stdin, clears the environment, selects `/` as the working directory
and maps stdout and stderr to `/dev/null`. The launcher deliberately does not scan the process-wide
parent descriptor table or change flags on ambient parent descriptors: another thread can change
that table between any preflight and spawn. Instead, as the final user-installed pre-exec hook, one
async-signal-safe
`close_range(3, UINT_MAX, CLOSE_RANGE_UNSHARE | CLOSE_RANGE_CLOEXEC)` syscall privatises the child
descriptor table and marks every non-standard descriptor close-on-exec; any kernel error makes
spawn fail. An isolated subprocess test proves that a deliberately inheritable parent descriptor
does not reach the authenticated worker and that `UNSHARE` leaves the parent sentinel's descriptor
flags unchanged. While the spawn lock is held and after retirement-permit acquisition, the parent
reads `Seccomp` and `Seccomp_filters` from `/proc/thread-self/status` immediately before
`Command::spawn`; the child therefore inherits that exact per-thread filter baseline.

One 30-second absolute monotonic deadline follows launcher setup,
the post-lock pre-spawn check, credentialed handshake records, sandbox observation and liveness
proofs. Spawn-lock acquisition repeatedly uses `try_lock` with deadline-bounded sleeps and rechecks
the same deadline after acquiring the mutex, so an expired queued caller creates no child. The
blocking `Command::spawn` operation itself is not interruptible. Before entering it, the launcher
constructs an armed retirement owner with its permit and empty child slot. The spawn boundary holds
that slot and moves a successfully returned `Child` into it before returning, so no allocation,
deadline check or other fallible post-spawn step can observe an unowned child. Late setup or
handshake failure therefore retires that exact child boundedly or transfers the same owner to the
escalation reaper. Production reuses this bound only for its single functional-alpha Client lease;
it is not route setup, a datapath, crash recovery, or acceptance evidence.

After exec, the child closes raw descriptor 3 if present, atomically duplicates stdin with
`fcntl_dupfd_cloexec` using minimum 3, requires the returned descriptor to be exactly 3 and closes
stdin. Its bounded self-audit then requires exactly descriptors `{1, 2, 3}`. Before authentication,
stdout and stderr must resolve to `/dev/null`, while descriptor 3 must remain the exact connected,
CLOEXEC Unix seqpacket channel. The production-only applicator then captures the parent
network-namespace identity, validates its
bootstrap `CAP_KILL`, `CAP_SETGID`, `CAP_SETUID`, `CAP_SETPCAP`, `CAP_NET_ADMIN` and `CAP_SYS_ADMIN`
authority,
and enters a new network namespace. It immediately clears ambient capabilities, reduces the
bounding set to `CAP_NET_ADMIN | CAP_SETPCAP`, and reduces permitted/effective capabilities to
exactly `CAP_SETGID | CAP_SETUID | CAP_SETPCAP | CAP_NET_ADMIN`; `CAP_KILL`, `CAP_SYS_ADMIN`,
`CAP_NET_RAW` and all other surplus authority are therefore gone before any handshake record is
processed. It then
sets `NoNewPrivs` and installs one fixed amd64 classic-BPF program with
`SECCOMP_FILTER_FLAG_TSYNC`. A kernel error or positive unsynchronised-thread ID aborts bootstrap.
The filter returns `EPERM` for the x32 ABI, an unexpected audit architecture, `clone`, `clone3`,
`fork`, `vfork`, `setns` and `unshare`; all other syscalls are allowed. It then stops at an affine
pre-identity barrier. The parent requires a
credential-bound `NamespaceReady` from the still-root child, observes exactly one task and
descriptors `{1, 2, 3}`, proves the fresh namespace, transition capabilities, NNP and exactly one
filter beyond the inherited baseline, and pins `ns/net` before returning `NamespacePinned`.

Only after that acknowledgement does the child require ambient capabilities to remain empty, clear
all supplementary groups, reduce its bounding set, enable keep-caps, and set all
real/effective/saved GIDs and UIDs to
the startup-pinned `volparossa-worker` identity. It immediately reduces permitted/effective
capabilities to `CAP_NET_ADMIN | CAP_SETPCAP`, disables and verifies keep-caps, removes
`CAP_SETPCAP` from the bounding set last, and reduces permitted/effective capabilities to exactly
`CAP_NET_ADMIN`. The pre-barrier seccomp restrictions are monotonic, remain across the identity
transition and exec, and make the pinned network-namespace membership immutable. Final inheritable
and ambient sets are empty; exact PID, PPID, four-way UID/GID, empty groups, capability and
`NoNewPrivs` readback, seccomp filter mode with exactly the inherited count plus one, and the
unchanged pinned network namespace are required before the child sends its sandbox proof.
Because Linux clears `PR_SET_PDEATHSIG` during credential changes, the child restores and reads back
`SIGKILL` and revalidates its original parent before any post-drop IPC. The fake applicator and
relaxed test observer exist only under `cfg(test)`; release code has no environment or runtime
selector that can substitute them.

The first parent record canonically binds the internal magic and version, route context, generation,
challenge, original parent PID, exact `Child::id`, and the startup-pinned worker UID/GID. The child
accepts it only with exact kernel-provided root-parent PID/UID/GID credentials. The staged
`NamespaceReady` record must still carry the root child's exact kernel credentials; after the
parent's namespace pin and `NamespacePinned` acknowledgement, `ChildHello`, the proof, Ready and
all operational records must carry the dedicated worker credentials. Every transition record
echoes the complete binding.

The subsequent canonical proof is the post-apply completion barrier: only after receiving it does
the parent independently observe final status through the one anchored `/proc/<pid>` directory
descriptor acquired immediately after spawn and the `ns/net` descriptor pinned before identity
drop. The hard-incompatible sandbox-proof record is version 5 with a 192-byte layout that additionally
binds exact UID/GID and empty supplementary groups. Bounded parsing requires the expected PID/PPID,
identity, group, capability and `NoNewPrivs` values and filter mode 2 with exactly the parent's
pre-spawn count plus one. `/proc` exposes mode and count, not filter instructions; exact filter
content is instead structurally fixed by the reopened `/proc/self/exe` image and the no-input UAPI
wrapper. The parent keeps the anchored directory, pidfd and pre-drop `ns/net` pin, checks pidfd
liveness before and after every phase, and retains a pre-drop-opened `/proc/<pid>/fd` directory for
an independent exact `{1, 2, 3}` re-enumeration after the proof. It verifies every proof field and
hashes the exact proof bytes. It then sends
`SandboxAccepted(proof_hash)`; the child must verify every field before returning an exact
`SandboxReady(proof_hash)`. Only after that independent parent observation and Accepted binding does
the child set and read back `PR_SET_DUMPABLE = 0`; this still precedes Ready, every operational
request and any future ephemeral-key generation. The shipped helper unit and transient proof driver
also set `LimitCORE=0`. The parent repeats liveness checks after Ready, and no child loop or
successful spawn return is reachable earlier.

The pidfd, anchored proc descriptor and network-namespace pin move into `ProcessRetirement` before
Accepted. Every later timeout, authentication failure, uncertain termination, process drop and
reaper transfer preserves their linear ownership.
Tests cover syscall order and injected failure at every applicator step, strict
status/fd/task/proof parsers, canonical version-5 offsets, every fixed BPF branch and amd64 UAPI
layout, real unprivileged filter installation, the namespace-pin-before-identity-drop order,
the parent-death-signal restoration source order and readback path, proof-before-final-observation ordering, mutated
Accepted/Ready fields, parent mismatch, death after proof, descriptor leakage, pin retention, and
rejection of a descriptor opened after the pin, and the strong proof-to-Accepted-to-Ready sequence.
The final child identity/parent/PDEATHSIG check and channel timeout transition occur before Ready.
The exact single-task check occurs after the
confinement filter and before identity drop. The worker leader receives `EPERM` for every later
`clone`/`clone3`/`fork`/`vfork`/`setns`/`unshare` attempt, including post-Ready; therefore neither
the proven single-task state nor pinned network-namespace membership can change afterwards. The
fixed child image contains no descendant-creation step or untrusted input before filter
installation, but the parent does not independently enumerate descendants from that earlier
pre-filter interval. The pins are released only after confirmed leader reap.

This proves the code-level network-namespace, capability, descriptor, credential and dedicated
identity bootstrap. The package declares a fully locked `volparossa-worker` account with its own
group and no `volparossa` membership. Before any NSS lookup, startup safely reads bounded,
single-link root:root `/etc/nsswitch.conf`, `/etc/passwd` and `/etc/group` files and rejects metadata
drift during each read. The account databases may use only `files` or `files systemd`, in that
order; an optional `initgroups` rule has the same restriction. Agent, operator, worker and `shadow`
names and numeric IDs must be unique local records. Name and numeric NSS lookups must both reproduce
every local field, and `getgrouplist` must reproduce exactly the local service memberships. Thus an
external NSS principal, alternate local name using a service ID, or group alias cannot be pinned.
Startup then pins the numeric worker identity, rejects root, the systemd/Linux reserved IDs `65535`
and `4294967295`, the agent UID/GID, non-`/nonexistent` home, non-nologin shell and any supplementary
membership. The agent and
worker may not belong to the live `shadow` group. One drift-checked, fixed-capacity zeroizing shadow
snapshot must contain unique entries for both identities. The agent password must start with `!`;
the worker password must also start with `!` and its account-expiry field must be
exactly `1`, matching Debian 13's account-wide `systemd-sysusers u!` lock. It reads both entries from a
bounded regular root-owned `/etc/shadow` file with one link, owner-read access, no execute,
group-write or world bits, and group-read access only for the resolved live `shadow` group. Neither
service identity can mutate that file. A present POSIX access ACL, or an ACL state that cannot be
attested as explicitly absent, is rejected fail closed. The read buffer cannot reallocate old password hashes. This closes the
pre-existing-account collision that idempotent `systemd-sysusers` cannot repair. The shipped helper
unit and doctor contract now grant and require the reviewed seven-capability bootstrap set. Its
`CAP_KILL` authority is retained by the root parent so it can retire the dedicated-UID worker, but
the child drops it before the namespace-pin barrier and proves a final `CAP_NET_ADMIN`-only state.
The contract rejects `CAP_SYS_PTRACE` and adds only the individual `seccomp` syscall to the existing systemd syscall
groups so the fixed child filter can be installed without allowing all of `@sandbox`. After the drop, the worker's
distinct UID/GID plus exact `CAP_NET_ADMIN` set excludes same-UID signalling of the root parent and
access through the root:`volparossa` runtime-directory mode. The functional-alpha backend now calls
the launcher. The committed disposable driver now exercises the account transition, pre-filter task
state, path access denials and parent-signal denial first through its diagnostic selector and then
observes the functional worker created by the no-argument production server. This remains an
implemented gate rather than earned acceptance evidence until the exact merged `main` revision
produces a retained, host-revalidated PASS; it is not installed-package or restart evidence.

The helper unit deliberately sets `RestrictSUIDSGID=no`, unlike the agent and native MPQUIC units,
which retain `yes`. In systemd v257.13 that setting installs a separate seccomp filter which returns
`ENOSYS` for every `openat2(2)` call because seccomp cannot inspect the mode in the indirect
`open_how` argument. The helper cannot use systemd's suggested `openat(2)` fallback. It uses
non-fallback `openat2` both to constrain ordinary process records and cgroup paths with
`RESOLVE_BENEATH`, `NO_MAGICLINKS` and `NO_SYMLINKS`, and to deliberately follow only the fixed
`exe` and `ns/cgroup` procfs magic links relative to an already pinned exact process directory.
The helper-specific compatibility exception therefore preserves those distinct `openat2`
operations and their fail-closed resolution. Its compensating boundaries
are the fixed typed protocol with no caller-selected filesystem paths, `NoNewPrivileges=yes`,
`ProtectSystem=strict`, fixed host-visible writable runtime paths, private temporary directories,
`UMask=0077`, and a capability set without `CAP_CHOWN`, `CAP_FSETID` or `CAP_SETFCAP`. The dedicated
worker then drops to its distinct UID/GID and final `CAP_NET_ADMIN`-only state before accepting any
operation.

### Sequential live worker and production IPC proof driver

`tests/helper/require-live-worker-identity-proof.sh` now provides a preview-first, execute-gated
driver for one real `--internal-worker-v3-live-proof` invocation followed by one true no-argument
production-helper invocation. Execution is restricted to root inside a recognised disposable
Debian 13 amd64 VM with the exact systemd v257 manager. It copies the already-built helper and fixed
production IPC probe into a root-only stage. Both sources must be non-empty, workspace-owned 0755
regular files with one hard link and at most 128 MiB. Each copy runs under its own exact 128 MiB
file-size ceiling and is fenced by stable source identity, metadata, and matching source/staged
digests. After those two large copies, the root producer sets and verifies its own 1 MiB soft/hard
file-size limit before copying the bounded hook or writing account, capture, and report files; its
fixed path never raises that limit. It then creates collision-free synthetic service identities and
binds the staged passwd, group, shadow and nsswitch files read-only. systemd v257 resolves static
`User=` and `Group=` credentials before constructing those private bind mounts, so both transient
services declare only the host-resolvable `User=0`, `Group=0`, and an empty
`SupplementaryGroups=` assignment. After the namespace exists, the exact root-owned
`/usr/bin/setpriv` image changes only the primary and singleton supplementary group to the raw
staged agent GID and then executes the staged helper in the same MainPID. The unchanged helper
parent contract rejects any other UID/GID quartet, supplementary-group vector, capability set,
no-new-privileges state, or seccomp state in the diagnostic phase. The production hook
independently reads the no-argument helper's live `/proc/<MainPID>/status`, requires the same exact
credential and five-capability-set envelope plus seccomp mode 2 and a bounded positive filter
count, and includes that canonical observation in every existing running-identity revalidation.
This avoids all host account changes while granting the helper parent exactly the reviewed seven
bootstrap capabilities. The transient unit has
`PrivateNetwork=yes`,
`NotifyAccess=main`, `FileDescriptorStoreMax=128`, `FileDescriptorStorePreserve=yes`, and a private
temporary `/run`. The canonical root-owned system bus socket is bound read-only into that
private `/run`, and the unit pins `DBUS_SYSTEM_BUS_ADDRESS` to that verified path, so the
live-proof-only adapter cannot follow a manager-provided alternate address for its uncached systemd
inventory reads. The canonical root-owned `/run/systemd/notify` socket is also validated and bound
read-only back into both private `/run` mount namespaces. This preserves the manager-provided
`NOTIFY_SOCKET` endpoint needed by the live FD-store publication and the production startup
inventory barrier; systemd v257 does not restore that socket automatically for a standalone
`TemporaryFileSystem=/run`. Strict cgroup protection is submitted through the string-valued
`ProtectControlGroupsEx=strict` D-Bus property. The legacy `ProtectControlGroups` property is
boolean-only in systemd-run v257 and is deliberately forbidden by the static contract. The staged
helper aliases remain absolute, read-only `/run` paths passed as arguments to the exact host-visible
`/usr/bin/setpriv` executable. An exact `ExecSearchPath=/usr/sbin /usr/bin /sbin /bin` transient
property preserves the driver's fixed child `PATH`; the driver reads that property back from PID 1
for both transient units before accepting their contracts. Both calls also set and read back
`RestrictSUIDSGID=no`: v257's `yes` filter would reject the mandatory `openat2` recovery-anchor
resolution before the internal worker handshake. The private transient `/run` remains explicitly
`nosuid,noexec`, and all other applicable helper sandbox boundaries remain pinned.
Both units also pin and read back `CollectMode=inactive`: a real failure therefore remains loaded
long enough for exact terminal inspection, while successful or reset units can still be collected
during bounded retirement. Neither transient launch uses `--ignore-failure` or the aggressive
`--collect` shortcut. The diagnostic phase uses blocking `Type=exec` startup: PID 1 completes the
start job after successful execution of the fixed credential trampoline. The exact terminal
records, MainPID executable and process predicates then independently require its replacement by
the staged helper; the separate `RuntimeMaxSec=45s` is also read back exactly. A fast diagnostic
`exit(1)` can nevertheless make systemd v257's blocking client return
from the failed start-job wait before its later JSON `InvocationID` acquisition and print path. In
that one case the driver may recover diagnostic authority only when the launch captures are safe,
stdout is exactly empty, no JSON binding was accepted, and the nonzero launch status accompanies
successful tentative adoption of the exact random unit name, SHA-256 ownership marker and current
nonzero PID 1 `InvocationID`. The marker and current ID are rechecked after adoption and again
before a byte-exact helper stage is mapped. A nonempty or malformed stdout capture, a missing or
changed marker or ID, `not-found`, or any failed observation leaves the launch generic. This
recovery cannot authorize PASS: success still requires launch status zero, one exact JSON object,
empty client stderr, the original manager binding and `active:exited:success:1:0`. The driver
additionally reads back `Type=exec` for both units, `RemainAfterExit=yes` only for the diagnostic
unit, and the production default `RemainAfterExit=no`.
The first phase succeeds only with the two exact ordered helper records, an externally observed
post-exit `NFileDescriptorStore=2`, confirmed worker reap and pin release. Before the first phase
and after the fully retired second phase, the driver compares privacy-safe digests of account files,
mounts, resolver configuration, sysctls, links, addresses, routes, rules, nexthops, qdiscs,
`nf_tables`, legacy IPv4/IPv6 `x_tables` state and optional WireGuard state. Canonical
`nft --json list ruleset` output is the authority for `nf_tables`, including the `iptables-nft`
frontend; the mutable generic `iptables-save` alternatives are never used as evidence for a legacy
backend. Each host-state fence takes two identical normalized nft JSON observations around the
separate legacy captures.

A failed live-proof helper main writes exactly one payload-free versioned phase record covering only
parent-contract validation, production-runtime preparation, worker spawn, FD-store publication, or
retirement cleanup. The driver maps it to a fixed retained label only when the private capture is
byte-exact and safe, PID 1 still reports the same ownership marker and bound invocation, and the
terminal tuple proves a normal `exit(1)` by main. This includes the exact failed-`Type=exec`
empty-stdout adoption described above; the nonzero client status is then evidence of the same
already-bound helper failure, not a separate success claim. Unknown, extra, truncated and otherwise
malformed records, signals, manager drift and ambiguous launch envelopes remain generic and never
reflect raw stderr. A publication error remains the primary phase after all mandatory local cleanup
attempts; an ambiguous child retirement or failed reservation settlement is classified as
retirement cleanup. The two capability-set observations are normalized by the exact dynamically
tested Debian-compatible awk body; its loop variables deliberately avoid names reserved by Debian's
default `mawk`.

Legacy `x_tables` custody is derived only from the current network namespace's
`/proc/self/net/ip_tables_names` and `/proc/self/net/ip6_tables_names` inventories. Each family is
kept distinct as proc entry absent, proc entry present with no registered tables, or a bounded
present table-name inventory. A present inventory additionally requires two successful, strictly
normalized and byte-identical captures from the fixed absolute
`/usr/sbin/iptables-legacy-save -M /bin/false` or
`/usr/sbin/ip6tables-legacy-save -M /bin/false` producer; inventory observations before and after
those dumps must also be identical. Absence or an empty inventory never falls back to a generic
frontend, while malformed metadata, names, dump structure, counters or any drift fails closed.
These observations prove stability within each capture and equality at the two outer host-state
fences; they are not a continuous guarantee that firewall state was unchanged between those
fences.

A WireGuard dump is streamed through a validated private FIFO into a separately checked SHA-256
consumer and is never persisted or logged. Other host-network and firewall producer output exists
only in validated mode-0600 files under the root-only temporary stage, is normalized in a separately
checked step, and is removed with that stage. Published comparison records contain only
privacy-safe digests; retained diagnostics use fixed failure labels and never expose table names,
rules or raw firewall output. Each JSON producer must yield exactly one expected top-level document
and object entry shape. Separate IPv4 and IPv6 route/rule captures are tagged canonically from their
invoking address family before they are joined; an explicit contradictory family fails closed. All
seven network JSON normalizers suppress data-dependent parser diagnostics, so only their fixed
failure labels can reach retained stderr. A generic regular resolver target must retain the capture
owner's exact UID/GID pair. The only service-owned exception is the validated active
`systemd-resolved` identity, and
only for exact `/run/systemd/resolve/stub-resolv.conf` or
`/run/systemd/resolve/resolv.conf`: the target must be mode `0644`, single-linked and at most 64 KiB,
while the exact service-owned runtime directory must be mode `0755` and every higher parent remains
root-owned and non-writable. The pinned Debian proof additionally requires the root-owned
`/etc/resolv.conf -> ../run/systemd/resolve/stub-resolv.conf` object. Repeated service-invocation,
process-credential, runtime-directory, object, target, metadata and digest observations reject
restart, replacement, mixed-owner authority, writable path components and other drift.

Private capture metadata is checked through the numeric regular-file type and exact owner, mode and
single-link tuple. It therefore accepts a successful zero-length stream without confusing GNU
`stat`'s `regular empty file` label with a different file type. Whether a capture must be empty,
non-empty or match a canonical shape is enforced separately at each semantic consumer; metadata
acceptance alone never supplies that content claim.

Only after the first transient unit is `not-found` and its exact cgroup is absent may the driver
reuse that random unit name. The second invocation gets a separately derived ownership marker and a
different nonzero `InvocationID`, runs the exact staged helper with no argument, and binds private
runtime and proof directories into its private `/run`. A fixed probe performs two successful
same-process tag-35 runtime queries around all negative cases. Separate connections prove zero and
oversized frame rejection, retired/unknown/version/noncanonical wire rejection, wrong UID with the
right socket group, right UID with the wrong primary GID but the right supplementary socket group,
and root UID rejection. Every negative credential case therefore passes filesystem DAC before the
server applies exact `SO_PEERCRED` policy. The probe additionally requires the server peer PID and
primary GID to equal the unit's exact `MainPID` and staged agent GID, while the hook brackets one
socket inode.

The hook then creates one fixed dummy underlay only inside that production unit's
`PrivateNetwork` namespace. The staged-agent probe registers an exact tag-35 intent, prepares one
Client-role lease, closes its first stream and publishes a fixed READY record. While it waits on a
root-owned FIFO, the hook requires one direct child of the unchanged helper `MainPID`, stable
process starttime and dedicated UID/GID, a network namespace distinct from the helper, and exactly one
live WireGuard interface beside loopback. That interface must be UP, carry the exact ownership-marker
prefix and one global `/128`, expose a non-zero public key/listen port, and have neither peers nor a
firewall mark. The probe validates the exact correlated response and `DirectAssigned` fixture
endpoint without printing handles, keys, ports or runtime IDs; the external hook deliberately does
not claim an independent byte-for-byte join to those response values.

One fixed release byte authorizes exact Destroy and an idempotent `existed=false` retry. A second
distinct context is then prepared and destroyed under the same helper runtime; distinct context and
lease handles plus a distinct public key prove capacity reuse. After both cycles, the hook requires
zero helper children, no WireGuard object in its retained first-worker namespace pin, no helper FD
retaining that namespace or any foreign worker network namespace, an empty descriptor store and the
fixed exact-one-loopback/no-default-route cleanup predicate after the dummy underlay is removed.
Only after all probe output and the unchanged manager launch tuple, bound helper image metadata,
process starttime, `MainPID` and `InvocationID` have been checked does the hook publish ten distinct fixed proof
records: the seven read-only/negative IPC records followed by READY, functional PASS and
external-cleanup PASS. PID 1 bounds the
second unit to three minutes even if the runner disappears, and each transient unit independently
receives a 1 MiB hard/soft `RLIMIT_FSIZE`. Unit stdout and stderr are attested as `null`, so structured
helper rejection logs cannot grow host files. The start hook proves that the same captured lock inode
is exclusively contended while the exact helper process runs. Normal `SIGTERM` must produce exit
status zero, remove the socket, preserve the initially absent-or-exact ownership journal, prove that
inode is then unlocked, keep the descriptor store empty, and leave no old process or cgroup.
Host `/run/volparossa` must be absent at both host-state fences; the private runtime bind never
targets the host path.

The first transient proof unit intentionally differs from the shipped production unit in every
following respect:

- it is a non-aggressively collected `Type=exec` with `RemainAfterExit=yes`, a 45-second activation
  and runtime bound, no restart, and the private proof selector instead of the production
  no-argument server;
- PID 1 installs only host-resolvable root/root unit credentials with an empty
  `SupplementaryGroups=` assignment because systemd resolves static credentials before installing
  the synthetic account-file bind mounts. Once inside that completed sandbox, the fixed
  `/usr/bin/setpriv` trampoline installs the raw collision-free staged GID as both primary group and
  the singleton supplementary group, then executes the helper without changing its UID or
  capabilities. The diagnostic helper parent contract and the production hook's repeated live
  process-status contract reject leaked host-root groups and every other final identity; no host
  account is created or modified;
- it overlays four synthetic account files read-only, adds `PrivateNetwork=yes`, and replaces host
  `/run` with a 16 MiB private tmpfs; the root-owned staged helper image is also bound read-only into
  that private `/run`, together with a read-only bind of the host system bus socket and an exact
  `DBUS_SYSTEM_BUS_ADDRESS` pointing to it. Consequently it
  does not use the production unit's host
  `ReadWritePaths=/run/volparossa -/run/netns` contract;
- it retains the shipped unit's exact `NotifyAccess=main`, 128-entry descriptor-store maximum and
  `FileDescriptorStorePreserve=yes` settings so the two published descriptors remain externally
  observable after the diagnostic main process exits;
- it captures stdout and stderr in the root-only stage, sets `TasksMax=16` and
  `SetLoginEnvironment=no`, and omits the production config condition/environment, ordering,
  restart and install-target semantics that are irrelevant to the internal proof.

The device policy, no-new-privileges setting, exact capability sets, system-call filter,
namespace restriction, address-family restriction and remaining applicable hardening properties
match the shipped helper unit. Retirement addresses only the exact random transient unit, waits
boundedly for stop, and binds every stop, reset and clean operation to one exact current nonzero
systemd v257 `InvocationID`. The normal route requires it to match the returned JSON ID; tentative
recovery requires the exact per-stage marker before adopting the manager's current ID. A failed
diagnostic unit is reset to inactive before its descriptor store is cleaned. Retirement cleans only
that unit's `fdstore`, requires either
`NFileDescriptorStore=0` or `LoadState=not-found`, resets it when still present and waits boundedly
for collection; any ambiguous observation fails the gate. The driver has not yet produced a retained
exact-main PASS. A non-main branch run may exercise and validate the same disposable proof, but
on PASS `non-retained-pr-smoke` deliberately discards its report, hash, environment, console and
proof diagnostics and requires an empty output directory. Its workflow never uploads branch PASS
artifacts or failure diagnostics; a failed smoke exposes only one fixed allowlisted category (or
`unclassified`) on job stderr. `worker-launch-status` may additionally expose only a fixed structural
launch-binding/terminal/stage classification. After branch
[run 33273482691](https://github.com/VOLPAROSSA/volparossa/actions/runs/33273482691) reached
`worker-confinement`, that category may additionally expose only its first fixed `bounding`,
`ambient`, `private-network` or `control-group` subcategory. It never reports the property value,
unit name, cgroup path or capability payload, and a missing, duplicate, malformed or late
confinement record is suppressed. Follow-up branch
[run 33274272679](https://github.com/VOLPAROSSA/volparossa/actions/runs/33274272679) at
`80e0dd077ceab4c8c8a33590a83299e179dde10f` ran the disposable VM in
[job 99158142816](https://github.com/VOLPAROSSA/volparossa/actions/runs/33274272679/job/99158142816)
and retained `control-group`. The already completed internal live proof had pinned the helper parent
and worker to the same cgroup path and inode while both existed. The external manager readback
occurred after the retained diagnostic service reached `active (exited)`, when systemd had
released its empty service cgroup and consequently returned an empty `ControlGroup`. The diagnostic
unit now explicitly selects `system.slice`, requires an exactly empty terminal `ControlGroup` plus
exact persistent `Slice=system.slice`, and derives the fixed former service-cgroup path only for its
post-retirement absence check. The production transient also selects and reads back exact
`Slice=system.slice`; its process remains running during observation and its exact nonempty live
`ControlGroup` readback is still mandatory. The next non-retained branch
[run 33275030601](https://github.com/VOLPAROSSA/volparossa/actions/runs/33275030601) at
`20f8a121f7aa020450587251dad9de66ec7738fc` ran that correction in
[job 99160142810](https://github.com/VOLPAROSSA/volparossa/actions/runs/33275030601/job/99160142810),
but the guest gate exited with status 2 before its normal fixed final report, so the runner could
retain only `unclassified`. Static review found two fail-closed observations that could mask a
fixed production predicate with that shell status: an unsafe or missing `unit.identity` left its
later retirement executable operand unset under `set -u`, and a failed redirection on the POSIX
special builtin `exec` could terminate the non-interactive shell before its `else` branch. All
identity operands are now initialized before validation, and the lock probe uses `command exec` so
redirection failure is an ordinary recorded predicate failure. As a bounded fallback, the existing
EXIT cleanup emits exactly one of eight value-free monotonic driver phases only for a nonzero exit
before normal final reporting; it never changes the original or cleanup-derived exit status. A
non-retained runner exposes that single phase only beside `unclassified`, rejecting missing,
duplicate, malformed, mixed, private-key-bearing or non-allowlisted records. This failed run is not
PASS evidence; the fixed alpha score remains **11/100** and AV1-09 remains Open. Follow-up branch
[run 33275945986](https://github.com/VOLPAROSSA/volparossa/actions/runs/33275945986) at
`38ee44a81991f660168a76342584416d04a6ef5d` ran the disposable VM in
[job 99162565524](https://github.com/VOLPAROSSA/volparossa/actions/runs/33275945986/job/99162565524)
and reached the fixed first failure `production-launch-status`. The production service still sends
both output streams to systemd null targets, so that failed run provides no raw `ExecStartPost`
message. The fixed start hook now advances through one fixed monotonic stage allowlist covering
preflight/runtime, identity, active-lock, each protocol probe group, functional underlay,
probe-ready, worker observation, probe finish, cleanup and publication. On failure it atomically
publishes at most one root-owned mode-0600 single-link `start.failure` containing only that stage.
All potentially failing hook descriptor opens and closes use ordinary-failure `command exec`,
including the background probe handoff, so redirection errors return through the same fixed failure
path. The gate accepts one exact canonical record only when the first recorded predicate is
`production-launch-status`; the non-retained runner exposes that fixed stage only paired with the
same exact category and rejects missing, duplicate, invalid, mixed and privacy-unsafe input. This
failed run remains non-PASS evidence; the fixed alpha score remains **11/100** and AV1-09 remains
Open. Exact branch
[run 33278664815](https://github.com/VOLPAROSSA/volparossa/actions/runs/33278664815) at
`b050fe576ebd2e77cc4d3c871dad22f9d91e267b` ran the disposable VM in
[job 99169908991](https://github.com/VOLPAROSSA/volparossa/actions/runs/33278664815/job/99169908991)
and retained `production-launch-status` with diagnostic `identity-command`. The preceding typed
manager fix therefore worked, but the separately confined hook could not read the non-dumpable
agent-GID helper's `/proc/<pid>/cmdline` and `exe` magic link. Granting `CAP_SYS_PTRACE` or binding
systemd's private manager socket would weaken the proof boundary, so neither is done.

The replacement launch lineage is externally anchored at PID 1. Over the read-only policy-mediated
system bus, the hook requires exact systemd v257 `ExecStart` and `ExecStartEx` ten-field tuple
shapes, matching running timestamps and PID, false/empty flags, and exactly
`/usr/bin/setpriv --regid=<agent-gid> --groups=<agent-gid> --
/run/volparossa-helper-production`. The bind-mounted launch image must independently remain one
root-owned, mode-0500, single-link regular file. Its initial metadata and SHA-256 are recorded; the
gate requires that digest to equal the already fenced staged helper digest, and ordinary identity
rechecks compare metadata without repeatedly hashing the roughly 78 MiB image. One stable bracket
observes `InvocationID`, `MainPID`, launch tuple, image, canonical process starttime, exact status,
then starttime, image, `MainPID` and `InvocationID` in reverse. Each socket probe inside the wider
hook is still bound by `SO_PEERCRED == MainPID`, and the same full identity artifact brackets it.
Post-retirement observation uses the captured starttime rather than a procfs magic link, treats a
different token as PID reuse, and never treats an extant unreadable proc record as absent. The
worker-side external check deliberately makes no byte-for-byte executable claim. The production
start/stop hook is source-pinned through `setpriv` to UID 0 with all GID fields and its sole group
equal to the agent GID; its own status must retain the helper capability mask, no-new-privileges and
seccomp contract. This matches the staged helper's procfs credentials without adding
`CAP_SYS_PTRACE`, making the manager's retained descriptors observable. `ExecStartPost` and
`ExecStopPost` are not yet independently re-read as typed manager tuples, so this is a
source-pinned command plus exact hook-self-status seam rather than an atomic PID-1 command proof.
At READY, every parent-held pidfd must name the one direct child in both `Pid` and `NSpid` fdinfo
fields and every pidfd duplicate must identify the same kernel object. Every retained numeric proc
directory must be `/proc/<child>`, and all parent-held foreign network-namespace descriptors must
identify the same distinct namespace. The hook duplicates one parent process-directory pin to FD 8
and one namespace pin to FD 7. Descriptor-relative `stat` and `status` observations bind the child
PID, PPID, namespace PID, single thread, starttime, dedicated credentials, empty groups,
no-new-privileges, one additional seccomp filter and the exact worker-only `CAP_NET_ADMIN` masks
before and after the namespace readback. After Destroy, FD 8 must expose no process records, the
helper must retain no pidfd, proc-directory or foreign-netns worker custody, and FD 7 must show no
WireGuard object before both observer pins close. The root-owned setgid mode-2700 proof directory
keeps hook-created artifacts root:root mode 0600 despite the agent GID. This failed run and the
correction are not PASS evidence; a
fresh exact-main KVM remains required and the alpha score remains **11/100**. The second phase
exercises the production server entry point, but not an installed package,
the shipped unit
file, restart policy, or inherited-descriptor adoption/recovery. Until a successful exact-main run
is durably tied to the same clean commit and retained, the gate is not earned package, datapath, A14
or A15 evidence.

Before the blocking start call, the driver atomically supplies a `Description` containing a
SHA-256 ownership marker derived from the validated random unit name and temporary-stage inode
identity. Normal bounded retirement begins after `systemd-run` has returned one exact JSON object
containing that unit name and a nonzero lowercase 128-bit `InvocationID`, and the manager reports
the same marker and ID. The exact failed-start diagnostic path and interrupt or invalid-reply
cleanup may instead promote tentative ownership only after bounded read-only observations prove
the exact name, marker and nonzero current ID. The failed-start diagnostic binding additionally
requires safe captures and byte-empty stdout, then rechecks both marker and current ID before
exposing the fixed helper stage. If tentative ownership cannot be established, the driver performs
no unit mutation, fails the proof, and requires the disposable VM to be discarded. Drift observed
after exact adoption still blocks stage mapping and permits only exact-ID retirement of that already
owned unit. It never guesses that a same-named unit belongs to this run.

The child opens its worker-local netlink sockets, activates loopback, and implements exact
single-lease WireGuard `Prepare` and `Destroy`. The no-argument production server now dispatches it
through the crate-private functional-alpha backend: for at most one live Client context at a time,
containing exactly one Client-role lease, the parent exclusively creates and provisionally proves
the helper-derived birth link at a deterministic retained ifindex, sets and re-proves its exact
durable alias, and moves it without renumbering into the pinned child `NEWNET` before Prepare.
Activate, Commit, peer configuration, routing, nftables, sysctl,
socket-factory operations and every datapath remain rejected. The public `HelperEngine::new`
constructor remains unavailable and does not select this backend.

A separate bounded registry now reserves a non-copyable monotonic generation token before spawn or
handshake. Pending tokens count against the same 64-context cap, are bound to one context and expiry,
and expire within the 15-minute maximum. Spawn consumes the token and either returns it unchanged on
failure for exact abandon, or packages it with the authenticated child for one exact registration
commit. Abandon, expiry and binding mismatch burn the generation; overflow fails closed and stale
tokens cannot remove or register a replacement. The registry also bounds both exact-response cache
entries and request-ID/digest tombstones at 1024. Tombstones cover descriptor-returning operations,
which are never replayed. Expiry, detected child death, digest collision and ambiguous IPC
quarantine the exact generation.

The registry uses one short synchronous mutex so shutdown can install its fence and detach every
process owner before returning a wait future. Code under that mutex only validates or moves state
and ownership; it never probes, kills, polls, sleeps or reaps. Bounded process work runs under a
supervisor after detachment. While the coordinator remains open, a failed bounded attempt is
reattached only to the exact quarantined generation. Once the shutdown fence is installed, normal
reattach is prohibited: the supervisor moves that detached owner into the bounded
shutdown-settlement queue. An orderly shutdown timeout retains each exact `DetachedWorker` and
unfinished supervisor handle in the coordinator for a later attempt. A non-shutdown reattach
failure, launch-cleanup uncertainty, fatal retirement result, or cancelled/panicked shutdown task
instead transfers every remaining linearly owned retirement record to the process-wide in-memory
escalation reaper. `WorkerProcess` and `ProcessRetirement` destruction perform no child-process
operation: they only move an armed retirement record to that reaper. Queue mutex poisoning is
recovered with the contained ownership intact.

The reaper and its fixed pool of 64 permits are initialised before `command.spawn()`. Every
admitted child consumes exactly one permit, carried through `WorkerProcess` and
`ProcessRetirement` until confirmed reap. If no permit is available, launch fails before child
creation. The queue is separately capped at the same 64 entries; because every queued record carries a distinct
permit, saturation by a valid additional owner is impossible. A wrong permit, an over-cap queue or
permit-accounting overflow is an internal ownership-invariant breach and terminates the helper
process without unwinding an owner. Failure to start the reaper is remembered and rejects every
later launch before a child exists; unexpected reaper-thread return or panic is likewise
process-fatal.

Each ordinary supervisor or reaper process attempt is bounded to 250 ms. A clean timeout leaves the
live hint, retirement ownership and namespace pins intact; the detached reaper waits 5 ms and queues
that same owner for another bounded round. Orderly shutdown instead uses the caller's absolute
deadline for each retirement proof and preserves a timed-out owner for an explicit later shutdown
attempt. A signal error gets one immediate wait race-check: an already reaped child succeeds, while
a still-running child or any wait error is process-fatal. Fatal outcomes abort without unwinding or
requeueing the armed owner. No ordinary request waiter follows the reaper retry loop. An orderly
shutdown waiter is bounded independently from its caller-independent cleanup task and can observe
`Pending`; the attempt later publishes `Confirmed`, `Retryable`, or terminal `Unresolved`. An exact
retry owner may remain in memory for the helper lifetime when the operating system never confirms
reap. Neither that state nor the reaper permits are durable across a helper crash. The
production-started v3 actor does not change that because no production issuance/arming writer or
restart reaper is connected.

Exact cache hits use a registry-lock-free point-in-time process probe followed by registry-locked
checks of the atomic hint, expiry, generation and shutdown state. There is deliberately no watcher
or pidfd, so a child can still die after a positive probe. The in-memory fallback queue is not a
replacement for durable secret-free ownership and crash recovery; the functional-alpha production
adapter deliberately remains process-lifetime-only.

The async coordinator enforces the required transaction shape: PLAN records the
exact context, generation, phase, token, request digest and one caller-owned monotonic deadline
under its short mutex, then starts an owned supervisor before the caller can wait on the oneshot
result. `execute_until` rejects expiry again immediately before PLAN, leaving no tombstone,
in-flight token or channel write. Exact cache hits carry the same deadline into their liveness
probe. For a new call, that one deadline is copied without renewal through request send, response
receive, the required second binding/optional-FD record and success-only third source-release record
for Acquire, liveness proof and the COMMIT decision. Credentialed transport uses readiness polling
plus nonblocking syscalls; interrupt and readiness races reuse the remaining budget, and every
send/receive syscall has a post-operation expiry check. Any late installed descriptor is already
RAII-owned and is closed before timeout is returned. This deadline is the PLAN/IPC/liveness/COMMIT
acceptance boundary, not a promise that the call future is delivered by that instant: Tokio
scheduling and mandatory exact-owner cleanup can delay an error result, but can never authorize a
late success or COMMIT.

An Acquire descriptor remains inside the private affine `CredentialedWorkerFd` owner until the
second record has the exact expected PID/UID/GID credential, exactly one credential and one FD, no
other ancillary data or truncation, the complete request/response binding, and remaining deadline.
Only then does the consuming adoption call the audited Linux-UAPI wrapper: `F_DUPFD_CLOEXEC` with
minimum descriptor 3 creates independent ownership, that result moves immediately into `OwnedFd`,
and `F_GETFD` must read back `FD_CLOEXEC`. The wrapper closes the duplicate on failed readback; the
private owner is consumed and closes the original when the duplication call returns, on either
success or error. The receiver then requires the exact domain-separated, descriptor-free
source-release record with the same credentials and original deadline. A missing, wrong or late
record closes the adopted duplicate and makes the call ambiguous. One final deadline completion
check returns the adopted `OwnedFd` or closes it on expiry. Thus rejection, adoption failure,
release-barrier failure and final-deadline failure retain no descriptor, while a success exposes
exactly one ordinary affine parent owner.

All blocking credentialed IPC and liveness work runs outside the registry mutex. The supervisor
reacquires the mutex only to commit after revalidating generation, token, digest, deadline, TTL,
shutdown and the latest registry-lock-free liveness hint, or to quarantine and detach for cleanup.
A successful terminal `DestroyContext` detaches for bounded retirement without requiring a positive
pre-retirement liveness probe. Timeout, EOF, join failure, malformed response, stale completion,
detected child death, or either-record failure for an Acquire result never retries the IPC
operation. Caller cancellation drops only its result receiver: the already-owned supervisor keeps
the transaction authority until commit rejection or exact cleanup.

Before admission, `execute`/`execute_until` must obtain the current Tokio runtime handle. Its absence
returns `RuntimeUnavailable` before any permit, registry PLAN or task creation. The legacy
`execute` wrapper creates one five-second absolute deadline for its complete typed call; it does not
reset that budget per response record. A fixed 64-slot linear supervisor admission is then acquired
under the same mutex as the shutdown fence before every PLAN, including exact cache hits and
cleanup-triggering requests. Saturation returns `Capacity` before registry mutation or task spawn.

Task creation is a gated two-phase handoff. The caller keeps the pending permit while it creates a
dormant supervisor task outside the supervisor mutex. The task cannot receive its permit or run
work until one later critical section rechecks the fence, converts pending to task ownership,
passes the permit and records the handle. A closed runtime or spawn panic is therefore handled
without a permit destructor relocking an already-held supervisor mutex; a fresh PLAN is either
owned by concurrent shutdown or token-bound quarantined with process ownership transferred to the
reaper. Fence rejection closes the dormant task without running work. The task settlement guard
keeps an activated permit through normal completion or cancellation, while caller cancellation
releases a still-pending permit. The accounting invariant remains
`recorded handles + pending admissions <= 64`; the pending side also bounds dormant handles. An
earlier PLAN is covered by the initial/final fenced detach sweeps.

`shutdown_until` is a synchronous starter that returns a bounded wait future. A request that would
start a new attempt first validates its deadline; an already-expired deadline returns `Retryable`
without fencing, detaching, incrementing the attempt ID or otherwise changing state. For a valid
deadline, before returning the future and before any await, one synchronous critical section fences
new supervisors, assigns a monotonically increasing attempt ID, performs the initial registry
detach and transfers those owners plus every existing supervisor handle to one caller-independent
shutdown task. Every supervisor has an explicit RAII settlement: a normal return settles it, an
abnormal task drop marks teardown unresolved, and a failed retire observed after the fence
transfers its detached process into the bounded shutdown-owner queue instead of reattaching it as a
registry worker.

The shutdown state is explicit: `Pending`, `Confirmed`, `Retryable`, or `Unresolved`. Concurrent
callers share the exact pending attempt and completion identity. Existing `Confirmed` and
`Unresolved` results are sticky and returned before considering a new deadline; an existing
`Pending` attempt also remains shared. A waiter's deadline can return `Pending` without cancelling
that owned attempt. It accepts a published result only when completion was linearized strictly
before that waiter's own absolute deadline; an equal or later publication is observed as `Pending`,
even if the result is available when the waiter checks. The task processes its initial owners,
waits for all captured supervisor handles, drains their shutdown-owner settlements, and then
performs a second fenced registry detach sweep. All process work remains outside the registry
mutex. An orderly deadline returns every still-owned worker and unfinished handle to coordinator
state as `Retryable`; only then may a later caller create a new attempt with a new ID. That later
attempt can upgrade the result to `Confirmed` after exact operating-system absence is proved.

`Confirmed` requires every retirement in both waves to be reaped and purged, every captured
supervisor to settle, no unresolved settlement, zero active or pending permits, no retained owner
or handle, and an empty worker-record registry after the final sweep. The task owns an
attempt-correlated RAII publication guard. Panic, abort, missing runtime or runtime/task
cancellation escalates remaining exact process owners, aborts retained handles and publishes
terminal `Unresolved`; that fail-closed status is never upgraded by a later runtime. The settlement
ledger's unresolved bit is also monotonic: setting it drains every already-captured shutdown owner
to the reaper while holding the ledger lock, and a later owner capture observes the same bit and
escalates immediately instead of becoming stranded. The legacy `shutdown()` wrapper creates one
five-second absolute deadline and returns `true` only for `Confirmed`; `Pending`, `Retryable`, and
`Unresolved` all map to `false`.

Tests cover waiter abort without task cancellation, concurrent callers sharing one attempt,
orderly timeout retaining exact owners for a later successful retry, runtime cancellation remaining
terminal, rejection of an expired new shutdown attempt without state mutation, waiter publication
ordering at its exact deadline, shutdown exactly between a failed retire and reattach, the final
detach sweep, launch cleanup timeout, reattach failure, process-owner permit-cap saturation,
parallel exact-cache-hit coordinator-cap rejection before PLAN, expired pre-PLAN admission without
registry mutation, no-runtime polling before admission or PLAN, mutex-poison ownership, caller abort
around PLAN, generation ABA, late/dead commit rejection, descriptor closure, tombstone bounds and
registry-lock availability.

The production server's functional-alpha backend now calls this worker path for one Client lease;
no production route manager calls it. The production engine supervises cancellation-safe
PLAN -> CALL -> COMMIT/rollback transactions: it
reserves and revalidates state under `EngineState`, while every backend call runs without that mutex
held. The narrow backend implements real Prepare/Destroy only. It returns `Unavailable` for
Activate, Probe and transport acquisition, and the engine rejects client ingress as `Unavailable`
before backend dispatch. This process-lifetime composition is not full production readiness.

### Affine asynchronous engine/backend boundary

Every mutating engine transaction now retains one non-cloneable, armed `OperationOwner` outside the
spawned backend task. The state and backend receive only non-authoritative correlation copies. An
unexpected owner drop after PLAN is process-fatal rather than silently leaving privileged state
ownerless. The backend future factory is invoked lazily inside the owned Tokio task, so a panic both
before future construction and during polling becomes a join failure while the engine still owns
exact rollback authority.

The stable backend lineage binds the helper runtime, route context, initial Prepare generation and
request ID/digest, and both Unix expiries. Activate and Commit rotate the engine operation generation
without rotating that lineage. Each call additionally binds the exact operation sequence, current
generation, prior phase, kind, request ID/digest, backend phase/action, and one monotonic absolute
deadline. A completion must echo that complete binding. Substitution is ambiguous; an owned
descriptor in a rejected or late Acquire completion is closed before exact Destroy begins.

The engine deadline is deliberately only a soft ambiguity boundary. It returns a bounded ambiguous
response without cancelling the task, then awaits task settlement without another engine timeout
while retaining the affine owner. A production adapter must therefore enforce the same absolute
deadline internally and reach a terminal result or transfer exact ownership to a hard-bounded
reaper. `CleanupIncomplete` is not a definitive error: Probe and Acquire uncertainty trigger exact
rollback, and failed absence proof leaves the lineage quarantined. Destroy accepts the stable
lineage plus the current operation binding, and `ConfirmedAbsent` means that exact worker and its
pins, journal authority and descriptors are gone. Runtime shutdown is correlated by runtime ID and
deadline and starts only after every per-context Destroy and all engine cleanup state are confirmed.

Fake/adversarial tests cover factory and poll panic, caller cancellation, missing state-binding
recovery, stale-owner rejection, generation overflow, deadline and completion substitution, runtime
shutdown correlation, wrong-binding and timed-out Acquire descriptor closure before Destroy, and
retryable shutdown after incomplete cleanup. This establishes only the adapter boundary. The public
standalone constructor still installs the unavailable backend and performs no worker or network
mutation; only the production server selects the functional-alpha adapter.

A private dormant worker-lifecycle seam now reserves a coordinator-local generation, changes its
reservation to a non-expiring `LifecycleOwned` shutdown fence, authenticates one passive sandboxed
worker under the caller's same hard deadline, and registers it in `Starting` without dispatching a
child operation. Failures before reservation, or definitive spawn failures followed by exact
absence, are rejected. Every other post-reservation deadline, spawn, registration, reap or purge
outcome returns a non-`Clone` owner carrying an exact placement. `Spawned`, `Registered`,
`Detached`, and `ReapedPendingPurge` transitions recheck the deadline immediately before their
registry mutation. A reaped retry never signals or waits for the process a second time; it retains
the pidfd, anchored process-directory descriptor and typed network-namespace descriptor until the
exact generation is absent from records, reservations, cache and tombstone maps and both ordering
indexes. Registration failure keeps the `LifecycleOwned` reservation visible to shutdown until
that detached process is reaped. Unspawned settlement removes secondary residue while retaining
the fence and abandons the reservation only as its final mutation.

If a successful terminal supervisor `DestroyContext` has already confirmed worker reap and purged
the exact generation from all six registry locations, a separately retained affine `Registered`
owner may prove that complete absence under the registry lock and settle idempotently to
`ConfirmedWorkerGenerationAbsent`. That settlement neither signals nor waits for the process a
second time. Any remaining record, reservation, cache entry, tombstone or ordering-index entry, or
an elapsed hard deadline, fails closed while retaining the affine owner for exact retry. This seam
remains private and dormant: it adds no production issuance/arming writer or restart reaper,
performs no host-network mutation, and is not datapath or acceptance evidence.

The corresponding recovery source is available only for the exact same coordinator and generation
while the registered record is live, unquarantined, idle and still in `Starting`. Bootstrap retains
the exact pidfd and proc directory, boot-ID procfs file, process start ticks, executable `O_PATH`
descriptor, cgroup namespace, cgroup2 root and service-cgroup descriptor, plus the typed network
namespace. The child executable is matched to the parent's running image and the child unified
cgroup is matched to the parent service cgroup. After independently observing that the fixed filter
denies both exec entry points and later namespace transitions, the parent revalidates the protected
procfs magic-link bindings before acknowledging the identity-drop barrier. Final post-drop
observation requires exact `EACCES` for both magic links, then seals the anchor from its retained
descriptors plus freshly read process-start and unified-cgroup records; `CAP_SYS_PTRACE` is neither
required nor permitted.

Recovery duplicates only affine descriptors and immutable snapshots while the registry record is
locked. It then drops that lock, checks pidfd liveness and re-derives all eight durable coordinates
from the retained objects under the caller's same deadline. Only after constructing the closed
durable Prepare anchor does it reacquire the registry and revalidate generation, TTL, phase, binding,
PID and process lifetime. An elapsed deadline or any substituted, moved, stale or unreadable object
fails closed without returning an anchor. Ambiguous spawn has no low-level completion channel and
therefore remains permanently fenced rather than falsely absent. Dropping or unwinding a retained
lifecycle owner is fail-closed but not recoverable. Concurrent terminal retirement may transiently
return a retained `Registered` owner while the record or detached process ownership is still
present; after confirmed reap and complete six-index purge, that same affine owner settles
idempotently without another signal or wait. Production activation consequently still requires an
owned cancellation-safe settlement guard, lifecycle quiescence before shutdown, and production
journal/reaper wiring.

A private composite handoff now commits the durable `Intent` before even reserving a local worker
generation, then authenticates one child in an anonymous `NEWNET` namespace and registers it as an
exact passive `Starting` worker under an atomically installed `DurableHandoffPending` dispatch
fence and the same caller-supplied absolute deadline. Normal planning rejects that generation
before cloning its channel or mutating in-flight, cache, tombstone, or phase state. The handoff
derives and revalidates the worker's complete recovery anchor, freezes the exact
pidfd/network-namespace identities through the descriptor-store adapter's measurement path, fences
the deadline again, and durably advances `Intent -> MayOwnCustody`. Only the returned affine
phase-4 token can derive the deterministic custody name and create one publication owner retaining
that token, worker, recovery-pin source, pidfd/network-namespace pair and original deadline. The
handoff itself does not publish descriptors. A private dormant supervisor synchronously consumes
that owner, reserves one bounded terminal slot, and registers both its capacity permit and blocking
task handle before activation. The blocking supervisor owns a private current-thread runtime for at
most one descriptor-store publication attempt and never retries; after exact attestation it fences
the deadline, verifies the role-ordered name and descriptor identities, revalidates the worker, and
uses a separately cloneable arm-only handle to advance `MayOwnCustody -> MayOwnPrepare`.
`BeforeSend`, `ManagerMayOwn`, explicit post-attestation failure, queued abort and success all retain
the exact affine terminal available at that boundary. An unwind while the supervisor guard still
owns the phase-4 publication stores `SupervisorDropped`; after that owner has been extracted, the
guard instead aborts fail-closed rather than falsely claiming an in-memory terminal. Neither adapter
failure authorizes retry. The terminal is stored before the non-authoritative completion is sent,
dropping that waiter has no effect, and an activated blocking publication survives outer-runtime
shutdown. A queued abort stores the phase-4 owner without polling the publisher. The pending fence
deliberately remains closed after arming: this slice has no transition which consumes the
`MayOwnPrepare` composite and opens child dispatch. It sends zero child protocol-request bytes and
performs no WireGuard link/address, route, firewall, or dataplane configuration. Worker launch still
creates the deliberately isolated process and anonymous `NEWNET`, without altering host-network
state.

The supervisor and publisher remain private and dormant, with no server, engine or request-path
caller and no production terminal consumer. Production startup now performs the separate read-only
complete-set classification described above before retiring any `Intent`, but every non-empty
classification still blocks. The durable `CleanupConfirmed` phase, dormant exact-name removal
adapter and shared manager-mutation serialization now exist, but a production restart reaper,
old-worker death proof, exact namespace/kernel cleanup, and authority-preserving composition of the
two settlement proofs remain required before those phases can progress.

Full durable production wiring remains a separate audited change with these explicit blockers:

- The functional-alpha adapter maps `BackendLineage`/`OperationBinding` to one process-owned Client
  worker generation and carries the engine deadline into the worker call. A separate non-cloneable
  live owner distinguishes same-runtime create/delete authority from its public WireGuard marker
  metadata. It does not bind that
  lineage to a durable ownership key or carry an owner from journal Intent through authenticated
  anchor, durable MayOwn, child dispatch and exact settlement. It does not obtain a phase-authorized
  per-link resource after durable `MayOwnPrepare`; its typed resource deliberately proves neither
  current journal phase nor crash-cleanup authority. Before a complete adapter returns success it
  must also revalidate every adopted kernel object
  against the requested socket kind, protocol, local/remote tuple, nonblocking/listening state and
  genuine MPTCP evidence. Descriptor adoption and complete-operation retryable shutdown therefore
  remain disconnected from the functional-alpha path.
- Retryable shutdown ownership and the escalation reaper are still process-memory-only. The
  journal has a production startup owner but no request-path issuance/arming writer or restart
  reaper, so helper-crash reconciliation is not yet durable.
- Add/Remove MPTCP endpoint operations are intentionally outside `AsyncLeaseBackend`; their typed
  asynchronous seam and dispatch are a separate bounded extension.

## Same-runtime ambiguous Prepare reconciliation

External tag 35 is `BindHelperRuntime`; its success outcome returns a non-zero, CSPRNG-generated
32-byte ID fixed for one helper process. With `prepare_intent = Some`, it also records the exact
route-context ID, original Prepare request ID and canonical digest, setup expiry, hard expiry,
context role, canonical role-complete lease identity set, and a monotonic generation. Registration
performs no backend or network call, is serialized under the
engine operation gate, and is capped together with retained reconciliation records at 1024. It is
runtime-global rather than attached to the socket that carried tag 35.

The HelperClient prebuilds the complete Prepare before Bind and uses one absolute five-second budget
for connect, `SO_PEERCRED`, Bind, and Prepare on the same stream. After a valid Bind response, its
typed state changes from Armed to Dispatched immediately before the first mutating Prepare write is
polled. Bind-side failures are definitive for network mutation; every subsequent I/O, timeout,
rejection, decoding, or correlation failure is ambiguous and transfers the complete exact authority
to route retirement. The dispatch state lives outside the inner timeout future. Full cancellation
safety nevertheless belongs to the owned route-ticket supervisor, which keeps awaiting and settling
the HelperClient call after its external waiter is gone. The crate-private Prepare method has no
other production call site; polling it standalone in future code would not preserve that authority
on cancellation.

At or after setup expiry, tag 28 `ReconcileExpiredPrepare` can prove absence only for the retained
same-runtime record with an exact match on all authority fields. The client first performs
`BindHelperRuntime(None)` on a new authenticated stream, compares the runtime ID, and sends tag 28 on
that same stream under one absolute five-second deadline. A mismatch sends no tag 28; retirement
keeps its authority quarantined. The successful outcome exactly echoes runtime, context, original
request ID/digest, and both expiries, and the client rejects any substitution before retirement can
release remote state.

Tag 28 is target-only and runs before the generic global expiry reaper. It never destroys by a
caller-supplied context ID alone: the server-owned record and generation must match. An expired Intent
with no context or pending cleanup becomes `Absent` without a backend call. Pending may retry cleanup
only for its exact orphan generation. Owned may destroy only the exact Prepared/Quarantined context;
Activated and Committed contexts are rejected. Missing, mismatched, in-flight, or non-quiescent state
returns `Unavailable` or `CleanupIncomplete`, never a positive absence proof.

`Absent` is a runtime-lifetime tombstone, retained so a lost tag-28 response can be retried and
re-evaluated without trusting a cached success. There is no authenticated ACK that permits pruning;
the fixed 1024-record bound makes retention finite and capacity exhaustion fails closed. Tag 28
itself retries exact Pending/Owned cleanup. Tag 29 `CleanupOwned` is an independent process-wide
cleanup operation, neither part of per-route reconciliation nor that ACK, and leaves `Absent` proof
retained. A helper restart loses this in-memory ledger and changes the runtime ID, so the agent
quarantines rather than releasing. A production-started secret-free journal substrate exists, but
the request-path issuance/arming writer, restart reaper, trusted worker/kernel-cleanup executor,
exact manager-absence composition, and cross-runtime proof needed to settle that case do not.

This same-runtime reconciliation path remains containment rather than crash recovery. The
functional-alpha production adapter can Prepare and Destroy one Client lease, but no production
route-manager caller drives it and there is no activation, peer route, transport or live datapath.

## Namespace-local transport descriptor

The external transport operation and outcome use exact protobuf tag 27. Tags 10, 11, 12, 14 and 24
remain retired and rejected. `AcquireTransportSocket` binds the route-context ID, committed context
handle, path 1–8, exact WireGuard endpoint role, and one of:

- already-connected MPTCP with concrete local and remote IP:port values;
- an MPTCP listener with a concrete local IP:port and no remote value;
- an explicitly unconnected Quinn UDP socket with a concrete local IP:port and no remote value.

Addresses are raw four- or sixteen-byte IP values with a non-zero port. Wildcard, loopback,
multicast, IPv4 broadcast, IPv6 link-local, mixed-family and identical connected pairs are rejected.
There is no interface name, filesystem path, hostname, command, backlog or free-form option.
Engine dispatch additionally requires the exact context handle, committed phase and existing
path/role lease.

After a valid `TransportSocketReady` frame, the server sends exactly one descriptor and a 32-byte
binding in one `sendmsg(SCM_RIGHTS)` call. Domain-separated BLAKE3 commits the protocol version,
request ID, canonical operation digest, full canonical response outcome and descriptor kind.
The agent validates the response correlation and successful typed outcome before calling `recvmsg`.
The shared Linux UAPI then requires exactly one descriptor, `MSG_CMSG_CLOEXEC`, the complete
1–256-byte binding, no duplicate or unexpected ancillary data, and no truncation. Every installed
FD is immediately RAII-owned, so wrong bindings, extra descriptors and all later correlation
failures close it. Failure responses carry no descriptor, and the server rejects a
success/descriptor mismatch before writing the response frame.

Worker-side closed factories now create sockets atomically with `SOCK_CLOEXEC|SOCK_NONBLOCK`.
They support a fixed-backlog listening `IPPROTO_MPTCP` socket, a bounded connected
`IPPROTO_MPTCP` socket, and an exactly bound unconnected UDP socket. Before handoff they re-query
`SO_TYPE`, `SO_PROTOCOL`, descriptor/status flags, exact local and peer state, `SO_ACCEPTCONN`
for listeners, and `MPTCP_INFO` negotiation without TCP fallback for connected MPTCP. The request
must match the worker-retained committed overlay IP for the exact lease. Connected MPTCP is
client-only, listening MPTCP is exit-only, UDP is client/exit-only, and relay roles can never obtain
an application transport socket.

A separate consuming parent-side validator now derives the same closed expectation from the exact
Acquire request and independently re-queries `SO_DOMAIN`, `SO_TYPE`, `SO_PROTOCOL`, exact local and
peer tuples, `O_NONBLOCK`, `FD_CLOEXEC`, IPv6-only family closure, `SO_ACCEPTCONN`, `SO_ERROR`, and
genuine negotiated `MPTCP_INFO` where applicable. Rejection drops the only supplied owner. The
audited Linux-UAPI also
provides fixed `SIOCGSKNS` namespace-FD acquisition with immediate RAII ownership and readback of
`FD_CLOEXEC`, read-only mode, and `CLONE_NEWNET`. For every planned Acquire call the disconnected
coordinator now takes an affine CLOEXEC duplicate of the already attested worker namespace pin
before it records this request's tombstone or in-flight transition. Expired cache and tombstone
housekeeping may run earlier but carries no socket or namespace authority. The duplicate keeps the
expected namespace alive independently of concurrent worker retirement and performs no process
probe under the registry lock. After the credentialed source-release barrier and an initial
worker-liveness check outside that lock, but before the final liveness proof and registry COMMIT,
the consuming parent validator obtains the socket's namespace with `SIOCGSKNS` and requires exact
non-zero nsfs device/inode equality with that retained duplicate in addition to the complete
socket-shape proof. Every post-PLAN error, mismatch or late result closes the socket and quarantines
the generation; no descriptor can be published first and checked afterwards.

Socketpair and fake-kernel tests cover the three metadata kinds, response/digest binding, retry-cache
cleanup on context destruction, missing/wrong binding, FD-on-error, worker EOF, unexpected
ancillary data and close-on-reject. Credentialed-channel tests separately cover exact credential and
descriptor counts, wrong-binding closure, shared-deadline receipt, successful consuming raw-owner
adoption, injected adoption-failure closure, consumed worker-source ownership, exact/missing/late
release records, and closure before ambiguous return. Parent socket tests reject wrong tuple,
family, type, protocol, flags, listener state, forbidden peer shape and namespace identity. Registry
tests also prove that an Acquire plan obtains its duplicate before this request's authority mutation,
while pin-owner tests prove the duplicate remains usable after the original namespace owner is
dropped. The audited UAPI/adoption
regressions prove invalid source rejection, `F_DUPFD_CLOEXEC` with minimum 3, independent ownership,
`FD_CLOEXEC` readback, original closure and closure of the final owner. A disposable user/network
namespace test proves the fixed `SIOCGSKNS` wrapper and exact same/different-namespace comparison
without changing host networking. Other socket
tests perform read-only kernel revalidation; no route, link, firewall or sysctl was changed. The
production backend still advertises the operation as unsupported and returns
`Unavailable/TRANSPORT_SOCKET_UNAVAILABLE` before context lookup or any socket/network work. The
factories are not invoked by a production v3 namespace worker, and the agent transport stacks do
not yet consume this helper API. No working namespace datapath is claimed.

## Pre-route client ingress boundary

External request/outcome tags 31 through 34 define a client-runtime lifecycle independent of route
contexts: `PrepareClientIngress`, `AcquireIngressSocket`, `ActivateClientIngress`, and
`DestroyClientIngress`. Retired tag 24 is absent from the active schema, remains permanently
reserved, and is rejected from raw input before dispatch.

A valid prepared response has one non-zero runtime ID, one opaque ingress handle, and exactly eight
socket authorities: four closed kinds (transparent TCP listener, transparent UDP, DNS TCP listener,
and DNS UDP) crossed with IPv4 and IPv6. Every ingress/socket/receipt handle is 32 bytes, non-zero,
and cross-category unique. Addresses are helper-selected wildcard binds with non-zero ports; the
agent cannot supply an interface, namespace, nftables expression, mark, table, command, path, or
free-form privileged option.

Acquisition is deliberately sequential. The agent's opaque `PreparedClientIngress` must be borrowed
mutably and locally consumes each identity before its first RPC, including on timeout, so it cannot
ask twice after an ambiguous descriptor transfer. One successful `IngressSocketReady` is followed
by exactly one CLOEXEC descriptor using the same canonical response/digest binding as transport
handoff. The agent correlates the runtime, ingress handle, socket handle, kind, family, wildcard tuple
and unique receipt before retaining the descriptor. Activation accepts exactly the complete set of
eight unique identities and receipts. An activation error returns the prepared cleanup authority and
all eight RAII-owned descriptors to the caller; prepared and active destruction borrow their
capability so timeout cannot erase authority needed for an idempotent retry.

The Linux UAPI foundation revalidates socket domain, type, protocol, transparent option, wildcard
bind and exact port, listening state where required, nonblocking status and CLOEXEC. TCP original
destination lookup additionally revalidates the accepted transparent connected socket. UDP
`recvmsg` accepts exactly one family-matching IPv4 or IPv6 original-destination control message and
rejects missing, duplicate, wrong-family, malformed, truncated, or extra ancillary data. Any received
`SCM_RIGHTS` descriptor is RAII-owned immediately and closed on rejection; rejected payload bytes
are cleared. Pure and Unix-socketpair tests cover these fail-closed parsers without root, network
namespaces, routes, firewall changes, or live product networking.

These are protocol, type, descriptor-handoff, and UAPI foundations only. The production engine
returns `Unavailable/CLIENT_INGRESS_UNAVAILABLE` for all four operations before consulting its
clock, cache, state, backend, or network. It creates no namespace, listener, nftables rule, route,
mark, DNS state, receipt, or descriptor. A future privileged runtime must itself cache or refuse a
second transfer for each runtime/identity and implement transaction-wide rollback; the agent's
one-shot guard is defense in depth, not a substitute for that privileged invariant.

## WRITE-STOP: remaining live-kernel gaps

No development-host network configuration is mutated or authorized for this slice. The committed gate confines
its fixed dummy underlay and ephemeral WireGuard leases to a transient `PrivateNetwork` and child
network namespaces inside the disposable VM. Before `Prepare`, `Activate`, `Commit`, transport
acquisition, client ingress, or datapath operation can be called complete, all of the following
remain:

- obtain one retained exact-main PASS from the committed disposable Debian 13 driver for the complete
  dedicated `volparossa-worker` UID/GID transition, exact post-drop credentials/groups/capabilities,
  parent-signal denial, runtime token/socket path denial, pre-filter single-task state, namespace-pin
  lifetime and equal enumerated host-state fences; a non-retained branch smoke, portable tests and
  package inspection do not substitute for this gate;
- validate the shipped seven-capability helper bootstrap and locked sysusers contract from the staged
  Debian package under the same acceptance environment, including the generated local
  passwd/group/shadow records and canonical files/systemd NSS binding; `CAP_SYS_PTRACE` must remain
  absent, `LimitCORE=0` must be effective, process dumpability must remain disabled after Ready, and
  the final worker must retain only `CAP_NET_ADMIN`;
- obtain one retained exact-main PASS for the already wired functional-alpha proof: read-only direct
  underlay selection, independently observed sandbox identity, parent birth-link creation and move,
  child WireGuard Prepare, correlated response validation, exact/idempotent Destroy, worker
  reap/purge, second-cycle capacity reuse and equal enumerated host-state fences; a non-retained
  branch smoke does not close this evidence gate, and the one-Client/one-lease capacity must then be
  extended without weakening atomic rollback;
- extend the asynchronous `HelperEngine` backend beyond Prepare/Destroy: Activate, Probe, descriptor
  acquisition, cached-descriptor cleanup and shutdown need the same plan/call/commit discipline and
  exact context/generation/phase/handle revalidation;
- wire descriptor retries to the live production generation registry. The coordinator purges caches
  on death and never retries ambiguous IPC, but the functional-alpha backend advertises descriptor
  acquisition as unsupported;
- extend the bounded `DirectAssigned` parent snapshot from the current one direct underlay to the
  exact multi-path evidence required by complete route setup, retaining rejection of multipath,
  duplicate, truncated or ambiguous dumps;
- carry every parent birth link through activation and complete cleanup/quarantine, preserving the
  exact no-peer/key, link-UP, port-zero `SET`, and correlated public-key/port `GET` ordering;
- derive and apply the exact overlay, peer, route, relay-fence, and interception state in activation;
- capture activation baselines and perform correlated handshake/RX/TX commit probes;
- connect the durable two-step settlement only after restart-stable pidfd/namespace custody, exact
  old-worker death, and a real namespace/kernel cleanup backend can prove the transition to
  `CleanupConfirmed`; then authority-order the dormant exact-name manager removal and its stable
  absence proof before `Absent`. The pure-tested typed marker/kernel foundation rejects an old
  same-name link carrying a non-exact marker but grants no journal-phase or cleanup authority;
- add the production tag-35/tag-28 writer plus restart reaper; until then a runtime mismatch must
  remain quarantined and the runtime-lifetime `Absent` ledger cannot be acknowledged or pruned;
- invoke the implemented factories inside the correct committed child namespace and feed their
  descriptors through the private channel into the implemented external ancillary handoff;
- make agent context cleanup close all handed-off `OwnedFd` values: an external socket can keep an
  anonymous network namespace alive after the worker and helper cache have dropped their copies;
- adopt those descriptors in the TCP/QUIC datapaths and prove the exact tuple and real transport;
- connect the implemented pre-route client-ingress protocol to a distinct privileged
  runtime/profile namespace transaction. It must create and revalidate all four socket kinds for
  both families, retain exactly one socket/receipt transfer per identity, and atomically own TPROXY,
  DNS and kill-switch nftables/routing state. Prepare, partial acquisition, activation failure,
  destruction, expiry, client crash, helper crash and ambiguous worker IPC each require exact
  rollback or quarantine. The unprivileged agent must never enter the namespace. The TCP/UDP
  consumers must adopt the descriptors and preserve the implemented original-destination evidence
  without destination substitution;
- implement signed reservation/lease renewal before supporting configured contexts beyond the
  current signed 15-minute grant;
- run disposable root namespace integration tests covering success, denial, ambiguity, expiry,
  crash cleanup, packet traversal, privacy, and proof that the development host is unchanged.

Until those items pass, production route preparation and client ingress remain deliberately
unavailable and no tunnel, interception, reservation, transport, capacity, or datapath-active claim
is justified.
