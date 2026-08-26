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
backend call; unrelated global expiry housekeeping may run before target admission. The server does
not bind the intent to that connection. Same-stream use is therefore a client-side socket-swap
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

## Prepare evidence and current fail-closed result

A successful `PrepareLeaseBatch` response is required to contain:

- opaque, non-secret context and lease handles;
- a helper-generated, non-zero ephemeral WireGuard public key;
- a public UDP endpoint whose address has `DirectAssigned` evidence from read-only rtnetlink state;
- a non-zero UDP port obtained from an exact acknowledged WireGuard `SET` followed by a bounded,
  correlated WireGuard `GET` that also matches the expected public key.

The internal v3 worker protocol, underlay evidence policy, secret-free link derivation, exact
WireGuard `SET` encoders, and bounded `GET` proof parser have pure tests. Successful internal
Prepare, Activate, Probe and MPTCP endpoint responses are now bound to the request's exact identity
order; the external engine also rejects duplicate public keys and public endpoints before pairing
affine handles. `NamespaceKernel` contains inactive v3 prepare, peer-activation, and probe
primitives plus a complete-batch preflight that requires exact name, current ownership alias,
WireGuard kind and fresh DOWN/key-zero/port-zero/fwmark-zero/peerless state before mutation. Its
exact-owned delete re-proves absence. A validated journal record now deterministically projects a
non-`Clone` resource for each exact link. Its public `ownership-v1` alias commits the immutable
ownership-record fields, closed plan, and per-link identity without exposing raw ownership
coordinates; lifecycle phase and reconciliation evidence do not change it. Every inactive
owner-sensitive kernel entry point consumes that typed resource and rejects any non-exact marker.
The underlay parser independently accepts only the exact helper grammar and interface binding,
rejecting malformed, legacy, or mismatched helper aliases. The marker is evidence, not current
journal-phase or cleanup authority, and has no production call site. These operations are not
connected to a production child lifecycle or transaction-wide rollback. The production
`HelperEngine::new` backend therefore
returns the explicit `Unavailable`
/ `PREPARE_FAILED` result and creates no context. It never returns an agent-supplied address,
placeholder address, guessed port, public key, or endpoint.

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
exact `Intent`, `MayOwnPrepare`, and `Absent` ownership records. Its fixed lock, atomic
file-fsync/rename/directory-fsync transaction, typed recovery anchor, and trusted
non-cryptographic exact-echo absence-proof interface have temp-directory tests. A private
single-writer actor now owns both this store and its recovery executor on one named thread. It
retains one verified parent-directory descriptor, acquires a process-global one-shot store latch
before opening the lock, sweeps every startup `Intent` and `MayOwnPrepare`, rechecks the complete
durable boundary, and only then reports ready. Its non-blocking admission accepts at most four
operations while reserving channel capacity for shutdown; opaque non-`Clone` keys expose neither
the journal revision nor raw ownership coordinates. Each validated wire intent locally receives a
fresh random 256-bit `OwnershipId` inside a non-`Clone` registration owner. Registration consumes
that owner into one durable key, and arming consumes the key into a `MayOwnPrepare` token which
exposes only the context and borrowed owner-bound resource metadata. Every error returns the exact
affine owner which still exists, so the typed API neither duplicates authority nor discards it on
an error path.

Validated records and private recovery targets now deterministically rederive the same non-`Clone`
per-link resources. Focused tests fix the public alias grammar and cover every immutable field
class, mutable-field exclusion, redacted debug output, canonical codec/reopen stability, a lost
insert reply, and recovery projection. This dormant projection exposes no production issuance API
and does not authorize a kernel operation.

Production exposes only a start/shutdown wrapper around the actor; registration, arming and raw
recovery authority remain inaccessible to the server and engine. Its production executor always
refuses `MayOwnPrepare`, so a potentially mutating record stays byte-identical and blocks startup.
Only a never-dispatched `Intent` may be durably settled to `Absent` before the internal actor-ready
and socket-publication boundary. There is no production request-path issuance/arming writer,
namespace-FD vault, absence-proving `MayOwnPrepare` recovery executor, restart reaper, supported
on-disk migration, or live-root proof. Every non-test actor entry point requires one caller-supplied
absolute hard deadline. That same value is carried through admission, the queued
command, actor-thread execution, reply handling and thread settlement. Recovery additionally
receives that exact same deadline and rechecks it before invoking the trusted executor and after the
exact proof, immediately before any
`MayOwnPrepare -> Absent` mutation. Startup rechecks it before the first filesystem or latch
operation and before each pending record; ordinary commands recheck it immediately after dequeue.
Work which expires before its first mutation returns `DeadlineElapsed` without touching journal
bytes. Non-recovery journal I/O which already began must settle, while a recovery executor may
return late but can no longer publish `Absent`; every late or unobservable completion permanently
fences admission as ambiguous. Shutdown gives settlement ambiguity precedence over a weaker queued
deadline result. Only `Drop` retains a private emergency deadline; relative-deadline convenience
wrappers are test-only. If the actor thread is stuck inside the non-cancellable recovery executor,
its join handle is detached after the bounded settlement wait; that thread may retain the journal
lock, while the process-global latch remains set until process exit. A clean shutdown now requires
both an intact durable boundary and every record already durably `Absent`; it never retires or
recovers an outstanding record and returns `RecoveryNotConfirmed` for a known `Intent` or
`MayOwnPrepare`. Reopening requires a fresh process. These limitations must be resolved at the
production service boundary before the actor can become the request-path issuance/arming writer.
The required tag-35 closed plan has a fallible exact conversion into the store's existing
`ClosedPlan`; this removes
the wire/schema mismatch but performs no journal I/O and grants no mutation authority. A missing
journal is therefore not proof that stale kernel state is absent, and the startup wrapper cannot
issue a cross-runtime tag-28 receipt. The current `doctor` has no helper-v3 crash-ownership readiness
check, so its other successful checks must not be interpreted as evidence of live recovery or
cleanup.

The store's insert, prepare-arm, never-dispatched retirement, and confirmed-recovery
transitions are exact-current-revision retry-safe after a lost reply. A retry succeeds only when the
complete durable post-state of that same operation still exists; an intervening transition, changed
intent, generation, recovery anchor, or reconciliation binding fails closed without another write.
`Absent` records persist whether they came from a never-dispatched intent or from confirmed
MayOwn recovery, so one operation can never acknowledge the other's tombstone and an already
confirmed recovery never reruns its executor. Mutation authority remains private and
pre-production: the server owns only the start/shutdown wrapper, version 3 has no supported on-disk
migration contract yet, and production decodes a v3 object only behind the canonical lock and
refuses Ready when a `MayOwnPrepare` record cannot be recovered.
After a definite pre-rename I/O failure, another mutation is admitted only if a read-only health
check re-proves the retained parent object, exact lock entry and exclusive lock, absence of the
temporary entry, and byte-exact durable snapshot. Any uncertainty poisons the actor permanently.

### Production fail-closed inherited-custody capture

Before constructing Tokio or binding the helper socket, the production entry parses systemd's
complete `LISTEN_PID`/`LISTEN_FDS`/`LISTEN_FDNAMES` tuple. The descriptor count must be positive,
even and at most 128, and every name is parsed directly into the fixed lowercase opaque
`CustodyFdName` buffer before descriptor-table mutation. The one-shot Linux-UAPI boundary seals
the complete contiguous advertised range beginning at fd 3 `CLOEXEC` and duplicates every entry
into a new Rust owner without claiming ownership of the raw source entries. The shipped production
entry treats every failure after the one-shot latch as terminal for that process.

Each same-name pair is then classified without trusting descriptor order. A pidfd is accepted only
when `fstatfs(2)` returns Debian 13's `PID_FS_MAGIC`; a network namespace is accepted only when
`NS_GET_NSTYPE` returns `CLONE_NEWNET`. Exactly one of each is retained in canonical role order,
both retained owners are re-sealed `CLOEXEC`, and their full
mode/device/inode/rdev/open-flag identities are retained for descriptor-store attestation. Object
overlap is rejected within and across all bounded names using the stable mode/device/inode/rdev
fields, so mutable `O_NONBLOCK` drift cannot hide an alias. Arbitrary files, other namespace kinds,
duplicate roles, incomplete groups and identity reuse fail closed. Type classification deliberately
accepts an exited pidfd: capture proves object type, not worker liveness or cleanup.

This is still a refusal boundary, not production recovery. Any non-empty captured set blocks
startup and drops its captured duplicate owners without constructing the runtime or publishing the
socket. The capture does not yet prove that a particular pidfd and namespace belong to the same
worker, bind the pair to durable journal evidence, reconcile manager inventory, remove manager
custody or reap kernel state. The sealed original advertised range also remains open: closing it
through the current public safe count-only UAPI would invalidate possible Rust-owned descriptors
without an ownership proof. A later explicit startup-ownership boundary must resolve that
I/O-safety requirement before positive adoption. Those proofs remain mandatory before the refusal
may be replaced by adoption.

### Production-dormant systemd descriptor-store publication boundary

The helper contains a private adapter for the systemd v257 descriptor-store protocol. Only the
private live-proof selector calls it; no production worker, journal, server or engine path does. It
validates one fixed-shape opaque custody name, borrows exactly two already-owned descriptors,
snapshots their kernel identities and sends them together in one `SCM_RIGHTS` datagram containing
only the required `FDSTORE=1`, `FDNAME=` and `FDPOLL=0` assignments. It then sends `BARRIER=1`
separately with exactly one pipe descriptor and carries one absolute monotonic deadline through
every send, barrier wait and inventory read. It never sends `READY=1` or `FDSTOREREMOVE=1`.
Before the first send it rejects an existing exact name and any partial or complete reuse of either
role identity elsewhere in the bounded descriptor-store inventory, including reuse under a
different name.

A successful notify send is not an acknowledgement that either descriptor was stored, and a
successful barrier proves only that systemd processed earlier notifications. The adapter therefore
accepts custody only after uncached D-Bus reads show stable pre/post `NFileDescriptorStore` counts
and `DumpFileDescriptorStore()` supplies the exact complete, bounded descriptor multiset, including
matching name, mode, device, inode, device-node and open-flag identity. Every failure after the
publication datagram may have been accepted is classified as manager-may-own. Callers must retain
their original affine descriptor owners; there is deliberately no automatic removal on an
ambiguous path.

The journal key now derives an opaque, domain-separated fixed custody name from its exact journal
epoch, context, ownership ID and generation without exposing those coordinates. A private dormant
worker typestate binds that name to the exact pidfd/network-namespace role identities and consumes
the resulting inventory attestation only after fencing the original absolute deadline. This is not
production composition: inherited descriptors are now snapshotted into typed local duplicate
owners but still refused rather than journal-bound or adopted; there is no non-cancellable
publication supervisor, manager reconciliation, restart reaper or request-path caller. Its
executable live-proof path has not yet produced a recorded result inside the required disposable
Debian 13 transient service.
It therefore closes no production, crash-cleanup, datapath or acceptance milestone.

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
unexpected ancillary data fail closed. Internal protocol v2 follows an Acquire response with a
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

The separate fixed `--internal-worker-v3` child entry now has a disconnected, tested parent
launcher. It has no production caller and `HelperEngine` still returns `Unavailable` before spawn or
network work. The launcher reopens the exact running Linux image through `/proc/self/exe`, creates a
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

One 30-second absolute monotonic deadline now follows the disconnected launcher through setup,
the post-lock pre-spawn check, credentialed handshake records, sandbox observation and liveness
proofs. Spawn-lock acquisition repeatedly uses `try_lock` with deadline-bounded sleeps and rechecks
the same deadline after acquiring the mutex, so an expired queued caller creates no child. The
blocking `Command::spawn` operation itself is not interruptible. Before entering it, the launcher
constructs an armed retirement owner with its permit and empty child slot. The spawn boundary holds
that slot and moves a successfully returned `Child` into it before returning, so no allocation,
deadline check or other fallible post-spawn step can observe an unowned child. Late setup or
handshake failure therefore retires that exact child boundedly or transfers the same owner to the
escalation reaper. This is a disconnected launcher bound, not production route-setup or acceptance
evidence.

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
access through the root:`volparossa` runtime-directory mode. This is not yet a production claim:
the launcher remains disconnected from the engine, and the complete account transition,
pre-filter task state, path access denials and parent-signal denial still require a disposable
Debian 13 live-root acceptance run.

### Component-only live worker proof driver

`tests/helper/require-live-worker-identity-proof.sh` now provides a preview-first, execute-gated
driver for one real `--internal-worker-v3-live-proof` invocation. Execution is restricted to root
inside a recognised disposable Debian 13 amd64 VM with the exact systemd v257 manager. It copies the
already-built helper into a root-only stage, creates collision-free synthetic service identities,
binds the staged passwd, group, shadow and nsswitch files read-only, and grants the helper parent
exactly the reviewed seven bootstrap capabilities. The transient unit has `PrivateNetwork=yes`,
`NotifyAccess=main`, `FileDescriptorStoreMax=128`, `FileDescriptorStorePreserve=yes`, and a private
temporary `/run`. Only the canonical root-owned system bus socket is bound read-only into that
private `/run`, and the unit pins `DBUS_SYSTEM_BUS_ADDRESS` to that verified path, so the
live-proof-only adapter cannot follow a manager-provided alternate address for its uncached systemd
inventory reads.
Success requires the two exact ordered helper records, an externally observed post-exit
`NFileDescriptorStore=2`, confirmed worker reap and pin release. Before and after the unit, the
driver compares privacy-safe digests of account files,
mounts, resolver configuration, sysctls, links, addresses, routes, rules, nexthops, qdiscs,
nftables, optional legacy iptables/ip6tables state and optional WireGuard state. A WireGuard dump
is streamed through a validated private FIFO into a separately checked SHA-256 consumer and is
never persisted or logged. Other host-network and firewall producer output exists only in validated
mode-0600 files under the root-only temporary stage, is normalized in a separately checked step,
and is removed with that stage; published comparison records contain only digests or explicit
absence markers. Resolver capture accepts either a regular Debian resolver file or a symlink whose
resolved regular target remains below `/etc` or `/run`; repeated object, target, metadata and digest
observations reject unsafe ownership, writable path components, target replacement and other drift.

The transient proof unit intentionally differs from the shipped production unit in every following
respect:

- it is a collected `Type=oneshot` with `RemainAfterExit=yes`, a 45-second activation bound, no restart,
  and the private proof selector instead of the production no-argument server;
- it uses a collision-free numeric staged primary group and requests no additional
  `SupplementaryGroups=` entries, rather than resolving the installed `volparossa` group from the
  host account database. An empty `SupplementaryGroups=` assignment does not override groups from
  the account database: systemd initializes them before installing the unit's synthetic account-file
  bind mounts. The helper therefore accepts exactly one kernel supplementary group, the staged agent
  GID; any additional group membership configured for host root blocks the proof;
- it overlays four synthetic account files read-only, adds `PrivateNetwork=yes`, and replaces host
  `/run` with a 16 MiB private tmpfs; the root-owned staged helper image is also bound read-only into
  that private `/run`, together with a read-only bind of the host system bus socket and an exact
  `DBUS_SYSTEM_BUS_ADDRESS` pointing to it. Consequently it
  does not use the production unit's host
  `ReadWritePaths=/run/volparossa -/run/netns` contract;
- it retains the shipped unit's exact `NotifyAccess=main`, 128-entry descriptor-store maximum and
  `FileDescriptorStorePreserve=yes` settings so the two published descriptors remain externally
  observable after the one-shot main process exits;
- it captures stdout and stderr in the root-only stage, sets `TasksMax=16` and
  `SetLoginEnvironment=no`, and omits the production config condition/environment, ordering,
  restart and install-target semantics that are irrelevant to the one-shot internal proof.

The device policy, no-new-privileges setting, exact capability sets, system-call filter,
namespace restriction, address-family restriction and remaining applicable hardening properties
match the shipped helper unit. Retirement addresses only the exact random transient unit, waits
boundedly for stop, and binds every stop, reset and clean operation to one exact current nonzero
systemd v257 `InvocationID`. The normal route requires it to match the returned JSON ID; tentative
recovery requires the exact per-stage marker before adopting the manager's current ID. A failed
one-shot is reset to inactive before its descriptor store is cleaned. Retirement cleans only that
unit's `fdstore`, requires either
`NFileDescriptorStore=0` or `LoadState=not-found`, resets it when still present and waits boundedly
for collection; any ambiguous observation fails the gate. The driver has not yet produced evidence
from the required disposable VM, and it does not validate an installed/staged package, production
systemd service lifecycle, inherited-descriptor restart adoption or recovery. It is therefore not
live-root, package, production, datapath, A14 or A15 acceptance evidence.

Before the blocking start call, the driver atomically supplies a `Description` containing a
SHA-256 ownership marker derived from the validated random unit name and temporary-stage inode
identity. Normal bounded retirement begins after `systemd-run` has returned one exact JSON object
containing that unit name and a nonzero lowercase 128-bit `InvocationID`, and the manager reports
the same marker and ID. During an interrupt or an invalid start reply, tentative ownership may be
promoted only after bounded read-only observations prove the exact name, marker and nonzero current
ID. If they cannot, the driver performs no unit mutation, fails the proof, and requires the
disposable VM to be discarded. It never guesses that a same-named unit belongs to this run.

The child still performs no link, WireGuard, route, nftables, sysctl, or socket-factory operation.
It keeps only an in-memory context marker, accepts `Initialise` and `DestroyContext`, and returns
`Invalid` for every network-affecting internal operation. Production `Prepare` and all network
operations remain unreachable and fail closed through the unavailable engine.

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
replacement for durable secret-free ownership and crash recovery; production remains disconnected.

The disconnected async coordinator demonstrates the required transaction shape: PLAN records the
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

Neither the launcher, registry, coordinator, nor production route manager calls this worker path.
The production engine already supervises cancellation-safe PLAN -> CALL -> COMMIT/rollback
transactions: it
reserves and revalidates state under `EngineState`, while every backend call runs without that mutex
held. This orchestration does not make the disconnected worker implementation production-ready.
The production backend still returns `Unavailable` for Prepare and transport acquisition, and the
engine rejects client ingress as `Unavailable` before backend dispatch.

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
production constructor still installs the unavailable backend and performs no worker or network
mutation.

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
derives and revalidates the worker's complete recovery anchor, derives the deterministic custody
name from the exact durable key and then stops with one affine publication owner retaining that key,
worker, recovery-pin source, pidfd/network-namespace pair and original deadline. It does not call
the descriptor-store adapter or arm the journal. A separate synchronous dormant transition fences
the deadline, verifies the exact role-ordered inventory attestation, fences the deadline again,
revalidates the complete worker recovery identity and only then arms `MayOwnPrepare`. Success keeps
the durable token, registered worker owner, affine fence owner, recovery-pin source, custody name
and attestation together. Every pre-arm failure retains or reconstructs the publication owner plus
attestation; the defensive post-arm context-mismatch path retains the `MayOwnPrepare` composite,
custody name and attestation. The pending fence deliberately remains closed after arming: this slice
has no transition which consumes the composite authority and opens child dispatch. The handoff
dispatches no child operation, sends zero protocol-request bytes, and
performs no WireGuard link/address, route, firewall, or dataplane configuration. Worker launch still
creates the deliberately isolated process and anonymous `NEWNET`, without altering host-network
state. The handoff remains private and dormant, with no server or engine caller, no restart reaper,
and no cancellation-safe production settlement. A production publisher cannot safely be attached
yet: once its future is first polled, neither a reported pre-send failure nor caller cancellation
proves that an older deterministic-name attempt did not publish. Moreover, the current startup
sweep treats journal `Intent` as never dispatched. Production therefore needs a non-cancellable
supervisor and a durable publication-pending/adoption phase which reconciles inherited descriptors
before that sweep.

Production wiring remains a separate audited change with these explicit blockers:

- No production adapter maps `BackendLineage`/`OperationBinding` and a durable ownership key to the
  dormant lifecycle owner, or carries that owner from journal Intent through authenticated anchor,
  durable MayOwn, child dispatch and exact settlement. No adapter obtains a phase-authorized
  per-link resource after durable `MayOwnPrepare` or carries it through birth-link creation,
  namespace movement, mutation, cleanup, and exact settlement; the typed resource deliberately
  proves neither current journal phase nor cleanup authority. The adapter also does not carry the
  engine's exact deadline through the complete lifecycle and into `execute_until`. Before returning
  success it must also revalidate every adopted kernel object
  against the requested socket kind, protocol, local/remote tuple, nonblocking/listening state and
  genuine MPTCP evidence. The implemented deadline, adoption and retryable-shutdown machinery
  therefore remains disconnected from `HelperEngine`.
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
the request-path issuance/arming writer, restart reaper, absence-proving recovery backend, and
cross-runtime proof needed to settle that case do not.

This entire path is dormant containment, not a live route implementation. Production Prepare still
returns `Unavailable`, and no production route-manager caller drives the helper-backed setup
transaction.

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

No host networking was executed for this slice. Before `Prepare`, `Activate`, `Commit`, transport
acquisition, client ingress, or datapath operation can be called complete, all of the following
remain:

- run the complete dedicated `volparossa-worker` UID/GID transition in a disposable Debian 13
  live-root environment and prove exact post-drop credentials/groups/capabilities, parent-signal
  denial, runtime token/socket path denial, pre-filter single-task state, namespace pin lifetime and
  unchanged host state; portable tests and package inspection do not substitute for this gate;
- validate the shipped seven-capability helper bootstrap and locked sysusers contract from the staged
  Debian package under the same acceptance environment, including the generated local
  passwd/group/shadow records and canonical files/systemd NSS binding; `CAP_SYS_PTRACE` must remain
  absent, `LimitCORE=0` must be effective, process dumpability must remain disabled after Ready, and
  the final worker must retain only `CAP_NET_ADMIN`;
- connect the authenticated worker-v3 launcher and generation registry to creation of the anonymous
  namespace only as part of an atomic underlay-snapshot, capability-reduction,
  independently observed sandbox-proof, birth-link, WireGuard-prepare and rollback transaction; the
  current child deliberately performs no link, WireGuard or network-policy operation;
- replace the synchronous `HelperEngine` backend interface across every caller with the tested
  plan/call/commit shape: validation and snapshot under the state lock, one bounded worker call
  outside it, and exact context/generation/phase/handle revalidation before publishing. Reap,
  cleanup, destroy, shutdown, and cached-descriptor paths require the same atomic refactor;
- wire descriptor retries to the live generation registry. The disconnected facade already purges
  caches on death and never retries ambiguous IPC, but the production engine is not yet using it;
- generate and zeroize ephemeral private keys exclusively in the worker;
- collect a bounded `DirectAssigned` snapshot from parent-side read-only rtnetlink link/address/route
  dumps before birth-link mutation, rejecting multipath, duplicate, truncated, or ambiguous state;
- connect parent birth-link creation/movement to the inactive v3 kernel primitives, preserving the
  exact no-peer/key, link-UP, port-zero `SET`, and correlated public-key/port `GET` ordering with
  full rollback or quarantine;
- derive and apply the exact overlay, peer, route, relay-fence, and interception state in activation;
- capture activation baselines and perform correlated handshake/RX/TX commit probes;
- extend the production startup-owned secret-free store with its typed per-link marker projection
  only after a real cleanup backend and restart-stable namespace/pidfd custody can prove reaper
  cleanup; the pure-tested typed marker/kernel foundation rejects an old same-name link carrying a
  non-exact marker but grants no journal-phase or cleanup authority;
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
