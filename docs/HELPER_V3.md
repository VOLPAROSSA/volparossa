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
ID, and sends that prebuilt Prepare on the same `SO_PEERCRED`-validated Unix stream. The helper stores
the intent in runtime-global state; the server does not bind it to that connection. Same-stream use is
therefore a client-side socket-swap defence, not a server-side session authorization rule.

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
WireGuard `SET` encoders, and bounded `GET` proof parser have pure tests. `NamespaceKernel` also
contains inactive v3 prepare, peer-activation, and probe primitives. They are not connected to a
production child lifecycle or the external engine, and do not yet provide transaction-wide
rollback. The production `HelperEngine::new` backend therefore returns the explicit `Unavailable`
/ `PREPARE_FAILED` result and creates no context. It never returns an agent-supplied address,
placeholder address, guessed port, public key, or endpoint.

## Ownership journal interlocks

The v1/v2 context worker, its internal command-line entry point, and its live journal cleanup
executor have been removed. Production startup performs read-only fail-closed interlocks before
cleanup-token rotation, stale-socket removal, or listener bind. Any filesystem object at the
retired `/run/volparossa/helper.ownership-v1` path, or at the dormant v3 store's exact
`helper.ownership-v3`, `helper.ownership-v3.lock`, or `helper.ownership-v3.next` path, stops startup
and requires explicit operator inspection. It does not parse, lock, create, repair, delete, or
execute cleanup from those objects. Operators must never remove them merely to bypass the
interlock.

The v3 module contains a boot-scoped, secret-free, canonical and length-bounded codec/CAS store for
exact `Intent`, `MayOwnPrepare`, and `Absent` ownership records. Its fixed lock, atomic
file-fsync/rename/directory-fsync transaction, typed recovery anchor, and trusted
non-cryptographic exact-echo absence-proof interface have temp-directory tests. No production
writer, startup reaper, recovery backend, or engine integration uses that store. A missing journal
is therefore not proof that stale kernel
state is absent, and the interlock cannot issue a cross-runtime tag-28 receipt. The current `doctor`
has no helper-v3 crash-ownership readiness check, so its other successful checks must not be
interpreted as evidence of live recovery or cleanup.

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
unexpected ancillary data fail closed. An Acquire response is followed by one domain-separated
32-byte completion record. Success requires exactly one `MSG_CMSG_CLOEXEC` descriptor in that
record, while an error requires exactly none. Every installed descriptor becomes RAII-owned before
semantic validation and is closed on every reject path. Creator-time `SO_PEERCRED` is never used as
proof of the later executed child PID.

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

After exec, the child closes raw descriptor 3 if present, atomically duplicates stdin with
`fcntl_dupfd_cloexec` using minimum 3, requires the returned descriptor to be exactly 3 and closes
stdin. Its bounded self-audit then requires exactly descriptors `{1, 2, 3}`. Before authentication,
the production-only applicator captures the parent network-namespace identity, validates its
bootstrap `CAP_NET_ADMIN`, `CAP_SETPCAP` and `CAP_SYS_ADMIN` authority, enters a new network
namespace and sets `NoNewPrivs`. It then reads its inherited seccomp baseline and installs one fixed
amd64 classic-BPF program with `SECCOMP_FILTER_FLAG_TSYNC`, before ambient or bounding-capability
reduction. A kernel error or positive unsynchronised-thread ID aborts bootstrap. The filter returns
`EPERM` for the x32 ABI, an unexpected audit architecture and `clone`, `clone3`, `fork` or `vfork`,
and allows other syscalls. Seccomp restrictions are monotonic and remain across exec. Ambient
capabilities are then cleared and bounding capabilities are
dropped through the kernel's bounded `cap_last_cap`, with `CAP_SETPCAP` dropped last; final
inheritable and ambient sets are empty and permitted, effective and bounding sets contain exactly
`CAP_NET_ADMIN`. Exact PID, PPID, capability and `NoNewPrivs` readback, seccomp filter mode with
exactly the inherited count plus one, and a changed network namespace are required before the child
sends its sandbox proof. The fake applicator and relaxed test observer exist only under `cfg(test)`;
release code has no environment or runtime selector that can substitute them.

The first parent record canonically binds the internal magic and version, route context, generation,
challenge, original parent PID and exact `Child::id`. The child accepts it only with exact
kernel-provided PID/UID/GID credentials and echoes the same binding. Its subsequent canonical proof
is the post-apply completion barrier: only after receiving it does the parent independently observe
the final state through the one anchored `/proc/<pid>` directory descriptor acquired immediately
after spawn. The hard-incompatible sandbox-proof record is version 4; its unchanged 180-byte layout
now binds seccomp mode and filter count in five formerly reserved bytes and retains two canonical
zero bytes. Bounded parsing requires the expected PID/PPID, exact capability and `NoNewPrivs`
values, filter mode 2 with exactly the parent's pre-spawn count plus one, exactly one task equal to
the child PID, and exactly descriptors `{1, 2, 3}`. `/proc` exposes mode and count, not filter
instructions; exact filter content is instead structurally fixed by the reopened `/proc/self/exe`
image and the no-input UAPI wrapper. The parent pins that directory, a pidfd and the observed
`ns/net` descriptor, checks pidfd liveness before and after observation, verifies every proof field
and hashes the exact proof bytes. It then sends
`SandboxAccepted(proof_hash)`; the child must verify every field before returning an exact
`SandboxReady(proof_hash)`. The parent repeats liveness checks after Ready, and no child loop or
successful spawn return is reachable earlier.

The pidfd, anchored proc descriptor and network-namespace pin move into `ProcessRetirement` before
Accepted. Every later timeout, authentication failure, uncertain termination, process drop and
reaper transfer preserves their linear ownership.
Tests cover syscall order and injected failure at every applicator step, strict status/fd/task/proof
parsers, canonical version-4 offsets, every fixed BPF branch and amd64 UAPI layout, real
unprivileged filter installation, proof-before-observation ordering, mutated Accepted/Ready fields,
parent mismatch, death after proof, descriptor leakage, pin retention, and the strong
proof-to-Accepted-to-Ready sequence. The single-task check occurs after the filter is installed and
before Accepted; the observed worker leader therefore receives `EPERM` for every later
`clone`/`clone3`/`fork`/`vfork` attempt, including post-Ready. This proof does not independently
enumerate or attest descendants that might have been created before filter installation. The pins
are released only after confirmed leader reap.

This proves narrow network-namespace, capability, descriptor and credential confinement only. The
worker still runs with effective UID 0, so same-UID signals and the root-writable `/run/volparossa`
directory are not isolated from it. After wiring, such a child could signal the helper parent,
read/replace the token, or unlink `helper.sock` and bind an impersonating Unix socket; NEWNET does
not isolate pathname `AF_UNIX` sockets. Production wiring is therefore blocked on a dedicated
worker identity or equivalently narrow broker design that excludes parent signalling and
runtime-directory/socket/token
access, credential attestation for that identity, explicit approval for the additional launcher
authority, and disposable live-root tests that include the prefilter process-tree state. The shipped
unit and doctor expectations deliberately remain unchanged and do not grant `CAP_SETPCAP`.

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
reattached only to the exact quarantined generation. Once the shutdown fence is installed, normal reattach is prohibited: the
supervisor moves that detached owner into the bounded shutdown-settlement queue. A non-shutdown
reattach failure, launch-cleanup uncertainty and shutdown uncertainty transfer a linearly owned
retirement record to a process-wide in-memory escalation reaper. `WorkerProcess`
and `ProcessRetirement` destruction perform no child-process operation: they only move an armed
retirement record to that reaper. Queue mutex poisoning is recovered with the contained ownership
intact.

The reaper and its fixed pool of 64 permits are initialised before `command.spawn()`. Every
admitted child consumes exactly one permit, carried through `WorkerProcess` and
`ProcessRetirement` until confirmed reap. If no permit is available, launch fails before child
creation. The queue is separately capped at the same 64 entries; because every queued record carries a distinct
permit, saturation by a valid additional owner is impossible. A wrong permit, an over-cap queue or
permit-accounting overflow is an internal ownership-invariant breach and terminates the helper
process without unwinding an owner. Failure to start the reaper is remembered and rejects every
later launch before a child exists; unexpected reaper-thread return or panic is likewise
process-fatal.

Each supervisor or reaper process attempt is bounded to 250 ms. On uncertainty, the detached reaper
waits 5 ms and queues the same owner for another bounded round; no request or shutdown waiter follows
that retry loop. Shutdown therefore completes `false` after its own bounded attempt instead of
waiting indefinitely for background confirmation. The retry record may remain in memory for the
helper lifetime when the operating system never confirms reap. This queue and its permits are not
durable across a helper crash. The dormant v3 store does not change that because no production
writer or restart reaper is connected.

Exact cache hits use a registry-lock-free point-in-time process probe followed by registry-locked
checks of the atomic hint, expiry, generation and shutdown state. There is deliberately no watcher
or pidfd, so a child can still die after a positive probe. The in-memory fallback queue is not a
replacement for durable secret-free ownership and crash recovery; production remains disconnected.

The disconnected async coordinator demonstrates the required transaction shape: PLAN records the
exact context, generation, phase, token and request digest under its short mutex, then starts an
owned supervisor before the caller can wait on the oneshot result. Bounded blocking credentialed
IPC runs outside the registry mutex. The supervisor reacquires the mutex only to commit after
revalidating generation, token, digest, TTL, shutdown and the latest registry-lock-free liveness
hint, or to quarantine and detach for cleanup. A successful terminal `DestroyContext` detaches for
bounded retirement without requiring a positive pre-retirement liveness probe. Timeout, EOF, join
failure, malformed response, stale completion, detected child death, or either-record failure for
an Acquire result never retries the IPC operation.

Before admission, `execute` must obtain the current Tokio runtime handle. Its absence returns
`RuntimeUnavailable` before any permit, registry PLAN or task creation. A fixed 64-slot linear
supervisor admission is then acquired under the same mutex as the shutdown fence before every PLAN,
including exact cache hits and cleanup-triggering requests. Saturation returns `Capacity` before
registry mutation or task spawn.

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

`shutdown()` is a synchronous starter that returns a wait future. Before returning that future and
before any await, one synchronous critical section fences new supervisors, performs the initial
registry detach and transfers those owners plus every existing supervisor handle to one
caller-independent shutdown task. Every supervisor has an explicit RAII settlement: a normal return
settles it, an abnormal task drop records unresolved teardown, and a failed retire observed after
the fence transfers its detached process into the bounded shutdown-owner queue instead of
reattaching it as a registry worker.

The shutdown task processes its initial owners, waits for all captured supervisor handles, drains
their shutdown-owner settlements, and then performs a second fenced registry detach sweep. All
process work remains outside the registry mutex. A `true` completion requires every retirement in
both waves to be confirmed, every captured supervisor to settle, no unresolved settlement, and an
empty worker-record registry after the final sweep. The task owns an RAII publication guard:
normal completion publishes exactly once, while task panic, abort or runtime cancellation
synchronously publishes the shared `false` result during future destruction. Concurrent, later,
and even next-runtime callers wait on or read that same completion rather than starting another
teardown.

A `false` result is fail-closed: full settlement was not proven and process ownership is retained
by the fenced registry, a shutdown settlement, or the in-memory escalation reaper according to the
point of interruption. Tests cover waiter abort, temporary-runtime cancellation followed by a
bounded next-runtime waiter, concurrent shutdown callers, shutdown exactly between a failed retire
and reattach, the final detach sweep, launch cleanup timeout, reattach failure,
process-owner permit-cap saturation, parallel exact-cache-hit coordinator-cap rejection before
PLAN, no-runtime polling before admission or PLAN, mutex-poison ownership, caller abort around PLAN,
generation ABA, expiry/death commit rejection, descriptor closure, tombstone bounds and
registry-lock availability.

Neither the launcher, registry, coordinator, nor production route manager calls this worker path.
The production engine already supervises cancellation-safe PLAN -> CALL -> COMMIT/rollback
transactions: it
reserves and revalidates state under `EngineState`, while every backend call runs without that mutex
held. This orchestration does not make the disconnected worker implementation production-ready.
The production backend still returns `Unavailable` for Prepare and transport acquisition, and the
engine rejects client ingress as `Unavailable` before backend dispatch.

## Same-runtime ambiguous Prepare reconciliation

External tag 35 is `BindHelperRuntime`; its success outcome returns a non-zero, CSPRNG-generated
32-byte ID fixed for one helper process. With `prepare_intent = Some`, it also records the exact
route-context ID, original Prepare request ID and canonical digest, setup expiry, hard expiry, and a
monotonic generation. Registration performs no backend or network call, is serialized under the
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
quarantines rather than releasing. A dormant secret-free journal substrate exists, but the
production writer, restart reaper, recovery backend, and cross-runtime proof needed to settle that
case do not.

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

Socketpair and fake-kernel tests cover the three metadata kinds, response/digest binding, retry-cache
cleanup on context destruction, CLOEXEC, missing/wrong binding, FD-on-error, worker EOF, unexpected
ancillary data and close-on-reject. Loopback sockets test only read-only kernel revalidation; no
namespace, route, link, firewall or sysctl was changed. The production backend still advertises the
operation as unsupported and returns `Unavailable/TRANSPORT_SOCKET_UNAVAILABLE` before context
lookup or any socket/network work. The factories are not invoked by a production v3 namespace
worker, and the agent transport stacks do not yet consume this helper API. No working namespace
datapath is claimed.

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

- choose and prove a dedicated worker UID/GID transition or equivalently narrow broker; the current
  effective-UID-0 child can signal the parent and access the root-writable runtime directory,
  including token replacement and Unix-socket unlink/rebind impersonation;
- obtain explicit approval before adding `CAP_SETPCAP` launcher authority to the helper unit and
  doctor contract, and prove the complete bootstrap in a disposable live-root environment; neither
  the shipped unit nor doctor expectation is changed by this disconnected slice;
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
- connect the dormant secret-free ownership store only after a real cleanup backend can prove
  reaper cleanup;
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
