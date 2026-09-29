# Same-flow MPTCP relay refill

The development candidate extends an existing Client/Exit context with a newly eligible
relay. It must preserve the application connection, both original MPTCP meta sockets and
the healthy existing path. A newly allocated WireGuard path is only a candidate: actual
subflow payload progress, both physical WireGuard legs and the final application hash
are required before claiming that the fresh path carried data.

## Retirement is not simultaneous TCP disappearance

The refill fixture deliberately blackholes the impaired paths in one direction. Removing
the Exit's MPTCP address endpoint can leave its old TCP subflow in `FIN-WAIT-1`, while the
Client still sees `ESTAB` because the closing packets cannot reach it. Neither row alone
proves that the Exit still schedules the path, and neither disappearance nor a helper log
alone proves that the exact intended endpoint was withdrawn.

Refill acceptance version 3 therefore retains separate established and closing-subflow
observations. Closing rows must match the previously productive warm path's exact socket
cookie, tuple, local/remote IDs and peer token, inside the unchanged local meta socket.
Unknown states, malformed rows, foreign paths and changed socket lifetimes still fail.
The original `mptcp-growth` scenario continues to require its historical established-only
TCP subflow observations; these refill-specific semantics do not change old evidence.

The retirement interval requires all of the following:

- A bounded `ip -j mptcp endpoint show` observation in the same lifetime-checked Exit
  helper namespace first contains the warm address/ID/interface, then shows it absent.
  Other previously present endpoints must remain intact.
- The Exit's exact warm subflow is closing or absent, never still established. An exact
  Client-side established residue may remain under the deliberate one-way loss and is
  kept in the evidence, not counted as a newly useful path.
- Two withdrawn observations span at least ten seconds. Any remaining old warm socket
  has no additional useful payload bytes; disappearance does not authorize a replacement
  socket with a reused path identity. The unchanged healthy original path makes substantial
  fresh progress at both ends during that interval.

Only then may R4 become newly eligible. The original requirements remain: R4 was absent
from the initial set, original context/socket identities survive, R4 and the healthy
original path carry fresh data, packet captures preserve the privacy boundaries, all
256 MiB of the application response match the expected hash, and owned cleanup completes.
This is a functional proof for one topology, not a speed guarantee or full-alpha claim.

The endpoint decoder follows the bounded address/ID/signal/device fields emitted by
[iproute2's MPTCP endpoint dump](https://github.com/iproute2/iproute2/blob/v6.15.0/ip/ipmptcp.c#L211).
This diagnostic command is read-only and runs only inside the disposable owned namespace;
production control continues to use its typed kernel backend.

## Evidence status

[Run 36581328449 on `5e6560e2`](https://github.com/VOLPAROSSA/volparossa/actions/runs/36581328449)
remains **failed** with `MPTCP_REFILL_WARM_NOT_RETIRED`. Its saved Exit TCP row is
`FIN-WAIT-1` with the same warm tuple and cookie `2002` previously observed as established;
the old parser rejected that state. The Client's warm row remained established under the
injected loss. Exit helper/agent records show endpoint retirement, but the run did not
retain the new independent endpoint-dump interval and did not reach R4 proof. It must not
be retroactively promoted to a passing refill result.

The final fixture report records complete disposable teardown and unchanged host state.
That is separate from the earlier route-disconnect failure still visible in its logs.
Twelve refill checker tests and nine historical growth checker tests pass locally after
this observer correction; these are synthetic checker regressions, not a new live run.

[Run 36586125461 on `05cda509`](https://github.com/VOLPAROSSA/volparossa/actions/runs/36586125461)
also remains **failed**, now at `MPTCP_REFILL_FRESH_PATH_MISSING`. Its version-3 evidence
does establish retirement: the exact warm Exit endpoint is withdrawn, its anchored TCP
residue is closing, and the original healthy path progresses while the old warm bytes
remain stalled. Rechecking that interval with the unchanged retirement checker succeeds.
R4 becomes eligible afterwards, but no new R4 helper context, subflow payload or complete
application hash is proved. The original evidence is retained without rewriting its result.

The Client reports `PRESELECTION_SAMPLE_INVALID_SNAPSHOT` on the refill retry cadence.
The corresponding production defect is that the established-route restriction filtered
candidate vectors **after** their affine subject bindings had been constructed. Their sizes
and pair indices then disagreed, so the existing shape check correctly rejected the attempt.
An earlier random control-relay choice could also discard the route's required original
control lineage. The correction selects that exact lineage from the complete, revalidated
and ambiguity-checked group, projects its relays, and only then constructs the affine
bindings. Unrestricted selection and all freshness, byte/hash, privacy and cleanup gates
are unchanged. This source correction is not yet a successful live refill proof.

The run's final disposable cleanup is complete and host state unchanged. Separately, the
agent reports `SHUTDOWN_CLEANUP_FAILED`; two relays record `ROUTE_RETIRE_OUTBOUND_DIAL_FAILED`
during their retirement exchanges. Those diagnostics identify a failed outbound dial, not
its underlying cause, and are not erased by the fixture's eventual teardown.

[Run 36591890165 on `4107389b`](https://github.com/VOLPAROSSA/volparossa/actions/runs/36591890165)
remains **failed**, also at `MPTCP_REFILL_FRESH_PATH_MISSING`. The corrected candidate
projection now reaches two fresh Exit-issued native permits and real helper Prepare on
R4 and its sampling companion, but neither completes native Ready. No R4 attachment,
new-path payload or complete application hash is established. Final disposable cleanup
is complete and host state unchanged; the immutable original result is not rewritten.

The saved injection and owner mapping identify the companion as original path 1/R2,
whose Exit-facing link is deliberately blackholed at 100% loss. The production caller
selected the first still-advertised original Relay, rather than the progressing sibling
that caused refill demand. Thus a fresh two-path measurement unnecessarily depended on
the already impaired path. The bounded correction retains the currently progressing,
non-lossy sibling's path ID from that same flow observation and resolves it through the
existing verified grant and Relay authority. Fresh A1/native readiness still has to prove
that both nominated paths work; telemetry does not replace that authority. All timing,
loss injection, original socket identity, payload/hash and cleanup requirements remain
unchanged. Focused synthetic nomination tests accompany this correction; a successful
new live refill is still pending.

[Run 36596674960 on `258c049e`](https://github.com/VOLPAROSSA/volparossa/actions/runs/36596674960)
remains **failed** at `MPTCP_REFILL_FRESH_PATH_MISSING`. The real fresh two-path native
measurement now reaches helper Commit on the Client, Exit and R4. Afterwards the original
Client and Exit prepare additive path 4, then immediately abort it before R4's route
reservation. The expanded R4 capture contains two WireGuard data datagrams on each leg,
consistent with the native probe, not the required fourth-path application payload.

The Exit's native-evidence verifier compared the new sample's ordinal (1 or 2) with the
established route's new path ID (4), so this valid extension could never pass that check.
The correction keeps initial-route ordinal equality and introduces a separate extension
binding: exact signed parent and permit, retained path, unchanged actors/control/Exit/
policy/transport, post-permit measurements, and both distinct members of the same completed
native batch. It does not rewrite signed native scopes or substitute advertisements for
measurement. Focused synthetic authority/batch regressions accompany the change; no new
successful live refill or application hash is claimed.

The final fixture reports complete teardown with zero owned leftovers and matching A15
host-state hashes. Expanded Client, Exit and R4 captures have no direct Client-to-Exit or
unexpected outer packets, no capture drops and no truncation. These limited observations
do not replace the unfinished full refill acceptance. The Client still separately reports
`SHUTDOWN_CLEANUP_FAILED`; its retained 400-row diagnostic tail does not identify that
failure's precise cleanup phase. The immutable original ZIP SHA-256 is
`f37ceb83b2c1f2122befeb164b80bc0d5e89909347ac50926073a909bd2cc8c3`.

[Run 36604968363 on `0f58f2f2`](https://github.com/VOLPAROSSA/volparossa/actions/runs/36604968363)
remains **failed**, at `MPTCP_REFILL_APPLICATION_ENDED`. This is not a failed or truncated
download: the retained Client completion record contains all 268,435,456 response bytes,
and its SHA-256 matches the deterministic fixture's expected
`9b3d1401c16ffa448d8225f14258f08c4e0fcc49b3e2e87cdb78d1ea0114f244`.
The response completes in 306.43 seconds while the fixture is still waiting for a fourth
subflow. The Client process exit status and separate destination completion record were
not retained at that early failure boundary; neither is inferred from the generic blocker.

The original warm path 2 first joins and carries application bytes, then retires under
the required injected loss. Fresh extension path 4 now reaches **Prepare, Activate and
Commit on both the original Client and Exit**, with its new WireGuard interfaces retained
alongside the original interfaces. The Exit adds its new MPTCP endpoint at 17:37:45 UTC,
then removes it about eleven seconds later because no useful subflow appears. Thus the
corrected native-evidence projection has progressed through real extension admission,
but helper Commit still does not establish fourth-path application traffic.

The new bounded diagnostics localize the failure after endpoint installation: Exit
`AddAddrTx` increases from 2 to 3, but Client `AddAddr` and `MPJoinSynTx` remain at 2,
as does Exit `EchoAdd`. No new JOIN attempt or JOIN error is observed. Both owned
namespaces report a 120-second `add_addr_timeout`. The original primary path 1 remains
100% blackholed, while healthy path 3 completes the download. R4's two physical legs
each contain only two WireGuard data datagrams, not the required application-scale bytes.

This exposes a limitation of the current kernel-managed announcement strategy. In the
fixture's [Linux 6.12.105 path manager](https://github.com/gregkh/linux/blob/v6.12.105/net/mptcp/pm_netlink.c),
`mptcp_pm_nl_addr_send_ack_avoid_list` chooses the first subflow that passes
[`__mptcp_subflow_active`](https://github.com/gregkh/linux/blob/v6.12.105/net/mptcp/protocol.h):
that check requires an established/joined TCP state, not useful progress or absence of
loss. A blackholed primary can therefore carry the announcement even while the data
scheduler uses a healthy sibling. The saved counters establish that the new announcement
did not reach the Client; they are not a decrypted packet trace of its exact selected
subflow. The native kernel retry interval also exceeds the unchanged warm-probe interval.
The required primary-path failure, all timers and all fourth-path acceptance gates remain
unchanged. An owner-bound Client userspace path-manager integration is under investigation;
kernel congestion control, scheduling, retransmission and reassembly would remain in use.
No such integration or passing fresh-refill datapath is claimed here.

Disposable teardown reports zero owned leftovers and unchanged host state. Retained R4
privacy observations contain no direct Client-to-Exit or unexpected destination outer
traffic and no capture drops/truncation, but full refill acceptance still fails. Separately,
the Client reports `SHUTDOWN_CLEANUP_FAILED` and retirement exchanges report outbound dial
failures; eventual fixture cleanup does not make agent shutdown clean. The immutable
original ZIP SHA-256 is
`f2aa60c0077325192487d98b66892863a7922b1df60be89713e58f2e202bf0a4`.

## Client-owned subflow control candidate

The candidate now selects Linux userspace path management only inside each authenticated,
new Client worker network namespace, before its first MPTCP socket. The fixed bootstrap
checks that this namespace differs from the parent and reads back `pm_type=1`; it never
changes the host or an existing socket's path-manager mode. Exit namespaces retain their
kernel path manager. Linux still performs all scheduling, congestion control, retransmission
and reassembly: this is not a TCP replacement or an mptcpd dependency.

Additional subflows are requested through a typed helper operation. A helper-issued opaque
flow handle is bound to the real connected socket's cookie, kernel token, original tuple,
namespace and context generation. Each mutation temporarily passes that actual socket
descriptor, held only until the worker command completes. The helper derives both addresses
from the already committed path; callers cannot supply addresses, ports or kernel tokens.
The original primary subflow cannot be removed through this interface. Kernel event and
command acknowledgement handling are bounded; neither is treated as application traffic.

The Client receives short-lived signed active/retired path snapshots from its original Exit
through the original control relay. They must match the retained signed reservation exactly,
the same authenticated connection lineage and a monotone committed path lifecycle. Only
then may an initial, warm or newly committed path get a subflow. Unavailable snapshots do
not invent activation, and contradictory snapshots fail closed. Fresh paths still require
the ordinary discovery, native evidence, reservations and Client/Relay/Exit ownership steps.

The current helper ledger is limited to 64 issued flow handles per context generation,
not unlimited sequential sockets; it retains metadata rather than data descriptors and is
cleared by context destruction. Propagating exact closed-flow lifetimes back to that ledger
is follow-up work. The unchanged primary-loss, fresh-path byte threshold, complete download
hash and privacy/cleanup acceptance gates must still pass in a new live run before this
candidate counts as working fresh refill.

Targeted local checks pass: ten subflow/descriptor checks (including the existing real
two-subflow disposable-kernel test), the Client monotone snapshot lifecycle, kernel-event
parser, private-namespace bootstrap predicate, two signed snapshot protocol checks and
the schema-tag parity check. Four-crate all-target/all-feature strict Clippy, formatting
and fourteen unchanged refill-fixture checks also pass. These do not substitute for a
new live userspace-PM/fresh-fourth-path run.

### First userspace-PM live result and parser correction

[Run `36614116209` on `01fcabe7`](https://github.com/VOLPAROSSA/volparossa/actions/runs/36614116209)
fails during the initial application, before fresh-refill proof. The first owned subflow
update returns `MPTCP_ENDPOINT_UNAVAILABLE`; the Client then records
`INGRESS_TCP_STREAM_FAILED` and the application receives a connection reset. The original
116 files remain unchanged (ZIP SHA-256
`448be2f2e846b6de073fca62d3c4059be5b65195125d685fa0dfb17053d155f1`).
Disposable cleanup reports zero owned objects and byte-identical host state, SHA-256
`ed70b3cc6a3c37636ecd78599e64950c520a2a24d84e8c7532aa4b3df8cee106`.

Source review found a concrete incompatibility: Linux v6.12's
[`mptcp_event_addr_announced`](https://github.com/torvalds/linux/blob/v6.12/net/mptcp/pm_netlink.c)
emits an IPv6 `ANNOUNCED` event with TOKEN, REM_ID, DPORT and DADDR6, without FAMILY.
Our parser wrongly rejected that form. The correction accepts missing FAMILY only for
that remote announcement, never an established/local tuple or an explicitly contradictory
family. Eight targeted kernel checks pass, including the exact emitted shape, malformed
and forged variants, and the existing real two-subflow disposable-kernel test; strict
MPTCP Clippy and formatting pass. The original artifact contains no raw event frame, so
this source-level defect is a plausible explanation of its kernel rejection, not a captured
event identity. A new live run is still required; failure-injection and byte gates are unchanged.
