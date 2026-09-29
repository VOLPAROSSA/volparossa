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
