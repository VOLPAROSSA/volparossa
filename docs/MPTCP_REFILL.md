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
