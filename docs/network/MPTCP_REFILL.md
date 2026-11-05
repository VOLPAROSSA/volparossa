# Same-flow MPTCP relay refill

The development implementation extends an existing Client/Exit context with a newly eligible
relay. It must preserve the application connection, both original MPTCP meta sockets and
the healthy existing path. A newly allocated WireGuard path is only a candidate: actual
subflow payload progress, both physical WireGuard legs and the final application hash
are required before claiming that the fresh path carried data.

## Current result: complete same-flow refill proof

[Run `36714634165`](https://github.com/VOLPAROSSA/volparossa/actions/runs/36714634165)
on exact source `c24fd086ef138f0fa415eca34f2b3bba079104f7` **passes** the unchanged
version-3 report checker against all 171 original artifacts. The complete 256-MiB
(268,435,456-byte) application response matches at both ends, SHA-256
`98b45951638603039e30b1cf89b598ff6587740edb261f996cf4139c673908e3`.

The original two paths carry application data, then the original warm third path joins
and carries data. Under deliberate loss, that exact warm endpoint is withdrawn while the
healthy original path keeps progressing; two withdrawn observations span 10.296 seconds.
Only afterwards does R4 become eligible and supply newly allocated path 4. In its checked
progress interval that new path carries 168,960 Client receive bytes and 170,280 Exit
acknowledged bytes, both above the unchanged 65,536-byte gate. The healthy original path
simultaneously gains 167,640 receive / 170,280 acknowledged bytes. The same application,
route context and both original kernel MPTCP meta-socket cookies, tokens and tuples survive
all eight raw-kernel observations. This is real new-path payload, not merely a helper
allocation, ADD_ADDR acknowledgement or substituted ordinary TCP connection.

Fourteen drained physical-interface captures verify the original and fresh paths' two
WireGuard legs, with no capture drops or forbidden direct Client-to-Exit traffic, no
destination exposure at the Client/Relays and no Client public address at the Exit.
Normal product retirement now succeeds for the original Relays, control Relay and fresh
R4, as well as the Exit. Final CLI status is disconnected with zero contexts/subflows and
an empty path list. The application completes, owned loss/rate qdiscs are removed, and
disposable teardown leaves zero owned objects. Both enumerated guest-parent host-state
snapshots have SHA-256
`596e0fc4ae16a11370d0c9662e3ce555a40d2a5532ea4b74492847885c68fd7b`.
The unchanged original ZIP has SHA-256
`558c1a90840d056dd52ec70cd19d27bc121ee5364b813bedfa0725d67a115830`.

This proves one live same-flow replacement sequence in the disposable topology, not
four simultaneously productive paths, measured speed improvement or complete alpha
acceptance. The implementation still allows at most eight issued path identities per
context lifetime, including aborted attempts, and 64 issued helper flow handles per
context generation. Signed-capability/expiry correctness is not independently reconstructed
from these exported kernel/WireGuard observations. Earlier failed runs below stay failed;
their pending statements describe their own revisions, not this later passing result.

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

## Earlier evidence and corrections

Earlier failures, original reports and fixes remain in the [development archive](../archive/network-architecture-notes-20261026.txt).
The passing result above does not change their verdicts.

<a id="client-owned-subflow-control-candidate"></a>

## Client-owned subflow control

The Client selects Linux userspace path management only inside each authenticated,
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
is follow-up work. The primary-loss, fresh-path byte threshold, complete download hash and privacy/cleanup
gates are the acceptance contract for this mechanism; the exact passing source is
recorded above, not inferred from helper allocation.

<a id="first-userspace-pm-live-result-and-parser-correction"></a>
<a id="successful-initial-update-then-fixture-socket-format-rejection"></a>
<a id="fourth-path-data-succeeds-normal-retirement-still-fails"></a>
<a id="fresh-relay-cleanup-succeeds-an-original-warm-relay-cannot-reconnect"></a>

The earlier userspace-PM trial sequence and cleanup failures remain in the
[development archive](../archive/network-architecture-notes-20261026.txt).
